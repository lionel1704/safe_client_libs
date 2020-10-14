use bincode::serialize;
use log::{debug, error, info, trace, warn};
use sn_data_types::{
    ClientFullId, Cmd, DataCmd, DebitAgreementProof, Message, Money, PublicKey, Query,
    QueryResponse, TransferCmd, TransferId, TransferQuery, TransferValidated,
};
use sn_transfers::{ActorEvent, ReplicaValidator, TransferInitiated};
use threshold_crypto::PublicKeySet;
use tokio::sync::mpsc::channel;

/// Module for Money balance management
pub mod balance_management;
/// Module for simulating Money for testing
pub mod simulated_payouts;
/// Module containing all PUT apis
pub mod write_apis;

/// Actual Transfer Actor
pub use sn_transfers::TransferActor as SafeTransferActor;

use crate::client::{Client, ConnectionManager};
use crate::errors::ClientError;

/// Simple client side validations
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientTransferValidator {}

impl ReplicaValidator for ClientTransferValidator {
    fn is_valid(&self, _replica_group: PublicKey) -> bool {
        true
    }
}

impl Client {
    /// Get the client's current coin balance from the network
    ///
    /// # Examples
    ///
    /// Retrieve an existing balance
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError;
    /// use sn_client::Client;
    /// use sn_data_types::Money;
    /// use std::str::FromStr;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's check the balance of a client with a random sk.
    /// // (It should have 0 balance)
    /// let secret_key = threshold_crypto::SecretKey::random();
    ///
    /// let mut client = Client::new(Some(secret_key)).await?;
    /// let initial_balance = Money::from_str("0")?;
    /// let balance = client.get_balance().await?;
    /// assert_eq!(balance, initial_balance);
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_balance(&mut self) -> Result<Money, ClientError>
    where
        Self: Sized,
    {
        trace!(
            "Getting balance for {:?}",
            self.full_id().await.public_key()
        );

        // we're a standard client grabbing our own key's balance
        self.get_balance_from_network(None).await
    }

    /// Get balance for a Public Key on the network.
    ///
    /// # Examples
    ///
    /// Retrieve an existing balance
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError;
    /// use sn_client::Client;
    /// use sn_data_types::{Money, PublicKey};
    /// use std::str::FromStr;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's check the balance of a client with a random sk.
    /// // (It should have 0 balance)
    /// let secret_key = threshold_crypto::SecretKey::random();
    /// let pk = PublicKey::from(secret_key.public_key());
    ///
    /// // And we use a random client to do this
    /// let mut client = Client::new(None).await?;
    /// let initial_balance = Money::from_str("0")?;
    /// let balance = client.get_balance_for(pk).await?;
    /// assert_eq!(balance, initial_balance);
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_balance_for(&mut self, public_key: PublicKey) -> Result<Money, ClientError>
    where
        Self: Sized,
    {
        trace!("Get balance for {:?}", public_key);
        self.get_balance_from_network(Some(public_key)).await
    }

    /// Retrieve the history of the account from the network and apply to our local client's AT2 actor.
    ///
    /// # Examples
    ///
    /// Retrieving an existing balance history
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError;
    /// use sn_client::Client;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's check the balance of a client with a random sk.
    /// let secret_key = threshold_crypto::SecretKey::random();
    ///
    /// // And we use a random client to do this
    /// let mut client = Client::new(Some(secret_key)).await?;
    /// // Upon calling, history is retrieved and applied to the local AT2 actor.
    /// let _ = client.get_history().await?;
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_history(&mut self) -> Result<(), ClientError> {
        let public_key = *self.full_id.public_key();
        info!("Getting SnTransfers history for pk: {:?}", public_key);

        let msg_contents = Query::Transfer(TransferQuery::GetHistory {
            at: public_key,
            since_version: 0,
        });

        let message = Self::create_query_message(msg_contents);

        // This is a normal response manager request. We want quorum on this for now...
        let res = self
            .connection_manager
            .lock()
            .await
            .send_query(&message)
            .await?;

        let history = match res {
            QueryResponse::GetHistory(history) => history.map_err(ClientError::from),
            _ => Err(ClientError::from(format!(
                "Unexpected response when retrieving account history {:?}",
                res
            ))),
        }?;

        trace!("Received history response is: {:?}", history);

        let mut actor = self.transfer_actor.lock().await;
        match actor.synch(history) {
            Ok(synced_transfer_outcome) => {
                if let Some(transfers) = synced_transfer_outcome {
                    actor.apply(ActorEvent::TransfersSynched(transfers))?;
                }
            }
            Err(error) => {
                if !error
                    .to_string()
                    .contains("No credits or debits found to sync to actor")
                {
                    return Err(ClientError::from(error));
                }

                warn!(
                    "No new transfer history  by TransferActor for pk: {:?}",
                    public_key
                );
            }
        }

        debug!("Current balance after GetHistory {:?}", actor.balance());

        Ok(())
    }

    /// Fetch latest StoreCost for given number of bytes from the network.
    pub async fn get_store_cost(&mut self, bytes: u64) -> Result<Money, ClientError> {
        info!("Sending Query for latest StoreCost");

        let public_key = *self.full_id.public_key();

        let msg_contents = Query::Transfer(TransferQuery::GetStoreCost {
            requester: public_key,
            bytes,
        });

        let message = Self::create_query_message(msg_contents);

        // This is a normal response manager request. We want quorum on this for now...
        let res = self
            .connection_manager
            .lock()
            .await
            .send_query(&message)
            .await?;

        match res {
            QueryResponse::GetStoreCost(cost) => cost.map_err(ClientError::DataError),
            _ => Err(ClientError::from(format!(
                "Unexpected response when retrieving account history {:?}",
                res
            ))),
        }
    }

    /// Validates a transaction for paying store_cost
    pub(crate) async fn create_write_payment_proof(
        &mut self,
        cmd: &DataCmd,
    ) -> Result<DebitAgreementProof, ClientError> {
        info!("Sending requests for payment for write operation");

        // Compute number of bytes
        let bytes = serialize(cmd)?.len() as u64;

        //set up message
        let _full_id = self.full_id.clone();

        self.get_history().await?;

        let section_key = PublicKey::Bls(self.replicas_pk_set.public_key());

        let cost_of_put = self.get_store_cost(bytes).await?;

        let signed_transfer = self
            .transfer_actor
            .lock()
            .await
            .transfer(cost_of_put, section_key)?
            .ok_or_else(|| ClientError::from("No transfer produced by actor."))?
            .signed_transfer;

        let command = Cmd::Transfer(TransferCmd::ValidateTransfer(signed_transfer.clone()));

        debug!("Transfer to be sent: {:?}", &signed_transfer);

        let transfer_message = Self::create_cmd_message(command);

        self.transfer_actor
            .lock()
            .await
            .apply(ActorEvent::TransferInitiated(TransferInitiated {
                signed_transfer: signed_transfer.clone(),
            }))?;

        let payment_proof: DebitAgreementProof = self
            .await_validation(&transfer_message, signed_transfer.id())
            .await?;

        debug!("Payment proof retrieved");
        Ok(payment_proof)
    }

    /// Get our replica instance PK set
    pub(crate) async fn get_replica_keys(
        full_id: ClientFullId,
        cm: &mut ConnectionManager,
    ) -> Result<PublicKeySet, ClientError> {
        trace!("Getting replica keys for {:?}", full_id);

        let keys_query_msg = Query::Transfer(TransferQuery::GetReplicaKeys(*full_id.public_key()));

        let message = Self::create_query_message(keys_query_msg);

        let res = cm.send_query(&message).await?;

        match res {
            QueryResponse::GetReplicaKeys(pk_set) => Ok(pk_set?),
            _ => Err(ClientError::from(format!(
                "Unexpected response when retrieving account replica keys for {:?}",
                full_id.public_key()
            ))),
        }
    }

    /// Send message and await validation and constructing of DebitAgreementProof
    async fn await_validation(
        &mut self,
        message: &Message,
        _id: TransferId,
    ) -> Result<DebitAgreementProof, ClientError> {
        info!("Awaiting transfer validation");

        let (sender, mut receiver) = channel::<Result<TransferValidated, ClientError>>(7);

        self.connection_manager
            .lock()
            .await
            .send_transfer_validation(&message, sender)
            .await?;

        loop {
            match receiver.recv().await {
                Some(event) => match event {
                    Ok(transfer_validated) => {
                        match self.transfer_actor.lock().await.receive(transfer_validated) {
                            Ok(result) => {
                                if let Some(validation) = result {
                                    info!("Transfer successfully validated.");
                                    if let Some(dap) = validation.proof {
                                        return Ok(dap);
                                    }
                                } else {
                                    info!("Aggregated given SignatureShare.");
                                }
                            }
                            Err(e) => error!("Error accumulating SignatureShare: {:?}", e),
                        }
                    }
                    Err(e) => error!("Error receiving SignatureShare: {:?}", e),
                },
                None => continue,
            }
        }
    }
}

// --------------------------------
// Tests
// ---------------------------------

// TODO: Do we need "new" to actually instantiate with a transfer?...
#[cfg(all(test, feature = "simulated-payouts"))]
mod tests {

    use super::*;
    use crate::crypto::shared_box;
    use sn_data_types::Money;
    use std::str::FromStr;

    #[tokio::test]
    async fn transfer_actor_creation_hydration_for_nonexistant_balance() -> Result<(), ClientError>
    {
        let (sk, _pk) = shared_box::gen_bls_keypair();

        match Client::new(Some(sk)).await {
            Ok(actor) => {
                assert_eq!(actor.get_local_balance().await, Money::from_str("0").unwrap() );
                Ok(())
            },
            Err(e) => panic!("Should not error for nonexistant keys, only create a new instance with no history, we got: {:?}" , e )
        }
    }

    // TODO: only do this for real node until we a local replica bank
    #[tokio::test]
    #[cfg(not(feature = "mock-network"))]
    async fn transfer_actor_creation_hydration_for_existing_balance() -> Result<(), ClientError> {
        let (sk, _pk) = shared_box::gen_bls_keypair();

        let mut initial_actor = Client::new(Some(sk.clone())).await?;

        let _ = initial_actor
            .trigger_simulated_farming_payout(Money::from_str("100")?)
            .await?;

        match Client::new(Some(sk)).await {
            Ok(mut client) => {
                assert_eq!(
                    client.get_balance_from_network(None).await?,
                    Money::from_str("100")?
                );
                assert_eq!(client.get_local_balance().await, Money::from_str("100")?);

                Ok(())
            }
            Err(e) => panic!("Account should exist {:?}", e),
        }
    }
}
