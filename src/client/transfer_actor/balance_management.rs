use sn_data_types::{
    Cmd, DebitAgreementProof, Event, Money, PublicKey, Query, QueryResponse, TransferCmd,
    TransferQuery,
};
use sn_transfers::{ActorEvent, TransferInitiated};

use crate::client::Client;
use crate::errors::ClientError;

use log::{debug, info, trace};

/// Handle all Money transfers and Write API requests for a given ClientId.
impl Client {
    /// Get the current known account balance from the local actor. (ie. Without querying the network)
    ///
    /// # Examples
    ///
    /// Create a random client
    /// ```no_run
    /// # extern crate tokio;use sn_client::ClientError;
    /// use sn_client::Client;
    /// use std::str::FromStr;
    /// use sn_data_types::Money;
    /// # #[tokio::main]async fn main() {let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// let client = Client::new(None).await?;
    /// // now we check the local balance
    /// let some_balance = client.get_local_balance().await;
    /// assert_eq!(some_balance, Money::from_str("0")?);
    /// # Ok(())} );}
    /// ```
    pub async fn get_local_balance(&self) -> Money {
        info!("Retrieving actor's local balance.");
        self.transfer_actor.lock().await.balance()
    }

    /// Handle a validation event.
    #[allow(dead_code)]
    pub(crate) async fn handle_validation_event(
        &mut self,
        event: Event,
    ) -> Result<Option<DebitAgreementProof>, ClientError> {
        debug!("Handling validation event: {:?}", event);
        let validation = match event {
            Event::TransferValidated { event, .. } => event,
            _ => {
                return Err(ClientError::from(format!(
                    "Unexpected event received at TransferActor, {:?}",
                    event
                )))
            }
        };
        let mut actor = self.transfer_actor.lock().await;
        let transfer_validation = match actor.receive(validation) {
            Ok(Some(validation)) => validation,
            Ok(None) => return Ok(None),
            Err(error) => {
                if !error.to_string().contains("Already received validation") {
                    return Err(ClientError::from(error));
                }

                return Ok(None);
            }
        };

        actor.apply(ActorEvent::TransferValidationReceived(
            transfer_validation.clone(),
        ))?;

        Ok(transfer_validation.proof)
    }

    /// Get the current balance for this TransferActor PK (by default) or any other...
    pub(crate) async fn get_balance_from_network(
        &mut self,
        pk: Option<PublicKey>,
    ) -> Result<Money, ClientError> {
        info!("Getting balance for {:?} or self", pk);
        let identity = self.full_id().await;
        let public_key = pk.unwrap_or(*identity.public_key());

        let msg_contents = Query::Transfer(TransferQuery::GetBalance(public_key));

        let message = Self::create_query_message(msg_contents);

        match self
            .connection_manager
            .lock()
            .await
            .send_query(&message)
            .await?
        {
            QueryResponse::GetBalance(balance) => balance.map_err(ClientError::from),
            _ => Err(ClientError::from(
                "Unexpected response when querying balance",
            )),
        }
    }

    /// Send money to another PublicKey.
    ///
    /// If the PublicKey does not exist as a balance on the network it will be created with the send amount.
    ///
    /// # Examples
    ///
    /// Send money to a PublickKey.
    /// (This test uses "simulated payouts" to generate test money. This of course would not be avaiable on a live network.)
    /// ```no_run
    /// # extern crate tokio;use sn_client::ClientError;
    /// use sn_client::Client;
    /// use sn_data_types::{PublicKey, Money};
    /// use std::str::FromStr;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // A random sk, to send money to
    /// let sk = threshold_crypto::SecretKey::random();
    /// let pk = PublicKey::from(sk.public_key());
    /// // Next we create a random client.
    /// let mut client = Client::new(None).await?;
    /// let target_balance = Money::from_str("100")?;
    /// // And trigger a simulated payout to our client's PublicKey, so we have money to send.
    /// let _ = client.trigger_simulated_farming_payout(target_balance).await?;
    ///
    /// // Now we have 100 money at our balance, we can send it elsewhere:
    /// let (count, sending_pk) = client.send_money( pk, target_balance ).await?;
    ///
    /// // Finally, we can see that the money has arrived:
    /// let received_balance = client.get_balance_for(pk).await?;
    ///
    /// assert_eq!(1, count);
    /// assert_ne!(pk, sending_pk);
    /// assert_eq!(received_balance, target_balance);
    /// # Ok(())} ); }
    /// ```
    pub async fn send_money(
        &mut self,
        to: PublicKey,
        amount: Money,
    ) -> Result<(u64, PublicKey), ClientError> {
        info!("Sending money");

        // first make sure our balance  history is up to date
        self.get_history().await?;

        println!(
            "Debits form our actor at send: {:?}",
            self.transfer_actor.lock().await.debits_since(0)
        );

        let signed_transfer = self
            .transfer_actor
            .lock()
            .await
            .transfer(amount, to)?
            .ok_or_else(|| ClientError::from("No transfer generated by the actor."))?
            .signed_transfer;

        let dot = signed_transfer.id();
        println!(
            "Signed transfer for send money: {:?}",
            signed_transfer.transfer
        );
        let msg_contents = Cmd::Transfer(TransferCmd::ValidateTransfer(signed_transfer.clone()));

        let message = Self::create_cmd_message(msg_contents);

        self.transfer_actor
            .lock()
            .await
            .apply(ActorEvent::TransferInitiated(TransferInitiated {
                signed_transfer: signed_transfer.clone(),
            }))?;

        let debit_proof: DebitAgreementProof = self
            .await_validation(&message, signed_transfer.id())
            .await?;

        // Register the transfer on the network.
        let msg_contents = Cmd::Transfer(TransferCmd::RegisterTransfer(debit_proof.clone()));

        let message = Self::create_cmd_message(msg_contents);
        trace!(
            "Debit proof received and to be sent in RegisterTransfer req: {:?}",
            debit_proof
        );

        let _ = self
            .connection_manager
            .lock()
            .await
            .send_cmd(&message)
            .await?;

        let mut actor = self.transfer_actor.lock().await;
        // First register with local actor, then reply.
        let register_event = actor
            .register(debit_proof)?
            .ok_or_else(|| ClientError::from("No transfer event to register locally"))?;

        actor.apply(ActorEvent::TransferRegistrationSent(register_event))?;

        Ok((dot.counter, dot.actor))
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
    use crate::utils::{generate_random_vector, test_utils::calculate_new_balance};
    use log::error;
    use sn_data_types::{Blob, Error as SndError, Error, Money, PublicBlob};
    use std::str::FromStr;

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    async fn transfer_actor_can_send_money_and_thats_reflected_locally() -> Result<(), ClientError>
    {
        let (_sk2, pk2) = shared_box::gen_bls_keypair();

        let pk2 = PublicKey::Bls(pk2);

        let mut client = Client::new(None).await?;

        let _ = client.send_money(pk2, Money::from_str("1")?).await?;

        // initial 10 on creation from farming simulation minus 1
        assert_eq!(client.get_local_balance().await, Money::from_str("9")?);

        assert_eq!(client.get_balance().await?, Money::from_str("9")?);

        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    async fn transfer_actor_can_send_several_transfers_and_thats_reflected_locally(
    ) -> Result<(), ClientError> {
        let (_, random_pk) = shared_box::gen_bls_keypair();
        let random_pk = PublicKey::Bls(random_pk);
        let mut client = Client::new(None).await?;

        // Transfers 1 Money to a random PK
        let _ = client
            .send_money(random_pk, Money::from_str("1.0")?)
            .await?;

        // Initial 10 Money on creation from farming simulation minus 1
        // Assert locally
        assert_eq!(client.get_local_balance().await, Money::from_str("9")?);

        // Fetch balance from network and assert the same.
        assert_eq!(
            client.get_balance_from_network(None).await?,
            Money::from_str("9")?
        );

        // Transfer 2 more Money to random PK.
        let _ = client.send_money(random_pk, Money::from_str("2")?).await?;

        // Initial 10 on creation from farming simulation minus 3
        assert_eq!(client.get_local_balance().await, Money::from_str("7")?);

        // Fetch balance from network and assert the same.
        assert_eq!(
            client.get_balance_from_network(None).await?,
            Money::from_str("7")?
        );

        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    async fn transfer_actor_cannot_send_0_money_req() -> Result<(), ClientError> {
        let (_, random_pk) = shared_box::gen_bls_keypair();

        let mut client = Client::new(None).await?;

        // Send 0 Money to a random PK.
        match client
            .send_money(PublicKey::Bls(random_pk), Money::from_str("0")?)
            .await
        {
            Err(ClientError::DataError(Error::Unexpected(_))) => (),
            _result => error!("Unexpected error. Zero-Value Transfers should not pass"),
        }

        // Unchanged balances - local and network.
        assert_eq!(client.get_local_balance().await, Money::from_str("10")?);

        assert_eq!(client.get_balance().await?, Money::from_str("10")?);

        Ok(())
    }

    // 1. Create a client A and allocate 100 Money to it. (Clients start with 10 Money by default on simulated-farming)
    // 2. Get the balance and verify it.
    // 3. Create another client B with a wallet holding 10 Money on start.
    // 4. Transfer 5 Money from client A to client B and verify the new balance.
    // 5. Try to do a coin transfer without enough funds, it should return `InsufficientBalance`
    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    pub async fn balance_transfers_between_clients() -> Result<(), ClientError> {
        let mut client = Client::new(None).await?;
        let mut receiving_client = Client::new(None).await?;

        let wallet1 = receiving_client.public_key().await;

        client
            .trigger_simulated_farming_payout(Money::from_str("100.0")?)
            .await?;

        let balance = client.get_balance().await?;
        assert_eq!(balance, Money::from_str("110")?); // 10 coins added automatically w/ farming sim on client init.

        let orig_balance = client.get_balance().await?;
        let _ = client.send_money(wallet1, Money::from_str("5.0")?).await?;

        // Assert sender is debited.
        let new_balance = client.get_balance().await?;
        assert_eq!(
            new_balance,
            calculate_new_balance(balance, None, Some(Money::from_str("5.0")?))
        );

        // Assert that the receiver has been credited.
        let mut receiving_bal = receiving_client.get_balance().await?;
        assert_eq!(receiving_bal, Money::from_str("15.0")?);

        // Try transferring money exceeding our balance.
        let res = client.send_money(wallet1, Money::from_str("5000")?).await;
        match res {
            Err(ClientError::DataError(SndError::InsufficientBalance)) => (),
            res => panic!("Unexpected result: {:?}", res),
        };

        // Assert if money is refunded.
        let balance = client.get_balance().await?;
        let expected = calculate_new_balance(orig_balance, None, Some(Money::from_str("5")?));
        assert_eq!(balance, expected);

        // Assert no money is credited accidentally.
        receiving_bal = receiving_client.get_balance().await?;
        assert_eq!(receiving_bal, Money::from_str("15")?);

        Ok(())
    }

    #[cfg(feature = "simulated-payouts")]
    #[tokio::test]
    pub async fn cannot_write_with_insufficient_balance() -> Result<(), ClientError> {
        let mut client = Client::new(None).await?;
        let receiving_client = Client::new(None).await?;

        let wallet1 = receiving_client.public_key().await;

        let _ = client.send_money(wallet1, Money::from_str("10")?).await?;

        let data = Blob::Public(PublicBlob::new(generate_random_vector::<u8>(10)));
        let res = client.store_blob(data).await;
        match res {
            Err(ClientError::DataError(SndError::InsufficientBalance)) => (),
            res => panic!(
                "Unexpected result in money transfer test, putting without balance: {:?}",
                res
            ),
        };

        Ok(())
    }
}
