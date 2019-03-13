// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Client, CoreError, MDataInfo};
use futures::Future;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use redland_rs::{EntryAction, KvStorage, Model, ModelIter, World};
use routing::{EntryAction as MDEntryAction, Value};
use std::collections::BTreeMap;

/// Represents an abstract RDF graph model
pub struct RdfGraph {
    /// Holds internal state of the RDF library
    world: World,
    /// Holds the internal state of the RDF graph
    model: Model,
    /// Holds internal triples storage
    storage: KvStorage,
}

impl RdfGraph {
    /// Create a new RDF graph
    pub fn new() -> Result<Self, i32> {
        let world = World::new();
        let storage = KvStorage::new(&world)?;
        let model = Model::new(&world, &storage)?;
        Ok(RdfGraph {
            world,
            model,
            storage,
        })
    }

    /// Get RDF model
    pub fn model_mut(&mut self) -> &mut Model {
        &mut self.model
    }

    /// Return internal representation of RDF world
    pub fn world(&self) -> &World {
        &self.world
    }

    /// Store an RDF graph on the network
    pub fn store(
        &self,
        client: impl Client,
        md_info: &MDataInfo,
    ) -> impl Future<Item = (), Error = CoreError> {
        let actions = convert_entry_actions(self.storage.entry_actions());
        client.mutate_mdata_entries(md_info.name, md_info.type_tag, actions)
    }

    /// Load an RDF graph from the network
    pub fn load(
        client: impl Client,
        md: &MDataInfo,
    ) -> impl Future<Item = RdfGraph, Error = CoreError> {
        client.get_mdata(md.name, md.type_tag).and_then(move |md| {
            let mut graph = RdfGraph::new()
                .map_err(|i| CoreError::Unexpected(format!("RDF graph init error {}", i)))?;
            let mut entries = convert_kv(md.entries());
            graph
                .storage
                .copy_entries(&mut entries)
                .map_err(|i| CoreError::Unexpected(format!("Storage copy error {}", i)))?;
            Ok(graph)
        })
    }

    /// Iterate over statements contained in this graph
    pub fn iter(&self) -> ModelIter {
        self.model.iter()
    }
}

fn convert_entry_actions(eas: &[EntryAction]) -> BTreeMap<Vec<u8>, MDEntryAction> {
    println!("{:?}", eas);

    eas.iter()
        .fold(BTreeMap::new(), |mut map, ea| match ea {
            EntryAction::Insert(id, key, data) => {
                map.entry(key.clone())
                    .or_insert_with(Vec::new)
                    .push((id, data.clone()));
                map
            }
            EntryAction::Delete(_id, _key) => map, // TODO: fix deletion
                                                   // EntryAction::Delete(_id, key) => (key.clone(), MDEntryAction::Del(1)),
        })
        .into_iter()
        .map(|(key, val)| {
            (
                key,
                MDEntryAction::Ins(Value {
                    content: unwrap!(serialise(&val)),
                    entry_version: 0,
                }),
            )
        })
        .collect()
}

fn convert_kv(md_kv: &BTreeMap<Vec<u8>, Value>) -> Vec<EntryAction> {
    println!("{:?}", md_kv);

    md_kv
        .iter()
        .flat_map(|(key, value)| {
            let vals: Vec<(i32, Vec<u8>)> = unwrap!(deserialise(&value.content));
            let key2 = key.clone();
            vals.into_iter()
                .map(move |(id, data)| EntryAction::Insert(id, key2.clone(), data))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::RdfGraph;
    use crate::{Client, MDataInfo};
    use futures::Future;
    use redland_rs::{Node, Statement, Uri};
    use routing::MutableData;
    use utils::test_utils::random_client;

    // Test storing RDF triples in Mutable Data on the network.
    #[test]
    fn mdata_storage() {
        // Create a MD address for storing the resource.
        let resource = unwrap!(MDataInfo::random_public(50));
        let resource2 = resource.clone();

        // Store RDF graph on the network.
        random_client(move |client| {
            // Create a new graph.
            let mut rdf = unwrap!(RdfGraph::new());

            let uri1 = unwrap!(Uri::new(rdf.world(), "https://localhost/#dolly"));
            let uri2 = unwrap!(Uri::new(rdf.world(), "https://localhost/#hears"));

            let mut triple1 = unwrap!(Statement::new(rdf.world()));
            triple1.set_subject(unwrap!(Node::new_from_uri(rdf.world(), &uri1)));
            triple1.set_predicate(unwrap!(Node::new_from_uri(rdf.world(), &uri2)));
            triple1.set_object(unwrap!(Node::new_from_literal(
                rdf.world(),
                "hello",
                None,
                false
            )));

            let mut triple2 = unwrap!(Statement::new(rdf.world()));
            triple2.set_subject(unwrap!(Node::new_from_uri(rdf.world(), &uri1)));
            triple2.set_predicate(unwrap!(Node::new_from_uri(rdf.world(), &uri2)));
            triple2.set_object(unwrap!(Node::new_from_literal(
                rdf.world(),
                "goodbye",
                None,
                false
            )));

            {
                let model = rdf.model_mut();
                unwrap!(model.add_statement(&triple1));
                unwrap!(model.add_statement(&triple2));
            }

            let client2 = client.clone();

            let new_md = unwrap!(MutableData::new(
                resource.name,
                resource.type_tag,
                btree_map![],
                btree_map![],
                btree_set![unwrap!(client.owner_key())],
            ));

            client
                .put_mdata(new_md)
                .and_then(move |_| rdf.store(client2, &resource))
        });

        // Load RDF graph from the network.
        random_client(move |client| {
            RdfGraph::load(client.clone(), &resource2).and_then(move |rdf| {
                let mut iter = rdf.iter();

                let stmt = iter.next();
                println!("{:?}", stmt);

                let stmt = iter.next();
                println!("{:?}", stmt);

                assert!(iter.next().is_none());
                Ok(())
            })
        });
    }
}

/*
/// Contains common functions for `Subject`, `Object`, and `Predicate`.
pub trait Node {}

/// Subject part of an RDF node
pub enum Subject {}
impl Node for Subject {}

/// Object part of an RDF node
pub enum Object {}
impl Node for Object {}

/// Predicate part of an RDF node
pub enum Predicate {}
impl Node for Predicate {}

/// RDF triple
pub struct Triple(Subject, Object, Predicate);

impl From<&Statement> for Triple {
    fn from() -> Self {}
}
*/
