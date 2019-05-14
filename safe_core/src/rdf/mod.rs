// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Client, CoreError, MDataInfo};
use futures::Future;
// use hex_fmt::HexFmt;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use redland_rs::{EntryAction, KvStorage, Model, ModelIter};
use routing::{EntryAction as MDEntryAction, Value};
use std::collections::BTreeMap;

/// Represents an abstract RDF graph model
pub struct RdfGraph {
    /// Holds the internal state of the RDF graph
    model: Model,
    /// Holds internal triples storage
    storage: KvStorage,
}

impl RdfGraph {
    /// Create a new RDF graph
    pub fn new() -> Result<Self, i32> {
        let storage = KvStorage::new()?;
        let model = Model::new(&storage)?;
        Ok(RdfGraph { model, storage })
    }

    /// Get RDF model
    pub fn model_mut(&mut self) -> &mut Model {
        &mut self.model
    }

    /// Get RDF storage
    pub fn storage(&mut self) -> &mut KvStorage {
        &mut self.storage
    }

    /// Store an RDF graph on the network
    pub fn store(
        &self,
        client: impl Client,
        md_info: &MDataInfo,
    ) -> impl Future<Item = (), Error = CoreError> {
        let client2 = client.clone();
        let md_info2 = md_info.clone();
        let entry_actions = self.storage.entry_actions().to_vec();
        client
            .list_mdata_entries(md_info.name, md_info.type_tag)
            .and_then(move |entries| {
                let actions = convert_entry_actions(&entry_actions, &entries);
                client2.mutate_mdata_entries(md_info2.name, md_info2.type_tag, actions)
            })
            .map_err(CoreError::from)
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

/// Actions on Redland hashes (key-value pairs)
#[derive(Default)]
pub struct MDataEntryActions {
    /// Insert a new key-value pair
    insertions: Vec<(i32, Vec<u8>)>,
    /// Remove a single value from a key
    deletions: Vec<(i32, Vec<u8>)>,
}

impl MDataEntryActions {
    fn insert(&mut self, id: i32, data: Vec<u8>) {
        self.insertions.push((id, data));
    }

    fn delete(&mut self, id: i32, data: Vec<u8>) {
        self.deletions.push((id, data));
    }
}

fn convert_entry_actions(
    eas: &[EntryAction],
    entries: &BTreeMap<Vec<u8>, Value>,
) -> BTreeMap<Vec<u8>, MDEntryAction> {
    eas.iter()
        .fold(
            BTreeMap::<Vec<u8>, MDataEntryActions>::new(),
            |mut map, ea| {
                // println!("{}", ea);
                match ea {
                    EntryAction::Insert(id, key, data) => {
                        map.entry(key.clone())
                            .or_insert_with(Default::default)
                            .insert(*id, data.clone());
                        map
                    }
                    EntryAction::Delete(id, key, data) => {
                        map.entry(key.clone())
                            .or_insert_with(Default::default)
                            .delete(*id, data.clone());
                        map
                    }
                }
            },
        )
        .into_iter()
        .map(|(key, mut val)| match entries.get(&key) {
            Some(value) => {
                let mut list: Vec<_> = unwrap!(deserialise(&value.content));
                list.append(&mut val.insertions);
                let _: Vec<_> = val
                    .deletions
                    .iter()
                    .map(|i| {
                        let index = list.iter_mut().position(|x| x.1 == i.1).unwrap();
                        list.remove(index)
                    })
                    .collect();
                (
                    key,
                    MDEntryAction::Update(Value {
                        content: unwrap!(serialise(&list)),
                        entry_version: value.entry_version + 1,
                    }),
                )
            }
            None => {
                let mut list: Vec<_> = Vec::new();
                list.append(&mut val.insertions);
                let _: Vec<_> = val
                    .deletions
                    .iter()
                    .map(|i| {
                        let index = list.iter_mut().position(|x| x.1 == i.1).unwrap();
                        list.remove(index)
                    })
                    .collect();
                (
                    key,
                    MDEntryAction::Ins(Value {
                        content: unwrap!(serialise(&list)),
                        entry_version: 0,
                    }),
                )
            }
        })
        .collect()
}

fn convert_kv(md_kv: &BTreeMap<Vec<u8>, Value>) -> Vec<EntryAction> {
    md_kv
        .iter()
        .filter(|(_, v)| v.content.len() > 0)
        .flat_map(|(key, value)| {
            // println!(
            //     "key : {} -- value : {} -- version : {}",
            //     HexFmt(key),
            //     HexFmt(&value.content),
            //     value.entry_version
            // );
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
    use crate::utils::test_utils::random_client;
    use crate::{Client, MDataInfo};
    use futures::Future;
    use redland_rs::{Node, Statement, Uri};
    use routing::{Action, MutableData, PermissionSet, User};
    use std::collections::BTreeMap;

    // Test storing RDF triples in Mutable Data on the network.
    #[test]
    fn mdata_storage() {
        // Create a MD address for storing the resource.
        let resource = unwrap!(MDataInfo::random_public(50));
        let resource2 = resource.clone();
        let resource3 = resource.clone();
        let resource4 = resource.clone();
        let resource5 = resource.clone();

        // Store RDF graph on the network.
        random_client(move |client| {
            // Create a new graph.
            let mut rdf = unwrap!(RdfGraph::new());

            let sub1 = unwrap!(Uri::new("dolly"));

            let pred1 = unwrap!(Uri::new("says"));

            let obj1 = unwrap!(Uri::new("hi"));
            let obj2 = unwrap!(Uri::new("bye"));

            let mut triple1 = unwrap!(Statement::new());
            triple1.set_subject(unwrap!(Node::new_from_uri(&sub1)));
            triple1.set_predicate(unwrap!(Node::new_from_uri(&pred1)));
            triple1.set_object(unwrap!(Node::new_from_uri(&obj1)));

            let mut triple2 = unwrap!(Statement::new());
            triple2.set_subject(unwrap!(Node::new_from_uri(&sub1)));
            triple2.set_predicate(unwrap!(Node::new_from_uri(&pred1)));
            triple2.set_object(unwrap!(Node::new_from_literal("high-five!", None, false)));

            let mut triple3 = unwrap!(Statement::new());
            triple3.set_subject(unwrap!(Node::new_from_uri(&sub1)));
            triple3.set_predicate(unwrap!(Node::new_from_uri(&pred1)));
            triple3.set_object(unwrap!(Node::new_from_uri(&obj2)));

            {
                let model = rdf.model_mut();
                unwrap!(model.add_statement(&triple1));
                unwrap!(model.add_statement(&triple2));
                unwrap!(model.add_statement(&triple3));
            }

            let client2 = client.clone();

            let mut permissions = BTreeMap::new();
            let _ = permissions.insert(
                User::Anyone,
                PermissionSet::new()
                    .allow(Action::Insert)
                    .allow(Action::Delete)
                    .allow(Action::Update),
            );

            let new_md = unwrap!(MutableData::new(
                resource.name,
                resource.type_tag,
                permissions,
                btree_map![],
                btree_set![unwrap!(client.owner_key())],
            ));

            // Store the graph on the network
            client
                .put_mdata(new_md)
                .and_then(move |_| rdf.store(client2, &resource))
        });

        // Load RDF graph from the network.
        random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            RdfGraph::load(client2, &resource2).and_then(move |mut rdf| {
                {
                    let mut iter = rdf.iter();

                    let stmt = iter.next();
                    println!("1. {:?}", stmt);

                    let stmt = iter.next();
                    println!("2. {:?}", stmt);

                    let stmt = iter.next();
                    println!("3. {:?}", stmt);

                    assert!(iter.next().is_none());
                }

                let sub = unwrap!(Uri::new("dolly"));
                let pred = unwrap!(Uri::new("says"));
                let obj = unwrap!(Uri::new("bye"));

                let mut triple1 = unwrap!(Statement::new());
                triple1.set_subject(unwrap!(Node::new_from_uri(&sub)));
                triple1.set_predicate(unwrap!(Node::new_from_uri(&pred)));
                triple1.set_object(unwrap!(Node::new_from_uri(&obj)));

                // Remove a triple from the graph and store it on the network
                let model = rdf.model_mut();
                unwrap!(model.remove_statement(&triple1));
                rdf.store(client3, &resource3)
            })
        });

        // Reload the graph from the network and verify the deletion
        random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            RdfGraph::load(client2, &resource4).and_then(move |mut rdf| {
                {
                    println!("Afer deletion:");
                    let mut iter = rdf.iter();

                    let stmt = iter.next();
                    println!("1. {:?}", stmt);

                    let stmt = iter.next();
                    println!("2. {:?}", stmt);

                    assert!(iter.next().is_none());
                }

                let sub = unwrap!(Uri::new("dolly"));
                let pred = unwrap!(Uri::new("says"));
                let obj = unwrap!(Uri::new("bye"));

                let mut triple1 = unwrap!(Statement::new());
                triple1.set_subject(unwrap!(Node::new_from_uri(&sub)));
                triple1.set_predicate(unwrap!(Node::new_from_uri(&pred)));
                triple1.set_object(unwrap!(Node::new_from_uri(&obj)));

                // Add the removed triple back to the graph.
                // An existing key should be reused.
                {
                    let model = rdf.model_mut();
                    unwrap!(model.add_statement(&triple1));
                    rdf.store(client3, &resource4)
                }
            })
        });

        // Reload the graph from the network and verify
        random_client(move |client| {
            let client2 = client.clone();
            RdfGraph::load(client2, &resource5).and_then(move |rdf| {
                {
                    println!("Re-addition:");
                    let mut iter = rdf.iter();

                    let stmt = iter.next();
                    println!("1. {:?}", stmt);

                    let stmt = iter.next();
                    println!("2. {:?}", stmt);

                    let stmt = iter.next();
                    println!("3. {:?}", stmt);

                    assert!(iter.next().is_none());
                }
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
