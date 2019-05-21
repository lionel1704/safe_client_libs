// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::errors::CoreError;
use crate::rdf::RdfGraph;
use redland_rs::{Parser, Serializer, Uri};

trait RdfSerialization {
    fn serialise(model: &mut RdfGraph) -> Result<String, CoreError>;
    fn deserialise(source: &str) -> Result<RdfGraph, CoreError>;
}

#[allow(unused)]
struct Turtle;
#[allow(unused)]
struct JsonLd;

fn common_serialise(serialiser: Serializer, graph: &mut RdfGraph) -> Result<String, CoreError> {
    let model = graph.model_mut();
    serialiser
        .serialize_model_to_string(&model)
        .map_err(|_| CoreError::from("Cannot serialize model into string!"))
}

fn common_deserialise(parser: Parser, source: &str) -> Result<RdfGraph, CoreError> {
    let mut graph = unwrap!(RdfGraph::new());
        let model = graph.model_mut();
        let base_uri = unwrap!(Uri::new("http://localhost:8080/#")); // why do we need this? the next line throws an error if `None` is passed :(
        let mut namespaces = unwrap!(Parser::parse_string(
            parser,
            source,
            Some(&base_uri),
            &model
        ));
        graph.namespaces_mut().append(&mut namespaces);
        Ok(graph)
}

impl RdfSerialization for Turtle {
    fn serialise(graph: &mut RdfGraph) -> Result<String, CoreError> {
        // TODO: Replace `unwrap` with `?` once error handling is implemented
        let serialiser = unwrap!(Serializer::new("turtle", None, None));
        let mut graph2 = graph.clone();
        let namespaces = graph2.namespaces_mut();
        let _: Vec<_> = namespaces.into_iter().map(|(prefix, uri)| {
             unwrap!(serialiser.set_namespace(&uri, prefix.as_str()));
             }).collect();
        common_serialise(serialiser, graph)
    }

    fn deserialise(source: &str) -> Result<RdfGraph, CoreError> {
        // TODO: Replace `unwrap` with `?` once error handling is implemented
        let parser = unwrap!(Parser::new("text/turtle"));
        common_deserialise(parser, source)
    }
}

impl RdfSerialization for JsonLd {
    fn serialise(graph: &mut RdfGraph) -> Result<String, CoreError> {
        // TODO: Replace `unwrap` with `?` once error handling is implemented
        let serialiser = unwrap!(Serializer::new("json", None, None));
        common_serialise(serialiser, graph)
    }

    fn deserialise(source: &str) -> Result<RdfGraph, CoreError> {
        // TODO: Replace `unwrap` with `?` once error handling is implemented
        let parser = unwrap!(Parser::new("application/json"));
        common_deserialise(parser, source)
    }
}

#[cfg(test)]
mod tests {

    use super::{JsonLd, RdfSerialization, Turtle};

    #[test]
    pub fn turtle_serialisation() {
        let turtle_string = r#"
        @prefix vcard: <http://www.w3.org/2006/vcard/ns#> .
        @prefix sn: <http://www.snee.com/hr/> .

        sn:emp1   vcard:given-name   "Heidi" .
        sn:emp1   vcard:family-name   "Smith" .
        sn:emp1   vcard:title   "CEO" .
        sn:emp1   sn:hireDate   "2015-01-13" .
        sn:emp1   sn:completedOrientation   "2015-01-30" .

        sn:emp2   vcard:given-name   "John" .
        sn:emp2   vcard:family-name   "Smith" .
        sn:emp2   sn:hireDate   "2015-01-28" .
        sn:emp2   vcard:title   "Engineer" .
        sn:emp2   sn:completedOrientation   "2015-01-30" .
        sn:emp2   sn:completedOrientation   "2015-03-15" .

        sn:emp3   vcard:given-name   "Francis" .
        sn:emp3   vcard:family-name   "Jones" .
        sn:emp3   sn:hireDate   "2015-02-13" .
        sn:emp3   vcard:title   "Vice President" .

        sn:emp4   vcard:given-name   "Jane" .
        sn:emp4   vcard:family-name   "Berger" .
        sn:emp4   sn:hireDate   "2015-03-10" .
        sn:emp4   vcard:title   "Sales" ."#;

        let mut graph = unwrap!(Turtle::deserialise(turtle_string));
        {
            let mut iter =  graph.iter();
            let mut x = 0;
            assert_eq!(graph.len(), 19);
            while x < graph.len() {
                assert!(iter.next().is_some());
                x += 1;
            }
            assert!(iter.next().is_none())
        }E

        let json_string_output = unwrap!(JsonLd::serialise(&mut graph));
        println!("OUTPUT:\n{}", json_string_output);

        let mut another_graph = unwrap!(JsonLd::deserialise(&json_string_output));
        {
            let mut iter =  graph.iter();
            let mut x = 0;
            assert_eq!(graph.len(), 19);
            while x < graph.len() {
                assert!(iter.next().is_some());
                x += 1;
            }
            assert!(iter.next().is_none())
        }
        let turtle_string_output = unwrap!(Turtle::serialise(&mut another_graph));
        println!("OUTPUT:\n{}", turtle_string_output);
    }

}
