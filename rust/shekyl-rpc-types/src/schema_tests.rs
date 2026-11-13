// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tests of the schema interpreter. They live beside the model so that
//! file stays the shapes, and a child module still sees the private walk.

use super::{walk, Walk};
use crate::method::Policy;

use super::*;
use crate::kinds::{Count, Done, Endpoint, Height, NoParams, Withheld};
use crate::nullable::Nullable;
use crate::wire_object;
use serde_json::json;
use shekyl_rpc_grants::Grant;

wire_object! {
    /// A header, as a test sees it.
    ["block header"]
    pub struct Header {
        pub height: Height,
        pub hash: crate::hash::HashHex,
        pub pow: Nullable<crate::hash::HashHex>,
    }
}

wire_object! {
    ["block"]
    pub struct Select {
        pub height: Vec<Height>,
        pub prune ["tx"]: bool,
    }
}

wire_object! {
    ["txpool"]
    pub struct Pool {
        pub count: Count,
        #[serde(default, skip_serializing_if = "Withheld::is_withheld")]
        pub private_count [shown Policy::HostOnly]: Withheld<Count>,
    }
}

fn row() -> crate::method::Row {
    crate::method::Row {
        name: "block_header_list",
        policy: Policy::Grant(Grant::Chain),
        request: Select::shape,
        reply: <Vec<Header>>::shape,
    }
}

fn pool_row() -> crate::method::Row {
    crate::method::Row {
        name: "txpool_stats",
        policy: Policy::Grant(Grant::Pool),
        request: NoParams::shape,
        reply: Pool::shape,
    }
}

/// A field's name is its identifier, its holder is the object's, and a
/// modifier walks under the holder it names. Red edit: drop `under`
/// from the walk and `prune` walks under `block`.
#[test]
fn every_name_carries_the_holder_its_walk_starts_from() {
    let walked: Vec<(NameKind, &str, &str)> = names(&[row()])
        .into_iter()
        .map(|name| (name.kind, name.holder, name.name))
        .collect();
    assert_eq!(
        walked,
        [
            (NameKind::Method, "", "block_header_list"),
            (NameKind::Parameter, "block", "height"),
            (NameKind::Parameter, "tx", "prune"),
            (NameKind::Field, "block header", "height"),
            (NameKind::Field, "block header", "hash"),
            (NameKind::Field, "block header", "pow"),
        ]
    );
}

/// The schema records who is shown each field: the method's policy,
/// or the hidden field's own. Red edit: walk a hidden field with the
/// method's policy.
#[test]
fn a_hidden_field_names_who_is_shown_it() {
    let text = render(&[pool_row()]);
    assert!(
        text.contains("txpool_stats\tfield\ttxpool\tcount\tpool\tcount\n"),
        "{text}"
    );
    assert!(
        text.contains("txpool_stats\tfield\ttxpool\tprivate_count\thost-only\tcount\n"),
        "{text}"
    );
}

/// A withheld field is absent, a shown one is written, and both read
/// back; the shape admits both documents and refuses a `null` in the
/// field's place.
#[test]
fn a_withheld_field_is_absent_and_never_null() {
    let withheld = Pool {
        count: Count(3),
        private_count: Withheld::Withheld,
    };
    let shown = Pool {
        count: Count(3),
        private_count: Withheld::Shown(Count(1)),
    };
    let withheld_doc = serde_json::to_value(&withheld).unwrap();
    let shown_doc = serde_json::to_value(&shown).unwrap();
    assert_eq!(withheld_doc, json!({"count": 3}));
    assert_eq!(shown_doc, json!({"count": 3, "private_count": 1}));
    assert_eq!(
        serde_json::from_value::<Pool>(withheld_doc.clone()).unwrap(),
        withheld
    );
    assert_eq!(
        serde_json::from_value::<Pool>(shown_doc.clone()).unwrap(),
        shown
    );
    conforms(&withheld_doc, &Pool::shape()).unwrap();
    conforms(&shown_doc, &Pool::shape()).unwrap();
    assert!(conforms(&json!({"count": 3, "private_count": null}), &Pool::shape()).is_err());
}

/// The struct the macro writes refuses an unknown key and a missing
/// one, and writes an unanswered field as `null`.
#[test]
fn a_wire_object_is_strict_and_writes_null_for_no_answer() {
    let header: Header = serde_json::from_value(json!({
        "height": 7,
        "hash": "00".repeat(32),
        "pow": null,
    }))
    .expect("a header");
    assert_eq!(
        serde_json::to_value(&header).unwrap()["pow"],
        serde_json::Value::Null
    );
    assert!(serde_json::from_value::<Header>(json!({
        "height": 7, "hash": "00".repeat(32), "pow": null, "extra": 1,
    }))
    .is_err());
    assert!(serde_json::from_value::<Header>(json!({
        "height": 7, "hash": "00".repeat(32),
    }))
    .is_err());
}

/// What serde writes for a wire object conforms to its shape, and the
/// shape refuses what serde refuses. Both directions.
#[test]
fn a_shape_and_its_serde_agree_in_both_directions() {
    let shape = Header::shape();
    let good = json!({"height": 7, "hash": "ab".repeat(32), "pow": null});
    conforms(&good, &shape).unwrap();
    assert!(serde_json::from_value::<Header>(good).is_ok());
    for bad in [
        json!({"height": 7, "hash": "ab".repeat(32)}),
        json!({"height": 7, "hash": "ab".repeat(32), "pow": null, "extra": 1}),
        json!({"height": "7", "hash": "ab".repeat(32), "pow": null}),
        json!({"height": 7, "hash": "ab", "pow": null}),
        json!([7]),
        json!(null),
    ] {
        assert!(conforms(&bad, &shape).is_err(), "{bad}");
        assert!(
            serde_json::from_value::<Header>(bad.clone()).is_err(),
            "{bad}"
        );
    }
}

/// The hand-written shapes: a state is exactly one key, a map's keys
/// are closed, a part is whole or absent, a slot is the item or its
/// stand-in.
#[test]
fn conforms_holds_states_maps_parts_and_slots() {
    let states = Shape::States(vec![("live", None), ("halted", Some(Header::shape()))]);
    conforms(&json!({"live": null}), &states).unwrap();
    assert!(conforms(&json!({"live": 1}), &states).is_err());
    assert!(conforms(&json!({"live": null, "halted": null}), &states).is_err());
    assert!(conforms(&json!({"dead": null}), &states).is_err());
    assert!(conforms(&json!("live"), &states).is_err());

    let map = Shape::Map {
        keys: Some(&["clearnet", "tor"]),
        value: Box::new(Shape::Scalar("count")),
    };
    conforms(&json!({"tor": 2}), &map).unwrap();
    conforms(&json!({}), &map).unwrap();
    assert!(conforms(&json!({"i2p": 2}), &map).is_err());

    let parted = Shape::Object {
        holder: "daemon",
        fields: vec![Field {
            name: "height",
            under: None,
            shape: Shape::Scalar("height"),
        }],
        parts: vec![Part {
            shown_to: Policy::Grant(Grant::Status),
            fields: vec![
                Field {
                    name: "started",
                    under: None,
                    shape: Shape::Scalar("time"),
                },
                Field {
                    name: "revision",
                    under: None,
                    shape: Shape::Scalar("text"),
                },
            ],
        }],
        choice: vec![],
    };
    conforms(&json!({"height": 1}), &parted).unwrap();
    conforms(
        &json!({"height": 1, "started": 5, "revision": "x"}),
        &parted,
    )
    .unwrap();
    assert!(conforms(&json!({"height": 1, "started": 5}), &parted).is_err());

    let slot = Shape::Either(
        Box::new(Shape::Scalar("hash")),
        Box::new(Shape::Nullable(Box::new(Shape::States(vec![(
            "missing", None,
        )])))),
    );
    conforms(&json!("cd".repeat(32)), &slot).unwrap();
    conforms(&json!({"missing": null}), &slot).unwrap();
    conforms(&json!(null), &slot).unwrap();
    assert!(conforms(&json!({"lost": null}), &slot).is_err());
}

/// No parameters is `{}`, and bare success is `{}`: never `null`,
/// which means no answer, never a list, never a key.
#[test]
fn no_parameters_and_bare_success_are_empty_objects() {
    assert_eq!(serde_json::to_value(NoParams).unwrap(), json!({}));
    assert_eq!(serde_json::to_value(Done).unwrap(), json!({}));
    assert!(serde_json::from_value::<NoParams>(json!({})).is_ok());
    assert!(serde_json::from_value::<Done>(json!({})).is_ok());
    for bad in [json!(null), json!([]), json!({"a": 1}), json!(0)] {
        assert!(
            serde_json::from_value::<NoParams>(bad.clone()).is_err(),
            "{bad}"
        );
        assert!(
            serde_json::from_value::<Done>(bad.clone()).is_err(),
            "{bad}"
        );
        assert!(conforms(&bad, &NoParams::shape()).is_err(), "{bad}");
    }
    assert_eq!(NoParams::from_params(None), Ok(NoParams));
    assert_eq!(NoParams::from_params(Some(&json!({}))), Ok(NoParams));
    assert!(NoParams::from_params(Some(&json!(null))).is_err());
}

wire_object! {
    ["peer connection"]
    pub struct WrongAddress {
        pub address: Endpoint,
    }
}

wire_object! {
    ["sync session"]
    pub struct WrongHeight {
        pub claimed_height: Count,
    }
}

/// A name states what it holds. The red edits the brief names: an
/// `address` holding an endpoint, and a `…_height` holding a count.
#[test]
fn a_name_whose_kind_is_not_its_terms_is_refused() {
    assert!(kind_faults(&[row(), pool_row()]).is_empty());
    let wrong = |reply: fn() -> Shape| crate::method::Row {
        name: "peer_connections",
        policy: Policy::Grant(Grant::Peers),
        request: NoParams::shape,
        reply,
    };
    let address = kind_faults(&[wrong(WrongAddress::shape)]);
    assert_eq!(address.len(), 1, "{address:?}");
    assert!(address[0].contains("`address`") && address[0].contains("endpoint"));
    let height = kind_faults(&[wrong(WrongHeight::shape)]);
    assert_eq!(height.len(), 1, "{height:?}");
    assert!(height[0].contains("`claimed_height`") && height[0].contains("holds count"));
}

fn selector() -> Shape {
    Shape::Object {
        holder: "block",
        fields: vec![Field {
            name: "pow",
            under: Some("block header"),
            shape: Shape::Optional(Box::new(Shape::Scalar("switch"))),
        }],
        parts: vec![],
        choice: vec![
            vec![Field {
                name: "height",
                under: None,
                shape: Shape::Scalar("height"),
            }],
            vec![Field {
                name: "hash",
                under: None,
                shape: Shape::Scalar("hash"),
            }],
            vec![Field {
                name: "tip",
                under: None,
                shape: Shape::Null,
            }],
        ],
    }
}

/// A selector is exactly one key (IG-Q94): none and two are refused,
/// and a switch beside it may be left out. Red edit: accept an empty
/// choice, and the first `is_err` below fails.
#[test]
fn a_selector_is_exactly_one_key() {
    let shape = selector();
    conforms(&json!({"height": 7}), &shape).unwrap();
    conforms(&json!({"height": 7, "pow": true}), &shape).unwrap();
    conforms(&json!({"tip": null}), &shape).unwrap();
    assert!(conforms(&json!({"tip": {}}), &shape).is_err());
    assert!(conforms(&json!({"pow": true}), &shape).is_err());
    assert!(conforms(&json!({}), &shape).is_err());
    assert!(conforms(&json!({"height": 7, "hash": "ab".repeat(32)}), &shape).is_err());
    assert!(conforms(&json!({"height": 7, "depth": 1}), &shape).is_err());
}

/// A range is one alternative wholly: `from` and `to` together, or
/// `hash`, and a switch beside either. Red edit: treat the two ends
/// as independent optionals, and `from` alone is admitted.
#[test]
fn an_alternative_is_wholly_present_or_absent() {
    let shape = Shape::Object {
        holder: "block",
        fields: vec![Field {
            name: "pow",
            under: Some("block header"),
            shape: Shape::Optional(Box::new(Shape::Scalar("switch"))),
        }],
        parts: vec![],
        choice: vec![
            vec![
                Field {
                    name: "from",
                    under: None,
                    shape: Shape::Scalar("height"),
                },
                Field {
                    name: "to",
                    under: None,
                    shape: Shape::Scalar("height"),
                },
            ],
            vec![Field {
                name: "hash",
                under: None,
                shape: Shape::List(Box::new(Shape::Scalar("hash"))),
            }],
        ],
    };
    conforms(&json!({"from": 1, "to": 4, "pow": false}), &shape).unwrap();
    conforms(&json!({"hash": ["ab".repeat(32)], "pow": true}), &shape).unwrap();
    for bad in [
        json!({"from": 1, "pow": false}),
        json!({"from": 1, "to": 4, "hash": ["ab".repeat(32)], "pow": false}),
        json!({"pow": false}),
        json!({}),
        json!({"to": 4, "hash": ["ab".repeat(32)]}),
    ] {
        assert!(conforms(&bad, &shape).is_err(), "{bad}");
    }
}

/// An optional field is a request's; in a reply it is a fault. Red
/// edit: drop the `in_reply` check in `kind_faults`.
#[test]
fn an_optional_field_is_refused_in_a_reply() {
    let row = |request: fn() -> Shape, reply: fn() -> Shape| crate::method::Row {
        name: "block_header_show",
        policy: Policy::Grant(Grant::Chain),
        request,
        reply,
    };
    assert!(kind_faults(&[row(selector, Header::shape)]).is_empty());
    let faults = kind_faults(&[row(NoParams::shape, selector)]);
    assert_eq!(faults.len(), 1, "{faults:?}");
    assert!(faults[0].contains("optional in a reply"));
}

/// A subject-keyed map's object value walks under each key, and a tag
/// names which fields follow it.
#[test]
fn a_subject_keyed_map_walks_under_each_key_and_a_tag_selects_fields() {
    let counts = Shape::Map {
        keys: Some(&["clearnet", "tor"]),
        value: Box::new(Shape::Object {
            holder: "connector",
            fields: vec![Field {
                name: "inbound_count",
                under: None,
                shape: Shape::Scalar("count"),
            }],
            parts: vec![],
            choice: vec![],
        }),
    };
    let mut out = Vec::new();
    let mut w = Walk {
        method: "daemon_status",
        in_reply: true,
        out: &mut out,
    };
    walk(
        &mut w,
        NameKind::Field,
        Policy::Grant(Grant::Peers),
        &counts,
    );
    let holders: Vec<&str> = out.iter().map(|name| name.holder).collect();
    assert_eq!(holders, ["clearnet", "tor"]);

    let verdict = Shape::Tagged {
        holder: "tx",
        tag: "verdict",
        variants: vec![
            ("accepted", vec![]),
            (
                "already-in-chain",
                vec![Field {
                    name: "mined_height",
                    under: None,
                    shape: Shape::Scalar("height"),
                }],
            ),
        ],
    };
    conforms(&json!({"verdict": "accepted"}), &verdict).unwrap();
    conforms(
        &json!({"verdict": "already-in-chain", "mined_height": 4}),
        &verdict,
    )
    .unwrap();
    assert!(conforms(&json!({"verdict": "accepted", "mined_height": 4}), &verdict).is_err());
    assert!(conforms(&json!({"verdict": "already-in-chain"}), &verdict).is_err());
    assert!(conforms(&json!({"verdict": "lost"}), &verdict).is_err());
}
