// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Known-answer tests for the rendezvous name and the instance rule.
//!
//! The vectors in `docs/test_vectors/RPC_CHANNEL_NAMES_V1/` come from
//! `generate.py` beside them, which carries its own cSHAKE256 and shares no
//! code with this crate. These tests check the crate against the vectors,
//! never the other way round. `shekyl-rpc-channel`'s own test checks the
//! channel's two derivations against the same file.

use serde_json::Value;
use shekyl_rpc_rendezvous::{
    rendezvous_name, Instance, InstanceName, InstanceNameError, DEFAULT_INSTANCE_LABEL,
    INSTANCE_NAME_MAX, NETWORK_ID_LEN, RENDEZVOUS_NAME_LEN,
};

/// The network id, as the vectors give it.
type NetworkId = [u8; NETWORK_ID_LEN];

const VECTORS: &str = include_str!("../../../docs/test_vectors/RPC_CHANNEL_NAMES_V1/vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vectors.json parses")
}

/// A section of the vector file, which must hold at least one case: a test
/// that iterates an empty list passes while checking nothing.
fn section<'a>(root: &'a Value, name: &str) -> &'a Vec<Value> {
    let cases = root[name]
        .as_array()
        .unwrap_or_else(|| panic!("section {name} is missing"));
    assert!(!cases.is_empty(), "section {name} is empty");
    cases
}

fn text<'a>(case: &'a Value, field: &str) -> &'a str {
    case[field]
        .as_str()
        .unwrap_or_else(|| panic!("{case}: no string field {field}"))
}

fn bytes<const N: usize>(case: &Value, field: &str) -> [u8; N] {
    let raw = hex::decode(text(case, field)).expect("hex field decodes");
    raw.try_into()
        .unwrap_or_else(|_| panic!("{field} is not {N} bytes"))
}

fn instance(label: &str) -> Instance {
    if label == DEFAULT_INSTANCE_LABEL {
        Instance::Default
    } else {
        Instance::Named(InstanceName::parse(label).expect("vector instance names are valid"))
    }
}

#[test]
fn rendezvous_name_matches_the_vectors() {
    let root = vectors();
    let mut default_seen = false;
    let mut named_seen = false;
    for case in section(&root, "rendezvous_name") {
        let network_id: NetworkId = bytes(case, "network_id_hex");
        let which = instance(text(case, "instance"));
        default_seen |= which == Instance::Default;
        named_seen |= which != Instance::Default;
        let got = rendezvous_name(&network_id, &which);
        let want = text(&case["expected"], "name_hex");
        assert_eq!(got.to_string(), want, "{}", text(case, "id"));
        assert_eq!(hex::encode(got.as_bytes()), want, "{}", text(case, "id"));
        assert_eq!(want.len(), 2 * RENDEZVOUS_NAME_LEN);
    }
    assert!(
        default_seen && named_seen,
        "vectors cover both instance kinds"
    );
}

#[test]
fn instance_names_follow_the_rule() {
    let root = vectors();
    for name in section(&root, "refused_instance_names") {
        let name = name.as_str().expect("a string");
        assert!(
            InstanceName::parse(name).is_err(),
            "{name:?} must be refused"
        );
    }
    for name in section(&root, "accepted_instance_names") {
        let name = name.as_str().expect("a string");
        let parsed = InstanceName::parse(name).unwrap_or_else(|e| panic!("{name:?}: {e}"));
        assert_eq!(parsed.as_str(), name, "nothing is folded or trimmed");
    }
    // Each rule by its own cause, so a rule cannot be deleted while another
    // happens to refuse the same input.
    assert_eq!(InstanceName::parse(""), Err(InstanceNameError::Empty));
    assert_eq!(
        InstanceName::parse(&"a".repeat(INSTANCE_NAME_MAX + 1)),
        Err(InstanceNameError::TooLong)
    );
    assert_eq!(InstanceName::parse("-a"), Err(InstanceNameError::BadStart));
    assert_eq!(
        InstanceName::parse("a_b"),
        Err(InstanceNameError::BadCharacter)
    );
    assert_eq!(
        InstanceName::parse(DEFAULT_INSTANCE_LABEL),
        Err(InstanceNameError::Reserved)
    );
    assert!(InstanceName::parse(&"a".repeat(INSTANCE_NAME_MAX)).is_ok());
}

/// The refusal's words carry the rule's numbers: the length limit and the
/// reserved label, so a change to either changes what an operator reads.
#[test]
fn the_refusal_states_the_rule_it_enforces() {
    let length = InstanceNameError::TooLong.rule();
    assert!(
        length.contains(&format!("1 to {INSTANCE_NAME_MAX} ")),
        "{length}"
    );
    let reserved = InstanceNameError::Reserved.rule();
    assert!(
        reserved.contains(&format!("`{DEFAULT_INSTANCE_LABEL}`")),
        "{reserved}"
    );
}

/// The default instance and a named one never share a rendezvous, and
/// neither does one name on two networks.
#[test]
fn rendezvous_names_separate_instances_and_networks() {
    let one: NetworkId = [1; NETWORK_ID_LEN];
    let two: NetworkId = [2; NETWORK_ID_LEN];
    let named = Instance::Named(InstanceName::parse("bench").expect("valid"));
    assert_ne!(
        rendezvous_name(&one, &Instance::Default),
        rendezvous_name(&one, &named)
    );
    assert_ne!(
        rendezvous_name(&one, &Instance::Default),
        rendezvous_name(&two, &Instance::Default)
    );
}

/// The network id's length is restated here; it is held equal to its
/// owner's, so a change there fails here.
#[test]
fn the_network_id_length_matches_its_owner() {
    let id: shekyl_network::NetworkId = [0; NETWORK_ID_LEN];
    let _: &[u8; NETWORK_ID_LEN] = &id;
}
