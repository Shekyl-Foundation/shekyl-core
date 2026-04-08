// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Integration tests for the wallet-level FROST multisig orchestration.
//!
//! Tests cover:
//! - `MultisigDkgSession` full roundtrip (3-of-5 group)
//! - `MultisigGroup` serialization/deserialization
//! - `MultisigGroup` PQC keypair management
//! - DKG session state machine error handling

use std::collections::HashMap;

use modular_frost::Participant;
use shekyl_fcmp::frost_dkg::{DkgRound1Message, DkgRound2Message};

use super::dkg::MultisigDkgSession;
use super::group::MultisigGroup;

fn run_dkg(threshold: u16, total: u16) -> Vec<MultisigGroup> {
    let context = [0xABu8; 32];
    let mut sessions: Vec<MultisigDkgSession> = (1..=total)
        .map(|i| MultisigDkgSession::new(threshold, total, i, context).unwrap())
        .collect();

    let round1_msgs: Vec<DkgRound1Message> =
        sessions.iter_mut().map(|s| s.round1().unwrap()).collect();

    let mut round2_outgoing: Vec<HashMap<Participant, DkgRound2Message>> =
        Vec::with_capacity(total as usize);
    for i in 0..total as usize {
        let others: HashMap<Participant, DkgRound1Message> = round1_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(j, msg)| (Participant::new((j + 1) as u16).unwrap(), msg.clone()))
            .collect();
        let shares = sessions[i].round2(others).unwrap();
        round2_outgoing.push(shares);
    }

    for i in 0..total as usize {
        let p = Participant::new((i + 1) as u16).unwrap();
        let my_shares: HashMap<Participant, DkgRound2Message> = round2_outgoing
            .iter()
            .enumerate()
            .filter_map(|(j, shares_map)| shares_map.get(&p).map(|s| {
                (Participant::new((j + 1) as u16).unwrap(), s.clone())
            }))
            .collect();
        sessions[i].process_shares(my_shares).unwrap();
    }

    sessions
        .into_iter()
        .map(|mut s| s.finalize().unwrap())
        .collect()
}

#[test]
fn dkg_roundtrip_2_of_3() {
    let groups = run_dkg(2, 3);
    assert_eq!(groups.len(), 3);

    let key0 = groups[0].group_public_key().unwrap();
    for g in &groups[1..] {
        assert_eq!(g.group_public_key().unwrap(), key0);
    }
    for g in &groups {
        assert_eq!(g.threshold, 2);
        assert_eq!(g.total, 3);
    }
}

#[test]
fn dkg_roundtrip_3_of_5() {
    let groups = run_dkg(3, 5);
    assert_eq!(groups.len(), 5);

    let key0 = groups[0].group_public_key().unwrap();
    for g in &groups[1..] {
        assert_eq!(g.group_public_key().unwrap(), key0);
    }
}

#[test]
fn group_serialization_roundtrip() {
    let groups = run_dkg(2, 3);
    let group = &groups[0];

    let json = serde_json::to_string(group).unwrap();
    let restored: MultisigGroup = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.group_id, group.group_id);
    assert_eq!(restored.threshold, group.threshold);
    assert_eq!(restored.total, group.total);
    assert_eq!(restored.our_index, group.our_index);
    assert_eq!(
        restored.group_public_key().unwrap(),
        group.group_public_key().unwrap()
    );
}

#[test]
fn group_pqc_keypair() {
    let mut groups = run_dkg(2, 3);
    let group = &mut groups[0];

    assert!(group.pqc_public_key.is_empty());
    assert!(group.pqc_secret_key().is_empty());

    let fake_pk = vec![1u8; 32];
    let fake_sk = vec![2u8; 64];
    group.set_pqc_keypair(fake_pk.clone(), fake_sk.clone());

    assert_eq!(group.pqc_public_key, fake_pk);
    assert_eq!(group.pqc_secret_key(), &fake_sk);

    let json = serde_json::to_string(group).unwrap();
    let restored: MultisigGroup = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.pqc_public_key, fake_pk);
    assert_eq!(restored.pqc_secret_key(), &fake_sk);
}

#[test]
fn dkg_session_double_round1_fails() {
    let context = [0xCDu8; 32];
    let mut session = MultisigDkgSession::new(2, 3, 1, context).unwrap();
    session.round1().unwrap();
    let result = session.round1();
    assert!(result.is_err(), "Second round1 should fail");
}

#[test]
fn dkg_session_round2_without_round1_fails() {
    let context = [0xCDu8; 32];
    let mut session = MultisigDkgSession::new(2, 3, 1, context).unwrap();
    let result = session.round2(HashMap::new());
    assert!(result.is_err(), "round2 before round1 should fail");
}

#[test]
fn group_threshold_keys_roundtrip() {
    let groups = run_dkg(2, 3);
    let group = &groups[0];

    let keys = group.threshold_keys().deserialize().unwrap();
    assert_eq!(keys.params().t(), 2);
    assert_eq!(keys.params().n(), 3);
}
