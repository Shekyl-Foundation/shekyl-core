// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The shard frame's entry for a real spend is the spend's two store rows,
//! and the client's checks accept exactly that entry.
//!
//! `rows_of` (serve side, from the segments) and `Transaction::txid_parts`
//! (the chain's rows, from the parsed body) must agree on every
//! transaction, or a fixture built from one would be refused by the other.
//! The spend is the pinned oracle body of `pruned_tx_hash_parity_v1.json`.

use std::path::PathBuf;

use serde_json::Value;
use shekyl_wire::shard_frame::{check_components, check_lengths, rows_of, FrameTx};
use shekyl_wire::{Ct, Transaction};

fn hex_bytes(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex in fixture");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn fixture(rel: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    serde_json::from_str(&std::fs::read_to_string(&path).expect("fixture")).expect("json")
}

#[test]
fn a_real_spends_frame_entry_is_its_two_rows_and_passes_both_checks() {
    let pin = fixture("tests/fixtures/pruned_tx_hash_parity_v1.json");
    let tx = Transaction::from_bytes(&hex_bytes(pin["tx_hex"].as_str().expect("tx_hex")))
        .expect("parse spend");
    let segments = tx.write_segments().expect("segments");
    let Ct::Fcmp { pqc_auths, .. } = &tx.ct else {
        panic!("the fixture is an FCMP++ spend");
    };
    let entry = FrameTx {
        pqc_auth_count: u64::try_from(pqc_auths.len()).unwrap(),
        pqc_auths: &segments.pqc_auths,
        prunable: &segments.prunable,
    };

    let parts = tx.txid_parts();
    let (pqc_auth_hash, prunable_hash, archival_len) = rows_of(&entry);
    assert_eq!(pqc_auth_hash, parts.pqc_auth_hash);
    assert_eq!(prunable_hash, parts.prunable_hash);
    assert_eq!(archival_len, parts.archival_len);
    assert!(parts.pqc_auth_hash.is_some(), "a spend hashes 4-part");

    let pqc_len = u64::try_from(segments.pqc_auths.len()).unwrap();
    let prunable_len = u64::try_from(segments.prunable.len()).unwrap();
    assert_eq!(check_lengths(0, &parts, pqc_len, prunable_len), Ok(()));
    assert_eq!(
        check_components(
            0,
            &parts,
            entry.pqc_auth_count,
            entry.pqc_auths,
            entry.prunable
        ),
        Ok(())
    );
}
