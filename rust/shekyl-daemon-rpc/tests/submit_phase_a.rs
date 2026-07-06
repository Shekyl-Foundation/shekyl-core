// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Phase-A admission tests (`docs/design/DAEMON_SUBMIT_VERDICT.md` §3.1
//! Phase A; §10 item 1's Rust-native half).
//!
//! Every rejection here must hold **without any shim** in play — Phase A
//! is Rust-native by construction, and these tests exercise it through the
//! same `parse_submission` entry the engine calls.

mod submit_fixtures;

use shekyl_daemon_rpc::submit::{parse_submission, SubmitTxKind};
use shekyl_rpc_types::{RejectCause, SubmitVerdict};
use shekyl_wire::transaction::PQC_HYBRID_SINGLE_KEY_LEN;
use shekyl_wire::{
    BondPost, BondPostKind, Ct, CtBase, Holdings, Input, Output, Transaction, TxPrefix,
};
use submit_fixtures::{
    hexify, serve_credit_tx, spend_tx, spend_tx_with_kis, valid_key_images, FIXTURE_REF_BLOCK,
};

fn reject_reason(tx_hex: &str) -> String {
    let reject = parse_submission(tx_hex).expect_err("expected Phase-A rejection");
    assert_eq!(
        reject.verdict(),
        SubmitVerdict::Rejected {
            cause: RejectCause::Malformed
        },
        "every Phase-A failure maps to Rejected{{Malformed}}"
    );
    reject.reason
}

// ── The admit path ──────────────────────────────────────────────────────

#[test]
fn valid_spend_parses_with_extracted_facts() {
    let kis = valid_key_images(2);
    let tx = spend_tx_with_kis(&kis, 12_345);
    let blob = tx.serialize();

    let parsed = parse_submission(&hexify(&tx)).expect("valid spend must clear Phase A");

    assert_eq!(parsed.blob, blob, "blob must be the exact decoded bytes");
    assert_eq!(parsed.tx, tx);
    assert_eq!(
        parsed.txid.to_bytes(),
        tx.hash(),
        "txid must be the canonical shekyl-wire hash (§3.4)"
    );
    assert_eq!(parsed.key_images, kis, "key images in vin order");
    assert_eq!(parsed.reference_block.to_bytes(), FIXTURE_REF_BLOCK);
    assert_eq!(parsed.fee, 12_345);
    assert_eq!(parsed.weight, tx.weight() as u64, "row I3 weight");
    assert_eq!(parsed.kind, SubmitTxKind::Spend);
}

#[test]
fn valid_serve_credit_parses_as_non_spending() {
    let parsed =
        parse_submission(&hexify(&serve_credit_tx(0))).expect("fee-0 serve-credit clears Phase A");
    assert_eq!(parsed.kind, SubmitTxKind::ServeCreditOnly);
    assert!(
        parsed.key_images.is_empty(),
        "no key images on the non-spending arm"
    );
    assert_eq!(parsed.fee, 0);
}

// ── Transport-shape rejects (rows T2 / I1 / I2) ─────────────────────────

#[test]
fn non_hex_rejects() {
    let reason = reject_reason("zz not hex");
    assert!(reason.contains("hex"), "unexpected reason: {reason}");
}

#[test]
fn odd_length_hex_rejects() {
    let reason = reject_reason("abc");
    assert!(reason.contains("hex"), "unexpected reason: {reason}");
}

#[test]
fn oversized_hex_rejects_before_decoding() {
    // 2 × MAX_TX_SIZE + 2 hex chars: over any admissible blob. The reject
    // must fire on the *length*, before the decode allocation (row I1's
    // DoS-bounded-decode property).
    let oversized = "00".repeat(1_000_001);
    let reason = reject_reason(&oversized);
    assert!(reason.contains("cap"), "unexpected reason: {reason}");
}

#[test]
fn trailing_bytes_reject() {
    let mut blob = spend_tx(1000).serialize();
    blob.push(0x00);
    let reason = reject_reason(&hex::encode(blob));
    assert!(reason.contains("trailing"), "unexpected reason: {reason}");
}

#[test]
fn truncated_blob_rejects() {
    let blob = spend_tx(1000).serialize();
    let truncated = &blob[..blob.len() - 10];
    let reason = reject_reason(&hex::encode(truncated));
    assert!(
        reason.contains("parse failed"),
        "unexpected reason: {reason}"
    );
}

// ── Statically-rejected shapes ──────────────────────────────────────────

#[test]
fn coinbase_submission_rejects() {
    // A structurally valid coinbase (sole gen input, Null ct) — parses and
    // validates, but RPC submission of a miner tx is the live
    // tx_sanity_check residue (§8.8) and must refuse.
    let coinbase = Transaction {
        prefix: TxPrefix {
            unlock_time: 60,
            inputs: vec![Input::Gen(42)],
            outputs: vec![Output {
                amount: 1_000_000,
                key: [0x22; 32],
                view_tag: 7,
            }],
            extra: vec![],
        },
        ct: Ct::Null(CtBase {
            enc_amounts: vec![[0u8; 9]],
            enc_labels: vec![[0u8; 9]],
            commitments: vec![[0u8; 32]],
        }),
    };
    let reason = reject_reason(&hexify(&coinbase));
    assert!(reason.contains("coinbase"), "unexpected reason: {reason}");
}

#[test]
fn nonzero_unlock_time_rejects() {
    // Pool-policy row P1: unlock_time == 0 exactly. 500 is a valid
    // block-height form (validate() passes it); the pool static must not.
    let mut tx = spend_tx(1000);
    tx.prefix.unlock_time = 500;
    let reason = reject_reason(&hexify(&tx));
    assert!(
        reason.contains("unlock_time"),
        "unexpected reason: {reason}"
    );
}

#[test]
fn serve_credit_with_nonzero_fee_rejects() {
    // Row N6's static leg: consensus pins the non-spending arm to fee 0
    // (tx_verification_utils.cpp:126). shekyl-wire's validate() does not
    // own the fee pin; the engine does.
    let reason = reject_reason(&hexify(&serve_credit_tx(1)));
    assert!(reason.contains("zero fee"), "unexpected reason: {reason}");
}

#[test]
fn empty_fcmp_proof_rejects() {
    let mut tx = spend_tx(1000);
    if let Ct::Fcmp {
        prunable: Some(prunable),
        ..
    } = &mut tx.ct
    {
        prunable.fcmp_proof.clear();
    }
    let reason = reject_reason(&hexify(&tx));
    assert!(
        reason.contains("empty FCMP++ proof"),
        "unexpected reason: {reason}"
    );
}

// ── Key-image rules (rows M6/M8, §12 ordering) ──────────────────────────

#[test]
fn ascending_key_images_reject() {
    let mut kis = valid_key_images(2);
    kis.reverse(); // strictly ascending now — violates §12
    let reason = reject_reason(&hexify(&spend_tx_with_kis(&kis, 1000)));
    assert!(reason.contains("descending"), "unexpected reason: {reason}");
}

#[test]
fn duplicate_key_images_reject() {
    let ki = valid_key_images(1)[0];
    let reason = reject_reason(&hexify(&spend_tx_with_kis(&[ki, ki], 1000)));
    assert!(reason.contains("descending"), "unexpected reason: {reason}");
}

#[test]
fn identity_key_image_rejects() {
    // Canonical identity encoding (y = 1): in the prime-order subgroup but
    // explicitly excluded (cryptonote_core.cpp:1051-1052).
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let reason = reject_reason(&hexify(&spend_tx_with_kis(&[identity], 1000)));
    assert!(reason.contains("identity"), "unexpected reason: {reason}");
}

#[test]
fn small_order_key_image_rejects() {
    // (0, -1): the canonical order-2 point — decompresses, non-identity,
    // outside the prime-order subgroup (`l·ki != identity`,
    // cryptonote_core.cpp:1053-1054).
    let mut order_two = [0xFF; 32];
    order_two[0] = 0xEC;
    order_two[31] = 0x7F;
    let reason = reject_reason(&hexify(&spend_tx_with_kis(&[order_two], 1000)));
    assert!(
        reason.contains("prime-order subgroup"),
        "unexpected reason: {reason}"
    );
}

#[test]
fn non_canonical_key_image_encoding_rejects() {
    // y = 1 with the sign bit set: either a decompress failure or a
    // non-canonical encoding of the identity depending on the backend —
    // both must refuse (the engine requires canonical encodings, stricter
    // than the C++ oracle by design; see phase_a.rs M8 note).
    let mut non_canonical = [0u8; 32];
    non_canonical[0] = 1;
    non_canonical[31] = 0x80;
    let reason = reject_reason(&hexify(&spend_tx_with_kis(&[non_canonical], 1000)));
    assert!(reason.contains("key image"), "unexpected reason: {reason}");
}

// ── Bond-post structural statics (row N7's context-free legs) ───────────

fn bond_post_input() -> Input {
    Input::BondPost(Box::new(BondPost {
        hybrid_public_key: vec![0xAB; PQC_HYBRID_SINGLE_KEY_LEN],
        p_canonical_id: [0x77; 32],
        kind: BondPostKind::JoinMarket {
            bond_spend_pk: vec![0xCD; PQC_HYBRID_SINGLE_KEY_LEN],
        },
        holdings: Holdings::ShardSetCompact(vec![1, 2, 3, 9]),
        bonded_total_atomic: 750_000_000 * 4,
        bond_credit: 750_000_000 * 4,
        bond_debit: 0,
    }))
}

/// A bond-post tx with `n_funding` txin_to_key inputs and `n_pseudo`
/// pseudo-outs. Built by reshaping the spend fixture: swap one input for
/// the bond-post arm, resize the pseudo-outs.
///
/// Since the §13 (F1/F3) coupling closure (`GENESIS_TX_WIRE_FORMAT.md`
/// §1.1, 2026-07-05) wire and consensus agree: `n_pseudo == n_funding`
/// (the ToKey subset) is the only parseable-and-valid shape; the bond-post
/// vin occupies a pqc_auths slot but no pseudo-out slot. Both the admit
/// and the mis-sized reject are exercised below.
fn bond_post_tx(n_funding: usize, n_pseudo: usize) -> Transaction {
    // Start from a spend with n_funding + 1 inputs so the pqc_auths / base
    // shapes are already right, then replace the last input (lowest key
    // image, keeping the descending order over the funding prefix intact).
    let mut tx = spend_tx_with_kis(&valid_key_images(n_funding + 1), 1000);
    *tx.prefix.inputs.last_mut().expect("n_funding + 1 inputs") = bond_post_input();
    if let Ct::Fcmp {
        prunable: Some(prunable),
        ..
    } = &mut tx.ct
    {
        prunable.pseudo_outs = (0..n_pseudo).map(|_| [0x30; 32]).collect();
    }
    tx
}

#[test]
fn bond_post_without_funding_input_rejects() {
    // ver_non_input_consensus:151-152: spend_input_count == 0 rejects.
    // (Zero pseudo-outs — the spend-subset shape for zero funding inputs —
    // so the wire parses cleanly and the *engine* static is what fires.)
    let reason = reject_reason(&hexify(&bond_post_tx(0, 0)));
    assert!(reason.contains("funding"), "unexpected reason: {reason}");
}

#[test]
fn funded_bond_post_with_spend_subset_pseudo_outs_admits() {
    // The §13 (F1/F3) coupling closure made the funded bond-post
    // admissible: pseudoOuts == funding (ToKey) count parses, validates,
    // and clears Phase A as a BondPost. (Before the closure the wire
    // demanded == vin count while consensus demanded == funding count, so
    // no funded bond-post could admit; that contradiction is gone.)
    let parsed = parse_submission(&hexify(&bond_post_tx(1, 1)))
        .expect("funded bond-post must clear Phase A");
    assert_eq!(parsed.kind, SubmitTxKind::BondPost);
    assert_eq!(
        parsed.key_images.len(),
        1,
        "key images come from the funding inputs only"
    );

    // Per-vin pseudo-outs (the pre-closure wire shape) no longer parse:
    // the reader consumes exactly the spend subset, so the extra chunk is
    // trailing garbage.
    let reason = reject_reason(&hexify(&bond_post_tx(1, 2)));
    assert!(reason.contains("trailing"), "unexpected reason: {reason}");
}
