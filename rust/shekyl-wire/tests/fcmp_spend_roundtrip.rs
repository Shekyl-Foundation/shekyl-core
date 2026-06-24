// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FCMP++ spend serializer tests.
//!
//! **Synthetic round-trip**: a full-shape `Ct::Fcmp` transaction (spend input,
//! tagged_key outputs, committed base, tx-level pqc_auths, prunable with a
//! Bulletproof+) is written and re-read, proving the serializer is internally
//! consistent (`read(write(x)) == x`) across every FCMP++ field with arbitrary
//! byte values. The byte layout is transcribed from the C++ oracle source
//! (`rctTypes.h` `serialize_rctsig_base`/`serialize_rctsig_prunable`,
//! `cryptonote_basic.h` `pqc_authentication`) — see `src/transaction.rs`.
//!
//! The byte-identity proof on a *real, consensus-valid* spend lives in
//! `tests/fcmp_spend_e2e.rs` (stage 11). It supersedes the former
//! `#[ignore]`d "live-oracle" KAT, which planned to capture a known-good
//! transaction blob from the C++ daemon — unsound, because the C++ FCMP++
//! spend path never produced a daemon-accepted transaction, so there was no
//! known-good blob to capture. The e2e test builds the spend in Rust and
//! self-validates it against `shekyl_fcmp::proof::verify` (the consensus rule),
//! then round-trips it through this serializer.

use shekyl_wire::{
    BpPlus, Ct, CtBase, Input, Output, PqcAuth, Prunable, ServeCredit, Transaction, TxPrefix,
};

/// Build a representative 1-in / 2-out FCMP++ spend. Field *sizes* mirror the
/// real shape (single-key PQC pk/sig, one Bp+, per-input pseudo-out); the byte
/// *values* are arbitrary — this exercises serialization structure, not crypto.
fn synthetic_spend() -> Transaction {
    let base = CtBase {
        enc_amounts: vec![[1u8; 9], [2u8; 9]],
        enc_labels: vec![[3u8; 9], [4u8; 9]],
        commitments: vec![[5u8; 32], [6u8; 32]],
    };
    let pqc_auths = vec![PqcAuth {
        auth_version: 1,
        scheme_id: 1,
        flags: 0,
        hybrid_public_key: vec![0xAB; 1996],
        hybrid_signature: vec![0xCD; 3385],
    }];
    let prunable = Prunable {
        bulletproofs: vec![BpPlus {
            a: [0x10; 32],
            a1: [0x11; 32],
            b: [0x12; 32],
            r1: [0x13; 32],
            s1: [0x14; 32],
            d1: [0x15; 32],
            l: vec![[0x20; 32]; 7],
            r: vec![[0x21; 32]; 7],
        }],
        tree_depth: 3,
        fcmp_proof: vec![0xEF; 2500],
        pseudo_outs: vec![[0x30; 32]],
    };
    Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![Input::ToKey {
                amount: 0,
                key_offsets: vec![],
                key_image: [0x77; 32],
            }],
            outputs: vec![
                Output {
                    amount: 0,
                    key: [0x22; 32],
                    view_tag: 7,
                },
                Output {
                    amount: 0,
                    key: [0x33; 32],
                    view_tag: 9,
                },
            ],
            extra: vec![0x06, 0xAA, 0xBB, 0xCC],
        },
        ct: Ct::Fcmp {
            fee: 12_345,
            reference_block: [0x44; 32],
            base,
            pqc_auths,
            prunable: Some(prunable),
        },
    }
}

#[test]
fn fcmp_spend_round_trips_self_consistently() {
    let tx = synthetic_spend();
    let bytes = tx.serialize();

    let parsed = Transaction::from_bytes(&bytes).expect("parse synthetic FCMP++ spend");
    assert_eq!(parsed, tx, "read(write(x)) must equal x");
    assert_eq!(parsed.serialize(), bytes, "write must be deterministic");

    // The ct dispatched to Fcmp and the per-input/per-output counts survived.
    match parsed.ct {
        Ct::Fcmp {
            pqc_auths,
            prunable,
            base,
            ..
        } => {
            assert_eq!(pqc_auths.len(), parsed.prefix.inputs.len());
            let prunable = prunable.expect("full spend carries a prunable proof");
            assert_eq!(prunable.pseudo_outs.len(), parsed.prefix.inputs.len());
            assert_eq!(base.commitments.len(), parsed.prefix.outputs.len());
        }
        Ct::Null(_) => panic!("expected Fcmp ct"),
    }
}

#[test]
fn fcmp_spend_rejects_trailing_bytes() {
    let mut bytes = synthetic_spend().serialize();
    bytes.push(0x00);
    let err = Transaction::from_bytes(&bytes).expect_err("trailing byte must be rejected");
    assert!(
        err.to_string().contains("trailing"),
        "unexpected error: {err}"
    );
}

#[test]
fn fee_only_serve_credit_round_trips_and_validates() {
    // The non-spend fee-only Fcmp shape (§2.5 serve-credit): one non-spending
    // serve_credit input, no outputs, empty pqc_auths, no prunable. Ct::read's
    // EOF-tolerant tail must parse it, and the shape-aware validate() must accept it.
    let serve_credit = Input::ServeCredit(Box::new(ServeCredit {
        p_canonical_id: [0x11; 32],
        shard_id: 7,
        settlement_epoch: 42,
        segment_subroot_rk: [0x22; 32],
        leaf_index_in_segment: 0x0403_0201,
        leaf_bytes: [0x33; 128],
        c1_layers: vec![vec![[0x44; 32]]],
        c2_layers: vec![vec![[0x55; 32]]],
        hybrid_signature: vec![0x66; 3385],
    }));
    let tx = Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![serve_credit],
            outputs: vec![],
            extra: vec![],
        },
        ct: Ct::Fcmp {
            fee: 0,
            reference_block: [0x44; 32],
            base: CtBase {
                enc_amounts: vec![],
                enc_labels: vec![],
                commitments: vec![],
            },
            pqc_auths: vec![],
            prunable: None,
        },
    };
    let parsed = Transaction::from_bytes(&tx.serialize()).expect("parse fee-only serve-credit tx");
    assert_eq!(parsed, tx, "fee-only form must round-trip");
    assert!(
        matches!(parsed.ct, Ct::Fcmp { prunable: None, .. }),
        "fee-only ct parses with no prunable"
    );
    tx.validate()
        .expect("fee-only serve-credit tx must validate");
    // Distinct 3-part (no-pqc) hash form — just exercise it (live parity deferred).
    let _ = tx.hash();
}

#[test]
fn fcmp_spend_rejects_oversized_pqc_blob() {
    // Consensus parity: a pqc_auths public key beyond PQC_MAX_PUBLIC_KEY_BLOB must be
    // rejected at parse, matching the C++ oracle's deserialization bound.
    let mut tx = synthetic_spend();
    if let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct {
        pqc_auths[0].hybrid_public_key =
            vec![0u8; shekyl_wire::transaction::PQC_MAX_PUBLIC_KEY_BLOB + 1];
    }
    let err = Transaction::from_bytes(&tx.serialize())
        .expect_err("oversized pqc public key must be rejected");
    assert!(err.to_string().contains("hybrid_public_key"), "{err}");
}

#[test]
fn synthetic_spend_hash_preimage_is_pinned() {
    // Regression guard for the 4-part FCMP++ spend hash (§11):
    //   cn_fast_hash( H(prefix) ‖ H(base) ‖ H(varint(N)·pqc_auths) ‖ H(prunable) ).
    // There is no live spend-hash oracle yet (the KAT is deferred), so this pins the
    // *preimage structure* against accidental drift — most importantly the leading
    // varint(N) count prefix on the pqc_auths component, which the C++ oracle emits
    // because the hash uses the generic std::vector serializer (begin_array(cnt) ->
    // serialize_varint), unlike the prefix-less tx body. If this value changes,
    // either the layout regressed or the live KAT just landed — confirm against the
    // daemon before updating.
    let h: String = synthetic_spend()
        .hash()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        h, "d6cb346f02830be0a91c395dcf64ba1492b05e47c17e6b2f54f0858735a0d03e",
        "synthetic FCMP++ spend hash preimage drifted (see the §11 note above)"
    );
}

#[test]
fn synthetic_spend_prefix_hash_is_pinned() {
    // The FCMP++ `signable_tx_hash` (FCMP_SPEND_SIGNING_PREIMAGE.md §1.2) — the prefix
    // hash the membership/SAL proof signs. It INCLUDES the version:
    // cn_fast_hash(varint(3) ‖ TxPrefix::write). Distinct from the chain-identity tx
    // hash above. Source-validated against the spec; no live spend-hash oracle yet, so
    // this pins the value against drift — confirm vs the daemon before changing it.
    let tx = synthetic_spend();
    assert_ne!(
        tx.prefix_hash(),
        tx.hash(),
        "prefix (signable) hash must differ from the chain-identity tx hash"
    );
    // Structural: the prefix hash depends ONLY on the prefix, not the ct — changing the
    // fee (a ct field) must leave it untouched.
    let mut ct_changed = synthetic_spend();
    if let Ct::Fcmp { fee, .. } = &mut ct_changed.ct {
        *fee += 1;
    }
    assert_eq!(
        tx.prefix_hash(),
        ct_changed.prefix_hash(),
        "prefix hash must not depend on the ct section"
    );
    let h: String = tx
        .prefix_hash()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        h, "271a9c0a13de6a1a7e81db6ef7e2cde7d2ac7145581050ae3dbe34e5858d9f9c",
        "FCMP++ prefix (signable_tx_hash) drifted (§1.2)"
    );
}

#[test]
fn synthetic_spend_pqc_signing_payload_hashes_are_pinned() {
    // Per-input PQC signing preimage (§1.1): payload(i) = prefix_blob ‖ rct_base_blob ‖
    // prunable_hash ‖ pqc_header(i) ‖ all_key_hashes, then cn_fast_hash. Source-validated;
    // the live C++ oracle KAT is the §1.1 residual. Regression guard against drift.
    let tx = synthetic_spend();
    let hashes = tx.pqc_signing_payload_hashes();
    assert_eq!(hashes.len(), 1, "one PQC signing hash per input");
    let h: String = hashes[0].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        h, "12997863855a3d6f731199b75780966075a36aa587b13adeef7f45e9100355dd",
        "FCMP++ PQC signing preimage drifted (§1.1)"
    );
    // Structural: the fee is bound into the preimage (it lives in rct_base_blob), so
    // bumping it must move the hash.
    let mut fee_changed = synthetic_spend();
    if let Ct::Fcmp { fee, .. } = &mut fee_changed.ct {
        *fee += 1;
    }
    assert_ne!(
        hashes,
        fee_changed.pqc_signing_payload_hashes(),
        "fee must be bound into the PQC signing preimage"
    );
}

#[test]
fn pqc_signing_payload_hashes_empty_for_non_spend() {
    // Non-spend shapes carry no per-input PQC signature: a fee-only `Fcmp` (no prunable)
    // and a `Null` ct both return an empty vec. `pqc_signing_payload_hashes` keys off the
    // ct shape, not the prefix, so the `Null` case need not be a full coinbase prefix.
    let mut fee_only = synthetic_spend();
    if let Ct::Fcmp {
        prunable,
        pqc_auths,
        ..
    } = &mut fee_only.ct
    {
        *prunable = None;
        pqc_auths.clear();
    }
    assert!(
        fee_only.pqc_signing_payload_hashes().is_empty(),
        "fee-only (no prunable) yields no signing hashes"
    );

    let mut null_ct = synthetic_spend();
    null_ct.ct = Ct::Null(CtBase {
        enc_amounts: Vec::new(),
        enc_labels: Vec::new(),
        commitments: Vec::new(),
    });
    assert!(
        null_ct.pqc_signing_payload_hashes().is_empty(),
        "Null ct yields no signing hashes"
    );
}

#[test]
fn bp_plus_from_bytes_parses_canonical_layout() {
    // BpPlus::from_bytes is how the tx-builder maps an oxide `Bulletproof` (byte-identical
    // layout: a‖a1‖b‖r1‖s1‖d1‖varint(L)·L‖varint(R)·R) into the wire BpPlus. Build that
    // exact layout by hand, parse it, and confirm round-trip + trailing-byte rejection.
    let bp = BpPlus {
        a: [1u8; 32],
        a1: [2u8; 32],
        b: [3u8; 32],
        r1: [4u8; 32],
        s1: [5u8; 32],
        d1: [6u8; 32],
        l: vec![[7u8; 32], [8u8; 32]],
        r: vec![[9u8; 32]],
    };
    let mut bytes = Vec::new();
    for field in [&bp.a, &bp.a1, &bp.b, &bp.r1, &bp.s1, &bp.d1] {
        bytes.extend_from_slice(field);
    }
    bytes.push(2); // varint(L_len = 2) — single byte for len < 128
    for p in &bp.l {
        bytes.extend_from_slice(p);
    }
    bytes.push(1); // varint(R_len = 1)
    for p in &bp.r {
        bytes.extend_from_slice(p);
    }
    assert_eq!(BpPlus::from_bytes(&bytes).expect("parses"), bp);

    bytes.push(0xFF);
    assert!(
        BpPlus::from_bytes(&bytes).is_err(),
        "trailing bytes after a Bp+ must be rejected"
    );
}
