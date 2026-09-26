// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `tx_extra` parser tests (GENESIS_TX_WIRE_FORMAT.md §9.6a).
//!
//! The coinbase case is **live-oracle** validated (the real `extra` blob must
//! parse and re-serialize byte-identically, and its 0x06/0x07 fields split by
//! output count). A synthetic case exercises the other field kinds.

use shekyl_wire::tx_extra::{
    self, TxExtraField, HYBRID_KEM_CT_BYTES, ML_KEM_768_CT_BYTES, PQC_LEAF_ENTRY_LEN,
    TX_EXTRA_TAG_NONCE,
};
use shekyl_wire::Block;

#[test]
fn coinbase_tx_extra_round_trips_and_splits_per_output() {
    let blk = Block::from_bytes(include_bytes!("vectors/regtest_coinbase_h0.block"))
        .expect("parse coinbase block");
    let extra = &blk.miner_transaction.prefix.extra;

    let fields = tx_extra::parse(extra).expect("parse coinbase tx_extra");
    assert_eq!(
        tx_extra::serialize(&fields).expect("re-serialize coinbase tx_extra"),
        *extra,
        "tx_extra must re-serialize byte-identically to the oracle blob"
    );

    // Structure: tx pubkey, then the per-output PQC scan fields.
    assert!(
        matches!(fields.first(), Some(TxExtraField::PubKey(_))),
        "first field is the tx pubkey"
    );

    let n_out = blk.miner_transaction.prefix.outputs.len();
    let mut saw_kem = false;
    let mut saw_leaf = false;
    for f in &fields {
        match f {
            TxExtraField::PqcKemCiphertext(blob) => {
                assert_eq!(blob.len(), n_out * HYBRID_KEM_CT_BYTES);
                let cts = tx_extra::pqc_kem_per_output(blob).unwrap();
                assert_eq!(cts.len(), n_out);
                assert_eq!(cts[0].ml_kem.len(), ML_KEM_768_CT_BYTES);
                saw_kem = true;
            }
            TxExtraField::PqcLeafEntries(blob) => {
                assert_eq!(blob.len(), n_out * PQC_LEAF_ENTRY_LEN);
                assert_eq!(
                    tx_extra::pqc_leaf_entries_per_output(blob).unwrap().len(),
                    n_out
                );
                saw_leaf = true;
            }
            _ => {}
        }
    }
    assert!(saw_kem && saw_leaf, "coinbase extra carries 0x06 and 0x07");
}

#[test]
fn synthetic_tx_extra_field_kinds_round_trip() {
    let fields = vec![
        TxExtraField::PubKey([0x11; 32]),
        TxExtraField::AdditionalPubKeys(vec![[0x22; 32], [0x23; 32]]),
        TxExtraField::Nonce(vec![0xAB, 0xCD, 0xEF]),
        // two outputs' worth of 0x06 / 0x07 payloads
        TxExtraField::PqcKemCiphertext(vec![0x44; HYBRID_KEM_CT_BYTES * 2]),
        TxExtraField::PqcLeafEntries(vec![0x55; PQC_LEAF_ENTRY_LEN * 2]),
        // padding is last (consumes to end)
        TxExtraField::Padding(5),
    ];
    let bytes = tx_extra::serialize(&fields).expect("serialize valid field kinds");
    assert_eq!(
        tx_extra::parse(&bytes).unwrap(),
        fields,
        "field kinds must round-trip"
    );

    // The 2-output 0x06 blob splits into two hybrid KEM ciphertexts.
    if let TxExtraField::PqcKemCiphertext(blob) = &fields[4] {
        assert_eq!(tx_extra::pqc_kem_per_output(blob).unwrap().len(), 2);
    }
}

#[test]
fn unknown_tag_is_rejected() {
    let err = tx_extra::parse(&[0xFE, 0x01, 0x02]).expect_err("unknown tag must be rejected");
    assert!(err.to_string().contains("unknown tag"), "unexpected: {err}");
}

/// The retired bytes stay retired: the inherited merge-mining (`0x03`) and
/// minergate (`0xDE`) tags, the rejected PQC-ownership entry (`0x05`) and the
/// reserved multisig-migration slot (`0x08`) all parse as unknown. There is
/// no generic skip, so a blob carrying one is unparseable — a later tag
/// cannot reuse a byte old software gave a meaning to (`tx_extra.h`).
#[test]
fn retired_and_reserved_tags_parse_as_unknown() {
    for tag in [0x03u8, 0x05, 0x08, 0xDE] {
        // A plausible length-prefixed payload after the tag, so the refusal
        // is the tag's and not a truncation's.
        let Err(err) = tx_extra::parse(&[tag, 0x02, 0xAA, 0xBB]) else {
            panic!("tag {tag:#04x} must not parse");
        };
        assert!(
            err.to_string().contains("unknown tag"),
            "tag {tag:#04x}: unexpected: {err}"
        );
    }
}

#[test]
fn oversized_padding_and_nonce_rejected_on_serialize() {
    // Oracle parity: C++ caps padding and nonce at 255 (tx_extra.h). serialize() is
    // symmetric with parse() — it rejects a self-invalid field rather than emitting a
    // blob parse would reject.
    let err = tx_extra::serialize(&[TxExtraField::Padding(256)])
        .expect_err("padding > 255 must be rejected at serialize");
    assert!(err.to_string().contains("padding run"), "{err}");

    let err = tx_extra::serialize(&[TxExtraField::Nonce(vec![0u8; 256])])
        .expect_err("nonce > 255 must be rejected at serialize");
    assert!(err.to_string().contains("nonce"), "{err}");
}

#[test]
fn padding_must_be_last_on_serialize() {
    // Padding consumes to end on parse, so a non-last padding field is self-invalid.
    let err = tx_extra::serialize(&[TxExtraField::Padding(2), TxExtraField::PubKey([0u8; 32])])
        .expect_err("non-last padding must be rejected");
    assert!(err.to_string().contains("last field"), "{err}");
}

#[test]
fn oversized_blob_field_rejected_on_serialize() {
    // The round-trip guard makes serialize a true inverse of parse for every field
    // kind: a length-prefixed blob beyond the parse cap (READ_LEN_CAP = 1_000_000)
    // serializes structurally but must be rejected (parse would reject it), without
    // serialize re-listing each per-variant cap.
    let huge = vec![0u8; 1_000_001];
    let err = tx_extra::serialize(&[TxExtraField::PqcKemCiphertext(huge)])
        .expect_err("blob beyond READ_LEN_CAP must be rejected at serialize");
    assert!(err.to_string().contains("exceeds cap"), "{err}");
}

#[test]
fn oversized_nonce_rejected_before_allocation_on_parse() {
    // A hostile nonce length is rejected at parse before the payload is allocated:
    // tag 0x02, varint(1_000_000), no payload — must error on the length, not EOF.
    let mut blob = vec![TX_EXTRA_TAG_NONCE];
    shekyl_wire::varint::write_varint(1_000_000usize, &mut blob).unwrap();
    let err = tx_extra::parse(&blob).expect_err("oversized nonce length must be rejected");
    assert!(err.to_string().contains("nonce"), "{err}");
}

/// `0x0B` archival attestation. The C++ daemon reads this tag on a live
/// consensus path (`blockchain.cpp`, `parse_archival_attestation_from_extra`
/// deciding `headers_readable`), so the port must model it or the two parsers
/// disagree about which coinbases exist.
#[test]
fn archival_attestation_field_round_trips() {
    let blob = vec![0xA7u8; 96];
    let fields = vec![
        TxExtraField::PubKey([0x11; 32]),
        TxExtraField::ArchivalAttestation(blob.clone()),
    ];

    let bytes = tx_extra::serialize(&fields).expect("serialize attestation extra");
    assert_eq!(
        bytes[33], 0x0B,
        "the attestation tag byte follows the pubkey"
    );

    let parsed = tx_extra::parse(&bytes).expect("parse attestation extra");
    assert_eq!(parsed, fields, "attestation extra must round-trip");
    match &parsed[1] {
        TxExtraField::ArchivalAttestation(b) => assert_eq!(*b, blob),
        other => panic!("expected an attestation field, got {other:?}"),
    }
}

/// A present-but-empty `0x0B` encodes as two bytes, not as the empty extra.
/// That is a codec pin. The consensus reader's committed empty set is a
/// successful parse with the tag *absent* (`attestation_reader_splits_absent_from_unreadable`);
/// present-empty and absent both yield an empty blob at that API.
#[test]
fn empty_archival_attestation_is_distinct_from_an_absent_one() {
    let with_empty = tx_extra::serialize(&[TxExtraField::ArchivalAttestation(Vec::new())])
        .expect("serialize empty attestation");
    let absent = tx_extra::serialize(&[]).expect("serialize empty extra");

    assert_ne!(
        with_empty, absent,
        "a present-but-empty attestation must not encode as an absent one"
    );
    assert_eq!(
        tx_extra::parse(&with_empty).expect("parse empty attestation"),
        vec![TxExtraField::ArchivalAttestation(Vec::new())]
    );
}

/// An attestation field must not disturb the per-output PQC shape rule, which
/// counts only 0x06 and 0x07.
#[test]
fn attestation_does_not_disturb_the_pqc_shape_check() {
    let n_out = 2usize;
    let fields = vec![
        TxExtraField::PubKey([0x11; 32]),
        TxExtraField::PqcKemCiphertext(vec![0u8; HYBRID_KEM_CT_BYTES * n_out]),
        TxExtraField::PqcLeafEntries(tx_extra::conforming_pqc_leaf_blob(n_out)),
        TxExtraField::ArchivalAttestation(vec![0x5A; 8]),
    ];
    tx_extra::check_pqc_field_shape_of(&fields, n_out)
        .expect("an attestation field is invisible to the 0x06/0x07 shape rule");
}

/// Cross-language grammar parity for `0x0B`: the same two literals the C++ leg
/// asserts in `tests/unit_tests/archival_credit_wire.cpp`
/// (`attestation_field_bytes_match_the_port`). The round-trip tests on each side
/// prove each encoder is self-consistent, which two mutually wrong encoders
/// would also satisfy; only a shared literal tests that they agree.
#[test]
fn attestation_field_bytes_match_the_daemon() {
    let non_empty = tx_extra::serialize(&[TxExtraField::ArchivalAttestation(vec![1, 2, 3])])
        .expect("serialize attestation");
    assert_eq!(
        non_empty,
        vec![0x0B, 0x03, 0x01, 0x02, 0x03],
        "the 0x0B encoding must match the daemon byte for byte"
    );

    let empty = tx_extra::serialize(&[TxExtraField::ArchivalAttestation(Vec::new())])
        .expect("serialize empty attestation");
    assert_eq!(
        empty,
        vec![0x0B, 0x00],
        "a present-but-empty attestation is two bytes, not zero"
    );

    // Both literals must parse back to what the daemon wrote.
    assert_eq!(
        tx_extra::parse(&non_empty).expect("parse"),
        vec![TxExtraField::ArchivalAttestation(vec![1, 2, 3])]
    );
    assert_eq!(
        tx_extra::parse(&empty).expect("parse empty"),
        vec![TxExtraField::ArchivalAttestation(Vec::new())]
    );
}

// ── Twins of the retired C++ parser tests (TX_EXTRA_RUST_CUTOVER.md §9.2) ──
//
// `tests/unit_tests/test_tx_utils.cpp` and `cryptonote_format_utils.cpp`
// tested the C++ `parse_tx_extra` / `sort_tx_extra` /
// `remove_field_from_tx_extra`. With that parser gone, "parity with the
// oracle" has no subject; the *cases* belong with the grammar's one
// implementation. Each C++ `TEST` maps to a test here (the table in §9.2
// names the pairs); the sorter and the field remover have no successor —
// canonical order is produced by construction (`shekyl_coinbase_extra`) and
// judged by `check_coinbase_extra_shape`, and nothing rewrites an extra in
// place any more.

/// C++ `parse_tx_extra.handles_empty_extra`.
#[test]
fn empty_extra_parses_to_no_fields() {
    assert_eq!(tx_extra::parse(&[]).unwrap(), Vec::<TxExtraField>::new());
}

/// C++ `handles_padding_only_size_1`, `_size_2`, `_max_size`: a run of
/// zero bytes is one padding field of that length, up to the cap.
#[test]
fn padding_only_parses_with_its_length_up_to_the_cap() {
    for n in [1usize, 2, tx_extra::TX_EXTRA_PADDING_MAX_COUNT] {
        assert_eq!(
            tx_extra::parse(&vec![0u8; n]).unwrap(),
            vec![TxExtraField::Padding(n)],
            "n = {n}"
        );
    }
}

/// C++ `handles_padding_only_exceed_max_size`.
#[test]
fn padding_past_the_cap_is_refused_on_parse() {
    let err = tx_extra::parse(&vec![0u8; tx_extra::TX_EXTRA_PADDING_MAX_COUNT + 1])
        .expect_err("256 zero bytes must not parse");
    assert!(err.to_string().contains("padding"), "{err}");
}

/// C++ `handles_invalid_padding_only`: padding consumes to the end, so a
/// non-zero byte inside it is a refusal, not a second field.
#[test]
fn a_nonzero_byte_inside_padding_is_refused() {
    assert!(tx_extra::parse(&[0x00, 42]).is_err());
}

/// The 33 bytes the C++ cases used for a pubkey field.
const CPP_PUBKEY_FIELD: [u8; 33] = [
    1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228, 80, 63,
    198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230,
];

/// C++ `handles_pub_key_only`, on the same bytes.
#[test]
fn pubkey_only_parses() {
    let fields = tx_extra::parse(&CPP_PUBKEY_FIELD).unwrap();
    assert_eq!(fields.len(), 1);
    assert!(matches!(fields[0], TxExtraField::PubKey(k) if k[..] == CPP_PUBKEY_FIELD[1..]));
}

/// C++ `handles_extra_nonce_only`, on the same bytes `{2, 1, 42}`.
#[test]
fn nonce_only_parses() {
    assert_eq!(
        tx_extra::parse(&[2, 1, 42]).unwrap(),
        vec![TxExtraField::Nonce(vec![42])]
    );
}

/// C++ `handles_pub_key_and_padding`: the pubkey field followed by 63 zero
/// bytes is two fields, the second a padding run of 63.
#[test]
fn pubkey_then_padding_parses_as_two_fields() {
    let mut extra = CPP_PUBKEY_FIELD.to_vec();
    extra.extend(std::iter::repeat_n(0u8, 63));
    let fields = tx_extra::parse(&extra).unwrap();
    assert_eq!(fields.len(), 2);
    assert!(matches!(fields[0], TxExtraField::PubKey(_)));
    assert_eq!(fields[1], TxExtraField::Padding(63));
}

/// C++ `parse_and_validate_tx_extra.fails_on_wrong_size_in_extra_nonce`:
/// a nonce whose declared length (255) runs past the bytes present.
#[test]
fn a_nonce_length_past_the_bytes_is_refused() {
    let mut extra = vec![0u8; 20];
    extra[0] = TX_EXTRA_TAG_NONCE;
    extra[1] = 255;
    assert!(tx_extra::parse(&extra).is_err());
}

/// C++ `sort_tx_extra.invalid` (`{1}`: a pubkey tag with no key) and
/// `invalid_suffix_strict` (a valid nonce field followed by a lone `1`):
/// truncation anywhere refuses the whole extra. The sorter's *partial*
/// mode (`invalid_suffix_partial`, which returned the unsorted prefix on a
/// bad suffix) has no successor: accepting a partial parse is the
/// fail-open the codec refuses.
#[test]
fn a_truncated_pubkey_field_is_refused_alone_and_as_a_suffix() {
    assert!(tx_extra::parse(&[1]).is_err());
    assert!(tx_extra::parse(&[2, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1]).is_err());
}

/// C++ `remove_field_from_tx_extra.invalid_varint`: a nonce whose length
/// varint is `0x80 0x00` — a non-canonical encoding of zero. The C++ parser
/// refused it; so does this one, and for the same reason: one byte string,
/// one reading.
#[test]
fn a_non_canonical_varint_length_is_refused() {
    let mut extra = CPP_PUBKEY_FIELD.to_vec();
    extra.extend_from_slice(&[TX_EXTRA_TAG_NONCE, 0x80, 0x00]);
    assert!(tx_extra::parse(&extra).is_err());
}

/// C++ `cn_format_utils.add_extra_nonce_to_tx_extra` (nonce sizes 0..=256,
/// with and without a preceding pubkey): every size up to the cap
/// serializes and parses back to the same field, the cap + 1 is refused at
/// serialize. Also `still_accepts_the_tags_that_remain` (pubkey + 8-byte
/// nonce parse as two fields in order).
#[test]
fn every_nonce_length_up_to_the_cap_round_trips_and_the_cap_plus_one_is_refused() {
    for with_prefix in [false, true] {
        for n in 0..=tx_extra::TX_EXTRA_NONCE_MAX_COUNT {
            let mut fields = Vec::new();
            if with_prefix {
                fields.push(TxExtraField::PubKey([0x11; 32]));
            }
            fields.push(TxExtraField::Nonce(vec![b'%'; n]));
            let bytes = tx_extra::serialize(&fields).unwrap_or_else(|e| panic!("n = {n}: {e}"));
            // tag + varint(len) + len, plus the pubkey field when present.
            let varint_len = if n < 0x80 { 1 } else { 2 };
            assert_eq!(
                bytes.len(),
                usize::from(with_prefix) * 33 + 1 + varint_len + n
            );
            assert_eq!(tx_extra::parse(&bytes).unwrap(), fields, "n = {n}");
        }
        let mut fields = Vec::new();
        if with_prefix {
            fields.push(TxExtraField::PubKey([0x11; 32]));
        }
        fields.push(TxExtraField::Nonce(vec![
            b'%';
            tx_extra::TX_EXTRA_NONCE_MAX_COUNT
                + 1
        ]));
        assert!(tx_extra::serialize(&fields).is_err());
    }
}

/// `docs/test_vectors/TX_EXTRA_PQC_ROUND_TRIP.json`, promoted to the pinned
/// vector for the two C++ `tx_extra_pqc_round_trip` cases (TXE-Q5a). The
/// JSON describes each case's inputs by pattern; this test derives the bytes
/// from those descriptions, so the vector file — not this test — is the
/// record of the case. `kem_and_leaf_entries_survive_sort`: the canonical
/// layout serializes to the pinned byte anchors and parses back
/// field-for-field, and serialize ∘ parse is the identity (the "double sort
/// idempotent" expectation with no sorter). `kem_and_leaf_entries_reverse_order`:
/// the same fields in the non-canonical order still parse to the same
/// three contents — and the coinbase grammar refuses the order, which is
/// what "sort reorders to canonical" became once nothing reorders.
#[test]
fn tx_extra_pqc_round_trip_vector_cases_hold_without_a_sorter() {
    let doc: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/test_vectors/TX_EXTRA_PQC_ROUND_TRIP.json"
    ))
    .expect("vector parses");
    assert_eq!(doc["constants"]["HYBRID_KEM_CT_BYTES"], HYBRID_KEM_CT_BYTES);
    assert_eq!(doc["constants"]["PQC_LEAF_ENTRY_LEN"], PQC_LEAF_ENTRY_LEN);
    let vectors = doc["vectors"].as_array().expect("vectors");
    assert_eq!(vectors.len(), 2);

    let hex32 = |s: &str| -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    };

    // Case 1: canonical order, sequential-byte patterns.
    let v = &vectors[0];
    assert_eq!(v["name"], "kem_and_leaf_entries_survive_sort");
    let n = usize::try_from(v["inputs"]["kem_ciphertext_num_outputs"].as_u64().unwrap()).unwrap();
    let low_byte = |i: usize| u8::try_from(i & 0xFF).unwrap();
    let kem: Vec<u8> = (0..n * HYBRID_KEM_CT_BYTES).map(low_byte).collect();
    let leaf: Vec<u8> = (0..n * PQC_LEAF_ENTRY_LEN)
        .map(|i| low_byte(i + 0x42))
        .collect();
    assert_eq!(kem.len() as u64, v["inputs"]["kem_ciphertext_total_bytes"]);
    assert_eq!(leaf.len() as u64, v["inputs"]["leaf_entries_total_bytes"]);
    let fields = vec![
        TxExtraField::PubKey(hex32(v["inputs"]["pubkey"].as_str().unwrap())),
        TxExtraField::PqcKemCiphertext(kem.clone()),
        TxExtraField::PqcLeafEntries(leaf.clone()),
    ];
    let bytes = tx_extra::serialize(&fields).unwrap();
    let parsed = tx_extra::parse(&bytes).unwrap();
    assert_eq!(parsed.len() as u64, v["expected"]["field_count_after_sort"]);
    assert_eq!(parsed, fields, "kem/leaf/pubkey preserved");
    assert_eq!(tx_extra::serialize(&parsed).unwrap(), bytes, "idempotent");

    // Case 2: non-canonical insertion order.
    let v = &vectors[1];
    assert_eq!(v["name"], "kem_and_leaf_entries_reverse_order");
    let kem = vec![0x55u8; HYBRID_KEM_CT_BYTES];
    let leaf = vec![0x77u8; PQC_LEAF_ENTRY_LEN];
    let pubkey = hex32(v["inputs"]["pubkey"].as_str().unwrap());
    let reversed = tx_extra::serialize(&[
        TxExtraField::PqcLeafEntries(leaf.clone()),
        TxExtraField::PqcKemCiphertext(kem.clone()),
        TxExtraField::PubKey(pubkey),
    ])
    .unwrap();
    let parsed = tx_extra::parse(&reversed).unwrap();
    assert_eq!(
        parsed.len() as u64,
        v["expected"]["field_count_before_sort"]
    );
    assert!(parsed.contains(&TxExtraField::PqcKemCiphertext(kem)));
    assert!(parsed.contains(&TxExtraField::PqcLeafEntries(leaf)));
    assert!(parsed.contains(&TxExtraField::PubKey(pubkey)));
    // No sorter reorders it; the grammar refuses the order (and, with no
    // nonce, the missing field first).
    assert!(tx_extra::check_coinbase_extra_shape(&parsed, 1).is_err());
}
