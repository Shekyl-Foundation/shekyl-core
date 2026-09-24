// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tests for the archival codecs (`codec::archival`): the bond record's round
//! trip at every genesis-frozen cap, each decode refusal on its own axis,
//! and the **v7 cross-check** — the C++ `ArchivalBondValue` corpus
//! (`docs/test_vectors/ARCHIVAL_BOND_RECORD_V7.json`, written and asserted
//! by `tests/unit_tests/archival_bond_record_v7_corpus.cpp`) rebuilt as
//! [`BondRecord`]s field by field, so the re-specified codec is shown to
//! carry the *same record*, not merely to round-trip itself
//! (`DRS_E1_SARCH.md` §7, ruled on PR #840).

use std::fs;
use std::path::Path;

use shekyl_store_codec::{BlobKind, Canonical, CodecError};
use shekyl_types::archival::{
    BadInterval, HoldingsKind, MAX_BOND_BAD_INTERVALS, MAX_CLAIMED_EPOCH_ENTRIES,
    MAX_CLAIM_AGE_W_EPOCHS, MAX_HOLDINGS_SHARDS,
};
use shekyl_types::{BlockHeight, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;

use super::archival::{
    AttestationWitnessBytes, BondRecord, HeldShard, Holdings, HoldingsError, RMarket,
    SigmaWorkMilli, MAX_BOND_KEY_BYTES,
};

fn invalid(reason: &'static str) -> CodecError {
    CodecError::Invalid {
        codec: BondRecord::NAME,
        reason,
    }
}

fn base() -> BondRecord {
    BondRecord {
        hybrid_pubkey: vec![0x11; 64],
        bond_spend_pk: vec![0x22; 32],
        endpoint: [0x33; 32],
        join_settlement_epoch: SettlementEpoch::from_raw(3),
        bonded_total: AtomicUnits::from_raw(5_000_000_000),
        holdings: Holdings::CompleteTree,
        bad_intervals: vec![],
        claimed_settlement_epochs: vec![],
        first_paying_emission_height: None,
    }
}

fn round_trips(record: &BondRecord) -> Vec<u8> {
    let bytes = record.encode();
    assert_eq!(
        &BondRecord::decode(&bytes).expect("own encoding decodes"),
        record
    );
    bytes
}

#[test]
fn the_record_round_trips_at_every_cap() {
    // Every optional part absent.
    round_trips(&base());

    // Holdings at the shard cap, insertion order kept.
    let held: Vec<HeldShard> = (0..MAX_HOLDINGS_SHARDS as u64)
        .rev()
        .map(|s| HeldShard {
            shard: ShardId::from_raw(s),
            add_epoch: SettlementEpoch::from_raw(5 + s % 3),
        })
        .collect();
    let at_shard_cap = BondRecord {
        holdings: Holdings::shard_set(held).expect("distinct, at the cap"),
        ..base()
    };
    let bytes = round_trips(&at_shard_cap);
    let Holdings::ShardSet(decoded) = &BondRecord::decode(&bytes).unwrap().holdings else {
        panic!("compact holdings decode as ShardSet");
    };
    assert_eq!(
        decoded[0].shard.to_raw(),
        MAX_HOLDINGS_SHARDS as u64 - 1,
        "order kept"
    );

    // The interval log at its genesis-frozen cap, both entry kinds present.
    let mut bad: Vec<BadInterval> = (0..MAX_BOND_BAD_INTERVALS as u64 - 2)
        .map(|i| BadInterval {
            start_epoch: 6 + 2 * i,
            end_exclusive: 7 + 2 * i,
        })
        .collect();
    bad.push(BadInterval {
        start_epoch: 900,
        end_exclusive: BadInterval::OPEN_END,
    });
    bad.push(BadInterval {
        start_epoch: 901,
        end_exclusive: 901,
    });
    round_trips(&BondRecord {
        bad_intervals: bad,
        ..base()
    });

    // The claimed set at the widest span the window admits (`W + 1` consecutive
    // epochs spanning exactly `W`); the entry cap (`W + 6`) is reachable only
    // with gaps — but consecutive claims fill a span before they fill the cap.
    round_trips(&BondRecord {
        claimed_settlement_epochs: (2..=2 + MAX_CLAIM_AGE_W_EPOCHS)
            .map(SettlementEpoch::from_raw)
            .collect(),
        first_paying_emission_height: Some(BlockHeight::from_raw(30_000)),
        ..base()
    });

    // The key fields at their codec cap.
    round_trips(&BondRecord {
        hybrid_pubkey: vec![0xaa; MAX_BOND_KEY_BYTES],
        bond_spend_pk: vec![0xbb; MAX_BOND_KEY_BYTES],
        ..base()
    });
}

#[test]
fn every_cap_is_a_refusal_one_past_it_before_any_allocation() {
    // A count one past each cap, with no bytes behind it: refused on the
    // cap (never on the missing bytes, never after allocating).
    let mut prefix = Vec::new();
    // hybrid_pubkey: length one past MAX_BOND_KEY_BYTES.
    prefix.extend_from_slice(&(u32::try_from(MAX_BOND_KEY_BYTES).unwrap() + 1).to_le_bytes());
    assert_eq!(
        BondRecord::decode(&prefix),
        Err(invalid("hybrid_pubkey exceeds MAX_BOND_KEY_BYTES"))
    );

    // held-shard count one past MAX_HOLDINGS_SHARDS.
    let mut bytes = base().encode();
    // base() is a complete tree: its holdings byte is the last of the
    // fixed prefix. Rewrite it to compact + an over-cap count.
    let kind_at = 4 + 64 + 4 + 32 + 32 + 8 + 8;
    assert_eq!(bytes[kind_at], HoldingsKind::CompleteTree as u8);
    bytes.truncate(kind_at);
    bytes.push(HoldingsKind::ShardSetCompact as u8);
    bytes.extend_from_slice(&(u32::try_from(MAX_HOLDINGS_SHARDS).unwrap() + 1).to_le_bytes());
    assert_eq!(
        BondRecord::decode(&bytes),
        Err(invalid("held-shard count exceeds MAX_HOLDINGS_SHARDS"))
    );

    // bad-interval count one past MAX_BOND_BAD_INTERVALS.
    let mut bytes = base().encode();
    let bad_count_at = kind_at + 1;
    bytes.truncate(bad_count_at);
    bytes.extend_from_slice(&(u32::try_from(MAX_BOND_BAD_INTERVALS).unwrap() + 1).to_le_bytes());
    assert_eq!(
        BondRecord::decode(&bytes),
        Err(invalid("bad-interval count exceeds MAX_BOND_BAD_INTERVALS"))
    );

    // claimed count one past MAX_CLAIMED_EPOCH_ENTRIES.
    let mut bytes = base().encode();
    let claimed_count_at = bad_count_at + 4;
    bytes.truncate(claimed_count_at);
    bytes.extend_from_slice(&(u32::try_from(MAX_CLAIMED_EPOCH_ENTRIES).unwrap() + 1).to_le_bytes());
    assert_eq!(
        BondRecord::decode(&bytes),
        Err(invalid(
            "claimed-epoch count exceeds MAX_CLAIMED_EPOCH_ENTRIES"
        ))
    );
}

#[test]
fn the_decode_refuses_what_the_type_makes_unrepresentable() {
    // A duplicate shard inside a compact holding — the row a desynced C++
    // writer could have produced — is SI-14's decode-side refusal.
    let mut bytes = base().encode();
    let kind_at = 4 + 64 + 4 + 32 + 32 + 8 + 8;
    bytes.truncate(kind_at);
    bytes.push(HoldingsKind::ShardSetCompact as u8);
    bytes.extend_from_slice(&2u32.to_le_bytes());
    for _ in 0..2 {
        bytes.extend_from_slice(&7u64.to_le_bytes());
        bytes.extend_from_slice(&3u64.to_le_bytes());
    }
    bytes.extend_from_slice(&0u32.to_le_bytes()); // no bad intervals
    bytes.extend_from_slice(&0u32.to_le_bytes()); // nothing claimed
    bytes.push(0); // never paid
    assert_eq!(
        BondRecord::decode(&bytes),
        Err(invalid("a shard is held twice"))
    );

    // The constructor refuses the same thing before it is ever encoded.
    let twice = vec![
        HeldShard {
            shard: ShardId::from_raw(7),
            add_epoch: SettlementEpoch::from_raw(3),
        },
        HeldShard {
            shard: ShardId::from_raw(7),
            add_epoch: SettlementEpoch::from_raw(4),
        },
    ];
    assert_eq!(
        Holdings::shard_set(twice),
        Err(HoldingsError::Duplicate {
            shard: ShardId::from_raw(7)
        })
    );

    // Claimed epochs spanning more than W.
    let mut bytes = base().encode();
    let claimed_count_at = kind_at + 1 + 4;
    bytes.truncate(claimed_count_at);
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&2u64.to_le_bytes());
    bytes.extend_from_slice(&(2 + MAX_CLAIM_AGE_W_EPOCHS + 1).to_le_bytes());
    bytes.push(0);
    assert_eq!(
        BondRecord::decode(&bytes),
        Err(invalid("claimed epochs span more than the claim window W"))
    );

    // Claimed epochs that are not strictly increasing.
    let mut bytes = base().encode();
    let claimed_count_at = kind_at + 1 + 4;
    bytes.truncate(claimed_count_at);
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&5u64.to_le_bytes());
    bytes.extend_from_slice(&5u64.to_le_bytes());
    bytes.push(0);
    assert_eq!(
        BondRecord::decode(&bytes),
        Err(invalid("claimed epochs are not strictly increasing"))
    );

    // An unknown holdings kind, a bad presence byte, trailing bytes.
    let mut bytes = base().encode();
    bytes[kind_at] = 2;
    assert_eq!(
        BondRecord::decode(&bytes),
        Err(invalid("holdings kind byte names neither shape"))
    );
    let mut bytes = base().encode();
    let last = bytes.len() - 1;
    bytes[last] = 2;
    assert_eq!(
        BondRecord::decode(&bytes),
        Err(invalid(
            "first-paying-height presence byte is neither 0 nor 1"
        ))
    );
    let mut bytes = base().encode();
    bytes.push(0);
    assert_eq!(
        BondRecord::decode(&bytes),
        Err(invalid("trailing bytes after the record"))
    );
}

#[test]
fn holdings_answer_held_at_tip_and_project_the_wire_descriptor() {
    let compact = Holdings::shard_set(vec![
        HeldShard {
            shard: ShardId::from_raw(42),
            add_epoch: SettlementEpoch::from_raw(3),
        },
        HeldShard {
            shard: ShardId::from_raw(7),
            add_epoch: SettlementEpoch::from_raw(5),
        },
    ])
    .unwrap();
    assert!(compact.holds(ShardId::from_raw(7)));
    assert!(!compact.holds(ShardId::from_raw(8)));
    assert_eq!(
        compact.add_epoch(ShardId::from_raw(7)),
        Some(SettlementEpoch::from_raw(5))
    );
    let d = compact.descriptor();
    assert_eq!(d.kind, HoldingsKind::ShardSetCompact);
    assert_eq!(d.shard_ids, [42u64, 7], "insertion order, not sorted");

    let complete = Holdings::CompleteTree;
    assert!(complete.holds(ShardId::from_raw(999_999)));
    assert_eq!(complete.add_epoch(ShardId::from_raw(1)), None);
    assert_eq!(complete.descriptor().kind, HoldingsKind::CompleteTree);
    assert!(complete.descriptor().shard_ids.is_empty());
}

#[test]
fn the_close_row_scalars_are_the_raw_le_word_and_the_witness_refuses_empty() {
    assert_eq!(RMarket::from_raw(1).encode(), [1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(RMarket::decode(&[0; 8]), Ok(RMarket::from_raw(0)));
    assert_eq!(
        SigmaWorkMilli::from_raw(2).encode(),
        [2, 0, 0, 0, 0, 0, 0, 0]
    );
    assert!(matches!(
        SigmaWorkMilli::decode(&[0; 7]),
        Err(CodecError::Length {
            codec: "sigma_work_milli",
            ..
        })
    ));
    assert!(AttestationWitnessBytes::well_formed(&[]).is_err());
    assert!(AttestationWitnessBytes::well_formed(&[1]).is_ok());
}

// ---------------------------------------------------------------------------
// The v7 cross-check
// ---------------------------------------------------------------------------

fn corpus_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/test_vectors/ARCHIVAL_BOND_RECORD_V7.json")
}

fn hex_bytes(v: &serde_json::Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    assert!(s.len().is_multiple_of(2), "even-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit pair"))
        .collect()
}

fn u64_of(v: &serde_json::Value) -> u64 {
    v.as_u64().expect("u64 field")
}

/// Build the Rust record from the fields the **C++ decoder** read out of a
/// v7 blob. This is the semantic map the re-specification claims — every
/// C++ field lands in exactly one Rust field; the two sentinels
/// (`first_paying_emission_height == 0`, `holdings_kind` + parallel
/// vectors) become the types that name them.
fn record_from_v7_fields(f: &serde_json::Value) -> BondRecord {
    let kind = HoldingsKind::from_u8(u8::try_from(u64_of(&f["holdings_kind"])).unwrap()).unwrap();
    let held: Vec<HeldShard> = f["held"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| HeldShard {
            shard: ShardId::from_raw(u64_of(&pair[0])),
            add_epoch: SettlementEpoch::from_raw(u64_of(&pair[1])),
        })
        .collect();
    let holdings = match kind {
        HoldingsKind::CompleteTree => {
            assert!(held.is_empty(), "a complete tree carries no list");
            Holdings::CompleteTree
        }
        HoldingsKind::ShardSetCompact => {
            Holdings::shard_set(held).expect("the C++ enforced the same bound and uniqueness")
        }
    };
    let first_paying = match u64_of(&f["first_paying_emission_height"]) {
        0 => None,
        h => Some(BlockHeight::from_raw(h)),
    };
    BondRecord {
        hybrid_pubkey: hex_bytes(&f["hybrid_pubkey_hex"]),
        bond_spend_pk: hex_bytes(&f["bond_spend_pk_hex"]),
        endpoint: hex_bytes(&f["endpoint_hex"])
            .try_into()
            .expect("32-byte endpoint"),
        join_settlement_epoch: SettlementEpoch::from_raw(u64_of(&f["join_settlement_epoch"])),
        bonded_total: AtomicUnits::from_raw(u64_of(&f["bonded_total_atomic"])),
        holdings,
        bad_intervals: f["bad_intervals"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| BadInterval {
                start_epoch: u64_of(&pair[0]),
                end_exclusive: u64_of(&pair[1]),
            })
            .collect(),
        claimed_settlement_epochs: f["claimed_settlement_epochs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| SettlementEpoch::from_raw(u64_of(e)))
            .collect(),
        first_paying_emission_height: first_paying,
    }
}

#[test]
fn the_v7_corpus_maps_onto_the_record_without_loss() {
    let text = fs::read_to_string(corpus_path()).unwrap_or_else(|e| {
        panic!(
            "the v7 corpus is missing ({e}); it is written by \
             tests/unit_tests/archival_bond_record_v7_corpus.cpp with SHEKYL_WRITE_V7_CORPUS=1"
        )
    });
    let doc: serde_json::Value = serde_json::from_str(&text).expect("corpus is JSON");
    // The caps the C++ record was encoded under are the caps this codec
    // bounds by: one pin, read from the corpus rather than assumed.
    let caps = &doc["caps"];
    assert_eq!(u64_of(&caps["max_holdings"]), MAX_HOLDINGS_SHARDS as u64);
    assert_eq!(
        u64_of(&caps["max_bad_intervals"]),
        MAX_BOND_BAD_INTERVALS as u64
    );
    assert_eq!(
        u64_of(&caps["max_claimed_epochs"]),
        MAX_CLAIMED_EPOCH_ENTRIES as u64
    );
    assert_eq!(u64_of(&caps["max_pubkey_len"]), MAX_BOND_KEY_BYTES as u64);
    assert_eq!(u64_of(&caps["max_claim_age_w"]), MAX_CLAIM_AGE_W_EPOCHS);

    let cases = doc["cases"].as_array().expect("cases");
    assert!(cases.len() >= 5, "the corpus has at least its five shapes");
    let mut seen_complete = false;
    let mut seen_compact = false;
    let mut seen_open = false;
    let mut seen_clean_close = false;
    let mut seen_paid = false;
    let mut seen_unpaid = false;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let f = &case["fields"];
        let record = record_from_v7_fields(f);

        // The v7 bytes exist and are not this codec's: the re-specification
        // is a different encoding of the same record, by construction.
        let v7 = hex_bytes(&case["v7_hex"]);
        assert!(!v7.is_empty(), "{name}: v7 bytes present");
        assert_ne!(
            record.encode(),
            v7,
            "{name}: the redb codec is not byte-compatible with v7"
        );

        // The record round-trips through this codec.
        let bytes = record.encode();
        assert_eq!(
            BondRecord::decode(&bytes).unwrap(),
            record,
            "{name}: round trip"
        );

        // Every C++ field is recoverable from the Rust record — the map is
        // lossless in the direction that matters (Rust → C++ fields).
        assert_eq!(
            u64::from(record.holdings.kind().to_u8()),
            u64_of(&f["holdings_kind"]),
            "{name}"
        );
        let held_json = f["held"].as_array().unwrap();
        match &record.holdings {
            Holdings::CompleteTree => assert!(held_json.is_empty(), "{name}"),
            Holdings::ShardSet(held) => {
                assert_eq!(held.len(), held_json.len(), "{name}");
                for (h, pair) in held.iter().zip(held_json) {
                    assert_eq!(
                        h.shard.to_raw(),
                        u64_of(&pair[0]),
                        "{name}: shard, order kept"
                    );
                    assert_eq!(h.add_epoch.to_raw(), u64_of(&pair[1]), "{name}: add-epoch");
                }
            }
        }
        assert_eq!(
            record
                .first_paying_emission_height
                .map_or(0, BlockHeight::to_raw),
            u64_of(&f["first_paying_emission_height"]),
            "{name}: the 0 sentinel is None and nothing else is"
        );
        assert_eq!(
            record.bad_intervals.len(),
            f["bad_intervals"].as_array().unwrap().len()
        );
        assert_eq!(
            record.claimed_settlement_epochs.len(),
            f["claimed_settlement_epochs"].as_array().unwrap().len()
        );

        seen_complete |= record.is_complete_tree();
        seen_compact |= !record.is_complete_tree();
        seen_open |= record.bad_intervals.iter().any(BadInterval::is_open);
        seen_clean_close |= record.bad_intervals.iter().any(BadInterval::is_clean_close);
        seen_paid |= record.first_paying_emission_height.is_some();
        seen_unpaid |= record.first_paying_emission_height.is_none();
    }
    assert!(
        seen_complete && seen_compact && seen_open && seen_clean_close && seen_paid && seen_unpaid,
        "the corpus exercises both holdings kinds, both interval entry kinds and both paid states"
    );
}
