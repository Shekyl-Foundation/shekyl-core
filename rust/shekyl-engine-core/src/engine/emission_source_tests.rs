// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the emission claim-source reader (`engine/emission_source.rs`).
//!
//! Wired as a `#[path]` child of `emission_source::tests`, so `use super::*`
//! resolves into the parent module and private items stay testable; the
//! sibling file exists so the decomposition ratchet counts the production
//! module, not its test suite (the `stake_engine_tests.rs` / `proofs_tests.rs`
//! pattern).

use super::*;
use crate::engine::emission_claim::test_fixtures::source_json;
use shekyl_archival_retention::{ARCHIVAL_REWARD_AGE_WEIGHT_MILLI, SETTLEMENT_EPOCH_BLOCKS};

/// A response as the daemon's epee KV JSON store emits it: one window
/// epoch with rows, one empty-row epoch (absent arrays omitted, as epee
/// omits empty containers — the shared encoder reproduces that, so the
/// absent-decodes-empty rule stays covered). Encoded through the
/// crate's single test-side wire encoder
/// (`emission_claim::test_fixtures::source_json`); the shape's
/// independent pin is the C++ wire-contract test on the serializer
/// side (`archival_claim_source_rpc.cpp`).
/// The exit operands must arrive or the decode must fail — they must never
/// default.
///
/// This is the slice's safety boundary in one test. `release_cooldown_elapsed`
/// and `slashes_settled_through` both treat an ABSENT serve anchor as
/// permissive, which is right at the daemon (nothing served ⇒ nothing to cool
/// down from) and wrong here, where absence can also mean "the field never
/// arrived". If the decoder defaulted instead of erroring, an older daemon or
/// a dropped field would make the wallet compute readiness from a value it
/// never received and tell a user an irreversible exit was safe to take.
///
/// So: every exit operand is a required field, and its absence is
/// `Malformed`. There is no `ServeAnchor` variant for "unknown" — a decode
/// that cannot answer refuses instead of guessing.
///
/// **What this test covers, stated precisely.** It exercises the *decoder's*
/// contract, not a shape today's wire produces: the C++ marshaler writes all
/// **four** exit operands whenever `has_bond_record` is set — the bonded
/// total, the interval-log count, and the two presence flags — so a current
/// daemon never omits them and this negative control cannot fire against
/// one. (It said "three" until 2026-08-26, which was the same undercount
/// that left `bad_interval_count` off the wire in the first place: the
/// operand with no absent state is the one that goes missing from a list.) Its
/// value is forward-looking and is the reason it is worth keeping — a daemon
/// that predates these fields, a field dropped in a future response edit, or
/// a transport that elides scalars would all arrive here, and the decoder
/// refuses rather than defaulting into the permissive branch. The
/// wire-shape pin lives on the C++ side (`archival_claim_source_rpc.cpp`),
/// where it belongs; this is the decoder's half.
#[test]
fn a_missing_exit_operand_is_a_decode_error_never_a_permissive_default() {
    for field in [
        "bonded_total_atomic",
        "bad_interval_count",
        "has_last_served_epoch",
        "has_last_settled_slash_epoch",
    ] {
        let mut v = fixture();
        v.as_object_mut()
            .expect("fixture is an object")
            .remove(field);
        let err =
            EmissionClaimSource::from_json(&v).expect_err("a missing exit operand must not decode");
        assert!(
            matches!(err, EmissionSourceError::Malformed(_)),
            "{field} absent must be Malformed, got {err:?}"
        );
    }
}

/// The pairing follows the **request**, not anything the reply says.
///
/// This canned daemon answers with the same fixture record no matter which
/// `P` is asked for — the shape of an honest-but-confused node, or a caching
/// proxy serving the wrong entry. The wrapper must still name the persona
/// the wallet *asked about*, because that is the fact the wallet holds
/// first-hand and the only one an untrusted reply cannot move.
///
/// That is also why the response carries no `p_id` echo to check against: a
/// daemon willing to send the wrong record is willing to echo the right id
/// over it, so an echo would authenticate nothing while making the field
/// look authoritative.
///
/// **Read this test as a limit, not a guarantee.** The canned daemon here
/// hands the SAME record to two different requests and both wrappers come
/// back correctly labelled — which is the property being asserted, and is
/// also a demonstration that the label is not a claim about the facts. That
/// is exactly the shape of a dishonest or stale answer, and this test shows
/// it passing. It has to: [`ClaimSourceFor`] binds request association, and
/// its "What this type does NOT prove" section is the other half of this
/// test's meaning. Anyone reaching for this test as evidence that a response
/// is authenticated has it backwards.
#[tokio::test]
async fn the_fetch_binds_the_response_to_the_id_it_asked_for() {
    #[derive(Clone)]
    struct OneRecordDaemon(std::sync::Arc<Value>);

    impl Rpc for OneRecordDaemon {
        fn post(
            &self,
            route: &str,
            _body: Vec<u8>,
        ) -> impl Send + std::future::Future<Output = Result<Vec<u8>, RpcError>> {
            let reply =
                serde_json::to_vec(&json!({ "result": *self.0 })).expect("fixture result encodes");
            let ok = route == "json_rpc";
            async move {
                if ok {
                    Ok(reply)
                } else {
                    Err(RpcError::InternalError("unexpected route".into()))
                }
            }
        }
    }

    let daemon = OneRecordDaemon(std::sync::Arc::new(fixture()));
    let asked = PCanonicalId::from_bytes([0x3C; 32]);
    let fetched = fetch_claim_source_for(&daemon, asked)
        .await
        .expect("the canned reply decodes");

    assert_eq!(fetched.p_id(), asked);
    // And the facts really are the ones that came back, so the pairing is a
    // binding rather than an id sitting beside an unrelated value.
    assert_eq!(
        fetched
            .source()
            .bond
            .as_ref()
            .expect("fixture has a bond record")
            .bad_interval_count,
        2
    );

    // A second request for a different `P` against the same daemon must not
    // come back wearing the first one's name.
    let other = PCanonicalId::from_bytes([0xC3; 32]);
    let again = fetch_claim_source_for(&daemon, other)
        .await
        .expect("the canned reply decodes");
    assert_eq!(again.p_id(), other);
    assert_ne!(again.p_id(), fetched.p_id());
}

/// The interval-log length is read from the wire, not assumed.
///
/// It is the sixth and last of `verify_unbond_bond_post`'s record operands
/// and the only one with no presence flag, because an empty log is a length
/// rather than a silence. That makes the decode the whole safety boundary:
/// `0 < MAX_BOND_BAD_INTERVALS` **passes**, so a defaulted read reports "the
/// log has room" for a record whose log may be full — and a full log makes
/// the exit unconnectable, which verify rejects. The fixture carries a
/// non-zero count precisely so this assertion can tell a real read from a
/// default.
#[test]
fn the_interval_log_length_is_decoded_not_defaulted() {
    let src = EmissionClaimSource::from_json(&fixture()).expect("fixture decodes");
    let bond = src.bond.as_ref().expect("fixture has a bond record");
    assert_eq!(bond.bad_interval_count, 2);
}

/// The two anchor types render their absent arm as a word, not a number.
///
/// [`ServeAnchor`]'s doc turns on epoch 0 being a real settlement epoch, so
/// the type keeps `NeverServed` and `ServedAt(0)` apart. Anything that
/// prints them has to keep them apart too — a refusal that reports the
/// anchor is read by a user deciding whether an irreversible exit is
/// blocked, and `0` is the one rendering that could mean either. The same
/// holds for the watermark, where the absent arm is the *restrictive* one.
#[test]
fn the_absent_arm_of_each_anchor_renders_distinctly_from_epoch_zero() {
    assert_ne!(
        ServeAnchor::NeverServed.to_string(),
        ServeAnchor::ServedAt(0).to_string()
    );
    assert_ne!(
        SlashWatermark::NothingSettled.to_string(),
        SlashWatermark::SettledThrough(0).to_string()
    );
    // Neither absent arm may render as a bare number of any kind: a caller
    // interpolating it into "epoch {}" must not produce a readable lie.
    for absent in [
        ServeAnchor::NeverServed.to_string(),
        SlashWatermark::NothingSettled.to_string(),
    ] {
        assert!(
            !absent.chars().any(|c| c.is_ascii_digit()),
            "absent arm rendered with a digit in it: {absent}"
        );
    }
}

/// A flag that vouches for a field which did not arrive is a decode error,
/// not a reconciliation.
///
/// The two presence encodings answer different questions — the required read
/// is authoritative about the wire, the flag is the daemon's assertion about
/// semantics — so `has_last_served_epoch: true` with `last_served_epoch`
/// missing has no consistent reading and must not be resolved into one. The
/// dangerous resolution would be "trust the flag, default the value": that
/// yields `ServedAt(0)`, the earliest possible anchor, which makes the
/// cooldown look maximally elapsed.
#[test]
fn a_flag_without_its_value_is_malformed_not_reconciled() {
    let mut v = fixture();
    let obj = v.as_object_mut().expect("fixture is an object");
    obj.insert("has_last_served_epoch".into(), true.into());
    obj.remove("last_served_epoch");
    let err = EmissionClaimSource::from_json(&v)
        .expect_err("a flag vouching for a missing value must not decode");
    assert!(
        matches!(err, EmissionSourceError::Malformed(_)),
        "got {err:?}"
    );

    // Same for the watermark, whose absence is fail-closed at consensus.
    let mut v = fixture();
    let obj = v.as_object_mut().expect("fixture is an object");
    obj.insert("has_last_settled_slash_epoch".into(), true.into());
    obj.remove("last_settled_slash_epoch");
    let err = EmissionClaimSource::from_json(&v)
        .expect_err("a flag vouching for a missing value must not decode");
    assert!(
        matches!(err, EmissionSourceError::Malformed(_)),
        "got {err:?}"
    );
}

/// The flag carries the fact; the value never encodes it. A served-at-epoch-0
/// record decodes as *served*, not as "never served" — the collapse a
/// zero-means-absent encoding would produce, and the one that would flip the
/// cooldown check from "not elapsed" to permissive.
#[test]
fn served_at_epoch_zero_decodes_as_served_not_as_never_served() {
    let mut v = fixture();
    let obj = v.as_object_mut().expect("fixture is an object");
    obj.insert("has_last_served_epoch".into(), true.into());
    obj.insert("last_served_epoch".into(), 0u64.into());
    let src = EmissionClaimSource::from_json(&v).expect("decodes");
    let bond = src.bond.expect("fixture has a bond record");
    assert_eq!(bond.last_served, ServeAnchor::ServedAt(0));
    assert_eq!(
        bond.last_served.as_verify_operand(),
        Some(0),
        "the verifier must see an anchor, not the permissive None"
    );
}

/// `NeverServed` is a real daemon answer and must still reach the verifier as
/// `None` — the permissive branch is correct when the daemon *said* so. This
/// is the other half of the pair: the mapping is not "always fail closed", it
/// is "closed on unknown, faithful on known".
#[test]
fn never_served_reaches_the_verifier_as_the_permissive_none() {
    let src = EmissionClaimSource::from_json(&fixture()).expect("decodes");
    let bond = src.bond.expect("fixture has a bond record");
    assert_eq!(bond.last_served, ServeAnchor::NeverServed);
    assert_eq!(bond.last_served.as_verify_operand(), None);
    assert_eq!(bond.last_settled_slash.as_verify_operand(), None);
}

fn fixture() -> Value {
    source_json(&EmissionClaimSource {
        chain_height: ChainCount::from_raw(30001),
        current_settled_epoch: 3,
        bond: Some(BondContext {
            join_settlement_epoch: 1,
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::ShardSetCompact,
                shard_ids: ShardSet::new(vec![4, 9]).unwrap(),
            },
            claimed_settlement_epochs: vec![1],
            bonded_total_atomic: 0,
            // Non-zero on purpose: 0 is what a dropped field would also
            // decode to if the read were ever defaulted, so a fixture
            // carrying 0 could not tell the two apart.
            bad_interval_count: 2,
            last_served: ServeAnchor::NeverServed,
            last_settled_slash: SlashWatermark::NothingSettled,
        }),
        epochs: vec![
            EpochSnapshot {
                settlement_epoch: 1,
                close_block_height: 20000,
                sigma_work_milli: 5000,
                budget_atomic: 777,
                has_budget_row: true,
                bonds: vec![BondRow {
                    join_settlement_epoch: 0,
                    is_foundation_complete_tree: false,
                    bad_intervals: vec![BadInterval {
                        start_epoch: 2,
                        end_exclusive: 3,
                    }],
                }],
                shards: vec![EpochCloseShard {
                    shard_id: 4,
                    freeze_height: 15,
                    has_segment: true,
                }],
                credit_pairs: vec![CreditPair {
                    bond_idx: 0,
                    shard_idx: 0,
                }],
                claimant_bond_idx: Some(0),
            },
            // The empty-row epoch: bonds/shards/credit_pairs are OMITTED
            // by the encoder (epee omit-empty), exercising the decoder's
            // absent-decodes-empty rule.
            EpochSnapshot {
                settlement_epoch: 2,
                close_block_height: 30000,
                sigma_work_milli: 0,
                budget_atomic: 0,
                has_budget_row: false,
                bonds: vec![],
                shards: vec![],
                credit_pairs: vec![],
                claimant_bond_idx: None,
            },
        ],
    })
}

/// The encoder really omits the empty containers (the premise of the
/// absent-decodes-empty coverage above — if it ever emitted `[]`, the
/// fixture would silently stop exercising the epee omission rule).
#[test]
fn fixture_omits_empty_containers() {
    let v = fixture();
    let e2 = &v["epochs"][1];
    for field in ["bonds", "shards", "credit_pairs"] {
        assert!(
            e2.get(field).is_none(),
            "`{field}` must be absent (epee omit-empty), not an empty array"
        );
    }
}

#[test]
fn decodes_fixture_field_for_field() {
    let src = EmissionClaimSource::from_json(&fixture()).unwrap();
    assert_eq!(src.chain_height, ChainCount::from_raw(30001));
    assert_eq!(src.current_settled_epoch, 3);

    let bond = src.bond.as_ref().unwrap();
    assert_eq!(bond.join_settlement_epoch, 1);
    assert_eq!(bond.holdings.kind, HoldingsKind::ShardSetCompact);
    assert_eq!(bond.holdings.shard_ids, [4, 9]);
    assert_eq!(bond.claimed_settlement_epochs, [1]);
    let record = bond.record();
    assert_eq!(record.join_settlement_epoch, 1);
    assert_eq!(record.claimed_settlement_epochs, [1]);

    assert_eq!(src.epochs.len(), 2);
    let e1 = &src.epochs[0];
    assert_eq!(e1.settlement_epoch, 1);
    assert_eq!(e1.close_block_height, 20000);
    assert_eq!(e1.sigma_work_milli, 5000);
    assert_eq!(e1.budget_atomic, 777);
    assert!(e1.has_budget_row);
    assert_eq!(e1.bonds.len(), 1);
    assert_eq!(
        e1.bonds[0].bad_intervals,
        [BadInterval {
            start_epoch: 2,
            end_exclusive: 3
        }]
    );
    assert_eq!(e1.shards.len(), 1);
    assert_eq!(
        e1.credit_pairs,
        [CreditPair {
            bond_idx: 0,
            shard_idx: 0
        }]
    );
    assert_eq!(e1.claimant_bond_idx, Some(0));

    // Sentinel + epee omit-empty-container behavior.
    let e2 = &src.epochs[1];
    assert!(!e2.has_budget_row);
    assert!(e2.bonds.is_empty());
    assert!(e2.shards.is_empty());
    assert!(e2.credit_pairs.is_empty());
    assert_eq!(e2.claimant_bond_idx, None);
}

#[test]
fn view_construction_matches_verify_shape() {
    let src = EmissionClaimSource::from_json(&fixture()).unwrap();
    let e1 = &src.epochs[0];
    let bonds = e1.bonds_view();
    let source = e1.source(&bonds);
    assert_eq!(source.inputs.settlement_epoch, 1);
    assert_eq!(source.inputs.close_block_height, 20000);
    assert_eq!(
        source.inputs.settlement_epoch_blocks,
        SETTLEMENT_EPOCH_BLOCKS
    );
    assert_eq!(
        source.inputs.age_weight_milli,
        ARCHIVAL_REWARD_AGE_WEIGHT_MILLI
    );
    assert_eq!(source.inputs.bonds.len(), 1);
    assert_eq!(
        source.inputs.bonds[0].bad_intervals,
        [BadInterval {
            start_epoch: 2,
            end_exclusive: 3
        }]
    );
    assert_eq!(source.persisted_sigma_work_milli, 5000);
    assert_eq!(source.claimant_bond_idx, Some(0));
    assert_eq!(source.budget, 777);
}

#[test]
fn no_bond_record_decodes_none_without_reading_bond_fields() {
    // A bond-less response zeroes part-A bond fields daemon-side; the
    // decode must not read them (has_bond_record is the gate).
    let v = json!({
        "status": "OK",
        "chain_height": 5,
        "current_settled_epoch": 0,
        "has_bond_record": false
    });
    let src = EmissionClaimSource::from_json(&v).unwrap();
    assert!(src.bond.is_none());
    assert!(src.epochs.is_empty());
}

#[test]
fn missing_mandatory_scalar_is_loud() {
    let mut v = fixture();
    v.as_object_mut().unwrap().remove("current_settled_epoch");
    assert!(matches!(
        EmissionClaimSource::from_json(&v),
        Err(EmissionSourceError::Malformed(_))
    ));
}

#[test]
fn non_ok_status_is_status_error_not_a_payload() {
    // A BUSY body carries zeroed payload fields that must never decode
    // as a valid "nothing claimable" source.
    let mut v = fixture();
    v["status"] = json!("BUSY");
    assert!(matches!(
        EmissionClaimSource::from_json(&v),
        Err(EmissionSourceError::Status(s)) if s == "BUSY"
    ));
}

#[test]
fn missing_status_is_loud() {
    let mut v = fixture();
    v.as_object_mut().unwrap().remove("status");
    assert!(matches!(
        EmissionClaimSource::from_json(&v),
        Err(EmissionSourceError::Malformed(_))
    ));
}

#[test]
fn unsorted_claimed_epochs_is_loud() {
    // The claimed set is a binary-search operand downstream; unsorted
    // input must be rejected at decode, never searched.
    let mut v = fixture();
    v["claimed_settlement_epochs"] = json!([5, 1]);
    assert!(matches!(
        EmissionClaimSource::from_json(&v),
        Err(EmissionSourceError::Malformed(_))
    ));
    // Duplicates violate *strictly* increasing too.
    let mut v = fixture();
    v["claimed_settlement_epochs"] = json!([1, 1]);
    assert!(matches!(
        EmissionClaimSource::from_json(&v),
        Err(EmissionSourceError::Malformed(_))
    ));
}

/// The settled/height pair is redundant (one `db.height()` read
/// daemon-side); a reply where they disagree under the frozen mapping is
/// malformed — refused at decode, never split across the builder's two
/// boundary systems (window verdicts read `current_settled_epoch`, the
/// step-7 self-check recomputes from `chain_height`).
#[test]
fn settled_epoch_inconsistent_with_chain_height_is_loud() {
    // Deflated settled: the builder's window floor would lag verify's
    // (whole-batch SelfCheckFailed on an expired admit).
    let mut v = fixture();
    v["current_settled_epoch"] = json!(2);
    assert!(matches!(
        EmissionClaimSource::from_json(&v),
        Err(EmissionSourceError::Malformed(_))
    ));
    // Inflated settled: genuinely claimable epochs would silently skip
    // as WindowExpired (forfeited rewards).
    let mut v = fixture();
    v["current_settled_epoch"] = json!(4);
    assert!(matches!(
        EmissionClaimSource::from_json(&v),
        Err(EmissionSourceError::Malformed(_))
    ));
    // The fixture itself is the consistent pair (sanity).
    assert_eq!(
        settlement_epoch_at_height(fixture()["chain_height"].as_u64().unwrap()),
        fixture()["current_settled_epoch"].as_u64().unwrap()
    );
}

#[test]
fn unsorted_window_epochs_is_loud() {
    let mut v = fixture();
    v["epochs"][0]["settlement_epoch"] = json!(2);
    v["epochs"][1]["settlement_epoch"] = json!(1);
    assert!(matches!(
        EmissionClaimSource::from_json(&v),
        Err(EmissionSourceError::Malformed(_))
    ));
}

#[test]
fn odd_bad_intervals_flat_is_loud() {
    let mut v = fixture();
    v["epochs"][0]["bonds"][0]["bad_intervals_flat"] = json!([2]);
    assert!(matches!(
        EmissionClaimSource::from_json(&v),
        Err(EmissionSourceError::Malformed(_))
    ));
}

#[test]
fn unknown_holdings_kind_is_loud() {
    let mut v = fixture();
    v["holdings_kind"] = json!(7);
    assert!(matches!(
        EmissionClaimSource::from_json(&v),
        Err(EmissionSourceError::Malformed(_))
    ));
}
