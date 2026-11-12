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
use serde_json::{json, Value};
use shekyl_archival_retention::{ARCHIVAL_REWARD_AGE_WEIGHT_MILLI, SETTLEMENT_EPOCH_BLOCKS};
use shekyl_types::BlockHeight;

/// The two gates a reply passes, in order: the method table's type (a
/// member absent, unknown or misshapen is no reply), then the record's own
/// invariants.
#[derive(Debug)]
enum Refused {
    /// The reply is not the method table's type.
    Shape,
    /// The reply decoded and does not hold together.
    Malformed,
}

fn decode(v: &Value) -> Result<EmissionClaimSource, Refused> {
    let reply: ClaimSource = serde_json::from_value(v.clone()).map_err(|_| Refused::Shape)?;
    EmissionClaimSource::from_reply(&reply).map_err(|e| match e {
        EmissionSourceError::Malformed(_) => Refused::Malformed,
        EmissionSourceError::Rpc(_) => unreachable!("no transport here"),
    })
}

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
/// So: every exit operand is a required member, and its absence is no
/// reply. `null` is the daemon's answer ("never served"); an absent member
/// is not. There is no `ServeAnchor` variant for "unknown" — a decode that
/// cannot answer refuses instead of guessing.
///
/// The edit that turns this red is a `#[serde(default)]` on any of them.
#[test]
fn a_missing_exit_operand_is_a_decode_error_never_a_permissive_default() {
    for field in ["bond_total", "failure_count", "served_epoch", "slash_epoch"] {
        let mut v = fixture();
        v.as_object_mut()
            .expect("fixture is an object")
            .remove(field);
        assert!(
            matches!(decode(&v), Err(Refused::Shape)),
            "{field} absent must be no reply"
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
/// That is also why the response carries no persona echo to check against:
/// a daemon willing to send the wrong record is willing to echo the right id
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
    let daemon = ClaimDaemon::new(fixture());
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

    // And the request named the persona it was asked for.
    let asked_params = daemon.last_params();
    assert_eq!(asked_params, json!({ "persona": hex::encode([0xC3; 32]) }));
}

/// The interval-log length is read from the wire, not assumed.
///
/// It is the sixth and last of `verify_release_bond_post`'s record operands
/// and the only one with no `null` state, because an empty log is a length
/// rather than a silence. That makes the decode the whole safety boundary:
/// `0 < MAX_BOND_BAD_INTERVALS` **passes**, so a defaulted read reports "the
/// log has room" for a record whose log may be full — and a full log makes
/// the exit unconnectable, which verify rejects. The fixture carries a
/// non-zero count precisely so this assertion can tell a real read from a
/// default.
#[test]
fn the_interval_log_length_is_decoded_not_defaulted() {
    let src = decode(&fixture()).expect("fixture decodes");
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

/// The value carries the fact; zero never encodes absence. A
/// served-at-epoch-0 record decodes as *served*, not as "never served" —
/// the collapse a zero-means-absent encoding would produce, and the one
/// that would flip the cooldown check from "not elapsed" to permissive.
#[test]
fn served_at_epoch_zero_decodes_as_served_not_as_never_served() {
    let mut v = fixture();
    v["served_epoch"] = json!(0);
    let src = decode(&v).expect("decodes");
    let bond = src.bond.expect("fixture has a bond record");
    assert_eq!(bond.last_served, ServeAnchor::ServedAt(0));
    assert_eq!(
        bond.last_served.as_verify_operand(),
        Some(0),
        "the verifier must see an anchor, not the permissive None"
    );
    let mut v = fixture();
    v["slash_epoch"] = json!(0);
    let bond = decode(&v).expect("decodes").bond.expect("bonded");
    assert_eq!(bond.last_settled_slash, SlashWatermark::SettledThrough(0));
}

/// `NeverServed` is a real daemon answer and must still reach the verifier as
/// `None` — the permissive branch is correct when the daemon *said* so. This
/// is the other half of the pair: the mapping is not "always fail closed", it
/// is "closed on unknown, faithful on known".
#[test]
fn never_served_reaches_the_verifier_as_the_permissive_none() {
    let src = decode(&fixture()).expect("decodes");
    let bond = src.bond.expect("fixture has a bond record");
    assert_eq!(bond.last_served, ServeAnchor::NeverServed);
    assert_eq!(bond.last_served.as_verify_operand(), None);
    assert_eq!(bond.last_settled_slash.as_verify_operand(), None);
}

/// The fixture record, gathered at block count 30 001.
fn fixture_source() -> EmissionClaimSource {
    EmissionClaimSource {
        chain_height: ChainCount::from_raw(30001),
        tip_hash: crate::engine::test_support::test_block_hash_at(30000),
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
                    is_support_complete_tree: false,
                    bad_intervals: vec![BadInterval {
                        start_epoch: 2,
                        end_exclusive: 3,
                    }],
                }],
                shards: vec![EpochCloseShard {
                    shard_id: 4,
                    close: ShardClose::ClosedAt(BlockHeight::from_raw(15)),
                }],
                credit_pairs: vec![CreditPair {
                    bond_idx: 0,
                    shard_idx: 0,
                }],
                claimant_bond_idx: Some(0),
            },
            // The empty-row epoch, with no budget row and no claimant.
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
    }
}

fn fixture() -> Value {
    source_json(&fixture_source())
}

/// **Empty lists are written, never omitted.** The reply is strict, so an
/// epoch with no bonds carries `"bond": []`, and one missing the member is
/// no reply rather than an empty list.
///
/// The edit that turns this red is a `#[serde(default)]` on a list.
#[test]
fn empty_lists_are_written_and_a_missing_one_is_refused() {
    let v = fixture();
    let e2 = &v["epoch"][1];
    for field in ["bond", "shard", "credit"] {
        assert_eq!(e2[field], json!([]), "`{field}` is written empty");
        let mut missing = fixture();
        missing["epoch"][1]
            .as_object_mut()
            .expect("an epoch is an object")
            .remove(field);
        assert!(
            matches!(decode(&missing), Err(Refused::Shape)),
            "`{field}` absent is no reply"
        );
    }
}

#[test]
fn decodes_fixture_field_for_field() {
    let src = decode(&fixture()).unwrap();
    assert_eq!(src.chain_height, ChainCount::from_raw(30001));
    assert_eq!(
        src.tip_hash,
        crate::engine::test_support::test_block_hash_at(30000)
    );
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

    let e2 = &src.epochs[1];
    assert!(!e2.has_budget_row);
    assert!(e2.bonds.is_empty());
    assert!(e2.shards.is_empty());
    assert!(e2.credit_pairs.is_empty());
    assert_eq!(e2.claimant_bond_idx, None);
}

/// **The failure interval is inclusive on the wire and end-exclusive in the
/// record.** The fixture's `[2, 3)` travels as `{"from": 2, "to": 2}`.
///
/// The edit that turns this red is the decode taking `to` as the exclusive
/// end: every interval would lose its last epoch.
#[test]
fn a_failure_interval_is_inclusive_on_the_wire() {
    let v = fixture();
    assert_eq!(
        v["epoch"][0]["bond"][0]["failure"],
        json!([{"from": 2, "to": 2}])
    );
}

#[test]
fn view_construction_matches_verify_shape() {
    let src = decode(&fixture()).unwrap();
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

/// `joined_epoch: null` is "no bond record", and the record's other members
/// are not read as one.
#[test]
fn no_bond_record_decodes_none() {
    let src = decode(&source_json(&EmissionClaimSource {
        bond: None,
        epochs: vec![],
        ..fixture_source()
    }))
    .unwrap();
    assert!(src.bond.is_none());
    assert!(src.epochs.is_empty());
}

#[test]
fn missing_mandatory_scalar_is_no_reply() {
    for field in ["settled_epoch", "height", "hash", "joined_epoch", "holding"] {
        let mut v = fixture();
        v.as_object_mut().unwrap().remove(field);
        assert!(
            matches!(decode(&v), Err(Refused::Shape)),
            "{field} absent is no reply"
        );
    }
}

/// **A refusal is not a payload.** A daemon that is not ready answers an
/// error object, never a zeroed record that would decode as "nothing
/// claimable"; the fetch surfaces it as the daemon's refusal.
#[tokio::test]
async fn a_refusal_is_an_error_not_an_empty_source() {
    #[derive(Clone)]
    struct NotReady;
    impl Rpc for NotReady {
        fn post(
            &self,
            _route: &str,
            _body: Vec<u8>,
        ) -> impl Send + std::future::Future<Output = Result<Vec<u8>, RpcError>> {
            let reply = serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "id": 0,
                "error": {
                    "code": -32004, "message": "not ready",
                    "data": {"code": "daemon.unready", "parameter": {}, "message": "not ready"},
                },
            }))
            .expect("encodes");
            async move { Ok(reply) }
        }
    }
    let err = fetch_emission_claim_source(&NotReady, &[7; 32])
        .await
        .expect_err("a refusal is not a source");
    assert!(
        matches!(&err, EmissionSourceError::Rpc(RpcError::Refused(refusal))
            if refusal.class == shekyl_rpc_client::ErrorClass::NotReady),
        "{err:?}"
    );
}

#[test]
fn unsorted_claimed_epochs_is_loud() {
    // The claimed set is a binary-search operand downstream; unsorted
    // input must be rejected at decode, never searched.
    let mut v = fixture();
    v["claimed"] = json!([5, 1]);
    assert!(matches!(decode(&v), Err(Refused::Malformed)));
    // Duplicates violate *strictly* increasing too.
    let mut v = fixture();
    v["claimed"] = json!([1, 1]);
    assert!(matches!(decode(&v), Err(Refused::Malformed)));
}

/// The settled/height pair is redundant (one read daemon-side); a reply
/// where they disagree under the frozen mapping is malformed — refused at
/// decode, never split across the builder's two boundary systems (window
/// verdicts read `current_settled_epoch`, the step-7 self-check recomputes
/// from the count).
#[test]
fn settled_epoch_inconsistent_with_height_is_loud() {
    // Deflated settled: the builder's window floor would lag verify's
    // (whole-batch SelfCheckFailed on an expired admit).
    let mut v = fixture();
    v["settled_epoch"] = json!(2);
    assert!(matches!(decode(&v), Err(Refused::Malformed)));
    // Inflated settled: genuinely claimable epochs would silently skip
    // as WindowExpired (forfeited rewards).
    let mut v = fixture();
    v["settled_epoch"] = json!(4);
    assert!(matches!(decode(&v), Err(Refused::Malformed)));
    // The fixture itself is the consistent pair: the settled epoch derives
    // from the COUNT, the wire's height plus one.
    assert_eq!(
        settlement_epoch_at_height(fixture()["height"].as_u64().unwrap() + 1),
        fixture()["settled_epoch"].as_u64().unwrap()
    );
}

#[test]
fn unsorted_window_epochs_is_loud() {
    let mut v = fixture();
    v["epoch"][0]["id"] = json!(2);
    v["epoch"][1]["id"] = json!(1);
    assert!(matches!(decode(&v), Err(Refused::Malformed)));
}

#[test]
fn an_inverted_failure_interval_is_loud() {
    let mut v = fixture();
    v["epoch"][0]["bond"][0]["failure"] = json!([{"from": 3, "to": 2}]);
    assert!(matches!(decode(&v), Err(Refused::Malformed)));
}

#[test]
fn unknown_holding_is_no_reply() {
    let mut v = fixture();
    v["holding"] = json!("everything");
    assert!(matches!(decode(&v), Err(Refused::Shape)));
}

// ── The record anchors itself: no re-read after it ──────────────────────

/// A daemon that answers the witness and the record, records the order it
/// was asked in, and keeps the last request's parameters.
#[derive(Clone)]
struct ClaimDaemon {
    record: std::sync::Arc<Value>,
    calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    params: std::sync::Arc<std::sync::Mutex<Value>>,
}

/// The witness answers at this count, so its tip is one below.
const WITNESS_COUNT: u64 = 30_001;

impl ClaimDaemon {
    fn new(record: Value) -> Self {
        Self {
            record: std::sync::Arc::new(record),
            calls: std::sync::Arc::default(),
            params: std::sync::Arc::default(),
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("call log").clone()
    }

    fn last_params(&self) -> Value {
        self.params.lock().expect("params").clone()
    }
}

impl Rpc for ClaimDaemon {
    fn get_block_hash(
        &self,
        number: usize,
    ) -> impl Send + std::future::Future<Output = Result<shekyl_types::BlockHash, RpcError>> {
        self.calls
            .lock()
            .expect("call log")
            .push(format!("get_block_hash({number})"));
        async move {
            Ok(crate::engine::test_support::test_block_hash_at(
                number as u64,
            ))
        }
    }

    fn post(
        &self,
        _route: &str,
        body: Vec<u8>,
    ) -> impl Send + std::future::Future<Output = Result<Vec<u8>, RpcError>> {
        use crate::engine::test_support::{method_name, requested_method, requested_params};
        let method = requested_method(&body);
        self.calls.lock().expect("call log").push(method.clone());
        *self.params.lock().expect("params") = requested_params(&body);
        let result = if method == method_name::<shekyl_rpc_client::wire::DaemonStatus>() {
            crate::engine::daemon::synced_chain_facts::DaemonStatusDocument {
                chain_count: shekyl_types::ChainCount::from_raw(WITNESS_COUNT),
                target_height: None,
                synchronized: true,
                top_hash: crate::engine::test_support::test_block_hash_at(WITNESS_COUNT - 1),
                peered: true,
            }
            .to_value()
        } else {
            (*self.record).clone()
        };
        let reply = crate::engine::test_support::result_envelope(&result);
        async move { Ok(reply) }
    }
}

/// The fixture record, re-stamped as gathered at `count` under `hash` — the
/// decoder cross-checks the settled epoch against the count, so both move
/// together.
fn record_at(count: u64, hash: [u8; 32]) -> Value {
    let mut v = fixture();
    v["height"] = json!(count - 1);
    v["hash"] = json!(hex::encode(hash));
    v["settled_epoch"] = json!(shekyl_archival_retention::settlement_epoch_at_height(count));
    v
}

/// **The record anchors itself.** It names the block it was gathered at, so
/// the vouched view's anchor is that block — its height and its hash, from
/// the record — and an observation drawn from it is stamped where it was
/// seen. The witness block is not consulted again.
///
/// The edit that turns this red is anchoring at the witness block, or
/// stamping at the witness height.
#[tokio::test]
async fn a_vouched_record_anchors_at_its_own_block() {
    let daemon = ClaimDaemon::new(record_at(WITNESS_COUNT + 5, [0x5E; 32]));
    let vouched = fetch_vouched_claim_source(&daemon, &[7; 32])
        .await
        .expect("the record reads");
    let view = vouched.actionable().expect("an advance is actionable");
    assert_eq!(
        view.anchor(),
        ChainAnchor {
            height: BlockHeight::from_raw(WITNESS_COUNT + 4),
            hash: shekyl_types::BlockHash::from_bytes([0x5E; 32]),
        }
    );
    assert_eq!(view.at(), BlockHeight::from_raw(WITNESS_COUNT + 4));
}

/// **Two reads, in order, and no third.** The witness is read first, so a
/// record below it is a rollback rather than a race; the record names its
/// own block, so no re-read after it can add anything.
///
/// The edit that turns this red is a re-read of the witness block after the
/// record, or the record read before the witness.
#[tokio::test]
async fn the_witness_then_the_record_and_nothing_after() {
    let daemon = ClaimDaemon::new(record_at(WITNESS_COUNT, [0x5E; 32]));
    fetch_vouched_claim_source(&daemon, &[7; 32])
        .await
        .expect("reads");
    assert_eq!(
        daemon.calls(),
        vec![
            crate::engine::test_support::method_name::<shekyl_rpc_client::wire::DaemonStatus>()
                .to_string(),
            crate::engine::test_support::method_name::<shekyl_rpc_client::wire::ArchivalClaimShow>(
            )
            .to_string(),
        ],
    );
}

/// **A record below its witness is a rollback**, refused for acting
/// whatever hash it carries.
#[tokio::test]
async fn a_record_below_its_witness_is_not_actionable() {
    let daemon = ClaimDaemon::new(record_at(WITNESS_COUNT - 10, [0x5E; 32]));
    let vouched = fetch_vouched_claim_source(&daemon, &[7; 32])
        .await
        .expect("the record reads");
    assert_eq!(
        vouched.actionable().expect_err("rolled back"),
        TimelineBreak::ChainRolledBack
    );
}
