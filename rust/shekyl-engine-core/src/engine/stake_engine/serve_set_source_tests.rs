// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tests for the production serve-set pinner (`stake_engine/serve_set_source.rs`).
//!
//! Wired as a `#[path]` child of `serve_set_source::tests`, so `use super::*`
//! resolves into the parent module and its private fields stay reachable;
//! the sibling file exists so the decomposition ratchet counts the production
//! module, not its test suite (the `departure_ledger_tests.rs` /
//! `synced_chain_facts_tests.rs` pattern). What lives here is the seam this
//! module owns — record decode, the two empties, the resync properties, the
//! holdings-kind transition and the rollback refresh.

use super::*;
use crate::engine::emission_claim::test_fixtures::source_json;
use crate::engine::emission_source::{BondContext, EmissionClaimSource};
use crate::engine::test_support::test_block_hash_at;
use shekyl_archival_retention::{
    settlement_epoch_at_height, HoldingsDescriptor, HoldingsKind, ShardSet,
};
use shekyl_curve_tree::{CurveTreeClient, PostureDeclaration, SegmentPin};
use shekyl_rpc_client::{Rpc, RpcError};
use shekyl_types::ChainCount;
use std::sync::Arc;

/// A daemon serving one canned claim-source reply through the real
/// `json_rpc_call` envelope (only the transport is canned, so the decode
/// this pinner depends on runs unmocked).
#[derive(Clone)]
struct ClaimSourceDaemon(Arc<serde_json::Value>);

impl Rpc for ClaimSourceDaemon {
    fn get_block_hash(
        &self,
        number: usize,
    ) -> impl Send + std::future::Future<Output = Result<[u8; 32], RpcError>> {
        async move { Ok(test_block_hash_at(number as u64)) }
    }

    /// Answers `get_info` as a **synchronized** daemon at the same chain
    /// count its claim source reports, so these fixtures keep exactly the
    /// semantics they had before `SyncedChainFacts` (`WSS-Q14`) — the
    /// unsynchronized timeline is `ScheduledDaemon`'s to exercise, and a
    /// fixture that answered it here would silently disable the release
    /// half of every test below.
    fn post(
        &self,
        route: &str,
        body: Vec<u8>,
    ) -> impl Send + std::future::Future<Output = Result<Vec<u8>, RpcError>> {
        let is_get_info = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("method").and_then(|m| m.as_str()).map(str::to_owned))
            .is_some_and(|m| m == "get_info");
        let result = if is_get_info {
            serde_json::json!({
                "height": self.0.get("chain_height").and_then(serde_json::Value::as_u64)
                    .expect("the fixture source carries a chain height"),
                "target_height": 0,
                "synchronized": true,
                "top_block_hash": hex::encode(test_block_hash_at(
                    self.0.get("chain_height").and_then(serde_json::Value::as_u64)
                        .expect("the fixture source carries a chain height")
                        .saturating_sub(1),
                )),
                "outgoing_connections_count": 8,
                "incoming_connections_count": 0,
            })
        } else {
            (*self.0).clone()
        };
        let reply = serde_json::to_vec(&serde_json::json!({ "result": result }))
            .expect("fixture result encodes");
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

// The §7.4 marker, asserted for the fixture exactly as
// `claim_orchestrator`'s test daemon asserts it. The bound is what the
// production wiring must satisfy, so the test transport has to satisfy it
// too — a fixture exempt from the pin would test a signature nothing else
// can call.
impl PersonaIsolatedTransport for ClaimSourceDaemon {}

/// A claim-source reply at `chain_height`, holding `shard_ids` (or no
/// bond record at all when `shard_ids` is `None`).
fn daemon(chain_height: u64, shard_ids: Option<Vec<u64>>) -> ClaimSourceDaemon {
    daemon_of_kind(chain_height, shard_ids, HoldingsKind::ShardSetCompact)
}

/// The same reply with the holdings **kind** chosen, so the two empties —
/// an empty `ShardSetCompact` and a `CompleteTree` — are both reachable.
fn daemon_of_kind(
    chain_height: u64,
    shard_ids: Option<Vec<u64>>,
    kind: HoldingsKind,
) -> ClaimSourceDaemon {
    ClaimSourceDaemon(Arc::new(source_json(&EmissionClaimSource {
        chain_height: ChainCount::from_raw(chain_height),
        // The decoder cross-checks this against `chain_height` — the
        // daemon derives both from one `db.height()` read — so the
        // fixture derives it the same way rather than pinning a literal
        // that would rot the moment the epoch length moves.
        current_settled_epoch: settlement_epoch_at_height(chain_height),
        bond: shard_ids.map(|ids| BondContext {
            join_settlement_epoch: 0,
            holdings: HoldingsDescriptor {
                kind,
                shard_ids: ShardSet::new(ids).expect("fixture shard set"),
            },
            claimed_settlement_epochs: Vec::new(),
            bonded_total_atomic: 0,
            bad_interval_count: 0,
            last_served: crate::engine::emission_source::ServeAnchor::NeverServed,
            last_settled_slash: crate::engine::emission_source::SlashWatermark::NothingSettled,
        }),
        epochs: Vec::new(),
    })))
}

fn handle() -> (tempfile::TempDir, CurveTreeHandle) {
    let dir = tempfile::tempdir().expect("tempdir");
    let client = CurveTreeClient::open(dir.path().join("curve_tree.redb"))
        .expect("open fresh curve-tree client");
    (dir, CurveTreeHandle::spawn(client))
}

/// A handle over a store whose segment 0 is already frozen.
///
/// The segment is written **before** the client opens, because the
/// actor holds the store exclusively once spawned — the same reason
/// this fixture cannot freeze anything mid-test.
fn handle_with_frozen_segment() -> (tempfile::TempDir, CurveTreeHandle) {
    use shekyl_curve_tree::{
        leaves_per_segment, Gindex, LeafEntry, LeafStore, OutputIdentity, TargetKind,
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("curve_tree.redb");
    {
        let store = LeafStore::open(&path).expect("open fresh store");
        let entries: Vec<LeafEntry> = (0..leaves_per_segment() as u64)
            .map(|gindex| {
                let mut leaf = [1u8; 128];
                leaf[..8].copy_from_slice(&(gindex + 1).to_le_bytes());
                LeafEntry {
                    gindex: Gindex::from_raw(gindex),
                    maturity: BlockHeight::from_raw(60),
                    creation_height: BlockHeight::from_raw(0),
                    leaf,
                    identity: OutputIdentity {
                        output_key: shekyl_curve_tree::OneTimePubkey::from_bytes([1u8; 32]),
                        commitment: Some(shekyl_curve_tree::CommitmentBytes::from_bytes([2u8; 32])),
                        cm: [3u8; 32],
                        target: TargetKind::TaggedKey,
                    },
                }
            })
            .collect();
        // Buried far past the freeze gate, so segment 0 froze on append.
        store
            .append_block_deltas(&entries, &[], &[], BlockHeight::from_raw(30_000))
            .expect("append a full frozen segment");
    }
    let client = CurveTreeClient::open(path).expect("resume over the frozen store");
    (dir, CurveTreeHandle::spawn(client))
}

/// **The production pinner's own KAT.** Every `shekyl-p-host` test drives
/// a test-side pinner, so the mapping this function performs — record →
/// `shard_ids`, `chain_height` → `as_of_height`, actor round trip →
/// outcomes + reader — is the one part of the seam no host-side test can
/// reach. Without this it could be wrong in any of those four places
/// while the whole suite stayed green.
// The gate's pure semantics — the two-epoch window, the returning-shard
// reset, the owed-shard refusal and the backwards-chain case — moved to
// `departure_ledger_tests.rs` with the type that now owns them. They are
// not duplicated here: a second copy of one gate's rules is how the two
// come to disagree. What stays below is the *seam* this file owns —
// record decode, the two empties, and the resync property test.

#[tokio::test]
async fn the_report_is_derived_from_the_connected_record() {
    let (_dir, curve_tree) = handle();
    let pinner = EngineServeSetPinner::new(curve_tree, daemon(30_001, Some(vec![4, 9])), [7; 32]);

    let report = pinner.pin_serve_set().await.expect("pin");

    let shekyl_p_host::ReportedSet::ShardList {
        shard_ids,
        outcomes,
    } = report.set
    else {
        panic!("explicit holdings report the list arm");
    };
    assert_eq!(
        shard_ids,
        vec![4, 9],
        "the set is the connected record's holdings, not anything held locally"
    );
    assert_eq!(
        report.as_of_height,
        BlockHeight::from_raw(30_000),
        "chain_height is a COUNT; the stamp is the tip it describes, one lower"
    );
    assert_eq!(
        outcomes
            .iter()
            .map(|(shard_id, _)| *shard_id)
            .collect::<Vec<_>>(),
        vec![4, 9],
        "outcomes come back covering the reported set, in the record's order"
    );
    assert!(
        outcomes
            .iter()
            .all(|(_, pin)| *pin == SegmentPin::PinnedNotYetFrozen),
        "an empty store has frozen nothing, so bonding is ahead of the freeze"
    );
}

/// No bond record is a persona that owes nothing — not a failure, and not
/// a serve-set the host has to guess at. It must still report a height,
/// so a wallet that has not bonded yet keeps a witness that describes
/// reality instead of failing every refresh forever.
#[tokio::test]
async fn an_released_persona_reports_the_empty_set_rather_than_failing() {
    let (_dir, curve_tree) = handle();
    let pinner = EngineServeSetPinner::new(curve_tree, daemon(30_001, None), [7; 32]);

    let report = pinner
        .pin_serve_set()
        .await
        .expect("no bond is not an error");

    let shekyl_p_host::ReportedSet::ShardList {
        shard_ids,
        outcomes,
    } = report.set
    else {
        panic!("a released persona reports the (empty) list arm");
    };
    assert!(shard_ids.is_empty());
    assert!(outcomes.is_empty());
    assert_eq!(report.as_of_height, BlockHeight::from_raw(30_000));
}

/// **The two empties, asserted together, because the pair is the
/// contract.** `CompleteTree` carries no shard list by wire rule
/// (`BondPostError::CompleteTreeWithShardIds`), so it decodes to the same
/// bytes as a persona owing nothing while meaning the exact opposite — the
/// whole corpus. Pinning that empty set would report a `Current` witness
/// for a persona serving none of its obligation.
///
/// Both arms live in one test on purpose: a `CompleteTree`-only assertion
/// would also pass against an implementation that keyed on
/// `shard_ids.is_empty()`, which is the *wrong* discriminant — it would
/// route the legitimately-empty `ShardSetCompact` case into the whole-
/// corpus arm in the same stroke. The discriminant is the thing under
/// test, not the emptiness.
///
/// **This is the slice-3 flip of the SH-2 refusal.** The same two
/// inputs that used to prove "CompleteTree refuses, empty compact
/// reports empty" now prove "CompleteTree reports the *prefix*, empty
/// compact still reports the empty *list*" — the obligation is
/// expressed, not refused, and the pair still cannot be conflated.
#[tokio::test]
async fn complete_tree_reports_the_prefix_while_an_empty_shard_set_reports_the_empty_list() {
    let (_dir_a, curve_tree_a) = handle();
    let complete_tree = EngineServeSetPinner::new(
        curve_tree_a,
        daemon_of_kind(30_001, Some(Vec::new()), HoldingsKind::CompleteTree),
        [7; 32],
    );
    let report = complete_tree
        .pin_serve_set()
        .await
        .expect("a whole-corpus obligation is expressed, not refused");
    let shekyl_p_host::ReportedSet::CompleteTreePrefix {
        frozen_count,
        declaration,
    } = report.set
    else {
        panic!("CompleteTree holdings must report the prefix arm");
    };
    assert_eq!(
        frozen_count, 0,
        "an un-ingested store has frozen nothing: the obligation is \
         honestly empty and grows as segments freeze (D-5)"
    );
    assert_eq!(
        declaration,
        PostureDeclaration::NewlyDeclared,
        "the first report declares the prune-disabled posture — the \
         prefix arm's pin — and says it did"
    );
    assert_eq!(report.as_of_height, BlockHeight::from_raw(30_000));

    // Same empty list on the wire, opposite meaning, and it must still
    // report the LIST arm.
    let (_dir_b, curve_tree_b) = handle();
    let owes_nothing = EngineServeSetPinner::new(
        curve_tree_b,
        daemon_of_kind(30_001, Some(Vec::new()), HoldingsKind::ShardSetCompact),
        [7; 32],
    );
    let report = owes_nothing
        .pin_serve_set()
        .await
        .expect("an empty ShardSetCompact owes nothing and is not an error");
    let shekyl_p_host::ReportedSet::ShardList {
        shard_ids,
        outcomes,
    } = report.set
    else {
        panic!("an empty ShardSetCompact reports the (empty) list arm");
    };
    assert!(shard_ids.is_empty());
    assert!(outcomes.is_empty());
}

/// **The reported count is the store's own cursor, and re-reporting is
/// quiet.** This is the mapping only an engine-side test can reach:
/// over a store that has actually frozen a segment the report carries
/// `1`, not the `0` a fresh store gives — so a pinner that hardcoded
/// the empty prefix, or read the wrong counter, fails here. The second
/// report's `AlreadyDeclared` is the steady-state answer that tells the
/// witness no retention gap opened between refreshes (RR-2).
///
/// Growth *across a refresh* (a segment freezing between two reports)
/// is `shekyl-p-host`'s KAT, driven against its own store; this test
/// does not duplicate it, because the actor holds this store
/// exclusively and freezing mid-test would mean driving full block
/// ingest to prove a mapping that layer already proves.
#[tokio::test]
async fn the_prefix_reports_the_store_cursor_and_redeclares_quietly() {
    let (_dir, curve_tree) = handle_with_frozen_segment();
    let pinner = EngineServeSetPinner::new(
        curve_tree,
        daemon_of_kind(30_001, Some(Vec::new()), HoldingsKind::CompleteTree),
        [7; 32],
    );

    let first = pinner.pin_serve_set().await.expect("first report");
    let shekyl_p_host::ReportedSet::CompleteTreePrefix {
        frozen_count,
        declaration,
    } = first.set
    else {
        panic!("prefix arm");
    };
    assert_eq!(
        frozen_count, 1,
        "the obligation is the store's frozen prefix — one segment is \
         frozen, so the persona owes exactly [0, 1)"
    );
    assert_eq!(declaration, PostureDeclaration::NewlyDeclared);

    let second = pinner.pin_serve_set().await.expect("second report");
    let shekyl_p_host::ReportedSet::CompleteTreePrefix {
        frozen_count,
        declaration,
    } = second.set
    else {
        panic!("prefix arm");
    };
    assert_eq!(frozen_count, 1, "nothing froze in between");
    assert_eq!(
        declaration,
        PostureDeclaration::AlreadyDeclared,
        "the posture was already declared, so no retention gap opened \
         between the two reports"
    );
}

/// An empty chain has no tip. `ChainCount(0).tip()` is `None`, and the
/// stamp must land on 0 rather than underflow or refuse — 0 is also what
/// an un-ingested store reports, so the host's lag reads zero and the
/// tripwire correctly stays quiet on a wallet at genesis.
#[tokio::test]
async fn an_empty_chain_stamps_height_zero() {
    let (_dir, curve_tree) = handle();
    let pinner = EngineServeSetPinner::new(curve_tree, daemon(0, None), [7; 32]);

    let report = pinner.pin_serve_set().await.expect("pin");
    assert_eq!(report.as_of_height, BlockHeight::from_raw(0));
}

/// The reader that comes back must be a handle on the store the pins
/// landed in — the trait contract `PinnedServeSet::refreshed` enforces
/// with `same_store`. One actor `ask` returns both, so they cannot
/// diverge; this pins that they do not.
#[tokio::test]
async fn the_reader_is_the_store_the_pins_landed_in() {
    let (_dir, curve_tree) = handle();
    let pinner = EngineServeSetPinner::new(curve_tree, daemon(30_001, Some(vec![1])), [7; 32]);

    let first = pinner.pin_serve_set().await.expect("pin");
    let second = pinner.pin_serve_set().await.expect("pin again");

    assert!(
        first.reader.same_store(&second.reader),
        "two pins through one handle are two pins in one store"
    );
}

// ── WSS-25: the resync that would erase every holding ───────────────
//
// `WALLET_SIDE_STORE.md` §6.7.3: *the release gate records no absence
// observations and releases nothing while the daemon is unsynced*, and it
// *"owes a property test: no shard is erased while the pair can still be
// drawn, including across a simulated resync. A test that only exercises a
// synced timeline cannot fail on WSS-25's scenario, which is the one that
// matters."*

/// Every shard id the store is actually retaining, read through the actor
/// that owns it. A no-op reconcile (pin nothing, release nothing) is the
/// only read path there is, and its `pinned_now` is the same value the
/// production refresh reads back.
async fn pins_in_store(curve_tree: &CurveTreeHandle) -> Vec<u64> {
    curve_tree
        .pin_serve_set(Vec::new(), Vec::new())
        .await
        .expect("read the pin set")
        .pinned_now
}

/// A daemon rebuilding its chain — the state the C++→Rust cutover forces
/// on every daemon.
///
/// One height schedule drives **both** answers, which is the point: the
/// resync hazard is that the record answers at a pre-bond height *while*
/// the daemon's own height climbs past epoch boundaries, so a fixture that
/// let the two drift apart would be testing something else. `get_info`
/// advances the cursor and the claim source reads it, matching production
/// order (health first, then the record).
///
/// `target_height` is the sync dial: a non-zero value above the answering
/// height is a daemon that says it is still catching up; `0` is the info
/// surface's "synchronized" convention.
/// One refresh's worth of daemon: the tip it answers at and what the bond
/// record says at that tip.
#[derive(Clone)]
struct Step {
    tip: u64,
    /// The tip the RECORD answers at, when it differs from the witness's
    /// — below it is the rollback signature.
    record_tip: Option<u64>,
    kind: HoldingsKind,
    owed: Vec<u64>,
}

impl Step {
    fn compact(tip: u64, owed: &[u64]) -> Self {
        Self {
            tip,
            record_tip: None,
            kind: HoldingsKind::ShardSetCompact,
            owed: owed.to_vec(),
        }
    }

    /// The witness answers at `tip`; the record answers **below** it, at
    /// `record_tip`: the chain rolled back between the two reads.
    fn rolled_back(tip: u64, record_tip: u64, owed: &[u64]) -> Self {
        assert!(
            record_tip < tip,
            "a rollback step answers its record below its witness"
        );
        Self {
            tip,
            record_tip: Some(record_tip),
            kind: HoldingsKind::ShardSetCompact,
            owed: owed.to_vec(),
        }
    }

    /// A `CompleteTree` record carries no list by wire rule.
    fn complete_tree(tip: u64) -> Self {
        Self {
            tip,
            record_tip: None,
            kind: HoldingsKind::CompleteTree,
            owed: Vec::new(),
        }
    }
}

#[derive(Clone)]
struct ScheduledDaemon {
    schedule: Arc<Vec<Step>>,
    cursor: Arc<std::sync::atomic::AtomicUsize>,
    /// The step the current refresh answers from, written by `get_info`.
    current: Arc<std::sync::Mutex<usize>>,
    /// `0` means synchronized; anything else is the climbing target.
    target_height: u64,
}

impl ScheduledDaemon {
    fn new(schedule: Vec<Step>, target_height: u64) -> Self {
        Self {
            schedule: Arc::new(schedule),
            cursor: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            current: Arc::new(std::sync::Mutex::new(0)),
            target_height,
        }
    }

    /// Take the next scheduled step, holding at the last one so a test
    /// may drive more refreshes than it scheduled.
    fn step(&self) -> Step {
        let i = self
            .cursor
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            .min(self.schedule.len() - 1);
        *self.current.lock().expect("schedule cursor") = i;
        self.schedule[i].clone()
    }

    fn current(&self) -> Step {
        self.schedule[*self.current.lock().expect("schedule cursor")].clone()
    }
}

impl Rpc for ScheduledDaemon {
    fn get_block_hash(
        &self,
        number: usize,
    ) -> impl Send + std::future::Future<Output = Result<[u8; 32], RpcError>> {
        async move { Ok(test_block_hash_at(number as u64)) }
    }

    fn post(
        &self,
        route: &str,
        body: Vec<u8>,
    ) -> impl Send + std::future::Future<Output = Result<Vec<u8>, RpcError>> {
        let method = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("method").and_then(|m| m.as_str()).map(str::to_owned))
            .unwrap_or_default();
        let result = if method == "get_info" {
            // `get_info.height` is the block COUNT (`top_block + 1`), and
            // the schedule is written in tips — the same relation the
            // claim source below reports, because both come off one
            // `db.height()` read on the daemon.
            let tip = self.step().tip;
            serde_json::json!({
                "height": tip + 1,
                "target_height": self.target_height,
                // A resyncing daemon says so outright; the heights are
                // the second half of the same statement.
                "synchronized": self.target_height == 0,
                "top_block_hash": hex::encode(test_block_hash_at(tip)),
                "outgoing_connections_count": 8,
                "incoming_connections_count": 0,
            })
        } else {
            // `chain_height` is a COUNT; the schedule is expressed in
            // tips, so the record answers one more than the tip — the
            // same relation `get_info` carries (`top_block + 1`).
            let step = self.current();
            let tip = step.record_tip.unwrap_or(step.tip);
            source_json(&EmissionClaimSource {
                chain_height: ChainCount::from_raw(tip + 1),
                current_settled_epoch: settlement_epoch_at_height(tip + 1),
                bond: Some(BondContext {
                    join_settlement_epoch: 0,
                    holdings: HoldingsDescriptor {
                        kind: step.kind,
                        shard_ids: ShardSet::new(step.owed).expect("fixture set"),
                    },
                    claimed_settlement_epochs: Vec::new(),
                    bonded_total_atomic: 0,
                    bad_interval_count: 0,
                    last_served: crate::engine::emission_source::ServeAnchor::NeverServed,
                    last_settled_slash:
                        crate::engine::emission_source::SlashWatermark::NothingSettled,
                }),
                epochs: Vec::new(),
            })
        };
        let reply = serde_json::to_vec(&serde_json::json!({ "result": result }))
            .expect("fixture result encodes");
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

impl PersonaIsolatedTransport for ScheduledDaemon {}

/// The heights a resync walks through: a pre-bond height, then a climb
/// crossing **four** settlement-epoch opens — far past the two the gate
/// releases at. `SETTLEMENT_EPOCH_BLOCKS = 10_000`.
fn resync_climb() -> Vec<u64> {
    vec![1_000, 9_999, 10_000, 20_000, 30_000, 40_000]
}

/// The climb as compact-record steps, owing `owed` throughout.
fn compact_climb(owed: &[u64]) -> Vec<Step> {
    resync_climb()
        .into_iter()
        .map(|tip| Step::compact(tip, owed))
        .collect()
}

/// **The `WSS-25` property.** A shard held but absent from the record
/// answered by an **unsynchronized** daemon is neither observed absent nor
/// released, however far the answering height climbs.
///
/// This bites against the release gate acting on a resyncing view; it does
/// **not** cover a daemon that lies "synchronized" (`SyncedChainFacts`
/// carries the daemon's claim, not an independent measurement), nor the
/// erasure semantics that replace unpinning after the `WSS-13` unwind.
#[tokio::test]
async fn a_resyncing_daemon_releases_nothing_and_observes_no_absence() {
    let (_dir, curve_tree) = handle();
    // Owes shard 1 only; shard 9 is held from an older record.
    let rpc = ScheduledDaemon::new(compact_climb(&[1]), 1_000_000);
    let pinner = EngineServeSetPinner::new(curve_tree, rpc, [7; 32]);

    // Seed the store's pin view with both shards, so 9 is retained-but-
    // not-owed for every step of the climb.
    pinner
        .curve_tree
        .pin_serve_set(vec![1, 9], Vec::new())
        .await
        .expect("seed pins");
    *pinner.last_pinned.lock().expect("pin view") = vec![1, 9];

    for _ in 0..resync_climb().len() {
        let report = pinner.pin_serve_set().await.expect("refresh");
        match report.set {
            shekyl_p_host::ReportedSet::ShardList { .. } => {}
            other => panic!("expected a shard list, got {other:?}"),
        }
    }

    assert!(
        pinner
            .absent_since
            .lock()
            .expect("departure ledger")
            .observed_absences()
            == 0,
        "an unsynchronized view must record NO absence observation: the \
         record answers at pre-bond heights, so 'absent' is a statement \
         about the resync, not about the persona's holdings",
    );
    assert_eq!(
        pins_in_store(&pinner.curve_tree).await,
        vec![1, 9],
        "nothing released across a climb of four epoch opens",
    );
}

/// The negative control, and the "two-epoch semantics unchanged" half:
/// the identical climb against a **synchronized** daemon releases the
/// departed shard at the second consecutive epoch open, exactly as before
/// this type existed. Without this, the test above would pass on a gate
/// that had simply stopped working.
#[tokio::test]
async fn the_same_climb_synchronized_still_releases_at_the_second_epoch_open() {
    let (_dir, curve_tree) = handle();
    let rpc = ScheduledDaemon::new(compact_climb(&[1]), 0);
    let pinner = EngineServeSetPinner::new(curve_tree, rpc, [7; 32]);

    pinner
        .curve_tree
        .pin_serve_set(vec![1, 9], Vec::new())
        .await
        .expect("seed pins");
    *pinner.last_pinned.lock().expect("pin view") = vec![1, 9];

    // 1_000 (first absent, epoch 0), 9_999 (epoch 0), 10_000 (epoch 1 —
    // one open, too tight), 20_000 (epoch 2 — released).
    for expected_pins in [vec![1, 9], vec![1, 9], vec![1, 9], vec![1]] {
        pinner.pin_serve_set().await.expect("refresh");
        assert_eq!(pins_in_store(&pinner.curve_tree).await, expected_pins);
    }
}

/// **A `CompleteTree` epoch is observed, not skipped.** Shard 9 is
/// absent under a compact record at epoch 0, owed by a `CompleteTree`
/// record at epoch 1 — drawable, so challengeable — and absent again
/// under a compact record at epoch 2. Its clock must restart at epoch 2:
/// the release comes two epoch opens after *that*, at epoch 4, and not
/// at epoch 2 on the strength of a clock the owed epoch should have
/// stopped.
///
/// The edit that turns this red is the `CompleteTree` arm not passing
/// through `observe` — the shape this pinner had, where the prefix arm
/// was exempt because it "has no release path". The control is the
/// release at epoch 4, which shows the clock restarted rather than
/// stopped for good.
#[tokio::test]
async fn a_complete_tree_epoch_forgets_the_absence_clock_before_it() {
    let (_dir, curve_tree) = handle();
    let schedule = vec![
        Step::compact(1_000, &[1]),
        Step::complete_tree(10_000),
        Step::compact(20_000, &[1]),
        Step::compact(30_000, &[1]),
        Step::compact(40_000, &[1]),
    ];
    let expected_pins: [&[u64]; 5] = [&[1, 9], &[1, 9], &[1, 9], &[1, 9], &[1]];
    let rpc = ScheduledDaemon::new(schedule, 0);
    let pinner = EngineServeSetPinner::new(curve_tree, rpc, [7; 32]);
    pinner
        .curve_tree
        .pin_serve_set(vec![1, 9], Vec::new())
        .await
        .expect("seed pins");
    *pinner.last_pinned.lock().expect("pin view") = vec![1, 9];

    for (i, expected) in expected_pins.into_iter().enumerate() {
        pinner.pin_serve_set().await.expect("refresh");
        assert_eq!(
            pins_in_store(&pinner.curve_tree).await,
            expected,
            "after refresh {i}: an absence clock does not survive an epoch in which the \
             shard was owed, and restarts when the shard leaves again",
        );
    }
}

/// **A rollback refresh leaves the ledger empty, and the next anchored
/// observation inherits nothing from it.** Shard 9 is absent at epoch 0;
/// the epoch-1 refresh reads its record below its witness — a rollback
/// — so nothing about that refresh is continuity-checkable; the epoch-2
/// refresh sees 9 absent again. Its clock must start at epoch 2, not
/// resume from epoch 0: release comes at epoch 4.
///
/// The rolled-back view never reaches the ledger — `observe` takes an
/// `AnchoredView`, which a rolled-back view cannot become — so the edit
/// that turns this red is structural: `observe` accepting a
/// `CoherentChainView` again *and* the pinner handing it one. What this
/// test pins at runtime is the ledger's state after the break and the
/// fresh start after it.
#[tokio::test]
async fn a_rollback_refresh_leaves_the_ledger_empty_and_the_next_observation_starts_fresh() {
    let (_dir, curve_tree) = handle();
    let schedule = vec![
        Step::compact(1_000, &[1]),
        Step::rolled_back(10_000, 9_000, &[1]),
        Step::compact(20_000, &[1]),
        Step::compact(30_000, &[1]),
        Step::compact(40_000, &[1]),
    ];
    let expected_pins: [&[u64]; 5] = [&[1, 9], &[1, 9], &[1, 9], &[1, 9], &[1]];
    let pinner = EngineServeSetPinner::new(curve_tree, ScheduledDaemon::new(schedule, 0), [7; 32]);
    pinner
        .curve_tree
        .pin_serve_set(vec![1, 9], Vec::new())
        .await
        .expect("seed pins");
    *pinner.last_pinned.lock().expect("pin view") = vec![1, 9];

    for (i, expected) in expected_pins.into_iter().enumerate() {
        pinner.pin_serve_set().await.expect("refresh");
        assert_eq!(
            pins_in_store(&pinner.curve_tree).await,
            expected,
            "after refresh {i}"
        );
        let ledger = pinner.absent_since.lock().expect("departure ledger");
        match i {
            0 => assert_eq!(ledger.observed_absences(), 1, "9 is absent at epoch 0"),
            1 => {
                assert_eq!(
                    ledger.observed_absences(),
                    0,
                    "a rollback refresh records nothing"
                );
                assert_eq!(ledger.resting_on(), None, "and rests on nothing");
            }
            2 => assert_eq!(
                ledger.observed_absences(),
                1,
                "9's clock restarts at epoch 2"
            ),
            _ => {}
        }
    }
}
