// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`SyncedChainFacts`] — the constructor's refusal, the unit it carries, and
//! the `get_info` decode it shares with the watchdog's health snapshot.

use super::*;
use serde_json::json;

/// A fixed identity for tests whose subject is the predicate, not the chain.
fn any_hash() -> BlockHash {
    BlockHash::from_bytes([0xAB; 32])
}

/// A `get_info` reply. `target_height` follows the info surface's convention:
/// `0` means the daemon considers itself synchronized.
fn info(height: u64, target_height: u64) -> Value {
    json!({
        "height": height,
        "target_height": target_height,
        "synchronized": true,
        "top_block_hash": hex::encode([0xAB; 32]),
        "outgoing_connections_count": 5,
        "incoming_connections_count": 3,
    })
}

/// With the daemon's own flag set, `target_height: 0` is the steady state —
/// a live synchronized node reports it at every height.
#[test]
fn a_zero_target_is_the_synchronized_statement_at_any_height() {
    for height in [0, 1, 20_000, u64::MAX] {
        assert!(
            SyncedChainFacts::new(ChainCount::from_raw(height), 0, true, any_hash()).is_some(),
            "target 0 is synchronized at height {height}",
        );
    }
}

/// A daemon still climbing toward a target above its height refuses to yield
/// the type. This is the `WSS-25` state: mid-resync, a record answers at a
/// pre-bond height while the daemon says it has a long way to go.
#[test]
fn a_daemon_below_its_target_yields_no_facts() {
    assert!(
        SyncedChainFacts::new(ChainCount::from_raw(1_000), 1_000_000, true, any_hash()).is_none()
    );
    assert!(
        SyncedChainFacts::new(ChainCount::from_raw(999_999), 1_000_000, true, any_hash()).is_none(),
        "one block short is still short — there is no near-enough",
    );
}

/// Reaching or overtaking the target is synchronized whatever the field says:
/// a node whose network estimate has been passed is not behind.
#[test]
fn reaching_or_overtaking_the_target_is_synchronized() {
    assert!(
        SyncedChainFacts::new(ChainCount::from_raw(1_000_000), 1_000_000, true, any_hash())
            .is_some()
    );
    assert!(
        SyncedChainFacts::new(ChainCount::from_raw(1_000_001), 1_000_000, true, any_hash())
            .is_some()
    );
}

/// The count/height distinction, pinned. `get_info.height` is the block
/// **count** (`core_rpc_server.cpp:206-207` increments the top block's
/// height), so the newest existing block sits one below it. A consumer doing
/// epoch arithmetic on the count instead of the tip lands one block early at
/// every boundary — invisible to any test that never crosses one.
#[test]
fn the_tip_is_one_below_the_count_and_an_empty_chain_reads_zero() {
    let facts =
        SyncedChainFacts::new(ChainCount::from_raw(20_001), 0, true, any_hash()).expect("synced");
    assert_eq!(facts.tip(), BlockHeight::from_raw(20_000));

    let empty = SyncedChainFacts::new(ChainCount::from_raw(0), 0, true, any_hash())
        .expect("synced, empty chain");
    assert_eq!(
        empty.tip(),
        BlockHeight::from_raw(0),
        "an empty chain has no tip; elapsed-block arithmetic reads it as zero",
    );
}

/// A reply without `height` is a malformed reply, not a synced chain of
/// length zero. Defaulting here would mint a `SyncedChainFacts` vouching for
/// a view that does not exist — the one decode error that must not fail soft.
#[test]
fn a_reply_without_a_height_is_refused_rather_than_defaulted() {
    let err = health_from_get_info(&json!({ "target_height": 0 }))
        .expect_err("a missing height is malformed");
    assert_eq!(err, GetInfoFault::HeightMissing);
}

/// Only the connection counts are optional, and only because zero is
/// honestly "none known" there.
///
/// `target_height` is **not** among them: zero is its synchronized sentinel,
/// so a default would have the decoder manufacture the claim the constructor
/// verifies. The edit that turns this red is restoring `.unwrap_or(0)` for
/// symmetry — which is exactly the tempting edit, hence the test.
#[test]
fn only_the_non_destructive_connection_counts_default() {
    let health = health_from_get_info(
        &json!({ "height": 77, "target_height": 0, "top_block_hash": hex::encode([0u8; 32]) }),
    )
    .expect("height and target are enough");
    assert_eq!(health.height, 77);
    assert_eq!(health.connections, 0);

    let err = health_from_get_info(&json!({ "height": 500, "synchronized": true }))
        .expect_err("an absent target_height is contract drift, not an omission");
    assert_eq!(err, GetInfoFault::TargetHeightMissing);
}

/// A non-numeric `target_height` is refused for the same reason — the
/// `and_then(as_u64)` arm must not fall through to the sentinel either.
#[test]
fn a_non_numeric_target_height_is_refused_rather_than_defaulted() {
    let err = health_from_get_info(&json!({ "height": 500, "target_height": "soon" }))
        .expect_err("a string target_height does not decode");
    assert_eq!(err, GetInfoFault::TargetHeightMissing);
}

/// Connection counts are summed with `saturating_add`, so a daemon reporting
/// absurd counts cannot wrap the sum to a peerless reading.
#[test]
fn the_connection_sum_saturates_rather_than_wrapping() {
    let health = health_from_get_info(&json!({
        "height": 1,
        // Mandatory since the sentinel may not be manufactured by the
        // decoder; this test's subject is the connection sum, not the gate.
        "target_height": 0,
        "outgoing_connections_count": u64::MAX,
        "incoming_connections_count": 4,
    }))
    .expect("decodes");
    assert_eq!(health.connections, u64::MAX);
}

/// The decode and the constructor compose: a synced reply yields facts at the
/// reply's count, an unsynced one yields none.
#[test]
fn the_decode_and_the_constructor_compose() {
    let reply = info(500, 0);
    let synced = SyncedChainFacts::from_health(
        health_from_get_info(&reply).expect("ok"),
        top_hash_from_get_info(&reply).expect("ok"),
    )
    .expect("synced");
    assert_eq!(synced.tip(), BlockHeight::from_raw(499));

    assert!(
        SyncedChainFacts::from_health(
            health_from_get_info(&info(500, 900)).expect("ok"),
            any_hash()
        )
        .is_none(),
        "a climbing daemon yields no facts to act on",
    );
}

/// **The hole the height comparison alone leaves open.** A freshly started
/// daemon with no peers reports `target_height == 0` — the sentinel that
/// *means* synchronized — while its own `synchronized` flag says otherwise
/// and its height is genesis-adjacent. That is precisely the `WSS-25` state:
/// a rebuilt database, before the node has anyone to catch up from.
///
/// Deleting `synchronized` from the constructor turns this red. It is the
/// edit `50-testing` asks you to be able to name.
#[test]
fn a_peerless_fresh_daemon_is_not_synchronized_despite_the_zero_target() {
    assert!(
        SyncedChainFacts::new(ChainCount::from_raw(5), 0, false, any_hash()).is_none(),
        "target 0 is the daemon's sentinel for synced, but the daemon itself \
         says it is not — the flag is not decoration on the heights",
    );
    assert!(
        health_from_get_info(&json!({ "height": 5, "target_height": 0 }))
            .map(|h| SyncedChainFacts::from_health(h, any_hash()))
            .expect("decodes")
            .is_none(),
        "an absent `synchronized` reads as false — the direction that refuses",
    );
}

/// Both halves are required, so the flag alone is not enough either: a daemon
/// claiming synchronized while its own height sits below its target is
/// contradicting itself, and the answer is still no.
#[test]
fn the_flag_alone_does_not_override_the_heights() {
    assert!(
        SyncedChainFacts::new(ChainCount::from_raw(1_000), 1_000_000, true, any_hash()).is_none()
    );
}

// ── CoherentChainView: the reconciliation the acting lanes rest on ──────

/// A view at `tip`, both reads agreeing.
fn agreeing_view(tip: u64) -> CoherentChainView {
    let synced =
        SyncedChainFacts::new(ChainCount::from_raw(tip + 1), 0, true, any_hash()).expect("synced");
    CoherentChainView::reconcile(
        &synced.bracket(synced.top_hash()).expect("bracketed"),
        ChainCount::from_raw(tip + 1),
    )
}

/// **The sticky-flag hazard.** `synchronized` never returns to false, so a
/// rollback between the sync read and the record read leaves a witness above
/// the record. The clock must believe the lower read.
///
/// The edit that turns this red is `at()` returning `witness_tip`. It bites
/// against the clock being set from a stale-high witness; it does **not**
/// cover a daemon that lies about being synchronized.
#[test]
fn the_clock_believes_the_lower_of_two_disagreeing_reads() {
    let stale_high =
        SyncedChainFacts::new(ChainCount::from_raw(20_001), 0, true, any_hash()).expect("synced");
    let rolled_back = CoherentChainView::reconcile(
        &stale_high
            .bracket(stale_high.top_hash())
            .expect("bracketed"),
        ChainCount::from_raw(10_001),
    );
    assert_eq!(rolled_back.at(), BlockHeight::from_raw(10_000));

    // The ordinary direction — chain advanced between the reads — takes the
    // same rule and equally must not admit the newer height.
    let witness =
        SyncedChainFacts::new(ChainCount::from_raw(10_001), 0, true, any_hash()).expect("synced");
    let advanced = CoherentChainView::reconcile(
        &witness.bracket(witness.top_hash()).expect("bracketed"),
        ChainCount::from_raw(20_001),
    );
    assert_eq!(advanced.at(), BlockHeight::from_raw(10_000));
}

/// **The signal `at()` alone would have destroyed.** Clocking conservatively
/// is right for a consumer that merely counts time; a consumer that acts on
/// the record's *contents* must know the two disagreed in the rollback
/// direction, and a stored minimum cannot tell it.
///
/// The edit that turns this red is collapsing the view to one height on
/// construction — the shape this type had before the acting lanes needed it.
#[test]
fn a_record_below_its_witness_is_reported_as_rolled_back() {
    let stale_high =
        SyncedChainFacts::new(ChainCount::from_raw(20_001), 0, true, any_hash()).expect("synced");
    assert!(
        CoherentChainView::reconcile(
            &stale_high
                .bracket(stale_high.top_hash())
                .expect("bracketed"),
            ChainCount::from_raw(10_001)
        )
        .rolled_back(),
        "a record below the witness read before it is the rollback signature"
    );

    // Equal, and the ordinary advance, are both NOT rollbacks — otherwise
    // every refresh on a live chain would read as one.
    assert!(!agreeing_view(10_000).rolled_back());
    let witness =
        SyncedChainFacts::new(ChainCount::from_raw(10_001), 0, true, any_hash()).expect("synced");
    assert!(!CoherentChainView::reconcile(
        &witness.bracket(witness.top_hash()).expect("bracketed"),
        ChainCount::from_raw(20_001)
    )
    .rolled_back());
}

/// The failure classifier draws the contract-fault/transport line once, so
/// every consumer inherits the same reading.
#[test]
fn a_failed_facts_read_is_classified_by_its_cause() {
    assert_eq!(
        TimelineBreak::from_facts_error(&RpcError::InvalidNode("bad shape".into())),
        TimelineBreak::FactsUnreadable,
    );
    assert_eq!(
        TimelineBreak::from_facts_error(&RpcError::InternalError("no route".into())),
        TimelineBreak::DaemonUnreachable,
    );
}

// ── Chain identity: the anchor and its decode ───────────────────────────

/// `top_block_hash` is mandatory for the same reason `target_height` is:
/// there is no honest default for an identity. A made-up hash would let the
/// ledger carry observations across a reorg it could not see.
#[test]
fn a_reply_without_a_top_hash_is_refused_rather_than_defaulted() {
    for (bad, fault) in [
        (
            json!({ "height": 5, "target_height": 0 }),
            GetInfoFault::TopBlockHashMissing,
        ),
        (
            json!({ "height": 5, "target_height": 0, "top_block_hash": 7 }),
            GetInfoFault::TopBlockHashMissing,
        ),
        (
            json!({ "height": 5, "target_height": 0, "top_block_hash": "not hex" }),
            GetInfoFault::TopBlockHashNotHex,
        ),
        (
            json!({ "height": 5, "target_height": 0, "top_block_hash": "abcd" }),
            GetInfoFault::TopBlockHashWrongLength,
        ),
    ] {
        assert_eq!(
            top_hash_from_get_info(&bad).expect_err("must refuse"),
            fault,
            "each shape names its own fault: {bad}"
        );
    }
    assert_eq!(
        top_hash_from_get_info(&info(5, 0)).expect("well-formed"),
        any_hash()
    );
}

/// **The anchor is at the observed height, and only a view that has one can
/// be observed.** `anchored()` is the sole way to an `AnchoredView`; a
/// rolled-back view has no anchor and is refused with `ChainRolledBack`, so
/// the ledger cannot be handed evidence it could never continuity-check.
///
/// The edit that turns this red is `anchored()` succeeding on a rolled-back
/// view, or anchoring at the record's height instead of the witness's.
#[test]
fn a_view_anchors_at_its_observed_height_unless_rolled_back() {
    let witness =
        SyncedChainFacts::new(ChainCount::from_raw(10_001), 0, true, any_hash()).expect("synced");
    let bracketed = witness.bracket(witness.top_hash()).expect("bracketed");
    let agreeing = CoherentChainView::reconcile(&bracketed, ChainCount::from_raw(10_001))
        .anchored()
        .expect("agreeing reads are anchored");
    assert_eq!(
        agreeing.anchor(),
        ChainAnchor {
            height: BlockHeight::from_raw(10_000),
            hash: witness.top_hash(),
        }
    );
    let advanced = CoherentChainView::reconcile(&bracketed, ChainCount::from_raw(20_001))
        .anchored()
        .expect("advance is anchored at the witness");
    assert_eq!(
        advanced.anchor().height,
        advanced.at(),
        "the anchor is at the observed height, not the record's"
    );

    let stale_high =
        SyncedChainFacts::new(ChainCount::from_raw(20_001), 0, true, any_hash()).expect("synced");
    let rolled_back = CoherentChainView::reconcile(
        &stale_high
            .bracket(stale_high.top_hash())
            .expect("bracketed"),
        ChainCount::from_raw(10_001),
    );
    assert_eq!(
        rolled_back
            .anchored()
            .expect_err("a rolled-back view has no anchor"),
        TimelineBreak::ChainRolledBack
    );
}

/// **The error contract, as a type.** Every `get_info` contract fault is
/// `InvalidNode` — the daemon answered, and its answer is not the shape this
/// wallet was built against — and so classifies as `FactsUnreadable`, never
/// as the daemon being unreachable. A caller reading a fault as a transport
/// failure would send an operator to the network for a version mismatch.
///
/// Enumerated over every member so a fault added later without a mapping
/// is a compile error here, not a silent transport misclassification.
#[test]
fn every_contract_fault_is_a_node_fault_and_never_a_transport_failure() {
    for fault in [
        GetInfoFault::HeightMissing,
        GetInfoFault::TargetHeightMissing,
        GetInfoFault::TopBlockHashMissing,
        GetInfoFault::TopBlockHashNotHex,
        GetInfoFault::TopBlockHashWrongLength,
    ] {
        let err = RpcError::from(fault);
        assert!(
            matches!(err, RpcError::InvalidNode(ref m) if m.starts_with("get_info ")),
            "{fault:?} converts to InvalidNode naming the reply: {err:?}"
        );
        assert_eq!(
            TimelineBreak::from_facts_error(&err),
            TimelineBreak::FactsUnreadable,
            "{fault:?} is a contract fault, not a connectivity problem"
        );
    }
    // The member list above is the whole enum: a new member fails here.
    let _exhaustive = |f: GetInfoFault| match f {
        GetInfoFault::HeightMissing
        | GetInfoFault::TargetHeightMissing
        | GetInfoFault::TopBlockHashMissing
        | GetInfoFault::TopBlockHashNotHex
        | GetInfoFault::TopBlockHashWrongLength => (),
    };
}
