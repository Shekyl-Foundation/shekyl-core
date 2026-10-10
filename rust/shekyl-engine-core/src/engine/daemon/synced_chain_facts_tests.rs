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

/// A `get_info` reply built by [`GetInfoDocument`], not a private schema.
/// `target_height` follows the info surface's convention: `0` means the
/// daemon considers itself synchronized.
fn info(height: u64, target_height: Option<u64>) -> GetInfoResponse {
    document(height, target_height).to_reply()
}

fn document(height: u64, target_height: Option<u64>) -> GetInfoDocument {
    GetInfoDocument {
        chain_count: ChainCount::from_raw(height),
        target_height,
        synchronized: true,
        top_hash: any_hash(),
        outgoing_connections: 5,
        incoming_connections: 3,
    }
}

/// The reply as JSON with `over`'s members laid over it. A member given as
/// JSON `null` is removed.
fn info_json(over: &Value) -> Value {
    let mut doc = document(500, None).to_value();
    let members = doc.as_object_mut().expect("a reply is an object");
    for (key, value) in over.as_object().expect("an overlay is an object") {
        if value.is_null() {
            members.remove(key);
        } else {
            members.insert(key.clone(), value.clone());
        }
    }
    doc
}

/// A transport that answers `get_info` with one canned result, so the
/// decode is exercised where production does it: inside
/// [`fetch_synced_chain_facts`].
#[derive(Clone)]
struct OneReply(Value);

impl Rpc for OneReply {
    fn post(
        &self,
        _route: &str,
        _body: Vec<u8>,
    ) -> impl Send + std::future::Future<Output = Result<Vec<u8>, RpcError>> {
        let bytes = json!({ "jsonrpc": "2.0", "id": 0, "result": self.0 })
            .to_string()
            .into_bytes();
        async move { Ok(bytes) }
    }
}

/// The daemon's flag is the whole predicate: set, there are facts at any
/// height; clear, there are none.
#[test]
fn the_flag_is_the_predicate_at_any_height() {
    for height in [0, 1, 20_000, u64::MAX] {
        assert!(
            SyncedChainFacts::new(ChainCount::from_raw(height), true, any_hash()).is_some(),
            "synchronized at height {height}",
        );
        assert!(
            SyncedChainFacts::new(ChainCount::from_raw(height), false, any_hash()).is_none(),
            "not synchronized at height {height}",
        );
    }
}

/// **The target decides nothing.** A synchronized daemon whose target sits
/// above its height — far above, one above, or absurdly above — yields
/// facts, and one that is not synchronized yields none wherever its target
/// is. The target is the tallest chain a peer has claimed, so a wallet that
/// compared against it could be stopped by one peer's handshake.
///
/// Until `CORE_RPC_VERSION` 3.46 the first half was refused (`WSS-25`'s
/// state was recognised partly by the heights). The state itself is still
/// refused: a resyncing daemon reports `synchronized: false`, which is the
/// second half.
///
/// The edit that turns this red is the health projection carrying the
/// target again and the constructor comparing against it.
#[test]
fn a_peer_claimed_target_neither_withholds_nor_grants_the_facts() {
    for target in [
        None,
        Some(0),
        Some(499),
        Some(500),
        Some(501),
        Some(1_000_000),
        Some(u64::MAX),
    ] {
        let synchronized = info(500, target);
        assert!(
            SyncedChainFacts::from_health(health_from_get_info(&synchronized), any_hash())
                .is_some(),
            "synchronized, target {target:?}",
        );
        let climbing = GetInfoDocument {
            synchronized: false,
            ..document(500, target)
        }
        .to_reply();
        assert!(
            SyncedChainFacts::from_health(health_from_get_info(&climbing), any_hash()).is_none(),
            "not synchronized, target {target:?}",
        );
    }
}

/// The count/height distinction, pinned. `get_info.height` is the block
/// **count** (the daemon reports the top block's height plus one), so the newest existing block sits one below it. A consumer doing
/// epoch arithmetic on the count instead of the tip lands one block early at
/// every boundary — invisible to any test that never crosses one.
#[test]
fn the_tip_is_one_below_the_count_and_an_empty_chain_reads_zero() {
    let facts =
        SyncedChainFacts::new(ChainCount::from_raw(20_001), true, any_hash()).expect("synced");
    assert_eq!(facts.tip(), BlockHeight::from_raw(20_000));

    let empty = SyncedChainFacts::new(ChainCount::from_raw(0), true, any_hash())
        .expect("synced, empty chain");
    assert_eq!(
        empty.tip(),
        BlockHeight::from_raw(0),
        "an empty chain has no tip; elapsed-block arithmetic reads it as zero",
    );
}

/// **The mandatory members, as one property.** A reply missing `height`,
/// `target_height`, `synchronized` or `top_block_hash`, or carrying one of
/// the wrong shape, does not become facts — it is a contract fault, and it
/// is classified as one.
///
/// Each of these had its own refusal in the hand-written decoder this
/// replaced, and its own reason: no `height` would mint facts for a chain
/// of length zero; a missing `synchronized` has no reading that is not a
/// guess; there is no honest default for an identity. `target_height` is
/// nullable and still required: `null` is "no target", a missing member is
/// not this build's reply. The shared type
/// decodes strictly, so the property now holds for every member, and it is
/// tested through the read production makes.
///
/// The edit that turns this red is a `#[serde(default)]` on any of them.
#[tokio::test]
async fn a_reply_missing_or_misshaping_a_mandatory_member_yields_no_facts() {
    for (over, what) in [
        (json!({ "height": null }), "no height"),
        (json!({ "height": "500" }), "a height that is not a number"),
        (json!({ "target_height": null }), "no target_height"),
        (
            json!({ "target_height": "soon" }),
            "a non-numeric target_height",
        ),
        (json!({ "synchronized": null }), "no synchronized"),
        (json!({ "top_block_hash": null }), "no top_block_hash"),
        (
            json!({ "top_block_hash": 7 }),
            "a top_block_hash that is not a string",
        ),
        (
            json!({ "top_block_hash": "not hex" }),
            "a top_block_hash that is not hex",
        ),
        (
            json!({ "top_block_hash": "abcd" }),
            "a top_block_hash that is not 32 bytes",
        ),
    ] {
        let err = fetch_synced_chain_facts(&OneReply(info_json(&over)))
            .await
            .expect_err(what);
        assert!(
            matches!(err, RpcError::InvalidNode(_)),
            "{what} is a contract fault, not a transport one: {err:?}"
        );
        assert_eq!(
            TimelineBreak::from_facts_error(&err),
            TimelineBreak::FactsUnreadable,
            "{what} must send an operator to the daemon's version, not to the network"
        );
    }
}

/// The control for the test above: the same document with nothing removed
/// is facts; with a target above its height it is still facts, because the
/// target decides nothing; and with the flag clear it is "syncing", not an
/// error.
#[tokio::test]
async fn a_whole_reply_yields_facts_and_a_climbing_one_yields_none() {
    let synced = fetch_synced_chain_facts(&OneReply(info_json(&json!({}))))
        .await
        .expect("a whole reply decodes")
        .expect("and is synchronized");
    assert_eq!(synced.tip(), BlockHeight::from_raw(499));
    assert_eq!(synced.top_hash(), any_hash());

    assert!(
        fetch_synced_chain_facts(&OneReply(info_json(&json!({ "target_height": 900 }))))
            .await
            .expect("a reply with a target decodes")
            .is_some(),
        "a synchronized daemon with a target above its height is synchronized"
    );
    assert!(fetch_synced_chain_facts(&OneReply(info_json(
        &json!({ "target_height": 900, "synchronized": false })
    )))
    .await
    .expect("a climbing reply decodes")
    .is_none());
}

/// A member this build does not know is refused too: the reply is one type,
/// defined once, and a daemon that sends more than it is at another version.
#[tokio::test]
async fn a_reply_with_an_unknown_member_yields_no_facts() {
    let err = fetch_synced_chain_facts(&OneReply(info_json(&json!({ "emission_era": "Tail" }))))
        .await
        .expect_err("an unknown member is not the contract");
    assert!(matches!(err, RpcError::InvalidNode(_)), "{err:?}");
}

/// The connection counts are a Status field, which a daemon may withhold.
/// Withheld reads as zero — "none known" — and nothing else about the reply
/// changes.
#[test]
fn withheld_connection_counts_read_as_none_known() {
    let mut reply = info(77, None);
    assert_eq!(health_from_get_info(&reply).connections, 8);
    reply.node = shekyl_rpc_types::Hidden::Withheld;
    let health = health_from_get_info(&reply);
    assert_eq!(health.connections, 0);
    assert_eq!(health.height, 77);
}

/// Connection counts are summed with `saturating_add`, so a daemon reporting
/// absurd counts cannot wrap the sum to a peerless reading.
#[test]
fn the_connection_sum_saturates_rather_than_wrapping() {
    let reply = GetInfoDocument {
        outgoing_connections: u64::MAX,
        incoming_connections: 4,
        ..document(1, None)
    }
    .to_reply();
    assert_eq!(health_from_get_info(&reply).connections, u64::MAX);
}

/// The decode and the constructor compose: a synced reply yields facts at the
/// reply's count, an unsynced one yields none.
#[test]
fn the_decode_and_the_constructor_compose() {
    let reply = info(500, None);
    let synced =
        SyncedChainFacts::from_health(health_from_get_info(&reply), top_hash_from_get_info(&reply))
            .expect("synced");
    assert_eq!(synced.tip(), BlockHeight::from_raw(499));

    let climbing = GetInfoDocument {
        synchronized: false,
        ..document(500, Some(900))
    }
    .to_reply();
    assert!(
        SyncedChainFacts::from_health(health_from_get_info(&climbing), any_hash()).is_none(),
        "a climbing daemon yields no facts to act on",
    );
}

/// `WSS-25`'s state: a freshly started daemon with no peers, a rebuilt
/// database, genesis-adjacent, and no target because it has nobody to learn
/// one from. Its `synchronized` flag says it has not caught up, and that is
/// what refuses it.
///
/// Deleting `synchronized` from the constructor turns this red. It is the
/// edit `50-testing` asks you to be able to name.
#[test]
fn a_peerless_fresh_daemon_is_not_synchronized() {
    assert!(SyncedChainFacts::new(ChainCount::from_raw(5), false, any_hash()).is_none());
    let peerless = GetInfoDocument {
        synchronized: false,
        outgoing_connections: 0,
        incoming_connections: 0,
        ..document(5, None)
    }
    .to_reply();
    assert!(
        SyncedChainFacts::from_health(health_from_get_info(&peerless), any_hash()).is_none(),
        "the reply's own flag is carried through the decode",
    );
}

// ── CoherentChainView: the reconciliation the acting lanes rest on ──────

/// A view at `tip`, both reads agreeing.
fn agreeing_view(tip: u64) -> CoherentChainView {
    let synced =
        SyncedChainFacts::new(ChainCount::from_raw(tip + 1), true, any_hash()).expect("synced");
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
        SyncedChainFacts::new(ChainCount::from_raw(20_001), true, any_hash()).expect("synced");
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
        SyncedChainFacts::new(ChainCount::from_raw(10_001), true, any_hash()).expect("synced");
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
        SyncedChainFacts::new(ChainCount::from_raw(20_001), true, any_hash()).expect("synced");
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
        SyncedChainFacts::new(ChainCount::from_raw(10_001), true, any_hash()).expect("synced");
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
        TimelineBreak::from_facts_error(&RpcError::ConnectionError("refused".into())),
        TimelineBreak::DaemonUnreachable,
    );
    // A request this wallet could not form repeats on every retry: the
    // contract class, not the transport one.
    assert_eq!(
        TimelineBreak::from_facts_error(&RpcError::InternalError("encode request".into())),
        TimelineBreak::FactsUnreadable,
    );
    let wrong_network = shekyl_rpc_types::IdentityMismatch::Network {
        ours: shekyl_rpc_types::DaemonNetwork::Mainnet,
        theirs: shekyl_rpc_types::DaemonNetwork::Testnet,
    };
    assert_eq!(
        TimelineBreak::from_facts_error(&RpcError::IdentityMismatch(wrong_network)),
        TimelineBreak::IdentityRefused(wrong_network),
        "a wrong daemon is its own remedy, not an outage"
    );
}

// ── Chain identity: the anchor and its decode ───────────────────────────

/// `top_block_hash` is the chain's identity, carried as the reply's 32
/// bytes. (A reply without one, or with one that is not 32 hex bytes, is
/// refused where the other mandatory members are:
/// `a_reply_missing_or_misshaping_a_mandatory_member_yields_no_facts`.)
#[test]
fn the_top_hash_is_the_replys() {
    assert_eq!(top_hash_from_get_info(&info(5, None)), any_hash());
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
        SyncedChainFacts::new(ChainCount::from_raw(10_001), true, any_hash()).expect("synced");
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
        SyncedChainFacts::new(ChainCount::from_raw(20_001), true, any_hash()).expect("synced");
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
