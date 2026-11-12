// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`SyncedChainFacts`] — the constructor's refusal, the unit it carries, and
//! the `daemon_status` decode it shares with the watchdog's health snapshot.

use super::*;
use serde_json::json;

/// A fixed identity for tests whose subject is the predicate, not the chain.
fn any_hash() -> BlockHash {
    BlockHash::from_bytes([0xAB; 32])
}

/// A `daemon_status` reply built by [`DaemonStatusDocument`], not a private
/// schema. `count` and `target_height` are block counts; the document writes
/// their tips.
fn info(count: u64, target_height: Option<u64>) -> DaemonStatus {
    document(count, target_height).to_reply()
}

fn document(count: u64, target_height: Option<u64>) -> DaemonStatusDocument {
    DaemonStatusDocument {
        chain_count: ChainCount::from_raw(count),
        target_height,
        synchronized: true,
        top_hash: any_hash(),
        peered: true,
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

/// A transport that answers `daemon_status` with one canned result, so the
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
            SyncedChainFacts::from_health(health_from_daemon_status(&synchronized), any_hash())
                .is_some(),
            "synchronized, target {target:?}",
        );
        let climbing = DaemonStatusDocument {
            synchronized: false,
            ..document(500, target)
        }
        .to_reply();
        assert!(
            SyncedChainFacts::from_health(health_from_daemon_status(&climbing), any_hash())
                .is_none(),
            "not synchronized, target {target:?}",
        );
    }
}

/// The count/height distinction, pinned. The facts carry the block
/// **count**, so the newest existing block sits one below it. A consumer
/// doing epoch arithmetic on the count instead of the tip lands one block
/// early at every boundary — invisible to any test that never crosses one.
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
/// `target_height`, `synchronized`, `peered` or `hash`, or carrying one of
/// the wrong shape, does not become facts — it is a contract fault, and it
/// is classified as one.
///
/// Each has its own reason: no `height` would mint facts for a chain of
/// unknown length; a missing `synchronized` has no reading that is not a
/// guess; there is no honest default for an identity. `target_height` and
/// `peered` are nullable and still required: `null` is an answer, a missing
/// member is not this build's reply. The shared type decodes strictly, so
/// the property holds for every member, and it is tested through the read
/// production makes.
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
        (json!({ "peered": null }), "no peered"),
        (json!({ "hash": null }), "no hash"),
        (json!({ "hash": 7 }), "a hash that is not a string"),
        (json!({ "hash": "not hex" }), "a hash that is not hex"),
        (json!({ "hash": "abcd" }), "a hash that is not 32 bytes"),
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

/// **Whether the daemon has peers is Health's word, and Status cannot
/// change it** (RK-D14). The reply's Status counts are zero here, and then
/// the whole Status part is withheld, as a daemon sends it to a caller
/// without the `status` grant: `peered` reads the same through both. A
/// projection that summed those counts would read a withheld part as zero
/// and call the daemon peerless.
///
/// The edit that turns this red is the projection reading Status again.
#[test]
fn peered_is_healths_word_whatever_status_says() {
    for peered in [true, false] {
        let reply = DaemonStatusDocument {
            peered,
            ..document(77, None)
        }
        .to_reply();
        assert_eq!(
            (
                reply.peer_outbound_count.shown(),
                reply.peer_inbound_count.shown()
            ),
            (
                Some(shekyl_rpc_types::nullable::Nullable(Some(
                    shekyl_rpc_types::kinds::Count(0)
                ))),
                Some(shekyl_rpc_types::nullable::Nullable(Some(
                    shekyl_rpc_types::kinds::Count(0)
                )))
            ),
            "the fixture's Status counts are zero"
        );
        assert_eq!(
            health_from_daemon_status(&reply).p2p.has_peers(),
            Some(peered)
        );

        let reply = DaemonStatusDocument {
            peered,
            ..document(77, None)
        }
        .to_reply_status_withheld();
        let health = health_from_daemon_status(&reply);
        assert_eq!(health.p2p.has_peers(), Some(peered), "Status withheld");
        assert_eq!(health.height, 77);
    }
}

/// **The wire carries the tip; the health projection carries the count.**
/// `daemon_status.height` is the tip's height (IG-Q45), and the count — what
/// the facts and the watchdog read — is one more, computed at the decode.
///
/// The edit that turns this red is the projection carrying `height` as the
/// count unconverted: every consumer would then read one block low.
#[test]
fn the_wire_height_is_the_tip_and_the_count_is_one_more() {
    let reply: DaemonStatus =
        serde_json::from_value(info_json(&json!({ "height": 41 }))).expect("a whole reply decodes");
    assert_eq!(health_from_daemon_status(&reply).height, 42);
}

/// An offline daemon is a state of its own, not a daemon with no peers:
/// `offline` with `peered: null` reads as offline.
#[test]
fn an_offline_daemon_is_offline_not_peerless() {
    let mut doc = document(500, None).to_value();
    doc["offline"] = json!(true);
    doc["peered"] = Value::Null;
    doc["peer_outbound_count"] = Value::Null;
    doc["peer_inbound_count"] = Value::Null;
    let reply: DaemonStatus = serde_json::from_value(doc).expect("an offline reply decodes");
    let health = health_from_daemon_status(&reply);
    assert!(health.p2p.is_offline());
    assert_eq!(health.p2p.has_peers(), None);
}

/// The decode and the constructor compose: a synced reply yields facts at the
/// reply's count, an unsynced one yields none.
#[test]
fn the_decode_and_the_constructor_compose() {
    let reply = info(500, None);
    let synced = SyncedChainFacts::from_health(
        health_from_daemon_status(&reply),
        top_hash_from_daemon_status(&reply),
    )
    .expect("synced");
    assert_eq!(synced.tip(), BlockHeight::from_raw(499));

    let climbing = DaemonStatusDocument {
        synchronized: false,
        ..document(500, Some(900))
    }
    .to_reply();
    assert!(
        SyncedChainFacts::from_health(health_from_daemon_status(&climbing), any_hash()).is_none(),
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
    let peerless = DaemonStatusDocument {
        synchronized: false,
        peered: false,
        ..document(5, None)
    }
    .to_reply();
    assert!(
        SyncedChainFacts::from_health(health_from_daemon_status(&peerless), any_hash()).is_none(),
        "the reply's own flag is carried through the decode",
    );
}

// ── CoherentChainView: the reconciliation the acting lanes rest on ──────

/// A synchronized witness at `tip`.
fn witness_at(tip: u64) -> SyncedChainFacts {
    SyncedChainFacts::new(ChainCount::from_raw(tip + 1), true, any_hash()).expect("synced")
}

/// The block a record was gathered at: `tip`, under its own hash.
fn record_at(tip: u64) -> ChainAnchor {
    ChainAnchor {
        height: BlockHeight::from_raw(tip),
        hash: BlockHash::from_bytes([0xCD; 32]),
    }
}

/// A view at `tip`, both reads agreeing.
fn agreeing_view(tip: u64) -> CoherentChainView {
    CoherentChainView::reconcile(&witness_at(tip), record_at(tip))
}

/// **The clock is the record's own height.** The record names the block it
/// was gathered at, so an observation drawn from it is stamped there. When
/// the chain advanced between the reads, stamping at the earlier witness
/// would date the observation before it was seen — the release-early
/// direction. When the chain rolled back, the record's height is the lower
/// one, and the view is refused for acting anyway.
///
/// The edit that turns this red is `at()` returning the witness's tip.
#[test]
fn the_clock_is_the_records_own_height() {
    let advanced = CoherentChainView::reconcile(&witness_at(10_000), record_at(20_000));
    assert_eq!(advanced.at(), BlockHeight::from_raw(20_000));

    let rolled_back = CoherentChainView::reconcile(&witness_at(20_000), record_at(10_000));
    assert_eq!(rolled_back.at(), BlockHeight::from_raw(10_000));
}

/// **A record below its witness is a rollback.** A consumer that acts on
/// the record's *contents* must know the two disagreed in that direction.
///
/// The edit that turns this red is `rolled_back()` comparing anything but
/// the record's height against the witness's.
#[test]
fn a_record_below_its_witness_is_reported_as_rolled_back() {
    assert!(
        CoherentChainView::reconcile(&witness_at(20_000), record_at(10_000)).rolled_back(),
        "a record below the witness read before it is the rollback signature"
    );

    // Equal, and the ordinary advance, are both NOT rollbacks — otherwise
    // every refresh on a live chain would read as one.
    assert!(!agreeing_view(10_000).rolled_back());
    assert!(!CoherentChainView::reconcile(&witness_at(10_000), record_at(20_000)).rolled_back());
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
        ours: shekyl_rpc_types::Network::Mainnet,
        theirs: shekyl_rpc_types::Network::Testnet,
    };
    assert_eq!(
        TimelineBreak::from_facts_error(&RpcError::IdentityMismatch(wrong_network)),
        TimelineBreak::IdentityRefused(wrong_network),
        "a wrong daemon is its own remedy, not an outage"
    );
}

// ── Chain identity: the anchor and its decode ───────────────────────────

/// `hash` is the chain's identity, carried as the reply's 32 bytes. (A
/// reply without one, or with one that is not 32 hex bytes, is refused
/// where the other mandatory members are:
/// `a_reply_missing_or_misshaping_a_mandatory_member_yields_no_facts`.)
#[test]
fn the_top_hash_is_the_replys() {
    assert_eq!(top_hash_from_daemon_status(&info(5, None)), any_hash());
}

/// **The anchor is the record's own block, and only a view that has one can
/// be observed.** `anchored()` is the sole way to an `AnchoredView`; a
/// rolled-back view has no anchor and is refused with `ChainRolledBack`, so
/// the ledger cannot be handed evidence it could never continuity-check.
///
/// The edit that turns this red is `anchored()` succeeding on a rolled-back
/// view, or anchoring at the witness's block instead of the record's.
#[test]
fn a_view_anchors_at_the_records_block_unless_rolled_back() {
    let agreeing = agreeing_view(10_000)
        .anchored()
        .expect("agreeing reads are anchored");
    assert_eq!(agreeing.anchor(), record_at(10_000));

    let advanced = CoherentChainView::reconcile(&witness_at(10_000), record_at(20_000))
        .anchored()
        .expect("advance is anchored at the record");
    assert_eq!(advanced.anchor(), record_at(20_000));
    assert_eq!(
        advanced.anchor().height,
        advanced.at(),
        "the anchor is at the observed height"
    );

    let rolled_back = CoherentChainView::reconcile(&witness_at(20_000), record_at(10_000));
    assert_eq!(
        rolled_back
            .anchored()
            .expect_err("a rolled-back view has no anchor"),
        TimelineBreak::ChainRolledBack
    );
}
