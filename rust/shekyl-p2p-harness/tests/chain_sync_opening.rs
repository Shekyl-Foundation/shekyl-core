// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The opening (CS-Q2 step 8, ruled by Rick 2026-11-01): a node on an open
//! network reads `NoView` until its first sessions have answered for their
//! claims, or the first session's header deadline has passed, and only
//! then `Synced`. A claim never grants a state; it can only hold the
//! opening `NoView`, and only until that deadline.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use shekyl_chain_ingest::follower::{NoJob, Posting};
use shekyl_chain_ingest::service::{ArrivalTag, Reply};
use shekyl_chain_sync::SyncState;
use shekyl_p2p_harness::sync::{Bodies, MutePeer, Node, ServingPeer, Step};

#[path = "chain_sync/support.rs"]
mod support;

use support::{claim, claim_of, logs, rng, source, spend, wait_synced, LIMIT};

/// One past the longest header deadline the model arms: the first
/// session's transit, at most a few seconds on a hand clock's connector,
/// plus `HEADERS_RESPONSE_BYTES / SYNC_RATE_FLOOR` (256 s).
const PAST_THE_HEADER_DEADLINE: Duration = Duration::from_secs(600);

/// A recorder of every state the node's handle publishes, by kind,
/// consecutive repeats folded (a `Behind` moves its counts as blocks
/// connect, and that is one stretch of `Behind`).
fn record(node: &Node) -> (Arc<Mutex<Vec<&'static str>>>, tokio::task::JoinHandle<()>) {
    fn kind(state: SyncState) -> &'static str {
        match state {
            SyncState::NoView => "NoView",
            SyncState::Behind { .. } => "Behind",
            SyncState::Following { .. } => "Following",
            SyncState::Synced => "Synced",
        }
    }
    let mut handle = node.state.subscribe();
    let kinds = Arc::new(Mutex::new(vec![kind(*handle.borrow_and_update())]));
    let watcher = {
        let kinds = Arc::clone(&kinds);
        tokio::spawn(async move {
            while handle.changed().await.is_ok() {
                let now = kind(*handle.borrow_and_update());
                let mut kinds = kinds.lock().expect("kinds");
                if kinds.last() != Some(&now) {
                    kinds.push(now);
                }
            }
        })
    };
    (kinds, watcher)
}

/// The recorder's history, with the value on the watch as its end: the
/// recorder may not have stored the last change when it is stopped.
fn history(
    node: &Node,
    kinds: &Arc<Mutex<Vec<&'static str>>>,
    watcher: &tokio::task::JoinHandle<()>,
) -> Vec<&'static str> {
    watcher.abort();
    let mut kinds = kinds.lock().expect("kinds").clone();
    let now = match node.state() {
        SyncState::NoView => "NoView",
        SyncState::Behind { .. } => "Behind",
        SyncState::Following { .. } => "Following",
        SyncState::Synced => "Synced",
    };
    if kinds.last() != Some(&now) {
        kinds.push(now);
    }
    kinds
}

/// **A fresh open node that is behind reads `NoView`, `Behind`, `Synced`,
/// and nothing else.** No `Synced` comes before the first verified
/// headers: the node has not seen the network until its peer has answered
/// for its claim.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_node_behind_reads_no_view_then_behind_then_synced() {
    logs();
    let (corpus, steps) = spend();
    let held = source("opening-behind-src", &corpus, &steps).await;
    let (count, _, _) = held.tip().expect("a chain");
    let mut node = Node::start("opening-behind", corpus.rules(), &steps[..1], 2, rng()).await;
    let (kinds, watcher) = record(&node);
    let (peer, _seen) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
    node.connect(Box::new(peer), Some(claim_of(&held)));
    wait_synced(&node, count).await;
    let kinds = history(&node, &kinds, &watcher);
    assert_eq!(kinds, vec!["NoView", "Behind", "Synced"]);
    node.stop().await;
    held.stop().await;
}

/// **A node at the tip whose peer claims the same chain reads `NoView`,
/// then `Synced`**, and asks that peer for no headers: a claim that does
/// not exceed the local work needs no answer, so the opening resolves on
/// the claim.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_at_the_tip_reads_no_view_then_synced_and_asks_nothing() {
    logs();
    let (corpus, steps) = spend();
    let held = source("opening-tip-src", &corpus, &steps).await;
    let mut node = Node::start("opening-tip", corpus.rules(), &steps, 2, rng()).await;
    let (kinds, watcher) = record(&node);
    let (peer, seen) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
    node.connect(Box::new(peer), Some(claim_of(&held)));
    assert!(
        node.wait(LIMIT, |node| node.state() == SyncState::Synced)
            .await,
        "state {:?}",
        node.state()
    );
    let kinds = history(&node, &kinds, &watcher);
    assert_eq!(kinds, vec!["NoView", "Synced"]);
    assert_eq!(
        seen.headers(),
        0,
        "a header request went to a peer at our tip"
    );
    node.stop().await;
    held.stop().await;
}

/// **A liar holds the opening only until the first session's header
/// deadline.** A peer claims more work than the node holds and never
/// answers. The node reads `NoView` until that deadline, then `Synced`:
/// the claim was never backed, so it moves nothing. A second liar after
/// the opening has resolved moves nothing either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_liar_holds_the_opening_until_the_header_deadline_and_no_longer() {
    logs();
    let (corpus, steps) = spend();
    let mut node = Node::start("opening-liar", corpus.rules(), &steps, 2, rng()).await;
    let (count, work, top) = node.chain.tip().expect("a chain");
    let (liar, _seen) = MutePeer::new();
    node.connect(Box::new(liar), Some(claim(count + 50, work * 4, top)));
    // Long enough for an owner that publishes on the open or the claim to
    // have done so.
    let early = node
        .wait(Duration::from_secs(5), |node| {
            node.state() != SyncState::NoView
        })
        .await;
    assert!(
        !early,
        "the unbacked claim did not hold the opening: {:?}",
        node.state()
    );
    node.advance(PAST_THE_HEADER_DEADLINE);
    assert!(
        node.wait(LIMIT, |node| node.state() == SyncState::Synced)
            .await,
        "the opening did not resolve at the header deadline: {:?}",
        node.state()
    );
    let (second, _seen) = MutePeer::new();
    node.connect(Box::new(second), Some(claim(count + 90, work * 8, top)));
    let moved = node
        .wait(Duration::from_secs(5), |node| {
            node.state() != SyncState::Synced
        })
        .await;
    assert!(
        !moved,
        "a liar after the opening moved the state: {:?}",
        node.state()
    );
    node.stop().await;
}

/// **During the opening the node acts as `NoView`.** A block submitted
/// locally connects, but it is not relayed, the tip follower posts no
/// template, and the published state, which `shekyl_node_is_synchronized`
/// reads (its unit test pins `NoView` to 0), is `NoView`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn during_the_opening_a_local_block_connects_and_is_not_relayed() {
    logs();
    let (corpus, steps) = spend();
    let Some((Step::Block { block, bodies }, before)) = steps.split_last() else {
        panic!("the corpus ends in a block");
    };
    let keys = {
        let wallet = shekyl_harness_wallet::MinerWallet::from_seed(&[0x6a; 32]);
        let recipient = wallet.recipient();
        shekyl_block_template::MinerKeys {
            spend_public: recipient.spend_public,
            x25519_pk: recipient.x25519_pk,
            ml_kem_ek: recipient.ml_kem_ek.clone(),
        }
    };
    let mut node =
        Node::start_mining("opening-quiet", corpus.rules(), before, 2, rng(), keys).await;
    let (count, work, top) = node.chain.tip().expect("a chain");
    let (liar, seen) = MutePeer::new();
    node.connect(Box::new(liar), Some(claim(count + 50, work * 4, top)));
    let mined = node
        .chain
        .service
        .door()
        .offer_local(ArrivalTag(u64::MAX), block.clone(), bodies.clone())
        .await
        .expect("the door takes a local block");
    assert!(
        matches!(mined.reply, Reply::Connected { .. }),
        "the local block did not connect: {:?}",
        mined.reply
    );
    // Long enough for a relay or a posting to have happened.
    let acted = node
        .wait(Duration::from_secs(5), |node| {
            seen.announced() > 0
                || node.state() != SyncState::NoView
                || matches!(
                    *node.miner.as_ref().expect("a mining node").posting.borrow(),
                    Posting::Posted(_)
                )
        })
        .await;
    let posting = node
        .miner
        .as_ref()
        .expect("a mining node")
        .posting
        .borrow()
        .clone();
    assert!(
        !acted,
        "during the opening: relayed {}, state {:?}, posting {posting:?}",
        seen.announced(),
        node.state()
    );
    assert!(
        matches!(
            posting,
            Posting::Withdrawn(NoJob::NotSynced(SyncState::NoView))
        ),
        "{posting:?}"
    );
    node.stop().await;
}
