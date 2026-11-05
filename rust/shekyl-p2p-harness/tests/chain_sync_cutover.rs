// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The cutover's loopback scenarios (CS-5): phase timing, a node that
//! posts no template while it is behind, stall recovery, a retired chain
//! request, and a missing-transaction serve.
//!
//! Its own integration binary. It includes `chain_sync/support.rs`, as
//! `chain_sync_loopback` and `chain_sync_claim_relay` do. The older
//! scenarios stay in `chain_sync_loopback`.

use std::sync::{Arc, Mutex};

use shekyl_chain_ingest::follower::{NoJob, Posting};
use shekyl_chain_rules::AtHeight;
use shekyl_chain_sync::SyncState;
use shekyl_levin::{
    notify, NewCompactBlock, PortableMap, RequestCompactMissingTx, NOTIFY_NEW_COMPACT_BLOCK,
    NOTIFY_REQUEST_COMPACT_MISSING_TX,
};
use shekyl_p2p_harness::sync::{Bodies, HeaderChainPeer, Node, ServingPeer, SyncPeer};
use shekyl_transport_layer::CloseKind;
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::Block;

#[path = "chain_sync/support.rs"]
mod support;

use support::{
    claim, claim_of, logs, rng, source, spend, wait_synced, LIMIT, PROFILES, RESPONSES, SEATED,
};

/// **A sync times every phase of each block** (CS-5 §8, the per-block
/// profile). A fresh node syncs the corpus from one honest peer; the one
/// sink the substrate, the entry and the owner share then holds, for every
/// block it fetched: the body request's transit, the header's hash, the
/// entry's answer to the offer, `form_judged`, and the connector's apply.
/// The owner logs this sink once the sync reaches the best chain, which is
/// the line the per-block profile is read from. Red edit: the owner does
/// not time a body response's transit.
///
/// **And records each response and each seated span** (CS-5 §10, the
/// measurement the constants are read from): the sink holds every
/// response's bytes, the header responses' count, bytes and round trip,
/// and the spans the door seated; the owner logs each response and each
/// seated span at debug, which the fleet's per-response reading needs.
/// Red edits, one record at a time: the owner passes no body bytes, times
/// no header response, counts no seated span, or logs neither line.
///
/// The seat wait itself is not red-checkable here: the model offers only
/// what the door last reported room for, and on loopback with 64 seats
/// nothing else takes one, so no span is refused for room. The sink's
/// `seat_waits` is asserted to be consistent with that (every seated span
/// is counted, and a wait is never more than a seated span), not to be
/// non-zero.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sync_times_every_phase_of_each_block() {
    logs();
    let (corpus, steps) = spend();
    let held = source("profile-src", &corpus, &steps).await;
    let (count, _, _) = held.tip().expect("a chain");
    let mut node = Node::start("profile", corpus.rules(), &steps[..1], 2, rng()).await;
    let (peer, _asked) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
    node.connect(Box::new(peer), Some(claim_of(&held)));
    wait_synced(&node, count).await;
    let fetched = count - 1;
    // The entry answers an offer after the connector commits it, and the
    // node reads `Synced` from that commit's tip: the last answers reach
    // the owner just after the state does.
    let answered = node
        .wait(LIMIT, |node| node.metrics.snapshot().entries >= fetched)
        .await;
    let profile = node.metrics.snapshot();
    assert!(
        answered,
        "entry: {} answers for {fetched} offers",
        profile.entries
    );
    eprintln!("{}", profile.to_json().expect("json"));
    assert!(
        profile.transit_blocks >= fetched && profile.transit_ns_total > 0,
        "transit: {} blocks over {} spans for {fetched} fetched",
        profile.transit_blocks,
        profile.transit_spans
    );
    assert!(
        profile.hashes >= fetched,
        "hash: {} for {fetched} headers",
        profile.hashes
    );
    assert!(
        profile.entries >= fetched && profile.entry_ns_total > 0,
        "entry: {} answers for {fetched} offers",
        profile.entries
    );
    assert!(
        profile.blocks_formed >= fetched,
        "form_judged: {} for {fetched} blocks",
        profile.blocks_formed
    );
    assert!(
        profile.applied_blocks >= fetched && profile.apply_ns_total > 0,
        "apply: {} blocks over {} runs for {fetched} blocks",
        profile.applied_blocks,
        profile.applies
    );
    // The responses' bytes: every body response carried its blocks.
    assert!(
        profile.transit_bytes > 0,
        "transit: {} bytes over {} spans",
        profile.transit_bytes,
        profile.transit_spans
    );
    // The header responses: the chain fits one, and it was timed.
    assert!(
        profile.header_responses > 0 && profile.header_bytes > 0 && profile.header_ns_total > 0,
        "headers: {} responses, {} bytes, {} ns",
        profile.header_responses,
        profile.header_bytes,
        profile.header_ns_total
    );
    // The door seated every span the model offered, and no more spans
    // waited for a seat than were seated.
    assert!(
        profile.seated_spans >= profile.transit_spans && profile.seated_spans > 0,
        "seats: {} spans seated for {} fetched",
        profile.seated_spans,
        profile.transit_spans
    );
    assert!(
        profile.seat_waits <= profile.seated_spans,
        "seats: {} waits over {} seated spans",
        profile.seat_waits,
        profile.seated_spans
    );
    // The per-response lines, one per header and body response, each
    // carrying its bytes: the fleet reads the rate floor off these. The
    // lines are read after the snapshot, and a response may land between
    // the two, so a line count is at least the snapshot's.
    let responses: Vec<_> = RESPONSES
        .lock()
        .expect("responses")
        .iter()
        .filter(|(tag, _)| tag == "profile")
        .map(|(_, response)| response.clone())
        .collect();
    let (headers, bodies): (Vec<_>, Vec<_>) = responses
        .iter()
        .partition(|response| response.kind == "headers");
    assert!(
        headers.len() >= usize::try_from(profile.header_responses).expect("small")
            && headers.iter().all(|response| response.bytes > 0),
        "header response lines: {headers:?} for {} responses",
        profile.header_responses
    );
    assert!(
        bodies.len() >= usize::try_from(profile.transit_spans).expect("small")
            && bodies
                .iter()
                .all(|response| response.kind == "bodies" && response.bytes > 0)
            && bodies
                .iter()
                .map(|response| response.items.unwrap_or(0))
                .sum::<u64>()
                >= profile.transit_blocks,
        "body response lines: {bodies:?} for {} spans",
        profile.transit_spans
    );
    // The seated lines, one per span the door admitted.
    let seated: Vec<_> = SEATED
        .lock()
        .expect("seated")
        .iter()
        .filter(|(tag, _)| tag == "profile")
        .map(|(_, seated)| seated.clone())
        .collect();
    assert!(
        seated.len() >= usize::try_from(profile.seated_spans).expect("small")
            && seated.iter().map(|seated| seated.blocks).sum::<u64>() >= fetched
            && seated.iter().filter(|seated| seated.waited).count()
                >= usize::try_from(profile.seat_waits).expect("small"),
        "seated lines: {seated:?} for {} seated spans, {} waits",
        profile.seated_spans,
        profile.seat_waits
    );
    // The line the profile is read from: logged as the sync reached the
    // best chain, carrying the fetched blocks' transit.
    let logged: Vec<serde_json::Value> = PROFILES
        .lock()
        .expect("profiles")
        .iter()
        .filter(|(tag, _)| tag == "profile")
        .map(|(_, json)| serde_json::from_str(json).expect("the profile line is JSON"))
        .collect();
    assert!(
        logged
            .iter()
            .any(|line| line["transit_blocks"].as_u64() >= Some(fetched)),
        "no profile line covering the sync was logged: {logged:?}"
    );
    node.stop().await;
    held.stop().await;
}

/// What a mining node's two watches said, in the order the recorder read
/// them.
#[derive(Clone, Debug)]
enum Heard {
    State(SyncState),
    /// A posted job and the height its block connects at; `None` when the
    /// board had moved on before the recorder read it.
    Posted(Option<u64>),
    Withdrawn(NoJob),
}

/// **A node posts no template while it is behind** (CS-5 §3). The owner
/// is the one writer of the state the node publishes, and the tip
/// follower reads that state: while the node is `Behind` it posts no job,
/// and once it is `Synced` at the corpus's tip it posts one there. The
/// shell's `is_synchronized` reads the same watch
/// (`shekyl_node_is_synchronized`, `Synced` only; its unit test pins each
/// state).
///
/// The handle goes `NoView` at open and `Synced` at the corpus's tip,
/// with `Behind` between. Before `Behind` it may read `Synced` on the
/// tip it opened on: a session that has opened, with no header verified
/// yet, leaves the local chain the best one the node knows, and a claim
/// does not move the state (CS-Q2; `a_claim_never_changes_the_state`).
/// A job on that opening tip is allowed here for that reason.
///
/// Each block the node connects while `Behind` wakes the follower, which
/// must withdraw with `NotSynced(Behind)`. A job built on a tip the node
/// reached mid-sync is the failure: it would hand the miner work on a
/// chain the node knows is not the best.
///
/// Seen red with the follower fed a watch fixed at `Synced`: jobs at
/// every height the sync passed through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_posts_no_template_while_it_is_behind() {
    logs();
    let (corpus, steps) = spend();
    let held = source("posting-src", &corpus, &steps).await;
    let (count, _, _) = held.tip().expect("a chain");
    let keys = {
        let wallet = shekyl_harness_wallet::MinerWallet::from_seed(&[0x5e; 32]);
        let recipient = wallet.recipient();
        shekyl_block_template::MinerKeys {
            spend_public: recipient.spend_public,
            x25519_pk: recipient.x25519_pk,
            ml_kem_ek: recipient.ml_kem_ek.clone(),
        }
    };
    let mut node = Node::start_mining("posting", corpus.rules(), &steps[..1], 2, rng(), keys).await;
    let opened = node.count();
    let heard = Arc::new(Mutex::new(Vec::new()));
    let state_watcher = {
        let heard = Arc::clone(&heard);
        let mut handle = node.state.subscribe();
        heard
            .lock()
            .expect("heard")
            .push(Heard::State(*handle.borrow_and_update()));
        tokio::spawn(async move {
            while handle.changed().await.is_ok() {
                let state = *handle.borrow_and_update();
                heard.lock().expect("heard").push(Heard::State(state));
            }
        })
    };
    let seat = node.miner.as_ref().expect("a mining node");
    let posting_watcher = {
        let heard = Arc::clone(&heard);
        let board = Arc::clone(&seat.board);
        let mut posting = seat.posting.clone();
        tokio::spawn(async move {
            loop {
                let now = posting.borrow_and_update().clone();
                let entry = match now {
                    Posting::Posted(generation) => Heard::Posted(
                        board
                            .posted()
                            .filter(|(at, _)| *at == generation)
                            .map(|(_, job)| job.height.to_raw()),
                    ),
                    Posting::Withdrawn(why) => Heard::Withdrawn(why),
                };
                heard.lock().expect("heard").push(entry);
                if posting.changed().await.is_err() {
                    break;
                }
            }
        })
    };
    let (peer, _asked) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
    node.connect(Box::new(peer), Some(claim_of(&held)));
    wait_synced(&node, count).await;
    let seat = node.miner.as_ref().expect("a mining node");
    let posted = node
        .wait(
            LIMIT,
            |_| matches!(seat.board.posted(), Some((_, job)) if job.height.to_raw() == count),
        )
        .await;
    assert!(posted, "the synced node posted no job on its tip");
    state_watcher.abort();
    posting_watcher.abort();
    let heard = heard.lock().expect("heard").clone();
    eprintln!("heard: {heard:?}");

    let states: Vec<&SyncState> = heard
        .iter()
        .filter_map(|h| match h {
            Heard::State(state) => Some(state),
            _ => None,
        })
        .collect();
    let behind = states
        .iter()
        .position(|state| matches!(state, SyncState::Behind { .. }));
    assert!(
        matches!(states.first(), Some(SyncState::NoView))
            && behind.is_some()
            && matches!(states.last(), Some(SyncState::Synced))
            && states
                .iter()
                .rposition(|state| matches!(state, SyncState::Synced))
                > behind,
        "the handle published {states:?}"
    );
    // No job on a tip the sync passed through: only the tip the node
    // opened on and the corpus's tip.
    let mid_sync: Vec<u64> = heard
        .iter()
        .filter_map(|h| match h {
            Heard::Posted(Some(height)) if *height != opened && *height != count => Some(*height),
            _ => None,
        })
        .collect();
    assert!(
        mid_sync.is_empty(),
        "jobs posted at heights the sync passed through: {mid_sync:?}; heard {heard:?}"
    );
    assert!(
        heard.iter().any(|h| matches!(
            h,
            Heard::Withdrawn(NoJob::NotSynced(SyncState::Behind { .. }))
        )),
        "the follower never withdrew for Behind; heard {heard:?}"
    );
    node.stop().await;
    held.stop().await;
}

/// The stall (CS-5 F5): the one session serving `H*` closes, and the one
/// left claims only the node's own tip. The node is `Behind`, nothing is in
/// flight, and the view says stalled. A session claiming the whole chain
/// arrives, the stall clears, and the node syncs to the tip.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_last_supplier_closing_stalls_and_a_new_claim_recovers() {
    logs();
    let (corpus, steps) = spend();
    let held = source("stall-src", &corpus, &steps).await;
    let (count, _, _) = held.tip().expect("a chain");
    let full = claim_of(&held);
    let mut node = Node::start("stall", corpus.rules(), &steps[..1], 2, rng()).await;
    let (own, work, top) = node.chain.tip().expect("a chain");
    let (level, _) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
    node.connect(Box::new(level), Some(claim(own, work, top)));
    let frames = Arc::new(Mutex::new(Vec::new()));
    let (supplier, seen) =
        ServingPeer::new(Arc::clone(&held.store), Bodies::Hold(Arc::clone(&frames)));
    let id = node.connect(Box::new(supplier), Some(full));
    assert!(
        node.wait(LIMIT, |node| seen.headers() >= 1
            && seen.bodies() >= 1
            && matches!(node.state(), SyncState::Behind { .. }))
            .await,
        "state {:?}, headers {}, bodies {}",
        node.state(),
        seen.headers(),
        seen.bodies()
    );
    assert!(!node.view().stalled, "a span in flight is not a stall");
    node.hub.close(id);
    assert!(
        node.wait(LIMIT, |node| node.view().stalled).await,
        "view {:?}",
        node.view()
    );
    let view = node.view();
    assert!(matches!(view.state, SyncState::Behind { .. }), "{view:?}");
    assert_eq!(view.sessions.len(), 1, "{view:?}");
    assert!(view.sessions[0].header_request.is_none(), "{view:?}");
    assert!(view.sessions[0].body_requests.is_empty(), "{view:?}");

    let (recovery, _) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
    node.connect(Box::new(recovery), Some(full));
    wait_synced(&node, count).await;
    assert!(!node.view().stalled, "view {:?}", node.view());
    node.stop().await;
    held.stop().await;
}

/// The inherited chain request (2006) is retired (CS-5 §6): the attached
/// router does not keep it, so it reaches the C++ handler's ingress, which
/// refuses it as it refuses any command this protocol does not define and
/// closes the session cleanly, with no fault.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retired_chain_request_is_refused_by_the_cpp_ingress() {
    logs();
    let (corpus, steps) = spend();
    let mut node = Node::start("retired", corpus.rules(), &steps[..1], 1, rng()).await;
    let (peer, _) = HeaderChainPeer::new(Vec::new(), 0);
    let id = node.connect(Box::new(peer), None);
    assert!(node.inject(id, notify(2006, b"chain")).await);
    assert!(
        node.wait(LIMIT, |node| node.closed(id).is_some()).await,
        "the session stayed open"
    );
    assert_eq!(node.closed(id), Some(CloseKind::SessionRefused));
    assert_eq!(node.stub.lock().expect("stub").refused, vec![id]);
    node.stop().await;
}

/// The 2008s an asking peer got back from a missing-transaction serve.
#[derive(Default)]
struct CompactAnswers {
    blocks: Vec<NewCompactBlock>,
}

/// Records each 2008 and answers nothing.
struct CompactAsker(Arc<Mutex<CompactAnswers>>);

impl SyncPeer for CompactAsker {
    fn on_message(&mut self, command: u32, payload: &[u8]) -> Vec<Vec<u8>> {
        if command == NOTIFY_NEW_COMPACT_BLOCK {
            self.0
                .lock()
                .expect("answers")
                .blocks
                .push(NewCompactBlock::load(payload).expect("the node's 2008 decodes"));
        }
        Vec::new()
    }
}

/// A peer asking for an announced block's missing transactions (2009) is
/// answered by the owner from the store (CS-5 §6): one 2008 carrying the
/// block, its witness and the transactions asked for. A duplicate index,
/// an index past the block's list and a block the node does not hold each
/// close the asking session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owner_serves_a_missing_tx_request_and_closes_on_its_faults() {
    logs();
    let (corpus, steps) = spend();
    let mut node = Node::start("missing-tx", corpus.rules(), &steps, 1, rng()).await;
    let (hash, listed) = {
        let snap = node.chain.store.begin_read().expect("a snapshot");
        let tip = snap.tip().expect("a tip").recorded.expect("a chain");
        (0..=tip.height.to_raw())
            .find_map(
                |height| match snap.block(BlockHeight::from_raw(height)).expect("a block") {
                    AtHeight::Recorded(body) if !body.block.transaction_hashes.is_empty() => {
                        Some((body.block.hash(), body.block.transaction_hashes.len()))
                    }
                    _ => None,
                },
            )
            .expect("the corpus lists a transaction")
    };
    let ask = |indices: Vec<u64>, block: BlockHash| {
        frame_notify(
            NOTIFY_REQUEST_COMPACT_MISSING_TX,
            &RequestCompactMissingTx {
                block_hash: *block.as_bytes(),
                current_blockchain_height: 1,
                missing_tx_indices: indices,
            },
        )
    };

    let answers = Arc::new(Mutex::new(CompactAnswers::default()));
    let id = node.connect(Box::new(CompactAsker(Arc::clone(&answers))), None);
    assert!(node.inject(id, ask(vec![0], hash)).await);
    assert!(
        node.wait(LIMIT, |_| !answers
            .lock()
            .expect("answers")
            .blocks
            .is_empty())
            .await,
        "no 2008 answered the 2009"
    );
    let compact = answers.lock().expect("answers").blocks[0].clone();
    let block = Block::from_bytes(&compact.b.block).expect("the block parses");
    assert_eq!(block.hash(), hash);
    assert_eq!(compact.b.txs.len(), 1);
    assert!(!compact.b.txs[0].blob.is_empty());
    assert_eq!(
        compact.current_blockchain_height, 1,
        "the request's height is echoed"
    );
    assert_eq!(node.closed(id), None);

    let unknown = BlockHash::from_bytes([0xab; 32]);
    let out_of_range = u64::try_from(listed).expect("small");
    for (indices, block, case) in [
        (vec![0, 0], hash, "a duplicate index"),
        (vec![out_of_range], hash, "an index past the list"),
        (vec![0], unknown, "an unknown block"),
    ] {
        let answers = Arc::new(Mutex::new(CompactAnswers::default()));
        let id = node.connect(Box::new(CompactAsker(Arc::clone(&answers))), None);
        assert!(node.inject(id, ask(indices, block)).await);
        assert!(
            node.wait(LIMIT, |node| node.closed(id).is_some()).await,
            "{case} did not close its session"
        );
        assert!(
            answers.lock().expect("answers").blocks.is_empty(),
            "{case} was answered"
        );
    }
    node.stop().await;
}

/// `message` as one Levin notify of `command`.
fn frame_notify(command: u32, message: &impl PortableMap) -> Vec<u8> {
    notify(command, &message.store().expect("the message encodes"))
}
