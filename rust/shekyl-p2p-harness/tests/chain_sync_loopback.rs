// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CS-Q11 end to end (`P2P_3_CHAIN_SYNC_BRIEF.md`, CS-3 §5): the sync
//! model, driven by real Levin frames over the seam, with real RandomX
//! under the hasher budget, syncing a real store through the real ingest
//! entry, against each scripted peer.
//!
//! The model's reason for each close is read off the owner's log line,
//! which carries the node's span: tests run side by side in one process,
//! and the span says which node closed which session.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use shekyl_chain_ingest::ProductionSubstrate;
use shekyl_chain_rules::{form_header, target_claim, FormAttempt, Substrate};
use shekyl_chain_store::codec::FollowingDegradedCell;
use shekyl_chain_store::store::SnapshotView;
use shekyl_chain_sync::SyncState;
use shekyl_draw_rng::SplitMix64;
use shekyl_hash_budget::Budget;
use shekyl_levin::{
    notify, RequestBodies, ResponseBodies, ResponseHeaders, SyncCommand, COMMAND_HANDSHAKE,
    NOTIFY_NEW_COMPACT_BLOCK, NOTIFY_NEW_TRANSACTIONS,
};
use shekyl_p2p_harness::sync::{
    announcement, fork_headers, frame, request_headers, substrate, Bodies, Chain, Corpus,
    HeaderChainPeer, Node, ServingPeer, Silent, Step, SyncPeer,
};
use shekyl_seam::SyncPayload;
use shekyl_transport_layer::CloseKind;
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::{Block, PowBlob};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

/// The ceiling on every wait for something to happen. Each wait returns
/// the moment its condition holds, which here takes seconds to a minute:
/// mostly real RandomX over a corpus's headers. The ceiling is for a
/// loaded runner, where fourteen of these share the cores, and it measures
/// nothing.
const LIMIT: Duration = Duration::from_secs(900);

// ---------------------------------------------------------------- logs --

/// Every close the owner logged: (node tag, session, cause).
static CLOSES: Mutex<Vec<(String, u64, String)>> = Mutex::new(Vec::new());

struct Tag(String);

#[derive(Default)]
struct Fields {
    tag: Option<String>,
    message: String,
    session: Option<u64>,
    cause: Option<String>,
}

impl Visit for Fields {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "session" {
            self.session = Some(value);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "tag" {
            self.tag = Some(value.to_owned());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "message" => self.message = format!("{value:?}"),
            "cause" => self.cause = Some(format!("{value:?}")),
            "tag" => self.tag = Some(format!("{value:?}").trim_matches('"').to_owned()),
            _ => {}
        }
    }
}

struct Closes;

impl<S> Layer<S> for Closes
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut fields = Fields::default();
        attrs.record(&mut fields);
        if let (Some(tag), Some(span)) = (fields.tag, ctx.span(id)) {
            span.extensions_mut().insert(Tag(tag));
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        if !fields.message.contains("closes a session") {
            return;
        }
        let tag = ctx.event_scope(event).and_then(|scope| {
            scope
                .from_root()
                .find_map(|span| span.extensions().get::<Tag>().map(|tag| tag.0.clone()))
        });
        if let (Some(tag), Some(session), Some(cause)) = (tag, fields.session, fields.cause) {
            CLOSES.lock().expect("closes").push((tag, session, cause));
        }
    }
}

fn logs() {
    let _installed = tracing_subscriber::registry()
        .with(Closes)
        .with(
            tracing_subscriber::fmt::layer()
                .with_test_writer()
                .with_filter(tracing_subscriber::EnvFilter::from_default_env()),
        )
        .try_init();
}

/// The model's closes on node `tag`, by session.
fn model_closes(tag: &str) -> HashMap<u64, String> {
    CLOSES
        .lock()
        .expect("closes")
        .iter()
        .filter(|(node, _, _)| node == tag)
        .map(|(_, session, cause)| (*session, cause.clone()))
        .collect()
}

// ------------------------------------------------------------- helpers --

/// The node's draw source: seeded, so a run repeats.
fn rng() -> SplitMix64 {
    SplitMix64::new(0x5EED)
}

/// A peer's handshake claim: its block count and cumulative work.
fn claim(count: u64, work: u128, top: BlockHash) -> SyncPayload {
    SyncPayload {
        current_height: count,
        cumulative_difficulty: u64::try_from(work & u128::from(u64::MAX)).expect("low"),
        cumulative_difficulty_top64: u64::try_from(work >> 64).expect("high"),
        top_id: *top.as_bytes(),
    }
}

/// The claim a chain's own tip makes.
fn claim_of(chain: &Chain) -> SyncPayload {
    let (count, work, top) = chain.tip().expect("a chain");
    claim(count, work, top)
}

/// A store holding `steps`, connected from its own node.
async fn source(tag: &str, corpus: &Corpus, steps: &[Step]) -> Chain {
    let (substrate, _) = substrate();
    let chain = Chain::empty(
        tag,
        corpus.rules(),
        Arc::new(substrate),
        Budget::new(NonZeroUsize::new(4).expect("four")),
    );
    chain.apply(steps).await;
    chain
}

fn spend() -> (Corpus, Vec<Step>) {
    let corpus = Corpus::open("spend-1in-2out");
    let steps = corpus.steps();
    (corpus, steps)
}

async fn wait_synced(node: &Node, count: u64) {
    let synced = node
        .wait(LIMIT, |node| {
            node.state() == SyncState::Synced && node.count() == count
        })
        .await;
    assert!(
        synced,
        "state {:?}, count {} of {count}",
        node.state(),
        node.count()
    );
}

// ---------------------------------------------------------- the honest --

/// A fresh node syncs a captured corpus from two honest peers and reaches
/// `Synced`. Every block connects through `form_judged`: the substrate
/// hashes each header once, and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_node_syncs_a_corpus_from_two_honest_peers_hashing_headers_only() {
    logs();
    let (corpus, steps) = spend();
    let held = source("honest-src", &corpus, &steps).await;
    let (count, _, _) = held.tip().expect("a chain");
    let mut node = Node::start("honest", corpus.rules(), &steps[..1], 2, rng()).await;
    let before = node.hashes();
    // Every state the node's handle publishes, in order. With genesis
    // alone and no claim yet, the first session is `Synced`; the claim
    // then makes the node `Behind` until the chain is in.
    let mut handle = node.state.subscribe();
    let published = Arc::new(Mutex::new(vec![*handle.borrow_and_update()]));
    let watcher = {
        let published = Arc::clone(&published);
        tokio::spawn(async move {
            while handle.changed().await.is_ok() {
                let state = *handle.borrow_and_update();
                published.lock().expect("states").push(state);
            }
        })
    };
    let mut seen = Vec::new();
    for _ in 0..2 {
        let (peer, asked) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
        seen.push(asked);
        node.connect(Box::new(peer), Some(claim_of(&held)));
    }
    wait_synced(&node, count).await;
    assert_eq!(
        node.hashes() - before,
        count - 1,
        "one hash per header and none in the entry"
    );
    // The handle went NoView, then Behind, then Synced.
    watcher.abort();
    let states = published.lock().expect("states").clone();
    let kinds: Vec<&str> = states
        .iter()
        .map(|state| match state {
            SyncState::NoView => "NoView",
            SyncState::Behind { .. } => "Behind",
            SyncState::Following { .. } => "Following",
            SyncState::Synced => "Synced",
        })
        .collect();
    let behind = kinds.iter().position(|kind| *kind == "Behind");
    assert!(
        kinds.first() == Some(&"NoView")
            && behind.is_some()
            && kinds.last() == Some(&"Synced")
            && kinds.iter().rposition(|kind| *kind == "Synced") > behind,
        "the handle published {kinds:?}"
    );
    // The chain fits one response: one header request, and no span
    // offered over another and fetched again.
    assert_eq!(seen.iter().map(|seen| seen.headers()).sum::<usize>(), 1);
    let bodies: usize = seen.iter().map(|seen| seen.bodies()).sum();
    assert!(
        bodies <= usize::try_from(count).expect("small"),
        "{bodies} body requests for {count} blocks"
    );
    assert!(model_closes("honest").is_empty());
    node.stop().await;
    held.stop().await;
}

// ---------------------------------------------------------- adversaries --

/// A peer whose chain ends below the work it states, and below this
/// node's, closes at `ClaimUnmet`.
///
/// The liar states the inflated work in every response's `tip_work` as well
/// as in its handshake: a response's `tip_work` replaces the claim (CS-Q2
/// step 1), so a peer that reports its real tip work there is not lying.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_liar_closes_at_claim_unmet() {
    logs();
    let (corpus, steps) = spend();
    let short = source("liar-src", &corpus, &steps[..41]).await;
    let node = Node::start("liar", corpus.rules(), &steps, 2, rng()).await;
    let mut node = node;
    let (_, _, top) = short.tip().expect("a chain");
    let (peer, seen) = ServingPeer::new(Arc::clone(&short.store), Bodies::Honest);
    let id = node.connect(Box::new(peer.stating(400)), Some(claim(400, 400, top)));
    assert!(
        node.wait(LIMIT, |node| node.closed(id).is_some()).await,
        "the liar was not closed; asked {} times",
        seen.headers()
    );
    assert_eq!(
        model_closes("liar").get(&id.get()).map(String::as_str),
        Some("ClaimUnmet")
    );
    node.stop().await;
    short.stop().await;
}

/// A peer that serves every header and marks every body unavailable keeps
/// its session and serves nothing: the node does not move.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_withholder_keeps_its_session_and_serves_nothing() {
    logs();
    let (corpus, steps) = spend();
    let held = source("withhold-src", &corpus, &steps).await;
    let mut node = Node::start("withhold", corpus.rules(), &steps[..1], 2, rng()).await;
    let (peer, seen) = ServingPeer::new(Arc::clone(&held.store), Bodies::Withhold);
    let id = node.connect(Box::new(peer), Some(claim_of(&held)));
    assert!(
        node.wait(LIMIT, |_| seen.bodies() >= 1).await,
        "no body was asked for"
    );
    // A few more rounds: still open, still at genesis.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(node.closed(id), None);
    assert_eq!(node.count(), 1);
    assert!(matches!(node.state(), SyncState::Behind { .. }));
    node.stop().await;
    held.stop().await;
}

/// A peer slower than the body deadline is excluded as a body source and
/// not closed; its late answer closes nothing; an honest peer that never
/// served a header, and names our tip, finishes the sync (CS-F8).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_slow_drip_is_excluded_as_a_body_source_and_not_closed() {
    logs();
    let (corpus, steps) = spend();
    let held = source("drip-src", &corpus, &steps).await;
    let (count, _, _) = held.tip().expect("a chain");
    let mut node = Node::start("drip", corpus.rules(), &steps[..1], 2, rng()).await;
    let late = Arc::new(Mutex::new(Vec::new()));
    let (peer, seen) = ServingPeer::new(Arc::clone(&held.store), Bodies::Hold(Arc::clone(&late)));
    let drip = node.connect(Box::new(peer), Some(claim_of(&held)));
    assert!(
        node.wait(LIMIT, |_| seen.bodies() >= 1).await,
        "no body was asked for"
    );
    let asked = seen.bodies();
    // Past every body deadline: the budget at the rate floor, plus transit.
    node.advance(Duration::from_secs(4_096));
    let (honest, _) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
    node.connect(Box::new(honest), Some(claim_of(&held)));
    wait_synced(&node, count).await;
    assert_eq!(seen.bodies(), asked, "an excluded source was asked again");
    // The late answers arrive now.
    let frames: Vec<Vec<u8>> = late.lock().expect("held").drain(..).collect();
    assert!(!frames.is_empty());
    for frame in frames {
        assert!(node.inject(drip, frame).await);
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(node.closed(drip), None);
    assert!(!model_closes("drip").contains_key(&drip.get()));
    node.stop().await;
    held.stop().await;
}

/// A fork with less work than this node's chain is never asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_low_work_fork_is_never_asked_for() {
    logs();
    let (corpus, steps) = spend();
    let mut node = Node::start("lowwork", corpus.rules(), &steps, 2, rng()).await;
    let mut chain: Vec<(BlockHash, Vec<u8>)> = (0..=60)
        .map(|height| {
            let block = node.chain.block(height);
            (block.hash(), block.pow_blob())
        })
        .collect();
    chain.extend(fork_headers(&node.chain, 60, 5));
    let (_, top_work, _) = node.chain.tip().expect("a chain");
    let top = chain.last().expect("a fork").0;
    let (peer, seen) = HeaderChainPeer::new(chain, 66);
    let id = node.connect(Box::new(peer), Some(claim(66, 66, top)));
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(top_work > 66);
    assert_eq!(seen.headers(), 0, "a lighter chain was asked for");
    assert_eq!(node.closed(id), None);
    assert_eq!(node.state(), SyncState::Synced);
    node.stop().await;
}

/// A heavier fork past the reorg cap raises the alarm: the latch is
/// written by the connector and read back set, with its evidence.
///
/// The test supplies one event after the fork's response: the evidence
/// draw waits for the next event (CS-Q2 step 3), and an idle node's next
/// event is the answered request's deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_past_cap_heavier_fork_raises_the_alarm_and_the_latch_reads_back() {
    logs();
    // The corpus with a cap short of its length: 64 blocks. Its reader
    // refuses a retired transaction at height 98, so the chain is the 98
    // blocks before it.
    let corpus = Corpus::open("emission-claim");
    let steps = corpus.steps_through(97);
    let mut node = Node::start("pastcap", corpus.rules(), &steps, 2, rng()).await;
    let (count, work, _) = node.chain.tip().expect("a chain");
    let fork_at = count - 1 - 70;
    let mut chain: Vec<(BlockHash, Vec<u8>)> = (0..=fork_at)
        .map(|height| {
            let block = node.chain.block(height);
            (block.hash(), block.pow_blob())
        })
        .collect();
    let fork = fork_headers(&node.chain, fork_at, 100);
    let top = fork.last().expect("a fork").0;
    chain.extend(fork);
    let fork_work = u128::from(fork_at + 1 + 100);
    assert!(fork_work > work, "the fork is heavier");
    let (peer, seen) = HeaderChainPeer::new(chain, fork_work);
    let id = node.connect(
        Box::new(peer),
        Some(claim(fork_at + 1 + 100, fork_work, top)),
    );
    assert!(
        node.wait(LIMIT, |_| seen.headers() >= 1).await,
        "the fork was not asked for"
    );
    // The response makes the fork a candidate; the one evidence draw waits
    // for the next event (CS-Q2 step 3). On an idle node that is the
    // answered request's deadline.
    tokio::time::sleep(Duration::from_secs(2)).await;
    node.advance(Duration::from_secs(4_096));
    assert!(
        node.wait(LIMIT, Node::alarm).await,
        "the alarm was not raised: {} header requests, state {:?}, closed {:?}, model {:?}",
        seen.headers(),
        node.state(),
        node.closed(id),
        model_closes("pastcap")
    );
    let snap = node.chain.store.begin_read().expect("a read");
    let latch = snap
        .get_property::<FollowingDegradedCell>()
        .expect("a read")
        .expect("the latch is set");
    assert!(latch.fork_at.to_raw() <= fork_at, "{latch:?}");
    assert!(latch.work.to_raw() > work);
    drop(snap);
    assert_eq!(node.count(), count, "nothing past the cap connected");
    node.stop().await;
}

/// A header whose proof fails closes its supplier on that one hash.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forged_header_closes_on_its_first_real_hash() {
    logs();
    let (corpus, steps) = spend();
    // A target of 2: half of all hashes fail it.
    let rules = corpus.rules_at(2);
    let mut node = Node::start("forged", rules, &steps[..1], 2, rng()).await;
    let genesis = node.chain.block(0);
    let Step::Block { block, .. } = &steps[1] else {
        panic!("height 1 is a block");
    };
    let mut forged = Block::from_bytes(block).expect("a block");
    let (prover, _) = substrate();
    let snap = node.chain.store.begin_read().expect("a read");
    let view = SnapshotView::new(&snap);
    let connecting = BlockHeight::from_raw(1);
    let rule_set = rules.in_force(connecting);
    let target = target_claim(&view, connecting, &rule_set)
        .expect("a read")
        .expect("a target");
    drop(snap);
    prover.pin_seed(&genesis.hash());
    let passes = |block: &Block, prover: &ProductionSubstrate| {
        let pow = PowBlob::read(&block.pow_blob()).expect("a preimage");
        matches!(
            form_header(
                &pow,
                &rule_set,
                prover,
                genesis.hash(),
                target,
                FormAttempt::FIRST
            ),
            Ok(Ok(_))
        )
    };
    let failing = (0..64u32)
        .find(|nonce| {
            forged.header.nonce = *nonce;
            !passes(&forged, &prover)
        })
        .expect("a nonce that fails target 2");
    forged.header.nonce = failing;
    let chain = vec![
        (genesis.hash(), genesis.pow_blob()),
        (forged.hash(), forged.pow_blob()),
    ];
    let (peer, _) = HeaderChainPeer::new(chain, 1_000);
    let before = node.hashes();
    let id = node.connect(Box::new(peer), Some(claim(2, 1_000, forged.hash())));
    assert!(
        node.wait(LIMIT, |node| node.closed(id).is_some()).await,
        "the forger was not closed"
    );
    let cause = model_closes("forged").get(&id.get()).cloned();
    assert!(
        cause
            .as_deref()
            .is_some_and(|cause| cause.starts_with("HeaderRefused")),
        "{cause:?}"
    );
    assert_eq!(node.hashes() - before, 1, "one hash, then the close");
    node.stop().await;
}

/// A body that is not its header's (a transaction it does not list)
/// closes the supplier at CEN-G2; the header survives, and an honest
/// peer's body connects under it unhashed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_substituted_body_closes_the_supplier_and_the_header_survives() {
    substituted("subst-body", Bodies::SubstituteBody, "Bind(G2)").await;
}

/// A witness that is not the block's closes the supplier at CEN-B4; the
/// header survives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_substituted_witness_closes_the_supplier_and_the_header_survives() {
    substituted("subst-witness", Bodies::SubstituteWitness, "Bind(B4)").await;
}

async fn substituted(tag: &str, bodies: Bodies, expected: &str) {
    logs();
    let (corpus, steps) = spend();
    let held = source(&format!("{tag}-src"), &corpus, &steps).await;
    let (count, _, _) = held.tip().expect("a chain");
    let mut node = Node::start(tag, corpus.rules(), &steps[..1], 2, rng()).await;
    let before = node.hashes();
    let (peer, _) = ServingPeer::new(Arc::clone(&held.store), bodies);
    let bad = node.connect(Box::new(peer), Some(claim_of(&held)));
    assert!(
        node.wait(LIMIT, |node| node.closed(bad).is_some()).await,
        "the substituter was not closed"
    );
    assert_eq!(
        model_closes(tag).get(&bad.get()).map(String::as_str),
        Some(expected)
    );
    // The headers survive. An honest peer that names our tip serves the
    // bodies under them (CS-F8), and nothing is hashed again.
    let (honest, _) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
    node.connect(Box::new(honest), Some(claim_of(&held)));
    wait_synced(&node, count).await;
    assert_eq!(
        node.hashes() - before,
        count - 1,
        "each header was hashed once, and none again"
    );
    node.stop().await;
    held.stop().await;
}

/// A server of skeletons only is not at fault: every block whose bodies
/// it serves whole connects, the first skeleton stops the span there, the
/// session stays open, and the skeleton's block is wanted whole from a
/// peer that names our tip (CS-F8).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_skeleton_only_server_is_kept_and_its_skeletons_are_wanted_whole() {
    logs();
    let (corpus, steps) = spend();
    let held = source("skeleton-src", &corpus, &steps).await;
    let (count, _, _) = held.tip().expect("a chain");
    let mut node = Node::start("skeleton", corpus.rules(), &steps[..1], 2, rng()).await;
    let (peer, seen) = ServingPeer::new(Arc::clone(&held.store), Bodies::Skeleton);
    let skeleton = node.connect(Box::new(peer), Some(claim_of(&held)));
    assert!(
        node.wait(LIMIT, |_| seen.bodies() >= 1).await,
        "no body was asked for"
    );
    let stopped = node
        .wait(LIMIT, |node| {
            let at = node.count();
            at > 1 && at < count
        })
        .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(stopped, "count {} of {count}", node.count());
    assert!(node.count() < count, "a skeleton connected");
    let (honest, _) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
    node.connect(Box::new(honest), Some(claim_of(&held)));
    wait_synced(&node, count).await;
    assert_eq!(node.closed(skeleton), None);
    assert!(!model_closes("skeleton").contains_key(&skeleton.get()));
    node.stop().await;
    held.stop().await;
}

/// A peer that names our tip and answers every body unavailable is the
/// withholder: kept, asked elsewhere first, and an honest peer finishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_naming_our_tip_and_withholding_every_body_is_the_withholder() {
    logs();
    let (corpus, steps) = spend();
    let held = source("named-src", &corpus, &steps).await;
    let (count, _, _) = held.tip().expect("a chain");
    let mut node = Node::start("named", corpus.rules(), &steps[..1], 2, rng()).await;
    // The headers come from a peer whose bodies do not bind: it closes, and
    // the headers stay.
    let (bad, _) = ServingPeer::new(Arc::clone(&held.store), Bodies::SubstituteBody);
    let bad = node.connect(Box::new(bad), Some(claim_of(&held)));
    assert!(
        node.wait(LIMIT, |node| node.closed(bad).is_some()).await,
        "the substituter was not closed"
    );
    let (withholder, asked) = ServingPeer::new(Arc::clone(&held.store), Bodies::Withhold);
    let withholder = node.connect(Box::new(withholder), Some(claim_of(&held)));
    assert!(
        node.wait(LIMIT, |_| asked.bodies() >= 1).await,
        "the named tip made no body source"
    );
    assert_eq!(
        asked.headers(),
        0,
        "an equal-work session is not asked for headers"
    );
    assert_eq!(node.count(), 1);
    let (honest, _) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
    node.connect(Box::new(honest), Some(claim_of(&held)));
    wait_synced(&node, count).await;
    assert_eq!(node.closed(withholder), None);
    assert!(!model_closes("named").contains_key(&withholder.get()));
    node.stop().await;
    held.stop().await;
}

/// A flood of unsolicited announcements beside a solicited sync does not
/// stall it: the flooded sync finishes within a bound of the unflooded
/// one, and the flooder is not closed.
///
/// Announcements (2008) are the owner's once the router is attached
/// (CS-4), so the flood reaches the model. It is a separate peer sending
/// a well-formed announcement of the chain's last block, which the node
/// cannot place until its parent is in; each costs the owner a decode
/// and the model's parent check, and at most one is proven per session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_announce_flood_does_not_stall_a_solicited_sync() {
    logs();
    let (corpus, steps) = spend();
    let held = source("flood-src", &corpus, &steps).await;
    let (count, _, _) = held.tip().expect("a chain");

    let mut quiet = Node::start("flood-quiet", corpus.rules(), &steps[..1], 2, rng()).await;
    let started = Instant::now();
    let (peer, _) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
    quiet.connect(Box::new(peer), Some(claim_of(&held)));
    wait_synced(&quiet, count).await;
    let unflooded = started.elapsed();
    quiet.stop().await;

    let mut loud = Node::start("flood", corpus.rules(), &steps[..1], 2, rng()).await;
    let started = Instant::now();
    let (peer, _) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
    loud.connect(Box::new(peer), Some(claim_of(&held)));
    let flooder = loud.connect(Box::new(Silent), None);
    let hub = loud.hub.clone();
    let announce = announcement(&held.store, count - 1);
    const ANNOUNCES: usize = 2_000;
    let flood = tokio::task::spawn_blocking(move || {
        (0..ANNOUNCES)
            .filter(|_| hub.inject(flooder, announce.clone()))
            .count()
    });
    wait_synced(&loud, count).await;
    let flooded = started.elapsed();
    let sent = flood.await.expect("the flood ends");
    assert_eq!(sent, ANNOUNCES);
    assert_eq!(
        loud.closed(flooder),
        None,
        "an unplaceable announcement is no fault"
    );
    assert!(
        !loud
            .stub
            .lock()
            .expect("stub")
            .commands
            .iter()
            .any(|(session, command)| *session == flooder && *command == NOTIFY_NEW_COMPACT_BLOCK),
        "an announcement reached the C++ handler"
    );
    assert!(
        flooded <= unflooded * 3 + Duration::from_secs(10),
        "flooded {flooded:?}, unflooded {unflooded:?}"
    );
    eprintln!(
        "sync of {count} blocks: unflooded {unflooded:?}, beside {ANNOUNCES} announcements {flooded:?}"
    );
    loud.stop().await;
    held.stop().await;
}

/// A bucket whose header does not read is the transport's refusal, as
/// today: the router hands the bytes to the C++ handler raw, its ingress
/// refuses them, and the session closes as refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_malformed_bucket_is_refused_by_the_cpp_ingress() {
    logs();
    let (corpus, steps) = spend();
    let mut node = Node::start("malformed", corpus.rules(), &steps[..1], 1, rng()).await;
    let (peer, _) = HeaderChainPeer::new(Vec::new(), 0);
    let id = node.connect(Box::new(peer), None);
    let mut bad = request_headers(vec![[0; 32]]);
    bad[0] ^= 0xFF;
    assert!(node.inject(id, bad).await);
    assert!(
        node.wait(LIMIT, |node| node.closed(id).is_some()).await,
        "the session stayed open"
    );
    assert_eq!(node.closed(id), Some(CloseKind::SessionRefused));
    assert_eq!(node.stub.lock().expect("stub").refused, vec![id]);
    node.stop().await;
}

/// The router forwards every non-sync command to the C++ handler byte for
/// byte: a handshake and a transaction relay reach the stub unchanged, and
/// a chain-sync request does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_router_forwards_non_sync_commands_untouched() {
    logs();
    let (corpus, steps) = spend();
    let mut node = Node::start("forward", corpus.rules(), &steps[..1], 1, rng()).await;
    let (peer, _) = HeaderChainPeer::new(Vec::new(), 0);
    let id = node.connect(Box::new(peer), None);
    let handshake = notify(COMMAND_HANDSHAKE, b"a handshake the stub does not parse");
    let relay = notify(NOTIFY_NEW_TRANSACTIONS, b"a relay the stub does not parse");
    let mut both = handshake.clone();
    both.extend_from_slice(&request_headers(vec![[0; 32]]));
    both.extend_from_slice(&relay);
    assert!(node.inject(id, both).await);
    assert!(
        node.wait(LIMIT, |node| node.stub.lock().expect("stub").commands.len()
            >= 2)
            .await,
        "nothing reached the C++ handler"
    );
    let mut expected = handshake;
    expected.extend_from_slice(&relay);
    let (delivered, commands) = {
        let stub = node.stub.lock().expect("stub");
        let delivered: Vec<u8> = stub
            .delivered
            .iter()
            .filter(|(session, _)| *session == id)
            .flat_map(|(_, bytes)| bytes.clone())
            .collect();
        (delivered, stub.commands.clone())
    };
    assert_eq!(delivered, expected, "the non-sync bytes, unchanged");
    assert_eq!(
        commands,
        vec![(id, COMMAND_HANDSHAKE), (id, NOTIFY_NEW_TRANSACTIONS)]
    );
    node.stop().await;
}

// --------------------------------------------------------------- serving --

/// What an asking peer got back.
#[derive(Default)]
struct Answers {
    headers: Vec<ResponseHeaders>,
    bodies: Vec<ResponseBodies>,
}

struct Asker(Arc<Mutex<Answers>>);

impl SyncPeer for Asker {
    fn on_message(&mut self, command: u32, payload: &[u8]) -> Vec<Vec<u8>> {
        let mut answers = self.0.lock().expect("answers");
        match SyncCommand::from_wire(command) {
            Some(SyncCommand::ResponseHeaders) => answers
                .headers
                .push(ResponseHeaders::decode(payload).expect("the node's response decodes")),
            Some(SyncCommand::ResponseBodies) => answers
                .bodies
                .push(ResponseBodies::decode(payload).expect("the node's response decodes")),
            _ => {}
        }
        Vec::new()
    }
}

/// The node answers both requests from its store, with responses the
/// requester's own form checks accept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_node_serves_requests_its_own_form_checks_accept() {
    logs();
    let (corpus, steps) = spend();
    let mut node = Node::start("serve", corpus.rules(), &steps, 1, rng()).await;
    let (count, _, _) = node.chain.tip().expect("a chain");
    let answers = Arc::new(Mutex::new(Answers::default()));
    let id = node.connect(Box::new(Asker(Arc::clone(&answers))), None);
    assert!(node.inject(id, request_headers(vec![[0; 32]])).await);
    assert!(
        node.wait(LIMIT, |_| !answers
            .lock()
            .expect("answers")
            .headers
            .is_empty())
            .await,
        "no header response"
    );
    let headers = answers.lock().expect("answers").headers[0].clone();
    assert_eq!(
        u64::try_from(headers.blobs.len()).expect("small"),
        count,
        "every header from genesis"
    );
    assert!(!headers.more);
    let hashes: Vec<[u8; 32]> = headers
        .blobs
        .iter()
        .map(|blob| {
            *PowBlob::read(blob)
                .expect("a preimage")
                .identity()
                .as_bytes()
        })
        .collect();
    let request = RequestBodies {
        hashes: hashes[1..].to_vec(),
    };
    assert!(
        node.inject(id, frame(SyncCommand::RequestBodies, &request))
            .await
    );
    assert!(
        node.wait(LIMIT, |_| !answers
            .lock()
            .expect("answers")
            .bodies
            .is_empty())
            .await,
        "no body response"
    );
    let bodies = answers.lock().expect("answers").bodies[0].clone();
    bodies
        .check_form(&request.hashes)
        .expect("the response passes the requester's form check");
    assert!(!bodies.bodies.is_empty());
    assert!(bodies.missed_ids.is_empty(), "every block is held");
    assert_eq!(node.closed(id), None);
    node.stop().await;
}

/// A locator hash this store holds only as an alternative block is
/// skipped, and the response starts after the next locator hash on the
/// main chain. The requester accepts a response only when its first
/// header's parent is a hash it named, and an alternative block's fork
/// point is seldom in a sparse locator.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_locator_hash_held_only_as_an_alternative_is_skipped() {
    use shekyl_chain_ingest::service::{Arrival, ArrivalTag, Origin, Reply};
    use shekyl_chain_sync_runtime::serve::serve_headers;
    use shekyl_levin::RequestHeaders;

    let (corpus, steps) = spend();
    let chain = source("serve-alt", &corpus, &steps).await;
    let (count, _, _) = chain.tip().expect("a chain");
    let fork_at = count - 3;
    let main = chain.block(fork_at + 1);
    let bodies = steps
        .iter()
        .find_map(|step| match step {
            Step::Block { block, bodies } if *block == main.serialize() => Some(bodies.clone()),
            _ => None,
        })
        .expect("the corpus holds the block");
    // The main block's sibling: the same parent and transactions, another
    // nonce. It is lighter than the main chain, so it is stored beside it.
    let mut sibling = main.clone();
    sibling.header.nonce ^= 0x5A5A_5A5A;
    let ticket = chain
        .service
        .door()
        .offer(Arrival {
            tag: ArrivalTag(9001),
            origin: Origin::Local,
            block: sibling.serialize(),
            bodies,
        })
        .expect("room");
    let reply = ticket.reply().await.reply;
    assert!(matches!(reply, Reply::Held { .. }), "{reply:?}");
    let named = chain.block(fork_at - 2).hash();
    let genesis = chain.block(0).hash();
    let response = serve_headers(
        &chain.store,
        &RequestHeaders {
            block_ids: vec![
                *sibling.hash().as_bytes(),
                *named.as_bytes(),
                *genesis.as_bytes(),
            ],
        },
    )
    .expect("the store answers");
    let first = PowBlob::read(response.blobs.first().expect("headers")).expect("a preimage");
    assert_eq!(
        first.header.previous, named,
        "the response starts after a hash the requester named"
    );
    assert!(!response.more);
    chain.stop().await;
}

/// A chunk that mixes chain-sync requests with bytes for the C++ handler
/// is finished by that handler, not after serving, so the transport does
/// not hold the peer back. The owner's queue bounds it instead: a flood of
/// header requests packed beside a relay is answered a few times, not once
/// per request, and the session stays open. A last request for our tip
/// (answered with no headers) marks the end of the flood's serving.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_flood_beside_cpp_bytes_is_bounded_by_the_serving_queue() {
    logs();
    let (corpus, steps) = spend();
    let mut node = Node::start("serve-flood", corpus.rules(), &steps, 1, rng()).await;
    let (_, _, tip) = node.chain.tip().expect("a chain");
    let answers = Arc::new(Mutex::new(Answers::default()));
    let id = node.connect(Box::new(Asker(Arc::clone(&answers))), None);
    const REQUESTS: usize = 64;
    let mut chunk = Vec::new();
    for index in 0..REQUESTS {
        chunk.extend_from_slice(&request_headers(vec![[0; 32]]));
        if index == REQUESTS / 2 {
            chunk.extend_from_slice(&notify(
                NOTIFY_NEW_TRANSACTIONS,
                b"a relay the stub does not parse",
            ));
        }
    }
    assert!(node.inject(id, chunk).await);
    assert!(
        node.wait(LIMIT, |node| node
            .stub
            .lock()
            .expect("stub")
            .commands
            .contains(&(id, NOTIFY_NEW_TRANSACTIONS)))
            .await,
        "the relay did not reach the C++ handler"
    );
    assert!(
        node.inject(id, request_headers(vec![*tip.as_bytes()]))
            .await
    );
    assert!(
        node.wait(LIMIT, |_| answers
            .lock()
            .expect("answers")
            .headers
            .iter()
            .any(|response| response.blobs.is_empty()))
            .await,
        "the marker request was not answered"
    );
    let flood = answers
        .lock()
        .expect("answers")
        .headers
        .iter()
        .filter(|response| !response.blobs.is_empty())
        .count();
    eprintln!("{REQUESTS} packed header requests were answered {flood} times");
    assert!(flood >= 1, "the flood was not served at all");
    assert!(
        flood < REQUESTS,
        "every packed request was served: the queue is unbounded"
    );
    assert_eq!(node.closed(id), None);
    node.stop().await;
}

// --------------------------------------------------------------- CS-4 --

/// An inbound session's claim arrives as a hint (`shekyl_chain_sync_hint`,
/// CS-Q10): before it the session is no source; after it the session
/// serves the headers and the bodies, with no outbound dial.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_inbound_session_serves_the_sync_after_its_hint() {
    logs();
    let (corpus, steps) = spend();
    let held = source("inbound-src", &corpus, &steps).await;
    let (count, _, _) = held.tip().expect("a chain");
    let mut node = Node::start("inbound", corpus.rules(), &steps[..1], 2, rng()).await;
    let (peer, seen) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
    let id = node.accept(Box::new(peer));
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        seen.headers(),
        0,
        "an inbound session with no claim is no source"
    );
    assert!(node.hint(id, claim_of(&held)), "the owner took the hint");
    wait_synced(&node, count).await;
    assert!(seen.headers() >= 1 && seen.bodies() >= 1);
    node.stop().await;
    held.stop().await;
}

/// A connected announcement is relayed as the C++ `relay_block` does: to
/// every established session but the one that announced it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connected_announcement_is_relayed_to_every_other_session() {
    logs();
    let (corpus, steps) = spend();
    let held = source("relay-src", &corpus, &steps).await;
    let (count, _, _) = held.tip().expect("a chain");
    // The node holds every block but the last.
    let mut node = Node::start("relay", corpus.rules(), &steps[..steps.len() - 1], 2, rng()).await;
    let (_, work, top) = node.chain.tip().expect("a chain");
    let mut seen = Vec::new();
    let mut ids = Vec::new();
    for _ in 0..3 {
        let (peer, asked) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
        seen.push(asked);
        ids.push(node.connect(Box::new(peer), Some(claim(count - 1, work, top))));
    }
    assert!(
        node.wait(LIMIT, |node| node.state() == SyncState::Synced)
            .await,
        "state {:?}",
        node.state()
    );
    assert!(
        node.inject(ids[0], announcement(&held.store, count - 1))
            .await
    );
    assert!(
        node.wait(LIMIT, |node| node.count() == count).await,
        "the announcement did not connect"
    );
    assert!(
        node.wait(LIMIT, |_| seen[1].announced() == 1
            && seen[2].announced() == 1)
            .await,
        "relayed {:?}",
        seen.iter().map(|seen| seen.announced()).collect::<Vec<_>>()
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(seen[0].announced(), 0, "not back to the announcer");
    node.stop().await;
    held.stop().await;
}
