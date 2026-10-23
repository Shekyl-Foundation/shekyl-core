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
use shekyl_hash_budget::Budget;
use shekyl_levin::{
    notify, RequestBodies, ResponseBodies, ResponseHeaders, SyncCommand, COMMAND_HANDSHAKE,
    NOTIFY_NEW_COMPACT_BLOCK, NOTIFY_NEW_TRANSACTIONS,
};
use shekyl_p2p_harness::sync::{
    fork_headers, frame, request_headers, substrate, Bodies, Chain, Corpus, HeaderChainPeer, Node,
    ServingPeer, Step, SyncPeer,
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

const SYNC_LIMIT: Duration = Duration::from_secs(240);
const SHORT: Duration = Duration::from_secs(60);

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
        .wait(SYNC_LIMIT, |node| {
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
    let mut node = Node::start("honest", corpus.rules(), &steps[..1], 2).await;
    let before = node.hashes();
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
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_liar_closes_at_claim_unmet() {
    logs();
    let (corpus, steps) = spend();
    let short = source("liar-src", &corpus, &steps[..41]).await;
    let node = Node::start("liar", corpus.rules(), &steps, 2).await;
    let mut node = node;
    let (_, _, top) = short.tip().expect("a chain");
    let (peer, seen) = ServingPeer::new(Arc::clone(&short.store), Bodies::Honest);
    let id = node.connect(Box::new(peer.stating(400)), Some(claim(400, 400, top)));
    assert!(
        node.wait(SHORT, |node| node.closed(id).is_some()).await,
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
    let mut node = Node::start("withhold", corpus.rules(), &steps[..1], 2).await;
    let (peer, seen) = ServingPeer::new(Arc::clone(&held.store), Bodies::Withhold);
    let id = node.connect(Box::new(peer), Some(claim_of(&held)));
    assert!(
        node.wait(SHORT, |_| seen.bodies() >= 1).await,
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
/// not closed, and its late answer closes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_slow_drip_is_excluded_as_a_body_source_and_not_closed() {
    logs();
    let (corpus, steps) = spend();
    let held = source("drip-src", &corpus, &steps).await;
    let mut node = Node::start("drip", corpus.rules(), &steps[..1], 2).await;
    let late = Arc::new(Mutex::new(Vec::new()));
    let (peer, seen) = ServingPeer::new(Arc::clone(&held.store), Bodies::Hold(Arc::clone(&late)));
    let drip = node.connect(Box::new(peer), Some(claim_of(&held)));
    assert!(
        node.wait(SHORT, |_| seen.bodies() >= 1).await,
        "no body was asked for"
    );
    let asked = seen.bodies();
    // Past every body deadline: the budget at the rate floor, plus transit.
    node.advance(Duration::from_secs(4_096));
    tokio::time::sleep(Duration::from_secs(3)).await;
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
    assert_eq!(node.count(), 1, "a late body is not a span's answer");
    node.stop().await;
    held.stop().await;
}

/// A fork with less work than this node's chain is never asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_low_work_fork_is_never_asked_for() {
    logs();
    let (corpus, steps) = spend();
    let mut node = Node::start("lowwork", corpus.rules(), &steps, 2).await;
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
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_past_cap_heavier_fork_raises_the_alarm_and_the_latch_reads_back() {
    logs();
    // The corpus with a cap short of its length: 64 blocks. Its reader
    // refuses a retired transaction at height 98, so the chain is the 98
    // blocks before it.
    let corpus = Corpus::open("emission-claim");
    let steps = corpus.steps_through(97);
    let mut node = Node::start("pastcap", corpus.rules(), &steps, 2).await;
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
        node.wait(SHORT, |_| seen.headers() >= 1).await,
        "the fork was not asked for"
    );
    // The response makes the fork a candidate; the one evidence draw waits
    // for the next event (CS-Q2 step 3). On an idle node that is the
    // answered request's deadline.
    tokio::time::sleep(Duration::from_secs(2)).await;
    node.advance(Duration::from_secs(4_096));
    assert!(
        node.wait(SYNC_LIMIT, Node::alarm).await,
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
    let mut node = Node::start("forged", rules, &steps[..1], 2).await;
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
        node.wait(SHORT, |node| node.closed(id).is_some()).await,
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
    let (count, work, _) = held.tip().expect("a chain");
    let mut node = Node::start(tag, corpus.rules(), &steps[..1], 2).await;
    let before = node.hashes();
    let (peer, _) = ServingPeer::new(Arc::clone(&held.store), bodies);
    let bad = node.connect(Box::new(peer), Some(claim_of(&held)));
    assert!(
        node.wait(SHORT, |node| node.closed(bad).is_some()).await,
        "the substituter was not closed"
    );
    assert_eq!(
        model_closes(tag).get(&bad.get()).map(String::as_str),
        Some(expected)
    );
    // The headers survive: with a session open again the node is behind
    // the substituter's verified chain, which nobody re-proves.
    let (honest, _) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
    node.connect(Box::new(honest), Some(claim_of(&held)));
    assert!(
        node.wait(SHORT, |node| matches!(
            node.state(),
            SyncState::Behind { best, .. } if best.to_raw() == work
        ))
        .await,
        "state {:?}",
        node.state()
    );
    assert_eq!(
        node.hashes() - before,
        count - 1,
        "each header was hashed once, and none again"
    );
    node.stop().await;
    held.stop().await;
}

/// A server of skeletons only is not at fault: every block whose bodies
/// it serves whole connects, the first skeleton stops the span there, and
/// the session stays open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_skeleton_only_server_is_not_closed() {
    logs();
    let (corpus, steps) = spend();
    let held = source("skeleton-src", &corpus, &steps).await;
    let (count, _, _) = held.tip().expect("a chain");
    let mut node = Node::start("skeleton", corpus.rules(), &steps[..1], 2).await;
    let (peer, seen) = ServingPeer::new(Arc::clone(&held.store), Bodies::Skeleton);
    let skeleton = node.connect(Box::new(peer), Some(claim_of(&held)));
    assert!(
        node.wait(SHORT, |_| seen.bodies() >= 1).await,
        "no body was asked for"
    );
    let stopped = node
        .wait(SHORT, |node| {
            let at = node.count();
            at > 1 && at < count
        })
        .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(stopped, "count {} of {count}", node.count());
    assert!(node.count() < count, "a skeleton connected");
    assert_eq!(node.closed(skeleton), None);
    assert!(!model_closes("skeleton").contains_key(&skeleton.get()));
    node.stop().await;
    held.stop().await;
}

/// A flood of unsolicited announcements beside a solicited sync goes to
/// the C++ handler and does not stall the sync: the flooded sync finishes
/// within a bound of the unflooded one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_announce_flood_does_not_stall_a_solicited_sync() {
    logs();
    let (corpus, steps) = spend();
    let held = source("flood-src", &corpus, &steps).await;
    let (count, _, _) = held.tip().expect("a chain");

    let mut quiet = Node::start("flood-quiet", corpus.rules(), &steps[..1], 2).await;
    let started = Instant::now();
    let (peer, _) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
    quiet.connect(Box::new(peer), Some(claim_of(&held)));
    wait_synced(&quiet, count).await;
    let unflooded = started.elapsed();
    quiet.stop().await;

    let mut loud = Node::start("flood", corpus.rules(), &steps[..1], 2).await;
    let started = Instant::now();
    let (peer, _) = ServingPeer::new(Arc::clone(&held.store), Bodies::Honest);
    let id = loud.connect(Box::new(peer), Some(claim_of(&held)));
    let hub = loud.hub.clone();
    const ANNOUNCES: usize = 2_000;
    let flood = tokio::task::spawn_blocking(move || {
        let announce = notify(NOTIFY_NEW_COMPACT_BLOCK, &[0u8; 512]);
        (0..ANNOUNCES)
            .filter(|_| hub.inject(id, announce.clone()))
            .count()
    });
    wait_synced(&loud, count).await;
    let flooded = started.elapsed();
    let sent = flood.await.expect("the flood ends");
    let forwarded = loud
        .stub
        .lock()
        .expect("stub")
        .commands
        .iter()
        .filter(|(session, command)| *session == id && *command == NOTIFY_NEW_COMPACT_BLOCK)
        .count();
    assert_eq!(sent, ANNOUNCES);
    assert!(
        loud.wait(SHORT, |node| {
            node.stub
                .lock()
                .expect("stub")
                .commands
                .iter()
                .filter(|(session, command)| *session == id && *command == NOTIFY_NEW_COMPACT_BLOCK)
                .count()
                == ANNOUNCES
        })
        .await,
        "{forwarded} of {ANNOUNCES} announcements reached the C++ handler"
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
    let mut node = Node::start("malformed", corpus.rules(), &steps[..1], 1).await;
    let (peer, _) = HeaderChainPeer::new(Vec::new(), 0);
    let id = node.connect(Box::new(peer), None);
    let mut bad = request_headers(vec![[0; 32]]);
    bad[0] ^= 0xFF;
    assert!(node.inject(id, bad).await);
    assert!(
        node.wait(SHORT, |node| node.closed(id).is_some()).await,
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
    let mut node = Node::start("forward", corpus.rules(), &steps[..1], 1).await;
    let (peer, _) = HeaderChainPeer::new(Vec::new(), 0);
    let id = node.connect(Box::new(peer), None);
    let handshake = notify(COMMAND_HANDSHAKE, b"a handshake the stub does not parse");
    let relay = notify(NOTIFY_NEW_TRANSACTIONS, b"a relay the stub does not parse");
    let mut both = handshake.clone();
    both.extend_from_slice(&request_headers(vec![[0; 32]]));
    both.extend_from_slice(&relay);
    assert!(node.inject(id, both).await);
    assert!(
        node.wait(SHORT, |node| node.stub.lock().expect("stub").commands.len()
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
    let mut node = Node::start("serve", corpus.rules(), &steps, 1).await;
    let (count, _, _) = node.chain.tip().expect("a chain");
    let answers = Arc::new(Mutex::new(Answers::default()));
    let id = node.connect(Box::new(Asker(Arc::clone(&answers))), None);
    assert!(node.inject(id, request_headers(vec![[0; 32]])).await);
    assert!(
        node.wait(SHORT, |_| !answers
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
        node.wait(SHORT, |_| !answers
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
