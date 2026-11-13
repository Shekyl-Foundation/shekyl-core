// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bundles between two nodes (`SO-D12` 4b-T; `ARCHIVAL_SERVE_CREDIT_SPEC.md`
//! §7.5, `SCS-P25`).
//!
//! Two nodes, each a real store, ingest service, sync owner and session
//! layer, hold the same chain: the spend corpus and one more block whose
//! `0x0C` commits to a witness key and seed this test holds. A bridge
//! carries each node's buckets to the other through the session layers, as
//! a link between two daemons does. A bundle filed on A is admitted by A's
//! queue, relayed as 2015, admitted by B's queue against B's own tip, and
//! held there.
//!
//! The bundle is for a block that issued no draws: a valid bundle with
//! empty bitmaps (§7.1), which a producer does not file but the rule
//! admits. The rule that admits it is the rule that admits any.
//!
//! A block whose section names that bundle then travels from A to B as a
//! 2008, which carries the references alone. B's own body store holds
//! the body, so B connects the block without a 2016 (`SCS-P27`).

use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use shekyl_archival_retention::{
    assemble_bundle, draw_commit, empty_section_root, section_root, sign_bundle_commitment,
    BundleBody, BundleKept, BundleRef, PassBitmap, BUNDLE_WITNESS_KEY_LEN,
};
use shekyl_block_template::{build, EmissionOperands, MinerKeys, TemplateContext};
use shekyl_chain_ingest::connector::{BundleOffered, TemplateFacts};
use shekyl_chain_ingest::service::{ArrivalTag, Reply};
use shekyl_chain_ingest::ChainRules;
use shekyl_crypto_pq::fn_dsa_hybrid::{FnDsaHybridSecretKey, HybridEd25519FnDsa};
use shekyl_levin::{NOTIFY_NEW_COMPACT_BLOCK, NOTIFY_REQUEST_BUNDLE_BODIES};
use shekyl_miner::Job;
use shekyl_p2p_harness::sync::{Node, PeerDial, SyncPeer};
use shekyl_transport_layer::SocketId;
use shekyl_types::{BlockHeight, SectionRoot, Timestamp};
use zeroize::Zeroizing;

// The shared support serves every chain-sync binary. This one links two
// nodes at the same tip and uses none of its sync claims or sources.
#[allow(dead_code)]
#[path = "chain_sync/support.rs"]
mod support;

use support::{logs, rng, session_rng, spend, LIMIT};

/// The commands one node sent across the bridge, in order.
type Carried = Arc<Mutex<Vec<u32>>>;

/// The far side of one node's session: every bucket the node sends goes to
/// the other node, and its command is recorded.
struct Bridge {
    to: mpsc::Sender<(u32, Vec<u8>)>,
    carried: Carried,
}

impl SyncPeer for Bridge {
    fn on_message(&mut self, command: u32, payload: &[u8]) -> Vec<Vec<u8>> {
        self.carried.lock().expect("carried").push(command);
        // The other side gone is the test ending.
        let _gone = self.to.send((command, payload.to_vec()));
        Vec::new()
    }
}

/// How many of `carried`'s commands are `command`.
fn sent(carried: &Carried, command: u32) -> usize {
    carried
        .lock()
        .expect("carried")
        .iter()
        .filter(|sent| **sent == command)
        .count()
}

/// Carry what one node sent into the other node's session, once that
/// session is established.
fn pump(
    from: mpsc::Receiver<(u32, Vec<u8>)>,
    into: Arc<PeerDial>,
    session: Arc<OnceLock<SocketId>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for (command, payload) in from {
            let id = loop {
                if let Some(id) = session.get() {
                    break *id;
                }
                thread::sleep(Duration::from_millis(5));
            };
            let _open = into.inject(id, shekyl_levin::notify(command, &payload));
        }
    })
}

/// A and B linked through two bridges: A dials, B accepts.
struct Link {
    a_id: SocketId,
    b_id: SocketId,
    /// What A sent B.
    from_a: Carried,
    /// What B sent A.
    from_b: Carried,
}

async fn link(a: &mut Node, b: &mut Node) -> Link {
    let (to_b, from_a) = mpsc::channel();
    let (to_a, from_b) = mpsc::channel();
    let a_session = Arc::new(OnceLock::new());
    let b_session = Arc::new(OnceLock::new());
    let _into_b = pump(from_a, Arc::clone(&b.dial), Arc::clone(&b_session));
    let _into_a = pump(from_b, Arc::clone(&a.dial), Arc::clone(&a_session));
    let carried_a = Carried::default();
    let carried_b = Carried::default();
    let a_id = a
        .connect(
            Box::new(Bridge {
                to: to_b,
                carried: Arc::clone(&carried_a),
            }),
            None,
        )
        .await;
    a_session.set(a_id).expect("set once");
    let b_id = b
        .accept(
            Box::new(Bridge {
                to: to_a,
                carried: Arc::clone(&carried_b),
            }),
            None,
        )
        .await;
    b_session.set(b_id).expect("set once");
    Link {
        a_id,
        b_id,
        from_a: carried_a,
        from_b: carried_b,
    }
}

/// A witness key and seed the test holds.
struct Witness {
    public: [u8; BUNDLE_WITNESS_KEY_LEN],
    secret: FnDsaHybridSecretKey,
    seed: [u8; 32],
}

impl Witness {
    fn new(tag: u8) -> Self {
        let (public, secret) =
            HybridEd25519FnDsa::keypair_from_seeds(&[tag; 32], &[tag ^ 0x5A; 32]).expect("keygen");
        Self {
            public: public
                .to_canonical_bytes()
                .try_into()
                .expect("the canonical key width"),
            secret,
            seed: [tag; 32],
        }
    }

    /// The bundle for `h`, a block that issued no draws.
    fn bundle(&self, rules: ChainRules, h: BlockHeight) -> (BundleRef, BundleBody) {
        let kept = BundleKept {
            h,
            seed: self.seed,
            passes: PassBitmap::none(),
            support: PassBitmap::none(),
        };
        assemble_bundle(
            &rules.trust().network_id(),
            &kept,
            &[],
            &self.public,
            |commitment| sign_bundle_commitment(&self.secret, commitment),
        )
        .expect("the key signs")
    }
}

/// The keys a block here pays.
fn miner_keys() -> MinerKeys {
    let wallet = shekyl_harness_wallet::MinerWallet::from_seed(&[0x6b; 32]);
    let recipient = wallet.recipient();
    MinerKeys {
        spend_public: recipient.spend_public,
        x25519_pk: recipient.x25519_pk,
        ml_kem_ek: recipient.ml_kem_ek.clone(),
    }
}

/// The block after `node`'s tip, its `0x0C` committed to `witness`. The
/// corpus is mined at difficulty 1, so its nonce is any nonce.
async fn committed_block(node: &Node, rules: ChainRules, witness: &Witness) -> Vec<u8> {
    let facts = node
        .chain
        .service
        .connector()
        .ask(TemplateFacts)
        .await
        .expect("the chain's facts");
    let rule_set = rules.in_force(facts.connecting);
    let miner = miner_keys();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    let commitment = draw_commit(&witness.public, &witness.seed);
    let template = build(&TemplateContext {
        height: facts.connecting,
        previous: facts.previous,
        curve_tree_root: facts.curve_tree_root,
        section_root: SectionRoot::from_bytes(empty_section_root()),
        major_version: rule_set.header_major_version(),
        now: Timestamp::from_raw(now),
        median_timestamp: facts.median_timestamp,
        unlock_window: rule_set.mined_money_unlock_window(),
        emission: EmissionOperands {
            already_generated_coins: facts.parent_coins_generated,
            total_burned: facts.total_burned,
            median_weight: facts.medians.effective_median.to_raw(),
            tx_volume: facts.tx_volume,
            closed_shards: facts.closed_shards,
        },
        params: shekyl_economics::economic_params(),
        miner: &miner,
        tx_key_secret: Zeroizing::new([0x42; 32]),
        extra_nonce: [0; shekyl_wire::tx_extra::COINBASE_NONCE_BYTES],
        draw_commitment: shekyl_wire::tx_extra::DrawCommitment::from_bytes(commitment),
        listed: &[],
    })
    .expect("the template builds");
    template.block.serialize()
}

async fn connect_local(node: &Node, block: Vec<u8>) -> BlockHeight {
    let mined = node
        .chain
        .service
        .door()
        .offer_local(ArrivalTag(u64::MAX), block, Vec::new())
        .await
        .expect("the door takes a local block");
    match mined.reply {
        Reply::Connected { height, .. } => height,
        other => panic!("the committed block did not connect: {other:?}"),
    }
}

fn queued(node: &Node) -> Vec<BlockHeight> {
    node.chain
        .store
        .begin_read()
        .expect("snapshot")
        .queued_bundles()
        .expect("the queue reads")
        .into_iter()
        .map(|entry| entry.h)
        .collect()
}

/// A bundle filed on A reaches B's queue (4b-T's done-when): A's queue
/// admits it and A relays it as 2015; B's queue admits it against B's own
/// tip, and B holds the same reference and body. A's link is not closed
/// for it. Red edits: relay a filed bundle to no session, or have the owner
/// drop a 2015 instead of offering it — B's queue stays empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bundle_filed_on_one_node_reaches_the_other_nodes_queue() {
    logs();
    let (corpus, steps) = spend();
    let rules = corpus.rules();
    let mut a = Node::start("bundle-a", rules, &steps, 2, rng(), session_rng()).await;
    let mut b = Node::start("bundle-b", rules, &steps, 2, rng(), session_rng()).await;

    let witness = Witness::new(0x41);
    let block = committed_block(&a, rules, &witness).await;
    let h = connect_local(&a, block.clone()).await;
    assert_eq!(
        connect_local(&b, block).await,
        h,
        "both hold the same chain"
    );

    let Link { a_id, b_id, .. } = link(&mut a, &mut b).await;

    let (reference, body) = witness.bundle(rules, h);
    let filed = a
        .chain
        .service
        .door()
        .file_bundle(reference.clone(), body.clone())
        .await
        .expect("A's connector answers");
    assert!(
        matches!(filed, BundleOffered::Queued { h: queued_h, .. } if queued_h == h),
        "A's queue admits its own bundle: {filed:?}"
    );

    let arrived = b.wait(LIMIT, |node| queued(node).contains(&h)).await;
    assert!(arrived, "B's queue never held the bundle A filed");
    let held = b
        .chain
        .store
        .begin_read()
        .expect("snapshot")
        .queued_bundles()
        .expect("the queue reads");
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].queued.reference, reference);
    assert_eq!(held[0].body, body);
    assert_eq!(queued(&a), vec![h], "A holds its own, once");
    assert_eq!(a.closed(a_id), None, "the relay closed no session");
    assert_eq!(b.closed(b_id), None, "the relay closed no session");

    a.stop().await;
    b.stop().await;
}

/// The job `node`'s follower posts for the block after `tip`.
async fn job_after(node: &Node, tip: BlockHeight) -> Job {
    let board = &node.miner.as_ref().expect("a mining node").board;
    let next = tip.to_raw() + 1;
    let mut job = None;
    let posted = node
        .wait(LIMIT, |_| {
            job = board
                .posted()
                .map(|(_, posted)| posted)
                .filter(|posted| posted.height.to_raw() == next);
            job.is_some()
        })
        .await;
    assert!(posted, "the follower posted no job at {next}");
    job.expect("the job the wait saw")
}

/// Jobs the follower may connect that still name no bundle. The job on
/// the tip the bundle was filed at can be empty; the next must name it,
/// inside the bundle's window (`h < h_incl ≤ h + W₂`).
const EMPTY_JOBS_BEFORE_THE_SECTION: usize = 1;

/// A block whose section names a bundle B already holds connects on B
/// without a 2016 (`SCS-P27`; the owner's `ask_bundle_bodies`). A files a
/// bundle, and B's queue admits it from A's 2015. A then mines its
/// follower's jobs: the door attaches the posting's section to each, and
/// the model relays each as 2008, references only. The follower builds on
/// a tip move, so the job on the tip the bundle was filed at may name no
/// bundle; the next names it. B connects every block, its store answers
/// the section, and B asks A for nothing. No session is closed. Red edit:
/// have the owner ask the session for every reference whatever the store
/// holds — B sends a 2016.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_block_naming_a_held_bundle_connects_without_a_body_request() {
    logs();
    let (corpus, steps) = spend();
    let rules = corpus.rules();
    let mut a = Node::start_mining(
        "held-a",
        rules,
        &steps,
        2,
        rng(),
        session_rng(),
        miner_keys(),
    )
    .await;
    let mut b = Node::start("held-b", rules, &steps, 2, rng(), session_rng()).await;

    let witness = Witness::new(0x43);
    let block = committed_block(&a, rules, &witness).await;
    let h = connect_local(&a, block.clone()).await;
    assert_eq!(
        connect_local(&b, block).await,
        h,
        "both hold the same chain"
    );

    let Link {
        a_id,
        b_id,
        from_a,
        from_b,
    } = link(&mut a, &mut b).await;

    let (reference, body) = witness.bundle(rules, h);
    let filed = a
        .chain
        .service
        .door()
        .file_bundle(reference.clone(), body)
        .await
        .expect("A's connector answers");
    assert!(
        matches!(filed, BundleOffered::Queued { h: queued_h, .. } if queued_h == h),
        "A's queue admits its own bundle: {filed:?}"
    );
    let arrived = b.wait(LIMIT, |node| queued(node).contains(&h)).await;
    assert!(arrived, "B's queue never held the bundle A filed");

    let naming = SectionRoot::from_bytes(
        section_root(std::slice::from_ref(&reference)).expect("one reference is a section"),
    );
    let empty = SectionRoot::from_bytes(empty_section_root());
    let mut tip = h;
    let mut mined = 0;
    loop {
        let job = job_after(&a, tip).await;
        let root = job.block.header.section_root;
        assert!(
            root == naming || root == empty,
            "the job at {} names a section of something else",
            job.height.to_raw()
        );
        tip = connect_local(&a, job.block.serialize()).await;
        assert_eq!(tip, job.height, "A connects its own job");
        mined += 1;
        let count = tip.to_raw() + 1;
        let followed = b.wait(LIMIT, |node| node.count() == count).await;
        assert!(followed, "B's tip never reached height {}", tip.to_raw());
        if root == naming {
            break;
        }
        assert!(
            mined <= EMPTY_JOBS_BEFORE_THE_SECTION,
            "the job after the tip move names no bundle B's queue holds"
        );
    }

    assert_eq!(b.chain.tip(), a.chain.tip(), "B holds A's chain");
    assert!(
        sent(&from_a, NOTIFY_NEW_COMPACT_BLOCK) >= mined,
        "A relayed fewer 2008s than the blocks it mined"
    );
    assert_eq!(
        sent(&from_b, NOTIFY_REQUEST_BUNDLE_BODIES),
        0,
        "B sent a 2016 for a body its store holds"
    );
    assert!(queued(&b).is_empty(), "the block took B's queued bundle");
    assert_eq!(a.closed(a_id), None, "the relay closed no session");
    assert_eq!(b.closed(b_id), None, "the relay closed no session");

    a.stop().await;
    b.stop().await;
}
