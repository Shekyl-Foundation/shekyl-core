// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The bundle queue on the connector, and the producer's task's own
//! pieces, on a regtest chain (`SO-D12` increment 4c). The whole path, with
//! draws and reads, is `bundle_producer_gate_tests` in the live lane.
//!
//! The queue's bundles here are for blocks that issued no draws: a valid
//! bundle with empty bitmaps (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §7.1), over a
//! `0x0C` the test committed with a key and seed it holds. The rule that
//! admits one is the rule that admits any.
//!
//! Every test names the edit that turns it red.

use std::sync::Arc;

use shekyl_archival_retention::{
    assemble_bundle, draw_commit, sign_bundle_commitment, BundleBody, BundleKept, BundleRef,
    PassBitmap, BUNDLE_WITNESS_KEY_LEN,
};
use shekyl_bundle_producer::{Producer, Window, WitnessRing};
use shekyl_chain_rules::CenRow;
use shekyl_crypto_pq::fn_dsa_hybrid::{FnDsaHybridSecretKey, HybridEd25519FnDsa};
use shekyl_types::archival::DrawCommitment;
use shekyl_types::{BlockCount, BlockHeight};

use crate::bundle_producer::SchemeLine;
use crate::connector::{BundleOffered, LearnDraws, Learned, OfferBundle};
use crate::scenario::{FreeHash, Mined, Scenario, RULES};

/// A witness key and seed the test holds, and the commitment they make.
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

    fn commitment(&self) -> DrawCommitment {
        DrawCommitment::from_bytes(draw_commit(&self.public, &self.seed))
    }

    /// The bundle for `h`, a block that issued no draws, revealing `seed`.
    fn bundle(&self, h: BlockHeight, seed: [u8; 32]) -> (BundleRef, BundleBody) {
        let kept = BundleKept {
            h,
            seed,
            passes: PassBitmap::none(),
            support: PassBitmap::none(),
        };
        assemble_bundle(&kept, &[], &self.public, |commitment| {
            sign_bundle_commitment(&self.secret, commitment)
        })
        .expect("the key signs")
    }
}

fn w2() -> BlockCount {
    let window = RULES
        .in_force(BlockHeight::ZERO)
        .settlement_schedule()
        .challenge_response_blocks()
        .expect("the production schedule has a window");
    BlockCount::from_raw(window.get())
}

/// A chain of `before` blocks, then one committed to `witness`, then one
/// more: the block the bundle is for is at `before`.
async fn committed(name: &str, witness: &Witness, before: u64) -> (Scenario<FreeHash>, Mined) {
    let mut scenario = Scenario::open(name);
    scenario.mine(before).await;
    scenario.commit_next(witness.commitment());
    let ours = scenario
        .mine_listing(Vec::new())
        .await
        .unwrap_or_else(|outcome| panic!("the committed block lands: {outcome}"));
    scenario.mine(1).await;
    (scenario, ours)
}

async fn offer(scenario: &Scenario<FreeHash>, bundle: (BundleRef, BundleBody)) -> BundleOffered {
    scenario
        .connector()
        .ask(OfferBundle {
            reference: bundle.0,
            body: bundle.1,
        })
        .await
        .expect("the connector answers")
}

fn queued(scenario: &Scenario<FreeHash>) -> Vec<shekyl_chain_store::store::QueueEntry> {
    scenario
        .store()
        .begin_read()
        .expect("snapshot")
        .queued_bundles()
        .expect("the queue reads")
}

/// The queue's admission is the bundle rule against the tip: a valid
/// bundle is queued at the tip it was judged against, and a second for its
/// block is not. Red edit: queue without judging — the J33 test below
/// queues its bundle.
#[tokio::test]
async fn an_offered_bundle_is_queued_once() {
    let witness = Witness::new(0x31);
    let (scenario, ours) = committed("bundle-queue-once", &witness, 3).await;
    let tip = BlockHeight::from_raw(ours.height.to_raw() + 1);
    assert_eq!(
        offer(&scenario, witness.bundle(ours.height, witness.seed)).await,
        BundleOffered::Queued {
            h: ours.height,
            tip_height: tip
        }
    );
    let entries = queued(&scenario);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].h, ours.height);
    assert_eq!(entries[0].queued.tip_height, tip);
    assert_eq!(
        offer(&scenario, witness.bundle(ours.height, witness.seed)).await,
        BundleOffered::AlreadyQueued { h: ours.height }
    );
    scenario.close().await;
}

/// A seed that does not open the block's `0x0C` is refused by the rule at
/// J33, and nothing is queued: the queue's admission is the self-check.
/// Red edit: compare the commitment against the wrong block — the bundle
/// is queued.
#[tokio::test]
async fn a_seed_that_does_not_open_the_commitment_is_refused_at_j33() {
    let witness = Witness::new(0x32);
    let (scenario, ours) = committed("bundle-queue-j33", &witness, 3).await;
    let offered = offer(&scenario, witness.bundle(ours.height, [0x77; 32])).await;
    let BundleOffered::Refused { row, .. } = offered else {
        panic!("expected a refusal, got {offered:?}");
    };
    assert_eq!(row, Some(CenRow::J33));
    assert!(queued(&scenario).is_empty());
    scenario.close().await;
}

/// An entry leaves when its window closes: once the next block could no
/// longer include it. Red edit: keep an entry past `h + W₂` — it is still
/// there after the window.
#[tokio::test]
async fn an_entry_leaves_when_its_window_closes() {
    let witness = Witness::new(0x33);
    let (mut scenario, ours) = committed("bundle-queue-window", &witness, 3).await;
    assert!(matches!(
        offer(&scenario, witness.bundle(ours.height, witness.seed)).await,
        BundleOffered::Queued { .. }
    ));
    // The tip is `h + 1`. At tip `h + W₂ − 1` the next block is `h + W₂`,
    // still inside; at tip `h + W₂` it is outside.
    scenario.mine(w2().to_raw() - 2).await;
    assert_eq!(queued(&scenario).len(), 1, "still inside its window");
    scenario.mine(1).await;
    assert!(queued(&scenario).is_empty(), "its window closed");
    scenario.close().await;
}

/// After a reorg pops the tip an entry was admitted against, the queue
/// judges it again by the same rule and keeps it, at the new tip. A pop of
/// the bundle's own block refuses it, and it leaves. Red edit: skip the
/// re-judge — the entry keeps its old tip.
#[tokio::test]
async fn a_reorg_judges_an_entry_again() {
    let witness = Witness::new(0x34);
    let (mut scenario, ours) = committed("bundle-queue-reorg", &witness, 3).await;
    scenario.mine(2).await;
    assert!(matches!(
        offer(&scenario, witness.bundle(ours.height, witness.seed)).await,
        BundleOffered::Queued { .. }
    ));
    let admitted_at = queued(&scenario)[0].queued.tip_height;
    let to = BlockHeight::from_raw(admitted_at.to_raw() - 1);
    scenario.rewind_to(to).await.expect("the rewind lands");
    let entries = queued(&scenario);
    assert_eq!(entries.len(), 1, "judged again and kept");
    assert_eq!(entries[0].queued.tip_height, to);

    // Pop the bundle's block and connect another at its height: the
    // commitment there is not the bundle's, and the rule refuses it.
    scenario
        .rewind_to(BlockHeight::from_raw(ours.height.to_raw() - 1))
        .await
        .expect("the rewind lands");
    assert_eq!(queued(&scenario).len(), 1, "above the tip it waits");
    scenario.mine(2).await;
    assert!(
        queued(&scenario).is_empty(),
        "another block at h refuses it"
    );
    scenario.close().await;
}

/// The queue is reconciled at open and survives a restart. Red edit: keep
/// the queue in the connector's memory — the reopened connector has none.
#[tokio::test]
async fn a_restart_keeps_the_queue() {
    let witness = Witness::new(0x35);
    let (mut scenario, ours) = committed("bundle-queue-restart", &witness, 3).await;
    assert!(matches!(
        offer(&scenario, witness.bundle(ours.height, witness.seed)).await,
        BundleOffered::Queued { .. }
    ));
    scenario.reopen(|_| {}).await;
    assert_eq!(queued(&scenario).len(), 1);
    scenario.close().await;
}

/// The connector derives a mined block's draws where the memo is, and
/// answers a block that is not the one claimed as not on chain. Red edit:
/// skip the hash check — the wrong hash gets targets.
#[tokio::test]
async fn the_connector_learns_a_blocks_draws_only_for_that_block() {
    let witness = Witness::new(0x36);
    let (scenario, ours) = committed("bundle-learn", &witness, 3).await;
    let learned = scenario
        .connector()
        .ask(LearnDraws {
            h: ours.height,
            hash: ours.hash,
            seed: zeroize::Zeroizing::new(witness.seed),
        })
        .await
        .expect("the connector answers");
    let Learned::Targets(targets) = learned else {
        panic!("expected targets, got {learned:?}");
    };
    assert!(
        targets.economy.is_empty() && targets.support.is_empty(),
        "no draws issued"
    );
    let elsewhere = scenario
        .connector()
        .ask(LearnDraws {
            h: ours.height,
            hash: shekyl_types::BlockHash::from_bytes([0xAB; 32]),
            seed: zeroize::Zeroizing::new(witness.seed),
        })
        .await
        .expect("the connector answers");
    assert!(matches!(elsewhere, Learned::NotOnChain));
    scenario.close().await;
}

/// The producer claims the blocks its ring drew and no other, reading the
/// chain the way its task does. Red edit: read the commitment from the
/// wrong field — nothing is claimed.
#[tokio::test]
async fn the_producer_claims_what_its_ring_drew() {
    let mut scenario = Scenario::open("bundle-claim");
    scenario.mine(2).await;
    let ring = Arc::new(WitnessRing::new());
    scenario.draw_from(Arc::clone(&ring));
    let ours = scenario.mine(1).await.remove(0);
    let mut producer = Producer::new(
        Arc::clone(&ring),
        Box::new(<rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(1)),
        shekyl_bundle_producer::read::READS_AT_ONCE,
    );
    let window = Window {
        response: w2(),
        reorg_cap: RULES.in_force(BlockHeight::ZERO).reorg_cap(),
    };
    let store = scenario.store();
    let snap = store.begin_read().expect("snapshot");
    let observed = producer.observe(ours.height, window, |h| {
        crate::bundle_producer::recorded_at(&snap, h)
    });
    assert_eq!(observed.learn.len(), 1);
    assert_eq!(observed.learn[0].h, ours.height);
    assert_eq!(producer.in_flight(), vec![ours.height]);
    drop(snap);
    drop(store);
    scenario.close().await;
}

/// The serving-scheme line is logged once per block. Red edit: log on
/// every offer — the second assertion fails.
#[test]
fn the_serving_scheme_line_is_once_per_block() {
    let mut line = SchemeLine::default();
    let h = BlockHeight::from_raw(7);
    assert!(!line.due(h, false), "a block with receipts logs nothing");
    assert!(line.due(h, true));
    assert!(!line.due(h, true), "once per block");
    assert!(line.due(BlockHeight::from_raw(8), true));
}
