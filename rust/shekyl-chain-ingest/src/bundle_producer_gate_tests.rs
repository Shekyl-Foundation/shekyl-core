// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The 4b gate (`ARCHIVAL_SETTLEMENT_WRITER.md` §16; round 0, F2): a bundle
//! this daemon's producer made is admitted by 4a's verifier on a driven
//! chain, and connects.
//!
//! One chain, in the live lane, because a compact bond needs a closed,
//! final and priced shard (CEN-J15) and that is a few hundred real spends:
//!
//! 1. Shard 0 fills and closes, and persona P joins it compactly. The next
//!    epoch's drawable set is P's one pair.
//! 2. From then on every block's template draws its `0x0C` from the witness
//!    ring, and the producer's own task ([`run`]) runs over the scenario's
//!    connector and store. It reads through the daemon's fetch scheduler,
//!    over the store's facts ([`StoreShardFacts`]), to P serving shard 0's
//!    real bytes behind the loopback shim, signing with the staged
//!    `ResidentReceiptKey` — the capability the cutover selects (4b).
//! 3. Each block with draws: the producer reads, files, and the queue
//!    admits the bundle; the next block takes every queued bundle through
//!    4a's door (`connect_admitting`, [`Scenario::mine_admitting`]). Every
//!    draw names P's pair and passed; the index rows carry the passed bits;
//!    the epoch's settlement credits P as served.
//! 4. Along the way: a restart mid-window reconciles the queue and the
//!    entry survives it; a reorg pops the admitting tip and the entry is
//!    judged again and re-queued at the new tip; an entry left untaken
//!    leaves when its window closes.
//! 5. The live path: P serving with an identity key. The producer files a
//!    bundle with no passes, and the queue admits it.
//!
//! Red edits, each of which turns this test red: P signing its receipts
//! with the identity key (every read is the serving side's scheme, and
//! the passed bits are clear); `challenge_nonce` without the attempt byte
//! on the producer's side (the receipt is over another nonce than
//! admission recomputes: J37 at the queue); a template commitment drawn
//! outside the ring (no block is claimed, and no bundle is filed).
//!
//! Live lane: `cargo test -p shekyl-chain-ingest -- --ignored
//! a_produced_bundle_is_admitted`.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use shekyl_archival_fetch_sched::{FetchScheduler, NeedBudget, ShardFacts, ShardStanding};
use shekyl_bundle_producer::WitnessRing;
use shekyl_chain_rules::{Claimable, EpochFloor, FakechainSchedule, Settling};
use shekyl_p_host::DaemonTipCache;
use shekyl_p_loopback::{endpoint_and_client, PFetchClient, PServeEndpoint, Timeouts};
use shekyl_types::archival::{SettlementEpochBlocks, SettlementOutcome};
use shekyl_types::{BlockCount, BlockHeight, ChainCount, SettlementEpoch, ShardId};
use shekyl_wire::shard_frame::{encode_frame, FrameTx};
use shekyl_wire::Ct;
use tokio::sync::watch;

use crate::archival_driver::{first_spending_height, ENDPOINT, FEE};
use crate::bundle_producer::{read_through, run, ProducerParts, ProducerProgress, ProducerSeat};
use crate::connector::{TipChanged, WatchTip};
use crate::scenario::{FreeHash, Mined, Scenario};
use crate::scenario_archival::{shard_set, Persona};
use crate::scenario_shard::{close_shards, first_admissible_compact_join, mine_to};
use crate::schedule::ChainRules;
use crate::shard_facts::{StoreHolderSource, StoreShardFacts};
use shekyl_harness_spender::Spender;

/// An epoch long enough for a response window that holds a read and a
/// filing: `W₂ = SEB / 20 = 60`, so reads fall in `(h, h + 30]`.
const EPOCH_BLOCKS: u64 = 1_200;
/// The levered chains' cap: inside the epoch, as the schedule requires.
const REORG_CAP_BLOCKS: u64 = 10;
/// `W₂` under [`EPOCH_BLOCKS`].
const W2: u64 = EPOCH_BLOCKS / 20;
/// P's slot. No other scenario persona uses it on this chain.
const SLOT: u32 = 12;
/// The first coinbase the fill spends. Coinbase 0 funds the join.
const FILL_FROM_COINBASE: u64 = 10;
/// How long one block's reads and filing may take on a loaded host.
const SETTLE: Duration = Duration::from_secs(120);

fn rules() -> ChainRules {
    ChainRules::Regtest {
        fixed_difficulty: Some(std::num::NonZeroU128::MIN),
        schedule: FakechainSchedule::new(
            SettlementEpochBlocks::new(EPOCH_BLOCKS).expect("non-zero"),
            BlockCount::from_raw(REORG_CAP_BLOCKS),
        )
        .expect("the cap sits inside the epoch and the window under the anchor depth"),
    }
}

fn timeouts() -> Timeouts {
    Timeouts {
        dial: Duration::from_secs(2),
        head: Duration::from_secs(10),
        body_stall: Duration::from_secs(10),
        body_total: Duration::from_secs(60),
    }
}

fn tip_of(chain: &[Mined]) -> BlockHeight {
    chain.last().expect("a mined chain").height
}

/// Shard `shard`'s body as P serves it: the closed shard's transactions,
/// in chain order, as one `shard_frame` over their two archival segments.
fn shard_body(scenario: &Scenario<FreeHash>, chain: &[Mined], shard: ShardId) -> Arc<[u8]> {
    let facts = StoreShardFacts::new(scenario.store());
    let ShardStanding::Closed(closed) = facts.shard(shard).expect("the facts read") else {
        panic!("shard {shard:?} is closed");
    };
    let mut segments = Vec::new();
    for row in closed.expected.txs() {
        let tx = chain
            .iter()
            .flat_map(|mined| mined.template.transactions.iter())
            .find(|tx| tx.txid_parts().hash == row.hash)
            .expect("every transaction of the shard was mined here");
        let Ct::Fcmp { pqc_auths, .. } = &tx.ct else {
            panic!("a fill transaction is an FCMP++ spend");
        };
        segments.push((
            u64::try_from(pqc_auths.len()).expect("fits"),
            tx.write_segments().expect("segments"),
        ));
    }
    let frame: Vec<FrameTx<'_>> = segments
        .iter()
        .map(|(count, segments)| FrameTx {
            pqc_auth_count: *count,
            pqc_auths: &segments.pqc_auths,
            prunable: &segments.prunable,
        })
        .collect();
    Arc::from(encode_frame(&frame))
}

/// P, serving `body` at `shard` behind the loopback shim, with its own
/// height read from `tip`, and the one client aimed at it (the client is
/// one per process by design: its in-flight cap is the Tor instance's).
/// `receipts` picks the staged receipt capability or, for the live path,
/// an identity key.
struct Serving {
    _endpoint: PServeEndpoint,
    _holder: Option<shekyl_engine_core::__test_helpers::ReceiptKeyHolder>,
}

async fn serve(
    shard: ShardId,
    body: Arc<[u8]>,
    tip: &Arc<DaemonTipCache>,
    receipts: bool,
) -> (Serving, PFetchClient) {
    if receipts {
        let (holder, key) = shekyl_engine_core::__test_helpers::resident_receipt_key(
            shekyl_harness_spender::Persona::at(SLOT).into_keys(),
            SLOT,
        );
        let signer = shekyl_p_host::signer_over_tip(Arc::clone(tip), key);
        let (endpoint, client) =
            endpoint_and_client(shard.to_raw(), body, signer, timeouts()).await;
        (
            Serving {
                _endpoint: endpoint,
                _holder: Some(holder),
            },
            client,
        )
    } else {
        let key = Arc::new(shekyl_p_serve::TestKeySigner::ephemeral(BlockHeight::ZERO));
        let signer = shekyl_p_host::signer_over_tip(
            Arc::clone(tip),
            key as Arc<dyn shekyl_p_host::PassKey<{ shekyl_p_host::IDENTITY_ENVELOPE_LEN }>>,
        );
        let (endpoint, client) =
            endpoint_and_client(shard.to_raw(), body, signer, timeouts()).await;
        (
            Serving {
                _endpoint: endpoint,
                _holder: None,
            },
            client,
        )
    }
}

/// The producer's task over the scenario, and what the test waits on.
struct Producing {
    stop: watch::Sender<bool>,
    progress: watch::Receiver<ProducerProgress>,
    tips: watch::Receiver<TipChanged>,
    task: tokio::task::JoinHandle<()>,
}

async fn start(
    scenario: &Scenario<FreeHash>,
    ring: &Arc<WitnessRing>,
    client: PFetchClient,
) -> Producing {
    let store = scenario.store();
    let scheduler = Arc::new(FetchScheduler::new(
        Arc::new(StoreShardFacts::new(Arc::clone(&store))),
        Arc::new(StoreHolderSource::new(Arc::clone(&store))),
        client,
    ));
    let seat = ProducerSeat {
        witness: Arc::clone(ring),
        read: read_through(scheduler, NeedBudget::DEFAULT),
    };
    let parts = ProducerParts {
        connector: scenario.connector().clone(),
        store,
        rules: rules(),
    };
    let tips = parts.connector.ask(WatchTip).await.expect("the tip watch");
    let watched = parts.connector.ask(WatchTip).await.expect("the tip watch");
    let (stop, stop_rx) = watch::channel(false);
    let (progress_tx, progress) = watch::channel(ProducerProgress::default());
    let task = tokio::spawn(run(parts, tips, stop_rx, seat, progress_tx));
    Producing {
        stop,
        progress,
        tips: watched,
        task,
    }
}

impl Producing {
    /// Wait until the producer has acted on the latest tip and has no read
    /// in flight: its filing for that tip, if any, is in the queue.
    async fn settle(&mut self) {
        let seq = self.tips.borrow().seq;
        tokio::time::timeout(
            SETTLE,
            self.progress
                .wait_for(|now| now.acted_on >= seq && now.reading == 0),
        )
        .await
        .expect("the producer settles within the bound")
        .expect("the producer's progress watch is open");
    }

    async fn stop(self) {
        let _sent = self.stop.send(true);
        self.task.await.expect("the producer's task joins");
    }
}

fn queued(scenario: &Scenario<FreeHash>) -> Vec<shekyl_chain_store::store::QueueEntry> {
    scenario
        .store()
        .begin_read()
        .expect("snapshot")
        .queued_bundles()
        .expect("the queue reads")
}

/// One more block, then the producer's turn. With bundles queued, the
/// block takes them through 4a's door; the verdicts come back.
async fn step(
    scenario: &mut Scenario<FreeHash>,
    chain: &mut Vec<Mined>,
    producing: &mut Producing,
    p_tip: &Arc<DaemonTipCache>,
    take: bool,
) -> Vec<shekyl_chain_rules::Admitted> {
    let admitted = if take && !queued(scenario).is_empty() {
        let (mined, admitted) = scenario
            .mine_admitting(Vec::new())
            .await
            .unwrap_or_else(|outcome| panic!("the block lands: {outcome}"));
        chain.push(mined);
        admitted
    } else {
        chain.push(
            scenario
                .mine_listing(Vec::new())
                .await
                .unwrap_or_else(|outcome| panic!("the block lands: {outcome}")),
        );
        Vec::new()
    };
    p_tip.stamp_synced(tip_of(chain));
    producing.settle().await;
    admitted
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "fills a shard with real proofs and mines three long epochs; minutes. Live lane: cargo test -p shekyl-chain-ingest -- --ignored a_produced_bundle_is_admitted"]
async fn a_produced_bundle_is_admitted_and_connects_through_the_staged_door() {
    let rules = rules();
    let schedule = rules.in_force(BlockHeight::ZERO).settlement_schedule();
    let mut scenario = Scenario::open_under("bundle-producer-gate", FreeHash, rules);
    let mut chain = scenario
        .mine(ChainCount::from_next_height(first_spending_height()).to_raw())
        .await;

    // 1. Shard 0 closes; P joins it.
    let filled = close_shards(&mut scenario, &mut chain, FILL_FROM_COINBASE, 1).await;
    let close = filled.closed[0];
    let shard = close.shard;
    let admissible = first_admissible_compact_join(&rules, close);
    mine_to(&mut scenario, &mut chain, admissible).await;
    let persona = Persona::at(SLOT);
    let joining = Spender::over(&chain).spend_coinbase_posting(
        scenario.wallet(),
        BlockHeight::ZERO,
        admissible,
        FEE,
        Some(&persona.join(shard_set(vec![shard.to_raw()]), ENDPOINT)),
    );
    let join = scenario
        .mine_listing(vec![joining])
        .await
        .unwrap_or_else(|outcome| panic!("the join connects: {outcome}"));
    let join_epoch = schedule.epoch_at(join.height);
    chain.push(join);
    let epoch = SettlementEpoch::from_raw(join_epoch.to_raw() + 1);

    // 2. The ring, P serving, the producer.
    let ring = Arc::new(WitnessRing::new());
    scenario.draw_from(Arc::clone(&ring));
    let p_tip = Arc::new(DaemonTipCache::new(Duration::from_secs(24 * 60 * 60)));
    p_tip.stamp_synced(tip_of(&chain));
    let body = shard_body(&scenario, &chain, shard);
    let (mut serving, client) = serve(shard, Arc::clone(&body), &p_tip, true).await;
    let mut producing = start(&scenario, &ring, client).await;

    // 3 and 4. Mine through the epoch and past its settlement.
    let settled_at = BlockHeight::from_raw(schedule.slash_deadline_height(epoch.to_raw()));
    let mut admitted_heights = BTreeSet::new();
    let mut restarted = false;
    let mut reorged = false;
    let mut ring = ring;
    while tip_of(&chain) < settled_at {
        let entries = queued(&scenario);
        if let Some(entry) = entries.first() {
            if !restarted {
                // A restart mid-window: the producer stops, the connector
                // reopens over the file and reconciles the queue, and the
                // entry is still there for the next block to take.
                restarted = true;
                let h = entry.h;
                producing.stop().await;
                scenario.reopen(|_| {}).await;
                assert_eq!(
                    queued(&scenario).iter().map(|e| e.h).collect::<Vec<_>>(),
                    vec![h],
                    "the queue survives a restart, reconciled"
                );
                // A restart's ring is empty: a fresh one, as a new process.
                ring = Arc::new(WitnessRing::new());
                scenario.draw_from(Arc::clone(&ring));
                let (restarted_serving, client) =
                    serve(shard, Arc::clone(&body), &p_tip, true).await;
                serving = restarted_serving;
                producing = start(&scenario, &ring, client).await;
            } else if !reorged && entry.queued.tip_height == tip_of(&chain) {
                // A reorg pops the tip the entry was admitted against; the
                // queue judges it again, and it stays, at the new tip.
                reorged = true;
                let h = entry.h;
                let popped = tip_of(&chain);
                let to = BlockHeight::from_raw(popped.to_raw() - 1);
                scenario.rewind_to(to).await.expect("the rewind lands");
                chain.truncate(usize::try_from(popped.to_raw()).expect("fits"));
                p_tip.stamp_synced(to);
                producing.settle().await;
                let after = queued(&scenario);
                let again = after.iter().find(|e| e.h == h).expect("re-judged and kept");
                assert_eq!(again.queued.tip_height, to, "re-queued at the new tip");
            }
        }
        let admitted = step(&mut scenario, &mut chain, &mut producing, &p_tip, true).await;
        for bundle in admitted {
            assert!(!bundle.draws.is_empty(), "a filed block issued draws");
            for draw in &bundle.draws {
                assert_eq!(draw.pair.persona, persona.id(), "the drawn pair is P's");
                assert_eq!(draw.pair.shard, shard);
                assert!(draw.passed, "P served the read: the draw passed");
            }
            admitted_heights.insert(bundle.kept.h);
        }
    }
    assert!(
        restarted && reorged,
        "the chain took the restart and the reorg"
    );

    // The index carries every admitted draw's passed bit, and the epoch's
    // settlement credits P as served.
    let store = scenario.store();
    let snap = store.begin_read().expect("snapshot");
    let rows = snap
        .issued_draws(
            epoch,
            EpochFloor::<Settling>::under(tip_of(&chain), schedule),
        )
        .expect("the index reads");
    let ours: Vec<_> = rows
        .iter()
        .filter(|row| row.persona == persona.id() && row.shard == shard)
        .collect();
    assert!(
        ours.len() >= 3,
        "three counted draws were issued: {}",
        ours.len()
    );
    assert!(ours.iter().all(|row| row.state.passed), "{ours:?}");
    assert!(ours
        .iter()
        .all(|row| admitted_heights.contains(&row.issuing_height)));
    let settled = snap
        .settlement_row(
            &persona.id(),
            shard,
            epoch,
            EpochFloor::<Claimable>::under(tip_of(&chain), schedule),
        )
        .expect("the settlement reads")
        .expect("the epoch settled P's pair");
    assert_eq!(settled.outcome(), SettlementOutcome::Served);
    drop(snap);
    drop(store);

    // 5. The live path: P signs with an identity key. The producer files a
    // bundle with no passes, and the queue admits it. Left untaken, the
    // entry leaves when its window closes.
    producing.stop().await;
    drop(serving);
    let (_identity, client) = serve(shard, body, &p_tip, false).await;
    let mut producing = start(&scenario, &ring, client).await;
    let mut no_pass = None;
    for _ in 0..(2 * EPOCH_BLOCKS) {
        step(&mut scenario, &mut chain, &mut producing, &p_tip, false).await;
        if let Some(entry) = queued(&scenario).first() {
            no_pass = Some((entry.h, entry.queued.reference.clone()));
            break;
        }
    }
    let (h, reference) =
        no_pass.expect("a block with draws filed while P signed with an identity key");
    assert!(reference.count() > 0);
    assert_eq!(reference.passes().popcount(), 0, "no read was a receipt");
    while tip_of(&chain) < h.saturating_add(BlockCount::from_raw(W2)) {
        step(&mut scenario, &mut chain, &mut producing, &p_tip, false).await;
    }
    assert!(
        queued(&scenario).iter().all(|e| e.h != h),
        "the entry for {h} left with its window"
    );
    producing.stop().await;
    scenario.close().await;
}
