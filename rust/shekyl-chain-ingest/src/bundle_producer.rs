// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The bundle producer's task (`SO-D12` increment 4c;
//! `ARCHIVAL_SETTLEMENT_WRITER.md` §16).
//!
//! [`shekyl_bundle_producer::Producer`] is the state machine; this is what
//! drives it in the node. It wakes on every tip the connector publishes
//! (the signal the drawable memo is filled on) and on every read that
//! ends, and on each wake:
//!
//! 1. reads the recorded blocks near the tip and has the producer claim
//!    the ones this daemon mined, pause the popped ones and give up on the
//!    lost ones;
//! 2. asks the connector for each newly claimed block's draws
//!    ([`LearnDraws`]), which it derives where `D` is;
//! 3. starts every read whose height has come, each through the one fetch
//!    path ([`ProducerSeat::read`]), and feeds each outcome back;
//! 4. offers every block that is ready to the queue ([`OfferBundle`]).
//!
//! Only a mining daemon is a witness, so only a node with a job seat runs
//! this, and only a node with a fetch path to read through.
//!
//! # What is logged
//!
//! A filing, with its height, draws and passes; once per block, "no
//! receipt scheme on the serving side yet" when a read met the identity
//! scheme (the live serving host until 4b); a refusal of this daemon's own
//! bundle, which is a producer defect, with its row; each block lost; and
//! at stop, one line per block in flight, whose draws expire in flight
//! because the ring is memory only. Never a seed, a nonce or a key
//! (`scripts/ci/check_bundle_producer_secrets.py`).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use shekyl_archival_fetch_sched::{FetchScheduler, HolderSource, NeedBudget, ShardFacts};
use shekyl_bundle_producer::{
    DueRead, Filing, Lost, Producer, ReadKey, ReadOutcome, Recorded, Window, WitnessRing,
};
use shekyl_chain_store::store::ReadSnapshot;
use shekyl_types::{BlockCount, BlockHeight};
use shekyl_wire::tx_extra::TxExtraField;
use tokio::sync::{mpsc, watch};

use crate::connector::{BundleOffered, Connector, LearnDraws, Learned, OfferBundle, TipChanged};
use crate::schedule::ChainRules;

/// One read through the daemon's fetch path: the due read in, its outcome
/// out. Built over the node's fetch scheduler by [`read_through`].
pub type ReadFn =
    Arc<dyn Fn(DueRead) -> Pin<Box<dyn Future<Output = ReadOutcome> + Send>> + Send + Sync>;

/// What the task drives the producer with: the single writer, the store
/// it writes (read here through snapshots only), and the rules in force.
#[derive(Clone)]
pub struct ProducerParts {
    /// The connector: the draws and the queue's admission.
    pub connector: kameo::actor::ActorRef<Connector>,
    /// The store, read for the blocks near the tip.
    pub store: Arc<shekyl_chain_store::store::ChainStore>,
    /// The rules by height.
    pub rules: ChainRules,
}

/// What the task has done: the last tip publication it acted on, and how
/// many reads it has in flight. What a caller waits on to know the
/// producer is done with a tip, as the follower's `followed` is for the
/// job.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProducerProgress {
    /// The `TipChanged` sequence number of the last wake that ran.
    pub acted_on: u64,
    /// Reads started and not yet ended.
    pub reading: usize,
}

/// What a node that produces bundles hands the service.
pub struct ProducerSeat {
    /// The ring the node's templates draw from: the job seat's own.
    pub witness: Arc<WitnessRing>,
    /// The challenge read.
    pub read: ReadFn,
}

/// The read through `scheduler`, with `budget` per read: the scheduler's
/// nonce read over a receipt-key holder (`shekyl_bundle_producer::read`).
#[must_use]
pub fn read_through<F, H>(scheduler: Arc<FetchScheduler<F, H>>, budget: NeedBudget) -> ReadFn
where
    F: ShardFacts + Send + Sync + 'static,
    H: HolderSource + Send + Sync + 'static,
{
    Arc::new(move |due: DueRead| {
        let scheduler = Arc::clone(&scheduler);
        Box::pin(
            async move { shekyl_bundle_producer::read::read_due(&scheduler, &due, budget).await },
        )
    })
}

/// The block at `h` as the producer reads it: its hash and its one `0x0C`.
/// A block whose extra does not yield exactly one commitment is not one
/// of this daemon's templates, and reads as absent here.
pub(crate) fn recorded_at(snap: &ReadSnapshot<'_>, h: BlockHeight) -> Option<Recorded> {
    let shekyl_chain_rules::AtHeight::Recorded(body) = snap.block(h).ok()? else {
        return None;
    };
    let fields = body.block.miner_transaction.prefix.parse_extra().ok()?;
    let mut found = None;
    for field in fields {
        if let TxExtraField::DrawCommitment(commitment) = field {
            if found.is_some() {
                return None;
            }
            found = Some(commitment);
        }
    }
    Some(Recorded {
        hash: body.hash,
        commitment: found?,
    })
}

/// Run the producer until `stop` reads true or the tip watch closes
/// (module docs).
pub async fn run(
    parts: ProducerParts,
    mut tips: watch::Receiver<TipChanged>,
    mut stop: watch::Receiver<bool>,
    seat: ProducerSeat,
    progress: watch::Sender<ProducerProgress>,
) {
    use rand::SeedableRng;
    let rng = rand::rngs::StdRng::from_entropy();
    let mut producer = Producer::new(Arc::clone(&seat.witness), Box::new(rng));
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<(ReadKey, ReadOutcome)>();
    let mut scheme_logged = SchemeLine::default();
    tracing::info!("the bundle producer is running: the witness ring starts empty");
    loop {
        // A read that ended leaves the count only once the wake it caused
        // has run: a caller that sees no read in flight sees its filing.
        let mut ended = 0usize;
        tokio::select! {
            changed = tips.changed() => {
                if changed.is_err() {
                    break;
                }
            }
            Some((key, outcome)) = done_rx.recv() => {
                producer.read_done(key, outcome);
                ended = 1;
            }
            _ = stop.wait_for(|stop| *stop) => break,
        }
        if *stop.borrow() {
            break;
        }
        let published = *tips.borrow();
        let Some(tip) = published.tip.and_then(|tip| tip.count.tip()) else {
            progress.send_modify(|now| now.reading = now.reading.saturating_sub(ended));
            continue;
        };
        let window = window_at(parts.rules, tip);
        step(
            &parts,
            &mut producer,
            &seat,
            tip,
            window,
            &done_tx,
            &mut scheme_logged,
            &progress,
        )
        .await;
        progress.send_modify(|now| {
            now.acted_on = published.seq;
            now.reading = now.reading.saturating_sub(ended);
        });
    }
    for (h, draws) in producer.dropped_at_stop() {
        tracing::info!(
            h = h.to_raw(),
            draws,
            "the bundle producer stopped with block {} in flight; its {} draws expire in flight",
            h.to_raw(),
            draws
        );
    }
}

/// The blocks the serving-scheme line was logged for: once per block.
#[derive(Default)]
pub(crate) struct SchemeLine(std::collections::BTreeSet<BlockHeight>);

impl SchemeLine {
    /// Whether `h`'s line is due now: the first filing of `h` that met the
    /// identity scheme. Later offers of the same block log nothing.
    pub(crate) fn due(&mut self, h: BlockHeight, absent: bool) -> bool {
        absent && self.0.insert(h)
    }
}

/// `W₂` and the reorg cap of the rule set the next block connects under.
fn window_at(rules: crate::schedule::ChainRules, tip: BlockHeight) -> Window {
    let rule_set = rules.in_force(tip.saturating_add(BlockCount::ONE));
    Window {
        response: rule_set
            .settlement_schedule()
            .challenge_response_blocks()
            .map_or(BlockCount::ZERO, |w| BlockCount::from_raw(w.get())),
        reorg_cap: rule_set.reorg_cap(),
    }
}

/// One wake (module docs, steps 1–4). Each read is counted in
/// `progress` before it starts, so a read that ends at once cannot be
/// subtracted before it was added.
#[allow(clippy::too_many_arguments)] // the wake's state, passed rather than bundled for one caller
async fn step(
    parts: &ProducerParts,
    producer: &mut Producer,
    seat: &ProducerSeat,
    tip: BlockHeight,
    window: Window,
    done: &mpsc::UnboundedSender<(ReadKey, ReadOutcome)>,
    scheme_logged: &mut SchemeLine,
    progress: &watch::Sender<ProducerProgress>,
) {
    let observed = match parts.store.begin_read() {
        Ok(snap) => producer.observe(tip, window, |h| recorded_at(&snap, h)),
        Err(error) => {
            tracing::warn!("the bundle producer could not read the chain: {error}");
            return;
        }
    };
    for lost in observed.lost {
        let (h, why) = match lost {
            Lost::PoppedPastCap { h } => (h, "popped and not reconnected within the reorg cap"),
            Lost::WindowClosed { h } => (h, "its window closed before it was filed"),
        };
        tracing::info!(
            h = h.to_raw(),
            "the bundle producer lost block {}: {why}",
            h.to_raw()
        );
    }
    for learn in observed.learn {
        let h = learn.h;
        let asked = parts
            .connector
            .ask(LearnDraws {
                h,
                hash: learn.hash,
                seed: learn.seed,
            })
            .await;
        match asked {
            Ok(Learned::Targets(targets)) => producer.learned(h, window, targets),
            Ok(Learned::NotOnChain) => {}
            Ok(Learned::Unanswered(why)) => {
                tracing::debug!(
                    h = h.to_raw(),
                    "the draws of block {} are not answered yet: {why}",
                    h.to_raw()
                );
            }
            Err(error) => {
                tracing::warn!(
                    h = h.to_raw(),
                    "the connector did not derive block {}'s draws: {error}",
                    h.to_raw()
                );
            }
        }
    }
    for due in producer.due(tip) {
        progress.send_modify(|now| now.reading += 1);
        let read = Arc::clone(&seat.read);
        let done = done.clone();
        tokio::spawn(async move {
            let key = due.key;
            let outcome = read(due).await;
            drop(done.send((key, outcome)));
        });
    }
    let (filings, failed) = producer.ready(tip, window);
    for (h, error) in failed {
        tracing::error!(
            h = h.to_raw(),
            "the bundle for block {} could not be signed: {error}",
            h.to_raw()
        );
    }
    for filing in filings {
        offer(parts, filing, scheme_logged).await;
    }
}

async fn offer(parts: &ProducerParts, filing: Filing, scheme_logged: &mut SchemeLine) {
    let Filing {
        h,
        reference,
        body,
        draws,
        passes,
        serving_scheme_absent,
    } = filing;
    if scheme_logged.due(h, serving_scheme_absent) {
        tracing::info!(
            h = h.to_raw(),
            "block {}: no receipt scheme on the serving side yet; filed with no passes",
            h.to_raw()
        );
    }
    let offered = parts.connector.ask(OfferBundle { reference, body }).await;
    match offered {
        Ok(BundleOffered::Queued { tip_height, .. }) => tracing::info!(
            h = h.to_raw(),
            draws,
            passes,
            "filed the bundle for block {} ({passes} of {draws} draws passed), queued at tip {}",
            h.to_raw(),
            tip_height.to_raw()
        ),
        Ok(BundleOffered::AlreadyRevealed { .. }) => tracing::info!(
            h = h.to_raw(),
            "the bundle for block {} was not queued: another bundle for it won",
            h.to_raw()
        ),
        Ok(BundleOffered::AlreadyQueued { .. }) => tracing::warn!(
            h = h.to_raw(),
            "the bundle for block {} was not queued: the queue already holds one",
            h.to_raw()
        ),
        Ok(BundleOffered::Refused { row, why, .. }) => tracing::error!(
            h = h.to_raw(),
            "the queue refused this daemon's bundle for block {} ({}): {why}; a producer defect",
            h.to_raw(),
            row.map_or("no row", |row| row.as_str())
        ),
        Err(error) => tracing::error!(
            h = h.to_raw(),
            "the connector did not take the bundle for block {}: {error}",
            h.to_raw()
        ),
    }
}
