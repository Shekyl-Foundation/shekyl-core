// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `produce` step: the bundle producer's own task, over the forge's
//! chain, reading a persona that serves its shard on the production serve
//! loop over loopback (`CHAIN_FORGE.md` §4, the producer audit).
//!
//! The audit classes every input a produced bundle depends on besides chain
//! state. Here each class is held as it says:
//!
//! - **drawn**: the ring's witness keys and draw seeds and each bundle's
//!   witness signature ([`PlanRing`], through `WitnessRing::drawing`), the
//!   serving persona's receipts ([`PlanReceipts`], its `PassKey`), and the
//!   task's read plans and start delays (`run_drawing`, over a ChaCha20
//!   stream from the plan's seed). A live run ([`Producing::live`]) draws
//!   every one from the OS, through the very same seams: `WitnessRing::new`
//!   and `run`, as a node runs them.
//! - **driver**: the tip each read runs under and the block that admits a
//!   bundle. The chain advances only once the producer reports it has acted
//!   on the tip and has no read in flight ([`Producing::settle`]), so every
//!   read's anchor is the tip the plan put there, and a filed bundle is
//!   carried by the next block the plan mines, whatever the start delays.
//! - **environment**: the persona is the pair's one holder, so the fetch
//!   scheduler has nothing to choose; a read that ended stall-class is
//!   recorded, and the forging is refused if there is one.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::SeedableRng as _;
use shekyl_archival_fetch_sched::{FetchScheduler, ReadFailure};
use shekyl_archival_retention::BUNDLE_SIGNATURE_LEN;
use shekyl_bundle_producer::{RingDraws, WitnessRing};
use shekyl_chain_forge::Role;
use shekyl_chain_ingest::bundle_producer::{
    run, run_drawing, ProducerParts, ProducerProgress, ProducerSeat, ReadFn,
};
use shekyl_chain_ingest::connector::{TipChanged, WatchTip, FILED_FEED_CAPACITY};
use shekyl_chain_ingest::scenario::{FreeHash, Scenario};
use shekyl_chain_ingest::schedule::ChainRules;
use shekyl_chain_ingest::shard_facts::{StoreHolderSource, StoreShardFacts};
use shekyl_crypto_pq::fn_dsa_hybrid::{
    FnDsaHybridSecretKey, FnDsaHybridSignature, HybridEd25519FnDsa,
};
use shekyl_crypto_pq::signature::{
    SignatureScheme as _, SCHEME_DOMAIN_RECEIPT, SCHEME_DOMAIN_WITNESS_BUNDLE,
};
use shekyl_crypto_pq::CryptoError;
use shekyl_network::envelope::Framed64;
use shekyl_p_host::{PassKey, PassTranscript, SignRefused};
use shekyl_p_loopback::Timeouts;
use shekyl_types::BlockHeight;
use tokio::sync::watch;

use crate::executor::seeds::{Seeds, Source};

/// How long one block's reads and filing may take on a loaded host.
pub const SETTLE: Duration = Duration::from_secs(120);

/// The loopback client's timeouts: generous, so a loaded host's read
/// completes rather than stalls (a stall refuses the forging).
#[must_use]
pub fn timeouts() -> Timeouts {
    Timeouts {
        dial: Duration::from_secs(5),
        head: Duration::from_secs(30),
        body_stall: Duration::from_secs(30),
        body_total: Duration::from_secs(120),
    }
}

/// The ring's draws from the plan: a template's witness (S7) and a bundle's
/// witness signature (S8), keyed by the template's height.
pub struct PlanRing(pub Arc<Seeds>);

impl RingDraws for PlanRing {
    fn witness(&self, connecting: BlockHeight) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let h = connecting.to_raw();
        (
            self.0.pick(Source::S7, Role::RingKey, 2 * h),
            self.0.pick(Source::S7, Role::RingKey, 2 * h + 1),
            self.0.pick(Source::S7, Role::RingSeed, h),
        )
    }

    fn sign_bundle(
        &self,
        h: BlockHeight,
        secret: &FnDsaHybridSecretKey,
        commitment: &Framed64,
    ) -> Result<[u8; BUNDLE_SIGNATURE_LEN], CryptoError> {
        let seed = self.0.pick(Source::S8, Role::RingSignature, h.to_raw());
        HybridEd25519FnDsa
            .sign_with_rng_seed(
                secret,
                SCHEME_DOMAIN_WITNESS_BUNDLE,
                commitment.as_bytes(),
                &seed,
            )?
            .to_canonical_bytes()
            .try_into()
            .map_err(|_| {
                CryptoError::SerializationError(
                    "a scheme-3 signature is not the canonical width".into(),
                )
            })
    }
}

/// The serving persona's receipt key: its own receipt secret, signing each
/// transcript with randomness from the plan (S8), keyed by the transcript,
/// or, on a live run, from the OS as the stake actor's held key does.
pub struct PlanReceipts {
    secret: FnDsaHybridSecretKey,
    seeds: Option<Arc<Seeds>>,
}

impl PlanReceipts {
    /// `secret`'s receipts: from the plan's seeds, or the OS when `None`.
    #[must_use]
    pub const fn new(secret: FnDsaHybridSecretKey, seeds: Option<Arc<Seeds>>) -> Self {
        Self { secret, seeds }
    }
}

impl PassKey for PlanReceipts {
    fn ready(&self, _shard_id: u64, _anchor_height: BlockHeight) -> Result<(), SignRefused> {
        Ok(())
    }

    fn sign_pass(&self, transcript: &PassTranscript) -> Result<FnDsaHybridSignature, SignRefused> {
        let message = transcript.message();
        let signed = match &self.seeds {
            Some(seeds) => {
                // The transcript names the read (its nonce, anchor and
                // shard), so its hash keys the receipt's draw.
                let digest = shekyl_chain_forge::sha256_hex(&message);
                let index = u64::from_str_radix(&digest[..16], 16).expect("hex");
                let seed = seeds.pick(Source::S8, Role::ProducerReceipt, index);
                HybridEd25519FnDsa.sign_with_rng_seed(
                    &self.secret,
                    SCHEME_DOMAIN_RECEIPT,
                    &message,
                    &seed,
                )
            }
            None => HybridEd25519FnDsa.sign(&self.secret, SCHEME_DOMAIN_RECEIPT, &message),
        };
        signed.map_err(|error| SignRefused::new(error.to_string()))
    }
}

/// A read that did not pass: which, why, and how it was classified.
#[derive(Debug)]
pub struct Ended {
    /// The read.
    pub key: shekyl_bundle_producer::ReadKey,
    /// Why it failed.
    pub failure: ReadFailure,
    /// How the producer classified it.
    pub outcome: shekyl_bundle_producer::ReadOutcome,
}

/// The producer's task over a scenario, and what the forge waits on.
pub struct Producing {
    stop: watch::Sender<bool>,
    progress: watch::Receiver<ProducerProgress>,
    tips: watch::Receiver<TipChanged>,
    task: tokio::task::JoinHandle<()>,
    /// Each read that did not pass, in order.
    pub ended: Arc<Mutex<Vec<Ended>>>,
}

/// What a producing run draws from: the plan's seeds, or the OS.
pub enum Draws {
    /// The plan's: the ring's, the receipts' and the task's, from `seeds`.
    Plan(Arc<Seeds>),
    /// The OS's, through the same seams a node runs.
    Live,
}

impl Producing {
    /// The ring this run's templates draw from.
    #[must_use]
    pub fn ring(draws: &Draws, network: shekyl_network::NetworkId) -> Arc<WitnessRing> {
        Arc::new(match draws {
            Draws::Plan(seeds) => {
                WitnessRing::drawing(network, Arc::new(PlanRing(Arc::clone(seeds))))
            }
            Draws::Live => WitnessRing::new(network),
        })
    }

    /// Start the producer's task over `scenario`, reading through a fetch
    /// scheduler over the store's facts and `client`, its ring `ring`.
    pub async fn start(
        scenario: &Scenario<FreeHash>,
        rules: ChainRules,
        ring: &Arc<WitnessRing>,
        client: shekyl_p_loopback::PFetchClient,
        draws: &Draws,
        start_spread: Duration,
    ) -> Self {
        let store = scenario.store();
        let scheduler = Arc::new(FetchScheduler::new(
            Arc::new(StoreShardFacts::new(Arc::clone(&store))),
            Arc::new(StoreHolderSource::new(Arc::clone(&store))),
            client,
        ));
        let ended = Arc::new(Mutex::new(Vec::new()));
        let ended_by_reads = Arc::clone(&ended);
        let read: ReadFn = Arc::new(move |due| {
            let scheduler = Arc::clone(&scheduler);
            let ended = Arc::clone(&ended_by_reads);
            Box::pin(async move {
                let key = due.key;
                match shekyl_bundle_producer::read::attempt_due(&scheduler, &due).await {
                    Ok(record) => shekyl_bundle_producer::ReadOutcome::Pass(Box::new(record)),
                    Err(failure) => {
                        let outcome = shekyl_bundle_producer::read::classify(&failure);
                        ended.lock().expect("the outcome list").push(Ended {
                            key,
                            failure,
                            outcome: outcome.clone(),
                        });
                        outcome
                    }
                }
            })
        });
        let seat = ProducerSeat {
            witness: Arc::clone(ring),
            read,
            start_spread,
        };
        let parts = ProducerParts {
            connector: scenario.connector().clone(),
            filed: tokio::sync::broadcast::Sender::new(FILED_FEED_CAPACITY),
            store,
            rules,
        };
        let tips = parts.connector.ask(WatchTip).await.expect("the tip watch");
        let watched = parts.connector.ask(WatchTip).await.expect("the tip watch");
        let (stop, stop_rx) = watch::channel(false);
        let (progress_tx, progress) = watch::channel(ProducerProgress::default());
        let task = match draws {
            Draws::Plan(seeds) => {
                let rng = rand_chacha::ChaCha20Rng::from_seed(seeds.key(Role::ProducerReads, 0));
                tokio::spawn(run_drawing(
                    parts,
                    tips,
                    stop_rx,
                    seat,
                    progress_tx,
                    Box::new(rng),
                ))
            }
            Draws::Live => tokio::spawn(run(parts, tips, stop_rx, seat, progress_tx)),
        };
        Self {
            stop,
            progress,
            tips: watched,
            task,
            ended,
        }
    }

    /// Wait until the producer has acted on the latest tip and has no read
    /// in flight: its filing for that tip, if any, is in the queue.
    pub async fn settle(&mut self) {
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

    /// Stop the task and join it.
    pub async fn stop(self) {
        let _sent = self.stop.send(true);
        self.task.await.expect("the producer's task joins");
    }
}
