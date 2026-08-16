// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The W₂ rig — the **concurrent-batch** measurement, and the provenance that
//! makes one of its numbers citable.
//!
//! `ARCHIVAL_CHALLENGE_MECHANISM.md` §9.5 puts the rig here rather than in a new
//! crate: it "extends the spike harness to the concurrent-batch shape". What it
//! measures is not what the SP-T3 spike measures. The spike answers a
//! *single-transfer* question (PD-F-2's `D*` inversion); §9.5's concurrency pin
//! says the W₂ unit is different:
//!
//! > **CONCURRENCY, not bandwidth, is the W₂ unit.** The schedule assigns
//! > `λ·D/E` pairs to each block's producer: at maturity ~97 pairs land on one
//! > block at once, so that producer must fetch ~323 MB **concurrently** inside
//! > W₂ … a single-transfer rig under-estimates badly, missing
//! > circuit-establishment throughput, Tor client memory, and guard capacity.
//!
//! # Which side carries the concurrency, because it is easy to get backwards
//!
//! The ~97 concurrent rendezvous circuits are the **witness's** — the producer
//! of block `h`, fetching from many personas at once, "from the same client".
//! They are *not* the serving persona's. A persona's own concurrency is the
//! number of simultaneous readers hitting it, which
//! [`SP_T3_SKELETON_MEASUREMENT.md`] §18 already measured (p50 10.9 s → 14.8 s
//! across 4→32 readers).
//!
//! That distinction decides what runs on the rule-76 floor device. Rule 76
//! provisions *anonymity guarantees for a node*, and the node being protected
//! here is the staker running `P` — so the Pi-4 is the floor for the **serving**
//! side. A producer sustaining 97 concurrent fetches is a mining box, and
//! nothing in rule 76 makes a Pi-4 the floor for mining. A rig that puts 97
//! outbound circuits on the Pi is measuring the wrong machine's problem.
//!
//! # What W₂ needs from this, after the pin
//!
//! W₂ is pinned by ruling, not derived by measurement, so this rig is a **floor
//! check**: does the honest concurrent-batch completion on the floor fit inside
//! the window with room to spare? A pass ends it; a fail raises W₂, which by
//! that ruling costs nothing. So the measurement can only move the constant in
//! the safe direction — which is why the reported statistic is the **batch**
//! completion, not the per-fetch one. The producer must land *every* pair it was
//! assigned inside W₂, so the quantity that matters is the slowest fetch in the
//! batch, not the median of all fetches.
//!
//! [`SP_T3_SKELETON_MEASUREMENT.md`]: ../../../../docs/design/SP_T3_SKELETON_MEASUREMENT.md

use std::time::Duration;

use shekyl_tor::vanguard_rotation::VanguardsActive;

/// Attestation that the tor this run measured had **full vanguards pinned**.
///
/// Mintable only from a [`VanguardsActive`], whose own constructor is private to
/// `shekyl-tor` and runs only after a confirmed `SETCONF` — so this cannot be
/// produced by a run that did not actually pin a set.
///
/// §9.5 requires it, and states the failure mode: full vanguards adds a guard
/// layer and costs "longer paths and higher latency — latency on exactly the
/// path W₂ measures", so a non-vanguards run measures a **shorter path than
/// production ships** and under-estimates *in the failure-causing direction*.
/// The numbers come back looking good. Prose could not stop that; a value you
/// cannot construct without the witness can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VanguardsAttested(());

impl VanguardsAttested {
    /// Take proof-of-possession of a live vanguards witness.
    ///
    /// Borrowed, not consumed: the caller keeps the witness for the run it is
    /// still driving. Nothing is copied out of it — the witness's *existence*
    /// is the whole claim.
    #[must_use]
    pub fn from_witness(_witness: &VanguardsActive) -> Self {
        Self(())
    }
}

/// The device a run executed on, recorded beside the number per rule 76 §1:
/// "Record which machine produced the number, beside the number."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunDevice {
    /// Free-form CPU identification, as read from the host.
    pub cpu: String,
    /// Target architecture the binary was built for.
    pub arch: &'static str,
    /// Whether this host satisfies the rule-76 floor.
    pub at_or_above_floor: bool,
}

impl RunDevice {
    /// Identify the running host.
    ///
    /// The floor is `Raspberry Pi 4 Model B` (Cortex-A72, aarch64). A run on a
    /// *faster* machine is at-or-above the floor and its number is a valid
    /// upper-bound check on capability, but it is **not** a floor datum: rule 76
    /// requires constants derived from work time to be provisioned at the floor,
    /// "not at the machine that happened to be available". Both facts are
    /// recorded so the reader can tell which they are holding.
    #[must_use]
    pub fn detect() -> Self {
        let cpu = std::fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("model name") || l.starts_with("Model"))
                    .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_owned())
            })
            .unwrap_or_else(|| "unknown".to_owned());
        Self {
            arch: std::env::consts::ARCH,
            // Deliberately not a claim this code can settle: "at or above the
            // floor" is a judgement about the whole machine, and the honest
            // machine-readable part is the identification above. `false` here
            // would libel every developer box; `true` would launder one. The
            // run reports what it saw and the reader decides.
            at_or_above_floor: std::env::consts::ARCH == "aarch64",
            cpu,
        }
    }
}

/// Attestation that the run used the **real Tor network**, not a local test net.
///
/// §9.5: "Measure on the **real Tor network**, never a local test net (chutney
/// has none of the latency structure that makes the distribution heavy-tailed)."
/// A chutney run is the third silent failure — it comes back fast and looks
/// like a pass.
///
/// The evidence is the size of the consensus the client bootstrapped against.
/// A real consensus carries thousands of relays; a chutney network carries a
/// handful. This is a *discriminator*, not a proof — someone determined to fake
/// it can — and the doc's requirement is that an incomplete run "yields no datum
/// rather than an unlabelled one", which this satisfies: a run that never read
/// the consensus cannot construct one of these at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveNetworkAttested {
    /// Relays the client saw in the consensus it bootstrapped against.
    pub relays_seen: usize,
}

/// Smallest consensus size accepted as the real network.
///
/// The real network runs in the thousands; chutney defaults to well under
/// twenty. Anything between is neither, and is refused rather than guessed at.
pub const MIN_REAL_CONSENSUS_RELAYS: usize = 500;

impl LiveNetworkAttested {
    /// Accept a consensus reading as evidence of the real network.
    ///
    /// # Errors
    ///
    /// [`ProvenanceError::ConsensusTooSmall`] when the reading is below
    /// [`MIN_REAL_CONSENSUS_RELAYS`] — which is what a chutney run looks like.
    pub fn from_consensus(relays_seen: usize) -> Result<Self, ProvenanceError> {
        if relays_seen < MIN_REAL_CONSENSUS_RELAYS {
            return Err(ProvenanceError::ConsensusTooSmall { relays_seen });
        }
        Ok(Self { relays_seen })
    }
}

/// Why a run could not produce provenance, and therefore produces no datum.
///
/// `Display`/`Error` are hand-written rather than derived: this crate is
/// deliberately disposable (rule 15, labelled at birth), and one enum with one
/// variant does not justify pulling `thiserror` into a dependency graph whose
/// whole point is being deletable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceError {
    /// The consensus was too small to be the real Tor network.
    ConsensusTooSmall {
        /// What the run actually saw.
        relays_seen: usize,
    },
}

impl std::fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConsensusTooSmall { relays_seen } => write!(
                f,
                "consensus carried {relays_seen} relays, below the \
                 {MIN_REAL_CONSENSUS_RELAYS} required to accept this as the real Tor \
                 network; a local test net has none of the latency structure that makes \
                 the W2 distribution heavy-tailed, and its numbers come back looking good"
            ),
        }
    }
}

impl std::error::Error for ProvenanceError {}

/// The three §9.5 requirements as **one indivisible value**.
///
/// This is the §9.7 item-6 requirement, in its own words:
///
/// > The rig's provenance record is a **single type that cannot be constructed
/// > without all three**, and a W₂ datum is a value of that type — so an
/// > incomplete run yields no datum rather than an unlabelled one. Three
/// > separate flags checked at three points is the shape that fails, because it
/// > makes "record the mode" a step someone can skip; one indivisible value is
/// > the shape that holds.
///
/// So there is no `Default`, no public fields, and no constructor that takes
/// fewer than three attestations. The same call
/// [`ServingPosture::Serving`](shekyl_tor::service::ServingPosture) makes by
/// carrying the onion and the vanguards mode as one value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunProvenance {
    vanguards: VanguardsAttested,
    device: RunDevice,
    network: LiveNetworkAttested,
}

impl RunProvenance {
    /// The only constructor. All three or nothing.
    #[must_use]
    pub fn attest(
        vanguards: VanguardsAttested,
        device: RunDevice,
        network: LiveNetworkAttested,
    ) -> Self {
        Self {
            vanguards,
            device,
            network,
        }
    }

    /// The device this run executed on (rule 76 §1's "beside the number").
    #[must_use]
    pub fn device(&self) -> &RunDevice {
        &self.device
    }

    /// The consensus this run bootstrapped against.
    #[must_use]
    pub fn network(&self) -> LiveNetworkAttested {
        self.network
    }

    /// Whether this datum was produced at the rule-76 floor.
    ///
    /// A `false` here does not invalidate the run — it says the number is a
    /// capability check on a faster machine, not a floor provisioning input.
    #[must_use]
    pub fn is_floor_datum(&self) -> bool {
        self.device.at_or_above_floor && self.device.arch == "aarch64"
    }
}

/// One concurrent batch: what a single block's producer faces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchObservation {
    /// Fetches launched together.
    pub launched: usize,
    /// Fetches that returned the full expected body.
    pub completed: usize,
    /// Wall time from launching the first fetch to the **last** completion.
    ///
    /// This is the W₂-relevant statistic and the reason the rig exists: the
    /// producer must land every pair it was assigned inside the window, so the
    /// batch is bounded by its slowest member, not its median.
    pub batch_completion: Duration,
    /// The slowest individual fetch, which for a fully-parallel launch is the
    /// same quantity — kept separately so a serialized run is visible as a
    /// divergence rather than hidden.
    pub slowest_fetch: Duration,
}

impl BatchObservation {
    /// Whether every launched fetch completed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.completed == self.launched
    }
}

/// A W₂ datum: batches, and the provenance without which they are not citable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct W2Datum {
    provenance: RunProvenance,
    batches: Vec<BatchObservation>,
}

impl W2Datum {
    /// Bind observations to their provenance.
    ///
    /// Taking [`RunProvenance`] by value here is what makes the type's guarantee
    /// real: there is no way to hold a `W2Datum` that was not built from all
    /// three attestations.
    #[must_use]
    pub fn new(provenance: RunProvenance, batches: Vec<BatchObservation>) -> Self {
        Self {
            provenance,
            batches,
        }
    }

    /// The run's provenance.
    #[must_use]
    pub fn provenance(&self) -> &RunProvenance {
        &self.provenance
    }

    /// The observed batches.
    #[must_use]
    pub fn batches(&self) -> &[BatchObservation] {
        &self.batches
    }

    /// The worst batch completion observed, or `None` if nothing ran.
    ///
    /// The floor check compares *this* to W₂ — not a quantile. With the window
    /// pinned at two orders above the estimate, a max over the run is the
    /// conservative reading and a quantile would only be needed if the answer
    /// were close.
    #[must_use]
    pub fn worst_batch_completion(&self) -> Option<Duration> {
        self.batches.iter().map(|b| b.batch_completion).max()
    }

    /// Whether every batch completed in full.
    #[must_use]
    pub fn all_batches_complete(&self) -> bool {
        !self.batches.is_empty() && self.batches.iter().all(BatchObservation::is_complete)
    }

    /// The floor check: does the worst batch fit inside `window` with `margin`×
    /// room to spare?
    ///
    /// Returns `None` when nothing ran or a batch was incomplete — an
    /// unanswered check, never a pass. A run that could not fetch everything is
    /// not a fast run.
    #[must_use]
    pub fn fits_within(&self, window: Duration, margin: u32) -> Option<bool> {
        if !self.all_batches_complete() {
            return None;
        }
        let worst = self.worst_batch_completion()?;
        worst.checked_mul(margin).map(|scaled| scaled <= window)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(arch_aarch64: bool) -> RunDevice {
        RunDevice {
            cpu: "test".to_owned(),
            arch: if arch_aarch64 { "aarch64" } else { "x86_64" },
            at_or_above_floor: arch_aarch64,
        }
    }

    fn network() -> LiveNetworkAttested {
        LiveNetworkAttested::from_consensus(7_000).expect("real consensus")
    }

    fn batch(launched: usize, completed: usize, secs: u64) -> BatchObservation {
        BatchObservation {
            launched,
            completed,
            batch_completion: Duration::from_secs(secs),
            slowest_fetch: Duration::from_secs(secs),
        }
    }

    /// The fold from a raw batch, including the property the two duration
    /// fields exist to expose: a batch whose completion greatly exceeds its
    /// slowest fetch did not run concurrently, and that must be visible rather
    /// than averaged away.
    #[test]
    fn a_serialized_batch_is_visible_as_a_divergence() {
        use crate::harness::BatchOutcome;
        use crate::measure::Observation;

        // Three fetches of ~1 s each. Run concurrently the batch takes ~1 s;
        // run serially it takes ~3 s. Same observations either way.
        let observations = vec![
            Observation::success(Duration::from_secs(1)),
            Observation::success(Duration::from_secs(1)),
            Observation::success(Duration::from_secs(1)),
        ];
        let concurrent = BatchOutcome {
            launched: 3,
            observations: observations.clone(),
            batch_completion: Duration::from_millis(1_100),
        }
        .observe();
        let serialized = BatchOutcome {
            launched: 3,
            observations,
            batch_completion: Duration::from_secs(3),
        }
        .observe();

        assert_eq!(concurrent.slowest_fetch, serialized.slowest_fetch);
        assert!(
            serialized.batch_completion > concurrent.batch_completion,
            "the per-fetch numbers are identical; only the batch duration \
             distinguishes a concurrent run from a serialized one, which is why \
             both are reported",
        );
        assert!(concurrent.is_complete() && serialized.is_complete());
    }

    /// A failed fetch must not count toward completion, or a batch that lost
    /// members would report a better completion than it earned.
    #[test]
    fn a_failed_fetch_does_not_count_as_completed() {
        use crate::harness::BatchOutcome;
        use crate::measure::{FailureKind, Observation};

        let out = BatchOutcome {
            launched: 3,
            observations: vec![
                Observation::success(Duration::from_secs(1)),
                Observation::failure(Duration::from_secs(2), FailureKind::Timeout),
                Observation::success(Duration::from_secs(1)),
            ],
            batch_completion: Duration::from_secs(2),
        }
        .observe();
        assert_eq!(out.completed, 2);
        assert!(!out.is_complete());
        assert_eq!(
            out.slowest_fetch,
            Duration::from_secs(2),
            "the time a failure spent before giving up is still time the \
             producer spent",
        );
    }

    /// A chutney-sized consensus is the third silent failure §9.5 names, and it
    /// must stop the datum from existing rather than annotate it.
    #[test]
    fn a_test_net_consensus_yields_no_attestation() {
        let err = LiveNetworkAttested::from_consensus(12).expect_err("must refuse");
        assert_eq!(
            err,
            ProvenanceError::ConsensusTooSmall { relays_seen: 12 },
            "a handful of relays is chutney, and its numbers come back looking good",
        );
        assert!(LiveNetworkAttested::from_consensus(MIN_REAL_CONSENSUS_RELAYS).is_ok());
    }

    /// An off-floor run is still a valid capability check — it just is not a
    /// floor datum, and the two must be distinguishable.
    #[test]
    fn an_off_floor_run_is_recorded_as_not_a_floor_datum() {
        let p = RunProvenance::attest(VanguardsAttested(()), device(false), network());
        assert!(
            !p.is_floor_datum(),
            "a developer box produces a capability reading, never a rule-76 \
             provisioning input",
        );
        let floor = RunProvenance::attest(VanguardsAttested(()), device(true), network());
        assert!(floor.is_floor_datum());
    }

    /// The statistic is the batch, not the fetch. A batch bounded by its slowest
    /// member is the producer's actual constraint.
    #[test]
    fn the_reported_statistic_is_the_worst_batch() {
        let d = W2Datum::new(
            RunProvenance::attest(VanguardsAttested(()), device(true), network()),
            vec![batch(97, 97, 30), batch(97, 97, 900), batch(97, 97, 45)],
        );
        assert_eq!(
            d.worst_batch_completion(),
            Some(Duration::from_secs(900)),
            "the check is against the worst batch: the producer must land every \
             pair, so a good median rescues nothing",
        );
    }

    /// An incomplete batch is an unanswered check, never a pass — a run that
    /// could not fetch everything is not a fast run.
    #[test]
    fn an_incomplete_batch_cannot_pass_the_floor_check() {
        let d = W2Datum::new(
            RunProvenance::attest(VanguardsAttested(()), device(true), network()),
            vec![batch(97, 96, 5)],
        );
        assert_eq!(
            d.fits_within(Duration::from_secs(60_000), 100),
            None,
            "96 of 97 in five seconds is a failure, and must not read as the \
             fastest batch in the run",
        );
        assert!(!d.all_batches_complete());
    }

    #[test]
    fn the_floor_check_requires_the_stated_margin() {
        let d = W2Datum::new(
            RunProvenance::attest(VanguardsAttested(()), device(true), network()),
            vec![batch(97, 97, 600)],
        );
        // W2 = 500 blocks x 120 s = 60_000 s. 600 s x 100 = 60_000 -> fits.
        assert_eq!(d.fits_within(Duration::from_secs(60_000), 100), Some(true));
        // Demanding two orders on top of that does not.
        assert_eq!(d.fits_within(Duration::from_secs(60_000), 200), Some(false));
    }

    /// Nothing ran is not a pass either.
    #[test]
    fn an_empty_run_answers_nothing() {
        let d = W2Datum::new(
            RunProvenance::attest(VanguardsAttested(()), device(true), network()),
            Vec::new(),
        );
        assert_eq!(d.fits_within(Duration::from_secs(60_000), 100), None);
        assert_eq!(d.worst_batch_completion(), None);
    }
}
