// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Daemon relay-privacy timing: the Dandelion++ epoch, stem, fluff and embargo
//! draws, derived from the paper rather than inherited as constants.
//!
//! # What this crate is for
//!
//! Shekyl inherits a complete Dandelion++ implementation in C++
//! (`src/net/dandelionpp.cpp`, `src/cryptonote_protocol/levin_notify.cpp`,
//! plus the stem embargo in `src/cryptonote_core/tx_pool.cpp`). It works. It
//! is also, on inspection, **entirely unmeasured**: the 33 `levin_notify` cases
//! in `tests/unit_tests/levin.cpp` drive the relay path through
//! `run_epoch()` / `run_stems()` / `run_fluff()`, every one of which cancels
//! the pending timer to force immediate execution. The suite verifies routing
//! mechanics — who receives what, with which fluff flag — and not one case
//! observes a delay. The randomized timing that *is* the privacy mechanism has
//! no test at all.
//!
//! This crate is the measurement instrument, built before any port so the
//! design round has numbers instead of inherited literals. It is deliberately
//! standalone: it links nothing, replaces nothing, and changes no daemon
//! behaviour. Its findings are meant to inform whether the values are worth
//! keeping before anyone spends a review cycle moving them.
//!
//! # The findings
//!
//! Two, both about the stem embargo, both asserted in code rather than left as
//! prose.
//!
//! 1. **The constant does not follow from its own derivation.** [`params`] has
//!    the detail. The inherited comment states inputs `k = 5`, `ep = 0.10`,
//!    `hop = 175 ms` and an answer of 39 s. Those inputs yield **16.61 s**
//!    under the Dandelion++ formula; 39 s is what you get by substituting a
//!    base-10 logarithm for the natural logarithm the formula specifies. The
//!    parameter is 2.3x its own justification.
//! 2. **The distribution family is wrong.** [`geometric`] has the detail. The
//!    formula's `ln(1 - ep)` term comes from an *exponential* survival
//!    function — the derivation models memoryless timers. The daemon draws
//!    from `crypto::random_poisson_seconds`, and a Poisson at these means is
//!    nearly deterministic (`CV ≈ 0.16` at λ = 39). The measured consequence
//!    is in `tests/propagation_measurement.rs`: the embargo almost never fires
//!    early enough to serve as the black-hole backstop it exists to be, and
//!    when it does fire it does so at a predictable offset from broadcast.
//!
//! Finding 2 is the more consequential of the two, and it is not fixed by
//! correcting finding 1 — a Poisson at 17 s has the same defect as a Poisson
//! at 39 s.
//!
//! # Why the distributions are re-implemented rather than bound
//!
//! The inherited draws go through `std::poisson_distribution` and
//! `std::uniform_int_distribution`. Both are **implementation-defined** — the
//! standard fixes the distribution, not the algorithm — so no cross-language
//! golden vector is possible and two nodes on different standard libraries
//! already draw different sequences. A port therefore cannot be validated by
//! differential replay the way the consensus port is; only a statistical grade
//! is available, and [`conformance`] is that grade. See [`poisson`] for how the
//! draw is made reviewable and reproducible instead.
//!
//! # Relationship to Cuprate
//!
//! `Cuprate` publishes `cuprate-dandelion-tower`, and its `config.rs` reaches
//! the same conclusion this crate does — derive `Tbase`, do not hard-code it.
//! It is prior art worth reading and is credited as such. It is **not** a
//! dependency, for two reasons that are worth recording so the question does
//! not get re-opened by accident:
//!
//! 1. **It is not published.** Every Cuprate crate on `crates.io`
//!    (`cuprate-levin`, `cuprate-epee-encoding`, `cuprate-wire`,
//!    `cuprate-dandelion-tower`) exists only as a `0.0.0-placeholder` name
//!    reservation. The real code is monorepo-internal with workspace-relative
//!    dependencies, so consuming it means vendoring at a pinned commit, not
//!    `cargo add`.
//! 2. **The shape is wrong for this seam.** `dandelion-tower` is a
//!    `tower::Service` stack over tokio timers and futures streams. The
//!    daemon's relay path runs inside a `boost::asio` strand; adopting it would
//!    mean running a second reactor inside the p2p path. Everything in
//!    [`schedule`] is a plain `&mut self` state machine that returns a
//!    deadline, precisely so the existing timer stays in charge.
//!
//! Cuprate's `net/levin` and `net/epee-encoding` are a genuinely different
//! question — they would remove the single largest obstacle to ever moving the
//! *full* relay path into Rust, which is that this workspace has no epee or
//! levin implementation. That belongs to a later decision, not to this crate.
//!
//! # Scope boundary
//!
//! Timing only. Nothing here serializes a message, chooses eligible peers, or
//! touches a socket. [`schedule`] explains why that line is where it is.
//!
//! The grading instruments live behind the `conformance` feature, which pulls
//! `shekyl-stats` and the float-bearing goodness-of-fit machinery. The default
//! build is the draws and the state machines only.

pub mod geometric;
pub mod params;
pub mod poisson;
pub mod rng;
pub mod schedule;
pub mod stem_map;

#[cfg(feature = "conformance")]
pub mod conformance;

pub use geometric::GeometricTable;
pub use params::{DandelionParams, StemGraph, EMBARGO_FULL_TRAVEL_PROBABILITY};
pub use poisson::PoissonTable;
pub use rng::{bernoulli, bounded_uniform, RelayRng, SplitMix64};
pub use schedule::{
    EmbargoDistribution, EmbargoTimer, Epoch, EpochScheduler, FluffScheduler, Millis, NoiseCadence,
    PeerDirection,
};
pub use stem_map::{ConnectionId, StemMap};
