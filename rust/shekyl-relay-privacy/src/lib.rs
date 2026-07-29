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
//! This crate is the measurement instrument **and** the production primitives
//! for the daemon relay-privacy rewrite (`docs/design/DAEMON_RELAY_PRIVACY.md`).
//!
//! **Boundary as of RP-2a.** Timing/measurement helpers and the feature-gated
//! conformance suite remain library-side instruments. [`StemMap`] is
//! production-linked: `shekyl-ffi` exposes it to C++ `net::dandelionpp::connection_map`,
//! and the daemon's live stem routing executes this map. Epoch/fluff schedule
//! and embargo cuts are RP-3/RP-4. Do not treat a `stem_map` change as
//! measurement-only.
//!
//! # The findings
//!
//! Five, all asserted in code rather than left as prose. Findings 1-4 came from
//! the initial measurement; finding 5 and the corrected embargo came out of the
//! Round-1 review (`DAEMON_RELAY_PRIVACY.md` §10).
//!
//! 1. **The embargo constant does not follow from its own derivation.**
//!    [`params`] has the detail. The inherited comment states inputs `k = 5`,
//!    `ep = 0.10`, `hop = 175 ms` and an answer of 39 s. Those inputs yield
//!    **16.61 s** under the Dandelion++ formula; 39 s is what you get by
//!    substituting a base-10 logarithm for the natural logarithm the formula
//!    specifies.
//! 2. **The embargo's distribution family is wrong.** [`geometric`] has the
//!    detail. The formula's `ln(1 - ep)` term comes from an *exponential*
//!    survival function — the derivation models memoryless timers. The daemon
//!    draws from `crypto::random_poisson_seconds`, and a Poisson at these
//!    means is nearly deterministic (`CV ≈ 0.16` at λ = 39). Measured, the
//!    backstop **never fires**: full-travel 1.0000 at both 39 s and a
//!    corrected 17 s, against a stem completing in ~700 ms.
//! 3. **The closed form under-provisions.** [`derive`] has the detail. It
//!    substitutes `E[K]` into an expression in `K(K-1)`, and stem length is
//!    geometric, where `E[K(K-1)] = 2·E[K](E[K]-1)` exactly. No constant
//!    correction factor recovers it; the exact solve in [`derive`] does. On an
//!    emission-terminated model that gives 31 s — see finding 5 (the return
//!    trip) and RD-4 (the origin always stems) for why the adopted value is
//!    144 s.
//! 4. **The fluff delay has the same defect as (2), on the timer that runs on
//!    every transaction.** [`schedule::FluffScheduler`] has the detail. The
//!    inherited comment cites Bitcoin Core, whose `PoissonNextSend` draws
//!    `-ln(U)·mean` — an *exponential* inter-arrival. The inherited code
//!    implements `std::poisson_distribution`, the discrete *count*. Measured,
//!    the inherited draw is ~1.96x more invertible: an adversary subtracting a
//!    fixed offset pins receipt time to within ±0.5 s 42% of the time — and
//!    for a transaction arriving *late* in a flush window, 93%.
//! 5. **The fluff flood is ~7x slower than it needs to be**, as a direct
//!    consequence of (4). [`conformance::simulate_fluff_return`] measures first
//!    passage to an arbitrary node at 13.75 s (p90) under the inherited draw
//!    versus 2.25 s memoryless. First passage is a minimum over parallel paths,
//!    and a minimum only helps when the paths differ.
//!
//! Findings 2 and 4 are the consequential ones, and neither is fixed by
//! correcting finding 1 — a Poisson at 17 s has exactly the defect a Poisson
//! at 39 s has.
//!
//! Finding 5 feeds straight back into the embargo: a stem node's embargo is
//! disarmed when the fluff *reaches* it, so the flood's return time is part of
//! every node's exposure window. [`derive`] counts it, which is why the adopted
//! embargo is 144 s (RD-4-corrected) rather than the 31 s an emission-terminated,
//! origin-may-fluff model gives.
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
//! ## Reason 2 stands — an earlier reversal of it is **withdrawn**
//!
//! RP-3 briefly recorded reason 2 as reversed, on the grounds that moving the
//! relay loop to Rust meant accepting a second reactor and that closing F-4/F-5
//! paid for it. **That ledger was wrong, and following the error back showed the
//! reversal was unnecessary.**
//!
//! - **F-4/F-5 close without any reactor change.** The corrected fluff draw is
//!   this crate's regardless of who owns the sleep, so the gain never required
//!   the cost it was charged against.
//! - **RP-3a adds no reactor.** Rust owns the zone state and every timing
//!   *decision*; the existing `boost::asio` timer is armed from the returned
//!   deadline and owns the *sleep*. Rust is a library the p2p path calls, not a
//!   loop beside it — so the p2p path still has exactly one reactor.
//! - That is not merely compatible with reason 2, it is **what reason 2
//!   prescribes**: *"a plain `&mut self` state machine that returns a deadline,
//!   precisely so the existing timer stays in charge."* RP-3a is that sentence,
//!   implemented.
//!
//! For precision: two reactors already coexist in the daemon process — the
//! Axum/tokio server in `shekyl-daemon-rpc` — and always have. Reason 2 was
//! never about the process; it is about the **p2p path**, which is why
//! asio-arms leaves it intact.
//!
//! The reactor does eventually move, when the C++ relay path is removed. That is
//! the point at which the move costs nothing: with asio gone, tokio is the sole
//! runtime, so there is no second reactor to create and no transitional
//! asio/tokio seam to maintain. Reason 2 is broken *then*, by the removal, not
//! now — and doing it before the removal would buy the seam and pay for it until
//! the C++ leaves.
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

pub mod derive;
pub mod geometric;
pub mod params;
pub mod poisson;
pub mod rng;
pub mod schedule;
pub mod stem_map;

#[cfg(feature = "conformance")]
pub mod conformance;

pub use derive::{
    derive_embargo, full_travel_probability, marginal_preemption_profile, EmbargoDerivation,
};
pub use geometric::GeometricTable;
pub use params::{DandelionParams, StemGraph, EMBARGO_FULL_TRAVEL_PROBABILITY};
pub use poisson::PoissonTable;
pub use rng::{bernoulli, bounded_uniform, RelayRng, SplitMix64};
#[allow(deprecated)]
pub use schedule::EmbargoDistribution;
pub use schedule::{
    DelayFamily, EmbargoTimer, Epoch, EpochScheduler, FluffScheduler, Millis, NoiseCadence,
    PeerDirection, DEFAULT_EMBARGO_TICK_MILLIS,
};
pub use stem_map::{ConnectionId, SourceId, StemMap, StemSetChange};
