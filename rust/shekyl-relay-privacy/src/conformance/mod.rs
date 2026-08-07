// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Goodness-of-fit instruments and the stem-propagation simulator —
//! feature-gated (`conformance`), float-bearing, never part of a default
//! build.
//!
//! Split by concern so instruments can grow without a 2k-line grab-bag:
//!
//! - [`grade`] — chi-square distribution grades
//! - [`analysis`] — inversion precision, CV, residual masses
//! - [`stem`] — stem walk + propagation / preemption / black-hole
//! - [`flood`] — fluff-return first-passage + diffusion first-spy
//! - [`transport`] — clearnet vs Tor supernode observation + passive leak
//! - [`selection`] — two-slot occupancy, epoch layering, ε-greedy
//! - [`reshape`] — origin exposure, δ increment, recovery latency
//!
//! The shared stem model is [`walk_stem`] / [`StemTrace`]: every stem instrument
//! that only needs the RD-4/RD-1 path is a thin consumer of that helper.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

pub mod analysis;
pub mod flood;
pub mod grade;
pub mod linkage;
pub mod reshape;
pub mod selection;
pub mod stem;
pub mod transport;

mod util;

// Stable public surface — keep `conformance::foo` paths working.
pub use analysis::{
    coefficient_of_variation, inference_precision, residual_masses, sample_poisson, sample_uniform,
};
pub use flood::{
    simulate_diffusion_first_spy, simulate_fluff_return, FirstSpyPrecision, FloodParams,
    FloodReach, FloodSummary,
};
pub use grade::{grade_bernoulli, grade_poisson, grade_stem_balance, grade_uniform, Grade};
pub use reshape::{
    simulate_origin_exposure, simulate_precision_increment, simulate_reshape_recovery,
    OriginExposure, PrecisionIncrement, ReshapeRecovery,
};
pub use selection::{
    simulate_epoch_layering, simulate_epsilon_greedy_selection, simulate_induced_churn_exposure,
    simulate_two_slot_occupancy, EpochLayering, EpsilonGreedySelection, InducedChurnExposure,
    TwoSlotOccupancy,
};
pub use stem::{
    simulate_blackhole_attack, simulate_preemption_profile, simulate_propagation,
    simulate_sighting_separability, solve_embargo_secs_for_target, walk_stem, walk_stem_observing,
    BlackHoleOutcome, PreemptionProfile, Propagation, PropagationSummary, SightingSeparation,
    StemTrace,
};
pub use transport::{
    simulate_passive_neighbor_leak, simulate_transport_observation, PassiveNeighborLeak,
    SupernodeObservation, Transport,
};
