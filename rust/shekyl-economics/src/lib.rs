//! Three-component economic system for Shekyl.
//!
//! Implements:
//! - Transaction-responsive release rate multiplier
//! - Adaptive fee burn with staker pool allocation
//! - Fixed-point arithmetic with overflow protection
//!
//! All calculations use u64 fixed-point with 10^6 scale (SCALE = 1_000_000).
//! A value of 1_000_000 represents 1.0, 400_000 represents 0.4, etc.

pub mod params;
pub mod release;
pub mod burn;

pub use params::EconomicParams;
pub use release::calc_release_multiplier;
pub use burn::{calc_burn_pct, BurnSplit};
