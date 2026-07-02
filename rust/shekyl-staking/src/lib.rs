//! Staking subsystem for Shekyl.
//!
//! Retained surface: per-output staking metadata ([`meta`]) and the lock-tier table
//! ([`tiers`]). The confidential claim-era machinery (entitlement / registry / rewards /
//! pool-division) was retired per DQ1 (plain-transfer `stake_in` + archival bonds) and
//! removed 2026-07-01 — see `docs/design/LEGACY_CLAIM_ERA_RETIREMENT.md`.

#![deny(unsafe_code)]

pub mod meta;
pub mod tiers;

pub use meta::StakingMeta;
pub use tiers::{LockTier, StakeTier, TierTable, MAX_CLAIM_RANGE, TIERS};
