//! **QUARANTINED legacy claim-era tier table — do not add consumers.**
//!
//! The confidential claim-era staking system (tiers, claims, pool-division
//! rewards, `StakingMeta`) was retired per DQ1 (plain-transfer `stake_in` +
//! archival bonds) and swept from the Rust wallet stack — see
//! `docs/design/LEGACY_CLAIM_ERA_RETIREMENT.md`. This crate survives **only**
//! because the C++ claim-era consensus wire (`txin_stake_claim` /
//! `txout_to_staked_key`, the stake-ratio cache, claim-range validation) has
//! not been deleted yet: `shekyl-ffi`'s `shekyl_stake_*` C ABI exports back
//! those C++ paths and need this tier table (build-generated from
//! `config/economics_params.json` — the single source the build script reads).
//!
//! **Sole permitted consumer:** `shekyl-ffi`. The crate is deleted wholesale
//! with the C++ claim-wire removal (retirement map "PR-4"); anything new that
//! wants tier-like data is a design error — genesis staking is archival bonds.

#![deny(unsafe_code)]

pub mod tiers;

pub use tiers::{LockTier, StakeTier, TierTable, MAX_CLAIM_RANGE, TIERS};
