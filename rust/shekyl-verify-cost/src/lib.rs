// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Verification-cost instruments.
//!
//! Pool admission ([`relay`](shekyl_types::relay), `DAEMON_RELAY_PRIVACY.md` §72), the pool
//! door's whole sequence (`door`, BA-T1) and cold-block connect
//! (`connect`, GAP-7). The benches and the pins call these modules, so
//! the wall-clock benches, the instruction-count gate and the pins measure
//! one set of fixtures.
//!
//! The fixtures call the verification bodies the pool door and block
//! connect run. They do not call `shekyl-chain-rules`, and nothing in the
//! production graph depends on this crate.
//!
//! Every module is behind the TEST_ONLY `seeded-rng` feature, because every
//! fixture proves through `shekyl-fcmp`'s seeded prover
//! (`shekyl_fcmp::proof::prove_with_rng`), which exists only under that
//! crate's `seeded-rng` (`CHAIN_FORGE.md` `CF-R9`). This crate's own benches
//! and tests enable it; a build without it has an empty library.

#![deny(unsafe_code)]

#[cfg(feature = "seeded-rng")]
pub mod connect;
#[cfg(feature = "seeded-rng")]
pub mod door;
#[cfg(feature = "seeded-rng")]
pub mod relay;
pub mod sweep;
