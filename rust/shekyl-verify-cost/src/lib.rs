// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Verification-cost instruments.
//!
//! Pool admission ([`relay`], `DAEMON_RELAY_PRIVACY.md` §72), the pool
//! door's whole sequence ([`door`], BA-T1) and cold-block connect
//! ([`connect`], GAP-7). The benches and the pins call these modules, so
//! the wall-clock benches, the instruction-count gate and the pins measure
//! one set of fixtures.
//!
//! The fixtures call the verification bodies the pool door and block
//! connect run. They do not call `shekyl-chain-rules`, and nothing in the
//! production graph depends on this crate.

#![deny(unsafe_code)]

pub mod connect;
pub mod door;
pub mod relay;
