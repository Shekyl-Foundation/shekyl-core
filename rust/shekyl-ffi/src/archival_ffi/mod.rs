// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Archival consensus-edge FFI (`ARCHIVAL_RETENTION_GATE2.md` §5.3).
//!
//! Wraps `shekyl-archival-retention` for the C++ consensus hook. Bond posture,
//! shard-registry geometry, and LMDB bit writes stay in the daemon; this module
//! tree covers challenge replay, path verify, hybrid signature, credit-window
//! timing, bond-post verify/connect, epoch-close, and emission vin verify.
//!
//! # Layout
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`codes`] | Shared early verdict codes + error mappers |
//! | [`schedule`] | Settlement-epoch / challenge height FFI |
//! | [`serve_credit`] | Serve-credit vin verify |
//! | [`attestation`] | Credit-wire attestation admission |
//! | [`bond`] | Bond-post verify / connect / pop |
//! | [`epoch_close`] | Failure window, prune, epoch-close compute |
//! | [`emission`] | Emission vin + claimed-epochs writer |
//! | [`ct_balance`] | Bond-post CT balance |
//!
//! Split from the former monofile so the archival C edge stays reviewable.
//! Pattern matches [`crate::relay_zone_ffi`].

mod attestation;
mod bond;
mod codes;
mod ct_balance;
mod emission;
mod epoch_close;
mod schedule;
mod serve_credit;
mod settlement;

pub use attestation::{ShekylArchivalAttestationVerifyCtx, ShekylArchivalPidPubkey};
pub use codes::*;
pub use epoch_close::ShekylArchivalEmissionEpochSnapshot;
pub use schedule::{
    settlement_epoch_close_height, settlement_epoch_open_height,
    settlement_epoch_slash_deadline_height,
};

// Re-export FFI entry points for `use super::*` in tests and in-crate callers.
#[allow(unused_imports)] // re-export surface; not all used inside this crate
pub use attestation::*;
#[allow(unused_imports)]
pub use bond::*;
#[allow(unused_imports)]
pub use ct_balance::*;
#[allow(unused_imports)]
pub use emission::*;
#[allow(unused_imports)]
pub use epoch_close::*;
#[allow(unused_imports)]
pub use schedule::*;
#[allow(unused_imports)]
pub use serve_credit::*;
pub use settlement::*;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod attestation_verify_tests;
