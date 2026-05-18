//! LWMA-1 difficulty adjustment for Shekyl.
//!
//! Implements the difficulty-adjustment algorithm ratified at Phase 0
//! of [`docs/design/DAA_LWMA1.md`](../../docs/design/DAA_LWMA1.md):
//! the canonical [zawy12 LWMA-1] window-shape with the Shekyl-specific
//! refinements documented in §5.3 step 2 (running-max + signed-
//! solvetime + symmetric `±6*T` clamp) defending against the
//! September 2018 selfish-mine attack class described in
//! [zawy12 issue #24 item 14].
//!
//! [zawy12 LWMA-1]: https://github.com/zawy12/difficulty-algorithms/issues/3
//! [zawy12 issue #24 item 14]: https://github.com/zawy12/difficulty-algorithms/issues/24
//!
//! # Crate posture
//!
//! - `#![no_std]` — pure-arithmetic crate; no allocations, no clock
//!   reads, no system state. Phase 4's C++ daemon and any future
//!   embedded validator consume the same code.
//! - `#![deny(unsafe_code)]` — the algorithm operates exclusively on
//!   safe Rust primitives; the FFI shim (Phase 3, in
//!   `rust/shekyl-ffi`) is the only `unsafe` boundary in the LWMA-1
//!   landing.
//! - Leaf crate per `docs/design/DAA_LWMA1.md` §2.1: zero internal
//!   workspace dependencies. The build script reads
//!   `config/consensus_constants.json` directly.
//!
//! # Public surface
//!
//! - [`lwma1_next`] — the algorithm. Inputs are
//!   `(chain_height, timestamps, cumulative_difficulties)`; the
//!   output is the difficulty target for the next block.
//! - [`is_timestamp_below_ftl`] and [`is_above_mtp`] — coupled
//!   timestamp-validation predicates per §5.5.
//! - Public consensus constants `N`, `T_SECONDS`, `FTL_SECONDS`,
//!   `MTP_WINDOW`, `GENESIS_DIFFICULTY` — see [`consts`].
//!
//! # FFI
//!
//! The FFI export `shekyl_difficulty_lwma1_next` (with the
//! `ShekylU128` ABI) lives in `rust/shekyl-ffi/src/lib.rs` and is
//! Phase 3 work, not Phase 1. This crate exposes only the safe-Rust
//! API; the FFI shim wraps it with the `#[repr(C)]` ABI and `i32`
//! error codes documented in `docs/design/DAA_LWMA1.md` §6.1.

#![no_std]
#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod consts;
mod error;
mod lwma1;
mod timestamp;

pub use consts::{
    FTL_SECONDS, GENESIS_DIFFICULTY, MTP_WINDOW, MTP_WINDOW_USIZE, N, N_USIZE, T_SECONDS,
};
pub use error::Error;
pub use lwma1::lwma1_next;
pub use timestamp::{is_above_mtp, is_timestamp_below_ftl};
