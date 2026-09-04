//! LWMA-1 difficulty adjustment for Shekyl.
//!
//! Implements the difficulty-adjustment algorithm ratified at Phase 0
//! of [`docs/completed/DAA_LWMA1.md`](../../docs/completed/DAA_LWMA1.md):
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
//! - Leaf crate per `docs/completed/DAA_LWMA1.md` §2.1: zero internal
//!   workspace dependencies. The build script reads
//!   `config/consensus_constants.json` directly.
//!
//! # Public surface
//!
//! - [`lwma1_next`] — the difficulty-adjustment algorithm. Inputs are
//!   `(chain_height, timestamps, cumulative_difficulties)`; the
//!   output is the difficulty target for the next block.
//! - [`check_hash`] — the PoW-target predicate: does a 256-bit hash
//!   satisfy a 128-bit difficulty? (`hash * difficulty < 2^256`.)
//!   Ported from the inherited C++ `check_hash`/`_64`/`_128` family
//!   into a single unified path.
//! - [`check_timestamp_rule`] — **the production owner of the C2-R3
//!   block-timestamp consensus rule**
//!   (`docs/completed/CONSENSUS_C2_R3_TIMESTAMPS.md` §4.3, ratified
//!   2026-09-01): saturating FTL + strict MTP over the 11 preceding
//!   timestamps, short windows genesis-padded, wider windows refused
//!   ([`TimestampRuleVerdict`] is the verdict, its discriminants the
//!   wire codes). The C++ validator's `check_block_timestamp` is a
//!   marshaling shim over this function's FFI export.
//! - [`is_timestamp_below_ftl`], [`is_above_mtp`] and [`mtp_median`] —
//!   the coupled timestamp predicates per §5.5, each the single site
//!   of its comparison; [`check_timestamp_rule`] composes them and is
//!   the entry consumers should reach for (the predicates alone are
//!   not the complete timestamp API).
//! - Public consensus constants `N`, `T_SECONDS`, `FTL_SECONDS`,
//!   `MTP_WINDOW`, `GENESIS_DIFFICULTY` — see [`consts`].
//!
//! # FFI
//!
//! Two consensus entry points live in
//! `rust/shekyl-ffi/src/difficulty_ffi.rs`, both consumed per-block by
//! the C++ validator: `shekyl_difficulty_lwma1_next` (the `ShekylU128`
//! ABI and `i32` error codes documented in
//! `docs/completed/DAA_LWMA1.md` §6.1) and
//! `shekyl_difficulty_check_timestamp_rule` (the C2-R3 rule; verdict
//! codes mirror [`TimestampRuleVerdict`]). This crate exposes only the
//! safe-Rust API; the FFI shims wrap it with the `#[repr(C)]` ABI.

#![no_std]
#![deny(unsafe_code)]
#![deny(missing_docs)]

mod alt_window;
mod check_hash;
pub mod consts;
mod error;
mod fork_choice;
mod lwma1;
mod timestamp;

pub use alt_window::{alt_window_plan, AltWindowPlan};
pub use check_hash::check_hash;
pub use consts::{
    FTL_SECONDS, GENESIS_DIFFICULTY, MTP_WINDOW, MTP_WINDOW_USIZE, N, N_USIZE, T_SECONDS,
};
pub use error::Error;
pub use fork_choice::{fork_choice, ForkChoiceVerdict};
pub use lwma1::lwma1_next;
pub use timestamp::{
    check_timestamp_rule, is_above_mtp, is_timestamp_below_ftl, mtp_median, TimestampRuleVerdict,
};
