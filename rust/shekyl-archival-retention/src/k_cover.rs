// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `K_COVER` — the M1 reward-gate cover threshold
//! ([`ARCHIVAL_REWARD_GATE_M1.md`](../../docs/design/ARCHIVAL_REWARD_GATE_M1.md) §4).
//!
//! Epochs whose `frozen_shard_count` is below [`K_COVER`] accrue zero reward
//! for every persona (the §2.1 zero-at-top gate in `consensus_state.rs`).
//! `K_COVER` is compared at **exactly one code site** — `epoch_close_compute`
//! — guarded by the §6 CI grep tripwire; do not add a second comparison.
//!
//! # Sentinel mechanics (§4, armed before anything consumes the constant)
//!
//! The value finalizes only from the WI-4 §14.4 partition run. Until then
//! `k_cover_provisional` is `true` in `config/consensus_constants.json` and
//! two structural refusals hold, per the spec's build-refused-not-checklist
//! disposition (§9 R1-D3 / §10 M1-6):
//!
//! 1. **The provisional value is unrepresentable-as-plausible.** While the
//!    flag is set, `build.rs` refuses any value other than `0` — the
//!    gate-identity sentinel (`frozen_shard_count < 0` is never true, so
//!    pre-seal behavior is exactly the pre-gate behavior and the store
//!    write paths stay exercised end-to-end by the existing test corpus).
//!    The shipping guard is the compile refusal below, never the sentinel
//!    value: a build that reaches genesis with the sentinel is refused at
//!    compile time, so the sentinel's runtime semantics are unreachable in
//!    a release artifact (`00-mission.mdc` hierarchy holds structurally).
//! 2. **Building without acknowledgment refuses.** The `compile_error!`
//!    below fires for any build of this crate while the flag is set unless
//!    the `provisional-k-cover` feature is enabled. Every consumer therefore
//!    carries a grep-able acknowledgment line in its `Cargo.toml`; the KAT
//!    parameterizes `K_COVER` and never bakes the sentinel (§5).
//!
//! **Sealing** (the §14.4 value lands): set `k_cover` (`>= 1` — `build.rs`
//! refuses a sealed `0`), flip `k_cover_provisional` to `false`, then delete
//! the `provisional-k-cover` feature and every acknowledgment line — the
//! deletion target is the seal itself (`15-deletion-and-debt.mdc`: the
//! version is named by the event).

include!(concat!(env!("OUT_DIR"), "/k_cover_generated.rs"));

// The armed refusal. `k_cover_provisional` is emitted by build.rs from the
// JSON authority; at seal the cfg disappears and this block compiles away.
#[cfg(all(k_cover_provisional, not(feature = "provisional-k-cover")))]
compile_error!(
    "K_COVER is a provisional sentinel (k_cover_provisional = true in \
     config/consensus_constants.json) — it finalizes only from the WI-4 §14.4 partition \
     run per ARCHIVAL_REWARD_GATE_M1.md §4. A genesis or release artifact must not build \
     against it. Non-genesis builds acknowledge explicitly by enabling the \
     `provisional-k-cover` feature on shekyl-archival-retention (grep-able; delete at seal)."
);

// Tripwire, mirroring the WORK_MILLI_SCALE idiom (reward_arithmetic.rs): the
// two states the JSON can express are (provisional, 0) and (sealed, >= 1).
// build.rs enforces this at generation; this guard re-asserts it at the
// consumption site so a hand-edited generated file also fails.
const _: () = assert!(
    K_COVER_PROVISIONAL == (K_COVER == 0),
    "K_COVER sentinel invariant violated: provisional iff 0 \
     (ARCHIVAL_REWARD_GATE_M1.md §4 sentinel mechanics)"
);

/// Capability newtype for the M1 cover threshold (segment-freeze pre-flight
/// PF-6a).
///
/// A bare `u64` threshold lets any future caller — a "simulate close" RPC
/// preview, a leaked test helper — pass an arbitrary value and it compiles.
/// This newtype makes accidental divergence a **type error**: the only
/// non-test constructor is [`KCover::consensus`], which returns the crate
/// constant. KAT parameterization goes through [`KCover::for_kat`], gated
/// behind the **permanent** `consensus-kat` feature (enabled only via
/// dev-dependencies; it must survive the §4 seal, so it does not ride
/// `provisional-k-cover`). Deliberate misuse — a production consumer
/// enabling `consensus-kat` and calling the KAT constructor — stays one
/// grep: the §6 tripwire refuses `for_kat` outside `tests/` and `#[cfg(test)]`
/// modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KCover(u64);

impl KCover {
    /// The consensus threshold — the only production constructor. Threads
    /// [`K_COVER`] verbatim; there is no way to construct a divergent value
    /// without the `consensus-kat` feature.
    #[must_use]
    pub const fn consensus() -> Self {
        Self(K_COVER)
    }

    /// KAT-injection constructor: the reward-gate and consensus-state KATs
    /// parameterize the threshold per case so the fixtures survive the §4
    /// constant finalization without rewrite. Test-only by construction —
    /// `cfg(test)` for in-crate unit tests, the `consensus-kat` dev-only
    /// feature for integration tests. Never call from production code (§6
    /// tripwire).
    #[cfg(any(test, feature = "consensus-kat"))]
    #[must_use]
    pub const fn for_kat(value: u64) -> Self {
        Self(value)
    }

    /// The threshold value, for the single `epoch_close_compute` comparison
    /// site (§6 tripwire: reading is not a second predicate).
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}
