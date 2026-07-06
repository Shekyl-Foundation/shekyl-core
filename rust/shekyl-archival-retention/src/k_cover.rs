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
//!    flag is set, `build.rs` refuses any value other than `u64::MAX` — the
//!    fail-closed sentinel (the gate never opens: a liveness failure, never
//!    the privacy failure of a too-loose gate; `00-mission.mdc` hierarchy).
//! 2. **Building without acknowledgment refuses.** The `compile_error!`
//!    below fires for any build of this crate while the flag is set unless
//!    the `provisional-k-cover` feature is enabled. Every consumer therefore
//!    carries a grep-able acknowledgment line in its `Cargo.toml`; the KAT
//!    parameterizes `K_COVER` and never bakes the sentinel (§5).
//!
//! **Sealing** (the §14.4 value lands): set `k_cover`, flip
//! `k_cover_provisional` to `false`, then delete the `provisional-k-cover`
//! feature and every acknowledgment line — the deletion target is the seal
//! itself (`15-deletion-and-debt.mdc`: the version is named by the event).

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
// two states the JSON can express are (provisional, u64::MAX) and (sealed,
// real value). build.rs enforces this at generation; this guard re-asserts it
// at the consumption site so a hand-edited generated file also fails.
const _: () = assert!(
    K_COVER_PROVISIONAL == (K_COVER == u64::MAX),
    "K_COVER sentinel invariant violated: provisional iff u64::MAX \
     (ARCHIVAL_REWARD_GATE_M1.md §4 sentinel mechanics)"
);
