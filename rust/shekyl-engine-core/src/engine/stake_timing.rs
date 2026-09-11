// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Typed newtypes for the archival bond request path (S4, Rounds 2 and 4).
//!
//! **Timing seams:** `NetworkGap(BlockSpan)` guards the block-level standoff
//! draw; `EconomicSpacing(SebSpan)` guards the principal→`P` funding interval.
//! They carry distinct inner types, so passing one where the other is expected
//! is a compile error.
//!
//! **Amount seams:** `CoverAmount` names the optional amount sent with the bond
//! transaction to decouple the principal→`P` flow from `bond_floor`. Lives here
//! (rather than a separate module) because it has one consumer today and
//! participates in the same request-path composition as the timing types.
//!
//! **Design-now / wire-later.** Both types and their default constants land in
//! 2c-2b. The *real checks* (has ≥ 1 SEB elapsed? has the standoff fired?) are
//! wired in later sub-PRs; only the logic that *names* the constraint is here.
//!
//! **Home rationale.** `BlockSpan` and `SebSpan` have a single consumer today
//! (this crate). Per `18-type-placement.mdc`, promoting them to `shekyl-types`
//! waits for a second consumer — `21-reversion-clause-discipline.mdc` reopening
//! criterion: "a downstream crate names one of these types in its public API."

use std::time::Duration;

use rand_core::RngCore as _;
use shekyl_standoff::draw::{bounded_uniform, GapRng};
use shekyl_units::AtomicUnits;

/// Bridges [`rand_core::OsRng`] to the standoff [`GapRng`] trait for the
/// wallet's **live** entropy draws: the stake engine's entry-gap draw
/// ([`PlanBondPost`](super::stake_engine)) and the WI-3 dispatch driver's
/// send-time dispersal draw
/// ([`DispatchDriver`](super::pscan::dispatch)). Zero-state — fresh OS
/// entropy per `next_u64` — so a single shared adapter serves both draws
/// with no per-site copy to drift.
///
/// `GapRng` needs only `next_u64`; `OsRng` provides it via `RngCore`. Pulling
/// only the one method keeps `rand_core`'s full trait out of the call sites.
/// If `OsRng::next_u64` panics (the entropy source dies mid-draw), the panic
/// is **loud, never silent**: the stake actor fail-stops (Round-3 acceptance
/// condition), and the dispatch tick unwinds its sweep — neither proceeds on a
/// low-entropy draw.
pub(crate) struct OsRngGapAdapter;

impl GapRng for OsRngGapAdapter {
    fn next_u64(&mut self) -> u64 {
        rand_core::OsRng.next_u64()
    }
}

/// Canonical session self-cert sample size (S6), **single-sourced** from
/// [`shekyl_standoff::conformance::CERTIFY_SAMPLE_N`] — the same `n` the reference
/// conformance KAT grades at, so the `8/√n` tolerance contract cannot fork between
/// the reference grade and the wallet's `on_start` self-cert. **The self-cert is
/// a `conformance`-feature (dev/test) build only — the default shipping binary
/// compiles it out (`stake_engine.rs` S6 note), so there is no production
/// self-cert; the grader is a tool an operator runs, not a shipped invariant.**
/// Re-exported here
/// (beside [`DEFAULT_ENTRY_GAP`]) for call-site ergonomics, mirroring how
/// `DEFAULT_ENTRY_GAP` wraps `shekyl_standoff::DEFAULT_ENTRY_GAP_WINDOW` (source of
/// truth down in the lower crate, alias up). Only present under `conformance` —
/// the const lives in standoff's feature-gated grader module.
#[cfg(feature = "conformance")]
pub(crate) use shekyl_standoff::conformance::CERTIFY_SAMPLE_N;

/// An additional amount of value sent with the bond transaction to decouple the
/// observed transaction amount from `bond_floor`.
///
/// The principal sends `bond_floor + cover` to `P`; `P` stakes the floor
/// (`bond_credit`) and holds the cover as working capital. The cover flows as
/// a P-change output, so `verify_credit_funding`'s `output_total` includes it
/// without any change to the check. JoinMarket provides no funding-time
/// amount mixing, making self-cover the primary (not a fallback) mechanism
/// for cold-start amount decorrelation.
///
/// # Defaults
///
/// [`CoverAmount::ZERO`] is the **stake-only path** — principal sends exactly
/// `bond_floor`. This is a disclosed privacy cost: the transaction carries a
/// clean `bond_floor`-shaped spend, facilitating amount correlation. It is
/// valid input to the engine but must be opt-in with a GUI/CLI privacy
/// warning; the recommended default is a non-zero randomly chosen cover.
///
/// # Opt-in cover recovery
///
/// Recovering the cover after the bond posts re-creates the principal↔`P`
/// link. Any recovery transfer must be independently timed (not tied to the
/// bond lifecycle), explicitly disclosed in the GUI/CLI as a privacy cost, and
/// never the default path. See §3.4 of `ARCHIVAL_BOND_REQUEST_2C2B_PLAN.md`.
///
/// **Design-now / wire-2d.** The bond transaction orchestration layer (2d)
/// takes `cover: CoverAmount`; the `PlanBondPost` message does not (the VIN
/// carries `bond_floor` only).
///
/// The inner value is [`AtomicUnits`] — the canonical money newtype — not a
/// bare `u64`, so the cover cannot be accidentally crossed with an unrelated
/// `u64` (a fee, a block count, an index) and composes directly with the
/// `AtomicUnits` arithmetic the funding path (`verify_credit_funding`,
/// transaction outputs) already speaks. `CoverAmount` itself stays a distinct
/// newtype so "the cover" is never confused with any other amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CoverAmount(pub AtomicUnits);

impl CoverAmount {
    /// No cover — stake-only path (opt-in; carries disclosed privacy cost).
    #[allow(dead_code)] // inert until 2d bond-transaction orchestration
    pub(crate) const ZERO: Self = Self(AtomicUnits::ZERO);
}

/// A span measured in blocks — the inner unit of [`NetworkGap`].
///
/// Wraps the `u64` `window` argument that `shekyl_standoff::draw_entry_gap`
/// expects. Using a newtype at the call site prevents confusing a block-count
/// argument with a plain `u64` fee, amount, or index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BlockSpan(pub u64);

impl BlockSpan {
    /// The raw block count, for the `u64`-typed `draw_entry_gap` boundary.
    pub(crate) const fn as_u64(self) -> u64 {
        self.0
    }
}

/// A span measured in Settlement Epoch Boundaries — the inner unit of
/// [`EconomicSpacing`].
///
/// One `SebSpan(1)` means "at least one full SEB must separate these events."
/// The raw `u64` is the SEB count; no finer granularity is defined here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SebSpan(pub u64);

/// A timing constraint measured in blocks — gates the `draw_entry_gap` standoff
/// window for the archival bond request path (S4, `ARCHIVAL_BOND_CONSTRUCTION.md`
/// §10, `ARCHIVAL_TIMING_CONSTANTS.md` §7).
///
/// Guards the bond-post placement within a single 600-block window
/// ([`DEFAULT_ENTRY_GAP`]). ⚠️ The window was derived as a *multi-event*
/// (prep-spend / announce / bond-post) horizon; the order-coin retirement
/// deleted the second (funding-send) event, so that derivation is now stale —
/// see the F-W3 banner on `shekyl_standoff::DEFAULT_ENTRY_GAP_WINDOW`.
///
/// **Not interchangeable with [`EconomicSpacing`]** — the inner type is
/// `BlockSpan`, not `SebSpan`, so cross-application is a compile error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NetworkGap(pub BlockSpan);

impl NetworkGap {
    /// The window as a raw block count, for the `u64`-typed
    /// `draw_entry_gap` / `draw_entry_gap_guarded` boundary. Reads
    /// semantically at the call site instead of a `.0 .0` tuple-index chain.
    pub(crate) const fn as_blocks(self) -> u64 {
        self.0.as_u64()
    }
}

/// A timing constraint measured in Settlement Epoch Boundaries — gates the
/// principal→`P` funding-transfer → bond-post interval for cold-start bonds
/// (SP-2.d, `ARCHIVAL_BOND_CONSTRUCTION.md` §10, `ARCHIVAL_TIMING_CONSTANTS.md`
/// §7).
///
/// The cold-start decorrelation guard: at least `MIN_COLD_START_SPACING` SEB
/// must elapse between the principal's generic seed transfer to `P` and `P`'s
/// bond post. The real elapsed check is wire-later (deferred to cold-start
/// wiring); this type names the constraint now.
///
/// **Not interchangeable with [`NetworkGap`]** — the inner type is `SebSpan`,
/// not `BlockSpan`, so cross-application is a compile error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EconomicSpacing(pub SebSpan);

/// The default archival-bond entry-gap window, **typed** as a [`NetworkGap`]
/// (B6).
///
/// The name deliberately omits `_WINDOW` so it does not collide with the raw
/// [`shekyl_standoff::DEFAULT_ENTRY_GAP_WINDOW`] (a `u64`) it wraps: the typed
/// `NetworkGap` constant and the raw scheme constant are distinguishable at a
/// glance (and the typed one is used via [`NetworkGap::as_blocks`], never a
/// `.0 .0` chain). The raw value is **single-sourced** from `shekyl-standoff`
/// (the canonical scheme window the golden vector is frozen at); this const only
/// wraps it. Because the wallet draws at the same value the golden vector
/// certifies, "what we validated is what ships" holds by construction — there is
/// no separate `600` literal to drift (B6 reconciliation, R0-D2). 2c-2b closes
/// the B6 open item from §4.
pub(crate) const DEFAULT_ENTRY_GAP: NetworkGap =
    NetworkGap(BlockSpan(shekyl_standoff::DEFAULT_ENTRY_GAP_WINDOW));

#[allow(dead_code)] // inert until cold-start spacing check is wired
/// Minimum economic spacing for cold-start principal→`P` funding (SP-2.d).
///
/// At least 1 Settlement Epoch Boundary must elapse between the principal's
/// generic seed transfer to `P` and `P`'s bond post — i.e. `≥ 1 settlement
/// epoch` per `ARCHIVAL_TIMING_CONSTANTS.md` §7 ("Min spacing join-Market ↔
/// principal spend", gate-6 R4). The SEB *length* is consensus
/// (`config/consensus_constants.json` `settlement_epoch_blocks = 10000`); this
/// const is the wallet-policy *count* (1 SEB). The real elapsed check —
/// `SebSpan → blocks` via `settlement_epoch_blocks` — wires in cold-start
/// wiring (B6b reconciliation, R0-D3).
pub(crate) const MIN_COLD_START_SPACING: EconomicSpacing = EconomicSpacing(SebSpan(1));

// ---------------------------------------------------------------------------
// SH-2b-2 — the serving-launch standoff (gate-6 §10.9 restore-flow)
// ---------------------------------------------------------------------------

/// Window for the **serving-launch standoff**: how long a staker's wallet waits
/// after open before publishing `P`'s onion service.
///
/// # What this is for
///
/// `ARCHIVAL_FIREWALL_GATE6.md` §10.9's restore-flow bullet: *"On wallet
/// restore, `StakeEngine` **must not auto-launch `P`'s HS in lockstep with
/// `LedgerEngine`'s principal sync**. Co-activation co-times principal-sync and
/// `P`-`.onion`-reanimation from one origin — a correlation `p_slot` rotation
/// does **not** foreclose (it changes the address, not the co-timing)."* The
/// §10.9 remedy is "independent scheduling + isolated circuits"; the isolated
/// circuits are `PTorClient::for_persona`'s business, and this constant is the
/// independent scheduling.
///
/// # What it buys, and what it does not — read before re-deriving the value
///
/// **It blurs the interval, not the sequence.** A serving host cannot start
/// before the store has a serve-set to pin, so `principal-sync → HS-up` is
/// forced by data dependency and is *not* something this delay conceals. An
/// adversary watching many opens sees that ordering every time. What the draw
/// removes is a *fixed* offset between the two — the thing that would let one
/// observation of the principal edge predict the onion edge. Anyone re-deriving
/// this window should start from that, not from "the delay hides the launch".
///
/// **It is a discrete, repeated event, not a continuous one.** Every wallet open
/// is one fresh sample from `U[0, window]`, so linkage sharpens with the number
/// of observed opens rather than staying flat: the minimum observed offset over
/// `n` opens has expectation `window / (n + 1)`. The window therefore has to be
/// sized against *expected open frequency*, and a window that is comfortable for
/// a wallet opened weekly is thin for one opened hourly. This is the same
/// discrete-vs-continuous axis [`posture`](super::posture) draws between fetch-③
/// (continuous, statistical, unavoidable — disclosed) and broadcast-③ (discrete,
/// categorical, avoidable — forbidden).
///
/// # Provenance of the value: **UNDERIVED, and deliberately named as such**
///
/// Ten minutes is a *starting* value chosen to be long against the principal
/// sync's own duration, not a derived one — there is no open-frequency model to
/// derive it from, and inventing a distribution to justify a number would be
/// provenance dressed as derivation. The mechanism is what this slice owes;
/// the number is a GF-7-class privacy parameter and wants the same treatment
/// the other measured parameters get.
///
/// **Reopening criterion (rule 21):** the first of — an open-frequency
/// distribution exists (measurement or a stated operator model), or the W₂ rig
/// produces onion-publish timing that bounds the observable edge. Either makes
/// `n` and the edge width concrete, and the window becomes derivable rather
/// than picked. Until then this is a **parameter of the start call**
/// (derive-don't-hardcode, the same discipline §9.5 item 1 applies to
/// `λ_target`), not a hardcoded sleep.
pub(crate) const DEFAULT_SERVING_LAUNCH_WINDOW: Duration = Duration::from_secs(10 * 60);

/// Draw the serving-launch standoff `d ~ U[0, window]`.
///
/// Deliberately **not** [`shekyl_standoff::draw_entry_gap`]: that function is
/// the single source for the *funding-seam* draw and its published conformance
/// vectors are pinned to that meaning, so a second semantic riding the same
/// function would make those vectors ambiguous and couple two windows that have
/// no reason to move together. The *arithmetic* is shared all the same — this
/// draws through [`bounded_uniform`](shekyl_standoff::bounded_uniform), the
/// standoff family's single unbiased sampler, exactly as the WI-3 dispatch
/// driver's dispersal draw does. Modulo bias would be privacy-load-bearing here
/// for the same reason it is there.
///
/// Millisecond resolution: the observable edge is a network publish, and
/// sub-millisecond precision on a multi-minute window is noise either way.
pub(crate) fn draw_serving_launch_delay<R: GapRng + ?Sized>(
    window: Duration,
    rng: &mut R,
) -> Duration {
    let window_ms = u64::try_from(window.as_millis()).unwrap_or(u64::MAX);
    if window_ms == 0 {
        // A zero window is "no standoff" — used by tests that assert the
        // start path itself. Drawing over an empty range would be a rejection
        // loop with nothing to accept.
        return Duration::ZERO;
    }
    Duration::from_millis(bounded_uniform(rng, window_ms))
}

#[cfg(test)]
mod serving_launch_tests {
    use super::*;

    /// Deterministic replay so a draw test asserts a property, not a sample.
    struct Seq(Vec<u64>, usize);

    impl GapRng for Seq {
        fn next_u64(&mut self) -> u64 {
            let v = self.0[self.1 % self.0.len()];
            self.1 += 1;
            v
        }
    }

    #[test]
    fn a_zero_window_draws_no_standoff() {
        let mut rng = Seq(vec![u64::MAX], 0);
        assert_eq!(
            draw_serving_launch_delay(Duration::ZERO, &mut rng),
            Duration::ZERO,
            "an empty range has nothing to accept; the rejection loop must not spin",
        );
    }

    #[test]
    fn every_draw_lands_inside_the_window() {
        let window = Duration::from_secs(600);
        // A spread of raw words including the extremes, so the mapping is
        // exercised at both ends rather than in the comfortable middle.
        let mut rng = Seq(vec![0, 1, u64::MAX / 2, u64::MAX - 1, u64::MAX], 0);
        for _ in 0..64 {
            let d = draw_serving_launch_delay(window, &mut rng);
            assert!(d <= window, "{d:?} exceeds the {window:?} window");
        }
    }

    #[test]
    fn the_draw_actually_uses_the_window() {
        // A degenerate draw — one that always returned zero, or always the cap —
        // would satisfy the bound test above while providing no standoff at all.
        let window = Duration::from_secs(600);
        let mut rng = Seq(vec![0, u64::MAX / 4, u64::MAX / 2, (u64::MAX / 4) * 3], 0);
        let draws: Vec<Duration> = (0..4)
            .map(|_| draw_serving_launch_delay(window, &mut rng))
            .collect();
        assert!(
            draws
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                > 1,
            "a standoff that always draws the same delay is not a standoff: {draws:?}",
        );
        assert!(
            draws.iter().any(|d| *d > Duration::ZERO),
            "at least one draw must be non-zero",
        );
    }
}
