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

use shekyl_units::AtomicUnits;

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
/// takes `cover: CoverAmount`; the `SignBond` message does not (the VIN
/// carries `bond_floor` only).
///
/// The inner value is [`AtomicUnits`] — the canonical money newtype — not a
/// bare `u64`, so the cover cannot be accidentally crossed with an unrelated
/// `u64` (a fee, a block count, an index) and composes directly with the
/// `AtomicUnits` arithmetic the funding path (`verify_credit_funding`,
/// transaction outputs) already speaks. `CoverAmount` itself stays a distinct
/// newtype so "the cover" is never confused with any other amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)] // inert until 2d bond-transaction orchestration
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
#[allow(dead_code)] // inert until 2c-2b request path is wired end-to-end
pub(crate) struct BlockSpan(pub u64);

impl BlockSpan {
    /// The raw block count, for the `u64`-typed `draw_entry_gap` boundary.
    #[allow(dead_code)] // inert until 2c-2b request path is wired end-to-end
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
#[allow(dead_code)] // inert until cold-start spacing check is wired
pub(crate) struct SebSpan(pub u64);

/// A timing constraint measured in blocks — gates the `draw_entry_gap` standoff
/// window for the archival bond request path (S4, `ARCHIVAL_BOND_CONSTRUCTION.md`
/// §10, `ARCHIVAL_TIMING_CONSTANTS.md` §7).
///
/// Guards: prep-spend / announce / bond-post events within a single
/// 600-block window ([`DEFAULT_ENTRY_GAP`]).
///
/// **Not interchangeable with [`EconomicSpacing`]** — the inner type is
/// `BlockSpan`, not `SebSpan`, so cross-application is a compile error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // inert until 2c-2b request path is wired end-to-end
pub(crate) struct NetworkGap(pub BlockSpan);

impl NetworkGap {
    /// The window as a raw block count, for the `u64`-typed
    /// `draw_entry_gap` / `draw_entry_gap_guarded` boundary. Reads
    /// semantically at the call site instead of a `.0 .0` tuple-index chain.
    #[allow(dead_code)] // inert until 2c-2b request path is wired end-to-end
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
#[allow(dead_code)] // inert until cold-start spacing check is wired
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
