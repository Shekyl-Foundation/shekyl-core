// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Typed timing-seam newtypes for the archival bond request path (S4, Round 2).
//!
//! Two seams, two units, no cross-apply: `NetworkGap(BlockSpan)` guards the
//! block-level standoff draw; `EconomicSpacing(SebSpan)` guards the principal→`P`
//! funding interval. They carry distinct inner types, so passing one where the
//! other is expected is a compile error.
//!
//! **Design-now / wire-later.** Both types and their default constants land in
//! 2c-2b. The *real checks* (has ≥ 1 SEB elapsed? has the standoff fired?) are
//! wired in later sub-PRs; only the logic that *names* the constraint is here.
//!
//! **Home rationale.** `BlockSpan` and `SebSpan` have a single consumer today
//! (this crate). Per `18-type-placement.mdc`, promoting them to `shekyl-types`
//! waits for a second consumer — `21-reversion-clause-discipline.mdc` reopening
//! criterion: "a downstream crate names one of these types in its public API."

/// A span measured in blocks — the inner unit of [`NetworkGap`].
///
/// Wraps the `u64` `window` argument that `shekyl_standoff::draw_entry_gap`
/// expects. Using a newtype at the call site prevents confusing a block-count
/// argument with a plain `u64` fee, amount, or index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)] // inert until 2c-2b request path is wired end-to-end
pub(crate) struct BlockSpan(pub u64);

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
/// 600-block window (`DEFAULT_ENTRY_GAP_WINDOW`).
///
/// **Not interchangeable with [`EconomicSpacing`]** — the inner type is
/// `BlockSpan`, not `SebSpan`, so cross-application is a compile error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // inert until 2c-2b request path is wired end-to-end
pub(crate) struct NetworkGap(pub BlockSpan);

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

/// Default block-count window for the archival bond entry-gap draw (B6).
///
/// Matches the golden-vector constant (`GOLDEN_WINDOW = 600` in
/// `shekyl-standoff`'s conformance tests and `golden_vector.rs:19`).
/// Named here so the `SignBond` handler and tests do not carry unnamed
/// magic-number literals; 2c-2b closes the B6 open item from §4.
pub(crate) const DEFAULT_ENTRY_GAP_WINDOW: NetworkGap = NetworkGap(BlockSpan(600));

#[allow(dead_code)] // inert until cold-start spacing check is wired
/// Minimum economic spacing for cold-start principal→`P` funding (SP-2.d).
///
/// At least 1 Settlement Epoch Boundary must elapse between the principal's
/// generic seed transfer to `P` and `P`'s bond post. Named here as the
/// design-now anchor; the real elapsed check wires in cold-start wiring.
pub(crate) const MIN_COLD_START_SPACING: EconomicSpacing = EconomicSpacing(SebSpan(1));
