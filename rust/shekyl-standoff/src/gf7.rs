//! GF-7 measurement-hook seam — the observer trait and the three-axis joint
//! event vocabulary (`docs/design/ARCHIVAL_BOND_2C_GF7_HOOKS.md` §3).
//!
//! **Feature-gated, never default.** This module compiles only under the
//! non-default `gf7-hooks` feature — the same build-enforced containment
//! shape as this crate's `conformance` grading (never in a default build;
//! hooks-spec §4 layer 3). The other two containment layers: the trait is
//! **inert by type** (typed events in, nothing out — no I/O, no writer, no
//! serialization; layer 1), and the only **non-test** recording
//! implementation lives in `shekyl-staking-sim`, a binary crate no
//! production crate depends on, CI-asserted by a dependency-graph check
//! (layer 2 — the containment claim is about production edges;
//! `#[cfg(test)]` recorders, e.g. the stake-engine emission-completeness
//! test's, are outside it by construction).
//!
//! # Why the seam lives here
//!
//! The hooks are **sim-facing against a modeled adversary, never production
//! telemetry**. The recording implementation must therefore be constructible
//! by the sim without pulling the wallet engine's dependency tree — so the
//! trait and vocabulary live in this dependency-free crate (GF-7's scoped
//! home per `ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md` §4, which already owns the
//! draw-parameter vocabulary the events carry). The scheduler's host crate
//! forwards the feature and injects the observer, `ScanSchedule`-discipline
//! (injectable, no hardwired sink).
//!
//! # Payload discipline (hooks-spec §3, load-bearing)
//!
//! - **Logical time only.** Block heights and plan offsets, never wall clock.
//!   A wall-clock field is a production-fingerprint hazard and a
//!   sim-irrelevance both; the sim supplies its own clock.
//! - **Opaque ordinals, not identities.** A persona is an opaque index; never
//!   a key, address, txid, or `PersonaHandle` content. The sim joins events
//!   to ground truth on its own side (it *is* the ground truth), so the
//!   emission needs correlatable ordinals only — the hook surface is
//!   secret-free by construction.
//! - **Sweepable parameters ride the events.** Window, spread, order-coin
//!   appear where they were consumed, so the measurement round grades
//!   `P(link | T_obs)` *as a function of* those parameters without
//!   re-instrumenting.

/// A logical instant: a block height in the sim's frame, or a block offset
/// where the event says so. Never wall clock (see the module docs).
pub type LogicalTime = u64;

/// An opaque per-observer-session persona index. Deliberately not a newtype
/// over any engine persona type: the ordinal's only property is that two
/// events with the same ordinal concern the same persona within one recorded
/// timeline.
pub type PersonaOrdinal = u64;

/// One event on the joint observable timeline. Three classes, mirroring the
/// three GF-7 correlation axes (hooks-spec §2/§3) — the correlator consumes
/// **one joint stream**, never per-axis series to be multiplied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimelineEvent {
    // -- Axis (iii): principal lifecycle -----------------------------------
    /// The principal dispatched a funding send (toward a `P` or otherwise —
    /// the adversary sees the send, not its purpose).
    FundingSendDispatched { at: LogicalTime },
    /// The principal dispatched a drain / unbond-shaped operation.
    DrainDispatched { at: LogicalTime },
    /// A principal refresh cycle ran (the wallet's periodic chain-sync
    /// rhythm — cadence, not content).
    RefreshCycleMarker { at: LogicalTime },
    /// A principal wallet session opened (the activity-rhythm boundary an
    /// observer of the principal's node accumulates).
    WalletSessionMarker { at: LogicalTime },

    // -- Axis (i): the bond-post and its draw ------------------------------
    /// The entry-gap draw was consumed by the planner. Carries the draw
    /// parameters — the actual values that ran, so the sim grades the draw
    /// that happened, not a re-derivation.
    EntryGapDrawConsumed {
        persona: PersonaOrdinal,
        /// The window the draw ran at (`spread ~ U[0, window]`).
        window_blocks: u64,
        /// The drawn spread.
        spread_blocks: u64,
        /// The fair order-coin (`true` = bond-post precedes the entry event).
        bond_first: bool,
    },
    /// The planner placed the two seam events. Offsets are **blocks relative
    /// to the private-intent anchor** (`shekyl_standoff::plan`); the anchor
    /// itself is the principal's secret and never appears.
    BondPostScheduled {
        persona: PersonaOrdinal,
        entry_offset_blocks: u64,
        bond_post_offset_blocks: u64,
    },
    /// The bond-post actually went to a wire (absolute logical time in the
    /// recording session's frame). Emitted by the live broadcast consumer
    /// when it exists; the sim synthesizes it from the schedule meanwhile.
    BondPostDispatched {
        persona: PersonaOrdinal,
        at: LogicalTime,
    },

    // -- Axis (ii): `P`'s other broadcasts ---------------------------------
    /// Any other per-`P` submit through the `PerP` arm (serve-credit claims,
    /// rebond top-ups as later slices land them).
    PerPSubmitDispatched {
        persona: PersonaOrdinal,
        at: LogicalTime,
    },
}

/// The injected observer seam the 2c-2b scheduler emits into.
///
/// **Inert by type**: takes a typed event, returns nothing, owns no writer /
/// socket / file. `Send + 'static` because the host holds the observer inside
/// a spawned actor task across `await` points (the same bound as the pscan
/// `ScanSchedule`).
pub trait BroadcastTimelineObserver: Send + 'static {
    /// Record one event onto the joint timeline.
    fn record(&mut self, event: TimelineEvent);
}

/// The production default: discards every event. Injected by every
/// production construction path; only the sim constructs a recording
/// observer.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoOpObserver;

impl BroadcastTimelineObserver for NoOpObserver {
    fn record(&mut self, _event: TimelineEvent) {}
}
