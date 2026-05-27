// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `PendingTx` lifecycle: build / submit / discard.
//!
//! Cross-cutting lock 4 in the rewrite plan binds the shape of the
//! in-flight transaction reservation system. Per the
//! `docs/V3_WALLET_DECISION_LOG.md` follow-up entry (2026-04-26), the
//! lock is refined to **runtime-only** reservations: the reservation
//! tracker lives on `Engine<S>` as a `BTreeMap<ReservationId,
//! Reservation>` field, *not* inside the persisted bookkeeping block.
//!
//! # Why runtime-only
//!
//! `Engine::close` errors with [`OpenError::OutstandingPendingTx`]
//! when any reservation is in flight, so the only path that could
//! persist a reservation across a wallet-close boundary is a process
//! crash between `build_pending_tx` and
//! `submit_pending_tx`/`discard_pending_tx`. Persisted reservations
//! on that path would be orphans: there is no in-memory `PendingTx`
//! handle to surface them through, the `tx_bytes` was process-local,
//! and the transaction never broadcast. The correct behavior on
//! crash is "the reservation is gone, the outputs become spendable
//! again on next open"; that is exactly what runtime-only tracking
//! gives us, with no reconciliation path.
//!
//! `BOOKKEEPING_BLOCK_VERSION` is therefore unchanged by this commit;
//! the bookkeeping block's scope stays "subaddress registry, labels,
//! address book."
//!
//! # State machine
//!
//! ```text
//! build_pending_tx(req)        ─►  Reservation { selected_outputs,
//!                                                built_at_height,
//!                                                built_at_tip_hash,
//!                                                fee, recipients }
//!                                  + PendingTx handle
//!
//! submit_pending_tx(handle)    ─►  invariants:
//!                                    - synced - built_at_height ≤ max_reorg_depth
//!                                      else PendingTxError::TooOld
//!                                    - block_hash_at(built_at_height) == built_at_tip_hash
//!                                      else PendingTxError::ChainStateChanged
//!                                  on pass: reservation is removed,
//!                                  selected outputs marked spent,
//!                                  TxHash returned
//!
//! discard_pending_tx(handle)   ─►  reservation removed, idempotent
//!                                  on unknown handles
//! ```
//!
//! # What is stubbed in Phase 1
//!
//! Three call sites are deferred to Phase 2a and named here so that
//! the seam is explicit in code review:
//!
//! 1. **`tx_bytes` construction.** [`PendingTx::tx_bytes`] is an
//!    empty `Vec<u8>` until Phase 2a wires `shekyl-tx-builder`. The
//!    chain-state tags ([`PendingTx::built_at_height`],
//!    [`PendingTx::built_at_tip_hash`],
//!    [`PendingTx::fee_atomic_units`]) are *real* and drive
//!    [`Engine::submit_pending_tx`]'s invariant checks.
//! 2. **Fee-priority resolution.** [`STUB_FEE_ATOMIC_UNITS`] is a
//!    flat constant. Phase 2a replaces this with a daemon
//!    `get_fee_estimates` call resolved through [`FeePriority`].
//! 3. **Daemon broadcast.** [`Engine::submit_pending_tx`] returns a
//!    `TxHash` synthesized from the [`ReservationId`]. Phase 2a
//!    replaces the body with a real broadcast call that returns the
//!    daemon-reported tx hash.
//!
//! # Output selection (Phase 1 placeholder)
//!
//! [`build_pending_tx_in_state`] picks the largest-amount unspent
//! outputs first until the cumulative sum covers `amount + fee`. This
//! is the simplest correct algorithm and is appropriate as a stub;
//! the production algorithm (decoy-friendly, change-output-aware,
//! locked-stake-aware) lands in Phase 2a alongside the real builder
//! integration. Outputs already cited by an existing reservation are
//! filtered out so a second concurrent build cannot select them.
//!
//! [`OpenError::OutstandingPendingTx`]: super::error::OpenError::OutstandingPendingTx
//! [`Engine::submit_pending_tx`]: super::Engine::submit_pending_tx

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use shekyl_address::Network;
use shekyl_engine_state::{LedgerBlock, NetworkSafetyConstants, SubaddressIndex};

use crate::engine::{
    error::{PendingTxError, SendError},
    local_ledger::LocalLedger,
    refresh::{derive_snapshot_id, LedgerSnapshot},
    traits::DaemonEngine,
    Engine, EngineSignerKind,
};

/// Stub fee for Phase 1 [`Engine::build_pending_tx`].
///
/// Replaced in Phase 2a by a daemon `get_fee_estimates` call resolved
/// against the caller's [`FeePriority`]. The constant is non-zero so
/// that lifecycle tests exercising [`Reservation::fee_atomic_units`]
/// run against a real value rather than zero-as-special-case.
pub const STUB_FEE_ATOMIC_UNITS: u64 = 1_000;

/// Opaque 16-byte content-derived ledger-snapshot digest.
///
/// Identifies the wallet's ledger state at the moment a reservation
/// was built; submit-time staleness checks compare a reservation's
/// `snapshot_id` against the engine's current `snapshot_id`. The bytes
/// are an engine-internal projection, never accepted from a caller
/// (the trait surface always derives `SnapshotId` from a freshly-read
/// [`LedgerSnapshot`] inside the engine).
///
/// Derived inside the `engine::refresh` module over the snapshot's
/// deterministic fields, hashed by Keccak-256 (via `shekyl-crypto-hash`'s
/// [`cn_fast_hash`](shekyl_crypto_hash::cn_fast_hash)) with a
/// domain-separation prefix and truncated to 128 bits per the
/// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 Phase 0b binding-form pin.
/// The 128-bit truncation is sized for bounded-population second-
/// preimage resistance, not generic collision resistance (≪ 2⁴⁰
/// snapshots over the wallet's operational lifetime); see the
/// `2026-05-26` `V3_WALLET_DECISION_LOG.md` entry, R2 disposition,
/// for the full security framing.
///
/// `Clone + Copy + PartialEq + Eq` is required by the submit-handler
/// field-comparison contract; `Hash + Ord` lets V3.x consumer-actor
/// surfaces key indexes off `SnapshotId` (zero V3.0-time cost via
/// derive).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SnapshotId(pub(crate) [u8; 16]);

impl SnapshotId {
    /// Underlying 16-byte digest. Exposed for diagnostics, log lines,
    /// and equality assertions in tests; the bytes are stable across
    /// reads but carry no meaning across processes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Process-local identifier for a [`Reservation`] / [`PendingTx`].
///
/// Generated by a monotonic `u64` counter on the owning `Engine<S>`;
/// the values are unique within a single `Engine` handle's lifetime
/// but carry no meaning across processes (reservations themselves are
/// process-local — see this module's docstring).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReservationId(u64);

impl ReservationId {
    /// Underlying counter value. Exposed for diagnostics and tests; not
    /// part of any wire format.
    pub fn raw(self) -> u64 {
        self.0
    }

    /// Construct a [`ReservationId`] from a raw counter value. Crate-
    /// internal; production code goes through `build_pending_tx` (which
    /// owns the monotonic counter on `Engine<S>`). Tests in sibling
    /// modules use this to synthesize a recognizable id without
    /// running the full build pipeline.
    #[cfg(test)]
    pub(crate) fn new(v: u64) -> Self {
        Self(v)
    }
}

/// Result of [`Engine::submit_pending_tx`].
///
/// Phase 1 stub: the bytes encode the [`ReservationId`] in
/// little-endian at offsets `0..8`, with the remaining bytes left
/// zero. Phase 2a replaces submit with a real daemon broadcast call
/// whose response carries the daemon's reported tx hash; callers
/// compare the field as opaque bytes either way and never rely on the
/// stub bit pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxHash(pub [u8; 32]);

// `FeePriority` migrated to `engine::fee_estimator` per PR 5
// C4γ (`STAGE_1_PR_5_PENDING_TX_ENGINE.md` §7.X "trait-surface
// is the canonical citation" pin). Re-exported here for
// backward source-text compatibility within the crate; the
// `engine::mod` re-export surface is unchanged.
pub use super::fee_estimator::FeePriority;

/// One transfer destination for [`TxRequest`].
#[derive(Clone, Debug)]
pub struct TxRecipient {
    /// Destination address in canonical Shekyl encoding (parsed and
    /// network-checked by [`build_pending_tx_in_state`]).
    pub address: String,
    /// Amount to send to this address in atomic units (no fee).
    pub amount_atomic_units: u64,
}

/// Caller request to [`Engine::build_pending_tx`].
#[derive(Clone, Debug)]
pub struct TxRequest {
    /// One or more destinations. Empty input is rejected with
    /// [`SendError::InvalidRecipient`].
    pub recipients: Vec<TxRecipient>,
    /// Fee tier; Phase 1 ignores and uses [`STUB_FEE_ATOMIC_UNITS`].
    pub priority: FeePriority,
    /// Optional source-subaddress filter. When `Some`, only outputs
    /// owned by this subaddress are eligible for selection.
    pub from_subaddress: Option<SubaddressIndex>,
}

/// Display-friendly recipient summary stored alongside the
/// reservation so the caller can render "what is in flight" without
/// parsing transaction bytes.
#[derive(Clone, Debug)]
pub struct TxRecipientSummary {
    /// Destination address, verbatim from the [`TxRecipient`] that
    /// produced the reservation.
    pub address: String,
    /// Amount the caller asked to send to this destination, in atomic
    /// units, before fee.
    pub amount_atomic_units: u64,
}

/// R14 reservation-extensibility seam.
///
/// `Reservation::extensions: Vec<ReservationExtension>` (added in
/// C2γ) carries the V3.x extension payload set associated with a
/// reservation — coinjoin coordination state, atomic-swap pre-image
/// commitments, time-locked / multi-stage build directives, and
/// other extensibility primitives that the V3.0 design intentionally
/// does not pre-provision. Phase 0d binding form per
/// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 (R14 closure, segment 2b).
///
/// # V3.0 variant set: empty
///
/// V3.0 ships `ReservationExtension` with **no variants**. The
/// uninhabited shape means `Vec<ReservationExtension>` is
/// permanently empty in V3.0 — consumers cannot construct a
/// `ReservationExtension` value, so `Reservation::extensions` is
/// always `Vec::new()` at C2γ build-pending-tx sites and there is
/// no engine-side variant-dispatch logic to land for V3.0.
///
/// The empty variant set is the named reopening criterion per
/// `21-reversion-clause-discipline.mdc`: the seam exists so V3.x
/// extension surfaces (each pinned in `docs/FOLLOWUPS.md` with a
/// target version) land additively by adding a variant here and
/// the matching dispatch in the affected engine paths. The current
/// state's disposition is reject-now-with-named-reopening (V3.x
/// per-extension FOLLOWUPS); it is neither pre-provisioned (no
/// hypothetical variants) nor refused-forever (the substrate is
/// here for V3.x to land into).
///
/// # Why `#[non_exhaustive]` on an already-uninhabited enum
///
/// Defense-in-depth against the V3.x activation pattern: when the
/// first variant lands, downstream crates that constructed
/// `ReservationExtension` values via the (currently impossible)
/// "match on no variants" idiom must still write a wildcard arm or
/// recompile. `#[non_exhaustive]` makes the V3.x variant addition a
/// non-breaking change for downstream consumers per the standard
/// reversion-clause discipline applied to enum surfaces.
///
/// # Why `pub` rather than `pub(crate)`
///
/// V3.x consumer code (test fixtures, actor-side variant-dispatch,
/// extension authors) needs to name the type. Restricting visibility
/// to `pub(crate)` now would force a V3.x compatibility break when
/// the first extension lands. The empty-variant-set is the
/// load-bearing privacy mechanism for V3.0 — consumers cannot
/// construct values, so visibility is information-only.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ReservationExtension {}

/// Runtime-only reservation: which transfers are earmarked for the
/// in-flight build, the chain state at build time, the fee, and the
/// recipient summary.
///
/// `pub(crate)`: callers reach this state through [`PendingTx`] and
/// the `Engine::*_pending_tx` methods, never directly. The submit /
/// discard path consumes the entry by removing it from the
/// reservation map.
#[derive(Clone, Debug)]
pub(crate) struct Reservation {
    /// Indices into [`LedgerBlock::transfers`] selected to fund the
    /// build. Sorted ascending so a debug print is deterministic.
    pub selected_transfer_indices: Vec<usize>,
    /// Engine's `synced_height` at the moment of the build.
    pub built_at_height: u64,
    /// Engine's recorded `block_hash_at(built_at_height)` at build
    /// time. The reorg-rewind invariant in
    /// [`PendingTxError::ChainStateChanged`] compares this against
    /// the wallet's current view at submit time.
    pub built_at_tip_hash: [u8; 32],
    /// [`SnapshotId`] derived at build time over the wallet's
    /// ledger snapshot. C5β's rewritten `submit` handler compares
    /// this against the engine's `current_snapshot` and emits
    /// `SubmitError::SnapshotInvalidated` on mismatch (lazy R5
    /// per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.6.5 F5+F6 /
    /// §5.6.6 P9). C2γ populates the field; C5β wires the read
    /// site.
    ///
    /// `dead_code` allow: the field is consumed only by the
    /// `Debug` derive until C5β's handler-body rewrite reads it
    /// for the staleness check. Pattern matches the surrounding
    /// `fee_atomic_units` / `recipients` / `priority` fields
    /// whose production readers also land in later commits.
    #[allow(dead_code)]
    pub snapshot_id: SnapshotId,
    /// R14 reservation-extension payload set. V3.0 ships with
    /// the always-empty vector (the
    /// [`ReservationExtension`] enum is uninhabited in V3.0
    /// per Phase 0d binding form — see the enum's doc-comment
    /// for the reopening-criteria-shaped reversion-clause
    /// disposition). V3.x extensions land additively via new
    /// `ReservationExtension` variants and matching engine-side
    /// dispatch.
    ///
    /// `dead_code` allow: the field is consumed only by the
    /// `Debug` derive until V3.x extensions land with their
    /// dispatch code.
    #[allow(dead_code)]
    pub extensions: Vec<ReservationExtension>,
    /// Fee in atomic units. Phase 1: [`STUB_FEE_ATOMIC_UNITS`].
    ///
    /// `dead_code` allow: the field is consumed only by the `Debug`
    /// derive and by tests that read the reservation map directly.
    /// The submit path on the [`PendingTx`] handle reads the same
    /// value off the handle, not off the reservation. Phase 2a reads
    /// this field when reconciling unconfirmed-spend tracking against
    /// the daemon's broadcast response.
    #[allow(dead_code)]
    pub fee_atomic_units: u64,
    /// Caller's recipient summary. Carried so a UI can describe an
    /// in-flight tx without reaching into `tx_bytes`. Read only via
    /// `Debug`; the same data lives on [`PendingTx::recipients`] for
    /// the caller-facing path.
    #[allow(dead_code)]
    pub recipients: Vec<TxRecipientSummary>,
    /// Caller-supplied fee tier. Stored for diagnostics; the actual
    /// fee is in [`Self::fee_atomic_units`] (Phase 1 stub). Read only
    /// via `Debug` and tests; Phase 2a reads it when resolving
    /// daemon `get_fee_estimates`.
    #[allow(dead_code)]
    pub priority: FeePriority,
}

/// Phase-1 in-flight transaction handle.
///
/// `tx_bytes` is empty until Phase 2a wires `shekyl-tx-builder`. Every
/// other field is real and drives [`Engine::submit_pending_tx`]'s
/// invariant checks against the wallet's current state.
#[derive(Clone, Debug)]
pub struct PendingTx {
    /// Reservation identifier; pass back to
    /// [`Engine::submit_pending_tx`] / [`Engine::discard_pending_tx`].
    pub id: ReservationId,
    /// Engine's `synced_height` at build time.
    pub built_at_height: u64,
    /// Engine's recorded block hash at `built_at_height` at build
    /// time.
    pub built_at_tip_hash: [u8; 32],
    /// Fee in atomic units captured at build time (Phase 1 stub).
    pub fee_atomic_units: u64,
    /// [`SnapshotId`] derived at build time from the wallet's
    /// ledger snapshot — mirrors the value stored on the
    /// engine-internal `Reservation` side. Caller-visible so
    /// diagnostics surfaces (and Stage 4's `MempoolMonitorActor`)
    /// can correlate handle equality across the wallet/consumer
    /// boundary without reaching into engine-private state. Per
    /// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 Phase 0b binding
    /// form.
    pub snapshot_id: SnapshotId,
    /// Constructed transaction bytes. Empty in Phase 1; Phase 2a
    /// fills this from `shekyl-tx-builder`.
    pub tx_bytes: Vec<u8>,
    /// Recipient summary for display.
    pub recipients: Vec<TxRecipientSummary>,
}

/// Default reservation TTL used by both
/// [`ReservationTTLConfig::consumer_held`] and
/// [`ReservationTTLConfig::in_flight`].
///
/// Provisional 24-hour order-of-magnitude per segment-2e R8
/// wargaming substrate (`STAGE_1_PR_5_PENDING_TX_ENGINE.md`
/// §5.6.7 V3.x FOLLOWUPS). The value is intentionally
/// "definitively long" rather than "tuned" — V3.0's R8 safety-net
/// posture is to bound stale-reservation lifetime so the wallet
/// eventually self-heals from forgotten reservations, without
/// imposing a short window that would conflict with legitimate
/// long-form approval workflows (hardware wallets, offline
/// signing, scheduled releases).
///
/// V3.x's `ReservationTTLActor` may tune per-collection values
/// independently; the constant is the V3.0 baseline that both
/// collections start from.
pub const DEFAULT_RESERVATION_TTL: Duration = Duration::from_secs(60 * 60 * 24);

/// Per-collection reservation TTL configuration. Phase 0l binding
/// form per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 (segment-2h F7
/// disposition; see §5.6.5 F7).
///
/// Both fields default to [`DEFAULT_RESERVATION_TTL`]; the
/// per-collection shape admits V3.x `ReservationTTLActor`
/// independent per-collection aging policy
/// (age-from-`created_at` vs. age-from-`submitted_at`) without
/// locking V3.0 into uniform-TTL.
///
/// `#[non_exhaustive]` per the reversion-clause discipline:
/// future TTL refinements (e.g., a per-collection bound on
/// `discard_requested`-marked reservations once that V3.x
/// substrate lands) extend the struct additively.
///
/// # V3.0 consumer (planned, C5α)
///
/// `LocalPendingTx::new(..., ttl: ReservationTTLConfig)`
/// constructor parameter. The engine's `outstanding()` and
/// TTL-cleanup background scan read `config.consumer_held` and
/// `config.in_flight` for per-collection aging.
///
/// # V3.x consumer (planned)
///
/// `ReservationTTLActor` reads the same `ReservationTTLConfig`
/// and applies per-collection policy without trait revision.
///
/// `dead_code` allow: no V3.0-time reader until C5α wires the
/// constructor parameter; the type lands in C2γ alongside the
/// `Reservation`/`PendingTx` field augmentation per the §7.X
/// commit decomposition's "type substrate before consumers"
/// ordering.
#[allow(dead_code)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservationTTLConfig {
    /// TTL applied to reservations in the `consumer_held`
    /// collection. The collection holds reservations that the
    /// engine has built but the consumer has not yet submitted;
    /// aging from `created_at` is the V3.0 default.
    pub consumer_held: Duration,
    /// TTL applied to reservations in the `in_flight` collection.
    /// The collection holds reservations whose `submit` is mid-
    /// flight (daemon round-trip outstanding). V3.0 defaults to
    /// age-from-`created_at` for parity with `consumer_held`;
    /// V3.x's `ReservationTTLActor` may switch to
    /// age-from-`submitted_at` per F7's per-collection-policy
    /// substrate.
    pub in_flight: Duration,
}

impl Default for ReservationTTLConfig {
    /// Uniform [`DEFAULT_RESERVATION_TTL`] across both
    /// collections — V3.0's R8 safety-net default per the
    /// segment-2e wargaming substrate.
    fn default() -> Self {
        Self {
            consumer_held: DEFAULT_RESERVATION_TTL,
            in_flight: DEFAULT_RESERVATION_TTL,
        }
    }
}

/// Actor-private in-flight reservation record. Phase 0a binding
/// form per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 (segment-2h P5
/// disposition; see §5.6.6 P5).
///
/// Created when a reservation moves from `consumer_held` to
/// `in_flight` at submit-dispatch time. The struct is
/// `pub(crate)` because it lives inside the engine's state
/// machine — consumers learn about its contents via the
/// `PendingTxDiagnostic` stream (`SubmitAttempted` /
/// `SubmitSucceeded` / `SubmitPendingResolution` emissions
/// project the fields they need to surface), never by reading
/// the struct directly. C5β introduces the `in_flight:
/// HashMap<ReservationId, InFlightSubmit>` collection that
/// stores values; C2γ lands the type ahead of the storage so
/// the type-substrate sub-commit is a coherent compile unit.
///
/// `dead_code` allow: no V3.0-time reader until C5β wires the
/// `in_flight` collection. Pattern matches the
/// `ReservationTTLConfig` allow above.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct InFlightSubmit {
    /// [`SnapshotId`] the reservation was built against;
    /// preserved verbatim from the source `Reservation` at the
    /// `consumer_held → in_flight` transition.
    pub snapshot_id: SnapshotId,
    /// When the reservation was originally built (the
    /// `consumer_held` insert timestamp). Preserved across the
    /// `consumer_held → in_flight` move so the `consumer_held`
    /// TTL semantics are not lost. V3.0's uniform "age from
    /// creation" aging policy reads this field for both
    /// collections.
    pub created_at: Instant,
    /// When the reservation entered `in_flight` (the submit-
    /// dispatch timestamp). V3.x's `ReservationTTLActor`
    /// age-from-submission policy reads this field for
    /// `in_flight` aging without trait revision.
    pub submitted_at: Instant,
}

// ---------------------------------------------------------------------------
// Free helpers (`pub(crate)`): operate on a free
// `(LedgerBlock, BTreeMap<ReservationId, Reservation>, u64 counter)`
// triple so unit tests can drive the lifecycle without standing up a
// full `Engine<S>` (whose constructors land in the lifecycle commit).
// `Engine::*` methods below are one-line wrappers over these.
// ---------------------------------------------------------------------------

/// Build a [`PendingTx`] against a free state triple. Inserts the
/// resulting [`Reservation`] into `reservations` and bumps `next_id`.
///
/// See [`Engine::build_pending_tx`] for the contract; this helper is
/// the same body, exposed for in-crate tests.
pub(crate) fn build_pending_tx_in_state(
    ledger: &LedgerBlock,
    reservations: &mut BTreeMap<ReservationId, Reservation>,
    next_id: &mut u64,
    request: &TxRequest,
) -> Result<PendingTx, SendError> {
    if request.recipients.is_empty() {
        return Err(SendError::InvalidRecipient {
            reason: "TxRequest must carry at least one recipient",
        });
    }

    let synced = ledger.height();
    let Some(tip_hash) = ledger.block_hash_at(synced).copied() else {
        return Err(SendError::CannotSign {
            reason: "wallet has not ingested any block yet",
        });
    };

    let mut total_amount: u64 = 0;
    for r in &request.recipients {
        total_amount =
            total_amount
                .checked_add(r.amount_atomic_units)
                .ok_or(SendError::InvalidRecipient {
                    reason: "recipient amount sum overflowed u64",
                })?;
    }
    let fee = STUB_FEE_ATOMIC_UNITS;
    let needed = total_amount
        .checked_add(fee)
        .ok_or(SendError::InvalidRecipient {
            reason: "amount + fee overflowed u64",
        })?;

    let reserved: BTreeSet<usize> = reservations
        .values()
        .flat_map(|r| r.selected_transfer_indices.iter().copied())
        .collect();

    let mut candidates: Vec<(usize, u64)> = ledger
        .spendable_outputs(synced, request.from_subaddress, None)
        .into_iter()
        .filter(|(idx, _)| !reserved.contains(idx))
        .map(|(idx, td)| (idx, td.amount()))
        .collect();
    candidates.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    let mut selected = Vec::new();
    let mut covered: u64 = 0;
    for (idx, amount) in candidates.iter().copied() {
        if covered >= needed {
            break;
        }
        selected.push(idx);
        covered = covered.saturating_add(amount);
    }
    if covered < needed {
        return Err(SendError::InsufficientFunds {
            needed,
            available: covered,
        });
    }
    selected.sort();

    let id = ReservationId(*next_id);
    *next_id = next_id
        .checked_add(1)
        .expect("ReservationId u64 counter overflowed within a single Engine handle");

    let summary: Vec<TxRecipientSummary> = request
        .recipients
        .iter()
        .map(|r| TxRecipientSummary {
            address: r.address.clone(),
            amount_atomic_units: r.amount_atomic_units,
        })
        .collect();

    // Derive the SnapshotId from a freshly-read LedgerSnapshot view
    // of the same LedgerBlock the rest of this body used for
    // candidate selection. The minor allocation (one ReorgBlocks
    // clone, capped at DEFAULT_REORG_BLOCKS_CAPACITY) is bounded by
    // the wallet's reorg-window length and dominated by the rest of
    // the build pipeline's allocations.
    //
    // Per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 Phase 0b binding
    // form: the engine derives `SnapshotId` over the snapshot's
    // deterministic fields; consumers never construct one.
    let snapshot_id = derive_snapshot_id(&LedgerSnapshot::from_ledger(ledger));

    let reservation = Reservation {
        selected_transfer_indices: selected,
        built_at_height: synced,
        built_at_tip_hash: tip_hash,
        snapshot_id,
        extensions: Vec::new(),
        fee_atomic_units: fee,
        recipients: summary.clone(),
        priority: request.priority,
    };

    let pending = PendingTx {
        id,
        built_at_height: synced,
        built_at_tip_hash: tip_hash,
        fee_atomic_units: fee,
        snapshot_id,
        tx_bytes: Vec::new(),
        recipients: summary,
    };

    reservations.insert(id, reservation);

    Ok(pending)
}

/// Submit a [`PendingTx`] handle: run invariants, mark its inputs
/// as locally spent, and return the (Phase-1 stubbed) tx hash.
///
/// See [`Engine::submit_pending_tx`] for the contract.
pub(crate) fn submit_pending_tx_in_state(
    ledger: &mut LedgerBlock,
    reservations: &mut BTreeMap<ReservationId, Reservation>,
    network: Network,
    id: ReservationId,
) -> Result<TxHash, PendingTxError> {
    let Some(entry) = reservations.get(&id) else {
        return Err(PendingTxError::UnknownHandle);
    };

    let safety = NetworkSafetyConstants::for_network(network);
    let max_reorg = safety.max_reorg_depth;
    let synced = ledger.height();

    if synced.saturating_sub(entry.built_at_height) > max_reorg {
        return Err(PendingTxError::TooOld {
            built: entry.built_at_height,
            current: synced,
            max_reorg,
        });
    }

    let stored = ledger.block_hash_at(entry.built_at_height).copied();
    if stored != Some(entry.built_at_tip_hash) {
        return Err(PendingTxError::ChainStateChanged {
            height: entry.built_at_height,
        });
    }

    let entry = reservations
        .remove(&id)
        .expect("reservation existence checked above");

    for &idx in &entry.selected_transfer_indices {
        if let Some(td) = ledger.transfer_mut(idx) {
            td.spent = true;
            // `spent_height` deliberately stays `None` until refresh
            // confirms the broadcast; this is the "unconfirmed-spent"
            // half-state the rewrite plan locks in. Phase 2a will
            // model unconfirmed-vs-confirmed spends explicitly when
            // the daemon broadcast call lands.
        }
    }

    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&id.0.to_le_bytes());
    Ok(TxHash(bytes))
}

/// Discard a reservation. Returns `true` if the handle was known,
/// `false` otherwise — the caller-facing `Engine::discard_pending_tx`
/// is `Ok(())` in either case (cross-cutting lock 4: discard is
/// idempotent and silent on unknown handles).
pub(crate) fn discard_pending_tx_in_state(
    reservations: &mut BTreeMap<ReservationId, Reservation>,
    id: ReservationId,
) -> bool {
    reservations.remove(&id).is_some()
}

// ---------------------------------------------------------------------------
// `Engine<S>` methods.
// ---------------------------------------------------------------------------

// `D: DaemonEngine` private-bound: see the rationale on the
// `pub struct Engine` definition in `engine/mod.rs`. The
// `L = LocalLedger` specialization is intentional: `build_pending_tx`
// and `submit_pending_tx` borrow the `WalletLedger` directly through
// `self.ledger.read()` / `self.ledger.write()`, which are
// `LocalLedger` inherent methods. The `LedgerEngine` trait surface
// does not yet expose borrowed-state read/write accessors; once a
// future commit (Stage 4 design space — see the Phase 0c amendment
// in `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §2.2) adds them, this
// block generalizes to `impl<S, D, L: LedgerEngine>`.
#[allow(private_bounds)]
impl<S: EngineSignerKind, D: DaemonEngine> Engine<S, D, LocalLedger> {
    /// Number of in-flight reservations on this wallet handle.
    ///
    /// `Engine::close` (lifecycle commit) calls this and refuses with
    /// [`OpenError::OutstandingPendingTx`](super::error::OpenError::OutstandingPendingTx)
    /// when the count is non-zero. Tests and callers that want to
    /// poll the count outside `close` use this accessor.
    pub fn outstanding_pending_txs(&self) -> usize {
        self.reservations.len()
    }

    /// Build a [`PendingTx`] against the wallet's current state.
    ///
    /// Phase 1 contract:
    ///
    /// - Selects unspent, mature, non-reserved outputs covering
    ///   `Σ recipient_amount + STUB_FEE_ATOMIC_UNITS`.
    /// - Captures `synced_height` and the recorded block hash at that
    ///   height as the reservation's chain-state tags.
    /// - Records the selection and tags in the wallet's runtime
    ///   reservation map.
    /// - Returns a [`PendingTx`] with `tx_bytes = Vec::new()` (Phase
    ///   2a wires `shekyl-tx-builder`).
    ///
    /// # Errors
    ///
    /// - [`SendError::InvalidRecipient`] for an empty `recipients`
    ///   list or amount overflow.
    /// - [`SendError::CannotSign`] when the wallet has not ingested
    ///   any block yet (no tip hash to anchor against).
    /// - [`SendError::InsufficientFunds`] when the available
    ///   non-reserved spendable balance cannot cover `amount + fee`.
    pub fn build_pending_tx(&mut self, request: &TxRequest) -> Result<PendingTx, SendError> {
        let guard = self.ledger.read();
        build_pending_tx_in_state(
            &guard.ledger.ledger,
            &mut self.reservations,
            &mut self.next_reservation_id,
            request,
        )
        // `guard` is dropped at end of expression, releasing the
        // LocalLedger read lock once the result has been computed.
    }

    /// Submit a [`PendingTx`] handle.
    ///
    /// Runs the cross-cutting-lock-4 invariants
    /// ([`PendingTxError::TooOld`], [`PendingTxError::ChainStateChanged`],
    /// [`PendingTxError::UnknownHandle`]) and on success removes the
    /// reservation, marks its inputs locally spent (with
    /// `spent_height = None` to reflect the still-unconfirmed state),
    /// and returns a [`TxHash`].
    ///
    /// Phase 1 stub: the body does not call the daemon; the returned
    /// `TxHash` is synthesized from the [`ReservationId`]. Phase 2a
    /// replaces this body with a real broadcast call. The invariant
    /// checks themselves are the same in both phases.
    pub fn submit_pending_tx(&mut self, id: ReservationId) -> Result<TxHash, PendingTxError> {
        let mut guard = self.ledger.write();
        submit_pending_tx_in_state(
            &mut guard.ledger.ledger,
            &mut self.reservations,
            self.network,
            id,
        )
    }

    /// Discard a reservation.
    ///
    /// Idempotent: `Ok(())` whether or not `id` is currently
    /// recognized. Per cross-cutting lock 4, `submit_pending_tx`
    /// raises [`PendingTxError::UnknownHandle`] for an unknown handle
    /// while `discard_pending_tx` does not.
    pub fn discard_pending_tx(&mut self, id: ReservationId) -> Result<(), PendingTxError> {
        let _ = discard_pending_tx_in_state(&mut self.reservations, id);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests: drive the helpers against a hand-constructed
// `(LedgerBlock, LedgerIndexes)` pair so the lifecycle is covered
// without depending on the (not-yet-landed) `Engine<S>` constructors.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar};
    use shekyl_address::Network;
    use shekyl_oxide::primitives::Commitment;
    use shekyl_scanner::{
        LedgerBlock, LedgerIndexes, LedgerIndexesExt, RecoveredWalletOutput, Timelocked,
        WalletOutput,
    };

    use super::{
        build_pending_tx_in_state, discard_pending_tx_in_state, submit_pending_tx_in_state,
        FeePriority, PendingTxError, Reservation, ReservationId, SendError, TxRecipient, TxRequest,
        STUB_FEE_ATOMIC_UNITS,
    };

    fn make_recovered_output(seed: u8, global_index: u64, amount: u64) -> RecoveredWalletOutput {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&global_index.to_le_bytes());
        bytes[8] = seed;
        let scalar = Scalar::from_bytes_mod_order(bytes);
        let key = &scalar * ED25519_BASEPOINT_TABLE;
        let base = WalletOutput::new_for_test(
            [seed; 32],
            0,
            global_index,
            key,
            Scalar::ZERO,
            Commitment {
                mask: Scalar::ONE,
                amount,
            },
            None,
        );
        RecoveredWalletOutput::new_for_test(base, amount)
    }

    /// Ingest `outputs` at `block_height` (single-block batch), then
    /// keep advancing the ledger by empty blocks up to `final_height`.
    fn populate(
        ledger: &mut LedgerBlock,
        indexes: &mut LedgerIndexes,
        block_height: u64,
        outputs: Vec<RecoveredWalletOutput>,
        final_height: u64,
    ) {
        let timelocked = Timelocked::from_vec(outputs);
        let block_hash = [u8::try_from(block_height & 0xFF).unwrap(); 32];
        let inserted_range =
            indexes.process_scanned_outputs(ledger, block_height, block_hash, timelocked);
        assert!(!inserted_range.is_empty() || ledger.transfer_count() == 0);
        for h in (block_height + 1)..=final_height {
            let hash = [u8::try_from(h & 0xFF).unwrap(); 32];
            let _ =
                indexes.process_scanned_outputs(ledger, h, hash, Timelocked::from_vec(Vec::new()));
        }
    }

    fn standard_request(amount: u64) -> TxRequest {
        TxRequest {
            recipients: vec![TxRecipient {
                address: "test_address".to_string(),
                amount_atomic_units: amount,
            }],
            priority: FeePriority::Standard,
            from_subaddress: None,
        }
    }

    #[test]
    fn build_reserves_outputs_and_advances_id_counter() {
        let mut ledger = LedgerBlock::empty();
        let mut indexes = LedgerIndexes::empty();
        populate(
            &mut ledger,
            &mut indexes,
            1,
            vec![
                make_recovered_output(1, 100, 10_000),
                make_recovered_output(2, 101, 5_000),
            ],
            20,
        );
        assert_eq!(ledger.height(), 20);

        let mut reservations = std::collections::BTreeMap::new();
        let mut next_id = 0u64;

        let pending = build_pending_tx_in_state(
            &ledger,
            &mut reservations,
            &mut next_id,
            &standard_request(7_000),
        )
        .expect("build ok");

        assert_eq!(pending.id.raw(), 0);
        assert_eq!(next_id, 1);
        assert_eq!(pending.fee_atomic_units, STUB_FEE_ATOMIC_UNITS);
        assert_eq!(pending.built_at_height, 20);
        assert!(pending.tx_bytes.is_empty(), "Phase 1 leaves tx_bytes empty");
        assert_eq!(reservations.len(), 1);
        let r = reservations.get(&pending.id).unwrap();
        // 10_000 alone covers 7_000 + 1_000 fee, so the algorithm
        // selects exactly the 10_000 output.
        assert_eq!(r.selected_transfer_indices.len(), 1);
    }

    #[test]
    fn build_filters_outputs_already_reserved_by_another_build() {
        let mut ledger = LedgerBlock::empty();
        let mut indexes = LedgerIndexes::empty();
        populate(
            &mut ledger,
            &mut indexes,
            1,
            vec![
                make_recovered_output(1, 100, 10_000),
                make_recovered_output(2, 101, 6_000),
            ],
            20,
        );

        let mut reservations = std::collections::BTreeMap::new();
        let mut next_id = 0u64;

        // First build reserves the 10_000 output.
        let _first = build_pending_tx_in_state(
            &ledger,
            &mut reservations,
            &mut next_id,
            &standard_request(7_000),
        )
        .expect("first build");

        // Second build needs more than 5_000 (the only remaining
        // output is 6_000, which can cover 4_000 + fee). Asking for
        // 5_000 exhausts available because 5_000 + 1_000 fee = 6_000.
        let second_ok = build_pending_tx_in_state(
            &ledger,
            &mut reservations,
            &mut next_id,
            &standard_request(5_000),
        )
        .expect("second build covers exactly 6_000");
        let r = reservations.get(&second_ok.id).unwrap();
        assert_eq!(r.selected_transfer_indices.len(), 1);

        // Third build cannot cover anything — every output is
        // reserved.
        let err = build_pending_tx_in_state(
            &ledger,
            &mut reservations,
            &mut next_id,
            &standard_request(1),
        )
        .unwrap_err();
        assert!(
            matches!(err, SendError::InsufficientFunds { available: 0, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn build_rejects_empty_recipients() {
        let mut ledger = LedgerBlock::empty();
        let mut indexes = LedgerIndexes::empty();
        populate(
            &mut ledger,
            &mut indexes,
            1,
            vec![make_recovered_output(1, 100, 10_000)],
            20,
        );
        let mut reservations = std::collections::BTreeMap::new();
        let mut next_id = 0u64;
        let req = TxRequest {
            recipients: Vec::new(),
            priority: FeePriority::Economy,
            from_subaddress: None,
        };
        let err =
            build_pending_tx_in_state(&ledger, &mut reservations, &mut next_id, &req).unwrap_err();
        assert!(matches!(err, SendError::InvalidRecipient { .. }));
        assert!(reservations.is_empty());
        assert_eq!(next_id, 0);
    }

    #[test]
    fn build_rejects_when_no_block_ingested_yet() {
        // Empty ledger: synced = 0, no recorded block hash at 0.
        let ledger = LedgerBlock::empty();
        let mut reservations = std::collections::BTreeMap::new();
        let mut next_id = 0u64;
        let err = build_pending_tx_in_state(
            &ledger,
            &mut reservations,
            &mut next_id,
            &standard_request(1),
        )
        .unwrap_err();
        assert!(matches!(err, SendError::CannotSign { .. }));
    }

    #[test]
    fn build_returns_insufficient_funds_when_balance_short() {
        let mut ledger = LedgerBlock::empty();
        let mut indexes = LedgerIndexes::empty();
        populate(
            &mut ledger,
            &mut indexes,
            1,
            vec![make_recovered_output(1, 100, 5_000)],
            20,
        );
        let mut reservations = std::collections::BTreeMap::new();
        let mut next_id = 0u64;
        let err = build_pending_tx_in_state(
            &ledger,
            &mut reservations,
            &mut next_id,
            &standard_request(10_000),
        )
        .unwrap_err();
        match err {
            SendError::InsufficientFunds { needed, available } => {
                assert_eq!(needed, 11_000);
                assert_eq!(available, 5_000);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn submit_unknown_handle_returns_unknown_handle() {
        let mut ledger = LedgerBlock::empty();
        let mut reservations: std::collections::BTreeMap<ReservationId, Reservation> =
            std::collections::BTreeMap::new();
        let err = submit_pending_tx_in_state(
            &mut ledger,
            &mut reservations,
            Network::Testnet,
            ReservationId(42),
        )
        .unwrap_err();
        assert!(matches!(err, PendingTxError::UnknownHandle));
    }

    #[test]
    fn submit_too_old_when_built_height_outside_reorg_window() {
        let mut ledger = LedgerBlock::empty();
        let mut indexes = LedgerIndexes::empty();
        populate(
            &mut ledger,
            &mut indexes,
            1,
            vec![make_recovered_output(1, 100, 10_000)],
            20,
        );
        let mut reservations = std::collections::BTreeMap::new();
        let mut next_id = 0u64;
        let pending = build_pending_tx_in_state(
            &ledger,
            &mut reservations,
            &mut next_id,
            &standard_request(1_000),
        )
        .expect("build");

        // Advance ledger so synced - built_at_height > max_reorg_depth.
        // Testnet's max_reorg_depth = 6.
        for h in 21..=40 {
            let hash = [u8::try_from(h & 0xFF).unwrap(); 32];
            let _ = indexes.process_scanned_outputs(
                &mut ledger,
                h,
                hash,
                Timelocked::from_vec(Vec::new()),
            );
        }

        let err = submit_pending_tx_in_state(
            &mut ledger,
            &mut reservations,
            Network::Testnet,
            pending.id,
        )
        .unwrap_err();
        match err {
            PendingTxError::TooOld {
                built,
                current,
                max_reorg,
            } => {
                assert_eq!(built, 20);
                assert_eq!(current, 40);
                assert_eq!(max_reorg, 6);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        // Reservation is preserved on TooOld so the caller can
        // discard it explicitly.
        assert_eq!(reservations.len(), 1);
    }

    #[test]
    fn submit_chain_state_changed_when_tip_hash_at_built_height_no_longer_matches() {
        let mut ledger = LedgerBlock::empty();
        let mut indexes = LedgerIndexes::empty();
        populate(
            &mut ledger,
            &mut indexes,
            1,
            vec![make_recovered_output(1, 100, 10_000)],
            5,
        );
        let mut reservations = std::collections::BTreeMap::new();
        let mut next_id = 0u64;

        // Drive the build at height 5 (well past the spendable_age
        // cutoff so the output qualifies).
        for h in 6..=15 {
            let hash = [u8::try_from(h & 0xFF).unwrap(); 32];
            let _ = indexes.process_scanned_outputs(
                &mut ledger,
                h,
                hash,
                Timelocked::from_vec(Vec::new()),
            );
        }
        let pending = build_pending_tx_in_state(
            &ledger,
            &mut reservations,
            &mut next_id,
            &standard_request(1_000),
        )
        .expect("build");
        assert_eq!(pending.built_at_height, 15);

        // Reorg: rewind to fork height 15, replay 15..=20 with new
        // hashes. After rewind, `block_hash_at(15)` differs from
        // `pending.built_at_tip_hash`.
        indexes.handle_reorg(&mut ledger, 15);
        for h in 15..=20 {
            let hash = [u8::try_from(0xA0 ^ (h & 0xFF)).unwrap(); 32];
            let _ = indexes.process_scanned_outputs(
                &mut ledger,
                h,
                hash,
                Timelocked::from_vec(Vec::new()),
            );
        }

        let err = submit_pending_tx_in_state(
            &mut ledger,
            &mut reservations,
            Network::Testnet,
            pending.id,
        )
        .unwrap_err();
        match err {
            PendingTxError::ChainStateChanged { height } => {
                assert_eq!(height, 15);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(reservations.len(), 1, "reservation preserved on error");
    }

    #[test]
    fn submit_marks_inputs_spent_and_consumes_reservation() {
        let mut ledger = LedgerBlock::empty();
        let mut indexes = LedgerIndexes::empty();
        populate(
            &mut ledger,
            &mut indexes,
            1,
            vec![make_recovered_output(1, 100, 10_000)],
            20,
        );
        let mut reservations = std::collections::BTreeMap::new();
        let mut next_id = 0u64;
        let pending = build_pending_tx_in_state(
            &ledger,
            &mut reservations,
            &mut next_id,
            &standard_request(5_000),
        )
        .expect("build");

        let tx_hash = submit_pending_tx_in_state(
            &mut ledger,
            &mut reservations,
            Network::Testnet,
            pending.id,
        )
        .expect("submit");

        assert_eq!(reservations.len(), 0);
        // Output was marked locally spent (Phase 1 stub).
        assert!(ledger.transfers()[0].spent);
        assert_eq!(
            ledger.transfers()[0].spent_height,
            None,
            "Phase 1 leaves spent_height None until refresh confirms"
        );

        // Stub TxHash encodes the reservation id in the first 8 bytes.
        assert_eq!(&tx_hash.0[..8], &pending.id.raw().to_le_bytes());
    }

    #[test]
    fn discard_releases_reservation_and_outputs_become_selectable_again() {
        let mut ledger = LedgerBlock::empty();
        let mut indexes = LedgerIndexes::empty();
        populate(
            &mut ledger,
            &mut indexes,
            1,
            vec![make_recovered_output(1, 100, 10_000)],
            20,
        );
        let mut reservations = std::collections::BTreeMap::new();
        let mut next_id = 0u64;
        let pending = build_pending_tx_in_state(
            &ledger,
            &mut reservations,
            &mut next_id,
            &standard_request(1_000),
        )
        .expect("build");

        assert!(discard_pending_tx_in_state(&mut reservations, pending.id));
        assert_eq!(reservations.len(), 0);

        // Re-build picks up the same output: it is no longer reserved.
        let again = build_pending_tx_in_state(
            &ledger,
            &mut reservations,
            &mut next_id,
            &standard_request(1_000),
        )
        .expect("rebuild");
        let r = reservations.get(&again.id).unwrap();
        assert_eq!(r.selected_transfer_indices, vec![0]);
    }

    #[test]
    fn discard_is_idempotent_on_unknown_handle() {
        let mut reservations: std::collections::BTreeMap<ReservationId, Reservation> =
            std::collections::BTreeMap::new();
        let was_present = discard_pending_tx_in_state(&mut reservations, ReservationId(99));
        assert!(!was_present);
        // No state change, no panic.
        assert!(reservations.is_empty());
    }

    #[test]
    fn priority_custom_is_accepted_and_preserved() {
        let mut ledger = LedgerBlock::empty();
        let mut indexes = LedgerIndexes::empty();
        populate(
            &mut ledger,
            &mut indexes,
            1,
            vec![make_recovered_output(1, 100, 10_000)],
            20,
        );
        let mut reservations = std::collections::BTreeMap::new();
        let mut next_id = 0u64;
        let req = TxRequest {
            recipients: vec![TxRecipient {
                address: "addr".into(),
                amount_atomic_units: 1_000,
            }],
            priority: FeePriority::Custom(NonZeroU64::new(42).unwrap()),
            from_subaddress: None,
        };
        let pending =
            build_pending_tx_in_state(&ledger, &mut reservations, &mut next_id, &req).unwrap();
        let r = reservations.get(&pending.id).unwrap();
        assert!(matches!(r.priority, FeePriority::Custom(_)));
    }
}
