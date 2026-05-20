// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shekyl engine domain orchestrator.
//!
//! `shekyl-engine-core::engine` is the home of the [`Engine`](Engine) type
//! that composes the file envelope ([`shekyl_engine_file::WalletFile`]),
//! identity material ([`shekyl_crypto_pq::account::AllKeysBlob`]), the
//! ledger ([`crate::engine::local_ledger::LocalLedger`] aggregating
//! [`shekyl_engine_state::WalletLedger`] and
//! [`shekyl_engine_state::LedgerIndexes`] under interior-mutability
//! `RwLock` per the `LedgerEngine` trait contract — the trait itself
//! is `pub(crate)` per `V3_ENGINE_TRAIT_BOUNDARIES.md` §1.4),
//! preferences ([`shekyl_engine_prefs::WalletPrefs`]), the daemon RPC
//! client (via the `DaemonEngine` trait, default `D = DaemonClient`,
//! also `pub(crate)` per §1.4), and the per-process scanning
//! surface into a single audited domain orchestrator. `Engine<S, D, L>`
//! is generic over signer / daemon / ledger trait implementors, with
//! defaults that preserve the existing concrete-typed shape for
//! production callers — the CLI ([`shekyl-cli`]) and the JSON-RPC
//! server ([`shekyl-engine-rpc`]) sit on top of this surface, never
//! reaching around it.
//!
//! # What this module rejects on purpose
//!
//! The Phase 1 design log
//! ([`docs/V3_WALLET_DECISION_LOG.md`]) names every monero-era pattern
//! that is *not* being carried forward; the briefest summary, kept here
//! so the rejection survives "while we're here" temptations:
//!
//! - **Integrated addresses and `payment_id`s.** Subaddresses provide
//!   per-recipient tracking with strictly stronger privacy properties.
//!   `TxRequest` carries no `payment_id` field and the `IntegratedAddress`
//!   type is not modeled.
//! - **The two-level account / subaddress hierarchy.** Shekyl ships a
//!   single flat [`SubaddressIndex`](shekyl_engine_state::SubaddressIndex)
//!   namespace; index 0 is the primary address. Exchanges that need
//!   stronger isolation use multiple wallet files (separate keys are a
//!   strictly stronger boundary than wallet2's account-shared keys).
//! - **The `export_outputs` / `import_outputs` / `export_key_images` /
//!   `import_key_images` four-call dance.** Air-gapped flows use two
//!   typed bundle types (`UnsignedTxBundle`, `SignedTxBundle`) — see
//!   Phase 2d.
//! - **A god-object `Engine` with hundreds of public members.** Every
//!   [`Engine`] member's mutability and locking discipline is explicit;
//!   the type is *composition*, not *inheritance*.
//! - **Background-sync as a wallet-internal feature.** Refresh is
//!   `tokio::spawn`'d by the caller; cancellation is RAII via
//!   `RefreshHandle` (lands in a follow-up commit).
//!
//! # Cross-cutting locks honored
//!
//! Every cross-cutting lock recorded in the in-tree decision log
//! ([`docs/V3_WALLET_DECISION_LOG.md`]) is enforced at the type layer
//! in this module:
//!
//! 1. **Async runtime** — caller-provided multi-threaded `tokio`. IO-bound
//!    methods are `async`; pure compute stays sync.
//! 2. **Error types** — per-domain enums in [`error`], unified at the
//!    RPC boundary by [`shekyl-engine-rpc`].
//! 3. **Locking discipline** — `&self` queries / `&mut self` mutations.
//!    The RPC binary wraps in [`Arc<RwLock<Engine>>`].
//! 4. **`PendingTx` lifetime** — process-local, chain-state-tagged,
//!    reservation-bearing. Lands with the build/submit/discard methods.
//! 5. **`Network`** — closed enum re-exported as [`Network`] from
//!    [`shekyl_address`]; daemon mismatch is `OpenError::NetworkMismatch`.
//! 6. **Subaddress hierarchy** — flat
//!    [`SubaddressIndex`](shekyl_engine_state::SubaddressIndex). No
//!    account level.
//! 7. **`RefreshHandle`** — cancel-on-drop RAII, single-flight via
//!    `&mut self`. Lands with `Engine::refresh`.
//! 8. **Fee priority** — `FeePriority { Economy | Standard | Priority |
//!    Custom(NonZeroU64) }` over daemon `get_fee_estimates`. Lands with
//!    `build_pending_tx`.
//! 9. **Logging** — `tracing` spans throughout, two-layer secret
//!    redaction via [`shekyl_engine_state::LocalLabel`] (type layer) and
//!    a redacting subscriber field formatter (subscriber layer). Lands
//!    with the `tracing` wiring commit.
//! 10. **KAT regression** — plain `cargo test --workspace`,
//!     [`docs/test_vectors/`] under `CODEOWNERS`.
//! 11. **Decision Log** — every binding sub-decision in this module
//!     ships an entry in [`docs/V3_WALLET_DECISION_LOG.md`].
//!
//! # Status (as of this commit)
//!
//! Type-layer foundations + the [`Engine<S>`](Engine) struct itself with
//! its accessor surface, the [`DaemonClient`] thin wrapper, and the
//! lifecycle methods on `Engine<SoloSigner>`. [`Engine::create`] and
//! [`Engine::open_full`] ship end-to-end against the
//! [`shekyl_engine_file::WalletFile`] envelope and the
//! [`shekyl_crypto_pq::account::AllKeysBlob`] re-derivation path;
//! [`Engine::open_view_only`] and [`Engine::open_hardware_offload`]
//! ship as signature stubs that return
//! [`OpenError::CapabilityNotYetImplemented`](error::OpenError::CapabilityNotYetImplemented)
//! pending the matching `shekyl-crypto-pq` constructors.
//! [`Engine::change_password`] and [`Engine::close`] ship for every
//! signer kind. The struct is composition over field type — every
//! member's purpose, mutability discipline, and ownership are
//! explicit:
//!
//! | Field                 | Type                                                 | Provenance                              |
//! | --------------------- | ---------------------------------------------------- | --------------------------------------- |
//! | `file`                | [`shekyl_engine_file::WalletFile`]                   | `.wallet.keys` envelope IO              |
//! | `keys`                | [`shekyl_crypto_pq::account::AllKeysBlob`]           | rederived from master seed              |
//! | `ledger`              | [`shekyl_engine_state::WalletLedger`]                | aggregator over the four blocks         |
//! | `indexes`             | [`shekyl_engine_state::LedgerIndexes`]               | rebuilt at open from `ledger`           |
//! | `reservations`        | `BTreeMap<ReservationId, Reservation>`               | runtime-only `PendingTx` tracker        |
//! | `next_reservation_id` | `u64`                                                | process-local monotonic counter         |
//! | `prefs`               | [`shekyl_engine_prefs::WalletPrefs`]                 | plaintext-with-HMAC layer 2             |
//! | `daemon`              | [`DaemonClient`]                                     | thin wrapper around `SimpleRequestRpc`  |
//! | `network`             | [`Network`]                                          | cached from `file.network()`            |
//! | `capability`          | [`Capability`]                                       | cached from `file.capability()`         |
//! | `_signer`             | `PhantomData<S>`                                     | compile-time signer dispatch            |
//!
//! `network` and `capability` are cached on the struct so the hot
//! `Engine::network()` / `Engine::capability()` accessors are infallible
//! and O(1). The cache is established at construction and never drifts:
//! `WalletFile`'s region 1 is write-once after `create`, and region 1 is
//! the only place either field is sourced from.
//!
//! # Runtime-only state on `Engine`
//!
//! Two fields on `Engine<S>` are deliberately runtime-only and are
//! never serialized to disk:
//!
//! - [`indexes`](Engine) (`LedgerIndexes`): key-image / pubkey lookup
//!   maps and the staker-pool aggregate. Rebuilt at every
//!   `Engine::open*` from `self.ledger.ledger`.
//! - [`reservations`](Engine) (`BTreeMap<ReservationId, Reservation>`):
//!   the in-flight transaction reservation tracker. Cross-cutting
//!   lock 4 binds the *behavioral* shape (build reserves, discard
//!   releases, submit consumes, close errors with outstanding); the
//!   2026-04-26 follow-up Decision Log entry refines the storage
//!   location to a runtime field rather than the persisted
//!   bookkeeping block. See [`pending`] for the full rationale.
//!
//! Per cross-cutting lock 7, the cancel-on-drop refresh handle is
//! **not** a `Engine` field; it is *returned* by `Engine::refresh`
//! and held by the caller, so its `Drop` implementation drives the
//! cancellation token. A `Engine`-internal handle would defeat the
//! single-flight `&mut self` borrow that enforces no concurrent
//! refresh.
//!
//! # Constructors land next
//!
//! This commit defines the struct and its accessor surface only. The
//! six lifecycle methods (`create`, `open_full`, `open_view_only`,
//! `open_hardware_offload`, `change_password`, `close`) and the
//! [`RefreshHandle`], `PendingTx`, and `ScanResult` types each land in
//! their own follow-up commits on this same Phase 1 branch. Splitting
//! along behavioral seams keeps each commit reviewable on its own.

pub mod capability;
pub mod daemon;
pub(crate) mod diagnostics;
pub mod error;
#[cfg(any(test, feature = "test-helpers"))]
pub(crate) mod fault_injecting_refresh;
pub mod lifecycle;
pub(crate) mod local_keys;
pub(crate) mod local_ledger;
pub(crate) mod local_refresh;
pub mod merge;
pub mod network;
pub mod pending;
pub mod refresh;
pub mod signer;
pub(crate) mod traits;
pub mod view_material;

#[cfg(test)]
pub(crate) mod test_support;

pub use capability::Capability;
pub use daemon::DaemonClient;
pub use diagnostics::{
    DaemonOp, DiagnosticSink, MalformedKind, NoopDiagnosticSink, ProtocolErrorKind,
    RefreshDiagnostic, SuppressedClass, TracingDiagnosticSink,
};
pub use error::{IoError, KeyError, OpenError, PendingTxError, RefreshError, SendError, TxError};
pub use lifecycle::{CapabilityInput, Credentials, EngineCreateParams, OpenedEngine};
pub use local_ledger::LocalLedger;
pub use local_refresh::LocalRefresh;
pub use network::Network;
pub use pending::{
    FeePriority, PendingTx, ReservationId, TxHash, TxRecipient, TxRecipientSummary, TxRequest,
};
pub use refresh::{
    RefreshHandle, RefreshOptions, RefreshPhase, RefreshProgress, RefreshReorgEvent, RefreshSummary,
};
pub use signer::{EngineSignerKind, SoloSigner};
pub use view_material::ViewMaterial;

use std::collections::BTreeMap;
use std::marker::PhantomData;

use shekyl_crypto_pq::account::AllKeysBlob;
use shekyl_engine_file::WalletFile;
use shekyl_engine_prefs::WalletPrefs;
use shekyl_engine_state::WalletLedger;

use crate::engine::local_ledger::LedgerState;
use crate::engine::traits::{DaemonEngine, LedgerEngine, RefreshEngine};

/// The Shekyl V3 wallet domain orchestrator.
///
/// `Engine<S>` composes the file envelope, identity material, persistent
/// ledger, user preferences, and daemon RPC connection into a single
/// audited surface. The CLI and JSON-RPC server both sit on top of
/// this type; neither reaches around it to the underlying crates.
///
/// # Type parameter `S`
///
/// `S: EngineSignerKind` selects between the V3.0
/// [`SoloSigner`] (in-process signing, single spend secret) and the
/// V3.1 multisig path (`MultisigSigner<N, K>`, lands behind the
/// existing `multisig` Cargo feature). V3.0 only constructs
/// `Engine<SoloSigner>`. The trait is sealed; see [`signer`].
///
/// # Lifecycle
///
/// Construction goes through one of the lifecycle methods:
///
/// - [`Engine::create`] — fresh wallet (BIP-39 seed for mainnet/stagenet,
///   raw 32-byte seed for testnet/fakechain).
/// - [`Engine::open_full`] — open an existing `Capability::Full`
///   wallet with the user's password.
/// - [`Engine::open_view_only`] — open an existing `Capability::ViewOnly`
///   wallet (no spend material).
/// - [`Engine::open_hardware_offload`] — open an existing
///   `Capability::HardwareOffload` wallet (signing happens out-of-band).
/// - [`Engine::change_password`] — rotate the user-supplied password
///   without rederiving the master seed.
/// - [`Engine::close`] — flush state to disk and release the advisory
///   lock; refuses if any [`PendingTx`] is in flight.
///
/// All six methods land in the lifecycle commit; this commit defines
/// the struct shape and the read-only accessor surface that those
/// methods produce.
///
/// # Locking discipline
///
/// Per cross-cutting lock 3, this type's methods follow the
/// `&self` for queries / `&mut self` for mutations split. The
/// JSON-RPC server binary wraps a `Engine<S>` in
/// `std::sync::Arc<tokio::sync::RwLock<Engine<S>>>`; the lock is the
/// caller's responsibility, not `Engine`'s. CLI and tests can hold a
/// `Engine<S>` directly without any lock.
///
/// # Drop semantics
///
/// `Engine<S>` does not implement `Drop`. The secret-bearing field
/// [`AllKeysBlob`] has its own `Drop` impl that zeroizes spend / view /
/// ML-KEM-DK material; [`WalletFile`] has its own `Drop` for the file
/// KEK and lock release. Composing types that already wipe correctly
/// is sound; adding a wrapper `Drop` here would risk shadowing the
/// inner ones at compile time without changing behavior at run time.
///
/// [`PendingTx`]: error::PendingTxError
// `D: DaemonEngine` and `L: LedgerEngine` are more private than this
// `pub` item: per `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §2 preamble,
// the Stage 1 trait surfaces are `pub(crate)` for V3.0 and revisable
// to `pub` at V3.2 alongside the JSON-RPC server cutover. External
// callers reach the daemon and ledger surfaces via inherent methods
// on `Engine<S>` (the defaults `D = DaemonClient` and
// `L = LocalLedger` plug in transparently); they cannot name `D` or
// `L` themselves and never need to. Stage 4's trait promotion
// deletes this allow attribute together with the sibling annotations
// (mod.rs inherent impls; lifecycle.rs's `OpenedEngine` / its
// inherent impl / signer-agnostic `Engine` impl; merge.rs /
// pending.rs / refresh.rs inherent impls) in a single sweep —
// they're all the same architectural relationship surfacing at each
// `pub` site.
#[allow(private_bounds)]
pub struct Engine<
    S: EngineSignerKind,
    D: DaemonEngine = DaemonClient,
    L: LedgerEngine = LocalLedger,
    R: RefreshEngine = LocalRefresh,
> {
    /// On-disk envelope: `.wallet.keys` (region 1) +
    /// `.wallet` (region 2). Owns the advisory lock and the
    /// per-session `prefs_hmac_key`. Region 1 is write-once after
    /// [`Engine::create`]; only `change_password` rewraps the file_kek.
    file: WalletFile,

    /// Identity material rederived from the master seed at every open.
    /// Holds Ed25519 spend / view scalars and the ML-KEM-768 decap key;
    /// these are wiped on drop by [`AllKeysBlob`]'s own `Drop` impl.
    /// Never serialized; persistence happens via the `master_seed_64`
    /// in region 1 of the wallet file.
    ///
    /// Read by [`Engine::keys`]; that accessor is `pub(crate)` and used
    /// by `Engine::refresh` (to assemble a `Scanner` per attempt) and
    /// by Phase 2 sign / proof code paths inside this crate.
    keys: AllKeysBlob,

    /// Persistent wallet state plus its runtime-only index projection,
    /// aggregated under a single [`std::sync::RwLock`] by [`LocalLedger`].
    ///
    /// The aggregate carries:
    ///
    /// - The [`shekyl_engine_state::WalletLedger`] — scanner-derived
    ///   transfers, bookkeeping (subaddress registry, labels, address
    ///   book, account tags), tx metadata (`tx_keys`, scanned pool
    ///   txs), and the sync-state block. **Reservations do not live
    ///   here** — see `reservations` below and the `pending` module's
    ///   docstring.
    /// - The [`shekyl_engine_state::LedgerIndexes`] — runtime-only
    ///   indexes derived from chain replay (key-image / pubkey lookup
    ///   maps, staker-pool accrual aggregate). Per the
    ///   `RuntimeWalletState audit` Decision Log entry (2026-04-25),
    ///   these fields are reconstructible from the [`WalletLedger`]
    ///   plus daemon block replay and are never persisted; they are
    ///   rebuilt at every `Engine::open*` and mutated together with
    ///   the `WalletLedger` by `apply_scan_result`.
    ///
    /// Stage 1 PR 2 promotes this aggregate from two `&mut self`-gated
    /// fields to a single `RwLock`-gated [`LocalLedger`] so the
    /// in-process orchestration can call into [`LedgerEngine`] methods
    /// through `&self`. The trait surface (commit 1) and the field
    /// shape (this commit) are co-aligned: [`LocalLedger`] is the
    /// Stage 1 implementor.
    ///
    /// [`LedgerEngine`]: traits::LedgerEngine
    ledger: L,

    /// Runtime-only reservation tracker for in-flight
    /// [`PendingTx`](pending::PendingTx) handles. Cross-cutting lock
    /// 4 binds the build / submit / discard state machine; the
    /// 2026-04-26 follow-up Decision Log entry refines storage from
    /// "persisted in `WalletLedger.bookkeeping`" to "runtime field on
    /// `Engine<S>`." See [`pending`] for the full rationale (the
    /// "why runtime-only" section explains why crash-survival is the
    /// wrong design).
    ///
    /// `Engine::close` (lifecycle commit) consults
    /// `outstanding_pending_txs()` and refuses with
    /// [`OpenError::OutstandingPendingTx`](error::OpenError::OutstandingPendingTx)
    /// when any reservation is in flight, so the only crash-recovery
    /// path that could lose data here is one where the user never
    /// gets to call submit / discard — and on that path the right
    /// behavior is "the reservation is gone, the outputs become
    /// spendable again."
    pub(crate) reservations: BTreeMap<pending::ReservationId, pending::Reservation>,

    /// Monotonic counter that produces [`pending::ReservationId`] values.
    /// Process-local; resets to zero on every `Engine::open*`. The
    /// counter is only exposed through the `pending` helpers, never
    /// directly to callers.
    pub(crate) next_reservation_id: u64,

    /// User preferences per the layer-2 plaintext+HMAC contract in
    /// [`docs/WALLET_PREFS.md`]. Loaded at open, saved on
    /// [`Engine::change_password`] / [`Engine::close`].
    prefs: WalletPrefs,

    /// Engine → daemon connection. Cloneable; shared by clone with the
    /// scanner and the tx-submission paths so each can issue daemon
    /// RPCs without touching the wallet's state.
    ///
    /// Generic over `D: DaemonEngine`. Production code defaults `D` to
    /// [`DaemonClient`] (a thin wrapper over
    /// `shekyl_simple_request_rpc::SimpleRequestRpc`); crate-internal
    /// tests substitute `MockDaemon` to drive failure-injection and
    /// deduplication scenarios against the same orchestration logic.
    /// See `crate::engine::traits::daemon` for the trait contract.
    daemon: D,

    /// Cached from `file.network()` for O(1) accessor speed. The
    /// wallet-file region 1 is the source of truth and never changes
    /// after `create`; this cache is therefore stable for the life of
    /// the open `Engine<S>`.
    network: Network,

    /// Cached from `file.capability()` for O(1) accessor speed. Same
    /// stability argument as `network`. Used by the lifecycle
    /// constructors to decide which `open_*` is appropriate (mismatched
    /// capability surfaces as
    /// [`OpenError::CapabilityMismatch`](error::OpenError::CapabilityMismatch))
    /// and by call sites that gate spend operations on
    /// [`Capability::can_spend_locally`].
    capability: Capability,

    /// Single-flight slot for [`Engine::start_refresh`]. Held by the
    /// engine for the lifetime of the open wallet; claimed (and
    /// guarded) by the producer task `run_refresh_task` for the
    /// duration of one refresh. A racing `start_refresh` finds the
    /// flag set and returns
    /// [`RefreshError::AlreadyRunning`](error::RefreshError::AlreadyRunning).
    ///
    /// Independent of the cross-cutting RwLock around `Engine<S>`:
    /// the slot is its own `Arc<AtomicBool>` so the slot-claim path
    /// only needs a brief shared read of the engine to clone the
    /// flag, not a write borrow. The producer task holds a
    /// [`SlotGuard`](refresh::SlotGuard) that releases the flag on
    /// task exit (RAII).
    refresh_slot: refresh::RefreshSlot,

    /// Producer-side [`RefreshEngine`] implementor.
    ///
    /// Per [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`] §7.X C5
    /// (`Engine<S, D, L, R>` parameterization), the engine owns one
    /// `R: RefreshEngine` for the lifetime of the open wallet; the
    /// orchestrator's refresh paths (`Engine::start_refresh` /
    /// `Engine::refresh`) dispatch the per-attempt producer body
    /// through the trait surface. Production callers default
    /// `R = LocalRefresh`, constructed at every `Engine::create` /
    /// `Engine::open_*` site by moving a freshly-derived
    /// [`ViewMaterial`](view_material::ViewMaterial) into
    /// `LocalRefresh::new`.
    ///
    /// # Why `Arc<R>` rather than `R`
    ///
    /// `run_refresh_task` takes an `Arc<RwLock<Engine<...>>>` because
    /// the orchestrator and the merge path share the same engine
    /// instance. The producer body (`produce_scan_result`) is long-
    /// running — network round-trips plus per-block scan — and must
    /// **not** hold any engine borrow across its `.await` boundary:
    /// the merge path needs the write half of the `RwLock` to land
    /// the scan result, and a read-borrow held through the scan
    /// would deadlock the merge.
    ///
    /// Holding the implementor as `Arc<R>` lets the orchestrator
    /// `Arc::clone` it out of the read-lock in a single brief borrow
    /// and then dispatch the trait call lock-free. The `&self`
    /// receiver on the trait method composes naturally: the cloned
    /// `Arc<R>` keeps `R` alive for the future's lifetime, the trait
    /// implementor's interior state is accessed through `&*arc` (free
    /// of borrow-on-Engine). `LocalRefresh`'s `ViewMaterial` remains
    /// owned-and-non-Clone at the implementor level; the Arc wraps
    /// the implementor, not the secret.
    ///
    /// # Visibility for trait-dispatch (Stage 4)
    ///
    /// Holding the implementor by-Arc on `Engine` makes the producer
    /// wipe-on-drop chain run when the last `Arc<R>` reference drops
    /// — typically at wallet close (today: `Engine::close`; Stage 4:
    /// actor shutdown). The Arc's strong count is exactly 1 in
    /// steady state (engine owns the only handle); the producer
    /// briefly bumps it to 2 for the duration of one
    /// `produce_scan_result` call, then drops back to 1 when the
    /// future settles. The Stage 4 actor cutover replaces this field
    /// with an actor handle; the trait surface stays the same.
    ///
    /// [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`]: ../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md
    pub(crate) refresh: std::sync::Arc<R>,

    /// Compile-time signer-kind dispatch. The actual key material lives
    /// in [`Engine::keys`] (for `SoloSigner`); this marker exists so
    /// the V3.1 multisig type can name distinct method signatures via
    /// associated items on [`EngineSignerKind`] without the V3.0 build
    /// paying a runtime branch on every send.
    _signer: PhantomData<S>,
}

impl<S: EngineSignerKind, D: DaemonEngine + std::fmt::Debug, L: LedgerEngine, R: RefreshEngine>
    std::fmt::Debug for Engine<S, D, L, R>
{
    /// Redacted debug output. Specific reasons each field is or is not
    /// printed:
    ///
    /// - `file` — passes through to [`WalletFile`]'s own `Debug`, which
    ///   already redacts sealed material and prints only filesystem
    ///   paths and the public `network` / `capability`.
    /// - `keys` — never printed. [`AllKeysBlob`] holds spend / view
    ///   secret scalars; the type does not implement `Debug` and
    ///   we do not want a stringly-typed leak path here.
    /// - `ledger`, `prefs` — printed as opaque `<…>` markers. The
    ///   `ledger` field is the [`LocalLedger`] aggregate (the
    ///   [`shekyl_engine_state::WalletLedger`] plus the rebuilt-on-open
    ///   [`shekyl_engine_state::LedgerIndexes`]); both halves contain
    ///   user labels (already typed as
    ///   [`shekyl_engine_state::LocalLabel`] with redacting `Debug`,
    ///   per cross-cutting lock 9), but a wallet-level dump would be
    ///   noisy and add nothing not already available via the per-block
    ///   accessors.
    /// - `daemon` — passes through to [`DaemonClient`]'s `Debug`, which
    ///   includes the daemon URL but no auth credentials (see
    ///   [`shekyl_simple_request_rpc::SimpleRequestRpc`]).
    /// - `network`, `capability` — printed verbatim; these are cached
    ///   public values from region 1 of the wallet file.
    /// - `reservations` — printed as a count, not contents. The
    ///   reservations carry recipient addresses and amounts; we expose
    ///   only the cardinality so a `Debug` dump cannot leak in-flight
    ///   transaction recipients.
    /// - `next_reservation_id` — printed verbatim. The counter is a
    ///   process-local monotonic `u64` with no observable secret
    ///   content; surfacing it helps debugging without leaking
    ///   reservation details.
    /// - `refresh` — printed as an opaque `<redacted: RefreshEngine>`
    ///   marker. The producer holds view-and-spend material per
    ///   §5.4.7 R4; surfacing the implementor's `Debug` would risk
    ///   leaking that material through a downstream sink. The
    ///   producer's identity type is also printed for diagnostic
    ///   purposes (e.g., distinguishing `LocalRefresh` from a future
    ///   actor-backed implementor at Stage 4); `type_name` is
    ///   secret-free.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("file", &self.file)
            .field("keys", &"<redacted: AllKeysBlob>")
            .field("ledger", &"<…>")
            .field("reservations", &self.reservations.len())
            .field("next_reservation_id", &self.next_reservation_id)
            .field("prefs", &"<…>")
            .field("daemon", &self.daemon)
            .field("network", &self.network)
            .field("capability", &self.capability)
            .field("refresh_running", &self.refresh_slot.is_claimed())
            .field("refresh", &"<redacted: RefreshEngine>")
            .field("refresh_kind", &std::any::type_name::<R>())
            .field("signer_kind", &std::any::type_name::<S>())
            .finish()
    }
}

/// RAII guard returned by [`Engine::ledger`]: holds a read lock on
/// the wallet's [`LocalLedger`] and derefs transparently to
/// [`WalletLedger`].
///
/// The guard is opaque: external callers cannot observe the
/// crate-private `LedgerState` aggregate or the `LedgerIndexes`
/// half — the [`Deref`] impl projects to `WalletLedger`, the only
/// type the public surface exposes. The `inner` field is private,
/// so even though its type names the `pub(crate)` `LedgerState`,
/// the `private_interfaces` lint does not fire (the type only
/// appears in private positions). The lint *would* fire if the
/// field were `pub`; it is deliberately not. Source compatibility
/// with the pre-Stage-1 `&WalletLedger` accessor is preserved by
/// the [`Deref`] impl, so calls of the form
/// `engine.ledger().some_wallet_ledger_method()` continue to compile
/// and behave identically.
///
/// A future refactor may project directly to `WalletLedger` via
/// `std::sync::RwLockReadGuard::map` (currently
/// `mapped_lock_guards`-feature-gated) or `parking_lot::RwLock`,
/// which would remove `LedgerState` from the field type entirely
/// and eliminate the rustdoc "private item" warning on the doc
/// comment below. Tracked under V3.x in `docs/FOLLOWUPS.md` →
/// "`LedgerReadGuard` field type leaks crate-private `LedgerState`".
///
/// Hold the guard for the minimum span necessary; concurrent writers
/// (`apply_scan_result` and the [`pending`]-module mutators) cannot
/// acquire the write lock while any reader is live.
///
/// [`Deref`]: std::ops::Deref
pub struct LedgerReadGuard<'a> {
    inner: std::sync::RwLockReadGuard<'a, LedgerState>,
}

impl std::ops::Deref for LedgerReadGuard<'_> {
    type Target = WalletLedger;

    fn deref(&self) -> &WalletLedger {
        &self.inner.ledger
    }
}

// `D: DaemonEngine` and `L: LedgerEngine` private-bound: see the
// rationale on the `pub struct Engine` definition in this file.
#[allow(private_bounds)]
impl<S: EngineSignerKind, D: DaemonEngine, L: LedgerEngine, R: RefreshEngine> Engine<S, D, L, R> {
    /// Network this wallet is bound to. Cached from
    /// [`WalletFile`]'s region 1 at construction; stable for the life
    /// of the open wallet.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Capability mode of this wallet (full / view-only /
    /// hardware-offload). Cached from [`WalletFile`]'s region 1 at
    /// construction; stable for the life of the open wallet.
    pub fn capability(&self) -> Capability {
        self.capability
    }

    /// Borrow the underlying [`WalletFile`] for filesystem-path,
    /// safety-overrides, and prefs-HMAC-key access. The file's
    /// `network()` and `capability()` accessors agree with the
    /// cache on `Engine`.
    pub fn file(&self) -> &WalletFile {
        &self.file
    }

    /// Borrow user preferences. Read-only; preference rotation goes
    /// through dedicated methods that re-HMAC the body and atomic-write
    /// both files together.
    pub fn prefs(&self) -> &WalletPrefs {
        &self.prefs
    }

    /// Borrow the daemon RPC client. Cloneable for handing to the
    /// scanner / tx-submission paths.
    ///
    /// The return type is `&D`, the type-parameter slot for the
    /// daemon. The production default `D = DaemonClient` resolves
    /// this to `&DaemonClient`; crate-internal tests substitute
    /// `MockDaemon` and observe the same accessor shape.
    pub fn daemon(&self) -> &D {
        &self.daemon
    }

    /// Crate-internal access to the rederived identity material.
    ///
    /// **Not** part of the public API. Spend / sign / proof code paths
    /// inside `shekyl-engine-core` go through this accessor; the
    /// returned reference must not escape the crate. Phase 2 will add
    /// dedicated method-level surfaces (`sign_transfer`, `tx_proof`,
    /// `reserve_proof`) that take borrowed inputs and return finished
    /// artifacts, so call sites elsewhere never need a borrow on
    /// [`AllKeysBlob`] directly.
    // After C5's trait-dispatch migration, the only previous reader
    // (`build_scanner_from_keys` in `refresh.rs`) is `#[cfg(test)]`-gated
    // alongside the legacy producer body; `LocalRefresh` constructs its
    // scanner from `ViewMaterial` derived at `Engine::assemble` time.
    // C5β re-evaluates whether `keys()` survives the producer-body
    // deletion or is itself deleted with the deprecation cycle; Phase 2's
    // `sign_transfer` / `tx_proof` / `reserve_proof` will need either
    // this accessor or a dedicated method-level surface.
    #[allow(dead_code)]
    pub(crate) fn keys(&self) -> &AllKeysBlob {
        &self.keys
    }

    /// Test-only setter that replaces the producer-side
    /// [`RefreshEngine`] implementor on this engine.
    ///
    /// Stage 1 PR 4 C6α introduces this surface so hybrid tests
    /// can swap a vanilla [`LocalRefresh`] for a
    /// [`FaultInjecting<LocalRefresh>`](super::fault_injecting_refresh::FaultInjecting)
    /// wrapper, exercising the orchestrator's retry / cancellation /
    /// merge paths against the same production implementor with the
    /// trait boundary perturbed. Per the Round 5 substrate-decision
    /// amendment (commit `8484e669a`), the test-substrate paradigm
    /// is composition: production types with optional fault
    /// injection at the trait boundary, not Mock-X parallel
    /// implementations.
    ///
    /// # Visibility
    ///
    /// `pub(crate)` and gated by `#[cfg(any(test, feature =
    /// "test-helpers"))]` per the F-Mock-1 symmetry pin: production
    /// builds do not compile this method, and crate-internal tests /
    /// downstream `test-helpers`-feature consumers reach it through
    /// the engine handle. The feature itself is declared in
    /// [`Cargo.toml`](../../Cargo.toml)'s `[features]` table; no
    /// downstream consumer exists pre-genesis, the feature is
    /// declared so the gating composes correctly when one emerges.
    ///
    /// # Arc replacement semantics
    ///
    /// The engine holds the implementor as `Arc<R>` (see the
    /// `refresh` field rustdoc above for the lock-free dispatch
    /// rationale). This setter constructs a fresh `Arc<R>` around
    /// `refresh` and replaces the previous reference; any in-flight
    /// `produce_scan_result` future spawned before the swap keeps
    /// its strong reference to the prior implementor until the
    /// future settles, then drops it. Tests must not call this
    /// setter while a refresh is in flight (the engine's
    /// single-flight slot guards against accidental concurrent
    /// `start_refresh`, but does not prevent setter-during-refresh
    /// races); per the F-Mock-2 queue contract, tests are expected
    /// to install the wrapper before driving any refresh.
    // C6α introduces the wrapper substrate; the first consumers of
    // `replace_refresh` land in C6β / C6γ when the hybrid tests
    // rewire from MockLedger/MockDaemon onto the FaultInjecting<L>
    // and TestDaemon shapes. Pre-genesis no production caller exists.
    #[cfg(any(test, feature = "test-helpers"))]
    #[allow(dead_code)]
    pub(crate) fn replace_refresh(&mut self, refresh: R) {
        self.refresh = std::sync::Arc::new(refresh);
    }
}

// `D: DaemonEngine` private-bound: see the rationale on the `pub
// struct Engine` definition in this file. The `L = LocalLedger`
// specialization is intentional: [`Engine::ledger`] returns a
// [`LedgerReadGuard`] tied to the in-process [`LocalLedger`]'s
// [`std::sync::RwLockReadGuard`]; once Stage 4 promotes the trait
// `LedgerEngine` to a richer surface (or replaces this accessor
// with a trait-level read-state method), this block dissolves.
#[allow(private_bounds)]
impl<S: EngineSignerKind, D: DaemonEngine, R: RefreshEngine> Engine<S, D, LocalLedger, R> {
    /// Borrow the persistent ledger for read-only queries (transfers,
    /// bookkeeping entries, tx metadata, sync cursor). Mutation goes
    /// through the methods on [`Engine`] that the lifecycle / refresh /
    /// send commits add — never through this borrow.
    ///
    /// The return value is a [`LedgerReadGuard`] that holds a
    /// [`std::sync::RwLockReadGuard`] over [`LocalLedger`]'s state
    /// for the borrow's lifetime; the guard derefs transparently to
    /// `&WalletLedger` so existing call sites that read through this
    /// accessor are source-compatible. Drop the guard to release the
    /// read lock and allow concurrent writers to acquire it.
    ///
    /// # Public-API signature change vs. pre-Stage-1
    ///
    /// Pre-Stage-1 this method returned `&WalletLedger`; Stage 1 PR 2
    /// changes the return type to `LedgerReadGuard<'_>` so the borrow
    /// is tied to a [`std::sync::RwLock`] read guard rather than a
    /// flat field. Source-compatible upgrade paths:
    ///
    /// - **Call-style read access** (`engine.ledger().balance()`,
    ///   `engine.ledger().transfers()`, …) keeps working unchanged
    ///   via the [`std::ops::Deref`] impl on [`LedgerReadGuard`].
    /// - **Code that named the old return type explicitly** — e.g.
    ///   `let l: &WalletLedger = engine.ledger();` or `fn(&WalletLedger)
    ///   = Engine::ledger;` — must change either to bind the guard
    ///   (`let l = engine.ledger(); let l: &WalletLedger = &*l;`) or
    ///   accept `LedgerReadGuard<'_>` as the named type.
    /// - **Long-lived borrows held across `.await`** are no longer
    ///   sound: holding the guard across an await blocks writers, so
    ///   refactor such call sites to drop the guard before awaiting.
    ///
    /// Specialized to `L = LocalLedger` because the guard is tied
    /// to that implementor's lock; mocked-`L` tests (commit 6) do
    /// not exercise this accessor.
    pub fn ledger(&self) -> LedgerReadGuard<'_> {
        LedgerReadGuard {
            inner: self.ledger.read(),
        }
    }
}

// ── Bench-internals helpers (gated; see `lib.rs`'s `__bench_internals`)
//
// These free functions live in this module so they can name the
// otherwise-private `Engine.ledger` field; they are re-exported through
// `crate::__bench_internals` for `engine_trait_bench_ledger_balance{,_iai}.rs`
// without widening the field's production visibility. The pattern is
// the same one PR 1 uses for `LedgerSnapshot::from_ledger_for_bench`:
// the hot-path code stays in its production module while the bench
// surface is unlocked with a focused feature flag.

/// Borrow the engine's [`LocalLedger`] field directly. See
/// [`crate::__bench_internals::engine_local_ledger_for_bench`] for the
/// public-facing wrapper and the use-site rationale.
#[cfg(feature = "bench-internals")]
pub fn engine_local_ledger_for_bench(
    engine: &Engine<SoloSigner, DaemonClient, LocalLedger>,
) -> &LocalLedger {
    &engine.ledger
}

/// Project the wallet's balance through the
/// [`LedgerEngine::balance`](traits::LedgerEngine::balance) trait
/// method, dispatched on `engine.ledger`. See
/// [`crate::__bench_internals::engine_balance_for_bench`] for the
/// public-facing wrapper and the use-site rationale.
///
/// The trait surface is `pub(crate)`, so this thin wrapper performs
/// the trait call inside the crate (where the trait is visible) and
/// surfaces the [`shekyl_scanner::BalanceSummary`] result across the
/// bench-target boundary.
#[cfg(feature = "bench-internals")]
pub fn engine_balance_for_bench(
    engine: &Engine<SoloSigner, DaemonClient, LocalLedger>,
) -> shekyl_scanner::BalanceSummary {
    use crate::engine::traits::LedgerEngine;
    engine.ledger.balance()
}

/// Project a wallet's account public address through the
/// `KeyEngine::account_public_address` trait method (the trait is
/// `pub(crate)` so rustdoc intra-doc links to it from a `pub`
/// item would render as private-link warnings; plain backticks
/// throughout match the convention used in the bench files'
/// module-level docstrings), dispatched on a standalone
/// [`local_keys::LocalKeys`] fixture. See
/// [`crate::__bench_internals::engine_account_public_address_for_bench`]
/// for the public-facing wrapper and the use-site rationale.
///
/// # Why this takes `&LocalKeys` and not `&Engine<...>`
///
/// `Engine<S, D, L>` holds `keys: AllKeysBlob` (the wallet key
/// material) but does not yet hold the `KeyEngine`-implementing
/// [`local_keys::LocalKeys`] as a field — that orchestrator
/// integration is `KeyEngine` PR-5 territory per
/// `docs/design/STAGE_1_PR_3_KEY_ENGINE.md` §2.1.1 (the Round 4a
/// workflow-shape pivot). The post-M3-series state preserves
/// `LocalKeys` as the `KeyEngine` implementor
/// (`#[allow(dead_code)]` per the orchestrator-integration
/// deferral) without wiring it into the `Engine` struct.
///
/// Given the substrate, the bench fixture is a standalone
/// `Box<LocalKeys>` rather than the unified
/// `(Box<Engine<SoloSigner, DaemonClient, LocalLedger>>, TempDir)`
/// shape the LedgerEngine bench uses. This divergence from the
/// canonical `engine_trait_bench_*` fixture shape is forced by the
/// substrate, not chosen for convenience; it is documented in the
/// bench module's file-level docstring and in the close-out PR's
/// pre-flight §1.2.
///
/// The bench still classifies under the `engine_trait_bench_*`
/// threshold class via the function-name routing discipline (per
/// `STAGE_0_HARNESS.md` §3.3.1's `classify()` rule, which routes on
/// the `#[library_benchmark]` function name, not on fixture shape).
///
/// # Why this returns `usize` rather than `&AccountPublicAddress`
///
/// The natural return type of the trait method is
/// `&AccountPublicAddress`, but that type is `pub(crate)` — exposing
/// it through this `pub fn`'s signature would widen the crate's
/// public API beyond the `bench-internals` gate. The helper instead
/// returns a `usize` summary (the sum of both field byte-lengths),
/// which is a primitive `pub` type. The trait call itself is
/// preserved against compiler elision by the internal
/// `std::hint::black_box(...)` around the address reference; the
/// returned length sum is a small additional load (two `Vec::len()`
/// metadata reads — the field bytes themselves are not touched) that
/// gives the criterion / iai-callgrind bench loops something
/// observable to consume so the bench function's overall result is
/// not elided. The measurement surface is unchanged from the natural
/// shape; only the API-widening footprint differs (zero added types
/// in `__bench_internals`).
#[cfg(feature = "bench-internals")]
pub fn engine_account_public_address_for_bench(keys: &local_keys::LocalKeys) -> usize {
    use crate::engine::traits::key::KeyEngine;
    let addr = std::hint::black_box(keys.account_public_address());
    addr.pqc_public_key.len() + addr.classical_address_bytes.len()
}
