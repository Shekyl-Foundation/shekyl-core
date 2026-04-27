// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shekyl wallet domain orchestrator.
//!
//! `shekyl-wallet-core::wallet` is the home of the [`Wallet`](Wallet) type
//! that composes the file envelope ([`shekyl_wallet_file::WalletFile`]),
//! identity material ([`shekyl_crypto_pq::account::AllKeysBlob`]), the
//! ledger ([`shekyl_wallet_state::WalletLedger`]), preferences
//! ([`shekyl_wallet_prefs::WalletPrefs`]), the daemon RPC client, and
//! the per-process scanning surface into a single audited domain
//! orchestrator. The CLI ([`shekyl-cli`]) and the JSON-RPC server
//! ([`shekyl-wallet-rpc`]) sit on top of this surface, never reaching
//! around it.
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
//!   single flat [`SubaddressIndex`](shekyl_wallet_state::SubaddressIndex)
//!   namespace; index 0 is the primary address. Exchanges that need
//!   stronger isolation use multiple wallet files (separate keys are a
//!   strictly stronger boundary than wallet2's account-shared keys).
//! - **The `export_outputs` / `import_outputs` / `export_key_images` /
//!   `import_key_images` four-call dance.** Air-gapped flows use two
//!   typed bundle types (`UnsignedTxBundle`, `SignedTxBundle`) — see
//!   Phase 2d.
//! - **A god-object `Wallet` with hundreds of public members.** Every
//!   [`Wallet`] member's mutability and locking discipline is explicit;
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
//!    RPC boundary by [`shekyl-wallet-rpc`].
//! 3. **Locking discipline** — `&self` queries / `&mut self` mutations.
//!    The RPC binary wraps in [`Arc<RwLock<Wallet>>`].
//! 4. **`PendingTx` lifetime** — process-local, chain-state-tagged,
//!    reservation-bearing. Lands with the build/submit/discard methods.
//! 5. **`Network`** — closed enum re-exported as [`Network`] from
//!    [`shekyl_address`]; daemon mismatch is `OpenError::NetworkMismatch`.
//! 6. **Subaddress hierarchy** — flat
//!    [`SubaddressIndex`](shekyl_wallet_state::SubaddressIndex). No
//!    account level.
//! 7. **`RefreshHandle`** — cancel-on-drop RAII, single-flight via
//!    `&mut self`. Lands with `Wallet::refresh`.
//! 8. **Fee priority** — `FeePriority { Economy | Standard | Priority |
//!    Custom(NonZeroU64) }` over daemon `get_fee_estimates`. Lands with
//!    `build_pending_tx`.
//! 9. **Logging** — `tracing` spans throughout, two-layer secret
//!    redaction via [`shekyl_wallet_state::LocalLabel`] (type layer) and
//!    a redacting subscriber field formatter (subscriber layer). Lands
//!    with the `tracing` wiring commit.
//! 10. **KAT regression** — plain `cargo test --workspace`,
//!     [`docs/test_vectors/`] under `CODEOWNERS`.
//! 11. **Decision Log** — every binding sub-decision in this module
//!     ships an entry in [`docs/V3_WALLET_DECISION_LOG.md`].
//!
//! # Status (as of this commit)
//!
//! Type-layer foundations + the [`Wallet<S>`](Wallet) struct itself with
//! its accessor surface, the [`DaemonClient`] thin wrapper, and the
//! lifecycle methods on `Wallet<SoloSigner>`. [`Wallet::create`] and
//! [`Wallet::open_full`] ship end-to-end against the
//! [`shekyl_wallet_file::WalletFile`] envelope and the
//! [`shekyl_crypto_pq::account::AllKeysBlob`] re-derivation path;
//! [`Wallet::open_view_only`] and [`Wallet::open_hardware_offload`]
//! ship as signature stubs that return
//! [`OpenError::CapabilityNotYetImplemented`](error::OpenError::CapabilityNotYetImplemented)
//! pending the matching `shekyl-crypto-pq` constructors.
//! [`Wallet::change_password`] and [`Wallet::close`] ship for every
//! signer kind. The struct is composition over field type — every
//! member's purpose, mutability discipline, and ownership are
//! explicit:
//!
//! | Field                 | Type                                                 | Provenance                              |
//! | --------------------- | ---------------------------------------------------- | --------------------------------------- |
//! | `file`                | [`shekyl_wallet_file::WalletFile`]                   | `.wallet.keys` envelope IO              |
//! | `keys`                | [`shekyl_crypto_pq::account::AllKeysBlob`]           | rederived from master seed              |
//! | `ledger`              | [`shekyl_wallet_state::WalletLedger`]                | aggregator over the four blocks         |
//! | `indexes`             | [`shekyl_wallet_state::LedgerIndexes`]               | rebuilt at open from `ledger`           |
//! | `reservations`        | `BTreeMap<ReservationId, Reservation>`               | runtime-only `PendingTx` tracker        |
//! | `next_reservation_id` | `u64`                                                | process-local monotonic counter         |
//! | `prefs`               | [`shekyl_wallet_prefs::WalletPrefs`]                 | plaintext-with-HMAC layer 2             |
//! | `daemon`              | [`DaemonClient`]                                     | thin wrapper around `SimpleRequestRpc`  |
//! | `network`             | [`Network`]                                          | cached from `file.network()`            |
//! | `capability`          | [`Capability`]                                       | cached from `file.capability()`         |
//! | `_signer`             | `PhantomData<S>`                                     | compile-time signer dispatch            |
//!
//! `network` and `capability` are cached on the struct so the hot
//! `Wallet::network()` / `Wallet::capability()` accessors are infallible
//! and O(1). The cache is established at construction and never drifts:
//! `WalletFile`'s region 1 is write-once after `create`, and region 1 is
//! the only place either field is sourced from.
//!
//! # Runtime-only state on `Wallet`
//!
//! Two fields on `Wallet<S>` are deliberately runtime-only and are
//! never serialized to disk:
//!
//! - [`indexes`](Wallet) (`LedgerIndexes`): key-image / pubkey lookup
//!   maps and the staker-pool aggregate. Rebuilt at every
//!   `Wallet::open*` from `self.ledger.ledger`.
//! - [`reservations`](Wallet) (`BTreeMap<ReservationId, Reservation>`):
//!   the in-flight transaction reservation tracker. Cross-cutting
//!   lock 4 binds the *behavioral* shape (build reserves, discard
//!   releases, submit consumes, close errors with outstanding); the
//!   2026-04-26 follow-up Decision Log entry refines the storage
//!   location to a runtime field rather than the persisted
//!   bookkeeping block. See [`pending`] for the full rationale.
//!
//! Per cross-cutting lock 7, the cancel-on-drop refresh handle is
//! **not** a `Wallet` field; it is *returned* by `Wallet::refresh`
//! and held by the caller, so its `Drop` implementation drives the
//! cancellation token. A `Wallet`-internal handle would defeat the
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
pub mod error;
pub mod lifecycle;
pub mod merge;
pub mod network;
pub mod pending;
pub mod refresh;
pub mod signer;

#[cfg(test)]
pub(crate) mod test_support;

pub use capability::Capability;
pub use daemon::DaemonClient;
pub use error::{IoError, KeyError, OpenError, PendingTxError, RefreshError, SendError, TxError};
pub use lifecycle::{CapabilityInput, Credentials, OpenedWallet, WalletCreateParams};
pub use network::Network;
pub use pending::{
    FeePriority, PendingTx, ReservationId, TxHash, TxRecipient, TxRecipientSummary, TxRequest,
};
pub use refresh::{RefreshOptions, RefreshReorgEvent, RefreshSummary};
pub use signer::{SoloSigner, WalletSignerKind};

use std::collections::BTreeMap;
use std::marker::PhantomData;

use shekyl_crypto_pq::account::AllKeysBlob;
use shekyl_wallet_file::WalletFile;
use shekyl_wallet_prefs::WalletPrefs;
use shekyl_wallet_state::{LedgerIndexes, WalletLedger};

/// The Shekyl V3 wallet domain orchestrator.
///
/// `Wallet<S>` composes the file envelope, identity material, persistent
/// ledger, user preferences, and daemon RPC connection into a single
/// audited surface. The CLI and JSON-RPC server both sit on top of
/// this type; neither reaches around it to the underlying crates.
///
/// # Type parameter `S`
///
/// `S: WalletSignerKind` selects between the V3.0
/// [`SoloSigner`] (in-process signing, single spend secret) and the
/// V3.1 multisig path (`MultisigSigner<N, K>`, lands behind the
/// existing `multisig` Cargo feature). V3.0 only constructs
/// `Wallet<SoloSigner>`. The trait is sealed; see [`signer`].
///
/// # Lifecycle
///
/// Construction goes through one of the lifecycle methods:
///
/// - [`Wallet::create`] — fresh wallet (BIP-39 seed for mainnet/stagenet,
///   raw 32-byte seed for testnet/fakechain).
/// - [`Wallet::open_full`] — open an existing `Capability::Full`
///   wallet with the user's password.
/// - [`Wallet::open_view_only`] — open an existing `Capability::ViewOnly`
///   wallet (no spend material).
/// - [`Wallet::open_hardware_offload`] — open an existing
///   `Capability::HardwareOffload` wallet (signing happens out-of-band).
/// - [`Wallet::change_password`] — rotate the user-supplied password
///   without rederiving the master seed.
/// - [`Wallet::close`] — flush state to disk and release the advisory
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
/// JSON-RPC server binary wraps a `Wallet<S>` in
/// `std::sync::Arc<tokio::sync::RwLock<Wallet<S>>>`; the lock is the
/// caller's responsibility, not `Wallet`'s. CLI and tests can hold a
/// `Wallet<S>` directly without any lock.
///
/// # Drop semantics
///
/// `Wallet<S>` does not implement `Drop`. The secret-bearing field
/// [`AllKeysBlob`] has its own `Drop` impl that zeroizes spend / view /
/// ML-KEM-DK material; [`WalletFile`] has its own `Drop` for the file
/// KEK and lock release. Composing types that already wipe correctly
/// is sound; adding a wrapper `Drop` here would risk shadowing the
/// inner ones at compile time without changing behavior at run time.
///
/// [`PendingTx`]: error::PendingTxError
pub struct Wallet<S: WalletSignerKind> {
    /// On-disk envelope: `.wallet.keys` (region 1) +
    /// `.wallet` (region 2). Owns the advisory lock and the
    /// per-session `prefs_hmac_key`. Region 1 is write-once after
    /// [`Wallet::create`]; only `change_password` rewraps the file_kek.
    file: WalletFile,

    /// Identity material rederived from the master seed at every open.
    /// Holds Ed25519 spend / view scalars and the ML-KEM-768 decap key;
    /// these are wiped on drop by [`AllKeysBlob`]'s own `Drop` impl.
    /// Never serialized; persistence happens via the `master_seed_64`
    /// in region 1 of the wallet file.
    ///
    /// Read by [`Wallet::keys`]; that accessor is `pub(crate)` and used
    /// by `Wallet::refresh` (to assemble a `Scanner` per attempt) and
    /// by Phase 2 sign / proof code paths inside this crate.
    keys: AllKeysBlob,

    /// Persistent wallet state: scanner-derived transfers, bookkeeping
    /// (subaddress registry, labels, address book, account tags), tx
    /// metadata (`tx_keys`, scanned pool txs), and the sync-state
    /// block. Mutated only via the methods on `Wallet<S>` that the
    /// lifecycle / refresh / send commits add. **Reservations do not
    /// live here** — see `reservations` below and the `pending`
    /// module's docstring.
    ledger: WalletLedger,

    /// Runtime-only indexes derived from chain replay: key-image
    /// and pubkey lookup maps, plus the staker-pool accrual
    /// aggregate. Per the `RuntimeWalletState audit` Decision Log
    /// entry (2026-04-25), these fields are reconstructible from
    /// `self.ledger.ledger` plus daemon block replay and are never
    /// persisted. Rebuilt at every `Wallet::open*` and mutated
    /// alongside `self.ledger.ledger` by `apply_scan_result` under
    /// the same `&mut self` borrow.
    indexes: LedgerIndexes,

    /// Runtime-only reservation tracker for in-flight
    /// [`PendingTx`](pending::PendingTx) handles. Cross-cutting lock
    /// 4 binds the build / submit / discard state machine; the
    /// 2026-04-26 follow-up Decision Log entry refines storage from
    /// "persisted in `WalletLedger.bookkeeping`" to "runtime field on
    /// `Wallet<S>`." See [`pending`] for the full rationale (the
    /// "why runtime-only" section explains why crash-survival is the
    /// wrong design).
    ///
    /// `Wallet::close` (lifecycle commit) consults
    /// `outstanding_pending_txs()` and refuses with
    /// [`OpenError::OutstandingPendingTx`](error::OpenError::OutstandingPendingTx)
    /// when any reservation is in flight, so the only crash-recovery
    /// path that could lose data here is one where the user never
    /// gets to call submit / discard — and on that path the right
    /// behavior is "the reservation is gone, the outputs become
    /// spendable again."
    pub(crate) reservations: BTreeMap<pending::ReservationId, pending::Reservation>,

    /// Monotonic counter that produces [`pending::ReservationId`] values.
    /// Process-local; resets to zero on every `Wallet::open*`. The
    /// counter is only exposed through the `pending` helpers, never
    /// directly to callers.
    pub(crate) next_reservation_id: u64,

    /// User preferences per the layer-2 plaintext+HMAC contract in
    /// [`docs/WALLET_PREFS.md`]. Loaded at open, saved on
    /// [`Wallet::change_password`] / [`Wallet::close`].
    prefs: WalletPrefs,

    /// Wallet → daemon connection. Cloneable; shared by clone with the
    /// scanner and the tx-submission paths so each can issue daemon
    /// RPCs without touching the wallet's state.
    daemon: DaemonClient,

    /// Cached from `file.network()` for O(1) accessor speed. The
    /// wallet-file region 1 is the source of truth and never changes
    /// after `create`; this cache is therefore stable for the life of
    /// the open `Wallet<S>`.
    network: Network,

    /// Cached from `file.capability()` for O(1) accessor speed. Same
    /// stability argument as `network`. Used by the lifecycle
    /// constructors to decide which `open_*` is appropriate (mismatched
    /// capability surfaces as
    /// [`OpenError::CapabilityMismatch`](error::OpenError::CapabilityMismatch))
    /// and by call sites that gate spend operations on
    /// [`Capability::can_spend_locally`].
    capability: Capability,

    /// Compile-time signer-kind dispatch. The actual key material lives
    /// in [`Wallet::keys`] (for `SoloSigner`); this marker exists so
    /// the V3.1 multisig type can name distinct method signatures via
    /// associated items on [`WalletSignerKind`] without the V3.0 build
    /// paying a runtime branch on every send.
    _signer: PhantomData<S>,
}

impl<S: WalletSignerKind> std::fmt::Debug for Wallet<S> {
    /// Redacted debug output. Specific reasons each field is or is not
    /// printed:
    ///
    /// - `file` — passes through to [`WalletFile`]'s own `Debug`, which
    ///   already redacts sealed material and prints only filesystem
    ///   paths and the public `network` / `capability`.
    /// - `keys` — never printed. [`AllKeysBlob`] holds spend / view
    ///   secret scalars; the type does not implement `Debug` and
    ///   we do not want a stringly-typed leak path here.
    /// - `ledger`, `prefs` — printed as opaque `<…>` markers. They
    ///   contain user labels (already typed as
    ///   [`shekyl_wallet_state::LocalLabel`] with redacting `Debug`,
    ///   per cross-cutting lock 9), but a wallet-level dump would be
    ///   noisy and add nothing not already available via the per-block
    ///   accessors.
    /// - `daemon` — passes through to [`DaemonClient`]'s `Debug`, which
    ///   includes the daemon URL but no auth credentials (see
    ///   [`shekyl_simple_request_rpc::SimpleRequestRpc`]).
    /// - `network`, `capability` — printed verbatim; these are cached
    ///   public values from region 1 of the wallet file.
    /// - `indexes` — printed as opaque `<…>`; the rebuilt-on-open
    ///   indexes shadow `ledger` and the same redaction argument
    ///   applies.
    /// - `reservations` — printed as a count, not contents. The
    ///   reservations carry recipient addresses and amounts; we expose
    ///   only the cardinality so a `Debug` dump cannot leak in-flight
    ///   transaction recipients.
    /// - `next_reservation_id` — printed verbatim. The counter is a
    ///   process-local monotonic `u64` with no observable secret
    ///   content; surfacing it helps debugging without leaking
    ///   reservation details.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("file", &self.file)
            .field("keys", &"<redacted: AllKeysBlob>")
            .field("ledger", &"<…>")
            .field("indexes", &"<…>")
            .field("reservations", &self.reservations.len())
            .field("next_reservation_id", &self.next_reservation_id)
            .field("prefs", &"<…>")
            .field("daemon", &self.daemon)
            .field("network", &self.network)
            .field("capability", &self.capability)
            .field("signer_kind", &std::any::type_name::<S>())
            .finish()
    }
}

impl<S: WalletSignerKind> Wallet<S> {
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
    /// cache on `Wallet`.
    pub fn file(&self) -> &WalletFile {
        &self.file
    }

    /// Borrow the persistent ledger for read-only queries (transfers,
    /// bookkeeping entries, tx metadata, sync cursor). Mutation goes
    /// through the methods on [`Wallet`] that the lifecycle / refresh /
    /// send commits add — never through this borrow.
    pub fn ledger(&self) -> &WalletLedger {
        &self.ledger
    }

    /// Borrow user preferences. Read-only; preference rotation goes
    /// through dedicated methods that re-HMAC the body and atomic-write
    /// both files together.
    pub fn prefs(&self) -> &WalletPrefs {
        &self.prefs
    }

    /// Borrow the daemon RPC client. Cloneable for handing to the
    /// scanner; see [`DaemonClient::inner`] for the underlying
    /// transport.
    pub fn daemon(&self) -> &DaemonClient {
        &self.daemon
    }

    /// Crate-internal access to the rederived identity material.
    ///
    /// **Not** part of the public API. Spend / sign / proof code paths
    /// inside `shekyl-wallet-core` go through this accessor; the
    /// returned reference must not escape the crate. Phase 2 will add
    /// dedicated method-level surfaces (`sign_transfer`, `tx_proof`,
    /// `reserve_proof`) that take borrowed inputs and return finished
    /// artifacts, so call sites elsewhere never need a borrow on
    /// [`AllKeysBlob`] directly.
    pub(crate) fn keys(&self) -> &AllKeysBlob {
        &self.keys
    }
}
