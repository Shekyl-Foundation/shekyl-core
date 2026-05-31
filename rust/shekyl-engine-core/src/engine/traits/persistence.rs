// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `PersistenceEngine` trait surface.
//!
//! Per [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`] §2.6 (PR 6 Phase 0a) and
//! [`docs/design/STAGE_1_PR_6_PERSISTENCE_ENGINE.md`] §5.9 (F5(b)), steady-state
//! persistence takes HKDF-derived sealing keys — not passwords. Stage 1
//! implementor: [`shekyl_engine_file::WalletFile`]; Stage 4:
//! `ActorRef<PersistenceActor>` with the same trait.
//!
//! # Backup warning (G4)
//!
//! Wallet files under the user's home directory may be copied by OS backup
//! tools (Time Machine, iCloud Drive, Dropbox). Encrypted blobs still leak to
//! third-party storage; offline password guessing remains a threat. Operators
//! should exclude wallet paths from cloud backup where the platform allows.
//!
//! Do not copy the wallet directory while the advisory lock on the keys file
//! (`<base>.keys`, where `base` is the `.wallet` path) is held. Use
//! [`Engine::close`](super::super::Engine::close)
//! (or process shutdown that runs the close flush) and copy from the filesystem,
//! or [`WalletFile::save_as`](shekyl_engine_file::WalletFile::save_as) to a
//! quiescent destination path.
//!
//! Release binaries should be verified per [`docs/SIGNING.md`](../../../../../docs/SIGNING.md)
//! (L4 — compromised wallet binaries defeat session-key blast-radius discipline).
//!
//! # Durability and nonces
//!
//! On `Ok`, `.wallet` bytes are durable across power loss (`atomic_write_file`:
//! tmp → fsync → rename → fsync parent). Region-2 AEAD uses a fresh 24-byte
//! nonce from the OS CSPRNG on every save — never counter-derived
//! (`seal_state_file` in `shekyl-crypto-pq`).
//!
//! # Stage-4 swap-in (§7)
//!
//! At Stage 4 the `PersistenceEngine` bound is satisfied by an
//! `ActorRef<PersistenceActor>` rather than by the in-process
//! [`shekyl_engine_file::WalletFile`] wrapping the on-disk artifact under a
//! `Mutex`. Trait method signatures do not change; only the implementor type
//! does. Callers that bind against `P: PersistenceEngine` get the swap-in for
//! free. The `impl Future + Send` returns on `save_state` / `save_prefs` /
//! `rotate_password` already match the actor model: at Stage 1 the future is
//! eager (`std::future::ready` wrapping a synchronous body); at Stage 4 the
//! same signature carries a mailbox round-trip.
//!
//! [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`]: ../../../../../docs/V3_ENGINE_TRAIT_BOUNDARIES.md
//! [`docs/design/STAGE_1_PR_6_PERSISTENCE_ENGINE.md`]: ../../../../../docs/design/STAGE_1_PR_6_PERSISTENCE_ENGINE.md

use std::path::Path;

use shekyl_address::Network;
use shekyl_crypto_pq::wallet_envelope::KdfParams;
use shekyl_engine_prefs::{PrefsHmacKey, WalletPrefs};
use shekyl_engine_state::WalletLedger;

use crate::engine::error::PersistenceError;
use crate::engine::lifecycle::Credentials;
use crate::engine::sealing_keys::StateWrapKey;
use crate::engine::Capability;

/// On-disk wallet persistence: state flush, prefs flush, password
/// rotation (§2.6).
///
/// Implementors own the wallet's durable artifacts — the `.wallet`
/// state file, the `<base>.prefs.toml` preferences file, and the
/// `.wallet.keys` key file plus its advisory lock — and serve the
/// flush/rotation surface against them. Hydration (`open` / `create`)
/// is deliberately **off-trait**: it stays on
/// [`Engine`](super::super::Engine) constructors per Q9.11, because
/// constructing a wallet handle is a one-time lifecycle event that
/// *produces* the implementor rather than an operation the implementor
/// serves. `PersistenceEngine` is the durable-write half of the
/// wallet's state surface; confirmed-chain reads
/// ([`LedgerEngine`](super::ledger::LedgerEngine)) and the reservation
/// lifecycle (`PendingTxEngine`, §2.4) live on their own traits.
///
/// # Supertrait bounds
///
/// - `Send + Sync + 'static` — `PersistenceEngine` instances are
///   shared across the orchestration future and the sync lifecycle
///   path that drives a flush from a Tokio worker via
///   [`drive_persistence`](super::lifecycle::drive_persistence)
///   (`block_in_place` + `block_on`), typically as `Arc<P>`.
///   [`WalletFile`](shekyl_engine_file::WalletFile) (Stage 1) and
///   `ActorRef<PersistenceActor>` (Stage 4) both satisfy these bounds.
/// - **Not** `Clone` — the on-disk wallet artifact and the advisory
///   lock on `.wallet.keys` are single-owner; the handle is shared by
///   `Arc`, not cloned. A forced `Clone` would imply two independent
///   owners of the same advisory lock, which the single-writer
///   discipline forbids.
pub(crate) trait PersistenceEngine: Send + Sync + 'static {
    /// Save/rotate vocabulary — not [`OpenError`](super::super::OpenError).
    type Error: Into<PersistenceError> + Send;

    /// Wallet cluster base path (the `.wallet` file path).
    ///
    /// # Cancellation
    ///
    /// Class **a** per §4: a synchronous read with no side effect.
    /// Not awaitable; cancellation is not a concept on this method.
    ///
    /// # Idempotency
    ///
    /// **Yes** per §4: returns the path fixed at open/create.
    /// Repeated calls observe the same value.
    ///
    /// # Panics
    ///
    /// Does not panic — the Stage 1 [`WalletFile`](shekyl_engine_file::WalletFile)
    /// implementor returns a borrowed `&Path` field cached at open,
    /// acquiring no lock.
    #[allow(dead_code)] // Stage 4 / wallet-RPC surface; V3.0 Engine caches base_path at open.
    fn base_path(&self) -> &Path;

    /// Network this wallet is bound to.
    ///
    /// # Cancellation
    ///
    /// Class **a** per §4: a synchronous read with no side effect.
    ///
    /// # Idempotency
    ///
    /// **Yes** per §4: returns the network decoded once at
    /// open/create.
    ///
    /// # Panics
    ///
    /// Does not panic — cached read; no lock acquisition.
    #[allow(dead_code)] // Stage 4 / wallet-RPC surface; V3.0 Engine caches network at open.
    fn network(&self) -> Network;

    /// Capability profile of this wallet (`Full` / `ViewOnly` /
    /// `HardwareOffload`).
    ///
    /// # Cancellation
    ///
    /// Class **a** per §4: a synchronous read with no side effect.
    ///
    /// # Idempotency
    ///
    /// **Yes** per §4: returns the capability decoded once at
    /// open/create.
    ///
    /// # Panics
    ///
    /// Does not panic — cached read; no lock acquisition.
    #[allow(dead_code)] // Stage 4 / wallet-RPC surface; V3.0 Engine caches capability at open.
    fn capability(&self) -> Capability;

    /// Seal and atomically write `.wallet` for `ledger`.
    ///
    /// `state_key` is `wrap_key_region_2` for this session.
    ///
    /// V3.0 password rotation rewraps the wrap layer only; `file_kek` plaintext is
    /// unchanged, so the same `wrap_key_region_2` bytes remain valid across
    /// [`rotate_password`](Self::rotate_password). A cached orchestrator key becomes
    /// **stale** when it no longer matches the keys-file bytes used for region-2 AAD
    /// (for example after external keys-file replacement without re-derive). Saving
    /// with a stale key seals state that fails authentication on the next open
    /// (Poly1305 MAC failure).
    /// Returns a [`Send`] future so sync lifecycle code can drive persistence
    /// from a Tokio worker via [`drive_persistence`](super::lifecycle::drive_persistence)
    /// (`block_in_place` + `block_on`). Matches [`RefreshEngine`](super::refresh::RefreshEngine)
    /// precedent (`impl Future + Send`, not `async fn` on the trait).
    ///
    /// # Cancellation
    ///
    /// Class **b** per §4: a state-flush side effect. The Stage 1
    /// implementor wraps a synchronous body in [`std::future::ready`],
    /// so the seal-and-write runs at call time with no interior
    /// `await` — there is no mid-write cancellation point.
    /// `atomic_write_file` is all-or-nothing (tmp → fsync → rename →
    /// fsync parent), so a dropped future or a crash leaves either the
    /// prior `.wallet` fully intact or the new one fully in place,
    /// never torn. At Stage 4 a drop after the message reaches the
    /// actor's mailbox is observation-only — the write may still
    /// complete.
    ///
    /// # Idempotency
    ///
    /// **Yes** per §4 at the wallet-state level: last-write-wins. The
    /// on-disk ciphertext differs per call (a fresh 24-byte region-2
    /// nonce from the OS CSPRNG) but decrypts to equivalent state;
    /// repeated saves of the same `ledger` converge.
    ///
    /// # Panics
    ///
    /// The Stage 1 [`WalletFile`](shekyl_engine_file::WalletFile)
    /// implementor panics on mutex poisoning
    /// (`.expect("wallet file mutex poisoned")` in
    /// `WalletFile::save_state`). Sync infallible-on-poison is the
    /// same disposition [`LedgerEngine`](super::ledger::LedgerEngine)
    /// documents for its `RwLock`: poisoning indicates an upstream
    /// invariant violation (a panic while a guard was held), not a
    /// recoverable error worth threading through every call site.
    fn save_state(
        &self,
        state_key: &StateWrapKey,
        ledger: &WalletLedger,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Seal and atomically write the wallet's preferences file
    /// (`<base>.prefs.toml`), HMAC'd with `prefs_key`.
    ///
    /// `prefs_key` is the session [`PrefsHmacKey`] derived at open.
    /// The Stage 1 implementor writes through
    /// `shekyl_engine_prefs::save_prefs`, which serializes `prefs`,
    /// appends the HMAC tag, and persists via the prefs crate's own
    /// atomic-write path. Returns a [`Send`] future for the same
    /// sync-lifecycle-driving reason as [`save_state`](Self::save_state).
    ///
    /// # Cancellation
    ///
    /// Class **b** per §4: a prefs-flush side effect, wrapped in eager
    /// [`std::future::ready`] (synchronous body, no interior `await`).
    /// The prefs write is atomic at the crate boundary, so a dropped
    /// future or a crash leaves the prior `.prefs.toml` intact or the
    /// new one in place.
    ///
    /// # Idempotency
    ///
    /// **Yes** per §4: last-write-wins. Repeated saves of the same
    /// `prefs` converge to equivalent on-disk preferences.
    ///
    /// # Panics
    ///
    /// **Does not panic on mutex poisoning.** Unlike
    /// [`save_state`](Self::save_state) and
    /// [`rotate_password`](Self::rotate_password), the Stage 1
    /// implementor routes this call through
    /// `shekyl_engine_prefs::save_prefs(self.state_path(), …)`, which
    /// reads the lockless `state_path()` accessor and never acquires
    /// the [`WalletFile`](shekyl_engine_file::WalletFile) mutex.
    /// Failures (serialization, HMAC, filesystem) surface as
    /// [`Self::Error`] via `PersistenceError::Prefs`, not as a panic.
    fn save_prefs(
        &self,
        prefs_key: &PrefsHmacKey,
        prefs: &WalletPrefs,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Password-handling moment: Argon2 rewrap of the keys file. Does not
    /// rewrite region-2 ciphertext on success (spec §4.2).
    ///
    /// # Cancellation
    ///
    /// Class **b** per §4, but **atomic**: a pure rewrap →
    /// `atomic_write_file(keys)` → in-memory cache update only *after*
    /// the disk write succeeds. The Stage 1 implementor's body is
    /// synchronous under eager [`std::future::ready`] (no interior
    /// `await`, so no mid-write cancellation point); a dropped future
    /// or a crash leaves the old keys file fully valid or the new one
    /// fully in place — never bricked.
    ///
    /// # Idempotency
    ///
    /// **No.** After a successful rotation the old password no longer
    /// authenticates, so a naive `(old, new)` retry after a lost
    /// acknowledgement fails with an authentication error rather than
    /// succeeding as a no-op. On a lost ack, treat the rotation as
    /// *may have succeeded*: try the new password first, and fall back
    /// to the old password only if the new one fails.
    ///
    /// # Panics
    ///
    /// The Stage 1 [`WalletFile`](shekyl_engine_file::WalletFile)
    /// implementor panics on mutex poisoning
    /// (`.expect("wallet file mutex poisoned")` in
    /// `WalletFile::rotate_password`). Sync infallible-on-poison by
    /// design, matching [`save_state`](Self::save_state).
    fn rotate_password(
        &self,
        old: &Credentials<'_>,
        new: &Credentials<'_>,
        new_kdf: Option<KdfParams>,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;
}
