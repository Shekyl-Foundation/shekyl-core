// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared lifecycle helpers: network mapping, error translation, and
//! the sync-over-async persistence drive.

use shekyl_address::Network;
use shekyl_crypto_pq::account::DerivationNetwork;
use shekyl_crypto_pq::wallet_envelope::WalletEnvelopeError;
use shekyl_engine_file::{SafetyOverrides, WalletFileError};

use crate::engine::error::{IoError, OpenError};
#[cfg(test)]
use crate::engine::traits::{DaemonEngine, LedgerEngine, RefreshEngine};
#[cfg(test)]
use crate::engine::{Engine, EngineSignerKind};

/// Map an address-layer [`Network`] into the derivation-layer
/// [`DerivationNetwork`].
///
/// The address layer has three networks; the derivation layer has
/// four. `Fakechain` is a derivation-only construct (Testnet
/// addresses with distinct derivation salts) and is not reachable
/// from a wallet file's network byte. Wallets that need Fakechain
/// keys must construct their `AllKeysBlob` outside the lifecycle
/// methods.
pub(crate) fn network_to_derivation(network: Network) -> DerivationNetwork {
    match network {
        Network::Mainnet => DerivationNetwork::Mainnet,
        Network::Testnet => DerivationNetwork::Testnet,
        Network::Stagenet => DerivationNetwork::Stagenet,
    }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Convert a [`WalletFileError`] from the `open` / `create` /
/// `rotate_password` call sites into the typed [`OpenError`] surface.
///
/// `expected` carries the network the caller asked for, used when the
/// underlying error is [`WalletFileError::NetworkMismatch`] so the
/// translated [`OpenError::NetworkMismatch`] preserves both ends of
/// the comparison.
pub(super) fn map_wallet_file_error(err: WalletFileError, expected: Network) -> OpenError {
    match err {
        WalletFileError::Envelope(WalletEnvelopeError::InvalidPasswordOrCorrupt) => {
            OpenError::IncorrectPassword
        }
        WalletFileError::NetworkMismatch { found, .. } => OpenError::NetworkMismatch {
            wallet: found,
            expected,
        },
        other => OpenError::Io(IoError::WalletFile {
            detail: other.to_string(),
        }),
    }
}

/// Run a [`PersistenceEngine`] future from sync lifecycle entry points
/// ([`Engine::close`](super::Engine::close), [`Engine::change_password`](super::Engine::change_password)).
///
/// # Tokio embedding
///
/// Callers may invoke these sync methods from a thread that already runs a
/// Tokio runtime (typical wallet-RPC path). A naïve [`Handle::block_on`] on a
/// worker thread panics (nested `block_on`). This helper:
///
/// - On a **multi-thread** runtime: [`tokio::task::block_in_place`] then
///   `block_on` on the active handle (same class of fix as JSON-RPC handlers
///   driving [`Engine::refresh`](super::Engine::refresh) via `spawn_blocking`).
/// - Otherwise (no runtime, or **current-thread** runtime): runs the future on
///   a short-lived current-thread runtime in a [`std::thread::scope`] thread so
///   nested-runtime panics are avoided.
///
/// Dedicated async lifecycle entry points remain a V3.1 follow-up when an
/// embedder needs cooperative cancellation across close/rotate; see
/// `docs/FOLLOWUPS.md` (V3.1 — sync close / `change_password` vs Tokio).
pub(crate) fn drive_persistence<Fut, T>(fut: Fut) -> T
where
    Fut: std::future::Future<Output = T> + Send,
    T: Send,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
            return tokio::task::block_in_place(|| handle.block_on(fut));
        }
    }
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("persistence drive runtime");
                rt.block_on(fut)
            })
            .join()
            .expect("persistence drive thread")
    })
}

/// Render a `shekyl-crypto-pq::CryptoError` into the static-string
/// detail expected by [`KeyError::Primitive`]. The message shape is
/// stable across the `shekyl-crypto-pq` API; we list the primitives
/// the lifecycle paths can plausibly hit.
pub(super) fn rederivation_failure_detail(_err: &shekyl_crypto_pq::CryptoError) -> &'static str {
    // The crypto-pq error is `Display` and carries a String detail,
    // but `KeyError::Primitive` is keyed on `&'static str` per the
    // closed-error contract. The lifecycle path can hit ML-KEM seed
    // expansion, X25519 birational mapping, or the
    // permitted-seed-format check; we collapse them to a single
    // category here because the typed branches that distinguish the
    // permitted-seed-format failure are already separate variants
    // (`UnsupportedDerivationPair`).
    "rederive_account failed (HKDF / scalar / ML-KEM / X25519)"
}

/// Render a transitional-extract refusal into a static detail string.
/// The function is unreachable on the FULL path (capability is
/// pre-gated) but kept here so the `extract_rederivation_inputs`
/// error-channel maps cleanly without an `unreachable!()` panic.
pub(super) fn extract_failure_detail(
    _err: &shekyl_engine_file::ExtractRederivationInputsError,
) -> &'static str {
    "wallet file refused master-seed extraction (defensive: capability pre-gated)"
}

/// Predicate for "this `SafetyOverrides` matches the create-time
/// default of `none()`". Tests typically do; CLI runs with a non-
/// default profile force a reopen so the session sees the requested
/// override set.
pub(super) fn is_default_overrides(overrides: &SafetyOverrides) -> bool {
    overrides == &SafetyOverrides::none()
}

#[cfg(test)]
#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D1: DaemonEngine,
        L: LedgerEngine,
        E: crate::engine::traits::EconomicsEngine,
        R: RefreshEngine,
        P: crate::engine::traits::PendingTxEngine,
        F: crate::engine::traits::PersistenceEngine,
    > Engine<S, D1, L, E, R, P, F>
{
    /// Test-only constructor: rebuild the engine with `daemon`
    /// substituted in place of the existing one, leaving every
    /// other field unchanged.
    ///
    /// Intended for hybrid tests (per
    /// `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §6.3) that need a
    /// fully-constructed `Engine<SoloSigner>` — file, keys,
    /// preferences, ledger, refresh slot — but want to drive
    /// `start_refresh` (or any other daemon-touching method)
    /// against a `TestDaemon` rather than a `DaemonClient` pointed
    /// at an unreachable URL. The pattern is:
    ///
    /// ```ignore
    /// let real = Engine::<SoloSigner>::create(params, dummy_daemon())?;
    /// let mock = TestDaemon::with_seed(derive_seed(&master, ROLE_DAEMON));
    /// let hybrid: Engine<SoloSigner, TestDaemon> = real.replace_daemon(mock);
    /// ```
    ///
    /// The original `D1` daemon is dropped; the returned engine's
    /// daemon field is the supplied `D2`. Net effect is that one
    /// real `Engine::create` ceremony pays for as many hybrid
    /// scenarios as the test composes.
    ///
    /// # Cleanup target (V3.2)
    ///
    /// V3.2 generalizes `Engine::create` and `Engine::open_full`
    /// over `D: DaemonEngine` (default `DaemonClient`) alongside
    /// the `DaemonEngine`-to-`pub` promotion. At that point the
    /// production constructors accept any `D` directly, hybrid
    /// tests construct their `Engine<SoloSigner, TestDaemon>` via
    /// the public path without intermediate dummy-daemon ceremony,
    /// and this `#[cfg(test)] pub(crate)` helper retires. The
    /// retirement commit deletes both `replace_daemon` and the
    /// dummy-daemon construction in `make_hybrid_engine_arc` (and
    /// any sibling helpers that arrive in later Stage 1 PRs);
    /// production paths are unaffected because they never named
    /// this method.
    ///
    /// Pre-V3.2, the public `Engine::create` and `Engine::open_full`
    /// constructors are concrete-typed (`daemon: DaemonClient`)
    /// because their callers — `shekyl-cli`, `shekyl-wallet-rpc` —
    /// only ever wire a real daemon transport. Until V3.2,
    /// `replace_daemon` is the
    /// test surface; production paths cannot reach it because
    /// `pub(crate) #[cfg(test)]` excludes them from the published
    /// API and from the non-test build.
    pub(crate) fn replace_daemon<D2: DaemonEngine>(
        self,
        daemon: D2,
    ) -> Engine<S, D2, L, E, R, P, F> {
        let Engine {
            persistence,
            state_wrap_key,
            prefs_hmac_key,
            key,
            curve_tree,
            merge_view_secret,
            ledger,
            pending,
            submit_driver,
            prefs,
            daemon: _old,
            network,
            capability,
            refresh_slot,
            open_slots,
            pending_write_lock,
            refresh,
            economics,
            stake,
            _signer,
        } = self;
        Engine {
            persistence,
            state_wrap_key,
            prefs_hmac_key,
            key,
            curve_tree,
            merge_view_secret,
            ledger,
            pending,
            submit_driver,
            prefs,
            daemon,
            network,
            capability,
            refresh_slot,
            open_slots,
            pending_write_lock,
            refresh,
            economics,
            stake,
            _signer,
        }
    }
}
