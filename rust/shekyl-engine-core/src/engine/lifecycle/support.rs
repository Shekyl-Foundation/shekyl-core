// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared lifecycle helpers: error translation and
//! the sync-over-async persistence drive.

use shekyl_address::Network;
use shekyl_crypto_pq::address_derivation_freeze::address_derivation_manifest_self_check;
use shekyl_crypto_pq::wallet_envelope::WalletEnvelopeError;
use shekyl_engine_file::{SafetyOverrides, WalletFileError};

use crate::engine::error::{IoError, OpenError};
#[cfg(test)]
use crate::engine::traits::{DaemonEngine, LedgerEngine, RefreshEngine};
#[cfg(test)]
use crate::engine::{Engine, EngineSignerKind};

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
        other => OpenError::Io(IoError::WalletFile(other)),
    }
}

/// Refuse when this binary's address-derivation corpus does not hash to its
/// pin, naming the platform the binary was built for.
///
/// Called first on create, restore and open, before any derivation. It costs
/// about 0.6 ms on the floor device, 1.5 ms at worst from a cold page cache
/// (decision log, 2026-11-23), so it runs at every open.
pub(super) fn check_address_derivation() -> Result<(), OpenError> {
    #[cfg(test)]
    let forced_failure = DERIVATION_CHECK_FAILS.with(std::cell::Cell::get);
    #[cfg(not(test))]
    let forced_failure = false;

    if forced_failure || address_derivation_manifest_self_check().is_err() {
        return Err(OpenError::DerivationSelfCheckFailed {
            platform: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        });
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static DERIVATION_CHECK_FAILS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// While held, [`check_address_derivation`] fails on this thread. The corpus
/// is compiled in, so a test has no other way to make the real check fail.
#[cfg(test)]
pub(super) struct DerivationCheckFails;

#[cfg(test)]
impl DerivationCheckFails {
    pub(super) fn new() -> Self {
        DERIVATION_CHECK_FAILS.with(|fails| fails.set(true));
        Self
    }
}

#[cfg(test)]
impl Drop for DerivationCheckFails {
    fn drop(&mut self) {
        DERIVATION_CHECK_FAILS.with(|fails| fails.set(false));
    }
}

/// Run a [`PersistenceEngine`](crate::engine::traits::persistence::PersistenceEngine) future from sync lifecycle steps
/// ([`Engine::persist_for_close`](crate::engine::Engine::persist_for_close), which
/// [`Engine::close`](crate::engine::Engine::close) runs, and
/// [`Engine::change_password`](crate::engine::Engine::change_password)).
///
/// # Tokio embedding
///
/// Callers may invoke these sync methods from a thread that already runs a
/// Tokio runtime (typical wallet-RPC path). A naïve
/// [`Handle::block_on`](tokio::runtime::Handle::block_on) on a worker thread
/// panics (nested `block_on`). This helper:
///
/// - On a **multi-thread** runtime: [`tokio::task::block_in_place`] then
///   `block_on` on the active handle (same class of fix as JSON-RPC handlers
///   driving [`Engine::refresh`](crate::engine::Engine::refresh) via `spawn_blocking`).
/// - Otherwise (no runtime, or **current-thread** runtime): runs the future on
///   a short-lived current-thread runtime in a [`std::thread::scope`] thread so
///   nested-runtime panics are avoided.
///
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
/// detail expected by [`KeyError::Primitive`](crate::engine::error::KeyError::Primitive). The message shape is
/// stable across the `shekyl-crypto-pq` API; we list the primitives
/// the lifecycle paths can plausibly hit.
pub(super) fn rederivation_failure_detail(_err: &shekyl_crypto_pq::CryptoError) -> &'static str {
    // The crypto-pq error is `Display` and carries a String detail,
    // but `KeyError::Primitive` is keyed on `&'static str` per the
    // closed-error contract. The lifecycle path can hit ML-KEM seed
    // expansion or X25519 birational mapping; we collapse them to a
    // single category here.
    "rederive_account failed (HKDF / scalar / ML-KEM / X25519)"
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
    /// # Cleanup target
    ///
    /// Remaining work (pre-genesis; not a V3.2 train; not coupled to
    /// trait-`pub` promotion): generalize `Engine::create` and
    /// `Engine::open_full` over `D: DaemonEngine` (default
    /// `DaemonClient`). Then production constructors accept any `D`
    /// directly, hybrid tests construct `Engine<SoloSigner, TestDaemon>`
    /// via that path without dummy-daemon ceremony, and this
    /// `#[cfg(test)] pub(crate)` helper retires. The retirement commit
    /// deletes both `replace_daemon` and the dummy-daemon construction
    /// in `make_hybrid_engine_arc` (and any sibling helpers that arrive
    /// in later Stage 1 PRs); production paths are unaffected because
    /// they never named this method.
    ///
    /// Until that lands, the public `Engine::create` and
    /// `Engine::open_full` constructors are concrete-typed (`daemon:
    /// DaemonClient`) because their callers — `shekyl-cli`,
    /// `shekyl-wallet-rpc` — only ever wire a real daemon transport.
    /// `replace_daemon` is the test surface; production paths cannot
    /// reach it because `pub(crate) #[cfg(test)]` excludes them from
    /// the published API and from the non-test build.
    pub(crate) fn replace_daemon<D2: DaemonEngine>(
        self,
        daemon: D2,
    ) -> Engine<S, D2, L, E, R, P, F> {
        let Engine {
            persistence,
            state_wrap_key,
            key,
            curve_tree,
            merge_view_secret,
            ledger,
            pending,
            submit_driver,
            daemon: _old,
            network,
            capability,
            refresh_slot,
            open_slots,
            pending_gate,
            refresh,
            economics,
            stake,
            _signer,
        } = self;
        Engine {
            persistence,
            state_wrap_key,
            key,
            curve_tree,
            merge_view_secret,
            ledger,
            pending,
            submit_driver,
            daemon,
            network,
            capability,
            refresh_slot,
            open_slots,
            pending_gate,
            refresh,
            economics,
            stake,
            _signer,
        }
    }
}
