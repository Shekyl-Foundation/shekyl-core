// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Lifecycle methods for [`Engine`](super::Engine).
//!
//! This module implements the six methods that produce, mutate, and
//! consume a `Engine<S>` handle: [`Engine::create`], [`Engine::open_full`],
//! [`Engine::open_view_only`], [`Engine::open_hardware_offload`],
//! [`Engine::change_password`], and [`Engine::close`].
//!
//! # V3.0 capability scope
//!
//! Cross-cutting decision γ (recorded in `docs/V3_WALLET_DECISION_LOG.md`)
//! locks scope: only [`Engine::open_full`] and [`Engine::create`] ship with
//! end-to-end bodies. The two non-FULL openers carry the locked
//! signatures so call-site code is forward-compatible, and they return
//! [`OpenError::CapabilityNotYetImplemented`] until the
//! `shekyl-crypto-pq` view-only / hardware-offload `AllKeysBlob`
//! constructors land. That variant is transient — its declaration in
//! [`super::error`] names the deletion target.
//!
//! # Synchronous IO
//!
//! Lifecycle methods are synchronous (`fn`, not `async fn`). The cost
//! center is Argon2id under the wallet-file envelope; that work is
//! CPU-bound with no upstream async ceremony to compose with. Callers
//! that want non-blocking semantics from an async runtime wrap each
//! call in [`tokio::task::spawn_blocking`]. Per cross-cutting lock 1,
//! [`Engine::refresh`](super::Engine) is the only async lifecycle
//! surface (lands in the refresh commit).
//!
//! # Credentials shape
//!
//! Every lifecycle method takes [`&Credentials<'_>`](Credentials), not
//! `&[u8]` directly. V3.0 has only password-based credentials, but the
//! struct gives V3.1's hardware-token integration (FIDO2 hmac-secret →
//! KEK derivation) a forward-compatible parameter shape: V3.1 adds
//! `Credentials::password_with_authenticator(...)` as a sibling and
//! existing `password_only` call sites continue to work unchanged.
//! The Decision Log entry "V3.0 ships password-only" records the
//! choice; the FOLLOWUPS entry under V3.1 names the recovery model
//! (seed-phrase restoration is the canonical recovery path).
//!
//! # Lost-state surfacing
//!
//! [`Engine::open_full`] returns an [`OpenedEngine`] sum rather than a
//! plain `Engine<S>` so the rebuilt-state recovery path
//! ([`OpenOutcome::StateLost`](shekyl_engine_file::OpenOutcome::StateLost))
//! is a typed branch the call site cannot accidentally ignore.

use std::path::Path;

use tracing::warn;

use shekyl_address::Network;
use shekyl_crypto_pq::account::{
    rederive_account, AllKeysBlob, DerivationNetwork, SeedFormat, MASTER_SEED_BYTES,
};
use shekyl_crypto_pq::wallet_envelope::{
    CapabilityContent, KdfParams, WalletEnvelopeError, EXPECTED_CLASSICAL_ADDRESS_BYTES,
};
use shekyl_engine_file::{
    CreateParams as FileCreateParams, OpenOutcome, SafetyOverrides, WalletFile, WalletFileError,
};
use shekyl_engine_prefs::{LoadOutcome as PrefsLoadOutcome, WalletPrefs};
use shekyl_engine_state::{LedgerIndexes, WalletLedger};

use super::error::{IoError, KeyError, OpenError};
use super::local_ledger::LocalLedger;
use super::local_refresh::LocalRefresh;
use super::traits::{DaemonEngine, LedgerEngine, RefreshEngine};
use super::{Capability, DaemonClient, Engine, EngineSignerKind, SoloSigner};

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// User-supplied credentials for a lifecycle operation.
///
/// V3.0 carries only a password. The struct's existence is forward
/// compatibility for V3.1 MFA: the V3.1 cycle adds an authenticator
/// field and a `Credentials::password_with_authenticator(...)`
/// constructor without breaking V3.0 call sites.
///
/// # Auditability
///
/// The `password` field is private. All construction goes through
/// [`Self::password_only`] (and, in V3.1, its sibling); all reads go
/// through [`Self::password`]. A grep for `Credentials::` enumerates
/// every construction site; a grep for `.password()` enumerates every
/// read site. This makes the credential surface trivially
/// reviewable.
pub struct Credentials<'a> {
    password: &'a [u8],
    // V3.1: authenticator: Option<AuthenticatorRequest<'a>>,
}

impl<'a> Credentials<'a> {
    /// Construct a credentials value carrying only a password.
    ///
    /// V3.0 callers use this for every credential path. V3.1 will add
    /// `Credentials::password_with_authenticator(pwd, auth)` as a
    /// sibling for FIDO2 hmac-secret integration; existing
    /// `password_only` call sites continue to work unchanged.
    #[must_use]
    pub fn password_only(password: &'a [u8]) -> Self {
        Self { password }
    }

    /// Borrow the password bytes. Used by lifecycle method bodies to
    /// drive the wallet-file envelope; never copied or stored.
    #[must_use]
    pub fn password(&self) -> &[u8] {
        self.password
    }
}

// ---------------------------------------------------------------------------
// OpenedEngine sum
// ---------------------------------------------------------------------------

/// Result of [`Engine::open_full`].
///
/// The two variants distinguish "state was loaded from disk" from
/// "state file was missing and a fresh ledger was synthesized from the
/// keys-file's `restore_height_hint`." A typed sum forces callers to
/// observe the recovery path explicitly: a UI can prompt "your wallet
/// state was rebuilt; resync from height N" rather than silently
/// presenting an empty wallet.
// `D: DaemonEngine` and `L: LedgerEngine` private-bound: see the
// rationale on the `pub struct Engine` definition in `engine/mod.rs`.
#[allow(private_bounds)]
pub enum OpenedEngine<
    S: EngineSignerKind,
    D: DaemonEngine = DaemonClient,
    L: LedgerEngine = LocalLedger,
    E: super::traits::EconomicsEngine = super::local_economics::LocalEconomics,
    R: RefreshEngine = LocalRefresh,
    P: super::traits::PendingTxEngine = super::LocalPendingTx<
        super::LocalSigner,
        super::WalletGreedyOutputSelector,
        super::DaemonFeeEstimator,
        super::LocalLedger,
    >,
> {
    /// `.wallet` was present and decoded successfully. The wallet is
    /// fully loaded against the persisted ledger.
    Loaded(Engine<S, D, L, E, R, P>),

    /// `.wallet` was missing. The keys file was intact and the wallet
    /// was reconstructed with an empty ledger anchored at
    /// `from_height`. The caller should drive a refresh to restore
    /// state, then `save_state` the rebuilt ledger.
    Restored {
        /// The reconstructed wallet, ready for refresh.
        wallet: Engine<S, D, L, E, R, P>,
        /// Block height the synthesized ledger anchors at; equals the
        /// keys-file's `restore_height_hint` widened to `u64`.
        from_height: u64,
    },
}

impl<
        S: EngineSignerKind,
        D: DaemonEngine + std::fmt::Debug,
        L: LedgerEngine,
        E: super::traits::EconomicsEngine,
        R: RefreshEngine,
        P: super::traits::PendingTxEngine,
    > std::fmt::Debug for OpenedEngine<S, D, L, E, R, P>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Loaded(w) => f.debug_tuple("Loaded").field(w).finish(),
            Self::Restored {
                wallet,
                from_height,
            } => f
                .debug_struct("Restored")
                .field("wallet", wallet)
                .field("from_height", from_height)
                .finish(),
        }
    }
}

// `D: DaemonEngine` and `L: LedgerEngine` private-bound: see the
// rationale on the `pub struct Engine` definition in `engine/mod.rs`.
#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        L: LedgerEngine,
        E: super::traits::EconomicsEngine,
        R: RefreshEngine,
        P: super::traits::PendingTxEngine,
    > OpenedEngine<S, D, L, E, R, P>
{
    /// Borrow the underlying wallet regardless of the variant.
    pub fn wallet(&self) -> &Engine<S, D, L, E, R, P> {
        match self {
            Self::Loaded(w) => w,
            Self::Restored { wallet, .. } => wallet,
        }
    }

    /// Mutably borrow the underlying wallet regardless of the variant.
    pub fn wallet_mut(&mut self) -> &mut Engine<S, D, L, E, R, P> {
        match self {
            Self::Loaded(w) => w,
            Self::Restored { wallet, .. } => wallet,
        }
    }

    /// Consume the outcome and return the wallet, discarding the
    /// recovery-path signal. Use only when the caller has already
    /// surfaced the lost-state branch through some other channel.
    pub fn into_wallet(self) -> Engine<S, D, L, E, R, P> {
        match self {
            Self::Loaded(w) => w,
            Self::Restored { wallet, .. } => wallet,
        }
    }

    /// True when the outcome is [`Self::Restored`].
    pub fn is_restored(&self) -> bool {
        matches!(self, Self::Restored { .. })
    }
}

// ---------------------------------------------------------------------------
// Create-time parameters
// ---------------------------------------------------------------------------

/// Capability-bearing portion of the create-time parameters.
///
/// V3.0 ships only the FULL variant. The view-only and
/// hardware-offload constructors are deferred to a follow-up alongside
/// the corresponding [`AllKeysBlob`] constructors in
/// `shekyl-crypto-pq`; until they land, this enum has only the FULL
/// arm and the lifecycle stubs return
/// [`OpenError::CapabilityNotYetImplemented`].
pub enum CapabilityInput<'a> {
    /// Spendable wallet. The wallet file persists the 64-byte master
    /// seed under the envelope; every open re-derives the spend / view
    /// scalars and the ML-KEM decapsulation key from this seed.
    Full {
        /// 64-byte master seed bytes the envelope persists. Must be
        /// the value the caller intends to be the long-term identity
        /// material — this function does **not** generate a fresh
        /// seed.
        master_seed_64: &'a [u8; MASTER_SEED_BYTES],
        /// Declared seed format. Bound to the wallet-file AAD so a
        /// raw-seed wallet cannot be silently reopened as BIP-39 (or
        /// vice versa). Must satisfy
        /// [`DerivationNetwork::permitted_seed_format`].
        seed_format: SeedFormat,
    },
}

/// Parameters for [`Engine::create`].
///
/// Borrowed-where-possible to avoid stack copies of the master seed.
/// CLI / RPC call sites pay the verbosity tax of explicit struct
/// construction once each; tests use [`Self::for_test_full`].
pub struct EngineCreateParams<'a> {
    /// Base path. The envelope writes `<base>.keys` (region 1) and
    /// `<base>` (region 2).
    pub base_path: &'a Path,
    /// User-supplied credentials. V3.0 carries only a password.
    pub credentials: &'a Credentials<'a>,
    /// Network the wallet is bound to. Persisted in the AAD so a
    /// cross-network reopen is rejected loudly at open time.
    pub network: Network,
    /// Capability and capability-specific seed material.
    pub capability: CapabilityInput<'a>,
    /// Wall-clock creation time, encoded as UNIX seconds. Caller-
    /// supplied: CLI / RPC pass `SystemTime::now()` converted to
    /// seconds-since-epoch; tests pin a known value (typically `0`
    /// or a fixed timestamp). Required field; not defaulted-to-now
    /// to keep tests deterministic without `#[cfg(test)]` divergence
    /// in the production type.
    pub creation_timestamp: u64,
    /// Block height at wallet creation; used as the rescan floor on
    /// the lost-`.wallet` recovery path.
    pub restore_height_hint: u32,
    /// Argon2id cost parameters for the envelope wrap.
    pub kdf: KdfParams,
    /// CLI-ephemeral safety overrides. Provisioning passes
    /// [`SafetyOverrides::none`].
    pub overrides: SafetyOverrides,
    /// Initial preferences value to persist alongside the wallet
    /// file pair.
    pub prefs: WalletPrefs,
}

#[cfg(test)]
impl<'a> EngineCreateParams<'a> {
    /// Test-only helper. Builds a FULL-capability `EngineCreateParams`
    /// with the supplied `base_path`, `credentials`, and
    /// `master_seed_64`, and pins all other fields to known-good
    /// defaults: `Network::Stagenet`, `SeedFormat::Bip39`,
    /// `creation_timestamp = 0`, `restore_height_hint = 0`,
    /// minimum-wall-clock KDF, [`SafetyOverrides::none`], and
    /// [`WalletPrefs::default`].
    ///
    /// `Stagenet + Bip39` is a permitted `(network, seed_format)` pair
    /// per [`DerivationNetwork::permitted_seed_format`]; passing an
    /// arbitrary 64-byte master seed is fine — the format byte is
    /// only used as a derivation-salt component, not as a re-derivation
    /// pre-check on the bytes themselves.
    pub(crate) fn for_test_full(
        base_path: &'a Path,
        credentials: &'a Credentials<'a>,
        master_seed_64: &'a [u8; MASTER_SEED_BYTES],
    ) -> Self {
        Self {
            base_path,
            credentials,
            network: Network::Stagenet,
            capability: CapabilityInput::Full {
                master_seed_64,
                seed_format: SeedFormat::Bip39,
            },
            creation_timestamp: 0,
            restore_height_hint: 0,
            // Minimum-wall-clock KDF; matches the relaxation other
            // wallet-file tests use so the test suite stays runnable
            // under a debug build.
            kdf: KdfParams {
                m_log2: 0x08,
                t: 1,
                p: 1,
            },
            overrides: SafetyOverrides::none(),
            prefs: WalletPrefs::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Network → DerivationNetwork
// ---------------------------------------------------------------------------

/// Map an address-layer [`Network`] into the derivation-layer
/// [`DerivationNetwork`].
///
/// The address layer has three networks; the derivation layer has
/// four. `Fakechain` is a derivation-only construct (Testnet
/// addresses with distinct derivation salts) and is not reachable
/// from a wallet file's network byte. Wallets that need Fakechain
/// keys must construct their `AllKeysBlob` outside the lifecycle
/// methods.
fn network_to_derivation(network: Network) -> DerivationNetwork {
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
fn map_wallet_file_error(err: WalletFileError, expected: Network) -> OpenError {
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

// ---------------------------------------------------------------------------
// Engine<SoloSigner> :: create / open_full / open_view_only / open_hardware_offload
// ---------------------------------------------------------------------------

impl Engine<SoloSigner> {
    /// Create a fresh V3.0 wallet pair on disk and return the open
    /// handle.
    ///
    /// On success, the returned wallet is ready for refresh: the file
    /// envelope, the derived [`AllKeysBlob`], an empty
    /// [`WalletLedger`], a freshly-rebuilt [`LedgerIndexes`], the
    /// caller-supplied preferences, and the daemon client are all in
    /// place.
    ///
    /// # Capability
    ///
    /// V3.0 ships only the FULL variant of [`CapabilityInput`].
    /// View-only and hardware-offload creation paths are deferred to
    /// the follow-up that lands the corresponding `AllKeysBlob`
    /// constructors in `shekyl-crypto-pq`.
    ///
    /// # Errors
    ///
    /// - [`OpenError::Io`] for filesystem / envelope failures
    ///   (including the keys-file-already-exists case).
    /// - [`OpenError::Key`] for re-derivation failures (envelope's
    ///   own `expected_classical_address` cross-check, or the
    ///   `(network, seed_format)` permission check).
    pub fn create(params: EngineCreateParams<'_>, daemon: DaemonClient) -> Result<Self, OpenError> {
        let EngineCreateParams {
            base_path,
            credentials,
            network,
            capability,
            creation_timestamp,
            restore_height_hint,
            kdf,
            overrides,
            prefs,
        } = params;

        let CapabilityInput::Full {
            master_seed_64,
            seed_format,
        } = capability;

        // Re-derive the AllKeysBlob first so we can compute the
        // expected_classical_address that the wallet-file's AAD
        // commits to. The envelope cross-checks this on every open,
        // so getting it right here is load-bearing.
        let derivation_network = network_to_derivation(network);
        if !derivation_network.permitted_seed_format(seed_format) {
            return Err(OpenError::Key(KeyError::UnsupportedDerivationPair));
        }
        let blob =
            rederive_account(master_seed_64, derivation_network, seed_format).map_err(|e| {
                OpenError::Key(KeyError::Primitive {
                    detail: rederivation_failure_detail(&e),
                })
            })?;

        let mut expected_classical_address = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
        expected_classical_address.copy_from_slice(&blob.classical_address_bytes);

        let mut initial_ledger = WalletLedger::empty();
        if restore_height_hint > 0 {
            initial_ledger.sync_state.restore_from_height = u64::from(restore_height_hint);
        }
        let cap_content = CapabilityContent::Full { master_seed_64 };

        let file_params = FileCreateParams {
            base_path,
            password: credentials.password(),
            network,
            seed_format: seed_format.as_u8(),
            capability: &cap_content,
            creation_timestamp,
            restore_height_hint,
            expected_classical_address: &expected_classical_address,
            kdf,
            initial_ledger: &initial_ledger,
        };

        let mut file =
            WalletFile::create(&file_params).map_err(|e| map_wallet_file_error(e, network))?;

        // The `WalletFile::create` provisioning path doesn't accept
        // overrides directly — the handle starts with `none()`. Apply
        // the caller's overrides by re-opening… no: `create` returns
        // a handle ready for use. Overrides are session-state, and
        // the create path is provisioning. Persist the requested
        // override profile for the immediate post-create session by
        // discarding the create handle and reopening once with the
        // overrides applied.
        //
        // (`WalletFile::create` internally uses `SafetyOverrides::none`
        // and there is no public mutator. The reopen pays one extra
        // Argon2id pass on the create path, which is fine: create is
        // a once-per-wallet operation.)
        if !is_default_overrides(&overrides) {
            // Drop the create-time handle so the advisory lock is
            // released; reopen will reacquire under the same OFD
            // semantics.
            drop(file);
            let (reopened, _outcome) =
                WalletFile::open(base_path, credentials.password(), network, overrides)
                    .map_err(|e| map_wallet_file_error(e, network))?;
            file = reopened;
        }

        // Persist the caller-supplied preferences so the next open
        // sees them. `save_prefs` is HMAC-keyed by the session-cached
        // PrefsHmacKey on `file`.
        file.save_prefs(&prefs).map_err(|e| {
            OpenError::Io(IoError::WalletFile {
                detail: e.to_string(),
            })
        })?;

        let indexes = LedgerIndexes::rebuild_from_ledger(&initial_ledger.ledger);

        Self::assemble(
            file,
            blob,
            initial_ledger,
            indexes,
            prefs,
            daemon,
            network,
            Capability::Full,
        )
    }

    /// Open an existing FULL-capability wallet.
    ///
    /// # Errors
    ///
    /// - [`OpenError::IncorrectPassword`] when the envelope refuses
    ///   the password.
    /// - [`OpenError::NetworkMismatch`] when the wallet file declares
    ///   a different network from `network`.
    /// - [`OpenError::CapabilityMismatch`] when the wallet file
    ///   declares a non-FULL capability.
    /// - [`OpenError::Io`] for any other wallet-file failure.
    /// - [`OpenError::Key`] for re-derivation failures including the
    ///   public-bytes cross-check against the envelope's
    ///   `expected_classical_address`.
    pub fn open_full(
        base_path: &Path,
        credentials: &Credentials<'_>,
        network: Network,
        daemon: DaemonClient,
        overrides: SafetyOverrides,
    ) -> Result<OpenedEngine<SoloSigner>, OpenError> {
        let (file, outcome) =
            WalletFile::open(base_path, credentials.password(), network, overrides)
                .map_err(|e| map_wallet_file_error(e, network))?;

        // Capability gating: FULL only.
        let capability = file.capability();
        if capability != Capability::Full {
            return Err(OpenError::CapabilityMismatch { found: capability });
        }

        // Pull the master seed out of the FULL-mode envelope and
        // re-derive every key. This is the load-bearing step: the
        // re-derived bytes must match the AAD-committed
        // `expected_classical_address` or we refuse loudly.
        let inputs = file.extract_rederivation_inputs().map_err(|e| {
            // Defensive: capability was already gated to FULL, so
            // this branch is unreachable in practice. Treat any
            // refusal as a key failure rather than panicking.
            OpenError::Key(KeyError::Primitive {
                detail: extract_failure_detail(&e),
            })
        })?;

        let seed_format = SeedFormat::from_u8(file.opened_keys().seed_format)
            .ok_or(OpenError::Key(KeyError::UnsupportedDerivationPair))?;
        let derivation_network = network_to_derivation(network);
        if !derivation_network.permitted_seed_format(seed_format) {
            return Err(OpenError::Key(KeyError::UnsupportedDerivationPair));
        }

        let blob = rederive_account(&inputs.master_seed_64, derivation_network, seed_format)
            .map_err(|e| {
                OpenError::Key(KeyError::Primitive {
                    detail: rederivation_failure_detail(&e),
                })
            })?;

        // Public-bytes cross-check: the envelope's AAD commits to a
        // 65-byte classical address; rederive must produce the same.
        if blob.classical_address_bytes != *file.expected_classical_address() {
            return Err(OpenError::Key(KeyError::PublicBytesMismatch));
        }

        // Layer-2 preferences. Tampered → warn + use defaults; this
        // mirrors `docs/WALLET_PREFS.md §5`'s advisory failure
        // policy. The structured fields make the warn line
        // grep-able for operators investigating tamper signals.
        let prefs = match file.load_prefs() {
            Ok(PrefsLoadOutcome::Loaded(p) | PrefsLoadOutcome::Missing(p)) => p,
            Ok(PrefsLoadOutcome::Tampered { prefs, .. }) => {
                warn!(
                    target: "shekyl_engine_core::lifecycle",
                    state_path = %file.state_path().display(),
                    "wallet preferences failed HMAC verification; quarantined and reset to \
                     defaults — investigate file corruption, manual edit, or hardware fault"
                );
                prefs
            }
            Err(e) => {
                return Err(OpenError::Io(IoError::WalletFile {
                    detail: e.to_string(),
                }));
            }
        };

        let (ledger, restored_from) = match outcome {
            OpenOutcome::StateLoaded(ledger) => (ledger, None),
            OpenOutcome::StateLost {
                ledger,
                restore_from_height,
            } => (ledger, Some(restore_from_height)),
        };
        let indexes = LedgerIndexes::rebuild_from_ledger(&ledger.ledger);

        let wallet = Self::assemble(
            file, blob, ledger, indexes, prefs, daemon, network, capability,
        )?;

        Ok(match restored_from {
            None => OpenedEngine::Loaded(wallet),
            Some(from_height) => OpenedEngine::Restored {
                wallet,
                from_height,
            },
        })
    }

    /// Open an existing view-only wallet.
    ///
    /// **Stub.** Returns
    /// [`OpenError::CapabilityNotYetImplemented`] until the
    /// `shekyl-crypto-pq` view-only `AllKeysBlob` constructor lands.
    /// The signature is locked here so call-site code is forward-
    /// compatible.
    pub fn open_view_only(
        _base_path: &Path,
        _credentials: &Credentials<'_>,
        _network: Network,
        _daemon: DaemonClient,
        _overrides: SafetyOverrides,
    ) -> Result<OpenedEngine<SoloSigner>, OpenError> {
        Err(OpenError::CapabilityNotYetImplemented {
            capability: Capability::ViewOnly,
        })
    }

    /// Open an existing hardware-offload wallet.
    ///
    /// **Stub.** Returns
    /// [`OpenError::CapabilityNotYetImplemented`] until the
    /// `shekyl-crypto-pq` hardware-offload `AllKeysBlob` constructor
    /// lands. The signature is locked here so call-site code is
    /// forward-compatible.
    pub fn open_hardware_offload(
        _base_path: &Path,
        _credentials: &Credentials<'_>,
        _network: Network,
        _daemon: DaemonClient,
        _overrides: SafetyOverrides,
    ) -> Result<OpenedEngine<SoloSigner>, OpenError> {
        Err(OpenError::CapabilityNotYetImplemented {
            capability: Capability::HardwareOffload,
        })
    }

    /// Internal field-by-field assembly used by [`Self::create`] and
    /// [`Self::open_full`]. Pulled out so the cache invariants
    /// (network, capability) are established in exactly one place.
    #[allow(clippy::too_many_arguments)]
    fn assemble(
        mut file: WalletFile,
        keys: AllKeysBlob,
        ledger: WalletLedger,
        indexes: LedgerIndexes,
        prefs: WalletPrefs,
        daemon: DaemonClient,
        network: Network,
        capability: Capability,
    ) -> Result<Self, OpenError> {
        let state_wrap_key = super::sealing_keys::state_wrap_key_from_wallet_file(&file);
        let prefs_hmac_key = shekyl_engine_prefs::PrefsHmacKey::derive(
            &file.opened_keys().file_kek,
            file.expected_classical_address(),
        );
        file.zeroize_transient_file_kek();
        // Construct the producer's view-and-spend material once, from
        // the freshly-derived `AllKeysBlob`, and move it into the
        // `LocalRefresh` aggregate per
        // [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`] §5.4.7 R4
        // (a-instance-scoped) + §7.X C5. `ViewMaterial` does not
        // implement `Clone`; the orchestrator never holds a second
        // copy after the move. The construction site is unique to
        // `assemble` so future open paths inherit the wiring
        // automatically.
        let view_material =
            super::view_material::ViewMaterial::try_from_keys(&keys).map_err(|e| match e {
                super::error::RefreshError::Io(io) => OpenError::Io(io),
                // `try_from_keys` constructs only `RefreshError::Io(IoError::Scanner)`,
                // but the exhaustive match keeps the mapping
                // robust if `try_from_keys`'s error surface ever
                // widens (and surfaces a defensive translation
                // rather than a panic).
                other => OpenError::Io(IoError::Scanner {
                    detail: format!("ViewMaterial construction failed: {other:?}"),
                }),
            })?;
        let scan_start_floor = super::scan_floor::effective_scan_floor(
            ledger.sync_state.restore_from_height,
            file.effective_skip_to_height(),
            file.effective_refresh_from_block_height(),
        );
        // §6 step 3(a): derive the merge-path view-secret projection from the
        // owned blob *while it is still borrowable* — before `KeyActor::spawn`
        // consumes it below. This is the (6-i) construction-time projection;
        // the full blob then lives only in the actor.
        let merge_view_secret = super::key_actor::HandleDerivationViewSecret::from_keys(&keys);
        let refresh = std::sync::Arc::new(super::local_refresh::LocalRefresh::new(
            view_material,
            scan_start_floor,
        ));

        // §6 step 3(b): spawn the `KeyActor`, which takes the `AllKeysBlob` by
        // value. After this point no `&AllKeysBlob` is reachable from the
        // orchestrator — every public read resolves from the handle's
        // construction-time projections, and every secret-touching op routes
        // through the actor's message protocol (§4.1–4.2). The spawn uses the
        // ambient runtime if one exists, else hosts an engine-owned runtime
        // (§4.2 ambient-or-owned disposition). `merge_view_secret` was derived
        // above (step 3(a)) before this consuming spawn.
        let key = super::key_actor::KeyEngineHandle::spawn(keys);
        let ledger = std::sync::Arc::new(super::local_ledger::LocalLedger::new(ledger, indexes));
        let pending = super::LocalPendingTx::new(
            // §6 step 4: the signer no longer holds `Arc<AllKeysBlob>`; it
            // carries a `KeyEngineHandle` clone and the future signing path
            // routes through the actor's `SignTransaction` message.
            std::sync::Arc::new(super::LocalSigner::new(key.clone())),
            super::WalletGreedyOutputSelector,
            super::DaemonFeeEstimator,
            std::sync::Arc::clone(&ledger),
            std::sync::Arc::new(super::TracingDiagnosticSink),
            super::pending::ReservationTTLConfig::default(),
            network,
        );

        // Economics reads the **same** `Arc<LocalLedger>` the ledger and
        // pending engines share, so `pool_weighted_total` observes the
        // identical mirrored state (PR 7 §5.2 R3 read contract). The slot
        // is assembled but not consumed by any production path at V3.0
        // (PR 7 R6). The base-subsidy consensus cutover (7-cutover / C2c,
        // #93) routed `get_block_reward` to the Rust primitive
        // `shekyl_base_block_reward` directly, not through this trait, so
        // this engine field stays unconsumed.
        let economics = super::local_economics::LocalEconomics::new(
            super::chain_economics_source::LedgerChainEconomicsSource::new(std::sync::Arc::clone(
                &ledger,
            )),
        );

        Ok(Self {
            persistence: file,
            state_wrap_key,
            prefs_hmac_key,
            key,
            merge_view_secret,
            ledger,
            pending,
            prefs,
            daemon,
            network,
            capability,
            refresh_slot: super::refresh::RefreshSlot::new(),
            refresh,
            economics,
            _signer: std::marker::PhantomData,
        })
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

#[cfg(test)]
#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D1: DaemonEngine,
        L: LedgerEngine,
        E: super::traits::EconomicsEngine,
        R: RefreshEngine,
        P: super::traits::PendingTxEngine,
        F: super::traits::PersistenceEngine,
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
    /// because their callers — `shekyl-cli`, `shekyl-engine-rpc`,
    /// the upcoming JSON-RPC server cutover — only ever wire a
    /// real daemon transport. Until V3.2, `replace_daemon` is the
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
            merge_view_secret,
            ledger,
            pending,
            prefs,
            daemon: _old,
            network,
            capability,
            refresh_slot,
            refresh,
            economics,
            _signer,
        } = self;
        Engine {
            persistence,
            state_wrap_key,
            prefs_hmac_key,
            key,
            merge_view_secret,
            ledger,
            pending,
            prefs,
            daemon,
            network,
            capability,
            refresh_slot,
            refresh,
            economics,
            _signer,
        }
    }
}

/// Render a `shekyl-crypto-pq::CryptoError` into the static-string
/// detail expected by [`KeyError::Primitive`]. The message shape is
/// stable across the `shekyl-crypto-pq` API; we list the primitives
/// the lifecycle paths can plausibly hit.
fn rederivation_failure_detail(_err: &shekyl_crypto_pq::CryptoError) -> &'static str {
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
fn extract_failure_detail(
    _err: &shekyl_engine_file::ExtractRederivationInputsError,
) -> &'static str {
    "wallet file refused master-seed extraction (defensive: capability pre-gated)"
}

/// Predicate for "this `SafetyOverrides` matches the create-time
/// default of `none()`". Tests typically do; CLI runs with a non-
/// default profile force a reopen so the session sees the requested
/// override set.
fn is_default_overrides(overrides: &SafetyOverrides) -> bool {
    overrides == &SafetyOverrides::none()
}

// ---------------------------------------------------------------------------
// Engine<S, D, LocalLedger> :: change_password / close (signer-kind-agnostic)
// ---------------------------------------------------------------------------

// `D: DaemonEngine` private-bound: see the rationale on the
// `pub struct Engine` definition in `engine/mod.rs`. The
// `L = LocalLedger` specialization is intentional: [`Engine::close`]
// acquires a [`LocalLedger`] read guard to hand `&WalletLedger` to
// [`WalletFile::save_state`]; the trait surface does not yet expose
// a borrowed-state read accessor (Stage 4 design space — see the
// Phase 0c amendment block in
// `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §2.2).
#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        E: super::traits::EconomicsEngine,
        P: super::traits::PendingTxEngine,
        F: super::traits::PersistenceEngine,
    > Engine<S, D, LocalLedger, E, super::LocalRefresh, P, F>
{
    /// Rotate the wallet password, optionally also rotating the KDF
    /// parameters of the on-disk envelope wrap.
    ///
    /// The handle's cached envelope bytes are updated in place; no
    /// re-derivation of [`AllKeysBlob`] runs. `.wallet` (region 2) is
    /// untouched — the rotation rewraps `file_kek` only.
    ///
    /// # Errors
    ///
    /// - [`super::ChangePasswordError::RotateFailed`] when `old` does not unlock
    ///   the existing envelope or the keys-file rewrap fails.
    /// - [`super::ChangePasswordError::RotatedButPrefsFlushFailed`] when rotation
    ///   succeeds but the prefs HMAC flush fails.
    pub fn change_password(
        &mut self,
        old: &Credentials<'_>,
        new: &Credentials<'_>,
        new_kdf: Option<KdfParams>,
    ) -> Result<(), super::ChangePasswordError> {
        drive_persistence(self.persistence.rotate_password(old, new, new_kdf))
            .map_err(|e| super::ChangePasswordError::RotateFailed(e.into()))?;
        drive_persistence(
            self.persistence
                .save_prefs(self.prefs_hmac_key(), &self.prefs),
        )
        .map_err(|e| super::ChangePasswordError::RotatedButPrefsFlushFailed(e.into()))?;
        Ok(())
    }

    /// Close the wallet. Errors if `outstanding_pending_txs() > 0`.
    ///
    /// On success, `self` is consumed and the drop sequence runs:
    ///
    /// 1. `self.persistence` — when the default [`WalletFile`] implementor is
    ///    used, `Drop` releases the advisory lock on the keys file (`<base>.keys`,
    ///    where `base` is the `.wallet` path; see
    ///    `shekyl_engine_file::handle::WalletFile::drop`).
    /// 2. `self.keys: AllKeysBlob` — `Drop` zeroizes `spend_sk`,
    ///    `view_sk`, `ml_kem_dk`, and (for uniform write patterns)
    ///    the public-key fields (see
    ///    `shekyl_crypto_pq::account::AllKeysBlob::drop`).
    /// 3. `self.ledger`, `self.pending`,
    ///    `self.prefs` — no special drop semantics; ordinary heap
    ///    frees.
    ///
    /// The zeroization chain is single-level
    /// (`Engine<S>.keys: AllKeysBlob`); there is no wrapper layer
    /// that could break propagation. Lower-layer `Drop` semantics
    /// are tested in `shekyl-crypto-pq` unit tests; this commit's
    /// responsibility is to not introduce a wrapper that breaks the
    /// chain, which it does not.
    ///
    /// # Errors
    ///
    /// - [`OpenError::OutstandingPendingTx`] when one or more
    ///   reservations are still in flight.
    /// - [`OpenError::Persistence`] for state-save / prefs-save failures.
    ///
    /// `credentials` is ignored on the steady-state close path (region-2 sealing
    /// uses the session [`StateWrapKey`](super::sealing_keys::StateWrapKey)); the
    /// parameter remains for API stability with pre-F5(b) callers.
    pub fn close(self, _credentials: &Credentials<'_>) -> Result<(), OpenError> {
        let count = self.outstanding_pending_txs();
        if count > 0 {
            return Err(OpenError::OutstandingPendingTx { count });
        }

        // Persist final state and prefs before drop via steady-state sealing
        // keys (F5(b)); see `docs/WALLET_FILE_FORMAT_V1.md` §4.3.
        //
        // Acquire a `LocalLedger` read guard for the duration of the
        // save call so the underlying `WalletLedger` is borrowed
        // immutably. `Engine::close` consumes `self`, so no concurrent
        // writers exist at this point; the read guard is structural,
        // not for contention.
        let ledger_guard = self.ledger.read();
        drive_persistence(
            self.persistence
                .save_state(self.state_wrap_key(), &ledger_guard.ledger),
        )
        .map_err(|e| OpenError::Persistence(e.into()))?;
        drop(ledger_guard);
        drive_persistence(
            self.persistence
                .save_prefs(self.prefs_hmac_key(), &self.prefs),
        )
        .map_err(|e| OpenError::Persistence(e.into()))?;

        // Explicit drop so the chain documented above runs at a
        // named program point rather than at the end of the function
        // scope. Equivalent observable behavior; clearer in a debug
        // session that wants to step into each Drop.
        drop(self);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    use shekyl_crypto_pq::wallet_envelope::KdfParams;
    use shekyl_engine_prefs::hmac_key::FILE_KEK_BYTES;
    use shekyl_simple_request_rpc::SimpleRequestRpc;
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    /// Produce a `DaemonClient` against a never-resolved URL. The
    /// lifecycle methods covered here do not issue any RPC calls;
    /// the daemon is held on the `Engine<S>` for refresh / submit
    /// paths that land in later commits.
    ///
    /// **Runs inside the ambient test runtime.** Since `KeyEngineHandle::spawn`
    /// became require-ambient (§4.2), every engine-building lifecycle test is a
    /// `#[tokio::test(flavor = "multi_thread")]`. This helper therefore must not
    /// build a *nested* runtime (`block_on` inside a runtime panics); it bridges
    /// the async `SimpleRequestRpc::new` to the sync test body via
    /// `block_in_place` + the ambient handle — the same shape as
    /// [`super::drive_persistence`]'s multi-thread branch, and the reason the
    /// tests pin `flavor = "multi_thread"`.
    fn dummy_daemon() -> DaemonClient {
        let rpc = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(SimpleRequestRpc::new("http://127.0.0.1:1".to_string()))
        })
        .expect("construct SimpleRequestRpc (no actual connection attempted)");
        DaemonClient::new(rpc)
    }

    fn fixed_seed() -> [u8; MASTER_SEED_BYTES] {
        let mut s = [0u8; MASTER_SEED_BYTES];
        for (i, b) in s.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).unwrap_or(0).wrapping_mul(7);
        }
        s
    }

    fn fixed_seed_other() -> [u8; MASTER_SEED_BYTES] {
        let mut s = fixed_seed();
        s[0] ^= 0x55;
        s[31] ^= 0xAA;
        s
    }

    fn state_wrap_key_from_bytes(
        bytes: &[u8; FILE_KEK_BYTES],
    ) -> super::super::sealing_keys::StateWrapKey {
        use super::super::sealing_keys::StateWrapKey;
        StateWrapKey::from_region2_key(Zeroizing::new(*bytes))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn drive_persistence_from_tokio_worker_does_not_panic() {
        tokio::spawn(async {
            super::drive_persistence(std::future::ready(()));
        })
        .await
        .expect("join");
    }

    fn assert_open_state_aead_failure(err: OpenError) {
        use super::super::error::PersistenceError;
        match err {
            OpenError::Persistence(PersistenceError::WalletFile(WalletFileError::Envelope(
                WalletEnvelopeError::InvalidPasswordOrCorrupt,
            )))
            | OpenError::Io(IoError::WalletFile { .. }) => {}
            other => panic!("expected state AEAD failure on reopen, got {other:?}"),
        }
    }

    struct CreateFixture {
        _tmp: TempDir,
        base_path: PathBuf,
    }

    fn make_create_fixture() -> CreateFixture {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        CreateFixture {
            _tmp: tmp,
            base_path,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_full_then_open_full_round_trips_state() {
        let fix = make_create_fixture();
        let password: &[u8] = b"correct horse battery staple";
        let creds = Credentials::password_only(password);
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
        let network = params.network;
        let created =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
        assert_eq!(created.network(), network);
        assert_eq!(created.capability(), Capability::Full);
        assert_eq!(created.outstanding_pending_txs(), 0);
        // Close so the advisory lock is released before reopen.
        created.close(&creds).expect("close created wallet");

        let opened = Engine::<SoloSigner>::open_full(
            &fix.base_path,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect("reopen FULL wallet");
        assert!(matches!(opened, OpenedEngine::Loaded(_)));
        let wallet = opened.into_wallet();
        assert_eq!(wallet.network(), network);
        assert_eq!(wallet.capability(), Capability::Full);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn open_full_with_wrong_password_returns_incorrect_password() {
        let fix = make_create_fixture();
        let password: &[u8] = b"correct horse";
        let creds = Credentials::password_only(password);
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
        let network = params.network;
        Engine::<SoloSigner>::create(params, dummy_daemon())
            .expect("create FULL wallet")
            .close(&creds)
            .expect("close after create");

        let bad_password: &[u8] = b"WRONG PASSWORD";
        let bad_creds = Credentials::password_only(bad_password);
        let err = Engine::<SoloSigner>::open_full(
            &fix.base_path,
            &bad_creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect_err("wrong password must refuse");
        assert!(matches!(err, OpenError::IncorrectPassword), "got {err:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn open_full_with_wrong_network_returns_network_mismatch() {
        let fix = make_create_fixture();
        let password: &[u8] = b"correct horse";
        let creds = Credentials::password_only(password);
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
        let wallet_network = params.network;
        Engine::<SoloSigner>::create(params, dummy_daemon())
            .expect("create FULL wallet")
            .close(&creds)
            .expect("close after create");

        // Stagenet was used at create time; ask Mainnet.
        let other = Network::Mainnet;
        let err = Engine::<SoloSigner>::open_full(
            &fix.base_path,
            &creds,
            other,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect_err("network mismatch must refuse");
        match err {
            OpenError::NetworkMismatch { wallet, expected } => {
                assert_eq!(wallet, wallet_network);
                assert_eq!(expected, other);
            }
            other => panic!("expected NetworkMismatch, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn change_password_rewraps_envelope_then_reopen_uses_new_password() {
        let fix = make_create_fixture();
        let p_old: &[u8] = b"old password";
        let p_new: &[u8] = b"new password";
        let creds_old = Credentials::password_only(p_old);
        let creds_new = Credentials::password_only(p_new);
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&fix.base_path, &creds_old, &seed);
        let network = params.network;
        let mut wallet =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
        wallet
            .change_password(&creds_old, &creds_new, None)
            .expect("rotate password");
        wallet.close(&creds_new).expect("close after rotate");

        // Old password must refuse.
        let err = Engine::<SoloSigner>::open_full(
            &fix.base_path,
            &creds_old,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect_err("old password must refuse after rotation");
        assert!(matches!(err, OpenError::IncorrectPassword), "got {err:?}");

        // New password succeeds.
        let _ = Engine::<SoloSigner>::open_full(
            &fix.base_path,
            &creds_new,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect("reopen with new password");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn open_full_after_state_file_deleted_returns_restored_from_height() {
        let fix = make_create_fixture();
        let password: &[u8] = b"correct horse";
        let creds = Credentials::password_only(password);
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
        let network = params.network;
        let restore_height = u64::from(params.restore_height_hint);
        Engine::<SoloSigner>::create(params, dummy_daemon())
            .expect("create FULL wallet")
            .close(&creds)
            .expect("close after create");

        // Delete the state file to force the lost-state recovery
        // path. The keys file is left intact.
        let state_path = {
            let mut p = fix.base_path.clone();
            // `shekyl_engine_file` writes `<base>.keys` and
            // `<base>` (no extension) — match the latter.
            assert!(p.set_extension(""), "base path should have no extension");
            p
        };
        std::fs::remove_file(&state_path).expect("delete state file");

        let opened = Engine::<SoloSigner>::open_full(
            &fix.base_path,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect("reopen after state loss");
        match opened {
            OpenedEngine::Restored {
                wallet,
                from_height,
            } => {
                assert_eq!(from_height, restore_height);
                assert_eq!(wallet.capability(), Capability::Full);
            }
            OpenedEngine::Loaded(_) => panic!("expected Restored, got Loaded"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn close_with_outstanding_reservation_returns_outstanding_pending_tx() {
        let fix = make_create_fixture();
        let password: &[u8] = b"correct horse";
        let creds = Credentials::password_only(password);
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
        let wallet =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");

        use std::time::Instant;

        use super::super::local_pending_tx::ConsumerHeldEntry;

        let id = super::super::pending::ReservationId::new(0);
        wallet
            .pending
            .state
            .lock()
            .expect("pending state lock not poisoned")
            .consumer_held
            .insert(
                id,
                ConsumerHeldEntry {
                    created_at: Instant::now(),
                    snapshot_id: super::super::pending::SnapshotId([0u8; 16]),
                    built_at_height: 0,
                    built_at_tip_hash: [0u8; 32],
                },
            );

        let count_before = wallet.outstanding_pending_txs();
        assert_eq!(count_before, 1);

        let err = wallet
            .close(&creds)
            .expect_err("close must refuse with outstanding reservation");
        match err {
            OpenError::OutstandingPendingTx { count } => assert_eq!(count, count_before),
            other => panic!("expected OutstandingPendingTx, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn open_view_only_returns_capability_not_yet_implemented() {
        let fix = make_create_fixture();
        let password: &[u8] = b"correct horse";
        let creds = Credentials::password_only(password);
        let seed = fixed_seed();

        // Create a FULL wallet on disk so the call site is realistic;
        // the stub method returns the typed error before touching the
        // file, but constructing the file makes the test resemble the
        // real CLI flow.
        let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
        let network = params.network;
        Engine::<SoloSigner>::create(params, dummy_daemon())
            .expect("create FULL wallet")
            .close(&creds)
            .expect("close after create");

        let err = Engine::<SoloSigner>::open_view_only(
            &fix.base_path,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect_err("view-only stub must refuse");
        match err {
            OpenError::CapabilityNotYetImplemented { capability } => {
                assert_eq!(capability, Capability::ViewOnly);
            }
            other => panic!("expected CapabilityNotYetImplemented, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn open_hardware_offload_returns_capability_not_yet_implemented() {
        let fix = make_create_fixture();
        let password: &[u8] = b"correct horse";
        let creds = Credentials::password_only(password);
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
        let network = params.network;
        Engine::<SoloSigner>::create(params, dummy_daemon())
            .expect("create FULL wallet")
            .close(&creds)
            .expect("close after create");

        let err = Engine::<SoloSigner>::open_hardware_offload(
            &fix.base_path,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect_err("hardware-offload stub must refuse");
        match err {
            OpenError::CapabilityNotYetImplemented { capability } => {
                assert_eq!(capability, Capability::HardwareOffload);
            }
            other => panic!("expected CapabilityNotYetImplemented, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tampered_prefs_are_recovered_and_warned_about() {
        let fix = make_create_fixture();
        let password: &[u8] = b"correct horse";
        let creds = Credentials::password_only(password);
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
        let network = params.network;
        Engine::<SoloSigner>::create(params, dummy_daemon())
            .expect("create FULL wallet")
            .close(&creds)
            .expect("close after create");

        // Corrupt the prefs HMAC companion file. The wallet-file
        // layer writes `<base>.prefs.toml` and
        // `<base>.prefs.toml.hmac`; flipping bits in the HMAC
        // triggers the tamper path on next load.
        let hmac_path = {
            let p = fix.base_path.with_extension("prefs.toml.hmac");
            // Some platforms silently drop the secondary extension;
            // tolerate either form.
            if p.exists() {
                p
            } else {
                let mut alt = fix.base_path.clone();
                alt.set_file_name(format!(
                    "{}.prefs.toml.hmac",
                    fix.base_path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("wallet")
                ));
                alt
            }
        };
        if hmac_path.exists() {
            let mut bytes = std::fs::read(&hmac_path).expect("read hmac");
            if let Some(b) = bytes.first_mut() {
                *b ^= 0xFF;
            }
            std::fs::write(&hmac_path, &bytes).expect("write tampered hmac");
        }

        // Reopen — must succeed even on the tampered branch (the
        // policy is "warn + use defaults", not refuse-to-open). The
        // warn is checked at the documentation layer; capturing
        // `tracing` events in tests requires a subscriber setup we
        // do not need here.
        let opened = Engine::<SoloSigner>::open_full(
            &fix.base_path,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect("reopen succeeds even when prefs are tampered");
        let _wallet = opened.into_wallet();
    }

    use super::super::traits::PersistenceEngine;
    use super::drive_persistence;
    use shekyl_crypto_pq::wallet_envelope::WalletEnvelopeError;
    use shekyl_engine_file::WalletFileError;

    #[tokio::test(flavor = "multi_thread")]
    async fn persistence_trait_save_state_round_trip() {
        let fix = make_create_fixture();
        let password: &[u8] = b"correct horse battery staple";
        let creds = Credentials::password_only(password);
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
        let network = params.network;
        let wallet =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
        let ledger_guard = wallet.ledger.read();
        drive_persistence(PersistenceEngine::save_state(
            wallet.persistence(),
            wallet.state_wrap_key(),
            &ledger_guard.ledger,
        ))
        .expect("trait save_state");
        drop(ledger_guard);
        wallet.close(&creds).expect("close");

        let opened = Engine::<SoloSigner>::open_full(
            &fix.base_path,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect("reopen after trait save");
        assert!(matches!(opened, OpenedEngine::Loaded(_)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn change_password_flushes_prefs() {
        let fix = make_create_fixture();
        let p_old: &[u8] = b"old password";
        let p_new: &[u8] = b"new password";
        let creds_old = Credentials::password_only(p_old);
        let creds_new = Credentials::password_only(p_new);
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&fix.base_path, &creds_old, &seed);
        let network = params.network;
        let mut wallet =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
        wallet.prefs_mut().cosmetic.default_decimal_point = 9;
        wallet
            .change_password(&creds_old, &creds_new, None)
            .expect("rotate password");
        wallet.close(&creds_new).expect("close after rotate");

        let reopened = Engine::<SoloSigner>::open_full(
            &fix.base_path,
            &creds_new,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect("reopen with new password")
        .into_wallet();
        assert_eq!(reopened.prefs().cosmetic.default_decimal_point, 9);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn password_rotate_preserves_state_wrap_key_bytes() {
        let fix = make_create_fixture();
        let p_old: &[u8] = b"old password";
        let p_new: &[u8] = b"new password";
        let creds_old = Credentials::password_only(p_old);
        let creds_new = Credentials::password_only(p_new);
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&fix.base_path, &creds_old, &seed);
        let mut wallet =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
        let before = *wallet.state_wrap_key().as_bytes();
        wallet
            .change_password(&creds_old, &creds_new, None)
            .expect("rotate password");
        assert_eq!(
            before,
            *wallet.state_wrap_key().as_bytes(),
            "wrap_key_region_2 is unchanged when file_kek plaintext is unchanged"
        );
    }

    /// Design §2c / F-R3.8: open → save_state(k) ok → rotate ok → save_state(k_stale)
    /// without re-derive must fail loud when keys-file bytes used for AAD drift.
    #[tokio::test(flavor = "multi_thread")]
    async fn stale_state_wrap_key_fails_after_rotate_without_rederive() {
        use shekyl_engine_file::paths::keys_path_from;

        let fix_a = make_create_fixture();
        let tmp_b = tempfile::tempdir().expect("tempdir");
        let base_b = tmp_b.path().join("other.wallet");
        let p_old: &[u8] = b"old password";
        let p_new: &[u8] = b"new password";
        let creds_old = Credentials::password_only(p_old);
        let creds_new = Credentials::password_only(p_new);
        let seed_a = fixed_seed();
        let seed_b = fixed_seed_other();

        let params_a = EngineCreateParams::for_test_full(&fix_a.base_path, &creds_old, &seed_a);
        let network = params_a.network;
        let mut wallet =
            Engine::<SoloSigner>::create(params_a, dummy_daemon()).expect("create wallet A");
        let ledger_guard = wallet.ledger.read();
        drive_persistence(PersistenceEngine::save_state(
            wallet.persistence(),
            wallet.state_wrap_key(),
            &ledger_guard.ledger,
        ))
        .expect("save before rotate");
        drop(ledger_guard);

        let k_stale = state_wrap_key_from_bytes(wallet.state_wrap_key().as_bytes());

        wallet
            .change_password(&creds_old, &creds_new, None)
            .expect("rotate password");

        // Wallet B: different seed → different seed_block_tag in keys file.
        let params_b = EngineCreateParams::for_test_full(&base_b, &creds_old, &seed_b);
        Engine::<SoloSigner>::create(params_b, dummy_daemon())
            .expect("create wallet B")
            .close(&creds_old)
            .expect("close B");
        let foreign_keys = std::fs::read(keys_path_from(&base_b)).expect("read B keys file");

        // Orchestrator still holds k_stale; in-memory keys bytes drift to another wallet.
        wallet
            .file()
            .replace_keys_file_bytes_in_memory_for_tests(foreign_keys);

        let ledger_guard = wallet.ledger.read();
        drive_persistence(PersistenceEngine::save_state(
            wallet.persistence(),
            &k_stale,
            &ledger_guard.ledger,
        ))
        .expect("save seals with stale key + mismatched keys-file AAD");
        drop(ledger_guard);
        drop(wallet);

        let err = Engine::<SoloSigner>::open_full(
            &fix_a.base_path,
            &creds_new,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect_err("reopen must reject state sealed with stale wrap key");
        assert_open_state_aead_failure(err);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wrong_state_wrap_key_sealed_state_fails_on_reopen() {
        let fix = make_create_fixture();
        let password: &[u8] = b"correct horse battery staple";
        let creds = Credentials::password_only(password);
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
        let network = params.network;
        let wallet =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
        let ledger_guard = wallet.ledger.read();
        drive_persistence(PersistenceEngine::save_state(
            wallet.persistence(),
            wallet.state_wrap_key(),
            &ledger_guard.ledger,
        ))
        .expect("save baseline");
        drop(ledger_guard);

        let mut wrong_bytes = *wallet.state_wrap_key().as_bytes();
        wrong_bytes[0] ^= 0xFF;
        let wrong_key = state_wrap_key_from_bytes(&wrong_bytes);

        let ledger_guard = wallet.ledger.read();
        drive_persistence(PersistenceEngine::save_state(
            wallet.persistence(),
            &wrong_key,
            &ledger_guard.ledger,
        ))
        .expect("save with wrong wrap key still seals");
        drop(ledger_guard);
        drop(wallet);

        let err = Engine::<SoloSigner>::open_full(
            &fix.base_path,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect_err("reopen must reject state sealed with wrong wrap key");
        assert_open_state_aead_failure(err);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rederived_state_wrap_key_succeeds_after_rotate() {
        let fix = make_create_fixture();
        let p_old: &[u8] = b"old password";
        let p_new: &[u8] = b"new password";
        let creds_old = Credentials::password_only(p_old);
        let creds_new = Credentials::password_only(p_new);
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&fix.base_path, &creds_old, &seed);
        let network = params.network;
        let mut wallet =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
        wallet
            .change_password(&creds_old, &creds_new, None)
            .expect("rotate password");
        wallet.close(&creds_new).expect("close after rotate");

        let wallet = Engine::<SoloSigner>::open_full(
            &fix.base_path,
            &creds_new,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect("reopen after rotate")
        .into_wallet();
        let ledger_guard = wallet.ledger.read();
        drive_persistence(PersistenceEngine::save_state(
            wallet.persistence(),
            wallet.state_wrap_key(),
            &ledger_guard.ledger,
        ))
        .expect("save with re-derived wrap key");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn open_does_not_retain_file_kek() {
        let fix = make_create_fixture();
        let password: &[u8] = b"correct horse";
        let creds = Credentials::password_only(password);
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
        let network = params.network;
        Engine::<SoloSigner>::create(params, dummy_daemon())
            .expect("create FULL wallet")
            .close(&creds)
            .expect("close after create");

        let wallet = Engine::<SoloSigner>::open_full(
            &fix.base_path,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect("open_full")
        .into_wallet();
        assert!(
            wallet.file().opened_keys().file_kek.iter().all(|&b| b == 0),
            "file_kek must be zeroized after open ritual"
        );
        assert_ne!(
            wallet.state_wrap_key().as_bytes(),
            &[0u8; 32],
            "session must hold derived wrap_key_region_2"
        );
    }

    #[test]
    fn panic_hook_does_not_leak_state_wrap_key() {
        use std::sync::{Arc, Mutex};

        use super::super::sealing_keys::StateWrapKey;
        use shekyl_engine_prefs::hmac_key::FILE_KEK_BYTES;
        use zeroize::Zeroizing;

        let marker = [0x42u8; FILE_KEK_BYTES];
        let key = StateWrapKey::from_region2_key(Zeroizing::new(marker));
        let captured = Arc::new(Mutex::new(String::new()));
        let captured_hook = Arc::clone(&captured);
        let previous = std::panic::take_hook();
        struct RestorePanicHook(
            Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync + 'static>,
        );
        impl Drop for RestorePanicHook {
            fn drop(&mut self) {
                std::panic::set_hook(std::mem::replace(&mut self.0, Box::new(|_| {})));
            }
        }
        let _restore = RestorePanicHook(previous);
        std::panic::set_hook(Box::new(move |info| {
            captured_hook
                .lock()
                .expect("panic capture lock")
                .push_str(&info.to_string());
        }));

        let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _hold = &key;
            panic!("forced persistence test panic");
        }));
        assert!(payload.is_err());

        let text = captured.lock().expect("panic capture lock");
        assert!(
            text.contains("forced persistence test panic"),
            "sanity: panic message present"
        );
        for chunk in marker.chunks(4) {
            let needle = chunk.iter().map(|b| format!("{b:02x}")).collect::<String>();
            assert!(
                !text.contains(&needle),
                "panic output leaked key bytes as hex: {text}"
            );
        }
    }

    /// Sanity-check that `for_test_full` produces a `EngineCreateParams`
    /// callable through `Engine::create` without surprises. Functionally
    /// covered by `create_full_then_open_full_round_trips_state`; this
    /// case is the smaller, focused regression for the helper itself.
    #[test]
    fn for_test_full_helper_produces_creatable_params() {
        let fix = make_create_fixture();
        let password: &[u8] = b"hunter2";
        let creds = Credentials::password_only(password);
        let seed = [0xAAu8; MASTER_SEED_BYTES];

        let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
        // Field assertions: pinned defaults from the helper.
        assert_eq!(params.network, Network::Stagenet);
        assert_eq!(params.creation_timestamp, 0);
        assert_eq!(params.restore_height_hint, 0);
        match params.capability {
            CapabilityInput::Full {
                seed_format,
                master_seed_64,
            } => {
                assert_eq!(seed_format, SeedFormat::Bip39);
                assert_eq!(master_seed_64, &seed);
            }
        }
        // KDF profile is the minimum-wall-clock fast variant.
        let _: KdfParams = params.kdf;
    }
}
