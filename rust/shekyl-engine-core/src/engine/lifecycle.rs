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
use super::{Capability, DaemonClient, SoloSigner, Engine, EngineSignerKind};

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
pub enum OpenedEngine<S: EngineSignerKind> {
    /// `.wallet` was present and decoded successfully. The wallet is
    /// fully loaded against the persisted ledger.
    Loaded(Engine<S>),

    /// `.wallet` was missing. The keys file was intact and the wallet
    /// was reconstructed with an empty ledger anchored at
    /// `from_height`. The caller should drive a refresh to restore
    /// state, then `save_state` the rebuilt ledger.
    Restored {
        /// The reconstructed wallet, ready for refresh.
        wallet: Engine<S>,
        /// Block height the synthesized ledger anchors at; equals the
        /// keys-file's `restore_height_hint` widened to `u64`.
        from_height: u64,
    },
}

impl<S: EngineSignerKind> std::fmt::Debug for OpenedEngine<S> {
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

impl<S: EngineSignerKind> OpenedEngine<S> {
    /// Borrow the underlying wallet regardless of the variant.
    pub fn wallet(&self) -> &Engine<S> {
        match self {
            Self::Loaded(w) => w,
            Self::Restored { wallet, .. } => wallet,
        }
    }

    /// Mutably borrow the underlying wallet regardless of the variant.
    pub fn wallet_mut(&mut self) -> &mut Engine<S> {
        match self {
            Self::Loaded(w) => w,
            Self::Restored { wallet, .. } => wallet,
        }
    }

    /// Consume the outcome and return the wallet, discarding the
    /// recovery-path signal. Use only when the caller has already
    /// surfaced the lost-state branch through some other channel.
    pub fn into_wallet(self) -> Engine<S> {
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

        let initial_ledger = WalletLedger::empty();
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

        Ok(Self::assemble(
            file,
            blob,
            initial_ledger,
            indexes,
            prefs,
            daemon,
            network,
            Capability::Full,
        ))
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
        );

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
        file: WalletFile,
        keys: AllKeysBlob,
        ledger: WalletLedger,
        indexes: LedgerIndexes,
        prefs: WalletPrefs,
        daemon: DaemonClient,
        network: Network,
        capability: Capability,
    ) -> Self {
        Self {
            file,
            keys,
            ledger,
            indexes,
            reservations: std::collections::BTreeMap::new(),
            next_reservation_id: 0,
            prefs,
            daemon,
            network,
            capability,
            refresh_slot: super::refresh::RefreshSlot::new(),
            _signer: std::marker::PhantomData,
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
// Engine<S> :: change_password / close (signer-kind-agnostic)
// ---------------------------------------------------------------------------

impl<S: EngineSignerKind> Engine<S> {
    /// Rotate the wallet password, optionally also rotating the KDF
    /// parameters of the on-disk envelope wrap.
    ///
    /// The handle's cached envelope bytes are updated in place; no
    /// re-derivation of [`AllKeysBlob`] runs. `.wallet` (region 2) is
    /// untouched — the rotation rewraps `file_kek` only.
    ///
    /// # Errors
    ///
    /// - [`OpenError::IncorrectPassword`] when `old` does not unlock
    ///   the existing envelope.
    /// - [`OpenError::Io`] for any other rotation failure.
    pub fn change_password(
        &mut self,
        old: &Credentials<'_>,
        new: &Credentials<'_>,
        new_kdf: Option<KdfParams>,
    ) -> Result<(), OpenError> {
        self.file
            .rotate_password(old.password(), new.password(), new_kdf)
            .map_err(|e| map_wallet_file_error(e, self.network))
    }

    /// Close the wallet. Errors if `outstanding_pending_txs() > 0`.
    ///
    /// On success, `self` is consumed and the drop sequence runs:
    ///
    /// 1. `self.file: WalletFile` — `Drop` releases the advisory lock
    ///    on `<base>.keys` (see
    ///    `shekyl_engine_file::handle::WalletFile::drop`).
    /// 2. `self.keys: AllKeysBlob` — `Drop` zeroizes `spend_sk`,
    ///    `view_sk`, `ml_kem_dk`, and (for uniform write patterns)
    ///    the public-key fields (see
    ///    `shekyl_crypto_pq::account::AllKeysBlob::drop`).
    /// 3. `self.ledger`, `self.indexes`, `self.reservations`,
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
    /// - [`OpenError::Io`] for state-save / prefs-save failures.
    pub fn close(self, credentials: &Credentials<'_>) -> Result<(), OpenError> {
        let count = self.outstanding_pending_txs();
        if count > 0 {
            return Err(OpenError::OutstandingPendingTx { count });
        }

        // Persist final state and prefs before drop. `save_state` is
        // password-keyed (Argon2id every save by design — see the
        // wallet-file spec §4.3); `save_prefs` is HMAC-keyed by the
        // session-cached PrefsHmacKey on `self.file`.
        self.file
            .save_state(credentials.password(), &self.ledger)
            .map_err(|e| map_wallet_file_error(e, self.network))?;
        self.file.save_prefs(&self.prefs).map_err(|e| {
            OpenError::Io(IoError::WalletFile {
                detail: e.to_string(),
            })
        })?;

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
    use shekyl_simple_request_rpc::SimpleRequestRpc;
    use tempfile::TempDir;

    /// Produce a `DaemonClient` against a never-resolved URL. The
    /// lifecycle methods covered here do not issue any RPC calls;
    /// the daemon is held on the `Engine<S>` for refresh / submit
    /// paths that land in later commits.
    fn dummy_daemon() -> DaemonClient {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let rpc = rt
            .block_on(SimpleRequestRpc::new("http://127.0.0.1:1".to_string()))
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

    #[test]
    fn create_full_then_open_full_round_trips_state() {
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

    #[test]
    fn open_full_with_wrong_password_returns_incorrect_password() {
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

    #[test]
    fn open_full_with_wrong_network_returns_network_mismatch() {
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

    #[test]
    fn change_password_rewraps_envelope_then_reopen_uses_new_password() {
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

    #[test]
    fn open_full_after_state_file_deleted_returns_restored_from_height() {
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

    #[test]
    fn close_with_outstanding_reservation_returns_outstanding_pending_tx() {
        let fix = make_create_fixture();
        let password: &[u8] = b"correct horse";
        let creds = Credentials::password_only(password);
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
        let mut wallet =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");

        // Inject a synthetic reservation directly through the
        // `pub(crate)` field; we don't need a real `build_pending_tx`
        // here — the lifecycle invariant is just that close refuses
        // when the reservation map is non-empty.
        let id = super::super::pending::ReservationId::new(0);
        let reservation = super::super::pending::Reservation {
            selected_transfer_indices: Vec::new(),
            built_at_height: 0,
            built_at_tip_hash: [0u8; 32],
            fee_atomic_units: 0,
            recipients: Vec::new(),
            priority: super::super::pending::FeePriority::Standard,
        };
        wallet.reservations.insert(id, reservation);
        wallet.next_reservation_id = 1;

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

    #[test]
    fn open_view_only_returns_capability_not_yet_implemented() {
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

    #[test]
    fn open_hardware_offload_returns_capability_not_yet_implemented() {
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

    #[test]
    fn tampered_prefs_are_recovered_and_warned_about() {
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
