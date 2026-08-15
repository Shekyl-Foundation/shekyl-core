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
use shekyl_engine_state::{LedgerIndexes, StakingBlock, WalletLedger};

use shekyl_crypto_pq::archival_p::derive_archival_p_keys;

use super::error::{IoError, KeyError, OpenError};
use super::local_ledger::LocalLedger;
use super::local_refresh::LocalRefresh;
use super::stake_engine::{PSlot, StakeEngineHandle, ARCHIVAL_PERSONA_LOOKAHEAD};
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
        super::fee_snapshot::DaemonFeeSnapshotSource<DaemonClient>,
        super::transaction_submitter::DaemonTransactionSubmitter<DaemonClient>,
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

/// The **transient first-stake intent** (SA-R1-a,
/// `ARCHIVAL_STAKE_ACTIVATION_PLAN.md` §5.6/§5.7): "spawn the StakeEngine for
/// this slot even though `staking_enabled` is still false, because a
/// credentialed first-stake is about to run."
///
/// A newtype rather than a bare `PSlot` because the **pin lives on the
/// type**: the intent is a *call parameter and nothing more* — it is never
/// persisted, never stored on the engine, and is set only by the
/// credentialed `stake` entry's open-with-intent (a sticky intent would
/// derive personas for a non-staker, the firewall hazard the pin names). Its
/// only consumer is the spawn gate; an aborted first-stake leaves only
/// transient derivation, dropped when the actor dies at close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FirstStakeIntent {
    slot: PSlot,
}

impl FirstStakeIntent {
    /// The intent for `slot` — constructed only on the `stake` entry path.
    pub(crate) fn for_slot(slot: PSlot) -> Self {
        Self { slot }
    }

    /// The slot the first stake targets.
    pub(crate) fn slot(&self) -> PSlot {
        self.slot
    }
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
            master_seed_64,
            seed_format,
            initial_ledger,
            indexes,
            prefs,
            daemon,
            network,
            Capability::Full,
            // SA-R1-d: first-stake is a credentialed post-create `stake` call,
            // never a create-time flag.
            None,
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
        Self::open_full_inner(base_path, credentials, network, daemon, overrides, None)
    }

    /// [`Self::open_full`] carrying a **transient first-stake intent**
    /// (SA-R1-a, `ARCHIVAL_STAKE_ACTIVATION_PLAN.md` §5.6/§5.7): the
    /// StakeEngine spawns for `{slot} ∪ lookahead` even though
    /// `staking_enabled` is still false, so the first-stake bootstrap has an
    /// actor to derive/scan/assemble against. The intent exists only as this
    /// call parameter — it is never persisted, and the sole production
    /// caller is the credentialed `stake` RPC's open-with-intent (the
    /// firewall pin: a sticky intent would derive personas for a
    /// non-staker).
    pub fn open_full_with_first_stake_intent(
        base_path: &Path,
        credentials: &Credentials<'_>,
        network: Network,
        daemon: DaemonClient,
        overrides: SafetyOverrides,
        intent_slot: u32,
    ) -> Result<OpenedEngine<SoloSigner>, OpenError> {
        Self::open_full_inner(
            base_path,
            credentials,
            network,
            daemon,
            overrides,
            Some(FirstStakeIntent::for_slot(PSlot::from_raw(intent_slot))),
        )
    }

    fn open_full_inner(
        base_path: &Path,
        credentials: &Credentials<'_>,
        network: Network,
        daemon: DaemonClient,
        overrides: SafetyOverrides,
        first_stake_intent: Option<FirstStakeIntent>,
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
            file,
            blob,
            &inputs.master_seed_64,
            seed_format,
            ledger,
            indexes,
            prefs,
            daemon,
            network,
            capability,
            first_stake_intent,
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
    /// (network, capability) are established in exactly one place, and the
    /// SP-R0 staking reconcile runs before the persona derive on every open path.
    #[allow(clippy::too_many_arguments)]
    fn assemble(
        mut file: WalletFile,
        keys: AllKeysBlob,
        master_seed: &[u8; MASTER_SEED_BYTES],
        seed_format: SeedFormat,
        mut ledger: WalletLedger,
        indexes: LedgerIndexes,
        prefs: WalletPrefs,
        daemon: DaemonClient,
        network: Network,
        capability: Capability,
        first_stake_intent: Option<FirstStakeIntent>,
    ) -> Result<Self, OpenError> {
        let state_wrap_key = super::sealing_keys::state_wrap_key_from_wallet_file(&file);

        // SP-R0 open-time staking reconciliation (arms #2 retired GC, #3
        // phantom GC, #4 SA-5 monotone raise) — before the persona derive.
        // The raise's interesting slots sit *outside* the bonded hint (a
        // rolled-back record is missing them), so this runs whenever a
        // pscan seal exists, not only when the hint is non-empty. Drops
        // stay no-ops on an empty hint. Mutations are in-memory (persisted
        // by the normal save discipline; a lost pass re-runs at the next
        // open — idempotent).
        //
        // A seal read/decode failure DEGRADES to skipping the reconcile
        // rather than failing the open: the seals are auxiliary. Skipping
        // the drops is conservative for funds (keep, don't drop). Skipping
        // the raise cannot heal a rolled-back cursor from chain evidence;
        // spawn still applies the hint-fed `monotone_current_slot_from_record`.
        // The staker's scan path still fails loud on the same corrupt seal
        // at `start_pscan`.
        let derivation_network = network_to_derivation(network);
        // Cache-first, identity-only on miss: persona ids are pure functions
        // of the seed and never invalidate, so a slot already in the sealed
        // `persona_id_cache` costs zero keygens here (the reconcile re-reads
        // ids for bonded + lookahead slots on EVERY open — re-deriving them
        // was pure waste), and a miss derives only the identity hybrid
        // (`derive_archival_p_identity_pk` — byte-identical to the full
        // bundle's `hybrid_bond_id`, pinned in `shekyl-crypto-pq`), skipping
        // the ML-KEM / receive / bond-spend work no id consumer needs.
        // Cache-consistency note: a sighted slot was matched against the
        // CACHED id at scan time, so evaluating arm #3 with the same cached
        // id is the self-consistent read; the cache rides the AEAD-sealed
        // ledger, which is what guards its integrity.
        let cached_probe_ids = ledger.staking.persona_id_cache.clone();
        let id_of_slot = move |slot: u32| -> Result<shekyl_types::PCanonicalId, OpenError> {
            if let Some(id) = cached_probe_ids.get(&slot) {
                return Ok(*id);
            }
            let identity_pk = shekyl_crypto_pq::archival_p::derive_archival_p_identity_pk(
                master_seed,
                derivation_network,
                seed_format,
                slot,
            )
            .map_err(|e| {
                OpenError::Key(KeyError::Primitive {
                    detail: rederivation_failure_detail(&e),
                })
            })?;
            let bytes = identity_pk.to_canonical_bytes().map_err(|_| {
                OpenError::Key(KeyError::Primitive {
                    detail: "persona canonical id encode failed",
                })
            })?;
            Ok(shekyl_archival_retention::p_canonical_id_from_hybrid_pubkey(&bytes))
        };
        // The bond watch's retired refusal set: probe ids for durably-retired
        // slots are excluded from the watch (their cursor burn is arm #2's,
        // from the same seal). Empty when the seal is ABSENT (fresh restore —
        // nothing was ever retired, so the empty set is a true statement and
        // the watch runs: that IS the flagship reconstruction path).
        //
        // An UNREADABLE seal is a different case: the retirement evidence
        // exists but cannot be consulted, so the refusal set is unknown, not
        // empty — and adoption on positive sightings would re-adopt durably
        // retired slots on every rescan with no arm #2 run to drop them
        // (the reconcile is skipped on the same unreadable seal, so this
        // does NOT converge; a persistent decode failure churns forever).
        // The watch therefore DISABLES until the evidence is readable:
        // `bond_watch_enabled` gates the producer's watch map below. The
        // wallet still opens (funds access must not hang on the staking
        // seal); the staker's scan path fails loud on the same seal at
        // `start_pscan`, which is where the corruption gets surfaced and
        // resolved — and the next open with a readable (or absent) seal
        // re-arms the watch.
        let mut probe_retired: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
        let mut bond_watch_enabled = true;
        match load_open_staking_evidence(&file, &state_wrap_key) {
            Ok(Some(OpenStakingEvidence {
                evidence,
                pending_slots,
                retired_slots,
            })) => {
                super::stake_persist::reconcile_staking_at_open(
                    &mut ledger.staking,
                    &evidence,
                    &pending_slots,
                    &retired_slots,
                    ARCHIVAL_PERSONA_LOOKAHEAD,
                    &id_of_slot,
                )?;
                probe_retired = retired_slots;
            }
            // No sealed scan state yet — nothing to reconcile against.
            Ok(None) => {}
            Err(detail) => {
                bond_watch_enabled = false;
                tracing::warn!(
                    %detail,
                    "SP-R0: open-time staking reconcile skipped — sealed scan \
                     evidence unreadable; bonded hint kept as-is, the \
                     chain-fed cursor raise does not run, and the bond watch \
                     is disabled for this session (the retired refusal set is \
                     unknown, so sighting adoption would be unsound). The \
                     wallet opens; a staker's scan will fail loud on the same \
                     seal"
                );
            }
        }

        // Bond-watch probe cache (SA-R-6 from-seed reconstruction): derive
        // the public persona ids for the probe window while the seed is
        // transiently in scope. Runs AFTER the reconcile so the window sits
        // above the (possibly raised) cursor, and UNCONDITIONALLY — a
        // never-staked wallet derives its `0..=W` window once (derive-once:
        // ids never invalidate), which is what makes the rescan-time pointer
        // reconstruction hold for every wallet, not only known stakers.
        super::bond_watch::extend_probe_cache(
            &mut ledger.staking,
            &probe_retired,
            super::stake_engine::ARCHIVAL_PERSONA_PROBE_WINDOW,
            &id_of_slot,
        )?;

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
        let refresh = std::sync::Arc::new(if bond_watch_enabled {
            super::local_refresh::LocalRefresh::with_bond_watch(
                view_material,
                scan_start_floor,
                // The watch map: the probe-id cache inverted, since-retired
                // slots filtered (see `bond_watch::watch_map`).
                super::bond_watch::watch_map(&ledger.staking, &probe_retired),
            )
        } else {
            // Retirement evidence unreadable (see the reconcile above): the
            // refusal set is unknown, so the watch runs EMPTY this session —
            // no sightings are produced and nothing can be (re-)adopted.
            // The probe-id cache above still extended (ids are pure,
            // derive-once, and never wrong); only adoption is gated.
            super::local_refresh::LocalRefresh::new(view_material, scan_start_floor)
        });

        // §6 step 3(b): spawn the `KeyActor`, which takes the `AllKeysBlob` by
        // value. After this point no `&AllKeysBlob` is reachable from the
        // orchestrator — every public read resolves from the handle's
        // construction-time projections, and every secret-touching op routes
        // through the actor's message protocol (§4.1–4.2). The spawn requires an
        // ambient runtime (`KeyEngineHandle::spawn` asserts `Handle::try_current`;
        // §4.2 require-ambient disposition — no engine-owned nested runtime).
        // `merge_view_secret` was derived above (step 3(a)) before this
        // consuming spawn.
        let key = super::key_actor::KeyEngineHandle::spawn(keys);

        // CT-5a commit 2: open the FCMP++ curve-tree store *beside the wallet
        // files* (`docs/design/CT5_ENGINE_WIRING.md` §3.1) and spawn the actor
        // over it. The store is the `.curvetree` sibling of the `.wallet` /
        // `.wallet.keys` pair; `open_and_spawn` resumes from its contents with
        // no genesis replay (R1-Q2). It requires the same ambient runtime the
        // `KeyEngineHandle::spawn` above already asserts, so it is grouped here
        // with the other actor spawn. A store-open failure is a wallet-file
        // boundary failure (the store is a wallet companion file), so it maps to
        // `IoError::WalletFile` with a curve-tree-store detail prefix rather than
        // a new error variant (which would force a downstream RPC-tier match).
        let curve_tree = {
            let store_path =
                shekyl_engine_file::paths::curve_tree_store_path_from(file.base_path());
            super::curve_tree_actor::CurveTreeHandle::open_and_spawn(&store_path).map_err(|e| {
                OpenError::Io(IoError::WalletFile {
                    detail: format!("curve-tree store open failed: {e:?}"),
                })
            })?
        };

        // ARCHIVAL_BOND_CONSTRUCTION.md §10.2 (Model D): for a staker, derive the
        // derive-forward set from the still-borrowed `master_seed` and spawn the
        // StakeEngine over it. Read `&ledger.staking` *before* `ledger` is moved
        // into the `LocalLedger` aggregate below. Non-stakers (the common case)
        // get `None` — no derivation, no resident personas, no actor.
        let stake = Self::spawn_stake_engine_if_staker(
            master_seed,
            network_to_derivation(network),
            seed_format,
            &ledger.staking,
            first_stake_intent,
        )?;

        let ledger = std::sync::Arc::new(super::local_ledger::LocalLedger::new(ledger, indexes));
        let fee_snapshot_source = super::fee_snapshot::DaemonFeeSnapshotSource::new(daemon.clone());
        let submitter = std::sync::Arc::new(
            super::transaction_submitter::DaemonTransactionSubmitter::new(std::sync::Arc::new(
                daemon.clone(),
            )),
        );
        let pending = super::LocalPendingTx::new(
            // §6 step 4: the signer no longer holds `Arc<AllKeysBlob>`; it
            // carries a `KeyEngineHandle` clone and the future signing path
            // routes through the actor's `SignTransaction` message.
            std::sync::Arc::new(super::LocalSigner::new(key.clone())),
            super::WalletGreedyOutputSelector,
            super::DaemonFeeEstimator,
            fee_snapshot_source,
            submitter,
            std::sync::Arc::clone(&ledger),
            // CT-5 §3.2.1 D1/D3 (commit 4b): share the curve-tree actor handle so
            // the spend path gates selection on `min(synced_height, tree_cursor)`.
            Some(curve_tree.clone()),
            std::sync::Arc::new(super::TracingDiagnosticSink),
            super::pending::ReservationTTLConfig::default(),
            network,
        );

        // The economics slot is assembled but not consumed by any production
        // path at V3.0 (PR 7 R6). The base-subsidy consensus cutover
        // (7-cutover / C2c, #93) routed `get_block_reward` to the Rust
        // primitive `shekyl_base_block_reward` directly, not through this
        // trait, so this engine field stays unconsumed. (The claim-era
        // pool_weighted_total chain-read seam was retired with the
        // confidential-staking sweep.)
        let economics = super::local_economics::LocalEconomics::new();

        // §5.3 submit lifecycle driver: the escape horizon is derived from
        // the consensus block target (`daa_target_seconds`, generated from
        // `config/consensus_constants.json` into `shekyl_economics`), the
        // same source the kernel's `WatchdogConfig::from_block_target`
        // documents. Owned by the Engine so its overlays persist across
        // ticks; the wallet surface and daemon are lent per tick.
        let submit_driver =
            tokio::sync::Mutex::new(super::submit_lifecycle::SubmitLifecycleDriver::new(
                shekyl_economics::EconomicParams::default().daa_target_seconds,
            ));

        Ok(Self {
            persistence: file,
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
            refresh_slot: super::refresh::RefreshSlot::new(),
            open_slots: super::refresh_slot::OpenTaskSlots::new(),
            pending_write_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            refresh,
            economics,
            stake,
            _signer: std::marker::PhantomData,
        })
    }

    /// Derive the Model-D derive-forward set and spawn the archival
    /// [`StakeEngine`](super::stake_engine::StakeEngine) for a staker, or return
    /// `None` for a non-staker (`ARCHIVAL_BOND_CONSTRUCTION.md` §10.2).
    ///
    /// The derive-forward set is
    /// [`StakingBlock::derive_forward_slots`] — `{bonded} ∪ {cursor ..= cursor+k}`,
    /// where `cursor` is the **scan-reconciled monotone** persona cursor
    /// ([`StakingBlock::monotone_current_slot_from_record`]) — never at or below
    /// an observed bonded slot, so a stale/rolled-back `p_slot` can never re-derive
    /// a moved-past persona as "current". The bonded slots are unioned in because
    /// under Model D the seed is dropped after this function returns, so a persona
    /// absent from the held set is unreachable for the wallet's life — and a
    /// retired-but-bonded persona's `bond_spend` key is needed to unbond it.
    ///
    /// The bundles are derived here from the transiently-borrowed `master_seed`;
    /// the seed is **not** moved in (it stays owned by the caller and drops at the
    /// caller's function end), and it never reaches the spawned actor. The actor
    /// starts **idle** (`active = None`): nothing is on the wire until 2c-2b's
    /// request path mints a [`PersonaHandle`](super::stake_engine::PersonaHandle)
    /// and activates it.
    ///
    /// # Cost
    ///
    /// One PQ keygen per slot in the set, run synchronously here. The whole
    /// `create` / `open_full` call is the blocking unit async callers wrap in
    /// `spawn_blocking` (module docs), so this is off the open hot path at that
    /// granularity; intra-call parallelism across the (small, `k`-bounded) set is
    /// a perf follow-up, not a correctness concern. Only stakers pay it.
    ///
    /// # Errors
    ///
    /// [`OpenError::Key`] if any archival derivation fails (same closed-error
    /// contract as `rederive_account`).
    fn spawn_stake_engine_if_staker(
        master_seed: &[u8; MASTER_SEED_BYTES],
        derivation_network: DerivationNetwork,
        seed_format: SeedFormat,
        staking: &StakingBlock,
        first_stake_intent: Option<FirstStakeIntent>,
    ) -> Result<Option<StakeEngineHandle>, OpenError> {
        // SA-R1-a (ARCHIVAL_STAKE_ACTIVATION_PLAN.md §5.6/§5.7, RATIFIED):
        // first-stake needs a spawned StakeEngine to assemble against BEFORE
        // `persist_bond_record` flips `staking_enabled`, so the gate admits a
        // transient first-stake intent. Pin (firewall gate): the intent is
        // NEVER persisted — it is set only by the credentialed `stake` RPC's
        // open-with-intent parameter and is `None` in every other open. An
        // aborted first-stake (spawn without persist) leaves only transient
        // derivation, dropped when the actor dies at close; the durable
        // staker state is exactly what `persist_bond_record` writes.
        if !staking.staking_enabled && first_stake_intent.is_none() {
            return Ok(None);
        }

        // The settlement-epoch schedule is consensus, and the wallet's epoch
        // arithmetic (P-scan accrual join epochs, claim-window recomputes)
        // runs on the genesis schedule unless this process explicitly armed
        // the regtest override — which no production wallet ever does. A
        // leaked SHEKYL_SETTLEMENT_EPOCH_BLOCKS (shared systemd template,
        // container base layer) is therefore ignored, and this is the loud,
        // once-per-open surface that names the ignored lever so the operator
        // can clean the environment instead of guessing.
        if shekyl_archival_retention::settlement_epoch_override_ignored() {
            warn!(
                "SHEKYL_SETTLEMENT_EPOCH_BLOCKS is set but this wallet is not an armed \
                 regtest context; the override is IGNORED and the genesis settlement-epoch \
                 schedule is in effect — unset the variable (it is a fakechain-only lever)"
            );
        }

        let mut slots = staking.derive_forward_slots(ARCHIVAL_PERSONA_LOOKAHEAD);
        // SA-R1-a: the intent slot rides the derive set (`{S} ∪ lookahead`,
        // plan §5.0 step 3) — normally already inside the lookahead window
        // (the monotone cursor IS the next slot), but unioned explicitly so
        // the bootstrap spawn is the real spawn even for a non-default slot.
        if let Some(intent) = first_stake_intent {
            slots.insert(intent.slot().to_raw());
        }

        let mut bundles = std::collections::BTreeMap::new();
        for &slot in &slots {
            let keys = derive_archival_p_keys(master_seed, derivation_network, seed_format, slot)
                .map_err(|e| {
                OpenError::Key(KeyError::Primitive {
                    detail: rederivation_failure_detail(&e),
                })
            })?;
            bundles.insert(PSlot::from_raw(slot), keys);
        }

        let mut bonded: std::collections::BTreeSet<PSlot> = staking
            .bonded_slots
            .iter()
            .copied()
            .map(PSlot::from_raw)
            .collect();
        // SA-R1-a: the intent slot is tagged bonded-ELECT (actor-local, never
        // persisted): the bonded tag is what makes a persona scannable
        // (`bonded_scan_inputs`) and activation-wipe-proof, and first-stake
        // needs both — the `stake_in` funding output must be discoverable by
        // the P-scan before the sweep can validate it, and an activation must
        // not wipe the elect's keys mid-bootstrap. If the first-stake aborts,
        // the tag dies with the actor (transient); durable bondedness remains
        // solely `persist_bond_record`'s write.
        if let Some(intent) = first_stake_intent {
            bonded.insert(intent.slot());
        }

        // Idle at open: the request path (2c-2b) mints a handle and activates.
        let handle = StakeEngineHandle::spawn(bundles, bonded, None);

        // S6 (conformance build only) — eager observation of the actor's
        // `on_start` RNG self-cert. Block wallet-open until the grade completes;
        // a non-conformant CSPRNG surfaces as `OpenError`, failing open loudly
        // rather than staking on an RNG that cannot produce unlinkable timing.
        //
        // This deliberately uses `block_in_place` directly rather than
        // `drive_persistence`: the awaited work (the actor's `on_start`) runs on
        // the *ambient* runtime, not inside the future, so `drive_persistence`'s
        // current-thread fallback (a fresh runtime on a scope thread) would
        // deadlock — the actor would never be polled while we wait. `block_in_place`
        // on a multi-thread runtime releases this worker so the actor keeps
        // running; on a current-thread runtime it *panics* loudly (the
        // panic-not-deadlock signal). Production wallet-open runs on the
        // `rt-multi-thread` ambient runtime; conformance tests must use
        // `#[tokio::test(flavor = "multi_thread")]`.
        #[cfg(feature = "conformance")]
        {
            let rt = tokio::runtime::Handle::current();
            let cert = tokio::task::block_in_place(|| rt.block_on(handle.wait_for_self_cert()));
            if let Err(failure) = cert {
                return Err(OpenError::StakeRngSelfCertFailed(failure));
            }
        }

        Ok(Some(handle))
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

/// Sealed evidence the open-time SP-R0 reconcile consumes: arm #3's
/// reconcile set, the W3 pending bridge, and arm #2's done-side retired
/// slots. `Ok(None)` if no pscan seal exists yet; `Err(detail)` on ANY
/// read/decode failure — including a pending seal that cannot be read
/// while the pscan seal can, because a GC run without the pending bridge
/// could wrongfully drop a W3 slot. The caller degrades an `Err` to
/// skipping the reconcile (keep the hint, skip the chain-fed raise),
/// never to an open failure.
struct OpenStakingEvidence {
    evidence: super::pscan::reconcile::PReconcileSet,
    pending_slots: std::collections::BTreeSet<u32>,
    retired_slots: std::collections::BTreeSet<u32>,
}

fn load_open_staking_evidence(
    file: &WalletFile,
    state_wrap_key: &super::sealing_keys::StateWrapKey,
) -> Result<Option<OpenStakingEvidence>, String> {
    let Some(bytes) = file
        .open_pscan_state(state_wrap_key.as_bytes())
        .map_err(|e| format!("pscan seal read failed: {e}"))?
    else {
        return Ok(None);
    };
    let state = shekyl_engine_state::pscan_state::PScanState::from_postcard_bytes(&bytes)
        .map_err(|e| format!("pscan seal decode failed: {e}"))?;
    let evidence = super::pscan::accrual::PScanAccrual::from_state(&state).reconcile_set();
    // SP-R0 arm #2: the done-side ledger's retired slots ride along so the
    // caller can apply the records-driven hint clean before the phantom sweep.
    let retired_slots: std::collections::BTreeSet<u32> = state
        .retired_records()
        .iter()
        .map(|r| r.p_slot.to_raw())
        .collect();
    let pending_slots: std::collections::BTreeSet<u32> = match file
        .open_pending_posts(state_wrap_key.as_bytes())
        .map_err(|e| format!("pending seal read failed: {e}"))?
    {
        Some(bytes) => {
            shekyl_engine_state::pending_post_block::PendingPostBlock::from_postcard_bytes(&bytes)
                .map_err(|e| format!("pending seal decode failed: {e}"))?
                .posts()
                .iter()
                .map(|p| p.p_slot.to_raw())
                .collect()
        }
        None => std::collections::BTreeSet::new(),
    };
    Ok(Some(OpenStakingEvidence {
        evidence,
        pending_slots,
        retired_slots,
    }))
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

    /// Persist the operator's Foundation `CompleteTree` serving posture
    /// (`operational.serve_complete_tree`) — the CLI-only activation switch.
    ///
    /// Mutates the pref and flushes the prefs sidecar immediately, so the
    /// choice survives a crash between now and close. The running serving
    /// host is deliberately untouched: the posture is read once at
    /// `start_serving_if_staker`, so activation takes effect at the next
    /// wallet open — the same reopen collapse every other serving lifecycle
    /// change rides.
    ///
    /// On flush failure the in-memory pref is rolled back, so what this
    /// session believes always matches what the next open will read.
    ///
    /// # Errors
    ///
    /// [`super::error::PersistenceError`] when the prefs sidecar write fails.
    pub fn set_serve_complete_tree(
        &mut self,
        enabled: bool,
    ) -> Result<(), super::error::PersistenceError> {
        let previous = self.prefs.operational.serve_complete_tree;
        self.prefs.operational.serve_complete_tree = enabled;
        if let Err(e) = drive_persistence(
            self.persistence
                .save_prefs(self.prefs_hmac_key(), &self.prefs),
        ) {
            self.prefs.operational.serve_complete_tree = previous;
            return Err(e.into());
        }
        Ok(())
    }

    /// Persist final state + prefs for close, without consuming `self`.
    ///
    /// Callers that must keep the live `Engine` when flush fails (e.g.
    /// wallet-rpc `close_wallet`, which re-installs the session on I/O
    /// error) use this before dropping. [`Self::close`] is the
    /// consume-on-any-outcome path for CLI / tests.
    ///
    /// # Errors
    ///
    /// - [`OpenError::OutstandingPendingTx`] when one or more
    ///   reservations are still in flight.
    /// - [`OpenError::Persistence`] for state-save / prefs-save failures.
    pub fn persist_for_close(&self) -> Result<(), OpenError> {
        let count = self.outstanding_pending_txs();
        if count > 0 {
            return Err(OpenError::OutstandingPendingTx { count });
        }

        // Persist final state and prefs via steady-state sealing keys
        // (F5(b)); see `docs/WALLET_FILE_FORMAT_V1.md` §4.3.
        //
        // Acquire a `LocalLedger` read guard for the duration of the
        // save call so the underlying `WalletLedger` is borrowed
        // immutably. Callers that reach here from `close` have already
        // taken sole ownership; the read guard is structural, not for
        // contention with other Engine writers on this instance.
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
    /// On either error variant, `self` is still dropped (by-value `self`
    /// cannot be returned through `Result<(), E>`). Callers that must
    /// retain the live engine on flush failure must call
    /// [`Self::persist_for_close`] first and only drop on `Ok`.
    ///
    /// `credentials` is ignored on the steady-state close path (region-2 sealing
    /// uses the session [`StateWrapKey`](super::sealing_keys::StateWrapKey)); the
    /// parameter remains for API stability with pre-F5(b) callers.
    pub fn close(self, _credentials: &Credentials<'_>) -> Result<(), OpenError> {
        self.persist_for_close()?;

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
#[path = "lifecycle_tests.rs"]
mod tests;
