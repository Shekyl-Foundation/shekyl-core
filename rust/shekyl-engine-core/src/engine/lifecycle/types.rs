// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Lifecycle types: credentials, create params, and the open outcome.

use std::path::Path;

use shekyl_address::Network;
use shekyl_crypto_pq::account::{SeedFormat, MASTER_SEED_BYTES};
use shekyl_crypto_pq::wallet_envelope::KdfParams;
use shekyl_engine_file::SafetyOverrides;
use shekyl_engine_prefs::WalletPrefs;

use crate::engine::local_ledger::LocalLedger;
use crate::engine::local_refresh::LocalRefresh;
use crate::engine::stake_engine::PSlot;
use crate::engine::traits::{DaemonEngine, LedgerEngine, RefreshEngine};
use crate::engine::{DaemonClient, Engine, EngineSignerKind};

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
    E: crate::engine::traits::EconomicsEngine = crate::engine::local_economics::LocalEconomics,
    R: RefreshEngine = LocalRefresh,
    P: crate::engine::traits::PendingTxEngine = crate::engine::LocalPendingTx<
        crate::engine::LocalSigner,
        crate::engine::WalletGreedyOutputSelector,
        crate::engine::DaemonFeeEstimator,
        crate::engine::fee_snapshot::DaemonFeeSnapshotSource<DaemonClient>,
        crate::engine::transaction_submitter::DaemonTransactionSubmitter<DaemonClient>,
        crate::engine::LocalLedger,
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
        E: crate::engine::traits::EconomicsEngine,
        R: RefreshEngine,
        P: crate::engine::traits::PendingTxEngine,
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
        E: crate::engine::traits::EconomicsEngine,
        R: RefreshEngine,
        P: crate::engine::traits::PendingTxEngine,
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
