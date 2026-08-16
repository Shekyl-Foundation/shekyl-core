// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Create and open entry points for [`Engine<SoloSigner>`](crate::engine::Engine).

use std::path::Path;

use tracing::warn;

use shekyl_address::Network;
use shekyl_crypto_pq::account::{rederive_account, SeedFormat};
use shekyl_crypto_pq::wallet_envelope::{CapabilityContent, EXPECTED_CLASSICAL_ADDRESS_BYTES};
use shekyl_engine_file::{
    CreateParams as FileCreateParams, OpenOutcome, SafetyOverrides, WalletFile,
};
use shekyl_engine_prefs::LoadOutcome as PrefsLoadOutcome;
use shekyl_engine_state::{LedgerIndexes, WalletLedger};

use crate::engine::error::{IoError, KeyError, OpenError};
use crate::engine::stake_engine::PSlot;
use crate::engine::{Capability, DaemonClient, Engine, SoloSigner};

use super::support::{
    extract_failure_detail, is_default_overrides, map_wallet_file_error, network_to_derivation,
    rederivation_failure_detail,
};
use super::{CapabilityInput, Credentials, EngineCreateParams, FirstStakeIntent, OpenedEngine};

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

        // The envelope stores (and AAD-commits, and KEK-binds) the 65-byte
        // `version ‖ spend ‖ view` PREFIX of the classical bytes — the
        // `msg_sign_pk` tail is deterministic from the same seed and adds
        // no mismatch-detection power, and keeping the stored bytes
        // prefix-shaped kept every pre-layout wallet file openable.
        let mut expected_classical_address = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
        expected_classical_address
            .copy_from_slice(&blob.classical_address_bytes[..EXPECTED_CLASSICAL_ADDRESS_BYTES]);

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

        // Public-bytes cross-check: the envelope's AAD commits to the
        // 65-byte `version ‖ spend ‖ view` classical PREFIX; rederive must
        // produce the same. Prefix-only by design (see the create path):
        // the `msg_sign_pk` tail is deterministic from the same seed, so
        // the prefix detects a seed/file mismatch at full strength.
        if blob.classical_address_bytes[..EXPECTED_CLASSICAL_ADDRESS_BYTES]
            != *file.expected_classical_address()
        {
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
}
