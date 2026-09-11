// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Password rotation and close for an assembled engine.

use shekyl_crypto_pq::wallet_envelope::KdfParams;

use crate::engine::error::OpenError;
use crate::engine::local_ledger::LocalLedger;
use crate::engine::traits::DaemonEngine;
use crate::engine::{Engine, EngineSignerKind};

use super::support::drive_persistence;
use super::Credentials;

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
        E: crate::engine::traits::EconomicsEngine,
        P: crate::engine::traits::PendingTxEngine,
        F: crate::engine::traits::PersistenceEngine,
    > Engine<S, D, LocalLedger, E, crate::engine::LocalRefresh, P, F>
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
    /// - [`crate::engine::ChangePasswordError::RotateFailed`] when `old` does not unlock
    ///   the existing envelope or the keys-file rewrap fails.
    /// - [`crate::engine::ChangePasswordError::RotatedButPrefsFlushFailed`] when rotation
    ///   succeeds but the prefs HMAC flush fails.
    pub fn change_password(
        &mut self,
        old: &Credentials<'_>,
        new: &Credentials<'_>,
        new_kdf: Option<KdfParams>,
    ) -> Result<(), crate::engine::ChangePasswordError> {
        drive_persistence(self.persistence.rotate_password(old, new, new_kdf))
            .map_err(|e| crate::engine::ChangePasswordError::RotateFailed(e.into()))?;
        drive_persistence(
            self.persistence
                .save_prefs(self.prefs_hmac_key(), &self.prefs),
        )
        .map_err(|e| crate::engine::ChangePasswordError::RotatedButPrefsFlushFailed(e.into()))?;
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
    /// uses the session [`StateWrapKey`](crate::engine::sealing_keys::StateWrapKey)); the
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
