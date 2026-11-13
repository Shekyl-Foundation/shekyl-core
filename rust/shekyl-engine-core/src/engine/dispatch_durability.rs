// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Saved-before-sent: the type every broadcast hand-off requires
//! ([`DurableTxBytes`]) and the commit that mints it for a plain send
//! ([`commit_dispatch`]).
//!
//! # Why a type, not a comment
//!
//! A send is network-exposed from the moment its bytes leave, not from the
//! daemon's verdict: a crash, a kill or a dropped connection after the send
//! can still leave a transaction the network mines. Whatever the wallet
//! must remember about it — the journal row, the retained tx secret (the
//! OUTBOUND proof), the inputs the F14 lock keeps unselectable, and the
//! bytes themselves — must therefore be on disk *before* the bytes leave.
//! Until A19 (alpha.11 bug hunt) the plain send wrote all of it in memory
//! and sent; the comment above the write said it was persisted.
//!
//! So the ordering is lifted into the type system, as the bond path already
//! does with `PersistedBondTicket` (`stake_persist.rs`):
//! [`TransactionSubmitter::submit`](super::transaction_submitter::TransactionSubmitter::submit)
//! takes a [`DurableTxBytes`], and a [`DurableTxBytes`] has two mints,
//! each of which witnesses a durable record of the bytes:
//!
//! - [`commit_dispatch`] — a plain send: the journal row (bytes included)
//!   and the retained secret are written and the whole ledger saved
//!   (`save_state` → `atomic_write_file`) under one write guard; a failed
//!   save undoes the record under the same guard and mints nothing.
//! - [`DurableTxBytes::from_sealed`] — a claim, drain, release or bond
//!   post: `submit_bound` receives [`PBoundBytes`] only from a record sealed
//!   in its pending store before the call (`claim_dispatch.rs`,
//!   `drain_dispatch.rs`, `release_dispatch.rs`, `pscan/dispatch.rs`).
//!
//! The watchdog's probe and the user's resend of a held send
//! (`held_sends.rs`) re-offer bytes read back from the saved journal row
//! straight to the daemon, not through a submitter: each is a status query
//! over bytes whose record is already on disk.

use shekyl_engine_state::WalletLedger;

use super::bond_assembly::PBoundBytes;
use super::error::PersistenceError;
use super::lifecycle::drive_persistence;
use super::sealing_keys::StateWrapKey;
use super::traits::PersistenceEngine;

/// Signed transaction bytes whose record is durably on disk — the only
/// thing a [`TransactionSubmitter`](super::transaction_submitter::TransactionSubmitter)
/// accepts.
///
/// The field is private and every constructor witnesses a durable record
/// (module docs). Deliberately **not** `Clone`: one durable record
/// authorizes one hand-off; a retry goes back to the record.
pub(crate) struct DurableTxBytes(Vec<u8>);

impl std::fmt::Debug for DurableTxBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DurableTxBytes({} bytes)", self.0.len())
    }
}

impl DurableTxBytes {
    /// Bytes from a record sealed in a staking pending store before the
    /// dispatch call (claim, drain, release, bond post). `submit_bound` is
    /// the only caller; every [`PBoundBytes`] that reaches it was sealed
    /// first (module docs).
    pub(crate) fn from_sealed(bound: PBoundBytes) -> Self {
        Self(bound.into_bytes())
    }

    /// Consume into the bytes, for the transport.
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Test-only mint for submitter unit tests that exercise the transport
    /// alone. Never a production mint.
    #[cfg(test)]
    pub(crate) fn for_test(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// Writes the whole wallet ledger durably — the capability the send path
/// borrows for one submit, so the pending-tx engine can save without
/// holding the persistence handle or the state key itself.
///
/// The production implementor is [`EngineLedgerCommit`], built per call
/// from the engine's own persistence and key. A test implementor is the
/// honest form only where a test names it as a seam.
pub(crate) trait LedgerCommit: Sync {
    /// Durably write `ledger` (`save_state`: tmp → fsync → rename →
    /// fsync parent). On `Err` nothing new is on disk.
    fn commit(&self, ledger: &WalletLedger) -> Result<(), PersistenceError>;
}

/// The engine's [`LedgerCommit`]: borrows its persistence and state key
/// for the duration of one submit.
pub(crate) struct EngineLedgerCommit<'a, F> {
    persistence: &'a F,
    state_key: &'a StateWrapKey,
}

impl<'a, F: PersistenceEngine> EngineLedgerCommit<'a, F> {
    pub(crate) fn new(persistence: &'a F, state_key: &'a StateWrapKey) -> Self {
        Self {
            persistence,
            state_key,
        }
    }
}

impl<F: PersistenceEngine> LedgerCommit for EngineLedgerCommit<'_, F> {
    fn commit(&self, ledger: &WalletLedger) -> Result<(), PersistenceError> {
        drive_persistence(self.persistence.save_state(self.state_key, ledger)).map_err(Into::into)
    }
}

/// Record a plain send's dispatch facts and save them, minting the
/// [`DurableTxBytes`] the hand-off requires only once the save succeeded.
///
/// Runs under the caller's ledger write guard (`wallet`). `record` writes
/// the journal row (with `tx_bytes`) and the retained secret; the whole
/// ledger is then saved under the same guard, so no refresh merge or
/// watchdog edge can interleave between the record and the save (the
/// `abandon_tx` crash-ordering contract). If the save fails, the record is
/// undone under the same guard ([`WalletLedger::undo_unsaved_dispatch`])
/// and nothing is minted: the bytes cannot be sent, and no later save can
/// write a send the user was told did not go.
pub(crate) fn commit_dispatch<C: LedgerCommit + ?Sized>(
    wallet: &mut WalletLedger,
    commit: &C,
    txid: [u8; 32],
    tx_bytes: Vec<u8>,
    record: impl FnOnce(&mut WalletLedger),
) -> Result<DurableTxBytes, PersistenceError> {
    record(wallet);
    debug_assert_eq!(
        wallet.send_journal.tx_bytes(&txid),
        Some(tx_bytes.as_slice()),
        "commit_dispatch: the record must hold the bytes it is about to authorize"
    );
    match commit.commit(wallet) {
        Ok(()) => Ok(DurableTxBytes(tx_bytes)),
        Err(error) => {
            wallet.undo_unsaved_dispatch(&txid);
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// A commit that fails or succeeds on demand and counts its calls —
    /// the seam for exercising the mint without a wallet file.
    struct CountingCommit {
        fail: bool,
        calls: AtomicUsize,
    }

    impl LedgerCommit for CountingCommit {
        fn commit(&self, _ledger: &WalletLedger) -> Result<(), PersistenceError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err(PersistenceError::WalletFile(
                    shekyl_engine_file::WalletFileError::Io(std::io::Error::other(
                        "test: save refused",
                    )),
                ))
            } else {
                Ok(())
            }
        }
    }

    fn record_send(txid: [u8; 32], bytes: Vec<u8>) -> impl FnOnce(&mut WalletLedger) {
        move |wallet: &mut WalletLedger| {
            wallet.record_retained_tx_key(
                txid,
                shekyl_engine_state::TxSecretKey::new(zeroize::Zeroizing::new([7; 32])),
            );
            wallet.record_dispatched_send(txid, 0, Vec::new(), Vec::new(), bytes);
        }
    }

    #[test]
    fn a_saved_dispatch_mints_the_bytes_it_recorded() {
        let mut wallet = WalletLedger::empty();
        let commit = CountingCommit {
            fail: false,
            calls: AtomicUsize::new(0),
        };
        let durable = commit_dispatch(
            &mut wallet,
            &commit,
            [1; 32],
            vec![9, 9],
            record_send([1; 32], vec![9, 9]),
        )
        .expect("save succeeded");
        assert_eq!(durable.into_bytes(), vec![9, 9]);
        assert_eq!(commit.calls.load(Ordering::SeqCst), 1);
        assert_eq!(wallet.send_journal.tx_bytes(&[1; 32]), Some(&[9u8, 9][..]));
        assert!(wallet.tx_meta.tx_keys.contains_key(&[1; 32]));
    }

    #[test]
    fn a_failed_save_mints_nothing_and_undoes_the_record() {
        let mut wallet = WalletLedger::empty();
        let commit = CountingCommit {
            fail: true,
            calls: AtomicUsize::new(0),
        };
        let result = commit_dispatch(
            &mut wallet,
            &commit,
            [2; 32],
            vec![1],
            record_send([2; 32], vec![1]),
        );
        assert!(result.is_err());
        assert!(!wallet.send_journal.rows.contains_key(&[2; 32]));
        assert!(!wallet.tx_meta.tx_keys.contains_key(&[2; 32]));
        assert!(!wallet.sync_state.pending_tx_hashes.contains(&[2; 32]));
    }
}
