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
//! - [`commit_dispatch`] — a plain send: this function writes the journal
//!   row (bytes included) and the retained secret, then saves the whole
//!   ledger (`save_state` → `atomic_write_file`) under one write guard.
//!   The minted bytes are the bytes the row stored. Only
//!   [`Durability::Confirmed`] mints. A save that fails before the rename
//!   undoes the record under the same guard. A rename whose parent-directory
//!   fsync did not confirm leaves the applied record and mints nothing.
//! - [`DurableTxBytes::from_sealed`] — a claim, drain, release or bond
//!   post: `submit_bound` receives [`PBoundBytes`] only from a record sealed
//!   in its pending store before the call (`claim_dispatch.rs`,
//!   `drain_dispatch.rs`, `release_dispatch.rs`, `pscan/dispatch.rs`).
//!
//! The watchdog's probe and the user's resend of a held send
//! (`held_sends.rs`) re-offer bytes read back from the saved journal row
//! straight to the daemon, not through a submitter: each is a status query
//! over bytes whose record is already on disk.

use shekyl_engine_file::Durability;
use shekyl_engine_state::{SendInputRef, SendRecipient, TxSecretKey, WalletLedger};

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
    /// Write `ledger` (`save_state`: tmp → fsync → rename → fsync parent).
    ///
    /// `Err` means the rename did not land: nothing new is on disk.
    /// [`Durability::Unconfirmed`] means the rename landed and the parent
    /// fsync missed: the write is applied, and the caller must not undo it.
    /// Only [`Durability::Confirmed`] authorizes a broadcast.
    fn commit(&self, ledger: &WalletLedger) -> Result<Durability, PersistenceError>;
}

/// A test seam that saves nothing and always succeeds — for unit tests
/// that drive the pending-tx engine or the watchdog without a wallet file.
/// Named for what it does so no reader takes a test using it as evidence
/// of durability; the tests of the save itself use a real wallet file or
/// a failing commit.
#[cfg(test)]
pub(crate) struct NoSaveCommit;

#[cfg(test)]
impl LedgerCommit for NoSaveCommit {
    fn commit(&self, _ledger: &WalletLedger) -> Result<Durability, PersistenceError> {
        Ok(Durability::Confirmed)
    }
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
    fn commit(&self, ledger: &WalletLedger) -> Result<Durability, PersistenceError> {
        drive_persistence(self.persistence.save_state(self.state_key, ledger)).map_err(Into::into)
    }
}

/// The dispatch facts [`commit_dispatch`] writes, and the bytes it may mint.
///
/// One value, so the row and the hand-off cannot carry different bytes.
pub(crate) struct DispatchRecord {
    /// Canonical transaction id.
    pub txid: [u8; 32],
    /// Retained per-transaction secret (the OUTBOUND proof).
    pub retained: TxSecretKey,
    /// Realized fee of the built transaction, in atomic units.
    pub fee: u64,
    /// Realized recipients, in transaction order.
    pub recipients: Vec<SendRecipient>,
    /// Dispatched input set the F14 lock re-derives from.
    pub inputs: Vec<SendInputRef>,
    /// Signed transaction bytes about to leave.
    pub tx_bytes: Vec<u8>,
}

/// Record a plain send and save it, minting [`DurableTxBytes`] only when
/// that save is [`Durability::Confirmed`].
///
/// Runs under the caller's ledger write guard (`wallet`). This function
/// writes the journal row (with `tx_bytes`) and the retained secret, then
/// saves the whole ledger under the same guard, so no refresh merge or
/// watchdog edge can interleave between the record and the save (the
/// `abandon_tx` crash-ordering contract). The minted bytes are read back
/// from the row just saved.
///
/// A save that fails before the rename undoes the record under the same
/// guard ([`WalletLedger::undo_unsaved_dispatch`]). A rename whose
/// parent-directory fsync did not confirm leaves the applied record: the
/// write is already on disk, and undoing it in memory would diverge from
/// that disk. Either outcome mints nothing, so the bytes cannot leave.
pub(crate) fn commit_dispatch<C: LedgerCommit + ?Sized>(
    wallet: &mut WalletLedger,
    commit: &C,
    record: DispatchRecord,
) -> Result<DurableTxBytes, PersistenceError> {
    let DispatchRecord {
        txid,
        retained,
        fee,
        recipients,
        inputs,
        tx_bytes,
    } = record;
    wallet.record_retained_tx_key(txid, retained);
    wallet.record_dispatched_send(txid, fee, recipients, inputs, tx_bytes);
    match commit.commit(wallet) {
        Ok(Durability::Confirmed) => {
            let bytes = wallet
                .send_journal
                .tx_bytes(&txid)
                .expect("commit_dispatch stored the bytes it authorizes")
                .to_vec();
            Ok(DurableTxBytes(bytes))
        }
        Ok(Durability::Unconfirmed) => Err(PersistenceError::DurabilityUnconfirmed),
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

    /// What one test commit reports.
    enum CommitAnswer {
        Confirmed,
        Unconfirmed,
        Fail,
    }

    /// A commit that answers on demand and counts its calls — the seam
    /// for exercising the mint without a wallet file.
    struct CountingCommit {
        answer: CommitAnswer,
        calls: AtomicUsize,
    }

    impl LedgerCommit for CountingCommit {
        fn commit(&self, _ledger: &WalletLedger) -> Result<Durability, PersistenceError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.answer {
                CommitAnswer::Confirmed => Ok(Durability::Confirmed),
                CommitAnswer::Unconfirmed => Ok(Durability::Unconfirmed),
                CommitAnswer::Fail => Err(PersistenceError::WalletFile(
                    shekyl_engine_file::WalletFileError::Io(std::io::Error::other(
                        "test: save refused",
                    )),
                )),
            }
        }
    }

    fn dispatch_record(txid: [u8; 32], bytes: Vec<u8>) -> DispatchRecord {
        DispatchRecord {
            txid,
            retained: TxSecretKey::new(zeroize::Zeroizing::new([7; 32])),
            fee: 0,
            recipients: Vec::new(),
            inputs: Vec::new(),
            tx_bytes: bytes,
        }
    }

    #[test]
    fn a_confirmed_save_mints_the_bytes_the_row_stored() {
        let mut wallet = WalletLedger::empty();
        let commit = CountingCommit {
            answer: CommitAnswer::Confirmed,
            calls: AtomicUsize::new(0),
        };
        let durable = commit_dispatch(&mut wallet, &commit, dispatch_record([1; 32], vec![9, 9]))
            .expect("save confirmed");
        assert_eq!(durable.into_bytes(), vec![9, 9]);
        assert_eq!(commit.calls.load(Ordering::SeqCst), 1);
        assert_eq!(wallet.send_journal.tx_bytes(&[1; 32]), Some(&[9u8, 9][..]));
        assert!(wallet.tx_meta.tx_keys.contains_key(&[1; 32]));
    }

    #[test]
    fn a_failed_save_mints_nothing_and_undoes_the_record() {
        let mut wallet = WalletLedger::empty();
        let commit = CountingCommit {
            answer: CommitAnswer::Fail,
            calls: AtomicUsize::new(0),
        };
        let result = commit_dispatch(&mut wallet, &commit, dispatch_record([2; 32], vec![1]));
        assert!(result.is_err());
        assert!(!wallet.send_journal.rows.contains_key(&[2; 32]));
        assert!(!wallet.tx_meta.tx_keys.contains_key(&[2; 32]));
        assert!(!wallet.sync_state.pending_tx_hashes.contains(&[2; 32]));
    }

    #[test]
    fn an_unconfirmed_save_mints_nothing_and_keeps_the_applied_record() {
        let mut wallet = WalletLedger::empty();
        let commit = CountingCommit {
            answer: CommitAnswer::Unconfirmed,
            calls: AtomicUsize::new(0),
        };
        let result = commit_dispatch(&mut wallet, &commit, dispatch_record([3; 32], vec![4, 5]));
        assert!(matches!(
            result,
            Err(PersistenceError::DurabilityUnconfirmed)
        ));
        assert_eq!(wallet.send_journal.tx_bytes(&[3; 32]), Some(&[4u8, 5][..]));
        assert!(wallet.tx_meta.tx_keys.contains_key(&[3; 32]));
        assert!(wallet.sync_state.pending_tx_hashes.contains(&[3; 32]));
    }
}
