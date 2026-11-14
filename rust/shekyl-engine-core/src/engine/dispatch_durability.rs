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
//! - [`DurableTxBytes::from_fresh_seal`] — a claim, drain, release or bond
//!   post whose pending-store save just returned [`Durability::Confirmed`].
//! - [`DurableTxBytes::from_loaded_seal`] — a resend of bytes
//!   [`PBoundBytes::from_pending`] read back out of that store.
//!
//! The watchdog's probe and the user's resend of a held send
//! (`held_sends.rs`) re-offer bytes read back from the saved journal row
//! straight to the daemon, not through a submitter: each is a status query
//! over bytes whose record is already on disk.
//!
//! # One save
//!
//! [`commit_or_restore`] and [`commit_keeping`] are the two policies over
//! one save. A broadcast that has not yet left restores the edit when the
//! rename does not land ([`commit_dispatch`], [`commit_release`]). A fact
//! that has already happened keeps the edit, so this process and the disk
//! agree once the next save confirms ([`commit_verdict`]). Only
//! [`Durability::Confirmed`] mints bytes that may leave.

use std::collections::HashSet;

use shekyl_engine_file::Durability;
use shekyl_engine_state::{SendInputRef, SendRecipient, SendRecord, TxSecretKey, WalletLedger};
use shekyl_types::TxHash;

use super::bond_assembly::{LoadedSeal, PBoundBytes};
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
    /// Bytes whose pending-store save just returned `durability`.
    ///
    /// Only [`Durability::Confirmed`] mints. [`Durability::Unconfirmed`]
    /// keeps the applied seal and refuses the hand-off: the rename is
    /// visible, and a crash before the directory entry is journaled must
    /// not meet bytes that have already left.
    pub(crate) fn from_fresh_seal(
        bound: PBoundBytes,
        durability: Durability,
    ) -> Result<Self, PersistenceError> {
        require_confirmed(durability)?;
        Ok(Self(bound.into_bytes()))
    }

    /// Bytes [`PBoundBytes::from_pending`] read back from the sealed store.
    ///
    /// The load is the witness: the store returned the record. A fresh
    /// assembly does not construct a [`LoadedSeal`].
    pub(crate) fn from_loaded_seal(seal: LoadedSeal) -> Self {
        Self(seal.into_bytes())
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

/// Apply `edit`, then save. A save that fails before the rename runs
/// `restore` under the caller's guard and returns the error. An applied
/// write, confirmed or not, leaves the edit in place.
pub(crate) fn commit_or_restore<C, E, R>(
    wallet: &mut WalletLedger,
    commit: &C,
    edit: E,
    restore: R,
) -> Result<Durability, PersistenceError>
where
    C: LedgerCommit + ?Sized,
    E: FnOnce(&mut WalletLedger),
    R: FnOnce(&mut WalletLedger),
{
    edit(wallet);
    restore_unless_saved(commit.commit(wallet), || restore(wallet))
}

/// Apply `edit`, then save. A failed save leaves the edit: the fact it
/// records has already happened, and undoing it would drop a lock whose
/// bytes have left, or forget a refusal the daemon already gave.
pub(crate) fn commit_keeping<C, E>(
    wallet: &mut WalletLedger,
    commit: &C,
    edit: E,
) -> Result<Durability, PersistenceError>
where
    C: LedgerCommit + ?Sized,
    E: FnOnce(&mut WalletLedger),
{
    edit(wallet);
    commit.commit(wallet)
}

/// `Ok` passes through. `Err` runs `restore`, then returns the error.
pub(crate) fn restore_unless_saved(
    result: Result<Durability, PersistenceError>,
    restore: impl FnOnce(),
) -> Result<Durability, PersistenceError> {
    match result {
        Ok(durability) => Ok(durability),
        Err(error) => {
            restore();
            Err(error)
        }
    }
}

/// The save authorized a broadcast.
pub(crate) fn require_confirmed(durability: Durability) -> Result<(), PersistenceError> {
    match durability {
        Durability::Confirmed => Ok(()),
        Durability::Unconfirmed => Err(PersistenceError::DurabilityUnconfirmed),
    }
}

/// An applied write is enough: nothing will be broadcast on this save.
///
/// Exhaustive so a third [`Durability`] variant has to choose a policy.
pub(crate) fn accept_applied(durability: Durability) {
    match durability {
        Durability::Confirmed | Durability::Unconfirmed => {}
    }
}

/// What a definite daemon verdict writes on the send journal.
///
/// The finalizer names the edit. [`commit_verdict`] applies it and saves
/// it under one ledger write guard, after the pending-tx state lock has
/// been released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerdictEdit {
    /// Fresh accept or pool duplicate. Baseline the lock at the wallet's
    /// synced height, read inside the save's guard.
    LockAtSyncedHeight {
        /// Canonical transaction id.
        txid: [u8; 32],
    },
    /// Already-in-chain. Baseline at `min(claimed_height, synced)`.
    LockAtClaimedHeight {
        /// Canonical transaction id.
        txid: [u8; 32],
        /// Daemon-claimed confirming height. Untrusted; the baseline is
        /// clamped to a height this wallet has reached.
        claimed_height: u64,
    },
    /// Definite terminal refusal. The row stays as failed-send history.
    TerminalRefusal {
        /// Canonical transaction id.
        txid: [u8; 32],
    },
    /// Definite retryable refusal. The dispatch row is removed.
    RetryableRefusal {
        /// Canonical transaction id.
        txid: [u8; 32],
    },
}

/// What [`commit_verdict`] did with a [`VerdictEdit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AppliedVerdict {
    /// The parent-directory fsync confirmed the edit.
    pub saved: bool,
    /// The already-in-chain claim sits at or behind the synced height,
    /// so the caller enqueues a targeted rescan after releasing this guard.
    /// The pair is `(txid, claimed_height)`.
    pub rescan: Option<([u8; 32], u64)>,
}

/// Apply `edit` and save it, keeping the edit if the save fails.
///
/// The bytes have already left, or the daemon has already refused them.
/// A pre-rename failure is logged and reported through
/// [`AppliedVerdict::saved`]; the in-memory edit stays so this process
/// keeps the lock or the refusal. The next successful save writes it.
pub(crate) fn commit_verdict<C: LedgerCommit + ?Sized>(
    wallet: &mut WalletLedger,
    commit: &C,
    edit: VerdictEdit,
) -> AppliedVerdict {
    let saved = match commit_keeping(wallet, commit, |wallet| apply_verdict(wallet, edit)) {
        Ok(Durability::Confirmed) => true,
        Ok(Durability::Unconfirmed) => {
            tracing::warn!(
                "submit: the verdict stands, but saving it was not confirmed; \
                 the next save writes it"
            );
            false
        }
        Err(error) => {
            tracing::error!(
                %error,
                "submit: the verdict stands, but saving it failed; the next save writes it"
            );
            false
        }
    };
    let rescan = match edit {
        VerdictEdit::LockAtClaimedHeight {
            txid,
            claimed_height,
        } if claimed_height <= wallet.ledger.height().to_raw() => Some((txid, claimed_height)),
        _ => None,
    };
    AppliedVerdict { saved, rescan }
}

fn apply_verdict(wallet: &mut WalletLedger, edit: VerdictEdit) {
    match edit {
        VerdictEdit::LockAtSyncedHeight { txid } => {
            let height = wallet.ledger.height().to_raw();
            wallet.stamp_send_lock_baseline(&txid, height);
        }
        VerdictEdit::LockAtClaimedHeight {
            txid,
            claimed_height,
        } => {
            let synced = wallet.ledger.height().to_raw();
            wallet.stamp_send_lock_baseline(&txid, claimed_height.min(synced));
        }
        VerdictEdit::TerminalRefusal { txid } => {
            wallet.retire_retained_tx_key(&txid);
            wallet.send_journal.mark_terminal_rejected(&txid);
        }
        VerdictEdit::RetryableRefusal { txid } => {
            wallet.retire_retained_tx_key(&txid);
            wallet.send_journal.undo_dispatch(&txid);
        }
    }
}

/// What [`commit_release`] did with the confirmed-absent release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReleasePersistence {
    /// No row held a lock. Nothing was written.
    Unchanged,
    /// The release is on disk and the parent-directory fsync confirmed it.
    Confirmed,
    /// The release was applied and the parent-directory fsync did not
    /// confirm it. The in-memory rows match that applied write.
    Unconfirmed,
    /// The save failed before the rename. The rows were restored.
    NotSaved,
}

impl ReleasePersistence {
    /// The inputs are free across a crash: nothing was locked, or the
    /// release was confirmed.
    pub(crate) fn inputs_confirmed_free(self) -> bool {
        matches!(self, Self::Confirmed | Self::Unchanged)
    }
}

/// Release the F14 locks under `tx_hashes` and save that release.
///
/// The whole [`SendRecord`] is the undo image. A save that fails before
/// the rename puts those rows back, so a later field of the release
/// cannot survive a failed save. Nothing is written when no lock clears.
pub(crate) fn commit_release<C: LedgerCommit + ?Sized>(
    wallet: &mut WalletLedger,
    commit: &C,
    tx_hashes: &HashSet<TxHash>,
) -> ReleasePersistence {
    if tx_hashes.is_empty() {
        return ReleasePersistence::Unchanged;
    }
    let before: Vec<([u8; 32], SendRecord)> = tx_hashes
        .iter()
        .filter_map(|tx| {
            let key = tx.to_bytes();
            wallet
                .send_journal
                .rows
                .get(&key)
                .cloned()
                .map(|row| (key, row))
        })
        .collect();
    super::submit_watchdog::release_awaiting_confirmation(wallet, tx_hashes);
    let changed = before
        .iter()
        .any(|(key, row)| wallet.send_journal.rows.get(key) != Some(row));
    if !changed {
        return ReleasePersistence::Unchanged;
    }
    match restore_unless_saved(commit.commit(wallet), || {
        for (key, row) in before {
            match wallet.send_journal.rows.get_mut(&key) {
                Some(slot) => *slot = row,
                None => {
                    wallet.send_journal.rows.insert(key, row);
                }
            }
        }
    }) {
        Ok(Durability::Confirmed) => ReleasePersistence::Confirmed,
        Ok(Durability::Unconfirmed) => {
            tracing::warn!(
                "watchdog: the release of a send that will not confirm was applied \
                 but not confirmed; the next confirmed save writes it"
            );
            ReleasePersistence::Unconfirmed
        }
        Err(error) => {
            tracing::error!(
                %error,
                "watchdog: the release of a send that will not confirm could not be \
                 saved; its inputs stay locked and the next probe asks again"
            );
            ReleasePersistence::NotSaved
        }
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
    let durability = commit_or_restore(
        wallet,
        commit,
        |wallet| {
            wallet.record_retained_tx_key(txid, retained);
            wallet.record_dispatched_send(txid, fee, recipients, inputs, tx_bytes);
        },
        |wallet| wallet.undo_unsaved_dispatch(&txid),
    )?;
    require_confirmed(durability)?;
    let bytes = wallet
        .send_journal
        .tx_bytes(&txid)
        .expect("commit_dispatch stored the bytes it authorizes")
        .to_vec();
    Ok(DurableTxBytes(bytes))
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

    #[test]
    fn a_failed_verdict_save_keeps_the_lock() {
        let mut wallet = WalletLedger::empty();
        let confirmed = CountingCommit {
            answer: CommitAnswer::Confirmed,
            calls: AtomicUsize::new(0),
        };
        commit_dispatch(&mut wallet, &confirmed, dispatch_record([4; 32], vec![1]))
            .expect("dispatch saved");
        let fail = CountingCommit {
            answer: CommitAnswer::Fail,
            calls: AtomicUsize::new(0),
        };
        let applied = commit_verdict(
            &mut wallet,
            &fail,
            VerdictEdit::TerminalRefusal { txid: [4; 32] },
        );
        assert!(!applied.saved);
        let row = wallet.send_journal.rows.get(&[4; 32]).unwrap();
        assert!(matches!(
            row.state,
            shekyl_engine_state::SendState::TerminalRejected
        ));
        assert!(row.tx_bytes.is_none());
    }

    #[test]
    fn a_failed_release_restores_the_whole_row() {
        let mut wallet = WalletLedger::empty();
        let confirmed = CountingCommit {
            answer: CommitAnswer::Confirmed,
            calls: AtomicUsize::new(0),
        };
        commit_dispatch(
            &mut wallet,
            &confirmed,
            dispatch_record([5; 32], vec![8, 8]),
        )
        .expect("dispatch saved");
        let before = wallet.send_journal.rows.get(&[5; 32]).unwrap().clone();
        let fail = CountingCommit {
            answer: CommitAnswer::Fail,
            calls: AtomicUsize::new(0),
        };
        let mut held = std::collections::HashSet::new();
        held.insert(TxHash::from_bytes([5; 32]));
        assert_eq!(
            commit_release(&mut wallet, &fail, &held),
            ReleasePersistence::NotSaved
        );
        assert_eq!(wallet.send_journal.rows.get(&[5; 32]), Some(&before));
    }
}
