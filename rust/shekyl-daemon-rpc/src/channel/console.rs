// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A service's console key, installed as one change (`RPC_CHANNEL.md` §5).
//!
//! The private half is a file. The fingerprint is a cell in the enrollment
//! store, and it is the admission record: a file edited by hand does not
//! become the console key. The two are written so a crash cannot leave
//! them disagreeing.
//!
//! Install writes the new key to the file's journal ([`private_file::staged_path`]),
//! commits the fingerprint and, on a reset, the reset note in one store
//! transaction, then renames the journal over the file. [`reconcile`] is
//! what the next start does with whatever of that survived:
//!
//! - a journal whose fingerprint is the cell is renamed into place;
//! - a journal that was never committed is discarded when the live file
//!   already matches the cell, and ignored when there is no cell yet (the
//!   install that follows replaces it);
//! - a live file that matches neither the cell nor a committed journal
//!   refuses the start. The reset command is the way back, and it installs
//!   a new key through the same steps.

use std::path::{Path, PathBuf};

use shekyl_rpc_channel::handshake::StaticKeypair;

use super::files::{self, FileRefused};
use super::store::{Store, StoreError};
use shekyl_os_account::private_file::{self, Access, StagedWrite};

/// What [`reconcile`] found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Reconcile {
    /// The live file is the cell's key.
    Consistent,
    /// A committed journal was renamed over the live file.
    Placed,
    /// There is no console key yet.
    Absent,
}

/// Why the console key could not be installed or reconciled.
#[derive(Debug)]
pub(crate) enum ConsoleFault {
    /// A key file could not be used.
    File(FileRefused),
    /// The enrollment store refused.
    Store(StoreError),
    /// The key could not be drawn.
    Generate(String),
    /// The file and the cell do not describe one key.
    Refuse(String),
}

impl std::fmt::Display for ConsoleFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(error) => write!(f, "{error}"),
            Self::Store(error) => write!(f, "{error}"),
            Self::Generate(error) => write!(f, "the console key could not be made: {error}"),
            Self::Refuse(reason) => f.write_str(reason),
        }
    }
}

impl From<FileRefused> for ConsoleFault {
    fn from(error: FileRefused) -> Self {
        Self::File(error)
    }
}

impl From<StoreError> for ConsoleFault {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// Install a new console key: journal, one store commit, rename.
///
/// `reset_at` is the reset note, committed in the same transaction as the
/// fingerprint. `None` is a first key, which leaves the note untouched.
/// A failure before the commit discards the journal. A failure of the
/// rename leaves it for [`reconcile`].
///
/// # Errors
///
/// [`ConsoleFault`].
pub(crate) fn install(
    dir: &Path,
    store: &Store,
    reset_at: Option<u64>,
) -> Result<PathBuf, ConsoleFault> {
    let key =
        StaticKeypair::generate().map_err(|error| ConsoleFault::Generate(error.to_string()))?;
    let fingerprint = fingerprint_of(&key);
    let live = dir.join(files::CONSOLE_KEY_FILE);
    let journal = StagedWrite::create(&live, &key.to_key_file(), Access::Console)
        .map_err(|error| FileRefused::Io(private_file::staged_path(&live), error))?;
    if let Err(error) = store.commit_console(&fingerprint, reset_at) {
        // The cell was not moved. The journal is not a key of record.
        drop(journal.discard());
        return Err(error.into());
    }
    journal
        .commit()
        .map_err(|error| FileRefused::Io(live.clone(), error))?;
    Ok(live)
}

/// Finish or refuse whatever an install left in `dir`.
///
/// # Errors
///
/// [`ConsoleFault`]. A file and a cell that are not one key is
/// [`ConsoleFault::Refuse`], and nothing is rewritten to make them agree.
pub(crate) fn reconcile(dir: &Path, store: &Store) -> Result<Reconcile, ConsoleFault> {
    let live = dir.join(files::CONSOLE_KEY_FILE);
    let journal = private_file::staged_path(&live);
    let cell = store.console()?;
    let live_key = seen(&live);
    let journal_key = seen(&journal);
    match next_step(cell, live_key.material, journal_key.material) {
        Step::Consistent => Ok(Reconcile::Consistent),
        Step::PlaceStaged => {
            // The same rename the install commits, directory sync included.
            // A crash after the rename and before the directory is durable
            // leaves the journal, and the next start places it again.
            StagedWrite::resume(&live)
                .map_err(|error| FileRefused::Io(journal.clone(), error))?
                .commit()
                .map_err(|error| FileRefused::Io(live, error))?;
            Ok(Reconcile::Placed)
        }
        Step::DiscardStaged => {
            StagedWrite::resume(&live)
                .map_err(|error| FileRefused::Io(journal.clone(), error))?
                .discard()
                .map_err(|error| FileRefused::Io(journal, error))?;
            Ok(Reconcile::Consistent)
        }
        Step::Generate => Ok(Reconcile::Absent),
        Step::Refuse(Refusal::Journal) => Err(fault_of(journal_key.fault, &journal)),
        Step::Refuse(Refusal::Live) => Err(fault_of(live_key.fault, &live)),
        Step::Refuse(Refusal::Missing) => Err(ConsoleFault::Refuse(format!(
            "{} is missing; `shekyld --rpc-console-key-reset` replaces it",
            live.display()
        ))),
        Step::Refuse(Refusal::Mismatch) => Err(ConsoleFault::Refuse(format!(
            "{} does not match the console key of record; `shekyld --rpc-console-key-reset` \
             replaces it",
            live.display()
        ))),
        Step::Refuse(Refusal::Unrecorded) => Err(ConsoleFault::Refuse(format!(
            "{} is present and the enrollment store has no console key; remove it, or replace \
             the console key with `shekyld --rpc-console-key-reset`",
            live.display()
        ))),
    }
}

fn fault_of(fault: Option<FileRefused>, path: &Path) -> ConsoleFault {
    match fault {
        Some(fault) => ConsoleFault::File(fault),
        None => ConsoleFault::Refuse(format!("{} could not be read", path.display())),
    }
}

fn fingerprint_of(key: &StaticKeypair) -> [u8; 32] {
    *key.public().fingerprint().as_bytes()
}

/// What a path holds, for [`next_step`]. The file fault is kept so a refusal
/// can say what `read_key` said.
struct Seen {
    material: KeyMaterial,
    fault: Option<FileRefused>,
}

fn seen(path: &Path) -> Seen {
    match files::read_console_key(path) {
        Ok(None) => Seen {
            material: KeyMaterial::Absent,
            fault: None,
        },
        Ok(Some(key)) => Seen {
            material: KeyMaterial::Fingerprint(fingerprint_of(&key)),
            fault: None,
        },
        Err(error @ FileRefused::Exposed(..)) => Seen {
            material: KeyMaterial::Bad(BadKey::Exposed),
            fault: Some(error),
        },
        Err(error @ FileRefused::Key(..)) => Seen {
            material: KeyMaterial::Bad(BadKey::NotAKey),
            fault: Some(error),
        },
        Err(error @ FileRefused::Io(..)) => Seen {
            material: KeyMaterial::Bad(BadKey::Unreadable),
            fault: Some(error),
        },
    }
}

/// A key file reduced to what the recovery plan needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyMaterial {
    Absent,
    Fingerprint([u8; 32]),
    Bad(BadKey),
}

/// Why a present file is not a fingerprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BadKey {
    /// Another account can read it.
    Exposed,
    /// Not a key file this build reads.
    NotAKey,
    /// The read failed.
    Unreadable,
}

/// What to do, with no IO.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Consistent,
    /// The journal's fingerprint is the cell. Rename it over the live file.
    PlaceStaged,
    /// The live file is the cell. The journal is not, so remove it.
    DiscardStaged,
    /// No cell. The caller installs a key; its create replaces a journal.
    Generate,
    Refuse(Refusal),
}

/// A state install does not repair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    /// The journal's own fault.
    Journal,
    /// The live file's own fault.
    Live,
    /// The cell's key is not on disk.
    Missing,
    /// The live file is a different key, and the journal is not the cell.
    Mismatch,
    /// A live file exists and the store has no console key.
    Unrecorded,
}

/// The recovery plan. The cell wins. The journal finishes a commit that
/// names it, and never overrules a cell it does not match.
fn next_step(cell: Option<[u8; 32]>, live: KeyMaterial, journal: KeyMaterial) -> Step {
    let Some(cell) = cell else {
        return without_record(live, journal);
    };
    if let KeyMaterial::Fingerprint(fingerprint) = journal {
        if fingerprint == cell {
            return Step::PlaceStaged;
        }
    }
    if let KeyMaterial::Fingerprint(fingerprint) = live {
        if fingerprint == cell {
            return match journal {
                KeyMaterial::Absent => Step::Consistent,
                KeyMaterial::Bad(BadKey::Exposed) => Step::Refuse(Refusal::Journal),
                KeyMaterial::Bad(_) | KeyMaterial::Fingerprint(_) => Step::DiscardStaged,
            };
        }
    }
    match (live, journal) {
        (KeyMaterial::Absent, KeyMaterial::Bad(_)) => Step::Refuse(Refusal::Journal),
        (KeyMaterial::Absent, _) => Step::Refuse(Refusal::Missing),
        (KeyMaterial::Bad(_), _) => Step::Refuse(Refusal::Live),
        (KeyMaterial::Fingerprint(_), _) => Step::Refuse(Refusal::Mismatch),
    }
}

/// No cell has been committed. A live file is not adopted: nothing has
/// recorded it. A journal is replaced by the install that follows, unless
/// it cannot be read or another account can read it.
fn without_record(live: KeyMaterial, journal: KeyMaterial) -> Step {
    if !matches!(live, KeyMaterial::Absent) {
        return Step::Refuse(Refusal::Unrecorded);
    }
    match journal {
        KeyMaterial::Bad(BadKey::Exposed | BadKey::Unreadable) => Step::Refuse(Refusal::Journal),
        KeyMaterial::Absent | KeyMaterial::Fingerprint(_) | KeyMaterial::Bad(BadKey::NotAKey) => {
            Step::Generate
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(byte: u8) -> KeyMaterial {
        KeyMaterial::Fingerprint([byte; 32])
    }

    /// The plan is a table: the cell, then the journal that matches it, and
    /// a file with no cell is never adopted. Red edit: return `PlaceStaged`
    /// for a journal the cell does not name, and a hand-written key becomes
    /// the console key.
    #[test]
    fn the_recovery_plan_follows_the_cell() {
        let cell = [1u8; 32];
        let cases = [
            (
                None,
                fp(2),
                KeyMaterial::Absent,
                Step::Refuse(Refusal::Unrecorded),
            ),
            (None, KeyMaterial::Absent, fp(2), Step::Generate),
            (
                None,
                KeyMaterial::Absent,
                KeyMaterial::Absent,
                Step::Generate,
            ),
            (
                None,
                KeyMaterial::Absent,
                KeyMaterial::Bad(BadKey::NotAKey),
                Step::Generate,
            ),
            (
                None,
                KeyMaterial::Absent,
                KeyMaterial::Bad(BadKey::Exposed),
                Step::Refuse(Refusal::Journal),
            ),
            (Some(cell), fp(1), KeyMaterial::Absent, Step::Consistent),
            (Some(cell), fp(2), fp(1), Step::PlaceStaged),
            (Some(cell), KeyMaterial::Absent, fp(1), Step::PlaceStaged),
            (Some(cell), fp(1), fp(2), Step::DiscardStaged),
            (
                Some(cell),
                fp(1),
                KeyMaterial::Bad(BadKey::NotAKey),
                Step::DiscardStaged,
            ),
            (
                Some(cell),
                fp(1),
                KeyMaterial::Bad(BadKey::Exposed),
                Step::Refuse(Refusal::Journal),
            ),
            (
                Some(cell),
                fp(2),
                KeyMaterial::Absent,
                Step::Refuse(Refusal::Mismatch),
            ),
            (
                Some(cell),
                KeyMaterial::Absent,
                KeyMaterial::Absent,
                Step::Refuse(Refusal::Missing),
            ),
            (
                Some(cell),
                KeyMaterial::Absent,
                fp(2),
                Step::Refuse(Refusal::Missing),
            ),
            (
                Some(cell),
                KeyMaterial::Bad(BadKey::NotAKey),
                KeyMaterial::Absent,
                Step::Refuse(Refusal::Live),
            ),
            (
                Some(cell),
                KeyMaterial::Bad(BadKey::Exposed),
                fp(1),
                Step::PlaceStaged,
            ),
        ];
        for (cell, live, journal, want) in cases {
            assert_eq!(next_step(cell, live, journal), want, "{live:?} {journal:?}");
        }
    }

    /// Install leaves one private key, the cell names it, and a reset's note
    /// is in that same commit. Red edit: commit the note after the rename,
    /// and a crash between them is the window this test's order forbids.
    #[test]
    fn install_commits_the_fingerprint_with_the_note_then_renames() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let live = install(dir.path(), &store, Some(9)).unwrap();
        assert!(!private_file::staged_path(&live).exists());
        let key = files::read_key(&live).unwrap().unwrap();
        assert_eq!(store.console().unwrap(), Some(fingerprint_of(&key)));
        assert_eq!(store.take_console_reset().unwrap(), Some(9));
    }

    /// A committed journal whose live file was not renamed is finished, and
    /// a journal the cell does not name is removed. A live file the cell
    /// does not name is left in place and refused. Red edit: adopt the live
    /// file when it disagrees, and the mismatch case starts.
    #[test]
    fn reconcile_finishes_a_commit_and_refuses_a_disagreement() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let live = install(dir.path(), &store, None).unwrap();
        let cell = store.console().unwrap().unwrap();
        let record = std::fs::read(&live).unwrap();

        let other = StaticKeypair::generate().unwrap();
        std::fs::remove_file(&live).unwrap();
        files::write_private(&live, &other.to_key_file()).unwrap();
        files::write_private(&private_file::staged_path(&live), &record).unwrap();
        assert_eq!(reconcile(dir.path(), &store).unwrap(), Reconcile::Placed);
        assert!(!private_file::staged_path(&live).exists());
        assert_eq!(
            fingerprint_of(&files::read_key(&live).unwrap().unwrap()),
            cell
        );

        let stray = StaticKeypair::generate().unwrap();
        files::write_private(&private_file::staged_path(&live), &stray.to_key_file()).unwrap();
        assert_eq!(
            reconcile(dir.path(), &store).unwrap(),
            Reconcile::Consistent
        );
        assert!(!private_file::staged_path(&live).exists());

        std::fs::remove_file(&live).unwrap();
        files::write_private(&live, &other.to_key_file()).unwrap();
        let refused = reconcile(dir.path(), &store).unwrap_err();
        assert!(refused.to_string().contains("does not match"), "{refused}");
        assert_eq!(store.console().unwrap(), Some(cell));
        assert_eq!(
            fingerprint_of(&files::read_key(&live).unwrap().unwrap()),
            fingerprint_of(&other),
            "a refused file is left as it was"
        );
    }

    /// A file with no cell is not the console key, and an uncommitted
    /// journal is replaced by the install. Red edit: record the live file's
    /// fingerprint when the cell is empty, and the planted key is admitted.
    #[test]
    fn a_file_with_no_cell_is_not_adopted() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let live = dir.path().join(files::CONSOLE_KEY_FILE);
        let planted = StaticKeypair::generate().unwrap();
        files::write_private(&live, &planted.to_key_file()).unwrap();
        let refused = reconcile(dir.path(), &store).unwrap_err();
        assert!(refused.to_string().contains("no console key"), "{refused}");
        assert!(store.console().unwrap().is_none());

        std::fs::remove_file(&live).unwrap();
        files::write_private(&private_file::staged_path(&live), &planted.to_key_file()).unwrap();
        assert_eq!(reconcile(dir.path(), &store).unwrap(), Reconcile::Absent);
        let installed = install(dir.path(), &store, None).unwrap();
        assert_ne!(
            fingerprint_of(&files::read_key(&installed).unwrap().unwrap()),
            fingerprint_of(&planted)
        );
        assert!(!private_file::staged_path(&installed).exists());
    }
}
