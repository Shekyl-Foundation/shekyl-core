// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The enrolled set (RT-O34; `RPC_CHANNEL.md` §5): a redb store of its own
//! in the network's data directory, owned by the RPC channel, changed only
//! through the enrollment methods and the console key's reset. There is no
//! file to edit behind the daemon's back.
//!
//! The file is the account's alone, as the channel's key files are
//! ([`super::files::private_store`]): created owner-only on a first start
//! and refused, never repaired, when another account can read it.
//!
//! One record per client fingerprint: its ceiling as expanded grants (never
//! a preset's name, IG-Q87), when it was enrolled, and by whom. The console
//! key, a service's, is not an enrollment: it sits in a cell of its own and
//! is never listed, set or removed through the enrollment methods.

use std::path::Path;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use shekyl_rpc_grants::GrantSet;

/// The store's file in the data directory.
pub const STORE_FILE: &str = "rpc-enrollments.redb";

/// Fingerprint → [`Enrollment::to_bytes`].
const ENROLLMENTS: TableDefinition<'static, &[u8; 32], &[u8]> = TableDefinition::new("enrollments");

/// The width of a cell in [`SINGLES`]. The console fingerprint fills it;
/// the reset note uses the first [`RESET_NOTE_LEN`] bytes.
const SINGLE_CELL: usize = 32;

/// The console key's fingerprint, under [`CONSOLE`].
const SINGLES: TableDefinition<'static, &str, &[u8; SINGLE_CELL]> = TableDefinition::new("singles");
const CONSOLE: &str = "console";
/// Set by the console key's reset, read and cleared by the next start,
/// which logs it (§5): the first 8 bytes are when, in seconds since the
/// Unix epoch, little-endian.
const CONSOLE_RESET: &str = "console-reset";

/// A record's first byte: its version (rule 42's discipline for persisted
/// state: a change of shape is a new version, refused by an older reader).
pub const RECORD_VERSION: u8 = 1;

/// Who enrolled a client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enroller {
    /// The daemon's owner, on the owner's socket or pipe, or a plaintext
    /// listener at the host's authority.
    Host,
    /// The console key.
    Console,
    /// An enrolled client, by its fingerprint.
    Client([u8; 32]),
}

/// One enrollment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Enrollment {
    /// The ceiling, expanded.
    pub ceiling: GrantSet,
    /// When, in seconds since the Unix epoch.
    pub enrolled_at: u64,
    /// By whom.
    pub by: Enroller,
}

impl Enrollment {
    const LEN: usize = 1 + 2 + 8 + 1 + 32;

    fn to_bytes(self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0] = RECORD_VERSION;
        out[1..3].copy_from_slice(&self.ceiling.bits().to_le_bytes());
        out[3..11].copy_from_slice(&self.enrolled_at.to_le_bytes());
        let (kind, who) = match self.by {
            Enroller::Host => (0, [0u8; 32]),
            Enroller::Console => (1, [0u8; 32]),
            Enroller::Client(fingerprint) => (2, fingerprint),
        };
        out[11] = kind;
        out[12..].copy_from_slice(&who);
        out
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        let corrupt = || StoreError::Corrupt;
        if bytes.len() != Self::LEN || bytes[0] != RECORD_VERSION {
            return Err(corrupt());
        }
        let ceiling =
            GrantSet::from_bits(u16::from_le_bytes([bytes[1], bytes[2]])).map_err(|_| corrupt())?;
        let enrolled_at = u64::from_le_bytes(bytes[3..11].try_into().map_err(|_| corrupt())?);
        let who: [u8; 32] = bytes[12..].try_into().map_err(|_| corrupt())?;
        let by = match bytes[11] {
            0 => Enroller::Host,
            1 => Enroller::Console,
            2 => Enroller::Client(who),
            _ => return Err(corrupt()),
        };
        Ok(Self {
            ceiling,
            enrolled_at,
            by,
        })
    }
}

/// Why the store could not answer.
#[derive(Debug)]
pub enum StoreError {
    /// The store's file is exposed, or could not be created or read.
    File(super::files::FileRefused),
    /// redb refused.
    Db(String),
    /// A record this build does not read.
    Corrupt,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(e) => write!(f, "the enrollment store: {e}"),
            Self::Db(e) => write!(f, "the enrollment store: {e}"),
            Self::Corrupt => {
                f.write_str("the enrollment store holds a record this build does not read")
            }
        }
    }
}

impl std::error::Error for StoreError {}

fn db_err(e: impl std::fmt::Display) -> StoreError {
    StoreError::Db(e.to_string())
}

/// The enrolled set.
pub struct Store {
    db: Database,
}

impl Store {
    /// Open the store in `data_dir`, creating it owner-only on a first
    /// start.
    ///
    /// # Errors
    ///
    /// [`StoreError::File`] when its file is exposed or cannot be made;
    /// [`StoreError::Db`] when redb cannot open or create it.
    pub fn open(data_dir: &Path) -> Result<Self, StoreError> {
        let path = data_dir.join(STORE_FILE);
        super::files::private_store(&path).map_err(StoreError::File)?;
        let db = Database::create(&path).map_err(db_err)?;
        let txn = db.begin_write().map_err(db_err)?;
        txn.open_table(ENROLLMENTS).map_err(db_err)?;
        txn.open_table(SINGLES).map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(Self { db })
    }

    /// The enrollment of `fingerprint`, if there is one.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    pub fn get(&self, fingerprint: &[u8; 32]) -> Result<Option<Enrollment>, StoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(ENROLLMENTS).map_err(db_err)?;
        table
            .get(fingerprint)
            .map_err(db_err)?
            .map(|value| Enrollment::from_bytes(value.value()))
            .transpose()
    }

    /// Every enrollment, by fingerprint.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    pub fn list(&self) -> Result<Vec<([u8; 32], Enrollment)>, StoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(ENROLLMENTS).map_err(db_err)?;
        let mut out = Vec::new();
        for entry in table.iter().map_err(db_err)? {
            let (key, value) = entry.map_err(db_err)?;
            out.push((*key.value(), Enrollment::from_bytes(value.value())?));
        }
        Ok(out)
    }

    /// Write `enrollment` for `fingerprint`, replacing any.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    pub fn put(&self, fingerprint: &[u8; 32], enrollment: Enrollment) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut table = txn.open_table(ENROLLMENTS).map_err(db_err)?;
            table
                .insert(fingerprint, enrollment.to_bytes().as_slice())
                .map_err(db_err)?;
        }
        txn.commit().map_err(db_err)
    }

    /// Remove `fingerprint`'s enrollment; whether there was one.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    pub fn remove(&self, fingerprint: &[u8; 32]) -> Result<bool, StoreError> {
        let txn = self.db.begin_write().map_err(db_err)?;
        let removed = {
            let mut table = txn.open_table(ENROLLMENTS).map_err(db_err)?;
            let removed = table.remove(fingerprint).map_err(db_err)?.is_some();
            removed
        };
        txn.commit().map_err(db_err)?;
        Ok(removed)
    }

    /// The console key's fingerprint, when this daemon has one.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    pub fn console(&self) -> Result<Option<[u8; 32]>, StoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(SINGLES).map_err(db_err)?;
        Ok(table.get(CONSOLE).map_err(db_err)?.map(|v| *v.value()))
    }

    /// Record `fingerprint` as the console key and, when `reset_at` is set,
    /// the reset note, in one transaction.
    ///
    /// This is the cell's only write. The private half is the journal
    /// [`super::console::install`] renames after this commit; a fingerprint
    /// with no key file is not a console key the next start will adopt.
    /// `None` leaves a reset note already stored untouched, which is a
    /// first key.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    pub fn commit_console(
        &self,
        fingerprint: &[u8; 32],
        reset_at: Option<u64>,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut table = txn.open_table(SINGLES).map_err(db_err)?;
            table.insert(CONSOLE, fingerprint).map_err(db_err)?;
            if let Some(at) = reset_at {
                table
                    .insert(CONSOLE_RESET, &reset_note(at))
                    .map_err(db_err)?;
            }
        }
        txn.commit().map_err(db_err)
    }

    /// When the console key was last replaced, if no start has logged it
    /// yet; clears the note.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    pub fn take_console_reset(&self) -> Result<Option<u64>, StoreError> {
        let txn = self.db.begin_write().map_err(db_err)?;
        let at = {
            let mut table = txn.open_table(SINGLES).map_err(db_err)?;
            let at = table.remove(CONSOLE_RESET).map_err(db_err)?.map(|cell| {
                let cell = cell.value();
                let mut at = [0u8; RESET_NOTE_LEN];
                at.copy_from_slice(&cell[..RESET_NOTE_LEN]);
                u64::from_le_bytes(at)
            });
            at
        };
        txn.commit().map_err(db_err)?;
        Ok(at)
    }
}

/// The reset note's width: when, in seconds since the Unix epoch. The rest
/// of the cell stays zero.
const RESET_NOTE_LEN: usize = std::mem::size_of::<u64>();

fn reset_note(at: u64) -> [u8; SINGLE_CELL] {
    let mut cell = [0u8; SINGLE_CELL];
    cell[..RESET_NOTE_LEN].copy_from_slice(&at.to_le_bytes());
    cell
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_rpc_grants::Preset;

    /// The store is the account's alone, as a key file is: created
    /// owner-only, and refused when another account can read it. Red edit:
    /// drop the check in `Store::open`, and the exposed store opens.
    #[cfg(unix)]
    #[test]
    fn the_store_is_the_accounts_alone_and_an_exposed_one_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STORE_FILE);
        drop(Store::open(dir.path()).unwrap());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        drop(Store::open(dir.path()).unwrap());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            Store::open(dir.path()),
            Err(StoreError::File(super::super::files::FileRefused::Exposed(
                ..
            )))
        ));
    }

    /// Windows: the store is created with the owner-only, no-read-up
    /// descriptor a key file has, and passes the same check.
    #[cfg(windows)]
    #[test]
    fn the_store_is_created_owner_only_and_labelled() {
        let dir = tempfile::tempdir().unwrap();
        drop(Store::open(dir.path()).unwrap());
        shekyl_win_sec::rendezvous::check_owner_only_labelled(&dir.path().join(STORE_FILE))
            .expect("owner-only and labelled");
        drop(Store::open(dir.path()).unwrap());
    }

    /// An enrollment is stored as its expanded grants and reads back whole,
    /// across a reopen; the console cell is separate from the enrollments.
    /// Red edit: write the ceiling's bits big-endian, and a reopened
    /// `wallet` ceiling reads as another set.
    #[test]
    fn an_enrollment_survives_a_reopen_as_expanded_grants() {
        let dir = tempfile::tempdir().unwrap();
        let fp = [7u8; 32];
        let enrollment = Enrollment {
            ceiling: Preset::Wallet.grants(),
            enrolled_at: 1_789_000_000,
            by: Enroller::Client([9u8; 32]),
        };
        {
            let store = Store::open(dir.path()).unwrap();
            store.put(&fp, enrollment).unwrap();
            store.commit_console(&[1u8; 32], None).unwrap();
        }
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.get(&fp).unwrap(), Some(enrollment));
        assert_eq!(store.list().unwrap(), vec![(fp, enrollment)]);
        assert_eq!(store.console().unwrap(), Some([1u8; 32]));
        assert!(store.remove(&fp).unwrap());
        assert!(!store.remove(&fp).unwrap());
        assert!(store.list().unwrap().is_empty());
        assert_eq!(store.console().unwrap(), Some([1u8; 32]));
    }

    /// A record of another version is refused, never read as this one.
    #[test]
    fn a_record_of_another_version_is_refused() {
        let mut bytes = Enrollment {
            ceiling: GrantSet::ALL,
            enrolled_at: 0,
            by: Enroller::Host,
        }
        .to_bytes();
        bytes[0] = 2;
        assert!(matches!(
            Enrollment::from_bytes(&bytes),
            Err(StoreError::Corrupt)
        ));
    }
}
