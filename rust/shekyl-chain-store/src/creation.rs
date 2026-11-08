// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A file's creation that a power loss cut off: what is left at the path,
//! and how an open finishes it instead of refusing it.
//!
//! Both stores create their file in three durable steps: `create_new`
//! claims the path, the engine initializes the file (its header, then its
//! magic number, each flushed), and the store seals it in its first
//! transaction. PB-S2's first power-loss replay (2026-11-01,
//! `DAEMON_REDB_STORE.md` §1.3a) found a node that could not start again
//! after a cut between any two of them. What each cut leaves is
//! recognizable, and only those shapes are finished:
//!
//! - **Nothing was written.** The file is empty. `create_new` had claimed
//!   the path and the process died before the engine's first flush.
//! - **The engine flushed its header and not its magic.** redb writes the
//!   magic only after the rest of the header is durable
//!   (`redb-4.4.0` `page_manager.rs`, the `to_bytes(false)` flush, then
//!   `to_bytes(true)`). That image is one length, a clear magic slot, the
//!   two-phase god byte, the engine's page size, and two slots that have
//!   never committed ([`header_image`]). A sealed store stays that same
//!   length until its first region fills, so length is not the test: a
//!   zero-filled file, and a sealed file whose magic bytes were cleared,
//!   both fail the header and stay where they are.
//! - **The engine finished, the seal did not.** A valid database with no
//!   table at all ([`no_table`]). The caller seals it in place.
//!
//! Anything else — a file with any table and no seal, foreign bytes, a
//! zero-filled file of the initialization length — is not a creation this
//! crate can prove it made, and stays refused, byte for byte.
//!
//! # The path, not only the inode
//!
//! [`set_aside_unfinished_init`] classifies under the store file's own
//! lock and renames while that lock is held, on platforms where an open
//! file can be renamed. The lock does not follow the directory entry: a
//! second open could otherwise claim the path in the gap and seal a
//! different file there. [`PathGuard`] is that exclusion, one sibling
//! lock file shared by the chain and the pool, taken before `create_new`
//! or the read-only filter and dropped only once the engine holds the
//! store file. A read-only open takes neither the guard nor the repair.
//! The lock file is runtime exclusion, not a store schema, and it stays
//! in the directory: deleting it reopens the gap.

use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read};
use std::path::{Path, PathBuf};

use redb::ReadTransaction;

use crate::store::{EngineError, StoreError};

/// The bytes redb's initialization flushes, at the default page and region
/// size both stores use. Pinned against the engine in `Cargo.lock` by
/// `the_engine_writes_its_magic_last_within_the_bound`: the pre-magic flush
/// and the magic flush are this long, and a young store stays this long
/// after it has committed. Length is the image's size, not a signal that
/// anything has been committed.
pub(crate) const ENGINE_INIT_LEN: u64 = 1_056_768;

/// How many aside names one move will try before it reports that none is
/// free. The first is `<name>.unfinished-<unix seconds>`; the rest append
/// `-<n>`. A second move in the same second takes the next name.
const ASIDE_NAME_TRIES: u32 = 1024;

const _: () = assert!(header_image::DB_HEADER_LEN as u64 <= ENGINE_INIT_LEN);

/// redb 4.4's database header, the fields this crate reads to recognize
/// an initialization that died before the magic flush.
///
/// Offsets are redb's, from `redb-4.4.0/src/tree_store/page_store/header.rs`
/// (`MAGICNUMBER`, the god byte, `PAGE_SIZE`, the two commit slots) and
/// `btree_base.rs` (`BtreeHeader::serialized_size`). A bump that moves the
/// header fails `the_engine_writes_its_magic_last_within_the_bound`, which
/// runs this recognizer on the engine's own flushes.
mod header_image {
    /// `MAGICNUMBER`'s width.
    pub(super) const MAGIC_LEN: usize = 9;
    /// `GOD_BYTE_OFFSET`.
    pub(super) const GOD_BYTE_OFFSET: usize = MAGIC_LEN;
    /// `PAGE_SIZE_OFFSET`: the god byte, one byte, then two of padding.
    pub(super) const PAGE_SIZE_OFFSET: usize = GOD_BYTE_OFFSET + 1 + 2;
    const PAGE_SIZE_WIDTH: usize = 4;

    /// `PAGE_SIZE`. Both stores open the engine at this default.
    pub(super) const ENGINE_PAGE_SIZE: u32 = 4096;

    /// God-byte flags: `PRIMARY_BIT`, `RECOVERY_REQUIRED`, `TWO_PHASE_COMMIT`.
    const GOD_PRIMARY: u8 = 1;
    const GOD_RECOVERY: u8 = 2;
    const GOD_TWO_PHASE: u8 = 4;

    /// What initialization stores before either flush: primary slot 0,
    /// recovery clear, two-phase set (`page_manager.rs` assigns those,
    /// then `to_bytes(false)`).
    pub(super) const INIT_GOD_BYTE: u8 = GOD_TWO_PHASE;

    /// `FILE_FORMAT_VERSION3`, the version byte of each commit slot.
    const FILE_FORMAT_VERSION: u8 = 3;

    /// `TRANSACTION_SIZE`, `TRANSACTION_0_OFFSET`, `TRANSACTION_1_OFFSET`.
    const SLOT_LEN: usize = 128;
    const SLOT0_OFFSET: usize = 64;
    const SLOT1_OFFSET: usize = SLOT0_OFFSET + SLOT_LEN;
    /// `DB_HEADER_SIZE`.
    pub(super) const DB_HEADER_LEN: usize = SLOT1_OFFSET + SLOT_LEN;

    /// Within a slot: the version byte, then the user-root and system-root
    /// present flags (`USER_ROOT_NON_NULL_OFFSET`, `SYSTEM_ROOT_NON_NULL_OFFSET`).
    const VERSION_OFFSET: usize = 0;
    const USER_ROOT_FLAG: usize = 1;
    const SYSTEM_ROOT_FLAG: usize = 2;

    /// `TRANSACTION_ID_OFFSET` within a slot. `USER_ROOT_OFFSET` is 8.
    /// `BtreeHeader::serialized_size` is 32 (page number 8, checksum 16,
    /// length 8). The id follows the user root, the system root, and the
    /// unused field of that same width.
    const BTREE_HEADER_LEN: usize = 8 + 16 + 8;
    const USER_ROOT_OFFSET: usize = 8;
    const TX_ID_IN_SLOT: usize = USER_ROOT_OFFSET + 3 * BTREE_HEADER_LEN;
    const TX_ID_WIDTH: usize = 8;

    const _: () = assert!(PAGE_SIZE_OFFSET + PAGE_SIZE_WIDTH <= DB_HEADER_LEN);
    const _: () = assert!(SLOT0_OFFSET + TX_ID_IN_SLOT + TX_ID_WIDTH <= SLOT1_OFFSET);
    const _: () = assert!(SLOT1_OFFSET + TX_ID_IN_SLOT + TX_ID_WIDTH <= DB_HEADER_LEN);
    const _: () = assert!(INIT_GOD_BYTE & (GOD_PRIMARY | GOD_RECOVERY) == 0);

    /// One commit slot, as far as "has a transaction ever committed here".
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct SlotImage {
        version: u8,
        user_root: bool,
        system_root: bool,
        transaction_id: u64,
    }

    /// The header fields the recognizer compares. Equality with
    /// [`PRE_MAGIC`] is the whole policy.
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct HeaderImage {
        magic_clear: bool,
        god: u8,
        page_size: u32,
        slots: [SlotImage; 2],
    }

    /// Initialization's `never_committed` header with the magic still clear.
    const PRE_MAGIC: HeaderImage = HeaderImage {
        magic_clear: true,
        god: INIT_GOD_BYTE,
        page_size: ENGINE_PAGE_SIZE,
        slots: [UNCOMMITTED, UNCOMMITTED],
    };

    /// `TransactionHeader::new(TransactionId::new(0))`: version 3, no roots,
    /// transaction id 0.
    const UNCOMMITTED: SlotImage = SlotImage {
        version: FILE_FORMAT_VERSION,
        user_root: false,
        system_root: false,
        transaction_id: 0,
    };

    pub(super) fn is_pre_magic(header: &[u8; DB_HEADER_LEN]) -> bool {
        read(header) == PRE_MAGIC
    }

    fn read(header: &[u8; DB_HEADER_LEN]) -> HeaderImage {
        HeaderImage {
            magic_clear: header[..MAGIC_LEN].iter().all(|&byte| byte == 0),
            god: header[GOD_BYTE_OFFSET],
            page_size: read_u32(header, PAGE_SIZE_OFFSET),
            slots: [
                read_slot(header, SLOT0_OFFSET),
                read_slot(header, SLOT1_OFFSET),
            ],
        }
    }

    fn read_slot(header: &[u8], slot: usize) -> SlotImage {
        SlotImage {
            version: header[slot + VERSION_OFFSET],
            user_root: header[slot + USER_ROOT_FLAG] != 0,
            system_root: header[slot + SYSTEM_ROOT_FLAG] != 0,
            transaction_id: read_u64(header, slot + TX_ID_IN_SLOT),
        }
    }

    fn read_u32(bytes: &[u8], at: usize) -> u32 {
        let mut wide = [0u8; PAGE_SIZE_WIDTH];
        wide.copy_from_slice(&bytes[at..at + PAGE_SIZE_WIDTH]);
        u32::from_le_bytes(wide)
    }

    fn read_u64(bytes: &[u8], at: usize) -> u64 {
        let mut wide = [0u8; TX_ID_WIDTH];
        wide.copy_from_slice(&bytes[at..at + TX_ID_WIDTH]);
        u64::from_le_bytes(wide)
    }
}

/// What a writable open finished when the file was a creation a power loss
/// cut short. `None` from the open is an ordinary create or reopen.
///
/// The pool maps the same two arms onto [`crate::pool::PoolOpen::Finished`]
/// and [`crate::pool::PoolOpen::SetAside`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CutShort {
    /// The engine had committed an empty database and the seal had not.
    /// The open sealed it in place.
    Unsealed,
    /// The engine never finished initializing. The file was moved to `to`
    /// and a fresh store was created at the path.
    Uninitialized {
        /// Where the unfinished file went.
        to: PathBuf,
    },
}

/// Whether `err` means "these bytes are not a database".
///
/// redb reports a magic mismatch, and an empty file opened rather than
/// created, as `Io(InvalidData)`; `Corrupted` is the same answer once a
/// header has been read and rejected. Any other `Io` — permissions, a full
/// disk — is an engine failure, not a cue to move the file.
pub(crate) fn open_is_foreign(err: &redb::DatabaseError) -> bool {
    match err {
        redb::DatabaseError::Storage(redb::StorageError::Corrupted(_)) => true,
        redb::DatabaseError::Storage(redb::StorageError::Io(io)) => {
            io.kind() == ErrorKind::InvalidData
        }
        _ => false,
    }
}

/// The sibling lock that excludes every other open of one store for the
/// whole creation decision.
///
/// The file is `<name>.creation-lock`, beside `<name>.unfinished-<seconds>`
/// and the pool's `<name>.discard`. The guard carries the store path it
/// covers: [`set_aside_unfinished_init`] moves that path, so a caller
/// cannot lock one file and classify another. One open holds one guard.
/// A second `acquire` on the same thread deadlocks: the lock is the
/// kernel's, and it does not re-enter.
pub(crate) struct PathGuard {
    file: File,
    store: PathBuf,
}

impl PathGuard {
    /// Block until this process holds the creation lock for `store`.
    ///
    /// The lock file is created if it is absent and left in place
    /// afterwards. Failing to take the lock fails the open: an unlocked
    /// decision is the race the guard exists to close.
    ///
    /// # Errors
    ///
    /// The lock file could not be opened or locked.
    pub(crate) fn acquire(store: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            // An existing lock file stays. It is the exclusion, not data,
            // and truncating it would not release whoever holds it.
            .truncate(false)
            .open(creation_lock_path(store))?;
        file.lock()?;
        Ok(Self {
            file,
            store: store.to_path_buf(),
        })
    }

    /// The store file this lock covers.
    pub(crate) fn store(&self) -> &Path {
        &self.store
    }
}

impl Drop for PathGuard {
    fn drop(&mut self) {
        // Closing releases the lock. Unlock first so a platform that does
        // not drop the lock with the file still frees the next opener.
        drop(self.file.unlock());
    }
}

/// `<filename>.creation-lock` beside `store`.
pub(crate) fn creation_lock_path(store: &Path) -> PathBuf {
    let mut name = store.file_name().unwrap_or_default().to_os_string();
    name.push(".creation-lock");
    store.with_file_name(name)
}

/// An unfinished file moved aside, and the empty file now at the path,
/// claimed with `create_new` and not yet locked. The caller hands `file`
/// to `create_file`. A second lock on it would make that open fail: the
/// engine locks the descriptor it is given, and [`PathGuard`] already
/// covers the path until that lock is held.
pub(crate) struct Replaced {
    /// Where the unfinished bytes went.
    pub to: PathBuf,
    /// The new file at the store's path.
    pub file: File,
}

/// Move [`PathGuard::store`] aside when it is an initialization the engine
/// did not finish, and claim a fresh empty file at that path.
///
/// `guard` names the store and is the lock held across the decision.
/// `None`, and the file untouched, when the file is not that image or
/// another process holds it (the store file's lock: a live creator or a
/// live store). The aside name is claimed with `create_new` before the
/// rename, so an earlier aside is never replaced.
///
/// A directory flush that fails after the rename leaves the aside in
/// place and the path empty, and returns the error. The next open creates
/// a fresh file; the aside is still there to inspect. The aside is never
/// removed on a later failure.
///
/// # Errors
///
/// The file could not be opened, read, or locked for a reason other than
/// a holder; no aside name was free; or the rename or its directory flush
/// failed.
pub(crate) fn set_aside_unfinished_init(guard: &PathGuard) -> io::Result<Option<Replaced>> {
    let path = guard.store();
    let mut source = File::open(path)?;
    match source.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
        Err(std::fs::TryLockError::Error(error)) => return Err(error),
    }
    let len = source.metadata()?.len();
    if !unfinished_init(&mut source, len)? {
        source.unlock()?;
        return Ok(None);
    }
    let claimed = claim_aside_name(path)?;
    if let Err(error) = rename_classified(source, path, &claimed.path) {
        drop(claimed.file);
        drop(std::fs::remove_file(&claimed.path));
        return Err(error);
    }
    drop(claimed.file);
    sync_parent(path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)?;
    Ok(Some(Replaced {
        to: claimed.path,
        file,
    }))
}

/// Empty, or [`ENGINE_INIT_LEN`] bytes whose leading header is the
/// pre-magic image. One predicate: the file open and the recorded-flush
/// test both ask it, so a recognizer change cannot leave the pin behind.
fn is_unfinished_init(len: u64, header: &[u8]) -> bool {
    if len == 0 {
        return true;
    }
    len == ENGINE_INIT_LEN
        && header
            .first_chunk::<{ header_image::DB_HEADER_LEN }>()
            .is_some_and(header_image::is_pre_magic)
}

/// Read just the header. A file of any other length is answered without
/// a read: an empty file is unfinished, and anything longer than the
/// initialization is not one.
fn unfinished_init(file: &mut File, len: u64) -> io::Result<bool> {
    if len != ENGINE_INIT_LEN {
        return Ok(len == 0);
    }
    let mut header = [0u8; header_image::DB_HEADER_LEN];
    file.read_exact(&mut header)?;
    Ok(is_unfinished_init(len, &header))
}

/// The whole recorded flush, judged by [`is_unfinished_init`].
#[cfg(test)]
fn image_is_unfinished(bytes: &[u8]) -> bool {
    match u64::try_from(bytes.len()) {
        Ok(len) => is_unfinished_init(len, bytes),
        Err(_) => false,
    }
}

struct ClaimedAside {
    path: PathBuf,
    file: File,
}

/// The first `<name>.unfinished-<unix seconds>[-<n>]` this process creates.
///
/// `create_new` is the claim. A name that already exists is left alone,
/// including one another process created between the tries.
fn claim_aside_name(path: &Path) -> io::Result<ClaimedAside> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    for n in 0..ASIDE_NAME_TRIES {
        let suffix = if n == 0 {
            format!("{name}.unfinished-{secs}")
        } else {
            format!("{name}.unfinished-{secs}-{n}")
        };
        let candidate = path.with_file_name(suffix);
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                return Ok(ClaimedAside {
                    path: candidate,
                    file,
                })
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        ErrorKind::AlreadyExists,
        "no free name for an unfinished creation",
    ))
}

/// Rename `from` onto the claimed aside name while `source` still holds
/// the store file's lock, where the platform can rename an open file.
/// Elsewhere the lock is dropped first; [`PathGuard`] still holds the path.
fn rename_classified(source: File, from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::rename(from, to)?;
        drop(source);
        Ok(())
    }
    #[cfg(not(unix))]
    {
        source.unlock()?;
        drop(source);
        std::fs::rename(from, to)
    }
}

/// Flush the directory holding `path`, so a rename in it is durable. Unix
/// only: elsewhere a directory cannot be opened to flush.
#[cfg_attr(
    not(unix),
    expect(
        clippy::unnecessary_wraps,
        reason = "the Unix arm's signature: callers handle both platforms the same way"
    )
)]
pub(crate) fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// The read transaction sees no table at all: the engine's first commit
/// and nothing after it, which is a creation stopped before its seal.
///
/// # Errors
///
/// The table list could not be read.
pub(crate) fn no_table(txn: &ReadTransaction) -> Result<bool, StoreError> {
    let none = txn
        .list_tables()
        .map_err(EngineError::Storage)?
        .next()
        .is_none()
        && txn
            .list_multimap_tables()
            .map_err(EngineError::Storage)?
            .next()
            .is_none();
    Ok(none)
}

/// The engine's pre-magic header, captured from the initialization this
/// crate links. Store and pool fixtures write this image.
#[cfg(test)]
pub(crate) fn pre_magic_image() -> Vec<u8> {
    tests::pre_magic_image()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    use crate::test_paths::tmp;

    fn untouched(path: impl AsRef<Path>) -> (Vec<u8>, std::time::SystemTime) {
        let path: &Path = path.as_ref();
        (
            std::fs::read(path).unwrap(),
            std::fs::metadata(path).unwrap().modified().unwrap(),
        )
    }

    /// One move, under the path guard the open would be holding.
    fn move_aside(path: impl AsRef<Path>) -> Option<Replaced> {
        let path: &Path = path.as_ref();
        let guard = PathGuard::acquire(path).unwrap();
        set_aside_unfinished_init(&guard).unwrap()
    }

    #[test]
    fn an_unfinished_init_is_moved_aside_and_nothing_else_is_touched() {
        // Empty, and the engine's own pre-magic header: moved aside, bytes
        // intact, and an empty file claimed at the path for the caller to
        // hand to the engine.
        for (label, bytes) in [("empty", Vec::new()), ("unwritten", pre_magic_image())] {
            let path = tmp(label);
            std::fs::write(&path, &bytes).unwrap();
            let replaced = move_aside(&path).unwrap_or_else(|| panic!("{label}: set aside"));
            assert_eq!(std::fs::read(&replaced.to).unwrap(), bytes, "{label}: kept");
            assert_eq!(
                std::fs::metadata(&path).unwrap().len(),
                0,
                "{label}: the replacement is the empty claim"
            );
            let name = replaced
                .to
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let store = path.path().file_name().unwrap().to_string_lossy();
            assert!(name.starts_with(&format!("{store}.unfinished-")), "{name}");
            assert!(
                creation_lock_path(path.path()).is_file(),
                "{label}: the path lock"
            );
            drop(replaced.file);
        }

        // A second set-aside in the same second takes the next name, never
        // the first one's. The first call left an empty claim at the path;
        // that empty file is itself an unfinished creation.
        let path = tmp("twice");
        std::fs::write(&path, b"").unwrap();
        let first = move_aside(&path).unwrap();
        drop(first.file);
        let second = move_aside(&path).unwrap();
        assert_ne!(first.to, second.to);
        assert!(first.to.exists() && second.to.exists());
        drop(second.file);

        // A zero-filled file of the initialization length is the lookalike
        // the length bound could not refuse: every young store is that
        // long. Red edit: accept any file of this length whose magic is
        // clear.
        let path = tmp("zeroed");
        let zeros = vec![0u8; usize::try_from(ENGINE_INIT_LEN).unwrap()];
        std::fs::write(&path, &zeros).unwrap();
        let before = untouched(&path);
        assert!(
            move_aside(&path).is_none(),
            "a zero-filled image is not the header"
        );
        assert_eq!(untouched(&path), before, "left byte for byte");

        // Shorter than the image, with the two-phase god byte set: still
        // not the flush. Red edit: accept any clear magic slot.
        let path = tmp("short");
        let mut short = vec![0u8; 4096];
        short[header_image::GOD_BYTE_OFFSET] = header_image::INIT_GOD_BYTE;
        std::fs::write(&path, &short).unwrap();
        let before = untouched(&path);
        assert!(move_aside(&path).is_none());
        assert_eq!(untouched(&path), before);

        // One byte past the image, magic clear: not the flush.
        let path = tmp("zeroed-long");
        let long = vec![0u8; usize::try_from(ENGINE_INIT_LEN).unwrap() + 4096];
        std::fs::write(&path, &long).unwrap();
        let before = untouched(&path);
        assert!(move_aside(&path).is_none());
        assert_eq!(untouched(&path), before);

        // Foreign bytes, an initialized database, and a file someone holds.
        let foreign = tmp("foreign");
        std::fs::write(&foreign, b"this is not a redb file, and it is somebody's").unwrap();
        let store = tmp("store");
        drop(redb::Database::create(&store).unwrap());
        for path in [&foreign, &store] {
            let before = untouched(path);
            assert!(move_aside(path).is_none());
            assert_eq!(untouched(path), before, "{}", path.path().display());
        }
        let held = tmp("held");
        std::fs::write(&held, b"").unwrap();
        let holder = File::open(&held).unwrap();
        holder.lock().unwrap();
        assert!(move_aside(&held).is_none(), "held");
        assert!(held.path().exists());
    }

    /// A young store whose magic slot was cleared is the case the length
    /// bound was added to refuse, at the size every store has until its
    /// first region fills. The transaction ids are what says a commit
    /// happened. Red edit: treat a clear magic slot at [`ENGINE_INIT_LEN`]
    /// as unfinished.
    #[test]
    fn a_committed_file_whose_magic_was_cleared_is_not_unfinished() {
        let path = tmp("cleared");
        {
            let db = redb::Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let definition = redb::TableDefinition::<&str, &str>::new("row");
                let mut table = txn.open_table(definition).unwrap();
                table.insert("k", "v").unwrap();
            }
            txn.commit().unwrap();
        }
        let mut bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            bytes.len() as u64,
            ENGINE_INIT_LEN,
            "a young store is still the initialization length"
        );
        bytes[..header_image::MAGIC_LEN].fill(0);
        std::fs::write(&path, &bytes).unwrap();
        assert!(
            !image_is_unfinished(&bytes),
            "a commit has a transaction id"
        );
        let before = untouched(&path);
        assert!(move_aside(&path).is_none());
        assert_eq!(untouched(&path), before, "left byte for byte");
    }

    /// The engine's storage as it stood at each flush.
    #[derive(Debug, Default)]
    struct Recorded {
        bytes: Vec<u8>,
        at_flush: Vec<Vec<u8>>,
    }

    #[derive(Debug, Default, Clone)]
    struct Recording(Arc<Mutex<Recorded>>);

    impl redb::StorageBackend for Recording {
        fn len(&self) -> Result<u64, std::io::Error> {
            Ok(self.0.lock().unwrap().bytes.len() as u64)
        }

        fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), std::io::Error> {
            let recorded = self.0.lock().unwrap();
            let at = usize::try_from(offset).unwrap();
            out.copy_from_slice(&recorded.bytes[at..at + out.len()]);
            Ok(())
        }

        fn set_len(&self, len: u64) -> Result<(), std::io::Error> {
            self.0
                .lock()
                .unwrap()
                .bytes
                .resize(usize::try_from(len).unwrap(), 0);
            Ok(())
        }

        fn sync_data(&self) -> Result<(), std::io::Error> {
            let mut recorded = self.0.lock().unwrap();
            let snapshot = recorded.bytes.clone();
            recorded.at_flush.push(snapshot);
            Ok(())
        }

        fn write(&self, offset: u64, data: &[u8]) -> Result<(), std::io::Error> {
            let mut recorded = self.0.lock().unwrap();
            let at = usize::try_from(offset).unwrap();
            if recorded.bytes.len() < at + data.len() {
                recorded.bytes.resize(at + data.len(), 0);
            }
            recorded.bytes[at..at + data.len()].copy_from_slice(data);
            Ok(())
        }
    }

    /// The last durable image of an initialization whose magic is still
    /// clear. Store and pool fixtures write this, rather than a buffer of
    /// zeros that happens to be about as long.
    pub(crate) fn pre_magic_image() -> Vec<u8> {
        let recording = Recording::default();
        drop(
            redb::Builder::new()
                .create_with_backend(recording.clone())
                .expect("an initialization"),
        );
        let recorded = recording.0.lock().unwrap();
        recorded
            .at_flush
            .iter()
            .rev()
            .find(|state| {
                state.len() < header_image::MAGIC_LEN
                    || state[..header_image::MAGIC_LEN]
                        .iter()
                        .all(|&byte| byte == 0)
            })
            .expect("the header is flushed before the magic")
            .clone()
    }

    /// The recognition rests on the engine's write order: the magic last,
    /// after the rest of the header is flushed, at [`ENGINE_INIT_LEN`].
    /// Every state a power loss can leave before the magic is durable is
    /// one [`image_is_unfinished`] accepts, and the magic flush is not.
    /// One byte short or long of that image is not either. A future engine
    /// that wrote its magic earlier, grew the file further first, or moved
    /// a header field, fails here.
    #[test]
    fn the_engine_writes_its_magic_last_within_the_bound() {
        let recording = Recording::default();
        drop(
            redb::Builder::new()
                .create_with_backend(recording.clone())
                .expect("an initialization"),
        );
        let recorded = recording.0.lock().unwrap();
        let magic_at = recorded
            .at_flush
            .iter()
            .position(|state| {
                state.len() >= header_image::MAGIC_LEN
                    && state[..header_image::MAGIC_LEN]
                        .iter()
                        .any(|&byte| byte != 0)
            })
            .expect("the magic is flushed");
        assert!(magic_at > 0, "the header is flushed before the magic");
        for state in &recorded.at_flush[..magic_at] {
            assert!(
                image_is_unfinished(state),
                "a pre-magic flush the next open would refuse: {} bytes, god {:02x}",
                state.len(),
                state
                    .get(header_image::GOD_BYTE_OFFSET)
                    .copied()
                    .unwrap_or(0),
            );
        }
        let magic = &recorded.at_flush[magic_at];
        assert!(!image_is_unfinished(magic), "the magic flush is a database");
        assert_eq!(magic.len() as u64, ENGINE_INIT_LEN, "the pinned length");
        assert_eq!(
            recorded.at_flush[magic_at - 1].len() as u64,
            ENGINE_INIT_LEN,
            "the pre-magic flush is the same length"
        );

        // The magic flush with its magic removed is the pre-magic image:
        // nothing has committed yet. One extra byte, or one missing, is not.
        let mut cleared = magic.clone();
        cleared[..header_image::MAGIC_LEN].fill(0);
        assert!(
            image_is_unfinished(&cleared),
            "clearing the magic of the init flush restores the pre-magic image"
        );
        let mut short = cleared.clone();
        short.pop();
        assert!(!image_is_unfinished(&short), "one byte short");
        let mut long = cleared.clone();
        long.push(0);
        assert!(!image_is_unfinished(&long), "one byte long");
    }
}
