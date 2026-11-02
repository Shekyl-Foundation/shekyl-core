// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one fact the store tests take from redb's on-disk header.
//!
//! redb 4.4.0 documents the super-header (`header.rs`): a 9-byte magic
//! number, then one god byte. Bit 1 of that byte is `RECOVERY_REQUIRED`.
//! Set, a read-only open answers [`redb::DatabaseError::RepairAborted`]
//! and a writable open repairs, keeping the committed rows. Both stores'
//! reopen paths treat that error as "repair, then judge", and nothing
//! else in this crate constructs the condition.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Length of redb's magic number. The god byte is the next byte.
const MAGIC_LEN: u64 = 9;

/// `RECOVERY_REQUIRED` in redb's god byte (`header.rs`, value 2).
const RECOVERY_REQUIRED: u8 = 2;

/// The printable prefix of the magic, so a file that is not a redb
/// database is not marked. The other five magic bytes are not needed
/// to find the god byte.
const MAGIC_PREFIX: &[u8; 4] = b"redb";

/// Set redb's recovery-required bit and flush it.
///
/// # Panics
///
/// Panics if `path` is not a redb file or the bit cannot be written.
pub(crate) fn mark_recovery_required(path: &Path) {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open");
    let mut prefix = [0_u8; 4];
    file.read_exact(&mut prefix).expect("magic");
    assert_eq!(&prefix, MAGIC_PREFIX, "not a redb file");
    file.seek(SeekFrom::Start(MAGIC_LEN)).expect("god byte");
    let mut god = [0_u8; 1];
    file.read_exact(&mut god).expect("god byte");
    god[0] |= RECOVERY_REQUIRED;
    file.seek(SeekFrom::Start(MAGIC_LEN)).expect("god byte");
    file.write_all(&god).expect("mark");
    file.sync_all().expect("flush");
}

/// Whether a read-only open of `path` is the repair arm.
pub(crate) fn read_only_open_is_repair_aborted(path: &Path) -> bool {
    matches!(
        redb::Builder::new().open_read_only(path),
        Err(redb::DatabaseError::RepairAborted)
    )
}
