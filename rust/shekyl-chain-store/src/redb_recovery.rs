// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What the store tests observe in a redb file on disk.
//!
//! redb 4.4.0 documents the super-header (`header.rs`): the 9-byte
//! [`MAGIC`], then one god byte. Bit 1 of that byte is `RECOVERY_REQUIRED`.
//! Set, a read-only open answers [`redb::DatabaseError::RepairAborted`]
//! and a writable open repairs, keeping the committed rows. Both stores'
//! reopen paths treat that error as "repair, then judge", and nothing
//! else in this crate constructs the condition.
//!
//! [`bytes_and_mtime`] is the snapshot a refusal test compares. Both
//! stores hold "wrote nothing" through this one function.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::SystemTime;

/// redb's magic number (`header.rs` `MAGICNUMBER`). The god byte is the
/// next byte.
const MAGIC: [u8; 9] = [b'r', b'e', b'd', b'b', 0x1A, 0x0A, 0xA9, 0x0D, 0x0A];

/// `RECOVERY_REQUIRED` in redb's god byte (`header.rs`, value 2).
const RECOVERY_REQUIRED: u8 = 2;

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
    let mut magic = [0_u8; MAGIC.len()];
    file.read_exact(&mut magic).expect("magic");
    assert_eq!(magic, MAGIC, "not a redb file");
    let god_at = u64::try_from(MAGIC.len()).expect("magic length");
    file.seek(SeekFrom::Start(god_at)).expect("god byte");
    let mut god = [0_u8; 1];
    file.read_exact(&mut god).expect("god byte");
    god[0] |= RECOVERY_REQUIRED;
    file.seek(SeekFrom::Start(god_at)).expect("god byte");
    file.write_all(&god).expect("mark");
    file.sync_all().expect("flush");
}

/// The file's bytes and its modification time.
///
/// # Panics
///
/// Panics if the file cannot be read or its modification time is
/// unavailable. A refusal test is comparing this with itself.
pub(crate) fn bytes_and_mtime(path: &Path) -> (Vec<u8>, SystemTime) {
    (
        std::fs::read(path).expect("bytes"),
        std::fs::metadata(path)
            .expect("stat")
            .modified()
            .expect("mtime"),
    )
}

/// Whether a read-only open of `path` is the repair arm.
pub(crate) fn read_only_open_is_repair_aborted(path: &Path) -> bool {
    matches!(
        redb::Builder::new().open_read_only(path),
        Err(redb::DatabaseError::RepairAborted)
    )
}
