// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Write a store's chain as the trace a later replay must reproduce
//! (`DAEMON_REDB_STORE.md` §12.1).
//!
//! Every facts record is read off the store at its height and the
//! checkpoint is the store's own state at the tip. Nothing here is a second
//! derivation: the facts are the rows `connect` wrote (`block_info`,
//! `block_burn`, `curve_tree_roots`), the digest is
//! `logical_state_digest_v0` and the archival rows are
//! `archival_snapshot`, the same reads the pipeline's checkpoint compares.
//! A later replay that disagrees has changed what this pipeline derives.
//!
//! [`write_trace_file`] serializes the whole trace before it touches the
//! destination, then replaces that file by renaming a sibling. A store that
//! cannot be written — empty, a hole, a refused read — leaves the previous
//! trace in place.

use std::io::Write;
use std::path::{Path, PathBuf};

use shekyl_chain_rules::AtHeight;
use shekyl_chain_store::store::{ReadSnapshot, StoreError};
use shekyl_types::BlockHeight;

use crate::trace::{Facts, TraceFault, TraceWriter};

/// Why a store could not be written out as a trace.
#[derive(Debug, thiserror::Error)]
pub enum RebaselineFault {
    /// The store refused a read.
    #[error("store read: {0}")]
    Store(#[from] StoreError),
    /// The trace writer refused.
    #[error("trace write: {0}")]
    Trace(#[from] TraceFault),
    /// The destination could not be replaced.
    #[error("trace file: {0}")]
    Io(#[from] std::io::Error),
    /// The store holds no block: there is no chain to pin.
    #[error("the store is empty; a trace pins a chain")]
    Empty,
    /// A height at or below the tip has no row it must have.
    #[error("height {height}: {row} is absent at or below the tip")]
    Hole {
        /// The height.
        height: BlockHeight,
        /// The row that was missing.
        row: &'static str,
    },
}

/// Write `snap`'s chain as a trace: one facts record per height from
/// genesis to the tip, then the checkpoint (the tip's logical-state digest)
/// and the archival snapshot beside it.
///
/// # Errors
///
/// [`RebaselineFault`].
pub fn trace_of<W: Write>(snap: &ReadSnapshot<'_>, out: W) -> Result<W, RebaselineFault> {
    let tip = snap
        .tip()?
        .recorded
        .map(|t| t.height)
        .ok_or(RebaselineFault::Empty)?;
    let mut writer = TraceWriter::new(out)?;
    for raw in 0..=tip.to_raw() {
        let height = BlockHeight::from_raw(raw);
        let hole = |row| RebaselineFault::Hole { height, row };
        let AtHeight::Recorded(info) = snap.block_info(height)? else {
            return Err(hole("block_info"));
        };
        let AtHeight::Recorded(burned) = snap.block_burn(height)? else {
            return Err(hole("block_burn"));
        };
        let after = BlockHeight::from_raw(raw.checked_add(1).ok_or(hole("curve_tree_roots"))?);
        let AtHeight::Recorded(root_after) = snap.root_at(after)? else {
            return Err(hole("curve_tree_roots"));
        };
        writer.push_facts(
            height,
            &Facts {
                weight: info.weight,
                long_term_weight: info.long_term_weight,
                coins_generated: info.coins_generated,
                burned,
                root_after,
                long_term_effective_median: info.long_term_effective_median,
                cumulative_difficulty: info.cumulative_difficulty,
            },
        )?;
    }
    writer.push_checkpoint(&snap.logical_state_digest_v0()?)?;
    writer.push_archival_snapshot(&snap.archival_snapshot()?)?;
    Ok(writer.finish()?)
}

/// Write `snap`'s chain to `path`, replacing any file already there.
///
/// The trace is serialized completely first. [`RebaselineFault::Empty`], a
/// hole, or a refused read returns before `path` is opened, so a previous
/// trace stays byte-for-byte. The bytes are then published by renaming a
/// same-directory sibling; a failure of that publish removes the sibling
/// and leaves `path` as it was.
///
/// # Errors
///
/// [`RebaselineFault`].
pub fn write_trace_file(snap: &ReadSnapshot<'_>, path: &Path) -> Result<(), RebaselineFault> {
    let bytes = trace_of(snap, Vec::<u8>::new())?;
    publish_bytes(path, &bytes)?;
    Ok(())
}

/// The sibling [`publish_bytes`] writes, then renames onto `path`.
fn partial_path(path: &Path) -> std::io::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "a trace path names a file",
        )
    })?;
    let mut partial = std::ffi::OsString::from(".");
    partial.push(name);
    partial.push(".partial");
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    Ok(parent.join(partial))
}

/// Replace `path` with `bytes` by writing a sibling and renaming it.
///
/// The destination is not opened until the sibling is complete, so a short
/// write never truncates it. The sibling is removed if the write or the
/// rename fails.
fn publish_bytes(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let partial = partial_path(path)?;
    let write = (|| {
        let mut file = std::fs::File::create(&partial)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(error) = write {
        // The sibling is ours. Leaving it would be a second trace beside the
        // destination the caller still has.
        let _removed = std::fs::remove_file(&partial);
        return Err(error);
    }
    if let Err(error) = std::fs::rename(&partial, path) {
        let _removed = std::fs::remove_file(&partial);
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_store_leaves_the_previous_trace_in_place() {
        let store_path = crate::test_support::tmp("rebaseline-empty-store");
        let store = crate::test_support::open_store(&store_path);
        let trace = crate::test_support::tmp("rebaseline-empty-trace");
        std::fs::write(&trace, b"previous").expect("seed the previous trace");
        let fault = write_trace_file(&store.begin_read().expect("read"), &trace)
            .expect_err("an empty store is not a chain");
        assert!(
            matches!(fault, RebaselineFault::Empty),
            "the refusal is the empty store, not a truncated file: {fault}"
        );
        assert_eq!(
            std::fs::read(&trace).expect("the previous trace is still there"),
            b"previous"
        );
        assert!(
            !partial_path(&trace).expect("sibling").exists(),
            "a refusal publishes nothing"
        );
        drop(store);
        crate::test_support::cleanup(&store_path);
        crate::test_support::cleanup(&trace);
    }

    #[test]
    fn publish_replaces_the_destination_and_leaves_no_sibling() {
        let path = crate::test_support::tmp("rebaseline-publish");
        std::fs::write(&path, b"previous").expect("seed");
        publish_bytes(&path, b"next").expect("publish");
        assert_eq!(std::fs::read(&path).expect("read"), b"next");
        assert!(!partial_path(&path).expect("sibling").exists());
        crate::test_support::cleanup(&path);
    }
}
