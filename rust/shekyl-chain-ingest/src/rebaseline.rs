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
//! destination, then replaces that file by renaming a sibling named for
//! that attempt. A store that cannot be written — empty, a hole, a refused
//! read — leaves the previous trace in place, and a failed publish removes
//! only the sibling it created.
//!
//! [`baseline`] is the whole of `shekyl-chain-replay baseline`: a corpus
//! connected against a fresh store under the production proof-of-work, with
//! nothing to compare, and the store's chain written as the trace. The
//! binary and the chain forge (`CHAIN_FORGE.md` §11.3: a forged chain's
//! trace is the production pipeline's verdict on the bytes it wrote) both
//! call it, so there is one baseline, not a copy per caller.

use std::fs::File;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use shekyl_chain_rules::{AtHeight, InvalidBlock};
use shekyl_chain_store::apply_policy::ApplyPolicy;
use shekyl_chain_store::store::{ChainStore, Horizons, ReadSnapshot, StoreError};
use shekyl_network::Network;
use shekyl_types::BlockHeight;

use crate::corpus::{CorpusFault, CorpusReader};
use crate::metrics::Metrics;
use crate::pipeline::{run, PipelineConfig, PipelineFault, RunReport};
use crate::schedule::ChainRules;
use crate::substrate::SubstrateFault;
use crate::trace::{Facts, Trace, TraceFault, TraceWriter};
use crate::ProductionPow;

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
/// same-directory sibling named for this attempt. Two publishes never share
/// a file, so one cannot truncate the other's staged bytes, and a failure
/// removes only the sibling this attempt created.
///
/// # Errors
///
/// [`RebaselineFault`].
pub fn write_trace_file(snap: &ReadSnapshot<'_>, path: &Path) -> Result<(), RebaselineFault> {
    let bytes = trace_of(snap, Vec::<u8>::new())?;
    publish_bytes(path, &bytes)?;
    Ok(())
}

/// Why a corpus could not be replayed against a store, or baselined.
#[derive(Debug, thiserror::Error)]
pub enum ReplayFault {
    /// The corpus file could not be opened.
    #[error("corpus file: {0}")]
    Io(#[from] std::io::Error),
    /// The corpus refused to open.
    #[error("corpus: {0}")]
    Corpus(#[from] CorpusFault),
    /// The corpus is another network's chain.
    #[error("the corpus is tagged {corpus:?} but the run's chain is {rules:?}")]
    WrongNetwork {
        /// The corpus header's tag.
        corpus: Network,
        /// The network the rules judge.
        rules: Network,
    },
    /// The store refused to open or to be read.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// The run ended in an error.
    #[error("pipeline: {0}")]
    Pipeline(#[from] PipelineFault<CorpusFault, SubstrateFault>),
    /// A baseline is written from a fresh store, and this one exists.
    #[error("{0} exists; a baseline is written from a fresh store")]
    StoreExists(PathBuf),
    /// The rules refused a block: a chain refused anywhere is no baseline.
    #[error("the corpus does not replay: refused at {height}: {verdict:?}")]
    Refused {
        /// The refused block's height.
        height: BlockHeight,
        /// The verdict.
        verdict: InvalidBlock,
    },
    /// The trace could not be written.
    #[error("trace: {0}")]
    Rebaseline(#[from] RebaselineFault),
}

/// Connect the corpus at `corpus` against the store at `store` under
/// `rules` and the production proof-of-work `pow`, held to `trace`.
///
/// The store runs the `(SEB, cap)` pair of the rule set that judges the
/// chain, read off that set (`Horizons::under`); a store file sealed under
/// another epoch is refused at open. The corpus must carry the rules'
/// network's tag.
///
/// # Errors
///
/// [`ReplayFault`]. A refusal of a block is not an error: it is the report's
/// [`RunReport::refused`].
pub async fn replay_corpus(
    corpus: &Path,
    store: &Path,
    rules: ChainRules,
    cfg: PipelineConfig,
    pow: Arc<ProductionPow>,
    metrics: Arc<Metrics>,
    trace: Arc<Trace>,
) -> Result<RunReport, ReplayFault> {
    let mut source = CorpusReader::open(BufReader::new(File::open(corpus)?))?;
    if source.net() != rules.network() {
        return Err(ReplayFault::WrongNetwork {
            corpus: source.net(),
            rules: rules.network(),
        });
    }
    let horizons = horizons(&rules)?;
    let store = ChainStore::with_horizons(store, ApplyPolicy::default(), horizons)?;
    Ok(run(&mut source, pow, metrics, rules, store, trace, cfg).await?)
}

/// `shekyl-chain-replay baseline`: connect the corpus at `corpus` against a
/// fresh store at `store` with nothing to compare, then write the store's
/// chain as the trace at `out` ([`write_trace_file`]).
///
/// # Errors
///
/// [`ReplayFault::StoreExists`] before anything is read;
/// [`ReplayFault::Refused`] when the rules refuse a block, before `out` is
/// opened; any other [`ReplayFault`].
pub async fn baseline(
    corpus: &Path,
    store: &Path,
    rules: ChainRules,
    cfg: PipelineConfig,
    pow: Arc<ProductionPow>,
    metrics: Arc<Metrics>,
    out: &Path,
) -> Result<RunReport, ReplayFault> {
    if store.exists() {
        return Err(ReplayFault::StoreExists(store.to_path_buf()));
    }
    let mut report = replay_corpus(
        corpus,
        store,
        rules,
        cfg,
        pow,
        metrics,
        Arc::new(Trace::empty()),
    )
    .await?;
    if let Some((height, verdict)) = report.refused.take() {
        return Err(ReplayFault::Refused { height, verdict });
    }
    let read = ChainStore::open_read_only(store, horizons(&rules)?)?;
    write_trace_file(&read.begin_read()?, out)?;
    Ok(report)
}

/// The store's horizons under `rules`' schedule at genesis.
fn horizons(rules: &ChainRules) -> Result<Horizons, StoreError> {
    Ok(Horizons::under(&rules.in_force(BlockHeight::from_raw(0)))?)
}

/// A sibling [`publish_bytes`] creates for one attempt, then renames onto
/// `path`. Each call is a new name: the process id and an attempt count.
fn sibling_path(path: &Path) -> std::io::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "a trace path names a file",
        )
    })?;
    static ATTEMPT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let attempt = ATTEMPT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut sibling = std::ffi::OsString::from(".");
    sibling.push(name);
    sibling.push(".");
    sibling.push(std::process::id().to_string());
    sibling.push(".");
    sibling.push(attempt.to_string());
    sibling.push(".partial");
    Ok(trace_parent(path).join(sibling))
}

/// The directory a sibling must share with `path`, so the rename is atomic.
fn trace_parent(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Replace `path` with `bytes` by writing a sibling and renaming it.
///
/// The destination is not opened until the sibling is complete. The sibling
/// is created with `create_new`, so this attempt never truncates a file
/// another attempt already holds, and the cleanup below removes only the
/// sibling this attempt created. The height-digest table publishes through
/// this same rename.
pub(crate) fn publish_bytes(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let sibling = sibling_path(path)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&sibling)?;
    if let Err(error) = write_synced(&mut file, bytes) {
        // The sibling is ours. Leaving it would be a second trace beside the
        // destination the caller still has.
        let _removed = std::fs::remove_file(&sibling);
        return Err(error);
    }
    if let Err(error) = std::fs::rename(&sibling, path) {
        let _removed = std::fs::remove_file(&sibling);
        return Err(error);
    }
    Ok(())
}

fn write_synced(file: &mut std::fs::File, bytes: &[u8]) -> std::io::Result<()> {
    file.write_all(bytes)?;
    file.sync_all()?;
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
        let fault = write_trace_file(&store.begin_read().expect("read"), trace.path())
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
            siblings_of(&trace).is_empty(),
            "a refusal publishes nothing"
        );
        drop(store);
    }

    #[test]
    fn publish_replaces_the_destination_and_leaves_no_sibling() {
        let path = crate::test_support::tmp("rebaseline-publish");
        std::fs::write(&path, b"previous").expect("seed");
        publish_bytes(path.path(), b"next").expect("publish");
        assert_eq!(std::fs::read(&path).expect("read"), b"next");
        assert!(siblings_of(&path).is_empty(), "the sibling was renamed");
    }

    #[test]
    fn two_attempts_name_different_siblings() {
        let path = crate::test_support::tmp("rebaseline-sibling-names");
        let first = sibling_path(path.path()).expect("first");
        let second = sibling_path(path.path()).expect("second");
        assert_ne!(first, second);
    }

    #[test]
    fn a_failed_publish_removes_only_its_own_sibling() {
        let path = crate::test_support::tmp("rebaseline-dest-dir");
        std::fs::create_dir(&path).expect("destination is a directory");
        let foreign = trace_parent(path.path()).join({
            let mut name = std::ffi::OsString::from(".");
            name.push(path.path().file_name().expect("name"));
            name.push(".partial");
            name
        });
        std::fs::write(&foreign, b"another attempt").expect("plant a shared-style sibling");
        let error = publish_bytes(path.path(), b"next").expect_err("a directory is not replaced");
        assert_eq!(error.kind(), std::io::ErrorKind::IsADirectory);
        assert!(path.path().is_dir(), "the destination is untouched");
        assert_eq!(
            std::fs::read(&foreign).expect("the other sibling survives"),
            b"another attempt"
        );
        assert!(
            siblings_of(&path).is_empty(),
            "this attempt removed only the sibling it created"
        );
    }

    /// Siblings this process would create for `path`: `.{name}.{pid}.{n}.partial`.
    /// The old shared name `.{name}.partial` does not match.
    fn siblings_of(path: impl AsRef<Path>) -> Vec<PathBuf> {
        let path: &Path = path.as_ref();
        let name = path.file_name().expect("a trace path names a file");
        let mut prefix = std::ffi::OsString::from(".");
        prefix.push(name);
        prefix.push(".");
        prefix.push(std::process::id().to_string());
        prefix.push(".");
        let parent = trace_parent(path);
        let mut found = Vec::new();
        for entry in std::fs::read_dir(parent).expect("the trace directory") {
            let entry = entry.expect("a directory entry");
            let file_name = entry.file_name();
            let bytes = file_name.as_encoded_bytes();
            if bytes.starts_with(prefix.as_encoded_bytes()) && bytes.ends_with(b".partial") {
                found.push(entry.path());
            }
        }
        found
    }
}
