// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The snapshot cache (`CHAIN_FORGE.md` §8): the store a full replay left at
//! one indexed event of a forged chain, kept so a consumer can start there.
//!
//! - **Built only by the production path.** [`build`] runs
//!   [`replay_corpus_through`]: every block from genesis, real proof of
//!   work, the production validator and connect. Nothing else writes a
//!   snapshot, and the node has no door that takes one.
//! - **Keyed on what decides its bytes** ([`SnapshotKey`]): the pinned
//!   chain's digest, the event, the store's schema version, and a digest of
//!   the consensus source trees ([`CONSENSUS_TREES`]).
//! - **Refused on open if a byte moved.** [`open_copy`] checks the file's
//!   SHA-256 against its seal before it copies, which a flip in a free page
//!   cannot pass, then recomputes the tables digest over the copy and holds
//!   it to the digest the chain's *pinned trace* carries at the event. The
//!   seal sits beside the file, so it catches damage; the trace is what an
//!   edit of both cannot satisfy.
//! - **Consumed by copy.** A consumer opens its own copy; the cached file
//!   is never opened for writing.
//!
//! The nightly rebuilds each snapshot from genesis ([`build`] holds the
//! replay to the trace), so a store whose bytes drifted from the chain is
//! found there rather than served.

use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use shekyl_chain_store::apply_policy::ApplyPolicy;
use shekyl_chain_store::codec::SCHEMA_VERSION;
use shekyl_chain_store::store::{ChainStore, StoreError};
use shekyl_hash_budget::Budget;
use shekyl_hasher::Hasher;

use crate::metrics::Metrics;
use crate::pipeline::PipelineConfig;
use crate::rebaseline::{horizons, replay_corpus_through, ReplayFault};
use crate::schedule::ChainRules;
use crate::source::SequenceNo;
use crate::trace::{Digest, Trace, TraceFault};
use crate::ProductionPow;

/// The store file in a snapshot's directory.
pub const STORE_FILE: &str = "chain.redb";
/// The seal beside it, written last: a directory without one is unfinished.
pub const SEAL_FILE: &str = "seal.json";

/// The source trees that decide what a replay leaves in the store, from the
/// repository's root: the ledger's `block-path` set, without its benches,
/// plus the economics configuration and the lock file. A fix to a fold moves
/// derived rows under one schema version, so the schema alone is no key.
pub const CONSENSUS_TREES: &[&str] = &[
    "config",
    "rust/Cargo.lock",
    "rust/shekyl-archival-retention/src",
    "rust/shekyl-bulletproofs/src",
    "rust/shekyl-chain-ingest/src",
    "rust/shekyl-chain-rules/src",
    "rust/shekyl-chain-store/src",
    "rust/shekyl-crypto-pq/src/signature.rs",
    "rust/shekyl-ct-balance/src",
    "rust/shekyl-difficulty/src",
    "rust/shekyl-economics/src",
    "rust/shekyl-fcmp-proofs/src",
    "rust/shekyl-fcmp/src",
    "rust/shekyl-oxide/crypto/fcmps",
    "rust/shekyl-store-codec/src",
    "rust/shekyl-wire/src",
];

/// Why a snapshot was not built or not opened.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotFault {
    /// A file could not be read or written.
    #[error("snapshot io: {0}")]
    Io(#[from] io::Error),
    /// The seal does not parse.
    #[error("snapshot seal: {0}")]
    Seal(#[from] serde_json::Error),
    /// The trace does not read.
    #[error("snapshot trace: {0}")]
    Trace(#[from] TraceFault),
    /// The replay failed.
    #[error("snapshot replay: {0}")]
    Replay(#[from] ReplayFault),
    /// The store refused to open or to be read.
    #[error("snapshot store: {0}")]
    Store(#[from] StoreError),
    /// The chain's trace names no event at this record.
    #[error("the trace names no event at record {0}")]
    NoEvent(u64),
    /// The replay did not end at the event, or disagreed with the trace.
    #[error("the replay to record {record} disagrees with the trace: {why}")]
    Disagrees {
        /// The event's record.
        record: u64,
        /// What the run reported.
        why: String,
    },
    /// The directory is another key's snapshot.
    #[error("the snapshot is keyed {found}, the caller asked for {wanted}")]
    WrongKey {
        /// The key asked for.
        wanted: String,
        /// The key its seal names.
        found: String,
    },
    /// The file is not the one sealed.
    #[error("the snapshot file's SHA-256 is {found}, its seal says {sealed}")]
    FileChanged {
        /// The seal's.
        sealed: String,
        /// The file's.
        found: String,
    },
    /// The store does not hold the state the pinned trace carries.
    #[error("the snapshot's tables digest is {found}, the trace's is {expected}")]
    DigestChanged {
        /// The trace's.
        expected: String,
        /// The copy's.
        found: String,
    },
}

/// What decides a snapshot's bytes (module docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotKey {
    /// The pinned chain's digest.
    pub chain: String,
    /// The event's name.
    pub event: String,
    /// The store's schema version.
    pub schema: u64,
    /// [`consensus_code_digest`].
    pub code: String,
}

impl SnapshotKey {
    /// The key of `event` on the chain pinned at `chain`, at the schema and
    /// consensus code of the tree at `root`.
    ///
    /// # Errors
    ///
    /// A consensus tree could not be read.
    pub fn at(chain: &str, event: &str, root: &Path) -> io::Result<Self> {
        Ok(Self {
            chain: chain.to_owned(),
            event: event.to_owned(),
            schema: SCHEMA_VERSION.get(),
            code: consensus_code_digest(root)?,
        })
    }

    /// The key as one name: a directory's, and a CI cache entry's suffix.
    #[must_use]
    pub fn name(&self) -> String {
        let chain = self.chain.strip_prefix("sha256:").unwrap_or(&self.chain);
        format!(
            "{}-{}-schema{}-{}",
            &chain[..chain.len().min(16)],
            self.event,
            self.schema,
            &self.code[..self.code.len().min(16)],
        )
    }
}

/// SHA-256 over every file of [`CONSENSUS_TREES`] under `root`, in sorted
/// path order, each framed by its path and length.
///
/// # Errors
///
/// A tree is missing or a file does not read: a key over a partial tree
/// would name code it never hashed.
pub fn consensus_code_digest(root: &Path) -> io::Result<String> {
    let mut files = Vec::new();
    for tree in CONSENSUS_TREES {
        collect_files(&root.join(tree), &mut files)?;
    }
    files.sort();
    let mut hash = Sha256::new();
    for file in &files {
        let relative = file.strip_prefix(root).map_err(io::Error::other)?;
        let name = relative.to_string_lossy().replace('\\', "/");
        let bytes = fs::read(file)?;
        hash.update(
            u64::try_from(name.len())
                .map_err(io::Error::other)?
                .to_le_bytes(),
        );
        hash.update(name.as_bytes());
        hash.update(
            u64::try_from(bytes.len())
                .map_err(io::Error::other)?
                .to_le_bytes(),
        );
        hash.update(&bytes);
    }
    Ok(lower_hex(&hash.finalize()))
}

/// `bytes` as lowercase hex.
fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        write!(out, "{byte:02x}").expect("a String takes the write");
        out
    })
}

fn collect_files(path: &Path, into: &mut Vec<PathBuf>) -> io::Result<()> {
    if path.is_file() {
        into.push(path.to_path_buf());
        return Ok(());
    }
    for entry in fs::read_dir(path)? {
        collect_files(&entry?.path(), into)?;
    }
    Ok(())
}

/// The seal beside a snapshot's store.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Seal {
    key: String,
    record: u64,
    file_sha256: String,
}

fn file_sha256(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(lower_hex(&hash.finalize()));
        }
        hash.update(&buffer[..read]);
    }
}

/// Seal the closed store in `dir` as `key`'s snapshot at `record`. Written
/// through a rename, so a seal on disk is a whole one.
///
/// # Errors
///
/// [`SnapshotFault::Io`], [`SnapshotFault::Seal`].
pub fn seal(dir: &Path, key: &SnapshotKey, record: SequenceNo) -> Result<(), SnapshotFault> {
    let seal = Seal {
        key: key.name(),
        record: record.to_raw(),
        file_sha256: file_sha256(&dir.join(STORE_FILE))?,
    };
    let staged = dir.join(format!("{SEAL_FILE}.new"));
    fs::write(&staged, serde_json::to_vec_pretty(&seal)?)?;
    fs::rename(&staged, dir.join(SEAL_FILE))?;
    Ok(())
}

/// What one chain's snapshot is replayed from.
#[derive(Clone, Copy, Debug)]
pub struct ChainFiles<'a> {
    /// The chain's corpus.
    pub corpus: &'a Path,
    /// Its trace.
    pub trace: &'a Path,
    /// The event's corpus record.
    pub record: SequenceNo,
    /// The rules it is judged under.
    pub rules: ChainRules,
}

impl ChainFiles<'_> {
    /// The tables digest the chain's trace carries at the event.
    ///
    /// # Errors
    ///
    /// The trace does not read, or names no event at the record.
    pub fn expected_digest(&self) -> Result<Digest, SnapshotFault> {
        let trace = Trace::read(BufReader::new(File::open(self.trace)?))?;
        trace
            .event_digest(self.record)
            .map(|expected| *expected.value())
            .ok_or(SnapshotFault::NoEvent(self.record.to_raw()))
    }
}

/// Replay `files`' chain from genesis to its event into `dir`, hold the
/// store to the trace there, and seal it as `key`.
///
/// # Errors
///
/// [`SnapshotFault`]: a replay that fails, disagrees or stops short.
pub async fn build(
    files: ChainFiles<'_>,
    dir: &Path,
    key: &SnapshotKey,
    hashers: NonZeroUsize,
) -> Result<(), SnapshotFault> {
    fs::create_dir_all(dir)?;
    let store = dir.join(STORE_FILE);
    if store.exists() {
        fs::remove_file(&store)?;
    }
    let record = files.record;
    let expected = files.expected_digest()?;
    let trace = Trace::read(BufReader::new(File::open(files.trace)?))?;
    let narrowed = trace
        .through_event(record)
        .ok_or(SnapshotFault::NoEvent(record.to_raw()))?;
    let metrics = Arc::new(Metrics::new());
    let (hasher, owner) = Hasher::start(Budget::new(hashers))?;
    let pow = Arc::new(ProductionPow::new(hasher, Arc::clone(&metrics)));
    let replayed = replay_corpus_through(
        files.corpus,
        &store,
        record,
        files.rules,
        PipelineConfig {
            window: PipelineConfig::DEFAULT_WINDOW,
            hashers,
            digest_each_commit: false,
        },
        Arc::clone(&pow),
        metrics,
        Arc::new(narrowed),
    )
    .await;
    // Every form has ended, so no lease is out: the stop frees the caches.
    drop(pow);
    owner.stop();
    let report = replayed?;
    let disagrees = |why: String| SnapshotFault::Disagrees {
        record: record.to_raw(),
        why,
    };
    let disagreements: Vec<String> = report
        .disagreements()
        .map(|disagreement| format!("{disagreement:?}"))
        .collect();
    if !disagreements.is_empty() {
        return Err(disagrees(disagreements.join("; ")));
    }
    match report.events.as_slice() {
        [event] if event.record == record && event.ours == expected => {}
        events => return Err(disagrees(format!("the run digested {events:?}"))),
    }
    seal(dir, key, record)
}

/// `key`'s snapshot under `root`, built by [`build`] if no process has.
/// Concurrent callers wait on one lock, so one of them replays.
///
/// # Errors
///
/// [`SnapshotFault`].
pub async fn ensure(
    root: &Path,
    files: ChainFiles<'_>,
    key: &SnapshotKey,
    hashers: NonZeroUsize,
) -> Result<PathBuf, SnapshotFault> {
    fs::create_dir_all(root)?;
    let name = key.name();
    let dir = root.join(&name);
    let lock = File::create(root.join(format!("{name}.lock")))?;
    lock.lock()?;
    if !dir.join(SEAL_FILE).is_file() {
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        build(files, &dir, key, hashers).await?;
    }
    drop(lock);
    Ok(dir)
}

/// Copy `key`'s snapshot in `dir` to `to`, refusing it unless the file is
/// the one sealed and the copy holds the state `expected` names (module
/// docs). The cached file is only read.
///
/// # Errors
///
/// [`SnapshotFault::WrongKey`], [`SnapshotFault::FileChanged`],
/// [`SnapshotFault::DigestChanged`], or a store that does not open.
pub fn open_copy(
    dir: &Path,
    key: &SnapshotKey,
    expected: &Digest,
    rules: &ChainRules,
    to: &Path,
) -> Result<(), SnapshotFault> {
    let seal: Seal = serde_json::from_slice(&fs::read(dir.join(SEAL_FILE))?)?;
    let wanted = key.name();
    if seal.key != wanted {
        return Err(SnapshotFault::WrongKey {
            wanted,
            found: seal.key,
        });
    }
    let source = dir.join(STORE_FILE);
    let found = file_sha256(&source)?;
    if found != seal.file_sha256 {
        return Err(SnapshotFault::FileChanged {
            sealed: seal.file_sha256,
            found,
        });
    }
    fs::copy(&source, to)?;
    let digest = {
        let store = ChainStore::with_horizons(to, ApplyPolicy::default(), horizons(rules)?)?;
        let read = store.begin_read()?;
        read.tables_digest_v1()?
    };
    if digest != *expected {
        fs::remove_file(to)?;
        return Err(SnapshotFault::DigestChanged {
            expected: lower_hex(expected),
            found: lower_hex(&digest),
        });
    }
    Ok(())
}

#[cfg(test)]
#[path = "snapshot_tests.rs"]
mod snapshot_tests;
