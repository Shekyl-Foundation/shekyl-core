// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The E2 corpus re-baselined from Rust (`DAEMON_REDB_STORE.md` §12.1).
//!
//! The captured chains were built by the C++ daemon and graded against
//! its trace: a conformance oracle with two sides. The C++ side is gone, so
//! the corpus becomes a regression gate with one: a replay of the chain
//! against a fresh store must reproduce the trace this module writes from
//! the store a previous replay of the same chain left. Every facts record
//! is read off the store at its height and the checkpoint is the store's
//! own state at the tip, so the trace pins what the Rust derivation
//! produced at the sha it was written from, not a ported verdict.
//!
//! Nothing here is a second derivation. The facts are the rows `connect`
//! wrote (`block_info`, `block_burn`, `curve_tree_roots`), the digest is
//! `logical_state_digest_v0` and the archival rows are
//! `archival_snapshot`, the same reads the pipeline's checkpoint compares.

use std::io::Write;

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
