// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The slash log as consensus history (DRS-E4 `ARW-Q2`): what one slash took,
//! for the as-of-height holdings fold.

use crate::{PCanonicalId, SettlementEpoch, ShardId};

// ---------------------------------------------------------------------------
// The slash log — consensus history, not a journal (DRS-E4 `ARW-Q2`)
// ---------------------------------------------------------------------------

/// What one slash took from a record's holdings — the pre-image the
/// as-of-height fold needs and nothing the undo log already holds.
///
/// `holds_shard_at(h)` asks *did `P` hold `s` at `h`*; for a shard the
/// record does not hold at tip, the answer is *yes* iff a logged slash
/// strictly above `h` removed it — either this exact shard was erased from
/// a compact set that had held it since `add_epoch`, or the record was a
/// complete tree that a slash demoted to empty (`db_lmdb.cpp`,
/// `archival_slash_removed_holding_after`). The two arms are the two
/// variants; the C++'s `holdings_pre_kind` byte plus a zero-when-unused
/// `slashed_shard_add_epoch` become one sum, so an add-epoch on a
/// complete-tree demotion cannot be spelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlashedHolding {
    /// A compact set held the challenged shard since `add_epoch`; the slash
    /// erased that one shard.
    Shard {
        /// The settlement epoch the erased shard had been acquired in.
        add_epoch: SettlementEpoch,
    },
    /// A complete-tree record; the slash demoted it to an empty compact set.
    CompleteTree,
}

/// `archival_slash_log[(height, seq)]` — one slash the scheduler applied,
/// as history.
///
/// This is the **one archival journal that is a fact**: the record after a
/// slash says what is held now, not when a shard left, and the as-of-height
/// question reaches back past the reorg window the undo log covers
/// (`DRS_E4_ARCHIVAL_WRITER.md` §3.3). What is here is exactly what that
/// read consumes — who, which shard, which epoch's failure, and what the
/// slash took. The C++ row also carried the slashed amount and an
/// epoch-marker row kind; neither has a reader once pop is the undo log's
/// (the amount's pre-image is the record's; the marker's job is the
/// `archival_last_slash_epoch` cell's own pre-image), so neither is here.
/// The amount reopens with a named reader (rule 21).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlashLogEntry {
    /// The slashed persona.
    pub persona: PCanonicalId,
    /// The shard whose challenge failed.
    pub shard: ShardId,
    /// The settlement epoch whose failure this slash settles.
    pub epoch: SettlementEpoch,
    /// What the slash took from the record's holdings.
    pub holding: SlashedHolding,
}
