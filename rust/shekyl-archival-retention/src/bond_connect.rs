// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bond-post block-connect state transitions (gate-4 §4.3/§4.5/§5;
//! `PHASE_2B_FSM_RETOOL.md` P2B-8 implementation locus).
//!
//! The C++ connect site owns the LMDB write transaction and marshals the
//! record's current state in; this module is the **single implementation** of
//! what the connect writes — the post-connect record fields, the interval-log
//! append, and the `total_bonded_atomic` movement are all *outputs* of the
//! fold here, so no consensus arithmetic lives in C++ (`20-rust-vs-cpp-policy`).
//! Every connect fold has a pop twin (gate-4 §5 all-types-atomic pop); the pop
//! restores the record from the connect's pre-image journal (C++ byte-copy) and
//! this module owns the counter re-credit plus the state-consistency checks.
//!
//! Errors here are **connect-time invariant breaches** — conditions the §3.5
//! verify (plus the block-level per-`P` pass) already rejected. The C++ caller
//! maps them to a FATAL abort, never a soft skip (the emission-connect §6.2
//! posture): a block must not connect with a half-applied bond release.

use thiserror::Error;

use crate::bond_floor::bond_floor_of;
use crate::bond_post::holdings_unchanged;
use crate::bond_wire::{HoldingsDescriptor, HoldingsKind, ShardSet, MAX_HOLDINGS_SHARDS};
use crate::consensus_state::BadInterval;

/// Interval-log entry cap — the cross-language pin of
/// `ArchivalBondValue::kMaxBadIntervals` (`src/blockchain_db/shekyl_types.h`,
/// whose static_assert pins the pair against silent drift).
/// The codec rejects records above this bound at encode/decode, so a connect
/// that would append past it can never persist; verify enforces the same bound
/// (`BondPostError::IntervalLogFull`) so such a tx never reaches connect.
///
/// **Genesis-frozen consensus constant** (P2B-8 Q3 posture): because Release
/// verify rejects on it, tx validity depends on the value — a change is a
/// hard fork, not a codec retune.
pub const MAX_BOND_BAD_INTERVALS: usize = 256;

// The C++ static_assert can only fire on a C++ edit; this is the Rust half of
// the pair-wise pin (the `bond_floor` idiom), so a Rust-only edit cannot
// silently diverge verify's IntervalLogFull bound from the codec cap either.
const _: () = assert!(
    MAX_BOND_BAD_INTERVALS == 256,
    "MAX_BOND_BAD_INTERVALS diverged from the kMaxBadIntervals genesis pin"
);

/// The clean interval-close (gate-4 §4.3 F3): a **zero-length** interval
/// `[E, E)` appended to the record's interval log at `Release` connect.
///
/// `good_through` skips it for every epoch (`end_exclusive != u64::MAX` and
/// `E < end_exclusive` is false at `E == start_epoch`), so backlog emission
/// for served epochs still verifies within `W` — the §4.3 requirement — while
/// the exit settlement epoch is durably recorded for the later `W`-lapse /
/// `p_slot`-burn step. Contrast: a slash writes an **open** bad interval
/// `[E_slash, u64::MAX)`.
#[must_use]
pub fn clean_interval_close(release_settlement_epoch: u64) -> BadInterval {
    BadInterval {
        start_epoch: release_settlement_epoch,
        end_exclusive: release_settlement_epoch,
    }
}

/// True when `interval` has the [`clean_interval_close`] shape for `epoch` —
/// the pop twin's trailing-entry consistency check.
#[must_use]
pub fn is_clean_interval_close(interval: &BadInterval, epoch: u64) -> bool {
    interval.start_epoch == epoch && interval.end_exclusive == epoch
}

/// The open bad interval a landed slash appends — or `None` under the
/// same-epoch coalescing invariant (P2B-9 Pin 5): an open interval already
/// exists, so the sibling slash appends nothing.
///
/// Every held shard is challenged every epoch and this epoch's failures are
/// slashed one call each against a stale pre-scan eligibility copy, so an
/// offline N-shard record takes N slashes in one block. The intervals they
/// would each append are IDENTICAL (`[E_slash, u64::MAX)` — later epochs are
/// `good_through`-blocked while any open interval exists, so multiplicity is
/// same-epoch only), and appending one per shard let a record with more
/// failing shards than the interval log's codec headroom
/// ([`MAX_BOND_BAD_INTERVALS`]) throw at encode inside the block-connect
/// slash hook — a deterministic consensus halt. Appending only when no open
/// interval exists leaves standing semantics unchanged (`good_through` only
/// asks whether SOME open interval covers the epoch) and establishes the
/// **at most one open interval** invariant the `Reinstate` verify (Pin 5) and
/// its in-place close depend on.
///
/// The decision and the interval shape are consensus semantics, so they live
/// here — the C++ slash writer appends exactly what this returns
/// (`20-rust-vs-cpp-policy`; the [`clean_interval_close`] placement's twin).
#[must_use]
pub fn slash_open_interval_to_append(
    record_bad_intervals: &[BadInterval],
    slash_settlement_epoch: u64,
) -> Option<BadInterval> {
    let has_open = record_bad_intervals
        .iter()
        .any(|iv| iv.end_exclusive == u64::MAX);
    (!has_open).then_some(BadInterval {
        start_epoch: slash_settlement_epoch,
        end_exclusive: u64::MAX,
    })
}

#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum ReleaseConnectError {
    /// `bond_debit` is zero — nothing to release (verify's `NothingToRelease`
    /// / `DebitNotFullBalance` should have rejected the tx).
    #[error("Release connect with zero bond_debit")]
    DebitZero,
    /// `bond_debit` does not equal the record's current `bonded_total` —
    /// verify ran against different record state than connect sees.
    #[error("Release bond_debit does not equal the record's current bonded_total")]
    DebitNotRecordTotal,
    /// The record's maintained invariant `bonded_total == bond_floor(holdings)`
    /// (gate-4 §3.2) does not hold — record corruption, not a tx fault.
    #[error("record bonded_total != bond_floor(record holdings)")]
    RecordFloorInvariantBroken,
    /// `total_bonded_atomic` would underflow — the global counter disagrees
    /// with the per-record balance it aggregates (§4.5 audit scalar).
    #[error("total_bonded_atomic underflow on Release debit")]
    TotalBondedUnderflow,
    /// The interval log is at `MAX_BOND_BAD_INTERVALS`; the clean close cannot
    /// append. Verify's `IntervalLogFull` arm forecloses this at tx admission.
    #[error("interval log full; clean interval-close cannot append")]
    IntervalLogFull,
}

/// The full `Release` connect effect (gate-4 §4.3 "On confirm").
///
/// The C++ connect arm writes **exactly** these fields: the record becomes
/// `post_bonded_total` / `post_holdings` with `interval_close` appended to its
/// interval log, and the global counter becomes `new_total_bonded_atomic`.
/// `refund_atomic` is the released balance the tx's `bond_debit` source term
/// returns to circulation — it is CT-balance-enforced on the wire
/// (`verify_bond_post_ct_balance`), not written by the connect; it is exposed
/// so tests pin the §4.3 identity `refund == debit == bond_floor(current)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseConnect {
    /// Always `0` — full release (§4.3 step "zero `bonded_total_atomic`").
    pub post_bonded_total: u64,
    /// Always the canonical empty set (`ShardSetCompact`, no shards) — the
    /// same exit shape the slash-to-zero path writes.
    pub post_holdings: HoldingsDescriptor,
    /// The clean interval-close to append (F3): `[E_release, E_release)`.
    pub interval_close: BadInterval,
    /// `total_bonded_atomic − bond_debit` (§4.5 release row).
    ///
    /// **Absolute post-value — thread it per post.** The caller must read the
    /// live counter immediately before *each* fold (`get → release_connect →
    /// set`, the JoinMarket arm's inline `get → set(get + credit)` shape,
    /// `blockchain_db.cpp`). A dispatch that hoists one counter read out of a
    /// multi-bond-post block and applies each fold's absolute would compute
    /// every debit from the same block-start total and clobber all but the
    /// last write. The per-`P` block pass does NOT cover this: different-`P`
    /// posts in one block are legitimate and still share the global counter.
    pub new_total_bonded_atomic: u64,
    /// `== bond_debit == bond_floor(record's current holdings)` (§4.3).
    pub refund_atomic: u64,
}

/// Fold the `Release` connect (gate-4 §4.3): given the record's **current**
/// state, the vin's `bond_debit`, and the connecting block's settlement epoch,
/// produce the post-connect record state, the interval-log append, and the
/// `total_bonded_atomic` movement.
///
/// The record's holdings arrive as `(kind, shard count)` — the floor invariant
/// never reads shard-id values ([`bond_floor_of`]), so the caller marshals the
/// count instead of copying the record's shard-id array across the FFI.
/// `record_bad_interval_count` is the record's interval-log length *before*
/// the append. The record **persists** (state `Exited`) for backlog claims
/// until `W` lapses — deletion / `p_slot` burn is a later, separate step.
pub fn release_connect(
    record_bonded_total: u64,
    record_holdings_kind: HoldingsKind,
    record_held_shard_count: usize,
    record_bad_interval_count: usize,
    vin_bond_debit: u64,
    total_bonded_atomic: u64,
    release_settlement_epoch: u64,
) -> Result<ReleaseConnect, ReleaseConnectError> {
    if vin_bond_debit == 0 {
        return Err(ReleaseConnectError::DebitZero);
    }
    if vin_bond_debit != record_bonded_total {
        return Err(ReleaseConnectError::DebitNotRecordTotal);
    }
    // §3.2 maintained invariant on the record being released — a mismatch is
    // record corruption the release must not paper over.
    if bond_floor_of(record_holdings_kind, record_held_shard_count) != record_bonded_total {
        return Err(ReleaseConnectError::RecordFloorInvariantBroken);
    }
    if record_bad_interval_count >= MAX_BOND_BAD_INTERVALS {
        return Err(ReleaseConnectError::IntervalLogFull);
    }
    let new_total_bonded_atomic = total_bonded_atomic
        .checked_sub(vin_bond_debit)
        .ok_or(ReleaseConnectError::TotalBondedUnderflow)?;

    Ok(ReleaseConnect {
        post_bonded_total: 0,
        post_holdings: HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::empty(),
        },
        interval_close: clean_interval_close(release_settlement_epoch),
        new_total_bonded_atomic,
        refund_atomic: vin_bond_debit,
    })
}

#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum ReleasePopError {
    /// The record is not in the `Release` post-connect state (`bonded_total`
    /// nonzero or holdings non-empty) — the journal row does not describe the
    /// tip's record; the pop would revert something else's write.
    #[error("record is not in the Release post-connect (Exited) state")]
    RecordNotExited,
    /// The record's trailing interval-log entry is not this connect's clean
    /// interval-close — journal/log desync.
    #[error("trailing interval-log entry is not the expected clean interval-close")]
    MissingCleanClose,
    /// The journaled pre-image has `bonded_total == 0` — connect can never
    /// journal that (a zero-balance record fails verify and connect alike).
    #[error("journaled pre-image bonded_total is zero")]
    PreImageEmpty,
    /// Re-crediting `total_bonded_atomic` would overflow.
    #[error("total_bonded_atomic overflow on Release pop re-credit")]
    TotalBondedOverflow,
}

/// Fold the `Release` pop twin (gate-4 §5): validate the tip record is the
/// connect's product, then re-credit `total_bonded_atomic` with the journaled
/// pre-image balance. Returns the restored `total_bonded_atomic`.
///
/// The record fields themselves are restored by the C++ pop arm as a byte-copy
/// of the pre-image journal row (the emission-claim WS-2 §6.3 shape) — that
/// restore carries the holdings and the interval log (the clean close vanishes
/// with it), so this fold's job is the counter movement plus the consistency
/// checks that make a desynced journal loud instead of silently corrupting.
///
/// **Trailing-entry invariant (ratified 2026-07-12, maintainer):** slashability
/// ends at the `Release` connect — the slash scheduler only examines currently
/// held shards and an `Exited` record holds none, so nothing ever appends after
/// the clean close and the refund is never clawed back. (The release verify
/// guarantees every epoch through the last-served anchor settled *before* the
/// connect: `release_cooldown` module docs.) The trailing entry at pop is
/// therefore always this connect's clean close. `pop_block` still reverts
/// slashes before the bond journal — a defensive ordering belt, since a
/// same-block slash on a *different* record is routine — and any future change
/// that let an interval land after a clean close would surface here as
/// `MissingCleanClose`: loud, not silent.
pub fn release_pop(
    current_record_bonded_total: u64,
    current_record_held_shard_count: usize,
    trailing_interval: Option<BadInterval>,
    release_settlement_epoch: u64,
    journal_pre_bonded_total: u64,
    total_bonded_atomic: u64,
) -> Result<u64, ReleasePopError> {
    if current_record_bonded_total != 0 || current_record_held_shard_count != 0 {
        return Err(ReleasePopError::RecordNotExited);
    }
    match trailing_interval {
        Some(iv) if is_clean_interval_close(&iv, release_settlement_epoch) => {}
        _ => return Err(ReleasePopError::MissingCleanClose),
    }
    if journal_pre_bonded_total == 0 {
        return Err(ReleasePopError::PreImageEmpty);
    }
    total_bonded_atomic
        .checked_add(journal_pre_bonded_total)
        .ok_or(ReleasePopError::TotalBondedOverflow)
}

#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum ReinstateConnectError {
    /// The post set is not the record's current holdings —
    /// verify's `ReinstateHoldingsChanged`.
    #[error("Reinstate post-holdings do not equal current (bond is immutable)")]
    HoldingsChanged,
    /// Empty post — verify's `ShardSetCompactEmpty` (reinstatement needs a position).
    #[error("Reinstate post-holdings are empty")]
    EmptyPost,
    /// The post set exceeds the codec shard cap — the resulting record could
    /// never encode; verify's `ReinstatePostOversize` forecloses this at tx
    /// admission, this is the fold's belt for verify-bypassing callers.
    #[error("Reinstate post-holdings exceed the codec shard cap")]
    PostOversize,
    /// The record's `bonded_total == bond_floor(holdings)` invariant (§3.2) does
    /// not hold — record corruption, not a tx fault.
    #[error("record bonded_total != bond_floor(record holdings)")]
    RecordFloorInvariantBroken,
    /// No open bad interval — the record is not slashed; verify's `ReinstateNotSlashed`.
    #[error("no open bad interval to close (record not slashed)")]
    NoOpenInterval,
    /// More than one open bad interval — corruption of the P2B-9 Pin 5 coalescing
    /// invariant (the loud multiplicity belt).
    #[error("multiple open bad intervals (coalescing invariant broken)")]
    MultipleOpenIntervals,
    /// `E_reinstate + 1` does not lie strictly after the open interval's start — the
    /// slash would have to postdate the reinstatement (corruption).
    #[error("interval close E_reinstate + 1 is not after the open interval's start")]
    IntervalOrdering,
    /// Counter/epoch arithmetic over/underflow.
    #[error("counter or epoch arithmetic out of range on Reinstate")]
    CounterRange,
}

/// The `Reinstate` connect effect: close the one open bad interval in place.
/// Holdings, add-epochs, and counters do not move — a persona's bond is
/// immutable (2026-09-20). The C++ arm journals the closed interval's identity
/// (index + start) so pop re-opens exactly that entry.
///
/// `end_exclusive = E_reinstate + 1` (Pin 3 — standing resumes at
/// `E_reinstate + 1`; the partial-reinstate epoch is forfeited in both
/// directions). No interval is appended or removed — post-connect
/// `bad_intervals.len()` is unchanged, which is what the verify-side `≤ 254`
/// headroom (Pin 6) budgeted for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReinstateConnect {
    /// Index into the record's `bad_intervals` of the one open interval to close.
    pub closed_interval_index: usize,
    /// `E_reinstate + 1` — the value to write into the closed interval's
    /// `end_exclusive`.
    pub interval_end_exclusive: u64,
}

/// Fold the `Reinstate` connect: post-holdings equal current, the record's floor
/// invariant holds, and exactly one open interval closes at `E + 1`.
pub fn reinstate_connect(
    record_bonded_total: u64,
    record_held_shard_ids: &[u64],
    record_bad_intervals: &[BadInterval],
    post_held_shard_ids: &[u64],
    reinstate_settlement_epoch: u64,
) -> Result<ReinstateConnect, ReinstateConnectError> {
    if post_held_shard_ids.is_empty() {
        return Err(ReinstateConnectError::EmptyPost);
    }
    // Codec-cap belt (verify's oversize twin): a post past the cap would fold
    // into a record ArchivalBondValue::encode refuses — fail typed here instead
    // of as an opaque encode throw in the LMDB writer.
    if post_held_shard_ids.len() > MAX_HOLDINGS_SHARDS {
        return Err(ReinstateConnectError::PostOversize);
    }
    if !holdings_unchanged(record_held_shard_ids, post_held_shard_ids) {
        return Err(ReinstateConnectError::HoldingsChanged);
    }
    if bond_floor_of(HoldingsKind::ShardSetCompact, record_held_shard_ids.len())
        != record_bonded_total
    {
        return Err(ReinstateConnectError::RecordFloorInvariantBroken);
    }
    let mut open_indices = record_bad_intervals
        .iter()
        .enumerate()
        .filter(|(_, iv)| iv.end_exclusive == u64::MAX)
        .map(|(i, _)| i);
    let Some(closed_interval_index) = open_indices.next() else {
        return Err(ReinstateConnectError::NoOpenInterval);
    };
    if open_indices.next().is_some() {
        return Err(ReinstateConnectError::MultipleOpenIntervals);
    }
    let interval_end_exclusive = reinstate_settlement_epoch
        .checked_add(1)
        .ok_or(ReinstateConnectError::CounterRange)?;
    // The slash that opened the interval predates the reinstatement, so the close
    // must land strictly after the open's start — anything else is corruption.
    if interval_end_exclusive <= record_bad_intervals[closed_interval_index].start_epoch {
        return Err(ReinstateConnectError::IntervalOrdering);
    }
    Ok(ReinstateConnect {
        closed_interval_index,
        interval_end_exclusive,
    })
}

#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum ReinstatePopError {
    /// The per-`P` balance moved between the journaled pre-image and the tip
    /// record — a `Reinstate` is zero-money, so that is not this journal's row.
    #[error("Reinstate pop: record bonded_total moved (must be unchanged)")]
    NotReinstateDelta,
}

/// Fold the `Reinstate` pop twin (gate-4 §5): the C++ arm re-opens the journaled
/// interval to `end_exclusive = MAX`. Holdings and counters did not move at
/// connect, so this fold only belts that the tip bonded_total still equals the
/// journaled pre-image.
pub fn reinstate_pop(
    current_record_bonded_total: u64,
    journal_pre_bonded_total: u64,
) -> Result<(), ReinstatePopError> {
    if current_record_bonded_total != journal_pre_bonded_total {
        return Err(ReinstatePopError::NotReinstateDelta);
    }
    Ok(())
}

#[cfg(test)]
#[path = "bond_connect_tests.rs"]
mod tests;
