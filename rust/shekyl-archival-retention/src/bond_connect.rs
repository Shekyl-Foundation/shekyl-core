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

use crate::bond_floor::{bond_floor_of, ARCHIVAL_BOND_FLOOR_ATOMIC};
use crate::bond_post::{single_shard_diff, superset_added_diff, SingleDiff};
use crate::bond_wire::{HoldingsDescriptor, HoldingsKind, ShardSet, MAX_HOLDINGS_SHARDS};
use crate::consensus_state::BadInterval;

/// Interval-log entry cap — the cross-language pin of
/// `ArchivalBondValue::kMaxBadIntervals` (`src/blockchain_db/shekyl_types.h`,
/// whose static_assert pins the pair against silent drift).
/// The codec rejects records above this bound at encode/decode, so a connect
/// that would append past it can never persist; verify enforces the same bound
/// (`BondPostError::IntervalLogFull`) so such a tx never reaches connect.
///
/// **Genesis-frozen consensus constant** (P2B-8 Q3 posture): because Unbond
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
/// `[E, E)` appended to the record's interval log at `Unbond` connect.
///
/// `good_through` skips it for every epoch (`end_exclusive != u64::MAX` and
/// `E < end_exclusive` is false at `E == start_epoch`), so backlog emission
/// for served epochs still verifies within `W` — the §4.3 requirement — while
/// the exit settlement epoch is durably recorded for the later `W`-lapse /
/// `p_slot`-burn step. Contrast: a slash writes an **open** bad interval
/// `[E_slash, u64::MAX)`.
#[must_use]
pub fn clean_interval_close(unbond_settlement_epoch: u64) -> BadInterval {
    BadInterval {
        start_epoch: unbond_settlement_epoch,
        end_exclusive: unbond_settlement_epoch,
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
/// **at most one open interval** invariant the `Rebond` verify (Pin 5) and
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
pub enum UnbondConnectError {
    /// `bond_debit` is zero — nothing to release (verify's `NothingToUnbond`
    /// / `DebitNotFullBalance` should have rejected the tx).
    #[error("Unbond connect with zero bond_debit")]
    DebitZero,
    /// `bond_debit` does not equal the record's current `bonded_total` —
    /// verify ran against different record state than connect sees.
    #[error("Unbond bond_debit does not equal the record's current bonded_total")]
    DebitNotRecordTotal,
    /// The record's maintained invariant `bonded_total == bond_floor(holdings)`
    /// (gate-4 §3.2) does not hold — record corruption, not a tx fault.
    #[error("record bonded_total != bond_floor(record holdings)")]
    RecordFloorInvariantBroken,
    /// `total_bonded_atomic` would underflow — the global counter disagrees
    /// with the per-record balance it aggregates (§4.5 audit scalar).
    #[error("total_bonded_atomic underflow on Unbond debit")]
    TotalBondedUnderflow,
    /// The interval log is at `MAX_BOND_BAD_INTERVALS`; the clean close cannot
    /// append. Verify's `IntervalLogFull` arm forecloses this at tx admission.
    #[error("interval log full; clean interval-close cannot append")]
    IntervalLogFull,
}

/// The full `Unbond` connect effect (gate-4 §4.3 "On confirm").
///
/// The C++ connect arm writes **exactly** these fields: the record becomes
/// `post_bonded_total` / `post_holdings` with `interval_close` appended to its
/// interval log, and the global counter becomes `new_total_bonded_atomic`.
/// `refund_atomic` is the released balance the tx's `bond_debit` source term
/// returns to circulation — it is CT-balance-enforced on the wire
/// (`verify_bond_post_ct_balance`), not written by the connect; it is exposed
/// so tests pin the §4.3 identity `refund == debit == bond_floor(current)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnbondConnect {
    /// Always `0` — full release (§4.3 step "zero `bonded_total_atomic`").
    pub post_bonded_total: u64,
    /// Always the canonical empty set (`ShardSetCompact`, no shards) — the
    /// same exit shape the slash-to-zero path writes.
    pub post_holdings: HoldingsDescriptor,
    /// The clean interval-close to append (F3): `[E_unbond, E_unbond)`.
    pub interval_close: BadInterval,
    /// `total_bonded_atomic − bond_debit` (§4.5 release row).
    ///
    /// **Absolute post-value — thread it per post.** The caller must read the
    /// live counter immediately before *each* fold (`get → unbond_connect →
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

/// Fold the `Unbond` connect (gate-4 §4.3): given the record's **current**
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
pub fn unbond_connect(
    record_bonded_total: u64,
    record_holdings_kind: HoldingsKind,
    record_held_shard_count: usize,
    record_bad_interval_count: usize,
    vin_bond_debit: u64,
    total_bonded_atomic: u64,
    unbond_settlement_epoch: u64,
) -> Result<UnbondConnect, UnbondConnectError> {
    if vin_bond_debit == 0 {
        return Err(UnbondConnectError::DebitZero);
    }
    if vin_bond_debit != record_bonded_total {
        return Err(UnbondConnectError::DebitNotRecordTotal);
    }
    // §3.2 maintained invariant on the record being released — a mismatch is
    // record corruption the release must not paper over.
    if bond_floor_of(record_holdings_kind, record_held_shard_count) != record_bonded_total {
        return Err(UnbondConnectError::RecordFloorInvariantBroken);
    }
    if record_bad_interval_count >= MAX_BOND_BAD_INTERVALS {
        return Err(UnbondConnectError::IntervalLogFull);
    }
    let new_total_bonded_atomic = total_bonded_atomic
        .checked_sub(vin_bond_debit)
        .ok_or(UnbondConnectError::TotalBondedUnderflow)?;

    Ok(UnbondConnect {
        post_bonded_total: 0,
        post_holdings: HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::empty(),
        },
        interval_close: clean_interval_close(unbond_settlement_epoch),
        new_total_bonded_atomic,
        refund_atomic: vin_bond_debit,
    })
}

#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum UnbondPopError {
    /// The record is not in the `Unbond` post-connect state (`bonded_total`
    /// nonzero or holdings non-empty) — the journal row does not describe the
    /// tip's record; the pop would revert something else's write.
    #[error("record is not in the Unbond post-connect (Exited) state")]
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
    #[error("total_bonded_atomic overflow on Unbond pop re-credit")]
    TotalBondedOverflow,
}

/// Fold the `Unbond` pop twin (gate-4 §5): validate the tip record is the
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
/// ends at the `Unbond` connect — the slash scheduler only examines currently
/// held shards and an `Exited` record holds none, so nothing ever appends after
/// the clean close and the refund is never clawed back. (The release verify
/// guarantees every epoch through the last-served anchor settled *before* the
/// connect: `release_cooldown` module docs.) The trailing entry at pop is
/// therefore always this connect's clean close. `pop_block` still reverts
/// slashes before the bond journal — a defensive ordering belt, since a
/// same-block slash on a *different* record is routine — and any future change
/// that let an interval land after a clean close would surface here as
/// `MissingCleanClose`: loud, not silent.
pub fn unbond_pop(
    current_record_bonded_total: u64,
    current_record_held_shard_count: usize,
    trailing_interval: Option<BadInterval>,
    unbond_settlement_epoch: u64,
    journal_pre_bonded_total: u64,
    total_bonded_atomic: u64,
) -> Result<u64, UnbondPopError> {
    if current_record_bonded_total != 0 || current_record_held_shard_count != 0 {
        return Err(UnbondPopError::RecordNotExited);
    }
    match trailing_interval {
        Some(iv) if is_clean_interval_close(&iv, unbond_settlement_epoch) => {}
        _ => return Err(UnbondPopError::MissingCleanClose),
    }
    if journal_pre_bonded_total == 0 {
        return Err(UnbondPopError::PreImageEmpty);
    }
    total_bonded_atomic
        .checked_add(journal_pre_bonded_total)
        .ok_or(UnbondPopError::TotalBondedOverflow)
}

// ── HoldingsUpdate add / drop connect + pop (gate-4 §4.4 grace-tail) ─────────

#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum HoldingsUpdateConnectError {
    /// The post-holdings are not `current ∪ {one new shard}` (add) — verify's
    /// `HoldingsUpdateNotSingleAdd` should have rejected this.
    #[error("HoldingsUpdate-add post is not current holdings plus exactly one shard")]
    NotSingleAdd,
    /// The post-holdings are not `current ∖ {one shard}` (drop).
    #[error("HoldingsUpdate-drop post is not current holdings minus exactly one shard")]
    NotSingleDrop,
    /// Drop would empty the shard set — verify's `HoldingsUpdateDropLastShard`.
    #[error("HoldingsUpdate-drop would leave no shards (use Unbond)")]
    DropLastShard,
    /// The record's `bonded_total == bond_floor(holdings)` invariant (§3.2)
    /// does not hold — record corruption, not a tx fault.
    #[error("record bonded_total != bond_floor(record holdings)")]
    RecordFloorInvariantBroken,
    /// `bonded_total_atomic` / `total_bonded_atomic` would overflow (add) or
    /// underflow (drop) — the counter disagrees with the balance it aggregates.
    #[error("bonded/total_bonded counter over/underflow on HoldingsUpdate")]
    CounterRange,
    /// The record is not Bonded (zero collateral / no held shards) — verify's
    /// `HoldingsUpdateRecordNotBonded` is the admission decision (P2B-7 Pin 1:
    /// `Bonded → Bonded`); this is the connect-fold belt so a verify-bypassing
    /// caller cannot resurrect an Exited record through a voluntary adjustment.
    /// Without it the add's floor invariant passes vacuously on an emptied
    /// record (`bond_floor(∅) == 0 == bonded_total`).
    #[error("HoldingsUpdate on a record with no bonded collateral (Exited/emptied)")]
    RecordNotBonded,
}

/// The `HoldingsUpdate`-add connect effect (gate-4 §4.4). The C++ arm journals
/// the record's full pre-image, then sets `held_shard_ids = post` and rebuilds
/// the index-parallel `shard_add_epochs` — the carried-over shards keep their
/// existing add-epoch, and `added_shard_id` takes `add_settlement_epoch` (the
/// connecting block's settlement epoch, `E_add`). The counter movement is the
/// absolute post-value, threaded per post (the `UnbondConnect` note).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldingsUpdateAddConnect {
    pub added_shard_id: u64,
    pub add_settlement_epoch: u64,
    /// `record_bonded_total + FLOOR`.
    pub new_bonded_total: u64,
    /// `total_bonded_atomic + FLOOR` (absolute — thread per post).
    pub new_total_bonded_atomic: u64,
}

/// Fold the `HoldingsUpdate`-add connect: validate the single-shard growth and
/// the record's floor invariant, and produce the counter movement.
pub fn holdings_update_add_connect(
    record_bonded_total: u64,
    record_held_shard_ids: &[u64],
    post_held_shard_ids: &[u64],
    total_bonded_atomic: u64,
    add_settlement_epoch: u64,
) -> Result<HoldingsUpdateAddConnect, HoldingsUpdateConnectError> {
    let SingleDiff::Added(added_shard_id) =
        single_shard_diff(record_held_shard_ids, post_held_shard_ids)
    else {
        return Err(HoldingsUpdateConnectError::NotSingleAdd);
    };
    if record_bonded_total == 0 || record_held_shard_ids.is_empty() {
        return Err(HoldingsUpdateConnectError::RecordNotBonded);
    }
    if bond_floor_of(HoldingsKind::ShardSetCompact, record_held_shard_ids.len())
        != record_bonded_total
    {
        return Err(HoldingsUpdateConnectError::RecordFloorInvariantBroken);
    }
    let new_bonded_total = record_bonded_total
        .checked_add(ARCHIVAL_BOND_FLOOR_ATOMIC)
        .ok_or(HoldingsUpdateConnectError::CounterRange)?;
    let new_total_bonded_atomic = total_bonded_atomic
        .checked_add(ARCHIVAL_BOND_FLOOR_ATOMIC)
        .ok_or(HoldingsUpdateConnectError::CounterRange)?;
    Ok(HoldingsUpdateAddConnect {
        added_shard_id,
        add_settlement_epoch,
        new_bonded_total,
        new_total_bonded_atomic,
    })
}

/// The `HoldingsUpdate`-drop connect effect (gate-4 §4.4 grace-tail). The C++ arm
/// journals the pre-image, then sets `held_shard_ids = post` and rebuilds the
/// index-parallel `shard_add_epochs` (the dropped shard's add-epoch vanishes with
/// it). `refund_atomic == FLOOR` is the released collateral the `bond_debit`
/// source term returns to circulation (CT-balance-enforced on the wire; not
/// written by the connect — exposed so tests pin the §3.2 identity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldingsUpdateDropConnect {
    pub dropped_shard_id: u64,
    /// `record_bonded_total − FLOOR`.
    pub new_bonded_total: u64,
    /// `total_bonded_atomic − FLOOR` (absolute — thread per post).
    pub new_total_bonded_atomic: u64,
    pub refund_atomic: u64,
}

/// Fold the `HoldingsUpdate`-drop connect: validate the single-shard shrink,
/// drop-last rejection, and the record's floor invariant, and produce the
/// counter movement.
pub fn holdings_update_drop_connect(
    record_bonded_total: u64,
    record_held_shard_ids: &[u64],
    post_held_shard_ids: &[u64],
    total_bonded_atomic: u64,
) -> Result<HoldingsUpdateDropConnect, HoldingsUpdateConnectError> {
    let SingleDiff::Removed(dropped_shard_id) =
        single_shard_diff(record_held_shard_ids, post_held_shard_ids)
    else {
        return Err(HoldingsUpdateConnectError::NotSingleDrop);
    };
    if post_held_shard_ids.is_empty() {
        return Err(HoldingsUpdateConnectError::DropLastShard);
    }
    if bond_floor_of(HoldingsKind::ShardSetCompact, record_held_shard_ids.len())
        != record_bonded_total
    {
        return Err(HoldingsUpdateConnectError::RecordFloorInvariantBroken);
    }
    let new_bonded_total = record_bonded_total
        .checked_sub(ARCHIVAL_BOND_FLOOR_ATOMIC)
        .ok_or(HoldingsUpdateConnectError::CounterRange)?;
    let new_total_bonded_atomic = total_bonded_atomic
        .checked_sub(ARCHIVAL_BOND_FLOOR_ATOMIC)
        .ok_or(HoldingsUpdateConnectError::CounterRange)?;
    Ok(HoldingsUpdateDropConnect {
        dropped_shard_id,
        new_bonded_total,
        new_total_bonded_atomic,
        refund_atomic: ARCHIVAL_BOND_FLOOR_ATOMIC,
    })
}

#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum HoldingsUpdatePopError {
    /// The per-`P` balance changed by something other than one `FLOOR` between
    /// the journaled pre-image and the tip record — not a single-shard
    /// HoldingsUpdate, so the pop would revert the wrong movement.
    #[error("HoldingsUpdate pop delta is not a single FLOOR")]
    NotSingleShardDelta,
    /// Re-applying the counter delta would over/underflow.
    #[error("total_bonded_atomic over/underflow on HoldingsUpdate pop")]
    CounterRange,
}

/// Fold the `HoldingsUpdate` add/drop pop twin (gate-4 §5): the C++ arm restores
/// the record's fields from the pre-image journal byte-identically (held shards,
/// add-epochs, bonded_total, bad intervals); this fold reverts the global
/// `total_bonded_atomic` by exactly the connect's `±FLOOR` delta. The tip
/// record's `bonded_total` (the connect's post-value) and the journaled
/// pre-image balance must differ by exactly one `FLOOR` — a single-shard change
/// — or the journal does not describe a HoldingsUpdate at this height.
pub fn holdings_update_pop(
    current_record_bonded_total: u64,
    journal_pre_bonded_total: u64,
    total_bonded_atomic: u64,
) -> Result<u64, HoldingsUpdatePopError> {
    if current_record_bonded_total.abs_diff(journal_pre_bonded_total) != ARCHIVAL_BOND_FLOOR_ATOMIC
    {
        return Err(HoldingsUpdatePopError::NotSingleShardDelta);
    }
    // Revert the connect's counter movement: total += (pre − post). Branch on the
    // direction so neither intermediate step over/underflows.
    let restored = if journal_pre_bonded_total >= current_record_bonded_total {
        total_bonded_atomic.checked_add(journal_pre_bonded_total - current_record_bonded_total)
    } else {
        total_bonded_atomic.checked_sub(current_record_bonded_total - journal_pre_bonded_total)
    };
    restored.ok_or(HoldingsUpdatePopError::CounterRange)
}

#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum RebondConnectError {
    /// The post set is not a duplicate-free superset of the record's holdings —
    /// verify's `RebondNotSuperset`.
    #[error("Rebond post-holdings are not a duplicate-free superset of current")]
    NotSuperset,
    /// Empty post — verify's `ShardSetCompactEmpty` (reinstatement needs a position).
    #[error("Rebond post-holdings are empty")]
    EmptyPost,
    /// The post set exceeds the codec shard cap — the resulting record could
    /// never encode; verify's `RebondPostOversize` forecloses this at tx
    /// admission, this is the fold's belt for verify-bypassing callers.
    #[error("Rebond post-holdings exceed the codec shard cap")]
    PostOversize,
    /// The record's `bonded_total == bond_floor(holdings)` invariant (§3.2) does
    /// not hold — record corruption, not a tx fault.
    #[error("record bonded_total != bond_floor(record holdings)")]
    RecordFloorInvariantBroken,
    /// No open bad interval — the record is not slashed; verify's `RebondNotSlashed`.
    #[error("no open bad interval to close (record not slashed)")]
    NoOpenInterval,
    /// More than one open bad interval — corruption of the P2B-9 Pin 5 coalescing
    /// invariant (the loud multiplicity belt).
    #[error("multiple open bad intervals (coalescing invariant broken)")]
    MultipleOpenIntervals,
    /// `E_rebond + 1` does not lie strictly after the open interval's start — the
    /// slash would have to postdate the reinstatement (corruption).
    #[error("interval close E_rebond + 1 is not after the open interval's start")]
    IntervalOrdering,
    /// Counter/epoch arithmetic over/underflow.
    #[error("counter or epoch arithmetic out of range on Rebond")]
    CounterRange,
}

/// The `Rebond` connect effect (gate-4 §3.4; P2B-9). The C++ arm journals the
/// record's pre-image (bonded_total, held shards, add-epochs, the closed
/// interval's index + pre-image), then: sets `held_shard_ids = post` and rebuilds
/// the index-parallel `shard_add_epochs` — carried shards keep their add-epochs,
/// every `added_shard_ids` member takes `add_settlement_epoch` (`E_rebond`,
/// Pin 7) — and closes the open bad interval **in place**:
/// `bad_intervals[closed_interval_index].end_exclusive = interval_end_exclusive`
/// (`E_rebond + 1`, Pin 3 — standing resumes at `E_rebond + 1`; the partial rebond
/// epoch is forfeited in both directions). The counter movement is the absolute
/// post-value, threaded per post (the `UnbondConnect` note). No interval is
/// appended and none removed — post-connect `bad_intervals.len()` is unchanged,
/// which is what the verify-side `≤ 254` headroom (Pin 6) budgeted for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebondConnect {
    /// `post ∖ current` — each takes `add_settlement_epoch` as its add-epoch.
    pub added_shard_ids: Vec<u64>,
    /// `E_rebond` (the connecting block's settlement epoch).
    pub add_settlement_epoch: u64,
    /// Index into the record's `bad_intervals` of the one open interval to close.
    pub closed_interval_index: usize,
    /// `E_rebond + 1` — the value to write into the closed interval's
    /// `end_exclusive`.
    pub interval_end_exclusive: u64,
    /// `record_bonded_total + |added|·FLOOR` (`== bond_floor(post)`).
    pub new_bonded_total: u64,
    /// `total_bonded_atomic + |added|·FLOOR` (absolute — thread per post).
    pub new_total_bonded_atomic: u64,
}

/// Fold the `Rebond` connect: validate the superset re-spec, the record's floor
/// invariant, and the single open interval, and produce the interval close + the
/// counter movement.
pub fn rebond_connect(
    record_bonded_total: u64,
    record_held_shard_ids: &[u64],
    record_bad_intervals: &[BadInterval],
    post_held_shard_ids: &[u64],
    total_bonded_atomic: u64,
    rebond_settlement_epoch: u64,
) -> Result<RebondConnect, RebondConnectError> {
    if post_held_shard_ids.is_empty() {
        return Err(RebondConnectError::EmptyPost);
    }
    // Codec-cap belt (verify's RebondPostOversize twin): a post past the cap
    // would fold into a record ArchivalBondValue::encode refuses — fail typed
    // and loud here instead of as an opaque encode throw in the LMDB writer.
    if post_held_shard_ids.len() > MAX_HOLDINGS_SHARDS {
        return Err(RebondConnectError::PostOversize);
    }
    let Some(added_shard_ids) = superset_added_diff(record_held_shard_ids, post_held_shard_ids)
    else {
        return Err(RebondConnectError::NotSuperset);
    };
    if bond_floor_of(HoldingsKind::ShardSetCompact, record_held_shard_ids.len())
        != record_bonded_total
    {
        return Err(RebondConnectError::RecordFloorInvariantBroken);
    }
    let mut open_indices = record_bad_intervals
        .iter()
        .enumerate()
        .filter(|(_, iv)| iv.end_exclusive == u64::MAX)
        .map(|(i, _)| i);
    let Some(closed_interval_index) = open_indices.next() else {
        return Err(RebondConnectError::NoOpenInterval);
    };
    if open_indices.next().is_some() {
        return Err(RebondConnectError::MultipleOpenIntervals);
    }
    let interval_end_exclusive = rebond_settlement_epoch
        .checked_add(1)
        .ok_or(RebondConnectError::CounterRange)?;
    // The slash that opened the interval predates the reinstatement, so the close
    // must land strictly after the open's start — anything else is corruption.
    if interval_end_exclusive <= record_bad_intervals[closed_interval_index].start_epoch {
        return Err(RebondConnectError::IntervalOrdering);
    }
    let credit = (added_shard_ids.len() as u64)
        .checked_mul(ARCHIVAL_BOND_FLOOR_ATOMIC)
        .ok_or(RebondConnectError::CounterRange)?;
    let new_bonded_total = record_bonded_total
        .checked_add(credit)
        .ok_or(RebondConnectError::CounterRange)?;
    let new_total_bonded_atomic = total_bonded_atomic
        .checked_add(credit)
        .ok_or(RebondConnectError::CounterRange)?;
    Ok(RebondConnect {
        added_shard_ids,
        add_settlement_epoch: rebond_settlement_epoch,
        closed_interval_index,
        interval_end_exclusive,
        new_bonded_total,
        new_total_bonded_atomic,
    })
}

#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum RebondPopError {
    /// The per-`P` balance moved by something other than a non-negative whole
    /// number of `FLOOR`s between the journaled pre-image and the tip record —
    /// the journal does not describe a `Rebond` at this height.
    #[error("Rebond pop delta is not a non-negative whole number of FLOORs")]
    NotRebondDelta,
    /// Re-applying the counter delta would underflow.
    #[error("total_bonded_atomic underflow on Rebond pop")]
    CounterRange,
}

/// Fold the `Rebond` pop twin (gate-4 §5): the C++ arm restores the record's
/// fields from the pre-image journal byte-identically (held shards, add-epochs,
/// bonded_total, and the closed interval re-opened to `end_exclusive = MAX`);
/// this fold reverts the global `total_bonded_atomic` by the connect's
/// `|added|·FLOOR` credit. A `Rebond` only grows the balance, so the tip record's
/// `bonded_total` must exceed the journaled pre-image by a non-negative whole
/// number of `FLOOR`s — **zero included** (the common standing-only
/// reinstatement moves no collateral).
pub fn rebond_pop(
    current_record_bonded_total: u64,
    journal_pre_bonded_total: u64,
    total_bonded_atomic: u64,
) -> Result<u64, RebondPopError> {
    let Some(delta) = current_record_bonded_total.checked_sub(journal_pre_bonded_total) else {
        return Err(RebondPopError::NotRebondDelta);
    };
    if delta % ARCHIVAL_BOND_FLOOR_ATOMIC != 0 {
        return Err(RebondPopError::NotRebondDelta);
    }
    total_bonded_atomic
        .checked_sub(delta)
        .ok_or(RebondPopError::CounterRange)
}

#[cfg(test)]
#[path = "bond_connect_tests.rs"]
mod tests;
