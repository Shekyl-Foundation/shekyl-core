// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! JoinMarket bond-post semantic verify (gate-4 §3.2–3.5).
//!
//! Structural bounds (hybrid pubkey length) and `P_canonical_id` hint checks stay
//! in C++ consensus glue; this module covers post-kind, holdings, term rigidity,
//! floor equality, and record-existence (via `record_exists` from LMDB).

use thiserror::Error;

use crate::bond_floor::{bond_floor, bond_floor_of};
use crate::bond_wire::{ArchivalBondPostVin, BondPostKind, HoldingsKind};
use crate::distinct::all_distinct;
use crate::release_cooldown::{release_cooldown_elapsed, slashes_settled_through};

#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum BondPostError {
    #[error("post_kind is not JoinMarket at genesis")]
    PostKindNotJoinMarket,
    #[error("ShardSetCompact requires at least one shard")]
    ShardSetCompactEmpty,
    #[error("CompleteTree must not carry shard ids")]
    CompleteTreeWithShardIds,
    #[error("JoinMarket bond-post must not carry bond_debit")]
    BondDebitNonzero,
    #[error("bond_credit and bond_debit are both non-zero")]
    BothTermsNonzero,
    #[error("bond_floor(holdings) is zero")]
    BondFloorZero,
    #[error("bonded_total_atomic and bond_credit must equal bond_floor")]
    FloorMismatch,
    #[error("bond record already exists for P_canonical_id")]
    RecordExists,
    #[error("post_kind is not Unbond")]
    PostKindNotUnbond,
    #[error("Unbond requires an existing bond record")]
    RecordMissing,
    #[error("Unbond on a record with zero bonded total (nothing to unbond)")]
    NothingToUnbond,
    #[error("Unbond bond-post must not carry bond_credit")]
    UnbondCreditNonzero,
    #[error("Unbond full-exit holdings must be empty, not a floor-zero shard set")]
    UnbondHoldingsNotEmpty,
    #[error("post-connect bonded_total_atomic must equal bond_floor(holdings)")]
    UnbondFloorMismatch,
    #[error("Unbond is a full exit: post-connect bonded_total_atomic must be zero")]
    NotFullUnbond,
    #[error("Unbond bond_debit must equal the record's current bonded_total")]
    DebitNotFullBalance,
    #[error("Unbond release cooldown has not elapsed")]
    CooldownNotElapsed,
    #[error("record interval log is full; the connect's clean interval-close cannot append")]
    IntervalLogFull,
    #[error("slash scheduler has not settled every epoch through the last-served anchor")]
    SlashSettlementPending,
    // ── HoldingsUpdate (add + drop; gate-4 §4.4, P2B-7) ──────────────────────
    #[error("post_kind is not HoldingsUpdate")]
    PostKindNotHoldingsUpdate,
    #[error("HoldingsUpdate is only valid on a ShardSetCompact record (not CompleteTree)")]
    HoldingsUpdateOnCompleteTree,
    #[error("HoldingsUpdate post-holdings must be ShardSetCompact")]
    HoldingsUpdatePostNotCompact,
    #[error("HoldingsUpdate-add requires bond_credit == FLOOR and bond_debit == 0")]
    HoldingsUpdateAddTerms,
    #[error("HoldingsUpdate-add requires the record in good standing (no open bad interval)")]
    HoldingsUpdateNotGoodStanding,
    #[error(
        "HoldingsUpdate-add post-holdings must be current holdings plus exactly one new shard"
    )]
    HoldingsUpdateNotSingleAdd,
    #[error("HoldingsUpdate-add post bonded_total must equal bond_floor(post-holdings)")]
    HoldingsUpdateAddFloorMismatch,
    #[error("HoldingsUpdate-drop requires bond_debit == FLOOR and bond_credit == 0")]
    HoldingsUpdateDropTerms,
    #[error("HoldingsUpdate-drop post-holdings must be current holdings minus exactly one shard")]
    HoldingsUpdateNotSingleDrop,
    #[error("HoldingsUpdate-drop must leave at least one shard (use Unbond for a full exit)")]
    HoldingsUpdateDropLastShard,
    #[error("HoldingsUpdate-drop post bonded_total must equal bond_floor(post-holdings)")]
    HoldingsUpdateDropFloorMismatch,
    #[error("HoldingsUpdate-drop shard is within its bond_duration retention horizon")]
    HoldingsUpdateDropWithinHorizon,
    #[error(
        "HoldingsUpdate requires a Bonded record (bonded collateral and at least one \
         held shard); an Exited or slash-emptied record re-enters via JoinMarket/Rebond"
    )]
    HoldingsUpdateRecordNotBonded,
    #[error("post_kind is not Rebond")]
    PostKindNotRebond,
    #[error("Rebond is only valid on a ShardSetCompact record (not CompleteTree)")]
    RebondOnCompleteTree,
    #[error("Rebond post-holdings must be ShardSetCompact")]
    RebondPostNotCompact,
    #[error("Rebond requires an open bad interval (the record is not slashed)")]
    RebondNotSlashed,
    #[error(
        "record carries more than one open bad interval — record corruption (the \
         same-epoch slash coalescing invariant, P2B-9 Pin 5, guarantees at most one)"
    )]
    RebondMultipleOpenIntervals,
    #[error(
        "record interval log lacks Rebond headroom (> 254 entries): re-arming \
         slashability must leave one slot for the next slash and one for the Unbond \
         clean close, so exit stays reachable"
    )]
    RebondIntervalLogHeadroom,
    #[error(
        "Rebond terms mismatch: bond_debit must be 0 and bond_credit must equal \
         bond_floor(post) − record bonded_total (zero for standing-only reinstatement)"
    )]
    RebondTerms,
    #[error(
        "Rebond post-holdings must be a duplicate-free superset of the record's \
         current holdings (reinstatement, not restructuring — shedding is \
         HoldingsUpdate-drop's gated job)"
    )]
    RebondNotSuperset,
    #[error(
        "record bonded_total != bond_floor(record holdings) — record corruption; \
         rejected at verify so a verify-valid tx can never meet the connect \
         fold's loud floor belt (tx rejection, not a chain halt)"
    )]
    RebondRecordFloorBroken,
}

/// The single-shard set difference `post ∖ current` when `post` grows `current` by
/// exactly one shard (`HoldingsUpdate`-add), or the reverse for a drop. Both
/// holdings are treated as **sets** (order-agnostic); the vin's `post` is validated
/// to carry no duplicate shard ids (the record's `current` is trusted).
///
/// Returns the single added/removed shard id, or `None` when the difference is not
/// exactly one shard in the requested direction (wrong cardinality, a duplicate in
/// `post`, or a shard changed on both sides).
pub(crate) enum SingleDiff {
    /// `post = current ∪ {shard}`, `shard ∉ current`, `|post| = |current| + 1`.
    Added(u64),
    /// `post = current ∖ {shard}`, `shard ∈ current`, `|post| = |current| − 1`.
    Removed(u64),
    /// Not a single-shard change in either direction.
    NotSingle,
}

pub(crate) fn single_shard_diff(current: &[u64], post: &[u64]) -> SingleDiff {
    // Reject a `post` carrying a duplicate shard id (a set on the wire).
    let mut post_sorted = post.to_vec();
    post_sorted.sort_unstable();
    if post_sorted.windows(2).any(|w| w[0] == w[1]) {
        return SingleDiff::NotSingle;
    }
    let mut cur_sorted = current.to_vec();
    cur_sorted.sort_unstable();

    // Both vectors are sorted, so membership is a `binary_search` — the diff is
    // O(n log n), not the O(n²) a linear `contains` per element would cost on
    // holdings that can reach the codec cap.
    let added: Vec<u64> = post_sorted
        .iter()
        .copied()
        .filter(|s| cur_sorted.binary_search(s).is_err())
        .collect();
    let removed: Vec<u64> = cur_sorted
        .iter()
        .copied()
        .filter(|s| post_sorted.binary_search(s).is_err())
        .collect();

    match (
        post_sorted.len().cmp(&cur_sorted.len()),
        added.as_slice(),
        removed.as_slice(),
    ) {
        (std::cmp::Ordering::Greater, [s], []) if post_sorted.len() == cur_sorted.len() + 1 => {
            SingleDiff::Added(*s)
        }
        (std::cmp::Ordering::Less, [], [s]) if post_sorted.len() + 1 == cur_sorted.len() => {
            SingleDiff::Removed(*s)
        }
        _ => SingleDiff::NotSingle,
    }
}

/// Shared `HoldingsUpdate` admission prologue, both directions (the add and drop
/// verifies below): post-kind pin, record existence, the ShardSetCompact pins on
/// record and post, and the **Bonded-state gate** (P2B-7 Pin 1: `HoldingsUpdate`
/// is `Bonded → Bonded`). Returns the record's current `bonded_total` for the
/// direction-specific arithmetic.
///
/// The Bonded gate is load-bearing, not a belt: without it an **Exited** record
/// (post-`Unbond`: zero total, empty holdings, zero-length clean close — which
/// `good_through` excludes nothing for) passes every add gate and becomes a
/// JoinMarket-bypassing resurrection path whose connect then throws on the
/// empty-pre-image journal encode — a verify-valid tx no block can connect
/// (chain-stall vector). Re-entry after an exit or a full slash is
/// `JoinMarket`/`Rebond`, never a voluntary adjustment.
fn holdings_update_prologue(
    vin: &ArchivalBondPostVin,
    record_bonded_total: Option<u64>,
    record_holdings_kind: HoldingsKind,
    record_held_shard_ids: &[u64],
) -> Result<u64, BondPostError> {
    if vin.post_kind != BondPostKind::HoldingsUpdate {
        return Err(BondPostError::PostKindNotHoldingsUpdate);
    }
    let Some(current_bonded) = record_bonded_total else {
        return Err(BondPostError::RecordMissing);
    };
    // HoldingsUpdate operates on a shard set; a foundation CompleteTree record
    // has no shard list to adjust.
    if record_holdings_kind != HoldingsKind::ShardSetCompact {
        return Err(BondPostError::HoldingsUpdateOnCompleteTree);
    }
    if vin.holdings.kind != HoldingsKind::ShardSetCompact {
        return Err(BondPostError::HoldingsUpdatePostNotCompact);
    }
    if current_bonded == 0 || record_held_shard_ids.is_empty() {
        return Err(BondPostError::HoldingsUpdateRecordNotBonded);
    }
    Ok(current_bonded)
}

/// Verify `HoldingsUpdate`-**add** bond-post semantics — voluntary growth of a
/// `Bonded` record by exactly one shard (gate-4 §4.4; `PHASE_2B_FSM_RETOOL.md`
/// P2B-7 Pin 1/5, Q4). Credit path (`bond_debit == 0`), so the pqc auth is the
/// identity key (the GF-1 selector routes credit → `P_pubkey`).
///
/// Marshaled facts (C++ reads, Rust decides): `record_bonded_total` is `None` when
/// no record exists; `record_held_shard_ids` is the record's **current** holdings
/// (needed for the single-shard diff — the vin carries the **post**-connect set per
/// the §3.5 debit-path pin, which applies uniformly to every `post_kind`);
/// `record_join_settlement_epoch` and `record_bad_intervals` feed the good-standing
/// gate (Q4: add is voluntary growth requiring `good_standing == true`, i.e.
/// `good_through` at the current epoch — no open bad interval).
///
/// The added shard is **not** required to be a frozen segment here: adding a shard
/// that never freezes locks `FLOOR` and earns nothing (the reward/challenge channel
/// is serve-credit-bit-driven, never descriptor-driven), so it is self-harm, not an
/// attack, and gating it would couple bond-post verify to the segment registry.
pub fn verify_holdings_update_add(
    vin: &ArchivalBondPostVin,
    record_bonded_total: Option<u64>,
    record_holdings_kind: HoldingsKind,
    record_held_shard_ids: &[u64],
    record_join_settlement_epoch: u64,
    record_bad_intervals: &[crate::consensus_state::BadInterval],
    current_settlement_epoch: u64,
) -> Result<(), BondPostError> {
    let current_bonded = holdings_update_prologue(
        vin,
        record_bonded_total,
        record_holdings_kind,
        record_held_shard_ids,
    )?;
    // Credit direction (§3.2 term table): exactly `+FLOOR`, no debit.
    if vin.bond_debit != 0 || vin.bond_credit != crate::bond_floor::ARCHIVAL_BOND_FLOOR_ATOMIC {
        return Err(BondPostError::HoldingsUpdateAddTerms);
    }
    // Good standing (Q4): voluntary growth requires the record be good_through the
    // current epoch — an open bad interval (post-slash, pre-Rebond) forecloses add.
    if !crate::consensus_state::good_through(
        record_join_settlement_epoch,
        current_settlement_epoch,
        record_bad_intervals,
    ) {
        return Err(BondPostError::HoldingsUpdateNotGoodStanding);
    }
    // Exactly one shard added; the post is `current ∪ {new}` (set semantics).
    match single_shard_diff(record_held_shard_ids, &vin.holdings.shard_ids) {
        SingleDiff::Added(_) => {}
        _ => return Err(BondPostError::HoldingsUpdateNotSingleAdd),
    }
    // Floor equality on the post-state: bonded_total == bond_floor(post) ==
    // (|current| + 1)·FLOOR. `bond_credit == FLOOR` (checked above) is the
    // single-shard increment; this pins the resulting total.
    let post_floor = bond_floor(&vin.holdings);
    if vin.bonded_total_atomic != post_floor
        || vin.bonded_total_atomic
            != current_bonded.saturating_add(crate::bond_floor::ARCHIVAL_BOND_FLOOR_ATOMIC)
    {
        return Err(BondPostError::HoldingsUpdateAddFloorMismatch);
    }
    Ok(())
}

/// Verify `HoldingsUpdate`-**drop** bond-post semantics — voluntary removal of exactly
/// one shard from a `Bonded` record (gate-4 §4.4 grace-tail; `PHASE_2B_FSM_RETOOL.md`
/// P2B-7 Pin 1/2/3). Debit path (`bond_debit == FLOOR`), so the pqc auth is the
/// record's committed `bond_spend_pk` (the GF-1 selector routes debit → the committed
/// key; enforced C++-side, as for `Unbond`).
///
/// **Grace-tail model (ratified 2026-07-15):** the drop is a precondition-gated shrink,
/// not a drop-then-cool. The dropped shard's release cooldown must have elapsed
/// ([`release_cooldown_elapsed`] on its per-shard last-served anchor) and the slash
/// scheduler must have settled through that anchor ([`slashes_settled_through`]) — the
/// same two predicates the `Unbond` release uses, applied to the one dropped shard.
/// The shard is additionally gated by the retention horizon
/// ([`bond_duration`](crate::bond_duration::bond_duration) of
/// [`ShardAgeAtAdd`](crate::bond_duration::ShardAgeAtAdd)): it is ineligible for
/// voluntary drop until `current_epoch − add_epoch ≥ bond_duration`. At connect the
/// shard leaves `holdings` and the `FLOOR` returns via the `bond_debit` source term —
/// no cooldown sub-state, no interval, no clean-close marker (`P` stays `Bonded`).
///
/// The per-shard facts (`add_epoch`, `freeze_height`, `last_served`) are for the shard
/// C++ identified by set-difference; this verify recomputes the diff and cross-checks
/// that `dropped_shard_id` is exactly the one it removed, so the passed facts cannot be
/// mis-associated (the exactly-one-dropped **rule** is decided here, not in C++).
#[allow(clippy::too_many_arguments)]
pub fn verify_holdings_update_drop(
    vin: &ArchivalBondPostVin,
    record_bonded_total: Option<u64>,
    record_holdings_kind: HoldingsKind,
    record_held_shard_ids: &[u64],
    dropped_shard_id: u64,
    dropped_shard_add_epoch: u64,
    dropped_shard_freeze_height: u64,
    dropped_shard_last_served: Option<u64>,
    last_settled_slash_epoch: Option<u64>,
    current_settlement_epoch: u64,
) -> Result<(), BondPostError> {
    let current_bonded = holdings_update_prologue(
        vin,
        record_bonded_total,
        record_holdings_kind,
        record_held_shard_ids,
    )?;
    // Debit direction (§3.2 term table): exactly `−FLOOR`, no credit.
    if vin.bond_credit != 0 || vin.bond_debit != crate::bond_floor::ARCHIVAL_BOND_FLOOR_ATOMIC {
        return Err(BondPostError::HoldingsUpdateDropTerms);
    }
    // Exactly one shard removed, and it is the shard C++ read facts for.
    match single_shard_diff(record_held_shard_ids, &vin.holdings.shard_ids) {
        SingleDiff::Removed(s) if s == dropped_shard_id => {}
        _ => return Err(BondPostError::HoldingsUpdateNotSingleDrop),
    }
    // Drop-last-shard rejected: a full exit is `Unbond` (→ `Exited`), not a drop
    // that would leave an empty ShardSetCompact (P2B-7 Pin 1).
    if vin.holdings.shard_ids.is_empty() {
        return Err(BondPostError::HoldingsUpdateDropLastShard);
    }
    // Floor equality on the post-state: bonded_total == bond_floor(post) ==
    // (|current| − 1)·FLOOR.
    let post_floor = bond_floor(&vin.holdings);
    if vin.bonded_total_atomic != post_floor
        || vin
            .bonded_total_atomic
            .saturating_add(crate::bond_floor::ARCHIVAL_BOND_FLOOR_ATOMIC)
            != current_bonded
    {
        return Err(BondPostError::HoldingsUpdateDropFloorMismatch);
    }
    // Retention horizon (gate-4 §4.4 / P2B-7 Pin 3): the shard is ineligible for
    // voluntary drop until `current_epoch − add_epoch ≥ bond_duration(age@add)`.
    // A `current < add_epoch` is record corruption (add cannot be in the future);
    // treat it as within-horizon (fail-closed, hardest to drop).
    let horizon =
        crate::bond_duration::bond_duration(crate::bond_duration::ShardAgeAtAdd::from_add(
            dropped_shard_add_epoch,
            dropped_shard_freeze_height,
        ));
    match current_settlement_epoch.checked_sub(dropped_shard_add_epoch) {
        Some(tenure) if tenure >= horizon => {}
        _ => return Err(BondPostError::HoldingsUpdateDropWithinHorizon),
    }
    // Per-shard release cooldown (grace-tail precondition) on the dropped shard's
    // last-served anchor, plus slash-settlement through it — the same guarantee as
    // `Unbond`, scoped to the one shard: no pending challenge can still slash it.
    if !release_cooldown_elapsed(dropped_shard_last_served, current_settlement_epoch) {
        return Err(BondPostError::CooldownNotElapsed);
    }
    if !slashes_settled_through(last_settled_slash_epoch, dropped_shard_last_served) {
        return Err(BondPostError::SlashSettlementPending);
    }
    Ok(())
}

/// The added-set difference for a `Rebond` re-specification: `post ∖ current` when
/// `post` is a duplicate-free **superset** of `current` (set semantics; the record's
/// `current` is trusted, the vin's `post` is validated). Returns `None` when `post`
/// carries a duplicate or misses any current shard — the reinstatement-not-
/// restructuring shape (P2B-9 Pin 1: the superset closes shedding of the *carried*
/// shards; the slashed shard is already absent from `current`, its abandonment
/// priced by the burn, not prevented).
pub(crate) fn superset_added_diff(current: &[u64], post: &[u64]) -> Option<Vec<u64>> {
    let mut post_sorted = post.to_vec();
    post_sorted.sort_unstable();
    if post_sorted.windows(2).any(|w| w[0] == w[1]) {
        return None;
    }
    if !current.iter().all(|s| post_sorted.binary_search(s).is_ok()) {
        return None;
    }
    let mut cur_sorted = current.to_vec();
    cur_sorted.sort_unstable();
    Some(
        post_sorted
            .iter()
            .copied()
            .filter(|s| cur_sorted.binary_search(s).is_err())
            .collect(),
    )
}

/// Verify `Rebond` bond-post semantics — post-slash reinstatement of a record with
/// an open bad interval (gate-4 §3.4; P2B-9, ratified 2026-07-14). Credit path
/// (`bond_debit == 0`), so the pqc auth is the identity key `P_pubkey` (the GF-1
/// selector routes credit → identity; enforced C++-side — P2B-9 Pin 4).
///
/// **Reinstatement, not re-entry:** the record resumes in place — same
/// `P_canonical_id`, same carried shards and add-epochs, same backlog. The
/// precondition is *an open bad interval exists* (`good_standing == false`, both
/// slash severities — partial and terminal); an `Exited` record is excluded
/// structurally (its clean interval-close is zero-length, never open). The
/// re-specified holdings must be a non-empty duplicate-free **superset** of the
/// record's current holdings (Pin 1 — shedding stays `HoldingsUpdate`-drop's gated
/// job), and the credit is owed only for growth:
/// `bond_credit == bond_floor(post) − record.bonded_total == |added|·FLOOR`, **zero
/// for the common standing-only reinstatement** (Pin 2 — the landed slash burns one
/// `FLOOR` and removes the shard atomically, so no deficit exists). The interval
/// log must leave headroom (`≤ 254` entries, Pin 6): re-arming slashability must
/// keep one slot for the next slash and one for the `Unbond` clean close, so exit
/// is always reachable. Exactly one open interval may exist (Pin 5's coalescing
/// invariant); more is record corruption, rejected here so a verify-valid tx can
/// never meet the connect fold's loud multiplicity belt.
pub fn verify_rebond_bond_post(
    vin: &ArchivalBondPostVin,
    record_bonded_total: Option<u64>,
    record_holdings_kind: HoldingsKind,
    record_held_shard_ids: &[u64],
    record_bad_intervals: &[crate::consensus_state::BadInterval],
) -> Result<(), BondPostError> {
    if vin.post_kind != BondPostKind::Rebond {
        return Err(BondPostError::PostKindNotRebond);
    }
    let Some(current_bonded) = record_bonded_total else {
        return Err(BondPostError::RecordMissing);
    };
    // A CompleteTree record with an open bad interval is unrepresentable (the
    // demotion flips the kind atomically with the interval append) — belt anyway.
    if record_holdings_kind != HoldingsKind::ShardSetCompact {
        return Err(BondPostError::RebondOnCompleteTree);
    }
    if vin.holdings.kind != HoldingsKind::ShardSetCompact {
        return Err(BondPostError::RebondPostNotCompact);
    }
    // Reinstatement needs a position to reinstate into; `∅` is a zombie (good
    // standing, no shards, no balance — HU-add and Unbond both reject it).
    if vin.holdings.shard_ids.is_empty() {
        return Err(BondPostError::ShardSetCompactEmpty);
    }
    // (No oversize guard here: `vin.holdings.shard_ids` is a `ShardSet`, bounded
    // at construction, so an oversize post is unrepresentable by the time verify
    // runs — the former `RebondPostOversize` belt was retired with the newtype.
    // The raw-slice connect path re-guards it in `rebond_connect`'s `PostOversize`.)
    // Precondition: exactly one open bad interval (Pin 5's coalescing invariant).
    let open_count = record_bad_intervals
        .iter()
        .filter(|iv| iv.end_exclusive == u64::MAX)
        .count();
    if open_count == 0 {
        return Err(BondPostError::RebondNotSlashed);
    }
    if open_count > 1 {
        return Err(BondPostError::RebondMultipleOpenIntervals);
    }
    // Pin 6 headroom: one slot reserved for the next slash + one for the Unbond
    // clean close (the close below is in-place, so post-Rebond size == size).
    if record_bad_intervals.len() > crate::bond_connect::MAX_BOND_BAD_INTERVALS - 2 {
        return Err(BondPostError::RebondIntervalLogHeadroom);
    }
    // Pin 1: duplicate-free superset of the current holdings. (The added-set
    // itself is the CONNECT fold's operand — verify only needs the shape.)
    if superset_added_diff(record_held_shard_ids, &vin.holdings.shard_ids).is_none() {
        return Err(BondPostError::RebondNotSuperset);
    }
    // §3.2 record floor invariant, checked HERE against the marshaled record
    // facts — not deferred to the connect fold's RecordFloorInvariantBroken
    // belt: a floor-drifted record would otherwise let this tx verify (its
    // terms are computed FROM the drifted total) and then FATAL-abort every
    // node at block connect. Verify rejects the tx; the fold's belt stays for
    // verify-bypassing callers (the multiplicity check's posture, one check up).
    if bond_floor_of(record_holdings_kind, record_held_shard_ids.len()) != current_bonded {
        return Err(BondPostError::RebondRecordFloorBroken);
    }
    // Pin 2 terms (§3.2): no debit; credit == bond_floor(post) − current bonded
    // (== |added|·FLOOR under the record floor invariant, checked just above;
    // zero legal); post-state floor equality. `checked_sub` fails closed on
    // a record whose bonded exceeds the post floor (corruption — the superset
    // makes an honest shrink unrepresentable).
    if vin.bond_debit != 0 {
        return Err(BondPostError::RebondTerms);
    }
    let post_floor = bond_floor(&vin.holdings);
    let Some(expected_credit) = post_floor.checked_sub(current_bonded) else {
        return Err(BondPostError::RebondTerms);
    };
    if vin.bond_credit != expected_credit || vin.bonded_total_atomic != post_floor {
        return Err(BondPostError::RebondTerms);
    }
    Ok(())
}

/// Verify JoinMarket bond-post semantics after wire decode and LMDB substrate read.
///
/// `record_exists` is `true` when `get_archival_bond_hybrid_pubkey` would succeed.
pub fn verify_join_market_bond_post(
    vin: &ArchivalBondPostVin,
    record_exists: bool,
) -> Result<(), BondPostError> {
    if vin.post_kind != BondPostKind::JoinMarket {
        return Err(BondPostError::PostKindNotJoinMarket);
    }

    match vin.holdings.kind {
        HoldingsKind::ShardSetCompact if vin.holdings.shard_ids.is_empty() => {
            return Err(BondPostError::ShardSetCompactEmpty);
        }
        HoldingsKind::CompleteTree if !vin.holdings.shard_ids.is_empty() => {
            return Err(BondPostError::CompleteTreeWithShardIds);
        }
        _ => {}
    }

    if vin.bond_credit > 0 && vin.bond_debit > 0 {
        return Err(BondPostError::BothTermsNonzero);
    }
    if vin.bond_debit != 0 {
        return Err(BondPostError::BondDebitNonzero);
    }

    let floor = bond_floor(&vin.holdings);
    if floor == 0 {
        return Err(BondPostError::BondFloorZero);
    }
    if vin.bonded_total_atomic != floor || vin.bond_credit != floor {
        return Err(BondPostError::FloorMismatch);
    }

    if record_exists {
        return Err(BondPostError::RecordExists);
    }

    Ok(())
}

/// Verify `Unbond` bond-post semantics — a full record release (gate-4 §3.2/§3.4/
/// §3.5/§4.3; `PHASE_2B_FSM_RETOOL.md` P2B-8).
///
/// Marshaled facts from LMDB (C++ reads, Rust decides — same split as
/// [`verify_join_market_bond_post`]): `record_bonded_total` is `None` when no bond
/// record exists for `P_canonical_id`; `last_served_epoch` is the derived
/// whole-record release-cooldown anchor
/// ([`crate::release_cooldown::whole_record_last_served`] over the per-shard
/// reverse-cursor maxima — for a `CompleteTree` record the maxima come from the
/// all-shards `P`-prefix scan, since the record stores no shard list), read at
/// `current_settlement_epoch`; `last_settled_slash_epoch` is the slash scheduler's
/// monotone watermark (`None` before any epoch settles).
///
/// The vin's `holdings` / `bonded_total_atomic` are the **post-connect** state
/// (gate-4 §3.5 debit-path note, ratified P2B-8): a full `Unbond` ends at empty
/// holdings, so `bonded_total_atomic == 0 == bond_floor(∅)`, and the debit removes
/// the whole current balance. The `bonded_total_atomic != 0` case is a partial
/// unbond and belongs on the `HoldingsUpdate`-drop path, not here.
///
/// `record_bad_interval_count` is the record's interval-log length; verify
/// rejects a log at [`MAX_BOND_BAD_INTERVALS`](crate::bond_connect::MAX_BOND_BAD_INTERVALS)
/// because the connect's clean interval-close could not append — a tx that
/// verifies but cannot connect would be a deterministic halt, so verify and
/// connect enforce the same bound.
pub fn verify_unbond_bond_post(
    vin: &ArchivalBondPostVin,
    record_bonded_total: Option<u64>,
    record_bad_interval_count: usize,
    last_served_epoch: Option<u64>,
    last_settled_slash_epoch: Option<u64>,
    current_settlement_epoch: u64,
) -> Result<(), BondPostError> {
    if vin.post_kind != BondPostKind::Unbond {
        return Err(BondPostError::PostKindNotUnbond);
    }

    let Some(current_bonded) = record_bonded_total else {
        return Err(BondPostError::RecordMissing);
    };
    if current_bonded == 0 {
        return Err(BondPostError::NothingToUnbond);
    }

    if vin.bond_credit != 0 {
        return Err(BondPostError::UnbondCreditNonzero);
    }

    // Step-4 floor equality on the vin's post-connect state (§3.5 debit-path note).
    let floor = bond_floor(&vin.holdings);
    // A full Unbond ends at the canonical empty holdings, whose floor is 0. But
    // `bond_floor` also returns 0 for a structurally-invalid (oversize) shard set,
    // so a floor-0 descriptor that still carries shards is not an exit — reject it
    // rather than let it masquerade as empty. (Join rejects floor-0 outright as
    // `BondFloorZero`; Unbond cannot, because the empty end-state is legitimately
    // floor 0, so it guards the non-empty case explicitly.)
    if floor == 0 && !vin.holdings.shard_ids.is_empty() {
        return Err(BondPostError::UnbondHoldingsNotEmpty);
    }
    if vin.bonded_total_atomic != floor {
        return Err(BondPostError::UnbondFloorMismatch);
    }
    // Full exit: post-connect total is zero (⇒ empty holdings, by floor equality).
    if vin.bonded_total_atomic != 0 {
        return Err(BondPostError::NotFullUnbond);
    }

    // The debit removes the whole current balance (§3.2 table; §4.3 refund).
    if vin.bond_debit != current_bonded {
        return Err(BondPostError::DebitNotFullBalance);
    }

    // The connect must append the clean interval-close (§4.3 F3); a full log
    // (`bond_connect::MAX_BOND_BAD_INTERVALS`, the codec's `kMaxBadIntervals`
    // pin) makes the tx unconnectable, so it is unverifiable too.
    if record_bad_interval_count >= crate::bond_connect::MAX_BOND_BAD_INTERVALS {
        return Err(BondPostError::IntervalLogFull);
    }

    // Release cooldown: the grace window past the last served epoch must have
    // elapsed (gate-4 §4.3; the Gate-6 F-D3/F-D4 gate).
    if !release_cooldown_elapsed(last_served_epoch, current_settlement_epoch) {
        return Err(BondPostError::CooldownNotElapsed);
    }

    // Slash settlement: the scheduler's watermark must have reached the anchor,
    // so every epoch up to the last serve has been slash-processed on bonded
    // collateral before the release verifies. The cooldown alone leaves a
    // one-block connect-ordering race open (`release_cooldown` module docs).
    // Together the two checks pin the ratified guarantee (2026-07-12): epochs
    // through the anchor are settled; the unserved exit tail is forgiven;
    // slashability ends at the Unbond connect — the refund is never clawed back.
    if !slashes_settled_through(last_settled_slash_epoch, last_served_epoch) {
        return Err(BondPostError::SlashSettlementPending);
    }

    Ok(())
}

/// Block-level intra-block cross-tx bond-post uniqueness — at most **one**
/// bond-post vin per `P_canonical_id` per block (gate-4 §3.5; the emission
/// `(P, E)` pass's sibling,
/// [`emission_block_claims_unique`](crate::claimed_epochs::emission_block_claims_unique)).
///
/// Per-tx verify runs against pre-block DB state, so every same-`P` same-block
/// pair — JoinMarket+JoinMarket (double `total_bonded_atomic` credit),
/// Unbond+Unbond (double debit), JoinMarket+Unbond, and every future
/// `HoldingsUpdate` combination — passes per-tx verify independently; each
/// pair interacts through the per-`P` record and the global counter, and the
/// §4.5 conservation audit is **not** a backstop (a double-credit doubles both
/// sides of `total_bonded == Σ bonded_P` consistently, so it passes on corrupt
/// state). This pass — run once per block over every bond-post vin's
/// `P_canonical_id`, before connect — is the layer that **rejects the block**.
/// Keyed on `P` alone, not `(P, post_kind)`: lifecycle transitions have no
/// legitimate multi-post-per-block use, and rejecting outright avoids inviting
/// intra-block ordering dependence. C++ only marshals the ids; the verdict is
/// decided here (the emission §9.5 item-6 decision-placement pin).
///
/// **Deliberately NOT covered (ratified 2026-07-12): a serve-credit response
/// and an `Unbond` for the same `P` in one block.** The pair is benign under
/// the settled release semantics: a served epoch carries a serve bit and is
/// slash-immune outright, and the epochs the fresh credit would have re-armed
/// the cooldown over are the unserved exit tail, which is exit-forgiven by
/// construction (`release_cooldown` module docs). Rejecting the pair would
/// force an honest exiting `P` to forfeit its final epoch's earned credit or
/// delay the exit a full cooldown — real cost, zero slashable exposure closed.
#[must_use]
pub fn bond_post_block_unique(p_canonical_ids: &[[u8; 32]]) -> bool {
    all_distinct(p_canonical_ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bond_floor::ARCHIVAL_BOND_FLOOR_ATOMIC;
    use crate::bond_wire::{HoldingsDescriptor, HoldingsKind, ShardSet};

    fn valid_join_vin() -> ArchivalBondPostVin {
        ArchivalBondPostVin {
            hybrid_public_key: vec![0xAB; 64],
            p_canonical_id: [0x11; 32],
            post_kind: BondPostKind::JoinMarket,
            bond_spend_pk: vec![0xE5; 64],
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::ShardSetCompact,
                shard_ids: ShardSet::new(vec![7, 42]).unwrap(),
            },
            bonded_total_atomic: 2 * ARCHIVAL_BOND_FLOOR_ATOMIC,
            bond_credit: 2 * ARCHIVAL_BOND_FLOOR_ATOMIC,
            bond_debit: 0,
        }
    }

    #[test]
    fn accepts_valid_join_market() {
        assert!(verify_join_market_bond_post(&valid_join_vin(), false).is_ok());
    }

    #[test]
    fn rejects_non_join_post_kind() {
        let mut vin = valid_join_vin();
        vin.post_kind = BondPostKind::Rebond;
        assert_eq!(
            verify_join_market_bond_post(&vin, false),
            Err(BondPostError::PostKindNotJoinMarket)
        );
    }

    #[test]
    fn rejects_empty_shard_set() {
        let mut vin = valid_join_vin();
        vin.holdings.shard_ids = ShardSet::empty();
        assert_eq!(
            verify_join_market_bond_post(&vin, false),
            Err(BondPostError::ShardSetCompactEmpty)
        );
    }

    #[test]
    fn rejects_complete_tree_with_shards() {
        let mut vin = valid_join_vin();
        vin.holdings.kind = HoldingsKind::CompleteTree;
        vin.holdings.shard_ids = ShardSet::new(vec![1]).unwrap();
        vin.bonded_total_atomic = ARCHIVAL_BOND_FLOOR_ATOMIC;
        vin.bond_credit = ARCHIVAL_BOND_FLOOR_ATOMIC;
        assert_eq!(
            verify_join_market_bond_post(&vin, false),
            Err(BondPostError::CompleteTreeWithShardIds)
        );
    }

    #[test]
    fn rejects_bond_debit_nonzero() {
        let mut vin = valid_join_vin();
        vin.bond_credit = 0;
        vin.bonded_total_atomic = 0;
        vin.bond_debit = 1;
        assert_eq!(
            verify_join_market_bond_post(&vin, false),
            Err(BondPostError::BondDebitNonzero)
        );
    }

    #[test]
    fn rejects_both_terms_nonzero() {
        let mut vin = valid_join_vin();
        vin.bond_debit = ARCHIVAL_BOND_FLOOR_ATOMIC;
        assert_eq!(
            verify_join_market_bond_post(&vin, false),
            Err(BondPostError::BothTermsNonzero)
        );
    }

    #[test]
    fn rejects_floor_zero_via_empty_shards() {
        let mut vin = valid_join_vin();
        vin.holdings.shard_ids = ShardSet::empty();
        assert_eq!(
            verify_join_market_bond_post(&vin, false),
            Err(BondPostError::ShardSetCompactEmpty)
        );
    }

    #[test]
    fn rejects_credit_above_floor() {
        let mut vin = valid_join_vin();
        vin.bond_credit = 2 * ARCHIVAL_BOND_FLOOR_ATOMIC + 1;
        assert_eq!(
            verify_join_market_bond_post(&vin, false),
            Err(BondPostError::FloorMismatch)
        );
    }

    #[test]
    fn rejects_total_below_floor() {
        let mut vin = valid_join_vin();
        vin.bonded_total_atomic = 2 * ARCHIVAL_BOND_FLOOR_ATOMIC - 1;
        assert_eq!(
            verify_join_market_bond_post(&vin, false),
            Err(BondPostError::FloorMismatch)
        );
    }

    #[test]
    fn rejects_existing_record() {
        assert_eq!(
            verify_join_market_bond_post(&valid_join_vin(), true),
            Err(BondPostError::RecordExists)
        );
    }

    // ── Unbond ──────────────────────────────────────────────────────────────

    // `RELEASE_COOLDOWN_EPOCHS` is config-generated (genesis 2); the fixture reads
    // it so a re-pin re-derives the cooldown boundary.
    const UNBOND_LAST_SERVED: u64 = 100;
    const UNBOND_CURRENT: u64 = UNBOND_LAST_SERVED + crate::bond_floor::RELEASE_COOLDOWN_EPOCHS;
    // The scheduler watermark has reached the anchor: epochs ≤ last-served settled.
    const UNBOND_SETTLED: Option<u64> = Some(UNBOND_LAST_SERVED);
    const RECORD_BONDED: u64 = 2 * ARCHIVAL_BOND_FLOOR_ATOMIC;

    /// The post-connect state of a full exit: empty holdings, zero total.
    fn valid_unbond_vin() -> ArchivalBondPostVin {
        ArchivalBondPostVin {
            hybrid_public_key: vec![0xAB; 64],
            p_canonical_id: [0x11; 32],
            post_kind: BondPostKind::Unbond,
            bond_spend_pk: Vec::new(),
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::ShardSetCompact,
                shard_ids: ShardSet::empty(),
            },
            bonded_total_atomic: 0,
            bond_credit: 0,
            bond_debit: RECORD_BONDED,
        }
    }

    fn ok_unbond(vin: &ArchivalBondPostVin) -> Result<(), BondPostError> {
        verify_unbond_bond_post(
            vin,
            Some(RECORD_BONDED),
            0,
            Some(UNBOND_LAST_SERVED),
            UNBOND_SETTLED,
            UNBOND_CURRENT,
        )
    }

    #[test]
    fn accepts_valid_full_unbond() {
        assert!(ok_unbond(&valid_unbond_vin()).is_ok());
    }

    #[test]
    fn accepts_unbond_when_never_served() {
        // No serve bit anywhere ⇒ no anchor: every held-but-unserved epoch either
        // already settled (slashed while bonded) or falls in the exit-forgiven
        // tail, with or without a scheduler watermark.
        assert!(verify_unbond_bond_post(
            &valid_unbond_vin(),
            Some(RECORD_BONDED),
            0,
            None,
            None,
            0
        )
        .is_ok());
    }

    #[test]
    fn rejects_slash_settlement_pending() {
        // The one-block race (release_cooldown module docs): cooldown elapsed by
        // epoch distance, but the scheduler watermark has not reached the anchor —
        // the anchor epoch's deadline block has not folded yet.
        for watermark in [Some(UNBOND_LAST_SERVED - 1), None] {
            assert_eq!(
                verify_unbond_bond_post(
                    &valid_unbond_vin(),
                    Some(RECORD_BONDED),
                    0,
                    Some(UNBOND_LAST_SERVED),
                    watermark,
                    UNBOND_CURRENT,
                ),
                Err(BondPostError::SlashSettlementPending)
            );
        }
        // Watermark past the anchor also accepts.
        assert!(verify_unbond_bond_post(
            &valid_unbond_vin(),
            Some(RECORD_BONDED),
            0,
            Some(UNBOND_LAST_SERVED),
            Some(UNBOND_LAST_SERVED + 5),
            UNBOND_CURRENT,
        )
        .is_ok());
    }

    #[test]
    fn rejects_full_interval_log() {
        // The connect's clean interval-close could not append (codec cap), so
        // verify refuses — a verified-but-unconnectable tx would be a halt.
        use crate::bond_connect::MAX_BOND_BAD_INTERVALS;
        assert_eq!(
            verify_unbond_bond_post(
                &valid_unbond_vin(),
                Some(RECORD_BONDED),
                MAX_BOND_BAD_INTERVALS,
                Some(UNBOND_LAST_SERVED),
                UNBOND_SETTLED,
                UNBOND_CURRENT,
            ),
            Err(BondPostError::IntervalLogFull)
        );
        assert!(verify_unbond_bond_post(
            &valid_unbond_vin(),
            Some(RECORD_BONDED),
            MAX_BOND_BAD_INTERVALS - 1,
            Some(UNBOND_LAST_SERVED),
            UNBOND_SETTLED,
            UNBOND_CURRENT,
        )
        .is_ok());
    }

    #[test]
    fn rejects_wrong_post_kind() {
        let mut vin = valid_unbond_vin();
        vin.post_kind = BondPostKind::JoinMarket;
        assert_eq!(ok_unbond(&vin), Err(BondPostError::PostKindNotUnbond));
    }

    #[test]
    fn rejects_missing_record() {
        assert_eq!(
            verify_unbond_bond_post(
                &valid_unbond_vin(),
                None,
                0,
                Some(UNBOND_LAST_SERVED),
                UNBOND_SETTLED,
                UNBOND_CURRENT
            ),
            Err(BondPostError::RecordMissing)
        );
    }

    #[test]
    fn rejects_nothing_to_unbond() {
        let mut vin = valid_unbond_vin();
        vin.bond_debit = 0;
        assert_eq!(
            verify_unbond_bond_post(
                &vin,
                Some(0),
                0,
                Some(UNBOND_LAST_SERVED),
                UNBOND_SETTLED,
                UNBOND_CURRENT
            ),
            Err(BondPostError::NothingToUnbond)
        );
    }

    #[test]
    fn rejects_credit_on_unbond() {
        let mut vin = valid_unbond_vin();
        vin.bond_credit = 1;
        assert_eq!(ok_unbond(&vin), Err(BondPostError::UnbondCreditNonzero));
    }

    #[test]
    fn rejects_floor_mismatch_nonempty_holdings() {
        // Non-empty holdings ⇒ bond_floor > 0, but bonded_total_atomic is 0.
        let mut vin = valid_unbond_vin();
        vin.holdings.shard_ids = ShardSet::new(vec![7]).unwrap();
        assert_eq!(ok_unbond(&vin), Err(BondPostError::UnbondFloorMismatch));
    }

    // (The former `rejects_oversize_shard_set_masquerading_as_empty` test is
    // retired: an oversize holdings is now unrepresentable — `ShardSet::new`
    // rejects it at the decode/marshal boundary before any verify runs. The
    // type-level rejection and byte-identity are covered by the `ShardSet` tests
    // in `bond_wire`; the FFI marshal boundary keeps its own oversize test.)

    #[test]
    fn rejects_partial_unbond_nonzero_post_total() {
        // Consistent post-state but total != 0 ⇒ partial exit; belongs on the
        // HoldingsUpdate-drop path, not Unbond.
        let mut vin = valid_unbond_vin();
        vin.holdings.shard_ids = ShardSet::new(vec![7]).unwrap();
        vin.bonded_total_atomic = ARCHIVAL_BOND_FLOOR_ATOMIC;
        assert_eq!(ok_unbond(&vin), Err(BondPostError::NotFullUnbond));
    }

    #[test]
    fn rejects_debit_not_full_balance() {
        // The debit must remove the record's whole current bonded_total.
        let mut vin = valid_unbond_vin();
        vin.bond_debit = ARCHIVAL_BOND_FLOOR_ATOMIC; // record holds RECORD_BONDED = 2*FLOOR
        assert_eq!(ok_unbond(&vin), Err(BondPostError::DebitNotFullBalance));
    }

    #[test]
    fn block_unique_rejects_every_same_p_pair() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        assert!(bond_post_block_unique(&[]));
        assert!(bond_post_block_unique(&[a]));
        assert!(bond_post_block_unique(&[a, b]));
        // Any same-P pair rejects, regardless of post kinds (the pass is
        // keyed on P alone) or position in the block.
        assert!(!bond_post_block_unique(&[a, a]));
        assert!(!bond_post_block_unique(&[a, b, a]));
    }

    #[test]
    fn rejects_cooldown_not_elapsed() {
        // One epoch before the boundary: pending challenge could still slash.
        assert_eq!(
            verify_unbond_bond_post(
                &valid_unbond_vin(),
                Some(RECORD_BONDED),
                0,
                Some(UNBOND_LAST_SERVED),
                UNBOND_SETTLED,
                UNBOND_CURRENT - 1,
            ),
            Err(BondPostError::CooldownNotElapsed)
        );
    }

    // ── HoldingsUpdate: the single-shard diff ────────────────────────────────

    #[test]
    fn single_shard_diff_classifies_add_drop_and_rejects_others() {
        assert!(matches!(
            single_shard_diff(&[7, 9], &[7, 9, 11]),
            SingleDiff::Added(11)
        ));
        assert!(matches!(
            single_shard_diff(&[7, 9, 11], &[7, 9]),
            SingleDiff::Removed(11)
        ));
        // Order-agnostic (holdings is a set): same set, no change.
        assert!(matches!(
            single_shard_diff(&[9, 7], &[7, 9]),
            SingleDiff::NotSingle
        ));
        // Two-shard change, a swap, and a duplicate in post all reject.
        assert!(matches!(
            single_shard_diff(&[7], &[7, 9, 11]),
            SingleDiff::NotSingle
        ));
        assert!(matches!(
            single_shard_diff(&[7, 9], &[7, 11]),
            SingleDiff::NotSingle
        ));
        assert!(matches!(
            single_shard_diff(&[7], &[7, 7]),
            SingleDiff::NotSingle
        ));
    }

    // ── HoldingsUpdate-add verify ────────────────────────────────────────────

    const HU_JOIN: u64 = 3;
    const HU_CURRENT: u64 = 20;
    fn hu_current_shards() -> Vec<u64> {
        vec![7, 9]
    }

    fn valid_add_vin() -> ArchivalBondPostVin {
        ArchivalBondPostVin {
            hybrid_public_key: vec![0xAB; 64],
            p_canonical_id: [0x11; 32],
            post_kind: BondPostKind::HoldingsUpdate,
            bond_spend_pk: Vec::new(),
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::ShardSetCompact,
                shard_ids: ShardSet::new(vec![7, 9, 11]).unwrap(), // current + one new shard
            },
            bonded_total_atomic: 3 * ARCHIVAL_BOND_FLOOR_ATOMIC,
            bond_credit: ARCHIVAL_BOND_FLOOR_ATOMIC,
            bond_debit: 0,
        }
    }

    fn ok_add(vin: &ArchivalBondPostVin) -> Result<(), BondPostError> {
        verify_holdings_update_add(
            vin,
            Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
            HoldingsKind::ShardSetCompact,
            &hu_current_shards(),
            HU_JOIN,
            &[],
            HU_CURRENT,
        )
    }

    #[test]
    fn accepts_valid_add() {
        assert!(ok_add(&valid_add_vin()).is_ok());
    }

    #[test]
    fn add_rejects_wrong_post_kind() {
        let mut vin = valid_add_vin();
        vin.post_kind = BondPostKind::JoinMarket;
        assert_eq!(ok_add(&vin), Err(BondPostError::PostKindNotHoldingsUpdate));
    }

    #[test]
    fn add_rejects_missing_record() {
        assert_eq!(
            verify_holdings_update_add(
                &valid_add_vin(),
                None,
                HoldingsKind::ShardSetCompact,
                &hu_current_shards(),
                HU_JOIN,
                &[],
                HU_CURRENT,
            ),
            Err(BondPostError::RecordMissing)
        );
    }

    #[test]
    fn add_rejects_complete_tree_record() {
        assert_eq!(
            verify_holdings_update_add(
                &valid_add_vin(),
                Some(ARCHIVAL_BOND_FLOOR_ATOMIC),
                HoldingsKind::CompleteTree,
                &[],
                HU_JOIN,
                &[],
                HU_CURRENT,
            ),
            Err(BondPostError::HoldingsUpdateOnCompleteTree)
        );
    }

    #[test]
    fn add_rejects_exited_record_resurrection() {
        // The Exited shape (post-Unbond): zero total, empty holdings, and a
        // zero-length clean interval-close that good_through excludes nothing
        // for. Without the Bonded gate this passed EVERY add gate — a
        // JoinMarket-bypassing re-entry path whose connect then threw on the
        // empty-pre-image journal encode (verify-valid but unconnectable on
        // every node: a chain-stall vector). P2B-7 Pin 1: Bonded → Bonded.
        let vin = ArchivalBondPostVin {
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::ShardSetCompact,
                shard_ids: ShardSet::new(vec![11]).unwrap(),
            },
            bonded_total_atomic: ARCHIVAL_BOND_FLOOR_ATOMIC,
            bond_credit: ARCHIVAL_BOND_FLOOR_ATOMIC,
            ..valid_add_vin()
        };
        assert_eq!(
            verify_holdings_update_add(
                &vin,
                Some(0), // Exited: nothing bonded
                HoldingsKind::ShardSetCompact,
                &[], // Exited: no held shards
                HU_JOIN,
                &[],
                HU_CURRENT,
            ),
            Err(BondPostError::HoldingsUpdateRecordNotBonded)
        );
    }

    #[test]
    fn add_rejects_open_bad_interval() {
        // An open bad interval (post-slash, pre-Rebond) is not good standing.
        let open = crate::consensus_state::BadInterval {
            start_epoch: 10,
            end_exclusive: u64::MAX,
        };
        assert_eq!(
            verify_holdings_update_add(
                &valid_add_vin(),
                Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
                HoldingsKind::ShardSetCompact,
                &hu_current_shards(),
                HU_JOIN,
                &[open],
                HU_CURRENT,
            ),
            Err(BondPostError::HoldingsUpdateNotGoodStanding)
        );
    }

    #[test]
    fn add_rejects_wrong_terms() {
        let mut vin = valid_add_vin();
        vin.bond_credit = 2 * ARCHIVAL_BOND_FLOOR_ATOMIC; // must be exactly one FLOOR
        assert_eq!(ok_add(&vin), Err(BondPostError::HoldingsUpdateAddTerms));
        let mut vin = valid_add_vin();
        vin.bond_debit = 1; // credit path must carry no debit
        assert_eq!(ok_add(&vin), Err(BondPostError::HoldingsUpdateAddTerms));
    }

    #[test]
    fn add_rejects_not_single_add() {
        // Post adds two shards.
        let mut vin = valid_add_vin();
        vin.holdings.shard_ids = ShardSet::new(vec![7, 9, 11, 13]).unwrap();
        vin.bonded_total_atomic = 4 * ARCHIVAL_BOND_FLOOR_ATOMIC;
        assert_eq!(ok_add(&vin), Err(BondPostError::HoldingsUpdateNotSingleAdd));
    }

    #[test]
    fn add_rejects_floor_mismatch() {
        let mut vin = valid_add_vin();
        vin.bonded_total_atomic = 4 * ARCHIVAL_BOND_FLOOR_ATOMIC; // != |post|·FLOOR
        assert_eq!(
            ok_add(&vin),
            Err(BondPostError::HoldingsUpdateAddFloorMismatch)
        );
    }

    // ── HoldingsUpdate-drop verify ───────────────────────────────────────────

    // A shard old enough to drop: added at epoch 0 (genesis band, freeze 0 ⇒ age
    // max ⇒ bond_duration 20), tenure = current − 0 must reach 20.
    const DROP_ADD_EPOCH: u64 = 0;
    const DROP_FREEZE: u64 = 0;
    const DROP_LAST_SERVED: u64 = 5;
    const DROP_CURRENT: u64 = 40; // tenure 40 ≥ horizon 20; cooldown/settle satisfied

    fn valid_drop_vin() -> ArchivalBondPostVin {
        ArchivalBondPostVin {
            hybrid_public_key: vec![0xAB; 64],
            p_canonical_id: [0x11; 32],
            post_kind: BondPostKind::HoldingsUpdate,
            bond_spend_pk: Vec::new(),
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::ShardSetCompact,
                shard_ids: ShardSet::new(vec![7]).unwrap(), // current {7, 11} minus 11
            },
            bonded_total_atomic: ARCHIVAL_BOND_FLOOR_ATOMIC,
            bond_credit: 0,
            bond_debit: ARCHIVAL_BOND_FLOOR_ATOMIC,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn ok_drop(vin: &ArchivalBondPostVin) -> Result<(), BondPostError> {
        verify_holdings_update_drop(
            vin,
            Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
            HoldingsKind::ShardSetCompact,
            &[7, 11],
            11,
            DROP_ADD_EPOCH,
            DROP_FREEZE,
            Some(DROP_LAST_SERVED),
            Some(DROP_CURRENT),
            DROP_CURRENT,
        )
    }

    #[test]
    fn accepts_valid_drop() {
        assert!(ok_drop(&valid_drop_vin()).is_ok());
    }

    #[test]
    fn drop_rejects_unbonded_record() {
        // The add arm's Bonded-gate twin (shared prologue): a zero-total /
        // no-shards record refuses before any diff or term arithmetic runs.
        assert_eq!(
            verify_holdings_update_drop(
                &valid_drop_vin(),
                Some(0),
                HoldingsKind::ShardSetCompact,
                &[],
                11,
                DROP_ADD_EPOCH,
                DROP_FREEZE,
                Some(DROP_LAST_SERVED),
                Some(DROP_CURRENT),
                DROP_CURRENT,
            ),
            Err(BondPostError::HoldingsUpdateRecordNotBonded)
        );
    }

    #[test]
    fn drop_rejects_wrong_terms() {
        let mut vin = valid_drop_vin();
        vin.bond_debit = 2 * ARCHIVAL_BOND_FLOOR_ATOMIC;
        assert_eq!(ok_drop(&vin), Err(BondPostError::HoldingsUpdateDropTerms));
    }

    #[test]
    fn drop_rejects_not_single_or_wrong_shard() {
        // The vin drops a shard, but C++ passed a different dropped_shard_id.
        let vin = valid_drop_vin();
        assert_eq!(
            verify_holdings_update_drop(
                &vin,
                Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
                HoldingsKind::ShardSetCompact,
                &[7, 11],
                7, // wrong: the diff removed 11, not 7
                DROP_ADD_EPOCH,
                DROP_FREEZE,
                Some(DROP_LAST_SERVED),
                Some(DROP_CURRENT),
                DROP_CURRENT,
            ),
            Err(BondPostError::HoldingsUpdateNotSingleDrop)
        );
    }

    #[test]
    fn drop_rejects_last_shard() {
        // Dropping the only shard: post empty → use Unbond.
        let mut vin = valid_drop_vin();
        vin.holdings.shard_ids = ShardSet::empty();
        vin.bonded_total_atomic = 0;
        assert_eq!(
            verify_holdings_update_drop(
                &vin,
                Some(ARCHIVAL_BOND_FLOOR_ATOMIC),
                HoldingsKind::ShardSetCompact,
                &[11],
                11,
                DROP_ADD_EPOCH,
                DROP_FREEZE,
                Some(DROP_LAST_SERVED),
                Some(DROP_CURRENT),
                DROP_CURRENT,
            ),
            Err(BondPostError::HoldingsUpdateDropLastShard)
        );
    }

    #[test]
    fn drop_rejects_within_horizon() {
        // Same shard, but current epoch is only 10 past add — horizon for a
        // genesis-band shard is 20, so tenure 10 < 20.
        assert_eq!(
            verify_holdings_update_drop(
                &valid_drop_vin(),
                Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
                HoldingsKind::ShardSetCompact,
                &[7, 11],
                11,
                DROP_ADD_EPOCH,
                DROP_FREEZE,
                Some(DROP_LAST_SERVED),
                Some(10),
                10,
            ),
            Err(BondPostError::HoldingsUpdateDropWithinHorizon)
        );
    }

    #[test]
    fn drop_rejects_cooldown_not_elapsed() {
        // Last-served at current − 1: the release cooldown (2 epochs) has not passed.
        let near = DROP_CURRENT;
        assert_eq!(
            verify_holdings_update_drop(
                &valid_drop_vin(),
                Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
                HoldingsKind::ShardSetCompact,
                &[7, 11],
                11,
                DROP_ADD_EPOCH,
                DROP_FREEZE,
                Some(near),
                Some(near),
                near,
            ),
            Err(BondPostError::CooldownNotElapsed)
        );
    }

    #[test]
    fn drop_rejects_slash_settlement_pending() {
        // Cooldown elapsed, but the slash scheduler has not settled through the
        // dropped shard's last-served anchor.
        assert_eq!(
            verify_holdings_update_drop(
                &valid_drop_vin(),
                Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
                HoldingsKind::ShardSetCompact,
                &[7, 11],
                11,
                DROP_ADD_EPOCH,
                DROP_FREEZE,
                Some(DROP_LAST_SERVED),
                Some(DROP_LAST_SERVED - 1), // watermark below the anchor
                DROP_CURRENT,
            ),
            Err(BondPostError::SlashSettlementPending)
        );
    }

    // ── Rebond (P2B-9) ────────────────────────────────────────────────────────

    use crate::consensus_state::BadInterval;

    fn open_interval(start: u64) -> BadInterval {
        BadInterval {
            start_epoch: start,
            end_exclusive: u64::MAX,
        }
    }

    fn closed_interval(start: u64, end: u64) -> BadInterval {
        BadInterval {
            start_epoch: start,
            end_exclusive: end,
        }
    }

    /// Partial-slash record: held {7, 9} (shard 11 was slashed away), one open
    /// interval, floor-consistent balance.
    fn rebond_record_shards() -> Vec<u64> {
        vec![7, 9]
    }

    fn rebond_vin(post: Vec<u64>, credit: u64) -> ArchivalBondPostVin {
        let shard_ids = ShardSet::new(post).expect("rebond fixture holdings are valid");
        let post_floor = shard_ids.len() as u64 * ARCHIVAL_BOND_FLOOR_ATOMIC;
        ArchivalBondPostVin {
            hybrid_public_key: vec![0xAB; 64],
            p_canonical_id: [0x11; 32],
            post_kind: BondPostKind::Rebond,
            bond_spend_pk: Vec::new(),
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::ShardSetCompact,
                shard_ids,
            },
            bonded_total_atomic: post_floor,
            bond_credit: credit,
            bond_debit: 0,
        }
    }

    fn ok_rebond(vin: &ArchivalBondPostVin) -> Result<(), BondPostError> {
        verify_rebond_bond_post(
            vin,
            Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
            HoldingsKind::ShardSetCompact,
            &rebond_record_shards(),
            &[open_interval(5)],
        )
    }

    #[test]
    fn rebond_accepts_standing_only_zero_credit() {
        // The common case: same set, credit 0 — pure reinstatement (Pin 2).
        assert!(ok_rebond(&rebond_vin(vec![7, 9], 0)).is_ok());
    }

    #[test]
    fn rebond_accepts_growth_with_matching_credit() {
        // Re-acquire the slashed shard + one new: credit = 2·FLOOR.
        assert!(ok_rebond(&rebond_vin(
            vec![7, 9, 11, 13],
            2 * ARCHIVAL_BOND_FLOOR_ATOMIC
        ))
        .is_ok());
    }

    #[test]
    fn rebond_accepts_terminal_slash_full_refund() {
        // Terminal: bonded 0, empty holdings, open interval — full floor credit.
        assert!(verify_rebond_bond_post(
            &rebond_vin(vec![7, 9], 2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
            Some(0),
            HoldingsKind::ShardSetCompact,
            &[],
            &[open_interval(5)],
        )
        .is_ok());
    }

    #[test]
    fn rebond_rejects_wrong_post_kind() {
        let mut vin = rebond_vin(vec![7, 9], 0);
        vin.post_kind = BondPostKind::HoldingsUpdate;
        assert_eq!(ok_rebond(&vin), Err(BondPostError::PostKindNotRebond));
    }

    #[test]
    fn rebond_rejects_missing_record() {
        assert_eq!(
            verify_rebond_bond_post(
                &rebond_vin(vec![7, 9], 0),
                None,
                HoldingsKind::ShardSetCompact,
                &rebond_record_shards(),
                &[open_interval(5)],
            ),
            Err(BondPostError::RecordMissing)
        );
    }

    #[test]
    fn rebond_rejects_complete_tree_record_and_post() {
        assert_eq!(
            verify_rebond_bond_post(
                &rebond_vin(vec![7, 9], 0),
                Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
                HoldingsKind::CompleteTree,
                &[],
                &[open_interval(5)],
            ),
            Err(BondPostError::RebondOnCompleteTree)
        );
        let mut vin = rebond_vin(vec![], 0);
        vin.holdings.kind = HoldingsKind::CompleteTree;
        assert_eq!(ok_rebond(&vin), Err(BondPostError::RebondPostNotCompact));
    }

    #[test]
    fn rebond_rejects_empty_post() {
        // A terminal-slash "standing-only" rebond to ∅ would mint a zombie.
        assert_eq!(
            verify_rebond_bond_post(
                &rebond_vin(vec![], 0),
                Some(0),
                HoldingsKind::ShardSetCompact,
                &[],
                &[open_interval(5)],
            ),
            Err(BondPostError::ShardSetCompactEmpty)
        );
    }

    #[test]
    fn rebond_rejects_unslashed_record() {
        // No open interval: nothing to reinstate (Exited's zero-length clean
        // close is not open — good_through skips it).
        assert_eq!(
            verify_rebond_bond_post(
                &rebond_vin(vec![7, 9], 0),
                Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
                HoldingsKind::ShardSetCompact,
                &rebond_record_shards(),
                &[closed_interval(5, 6), closed_interval(9, 9)],
            ),
            Err(BondPostError::RebondNotSlashed)
        );
    }

    #[test]
    fn rebond_rejects_multiple_open_intervals() {
        // Corruption of the Pin-5 coalescing invariant — reject at verify so a
        // verify-valid tx can never meet the connect fold's loud belt.
        assert_eq!(
            verify_rebond_bond_post(
                &rebond_vin(vec![7, 9], 0),
                Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
                HoldingsKind::ShardSetCompact,
                &rebond_record_shards(),
                &[open_interval(5), open_interval(5)],
            ),
            Err(BondPostError::RebondMultipleOpenIntervals)
        );
    }

    #[test]
    fn rebond_rejects_interval_log_without_headroom() {
        // Pin 6: 254 is the last acceptable size (one slot for the next slash +
        // one for the Unbond clean close); 255 rejects.
        let mut log: Vec<BadInterval> = (0..254u64).map(|i| closed_interval(i, i + 1)).collect();
        log.push(open_interval(300));
        assert_eq!(log.len(), 255);
        assert_eq!(
            verify_rebond_bond_post(
                &rebond_vin(vec![7, 9], 0),
                Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
                HoldingsKind::ShardSetCompact,
                &rebond_record_shards(),
                &log,
            ),
            Err(BondPostError::RebondIntervalLogHeadroom)
        );
        // At exactly 254 (253 closed + the open one) the same vin verifies.
        log.pop();
        log.pop();
        log.push(open_interval(300));
        assert_eq!(log.len(), 254);
        assert!(verify_rebond_bond_post(
            &rebond_vin(vec![7, 9], 0),
            Some(2 * ARCHIVAL_BOND_FLOOR_ATOMIC),
            HoldingsKind::ShardSetCompact,
            &rebond_record_shards(),
            &log,
        )
        .is_ok());
    }

    #[test]
    fn rebond_rejects_swap_and_shed_respec() {
        // The swap-shed dodge (Pin 1): drop a carried shard, add a different one
        // — same floor, credit 0 — must NOT pass as reinstatement.
        assert_eq!(
            ok_rebond(&rebond_vin(vec![7, 13], 0)),
            Err(BondPostError::RebondNotSuperset)
        );
        // A plain shed (subset) is arithmetically a shrink and also not a superset.
        assert_eq!(
            ok_rebond(&rebond_vin(vec![7], 0)),
            Err(BondPostError::RebondNotSuperset)
        );
        // (A duplicate post — `vec![7, 9, 9]` — is no longer reachable here: it
        // cannot be constructed into a `ShardSet`, so the "not a set" case is a
        // `ShardSet::new` rejection, tested in `bond_wire`.)
    }

    #[test]
    fn rebond_rejects_term_mismatches() {
        // Debit is never carried on a credit path.
        let mut vin = rebond_vin(vec![7, 9], 0);
        vin.bond_debit = 1;
        assert_eq!(ok_rebond(&vin), Err(BondPostError::RebondTerms));
        // Credit must equal floor(post) − bonded: growth without credit…
        assert_eq!(
            ok_rebond(&rebond_vin(vec![7, 9, 11], 0)),
            Err(BondPostError::RebondTerms)
        );
        // …and credit on a standing-only re-spec.
        assert_eq!(
            ok_rebond(&rebond_vin(vec![7, 9], ARCHIVAL_BOND_FLOOR_ATOMIC)),
            Err(BondPostError::RebondTerms)
        );
        // Post bonded_total must equal bond_floor(post).
        let mut vin = rebond_vin(vec![7, 9], 0);
        vin.bonded_total_atomic += 1;
        assert_eq!(ok_rebond(&vin), Err(BondPostError::RebondTerms));
        // A record whose bonded exceeds floor(record holdings) is corruption —
        // the explicit floor-invariant check names it (an honest shrink is
        // unrepresentable under the superset anyway).
        assert_eq!(
            verify_rebond_bond_post(
                &rebond_vin(vec![7, 9], 0),
                Some(3 * ARCHIVAL_BOND_FLOOR_ATOMIC),
                HoldingsKind::ShardSetCompact,
                &rebond_record_shards(),
                &[open_interval(5)],
            ),
            Err(BondPostError::RebondRecordFloorBroken)
        );
    }

    // (The former `rebond_rejects_oversize_shard_set` verify test is retired
    // with the `RebondPostOversize` belt: an oversize post cannot be built into
    // the vin's `ShardSet`, so the fail-open hole it closed — an oversize post
    // collapsing `bond_floor` to 0 on a terminal record, verifying with zero
    // collateral, then aborting the block-connect encode — is now
    // unrepresentable at the decode/marshal boundary. The bound is proven by
    // the `ShardSet` construction tests and re-guarded on the raw-slice connect
    // path by `rebond_connect`'s `PostOversize` belt + the FFI marshal test.)

    #[test]
    fn rebond_rejects_record_floor_drift() {
        // A record whose bonded_total drifted BELOW bond_floor(holdings)
        // (1.5·FLOOR over two shards — no honest path produces it; any latent
        // bug or DB corruption could). The terms alone would verify — credit =
        // bond_floor(post) − 1.5·FLOOR via the checked_sub — and the connect
        // fold's RecordFloorInvariantBroken belt would then FATAL-abort every
        // node connecting the block. The verify-side check turns the chain
        // halt into a tx rejection.
        let drifted = ARCHIVAL_BOND_FLOOR_ATOMIC + ARCHIVAL_BOND_FLOOR_ATOMIC / 2;
        let vin = rebond_vin(vec![7, 9], 2 * ARCHIVAL_BOND_FLOOR_ATOMIC - drifted);
        assert_eq!(
            verify_rebond_bond_post(
                &vin,
                Some(drifted),
                HoldingsKind::ShardSetCompact,
                &rebond_record_shards(),
                &[open_interval(5)],
            ),
            Err(BondPostError::RebondRecordFloorBroken)
        );
    }
}
