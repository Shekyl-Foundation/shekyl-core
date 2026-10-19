// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The epoch's drawable set: the builder of its [`DrawableEpoch`]
//! (`SO-D12` increment 2, `ARCHIVAL_SETTLEMENT_WRITER.md` §16).
//!
//! `D(E)` is the pairs held in the state after `h_open(E)` connects, that
//! block's slash pass included, each with its persona's receipt key
//! (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §4.1, §9.6). It is fixed for the epoch:
//! a pair slashed or released during `E` stays in it. Two derivations
//! produce it, through one emitter:
//!
//! 1. [`drawable_epoch_at_open`] — at `h_open(E)` itself, over the block's
//!    post-state: the recorded records under this block's post-images,
//!    after its slash pass and its close. At that height the post-state
//!    *is* `D(E)`, so no journal is read, and a Release or a slash in the
//!    block is applied. Its digest is written in the block's delta.
//! 2. [`drawable_epoch_walked_back`] — at any later tip, from the records
//!    at tip with every Release (the Release journal, A20) and every slash
//!    (the slash log, A21) connected strictly above `h_open(E)` undone,
//!    newest first. The settlement pass that settles `E` compares its
//!    digest with the one written at the open (§9.5 check 2).
//!
//! **The two are independent.** The first reads no journal; the second
//! reads no value the first produced — not the digest, and not a cached
//! set. The check compares them, and a shared shortcut would make it test
//! nothing (`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md` §6.3 item 2).
//!
//! # The filters both apply
//!
//! [`emit`] holds the three pins of the proposal's §7.4 for both: a bond
//! that joined in `E` or later is excluded (pin 1); a complete tree expands
//! to the shards closed and final at `h_open(E)`, not at tip (pin 2); and
//! the pairs are in canonical order (pin 3, [`DrawablePair`]'s `Ord`).
//!
//! Closed and final at `h_open` is one count for both arms. Shards close
//! in order, so the shards closed and final at `h_open` are the prefix
//! `0..final_count`, with `final_count` the
//! [`ClosedUniverse::final_before`] count for a block connecting at
//! `h_open + 1` ([`closed_and_final`](super::closed_and_final) taken over
//! every shard at once). A compact holding keeps a shard below it. The
//! count reads blocks at or below `h_open − reorg_cap`, so derivation 1 can
//! take it while block `h_open` is connecting, and derivation 2 reads the
//! same blocks at any later tip.
//!
//! # What the walk undoes, and what it need not
//!
//! Holdings change by two events only: a slash removes a shard (or demotes
//! a complete tree to the empty set), and a Release empties the record.
//! A JoinMarket above `h_open(E)` joins in `E` or later and is excluded by
//! pin 1. A Reinstate changes no holdings: it is refused unless the post's
//! shard set equals the record's, and its one write ends the open bad
//! interval (§16.7). No other post changes holdings: `HoldingsUpdate` is
//! rejected and the bond is immutable. Records are never deleted, so a
//! journal row always finds its persona's record.
//!
//! The receipt key is not restored by anything: a Release keeps the
//! record and no post changes the key, so tip and the pre-image agree on
//! it.
//!
//! # The walk's span, and the journals' floor
//!
//! The walk reads everything strictly above `h_open(E)`. It runs at the
//! slash pass that settles `E`, in the block whose `count` (one above its
//! height) first passes `E`'s slash deadline: the last block of epoch
//! `E + k`, with `k` the slash grace, so the span is under `(k + 1)·SEB`. A
//! reorg can run that pass again with the tip up to `reorg_cap` blocks
//! lower than the tip the last prune ran at. Both
//! journals are retired below [`SlashLogFloor`], `(k + n)·SEB + reorg_cap`
//! below the pruning tip, so the walk stays above the floor when
//! `(k + 1)·SEB + reorg_cap ≤ (k + n)·SEB + reorg_cap`. Both sides scale
//! with `SEB` and carry the same cap, so the relation is in epochs and
//! holds under every schedule, Fakechain's included:
//! [`WALK_BACK_EPOCHS`] against the floor's epochs, asserted at compile
//! time. A walk asked to start below the floor anyway is refused, never
//! degraded ([`DrawableEpochFault::BelowFloor`], §7.4 pin 4).

use std::collections::BTreeMap;

use shekyl_archival_retention::{
    DrawableEpoch, DrawablePair, SettlementSchedule, FAILURE_WINDOW_N, SLASH_GRACE_EPOCHS,
};
use shekyl_types::archival::{
    BondRecord, DrawableDigest, HeldShard, Holdings, LoggedSlash, ReleasedRecord, SlashedHolding,
};
use shekyl_types::{BlockCount, BlockHeight, PCanonicalId, SettlementEpoch, ShardId};

use crate::archival::ClosedUniverse;
use crate::fault::{Corrupt, DrawableEpochFault, SettlementCheck, ViewRead};
use crate::reorg::SlashLogFloor;
use crate::view::ChainView;

/// The epochs the walk back reads, from `h_open(E)` to the slash pass
/// that settles `E`: the epoch itself and the slash grace after it (module
/// docs, *The walk's span*).
pub const WALK_BACK_EPOCHS: u64 = 1 + SLASH_GRACE_EPOCHS;

// The walk stays above the journals' floor under every schedule: the floor
// is `(k + n)` epochs and a reorg cap below the tip, the walk `(k + 1)`
// epochs and at most a reorg cap. Re-pinning the grace or the window so
// the walk reaches below the floor fails here.
#[allow(clippy::cast_lossless)] // `u64::from` is not const.
const _: () = assert!(WALK_BACK_EPOCHS <= SLASH_GRACE_EPOCHS + FAILURE_WINDOW_N as u64);

/// The count of shards closed and final at `h_open`: the prefix both
/// derivations expand a complete tree to and keep a compact shard inside
/// (module docs, *The filters both apply*).
pub(crate) fn final_count_at_open<'id, V: ChainView<'id>>(
    view: &V,
    h_open: BlockHeight,
    reorg_cap: BlockCount,
) -> Result<u64, ViewRead<V::Fault>> {
    let h_next = h_open
        .checked_add(BlockCount::ONE)
        .expect("an open height below u64::MAX");
    Ok(ClosedUniverse::final_before(view, h_next, reorg_cap)?
        .count()
        .get())
}

/// Derivation 1: `D(epoch)` over the state after `h_open(epoch)` connects
/// — `records` is every bond record as the connecting block leaves it, its
/// slash pass included — with `final_count` from [`final_count_at_open`].
///
/// # Errors
///
/// [`DrawableEpochFault::Construction`] when a record's receipt key does
/// not parse.
pub(crate) fn drawable_epoch_at_open<'r>(
    epoch: SettlementEpoch,
    records: impl IntoIterator<Item = (&'r PCanonicalId, &'r BondRecord)>,
    final_count: u64,
) -> Result<DrawableEpoch, DrawableEpochFault> {
    emit(epoch, records, final_count)
}

/// Derivation 2: `D(epoch)` rebuilt at this view's tip from the records at
/// tip and the two bond journals, with every Release and slash above
/// `h_open(epoch)` undone. `None` when `epoch` has not opened on this view:
/// there is no state after `h_open(epoch)` to rebuild.
///
/// `schedule` and `reorg_cap` are the rule set's, and `floor` is the
/// journals' floor under it — the caller's, as for every slash-log read
/// (`SLK-2`).
///
/// # Errors
///
/// The view's fault; [`Corrupt::DrawableEpoch`] when the walk would start
/// below `floor`, when a journal row names a persona with no record, when
/// a slash cannot be undone on the record the walk holds, or when the
/// rebuilt set cannot be built; or [`closed_and_final`](super::closed_and_final)'s
/// [`Corrupt::ShardCloseUnplaced`].
pub fn drawable_epoch_walked_back<'id, V: ChainView<'id>>(
    view: &V,
    epoch: SettlementEpoch,
    schedule: SettlementSchedule,
    reorg_cap: BlockCount,
    floor: SlashLogFloor,
) -> Result<Option<DrawableEpoch>, ViewRead<V::Fault>> {
    let corrupt = |why| ViewRead::Corrupt(Corrupt::DrawableEpoch { epoch, why });
    let Some(tip) = view.tip().map_err(ViewRead::View)? else {
        return Ok(None);
    };
    let h_open = BlockHeight::from_raw(schedule.open_height(epoch.to_raw()));
    if h_open > tip.height {
        return Ok(None);
    }
    // Rows strictly above `h_open` are read; the lowest is `h_open + 1`, and
    // the floor is the lowest retained.
    if let Some(kept_from) = floor.height() {
        if h_open.to_raw().saturating_add(1) < kept_from.to_raw() {
            return Err(corrupt(DrawableEpochFault::BelowFloor {
                h_open,
                floor: kept_from,
            }));
        }
    }
    let records = view.bond_records().map_err(ViewRead::View)?;
    let releases = view
        .release_journal_after(h_open, floor)
        .map_err(ViewRead::View)?;
    let slashes = view
        .slash_log_rows_after(h_open, floor)
        .map_err(ViewRead::View)?;
    let at_open = rewind(records, releases, slashes).map_err(corrupt)?;
    let final_count = final_count_at_open(view, h_open, reorg_cap)?;
    emit(epoch, at_open.iter(), final_count)
        .map(Some)
        .map_err(corrupt)
}

/// §9.5 check 2, on the two values and nothing else.
///
/// `written` is the digest the open recorded. `rebuilt` is the walk's set,
/// `None` when `epoch` has not opened on the view. A missing digest, a
/// digest for an epoch with no post-state, and a digest that differs are
/// three faults. Only the last is drift: comparing the walk's `Option`
/// with the recorded digest would report an unopened epoch as one.
pub(super) fn compare_recorded_digest(
    epoch: SettlementEpoch,
    h_open: BlockHeight,
    written: Option<DrawableDigest>,
    rebuilt: Option<&DrawableEpoch>,
) -> Result<(), Corrupt> {
    let Some(written) = written else {
        return Err(Corrupt::SettlementIntegrity {
            epoch,
            check: SettlementCheck::DrawableDigestMissing,
        });
    };
    let Some(rebuilt) = rebuilt else {
        return Err(Corrupt::DrawableEpoch {
            epoch,
            why: DrawableEpochFault::Unopened { h_open },
        });
    };
    if rebuilt.digest() != written {
        return Err(Corrupt::SettlementIntegrity {
            epoch,
            check: SettlementCheck::DrawableDrift,
        });
    }
    Ok(())
}

/// One event the walk undoes. Within a block a Release (an input) connects
/// before a slash (the slash pass), so at one height a slash is the newer.
enum Undo {
    Release(ReleasedRecord),
    Slash(LoggedSlash),
}

impl Undo {
    /// The order the events connected in: height, then the Release before
    /// the slash pass. Ties within a kind keep the read's order.
    fn connected_at(&self) -> (BlockHeight, u8) {
        match self {
            Self::Release(release) => (release.height, 0),
            Self::Slash(slash) => (slash.height, 1),
        }
    }
}

/// The records as they stood after `h_open(E)` connected: `records` at tip
/// with every journaled event above `h_open(E)` undone, newest first. A
/// Release is undone by restoring its pre-image; a slash by giving back the
/// shard it removed, with its add epoch, or the complete tree it demoted.
///
/// Pure: the fold over three reads, so its arms are tested on plain data.
fn rewind(
    records: Vec<(PCanonicalId, BondRecord)>,
    releases: Vec<ReleasedRecord>,
    slashes: Vec<LoggedSlash>,
) -> Result<BTreeMap<PCanonicalId, BondRecord>, DrawableEpochFault> {
    let mut records: BTreeMap<PCanonicalId, BondRecord> = records.into_iter().collect();
    let mut events: Vec<Undo> = releases
        .into_iter()
        .map(Undo::Release)
        .chain(slashes.into_iter().map(Undo::Slash))
        .collect();
    // Stable, so rows of one kind at one height keep their read order.
    events.sort_by_key(Undo::connected_at);
    for event in events.into_iter().rev() {
        match event {
            Undo::Release(release) => {
                let persona = release.persona;
                let record = records
                    .get_mut(&persona)
                    .ok_or(DrawableEpochFault::NoRecord { persona })?;
                *record = release.pre_image;
            }
            Undo::Slash(LoggedSlash { entry, .. }) => {
                let (persona, shard) = (entry.persona, entry.shard);
                let record = records
                    .get_mut(&persona)
                    .ok_or(DrawableEpochFault::NoRecord { persona })?;
                record.holdings = unslashed(&record.holdings, shard, entry.holding)
                    .ok_or(DrawableEpochFault::SlashNotUndoable { persona, shard })?;
            }
        }
    }
    Ok(records)
}

/// `holdings` with one slash undone, or `None` when `holdings` is not a
/// state that slash can have left: a compact set that already holds the
/// removed shard (or that the shard cannot rejoin), or anything but the
/// empty set for a complete-tree demotion.
fn unslashed(holdings: &Holdings, shard: ShardId, took: SlashedHolding) -> Option<Holdings> {
    match (holdings, took) {
        (Holdings::ShardSet(held), SlashedHolding::Shard { add_epoch }) => {
            let mut restored = held.as_slice().to_vec();
            restored.push(HeldShard { shard, add_epoch });
            Holdings::shard_set(restored).ok()
        }
        (Holdings::ShardSet(held), SlashedHolding::CompleteTree) if held.is_empty() => {
            Some(Holdings::CompleteTree)
        }
        _ => None,
    }
}

/// The emitter both derivations share: pins 1 to 3 over `records`, and
/// each persona's receipt key, into the one constructor.
fn emit<'r>(
    epoch: SettlementEpoch,
    records: impl IntoIterator<Item = (&'r PCanonicalId, &'r BondRecord)>,
    final_count: u64,
) -> Result<DrawableEpoch, DrawableEpochFault> {
    let mut pairs = Vec::new();
    let mut keys = Vec::new();
    for (&persona, record) in records {
        if record.join_settlement_epoch >= epoch {
            continue;
        }
        let held = pairs.len();
        match &record.holdings {
            Holdings::CompleteTree => {
                pairs.extend((0..final_count).map(|shard| DrawablePair {
                    persona,
                    shard: ShardId::from_raw(shard),
                }));
            }
            Holdings::ShardSet(set) => {
                pairs.extend(
                    set.iter()
                        .filter(|h| h.shard.to_raw() < final_count)
                        .map(|h| DrawablePair {
                            persona,
                            shard: h.shard,
                        }),
                );
            }
        }
        if pairs.len() > held {
            keys.push((persona, &record.receipt_sign_pk));
        }
    }
    DrawableEpoch::new(epoch, keys, pairs).map_err(DrawableEpochFault::Construction)
}

#[cfg(test)]
#[path = "drawable_tests.rs"]
mod tests;
