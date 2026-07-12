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

use crate::bond_floor::bond_floor;
use crate::bond_wire::{HoldingsDescriptor, HoldingsKind};
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
    pub new_total_bonded_atomic: u64,
    /// `== bond_debit == bond_floor(record's current holdings)` (§4.3).
    pub refund_atomic: u64,
}

/// Fold the `Unbond` connect (gate-4 §4.3): given the record's **current**
/// state, the vin's `bond_debit`, and the connecting block's settlement epoch,
/// produce the post-connect record state, the interval-log append, and the
/// `total_bonded_atomic` movement.
///
/// `record_bad_interval_count` is the record's interval-log length *before*
/// the append. The record **persists** (state `Exited`) for backlog claims
/// until `W` lapses — deletion / `p_slot` burn is a later, separate step.
pub fn unbond_connect(
    record_bonded_total: u64,
    record_holdings: &HoldingsDescriptor,
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
    if bond_floor(record_holdings) != record_bonded_total {
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
            shard_ids: Vec::new(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bond_floor::ARCHIVAL_BOND_FLOOR_ATOMIC;
    use crate::consensus_state::good_through;

    const E_UNBOND: u64 = 42;
    const RECORD_BONDED: u64 = 2 * ARCHIVAL_BOND_FLOOR_ATOMIC;
    const TOTAL_BONDED: u64 = 5 * ARCHIVAL_BOND_FLOOR_ATOMIC;

    fn record_holdings() -> HoldingsDescriptor {
        HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: vec![7, 42],
        }
    }

    fn ok_connect() -> UnbondConnect {
        unbond_connect(
            RECORD_BONDED,
            &record_holdings(),
            0,
            RECORD_BONDED,
            TOTAL_BONDED,
            E_UNBOND,
        )
        .expect("valid connect")
    }

    #[test]
    fn connect_full_release_effect() {
        let effect = ok_connect();
        assert_eq!(effect.post_bonded_total, 0);
        assert_eq!(effect.post_holdings.kind, HoldingsKind::ShardSetCompact);
        assert!(effect.post_holdings.shard_ids.is_empty());
        assert_eq!(effect.interval_close, clean_interval_close(E_UNBOND));
        assert_eq!(effect.new_total_bonded_atomic, TOTAL_BONDED - RECORD_BONDED);
        // §4.3 identity: refund == debit == bond_floor(record's current holdings).
        assert_eq!(effect.refund_atomic, RECORD_BONDED);
        assert_eq!(effect.refund_atomic, bond_floor(&record_holdings()));
    }

    #[test]
    fn connect_releases_complete_tree_record() {
        // Foundation-shaped record: floor is one FLOOR regardless of shards.
        let holdings = HoldingsDescriptor {
            kind: HoldingsKind::CompleteTree,
            shard_ids: Vec::new(),
        };
        let effect = unbond_connect(
            ARCHIVAL_BOND_FLOOR_ATOMIC,
            &holdings,
            0,
            ARCHIVAL_BOND_FLOOR_ATOMIC,
            TOTAL_BONDED,
            E_UNBOND,
        )
        .expect("complete-tree release");
        // The exit shape is uniform: compact-and-empty, same as slash-to-zero.
        assert_eq!(effect.post_holdings.kind, HoldingsKind::ShardSetCompact);
        assert!(effect.post_holdings.shard_ids.is_empty());
    }

    #[test]
    fn clean_close_leaves_good_through_true() {
        // The load-bearing §4.3 property: appending the clean interval-close
        // changes no `good_through(E)` verdict — backlog emission for served
        // epochs still verifies within `W`.
        let close = clean_interval_close(E_UNBOND);
        let join = 3u64;
        for epoch in [join + 1, E_UNBOND - 1, E_UNBOND, E_UNBOND + 1, u64::MAX] {
            assert_eq!(
                good_through(join, epoch, &[close]),
                good_through(join, epoch, &[]),
                "clean close changed good_through at E = {epoch}"
            );
        }
    }

    #[test]
    fn clean_close_is_inert_next_to_an_open_interval() {
        // Capital flight after a slash: the open interval keeps post-slash
        // epochs bad; the appended close changes nothing.
        let open = BadInterval {
            start_epoch: 10,
            end_exclusive: u64::MAX,
        };
        let with_close = [open, clean_interval_close(E_UNBOND)];
        for epoch in [1, 9, 10, E_UNBOND, E_UNBOND + 7] {
            assert_eq!(
                good_through(0, epoch, &with_close),
                good_through(0, epoch, &[open]),
                "clean close changed good_through at E = {epoch}"
            );
        }
    }

    #[test]
    fn connect_rejects_zero_debit() {
        assert_eq!(
            unbond_connect(0, &record_holdings(), 0, 0, TOTAL_BONDED, E_UNBOND),
            Err(UnbondConnectError::DebitZero)
        );
    }

    #[test]
    fn connect_rejects_debit_mismatch() {
        assert_eq!(
            unbond_connect(
                RECORD_BONDED,
                &record_holdings(),
                0,
                RECORD_BONDED - 1,
                TOTAL_BONDED,
                E_UNBOND,
            ),
            Err(UnbondConnectError::DebitNotRecordTotal)
        );
    }

    #[test]
    fn connect_rejects_broken_floor_invariant() {
        // Record claims 3×FLOOR bonded over 2 shards — §3.2 equality broken.
        let corrupt = 3 * ARCHIVAL_BOND_FLOOR_ATOMIC;
        assert_eq!(
            unbond_connect(
                corrupt,
                &record_holdings(),
                0,
                corrupt,
                TOTAL_BONDED,
                E_UNBOND
            ),
            Err(UnbondConnectError::RecordFloorInvariantBroken)
        );
    }

    #[test]
    fn connect_rejects_total_bonded_underflow() {
        assert_eq!(
            unbond_connect(
                RECORD_BONDED,
                &record_holdings(),
                0,
                RECORD_BONDED,
                RECORD_BONDED - 1,
                E_UNBOND,
            ),
            Err(UnbondConnectError::TotalBondedUnderflow)
        );
    }

    #[test]
    fn connect_rejects_full_interval_log() {
        assert_eq!(
            unbond_connect(
                RECORD_BONDED,
                &record_holdings(),
                MAX_BOND_BAD_INTERVALS,
                RECORD_BONDED,
                TOTAL_BONDED,
                E_UNBOND,
            ),
            Err(UnbondConnectError::IntervalLogFull)
        );
    }

    #[test]
    fn connect_appends_below_the_cap() {
        assert!(unbond_connect(
            RECORD_BONDED,
            &record_holdings(),
            MAX_BOND_BAD_INTERVALS - 1,
            RECORD_BONDED,
            TOTAL_BONDED,
            E_UNBOND,
        )
        .is_ok());
    }

    #[test]
    fn pop_restores_total_bonded_exactly() {
        // Connect ∘ pop is the identity on the global counter (§5 pop twin).
        let effect = ok_connect();
        let restored = unbond_pop(
            effect.post_bonded_total,
            effect.post_holdings.shard_ids.len(),
            Some(effect.interval_close),
            E_UNBOND,
            RECORD_BONDED,
            effect.new_total_bonded_atomic,
        )
        .expect("valid pop");
        assert_eq!(restored, TOTAL_BONDED);
    }

    #[test]
    fn pop_rejects_record_not_exited() {
        assert_eq!(
            unbond_pop(
                1,
                0,
                Some(clean_interval_close(E_UNBOND)),
                E_UNBOND,
                RECORD_BONDED,
                0,
            ),
            Err(UnbondPopError::RecordNotExited)
        );
        assert_eq!(
            unbond_pop(
                0,
                1,
                Some(clean_interval_close(E_UNBOND)),
                E_UNBOND,
                RECORD_BONDED,
                0,
            ),
            Err(UnbondPopError::RecordNotExited)
        );
    }

    #[test]
    fn pop_rejects_missing_or_mismatched_clean_close() {
        assert_eq!(
            unbond_pop(0, 0, None, E_UNBOND, RECORD_BONDED, 0),
            Err(UnbondPopError::MissingCleanClose)
        );
        // Wrong epoch.
        assert_eq!(
            unbond_pop(
                0,
                0,
                Some(clean_interval_close(E_UNBOND + 1)),
                E_UNBOND,
                RECORD_BONDED,
                0,
            ),
            Err(UnbondPopError::MissingCleanClose)
        );
        // An open interval is not a clean close.
        assert_eq!(
            unbond_pop(
                0,
                0,
                Some(BadInterval {
                    start_epoch: E_UNBOND,
                    end_exclusive: u64::MAX,
                }),
                E_UNBOND,
                RECORD_BONDED,
                0,
            ),
            Err(UnbondPopError::MissingCleanClose)
        );
    }

    #[test]
    fn pop_rejects_empty_pre_image() {
        assert_eq!(
            unbond_pop(0, 0, Some(clean_interval_close(E_UNBOND)), E_UNBOND, 0, 0),
            Err(UnbondPopError::PreImageEmpty)
        );
    }

    #[test]
    fn pop_rejects_total_bonded_overflow() {
        assert_eq!(
            unbond_pop(
                0,
                0,
                Some(clean_interval_close(E_UNBOND)),
                E_UNBOND,
                RECORD_BONDED,
                u64::MAX,
            ),
            Err(UnbondPopError::TotalBondedOverflow)
        );
    }
}
