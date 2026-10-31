// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Epoch-close, failure-window, prune, and emission-epoch snapshot types.

use shekyl_archival_retention::{
    BadInterval, CreditPair, EpochCloseBond, EpochCloseShard, ShardClose, ShardCloseWire,
};
/// [`shekyl_archival_slash_open_interval_to_append`]: no append — an open
/// interval already exists (the same-epoch sibling coalesces).
pub const SHEKYL_ARCHIVAL_SLASH_INTERVAL_COALESCE: u8 = 0;
/// [`shekyl_archival_slash_open_interval_to_append`]: append the out-params'
/// open interval.
pub const SHEKYL_ARCHIVAL_SLASH_INTERVAL_APPEND: u8 = 1;
/// [`shekyl_archival_slash_open_interval_to_append`]: marshal error (null
/// pointer with nonzero length, pair-count overflow, or null out-pointer) —
/// the C++ slash writer maps this to a FATAL abort, never a skip.
pub const SHEKYL_ARCHIVAL_SLASH_INTERVAL_ERR_MARSHAL: u8 = 2;

/// [`shekyl_archival_failure_window_slashable`]: the window absorbs this miss —
/// fewer than `m` of the last `n` baseline observations were missed, so the
/// slash does NOT fire (pin §1 "an isolated transient miss does not slash").
pub const SHEKYL_ARCHIVAL_FAILURE_WINDOW_ABSORB: u8 = 0;
/// [`shekyl_archival_failure_window_slashable`]: `m` of the last `n`
/// observations were missed — a confirmed durable absence; proceed to the
/// gate-4 §4.2 slash.
pub const SHEKYL_ARCHIVAL_FAILURE_WINDOW_SLASH: u8 = 1;
/// [`shekyl_archival_failure_window_slashable`] /
/// [`shekyl_archival_failure_window_params`]: marshal error (null pointer, an
/// empty window (`observations_len == 0`), a window longer than `n`,
/// non-descending epochs, or a passed head). The C++ slash scan maps this to a
/// FATAL abort, never a skip in either direction — deciding a slash over a
/// malformed window would be a consensus divergence.
pub const SHEKYL_ARCHIVAL_FAILURE_WINDOW_ERR_MARSHAL: u8 = 2;

/// Why the daemon's settlement rows were refused. Each arm names the row
/// it is about, except a latch that already happened: that refusal is the
/// machine's, and pinning either row would blame the wrong one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementScheduleRefusal {
    /// `dev-settlement-epoch-blocks` is outside the cap's floor.
    Epoch(String),
    /// `dev-archival-reorg-depth` is outside `1..=ARCHIVAL_REORG_DEPTH_BLOCKS`.
    Reorg(String),
    /// The schedule had already latched. No row owns that fact.
    Latched(String),
}

impl SettlementScheduleRefusal {
    /// The option the refusal is about, when one option owns it.
    #[must_use]
    pub const fn row(&self) -> Option<&'static str> {
        match self {
            Self::Epoch(_) => Some("dev-settlement-epoch-blocks"),
            Self::Reorg(_) => Some("dev-archival-reorg-depth"),
            Self::Latched(_) => None,
        }
    }

    /// The rule the diagnostic prints, in the row's terms.
    #[must_use]
    pub fn rule(&self) -> &str {
        match self {
            Self::Epoch(rule) | Self::Reorg(rule) | Self::Latched(rule) => rule,
        }
    }
}

impl std::fmt::Display for SettlementScheduleRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.rule())
    }
}

impl std::error::Error for SettlementScheduleRefusal {}

/// Arms the settlement schedule from the daemon's `dev-` rows
/// (`DAEMON_CONFIG_CUTOVER.md` §4.2): the Rust `main()` calls this at
/// step 6, before the core whose first epoch arithmetic latches the
/// schedule exists. `None` is the genesis pin. The daemon refuses to start
/// on `Err`, naming the row the arm carries.
///
/// # Errors
/// [`SettlementScheduleRefusal`]: a value outside its range, or a schedule
/// already latched.
pub fn arm_settlement_schedule(
    blocks: Option<u64>,
    reorg_cap: Option<u64>,
) -> Result<u64, SettlementScheduleRefusal> {
    shekyl_archival_retention::arm_settlement_epoch_override(blocks, reorg_cap)
        .map_err(|e| in_the_rows_terms(&e))
}

/// The settlement epoch length the daemon's `dev-` rows name, or the
/// row's refusal, with nothing latched: the configuration check's half
/// (`INPUT_GRAMMAR.md` IG-Q59). [`arm_settlement_schedule`] judges by the
/// same check before it latches.
///
/// # Errors
/// [`SettlementScheduleRefusal::Epoch`] and
/// [`SettlementScheduleRefusal::Reorg`]; never `Latched`.
pub fn check_settlement_schedule(
    blocks: Option<u64>,
    reorg_cap: Option<u64>,
) -> Result<u64, SettlementScheduleRefusal> {
    shekyl_archival_retention::check_settlement_epoch_override(blocks, reorg_cap)
        .map(|(target, _)| target)
        .map_err(|e| in_the_rows_terms(&e))
}

/// The rule in the row's terms. The error's own text names the
/// environment variables the wallet engine still reads; this mapping
/// does not.
fn in_the_rows_terms(
    e: &shekyl_archival_retention::SettlementEpochOverrideError,
) -> SettlementScheduleRefusal {
    use shekyl_archival_retention::SettlementEpochOverrideError as E;
    use shekyl_archival_retention::ARCHIVAL_REORG_DEPTH_BLOCKS;
    let epoch_max = shekyl_archival_retention::archival_params().settlement_epoch_blocks;
    match e {
        E::Invalid {
            floor, reorg_cap, ..
        } => SettlementScheduleRefusal::Epoch(format!(
            "an integer from {floor} to {epoch_max}, strictly above the archival reorg depth of {reorg_cap}"
        )),
        E::InvalidReorgCap { .. } => SettlementScheduleRefusal::Reorg(format!(
            "an integer from 1 to {ARCHIVAL_REORG_DEPTH_BLOCKS}"
        )),
        E::ArmedTooLate { latched } => SettlementScheduleRefusal::Latched(format!(
            "the settlement schedule had already latched at {latched} blocks before the daemon recorded the row"
        )),
    }
}

/// Epoch-close computation succeeded.
pub const SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK: u8 = 0;
/// A required pointer was null (or null with nonzero length).
pub const SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_NULL_PTR: u8 = 1;
/// A per-bond interval pair count overflowed `usize`.
pub const SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_LEN_OVERFLOW: u8 = 2;
/// A credit pair referenced a bond/shard index outside the gather arrays.
pub const SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_INDEX_RANGE: u8 = 3;

/// One gathered bond for `shekyl_archival_epoch_close_compute`.
///
/// Layout must match `struct shekyl_archival_epoch_close_bond` in `shekyl_ffi.h`.
///
/// Carries no holdings descriptor (WS-1): the held-and-served set is sourced
/// solely from the serve-credit ledger rows the gather passes as credit
/// pairs, so tip holdings never cross into the work channel.
#[repr(C)]
pub struct ShekylArchivalEpochCloseBond {
    pub join_settlement_epoch: u64,
    /// Flattened `(start_epoch, end_exclusive)` pairs; `2 × bad_intervals_len` u64s.
    pub bad_intervals_ptr: *const u64,
    /// Pair count (not u64 count).
    pub bad_intervals_len: usize,
    pub is_support_complete_tree: u8,
}

/// One gathered shard-registry row for `shekyl_archival_epoch_close_compute`.
///
/// Layout must match `struct shekyl_archival_epoch_close_shard` in `shekyl_ffi.h`.
/// The `freeze_height` / `has_segment` pair is the C++ LMDB validator's
/// segment-keyed reading of a shard's close (CEN-L10); it crosses this ABI
/// as-is and becomes a `ShardClose` via `ShardClose::from_wire` in the
/// decoder below.
#[repr(C)]
pub struct ShekylArchivalEpochCloseShard {
    pub shard_id: u64,
    pub freeze_height: u64,
    /// `0` when no frozen segment row exists (the shard is open; its age
    /// is then zero).
    pub has_segment: u8,
}

/// One serve-credit row as indices into the bond/shard gather arrays.
///
/// Layout must match `struct shekyl_archival_credit_pair` in `shekyl_ffi.h`.
#[repr(C)]
pub struct ShekylArchivalCreditPair {
    pub bond_idx: usize,
    pub shard_idx: usize,
}

/// Owned decode of the as-of-`E` gather arrays, shared by
/// `shekyl_archival_epoch_close_compute` and
/// `shekyl_archival_emission_epoch_work`. One decoder for both consumers of
/// the frozen gather (WS-1 single sourcing, `REWARD_EMISSION_E3_GATING_ROUND.md`
/// §5.5): close and verify cannot diverge on marshaling semantics because
/// there is only one marshaling path to diverge from.
pub(super) struct DecodedEpochRows {
    pub(super) joins: Vec<u64>,
    pub(super) completes: Vec<bool>,
    pub(super) bad: Vec<Vec<BadInterval>>,
    pub(super) shards: Vec<EpochCloseShard>,
    pub(super) pairs: Vec<CreditPair>,
}

impl DecodedEpochRows {
    pub(super) fn bonds(&self) -> Vec<EpochCloseBond<'_>> {
        self.joins
            .iter()
            .zip(&self.completes)
            .zip(&self.bad)
            .map(|((&join, &complete), bad)| EpochCloseBond {
                join_settlement_epoch: join,
                is_support_complete_tree: complete,
                bad_intervals: bad,
            })
            .collect()
    }
}

/// # Safety
///
/// Pointers must satisfy their stated lengths for the duration of the call,
/// including each bond's interval buffer per its embedded lengths.
pub(super) unsafe fn decode_epoch_rows(
    bonds_ptr: *const ShekylArchivalEpochCloseBond,
    bonds_len: usize,
    shards_ptr: *const ShekylArchivalEpochCloseShard,
    shards_len: usize,
    credit_pairs_ptr: *const ShekylArchivalCreditPair,
    credit_pairs_len: usize,
) -> Result<DecodedEpochRows, u8> {
    if (bonds_ptr.is_null() && bonds_len > 0)
        || (shards_ptr.is_null() && shards_len > 0)
        || (credit_pairs_ptr.is_null() && credit_pairs_len > 0)
    {
        return Err(SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_NULL_PTR);
    }

    let raw_bonds: &[ShekylArchivalEpochCloseBond] = if bonds_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(bonds_ptr, bonds_len) }
    };
    let raw_shards: &[ShekylArchivalEpochCloseShard] = if shards_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(shards_ptr, shards_len) }
    };
    let raw_pairs: &[ShekylArchivalCreditPair] = if credit_pairs_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(credit_pairs_ptr, credit_pairs_len) }
    };

    let mut joins = Vec::with_capacity(raw_bonds.len());
    let mut completes = Vec::with_capacity(raw_bonds.len());
    let mut bad = Vec::with_capacity(raw_bonds.len());
    for bond in raw_bonds {
        let Some(intervals) =
            (unsafe { gather_bad_intervals(bond.bad_intervals_ptr, bond.bad_intervals_len) })
        else {
            return Err(if bond.bad_intervals_ptr.is_null() {
                SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_NULL_PTR
            } else {
                SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_LEN_OVERFLOW
            });
        };
        joins.push(bond.join_settlement_epoch);
        completes.push(bond.is_support_complete_tree != 0);
        bad.push(intervals);
    }

    let shards: Vec<EpochCloseShard> = raw_shards
        .iter()
        .map(|s| EpochCloseShard {
            shard_id: s.shard_id,
            close: ShardClose::from_wire(ShardCloseWire {
                has_segment: s.has_segment != 0,
                freeze_height: s.freeze_height,
            }),
        })
        .collect();
    let pairs: Vec<CreditPair> = raw_pairs
        .iter()
        .map(|p| CreditPair {
            bond_idx: p.bond_idx,
            shard_idx: p.shard_idx,
        })
        .collect();

    Ok(DecodedEpochRows {
        joins,
        completes,
        bad,
        shards,
        pairs,
    })
}

/// Decode a flattened `(start, end_exclusive)` interval buffer; `None` on
/// null-with-length or pair-count overflow.
pub(super) unsafe fn gather_bad_intervals(
    ptr: *const u64,
    pair_len: usize,
) -> Option<Vec<BadInterval>> {
    if pair_len == 0 {
        return Some(Vec::new());
    }
    if ptr.is_null() {
        return None;
    }
    let flat_len = pair_len.checked_mul(2)?;
    let flat = unsafe { std::slice::from_raw_parts(ptr, flat_len) };
    Some(
        flat.chunks_exact(2)
            .map(|pair| BadInterval {
                start_epoch: pair[0],
                end_exclusive: pair[1],
            })
            .collect(),
    )
}

/// The M-2/Q7 as-of-`E` consensus snapshot for one claimed settlement epoch
/// (`REWARD_EMISSION_E3_GATING_ROUND.md` §3 item 2;
/// `REWARD_EMISSION_VIN_PLAN.md` §8.0.2(B)).
///
/// Layout must match `struct shekyl_archival_emission_epoch_snapshot` in
/// `shekyl_ffi.h`. Marshaled by value from the frozen `E`-close
/// materialization: the serve-credit rows for `E` (the WS-1 §5 held source),
/// the credited bonds' standing fields, shard freeze heights, and the
/// **persisted** `Σwork(E)` — never the live bond holdings descriptor. Every
/// row is immutable for a claimable `E` (credit acceptance rejects past
/// `H_close(E)`; pruning deletes only below the claim window's floor; reorg
/// pops revert close and credits symmetrically), so a re-gather at any height
/// in the claim window reproduces the close's gather exactly.
///
/// `sigma_work_milli` must be the persisted close output, not a recompute —
/// the close's outcome reaches verify only through the stored denominator.
#[repr(C)]
pub struct ShekylArchivalEmissionEpochSnapshot {
    pub settlement_epoch: u64,
    /// The close-processing height `(E+1) × SEB` the gather froze at (shard-age
    /// operand; must equal the height the close ran at). One above the epoch's
    /// last block, `shekyl_archival_epoch_last_block(E)` = `(E+1) × SEB − 1`.
    pub close_block_height: u64,
    /// Persisted finalized `Σwork(E)` milli — the stored denominator.
    pub sigma_work_milli: u64,
    /// Persisted frozen `budget(E)` atomic — the gate-1 numerator operand,
    /// stored at close beside `Σwork(E)` (the `archival_budget` close row,
    /// `ARCHIVAL_BUDGET_SCHEDULE.md` §5). Like the denominator, always the
    /// stored value, never a recompute: the accrual accumulator is live
    /// state; only the close row is frozen.
    pub budget_atomic: u64,
    pub bonds_ptr: *const ShekylArchivalEpochCloseBond,
    pub bonds_len: usize,
    pub shards_ptr: *const ShekylArchivalEpochCloseShard,
    pub shards_len: usize,
    pub credit_pairs_ptr: *const ShekylArchivalCreditPair,
    pub credit_pairs_len: usize,
    /// Claimant `P`'s index into `bonds`, or `SIZE_MAX` when `P` has no
    /// serve-credit row in `E` (its work is then zero by construction).
    pub claimant_bond_idx: usize,
}

#[cfg(test)]
mod arm_tests {
    use super::{arm_settlement_schedule, check_settlement_schedule};

    /// The daemon's refusal names the row's rule, not an environment
    /// variable. The latch is process-wide, so this test arms nothing
    /// that could succeed; the refusals come before the latch.
    #[test]
    fn a_settlement_lever_off_its_range_is_refused_in_the_rows_terms() {
        let e = arm_settlement_schedule(Some(40), None).unwrap_err();
        assert!(matches!(e, super::SettlementScheduleRefusal::Epoch(_)));
        assert_eq!(e.row(), Some("dev-settlement-epoch-blocks"));
        assert!(
            e.rule().starts_with("an integer from 721 to 10000"),
            "{}",
            e.rule()
        );
        assert!(!e.rule().contains("SHEKYL_"), "{}", e.rule());
        let e = arm_settlement_schedule(None, Some(0)).unwrap_err();
        assert!(matches!(e, super::SettlementScheduleRefusal::Reorg(_)));
        assert_eq!(e.row(), Some("dev-archival-reorg-depth"));
        assert!(
            e.rule().starts_with("an integer from 1 to "),
            "{}",
            e.rule()
        );
    }

    /// The configuration check's half: the same refusals in the same
    /// terms, and a valid pair is a value, never a latch, however many
    /// times it is asked and whatever this process latched.
    #[test]
    fn the_check_refuses_as_the_arm_does_and_latches_nothing() {
        let a = arm_settlement_schedule(Some(40), None).unwrap_err();
        let c = check_settlement_schedule(Some(40), None).unwrap_err();
        assert_eq!(a, c);
        let a = arm_settlement_schedule(None, Some(0)).unwrap_err();
        let c = check_settlement_schedule(None, Some(0)).unwrap_err();
        assert_eq!(a, c);
        assert_eq!(check_settlement_schedule(Some(800), Some(10)), Ok(800));
        assert_eq!(check_settlement_schedule(Some(900), Some(10)), Ok(900));
        assert_eq!(
            check_settlement_schedule(None, None),
            Ok(shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS)
        );
    }
}
