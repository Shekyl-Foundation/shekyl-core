// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The archival transition's fixture-side cases (DRS-E4 commit 4). Every
//! case here says which of rule 50's exemptions admits it, because the
//! transition's production witness lives elsewhere and a fixture case has
//! to earn its place against that:
//!
//! - **Exemption 1 — pure arithmetic on plain values.** The slash fold over
//!   a constructed [`BondRecord`] and the shard-close search over a fold
//!   sequence: functions of their arguments, no chain asserted.
//! - **Exemption 3 — a state the store cannot hold.** CEN-L8's overflow and
//!   CEN-L9's shard-not-held / bonded-underflow arms, a non-monotone fold,
//!   and a compact holding with a repeated shard (the wire decoder refuses
//!   it before any rule reads the block, so L7's arm there is a belt behind
//!   the decoder). These stay on the fixture permanently: no production
//!   path produces the state, and the belt's job is to refuse it anyway.
//!
//! What is **not** here any more: the single-block arms over a view with no
//! bonds — a join's insert, a same-block credit, the refusals of a post for
//! a persona with no record, the accrual. A `MockChain` asserting "this
//! persona has no bond" is a view with no archival state asserting a fact
//! about a chain; rule 50's third job was minted for exactly that. Their
//! witness is `shekyl-chain-ingest::scenario_archival_tests`: posts a
//! persona's keys built and signed, riding the driver's real spend, judged
//! over the redb store's view. Nor the multi-block arms — a release, a
//! reinstate, a second join, a credit or a claim for a persona whose
//! record an earlier block wrote: since DRS-E4 commit 5 the store writes
//! the record, and those arms are witnessed over redb (the scenario
//! driver's chain in `scenario_archival_tests`; the store's own
//! `archival_write_tests` for the claim, whose emission body the driver
//! does not produce; the `emission-claim` corpus vector for a settled
//! claim that pays). The same-block pile that stood in for them until the
//! writer landed is gone with it.

use super::*;
use crate::harness::assert_refused;
use crate::harness::fixture::{candidate_on, chain_of, listed, recorded, root};
use crate::rules::miner::closed_shards_before;
use crate::view::RecordedBlock;
use shekyl_archival_retention::ARCHIVAL_BOND_FLOOR_ATOMIC;
use shekyl_crypto_pq::multisig::SINGLE_KEY_CANONICAL_LEN;
use shekyl_types::archival::BadInterval;
use shekyl_types::archival::{HeldShard, SlashLogEntry, SlashedHolding};
use shekyl_types::{ArchivalLength, BlockCount, SHARD_LENGTH};
use shekyl_wire::transaction::{
    BondPost, BondPostKind as WireKind, Holdings as WireHoldings, Input,
};
use shekyl_wire::Transaction;

const P1: [u8; 32] = [0xa1; 32];
const FLOOR: u64 = ARCHIVAL_BOND_FLOOR_ATOMIC;

fn persona(p: [u8; 32]) -> PCanonicalId {
    PCanonicalId::from_bytes(p)
}

fn post(p: PCanonicalId, kind: WireKind, holdings: WireHoldings, total: u64, debit: u64) -> Input {
    Input::BondPost(Box::new(BondPost {
        hybrid_public_key: vec![0xb1; SINGLE_KEY_CANONICAL_LEN],
        p_canonical_id: p,
        kind,
        holdings,
        bonded_total_atomic: total,
        bond_credit: 0,
        bond_debit: debit,
    }))
}

/// A JoinMarket for `p` holding `shards` compactly, bonded at their floor.
fn join(p: PCanonicalId, shards: &[u64]) -> Input {
    post(
        p,
        WireKind::JoinMarket {
            bond_spend_pk: vec![0xb5; SINGLE_KEY_CANONICAL_LEN],
            endpoint: [0xe0; 32],
        },
        WireHoldings::ShardSetCompact(shards.to_vec()),
        FLOOR * shards.len() as u64,
        0,
    )
}

/// A body carrying exactly `inputs`.
fn body_with(inputs: Vec<Input>) -> Transaction {
    let mut tx = listed([0x77; 32]);
    tx.prefix.inputs = inputs;
    tx
}

const INFLOW: AtomicUnits = AtomicUnits::from_raw(1_234);

/// Run the transition for `bodies` on a short honest-empty chain.
fn run(bodies: Vec<Transaction>) -> Verdict<ArchivalDelta> {
    let chain = chain_of(3);
    let candidate = candidate_on(&chain, bodies);
    let connecting = BlockHeight::from_raw(3);
    chain.with_view(|view| {
        let mut coverage = RuleCoverage::EMPTY;
        let verdict = transition(
            &view,
            connecting,
            &RuleSet::GENESIS,
            &candidate,
            INFLOW,
            &mut coverage,
        )
        .expect("an honest-empty view neither faults nor is corrupt");
        if verdict.is_ok() {
            assert!(
                coverage.contains(CenRow::L7),
                "a passing transition records L7"
            );
        }
        verdict
    })
}

fn at(slot: usize, input: usize) -> Locus {
    Locus::Input {
        slot: TxSlot::Listed(slot),
        input,
    }
}

// ---- exemption 3: a holding the wire refuses to carry -------------------

/// Exemption 3. `shekyl_wire::Holdings::read` refuses a repeated shard id,
/// so no block reaching `validate` carries one; the transition's arm is a
/// belt behind the decoder and the fixture is the only place it can be
/// reached.
#[test]
fn a_compact_join_with_a_duplicate_shard_is_refused() {
    assert_refused(
        run(vec![body_with(vec![join(persona(P1), &[3, 3])])]),
        CenRow::L7,
        at(0, 0),
    );
}

// ---- exemption 3: CEN-L8 and CEN-L9's corrupt-view arms -----------------

/// Exemption 3. CEN-L8's overflow clause: the accrual fold is total over
/// `checked_add` and its one failure is a [`Corrupt`], never a wrap. No
/// store holds an accrual one unit under `u64::MAX`; the arm is reached
/// only by construction.
#[test]
fn l8_an_accrual_that_overflows_is_a_corrupt_view() {
    let epoch = SettlementEpoch::from_raw(4);
    assert_eq!(
        accrue(
            AtomicUnits::from_raw(u64::MAX),
            AtomicUnits::from_raw(1),
            epoch
        ),
        Err(Corrupt::AccrualOverflow { epoch })
    );
    assert_eq!(
        accrue(AtomicUnits::from_raw(40), AtomicUnits::from_raw(2), epoch),
        Ok(AtomicUnits::from_raw(42))
    );
}

// ---- the slash fold: exemption 3 (L9) and exemption 1 (the fold) --------

/// A constructed record: plain values the fold cases below are functions
/// of. Its keys are fixture bytes because nothing here derives from them.
fn record_holding(shards: &[u64], add_epoch: u64) -> BondRecord {
    BondRecord {
        hybrid_pubkey: vec![0xb1; 4],
        bond_spend_pk: vec![0xb5; 4],
        endpoint: [0xe0; 32],
        join_settlement_epoch: SettlementEpoch::from_raw(add_epoch),
        bonded_total: AtomicUnits::from_raw(FLOOR * shards.len() as u64),
        holdings: Holdings::shard_set(
            shards
                .iter()
                .map(|&shard| HeldShard {
                    shard: ShardId::from_raw(shard),
                    add_epoch: SettlementEpoch::from_raw(add_epoch),
                })
                .collect(),
        )
        .expect("distinct shards under the cap"),
        bad_intervals: Vec::new(),
        claimed_settlement_epochs: Vec::new(),
        first_paying_emission_height: None,
    }
}

/// Exemption 3. CEN-L9's record-shaped invariants (a shard the record does
/// not hold; a `bonded_total` below one floor) are [`Corrupt`] here — a
/// `BondRecord` the store cannot hold, because the transition that writes
/// one never produces it — and the interval decision cannot fail: it is an
/// `Option` the fold answers, not a fault it raises.
#[test]
fn l9_slashing_a_shard_the_record_does_not_hold_is_a_corrupt_view() {
    let p = persona(P1);
    let epoch = SettlementEpoch::from_raw(6);
    let mut record = record_holding(&[3], 2);
    assert_eq!(
        apply_slash(p, &mut record, ShardId::from_raw(4), epoch),
        Err(Corrupt::BondRecordInvariant {
            persona: p,
            which: RecordInvariant::ShardNotHeld,
        })
    );
    // Untouched by the refusal.
    assert_eq!(record, record_holding(&[3], 2));

    let mut broke = record_holding(&[3], 2);
    broke.bonded_total = AtomicUnits::ZERO;
    assert_eq!(
        apply_slash(p, &mut broke, ShardId::from_raw(3), epoch),
        Err(Corrupt::BondRecordInvariant {
            persona: p,
            which: RecordInvariant::BondedUnderflow,
        })
    );
}

/// Exemption 1. The fold's arithmetic over a constructed record: one shard
/// out, one floor burned, one interval opened, a same-epoch second slash
/// coalescing into it.
#[test]
fn a_slash_removes_the_shard_opens_one_interval_and_burns_one_floor() {
    let p = persona(P1);
    let epoch = SettlementEpoch::from_raw(6);
    let mut record = record_holding(&[3, 5], 2);
    let first = apply_slash(p, &mut record, ShardId::from_raw(3), epoch).expect("held");
    assert_eq!(
        first,
        Slash {
            entry: SlashLogEntry {
                persona: p,
                shard: ShardId::from_raw(3),
                epoch,
                holding: SlashedHolding::Shard {
                    add_epoch: SettlementEpoch::from_raw(2),
                },
            },
            burned: AtomicUnits::from_raw(FLOOR),
        }
    );
    assert_eq!(record.bonded_total, AtomicUnits::from_raw(FLOOR));
    assert_eq!(record.holdings, record_holding(&[5], 2).holdings);
    assert_eq!(
        record.bad_intervals,
        vec![BadInterval {
            start_epoch: 6,
            end_exclusive: u64::MAX,
        }]
    );
    // A second slash in the same epoch coalesces into the open interval.
    apply_slash(p, &mut record, ShardId::from_raw(5), epoch).expect("held");
    assert_eq!(record.bonded_total, AtomicUnits::ZERO);
    assert_eq!(record.holdings, emptied());
    assert_eq!(record.bad_intervals.len(), 1);
}

/// Exemption 1. The complete-tree arm of the same fold.
#[test]
fn a_complete_tree_slash_demotes_the_record_to_an_empty_compact_one() {
    let p = persona(P1);
    let mut record = record_holding(&[], 2);
    record.holdings = Holdings::CompleteTree;
    record.bonded_total = AtomicUnits::from_raw(FLOOR);
    let slash = apply_slash(
        p,
        &mut record,
        ShardId::from_raw(0),
        SettlementEpoch::from_raw(6),
    )
    .expect("a complete tree holds every shard");
    assert_eq!(slash.entry.holding, SlashedHolding::CompleteTree);
    assert_eq!(record.holdings, emptied());
    assert_eq!(record.bonded_total, AtomicUnits::ZERO);
}

// ---- shard close heights: exemption 1 (the search) and 3 (the cut) ------

/// One chain, both close tests. h1 reaches `W` (shard 0 closes), h3 reaches
/// `2W + 4` (shard 1 closes), h4 adds nothing. The height search and
/// `shard_close` read this same chain, so the two cannot drift apart.
fn chain_closing_two_shards() -> crate::harness::MockChain {
    let w = SHARD_LENGTH.to_raw();
    let folds = [0, w, w + 3, 2 * w + 4, 2 * w + 4];
    folds
        .into_iter()
        .enumerate()
        .fold(crate::harness::MockChain::default(), |chain, (h, fold)| {
            chain.push(
                RecordedBlock {
                    cumulative_archival_len: ArchivalLength::from_raw(fold),
                    ..recorded(1_000 + h as u64)
                },
                root(0x11),
            )
        })
}

/// Exemption 1. `SCC-Q3` on `SHT-Q2`'s partition: the height whose
/// archival fold first reached a shard's end, found by binary search over
/// `cumulative_archival_len` — a function of the fold sequence, which is
/// the only thing the `MockChain` here carries.
#[test]
fn shard_close_height_is_the_block_whose_fold_reached_the_shards_end() {
    let chain = chain_closing_two_shards();
    let parent = BlockHeight::from_raw(4);
    chain.with_view(|view| {
        assert_eq!(
            shard_close_height(&view, ShardId::from_raw(0), parent),
            Ok(BlockHeight::from_raw(1))
        );
        assert_eq!(
            shard_close_height(&view, ShardId::from_raw(1), parent),
            Ok(BlockHeight::from_raw(3))
        );
        assert_eq!(
            closed_shards_before(&view, BlockHeight::from_raw(5))
                .map(shekyl_economics::ClosedShardCount::get),
            Ok(2)
        );
        // Shard 2 is open through the parent: no height places its close,
        // and the search says so rather than returning the tip.
        assert_eq!(
            shard_close_height(&view, ShardId::from_raw(2), parent),
            Err(ViewRead::Corrupt(Corrupt::ShardCloseUnplaced {
                shard: ShardId::from_raw(2),
                at: parent,
            }))
        );
    });
}

/// Exemption 1. `SHT-Q1`'s falsifier (i), run on `g(age)`'s operand
/// (`SHT-8` item 2; `ARCHIVAL_SHARD_COUNT_CUTOVER.md` §F's `g(age)` row).
/// The operand is the height search, read through one [`ClosedUniverse`]:
/// every shard below the count is `ClosedAt` exactly
/// [`shard_close_height`] of that universe's parent, and the next shard —
/// at the count, fold short of its end — is `Open`. Age of that operand
/// is the retention falsifier
/// `shard_close_age_is_zero_while_open_and_the_fold_height_once_closed`.
#[test]
fn shard_close_is_the_fold_height_below_the_universe_and_open_at_it() {
    use shekyl_archival_retention::ShardClose;
    let chain = chain_closing_two_shards();
    // The same subtraction `closed_shards_before` and `ClosedUniverse::before`
    // make: connecting 5 reads parent 4, the parent the height search above
    // names. Two shards are closed on this chain.
    let connecting = BlockHeight::from_raw(5);
    let parent = BlockHeight::from_raw(
        connecting
            .to_raw()
            .checked_sub(1)
            .expect("connecting is past genesis"),
    );
    chain.with_view(|view| {
        let universe = ClosedUniverse::before(&view, connecting).expect("parent is recorded");
        assert_eq!(
            universe.count().get(),
            closed_shards_before(&view, connecting)
                .expect("parent is recorded")
                .get()
        );
        assert_eq!(universe.count().get(), 2);
        for shard in 0..universe.count().get() {
            let close = shard_close(&view, ShardId::from_raw(shard), &universe)
                .expect("a shard below the count has a close height");
            let ShardClose::ClosedAt(closed_at) = close else {
                panic!("shard {shard} is below the closed universe");
            };
            assert_eq!(
                shard_close_height(&view, ShardId::from_raw(shard), parent)
                    .expect("the search places the same height"),
                closed_at
            );
        }
        let open = universe.count().get();
        assert_eq!(
            shard_close(&view, ShardId::from_raw(open), &universe).expect("open has no search"),
            ShardClose::Open
        );
    });
}

/// Exemption 1. SO-D8 §8.0 input 4's fixture, run on the predicate CEN-J15
/// bounds a held shard by. On `chain_closing_two_shards` shard 0 closes
/// at `c = 1`; with `reorg_cap = 2` it is not closed-and-final for
/// `at < 3` — `at = c` included, the close being the newest block — and
/// is from `at = 3` on. Shard 2 is open through every height and never
/// is. Monotone in `at` by the same walk. The predicate reads the fold
/// alone, so the chain here carries nothing but the fold, and a cap the
/// close height cannot carry is not final anywhere.
#[test]
fn closed_and_final_is_false_through_the_cap_and_true_from_it() {
    let chain = chain_closing_two_shards();
    let cap = BlockCount::from_raw(2);
    chain.with_view(|view| {
        let judged = |shard: u64, at: u64| {
            closed_and_final(
                &view,
                ShardId::from_raw(shard),
                BlockHeight::from_raw(at),
                cap,
            )
            .expect("every height here is recorded")
        };
        // Shard 0 closed at 1: open at 0, closed-not-final at 1 and 2,
        // final at 3 and 4.
        assert_eq!(
            (0..5).map(|at| judged(0, at)).collect::<Vec<bool>>(),
            [false, false, false, true, true]
        );
        // Shard 1 closed at 3: final at none of the recorded heights.
        assert_eq!(
            (0..5).map(|at| judged(1, at)).collect::<Vec<bool>>(),
            [false; 5]
        );
        // Shard 2 never closes.
        assert_eq!(
            (0..5).map(|at| judged(2, at)).collect::<Vec<bool>>(),
            [false; 5]
        );
        // Cap zero is "closed": shard 1 is final the block it closes.
        assert!(closed_and_final(
            &view,
            ShardId::from_raw(1),
            BlockHeight::from_raw(3),
            BlockCount::from_raw(0),
        )
        .expect("recorded"));
        // A cap the close height cannot carry: not final at any height.
        assert!(!closed_and_final(
            &view,
            ShardId::from_raw(0),
            BlockHeight::from_raw(4),
            BlockCount::from_raw(u64::MAX),
        )
        .expect("recorded"));
    });
}

/// The gather's universe is the per-shard predicate taken over every shard
/// at once (`SO-D11f`): for a block connecting at `at + 1`, whose parent
/// is `at`, [`ClosedUniverse::final_before`] counts exactly the shards
/// [`closed_and_final`] accepts at `at` — at every height, for the caps
/// that put the boundary before, on and after each close, and a chain not
/// yet a cap deep counts none. The two were written apart; this holds them
/// to one arithmetic.
#[test]
fn the_final_universe_counts_the_shards_the_predicate_accepts() {
    use shekyl_archival_retention::ShardClose;
    let chain = chain_closing_two_shards();
    chain.with_view(|view| {
        for cap in [0u64, 1, 2, 3, 7] {
            let cap = BlockCount::from_raw(cap);
            for at in 0..5u64 {
                let accepted = (0..3u64)
                    .filter(|shard| {
                        closed_and_final(
                            &view,
                            ShardId::from_raw(*shard),
                            BlockHeight::from_raw(at),
                            cap,
                        )
                        .expect("recorded")
                    })
                    .count();
                let universe =
                    ClosedUniverse::final_before(&view, BlockHeight::from_raw(at + 1), cap)
                        .expect("recorded");
                assert_eq!(
                    universe.count().get(),
                    u64::try_from(accepted).expect("fits"),
                    "cap {cap:?}, parent {at}"
                );
            }
        }
        // Shards close in order, so the accepted set is a prefix and the
        // count names it; cap 2 at parent 3 is shard 0 alone.
        let universe =
            ClosedUniverse::final_before(&view, BlockHeight::from_raw(4), BlockCount::from_raw(2))
                .expect("recorded");
        assert_eq!(universe.count().get(), 1);
        assert!(matches!(
            shard_close(&view, ShardId::from_raw(0), &universe).expect("recorded"),
            ShardClose::ClosedAt(h) if h == BlockHeight::from_raw(1)
        ));
        assert_eq!(
            shard_close(&view, ShardId::from_raw(1), &universe).expect("recorded"),
            ShardClose::Open,
            "closed at 3 and not yet final: outside the universe"
        );
    });
}

/// Exemption 3. A fold that fell back below a shard's end after reaching
/// it — a sequence the store's monotone `cumulative_archival_len` cannot
/// hold — is the cut the search cannot verify (SI-13): height 0 reached the end, the later
/// heights fell back below it, the search steps past the fallen middle,
/// lands on the tip, and finds the fold there short of the end — so it
/// refuses rather than name the tip (or height 0, which it never probed
/// as such) as the close.
#[test]
fn shard_close_height_refuses_a_fold_that_is_not_monotone_at_the_cut() {
    let w = SHARD_LENGTH.to_raw();
    let folds = [w, w - 1, w - 1];
    let chain =
        folds
            .iter()
            .enumerate()
            .fold(crate::harness::MockChain::default(), |chain, (h, &fold)| {
                chain.push(
                    RecordedBlock {
                        cumulative_archival_len: ArchivalLength::from_raw(fold),
                        ..recorded(1_000 + h as u64)
                    },
                    root(0x11),
                )
            });
    chain.with_view(|view| {
        assert_eq!(
            shard_close_height(&view, ShardId::from_raw(0), BlockHeight::from_raw(2)),
            Err(ViewRead::Corrupt(Corrupt::ShardCloseUnplaced {
                shard: ShardId::from_raw(0),
                at: BlockHeight::from_raw(2),
            }))
        );
    });
}
