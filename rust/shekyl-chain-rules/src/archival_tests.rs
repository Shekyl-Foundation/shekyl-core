// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The archival transition over an honest-empty chain (DRS-E4 commit 4):
//! what one block's posts, credits and claims do to the delta, what CEN-L7
//! refuses and where, and the two record-level folds CEN-L8 and CEN-L9
//! pin by construction. The slash scan and the epoch close over a
//! populated archival state are commit 5's scenario driver (E4 §5.2: no
//! `Mock*` archival state; the driver runs the production stack).

use super::*;
use crate::harness::assert_refused;
use crate::harness::fixture::{candidate_on, chain_of, listed, recorded, root, serve_credit_vin};
use crate::view::RecordedBlock;
use shekyl_archival_retention::{
    p_canonical_id_from_hybrid_pubkey, HoldingsDescriptor, HoldingsKind, ShardSet,
};
use shekyl_crypto_pq::multisig::{SINGLE_KEY_CANONICAL_LEN, SINGLE_SIG_CANONICAL_LEN};
use shekyl_types::archival::BadInterval;
use shekyl_types::{ArchivalLength, SHARD_LENGTH};
use shekyl_wire::Transaction;

const P1: [u8; 32] = [0xa1; 32];
const FLOOR: u64 = ARCHIVAL_BOND_FLOOR_ATOMIC;

fn persona(p: [u8; 32]) -> PCanonicalId {
    PCanonicalId::from_bytes(p)
}

/// The emission vin's persona is derived from its pubkey; `claimant`
/// returns the persona a `[fill; LEN]` pubkey derives to so a JoinMarket
/// can precede the claim.
fn claimant(p_pubkey_fill: u8) -> PCanonicalId {
    p_canonical_id_from_hybrid_pubkey(&vec![p_pubkey_fill; SINGLE_KEY_CANONICAL_LEN])
}

fn emission_vin(p_pubkey_fill: u8, epochs: &[u64]) -> Input {
    use shekyl_archival_retention::{
        ArchivalRewardEmissionVin, MembershipOnlyBacking, ShardWorkEntry, WorkEpochClaim,
    };
    let vin = ArchivalRewardEmissionVin {
        p_pubkey: vec![p_pubkey_fill; SINGLE_KEY_CANONICAL_LEN],
        holdings: HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(vec![7]).expect("one shard"),
        },
        settlement_epochs: epochs.to_vec(),
        work_claim: epochs
            .iter()
            .map(|&epoch| WorkEpochClaim {
                epoch,
                shard_entries: vec![ShardWorkEntry {
                    shard_id: 7,
                    serve_credit_bit: true,
                    scarcity_micro: 1_000,
                }],
            })
            .collect(),
        backing: MembershipOnlyBacking {
            proof: vec![0xee; 64],
            pseudo_out: [0x22; 32],
            backing_pubkey: vec![0xb2; SINGLE_KEY_CANONICAL_LEN],
            tree_depth: 3,
        },
        reward_amount_plain: epochs.iter().map(|_| 1_000_000).collect(),
        auth_backing: vec![0xc3; SINGLE_SIG_CANONICAL_LEN],
        auth_claim: vec![0xd4; SINGLE_SIG_CANONICAL_LEN],
    };
    Input::ArchivalRewardEmission {
        canonical_bytes: vin.serialize().expect("an emission vin serializes"),
    }
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

fn other(p: PCanonicalId, kind: u8, holdings: WireHoldings, debit: u64) -> Input {
    post(p, WireKind::Other(kind), holdings, 0, debit)
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

fn open_epoch() -> SettlementEpoch {
    SettlementEpoch::from_raw(SettlementSchedule::GENESIS.epoch_at_height(3))
}

// ---- the JoinMarket ---------------------------------------------------

#[test]
fn a_join_market_inserts_a_record_joining_at_the_open_epoch() {
    let p = persona(P1);
    let delta = run(vec![body_with(vec![join(p, &[3, 5])])]).expect("passes");
    let epoch = open_epoch();
    let [write] = delta.records() else {
        panic!("one record write, got {:?}", delta.records());
    };
    assert_eq!(write.persona(), &p);
    assert_eq!(write.kind(), RecordWriteKind::Insert);
    let record = write.record();
    assert_eq!(record.join_settlement_epoch, epoch);
    assert_eq!(record.bonded_total, AtomicUnits::from_raw(2 * FLOOR));
    assert_eq!(record.endpoint, [0xe0; 32]);
    assert_eq!(record.bond_spend_pk, vec![0xb5; SINGLE_KEY_CANONICAL_LEN]);
    assert_eq!(
        record.holdings,
        Holdings::shard_set(vec![
            HeldShard {
                shard: ShardId::from_raw(3),
                add_epoch: epoch,
            },
            HeldShard {
                shard: ShardId::from_raw(5),
                add_epoch: epoch,
            },
        ])
        .expect("two shards")
    );
    assert!(record.bad_intervals.is_empty());
    assert!(record.claimed_settlement_epochs.is_empty());
    assert_eq!(record.first_paying_emission_height, None);
    // Nothing else moved on an honest-empty chain at height 3.
    assert!(delta.serve_credits().is_empty());
    assert!(delta.slashes().is_empty());
    assert_eq!(delta.slash_watermark(), None);
    assert_eq!(delta.close(), None);
}

#[test]
fn a_complete_tree_join_is_recorded_as_one() {
    let p = persona(P1);
    let delta = run(vec![body_with(vec![post(
        p,
        WireKind::JoinMarket {
            bond_spend_pk: vec![0xb5; SINGLE_KEY_CANONICAL_LEN],
            endpoint: [0xe0; 32],
        },
        WireHoldings::CompleteTree,
        FLOOR,
        0,
    )])])
    .expect("passes");
    assert_eq!(delta.records()[0].record().holdings, Holdings::CompleteTree);
}

#[test]
fn a_second_join_for_the_same_persona_is_refused_at_its_input() {
    let p = persona(P1);
    assert_refused(
        run(vec![
            body_with(vec![join(p, &[3])]),
            body_with(vec![serve_credit_vin(P1, 3, 0), join(p, &[4])]),
        ]),
        CenRow::L7,
        at(1, 1),
    );
}

#[test]
fn a_compact_join_holding_nothing_is_refused() {
    assert_refused(
        run(vec![body_with(vec![join(persona(P1), &[])])]),
        CenRow::L7,
        at(0, 0),
    );
}

#[test]
fn a_compact_join_with_a_duplicate_shard_is_refused() {
    assert_refused(
        run(vec![body_with(vec![join(persona(P1), &[3, 3])])]),
        CenRow::L7,
        at(0, 0),
    );
}

// ---- serve credits -----------------------------------------------------

#[test]
fn a_serve_credit_after_a_join_in_the_same_block_is_keyed() {
    let p = persona(P1);
    let delta = run(vec![body_with(vec![
        join(p, &[3]),
        serve_credit_vin(P1, 3, 0),
    ])])
    .expect("passes");
    assert_eq!(
        delta.serve_credits(),
        &[ServeCreditKey {
            persona: p,
            shard: ShardId::from_raw(3),
            epoch: SettlementEpoch::ZERO,
        }]
    );
}

#[test]
fn a_serve_credit_for_a_persona_with_no_bond_is_refused_at_its_input() {
    assert_refused(
        run(vec![
            body_with(vec![join(persona(P1), &[3])]),
            body_with(vec![serve_credit_vin([0xa2; 32], 3, 0)]),
        ]),
        CenRow::L7,
        at(1, 0),
    );
}

// ---- Release and Reinstate --------------------------------------------

#[test]
fn a_release_empties_the_record_and_closes_the_interval_cleanly() {
    let p = persona(P1);
    let delta = run(vec![body_with(vec![
        join(p, &[3, 5]),
        other(
            p,
            PostKind::Release as u8,
            WireHoldings::CompleteTree,
            2 * FLOOR,
        ),
    ])])
    .expect("passes");
    let [write] = delta.records() else {
        panic!("one record write");
    };
    // The join's insert survives the release's update: one write, inserted.
    assert_eq!(write.kind(), RecordWriteKind::Insert);
    let record = write.record();
    assert_eq!(record.bonded_total, AtomicUnits::ZERO);
    assert_eq!(record.holdings, emptied());
    let epoch = open_epoch().to_raw();
    assert_eq!(
        record.bad_intervals,
        vec![BadInterval {
            start_epoch: epoch,
            end_exclusive: epoch,
        }]
    );
}

#[test]
fn a_release_whose_debit_is_not_the_record_total_is_refused() {
    let p = persona(P1);
    assert_refused(
        run(vec![body_with(vec![
            join(p, &[3, 5]),
            other(
                p,
                PostKind::Release as u8,
                WireHoldings::CompleteTree,
                FLOOR,
            ),
        ])]),
        CenRow::L7,
        at(0, 1),
    );
}

#[test]
fn a_release_for_a_persona_with_no_bond_is_refused() {
    assert_refused(
        run(vec![body_with(vec![other(
            persona(P1),
            PostKind::Release as u8,
            WireHoldings::CompleteTree,
            FLOOR,
        )])]),
        CenRow::L7,
        at(0, 0),
    );
}

#[test]
fn a_reinstate_with_no_open_interval_is_refused() {
    let p = persona(P1);
    assert_refused(
        run(vec![body_with(vec![
            join(p, &[3]),
            other(
                p,
                PostKind::Reinstate as u8,
                WireHoldings::ShardSetCompact(vec![3]),
                0,
            ),
        ])]),
        CenRow::L7,
        at(0, 1),
    );
}

#[test]
fn a_reinstate_for_a_persona_with_no_bond_is_refused() {
    assert_refused(
        run(vec![body_with(vec![other(
            persona(P1),
            PostKind::Reinstate as u8,
            WireHoldings::ShardSetCompact(vec![3]),
            0,
        )])]),
        CenRow::L7,
        at(0, 0),
    );
}

#[test]
fn an_unknown_post_kind_is_refused() {
    let p = persona(P1);
    assert_refused(
        run(vec![body_with(vec![
            join(p, &[3]),
            other(p, 9, WireHoldings::CompleteTree, 0),
        ])]),
        CenRow::L7,
        at(0, 1),
    );
}

// ---- claims -------------------------------------------------------------

#[test]
fn a_claim_for_an_epoch_not_yet_settled_is_refused() {
    let p = claimant(0xc1);
    // The open epoch is not settled; a claim on it is `NotSettled`.
    let epoch = open_epoch().to_raw();
    assert_refused(
        run(vec![body_with(vec![
            join(p, &[7]),
            emission_vin(0xc1, &[epoch]),
        ])]),
        CenRow::L7,
        at(0, 1),
    );
}

#[test]
fn a_claim_by_a_persona_with_no_bond_is_refused() {
    assert_refused(
        run(vec![body_with(vec![emission_vin(0xc1, &[0])])]),
        CenRow::L7,
        at(0, 0),
    );
}

// ---- the accrual --------------------------------------------------------

#[test]
fn the_accrual_is_the_open_epochs_post_image() {
    let delta = run(Vec::new()).expect("passes");
    assert_eq!(
        delta.accrual(),
        Accrual {
            epoch: open_epoch(),
            total: INFLOW,
        }
    );
}

/// CEN-L8's overflow clause, by construction: the accrual fold is total
/// over `checked_add` and its one failure is a [`Corrupt`], never a wrap.
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

// ---- the slash fold -----------------------------------------------------

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

/// CEN-L9, by construction: the record-shaped `FATAL`s of the C++ slash
/// (a shard the record does not hold; a `bonded_total` below one floor)
/// are [`Corrupt`] here, and the interval decision cannot fail — it is an
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

// ---- shard close heights -----------------------------------------------

/// `SCC-Q3` on `SHT-Q2`'s partition: the height whose archival fold
/// first reached a shard's end, found by binary search over
/// `cumulative_archival_len`.
#[test]
fn shard_close_height_is_the_block_whose_fold_reached_the_shards_end() {
    let w = SHARD_LENGTH.to_raw();
    // Fold through h: h1 reaches W (shard 0 closes), h3 reaches 2W + 4
    // (shard 1 closes), h4 adds nothing.
    let folds = [0, w, w + 3, 2 * w + 4, 2 * w + 4];
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

/// A fold that fell back below a shard's end after reaching it is the cut
/// the search cannot verify (SI-13): height 0 reached the end, the later
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
