// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `BlockSpace` against the pool it models: the reference window, the fee
//! fixed at build, and each cohort walk against the same walk over every
//! transaction in `shekyl-mempool`'s own order.

use super::*;
use shekyl_chain_store::pool::ReceivedHour;
use shekyl_curve_tree::PROOF_VALIDITY_HORIZON;
use shekyl_economics::TxVolume;

use crate::engine::SimParams;
use shekyl_mempool::policy::AdmissionRank;
use shekyl_types::{TxHash, UnixSeconds};

/// The point a block is priced at, on `run`'s parameter sets.
fn at(run: &SimParams) -> FeePoint<'_> {
    let params = run.economic();
    FeePoint {
        already_generated: 0,
        volume: TxVolume::per_block(params.tx_volume_baseline),
        long_term_median: params.full_reward_zone,
        sigma_scaled: 0,
        burn_pct_scaled: 0,
        chain_leaves: 1,
        params,
        relay: run.relay(),
    }
}

fn baseline_tx() -> OrdinaryTx {
    OrdinaryTx {
        fee_atomic: 3_000_000_000,
        weight: 14_643,
    }
}

/// The running total against the cohorts it stands for.
fn assert_total_is_the_pool(space: &BlockSpace) {
    let pooled: u64 = space.waiting.iter().map(|cohort| cohort.count).sum();
    assert_eq!(
        space.waiting(),
        pooled,
        "the running total is the pool's sum"
    );
}

/// A cohort built at an arbitrary block, for the walks below.
fn cohort(fee: u64, weight: u64, count: u64, hour: u64) -> Cohort {
    Cohort {
        arrived: 1_000,
        reference: 993,
        hour,
        fee,
        weight,
        count,
    }
}

fn space_of(cohorts: &[Cohort]) -> BlockSpace {
    BlockSpace::holding(cohorts)
}

/// A hash per transaction that does not follow the build order.
fn hash_of(cohort: usize, index: u64) -> TxHash {
    let mut bytes = [0u8; 32];
    let mixed =
        (index.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (cohort as u64).rotate_left(17)).to_le_bytes();
    bytes[..8].copy_from_slice(&mixed);
    TxHash::from_bytes(bytes)
}

/// Every transaction of `cohorts`, with its rank in the pool's own order.
fn every_transaction(cohorts: &[Cohort]) -> Vec<(AdmissionRank<u64>, usize)> {
    cohorts
        .iter()
        .enumerate()
        .flat_map(|(at, cohort)| {
            (0..cohort.count).map(move |index| {
                (
                    AdmissionRank::new(cohort.rate(), cohort.hour, hash_of(at, index)),
                    at,
                )
            })
        })
        .collect()
}

/// The sim's hour is the pool's received key.
#[test]
fn the_received_key_is_the_pools_hour() {
    for seconds in [0, 3_599, 3_600, 7_199, 86_400 * 3 + 17, 1_700_000_000] {
        assert_eq!(
            ReceivedHour::of(UnixSeconds::from_raw(seconds)).to_raw(),
            seconds / SECONDS_PER_RECEIVED_KEY,
            "at {seconds} s"
        );
    }
}

/// A transaction built on tip `t` is listable in blocks `t + 1` through
/// `t + PROOF_VALIDITY_HORIZON` and gone at the next: the horizon falls out
/// of the wallet's anchor and CEN-I11's window, both called.
#[test]
fn a_cohort_lives_for_the_proof_validity_horizon() {
    let run = SimParams::default();
    let params = run.economic();
    let first = 10_000u64;
    let built_on = first - 1;
    let mut space = BlockSpace::default();
    let (evicted, refused) =
        space.admit(first, 3, baseline_tx(), u64::MAX, params.daa_target_seconds);
    assert_eq!((evicted, refused, space.waiting()), (0, 0, 3));
    let horizon = PROOF_VALIDITY_HORIZON.to_raw();
    for connecting in first..=built_on + horizon {
        assert_eq!(
            space.expire(connecting),
            0,
            "still listable at {connecting}"
        );
    }
    assert_eq!(
        space.expire(built_on + horizon + 1),
        3,
        "refused past the horizon"
    );
    assert_eq!(space.waiting(), 0);
    assert_total_is_the_pool(&space);
}

/// A waiting transaction pays the fee it was built with, not the fee of the
/// block that lists it.
#[test]
fn a_waiting_transaction_keeps_the_fee_it_was_built_with() {
    let run = SimParams::default();
    let params = run.economic();
    let point = at(&run);
    let mut space = BlockSpace::default();
    let built = baseline_tx();
    let first = space.fill(1_000, space.medians(params), 100, built, &point);
    assert!(first.included < 100, "some of it waits");
    let later = OrdinaryTx {
        fee_atomic: built.fee_atomic * 2,
        ..built
    };
    let second = space.fill(1_001, space.medians(params), 0, later, &point);
    assert!(second.included > 0);
    assert_eq!(
        second.fees,
        second.included * built.fee_atomic,
        "the listed bodies pay the fee they were built with"
    );
}

/// The cohort walk lists what the template's walk over every transaction
/// lists — `AdmissionRank::template` with the hashes, every candidate
/// offered to `Fill::admit`, none skipped — on pools that cross the
/// penalty-free weight with mixed fees and weights.
#[test]
fn the_cohort_walk_is_the_templates_walk_over_every_transaction() {
    let run = SimParams::default();
    let params = run.economic();
    let point = at(&run);
    let pools: [&[Cohort]; 4] = [
        // One rate: the old pool.
        &[cohort(3_000_000_000, 14_643, 60, 5)],
        // Mixed fees at one weight, one equal group across two hours.
        &[
            cohort(3_000_000_000, 14_643, 15, 5),
            cohort(3_100_000_000, 14_643, 10, 6),
            cohort(3_000_000_000, 14_643, 15, 6),
            cohort(2_900_000_000, 14_643, 20, 7),
        ],
        // Mixed weights; a rich light cohort past the penalty-free weight.
        &[
            cohort(3_000_000_000, 14_643, 18, 5),
            cohort(9_000_000, 9_000, 30, 5),
            cohort(900_000_000_000, 9_000, 6, 7),
            cohort(1_000_000_000, 20_000, 8, 4),
        ],
        // Fees large enough to buy into the penalty zone.
        &[
            cohort(400_000_000_000, 14_643, 25, 5),
            cohort(3_000_000_000, 14_643, 25, 5),
            cohort(250_000_000_000, 20_000, 10, 6),
        ],
    ];
    for (case, pool) in pools.iter().enumerate() {
        let medians = BlockSpace::default().medians(params);
        let empty = || {
            Fill::empty(
                medians.effective_median.to_raw(),
                u64::try_from(COINBASE_RESERVE).expect("fits"),
                point.already_generated,
                point.volume,
                params,
            )
            .expect("priced")
        };

        let mut space = space_of(pool);
        let mut cohort_fill = empty();
        let included = space.offer(&mut cohort_fill, 1_000);

        let mut every = every_transaction(pool);
        every.sort_by(|a, b| a.0.template(b.0));
        let mut naive = empty();
        let mut listed = 0u64;
        for (_, index) in &every {
            if naive.admit(pool[*index].weight, pool[*index].fee) {
                listed += 1;
            }
        }
        assert_eq!(included, listed, "case {case}: the count");
        assert_eq!(cohort_fill.fees(), naive.fees(), "case {case}: the fees");
        assert_eq!(
            cohort_fill.bodies_weight(),
            naive.bodies_weight(),
            "case {case}: the weight"
        );
        let listed_by_cohort: u64 = space.listed().iter().map(|bodies| bodies.count).sum();
        assert_eq!(listed_by_cohort, included, "case {case}: the listing");
        assert_total_is_the_pool(&space);
    }
}

/// Admission under the limit makes room as the pool does: each arrival is
/// `make_room` over every entry in eviction order, the hashes included.
/// Compared by `(rate, hour)` class, which is what the hash order cannot
/// split.
#[test]
fn admission_makes_room_as_the_pool_does() {
    let cases: [(&[Cohort], OrdinaryTx, u64, u64); 4] = [
        // Same weight: the batch path.
        (
            &[cohort(1_000, 10, 50, 3), cohort(2_000, 10, 30, 4)],
            OrdinaryTx {
                fee_atomic: 3_000,
                weight: 10,
            },
            60,
            800,
        ),
        // Victims of another weight: the general path.
        (
            &[
                cohort(500, 7, 40, 3),
                cohort(1_500, 13, 20, 4),
                cohort(4_000, 10, 10, 2),
            ],
            OrdinaryTx {
                fee_atomic: 2_500,
                weight: 10,
            },
            45,
            700,
        ),
        // An equal rate does not leave: refused once the cheaper are gone.
        (
            &[cohort(1_000, 10, 5, 3), cohort(3_000, 10, 70, 4)],
            OrdinaryTx {
                fee_atomic: 3_000,
                weight: 10,
            },
            20,
            750,
        ),
        // A shrunk limit: the first arrival evicts many.
        (
            &[cohort(1_000, 10, 50, 3), cohort(2_000, 10, 50, 4)],
            OrdinaryTx {
                fee_atomic: 3_000,
                weight: 10,
            },
            10,
            600,
        ),
    ];
    for (case, (pool, tx, demand, limit)) in cases.iter().enumerate() {
        // The pool's cohorts arrived at 1 000; these arrivals at 2 000.
        let connecting = 2_000;
        let mut space = space_of(pool);
        let (evicted, refused) = space.admit(connecting, *demand, *tx, *limit, 120);
        assert_total_is_the_pool(&space);

        // The pool's own walk, one arrival at a time. `None` marks an arrival.
        let mut held: Vec<(AdmissionRank<u64>, Option<usize>)> = every_transaction(pool)
            .into_iter()
            .map(|(rank, index)| (rank, Some(index)))
            .collect();
        let arrival_hour = (connecting - 1) * 120 / SECONDS_PER_RECEIVED_KEY;
        let rate = FeeRate::new(tx.fee_atomic, tx.weight);
        let weight_of = |index: Option<usize>| index.map_or(tx.weight, |i| pool[i].weight);
        let rate_of = |index: Option<usize>| index.map_or(rate, |i| pool[i].rate());
        let (mut naive_evicted, mut naive_refused, mut admitted) = (0u64, 0u64, 0u64);
        for arrival in 0..*demand {
            held.sort_by(|a, b| a.0.eviction(b.0));
            let total: u128 = held
                .iter()
                .map(|(_, index)| u128::from(weight_of(*index)))
                .sum();
            let entries = held
                .iter()
                .enumerate()
                .map(|(position, (_, index))| (position, rate_of(*index), weight_of(*index)));
            match make_room(total, tx.weight, *limit, rate, entries) {
                Some(victims) => {
                    naive_evicted += victims.len() as u64;
                    let mut keep = vec![true; held.len()];
                    for position in victims {
                        keep[position] = false;
                    }
                    let mut flags = keep.into_iter();
                    held.retain(|_| flags.next().expect("one flag per entry"));
                    held.push((
                        AdmissionRank::new(rate, arrival_hour, hash_of(usize::MAX, arrival)),
                        None,
                    ));
                    admitted += 1;
                }
                None => naive_refused += 1,
            }
        }
        assert_eq!(
            (evicted, refused),
            (naive_evicted, naive_refused),
            "case {case}"
        );
        let arrived: u64 = space
            .waiting
            .iter()
            .filter(|cohort| cohort.arrived == connecting)
            .map(|cohort| cohort.count)
            .sum();
        assert_eq!(arrived, admitted, "case {case}: admitted");
        let classes: std::collections::BTreeSet<(u64, u64, u64)> =
            pool.iter().map(|c| (c.fee, c.weight, c.hour)).collect();
        for class in classes {
            let left: u64 = space
                .waiting
                .iter()
                .filter(|c| c.arrived != connecting && (c.fee, c.weight, c.hour) == class)
                .map(|c| c.count)
                .sum();
            let naive_left = held
                .iter()
                .filter(|(_, index)| {
                    index.is_some_and(|i| (pool[i].fee, pool[i].weight, pool[i].hour) == class)
                })
                .count() as u64;
            assert_eq!(left, naive_left, "case {case}, class {class:?}");
        }
    }
}

/// The trim brings the pool within the limit as the pool's does, passing
/// over the listed bodies.
#[test]
fn the_trim_passes_over_the_listing_as_the_pool_does() {
    let before = [
        cohort(1_000, 10, 40, 3),
        cohort(2_000, 10, 40, 4),
        cohort(500, 7, 20, 5),
    ];
    // The block listed 10 of the richest cohort and 5 of the cheapest.
    let mut after = before;
    after[1].count -= 10;
    after[2].count -= 5;
    let limit = 600;
    // The pool after the listing, with the listing recorded as the block
    // left it: the trim counts it and never chooses it.
    let mut space = space_of(&after);
    space.taken = space
        .waiting
        .iter()
        .map(|left| {
            let index = before
                .iter()
                .position(|c| c.fee == left.fee)
                .expect("one per fee");
            before[index].count - left.count
        })
        .collect();
    let trimmed = space.trim(limit);

    let mut every = every_transaction(&before);
    every.sort_by(|a, b| a.0.eviction(b.0));
    let mut listed_left = [0u64, 10, 5];
    let units: Vec<(usize, u64, bool)> = every
        .iter()
        .map(|(_, index)| {
            let listed = listed_left[*index] > 0;
            if listed {
                listed_left[*index] -= 1;
            }
            (*index, before[*index].weight, listed)
        })
        .collect();
    let naive = trim_to(
        limit,
        units
            .iter()
            .enumerate()
            .map(|(position, (_, weight, _))| (position, *weight)),
        |position| units[*position].2,
    );
    assert_eq!(trimmed, naive.len() as u64);
    for (index, listed_out) in after.iter().enumerate() {
        let left = space
            .waiting
            .iter()
            .find(|c| c.fee == listed_out.fee)
            .expect("one per fee");
        let naive_taken = naive.iter().filter(|p| units[**p].0 == index).count() as u64;
        assert_eq!(listed_out.count - left.count, naive_taken, "cohort {index}");
    }
    assert_total_is_the_pool(&space);
}

/// The share is the largest-remainder apportionment.
#[test]
fn pro_rata_is_the_largest_remainder() {
    assert_eq!(pro_rata(&[1, 1, 1], 2), vec![1, 1, 0]);
    assert_eq!(pro_rata(&[10, 30], 4), vec![1, 3]);
    assert_eq!(pro_rata(&[5, 5, 5], 15), vec![5, 5, 5]);
    assert_eq!(
        pro_rata(&[3, 7], 5),
        vec![2, 3],
        "a tied remainder goes to the earlier"
    );
    assert_eq!(pro_rata(&[0, 4], 3), vec![0, 3]);
    assert_eq!(pro_rata(&[], 0), Vec::<u64>::new());
}

/// Below the median a block takes all it is offered; what the rule refuses
/// waits and leaves when its reference leaves the window.
#[test]
fn the_block_takes_what_the_rule_admits_and_the_rest_waits_then_expires() {
    let run = SimParams::default();
    let params = run.economic();
    let point = at(&run);
    let mut space = BlockSpace::default();
    let start = 1_000u64;
    let small = space.fill(start, space.medians(params), 5, baseline_tx(), &point);
    assert_eq!(
        (small.included, space.waiting()),
        (5, 0),
        "five fit under the zone"
    );

    // More than the blocks drain over the horizon, less than the limit.
    let demand = 3_000;
    let full = space.fill(
        start + 1,
        space.medians(params),
        demand,
        baseline_tx(),
        &point,
    );
    assert_eq!(full.refused, 0, "the pool holds it");
    assert!(full.included < demand, "the rule refuses past the median");
    assert_total_is_the_pool(&space);
    assert_eq!(space.waiting(), demand - full.included);

    let horizon = PROOF_VALIDITY_HORIZON.to_raw();
    let mut drained = full.included;
    let last_listable = start + horizon;
    for height in start + 2..=last_listable {
        let block = space.fill(height, space.medians(params), 0, baseline_tx(), &point);
        assert_eq!(block.expired, 0, "nothing has left the window at {height}");
        drained += block.included;
        assert_total_is_the_pool(&space);
    }
    let last = space.fill(
        last_listable + 1,
        space.medians(params),
        0,
        baseline_tx(),
        &point,
    );
    assert!(last.expired > 0, "the rest has left the window");
    assert_eq!(last.included, 0, "dropped before the block is filled");
    assert_eq!(
        drained + last.expired,
        demand,
        "every transaction is served or dropped"
    );
    assert_eq!(space.waiting(), 0);
    assert_total_is_the_pool(&space);
}
