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

/// `count` Standard transactions, each `tx`: one block's demand before
/// ESR-10.
fn standard(count: u64, tx: OrdinaryTx) -> [Arrival; 1] {
    [Arrival {
        rung: Rung::Standard,
        count,
        tx,
    }]
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

/// A Standard cohort built at an arbitrary block, for the walks below.
fn cohort(fee: u64, weight: u64, count: u64, hour: u64) -> Cohort {
    rung_cohort(Rung::Standard, fee, weight, count, hour)
}

/// A cohort on `rung` built at an arbitrary block.
fn rung_cohort(rung: Rung, fee: u64, weight: u64, count: u64, hour: u64) -> Cohort {
    Cohort {
        arrived: 1_000,
        reference: 993,
        hour,
        fee,
        weight,
        count,
        rung,
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
    let mut evicted = PerRung::default();
    let [arrival] = standard(3, baseline_tx());
    let refused = space.admit(
        first,
        arrival,
        u64::MAX,
        params.daa_target_seconds,
        &mut evicted,
    );
    assert_eq!(
        (evicted.iter().sum::<u64>(), refused, space.waiting()),
        (0, 0, 3)
    );
    let horizon = PROOF_VALIDITY_HORIZON.to_raw();
    for connecting in first..=built_on + horizon {
        assert_eq!(
            space.expire(connecting).iter().sum::<u64>(),
            0,
            "still listable at {connecting}"
        );
    }
    assert_eq!(
        space.expire(built_on + horizon + 1)[Rung::Standard],
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
    let first = space.fill(1_000, space.medians(params), &standard(100, built), &point);
    assert!(first.carried_txs() < 100, "some of it waits");
    let later = OrdinaryTx {
        fee_atomic: built.fee_atomic * 2,
        ..built
    };
    let second = space.fill(1_001, space.medians(params), &standard(0, later), &point);
    assert!(second.carried_txs() > 0);
    assert_eq!(
        second.fees_atomic(),
        second.carried_txs() * built.fee_atomic,
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
        let mut rungs = PerRung::default();
        space.offer(&mut cohort_fill, 1_000, &mut rungs);
        let included: u64 = rungs.sum(|r| r.carried_txs);

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
        let mut evicted_by_rung = PerRung::default();
        let [arrival] = standard(*demand, *tx);
        let refused = space.admit(connecting, arrival, *limit, 120, &mut evicted_by_rung);
        let evicted: u64 = evicted_by_rung.iter().sum();
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
    let mut evicted = PerRung::default();
    space.trim(limit, &mut evicted);
    let trimmed: u64 = evicted.iter().sum();

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
    let small = space.fill(
        start,
        space.medians(params),
        &standard(5, baseline_tx()),
        &point,
    );
    assert_eq!(
        (small.carried_txs(), space.waiting()),
        (5, 0),
        "five fit under the zone"
    );

    // More than the blocks drain over the horizon, less than the limit.
    let demand = 3_000;
    let full = space.fill(
        start + 1,
        space.medians(params),
        &standard(demand, baseline_tx()),
        &point,
    );
    assert_eq!(full.rungs.sum(|r| r.refused_txs), 0, "the pool holds it");
    assert!(
        full.carried_txs() < demand,
        "the rule refuses past the median"
    );
    assert_total_is_the_pool(&space);
    assert_eq!(space.waiting(), demand - full.carried_txs());

    let horizon = PROOF_VALIDITY_HORIZON.to_raw();
    let mut drained = full.carried_txs();
    let last_listable = start + horizon;
    for height in start + 2..=last_listable {
        let block = space.fill(
            height,
            space.medians(params),
            &standard(0, baseline_tx()),
            &point,
        );
        assert_eq!(
            block.rungs.sum(|r| r.expired_txs),
            0,
            "nothing has left the window at {height}"
        );
        drained += block.carried_txs();
        assert_total_is_the_pool(&space);
    }
    let last = space.fill(
        last_listable + 1,
        space.medians(params),
        &standard(0, baseline_tx()),
        &point,
    );
    assert!(
        last.rungs.sum(|r| r.expired_txs) > 0,
        "the rest has left the window"
    );
    assert_eq!(last.carried_txs(), 0, "dropped before the block is filled");
    assert_eq!(
        drained + last.rungs.sum(|r| r.expired_txs),
        demand,
        "every transaction is served or dropped"
    );
    assert_eq!(space.waiting(), 0);
    assert_total_is_the_pool(&space);
}

/// ESR-10's three rungs: the cohort walk lists what the template's walk over
/// every transaction lists, rung by rung, on pools where the rungs pay the
/// ladder's ratios (Priority 50× Standard per byte and a byte heavier for
/// its fee's longer varint, Standard 4× Economy), with cohorts of every age.
/// The rung orders nothing: each transaction's rank is its rate, hour and
/// hash, as the pool's.
#[test]
fn the_three_rung_walk_is_the_templates_walk_rung_by_rung() {
    let run = SimParams::default();
    let params = run.economic();
    let point = at(&run);
    let (e, s, p) = (Rung::Economy, Rung::Standard, Rung::Priority);
    let pools: [&[Cohort]; 3] = [
        // The constrained era: a Priority sprinkle, Standard over the room,
        // Economy behind both, the oldest of each the richest.
        &[
            rung_cohort(p, 60_000_000_000, 14_644, 3, 7),
            rung_cohort(s, 1_200_000_000, 14_643, 40, 5),
            rung_cohort(s, 1_190_000_000, 14_643, 40, 6),
            rung_cohort(e, 300_000_000, 14_643, 8, 5),
            rung_cohort(e, 297_500_000, 14_643, 7, 6),
        ],
        // Priority enough to buy into the penalty zone.
        &[
            rung_cohort(p, 60_000_000_000, 14_644, 40, 7),
            rung_cohort(s, 1_200_000_000, 14_643, 30, 5),
            rung_cohort(e, 300_000_000, 14_643, 10, 5),
        ],
        // Room for everything: every rung listed.
        &[
            rung_cohort(p, 60_000_000_000, 14_644, 1, 7),
            rung_cohort(s, 1_200_000_000, 14_643, 8, 5),
            rung_cohort(e, 300_000_000, 14_643, 2, 5),
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
        let mut rungs = PerRung::<RungTraffic<u64>>::default();
        space.offer(&mut cohort_fill, 1_000, &mut rungs);

        let mut every = every_transaction(pool);
        every.sort_by(|a, b| a.0.template(b.0));
        let mut naive = empty();
        let mut naive_rungs = PerRung::<(u64, u64)>::default();
        for (_, index) in &every {
            let c = pool[*index];
            if naive.admit(c.weight, c.fee) {
                naive_rungs[c.rung].0 += 1;
                naive_rungs[c.rung].1 += c.fee;
            }
        }
        for rung in Rung::ALL {
            assert_eq!(
                (rungs[rung].carried_txs, rungs[rung].fees_atomic),
                naive_rungs[rung],
                "case {case}: {rung:?}"
            );
        }
        assert_eq!(cohort_fill.fees(), naive.fees(), "case {case}: the fees");
        assert_total_is_the_pool(&space);
    }
}

/// A full pool refuses the cheapest arrival and lets a richer one evict the
/// cheapest entry, and the pool counts each drop against the rung it was
/// built on.
#[test]
fn a_full_pool_drops_the_cheapest_rung_and_counts_it() {
    let weight = 10;
    let pool = [
        rung_cohort(Rung::Standard, 4_000, weight, 50, 3),
        rung_cohort(Rung::Economy, 1_000, weight, 30, 3),
    ];
    let limit = 80 * weight;
    let mut space = space_of(&pool);
    let mut evicted = PerRung::default();
    let economy = Arrival {
        rung: Rung::Economy,
        count: 5,
        tx: OrdinaryTx {
            fee_atomic: 990,
            weight,
        },
    };
    assert_eq!(
        space.admit(2_000, economy, limit, 120, &mut evicted),
        5,
        "the cheapest arrival has nothing cheaper to evict"
    );
    let standard_arrival = Arrival {
        rung: Rung::Standard,
        count: 12,
        tx: OrdinaryTx {
            fee_atomic: 3_990,
            weight,
        },
    };
    assert_eq!(
        space.admit(2_000, standard_arrival, limit, 120, &mut evicted),
        0
    );
    assert_eq!(
        evicted[Rung::Economy],
        12,
        "the Standard arrivals evict Economy"
    );
    assert_eq!(evicted[Rung::Standard], 0);
    assert_total_is_the_pool(&space);
}

/// What a pool holds after a block's arrivals, and what they dropped.
struct Admitted {
    /// The pool's entries, in its order: rung, fee, count.
    held: Vec<(Rung, u64, u64)>,
    evicted: PerRung<u64>,
    refused: PerRung<u64>,
}

impl Admitted {
    fn rungs(&self) -> Vec<Rung> {
        self.held.iter().map(|&(rung, ..)| rung).collect()
    }
}

/// Admits each of `order`'s arrivals in turn into a pool holding `pool`
/// under `limit`.
fn admit_in_order(pool: &[Cohort], order: &[Arrival], limit: u64) -> Admitted {
    let mut space = space_of(pool);
    let mut evicted = PerRung::default();
    let mut refused = PerRung::<u64>::default();
    for &a in order {
        refused[a.rung] += space.admit(2_000, a, limit, 120, &mut evicted);
    }
    assert_total_is_the_pool(&space);
    Admitted {
        held: space
            .waiting
            .iter()
            .map(|c| (c.rung, c.fee, c.count))
            .collect(),
        evicted,
        refused,
    }
}

/// At equal weights the order one block's arrivals reach the pool moves a
/// drop's label, not the pool: Economy admitted first and evicted by
/// Standard leaves the pool that Economy refused after Standard leaves.
#[test]
fn at_equal_weights_the_admission_order_relabels_a_drop_and_leaves_the_pool() {
    let weight = 10;
    let pool = [rung_cohort(Rung::Standard, 4_000, weight, 70, 3)];
    let limit = 80 * weight;
    let arrival = |rung, count, fee_atomic| Arrival {
        rung,
        count,
        tx: OrdinaryTx { fee_atomic, weight },
    };
    let economy = arrival(Rung::Economy, 6, 1_000);
    let standard_arrival = arrival(Rung::Standard, 7, 3_990);
    let richest_first = admit_in_order(&pool, &[standard_arrival, economy], limit);
    let cheapest_first = admit_in_order(&pool, &[economy, standard_arrival], limit);
    assert_eq!(
        richest_first.held, cheapest_first.held,
        "the same pool either way"
    );
    assert_eq!(
        (
            richest_first.evicted[Rung::Economy],
            richest_first.refused[Rung::Economy]
        ),
        (0, 3),
        "richest first: Economy refused"
    );
    assert_eq!(
        (
            cheapest_first.evicted[Rung::Economy],
            cheapest_first.refused[Rung::Economy]
        ),
        (3, 0),
        "cheapest first: Economy admitted, then evicted"
    );
}

/// At unequal weights the order can change the pool, which is why
/// [`Rung::ADMISSION`] is a declared assumption. A 20-byte pool holds a
/// 10-byte Standard entry. Priority (11 bytes) first evicts Standard, and
/// Economy (9 bytes) then fits beside it. Economy first fits beside
/// Standard, and Priority then evicts both, the cheapest first, until it
/// fits.
#[test]
fn at_unequal_weights_the_admission_order_can_change_the_pool() {
    let pool = [rung_cohort(Rung::Standard, 4_000, 10, 1, 3)];
    let limit = 20;
    let economy = Arrival {
        rung: Rung::Economy,
        count: 1,
        tx: OrdinaryTx {
            fee_atomic: 900,
            weight: 9,
        },
    };
    let priority = Arrival {
        rung: Rung::Priority,
        count: 1,
        tx: OrdinaryTx {
            fee_atomic: 50_000,
            weight: 11,
        },
    };
    let richest_first = admit_in_order(&pool, &[priority, economy], limit);
    let cheapest_first = admit_in_order(&pool, &[economy, priority], limit);
    assert_eq!(
        richest_first.rungs(),
        [Rung::Priority, Rung::Economy],
        "richest first: Priority and Economy"
    );
    assert_eq!(
        cheapest_first.rungs(),
        [Rung::Priority],
        "cheapest first: Priority alone"
    );
    assert_eq!(
        (
            cheapest_first.evicted[Rung::Economy],
            cheapest_first.evicted[Rung::Standard]
        ),
        (1, 1),
        "cheapest first: Priority evicts both"
    );
}
