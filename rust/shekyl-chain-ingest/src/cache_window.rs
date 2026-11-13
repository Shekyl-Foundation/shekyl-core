// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The seeds the node needs, ranked (`RANDOMX_CACHE_ACTOR.md` §5.1), and
//! what an alternative may hash under.
//!
//! The hasher keeps a cache for each seed on the ranked list
//! ([`ranked_seeds`]), which this module computes from one store snapshot
//! and chain sync's header frontier:
//!
//! 1. **the window's seeds**: a block inside the reorg cap, and not below
//!    a reached checkpoint, whose seed lies below its fork names one of at
//!    most two seeds, because the window fits inside one seed epoch. The
//!    connecting height's seed is first.
//! 2. **the third**: the seed the next block of the most-work chain the
//!    window does not cover hashes under. That chain is a held fork inside
//!    the cap, or the header frontier.
//!
//! A hash never reads this list. Every hash is a job on its own seed, and
//! a job always gets its cache (HA-R1): the list says what stays warm
//! between jobs. An alternative is still judged against the window before
//! any job is asked for ([`spend`]): past the cap it is not hashed, and a
//! below-fork seed outside the window is a defect in this arithmetic, a
//! fault.

use shekyl_chain_rules::{
    seed_height, AtHeight, Corrupt, Fork, PerHeightRecord, RuleSet, ViewRead, D_MAX,
};
use shekyl_chain_store::store::{AltView, ReadSnapshot, StoreError};
use shekyl_difficulty::{CumulativeDifficulty, SEEDHASH_EPOCH_BLOCKS};
use shekyl_hasher::{Class, Ranked};
use shekyl_pow_randomx::Seedhash;
use shekyl_types::{BlockCount, BlockHash, BlockHeight};

use crate::connector::PopBeyondReorgCap;
use crate::schedule::ChainRules;

/// Two reorg caps fit inside one seed epoch, so the window names at most
/// two seeds and they cover every below-fork seed an in-cap alternative
/// can name. A wider cap must not assume that.
const _: () = assert!(
    2 * D_MAX.to_raw() < SEEDHASH_EPOCH_BLOCKS,
    "two reorg caps no longer fit in one seed epoch; the window's two seeds cannot cover an in-cap alternative"
);

/// How far above the connecting height the window reaches: the cap, and
/// never less than the seed lag plus one. A seed block mined below the
/// tip is named only from 65 blocks above it, so a lever cap under 65
/// would otherwise leave a mined below-fork seed out of the pair. The
/// window stays `cap + max(cap, 65) < SEEDHASH_EPOCH_BLOCKS` wide.
fn reach_above(cap: BlockCount) -> BlockCount {
    let lag_reach = BlockCount::from_raw(shekyl_difficulty::SEEDHASH_EPOCH_LAG + 1);
    if cap.to_raw() < lag_reach.to_raw() {
        lag_reach
    } else {
        cap
    }
}

/// How many recorded blocks a reorg may pop below `connecting`: the cap,
/// and never past `floor`, the store's lowest poppable height (genesis is
/// never popped, nor anything the undo journal has retired). The window's
/// lower end and [`spend`]'s depth refusal both read this one bound, so
/// the window never names a seed that only a block the store will not pop
/// hashes under (A2: the null seed, once genesis is connected), and a fork
/// the window does not cover is refused before its seed is looked for.
fn pop_reach(cap: BlockCount, connecting: BlockHeight, floor: BlockHeight) -> BlockCount {
    let poppable = connecting.checked_sub(floor).unwrap_or(BlockCount::ZERO);
    if poppable.to_raw() < cap.to_raw() {
        poppable
    } else {
        cap
    }
}

/// The seeds the rules name at the committed tip: the connecting height's,
/// and the other endpoint of the serviceable window when it differs.
///
/// This is the head of the ranked list ([`ranked_seeds`]), and the window a
/// below-fork alternative's seed is judged against ([`spend`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeedPair {
    /// The seed a block connecting at the tip's successor hashes under.
    pub(crate) canonical: BlockHash,
    /// The other seed the window names, when the two ends differ.
    pub(crate) transient: Option<BlockHash>,
}

impl SeedPair {
    /// Whether `seed` is one of the two this window names.
    #[must_use]
    pub fn holds(self, seed: &BlockHash) -> bool {
        self.canonical == *seed || self.transient == Some(*seed)
    }
}

/// Chain sync's header frontier, as the ranked list needs it: the run with
/// the most proven cumulative work (`RANDOMX_CACHE_ACTOR.md` §5.1).
/// Evidence runs are not a frontier: the evidence check is a job, not
/// residency (HA-R3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frontier {
    /// The seed the run's next header proof hashes under. The model has
    /// judged it earned.
    pub seed: BlockHash,
    /// The run's proven cumulative work.
    pub work: CumulativeDifficulty,
}

/// A held fork inside the reorg cap, as the ranked list needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HeldFork {
    /// The seed the fork's next block hashes under: the main chain's block
    /// when its seed height is at or below the fork point, and otherwise
    /// the fork's own block.
    pub(crate) seed: BlockHash,
    /// The fork tip's cumulative work.
    pub(crate) work: CumulativeDifficulty,
}

/// What one snapshot says the ranked list is computed from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Gathered {
    /// The window at the tip.
    pub(crate) window: SeedPair,
    /// Each held fork inside the cap, in the alt table's key order.
    pub(crate) forks: Vec<HeldFork>,
}

/// Read what [`ranked_seeds`] needs off `snap`. `None` on a store with no
/// block: nothing is ranked there, so the list never names the null seed.
/// Genesis is still hashed under it, by its own job.
///
/// # Errors
///
/// As [`seeds_on`], and the store's while it reads the held forks. A
/// fork's seed block missing below its tip is a hole there.
pub(crate) fn gather(
    snap: &ReadSnapshot<'_>,
    rules: ChainRules,
) -> Result<Option<Gathered>, ViewRead<StoreError>> {
    let Some(tip) = snap.tip()?.recorded else {
        return Ok(None);
    };
    let window = seeds_on(snap, rules)?;
    let connecting = shekyl_chain_rules::Tip::connecting_height(Some(&tip));
    let reach = pop_reach(
        rules.in_force(connecting).reorg_cap(),
        connecting,
        snap.undo_floor()?,
    );
    let mut forks = Vec::new();
    for chain in snap.alternate_chains()? {
        if chain.fork().pops() > reach {
            continue;
        }
        let next = chain.candidate_height();
        let fork_tip = chain.parent().height;
        let view = AltView::new(snap, chain);
        let recorded = |at: BlockHeight| match shekyl_chain_rules::HeaderView::header_at(&view, at)
        {
            Ok(AtHeight::Recorded(record)) => Ok(record),
            Ok(AtHeight::AboveTip) => Err(ViewRead::Corrupt(Corrupt::HoleBelowTip {
                at,
                record: PerHeightRecord::Header,
            })),
            Err(store) => Err(ViewRead::View(store)),
        };
        let seed = match seed_height(next) {
            None => BlockHash::NULL,
            Some(at) => recorded(at)?.hash,
        };
        forks.push(HeldFork {
            seed,
            work: recorded(fork_tip)?.cumulative_difficulty,
        });
    }
    Ok(Some(Gathered { window, forks }))
}

/// The ranked list (`RANDOMX_CACHE_ACTOR.md` §5.1, HA-R4). Pure.
///
/// 1. The window's canonical seed, then its other seed.
/// 2. The third: the seed of the most-work chain among the held forks and
///    the frontier, when the window does not already name that seed. When
///    it does there is no third, and the next-heaviest chain does not take
///    the place: one rule decides the third (HA-R2).
///
/// Equal work is decided by a fixed order: a held fork before the
/// frontier, and between forks the first in the alt table's key order. The
/// third's class is the class its jobs hash at: [`Class::HeaderPow`] for
/// the frontier, and [`Class::Unsolicited`] for a held fork, which is
/// lighter than the main chain and reaches this node as announcements.
///
/// `None` when nothing was gathered: a store with no block.
#[must_use]
pub(crate) fn ranked_seeds(
    gathered: Option<&Gathered>,
    frontier: Option<Frontier>,
) -> Option<Ranked> {
    let gathered = gathered?;
    let window = gathered.window;
    let mut heaviest: Option<(BlockHash, CumulativeDifficulty, Class)> = None;
    let chains = gathered
        .forks
        .iter()
        .map(|fork| (fork.seed, fork.work, Class::Unsolicited))
        .chain(frontier.map(|frontier| (frontier.seed, frontier.work, Class::HeaderPow)));
    for chain in chains {
        // Strictly more work replaces: the first of equals stands, and the
        // forks come before the frontier.
        if heaviest.is_none_or(|(_, work, _)| chain.1 > work) {
            heaviest = Some(chain);
        }
    }
    let third = heaviest
        .filter(|(seed, _, _)| !window.holds(seed))
        .map(|(seed, _, class)| (seedhash(&seed), class));
    Some(
        Ranked::new(
            seedhash(&window.canonical),
            window.transient.as_ref().map(seedhash),
            third,
        )
        .expect("the window's two seeds differ, and the third is not one of them"),
    )
}

fn seedhash(seed: &BlockHash) -> Seedhash {
    Seedhash::from_bytes(*seed.as_bytes())
}

/// What an alternative may cost before any cache is built or any proof of
/// work is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AltSpend {
    /// The fork is inside the band, and the seed is either below the fork
    /// and in the window, or the branch's own block above the fork. Hash
    /// it, as a job on that seed.
    Hash,
    /// Past the reorg cap. Local, not a consensus verdict: this node cannot
    /// switch that deep. Nothing is stored and nothing is hashed.
    BeyondCap(PopBeyondReorgCap),
    /// A seed below the fork that the pair does not hold. The window's
    /// arithmetic says it cannot happen inside the cap: a driver defect,
    /// which the caller faults on. Never a reply.
    SeedNotInWindow {
        /// The block's height on its chain.
        height: BlockHeight,
    },
}

/// The window for `rules` at `snap`'s tip: the one an alternative claimed
/// on the same snapshot is judged against.
///
/// # Errors
///
/// The store's, or [`Corrupt::HoleBelowTip`] when the store has no block
/// at the connecting height's seed height, which is below its tip.
pub(crate) fn seeds_on(
    snap: &ReadSnapshot<'_>,
    rules: ChainRules,
) -> Result<SeedPair, ViewRead<StoreError>> {
    let tip = snap.tip()?.recorded;
    let connecting = shekyl_chain_rules::Tip::connecting_height(tip.as_ref());
    let cap = rules.in_force(connecting).reorg_cap();
    let low = connecting.saturating_sub_count(pop_reach(cap, connecting, snap.undo_floor()?));
    let high = connecting.saturating_add(reach_above(cap));
    // The connecting height's seed lags the tip, or is the null hash
    // before any block exists. The window's far end can name the next
    // epoch before that block is mined; that seed is not in the window.
    let canonical = required_seed(seed_hash(snap, connecting)?, connecting)?;
    let older = seed_hash(snap, low)?;
    let newer = seed_hash(snap, high)?;
    Ok(pair_of(canonical, older, newer))
}

/// The connecting height's seed, which the store must hold: its seed
/// height lags the tip, so a missing block there is a hole below the tip,
/// a store fault, never a peer's doing.
fn required_seed(
    found: Option<BlockHash>,
    connecting: BlockHeight,
) -> Result<BlockHash, ViewRead<StoreError>> {
    found.ok_or_else(|| {
        ViewRead::Corrupt(Corrupt::HoleBelowTip {
            at: seed_height(connecting).unwrap_or(BlockHeight::ZERO),
            record: PerHeightRecord::Block,
        })
    })
}

/// The window from the seeds the chain can already name.
///
/// `older` is the far end below the tip, `newer` the far end above it.
/// A `None` end is an epoch the chain has not reached, so the window does
/// not name it. When both ends differ from `canonical` the lower one is
/// the window's other seed: one seed boundary fits in the window.
fn pair_of(canonical: BlockHash, older: Option<BlockHash>, newer: Option<BlockHash>) -> SeedPair {
    let transient = [older, newer]
        .into_iter()
        .flatten()
        .find(|seed| *seed != canonical);
    SeedPair {
        canonical,
        transient,
    }
}

/// The seed a block connecting at `height` hashes under, when this
/// snapshot holds the seed block.
///
/// `None` is a seed height above the tip: the block is not mined, and
/// nothing may build its cache. The null hash — genesis admission — is
/// `Some`, because that cache is real.
fn seed_hash(
    snap: &ReadSnapshot<'_>,
    height: BlockHeight,
) -> Result<Option<BlockHash>, StoreError> {
    let Some(at) = seed_height(height) else {
        return Ok(Some(BlockHash::NULL));
    };
    match snap.block_info(at)? {
        AtHeight::Recorded(info) => Ok(Some(info.hash)),
        AtHeight::AboveTip => Ok(None),
    }
}

/// Where an alternative's seed block lies against its fork.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SeedSide {
    /// At or below the fork point: a main-chain block, or the null seed.
    BelowFork,
    /// Above the fork point: the branch's own block.
    OnBranch,
}

/// Whether `fork`'s block, hashing under `seed` (which lies on `side`) at
/// `height`, may be hashed against `window`, and how. Records nothing.
/// Builds nothing.
///
/// `floor` is the store's lowest poppable height on the snapshot `window`
/// was read from. A fork that would pop below it is past the reach the
/// window was built for ([`pop_reach`]), so it is refused as past the cap:
/// this node cannot switch that deep. Its seed is never looked for, so it
/// cannot be a [`AltSpend::SeedNotInWindow`] fault.
#[must_use]
pub(crate) fn spend(
    fork: &Fork,
    seed: &BlockHash,
    side: SeedSide,
    height: BlockHeight,
    rule_set: &RuleSet,
    window: &SeedPair,
    floor: BlockHeight,
) -> AltSpend {
    let connecting = fork.recorded_tip().height.saturating_add(BlockCount::ONE);
    let reach = pop_reach(rule_set.reorg_cap(), connecting, floor);
    if fork.pops() > reach {
        return AltSpend::BeyondCap(PopBeyondReorgCap {
            depth: fork.pops(),
            cap: reach,
        });
    }
    match side {
        SeedSide::OnBranch => AltSpend::Hash,
        SeedSide::BelowFork if window.holds(seed) => AltSpend::Hash,
        SeedSide::BelowFork => AltSpend::SeedNotInWindow { height },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_chain_rules::Tip;
    use shekyl_types::BlockCount;

    /// The store's lowest poppable height while nothing is retired.
    const GENESIS_FLOOR: BlockHeight = BlockHeight::from_raw(1);

    fn seed(fill: u8) -> BlockHash {
        BlockHash::from_bytes([fill; 32])
    }

    fn work(raw: u128) -> CumulativeDifficulty {
        CumulativeDifficulty::from_raw(raw)
    }

    /// The window's canonical seed is 1; `other` is 2 when the window
    /// spans a seed boundary.
    fn gathered(two_seeds: bool, forks: &[(u8, u128)]) -> Gathered {
        Gathered {
            window: SeedPair {
                canonical: seed(1),
                transient: two_seeds.then(|| seed(2)),
            },
            forks: forks
                .iter()
                .map(|&(fill, raw)| HeldFork {
                    seed: seed(fill),
                    work: work(raw),
                })
                .collect(),
        }
    }

    fn frontier(fill: u8, raw: u128) -> Option<Frontier> {
        Some(Frontier {
            seed: seed(fill),
            work: work(raw),
        })
    }

    /// The list `ranked_seeds` must return: the window's seeds, canonical
    /// first, then the third and its class.
    fn list(other: Option<u8>, third: Option<(u8, Class)>) -> Option<Ranked> {
        Some(
            Ranked::new(
                seedhash(&seed(1)),
                other.map(|fill| seedhash(&seed(fill))),
                third.map(|(fill, class)| (seedhash(&seed(fill)), class)),
            )
            .expect("distinct seeds"),
        )
    }

    /// `RANDOMX_CACHE_ACTOR.md` §8's table for the ranked list. Each row:
    /// the window, the held forks as (seed, work), the frontier, the list.
    ///
    /// Red edits, one per rule: rank the frontier before the forks
    /// (`equal work` row); take the next-heaviest chain when the winner's
    /// seed is in the window (`heaviest is in the window` row); give a
    /// fork `HeaderPow` (any fork row); list the lighter fork (`two forks`
    /// row).
    #[test]
    fn the_ranked_list_is_the_window_then_the_most_work_chain_outside_it() {
        type Row = (&'static str, Gathered, Option<Frontier>, Option<Ranked>);
        let fork = Class::Unsolicited;
        let ahead = Class::HeaderPow;
        let rows: Vec<Row> = vec![
            (
                "a one-seed window",
                gathered(false, &[]),
                None,
                list(None, None),
            ),
            (
                "a two-seed window",
                gathered(true, &[]),
                None,
                list(Some(2), None),
            ),
            (
                "a held fork past its seed point",
                gathered(false, &[(7, 10)]),
                None,
                list(None, Some((7, fork))),
            ),
            (
                "two held forks: the heavier is listed",
                gathered(true, &[(7, 10), (8, 11)]),
                None,
                list(Some(2), Some((8, fork))),
            ),
            (
                "two held forks of equal work: the first in key order",
                gathered(false, &[(7, 10), (8, 10)]),
                None,
                list(None, Some((7, fork))),
            ),
            (
                "a header frontier ahead of the window",
                gathered(true, &[]),
                frontier(9, 50),
                list(Some(2), Some((9, ahead))),
            ),
            (
                "a frontier and a fork: the frontier has more work",
                gathered(false, &[(7, 10)]),
                frontier(9, 11),
                list(None, Some((9, ahead))),
            ),
            (
                "a frontier and a fork: the fork has more work",
                gathered(false, &[(7, 12)]),
                frontier(9, 11),
                list(None, Some((7, fork))),
            ),
            (
                "a frontier and a fork of equal work: the fork",
                gathered(false, &[(7, 11)]),
                frontier(9, 11),
                list(None, Some((7, fork))),
            ),
            (
                "a fork whose seed is the window's: not listed twice",
                gathered(true, &[(2, 10)]),
                None,
                list(Some(2), None),
            ),
            (
                "a frontier whose seed is the window's: not listed twice",
                gathered(false, &[]),
                frontier(1, 50),
                list(None, None),
            ),
            (
                "the heaviest is in the window: the next-heaviest does not take the place",
                gathered(true, &[(7, 10)]),
                frontier(2, 50),
                list(Some(2), None),
            ),
        ];
        for (name, gathered, frontier, expected) in rows {
            assert_eq!(ranked_seeds(Some(&gathered), frontier), expected, "{name}");
        }
    }

    /// A store with no block gathers nothing, and nothing is ranked: with
    /// or without a frontier. The list never names the null seed.
    ///
    /// Red edit: return `Ranked::new(null seed, None, None)` for `None`.
    #[test]
    fn nothing_is_ranked_on_a_store_with_no_block() {
        assert_eq!(ranked_seeds(None, None), None);
        assert_eq!(ranked_seeds(None, frontier(9, 50)), None);
    }

    fn tip(height: BlockHeight, fill: u8) -> Tip {
        Tip {
            height,
            hash: BlockHash::from_bytes([fill; 32]),
        }
    }

    /// A fork that pops `pops` recorded blocks.
    fn popping(pops: BlockCount) -> Fork {
        Fork::new(
            tip(BlockHeight::ZERO, 1),
            tip(BlockHeight::ZERO.saturating_add(pops), 2),
        )
        .expect("the root is not above the tip")
    }

    #[test]
    fn a_fork_past_the_cap_is_not_hashed_and_not_an_invalid_block() {
        let fork = popping(BlockCount::from_raw(D_MAX.to_raw() + 1));
        let window = SeedPair {
            canonical: BlockHash::NULL,
            transient: None,
        };
        let spend = spend(
            &fork,
            &BlockHash::NULL,
            SeedSide::BelowFork,
            BlockHeight::from_raw(1),
            &RuleSet::GENESIS,
            &window,
            GENESIS_FLOOR,
        );
        assert!(
            matches!(spend, AltSpend::BeyondCap(beyond) if beyond.cap == D_MAX),
            "{spend:?}"
        );
    }

    /// B2: a seed below the fork must be one of the pair, and a miss is a
    /// defect, never a reply. The branch's own seed block is hashed,
    /// whatever the pair holds: the form is a job on it.
    #[test]
    fn a_below_fork_miss_is_a_defect_and_a_branch_seed_is_hashed() {
        let fork = popping(BlockCount::from_raw(1));
        let window = SeedPair {
            canonical: BlockHash::NULL,
            transient: None,
        };
        let other = BlockHash::from_bytes([9; 32]);
        let at = BlockHeight::from_raw(2);
        let below = spend(
            &fork,
            &other,
            SeedSide::BelowFork,
            at,
            &RuleSet::GENESIS,
            &window,
            GENESIS_FLOOR,
        );
        assert!(
            matches!(below, AltSpend::SeedNotInWindow { height } if height == at),
            "{below:?}"
        );
        let branch = spend(
            &fork,
            &other,
            SeedSide::OnBranch,
            at,
            &RuleSet::GENESIS,
            &window,
            GENESIS_FLOOR,
        );
        assert!(matches!(branch, AltSpend::Hash), "{branch:?}");
    }

    #[test]
    fn a_seed_the_pair_holds_is_hashed() {
        let fork = popping(BlockCount::from_raw(1));
        let seed = BlockHash::from_bytes([4; 32]);
        let window = SeedPair {
            canonical: seed,
            transient: Some(BlockHash::NULL),
        };
        let gated = spend(
            &fork,
            &seed,
            SeedSide::BelowFork,
            BlockHeight::from_raw(2),
            &RuleSet::GENESIS,
            &window,
            GENESIS_FLOOR,
        );
        assert!(matches!(gated, AltSpend::Hash), "{gated:?}");
        // At the cap, still hashed: the cap refuses only past it.
        let at_cap = popping(D_MAX);
        assert!(matches!(
            spend(
                &at_cap,
                &seed,
                SeedSide::BelowFork,
                BlockHeight::from_raw(2),
                &RuleSet::GENESIS,
                &window,
                GENESIS_FLOOR,
            ),
            AltSpend::Hash
        ));
    }

    #[test]
    fn a_seed_the_chain_has_not_mined_is_not_in_the_window() {
        let canonical = BlockHash::from_bytes([1; 32]);
        let unmined = pair_of(canonical, Some(canonical), None);
        assert_eq!(unmined.canonical, canonical);
        assert_eq!(unmined.transient, None);
        let next = BlockHash::from_bytes([2; 32]);
        let held = pair_of(canonical, Some(canonical), Some(next));
        assert_eq!(held.transient, Some(next));
        // The lower end wins when it is the one that differs.
        let previous = BlockHash::from_bytes([3; 32]);
        let lower = pair_of(canonical, Some(previous), Some(next));
        assert_eq!(lower.transient, Some(previous));
    }

    /// A store that has no block at the connecting height's seed height is
    /// a hole below its tip: a typed fault the service records and stops
    /// on, not a panic.
    #[test]
    fn a_missing_seed_block_is_a_hole_below_the_tip() {
        let connecting = BlockHeight::from_raw(5_000);
        let missing = required_seed(None, connecting);
        assert!(
            matches!(
                missing,
                Err(ViewRead::Corrupt(Corrupt::HoleBelowTip { at, record: PerHeightRecord::Block }))
                    if Some(at) == seed_height(connecting)
            ),
            "{missing:?}"
        );
        let held = BlockHash::from_bytes([6; 32]);
        assert!(matches!(required_seed(Some(held), connecting), Ok(seed) if seed == held));
    }

    /// A2: the pop reach never passes the store's floor. Until the chain
    /// is a cap deep, a reorg reaches block 1 and no lower: genesis is
    /// never popped, so the window's lower end is never height 0, whose
    /// seed is the null hash that only genesis hashes under.
    #[test]
    fn the_pop_reach_stops_at_the_floor() {
        let cap = BlockCount::from_raw(10);
        for connecting in 0..=cap.to_raw() + 3 {
            let connecting = BlockHeight::from_raw(connecting);
            let reach = pop_reach(cap, connecting, GENESIS_FLOOR);
            let low = connecting.saturating_sub_count(reach);
            if connecting.is_zero() {
                assert_eq!(low, BlockHeight::ZERO, "an empty chain: genesis connects");
            } else {
                assert!(
                    low >= GENESIS_FLOOR,
                    "connecting {connecting:?}: low {low:?}"
                );
                assert!(seed_height(low).is_some(), "the null seed is not named");
            }
            assert!(reach <= cap);
        }
        // A cap deep, the cap binds again.
        let deep = BlockHeight::from_raw(500);
        assert_eq!(pop_reach(cap, deep, GENESIS_FLOOR), cap);
        // A retired journal raises the floor above the cap's reach: an
        // operator's pop left the tip within a cap of it.
        let raised = BlockHeight::from_raw(495);
        assert_eq!(pop_reach(cap, deep, raised), BlockCount::from_raw(5));
    }

    /// A2's other half: a fork that would pop below the floor is refused
    /// as past the cap, before its seed is looked for, so a window built to
    /// the floor cannot turn it into a `SeedNotInWindow` fault.
    #[test]
    fn a_fork_below_the_floor_is_refused_before_its_seed_is_read() {
        // Root 0, tip 5: pops five, inside the cap; block 1 is the lowest
        // it would pop. A floor at 3 (heights 1 and 2 retired) refuses it.
        let fork = popping(BlockCount::from_raw(5));
        let window = SeedPair {
            canonical: BlockHash::from_bytes([4; 32]),
            transient: None,
        };
        let unheld = BlockHash::from_bytes([9; 32]);
        let refused = spend(
            &fork,
            &unheld,
            SeedSide::BelowFork,
            BlockHeight::from_raw(3),
            &RuleSet::GENESIS,
            &window,
            BlockHeight::from_raw(3),
        );
        assert!(
            matches!(refused, AltSpend::BeyondCap(beyond)
                if beyond.depth.to_raw() == 5 && beyond.cap.to_raw() == 3),
            "{refused:?}"
        );
        // The same fork over the genesis floor is in reach, and its unheld
        // below-fork seed is the defect it always was.
        let in_reach = spend(
            &fork,
            &unheld,
            SeedSide::BelowFork,
            BlockHeight::from_raw(3),
            &RuleSet::GENESIS,
            &window,
            GENESIS_FLOOR,
        );
        assert!(
            matches!(in_reach, AltSpend::SeedNotInWindow { .. }),
            "{in_reach:?}"
        );
    }

    #[test]
    fn two_caps_name_at_most_two_seeds() {
        // The const assert is the compile-time pin. This names the
        // distance the window walks: `low` to `high` is the cap below and
        // `reach_above` above, under one seed epoch for every cap a
        // schedule can name (`ReorgCapOutrunsSeedEpoch`).
        let largest = shekyl_chain_rules::ReorgCapOutrunsSeedEpoch::LARGEST_CAP_BLOCKS;
        for cap in [1, 10, 64, 65, D_MAX.to_raw(), largest] {
            let cap = BlockCount::from_raw(cap);
            let connecting = BlockHeight::from_raw(SEEDHASH_EPOCH_BLOCKS);
            let low = connecting.saturating_sub_count(cap);
            let high = connecting.saturating_add(reach_above(cap));
            assert!(
                high.to_raw() - low.to_raw() < SEEDHASH_EPOCH_BLOCKS,
                "cap {cap:?}"
            );
            assert!(reach_above(cap).to_raw() > shekyl_difficulty::SEEDHASH_EPOCH_LAG);
        }
    }
}
