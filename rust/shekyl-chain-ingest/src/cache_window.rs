// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The two RandomX caches an arrival may hash under.
//!
//! The cache store holds two slots. A cache is derived only for a seed the
//! chain has earned (B2, design review 2026-10-19):
//!
//! - **a main-chain seed in the window.** A block inside the reorg cap, and
//!   not below a reached checkpoint, whose seed lies below its fork names
//!   one of at most two seeds, because the window fits inside one seed
//!   epoch. The service pins that pair, older endpoint first and the
//!   connecting height's seed as the canonical slot. A below-fork seed
//!   outside the pair is a defect in this arithmetic, a fault.
//! - **the seed block of the arrival's own in-cap branch.** A branch that
//!   forked below a seed block and grew past it names its own block there.
//!   That block is a stored alt row whose proof of work passed, and no
//!   block names it until the branch holds 65 or more stored blocks from it
//!   up. It is prepared into the transient slot under the arrival's permit
//!   and never pinned; the form hashes with the cache the preparation
//!   returned.
//!
//! Only the main chain and the miner's next block move the canonical
//! slot, and every build takes a hasher permit.

use shekyl_chain_rules::{
    seed_height, AtHeight, Corrupt, Fork, PerHeightRecord, RuleSet, ViewRead, D_MAX,
};
use shekyl_chain_store::store::{ChainStore, ReadSnapshot, StoreError};
use shekyl_difficulty::SEEDHASH_EPOCH_BLOCKS;
use shekyl_types::{BlockCount, BlockHash, BlockHeight};

use crate::connector::PopBeyondReorgCap;
use crate::schedule::ChainRules;

/// Two reorg caps fit inside one seed epoch, so the two slots hold every
/// below-fork seed an in-cap alternative can name. A wider cap must not
/// assume that.
const _: () = assert!(
    2 * D_MAX.to_raw() < SEEDHASH_EPOCH_BLOCKS,
    "two reorg caps no longer fit in one seed epoch; the two cache slots cannot cover an in-cap alternative"
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
/// This is the window an install pins, and the only seeds a later install
/// may release. It is not what the cache slots hold. A run or a branch may
/// keep a seed beside the window; that resident pair is a [`SlotPair`],
/// published on [`Door::seeds`](crate::service::Door::seeds).
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

/// The seeds the two cache slots hold.
///
/// Distinct from [`SeedPair`]. The window is what the rules name. The slots
/// are what is resident: that window, or that window plus a seed a run or a
/// branch prepared and the window does not name. `None` from
/// [`from_stored`](Self::from_stored) until a seed is canonical. A cache
/// that sits only in the transient slot is not a pair a hash may use, and
/// the service does not hash until the window's canonical seed is pinned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotPair {
    /// The canonical slot.
    pub(crate) canonical: BlockHash,
    /// The transient slot, when it holds a seed.
    pub(crate) transient: Option<BlockHash>,
}

impl SlotPair {
    /// `slots` as the store reports them, canonical then transient.
    /// `None` when the canonical slot is empty.
    #[must_use]
    pub(crate) fn from_stored(
        (canonical, transient): (Option<BlockHash>, Option<BlockHash>),
    ) -> Option<Self> {
        canonical.map(|canonical| Self {
            canonical,
            transient,
        })
    }

    /// Whether `seed` is one of the two the slots hold.
    #[must_use]
    pub fn holds(self, seed: &BlockHash) -> bool {
        self.canonical == *seed || self.transient == Some(*seed)
    }

    /// Whether the slots hold exactly the seeds `window` names.
    #[must_use]
    pub fn same_seeds(self, window: SeedPair) -> bool {
        self.canonical == window.canonical && self.transient == window.transient
    }
}

/// What an alternative may cost before any cache is built or any proof of
/// work is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AltSpend {
    /// The fork is inside the band and the seed lies below it, in the
    /// pair. Hash it. Do not pin: the slots already hold the seed.
    Hash,
    /// The fork is inside the band and the seed is the branch's own block,
    /// above the fork. Prepare it into the transient slot under the
    /// arrival's permit, never pinned, and hash with the cache that
    /// returns.
    Prepare,
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

/// The seeds the slots must hold for `rules` at `store`'s tip.
///
/// # Errors
///
/// The store's, or [`Corrupt::HoleBelowTip`] when the store has no block
/// at the connecting height's seed height, which is below its tip.
pub(crate) fn seeds_for(
    store: &ChainStore,
    rules: ChainRules,
) -> Result<SeedPair, ViewRead<StoreError>> {
    seeds_on(&store.begin_read()?, rules)
}

/// [`seeds_for`] on `snap`: the window an alternative claimed on the same
/// snapshot is judged against.
///
/// # Errors
///
/// As [`seeds_for`].
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
    // epoch before that block is mined; that seed is not a slot.
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

/// The two slots from the seeds the chain can already name.
///
/// `older` is the far end below the tip, `newer` the far end above it.
/// A `None` end is an epoch the chain has not reached, so it is not a
/// slot. When both ends differ from `canonical` the lower one is the
/// transient slot: one seed boundary fits in the window.
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
        SeedSide::OnBranch => AltSpend::Prepare,
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

    #[test]
    fn a_pair_names_the_slots_once_a_seed_is_canonical() {
        let canonical = BlockHash::from_bytes([1; 32]);
        let transient = BlockHash::from_bytes([2; 32]);
        assert_eq!(SlotPair::from_stored((None, None)), None);
        assert_eq!(
            SlotPair::from_stored((None, Some(transient))),
            None,
            "a transient cache alone is not a pair a hash may use"
        );
        let pair = SlotPair::from_stored((Some(canonical), Some(transient))).expect("canonical");
        assert!(pair.holds(&canonical));
        assert!(pair.holds(&transient));
        assert!(pair.same_seeds(SeedPair {
            canonical,
            transient: Some(transient),
        }));
        assert!(!pair.same_seeds(SeedPair {
            canonical,
            transient: None,
        }));
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
    /// defect, never a reply. The branch's own seed block is prepared,
    /// whatever the pair holds.
    #[test]
    fn a_below_fork_miss_is_a_defect_and_a_branch_seed_is_prepared() {
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
        assert!(matches!(branch, AltSpend::Prepare), "{branch:?}");
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
    fn a_seed_the_chain_has_not_mined_is_not_a_slot() {
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
