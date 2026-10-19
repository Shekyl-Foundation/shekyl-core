// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The two RandomX caches an arrival may hash under.
//!
//! The cache store holds two slots. A block this node will hash — one
//! inside the reorg cap, and not below a reached checkpoint — names at
//! most those two seeds, because two caps fit inside one seed epoch. The
//! service pins that pair, older endpoint first and the connecting height's
//! seed as the canonical slot. An alternative whose seed is not one of
//! them is refused before any cache is built. Only the main chain and the
//! miner's next block move the canonical slot, and every build takes a
//! hasher permit.

use shekyl_chain_rules::{
    anchor_band, seed_height, AnchorBand, AtHeight, CenRow, Corrupt, Fork, InvalidBlock, Locus,
    PerHeightRecord, RuleSet, Trust, ViewRead, D_MAX,
};
use shekyl_chain_store::store::{ChainStore, ReadSnapshot, StoreError};
use shekyl_difficulty::SEEDHASH_EPOCH_BLOCKS;
use shekyl_types::{BlockHash, BlockHeight};

use crate::connector::PopBeyondReorgCap;
use crate::schedule::ChainRules;

/// Two reorg caps fit inside one seed epoch, so the two slots hold every
/// seed an in-cap alternative can name. A wider cap must not assume that.
const _: () = assert!(
    2 * D_MAX.to_raw() < SEEDHASH_EPOCH_BLOCKS,
    "two reorg caps no longer fit in one seed epoch; the two cache slots cannot cover an in-cap alternative"
);

/// The seeds the two slots hold: the connecting height's, and the other
/// endpoint of the serviceable window when it differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SeedPair {
    /// The seed a block connecting at the tip's successor hashes under.
    /// The canonical slot.
    pub(crate) canonical: BlockHash,
    /// The other seed the window names, in the transient slot.
    pub(crate) transient: Option<BlockHash>,
}

impl SeedPair {
    /// Whether `seed` is one of the two this pair holds.
    #[must_use]
    pub(crate) fn holds(self, seed: &BlockHash) -> bool {
        self.canonical == *seed || self.transient == Some(*seed)
    }
}

/// What an alternative may cost before any cache is built or any proof of
/// work is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AltSpend {
    /// The fork is inside the band and the seed is held. Hash it. Do not
    /// pin: the slots already hold the seed.
    Hash,
    /// Below a reached checkpoint, or past the cap on an anchored chain.
    /// CEN-E2. Nothing is stored.
    Refused(InvalidBlock),
    /// Past the cap on a chain where the cap does not bind as consensus.
    /// Local. Nothing is stored and nothing is hashed.
    BeyondCap(PopBeyondReorgCap),
    /// The seed is not one of the two slots. Local. Nothing is stored and
    /// nothing is hashed.
    OutsideWindow {
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
    let snap = store.begin_read()?;
    let tip = snap.tip()?.recorded;
    let connecting = shekyl_chain_rules::Tip::connecting_height(tip.as_ref());
    let cap = rules.in_force(connecting).reorg_cap();
    let low = connecting.saturating_sub_count(cap);
    let high = connecting.saturating_add(cap);
    // The connecting height's seed lags the tip, or is the null hash
    // before any block exists. The window's far end can name the next
    // epoch before that block is mined; that seed is not a slot.
    let canonical = required_seed(seed_hash(&snap, connecting)?, connecting)?;
    let older = seed_hash(&snap, low)?;
    let newer = seed_hash(&snap, high)?;
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

/// Whether `fork`'s block, hashing under `seed` at `height`, may be hashed
/// against `window`. Records nothing. Builds nothing.
#[must_use]
pub(crate) fn spend(
    fork: &Fork,
    seed: &BlockHash,
    height: BlockHeight,
    rule_set: &RuleSet,
    trust: &Trust,
    window: &SeedPair,
) -> AltSpend {
    match anchor_band(fork, rule_set, trust) {
        Some(AnchorBand::BelowAnchor { .. } | AnchorBand::BeyondCap { .. }) => {
            AltSpend::Refused(InvalidBlock::new(CenRow::E2, Locus::Block))
        }
        None if fork.pops() > rule_set.reorg_cap() => AltSpend::BeyondCap(PopBeyondReorgCap {
            depth: fork.pops(),
            cap: rule_set.reorg_cap(),
        }),
        None if !window.holds(seed) => AltSpend::OutsideWindow { height },
        None => AltSpend::Hash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_chain_rules::Tip;
    use shekyl_types::BlockCount;

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
    fn an_unanchored_fork_past_the_cap_is_not_hashed_and_not_an_invalid_block() {
        let fork = popping(BlockCount::from_raw(D_MAX.to_raw() + 1));
        let window = SeedPair {
            canonical: BlockHash::NULL,
            transient: None,
        };
        let spend = spend(
            &fork,
            &BlockHash::NULL,
            BlockHeight::from_raw(1),
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
            &window,
        );
        assert!(
            matches!(spend, AltSpend::BeyondCap(beyond) if beyond.cap == D_MAX),
            "{spend:?}"
        );
    }

    #[test]
    fn a_seed_outside_the_held_pair_is_not_hashed() {
        let fork = popping(BlockCount::from_raw(1));
        let window = SeedPair {
            canonical: BlockHash::NULL,
            transient: None,
        };
        let other = BlockHash::from_bytes([9; 32]);
        let spend = spend(
            &fork,
            &other,
            BlockHeight::from_raw(2),
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
            &window,
        );
        assert!(
            matches!(spend, AltSpend::OutsideWindow { height } if height == BlockHeight::from_raw(2)),
            "{spend:?}"
        );
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
            BlockHeight::from_raw(2),
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
            &window,
        );
        assert!(matches!(gated, AltSpend::Hash), "{gated:?}");
        // At the cap, still hashed: the cap binds only when anchored.
        let at_cap = popping(D_MAX);
        assert!(matches!(
            spend(
                &at_cap,
                &seed,
                BlockHeight::from_raw(2),
                &RuleSet::GENESIS,
                &Trust::UNANCHORED,
                &window,
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

    #[test]
    fn two_caps_name_at_most_two_seeds() {
        // The const assert is the compile-time pin. This names the
        // distance the window walks: `low` to `high` is `2 * cap`.
        let cap = BlockCount::from_raw(D_MAX.to_raw());
        let connecting = BlockHeight::from_raw(SEEDHASH_EPOCH_BLOCKS);
        let low = connecting.saturating_sub_count(cap);
        let high = connecting.saturating_add(cap);
        assert!(high.to_raw() - low.to_raw() == 2 * cap.to_raw());
        assert!(2 * cap.to_raw() < SEEDHASH_EPOCH_BLOCKS);
    }
}
