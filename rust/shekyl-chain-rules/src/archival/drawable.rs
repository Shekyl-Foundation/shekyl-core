// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The epoch's drawable set (`DrawableSet::at_epoch_open`, SO-D8 Q3).
//!
//! The enumerator is a pure function over the recorded chain: tip bond
//! records, the closed-and-final registry at `h_open(E)`, and the join
//! filter. No snapshot table (`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`
//! §7.4). The journal walk that recovers holdings a Release or slash has
//! cleared at tip is Slice C's — this increment lands the type and the
//! pins that do not need those journals (E_join, CompleteTree at
//! `h_open`, canonical order). Holder adapters until then read the same
//! tip held sets (`shekyl-archival-fetch-sched` `HolderSource`).

use shekyl_archival_retention::DrawablePair;
use shekyl_types::archival::{BondRecord, Holdings};
use shekyl_types::{BlockCount, BlockHeight, PCanonicalId, SettlementEpoch, ShardId};

use crate::archival::{closed_and_final, ClosedUniverse};
use crate::fault::ViewRead;
use crate::rule_set::RuleSet;
use crate::view::ChainView;

/// The drawable `(P, s)` pairs of one settlement epoch, in canonical
/// order (persona canonical-id bytes, then `shard_id` numeric).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DrawableSet {
    pairs: Vec<DrawablePair>,
}

impl DrawableSet {
    /// The pairs `E` can draw, computed at this view's tip against
    /// holdings as they stand and the shards that were closed and final
    /// at `h_open(E)` (SO-D8 §7.4 pins 1–3).
    ///
    /// An empty chain, or an epoch that has not opened on this tip,
    /// yields an empty set — genesis and a future `E` schedule nothing.
    ///
    /// # Errors
    ///
    /// The view's fault, or [`crate::Corrupt::ShardCloseUnplaced`] from
    /// [`closed_and_final`] when a shard the count says is closed has no
    /// close height.
    pub fn at_epoch_open<'id, V: ChainView<'id>>(
        view: &V,
        epoch: SettlementEpoch,
        rule_set: &RuleSet,
    ) -> Result<Self, ViewRead<V::Fault>> {
        let Some(tip) = view.tip().map_err(ViewRead::View)? else {
            return Ok(Self::default());
        };
        let h_open =
            BlockHeight::from_raw(rule_set.settlement_schedule().open_height(epoch.to_raw()));
        if h_open > tip.height {
            return Ok(Self::default());
        }
        let records = view.bond_records().map_err(ViewRead::View)?;
        let cap = rule_set.reorg_cap();
        // `final_before(h_open + 1, cap)` is `closed_and_final` at `h_open`
        // over the set. The per-shard walk re-derived the same predicate.
        let h_next = h_open
            .checked_add(BlockCount::ONE)
            .expect("h_open + 1 fits");
        let final_count = ClosedUniverse::final_before(view, h_next, cap)?
            .count()
            .get();
        let mut is_final = |shard: ShardId| closed_and_final(view, shard, h_open, cap);
        let pairs = emit_pairs(records, epoch, final_count, &mut is_final)?;
        Ok(Self { pairs })
    }

    /// The pairs, in canonical order.
    #[must_use]
    pub fn pairs(&self) -> &[DrawablePair] {
        &self.pairs
    }

    /// The pairs, consuming the set.
    #[must_use]
    pub fn into_pairs(self) -> Vec<DrawablePair> {
        self.pairs
    }
}

/// Pin 1 (exclude `E_join ≥ E`), pin 2 (`CompleteTree` over the
/// closed-and-final registry at `h_open`, not tip), pin 3 (sort persona
/// canonical-id bytes, then `shard_id` numeric). `final_count` is
/// [`ClosedUniverse::final_before`] at `h_open + 1`: a CompleteTree expands
/// `0..final_count` and does not re-derive the predicate per shard.
/// `is_final` is that same predicate for a compact holding, which names
/// shards rather than a prefix.
fn emit_pairs<E>(
    records: impl IntoIterator<Item = (PCanonicalId, BondRecord)>,
    epoch: SettlementEpoch,
    final_count: u64,
    is_final: &mut impl FnMut(ShardId) -> Result<bool, E>,
) -> Result<Vec<DrawablePair>, E> {
    let mut pairs = Vec::new();
    for (persona, record) in records {
        if record.join_settlement_epoch >= epoch {
            continue;
        }
        let p_id = persona.to_bytes();
        match &record.holdings {
            Holdings::CompleteTree => {
                for shard in 0..final_count {
                    pairs.push(DrawablePair {
                        p_id,
                        shard_id: shard,
                    });
                }
            }
            Holdings::ShardSet(held) => {
                for held in held.iter() {
                    if is_final(held.shard)? {
                        pairs.push(DrawablePair {
                            p_id,
                            shard_id: held.shard.to_raw(),
                        });
                    }
                }
            }
        }
    }
    pairs.sort_unstable();
    Ok(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archival::{closed_and_final, ClosedUniverse};
    use crate::harness::fixture::{recorded, root};
    use crate::harness::MockChain;
    use crate::view::RecordedBlock;
    use shekyl_archival_retention::ARCHIVAL_BOND_FLOOR_ATOMIC;
    use shekyl_types::archival::HeldShard;
    use shekyl_types::{ArchivalLength, BlockCount, SHARD_LENGTH};
    use shekyl_units::AtomicUnits;

    const P1: [u8; 32] = [0xa1; 32];
    const P2: [u8; 32] = [0xa2; 32];

    fn persona(p: [u8; 32]) -> PCanonicalId {
        PCanonicalId::from_bytes(p)
    }

    fn compact(p: [u8; 32], shards: &[u64], join: u64) -> (PCanonicalId, BondRecord) {
        (
            persona(p),
            BondRecord {
                hybrid_pubkey: vec![0xb1; 4],
                bond_spend_pk: vec![0xb5; 4],
                endpoint: [0xe0; 32],
                join_settlement_epoch: SettlementEpoch::from_raw(join),
                bonded_total: AtomicUnits::from_raw(
                    ARCHIVAL_BOND_FLOOR_ATOMIC * shards.len() as u64,
                ),
                holdings: Holdings::shard_set(
                    shards
                        .iter()
                        .map(|&shard| HeldShard {
                            shard: ShardId::from_raw(shard),
                            add_epoch: SettlementEpoch::from_raw(join),
                        })
                        .collect(),
                )
                .expect("distinct shards under the cap"),
                bad_intervals: Vec::new(),
                claimed_settlement_epochs: Vec::new(),
                first_paying_emission_height: None,
            },
        )
    }

    fn complete(p: [u8; 32], join: u64) -> (PCanonicalId, BondRecord) {
        let (id, mut record) = compact(p, &[], join);
        record.holdings = Holdings::CompleteTree;
        record.bonded_total = AtomicUnits::from_raw(ARCHIVAL_BOND_FLOOR_ATOMIC);
        (id, record)
    }

    fn pair(p: [u8; 32], shard: u64) -> DrawablePair {
        DrawablePair {
            p_id: p,
            shard_id: shard,
        }
    }

    #[test]
    fn empty_records_emit_nothing() {
        let pairs = emit_pairs(Vec::new(), SettlementEpoch::from_raw(1), 4, &mut |_| {
            Ok::<_, ()>(true)
        })
        .expect("no predicate read");
        assert!(pairs.is_empty());
    }

    #[test]
    fn a_bond_that_joined_in_e_is_not_drawable_in_e() {
        let records = [compact(P1, &[0], 1)];
        let pairs = emit_pairs(records, SettlementEpoch::from_raw(1), 4, &mut |_| {
            Ok::<_, ()>(true)
        })
        .expect("no predicate read");
        assert!(pairs.is_empty());
    }

    #[test]
    fn compact_holdings_keep_only_final_shards_and_sort_canonically() {
        let records = [compact(P2, &[2, 0], 0), compact(P1, &[1], 0)];
        let pairs = emit_pairs(records, SettlementEpoch::from_raw(1), 4, &mut |s| {
            Ok::<_, ()>(s.to_raw() != 2)
        })
        .expect("no predicate fault");
        assert_eq!(pairs, [pair(P1, 1), pair(P2, 0)]);
    }

    #[test]
    fn complete_tree_expands_the_closed_and_final_registry_not_tip() {
        let records = [complete(P1, 0)];
        let pairs = emit_pairs(records, SettlementEpoch::from_raw(1), 1, &mut |s| {
            Ok::<_, ()>(s.to_raw() == 0)
        })
        .expect("no predicate fault");
        assert_eq!(pairs, [pair(P1, 0)]);
    }

    /// Exemption 1: an empty chain has no tip and no pairs — the
    /// enumerator, not a planted archival state.
    #[test]
    fn an_empty_chain_has_an_empty_drawable_set() {
        MockChain::default().with_view(|view| {
            let set =
                DrawableSet::at_epoch_open(&view, SettlementEpoch::from_raw(0), &RuleSet::GENESIS)
                    .expect("no view fault");
            assert!(set.pairs().is_empty());
        });
    }

    /// Exemption 1: `h_open(E)` past the tip is a future epoch, not a
    /// fold to invent pairs from.
    #[test]
    fn an_epoch_that_has_not_opened_is_empty() {
        let w = SHARD_LENGTH.to_raw();
        let chain = MockChain::default().push(
            RecordedBlock {
                cumulative_archival_len: ArchivalLength::from_raw(w),
                ..recorded(1_000)
            },
            root(0x11),
        );
        chain.with_view(|view| {
            let set =
                DrawableSet::at_epoch_open(&view, SettlementEpoch::from_raw(1), &RuleSet::GENESIS)
                    .expect("genesis SEB opens epoch 1 far above this tip");
            assert!(set.pairs().is_empty());
        });
    }

    /// The closed-and-final predicate this enumerator uses is the same
    /// function CEN-J15 already pins on this fold sequence.
    #[test]
    fn closed_and_final_on_the_two_shard_fold_is_the_registry() {
        let w = SHARD_LENGTH.to_raw();
        let folds = [0, w, w + 3, 2 * w + 4, 2 * w + 4];
        let chain = folds
            .into_iter()
            .enumerate()
            .fold(MockChain::default(), |chain, (h, fold)| {
                chain.push(
                    RecordedBlock {
                        cumulative_archival_len: ArchivalLength::from_raw(fold),
                        ..recorded(1_000 + h as u64)
                    },
                    root(0x11),
                )
            });
        let cap = BlockCount::from_raw(2);
        chain.with_view(|view| {
            let h_open = BlockHeight::from_raw(4);
            assert!(closed_and_final(&view, ShardId::from_raw(0), h_open, cap).unwrap());
            assert!(!closed_and_final(&view, ShardId::from_raw(1), h_open, cap).unwrap());
            let universe = ClosedUniverse::final_before(
                &view,
                h_open.checked_add(BlockCount::ONE).expect("fits"),
                cap,
            )
            .unwrap();
            assert_eq!(universe.count().get(), 1);
        });
    }
}
