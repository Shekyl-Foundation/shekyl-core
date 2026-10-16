// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The drain's source arithmetic and its two `Corrupt` arms. The
//! end-to-end drain — real outputs maturing into real growth — is the
//! store's connect tests (`shekyl-chain-store`), where outputs exist.

use core::convert::Infallible;

use shekyl_types::{
    BlockCount, BlockHash, BlockHeight, CurveTreeRoot, GlobalOutputIndex, KeyImage, TxHash,
};

use super::{drain, sources, tree_after, DrainSources};
use crate::fault::{Corrupt, PerHeightRecord, ViewRead};
use crate::rule_set::RuleSet;
use crate::tree_growth::TreeFrontier;
use crate::view::{
    AtHeight, BlockOutputs, ChainView, HeaderRecord, HeaderView, LeafSource, RecordedBlock,
    RecordedWeights, Tip,
};

fn h(height: u64) -> BlockHeight {
    BlockHeight::from_raw(height)
}

#[test]
fn the_sources_are_the_two_maturity_windows_back() {
    let rules = RuleSet::GENESIS;
    assert_eq!(
        sources(h(100), &rules),
        DrainSources {
            coinbase_of: Some(h(40)),
            listed_of: Some(h(90)),
        }
    );
    // Below either window, that half has nothing to drain yet.
    assert_eq!(
        sources(h(10), &rules),
        DrainSources {
            coinbase_of: None,
            listed_of: Some(h(0)),
        }
    );
    assert_eq!(
        sources(h(9), &rules),
        DrainSources {
            coinbase_of: None,
            listed_of: None,
        }
    );
    assert_eq!(
        sources(h(60), &rules),
        DrainSources {
            coinbase_of: Some(h(0)),
            listed_of: Some(h(50)),
        }
    );
}

/// A view that answers `outputs_at` from a closure and has an empty tree.
struct OutputsOnly<F: Fn(BlockHeight) -> AtHeight<BlockOutputs>>(F);

impl<'id, F: Fn(BlockHeight) -> AtHeight<BlockOutputs>> HeaderView<'id> for OutputsOnly<F> {
    type Fault = Infallible;
    fn tip(&self) -> Result<Option<Tip>, Infallible> {
        Ok(None)
    }
    fn header_at(&self, _: BlockHeight) -> Result<AtHeight<HeaderRecord>, Infallible> {
        Ok(AtHeight::AboveTip)
    }
}

impl<'id, F: Fn(BlockHeight) -> AtHeight<BlockOutputs>> ChainView<'id> for OutputsOnly<F> {
    fn has_key_image(&self, _: &KeyImage) -> Result<bool, Infallible> {
        Ok(false)
    }
    fn total_burned(&self) -> Result<shekyl_units::AtomicUnits, Infallible> {
        Ok(shekyl_units::AtomicUnits::ZERO)
    }
    fn block_at(&self, _: BlockHeight) -> Result<AtHeight<RecordedBlock>, Infallible> {
        Ok(AtHeight::AboveTip)
    }
    fn weights_window(
        &self,
        _: BlockHeight,
        _: BlockCount,
    ) -> Result<AtHeight<Vec<RecordedWeights>>, Infallible> {
        Ok(AtHeight::AboveTip)
    }
    fn has_transaction(&self, _: &TxHash) -> Result<bool, Infallible> {
        Ok(false)
    }
    fn height_of(&self, _: &BlockHash) -> Result<Option<BlockHeight>, Infallible> {
        Ok(None)
    }
    fn root_at(&self, _: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Infallible> {
        Ok(AtHeight::Recorded(CurveTreeRoot::EMPTY))
    }
    fn tree_frontier(&self) -> Result<TreeFrontier, Infallible> {
        Ok(TreeFrontier::EMPTY)
    }
    fn leaf_count_at(&self, _: BlockHeight) -> Result<AtHeight<u64>, Infallible> {
        Ok(AtHeight::Recorded(0))
    }
    fn outputs_at(&self, height: BlockHeight) -> Result<AtHeight<BlockOutputs>, Infallible> {
        Ok((self.0)(height))
    }
    // No bonds: the honest empty archival state (DRS-E4 §5.2).
    crate::archival_reads!(empty);
}

#[test]
fn nothing_matured_is_no_growth() {
    let view = OutputsOnly(|_| AtHeight::Recorded(BlockOutputs::default()));
    assert_eq!(drain(&view, h(100), &RuleSet::GENESIS), Ok(None));
    // Before any window has elapsed no source is read at all.
    let view = OutputsOnly(|_| AtHeight::AboveTip);
    assert_eq!(drain(&view, h(5), &RuleSet::GENESIS), Ok(None));
}

#[test]
fn a_source_height_the_view_withholds_is_a_hole_below_tip() {
    let view = OutputsOnly(|height| {
        if height == h(90) {
            AtHeight::AboveTip
        } else {
            AtHeight::Recorded(BlockOutputs::default())
        }
    });
    assert_eq!(
        drain(&view, h(100), &RuleSet::GENESIS),
        Err(ViewRead::Corrupt(Corrupt::HoleBelowTip {
            at: h(90),
            record: PerHeightRecord::Outputs,
        }))
    );
}

#[test]
fn a_recorded_output_whose_point_is_not_a_point_halts() {
    // 0xFF.. is not a canonical Ed25519 encoding; `construct_leaf` refuses it.
    let bad = LeafSource {
        output: GlobalOutputIndex::from_raw(7),
        key: [0xFF; 32],
        commitment: [0xFF; 32],
        pqc_leaf_commitment: [0xFF; 32],
    };
    let view = OutputsOnly(move |height| {
        if height == h(40) {
            AtHeight::Recorded(BlockOutputs {
                coinbase: vec![bad],
                listed: Vec::new(),
            })
        } else {
            AtHeight::Recorded(BlockOutputs::default())
        }
    });
    assert_eq!(
        drain(&view, h(100), &RuleSet::GENESIS),
        Err(ViewRead::Corrupt(Corrupt::LeafNotConstructible {
            output: GlobalOutputIndex::from_raw(7),
            input: shekyl_fcmp::LeafInput::OutputKey,
        }))
    );
}

#[test]
fn a_bad_leaf_commitment_names_that_point() {
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;
    use curve25519_dalek::scalar::Scalar;
    let point = |k: u64| (Scalar::from(k) * G).compress().to_bytes();
    let source = LeafSource {
        output: GlobalOutputIndex::from_raw(4),
        key: point(1),
        commitment: point(2),
        pqc_leaf_commitment: [0xff; 32],
    };
    let view = OutputsOnly(move |height| {
        if height == h(90) {
            AtHeight::Recorded(BlockOutputs {
                coinbase: Vec::new(),
                listed: vec![source],
            })
        } else {
            AtHeight::Recorded(BlockOutputs::default())
        }
    });
    assert_eq!(
        drain(&view, h(100), &RuleSet::GENESIS),
        Err(ViewRead::Corrupt(Corrupt::LeafNotConstructible {
            output: GlobalOutputIndex::from_raw(4),
            input: shekyl_fcmp::LeafInput::LeafCommitment,
        }))
    );
}

#[test]
fn real_points_grow_the_tree_from_empty() {
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;
    use curve25519_dalek::scalar::Scalar;
    let point = |k: u64| (Scalar::from(k) * G).compress().to_bytes();
    let source = |i: u64| LeafSource {
        output: GlobalOutputIndex::from_raw(i),
        key: point(i * 3 + 1),
        commitment: point(i * 3 + 2),
        pqc_leaf_commitment: point(i * 3 + 3),
    };
    let view = OutputsOnly(move |height| {
        if height == h(40) {
            AtHeight::Recorded(BlockOutputs {
                coinbase: vec![source(0)],
                listed: vec![source(1)],
            })
        } else if height == h(90) {
            AtHeight::Recorded(BlockOutputs {
                coinbase: vec![source(2)],
                listed: vec![source(3), source(4)],
            })
        } else {
            AtHeight::Recorded(BlockOutputs::default())
        }
    });
    let drained = drain(&view, h(100), &RuleSet::GENESIS)
        .expect("drains")
        .expect("grows");
    // Drain order: block 40's coinbase, then block 90's listed — never
    // block 40's listed or block 90's coinbase (SOK-10, §3.3).
    assert_eq!(
        drained
            .drained()
            .iter()
            .map(|row| row.output)
            .collect::<Vec<_>>(),
        [0, 3, 4].map(GlobalOutputIndex::from_raw).to_vec()
    );
    assert_eq!(drained.growth().leaf_count_before, 0);
    assert_eq!(drained.drained().len(), 3);
    assert_eq!(drained.growth().leaves_appended, 3);
    assert_ne!(drained.growth().root, CurveTreeRoot::EMPTY);
    assert_eq!(drained.growth().depth, 1);
}

/// A recorded output at `i` whose points are real, so its leaf constructs.
fn real_source(i: u64) -> LeafSource {
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;
    use curve25519_dalek::scalar::Scalar;
    let point = |k: u64| (Scalar::from(k) * G).compress().to_bytes();
    LeafSource {
        output: GlobalOutputIndex::from_raw(i),
        key: point(i * 3 + 1),
        commitment: point(i * 3 + 2),
        pqc_leaf_commitment: point(i * 3 + 3),
    }
}

/// CEN-L11's falsifier: every accepted output becomes a leaf. Growth has
/// no rule type (E3 Round 1, the module docs); the row binds because
/// CEN-B5 judges the next header's root against the root [`tree_after`]
/// derives, and that root is a function of every output the block
/// recorded. A drain that left one out would be a different root, which
/// B5 refuses at the next block.
#[test]
fn l11_an_accepted_output_left_out_of_the_tree_is_a_different_root() {
    let listed: Vec<LeafSource> = (1..=3).map(real_source).collect();
    let at = |outputs: Vec<LeafSource>| {
        OutputsOnly(move |height| {
            AtHeight::Recorded(if height == h(90) {
                BlockOutputs {
                    coinbase: Vec::new(),
                    listed: outputs.clone(),
                }
            } else {
                BlockOutputs::default()
            })
        })
    };
    let (root, drained) =
        tree_after(&at(listed.clone()), h(100), &RuleSet::GENESIS).expect("drains");
    let drained = drained.expect("grows");
    assert_eq!(
        drained
            .drained()
            .iter()
            .map(|row| row.output)
            .collect::<Vec<_>>(),
        listed.iter().map(|s| s.output).collect::<Vec<_>>(),
        "every recorded output is drained, in order"
    );
    for dropped in 0..listed.len() {
        let mut fewer = listed.clone();
        fewer.remove(dropped);
        let (short, _) = tree_after(&at(fewer), h(100), &RuleSet::GENESIS).expect("drains");
        assert_ne!(short, root, "dropping output {dropped} must move the root");
    }
}

/// CEN-L12's falsifier: maturity is deferred insertion. A coinbase
/// output recorded at `h` joins the tree when `h + 60` connects and a
/// listed output when `h + 10` does — at no earlier height and at no
/// other — and the drain reads nothing else (no `unlock_time`).
#[test]
fn l12_a_coinbase_leaf_joins_at_sixty_and_a_listed_leaf_at_ten_and_neither_earlier() {
    const RECORDED: u64 = 100;
    let view = OutputsOnly(|height| {
        AtHeight::Recorded(if height == h(RECORDED) {
            BlockOutputs {
                coinbase: vec![real_source(0)],
                listed: vec![real_source(1)],
            }
        } else {
            BlockOutputs::default()
        })
    });
    for connecting in RECORDED..=RECORDED + 70 {
        let drained: Vec<GlobalOutputIndex> = drain(&view, h(connecting), &RuleSet::GENESIS)
            .expect("drains")
            .map(|d| d.drained().iter().map(|row| row.output).collect())
            .unwrap_or_default();
        let coinbase = connecting == RECORDED + 60;
        let listed = connecting == RECORDED + 10;
        assert_eq!(
            drained.contains(&GlobalOutputIndex::from_raw(0)),
            coinbase,
            "coinbase leaf at {connecting}"
        );
        assert_eq!(
            drained.contains(&GlobalOutputIndex::from_raw(1)),
            listed,
            "listed leaf at {connecting}"
        );
    }
}
