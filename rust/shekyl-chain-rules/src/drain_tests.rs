// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The drain's source arithmetic and its two `Corrupt` arms. The
//! end-to-end drain — real outputs maturing into real growth — is the
//! store's connect tests (`shekyl-chain-store`), where outputs exist.

use core::convert::Infallible;

use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot, GlobalOutputIndex, KeyImage};

use super::{drain, sources, DrainSources};
use crate::fault::{Corrupt, PerHeightRecord, ViewRead};
use crate::rule_set::RuleSet;
use crate::tree_growth::TreeFrontier;
use crate::view::{AtHeight, BlockOutputs, ChainView, LeafSource, RecordedBlock, Tip};

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

impl<'id, F: Fn(BlockHeight) -> AtHeight<BlockOutputs>> ChainView<'id> for OutputsOnly<F> {
    type Fault = Infallible;
    fn has_key_image(&self, _: &KeyImage) -> Result<bool, Infallible> {
        Ok(false)
    }
    fn block_at(&self, _: BlockHeight) -> Result<AtHeight<RecordedBlock>, Infallible> {
        Ok(AtHeight::AboveTip)
    }
    fn height_of(&self, _: &BlockHash) -> Result<Option<BlockHeight>, Infallible> {
        Ok(None)
    }
    fn root_at(&self, _: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Infallible> {
        Ok(AtHeight::Recorded(CurveTreeRoot::EMPTY))
    }
    fn tip(&self) -> Result<Option<Tip>, Infallible> {
        Ok(None)
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
    let growth = drain(&view, h(100), &RuleSet::GENESIS)
        .expect("drains")
        .expect("grows");
    // Drain order: block 40's coinbase, then block 90's listed — never
    // block 40's listed or block 90's coinbase (SOK-10, §3.3).
    assert_eq!(growth.leaf_count_before, 0);
    assert_eq!(growth.leaves.len(), 3);
    assert_ne!(growth.root, CurveTreeRoot::EMPTY);
    assert_eq!(growth.depth, 1);
}
