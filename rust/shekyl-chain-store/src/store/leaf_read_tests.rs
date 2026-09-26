// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The three DRS-E3 reads on the batch view, and the growth the verdict
//! derives from them (`DRS_E3_CURVE_WRITER.md` §3.1–§3.3, §6 commit 4b).
//!
//! What this file pins is the **read side and the derivation**: a
//! recorded block's outputs come back as leaf sources in output order, the
//! drain at `h` takes block `h − 60`'s coinbase then block `h − 10`'s
//! listed outputs, and the verdict carries a non-empty root over them.
//! The tree is not written yet — the phase-3 body is commit 5 — so the
//! frontier here is still `EMPTY` and every derived growth starts at leaf
//! `0`; commit 5's tests take over the "before" side.

use shekyl_chain_rules::{AtHeight, ChainView, RuleSet, TreeFrontier};
use shekyl_types::{BlockHeight, CurveTreeRoot, GlobalOutputIndex};

use super::connect_fixtures::{
    candidate, connect_chain, judge, spend, spendable_prefix, FIRST_SPEND_HEIGHT,
};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::*;

fn h(height: u64) -> BlockHeight {
    BlockHeight::from_raw(height)
}

/// Heights `0..=62` — the fixture `facts` root fits a byte up to `63`.
/// A two-output spend sits in block `53`, so a connect at `63` drains
/// block `3`'s coinbase and block `53`'s three outputs.
const TIP: u64 = 62;
const SPEND_HEIGHT: u64 = 53;
const _: () = assert!(SPEND_HEIGHT >= FIRST_SPEND_HEIGHT);

fn listing() -> Vec<Vec<shekyl_wire::Transaction>> {
    let mut listed = spendable_prefix(&[]);
    listed.resize(usize::try_from(TIP + 1).expect("small"), Vec::new());
    listed[usize::try_from(SPEND_HEIGHT).expect("small")] = vec![spend(9, 2)];
    listed
}

#[test]
fn outputs_at_returns_a_blocks_outputs_as_leaf_sources_in_output_order() {
    let path = tmp("leaf-outputs-at");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &listing());
    let snap = store.begin_read().expect("read");
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        // Heights below the spend hold one coinbase output each, so block
        // 53's coinbase is global output 53 and its spend's two are 54, 55.
        let AtHeight::Recorded(outputs) = view.outputs_at(h(SPEND_HEIGHT))? else {
            panic!("a recorded height");
        };
        let gids = |sources: &[shekyl_chain_rules::LeafSource]| {
            sources
                .iter()
                .map(|s| s.output.to_raw())
                .collect::<Vec<_>>()
        };
        assert_eq!(gids(&outputs.coinbase), vec![SPEND_HEIGHT]);
        assert_eq!(
            gids(&outputs.listed),
            vec![SPEND_HEIGHT + 1, SPEND_HEIGHT + 2]
        );
        // The key and commitment are the recorded rows'; the CM is the
        // `0x07` entry's point (that all three decompress is what the
        // derivation test below relies on).
        for source in outputs.coinbase.iter().chain(&outputs.listed) {
            let AtIndex::Recorded(recorded) = snap.output(source.output)? else {
                panic!("a recorded output");
            };
            assert_eq!(source.key, recorded.pubkey.to_bytes());
            assert_eq!(source.commitment, recorded.commitment.to_bytes());
            assert_ne!(
                source.pqc_leaf_commitment, [0; 32],
                "the 0x07 entry's point"
            );
            assert_ne!(source.pqc_leaf_commitment, source.key);
        }
        // A coinbase-only height has an empty listed half; past the tip is
        // `AboveTip`, not a fault.
        let AtHeight::Recorded(plain) = view.outputs_at(h(3))? else {
            panic!("a recorded height");
        };
        assert_eq!(plain.coinbase.len(), 1);
        assert!(plain.listed.is_empty());
        assert_eq!(view.outputs_at(h(TIP + 1))?, AtHeight::AboveTip);
        Ok(())
    });
    out.expect("reads");
    cleanup(&path);
}

#[test]
fn the_verdict_derives_the_drain_in_drain_order_over_an_unwritten_tree() {
    let path = tmp("leaf-derive");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &listing());
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        // Commit 5 writes the tree; until then the store's frontier is the
        // seal's, and a derived growth starts at position 0.
        assert_eq!(view.tree_frontier()?, TreeFrontier::EMPTY);
        assert_eq!(view.leaf_count_at(h(0))?, AtHeight::Recorded(0));
        assert_eq!(view.leaf_count_at(h(TIP + 2))?, AtHeight::AboveTip);
        assert_eq!(view.depth_at(h(0))?, AtHeight::Recorded(0));

        let connecting = TIP + 1;
        let previous = hashes[usize::try_from(TIP).expect("small")];
        let verdict = judge(&view, candidate(connecting, previous, Vec::new()))?;
        let block = verdict.block();
        let growth = block
            .growth()
            .expect("block 3's coinbase and block 53's listed matured");
        assert_eq!(growth.leaf_count_before, 0);
        assert_eq!(growth.leaves.len(), 3, "one coinbase + two listed");
        assert_eq!(growth.depth, 1);
        assert_eq!(block.root_after(), growth.root);
        assert_ne!(block.root_after(), CurveTreeRoot::EMPTY);
        // Drain order (§3.3): block 3's coinbase (global 3) is leaf 0;
        // block 53's listed outputs (54, 55) follow. Block 53's coinbase
        // and block 3's (empty) listed half are not in this drain.
        let drained = shekyl_chain_rules::drained_outputs(&view, h(connecting), &RuleSet::GENESIS)
            .expect("reads");
        assert_eq!(
            drained.iter().map(|s| s.output).collect::<Vec<_>>(),
            [3, SPEND_HEIGHT + 1, SPEND_HEIGHT + 2]
                .map(GlobalOutputIndex::from_raw)
                .to_vec()
        );
        Ok(())
    });
    out.expect("derives");
    cleanup(&path);
}

#[test]
fn before_any_window_elapses_the_verdict_carries_the_root_forward_unchanged() {
    let path = tmp("leaf-unchanged");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &spendable_prefix(&[])[..5]);
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let verdict = judge(&view, candidate(5, hashes[4], Vec::new()))?;
        let block = verdict.block();
        assert!(block.growth().is_none());
        assert_eq!(
            AtHeight::Recorded(block.root_after()),
            view.root_at(h(5))?,
            "nothing matured: the root going into 5 is the root after 5"
        );
        Ok(())
    });
    out.expect("derives");
    cleanup(&path);
}
