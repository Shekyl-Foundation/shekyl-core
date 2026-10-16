// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The relay floor's window over the captured chains, held to the owner
//! fed from rows read independently (FL PR C §6).
//!
//! The replay connects each captured chain into a real store; this test
//! then asks `relay_floor_window` at every connecting height through the
//! store's `ChainView` and compares each floor with
//! `shekyl_economics::relay_floor_from` over operands read directly off
//! the committed snapshot: `block_info` rows for the parent's accumulator
//! and the two prefix sums, `block_burn` rows summed from genesis for the
//! burned total through the parent, the stored median at a recorded
//! height and `medians_over` the recorded weights at the connecting one.
//!
//! The captured traces carry no relay-floor value (the C++ ring is not
//! exported), so the C++ ring's floors cannot be compared here; the one
//! divergence known by construction is the burn operand (gross in the
//! C++, net here, FL-R16c), and it is zero on these chains until a block
//! burns.

#![cfg(test)]

use std::sync::Arc;

use shekyl_chain_rules::{
    medians_over, relay_floor_window, tx_volume_span, AtHeight, RecordedWeights,
};
use shekyl_chain_store::apply_policy::ApplyPolicy;
use shekyl_chain_store::store::StoreError;
use shekyl_economics::{
    relay_floor_from, CirculatingSupply, EconomicParams, FeeOperands, RELAY_FLOOR_LOOKBACK,
};
use shekyl_types::BlockHeight;
use shekyl_units::AtomicUnits;

use super::{captured_chains, mock_with_the_real_clock, replay_keeping_store};
use crate::test_support::{cleanup, h, open_store_under};

/// Every connecting height of every captured chain: the window off the
/// view equals the owner over independently read rows, height by height.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_window_off_the_store_is_the_owner_over_its_rows() {
    let params = EconomicParams::default();
    let substrate = mock_with_the_real_clock();
    let mut compared = 0usize;
    for (dir, manifest) in captured_chains() {
        let (report, path, rules) = replay_keeping_store(
            &dir,
            &manifest,
            Arc::clone(&substrate),
            ApplyPolicy::Full,
            "relay-floor",
        )
        .await;
        report
            .unwrap_or_else(|e| panic!("{}: the captured chain must replay: {e}", manifest.shape));
        let store = open_store_under(&path, &rules.in_force(h(0)), ApplyPolicy::Full);
        let snap = store.begin_read().expect("read");
        let tip = snap
            .tip()
            .expect("tip")
            .recorded
            .unwrap_or_else(|| panic!("{}: nothing connected", manifest.shape))
            .height;

        // The rows, read once, independently of the view: per height the
        // accumulator, the listed prefix sum, the stored median, the two
        // weights and the block's own burn.
        let mut infos = Vec::with_capacity(usize::try_from(tip.to_raw() + 1).expect("short"));
        let mut burned_through = Vec::with_capacity(infos.capacity());
        let mut fold = 0u64;
        for height in (0..=tip.to_raw()).map(h) {
            let AtHeight::Recorded(info) = snap.block_info(height).expect("row") else {
                panic!("{}: block_info[{height:?}] below the tip", manifest.shape);
            };
            let AtHeight::Recorded(burn) = snap.block_burn(height).expect("row") else {
                panic!("{}: block_burn[{height:?}] below the tip", manifest.shape);
            };
            fold = fold.checked_add(burn.to_raw()).expect("fits");
            infos.push(info);
            burned_through.push(fold);
        }
        assert_eq!(
            snap.total_burned().expect("fold").to_raw(),
            fold,
            "{}: the fold is the sum of its rows",
            manifest.shape
        );
        let weights: Vec<RecordedWeights> = infos
            .iter()
            .map(|i| RecordedWeights {
                weight: i.weight,
                long_term_weight: i.long_term_weight,
            })
            .collect();

        let at = |height: BlockHeight| usize::try_from(height.to_raw()).expect("short");
        let owner_at = |height: BlockHeight| -> u64 {
            let (parent_coins, burned) = match height.to_raw().checked_sub(1).map(h) {
                None => (0, 0),
                Some(parent) => (
                    infos[at(parent)].coins_generated.to_raw(),
                    burned_through[at(parent)],
                ),
            };
            let span = tx_volume_span(height);
            let sum_at = |at_height: Option<BlockHeight>| {
                at_height.map_or(0, |b| infos[at(b)].cumulative_tx_count)
            };
            let tx_volume = span
                .volume(sum_at(span.upper), sum_at(span.lower))
                .expect("prefix sums grow");
            let median = if height <= tip {
                infos[at(height)].long_term_effective_median.to_raw()
            } else {
                medians_over(&weights[..at(height)])
                    .long_term_effective_median
                    .to_raw()
            };
            relay_floor_from(
                FeeOperands {
                    height: height.to_raw(),
                    parent_coins_generated: parent_coins,
                    supply: CirculatingSupply::derive(
                        AtomicUnits::from_raw(parent_coins),
                        AtomicUnits::from_raw(burned),
                    )
                    .expect("a captured chain burns under its emission"),
                    tx_volume,
                    long_term_effective_median: median,
                },
                &params,
            )
            .expect("priced")
        };

        for connecting in (0..=tip.to_raw() + 1).map(h) {
            let window: Result<AtHeight<Vec<u64>>, StoreError> = store.write(|batch| {
                let view = batch.chain_view();
                relay_floor_window(&view, connecting).map_err(|e| match e {
                    shekyl_chain_rules::ViewRead::View(f) => f,
                    shekyl_chain_rules::ViewRead::Corrupt(c) => {
                        panic!("{}: corrupt at {connecting:?}: {c:?}", manifest.shape)
                    }
                })
            });
            let AtHeight::Recorded(window) = window.expect("the view answers") else {
                panic!(
                    "{}: {connecting:?} is at most the connecting height",
                    manifest.shape
                );
            };
            let oldest = connecting
                .to_raw()
                .saturating_sub(RELAY_FLOOR_LOOKBACK as u64);
            let expected: Vec<u64> = (oldest..=connecting.to_raw())
                .map(h)
                .map(owner_at)
                .collect();
            assert_eq!(
                window, expected,
                "{}: the window at {connecting:?} is not the owner over the rows",
                manifest.shape
            );
            compared += window.len();
        }
        drop(snap);
        drop(store);
        cleanup(&path);
    }
    assert!(compared > 0, "no floor was compared (rule 47)");
    println!("relay-floor: {compared} floors compared against the owner over the rows");
}
