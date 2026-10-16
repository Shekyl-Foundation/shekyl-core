// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The relay floor off the view: the window reads the operands the
//! validator reads, a fork prices its own floors, and the store's
//! projections are what the owner is fed.

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_economics::{
    relay_floor_from, CirculatingSupply, FeeOperands, TxVolume, FULL_REWARD_ZONE,
    RELAY_FLOOR_LOOKBACK, RELAY_FLOOR_WINDOW,
};
use shekyl_types::{BlockHeight, LongTermWeight};
use shekyl_units::AtomicUnits;

use crate::fault::{Corrupt, ViewRead};
use crate::harness::fixture::{recorded_with_work, root};
use crate::harness::MockChain;
use crate::relay_floor::{fee_operands_at, relay_floor_at, relay_floor_window};
use crate::rules::miner::economics;
use crate::view::{AtHeight, ChainView, RecordedBlock};

fn h(n: u64) -> BlockHeight {
    BlockHeight::from_raw(n)
}

/// The planted root after the block at `height`; the fixture keys roots
/// by a byte, and these chains are a dozen blocks long.
fn root_after(height: u64) -> shekyl_types::CurveTreeRoot {
    root(u8::try_from(height + 1).expect("a dozen-block fixture"))
}

/// A recorded block at `height` carrying an accumulator and a listed
/// prefix sum: `coins` per block cumulatively, `txs` per block
/// cumulatively, a distinct identity per height.
fn block(height: u64, coins_per_block: u64, txs_per_block: u64) -> RecordedBlock {
    RecordedBlock {
        coins_generated: AtomicUnits::from_raw((height + 1) * coins_per_block),
        cumulative_tx_count: (height + 1) * txs_per_block,
        ..recorded_with_work(
            1_000 + height,
            CumulativeDifficulty::from_raw(u128::from(height + 1)),
        )
    }
}

/// A chain of `len` blocks, `txs` listed per block, one SKL-scale
/// accumulator step per block.
fn chain(len: u64, txs: u64) -> MockChain {
    let mut chain = MockChain::default();
    for height in 0..len {
        chain = chain.push(block(height, 1_000_000_000, txs), root_after(height));
    }
    chain
}

/// The owner fed from the operands read one by one — the independent
/// composition the window is held to.
fn owner_at(chain: &MockChain, height: u64, median: u64) -> u64 {
    let params = economics();
    chain.with_view(|view| {
        let parent_coins = if height == 0 {
            0
        } else {
            match view.block_at(h(height - 1)).expect("infallible") {
                AtHeight::Recorded(b) => b.coins_generated.to_raw(),
                AtHeight::AboveTip => panic!("parent recorded"),
            }
        };
        let burned = if height == 0 {
            0
        } else {
            match view.burned_through(h(height - 1)).expect("infallible") {
                AtHeight::Recorded(b) => b.to_raw(),
                AtHeight::AboveTip => panic!("parent recorded"),
            }
        };
        let tx_volume = crate::tx_volume_window(&view, h(height)).expect("window reads");
        relay_floor_from(
            FeeOperands {
                height,
                parent_coins_generated: parent_coins,
                supply: CirculatingSupply::derive(
                    AtomicUnits::from_raw(parent_coins),
                    AtomicUnits::from_raw(burned),
                )
                .expect("fixture burns under its emission"),
                tx_volume,
                long_term_effective_median: median,
            },
            params,
        )
        .expect("priced")
    })
}

/// The window at the connecting height is `G + 1` floors, oldest first,
/// each the owner at that height's operands; the connecting height's
/// median is derived (the zone on a zone-weighted chain) and every
/// recorded height's is its row.
#[test]
fn the_window_is_the_owner_at_each_heights_operands() {
    let chain = chain(12, 40).with_total_burned(AtomicUnits::from_raw(600));
    let connecting = 12u64;
    let window = chain.with_view(|view| relay_floor_window(&view, h(connecting)));
    let AtHeight::Recorded(window) = window.expect("the view answers") else {
        panic!("the connecting height is not above the tip");
    };
    assert_eq!(window.len(), RELAY_FLOOR_WINDOW);
    for (i, floor) in window.iter().enumerate() {
        let height = connecting - RELAY_FLOOR_LOOKBACK as u64 + i as u64;
        assert_eq!(
            *floor,
            owner_at(&chain, height, FULL_REWARD_ZONE),
            "floor at height {height}"
        );
    }
    // The floors are not all equal: the accumulator and the window move
    // with height, so a window that read one height six times would show.
    assert!(window.iter().any(|f| *f != window[0]) || window[0] >= 1);
    assert_eq!(
        chain.with_view(|view| relay_floor_at(&view, h(connecting))),
        Ok(AtHeight::Recorded(window[RELAY_FLOOR_LOOKBACK]))
    );
}

/// A chain shorter than `G` has a shorter window — stricter, never looser
/// (`relay_floor_admits` takes the minimum) — and genesis prices on no
/// parent: zero coins, zero burn, an empty volume window.
#[test]
fn a_short_chain_has_a_short_window_and_genesis_prices_on_nothing() {
    let empty = MockChain::default();
    let AtHeight::Recorded(ops) = empty
        .with_view(|view| fee_operands_at(&view, h(0)))
        .expect("the view answers")
    else {
        panic!("genesis is the connecting height of an empty chain");
    };
    assert_eq!(ops.parent_coins_generated, 0);
    assert_eq!(ops.supply.to_raw(), 0);
    assert_eq!(ops.tx_volume, TxVolume::window(0, 0));
    assert_eq!(ops.long_term_effective_median, FULL_REWARD_ZONE);
    assert_eq!(
        empty.with_view(|view| relay_floor_window(&view, h(0))),
        Ok(AtHeight::Recorded(vec![owner_at(
            &empty,
            0,
            FULL_REWARD_ZONE
        )]))
    );
    let three = chain(3, 10);
    let AtHeight::Recorded(window) = three
        .with_view(|view| relay_floor_window(&view, h(3)))
        .expect("the view answers")
    else {
        panic!("connecting");
    };
    assert_eq!(window.len(), 4, "heights 0 ..= 3");
    // Above the connecting height there is nothing to read.
    assert_eq!(
        three.with_view(|view| relay_floor_window(&view, h(4))),
        Ok(AtHeight::AboveTip)
    );
}

/// A recorded height reads its stored median; the connecting height
/// derives one. Plant a row and the recorded height's floor moves with
/// it while the connecting height's does not.
#[test]
fn a_recorded_height_reads_its_stored_median() {
    let plain = chain(8, 40);
    let planted = chain(8, 40).with_median_at(h(6), LongTermWeight::from_raw(2 * FULL_REWARD_ZONE));
    let at = |chain: &MockChain, height: u64| {
        chain
            .with_view(|view| relay_floor_at(&view, h(height)))
            .expect("the view answers")
    };
    assert_ne!(at(&plain, 6), at(&planted, 6), "the row is the operand");
    assert_eq!(
        at(&planted, 6),
        AtHeight::Recorded(owner_at(&planted, 6, 2 * FULL_REWARD_ZONE))
    );
    assert_eq!(at(&plain, 7), at(&planted, 7));
    assert_eq!(
        at(&plain, 8),
        at(&planted, 8),
        "the connecting height derives"
    );
}

/// The supply operand at a recorded height is the parent's emission less
/// the burned total THROUGH the parent, not the chain's whole fold: a
/// burn above the parent does not reach that height's floor.
#[test]
fn a_burn_above_the_parent_does_not_reach_a_recorded_heights_floor() {
    let base = chain(8, 200).with_total_burned(AtomicUnits::from_raw(300_000_000));
    // The same fold, all of it burned at height 7: heights ≤ 7 see none of
    // it at their parents, and only the connecting height's supply nets it.
    let late = chain(8, 200)
        .with_total_burned(AtomicUnits::from_raw(300_000_000))
        .with_burn_at(h(7), AtomicUnits::from_raw(300_000_000));
    let at = |chain: &MockChain, height: u64| {
        chain
            .with_view(|view| fee_operands_at(&view, h(height)))
            .expect("the view answers")
    };
    let AtHeight::Recorded(base_6) = at(&base, 6) else {
        panic!()
    };
    let AtHeight::Recorded(late_6) = at(&late, 6) else {
        panic!()
    };
    assert!(
        late_6.supply > base_6.supply,
        "nothing had burned through height 5 on the late chain"
    );
    let AtHeight::Recorded(base_8) = at(&base, 8) else {
        panic!()
    };
    let AtHeight::Recorded(late_8) = at(&late, 8) else {
        panic!()
    };
    assert_eq!(
        base_8.supply, late_8.supply,
        "the connecting height nets the whole fold"
    );
}

/// A fold above the parent's emission is the store invariant FL-R16c
/// names, raised as `Corrupt`, never priced as a zero supply.
#[test]
fn a_burn_above_the_emission_is_corrupt() {
    let chain = chain(4, 10).with_total_burned(AtomicUnits::from_raw(u64::MAX / 2));
    let out = chain.with_view(|view| relay_floor_at(&view, h(4)));
    assert!(
        matches!(
            out,
            Err(ViewRead::Corrupt(Corrupt::BurnExceedsEmission { .. }))
        ),
        "{out:?}"
    );
}

/// Two chains sharing a prefix and diverging after it: each view yields
/// its own fork's floors at the heights past the fork, and the same
/// floors below it — a reorg needs no ring to rebuild.
#[test]
fn the_window_on_a_forked_view_yields_the_forks_floors() {
    let fork_at = 6u64;
    let mut quiet = MockChain::default();
    let mut busy = MockChain::default();
    for height in 0..fork_at {
        quiet = quiet.push(block(height, 1_000_000_000, 40), root_after(height));
        busy = busy.push(block(height, 1_000_000_000, 40), root_after(height));
    }
    for height in fork_at..12 {
        // The forks differ in what they list: one keeps 40 a block, the
        // other 400 — a different window, a different `M_r`, `b` and `C`.
        quiet = quiet.push(
            RecordedBlock {
                cumulative_tx_count: fork_at * 40 + (height - fork_at + 1) * 40,
                ..block(height, 1_000_000_000, 40)
            },
            root_after(height),
        );
        busy = busy.push(
            RecordedBlock {
                cumulative_tx_count: fork_at * 40 + (height - fork_at + 1) * 400,
                ..block(height, 1_000_000_000, 40)
            },
            root_after(height),
        );
    }
    let floors = |chain: &MockChain, connecting: u64| -> Vec<u64> {
        match chain
            .with_view(|view| relay_floor_window(&view, h(connecting)))
            .expect("the view answers")
        {
            AtHeight::Recorded(w) => w,
            AtHeight::AboveTip => panic!("connecting"),
        }
    };
    // Below the fork the window is shared.
    assert_eq!(floors(&quiet, fork_at), floors(&busy, fork_at));
    // Past it each fork prices its own history.
    let quiet_tip = floors(&quiet, 12);
    let busy_tip = floors(&busy, 12);
    assert_ne!(quiet_tip, busy_tip);
    for (i, floor) in busy_tip.iter().enumerate() {
        let height = 12 - RELAY_FLOOR_LOOKBACK as u64 + i as u64;
        assert_eq!(*floor, owner_at(&busy, height, FULL_REWARD_ZONE));
        assert_eq!(quiet_tip[i], owner_at(&quiet, height, FULL_REWARD_ZONE));
    }
    assert!(
        busy_tip[RELAY_FLOOR_LOOKBACK] > quiet_tip[RELAY_FLOOR_LOOKBACK],
        "a busier window raises C and the floor"
    );
}
