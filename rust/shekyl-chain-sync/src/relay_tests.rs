// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! When a connected block is relayed (CS-Q2 step 7).
//!
//! The decision is [`crate::model::Sync`]'s, from the height the block took
//! and whether the node, with it, is `Behind`. How the block arrived does
//! not enter: a switch is that connect only after the owner translates it.

#![cfg(test)]

use shekyl_chain_rules::harness::fixture::{candidate_on, chain_of};
use shekyl_chain_rules::{AtHeight, HeaderView, RuleSet, Trust};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_levin::PortableMap;
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::PowBlob;

use crate::model::{Event, Outcome, Sync};
use crate::proof::{drive, open_claim, serialized};
use crate::scenarios::{answer, no_close, offer_tag, request_for, target_one, with_offer};
use crate::Command;

/// A shorter chain whose work meets or exceeds the tip already seen is a
/// replacement, not an ancestor. The reply can be applied before the tip
/// observation, and the height alone would then refuse the relay.
#[test]
fn a_shorter_heavier_replacement_is_not_beneath_the_tip_already_seen() {
    let rules = crate::proof::fixed(1, 64);
    let mut sync: Sync<u8, _> = Sync::new(Trust::UNANCHORED, move |_| rules);
    sync.local = Some(crate::model::Local {
        hash: BlockHash::from_bytes([1; 32]),
        height: Some(BlockHeight::from_raw(20)),
        work: CumulativeDifficulty::from_raw(100),
    });
    let arrival = BlockHash::from_bytes([2; 32]);
    assert!(
        sync.relays(
            arrival,
            BlockHeight::from_raw(8),
            CumulativeDifficulty::from_raw(101),
        ),
        "a shorter heavier tip was treated as an ancestor"
    );
    assert!(
        sync.relays(
            arrival,
            BlockHeight::from_raw(8),
            CumulativeDifficulty::from_raw(100),
        ),
        "equal work below the tip was treated as an ancestor"
    );
    assert!(
        !sync.relays(
            arrival,
            BlockHeight::from_raw(8),
            CumulativeDifficulty::from_raw(99),
        ),
        "a lighter block below the tip was relayed"
    );
}

/// A synced node that fetches the next block by sync relays it once it
/// connects: it is the new tip, and with it the node is not behind. The
/// supplier is named, so the fan-out skips it.
#[test]
fn a_synced_node_relays_a_tip_block_it_fetched_by_sync() {
    with_offer(|sync, view, tag, hash, _raw| {
        let out = drive(
            sync,
            view,
            Event::Entry {
                tag,
                outcome: Outcome::Connected {
                    height: BlockHeight::from_raw(8),
                },
            },
        );
        let relays: Vec<(BlockHash, u8)> = out
            .iter()
            .filter_map(|command| match command {
                Command::Relay { hash, from } => Some((*hash, *from)),
                _ => None,
            })
            .collect();
        assert_eq!(relays, vec![(hash, 1)], "{out:?}");
        no_close(&out);
    });
}

/// A node behind its best verified chain relays nothing. The first of two
/// verified blocks connects, and with it the node is still behind the
/// second: no relay. The second connects, the node is no longer behind,
/// and that block is relayed with its supplier named.
#[test]
fn a_node_behind_relays_nothing() {
    with_two_headers(|sync, view, (first_raw, first), (second_raw, second)| {
        let out = drive(sync, view, Event::Room { seats: 1 });
        let (who, asked) = request_for(&out).expect("the first body is wanted");
        assert_eq!(asked, vec![*first.as_bytes()]);
        let out = answer(sync, view, who, first_raw);
        let tag = offer_tag(&out);
        let out = drive(
            sync,
            view,
            Event::Entry {
                tag,
                outcome: Outcome::Connected {
                    height: BlockHeight::from_raw(8),
                },
            },
        );
        assert!(
            !out.iter()
                .any(|command| matches!(command, Command::Relay { .. })),
            "a node behind relayed: {out:?}"
        );
        let out = drive(sync, view, Event::Room { seats: 1 });
        let (who, asked) = request_for(&out).expect("the second body is wanted");
        assert_eq!(asked, vec![*second.as_bytes()]);
        let out = answer(sync, view, who, second_raw);
        let tag = offer_tag(&out);
        let out = drive(
            sync,
            view,
            Event::Entry {
                tag,
                outcome: Outcome::Connected {
                    height: BlockHeight::from_raw(9),
                },
            },
        );
        let relays: Vec<(BlockHash, u8)> = out
            .iter()
            .filter_map(|command| match command {
                Command::Relay { hash, from } => Some((*hash, *from)),
                _ => None,
            })
            .collect();
        assert_eq!(relays, vec![(second, who)], "{out:?}");
    });
}

/// Two blocks above the tip, `first` then `second`, whose headers session
/// 1 served and `T` holds: `H*` is `second`. Each is its raw block and its
/// hash.
fn with_two_headers<F>(f: F)
where
    F: for<'a, 'id> FnOnce(
        &mut Sync<u8, fn(BlockHeight) -> RuleSet>,
        &shekyl_chain_rules::harness::MockView<'a, 'id>,
        (Vec<u8>, BlockHash),
        (Vec<u8>, BlockHash),
    ),
{
    let main = chain_of(8);
    let mut block = candidate_on(&main, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, target_one as fn(BlockHeight) -> RuleSet);
    main.with_view(|view| {
        let tip = view.tip().expect("main answers").expect("a tip");
        drive(&mut sync, &view, Event::Tip { tip });
        open_claim(&mut sync, &view, 1);
        let timestamp = match view.header_at(tip.height).expect("main answers") {
            AtHeight::Recorded(record) => record.header.timestamp,
            AtHeight::AboveTip => panic!("the tip"),
        };
        block.header.previous = tip.hash;
        block.header.timestamp = timestamp + 120;
        block.header.nonce = 0;
        let first_raw = serialized(&block);
        let first_pow = block.pow_blob();
        let first = PowBlob::read(&first_pow).expect("preimage").identity();
        block.header.previous = first;
        block.header.timestamp = timestamp + 240;
        let second_raw = serialized(&block);
        let second_pow = block.pow_blob();
        let second = PowBlob::read(&second_pow).expect("preimage").identity();
        let out = drive(
            &mut sync,
            &view,
            Event::Headers {
                session: 1,
                bytes: shekyl_levin::ResponseHeaders {
                    blobs: vec![first_pow, second_pow],
                    tip_work: u128::MAX,
                    more: false,
                }
                .store()
                .expect("the headers encode"),
            },
        );
        assert!(sync.contains_header(second), "{out:?}");
        f(&mut sync, &view, (first_raw, first), (second_raw, second));
    });
}
