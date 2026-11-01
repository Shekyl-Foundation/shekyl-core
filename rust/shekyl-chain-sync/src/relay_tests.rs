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
use shekyl_chain_rules::{AtHeight, HeaderRecord, HeaderView, RuleSet, Trust};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_levin::PortableMap;
use shekyl_types::{BlockHash, BlockHeight, ChainCount};
use shekyl_wire::{Block, PowBlob};

use crate::claim::PeerClaim;
use crate::model::{Event, Outcome, Requesting, Sync};
use crate::proof::{drive, open_claim, resolve_opening, serialized};
use crate::scenarios::{
    answer, no_close, offer_tag, request_for, target_one, with_offer, NoDraw, Prefix,
};
use crate::Command;

/// A shorter chain whose work meets or exceeds the tip already seen is a
/// replacement, not an ancestor. The reply can be applied before the tip
/// observation, and the height alone would then refuse the relay.
#[test]
fn a_shorter_heavier_replacement_is_not_beneath_the_tip_already_seen() {
    let rules = crate::proof::fixed(1, 64);
    // Closed, with no session open: synced, so the relay judges `beneath`
    // alone, which is this test's subject.
    let mut sync: Sync<u8, _> =
        Sync::new(Trust::UNANCHORED, move |_| rules).with_declaration(crate::Declaration::Closed);
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
        assert_eq!(relays(&out), vec![(hash, Some(1))], "{out:?}");
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
        assert_eq!(relays(&out), vec![(second, Some(who))], "{out:?}");
    });
}

/// A tip no session supplied, such as a block this node mined, relays
/// from the tip event to every established session (CS-5 F1). The first
/// tip observed is the chain the node opened on, and a second observation
/// of the same tip is not new: neither relays.
#[test]
fn a_tip_no_session_supplied_relays_to_every_session() {
    let below = chain_of(8);
    let above = chain_of(9);
    let mut sync = Sync::new(Trust::UNANCHORED, target_one as fn(BlockHeight) -> RuleSet);
    below.with_view(|view| {
        let tip = view.tip().expect("main answers").expect("a tip");
        let out = drive(&mut sync, &view, Event::Tip { tip });
        assert!(relays(&out).is_empty(), "the opening tip relayed: {out:?}");
        open_claim(&mut sync, &view, 1);
        // The claim is never answered: the opening resolves at its deadline.
        resolve_opening(&mut sync, &view);
    });
    above.with_view(|view| {
        let tip = view.tip().expect("main answers").expect("a tip");
        let out = drive(&mut sync, &view, Event::Tip { tip });
        assert_eq!(relays(&out), vec![(tip.hash, None)], "{out:?}");
        let out = drive(&mut sync, &view, Event::Tip { tip });
        assert!(
            relays(&out).is_empty(),
            "the same tip relayed twice: {out:?}"
        );
    });
}

/// The store can report the tip before the entry's reply for the block the
/// model offered. The tip event relays nothing; the reply relays the block
/// once, with its supplier named, so the fan-out skips it.
#[test]
fn an_offered_tip_seen_before_its_reply_relays_once_from_the_reply() {
    with_offer(|sync, view, tag, hash, raw| {
        let records = with_block(view, &raw);
        let main = Prefix(&records);
        let tip = main.tip().expect("main answers").expect("a tip");
        assert_eq!(tip.hash, hash);
        let out = drive(sync, &main, Event::Tip { tip });
        assert!(
            relays(&out).is_empty(),
            "the tip event relayed an offered block: {out:?}"
        );
        let out = drive(
            sync,
            &main,
            Event::Entry {
                tag,
                outcome: Outcome::Connected {
                    height: BlockHeight::from_raw(8),
                },
            },
        );
        assert_eq!(relays(&out), vec![(hash, Some(1))], "{out:?}");
    });
}

/// The entry's reply before the tip event: the reply relays the block with
/// its supplier named, and the tip event that follows relays nothing.
#[test]
fn an_offered_tip_seen_after_its_reply_relays_once_from_the_reply() {
    with_offer(|sync, view, tag, hash, raw| {
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
        assert_eq!(relays(&out), vec![(hash, Some(1))], "{out:?}");
        let records = with_block(view, &raw);
        let main = Prefix(&records);
        let tip = main.tip().expect("main answers").expect("a tip");
        let out = drive(sync, &main, Event::Tip { tip });
        assert!(relays(&out).is_empty(), "a block relayed twice: {out:?}");
    });
}

/// The regtest `dev-sync` row off (CS-5 §2): the model builds no request
/// of any kind, where the same flow with requests on asks the claimant for
/// headers, and a tip this node mined still relays.
#[test]
fn with_requests_off_nothing_is_asked_and_a_mined_tip_still_relays() {
    for requesting in [Requesting::On, Requesting::Off] {
        let below = chain_of(8);
        let above = chain_of(9);
        let mut sync = Sync::new(Trust::UNANCHORED, target_one as fn(BlockHeight) -> RuleSet)
            .with_requesting(requesting);
        let mut out = Vec::new();
        below.with_view(|view| {
            let tip = view.tip().expect("main answers").expect("a tip");
            out.extend(drive(&mut sync, &view, Event::Tip { tip }));
            out.extend(drive(
                &mut sync,
                &view,
                Event::SessionOpened {
                    session: 1,
                    transit: std::time::Duration::from_secs(1),
                },
            ));
            sync.claim(
                1,
                PeerClaim {
                    count: ChainCount::from_raw(20),
                    work: CumulativeDifficulty::from_raw(u128::MAX),
                    top: BlockHash::NULL,
                },
                &view,
                std::time::Instant::now(),
                &mut NoDraw,
                &mut out,
            )
            .expect("the claim is a chain");
            out.extend(drive(&mut sync, &view, Event::Room { seats: 4 }));
        });
        let asked = out.iter().any(|command| {
            matches!(
                command,
                Command::RequestHeaders { .. }
                    | Command::RequestBodies { .. }
                    | Command::RequestComplement { .. }
                    | Command::RequestMissingTxs { .. }
            )
        });
        assert_eq!(
            asked,
            requesting == Requesting::On,
            "{requesting:?}: {out:?}"
        );
        // Nothing answers the claim: the opening resolves at its deadline.
        below.with_view(|view| {
            resolve_opening(&mut sync, &view);
        });
        above.with_view(|view| {
            let tip = view.tip().expect("main answers").expect("a tip");
            let out = drive(&mut sync, &view, Event::Tip { tip });
            assert_eq!(
                relays(&out),
                vec![(tip.hash, None)],
                "{requesting:?}: {out:?}"
            );
        });
    }
}

/// A tip that no entry reply judged for relay relays from the tip event
/// (CS-Q2 step 7; the ruling on #1169). Both offers come back `Noted`: the
/// first held as an alternative, the second a switch whose promoted tip is
/// not the arrival that caused it (`outcome_of`). Neither reply was a
/// connect, so the tip event relays the new tip, with no supplier named.
/// `accepted` holds both, so it cannot be what the tip event checks.
#[test]
fn a_tip_no_reply_judged_relays_from_the_tip_event() {
    with_two_headers(|sync, view, (first_raw, first), (second_raw, second)| {
        let out = drive(sync, view, Event::Room { seats: 1 });
        let (who, asked) = request_for(&out).expect("the first body is wanted");
        assert_eq!(asked, vec![*first.as_bytes()]);
        let out = answer(sync, view, who, first_raw.clone());
        let tag = offer_tag(&out);
        let out = drive(
            sync,
            view,
            Event::Entry {
                tag,
                outcome: Outcome::Noted,
            },
        );
        assert!(relays(&out).is_empty(), "a noted reply relayed: {out:?}");
        let out = drive(sync, view, Event::Room { seats: 1 });
        let (who, asked) = request_for(&out).expect("the second body is wanted");
        assert_eq!(asked, vec![*second.as_bytes()]);
        let out = answer(sync, view, who, second_raw.clone());
        let tag = offer_tag(&out);
        let out = drive(
            sync,
            view,
            Event::Entry {
                tag,
                outcome: Outcome::Noted,
            },
        );
        assert!(relays(&out).is_empty(), "a noted reply relayed: {out:?}");
        let records = with_block(view, &first_raw);
        let records = with_block(&Prefix(&records), &second_raw);
        let main = Prefix(&records);
        let tip = main.tip().expect("main answers").expect("a tip");
        assert_eq!(tip.hash, second);
        let out = drive(sync, &main, Event::Tip { tip });
        assert_eq!(relays(&out), vec![(second, None)], "{out:?}");
    });
}

/// Each relay in `out`: the block and its supplier.
fn relays(out: &[Command<u8>]) -> Vec<(BlockHash, Option<u8>)> {
    out.iter()
        .filter_map(|command| match command {
            Command::Relay { hash, from } => Some((*hash, *from)),
            _ => None,
        })
        .collect()
}

/// `view`'s records with `raw`'s block connected above its tip.
fn with_block<'id, H>(view: &H, raw: &[u8]) -> Vec<HeaderRecord>
where
    H: HeaderView<'id>,
    H::Fault: std::fmt::Debug,
{
    let tip = view.tip().expect("main answers").expect("a tip");
    let mut records: Vec<HeaderRecord> = (0..=tip.height.to_raw())
        .map(|height| {
            match view
                .header_at(BlockHeight::from_raw(height))
                .expect("main answers")
            {
                AtHeight::Recorded(record) => record,
                AtHeight::AboveTip => panic!("below the tip"),
            }
        })
        .collect();
    let work = records.last().expect("a tip").cumulative_difficulty;
    let block = Block::from_bytes(raw).expect("the block parses");
    let hash = PowBlob::read(&block.pow_blob())
        .expect("preimage")
        .identity();
    records.push(HeaderRecord {
        hash,
        header: block.header,
        cumulative_difficulty: CumulativeDifficulty::from_raw(work.to_raw() + 1),
    });
    records
}

/// Two blocks above the tip, `first` then `second`, whose headers session
/// 1 served and `T` holds: `H*` is `second`. Each is its raw block and its
/// hash.
pub(crate) fn with_two_headers<F>(f: F)
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

/// **An orphan re-syncs; it does not sever** (C2-R1c-Q3b, carried from
/// the C++ span loop into the model). The entry answers a body it could
/// not link (`Unlinked`, its parent reaches nothing this node holds): the
/// supplier keeps its session, and the model asks it for headers from the
/// missing parent. Only a refused block closes a session. Red edit: close
/// the session on `Unlinked`. `check_consensus_invariants.sh` [5/5] reads
/// this test and the arm it pins.
#[test]
fn an_unlinked_body_relocates_its_supplier_and_closes_nothing() {
    with_offer(|sync, view, tag, _hash, _raw| {
        let parent = BlockHash::from_bytes([0x77; 32]);
        let out = drive(
            sync,
            view,
            Event::Entry {
                tag,
                outcome: Outcome::Unlinked { at: parent },
            },
        );
        no_close(&out);
        assert!(sync.peers.contains_key(&1), "the supplier's session left");
        assert!(
            out.iter()
                .any(|command| matches!(command, Command::RequestHeaders { session: 1, .. })),
            "the supplier was not asked for headers from the missing parent: {out:?}"
        );
    });
}
