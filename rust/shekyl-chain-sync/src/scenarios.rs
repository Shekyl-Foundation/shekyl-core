// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Scripted peers for the behaviours a synthetic header does not reach.
//!
//! The spend chain is a captured corpus, hashed by [`crate::proof`]'s
//! substrate. The other tests are one or two target-1 headers: a proof
//! is one hash, and the subject is what the model does with the reply.

// Whole-file test module. `lib.rs` gates it with `#[cfg(test)]`, which
// the debug-macro lint cannot see, so the file declares itself. The
// timing line below is a test's output.
#![cfg(test)]

use std::io::BufReader;
use std::num::NonZeroU128;
use std::path::PathBuf;
use std::time::Instant;

use shekyl_chain_ingest::{CorpusReader, IngestEvent, Source};
use shekyl_chain_rules::harness::fixture::{candidate_on, chain_of};
use shekyl_chain_rules::{
    AtHeight, FakechainSchedule, HeaderRecord, HeaderView, RuleSet, SettlementEpochBlocks, Tip,
    Trust,
};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_draw_rng::RelayRng;
use shekyl_levin::PortableMap;
use shekyl_types::{BlockCount, BlockHash, BlockHeight, ChainCount, Timestamp};
use shekyl_wire::{BlockBody, PowBlob, SkeletonTx, TxBody};

use crate::harness::UnitWork;
use crate::model::{CloseCause, Event, Outcome, Proved, Sync};
use crate::proof::{drive, fixed, headers_of, open_claim, prove_item, serialized};
use crate::{Command, PeerClaim};

pub(crate) struct NoDraw;

impl RelayRng for NoDraw {
    fn next_u64(&mut self) -> u64 {
        0
    }
}

pub(crate) fn target_one(_: BlockHeight) -> RuleSet {
    fixed(1, 64)
}

fn coinbase(raw: Vec<u8>) -> BlockBody {
    BlockBody {
        block: raw,
        txs: Vec::new(),
        attestation_witness: Vec::new(),
    }
}

fn bodies(sent: Vec<BlockBody>, deferred: Vec<[u8; 32]>, missed: Vec<[u8; 32]>) -> Vec<u8> {
    shekyl_levin::ResponseBodies {
        bodies: sent,
        deferred,
        missed_ids: missed,
    }
    .store()
    .expect("the response encodes")
}

pub(crate) fn no_close(out: &[Command<u8>]) {
    assert!(
        out.iter()
            .all(|command| !matches!(command, Command::Close { .. })),
        "the session was closed: {out:?}"
    );
}

pub(crate) fn request_for(out: &[Command<u8>]) -> Option<(u8, Vec<[u8; 32]>)> {
    out.iter().find_map(|command| match command {
        Command::RequestBodies {
            session, request, ..
        } => Some((*session, request.hashes.clone())),
        _ => None,
    })
}

/// A listed transaction served as a skeleton binds, and the block is
/// wanted in full from the other session.
#[test]
fn a_spend_chain_skeleton_is_bound_and_wanted_in_full_from_another_session() {
    let started = Instant::now();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../shekyl-chain-ingest/tests/vectors/spend-1in-2out/corpus.e2");
    let file = std::fs::File::open(&path).expect("the spend corpus");
    let mut reader = CorpusReader::open(BufReader::new(file)).expect("the corpus opens");
    let mut candidates = Vec::new();
    while let Some(sequenced) = Source::next(&mut reader).expect("the corpus reads") {
        if let IngestEvent::Extend(candidate) = sequenced.event {
            candidates.push(*candidate);
        }
    }
    let spend = candidates
        .iter()
        .position(|candidate| !candidate.transactions.is_empty())
        .expect("the corpus lists a transaction");
    let records: Vec<HeaderRecord> = candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| HeaderRecord {
            hash: candidate.block.hash(),
            header: candidate.block.header.clone(),
            cumulative_difficulty: CumulativeDifficulty::from_raw(
                u128::try_from(index).unwrap() + 1,
            ),
        })
        .collect();
    let epoch = SettlementEpochBlocks::new(10_000).expect("the corpus epoch");
    let schedule =
        FakechainSchedule::new(epoch, BlockCount::from_raw(720)).expect("the corpus cap");
    let rules = RuleSet::fakechain(NonZeroU128::new(1), schedule);
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    let genesis = Prefix(&records[..1]);
    let tip = genesis.tip().expect("genesis").expect("a tip");
    drive(&mut sync, &genesis, Event::Tip { tip });
    open_claim(&mut sync, &genesis, 1);
    let blobs: Vec<Vec<u8>> = candidates[1..=spend]
        .iter()
        .map(|candidate| candidate.block.pow_blob())
        .collect();
    let spend_hash = records[spend].hash;
    let wall = candidates[1..=spend]
        .iter()
        .map(|candidate| candidate.block.header.timestamp)
        .max()
        .expect("a header");
    sync.set_wall(Timestamp::from_raw(wall));
    let out = drive(
        &mut sync,
        &genesis,
        Event::Headers {
            session: 1,
            bytes: shekyl_levin::ResponseHeaders {
                blobs,
                tip_work: u128::MAX,
                more: false,
            }
            .store()
            .expect("the headers encode"),
        },
    );
    assert!(
        sync.contains_header(spend_hash),
        "the spend header did not enter: {out:?}"
    );
    // `L` moves to the spend block's parent. The body span is that one block.
    let parent = Prefix(&records[..spend]);
    let parent_tip = parent.tip().expect("the parent").expect("a tip");
    drive(&mut sync, &parent, Event::Tip { tip: parent_tip });
    assert!(
        sync.contains_header(spend_hash),
        "moving L dropped the spend block"
    );
    open_claim(&mut sync, &parent, 2);
    let mut low = Vec::new();
    sync.claim(
        1,
        PeerClaim {
            count: ChainCount::from_raw(1),
            work: CumulativeDifficulty::from_raw(1),
            top: BlockHash::NULL,
        },
        &parent,
        Instant::now(),
        &mut NoDraw,
        &mut low,
    )
    .expect("a one-block claim is a chain");
    for request in 1..8 {
        drive(
            &mut sync,
            &parent,
            Event::Deadline {
                session: 1,
                request,
            },
        );
    }
    drive(
        &mut sync,
        &parent,
        Event::Headers {
            session: 2,
            bytes: headers_of(candidates[spend].block.pow_blob()),
        },
    );
    let out = drive(&mut sync, &parent, Event::Room { seats: 1 });
    let (who, asked) = request_for(&out).expect("the spend block is wanted");
    assert_eq!(who, 1, "the first server is asked first: {out:?}");
    assert_eq!(asked, vec![*spend_hash.as_bytes()]);
    let candidate = &candidates[spend];
    let tx = &candidate.transactions[0];
    let segments = tx.write_segments().expect("the transaction splits");
    let archival_len = segments.archival_len();
    let body = BlockBody {
        block: serialized(&candidate.block),
        txs: vec![TxBody::Skeleton(SkeletonTx {
            unprunable: segments.pruned,
            prunable_hash: tx.prunable_hash(),
            pqc_auth_hash: tx.pqc_auth_hash(),
            archival_len,
        })],
        attestation_witness: candidate
            .attestation_witness
            .as_ref()
            .map(|witness| witness.as_bytes().to_vec())
            .unwrap_or_default(),
    };
    let out = drive(
        &mut sync,
        &parent,
        Event::Bodies {
            session: 1,
            bytes: bodies(vec![body], Vec::new(), Vec::new()),
        },
    );
    no_close(&out);
    let (who, asked) = request_for(&out).expect("the skeleton is wanted in full");
    assert_eq!(
        who, 2,
        "the skeleton was asked of the session that served it: {out:?}"
    );
    assert_eq!(asked, vec![*spend_hash.as_bytes()]);
    eprintln!(
        "a_spend_chain_skeleton_is_bound_and_wanted_in_full_from_another_session: {} headers, {:?}",
        spend,
        started.elapsed()
    );
}

struct Prefix<'a>(&'a [HeaderRecord]);

impl HeaderView<'static> for Prefix<'_> {
    type Fault = core::convert::Infallible;

    fn tip(&self) -> Result<Option<Tip>, Self::Fault> {
        self.0.last().map_or(Ok(None), |record| {
            Ok(Some(Tip {
                height: BlockHeight::from_raw(u64::try_from(self.0.len()).unwrap() - 1),
                hash: record.hash,
            }))
        })
    }

    fn header_at(&self, height: BlockHeight) -> Result<AtHeight<HeaderRecord>, Self::Fault> {
        Ok(self
            .0
            .get(usize::try_from(height.to_raw()).unwrap())
            .cloned()
            .map_or(AtHeight::AboveTip, AtHeight::Recorded))
    }
}

struct TipAt {
    height: BlockHeight,
    hash: BlockHash,
    header: shekyl_wire::BlockHeader,
}

impl HeaderView<'static> for TipAt {
    type Fault = core::convert::Infallible;

    fn tip(&self) -> Result<Option<Tip>, Self::Fault> {
        Ok(Some(Tip {
            height: self.height,
            hash: self.hash,
        }))
    }

    fn header_at(&self, height: BlockHeight) -> Result<AtHeight<HeaderRecord>, Self::Fault> {
        if height != self.height {
            return Ok(AtHeight::AboveTip);
        }
        Ok(AtHeight::Recorded(HeaderRecord {
            hash: self.hash,
            header: self.header.clone(),
            cumulative_difficulty: CumulativeDifficulty::from_raw(1),
        }))
    }
}

/// Deferred may be asked of the session that deferred it. Unavailable is
/// asked of the other session first. Two headers, so the deferred hash is
/// not the first one held.
#[test]
fn a_deferred_body_is_asked_of_the_session_that_deferred_it() {
    parted(true);
}

#[test]
fn an_unavailable_body_is_asked_of_the_other_session_first() {
    parted(false);
}

fn parted(defer: bool) {
    let main = chain_of(8);
    let mut block = candidate_on(&main, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, target_one);
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
        let first_hash = PowBlob::read(&first_pow).expect("preimage").identity();
        block.header.previous = first_hash;
        block.header.timestamp = timestamp + 240;
        let second_pow = block.pow_blob();
        let second_hash = PowBlob::read(&second_pow).expect("preimage").identity();
        let out = drive(
            &mut sync,
            &view,
            Event::Headers {
                session: 1,
                bytes: shekyl_levin::ResponseHeaders {
                    blobs: vec![first_pow, second_pow.clone()],
                    tip_work: u128::MAX,
                    more: false,
                }
                .store()
                .expect("the headers encode"),
            },
        );
        assert!(
            sync.contains_header(second_hash),
            "the second header did not enter: {out:?}"
        );
        open_claim(&mut sync, &view, 2);
        let mut low = Vec::new();
        sync.claim(
            1,
            PeerClaim {
                count: ChainCount::from_raw(1),
                work: CumulativeDifficulty::from_raw(1),
                top: BlockHash::NULL,
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut low,
        )
        .expect("a one-block claim is a chain");
        for request in 1..8 {
            drive(
                &mut sync,
                &view,
                Event::Deadline {
                    session: 1,
                    request,
                },
            );
        }
        drive(
            &mut sync,
            &view,
            Event::Headers {
                session: 2,
                bytes: headers_of(second_pow),
            },
        );
        let out = drive(&mut sync, &view, Event::Room { seats: 2 });
        let (who, asked) = request_for(&out).expect("both blocks are wanted");
        assert_eq!(who, 1, "the first server is asked first: {out:?}");
        assert_eq!(asked.len(), 2, "the span is both headers: {asked:?}");
        let (deferred, missed) = if defer {
            (vec![*second_hash.as_bytes()], Vec::new())
        } else {
            (Vec::new(), vec![*second_hash.as_bytes()])
        };
        let out = drive(
            &mut sync,
            &view,
            Event::Bodies {
                session: 1,
                bytes: bodies(vec![coinbase(first_raw)], deferred, missed),
            },
        );
        no_close(&out);
        let (who, asked) = request_for(&out).expect("the held hash is wanted again");
        assert_eq!(asked, vec![*second_hash.as_bytes()]);
        let expect = if defer { 1 } else { 2 };
        assert_eq!(who, expect, "defer {defer}: {out:?}");
        let _ = first_hash;
    });
}

/// `H*` moves while a body request is out. The late response matches no
/// request, and the session stays.
///
/// The body is asked only once that header run has its headers. A second
/// session then outweighs the chain. Selection drops the span, and the
/// first session's body is not a fault.
#[test]
fn a_late_body_after_the_selected_chain_changes_is_not_a_fault() {
    let main = chain_of(8);
    let mut block = candidate_on(&main, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, target_one);
    main.with_view(|view| {
        let tip = view.tip().expect("main answers").expect("a tip");
        drive(&mut sync, &view, Event::Tip { tip });
        open_claim(&mut sync, &view, 1);
        open_claim(&mut sync, &view, 2);
        let timestamp = match view.header_at(tip.height).expect("main answers") {
            AtHeight::Recorded(record) => record.header.timestamp,
            AtHeight::AboveTip => panic!("the tip"),
        };
        block.header.previous = tip.hash;
        block.header.timestamp = timestamp + 120;
        block.header.nonce = 0;
        let first_pow = block.pow_blob();
        let first_hash = PowBlob::read(&first_pow).expect("preimage").identity();
        let out = drive(
            &mut sync,
            &view,
            Event::Headers {
                session: 1,
                bytes: headers_of(first_pow),
            },
        );
        assert!(
            sync.contains_header(first_hash),
            "the first header did not enter: {out:?}"
        );
        // The proof moves `H*` and the coordinator asks the frontier
        // again. That id is the live header request; an earlier one was
        // dropped when selection changed.
        let header_request = out.iter().rev().find_map(|command| match command {
            Command::RequestHeaders { session, id, .. } if *session == 1 => Some(*id),
            _ => None,
        });
        let Some(header_request) = header_request else {
            panic!("the frontier was not asked again: {out:?}");
        };
        let out = drive(&mut sync, &view, Event::Room { seats: 1 });
        let (who, asked) = request_for(&out).expect("the body was not requested");
        assert_eq!(who, 1, "the server of the header is asked: {out:?}");
        assert_eq!(asked, vec![*first_hash.as_bytes()]);
        // Session 1 leaves the draw. Ending its header request does not
        // end the body span.
        let mut low = Vec::new();
        sync.claim(
            1,
            PeerClaim {
                count: ChainCount::from_raw(1),
                work: CumulativeDifficulty::from_raw(1),
                top: BlockHash::NULL,
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut low,
        )
        .expect("a one-block claim is a chain");
        let out = drive(
            &mut sync,
            &view,
            Event::Deadline {
                session: 1,
                request: header_request,
            },
        );
        assert!(
            out.iter()
                .any(|command| { matches!(command, Command::RequestHeaders { session: 2, .. }) }),
            "session 2 was not asked: {out:?}"
        );
        // A sibling of the first header, then one more block. Two headers
        // outweigh the one-header chain.
        block.header.nonce = 1;
        let fork_pow = block.pow_blob();
        let fork_hash = PowBlob::read(&fork_pow).expect("preimage").identity();
        block.header.previous = fork_hash;
        block.header.timestamp = timestamp + 240;
        block.header.nonce = 0;
        let heavier_pow = block.pow_blob();
        let heavier_hash = PowBlob::read(&heavier_pow).expect("preimage").identity();
        let out = drive(
            &mut sync,
            &view,
            Event::Headers {
                session: 2,
                bytes: shekyl_levin::ResponseHeaders {
                    blobs: vec![fork_pow, heavier_pow],
                    tip_work: u128::MAX,
                    more: false,
                }
                .store()
                .expect("the headers encode"),
            },
        );
        assert!(
            sync.contains_header(heavier_hash),
            "the heavier header did not enter: {out:?}"
        );
        assert_eq!(sync.selected().hash, heavier_hash);
        let out = drive(
            &mut sync,
            &view,
            Event::Bodies {
                session: 1,
                bytes: bodies(Vec::new(), Vec::new(), Vec::new()),
            },
        );
        no_close(&out);
        assert!(sync.transit(1).is_some());
    });
}

#[test]
fn a_solicited_oversize_body_marks_the_header_and_closes() {
    with_offer(|sync, view, tag, hash, _raw| {
        let out = drive(
            sync,
            view,
            Event::Entry {
                tag,
                outcome: Outcome::Oversize { invalidate: true },
            },
        );
        assert!(
            out.iter().any(|command| matches!(
                command,
                Command::Close {
                    cause: CloseCause::Oversize,
                    ..
                }
            )),
            "oversize did not close: {out:?}"
        );
        assert!(sync.remembers_header(hash));
        assert!(sync.transit(1).is_none());
    });
}

#[test]
fn an_announced_oversize_body_closes_and_leaves_the_header() {
    with_offer(|sync, view, tag, hash, _raw| {
        let out = drive(
            sync,
            view,
            Event::Entry {
                tag,
                outcome: Outcome::Oversize { invalidate: false },
            },
        );
        assert!(
            out.iter().any(|command| matches!(
                command,
                Command::Close {
                    cause: CloseCause::Oversize,
                    ..
                }
            )),
            "an oversize announce did not close: {out:?}"
        );
        assert!(
            !sync.remembers_header(hash),
            "an oversize announce invalidated the header"
        );
        assert!(sync.transit(1).is_none());
    });
}

#[test]
fn cancelled_and_stopped_ask_for_the_block_again() {
    with_offer(|sync, view, tag, hash, raw| {
        let out = drive(
            sync,
            view,
            Event::Entry {
                tag,
                outcome: Outcome::Again,
            },
        );
        no_close(&out);
        let (who, asked) = request_for(&out).expect("cancelled is asked again");
        assert_eq!(asked, vec![*hash.as_bytes()]);
        let out = answer(sync, view, who, raw.clone());
        let tag = offer_tag(&out);
        let out = drive(
            sync,
            view,
            Event::Entry {
                tag,
                outcome: Outcome::Again,
            },
        );
        no_close(&out);
        let (_, asked) = request_for(&out).expect("stopped is asked again");
        assert_eq!(asked, vec![*hash.as_bytes()]);
        assert!(sync.transit(1).is_some());
    });
}

#[test]
fn a_connected_announce_is_relayed() {
    with_offer(|sync, view, tag, hash, _raw| {
        let out = drive(
            sync,
            view,
            Event::Entry {
                tag,
                outcome: Outcome::Connected { relay: true },
            },
        );
        assert!(
            out.iter().any(
                |command| matches!(command, Command::Relay { hash: relayed } if *relayed == hash)
            ),
            "a connected announce was not relayed: {out:?}"
        );
        no_close(&out);
    });
}

/// The header left `T` while its body request was still out. The body
/// passes the form check and is dropped. The session stays.
#[test]
fn a_body_for_a_header_no_longer_in_the_tree_is_not_a_fault() {
    let main = chain_of(8);
    let mut block = candidate_on(&main, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, target_one);
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
        let first = block.clone();
        let first_hash = PowBlob::read(&first.pow_blob())
            .expect("preimage")
            .identity();
        let out = drive(
            &mut sync,
            &view,
            Event::Headers {
                session: 1,
                bytes: shekyl_levin::ResponseHeaders {
                    blobs: vec![first.pow_blob()],
                    tip_work: u128::MAX,
                    more: true,
                }
                .store()
                .expect("the headers encode"),
            },
        );
        assert!(sync.contains_header(first_hash), "{out:?}");
        block.header.previous = first_hash;
        block.header.timestamp = timestamp + 240;
        let second_hash = PowBlob::read(&block.pow_blob())
            .expect("preimage")
            .identity();
        let out = drive(
            &mut sync,
            &view,
            Event::Headers {
                session: 1,
                bytes: headers_of(block.pow_blob()),
            },
        );
        assert!(sync.contains_header(second_hash), "{out:?}");
        let out = drive(&mut sync, &view, Event::Room { seats: 1 });
        let (_, asked) = request_for(&out).expect("the lower header is wanted");
        assert_eq!(asked, vec![*first_hash.as_bytes()]);
        let at = TipAt {
            height: tip.height + BlockCount::ONE,
            hash: first_hash,
            header: first.header.clone(),
        };
        drive(
            &mut sync,
            &at,
            Event::Tip {
                tip: Tip {
                    height: at.height,
                    hash: first_hash,
                },
            },
        );
        assert!(
            !sync.contains_header(first_hash),
            "the header stayed in T after it connected"
        );
        assert!(sync.contains_header(second_hash));
        let out = drive(
            &mut sync,
            &at,
            Event::Bodies {
                session: 1,
                bytes: bodies(vec![coinbase(serialized(&first))], Vec::new(), Vec::new()),
            },
        );
        no_close(&out);
        assert!(sync.transit(1).is_some());
    });
}

/// The run is under the tip, so it takes the slot. The next response is
/// hashed too: `prove_item` is the hash.
#[test]
fn the_slot_holder_is_hashed_on_each_response() {
    let rules = fixed(1, 2);
    let main = chain_of(40);
    let mut block = candidate_on(&main, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    main.with_view(|view| {
        let view = UnitWork(view);
        let tip = view.tip().expect("main answers").expect("a tip");
        drive(&mut sync, &view, Event::Tip { tip });
        open_claim(&mut sync, &view, 1);
        // Two below the tip: the cap is 2, so a deeper fork is past it,
        // and two blocks of work 1 land on the tip's work without passing it.
        let parent_height = BlockHeight::from_raw(tip.height.to_raw() - 2);
        let parent = match view.header_at(parent_height).expect("main answers") {
            AtHeight::Recorded(record) => record,
            AtHeight::AboveTip => panic!("the fork parent"),
        };
        let mut previous = parent.hash;
        let mut timestamp = parent.header.timestamp;
        let mut blobs = Vec::new();
        for _ in 0..2 {
            block.header.previous = previous;
            timestamp += 120;
            block.header.timestamp = timestamp;
            block.header.nonce = 0;
            let pow = block.pow_blob();
            previous = PowBlob::read(&pow).expect("preimage").identity();
            blobs.push(pow);
        }
        let mut out = Vec::new();
        sync.handle(
            Event::Headers {
                session: 1,
                bytes: shekyl_levin::ResponseHeaders {
                    blobs,
                    tip_work: u128::MAX,
                    more: true,
                }
                .store()
                .expect("the headers encode"),
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("main answers");
        hash_proves(&mut sync, &view, &mut out);
        assert_eq!(
            sync.slot_session(),
            Some(1),
            "the budget did not take the slot: {out:?}"
        );
        block.header.previous = previous;
        block.header.timestamp = timestamp + 120;
        let mut out = Vec::new();
        sync.handle(
            Event::Headers {
                session: 1,
                bytes: headers_of(block.pow_blob()),
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect("main answers");
        let hashed = out
            .iter()
            .any(|command| matches!(command, Command::Prove { .. }));
        assert!(
            hashed,
            "the slot holder was not hashed on the next response: {out:?}"
        );
        hash_proves(&mut sync, &view, &mut out);
        no_close(&out);
    });
}

fn hash_proves<'id, H, R>(sync: &mut Sync<u8, R>, main: &H, out: &mut Vec<Command<u8>>)
where
    H: HeaderView<'id>,
    H::Fault: std::fmt::Debug,
    R: Fn(BlockHeight) -> RuleSet,
{
    for _ in 0..4 {
        let Some((job, items)) = out.iter().find_map(|command| match command {
            Command::Prove { job, items, .. } => Some((*job, items.clone())),
            _ => None,
        }) else {
            return;
        };
        let mut results = Vec::new();
        for item in items {
            let formed = prove_item(&item).expect("target 1 accepts the header");
            results.push(Proved::Formed(Box::new(formed)));
        }
        out.clear();
        sync.handle(
            Event::Proven { job, results },
            main,
            Instant::now(),
            &mut NoDraw,
            out,
        )
        .expect("main answers");
    }
}

fn with_offer<F>(f: F)
where
    F: for<'a, 'id> FnOnce(
        &mut Sync<u8, fn(BlockHeight) -> RuleSet>,
        &shekyl_chain_rules::harness::MockView<'a, 'id>,
        u64,
        BlockHash,
        Vec<u8>,
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
        let raw = serialized(&block);
        let pow = block.pow_blob();
        let hash = PowBlob::read(&pow).expect("preimage").identity();
        let out = drive(
            &mut sync,
            &view,
            Event::Headers {
                session: 1,
                bytes: headers_of(pow),
            },
        );
        assert!(sync.contains_header(hash), "{out:?}");
        let out = drive(&mut sync, &view, Event::Room { seats: 1 });
        let (who, _) = request_for(&out).expect("the block is wanted");
        let out = answer(&mut sync, &view, who, raw.clone());
        let tag = offer_tag(&out);
        f(&mut sync, &view, tag, hash, raw);
    });
}

pub(crate) fn answer<'id, H>(
    sync: &mut Sync<u8, fn(BlockHeight) -> RuleSet>,
    view: &H,
    who: u8,
    raw: Vec<u8>,
) -> Vec<Command<u8>>
where
    H: HeaderView<'id>,
    H::Fault: std::fmt::Debug,
{
    drive(
        sync,
        view,
        Event::Bodies {
            session: who,
            bytes: bodies(vec![coinbase(raw)], Vec::new(), Vec::new()),
        },
    )
}

pub(crate) fn offer_tag(out: &[Command<u8>]) -> u64 {
    out.iter()
        .find_map(|command| match command {
            Command::Offer { arrivals } => Some(arrivals[0].tag),
            _ => None,
        })
        .expect("the body was not offered")
}
