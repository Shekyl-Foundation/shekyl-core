// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Real proofs for the sync model's tests.
//!
//! One [`CacheStore`] for the process. A header under a fixed target of 1
//! is a proof at nonce 0: every RandomX output satisfies, so verification
//! is one hash. A forged header is mined at target 2 and then altered;
//! the refusal is that hash failing.

// Whole-file test module. `lib.rs` gates it with `#[cfg(test)]`, which
// the debug-macro lint cannot see, so the file declares itself. The
// timing line below is a test's output.
#![cfg(test)]

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use shekyl_chain_ingest::{Metrics, ProductionSubstrate};
use shekyl_chain_rules::harness::fixture::{candidate_on, chain_of};
use shekyl_chain_rules::{
    form_header, AtHeight, FakechainSchedule, FormAttempt, HeaderView, InvalidBlock, RuleSet,
    SettlementEpochBlocks, Substrate, Trust,
};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_draw_rng::RelayRng;
use shekyl_levin::PortableMap;
use shekyl_pow_randomx::CacheStore;
use shekyl_types::{BlockCount, BlockHash, BlockHeight, ChainCount};
use shekyl_wire::{Block, BlockBody, PowBlob};

use crate::model::{CloseCause, Event, Outcome, ProveItem, Proved, Sync};

use crate::{Command, PeerClaim};

pub(crate) fn substrate() -> &'static ProductionSubstrate {
    static CELL: OnceLock<ProductionSubstrate> = OnceLock::new();
    CELL.get_or_init(|| {
        ProductionSubstrate::new(Arc::new(CacheStore::new()), Arc::new(Metrics::new()))
    })
}

/// One real verification of a prove item. `Err` is the header's refusal.
pub(crate) fn prove_item(
    item: &ProveItem,
) -> Result<shekyl_chain_rules::FormedHeader, InvalidBlock> {
    let substrate = substrate();
    substrate.pin_seed(&item.seed);
    let pow = PowBlob::read(&item.pow).expect("the preimage parses");
    match form_header(
        &pow,
        &item.rule_set,
        substrate,
        item.seed,
        item.target,
        item.attempt,
    ) {
        Ok(Ok(formed)) => Ok(formed),
        Ok(Err(refused)) => Err(refused),
        Err(fault) => panic!("the production substrate faulted: {fault}"),
    }
}

pub(crate) fn fixed(target: u128, blocks: u64) -> RuleSet {
    let epoch = SettlementEpochBlocks::new(512).expect("512");
    let schedule =
        FakechainSchedule::new(epoch, BlockCount::from_raw(blocks)).expect("cap inside the epoch");
    RuleSet::fakechain(core::num::NonZeroU128::new(target), schedule)
}

struct NoDraw;

impl RelayRng for NoDraw {
    fn next_u64(&mut self) -> u64 {
        0
    }
}

pub(crate) fn drive<'id, H, R>(
    sync: &mut Sync<u8, R>,
    main: &H,
    event: Event<u8>,
) -> Vec<Command<u8>>
where
    H: HeaderView<'id>,
    H::Fault: std::fmt::Debug,
    R: Fn(BlockHeight) -> RuleSet,
{
    let mut out = Vec::new();
    sync.handle(event, main, Instant::now(), &mut NoDraw, &mut out)
        .expect("the view answers");
    resolve(&mut out, sync, main);
    out
}

fn resolve<'id, H, R>(out: &mut Vec<Command<u8>>, sync: &mut Sync<u8, R>, main: &H)
where
    H: HeaderView<'id>,
    H::Fault: std::fmt::Debug,
    R: Fn(BlockHeight) -> RuleSet,
{
    for _ in 0..8 {
        let Some((job, items)) = out.iter().find_map(|command| match command {
            Command::Prove { job, items, .. } => Some((*job, items.clone())),
            _ => None,
        }) else {
            return;
        };
        let mut results = Vec::new();
        for item in items {
            match prove_item(&item) {
                Ok(formed) => results.push(Proved::Formed(Box::new(formed))),
                Err(refused) => {
                    results.push(Proved::Refused(refused));
                    break;
                }
            }
        }
        let mut next = Vec::new();
        sync.handle(
            Event::Proven { job, results },
            main,
            Instant::now(),
            &mut NoDraw,
            &mut next,
        )
        .expect("the view answers");
        out.append(&mut next);
    }
}

/// Mine under `rules` until the header passes, then return a mutation
/// that fails. The panic names the nonce that passed.
fn forged_preimage<'id, H>(
    view: &H,
    rules: &RuleSet,
    block: &mut Block,
    parent: BlockHash,
) -> Vec<u8>
where
    H: HeaderView<'id>,
    H::Fault: std::fmt::Debug,
{
    let tip = view.tip().expect("the view answers").expect("a tip");
    let timestamp = match view.header_at(tip.height).expect("the view answers") {
        AtHeight::Recorded(record) => record.header.timestamp + 120,
        AtHeight::AboveTip => panic!("the tip is on the view"),
    };
    block.header.previous = parent;
    block.header.timestamp = timestamp;
    let connecting = tip.height + BlockCount::ONE;
    let seed = match view
        .header_at(shekyl_chain_rules::seed_height(connecting).unwrap_or(BlockHeight::ZERO))
        .expect("the view answers")
    {
        AtHeight::Recorded(record) => record.hash,
        AtHeight::AboveTip => BlockHash::NULL,
    };
    let target = shekyl_chain_rules::target_claim(view, connecting, rules)
        .expect("the view answers")
        .expect("the target is claimed");
    let mut passed = None;
    for nonce in 0..64u32 {
        block.header.nonce = nonce;
        let pow = PowBlob::read(&block.pow_blob()).expect("preimage");
        let item = ProveItem {
            pow: pow.write(),
            seed,
            target,
            attempt: FormAttempt::FIRST,
            rule_set: *rules,
        };
        if prove_item(&item).is_ok() {
            passed = Some(nonce);
            break;
        }
    }
    let Some(nonce) = passed else {
        panic!("no nonce in 0..64 passed at this target");
    };
    for flip in 1..16u32 {
        block.header.nonce = nonce ^ flip;
        let pow = PowBlob::read(&block.pow_blob()).expect("preimage");
        let item = ProveItem {
            pow: pow.write(),
            seed,
            target,
            attempt: FormAttempt::FIRST,
            rule_set: *rules,
        };
        if prove_item(&item).is_err() {
            return pow.write();
        }
    }
    panic!("nonce {nonce} passed, and nonce^{nonce}..15 still passed");
}

pub(crate) fn open_claim<'id, H, R>(sync: &mut Sync<u8, R>, main: &H, session: u8)
where
    H: HeaderView<'id>,
    H::Fault: std::fmt::Debug,
    R: Fn(BlockHeight) -> RuleSet,
{
    drive(
        sync,
        main,
        Event::SessionOpened {
            session,
            transit: Duration::from_secs(1),
        },
    );
    let mut out = Vec::new();
    sync.claim(
        session,
        PeerClaim {
            count: ChainCount::from_raw(2),
            work: CumulativeDifficulty::from_raw(u128::MAX),
        },
        main,
        Instant::now(),
        &mut NoDraw,
        &mut out,
    )
    .expect("the claim is a chain");
}

/// A `Stale` from `judge_header` is planned again with the attempt the
/// fault names. The session stays open.
#[test]
fn a_stale_proof_is_planned_again_with_its_attempt() {
    let rules = fixed(1, 64);
    let main = chain_of(8);
    let mut block = candidate_on(&main, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    main.with_view(|view| {
        let tip = view.tip().unwrap().unwrap();
        drive(&mut sync, &view, Event::Tip { tip });
        open_claim(&mut sync, &view, 1);
        let timestamp = match view.header_at(tip.height).unwrap() {
            AtHeight::Recorded(record) => record.header.timestamp,
            AtHeight::AboveTip => panic!("the tip"),
        };
        block.header.previous = tip.hash;
        block.header.timestamp = timestamp + 120;
        block.header.nonce = 0;
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
        .unwrap();
        let (job, mut item) = out
            .iter()
            .find_map(|command| match command {
                Command::Prove { job, items, .. } => items.first().map(|item| (*job, item.clone())),
                _ => None,
            })
            .expect("the header is proved");
        item.seed = BlockHash::from_bytes([9; 32]);
        let formed = prove_item(&item).expect("target 1 accepts the altered seed");
        let attempt = formed.attempt();
        out.clear();
        sync.handle(
            Event::Proven {
                job,
                results: vec![Proved::Formed(Box::new(formed))],
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        assert!(
            out.iter()
                .all(|command| !matches!(command, Command::Close { .. })),
            "a stale result closed the session: {out:?}"
        );
        let replanned = out.iter().any(|command| match command {
            Command::Prove { items, .. } => items.iter().any(|item| item.attempt != attempt),
            _ => false,
        });
        assert!(
            replanned,
            "the stale attempt was not planned again: {out:?}"
        );
        assert!(sync.transit(1).is_some());
    });
}

/// A header mined at target 2 and then altered is a real refusal, and the
/// session closes.
#[test]
fn an_invalid_proof_closes_the_session() {
    let rules = fixed(2, 64);
    let main = chain_of(8);
    let mut block = candidate_on(&main, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    let started = Instant::now();
    main.with_view(|view| {
        let tip = view.tip().unwrap().unwrap();
        drive(&mut sync, &view, Event::Tip { tip });
        open_claim(&mut sync, &view, 1);
        let bad = forged_preimage(&view, &rules, &mut block, tip.hash);
        let bytes = shekyl_levin::ResponseHeaders {
            blobs: vec![bad],
            tip_work: u128::MAX,
            more: false,
        }
        .store()
        .unwrap();
        let out = drive(&mut sync, &view, Event::Headers { session: 1, bytes });
        assert!(
            out.iter().any(|command| matches!(
                command,
                Command::Close {
                    cause: CloseCause::HeaderRefused(_),
                    ..
                }
            )),
            "a forged proof did not close: {out:?}"
        );
        assert!(sync.transit(1).is_none());
    });
    eprintln!(
        "an_invalid_proof_closes_the_session: {:?}",
        started.elapsed()
    );
}

pub(crate) fn serialized(block: &Block) -> Vec<u8> {
    let mut bytes = Vec::new();
    block.write(&mut bytes).expect("the block encodes");
    bytes
}

pub(crate) fn headers_of(pow: Vec<u8>) -> Vec<u8> {
    shekyl_levin::ResponseHeaders {
        blobs: vec![pow],
        tip_work: u128::MAX,
        more: false,
    }
    .store()
    .expect("the response encodes")
}

/// The reply is the arrival's tag. Refusing the second span closes only
/// that session and marks only that header.
#[test]
fn a_reply_is_the_arrival_it_was_tagged_with() {
    let rules = fixed(1, 64);
    let main = chain_of(8);
    let mut block = candidate_on(&main, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    main.with_view(|view| {
        let tip = view.tip().unwrap().unwrap();
        drive(&mut sync, &view, Event::Tip { tip });
        open_claim(&mut sync, &view, 1);
        open_claim(&mut sync, &view, 2);
        let timestamp = match view.header_at(tip.height).unwrap() {
            AtHeight::Recorded(record) => record.header.timestamp,
            AtHeight::AboveTip => panic!("the tip"),
        };
        block.header.previous = tip.hash;
        block.header.timestamp = timestamp + 120;
        block.header.nonce = 0;
        let first_bytes = serialized(&block);
        let first_pow = block.pow_blob();
        let first_hash = PowBlob::read(&first_pow).unwrap().identity();
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
        // Take session 1 out of the draw, then end its outstanding
        // request. The replacement is session 2's.
        let mut low = Vec::new();
        sync.claim(
            1,
            PeerClaim {
                count: ChainCount::from_raw(1),
                work: CumulativeDifficulty::from_raw(1),
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
        block.header.previous = first_hash;
        block.header.timestamp = timestamp + 240;
        let second_bytes = serialized(&block);
        let second_pow = block.pow_blob();
        let second_hash = PowBlob::read(&second_pow).unwrap().identity();
        let out = drive(
            &mut sync,
            &view,
            Event::Headers {
                session: 2,
                bytes: headers_of(second_pow),
            },
        );
        assert!(
            sync.contains_header(second_hash),
            "the second header did not enter: {out:?}"
        );
        let mut out = drive(&mut sync, &view, Event::Room { seats: 1 });
        let (who, asked) = out
            .iter()
            .find_map(|command| match command {
                Command::RequestBodies {
                    session, request, ..
                } => Some((*session, request.hashes.clone())),
                _ => None,
            })
            .expect("the first body is wanted");
        assert_eq!(asked.len(), 1);
        let raw = if asked[0] == *first_hash.as_bytes() {
            first_bytes.clone()
        } else {
            second_bytes.clone()
        };
        let body = BlockBody {
            block: raw,
            txs: Vec::new(),
            attestation_witness: Vec::new(),
        };
        out = drive(
            &mut sync,
            &view,
            Event::Bodies {
                session: who,
                bytes: shekyl_levin::ResponseBodies {
                    bodies: vec![body],
                    deferred: Vec::new(),
                    missed_ids: Vec::new(),
                }
                .store()
                .unwrap(),
            },
        );
        let first_tag = out.iter().find_map(|command| match command {
            Command::Offer { arrivals } => Some(arrivals[0].tag),
            _ => None,
        });
        let Some(first_tag) = first_tag else {
            panic!("the first body was not offered");
        };
        if !out
            .iter()
            .any(|command| matches!(command, Command::RequestBodies { .. }))
        {
            out = drive(&mut sync, &view, Event::Room { seats: 1 });
        }
        let (who2, asked2) = out
            .iter()
            .find_map(|command| match command {
                Command::RequestBodies {
                    session, request, ..
                } => Some((*session, request.hashes.clone())),
                _ => None,
            })
            .expect("the second body is wanted");
        let raw2 = if asked2[0] == *second_hash.as_bytes() {
            second_bytes
        } else {
            first_bytes
        };
        out = drive(
            &mut sync,
            &view,
            Event::Bodies {
                session: who2,
                bytes: shekyl_levin::ResponseBodies {
                    bodies: vec![BlockBody {
                        block: raw2,
                        txs: Vec::new(),
                        attestation_witness: Vec::new(),
                    }],
                    deferred: Vec::new(),
                    missed_ids: Vec::new(),
                }
                .store()
                .unwrap(),
            },
        );
        let second_tag = out.iter().find_map(|command| match command {
            Command::Offer { arrivals } => Some((arrivals[0].tag, arrivals[0].header.hash())),
            _ => None,
        });
        let Some((second_tag, refused_hash)) = second_tag else {
            panic!("the second body was not offered: {out:?}");
        };
        assert_ne!(first_tag, second_tag);
        let unknown = drive(
            &mut sync,
            &view,
            Event::Entry {
                tag: 0,
                outcome: Outcome::Refused {
                    verdict: InvalidBlock::new(
                        shekyl_chain_rules::CenRow::G2,
                        shekyl_chain_rules::Locus::Block,
                    ),
                },
            },
        );
        assert!(
            unknown
                .iter()
                .all(|command| !matches!(command, Command::Close { .. })),
            "an unknown tag closed a session: {unknown:?}"
        );
        let refused = drive(
            &mut sync,
            &view,
            Event::Entry {
                tag: second_tag,
                outcome: Outcome::Refused {
                    verdict: InvalidBlock::new(
                        shekyl_chain_rules::CenRow::G2,
                        shekyl_chain_rules::Locus::Block,
                    ),
                },
            },
        );
        let closed: Vec<u8> = refused
            .iter()
            .filter_map(|command| match command {
                Command::Close { session, .. } => Some(*session),
                _ => None,
            })
            .collect();
        assert_eq!(closed, vec![who2]);
        assert!(sync.remembers_header(refused_hash));
        let other = if refused_hash == first_hash {
            second_hash
        } else {
            first_hash
        };
        assert!(!sync.remembers_header(other));
        assert!(sync.transit(if who2 == 1 { 2 } else { 1 }).is_some());
    });
}
