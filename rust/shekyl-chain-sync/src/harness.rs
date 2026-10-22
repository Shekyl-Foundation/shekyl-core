// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The CS-2 harness (brief §5). Scripted peers over synthetic forks,
//! an in-process executor (`ProductionSubstrate`), and a fake entry.
//! Each test names the property it pins. The captured-chain agreement
//! between the two `form` entries lives in `shekyl-chain-ingest`.

use std::time::{Duration, Instant};

use shekyl_chain_rules::harness::fixture::{candidate_on, chain_of};
use shekyl_chain_rules::{
    AtHeight, FakechainSchedule, HeaderRecord, HeaderView, RuleSet, SettlementEpochBlocks, Tip,
    Trust,
};
use shekyl_difficulty::{CumulativeDifficulty, MTP_WINDOW_USIZE, N_USIZE};
use shekyl_draw_rng::{RelayRng, SplitMix64};
use shekyl_levin::{PortableMap, ResponseBodies, ResponseHeaders};
use shekyl_types::{BlockCount, BlockHash, BlockHeight, ChainCount};
use shekyl_wire::{Block, BlockBody, PowBlob, TxBody};

use crate::model::{CloseCause, Event, HashClass, Job, Proved, Sync};
use crate::{Command, PeerClaim};

fn cap(blocks: u64) -> RuleSet {
    let epoch = SettlementEpochBlocks::new(512).expect("512");
    let schedule =
        FakechainSchedule::new(epoch, BlockCount::from_raw(blocks)).expect("cap inside the epoch");
    // Target 1: every RandomX output satisfies, so a nonce of 0 is a proof.
    RuleSet::fakechain(core::num::NonZeroU128::new(1), schedule)
}

struct NoDraw;

impl RelayRng for NoDraw {
    fn next_u64(&mut self) -> u64 {
        0
    }
}

struct Words(Vec<u64>);

impl RelayRng for Words {
    fn next_u64(&mut self) -> u64 {
        self.0.remove(0)
    }
}

/// Main chain through `fork`, then the run's headers above it.
/// The chain's headers, with work `height + 1`. A fixed target of 1 adds
/// 1 per block, so a fork can outweigh a short main chain. The planted
/// mock work cannot: it is the DAA constant times the height.
pub(crate) struct UnitWork<H>(pub(crate) H);

impl<'id, H: HeaderView<'id>> HeaderView<'id> for UnitWork<H> {
    type Fault = H::Fault;

    fn tip(&self) -> Result<Option<Tip>, Self::Fault> {
        self.0.tip()
    }

    fn header_at(&self, height: BlockHeight) -> Result<AtHeight<HeaderRecord>, Self::Fault> {
        Ok(match self.0.header_at(height)? {
            AtHeight::Recorded(mut record) => {
                record.cumulative_difficulty =
                    CumulativeDifficulty::from_raw(u128::from(height.to_raw()) + 1);
                AtHeight::Recorded(record)
            }
            other => other,
        })
    }
}

struct Along<'a> {
    prefix: &'a [HeaderRecord],
    extra: &'a [HeaderRecord],
    fork: u64,
}

impl HeaderView<'static> for Along<'_> {
    type Fault = core::convert::Infallible;

    fn tip(&self) -> Result<Option<Tip>, Self::Fault> {
        if let Some(last) = self.extra.last() {
            return Ok(Some(Tip {
                height: BlockHeight::from_raw(self.fork + u64::try_from(self.extra.len()).unwrap()),
                hash: last.hash,
            }));
        }
        self.prefix.last().map_or(Ok(None), |record| {
            Ok(Some(Tip {
                height: BlockHeight::from_raw(self.fork),
                hash: record.hash,
            }))
        })
    }

    fn header_at(&self, height: BlockHeight) -> Result<AtHeight<HeaderRecord>, Self::Fault> {
        let h = height.to_raw();
        if h <= self.fork {
            return Ok(self
                .prefix
                .get(usize::try_from(h).unwrap())
                .cloned()
                .map_or(AtHeight::AboveTip, AtHeight::Recorded));
        }
        let index = usize::try_from(h - self.fork - 1).unwrap();
        Ok(self
            .extra
            .get(index)
            .cloned()
            .map_or(AtHeight::AboveTip, AtHeight::Recorded))
    }
}

fn formed_on<'id, H>(
    view: &H,
    rules: &RuleSet,
    block: &mut Block,
    parent: BlockHash,
    timestamp: u64,
) where
    H: HeaderView<'id>,
    H::Fault: std::fmt::Debug,
{
    block.header.previous = parent;
    block.header.timestamp = timestamp;
    let tip = view.tip().expect("the view answers").expect("a tip");
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
    // The proof is the executor's one real hash, not a second one here.
    let _ = (rules, seed, target, parent);
}

fn open_and_claim<'id, R, H>(sync: &mut Sync<u8, R>, main: &H, session: u8, work: u128)
where
    R: Fn(BlockHeight) -> RuleSet,
    H: HeaderView<'id>,
    H::Fault: std::fmt::Debug,
{
    let mut out = Vec::new();
    sync.handle(
        Event::SessionOpened {
            session,
            transit: Duration::from_secs(1),
        },
        main,
        Instant::now(),
        &mut NoDraw,
        &mut out,
    )
    .expect("main answers");
    sync.claim(
        session,
        PeerClaim {
            count: ChainCount::from_raw(2),
            work: CumulativeDifficulty::from_raw(work),
        },
        main,
        Instant::now(),
        &mut NoDraw,
        &mut out,
    )
    .expect("the claim is a chain");
}

/// Feed one header response and run every `Prove` it produced.
fn answer<'id, R, H>(
    sync: &mut Sync<u8, R>,
    main: &H,
    session: u8,
    pow: Vec<u8>,
    tip_work: u128,
    more: bool,
) -> Vec<Command<u8>>
where
    R: Fn(BlockHeight) -> RuleSet,
    H: HeaderView<'id>,
    H::Fault: std::fmt::Debug,
{
    let bytes = ResponseHeaders {
        blobs: vec![pow],
        tip_work,
        more,
    }
    .store()
    .expect("the response encodes");
    let mut out = Vec::new();
    sync.handle(
        Event::Headers { session, bytes },
        main,
        Instant::now(),
        &mut NoDraw,
        &mut out,
    )
    .expect("main answers");
    resolve_proves(sync, main, &mut out);
    out
}

fn resolve_proves<'id, R, H>(sync: &mut Sync<u8, R>, main: &H, out: &mut Vec<Command<u8>>)
where
    R: Fn(BlockHeight) -> RuleSet,
    H: HeaderView<'id>,
    H::Fault: std::fmt::Debug,
{
    for _ in 0..8 {
        let Some((job, items, class)) = out.iter().find_map(|command| match command {
            Command::Prove {
                job, items, class, ..
            } => Some((*job, items.clone(), *class)),
            _ => None,
        }) else {
            return;
        };
        let _ = class;
        let mut results = Vec::new();
        for item in items {
            match crate::proof::prove_item(&item) {
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
        .expect("main answers");
        out.append(&mut next);
    }
}

fn closes(out: &[Command<u8>]) -> Vec<&CloseCause> {
    out.iter()
        .filter_map(|command| match command {
            Command::Close { cause, .. } => Some(cause),
            _ => None,
        })
        .collect()
}

fn proves(out: &[Command<u8>]) -> Vec<HashClass> {
    out.iter()
        .filter_map(|command| match command {
            Command::Prove { class, .. } => Some(*class),
            _ => None,
        })
        .collect()
}

/// An honest run longer than one response is accepted, and `H*` becomes it.
#[test]
fn an_honest_chain_longer_than_one_response_is_never_refused() {
    let rules = cap(64);
    let main = chain_of(21);
    let mut block = candidate_on(&main, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    main.with_view(|view| {
        let tip = view.tip().expect("main answers").expect("a tip");
        let mut out = Vec::new();
        sync.handle(
            Event::Tip { tip },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        open_and_claim(&mut sync, &view, 1, u128::MAX);
        let mut parent = tip.hash;
        let mut timestamp = match view.header_at(tip.height).unwrap() {
            AtHeight::Recorded(record) => record.header.timestamp,
            AtHeight::AboveTip => panic!("the tip is on main"),
        };
        let mut last = parent;
        for step in 0..3 {
            timestamp += 120;
            let branch = sync.branch_of(&view, parent).expect("the parent is known");
            formed_on(&branch, &rules, &mut block, parent, timestamp);
            last = PowBlob::read(&block.pow_blob())
                .expect("preimage")
                .identity();
            let out = answer(&mut sync, &view, 1, block.pow_blob(), u128::MAX, step < 2);
            assert!(closes(&out).is_empty(), "an honest header closed: {out:?}");
            parent = last;
        }
        assert_eq!(sync.selected().hash, last);
        assert!(sync.header_count() >= 3);
    });
}

/// A lighter fork is not hashed.
#[test]
fn a_run_that_does_not_beat_the_selected_chain_is_not_hashed() {
    let rules = cap(64);
    let main = chain_of(21);
    let fork = chain_of(11);
    let mut block = candidate_on(&fork, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    main.with_view(|view| {
        let tip = view.tip().unwrap().unwrap();
        let mut out = Vec::new();
        sync.handle(
            Event::Tip { tip },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        open_and_claim(&mut sync, &view, 1, u128::MAX);
        let parent = fork.with_view(|fork_view| fork_view.tip().unwrap().unwrap().hash);
        let timestamp = fork.with_view(|fork_view| {
            match fork_view.header_at(BlockHeight::from_raw(10)).unwrap() {
                AtHeight::Recorded(record) => record.header.timestamp,
                AtHeight::AboveTip => panic!("the fork tip"),
            }
        });
        fork.with_view(|fork_view| {
            formed_on(&fork_view, &rules, &mut block, parent, timestamp + 120)
        });
        let out = answer(&mut sync, &view, 1, block.pow_blob(), 1, false);
        assert!(proves(&out).is_empty(), "a lighter run was hashed: {out:?}");
        assert_eq!(sync.selected().hash, tip.hash);
    });
}

/// `H*` stays the heavier of the local tip and the verified branches.
#[test]
fn the_selected_chain_is_the_most_verified_work() {
    let rules = cap(64);
    let main = chain_of(21);
    let mut block = candidate_on(&main, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    main.with_view(|view| {
        let tip = view.tip().unwrap().unwrap();
        let mut out = Vec::new();
        sync.handle(
            Event::Tip { tip },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        let before = sync.selected().work;
        open_and_claim(&mut sync, &view, 1, u128::MAX);
        let timestamp = match view.header_at(tip.height).unwrap() {
            AtHeight::Recorded(record) => record.header.timestamp,
            AtHeight::AboveTip => panic!("the tip"),
        };
        let branch = sync.branch_of(&view, tip.hash).unwrap();
        formed_on(&branch, &rules, &mut block, tip.hash, timestamp + 120);
        let _ = answer(&mut sync, &view, 1, block.pow_blob(), u128::MAX, false);
        assert!(sync.selected().work > before);
    });
}

/// A claim's value is not an input to the state.
#[test]
fn a_claim_never_changes_the_derived_state() {
    proptest::proptest!(|(work in 2u128..10_000, count in 1u64..100)| {
        let mut sync = Sync::new(Trust::UNANCHORED, |_: BlockHeight| RuleSet::GENESIS);
        let main = chain_of(4);
        main.with_view(|view| {
            let tip = view.tip().unwrap().unwrap();
            let mut out = Vec::new();
            sync.handle(Event::Tip { tip }, &view, Instant::now(), &mut NoDraw, &mut out).unwrap();
            let before = sync.state();
            sync.claim(
                1,
                PeerClaim {
                    count: ChainCount::from_raw(count),
                    work: CumulativeDifficulty::from_raw(work.max(u128::from(count))),
                },
                &view,
                Instant::now(),
                &mut NoDraw,
                &mut out,
            )
            .unwrap();
            assert_eq!(sync.state(), before);
        });
    });
}

/// The latch is not a sync state. `Synced` still holds while it is set.
#[test]
fn the_latch_does_not_withhold_synced() {
    let mut sync = Sync::new(Trust::UNANCHORED, |_: BlockHeight| RuleSet::GENESIS);
    let main = chain_of(4);
    main.with_view(|view| {
        let tip = view.tip().unwrap().unwrap();
        let mut out = Vec::new();
        sync.handle(
            Event::SessionOpened {
                session: 1,
                transit: Duration::from_secs(1),
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        sync.handle(
            Event::Tip { tip },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        assert_eq!(sync.state(), crate::SyncState::Synced);
        sync.handle(
            Event::Latch { set: true },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        assert!(sync.alarm());
        assert_eq!(sync.state(), crate::SyncState::Synced);
    });
}

/// A missed deadline ends the request and does not close the session.
#[test]
fn a_missed_deadline_ends_the_request_and_does_not_close() {
    let mut sync = Sync::new(Trust::UNANCHORED, |_: BlockHeight| RuleSet::GENESIS);
    let main = chain_of(4);
    main.with_view(|view| {
        let tip = view.tip().unwrap().unwrap();
        let mut out = Vec::new();
        sync.handle(
            Event::Tip { tip },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        open_and_claim(&mut sync, &view, 1, u128::MAX);
        out.clear();
        sync.handle(
            Event::SessionOpened {
                session: 2,
                transit: Duration::from_secs(1),
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        // The request was drawn for session 1. Its deadline is not a close.
        sync.handle(
            Event::Deadline {
                session: 1,
                request: 1,
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        assert!(closes(&out).is_empty(), "{out:?}");
        assert!(sync.transit(1).is_some());
    });
}

/// `PayloadRefused` is the structurally impossible claims, and no others.
#[test]
fn payload_refused_is_only_an_impossible_claim() {
    proptest::proptest!(|(count in 1u64..50, extra in 0u128..100)| {
        let mut sync = Sync::new(Trust::UNANCHORED, |_: BlockHeight| RuleSet::GENESIS);
        let main = chain_of(2);
        main.with_view(|view| {
            let mut out = Vec::new();
            sync.handle(
                Event::SessionOpened { session: 1, transit: Duration::from_secs(1) },
                &view,
                Instant::now(),
                &mut NoDraw,
                &mut out,
            )
            .unwrap();
            let work = u128::from(count) + extra;
            sync.claim(
                1,
                PeerClaim { count: ChainCount::from_raw(count), work: CumulativeDifficulty::from_raw(work) },
                &view,
                Instant::now(),
                &mut NoDraw,
                &mut out,
            )
            .expect("a chain is not refused");
            let zero = sync.claim(
                1,
                PeerClaim { count: ChainCount::ZERO, work: CumulativeDifficulty::from_raw(work) },
                &view,
                Instant::now(),
                &mut NoDraw,
                &mut out,
            );
            assert!(matches!(zero, Err(crate::ClaimError::Refused(_))));
            let short = sync.claim(
                1,
                PeerClaim {
                    count: ChainCount::from_raw(count),
                    work: CumulativeDifficulty::from_raw(u128::from(count) - 1),
                },
                &view,
                Instant::now(),
                &mut NoDraw,
                &mut out,
            );
            assert!(matches!(short, Err(crate::ClaimError::Refused(_))));
        });
    });
}

/// A proof refusal closes the supplier. A `Stale` and an unmatched job do not.
#[test]
fn a_proof_refusal_closes_and_a_stale_does_not() {
    let rules = cap(64);
    let main = chain_of(21);
    let mut block = candidate_on(&main, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    main.with_view(|view| {
        let tip = view.tip().unwrap().unwrap();
        let mut out = Vec::new();
        sync.handle(
            Event::Tip { tip },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        open_and_claim(&mut sync, &view, 1, u128::MAX);
        let timestamp = match view.header_at(tip.height).unwrap() {
            AtHeight::Recorded(record) => record.header.timestamp,
            AtHeight::AboveTip => panic!("the tip"),
        };
        let branch = sync.branch_of(&view, tip.hash).unwrap();
        formed_on(&branch, &rules, &mut block, tip.hash, timestamp + 120);
        let bytes = ResponseHeaders {
            blobs: vec![block.pow_blob()],
            tip_work: u128::MAX,
            more: false,
        }
        .store()
        .unwrap();
        out.clear();
        sync.handle(
            Event::Headers { session: 1, bytes },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        let (job, item) = out
            .iter()
            .find_map(|command| match command {
                Command::Prove { job, items, .. } => items.first().map(|item| (*job, item.clone())),
                _ => None,
            })
            .expect("the heavier header is proved");
        // The seed the view would not claim. `judge_header` reports Stale.
        let mut item = item;
        item.seed = BlockHash::from_bytes([9; 32]);
        let formed = crate::proof::prove_item(&item).expect("target 1 accepts the altered seed");
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
            closes(&out).is_empty(),
            "a stale result closed the session: {out:?}"
        );
        assert!(sync.transit(1).is_some());
        out.clear();
        sync.handle(
            Event::Proven {
                job: Job::from_raw(999),
                results: vec![Proved::Refused(shekyl_chain_rules::InvalidBlock::new(
                    shekyl_chain_rules::CenRow::B6,
                    shekyl_chain_rules::Locus::Block,
                ))],
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        assert!(closes(&out).is_empty(), "an unmatched job closed a session");
    });
}

/// Bodies are requested only for headers on `H*`.
#[test]
fn no_body_is_requested_off_the_selected_chain() {
    let rules = cap(64);
    let main = chain_of(21);
    let mut block = candidate_on(&main, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    main.with_view(|view| {
        let tip = view.tip().unwrap().unwrap();
        let mut out = Vec::new();
        sync.handle(
            Event::Tip { tip },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        open_and_claim(&mut sync, &view, 1, u128::MAX);
        let timestamp = match view.header_at(tip.height).unwrap() {
            AtHeight::Recorded(record) => record.header.timestamp,
            AtHeight::AboveTip => panic!("the tip"),
        };
        let branch = sync.branch_of(&view, tip.hash).unwrap();
        formed_on(&branch, &rules, &mut block, tip.hash, timestamp + 120);
        let hash = Block::from_bytes(&{
            let mut bytes = Vec::new();
            block.write(&mut bytes).unwrap();
            bytes
        })
        .unwrap()
        .hash();
        let _ = answer(&mut sync, &view, 1, block.pow_blob(), u128::MAX, false);
        assert_eq!(sync.selected().hash, hash);
        out.clear();
        sync.handle(
            Event::Room { seats: 4 },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        for command in &out {
            if let Command::RequestBodies { request, .. } = command {
                assert!(
                    request
                        .hashes
                        .iter()
                        .all(|raw| BlockHash::from_bytes(*raw) == hash),
                    "a body request left H*"
                );
            }
        }
    });
}

/// While the latch is set, a past-cap offer plans no evidence hash.
#[test]
fn the_latch_plans_no_evidence_hash() {
    let rules = cap(1);
    let main = chain_of(8);
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    main.with_view(|view| {
        let tip = view.tip().unwrap().unwrap();
        let mut out = Vec::new();
        sync.handle(
            Event::Tip { tip },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        sync.handle(
            Event::Latch { set: true },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        open_and_claim(&mut sync, &view, 1, u128::MAX);
        let prefix = prefix_of(&main, 0);
        let along = Along {
            prefix: &prefix,
            extra: &[],
            fork: 0,
        };
        let mut block = candidate_on(&main, Vec::new()).block;
        let parent = prefix[0].hash;
        let timestamp = prefix[0].header.timestamp;
        formed_on(&along, &rules, &mut block, parent, timestamp + 120);
        let out = answer(&mut sync, &view, 1, block.pow_blob(), u128::MAX, true);
        assert!(!proves(&out).contains(&HashClass::Evidence));
        assert!(sync.evidence_session().is_none());
    });
}

fn prefix_of(main: &shekyl_chain_rules::harness::MockChain, fork: u64) -> Vec<HeaderRecord> {
    main.with_view(|view| {
        (0..=fork)
            .map(
                |h| match view.header_at(BlockHeight::from_raw(h)).unwrap() {
                    AtHeight::Recorded(record) => record,
                    AtHeight::AboveTip => panic!("height {h} is on main"),
                },
            )
            .collect()
    })
}

/// A past-cap run keeps the branch-view window, not every header it saw.
#[test]
fn a_past_cap_run_holds_only_its_window() {
    let rules = cap(1);
    let main = chain_of(400);
    let window = N_USIZE.max(MTP_WINDOW_USIZE).saturating_add(8);
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    main.with_view(|raw| {
        let view = UnitWork(raw);
        let tip = view.tip().unwrap().unwrap();
        let mut out = Vec::new();
        sync.handle(
            Event::Tip { tip },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        open_and_claim(&mut sync, &view, 1, u128::MAX);
        let prefix = prefix_of(&main, 0);
        let mut block = candidate_on(&main, Vec::new()).block;
        let mut parent = prefix[0].hash;
        let mut timestamp = prefix[0].header.timestamp;
        let steps = u64::try_from(window).unwrap() + 20;
        let mut peak = 0usize;
        for step in 0..steps {
            let extra = sync.run_records(1);
            let along = Along {
                prefix: &prefix,
                extra: &extra,
                fork: 0,
            };
            timestamp += 120;
            formed_on(&along, &rules, &mut block, parent, timestamp);
            parent = PowBlob::read(&block.pow_blob())
                .expect("preimage")
                .identity();
            let _ = answer(
                &mut sync,
                &view,
                1,
                block.pow_blob(),
                u128::MAX,
                step + 1 < steps,
            );
            peak = peak.max(sync.run_len(1));
        }
        let sent = usize::try_from(steps).unwrap();
        assert!(
            peak <= window,
            "the run held {peak} headers; the window is {window}"
        );
        assert!(
            peak + 8 < sent,
            "the run kept every header it was sent ({peak} of {sent})"
        );
    });
}

/// The evidence draw over two waiting candidates is uniform.
#[test]
fn the_evidence_draw_is_uniform_over_the_waiting_candidates() {
    let rules = cap(1);
    let main = chain_of(4);
    let prefix = prefix_of(&main, 0);
    let mut block = candidate_on(&main, Vec::new()).block;
    let mut blobs = Vec::new();
    let mut parent = prefix[0].hash;
    let mut timestamp = prefix[0].header.timestamp;
    let mut scratch = Sync::new(Trust::UNANCHORED, move |_| rules);
    main.with_view(|raw| {
        let view = UnitWork(raw);
        let tip = view.tip().unwrap().unwrap();
        let mut out = Vec::new();
        scratch
            .handle(
                Event::Tip { tip },
                &view,
                Instant::now(),
                &mut NoDraw,
                &mut out,
            )
            .unwrap();
        open_and_claim(&mut scratch, &view, 1, u128::MAX);
        for step in 0..4 {
            let extra = scratch.run_records(1);
            let along = Along {
                prefix: &prefix,
                extra: &extra,
                fork: 0,
            };
            timestamp += 120;
            formed_on(&along, &rules, &mut block, parent, timestamp);
            let pow = block.pow_blob();
            parent = PowBlob::read(&pow).expect("preimage").identity();
            blobs.push(pow.clone());
            let out = answer(&mut scratch, &view, 1, pow, u128::MAX, step < 3);
            assert!(
                closes(&out).is_empty(),
                "header {} closed: {out:?}",
                blobs.len()
            );
        }
        assert!(scratch.run_len(1) > 0, "the candidate run did not form");
    });
    let mut hits = [0u32; 2];
    let trials = 80u64;
    for seed in 0..trials {
        let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
        let mut rng = SplitMix64::new(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        main.with_view(|raw| {
            let view = UnitWork(raw);
            let tip = view.tip().unwrap().unwrap();
            let mut out = Vec::new();
            sync.handle(
                Event::Tip { tip },
                &view,
                Instant::now(),
                &mut rng,
                &mut out,
            )
            .unwrap();
            for session in [1u8, 2] {
                sync.handle(
                    Event::SessionOpened {
                        session,
                        transit: Duration::from_secs(1),
                    },
                    &view,
                    Instant::now(),
                    &mut rng,
                    &mut out,
                )
                .unwrap();
            }
            sync.claim(
                1,
                PeerClaim {
                    count: ChainCount::from_raw(2),
                    work: CumulativeDifficulty::from_raw(u128::MAX),
                },
                &view,
                Instant::now(),
                &mut rng,
                &mut out,
            )
            .unwrap();
            for (index, pow) in blobs.iter().enumerate() {
                let bytes = ResponseHeaders {
                    blobs: vec![pow.clone()],
                    tip_work: u128::MAX,
                    more: index + 1 < blobs.len(),
                }
                .store()
                .unwrap();
                sync.handle(
                    Event::Headers { session: 1, bytes },
                    &view,
                    Instant::now(),
                    &mut rng,
                    &mut out,
                )
                .unwrap();
            }
            // The first run has ended, so the next request is session 2's.
            // `claim` does not draw; the room event draws over both runs.
            out.clear();
            sync.claim(
                2,
                PeerClaim {
                    count: ChainCount::from_raw(2),
                    work: CumulativeDifficulty::from_raw(u128::MAX),
                },
                &view,
                Instant::now(),
                &mut rng,
                &mut out,
            )
            .unwrap();
            let asked = out.iter().find_map(|command| match command {
                Command::RequestHeaders { session, .. } => Some(*session),
                _ => None,
            });
            assert_eq!(asked, Some(2), "the second request went to {asked:?}");
            for (index, pow) in blobs.iter().enumerate() {
                let bytes = ResponseHeaders {
                    blobs: vec![pow.clone()],
                    tip_work: u128::MAX,
                    more: index + 1 < blobs.len(),
                }
                .store()
                .unwrap();
                sync.handle(
                    Event::Headers { session: 2, bytes },
                    &view,
                    Instant::now(),
                    &mut rng,
                    &mut out,
                )
                .unwrap();
            }
            assert!(
                sync.run_len(1) > 0 && sync.run_len(2) > 0,
                "candidates {} {}",
                sync.run_len(1),
                sync.run_len(2)
            );
            out.clear();
            sync.handle(
                Event::Room { seats: 0 },
                &view,
                Instant::now(),
                &mut rng,
                &mut out,
            )
            .unwrap();
            let drawn = out.iter().find_map(|command| match command {
                Command::Prove {
                    class: HashClass::Evidence,
                    ..
                } => sync.evidence_session(),
                _ => None,
            });
            match drawn {
                Some(1) => hits[0] += 1,
                Some(2) => hits[1] += 1,
                other => panic!("the draw picked {other:?}"),
            }
        });
    }
    let expected = f64::from(u32::try_from(trials).unwrap()) / 2.0;
    let chi: f64 = hits
        .iter()
        .map(|hit| {
            let d = f64::from(*hit) - expected;
            d * d / expected
        })
        .sum();
    assert!(
        chi < 10.83,
        "chi-squared {chi} over {hits:?} is not a uniform draw"
    );
}

/// An unavailable block does not close. A body that fails the binding
/// closes the supplier and leaves the header in `T`.
#[test]
fn a_bind_failure_closes_and_an_unavailable_block_does_not() {
    let rules = cap(64);
    let main = chain_of(21);
    let mut block = candidate_on(&main, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    main.with_view(|view| {
        let tip = view.tip().unwrap().unwrap();
        let mut out = Vec::new();
        sync.handle(
            Event::Tip { tip },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        open_and_claim(&mut sync, &view, 1, u128::MAX);
        let timestamp = match view.header_at(tip.height).unwrap() {
            AtHeight::Recorded(record) => record.header.timestamp,
            AtHeight::AboveTip => panic!("the tip"),
        };
        let branch = sync.branch_of(&view, tip.hash).unwrap();
        formed_on(&branch, &rules, &mut block, tip.hash, timestamp + 120);
        let raw = {
            let mut bytes = Vec::new();
            block.write(&mut bytes).unwrap();
            bytes
        };
        let hash = Block::from_bytes(&raw).unwrap().hash();
        let _ = answer(&mut sync, &view, 1, block.pow_blob(), u128::MAX, false);
        let before = sync.header_count();
        out.clear();
        sync.handle(
            Event::Room { seats: 4 },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        let request = out
            .iter()
            .find_map(|command| match command {
                Command::RequestBodies { request, .. } => Some(request.hashes.clone()),
                _ => None,
            })
            .expect("a body is wanted along H*");
        let missed = ResponseBodies {
            bodies: Vec::new(),
            deferred: Vec::new(),
            missed_ids: request.clone(),
        }
        .store()
        .unwrap();
        out.clear();
        sync.handle(
            Event::Bodies {
                session: 1,
                bytes: missed,
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        assert!(
            closes(&out).is_empty(),
            "an unavailable block closed the session: {out:?}"
        );
        assert_eq!(sync.header_count(), before);
        // The block is wanted again, from the same session once no other
        // session covers it. A body whose transactions are not the header's
        // closes that session and leaves the header in `T`.
        assert!(
            out.iter()
                .any(|command| matches!(command, Command::RequestBodies { .. })),
            "the unavailable block was not wanted again: {out:?}"
        );
        let body = BlockBody {
            block: raw,
            txs: vec![TxBody::Full(vec![1, 2, 3])],
            attestation_witness: Vec::new(),
        };
        let bad = ResponseBodies {
            bodies: vec![body],
            deferred: Vec::new(),
            missed_ids: Vec::new(),
        }
        .store()
        .unwrap();
        out.clear();
        sync.handle(
            Event::Bodies {
                session: 1,
                bytes: bad,
            },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        assert!(
            closes(&out)
                .iter()
                .any(|cause| matches!(cause, CloseCause::Bind(_))),
            "a mismatched body did not close: {out:?}"
        );
        assert!(sync.contains_header(hash));
        assert_eq!(sync.header_count(), before);
    });
}

/// Two honest sessions extend one frontier with one header request.
#[test]
fn one_header_request_extends_the_frontier() {
    let mut sync = Sync::new(Trust::UNANCHORED, |_: BlockHeight| RuleSet::GENESIS);
    let main = chain_of(4);
    main.with_view(|view| {
        let tip = view.tip().unwrap().unwrap();
        let mut out = Vec::new();
        sync.handle(
            Event::Tip { tip },
            &view,
            Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .unwrap();
        open_and_claim(&mut sync, &view, 1, u128::MAX);
        open_and_claim(&mut sync, &view, 2, u128::MAX);
        out.clear();
        sync.handle(
            Event::Deadline {
                session: 9,
                request: 0,
            },
            &view,
            Instant::now(),
            &mut Words(vec![0]),
            &mut out,
        )
        .unwrap();
        let requests = out
            .iter()
            .filter(|command| matches!(command, Command::RequestHeaders { .. }))
            .count();
        assert!(
            requests <= 1,
            "two header requests extended one frontier: {out:?}"
        );
    });
}
