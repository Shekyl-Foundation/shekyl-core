// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A block whose section names a bundle body it was not sent waits for it
//! (`runs::awaiting`): it is not offered, the owner is asked, and the
//! answer decides. The block is announced by session 1 on main's tip; its
//! section is one real bundle for the tip, built by the rules crate's
//! fixture, and the body travels only where a test sends it.

use std::time::{Duration, Instant};

use shekyl_archival_retention::{bundle_root, BundleBody, BundleRef};
use shekyl_chain_rules::harness::bundle::BundleWorld;
use shekyl_chain_rules::harness::fixture::{candidate_on, chain_of};
use shekyl_chain_rules::harness::MockSubstrate;
use shekyl_chain_rules::{form_header, AtHeight, HeaderRecord, HeaderView, Trust};
use shekyl_draw_rng::RelayRng;
use shekyl_types::{BlockHash, BlockHeight, BundleRoot, ChainCount, Timestamp};
use shekyl_wire::{Block, BlockBody, PowBlob};

use super::{AWAITING_AGE, AWAITING_PER_SESSION, AWAITING_TOTAL};
use crate::model::{Event, HashClass, Proved, Sync};
use crate::proof::{fixed, serialized};
use crate::protocol::CloseCause;
use crate::scenarios::Prefix;
use crate::{Command, PeerClaim};

struct NoDraw;

impl RelayRng for NoDraw {
    fn next_u64(&mut self) -> u64 {
        0
    }
}

/// Main of eight blocks, one session open with a claim to it, room to
/// offer, and the blocks a test announces on main's tip: each carries a
/// section of one bundle for the tip, and the bundle's body.
struct World {
    sync: Sync<u8, Box<dyn Fn(BlockHeight) -> shekyl_chain_rules::RuleSet>>,
    records: Vec<HeaderRecord>,
    substrate: MockSubstrate,
    start: Instant,
}

/// One announced block: its body as sent (references, no bundle body), its
/// hash, and the body its section names.
struct Announced {
    body: BlockBody,
    hash: BlockHash,
    bundle: BundleBody,
}

impl World {
    fn new() -> Self {
        let rules = fixed(1, 64);
        let fixture = chain_of(8);
        let records: Vec<HeaderRecord> = fixture.with_view(|view| {
            (0..8)
                .map(
                    |height| match view.header_at(BlockHeight::from_raw(height)) {
                        Ok(AtHeight::Recorded(record)) => record,
                        _ => panic!("main has height {height}"),
                    },
                )
                .collect()
        });
        let schedule: Box<dyn Fn(BlockHeight) -> shekyl_chain_rules::RuleSet> =
            Box::new(move |_| rules);
        let mut sync = Sync::new(Trust::UNPINNED, schedule);
        let wall = Timestamp::from_raw(u64::MAX / 4);
        sync.set_wall(wall);
        let substrate = MockSubstrate {
            clock: wall,
            ..MockSubstrate::default()
        };
        let mut world = Self {
            sync,
            records,
            substrate,
            start: Instant::now(),
        };
        let tip = Prefix(&world.records)
            .tip()
            .expect("answers")
            .expect("a tip");
        world.drive(Event::Tip { tip }, Duration::ZERO);
        let mut out = world.drive(
            Event::SessionOpened {
                session: 1,
                transit: Duration::from_secs(1),
            },
            Duration::ZERO,
        );
        let top = world.records.last().expect("eight").clone();
        world
            .sync
            .claim(
                1,
                PeerClaim {
                    count: ChainCount::from_raw(8),
                    work: top.cumulative_difficulty,
                    top: tip.hash,
                },
                &Prefix(&world.records),
                world.start,
                &mut NoDraw,
                &mut out,
            )
            .expect("the claim is a chain");
        world.drive(Event::Room { seats: 4 }, Duration::ZERO);
        let _ = fixture;
        world
    }

    fn drive(&mut self, event: Event<u8>, after: Duration) -> Vec<Command<u8>> {
        let mut out = Vec::new();
        self.sync
            .handle(
                event,
                &Prefix(&self.records),
                self.start + after,
                &mut NoDraw,
                &mut out,
            )
            .expect("the view answers");
        out
    }

    /// A block on main's tip whose section names one bundle for height 7,
    /// told apart from its siblings by `nonce`.
    fn block_with_section(&self, nonce: u32) -> Announced {
        let fixture = chain_of(8);
        let mut block: Block = candidate_on(&fixture, Vec::new()).block;
        let top = self.records.last().expect("eight");
        block.header.previous = top.hash;
        block.header.timestamp = top.header.timestamp.saturating_add(120);
        block.header.nonce = nonce;
        let world = BundleWorld::with(
            BlockHeight::from_raw(7),
            BundleWorld::SEED,
            0,
            &fixed(1, 64),
        );
        let (reference, bundle): (BundleRef, BundleBody) = world.bundle(&[]);
        let root = bundle_root(std::slice::from_ref(&reference)).expect("one reference");
        block.header.bundle_root = BundleRoot::from_bytes(root);
        let hash = PowBlob::read(&block.pow_blob())
            .expect("preimage")
            .identity();
        Announced {
            body: BlockBody {
                block: serialized(&block),
                txs: Vec::new(),
                bundle_references: vec![reference.encode()],
                bundle_bodies: Vec::new(),
            },
            hash,
            bundle,
        }
    }

    /// Announce `announced` from session 1 and prove it: the commands the
    /// proof's landing emitted.
    fn announce(&mut self, announced: &Announced) -> Vec<Command<u8>> {
        let out = self.drive(
            Event::Announce {
                session: 1,
                body: announced.body.clone(),
            },
            Duration::ZERO,
        );
        let (job, item) = out
            .iter()
            .find_map(|command| match command {
                Command::Prove {
                    job,
                    class: HashClass::Unsolicited,
                    items,
                    ..
                } => items.first().map(|item| (*job, item.clone())),
                _ => None,
            })
            .expect("the announce is proven");
        let pow = PowBlob::read(&item.pow).expect("preimage");
        let formed = form_header(
            &pow,
            &item.rule_set,
            &self.substrate,
            item.seed,
            item.target,
            item.attempt,
        )
        .expect("the mock answers")
        .expect("the header forms");
        self.drive(
            Event::Proven {
                job,
                results: vec![Proved::Formed(Box::new(formed))],
            },
            Duration::ZERO,
        )
    }
}

fn offered(out: &[Command<u8>]) -> Vec<BlockHash> {
    out.iter()
        .flat_map(|command| match command {
            Command::Offer { arrivals } => arrivals
                .iter()
                .map(|arrival| arrival.header.hash())
                .collect(),
            _ => Vec::new(),
        })
        .collect()
}

fn asked(out: &[Command<u8>]) -> Vec<(u8, BlockHash, usize)> {
    out.iter()
        .filter_map(|command| match command {
            Command::RequestBundleBodies {
                session,
                block,
                references,
            } => Some((*session, *block, references.len())),
            _ => None,
        })
        .collect()
}

fn closed(out: &[Command<u8>]) -> Vec<(u8, &CloseCause)> {
    out.iter()
        .filter_map(|command| match command {
            Command::Close { session, cause } => Some((*session, cause)),
            _ => None,
        })
        .collect()
}

/// The wargame (the review's finding 2): a miner announces a block whose
/// section names its own bundle and withholds the body. The block is not
/// offered; the body is asked of the announcer; the announcer answers with
/// nothing and is closed. The block is never offered, so a branch built
/// on it is never adopted, and the honest tip is untouched. Red edit: offer
/// a bound body whatever its section names — the block is offered without
/// its bundle's body.
#[test]
fn an_announcer_that_withholds_its_bundle_body_is_closed_and_its_block_never_offered() {
    let mut world = World::new();
    let block = world.block_with_section(1);
    let out = world.announce(&block);
    assert!(
        offered(&out).is_empty(),
        "a block missing its bundle body is not offered: {out:?}"
    );
    assert_eq!(
        asked(&out),
        vec![(1, block.hash, 1)],
        "the body is asked of the announcer"
    );
    let out = world.drive(
        Event::BundleBodies {
            session: 1,
            block: block.hash,
            bodies: Vec::new(),
        },
        Duration::from_secs(1),
    );
    assert_eq!(
        closed(&out),
        vec![(1, &CloseCause::BundleBodiesWithheld)],
        "the announcer withheld the body it relayed"
    );
    assert!(offered(&out).is_empty(), "the block is never offered");
}

/// The honest case: the body comes back, and the block is offered with it.
#[test]
fn a_block_whose_bundle_body_arrives_is_offered_with_it() {
    let mut world = World::new();
    let block = world.block_with_section(2);
    let out = world.announce(&block);
    assert_eq!(asked(&out).len(), 1);
    let out = world.drive(
        Event::BundleBodies {
            session: 1,
            block: block.hash,
            bodies: vec![block.bundle.as_bytes().to_vec()],
        },
        Duration::from_secs(1),
    );
    assert_eq!(
        offered(&out),
        vec![block.hash],
        "the block is offered: {out:?}"
    );
    let carried = out
        .iter()
        .find_map(|command| match command {
            Command::Offer { arrivals } => Some(arrivals[0].body.bundle_bodies.clone()),
            _ => None,
        })
        .expect("an offer");
    assert_eq!(carried, vec![block.bundle.as_bytes().to_vec()]);
    assert!(closed(&out).is_empty());
}

/// A block whose body never comes is dropped at [`AWAITING_AGE`], not
/// refused: a late answer finds nothing waiting, offers nothing and closes
/// nobody. Red edit: drop the expiry — the late answer offers the block.
#[test]
fn a_block_that_waits_past_the_age_is_dropped_not_refused() {
    let mut world = World::new();
    let block = world.block_with_section(3);
    world.announce(&block);
    let late = AWAITING_AGE + Duration::from_secs(1);
    let out = world.drive(
        Event::BundleBodies {
            session: 1,
            block: block.hash,
            bodies: vec![block.bundle.as_bytes().to_vec()],
        },
        late,
    );
    assert!(offered(&out).is_empty(), "the wait expired: {out:?}");
    assert!(closed(&out).is_empty(), "an expired wait closes nobody");
}

/// One session holds at most [`AWAITING_PER_SESSION`] blocks waiting. The
/// next is held back: not asked for, and no wait is evicted for it, so the
/// asks out to the session never pass the owner's bound (`runs::awaiting`
/// module docs). The oldest wait still completes on its answer. The blocks
/// are siblings on main's tip; the bound is read off the waiting set. Red
/// edit: evict the oldest wait at the bound — the fifth block is asked
/// for, a fifth ask out to a session that has done nothing wrong.
#[test]
fn a_session_at_its_bound_is_not_asked_again_and_no_wait_is_evicted() {
    let mut world = World::new();
    let blocks: Vec<Announced> = (0..=AWAITING_PER_SESSION)
        .map(|n| world.block_with_section(100 + u32::try_from(n).expect("small")))
        .collect();
    let (within, past) = blocks.split_at(AWAITING_PER_SESSION);
    for block in within {
        let out = world.announce(block);
        assert_eq!(asked(&out).len(), 1, "each block's body is asked for");
    }
    let out = world.announce(&past[0]);
    assert!(
        asked(&out).is_empty(),
        "the session is at its bound: {out:?}"
    );
    assert_eq!(world.sync.awaiting.len(), AWAITING_PER_SESSION);
    assert!(
        within
            .iter()
            .all(|block| world.sync.awaiting.contains_key(&block.hash)),
        "no wait was evicted"
    );
    assert!(!world.sync.awaiting.contains_key(&past[0].hash));
    let out = world.drive(
        Event::BundleBodies {
            session: 1,
            block: blocks[0].hash,
            bodies: vec![blocks[0].bundle.as_bytes().to_vec()],
        },
        Duration::from_secs(1),
    );
    assert!(closed(&out).is_empty());
    assert_eq!(world.sync.awaiting.len(), AWAITING_PER_SESSION - 1);
}

/// At [`AWAITING_TOTAL`] over every session, a new block is held back and
/// no other session's wait is evicted: each of those has its ask out.
/// Fifteen waits from sessions 2 to 5 stand in beside session 1's one.
/// Red edit: evict the oldest wait at the total bound — the new block is
/// asked for and another session's wait is gone.
#[test]
fn the_total_bound_holds_back_a_new_block_and_evicts_no_other_wait() {
    let mut world = World::new();
    let first = world.block_with_section(200);
    world.announce(&first);
    let template = world
        .sync
        .awaiting
        .get(&first.hash)
        .expect("the first block waits")
        .arrival
        .clone();
    let since = world.start;
    for n in 1..AWAITING_TOTAL {
        let mut arrival = template.clone();
        arrival.session = 2 + u8::try_from(n % 4).expect("small");
        let key = BlockHash::from_bytes([u8::try_from(n).expect("small"); 32]);
        world
            .sync
            .awaiting
            .insert(key, super::Waiting { arrival, since });
    }
    assert_eq!(world.sync.awaiting.len(), AWAITING_TOTAL);
    let before: Vec<BlockHash> = world.sync.awaiting.keys().copied().collect();
    let next = world.block_with_section(201);
    let out = world.announce(&next);
    assert!(asked(&out).is_empty(), "the set is full: {out:?}");
    let after: Vec<BlockHash> = world.sync.awaiting.keys().copied().collect();
    assert_eq!(after, before, "no wait was evicted");
}

/// A waiting block is not put in a body span while its bundle bodies are
/// asked for: its body is here, and asked for again it would come back
/// without them on every plan (Copilot on #1327). The plan that follows the
/// announce is the one that would ask, and so is every later one. Red edit:
/// leave the waiting set out of the span planner — the announce's own
/// batch asks for the block in a 2014.
#[test]
fn a_waiting_block_is_not_asked_for_again_in_a_body_span() {
    let mut world = World::new();
    let block = world.block_with_section(300);
    let spans = |out: &[Command<u8>]| {
        out.iter()
            .filter(|command| {
                matches!(command, Command::RequestBodies { request, .. }
                    if request.hashes.contains(block.hash.as_bytes()))
            })
            .count()
    };
    let out = world.announce(&block);
    assert_eq!(asked(&out).len(), 1);
    assert_eq!(spans(&out), 0, "the waiting block was asked for: {out:?}");
    let out = world.drive(Event::Room { seats: 4 }, Duration::from_secs(1));
    assert_eq!(spans(&out), 0, "the waiting block was asked for: {out:?}");
    assert!(world.sync.awaiting.contains_key(&block.hash));
}

/// A copy that carries the bundle body, announced while the block waits,
/// is offered at once; the wait's own answer then holds nothing a second
/// time. Red edit: hold the completed wait whatever the entry already has
/// — the late answer leaves a second copy held behind the offered one.
#[test]
fn a_whole_copy_offers_a_waiting_block_and_its_late_answer_offers_nothing() {
    let mut world = World::new();
    let block = world.block_with_section(400);
    world.announce(&block);
    let mut whole = block.body.clone();
    whole.bundle_bodies = vec![block.bundle.as_bytes().to_vec()];
    let out = world.drive(
        Event::Announce {
            session: 1,
            body: whole,
        },
        Duration::from_secs(1),
    );
    assert_eq!(
        offered(&out),
        vec![block.hash],
        "the whole copy is offered: {out:?}"
    );
    let out = world.drive(
        Event::BundleBodies {
            session: 1,
            block: block.hash,
            bodies: vec![block.bundle.as_bytes().to_vec()],
        },
        Duration::from_secs(2),
    );
    assert!(offered(&out).is_empty(), "offered once: {out:?}");
    assert!(
        !world.sync.held.contains(block.hash),
        "the late answer holds no second copy"
    );
    assert!(closed(&out).is_empty());
}
