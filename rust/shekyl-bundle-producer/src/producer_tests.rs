// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The producer's state machine over a real ring and plain chain facts.
//! What the reads return is written here; the read itself is
//! `read_tests`, and the whole path is the ingest crate's gate test.
//!
//! Every test names the edit that turns it red.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;

use rand::rngs::StdRng;
use rand::SeedableRng;
use shekyl_archival_retention::{draw_commit, BUNDLE_SIGNATURE_LEN};
use shekyl_crypto_pq::fn_dsa_hybrid::HybridEd25519FnDsa;

use super::*;

const W: Window = Window {
    response: BlockCount::from_raw(500),
    reorg_cap: BlockCount::from_raw(720),
};

const fn h(n: u64) -> BlockHeight {
    BlockHeight::from_raw(n)
}

fn hash_of(n: u64, fork: u8) -> BlockHash {
    let mut bytes = [fork; 32];
    bytes[..8].copy_from_slice(&n.to_le_bytes());
    BlockHash::from_bytes(bytes)
}

/// A chain in a map: height → the recorded block.
#[derive(Default)]
struct Chain {
    blocks: BTreeMap<BlockHeight, Recorded>,
}

impl Chain {
    /// Connect at `n` another miner's block.
    fn theirs(&mut self, n: u64) {
        self.blocks.insert(
            h(n),
            Recorded {
                hash: hash_of(n, 0xEE),
                commitment: DrawCommitment::from_bytes([0xEE; 32]),
            },
        );
    }

    /// Connect at `n` the block whose template drew `commitment`.
    fn ours(&mut self, n: u64, commitment: DrawCommitment) {
        self.blocks.insert(
            h(n),
            Recorded {
                hash: hash_of(n, 0x0A),
                commitment,
            },
        );
    }

    fn pop(&mut self, n: u64) {
        self.blocks.remove(&h(n));
    }

    fn look(&self) -> impl FnMut(BlockHeight) -> Option<Recorded> + '_ {
        |at| self.blocks.get(&at).copied()
    }
}

/// A producer whose slots no test here fills: the cap is its own test's
/// subject ([`producer_with_slots`]).
fn producer(ring: &Arc<WitnessRing>, seed: u64) -> Producer {
    producer_with_slots(ring, seed, NonZeroUsize::MAX)
}

fn producer_with_slots(ring: &Arc<WitnessRing>, seed: u64, slots: NonZeroUsize) -> Producer {
    Producer::new(
        Arc::clone(ring),
        Box::new(StdRng::seed_from_u64(seed)),
        slots,
    )
}

fn target(draw: u32) -> DrawTarget {
    let n = u8::try_from(draw + 1).expect("small");
    let (key, _) = HybridEd25519FnDsa::keypair_from_seeds(&[n; 32], &[n ^ 0x55; 32]).expect("key");
    DrawTarget {
        draw,
        persona: PCanonicalId::from_bytes([n; 32]),
        shard: ShardId::from_raw(u64::from(draw) * 7),
        receipt_key: key,
        endpoint: [n; 32],
    }
}

fn targets(economy: u32, support: u32) -> Targets {
    Targets {
        economy: (0..economy).map(target).collect(),
        support: (0..support).map(target).collect(),
    }
}

fn record(attempt: u8) -> BundleRecord {
    BundleRecord {
        attempt,
        anchor_height: h(1),
        delivery_digest: [attempt; 32],
        receipt: [0x5C; BUNDLE_SIGNATURE_LEN],
    }
}

/// Mine block 100 from the ring, connect it beside another miner's 101,
/// and learn its draws.
fn mined(seed: u64, economy: u32, support: u32) -> (Arc<WitnessRing>, Producer, Chain) {
    mined_with_slots(seed, economy, support, NonZeroUsize::MAX)
}

/// [`mined`], on a client with `slots` slots.
fn mined_with_slots(
    seed: u64,
    economy: u32,
    support: u32,
    slots: NonZeroUsize,
) -> (Arc<WitnessRing>, Producer, Chain) {
    let ring = Arc::new(WitnessRing::new());
    let mut producer = producer_with_slots(&ring, seed, slots);
    let mut chain = Chain::default();
    // Two templates for 100; the second is the one mined.
    ring.draw(h(100)).expect("draws");
    let commitment = ring.draw(h(100)).expect("draws");
    chain.ours(100, commitment);
    chain.theirs(101);
    let observed = producer.observe(h(101), W, chain.look());
    assert_eq!(observed.learn.len(), 1);
    assert_eq!(observed.learn[0].h, h(100));
    assert_eq!(ring.candidates(), 0, "the rival template for 100 went");
    producer.learned(h(100), W, targets(economy, support));
    (ring, producer, chain)
}

/// Drive the block's reads to their end: every due read gets `answer`.
fn drive(producer: &mut Producer, from: u64, to: u64, answer: impl Fn(&DueRead) -> ReadOutcome) {
    for tip in from..=to {
        for due in producer.due(h(tip)) {
            let outcome = answer(&due);
            producer.read_done(due.key, outcome);
        }
    }
}

/// The whole path over plain values: claim, plan, read, pass, file. The
/// filed bundle's bitmap and records are the passes, and its seed opens
/// the commitment the block carried. Red edit: put the support records
/// before the economy ones — the record order assertion fails.
#[test]
fn a_mined_block_files_its_passes_in_draw_order() {
    let (ring, mut producer, chain) = mined(1, 3, 1);
    let commitment = chain.blocks[&h(100)].commitment;
    drive(&mut producer, 101, 510, |due| {
        if due.key.stream == PassStream::Economy && due.key.draw == 1 {
            ReadOutcome::Answered(Answered::Refused)
        } else {
            ReadOutcome::Pass(Box::new(record(due.key.attempt)))
        }
    });
    // Every first read is due by `h + W₂ − M − 2·spacing` = 510, and each
    // settles on its first read, so the block files before its deadline.
    let (filings, failed) = producer.ready(h(510), W);
    assert!(failed.is_empty());
    assert_eq!(filings.len(), 1);
    let filing = &filings[0];
    assert_eq!(filing.h, h(100));
    assert_eq!((filing.draws, filing.passes), (4, 3));
    assert!(!filing.serving_scheme_absent);
    let kept = filing.reference.kept();
    assert_eq!(kept.passes.count(), 3);
    assert_eq!(kept.passes.iter_set().collect::<Vec<_>>(), [0, 2]);
    assert_eq!(kept.support.count(), 1);
    assert!(kept.support.get(0));
    assert_eq!(filing.body.record_count(), 3);
    assert_eq!(
        DrawCommitment::from_bytes(draw_commit(
            filing.body.witness_public_key(),
            filing.reference.seed()
        )),
        commitment
    );
    assert!(ring.in_flight().is_empty(), "filed: the secrets went");
    assert!(producer.in_flight().is_empty());
}

/// A stall reads again at the plan's next height with the next attempt
/// and a new nonce; a completed exchange ends the draw; there are never
/// more than `K` reads. Red edit: treat a stall as final — the second
/// read never comes.
#[test]
fn a_stall_reads_again_and_an_answer_ends_the_draw() {
    let (_ring, mut producer, _chain) = mined(2, 2, 0);
    let mut reads: BTreeMap<u32, Vec<(u8, BlockHeight, [u8; 32])>> = BTreeMap::new();
    for tip in 101..=570 {
        for due in producer.due(h(tip)) {
            reads
                .entry(due.key.draw)
                .or_default()
                .push((due.key.attempt, h(tip), due.nonce));
            // Draw 0 always stalls; draw 1 stalls once, then is answered.
            let outcome = match (due.key.draw, due.key.attempt) {
                (1, 1) => ReadOutcome::Answered(Answered::Refused),
                _ => ReadOutcome::Stall,
            };
            producer.read_done(due.key, outcome);
        }
    }
    let zero = &reads[&0];
    assert_eq!(
        zero.iter().map(|r| r.0).collect::<Vec<_>>(),
        [0, 1, 2],
        "K reads, then abandoned"
    );
    assert!(zero[1].1 >= zero[0].1 + crate::READ_SPACING);
    assert_ne!(zero[0].2, zero[1].2, "each attempt has its own nonce");
    assert_eq!(reads[&1].iter().map(|r| r.0).collect::<Vec<_>>(), [0, 1]);

    let (filings, _) = producer.ready(h(570), W);
    assert_eq!(filings.len(), 1);
    assert_eq!(filings[0].passes, 0);
}

/// A block whose every read fails files all the same, with an empty
/// bitmap of the full count (§7.1). Red edit: skip a block with no passes
/// — nothing is filed.
#[test]
fn a_block_with_no_passes_files_a_no_pass_bundle() {
    let (_ring, mut producer, _chain) = mined(3, 4, 0);
    drive(&mut producer, 101, 510, |_| {
        ReadOutcome::Answered(Answered::Refused)
    });
    let (filings, _) = producer.ready(h(510), W);
    assert_eq!(filings.len(), 1);
    assert_eq!(filings[0].reference.kept().passes.count(), 4);
    assert_eq!(filings[0].reference.kept().passes.popcount(), 0);
    assert_eq!(filings[0].body.record_count(), 0);
}

/// At the deadline `h + W₂ − M` reads not yet started are abandoned, a read
/// in flight is waited for, and the block files when it ends; the last tip
/// that can still include it files whatever is in flight. Nothing files
/// before the deadline while reads are out. Red edit: file at the deadline
/// regardless — the read started at the deadline is abandoned unread.
#[test]
fn the_deadline_waits_for_a_read_in_flight_and_abandons_the_rest() {
    let (_ring, mut producer, _chain) = mined(4, 2, 0);
    let deadline = W.filing_deadline(h(100));
    assert_eq!(deadline, h(570));
    // Hold draw 0's first read; every other read stalls.
    let mut held = None;
    for tip in 101..=569 {
        for due in producer.due(h(tip)) {
            if due.key.draw == 0 && held.is_none() {
                held = Some(due);
            } else {
                producer.read_done(due.key, ReadOutcome::Stall);
            }
        }
    }
    let held = held.expect("draw 0 was read");
    assert!(
        producer.ready(h(569), W).0.is_empty(),
        "before the deadline"
    );
    assert!(
        producer.ready(deadline, W).0.is_empty(),
        "a read in flight is waited for"
    );
    producer.read_done(
        held.key,
        ReadOutcome::Pass(Box::new(record(held.key.attempt))),
    );
    let (filings, _) = producer.ready(deadline, W);
    assert_eq!(filings.len(), 1);
    assert_eq!(filings[0].passes, 1, "the waited read's pass is filed");
    assert!(producer.in_flight().is_empty());

    // A read that never ends files at the last tip that can include it.
    let (_ring, mut producer, _chain) = mined(14, 1, 0);
    let out: Vec<_> = (101..=570).flat_map(|tip| producer.due(h(tip))).collect();
    assert_eq!(out.len(), 1);
    assert!(producer
        .ready(W.last_chance(h(100)) - BlockCount::ONE, W)
        .0
        .is_empty());
    let (filings, _) = producer.ready(W.last_chance(h(100)), W);
    assert_eq!(filings.len(), 1);
    assert_eq!(filings[0].passes, 0);
    producer.read_done(out[0].key, ReadOutcome::Pass(Box::new(record(0))));
    assert!(producer.in_flight().is_empty(), "a late read is ignored");
}

/// The producer starts no more reads than the client has slots; a read
/// that ends frees its slot and a waiting read starts at the next wake; a
/// read still waiting at the filing deadline is abandoned, not waited for;
/// and a read whose block filed keeps its slot until it ends. Red edits:
/// ignore the cap — every due read starts; free a slot only for a block
/// still held — the filed block's read keeps it forever.
#[test]
fn reads_start_only_while_the_client_has_a_slot() {
    let two = NonZeroUsize::new(2).expect("two");
    let (_ring, mut producer, _chain) = mined_with_slots(16, 5, 0, two);
    let mut started = Vec::new();
    for tip in 101..570 {
        started.extend(producer.due(h(tip)));
        assert!(producer.reading() <= 2, "at tip {tip}");
    }
    assert_eq!(started.len(), 2, "two slots: two of five due reads start");
    let first = started.remove(0);
    producer.read_done(
        first.key,
        ReadOutcome::Pass(Box::new(record(first.key.attempt))),
    );
    let more = producer.due(h(569));
    assert_eq!(more.len(), 1, "the freed slot starts a waiting read");
    started.extend(more);
    assert_eq!(producer.reading(), 2);
    // At the deadline the two reads still waiting are abandoned and the two
    // started are waited for.
    assert!(producer.ready(W.filing_deadline(h(100)), W).0.is_empty());
    for read in started {
        producer.read_done(
            read.key,
            ReadOutcome::Pass(Box::new(record(read.key.attempt))),
        );
    }
    let (filings, _) = producer.ready(W.filing_deadline(h(100)), W);
    assert_eq!(filings.len(), 1);
    assert_eq!((filings[0].draws, filings[0].passes), (5, 3));
    assert_eq!(producer.reading(), 0);

    // A block that files at its last chance leaves its read holding a slot.
    let (_ring, mut producer, _chain) = mined_with_slots(17, 1, 0, two);
    let out: Vec<_> = (101..=570).flat_map(|tip| producer.due(h(tip))).collect();
    assert_eq!(out.len(), 1);
    let (filings, _) = producer.ready(W.last_chance(h(100)), W);
    assert_eq!(filings.len(), 1);
    assert_eq!(
        producer.reading(),
        1,
        "the slot is held until the read ends"
    );
    producer.read_done(out[0].key, ReadOutcome::Stall);
    assert_eq!(producer.reading(), 0);
}

/// A reorg pops a block of ours and connects another block of ours at the
/// same height: the new block is claimed and learned, the old entry goes.
/// Red edit: skip a height already held — the new block is never learned.
#[test]
fn a_block_of_ours_replaces_a_popped_one_at_its_height() {
    let (ring, mut producer, mut chain) = mined(15, 1, 0);
    chain.pop(101);
    chain.pop(100);
    assert!(producer.observe(h(99), W, chain.look()).lost.is_empty());
    let replacement = ring.draw(h(100)).expect("draws");
    chain.blocks.insert(
        h(100),
        Recorded {
            hash: hash_of(100, 0x0B),
            commitment: replacement,
        },
    );
    let observed = producer.observe(h(100), W, chain.look());
    assert_eq!(observed.learn.len(), 1, "the new block is learned");
    assert_eq!(observed.learn[0].hash, hash_of(100, 0x0B));
    assert_eq!(ring.in_flight(), vec![h(100)]);
}

/// The live serving host signs with the identity key: every read meets
/// another scheme, and the filing says so, for the one log line, with no
/// passes. Red edit: drop the flag on `Answered::ServingScheme` — the
/// filing does not say it.
/// A read of a popped block that ends after another block of ours took
/// its height names the old block's hash, and does not settle the new
/// block's draw: it was read with the old block's nonce. Red edit: drop
/// the hash check in `read_done` — the old read's pass settles the new
/// draw, and the block files it at the deadline.
#[test]
fn a_read_of_a_replaced_block_does_not_settle_the_new_one() {
    let (ring, mut producer, mut chain) = mined(18, 1, 0);
    let old = (101..=510)
        .flat_map(|tip| producer.due(h(tip)))
        .next()
        .expect("the first block's read starts");
    assert_eq!(old.key.hash, hash_of(100, 0x0A));
    chain.pop(101);
    chain.pop(100);
    assert!(producer.observe(h(99), W, chain.look()).lost.is_empty());
    let replacement = ring.draw(h(100)).expect("draws");
    chain.blocks.insert(
        h(100),
        Recorded {
            hash: hash_of(100, 0x0B),
            commitment: replacement,
        },
    );
    assert_eq!(producer.observe(h(100), W, chain.look()).learn.len(), 1);
    producer.learned(h(100), W, targets(1, 0));
    let new = (101..=510)
        .flat_map(|tip| producer.due(h(tip)))
        .next()
        .expect("the new block's read starts");
    assert_eq!(new.key.hash, hash_of(100, 0x0B));
    producer.read_done(old.key, ReadOutcome::Pass(Box::new(record(0))));
    assert!(
        producer.ready(W.filing_deadline(h(100)), W).0.is_empty(),
        "the new block's own read is still out"
    );
    assert_eq!(producer.reading(), 1, "the old read freed its slot");
}

#[test]
fn the_identity_scheme_on_the_serving_side_files_no_passes_and_says_so() {
    let (_ring, mut producer, _chain) = mined(5, 3, 0);
    drive(&mut producer, 101, 510, |_| {
        ReadOutcome::Answered(Answered::ServingScheme)
    });
    let (filings, _) = producer.ready(h(510), W);
    assert!(filings[0].serving_scheme_absent);
    assert_eq!(filings[0].passes, 0);
}

/// A popped block pauses: no reads, no filing. Reconnected under the same
/// hash within the cap, it resumes. Red edit: drop a popped block at once
/// — the resumed read never comes.
#[test]
fn a_popped_block_pauses_and_resumes_on_reconnect() {
    let (ring, mut producer, mut chain) = mined(6, 1, 0);
    let ours = chain.blocks[&h(100)];
    chain.pop(101);
    chain.pop(100);
    let observed = producer.observe(h(99), W, chain.look());
    assert!(observed.lost.is_empty());
    for tip in 101..=569 {
        assert!(producer.due(h(tip)).is_empty(), "paused at {tip}");
    }
    assert!(
        producer.ready(h(570), W).0.is_empty(),
        "a paused block does not file"
    );

    chain.blocks.insert(h(100), ours);
    chain.theirs(101);
    let observed = producer.observe(h(101), W, chain.look());
    assert!(observed.lost.is_empty());
    assert!(observed.learn.is_empty(), "its draws are already known");
    let resumed: Vec<_> = (101..=569).flat_map(|tip| producer.due(h(tip))).collect();
    assert_eq!(resumed.len(), 1);
    assert_eq!(ring.in_flight(), vec![h(100)]);
}

/// A popped block that does not come back within the reorg cap is lost,
/// and its secrets go with it. Red edit: never drop a popped block — it
/// stays in flight.
#[test]
fn a_block_popped_past_the_cap_is_lost() {
    let (ring, mut producer, mut chain) = mined(7, 1, 0);
    chain.pop(101);
    chain.pop(100);
    chain.theirs(100);
    let observed = producer.observe(h(100), W, chain.look());
    assert!(observed.lost.is_empty(), "another block at 100: paused");
    let at_cap = h(100) + W.reorg_cap;
    let observed = producer.observe(at_cap - BlockCount::ONE, W, |_| None);
    // The window closes first at this cap: `W₂` < the cap.
    assert_eq!(observed.lost, vec![Lost::WindowClosed { h: h(100) }]);
    assert!(ring.in_flight().is_empty());

    // With a cap inside the window, the cap is what drops it.
    let short = Window {
        response: BlockCount::from_raw(500),
        reorg_cap: BlockCount::from_raw(10),
    };
    let (ring, mut producer, mut chain) = mined(8, 1, 0);
    chain.pop(101);
    chain.pop(100);
    assert!(producer.observe(h(99), short, chain.look()).lost.is_empty());
    let observed = producer.observe(h(109), short, chain.look());
    assert_eq!(observed.lost, vec![Lost::PoppedPastCap { h: h(100) }]);
    assert!(ring.in_flight().is_empty());
}

/// A block that issued no draw on either stream files nothing (SCS-P33),
/// and its secrets go. Red edit: file it — a filing appears.
#[test]
fn a_block_with_no_draws_files_nothing() {
    let (ring, mut producer, _chain) = mined(9, 0, 0);
    assert!(producer.in_flight().is_empty());
    assert!(ring.in_flight().is_empty());
    assert!(producer.ready(h(570), W).0.is_empty());
}

/// Another miner's block is not claimed, and the producer learns nothing
/// of it. Red edit: claim by height alone — 101 is learned.
#[test]
fn another_miners_block_is_not_ours() {
    let ring = Arc::new(WitnessRing::new());
    let mut producer = producer(&ring, 10);
    let mut chain = Chain::default();
    ring.draw(h(101)).expect("draws");
    chain.theirs(101);
    let observed = producer.observe(h(101), W, chain.look());
    assert!(observed.learn.is_empty());
    assert!(producer.in_flight().is_empty());
}

/// The read heights are the daemon's randomness, not the block's seed:
/// two blocks with different seeds planned from the same daemon RNG read
/// at the same heights, and the same block shape under another RNG reads
/// at others. Red edit: seed the plan from the block's seed — the first
/// pair differs.
#[test]
fn the_read_heights_are_not_a_function_of_the_seed() {
    let first_reads = |rng_seed: u64| {
        let (_ring, mut producer, _chain) = mined(rng_seed, 4, 0);
        (101..=569)
            .flat_map(|tip| {
                producer
                    .due(h(tip))
                    .into_iter()
                    .map(move |due| (due.key.draw, tip))
            })
            .collect::<Vec<_>>()
    };
    // Each `mined` draws its block's seed from the OS.
    assert_eq!(first_reads(11), first_reads(11));
    assert_ne!(first_reads(11), first_reads(12));
}

/// What the producer shows holds no seed: a `Learn` prints its height and
/// hash, never the seed. Red edit: derive `Debug` on `Learn` — the seed
/// bytes appear.
#[test]
fn a_learn_shows_no_seed() {
    let ring = Arc::new(WitnessRing::new());
    let mut producer = producer(&ring, 13);
    let mut chain = Chain::default();
    let commitment = ring.draw(h(100)).expect("draws");
    chain.ours(100, commitment);
    let observed = producer.observe(h(100), W, chain.look());
    let learn = &observed.learn[0];
    let hex: String = learn.seed.iter().map(|b| format!("{b:02x}")).collect();
    let shown = format!("{learn:?} {producer:?}");
    assert!(!shown.contains(&hex), "{shown}");
    assert!(
        !shown.contains(&format!("{:?}", &learn.seed[..4])),
        "{shown}"
    );
}
