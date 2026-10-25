// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The producer as a state machine over plain values (crate docs).
//!
//! The ingest crate drives it, and each call is one thing that happened:
//!
//! - [`Producer::observe`] — the chain's tip moved. The producer claims
//!   the blocks this daemon mined, pauses the ones a reorg popped, resumes
//!   the ones that came back, and gives up on the ones past the reorg cap
//!   or past their window. It returns the blocks whose draws it must learn.
//! - [`Producer::learned`] — a block's draws, as the connector derived
//!   them. The producer plans each draw's reads.
//! - [`Producer::due`] — the reads whose height has come.
//! - [`Producer::read_done`] — how a read ended.
//! - [`Producer::ready`] — the bundles to file: every read of the block
//!   completed or was abandoned, or the block reached `h + W₂ − M` with no
//!   read in flight, or the last tip that can still include it. Each is
//!   signed inside the ring, and the entry's secrets are wiped.
//!
//! # The deadline and a read in flight
//!
//! A read may be planned at `h + W₂ − M` itself (§5.3: reads inside
//! `(h, h + W₂ − M]`). At that height every read not yet started is
//! abandoned, and a read already in flight is waited for: its draw settles
//! within the read's timeouts, a few blocks at most, and `M` is the margin
//! that absorbs it. The last tip that can still include the bundle,
//! `h + W₂ − 1`, files whatever is still in flight.
//!
//! # A block of ours replaces a popped one at its height
//!
//! A reorg can pop a block of ours and connect another block of ours at the
//! same height. The new block is claimed, and the popped one's entry and
//! secrets go: only one block at a height is on the chain.
//!
//! # A popped block pauses
//!
//! A block popped by a reorg may reconnect under the same hash, so its
//! entry stays while the reorg cap has not passed, and its reads wait. A
//! block that reconnects resumes where it was. One that does not is
//! dropped once the tip is a reorg cap past the pop. A paused block is
//! not filed: its bundle could not be included on the chain that popped
//! it.

use std::collections::BTreeMap;

use rand::RngCore;
use shekyl_archival_retention::{
    challenge_nonce, support_challenge_nonce, BundleBody, BundleRecord, BundleRef, PassBitmap,
    PassStream,
};
use shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridPublicKey;
use shekyl_crypto_pq::CryptoError;
use shekyl_types::archival::DrawCommitment;
use shekyl_types::{BlockCount, BlockHash, BlockHeight, PCanonicalId, ShardId};
use zeroize::Zeroizing;

use crate::outcome::{Answered, ReadKey, ReadOutcome};
use crate::plan::ReadPlan;
use crate::ring::WitnessRing;
use crate::{CANDIDATE_DEPTH, FILING_MARGIN};

/// The two windows the producer reads off the rule set in force.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    /// `W₂`: a bundle for `h` is admissible in `(h, h + W₂]`.
    pub response: BlockCount,
    /// The reorg cap: how long a popped block's entry waits for it to
    /// reconnect.
    pub reorg_cap: BlockCount,
}

impl Window {
    /// `h + W₂ − M`: the last height a read of `h` starts at; a block with
    /// no read in flight files by it.
    #[must_use]
    pub fn filing_deadline(self, h: BlockHeight) -> BlockHeight {
        h.saturating_add(self.response)
            .saturating_sub_count(FILING_MARGIN)
    }

    /// `h + W₂ − 1`: the last tip after which a bundle for `h` can still be
    /// included. A block that reaches it files whatever is in flight.
    #[must_use]
    pub fn last_chance(self, h: BlockHeight) -> BlockHeight {
        h.saturating_add(self.response)
            .saturating_sub_count(BlockCount::ONE)
    }

    /// Whether a bundle for `h` can still be included in the block after
    /// `tip`: `tip + 1 ≤ h + W₂`.
    #[must_use]
    pub fn open(self, h: BlockHeight, tip: BlockHeight) -> bool {
        tip < h.saturating_add(self.response)
    }
}

/// The recorded block at a height, as the producer reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recorded {
    /// Its hash.
    pub hash: BlockHash,
    /// Its `0x0C` commitment.
    pub commitment: DrawCommitment,
}

/// One block whose draws the producer must learn: the connector derives
/// them from `seed` where the drawable memo is.
pub struct Learn {
    /// The block.
    pub h: BlockHeight,
    /// Its hash when it was claimed. A connector that finds another block
    /// at `h` answers nothing.
    pub hash: BlockHash,
    /// The block's seed. Wiped when this value drops.
    pub seed: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for Learn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Learn")
            .field("h", &self.h)
            .field("hash", &self.hash)
            .finish_non_exhaustive()
    }
}

/// A block the producer gave up on without filing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lost {
    /// Popped, and not reconnected within the reorg cap.
    PoppedPastCap {
        /// The block.
        h: BlockHeight,
    },
    /// Its window closed before it could be filed.
    WindowClosed {
        /// The block.
        h: BlockHeight,
    },
}

/// What [`Producer::observe`] found.
#[derive(Debug, Default)]
pub struct Observed {
    /// Blocks this daemon mined whose draws are not yet known.
    pub learn: Vec<Learn>,
    /// Blocks given up on, for the log.
    pub lost: Vec<Lost>,
}

/// One draw to read: whom, which shard, and under which key its receipt
/// verifies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrawTarget {
    /// The draw `j` within its stream.
    pub draw: u32,
    /// The persona that holds the shard.
    pub persona: PCanonicalId,
    /// The shard.
    pub shard: ShardId,
    /// The receipt key the record's receipt verifies under, as the bond
    /// record carries it.
    pub receipt_key: FnDsaHybridPublicKey,
    /// The persona's endpoint column, from the bond record.
    pub endpoint: [u8; 32],
}

/// A block's draws, in order on each stream. The lengths are the counts
/// the bundle's two bitmaps state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Targets {
    /// Economy draws `j < count(h)`.
    pub economy: Vec<DrawTarget>,
    /// Support draws `j < support_count(h)`.
    pub support: Vec<DrawTarget>,
}

/// A read whose height has come.
#[derive(Clone, PartialEq, Eq)]
pub struct DueRead {
    /// Which read.
    pub key: ReadKey,
    /// The persona to dial.
    pub persona: PCanonicalId,
    /// Its endpoint column.
    pub endpoint: [u8; 32],
    /// The key its receipt verifies under.
    pub receipt_key: FnDsaHybridPublicKey,
    /// The shard to read.
    pub shard: ShardId,
    /// The challenge nonce: derived from the seed, `block_hash(h)`, `j` and
    /// `attempt`, under the stream's label. Indistinguishable from random
    /// until the bundle reveals the seed.
    pub nonce: [u8; 32],
}

/// The nonce is not shown: the read's SOCKS credentials derive from it,
/// and nothing of ours logs them (§5.3, `SF-D3`).
impl core::fmt::Debug for DueRead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DueRead")
            .field("key", &self.key)
            .field("persona", &self.persona)
            .field("shard", &self.shard)
            .finish_non_exhaustive()
    }
}

/// A bundle to offer to the queue.
#[derive(Debug)]
pub struct Filing {
    /// The block.
    pub h: BlockHeight,
    /// The reference: the kept bytes and the prunable hash.
    pub reference: BundleRef,
    /// The body the reference names.
    pub body: BundleBody,
    /// How many draws the block issued, on both streams.
    pub draws: usize,
    /// How many of them passed.
    pub passes: usize,
    /// Whether a read met the identity scheme on the serving side.
    pub serving_scheme_absent: bool,
}

#[derive(Clone, Debug)]
enum DrawState {
    /// Attempt `attempt` is read at its plan height.
    Pending { attempt: u8 },
    /// Attempt `attempt` is being read.
    Reading { attempt: u8 },
    /// It passed.
    Passed(Box<BundleRecord>),
    /// `P` answered and it was not a pass, or every attempt stalled, or
    /// the deadline came first.
    Done,
}

impl DrawState {
    const fn settled(&self) -> bool {
        matches!(self, Self::Passed(_) | Self::Done)
    }
}

struct Draw {
    target: DrawTarget,
    plan: ReadPlan,
    state: DrawState,
}

enum Stage {
    /// Claimed; the connector has not answered with its draws yet.
    Learning,
    /// Draws known and planned: economy then support.
    Reading {
        economy: Vec<Draw>,
        support: Vec<Draw>,
    },
}

struct BlockWork {
    hash: BlockHash,
    /// The tip at the pop, while the block is off the chain.
    popped_at: Option<BlockHeight>,
    stage: Stage,
    serving_scheme_absent: bool,
}

/// The producer (module docs).
pub struct Producer {
    ring: std::sync::Arc<WitnessRing>,
    blocks: BTreeMap<BlockHeight, BlockWork>,
    rng: Box<dyn RngCore + Send>,
}

impl core::fmt::Debug for Producer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Producer")
            .field("blocks", &self.blocks.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Producer {
    /// A producer over `ring`, planning reads from `rng` — the daemon's
    /// own randomness, never the seed.
    #[must_use]
    pub fn new(ring: std::sync::Arc<WitnessRing>, rng: Box<dyn RngCore + Send>) -> Self {
        Self {
            ring,
            blocks: BTreeMap::new(),
            rng,
        }
    }

    /// The ring this producer files from.
    #[must_use]
    pub fn ring(&self) -> &std::sync::Arc<WitnessRing> {
        &self.ring
    }

    /// The blocks in flight, ascending: claimed and neither filed nor lost.
    #[must_use]
    pub fn in_flight(&self) -> Vec<BlockHeight> {
        self.blocks.keys().copied().collect()
    }

    /// The chain's tip is `tip`. `look(h)` reads the recorded block at `h`,
    /// `None` above the tip.
    ///
    /// Every height from [`CANDIDATE_DEPTH`] below the tip up to it is
    /// matched against the ring, so a block of ours a short reorg brought
    /// back is claimed as well as a new one. Every block in flight is
    /// checked against the chain: popped, back, past the cap, or past its
    /// window.
    pub fn observe(
        &mut self,
        tip: BlockHeight,
        window: Window,
        mut look: impl FnMut(BlockHeight) -> Option<Recorded>,
    ) -> Observed {
        let mut observed = Observed::default();
        self.ring.evict(tip);

        let mut h = tip.saturating_sub_count(CANDIDATE_DEPTH);
        loop {
            if let Some(recorded) = look(h) {
                let held = self.blocks.get(&h).map(|work| work.hash);
                if held != Some(recorded.hash) && self.ring.claim(h, &recorded.commitment) {
                    self.blocks.insert(
                        h,
                        BlockWork {
                            hash: recorded.hash,
                            popped_at: None,
                            stage: Stage::Learning,
                            serving_scheme_absent: false,
                        },
                    );
                }
            }
            if h >= tip {
                break;
            }
            h = h.saturating_add(BlockCount::ONE);
        }

        let mut gone = Vec::new();
        for (&h, work) in &mut self.blocks {
            if !window.open(h, tip) {
                gone.push((h, Lost::WindowClosed { h }));
                continue;
            }
            let on_chain = look(h).is_some_and(|recorded| recorded.hash == work.hash);
            if on_chain {
                work.popped_at = None;
                continue;
            }
            let popped_at = *work.popped_at.get_or_insert(tip);
            if tip >= popped_at.saturating_add(window.reorg_cap) {
                gone.push((h, Lost::PoppedPastCap { h }));
            }
        }
        for (h, lost) in gone {
            self.blocks.remove(&h);
            self.ring.forget(h);
            observed.lost.push(lost);
        }

        for (&h, work) in &self.blocks {
            if matches!(work.stage, Stage::Learning) && work.popped_at.is_none() {
                if let Some(seed) = self.ring.seed(h) {
                    observed.learn.push(Learn {
                        h,
                        hash: work.hash,
                        seed,
                    });
                }
            }
        }
        observed
    }

    /// `h`'s draws, as the connector derived them. A block that issued
    /// none on either stream files nothing (`SCS-P33`): its entry and its
    /// secrets go. A block no longer in flight, or already planned,
    /// ignores this.
    pub fn learned(&mut self, h: BlockHeight, window: Window, targets: Targets) {
        let Some(work) = self.blocks.get_mut(&h) else {
            return;
        };
        if !matches!(work.stage, Stage::Learning) {
            return;
        }
        if targets.economy.is_empty() && targets.support.is_empty() {
            self.blocks.remove(&h);
            self.ring.forget(h);
            return;
        }
        let rng = &mut self.rng;
        let mut plan = |target: DrawTarget| Draw {
            plan: ReadPlan::draw(rng, h, window.response),
            target,
            state: DrawState::Pending { attempt: 0 },
        };
        let economy = targets.economy.into_iter().map(&mut plan).collect();
        let support = targets.support.into_iter().map(&mut plan).collect();
        work.stage = Stage::Reading { economy, support };
    }

    /// The reads whose height has come at `tip`, each marked as being
    /// read. A paused block reads nothing.
    pub fn due(&mut self, tip: BlockHeight) -> Vec<DueRead> {
        let mut due = Vec::new();
        for (&h, work) in &mut self.blocks {
            if work.popped_at.is_some() {
                continue;
            }
            let Stage::Reading { economy, support } = &mut work.stage else {
                continue;
            };
            let Some(seed) = self.ring.seed(h) else {
                continue;
            };
            let hash = work.hash;
            let streams = [
                (PassStream::Economy, economy),
                (PassStream::Support, support),
            ];
            for (stream, draws) in streams {
                for draw in draws.iter_mut() {
                    let DrawState::Pending { attempt } = draw.state else {
                        continue;
                    };
                    let Some(at) = draw.plan.at(attempt) else {
                        draw.state = DrawState::Done;
                        continue;
                    };
                    if at > tip {
                        continue;
                    }
                    let j = draw.target.draw;
                    let nonce = match stream {
                        PassStream::Economy => challenge_nonce(&seed, hash.as_bytes(), j, attempt),
                        PassStream::Support => {
                            support_challenge_nonce(&seed, hash.as_bytes(), j, attempt)
                        }
                    };
                    draw.state = DrawState::Reading { attempt };
                    due.push(DueRead {
                        key: ReadKey {
                            h,
                            stream,
                            draw: j,
                            attempt,
                        },
                        persona: draw.target.persona,
                        endpoint: draw.target.endpoint,
                        receipt_key: draw.target.receipt_key.clone(),
                        shard: draw.target.shard,
                        nonce,
                    });
                }
            }
        }
        due
    }

    /// How the read `key` ended. A read the producer no longer waits for —
    /// the block was filed, lost, or the deadline settled the draw — is
    /// ignored.
    pub fn read_done(&mut self, key: ReadKey, outcome: ReadOutcome) {
        let Some(work) = self.blocks.get_mut(&key.h) else {
            return;
        };
        let Stage::Reading { economy, support } = &mut work.stage else {
            return;
        };
        let draws = match key.stream {
            PassStream::Economy => economy,
            PassStream::Support => support,
        };
        let Some(draw) = draws.iter_mut().find(|d| d.target.draw == key.draw) else {
            return;
        };
        if !matches!(draw.state, DrawState::Reading { attempt } if attempt == key.attempt) {
            return;
        }
        draw.state = match outcome {
            ReadOutcome::Pass(record) => DrawState::Passed(record),
            ReadOutcome::Stall => {
                let next = key.attempt.saturating_add(1);
                if draw.plan.at(next).is_some() {
                    DrawState::Pending { attempt: next }
                } else {
                    DrawState::Done
                }
            }
            ReadOutcome::Answered(answered) => {
                if answered == Answered::ServingScheme {
                    work.serving_scheme_absent = true;
                }
                DrawState::Done
            }
        };
    }

    /// The bundles to file at `tip`, signed inside the ring.
    ///
    /// A block files once every draw has settled; at its deadline
    /// `h + W₂ − M` every read not yet started is abandoned and the block
    /// files once no read is in flight; at `h + W₂ − 1` it files whatever
    /// is in flight (module docs). A paused block does not file. A block
    /// whose signing fails is dropped with its secrets and reported in the
    /// `Err` list: there is nothing to retry it with.
    pub fn ready(
        &mut self,
        tip: BlockHeight,
        window: Window,
    ) -> (Vec<Filing>, Vec<(BlockHeight, CryptoError)>) {
        let mut ready = Vec::new();
        for (&h, work) in &mut self.blocks {
            if work.popped_at.is_some() {
                continue;
            }
            let Stage::Reading { economy, support } = &mut work.stage else {
                continue;
            };
            if tip >= window.filing_deadline(h) {
                for draw in economy.iter_mut().chain(support.iter_mut()) {
                    if matches!(draw.state, DrawState::Pending { .. }) {
                        draw.state = DrawState::Done;
                    }
                }
            }
            let settled = economy
                .iter()
                .chain(support.iter())
                .all(|d| d.state.settled());
            if settled || tip >= window.last_chance(h) {
                ready.push(h);
            }
        }
        let mut filings = Vec::new();
        let mut failed = Vec::new();
        for h in ready {
            let Some(work) = self.blocks.remove(&h) else {
                continue;
            };
            let Stage::Reading { economy, support } = work.stage else {
                continue;
            };
            let (passes, mut records) = bitmap_and_records(&economy);
            let (support_passes, support_records) = bitmap_and_records(&support);
            records.extend(support_records);
            let passed = records.len();
            match self.ring.file(h, passes, support_passes, &records) {
                Some(Ok((reference, body))) => filings.push(Filing {
                    h,
                    reference,
                    body,
                    draws: economy.len() + support.len(),
                    passes: passed,
                    serving_scheme_absent: work.serving_scheme_absent,
                }),
                Some(Err(error)) => failed.push((h, error)),
                None => {}
            }
        }
        (filings, failed)
    }

    /// Every block in flight, for the log when the producer stops: the
    /// ring is memory only, and these blocks' draws expire in flight.
    #[must_use]
    pub fn dropped_at_stop(&self) -> Vec<(BlockHeight, usize)> {
        self.blocks
            .iter()
            .map(|(&h, work)| {
                let draws = match &work.stage {
                    Stage::Learning => 0,
                    Stage::Reading { economy, support } => economy.len() + support.len(),
                };
                (h, draws)
            })
            .collect()
    }
}

/// One stream's bitmap and its records, in draw order.
fn bitmap_and_records(draws: &[Draw]) -> (PassBitmap, Vec<BundleRecord>) {
    let count = u32::try_from(draws.len()).expect("a stream's draws fit the u32 count");
    let mut passed = Vec::new();
    let mut records = Vec::new();
    for draw in draws {
        if let DrawState::Passed(record) = &draw.state {
            passed.push(draw.target.draw);
            records.push(**record);
        }
    }
    let bitmap = PassBitmap::from_passes(count, passed)
        .expect("every draw index is below the stream's count");
    (bitmap, records)
}

#[cfg(test)]
#[path = "producer_tests.rs"]
mod tests;
