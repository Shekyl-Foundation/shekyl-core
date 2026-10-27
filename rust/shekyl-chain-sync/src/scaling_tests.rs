// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The owner's cost per header, apart from RandomX (`P2P_3_CHAIN_SYNC_BRIEF.md`
//! CS-Q11; Rick, 2026-10-24).
//!
//! The floor device's header sync was bounded by the model, not by
//! hashing: each event did work that grew with the header tree `T`, so
//! the sync was quadratic. This drives the model through a header sync
//! and then a connect of every header, at 5,000, 10,000 and 20,000
//! headers, with every proof answered by a substrate whose hash always
//! passes (a fixed target of 1 accepts any hash, so the model's path is
//! the real one). The cost per header must not grow with the size: by
//! the reads the model makes (tree node loads and pending-header reads)
//! and, loosely, by wall time.

#![cfg(test)]

use std::time::{Duration, Instant};

use shekyl_chain_rules::harness::fixture::{candidate_on, chain_of};
use shekyl_chain_rules::harness::MockSubstrate;
use shekyl_chain_rules::{form_header, AtHeight, HeaderRecord, HeaderView, RuleSet, Tip, Trust};
use shekyl_draw_rng::RelayRng;
use shekyl_levin::PortableMap;
use shekyl_types::{BlockHash, BlockHeight, Timestamp};
use shekyl_wire::PowBlob;

use crate::branch::PENDING_READS;
use crate::model::{Event, Proved, Sync};
use crate::proof::{fixed, open_claim};
use crate::Command;

/// Headers per response. Any size shows the same shape.
const PER_RESPONSE: usize = 2_048;

/// Headers connected per tip event, as body sync connects them.
const PER_CONNECT: usize = 64;

struct NoDraw;

impl RelayRng for NoDraw {
    fn next_u64(&mut self) -> u64 {
        0
    }
}

/// What one phase cost the model, over `headers` headers.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Cost {
    pub headers: usize,
    /// Time inside `Sync::handle`, and nothing else.
    pub handle: Duration,
    /// Tree node loads plus pending-header reads.
    pub reads: u64,
}

impl Cost {
    fn headers(&self) -> u128 {
        u128::try_from(self.headers).expect("a count")
    }

    /// Whether this phase's cost per header, by `of`, is at most
    /// `num / den` times `small`'s. Integers, so the comparison is exact.
    fn within(&self, small: &Self, of: impl Fn(&Self) -> u128, num: u128, den: u128) -> bool {
        of(self) * small.headers() * den <= of(small) * self.headers() * num
    }

    fn line(&self) -> String {
        format!(
            "{}: {} reads, {} ns per header",
            self.headers,
            u128::from(self.reads) / self.headers(),
            self.handle.as_nanos() / self.headers()
        )
    }
}

/// Main as the fixture chain, grown by the synthetic headers up to `upto`.
struct Grown<'v, V> {
    base: &'v V,
    base_tip: Tip,
    extra: &'v [HeaderRecord],
    upto: usize,
}

impl<'id, V: HeaderView<'id>> HeaderView<'id> for Grown<'_, V> {
    type Fault = V::Fault;

    fn tip(&self) -> Result<Option<Tip>, Self::Fault> {
        match self
            .upto
            .checked_sub(1)
            .and_then(|last| self.extra.get(last))
        {
            None => Ok(Some(self.base_tip)),
            Some(record) => Ok(Some(Tip {
                height: self.height_of(self.upto - 1),
                hash: record.hash,
            })),
        }
    }

    fn header_at(&self, height: BlockHeight) -> Result<AtHeight<HeaderRecord>, Self::Fault> {
        let base = self.base_tip.height.to_raw();
        if height.to_raw() <= base {
            return self.base.header_at(height);
        }
        let index = usize::try_from(height.to_raw() - base - 1).unwrap_or(usize::MAX);
        if index >= self.upto {
            return Ok(AtHeight::AboveTip);
        }
        Ok(self
            .extra
            .get(index)
            .cloned()
            .map_or(AtHeight::AboveTip, AtHeight::Recorded))
    }
}

impl<V> Grown<'_, V> {
    fn height_of(&self, index: usize) -> BlockHeight {
        BlockHeight::from_raw(
            self.base_tip.height.to_raw() + 1 + u64::try_from(index).expect("a height"),
        )
    }
}

fn reads<R: Fn(BlockHeight) -> RuleSet>(sync: &Sync<u8, R>) -> u64 {
    sync.tree_visits() + PENDING_READS.with(std::cell::Cell::get)
}

fn reset<R: Fn(BlockHeight) -> RuleSet>(sync: &Sync<u8, R>) {
    sync.reset_visits();
    PENDING_READS.with(|reads| reads.set(0));
}

/// Sync `count` synthetic headers from one peer, then connect them all.
/// Returns the header phase's cost and the connect phase's.
pub(crate) fn sync_then_connect(count: usize) -> (Cost, Cost) {
    let rules = fixed(1, 64);
    let main = chain_of(8);
    let mut block = candidate_on(&main, Vec::new()).block;
    let mut sync = Sync::new(Trust::UNANCHORED, move |_| rules);
    // Far past every synthetic timestamp, which climb by 120 s a header.
    let wall = Timestamp::from_raw(u64::MAX / 4);
    sync.set_wall(wall);
    let substrate = MockSubstrate {
        clock: wall,
        ..MockSubstrate::default()
    };
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
        .expect("main answers");
        open_claim(&mut sync, &view, 1);
        let mut when = match view.header_at(tip.height).expect("main answers") {
            AtHeight::Recorded(record) => record.header.timestamp,
            AtHeight::AboveTip => panic!("the tip is on main"),
        };
        let mut previous = tip.hash;
        let mut pows = Vec::with_capacity(count);
        let mut hashes: Vec<BlockHash> = Vec::with_capacity(count);
        for _ in 0..count {
            block.header.previous = previous;
            when = when.saturating_add(120);
            block.header.timestamp = when;
            let pow = block.pow_blob();
            previous = PowBlob::read(&pow).expect("preimage").identity();
            hashes.push(previous);
            pows.push(pow);
        }

        // Headers.
        reset(&sync);
        let mut headers = Cost {
            headers: count,
            handle: Duration::ZERO,
            reads: 0,
        };
        let mut start = 0;
        while start < pows.len() {
            let end = (start + PER_RESPONSE).min(pows.len());
            let bytes = shekyl_levin::ResponseHeaders {
                blobs: pows[start..end].to_vec(),
                tip_work: u128::MAX,
                more: end < pows.len(),
            }
            .store()
            .expect("the headers encode");
            let mut out = Vec::new();
            let started = Instant::now();
            sync.handle(
                Event::Headers { session: 1, bytes },
                &view,
                Instant::now(),
                &mut NoDraw,
                &mut out,
            )
            .expect("the view answers");
            headers.handle += started.elapsed();
            while let Some((job, items)) = out.iter().find_map(|command| match command {
                Command::Prove { job, items, .. } => Some((*job, items.clone())),
                _ => None,
            }) {
                let results = items
                    .iter()
                    .map(|item| {
                        let pow = PowBlob::read(&item.pow).expect("preimage");
                        let formed = form_header(
                            &pow,
                            &item.rule_set,
                            &substrate,
                            item.seed,
                            item.target,
                            item.attempt,
                        )
                        .expect("the mock answers")
                        .expect("the header forms");
                        Proved::Formed(Box::new(formed))
                    })
                    .collect();
                out.clear();
                let started = Instant::now();
                sync.handle(
                    Event::Proven { job, results },
                    &view,
                    Instant::now(),
                    &mut NoDraw,
                    &mut out,
                )
                .expect("the view answers");
                headers.handle += started.elapsed();
            }
            start = end;
        }
        headers.reads = reads(&sync);
        let last = *hashes.last().expect("headers");
        assert!(sync.contains_header(last), "the synthetic tip entered T");

        // Connect: main grows over the synced headers, 64 at a time, and
        // each tip event takes the connected prefix out of `T`.
        let records: Vec<HeaderRecord> = hashes
            .iter()
            .map(|hash| sync.header_record(*hash).expect("every header is in T"))
            .collect();
        reset(&sync);
        let mut connect = Cost {
            headers: count,
            handle: Duration::ZERO,
            reads: 0,
        };
        let mut upto = 0;
        while upto < count {
            upto = (upto + PER_CONNECT).min(count);
            let grown = Grown {
                base: &view,
                base_tip: tip,
                extra: &records,
                upto,
            };
            let at = grown.tip().expect("grown answers").expect("a tip");
            let mut out = Vec::new();
            let started = Instant::now();
            sync.handle(
                Event::Tip { tip: at },
                &grown,
                Instant::now(),
                &mut NoDraw,
                &mut out,
            )
            .expect("the view answers");
            connect.handle += started.elapsed();
        }
        connect.reads = reads(&sync);
        assert!(
            !sync.contains_header(last),
            "every header left T on connect"
        );
        (headers, connect)
    })
}

/// The owner's cost per header is flat across 5,000, 10,000 and 20,000
/// headers, for the header sync and for the connect.
///
/// Reads per header may grow with the tree's depth (skip pointers make an
/// ancestor lookup O(log n)), so 20,000 headers may cost up to 1.5 times
/// what 5,000 do; a pass over `T` per event costs 4 times. Wall time per
/// header is held to 2.5 times, loose enough for a loaded machine and
/// still below the quadratic's 4. Red edits: a linear scan of the run in
/// the branch view; rebuilding every skip pointer on connect.
#[test]
fn owner_cost_per_header_is_flat_across_sizes() {
    let sizes = [5_000, 10_000, 20_000];
    let costs: Vec<(Cost, Cost)> = sizes
        .iter()
        .map(|count| sync_then_connect(*count))
        .collect();
    for (phase, pick) in [("headers", 0usize), ("connect", 1)] {
        let of = |index: usize| {
            if pick == 0 {
                costs[index].0
            } else {
                costs[index].1
            }
        };
        let (small, large) = (of(0), of(2));
        let lines: Vec<String> = (0..sizes.len()).map(|index| of(index).line()).collect();
        let reads = |cost: &Cost| u128::from(cost.reads);
        let nanos = |cost: &Cost| cost.handle.as_nanos();
        assert!(
            large.within(&small, reads, 3, 2),
            "{phase}: reads per header grew with the size ({})",
            lines.join("; ")
        );
        assert!(
            large.within(&small, nanos, 5, 2),
            "{phase}: time per header grew with the size ({})",
            lines.join("; ")
        );
    }
}
