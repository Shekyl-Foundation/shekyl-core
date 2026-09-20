// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The open edge — measured as round trips, not as bandwidth.
//!
//! ## Why this module does not measure throughput
//!
//! This harness's opening brief modelled the open edge as
//! `bytes / (bytes per second)`: measure fetch-and-decode throughput against a
//! spawned daemon, multiply by worst-case window bytes. Reading the landed
//! fetch path refuted the model before it was built.
//!
//! [`shekyl_engine_core::DaemonClient::fetch_scannable_block`] resolves to
//! `engine::block_fetch::fetch_scannable_block_with_form`, which is **strictly
//! per-block** and issues, sequentially and with no pipelining:
//!
//! 1. `get_block` (JSON-RPC; the block arrives **hex-encoded**),
//! 2. `get_transactions` — one call per [`TXS_PER_REQUEST`]-sized batch, so one
//!    call for any realistic block, and none for an empty one,
//! 3. `get_o_indexes`, inside `compute_first_output_index`.
//!
//! Over [`crate::corpus::HELD_BUFFER_BLOCKS`] that is roughly 1 600–2 400
//! **serialized** round trips. On a Pi 4 driving a loopback daemon the fixed
//! per-round-trip cost is very likely to dominate the byte cost, and a
//! throughput model cannot see it at all: it would report a number that graded
//! the wrong term.
//!
//! [`TXS_PER_REQUEST`]: https://github.com/Shekyl-Foundation/shekyl-core
//!
//! ## Why the attribution is part of the measurement
//!
//! §6.3.4 row 3 pre-registers the miss response as *"the buffer gets its own
//! companion file"* — a remedy that fits a **volume**-bound cost. If the cost
//! is round-trip bound, the proportionate remedy is a bulk or pipelined fetch,
//! and the companion file is a much larger change aimed at the wrong term. So
//! the harness attributes the cost to a term *in the same record as the
//! measurement*, and the ruled row carries the matching amendment.

use serde::Serialize;

use crate::corpus::HELD_BUFFER_BLOCKS;
use crate::timing::duration_s;

/// Share of projected cost above which one term is called dominant.
pub const DOMINANCE_THRESHOLD: f64 = 0.60;

/// Fraction of the graded density a corpus must reach before a run may grade.
///
/// A sample far below the density the budget is stated at cannot fail, so a
/// pass over it is a pass for the wrong reason. The first live run measured
/// **1 432 B** per block against a nominal target three orders of magnitude
/// larger — coinbase-only regtest blocks — and the harness must say so rather
/// than report 0.2 s and a green tick.
pub const MIN_CORPUS_DENSITY_FRACTION: f64 = 0.50;

/// Whether the sampled blocks were dense enough for the budget to bite.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct CorpusDensity {
    /// Mean decoded bytes per sampled block.
    pub measured_bytes_per_block: u64,
    /// The per-block weight the budget is graded at
    /// ([`crate::corpus::nominal_block_weight`]).
    pub graded_at_weight: u64,
    /// `measured / graded`.
    pub fraction_of_graded: f64,
    /// Whether the corpus is dense enough to grade against.
    pub sufficient: bool,
}

/// Judge a sample's density against the weight the budget is stated at.
///
/// Weight and decoded bytes are not the same unit — weight carries the
/// Bulletproof+ clawback — but they agree within a small factor for ordinary
/// transactions, and the question here is three-orders-of-magnitude coarse.
/// Treating them as comparable is stated rather than assumed.
#[must_use]
pub fn judge_density(samples: &[BlockSample], graded_at_weight: u64) -> CorpusDensity {
    let measured = if samples.is_empty() {
        0
    } else {
        samples.iter().map(|s| s.decoded_bytes).sum::<u64>() / samples.len() as u64
    };
    let fraction = if graded_at_weight == 0 {
        0.0
    } else {
        measured as f64 / graded_at_weight as f64
    };
    CorpusDensity {
        measured_bytes_per_block: measured,
        graded_at_weight,
        fraction_of_graded: fraction,
        sufficient: fraction >= MIN_CORPUS_DENSITY_FRACTION,
    }
}

/// Which term an open-edge cost sits in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Attribution {
    /// Fixed per-round-trip cost dominates. A miss here fires bulk/pipelined
    /// fetch, **not** §6.3.4 row 3's companion file.
    RoundTripBound,
    /// Byte transfer and decode dominate. A miss here fires the companion file
    /// as pre-registered.
    VolumeBound,
    /// Neither term clears [`DOMINANCE_THRESHOLD`]. A miss here is attributed
    /// by the maintainer, not by the harness.
    Mixed,
}

/// One fetched block, with every term the attribution needs.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct BlockSample {
    /// Height fetched.
    pub height: u64,
    /// Sequential RPC round trips the fetch made.
    pub round_trips: u32,
    /// Bytes as they crossed the wire — the block blob arrives hex-encoded, so
    /// this is about twice the decoded size and is **not** interchangeable
    /// with it.
    pub wire_hex_bytes: u64,
    /// Bytes after hex decode.
    pub decoded_bytes: u64,
    /// Wall seconds for the whole per-block fetch.
    pub seconds: f64,
}

/// The measured floor cost of a single round trip.
///
/// Measured directly rather than regressed out of the block samples: round
/// trips per block are nearly constant (2–3), so a two-parameter fit over them
/// is ill-conditioned and would report a confident number from an
/// under-determined system. Timing the cheapest RPC repeatedly determines the
/// term instead of inferring it.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct RoundTripFloor {
    /// Median seconds for one minimal RPC.
    pub median_s: f64,
    /// Calls timed.
    pub samples: usize,
}

/// The projection from a measured sample to the full held buffer.
#[derive(Clone, Debug, Serialize)]
pub struct Projection {
    /// Blocks actually fetched.
    pub blocks_measured: u64,
    /// [`HELD_BUFFER_BLOCKS`] — what the projection is to.
    pub blocks_projected: u64,
    /// Median per-block seconds across the measured sample.
    pub per_block_median_s: f64,
    /// 95th-percentile per-block seconds.
    pub per_block_p95_s: f64,
    /// Total round trips the full buffer would make.
    pub projected_round_trips: u64,
    /// Projected wall seconds, built from the **per-block distribution**, not
    /// from a bandwidth product.
    pub projected_s: f64,
    /// Seconds of the projection attributable to fixed round-trip cost.
    pub round_trip_term_s: f64,
    /// The remainder: bytes, parsing, and daemon-side work that scales with
    /// block content.
    pub volume_term_s: f64,
    /// Which term dominates.
    pub attribution: Attribution,
    /// Projected wire (hex) bytes.
    pub projected_wire_hex_bytes: u64,
    /// Projected decoded bytes.
    pub projected_decoded_bytes: u64,
}

/// Project a measured sample onto the full held buffer and attribute its cost.
///
/// # Panics
/// Never: an empty sample yields a zeroed projection attributed `Mixed`.
#[must_use]
pub fn project(samples: &[BlockSample], floor: RoundTripFloor) -> Projection {
    if samples.is_empty() {
        return Projection {
            blocks_measured: 0,
            blocks_projected: HELD_BUFFER_BLOCKS,
            per_block_median_s: 0.0,
            per_block_p95_s: 0.0,
            projected_round_trips: 0,
            projected_s: 0.0,
            round_trip_term_s: 0.0,
            volume_term_s: 0.0,
            attribution: Attribution::Mixed,
            projected_wire_hex_bytes: 0,
            projected_decoded_bytes: 0,
        };
    }
    let n = samples.len() as f64;
    let mut seconds: Vec<f64> = samples.iter().map(|s| s.seconds).collect();
    seconds.sort_by(|a, b| a.partial_cmp(b).expect("timings are never NaN"));
    let median = seconds[seconds.len() / 2];
    let p95_rank = ((0.95 * seconds.len() as f64).ceil().max(1.0) as usize).min(seconds.len());
    let p95 = seconds[p95_rank - 1];

    let mean_round_trips = samples
        .iter()
        .map(|s| f64::from(s.round_trips))
        .sum::<f64>()
        / n;
    let mean_wire = samples.iter().map(|s| s.wire_hex_bytes as f64).sum::<f64>() / n;
    let mean_decoded = samples.iter().map(|s| s.decoded_bytes as f64).sum::<f64>() / n;

    let blocks = HELD_BUFFER_BLOCKS as f64;
    // The projection is the per-block *distribution* scaled by block count --
    // the median carries the typical block and the record carries p95 beside
    // it, so a reader can see the spread the single number hides.
    let projected_s = median * blocks;
    let projected_round_trips = mean_round_trips * blocks;
    // The floor is per round trip and cannot exceed the whole cost; clamping
    // keeps a noisy floor measurement from reporting a negative volume term.
    let round_trip_term_s = (floor.median_s * projected_round_trips).min(projected_s);
    let volume_term_s = projected_s - round_trip_term_s;

    let attribution = if projected_s <= 0.0 {
        Attribution::Mixed
    } else if round_trip_term_s / projected_s >= DOMINANCE_THRESHOLD {
        Attribution::RoundTripBound
    } else if volume_term_s / projected_s >= DOMINANCE_THRESHOLD {
        Attribution::VolumeBound
    } else {
        Attribution::Mixed
    };

    Projection {
        blocks_measured: samples.len() as u64,
        blocks_projected: HELD_BUFFER_BLOCKS,
        per_block_median_s: median,
        per_block_p95_s: p95,
        projected_round_trips: projected_round_trips as u64,
        projected_s,
        round_trip_term_s,
        volume_term_s,
        attribution,
        projected_wire_hex_bytes: (mean_wire * blocks) as u64,
        projected_decoded_bytes: (mean_decoded * blocks) as u64,
    }
}

/// Time one closure, returning its result and the seconds it took.
pub fn timed<T, F: FnOnce() -> T>(f: F) -> (T, f64) {
    let start = std::time::Instant::now();
    let out = f();
    (out, duration_s(start.elapsed()))
}

#[cfg(test)]
#[path = "openedge_tests.rs"]
mod tests;
