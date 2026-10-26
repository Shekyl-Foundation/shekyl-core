// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The read plan of one draw (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §5.3).
//!
//! Up to `K` attempt heights inside `(h, h + W₂ − M]`, consecutive ones
//! at least [`crate::READ_SPACING`] apart, drawn when `h` connects from a
//! daemon-local RNG. Not from the seed: the seed is public once the bundle
//! reveals it, and the timing of the reads must not be derivable from it.
//!
//! Attempt `i` is read at `heights[i]` only if attempt `i − 1` ended
//! stall-class. A completed exchange ends the draw, so most plans read
//! once.

use rand::Rng;
use shekyl_archival_retention::CHALLENGE_READS;
use shekyl_types::{BlockCount, BlockHeight};

use crate::{FILING_MARGIN, READ_SPACING};

/// The attempt heights of one draw, ascending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadPlan {
    heights: Vec<BlockHeight>,
}

impl ReadPlan {
    /// The plan for a draw of `h` under response window `w2`, drawn from
    /// `rng`.
    ///
    /// The window `(h, h + W₂ − M]` holds `1 + (W₂ − M − 1) / spacing`
    /// spaced attempts at most, capped at `K`. Each attempt is uniform
    /// over what is left once the later ones have room: attempt `i` lies
    /// in `[previous + spacing, last − (n − 1 − i) · spacing]`. A window
    /// too short for even one read past `h` plans one read at `h + 1`:
    /// the deadline is then the next block, and the read is still made.
    #[must_use]
    pub fn draw(rng: &mut impl Rng, h: BlockHeight, w2: BlockCount) -> Self {
        let first = h.saturating_add(BlockCount::ONE).to_raw();
        let last = h
            .saturating_add(w2)
            .saturating_sub_count(FILING_MARGIN)
            .to_raw()
            .max(first);
        let spacing = READ_SPACING.to_raw();
        let fit = 1 + (last - first) / spacing;
        let n = fit.min(u64::from(CHALLENGE_READS));
        let mut heights = Vec::with_capacity(usize::from(CHALLENGE_READS));
        let mut lo = first;
        for i in 0..n {
            let hi = last - (n - 1 - i) * spacing;
            let at = rng.gen_range(lo..=hi);
            heights.push(BlockHeight::from_raw(at));
            lo = at + spacing;
        }
        Self { heights }
    }

    /// The height attempt `attempt` is read at, if the plan has one.
    #[must_use]
    pub fn at(&self, attempt: u8) -> Option<BlockHeight> {
        self.heights.get(usize::from(attempt)).copied()
    }

    /// Every attempt height, ascending.
    #[must_use]
    pub fn heights(&self) -> &[BlockHeight] {
        &self.heights
    }
}

#[cfg(test)]
#[path = "plan_tests.rs"]
mod tests;
