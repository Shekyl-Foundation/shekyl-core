// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The holder draw (`SF-D10`): uniform over the holders of a shard,
//! memoryless across needs, without replacement within one.
//!
//! The urn is the need's own: it is built from the holder set when the
//! need opens and dies with the need. Nothing about a prior need — which
//! `P` served, which stalled — reaches the next draw. That is `SF-D10`'s
//! "forms no opinions": a `P` that stalled on one read is as likely to be
//! drawn for the next as any other, and the only thing that makes it less
//! likely to be *re*-drawn is that the current need has already tried it.
//!
//! Entropy is the OS's ([`getrandom`]), never derived from chain state: a
//! draw derivable from public state is a draw `P` can predict.

use shekyl_types::PCanonicalId;

use crate::facts::Holder;

/// Why a draw produced nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DrawFault {
    /// The OS entropy source failed. Not retried here: a requester without
    /// entropy has a bigger problem than this read.
    #[error("OS entropy unavailable for the holder draw")]
    Entropy,
}

/// One need's urn of holders not yet tried.
pub(crate) struct Urn {
    remaining: Vec<Holder>,
}

impl Urn {
    pub(crate) fn new(holders: Vec<Holder>) -> Self {
        Self { remaining: holders }
    }

    /// Holders not yet drawn.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.remaining.len()
    }

    /// Draw one holder uniformly from those remaining, removing it. `None`
    /// once the urn is empty.
    pub(crate) fn draw(&mut self) -> Result<Option<Holder>, DrawFault> {
        let n = self.remaining.len();
        if n == 0 {
            return Ok(None);
        }
        let index = uniform_below(n)?;
        Ok(Some(self.remaining.swap_remove(index)))
    }

    /// Remove a specific holder, if present. Used when the caller has
    /// already been assigned a `P` and must not draw it twice.
    pub(crate) fn exclude(&mut self, id: PCanonicalId) {
        self.remaining.retain(|h| h.id != id);
    }
}

/// A uniform index in `0..n`, by rejection sampling over a `u64`: the
/// largest multiple of `n` below `2^64` is the acceptance bound, so no
/// residue class is favoured. `n` is a holder count — small — so the
/// expected number of rejections is far below one.
fn uniform_below(n: usize) -> Result<usize, DrawFault> {
    debug_assert!(n > 0);
    let n64 = u64::try_from(n).expect("a holder count fits u64");
    let bound = u64::MAX - (u64::MAX % n64);
    loop {
        let mut raw = [0u8; 8];
        getrandom::getrandom(&mut raw).map_err(|_| DrawFault::Entropy)?;
        let value = u64::from_le_bytes(raw);
        if value < bound {
            return Ok(usize::try_from(value % n64).expect("below a usize bound"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_below_stays_in_range() {
        for n in 1..=17 {
            for _ in 0..200 {
                assert!(uniform_below(n).unwrap() < n);
            }
        }
    }

    #[test]
    fn uniform_below_one_is_always_zero() {
        for _ in 0..50 {
            assert_eq!(uniform_below(1).unwrap(), 0);
        }
    }
}
