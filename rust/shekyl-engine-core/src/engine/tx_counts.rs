// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bounded transaction input/output counts for the fee/weight path.
//!
//! [`InputCount`] (`1..=MAX_INPUTS`) and [`OutputCount`] (`1..=MAX_OUTPUTS`) make
//! an out-of-range count *unrepresentable* in the weight predictor. With the
//! counts type-bounded, [`predict_weight`](super::tx_fee_model::predict_weight)
//! and its helpers use plain arithmetic that is provably overflow-free for any
//! representable count — replacing the `saturating_*` products/fold and the
//! `padded_outputs` clamp that #179 added to fail-safe against raw `usize`
//! counts arriving uncapped from the fee context.
//!
//! The bounds are the consensus limits re-exported by `shekyl-tx-builder`
//! (`MAX_INPUTS` originates in `shekyl-fcmp`; `MAX_OUTPUTS` mirrors the
//! `shekyl-wire` consensus limit). Counts reach this path from coin selection
//! (`SelectedOutputs::indices.len()`, already `<= MAX_INPUTS`) and the request's
//! recipient count, plus a speculative `+1` for the with-change variant that can
//! legitimately reach `MAX_OUTPUTS + 1` (an unbuildable variant the orchestrator
//! discards). [`clamped`](OutputCount::clamped) therefore caps into range —
//! matching the prior clamp/saturate behaviour exactly for any valid tx, while
//! an oversize request still fails at build validation rather than here.

use shekyl_tx_builder::{MAX_INPUTS, MAX_OUTPUTS};

macro_rules! bounded_count {
    ($name:ident, $max:expr, $what:literal) => {
        #[doc = concat!("Transaction ", $what, " count, bounded to `1..=", stringify!($max), "`.")]
        ///
        /// Constructed via [`Self::clamped`] at the fee-path boundary; the bound
        /// is a type invariant, so consumers do plain (overflow-free) arithmetic.
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
        pub struct $name(usize);

        impl $name {
            /// Wrap a raw count, clamping into `1..=MAX`. An out-of-range value
            /// caps at the bound (the prior clamp/saturate behaviour): a valid tx
            /// is exact, and an oversize request still fails at build validation,
            /// so the predictor never sees a value that could overflow.
            #[must_use]
            pub fn clamped(n: usize) -> Self {
                Self(n.clamp(1, $max))
            }

            /// The count as a `usize`, guaranteed in `1..=MAX`.
            #[must_use]
            pub const fn get(self) -> usize {
                self.0
            }
        }
    };
}

bounded_count!(InputCount, MAX_INPUTS, "input");
bounded_count!(OutputCount, MAX_OUTPUTS, "output");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_into_range() {
        assert_eq!(InputCount::clamped(0).get(), 1, "zero clamps up to 1");
        assert_eq!(InputCount::clamped(3).get(), 3, "in-range is exact");
        assert_eq!(
            InputCount::clamped(MAX_INPUTS).get(),
            MAX_INPUTS,
            "MAX is exact"
        );
        assert_eq!(
            InputCount::clamped(MAX_INPUTS + 5).get(),
            MAX_INPUTS,
            "oversize caps at MAX_INPUTS"
        );
        assert_eq!(
            InputCount::clamped(usize::MAX).get(),
            MAX_INPUTS,
            "usize::MAX caps"
        );

        assert_eq!(OutputCount::clamped(0).get(), 1);
        assert_eq!(OutputCount::clamped(MAX_OUTPUTS).get(), MAX_OUTPUTS);
        assert_eq!(
            OutputCount::clamped(MAX_OUTPUTS + 1).get(),
            MAX_OUTPUTS,
            "with-change +1 over the limit caps at MAX_OUTPUTS"
        );
    }
}
