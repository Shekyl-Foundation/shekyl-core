// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Instant ± span algebra for the block axis.
//!
//! [`BlockHeight`] (ordinal) and [`ChainCount`] (count) are different
//! quantities. Their arithmetic against a [`BlockCount`] span is the same
//! `Instant`/`Duration` shape, so it is defined once. Adding two instants
//! does not compile. Subtracting two instants of the same kind yields a
//! span. Mixing height and count does not compile.
//!
//! [`ChainCount`]'s named bridges to [`BlockHeight`] live here beside that
//! algebra: [`ChainCount::tip`], [`ChainCount::next_height`], and
//! [`ChainCount::from_next_height`]. `from_raw` / `to_raw` remain the
//! decode/encode edge, not a quantity bridge.

use core::ops::{Add, Sub};

use crate::{BlockCount, BlockHeight, ChainCount};

/// One Instant/Duration family for a block-axis instant.
///
/// `$floor` is the English name of the zero instant ("genesis" /
/// "empty"), used in rustdoc and in the panicking `Sub<BlockCount>`
/// message. Panic strings stay type-prefixed so a test can match them.
macro_rules! instant_span_ops {
    ($instant:ident, $floor:literal) => {
        impl $instant {
            /// Advance by a span, returning `None` on overflow.
            #[must_use]
            pub const fn checked_add(self, rhs: BlockCount) -> Option<$instant> {
                match self.0.checked_add(rhs.0) {
                    Some(v) => Some($instant(v)),
                    None => None,
                }
            }

            /// Advance by a span, saturating at `u64::MAX`.
            #[must_use]
            pub const fn saturating_add(self, rhs: BlockCount) -> $instant {
                $instant(self.0.saturating_add(rhs.0))
            }

            /// The span back to an earlier instant, returning `None` if
            /// `earlier` is actually ahead of `self`.
            #[must_use]
            pub const fn checked_sub(self, earlier: $instant) -> Option<BlockCount> {
                match self.0.checked_sub(earlier.0) {
                    Some(v) => Some(BlockCount(v)),
                    None => None,
                }
            }

            /// The span back to an earlier instant, saturating to
            /// [`BlockCount::ZERO`] when `earlier` is ahead of `self`.
            #[must_use]
            pub const fn saturating_sub(self, earlier: $instant) -> BlockCount {
                BlockCount(self.0.saturating_sub(earlier.0))
            }

            /// Rewind by a span, saturating at the floor rather than panicking.
            ///
            /// [`Sub<BlockCount>`](core::ops::Sub) panics below the floor;
            /// a reorg window on a young chain needs one.
            #[must_use]
            pub const fn saturating_sub_count(self, rhs: BlockCount) -> $instant {
                $instant(self.0.saturating_sub(rhs.0))
            }

            /// Rewind by a span, returning `None` if the span is larger
            /// than the instant.
            #[must_use]
            pub const fn checked_sub_count(self, rhs: BlockCount) -> Option<$instant> {
                match self.0.checked_sub(rhs.0) {
                    Some(v) => Some($instant(v)),
                    None => None,
                }
            }
        }

        impl Add<BlockCount> for $instant {
            type Output = $instant;

            /// Grow by a span. Panics on `u64` overflow.
            fn add(self, rhs: BlockCount) -> $instant {
                $instant(self.0.checked_add(rhs.0).expect(concat!(
                    stringify!($instant),
                    " + BlockCount overflowed u64"
                )))
            }
        }

        impl Sub<BlockCount> for $instant {
            type Output = $instant;

            /// Shrink by a span. Panics if the span is larger than the
            /// instant (would underflow below the floor).
            fn sub(self, rhs: BlockCount) -> $instant {
                $instant(self.0.checked_sub(rhs.0).expect(concat!(
                    stringify!($instant),
                    " - BlockCount underflowed below ",
                    $floor
                )))
            }
        }

        impl Sub<$instant> for $instant {
            type Output = BlockCount;

            /// The span between two instants. Panics if `rhs > self`; use
            /// [`saturating_sub`](Self::saturating_sub) when `rhs` may be
            /// ahead.
            fn sub(self, rhs: $instant) -> BlockCount {
                BlockCount(self.0.checked_sub(rhs.0).expect(concat!(
                    stringify!($instant),
                    " - ",
                    stringify!($instant),
                    " underflowed (rhs ahead of self)"
                )))
            }
        }
    };
}

instant_span_ops!(BlockHeight, "genesis");
instant_span_ops!(ChainCount, "empty");

impl Add<BlockCount> for BlockCount {
    type Output = BlockCount;

    /// Sum two spans. Panics on `u64` overflow.
    fn add(self, rhs: BlockCount) -> BlockCount {
        BlockCount(
            self.0
                .checked_add(rhs.0)
                .expect("BlockCount + BlockCount overflowed u64"),
        )
    }
}

impl BlockCount {
    /// A one-block span. Consecutive-height and drain-cutoff arithmetic
    /// uses this instead of punching through to `u64`.
    pub const ONE: Self = Self(1);
}

impl ChainCount {
    /// The newest existing block's height (`count − 1`), or `None` on an
    /// empty chain. The spendability / reference-anchoring operand.
    #[must_use]
    pub const fn tip(self) -> Option<BlockHeight> {
        match self.0.checked_sub(1) {
            Some(v) => Some(BlockHeight(v)),
            None => None,
        }
    }

    /// The height the **next** block will carry — numerically the count
    /// itself, typed as the instant it will become. The earliest-inclusion
    /// operand (a tx assembled now lands at this height at the soonest).
    ///
    /// Also the exclusive ordinal end of a half-open scan over this many
    /// blocks (`0 .. count`).
    #[must_use]
    pub const fn next_height(self) -> BlockHeight {
        BlockHeight(self.0)
    }

    /// Inverse of [`Self::next_height`]: the count of a chain whose next
    /// block would carry `h`.
    ///
    /// This is C6's inverse — exclusive-end ordinal as count — not "this
    /// existing block's height, laundered." An ordinal of a block that
    /// already exists is [`BlockHeight`]; converting *that* here names a
    /// shorter chain.
    #[must_use]
    pub const fn from_next_height(h: BlockHeight) -> ChainCount {
        ChainCount(h.0)
    }
}
