// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Foundational **state-shaped** domain newtypes shared across the Shekyl
//! wallet and consensus stack.
//!
//! These are the identity, position, and clock types that `wallet2.cpp`
//! carried as interchangeable raw `u64` / `[u8; 32]` scalars, lifted into
//! distinct types so the compiler rejects the confusions that a KAT would
//! otherwise have to catch later: a block hash passed where a tx hash is
//! expected, a wall-clock timestamp subtracted from a block height, an
//! in-transaction output index used as a ledger-wide global index.
//!
//! This crate is the canonical home for these types per
//! `18-type-placement.mdc` (state-shaped types live with a foundational
//! semantic owner, not in `shekyl-curve-tree` where some predecessors
//! incidentally landed). It is the PR-0 deliverable of
//! `docs/design/RAW_TYPE_NEWTYPE_MIGRATION.md`; downstream crates re-export
//! or import from here rather than redefining.
//!
//! ## Two clocks, three types
//!
//! Per the 2026-06-14 decision-log entry "Time fields: block-height vs
//! wall-clock dichotomy":
//!
//! - [`BlockHeight`] — an **absolute chain instant**. Consensus- and
//!   on-chain-evaluated deadlines (maturity, spend eligibility, stake-claim
//!   windows) live here.
//! - [`BlockCount`] — a **relative block span** (à la `Duration` vs
//!   `Instant`). [`BlockHeight`] arithmetic is expressed against it.
//! - [`Timestamp`] — **wall-clock Unix seconds, UTC**. Off-chain,
//!   human-facing, cross-party, or wallet-local-audit deadlines live here.
//!
//! The three are distinct types: `height + count` yields a height,
//! `height - height` yields a count, and `height + height` /
//! `height - timestamp` do not compile.
//!
//! ## Boundaries
//!
//! Inner fields are private. Conversion is through the named edge
//! constructors/accessors ([`BlockHeight::from_raw`] / [`BlockHeight::to_raw`],
//! [`TxHash::from_bytes`] / [`TxHash::to_bytes`]), so the conversion call
//! sites are the greppable edge set that bounds each migration — the same
//! discipline `AtomicUnits` uses. `#[serde(transparent)]` +
//! `#[repr(transparent)]` keep every type wire- and ABI-identical to the
//! primitive it wraps, so adopting one in a persisted field requires no
//! serialized-format version bump (it may still require a `postcard-schema`
//! snapshot regeneration; see `42-serialization-policy.mdc`).

#![deny(unsafe_code)]

use core::fmt;
use core::ops::{Add, Sub};

/// Defines a `u64`-backed, transparent domain newtype with the common edge
/// surface (`ZERO`, `from_raw`, `to_raw`, `is_zero`). Arithmetic algebra
/// (for the height/count pair) is added in dedicated impl blocks below.
macro_rules! scalar_u64 {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(
            Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default,
            ::serde::Serialize, ::serde::Deserialize,
        )]
        #[cfg_attr(feature = "schema", derive(::postcard_schema::Schema))]
        #[serde(transparent)]
        #[repr(transparent)]
        pub struct $name(u64);

        impl $name {
            #[doc = concat!("The zero ", stringify!($name), ".")]
            pub const ZERO: Self = $name(0);

            /// Wrap a raw `u64`. An *edge* constructor — use it only where a
            /// value crosses into the typed domain (FFI, RPC decode, the
            /// `shekyl-oxide` fork, deserialization helpers).
            #[must_use]
            pub const fn from_raw(value: u64) -> Self {
                $name(value)
            }

            /// Unwrap to the raw `u64`. An *edge* accessor — use it only
            /// where a value crosses back out to a `u64`-typed boundary.
            #[must_use]
            pub const fn to_raw(self) -> u64 {
                self.0
            }

            /// Whether this is the zero value.
            #[must_use]
            pub const fn is_zero(self) -> bool {
                self.0 == 0
            }
        }
    };
}

/// Defines a `[u8; 32]`-backed, transparent identity-hash newtype with
/// `from_bytes` / `to_bytes` / `as_bytes` and a lowercase-hex `Display`.
macro_rules! hash32 {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(
            Clone, Copy, PartialEq, Eq, Hash,
            ::serde::Serialize, ::serde::Deserialize,
        )]
        #[cfg_attr(feature = "schema", derive(::postcard_schema::Schema))]
        #[serde(transparent)]
        #[repr(transparent)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Wrap raw bytes. An *edge* constructor.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                $name(bytes)
            }

            /// Unwrap to the raw bytes. An *edge* accessor.
            #[must_use]
            pub const fn to_bytes(self) -> [u8; 32] {
                self.0
            }

            /// Borrow the raw bytes (e.g. for a hash input or a map key).
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // Delegate to the hex `Display` rather than dumping the raw
                // byte array; `debug_tuple().field(...)` keeps the single
                // field represented so `missing_fields_in_debug` is satisfied.
                f.debug_tuple(stringify!($name))
                    .field(&format_args!("{self}"))
                    .finish()
            }
        }
    };
}

scalar_u64! {
    /// An absolute block height on the Shekyl chain.
    ///
    /// The canonical "chain instant." Arithmetic is expressed against
    /// [`BlockCount`] (a span), never against another `BlockHeight` directly
    /// for addition — `height + height` is meaningless and does not compile.
    BlockHeight
}

scalar_u64! {
    /// A relative span of blocks (a *duration*, not an instant).
    ///
    /// `StakeTier.lock_blocks` and reorg-window depths are [`BlockCount`]s,
    /// not [`BlockHeight`]s. The distinction mirrors `Duration` vs `Instant`.
    BlockCount
}

scalar_u64! {
    /// Wall-clock time as Unix seconds since the epoch, UTC.
    ///
    /// Used for off-chain, human-facing, cross-party, or wallet-local-audit
    /// deadlines (invoice expiry, multisig-proposal TTL, address provenance)
    /// — *not* for any consensus- or chain-evaluated deadline, which is a
    /// [`BlockHeight`].
    Timestamp
}

scalar_u64! {
    /// A ledger-wide global output index (the daemon's `next_output_seq`
    /// counter), assigned densely to every output in drain order.
    ///
    /// Canonical replacement for the historical `shekyl-curve-tree::Gindex`.
    /// Distinct from [`OutputIndexInTx`]: this is the chain-wide position, not
    /// the position within a single transaction's output vector.
    GlobalOutputIndex
}

scalar_u64! {
    /// The position of an output within its own transaction's output vector.
    ///
    /// May be sparse (outputs can be absent/burned). Distinct from
    /// [`GlobalOutputIndex`], which is the dense chain-wide position; mixing
    /// the two is the confusion this type exists to prevent.
    OutputIndexInTx
}

hash32! {
    /// A block identity hash.
    ///
    /// Distinct from [`TxHash`] and from a curve-tree root: a block hash can
    /// never be passed where a transaction hash is expected.
    BlockHash
}

hash32! {
    /// A transaction identity hash (txid).
    ///
    /// Distinct from [`BlockHash`]. Canonical replacement for the ad-hoc
    /// `TxHash([u8; 32])` previously defined in `shekyl-engine-core`.
    TxHash
}

// ── BlockHeight ↔ BlockCount algebra ────────────────────────────────────────
//
// All arithmetic is checked: with `overflow-checks = true` across every
// profile (see the workspace manifest), an unchecked `+`/`-` would already
// panic, but the explicit `.expect(...)` names the condition. Callers that
// must *handle* the boundary use the `checked_*` / `saturating_*` methods.

impl Add<BlockCount> for BlockHeight {
    type Output = BlockHeight;

    /// Advance a height by a span. Panics on `u64` overflow (unreachable in
    /// practice; a `2^64`-block chain does not exist).
    fn add(self, rhs: BlockCount) -> BlockHeight {
        BlockHeight(
            self.0
                .checked_add(rhs.0)
                .expect("BlockHeight + BlockCount overflowed u64"),
        )
    }
}

impl Sub<BlockCount> for BlockHeight {
    type Output = BlockHeight;

    /// Rewind a height by a span (e.g. a reorg-window floor). Panics if the
    /// span is larger than the height (would underflow below genesis).
    fn sub(self, rhs: BlockCount) -> BlockHeight {
        BlockHeight(
            self.0
                .checked_sub(rhs.0)
                .expect("BlockHeight - BlockCount underflowed below genesis"),
        )
    }
}

impl Sub<BlockHeight> for BlockHeight {
    type Output = BlockCount;

    /// The span between two heights. Panics if `rhs > self`; use
    /// [`BlockHeight::saturating_sub`] when `rhs` may be ahead.
    fn sub(self, rhs: BlockHeight) -> BlockCount {
        BlockCount(
            self.0
                .checked_sub(rhs.0)
                .expect("BlockHeight - BlockHeight underflowed (rhs ahead of self)"),
        )
    }
}

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

impl BlockHeight {
    /// Advance by a span, returning `None` on overflow.
    #[must_use]
    pub const fn checked_add(self, rhs: BlockCount) -> Option<BlockHeight> {
        match self.0.checked_add(rhs.0) {
            Some(v) => Some(BlockHeight(v)),
            None => None,
        }
    }

    /// The span back to an earlier height, returning `None` if `earlier` is
    /// actually ahead of `self`.
    #[must_use]
    pub const fn checked_sub(self, earlier: BlockHeight) -> Option<BlockCount> {
        match self.0.checked_sub(earlier.0) {
            Some(v) => Some(BlockCount(v)),
            None => None,
        }
    }

    /// The span back to an earlier height, saturating to
    /// [`BlockCount::ZERO`] when `earlier` is ahead of `self`.
    #[must_use]
    pub const fn saturating_sub(self, earlier: BlockHeight) -> BlockCount {
        BlockCount(self.0.saturating_sub(earlier.0))
    }
}

impl Timestamp {
    /// Whole seconds elapsed since an earlier instant, returning `None` if
    /// `earlier` is actually ahead of `self` (a clock that went backwards).
    #[must_use]
    pub const fn checked_secs_since(self, earlier: Timestamp) -> Option<u64> {
        self.0.checked_sub(earlier.0)
    }
}

#[cfg(test)]
mod tests;
