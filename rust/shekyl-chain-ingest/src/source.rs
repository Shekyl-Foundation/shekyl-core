// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Where blocks come from, as an ordered event stream (RD-Q13).
//!
//! A height-ordered stream of blocks cannot represent a reorg: the pipeline
//! would have no way to say *pop*. So a source yields [`IngestEvent`]s —
//! `Extend` with a candidate, or `Rewind { to }` — each stamped with a
//! [`SequenceNo`] the source assigns, and the pipeline's contract is stated
//! against that number:
//!
//! - The **Sequencer** restores sequence order after parallel formation and
//!   **never reorders across a `Rewind`**: a `Rewind` is a barrier. Formation
//!   of the `Extend`s after it waits for it to commit, because their seed
//!   context (CEN-D3) depends on the post-rewind chain.
//! - The **actor** executes `Rewind { to }` as `pop` until the tip is `to`,
//!   then connects the `Extend`s at `to + 1…`.
//! - The **digest sink** records after each `Rewind` commit — the "digest
//!   after each switch" the reorg fixture family needs.
//!
//! Who *decides* a rewind is the source's business: the reorg fixture scripts
//! it; E3's p2p source computes the heavier-chain switch (the daemon's
//! alt-chain logic) and emits it. The pipeline only executes.
//!
//! The corpus source (E2's first) and the mutation family are Extend-only;
//! the reorg family and E3's feed emit `Rewind`.

use shekyl_chain_rules::Candidate;
use shekyl_types::BlockHeight;

/// A source-assigned position in its event stream. Total order; the
/// sequencer restores it after parallel formation.
///
/// Not a height: two `Extend`s at the same height (before and after a
/// `Rewind`) have different sequence numbers, and a `Rewind` has one too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SequenceNo(u64);

impl SequenceNo {
    /// The first event a source emits.
    pub const FIRST: Self = Self(0);

    /// The next position. Sequence numbers strictly increase: exhaustion of
    /// the `u64` space panics rather than wrapping (a restart from zero) or
    /// saturating (two events sharing a number).
    #[must_use]
    pub const fn next(self) -> Self {
        Self(
            self.0
                .checked_add(1)
                .expect("ingest sequence space exhausted"),
        )
    }

    /// The raw position, for logs and artifacts.
    #[must_use]
    pub const fn to_raw(self) -> u64 {
        self.0
    }
}

/// One event a [`Source`] emits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngestEvent {
    /// Connect this candidate at the tip. The candidate carries its block
    /// and the **full bodies** of its listed transactions in header order —
    /// what the validator consumes (`Candidate`, RD-F8); a corpus source
    /// verified count, order and hash against the header before emitting
    /// it (RD-F15). Boxed: a candidate carries whole bodies and travels
    /// through the stage channels; the variant stays one pointer wide.
    Extend(Box<Candidate>),
    /// Pop until the tip is `to`. The `Extend`s that follow connect at
    /// `to + 1…` and are formed against the post-rewind chain.
    Rewind {
        /// The height the tip must be at when the rewind has committed.
        to: BlockHeight,
    },
}

impl IngestEvent {
    /// Whether the sequencer may reorder formation across this event.
    /// `true` exactly for a `Rewind`: it is a barrier. Exhaustive so a
    /// third variant is a compile error, not a silent non-barrier.
    #[must_use]
    pub const fn is_barrier(&self) -> bool {
        match self {
            Self::Rewind { .. } => true,
            Self::Extend(_) => false,
        }
    }
}

/// An event at its position in the stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sequenced<T> {
    /// The source's position for this event.
    pub seq: SequenceNo,
    /// The event.
    pub event: T,
}

/// A supplier of ordered ingest events.
///
/// Implemented by the corpus reader (E2), the mutation and reorg fixture
/// families, and E3's p2p feed. A source is pulled, not pushed: the
/// pipeline asks for the next event when it has room, so back-pressure is
/// the caller's `next` cadence and no channel is hidden inside the trait.
pub trait Source {
    /// Why the source could not produce its next event: an unreadable
    /// artifact, a refused corpus height, a closed feed. Opaque to the
    /// pipeline, which surfaces it and ends the run — never a verdict.
    type Fault;

    /// The next event, `Ok(None)` when the stream is exhausted. Sequence
    /// numbers strictly increase across the `Some`s a source yields.
    ///
    /// # Errors
    ///
    /// The source's own [`Self::Fault`].
    fn next(&mut self) -> Result<Option<Sequenced<IngestEvent>>, Self::Fault>;
}

#[cfg(test)]
#[path = "source_tests.rs"]
mod source_tests;
