// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What feeds the pipeline: a [`Source`] of sequenced [`IngestEvent`]s.
//!
//! # The event model (RD-Q13)
//!
//! Two variants, one ordering rule. A source emits [`IngestEvent::Extend`]
//! (a block with the full bodies of its listed transactions, in header
//! order — what [`Candidate`] consumes) and [`IngestEvent::Rewind`] (pop
//! until the tip is `to`). Every event carries a source-assigned [`Seq`]
//! and the stream is **totally ordered** by it: the sequencer restores that
//! order after parallel formation, and it never reorders across a
//! `Rewind`.
//!
//! **A `Rewind` is a barrier.** Formation of the `Extend`s after it waits
//! for it to commit, because their seed context — the block at
//! `seedheight(h)` on the *post-rewind* chain — depends on it. Who decides
//! a rewind is the source's business (the reorg fixture scripts it; E3's
//! p2p source computes the heavier-chain switch and emits it); the pipeline
//! only executes.
//!
//! # Network-shaped only (RD-Q2)
//!
//! A [`CorpusBlock`] is the block plus its bodies and nothing else. The six
//! passed-through facts (`weight`, `long_term_weight`, `coins_generated`,
//! `burned`, `root_after`, `long_term_effective_median`) do **not** travel
//! on the event: they come through the trace's typed `borrow(h)` door,
//! keyed by height, so a source cannot smuggle an oracle into the
//! validator's input and the grader cannot read a borrowed value as
//! evidence. E3's p2p source has no facts to offer, and the event type
//! says so.

use shekyl_chain_rules::Candidate;
use shekyl_types::BlockHeight;

/// A source-assigned sequence number: the position of an event in the
/// source's total order. Dense from [`Seq::FIRST`]; the sequencer releases
/// `n` only after every `m < n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Seq(u64);

impl Seq {
    /// The first sequence number a source assigns.
    pub const FIRST: Self = Self(0);

    /// The position after this one.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// The raw position, for logs and artifacts.
    #[must_use]
    pub const fn to_raw(self) -> u64 {
        self.0
    }
}

/// A value at a position in the source's order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sequenced<T> {
    /// The position.
    pub seq: Seq,
    /// The value.
    pub item: T,
}

impl<T> Sequenced<T> {
    /// Pair `item` with `seq`.
    #[must_use]
    pub const fn new(seq: Seq, item: T) -> Self {
        Self { seq, item }
    }

    /// The same position, a different value — what a stage does to an event
    /// on its way through.
    #[must_use]
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Sequenced<U> {
        Sequenced {
            seq: self.seq,
            item: f(self.item),
        }
    }
}

/// One block as the network carries it: the block and the full bodies of
/// its listed transactions, in header order (RD-F8). The height it claims
/// is the height the pipeline expects it to connect at; the actor refuses a
/// mismatch as a source defect, never as a verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorpusBlock {
    /// The height this block connects at.
    pub height: BlockHeight,
    /// The block and its bodies — the validator's input, unchanged.
    pub candidate: Candidate,
}

/// What a source emits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngestEvent {
    /// Connect this block at its height. Boxed: a block with its bodies is
    /// hundreds of bytes inline and a `Rewind` is sixteen; the event moves
    /// through channels and the box is one allocation the bodies already
    /// paid for.
    Extend(Box<CorpusBlock>),
    /// Pop until the tip is `to`. A barrier (module docs).
    Rewind {
        /// The height that is the tip after the rewind.
        to: BlockHeight,
    },
}

impl IngestEvent {
    /// Whether this event is a barrier the sequencer must not reorder
    /// across and formation must wait behind.
    #[must_use]
    pub const fn is_barrier(&self) -> bool {
        matches!(self, Self::Rewind { .. })
    }
}

/// A producer of sequenced ingest events: the corpus reader (Extend-only),
/// the mutation family (Extend-only), the reorg family and E3's p2p feed
/// (both kinds).
pub trait Source {
    /// What the source can fail with — a truncated artifact, a refused
    /// prune state, a transport error. Opaque to the pipeline; a source
    /// fault ends the run, it is never a verdict.
    type Fault;

    /// The next event in order, `None` when the source is exhausted.
    ///
    /// # Errors
    ///
    /// The source's own fault.
    fn next(&mut self) -> Result<Option<Sequenced<IngestEvent>>, Self::Fault>;
}
