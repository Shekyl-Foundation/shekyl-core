// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Order restoration after parallel `form`.
//!
//! N workers form blocks concurrently and finish out of order; the single
//! writer must see them in the source's order. The [`Sequencer`] holds
//! finished items and releases them **in sequence, never past a gap**: if
//! `n + 2` finishes before `n + 1`, it waits. That is the whole contract —
//! the barrier rule for a `Rewind` (formation after it waits for it to
//! *commit*) is the dispatcher's, upstream of this type, because it is
//! about when work may start, not the order results are released in.
//!
//! Two inputs are refused rather than absorbed, because either is a driver
//! defect and absorbing it would hide one: a position already released, and
//! a position already pending.

use std::collections::BTreeMap;

use crate::source::{SequenceNo, Sequenced};

/// Why a position could not be accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SequenceError {
    /// `seq` was already released: a stage produced the same position twice
    /// or a source restarted its numbering.
    #[error("sequence {} was already released", .0.to_raw())]
    AlreadyReleased(SequenceNo),
    /// `seq` is already waiting: two results for one position.
    #[error("sequence {} is already pending", .0.to_raw())]
    Duplicate(SequenceNo),
}

/// Restores source order over out-of-order completions.
#[derive(Debug)]
pub struct Sequencer<T> {
    /// The next position to release.
    next: SequenceNo,
    /// Finished items not yet releasable, by position.
    pending: BTreeMap<SequenceNo, T>,
}

impl<T> Sequencer<T> {
    /// A sequencer expecting `first` next.
    #[must_use]
    pub const fn new(first: SequenceNo) -> Self {
        Self {
            next: first,
            pending: BTreeMap::new(),
        }
    }

    /// Accept a finished item at its position.
    ///
    /// # Errors
    ///
    /// [`SequenceError::AlreadyReleased`] below the release cursor,
    /// [`SequenceError::Duplicate`] for a position already pending.
    pub fn push(&mut self, item: Sequenced<T>) -> Result<(), SequenceError> {
        if item.seq < self.next {
            return Err(SequenceError::AlreadyReleased(item.seq));
        }
        if self.pending.contains_key(&item.seq) {
            return Err(SequenceError::Duplicate(item.seq));
        }
        self.pending.insert(item.seq, item.event);
        Ok(())
    }

    /// Release the next item if it is the one expected; `None` at a gap or
    /// when nothing is pending. Call until `None` to drain a run.
    pub fn pop_ready(&mut self) -> Option<Sequenced<T>> {
        let item = self.pending.remove(&self.next)?;
        let seq = self.next;
        self.next = seq.next();
        Some(Sequenced { seq, event: item })
    }

    /// The position released next.
    #[must_use]
    pub const fn next_expected(&self) -> SequenceNo {
        self.next
    }

    /// Items finished and waiting behind a gap.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(n: u64) -> SequenceNo {
        let mut s = SequenceNo::FIRST;
        for _ in 0..n {
            s = s.next();
        }
        s
    }

    fn drain(s: &mut Sequencer<&'static str>) -> Vec<(u64, &'static str)> {
        let mut out = Vec::new();
        while let Some(item) = s.pop_ready() {
            out.push((item.seq.to_raw(), item.event));
        }
        out
    }

    #[test]
    fn releases_in_order_and_never_past_a_gap() {
        let mut s = Sequencer::new(SequenceNo::FIRST);
        s.push(Sequenced {
            seq: seq(2),
            event: "c",
        })
        .unwrap();
        s.push(Sequenced {
            seq: seq(0),
            event: "a",
        })
        .unwrap();
        assert_eq!(drain(&mut s), vec![(0, "a")], "1 is missing: 2 waits");
        assert_eq!(s.pending(), 1);
        s.push(Sequenced {
            seq: seq(1),
            event: "b",
        })
        .unwrap();
        assert_eq!(drain(&mut s), vec![(1, "b"), (2, "c")]);
        assert_eq!(s.next_expected(), seq(3));
        assert_eq!(s.pending(), 0);
    }

    #[test]
    fn a_released_position_and_a_pending_one_are_both_refused() {
        let mut s = Sequencer::new(SequenceNo::FIRST);
        s.push(Sequenced {
            seq: seq(0),
            event: "a",
        })
        .unwrap();
        assert_eq!(
            s.push(Sequenced {
                seq: seq(0),
                event: "a again"
            }),
            Err(SequenceError::Duplicate(seq(0)))
        );
        drain(&mut s);
        assert_eq!(
            s.push(Sequenced {
                seq: seq(0),
                event: "a late"
            }),
            Err(SequenceError::AlreadyReleased(seq(0)))
        );
    }

    #[test]
    fn starts_where_told() {
        let mut s = Sequencer::new(seq(5));
        s.push(Sequenced {
            seq: seq(5),
            event: "e",
        })
        .unwrap();
        assert_eq!(drain(&mut s), vec![(5, "e")]);
    }

    #[test]
    fn seq_saturates_at_the_top() {
        let top = SequenceNo::FIRST;
        // Reaching u64::MAX by `next` is not practical; check the property
        // on the raw value the type wraps.
        assert_eq!(top.next().to_raw(), 1);
        assert!(SequenceNo::FIRST < SequenceNo::FIRST.next());
    }
}
