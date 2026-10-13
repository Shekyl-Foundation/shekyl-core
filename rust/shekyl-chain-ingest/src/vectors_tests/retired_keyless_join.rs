// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Captured chains whose JoinMarket is the retired keyless form.
//!
//! `FN_DSA_HYBRID.md` `FND-19`: a C++ capture carries `post_kind` 0, which
//! the wire refuses. The corpus reader is sequential, so the replay of such
//! a chain ends at that block. The stop matches
//! [`RetiredKeylessJoinMarket`](shekyl_wire::RetiredKeylessJoinMarket), the
//! type `BondPost::read` returns — not the sentence that type displays.

use shekyl_types::BlockHeight;
use shekyl_wire::RetiredKeylessJoinMarket;

use crate::corpus::CorpusFault;
use crate::source::{IngestEvent, Source};

/// A captured chain that carries a **keyless JoinMarket** (`post_kind` 0),
/// and so can be read only up to that block.
///
/// Retired 2026-10-12 (ruling on PR #1046; `FN_DSA_HYBRID.md` `FND-19`):
/// the receipt key is mandatory, the keyless byte is refused at parse, and
/// these chains were captured from the C++ daemon, whose serializer has no
/// key-carrying JoinMarket — a C++ capture can never contain one, and the
/// wire refuses a keyless one. So for such a chain what is retired is not
/// one comparison but everything from the join's block on: the block does
/// not parse, the corpus reader is sequential, and nothing above it can be
/// connected. Retired with it: the daemon's digest and its `0x04` archival
/// snapshot at the tip (the Bond family among them), and every height's
/// roots, weights and accumulator from `at` upward.
///
/// What still runs, and is still held: every block below `at` connects
/// through `form → validate → connect` against a real store and is compared
/// against the trace at every one of those heights, exactly as before.
///
/// Enumerated, not discovered: the stop is pinned — the height, and that it
/// is this refusal and no other — and a chain that stops anywhere else, or
/// a listed chain that reads whole, fails ([`UntilRetiredJoin::finish`]).
/// A record is deleted the day its chain is re-captured from a daemon that
/// builds key-carrying joins. The corpus files are untouched.
#[derive(Debug)]
pub(crate) struct RetiredKeylessJoin {
    pub(crate) shape: &'static str,
    /// The height of the block that lists the keyless JoinMarket: the first
    /// height that does not connect.
    pub(crate) at: BlockHeight,
}

/// The two captured chains that post a bond. `emission-claim` was a
/// [`super::PREDATES`] record until this date (refused at 98 by CEN-J15):
/// the same block now fails to parse before any rule reads it, so that
/// record could no longer be observed and is replaced by this one.
pub(crate) const RETIRED_KEYLESS_JOINS: [RetiredKeylessJoin; 2] = [
    RetiredKeylessJoin {
        shape: "bond-post",
        at: BlockHeight::from_raw(98),
    },
    RetiredKeylessJoin {
        shape: "emission-claim",
        at: BlockHeight::from_raw(98),
    },
];

/// The record for a captured chain, if it carries a keyless JoinMarket.
pub(crate) fn retired_keyless_join(shape: &str) -> Option<&'static RetiredKeylessJoin> {
    RETIRED_KEYLESS_JOINS.iter().find(|r| r.shape == shape)
}

/// A captured corpus read up to — and not including — the block that lists
/// a retired keyless JoinMarket. That one refusal, and only it, ends the
/// stream as if the corpus ended there; every other fault is passed on.
pub(crate) struct UntilRetiredJoin<S> {
    inner: S,
    stopped_at: Option<BlockHeight>,
}

impl<S> UntilRetiredJoin<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner,
            stopped_at: None,
        }
    }

    /// Hold the stop to the table: a listed chain stopped at its recorded
    /// height, and an unlisted one read whole.
    pub(crate) fn finish(&self, shape: &str) {
        assert_eq!(
            self.stopped_at,
            retired_keyless_join(shape).map(|r| r.at),
            "{shape}: where the corpus stopped for a retired keyless JoinMarket is not what \
             RETIRED_KEYLESS_JOINS records"
        );
    }
}

impl<S: Source<Fault = CorpusFault>> Source for UntilRetiredJoin<S> {
    type Fault = CorpusFault;

    fn first_height(&self) -> BlockHeight {
        self.inner.first_height()
    }

    fn next(&mut self) -> Result<Option<crate::source::Sequenced<IngestEvent>>, CorpusFault> {
        if self.stopped_at.is_some() {
            return Ok(None);
        }
        match self.inner.next() {
            Err(CorpusFault::Malformed {
                height,
                what: "transaction",
                cause,
            }) if cause
                .get_ref()
                .is_some_and(RetiredKeylessJoinMarket::downcast_is) =>
            {
                self.stopped_at = Some(height);
                Ok(None)
            }
            other => other,
        }
    }
}

/// Every captured chain's directory is named for its shape, so a walker
/// that has only the directory holds its stop to the right record.
#[test]
fn every_captured_chain_s_directory_is_its_shape_and_every_retired_record_names_one() {
    let chains = super::captured_chains();
    for (dir, manifest) in &chains {
        assert_eq!(super::shape_of(dir), manifest.shape);
    }
    for record in &RETIRED_KEYLESS_JOINS {
        assert!(
            chains.iter().any(|(_, m)| m.shape == record.shape),
            "RETIRED_KEYLESS_JOINS names `{}`, which is not captured",
            record.shape
        );
        assert!(
            super::predates(record.shape).is_none(),
            "`{}` cannot both stop at a retired join and be refused by a rule above it",
            record.shape
        );
    }
}
