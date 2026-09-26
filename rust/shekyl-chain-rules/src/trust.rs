// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What this node takes on the release's word — `validate`'s fourth input,
//! orthogonal to `RuleSet` (`PDM-Q5`, `PDM-Q-F27`; `CHAIN_RULES_SLICE_3.md`
//! §4.1, Q1 as ruled).
//!
//! A rule set says what the chain's rules *are*; a [`Trust`] says how much
//! of the chain *this node* verifies for itself and what it takes from the
//! binary instead. Today that is one thing — the release-carried
//! [`ReleaseAnchors`] (CEN-E1 reads them per block). From slice 6 it is
//! two: the anchors, and the **posture** — `Full`, or `BelowAnchor(anchor)`,
//! under which the proof rows (4.I) are not run for a block in band 1 and
//! their absence is recorded in coverage and in `connect`'s provenance, so
//! a band-1 file is never parity evidence. `BelowAnchor`'s meaning is
//! already ruled, not slice 6's to derive: `PDM-Q5` `:293` — *"`≤ C`
//! skeleton, trusted with the binary"* — band 1's skeleton, not an ad-hoc
//! skip list; and it is mintable only from the table's current anchor
//! (`F27`), so `D_max` never has to defend a node below its anchor. That
//! anchor is a **checkpoint, at height `≥ 1`** — never genesis, which the
//! binary defines rather than trusts and which sits in no band
//! (`CHAIN_RULES_SLICE_4.md` Q3, the PDM lane's answer 2026-09-22). So
//! `assumevalid = 0`, the first release's setting (`PDM :304`), has one
//! constructible meaning: `Full` — [`ReleaseAnchors::current`] is `None`
//! and there is nothing for `below_anchor` to be minted from.
//!
//! # Why a separate input
//!
//! - **Not on `RuleSet`.** An anchor addition is a *release*; a rule-set
//!   change is a *hard fork*. And `connect` compares the verdict's rule set
//!   with the one in force **by value** (`connect.rs`, RD-Q10): a table on
//!   the set would be refused whenever the driver's copy differed, or would
//!   have to be carved out of the comparison. `PDM-Q5`'s reversion clause
//!   names exactly this check.
//! - **Not on `Substrate`.** That trait is *services with faults* — a clock
//!   that may be unavailable, a VM that may fail (and, since `pin_seed`,
//!   advisory hints to those services). The table is static data with no
//!   failure mode and nothing to serve; a method returning it would make
//!   the trait carry configuration, and its mock in every test would have
//!   to answer with a table it has no reason to hold.
//! - **Not on the `form` token.** `form` is stateless and has no height;
//!   E1 is view-bound. The posture is a per-sync-session choice, not a
//!   property of one block's stateless judgement.
//!
//! The constructors are the seam: [`Trust::full`] is the only one today,
//! `Trust::below_anchor(anchors)` arrives with slice 6, and **no existing
//! caller changes** when it does — which is the retrofit this parameter
//! exists to avoid (`CHAIN_RULES_CRATE.md` §13: *"the signature is one
//! parameter today and every later caller is a retrofit"*).

use crate::anchors::ReleaseAnchors;

/// How much of the chain this node verifies for itself.
///
/// Carries the release's anchors; grows a posture in slice 6. Construct
/// with [`Trust::full`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Trust {
    anchors: ReleaseAnchors,
}

impl Trust {
    /// Verify everything, with nothing pinned — not even a genesis: what a
    /// Fakechain node always is. `Trust::full(ReleaseAnchors::EMPTY)`. A
    /// public-network node is `Trust::full(ReleaseAnchors::for_network(_))`:
    /// its genesis pinned, no anchor (band 1 empty) until the first
    /// checkpoint release.
    pub const UNANCHORED: Self = Self::full(ReleaseAnchors::EMPTY);

    /// Verify everything; consult the table where a rule reads it (CEN-E1
    /// at pinned heights, CEN-E5 at open). What every node does today —
    /// `assumevalid = 0` — and what a Fakechain node does with
    /// [`ReleaseAnchors::EMPTY`].
    #[must_use]
    pub const fn full(anchors: ReleaseAnchors) -> Self {
        Self { anchors }
    }

    /// The release-carried anchors this node trusts.
    #[must_use]
    pub const fn anchors(&self) -> &ReleaseAnchors {
        &self.anchors
    }
}
