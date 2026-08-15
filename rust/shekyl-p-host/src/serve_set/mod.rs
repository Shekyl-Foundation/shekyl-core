// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The serve-set: which shards this persona is bonded to answer for, where
//! that list is allowed to come from, and the pin that must succeed before
//! any of them is served.
//!
//! `ARCHIVAL_CHALLENGE_MECHANISM.md` §9.6 item 4 names the hazard this
//! module exists to close: nothing structural binds `held_shard_ids` in the
//! **consensus** bond record to local `pin_segment` state, so a `P` that
//! posts holdings and forgets to pin has *its own node* prune the leaf bytes
//! it is obligated to serve — and then fails challenges, and then slashes,
//! an epoch later, for a local bookkeeping mismatch. The failure is silent
//! all the way to the slash, which is what makes a runtime check the wrong
//! shape of defense.
//!
//! Two obligation shapes ride the one seam (`COMPLETETREE_ACTIVATION.md`
//! D-1): explicit holdings pin per member, exactly as SH-2 built it; the
//! Foundation **CompleteTree prefix** — the whole frozen corpus,
//! `[0, frozen_count)` — carries no per-member pins at all, because the
//! store's one-way prune-disabled posture makes the bad state
//! unrepresentable instead of pinned-against. Same hazard, two closures:
//! the list arm's witness checks pin rows, the prefix arm's checks the
//! posture declaration.

mod report;
mod set;
mod staleness;
mod witness;

pub use report::{PinError, PinReport, ReportedSet, ServeSetPinner};
pub use set::{ServeObligation, ServeSet};
pub use staleness::{Staleness, StalenessBound};
pub use witness::PinnedServeSet;
