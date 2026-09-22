// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! Peer-attribution policy — PWD-B7 of `docs/design/SHEKYL_P2P_PROTOCOL.md`.
//!
//! # The rule this crate exists to make unbreakable
//!
//! > Drop the peer only when the rejection is *attributable to the sender's
//! > choice*. That requires two things together — the rejection must describe
//! > the INPUT rather than our own state, *and* the rule it fails must be
//! > UNIVERSAL rather than local policy.
//!
//! # Why this is a type and not a `bool`
//!
//! The mechanism this replaces was `bool m_no_drop_offense`: a carve-out list
//! whose *absence* meant "droppable". That default is the defect. Absence does
//! not identify *form* — it identifies everything that is not one of the four
//! carve-outs, and that set includes **our own failures**. A pool-bookkeeping
//! invariant tripping, or a storage exception, returned with the flag unset and
//! severed an innocent peer: our own storage throwing partitioned us from the
//! network.
//!
//! So the surface is affirmative and tri-state, and the *unset* arm — along
//! with any byte a future writer has not taught this crate about — resolves to
//! [`DropVerdict::Unclassified`], which does not sever. The asymmetry is
//! deliberate and is the whole reason the default points this way:
//!
//! - Mis-classifying a form failure as internal keeps **one** hostile
//!   connection alive, which PWD-B1's token bucket is what charges.
//! - The opposite default partitions the network on **our own bugs**.
//!
//! A drop rule doing rate limiting's job is what severs honest peers, so the
//! two are kept apart: this crate answers *"may we sever?"*, never *"is this
//! peer expensive?"*.
//!
//! # Why the crate boundary is here
//!
//! Not `shekyl-relay`: that crate's charter is the live relay *scheduler*, and
//! its own module docs argue that charter erosion is the failure mode worth
//! guarding against. Not `shekyl-consensus`: attributability is explicitly
//! *not* a consensus question — two of the four original carve-outs are
//! relay-tier policy that honest nodes may legitimately disagree on, and
//! treating them as consensus is precisely the error that would fracture the
//! network along configuration lines.
//!
//! The same boundary owns the block twin: [`BlockIngest`] is the outcome,
//! [`DropVerdict`] on a separate slot is still the drop, and
//! [`BlockAnnounceAction`] / [`BlockSyncAction`] are what P2P does with
//! those two slots. C++ writes through named constructors and asks
//! predicates. It never switches on a classification byte, and it does not
//! compose "record outcome then classify drop" — that pairing lives here.

mod block_ingest;
mod block_peer;
mod drop_verdict;

pub use block_ingest::BlockIngest;
pub use block_peer::{BlockAnnounceAction, BlockSyncAction};
pub use drop_verdict::DropVerdict;
