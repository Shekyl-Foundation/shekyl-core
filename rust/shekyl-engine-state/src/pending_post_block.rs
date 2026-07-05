// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! WI-2 D-A4 — [`PendingPostBlock`]: the durable pending bond-post record
//! (`ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.5, discharging SP-T4 §3.1.1 pin P-2).
//!
//! A **sibling sealed block** beside the `.wallet.pscan` seal — deliberately
//! *not* a field inside `PScanState`. The pscan seal is rewritten every sweep
//! batch by the pscan task under its single-flight slot; pending posts are
//! written by the assemble path — a different writer on a different cadence.
//! Two writers racing one read-modify-seal cycle is the bug class the slot
//! exists to prevent, so each seal stays single-writer by construction.
//!
//! ## Persist-before-dispatch (the load-bearing invariant)
//!
//! No transaction bytes reach any submitter unless the sealed record already
//! holds them. The assemble path seals a [`PendingBondPost`] carrying the
//! **exact** bound bytes before returning; WI-3's dispatch driver re-reads
//! them from the seal on every send — including F31/watchdog resubmits, which
//! re-send the *stored* value through the same choke path (pin P-2), never a
//! re-encode.
//!
//! ## Rule-18 note on the bound-bytes twin
//!
//! Engine-core's `PBoundBytes` is the transform-shaped byte↔persona pairing;
//! this block persists its state-shaped twin as `(persona, tx_bytes)` fields.
//! The re-lift into `PBoundBytes` on load happens in engine-core's assemble
//! module (the P-1 provenance boundary) — trusting our own prior seal exactly
//! as `PScanAccrual::from_state` trusts the sealed frontier.

use serde::{Deserialize, Serialize};
use shekyl_types::{BlockHeight, PCanonicalId};

use crate::error::WalletLedgerError;

/// Schema version of the durable pending-post block. **v1** is the WI-2
/// genesis shape: JoinMarket-only, dispatch state [`PendingPostState::Pending`]
/// only (WI-3 adds the dispatched/confirmed arms and bumps this). Any field
/// addition / removal / renaming bumps this; loads that see a different
/// version **refuse rather than migrate** (pre-genesis, a mismatch means
/// re-assemble; rule 15).
pub const PENDING_POST_VERSION: u32 = 1;

/// Dispatch state of a pending bond post. WI-2 writes only
/// [`Self::Pending`]; WI-3's block-timed dispatch driver extends this with
/// its dispatched/confirmed arms (a version-bumping change, by design — the
/// driver owns those semantics, not the assemble path).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub enum PendingPostState {
    /// Assembled and sealed; not yet handed to any submitter.
    Pending,
}

/// One durable pending bond post: the assembled, signed, wire-encoded
/// transaction bytes bound to their persona, the entry-seam placement they
/// were drawn with, and the funding reservation they hold.
///
/// Every field is `P`-side behavioral history (persona, plan offsets, funding
/// placement) — the same class as the pscan state's persona-history rows — so
/// the type carries the redacted-`Debug` discipline (contents *and* count at
/// the block level).
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct PendingBondPost {
    /// The owning persona's slot ordinal.
    pub p_slot: u32,
    /// The persona the transaction bytes are bound to — must match the
    /// binding engine-core's `PBoundBytes` carries when the record is
    /// re-lifted for dispatch.
    pub persona: PCanonicalId,
    /// The fully-assembled, signed, wire-encoded transaction bytes — the
    /// value itself, per pin P-2: retries re-send these stored bytes.
    pub tx_bytes: Vec<u8>,
    /// Blocks from `anchor_t0` to `P`'s observable funding/entry event
    /// (state-shaped twin of `shekyl_standoff::EntrySeamPlan`).
    pub entry_offset_blocks: u64,
    /// Blocks from `anchor_t0` to the bond-post broadcast.
    pub bond_post_offset_blocks: u64,
    /// Tip height at assemble time — the private intent anchor `t0` the
    /// plan's offsets are relative to. WI-3's due-check is pure:
    /// `due = anchor_t0 + bond_post_offset_blocks`.
    pub anchor_t0: BlockHeight,
    /// Global output indexes of the funding outputs this post spends — the
    /// reservation set: funding selection excludes these while the post is
    /// live (`ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.2 rule 1).
    pub funding_gindexes: Vec<u64>,
    /// Dispatch state (WI-2: always [`PendingPostState::Pending`]).
    pub state: PendingPostState,
}

impl std::fmt::Debug for PendingBondPost {
    /// **Redacted on purpose** — a pending post is a row of `P`'s imminent
    /// on-chain activity (persona, timing plan, funding placement); rendering
    /// it through a log / error / `{:?}` path is exactly the off-chain
    /// correlation the firewall exists to prevent.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingBondPost(<redacted pending-post>)")
    }
}

/// The durable pending-post block: every live pending bond post, sealed as
/// one atomic unit to the `P`-isolated `.wallet.pending` sibling file.
///
/// `Debug` is hand-written to redact the posts (contents and count) — the
/// number of in-flight posts alone is `P`-activity volume.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct PendingPostBlock {
    /// Per-block schema version — [`PENDING_POST_VERSION`] on construction,
    /// version-gated on load.
    version: u32,
    /// The live pending posts. At most one per persona at genesis
    /// (JoinMarket-only; the assemble path refuses a second — `ARCHIVAL_BOND_WI2_ASSEMBLY.md`
    /// §3.5 "one live post per persona").
    posts: Vec<PendingBondPost>,
}

impl std::fmt::Debug for PendingPostBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingPostBlock")
            .field("version", &self.version)
            .field("posts", &"<redacted pending-posts>")
            .finish()
    }
}

impl Default for PendingPostBlock {
    fn default() -> Self {
        Self::empty()
    }
}

impl PendingPostBlock {
    /// A fresh block with no pending posts.
    pub fn empty() -> Self {
        Self {
            version: PENDING_POST_VERSION,
            posts: Vec::new(),
        }
    }

    /// A block carrying `posts`, stamped with the current version. The caller
    /// (the assemble path) owns the one-live-post-per-persona invariant.
    pub fn new(posts: Vec<PendingBondPost>) -> Self {
        Self {
            version: PENDING_POST_VERSION,
            posts,
        }
    }

    /// The on-block schema version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The live pending posts.
    pub fn posts(&self) -> &[PendingBondPost] {
        &self.posts
    }

    /// Whether `persona` already has a live pending post — the
    /// `PendingPostExists` refusal predicate.
    pub fn has_live_post_for(&self, persona: &PCanonicalId) -> bool {
        self.posts.iter().any(|p| &p.persona == persona)
    }

    /// Every funding gindex reserved by a live post — the exclusion set for
    /// funding selection (`ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.2 rule 1).
    pub fn reserved_gindexes(&self) -> std::collections::BTreeSet<u64> {
        self.posts
            .iter()
            .flat_map(|p| p.funding_gindexes.iter().copied())
            .collect()
    }

    /// Append a pending post. Refuses (returns `false`, block unchanged) if
    /// the persona already has a live post — the caller surfaces this as its
    /// typed `PendingPostExists` error.
    #[must_use]
    pub fn push_post(&mut self, post: PendingBondPost) -> bool {
        if self.has_live_post_for(&post.persona) {
            return false;
        }
        self.posts.push(post);
        true
    }

    /// Serialize to postcard bytes (the inner half of the seal; the engine
    /// layer applies the AEAD + atomic write to the sibling file).
    pub fn to_postcard_bytes(&self) -> Result<Vec<u8>, WalletLedgerError> {
        postcard::to_allocvec(self).map_err(Into::into)
    }

    /// Deserialize from [`Self::to_postcard_bytes`] output. **Refuses a
    /// version mismatch.**
    pub fn from_postcard_bytes(bytes: &[u8]) -> Result<Self, WalletLedgerError> {
        let block: Self = postcard::from_bytes(bytes)?;
        block.check_version()?;
        Ok(block)
    }

    /// Version gate. Called automatically by [`Self::from_postcard_bytes`].
    pub fn check_version(&self) -> Result<(), WalletLedgerError> {
        if self.version != PENDING_POST_VERSION {
            return Err(WalletLedgerError::UnsupportedBlockVersion {
                block: "pending_post_block",
                file: self.version,
                binary: PENDING_POST_VERSION,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn post(persona_byte: u8, gindexes: &[u64]) -> PendingBondPost {
        PendingBondPost {
            p_slot: 0,
            persona: PCanonicalId::from_bytes([persona_byte; 32]),
            tx_bytes: vec![0xAB; 16],
            entry_offset_blocks: 3,
            bond_post_offset_blocks: 12,
            anchor_t0: BlockHeight::from_raw(1_000),
            funding_gindexes: gindexes.to_vec(),
            state: PendingPostState::Pending,
        }
    }

    #[test]
    fn round_trips_through_postcard() {
        let mut block = PendingPostBlock::empty();
        assert!(block.push_post(post(0xAA, &[1, 2])));
        let bytes = block.to_postcard_bytes().expect("encode");
        let back = PendingPostBlock::from_postcard_bytes(&bytes).expect("decode");
        assert_eq!(back, block);
        assert_eq!(back.posts().len(), 1);
    }

    #[test]
    fn version_mismatch_fails_closed() {
        let wrong = PendingPostBlock {
            version: PENDING_POST_VERSION + 1,
            posts: Vec::new(),
        };
        let bytes = postcard::to_allocvec(&wrong).expect("encode");
        let err = PendingPostBlock::from_postcard_bytes(&bytes).expect_err("must refuse");
        assert!(matches!(
            err,
            WalletLedgerError::UnsupportedBlockVersion {
                block: "pending_post_block",
                ..
            }
        ));
    }

    #[test]
    fn one_live_post_per_persona() {
        let mut block = PendingPostBlock::empty();
        assert!(block.push_post(post(0xAA, &[1])));
        assert!(
            !block.push_post(post(0xAA, &[2])),
            "a second post for the same persona is refused"
        );
        assert!(block.push_post(post(0xBB, &[2])), "another persona is fine");
        assert_eq!(block.posts().len(), 2);
    }

    #[test]
    fn reserved_gindexes_union_all_live_posts() {
        let mut block = PendingPostBlock::empty();
        assert!(block.push_post(post(0xAA, &[1, 2])));
        assert!(block.push_post(post(0xBB, &[2, 7])));
        let reserved = block.reserved_gindexes();
        assert_eq!(reserved.into_iter().collect::<Vec<_>>(), vec![1, 2, 7]);
    }

    #[test]
    fn debug_is_redacted_including_count() {
        let mut block = PendingPostBlock::empty();
        assert!(block.push_post(post(0xAA, &[1])));
        let rendered = format!("{block:?}");
        assert!(rendered.contains("<redacted pending-posts>"));
        assert!(!rendered.contains("0xAA") && !rendered.contains("170"));
        let one = post(0xCC, &[4]);
        assert_eq!(
            format!("{one:?}"),
            "PendingBondPost(<redacted pending-post>)"
        );
    }
}
