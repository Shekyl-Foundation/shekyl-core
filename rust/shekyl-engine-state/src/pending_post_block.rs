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

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use shekyl_types::{BlockHeight, PCanonicalId};

use crate::error::WalletLedgerError;

/// Schema version of the durable pending-post block. **v2** is the WI-3
/// dispatch shape: v1's JoinMarket-only record plus the
/// [`PendingPostState::Dispatched`] arm (`ARCHIVAL_BOND_WI3_DISPATCH.md`
/// §3.3). Any field addition / removal / renaming bumps this; loads that see
/// a different version **refuse rather than migrate** — pre-genesis, a v1
/// seal under a v2 binary fails closed and the operator re-assembles
/// (rule 15).
pub const PENDING_POST_VERSION: u32 = 2;

/// Dispatch state of a pending bond post. The WI-2 assemble path writes only
/// [`Self::Pending`]; WI-3's block-timed dispatch driver owns the
/// [`Self::Dispatched`] transition (seal-before-send, §3.3) and the attempt
/// bookkeeping.
///
/// There is deliberately **no persisted `Confirmed` arm**: confirmation
/// *removes* the record (§3.5) — retirement and reservation release are one
/// atomic seal, so a live record always means a live reservation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub enum PendingPostState {
    /// Assembled and sealed; not yet handed to any submitter.
    Pending,
    /// Sealed as dispatched **before** the first network send
    /// (seal-before-send): a crash after this seal resumes as "maybe sent",
    /// which is safe because every resend is byte-identical (pin P-2).
    Dispatched {
        /// Tip height the due-check fired against at the first send.
        at: BlockHeight,
        /// Total send attempts (first send inclusive); bumped on every
        /// byte-identical resubmit, bounded by the driver's attempt budget.
        attempts: u32,
    },
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

    /// WI-3 §3.3 step 2 — transition `persona`'s post into
    /// [`PendingPostState::Dispatched`] with `attempts = 1`, or bump its
    /// attempt counter (saturating) if it is already dispatched (the
    /// byte-identical resubmit path, §3.4). Returns the post-transition
    /// attempt count **and a reference to the transitioned post**, or `None`
    /// if the persona has no live post.
    ///
    /// Returning the post (not just the count) lets the dispatch driver lift
    /// the sealed bytes it must re-send from the *same* lookup that performed
    /// the transition — no second `posts` scan to re-find the record it just
    /// mutated.
    ///
    /// A pure in-memory mutation: the caller (the locked `PendingPostStore`
    /// write path) seals the whole block **before any network send**.
    #[must_use]
    pub fn mark_dispatched(
        &mut self,
        persona: &PCanonicalId,
        at: BlockHeight,
    ) -> Option<(u32, &PendingBondPost)> {
        let post = self.posts.iter_mut().find(|p| &p.persona == persona)?;
        let attempts = match &mut post.state {
            PendingPostState::Pending => {
                post.state = PendingPostState::Dispatched { at, attempts: 1 };
                1
            }
            PendingPostState::Dispatched { attempts, .. } => {
                // `at` is NOT updated on resubmit: it records the tip the
                // due-check *first* fired against (the dispatch fact), and a
                // resubmit re-sends the same bytes, not a new dispatch.
                *attempts = attempts.saturating_add(1);
                *attempts
            }
        };
        Some((attempts, &*post))
    }

    /// WI-3 §3.5 / §3.6 — remove `persona`'s post (confirmation retire, or
    /// terminal-reject prune). Removal *is* the byte-prune and the
    /// reservation release in one seal: the record is the stored bytes and
    /// the reservation is derived ([`Self::reserved_gindexes`]), so neither
    /// can survive it (R2-4). Returns the removed post, or `None` if the
    /// persona has no live post (idempotent under crash-replay).
    #[must_use]
    pub fn remove_post(&mut self, persona: &PCanonicalId) -> Option<PendingBondPost> {
        let idx = self.posts.iter().position(|p| &p.persona == persona)?;
        Some(self.posts.remove(idx))
    }

    /// WI-3 §3.5 — confirmation retire, batched: drop every live post whose
    /// persona is in `confirmed`, returning the removed personas. Each removal
    /// *is* the byte-prune + reservation release in the same seal (R2-4), as in
    /// [`Self::remove_post`].
    ///
    /// Walks the **live posts once** (`O(live posts)`), so the cost is bounded
    /// by the wallet's in-flight post count — **not** by `|confirmed|`, which is
    /// the pscan's monotonically-growing confirmed-persona set (never pruned
    /// until 2d-2 SP-6). A persona-by-persona `remove_post` loop over `confirmed`
    /// would instead re-scan the block once per ever-confirmed persona
    /// (`O(|confirmed| · live)`), doing more work every sweep for the wallet's
    /// whole lifetime to retire the same handful of live posts.
    #[must_use]
    pub fn remove_confirmed(&mut self, confirmed: &BTreeSet<PCanonicalId>) -> Vec<PCanonicalId> {
        let mut retired = Vec::new();
        self.posts.retain(|post| {
            if confirmed.contains(&post.persona) {
                retired.push(post.persona);
                false
            } else {
                true
            }
        });
        retired
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

    /// Gate 7 (WI-3 §5): the `Dispatched` arm round-trips with its `at` /
    /// `attempts` payload intact.
    #[test]
    fn dispatched_arm_round_trips_through_postcard() {
        let mut block = PendingPostBlock::empty();
        assert!(block.push_post(post(0xAA, &[1, 2])));
        assert_eq!(
            block
                .mark_dispatched(
                    &PCanonicalId::from_bytes([0xAA; 32]),
                    BlockHeight::from_raw(1_012)
                )
                .map(|(attempts, _)| attempts),
            Some(1)
        );
        let bytes = block.to_postcard_bytes().expect("encode");
        let back = PendingPostBlock::from_postcard_bytes(&bytes).expect("decode");
        assert_eq!(back, block);
        assert_eq!(
            back.posts()[0].state,
            PendingPostState::Dispatched {
                at: BlockHeight::from_raw(1_012),
                attempts: 1
            }
        );
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

    /// Gate 7 (WI-3 §5): a WI-2 **v1** seal under this v2 binary fails
    /// closed on the version gate — refuse-not-migrate; the operator
    /// re-assembles (rule 15, pre-genesis).
    #[test]
    fn v1_seal_fails_closed_under_v2_binary() {
        let v1 = PendingPostBlock {
            version: 1,
            posts: Vec::new(),
        };
        let bytes = postcard::to_allocvec(&v1).expect("encode");
        let err = PendingPostBlock::from_postcard_bytes(&bytes).expect_err("v1 must refuse");
        assert!(matches!(
            err,
            WalletLedgerError::UnsupportedBlockVersion {
                block: "pending_post_block",
                file: 1,
                binary: PENDING_POST_VERSION,
            }
        ));
    }

    /// §3.3 — first `mark_dispatched` transitions Pending→Dispatched with
    /// `attempts = 1`; each subsequent call is the resubmit path: `attempts`
    /// bumps, `at` (the first-dispatch tip) does NOT move.
    #[test]
    fn mark_dispatched_transitions_then_bumps_attempts_without_moving_at() {
        let persona = PCanonicalId::from_bytes([0xAA; 32]);
        let mut block = PendingPostBlock::empty();
        assert!(block.push_post(post(0xAA, &[1])));

        assert_eq!(
            block
                .mark_dispatched(&persona, BlockHeight::from_raw(500))
                .map(|(attempts, _)| attempts),
            Some(1)
        );
        // Resubmit at a later tip: attempts bump, `at` stays at first send. The
        // returned post reflects the just-applied transition (same lookup).
        let (attempts, post) = block
            .mark_dispatched(&persona, BlockHeight::from_raw(510))
            .expect("live post");
        assert_eq!(attempts, 2);
        assert_eq!(
            post.state,
            PendingPostState::Dispatched {
                at: BlockHeight::from_raw(500),
                attempts: 2
            }
        );
        assert_eq!(
            block.posts()[0].state,
            PendingPostState::Dispatched {
                at: BlockHeight::from_raw(500),
                attempts: 2
            }
        );
        // No live post for an unknown persona.
        assert!(block
            .mark_dispatched(
                &PCanonicalId::from_bytes([0xEE; 32]),
                BlockHeight::from_raw(1)
            )
            .is_none());
    }

    /// §3.5/§3.6 (R2-4) — removal retires the record, prunes the held bytes,
    /// and releases the derived reservation in one mutation; re-removal is
    /// idempotent (`None`).
    #[test]
    fn remove_post_prunes_bytes_and_releases_the_derived_reservation() {
        let persona = PCanonicalId::from_bytes([0xAA; 32]);
        let mut block = PendingPostBlock::empty();
        assert!(block.push_post(post(0xAA, &[1, 2])));
        assert!(block.push_post(post(0xBB, &[7])));

        let removed = block.remove_post(&persona).expect("live post removes");
        assert_eq!(removed.persona, persona);
        assert!(!block.has_live_post_for(&persona));
        assert_eq!(
            block.reserved_gindexes().into_iter().collect::<Vec<_>>(),
            vec![7],
            "the removed post's reservation is gone in the same mutation"
        );
        assert!(
            block.remove_post(&persona).is_none(),
            "re-removal is idempotent (crash-replay safe)"
        );
    }

    /// §3.5 batched retire: `remove_confirmed` drops exactly the live posts
    /// whose persona is confirmed (releasing their reservations), leaves the
    /// rest, and ignores confirmed personas with no live post — so a
    /// monotonically-growing confirmed set costs nothing per unmatched entry.
    #[test]
    fn remove_confirmed_retires_only_matching_live_posts() {
        let persona = |b: u8| PCanonicalId::from_bytes([b; 32]);
        let mut block = PendingPostBlock::empty();
        assert!(block.push_post(post(0xAA, &[1])));
        assert!(block.push_post(post(0xBB, &[2, 3])));

        // Confirm 0xAA (live) plus 0xCC (never had a post — the ever-growing
        // confirmed-set case).
        let confirmed: BTreeSet<PCanonicalId> = [persona(0xAA), persona(0xCC)].into();
        let retired = block.remove_confirmed(&confirmed);

        assert_eq!(retired, vec![persona(0xAA)], "only the live match retires");
        assert!(!block.has_live_post_for(&persona(0xAA)));
        assert!(
            block.has_live_post_for(&persona(0xBB)),
            "unconfirmed post kept"
        );
        assert_eq!(
            block.reserved_gindexes().into_iter().collect::<Vec<_>>(),
            vec![2, 3],
            "the retired post's reservation released; the kept post's remains"
        );

        // Idempotent: re-running with the same set retires nothing more.
        assert!(block.remove_confirmed(&confirmed).is_empty());
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
