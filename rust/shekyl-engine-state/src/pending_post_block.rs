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
use shekyl_types::{BlockHeight, GlobalOutputIndex, PCanonicalId, PSlot};

use crate::error::WalletLedgerError;

/// Schema version of the durable pending-post block. **v6** REMOVES
/// `PendingBondPost::entry_offset_blocks` — the offset for a second entry-seam
/// event that does not exist: at entry only the bond post is attributable, so
/// there was never an entry event to schedule against it
/// (`ARCHIVAL_FIREWALL_GATE6.md` §10.12 pass-4 (d) + method note 8). The field
/// carried no dispatch decision — `due` was always
/// `anchor_t0 + bond_post_offset_blocks` — so nothing is lost with it. **v7**
/// removes dead fields (SA-4 dead persisted-field sweep, rule-15): the
/// unread `p_slot` ordinal from [`PendingEmissionClaim`] and [`PendingDrain`]
/// (every path keys on `persona`, `PCanonicalId`) and the unread
/// `claimed_epochs` from [`PendingEmissionClaim`] (the sealed tx bytes bind
/// the epochs; the dedup is per-persona, not per-epoch). Reopen: a
/// per-epoch or per-slot pending-post reader that `persona` + the sealed
/// bytes cannot serve. **v5**
/// adds the [`PendingDrain`] record set — the F-D2 drain's
/// persist-before-dispatch sibling (DS-PR-1): a drain spends `P`-funding
/// inputs, so all of its input gindexes must be reserved durably **before** the
/// bytes reach any submitter, exactly as a bond post reserves its funding.
/// **v4** adds the
/// [`PendingEmissionClaim`] record set — the emission-claim sibling of the
/// bond post's persist-before-dispatch discipline (CB-3 dispatch seam): the
/// claim's fee-gindex reservation and claimed-epoch dedup facts must exist
/// durably **before** the bytes reach any submitter. **v3** domain-newtypes
/// `funding_gindexes` as [`GlobalOutputIndex`] (WI-2 orchestrator carrier;
/// postcard-transparent). **v2** is the WI-3
/// dispatch shape: v1's JoinMarket-only record plus the
/// [`PendingPostState::Dispatched`] arm (`ARCHIVAL_BOND_WI3_DISPATCH.md`
/// §3.3). Any field addition / removal / renaming bumps this; loads that see
/// a different version **refuse rather than migrate** — pre-genesis, a v4
/// seal under a v5 binary fails closed and the operator re-assembles
/// (rule 15).
pub const PENDING_POST_VERSION: u32 = 7;

/// Dispatch state of a pending bond post. The WI-2 assemble path writes only
/// [`Self::Pending`]; WI-3's block-timed dispatch driver owns the
/// [`Self::Dispatched`] transition (seal-before-send, §3.3) and the attempt
/// bookkeeping.
///
/// There is deliberately **no persisted `Confirmed` arm**: confirmation
/// *removes* the record (§3.5) — retirement and reservation release are one
/// atomic seal, so a live record always means a live reservation.
///
/// **Removal-ordering contract (binding on the GF-7 dispatch driver):** a
/// record's durable removal must not become visible before the
/// match-bearing pscan-state seal that justified it is itself durable — the
/// live record is the bridge the open-time phantom `bonded_slots` GC relies
/// on across the scan lag (see `shekyl-engine-core`'s
/// `reconcile_phantom_bonded_slots`); removing it first opens a crash
/// window where a real on-chain bond is GC'd as a phantom.
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
    pub p_slot: PSlot,
    /// The persona the transaction bytes are bound to — must match the
    /// binding engine-core's `PBoundBytes` carries when the record is
    /// re-lifted for dispatch.
    pub persona: PCanonicalId,
    /// The fully-assembled, signed, wire-encoded transaction bytes — the
    /// value itself, per pin P-2: retries re-send these stored bytes.
    pub tx_bytes: Vec<u8>,
    /// Blocks from `anchor_t0` to the bond-post broadcast.
    pub bond_post_offset_blocks: u64,
    /// Tip height at assemble time — the private intent anchor `t0` the
    /// plan's offsets are relative to. WI-3's due-check is pure:
    /// `due = anchor_t0 + bond_post_offset_blocks`.
    pub anchor_t0: BlockHeight,
    /// Global output indexes of the funding outputs this post spends — the
    /// reservation set: funding selection excludes these while the post is
    /// live (`ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.2 rule 1).
    pub funding_gindexes: Vec<GlobalOutputIndex>,
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

/// One durable pending **emission claim**: the assembled, signed,
/// wire-encoded claim bytes bound to their persona, the fee reservation they
/// hold, and the epochs they claim — sealed **before** dispatch (the CB-3
/// seam's persist-before-dispatch, pin P-2's sibling: retries re-send these
/// stored bytes, and the reservation/dedup facts exist durably before any
/// network send).
///
/// A live claim record means its `fee_gindexes` are reserved (they feed
/// [`PendingPostBlock::reserved_gindexes`], so neither a bond sweep nor a
/// second claim sweep can double-spend them) and the persona has a claim
/// in flight: the epoch-dedup is the **one-live-claim-per-persona** refusal
/// (`has_live_claim_for`), because a second claim while one is live would
/// re-derive and re-claim the same epochs by construction — the sealed tx
/// bytes already bind the exact claimed epochs, so no separate epoch list
/// need be persisted. Retirement (confirmation observe / terminal reject)
/// is the claim dispatch driver's slice, mirroring WI-3's bond retire.
///
/// Same redacted-`Debug` class as [`PendingBondPost`]: persona, funding
/// placement, and claim timing are `P`-side behavioral history.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct PendingEmissionClaim {
    /// The persona the claim bytes are bound to. Keyed on throughout
    /// (`has_live_claim_for` / dispatch retire) — the owning slot ordinal
    /// is not persisted separately (SA-4: it had no reader; the persona is
    /// the identity every path uses).
    pub persona: PCanonicalId,
    /// The fully-assembled, signed, wire-encoded claim bytes — the value
    /// itself: retries re-send these stored bytes, never a re-encode.
    pub tx_bytes: Vec<u8>,
    /// Global output indexes of the swept **fee** funding records — the
    /// reservation this claim holds while live. The backing's gindex is
    /// deliberately absent (proven, not spent).
    pub fee_gindexes: Vec<GlobalOutputIndex>,
    /// Dispatch state — same lifecycle as the bond post's.
    pub state: PendingPostState,
}

impl std::fmt::Debug for PendingEmissionClaim {
    /// Redacted for the same reason as [`PendingBondPost`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingEmissionClaim(<redacted pending-claim>)")
    }
}

/// One durable pending **`P`→principal drain** (F-D2 / DS-PR-1): the
/// assembled, signed, wire-encoded drain bytes bound to their persona and the
/// funding reservation they hold — sealed **before** dispatch (the DS-PR-2
/// drain-dispatch seam's persist-before-dispatch, the claim/bond sibling: a
/// retry re-sends these stored bytes, and the reservation exists durably
/// before any network send).
///
/// Unlike [`PendingEmissionClaim`] (whose backing gindex is *proven, not
/// spent*, so only the swept fee inputs reserve), a drain **spends every one
/// of its funding inputs** — so `funding_gindexes` is the whole input set and
/// the whole reservation. It carries no `claimed_epochs`: a drain is a
/// value-out crossing, not an epoch claim, so there is no epoch-dedup fact.
/// A live drain record means those gindexes are reserved (they feed
/// [`PendingPostBlock::reserved_gindexes`], so neither a bond sweep, a claim
/// sweep, nor a second drain can double-spend an in-flight input).
///
/// Same redacted-`Debug` class as [`PendingBondPost`]: persona, funding
/// placement, and drain timing are `P`-side behavioral history.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct PendingDrain {
    /// The persona the drain bytes are bound to. Keyed on throughout
    /// (`has_live_drain_for` / dispatch retire); the owning slot ordinal is
    /// not persisted separately (SA-4: it had no reader).
    pub persona: PCanonicalId,
    /// The fully-assembled, signed, wire-encoded drain bytes — the value
    /// itself: retries re-send these stored bytes, never a re-encode.
    pub tx_bytes: Vec<u8>,
    /// Global output indexes of the funding outputs this drain spends — the
    /// reservation this drain holds while live. A drain spends *all* its
    /// inputs (no proven-not-spent backing), so this is the full input set.
    pub funding_gindexes: Vec<GlobalOutputIndex>,
    /// Dispatch state — same lifecycle as the bond post's / claim's.
    pub state: PendingPostState,
}

impl std::fmt::Debug for PendingDrain {
    /// Redacted for the same reason as [`PendingBondPost`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingDrain(<redacted pending-drain>)")
    }
}
/// What [`PendingPostBlock::remove_settled`] retired, split by kind.
///
/// Two vectors rather than one merged list: the caller logs and books them
/// separately (a retired claim releases the epoch-dedup gate, a retired drain
/// releases the one-live-drain lane), and merging them would force a second
/// lookup to tell which gate just opened.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SettledRetirement {
    /// Personas whose live emission claim settled.
    pub claims: Vec<PCanonicalId>,
    /// Personas whose live `P`→principal drain settled.
    pub drains: Vec<PCanonicalId>,
}

impl SettledRetirement {
    /// Nothing retired this tick — the common case, and the one the caller
    /// short-circuits on rather than sealing an unchanged block.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.claims.is_empty() && self.drains.is_empty()
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
    /// The live pending emission claims. At most one per persona (the
    /// claim seam refuses a second — a live claim is the in-flight
    /// epoch-dedup fact).
    claims: Vec<PendingEmissionClaim>,
    /// The live pending `P`→principal drains. At most one per persona (the
    /// drain seam refuses a second — a live drain reserves the inputs a
    /// second would race for).
    drains: Vec<PendingDrain>,
}

impl std::fmt::Debug for PendingPostBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingPostBlock")
            .field("version", &self.version)
            .field("posts", &"<redacted pending-posts>")
            .field("claims", &"<redacted pending-claims>")
            .field("drains", &"<redacted pending-drains>")
            .finish()
    }
}

impl Default for PendingPostBlock {
    fn default() -> Self {
        Self::empty()
    }
}

impl PendingPostBlock {
    /// A fresh block with no pending posts, claims, or drains.
    pub fn empty() -> Self {
        Self {
            version: PENDING_POST_VERSION,
            posts: Vec::new(),
            claims: Vec::new(),
            drains: Vec::new(),
        }
    }

    /// A block carrying `posts` (no claims, no drains), stamped with the
    /// current version. The caller (the assemble path) owns the
    /// one-live-post-per-persona invariant.
    pub fn new(posts: Vec<PendingBondPost>) -> Self {
        Self {
            version: PENDING_POST_VERSION,
            posts,
            claims: Vec::new(),
            drains: Vec::new(),
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

    /// The live pending emission claims.
    pub fn claims(&self) -> &[PendingEmissionClaim] {
        &self.claims
    }

    /// Whether `persona` already has a live pending emission claim — the
    /// claim seam's one-live-claim-per-persona refusal predicate (which is
    /// also the in-flight epoch dedup: a second claim would re-derive and
    /// re-claim the same epochs).
    pub fn has_live_claim_for(&self, persona: &PCanonicalId) -> bool {
        self.claims.iter().any(|c| &c.persona == persona)
    }

    /// The live pending drains.
    pub fn drains(&self) -> &[PendingDrain] {
        &self.drains
    }

    /// Whether `persona` already has a live pending drain — the drain seam's
    /// one-live-drain-per-persona refusal predicate (a live drain reserves
    /// the inputs a second would race for).
    pub fn has_live_drain_for(&self, persona: &PCanonicalId) -> bool {
        self.drains.iter().any(|d| &d.persona == persona)
    }

    /// Every funding gindex reserved by a live post, a live claim's fee
    /// sweep, **or a live drain's input set** — the exclusion set for funding
    /// selection (`ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.2 rule 1): no bond sweep,
    /// claim fee sweep, or drain may select an output an in-flight tx already
    /// spends.
    pub fn reserved_gindexes(&self) -> std::collections::BTreeSet<GlobalOutputIndex> {
        self.posts
            .iter()
            .flat_map(|p| p.funding_gindexes.iter().copied())
            .chain(
                self.claims
                    .iter()
                    .flat_map(|c| c.fee_gindexes.iter().copied()),
            )
            .chain(
                self.drains
                    .iter()
                    .flat_map(|d| d.funding_gindexes.iter().copied()),
            )
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

    /// Append a pending emission claim. Refuses (returns `false`, block
    /// unchanged) if the persona already has a live claim — the caller
    /// surfaces this as its typed claim-pending error.
    #[must_use]
    pub fn push_claim(&mut self, claim: PendingEmissionClaim) -> bool {
        if self.has_live_claim_for(&claim.persona) {
            return false;
        }
        self.claims.push(claim);
        true
    }

    /// Transition `persona`'s live claim into
    /// [`PendingPostState::Dispatched`] (or bump its attempt counter on a
    /// byte-identical resubmit) — the claim twin of
    /// [`Self::mark_dispatched`], same seal-before-send discipline. Returns
    /// the post-transition attempt count and the transitioned claim, or
    /// `None` when the persona has no live claim.
    #[must_use]
    pub fn mark_claim_dispatched(
        &mut self,
        persona: &PCanonicalId,
        at: BlockHeight,
    ) -> Option<(u32, &PendingEmissionClaim)> {
        let claim = self.claims.iter_mut().find(|c| &c.persona == persona)?;
        let attempts = match &mut claim.state {
            PendingPostState::Pending => {
                claim.state = PendingPostState::Dispatched { at, attempts: 1 };
                1
            }
            PendingPostState::Dispatched { attempts, .. } => {
                *attempts = attempts.saturating_add(1);
                *attempts
            }
        };
        Some((attempts, &*claim))
    }

    /// Remove `persona`'s live claim (confirmation retire, or terminal-
    /// reject prune). As with [`Self::remove_post`], removal *is* the
    /// byte-prune, the reservation release, and the epoch-dedup release in
    /// one seal; idempotent under crash-replay (`None` when absent).
    #[must_use]
    pub fn remove_claim(&mut self, persona: &PCanonicalId) -> Option<PendingEmissionClaim> {
        let idx = self.claims.iter().position(|c| &c.persona == persona)?;
        Some(self.claims.remove(idx))
    }

    /// Append a pending drain. Refuses (returns `false`, block unchanged) if
    /// the persona already has a live drain — the caller surfaces this as its
    /// typed drain-pending error.
    #[must_use]
    pub fn push_drain(&mut self, drain: PendingDrain) -> bool {
        if self.has_live_drain_for(&drain.persona) {
            return false;
        }
        self.drains.push(drain);
        true
    }

    /// Transition `persona`'s live drain into [`PendingPostState::Dispatched`]
    /// (or bump its attempt counter on a byte-identical resubmit) — the drain
    /// twin of [`Self::mark_dispatched`], same seal-before-send discipline.
    /// Returns the post-transition attempt count and the transitioned drain,
    /// or `None` when the persona has no live drain.
    #[must_use]
    pub fn mark_drain_dispatched(
        &mut self,
        persona: &PCanonicalId,
        at: BlockHeight,
    ) -> Option<(u32, &PendingDrain)> {
        let drain = self.drains.iter_mut().find(|d| &d.persona == persona)?;
        let attempts = match &mut drain.state {
            PendingPostState::Pending => {
                drain.state = PendingPostState::Dispatched { at, attempts: 1 };
                1
            }
            PendingPostState::Dispatched { attempts, .. } => {
                *attempts = attempts.saturating_add(1);
                *attempts
            }
        };
        Some((attempts, &*drain))
    }

    /// Remove `persona`'s live drain (confirmation retire, or terminal-reject
    /// prune). As with [`Self::remove_post`], removal *is* the byte-prune and
    /// the reservation release in one seal; idempotent under crash-replay
    /// (`None` when absent).
    #[must_use]
    pub fn remove_drain(&mut self, persona: &PCanonicalId) -> Option<PendingDrain> {
        let idx = self.drains.iter().position(|d| &d.persona == persona)?;
        Some(self.drains.remove(idx))
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

    /// Confirmation retire for the **reservation-observed** kinds — claims and
    /// drains — the sibling of [`Self::remove_confirmed`].
    ///
    /// A bond post is retired against a direct on-chain observation of itself
    /// (`confirmed_join_market_personas`: the pscan matched the post). Claims
    /// and drains have no such match set, so their settlement is observed
    /// **through their reservation**: each spends the funding outputs it holds,
    /// so once every reserved gindex has left the accrual's live funding set,
    /// the transaction that spent them confirmed.
    ///
    /// That inference is sound only while the reservation makes the record the
    /// *sole* possible spender inside this wallet. Three things together give
    /// that, and the first draft of this doc asserted the second when it was
    /// only two-thirds true:
    ///
    /// 1. `push_post` / `push_claim` / `push_drain` admit one live record per
    ///    persona **per kind** — which says nothing about a cross-kind gindex
    ///    collision, so it is not sufficient on its own.
    /// 2. Every writer re-reads the live union **inside its own seal mutate**
    ///    and refuses on overlap. The drain seam did this; the claim and
    ///    bond-post seams did not until review #572 added it, so two records
    ///    could reserve one gindex and either confirming would retire both.
    ///    `every_reservation_writer_rechecks_the_union_under_the_seal_lock`
    ///    pins all three, and names the file when a fourth writer forgets.
    /// 3. Pin P-2: a retry re-sends the same bytes rather than building a
    ///    competing transaction. Nothing outside the wallet can spend `P`'s
    ///    outputs at all.
    ///
    /// With all three, "these inputs are gone" and "this record's transaction
    /// confirmed" are the same fact. Without (2) they are not, which is why the
    /// guard is part of this method's contract rather than local hygiene at the
    /// seams.
    ///
    /// **An empty reservation is never settled.** A record holding no gindexes
    /// would satisfy "all of them are gone" vacuously and retire the instant it
    /// was sealed — before its transaction reached the network. That is not
    /// hypothetical: the Q11 zero-fee-input emission claim (the destitute corner,
    /// where the fee comes out of the mint) holds exactly zero `fee_gindexes`.
    /// The empty case is therefore excluded explicitly rather than left to
    /// `all()`'s vacuous truth, which is the permissive-default shape this
    /// codebase keeps finding. Such a claim's seal stays live until a direct
    /// claim-match observation exists to retire it against — recorded in
    /// FOLLOWUPS as the named residual, and fail-closed in the meantime
    /// (a held seal refuses a second claim; a wrongly-released one would let a
    /// second claim race the first's inputs).
    ///
    /// Walks the live records once, like [`Self::remove_confirmed`], so the cost
    /// is bounded by in-flight records rather than by `|live_funding|`.
    #[must_use]
    pub fn remove_settled(
        &mut self,
        live_funding: &std::collections::BTreeSet<GlobalOutputIndex>,
    ) -> SettledRetirement {
        fn settled(
            reserved: &[GlobalOutputIndex],
            live: &std::collections::BTreeSet<GlobalOutputIndex>,
        ) -> bool {
            !reserved.is_empty() && reserved.iter().all(|g| !live.contains(g))
        }

        let mut out = SettledRetirement::default();
        self.claims.retain(|claim| {
            if settled(&claim.fee_gindexes, live_funding) {
                out.claims.push(claim.persona);
                false
            } else {
                true
            }
        });
        self.drains.retain(|drain| {
            if settled(&drain.funding_gindexes, live_funding) {
                out.drains.push(drain.persona);
                false
            } else {
                true
            }
        });
        out
    }

    /// Serialize to postcard bytes (the inner half of the seal; the engine
    /// layer applies the AEAD + atomic write to the sibling file).
    pub fn to_postcard_bytes(&self) -> Result<Vec<u8>, WalletLedgerError> {
        postcard::to_allocvec(self).map_err(Into::into)
    }

    /// Deserialize from [`Self::to_postcard_bytes`] output. **Refuses a
    /// version mismatch before decoding the body** (refuse-not-migrate, rules
    /// 15/60), so a blob written by any other schema version names its version
    /// instead of surfacing as an opaque postcard EOF/layout error — e.g. a v4
    /// blob has no `drains` field, so a full v5 decode would EOF. This block
    /// was the first to need that ordering; [`crate::version_gate`] now owns it
    /// for every persisted block.
    pub fn from_postcard_bytes(bytes: &[u8]) -> Result<Self, WalletLedgerError> {
        crate::version_gate::gate_leading_version(
            bytes,
            "pending_post_block",
            PENDING_POST_VERSION,
        )?;
        Ok(postcard::from_bytes(bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn post(persona_byte: u8, gindexes: &[u64]) -> PendingBondPost {
        PendingBondPost {
            p_slot: PSlot::from_raw(0),
            persona: PCanonicalId::from_bytes([persona_byte; 32]),
            tx_bytes: vec![0xAB; 16],
            bond_post_offset_blocks: 12,
            anchor_t0: BlockHeight::from_raw(1_000),
            funding_gindexes: gindexes
                .iter()
                .copied()
                .map(GlobalOutputIndex::from_raw)
                .collect(),
            state: PendingPostState::Pending,
        }
    }

    /// The accrual's live funding set, as `remove_settled` reads it.
    fn live(v: &[u64]) -> std::collections::BTreeSet<GlobalOutputIndex> {
        v.iter().copied().map(GlobalOutputIndex::from_raw).collect()
    }

    /// The seal releases when the reservation is gone — the whole point of the
    /// driver, and the defect this closes: before it, a confirmed drain's record
    /// stayed live forever and the persona's drain lane refused across sessions.
    #[test]
    fn a_spent_reservation_retires_its_claim_and_its_drain() {
        let mut block = PendingPostBlock::empty();
        assert!(block.push_claim(claim(0xAA, &[1, 2])));
        assert!(block.push_drain(drain(0xBB, &[3])));

        // Neither reservation is live any more: both transactions confirmed.
        let out = block.remove_settled(&live(&[99]));

        assert_eq!(out.claims, vec![PCanonicalId::from_bytes([0xAA; 32])]);
        assert_eq!(out.drains, vec![PCanonicalId::from_bytes([0xBB; 32])]);
        assert!(!block.has_live_claim_for(&PCanonicalId::from_bytes([0xAA; 32])));
        assert!(!block.has_live_drain_for(&PCanonicalId::from_bytes([0xBB; 32])));
    }

    /// A reservation still on chain is still in flight.
    #[test]
    fn a_live_reservation_holds_its_seal() {
        let mut block = PendingPostBlock::empty();
        assert!(block.push_drain(drain(0xBB, &[3, 4])));
        let out = block.remove_settled(&live(&[3, 4]));
        assert!(out.is_empty());
        assert!(block.has_live_drain_for(&PCanonicalId::from_bytes([0xBB; 32])));
    }

    /// **Partial spend is not settlement.** A drain spends all its inputs in one
    /// transaction, so a half-gone reservation is not "mostly confirmed" — it is
    /// a state the confirming transaction cannot produce. Retiring on `any`
    /// would release the seal on an anomaly; holding is fail-closed.
    #[test]
    fn a_partly_spent_reservation_is_not_settled() {
        let mut block = PendingPostBlock::empty();
        assert!(block.push_drain(drain(0xBB, &[3, 4])));
        let out = block.remove_settled(&live(&[4]));
        assert!(
            out.is_empty(),
            "one input gone is not the confirming spend of both"
        );
        assert!(block.has_live_drain_for(&PCanonicalId::from_bytes([0xBB; 32])));
    }

    /// **The vacuous-truth guard.** `[].iter().all(..)` is `true`, so a record
    /// holding no reservation would read as settled the instant it was sealed —
    /// retired before its bytes ever reached the network, releasing the gate that
    /// stops a second transaction racing the first.
    ///
    /// This is not a theoretical shape: the Q11 zero-fee-input emission claim
    /// (fee out of the mint, the destitute corner) carries exactly zero
    /// `fee_gindexes`. Deleting the `!reserved.is_empty()` term turns this test
    /// red, which is the only reason it is a test rather than a comment.
    #[test]
    fn an_empty_reservation_is_never_settled() {
        let mut block = PendingPostBlock::empty();
        assert!(block.push_claim(claim(0xAA, &[])));
        let out = block.remove_settled(&live(&[]));
        assert!(
            out.is_empty(),
            "a zero-fee-input claim has nothing to observe and must not retire vacuously"
        );
        assert!(block.has_live_claim_for(&PCanonicalId::from_bytes([0xAA; 32])));
    }

    /// **The negative control that matters.** Posts and the reservation-observed
    /// kinds are retired against *different evidence*, and the two must not be
    /// crossed: `remove_settled` never touches a bond post, whose settlement is
    /// the pscan's own match (`remove_confirmed`), and whose funding reservation
    /// disappearing means only that its funding was spent — which is what the
    /// bond post itself does.
    #[test]
    fn remove_settled_never_retires_a_bond_post() {
        let mut block = PendingPostBlock::empty();
        assert!(block.push_post(post(0xCC, &[7, 8])));
        let out = block.remove_settled(&live(&[]));
        assert!(out.is_empty());
        assert!(
            block.has_live_post_for(&PCanonicalId::from_bytes([0xCC; 32])),
            "a bond post is retired by its own on-chain match, never by its reservation"
        );
    }

    /// The mirror of the above: the post path must not retire a claim or drain
    /// just because their persona confirmed a bond post.
    #[test]
    fn remove_confirmed_never_retires_a_claim_or_drain() {
        let persona = PCanonicalId::from_bytes([0xAA; 32]);
        let mut block = PendingPostBlock::empty();
        assert!(block.push_claim(claim(0xAA, &[1])));
        assert!(block.push_drain(drain(0xAA, &[2])));

        let retired = block.remove_confirmed(&[persona].into_iter().collect());

        assert!(retired.is_empty(), "there was no live post to retire");
        assert!(
            block.has_live_claim_for(&persona) && block.has_live_drain_for(&persona),
            "a JoinMarket bond-post confirmation says nothing about this persona's \
             claim or drain — they are different transactions"
        );
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
            claims: Vec::new(),
            drains: Vec::new(),
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
            claims: Vec::new(),
            drains: Vec::new(),
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
            vec![GlobalOutputIndex::from_raw(7)],
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
            vec![
                GlobalOutputIndex::from_raw(2),
                GlobalOutputIndex::from_raw(3),
            ],
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
        assert_eq!(
            reserved.into_iter().collect::<Vec<_>>(),
            [1, 2, 7]
                .into_iter()
                .map(GlobalOutputIndex::from_raw)
                .collect::<Vec<_>>()
        );
    }

    fn claim(persona_byte: u8, fee_gindexes: &[u64]) -> PendingEmissionClaim {
        PendingEmissionClaim {
            persona: PCanonicalId::from_bytes([persona_byte; 32]),
            tx_bytes: vec![0xCD; 16],
            fee_gindexes: fee_gindexes
                .iter()
                .copied()
                .map(GlobalOutputIndex::from_raw)
                .collect(),
            state: PendingPostState::Pending,
        }
    }

    /// The claim record's persist-before-dispatch surface: one live claim
    /// per persona, its fee gindexes join the shared reservation union
    /// (bond sweeps and claim sweeps read one exclusion set), the seal
    /// round-trips, and removal releases reservation + dedup in one
    /// mutation (idempotent under crash-replay).
    #[test]
    fn claim_records_reserve_dedup_and_round_trip() {
        let persona = PCanonicalId::from_bytes([0xAA; 32]);
        let mut block = PendingPostBlock::empty();
        assert!(block.push_post(post(0xBB, &[1])));
        assert!(block.push_claim(claim(0xAA, &[7, 9])));

        // One live claim per persona — the in-flight epoch dedup.
        assert!(block.has_live_claim_for(&persona));
        assert!(!block.push_claim(claim(0xAA, &[11])));

        // The reservation union spans posts AND claims.
        assert_eq!(
            block.reserved_gindexes().into_iter().collect::<Vec<_>>(),
            [1, 7, 9]
                .into_iter()
                .map(GlobalOutputIndex::from_raw)
                .collect::<Vec<_>>(),
        );

        // Seal-before-send transition + round-trip through postcard.
        assert_eq!(
            block
                .mark_claim_dispatched(&persona, BlockHeight::from_raw(500))
                .map(|(attempts, _)| attempts),
            Some(1)
        );
        let bytes = block.to_postcard_bytes().expect("encode");
        let back = PendingPostBlock::from_postcard_bytes(&bytes).expect("decode");
        assert_eq!(back, block);
        assert_eq!(back.claims().len(), 1);
        assert_eq!(
            back.claims()[0].state,
            PendingPostState::Dispatched {
                at: BlockHeight::from_raw(500),
                attempts: 1
            }
        );

        // Removal releases the reservation in the same mutation; re-removal
        // is idempotent.
        let removed = block.remove_claim(&persona).expect("live claim removes");
        assert_eq!(removed.persona, persona);
        assert!(!block.has_live_claim_for(&persona));
        assert_eq!(
            block.reserved_gindexes().into_iter().collect::<Vec<_>>(),
            vec![GlobalOutputIndex::from_raw(1)],
            "only the bond post's reservation remains"
        );
        assert!(block.remove_claim(&persona).is_none());
    }

    fn drain(persona_byte: u8, funding_gindexes: &[u64]) -> PendingDrain {
        PendingDrain {
            persona: PCanonicalId::from_bytes([persona_byte; 32]),
            tx_bytes: vec![0xDE; 16],
            funding_gindexes: funding_gindexes
                .iter()
                .copied()
                .map(GlobalOutputIndex::from_raw)
                .collect(),
            state: PendingPostState::Pending,
        }
    }

    /// The drain record's persist-before-dispatch surface (DS-PR-1): one live
    /// drain per persona, its **full input set** joins the shared reservation
    /// union (a drain spends every input, unlike a claim's fee-only reserve),
    /// the seal round-trips, and removal releases the reservation in one
    /// mutation (idempotent under crash-replay).
    #[test]
    fn drain_records_reserve_and_round_trip() {
        let persona = PCanonicalId::from_bytes([0xAA; 32]);
        let mut block = PendingPostBlock::empty();
        assert!(block.push_post(post(0xBB, &[1])));
        assert!(block.push_drain(drain(0xAA, &[7, 9])));

        // One live drain per persona.
        assert!(block.has_live_drain_for(&persona));
        assert!(!block.push_drain(drain(0xAA, &[11])));

        // The reservation union spans posts AND drains — and a drain reserves
        // every input, not a fee subset.
        assert_eq!(
            block.reserved_gindexes().into_iter().collect::<Vec<_>>(),
            [1, 7, 9]
                .into_iter()
                .map(GlobalOutputIndex::from_raw)
                .collect::<Vec<_>>(),
        );

        // Seal-before-send transition + round-trip through postcard.
        assert_eq!(
            block
                .mark_drain_dispatched(&persona, BlockHeight::from_raw(500))
                .map(|(attempts, _)| attempts),
            Some(1)
        );
        let bytes = block.to_postcard_bytes().expect("encode");
        let back = PendingPostBlock::from_postcard_bytes(&bytes).expect("decode");
        assert_eq!(back, block);
        assert_eq!(back.drains().len(), 1);
        assert_eq!(
            back.drains()[0].state,
            PendingPostState::Dispatched {
                at: BlockHeight::from_raw(500),
                attempts: 1
            }
        );

        // Removal releases the reservation in the same mutation; re-removal
        // is idempotent.
        let removed = block.remove_drain(&persona).expect("live drain removes");
        assert_eq!(removed.persona, persona);
        assert!(!block.has_live_drain_for(&persona));
        assert_eq!(
            block.reserved_gindexes().into_iter().collect::<Vec<_>>(),
            vec![GlobalOutputIndex::from_raw(1)],
            "only the bond post's reservation remains"
        );
        assert!(block.remove_drain(&persona).is_none());
    }

    /// A v4 seal (no drain set) under this v5 binary fails closed on the
    /// version gate — refuse-not-migrate (rule 15, pre-genesis).
    #[test]
    fn v4_seal_fails_closed_under_v5_binary() {
        // Model REAL v4 bytes, not a v5 struct with an empty `drains` vec: a v4
        // binary never wrote a `drains` field at all. postcard encodes a struct
        // as its fields concatenated with no framing, so a `(version, posts,
        // claims)` tuple is byte-identical to what the v4 layout produced. The
        // version prefix gate must refuse this on the leading `4` before it ever
        // tries (and fails at EOF) to read the absent `drains` field.
        let v4_bytes = postcard::to_allocvec(&(
            4u32,
            Vec::<PendingBondPost>::new(),
            Vec::<PendingEmissionClaim>::new(),
        ))
        .expect("encode v4-shaped bytes");
        let err = PendingPostBlock::from_postcard_bytes(&v4_bytes).expect_err("v4 must refuse");
        assert!(matches!(
            err,
            WalletLedgerError::UnsupportedBlockVersion {
                block: "pending_post_block",
                file: 4,
                binary: PENDING_POST_VERSION,
            }
        ));
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
