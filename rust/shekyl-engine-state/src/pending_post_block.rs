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
use shekyl_types::{BlockCount, BlockHeight, ChainCount, GlobalOutputIndex, PCanonicalId, PSlot};

use crate::error::WalletLedgerError;

/// Schema version of the durable pending-post block. **v13** gives every
/// record its end date and every ending a durable outcome
/// (`WALLET_RPC_STAKING_OUTCOMES.md` WR-Q2, WR-Q3, WR-Q4; the amendment of
/// `ARCHIVAL_BOND_POST_DELAY.md` BD-Q3 Rule 2): each of the four record kinds
/// gains `reference_height` (the FCMP++ reference its proof was built at, so
/// its end date is `reference_height + FCMP_REFERENCE_BLOCK_MAX_AGE`) and
/// `terminal` (the cause of a terminal daemon verdict, once one is seen; the
/// record is held, not removed), and the block gains `outcomes`, one
/// [`StakingOutcome`] per `(kind, persona)`. Pre-genesis: refuse, don't
/// migrate. **v12** retypes
/// [`PendingBondPost::bond_post_offset_blocks`] from bare `u64` to
/// [`BlockCount`] (height-semantics Phase 2e, C4; postcard bytes of the
/// transparent `u64` are identical; the schema type-name change still
/// bumps per rule 42). Pre-genesis: refuse, don't migrate. **v11** retypes the
/// dispatch-clock stamp fields (`anchor_t0`, `Dispatched::at`) from
/// ordinal `BlockHeight` to [`ChainCount`] (height-semantics Phase 2b;
/// postcard bytes of the transparent `u64` are identical; the schema
/// type-name change still bumps per rule 42). Pre-genesis: refuse, don't
/// migrate. **v10** renames the
/// v9 `PendingUnbond` record set to [`PendingRelease`] (the internal
/// Unbond → Release vocabulary rename; wire `BondPostKind` discriminant `2`
/// unchanged) — the terminal exit's persist-before-dispatch
/// sibling (the `submit_release` dispatch seam): a `Release` spends `P`-funding
/// inputs, so all of its input gindexes must be reserved durably **before**
/// the bytes reach any submitter, exactly as a drain reserves its inputs. It
/// is deliberately NOT a [`PendingBondPost`]: the exit draws no decorrelation
/// offset (its trigger — a cooldown expiring — is already public), so it must
/// not enter WI-3's due-check/dispatch plan, and its confirmation observable
/// is reservation-shaped ([`PendingPostBlock::remove_settled`]) rather than a
/// pscan bond-post match ([`PendingPostBlock::remove_confirmed`]). **v8** adds
/// the persisted `generation` reservation-release counter (see its field
/// docs): release-then-reseal races are invisible to the set-union check, so
/// the seal compares against the count the assembly snapshotted. **v6** REMOVES
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
pub const PENDING_POST_VERSION: u32 = 13;

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
        /// Claimed chain **count** the due-check fired against at the first
        /// send (WI-3 R2-1 clock; not an ordinal).
        at: ChainCount,
        /// Total send attempts (first send inclusive); bumped on every
        /// byte-identical resubmit, bounded by the driver's attempt budget.
        attempts: u32,
    },
}

/// The cause of a terminal daemon verdict, as the pending record keeps it.
///
/// The persisted twin of engine-core's `TerminalErrorKind`, which this crate
/// cannot name (rule 18: the state-shaped copy lives with the record that
/// persists it). Engine-core converts into it; a cause that conversion does
/// not know becomes [`Self::Unrecognized`], so a future engine-side variant
/// can never fail to persist.
///
/// A recorded cause never ends a record (BD-Q3 Rule 2): the chain decides at
/// the end date. It decides only what the outcome says if the record did not
/// land, and it stops further sends.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub enum TerminalCause {
    /// An input was already spent on the chain the daemon saw.
    DoubleSpend,
    /// The fee was below the daemon's relay floor.
    FeeTooLow,
    /// The daemon found the transaction structurally invalid.
    Malformed,
    /// The daemon gave a cause this wallet build does not know.
    Unrecognized,
    /// The daemon cannot admit a JoinMarket bond post (until `DEL-008`).
    JoinMarketUnsupported,
}

/// Which kind of pending record an outcome is about. Public, unlike the
/// seal classifier's private kind: the seal methods still choose the kind,
/// and this one only names it in an outcome.
#[derive(
    Clone,
    Copy,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    postcard_schema::Schema,
)]
pub enum RecordKind {
    /// A bond post (a stake).
    Post,
    /// An emission claim.
    Claim,
    /// A `P`→principal drain.
    Drain,
    /// A terminal `Release` exit.
    Release,
}

/// How a pending record ended without landing (WR-Q2). A record that landed
/// leaves no outcome: confirmation and settlement are the ordinary paths.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub enum OutcomeKind {
    /// A terminal verdict was seen and the record reached its end date
    /// without landing. Its reservation was returned.
    Rejected(TerminalCause),
    /// The end date passed with every reserved input still live: the
    /// transaction never landed. Its reservation was returned.
    Expired,
    /// The end date passed for a record that reserves no inputs (the Q11
    /// zero-fee emission claim), whose landing the scan cannot see. Nothing
    /// was held. A terminal verdict does not make it `Rejected`, because a
    /// daemon can relay what it refused and the scan could not tell; the
    /// cause, if one was recorded, is kept so its sentence can be shown.
    EndedUnconfirmed(Option<TerminalCause>),
    /// The end date passed with the record's reserved inputs partly spent
    /// by another transaction. Nothing outside the wallet can spend `P`'s
    /// outputs, so this is a wallet bug or a compromised key. The unspent
    /// rest was returned.
    SpentElsewhere,
}

/// The durable last outcome for one `(kind, persona)` (WR-Q2).
///
/// Written in the same seal that removes the record, replaced by a later
/// ending of the same kind for the same persona, and cleared by that
/// persona's next admitted seal of the kind or by an acknowledgement
/// ([`PendingPostBlock::acknowledge_outcomes`]). A `spent_elsewhere`
/// outcome is the exception: neither a later ending nor a new seal touches
/// it, and only an acknowledgement clears it.
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct StakingOutcome {
    /// The record kind that ended.
    pub kind: RecordKind,
    /// The persona whose record ended.
    pub persona: PCanonicalId,
    /// How it ended.
    pub outcome: OutcomeKind,
    /// The tip height when the outcome was written.
    pub at_height: BlockHeight,
    /// Whether the record's bytes may have reached a daemon: its state
    /// reached `Dispatched`, which is sealed *before* the first send, or a
    /// daemon answered it with a terminal verdict. A first send that died in
    /// transport still counts, the same "maybe sent" reading as
    /// `Dispatched` itself, so the linkage sentence errs toward warning.
    /// Only a sent record published its inputs' key images, so only its
    /// ending carries that sentence (WR-Q5); a post that reached its end
    /// date before it was due was never seen.
    pub sent: bool,
}

impl std::fmt::Debug for StakingOutcome {
    /// Redacted for the same reason as [`PendingBondPost`]: an outcome ties a
    /// persona to an ending, which is `P`-side history.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StakingOutcome(<redacted outcome>)")
    }
}

/// A record's end date: the last height at which a block can include its
/// transaction, `reference_height + max_age`, inclusive. Past it, every
/// daemon refuses the reference as too old, on every chain.
///
/// `max_age` is the consensus `FCMP_REFERENCE_BLOCK_MAX_AGE`, passed by the
/// caller, which also pins it (WR-Q3's invariant: the end date assumes the
/// limit never rises). Saturating: an overflowing end date never arrives,
/// which only holds funds longer.
#[must_use]
pub const fn end_date(reference_height: BlockHeight, max_age: BlockCount) -> BlockHeight {
    reference_height.saturating_add(max_age)
}

/// Whether a record reserves inputs and every one of them is gone from the
/// live funding set.
fn all_reserved_gone(
    reserved: &[GlobalOutputIndex],
    live: &std::collections::BTreeSet<GlobalOutputIndex>,
) -> bool {
    !reserved.is_empty() && reserved.iter().all(|g| !live.contains(g))
}

/// What [`PendingPostBlock::release_ended`] released, one entry per record.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EndedRelease {
    /// `(kind, persona, outcome)` for every record released this call.
    pub released: Vec<(RecordKind, PCanonicalId, OutcomeKind)>,
}

impl EndedRelease {
    /// Nothing reached its end date this call.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.released.is_empty()
    }
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
    /// Blocks from `anchor_t0` to the bond-post broadcast — a span
    /// ([`BlockCount`]), on the same clock as `anchor_t0`.
    ///
    /// ```
    /// fn needs_span(offset: shekyl_types::BlockCount) {}
    /// fn check(post: &shekyl_engine_state::PendingBondPost) {
    ///     needs_span(post.bond_post_offset_blocks);
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// // HEIGHT_SEMANTICS.md C9: the due-count offset is a span, not an ordinal.
    /// fn needs_height(_: shekyl_types::BlockHeight) {}
    /// fn check(post: &shekyl_engine_state::PendingBondPost) {
    ///     needs_height(post.bond_post_offset_blocks);
    /// }
    /// ```
    pub bond_post_offset_blocks: BlockCount,
    /// Claimed chain **count** at assemble time — the private intent
    /// anchor `t0` the plan's offsets are relative to. WI-3's due-check
    /// is pure: `due = anchor_t0 + bond_post_offset_blocks` on this
    /// count clock (not an ordinal).
    pub anchor_t0: ChainCount,
    /// Global output indexes of the funding outputs this post spends — the
    /// reservation set: funding selection excludes these while the post is
    /// live (`ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.2 rule 1).
    pub funding_gindexes: Vec<GlobalOutputIndex>,
    /// Dispatch state (WI-2: always [`PendingPostState::Pending`]).
    pub state: PendingPostState,
    /// The height of the FCMP++ reference the bytes were proved against. The
    /// record's end date is [`end_date`] of it (WR-Q3).
    pub reference_height: BlockHeight,
    /// The cause of a terminal daemon verdict, once one is seen. The record
    /// is held to its end date regardless (BD-Q3 Rule 2); this only stops
    /// further sends and names the outcome.
    pub terminal: Option<TerminalCause>,
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
    /// The height of the FCMP++ reference the bytes were proved against: the
    /// backing's membership path is assembled against it even when the claim
    /// sweeps no fee inputs (see [`PendingBondPost::reference_height`]).
    pub reference_height: BlockHeight,
    /// A terminal verdict's cause, once seen (see [`PendingBondPost::terminal`]).
    pub terminal: Option<TerminalCause>,
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
    /// The height of the FCMP++ reference the bytes were proved against
    /// (see [`PendingBondPost::reference_height`]).
    pub reference_height: BlockHeight,
    /// A terminal verdict's cause, once seen (see [`PendingBondPost::terminal`]).
    pub terminal: Option<TerminalCause>,
}

impl std::fmt::Debug for PendingDrain {
    /// Redacted for the same reason as [`PendingBondPost`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingDrain(<redacted pending-drain>)")
    }
}

/// One durable pending **`Release` exit** (gate-4 §3.5 / the `submit_release`
/// dispatch seam): the assembled, signed, wire-encoded exit bytes bound to
/// their persona and the funding reservation they hold — sealed **before**
/// dispatch (persist-before-dispatch, the drain's sibling: a retry re-sends
/// these stored bytes, and the reservation exists durably before any network
/// send).
///
/// Like [`PendingDrain`] (and unlike a claim's proven-not-spent backing), an
/// exit **spends every one of its funding inputs**, so `funding_gindexes` is
/// the whole input set and the whole reservation — the released bond
/// collateral is a *debit term inside the tx*, not an input with a gindex. It
/// carries no timing plan: the exit deliberately draws no decorrelation
/// offset (the event it follows — a release cooldown expiring — is already
/// public on-chain), which is why this is not a [`PendingBondPost`] and never
/// enters WI-3's due-check. A live release record means those gindexes are
/// reserved and the persona has its one terminal exit in flight
/// ([`PendingPostBlock::has_live_release_for`]).
///
/// Same redacted-`Debug` class as [`PendingBondPost`]: persona, funding
/// placement, and exit timing are `P`-side behavioral history.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct PendingRelease {
    /// The persona the exit bytes are bound to. Keyed on throughout
    /// (`has_live_release_for` / reservation settlement).
    pub persona: PCanonicalId,
    /// The fully-assembled, signed, wire-encoded exit bytes — the value
    /// itself: retries re-send these stored bytes, never a re-encode.
    pub tx_bytes: Vec<u8>,
    /// Global output indexes of the funding outputs this exit spends — the
    /// reservation this exit holds while live (the full input set; the
    /// released collateral is a debit term, not an input).
    pub funding_gindexes: Vec<GlobalOutputIndex>,
    /// Dispatch state — same lifecycle as the drain's.
    pub state: PendingPostState,
    /// The height of the FCMP++ reference the bytes were proved against
    /// (see [`PendingBondPost::reference_height`]).
    pub reference_height: BlockHeight,
    /// A terminal verdict's cause, once seen (see [`PendingBondPost::terminal`]).
    pub terminal: Option<TerminalCause>,
}

impl std::fmt::Debug for PendingRelease {
    /// Redacted for the same reason as [`PendingBondPost`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingRelease(<redacted pending-release>)")
    }
}

/// Which pending record a seal attempt is for. Private: the kind is chosen by
/// the `seal_*` method the caller picks, never passed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingKind {
    /// A bond post.
    Post,
    /// An emission claim.
    Claim,
    /// A `P`→principal drain.
    Drain,
    /// A terminal `Release` exit.
    Release,
}

/// What `PendingPostBlock`'s seal classifier decided about a seal attempt.
///
/// The two refusals carry **contradictory remedies**, which is the whole reason
/// they are separate and the whole reason their order matters:
/// [`Self::PersonaLive`] means *wait* — retrying cannot help until the live
/// record retires — while [`Self::InputRaced`] means *retry*, because the next
/// assembly reads the current reservation set and selects around the taken
/// input. Handing a caller the wrong one sends it into a loop or a stall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealAdmission {
    /// No live record of this kind for this persona, and no gindex overlap.
    Admit,
    /// This persona already holds a live record of this kind (the authoritative
    /// one-per-persona-per-kind refusal).
    PersonaLive,
    /// Another live record — of any kind — already reserves one of these
    /// gindexes.
    InputRaced,
    /// A reservation was **released** between the assembly's snapshot and this
    /// seal, so the snapshot the inputs were selected against is no longer
    /// current. The released record may have confirmed and spent inputs this
    /// assembly still believes are fundable; admitting it would seal a
    /// transaction the network will reject, whose absent inputs the next
    /// settlement tick would then misread as its own confirmation.
    ///
    /// Same remedy as [`Self::InputRaced`] — retry against a fresh snapshot —
    /// but a distinct cause, and the only one the union check cannot see.
    Stale,
}

/// What [`PendingPostBlock::remove_settled`] retired, split by kind.
///
/// One vector per kind rather than one merged list: the caller logs and books
/// them separately (a retired claim releases the epoch-dedup gate, a retired
/// drain the one-live-drain lane, a retired release the one-live-exit lane),
/// and merging them would force a second lookup to tell which gate just
/// opened.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SettledRetirement {
    /// Personas whose live emission claim settled.
    pub claims: Vec<PCanonicalId>,
    /// Personas whose live `P`→principal drain settled.
    pub drains: Vec<PCanonicalId>,
    /// Personas whose live terminal `Release` exit settled.
    pub releases: Vec<PCanonicalId>,
}

impl SettledRetirement {
    /// Nothing retired this tick — the common case, and the one the caller
    /// short-circuits on rather than sealing an unchanged block.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.claims.is_empty() && self.drains.is_empty() && self.releases.is_empty()
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
    /// **Monotonic count of reservation-releasing OPERATIONS.** Bumped once by
    /// every method call that drops at least one live record, and compared at
    /// `classify_seal` against the value an assembly read when it snapshotted
    /// the reservation set.
    ///
    /// Counting operations rather than records is deliberate: only inequality
    /// is ever read, so the magnitude carries no meaning, and counting records
    /// would need a `usize`→`u64` conversion whose saturating arm fails *open*
    /// — a counter pinned at its maximum stops refusing anything.
    ///
    /// The union check sees reservations that are *present*; this makes
    /// reservations that were *released* visible. Comparing the reservation
    /// sets themselves cannot: a record that seals, confirms and retires during
    /// an assembly returns the set to exactly its snapshot value, so the
    /// snapshot and the seal read as identical while the inputs behind them
    /// have been spent. Only a monotonic counter distinguishes "unchanged" from
    /// "changed back".
    ///
    /// Persisted rather than in-memory because the engine's pending-post store
    /// reloads the block from the seal on every read and every mutation — an
    /// unpersisted counter would reset to zero on each load and never refuse
    /// anything.
    generation: u64,
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
    /// The live pending terminal `Release` exits. At most one per persona
    /// (the exit seam refuses a second — the exit debits the record's whole
    /// bonded total, so a second is doomed by construction).
    releases: Vec<PendingRelease>,
    /// The durable last outcome per `(kind, persona)`: at most one entry per
    /// pair (WR-Q2).
    outcomes: Vec<StakingOutcome>,
}

impl std::fmt::Debug for PendingPostBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingPostBlock")
            .field("version", &self.version)
            // Redacted like the record collections, and for the same reason
            // this type already gives above: a count IS `P`-activity volume.
            // This one is a lifetime total of settled records, so it is
            // strictly more telling than the in-flight count the doc names.
            // The field is kept so a reader can see the guard exists.
            .field("generation", &"<redacted release count>")
            .field("posts", &"<redacted pending-posts>")
            .field("claims", &"<redacted pending-claims>")
            .field("drains", &"<redacted pending-drains>")
            .field("releases", &"<redacted pending-releases>")
            .field("outcomes", &"<redacted outcomes>")
            .finish()
    }
}

impl Default for PendingPostBlock {
    fn default() -> Self {
        Self::empty()
    }
}

impl PendingPostBlock {
    /// A fresh block with no pending posts, claims, drains, or releases.
    pub fn empty() -> Self {
        Self {
            version: PENDING_POST_VERSION,
            generation: 0,
            posts: Vec::new(),
            claims: Vec::new(),
            drains: Vec::new(),
            releases: Vec::new(),
            outcomes: Vec::new(),
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

    /// The live pending terminal `Release` exits.
    pub fn releases(&self) -> &[PendingRelease] {
        &self.releases
    }

    /// Whether `persona` already has a live pending `Release` exit — the exit
    /// seam's one-live-exit-per-persona refusal predicate (the exit debits
    /// the record's whole bonded total, so a second is doomed by
    /// construction; wait for the live one to settle).
    pub fn has_live_release_for(&self, persona: &PCanonicalId) -> bool {
        self.releases.iter().any(|u| &u.persona == persona)
    }

    /// Every funding gindex reserved by a live post, a live claim's fee
    /// sweep, a live drain's input set, **or a live `Release` exit's input
    /// set** — the exclusion set for funding selection
    /// (`ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.2 rule 1): no bond sweep, claim
    /// fee sweep, drain, or exit may select an output an in-flight tx already
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
            .chain(
                self.releases
                    .iter()
                    .flat_map(|u| u.funding_gindexes.iter().copied()),
            )
            .collect()
    }

    /// Append a pending post. Refuses (returns `false`, block unchanged) if
    /// the persona already has a live post — the caller surfaces this as its
    /// typed `PendingPostExists` error.
    #[must_use]
    /// **Test seeding only** (`#[cfg(test)]`), like its two siblings.
    ///
    /// These insert on persona dedup alone — no cross-kind overlap check, no
    /// generation comparison — so they can stage states the guards exist to
    /// prevent. That is a legitimate thing for a test to need and an
    /// illegitimate thing for production to reach, which is why they are
    /// compiled out of the library entirely rather than merely made private.
    /// Production has exactly one insertion path: the `seal_*` methods, over
    /// `classify_seal`.
    #[cfg(test)]
    fn push_post(&mut self, post: PendingBondPost) -> bool {
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
    #[cfg(test)]
    fn push_claim(&mut self, claim: PendingEmissionClaim) -> bool {
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
        at: ChainCount,
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
        self.generation += 1;
        Some(self.claims.remove(idx))
    }

    /// Append a pending drain. Refuses (returns `false`, block unchanged) if
    /// the persona already has a live drain — the caller surfaces this as its
    /// typed drain-pending error.
    #[must_use]
    #[cfg(test)]
    fn push_drain(&mut self, drain: PendingDrain) -> bool {
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
        at: ChainCount,
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
        self.generation += 1;
        Some(self.drains.remove(idx))
    }

    /// Remove `persona`'s live `Release` exit — the terminal-reject release
    /// (the `submit_release` seam prunes the record it just sealed when the
    /// daemon's FIRST-send verdict is `RejectedTerminal`: a definite refusal
    /// means the bytes were never admitted or relayed, so holding the
    /// reservation would brick the persona's one-live-exit lane on a
    /// transaction that cannot confirm). Removal *is* the byte-prune and the
    /// reservation release in one seal — the generation bump makes the
    /// release visible to any assembly snapshotted across it; idempotent
    /// under crash-replay (`None` when absent).
    #[must_use]
    pub fn remove_release(&mut self, persona: &PCanonicalId) -> Option<PendingRelease> {
        let idx = self.releases.iter().position(|u| &u.persona == persona)?;
        self.generation += 1;
        Some(self.releases.remove(idx))
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
        at: ChainCount,
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
        self.generation += 1;
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
        if !retired.is_empty() {
            self.generation += 1;
        }
        retired
    }

    /// The reservation-release counter an assembly must carry from its
    /// snapshot to its seal. See the field docs for why a counter rather than a
    /// set comparison.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Classify a seal attempt **under the write lock**, in the one order that
    /// gives each refusal its documented remedy.
    ///
    /// Persona dedup is checked FIRST and is authoritative. Two same-persona
    /// assemblies select the same deterministic inputs, so the second would
    /// *also* trip the gindex overlap — and reporting that as `InputRaced`
    /// tells the caller to retry when the truth is "wait for the live record to
    /// retire". Retrying cannot help; the remedies are opposites. Overlap is
    /// therefore only ever reported for what it actually means: a **cross-kind**
    /// collision, where some other kind of record took the input.
    ///
    /// Both checks live here rather than at the seams because every seam
    /// needs the identical decision and the original three had been
    /// hand-rolling it — the drain seam with this same inverted order, and
    /// the claim and bond-post seams (until review #572) with no overlap
    /// check at all; the release seam (the fourth writer, PR #601) was born
    /// onto the shared decision. One implementation cannot drift from
    /// itself.
    ///
    /// Private, and reached only through [`Self::seal_post`],
    /// [`Self::seal_claim`], [`Self::seal_drain`], and [`Self::seal_release`]:
    /// a seam that could classify without sealing could also seal without
    /// classifying.
    ///
    /// The overlap half is [`Self::remove_settled`]'s premise, not local
    /// hygiene: that retire reads "the inputs this record reserved are gone" as
    /// proof this record's transaction confirmed, which holds only while one
    /// live record can hold a given gindex.
    #[must_use]
    fn classify_seal(
        &self,
        kind: PendingKind,
        persona: &PCanonicalId,
        gindexes: &[GlobalOutputIndex],
        snapshot_generation: u64,
    ) -> SealAdmission {
        // A current-state fact, true regardless of how old the snapshot is.
        let live = match kind {
            PendingKind::Post => self.has_live_post_for(persona),
            PendingKind::Claim => self.has_live_claim_for(persona),
            PendingKind::Drain => self.has_live_drain_for(persona),
            PendingKind::Release => self.has_live_release_for(persona),
        };
        if live {
            return SealAdmission::PersonaLive;
        }
        // Only now ask whether the snapshot is still a basis worth reasoning
        // from. A conclusion drawn from a stale reservation set — including
        // "these gindexes are free" — is not evidence, so this precedes the
        // union check rather than following it.
        if snapshot_generation != self.generation {
            return SealAdmission::Stale;
        }
        let reserved = self.reserved_gindexes();
        if gindexes.iter().any(|g| reserved.contains(g)) {
            return SealAdmission::InputRaced;
        }
        SealAdmission::Admit
    }

    /// Seal a bond post: classify, and insert it iff admitted.
    ///
    /// Deciding and inserting are one call because splitting them let each seam
    /// re-derive the outcome from `push_post`'s bool — and after an `Admit` that
    /// bool can only be `true`, so the `false` arm was dead code that reported
    /// the *wait* remedy for what could only have been an internal break. There
    /// is no bool here to re-derive from: the insert is unconditional on the
    /// admitted path, because `classify_seal` is what establishes the
    /// one-live-per-persona-per-kind precondition `push_post` would re-check.
    pub fn seal_post(&mut self, post: PendingBondPost, snapshot_generation: u64) -> SealAdmission {
        match self.classify_seal(
            PendingKind::Post,
            &post.persona,
            &post.funding_gindexes,
            snapshot_generation,
        ) {
            SealAdmission::Admit => {}
            refused => return refused,
        }
        self.replace_outcome(RecordKind::Post, &post.persona);
        self.posts.push(post);
        SealAdmission::Admit
    }

    /// Seal an emission claim and stamp it `Dispatched` at `at`, the sibling of
    /// [`Self::seal_post`].
    ///
    /// The record enters the block already dispatched rather than being pushed
    /// `Pending` and transitioned by a second call. That is the same end state
    /// the two-call form reached, minus the instant in between: this block is
    /// persisted *before* the network send, so a `Pending` record that the
    /// seam still owed a transition to could be persisted by a concurrent
    /// writer's flush and read back as never-dispatched.
    pub fn seal_claim(
        &mut self,
        mut claim: PendingEmissionClaim,
        at: ChainCount,
        snapshot_generation: u64,
    ) -> SealAdmission {
        match self.classify_seal(
            PendingKind::Claim,
            &claim.persona,
            &claim.fee_gindexes,
            snapshot_generation,
        ) {
            SealAdmission::Admit => {}
            refused => return refused,
        }
        claim.state = PendingPostState::Dispatched { at, attempts: 1 };
        self.replace_outcome(RecordKind::Claim, &claim.persona);
        self.claims.push(claim);
        SealAdmission::Admit
    }

    /// Seal a `P`→principal drain and stamp it `Dispatched` at `at`, the
    /// sibling of [`Self::seal_claim`].
    pub fn seal_drain(
        &mut self,
        mut drain: PendingDrain,
        at: ChainCount,
        snapshot_generation: u64,
    ) -> SealAdmission {
        match self.classify_seal(
            PendingKind::Drain,
            &drain.persona,
            &drain.funding_gindexes,
            snapshot_generation,
        ) {
            SealAdmission::Admit => {}
            refused => return refused,
        }
        drain.state = PendingPostState::Dispatched { at, attempts: 1 };
        self.replace_outcome(RecordKind::Drain, &drain.persona);
        self.drains.push(drain);
        SealAdmission::Admit
    }

    /// Seal a terminal `Release` exit and stamp it `Dispatched` at `at`, the
    /// sibling of [`Self::seal_drain`]: the exit draws no decorrelation
    /// offset, so like the claim and the drain — and unlike the bond post —
    /// it is dispatched by its own seam immediately after this seal, and the
    /// record enters the block already `Dispatched` (see [`Self::seal_claim`]
    /// for why the two-call form is refused).
    pub fn seal_release(
        &mut self,
        mut release: PendingRelease,
        at: ChainCount,
        snapshot_generation: u64,
    ) -> SealAdmission {
        match self.classify_seal(
            PendingKind::Release,
            &release.persona,
            &release.funding_gindexes,
            snapshot_generation,
        ) {
            SealAdmission::Admit => {}
            refused => return refused,
        }
        release.state = PendingPostState::Dispatched { at, attempts: 1 };
        self.replace_outcome(RecordKind::Release, &release.persona);
        self.releases.push(release);
        SealAdmission::Admit
    }

    /// Confirmation retire for the **reservation-observed** kinds — claims,
    /// drains, and `Release` exits — the sibling of [`Self::remove_confirmed`].
    ///
    /// A bond post is retired against a direct on-chain observation of itself
    /// (`confirmed_join_market_personas`: the pscan matched the post). Claims,
    /// drains, and exits have no such match set, so their settlement is observed
    /// **through their reservation**: each spends the funding outputs it holds,
    /// so once every reserved gindex has left the accrual's live funding set,
    /// the transaction that spent them confirmed.
    ///
    /// That inference is sound only while the reservation makes the record the
    /// *sole* possible spender inside this wallet. Four things together give
    /// that, and this doc has twice asserted a subset — each time the missing
    /// piece was one that fails silently:
    ///
    /// 1. **One live record per persona, per kind.** True, and on its own not
    ///    sufficient: it says nothing about a *cross-kind* gindex collision.
    /// 2. **Every insertion goes through `classify_seal`**, which adds
    ///    the cross-kind overlap refusal, inside the same locked mutate that
    ///    performs the insert. The drain seam re-read the union; the claim and
    ///    bond-post seams did not until review #572, so two records could
    ///    reserve one gindex and either confirming would retire both. The
    ///    `seal_*` methods are now the only way in — the raw `push_*` inserters are
    ///    private — so a fourth writer cannot reintroduce the gap, and
    ///    `every_reservation_writer_rechecks_the_union_under_the_seal_lock`
    ///    names the seam if one tries.
    /// 3. **The generation guard**, because (2) still only compares against
    ///    reservations that are *present*. A record that seals, confirms and
    ///    retires inside another assembly's window frees its gindex, so that
    ///    assembly's overlap check passes and it seals against an input the
    ///    retired record already spent — whose absence this method would then
    ///    read as the new record's own confirmation. Comparing reservation sets
    ///    cannot see it (the release returns the set to its snapshot value); a
    ///    monotonic counter can. Its two halves must also be read in order —
    ///    pending block before pscan seal — or stale funding pairs with a
    ///    current generation and the hole reopens (`load_seal_basis`).
    /// 4. **Pin P-2**: a retry re-sends the same bytes rather than building a
    ///    competing transaction. Nothing outside the wallet can spend `P`'s
    ///    outputs at all.
    ///
    /// With all four, "these inputs are gone" and "this record's transaction
    /// confirmed" are the same fact. Without (2) or (3) they are not, which is
    /// why both guards are part of this method's contract rather than local
    /// hygiene at the seams.
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
        self.releases.retain(|release| {
            if settled(&release.funding_gindexes, live_funding) {
                out.releases.push(release.persona);
                false
            } else {
                true
            }
        });
        if !out.is_empty() {
            self.generation += 1;
        }
        out
    }

    /// The durable outcomes, one per `(kind, persona)` (WR-Q2).
    pub fn outcomes(&self) -> &[StakingOutcome] {
        &self.outcomes
    }

    /// Record the cause of a terminal daemon verdict on `persona`'s live
    /// record of `kind` (BD-Q3 Rule 2). The record and its reservation stay;
    /// a recorded cause stops further sends and names the outcome if the
    /// record reaches its end date without landing. The first cause seen is
    /// kept. Returns `true` when this call recorded it.
    #[must_use]
    pub fn record_terminal(
        &mut self,
        kind: RecordKind,
        persona: &PCanonicalId,
        cause: TerminalCause,
    ) -> bool {
        let slot = match kind {
            RecordKind::Post => self
                .posts
                .iter_mut()
                .find(|r| &r.persona == persona)
                .map(|r| &mut r.terminal),
            RecordKind::Claim => self
                .claims
                .iter_mut()
                .find(|r| &r.persona == persona)
                .map(|r| &mut r.terminal),
            RecordKind::Drain => self
                .drains
                .iter_mut()
                .find(|r| &r.persona == persona)
                .map(|r| &mut r.terminal),
            RecordKind::Release => self
                .releases
                .iter_mut()
                .find(|r| &r.persona == persona)
                .map(|r| &mut r.terminal),
        };
        match slot {
            Some(t @ None) => {
                *t = Some(cause);
                true
            }
            _ => false,
        }
    }

    /// Release every record whose end date the sealed scan has covered,
    /// writing its outcome in the same mutation (WR-Q3, WR-Q4).
    ///
    /// `scanned_through` is the highest height the sealed scan has covered,
    /// **inclusive**. The scan's own frontier is exclusive (the first
    /// unscanned height), so the caller passes one below it: a record is
    /// released only once the block at its end date has itself been
    /// scanned, since that block can still include the transaction.
    ///
    /// **Call it after [`Self::remove_confirmed`] and [`Self::remove_settled`],
    /// in the same pass and over the same evidence.** A record that landed has
    /// landed at or below its end date, so once the scan has covered the end
    /// date those two retires have already removed it; what is left here did
    /// not land. Two guards keep that true even if the order slips: a
    /// reservation-kind record whose every reserved input is gone is left for
    /// [`Self::remove_settled`], and a post whose every reserved input is gone
    /// is held (below).
    ///
    /// **A post whose every reserved input is gone is held, never released.**
    /// A transaction spends all of its inputs or none, so it is either the
    /// post itself, landed with no match seen, or one other transaction that
    /// spent them all. Releasing it would return nothing and would remove the
    /// pending record the phantom-slot cleanup reads as its bridge
    /// (`engine/stake_persist.rs` `reconcile_phantom_bonded_slots`): if the
    /// post did land, its slot would be dropped and could never be adopted
    /// again. [`Self::held_spent_posts`] names such posts, so the integrity
    /// alarm is re-derived from this durable state.
    ///
    /// The outcome, in precedence order:
    ///
    /// | Evidence at `scanned_through` | Outcome |
    /// | --- | --- |
    /// | a post with every reserved input gone | held: no outcome, not released |
    /// | some reserved input gone, not all | [`OutcomeKind::SpentElsewhere`] |
    /// | the record reserves no inputs (the Q11 zero-fee claim) | [`OutcomeKind::EndedUnconfirmed`], with the cause if one was recorded |
    /// | a terminal verdict was recorded | [`OutcomeKind::Rejected`] |
    /// | every reserved input still live | [`OutcomeKind::Expired`] |
    ///
    /// Releasing is safe at the end date because no block above it can
    /// include the transaction and every block at or below it is inside the
    /// sealed, reorg-deep scan the evidence came from.
    #[must_use]
    pub fn release_ended(
        &mut self,
        scanned_through: BlockHeight,
        live_funding: &std::collections::BTreeSet<GlobalOutputIndex>,
        max_age: BlockCount,
        at_height: BlockHeight,
    ) -> EndedRelease {
        /// `None`: not ended, or settled (left for `remove_settled`).
        fn classify(
            reference_height: BlockHeight,
            reserved: &[GlobalOutputIndex],
            terminal: Option<TerminalCause>,
            scanned_through: BlockHeight,
            live: &std::collections::BTreeSet<GlobalOutputIndex>,
            max_age: BlockCount,
        ) -> Option<OutcomeKind> {
            if scanned_through < end_date(reference_height, max_age) {
                return None;
            }
            // Every reserved input gone: a reservation-kind record settled
            // (`remove_settled`'s), and a post is held (see above).
            if all_reserved_gone(reserved, live) {
                return None;
            }
            let gone = reserved.iter().filter(|g| !live.contains(g)).count();
            Some(if gone > 0 {
                OutcomeKind::SpentElsewhere
            } else if reserved.is_empty() {
                OutcomeKind::EndedUnconfirmed(terminal)
            } else if let Some(cause) = terminal {
                OutcomeKind::Rejected(cause)
            } else {
                OutcomeKind::Expired
            })
        }

        let mut out = EndedRelease::default();
        let mut sent_flags = Vec::new();
        let mut take = |kind: RecordKind,
                        persona: PCanonicalId,
                        state: PendingPostState,
                        terminal: Option<TerminalCause>,
                        outcome: Option<OutcomeKind>| {
            outcome.is_some_and(|outcome| {
                out.released.push((kind, persona, outcome));
                sent_flags.push(
                    matches!(state, PendingPostState::Dispatched { .. }) || terminal.is_some(),
                );
                true
            })
        };
        self.posts.retain(|r| {
            let o = classify(
                r.reference_height,
                &r.funding_gindexes,
                r.terminal,
                scanned_through,
                live_funding,
                max_age,
            );
            !take(RecordKind::Post, r.persona, r.state, r.terminal, o)
        });
        self.claims.retain(|r| {
            let o = classify(
                r.reference_height,
                &r.fee_gindexes,
                r.terminal,
                scanned_through,
                live_funding,
                max_age,
            );
            !take(RecordKind::Claim, r.persona, r.state, r.terminal, o)
        });
        self.drains.retain(|r| {
            let o = classify(
                r.reference_height,
                &r.funding_gindexes,
                r.terminal,
                scanned_through,
                live_funding,
                max_age,
            );
            !take(RecordKind::Drain, r.persona, r.state, r.terminal, o)
        });
        self.releases.retain(|r| {
            let o = classify(
                r.reference_height,
                &r.funding_gindexes,
                r.terminal,
                scanned_through,
                live_funding,
                max_age,
            );
            !take(RecordKind::Release, r.persona, r.state, r.terminal, o)
        });
        if !out.is_empty() {
            self.generation += 1;
            for (&(kind, persona, outcome), sent) in out.released.iter().zip(sent_flags) {
                self.replace_outcome(kind, &persona);
                self.outcomes.push(StakingOutcome {
                    kind,
                    persona,
                    outcome,
                    at_height,
                    sent,
                });
            }
        }
        out
    }

    /// Posts held at their end date because every reserved input is gone
    /// and no confirmation retired them (see [`Self::release_ended`]). The
    /// same predicate the release uses, over the same evidence, so the
    /// integrity alarm and the read view agree with what the release kept.
    ///
    /// Run it over evidence from which confirmed posts are already excluded:
    /// a post whose match the scan has sealed is the dispatch tick's to
    /// retire, not a held post.
    pub fn held_spent_posts<'a>(
        &'a self,
        scanned_through: BlockHeight,
        live_funding: &'a std::collections::BTreeSet<GlobalOutputIndex>,
        max_age: BlockCount,
    ) -> impl Iterator<Item = &'a PendingBondPost> + 'a {
        self.posts.iter().filter(move |p| {
            scanned_through >= end_date(p.reference_height, max_age)
                && all_reserved_gone(&p.funding_gindexes, live_funding)
        })
    }

    /// Clear every outcome of `kind`, for every persona, written at or below
    /// `through_height` (the acknowledgement, WR-Q2 as ruled 2026-10-17).
    /// The height is the newest ending the owner was shown, so an ending
    /// written after that is never cleared unseen. Returns how many were
    /// cleared; acknowledging twice clears nothing the second time.
    #[must_use]
    pub fn acknowledge_outcomes(&mut self, kind: RecordKind, through_height: BlockHeight) -> usize {
        let before = self.outcomes.len();
        self.outcomes
            .retain(|o| !(o.kind == kind && o.at_height <= through_height));
        before - self.outcomes.len()
    }

    /// A new seal or a new ending of `kind` for `persona` replaces its last
    /// outcome, except `spent_elsewhere`: that one is an integrity signal and
    /// clears only on acknowledgement.
    fn replace_outcome(&mut self, kind: RecordKind, persona: &PCanonicalId) {
        self.outcomes.retain(|o| {
            !(o.kind == kind && &o.persona == persona) || o.outcome == OutcomeKind::SpentElsewhere
        });
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

    /// The reference every test record is built at. Its end date under the
    /// consensus limit is `TEST_REFERENCE + TEST_MAX_AGE`.
    const TEST_REFERENCE: BlockHeight = BlockHeight::from_raw(5_000);
    const TEST_MAX_AGE: BlockCount = BlockCount::from_raw(100);
    const TEST_END: BlockHeight = BlockHeight::from_raw(5_100);

    fn post(persona_byte: u8, gindexes: &[u64]) -> PendingBondPost {
        PendingBondPost {
            p_slot: PSlot::from_raw(0),
            persona: PCanonicalId::from_bytes([persona_byte; 32]),
            tx_bytes: vec![0xAB; 16],
            bond_post_offset_blocks: BlockCount::from_raw(12),
            anchor_t0: ChainCount::from_raw(1_000),
            funding_gindexes: gindexes
                .iter()
                .copied()
                .map(GlobalOutputIndex::from_raw)
                .collect(),
            state: PendingPostState::Pending,
            reference_height: TEST_REFERENCE,
            terminal: None,
        }
    }

    /// **Persona dedup outranks overlap, because their remedies are opposites.**
    ///
    /// Two same-persona assemblies select the same deterministic inputs, so the
    /// second trips BOTH conditions. Reporting the overlap tells the caller to
    /// retry; the truth is that retrying cannot help until the live record
    /// retires. Checking overlap first — the order the original three seams
    /// used — turns this red.
    #[test]
    fn a_same_persona_race_is_persona_live_not_input_raced() {
        let p = PCanonicalId::from_bytes([0xAA; 32]);
        let mut block = PendingPostBlock::empty();
        assert!(block.push_claim(claim(0xAA, &[1, 2])));

        // The second claim for the same persona reserves the same inputs.
        assert_eq!(
            block.classify_seal(
                PendingKind::Claim,
                &p,
                &gindexes(&[1, 2]),
                block.generation()
            ),
            SealAdmission::PersonaLive,
            "a live claim must be awaited, not retried around"
        );
    }

    /// Overlap is reported only for what it means: another KIND took the input.
    #[test]
    fn a_cross_kind_collision_is_input_raced() {
        let other = PCanonicalId::from_bytes([0xBB; 32]);
        let mut block = PendingPostBlock::empty();
        assert!(block.push_drain(drain(0xAA, &[7])));

        // A different persona's claim wanting the drain's input: no persona
        // dedup applies, and the overlap is real.
        assert_eq!(
            block.classify_seal(
                PendingKind::Claim,
                &other,
                &gindexes(&[7]),
                block.generation()
            ),
            SealAdmission::InputRaced
        );
        // Same persona, different kind, same input — still the overlap arm,
        // because one-per-persona is per KIND.
        let same = PCanonicalId::from_bytes([0xAA; 32]);
        assert_eq!(
            block.classify_seal(
                PendingKind::Claim,
                &same,
                &gindexes(&[7]),
                block.generation()
            ),
            SealAdmission::InputRaced
        );
    }

    /// A free persona and free inputs admit.
    #[test]
    fn a_clear_seal_is_admitted() {
        let p = PCanonicalId::from_bytes([0xCC; 32]);
        let mut block = PendingPostBlock::empty();
        assert!(block.push_drain(drain(0xAA, &[7])));
        assert_eq!(
            block.classify_seal(
                PendingKind::Drain,
                &p,
                &gindexes(&[8, 9]),
                block.generation()
            ),
            SealAdmission::Admit
        );
    }

    /// One-live is per KIND, so a live drain does not block that persona's
    /// claim — only a shared input does.
    #[test]
    fn one_live_is_per_kind_not_per_persona() {
        let p = PCanonicalId::from_bytes([0xAA; 32]);
        let mut block = PendingPostBlock::empty();
        assert!(block.push_drain(drain(0xAA, &[7])));
        assert_eq!(
            block.classify_seal(PendingKind::Claim, &p, &gindexes(&[8]), block.generation()),
            SealAdmission::Admit,
            "a live drain is not a live claim"
        );
    }

    /// An admitted claim seal inserts the record **already dispatched** — the
    /// end state the old push-then-mark pair reached, with no persistable
    /// instant in between where the record is `Pending` and the seam still owes
    /// it a transition.
    #[test]
    fn an_admitted_claim_seal_inserts_a_dispatched_record() {
        let at = ChainCount::from_raw(900);
        let mut block = PendingPostBlock::empty();

        let g = block.generation();
        assert_eq!(
            block.seal_claim(claim(0xAA, &[1, 2]), at, g),
            SealAdmission::Admit
        );

        let sealed = block.claims();
        assert_eq!(sealed.len(), 1, "the admitted record must be present");
        assert_eq!(
            sealed[0].state,
            PendingPostState::Dispatched { at, attempts: 1 },
            "an admitted seal is a dispatch, not a pending insert"
        );
        assert_eq!(
            block.reserved_gindexes(),
            gindexes(&[1, 2]).into_iter().collect(),
            "the seal is what makes the reservation visible to the next seal"
        );
    }

    /// A bond post is *not* stamped dispatched: its send is a later step of the
    /// pscan driver, so `seal_post` takes no height and leaves the state alone.
    #[test]
    fn an_admitted_post_seal_leaves_the_record_pending() {
        let mut block = PendingPostBlock::empty();
        let g = block.generation();
        assert_eq!(block.seal_post(post(0xAA, &[1]), g), SealAdmission::Admit);
        assert_eq!(block.posts()[0].state, PendingPostState::Pending);
    }

    /// **A refused seal inserts nothing**, on both refusal arms. Deciding and
    /// inserting in one call is only safe if the refusing paths leave the block
    /// untouched — otherwise a doomed record would hold a reservation that
    /// `remove_settled` later reads as evidence.
    #[test]
    fn a_refused_seal_inserts_nothing() {
        let at = ChainCount::from_raw(900);
        let mut block = PendingPostBlock::empty();
        let g = block.generation();
        assert_eq!(
            block.seal_drain(drain(0xAA, &[7]), at, g),
            SealAdmission::Admit
        );

        // Persona-live refusal: same persona, same kind. Sealing releases
        // nothing, so `g` is still current and these reach their own arms
        // rather than the staleness one.
        assert_eq!(
            block.seal_drain(drain(0xAA, &[8]), at, g),
            SealAdmission::PersonaLive
        );
        // Input-raced refusal: different persona, gindex already reserved.
        assert_eq!(
            block.seal_claim(claim(0xBB, &[7]), at, g),
            SealAdmission::InputRaced
        );

        assert_eq!(
            block.drains().len(),
            1,
            "a refused drain must not be inserted"
        );
        assert!(
            block.claims().is_empty(),
            "a refused claim must not be inserted"
        );
        assert_eq!(
            block.reserved_gindexes(),
            gindexes(&[7]).into_iter().collect(),
            "a refused seal must not widen the reservation set"
        );
    }

    /// **The staleness the union check cannot see** (review #572, round 5).
    ///
    /// The exact interleaving: assembly A snapshots the reservation set, and
    /// while its proof work runs, drain B seals A's chosen input, confirms, and
    /// is retired by `remove_settled`. B's reservation is now *gone*, so the
    /// union check A performs at seal time sees the gindex free and admits —
    /// sealing a transaction whose input B already spent. Worse, the next tick
    /// sees that input absent from live funding and reads it as A's OWN
    /// confirmation, retiring a record whose transaction the network rejected.
    ///
    /// The generation counter is what makes the release visible. Note the
    /// reservation set is byte-identical at snapshot and at seal — empty both
    /// times — so no comparison of the sets themselves could catch this.
    #[test]
    fn a_reservation_released_during_assembly_refuses_the_stale_seal() {
        let a = PCanonicalId::from_bytes([0xAA; 32]);
        let mut block = PendingPostBlock::empty();

        // A snapshots: nothing reserved, so gindex 7 looks free and A selects
        // it. Proof work begins.
        let a_snapshot = block.generation();
        assert!(block.reserved_gindexes().is_empty());

        // B seals the same input and confirms; the settlement tick retires it.
        assert_eq!(
            block.seal_drain(drain(0xBB, &[7]), ChainCount::from_raw(900), a_snapshot),
            SealAdmission::Admit
        );
        let retired = block.remove_settled(&live(&[]));
        assert_eq!(retired.drains.len(), 1, "B must have been retired");

        // The set A would compare against is identical to its snapshot.
        assert!(
            block.reserved_gindexes().is_empty(),
            "the release returned the set to its snapshot value — this is why a \
             set comparison cannot detect it"
        );

        // A now seals. The union check would admit; the generation refuses.
        assert_eq!(
            block.classify_seal(PendingKind::Claim, &a, &gindexes(&[7]), a_snapshot),
            SealAdmission::Stale,
            "a seal whose snapshot predates a release must be refused"
        );

        // Control: the same seal against a CURRENT snapshot is admitted, so it
        // is the staleness being refused and not the persona or the gindex.
        assert_eq!(
            block.classify_seal(PendingKind::Claim, &a, &gindexes(&[7]), block.generation()),
            SealAdmission::Admit
        );
    }

    /// Every reservation-releasing method moves the generation, and the
    /// non-releasing ones do not. A release that forgot to bump would leave
    /// exactly the window the test above closes.
    #[test]
    fn every_release_moves_the_generation_and_only_a_release_does() {
        let at = ChainCount::from_raw(900);
        let p = PCanonicalId::from_bytes([0xAA; 32]);
        let mut block = PendingPostBlock::empty();

        // Sealing reserves; it must NOT move the generation, or every seal
        // would invalidate every other assembly in flight.
        let g0 = block.generation();
        assert_eq!(block.seal_post(post(0xAA, &[1]), g0), SealAdmission::Admit);
        assert_eq!(
            block.seal_claim(claim(0xAA, &[2]), at, g0),
            SealAdmission::Admit
        );
        assert_eq!(
            block.seal_drain(drain(0xAA, &[3]), at, g0),
            SealAdmission::Admit
        );
        assert_eq!(
            block.generation(),
            g0,
            "reserving is not releasing; a seal must not invalidate other assemblies"
        );

        // Each remover releases, and each must be visible.
        assert!(block.remove_claim(&p).is_some());
        assert_eq!(block.generation(), g0 + 1, "remove_claim");
        assert!(block.remove_drain(&p).is_some());
        assert_eq!(block.generation(), g0 + 2, "remove_drain");
        assert!(block.remove_post(&p).is_some());
        assert_eq!(block.generation(), g0 + 3, "remove_post");

        // A remover that removes nothing releases nothing.
        let g = block.generation();
        assert!(block.remove_post(&p).is_none());
        assert_eq!(block.generation(), g, "a no-op remove must not move it");

        // The batched retires, by count.
        let g = block.generation();
        assert_eq!(block.seal_post(post(0xCC, &[4]), g), SealAdmission::Admit);
        let confirmed: BTreeSet<PCanonicalId> =
            [PCanonicalId::from_bytes([0xCC; 32])].into_iter().collect();
        assert_eq!(block.remove_confirmed(&confirmed).len(), 1);
        assert_eq!(block.generation(), g + 1, "remove_confirmed");

        let g = block.generation();
        assert_eq!(
            block.seal_claim(claim(0xDD, &[5]), at, g),
            SealAdmission::Admit
        );
        assert_eq!(
            block.seal_drain(drain(0xDD, &[6]), at, g),
            SealAdmission::Admit
        );
        let retired = block.remove_settled(&live(&[]));
        assert_eq!(retired.claims.len() + retired.drains.len(), 2);
        assert_eq!(
            block.generation(),
            g + 1,
            "remove_settled bumps once for the retirement, both kinds included"
        );
    }

    fn gindexes(v: &[u64]) -> Vec<GlobalOutputIndex> {
        v.iter().copied().map(GlobalOutputIndex::from_raw).collect()
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
                    ChainCount::from_raw(1_012)
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
                at: ChainCount::from_raw(1_012),
                attempts: 1
            }
        );
    }

    #[test]
    fn version_mismatch_fails_closed() {
        let wrong = PendingPostBlock {
            version: PENDING_POST_VERSION + 1,
            generation: 0,
            posts: Vec::new(),
            claims: Vec::new(),
            drains: Vec::new(),
            releases: Vec::new(),
            outcomes: Vec::new(),
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

    /// A **v12** seal under this v13 binary fails closed on the version gate:
    /// v12 records have no `reference_height`, so they have no end date and
    /// could never be released (WR-Q3). Refuse-not-migrate; re-assemble.
    #[test]
    fn v12_seal_fails_closed_under_v13_binary() {
        assert_eq!(PENDING_POST_VERSION, 13);
        let mut bytes = PendingPostBlock::empty()
            .to_postcard_bytes()
            .expect("encode");
        // The leading varint is the version; 12 and 13 both fit one byte.
        assert_eq!(bytes[0], 13);
        bytes[0] = 12;
        let err = PendingPostBlock::from_postcard_bytes(&bytes).expect_err("v12 must refuse");
        assert!(matches!(
            err,
            WalletLedgerError::UnsupportedBlockVersion {
                block: "pending_post_block",
                file: 12,
                binary: 13,
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
            generation: 0,
            posts: Vec::new(),
            claims: Vec::new(),
            drains: Vec::new(),
            releases: Vec::new(),
            outcomes: Vec::new(),
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
                .mark_dispatched(&persona, ChainCount::from_raw(500))
                .map(|(attempts, _)| attempts),
            Some(1)
        );
        // Resubmit at a later tip: attempts bump, `at` stays at first send. The
        // returned post reflects the just-applied transition (same lookup).
        let (attempts, post) = block
            .mark_dispatched(&persona, ChainCount::from_raw(510))
            .expect("live post");
        assert_eq!(attempts, 2);
        assert_eq!(
            post.state,
            PendingPostState::Dispatched {
                at: ChainCount::from_raw(500),
                attempts: 2
            }
        );
        assert_eq!(
            block.posts()[0].state,
            PendingPostState::Dispatched {
                at: ChainCount::from_raw(500),
                attempts: 2
            }
        );
        // No live post for an unknown persona.
        assert!(block
            .mark_dispatched(
                &PCanonicalId::from_bytes([0xEE; 32]),
                ChainCount::from_raw(1)
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
            reference_height: TEST_REFERENCE,
            terminal: None,
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
                .mark_claim_dispatched(&persona, ChainCount::from_raw(500))
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
                at: ChainCount::from_raw(500),
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
            reference_height: TEST_REFERENCE,
            terminal: None,
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
                .mark_drain_dispatched(&persona, ChainCount::from_raw(500))
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
                at: ChainCount::from_raw(500),
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

    fn release(persona_byte: u8, funding_gindexes: &[u64]) -> PendingRelease {
        PendingRelease {
            persona: PCanonicalId::from_bytes([persona_byte; 32]),
            tx_bytes: vec![0xEB; 16],
            funding_gindexes: funding_gindexes
                .iter()
                .copied()
                .map(GlobalOutputIndex::from_raw)
                .collect(),
            state: PendingPostState::Pending,
            reference_height: TEST_REFERENCE,
            terminal: None,
        }
    }

    /// The v9 record set, end to end on the production insert path: an
    /// admitted `seal_release` inserts the record already `Dispatched`,
    /// reserves every funding input, holds the one-live-exit lane, and
    /// round-trips through postcard.
    #[test]
    fn release_records_reserve_dedup_and_round_trip() {
        let persona = PCanonicalId::from_bytes([0xAA; 32]);
        let mut block = PendingPostBlock::empty();
        assert!(block.push_post(post(0xBB, &[1])));
        let generation = block.generation();
        assert_eq!(
            block.seal_release(
                release(0xAA, &[7, 9]),
                ChainCount::from_raw(500),
                generation
            ),
            SealAdmission::Admit
        );

        // Inserted already dispatched (the seam sends immediately after the
        // seal — no persistable Pending instant, same as claim/drain).
        assert_eq!(
            block.releases()[0].state,
            PendingPostState::Dispatched {
                at: ChainCount::from_raw(500),
                attempts: 1
            }
        );

        // One live exit per persona — the second is refused as PersonaLive
        // even on disjoint inputs (an exit debits the whole bonded total; a
        // second is doomed, and "retry" would be the wrong remedy).
        assert!(block.has_live_release_for(&persona));
        assert_eq!(
            block.seal_release(release(0xAA, &[11]), ChainCount::from_raw(501), generation),
            SealAdmission::PersonaLive
        );

        // The reservation union spans posts AND releases — and an exit
        // reserves every input (the released collateral is a debit term, not
        // an input, so it contributes no gindex).
        assert_eq!(
            block.reserved_gindexes().into_iter().collect::<Vec<_>>(),
            [1, 7, 9]
                .into_iter()
                .map(GlobalOutputIndex::from_raw)
                .collect::<Vec<_>>(),
        );

        // A cross-kind seal against a reserved input refuses as InputRaced.
        assert_eq!(
            block.classify_seal(
                PendingKind::Drain,
                &PCanonicalId::from_bytes([0xCC; 32]),
                &gindexes(&[9]),
                block.generation()
            ),
            SealAdmission::InputRaced
        );

        let bytes = block.to_postcard_bytes().expect("encode");
        let back = PendingPostBlock::from_postcard_bytes(&bytes).expect("decode");
        assert_eq!(back, block);
        assert_eq!(back.releases().len(), 1);

        // Terminal-reject release: removal prunes the bytes, releases the
        // reservation, bumps the generation (a release IS a release — an
        // assembly snapshotted across it must land Stale), and is idempotent.
        let g_before = block.generation();
        let removed = block
            .remove_release(&persona)
            .expect("live release removes");
        assert_eq!(removed.persona, persona);
        assert!(!block.has_live_release_for(&persona));
        assert_eq!(
            block.reserved_gindexes().into_iter().collect::<Vec<_>>(),
            vec![GlobalOutputIndex::from_raw(1)],
            "only the bond post's reservation remains"
        );
        assert_eq!(
            block.generation(),
            g_before + 1,
            "a terminal-reject release must move the generation"
        );
        assert!(block.remove_release(&persona).is_none());
    }

    /// The reservation-observed retire covers the exit: every reserved input
    /// gone means the exit confirmed, which retires the record, reopens the
    /// one-live-exit lane, and bumps the generation (a release is a release).
    #[test]
    fn a_spent_reservation_retires_its_release() {
        let persona = PCanonicalId::from_bytes([0xAA; 32]);
        let mut block = PendingPostBlock::empty();
        let g0 = block.generation();
        assert_eq!(
            block.seal_release(release(0xAA, &[7, 9]), ChainCount::from_raw(500), g0),
            SealAdmission::Admit
        );

        // Partly spent holds (the confirming spend cannot produce it) …
        let held = block.remove_settled(&live(&[9]));
        assert!(held.is_empty());
        assert!(block.has_live_release_for(&persona));

        // … fully gone retires, in the release vector specifically.
        let out = block.remove_settled(&live(&[99]));
        assert_eq!(out.releases, vec![persona]);
        assert!(out.claims.is_empty() && out.drains.is_empty());
        assert!(!block.has_live_release_for(&persona));
        assert!(block.reserved_gindexes().is_empty());
        assert_eq!(
            block.generation(),
            g0 + 1,
            "a settled exit is a reservation release the generation must count"
        );
    }

    /// The terminal-reject release removes ONLY the named persona's exit —
    /// a release keyed on the wrong persona would free a live reservation
    /// (the inputs a still-in-flight exit spends) while holding the dead one.
    #[test]
    fn remove_release_frees_only_the_named_persona() {
        let mut block = PendingPostBlock::empty();
        let g = block.generation();
        assert_eq!(
            block.seal_release(release(0xAA, &[7]), ChainCount::from_raw(500), g),
            SealAdmission::Admit
        );
        assert_eq!(
            block.seal_release(release(0xBB, &[8]), ChainCount::from_raw(500), g),
            SealAdmission::Admit
        );

        let removed = block
            .remove_release(&PCanonicalId::from_bytes([0xAA; 32]))
            .expect("the named persona's exit removes");
        assert_eq!(removed.persona, PCanonicalId::from_bytes([0xAA; 32]));
        assert!(
            block.has_live_release_for(&PCanonicalId::from_bytes([0xBB; 32])),
            "the other persona's live exit must survive the release"
        );
        assert_eq!(
            block.reserved_gindexes().into_iter().collect::<Vec<_>>(),
            vec![GlobalOutputIndex::from_raw(8)],
            "only the removed exit's reservation is released"
        );
    }

    /// A v8 seal (no release set) under this v9 binary fails closed on the
    /// version gate — refuse-not-migrate (rule 15, pre-genesis). Models REAL
    /// v8 bytes the way the v4 test below does: a v8 binary never wrote an
    /// `releases` field, so the tuple form is byte-identical to a v8 layout
    /// with empty sets, and the gate must refuse on the leading `8` before it
    /// ever tries (and fails at EOF) to read the absent field.
    #[test]
    fn v8_seal_fails_closed_under_v9_binary() {
        let v8_bytes = postcard::to_allocvec(&(
            8u32,
            0u64, // generation
            Vec::<PendingBondPost>::new(),
            Vec::<PendingEmissionClaim>::new(),
            Vec::<PendingDrain>::new(),
        ))
        .expect("encode v8-shaped bytes");
        let err = PendingPostBlock::from_postcard_bytes(&v8_bytes).expect_err("v8 must refuse");
        assert!(matches!(
            err,
            WalletLedgerError::UnsupportedBlockVersion {
                block: "pending_post_block",
                file: 8,
                binary: PENDING_POST_VERSION,
            }
        ));
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

    // -- WR-Q2 / WR-Q3 / WR-Q4: end-date release and durable outcomes --------

    fn sealed(records: impl FnOnce(&mut PendingPostBlock)) -> PendingPostBlock {
        let mut block = PendingPostBlock::empty();
        records(&mut block);
        block
    }

    #[test]
    fn the_end_date_is_reference_plus_max_age_inclusive() {
        assert_eq!(end_date(TEST_REFERENCE, TEST_MAX_AGE), TEST_END);
        assert_eq!(
            end_date(BlockHeight::from_raw(u64::MAX - 1), TEST_MAX_AGE),
            BlockHeight::from_raw(u64::MAX),
            "an overflowing end date saturates: it never arrives, which only holds funds longer"
        );
    }

    /// One block short of the end date nothing is released; at the end date
    /// the record goes, with its outcome, in the same mutation.
    #[test]
    fn a_record_is_released_at_its_end_date_and_not_a_block_before() {
        let mut block = sealed(|b| assert!(b.push_drain(drain(0x01, &[7]))));
        let before = block.release_ended(
            BlockHeight::from_raw(TEST_END.to_raw() - 1),
            &live(&[7]),
            TEST_MAX_AGE,
            BlockHeight::from_raw(6_000),
        );
        assert!(before.is_empty());
        assert_eq!(block.drains().len(), 1);
        let g = block.generation();

        let at = block.release_ended(
            TEST_END,
            &live(&[7]),
            TEST_MAX_AGE,
            BlockHeight::from_raw(6_000),
        );
        assert_eq!(
            at.released,
            vec![(
                RecordKind::Drain,
                PCanonicalId::from_bytes([0x01; 32]),
                OutcomeKind::Expired
            )]
        );
        assert!(block.drains().is_empty());
        assert!(
            block.reserved_gindexes().is_empty(),
            "the reservation goes with the record"
        );
        assert!(
            block.generation() > g,
            "a release is a reservation-releasing operation"
        );
        assert_eq!(block.outcomes().len(), 1);
        assert_eq!(block.outcomes()[0].outcome, OutcomeKind::Expired);
        assert_eq!(block.outcomes()[0].at_height, BlockHeight::from_raw(6_000));
    }

    /// The release table, row by row, for every kind it applies to.
    #[test]
    fn the_release_outcome_follows_the_precedence_table() {
        let p = |b: u8| PCanonicalId::from_bytes([b; 32]);
        let mut block = sealed(|b| {
            // stake, inputs live, no verdict -> expired
            assert!(b.push_post(post(0x10, &[1])));
            // stake, an input gone without a match -> spent elsewhere
            assert!(b.push_post(post(0x11, &[2, 3])));
            // claim, nothing reserved -> ended unconfirmed
            assert!(b.push_claim(claim(0x12, &[])));
            // drain, inputs live, a terminal verdict seen -> rejected
            assert!(b.push_drain(drain(0x13, &[4])));
            // exit, part of its inputs gone -> spent elsewhere
            let g = b.generation();
            assert_eq!(
                b.seal_release(release(0x14, &[5, 6]), ChainCount::from_raw(1), g),
                SealAdmission::Admit
            );
            // claim, nothing reserved, a verdict seen -> ended unconfirmed,
            // the cause kept: the scan cannot see whether it landed
            assert!(b.push_claim(claim(0x15, &[])));
            // stake, every input gone, no match -> held, not released
            assert!(b.push_post(post(0x16, &[7, 8])));
        });
        assert!(block.record_terminal(RecordKind::Drain, &p(0x13), TerminalCause::FeeTooLow));
        assert!(block.record_terminal(RecordKind::Claim, &p(0x15), TerminalCause::Malformed));

        let out = block.release_ended(TEST_END, &live(&[1, 3, 4, 6]), TEST_MAX_AGE, TEST_END);
        let got: std::collections::BTreeMap<_, _> = out
            .released
            .iter()
            .map(|&(k, who, o)| ((k, who.to_bytes()[0]), o))
            .collect();
        assert_eq!(got.len(), 6, "every ended record is released: {got:?}");
        assert_eq!(got[&(RecordKind::Post, 0x10)], OutcomeKind::Expired);
        assert_eq!(got[&(RecordKind::Post, 0x11)], OutcomeKind::SpentElsewhere);
        assert_eq!(
            got[&(RecordKind::Claim, 0x12)],
            OutcomeKind::EndedUnconfirmed(None)
        );
        assert_eq!(
            got[&(RecordKind::Drain, 0x13)],
            OutcomeKind::Rejected(TerminalCause::FeeTooLow)
        );
        assert_eq!(
            got[&(RecordKind::Release, 0x14)],
            OutcomeKind::SpentElsewhere
        );
        assert_eq!(
            got[&(RecordKind::Claim, 0x15)],
            OutcomeKind::EndedUnconfirmed(Some(TerminalCause::Malformed))
        );
        assert!(
            !got.contains_key(&(RecordKind::Post, 0x16)),
            "a stake with every input gone is held"
        );
        assert!(
            block.has_live_post_for(&p(0x16)),
            "its record stays the bridge"
        );
        let held: Vec<u8> = block
            .held_spent_posts(TEST_END, &live(&[1, 3, 4, 6]), TEST_MAX_AGE)
            .map(|post| post.persona.to_bytes()[0])
            .collect();
        assert_eq!(held, vec![0x16], "the held query names it, and only it");
        assert_eq!(
            block.reserved_gindexes(),
            gindexes(&[7, 8]).into_iter().collect(),
            "every other reservation, partly spent ones included, is freed"
        );
        assert!(
            !block.has_live_claim_for(&p(0x12)),
            "the zero-fee claim's gate reopens"
        );
        assert_eq!(block.outcomes().len(), 6);
        // Sent: the exit (sealed as dispatched, seal-before-send) and the two
        // records a daemon answered with a verdict. The others were never
        // handed to a daemon, so their endings say nothing about linkage
        // (WR-Q5).
        for o in block.outcomes() {
            let byte = o.persona.to_bytes()[0];
            assert_eq!(
                o.sent,
                (0x13..=0x15).contains(&byte),
                "sent flag for {byte:#x}"
            );
        }
    }

    /// A reservation-kind record whose every input is gone landed: it is
    /// `remove_settled`'s, so the release leaves it alone even when called
    /// out of order, and no outcome is written for it.
    #[test]
    fn a_settled_record_is_never_released_as_an_ending() {
        let mut block = sealed(|b| assert!(b.push_drain(drain(0x20, &[8, 9]))));
        let out = block.release_ended(TEST_END, &live(&[]), TEST_MAX_AGE, TEST_END);
        assert!(out.is_empty());
        assert_eq!(block.drains().len(), 1);
        let settled = block.remove_settled(&live(&[]));
        assert_eq!(settled.drains.len(), 1);
        assert!(block.outcomes().is_empty());
    }

    /// A terminal verdict holds the record and its reservation (BD-Q3 Rule
    /// 2). The first cause is kept, and only a live record can take one.
    #[test]
    fn a_terminal_verdict_is_recorded_and_holds_the_record() {
        let who = PCanonicalId::from_bytes([0x30; 32]);
        let mut block = sealed(|b| assert!(b.push_post(post(0x30, &[11]))));
        assert!(block.record_terminal(
            RecordKind::Post,
            &who,
            TerminalCause::JoinMarketUnsupported
        ));
        assert!(
            !block.record_terminal(RecordKind::Post, &who, TerminalCause::DoubleSpend),
            "the first cause is kept"
        );
        assert!(
            !block.record_terminal(RecordKind::Claim, &who, TerminalCause::DoubleSpend),
            "no live claim to mark"
        );
        assert_eq!(
            block.posts().len(),
            1,
            "a verdict never removes a submitted record"
        );
        assert_eq!(
            block.posts()[0].terminal,
            Some(TerminalCause::JoinMarketUnsupported)
        );
        assert_eq!(
            block.reserved_gindexes(),
            live(&[11]),
            "and never releases its reservation"
        );
    }

    /// An outcome is per `(kind, persona)`: a later ending replaces it, the
    /// persona's next admitted seal of the kind clears it, and so does an
    /// acknowledgement.
    #[test]
    fn an_outcome_is_replaced_cleared_by_a_new_seal_and_acknowledged() {
        let mut block = sealed(|b| assert!(b.push_drain(drain(0x40, &[12]))));
        assert_eq!(
            block
                .release_ended(TEST_END, &live(&[12]), TEST_MAX_AGE, TEST_END)
                .released
                .len(),
            1
        );
        assert_eq!(block.outcomes().len(), 1);

        let g = block.generation();
        assert_eq!(
            block.seal_drain(drain(0x40, &[13]), ChainCount::from_raw(6_000), g),
            SealAdmission::Admit
        );
        assert!(
            block.outcomes().is_empty(),
            "the next admitted seal of the kind clears it"
        );

        assert_eq!(
            block
                .release_ended(TEST_END, &live(&[13]), TEST_MAX_AGE, TEST_END)
                .released
                .len(),
            1
        );
        assert_eq!(block.outcomes().len(), 1, "one outcome per (kind, persona)");
        assert_eq!(
            block.acknowledge_outcomes(RecordKind::Claim, TEST_END),
            0,
            "another kind's is untouched"
        );
        assert_eq!(block.acknowledge_outcomes(RecordKind::Drain, TEST_END), 1);
        assert!(block.outcomes().is_empty());
        assert_eq!(
            block.acknowledge_outcomes(RecordKind::Drain, TEST_END),
            0,
            "nothing left to acknowledge"
        );
    }

    /// The acknowledgement as ruled 2026-10-17: every outcome of the kind,
    /// across personas, written at or below the height shown; a newer one is
    /// never cleared unseen.
    #[test]
    fn an_acknowledgement_clears_every_persona_through_the_height_shown() {
        let mut block = sealed(|b| {
            assert!(b.push_drain(drain(0x41, &[20])));
            assert!(b.push_drain(drain(0x42, &[21])));
            assert!(b.push_claim(claim(0x43, &[])));
        });
        let shown = BlockHeight::from_raw(TEST_END.to_raw() + 10);
        let ended = block.release_ended(TEST_END, &live(&[20, 21]), TEST_MAX_AGE, shown);
        assert_eq!(ended.released.len(), 3);
        let mut late = drain(0x44, &[22]);
        late.reference_height = BlockHeight::from_raw(TEST_REFERENCE.to_raw() + 50);
        assert!(block.push_drain(late));
        let later_end = BlockHeight::from_raw(TEST_END.to_raw() + 50);
        let after = BlockHeight::from_raw(shown.to_raw() + 1);
        assert_eq!(
            block
                .release_ended(later_end, &live(&[22]), TEST_MAX_AGE, after)
                .released
                .len(),
            1
        );

        assert_eq!(
            block.acknowledge_outcomes(RecordKind::Drain, shown),
            2,
            "both personas' drains at or below the height shown"
        );
        let left: Vec<_> = block
            .outcomes()
            .iter()
            .map(|o| (o.kind, o.persona.to_bytes()[0]))
            .collect();
        assert_eq!(
            left,
            vec![(RecordKind::Claim, 0x43), (RecordKind::Drain, 0x44)],
            "the other kind, and the drain written after the height shown, stay"
        );
        assert_eq!(block.acknowledge_outcomes(RecordKind::Drain, shown), 0);
    }

    /// `spent_elsewhere` clears only on acknowledgement: a new seal, or a new
    /// ending, of the same kind for that persona leaves it in place.
    #[test]
    fn spent_elsewhere_survives_a_new_seal_and_a_new_ending() {
        let mut block = sealed(|b| assert!(b.push_drain(drain(0x45, &[30, 31]))));
        let ended = block.release_ended(TEST_END, &live(&[30]), TEST_MAX_AGE, TEST_END);
        assert_eq!(
            ended.released[0].2,
            OutcomeKind::SpentElsewhere,
            "one of two inputs gone"
        );

        let g = block.generation();
        assert_eq!(
            block.seal_drain(drain(0x45, &[32]), ChainCount::from_raw(6_000), g),
            SealAdmission::Admit
        );
        assert_eq!(block.outcomes().len(), 1, "the seal leaves it");
        assert_eq!(block.outcomes()[0].outcome, OutcomeKind::SpentElsewhere);

        let next = block.release_ended(TEST_END, &live(&[32]), TEST_MAX_AGE, TEST_END);
        assert_eq!(next.released[0].2, OutcomeKind::Expired);
        let kinds: Vec<_> = block.outcomes().iter().map(|o| o.outcome).collect();
        assert_eq!(
            kinds,
            vec![OutcomeKind::SpentElsewhere, OutcomeKind::Expired],
            "a later ending is added beside it, not over it"
        );
        assert_eq!(block.acknowledge_outcomes(RecordKind::Drain, TEST_END), 2);
        assert!(block.outcomes().is_empty());
    }

    /// The outcome and its cause survive the codec, and `Debug` names no
    /// persona.
    #[test]
    fn outcomes_round_trip_and_debug_redacts_them() {
        let mut block = sealed(|b| assert!(b.push_post(post(0x50, &[14]))));
        assert!(block.record_terminal(
            RecordKind::Post,
            &PCanonicalId::from_bytes([0x50; 32]),
            TerminalCause::DoubleSpend
        ));
        assert_eq!(
            block
                .release_ended(TEST_END, &live(&[14]), TEST_MAX_AGE, TEST_END)
                .released
                .len(),
            1
        );
        let back =
            PendingPostBlock::from_postcard_bytes(&block.to_postcard_bytes().unwrap()).unwrap();
        assert_eq!(back, block);
        assert_eq!(
            back.outcomes()[0].outcome,
            OutcomeKind::Rejected(TerminalCause::DoubleSpend)
        );
        let shown = format!("{block:?} {:?}", block.outcomes()[0]);
        assert!(
            !shown.contains("80, 80"),
            "no persona bytes in Debug: {shown}"
        );
        assert!(shown.contains("redacted outcome"));
    }
}
