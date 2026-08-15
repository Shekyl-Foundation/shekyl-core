// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pinner's report: the obligation, the evidence that retains it, and
//! the store both landed in.

use shekyl_curve_tree::{BlockHeight, PostureDeclaration, SegmentPin, ServingReader};

/// Why a serve-set could not be pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinError {
    /// A member is frozen but its leaf bytes were already pruned. Pinning
    /// cannot bring bytes back, so this is refused rather than reported
    /// healthy: a persona that starts serving over a set in this state
    /// reaches its challenge epoch unable to answer, and the operator's
    /// first signal is the slash. The remedy is a store rebuild by chain
    /// replay, not a retry.
    ///
    /// Every pruned member is listed, not just the first — an operator
    /// facing a rebuild wants to know the extent of it in one message.
    MembersAlreadyPruned {
        /// Every serve-set member whose bytes are gone.
        shard_ids: Vec<u64>,
    },
    /// The pinner failed (store I/O, a dead actor, a poisoned client), or
    /// the store could not be read for the witness's own staleness baseline.
    /// Either way the serve-set's state is unknown, so the host does not
    /// start; pinning is idempotent, so a retry re-covers whatever was
    /// already applied.
    ///
    /// The baseline read shares this variant rather than getting its own
    /// because this enum splits on **remedy**, not on origin, and the remedy
    /// is the same one: retry. A witness minted without a baseline could not
    /// answer [`super::PinnedServeSet::staleness`] at all, so there is nothing
    /// weaker to fall back to.
    Pinner {
        /// Local diagnostic; never on the wire.
        detail: String,
    },
    /// A pin report's outcomes do not describe the set it reported.
    ///
    /// Distinct from [`Self::Pinner`] because the remedy is different: a
    /// pinner failure is an environment fault and a retry re-covers it, but a
    /// report whose evidence does not cover its own claim is a defect in the
    /// implementor, and retrying only repeats it. Both lists are carried so
    /// the divergence is readable without re-running anything.
    PinnerCoverageMismatch {
        /// The shard set the report claimed, in the record's order.
        reported_set: Vec<u64>,
        /// The members its outcomes actually covered, in the order reported.
        covered: Vec<u64>,
    },
    /// The report claims the whole frozen corpus
    /// ([`ReportedSet::CompleteTreePrefix`]) over a store whose
    /// prune-disabled posture is **not declared**.
    ///
    /// The posture flag is the prefix arm's pin: no per-member pin rows
    /// exist, so retention of the corpus rests entirely on
    /// `LeafStore::prune_frozen` refusing under the declared posture. A
    /// prefix witness over an undeclared store would claim an obligation
    /// nothing retains — §9.6 item 4's silent slash with the pin table
    /// swapped out from under it.
    ///
    /// An implementor defect, not a transient fault: the flag is one-way
    /// and the production pinner declares it (idempotently, through the
    /// curve-tree actor) before reporting the prefix, so a report that
    /// trips this was built without the declaration and retrying repeats
    /// it. The remedy is in the implementor: declare the posture, then
    /// report.
    PostureNotDeclared,
    /// The report claims a CompleteTree prefix longer than the store's
    /// burial-gated freeze cursor.
    ///
    /// The store *is* the authority for that number. A report that
    /// overstates it claims shards the store has not frozen — the
    /// dangerous direction of the list arm's coverage check, applied to
    /// the prefix. A report that *understates* the cursor is a stale-low
    /// snapshot and is accepted: refresh grows the obligation (D-5), and
    /// equality can race if a segment freezes between the pinner's read
    /// and this check.
    ///
    /// An implementor defect, not a transient fault. Retrying a lying
    /// report repeats it.
    FrozenCountExceedsCursor {
        /// The prefix length the report claimed.
        reported: u64,
        /// The store's `next_freeze_seg` at the check.
        cursor: u64,
    },
    /// A refresh's pins landed in a different open store than the one this
    /// witness is serving.
    ///
    /// Distinct from [`Self::PinnerCoverageMismatch`] because the two
    /// halves of the report can agree with each other and still describe
    /// the wrong database. Retrying only repeats it. The production
    /// pinner cannot produce this: it pins through the wallet's
    /// curve-tree handle, which resumes over the same store Arc across
    /// fail-stop, so the reader it returns is the store the host already
    /// serves. A report that trips this is an implementor defect.
    PinnerStoreMismatch,
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MembersAlreadyPruned { shard_ids } => write!(
                f,
                "serve-set members {shard_ids:?} were pruned before they were pinned; \
                 the store must be rebuilt by chain replay before this persona can serve"
            ),
            Self::Pinner { detail } => write!(f, "serve-set pin failed: {detail}"),
            Self::PinnerCoverageMismatch {
                reported_set,
                covered,
            } => write!(
                f,
                "the pin report claims the serve-set {reported_set:?} but its outcomes \
                 cover {covered:?}; the pins cannot be witnessed for members the report \
                 does not describe, so this persona does not serve. This is an \
                 implementor defect, not a transient fault — retrying will repeat it"
            ),
            Self::PinnerStoreMismatch => write!(
                f,
                "the pin report's reader is not the store this host is serving; \
                 the pins cannot be witnessed for a store nobody is reading, so \
                 this persona keeps its previous pins. This is an implementor \
                 defect, not a transient fault — retrying will repeat it"
            ),
            Self::PostureNotDeclared => write!(
                f,
                "the pin report claims the whole frozen corpus but the store's \
                 prune-disabled posture is not declared, so nothing retains the \
                 bytes the claim rests on; declare the posture \
                 (LeafStore::set_prune_disabled, through the curve-tree actor) \
                 before reporting a CompleteTree prefix. This is an implementor \
                 defect, not a transient fault — retrying will repeat it"
            ),
            Self::FrozenCountExceedsCursor { reported, cursor } => write!(
                f,
                "the pin report claims a CompleteTree prefix of length {reported} \
                 but the store's freeze cursor is {cursor}; a report that overstates \
                 the frozen set claims shards the store has not frozen, so this \
                 persona does not serve. This is an implementor defect, not a \
                 transient fault — retrying will repeat it"
            ),
        }
    }
}

impl std::error::Error for PinError {}

/// What a [`ServeSetPinner`] returns: the obligation it derived, the
/// evidence that retains it, and a read-only handle on the store both
/// landed in.
///
/// The two travel together so they cannot be paired wrongly — see the trait
/// doc for why that is a soundness property and not a convenience.
#[derive(Debug, Clone)]
pub struct PinReport {
    /// The obligation the implementor derived from the **connected** bond
    /// record, with the evidence appropriate to its arm.
    pub set: ReportedSet,
    /// The chain height that record was read at; becomes
    /// [`ServeSet::as_of_height`](super::ServeSet::as_of_height), the set's
    /// **provenance** stamp.
    ///
    /// Not an operand of the staleness reading — that is
    /// [`ServingReader::sync_tip_height`] read twice, so no remote height
    /// is ever subtracted from a local one. A [`BlockHeight`] rather than a
    /// raw chain count all the same: the value answers "at what height was
    /// this obligation true", and a count is one more than the height it
    /// describes.
    pub as_of_height: BlockHeight,
    /// A reader on the store the pins (or the posture declaration) were
    /// applied in.
    pub reader: ServingReader,
}

/// The two obligation shapes a pinner can report, each with the evidence
/// that makes it a witness.
///
/// Public fields on a public enum, unlike [`ServeSet`](super::ServeSet): this
/// is the *reported* side of the seam — the implementor builds it, and the
/// implementor is already the trusted residual the trait doc names. The
/// witness the host holds is still minted only through
/// [`super::PinnedServeSet::acquire`]/[`refreshed`](super::PinnedServeSet::refreshed),
/// which validate a report before anything serves.
#[derive(Debug, Clone)]
pub enum ReportedSet {
    /// Explicit holdings: the record's shard list, pinned per member —
    /// unchanged from SH-2.
    ShardList {
        /// The shard ids derived from the connected record, in the record's
        /// own order — the set the implementor pinned.
        shard_ids: Vec<u64>,
        /// Each member's outcome paired with its shard id, in `shard_ids`
        /// order.
        outcomes: Vec<(u64, SegmentPin)>,
    },
    /// The whole frozen corpus, as a structural prefix
    /// (`COMPLETETREE_ACTIVATION.md` D-1): the obligation is
    /// `[0, frozen_count)` where `frozen_count` is the store's burial-gated
    /// freeze cursor (`LeafStore::next_freeze_seg` — **not**
    /// `shekyl_archival_retention::frozen_segment_count`, the first-crossing
    /// helper, which would admit unburied segments as owed).
    ///
    /// **No pin outcomes — the posture flag is the pin.** A CompleteTree
    /// store declares the prune-disabled posture
    /// (`LeafStore::set_prune_disabled`, one-way), under which
    /// `prune_frozen` refuses outright; per-member pin rows would be a pin
    /// table permanently restating that structural fact, O(D) writes per
    /// refresh over a `D` that grows forever, plus the freeze→pin race
    /// window the posture removes entirely. The witness constructors verify
    /// the declaration ([`PinError::PostureNotDeclared`]) and that
    /// `frozen_count` does not exceed the store's cursor
    /// ([`PinError::FrozenCountExceedsCursor`]) instead of checking rows.
    ///
    /// # The freeze-lag window (`COMPLETETREE_ACTIVATION.md` §4 item 2)
    ///
    /// The wallet's prefix and the daemon's challenge registry freeze on
    /// the **same rule** (`segment_freeze_eligible`) but not the same
    /// driver: the registry advances with the daemon's tip, this cursor
    /// with the wallet's ingest. A wallet trailing inside the caught-up
    /// slack (`CAUGHT_UP_SLACK_BLOCKS`, one archival reorg depth) has a
    /// real window in which the chain can challenge a shard the wallet has
    /// not yet frozen-and-begun-serving. That window is absorbed by
    /// design, not accident: challenges slash only across the m-of-n
    /// sliding window (m = 11), and the daemon's own scan-cost note
    /// (`db_lmdb.cpp:6074-6085`) prices the absorb. Stated here because
    /// the prefix arm is where the two enumerations meet; nothing in this
    /// crate needs to compensate for it.
    CompleteTreePrefix {
        /// The frozen-prefix length at the time of the report.
        frozen_count: u64,
        /// What the store answered when the implementor declared the
        /// posture for this report (declare-before-report is the prefix
        /// contract; the declaration is idempotent).
        ///
        /// This is the **posture-loss detector for the gap the refresh
        /// itself repairs**: the production loop re-declares and *then*
        /// reads staleness, so a flag lost between ticks is restored
        /// before any poll could observe it —
        /// [`PostureDeclaration::NewlyDeclared`] at a refresh is the one
        /// evidence the loss happened, and the witness responds by
        /// running the corpus integrity scan over the reader rather than
        /// trusting the gap was harmless. Same trust level as the list
        /// arm's outcomes: the implementor reports what the store told
        /// it, and the residual (an implementor that lies) is the one the
        /// trait doc already names.
        declaration: PostureDeclaration,
    },
}

/// Pins a serve-set, and hands back the store those pins (or the posture
/// declaration) are in.
///
/// A trait rather than a concrete store handle because pinning is a **store
/// write**, and the store's single writer is the wallet's curve-tree actor —
/// the serving host must reach it through that actor, not around it. The
/// production implementor is the actor's handle; tests implement it
/// directly.
///
/// # The host does not choose anything about its own duty
///
/// This trait reports three things and takes none of them: **the
/// obligation** (a shard list or a CompleteTree prefix), **the evidence
/// that retains it** (per-member pin outcomes, or the prune-disabled
/// posture the witness will verify), and **which store** that evidence
/// landed in. All three come from the side holding the bond record and the
/// store, because that is the side that knows — and a value the host cannot
/// supply is a value the host cannot get wrong.
///
/// That is one rule, not three local fixes. Each parameter removed from this
/// seam closed a real defect of the same shape: a caller pairing a pinner for
/// one store with a reader for another, or handing the pin a shard list it
/// maintained alongside the record instead of derived from it
/// (`ARCHIVAL_CHALLENGE_MECHANISM.md` §9.6 item 4). Both are call-site
/// mistakes, and the fix for a call-site mistake is to delete the call site's
/// opportunity, not to validate it afterwards.
///
/// **The residual, stated rather than left implicit:** an implementor can
/// report a set it did not derive from the record, or a reader for a store it
/// did not pin. That is one engine-side implementor, reviewable by reading
/// it, and it is strictly narrower than a public constructor any caller could
/// reach. The corresponding "second construction site" therefore never comes
/// into existence rather than being permitted.
///
/// # Why the reader comes back from the pin
///
/// The pin and the serving read must land on **the same store**, and the
/// only way to make that unconditional is to derive one from the other.
/// Taking a [`ServingReader`] as a separate argument anywhere — on this
/// method, on [`super::PinnedServeSet::acquire`], or on
/// [`crate::PersonaServingHost::start`] — recreates a call site holding two
/// opaque handles that a caller can pair wrongly, which is not a fix but a
/// relocation of the same defect: pins applied to store A while store B is
/// served leaves the served store unpinned, and `prune_frozen` is then free
/// to remove the bytes a challenge will ask for. Silent to the slash, like
/// everything else on this path.
///
/// So [`PinReport`] carries both. The caller never chooses a reader, because
/// there is no argument through which to choose one. What remains is an
/// *implementor* returning a reader for some other store — a much narrower
/// surface, and the same trust level this trait already extends to the
/// reported obligation itself.
///
/// Generic rather than `dyn`: the production implementor round-trips an
/// actor message, so the method is `async`, and there is exactly one
/// implementor per process — nothing here needs the vtable that would cost
/// a boxed future.
///
/// **The `String` error is deliberate, against this codebase's usual typed-
/// error grain.** The failures an implementor can have are its own — a redb
/// fault, a dead kameo actor, a poisoned client — and this crate has no
/// business enumerating them: an error type here would either have to name
/// the curve-tree actor's failure modes (a dependency inversion) or be a
/// catch-all with one variant. What matters to the *caller* is a single
/// bit — the obligation is not retained, so no host starts — and that
/// distinction is typed, as [`PinError::Pinner`] versus
/// [`PinError::MembersAlreadyPruned`] versus
/// [`PinError::PostureNotDeclared`]: retry the first, rebuild the store
/// for the second, declare the posture for the third. The string is the
/// diagnostic riding along, and it never reaches the wire.
pub trait ServeSetPinner {
    /// Read the connected bond record, retain what it holds, and report the
    /// obligation, the evidence, and a handle on the store they landed in.
    ///
    /// **Takes no serve-set argument, deliberately.** The implementor derives
    /// the obligation from the record; the caller does not supply it. See the
    /// trait doc for why that is the whole seam rather than a convenience.
    ///
    /// The two arms retain differently:
    ///
    /// - **List** (`ReportedSet::ShardList`): pin every reported shard.
    ///   Contract matching `LeafStore::pin_serve_set`: outcomes come back
    ///   in the reported set's order, [`SegmentPin::AlreadyPruned`] is
    ///   *reported* rather than raised, the whole set is applied in one
    ///   transaction, and pinning is idempotent.
    /// - **Prefix** (`ReportedSet::CompleteTreePrefix`): declare the
    ///   prune-disabled posture (idempotent, through the curve-tree actor),
    ///   report the store's `next_freeze_seg` **and the store's answer to
    ///   the declaration** ([`PostureDeclaration`]). No per-member pin
    ///   outcomes — the posture flag is the pin. The witness verifies the
    ///   declaration, that `frozen_count` does not exceed the cursor, and
    ///   — on `NewlyDeclared` at a refresh — that the corpus survived the
    ///   unretained gap (the integrity scan).
    ///
    /// [`PinReport::reader`] must be a handle on **the store the retention
    /// landed in** — the production implementor takes both from the one
    /// `CurveTreeClient` it owns, so they cannot diverge.
    ///
    /// # Errors
    ///
    /// Implementor-defined; surfaced as [`PinError::Pinner`].
    fn pin_serve_set(&self) -> impl std::future::Future<Output = Result<PinReport, String>> + Send;
}

/// A shared reference pins exactly as the value does.
///
/// [`crate::PersonaServingHost`] takes its pinner **by value** and keeps it
/// for life — that ownership is what makes "one host, one pinner, one store"
/// structural. This impl is how a caller that must also retain the pinner
/// (a supervisor holding it to observe, a test driving holdings changes)
/// hands the host a `&P` without a second pinner existing.
impl<T: ServeSetPinner + Sync> ServeSetPinner for &T {
    fn pin_serve_set(&self) -> impl std::future::Future<Output = Result<PinReport, String>> + Send {
        (**self).pin_serve_set()
    }
}
