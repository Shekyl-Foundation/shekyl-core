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

use shekyl_curve_tree::{BlockHeight, SegmentPin, ServingReader, StoreError};

/// The shards a persona is bonded to serve, as read back from the chain.
///
/// # Where a serve-set may come from
///
/// **Not from the host, and not from its caller.** `ServeSet` has no public
/// constructor at all: the only way to obtain one is
/// [`ServeSetPinner::pin_serve_set`], which reports the shards it derived
/// from the connected bond record *and pinned*. A serving host cannot
/// nominate its own obligations, because there is no argument through which
/// to nominate them.
///
/// That is the same move made twice elsewhere on this path — the store comes
/// from the pin ([`PinReport::reader`]), and now the set does too — and it is
/// one rule rather than three fixes: **the host does not choose anything
/// about its own duty.** Every such value is reported by the side that holds
/// the bond record and the store, because that is the side that knows.
///
/// The residual is an *implementor* that reports the wrong set. That is one
/// engine-side implementor, reviewable by reading it, and it is a strictly
/// narrower surface than a constructor any caller could reach — the second
/// construction site never comes into existence rather than being permitted.
///
/// # The height stamp
///
/// A serve-set is a snapshot: holdings change on-chain (`HoldingsUpdate`),
/// and new segments freeze continuously — §9.6 item 3's point that `D` is a
/// moving number, not a plateau. [`Self::as_of_height`] records the chain
/// height the record was read at, so a set carries the provenance of the
/// claim it makes: *these shards, as the daemon's database had them at that
/// height*. Nothing here expires a set, and nothing here decides whether to
/// refresh: refresh is unconditional (pinning is idempotent; a "did holdings
/// change?" gate is the question §9.6 item 4 exists because nobody answers
/// it reliably).
///
/// **This stamp is provenance, not the staleness clock.** It is the
/// *daemon's* height, read over RPC, and the wallet's own ingest is
/// routinely far behind it — a wallet catching up after a week offline is
/// thousands of blocks below a record stamped at the daemon's tip.
/// Subtracting the two would measure how far this wallet trails its daemon,
/// which reads healthy for exactly as long as the catch-up lasts. The
/// tripwire is built from one clock read twice instead; see [`Staleness`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeSet {
    derivation: SetDerivation,
    as_of_height: BlockHeight,
}

/// The two shapes an obligation can take — private so both stay
/// reported-only: a public enum's variants are public constructors, and the
/// no-public-constructor rule is the module's load-bearing property.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SetDerivation {
    /// Explicit holdings: the record's shard list, in the record's order.
    ShardList(Vec<u64>),
    /// The whole frozen corpus, as a structural prefix (`COMPLETETREE_
    /// ACTIVATION.md` D-1): frozen segments are exactly `[0, frozen_count)`,
    /// so the obligation is one number, never a stored list. `frozen_count`
    /// is the store's burial-gated freeze cursor (`LeafStore::
    /// next_freeze_seg`), **not** `shekyl_archival_retention::
    /// frozen_segment_count` — that helper is first-crossing completeness
    /// and would admit unburied segments as owed.
    CompleteTreePrefix { frozen_count: u64 },
}

impl ServeSet {
    /// Build the list-arm set the pinner reported. Crate-private on purpose:
    /// see the type doc — a serving host does not get to name its own
    /// obligations, and the only path to a `ServeSet` runs through
    /// [`ServeSetPinner::pin_serve_set`].
    pub(crate) fn reported(shard_ids: Vec<u64>, as_of_height: BlockHeight) -> Self {
        Self {
            derivation: SetDerivation::ShardList(shard_ids),
            as_of_height,
        }
    }

    /// Build the prefix-arm set the pinner reported. Crate-private for the
    /// same reason as [`Self::reported`].
    pub(crate) fn reported_prefix(frozen_count: u64, as_of_height: BlockHeight) -> Self {
        Self {
            derivation: SetDerivation::CompleteTreePrefix { frozen_count },
            as_of_height,
        }
    }

    /// The bonded shard ids, in the record's own order — `None` for the
    /// CompleteTree prefix arm, which has no list to return.
    ///
    /// Deliberately not an empty slice for the prefix arm: an empty list and
    /// a whole-corpus obligation are this arc's two-empties hazard (the
    /// `CompleteTree` wire form decodes to the same bytes as owing nothing),
    /// and an accessor that renders "everything" as `[]` would rebuild that
    /// conflation one layer up.
    #[must_use]
    pub fn shard_ids(&self) -> Option<&[u64]> {
        match &self.derivation {
            SetDerivation::ShardList(shard_ids) => Some(shard_ids),
            SetDerivation::CompleteTreePrefix { .. } => None,
        }
    }

    /// The frozen-prefix length — `None` for the shard-list arm.
    #[must_use]
    pub fn complete_tree_frozen_count(&self) -> Option<u64> {
        match self.derivation {
            SetDerivation::ShardList(_) => None,
            SetDerivation::CompleteTreePrefix { frozen_count } => Some(frozen_count),
        }
    }

    /// Whether `shard_id` is in this persona's obligation.
    ///
    /// List arm: set membership. Prefix arm: `shard_id < frozen_count`.
    ///
    /// **Exposed, not wired.** The request path does not consult serve-set
    /// membership anywhere today — `StoreShardProvider` answers from the
    /// store, whose per-read `Ok(None)` for an uncommitted segment is the
    /// live servability authority — and this slice deliberately does not
    /// invent request-path behavior for the predicate to gate (the brief's
    /// halt condition, honored by stopping here). It exists so the arm's
    /// meaning is a method callers share, not a comparison each consumer
    /// re-derives.
    #[must_use]
    pub fn contains(&self, shard_id: u64) -> bool {
        match &self.derivation {
            SetDerivation::ShardList(shard_ids) => shard_ids.contains(&shard_id),
            SetDerivation::CompleteTreePrefix { frozen_count } => shard_id < *frozen_count,
        }
    }

    /// The chain height the record was read at.
    #[must_use]
    pub fn as_of_height(&self) -> BlockHeight {
        self.as_of_height
    }

    /// Whether this obligation is empty: an empty list, or a prefix over a
    /// store that has frozen nothing yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match &self.derivation {
            SetDerivation::ShardList(shard_ids) => shard_ids.is_empty(),
            SetDerivation::CompleteTreePrefix { frozen_count } => *frozen_count == 0,
        }
    }
}

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
    /// answer [`PinnedServeSet::staleness`] at all, so there is nothing
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
        }
    }
}

impl std::error::Error for PinError {}

/// What a [`ServeSetPinner`] returns: the per-member pin outcomes, and a
/// read-only handle on the store they were written to.
///
/// The two travel together so they cannot be paired wrongly — see the trait
/// doc for why that is a soundness property and not a convenience.
#[derive(Debug, Clone)]
pub struct PinReport {
    /// The obligation the implementor derived from the **connected** bond
    /// record, with the evidence appropriate to its arm.
    pub set: ReportedSet,
    /// The chain height that record was read at; becomes
    /// [`ServeSet::as_of_height`], the set's **provenance** stamp.
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
/// Public fields on a public enum, unlike [`ServeSet`]: this is the
/// *reported* side of the seam — the implementor builds it, and the
/// implementor is already the trusted residual the trait doc names. The
/// witness the host holds is still minted only through
/// [`PinnedServeSet::acquire`]/[`refreshed`](PinnedServeSet::refreshed),
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
    /// the declaration ([`PinError::PostureNotDeclared`]) instead of
    /// checking rows.
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
    },
}

/// Pins a serve-set, and hands back the store those pins are in.
///
/// A trait rather than a concrete store handle because pinning is a **store
/// write**, and the store's single writer is the wallet's curve-tree actor —
/// the serving host must reach it through that actor, not around it. The
/// production implementor is the actor's handle; tests implement it
/// directly.
///
/// # The host does not choose anything about its own duty
///
/// This trait reports three things and takes none of them: **which shards**
/// the persona is obligated to serve, **whether they are pinned**, and
/// **which store** they are pinned in. All three come from the side holding
/// the bond record and the store, because that is the side that knows —
/// and a value the host cannot supply is a value the host cannot get wrong.
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
/// method, on [`PinnedServeSet::acquire`], or on
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
/// surface, and the same trust level this trait already extends to the pin
/// outcomes themselves.
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
/// bit — the pins are not established, so no host starts — and that
/// distinction is typed, as [`PinError::Pinner`] versus
/// [`PinError::MembersAlreadyPruned`]: retry the first, rebuild the store
/// for the second. The string is the diagnostic riding along, and it never
/// reaches the wire.
pub trait ServeSetPinner {
    /// Read the connected bond record, pin every shard it holds, and report
    /// the set, the outcomes, and a handle on the store they landed in.
    ///
    /// **Takes no serve-set argument, deliberately.** The implementor derives
    /// the shards from the record; the caller does not supply them. See the
    /// trait doc for why that is the whole seam rather than a convenience.
    ///
    /// Contract (matching `LeafStore::pin_serve_set`, which the production
    /// implementor forwards to): outcomes come back in the caller's order,
    /// [`SegmentPin::AlreadyPruned`] is *reported* rather than raised, the
    /// whole set is applied in one transaction, and pinning is idempotent.
    /// [`PinReport::reader`] must be a handle on **the store the pins were
    /// written to** — the production implementor takes both from the one
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

/// A serve-set whose pins are in place — the host's live pin state.
///
/// [`Self::acquire`] is the only way to mint one. The host calls it
/// inside [`crate::PersonaServingHost::start`] (so serving cannot begin
/// unpinned) and replaces the result on every [`crate::PersonaServingHost::refresh`].
/// It is not a ticket the caller hands `start`: that argument was removed
/// so a host cannot be started on pins its later refreshes cannot reach.
///
/// The sealed-witness shape this codebase already uses for
/// `VerifiedTorBinary` (the binary passed its hash gate) and
/// `VanguardsActive` (full vanguards are configured on this incarnation),
/// applied to the third precondition a serving persona has: **its shards
/// will survive the next prune**. Possessing one is evidence the pin ran;
/// replacing one is how holdings that arrive later stay covered.
///
/// It also carries the [`ServeSet`], so the host holds the record-derived
/// list rather than a second copy of it.
///
/// # A point-in-time fact, not a standing property
///
/// This witnesses that **these** shards were pinned against the record read
/// at [`ServeSet::as_of_height`] — not that the host's pins still match the
/// connected record. They diverge whenever holdings change: an ordinary
/// `HoldingsUpdate` (which an archiver posts continuously to keep covering
/// newly frozen segments) or a reorg that alters `held_shard_ids` without
/// moving the curve tree. The store clears pins on **tree** rollback only,
/// and there is no unpin path at all, so nothing self-corrects.
///
/// The consequence that matters: a shard *gained* after this witness was
/// minted is unpinned, and a `prune_frozen` in that window discards bytes no
/// re-pin can restore. Keeping the set current is the refresh loop's job
/// (SH-2), and the governing rule is that **acquiring a pin needs no
/// finality while releasing one does** — re-pin the whole set on every
/// refresh, unconditionally; release, if implemented at all, waits on a
/// finality depth, because a reorged-back release can cost bytes a slash is
/// measured in while the disk it reclaims is merely disk. See
/// `ARCHIVAL_CHALLENGE_MECHANISM.md` §9.7 item 5.
#[derive(Debug, Clone)]
pub struct PinnedServeSet {
    set: ServeSet,
    not_yet_frozen_at_last_pin: Vec<u64>,
    already_pruned: Vec<u64>,
    /// The store's ingest tip when this witness was minted — the staleness
    /// baseline, read from [`Self::reader`] so the later reading is the
    /// same quantity from the same store. See [`Staleness`].
    minted_at_tip: BlockHeight,
    /// The store these pins are in — carried, never supplied, so the host
    /// cannot serve a different one. No `PartialEq`/`Eq` on this type as a
    /// result; nothing needs them, and a store handle has no meaningful
    /// equality anyway.
    reader: ServingReader,
}

impl PinnedServeSet {
    /// Pin the set the pinner reports and mint the witness.
    ///
    /// Members that have not frozen yet are pinned and **accepted**: bonding
    /// before a segment freezes is legal by design, and pinning ahead is
    /// what stops a prune from landing in the window between the freeze and
    /// the next re-pin. They are recorded in
    /// [`Self::not_yet_frozen_at_last_pin`] because they are not servable
    /// *yet* — a shard read for one is an honest miss until the freeze
    /// boundary crosses it, and an operator looking at a non-zero miss count
    /// should be able to tell that apart from a fault.
    ///
    /// **A pruned member refuses the start.** Nothing is serving yet, so
    /// refusing costs nothing and the remedy — rebuild the store by chain
    /// replay — wants to be paid before the persona advertises itself.
    /// [`Self::refreshed`] deliberately does *not* refuse: see its doc.
    /// (List arm only: a CompleteTree-prefix report has no per-member
    /// outcomes to be pruned in — the posture flag it verifies instead is
    /// what makes pruning unrepresentable — so this refusal is structurally
    /// unreachable for it.)
    ///
    /// # Errors
    ///
    /// [`PinError::MembersAlreadyPruned`] if any member's bytes are already
    /// gone, [`PinError::PinnerCoverageMismatch`] if the report's outcomes do
    /// not describe the set it claims, and [`PinError::Pinner`] if the pin
    /// could not be applied or the store's ingest tip could not be read.
    pub async fn acquire<P: ServeSetPinner>(pinner: &P) -> Result<Self, PinError> {
        let report = pinner
            .pin_serve_set()
            .await
            .map_err(|detail| PinError::Pinner { detail })?;
        let reader = report.reader.clone();
        let pinned = Self::from_report(report, reader)?;
        // The refusal lives here rather than inside `from_report`, which both
        // constructors share. `refreshed` must be able to mint a witness that
        // *records* terminally-pruned members without failing (see its doc), so
        // a check pushed down into the shared constructor could not tell the two
        // callers apart without being handed a flag saying which one it was —
        // which is this `if` with extra steps, one level further from the
        // asymmetry it encodes.
        if !pinned.already_pruned.is_empty() {
            return Err(PinError::MembersAlreadyPruned {
                shard_ids: pinned.already_pruned,
            });
        }
        Ok(pinned)
    }

    /// Re-pin `set` through `pinner`, **keeping this witness's store**.
    ///
    /// The reader the pinner returns is deliberately discarded here, and that
    /// is a soundness choice rather than an oversight. The store a host
    /// serves is bound to its listener, and the listener never rebinds — so
    /// the served store cannot change for the life of the host, and a refresh
    /// that could swap it would defeat the no-rebind invariant from the other
    /// side: the endpoint would stay up, still published, now reading a store
    /// nobody pinned. Refresh therefore changes *which shards*, never *which
    /// store*.
    ///
    /// **A terminally-pruned member does not refuse the refresh.** This is
    /// the one place the refresh's checks deliberately diverge from
    /// [`Self::acquire`]'s, and the asymmetry is the point:
    /// [`SegmentPin::AlreadyPruned`] is terminal by the store's own contract
    /// (chain replay, not retry), so a whole-set refusal here would make
    /// *every* later refresh fail for the life of the host. The witness
    /// would freeze, and every shard connected afterwards would go unpinned
    /// and prunable — §9.6 item 4's slash, re-entering through the error
    /// path of the very refresh that exists to close it. One member whose
    /// bytes are already gone must not cost the other members their pins.
    /// The pins the report *did* apply are already committed in the store
    /// regardless (the pinner writes them in one transaction and reports
    /// `AlreadyPruned` rather than raising it), so installing the new
    /// witness records what is true; the unrecoverable members stay visible
    /// on [`Self::already_pruned`].
    ///
    /// # Errors
    ///
    /// [`PinError::Pinner`] if the pin could not be applied or the ingest
    /// tip could not be read, [`PinError::PinnerCoverageMismatch`] if the
    /// report's outcomes do not describe the set it claims, and
    /// [`PinError::PinnerStoreMismatch`] if the pins landed in a different
    /// open store. Never [`PinError::MembersAlreadyPruned`] — that refusal
    /// is `acquire`-only, per the paragraph above.
    pub async fn refreshed<P: ServeSetPinner>(&self, pinner: &P) -> Result<Self, PinError> {
        let report = pinner
            .pin_serve_set()
            .await
            .map_err(|detail| PinError::Pinner { detail })?;
        // Pins must have landed in the store this witness already serves.
        // `same_store` is allocation identity, and that is store identity
        // here: the wallet's curve-tree handle keeps the store Arc across
        // fail-stop and resumes the writer over it, so a healthy recovery
        // does not mint a second database. A report whose reader is a
        // different Arc is therefore a different open store — the pins
        // are not in the one the host is reading.
        if !self.reader.same_store(&report.reader) {
            return Err(PinError::PinnerStoreMismatch);
        }
        Self::from_report(report, self.reader.clone())
    }

    /// Validate a report's **soundness as a witness** and mint it. The one
    /// place those checks live, so `acquire` and `refreshed` cannot drift
    /// apart on what a witness requires.
    ///
    /// Soundness, not fitness: this function decides whether the report's
    /// evidence supports its claim — list arm: the outcomes describe the
    /// reported set; prefix arm: the posture declaration the claim rests on
    /// is actually in the store — never whether the resulting witness is fit
    /// to start serving. Fitness is a policy question, it differs between
    /// the two callers, and it therefore lives in the caller — `acquire`
    /// refuses a pruned member, `refreshed` records it. Splitting on that
    /// line is what keeps this function free of a mode flag. (The posture
    /// check does NOT differ per caller, which is why it belongs here: the
    /// flag is one-way, so a missing declaration is an implementor defect in
    /// both directions, and refusing a refresh over it cannot wedge the loop
    /// the way a terminal `AlreadyPruned` refusal would.)
    fn from_report(report: PinReport, reader: ServingReader) -> Result<Self, PinError> {
        let PinReport {
            set: reported,
            as_of_height,
            reader: _,
        } = report;
        let (set, not_yet_frozen_at_last_pin, already_pruned) = match reported {
            ReportedSet::ShardList {
                shard_ids,
                outcomes,
            } => {
                // THE EVIDENCE MUST COVER THE OBLIGATION. The report states
                // two things — the set this persona owes, and the pins that
                // were applied — and the witness is only meaningful if the
                // second describes the first. A report whose outcomes are
                // short mints a witness for a set whose unreported members
                // were never pinned, and an unpinned member is exactly what
                // `prune_frozen` is free to remove out from under a read.
                //
                // Since the pinner reports the set as well as the outcomes,
                // this is an internal-coherence check rather than a did-you-
                // answer-what-I-asked one. That is a narrower guarantee and
                // worth naming: it cannot catch an implementor that derived
                // the wrong set (the residual the trait doc states), but it
                // does catch the bug class this whole slice is about — two
                // derivations of the same fact drifting apart, here the
                // reported set and the ids actually pinned.
                //
                // Sequence equality rather than set coverage: the trait
                // promises outcomes in the reported set's order, so comparing
                // the sequence enforces that contract exactly and catches
                // omissions, extras, duplicates and reordering in one
                // comparison. A coverage-only check would leave the
                // documented ordering unverified and free to drift.
                let covered: Vec<u64> = outcomes.iter().map(|(shard_id, _)| *shard_id).collect();
                if covered != shard_ids {
                    return Err(PinError::PinnerCoverageMismatch {
                        reported_set: shard_ids,
                        covered,
                    });
                }

                let already_pruned: Vec<u64> = outcomes
                    .iter()
                    .filter(|(_, pin)| *pin == SegmentPin::AlreadyPruned)
                    .map(|(shard_id, _)| *shard_id)
                    .collect();
                let not_yet_frozen_at_last_pin: Vec<u64> = outcomes
                    .iter()
                    .filter(|(_, pin)| *pin == SegmentPin::PinnedNotYetFrozen)
                    .map(|(shard_id, _)| *shard_id)
                    .collect();
                (
                    ServeSet::reported(shard_ids, as_of_height),
                    not_yet_frozen_at_last_pin,
                    already_pruned,
                )
            }
            ReportedSet::CompleteTreePrefix { frozen_count } => {
                // THE DECLARATION MUST BACK THE CLAIM — the prefix arm's
                // coverage check. There are no outcomes to cover the set
                // because the posture flag is the pin, so what the witness
                // must verify is that the flag is actually declared in the
                // store these bytes live in. Read from the reader rather
                // than trusted from the report: the reader is the store,
                // and a claim about the store is checked against the store.
                //
                // Both `not_yet_frozen_at_last_pin` and `already_pruned` are
                // structurally empty here: the prefix is the *frozen* set by
                // definition (an unfrozen segment is not in `[0, k)`), and
                // nothing under the declared posture can prune — which is
                // also why `PinError::MembersAlreadyPruned` is unreachable
                // for this arm. The list-arm check stays: explicit holdings
                // ride per-member pins and can still meet pruned bytes.
                let declared = reader.prune_disabled().map_err(|e| PinError::Pinner {
                    detail: format!("posture read failed: {e:?}"),
                })?;
                if !declared {
                    return Err(PinError::PostureNotDeclared);
                }
                (
                    ServeSet::reported_prefix(frozen_count, as_of_height),
                    Vec::new(),
                    Vec::new(),
                )
            }
        };

        // THE STALENESS BASELINE, TAKEN FROM THE SAME STORE THE PINS ARE IN.
        // Stamping it here rather than accepting it in the report is what
        // makes the later reading a difference of one quantity: `staleness`
        // re-reads this exact call on this exact reader, so there is no
        // second clock to mismatch. It is deliberately *not* the record's
        // `as_of_height`, which is the daemon's height over RPC.
        //
        // The stamp is taken after the pin commits, so ingest can advance in
        // between and land it a round trip high — which understates lag by
        // however many blocks arrived during one actor `ask`. Named rather
        // than corrected: the bound this feeds is measured in blocks of
        // ingest, and a bound that could not absorb a single round trip
        // would be reporting the scheduler, not the serve-set.
        let minted_at_tip = reader.sync_tip_height().map_err(|e| PinError::Pinner {
            detail: format!("staleness baseline read failed: {e:?}"),
        })?;

        Ok(Self {
            set,
            not_yet_frozen_at_last_pin,
            already_pruned,
            minted_at_tip,
            reader,
        })
    }

    /// The record-derived set these pins cover.
    #[must_use]
    pub fn serve_set(&self) -> &ServeSet {
        &self.set
    }

    /// Members that had not frozen yet **when this witness was minted**, so
    /// were pinned but not servable at that moment.
    ///
    /// The name carries the tense on purpose. This is a snapshot taken at
    /// the last pin and never re-evaluated: a segment that freezes a block
    /// later stays on this list until the next successful refresh replaces
    /// the witness. It is a *diagnostic* — the thing that lets an operator
    /// read a non-zero miss count as "bonded ahead of the freeze" rather
    /// than "faulty" — and it must not be used to decide whether a shard is
    /// servable.
    ///
    /// Servability has exactly one authority and it is live: the store
    /// answers it on every read, because
    /// [`ServingReader::open_frozen_segment_body`] returns `Ok(None)` for a
    /// segment with no committed `R_k`. The serving loop already asks it
    /// there, per request. A second, staler answer to the same question is
    /// the kind of duplicate that only ever drifts, so this one is scoped by
    /// its name to the question it can actually answer.
    #[must_use]
    pub fn not_yet_frozen_at_last_pin(&self) -> &[u64] {
        &self.not_yet_frozen_at_last_pin
    }

    /// Members whose leaf bytes were already gone at the last pin.
    ///
    /// Always empty on a witness from [`Self::acquire`], which refuses to
    /// start over one. Non-empty only on a [`Self::refreshed`] witness,
    /// where refusing would wedge every later refresh — the operator-facing
    /// record of a store that needs rebuilding by chain replay while the
    /// persona keeps serving everything it still has.
    #[must_use]
    pub fn already_pruned(&self) -> &[u64] {
        &self.already_pruned
    }

    /// A reader on the store these pins are in — the store the host serves
    /// from, by construction rather than by the caller's choice.
    #[must_use]
    pub fn reader(&self) -> &ServingReader {
        &self.reader
    }

    /// How much this wallet has ingested since this serve-set was derived.
    ///
    /// **One clock, read twice.** Both operands are
    /// [`ServingReader::sync_tip_height`] on this witness's own store: the
    /// baseline stamped when the witness was minted, and the tip now. See
    /// [`Staleness`] for why that pair is a liveness signal and why a remote
    /// height is not.
    ///
    /// A tip *below* the baseline is [`Staleness::RolledBack`], never a
    /// saturating zero. Once both operands are the same clock, going
    /// backwards can only be a store event — `truncate_from_tree_position`
    /// or `rollback_to_fork` — and those delete pinned-segment rows above
    /// the truncation point, so the witness is claiming pins the store may
    /// have just dropped. Reporting that as "zero blocks behind" would be an
    /// affirmative all-clear on the one store event that can unpin a member.
    ///
    /// This reading cannot see a refresh that is *failing* rather than
    /// stopped; that is host state, and
    /// [`crate::PersonaServingHost::staleness`] folds it in.
    ///
    /// # Errors
    ///
    /// Store failure reading the sync tip.
    /// The members this witness asserts are pinned: the reported set minus the
    /// terminally pruned ones.
    ///
    /// `already_pruned` members are excluded because they never had a pin row
    /// — `pin_ids_within` writes one for every outcome *except*
    /// `AlreadyPruned` — so counting them as claimed would report a permanent
    /// drop on a witness that is behaving exactly as documented.
    fn claimed_members(&self) -> Vec<u64> {
        match self.set.shard_ids() {
            Some(shard_ids) => shard_ids
                .iter()
                .copied()
                .filter(|id| !self.already_pruned.contains(id))
                .collect(),
            // The prefix arm claims no per-member pins — retention is the
            // posture flag, checked in `staleness` — so there are no
            // members whose pin rows could be interrogated.
            None => Vec::new(),
        }
    }

    /// Which claimed members the store no longer holds pins for.
    ///
    /// The diagnostic behind [`Staleness::PinsDropped`], which carries only a
    /// ratio so it can stay `Copy`. Call this when an operator needs the ids —
    /// a log line, a CLI report — rather than on every poll.
    ///
    /// Always empty for a CompleteTree-prefix witness: no per-member pin
    /// rows exist to drop, and the retention it rests on (the posture flag)
    /// is checked by [`Self::staleness`] on every poll instead.
    ///
    /// # Errors
    ///
    /// Store failure reading the pinned-segment table.
    pub fn dropped_pins(&self) -> Result<Vec<u64>, StoreError> {
        self.reader.members_missing_pins(&self.claimed_members())
    }

    pub fn staleness(&self, bound: StalenessBound) -> Result<Staleness, StoreError> {
        // Checked before any tip arithmetic, because it is the only reading
        // here that reports an exposure rather than a risk of one — and
        // because the tip cannot answer it. A member whose pin row is gone is
        // prunable now, whatever the tip says, and re-ingest moves the tip
        // back above the stamp without restoring a single pin. Ordering this
        // second would let the arithmetic below return `Current` over it.
        match self.set.complete_tree_frozen_count() {
            None => {
                // The claimed set is every member except the terminally
                // pruned ones: `pin_ids_within` writes a row for
                // `PinnedNotYetFrozen` as well as `PinnedServable`, and
                // `already_pruned` members never had one, so including them
                // would report a permanent false positive.
                let claimed = self.claimed_members();
                let dropped = self.reader.members_missing_pins(&claimed)?;
                if !dropped.is_empty() {
                    return Ok(Staleness::PinsDropped {
                        dropped: u32::try_from(dropped.len()).unwrap_or(u32::MAX),
                        claimed: u32::try_from(claimed.len()).unwrap_or(u32::MAX),
                    });
                }
            }
            Some(frozen_count) => {
                // The prefix arm's analogue of the pin-rows read: the
                // retention this witness rests on is the posture flag, so
                // that is what gets re-read from the store on every poll —
                // measured, not inferred, window-free, exactly like the pin
                // table it replaces. Every store surface makes the flag
                // one-way, so a `false` here is corruption or tampering,
                // and it lands on the same arm because the meaning is the
                // list arm's exactly: the retention behind the witness is
                // gone, everything it claims is prunable now, and it clears
                // only when a refresh re-declares. `dropped == claimed`
                // states the store-wide scope the arm's docs already give
                // that shape.
                if !self.reader.prune_disabled()? {
                    let claimed = u32::try_from(frozen_count).unwrap_or(u32::MAX);
                    return Ok(Staleness::PinsDropped {
                        dropped: claimed,
                        claimed,
                    });
                }
            }
        }

        let tip = self.reader.sync_tip_height()?;
        let Some(lag) = tip.0.checked_sub(self.minted_at_tip.0) else {
            return Ok(Staleness::RolledBack {
                minted_at_tip: self.minted_at_tip.0,
                tip: tip.0,
            });
        };
        Ok(if lag > bound.get() {
            Staleness::Stale {
                lag,
                bound: bound.get(),
            }
        } else {
            Staleness::Current { lag }
        })
    }
}

/// How many blocks of local ingest a serve-set may lag the record it was
/// derived from before the host is considered stale.
///
/// **Injectable, and deliberately not pinned here.** The tolerable lag is
/// "how long can a newly-connected shard go unpinned before a challenge can
/// ask for it", which is a function of the assignment schedule and
/// drawability — fork-2-adjacent territory, and the same class of number the
/// round refuses to guess for W₂ (`ARCHIVAL_CHALLENGE_MECHANISM.md` §7 fork
/// 5: deriving it first would be picking a number and back-filling the
/// justification). Injected rather than constant, on the `ScanSchedule`
/// precedent: the loop takes its cadence as a parameter so a later round can
/// pin it without touching the loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StalenessBound(u64);

impl StalenessBound {
    /// A bound of `blocks` of local ingest.
    #[must_use]
    pub const fn blocks(blocks: u64) -> Self {
        Self(blocks)
    }

    /// The bound in blocks.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Whether a host's serve-set is still tracking its bond record.
///
/// # One clock read twice, and two drivers
///
/// The lag is [`ServingReader::sync_tip_height`] now, minus the same value
/// stamped when the witness was minted. That is deliberately *one* quantity:
/// a difference of two different quantities is only a lag when they happen
/// to agree, and the two available here do not — the record's
/// [`ServeSet::as_of_height`] is the daemon's tip over RPC, and a wallet
/// catching up sits thousands of blocks below it. Subtracting those would
/// read `Current { lag: 0 }` for the whole catch-up, which is exactly the
/// window in which holdings move and a gained shard goes unpinned.
///
/// What makes one clock a *liveness* signal is that the reader and the
/// writer of the stamp are different: the stamp is taken by the persona-side
/// P-scan refresh, and the value it stamps is advanced by the principal's
/// block scan. Stop the refresh and the stamp freezes while ingest keeps
/// climbing. A quantity the same driver moved on both sides would read
/// `Current` forever, which is the failure this exists to catch.
///
/// # What it cannot see
///
/// A wallet where the block scan **and** the refresh have both stopped —
/// most concretely a curve-tree actor that fail-stopped and could not be
/// resumed — freezes ingest and the stamp together, and the lag stays
/// constant. [`Self::RefreshFailing`] is the arm that covers it, and it is
/// host state rather than store state precisely so that a common-mode store
/// fault cannot silence it: a refresh that keeps being *attempted* and keeps
/// failing is evidence no store reading can supply.
///
/// The residual, stated rather than left implicit: if the refresh loop is
/// itself gone *and* ingest is stopped, nothing is attempted and nothing
/// advances, so there is no local evidence at all. That is a wallet in which
/// no task is running, and it is out of reach of any signal this host can
/// produce from inside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Staleness {
    /// Within the bound.
    Current {
        /// Blocks ingested since the serve-set was last derived.
        lag: u64,
    },
    /// Past the bound: the serve-set has stopped tracking the bond record.
    ///
    /// **This is the shape the refresh's own failure takes, and it needs no
    /// adversary.** The refresh is periodic and lives *outside* the host, so
    /// anything that stops it stops it silently from here: the task is
    /// cancelled and nothing restarts it, the task was never started, it
    /// panics, or every sweep fails and retries forever against a daemon
    /// that is simply unreachable. A host whose refresh has stopped keeps
    /// serving a frozen serve-set, and a shard connected after the freeze is
    /// unpinned and prunable — the same ordinary steady-state hazard
    /// [`crate::PersonaServingHost::refresh`] exists to close, re-entering
    /// through the trigger rather than through the pins.
    ///
    /// A periodic job that has stopped is invisible to whatever depends on
    /// it; that is the whole of the argument, and it holds under every
    /// posture and every threat model. This is the only local evidence.
    Stale {
        /// Blocks ingested since the serve-set was last derived.
        lag: u64,
        /// The bound that was exceeded.
        bound: u64,
    },
    /// The store's ingest tip is **below** where it was when this witness
    /// was minted: the tree rolled back beneath these pins.
    ///
    /// Its own arm rather than a saturating zero, and rather than folding
    /// into [`Self::Stale`], because the diagnosis differs completely even
    /// though the next action is the same. `Stale` says the refresh
    /// machinery has stopped and should be investigated; this says a reorg
    /// happened, nothing is broken, and the next refresh tick re-pins and
    /// re-stamps. Sending an operator to debug a healthy refresh loop is a
    /// false alarm, and false alarms are how a tripwire gets ignored.
    ///
    /// **This arm does not answer the pin question, and must not be read as
    /// if it did.** It is a statement about the tip only. An earlier version
    /// of this doc said a rollback means "during this window the witness names
    /// pins the store no longer holds" — true, and the trap is the phrase
    /// *this window*: the tip is not monotonic, so re-ingest lifts it back
    /// above the stamp and closes the window while the deleted pin rows stay
    /// deleted. Whether pins are actually gone is measured by
    /// [`Self::PinsDropped`], which is checked first and has no window.
    RolledBack {
        /// The ingest tip stamped when the witness was minted.
        minted_at_tip: u64,
        /// The ingest tip now — below `minted_at_tip`.
        tip: u64,
    },
    /// Members this witness claims are pinned **are no longer pinned in the
    /// store**, so `prune_frozen` is free to discard their bytes.
    ///
    /// The most serious arm, and the only one that reports an exposure that
    /// has already happened rather than a signal that one might be developing.
    ///
    /// **Measured, not inferred, and that is the whole point.** Pins are
    /// deleted by `truncate_from_tree_position` / `rollback_to_fork` (the F9
    /// pinned-segment rollback) and **nothing recreates them but a re-pin** —
    /// block ingest does not. [`Self::RolledBack`] can only see the window
    /// where the tip is still below the stamp, and the tip is not monotonic:
    /// once the principal re-ingests past that height the subtraction goes
    /// positive again and every tip-derived arm reports `Current` while the
    /// pins stay gone. A host whose refresh trigger is the failed component
    /// would return to an affirmative healthy reading while serving shards
    /// nothing retains. Asking the pin table directly has no such window.
    ///
    /// **It cannot self-clear.** The condition is re-read from the store on
    /// every call, so it persists until a refresh actually re-pins — which
    /// mints a new witness. That is the latch, and it is structural rather
    /// than a flag someone has to remember to reset.
    /// A ratio rather than the id list, so this stays `Copy` like every other
    /// arm — it is polled beside the tor posture and folded into one operator
    /// alarm, and a status value that allocates would be the odd one out.
    /// `dropped` against `claimed` also separates the two cases that differ in
    /// remedy: a partial loss is a reorg above some members, while
    /// `dropped == claimed` is a store-wide event. The ids themselves are a
    /// diagnostic rather than a status, and live on
    /// [`PinnedServeSet::dropped_pins`].
    PinsDropped {
        /// Claimed members with no pin row.
        dropped: u32,
        /// Members this witness claims are pinned — the denominator.
        claimed: u32,
    },
    /// The last refresh attempt **failed**, and this many have failed in a
    /// row since the last success.
    ///
    /// Produced by [`crate::PersonaServingHost::staleness`], never by
    /// [`PinnedServeSet::staleness`]: it is a fact about attempts, not about
    /// the store, and that is what makes it the one arm a store-wide fault
    /// cannot suppress. When ingest and the refresh stop together — the
    /// fail-stopped curve-tree actor — the lag arms freeze and this one
    /// keeps counting.
    ///
    /// **No threshold, deliberately.** Reporting the first failure is not a
    /// verdict that the host is broken; it is the fact that the last attempt
    /// did not succeed, and `consecutive` is what separates a transient RPC
    /// blip from a refresh that has been failing for four hundred ticks.
    /// Inventing a "how many failures is too many" constant here would be
    /// the number-first, justification-after move this round refuses
    /// elsewhere — and unlike [`StalenessBound`], there is no injection site
    /// that would make it anyone else's to choose yet.
    RefreshFailing {
        /// Failed refresh attempts since the last successful one; at least 1.
        consecutive: u32,
    },
}

impl Staleness {
    /// Whether the serve-set is **not** known to be tracking the record.
    ///
    /// True for every arm but [`Self::Current`]. Note that a single failed
    /// refresh already reads stale: the arms report what is known, and what
    /// is known after a failed attempt is that the set was not re-derived.
    /// A caller that wants to tolerate a blip should match
    /// [`Self::RefreshFailing`] and read `consecutive` rather than ask this
    /// question.
    #[must_use]
    pub fn is_stale(self) -> bool {
        !matches!(self, Self::Current { .. })
    }

    /// Blocks ingested since the serve-set was last derived, where that is a
    /// meaningful number.
    ///
    /// `None` for [`Self::RolledBack`] (the store un-ingested; the
    /// difference is not a lag) and [`Self::RefreshFailing`] (no store
    /// reading was taken). Returning `0` for those would be the same
    /// false all-clear this reading exists to avoid, one layer up.
    #[must_use]
    pub fn lag(self) -> Option<u64> {
        match self {
            Self::Current { lag } | Self::Stale { lag, .. } => Some(lag),
            Self::RolledBack { .. } | Self::RefreshFailing { .. } | Self::PinsDropped { .. } => {
                None
            }
        }
    }
}

impl std::fmt::Display for Staleness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Current { lag } => write!(f, "serve-set current ({lag} blocks behind ingest)"),
            Self::Stale { lag, bound } => write!(
                f,
                "serve-set has not been re-derived for {lag} blocks of ingest (bound {bound}): \
                 a shard connected since then is unpinned and can be pruned before it is \
                 served — check that refresh is still succeeding"
            ),
            Self::RolledBack { minted_at_tip, tip } => write!(
                f,
                "the curve-tree store rolled back beneath this serve-set (ingest tip {tip}, \
                 pinned at {minted_at_tip}): a rollback drops pinned-segment rows above the \
                 fork, so these shards may no longer be pinned. The next refresh re-pins them; \
                 no action is needed unless this persists"
            ),
            Self::RefreshFailing { consecutive } => write!(
                f,
                "the serve-set refresh has failed {consecutive} time(s) in a row: the shard \
                 list is not being re-derived, so a shard connected since the last success is \
                 unpinned and can be pruned before it is served — check the persona's daemon \
                 transport and the curve-tree actor"
            ),
            Self::PinsDropped { dropped, claimed } => write!(
                f,
                "{dropped} of {claimed} serve-set members are no longer pinned in the store: \
                 their bytes can be pruned now, and this persona would fail a challenge on \
                 them. A rollback drops pinned rows and block ingest does not restore them, \
                 so this clears only when a refresh re-pins — check that refresh is still \
                 succeeding"
            ),
        }
    }
}
