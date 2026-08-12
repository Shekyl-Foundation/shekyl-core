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
/// height the record was read at, so a stale set is *distinguishable* from a
/// current one rather than merely being out of date. Nothing here expires a
/// set, and nothing here decides whether to refresh: refresh is
/// unconditional (pinning is idempotent; a "did holdings change?" gate is
/// the question §9.6 item 4 exists because nobody answers it reliably).
/// The stamp is the tripwire for a refresh that has *stopped* — see
/// [`Staleness`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeSet {
    shard_ids: Vec<u64>,
    as_of_height: BlockHeight,
}

impl ServeSet {
    /// Build the set the pinner reported. Crate-private on purpose: see the
    /// type doc — a serving host does not get to name its own obligations,
    /// and the only path to a `ServeSet` runs through
    /// [`ServeSetPinner::pin_serve_set`].
    pub(crate) fn reported(shard_ids: Vec<u64>, as_of_height: BlockHeight) -> Self {
        Self {
            shard_ids,
            as_of_height,
        }
    }

    /// The bonded shard ids, in the record's own order.
    #[must_use]
    pub fn shard_ids(&self) -> &[u64] {
        &self.shard_ids
    }

    /// The chain height the record was read at.
    #[must_use]
    pub fn as_of_height(&self) -> BlockHeight {
        self.as_of_height
    }

    /// Whether this set carries no shards at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.shard_ids.is_empty()
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
    /// The pinner failed (store I/O, a dead actor, a poisoned client). The
    /// serve-set's state is unknown, so the host does not start; pinning is
    /// idempotent, so a retry re-covers whatever was already applied.
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
    /// The shard ids derived from the **connected** bond record, in the
    /// record's own order — the set the implementor pinned.
    pub shard_ids: Vec<u64>,
    /// The chain height that record was read at; becomes
    /// [`ServeSet::as_of_height`], the tripwire's first clock. A
    /// [`BlockHeight`], not a raw count: the other clock
    /// ([`ServingReader::sync_tip_height`]) is a height, and a
    /// `ChainCount` laundered in here would cry wolf by one block
    /// forever.
    pub as_of_height: BlockHeight,
    /// Each member's outcome paired with its shard id, in `shard_ids` order.
    pub outcomes: Vec<(u64, SegmentPin)>,
    /// A reader on the store the pins were applied in.
    pub reader: ServingReader,
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
    not_yet_frozen: Vec<u64>,
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
    /// the next re-pin. They are recorded in [`Self::not_yet_frozen`] because
    /// they are not servable *yet* — a shard read for one is an honest miss
    /// until the freeze boundary crosses it, and an operator looking at a
    /// non-zero miss count should be able to tell that apart from a fault.
    ///
    /// # Errors
    ///
    /// [`PinError::MembersAlreadyPruned`] if any member's bytes are already
    /// gone, and [`PinError::Pinner`] if the pin could not be applied.
    pub async fn acquire<P: ServeSetPinner>(pinner: &P) -> Result<Self, PinError> {
        let report = pinner
            .pin_serve_set()
            .await
            .map_err(|detail| PinError::Pinner { detail })?;
        let reader = report.reader.clone();
        Self::from_report(report, reader)
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
    /// # Errors
    ///
    /// Exactly [`Self::acquire`]'s.
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

    /// Validate a report's internal coherence and mint the witness. The one
    /// place the checks live, so `acquire` and `refreshed` cannot drift apart
    /// on what a witness requires.
    fn from_report(report: PinReport, reader: ServingReader) -> Result<Self, PinError> {
        let PinReport {
            shard_ids,
            as_of_height,
            outcomes,
            reader: _,
        } = report;
        let set = ServeSet::reported(shard_ids, as_of_height);
        // THE EVIDENCE MUST COVER THE OBLIGATION. The report states two
        // things — the set this persona owes, and the pins that were applied
        // — and the witness is only meaningful if the second describes the
        // first. A report whose outcomes are short mints a witness for a set
        // whose unreported members were never pinned, and an unpinned member
        // is exactly what `prune_frozen` is free to remove out from under a
        // read.
        //
        // Since the pinner now reports the set as well as the outcomes, this
        // is an internal-coherence check rather than a did-you-answer-what-I-
        // asked one. That is a narrower guarantee and worth naming: it cannot
        // catch an implementor that derived the wrong set (the residual the
        // trait doc states), but it does catch the bug class this whole slice
        // is about — two derivations of the same fact drifting apart, here
        // the reported set and the ids actually pinned.
        //
        // Sequence equality rather than set coverage: the trait promises
        // outcomes in the reported set's order, so comparing the sequence
        // enforces that contract exactly and catches omissions, extras,
        // duplicates and reordering in one comparison. A coverage-only check
        // would leave the documented ordering unverified and free to drift.
        let covered: Vec<u64> = outcomes.iter().map(|(shard_id, _)| *shard_id).collect();
        if covered != set.shard_ids() {
            return Err(PinError::PinnerCoverageMismatch {
                reported_set: set.shard_ids().to_vec(),
                covered,
            });
        }

        let pruned: Vec<u64> = outcomes
            .iter()
            .filter(|(_, pin)| *pin == SegmentPin::AlreadyPruned)
            .map(|(shard_id, _)| *shard_id)
            .collect();
        if !pruned.is_empty() {
            return Err(PinError::MembersAlreadyPruned { shard_ids: pruned });
        }

        let not_yet_frozen = outcomes
            .iter()
            .filter(|(_, pin)| *pin == SegmentPin::PinnedNotYetFrozen)
            .map(|(shard_id, _)| *shard_id)
            .collect();
        Ok(Self {
            set,
            not_yet_frozen,
            reader,
        })
    }

    /// The record-derived set these pins cover.
    #[must_use]
    pub fn serve_set(&self) -> &ServeSet {
        &self.set
    }

    /// Pinned members that have not frozen yet, so are not servable until
    /// they do.
    #[must_use]
    pub fn not_yet_frozen(&self) -> &[u64] {
        &self.not_yet_frozen
    }

    /// A reader on the store these pins are in — the store the host serves
    /// from, by construction rather than by the caller's choice.
    #[must_use]
    pub fn reader(&self) -> &ServingReader {
        &self.reader
    }

    /// How far this serve-set has fallen behind the store's own ingest.
    ///
    /// Both operands come from here: `as_of_height` from the record this set
    /// was derived from, the tip from the store the pins are in. See
    /// [`Staleness`] for why the two clocks' independence is what makes the
    /// reading meaningful.
    ///
    /// A tip *below* `as_of_height` reads as zero lag rather than as an
    /// error: the wallet's own ingest trailing the daemon's reported height
    /// is ordinary (the record is read over RPC, the tip is local), and it is
    /// not a staleness condition — nothing has been ingested that the
    /// serve-set has not seen.
    ///
    /// # Errors
    ///
    /// Store failure reading the sync tip.
    pub fn staleness(&self, bound: StalenessBound) -> Result<Staleness, StoreError> {
        let tip = self.reader.sync_tip_height()?;
        let lag = tip.0.saturating_sub(self.set.as_of_height().0);
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

/// How far a host's serve-set has fallen behind its own ingest.
///
/// Read from two clocks with **different drivers**: `as_of_height` advances
/// only when the refresh runs (the persona-side P-scan sweep), while the
/// store's sync tip advances on the principal's block scan. That
/// independence is the whole point — a refresh that has stopped freezes one
/// and not the other. Two clocks the same driver advances would read
/// `Current` forever, which is the failure the tripwire exists to catch.
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
}

impl Staleness {
    /// Whether the bound was exceeded.
    #[must_use]
    pub fn is_stale(self) -> bool {
        matches!(self, Self::Stale { .. })
    }

    /// Blocks ingested since the serve-set was last derived.
    #[must_use]
    pub fn lag(self) -> u64 {
        match self {
            Self::Current { lag } | Self::Stale { lag, .. } => lag,
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
        }
    }
}
