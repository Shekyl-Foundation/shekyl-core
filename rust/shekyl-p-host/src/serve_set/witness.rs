// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The sealed witness: a serve-set whose retention is in place.

use shekyl_curve_tree::{BlockHeight, SegmentPin, ServingReader, StoreError};

use super::{
    PinError, PinReport, ReportedSet, ServeObligation, ServeSet, ServeSetPinner, Staleness,
    StalenessBound,
};

/// A serve-set whose pins (or posture declaration) are in place — the
/// host's live pin state.
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
/// obligation rather than a second copy of it.
///
/// # A point-in-time fact, not a standing property
///
/// This witnesses that **these** shards were retained against the record
/// read at [`ServeSet::as_of_height`] — not that the host's retention still
/// matches the connected record. They diverge whenever holdings change: an
/// ordinary `HoldingsUpdate` (which an archiver posts continuously to keep
/// covering newly frozen segments) or a reorg that alters `held_shard_ids`
/// without moving the curve tree. The store clears pins on **tree**
/// rollback only, and there is no unpin path at all, so nothing
/// self-corrects.
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
    /// gone, [`PinError::PinnerCoverageMismatch`] if a list report's
    /// outcomes do not describe the set it claims,
    /// [`PinError::PostureNotDeclared`] if a prefix report's store has not
    /// declared the prune-disabled posture,
    /// [`PinError::FrozenCountExceedsCursor`] if a prefix report overstates
    /// the store's freeze cursor, and [`PinError::Pinner`] if the pin could
    /// not be applied or the store's ingest tip could not be read.
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
    /// tip could not be read, [`PinError::PinnerCoverageMismatch`] if a
    /// list report's outcomes do not describe the set it claims,
    /// [`PinError::PostureNotDeclared`] if a prefix report's store has not
    /// declared the prune-disabled posture,
    /// [`PinError::FrozenCountExceedsCursor`] if a prefix report overstates
    /// the store's freeze cursor, and [`PinError::PinnerStoreMismatch`] if
    /// the pins landed in a different open store. Never
    /// [`PinError::MembersAlreadyPruned`] — that refusal is `acquire`-only,
    /// per the paragraph above.
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
    /// is actually in the store, and `frozen_count` does not exceed the
    /// store's cursor — never whether the resulting witness is fit to start
    /// serving. Fitness is a policy question, it differs between the two
    /// callers, and it therefore lives in the caller — `acquire` refuses a
    /// pruned member, `refreshed` records it. Splitting on that line is
    /// what keeps this function free of a mode flag. (The posture and
    /// cursor checks do NOT differ per caller, which is why they belong
    /// here: the flag is one-way, so a missing declaration is an
    /// implementor defect in both directions, and refusing a refresh over
    /// it cannot wedge the loop the way a terminal `AlreadyPruned` refusal
    /// would.)
    fn from_report(report: PinReport, reader: ServingReader) -> Result<Self, PinError> {
        let PinReport {
            set: reported,
            as_of_height,
            // Not the store-identity check. `acquire` cloned this handle
            // into `reader`; `refreshed` already refused a different
            // store (`PinnerStoreMismatch`) and passes the witness's own
            // reader so the served store cannot change. Re-checking
            // identity here would need a previous-store argument — a
            // mode flag by another name, which this function exists to
            // avoid.
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
                // The store is also the authority for `frozen_count`. A
                // report that overstates the cursor claims shards the
                // store has not frozen — the dangerous direction of the
                // list arm's coverage check. A report that understates it
                // is a stale-low snapshot and is accepted: refresh grows
                // the obligation (D-5), and equality can race if a segment
                // freezes between the pinner's read and this check.
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
                let cursor = reader.next_freeze_seg().map_err(|e| PinError::Pinner {
                    detail: format!("freeze-cursor read failed: {e:?}"),
                })?;
                if frozen_count > cursor {
                    return Err(PinError::FrozenCountExceedsCursor {
                        reported: frozen_count,
                        cursor,
                    });
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

    /// The members this witness asserts are pinned: the reported list minus
    /// the terminally pruned ones.
    ///
    /// Empty for the prefix arm: there are no per-member pin rows. Retention
    /// is the posture flag, checked by [`Self::staleness`] as
    /// [`Staleness::PostureLost`].
    ///
    /// `already_pruned` members are excluded because they never had a pin
    /// row — `pin_ids_within` writes one for every outcome *except*
    /// `AlreadyPruned` — so counting them as claimed would report a
    /// permanent drop on a witness that is behaving exactly as documented.
    fn claimed_members(&self) -> Vec<u64> {
        match self.set.obligation() {
            ServeObligation::ShardList(shard_ids) => shard_ids
                .iter()
                .copied()
                .filter(|id| !self.already_pruned.contains(id))
                .collect(),
            ServeObligation::CompleteTreePrefix { .. } => Vec::new(),
        }
    }

    /// Which claimed members the store no longer holds pins for.
    ///
    /// The diagnostic behind [`Staleness::PinsDropped`], which carries only a
    /// ratio so it can stay `Copy`. Call this when an operator needs the ids —
    /// a log line, a CLI report — rather than on every poll.
    ///
    /// Always empty for a CompleteTree-prefix witness: no per-member pin
    /// rows exist to drop. A missing posture declaration is
    /// [`Staleness::PostureLost`], not a pin-id list.
    ///
    /// # Errors
    ///
    /// Store failure reading the pinned-segment table.
    pub fn dropped_pins(&self) -> Result<Vec<u64>, StoreError> {
        self.reader.members_missing_pins(&self.claimed_members())
    }

    /// How much this wallet has ingested since this serve-set was derived,
    /// and whether the retention this witness rests on is still in the
    /// store.
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
    /// Retention is checked **before** any tip arithmetic, and it matches
    /// [`ServeSet::obligation`] so the two arms cannot be reconstructed
    /// from an `Option` pair: the list arm asks the pin table
    /// ([`Staleness::PinsDropped`]); the prefix arm re-reads the
    /// prune-disabled flag ([`Staleness::PostureLost`]).
    ///
    /// This reading cannot see a refresh that is *failing* rather than
    /// stopped; that is host state, and
    /// [`crate::PersonaServingHost::staleness`] folds it in.
    ///
    /// # Errors
    ///
    /// Store failure reading the pin table, the posture flag, or the sync
    /// tip.
    pub fn staleness(&self, bound: StalenessBound) -> Result<Staleness, StoreError> {
        // Checked before any tip arithmetic, because it is the only reading
        // here that reports an exposure rather than a risk of one — and
        // because the tip cannot answer it. A member whose pin row is gone
        // (or a prefix whose posture flag is gone) is prunable now, whatever
        // the tip says, and re-ingest moves the tip back above the stamp
        // without restoring a single pin. Ordering this second would let
        // the arithmetic below return `Current` over it.
        match self.set.obligation() {
            ServeObligation::ShardList(_) => {
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
            ServeObligation::CompleteTreePrefix { frozen_count } => {
                // The prefix arm's pin is the posture flag, so that is
                // what gets re-read from the store on every poll —
                // measured, not inferred, window-free. Every store surface
                // makes the flag one-way, so a `false` here is corruption
                // or tampering. It is not `PinsDropped`: there are no pin
                // rows, the recovery story is different, and the operator
                // text must not send anyone to debug a pin table.
                if !self.reader.prune_disabled()? {
                    return Ok(Staleness::PostureLost { frozen_count });
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
