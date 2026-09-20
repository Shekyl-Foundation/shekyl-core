// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`EngineServeSetPinner`] — the production `ServeSetPinner`: read the
//! connected bond record, pin what it holds, report both (SH-2).
//!
//! This is the one implementor of `shekyl-p-host`'s seam, and the seam is
//! shaped so that it is the *only* place a serve-set can come from. The host
//! supplies none of the three values this returns — which shards the persona
//! owes, whether they are pinned, which store they are pinned in — because a
//! value the host cannot supply is a value the host cannot get wrong. The
//! corresponding residual lands here instead: everything the witness rests on
//! is derived in this one function, reviewable by reading it.
//!
//! # The two halves, and why each comes from where it does
//!
//! **The set** comes from `get_archival_emission_claim_source`, decoded by
//! [`fetch_emission_claim_source`](crate::engine::emission_source::fetch_emission_claim_source)
//! — the **connected** record as the daemon
//! read it back from its own database, never the wallet's memory of what it
//! posted. "What I posted" is not "what connected"
//! (`ARCHIVAL_CHALLENGE_MECHANISM.md` §9.6 item 4), and a locally-maintained
//! shard list that drifts from the record is the silent-slash path the whole
//! serving arc is built to close.
//!
//! **The pins and the reader** come from one [`CurveTreeHandle::pin_serve_set`]
//! round trip, because pinning is a store write and the curve-tree actor is
//! the store's single writer. One `ask` returns both, so a respawn between two
//! calls cannot hand back a reader for a different client than the one that
//! pinned.
//!
//! # Transport
//!
//! `R` is bound to [`PersonaIsolatedTransport`], not to bare `Rpc`: the §7.4
//! transport pin is the bound itself, not a note asking the wiring to be
//! careful. A persona's claim-source query must ride its own `PRpc` and never
//! the principal's daemon session, and SH-2b wires this pinner from the
//! lifecycle code that is *holding* the principal's handle — the one place the
//! wrong transport is closest to hand, and the reason prose was not enough.
//!
//! [`orchestrate_emission_claim`](crate::engine::claim_orchestrator::orchestrate_emission_claim)
//! carries the same bound for the same reason. It reads the epoch set where
//! this reads `bond.holdings`, so a transport audit has to see both — and both
//! now refuse the wrong transport at compile time rather than documenting it.
//!
//! This type still does not create transports; it takes one. The bound decides
//! *which kind*, the construction site decides *whose*.

use shekyl_archival_retention::HoldingsKind;
use shekyl_curve_tree::{BlockHeight, ServingReader};
use shekyl_p_host::{PinReport, ServeSetPinner};

use crate::engine::curve_tree_actor::CurveTreeHandle;

use super::departure_ledger::{Continuity, DepartureLedger, Obligation, EPOCHS_BEFORE_PIN_RELEASE};
use shekyl_types::BlockHash;

use crate::engine::daemon::synced_chain_facts::{AnchoredView, TimelineBreak};
use crate::engine::emission_source::fetch_vouched_claim_source;
use crate::engine::prpc::PersonaIsolatedTransport;

/// Derives a persona's serve-set from its connected bond record and pins it.
// Wired by `Engine::start_serving_if_staker` (SH-2b-2). Landed with the seam
// it implements rather than after it, so the one place a serve-set can come
// from exists before anything can be wired to a second one.
//
// SH-2b's open question — whether `start_serving_if_staker` should start a
// serving host **at all** for a `CompleteTree` persona — is answered: it
// does, and this seam is where the answer lives (`COMPLETETREE_ACTIVATION.md`
// D-1/D-5). A CompleteTree persona serves the frozen prefix under the store's
// prune-disabled posture; the construction site stays kind-blind, because the
// kind-aware decision is this pinner's. The `first_stake` hardcode that made
// the question urgent is gone with it (D-3): a posture is now named by the
// caller, so a wallet owes the corpus only if someone asked for that.
//
// Lives under `stake_engine/` rather than at `engine/` top level because both
// halves of its input are already this tree's: the bond record it reads is what
// `bond`/`claim` assemble, and the lifecycle call that starts the host is a
// `StakeEngine` identity + this pinner. A `serve_set_source` at the engine
// root would have been a module the composition root declares and nothing
// else near it uses.
pub(crate) struct EngineServeSetPinner<R: PersonaIsolatedTransport> {
    curve_tree: CurveTreeHandle,
    rpc: R,
    p_id: [u8; 32],
    /// The departure ledger: which pinned shards are absent from the record,
    /// since when, and whether the timeline those observations sit on is
    /// still intact. Owns the release decision; see
    /// [`DepartureLedger::observe`].
    absent_since: std::sync::Mutex<DepartureLedger>,
    /// The store's pin set as of the last reconcile — the other half of the
    /// release input, kept here so a refresh costs one actor round trip.
    last_pinned: std::sync::Mutex<Vec<u64>>,
}

impl<R: PersonaIsolatedTransport> EngineServeSetPinner<R> {
    /// Bind a pinner to one persona's canonical id and its own transport.
    pub(crate) fn new(curve_tree: CurveTreeHandle, rpc: R, p_id: [u8; 32]) -> Self {
        Self {
            curve_tree,
            rpc,
            p_id,
            absent_since: std::sync::Mutex::new(DepartureLedger::default()),
            last_pinned: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Fold this refresh's observation into the departure ledger and return
    /// the shards whose pins are now releasable.
    ///
    /// The gate's reasoning, its constant and the evidence hazards it guards
    /// live in [`departure_ledger`](super::departure_ledger) — this is the
    /// seam that binds the ledger to *this* refresh's reads. The binding is
    /// the whole content: the observation height is
    /// [`CoherentChainView::reconcile`]'s verdict on the bracketed sync
    /// witness and the record's own height, never a number chosen here, so
    /// neither a stale witness nor a rolled-back record can set the clock.
    ///
    /// The pin set it observes against is the *previous* reconcile's view of
    /// the store, which is what `pinned_now` came back for. One round trip
    /// per refresh, and the release lags one refresh — against a gate
    /// measured in settlement epochs that is not a lag that means anything.
    async fn observe(&self, obligation: Obligation<'_>, view: AnchoredView) -> Vec<u64> {
        let pinned = self.last_pinned.lock().expect("pin view").clone();
        // Re-read the block the ledger's observations rest on, at its own
        // height, from the chain as it is NOW. This is one `get_block_hash`
        // per refresh, and only when there is something to carry. The verdict
        // is the ledger's; this only fetches the fact.
        let resting_on = self
            .absent_since
            .lock()
            .expect("departure ledger")
            .resting_on();
        let continuity = match resting_on {
            None => Continuity::FirstObservation,
            Some(anchor) => match usize::try_from(anchor.height.to_raw()) {
                Ok(number) => match self.rpc.get_block_hash(number).await {
                    Ok(bytes) => Continuity::Verified {
                        canonical_now: BlockHash::from_bytes(bytes),
                    },
                    Err(_) => Continuity::Unverifiable,
                },
                Err(_) => Continuity::Unverifiable,
            },
        };
        self.absent_since
            .lock()
            .expect("departure ledger")
            .observe(view, continuity, obligation, &pinned)
    }

    /// Forget the departure ledger's observations.
    ///
    /// One helper so every break path reads identically and none can forget
    /// to forget — the defect that produced this method.
    fn break_ledger(&self, why: TimelineBreak) {
        self.absent_since
            .lock()
            .expect("departure ledger")
            .break_timeline(why);
    }

    /// CompleteTree prefix arm: declare the prune-disabled posture, then
    /// report the freeze cursor that declaration vouches for.
    ///
    /// Declare-before-report is the actor message's own order
    /// ([`CurveTreeHandle::pin_complete_tree_prefix`]), so this arm cannot
    /// pair a declaration with a cursor from another moment. Both race
    /// directions are already ruled and neither is silent: a segment that
    /// freezes after the read makes the count stale-LOW, which the witness
    /// accepts (the next refresh grows it — D-5); a rollback after the
    /// read makes it overstate, which the witness refuses loudly
    /// (`FrozenCountExceedsCursor`) so the caller re-acquires.
    async fn report_prefix(&self) -> Result<(shekyl_p_host::ReportedSet, ServingReader), String> {
        let reply = self
            .curve_tree
            .pin_complete_tree_prefix()
            .await
            // Names the whole operation, not its first step: this one
            // round trip declares the posture, reads the freeze cursor
            // and takes the reader, and it collapses a dead actor into
            // the same error. "posture declaration failed" would send
            // an operator to the prune-disabled flag for a fault that
            // never touched it (rule 82's misdiagnosis guard); the
            // cause rides along in `{e:?}`.
            .map_err(|e| format!("complete-tree prefix derivation failed: {e:?}"))?;
        Ok((
            shekyl_p_host::ReportedSet::CompleteTreePrefix {
                frozen_count: reply.frozen_count,
                declaration: reply.declaration,
            },
            reply.reader,
        ))
    }

    /// Explicit-holdings list arm: pin the record's shard list, release
    /// what the ledger has cleared, report both.
    ///
    /// `releasable` is the ledger's verdict, decided in [`Self::pin_serve_set`]
    /// before the holdings kind branched — this arm holds no release
    /// decision of its own. The pin half runs on every refresh — the host's
    /// witness must keep describing reality, and pinning is additive and
    /// idempotent (the store's `pin_serve_set` has **no** implicit release:
    /// *"Pins are cleared by `truncate_from_tree_position` … and by nothing
    /// else"*), so an empty owed list from a resyncing daemon unpins nothing
    /// by itself.
    async fn report_list(
        &self,
        shard_ids: &[u64],
        releasable: Vec<u64>,
    ) -> Result<(shekyl_p_host::ReportedSet, ServingReader), String> {
        let shard_ids = shard_ids.to_vec();

        let reply = self
            .curve_tree
            .pin_serve_set(shard_ids.clone(), releasable.clone())
            .await
            .map_err(|e| format!("serve-set pin failed: {e:?}"))?;
        *self.last_pinned.lock().expect("pin view") = reply.pinned_now.clone();
        if reply.released > 0 {
            // Counts, never ids (`WSS-20`). A released shard id matched
            // against the chain's public bond history identifies `P`, and
            // this sink is a plaintext file that outlives the process — the
            // same at-rest adversary the encrypted wallet was ruled against.
            // `releasable` is what the epoch gate cleared; `released` is what
            // the store actually unpinned, and the two differ when a pin was
            // already gone. Both counts are diagnostic; neither names a shard.
            tracing::info!(
                released = reply.released,
                releasable = releasable.len(),
                epochs_absent = EPOCHS_BEFORE_PIN_RELEASE,
                "released serve-set pins: these shards were absent from the bond record \
                 across two consecutive settlement-epoch opens, so the last epoch they \
                 could have been challenged in has closed. The prune may now reclaim \
                 their bytes"
            );
        }
        Ok((
            shekyl_p_host::ReportedSet::ShardList {
                shard_ids,
                outcomes: reply.outcomes,
            },
            reply.reader,
        ))
    }
}

impl<R: PersonaIsolatedTransport + Sync> ServeSetPinner for EngineServeSetPinner<R> {
    async fn pin_serve_set(&self) -> Result<PinReport, String> {
        // **Sync reading first, record second, then the witness block
        // re-read** (`WSS-Q14`). Of the two orderings of the first pair only
        // this one is sound: a daemon that reports synchronized and *then*
        // answers the record cannot have answered it from deep resync,
        // whereas reading the record first leaves a window in which a
        // pre-bond record is paired with a by-then-caught-up `get_info`. It
        // also makes the witness's height the earlier of the two, which is
        // the conservative direction for the release gate's clock (see
        // [`Self::observe`]). The third read is the bracket — the witness
        // block confirmed after the record — without which a reorg that
        // crossed the witness tip and caught back up would read as advance;
        // all three are `fetch_vouched_claim_source`'s, not this caller's.
        //
        // Neither a syncing daemon (`Ok(None)`) nor an unreachable one
        // (`Err`) yields facts to act on, so both withhold the release half —
        // but they are different faults and the log says which, because an
        // operator diagnosing pins that never release should not be sent to
        // the wrong one (rule 82). The refresh itself does **not** fail: the
        // pin half and the host's witness still need to run, for the same
        // reason a persona with no bond record reports an empty list rather
        // than failing forever.
        // One acquisition, ordered inside: witness, then record, then
        // reconciliation. A failed *record* read is still fatal to the
        // refresh — there is nothing to report a serve set from — but the
        // ledger must forget FIRST, because that failure is itself an
        // unobserved interval.
        let vouched = match fetch_vouched_claim_source(&self.rpc, &self.p_id).await {
            Ok(v) => v,
            Err(e) => {
                self.break_ledger(TimelineBreak::DaemonUnreachable);
                return Err(format!("claim-source fetch failed: {e}"));
            }
        };

        // **The break is applied here, once, before anything branches.**
        // It used to live in `report_list`, which meant it never ran on the
        // `CompleteTree` arm (that goes to `report_prefix`) nor when the
        // record read failed — so on exactly those paths a pre-gap absence
        // survived an interval nobody watched and could release the moment
        // sync resumed. A reset deferred to one branch is not a reset; it is
        // a reset the other branches silently opt out of.
        let view = match vouched.actionable() {
            Ok(anchored) => Some(anchored),
            Err(why) => {
                match why {
                    // Not fatal here, unlike the acting lanes: this refresh
                    // still describes what it holds. But the ledger's
                    // evidence is not comparable across a rollback, so it
                    // forgets — and an `AnchoredView` cannot be minted from
                    // a rolled-back view, so it could not be observed anyway.
                    TimelineBreak::ChainRolledBack => tracing::warn!(
                        "serve-set refresh: the bond record came back below the sync witness read \
                         before it — the chain rolled back between the two reads. Departure \
                         observations are discarded and re-taken; no pin is released this refresh"
                    ),
                    TimelineBreak::DaemonSyncing => tracing::info!(
                        "serve-set refresh: the daemon reports it is still synchronizing, so \
                         no serve-set pin will be released this refresh. Holdings are retained \
                         until it is caught up — an unsynchronized view cannot tell a shard \
                         this persona no longer owes from one the resync has not reached yet"
                    ),
                    TimelineBreak::FactsUnreadable => tracing::error!(
                        "serve-set refresh: the daemon answered, but its chain facts did not \
                         decode — a protocol or contract fault, NOT a connectivity problem. No \
                         pin is released and holdings are retained. Check that the daemon's \
                         version matches this wallet's expectations"
                    ),
                    TimelineBreak::WitnessBlockReplaced => tracing::warn!(
                        "serve-set refresh: the block the sync witness stood on was replaced \
                         while the bond record was being read — a reorg crossed it, so nothing \
                         vouches for this record. Departure observations are discarded and \
                         re-taken; no pin is released this refresh"
                    ),
                    TimelineBreak::DaemonUnreachable => tracing::warn!(
                        why = ?why,
                        "serve-set refresh: could not vouch for the daemon's chain facts, \
                         so no serve-set pin will be released this refresh. Holdings are \
                         retained"
                    ),
                }
                self.break_ledger(why);
                None
            }
        };
        let source = vouched.source();

        // One stamp, both arms. `chain_height` is a ChainCount (the
        // daemon's `db.height()`), one more than the height of the block
        // it counts; this field is a height, so the stamp is `tip()`. An
        // empty chain has no tip and reads 0.
        //
        // The obligation's shape changed; the question "at what height
        // was this true" did not. It is **not** an operand of the host's
        // staleness reading and must not become one: this is the daemon's
        // height over RPC while the store's ingest tip is local, and a
        // wallet catching up sits far below it. `PinnedServeSet` stamps
        // the local ingest tip instead and compares that one clock to
        // itself.
        let as_of_height = source
            .chain_height
            .tip()
            .map_or(BlockHeight::from_raw(0), |h| {
                BlockHeight::from_raw(h.to_raw())
            });

        // Two different empties reach this match, and conflating them is
        // the defect it exists to prevent. `shard_ids` is only in scope
        // on the compact arm — a third `HoldingsKind` fails to compile.
        //
        // **Owing nothing.** No connected record is not an error — a
        // persona with no bond owes nothing and pins nothing. Reported as
        // the empty list so the host's witness still describes reality
        // (and its staleness clock still advances) rather than the
        // refresh failing forever on a wallet that simply has not bonded
        // yet. A `ShardSetCompact` record with an empty list is the same
        // statement, made by a record that exists.
        //
        // **Owing everything, in the same bytes.** `CompleteTree` carries
        // no shard list *by wire rule* —
        // `BondPostError::CompleteTreeWithShardIds` rejects one, and the
        // daemon's own vin builder writes `ShardSet::empty()` for it — so
        // reading `shard_ids` blind here would pin nothing and report a
        // `Current` witness for a persona owing the whole corpus: §9.6
        // item 4's silent slash, produced by the refresh built to close
        // it. The prefix arm is what that obligation is *expressed* as;
        // the grow-forever / no-pin rationale lives on
        // `ReportedSet::CompleteTreePrefix`, which owns it.
        //
        // **Every vouched view is observed here, once, before the kind
        // branches** — the same shape as the break above, for the same
        // reason. The ledger's invariant is that every vouched observation
        // of the holdings passes through `observe`; a holdings kind that
        // skipped it broke that regardless of whether its own arm releases.
        // A `CompleteTree` record has no release path, but it has a ledger
        // effect: it says every shard is owed, which must forget the absence
        // clocks a compact record started — otherwise a shard absent at
        // epoch 0, owed under `CompleteTree` at epoch 1 and absent again at
        // epoch 2 resumed the epoch-0 clock and released at once, though it
        // was drawable at epoch 1. The kind chooses the *obligation*, not
        // whether the ledger hears about it.
        let owed_list: std::collections::BTreeSet<u64> = source
            .bond
            .as_ref()
            .map(|bond| bond.holdings.shard_ids.as_slice().iter().copied().collect())
            .unwrap_or_default();
        let obligation = match source.bond.as_ref().map(|bond| bond.holdings.kind) {
            Some(HoldingsKind::CompleteTree) => Obligation::Everything,
            Some(HoldingsKind::ShardSetCompact) | None => Obligation::Exactly(&owed_list),
        };
        let releasable = match view {
            Some(view) => self.observe(obligation, view).await,
            // `WSS-25`, §6.7.3: *records no absence observations and releases
            // nothing while the daemon is unsynced*. Both halves come from
            // this one arm, because `observe` is the departure ledger's only
            // writer — not calling it writes nothing, so a resync leaves no
            // trace to act on once the daemon catches up. The break was
            // already applied at acquisition, on every path.
            None => Vec::new(),
        };
        let (set, reader) = match source.bond.as_ref() {
            Some(bond) => match bond.holdings.kind {
                // Owing everything releases nothing, by construction of the
                // obligation; the prefix arm has no release to carry.
                HoldingsKind::CompleteTree => self.report_prefix().await?,
                HoldingsKind::ShardSetCompact => {
                    self.report_list(bond.holdings.shard_ids.as_slice(), releasable)
                        .await?
                }
            },
            None => self.report_list(&[], releasable).await?,
        };

        Ok(PinReport {
            set,
            as_of_height,
            reader,
        })
    }
}

#[cfg(test)]
#[path = "serve_set_source_tests.rs"]
mod tests;
