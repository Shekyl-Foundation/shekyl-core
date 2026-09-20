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
//! [`fetch_emission_claim_source`] — the **connected** record as the daemon
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
use shekyl_rpc_client::RpcError;
use shekyl_types::ChainCount;

use super::departure_ledger::{DepartureLedger, EPOCHS_BEFORE_PIN_RELEASE};
use crate::engine::daemon::synced_chain_facts::{CoherentChainView, TimelineBreak};
use crate::engine::emission_source::{fetch_vouched_claim_source, Vouching};
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
    /// The gate's reasoning, its constant and the two evidence hazards it
    /// guards live in [`departure_ledger`](super::departure_ledger) — this is
    /// the seam that binds the ledger to *this* refresh's two reads. The
    /// binding is the whole content: the observation height is
    /// [`CoherentChainView::reconcile`]'s verdict on the sync witness and the
    /// record's own height, never a number chosen here, so neither a stale
    /// witness nor a rolled-back record can set the clock.
    fn releasable(&self, owed: &[u64], pinned: &[u64], view: CoherentChainView) -> Vec<u64> {
        let owed: std::collections::BTreeSet<u64> = owed.iter().copied().collect();
        self.absent_since
            .lock()
            .expect("departure ledger")
            .observe(view, &owed, pinned)
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
    /// what the epoch gate has cleared, report both.
    ///
    /// `synced` is `None` while the daemon reports syncing. The pin half runs
    /// regardless — the host's witness must keep describing reality, and
    /// pinning is additive and idempotent (the store's `pin_serve_set` has
    /// **no** implicit release: *"Pins are cleared by
    /// `truncate_from_tree_position` … and by nothing else"*), so an empty
    /// owed list from a resyncing daemon unpins nothing by itself. Only the
    /// **release** half is withheld, and it is withheld structurally: the
    /// gate takes `&SyncedChainFacts`, so there is no unsynced call to make.
    async fn report_list(
        &self,
        shard_ids: &[u64],
        view: Option<CoherentChainView>,
    ) -> Result<(shekyl_p_host::ReportedSet, ServingReader), String> {
        let shard_ids = shard_ids.to_vec();
        // The release set is computed from the *previous* reconcile's view
        // of the store, which is what `pinned_now` came back for. One
        // round trip per refresh, and the release lags one refresh —
        // against a gate measured in settlement epochs that is not a lag
        // that means anything.
        let releasable = match view {
            Some(view) => {
                let pinned = self.last_pinned.lock().expect("pin view").clone();
                self.releasable(&shard_ids, &pinned, view)
            }
            // `WSS-25`, §6.7.3: *records no absence observations and releases
            // nothing while the daemon is unsynced*. Both halves come from
            // this one arm, because `releasable` is the departure ledger's
            // only writer — not calling it writes nothing, so a resync leaves
            // no trace to act on once the daemon catches up.
            // The break was already applied at acquisition, on every
            // path rather than only this one. Nothing to release without a
            // view, and nothing left to forget.
            None => Vec::new(),
        };

        let reply = self
            .curve_tree
            .pin_serve_set(shard_ids.clone(), releasable.clone())
            .await
            .map_err(|e| format!("serve-set pin failed: {e:?}"))?;
        *self.last_pinned.lock().expect("pin view") = reply.pinned_now.clone();
        if reply.released > 0 {
            tracing::info!(
                released = reply.released,
                shard_ids = ?releasable,
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
        // **Sync reading first, record second** (`WSS-Q14`). Two orderings
        // were available and only this one is sound: a daemon that reports
        // synchronized and *then* answers the record cannot have answered it
        // from deep resync, whereas reading the record first leaves a window
        // in which a pre-bond record is paired with a by-then-caught-up
        // `get_info`. It also makes the witness's height the earlier of the
        // two, which is the conservative direction for the release gate's
        // clock (see [`Self::releasable`]).
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
        let view = match vouched.vouching() {
            Vouching::Vouched(view) if view.rolled_back() => {
                // Not fatal here, unlike the acting lanes: this refresh
                // still describes what it holds. But the ledger's evidence
                // is not comparable across a rollback, so it forgets.
                tracing::warn!(
                    "serve-set refresh: the bond record came back below the sync witness read \
                     before it — the chain rolled back between the two reads. Departure \
                     observations are discarded and re-taken; no pin is released this refresh"
                );
                self.break_ledger(TimelineBreak::ChainRolledBack);
                None
            }
            Vouching::Vouched(view) => Some(view),
            Vouching::Broken(why) => {
                match why {
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
                    TimelineBreak::DaemonUnreachable | TimelineBreak::ChainRolledBack => {
                        tracing::warn!(
                            why = ?why,
                            "serve-set refresh: could not vouch for the daemon's chain facts, \
                             so no serve-set pin will be released this refresh. Holdings are \
                             retained"
                        )
                    }
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
        let (set, reader) = match source.bond.as_ref() {
            Some(bond) => match bond.holdings.kind {
                HoldingsKind::CompleteTree => self.report_prefix().await?,
                HoldingsKind::ShardSetCompact => {
                    self.report_list(bond.holdings.shard_ids.as_slice(), view)
                        .await?
                }
            },
            None => self.report_list(&[], view).await?,
        };

        Ok(PinReport {
            set,
            as_of_height,
            reader,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::emission_claim::test_fixtures::source_json;
    use crate::engine::emission_source::{BondContext, EmissionClaimSource};
    use shekyl_archival_retention::{
        settlement_epoch_at_height, HoldingsDescriptor, HoldingsKind, ShardSet,
    };
    use shekyl_curve_tree::{CurveTreeClient, PostureDeclaration, SegmentPin};
    use shekyl_rpc_client::{Rpc, RpcError};
    use shekyl_types::ChainCount;
    use std::sync::Arc;

    /// A daemon serving one canned claim-source reply through the real
    /// `json_rpc_call` envelope (only the transport is canned, so the decode
    /// this pinner depends on runs unmocked).
    #[derive(Clone)]
    struct ClaimSourceDaemon(Arc<serde_json::Value>);

    impl Rpc for ClaimSourceDaemon {
        /// Answers `get_info` as a **synchronized** daemon at the same chain
        /// count its claim source reports, so these fixtures keep exactly the
        /// semantics they had before `SyncedChainFacts` (`WSS-Q14`) — the
        /// unsynchronized timeline is `ResyncingDaemon`'s to exercise, and a
        /// fixture that answered it here would silently disable the release
        /// half of every test below.
        fn post(
            &self,
            route: &str,
            body: Vec<u8>,
        ) -> impl Send + std::future::Future<Output = Result<Vec<u8>, RpcError>> {
            let is_get_info = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("method").and_then(|m| m.as_str()).map(str::to_owned))
                .is_some_and(|m| m == "get_info");
            let result = if is_get_info {
                serde_json::json!({
                    "height": self.0.get("chain_height").and_then(serde_json::Value::as_u64)
                        .expect("the fixture source carries a chain height"),
                    "target_height": 0,
                    "synchronized": true,
                    "outgoing_connections_count": 8,
                    "incoming_connections_count": 0,
                })
            } else {
                (*self.0).clone()
            };
            let reply = serde_json::to_vec(&serde_json::json!({ "result": result }))
                .expect("fixture result encodes");
            let ok = route == "json_rpc";
            async move {
                if ok {
                    Ok(reply)
                } else {
                    Err(RpcError::InternalError("unexpected route".into()))
                }
            }
        }
    }

    // The §7.4 marker, asserted for the fixture exactly as
    // `claim_orchestrator`'s test daemon asserts it. The bound is what the
    // production wiring must satisfy, so the test transport has to satisfy it
    // too — a fixture exempt from the pin would test a signature nothing else
    // can call.
    impl PersonaIsolatedTransport for ClaimSourceDaemon {}

    /// A claim-source reply at `chain_height`, holding `shard_ids` (or no
    /// bond record at all when `shard_ids` is `None`).
    fn daemon(chain_height: u64, shard_ids: Option<Vec<u64>>) -> ClaimSourceDaemon {
        daemon_of_kind(chain_height, shard_ids, HoldingsKind::ShardSetCompact)
    }

    /// The same reply with the holdings **kind** chosen, so the two empties —
    /// an empty `ShardSetCompact` and a `CompleteTree` — are both reachable.
    fn daemon_of_kind(
        chain_height: u64,
        shard_ids: Option<Vec<u64>>,
        kind: HoldingsKind,
    ) -> ClaimSourceDaemon {
        ClaimSourceDaemon(Arc::new(source_json(&EmissionClaimSource {
            chain_height: ChainCount::from_raw(chain_height),
            // The decoder cross-checks this against `chain_height` — the
            // daemon derives both from one `db.height()` read — so the
            // fixture derives it the same way rather than pinning a literal
            // that would rot the moment the epoch length moves.
            current_settled_epoch: settlement_epoch_at_height(chain_height),
            bond: shard_ids.map(|ids| BondContext {
                join_settlement_epoch: 0,
                holdings: HoldingsDescriptor {
                    kind,
                    shard_ids: ShardSet::new(ids).expect("fixture shard set"),
                },
                claimed_settlement_epochs: Vec::new(),
                bonded_total_atomic: 0,
                bad_interval_count: 0,
                last_served: crate::engine::emission_source::ServeAnchor::NeverServed,
                last_settled_slash: crate::engine::emission_source::SlashWatermark::NothingSettled,
            }),
            epochs: Vec::new(),
        })))
    }

    fn handle() -> (tempfile::TempDir, CurveTreeHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let client = CurveTreeClient::open(dir.path().join("curve_tree.redb"))
            .expect("open fresh curve-tree client");
        (dir, CurveTreeHandle::spawn(client))
    }

    /// A handle over a store whose segment 0 is already frozen.
    ///
    /// The segment is written **before** the client opens, because the
    /// actor holds the store exclusively once spawned — the same reason
    /// this fixture cannot freeze anything mid-test.
    fn handle_with_frozen_segment() -> (tempfile::TempDir, CurveTreeHandle) {
        use shekyl_curve_tree::{
            leaves_per_segment, Gindex, LeafEntry, LeafStore, OutputIdentity, TargetKind,
        };

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("curve_tree.redb");
        {
            let store = LeafStore::open(&path).expect("open fresh store");
            let entries: Vec<LeafEntry> = (0..leaves_per_segment() as u64)
                .map(|gindex| {
                    let mut leaf = [1u8; 128];
                    leaf[..8].copy_from_slice(&(gindex + 1).to_le_bytes());
                    LeafEntry {
                        gindex: Gindex::from_raw(gindex),
                        maturity: BlockHeight::from_raw(60),
                        creation_height: BlockHeight::from_raw(0),
                        leaf,
                        identity: OutputIdentity {
                            output_key: shekyl_curve_tree::OneTimePubkey::from_bytes([1u8; 32]),
                            commitment: Some(shekyl_curve_tree::CommitmentBytes::from_bytes(
                                [2u8; 32],
                            )),
                            cm: [3u8; 32],
                            target: TargetKind::TaggedKey,
                        },
                    }
                })
                .collect();
            // Buried far past the freeze gate, so segment 0 froze on append.
            store
                .append_block_deltas(&entries, &[], &[], BlockHeight::from_raw(30_000))
                .expect("append a full frozen segment");
        }
        let client = CurveTreeClient::open(path).expect("resume over the frozen store");
        (dir, CurveTreeHandle::spawn(client))
    }

    /// **The production pinner's own KAT.** Every `shekyl-p-host` test drives
    /// a test-side pinner, so the mapping this function performs — record →
    /// `shard_ids`, `chain_height` → `as_of_height`, actor round trip →
    /// outcomes + reader — is the one part of the seam no host-side test can
    /// reach. Without this it could be wrong in any of those four places
    /// while the whole suite stayed green.
    // The gate's pure semantics — the two-epoch window, the returning-shard
    // reset, the owed-shard refusal and the backwards-chain case — moved to
    // `departure_ledger_tests.rs` with the type that now owns them. They are
    // not duplicated here: a second copy of one gate's rules is how the two
    // come to disagree. What stays below is the *seam* this file owns —
    // record decode, the two empties, and the resync property test.

    #[tokio::test]
    async fn the_report_is_derived_from_the_connected_record() {
        let (_dir, curve_tree) = handle();
        let pinner =
            EngineServeSetPinner::new(curve_tree, daemon(30_001, Some(vec![4, 9])), [7; 32]);

        let report = pinner.pin_serve_set().await.expect("pin");

        let shekyl_p_host::ReportedSet::ShardList {
            shard_ids,
            outcomes,
        } = report.set
        else {
            panic!("explicit holdings report the list arm");
        };
        assert_eq!(
            shard_ids,
            vec![4, 9],
            "the set is the connected record's holdings, not anything held locally"
        );
        assert_eq!(
            report.as_of_height,
            BlockHeight::from_raw(30_000),
            "chain_height is a COUNT; the stamp is the tip it describes, one lower"
        );
        assert_eq!(
            outcomes
                .iter()
                .map(|(shard_id, _)| *shard_id)
                .collect::<Vec<_>>(),
            vec![4, 9],
            "outcomes come back covering the reported set, in the record's order"
        );
        assert!(
            outcomes
                .iter()
                .all(|(_, pin)| *pin == SegmentPin::PinnedNotYetFrozen),
            "an empty store has frozen nothing, so bonding is ahead of the freeze"
        );
    }

    /// No bond record is a persona that owes nothing — not a failure, and not
    /// a serve-set the host has to guess at. It must still report a height,
    /// so a wallet that has not bonded yet keeps a witness that describes
    /// reality instead of failing every refresh forever.
    #[tokio::test]
    async fn an_released_persona_reports_the_empty_set_rather_than_failing() {
        let (_dir, curve_tree) = handle();
        let pinner = EngineServeSetPinner::new(curve_tree, daemon(30_001, None), [7; 32]);

        let report = pinner
            .pin_serve_set()
            .await
            .expect("no bond is not an error");

        let shekyl_p_host::ReportedSet::ShardList {
            shard_ids,
            outcomes,
        } = report.set
        else {
            panic!("a released persona reports the (empty) list arm");
        };
        assert!(shard_ids.is_empty());
        assert!(outcomes.is_empty());
        assert_eq!(report.as_of_height, BlockHeight::from_raw(30_000));
    }

    /// **The two empties, asserted together, because the pair is the
    /// contract.** `CompleteTree` carries no shard list by wire rule
    /// (`BondPostError::CompleteTreeWithShardIds`), so it decodes to the same
    /// bytes as a persona owing nothing while meaning the exact opposite — the
    /// whole corpus. Pinning that empty set would report a `Current` witness
    /// for a persona serving none of its obligation.
    ///
    /// Both arms live in one test on purpose: a `CompleteTree`-only assertion
    /// would also pass against an implementation that keyed on
    /// `shard_ids.is_empty()`, which is the *wrong* discriminant — it would
    /// route the legitimately-empty `ShardSetCompact` case into the whole-
    /// corpus arm in the same stroke. The discriminant is the thing under
    /// test, not the emptiness.
    ///
    /// **This is the slice-3 flip of the SH-2 refusal.** The same two
    /// inputs that used to prove "CompleteTree refuses, empty compact
    /// reports empty" now prove "CompleteTree reports the *prefix*, empty
    /// compact still reports the empty *list*" — the obligation is
    /// expressed, not refused, and the pair still cannot be conflated.
    #[tokio::test]
    async fn complete_tree_reports_the_prefix_while_an_empty_shard_set_reports_the_empty_list() {
        let (_dir_a, curve_tree_a) = handle();
        let complete_tree = EngineServeSetPinner::new(
            curve_tree_a,
            daemon_of_kind(30_001, Some(Vec::new()), HoldingsKind::CompleteTree),
            [7; 32],
        );
        let report = complete_tree
            .pin_serve_set()
            .await
            .expect("a whole-corpus obligation is expressed, not refused");
        let shekyl_p_host::ReportedSet::CompleteTreePrefix {
            frozen_count,
            declaration,
        } = report.set
        else {
            panic!("CompleteTree holdings must report the prefix arm");
        };
        assert_eq!(
            frozen_count, 0,
            "an un-ingested store has frozen nothing: the obligation is \
             honestly empty and grows as segments freeze (D-5)"
        );
        assert_eq!(
            declaration,
            PostureDeclaration::NewlyDeclared,
            "the first report declares the prune-disabled posture — the \
             prefix arm's pin — and says it did"
        );
        assert_eq!(report.as_of_height, BlockHeight::from_raw(30_000));

        // Same empty list on the wire, opposite meaning, and it must still
        // report the LIST arm.
        let (_dir_b, curve_tree_b) = handle();
        let owes_nothing = EngineServeSetPinner::new(
            curve_tree_b,
            daemon_of_kind(30_001, Some(Vec::new()), HoldingsKind::ShardSetCompact),
            [7; 32],
        );
        let report = owes_nothing
            .pin_serve_set()
            .await
            .expect("an empty ShardSetCompact owes nothing and is not an error");
        let shekyl_p_host::ReportedSet::ShardList {
            shard_ids,
            outcomes,
        } = report.set
        else {
            panic!("an empty ShardSetCompact reports the (empty) list arm");
        };
        assert!(shard_ids.is_empty());
        assert!(outcomes.is_empty());
    }

    /// **The reported count is the store's own cursor, and re-reporting is
    /// quiet.** This is the mapping only an engine-side test can reach:
    /// over a store that has actually frozen a segment the report carries
    /// `1`, not the `0` a fresh store gives — so a pinner that hardcoded
    /// the empty prefix, or read the wrong counter, fails here. The second
    /// report's `AlreadyDeclared` is the steady-state answer that tells the
    /// witness no retention gap opened between refreshes (RR-2).
    ///
    /// Growth *across a refresh* (a segment freezing between two reports)
    /// is `shekyl-p-host`'s KAT, driven against its own store; this test
    /// does not duplicate it, because the actor holds this store
    /// exclusively and freezing mid-test would mean driving full block
    /// ingest to prove a mapping that layer already proves.
    #[tokio::test]
    async fn the_prefix_reports_the_store_cursor_and_redeclares_quietly() {
        let (_dir, curve_tree) = handle_with_frozen_segment();
        let pinner = EngineServeSetPinner::new(
            curve_tree,
            daemon_of_kind(30_001, Some(Vec::new()), HoldingsKind::CompleteTree),
            [7; 32],
        );

        let first = pinner.pin_serve_set().await.expect("first report");
        let shekyl_p_host::ReportedSet::CompleteTreePrefix {
            frozen_count,
            declaration,
        } = first.set
        else {
            panic!("prefix arm");
        };
        assert_eq!(
            frozen_count, 1,
            "the obligation is the store's frozen prefix — one segment is \
             frozen, so the persona owes exactly [0, 1)"
        );
        assert_eq!(declaration, PostureDeclaration::NewlyDeclared);

        let second = pinner.pin_serve_set().await.expect("second report");
        let shekyl_p_host::ReportedSet::CompleteTreePrefix {
            frozen_count,
            declaration,
        } = second.set
        else {
            panic!("prefix arm");
        };
        assert_eq!(frozen_count, 1, "nothing froze in between");
        assert_eq!(
            declaration,
            PostureDeclaration::AlreadyDeclared,
            "the posture was already declared, so no retention gap opened \
             between the two reports"
        );
    }

    /// An empty chain has no tip. `ChainCount(0).tip()` is `None`, and the
    /// stamp must land on 0 rather than underflow or refuse — 0 is also what
    /// an un-ingested store reports, so the host's lag reads zero and the
    /// tripwire correctly stays quiet on a wallet at genesis.
    #[tokio::test]
    async fn an_empty_chain_stamps_height_zero() {
        let (_dir, curve_tree) = handle();
        let pinner = EngineServeSetPinner::new(curve_tree, daemon(0, None), [7; 32]);

        let report = pinner.pin_serve_set().await.expect("pin");
        assert_eq!(report.as_of_height, BlockHeight::from_raw(0));
    }

    /// The reader that comes back must be a handle on the store the pins
    /// landed in — the trait contract `PinnedServeSet::refreshed` enforces
    /// with `same_store`. One actor `ask` returns both, so they cannot
    /// diverge; this pins that they do not.
    #[tokio::test]
    async fn the_reader_is_the_store_the_pins_landed_in() {
        let (_dir, curve_tree) = handle();
        let pinner = EngineServeSetPinner::new(curve_tree, daemon(30_001, Some(vec![1])), [7; 32]);

        let first = pinner.pin_serve_set().await.expect("pin");
        let second = pinner.pin_serve_set().await.expect("pin again");

        assert!(
            first.reader.same_store(&second.reader),
            "two pins through one handle are two pins in one store"
        );
    }

    // ── WSS-25: the resync that would erase every holding ───────────────
    //
    // `WALLET_SIDE_STORE.md` §6.7.3: *the release gate records no absence
    // observations and releases nothing while the daemon is unsynced*, and it
    // *"owes a property test: no shard is erased while the pair can still be
    // drawn, including across a simulated resync. A test that only exercises a
    // synced timeline cannot fail on WSS-25's scenario, which is the one that
    // matters."*

    /// Every shard id the store is actually retaining, read through the actor
    /// that owns it. A no-op reconcile (pin nothing, release nothing) is the
    /// only read path there is, and its `pinned_now` is the same value the
    /// production refresh reads back.
    async fn pins_in_store(curve_tree: &CurveTreeHandle) -> Vec<u64> {
        curve_tree
            .pin_serve_set(Vec::new(), Vec::new())
            .await
            .expect("read the pin set")
            .pinned_now
    }

    /// A daemon rebuilding its chain — the state the C++→Rust cutover forces
    /// on every daemon.
    ///
    /// One height schedule drives **both** answers, which is the point: the
    /// resync hazard is that the record answers at a pre-bond height *while*
    /// the daemon's own height climbs past epoch boundaries, so a fixture that
    /// let the two drift apart would be testing something else. `get_info`
    /// advances the cursor and the claim source reads it, matching production
    /// order (health first, then the record).
    ///
    /// `target_height` is the sync dial: a non-zero value above the answering
    /// height is a daemon that says it is still catching up; `0` is the info
    /// surface's "synchronized" convention.
    #[derive(Clone)]
    struct ResyncingDaemon {
        schedule: Arc<Vec<u64>>,
        cursor: Arc<std::sync::atomic::AtomicUsize>,
        /// The height the current step answers at, written by `get_info`.
        current: Arc<std::sync::Mutex<u64>>,
        /// `0` means synchronized; anything else is the climbing target.
        target_height: u64,
        /// What the bond record says this persona owes, at every step.
        owed: Vec<u64>,
    }

    impl ResyncingDaemon {
        fn new(schedule: Vec<u64>, target_height: u64, owed: Vec<u64>) -> Self {
            let first = schedule[0];
            Self {
                schedule: Arc::new(schedule),
                cursor: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                current: Arc::new(std::sync::Mutex::new(first)),
                target_height,
                owed,
            }
        }

        /// Take the next scheduled height, holding at the last one so a test
        /// may drive more refreshes than it scheduled.
        fn step(&self) -> u64 {
            let i = self
                .cursor
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                .min(self.schedule.len() - 1);
            let h = self.schedule[i];
            *self.current.lock().expect("resync cursor") = h;
            h
        }
    }

    impl Rpc for ResyncingDaemon {
        fn post(
            &self,
            route: &str,
            body: Vec<u8>,
        ) -> impl Send + std::future::Future<Output = Result<Vec<u8>, RpcError>> {
            let method = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("method").and_then(|m| m.as_str()).map(str::to_owned))
                .unwrap_or_default();
            let result = if method == "get_info" {
                // `get_info.height` is the block COUNT (`top_block + 1`), and
                // the schedule is written in tips — the same relation the
                // claim source below reports, because both come off one
                // `db.height()` read on the daemon.
                let tip = self.step();
                serde_json::json!({
                    "height": tip + 1,
                    "target_height": self.target_height,
                    // A resyncing daemon says so outright; the heights are
                    // the second half of the same statement.
                    "synchronized": self.target_height == 0,
                    "outgoing_connections_count": 8,
                    "incoming_connections_count": 0,
                })
            } else {
                // `chain_height` is a COUNT; the schedule is expressed in
                // tips, so the record answers one more than the tip — the
                // same relation `get_info` carries (`top_block + 1`).
                let tip = *self.current.lock().expect("resync cursor");
                source_json(&EmissionClaimSource {
                    chain_height: ChainCount::from_raw(tip + 1),
                    current_settled_epoch: settlement_epoch_at_height(tip + 1),
                    bond: Some(BondContext {
                        join_settlement_epoch: 0,
                        holdings: HoldingsDescriptor {
                            kind: HoldingsKind::ShardSetCompact,
                            shard_ids: ShardSet::new(self.owed.clone()).expect("fixture set"),
                        },
                        claimed_settlement_epochs: Vec::new(),
                        bonded_total_atomic: 0,
                        bad_interval_count: 0,
                        last_served: crate::engine::emission_source::ServeAnchor::NeverServed,
                        last_settled_slash:
                            crate::engine::emission_source::SlashWatermark::NothingSettled,
                    }),
                    epochs: Vec::new(),
                })
            };
            let reply = serde_json::to_vec(&serde_json::json!({ "result": result }))
                .expect("fixture result encodes");
            let ok = route == "json_rpc";
            async move {
                if ok {
                    Ok(reply)
                } else {
                    Err(RpcError::InternalError("unexpected route".into()))
                }
            }
        }
    }

    impl PersonaIsolatedTransport for ResyncingDaemon {}

    /// The heights a resync walks through: a pre-bond height, then a climb
    /// crossing **four** settlement-epoch opens — far past the two the gate
    /// releases at. `SETTLEMENT_EPOCH_BLOCKS = 10_000`.
    fn resync_climb() -> Vec<u64> {
        vec![1_000, 9_999, 10_000, 20_000, 30_000, 40_000]
    }

    /// **The `WSS-25` property.** A shard held but absent from the record
    /// answered by an **unsynchronized** daemon is neither observed absent nor
    /// released, however far the answering height climbs.
    ///
    /// This bites against the release gate acting on a resyncing view; it does
    /// **not** cover a daemon that lies "synchronized" (`SyncedChainFacts`
    /// carries the daemon's claim, not an independent measurement), nor the
    /// erasure semantics that replace unpinning after the `WSS-13` unwind.
    #[tokio::test]
    async fn a_resyncing_daemon_releases_nothing_and_observes_no_absence() {
        let (_dir, curve_tree) = handle();
        // Owes shard 1 only; shard 9 is held from an older record.
        let rpc = ResyncingDaemon::new(resync_climb(), 1_000_000, vec![1]);
        let pinner = EngineServeSetPinner::new(curve_tree, rpc, [7; 32]);

        // Seed the store's pin view with both shards, so 9 is retained-but-
        // not-owed for every step of the climb.
        pinner
            .curve_tree
            .pin_serve_set(vec![1, 9], Vec::new())
            .await
            .expect("seed pins");
        *pinner.last_pinned.lock().expect("pin view") = vec![1, 9];

        for _ in 0..resync_climb().len() {
            let report = pinner.pin_serve_set().await.expect("refresh");
            match report.set {
                shekyl_p_host::ReportedSet::ShardList { .. } => {}
                other => panic!("expected a shard list, got {other:?}"),
            }
        }

        assert!(
            pinner
                .absent_since
                .lock()
                .expect("departure ledger")
                .observed_absences()
                == 0,
            "an unsynchronized view must record NO absence observation: the \
             record answers at pre-bond heights, so 'absent' is a statement \
             about the resync, not about the persona's holdings",
        );
        assert_eq!(
            pins_in_store(&pinner.curve_tree).await,
            vec![1, 9],
            "nothing released across a climb of four epoch opens",
        );
    }

    /// The negative control, and the "two-epoch semantics unchanged" half:
    /// the identical climb against a **synchronized** daemon releases the
    /// departed shard at the second consecutive epoch open, exactly as before
    /// this type existed. Without this, the test above would pass on a gate
    /// that had simply stopped working.
    #[tokio::test]
    async fn the_same_climb_synchronized_still_releases_at_the_second_epoch_open() {
        let (_dir, curve_tree) = handle();
        let rpc = ResyncingDaemon::new(resync_climb(), 0, vec![1]);
        let pinner = EngineServeSetPinner::new(curve_tree, rpc, [7; 32]);

        pinner
            .curve_tree
            .pin_serve_set(vec![1, 9], Vec::new())
            .await
            .expect("seed pins");
        *pinner.last_pinned.lock().expect("pin view") = vec![1, 9];

        // 1_000 (first absent, epoch 0), 9_999 (epoch 0), 10_000 (epoch 1 —
        // one open, too tight), 20_000 (epoch 2 — released).
        for expected_pins in [vec![1, 9], vec![1, 9], vec![1, 9], vec![1]] {
            pinner.pin_serve_set().await.expect("refresh");
            assert_eq!(pins_in_store(&pinner.curve_tree).await, expected_pins);
        }
    }
}
