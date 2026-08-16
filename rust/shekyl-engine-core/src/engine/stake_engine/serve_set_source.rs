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

use shekyl_archival_retention::{HoldingsKind, SETTLEMENT_EPOCH_BLOCKS};
use shekyl_curve_tree::{BlockHeight, SegmentPin, ServingReader};
use shekyl_p_host::{PinReport, ServeSetPinner};

use crate::engine::curve_tree_actor::CurveTreeHandle;
use crate::engine::emission_source::fetch_emission_claim_source;
use crate::engine::prpc::PersonaIsolatedTransport;

/// Derives a persona's serve-set from its connected bond record and pins it.
// Wired by `Engine::start_serving_if_staker` (SH-2b-2). Landed with the seam
// it implements rather than after it, so the one place a serve-set can come
// from exists before anything can be wired to a second one.
//
// SH-2b inherits an open question this refusal makes visible: whether
// `start_serving_if_staker` should start a serving host **at all** for a
// `CompleteTree` persona. `first_stake` hardcodes that posture today — a named
// PR-4c deviation, since no wallet entry posts a market bond yet — so wiring
// the host unconditionally would make every first-stake wallet fail to start
// one. A host that reliably refuses to start is correct and is not a finished
// answer; the caller decides.
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
    /// Shards pinned in the store but absent from the connected record, and the
    /// record height at which each was *first* observed absent. The release
    /// gate reads from here; see [`Self::releasable`].
    ///
    /// **In memory, per session, deliberately.** A restart forgets the clock
    /// and restarts it, so a wallet that reopens repeatedly reclaims more
    /// slowly — but it never releases *early*, which is the only direction
    /// that costs anything irreversible. Persisting it would buy faster
    /// reclamation of disk (recoverable) at the price of a schema version and
    /// a migration (not free), for a decision §9.7 item 5 already rules should
    /// fail toward retention.
    absent_since: std::sync::Mutex<std::collections::BTreeMap<u64, u64>>,
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
            absent_since: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            last_pinned: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Fold this refresh's observation into the departure ledger and return the
    /// shards whose pins are now releasable.
    ///
    /// `owed` is what the connected record says this persona must serve;
    /// `pinned` is what the store is actually retaining. The difference is
    /// retained-but-not-owed — the leak `ARCHIVAL_CHALLENGE_MECHANISM.md` §9.7
    /// item 5 prices at ~13.6 GB against a rule-76 Pi-4 floor, since nothing
    /// else ever removes a pin.
    ///
    /// # The gate is epoch-shaped, not reorg-shaped, and that is the whole point
    ///
    /// The obvious gate is a reorg depth — wait until the departure has settled
    /// on the chain. **That is the wrong quantity, and using it here would turn
    /// a disk leak into a slash risk.** §4 quantizes drawability to epoch
    /// boundaries: *"a pair is drawable in E iff it held the shard at E's
    /// open"*, and evaluation at that fixed pre-challenge height is deliberate
    /// — it is the WS-1 constraint, *"no tip-holdings read that would let P
    /// drop the shard after the fire and escape"*. So a mid-epoch drop does
    /// **not** end the obligation for E; the pair stays drawable, and
    /// challengeable, through E's close.
    ///
    /// That matters here and not one layer up, because
    /// [`StoreShardProvider`](shekyl_p_serve::StoreShardProvider) is
    /// **serve-set-blind**: it holds only a `ServingReader` and answers for any
    /// shard whose bytes are in the store. A dropped-but-still-pinned shard is
    /// therefore still *served*, which is why today's leak happens to keep the
    /// obligation met. Release the pin early and the prune reclaims the bytes
    /// while the pair is still drawable — a miss, then a slash, for disk.
    /// §9.7's own asymmetry, pointed the other way: the reclaim is recoverable,
    /// the loss is not.
    ///
    /// # The condition
    ///
    /// Release once the shard has been absent across **two consecutive epoch
    /// opens**. Then it was not drawable in the current epoch or the one
    /// before, so the last epoch in which it could have been drawn closed a
    /// full epoch ago.
    ///
    /// Two epochs rather than one because one is too tight: absent at only the
    /// current epoch's open makes the previous epoch the last drawable one, and
    /// a challenge issued in its final block still has to resolve. The extra
    /// epoch is that resolution slack.
    ///
    /// **W₂ is deliberately not an input.** The resolution window has no landed
    /// constant — it is the rig's output (§9.7 item 6, still UNDERIVED) — so a
    /// gate that named it could not be written yet. This one does not need it:
    /// a full epoch of slack covers any W₂ shorter than
    /// `SETTLEMENT_EPOCH_BLOCKS`, which at ~14 days against a window measured
    /// in minutes-to-hours is not a close call. **Reopening criterion (rule
    /// 21):** if the rig ever derives a W₂ at or above one epoch, this gate is
    /// wrong and must take W₂ as an operand.
    ///
    /// The reorg question the naive gate was answering is subsumed rather than
    /// dropped: §2 notes drawability is evaluated at epoch open, *"deep history
    /// relative to any plausible reorg, so the drawable set is reorg-stable"*.
    /// Two epoch boundaries is far deeper than `ARCHIVAL_REORG_DEPTH_BLOCKS`.
    ///
    /// A shard that reappears in the record clears its entry, so a departure
    /// that reverses inside the window costs nothing and leaves no trace.
    fn releasable(&self, owed: &[u64], pinned: &[u64], as_of: u64) -> Vec<u64> {
        let owed: std::collections::BTreeSet<u64> = owed.iter().copied().collect();
        let mut ledger = self.absent_since.lock().expect("departure ledger");

        // A shard back in the record is not departed at all: drop its entry so
        // its clock restarts if it leaves again.
        ledger.retain(|shard_id, _| !owed.contains(shard_id));

        let now_epoch = as_of / SETTLEMENT_EPOCH_BLOCKS;
        let mut releasable = Vec::new();
        for &shard_id in pinned {
            if owed.contains(&shard_id) {
                continue;
            }
            let first_absent = *ledger.entry(shard_id).or_insert(as_of);
            let absent_epoch = first_absent / SETTLEMENT_EPOCH_BLOCKS;
            // Saturating: a record height below the first observation means the
            // chain moved backwards under us, which is not elapsed obligation.
            if now_epoch.saturating_sub(absent_epoch) >= EPOCHS_BEFORE_PIN_RELEASE {
                releasable.push(shard_id);
            }
        }
        // Released pins stop being pinned, so their ledger entries are spent.
        for shard_id in &releasable {
            ledger.remove(shard_id);
        }
        releasable
    }
}

/// Consecutive epoch opens a shard must be absent across before its pin may be
/// released. See [`EngineServeSetPinner::releasable`] for why two, and why the
/// resolution window `W₂` is not an operand.
const EPOCHS_BEFORE_PIN_RELEASE: u64 = 2;

impl<R: PersonaIsolatedTransport + Sync> ServeSetPinner for EngineServeSetPinner<R> {
    async fn pin_serve_set(&self) -> Result<PinReport, String> {
        let source = fetch_emission_claim_source(&self.rpc, &self.p_id)
            .await
            .map_err(|e| format!("claim-source fetch failed: {e}"))?;

        // Two different empties reach this line, and conflating them is the
        // defect this match exists to prevent. `shard_ids` must never be read
        // without its discriminant.
        //
        // **Owing nothing.** No connected record is not an error — a persona
        // with no bond owes nothing and pins nothing. Reported as the empty
        // set so the host's witness still describes reality (and its
        // staleness clock still advances) rather than the refresh failing
        // forever on a wallet that simply has not bonded yet. A
        // `ShardSetCompact` record with an empty list is the same statement,
        // made by a record that exists.
        //
        // **Owing everything, in the same bytes.** `CompleteTree` carries no
        // shard list *by wire rule* — `BondPostError::CompleteTreeWithShardIds`
        // rejects one, and the daemon's own vin builder writes
        // `ShardSet::empty()` for it — and it means the persona owes the whole
        // corpus, holdings that "grow forever by definition"
        // (`ARCHIVAL_CHALLENGE_MECHANISM.md`, Foundation CompleteTree nodes).
        // Reading `shard_ids` blind would pin nothing and report a `Current`
        // witness for a persona owing everything: §9.6 item 4's silent slash,
        // produced by the refresh built to close it. Foundation nodes sit
        // outside the reward market but are explicitly **not** exempt from the
        // slash side (examined and closed 2026-08-07), so the loss is live.
        //
        // **Refused rather than approximated.** `ServeSet` is a shard-id list
        // with no representation of "all", so this seam cannot express the
        // obligation at all. Whole-corpus pinning would need a store
        // enumeration that does not exist and an unbounded-growth policy that
        // is a different validation surface. Failing here fails
        // `PinnedServeSet::acquire`, so the host does not start — loud and
        // early, instead of a witness that is wrong in the dangerous
        // direction.
        let shard_ids: Vec<u64> = match source.bond.as_ref() {
            None => Vec::new(),
            Some(bond) => match bond.holdings.kind {
                HoldingsKind::ShardSetCompact => bond.holdings.shard_ids.as_slice().to_vec(),
                HoldingsKind::CompleteTree => {
                    return Err(
                        "connected bond has CompleteTree holdings: this persona owes the \
                                whole corpus, which a shard-id serve-set cannot express — \
                                refusing rather than serving the empty set it decodes to"
                            .to_string(),
                    )
                }
            },
        };

        let as_of = source
            .chain_height
            .tip()
            .map_or(0, shekyl_types::BlockHeight::to_raw);

        // The release set is computed from the *previous* reconcile's view of
        // the store, which is what `pinned_now` came back for. One round trip
        // per refresh, and the release lags one refresh — against a gate
        // measured in settlement epochs that is not a lag that means anything.
        let releasable = {
            let pinned = self.last_pinned.lock().expect("pin view").clone();
            self.releasable(&shard_ids, &pinned, as_of)
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
        let (outcomes, reader): (Vec<(u64, SegmentPin)>, ServingReader) =
            (reply.outcomes, reply.reader);

        Ok(PinReport {
            // Compile-fix only for the slice-2 PinReport reshape: this
            // pinner still derives explicit holdings, so it reports the
            // list arm; the CompleteTree prefix arm is slice 3's, where the
            // refusal above is replaced.
            set: shekyl_p_host::ReportedSet::ShardList {
                shard_ids,
                outcomes,
            },
            // The height the daemon read the record at — the set's
            // provenance, and deliberately the reply's own height rather than
            // anything measured locally: it says at what height this shard
            // list was true, which is a fact about the record and not about
            // this wallet.
            //
            // It is **not** an operand of the host's staleness reading, and
            // must not become one. This is the daemon's height over RPC while
            // the store's ingest tip is local, and a wallet catching up sits
            // far below it; differencing the two would measure the catch-up
            // and read healthy right through it. `PinnedServeSet` stamps the
            // local ingest tip instead and compares that one clock to itself.
            //
            // `tip()`, not the raw count: `chain_height` is a ChainCount (the
            // daemon's `db.height()`), one more than the height of the block
            // it counts, and this field is a height. An empty chain has no
            // tip and reads 0.
            as_of_height: source
                .chain_height
                .tip()
                .map_or(BlockHeight(0), |h| BlockHeight(h.to_raw())),
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
    use shekyl_curve_tree::CurveTreeClient;
    use shekyl_rpc_client::{Rpc, RpcError};
    use shekyl_types::ChainCount;
    use std::sync::Arc;

    /// A daemon serving one canned claim-source reply through the real
    /// `json_rpc_call` envelope (only the transport is canned, so the decode
    /// this pinner depends on runs unmocked).
    #[derive(Clone)]
    struct ClaimSourceDaemon(Arc<serde_json::Value>);

    impl Rpc for ClaimSourceDaemon {
        fn post(
            &self,
            route: &str,
            _body: Vec<u8>,
        ) -> impl Send + std::future::Future<Output = Result<Vec<u8>, RpcError>> {
            let reply = serde_json::to_vec(&serde_json::json!({ "result": *self.0 }))
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

    /// **The production pinner's own KAT.** Every `shekyl-p-host` test drives
    /// a test-side pinner, so the mapping this function performs — record →
    /// `shard_ids`, `chain_height` → `as_of_height`, actor round trip →
    /// outcomes + reader — is the one part of the seam no host-side test can
    /// reach. Without this it could be wrong in any of those four places
    /// while the whole suite stayed green.
    /// The gate, exercised as a pure function of its three inputs — no store,
    /// no actor, no daemon. This is where the slash-vs-disk asymmetry lives.
    ///
    /// The heights are chosen against `SETTLEMENT_EPOCH_BLOCKS = 10_000`:
    /// a drop at 1_000 is mid-epoch-0, and the pair stays drawable through
    /// epoch 0's close at 9_999.
    #[tokio::test]
    async fn a_departed_shard_is_not_releasable_while_it_is_still_drawable() {
        let (_dir, curve_tree) = handle();
        let pinner = EngineServeSetPinner::new(curve_tree, daemon(1, None), [7; 32]);

        // Dropped mid-epoch-0. Still drawable for the rest of epoch 0.
        assert!(pinner.releasable(&[1], &[1, 9], 1_000).is_empty());

        // A reorg depth later — what the first version of this gate released
        // on. Epoch 0 has ~8_280 blocks left, and the provider is
        // serve-set-blind, so reclaiming here means a real challenge finds no
        // bytes.
        assert!(
            pinner.releasable(&[1], &[1, 9], 1_720).is_empty(),
            "720 blocks is a reorg depth, not an obligation: releasing here \
             converts a disk leak into a miss",
        );

        // Epoch 1's open: not drawable in epoch 1, but epoch 0's challenges
        // may have fired as late as block 9_999 and still need to resolve.
        assert!(
            pinner.releasable(&[1], &[1, 9], 10_000).is_empty(),
            "one epoch is too tight — a challenge issued in epoch 0's last \
             block has had no time to resolve",
        );
        assert!(pinner.releasable(&[1], &[1, 9], 19_999).is_empty());

        // Epoch 2's open: absent across two consecutive epoch opens, and the
        // last epoch it could have been drawn in closed a full epoch ago.
        assert_eq!(pinner.releasable(&[1], &[1, 9], 20_000), vec![9]);
    }

    /// A departure that reverses inside the window costs nothing, and the clock
    /// restarts if it leaves again.
    #[tokio::test]
    async fn a_shard_that_returns_clears_its_departure_clock() {
        let (_dir, curve_tree) = handle();
        let pinner = EngineServeSetPinner::new(curve_tree, daemon(1, None), [7; 32]);

        assert!(pinner.releasable(&[1], &[1, 9], 1_000).is_empty());
        // Back in the record inside epoch 0 — it was held at no epoch open it
        // missed, so nothing has elapsed.
        assert!(pinner.releasable(&[1, 9], &[1, 9], 5_000).is_empty());
        // It leaves again in epoch 1. Had the first clock survived, epoch 2's
        // open would release it while it was drawable in epoch 1.
        assert!(pinner.releasable(&[1], &[1, 9], 15_000).is_empty());
        assert!(
            pinner.releasable(&[1], &[1, 9], 20_000).is_empty(),
            "the clock restarted at the second departure: absent at epoch 2's \
             open only, and it was drawable in epoch 1",
        );
        assert_eq!(pinner.releasable(&[1], &[1, 9], 30_000), vec![9]);
    }

    /// A shard still owed is never releasable, however long it has been pinned
    /// — the direction that would cause a slash rather than waste disk.
    #[tokio::test]
    async fn an_owed_shard_is_never_releasable() {
        let (_dir, curve_tree) = handle();
        let pinner = EngineServeSetPinner::new(curve_tree, daemon(1, None), [7; 32]);
        assert!(pinner
            .releasable(&[1, 9], &[1, 9], 10 * SETTLEMENT_EPOCH_BLOCKS)
            .is_empty());
    }

    /// A chain that moves backwards under the ledger is not elapsed finality.
    #[tokio::test]
    async fn a_record_height_going_backwards_does_not_elapse_the_gate() {
        let (_dir, curve_tree) = handle();
        let pinner = EngineServeSetPinner::new(curve_tree, daemon(1, None), [7; 32]);
        assert!(pinner.releasable(&[1], &[1, 9], 50_000).is_empty());
        assert!(
            pinner.releasable(&[1], &[1, 9], 100).is_empty(),
            "saturating subtraction: a lower height is not five epochs of elapsed \
             obligation",
        );
    }

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
            BlockHeight(30_000),
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
    async fn an_unbonded_persona_reports_the_empty_set_rather_than_failing() {
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
            panic!("an unbonded persona reports the (empty) list arm");
        };
        assert!(shard_ids.is_empty());
        assert!(outcomes.is_empty());
        assert_eq!(report.as_of_height, BlockHeight(30_000));
    }

    /// **The two empties, asserted together, because the pair is the
    /// contract.** `CompleteTree` carries no shard list by wire rule
    /// (`BondPostError::CompleteTreeWithShardIds`), so it decodes to the same
    /// bytes as a persona owing nothing while meaning the exact opposite — the
    /// whole corpus. Pinning that empty set would report a `Current` witness
    /// for a persona serving none of its obligation.
    ///
    /// Both arms live in one test on purpose: a `CompleteTree`-only assertion
    /// would also pass against an implementation that refused on
    /// `shard_ids.is_empty()`, which is the *wrong* fix — it would break the
    /// legitimately-empty `ShardSetCompact` case in the same stroke. The
    /// discriminant is the thing under test, not the emptiness.
    #[tokio::test]
    async fn complete_tree_holdings_refuse_while_an_empty_shard_set_reports_empty() {
        let (_dir_a, curve_tree_a) = handle();
        let complete_tree = EngineServeSetPinner::new(
            curve_tree_a,
            daemon_of_kind(30_001, Some(Vec::new()), HoldingsKind::CompleteTree),
            [7; 32],
        );
        let err = complete_tree
            .pin_serve_set()
            .await
            .expect_err("a whole-corpus obligation must refuse, not pin the empty set");
        assert!(
            err.contains("CompleteTree"),
            "the refusal must name the holdings kind so the operator can act on it: {err}"
        );

        // Same empty list, opposite meaning, and it must still succeed.
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

    /// An empty chain has no tip. `ChainCount(0).tip()` is `None`, and the
    /// stamp must land on 0 rather than underflow or refuse — 0 is also what
    /// an un-ingested store reports, so the host's lag reads zero and the
    /// tripwire correctly stays quiet on a wallet at genesis.
    #[tokio::test]
    async fn an_empty_chain_stamps_height_zero() {
        let (_dir, curve_tree) = handle();
        let pinner = EngineServeSetPinner::new(curve_tree, daemon(0, None), [7; 32]);

        let report = pinner.pin_serve_set().await.expect("pin");
        assert_eq!(report.as_of_height, BlockHeight(0));
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
}
