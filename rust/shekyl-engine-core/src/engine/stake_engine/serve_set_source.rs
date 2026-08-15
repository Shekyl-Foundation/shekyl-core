// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`EngineServeSetPinner`] — the production `ServeSetPinner`: read the
//! connected bond record, pin what it holds, report both (SH-2).
//!
//! Two holdings kinds, two derivations, one seam. `ShardSetCompact` pins the
//! record's explicit list. `CompleteTree` — the Foundation archival posture —
//! owes the whole corpus, which no list can express, so the serve-set is
//! *enumerated from the store's own frozen-segments table* and re-enumerated
//! on every refresh: as segments freeze they join the corpus with no list
//! maintained anywhere that could drift ([`CurveTreeHandle::pin_frozen_corpus`]).
//! That arm runs only for an operator who activated it through the CLI
//! ([`CompleteTreeServing`]); otherwise it refuses loudly, because serving
//! the empty set a `CompleteTree` record decodes to is §9.6 item 4's silent
//! slash.
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
use shekyl_curve_tree::{BlockHeight, SegmentPin, ServingReader};
use shekyl_p_host::{PinReport, ServeSetPinner};

use crate::engine::curve_tree_actor::CurveTreeHandle;
use crate::engine::emission_source::fetch_emission_claim_source;
use crate::engine::prpc::PersonaIsolatedTransport;

/// Whether this wallet's operator has activated Foundation `CompleteTree`
/// serving (`operational.serve_complete_tree`, flipped only by the CLI).
///
/// A two-variant enum rather than a `bool` so the construction site reads as
/// what it is — a posture the operator chose after the CLI stated the terms
/// (no rewards, outside the staking economy, unbounded disk, slash side
/// intact) — and so the `CompleteTree` match arm below cannot be satisfied
/// by an accidental `true` from some unrelated flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompleteTreeServing {
    /// The default: a `CompleteTree` bond refuses to serve, loudly, with the
    /// activation remedy named.
    NotActivated,
    /// The operator activated the archival posture: the frozen corpus is the
    /// serve-set, re-enumerated on every refresh.
    Activated,
}

/// Derives a persona's serve-set from its connected bond record and pins it.
// Wired by `Engine::start_serving_if_staker` (SH-2b-2). Landed with the seam
// it implements rather than after it, so the one place a serve-set can come
// from exists before anything can be wired to a second one.
//
// The SH-2b open question — whether the lifecycle should start a host at all
// for a `CompleteTree` persona — is now answered where the caller could not
// answer it: the host starts unconditionally, and *this* seam decides per
// holdings kind. `first_stake` still hardcodes the CompleteTree posture (the
// named PR-4c deviation), so a first-stake wallet that has not activated
// archival serving keeps the loud refusal, now with its remedy named.
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
    complete_tree: CompleteTreeServing,
}

impl<R: PersonaIsolatedTransport> EngineServeSetPinner<R> {
    /// Bind a pinner to one persona's canonical id, its own transport, and
    /// the operator's `CompleteTree` posture (read from prefs at wallet open).
    pub(crate) fn new(
        curve_tree: CurveTreeHandle,
        rpc: R,
        p_id: [u8; 32],
        complete_tree: CompleteTreeServing,
    ) -> Self {
        Self {
            curve_tree,
            rpc,
            p_id,
            complete_tree,
        }
    }
}

impl<R: PersonaIsolatedTransport + Sync> ServeSetPinner for EngineServeSetPinner<R> {
    async fn pin_serve_set(&self) -> Result<PinReport, String> {
        let source = fetch_emission_claim_source(&self.rpc, &self.p_id)
            .await
            .map_err(|e| format!("claim-source fetch failed: {e}"))?;

        // Two different empties reach this match, and conflating them is the
        // defect it exists to prevent. `shard_ids` must never be read
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
        // What "the whole corpus" means is therefore never a list this seam
        // holds: activated, it is the store's own frozen-segments enumeration,
        // pinned in the same write transaction that reads it
        // (`LeafStore::pin_frozen_corpus`), and the refresh cadence re-running
        // this function is the growth policy — a segment that froze since the
        // last refresh joins the serve-set on the next one.
        //
        // **Refused when not activated.** Serving the corpus is an operator
        // posture with real terms (no rewards, outside the staking economy,
        // unbounded disk growth, slash side intact), and the CLI is the one
        // surface that states those terms and asks. Until then, failing here
        // fails `PinnedServeSet::acquire`, so the host does not start — loud
        // and early, instead of a witness that is wrong in the dangerous
        // direction.
        enum Derivation {
            Explicit(Vec<u64>),
            FrozenCorpus,
        }
        let derivation = match source.bond.as_ref() {
            None => Derivation::Explicit(Vec::new()),
            Some(bond) => match bond.holdings.kind {
                HoldingsKind::ShardSetCompact => {
                    Derivation::Explicit(bond.holdings.shard_ids.as_slice().to_vec())
                }
                HoldingsKind::CompleteTree => match self.complete_tree {
                    CompleteTreeServing::Activated => Derivation::FrozenCorpus,
                    CompleteTreeServing::NotActivated => {
                        return Err(
                            "connected bond has CompleteTree holdings: this persona owes \
                             the whole corpus, and serving it is not activated on this \
                             wallet — a Foundation archival operator activates it from \
                             the CLI (`serve_complete_tree`), which states the terms: no \
                             staking rewards, unbounded disk growth, slash exposure while \
                             not serving"
                                .to_string(),
                        )
                    }
                },
            },
        };

        let (outcomes, reader): (Vec<(u64, SegmentPin)>, ServingReader) = match derivation {
            Derivation::Explicit(shard_ids) => self
                .curve_tree
                .pin_serve_set(shard_ids)
                .await
                .map_err(|e| format!("serve-set pin failed: {e:?}"))?,
            Derivation::FrozenCorpus => self
                .curve_tree
                .pin_frozen_corpus()
                .await
                .map_err(|e| format!("frozen-corpus pin failed: {e:?}"))?,
        };

        Ok(PinReport {
            // Derived from the outcomes rather than echoed from the request:
            // for the explicit arm the two are identical by the store's
            // one-outcome-per-member contract, and for the corpus arm the
            // outcomes ARE the enumeration — there is no request list to echo.
            shard_ids: outcomes.iter().map(|(shard_id, _)| *shard_id).collect(),
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
            outcomes,
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

    /// A store whose segment 0 is already frozen, opened through the same
    /// client/handle path production uses — the fixture the `CompleteTree`
    /// arm needs, because a corpus pin over an empty store proves nothing
    /// (the enumeration and the refusal would both report the empty set).
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
                        gindex: Gindex(gindex),
                        maturity: shekyl_curve_tree::BlockHeight(60),
                        creation_height: shekyl_curve_tree::BlockHeight(0),
                        leaf,
                        identity: OutputIdentity {
                            output_key: [1u8; 32],
                            commitment: Some([2u8; 32]),
                            h_pqc: [3u8; 32],
                            target: TargetKind::TaggedKey,
                        },
                    }
                })
                .collect();
            // Buried far past the freeze gate, so segment 0 froze on append.
            // (`append_block_deltas` with empty pending deltas — the same
            // shape the store's own test wrapper uses.)
            store
                .append_block_deltas(&entries, &[], &[], shekyl_curve_tree::BlockHeight(30_000))
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
    #[tokio::test]
    async fn the_report_is_derived_from_the_connected_record() {
        let (_dir, curve_tree) = handle();
        let pinner = EngineServeSetPinner::new(
            curve_tree,
            daemon(30_001, Some(vec![4, 9])),
            [7; 32],
            CompleteTreeServing::NotActivated,
        );

        let report = pinner.pin_serve_set().await.expect("pin");

        assert_eq!(
            report.shard_ids,
            vec![4, 9],
            "the set is the connected record's holdings, not anything held locally"
        );
        assert_eq!(
            report.as_of_height,
            BlockHeight(30_000),
            "chain_height is a COUNT; the stamp is the tip it describes, one lower"
        );
        assert_eq!(
            report
                .outcomes
                .iter()
                .map(|(shard_id, _)| *shard_id)
                .collect::<Vec<_>>(),
            vec![4, 9],
            "outcomes come back covering the reported set, in the record's order"
        );
        assert!(
            report
                .outcomes
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
        let pinner = EngineServeSetPinner::new(
            curve_tree,
            daemon(30_001, None),
            [7; 32],
            CompleteTreeServing::NotActivated,
        );

        let report = pinner
            .pin_serve_set()
            .await
            .expect("no bond is not an error");

        assert!(report.shard_ids.is_empty());
        assert!(report.outcomes.is_empty());
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
            CompleteTreeServing::NotActivated,
        );
        let err = complete_tree
            .pin_serve_set()
            .await
            .expect_err("a whole-corpus obligation must refuse, not pin the empty set");
        assert!(
            err.contains("CompleteTree"),
            "the refusal must name the holdings kind so the operator can act on it: {err}"
        );
        assert!(
            err.contains("serve_complete_tree"),
            "the refusal must name the activation remedy (rule 82): {err}"
        );

        // Same empty list, opposite meaning, and it must still succeed.
        let (_dir_b, curve_tree_b) = handle();
        let owes_nothing = EngineServeSetPinner::new(
            curve_tree_b,
            daemon_of_kind(30_001, Some(Vec::new()), HoldingsKind::ShardSetCompact),
            [7; 32],
            CompleteTreeServing::NotActivated,
        );
        let report = owes_nothing
            .pin_serve_set()
            .await
            .expect("an empty ShardSetCompact owes nothing and is not an error");
        assert!(report.shard_ids.is_empty());
        assert!(report.outcomes.is_empty());
    }

    /// **The activated arm, over a store that has actually frozen a shard.**
    /// The serve-set is the store's enumeration — the bond record supplied no
    /// list — and it is reported pinned-servable, so the witness describes a
    /// Foundation node serving everything that exists so far. Over an empty
    /// store this test would be vacuous (refusal and corpus both read empty),
    /// which is why the fixture freezes a segment first.
    #[tokio::test]
    async fn activated_complete_tree_serves_the_enumerated_frozen_corpus() {
        let (_dir, curve_tree) = handle_with_frozen_segment();
        let pinner = EngineServeSetPinner::new(
            curve_tree,
            daemon_of_kind(30_001, Some(Vec::new()), HoldingsKind::CompleteTree),
            [7; 32],
            CompleteTreeServing::Activated,
        );

        let report = pinner
            .pin_serve_set()
            .await
            .expect("an activated CompleteTree persona pins the frozen corpus");

        assert_eq!(
            report.shard_ids,
            vec![0],
            "the serve-set is the store's frozen enumeration, not the record's \
             (empty) shard list"
        );
        assert_eq!(
            report.outcomes,
            vec![(0, SegmentPin::PinnedServable)],
            "the one frozen segment is pinned and servable"
        );
        assert_eq!(
            report.as_of_height,
            BlockHeight(30_000),
            "the record height still stamps the report — the set's provenance \
             clock does not change with the derivation"
        );
    }

    /// Activation changes nothing for a `ShardSetCompact` bond: the explicit
    /// list stays the serve-set. The posture selects how `CompleteTree` is
    /// derived; it is not a second growth policy for market bonds.
    #[tokio::test]
    async fn activation_does_not_reroute_an_explicit_shard_set() {
        let (_dir, curve_tree) = handle_with_frozen_segment();
        let pinner = EngineServeSetPinner::new(
            curve_tree,
            daemon(30_001, Some(Vec::new())),
            [7; 32],
            CompleteTreeServing::Activated,
        );

        let report = pinner
            .pin_serve_set()
            .await
            .expect("an empty ShardSetCompact still owes nothing");
        assert!(
            report.shard_ids.is_empty(),
            "the frozen segment must NOT leak into an explicit-set bond's \
             serve-set just because the operator activated archival serving"
        );
    }

    /// An empty chain has no tip. `ChainCount(0).tip()` is `None`, and the
    /// stamp must land on 0 rather than underflow or refuse — 0 is also what
    /// an un-ingested store reports, so the host's lag reads zero and the
    /// tripwire correctly stays quiet on a wallet at genesis.
    #[tokio::test]
    async fn an_empty_chain_stamps_height_zero() {
        let (_dir, curve_tree) = handle();
        let pinner = EngineServeSetPinner::new(
            curve_tree,
            daemon(0, None),
            [7; 32],
            CompleteTreeServing::NotActivated,
        );

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
        let pinner = EngineServeSetPinner::new(
            curve_tree,
            daemon(30_001, Some(vec![1])),
            [7; 32],
            CompleteTreeServing::NotActivated,
        );

        let first = pinner.pin_serve_set().await.expect("pin");
        let second = pinner.pin_serve_set().await.expect("pin again");

        assert!(
            first.reader.same_store(&second.reader),
            "two pins through one handle are two pins in one store"
        );
    }
}
