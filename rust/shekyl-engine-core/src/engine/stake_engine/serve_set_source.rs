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

use shekyl_curve_tree::{BlockHeight, SegmentPin, ServingReader};
use shekyl_p_host::{PinReport, ServeSetPinner};

use crate::engine::curve_tree_actor::CurveTreeHandle;
use crate::engine::emission_source::fetch_emission_claim_source;
use crate::engine::prpc::PersonaIsolatedTransport;

/// Derives a persona's serve-set from its connected bond record and pins it.
// Inert until the lifecycle slice starts a `PersonaServingHost` and drives its
// refresh from the P-scan sweep. Landed with the seam it implements rather
// than after it, so the one place a serve-set can come from exists before
// anything can be wired to a second one.
//
// Lives under `stake_engine/` rather than at `engine/` top level because both
// halves of its input are already this tree's: the bond record it reads is what
// `bond`/`claim` assemble, and the lifecycle call that will start the host is a
// `StakeEngine` message. A `serve_set_source` at the engine root would have been
// a module the composition root declares and nothing else near it uses.
#[allow(dead_code)]
pub(crate) struct EngineServeSetPinner<R: PersonaIsolatedTransport> {
    curve_tree: CurveTreeHandle,
    rpc: R,
    p_id: [u8; 32],
}

#[allow(dead_code)]
impl<R: PersonaIsolatedTransport> EngineServeSetPinner<R> {
    /// Bind a pinner to one persona's canonical id and its own transport.
    pub(crate) fn new(curve_tree: CurveTreeHandle, rpc: R, p_id: [u8; 32]) -> Self {
        Self {
            curve_tree,
            rpc,
            p_id,
        }
    }
}

impl<R: PersonaIsolatedTransport + Sync> ServeSetPinner for EngineServeSetPinner<R> {
    async fn pin_serve_set(&self) -> Result<PinReport, String> {
        let source = fetch_emission_claim_source(&self.rpc, &self.p_id)
            .await
            .map_err(|e| format!("claim-source fetch failed: {e}"))?;

        // No connected record is **not** an error and **not** an empty
        // serve-set by default — it is a persona with no bond, which owes
        // nothing and pins nothing. Reported as the empty set so the host's
        // witness still describes reality (and its staleness clock still
        // advances) rather than the refresh failing forever on a wallet that
        // simply has not bonded yet.
        let shard_ids: Vec<u64> = source
            .bond
            .as_ref()
            .map(|bond| bond.holdings.shard_ids.as_slice().to_vec())
            .unwrap_or_default();

        let (outcomes, reader): (Vec<(u64, SegmentPin)>, ServingReader) = self
            .curve_tree
            .pin_serve_set(shard_ids.clone())
            .await
            .map_err(|e| format!("serve-set pin failed: {e:?}"))?;

        Ok(PinReport {
            shard_ids,
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
                    kind: HoldingsKind::ShardSetCompact,
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
    #[tokio::test]
    async fn the_report_is_derived_from_the_connected_record() {
        let (_dir, curve_tree) = handle();
        let pinner =
            EngineServeSetPinner::new(curve_tree, daemon(30_001, Some(vec![4, 9])), [7; 32]);

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
        let pinner = EngineServeSetPinner::new(curve_tree, daemon(30_001, None), [7; 32]);

        let report = pinner
            .pin_serve_set()
            .await
            .expect("no bond is not an error");

        assert!(report.shard_ids.is_empty());
        assert!(report.outcomes.is_empty());
        assert_eq!(report.as_of_height, BlockHeight(30_000));
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
