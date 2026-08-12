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
//! The fetch rides the caller-supplied [`Rpc`], which for a persona **must**
//! be its own `PTorClient`/`PRpc` — never the principal's daemon session
//! (§7.4 transport pin). This type does not create transports; it takes one,
//! so the enforcement stays where the persona's identity is known.

use shekyl_curve_tree::{SegmentPin, ServingReader};
use shekyl_p_host::{PinReport, ServeSetPinner};
use shekyl_rpc_client::Rpc;

use super::curve_tree_actor::CurveTreeHandle;
use super::emission_source::fetch_emission_claim_source;

/// Derives a persona's serve-set from its connected bond record and pins it.
// Inert until the lifecycle slice starts a `PersonaServingHost` and drives its
// refresh from the P-scan sweep. Landed with the seam it implements rather
// than after it, so the one place a serve-set can come from exists before
// anything can be wired to a second one.
#[allow(dead_code)]
pub(crate) struct EngineServeSetPinner<R: Rpc> {
    curve_tree: CurveTreeHandle,
    rpc: R,
    p_id: [u8; 32],
}

#[allow(dead_code)]
impl<R: Rpc> EngineServeSetPinner<R> {
    /// Bind a pinner to one persona's canonical id and its own transport.
    pub(crate) fn new(curve_tree: CurveTreeHandle, rpc: R, p_id: [u8; 32]) -> Self {
        Self {
            curve_tree,
            rpc,
            p_id,
        }
    }
}

impl<R: Rpc + Sync> ServeSetPinner for EngineServeSetPinner<R> {
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
            // The height the daemon read the record at — the tripwire's
            // record-side clock. Deliberately the reply's own height rather
            // than anything measured locally: it is the height the shard list
            // is true *as of*, and pairing it with a locally-observed tip
            // would compare two facts about different moments.
            //
            // `tip()`, not the raw count. `chain_height` is a ChainCount (the
            // daemon's `db.height()`), and the value it is compared against —
            // `LeafStore::sync_tip_height` — is a block *height*. Passing the
            // count would make a perfectly current serve-set read as one block
            // stale forever, a permanent off-by-one in the direction that
            // cries wolf. An empty chain has no tip and reads 0, which is also
            // what an un-ingested store reports, so the lag is 0 and the
            // tripwire correctly stays quiet.
            as_of_height: source
                .chain_height
                .tip()
                .map_or(0, shekyl_types::BlockHeight::to_raw),
            outcomes,
            reader,
        })
    }
}
