// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! ScanStep message handler.

use kameo::message::{Context, Message};

#[cfg(feature = "gf7-hooks")]
use shekyl_standoff::gf7::{BroadcastTimelineObserver, NoOpObserver, TimelineEvent};

use crate::engine::pscan::scan_step::{
    run_dual_extractor, DualExtractOutput, ScanStep, ScanStepResult, SpentFundingMatch,
};

use super::actor::StakeEngine;
use super::types::*;

// SP-5 — the actor performs the per-batch scan-step; `view_sk` never crosses the
// boundary. The handler builds the bonded union's transient scanners from the
// resident bundles and **offloads** the CPU+secret dual extraction to
// `spawn_blocking`, so the secret lives only inside the closure and drops at its
// end (DQ5). The handler holds `&mut self` across the offload `await`, so the
// (unbounded) mailbox cannot process another message until it returns — which is
// exactly why the task sends **bounded** `ScanStep`s, interleaving
// activation/sign/activate between batches (DQ6: bounded AND offloaded). Only the
// public `ScanStepResult` comes back.
impl Message<ScanStep> for StakeEngine {
    type Reply = Result<ScanStepResult, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: ScanStep,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let ScanStep {
            range,
            blocks,
            held_funding,
        } = msg;
        // SP-R0 arm #1 (DQ-A): watch upkeep against the task's held list —
        // cheap set work in-actor; any uncached record's derivation offloads
        // to its own blocking closure (DQ5/DQ6 — the vault moves in and back;
        // spend material never enters the *extractor* closure below). The
        // common warm-cache step derives nothing and skips the offload.
        let to_derive = self.watch_upkeep(&held_funding);
        if !to_derive.is_empty() {
            let outcomes = self.derive_watch_key_images_offloaded(to_derive).await;
            for (gindex, outcome) in outcomes {
                self.absorb_watch_derivation(gindex, outcome);
            }
        }
        let (scanners, known_personas) = self.bonded_scan_inputs()?;
        // Hand the extractor closure a transient watch snapshot (documented
        // rule-35 `Clone` exception on the type; both copies wipe on drop).
        let watch = self.watch_cache.clone();
        // The secret `scanners` are MOVED into the closure; they never reach the
        // actor task again and are dropped at the closure's end. The two `?`
        // surface the join failure (`ScanJoin`) and the extraction failure
        // (`ScanStep`) via their `#[from]` conversions — structured, not
        // stringified.
        let DualExtractOutput {
            mut result,
            trailing_key_images,
        } = tokio::task::spawn_blocking(move || {
            run_dual_extractor(scanners, &known_personas, range, &blocks, &watch)
        })
        .await??;
        // Close arm (c)'s in-step blind spot: derive this step's discoveries
        // (derive-on-add, offloaded exactly like the refresh) and match them
        // against the trailing spend key images the closure collected — an
        // output discovered at height `h` can be spent at `h' > h` within
        // the same step, and only the actor can derive its key image. Merged
        // hits prune exactly like watch hits; the derived entries also warm
        // the cache for the next step. Discoveries are rare (the common case
        // is an empty candidate list — zero cost, no offload).
        let to_derive = self.watch_derivation_candidates(&result.funding_outputs);
        if !to_derive.is_empty() {
            let outcomes = self.derive_watch_key_images_offloaded(to_derive).await;
            for (gindex, outcome) in outcomes {
                if let Some(key_image) = self.absorb_watch_derivation(gindex, outcome) {
                    if trailing_key_images.contains(&key_image) {
                        result.spent_funding.push(SpentFundingMatch { gindex });
                    }
                }
            }
        }
        // Drop-on-prune: spent outputs leave the watch with their records.
        for spent in &result.spent_funding {
            self.watch_cache.remove_gindex(spent.gindex);
        }
        Ok(result)
    }
}
