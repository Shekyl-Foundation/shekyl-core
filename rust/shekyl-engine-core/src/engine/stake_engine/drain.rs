// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! AssembleDrain thin validate-and-delegate handler.

use kameo::message::{Context, Message};

#[cfg(feature = "gf7-hooks")]
use shekyl_standoff::gf7::{BroadcastTimelineObserver, NoOpObserver, TimelineEvent};

use crate::engine::drain_assembly::{assemble_drain_tx, AssembleDrain, AssembledDrain};

use super::actor::StakeEngine;
use super::types::*;

// ---------------------------------------------------------------------------
// F-D2 DS-PR-1 — AssembleDrain: the P→principal value-out message
// ---------------------------------------------------------------------------

impl Message<AssembleDrain> for StakeEngine {
    type Reply = Result<AssembledDrain, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: AssembleDrain,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // Thin validate-and-delegate shell (composition discipline): the same
        // handle-validation preamble as `AssembleEmissionClaim` (no ticket, no
        // entry-seam draw), then the held bundle is borrowed and the crypto
        // assembly runs in `drain_assembly::assemble_drain_tx`. `keys` never
        // crosses the actor boundary (rule 36); `&mut self` is held across the
        // proving await so the mailbox cannot interleave.
        self.validate_handle(&msg.handle)?;
        let handle_slot = msg.handle.p_slot();
        let keys = self
            .held
            .get(&handle_slot)
            .expect("validate_handle confirmed slot is held")
            .keys();
        assemble_drain_tx(
            keys,
            &msg.dest,
            msg.funding,
            msg.tree_ctx,
            msg.payment_amount,
            msg.fee,
        )
        .await
    }
}
