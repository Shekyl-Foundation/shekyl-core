// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Retire / project-id messages.

use kameo::message::{Context, Message};

use shekyl_types::PCanonicalId;

use super::actor::StakeEngine;
use super::types::*;

use super::actor::persona_canonical_id;
/// Project the **public** canonical id of a held persona (SA-DQ-3 / first-stake
/// W2-resume: the engine needs to ask "does a confirmed bond post exist for
/// slot S?" against the pscan evidence, which is keyed by canonical id). Same
/// public projection `bonded_scan_inputs` computes per scan; no secret
/// crosses the boundary.
pub(crate) struct ProjectPersonaCanonicalId {
    pub p_slot: PSlot,
}

impl Message<ProjectPersonaCanonicalId> for StakeEngine {
    type Reply = Result<PCanonicalId, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: ProjectPersonaCanonicalId,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let held = self
            .held
            .get(&msg.p_slot)
            .ok_or(StakeEngineError::LookaheadExhausted {
                requested: msg.p_slot,
            })?;
        persona_canonical_id(held.keys())
            .map_err(|e| StakeEngineError::ScanSetup(ScanSetupError::CanonicalId(e)))
    }
}

/// Retire a now-terminal bonded persona from the scan union (2d-1 DQ8), wiping its
/// key. Carries the [`RetirementWitness`] — the positive-confirmation evidence
/// that gates the wipe (the actor cannot re-verify). Sent by the SP-5 scan task
/// when it confirms an `Unbond` + `W`-lapse + finality-deep.
#[allow(dead_code)] // transient — the SP-5 scan task is the lib sender.
pub(crate) struct RetireBondedPersona {
    pub witness: RetirementWitness,
    /// Slots the caller knows still hold unspent funding — the funded-gate
    /// operand. The handler resolves the witness to a slot and refuses the
    /// irreversible wipe if the slot is in this set (returns `SkippedFunded`).
    /// `Arc` so a sweep with many retire candidates clones a pointer per
    /// message, not the set (the containment properties — redacting `Debug`,
    /// no `Serialize` — ride through the `Arc` unchanged).
    pub funded_slots: std::sync::Arc<FundedSlots>,
}

// The retire is infallible at the actor — all outcomes are valid and idempotent,
// so the handler always returns `Ok`. The `Result` reply matches the other
// handlers (and lets the handle's `ask` surface a stopped actor as
// `StakeActorUnavailable`); the `Err` arm is only ever the actor being gone.
impl Message<RetireBondedPersona> for StakeEngine {
    type Reply = Result<RetireOutcome, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: RetireBondedPersona,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self.retire_bonded(&msg.witness, &msg.funded_slots))
    }
}

// ---------------------------------------------------------------------------
// Handle
