
use kameo::message::{Context, Message};

#[cfg(feature = "gf7-hooks")]
use shekyl_standoff::gf7::{BroadcastTimelineObserver, NoOpObserver, TimelineEvent};
use shekyl_types::PCanonicalId;


// S6 / DQ3 — the session RNG self-cert grader (`shekyl-standoff` `conformance`)
// is gated to **`x86_64` exactly** (the guard below is `target_arch = "x86_64"`,
// matching the `x86_64`-only CI conformance lane and the standoff conformance
// lane it mirrors): its goodness-of-fit is float, which is not bit-identical
// across architectures, and `x86_64` is the only target the diagnostic is built
// and run on. Rather than silently compile the self-cert out on a non-`x86_64`
// target (which would let a `--features conformance` diagnostic build report
// "conformance passed" when the grade never ran — false assurance), fail the
// build loudly: a diagnostic build that cannot run the diagnostic must say so at
// compile time, not pretend success at runtime. With this guard, `conformance`
// implies `x86_64`, so the self-cert call below needs only `cfg(feature)`.
#[cfg(all(feature = "conformance", not(target_arch = "x86_64")))]
compile_error!(
    "the StakeEngine session RNG self-cert grader (shekyl-standoff `conformance`) \
     is `x86_64`-only — its float goodness-of-fit is not bit-identical across \
     architectures. Build the `conformance` feature on `x86_64` (where the CI \
     conformance lane runs); do not enable it on other targets (including 32-bit \
     x86)."
);


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






