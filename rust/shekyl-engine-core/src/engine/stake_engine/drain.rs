
use kameo::message::{Context, Message};

#[cfg(feature = "gf7-hooks")]
use shekyl_standoff::gf7::{BroadcastTimelineObserver, NoOpObserver, TimelineEvent};

use crate::engine::drain_assembly::{assemble_drain_tx, AssembleDrain, AssembledDrain};

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

