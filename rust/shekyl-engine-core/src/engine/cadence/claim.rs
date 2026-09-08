// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Leg 3 (`ENGINE_CADENCE_DRIVER.md` §3 leg 3, §4): per-epoch emission claim.
//!
//! The scheduler in [`super`] fires this adapter; claim policy — held-epoch
//! memory, evaluate-and-forfeit, the value floor, the foreground yield —
//! lives here, next to the dispatch seam it calls.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::time::Duration;

use shekyl_engine_file::WalletFile;
use shekyl_operator_alarm::{AlarmCondition, OperatorAlarms};

use super::super::claim_dispatch::ClaimTickOutcome;
use super::super::signer::EngineSignerKind;
use super::super::traits::{
    DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, RefreshEngine,
};
use super::super::Engine;
use super::{CadenceLeg, WeakEngine};

/// Consecutive claim-leg faults before [`AlarmCondition::EpochClaim`]
/// raises (rule 75: rationale + bounds).
///
/// **Rationale.** One fault is routine (a daemon restart, a transient
/// transport refusal); the leg retries on the next chain advance for free.
/// Three consecutive faults span ≥ 3 observed block advances — minutes of
/// wall time over distinct daemon round-trips — at which point the refusal
/// is a condition, not a blip.
///
/// **Bounds.** [2, 10]: 1 alarm-fatigues on transients; past ~10 the
/// operator has been blind to a real refusal for the better part of an
/// hour.
pub(crate) const CLAIM_FAULT_ALARM_THRESHOLD: u32 = 3;

/// Byte allowance for the single claim vin row, added to
/// [`EMISSION_NON_CLAIMS_RESERVE_BYTES`] when pricing the claim envelope —
/// the regtest-e2e fee model (live run 4: the bond's 32 KiB ceiling
/// underprices a claim, which carries two input proofs; overpaying is a
/// miner transfer, never a conservation term).
///
/// [`EMISSION_NON_CLAIMS_RESERVE_BYTES`]: super::super::emission_claim::EMISSION_NON_CLAIMS_RESERVE_BYTES
const CLAIM_VIN_ALLOWANCE_BYTES: usize = 2048;

/// Request timeout for the claim leg's loopback claim-source transport.
const CLAIM_RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Leg 3's cross-tick state, shared between fires through an `Arc<Mutex>`
/// (a fire's future is `'static`, so it cannot borrow the leg).
/// Session-scoped, deliberately: everything durable about a claim lives in
/// the sealed [`PendingEmissionClaim`] record and the chain itself; this is
/// only the leg's memory of what it deferred and what it already looked at.
///
/// [`PendingEmissionClaim`]: shekyl_engine_state::pending_post_block::PendingEmissionClaim
#[derive(Default)]
pub(crate) struct ClaimLegState {
    /// The settled epoch as of the last **completed** evaluation (claimed,
    /// idle, or value-deferred). `None` until the first one — which is why
    /// a wallet closed for months evaluates its whole backlog on the first
    /// post-open tick (§4: expected; for a serving persona, liveness is
    /// already public). Not advanced by yields, faults, or a pending claim,
    /// so those retry on the next chain advance instead of waiting a close.
    pub(crate) evaluated_at_epoch: Option<u64>,
    /// The last `ValueDeferred` set, `(epoch, reward)` — kept because the
    /// reward is recomputed inside derivation and is no longer derivable
    /// once the window expires the epoch; pricing a forfeit honestly needs
    /// it (§4 evaluate-and-forfeit).
    pub(crate) held: Vec<(u64, u64)>,
    /// Consecutive faulted fires; reset by any completed evaluation.
    pub(crate) consecutive_faults: u32,
    /// Session-running forfeited total ([`record_forfeit`](shekyl_operator_alarm::cadence::record_forfeit)'s
    /// contract: the standing alarm shows the full amount lost this session).
    pub(crate) forfeited_total: u64,
}

/// Uniform per-epoch claim. Un-GF-4: the "scheduling stays external (the
/// GF-4 seam)" comments deferred to a grading scheduler that was never
/// built; this leg is the scheduler, and the schedule is **uniform** —
/// every staker wallet evaluates at every settlement close (plus its own
/// poll phase), no per-wallet jitter, no grading. The *inclusion decision*
/// is value-conditional (the §4 concession): Σreward across held epochs
/// must clear [`EMISSION_CLAIM_FEE_FLOOR`] or the whole set holds
/// ([`EmissionClaimError::ValueDeferred`]), re-evaluated at every close,
/// **evaluate-and-forfeit** at the window floor — never force a claim whose
/// fee exceeds its reward.
///
/// Fire shape, in order:
///
/// 1. **Once per close:** no-op unless the settled epoch advanced past the
///    last completed evaluation (or a prior fire faulted/yielded — those
///    retry every advance).
/// 2. **Staker + active persona:** a non-staker produces no claim
///    observations at all (the board reads "not watched", honestly); an
///    idle staker has no claimant to sign as.
/// 3. **User work always wins (§3):** user-initiated pending-post
///    operations hold the engine gate's [`ForegroundSession`] across their
///    whole assemble→seal span. The leg reads the gauge twice — here, as a
///    cheap pre-assembly skip, and authoritatively inside the dispatch
///    seam's seal critical section ([`ForegroundHold`]), where the pending
///    write lock totally orders the check against every foreground
///    registration.
/// 4. **Fee + transport:** the daemon's live economy estimate over the
///    claim envelope; the claim-source fetch rides a fresh loopback
///    [`LocalNodeRpc`] over the driver's daemon address (a non-loopback
///    daemon is a named, alarmable refusal).
/// 5. **Dispatch** through [`Engine::submit_emission_claim`] — the CB-3
///    seam, persist-before-dispatch and the audited submitter choke point
///    included.
///
/// [`EMISSION_CLAIM_FEE_FLOOR`]: shekyl_economics::EMISSION_CLAIM_FEE_FLOOR
/// [`EmissionClaimError::ValueDeferred`]: super::super::emission_claim::EmissionClaimError::ValueDeferred
/// [`ForegroundSession`]: super::super::pending_post_gate::ForegroundSession
/// [`ForegroundHold`]: super::super::claim_dispatch::EmissionClaimRequestError::ForegroundHold
/// [`LocalNodeRpc`]: super::super::prpc::LocalNodeRpc
pub(crate) struct EpochClaimLeg<S, D, L, E, R, P>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
{
    pub(crate) engine: WeakEngine<S, D, L, E, R, P, WalletFile>,
    /// The loopback daemon endpoint the claim-source fetch rides — the
    /// same embedder-supplied address leg 2 serves over.
    pub(crate) daemon_address: String,
    /// The driver's shared board ([`super::CadenceHandle::alarms`]).
    pub(crate) alarms: Arc<OperatorAlarms>,
    pub(crate) state: Arc<std::sync::Mutex<ClaimLegState>>,
}

/// One completed evaluation (claimed / deferred / idle): sweep the
/// previously-held set for forfeits, replace it, advance the epoch
/// cursor, clear the fault streak, and read healthy on the board.
///
/// **Forfeit rule (§4):** a previously-held epoch that is in neither
/// the newly-claimed nor the newly-deferred set *and* has passed the
/// claim-window floor was let expire underwater — record it at its held
/// reward. (Missing but unexpired epochs just fell out of this
/// evaluation — a re-derivation picks them up next close; nothing to
/// record.)
pub(crate) fn claim_complete(
    state: &std::sync::Mutex<ClaimLegState>,
    alarms: &OperatorAlarms,
    settled: u64,
    claimed: &[u64],
    new_held: Vec<(u64, u64)>,
) {
    let mut s = state.lock().expect("claim leg state lock");
    let previously_held = std::mem::take(&mut s.held);
    for (epoch, reward) in previously_held {
        let still_present = claimed.contains(&epoch) || new_held.iter().any(|(e, _)| *e == epoch);
        if !still_present && shekyl_archival_retention::epoch_is_claim_expired(epoch, settled) {
            s.forfeited_total += reward;
            shekyl_operator_alarm::cadence::record_forfeit(alarms, epoch, s.forfeited_total);
            tracing::warn!(
                epoch,
                forfeited_atomic = reward,
                session_total = s.forfeited_total,
                "emission claim forfeited: epoch reached the window floor \
                 still below the fee floor and was let expire (§4 \
                 evaluate-and-forfeit)"
            );
        }
    }
    s.held = new_held;
    s.evaluated_at_epoch = Some(settled);
    s.consecutive_faults = 0;
    shekyl_operator_alarm::cadence::apply_claim(
        alarms,
        shekyl_operator_alarm::cadence::ClaimObservation::Current,
    );
}

/// One faulted fire: count it, and past the threshold raise the
/// backlog alarm. The oldest/outstanding figures derive from the last
/// completed evaluation — a heuristic that may **under**state the
/// backlog when the leg never completed one (it claims one outstanding
/// epoch, not the true count it cannot know without the derivation
/// that is itself faulting) — honest, never overstated.
pub(crate) fn claim_fault(
    state: &std::sync::Mutex<ClaimLegState>,
    alarms: &OperatorAlarms,
    settled: u64,
    detail: &dyn std::fmt::Display,
) {
    let mut s = state.lock().expect("claim leg state lock");
    s.consecutive_faults += 1;
    tracing::warn!(
        error = %detail,
        consecutive = s.consecutive_faults,
        "epoch-claim leg: attempt faulted; retrying on the next chain advance"
    );
    if s.consecutive_faults >= CLAIM_FAULT_ALARM_THRESHOLD {
        let oldest_epoch = s.evaluated_at_epoch.map_or(settled, |e| e + 1);
        let outstanding_epochs = settled.saturating_sub(oldest_epoch).max(1);
        shekyl_operator_alarm::cadence::apply_claim(
            alarms,
            shekyl_operator_alarm::cadence::ClaimObservation::Behind {
                oldest_epoch,
                outstanding_epochs,
            },
        );
    }
}

impl<S, D, L, E, R, P> CadenceLeg for EpochClaimLeg<S, D, L, E, R, P>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    Engine<S, D, L, E, R, P, WalletFile>: Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        "epoch-claim"
    }

    fn park_condition(&self) -> Option<AlarmCondition> {
        Some(AlarmCondition::EpochClaim)
    }

    fn fire(&mut self, tip: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let weak = Weak::clone(&self.engine);
        let address = self.daemon_address.clone();
        let alarms = Arc::clone(&self.alarms);
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let settled = shekyl_archival_retention::settlement_epoch_at_height(tip);
            {
                let s = state.lock().expect("claim leg state lock");
                // Once per close — unless the last fire faulted or yielded,
                // which retry on every advance rather than waiting a close.
                if s.consecutive_faults == 0 && s.evaluated_at_epoch == Some(settled) {
                    return;
                }
            }
            let Some(engine) = weak.upgrade() else {
                return;
            };
            let (stake, daemon, pending_gate) = {
                let g = engine.read().await;
                let Some(stake) = g.stake_handle() else {
                    // Not a staker: no claim obligation, and deliberately no
                    // claim observation either — the board carries no
                    // EpochClaim row at all ("not watched", the honest
                    // rendering).
                    return;
                };
                (stake, g.daemon().clone(), g.pending_gate.clone())
            };
            let p_slot = match stake.active_persona().await {
                Ok(Some(identity)) => identity.p_slot,
                // An idle staker has no claimant to sign as this tick.
                Ok(None) => return,
                Err(e) => return claim_fault(&state, &alarms, settled, &e),
            };

            // §3: user work always wins. A raised foreground gauge means a
            // user-initiated pending-post is somewhere in its assemble→seal
            // span; yield the whole tick before spending any work. This
            // pre-assembly read is the cheap skip — the authoritative check
            // runs inside the dispatch seam's seal critical section
            // (`ForegroundHold`). Ordinary transfers are not part of this
            // gauge: they fund from the wallet ledger under `output_locks`,
            // a pool disjoint from the persona funding gindexes claims
            // reserve.
            if pending_gate.foreground_in_flight() {
                return;
            }

            let fee = match daemon.get_fee_estimates().await {
                Ok(estimates) => estimates.economy.calculate_fee_from_weight(
                    super::super::emission_claim::EMISSION_NON_CLAIMS_RESERVE_BYTES
                        + CLAIM_VIN_ALLOWANCE_BYTES,
                ),
                Err(e) => return claim_fault(&state, &alarms, settled, &e.into()),
            };
            let claim_rpc =
                match super::super::prpc::LocalNodeRpc::new(address, CLAIM_RPC_TIMEOUT).await {
                    Ok(rpc) => rpc,
                    Err(e) => {
                        // Named requirement (rule 82): the claim-source fetch is
                        // persona-isolated and currently loopback-only.
                        tracing::warn!(
                            error = %e,
                            "epoch-claim leg: emission claims require a loopback \
                             daemon address; claims are on hold until one is \
                             configured"
                        );
                        return claim_fault(&state, &alarms, settled, &e);
                    }
                };

            match Engine::submit_emission_claim(
                engine,
                &claim_rpc,
                p_slot,
                shekyl_units::AtomicUnits::from_raw(fee),
                &super::super::bond_assembly::SpentRecordsDurablyPruned::arm1_watch_pruning_live(),
            )
            .await
            {
                Ok(receipt) => {
                    tracing::info!(
                        claimed = ?receipt.claim.claimed_epochs,
                        total_reward = receipt.claim.total_reward,
                        verdict = ?receipt.submit,
                        "emission claim dispatched"
                    );
                    claim_complete(
                        &state,
                        &alarms,
                        settled,
                        &receipt.claim.claimed_epochs,
                        Vec::new(),
                    );
                }
                Err(e) => match e.tick_outcome() {
                    ClaimTickOutcome::Idle => {
                        claim_complete(&state, &alarms, settled, &[], Vec::new())
                    }
                    ClaimTickOutcome::Deferred(held) => {
                        tracing::debug!(
                            held = ?held,
                            "emission claim value-deferred: holding until the \
                             accumulated set clears the fee floor (§4)"
                        );
                        claim_complete(&state, &alarms, settled, &[], held);
                    }
                    ClaimTickOutcome::Yield => {}
                    ClaimTickOutcome::Fault => claim_fault(&state, &alarms, settled, &e),
                },
            }
        })
    }
}
