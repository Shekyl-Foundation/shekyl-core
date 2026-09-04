// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The **public** drain façade (WI-RPC-5): one embedder-callable method,
//! [`Engine::drain_to_principal`], over the crate-internal CB-3 dispatch seam
//! ([`Engine::submit_drain`](super::drain_dispatch)).
//!
//! The façade exists so the wallet-RPC `drain` handler can fire a drain
//! without constructing witnesses or naming persona slots — and, more
//! load-bearingly, so it **cannot** steer the parameters the firewall pins:
//!
//! - **No `p_slot` parameter (type-level active-persona restriction).** The
//!   façade resolves the live active persona from the stake actor's own state
//!   and refuses ([`DrainToPrincipalError::NoActivePersona`]) when there is
//!   none. There is no argument through which a caller could point the drain
//!   at another persona — and no `retired` flag either: the dispatch seam
//!   resolves live-vs-retired from the sealed P-scan state itself
//!   (`pending_unbonds`), so a live persona can never be treated as
//!   terminally unbonded and the DS-4 `EXIT_FEE_RESERVE_ATOMIC` gate stays on
//!   exactly the orchestrator path `submit_drain` already runs. The
//!   structural test below pins both absences.
//! - **No `fee` parameter (P-lane fee-uniformity CONTRACT PIN).** The fee is
//!   the canonical `P`-lane floor, quoted internally from the **same**
//!   function the bond post uses
//!   ([`p_lane_floor_fee`](super::bond_orchestrator::p_lane_floor_fee)) — a
//!   user fee control would be a wallet fingerprint in a cleartext field.
//! - **No `destination` parameter.** The dispatch seam pins vout 0 to the
//!   wallet's own principal address (T-DS-3); the façade adds nothing a
//!   caller could redirect.
//! - **Production prune witness.** The façade mints
//!   [`SpentRecordsDurablyPruned::arm1_watch_pruning_live`] the same way the
//!   bond orchestrator does, so the drain's go-live stays compile-blocked on
//!   the same SP-R0 production mint as every other funding-output spender.
//!
//! `payment` is the one caller input: user intent, never pre-filled from a
//! reward vector (F-D2). Everything downstream — persist-before-dispatch,
//! the one-live-drain seal, the audited transport choke point — is the
//! dispatch seam's, unchanged.

use std::sync::Arc;

use shekyl_units::AtomicUnits;
use tokio::sync::RwLock;

use super::bond_assembly::SpentRecordsDurablyPruned;
use super::bond_orchestrator::p_lane_floor_fee;
use super::drain_dispatch::DrainRequestError;
use super::drain_orchestrator::DrainIntent;
use super::drain_orchestrator::{DrainError, DrainOrchestrationError};
use super::fee_policy::FeeEstimatorError;
use super::pending::TxHash;
use super::pscan::start::pending_post_store_for_engine;
use super::signer::EngineSignerKind;
use super::traits::{DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, RefreshEngine};
use super::transaction_submitter::SubmitSuccess;
use super::Engine;
use shekyl_engine_file::WalletFile;

/// What one drain did, projected public: the network verdict plus the
/// locally-computed tx id. The wallet-RPC `drain` handler renders this
/// directly (`BROADCAST` / `ALREADY_IN_CHAIN` + `confirmed_height`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainOutcome {
    /// The bytes are held by the daemon and network-exposed (accepted or
    /// already pooled), not yet settled.
    Broadcast {
        /// The locally computed tx id.
        tx_hash: TxHash,
    },
    /// A previously-sealed identical drain was found confirmed in the main
    /// chain at submit time.
    AlreadyInChain {
        /// The locally computed tx id.
        tx_hash: TxHash,
        /// Daemon-claimed confirming-block height (untrusted; a release-path
        /// discriminant, never settlement truth).
        height: u64,
    },
}

/// Why [`Engine::drain_to_principal`] refused, flattened for the `pub`
/// boundary: each arm carries the crate-internal error's user-facing
/// **rendering** where detail is needed, never the crate-private type itself.
/// Every rendering is scalar-free (no amount, no gindex — the firewall's
/// value-out leg leaks nothing through its errors), inherited from the
/// dispatch seam's own discipline. Arms are cut by the wallet-RPC code they
/// map to (rule 82: distinct remedy ⇒ distinct arm).
#[derive(Debug, thiserror::Error)]
pub enum DrainToPrincipalError {
    /// This wallet runs no stake engine — it is not an archival staker, and
    /// the drain path does not exist here (`-29507`).
    #[error("this wallet is not a staker: no stake engine is running")]
    NotStaker,
    /// The wallet is a staker but no persona is currently active — there is
    /// nothing for a drain to act on (`-29508`).
    #[error("no active persona to drain")]
    NoActivePersona,
    /// The drain would spend a **live** persona's pool below the exit-fee
    /// reserve (DS-4). Lower the payment, or retire the persona first
    /// (`-29509`).
    #[error("drain would spend the live persona pool below the exit-fee reserve")]
    ReserveBreached,
    /// No submittable curve-tree reference can be anchored yet — transient;
    /// let the wallet sync and retry (`-29510`).
    #[error("no submittable reference can be anchored: {detail}")]
    Unanchorable {
        /// The anchoring helper's own (scalar-free) reason.
        detail: String,
    },
    /// A live pending drain already exists for this persona — one live drain
    /// per persona (`-29511`). Releasing the seal is the drain lifecycle
    /// driver's job, and that driver is **half wired** as of PR #572: a drain
    /// that CONFIRMS now releases its seal (retired against its reserved inputs
    /// leaving the wallet's live funding set), so this refusal no longer
    /// outlives a successful drain. It still persists across sessions on the
    /// failure path, by **two** routes — a drain the network rejects
    /// **terminally**, and a drain whose submit was **ambiguous** (a transport
    /// error leaves the sealed record live on purpose, because the bytes may
    /// already have reached the network; if they did not, nothing resubmits
    /// them — the driver resubmits bond posts only). Either way the inputs are
    /// never spent, so the drain never settles and the lane stays shut until
    /// terminal-reject prune and byte-identical resubmit land
    /// (`docs/FOLLOWUPS.md` "Drain/claim dispatch driver — terminal-reject
    /// prune + byte-identical resubmit", target V3.0 pre-genesis). A stall
    /// alarm names the stuck lane in the operator log rather than leaving it
    /// silent.
    #[error("a pending drain already exists for this persona; one live drain per persona")]
    InFlight,
    /// This drain's swept inputs are no longer current — either a concurrent
    /// bond post or emission claim reserves one, or a reservation was released
    /// mid-assembly; nothing was sealed — retry
    /// (`-29511`, retry remedy).
    #[error(
        "this drain's inputs are no longer current — another live record holds \
         one, or a reservation was released mid-assembly; retry"
    )]
    InputRaced,
    /// The requested payment is zero — nothing to move. Its own arm, never
    /// folded into [`Self::Refused`] (rule 82: `-29101`'s "lower the payment
    /// or wait for accrual" remedy is unsatisfiable at zero — the remedy here
    /// is "send a nonzero amount", a malformed *request*). The wallet-RPC
    /// layer also rejects zero at its params boundary (`-32602`) before any
    /// engine work; this arm keeps the refusal honest for direct embedder
    /// callers and is checked up front, before persona resolution or any
    /// daemon round trip.
    #[error("the requested drain amount is zero — nothing to move")]
    EmptyRequest,
    /// The F-D1 planner refused the payment itself (exceeds spendable,
    /// uncoverable by the spendable outputs, or needs more inputs than one
    /// drain can spend). User-actionable: lower the payment or wait for `P`
    /// accrual.
    #[error("drain refused: {detail}")]
    Refused {
        /// The planner's own (scalar-free) reason.
        detail: String,
    },
    /// The daemon fee-estimate query failed — check the daemon connection and
    /// retry (the `-29102` remedy shape).
    #[error("drain fee estimate failed: {detail}")]
    FeeEstimate {
        /// The query failure's rendering.
        detail: String,
    },
    /// The daemon *answered* the fee query and the wallet refused the answer
    /// (`ValidatedFeeEstimates` ceiling) — retrying the connection does not
    /// help (the `-29109` remedy shape). Carries the violation's public
    /// scalars (daemon-quoted per-weight rate vs. the wallet's bound — chain
    /// facts, never wallet amounts) so the RPC layer can fill `-29109`'s
    /// structured `error.data` exactly as the send path does.
    #[error("drain fee estimate refused by the wallet's sanity ceiling ({reason})")]
    FeeUnreasonable {
        /// Which interim check refused (engine-supplied static string).
        reason: &'static str,
        /// Offending per-weight rate (atomic units).
        rate: u64,
        /// The violated bound (atomic units per weight).
        bound: u64,
    },
    /// A non-transient engine fault: a sealed-state read, a corrupted
    /// resident key, the curve-tree actor, or the assembly itself. Fail
    /// closed; not retryable by waiting.
    #[error("engine state ({context}): {detail}")]
    State {
        /// Which stage refused.
        context: &'static str,
        /// The stage's own (scalar-free) rendering.
        detail: String,
    },
    /// The assembled bytes' dispatch failed at (or behind) the submit choke
    /// point. The sealed record stays live; the drain driver owns its fate —
    /// do **not** re-fire blindly.
    #[error("drain broadcast: {detail}")]
    Submit {
        /// The transport failure's rendering.
        detail: String,
    },
}

impl From<DrainRequestError> for DrainToPrincipalError {
    fn from(e: DrainRequestError) -> Self {
        match e {
            DrainRequestError::NotStaker => Self::NotStaker,
            DrainRequestError::Stake(e) => Self::State {
                context: "stake engine",
                detail: e.to_string(),
            },
            DrainRequestError::Destination { detail } => Self::State {
                context: "principal destination",
                detail: detail.to_string(),
            },
            DrainRequestError::State { context, detail } => Self::State { context, detail },
            // The seam types the pre-seal daemon-tip failure separately for
            // the exit verbs' retry contract; this WI-RPC-5 façade keeps its
            // prior disposition (the failure was `State` before) — retyping
            // `drain_to_principal`'s daemon-outage remedy is its own concern,
            // not the exit lane's.
            DrainRequestError::DaemonUnreachable { context, detail } => {
                Self::State { context, detail }
            }
            DrainRequestError::DrainPending => Self::InFlight,
            DrainRequestError::InputRaced => Self::InputRaced,
            DrainRequestError::Drain(orch) => match orch {
                DrainOrchestrationError::ReferenceUnanchorable { detail } => {
                    Self::Unanchorable { detail }
                }
                DrainOrchestrationError::ReserveBreached => Self::ReserveBreached,
                // The planner's zero arm keeps its own façade arm (the façade
                // pre-check makes it unreachable from `drain_to_principal`,
                // but the mapping stays total and honest for any other
                // pipeline entry).
                DrainOrchestrationError::Plan(DrainError::EmptyRequest) => Self::EmptyRequest,
                DrainOrchestrationError::Plan(e) => Self::Refused {
                    detail: e.to_string(),
                },
                DrainOrchestrationError::Tree(e) => Self::State {
                    context: "curve tree",
                    detail: format!("{e:?}"),
                },
                DrainOrchestrationError::PathAssembly { detail } => Self::State {
                    context: "path assembly",
                    detail,
                },
                DrainOrchestrationError::Stake(e) => Self::State {
                    context: "drain assembly",
                    detail: e.to_string(),
                },
                // Unreachable through this façade (it only ever sends a
                // `Payment` intent — the structural test pins that); mapped
                // for totality, as a defect rather than a user remedy.
                e @ DrainOrchestrationError::SweepOnLivePersona => Self::State {
                    context: "drain intent",
                    detail: e.to_string(),
                },
            },
            DrainRequestError::Submit(e) => Self::Submit {
                detail: e.to_string(),
            },
        }
    }
}

#[allow(private_bounds)] // same Engine-trait privacy posture as submit_drain
impl<S, D, L, E, R, P> Engine<S, D, L, E, R, P, WalletFile>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    Self: Send + Sync,
{
    /// Drain `payment` from the **live active persona's** `P` pool back to
    /// this wallet's own principal balance (module docs: no slot, no fee, no
    /// destination — by type, not by convention).
    ///
    /// Seals before it sends (persist-before-dispatch) and submits through
    /// the audited persona-transport choke point; the returned
    /// [`DrainOutcome`] is the network verdict. The canonical floor fee is
    /// paid from the pool on top of `payment`; a live persona refuses
    /// [`DrainToPrincipalError::ReserveBreached`] rather than dip below the
    /// exit-fee reserve.
    pub async fn drain_to_principal(
        self_arc: Arc<RwLock<Self>>,
        payment: AtomicUnits,
    ) -> Result<DrainOutcome, DrainToPrincipalError> {
        // A zero payment is a malformed request, refused before any actor,
        // file, or network work — the planner's own zero arm stays the
        // authoritative check inside the pipeline; this copy only spares a
        // request that cannot succeed its daemon round trip.
        if payment.is_zero() {
            return Err(DrainToPrincipalError::EmptyRequest);
        }

        // Brief read: the stake handle (refuse a non-staker before any I/O),
        // a daemon clone for the fee quote, and the pending-post write lock
        // for the advisory in-flight read below.
        let (daemon, stake, pending_write_lock) = {
            let g = self_arc.read().await;
            let stake = g.stake_handle().ok_or(DrainToPrincipalError::NotStaker)?;
            (g.daemon().clone(), stake, g.pending_write_lock.clone())
        };

        // Resolve the LIVE active persona from the actor's own state — the
        // type-level restriction: no caller-supplied slot exists to disagree
        // with it. Idle staker ⇒ refuse before any network round trip.
        let identity = stake
            .active_persona()
            .await
            .map_err(|e| DrainToPrincipalError::State {
                context: "active persona",
                detail: e.to_string(),
            })?
            .ok_or(DrainToPrincipalError::NoActivePersona)?;

        // Advisory copy of the one-live-drain read, BEFORE the daemon fee
        // round trip. The AUTHORITATIVE serialization stays `seal_drain`
        // under the write lock at the dispatch seam's seal; this read is
        // sound by that seam's own argument for its pre-assembly copy ("this
        // read only saves the wasted proof work") — here it saves the
        // network RTT, and keeps the refusal truthful: a wallet whose drain
        // lane is sealed AND whose daemon is unreachable answers the
        // in-flight `-29511`, not a `-29102` sending the user to debug a
        // daemon that is not the problem.
        let p_canonical_id = stake
            .persona_canonical_id(identity.p_slot)
            .await
            .map_err(|e| DrainToPrincipalError::State {
                context: "persona identity",
                detail: e.to_string(),
            })?;
        let store = pending_post_store_for_engine(self_arc.clone(), pending_write_lock);
        let already = store
            .read(|block| block.has_live_drain_for(&p_canonical_id))
            .await
            .map_err(|e| DrainToPrincipalError::State {
                context: "pending-drain read",
                detail: e.to_string(),
            })?;
        if already {
            return Err(DrainToPrincipalError::InFlight);
        }

        // Canonical P-lane floor fee — the same function the bond post
        // quotes, preserving the -29109 vs -29102 remedy split.
        let fee = p_lane_floor_fee(daemon.get_fee_estimates().await.map_err(|e| {
            DrainToPrincipalError::FeeEstimate {
                detail: e.into().to_string(),
            }
        })?)
        .map_err(|e| match e {
            FeeEstimatorError::DaemonFeeUnreasonable(v) => DrainToPrincipalError::FeeUnreasonable {
                reason: v.reason(),
                rate: v.rate(),
                bound: v.bound(),
            },
            other => DrainToPrincipalError::FeeEstimate {
                detail: other.to_string(),
            },
        })?;

        // Production prune witness (SP-R0), minted exactly as the bond
        // orchestrator mints it; then the crate-internal dispatch seam owns
        // everything else (reserve gate, seal, transport).
        let witness = SpentRecordsDurablyPruned::arm1_watch_pruning_live();
        let receipt = Engine::submit_drain(
            self_arc,
            identity.p_slot,
            DrainIntent::Payment(payment),
            fee,
            &witness,
        )
        .await?;

        Ok(match receipt.submit {
            SubmitSuccess::Broadcast { hash, .. } => DrainOutcome::Broadcast { tx_hash: hash },
            SubmitSuccess::AlreadyInChain { hash, height } => DrainOutcome::AlreadyInChain {
                tx_hash: hash,
                height,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use shekyl_units::AtomicUnits;
    use tokio::sync::RwLock;

    use super::super::drain_dispatch::DrainRequestError;
    use super::super::drain_orchestrator::{DrainError, DrainOrchestrationError};
    use super::DrainToPrincipalError;
    use crate::engine::Engine;

    /// The façade's structural pins, `drain_dispatch`-tripwire style (comment
    /// lines stripped so module docs cannot satisfy a negative guard):
    ///
    /// 1. **No slot steering:** the production section never names `p_slot:`
    ///    in a signature — the persona comes from `active_persona()` alone.
    /// 2. **No live-vs-retired steering:** the façade never constructs a
    ///    `DrainCtx` and never touches a `retired` flag — the dispatch seam's
    ///    own pscan-state resolution (the DS-4 gate's input) is the only one.
    /// 3. **Production witness + canonical fee:** the SP-R0 mint and the
    ///    shared `p_lane_floor_fee` are the quoted sources.
    /// 4. The one submit route is the crate-internal `submit_drain` seam.
    #[test]
    fn facade_cannot_steer_slot_fee_or_retirement() {
        // Split on the `#[cfg(test)]` boundary only — not the full
        // `mod tests {` line — so a reformat of the test-module declaration
        // can't silently fold the test section into the scanned text
        // (`drain_amount.rs` pattern). `split_once` + `expect` fails loudly
        // if the boundary is ever absent, rather than the old
        // `.split(..).next()` — whose `expect` could never fire (`split`
        // always yields a first element) — defaulting to the whole file.
        let (production, _tests) = include_str!("drain_facade.rs")
            .split_once("\n#[cfg(test)]")
            .expect("drain_facade.rs has a #[cfg(test)] section to exclude from the scan");
        let code: String = production
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            !code.contains("p_slot:"),
            "the façade must not take or bind a slot parameter (type-level active-persona pin)"
        );
        assert!(
            code.contains(".active_persona()"),
            "the persona must come from the actor's own active state"
        );
        assert!(
            !code.contains("DrainCtx") && !code.contains("retired"),
            "the façade must not construct the pipeline context or steer live-vs-retired \
             (the DS-4 reserve gate's input stays the dispatch seam's pscan resolution)"
        );
        assert!(
            code.contains("SpentRecordsDurablyPruned::arm1_watch_pruning_live()"),
            "the SP-R0 production witness mint"
        );
        assert!(
            code.contains("p_lane_floor_fee("),
            "the fee must be the shared canonical P-lane floor quote"
        );
        assert!(
            code.contains("Engine::submit_drain("),
            "the one dispatch route is the crate-internal seam"
        );
        assert!(
            code.contains("DrainIntent::Payment(")
                && !code.contains("TerminalSweep")
                && !code.contains("TerminalExitObserved"),
            "this façade sends the user-target Payment intent ONLY — the \
             terminal sweep and its witness mint belong to collect_unstaked \
             (unstake_facade), whose exited-persona resolution this \
             active-persona façade must never inherit"
        );
    }

    /// The reserve-gate refusal survives the flattening: the orchestrator's
    /// `ReserveBreached` (the DS-4 gate, pinned by the orchestrator's own
    /// tests) maps onto the façade arm the RPC renders as `-29509` — the
    /// in-flight/raced pair both land on the `-29511` remedy arms — and the
    /// planner's zero arm keeps its own `EmptyRequest` identity while every
    /// other planner refusal stays `Refused` (rule 82: the "lower the
    /// payment" remedy is unsatisfiable at zero).
    #[test]
    fn error_flattening_preserves_the_rpc_discriminants() {
        let breached: DrainToPrincipalError =
            DrainRequestError::Drain(DrainOrchestrationError::ReserveBreached).into();
        assert!(matches!(breached, DrainToPrincipalError::ReserveBreached));

        let pending: DrainToPrincipalError = DrainRequestError::DrainPending.into();
        assert!(matches!(pending, DrainToPrincipalError::InFlight));

        let raced: DrainToPrincipalError = DrainRequestError::InputRaced.into();
        assert!(matches!(raced, DrainToPrincipalError::InputRaced));

        let unanchored: DrainToPrincipalError =
            DrainRequestError::Drain(DrainOrchestrationError::ReferenceUnanchorable {
                detail: "tree behind tip".into(),
            })
            .into();
        assert!(matches!(
            unanchored,
            DrainToPrincipalError::Unanchorable { .. }
        ));

        let zero: DrainToPrincipalError =
            DrainRequestError::Drain(DrainOrchestrationError::Plan(DrainError::EmptyRequest))
                .into();
        assert!(matches!(zero, DrainToPrincipalError::EmptyRequest));

        let unaffordable: DrainToPrincipalError =
            DrainRequestError::Drain(DrainOrchestrationError::Plan(DrainError::Unaffordable))
                .into();
        assert!(
            matches!(unaffordable, DrainToPrincipalError::Refused { .. }),
            "non-zero planner refusals stay on the Refused arm"
        );
    }

    use crate::engine::test_support::{activate_persona, non_staker_engine, staker_engine};

    /// This suite's deterministic-seed multiplier (`test_support::fixed_seed`).
    const SEED_MULT: u8 = 7;

    /// A zero payment is refused as its own malformed-request arm, before
    /// persona resolution or any I/O — even a non-staker gets `EmptyRequest`,
    /// not `NotStaker` (the request is invalid regardless of who sent it).
    #[tokio::test(flavor = "multi_thread")]
    async fn drain_of_zero_is_an_empty_request_before_any_work() {
        let (_tmp, engine) = non_staker_engine(SEED_MULT);
        let engine = Arc::new(RwLock::new(engine));

        let err = Engine::drain_to_principal(engine, AtomicUnits::from_raw(0))
            .await
            .expect_err("a zero drain must refuse");
        assert!(
            matches!(err, DrainToPrincipalError::EmptyRequest),
            "got {err:?}"
        );
    }

    /// A non-staker cannot drain — refused up front, before persona
    /// resolution, fee quote, or any network I/O.
    #[tokio::test(flavor = "multi_thread")]
    async fn drain_on_a_non_staker_is_not_staker() {
        let (_tmp, engine) = non_staker_engine(SEED_MULT);
        let engine = Arc::new(RwLock::new(engine));

        let err = Engine::drain_to_principal(engine, AtomicUnits::from_raw(50_000))
            .await
            .expect_err("a non-staker cannot drain");
        assert!(
            matches!(err, DrainToPrincipalError::NotStaker),
            "got {err:?}"
        );
    }

    /// A staker with no active persona has nothing to drain — refused before
    /// the fee quote (no daemon round trip; the dummy daemon would fail one).
    #[tokio::test(flavor = "multi_thread")]
    async fn drain_on_an_idle_staker_has_no_active_persona() {
        let (_tmp, engine) = staker_engine(3, SEED_MULT);
        let engine = Arc::new(RwLock::new(engine));

        let err = Engine::drain_to_principal(engine, AtomicUnits::from_raw(50_000))
            .await
            .expect_err("an idle staker has no active persona to drain");
        assert!(
            matches!(err, DrainToPrincipalError::NoActivePersona),
            "got {err:?}"
        );
    }

    /// A sealed live drain refuses `InFlight` (`-29511`) **before the daemon
    /// fee round trip**: this test runs against the never-connecting dummy
    /// daemon, so reaching the fee quote would fail as `FeeEstimate`
    /// (`-29102`, "check the daemon") — getting `InFlight` therefore proves
    /// the advisory in-flight read precedes the quote. That ordering is the
    /// fix for the sealed-wallet-with-flaky-daemon misdiagnosis (the truthful
    /// refusal is the seal, not the daemon), and this is the dispatch-layer
    /// `-29511` path's first behavioral coverage — the seal is produced
    /// through the same `seal_drain` store mutation production seals with,
    /// not a hand-built error value.
    #[tokio::test(flavor = "multi_thread")]
    async fn sealed_live_drain_refuses_in_flight_before_the_fee_quote() {
        use crate::engine::pscan::start::pending_post_store_for_engine;
        use shekyl_engine_state::pending_post_block::{
            PendingDrain, PendingPostState, SealAdmission,
        };
        use shekyl_types::PSlot;

        let (_tmp, engine) = staker_engine(3, SEED_MULT);
        activate_persona(&engine, 3).await;
        let engine = Arc::new(RwLock::new(engine));

        // Seal a live drain for the active persona, exactly as the dispatch
        // seam would (persona-keyed record; the reservation is the record).
        let (stake, write_lock) = {
            let g = engine.read().await;
            (
                g.stake_handle().expect("staker"),
                g.pending_write_lock.clone(),
            )
        };
        let persona = stake
            .persona_canonical_id(PSlot::from_raw(3))
            .await
            .expect("canonical id");
        let store = pending_post_store_for_engine(engine.clone(), write_lock);
        let sealed = store
            .mutate(move |block| {
                let g = block.generation();
                let admitted = block.seal_drain(
                    PendingDrain {
                        persona,
                        tx_bytes: vec![0xd7; 32],
                        funding_gindexes: vec![shekyl_types::GlobalOutputIndex::from_raw(42)],
                        state: PendingPostState::Pending,
                    },
                    shekyl_types::BlockHeight::from_raw(1),
                    g,
                ) == SealAdmission::Admit;
                (admitted, admitted)
            })
            .await
            .expect("seal a live drain");
        assert!(sealed, "fixture drain must seal");

        let err = Engine::drain_to_principal(engine, AtomicUnits::from_raw(50_000))
            .await
            .expect_err("a sealed live drain refuses a second drain");
        assert!(
            matches!(err, DrainToPrincipalError::InFlight),
            "expected InFlight before the fee quote (a FeeEstimate arm here \
             means the advisory read ran after the quote), got {err:?}"
        );
    }
}
