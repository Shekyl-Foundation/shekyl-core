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
use super::drain_orchestrator::DrainOrchestrationError;
use super::fee_policy::FeeEstimatorError;
use super::pending::TxHash;
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
    /// per persona; wait for it to confirm or fail (`-29511`).
    #[error("a pending drain already exists for this persona; one live drain per persona")]
    InFlight,
    /// A concurrent same-persona post reserved one of this drain's swept
    /// inputs between snapshot and seal; nothing was sealed — retry
    /// (`-29511`, retry remedy).
    #[error("a concurrent post reserved one of this drain's inputs; retry")]
    InputRaced,
    /// The F-D1 planner refused the payment itself (zero, exceeds spendable,
    /// uncoverable by the spendable outputs). User-actionable: lower the
    /// payment or wait for `P` accrual.
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
    /// help (the `-29109` remedy shape).
    #[error("drain fee estimate refused: {detail}")]
    FeeUnreasonable {
        /// The ceiling violation's rendering.
        detail: String,
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
            DrainRequestError::Identity(e) => Self::State {
                context: "persona identity",
                detail: e.to_string(),
            },
            DrainRequestError::Destination { detail } => Self::State {
                context: "principal destination",
                detail: detail.to_string(),
            },
            DrainRequestError::State { context, detail } => Self::State { context, detail },
            DrainRequestError::DrainPending => Self::InFlight,
            DrainRequestError::InputRaced => Self::InputRaced,
            DrainRequestError::Drain(orch) => match orch {
                DrainOrchestrationError::ReferenceUnanchorable { detail } => {
                    Self::Unanchorable { detail }
                }
                DrainOrchestrationError::ReserveBreached => Self::ReserveBreached,
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
        // Brief read: the stake handle (refuse a non-staker before any I/O)
        // and a daemon clone for the fee quote.
        let (daemon, stake) = {
            let g = self_arc.read().await;
            let stake = g.stake_handle().ok_or(DrainToPrincipalError::NotStaker)?;
            (g.daemon().clone(), stake)
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

        // Canonical P-lane floor fee — the same function the bond post
        // quotes, preserving the -29109 vs -29102 remedy split.
        let fee = p_lane_floor_fee(daemon.get_fee_estimates().await.map_err(|e| {
            DrainToPrincipalError::FeeEstimate {
                detail: e.into().to_string(),
            }
        })?)
        .map_err(|e| match e {
            FeeEstimatorError::DaemonFeeUnreasonable(v) => DrainToPrincipalError::FeeUnreasonable {
                detail: v.to_string(),
            },
            other => DrainToPrincipalError::FeeEstimate {
                detail: other.to_string(),
            },
        })?;

        // Production prune witness (SP-R0), minted exactly as the bond
        // orchestrator mints it; then the crate-internal dispatch seam owns
        // everything else (reserve gate, seal, transport).
        let witness = SpentRecordsDurablyPruned::arm1_watch_pruning_live();
        let receipt =
            Engine::submit_drain(self_arc, identity.p_slot, payment, fee, &witness).await?;

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

    use shekyl_crypto_pq::account::MASTER_SEED_BYTES;
    use shekyl_engine_file::SafetyOverrides;
    use shekyl_rpc_transport::HttpRpc;
    use shekyl_types::PSlot;
    use shekyl_units::AtomicUnits;
    use tempfile::TempDir;
    use tokio::sync::RwLock;

    use super::super::drain_dispatch::DrainRequestError;
    use super::super::drain_orchestrator::DrainOrchestrationError;
    use super::DrainToPrincipalError;
    use crate::engine::{
        Credentials, DaemonClient, Engine, EngineCreateParams, OpenedEngine, SoloSigner,
    };

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
        let production = include_str!("drain_facade.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("drain_facade.rs has a production section");
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
    }

    /// The reserve-gate refusal survives the flattening: the orchestrator's
    /// `ReserveBreached` (the DS-4 gate, pinned by the orchestrator's own
    /// tests) maps onto the façade arm the RPC renders as `-29509` — and the
    /// in-flight/raced pair both land on the `-29511` remedy arms.
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
    }

    /// A `DaemonClient` that never connects: both refusal paths under test
    /// short-circuit before any network I/O. (Replicated from the
    /// `principal_stake` suite — those helpers are test-private.)
    fn dummy_daemon() -> DaemonClient {
        let rpc = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(HttpRpc::new("http://127.0.0.1:1".to_string()))
        })
        .expect("construct HttpRpc (no actual connection attempted)");
        DaemonClient::new(rpc)
    }

    fn fixed_seed() -> [u8; MASTER_SEED_BYTES] {
        let mut s = [0u8; MASTER_SEED_BYTES];
        for (i, b) in s.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).unwrap_or(0).wrapping_mul(7);
        }
        s
    }

    fn creds() -> Credentials<'static> {
        Credentials::password_only(b"correct horse battery staple")
    }

    /// A non-staker cannot drain — refused up front, before persona
    /// resolution, fee quote, or any network I/O.
    #[tokio::test(flavor = "multi_thread")]
    async fn drain_on_a_non_staker_is_not_staker() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path().join("wallet");
        let (creds, seed) = (creds(), fixed_seed());
        let params = EngineCreateParams::for_test_full(&base, &creds, &seed);
        let engine =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create non-staker");
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
        let (_tmp, engine) = staker_engine(3);
        let engine = Arc::new(RwLock::new(engine));

        let err = Engine::drain_to_principal(engine, AtomicUnits::from_raw(50_000))
            .await
            .expect_err("an idle staker has no active persona to drain");
        assert!(
            matches!(err, DrainToPrincipalError::NoActivePersona),
            "got {err:?}"
        );
    }

    /// A **staker** engine (persists a bond record for `slot` →
    /// `staking_enabled`, then reopens so the StakeEngine spawns). Idle — no
    /// persona is activated.
    fn staker_engine(slot: u32) -> (TempDir, Engine<SoloSigner>) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path().join("wallet");
        let (creds, seed) = (creds(), fixed_seed());
        let params = EngineCreateParams::for_test_full(&base, &creds, &seed);
        let network = params.network;
        let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create");
        engine
            .persist_bond_record(PSlot::from_raw(slot))
            .expect("persist bond record → staking_enabled");
        engine.close(&creds).expect("close created wallet");
        let opened = Engine::<SoloSigner>::open_full(
            &base,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect("reopen staker wallet");
        let engine = match opened {
            OpenedEngine::Loaded(w) => w,
            OpenedEngine::Restored { wallet, .. } => wallet,
        };
        assert!(
            engine.stake_handle().is_some(),
            "a staker reopen spawns the StakeEngine"
        );
        (tmp, engine)
    }
}
