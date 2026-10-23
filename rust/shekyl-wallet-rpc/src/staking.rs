// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Staking read-only JSON-RPC methods (WI-RPC-1).
//!
//! Pure projections of [`shekyl_engine_core::Engine::stake`] /
//! [`shekyl_engine_core::StakeFacade::staking_read_view`], the one
//! authoritative aggregation over the sealed pscan / pending-post records —
//! never the `bonded_slots` hint. All three methods are read-only (`&self`
//! under the engine read guard). The façade is always a view, so non-stakers
//! get honest zeros rather than a missing-handle error. Staking *actions*
//! (unstake, claim) are out of scope: they land on
//! [`shekyl_engine_core::StakeFacade`] when reachable.
//!
//! `get_balance` / `get_wallet_info` snapshot-then-read through the engine's
//! own `StakeFacade::balance_snapshot_with` — nested `ledger.read()` under a live
//! [`shekyl_engine_core::LedgerReadGuard`] deadlocks, so the guard-drop
//! choreography and the degrade/loud split live in engine-core, once, for
//! this server and the desktop wallet alike; [`map_balance_view`] is the
//! only balance-side mapping left here.

use serde::Deserialize;
use serde_json::Value;
use shekyl_engine_core::{
    Engine, InFlightRecord, InFlightState, ReportedOutcome, ServingPosture, ServingStatus,
    SoloSigner, StakedOutput, StakingReadView,
};
use shekyl_engine_state::pending_post_block::{OutcomeKind, RecordKind};
use shekyl_types::BlockHeight;

use crate::error::WalletRpcError;
use crate::params::{parse_optional_object, require_empty_object};
use crate::tenant::{require_open_engine, TenantState};
use crate::types::{
    GetStakedBalanceResult, GetStakedOutputsResult, InFlightEntry, StakedOutputView,
    StakingInfoResult, StakingOutcomeEntry,
};

/// Params for `get_staked_outputs`.
#[derive(Debug, Default, Deserialize)]
struct GetStakedOutputsParams {
    /// Accepted for wire-shape stability; the authoritative set contains
    /// only finality-confirmed outputs at V3.0, so `false` changes nothing.
    #[allow(dead_code)]
    confirmed_only: Option<bool>,
}

pub(crate) async fn get_staked_balance(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "get_staked_balance")?;
    let view = read_view(tenants).await?;
    serde_json::to_value(balance_result(&view))
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_staked_balance: {e}")))
}

pub(crate) async fn get_staked_outputs(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let _p: GetStakedOutputsParams = parse_optional_object(params, "get_staked_outputs")?;
    let view = read_view(tenants).await?;
    let result = GetStakedOutputsResult {
        staked_outputs: view.outputs.iter().map(staked_output_view).collect(),
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_staked_outputs: {e}")))
}

pub(crate) async fn staking_info(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "staking_info")?;
    let (view, serving) = read_view_with_serving(tenants).await?;
    serde_json::to_value(staking_info_result(&view, serving))
        .map_err(|e| WalletRpcError::InternalError(format!("serialize staking_info: {e}")))
}

/// Compute the authoritative view from an already-held engine read guard.
///
/// The staking RPC methods' single call site of
/// [`StakeFacade::staking_read_view`](shekyl_engine_core::StakeFacade::staking_read_view)
/// (product door; the Engine inherent still owns the body). The
/// off-the-worker discipline and the error mapping below have one home
/// rather than a copy per caller.
///
/// **Do not call this while a [`shekyl_engine_core::LedgerReadGuard`] is
/// live.** `staking_read_view` takes its own brief `ledger.read()` for
/// `staking_enabled`; nesting that under a held guard deadlocks on
/// non-reentrant `std::sync::RwLock`. Callers that already observed the flag
/// under a ledger guard must drop that guard and use
/// `StakeFacade::balance_snapshot_with` instead (`get_wallet_info` is the exemplar).
///
/// `staking_read_view` opens and decrypts the sealed `.wallet.pscan` /
/// `.wallet.pending` files inline (envelope KDF + AEAD + postcard decode), so
/// it is run through [`tokio::task::block_in_place`] — the same off-the-worker
/// discipline `lifecycle.rs` uses for its synchronous engine calls, so a large
/// seal cannot stall the tokio worker (and any tenant scheduled on it) for the
/// decrypt. Every runtime that hosts this server is multi-threaded — the
/// `#[tokio::main]` binary and the CLI's in-process
/// `Builder::new_multi_thread` spawn — so `block_in_place` never hits its
/// `current_thread` panic. A future single-threaded host would have to move
/// this to `spawn_blocking`, which is why the call is not scattered.
///
/// A corrupt or version-mismatched seal fails closed as `InternalError` with
/// a stable, detail-free client message (the cause can carry filesystem
/// paths; it is logged server-side only — same discipline as the
/// `PScanStartError::LoadFailed` mapping).
pub(crate) fn read_view_under_guard(
    engine: &Engine<SoloSigner>,
) -> Result<StakingReadView, WalletRpcError> {
    map_staking_read(tokio::task::block_in_place(|| {
        engine.stake().staking_read_view()
    }))
}

fn map_staking_read(
    result: Result<StakingReadView, shekyl_engine_core::StakingReadError>,
) -> Result<StakingReadView, WalletRpcError> {
    result.map_err(|e| {
        tracing::warn!(error = %e, "staking read view failed");
        WalletRpcError::InternalError("staking state failed to load".into())
    })
}

/// Map a loud [`shekyl_engine_core::BalanceViewError`] to `-32603`.
///
/// The client message is the error's own text, so
/// [`shekyl_engine_core::BalanceViewError::BondedLegs`] and
/// [`shekyl_engine_core::BalanceViewError::SealedTotals`] stay distinct.
/// An unreadable seal never reaches here: the engine degrades it to absent
/// staking fields, and the engine is the one that logs the loud arm.
pub(crate) fn map_balance_view(e: shekyl_engine_core::BalanceViewError) -> WalletRpcError {
    WalletRpcError::InternalError(e.to_string())
}

/// Acquire the engine read guard and compute the authoritative view.
async fn read_view(
    tenants: &tokio::sync::Mutex<TenantState>,
) -> Result<StakingReadView, WalletRpcError> {
    let shared = require_open_engine(tenants).await?;
    let engine = shared.read().await;
    read_view_under_guard(&engine)
}

/// Like [`read_view`], but also snapshots the parked lifecycle under the
/// tenant lock — before the engine guard, never nested.
///
/// The snapshot is the embedder's fact (`Tenant::serving_status`); it
/// does not belong on [`StakingReadView`]. Assembled here so
/// `staking_info` can project it without stuffing an embedder snapshot
/// into the engine's sealed-state aggregation. One value: a restart
/// cannot pair one lifecycle's posture with another's count.
async fn read_view_with_serving(
    tenants: &tokio::sync::Mutex<TenantState>,
) -> Result<(StakingReadView, Option<ServingStatus>), WalletRpcError> {
    let (shared, serving) = {
        let state = tenants.lock().await;
        let shared = state.tenant.engine().ok_or(WalletRpcError::WalletNotOpen)?;
        (shared, state.tenant.serving_status())
    };
    let engine = shared.read().await;
    Ok((read_view_under_guard(&engine)?, serving))
}

/// The wire pair from one [`ServingStatus`].
///
/// The count is absent exactly when no lifecycle is parked, the same
/// absence as a missing posture from a missing lifecycle. A parked
/// lifecycle that has not published a posture still carries a count, and
/// zero is that reading.
pub(crate) fn serving_wire(status: Option<ServingStatus>) -> (Option<String>, Option<u32>) {
    match status {
        None => (None, None),
        Some(status) => (
            posture_str(status.posture),
            Some(status.priority_not_lowered),
        ),
    }
}

/// The wire spelling of a serving posture — the contract's values,
/// produced in exactly one place so `staking_info` and `get_wallet_info`
/// cannot disagree about what a foundation node is called.
pub(crate) fn posture_str(posture: Option<ServingPosture>) -> Option<String> {
    match posture {
        Some(ServingPosture::Market) => Some("market".to_owned()),
        Some(ServingPosture::SupportCompleteTree) => Some("support_complete_tree".to_owned()),
        None => None,
    }
}

/// The `staking_info` block, projected once for both methods that carry it
/// (`staking_info` and `get_wallet_info`), so the two cannot disagree.
pub(crate) fn staking_info_result(
    view: &StakingReadView,
    serving: Option<ServingStatus>,
) -> StakingInfoResult {
    let (posture, serving_priority_not_lowered) = serving_wire(serving);
    StakingInfoResult {
        staking_enabled: view.staking_enabled,
        balance: balance_result(view),
        staked_output_count: i64::try_from(view.outputs.len()).unwrap_or(i64::MAX),
        pscan_synced_height: view.pscan_synced_height.map(height_wire).into(),
        recovery_pending_reopen: view.recovery_pending_reopen,
        in_flight: view.in_flight.iter().map(in_flight_entry).collect(),
        outcomes: view.outcomes.iter().map(outcome_entry).collect(),
        posture: posture.into(),
        serving_priority_not_lowered: serving_priority_not_lowered.into(),
    }
}

fn height_wire(h: BlockHeight) -> i64 {
    i64::try_from(h.to_raw()).unwrap_or(i64::MAX)
}

/// The wire name of a record kind. The exit is `exit` on the wire, as the
/// user calls it, not the `Release` the record is named for.
pub(crate) fn kind_wire(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::Post => "stake",
        RecordKind::Claim => "claim",
        RecordKind::Drain => "drain",
        RecordKind::Release => "exit",
    }
}

fn in_flight_entry(r: &InFlightRecord) -> InFlightEntry {
    let (state, funds_return_at) = match r.state {
        InFlightState::Pending => ("pending", None),
        InFlightState::Dispatched => ("dispatched", None),
        InFlightState::Refused {
            funds_return_at, ..
        } => ("refused", Some(funds_return_at)),
        InFlightState::Expired {
            funds_return_at, ..
        } => ("expired", Some(funds_return_at)),
        InFlightState::Held => ("held", None),
    };
    InFlightEntry {
        kind: kind_wire(r.kind).to_owned(),
        state: state.to_owned(),
        dispatched_at_height: r.sends.map(|s| height_wire(s.first_at_height)).into(),
        attempts: r.sends.map_or(0, |s| s.attempts),
        funds_return_at: funds_return_at.map(height_wire).into(),
        reason: r.state.reason().into(),
    }
}

fn outcome_entry(o: &ReportedOutcome) -> StakingOutcomeEntry {
    let outcome = match o.outcome {
        OutcomeKind::Rejected(_) => "rejected",
        OutcomeKind::Expired => "expired",
        OutcomeKind::EndedUnconfirmed(_) => "ended_unconfirmed",
        OutcomeKind::SpentElsewhere => "spent_elsewhere",
    };
    StakingOutcomeEntry {
        kind: kind_wire(o.kind).to_owned(),
        outcome: outcome.to_owned(),
        reason: o.reason(),
        at_height: height_wire(o.at_height),
        funds: if o.returned_funds() {
            "returned"
        } else {
            "none_held"
        }
        .to_owned(),
    }
}

fn balance_result(view: &StakingReadView) -> GetStakedBalanceResult {
    GetStakedBalanceResult {
        bonded_principal_confirmed: view.balance.bonded_principal_confirmed.into(),
        bonded_principal_pending: view.balance.bonded_principal_pending.into(),
        rewards_received_unspent: view.balance.rewards_received_unspent.into(),
    }
}

fn staked_output_view(o: &StakedOutput) -> StakedOutputView {
    StakedOutputView {
        gindex: o.gindex.to_raw().to_string(),
        amount: o.amount.into(),
        p_slot: i64::from(o.p_slot.to_raw()),
        unlock_height: i64::try_from(o.unlock_height.to_raw()).unwrap_or(i64::MAX),
        confirmed: o.confirmed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posture_str_is_the_contract_spelling() {
        assert_eq!(
            posture_str(Some(ServingPosture::Market)).as_deref(),
            Some("market")
        );
        assert_eq!(
            posture_str(Some(ServingPosture::SupportCompleteTree)).as_deref(),
            Some("support_complete_tree")
        );
        assert_eq!(posture_str(None), None);
    }

    #[test]
    fn serving_wire_is_absent_only_when_no_lifecycle_is_parked() {
        assert_eq!(serving_wire(None), (None, None));
        assert_eq!(
            serving_wire(Some(ServingStatus {
                posture: None,
                priority_not_lowered: 0,
            })),
            (None, Some(0)),
            "a parked lifecycle that has not published a posture still has a count"
        );
        assert_eq!(
            serving_wire(Some(ServingStatus {
                posture: Some(ServingPosture::Market),
                priority_not_lowered: 3,
            })),
            (Some("market".to_owned()), Some(3))
        );
    }

    #[test]
    fn balance_overflows_keep_their_client_messages() {
        use shekyl_engine_core::BalanceViewError;
        for err in [BalanceViewError::BondedLegs, BalanceViewError::SealedTotals] {
            let mapped = map_balance_view(err);
            assert!(
                matches!(mapped, WalletRpcError::InternalError(ref message) if message == &err.to_string()),
                "{err:?} must reach the client as its own text, got {mapped:?}"
            );
        }
    }
}
