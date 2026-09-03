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
//! `get_balance` / `get_wallet_info` snapshot-then-read through
//! [`ledger_snapshot_with_staking`] — nested `ledger.read()` under a live
//! [`shekyl_engine_core::LedgerReadGuard`] deadlocks, so the guard-drop
//! choreography lives in that one helper.

use serde::Deserialize;
use serde_json::Value;
use shekyl_engine_core::{Engine, ServingPosture, SoloSigner, StakedOutput, StakingReadView};
use shekyl_scanner::WalletLedgerExt as _;

use crate::error::WalletRpcError;
use crate::params::{parse_optional_object, require_empty_object};
use crate::project::atomic_units_string;
use crate::tenant::{require_open_engine, TenantState};
use crate::types::{
    GetStakedBalanceResult, GetStakedOutputsResult, StakedOutputView, StakingInfoResult,
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
    let (view, posture) = read_view_with_posture(tenants).await?;
    let result = StakingInfoResult {
        staking_enabled: view.staking_enabled,
        balance: balance_result(&view),
        staked_output_count: i64::try_from(view.outputs.len()).unwrap_or(i64::MAX),
        pscan_synced_height: view
            .pscan_synced_height
            .map(|h| i64::try_from(h.to_raw()).unwrap_or(i64::MAX)),
        recovery_pending_reopen: view.recovery_pending_reopen,
        posture: posture_str(posture),
    };
    serde_json::to_value(result)
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
/// [`read_view_with_snapshot`] instead (`get_wallet_info` is the exemplar).
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

/// Like [`read_view_under_guard`], but uses a caller-supplied ledger
/// snapshot so the sealed-file path never re-enters the ledger lock.
///
/// `get_wallet_info` snapshots the flags under its ledger guard, drops that
/// guard, then calls this — keeping the bits coherent with the rest of
/// the aggregate without nesting `RwLock` reads.
///
/// Returns the engine's own [`StakingReadError`] rather than a mapped
/// [`WalletRpcError`]: the sole caller ([`ledger_snapshot_with_staking`])
/// classifies the variants — an unreadable seal degrades, a corrupt total
/// answers loud — and that split needs the variant, which the mapped form
/// erases.
///
/// [`StakingReadError`]: shekyl_engine_core::StakingReadError
fn read_view_with_snapshot(
    engine: &Engine<SoloSigner>,
    staking_enabled: bool,
    recovery_pending_reopen: bool,
) -> Result<StakingReadView, shekyl_engine_core::StakingReadError> {
    tokio::task::block_in_place(|| {
        engine
            .stake()
            .staking_read_view_with_snapshot(staking_enabled, recovery_pending_reopen)
    })
}

fn map_staking_read(
    result: Result<StakingReadView, shekyl_engine_core::StakingReadError>,
) -> Result<StakingReadView, WalletRpcError> {
    result.map_err(|e| {
        tracing::warn!(error = %e, "staking read view failed");
        WalletRpcError::InternalError("staking state failed to load".into())
    })
}

/// Classify a staking read for the **degrading** callers (`get_balance`,
/// `get_wallet_info`): which failures may be answered with structurally
/// absent staking fields, and which must fail the request loudly.
///
/// - [`File`] / [`Codec`]: the seal could not be opened or decoded — the
///   degrade arm. The wire contract defines absence as "the sealed staking
///   state could not be read", and that is literally what happened.
/// - [`Overflow`]: the seal **loaded** — its monetary totals overflowed the
///   money type. That is corrupt-loud territory (`project.rs`'s pin on
///   `get_balance_result`: deliberately NOT folded into the degrade arm);
///   rendering it as absence would misreport a corrupt-but-readable seal as
///   an unreadable one. Answers `-32603` with a detail-free client message.
///
/// Pure so the classification is unit-testable; the non-degrading staking
/// methods (`get_staked_balance`, `staking_info`) keep [`map_staking_read`],
/// which answers every arm loud.
///
/// [`File`]: shekyl_engine_core::StakingReadError::File
/// [`Codec`]: shekyl_engine_core::StakingReadError::Codec
/// [`Overflow`]: shekyl_engine_core::StakingReadError::Overflow
fn degrade_or_loud(
    result: Result<StakingReadView, shekyl_engine_core::StakingReadError>,
) -> Result<Option<StakingReadView>, WalletRpcError> {
    use shekyl_engine_core::StakingReadError;
    match result {
        Ok(view) => Ok(Some(view)),
        Err(e @ (StakingReadError::File(_) | StakingReadError::Codec(_))) => {
            tracing::warn!(error = %e, "staking read view failed; degrading staking fields");
            Ok(None)
        }
        Err(e @ StakingReadError::Overflow) => {
            tracing::warn!(error = %e, "staking read view corrupt");
            Err(WalletRpcError::InternalError(
                "staking totals overflowed the money type (corrupt staking state)".into(),
            ))
        }
    }
}

/// One-guard ledger snapshot + sealed staking read, in the only safe order —
/// the shared choreography `get_balance` and `get_wallet_info` both need:
///
/// 1. snapshot the balance summary, `staking_enabled`, and the caller's
///    `under_guard` extras under ONE ledger read guard (coherent snapshot);
/// 2. **drop that guard** — `staking_read_view*` takes its own brief
///    `ledger.read()`, and nesting it under a live guard deadlocks the
///    non-reentrant `std::sync::RwLock`;
/// 3. read the session-adoption flag and the sealed staking view.
///
/// One body rather than a per-handler copy of the sequence: the guard-drop
/// step is the load-bearing line the type system cannot enforce, so it lives
/// exactly once. `under_guard` runs while the ledger guard is live, so a
/// caller's extra fields (heights, flags) stay coherent with the summary;
/// `get_balance` passes `|_| ()`.
///
/// The staking view comes back as an `Option`, classified by
/// [`degrade_or_loud`]: `None` means the seal could not be read
/// (file/codec — logged server-side) and the caller **degrades** — liquid
/// fields stay served, staking projections go structurally absent. Never
/// `-32603` over the whole balance surface for an unreadable staking seal,
/// and never zeros over a bad seal (the engine's fail-closed pin: absence
/// is distinct from `"0"`). A seal that *loaded* but overflowed a money
/// total is the one staking-side fault that IS `-32603` (this function's
/// `Err`): that seal was readable, so absence would misdescribe it, and a
/// corrupt total must fail loud (`project.rs`'s corrupt-loud pin).
pub(crate) fn ledger_snapshot_with_staking<T>(
    engine: &Engine<SoloSigner>,
    under_guard: impl FnOnce(&shekyl_engine_state::WalletLedger) -> T,
) -> Result<(shekyl_scanner::BalanceSummary, T, Option<StakingReadView>), WalletRpcError> {
    let (summary, staking_enabled, extra) = {
        let wallet = engine.ledger();
        (
            wallet.balance(),
            wallet.staking.staking_enabled,
            under_guard(&wallet),
        )
    };
    // Guard dropped above (non-reentrant lock): the session-adoption flag
    // takes its own brief ledger read, then the sealed-file staking read.
    let recovery_pending_reopen = engine.stake().staking_recovery_pending_reopen();
    let staking = degrade_or_loud(read_view_with_snapshot(
        engine,
        staking_enabled,
        recovery_pending_reopen,
    ))?;
    Ok((summary, extra, staking))
}

/// Acquire the engine read guard and compute the authoritative view.
async fn read_view(
    tenants: &tokio::sync::Mutex<TenantState>,
) -> Result<StakingReadView, WalletRpcError> {
    let shared = require_open_engine(tenants).await?;
    let engine = shared.read().await;
    read_view_under_guard(&engine)
}

/// Like [`read_view`], but also snapshots the parked host's posture
/// under the tenant lock — before the engine guard, never nested.
///
/// The posture is the embedder's fact (`Tenant::serving_posture`); it
/// does not belong on [`StakingReadView`]. Assembled here so
/// `staking_info` can project it without stuffing an embedder snapshot
/// into the engine's sealed-state aggregation.
async fn read_view_with_posture(
    tenants: &tokio::sync::Mutex<TenantState>,
) -> Result<(StakingReadView, Option<ServingPosture>), WalletRpcError> {
    let (shared, posture) = {
        let state = tenants.lock().await;
        let shared = state.tenant.engine().ok_or(WalletRpcError::WalletNotOpen)?;
        (shared, state.tenant.serving_posture())
    };
    let engine = shared.read().await;
    Ok((read_view_under_guard(&engine)?, posture))
}

/// The wire spelling of a serving posture — the contract's values,
/// produced in exactly one place so `staking_info` and `get_wallet_info`
/// cannot disagree about what a foundation node is called.
pub(crate) fn posture_str(posture: Option<ServingPosture>) -> Option<String> {
    match posture {
        Some(ServingPosture::Market) => Some("market".to_owned()),
        Some(ServingPosture::FoundationCompleteTree) => Some("foundation_complete_tree".to_owned()),
        None => None,
    }
}

fn balance_result(view: &StakingReadView) -> GetStakedBalanceResult {
    GetStakedBalanceResult {
        bonded_principal_confirmed: atomic_units_string(view.balance.bonded_principal_confirmed),
        bonded_principal_pending: atomic_units_string(view.balance.bonded_principal_pending),
        rewards_received_unspent: atomic_units_string(view.balance.rewards_received_unspent),
    }
}

fn staked_output_view(o: &StakedOutput) -> StakedOutputView {
    StakedOutputView {
        gindex: o.gindex.to_raw().to_string(),
        amount: atomic_units_string(o.amount),
        p_slot: i64::from(o.p_slot.to_raw()),
        unlock_height: i64::try_from(o.unlock_height.to_raw()).unwrap_or(i64::MAX),
        confirmed: o.confirmed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_engine_core::{StakedBalance, StakingReadError};

    // ---- degrade_or_loud: the degrade/loud split for the balance surface ---

    #[test]
    fn readable_view_passes_through_the_degrade_classifier() {
        let view = StakingReadView {
            staking_enabled: false,
            balance: StakedBalance::ZERO,
            outputs: vec![],
            pscan_synced_height: None,
            recovery_pending_reopen: false,
        };
        let classified = degrade_or_loud(Ok(view)).expect("Ok is never loud");
        assert!(classified.is_some(), "a readable view must project");
    }

    #[test]
    fn unreadable_seal_degrades_to_absence() {
        // File / codec: the seal could not be READ — exactly what the wire
        // contract defines absence to mean. Degrade, never -32603.
        let unreadable = StakingReadError::File(shekyl_engine_file::WalletFileError::Io(
            std::io::Error::other("disk gone"),
        ));
        let classified = degrade_or_loud(Err(unreadable)).expect("an unreadable seal degrades");
        assert!(classified.is_none(), "degrade arm is structural absence");
    }

    #[test]
    fn overflow_is_loud_never_the_degrade_arm() {
        // The seal LOADED but a money total overflowed: corrupt-loud
        // (project.rs pin). Absence would misreport a corrupt-but-readable
        // seal as an unreadable one.
        let err = degrade_or_loud(Err(StakingReadError::Overflow))
            .expect_err("a corrupt total must fail the request");
        assert!(
            matches!(err, WalletRpcError::InternalError(_)),
            "expected -32603 InternalError, got {err:?}"
        );
    }

    #[test]
    fn posture_str_is_the_contract_spelling() {
        assert_eq!(
            posture_str(Some(ServingPosture::Market)).as_deref(),
            Some("market")
        );
        assert_eq!(
            posture_str(Some(ServingPosture::FoundationCompleteTree)).as_deref(),
            Some("foundation_complete_tree")
        );
        assert_eq!(posture_str(None), None);
    }
}
