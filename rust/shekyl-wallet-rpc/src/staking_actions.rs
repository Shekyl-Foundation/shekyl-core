// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Archival principal staking **actions**: WI-RPC-5's `stake_in`,
//! `get_drain_balance`, `drain`, and PR-C's exit pair `unstake` /
//! `collect_unstaked`.
//!
//! Its own module rather than growth on [`crate::staking`] (which stays the
//! read-only projection surface): every method here moves money or reads the
//! value-out leg, and their params discipline is the F-1 pin — every params
//! struct here carries `#[serde(deny_unknown_fields)]`, so a client sending
//! `fee` / `destination` / `p_slot` next to `amount` gets `-32602` instead of
//! having the extra key silently dropped. That rejection is the *actual
//! enforcement* of the contract's `additionalProperties: false`; the yaml
//! alone enforces nothing.
//!
//! GF-7 disclosure (`stake_in`): the funding transfer appends the
//! principal's own change output co-present with the `P`-output in the same
//! tx — an open linkage question shipped with a disclosure warning (the
//! contract description and the CLI pre-confirm print carry it), not
//! resolved here. Carrier: the bond-funding-separation work, per
//! `docs/FOLLOWUPS.md`.

use serde::Deserialize;
use serde_json::Value;
use shekyl_engine_core::{
    CollectOutcome, DrainBalanceReadError, DrainOutcome, StakeFacade, UnstakeOutcome,
};

use crate::error::WalletRpcError;
use crate::params::{parse_atomic_units, parse_optional_object, parse_required_object};
use crate::project::{atomic_units_string, pending_tx_result};
use crate::tenant::{require_open_engine, TenantState};
use crate::types::{
    CollectUnstakedResult, DrainResult, DrainVerdictView, GetDrainBalanceResult, UnstakeResult,
};

/// Params for `stake_in`: `{ amount }` only. The `P` receive address is
/// engine-derived (never on the wire) and the cover is system-drawn (never a
/// parameter); unknown keys are `-32602` (F-1).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StakeInParams {
    /// Decimal atomic-units string — the stake amount, before the
    /// system-drawn cover.
    amount: String,
}

/// Params for `drain`: `{ amount }` only — **no `fee`, no `destination`, no
/// `p_slot`**, and `deny_unknown_fields` is what makes those absences
/// enforced rather than prose (F-1). The fee is the canonical P-lane floor
/// quoted inside the Engine, the destination is engine-pinned to this
/// wallet's primary address (T-DS-3), and the persona is the live active
/// persona resolved from actor state.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainParams {
    /// Decimal atomic-units string — the payment (user intent, F-D2: never
    /// pre-filled from a reward vector).
    amount: String,
}

/// Params for `get_drain_balance`: none. Deserialized through serde (rather
/// than `require_empty_object`) so the rejection mechanism is the same
/// `deny_unknown_fields` gate the other two methods use.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetDrainBalanceParams {}

/// `stake_in` — fund the active persona's staking balance with an ordinary
/// principal→`P` transfer. Returns the same `BuildPendingTxResult` shape as
/// `build_pending_tx`: the client confirms and fires it through the existing
/// `submit_pending_tx` / `discard_pending_tx` lifecycle (it **is** a
/// principal transfer; no parallel submit path).
pub(crate) async fn stake_in(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: StakeInParams = parse_required_object(params, "stake_in")?;
    let amount = parse_atomic_units(&p.amount)?;

    let shared = require_open_engine(tenants).await?;
    // Read guard, exactly like `build_pending_tx`'s W-B step-1 build (which
    // IS this call's body after the address projection): the slow FCMP++
    // assembly is serialized by the pending-tx implementor's own permit, so
    // concurrent read RPCs (`get_balance` polls, `get_height`) proceed while
    // the funding build runs. A write guard here would queue every reader
    // behind a daemon round trip + proving build — tokio's RwLock is FIFO,
    // so one `stake_in` would hang the whole read surface — for exclusivity
    // that binds nothing (`Engine::stake_in` is `&self`).
    let engine = shared.read().await;
    let pending = engine.stake().stake_in(amount).await?;
    let result = pending_tx_result(&pending);
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize stake_in: {e}")))
}

/// `get_drain_balance` — the aggregate drainable `P` scalar, **scoped to
/// the live active persona** (the same slot-scoped set `drain` can spend,
/// so the advertised figure is affordable by construction), two-armed
/// (F-D2 / rule 82): `ready` with the amount, or `syncing` with a
/// scalar-free detail — **never `"0"` while syncing**. A non-staker, an
/// idle staker (no active persona — `drain` would refuse `-29508`), or a
/// staker that has scanned nothing is an honest `ready` zero: nothing is
/// drainable right now, which is a true answer, not a placeholder.
pub(crate) async fn get_drain_balance(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let _p: GetDrainBalanceParams = parse_optional_object(params, "get_drain_balance")?;

    let shared = require_open_engine(tenants).await?;
    let result = drain_balance_result(StakeFacade::drain_balance_aggregate(shared).await)?;
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_drain_balance: {e}")))
}

/// Map the engine's aggregate-read outcome onto the two-armed wire contract
/// — a pure function so the fail-closed arm is unit-testable (the corrupt
/// seal that produces a real `State` error is not constructible through the
/// HTTP fixture).
///
/// The `State` arm **fails closed** (an error, never a zero): collapsing it
/// to `Ready { spendable: "0" }` would render a corrupt read as a plausible
/// drained-to-zero balance — the exact fail-open F-D2/rule 82 forbids.
/// Category-only on the wire; the engine's rendering is public text but
/// stays in the server log like every other internal fault.
fn drain_balance_result(
    outcome: Result<shekyl_units::AtomicUnits, DrainBalanceReadError>,
) -> Result<GetDrainBalanceResult, WalletRpcError> {
    match outcome {
        Ok(spendable) => Ok(GetDrainBalanceResult::Ready {
            spendable: atomic_units_string(spendable),
        }),
        Err(DrainBalanceReadError::Unanchorable { detail }) => Ok(GetDrainBalanceResult::Syncing {
            detail: detail.to_owned(),
        }),
        Err(DrainBalanceReadError::State { detail }) => {
            tracing::warn!(detail = %detail, "drain balance read failed");
            Err(WalletRpcError::InternalError(
                "drain balance read failed".into(),
            ))
        }
    }
}

/// `drain` — move `amount` from the live active persona's staking pool back
/// to this wallet's own principal balance. Seals before it sends
/// (persist-then-dispatch) and submits in the same call; there is no
/// confirm step, and the one-live-drain seal (`-29511`) is the in-flight
/// brake.
pub(crate) async fn drain(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: DrainParams = parse_required_object(params, "drain")?;
    let payment = parse_atomic_units(&p.amount)?;
    // A zero drain is a malformed request, refused at the params boundary
    // (`-32602`) before the wallet gate or any engine/daemon work. Folding
    // it into `-29101` would hand out an unsatisfiable remedy ("lower the
    // payment" has no answer at zero — rule 82); the engine façade carries
    // its own `EmptyRequest` arm for direct embedder callers. `stake_in`
    // deliberately has NO such check: a zero stake is designed-valid (DQ1,
    // no floor), and the shared `parse_atomic_units` must keep accepting
    // `"0"` for it.
    if payment.is_zero() {
        return Err(WalletRpcError::InvalidParams(
            "the drain amount must be greater than zero".into(),
        ));
    }

    let shared = require_open_engine(tenants).await?;
    let outcome = StakeFacade::drain_to_principal(shared, payment).await?;
    let result = drain_result(&outcome);
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize drain: {e}")))
}

/// Project a sealed-then-dispatched submit onto the OpenAPI `DrainResult`
/// shape — shared by `drain` and `unstake` so the two receipts cannot
/// drift (`confirmed_height` present iff `ALREADY_IN_CHAIN`).
fn sealed_submit_result(tx_hash: String, height: Option<u64>) -> DrainResult {
    match height {
        None => DrainResult {
            tx_hash,
            verdict: DrainVerdictView::Broadcast,
            confirmed_height: None,
        },
        Some(h) => DrainResult {
            tx_hash,
            verdict: DrainVerdictView::AlreadyInChain,
            confirmed_height: Some(i64::try_from(h).unwrap_or(i64::MAX)),
        },
    }
}

/// Project the Engine's [`DrainOutcome`] onto the OpenAPI `DrainResult`
/// shape — same field discipline as `submit_pending_tx_result`.
fn drain_result(outcome: &DrainOutcome) -> DrainResult {
    match outcome {
        DrainOutcome::Broadcast { tx_hash } => sealed_submit_result(tx_hash.to_string(), None),
        DrainOutcome::AlreadyInChain { tx_hash, height } => {
            sealed_submit_result(tx_hash.to_string(), Some(*height))
        }
    }
}

/// Params for `unstake` and `collect_unstaked`: none. The wire never names
/// a slot, a fee, or a destination — both verbs resolve their persona
/// engine-side (the `first_stake` precedent) — and `deny_unknown_fields`
/// is what makes those absences enforced rather than prose (F-1): a client
/// steering with `p_slot` / `amount` / `fee` gets `-32602`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExitParams {}

/// `unstake` — post the terminal exit for the first live-bonded persona.
/// **The irreversible step**: once the exit connects, the bond debits to
/// zero and the persona can never re-bond on this record. The CLI carries
/// the confirmation prompt (prompts are CLI-side, not RPC-side); this
/// method fires on call.
pub(crate) async fn unstake(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let _p: ExitParams = parse_optional_object(params, "unstake")?;

    // One short tenant hold for both the engine handle and the embedder's
    // daemon endpoint (the exit's record fetch rides the ① local-posture
    // transport built from it — the serving-start shape).
    let (shared, daemon_address) = {
        let state = tenants.lock().await;
        let shared = state.tenant.engine().ok_or(WalletRpcError::WalletNotOpen)?;
        (shared, state.daemon.address.clone())
    };
    let outcome = StakeFacade::unstake(shared, &daemon_address).await?;
    let result: UnstakeResult = match outcome {
        UnstakeOutcome::Broadcast { tx_hash } => sealed_submit_result(tx_hash.to_string(), None),
        UnstakeOutcome::AlreadyInChain { tx_hash, height } => {
            sealed_submit_result(tx_hash.to_string(), Some(height))
        }
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize unstake: {e}")))
}

/// `collect_unstaked` — sweep one pass of the released exit collateral to
/// this wallet's principal. The reply carries the two-part completion fact
/// (see [`CollectUnstakedResult`]); `NOTHING_LEFT` means the collection
/// is already complete and the funded-gated retirement proceeds on its own.
pub(crate) async fn collect_unstaked(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let _p: ExitParams = parse_optional_object(params, "collect_unstaked")?;

    let shared = require_open_engine(tenants).await?;
    let outcome = StakeFacade::collect_unstaked(shared).await?;
    let result = match outcome {
        CollectOutcome::Swept {
            tx_hash,
            swept,
            remainder,
            another_pool_remains,
        } => CollectUnstakedResult::Swept {
            tx_hash: tx_hash.to_string(),
            swept: atomic_units_string(swept),
            remainder: atomic_units_string(remainder),
            another_pool_remains,
        },
        CollectOutcome::NothingLeft => CollectUnstakedResult::NothingLeft,
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize collect_unstaked: {e}")))
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use shekyl_types::TxHash;

    use super::*;

    /// The F-1 pin, at the deserializer (the actual enforcement): an extra
    /// key is a params error, never silently dropped. This bites against
    /// removing `deny_unknown_fields` from any params struct here; the HTTP
    /// suite covers the same property end-to-end with the wire `-32602`
    /// code. The exit pair is in scope: a `p_slot` / `amount` / `fee` on
    /// `unstake` or `collect_unstaked` is the anti-shape this PR refuses.
    #[test]
    fn extra_params_are_rejected_not_dropped() {
        for (method, bad) in [
            ("stake_in", json!({ "amount": "5", "fee": "1" })),
            ("drain", json!({ "amount": "5", "destination": "shekyl1x" })),
            ("drain", json!({ "amount": "5", "p_slot": 3 })),
            ("drain", json!({ "amount": "5", "fee": "1" })),
        ] {
            let err = if method == "stake_in" {
                parse_required_object::<StakeInParams>(&bad, method).expect_err("must reject")
            } else {
                parse_required_object::<DrainParams>(&bad, method).expect_err("must reject")
            };
            assert!(
                matches!(err, WalletRpcError::InvalidParams(_)),
                "{method} {bad}: {err:?}"
            );
        }

        let err = parse_optional_object::<GetDrainBalanceParams>(
            &json!({ "p_slot": 1 }),
            "get_drain_balance",
        )
        .expect_err("must reject");
        assert!(matches!(err, WalletRpcError::InvalidParams(_)));

        for (method, bad) in [
            ("unstake", json!({ "p_slot": 1 })),
            ("unstake", json!({ "amount": "5" })),
            ("unstake", json!({ "fee": "1" })),
            ("collect_unstaked", json!({ "p_slot": 1 })),
            ("collect_unstaked", json!({ "amount": "5" })),
            ("collect_unstaked", json!({ "fee": "1" })),
        ] {
            let err = parse_optional_object::<ExitParams>(&bad, method).expect_err("must reject");
            assert!(
                matches!(err, WalletRpcError::InvalidParams(_)),
                "{method} {bad}: {err:?}"
            );
        }

        // And the well-formed shapes still parse.
        parse_required_object::<StakeInParams>(&json!({ "amount": "5" }), "stake_in")
            .expect("well-formed stake_in params");
        parse_required_object::<DrainParams>(&json!({ "amount": "5" }), "drain")
            .expect("well-formed drain params");
        parse_optional_object::<GetDrainBalanceParams>(&Value::Null, "get_drain_balance")
            .expect("omitted get_drain_balance params");
        parse_optional_object::<ExitParams>(&Value::Null, "unstake")
            .expect("omitted unstake params");
        parse_optional_object::<ExitParams>(&json!({}), "collect_unstaked")
            .expect("empty collect_unstaked params");
    }

    /// The two result arms serialize to the contract's tagged shapes: the
    /// ready arm carries `spendable` and no `detail`; the syncing arm
    /// carries `detail` and **no `spendable`** — there is structurally no
    /// way to render a `"0"` beside `syncing` (rule 82 / F-D2).
    #[test]
    fn drain_balance_result_arms_match_the_contract_shapes() {
        let ready = serde_json::to_value(GetDrainBalanceResult::Ready {
            spendable: "12345".into(),
        })
        .expect("serialize");
        assert_eq!(ready, json!({ "status": "ready", "spendable": "12345" }));

        let syncing = serde_json::to_value(GetDrainBalanceResult::Syncing {
            detail: "curve-tree ingest behind the anchor age".into(),
        })
        .expect("serialize");
        assert_eq!(syncing["status"], "syncing");
        assert!(syncing.get("spendable").is_none(), "{syncing}");
    }

    /// `confirmed_height` is present iff the verdict is `ALREADY_IN_CHAIN` —
    /// the same field discipline as `submit_pending_tx`.
    #[test]
    fn drain_result_confirmed_height_tracks_the_verdict() {
        let hash = TxHash::from_bytes([0xab; 32]);

        let broadcast =
            serde_json::to_value(drain_result(&DrainOutcome::Broadcast { tx_hash: hash }))
                .expect("serialize");
        assert_eq!(broadcast["verdict"], "BROADCAST");
        assert_eq!(broadcast["tx_hash"], "ab".repeat(32));
        assert!(broadcast.get("confirmed_height").is_none());

        let in_chain = serde_json::to_value(drain_result(&DrainOutcome::AlreadyInChain {
            tx_hash: hash,
            height: 4242,
        }))
        .expect("serialize");
        assert_eq!(in_chain["verdict"], "ALREADY_IN_CHAIN");
        assert_eq!(in_chain["confirmed_height"], 4242);
    }

    /// `CollectUnstakedResult` is internally tagged like
    /// `GetDrainBalanceResult`: SWEPT carries its four required fields —
    /// neither half of the completion fact is optional (a missing
    /// `remainder` OR a missing `another_pool_remains` cannot deserialize,
    /// so neither the per-slot nor the lane-wide claim can be forged by
    /// omission) — and NOTHING_LEFT carries only the tag.
    #[test]
    fn collect_unstaked_result_arms_match_the_contract_shapes() {
        let swept = serde_json::to_value(CollectUnstakedResult::Swept {
            tx_hash: "ab".repeat(32),
            swept: "100".into(),
            remainder: "0".into(),
            another_pool_remains: true,
        })
        .expect("serialize");
        assert_eq!(swept["status"], "SWEPT");
        assert_eq!(swept["remainder"], "0");
        assert_eq!(swept["another_pool_remains"], true);
        assert!(swept.get("tx_hash").is_some());

        let empty = serde_json::from_value::<CollectUnstakedResult>(json!({
            "status": "SWEPT",
            "tx_hash": "ab".repeat(32),
            "swept": "100",
            "another_pool_remains": false
        }));
        assert!(
            empty.is_err(),
            "SWEPT without remainder must not deserialize: {empty:?}"
        );
        let no_lane = serde_json::from_value::<CollectUnstakedResult>(json!({
            "status": "SWEPT",
            "tx_hash": "ab".repeat(32),
            "swept": "100",
            "remainder": "0"
        }));
        assert!(
            no_lane.is_err(),
            "SWEPT without another_pool_remains must not deserialize — a \
             per-slot 0 alone must not read as lane-wide completion: {no_lane:?}"
        );

        let done = serde_json::to_value(CollectUnstakedResult::NothingLeft).expect("serialize");
        assert_eq!(done, json!({ "status": "NOTHING_LEFT" }));
    }

    /// The engine outcome → wire mapping, all three arms — in particular the
    /// fail-closed `State` arm: a non-transient read fault answers `-32603`,
    /// NEVER `Ready {"0"}` (the fail-open would render a corrupt read as a
    /// plausible drained-to-zero balance — F-D2 / rule 82). Unit-level
    /// because a real corrupt seal is not constructible through the HTTP
    /// fixture; the arm was previously only hand-described in a comment.
    #[test]
    fn drain_balance_outcome_maps_ready_syncing_and_fail_closed() {
        use shekyl_engine_core::DrainBalanceReadError;
        use shekyl_units::AtomicUnits;

        let ready = drain_balance_result(Ok(AtomicUnits::from_raw(42_000))).expect("ready");
        assert!(matches!(
            &ready,
            GetDrainBalanceResult::Ready { spendable } if spendable == "42000"
        ));

        let syncing = drain_balance_result(Err(DrainBalanceReadError::Unanchorable {
            detail: "curve-tree ingest behind the anchor age",
        }))
        .expect("syncing is a result arm, not an error");
        assert!(matches!(&syncing, GetDrainBalanceResult::Syncing { .. }));

        let err = drain_balance_result(Err(DrainBalanceReadError::State {
            detail: "seal version refused".into(),
        }))
        .expect_err("a state fault must fail closed, never render a zero");
        assert!(matches!(err, WalletRpcError::InternalError(_)), "{err:?}");
    }
}
