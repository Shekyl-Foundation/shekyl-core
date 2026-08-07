// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! JSON-RPC 2.0 wire types conforming to `docs/api/wallet_rpc.yaml`.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use shekyl_engine_core::Capability;

use crate::error::WalletRpcError;

/// Monotonic API contract version. Pre-genesis this stays `1` — incompatible
/// changes are atomic cutovers, not versioned skew (rule 16 user-absent
/// context inversion; `GetVersionResult.api_version` in the OpenAPI spec).
pub const API_VERSION: u32 = 1;

/// Incoming JSON-RPC 2.0 request (validated against the OpenAPI contract).
#[derive(Debug, Clone)]
pub struct JsonRpcRequest {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// Client-supplied id: string or integer only (OpenAPI `oneOf`).
    pub id: Value,
    /// Method name.
    pub method: String,
    /// Per-method params object; `null` when omitted.
    pub params: Value,
}

/// Outgoing JSON-RPC 2.0 response. Exactly one of `result` / `error` is set
/// (JSON-RPC 2.0 §5).
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    /// Always `"2.0"`.
    pub jsonrpc: &'static str,
    /// Echo of the request id, or `null` when the request id was absent /
    /// invalid (JSON-RPC 2.0 §5 / §5.1).
    pub id: Value,
    /// Success payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcErrorBody>,
}

/// JSON-RPC `error` object.
#[derive(Debug, Serialize)]
pub struct JsonRpcErrorBody {
    /// Allocated code from `WalletRpcErrorCode`.
    pub code: i32,
    /// Human-readable summary (no secrets / amounts / counterparty addresses).
    pub message: String,
    /// Optional structured detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcResponse {
    /// Build a success response.
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Build an error response from a [`WalletRpcError`].
    pub fn from_error(id: Value, err: &WalletRpcError) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(JsonRpcErrorBody {
                code: err.code().as_i32(),
                message: err.message(),
                data: err.data(),
            }),
        }
    }

    /// `-32700` parse error (invalid JSON syntax). Always `id: null`.
    pub fn parse_error() -> Self {
        Self::from_error(Value::Null, &WalletRpcError::ParseError)
    }
}

impl JsonRpcRequest {
    /// Validate a parsed JSON value as a JSON-RPC request.
    ///
    /// On failure returns `(response_id, error)` where `response_id` is the
    /// request's id when it was a valid string/integer, otherwise `null`
    /// (JSON-RPC 2.0 §5.1 — do not echo an invalid id).
    pub fn try_from_value(value: Value) -> Result<Self, (Value, WalletRpcError)> {
        let Value::Object(map) = value else {
            return Err((
                Value::Null,
                WalletRpcError::InvalidRequest("request must be a JSON object".into()),
            ));
        };

        let response_id = extract_valid_id(&map).unwrap_or(Value::Null);

        let jsonrpc = match map.get("jsonrpc") {
            Some(Value::String(s)) if s == "2.0" => s.clone(),
            Some(Value::String(_)) => {
                return Err((
                    response_id,
                    WalletRpcError::InvalidRequest("jsonrpc must be \"2.0\"".into()),
                ));
            }
            Some(_) => {
                return Err((
                    response_id,
                    WalletRpcError::InvalidRequest("jsonrpc must be a string".into()),
                ));
            }
            None => {
                return Err((
                    response_id,
                    WalletRpcError::InvalidRequest("missing jsonrpc".into()),
                ));
            }
        };

        // OpenAPI requires `id`. Absent → invalid request with id:null.
        // Present but wrong type → invalid request with id:null (do not echo).
        let id = match map.get("id") {
            None => {
                return Err((
                    Value::Null,
                    WalletRpcError::InvalidRequest("missing id".into()),
                ));
            }
            Some(v) if is_valid_request_id(v) => v.clone(),
            Some(_) => {
                return Err((
                    Value::Null,
                    WalletRpcError::InvalidRequest("id must be a string or integer".into()),
                ));
            }
        };

        let method = match map.get("method") {
            Some(Value::String(s)) if !s.is_empty() => s.clone(),
            Some(Value::String(_)) => {
                return Err((
                    id,
                    WalletRpcError::InvalidRequest("method must be non-empty".into()),
                ));
            }
            Some(_) => {
                return Err((
                    id,
                    WalletRpcError::InvalidRequest("method must be a string".into()),
                ));
            }
            None => {
                return Err((id, WalletRpcError::InvalidRequest("missing method".into())));
            }
        };

        let params = map.get("params").cloned().unwrap_or(Value::Null);

        Ok(Self {
            jsonrpc,
            id,
            method,
            params,
        })
    }
}

/// OpenAPI / JSON-RPC request `id`: string or integer (not float, bool,
/// null, object, or array).
fn is_valid_request_id(v: &Value) -> bool {
    match v {
        Value::String(_) => true,
        Value::Number(n) => n.is_i64() || n.is_u64(),
        _ => false,
    }
}

fn extract_valid_id(map: &Map<String, Value>) -> Option<Value> {
    map.get("id").filter(|v| is_valid_request_id(v)).cloned()
}

/// `get_version` result (`GetVersionResult` in the OpenAPI spec).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetVersionResult {
    /// `shekyl-wallet-rpc` semver.
    pub version: String,
    /// Monotonic API contract version (see [`API_VERSION`]).
    pub api_version: u32,
}

/// OpenAPI `CapabilityMode` for FULL wallets (Phase 4b create/open).
pub const CAPABILITY_FULL: &str = "FULL";

/// Map an Engine [`Capability`] to its OpenAPI `CapabilityMode` string.
///
/// Single source of truth for the `WalletHandle.capability` response field and
/// the `CapabilityForbids` (`-29005`) `error.data.capability` field, so the two
/// never disagree when a new capability variant lands.
pub fn capability_mode_str(cap: Capability) -> &'static str {
    match cap {
        Capability::Full => CAPABILITY_FULL,
        Capability::ViewOnly => "VIEW_ONLY",
        Capability::HardwareOffload => "HARDWARE_OFFLOAD",
    }
}

/// `WalletHandle` returned by lifecycle methods that leave a wallet open.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletHandle {
    /// Wallet file stem within the served wallet directory.
    pub name: String,
    /// Capability mode (`FULL` / `VIEW_ONLY` / `HARDWARE_OFFLOAD`).
    pub capability: String,
    /// Network (`MAINNET` / `TESTNET` / `STAGENET`).
    pub network: String,
    /// Present when open reconstructed state from `restore_height_hint`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restore_height_hint: Option<i64>,
}

/// Atomic-units amount as a decimal string (OpenAPI `AtomicUnits`).
pub type AtomicUnitsString = String;

/// `get_balance` result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetBalanceResult {
    /// Spendable liquid balance (maps from unlocked until staking lands).
    pub liquid: AtomicUnitsString,
    /// Staked principal; `"0"` until Stage 3 stake methods land.
    pub staked: AtomicUnitsString,
    /// Unlocked / spendable now.
    pub unlocked: AtomicUnitsString,
    /// Claimable staking rewards; `"0"` until Stage 3.
    pub claimable_rewards: AtomicUnitsString,
    /// Awaiting-confirmation / in-flight spend lock.
    pub pending: AtomicUnitsString,
}

/// `get_primary_address` result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetPrimaryAddressResult {
    /// Canonical Shekyl address string.
    pub address: String,
}

/// `get_height` result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetHeightResult {
    /// Wallet synced height (always available — read from local state).
    pub wallet_height: i64,
    /// Daemon chain height, or `null` when the daemon is unreachable. The
    /// wallet height is still returned in that case so an offline/​syncing
    /// node does not hide the wallet's own status.
    pub daemon_height: Option<i64>,
}

/// Transfer direction (OpenAPI `Transfer.direction`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransferDirection {
    /// Received output (ledger / scan-derived row).
    Incoming,
    /// Sent transfer (send-journal row; SJ-DQ-7 / PR-SJ-2).
    Outgoing,
}

/// Transfer confirmation state (OpenAPI `Transfer.state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransferState {
    /// Network-exposed spend awaiting confirmation (or still unsettled).
    Pending,
    /// Confirmed on chain, unspent (receive) or observed spent-on-chain (send).
    Confirmed,
    /// Spent (receive-side output consumed).
    Spent,
    /// Terminal failure: daemon refused the dispatch; the tx never mined
    /// (OUTGOING journal `TerminalRejected` only — rule 82 failed-send history).
    Failed,
}

/// Client-facing transfer projection (OpenAPI `Transfer`).
///
/// Accounting facts only — no key material, offsets, or commitments.
/// INCOMING rows project scan ledger outputs; OUTGOING rows project
/// send-journal records (SJ-DQ-7).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferView {
    /// Stable per-wallet id: `{tx_hash_hex}:{internal_output_index}` for
    /// INCOMING; bare `{tx_hash_hex}` for OUTGOING journal rows (SJ-DQ-7).
    pub id: String,
    /// Incoming / outgoing.
    pub direction: TransferDirection,
    /// Transaction hash (lowercase hex).
    pub tx_hash: String,
    /// Output amount.
    pub amount: AtomicUnitsString,
    /// Fee when known; `"0"` for receive-side ledger rows.
    pub fee: AtomicUnitsString,
    /// Inclusion height.
    pub block_height: i64,
    /// Confirmation / spend / failure state.
    pub state: TransferState,
    /// Height at which the output was spent, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spent_height: Option<i64>,
}

/// `get_transfers` result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetTransfersResult {
    /// Matching transfers.
    pub transfers: Vec<TransferView>,
}

/// `get_transfer_by_id` result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetTransferByIdResult {
    /// The matching transfer.
    pub transfer: TransferView,
}

/// `refresh` result (OpenAPI `RefreshResult`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefreshResult {
    /// Heights scanned this call.
    pub blocks_processed: i64,
    /// Detected transfers ingested this call.
    pub transfers_detected: i64,
    /// Wallet synced height after the refresh.
    pub synced_height: i64,
    /// Present iff a reorg was detected and rewound this refresh.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reorg_fork_height: Option<i64>,
}

/// `rescan_blockchain` result (OpenAPI `RescanBlockchainResult`).
///
/// Same counters as [`RefreshResult`] but **without** `reorg_fork_height` —
/// a full rescan rebuilds from the wallet's scan floor rather than rewinding
/// a fork tip, so there is no fork to report.
///
/// Deliberately a distinct type rather than a reuse of [`RefreshResult`]
/// (whose `reorg_fork_height` is `skip_serializing_if`, so today the two
/// serialize identically). The contract declares two schemas; mirroring them
/// one-to-one is what keeps a future change to one from silently rewriting
/// the other's wire shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RescanBlockchainResult {
    /// Heights scanned this call.
    pub blocks_processed: i64,
    /// Detected transfers ingested this call.
    pub transfers_detected: i64,
    /// Wallet synced height after the rescan.
    pub synced_height: i64,
}

/// `build_pending_tx` result (OpenAPI `BuildPendingTxResult`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildPendingTxResult {
    /// Opaque reservation handle (`ReservationId::raw` decimal string).
    pub pending_tx_id: String,
    /// Engine synced height at build time.
    pub built_at_height: i64,
    /// Tip hash at build height (lowercase hex).
    pub built_at_tip_hash: String,
    /// Fee in atomic units.
    pub fee: AtomicUnitsString,
    /// CT-5d content generation; pass back as `seen_gen` on submit.
    pub content_gen: i64,
}

/// Success verdict projection for `submit_pending_tx` — the client image
/// of the Engine's [`shekyl_engine_core::SubmitOutcome`], 1:1 with the
/// wire `SubmitVerdict` success arms (`DAEMON_SUBMIT_VERDICT.md` §2.1;
/// projected by `project::submit_pending_tx_result`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SubmitVerdictView {
    /// Fresh accept / broadcast success.
    Accepted,
    /// Already in the mempool: an earlier submit of these bytes reached
    /// the network (e.g. a retry after a transport-ambiguous attempt).
    AlreadyInPool,
    /// Already confirmed on chain per the daemon's claim;
    /// `confirmed_height` carries the claimed height (display metadata —
    /// refresh remains the settlement authority).
    AlreadyInChain,
}

/// `submit_pending_tx` result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmitPendingTxResult {
    /// Transaction hash (lowercase hex).
    pub tx_hash: String,
    /// Success verdict.
    pub verdict: SubmitVerdictView,
    /// Present iff verdict is `ALREADY_IN_CHAIN`: the daemon-claimed
    /// confirming height (untrusted display metadata,
    /// `DAEMON_SUBMIT_VERDICT.md` §7.2 — never settlement truth). The
    /// field exists only on this result type — no refresh-populated
    /// view shares it, structurally.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmed_height: Option<i64>,
}

/// `discard_pending_tx` result (empty object).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DiscardPendingTxResult {}

/// Payment-request lifecycle state (WI-RPC-1 receiving).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaymentRequestStateView {
    /// Awaiting a matching incoming payment.
    Pending,
    /// Matched to an incoming transfer.
    Matched,
    /// Expiry height passed without a match.
    Expired,
    /// Cancelled by the user.
    Cancelled,
}

/// One payment request (WI-RPC-1 receiving; bookkeeping facts only).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaymentRequestView {
    /// Opaque request id (`rid`; non-zero u48, decimal string).
    pub id: String,
    /// Merchant-local label (may be empty).
    pub label: String,
    /// Requested amount.
    pub amount: AtomicUnitsString,
    /// Block height at creation (the request clock is block height).
    pub created_at: i64,
    /// Absolute expiry height, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<i64>,
    /// Lifecycle state.
    pub state: PaymentRequestStateView,
    /// Matching transaction hash (lowercase hex), when matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_tx_hash: Option<String>,
    /// Output index within the matching transaction, when matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_output_index: Option<i64>,
}

/// `create_payment_request` result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreatePaymentRequestResult {
    /// Opaque request id (`rid`, decimal string).
    pub id: String,
    /// `shekyl:` URI carrying the wallet's primary address and this `rid`
    /// (composed from the stored request, so the two cannot drift).
    pub uri: String,
}

/// `list_payment_requests` result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListPaymentRequestsResult {
    /// Matching requests, in creation order.
    pub payment_requests: Vec<PaymentRequestView>,
}

/// `make_uri` result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MakeUriResult {
    /// The composed `shekyl:` payment URI.
    pub uri: String,
}

/// `parse_uri` result (the parsed query components; address format is not
/// validated at parse time, mirroring `shekyl_address::parse_payment_uri`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParseUriResult {
    /// Address string from the URI path.
    pub address: String,
    /// `amount` query parameter, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<AtomicUnitsString>,
    /// `label` query parameter, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// `rid` query parameter (decimal string), if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rid: Option<String>,
    /// `expiry` query parameter (absolute block height), if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<i64>,
}

/// `estimate_tx_size_and_weight` result (WI-RPC-1 fees).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EstimateTxSizeAndWeightResult {
    /// Serialized transaction size in bytes.
    pub size: i64,
    /// Fee weight in bytes (`size` + Bp+ verification clawback; equals
    /// `Transaction::weight()`).
    pub weight: i64,
    /// Curve-tree depth the FCMP++ proof-size term was evaluated at.
    pub tree_depth: i64,
}

/// `get_default_fee_priority` result (WI-RPC-1 fees).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetDefaultFeePriorityResult {
    /// The default tier (`STANDARD`).
    pub default_priority: String,
    /// Converged fee at the daemon's economy rate for the given shape.
    pub economy_fee: AtomicUnitsString,
    /// Converged fee at the daemon's standard rate (the default tier).
    pub standard_fee: AtomicUnitsString,
    /// Converged fee at the daemon's priority rate.
    pub priority_fee: AtomicUnitsString,
    /// Curve-tree depth the quotes were evaluated at.
    pub tree_depth: i64,
}

/// Staked-balance breakdown (WI-RPC-1 staking; fields never conflated).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetStakedBalanceResult {
    /// Bond principal locked under confirmed live bonds.
    pub bonded_principal_confirmed: AtomicUnitsString,
    /// Bond principal committed by in-flight (sealed, unconfirmed) posts.
    pub bonded_principal_pending: AtomicUnitsString,
    /// Emission-reward money received and still unspent in staking-side
    /// outputs. Not "accrued but unclaimed" — that is a separate surface.
    pub rewards_received_unspent: AtomicUnitsString,
}

/// One staked (unspent staking-side) output (WI-RPC-1 staking).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StakedOutputView {
    /// Global (chain-wide) output index, decimal string.
    pub gindex: String,
    /// Recovered cleartext amount.
    pub amount: AtomicUnitsString,
    /// Owning persona slot ordinal.
    pub p_slot: i64,
    /// Height at which the output becomes spendable.
    pub unlock_height: i64,
    /// Whether the output is finality-confirmed (always `true` at V3.0: the
    /// staking scan records outputs only behind the finality horizon).
    pub confirmed: bool,
}

/// `get_staked_outputs` result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetStakedOutputsResult {
    /// Unspent staking-side outputs, in scan order.
    pub staked_outputs: Vec<StakedOutputView>,
}

/// `staking_info` result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StakingInfoResult {
    /// Whether staking is enabled for this wallet.
    pub staking_enabled: bool,
    /// The staked-balance breakdown.
    pub balance: GetStakedBalanceResult,
    /// Count of unspent staking-side outputs.
    pub staked_output_count: i64,
    /// The staking scan's sealed frontier height (`null` when the wallet has
    /// never scanned as a staker).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pscan_synced_height: Option<i64>,
}

/// `get_tx_proof` result (WI-RPC-3 proofs).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetTxProofResult {
    /// Bech32m proof string, HRP `shekyltxproof`. A disclosure artifact —
    /// OUTBOUND strings carry the tx key in signed plaintext (contract
    /// DISCLOSURE SEMANTICS); share only with the intended verifier.
    pub proof: String,
    /// `OUTBOUND` / `INBOUND`, selected by decoded-address ownership.
    pub direction: String,
}

/// One verified output in a valid `check_tx_proof` (WI-RPC-3 proofs).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxProofOutputView {
    /// The output's vout position in the proven transaction.
    pub output_index: u64,
    /// The output's decrypted amount.
    pub amount: AtomicUnitsString,
}

/// `check_tx_proof` result (WI-RPC-3 proofs). `valid: false` means the
/// proof parsed but its cryptographic content does not verify against
/// this (txid, address, message) — all other fields are present only
/// when `valid` is true (contract `CheckTxProofResult`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckTxProofResult {
    /// Whether the proof verifies.
    pub valid: bool,
    /// `OUTBOUND` / `INBOUND`, read from the proof payload (never guessed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    /// Sum of the verified outputs' decrypted amounts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received: Option<AtomicUnitsString>,
    /// Per-output verification detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outputs: Option<Vec<TxProofOutputView>>,
    /// Whether the tx is still in the mempool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_pool: Option<bool>,
    /// Daemon chain height (block COUNT) minus the tx's block height
    /// (0-based index): a tip-block tx reports 1; 0 only while pool-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmations: Option<u64>,
}

/// `get_reserve_proof` result (WI-RPC-3 proofs).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetReserveProofResult {
    /// Bech32m proof string, HRP `shekylreserveproof`. A disclosure
    /// artifact — holders learn amounts and gain permanent
    /// spend-detection on the disclosed outputs (contract DISCLOSURE
    /// SEMANTICS); prefer amount-bounded proofs.
    pub proof: String,
    /// Sum of the amounts the proof actually discloses.
    pub total: AtomicUnitsString,
    /// Number of outputs disclosed.
    pub output_count: u64,
}

/// `check_reserve_proof` result (WI-RPC-3 proofs). Same valid/invalid
/// contract as [`CheckTxProofResult`]; the provable live reserve is
/// `total - spent`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckReserveProofResult {
    /// Whether the proof verifies.
    pub valid: bool,
    /// Sum of all verified outputs in the proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<AtomicUnitsString>,
    /// Portion of `total` whose key images the daemon reports spent at
    /// verification time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spent: Option<AtomicUnitsString>,
    /// Number of outputs the proof discloses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_count: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::WalletRpcErrorCode;
    use serde_json::json;

    #[test]
    fn accepts_string_and_integer_ids() {
        let r = JsonRpcRequest::try_from_value(json!({
            "jsonrpc": "2.0",
            "id": "abc",
            "method": "get_version"
        }))
        .expect("string id");
        assert_eq!(r.id, json!("abc"));

        let r = JsonRpcRequest::try_from_value(json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "get_version"
        }))
        .expect("int id");
        assert_eq!(r.id, json!(7));
    }

    #[test]
    fn rejects_null_id_with_null_response_id() {
        let (id, err) = JsonRpcRequest::try_from_value(json!({
            "jsonrpc": "2.0",
            "id": null,
            "method": "get_version"
        }))
        .unwrap_err();
        assert!(id.is_null());
        assert_eq!(err.code(), WalletRpcErrorCode::InvalidRequest);
    }

    #[test]
    fn rejects_float_id() {
        let (id, err) = JsonRpcRequest::try_from_value(json!({
            "jsonrpc": "2.0",
            "id": 1.5,
            "method": "get_version"
        }))
        .unwrap_err();
        assert!(id.is_null());
        assert_eq!(err.code(), WalletRpcErrorCode::InvalidRequest);
    }

    #[test]
    fn missing_method_echoes_valid_id() {
        let (id, err) = JsonRpcRequest::try_from_value(json!({
            "jsonrpc": "2.0",
            "id": 9,
        }))
        .unwrap_err();
        assert_eq!(id, json!(9));
        assert_eq!(err.code(), WalletRpcErrorCode::InvalidRequest);
    }

    #[test]
    fn non_object_is_invalid_request() {
        let (id, err) = JsonRpcRequest::try_from_value(json!([1, 2, 3])).unwrap_err();
        assert!(id.is_null());
        assert_eq!(err.code(), WalletRpcErrorCode::InvalidRequest);
    }
}
