// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Receiving / payment-request JSON-RPC methods (WI-RPC-1).
//!
//! Pure projection of the FA-8d Engine surface. Shekyl has **no
//! subaddresses and no accounts**: the merchant reference is the opaque
//! `rid` riding the `shekyl:` URI, matched by the wallet's normal scan
//! (`SUBADDRESS_UNDER_PQC.md` §5.7.9). Only `create_payment_request`
//! mutates (local bookkeeping, persisted via the normal ledger save path);
//! `list_payment_requests`, `make_uri`, and `parse_uri` are read-only.

use serde::Deserialize;
use serde_json::Value;
use shekyl_engine_core::{format_payment_uri, parse_payment_uri, NewPaymentRequest};
use shekyl_engine_state::{PaymentRequest, PaymentRequestId, PaymentRequestState};
use shekyl_units::{AtomicUnits, AtomicUnitsString};

use crate::error::WalletRpcError;
use crate::params::{parse_optional_object, parse_required_object, parse_rid};
use crate::tenant::{require_open_engine, TenantState};
use crate::types::{
    CreatePaymentRequestResult, ListPaymentRequestsResult, MakeUriResult, ParseUriResult,
    PaymentRequestStateView, PaymentRequestView,
};

/// Params for `create_payment_request`.
#[derive(Debug, Deserialize)]
struct CreatePaymentRequestParams {
    label: String,
    amount: AtomicUnitsString,
    expiry: Option<i64>,
}

/// Params for `list_payment_requests`.
#[derive(Debug, Default, Deserialize)]
struct ListPaymentRequestsParams {
    filter: Option<String>,
}

/// Params for `make_uri`. `address` defaults to the open wallet's primary
/// address when omitted.
#[derive(Debug, Deserialize)]
struct MakeUriParams {
    address: Option<String>,
    amount: Option<AtomicUnitsString>,
    label: Option<String>,
    rid: Option<String>,
    expiry: Option<i64>,
}

/// Params for `parse_uri`.
#[derive(Debug, Deserialize)]
struct ParseUriParams {
    uri: String,
}

pub(crate) async fn create_payment_request(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: CreatePaymentRequestParams = parse_required_object(params, "create_payment_request")?;
    let amount = p.amount.to_atomic_units();
    let expiry = p.expiry.map(parse_unix_timestamp).transpose()?;

    let shared = require_open_engine(tenants).await?;
    // Write guard: this is the one receiving method that mutates (local
    // bookkeeping, committed via the normal crash-atomic ledger save).
    let engine = shared.write().await;

    // Invoice clocks are wall-clock Unix seconds (RTN-6). Stamp creation
    // from the host clock so `created_at` cannot be a chain height.
    let created_at = unix_now();
    let id = engine
        .create_payment_request_persisted(NewPaymentRequest {
            label: p.label,
            amount_atomic: amount,
            created_at,
            expiry,
        })
        .map_err(WalletRpcError::from)?;

    let address = engine
        .primary_address()
        .encode()
        .map_err(|e| WalletRpcError::InternalError(format!("encode address: {e}")))?;
    // Compose from the stored request so the on-wire `rid`/amount/label
    // cannot drift from bookkeeping. `None` is unreachable for an id that
    // was just created under this same engine guard.
    let uri = engine
        .format_request_uri(&address, id)
        .ok_or_else(|| WalletRpcError::InternalError("created payment request not found".into()))?;

    let result = CreatePaymentRequestResult {
        id: id.as_u64().to_string(),
        uri,
    };
    serde_json::to_value(result).map_err(|e| {
        WalletRpcError::InternalError(format!("serialize create_payment_request: {e}"))
    })
}

pub(crate) async fn list_payment_requests(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: ListPaymentRequestsParams = parse_optional_object(params, "list_payment_requests")?;
    let filter = parse_filter(p.filter.as_deref())?;

    let shared = require_open_engine(tenants).await?;
    let engine = shared.read().await;
    let requests = engine.list_payment_requests(filter);

    let result = ListPaymentRequestsResult {
        payment_requests: requests.iter().map(payment_request_view).collect(),
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize list_payment_requests: {e}")))
}

pub(crate) async fn make_uri(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: MakeUriParams = parse_required_object(params, "make_uri")?;
    let amount = p.amount.map(AtomicUnitsString::to_atomic_units);
    let rid = p
        .rid
        .as_deref()
        .map(parse_rid)
        .transpose()?
        .map(PaymentRequestId::as_u64);
    let expiry = p
        .expiry
        .map(parse_unix_timestamp)
        .transpose()?
        .map(shekyl_types::Timestamp::to_raw);

    let address = match p.address {
        // Reject — never trim-and-repair — per the boundary discipline the
        // rest of the surface follows (rid=0 rejected, counts rejected).
        // Whitespace anywhere (padding or internal) would embed into the
        // composed URI and produce an ambiguous `shekyl:` string.
        Some(a) if !a.is_empty() && !a.chars().any(char::is_whitespace) => a,
        Some(_) => {
            return Err(WalletRpcError::InvalidParams(
                "address must be non-empty and contain no whitespace".into(),
            ));
        }
        None => {
            // Default to the open wallet's primary address.
            let shared = require_open_engine(tenants).await?;
            let engine = shared.read().await;
            engine
                .primary_address()
                .encode()
                .map_err(|e| WalletRpcError::InternalError(format!("encode address: {e}")))?
        }
    };

    let uri = format_payment_uri(
        &address,
        amount.map(AtomicUnits::to_raw),
        p.label.as_deref(),
        rid,
        expiry,
    );
    let result = MakeUriResult { uri };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize make_uri: {e}")))
}

pub(crate) fn parse_uri(
    _tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: ParseUriParams = parse_required_object(params, "parse_uri")?;
    let parsed = parse_payment_uri(&p.uri)
        .map_err(|e| WalletRpcError::InvalidParams(format!("invalid payment URI: {e}")))?;

    let result = ParseUriResult {
        address: parsed.address,
        amount: parsed
            .amount_atomic
            .map(|a| AtomicUnits::from_raw(a).into()),
        label: parsed.label,
        rid: parsed.rid.map(|r| r.to_string()),
        expiry: parsed.expiry.map(|e| i64::try_from(e).unwrap_or(i64::MAX)),
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize parse_uri: {e}")))
}

/// Project a bookkeeping [`PaymentRequest`] to the RPC view.
fn payment_request_view(r: &PaymentRequest) -> PaymentRequestView {
    PaymentRequestView {
        id: r.id.as_u64().to_string(),
        label: r.label.expose().as_str().to_owned(),
        amount: r.amount_atomic.into(),
        created_at: i64::try_from(r.created_at.to_raw()).unwrap_or(i64::MAX),
        expiry: r
            .expiry
            .map(|e| i64::try_from(e.to_raw()).unwrap_or(i64::MAX)),
        state: match r.state {
            PaymentRequestState::Pending => PaymentRequestStateView::Pending,
            PaymentRequestState::Matched => PaymentRequestStateView::Matched,
            PaymentRequestState::Expired => PaymentRequestStateView::Expired,
            PaymentRequestState::Cancelled => PaymentRequestStateView::Cancelled,
        },
        matched_tx_hash: r.matched_tx_hash.map(|h| h.to_string()),
        matched_output_index: r
            .matched_output_index
            .map(|i| i64::try_from(i.to_raw()).unwrap_or(i64::MAX)),
    }
}

fn parse_filter(
    s: Option<&str>,
) -> Result<shekyl_engine_core::PaymentRequestFilter, WalletRpcError> {
    use shekyl_engine_core::PaymentRequestFilter;
    match s {
        None | Some("ALL") => Ok(PaymentRequestFilter::All),
        Some("PENDING") => Ok(PaymentRequestFilter::Pending),
        Some("MATCHED") => Ok(PaymentRequestFilter::Matched),
        // Stable message; never reflect the client-supplied string (same
        // no-echo discipline as `AtomicUnitsString`'s parse).
        Some(_) => Err(WalletRpcError::InvalidParams(
            "unknown payment-request filter (expected ALL, PENDING, or MATCHED)".into(),
        )),
    }
}

fn parse_unix_timestamp(h: i64) -> Result<shekyl_types::Timestamp, WalletRpcError> {
    let secs = u64::try_from(h).map_err(|_| {
        WalletRpcError::InvalidParams("expiry must be a non-negative unix timestamp".into())
    })?;
    shekyl_types::Timestamp::from_invoice_unix(secs).ok_or_else(|| {
        WalletRpcError::InvalidParams(
            "expiry must be unix seconds, not a chain height (values below 1e9 are refused)".into(),
        )
    })
}

fn unix_now() -> shekyl_types::Timestamp {
    shekyl_types::Timestamp::from_raw(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
}
