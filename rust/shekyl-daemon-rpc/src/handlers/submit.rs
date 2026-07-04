// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `POST /submit_transaction` — the native typed submit route
//! (`docs/design/DAEMON_SUBMIT_VERDICT.md` §2.4).
//!
//! The response body **is** the serde-tagged [`SubmitVerdict`]: HTTP 200
//! for every verdict including `Rejected`. Transport-level failures use
//! transport-level status codes and surface client-side as the `Err` arm,
//! never as a verdict — an unparseable request is 400; an [`EngineFault`]
//! (§3.4's loud-failure arm) is 500, so a daemon defect is never converted
//! into a wallet-visible verdict.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use std::sync::Arc;

use shekyl_rpc_types::SubmitTransactionRequest;

use crate::server::AppState;

/// Handle `POST /submit_transaction`.
pub async fn submit_transaction(State(state): State<Arc<AppState>>, body: String) -> Response {
    let request: SubmitTransactionRequest = match serde_json::from_str(&body) {
        Ok(request) => request,
        Err(e) => {
            // Not a verdict: the engine never saw bytes. 400 routes the
            // client into its transport `Err` arm (§2.3).
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid request body: {e}"),
            )
                .into_response();
        }
    };

    // The engine blocks (short FFI lock scopes + the Phase-C crypto battery
    // behind the F39 gate), so it runs on the blocking pool.
    let engine = state.submit_engine.clone();
    let joined = tokio::task::spawn_blocking(move || engine.submit(&request.tx_blob)).await;

    match joined {
        Ok(Ok(verdict)) => (StatusCode::OK, Json(verdict)).into_response(),
        Ok(Err(fault)) => {
            // §3.4: internal faults are transport-level errors, never
            // verdicts. Specifics are already in the daemon log.
            tracing::error!(%fault, "submit engine internal fault");
            (StatusCode::INTERNAL_SERVER_ERROR, fault.to_string()).into_response()
        }
        Err(join_error) => {
            tracing::error!(%join_error, "submit task join failure");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "submit task failed".to_string(),
            )
                .into_response()
        }
    }
}
