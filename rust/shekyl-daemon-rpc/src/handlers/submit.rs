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
use crate::submit::{phase_c_semaphore, SubmitCaller};

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

    // The endpoint's trust tier is the Dandelion++ embargo-disclosure
    // boundary (§3.1): a foreign caller on the restricted/public bind must
    // not be able to probe embargoed pool presence, so it sees only
    // broadcast-visible identity. The owner (unrestricted/local endpoint)
    // keeps the F31 resubmit-as-status query.
    let caller = if state.restricted {
        SubmitCaller::Foreign
    } else {
        SubmitCaller::Owner
    };

    // F39 verification cap, enforced at the async dispatch layer: acquire a
    // permit from the process-global Phase-C semaphore BEFORE spawning the
    // blocking submit, so a queued submission parks as a cheap async task
    // rather than pinning a spawn_blocking worker (the earlier in-engine
    // Condvar wait did the latter, exhausting the blocking pool under exactly
    // the flood the cap exists to bound). One semaphore across every bind ⇒
    // the cap is per-daemon, not per-endpoint.
    let permit = match phase_c_semaphore().acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => {
            // The process-global semaphore is never closed; a closed gate is
            // an internal fault, never a verdict.
            tracing::error!("phase-C semaphore closed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "submit gate unavailable".to_string(),
            )
                .into_response();
        }
    };

    // The engine blocks (short FFI lock scopes + the Phase-C crypto battery),
    // so it runs on the blocking pool. The permit is held across the whole
    // blocking submit and released immediately after.
    let engine = state.submit_engine.clone();
    let joined = tokio::task::spawn_blocking(move || engine.submit(&request.tx_blob, caller)).await;
    drop(permit);

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
