// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Message-signing JSON-RPC methods (PR-SM-2): `sign_message` /
//! `verify_message`, projecting the PR-SM-1 construction
//! (`shekyl_crypto_pq::message_signing`, `Engine::sign_message`) onto the
//! contract's `-29800..-29899` band.
//!
//! - `sign_message` requires the open wallet (it needs the master seed)
//!   and delegates to the Engine workflow. It is **multi-second by
//!   design** (~4.3 s on the Pi-4 floor, SM-R-8): the Engine moves the
//!   CPU-bound half off the executor, so the server stays responsive
//!   while one call signs.
//! - `verify_message` is **SESSION-LESS** (SM-R-6): a thin projection of
//!   [`shekyl_engine_core::engine::message_signing::verify_message`]. It
//!   never touches wallet state and never dials the daemon — refusing a
//!   public operation for lack of a wallet session would be a rule-82
//!   lie. Only the tenant's network binding is read (the same read the
//!   wallet-less `check_*` proof methods perform).
//!
//! # Error taxonomy (SM-R-6)
//!
//! The map onto the `-29800` band lives in `shekyl-wallet-contract`.
//! This module calls [`WalletRpcError::from`] and does not keep a second
//! copy. Shape errors are the caller's bug (`-32602`); everything else
//! is an answer: `-29800` not-from-that-address, `-29801` corrupted
//! paste, `-29802` unknown scheme. The signature string is judged
//! **before** the address. (`-29803` ADDRESS_UNBOUND was allocated while
//! verification was R6-a-gated and retired unused when every address
//! came to carry the key.)
//!
//! # The R6-a gate, lifted
//!
//! Every decodable address carries the 48-byte SLH-DSA key as its fourth
//! classical field, so verify takes the address's bound classical
//! segment and the success path is live end to end.

use serde::Deserialize;
use serde_json::Value;
use shekyl_engine_core::engine::message_signing as engine_signing;

use crate::error::WalletRpcError;
use crate::params::parse_required_object;
use crate::tenant::{require_open_engine, TenantState};
use crate::types::{SignMessageResult, Verified, VerifyMessageResult};

// ── Params (contract shapes) ─────────────────────────────────────────

/// Params for `sign_message`.
#[derive(Debug, Deserialize)]
struct SignMessageParams {
    /// The exact string to sign. Bound byte-for-byte (UTF-8): the
    /// verifier must supply the identical string.
    message: String,
}

/// Params for `verify_message`.
#[derive(Debug, Deserialize)]
struct VerifyMessageParams {
    /// The claimed signer's full Shekyl address.
    address: String,
    /// The exact string the signer claims to have signed.
    message: String,
    /// The armored `shekylmsgsig1.` signature string.
    signature: String,
}

// ── Handlers ─────────────────────────────────────────────────────────

pub(crate) async fn sign_message(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: SignMessageParams = parse_required_object(params, "sign_message")?;

    let engine = require_open_engine(tenants).await?;
    let engine = engine.read().await;

    let signature = engine
        .sign_message(p.message.as_bytes())
        .await
        .map_err(WalletRpcError::from)?;

    serde_json::to_value(SignMessageResult { signature })
        .map_err(|e| WalletRpcError::InternalError(format!("serialize sign_message: {e}")))
}

pub(crate) async fn verify_message(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: VerifyMessageParams = parse_required_object(params, "verify_message")?;

    // Session-less: only the tenant's network binding is read (SM-R-6).
    // Assembly (signature-first taxonomy, address decode, identity,
    // network mapping) lives next to sign in engine-core.
    let network = tenants.lock().await.network;

    // Off the worker: SLH-DSA-192s + Schnorr verification plus the
    // ~21.7 KB armored decode is CPU-bound work, and it must not stall
    // the tokio worker that also serves every other tenant request.
    //
    // `spawn_blocking`, not the `staking::read_view_under_guard`
    // `block_in_place` convention: that convention exists for reads that
    // BORROW under the engine guard, and this path holds no guard — the
    // owned params move into the job. The blocking pool is then also the
    // concurrency bound: a burst of verifies saturates at the pool cap
    // and queues FIFO behind it, instead of `block_in_place` growing a
    // replacement worker per in-flight call without limit. A dedicated
    // verify permit (sign's single-flight shape) is deliberately absent:
    // sign holds one because its unit is ~4 s of CPU plus key-actor
    // residency, while verify's unit is milliseconds (~3.4 ms Pi-4 floor
    // once the v2 gate opens; sub-ms today), it holds no wallet
    // resource, and the caller already sits inside the server's auth
    // boundary (UDS filesystem permissions / HTTP basic auth run before
    // dispatch — session-less is not unauthenticated). Bound it for real
    // if this server ever fronts verify outside that boundary, or if a
    // scheme change moves the unit cost out of the millisecond class.
    let VerifyMessageParams {
        address,
        message,
        signature,
    } = p;
    tokio::task::spawn_blocking(move || {
        engine_signing::verify_message(network, &address, message.as_bytes(), &signature)
    })
    .await
    .map_err(|e| WalletRpcError::InternalError(format!("verify_message task failed: {e}")))?
    .map_err(WalletRpcError::from)?;

    serde_json::to_value(VerifyMessageResult { verified: Verified })
        .map_err(|e| WalletRpcError::InternalError(format!("serialize verify_message: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::WalletRpcErrorCode;

    #[test]
    fn band_codes_are_the_allocated_values() {
        // The numeric allocation is the frozen fact (wallet_rpc.yaml
        // header); the enum names are ours to refactor.
        assert_eq!(WalletRpcErrorCode::MessageSigVerifyFailed.as_i32(), -29800);
        assert_eq!(WalletRpcErrorCode::MessageSigCorrupted.as_i32(), -29801);
        assert_eq!(
            WalletRpcErrorCode::MessageSigUnsupportedScheme.as_i32(),
            -29802
        );
    }

    #[test]
    fn verify_result_cannot_represent_false() {
        let ok =
            serde_json::to_value(VerifyMessageResult { verified: Verified }).expect("serialize");
        assert_eq!(ok["verified"], true);
        assert!(serde_json::from_value::<VerifyMessageResult>(
            serde_json::json!({ "verified": false })
        )
        .is_err());
        assert!(serde_json::from_value::<VerifyMessageResult>(
            serde_json::json!({ "verified": true })
        )
        .is_ok());
    }
}
