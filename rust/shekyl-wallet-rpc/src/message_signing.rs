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
//! # Error taxonomy (SM-R-6, the reason this module exists)
//!
//! Shape errors are the caller's bug (`-32602`); everything else is an
//! *answer* with its own code: `-29800` not-from-that-address, `-29801`
//! corrupted paste, `-29802` unknown scheme, `-29803` address format
//! carries no signing key. The signature string is judged **before** the
//! address: its taxonomy (corruption vs. unknown scheme) is a property of
//! the paste alone, and judging it first keeps those sentences reachable
//! while every in-tree address still answers `-29803` (R6-a below).
//!
//! # The R6-a gate, honestly stated
//!
//! The engine free function's success path is **unreachable today**: the
//! only `SignerIdentity` constructor refuses every in-tree address
//! because no address version carries the 48-byte SLH-DSA key (fork (ii)
//! puts it inline in the v2 address). This projection maps that refusal
//! to `-29803`; when the v2 layout lands, the constructor starts
//! succeeding and nothing here changes.

use serde::Deserialize;
use serde_json::Value;
use shekyl_crypto_pq::message_signing::MessageSigError;
use shekyl_engine_core::engine::message_signing::{
    self as engine_signing, SignMessageError, VerifyMessageError,
};

use crate::error::WalletRpcError;
use crate::params::parse_required_object;
use crate::tenant::{require_open_engine, TenantState};
use crate::types::{capability_mode_str, SignMessageResult, Verified, VerifyMessageResult};

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
    let capability = capability_mode_str(engine.capability());

    let signature = engine
        .sign_message(p.message.as_bytes())
        .await
        .map_err(|e| map_sign_error(&e, capability))?;

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
    // ~21.7 KB armored decode is CPU-bound work an unauthenticated
    // caller can invoke at will, and it must not stall the tokio worker
    // that also serves every other tenant request. `block_in_place` per
    // the crate convention (see `staking::read_view_under_guard` for why
    // every hosting runtime is multi-threaded and why the call is not
    // scattered).
    tokio::task::block_in_place(|| {
        engine_signing::verify_message(network, &p.address, p.message.as_bytes(), &p.signature)
    })
    .map_err(map_verify_error)?;

    serde_json::to_value(VerifyMessageResult { verified: Verified })
        .map_err(|e| WalletRpcError::InternalError(format!("serialize verify_message: {e}")))
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Map the engine verify assembly onto the contract codes.
fn map_verify_error(e: VerifyMessageError) -> WalletRpcError {
    match e {
        // SM-R-6: address shape is the caller's bug (`-32602`), never
        // the proofs-surface `-29100`.
        VerifyMessageError::InvalidAddress | VerifyMessageError::ClassicalOnly => {
            WalletRpcError::InvalidParams(e.to_string())
        }
        VerifyMessageError::Crypto(inner) => map_sig_error(&inner),
    }
}

/// Map the crypto-layer taxonomy onto the contract codes (SM-R-6).
///
/// `Malformed` is the caller's bug (`-32602`, shape-first); every other
/// variant is an answer with its own `-29800`-band code. The sign-side
/// variants (`InvalidKey` / `Rng`) are unreachable through the verify
/// path's types but mapped honestly rather than panicked on.
fn map_sig_error(e: &MessageSigError) -> WalletRpcError {
    match e {
        MessageSigError::Malformed(detail) => {
            WalletRpcError::InvalidParams(format!("malformed signature string: {detail}"))
        }
        MessageSigError::UnsupportedScheme(scheme) => {
            WalletRpcError::MessageSigUnsupportedScheme { scheme: *scheme }
        }
        MessageSigError::Corrupted => WalletRpcError::MessageSigCorrupted,
        MessageSigError::VerifyFailed => WalletRpcError::MessageSigVerifyFailed,
        MessageSigError::UnboundIdentity => WalletRpcError::MessageSigAddressUnbound,
        MessageSigError::InvalidKey => {
            WalletRpcError::InternalError("message-signing key material invalid".into())
        }
        MessageSigError::Rng => WalletRpcError::InternalError(
            "the system random number generator failed — try again".into(),
        ),
    }
}

/// Map the Engine sign workflow's refusals onto the contract codes.
///
/// Capability refusals reuse `-29005` with the open wallet's mode string
/// (the proofs precedent); everything else is internal, with
/// detail-bearing variants logged server-side and category-only on the
/// wire (`message()` contract / rule 30).
fn map_sign_error(e: &SignMessageError, capability: &str) -> WalletRpcError {
    match e {
        SignMessageError::ViewOnly | SignMessageError::HardwareOffload => {
            WalletRpcError::CapabilityForbids {
                capability: capability.to_owned(),
            }
        }
        // Terminal for the session, with its own user action (close and
        // reopen). Its own code, not `-32603`: the engine gave this
        // failure its own variant precisely because the remedy differs,
        // and a client automating the reopen must branch on a code, not
        // string-match an English sentence (the same ruling that gave
        // the stake path `-29504`).
        SignMessageError::WalletSessionEnded => WalletRpcError::WalletSessionEnded,
        SignMessageError::Key(detail) => {
            tracing::warn!(detail = %detail, "sign_message key-engine failure");
            WalletRpcError::InternalError("sign_message key-engine failure".into())
        }
        SignMessageError::Crypto(inner) => {
            tracing::warn!(detail = %inner, "sign_message crypto refusal");
            map_sig_error(inner)
        }
        SignMessageError::Internal(detail) => {
            tracing::warn!(detail = %detail, "sign_message internal failure");
            WalletRpcError::InternalError("sign_message internal failure".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::WalletRpcErrorCode;

    // ── error mapping (contract code table) ──────────────────────────

    #[test]
    fn crypto_taxonomy_maps_to_contract_codes() {
        // Every variant, exact code — the mapping IS the contract.
        let cases: Vec<(MessageSigError, WalletRpcErrorCode)> = vec![
            (
                MessageSigError::Malformed("x"),
                WalletRpcErrorCode::InvalidParams,
            ),
            (
                MessageSigError::UnsupportedScheme(0x7f),
                WalletRpcErrorCode::MessageSigUnsupportedScheme,
            ),
            (
                MessageSigError::Corrupted,
                WalletRpcErrorCode::MessageSigCorrupted,
            ),
            (
                MessageSigError::VerifyFailed,
                WalletRpcErrorCode::MessageSigVerifyFailed,
            ),
            (
                MessageSigError::UnboundIdentity,
                WalletRpcErrorCode::MessageSigAddressUnbound,
            ),
            (
                MessageSigError::InvalidKey,
                WalletRpcErrorCode::InternalError,
            ),
            (MessageSigError::Rng, WalletRpcErrorCode::InternalError),
        ];
        for (e, code) in cases {
            assert_eq!(map_sig_error(&e).code(), code);
        }
    }

    #[test]
    fn unsupported_scheme_data_carries_the_byte() {
        let err = map_sig_error(&MessageSigError::UnsupportedScheme(0x42));
        assert_eq!(err.code().as_i32(), -29802);
        assert_eq!(err.data().expect("data")["scheme"], 0x42);
    }

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
        assert_eq!(
            WalletRpcErrorCode::MessageSigAddressUnbound.as_i32(),
            -29803
        );
    }

    #[test]
    fn capability_refusals_carry_the_open_mode() {
        for e in [
            SignMessageError::ViewOnly,
            SignMessageError::HardwareOffload,
        ] {
            let err = map_sign_error(&e, "VIEW_ONLY");
            assert_eq!(err.code(), WalletRpcErrorCode::CapabilityForbids);
            assert_eq!(err.data().expect("data")["capability"], "VIEW_ONLY");
        }
    }

    /// The one sign failure with a different user action (close and
    /// reopen) keeps its own code on the wire — a client automating the
    /// remedy branches on `-29006`, never on English prose (rule 82).
    #[test]
    fn wallet_session_ended_gets_its_own_code() {
        let err = map_sign_error(&SignMessageError::WalletSessionEnded, "FULL");
        assert_eq!(err.code(), WalletRpcErrorCode::WalletSessionEnded);
        assert_eq!(err.code().as_i32(), -29006);
        assert!(
            err.message().contains("close and reopen"),
            "the remedy sentence must survive onto the wire: {}",
            err.message()
        );
    }

    #[test]
    fn sign_internal_failures_are_category_only() {
        let err = map_sign_error(
            &SignMessageError::Internal("/home/user/.shekyl/w.wallet: ENOSPC".into()),
            "FULL",
        );
        assert_eq!(err.code(), WalletRpcErrorCode::InternalError);
        assert!(
            !err.message().contains("/home"),
            "internal detail must not cross the wire: {}",
            err.message()
        );
    }

    #[test]
    fn address_shape_errors_are_params_not_proofs_codes() {
        for e in [
            VerifyMessageError::InvalidAddress,
            VerifyMessageError::ClassicalOnly,
        ] {
            let err = map_verify_error(e);
            assert_eq!(err.code(), WalletRpcErrorCode::InvalidParams);
        }
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
