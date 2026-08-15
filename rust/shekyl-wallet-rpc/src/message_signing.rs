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
//! - `verify_message` is **SESSION-LESS** (SM-R-6): message, signature,
//!   and address are all public, caller-supplied inputs, so it never
//!   touches wallet state and never dials the daemon — refusing a public
//!   operation for lack of a wallet session would be a rule-82 lie. Only
//!   the tenant's network binding is read (the same read the wallet-less
//!   `check_*` proof methods perform).
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
//! `verify_message`'s success path is **unreachable today**: the only
//! constructor of [`SignerIdentity`] refuses every in-tree address
//! because no address version carries the 48-byte SLH-DSA key (fork (ii)
//! puts it inline in the v2 address, whose in-code layout is the one
//! outstanding checklist row). This module still ships the full pipeline
//! so that when the v2 layout lands, the constructor starts succeeding
//! and nothing here changes — the same compiler-enforced sequencing that
//! let PR-SM-1 land ahead of the sign-off.

use serde::Deserialize;
use serde_json::Value;
use shekyl_address::ShekylAddress;
use shekyl_crypto_pq::message_signing::{
    verify_message as crypto_verify_message, ArmoredSignature, MessageSigError, SignerIdentity,
};
use shekyl_engine_core::engine::lifecycle::network_to_derivation;
use shekyl_engine_core::engine::message_signing::SignMessageError;
use shekyl_engine_core::Network;

use crate::error::WalletRpcError;
use crate::params::parse_required_object;
use crate::tenant::{require_open_engine, TenantState};
use crate::types::{capability_mode_str, SignMessageResult, VerifyMessageResult};

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

    // The signature string is judged first — see the module docs for why
    // this order is the taxonomy, not a convenience. The decode here is
    // the same one `crypto_verify_message` performs internally; running
    // it ahead of the address costs one cheap re-decode and buys the
    // error precedence the contract pins.
    ArmoredSignature::decode(&p.signature).map_err(|e| map_sig_error(&e))?;

    // Session-less: only the tenant's network binding is read (SM-R-6).
    let network = tenants.lock().await.network;
    let address = decode_signer_address(&p.address, network)?;

    // The bound classical segment is assembled by its single owner
    // (`BoundClassicalSegment` — the same bytes the address encodes and
    // the signer bound), and the identity is extracted from it or not at
    // all (R6-a): accepting keys from anywhere else would let a recovered
    // spend scalar demote the PQ half to decoration.
    let segment = address.bound_classical_segment();
    let identity =
        SignerIdentity::from_bound_segment(segment.as_bytes()).map_err(|e| map_sig_error(&e))?;

    crypto_verify_message(
        &identity,
        network_to_derivation(network),
        segment.as_bytes(),
        p.message.as_bytes(),
        &p.signature,
    )
    .map_err(|e| map_sig_error(&e))?;

    serde_json::to_value(VerifyMessageResult { verified: true })
        .map_err(|e| WalletRpcError::InternalError(format!("serialize verify_message: {e}")))
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Decode the claimed signer's address against the tenant's network.
///
/// A bad address is `-32602` by ruling (SM-R-6: shape-first), unlike the
/// proof methods' `-29100`. The classical-only display form is refused
/// here too: a message signature binds the full bound segment including
/// the `ek_bind_tag`, which cannot be reconstructed without the PQC
/// segment — and letting it through would assemble a tag over an empty
/// key and fail verification confusingly downstream. Parse detail is
/// logged server-side, never echoed (the input is client-controlled).
fn decode_signer_address(s: &str, network: Network) -> Result<ShekylAddress, WalletRpcError> {
    let address = ShekylAddress::decode_for_network(s, network).map_err(|e| {
        tracing::warn!(detail = %e, "verify_message address decode failed");
        WalletRpcError::InvalidParams(
            "address is not a valid Shekyl address for this network".into(),
        )
    })?;
    if !address.has_pqc_segment() {
        return Err(WalletRpcError::InvalidParams(
            "verify_message requires the full address, not the classical-only form".into(),
        ));
    }
    Ok(address)
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
        // reopen); the Display string already says exactly that.
        SignMessageError::WalletSessionEnded => WalletRpcError::InternalError(e.to_string()),
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
}
