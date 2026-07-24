// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transaction-proof and reserve-proof JSON-RPC methods (WI-RPC-3).
//!
//! Thin projections of the Engine proofs workflow
//! (`shekyl_engine_core::engine::proofs`) onto the contract's four
//! methods:
//!
//! - `get_tx_proof` / `get_reserve_proof` require an open wallet and
//!   delegate to the Engine's thin proof delegators (which assemble the
//!   `ProofsCtx` per `ENGINE_COMPOSITION_DECOMPOSITION.md` — no proof
//!   logic lives here).
//! - `check_tx_proof` / `check_reserve_proof` are WALLET-LESS: a
//!   verifier checks someone else's proof against an address and the
//!   chain, so they dial the tenant's daemon directly
//!   ([`crate::lifecycle::make_daemon`]) and never touch wallet state.
//!
//! The counterparty address is compared and bound in DECODED form
//! (contract `GetTxProofParams`): Bech32m admits an all-uppercase
//! encoding of the same address, so raw string comparison would
//! silently misroute direction selection. Proofs bind the full hybrid
//! address (`network ‖ spend ‖ view ‖ ml_kem_encap_key`), so the
//! classical-only address form is refused as `-29100` here rather than
//! failing verification confusingly downstream.

use serde::Deserialize;
use serde_json::Value;
use shekyl_address::ShekylAddress;
use shekyl_engine_core::engine::proofs::{self, CheckedReserveProof, CheckedTxProof, ProofsError};
use shekyl_engine_core::Network;
use shekyl_types::TxHash;

use crate::error::WalletRpcError;
use crate::lifecycle::make_daemon;
use crate::params::{parse_atomic_units, parse_optional_object, parse_required_object};
use crate::project::atomic_units_string;
use crate::tenant::{require_open_engine, TenantState};
use crate::types::{
    capability_mode_str, CheckReserveProofResult, CheckTxProofResult, GetReserveProofResult,
    GetTxProofResult, TxProofOutputView,
};

// ── Params (contract shapes) ─────────────────────────────────────────

/// Params for `get_tx_proof`.
#[derive(Debug, Deserialize)]
struct GetTxProofParams {
    txid: String,
    address: String,
    #[serde(default)]
    message: String,
}

/// Params for `check_tx_proof`.
#[derive(Debug, Deserialize)]
struct CheckTxProofParams {
    txid: String,
    address: String,
    proof: String,
    #[serde(default)]
    message: String,
}

/// Params for `get_reserve_proof` (all fields optional: omitted
/// `amount` = prove the full eligible balance).
#[derive(Debug, Default, Deserialize)]
struct GetReserveProofParams {
    amount: Option<String>,
    #[serde(default)]
    message: String,
}

/// Params for `check_reserve_proof`.
#[derive(Debug, Deserialize)]
struct CheckReserveProofParams {
    address: String,
    proof: String,
    #[serde(default)]
    message: String,
}

// ── Handlers ─────────────────────────────────────────────────────────

pub(crate) async fn get_tx_proof(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: GetTxProofParams = parse_required_object(params, "get_tx_proof")?;
    let txid = parse_txid(&p.txid)?;

    let engine = require_open_engine(tenants).await?;
    let engine = engine.read().await;
    let address = decode_proof_address(&p.address, engine.network())?;
    let capability = capability_mode_str(engine.capability());

    let generated = engine
        .get_tx_proof(TxHash::from_bytes(txid), &address, &p.message)
        .await
        .map_err(|e| map_proofs_error(e, capability))?;

    let result = GetTxProofResult {
        proof: generated.proof,
        direction: generated.direction.as_contract_str().to_owned(),
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_tx_proof: {e}")))
}

pub(crate) async fn get_reserve_proof(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: GetReserveProofParams = parse_optional_object(params, "get_reserve_proof")?;
    let amount = p.amount.as_deref().map(parse_atomic_units).transpose()?;

    let engine = require_open_engine(tenants).await?;
    let engine = engine.read().await;
    let capability = capability_mode_str(engine.capability());

    let generated = engine
        .get_reserve_proof(amount, &p.message)
        .await
        .map_err(|e| map_proofs_error(e, capability))?;

    let result = GetReserveProofResult {
        proof: generated.proof,
        total: atomic_units_string(generated.total),
        output_count: generated.output_count as u64,
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_reserve_proof: {e}")))
}

pub(crate) async fn check_tx_proof(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: CheckTxProofParams = parse_required_object(params, "check_tx_proof")?;
    let txid = parse_txid(&p.txid)?;

    // Wallet-less: only the tenant's network / daemon binding is read.
    let (network, daemon_address) = network_and_daemon(tenants).await;
    let address = decode_proof_address(&p.address, network)?;
    let daemon = make_daemon(&daemon_address).await?;

    let checked = proofs::check_tx_proof(&daemon, txid, &address, &p.message, &p.proof)
        .await
        .map_err(map_walletless_error)?;

    let result = match checked {
        CheckedTxProof::Invalid => CheckTxProofResult {
            valid: false,
            direction: None,
            received: None,
            outputs: None,
            in_pool: None,
            confirmations: None,
        },
        CheckedTxProof::Valid {
            direction,
            received,
            outputs,
            in_pool,
            confirmations,
        } => CheckTxProofResult {
            valid: true,
            direction: Some(direction.as_contract_str().to_owned()),
            received: Some(atomic_units_string(received)),
            outputs: Some(
                outputs
                    .iter()
                    .map(|o| TxProofOutputView {
                        output_index: o.output_index,
                        amount: atomic_units_string(o.amount),
                    })
                    .collect(),
            ),
            in_pool: Some(in_pool),
            confirmations: Some(confirmations),
        },
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize check_tx_proof: {e}")))
}

pub(crate) async fn check_reserve_proof(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: CheckReserveProofParams = parse_required_object(params, "check_reserve_proof")?;

    let (network, daemon_address) = network_and_daemon(tenants).await;
    let address = decode_proof_address(&p.address, network)?;
    let daemon = make_daemon(&daemon_address).await?;

    let checked = proofs::check_reserve_proof(&daemon, &address, &p.message, &p.proof)
        .await
        .map_err(map_walletless_error)?;

    let result = match checked {
        CheckedReserveProof::Invalid => CheckReserveProofResult {
            valid: false,
            total: None,
            spent: None,
            output_count: None,
        },
        CheckedReserveProof::Valid {
            total,
            spent,
            output_count,
        } => CheckReserveProofResult {
            valid: true,
            total: Some(atomic_units_string(total)),
            spent: Some(atomic_units_string(spent)),
            output_count: Some(output_count as u64),
        },
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize check_reserve_proof: {e}")))
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Read the tenant's network / daemon binding without requiring an open
/// wallet (the `check_*` methods are wallet-less by contract).
async fn network_and_daemon(tenants: &tokio::sync::Mutex<TenantState>) -> (Network, String) {
    let state = tenants.lock().await;
    (state.network, state.daemon_address.clone())
}

/// Parse a contract `Hex32` txid (64 lowercase hex chars → 32 bytes).
///
/// The error message is stable and never echoes the client string.
fn parse_txid(s: &str) -> Result<[u8; 32], WalletRpcError> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(WalletRpcError::InvalidParams(
            "txid must be 64 lowercase hex characters".into(),
        ));
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(s, &mut bytes)
        .map_err(|_| WalletRpcError::InvalidParams("txid must be valid hex".into()))?;
    Ok(bytes)
}

/// Decode a proof-bound address against the tenant's network.
///
/// Refuses the classical-only (single-segment) form: proofs bind the
/// full hybrid address bytes and OUTBOUND verification re-encapsulates
/// against the ML-KEM key, so an address without its PQC segment can
/// never verify — refusing here (-29100) beats a confusing
/// `valid: false` downstream. Parse detail is logged server-side, not
/// echoed (the input is client-controlled).
fn decode_proof_address(s: &str, network: Network) -> Result<ShekylAddress, WalletRpcError> {
    let address = ShekylAddress::decode_for_network(s, network).map_err(|e| {
        tracing::warn!(detail = %e, "proof address decode failed");
        WalletRpcError::InvalidRecipient
    })?;
    if !address.has_pqc_segment() {
        tracing::warn!("proof address lacks the PQC segment (classical-only form)");
        return Err(WalletRpcError::InvalidRecipient);
    }
    Ok(address)
}

/// Map [`ProofsError`] onto the contract's error codes for the
/// open-wallet generation methods. `capability` is the open wallet's
/// mode string, reported when the refusal is capability-shaped
/// (`get_reserve_proof` on a non-FULL wallet).
fn map_proofs_error(e: ProofsError, capability: &str) -> WalletRpcError {
    match e {
        ProofsError::NotFullWallet => WalletRpcError::CapabilityForbids {
            capability: capability.to_owned(),
        },
        other => map_walletless_error(other),
    }
}

/// Map [`ProofsError`] onto the contract's error codes for the
/// wallet-less check methods (no capability context exists).
///
/// Detail-bearing variants log server-side and return the stable
/// client message — the framing detail can echo client-controlled
/// bytes and `message()` is the most-logged surface.
fn map_walletless_error(e: ProofsError) -> WalletRpcError {
    match e {
        ProofsError::Malformed(detail) => {
            tracing::warn!(detail = %detail, "proof rejected as malformed");
            WalletRpcError::ProofMalformed
        }
        ProofsError::TxSecretUnavailable => WalletRpcError::ProofTxSecretUnavailable,
        ProofsError::NoProvableOutputs(detail) => {
            tracing::info!(detail = %detail, "proof request had no provable outputs");
            WalletRpcError::ProofNoProvableOutputs
        }
        ProofsError::TxNotFound(txid) => {
            tracing::info!(txid = %txid, "proof-named tx unknown to the daemon");
            WalletRpcError::ProofTxNotFound
        }
        // Reachable only via `map_proofs_error`'s passthrough when the
        // capability context was already consumed; map defensively.
        ProofsError::NotFullWallet => WalletRpcError::CapabilityForbids {
            capability: "FULL".to_owned(),
        },
        ProofsError::InvalidRecipient => WalletRpcError::InvalidRecipient,
        ProofsError::AmountOverflow => {
            WalletRpcError::InternalError("proof amount sum overflow".into())
        }
        ProofsError::Daemon(detail) => {
            tracing::warn!(detail = %detail, "proof daemon RPC failure");
            WalletRpcError::DaemonUnreachable
        }
        ProofsError::Key(detail) => {
            tracing::warn!(detail = %detail, "proof key-engine failure");
            WalletRpcError::InternalError("proof key-engine failure".into())
        }
        ProofsError::Generate(detail) => {
            tracing::warn!(detail = %detail, "proof generation failure");
            WalletRpcError::InternalError("proof generation failure".into())
        }
        ProofsError::Encoding(detail) => {
            tracing::warn!(detail = %detail, "proof encoding failure");
            WalletRpcError::InternalError("proof encoding failure".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::WalletRpcErrorCode;

    // ── txid parsing ─────────────────────────────────────────────────

    #[test]
    fn parse_txid_accepts_canonical_hex32() {
        let txid = parse_txid(&"ab".repeat(32)).expect("canonical");
        assert_eq!(txid, [0xab; 32]);
    }

    #[test]
    fn parse_txid_rejects_non_canonical_forms() {
        for bad in [
            String::new(),
            "ab".repeat(31),                  // short
            "ab".repeat(33),                  // long
            "AB".repeat(32),                  // uppercase (contract pins lowercase)
            format!("{}zz", "ab".repeat(31)), // non-hex
        ] {
            let err = parse_txid(&bad).expect_err("must refuse");
            assert_eq!(err.code(), WalletRpcErrorCode::InvalidParams, "{bad:?}");
        }
    }

    // ── address decoding ─────────────────────────────────────────────

    fn test_address() -> ShekylAddress {
        ShekylAddress::new(
            shekyl_address::Network::Stagenet,
            [0xAA; 32],
            [0xBB; 32],
            vec![0xCC; 1184],
        )
    }

    #[test]
    fn decode_proof_address_round_trips_full_form() {
        let addr = test_address();
        let encoded = addr.encode().expect("encode");
        let decoded =
            decode_proof_address(&encoded, shekyl_address::Network::Stagenet).expect("decode");
        assert_eq!(decoded, addr);
    }

    #[test]
    fn decode_proof_address_rejects_wrong_network() {
        let addr = test_address();
        let encoded = addr.encode().expect("encode");
        let err = decode_proof_address(&encoded, shekyl_address::Network::Mainnet)
            .expect_err("network mismatch");
        assert_eq!(err.code(), WalletRpcErrorCode::InvalidRecipient);
    }

    #[test]
    fn decode_proof_address_rejects_classical_only_form() {
        // The single-segment classical form parses as a valid address but
        // lacks the PQC segment proofs bind to.
        let addr = test_address();
        let full = addr.encode().expect("encode");
        let classical = full
            .split(shekyl_address::SEGMENT_SEPARATOR)
            .next()
            .expect("classical segment");
        let err = decode_proof_address(classical, shekyl_address::Network::Stagenet)
            .expect_err("classical-only must refuse");
        assert_eq!(err.code(), WalletRpcErrorCode::InvalidRecipient);
    }

    #[test]
    fn decode_proof_address_rejects_garbage() {
        let err = decode_proof_address("not-an-address", shekyl_address::Network::Stagenet)
            .expect_err("garbage");
        assert_eq!(err.code(), WalletRpcErrorCode::InvalidRecipient);
    }

    // ── error mapping (contract code table) ──────────────────────────

    #[test]
    fn proofs_errors_map_to_contract_codes() {
        let cases: Vec<(ProofsError, WalletRpcErrorCode)> = vec![
            (
                ProofsError::Malformed("x".into()),
                WalletRpcErrorCode::ProofMalformed,
            ),
            (
                ProofsError::TxSecretUnavailable,
                WalletRpcErrorCode::ProofTxSecretUnavailable,
            ),
            (
                ProofsError::NoProvableOutputs("x".into()),
                WalletRpcErrorCode::ProofNoProvableOutputs,
            ),
            (
                ProofsError::TxNotFound("ab".repeat(32)),
                WalletRpcErrorCode::ProofTxNotFound,
            ),
            (
                ProofsError::InvalidRecipient,
                WalletRpcErrorCode::InvalidRecipient,
            ),
            (
                ProofsError::AmountOverflow,
                WalletRpcErrorCode::InternalError,
            ),
        ];
        for (e, code) in cases {
            assert_eq!(map_walletless_error(e).code(), code);
        }
    }

    #[test]
    fn not_full_wallet_maps_to_capability_forbids_with_mode() {
        let err = map_proofs_error(ProofsError::NotFullWallet, "VIEW_ONLY");
        assert_eq!(err.code(), WalletRpcErrorCode::CapabilityForbids);
        let data = err.data().expect("data");
        assert_eq!(data["capability"], "VIEW_ONLY");
    }

    #[test]
    fn malformed_message_is_stable_and_detail_free() {
        // The framing detail can echo client bytes (the HRP); the wire
        // message must not carry it.
        let err = map_walletless_error(ProofsError::Malformed(
            "wrong HRP 'attacker-controlled'".into(),
        ));
        assert_eq!(err.message(), "proof string malformed");
    }
}
