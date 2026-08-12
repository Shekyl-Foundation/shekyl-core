// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transaction-note JSON-RPC methods (PR-SA-4 / SJ-DQ-7).
//!
//! Notes are local UX annotations on a bare txid — not part of the send
//! lifecycle. The handlers live here (not under `send`) so annotation policy
//! does not leak into the pending-tx / abandon surface.
//!
//! # The pair is the surface
//!
//! `set_tx_note` writes and `get_tx_note` reads the same keyspace. The reader
//! is not optional convenience: a note may be attached to a txid the wallet
//! does not yet know — the ratified SJ-DQ-7 shape, so a user can annotate an
//! incoming payment before the scanner catches up — and such a note appears on
//! no transfer row, because `TransferView.note` can only annotate rows that
//! exist. Without `get_tx_note` a note on a not-yet-known txid would be
//! write-only: acknowledged, persisted, and unreadable until the scanner
//! happened to catch up.
//!
//! **Residual, stated so it is not re-raised as new:** a note written against
//! a *mistyped* txid is still unrecoverable without retyping the same wrong
//! txid. That is inherent to id-keyed annotation with no membership
//! precondition — the same property that lets the ahead-of-the-scanner case
//! work — and it is bounded: such a note is a stray map entry, never a
//! misdirected payment.

use serde::Deserialize;
use serde_json::Value;
use shekyl_engine_state::check_tx_note_len;
use shekyl_types::TxHash;

use crate::error::WalletRpcError;
use crate::params::{parse_hex32, parse_required_object};
use crate::tenant::{require_open_engine, TenantState};
use crate::types::{GetTxNoteResult, SetTxNoteResult};

/// Params for `set_tx_note` (SJ-DQ-7). An empty `note` clears the entry.
#[derive(Debug, Deserialize)]
struct SetTxNoteParams {
    tx_hash: String,
    note: String,
}

/// Params for `get_tx_note` (SJ-DQ-7).
#[derive(Debug, Deserialize)]
struct GetTxNoteParams {
    tx_hash: String,
}

/// Parse the `tx_hash` param shared by both methods.
fn parse_txid(tx_hash: &str) -> Result<TxHash, WalletRpcError> {
    parse_hex32(tx_hash).map(TxHash::from_bytes).ok_or_else(|| {
        WalletRpcError::InvalidParams("tx_hash must be 64 lowercase hex characters".into())
    })
}

/// `set_tx_note` (`WALLET_SEND_RECORD.md` SJ-DQ-7): attach or clear a
/// user-authored note on a transaction, keyed by the bare txid. An empty
/// `note` clears the entry (there is no separate delete method). Purely
/// local UX state — never on the wire. The engine drives its own
/// crash-atomic save; an exclusive `Engine` borrow is not required (same
/// shape as `abandon_tx`).
///
/// The note is counterparty-bearing free text (rules 35/36): the
/// over-length refusal reports the byte counts, never the note content, so
/// nothing the user wrote leaves the AEAD envelope through an error string.
pub(crate) async fn set_tx_note(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: SetTxNoteParams = parse_required_object(params, "set_tx_note")?;
    let txid = parse_txid(&p.tx_hash)?;
    // Fast-fail an over-length note before taking a lock — a refused note
    // never reaches the engine or its write guard. This defers to the engine's
    // single checker (`set_note` enforces the same one on the write path), so
    // an early refusal cannot differ from the write-door one; `TxNoteTooLong`
    // maps to `-32602 InvalidParams` and reports byte counts only (rules 35/36).
    check_tx_note_len(&p.note)?;

    let shared = require_open_engine(tenants).await?;
    let engine = shared.read().await;
    let stored = engine.set_tx_note(txid, p.note)?;

    let result = SetTxNoteResult {
        tx_hash: txid.to_string(),
        note: stored,
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize set_tx_note: {e}")))
}

/// `get_tx_note` (`WALLET_SEND_RECORD.md` SJ-DQ-7): read back the note for a
/// txid, or its absence.
///
/// An unknown txid is **not** an error — it answers with the note omitted,
/// the same shape as a cleared one. There is nothing to distinguish: a note
/// carries no existence claim about the transaction, so "no note for this
/// txid" is the whole truth in both cases, and a refusal would additionally
/// turn this read into an oracle for which txids the wallet has annotated.
pub(crate) async fn get_tx_note(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: GetTxNoteParams = parse_required_object(params, "get_tx_note")?;
    let txid = parse_txid(&p.tx_hash)?;

    let shared = require_open_engine(tenants).await?;
    let engine = shared.read().await;

    let result = GetTxNoteResult {
        tx_hash: txid.to_string(),
        note: engine.tx_note(txid),
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_tx_note: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::error::WalletRpcErrorCode;
    use shekyl_engine_state::TX_NOTE_MAX_BYTES;

    /// The boundary maps the engine's over-length refusal onto the wire
    /// contract `-32602 InvalidParams` **without echoing the note content**.
    /// The bound itself is owned and tested in `shekyl-engine-state`; this
    /// pins the RPC-facing half — the wire code and the no-echo property that
    /// fires if the refusal ever grows to include the note.
    #[test]
    fn over_length_note_maps_to_invalid_params_without_echoing_content() {
        // At the limit is accepted; one byte over is refused.
        assert!(check_tx_note_len(&"x".repeat(TX_NOTE_MAX_BYTES)).is_ok());
        assert!(check_tx_note_len("short note").is_ok());

        let over = format!("CANARY{}", "x".repeat(TX_NOTE_MAX_BYTES));
        let err: WalletRpcError = check_tx_note_len(&over)
            .expect_err("over-length note must be refused")
            .into();

        assert_eq!(
            err.code(),
            WalletRpcErrorCode::InvalidParams,
            "an over-length note must refuse as invalid params"
        );
        match err {
            WalletRpcError::InvalidParams(msg) => {
                assert!(
                    !msg.contains("CANARY"),
                    "refusal must not echo note content: {msg}"
                );
                assert!(
                    msg.contains("maximum"),
                    "refusal should name the limit: {msg}"
                );
            }
            other => panic!("expected InvalidParams, got {other:?}"),
        }
    }
}
