// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transaction-note JSON-RPC method (PR-SA-4 / SJ-DQ-7).
//!
//! Notes are local UX annotations on a bare txid — not part of the send
//! lifecycle. The handler lives here (not under `send`) so annotation policy
//! does not leak into the pending-tx / abandon surface.

use serde::Deserialize;
use serde_json::Value;
use shekyl_engine_state::TX_NOTE_MAX_BYTES;
use shekyl_types::TxHash;

use crate::error::WalletRpcError;
use crate::params::{parse_hex32, parse_required_object};
use crate::tenant::{require_open_engine, TenantState};
use crate::types::SetTxNoteResult;

/// Params for `set_tx_note` (SJ-DQ-7). An empty `note` clears the entry.
#[derive(Debug, Deserialize)]
struct SetTxNoteParams {
    tx_hash: String,
    note: String,
}

/// Reject a note over [`TX_NOTE_MAX_BYTES`]. Reports byte counts only —
/// **never the note content** — so counterparty text cannot escape via the
/// error string (rules 35/36). Extracted so the no-echo property is pinned
/// by a test, not left to code inspection.
///
/// This is a pre-lock fast-fail; the ledger invariant is also enforced on
/// the engine write path (`TxMetaBlock::set_note`).
fn check_note_len(note: &str) -> Result<(), WalletRpcError> {
    if note.len() > TX_NOTE_MAX_BYTES {
        return Err(WalletRpcError::InvalidParams(format!(
            "note exceeds the {TX_NOTE_MAX_BYTES}-byte maximum ({} bytes)",
            note.len()
        )));
    }
    Ok(())
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
    let txid = parse_hex32(&p.tx_hash).ok_or_else(|| {
        WalletRpcError::InvalidParams("tx_hash must be 64 lowercase hex characters".into())
    })?;
    // Bound before the note can enter the ledger, and before any lock is
    // taken — a refused note never reaches the engine or its write guard.
    // The same constant is enforced again on the write path.
    check_note_len(&p.note)?;

    let shared = require_open_engine(tenants).await?;
    let engine = shared.read().await;
    let stored = engine.set_tx_note(TxHash::from_bytes(txid), p.note)?;

    let result = SetTxNoteResult {
        tx_hash: TxHash::from_bytes(txid).to_string(),
        note: stored,
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize set_tx_note: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_length_bound_refuses_without_echoing_content() {
        // At the limit is accepted; one byte over is refused.
        assert!(check_note_len(&"x".repeat(TX_NOTE_MAX_BYTES)).is_ok());
        assert!(check_note_len("short note").is_ok());

        // An over-length note carrying a marker: the refusal must report
        // byte counts only and must NOT echo the note content, so
        // counterparty text cannot escape through the error string (the
        // property fires if someone later "improves" the message to include
        // the note).
        let over = format!("CANARY{}", "x".repeat(TX_NOTE_MAX_BYTES));
        match check_note_len(&over).expect_err("over-length note must be refused") {
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
