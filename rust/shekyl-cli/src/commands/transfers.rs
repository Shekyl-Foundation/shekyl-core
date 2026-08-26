// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transfer commands over the native RPC surface (WI-RPC-2a).
//!
//! The send flow follows the wallet-RPC three-phase contract:
//! `build_pending_tx` (funds reserved) → CLI-side confirmation showing the
//! actual fee → `submit_pending_tx` on an explicit "yes", or
//! `discard_pending_tx` on anything else. Confirmation lives here, not in
//! the server (rewrite-plan pin: the RPC surface is UI-free).

use serde_json::{json, Value};
use shekyl_wallet_rpc::types::{SubmitPendingTxResult, SubmitVerdictView};

use super::{confirm, format_amount, format_amount_str, require_open};
use crate::rpc_client::RpcSession;

/// Map the wallet2-era numeric `--priority N` flag onto the wallet-RPC
/// named tiers: 0-1 → ECONOMY, 2 (and unset) → STANDARD, 3+ → PRIORITY.
pub(crate) fn priority_tier(priority: Option<u32>) -> &'static str {
    match priority {
        None | Some(2) => "STANDARD",
        Some(0 | 1) => "ECONOMY",
        Some(_) => "PRIORITY",
    }
}

/// The handle fields of a `build_pending_tx`-shaped success (`transfer` and
/// `stake_in` share this contract shape) that the confirm/submit flow needs.
pub(crate) struct BuiltPendingTx {
    pub id: String,
    pub seen_gen: i64,
    /// The actual fee, already rendered as SKL for the confirmation print.
    pub fee_skl: String,
}

/// Extract the [`BuiltPendingTx`] fields from a build-phase response.
///
/// The build succeeded, so the server now holds a funds reservation keyed by
/// `pending_tx_id`. Every abort path from here MUST release it, or the
/// reserved outputs stay unspendable until the wallet is closed and reopened
/// — so a malformed response discards the reservation before returning
/// `None` (except when `pending_tx_id` itself is missing, in which case
/// there is no handle to discard with; the contract guarantees the field, so
/// its absence is a genuine protocol error).
///
/// `content_gen` and `fee` are contractually required. Do NOT default them:
/// a wrong `seen_gen` guarantees a CONTENT_GEN_MISMATCH on submit (leaving
/// the reservation live), and a missing fee would ask the user to confirm a
/// send without its real cost.
pub(crate) fn take_built_pending_tx(rpc: &RpcSession, built: &Value) -> Option<BuiltPendingTx> {
    let Some(id) = built
        .get("pending_tx_id")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
    else {
        eprintln!("Malformed build response (missing pending_tx_id).");
        return None;
    };
    let Some(seen_gen) = built.get("content_gen").and_then(serde_json::Value::as_i64) else {
        eprintln!("Malformed build response (missing content_gen).");
        discard_reservation(rpc, &id);
        return None;
    };
    let Some(fee_skl) = built
        .get("fee")
        .and_then(|v| v.as_str())
        .map(format_amount_str)
    else {
        eprintln!("Malformed build response (missing fee).");
        discard_reservation(rpc, &id);
        return None;
    };
    Some(BuiltPendingTx {
        id,
        seen_gen,
        fee_skl,
    })
}

/// Release a reservation the user declined, with a "nothing was sent" line.
pub(crate) fn discard_declined(rpc: &RpcSession, built: &BuiltPendingTx) {
    match rpc.call("discard_pending_tx", json!({ "pending_tx_id": built.id })) {
        Ok(_) => println!("Transaction discarded."),
        Err(e) => rpc.report("Failed to discard pending transaction", &e),
    }
}

/// Submit a confirmed pending transaction and render the verdict. On a
/// failed submit the reservation is released so the user's spendable
/// balance is not silently tied up.
pub(crate) fn submit_pending(rpc: &RpcSession, built: &BuiltPendingTx) {
    match rpc.call(
        "submit_pending_tx",
        json!({ "pending_tx_id": built.id, "seen_gen": built.seen_gen }),
    ) {
        // Decoded through the server's own result type, not a second copy of
        // the verdict vocabulary: `SubmitVerdictView` owns the wire strings,
        // and matching it exhaustively means a new verdict arm fails this
        // build instead of silently rendering as a plain submit.
        Ok(val) => match serde_json::from_value::<SubmitPendingTxResult>(val.clone()) {
            // Render the verdict distinctly (rule 82): all three are success —
            // the funds are on their way either way — but "already" tells the
            // user an earlier attempt went through, so they neither resubmit
            // nor double-count.
            Ok(result) => {
                let tx_hash = result.tx_hash;
                match result.verdict {
                    SubmitVerdictView::Accepted => println!("Transaction submitted: {tx_hash}"),
                    SubmitVerdictView::AlreadyInPool => println!(
                        "Transaction already in the network's pool (an earlier submit went \
                         through): {tx_hash}"
                    ),
                    // The height is the daemon's claim, not an observation of
                    // ours — say "reported" so the user reads it as such.
                    SubmitVerdictView::AlreadyInChain => match result.confirmed_height {
                        Some(h) => println!(
                            "Transaction already confirmed on chain (reported height {h}): \
                             {tx_hash}"
                        ),
                        None => println!("Transaction already confirmed on chain: {tx_hash}"),
                    },
                }
            }
            // A server newer than this CLI, or a malformed reply: the submit
            // still succeeded, so never swallow the hash — print what we can
            // and say the verdict was not understood.
            Err(_) => {
                let tx_hash = val.get("tx_hash").and_then(|v| v.as_str()).unwrap_or("?");
                println!("Transaction submitted (verdict not recognized): {tx_hash}");
            }
        },
        Err(e) => {
            rpc.report("Failed to submit transaction", &e);
            // The failed submit left the reservation live; release it so the
            // user's spendable balance is not silently tied up.
            discard_reservation(rpc, &built.id);
        }
    }
}

pub fn cmd_transfer(
    rpc: &RpcSession,
    amount: u64,
    dest: &str,
    priority: Option<u32>,
    no_confirm: bool,
) {
    if !require_open(rpc) {
        return;
    }

    let response = match rpc.call(
        "build_pending_tx",
        json!({
            "recipients": [{ "address": dest, "amount": amount.to_string() }],
            "priority": priority_tier(priority),
        }),
    ) {
        Ok(v) => v,
        Err(e) => {
            rpc.report("Failed to build transaction", &e);
            return;
        }
    };
    let Some(built) = take_built_pending_tx(rpc, &response) else {
        return;
    };

    println!("Transaction summary:");
    println!("  To:     {dest}");
    println!("  Amount: {} SKL", format_amount(amount));
    println!("  Fee:    {} SKL", built.fee_skl);

    let stdin_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
    let accepted = if no_confirm {
        if stdin_is_tty {
            eprintln!("--no-confirm is only honored for non-interactive input; confirming.");
            confirm("Send this transaction?")
        } else {
            true
        }
    } else if !stdin_is_tty {
        // Non-interactive input without --no-confirm: reading confirm() here
        // would silently consume the next piped line (or hit EOF) as the
        // answer and discard the send with no clear reason — automation would
        // see funds "sent" that never moved. Refuse loudly and point at the
        // explicit flag instead.
        eprintln!(
            "Refusing to send without confirmation on non-interactive input. \
             Re-run with --no-confirm to send unattended, or run interactively."
        );
        false
    } else {
        confirm("Send this transaction?")
    };

    if !accepted {
        discard_declined(rpc, &built);
        return;
    }

    submit_pending(rpc, &built);
}

/// Best-effort release of a `build_pending_tx` reservation on an abort path
/// (malformed response or failed submit). A failure to discard is surfaced,
/// since the reserved funds stay unspendable until the wallet is reopened.
fn discard_reservation(rpc: &RpcSession, pending_tx_id: &str) {
    if let Err(e) = rpc.call(
        "discard_pending_tx",
        json!({ "pending_tx_id": pending_tx_id }),
    ) {
        rpc.report(
            "Failed to release reserved funds (close and reopen the wallet if a \
             later send reports insufficient funds)",
            &e,
        );
    }
}

pub fn cmd_transfers(rpc: &RpcSession) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call("get_transfers", json!({})) {
        Ok(val) => {
            let transfers = val.get("transfers").and_then(|v| v.as_array());
            let Some(transfers) = transfers.filter(|a| !a.is_empty()) else {
                println!("No transfers.");
                return;
            };
            println!(
                "{:<10} {:<10} {:>18} {:>14} {:>10}  TxID",
                "Direction", "State", "Amount (SKL)", "Fee (SKL)", "Height"
            );
            for t in transfers {
                print_transfer_row(t);
            }
        }
        Err(e) => rpc.report("Failed to get transfers", &e),
    }
}

/// One history row.
///
/// A single send produces several rows sharing one TxID — the OUTGOING
/// journal row plus the receive-side rows for its change and for the
/// inputs it consumed — so the fee is rendered per row rather than
/// folded into the amount: a user reconciling the table needs the
/// amount and the cost to be separately visible, not summed for them.
/// A row that was never mined has no height, and prints `—` rather than
/// a block number it does not have.
fn print_transfer_row(t: &Value) {
    let s = |name: &str| t.get(name).and_then(|v| v.as_str()).unwrap_or("?");
    let direction = s("direction");
    let state = s("state");
    let amount = format_amount_str(s("amount"));
    let fee = format_amount_str(s("fee"));
    let height = format_height(t);
    let tx_hash = s("tx_hash");
    println!("{direction:<10} {state:<10} {amount:>18} {fee:>14} {height:>10}  {tx_hash}");
}

/// Inclusion height, or `—` when the transaction is not on chain.
///
/// `block_height` is absent for a send that was never mined (PENDING /
/// FAILED / DROPPED). Printing `0` there would render a plausible block
/// number beside a send that does not exist on chain.
fn format_height(t: &Value) -> String {
    t.get("block_height")
        .and_then(serde_json::Value::as_i64)
        .map_or_else(|| "—".to_owned(), |h| h.to_string())
}

pub fn cmd_show_transfer(rpc: &RpcSession, id: &str) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call("get_transfer_by_id", json!({ "id": id })) {
        Ok(val) => {
            let Some(t) = val.get("transfer") else {
                eprintln!("Malformed get_transfer_by_id response.");
                return;
            };
            let s = |name: &str| t.get(name).and_then(|v| v.as_str()).unwrap_or("?");
            println!("Transfer {}:", s("id"));
            println!("  Direction: {}", s("direction"));
            println!("  State:     {}", s("state"));
            println!("  TxID:      {}", s("tx_hash"));
            println!("  Amount:    {} SKL", format_amount_str(s("amount")));
            println!("  Fee:       {} SKL", format_amount_str(s("fee")));
            println!("  Height:    {}", format_height(t));
            if let Some(spent) = t.get("spent_height").and_then(serde_json::Value::as_i64) {
                println!("  Spent at:  {spent}");
            }
            if let Some(attr) = t.get("attribution") {
                let kind = attr.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
                println!("  Attribution: {kind}");
            }
        }
        Err(e) => rpc.report("Failed to get transfer", &e),
    }
}

/// `get_tx_note <txid>` — read the local note stored for a transaction
/// (SJ-DQ-7). An absent note is also the answer for a txid the wallet has
/// never seen: the note store carries no existence claim (contract pin), so
/// the copy must not imply "unknown transaction".
pub fn cmd_get_tx_note(rpc: &RpcSession, txid: &str) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call("get_tx_note", json!({ "tx_hash": txid })) {
        Ok(val) => match val.get("note").and_then(|v| v.as_str()) {
            Some(note) => println!("{note}"),
            None => println!("No note stored for this transaction."),
        },
        Err(e) => rpc.report("Failed to get the note", &e),
    }
}

/// `set_tx_note <txid> <note>` — attach a local note to a transaction
/// (SJ-DQ-7). The result echoes the note as stored, so what is printed is
/// the server's truth, not an assumption that the write took the input
/// verbatim.
pub fn cmd_set_tx_note(rpc: &RpcSession, txid: &str, note: &str) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call("set_tx_note", json!({ "tx_hash": txid, "note": note })) {
        Ok(val) => match val.get("note").and_then(|v| v.as_str()) {
            Some(stored) => println!("Note stored: {stored}"),
            // Unreachable through this CLI (the parser requires a non-empty
            // note), but the wire allows a clearing write — echo it honestly.
            None => println!("Note cleared."),
        },
        Err(e) => rpc.report("Failed to set the note", &e),
    }
}

/// `abandon <txid>` — give up on a dispatched send (`abandon_tx`, PR-SJ-3 /
/// SJ-DQ-8).
///
/// The copy is careful about what abandoning does NOT do: input locks are
/// not released by intent — an abandoned-but-still-landable send keeps its
/// spent-input locks until confirmed-absent evidence releases them (the
/// self-link defence), and a late confirmation flips the row back to
/// CONFIRMED. Claiming "your funds are free again" here would be a lie the
/// user acts on.
pub fn cmd_abandon(rpc: &RpcSession, txid: &str) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call("abandon_tx", json!({ "tx_hash": txid })) {
        Ok(_) => {
            println!("Send abandoned: the wallet has given up on it.");
            println!(
                "Its funds stay locked until the network is confirmed to have \
                 dropped it — and if the network confirms it after all, the \
                 send shows as confirmed again."
            );
        }
        Err(e) => rpc.report("Failed to abandon the send", &e),
    }
}

/// FA-8 unattributed receives — `get_transfers` with INCOMING + UNATTRIBUTED
/// (WI-RPC-4; closes the WI-RPC-2b `history incoming --unattributed` deferral).
pub fn cmd_history_incoming_unattributed(rpc: &RpcSession) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call(
        "get_transfers",
        json!({
            "direction": "INCOMING",
            "attribution": "UNATTRIBUTED",
        }),
    ) {
        Ok(val) => {
            let transfers = val.get("transfers").and_then(|v| v.as_array());
            let Some(transfers) = transfers.filter(|a| !a.is_empty()) else {
                println!("No unattributed receives.");
                return;
            };
            println!(
                "{:<10} {:<10} {:>18} {:>14} {:>10}  TxID",
                "Direction", "State", "Amount (SKL)", "Fee (SKL)", "Height"
            );
            for t in transfers {
                print_transfer_row(t);
            }
        }
        Err(e) => rpc.report("Failed to list unattributed receives", &e),
    }
}

#[cfg(test)]
mod tests {
    use super::priority_tier;

    /// The named tiers are the OpenAPI `FeePriority` enum values; the
    /// default (no flag) is the server's documented STANDARD default.
    #[test]
    fn priority_flag_maps_onto_named_tiers() {
        assert_eq!(priority_tier(None), "STANDARD");
        assert_eq!(priority_tier(Some(0)), "ECONOMY");
        assert_eq!(priority_tier(Some(1)), "ECONOMY");
        assert_eq!(priority_tier(Some(2)), "STANDARD");
        assert_eq!(priority_tier(Some(3)), "PRIORITY");
        assert_eq!(priority_tier(Some(9)), "PRIORITY");
    }
}
