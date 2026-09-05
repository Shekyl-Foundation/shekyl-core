// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Console rendering for natively-served methods
//! (`docs/design/DAEMON_RPC_KV_CUTOVER.md` §3.4, RK-D5).
//!
//! `shekyld`'s console has two arms that used to share one C++ struct: the
//! interactive console inside the daemon (which called
//! `core_rpc_server::on_*` directly) and `shekyld <command>` from a second
//! process (which framed the struct as JSON through the loopback client).
//! When a method's struct moves to Rust, both arms render here through one
//! export, [`shekyl_daemon_console_run`]: given a live core it calls the
//! native method directly; given an address it posts through the same
//! transport `shekyld <command>` already uses and renders the typed reply.
//! The C++ executor entry becomes a forward and dies with RK-C.

use std::os::raw::{c_char, c_void};
use std::sync::Arc;
use std::time::Duration;

use shekyl_rpc_types::{GetHeightResponse, RestErrorEnvelope};
use shekyl_units::AtomicUnits;

use crate::chain_facts::FfiChainFacts;
use crate::core::CoreRpc;
use crate::ctl_client;

mod alt_chain;
mod blockchain;
mod info;
mod status;
#[cfg(test)]
mod tests;

use alt_chain::alt_chain_info;
use blockchain::{print_blockchain_dynamic_stats, print_blockchain_info};
use status::{hard_fork_info, show_status};

/// Rendered; `out` holds the text to print as success output.
pub const SHEKYL_DAEMON_CONSOLE_OK: i32 = 0;
/// A required pointer was null or not UTF-8.
pub const SHEKYL_DAEMON_CONSOLE_ERR_NULL_PTR: i32 = -1;
/// `argv[0]` names no natively-rendered command.
pub const SHEKYL_DAEMON_CONSOLE_ERR_UNKNOWN: i32 = -2;
/// The request failed; `out` holds the reason to print as failure output.
pub const SHEKYL_DAEMON_CONSOLE_ERR_REQUEST: i32 = -3;
/// Both a live core and an address were given: the contract is exactly one.
pub const SHEKYL_DAEMON_CONSOLE_ERR_AMBIGUOUS_SOURCE: i32 = -4;

/// Where a console command gets its facts from.
enum Source {
    /// Inside the daemon: the live core.
    Live(Arc<CoreRpc>),
    /// A second process: the daemon's RPC address.
    Remote { address: String, timeout: Duration },
}

/// Decode a REST reply body: the success type, else the daemon's error
/// envelope (the transport hands the body through whatever the HTTP status
/// was), else a malformed-reply error. The envelope's reason is what the
/// operator reads, never "missing field `height`".
fn decode_reply<T: serde::de::DeserializeOwned>(body: &[u8], method: &str) -> Result<T, String> {
    if let Ok(reply) = serde_json::from_slice::<T>(body) {
        return Ok(reply);
    }
    if let Ok(envelope) = serde_json::from_slice::<RestErrorEnvelope>(body) {
        return Err(format!("{method} failed: {}", envelope.error));
    }
    Err(format!(
        "malformed {method} reply: {}",
        String::from_utf8_lossy(body)
            .chars()
            .take(120)
            .collect::<String>()
    ))
}

/// `%Y-%m-%d %H:%M:%S` in UTC, or `<unknown>` below the same cutoff the C++
/// used (`tools::get_human_readable_timestamp`). The cutoff is 2009-02-13,
/// which predates any Shekyl block by years; it is kept so a corrupt or
/// zero timestamp reads as unknown rather than as 1970.
fn human_readable_timestamp(ts: u64) -> String {
    const UNKNOWN_BEFORE: u64 = 1_234_567_890;
    if ts < UNKNOWN_BEFORE {
        return "<unknown>".to_owned();
    }
    // Civil-from-days (Howard Hinnant's algorithm): no dependency, no libc
    // `gmtime`, and total for every value a u64 timestamp can hold.
    let days = i64::try_from(ts / 86_400).unwrap_or(i64::MAX);
    let secs_of_day = ts % 86_400;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!(
        "{year:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// The `0x`-prefixed wide difficulty rendered as decimal, which is what the
/// C++ console printed by constructing a `difficulty_type` from it.
fn wide_difficulty_decimal(wide: &str) -> String {
    let digits = wide.strip_prefix("0x").unwrap_or(wide);
    match u128::from_str_radix(digits, 16) {
        Ok(value) => value.to_string(),
        // The daemon produced this field; if it is ever unreadable, showing
        // it verbatim beats showing nothing.
        Err(_) => wide.to_owned(),
    }
}

/// `print_block_header`'s text, field for field and in its order.
///
/// Built as lines and joined: writing to a `String` cannot fail, so
/// `write!` here would only produce `Result`s to discard.
fn render_block_header(h: &shekyl_rpc_types::BlockHeader) -> String {
    let pow_hash = h.pow_hash.map_or_else(String::new, |p| p.to_string());
    [
        format!(
            "timestamp: {} ({})",
            h.timestamp,
            human_readable_timestamp(h.timestamp)
        ),
        format!("previous hash: {}", h.prev_hash),
        format!("nonce: {}", h.nonce),
        // The C++ streamed a bool, which prints as 0/1.
        format!("is orphan: {}", u8::from(h.orphan_status)),
        format!("height: {}", h.height),
        format!("depth: {}", h.depth),
        format!("hash: {}", h.hash),
        format!(
            "difficulty: {}",
            wide_difficulty_decimal(&h.wide_difficulty)
        ),
        format!(
            "cumulative difficulty: {}",
            wide_difficulty_decimal(&h.wide_cumulative_difficulty)
        ),
        // Empty when it was not asked for or not allowed — the C++ printed
        // the empty string just the same.
        format!("POW hash: {pow_hash}"),
        format!("block size: {}", h.block_size),
        format!("block weight: {}", h.block_weight),
        format!("long term weight: {}", h.long_term_weight),
        format!("num txes: {}", h.num_txes),
        format!(
            "reward: {}",
            AtomicUnits::from_raw(h.reward).to_skl_string()
        ),
        format!("miner tx hash: {}", h.miner_tx_hash),
    ]
    .join("\n")
}

/// `print_block_by_hash` / `print_block_by_height`: the two console commands
/// that read `get_block` and nothing else, which is why they migrate with it
/// (the design's console matrix, §2.1).
fn print_block(
    src: &Source,
    by_hash: bool,
    argument: &str,
    include_hex: bool,
) -> Result<String, String> {
    let mut request = shekyl_rpc_types::GetBlockRequest {
        fill_pow_hash: true,
        ..Default::default()
    };
    if by_hash {
        request.hash = argument.to_owned();
    } else {
        request.height = argument
            .parse()
            .map_err(|_| format!("not a block height: {argument}"))?;
    }

    // In-process the console is the operator's own terminal, so the
    // restricted-listener rule does not apply: the C++ passed
    // `fill_pow_hash` straight through here too.
    let reply = native_json_rpc(src, "get_block", &request, |core| {
        crate::methods::get_block(&FfiChainFacts::new(core.clone()), &request, true)
    })?;
    require_ok(&reply.status)?;

    // The C++ order: the blob (only with `+hex`) and a blank line, then the
    // header, then the block's json.
    let mut out = String::new();
    if include_hex {
        out.push_str(&reply.blob);
        out.push_str("\n\n");
    }
    out.push_str(&render_block_header(&reply.block_header));
    out.push('\n');
    out.push_str(&reply.json);
    Ok(out)
}

/// Unwrap a JSON-RPC 2.0 envelope: the `result`, or the `error`'s message as
/// the operator's reason. A daemon that refused says why; a body that is
/// neither is a malformed reply.
fn json_rpc_result<T: serde::de::DeserializeOwned>(body: &[u8], method: &str) -> Result<T, String> {
    let envelope: serde_json::Value = serde_json::from_slice(body).map_err(|_| {
        format!(
            "malformed {method} reply: {}",
            String::from_utf8_lossy(body)
                .chars()
                .take(120)
                .collect::<String>()
        )
    })?;
    if let Some(error) = envelope.get("error") {
        let message = error
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("no reason given");
        return Err(format!("{method} failed: {message}"));
    }
    let result = envelope
        .get("result")
        .ok_or_else(|| format!("malformed {method} reply: no result"))?;
    serde_json::from_value(result.clone()).map_err(|e| format!("malformed {method} reply: {e}"))
}

/// Call a natively-served JSON-RPC method on whichever arm this console is on.
///
/// Live: the method function directly, so a method leaving this crate is a
/// compile error. Remote: one `/json_rpc` POST, unwrapped as JSON-RPC 2.0.
fn native_json_rpc<Req, Res>(
    src: &Source,
    method: &str,
    request: &Req,
    live: impl FnOnce(&Arc<CoreRpc>) -> Result<Res, crate::methods::RpcFault>,
) -> Result<Res, String>
where
    Req: serde::Serialize,
    Res: serde::de::DeserializeOwned,
{
    match src {
        Source::Live(core) => live(core).map_err(|e| format!("{e:?}")),
        Source::Remote { address, timeout } => {
            let body = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "0",
                "method": method,
                "params": request,
            }))
            .map_err(|e| format!("cannot encode the request: {e}"))?;
            let raw = ctl_client::post_blocking(address, "/json_rpc", body, *timeout)
                .map_err(|(_, reason)| reason)?;
            json_rpc_result::<Res>(&raw, method)
        }
    }
}

fn require_ok(status: &shekyl_rpc_types::RpcStatus) -> Result<(), String> {
    if status.is_ok() {
        Ok(())
    } else {
        Err(status.0.clone())
    }
}

/// Unwrap the in-process bridge's own envelope.
///
/// `dispatch_jsonrpc_we` answers `{"ok":true,"result":…}` or
/// `{"ok":false,"error_code":…,"error_message":…}` — **not** a JSON-RPC 2.0
/// envelope, which is what the remote arm gets from the HTTP listener. Two
/// shapes for one method because the bridge is not the transport; keeping the
/// unwrapping in two named functions is what stops the difference being
/// rediscovered at each new bridged leg.
fn ffi_json_rpc_result<T: serde::de::DeserializeOwned>(
    raw: &str,
    method: &str,
) -> Result<T, String> {
    let envelope: crate::types::FfiJsonRpcResult =
        serde_json::from_str(raw).map_err(|e| format!("malformed {method} reply: {e}"))?;
    if !envelope.ok {
        return Err(envelope
            .error_message
            .unwrap_or_else(|| format!("{method} failed")));
    }
    let result = envelope
        .result
        .ok_or_else(|| format!("malformed {method} reply: ok with no result"))?;
    serde_json::from_value(result).map_err(|e| format!("malformed {method} reply: {e}"))
}

/// The wide difficulty as a number, or `None` if the daemon sent something
/// unreadable.
///
/// [`wide_difficulty_decimal`] is this plus a fallback to the raw string;
/// the two exist apart because summing needs the number and rendering needs
/// something to print either way.
fn wide_difficulty_value(wide: &str) -> Option<u128> {
    u128::from_str_radix(wide.strip_prefix("0x").unwrap_or(wide), 16).ok()
}

fn print_height(src: &Source) -> Result<String, String> {
    let reply = match src {
        Source::Live(core) => {
            let facts = FfiChainFacts::new(core.clone());
            crate::methods::get_height(&facts).map_err(|e| format!("{e:?}"))?
        }
        Source::Remote { address, timeout } => {
            let body = ctl_client::post_blocking(address, "/get_height", b"{}".to_vec(), *timeout)
                .map_err(|(_, reason)| reason)?;
            decode_reply::<GetHeightResponse>(&body, "get_height")?
        }
    };
    if !reply.status.is_ok() {
        return Err(reply.status.0);
    }
    Ok(reply.height.to_string())
}

/// `print_transaction <hash> [+meta] [+hex] [+json]` — RK-4c. Reads
/// `get_transactions` and nothing else, which is why it migrates with it
/// (§2.1).
///
/// The C++ rendered the JSON client-side: it parsed the hex back into a
/// transaction and called `obj_to_json_str` locally. Here the daemon is asked
/// for it (`decode_as_json`) and the reply's `as_json` is printed. Same
/// string — both are epee over the same transaction — and it works on the
/// remote arm, which has no core to render with.
fn print_transaction(src: &Source, args: &[String]) -> Result<String, String> {
    let Some(hash) = args.first() else {
        return Err("Invalid syntax: At least one parameter expected. For more                     details, use the help command."
            .to_owned());
    };
    let (mut meta, mut hex_out, mut json_out) = (false, false, false);
    for flag in &args[1..] {
        match flag.as_str() {
            "+meta" => meta = true,
            "+hex" => hex_out = true,
            "+json" => json_out = true,
            other => {
                return Err(format!(
                    "Invalid syntax: Unexpected parameter: {other}. For more                      details, use the help command."
                ))
            }
        }
    }
    // `split` is not a display preference here, it is what makes the
    // "(pruned)" label answerable. The label asks whether the daemon holds
    // this transaction's prunable half, and reads `prunable_as_hex` to decide
    // — a field only the split form fills. Ask for the whole transaction
    // instead and the halves arrive concatenated in `as_hex` with
    // `prunable_as_hex` empty, which is indistinguishable from "pruned" and
    // would label every ordinary confirmed transaction as such. The C++
    // console set `req.split = true` for the same reason; the rendering below
    // already reassembles the halves.
    let request = shekyl_rpc_types::GetTransactionsRequest {
        txs_hashes: vec![hash.clone()],
        decode_as_json: json_out,
        prune: false,
        split: true,
    };
    let reply = fetch_transactions(src, &request)?;
    if !reply.status.is_ok() {
        return Err(reply.status.0);
    }
    // Exactly one, not "at least one": this command requested a single
    // hash. Empty is "not found"; extra entries are a malformed reply,
    // same shape as `is_key_image_spent` beside it.
    // A count is not a binding. The daemon is untrusted here, so the entry
    // must be the one that was asked for: `parse_tx_batch` holds the wallet's
    // consumers to the same rule, and a console that printed whatever came
    // back would answer a question the operator did not ask.
    if !reply.missed_tx.is_empty() {
        return Err(format!("Transaction wasn't found: {hash}"));
    }
    let tx = match reply.txs.as_slice() {
        [] => return Err(format!("Transaction wasn't found: {hash}")),
        [tx] => tx,
        _ => {
            return Err(format!(
                "print_transaction: asked about 1 transaction, got {}",
                reply.txs.len()
            ))
        }
    };
    if !tx.tx_hash.to_string().eq_ignore_ascii_case(hash) {
        return Err(format!(
            "print_transaction: asked about {hash}, got {}",
            tx.tx_hash
        ));
    }

    // The label check above says the daemon *claims* this entry answers the
    // request; it does not make it so — every field of the reply is the
    // daemon's to choose, and the remote arm posts wherever the operator
    // pointed it. So the body is bound the way `parse_tx_batch` binds the
    // wallet's: parse the bytes and recompute the identity. A reply carrying
    // its prunable half (or a transaction with nothing prunable) rehashes
    // whole; a storage-pruned body mixes the reply's `prunable_hash` in,
    // which turns a substituted body into a keccak preimage instead of a
    // free choice. `as_json` stays unverified: it is the daemon's epee
    // rendering of the same bytes the binding just checked (RK-D11).
    //
    // "(pruned)" below means the daemon holds no prunable half for a
    // transaction that has one — `prunable_hash` distinguishes that from a
    // coinbase, which has nothing prunable to begin with and whose hash is
    // null or the hash of the empty string.
    let pruned = tx.prunable_as_hex.is_empty() && !is_empty_prunable(&tx.prunable_hash);
    let full_hex = if tx.as_hex.is_empty() {
        format!("{}{}", tx.pruned_as_hex, tx.prunable_as_hex)
    } else {
        tx.as_hex.clone()
    };
    let blob = hex::decode(&full_hex)
        .map_err(|_| format!("print_transaction: the daemon's body for {hash} is not hex"))?;
    let parsed = shekyl_wire::Transaction::from_bytes(&blob).map_err(|_| {
        format!("print_transaction: the daemon's body for {hash} is not a transaction")
    })?;
    let derived = if pruned {
        parsed.hash_with_supplied_prunable(tx.prunable_hash.to_bytes())
    } else {
        parsed.hash()
    };
    let derived_hex = hex::encode(derived);
    if !derived_hex.eq_ignore_ascii_case(hash) {
        return Err(format!(
            "print_transaction: the entry is labeled {hash} but its body hashes \
             to {derived_hex} — a label is not an identity"
        ));
    }

    let mut out = Vec::new();
    match &tx.location {
        shekyl_rpc_types::TxLocation::Pooled { .. } => out.push("Found in pool".to_owned()),
        shekyl_rpc_types::TxLocation::Mined { block_height, .. } => {
            out.push(format!(
                "Found in blockchain at height {block_height}{}",
                if pruned { " (pruned)" } else { "" }
            ));
        }
    }

    if meta {
        if let shekyl_rpc_types::TxLocation::Mined {
            block_timestamp, ..
        } = &tx.location
        {
            out.push(format!(
                "Block timestamp: {block_timestamp} ({})",
                human_readable_timestamp(*block_timestamp)
            ));
        }
        // The parse is the binding's, above — a body that did not parse (or
        // did not hash to the request) never reached this rendering, so the
        // old "Error parsing transaction" soft lines have no input left.
        out.push(format!("Size: {}", blob.len()));
        out.push(format!("Weight: {}", parsed.weight()));
    }
    if hex_out {
        out.push(full_hex);
    }
    if json_out {
        out.push(tx.as_json.clone());
    }
    Ok(out.join("\n"))
}

/// A `prunable_hash` that means "there was nothing prunable" rather than "the
/// prunable half was dropped": all-zero, or the hash of the empty string,
/// which is what a transaction with no prunable part carries.
///
/// The constant is `crypto::cn_fast_hash("", 0)`, the expression the C++
/// console computed once into a static. **Measured, not assumed** — an
/// earlier draft of this function carried a plausible-looking wrong value,
/// which would have printed "(pruned)" for transactions that are not:
///
/// ```text
/// crypto::hash h = crypto::cn_fast_hash("", 0);   // -> c5d24601…d85a470
/// ```
const EMPTY_PRUNABLE_HASH: &str =
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

fn is_empty_prunable(h: &shekyl_rpc_types::HashHex) -> bool {
    h.is_zero() || h.to_string() == EMPTY_PRUNABLE_HASH
}

/// `is_key_image_spent <key_image>` — RK-4c. Reads that method only.
fn is_key_image_spent(src: &Source, args: &[String]) -> Result<String, String> {
    let Some(ki) = args.first() else {
        return Err("Invalid syntax: At least one parameter expected. For more                     details, use the help command."
            .to_owned());
    };
    let request = shekyl_rpc_types::IsKeyImageSpentRequest {
        key_images: vec![ki.clone()],
    };
    let reply = match src {
        // Direct, for `fetch_transactions`'s reason: the C++ route is gone.
        Source::Live(core) => {
            let ids = crate::methods::parse_request_hashes(
                &request.key_images,
                crate::methods::KI_PARSE_FAILED,
            )?;
            let raw = core
                .key_images_spent(&ids)
                .map_err(|rc| format!("is_key_image_spent: facts unavailable ({rc})"))?;
            let mut spent_status = Vec::with_capacity(raw.len());
            for s in raw {
                spent_status.push(
                    shekyl_rpc_types::KeyImageStatus::try_from(s)
                        .map_err(|e| format!("is_key_image_spent: {e}"))?,
                );
            }
            shekyl_rpc_types::IsKeyImageSpentResponse {
                status: shekyl_rpc_types::RpcStatus::ok(),
                spent_status,
            }
        }
        Source::Remote { address, timeout } => {
            let body = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
            let raw = ctl_client::post_blocking(address, "/is_key_image_spent", body, *timeout)
                .map_err(|(_, reason)| reason)?;
            // Through `decode_reply`, as `print_height` does: a native handler
            // reports failure as a `RestErrorEnvelope`, and a success-only
            // decode turns the server's stated reason into "malformed reply".
            // Refusing unknown fields made that worse, not better — the
            // envelope's `error` is exactly the field this type does not model.
            decode_reply::<shekyl_rpc_types::IsKeyImageSpentResponse>(&raw, "is_key_image_spent")?
        }
    };
    if !reply.status.is_ok() {
        return Err(reply.status.0);
    }
    // Exactly one, not "at least one": the request carries one key image, the
    // reply is positional, and a reply of a different length is unreadable
    // rather than partially readable — the property the type's own doc names.
    let [status] = reply.spent_status.as_slice() else {
        return Err(format!(
            "is_key_image_spent: asked about 1 key image, got {} statuses",
            reply.spent_status.len()
        ));
    };
    Ok(format!(
        "{ki}: {}",
        match status {
            shekyl_rpc_types::KeyImageStatus::Unspent => "unspent",
            shekyl_rpc_types::KeyImageStatus::SpentInBlockchain => "spent",
            shekyl_rpc_types::KeyImageStatus::SpentInPool => "spent (in pool)",
        }
    ))
}

/// The `get_transactions` fetch, shared by the console commands that need it.
///
/// The live arm calls the facts path and the projection **directly**, as
/// `print_block` does — not `json_endpoint`, which dispatches through the C++
/// JSON table this slice empties. Naming a route by string there would have
/// compiled and then answered "no reply" the moment the route left C++, which
/// is exactly what it did until Copilot caught it on this PR. Calling the
/// Rust functions makes that class of breakage a compile error.
///
/// The console is the operator's own node, so the pool read is unrestricted —
/// the same answer the C++ gave a null `ctx` (§7, 2026-08-26).
fn fetch_transactions(
    src: &Source,
    request: &shekyl_rpc_types::GetTransactionsRequest,
) -> Result<shekyl_rpc_types::GetTransactionsResponse, String> {
    match src {
        Source::Live(core) => {
            let ids = crate::methods::parse_request_hashes(
                &request.txs_hashes,
                crate::methods::TX_PARSE_FAILED,
            )?;
            let (slots, chain_height) = core
                .transactions(&ids, true)
                .map_err(|rc| format!("get_transactions: facts unavailable ({rc})"))?;
            crate::methods::project_transactions(
                request,
                &ids,
                &slots,
                chain_height,
                |blob, pruned| core.tx_to_json(blob, pruned),
            )
            .map_err(|f| format!("could not decode {} to json ({})", f.txid, f.code))
        }
        Source::Remote { address, timeout } => {
            let body = serde_json::to_vec(request).map_err(|e| e.to_string())?;
            let raw = ctl_client::post_blocking(address, "/get_transactions", body, *timeout)
                .map_err(|(_, reason)| reason)?;
            // See the `is_key_image_spent` arm: a native handler's failure is a
            // `RestErrorEnvelope`, so decoding success-only reports "malformed"
            // over the reason the server actually gave.
            decode_reply::<shekyl_rpc_types::GetTransactionsResponse>(&raw, "get_transactions")
        }
    }
}

/// Run one console command and hand back its rendered output.
///
/// * `argv` / `argc` — the command and its arguments; `argv[0]` selects.
/// * `rpc_server_ptr` — the live `core_rpc_server` when running inside the
///   daemon, else null.
/// * `address` — `host:port` of the daemon's RPC when running as
///   `shekyld <command>`, else null. Exactly one of the two is set.
/// * `timeout_secs` — per-request bound for the remote arm.
/// * `out_ptr` / `out_len` — on `OK` the text to print; on `ERR_REQUEST` the
///   reason. Release with `shekyl_daemon_ctl_free` (null/0 is a no-op).
///
/// # Safety
///
/// `argv` must point to `argc` valid NUL-terminated C strings; `address`
/// must be null or a valid C string; `rpc_server_ptr` must be null or a live
/// `core_rpc_server`; `out_ptr` / `out_len` must be valid for writes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_daemon_console_run(
    argv: *const *const c_char,
    argc: usize,
    rpc_server_ptr: *mut c_void,
    address: *const c_char,
    timeout_secs: u64,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if out_ptr.is_null() || out_len.is_null() {
        return SHEKYL_DAEMON_CONSOLE_ERR_NULL_PTR;
    }
    out_ptr.write(std::ptr::null_mut());
    out_len.write(0);
    if argv.is_null() || argc == 0 {
        return SHEKYL_DAEMON_CONSOLE_ERR_NULL_PTR;
    }
    let mut args = Vec::with_capacity(argc);
    for i in 0..argc {
        let p = *argv.add(i);
        let Some(s) = ctl_client::c_string(p) else {
            return SHEKYL_DAEMON_CONSOLE_ERR_NULL_PTR;
        };
        args.push(s);
    }
    // Exactly one source. Silently preferring one when both are given would
    // make the same argv render from different daemons depending on which
    // caller forgot to null the other — refuse instead.
    if !rpc_server_ptr.is_null() && !address.is_null() {
        return SHEKYL_DAEMON_CONSOLE_ERR_AMBIGUOUS_SOURCE;
    }
    let source = if !rpc_server_ptr.is_null() {
        match CoreRpc::from_raw(rpc_server_ptr) {
            Some(core) => Source::Live(Arc::new(core)),
            None => return SHEKYL_DAEMON_CONSOLE_ERR_NULL_PTR,
        }
    } else {
        match ctl_client::c_string(address) {
            Some(address) => Source::Remote {
                address,
                timeout: Duration::from_secs(timeout_secs),
            },
            None => return SHEKYL_DAEMON_CONSOLE_ERR_NULL_PTR,
        }
    };

    let result = match args[0].as_str() {
        "print_height" => print_height(&source),
        "print_block_by_hash" | "print_block_by_height" => {
            let Some(argument) = args.get(1) else {
                return SHEKYL_DAEMON_CONSOLE_ERR_UNKNOWN;
            };
            let by_hash = args[0] == "print_block_by_hash";
            let include_hex = args.get(2).is_some_and(|f| f == "+hex");
            print_block(&source, by_hash, argument, include_hex)
        }
        "print_transaction" => print_transaction(&source, &args[1..]),
        "is_key_image_spent" => is_key_image_spent(&source, &args[1..]),
        // RK-5a. `now` is read once here rather than inside each renderer, so
        // a command's whole output describes one instant.
        "print_peer_list" => {
            let (white, gray) = peer_list_selection(args.get(1).map(String::as_str));
            let limit = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(0);
            let pruned_only = args.iter().any(|a| a == "pruned");
            print_peer_list(&source, white, gray, limit, pruned_only, unix_now())
        }
        "print_peer_list_stats" => print_peer_list_stats(&source),
        "print_connections" => print_connections(&source),
        "print_net_stats" => print_net_stats(&source, unix_now()),
        "sync_info" => sync_info(&source),
        // RK-5b. The C++ parser has already validated and normalized these
        // arguments (`command_parser_executor.cpp`), and the executor
        // forwards them as strings — so a value that does not parse here is
        // the bridge disagreeing with itself, not an operator typo, and it
        // refuses rather than defaulting.
        "print_blockchain_info" => {
            let (Some(start), Some(end)) = (
                args.get(1).and_then(|a| a.parse::<i64>().ok()),
                args.get(2).and_then(|a| a.parse::<u64>().ok()),
            ) else {
                return SHEKYL_DAEMON_CONSOLE_ERR_UNKNOWN;
            };
            print_blockchain_info(&source, start, end)
        }
        "print_blockchain_dynamic_stats" => {
            let Some(nblocks) = args.get(1).and_then(|a| a.parse::<u64>().ok()) else {
                return SHEKYL_DAEMON_CONSOLE_ERR_UNKNOWN;
            };
            print_blockchain_dynamic_stats(&source, nblocks)
        }
        // The C++ parser resolves the single optional argument into three:
        // a tip hash, a `>above` filter, or a `-last_blocks` filter.
        "alt_chain_info" => {
            let (Some(tip), Some(above), Some(last_blocks)) = (
                args.get(1),
                args.get(2).and_then(|a| a.parse::<u64>().ok()),
                args.get(3).and_then(|a| a.parse::<u64>().ok()),
            ) else {
                return SHEKYL_DAEMON_CONSOLE_ERR_UNKNOWN;
            };
            alt_chain_info(&source, tip, above, last_blocks, unix_now())
        }
        "status" => show_status(&source, unix_now()),
        // The C++ parser accepts no argument or 1..=255 and forwards 0 for
        // the first; `None` asks about the fork the daemon would vote in
        // next, which is what a zero meant.
        "hard_fork_info" => {
            let Some(version) = args.get(1).and_then(|a| a.parse::<u8>().ok()) else {
                return SHEKYL_DAEMON_CONSOLE_ERR_UNKNOWN;
            };
            // `NonZeroU8::new` *is* the "0 means the next fork" rule, so the
            // console no longer spells it out: the sentinel cannot survive
            // into the request type.
            hard_fork_info(&source, core::num::NonZeroU8::new(version))
        }
        _ => return SHEKYL_DAEMON_CONSOLE_ERR_UNKNOWN,
    };
    match result {
        Ok(text) => {
            ctl_client::emit(text.into_bytes(), out_ptr, out_len);
            SHEKYL_DAEMON_CONSOLE_OK
        }
        Err(reason) => {
            ctl_client::emit(reason.into_bytes(), out_ptr, out_len);
            SHEKYL_DAEMON_CONSOLE_ERR_REQUEST
        }
    }
}

/// Unix seconds, read once per console command so a whole rendering
/// describes one instant.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ── RK-5a: the p2p console commands ─────────────────────────────────────────
//
// Five commands, four methods. Console output is not a wire contract, so the
// layouts below are rationalized rather than transcribed — but every *value*
// is the value the C++ printed, and the pinned tests are on values.
//
// Two things the C++ layout got wrong that are not reproduced.
// `print_connections` computed a `host_field_width` from the widest address
// and then wrote `setw(30)` anyway, so the computation had no effect; and it
// composed the address column as `ip + ":" + port`, which for a tor peer —
// where both are empty by construction — printed `OUT :`. The address column
// here uses `address`, which is populated for every arm.

/// Format a float for a human: fixed precision, then trailing zeros and a
/// bare trailing dot removed.
///
/// Rust's `{}` on an `f64` prints the shortest string that round-trips, which
/// is exactly the wrong property for a display — `7.0 / 1000.0 * 100.0`
/// renders `0.7000000000000001`. The C++ printed through an ostream at its
/// six-significant-digit default; this is not that, and does not try to be
/// (console output is not a wire contract). What it is is bounded: the noise
/// cannot reach the operator, and a value that is exactly round still reads
/// round.
fn trimmed(value: f64, decimals: usize) -> String {
    let s = format!("{value:.decimals$}");
    match s.find('.') {
        Some(_) => s.trim_end_matches('0').trim_end_matches('.').to_owned(),
        None => s,
    }
}

/// `d<days>.h<hours>.m<minutes>.s<seconds>`, as
/// `epee::misc_utils::get_time_interval_string` formats it.
fn time_interval(seconds: u64) -> String {
    let days = seconds / 86400;
    let rest = seconds % 86400;
    let hours = rest / 3600;
    let rest = rest % 3600;
    format!("d{days}.h{hours}.m{}.s{}", rest / 60, rest % 60)
}

/// `tools::get_human_readable_bytes`: base-2 units, `B` with no decimals and
/// every larger unit with two.
fn human_readable_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    #[expect(
        clippy::cast_precision_loss,
        reason = "a display string; the C++ casts to double here too"
    )]
    let value = bytes as f64;
    if bytes < 1024 {
        return format!("{value:.0} B");
    }
    for (limit, unit, divisor) in [
        (1024u64 * 1024, "kB", KIB),
        (1024 * 1024 * 1024, "MB", KIB * KIB),
        (1024 * 1024 * 1024 * 1024, "GB", KIB * KIB * KIB),
    ] {
        if bytes < limit {
            return format!("{:.2} {unit}", value / divisor);
        }
    }
    format!("{:.2} TB", value / (KIB * KIB * KIB * KIB))
}

/// `tools::get_human_readable_timespan`: seconds below a minute, otherwise
/// one decimal place in the largest unit that fits.
fn human_readable_timespan(seconds: u64) -> String {
    #[expect(
        clippy::cast_precision_loss,
        reason = "a display string; the C++ casts to float here too"
    )]
    let s = seconds as f64;
    const MINUTE: f64 = 60.0;
    const HOUR: f64 = 3600.0;
    const DAY: f64 = 3600.0 * 24.0;
    // The C++ uses 30.5 days for a month and 365.25 for a year, and the
    // boundaries are the same expressions — so the unit a value falls into is
    // decided by the same arithmetic that then divides it.
    const MONTH: f64 = DAY * 30.5;
    const YEAR: f64 = DAY * 365.25;
    if s < MINUTE {
        return format!("{seconds} seconds");
    }
    for (limit, divisor, unit) in [
        (HOUR, MINUTE, "minutes"),
        (DAY, HOUR, "hours"),
        (MONTH, DAY, "days"),
        (YEAR, MONTH, "months"),
        (YEAR * 100.0, YEAR, "years"),
    ] {
        if s < limit {
            return format!("{:.1} {unit}", s / divisor);
        }
    }
    "a long time".to_owned()
}

/// What the console passes for `public_only`: the whole peerlist. Named
/// rather than written twice as a bare `false`, so the two commands cannot
/// drift apart — `print_pl` and `print_pl_stats` reporting different lists
/// would read as a peerlist that changed between two adjacent commands.
const PUBLIC_ONLY: bool = false;

/// The peerlist as the console asks for it.
///
/// Blocked peers included, because the operator asking for the peer list is
/// the one person who wants to see them — and **the whole list, not the
/// public part of it**, which is what both C++ callers asked for. That is
/// worth spelling out because the wire default is the opposite and reading
/// the struct suggests otherwise: `public_only` is `KV_SERIALIZE_OPT(…,
/// true)`, but an `OPT` default is applied when *deserializing* a document
/// that omits the field, and the console never deserialized one — it filled
/// an `epee::misc_utils::struct_init` request, which value-initializes, so
/// `public_only` was `false` on the in-process arm and serialized as an
/// explicit `false` on the RPC arm. `print_pl_stats` also wrote `= false`
/// outright. Asking for the public list here would silently drop the
/// non-public zones from `print_pl` and leave it disagreeing with the counts
/// `print_pl_stats` prints.
fn fetch_peer_list(
    src: &Source,
    public_only: bool,
) -> Result<shekyl_rpc_types::GetPeerListResponse, String> {
    let request = shekyl_rpc_types::GetPeerListRequest {
        public_only,
        include_blocked: true,
    };
    let reply = match src {
        Source::Live(core) => {
            let facts = crate::chain_facts::FfiP2pFacts::new(core.clone());
            crate::methods::get_peer_list(&request, &facts).map_err(|e| format!("{e:?}"))?
        }
        Source::Remote { address, timeout } => {
            let body = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
            let raw = ctl_client::post_blocking(address, "/get_peer_list", body, *timeout)
                .map_err(|(_, reason)| reason)?;
            decode_reply::<shekyl_rpc_types::GetPeerListResponse>(&raw, "get_peer_list")?
        }
    };
    if !reply.status.is_ok() {
        return Err(reply.status.0);
    }
    Ok(reply)
}

#[deny(clippy::arithmetic_side_effects)]
fn render_peer(prefix: &str, peer: &shekyl_rpc_types::Peer, now: u64) -> String {
    let elapsed = if peer.last_seen == 0 {
        // Not "d19000.h..." — a peer never seen has no interval, and the C++
        // says so too.
        "never".to_owned()
    } else {
        time_interval(now.saturating_sub(peer.last_seen))
    };
    // `host` means three different things across the address arms, and only
    // two of them leave a port to append. On the third — tor, i2p — `host` is
    // the whole `network_address::str()`, which *already ends in a port*, and
    // `port` is 0; the C++ appended anyway and printed
    // `abcdefghijklmnop.onion:18080:0`. An inherited rendering, not a
    // regression, and corrected here rather than carried (rule 16).
    let addr = if peer.port == 0 {
        peer.host.clone()
    } else {
        format!("{}:{}", peer.host, peer.port)
    };
    format!(
        "{prefix:<10} {:016x} {addr:<25} {:<4x} {elapsed}",
        peer.id, peer.pruning_seed
    )
}

/// Which lists `print_peer_list` prints, from the selector argument.
///
/// Only `white` and `gray` narrow. Anything else — including no selector at
/// all — means both, which is what the C++ parser resolves an unqualified
/// `print_pl` to. Defaulting to *neither* is the failure worth naming: a
/// mis-sent argument would print an empty result that reads exactly like an
/// empty peerlist, so the command would lie rather than complain.
///
/// A function rather than two expressions at the call site because the call
/// site needs a live daemon and a populated peerlist to observe, and a
/// loopback node never populates one — local addresses are not appended to
/// the peerlist, so the arms are indistinguishable on any single-host rig.
fn peer_list_selection(selector: Option<&str>) -> (bool, bool) {
    (selector != Some("gray"), selector != Some("white"))
}

/// `print_peer_list [white|gray] [limit] [pruned]`.
///
/// `limit` applies **per list**, not to the pair, and `pruned` filters
/// unpruned peers out client-side — both as the C++ did.
#[deny(clippy::arithmetic_side_effects)]
fn print_peer_list(
    src: &Source,
    white: bool,
    gray: bool,
    limit: usize,
    pruned_only: bool,
    now: u64,
) -> Result<String, String> {
    let reply = fetch_peer_list(src, PUBLIC_ONLY)?;
    let mut out = Vec::new();
    let mut take = |prefix: &str, peers: &[shekyl_rpc_types::Peer]| {
        // `take` **before** `filter`: `limit` bounds the peers examined, not
        // the peers printed. That is the C++ order — it advanced an iterator
        // `limit` entries and let `print_peer` skip the unpruned ones inside
        // the loop — so `print_pl 5 pruned` shows the pruned peers among the
        // first five, not the first five pruned peers.
        for peer in peers
            .iter()
            .take(if limit == 0 { usize::MAX } else { limit })
            .filter(|p| !pruned_only || p.pruning_seed != 0)
        {
            out.push(render_peer(prefix, peer, now));
        }
    };
    if white {
        take("white", &reply.white_list);
    }
    if gray {
        take("gray", &reply.gray_list);
    }
    Ok(out.join("\n"))
}

/// `print_pl_stats`: how full each list is.
#[deny(clippy::arithmetic_side_effects)]
fn print_peer_list_stats(src: &Source) -> Result<String, String> {
    let reply = fetch_peer_list(src, PUBLIC_ONLY)?;
    let (white_limit, gray_limit) = CoreRpc::peerlist_limits();
    Ok(render_peer_list_stats(
        reply.white_list.len(),
        reply.gray_list.len(),
        white_limit,
        gray_limit,
    ))
}

/// The rendering, over values a caller states.
///
/// **Split out so the capacities are a parameter rather than an ambient FFI
/// read.** `shekyl_rpc_peerlist_limits` is a bare `#[no_mangle]` symbol whose
/// unit-test link stub answers 0, and `ffi.rs` carries a comment saying no
/// unit test may take an answer from it — a prohibition with nothing enforcing
/// it, which is how `fee_grace_blocks_max` was later added without inheriting
/// the rule. Hoisting the read to the caller makes the prohibition
/// unnecessary rather than unenforced: this function can be tested with real
/// values, and the symbol is read in exactly one place.
fn render_peer_list_stats(white: usize, gray: usize, white_limit: u32, gray_limit: u32) -> String {
    let line = |name: &str, size: usize, limit: u32| -> String {
        let percent = if limit == 0 {
            0.0
        } else {
            #[expect(
                clippy::cast_precision_loss,
                reason = "a percentage for a human, from two small counts"
            )]
            let fraction = size as f64 / f64::from(limit);
            fraction * 100.0
        };
        format!(
            "{name} list size: {size}/{limit} ({}%)",
            trimmed(percent, 4)
        )
    };
    format!(
        "{}\n{}",
        line("White", white, white_limit),
        line("Gray", gray, gray_limit)
    )
}

/// `print_connections`.
#[deny(clippy::arithmetic_side_effects)]
fn print_connections(src: &Source) -> Result<String, String> {
    let reply = native_json_rpc(src, "get_connections", &serde_json::json!({}), |core| {
        crate::methods::get_connections(&crate::chain_facts::FfiP2pFacts::new(core.clone()))
    })?;
    require_ok(&reply.status)?;
    // Wide enough for the widest address actually present, plus the four
    // characters of the `INC `/`OUT ` prefix and a two-column gutter — the
    // computation the C++ did and then ignored in favour of a fixed `setw(30)`
    // that its own prefix could overrun.
    let width = reply
        .connections
        .iter()
        .map(|c| c.address.len().saturating_add(6))
        .max()
        .unwrap_or(0)
        .max(21);
    let mut out = vec![format!(
        "{:<width$}{:<8}{:<20}{:<15}{:<30}{:<18}{:<15}{:<12}{:<14}{:<10}{}",
        "Remote Host",
        "Type",
        "Peer id",
        "Support Flags",
        "Recv/Sent (inactive,sec)",
        "State",
        "Livetime(sec)",
        "Down (kB/s)",
        "Down(now)",
        "Up (kB/s)",
        "Up(now)"
    )];
    for c in &reply.connections {
        let direction = if c.incoming { "INC " } else { "OUT " };
        let tail = format!(
            "{}{}",
            if c.localhost { "[LOCALHOST]" } else { "" },
            if c.local_ip { "[LAN]" } else { "" }
        );
        out.push(format!(
            "{:<width$}{:<8}{:<20}{:<15}{:<30}{:<18}{:<15}{:<12}{:<14}{:<10}{:<8}{tail}",
            format!("{direction}{}", c.address),
            address_type_name(c.address_type),
            c.peer_id,
            c.support_flags,
            format!(
                "{}({})/{}({})",
                c.recv_count, c.recv_idle_time, c.send_count, c.send_idle_time
            ),
            c.state.as_str(),
            c.live_time,
            c.avg_download,
            c.current_download,
            c.avg_upload,
            c.current_upload,
        ));
    }
    Ok(out.join("\n"))
}

/// `get_address_type_name`'s mapping, as the console printed it — including
/// its lower-case `invalid`, which is the only arm whose spelling differs
/// from the others. Carried verbatim; the C++ it came from is deleted, so
/// this is the definition now rather than a second copy of one.
fn address_type_name(address_type: u8) -> &'static str {
    match address_type {
        1 => "IPv4",
        2 => "IPv6",
        3 => "I2P",
        4 => "Tor",
        _ => "invalid",
    }
}

/// The `/get_limit` reply, as much of it as `print_net_stats` reads.
///
/// **A bridged leg, on purpose** (§2.1.1): `/get_limit` is RK-8's, and until
/// that slice lands it is still served from the C++ dispatch table. The
/// condition that makes this safe is that the leg names a route the table
/// really serves *and* that the console gate covers this command — so the
/// slice that deletes the route turns this red rather than leaving it
/// answering "no reply" forever. Both are in place; when RK-8 moves the
/// route, this struct is replaced by the shared type.
///
/// **Neither field carries `#[serde(default)]`, and that is the second half
/// of the guarantee.** Route deletion is the loud failure the `ok_or_else`
/// above catches; a *rename or removal of a field* is the quiet one, and a
/// default would absorb it — `print_net_stats` would report `0` up and `0`
/// down, a real number the daemon does not hold, with no error and no red
/// test. Required fields turn that into a deserialization error naming the
/// field that moved. Both are `KV_SERIALIZE` (not `_OPT`) in
/// `COMMAND_RPC_GET_LIMIT::response_t`, so the reply always carries them and
/// absence can only mean the contract moved.
#[derive(serde::Deserialize)]
struct GetLimitReplyProvisional {
    limit_up: u64,
    limit_down: u64,
}

/// `print_net_stats`.
#[deny(clippy::arithmetic_side_effects)]
fn print_net_stats(src: &Source, now: u64) -> Result<String, String> {
    let (stats, limits) = match src {
        Source::Live(core) => {
            let facts = crate::chain_facts::FfiP2pFacts::new(core.clone());
            let stats = crate::methods::get_net_stats(&facts).map_err(|e| format!("{e:?}"))?;
            let raw = core
                .json_endpoint("/get_limit", "{}")
                .ok_or_else(|| "no reply from /get_limit".to_owned())?;
            let limits: GetLimitReplyProvisional = serde_json::from_str(&raw)
                .map_err(|e| format!("malformed get_limit reply: {e}"))?;
            (stats, limits)
        }
        Source::Remote { address, timeout } => {
            let raw =
                ctl_client::post_blocking(address, "/get_net_stats", b"{}".to_vec(), *timeout)
                    .map_err(|(_, reason)| reason)?;
            let stats =
                decode_reply::<shekyl_rpc_types::GetNetStatsResponse>(&raw, "get_net_stats")?;
            let raw = ctl_client::post_blocking(address, "/get_limit", b"{}".to_vec(), *timeout)
                .map_err(|(_, reason)| reason)?;
            let limits: GetLimitReplyProvisional = serde_json::from_slice(&raw)
                .map_err(|e| format!("malformed get_limit reply: {e}"))?;
            (stats, limits)
        }
    };
    if !stats.status.is_ok() {
        return Err(stats.status.0);
    }
    let seconds = now.saturating_sub(stats.start_time);
    let line = |verb: &str, bytes: u64, packets: u64, limit_kb: u64| -> String {
        // Total by construction rather than guarded; see `methods::average_kib`.
        let average = bytes.checked_div(seconds).unwrap_or(0);
        // `/set_limit` takes an `int64_t` and passes any positive value
        // straight to `set_rate_down_limit`, so `limit_kb` is whatever an
        // admin typed — and `limit_kb * 1024` overflows above `u64::MAX /
        // 1024`. Saturating, like every other peer- or admin-influenced
        // arithmetic in this file.
        let limit = limit_kb.saturating_mul(1024);
        let percent = if limit == 0 {
            0.0
        } else {
            #[expect(
                clippy::cast_precision_loss,
                reason = "a percentage for a human, from byte counts"
            )]
            let fraction = average as f64 / limit as f64;
            fraction * 100.0
        };
        format!(
            "{verb} {bytes} bytes ({}) in {packets} packets in {}, average {}/s = {percent:.2}% of the limit of {}/s",
            human_readable_bytes(bytes),
            human_readable_timespan(seconds),
            human_readable_bytes(average),
            human_readable_bytes(limit)
        )
    };
    Ok(format!(
        "{}\n{}",
        line(
            "Received",
            stats.total_bytes_in,
            stats.total_packets_in,
            limits.limit_down
        ),
        line(
            "Sent",
            stats.total_bytes_out,
            stats.total_packets_out,
            limits.limit_up
        )
    ))
}

/// `sync_info`.
#[deny(clippy::arithmetic_side_effects)]
fn sync_info(src: &Source) -> Result<String, String> {
    let reply = native_json_rpc(src, "sync_info", &serde_json::json!({}), |core| {
        let chain = FfiChainFacts::new(core.clone());
        let p2p = crate::chain_facts::FfiP2pFacts::new(core.clone());
        crate::methods::sync_info(&chain, &p2p)
    })?;
    require_ok(&reply.status)?;
    // A target below our own height means we are ahead of what we were told
    // to reach; the progress line uses our height so the percentage cannot
    // exceed 100 or divide by zero.
    let target = reply.target_height.max(reply.height).max(1);
    #[expect(
        clippy::cast_precision_loss,
        reason = "a percentage for a human, from two heights"
    )]
    let progress = (reply.height as f64 / target as f64) * 100.0;
    let mut out = vec![format!(
        "Height: {}, target: {target} ({}%)",
        reply.height,
        trimmed(progress, 4)
    )];
    // **Every accumulation in this function saturates**, and the reason is one
    // step upstream: `kib_per_second` clamps a finite but absurd rate to
    // `u64::MAX` rather than invoking undefined behaviour, so a value near the
    // ceiling is now *reachable* by design. Summing two of them overflows —
    // which in a debug build is a panic unwinding through `extern "C"`, i.e.
    // an abort of the daemon, and in release a wrapped number printed as a
    // download rate. Every one of these operands is peer-influenced.
    let current_download: u64 = reply
        .peers
        .iter()
        .fold(0u64, |acc, p| acc.saturating_add(p.info.current_download));
    out.push(format!("Downloading at {current_download} kB/s"));
    if reply.next_needed_pruning_seed != 0 {
        out.push(format!(
            "Next needed pruning seed: {}",
            reply.next_needed_pruning_seed
        ));
    }
    out.push(format!("{} peers", reply.peers.len()));
    out.push(
        "Remote Host                        Peer_ID   State   Prune_Seed          Height  DL kB/s, Queued Blocks / MB"
            .to_owned(),
    );
    for p in &reply.peers {
        let (nblocks, size) = reply
            .spans
            .iter()
            .filter(|s| s.connection_id == p.info.connection_id)
            .fold((0u64, 0u64), |(n, b), s| {
                (n.saturating_add(s.nblocks), b.saturating_add(s.size))
            });
        #[expect(
            clippy::cast_precision_loss,
            reason = "a size for a human, in megabytes"
        )]
        let megabytes = size as f64 / 1e6;
        out.push(format!(
            "{:<24}  {}  {:<16}  {:<8x}  {}  {} kB/s, {nblocks} blocks / {} MB queued",
            p.info.address,
            p.info.peer_id,
            p.info.state.as_str(),
            p.info.pruning_seed,
            p.info.height,
            p.info.current_download,
            trimmed(megabytes, 6),
        ));
    }
    let total: u64 = reply
        .spans
        .iter()
        .fold(0u64, |acc, s| acc.saturating_add(s.size));
    #[expect(
        clippy::cast_precision_loss,
        reason = "a size for a human, in megabytes"
    )]
    let total_mb = total as f64 / 1e6;
    out.push(format!(
        "{} spans, {} MB",
        reply.spans.len(),
        trimmed(total_mb, 6)
    ));
    out.push(reply.overview.clone());
    for s in &reply.spans {
        // Both halves saturate. `nblocks == 0` would make `start + nblocks - 1`
        // wrap through the subtraction, and a span far up the chain would wrap
        // through the addition; the C++ wrote it as one unchecked expression.
        // `render_overview` already saturates the same addition, which is what
        // makes this one an omission rather than a judgement.
        let last = s
            .start_block_height
            .saturating_add(s.nblocks.saturating_sub(1));
        let range = format!("{} - {last}", s.start_block_height);
        // Computed, not carried: the wire `span` has never had this field,
        // and the C++ console derived it the same way from the same height.
        let seed = CoreRpc::span_pruning_seed(s.start_block_height);
        if s.size == 0 {
            out.push(format!(
                "{:<24}  {}/{:x} ({range})  -",
                s.remote_address, s.nblocks, seed
            ));
        } else {
            let speed = f64::from(s.speed) / 100.0;
            out.push(format!(
                "{:<24}  {}/{:x} ({range}, {} kB)  {} kB/s ({})",
                s.remote_address,
                s.nblocks,
                seed,
                s.size / 1000,
                s.rate / 1000,
                trimmed(speed, 2)
            ));
        }
    }
    Ok(out.join("\n"))
}
