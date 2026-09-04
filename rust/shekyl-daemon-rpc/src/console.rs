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

    let reply = match src {
        Source::Live(core) => {
            let facts = FfiChainFacts::new(core.clone());
            // In-process the console is the operator's own terminal, so the
            // restricted-listener rule does not apply: the C++ passed
            // `fill_pow_hash` straight through here too.
            crate::methods::get_block(&facts, &request, true).map_err(|e| format!("{e:?}"))?
        }
        Source::Remote { address, timeout } => {
            let body = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "0",
                "method": "get_block",
                "params": request,
            }))
            .map_err(|e| format!("cannot encode the request: {e}"))?;
            let raw = ctl_client::post_blocking(address, "/json_rpc", body, *timeout)
                .map_err(|(_, reason)| reason)?;
            json_rpc_result::<shekyl_rpc_types::GetBlockResponse>(&raw, "get_block")?
        }
    };
    if !reply.status.is_ok() {
        return Err(reply.status.0);
    }

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
    let reply = match src {
        Source::Live(core) => {
            let facts = crate::chain_facts::FfiP2pFacts::new(core.clone());
            crate::methods::get_connections(&facts).map_err(|e| format!("{e:?}"))?
        }
        Source::Remote { address, timeout } => {
            let body = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "0",
                "method": "get_connections",
            }))
            .map_err(|e| format!("cannot encode the request: {e}"))?;
            let raw = ctl_client::post_blocking(address, "/json_rpc", body, *timeout)
                .map_err(|(_, reason)| reason)?;
            json_rpc_result::<shekyl_rpc_types::GetConnectionsResponse>(&raw, "get_connections")?
        }
    };
    if !reply.status.is_ok() {
        return Err(reply.status.0);
    }
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

// ── RK-5b: the header console commands ──────────────────────────────────────
//
// Four commands, and every one of them crosses to a route this slice does not
// serve. All four read `/get_info`, which is RK-5c's; `alt_chain_info` also
// reads `get_alternate_chains` and `show_status` also reads `/mining_status`,
// which belong to RK-8 and RK-7. Every one of those three names is still in
// the C++ dispatch tables (`core_rpc_ffi.cpp:174`, `:180`, `:284`) — §2.1.1's
// condition — and the tests at the bottom of this file drive all four
// commands on their remote arm, which is the other half of it.
//
// The slice plan said "one bridged `/get_info` leg per crosser", and two of
// the four carry a second leg. Recorded rather than quietly absorbed: a
// bridged leg is a dated liability, and the count is what says how much comes
// home when RK-7 and RK-8 land.

/// The `/get_info` reply, as much of it as the four commands above read.
///
/// **A bridged leg, on purpose** (§2.1.1). One struct rather than four,
/// because RK-5c changes this reply and one struct means one place to fix and
/// four commands that go red together rather than one that goes red and three
/// that go quiet.
///
/// **No field carries `#[serde(default)]`, and RK-5c is the reason.** Route
/// deletion is caught by the `ok_or_else` in [`fetch_get_info`]; a *renamed
/// or removed field* is the quiet failure, and a default would turn it into a
/// confident zero — `show_status` reporting height 0 on a synced daemon. The
/// failure this slice must hand RK-5c is a deserialization error naming the
/// field that moved. Every field below is `KV_SERIALIZE` (not `_OPT`) in
/// `COMMAND_RPC_GET_INFO::response_t`, so absence can only mean the contract
/// moved. Unknown fields are ignored on purpose — RK-5c *adding* a field is
/// not a break, and `/get_info` carries about thirty this console never reads.
///
/// It holds exactly the fields that have a reader, and gains one when a
/// command that reads it lands: a field with no reader is a claim about the
/// reply that nothing checks, and it would make the "four go red together"
/// property above weaker than it looks.
#[derive(serde::Deserialize)]
struct GetInfoReplyProvisional {
    status: shekyl_rpc_types::RpcStatus,
    height: u64,
    /// The DAA's target block time in seconds. Read as **data** rather than
    /// compiled in from `SHEKYL_DAA_TARGET_SECONDS`: the daemon already
    /// reports its own target, and a console built against a different value
    /// than the daemon it is talking to would print a confidently wrong
    /// number rather than fail.
    target: u64,
    wide_difficulty: String,
    wide_cumulative_difficulty: String,
    target_height: u64,
    testnet: bool,
    stagenet: bool,
    /// Zero on a restricted listener, which does not disclose it. Required
    /// all the same — the daemon always sends the field — and the zero is
    /// handled where it is rendered, as the C++ did.
    start_time: u64,
    outgoing_connections_count: u64,
    incoming_connections_count: u64,
}

/// Fetch `/get_info` over whichever arm this console is running on.
fn fetch_get_info(src: &Source) -> Result<GetInfoReplyProvisional, String> {
    let reply: GetInfoReplyProvisional = match src {
        Source::Live(core) => {
            let raw = core
                .json_endpoint("/get_info", "{}")
                .ok_or_else(|| "no reply from /get_info".to_owned())?;
            serde_json::from_str(&raw)
        }
        Source::Remote { address, timeout } => {
            let raw = ctl_client::post_blocking(address, "/get_info", b"{}".to_vec(), *timeout)
                .map_err(|(_, reason)| reason)?;
            serde_json::from_slice(&raw)
        }
    }
    .map_err(|e| format!("malformed get_info reply: {e}"))?;
    if reply.status.is_ok() {
        Ok(reply)
    } else {
        Err(reply.status.0)
    }
}

/// Fetch `get_block_headers_range` — native here, over `/json_rpc` remotely.
fn fetch_block_headers_range(
    src: &Source,
    start_height: u64,
    end_height: u64,
) -> Result<Vec<shekyl_rpc_types::BlockHeader>, String> {
    let request = shekyl_rpc_types::GetBlockHeadersRangeRequest {
        start_height,
        end_height,
        fill_pow_hash: false,
    };
    let reply = match src {
        Source::Live(core) => {
            let facts = FfiChainFacts::new(core.clone());
            // In-process the console is the operator's own terminal, so the
            // restricted rule does not apply — as `print_block` says.
            crate::methods::get_block_headers_range(&facts, &request, false)
                .map_err(|e| format!("{e:?}"))?
        }
        Source::Remote { address, timeout } => {
            let body = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "0",
                "method": "get_block_headers_range",
                "params": request,
            }))
            .map_err(|e| format!("cannot encode the request: {e}"))?;
            let raw = ctl_client::post_blocking(address, "/json_rpc", body, *timeout)
                .map_err(|(_, reason)| reason)?;
            json_rpc_result::<shekyl_rpc_types::GetBlockHeadersRangeResponse>(
                &raw,
                "get_block_headers_range",
            )?
        }
    };
    if reply.status.is_ok() {
        Ok(reply.headers)
    } else {
        Err(reply.status.0)
    }
}

/// `print_blockchain_info <start> [end]`, and `print_blockchain_info -<n>`.
///
/// The negative form is why this command reads `/get_info`: the C++ parser
/// forwards `(-n, n)` and the executor resolves the window against the tip.
/// That resolution is the only arithmetic here and it is the arithmetic that
/// can be asked to describe a chain shorter than the window, which the C++
/// refused by name — kept, because "start offset is larger than blockchain
/// height" tells an operator what to type next and an empty listing does not.
#[deny(clippy::arithmetic_side_effects)]
fn print_blockchain_info(src: &Source, start: i64, end: u64) -> Result<String, String> {
    let (start_height, end_height) = if start < 0 {
        let info = fetch_get_info(src)?;
        // `-start` as a magnitude, taken through `unsigned_abs` so
        // `i64::MIN` has no special case.
        let back = start.unsigned_abs();
        if back >= info.height {
            return Err("start offset is larger than blockchain height".to_owned());
        }
        let first = info.height.saturating_sub(back);
        // The C++ wrote `start + end - 1` with `end == -start`, i.e. the
        // window ends where the tip is. Saturating rather than wrapping: a
        // zero-length window would otherwise underflow past the tip.
        (first, first.saturating_add(end).saturating_sub(1))
    } else {
        // Non-negative: both indices are literal, and `end` defaults to 0 —
        // so `print_blockchain_info 5` asks for [5, 0] and is refused by the
        // method, exactly as the C++ was. RK-D8: the shape is preserved
        // because changing it is a separate decision from moving it.
        (start.unsigned_abs(), end)
    };
    let headers = fetch_block_headers_range(src, start_height, end_height)?;
    Ok(headers
        .iter()
        .map(render_blockchain_info_entry)
        .collect::<Vec<_>>()
        .join("\n\n"))
}

/// One header as `print_blockchain_info` listed it: four lines, and a blank
/// line between entries supplied by the join above.
fn render_blockchain_info_entry(h: &shekyl_rpc_types::BlockHeader) -> String {
    [
        format!(
            "height: {}, timestamp: {} ({}), size: {}, weight: {} (long term {}), transactions: {}",
            h.height,
            h.timestamp,
            human_readable_timestamp(h.timestamp),
            h.block_size,
            h.block_weight,
            h.long_term_weight,
            h.num_txes
        ),
        format!(
            "major version: {}, minor version: {}",
            h.major_version, h.minor_version
        ),
        format!("block id: {}, previous block id: {}", h.hash, h.prev_hash),
        format!(
            "difficulty: {}, nonce {}, reward {}",
            wide_difficulty_decimal(&h.wide_difficulty),
            h.nonce,
            AtomicUnits::from_raw(h.reward).to_skl_string()
        ),
    ]
    .join("\n")
}

/// Fetch `get_fee_estimate` — native here, over `/json_rpc` remotely.
fn fetch_fee_estimate(
    src: &Source,
    grace_blocks: u64,
) -> Result<shekyl_rpc_types::GetFeeEstimateResponse, String> {
    let request = shekyl_rpc_types::GetFeeEstimateRequest { grace_blocks };
    let reply = match src {
        Source::Live(core) => {
            let facts = FfiChainFacts::new(core.clone());
            crate::methods::get_fee_estimate(&facts, &request).map_err(|e| format!("{e:?}"))?
        }
        Source::Remote { address, timeout } => {
            let body = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "0",
                "method": "get_fee_estimate",
                "params": request,
            }))
            .map_err(|e| format!("cannot encode the request: {e}"))?;
            let raw = ctl_client::post_blocking(address, "/json_rpc", body, *timeout)
                .map_err(|(_, reason)| reason)?;
            json_rpc_result::<shekyl_rpc_types::GetFeeEstimateResponse>(&raw, "get_fee_estimate")?
        }
    };
    if reply.status.is_ok() {
        Ok(reply)
    } else {
        Err(reply.status.0)
    }
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

/// epee's `median`, which is what the C++ printed: the middle element of an
/// odd-length sample, and the **floor of the mean of the two middle
/// elements** of an even-length one (`misc_language.h`'s `get_mid`, whose
/// halve-then-add form exists to avoid overflowing the sum).
fn median(values: &mut [u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    let n = values.len() / 2;
    if values.len() % 2 == 1 {
        values[n]
    } else {
        let (a, b) = (values[n.saturating_sub(1)], values[n]);
        // `a/2 + b/2 + (a%2 + b%2)/2` — the same identity, so the sum is
        // never formed and cannot overflow.
        (a / 2)
            .saturating_add(b / 2)
            .saturating_add(((a % 2).saturating_add(b % 2)) / 2)
    }
}

/// A `count` of `version` byte tallies as the C++ listed them: `"3 v1, 1 v2"`,
/// ascending by version, versions with no votes omitted.
fn version_tally(counts: &[u32; 256]) -> String {
    counts
        .iter()
        .enumerate()
        .filter(|(_, n)| **n > 0)
        .map(|(version, n)| format!("{n} v{version}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `print_blockchain_dynamic_stats <nblocks>`.
///
/// **The `hard_fork_info` leg is deleted rather than ported.** Its only use
/// was `hfres.enabled ? "byte" : "kB"` against `HF_VERSION_PER_BYTE_FEE`,
/// which is `1` (`cryptonote_config.h:282`), and `enabled` is
/// `get_current_version() >= 1`. `Blockchain` constructs its `HardFork` with
/// `original_version = 1` on all three networks
/// (`blockchain.cpp:474`/`:476`/`:478`), `init()` seeds `heights[0]` with
/// that version at height 0, and `current_fork_index` starts at 0 and only
/// advances — so the condition is true on every chain this daemon can be
/// running, and the `kB` arm is unreachable. Shekyl is v3-from-genesis with
/// no pre-v1 history for it to describe (rule 60). The unit is per byte; the
/// round trip that asked is gone with the branch it fed.
#[deny(clippy::arithmetic_side_effects)]
fn print_blockchain_dynamic_stats(src: &Source, nblocks: u64) -> Result<String, String> {
    let info = fetch_get_info(src)?;
    let fees = fetch_fee_estimate(src, 0)?;
    // `res.fee = res.fees[0]` — `on_get_base_fee_estimate` set the scalar
    // from the first tier, which is why RK-5b could retire it. The console
    // read the scalar, so it reads tier 0.
    let dynamic_fee = AtomicUnits::from_raw(fees.fees.0[0]).to_skl_string();
    let mut out = vec![format!(
        "Height: {}, diff {}, cum. diff {}, target {} sec, dyn fee {dynamic_fee}/byte",
        info.height,
        wide_difficulty_decimal(&info.wide_difficulty),
        wide_difficulty_decimal(&info.wide_cumulative_difficulty),
        info.target
    )];
    if nblocks == 0 {
        return Ok(out.join("\n"));
    }
    // The window is the last `nblocks` below the tip; `height` is a count, so
    // the tip's own height is one below it.
    let window = nblocks.min(info.height);
    let headers = fetch_block_headers_range(
        src,
        info.height.saturating_sub(window),
        info.height.saturating_sub(1),
    )?;
    let Ok(sample) = u64::try_from(headers.len()) else {
        return Err("the daemon returned more headers than can be counted".to_owned());
    };
    if sample == 0 {
        return Ok(out.join("\n"));
    }

    // **Every accumulation below saturates and every divisor is `sample`,
    // which the guard above proves non-zero.** These are chain values, so
    // they are as large as a difficulty gets — the C++ summed `avgreward`
    // and `avgnumtxes` into `double`s, which above 2^53 stops being exact,
    // and printed the result through `print_money`, an integer renderer. The
    // means here are integer throughout for the money one and the divisor is
    // the count of headers actually returned rather than the count asked for.
    let mut difficulty_sum: u128 = 0;
    let mut tx_count: u64 = 0;
    let mut reward_sum: u64 = 0;
    let mut weights: Vec<u64> = Vec::with_capacity(headers.len());
    let mut earliest = u64::MAX;
    let mut latest = 0u64;
    let mut major = [0u32; 256];
    let mut minor = [0u32; 256];
    for h in &headers {
        // An unreadable wide difficulty contributes nothing rather than
        // failing the whole listing; `wide_difficulty_decimal` shows the raw
        // string in the per-block view for the same reason.
        difficulty_sum =
            difficulty_sum.saturating_add(wide_difficulty_value(&h.wide_difficulty).unwrap_or(0));
        tx_count = tx_count.saturating_add(h.num_txes);
        reward_sum = reward_sum.saturating_add(h.reward);
        weights.push(h.block_weight);
        earliest = earliest.min(h.timestamp);
        latest = latest.max(h.timestamp);
        major[usize::from(h.major_version)] = major[usize::from(h.major_version)].saturating_add(1);
        minor[usize::from(h.minor_version)] = minor[usize::from(h.minor_version)].saturating_add(1);
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "a transaction count average for a human"
    )]
    let average_txes = tx_count as f64 / sample as f64;
    // The C++ divided the timestamp span by `nblocks` rather than by the
    // `nblocks - 1` intervals those blocks actually span. Preserved: it is
    // the number this command has always printed, it is not wrong enough to
    // have a victim, and an operator's baseline is worth more than a
    // one-block correction made in passing.
    // `checked_div` rather than `/`: the guard above already returned on a
    // zero sample, so the `None` arm is unreachable — but total by
    // construction is this file's rule for peer-influenced arithmetic, and a
    // guard three statements away is not construction. Same idiom as
    // `print_net_stats`; see `methods::average_kib`.
    let average_seconds = latest
        .saturating_sub(earliest)
        .checked_div(sample)
        .unwrap_or(0);
    out.push(format!(
        "Last {window}: avg. diff {}, {average_seconds} avg sec/block, avg num txes {}, \
         avg. reward {}, median block weight {}",
        difficulty_sum.checked_div(u128::from(sample)).unwrap_or(0),
        trimmed(average_txes, 6),
        AtomicUnits::from_raw(reward_sum.checked_div(sample).unwrap_or(0)).to_skl_string(),
        median(&mut weights)
    ));
    out.push(format!("Block versions: {}", version_tally(&major)));
    out.push(format!("Voting for: {}", version_tally(&minor)));
    Ok(out.join("\n"))
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

/// One entry of the `get_alternate_chains` reply.
///
/// **A bridged leg, on purpose** (§2.1.1): `get_alternate_chains` is RK-8's
/// and is still served from the C++ table (`core_rpc_ffi.cpp:284`). Required
/// fields for the reason [`GetLimitReplyProvisional`] gives — a defaulted
/// `length` would make every alt chain read as zero blocks long, which is a
/// sentence about the chain rather than about the reply.
#[derive(serde::Deserialize)]
struct AltChainProvisional {
    block_hash: shekyl_rpc_types::HashHex,
    height: u64,
    length: u64,
    wide_difficulty: String,
    block_hashes: Vec<shekyl_rpc_types::HashHex>,
    main_chain_parent_block: shekyl_rpc_types::HashHex,
}

/// The `get_alternate_chains` reply. See [`AltChainProvisional`].
#[derive(serde::Deserialize)]
struct AltChainsReplyProvisional {
    status: shekyl_rpc_types::RpcStatus,
    chains: Vec<AltChainProvisional>,
}

/// Fetch `get_alternate_chains` — bridged on both arms.
fn fetch_alt_chains(src: &Source) -> Result<Vec<AltChainProvisional>, String> {
    let reply: AltChainsReplyProvisional = match src {
        Source::Live(core) => {
            let raw = core
                .json_rpc("get_alternate_chains", "{}")
                .ok_or_else(|| "no reply from get_alternate_chains".to_owned())?;
            ffi_json_rpc_result(&raw, "get_alternate_chains")?
        }
        Source::Remote { address, timeout } => {
            let body = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "0",
                "method": "get_alternate_chains",
            }))
            .map_err(|e| format!("cannot encode the request: {e}"))?;
            let raw = ctl_client::post_blocking(address, "/json_rpc", body, *timeout)
                .map_err(|(_, reason)| reason)?;
            json_rpc_result::<AltChainsReplyProvisional>(&raw, "get_alternate_chains")?
        }
    };
    if reply.status.is_ok() {
        Ok(reply.chains)
    } else {
        Err(reply.status.0)
    }
}

/// Fetch `get_block_header_by_hash` — native here, over `/json_rpc` remotely.
fn fetch_block_headers_by_hash(
    src: &Source,
    hashes: Vec<shekyl_rpc_types::HashHex>,
) -> Result<Vec<shekyl_rpc_types::BlockHeaderSlot>, String> {
    let request = shekyl_rpc_types::GetBlockHeaderByHashRequest {
        hashes,
        fill_pow_hash: false,
    };
    let reply = match src {
        Source::Live(core) => {
            let facts = FfiChainFacts::new(core.clone());
            crate::methods::get_block_header_by_hash(&facts, &request, false)
                .map_err(|e| format!("{e:?}"))?
        }
        Source::Remote { address, timeout } => {
            let body = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "0",
                "method": "get_block_header_by_hash",
                "params": request,
            }))
            .map_err(|e| format!("cannot encode the request: {e}"))?;
            let raw = ctl_client::post_blocking(address, "/json_rpc", body, *timeout)
                .map_err(|(_, reason)| reason)?;
            json_rpc_result::<shekyl_rpc_types::GetBlockHeaderByHashResponse>(
                &raw,
                "get_block_header_by_hash",
            )?
        }
    };
    if reply.status.is_ok() {
        Ok(reply.block_headers)
    } else {
        Err(reply.status.0)
    }
}

/// Read the headers for `requested`, insisting each slot answers the hash it
/// was asked about.
///
/// **This is the check the C++ `bhres.block_headers.size() != chain.length + 1`
/// became**, and it is a different kind of check. A count could only say "the
/// daemon returned the wrong number of headers"; against the per-element
/// reply it can say *which hash* has no header — and it also catches a reply
/// of the right length whose slots are in the wrong order or answer hashes
/// nobody asked about, which the count could not see at all.
///
/// A missing slot is normal rather than exceptional here: `alt_chain_info`
/// asks `get_alternate_chains` for hashes and then asks for their headers, so
/// a reorg between the two calls makes one vanish. That is the case the old
/// batching could not express — it returned zero headers and an error string
/// naming nothing.
fn headers_in_correspondence(
    slots: &[shekyl_rpc_types::BlockHeaderSlot],
    requested: &[shekyl_rpc_types::HashHex],
) -> Result<Vec<shekyl_rpc_types::BlockHeader>, String> {
    if slots.len() != requested.len() {
        return Err(format!(
            "the daemon answered {} of {} block hashes",
            slots.len(),
            requested.len()
        ));
    }
    let mut headers = Vec::with_capacity(slots.len());
    for (slot, asked) in slots.iter().zip(requested) {
        if slot.hash != *asked {
            return Err(format!(
                "the daemon answered about {} where {asked} was asked",
                slot.hash
            ));
        }
        let Some(header) = slot.block_header.as_ref() else {
            return Err(format!(
                "no block header for {asked} — the chain may have moved since it was listed"
            ));
        };
        headers.push(header.clone());
    }
    Ok(headers)
}

/// `alt_chain_info [<tip> | >above | -last_blocks]`.
#[deny(clippy::arithmetic_side_effects)]
fn alt_chain_info(
    src: &Source,
    tip: &str,
    above: u64,
    last_blocks: u64,
    now: u64,
) -> Result<String, String> {
    let info = fetch_get_info(src)?;
    let mut chains = fetch_alt_chains(src)?;
    // The alt chain's first block. Saturating: an alt chain longer than our
    // own height is not something this console gets to be surprised by.
    let start_of = |c: &AltChainProvisional| c.height.saturating_sub(c.length).saturating_add(1);
    // "deep" as the C++ computed it: how far below our tip the fork point is.
    let depth_of =
        |c: &AltChainProvisional| info.height.saturating_sub(start_of(c)).saturating_sub(1);

    if tip.is_empty() {
        chains.sort_by_key(|c| c.height);
        let shown: Vec<&AltChainProvisional> = chains
            .iter()
            .filter(|c| c.length > above)
            .filter(|c| last_blocks == 0 || depth_of(c) < last_blocks)
            .collect();
        let mut out = vec![format!("{} alternate chains found:", shown.len())];
        for c in shown {
            out.push(format!(
                "{} blocks long, from height {} ({} deep), diff {}: {}",
                c.length,
                start_of(c),
                depth_of(c),
                wide_difficulty_decimal(&c.wide_difficulty),
                c.block_hash
            ));
        }
        return Ok(out.join("\n"));
    }

    let Some(chain) = chains.iter().find(|c| c.block_hash.to_string() == tip) else {
        return Err(format!(
            "Block hash {tip} is not the tip of any known alternate chain"
        ));
    };
    let start_height = start_of(chain);
    let mut out = vec![
        format!("Found alternate chain with tip {tip}"),
        format!(
            "{} blocks long, from height {start_height} ({} deep), diff {}:",
            chain.length,
            depth_of(chain),
            wide_difficulty_decimal(&chain.wide_difficulty)
        ),
    ];
    for hash in &chain.block_hashes {
        out.push(format!("  {hash}"));
    }
    out.push(format!(
        "Chain parent on main chain: {}",
        chain.main_chain_parent_block
    ));

    // The chain's own blocks, then its parent on the main chain — the parent
    // last, because the difficulty read below is `.back()`.
    let mut requested = chain.block_hashes.clone();
    requested.push(chain.main_chain_parent_block);
    let slots = fetch_block_headers_by_hash(src, requested.clone())?;
    let headers = headers_in_correspondence(&slots, &requested)?;

    let (earliest, latest) = headers.iter().fold((u64::MAX, 0u64), |(lo, hi), h| {
        (lo.min(h.timestamp), hi.max(h.timestamp))
    });
    let span = latest.saturating_sub(earliest);
    let age = span.max(now.saturating_sub(earliest));
    out.push(format!("Age: {}", human_readable_timespan(age)));
    if chain.length > 1 {
        out.push(format!("Time span: {}", human_readable_timespan(span)));
        // **The guard is on the span, not on the difficulty.** The C++
        // required `block_headers.back().difficulty > 0` and then computed a
        // percentage the difficulty does not appear in — a check standing in
        // front of a formula it is not part of, whose message named
        // `cumulative difficulty` while reading `difficulty`. The hazard the
        // site actually has is `dt == 0`: two or more blocks sharing a
        // timestamp, which is reachable and which made the C++ print `inf%`.
        if span == 0 {
            out.push(
                "Cannot estimate the network hash rate: the chain's blocks share a timestamp"
                    .to_owned(),
            );
        } else {
            #[expect(
                clippy::cast_precision_loss,
                reason = "a percentage for a human, from a block count and a timespan"
            )]
            let share = 100.0 * (info.target as f64) * (chain.length as f64) / (span as f64);
            out.push(format!(
                "Approximated {}% of network hash rate",
                trimmed(share, 6)
            ));
        }
    }
    Ok(out.join("\n"))
}

/// The `/mining_status` reply, as much of it as `show_status` reads.
///
/// **A bridged leg, on purpose** (§2.1.1): `/mining_status` is RK-7's and is
/// still served from the C++ table (`core_rpc_ffi.cpp:180`). Required fields
/// for the reason [`GetLimitReplyProvisional`] gives — a defaulted `active`
/// would report a mining daemon as idle.
#[derive(serde::Deserialize)]
struct MiningStatusProvisional {
    status: shekyl_rpc_types::RpcStatus,
    active: bool,
    speed: u64,
    is_background_mining_enabled: bool,
}

/// What `show_status` could learn about mining.
enum MiningReadout {
    /// The daemon answered. `BUSY` is its own arm because a syncing daemon
    /// answers the question with "ask me later", which is neither idle nor
    /// mining.
    Ready(MiningStatusProvisional),
    Syncing,
    /// The remote daemon would not say — a restricted listener does not serve
    /// `/mining_status`. Only reachable on the remote arm; see
    /// [`fetch_mining_status`].
    Unavailable,
}

/// Fetch `/mining_status`, and treat a failure differently on each arm.
///
/// **The asymmetry is the C++'s and it is carried on purpose.** In-process
/// the console *is* the daemon, so a `/mining_status` that will not answer is
/// a fault in this daemon and the command says so. Remotely the daemon may
/// simply be running a restricted listener, which does not serve the route at
/// all — an ordinary posture, not a failure, and the status line says "mining
/// info unavailable" rather than refusing to print the eight other things it
/// knows. Unifying the arms would either turn a normal restricted daemon into
/// an error or hide a real local fault.
fn fetch_mining_status(src: &Source) -> Result<MiningReadout, String> {
    let raw = match src {
        Source::Live(core) => core
            .json_endpoint("/mining_status", "{}")
            .ok_or_else(|| "no reply from /mining_status".to_owned())?,
        Source::Remote { address, timeout } => {
            match ctl_client::post_blocking(address, "/mining_status", b"{}".to_vec(), *timeout) {
                // **An empty body is the route declining to exist.** The
                // control transport does not surface the HTTP status — its
                // contract is "a response arrived", because every route the
                // daemon *serves* answers with a JSON body carrying its own
                // `status`. `/mining_status` is `Visibility::AdminOnly`
                // (`server.rs`), so a restricted listener has no such route
                // and axum's fallback answers 404 with no body at all. That
                // is the only way a zero-length body reaches here, and it is
                // exactly the case the C++'s `has_mining_info` keyed on.
                Ok(raw) if raw.is_empty() => return Ok(MiningReadout::Unavailable),
                Ok(raw) => String::from_utf8_lossy(&raw).into_owned(),
                // The daemon is not answering at all — no host, no listener.
                Err(_) => return Ok(MiningReadout::Unavailable),
            }
        }
    };
    let reply: MiningStatusProvisional =
        serde_json::from_str(&raw).map_err(|e| format!("malformed mining_status reply: {e}"))?;
    if reply.status.0 == shekyl_rpc_types::RpcStatus::BUSY {
        return Ok(MiningReadout::Syncing);
    }
    if !reply.status.is_ok() {
        return Err(reply.status.0);
    }
    Ok(MiningReadout::Ready(reply))
}

/// Fetch `hard_fork_info` — native here, over `/json_rpc` remotely.
fn fetch_hard_fork_info(
    src: &Source,
    version: Option<u8>,
) -> Result<shekyl_rpc_types::HardForkInfoResponse, String> {
    let request = shekyl_rpc_types::HardForkInfoRequest { version };
    let reply = match src {
        Source::Live(core) => {
            let facts = FfiChainFacts::new(core.clone());
            crate::methods::hard_fork_info(&facts, &request).map_err(|e| format!("{e:?}"))?
        }
        Source::Remote { address, timeout } => {
            let body = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "0",
                "method": "hard_fork_info",
                "params": request,
            }))
            .map_err(|e| format!("cannot encode the request: {e}"))?;
            let raw = ctl_client::post_blocking(address, "/json_rpc", body, *timeout)
                .map_err(|(_, reason)| reason)?;
            json_rpc_result::<shekyl_rpc_types::HardForkInfoResponse>(&raw, "hard_fork_info")?
        }
    };
    if reply.status.is_ok() {
        Ok(reply)
    } else {
        Err(reply.status.0)
    }
}

/// A hash rate for a human: `get_metric_prefix` + `get_mining_speed`.
///
/// Below 1000 the raw number in `H/s`; otherwise the largest metric prefix
/// that leaves the value under a million, to two decimals. A rate so large
/// that eight prefixes do not reach it prints raw — the C++ fell out of its
/// loop with `prefix = 0` and formatted the *original* value, which this
/// keeps.
#[deny(clippy::arithmetic_side_effects)]
fn mining_speed(rate: u128) -> String {
    const PREFIXES: [char; 8] = ['k', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y'];
    if rate < 1000 {
        return format!("{rate} H/s");
    }
    let mut scaled = rate;
    for prefix in PREFIXES {
        if scaled < 1_000_000 {
            #[expect(
                clippy::cast_precision_loss,
                reason = "a hash rate for a human, below a million by the test above"
            )]
            let value = scaled as f64 / 1000.0;
            return format!("{value:.2} {prefix}H/s");
        }
        scaled /= 1000;
    }
    format!("{rate} H/s")
}

/// `get_sync_percentage`, including its refusal to round up to 100.
#[deny(clippy::arithmetic_side_effects)]
fn sync_percentage(height: u64, target_height: u64) -> f64 {
    // A target below our height means we are ahead of it; `max(1)` keeps the
    // divisor non-zero on a chain with no blocks, which cannot occur but
    // costs nothing to make impossible here rather than three lines down.
    let target = target_height.max(height).max(1);
    #[expect(
        clippy::cast_precision_loss,
        reason = "a percentage for a human, from two heights"
    )]
    let pc = 100.0 * (height as f64) / (target as f64);
    // Not yet synced must not read as 100%: the last block is the one an
    // operator is waiting for.
    if height < target && pc > 99.9 {
        99.9
    } else {
        pc
    }
}

/// `get_fork_extra_info`: what to append after the version, if anything.
#[deny(clippy::arithmetic_side_effects)]
fn fork_extra_info(earliest_height: u64, net_height: u64, block_time: u64) -> String {
    if earliest_height == net_height {
        return " (forking now)".to_owned();
    }
    let Some(blocks) = earliest_height.checked_sub(net_height).filter(|d| *d > 0) else {
        return String::new();
    };
    if blocks <= 30 {
        return format!(" (next fork in {blocks} blocks)");
    }
    // `86400 / block_time`, and `blocks_per_day / 24` below, are the C++'s
    // integer divisions. Both can be zero — the first if the daemon reports a
    // target above a day, the second if it reports one above an hour — and
    // the C++ divided by them regardless. A daemon whose target is that large
    // is not one this line can say anything useful about, so it says nothing
    // rather than `inf`.
    let (Some(per_day), Some(per_hour)) = (
        86_400u64.checked_div(block_time).filter(|d| *d > 0),
        86_400u64
            .checked_div(block_time)
            .and_then(|d| d.checked_div(24))
            .filter(|d| *d > 0),
    ) else {
        return String::new();
    };
    #[expect(
        clippy::cast_precision_loss,
        reason = "a countdown for a human, from a block count"
    )]
    let (blocks_f, per_day_f, per_hour_f) = (blocks as f64, per_day as f64, per_hour as f64);
    if blocks <= per_day / 2 {
        return format!(" (next fork in {:.1} hours)", blocks_f / per_hour_f);
    }
    if blocks <= per_day.saturating_mul(30) {
        return format!(" (next fork in {:.1} days)", blocks_f / per_day_f);
    }
    String::new()
}

/// `status` / `show_status`.
#[deny(clippy::arithmetic_side_effects)]
fn show_status(src: &Source, now: u64) -> Result<String, String> {
    let info = fetch_get_info(src)?;
    // `hfreq.version = 0` in the C++, i.e. "tell me about the active fork".
    // The line prints `active_version`, which is what `res.version` was:
    // `on_hard_fork_info` set it from `get_current_hard_fork_version()`
    // regardless of the request, while the *voting* fields described the
    // requested one. Reporting the two apart is why RK-5b split them; reading
    // `queried_version` here would invert the whole point.
    let fork = fetch_hard_fork_info(src, None)?;
    let mining = fetch_mining_status(src)?;

    let net_height = info.target_height.max(info.height);
    let network = if info.testnet {
        "testnet"
    } else if info.stagenet {
        "stagenet"
    } else {
        "mainnet"
    };
    let mining_text = match &mining {
        MiningReadout::Unavailable => "mining info unavailable".to_owned(),
        MiningReadout::Syncing => "syncing".to_owned(),
        MiningReadout::Ready(m) if m.active => format!(
            "{}mining at {}",
            if m.is_background_mining_enabled {
                "smart "
            } else {
                ""
            },
            mining_speed(u128::from(m.speed))
        ),
        MiningReadout::Ready(_) => "not mining".to_owned(),
    };
    // Network hash rate as difficulty per target second. `checked_div` for
    // the same reason as everywhere else in this file: `target` is a number
    // the daemon sent.
    let net_hash = wide_difficulty_value(&info.wide_difficulty)
        .and_then(|d| d.checked_div(u128::from(info.target)))
        .map_or_else(|| "unknown".to_owned(), mining_speed);
    let mut line = format!(
        "Height: {}/{net_height} ({:.1}%) on {network}, {mining_text}, net hash {net_hash}, \
         v{}{}, {}(out)+{}(in) connections",
        info.height,
        sync_percentage(info.height, info.target_height),
        fork.active_version,
        fork_extra_info(fork.earliest_height, net_height, info.target),
        info.outgoing_connections_count,
        info.incoming_connections_count
    );
    // A restricted listener does not disclose the start time, and the C++
    // omitted the whole clause rather than reporting an uptime of zero.
    if info.start_time != 0 {
        let uptime = now.saturating_sub(info.start_time);
        line.push_str(&format!(
            ", uptime {}d {}h {}m {}s",
            uptime / 86_400,
            (uptime / 3_600) % 24,
            (uptime / 60) % 60,
            uptime % 60
        ));
    }
    Ok(line)
}

/// `sync_info`.
#[deny(clippy::arithmetic_side_effects)]
fn sync_info(src: &Source) -> Result<String, String> {
    let reply = match src {
        Source::Live(core) => {
            let chain = FfiChainFacts::new(core.clone());
            let p2p = crate::chain_facts::FfiP2pFacts::new(core.clone());
            crate::methods::sync_info(&chain, &p2p).map_err(|e| format!("{e:?}"))?
        }
        Source::Remote { address, timeout } => {
            let body = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "0",
                "method": "sync_info",
            }))
            .map_err(|e| format!("cannot encode the request: {e}"))?;
            let raw = ctl_client::post_blocking(address, "/json_rpc", body, *timeout)
                .map_err(|(_, reason)| reason)?;
            json_rpc_result::<shekyl_rpc_types::SyncInfoResponse>(&raw, "sync_info")?
        }
    };
    if !reply.status.is_ok() {
        return Err(reply.status.0);
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use shekyl_rpc_types::{HashHex, RpcStatus};

    fn run(args: &[&str], address: Option<&str>) -> (i32, String) {
        let cstrs: Vec<CString> = args.iter().map(|a| CString::new(*a).unwrap()).collect();
        let ptrs: Vec<*const c_char> = cstrs.iter().map(|c| c.as_ptr()).collect();
        let addr = address.map(|a| CString::new(a).unwrap());
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        // SAFETY: valid argv/address/out pointers; null core (remote arm).
        let code = unsafe {
            shekyl_daemon_console_run(
                ptrs.as_ptr(),
                ptrs.len(),
                std::ptr::null_mut(),
                addr.as_ref().map_or(std::ptr::null(), |a| a.as_ptr()),
                5,
                &raw mut ptr,
                &raw mut len,
            )
        };
        let text = if ptr.is_null() {
            String::new()
        } else {
            // SAFETY: the export produced this pair.
            unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).into_owned() }
        };
        // SAFETY: freeing exactly the produced pair.
        unsafe { ctl_client::shekyl_daemon_ctl_free(ptr, len) };
        (code, text)
    }

    /// One-request HTTP acceptor answering `reply` with 200.
    /// A reply built through the wire type rather than hand-written, so a
    /// fixture cannot describe a document the daemon could never send. Two
    /// of these were hand-written `"hash"` strings that RK-3's `HashHex`
    /// immediately refused.
    fn typed_reply<T: serde::Serialize>(reply: &T) -> String {
        serde_json::to_string(reply).expect("wire type serializes")
    }

    fn one_shot(reply: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).expect("read request");
            assert!(n > 0, "empty request");
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                reply.len()
            );
            s.write_all(head.as_bytes()).unwrap();
            s.write_all(reply.as_bytes()).unwrap();
        });
        address
    }

    /// A **multi-request** acceptor that routes on what the console asked
    /// for: by request path for the REST legs, and by the JSON-RPC `method`
    /// in the body for `/json_rpc`.
    ///
    /// Its reason to exist is the bridged legs (§2.1.1). A console command
    /// that crosses to a route this slice does not serve makes *two or more*
    /// requests, and `one_shot` can only answer the first — so the commands
    /// whose safety condition is "the console gate covers this command" were
    /// the exact commands no gate could reach. Routing rather than replaying
    /// a queue also means the assertion is on the reply the console asked
    /// for, not on call order: a command that stopped issuing one of its legs
    /// gets `no reply`, not a silently shifted answer.
    ///
    /// An unrouted request is answered `404` with an empty body, which is
    /// what a daemon that no longer serves the route would do.
    fn route_server(routes: Vec<(&'static str, String)>) -> String {
        route_server_recording(routes).0
    }

    /// [`route_server`], plus the log of what was asked of it.
    ///
    /// A canned reply is blind to the request that fetched it, so a test that
    /// only reads the output cannot tell a command that asked for the right
    /// window from one that asked for the wrong window and was answered
    /// anyway. The log makes the *request* assertable, which for the
    /// window-resolving commands is the whole behaviour under test.
    #[expect(clippy::type_complexity, reason = "a test log of (route, body)")]
    fn route_server_recording(
        routes: Vec<(&'static str, String)>,
    ) -> (
        String,
        std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
    ) {
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let recorder = std::sync::Arc::clone(&log);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { return };
                let Some((path, body)) = read_request(&mut s) else {
                    continue;
                };
                if let Ok(mut log) = recorder.lock() {
                    log.push((path.clone(), body.clone()));
                }
                // `/json_rpc` carries the name in the body; every other route
                // *is* the name.
                let key = if path == "/json_rpc" {
                    serde_json::from_str::<serde_json::Value>(&body)
                        .ok()
                        .and_then(|v| v.get("method")?.as_str().map(str::to_owned))
                        .map_or_else(|| path.clone(), |m| format!("json_rpc:{m}"))
                } else {
                    path.clone()
                };
                let reply = routes.iter().find(|(k, _)| *k == key).map(|(_, v)| v);
                let (status, body) = reply.map_or_else(
                    || ("404 Not Found", String::new()),
                    |r| ("200 OK", r.clone()),
                );
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                // One write: a head-then-body pair lets a client that hung
                // up between them see a truncated reply, which reads as a
                // malformed daemon rather than a closed socket.
                let mut response = head.into_bytes();
                response.extend_from_slice(body.as_bytes());
                if s.write_all(&response).is_err() {
                    continue;
                }
            }
        });
        (address, log)
    }

    /// Read one HTTP request, returning its path and body.
    ///
    /// Headers first, then exactly `Content-Length` more bytes — a single
    /// `read` would truncate a body split across packets, which on loopback
    /// is rare enough to pass locally and fail in CI.
    fn read_request(s: &mut std::net::TcpStream) -> Option<(String, String)> {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            if s.read(&mut byte).ok()? == 0 {
                return None;
            }
            buf.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&buf).into_owned();
        let path = head.split_whitespace().nth(1)?.to_owned();
        let length: usize = head
            .lines()
            .find_map(|l| {
                let (name, value) = l.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().ok())?
            })
            .unwrap_or(0);
        let mut body = vec![0u8; length];
        s.read_exact(&mut body).ok()?;
        Some((path, String::from_utf8_lossy(&body).into_owned()))
    }

    /// A one-request acceptor that answers by running the **real projection**
    /// over fixed facts, so the reply depends on the request the console
    /// actually sent.
    ///
    /// A canned reply would be blind to the defect this exists to catch: the
    /// "(pruned)" label reads `prunable_as_hex`, which only the split form
    /// fills, so a fixture that always returns split-form data would pass
    /// whatever the console asked for. Serving the projection makes the
    /// request an input rather than a formality.
    fn one_shot_projected(slot: crate::core::TxSlot, txid: [u8; 32]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = vec![0u8; 8192];
            let n = s.read(&mut buf).expect("read request");
            let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
            let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
            let request: shekyl_rpc_types::GetTransactionsRequest =
                serde_json::from_str(&body).expect("the console sends a typed request");
            let reply = crate::methods::project_transactions(
                &request,
                &[txid],
                &[slot],
                9,
                |blob, pruned| {
                    Ok(format!(
                        "{{\"json\":\"{}\",\"pruned\":{pruned}}}",
                        hex::encode(blob)
                    ))
                },
            )
            .expect("projection succeeds");
            let out = serde_json::to_string(&reply).unwrap();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                out.len()
            );
            s.write_all(head.as_bytes()).unwrap();
            s.write_all(out.as_bytes()).unwrap();
        });
        address
    }

    /// A structurally canonical spend for the body-binding: the console now
    /// recomputes each entry's identity from its bytes, so a fixture can no
    /// longer label an arbitrary blob — a fixture that invents a hash is
    /// staging the substitution the binding exists to refuse (the engine's
    /// doubles learned this the same way).
    fn console_spend() -> shekyl_wire::Transaction {
        use shekyl_wire::transaction::{PQC_HYBRID_SINGLE_KEY_LEN, PQC_HYBRID_SINGLE_SIG_LEN};
        use shekyl_wire::{BpPlus, Ct, CtBase, Input, Output, PqcAuth, Prunable, TxPrefix};
        shekyl_wire::Transaction {
            prefix: TxPrefix {
                unlock_time: 0,
                inputs: vec![Input::ToKey {
                    amount: 0,
                    key_offsets: vec![],
                    key_image: [0x42; 32],
                }],
                outputs: vec![
                    Output {
                        amount: 0,
                        key: [1; 32],
                        view_tag: 0,
                    },
                    Output {
                        amount: 0,
                        key: [3; 32],
                        view_tag: 1,
                    },
                ],
                extra: vec![],
            },
            ct: Ct::Fcmp {
                fee: 0,
                reference_block: [0; 32],
                base: CtBase {
                    enc_amounts: vec![[0; 9], [0; 9]],
                    enc_labels: vec![[0; 9], [0; 9]],
                    commitments: vec![[2; 32], [3; 32]],
                },
                pqc_auths: vec![PqcAuth {
                    auth_version: 1,
                    scheme_id: 1,
                    flags: 0,
                    hybrid_public_key: vec![0; PQC_HYBRID_SINGLE_KEY_LEN],
                    hybrid_signature: vec![0; PQC_HYBRID_SINGLE_SIG_LEN],
                }],
                prunable: Some(Prunable {
                    serve_credit_pruned: vec![],
                    bulletproofs: vec![BpPlus {
                        a: [0; 32],
                        a1: [0; 32],
                        b: [0; 32],
                        r1: [0; 32],
                        s1: [0; 32],
                        d1: [0; 32],
                        l: vec![[0; 32]; 7],
                        r: vec![[0; 32]; 7],
                    }],
                    tree_depth: 1,
                    fcmp_proof: vec![0; 8],
                    pseudo_outs: vec![[0; 32]],
                }),
            },
        }
    }

    /// [`console_spend`] split at the production boundary: (pruned form,
    /// prunable tail) — the two halves a split `get_transactions` reply
    /// carries, whose concatenation is the full serialization.
    fn console_spend_halves() -> (Vec<u8>, Vec<u8>) {
        let tx = console_spend();
        let full = tx.serialize();
        let mut pruned_tx = console_spend();
        let shekyl_wire::Ct::Fcmp { prunable, .. } = &mut pruned_tx.ct else {
            unreachable!("console_spend is Fcmp by construction");
        };
        *prunable = None;
        let pruned = pruned_tx.serialize();
        let tail = full[pruned.len()..].to_vec();
        (pruned, tail)
    }

    fn mined_slot(prunable: Vec<u8>) -> crate::core::TxSlot {
        crate::core::TxSlot::Chain {
            pruned: console_spend_halves().0,
            prunable,
            // Nonempty: this transaction HAS a prunable half, so an empty
            // `prunable_as_hex` would mean the daemon dropped it.
            prunable_hash: [0x5A; 32],
            block_height: 3,
            block_timestamp: 1_700_000_000,
            output_indices: vec![1],
            pruned_flag: false,
        }
    }

    /// **An ordinary confirmed transaction is not labelled `(pruned)`.**
    ///
    /// It was, until this test: the console asked for the whole transaction,
    /// so the halves came back concatenated in `as_hex` with `prunable_as_hex`
    /// empty — which the label cannot tell apart from a daemon that pruned the
    /// half away. Every mined transaction printed as `(pruned)`.
    #[test]
    fn a_retained_transaction_is_not_reported_pruned() {
        // The halves reassemble to the full body, so the identity is the
        // whole-transaction hash.
        let txid = console_spend().hash();
        let addr = one_shot_projected(mined_slot(console_spend_halves().1), txid);
        let (_, out) = run(&["print_transaction", &hex::encode(txid)], Some(&addr));
        assert!(
            out.contains("Found in blockchain at height 3"),
            "expected the confirmed line, got: {out}"
        );
        assert!(
            !out.contains("(pruned)"),
            "a transaction whose prunable half the daemon still holds must not \
             be labelled pruned: {out}"
        );
    }

    /// And the label still fires when the half really is gone — so the test
    /// above is not passing by disabling the label.
    #[test]
    fn a_pruned_transaction_is_reported_pruned() {
        // The prunable half is gone, so the identity mixes the reply's
        // supplied digest — the same recomputation the binding performs.
        let txid = console_spend().hash_with_supplied_prunable([0x5A; 32]);
        let addr = one_shot_projected(mined_slot(Vec::new()), txid);
        let (_, out) = run(&["print_transaction", &hex::encode(txid)], Some(&addr));
        assert!(
            out.contains("(pruned)"),
            "a transaction whose prunable half is absent must be labelled \
             pruned: {out}"
        );
    }

    /// **An echoed label over a substituted body is refused.** The label
    /// check compares two daemon-chosen strings, so a daemon that echoes the
    /// requested hash while serving another canonical body sails through it;
    /// the binding recomputes the identity from the bytes and refuses. This
    /// is `parse_tx_batch`'s rule applied to the console's remote arm, which
    /// posts wherever the operator pointed it.
    #[test]
    fn an_echoed_label_over_a_substituted_body_is_refused() {
        // The identity of a DIFFERENT transaction (unlock_time moved), which
        // the daemon echoes while serving `console_spend`'s body.
        let mut other = console_spend();
        other.prefix.unlock_time = 5;
        let requested = other.hash();
        let (pruned, tail) = console_spend_halves();
        let entry = shekyl_rpc_types::TxEntry {
            tx_hash: HashHex::from_bytes(requested),
            as_hex: String::new(),
            pruned_as_hex: hex::encode(pruned),
            prunable_as_hex: hex::encode(tail),
            prunable_hash: HashHex::from_bytes([0x5A; 32]),
            as_json: String::new(),
            pruned: false,
            double_spend_seen: false,
            location: shekyl_rpc_types::TxLocation::Mined {
                block_height: 3,
                confirmations: 6,
                block_timestamp: 1_700_000_000,
                output_indices: vec![1],
            },
        };
        let reply = shekyl_rpc_types::GetTransactionsResponse {
            status: RpcStatus::ok(),
            txs: vec![entry],
            missed_tx: vec![],
        };
        let addr = one_shot_raw(reply);
        let (code, out) = run(&["print_transaction", &hex::encode(requested)], Some(&addr));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST);
        assert!(
            out.contains("a label is not an identity"),
            "the substituted body must be refused by the binding, not \
             rendered: {out}"
        );
    }

    /// **And on the pruned arm, where the daemon also chooses the digest.**
    /// The test above substitutes a body whose prunable half is present, so
    /// the identity is a whole-body hash the daemon cannot steer. The pruned
    /// arm is the interesting one: `prunable_hash` is the daemon's to pick,
    /// and the comment on the binding claims picking it freely buys nothing
    /// because it leaves `H(prefix ‖ base ‖ pqc ‖ X) = txid` to solve for
    /// `X`. That claim is argued at the call site and pinned here — the
    /// daemon serves another transaction's pruned body under this label and
    /// supplies the very digest that makes the *requested* identity come out
    /// right for its own body, which is the best choice available to it.
    #[test]
    fn a_substituted_pruned_body_is_refused_even_with_a_chosen_digest() {
        const CHOSEN: [u8; 32] = [0x11; 32];
        // The pruned identity of a DIFFERENT transaction, under the digest
        // the daemon will also supply — so only the body differs.
        let mut other = console_spend();
        other.prefix.unlock_time = 5;
        let requested = other.hash_with_supplied_prunable(CHOSEN);
        // Sanity: the two bodies really do have different pruned identities,
        // or the refusal below would prove nothing.
        assert_ne!(
            requested,
            console_spend().hash_with_supplied_prunable(CHOSEN),
            "the fixture must substitute a genuinely different body"
        );
        let (pruned, _tail) = console_spend_halves();
        let entry = shekyl_rpc_types::TxEntry {
            tx_hash: HashHex::from_bytes(requested),
            as_hex: String::new(),
            pruned_as_hex: hex::encode(pruned),
            // The half is gone, so the binding takes the pruned arm.
            prunable_as_hex: String::new(),
            prunable_hash: HashHex::from_bytes(CHOSEN),
            as_json: String::new(),
            pruned: true,
            double_spend_seen: false,
            location: shekyl_rpc_types::TxLocation::Mined {
                block_height: 3,
                confirmations: 6,
                block_timestamp: 1_700_000_000,
                output_indices: vec![1],
            },
        };
        let reply = shekyl_rpc_types::GetTransactionsResponse {
            status: RpcStatus::ok(),
            txs: vec![entry],
            missed_tx: vec![],
        };
        let addr = one_shot_raw(reply);
        let (code, out) = run(&["print_transaction", &hex::encode(requested)], Some(&addr));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST);
        assert!(
            out.contains("a label is not an identity"),
            "a substituted pruned body must be refused however the digest is \
             chosen, not rendered: {out}"
        );
    }

    /// A reply with extra entries is unreadable, not "use the first one".
    /// The command requested one hash; the adjacent key-image command already
    /// requires a one-element slice for the same reason.
    #[test]
    fn extra_transaction_entries_are_a_malformed_reply() {
        let txid = [0x33; 32];
        let entry = |n: u8| shekyl_rpc_types::TxEntry {
            tx_hash: HashHex::from_bytes([n; 32]),
            as_hex: String::new(),
            pruned_as_hex: "aabb".to_owned(),
            prunable_as_hex: "ccdd".to_owned(),
            prunable_hash: HashHex::from_bytes([0x5A; 32]),
            as_json: String::new(),
            pruned: false,
            double_spend_seen: false,
            location: shekyl_rpc_types::TxLocation::Mined {
                block_height: 3,
                confirmations: 6,
                block_timestamp: 1_700_000_000,
                output_indices: vec![1],
            },
        };
        let reply = shekyl_rpc_types::GetTransactionsResponse {
            status: RpcStatus::ok(),
            txs: vec![entry(0x33), entry(0x34)],
            missed_tx: vec![],
        };
        let addr = one_shot(typed_reply(&reply));
        let (code, out) = run(&["print_transaction", &hex::encode(txid)], Some(&addr));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST);
        assert!(
            out.contains("asked about 1 transaction, got 2"),
            "extra entries must be named, not silently truncated: {out}"
        );
    }

    /// A one-request acceptor answering with a fixed document, for the cases
    /// where the point is that the daemon said something the request did not
    /// ask for — which the projection-backed fixture cannot stage, because it
    /// only ever answers about the hash it was handed.
    fn one_shot_raw(reply: shekyl_rpc_types::GetTransactionsResponse) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf).expect("read request");
            let out = serde_json::to_string(&reply).unwrap();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                out.len()
            );
            s.write_all(head.as_bytes()).unwrap();
            s.write_all(out.as_bytes()).unwrap();
        });
        address
    }

    fn mined_entry(txid: [u8; 32]) -> shekyl_rpc_types::TxEntry {
        shekyl_rpc_types::TxEntry {
            tx_hash: HashHex::from_bytes(txid),
            as_hex: String::new(),
            pruned_as_hex: hex::encode([0xAAu8, 0xBB]),
            prunable_as_hex: hex::encode([0xCCu8]),
            prunable_hash: HashHex::from_bytes([0x5A; 32]),
            as_json: String::new(),
            pruned: false,
            double_spend_seen: false,
            location: shekyl_rpc_types::TxLocation::Mined {
                block_height: 3,
                block_timestamp: 1_700_000_000,
                confirmations: 1,
                output_indices: vec![1],
            },
        }
    }

    /// **The server's reason survives to the operator.**
    ///
    /// A native handler reports failure as a `RestErrorEnvelope`, which the
    /// success type does not model — so a success-only decode reported
    /// "malformed reply" over the reason the daemon actually gave, and refusing
    /// unknown fields made that certain rather than incidental. `decode_reply`
    /// tries the envelope second, which is what keeps the failure actionable.
    #[test]
    fn a_handler_error_envelope_reaches_the_operator() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf).expect("read request");
            let out = r#"{"error":"the store is inconsistent at height 7"}"#;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                out.len()
            );
            s.write_all(head.as_bytes()).unwrap();
            s.write_all(out.as_bytes()).unwrap();
        });
        let (_, out) = run(
            &["print_transaction", &hex::encode([0x31u8; 32])],
            Some(&address),
        );
        assert!(
            out.contains("the store is inconsistent at height 7"),
            "the daemon's own reason must reach the operator, not be replaced \
             by a decode complaint: {out}"
        );
    }

    /// **A reply about a different transaction is not an answer.** The count
    /// matched, every field was well-formed, and only the identity was wrong —
    /// so a console binding the reply to the request by arity alone would have
    /// printed another transaction under the operator's hash.
    #[test]
    fn an_entry_for_a_different_hash_is_refused() {
        let asked = [0x31u8; 32];
        let served = [0x99u8; 32];
        let addr = one_shot_raw(shekyl_rpc_types::GetTransactionsResponse {
            status: shekyl_rpc_types::RpcStatus::ok(),
            txs: vec![mined_entry(served)],
            missed_tx: Vec::new(),
        });
        let (_, out) = run(&["print_transaction", &hex::encode(asked)], Some(&addr));
        assert!(
            out.contains("asked about") && !out.contains("Found in blockchain"),
            "an entry for another hash must be refused, not rendered: {out}"
        );
    }

    /// A reply that answers AND reports the hash missed is self-contradictory;
    /// the miss is the honest half, so it decides.
    #[test]
    fn an_entry_alongside_a_missed_hash_is_not_found() {
        let asked = [0x31u8; 32];
        let addr = one_shot_raw(shekyl_rpc_types::GetTransactionsResponse {
            status: shekyl_rpc_types::RpcStatus::ok(),
            txs: vec![mined_entry(asked)],
            missed_tx: vec![HashHex::from_bytes(asked)],
        });
        let (_, out) = run(&["print_transaction", &hex::encode(asked)], Some(&addr));
        assert!(
            out.contains("wasn't found"),
            "a contradictory reply must not render as a hit: {out}"
        );
    }

    /// The C++ printed `<unknown>` below its cutoff and UTC
    /// `%Y-%m-%d %H:%M:%S` above it. A genesis block with timestamp 0 is the
    /// case an operator actually sees.
    #[test]
    fn timestamps_render_as_the_cpp_did() {
        assert_eq!(human_readable_timestamp(0), "<unknown>");
        assert_eq!(human_readable_timestamp(1_234_567_889), "<unknown>");
        assert_eq!(
            human_readable_timestamp(1_234_567_890),
            "2009-02-13 23:31:30"
        );
        assert_eq!(
            human_readable_timestamp(1_700_000_000),
            "2023-11-14 22:13:20"
        );
        // A leap day, and the end of a year — the civil-from-days arithmetic
        // is where a hand-rolled calendar goes wrong.
        assert_eq!(
            human_readable_timestamp(1_709_164_800),
            "2024-02-29 00:00:00"
        );
        assert_eq!(
            human_readable_timestamp(1_735_689_599),
            "2024-12-31 23:59:59"
        );
    }

    /// The console showed the difficulty in decimal, which the C++ got by
    /// constructing a `difficulty_type` from the `0x` wide form.
    #[test]
    fn wide_difficulty_renders_in_decimal() {
        assert_eq!(wide_difficulty_decimal("0x1"), "1");
        // 2^70 + 12345, the value the oracle emitter used.
        assert_eq!(
            wide_difficulty_decimal("0x400000000000003039"),
            "1180591620717411315769"
        );
        // Above 2^64, which is the reason the wide form exists at all.
        assert_eq!(
            wide_difficulty_decimal("0x10000000000000000"),
            "18446744073709551616"
        );
        // Unreadable input is shown rather than swallowed.
        assert_eq!(wide_difficulty_decimal("not-hex"), "not-hex");
    }

    /// Every line of `print_block_header`, in its order and wording.
    /// `reward` is SKL with nine fractional digits (`print_money`), `is
    /// orphan` is the 0/1 a streamed C++ bool produced, and an unfilled
    /// `pow_hash` prints as nothing after the colon.
    #[test]
    fn the_block_header_renders_line_for_line() {
        let header = shekyl_rpc_types::BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 0,
            prev_hash: HashHex::ZERO,
            nonce: 10101,
            orphan_status: false,
            height: 0,
            depth: 0,
            hash: HashHex::from_bytes([7u8; 32]),
            difficulty: 1,
            wide_difficulty: "0x1".to_owned(),
            difficulty_top64: 0,
            cumulative_difficulty: 1,
            wide_cumulative_difficulty: "0x1".to_owned(),
            cumulative_difficulty_top64: 0,
            reward: 100_000_000_000_000,
            block_size: 6263,
            block_weight: 6263,
            num_txes: 0,
            pow_hash: None,
            long_term_weight: 176_470,
            miner_tx_hash: HashHex::from_bytes([9u8; 32]),
            curve_tree_root: HashHex::ZERO,
            attestation_root: HashHex::ZERO,
        };
        let seven = HashHex::from_bytes([7u8; 32]).to_string();
        let nine = HashHex::from_bytes([9u8; 32]).to_string();
        let zero = HashHex::ZERO.to_string();
        assert_eq!(
            render_block_header(&header),
            format!(
                "timestamp: 0 (<unknown>)\n\
                 previous hash: {zero}\n\
                 nonce: 10101\n\
                 is orphan: 0\n\
                 height: 0\n\
                 depth: 0\n\
                 hash: {seven}\n\
                 difficulty: 1\n\
                 cumulative difficulty: 1\n\
                 POW hash: \n\
                 block size: 6263\n\
                 block weight: 6263\n\
                 long term weight: 176470\n\
                 num txes: 0\n\
                 reward: 100000.000000000\n\
                 miner tx hash: {nine}"
            )
        );
    }

    #[test]
    fn print_height_renders_the_remote_reply() {
        let address = one_shot(typed_reply(&GetHeightResponse {
            status: RpcStatus::ok(),
            height: 42,
            hash: HashHex::from_bytes([7u8; 32]),
        }));
        let (code, text) = run(&["print_height"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{text}");
        assert_eq!(text, "42");
    }

    #[test]
    fn non_ok_status_is_a_request_failure_with_the_status_as_reason() {
        let address = one_shot(typed_reply(&GetHeightResponse {
            status: RpcStatus(RpcStatus::BUSY.to_owned()),
            height: 0,
            hash: HashHex::ZERO,
        }));
        let (code, text) = run(&["print_height"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST);
        assert_eq!(text, "BUSY");
    }

    /// A daemon that could not answer sends the error envelope (HTTP 500,
    /// body still delivered); the operator sees its reason, not a serde
    /// complaint about the success type.
    #[test]
    fn error_envelope_reason_is_surfaced() {
        let address = one_shot(typed_reply(&RestErrorEnvelope {
            status: RpcStatus("ERROR".to_owned()),
            error: "chain facts unavailable".to_owned(),
        }));
        let (code, text) = run(&["print_height"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST);
        assert_eq!(text, "get_height failed: chain facts unavailable");
    }

    /// Neither shape: the reply is reported as malformed, with a bounded
    /// excerpt of what arrived.
    #[test]
    fn malformed_reply_is_named_as_such() {
        // Deliberately raw: this fixture's point is that it is not a reply.
        let address = one_shot(r#"<html>not json</html>"#.to_owned());
        let (code, text) = run(&["print_height"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST);
        assert!(
            text.starts_with("malformed get_height reply: <html>"),
            "{text}"
        );
    }

    #[test]
    fn refused_connection_is_a_request_failure_with_a_reason() {
        let (code, text) = run(&["print_height"], Some("127.0.0.1:1"));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST);
        assert!(!text.is_empty());
    }

    /// Both sources given: refused before either is touched (the live
    /// pointer is never dereferenced — it is a sentinel here).
    #[test]
    fn both_sources_is_ambiguous_and_refused() {
        let cmd = CString::new("print_height").unwrap();
        let argv = [cmd.as_ptr()];
        let address = CString::new("127.0.0.1:1").unwrap();
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        let sentinel = std::ptr::dangling_mut::<c_void>();
        // SAFETY: valid argv/address/out pointers; the non-null core pointer
        // is refused before any dereference.
        let code = unsafe {
            shekyl_daemon_console_run(
                argv.as_ptr(),
                1,
                sentinel,
                address.as_ptr(),
                1,
                &raw mut ptr,
                &raw mut len,
            )
        };
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_AMBIGUOUS_SOURCE);
        assert!(ptr.is_null());
    }

    #[test]
    fn unknown_command_and_null_arguments_refuse() {
        let (code, _) = run(&["no_such_command"], Some("127.0.0.1:1"));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_UNKNOWN);
        let (code, _) = run(&["print_height"], None);
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_NULL_PTR);
    }

    // ── RK-5a: the ported format helpers ───────────────────────────────────
    //
    // Every expected string below was **printed by the C++ it replaces**, by
    // linking `get_human_readable_timespan`, `get_human_readable_bytes` and
    // `get_time_interval_string` into the unit-test binary and dumping them
    // for these inputs. They are transcriptions of an oracle's output, not a
    // reading of its source — which is the difference between a test that
    // pins the format and one that repeats whatever the port got wrong.

    #[test]
    fn a_timespan_reads_the_way_the_daemon_has_always_printed_it() {
        for (seconds, expected) in [
            (0u64, "0 seconds"),
            (1, "1 seconds"),
            (59, "59 seconds"),
            (60, "1.0 minutes"),
            (90, "1.5 minutes"),
            // The boundary is `< 3600`, so one second short of an hour is
            // sixty minutes rather than an hour.
            (3599, "60.0 minutes"),
            (3600, "1.0 hours"),
            (5400, "1.5 hours"),
            (86399, "24.0 hours"),
            (86400, "1.0 days"),
            (200_000, "2.3 days"),
            // A "month" is 30.5 days and a "year" 365.25, and the boundary
            // uses the same expression as the divisor.
            (2_635_200, "1.0 months"),
            (31_557_600, "1.0 years"),
            // Exactly a century is not "100.0 years".
            (3_155_760_000, "a long time"),
            (4_000_000_000, "a long time"),
        ] {
            assert_eq!(human_readable_timespan(seconds), expected, "{seconds}s");
        }
    }

    #[test]
    fn bytes_read_in_base_two_units() {
        for (bytes, expected) in [
            (0u64, "0 B"),
            (1, "1 B"),
            (1023, "1023 B"),
            (1024, "1.00 kB"),
            (1500, "1.46 kB"),
            // One byte short of a mebibyte rounds *up* to "1024.00 kB"
            // rather than crossing into MB.
            (1_048_575, "1024.00 kB"),
            (1_048_576, "1.00 MB"),
            (1_073_741_824, "1.00 GB"),
            (1_099_511_627_776, "1.00 TB"),
            (5_000_000_000_000, "4.55 TB"),
        ] {
            assert_eq!(human_readable_bytes(bytes), expected, "{bytes} bytes");
        }
    }

    #[test]
    fn a_time_interval_is_the_dotted_dhms_form() {
        for (seconds, expected) in [
            (0u64, "d0.h0.m0.s0"),
            (1, "d0.h0.m0.s1"),
            (59, "d0.h0.m0.s59"),
            (61, "d0.h0.m1.s1"),
            (3661, "d0.h1.m1.s1"),
            (90061, "d1.h1.m1.s1"),
            (1_000_000, "d11.h13.m46.s40"),
        ] {
            assert_eq!(time_interval(seconds), expected, "{seconds}s");
        }
    }

    /// A peer never seen reads "never", not an interval measured from 1970.
    #[test]
    fn a_peer_never_seen_has_no_interval() {
        let peer = shekyl_rpc_types::Peer {
            id: 0x1122_3344_5566_7788,
            host: "10.32.0.7".to_owned(),
            ip: 0x0700_200a,
            port: 18080,
            last_seen: 0,
            pruning_seed: 0,
        };
        let line = render_peer("white", &peer, 1_750_000_000);
        assert!(line.contains("never"), "{line}");
        // The id is zero-padded to 16 hex characters, as `peerid_to_string`
        // padded it.
        assert!(line.contains("1122334455667788"), "{line}");
        assert!(line.contains("10.32.0.7:18080"), "{line}");

        let seen = shekyl_rpc_types::Peer {
            last_seen: 1_750_000_000 - 90061,
            ..peer
        };
        assert!(
            render_peer("gray", &seen, 1_750_000_000).contains("d1.h1.m1.s1"),
            "a seen peer carries its interval"
        );
    }

    /// The three address arms, rendered.
    ///
    /// The tor arm is the one the C++ got wrong: its `host` is the whole
    /// `str()`, port included, and its `port` is 0, so appending produced
    /// `…onion:18080:0`.
    #[test]
    fn a_peer_address_gains_a_port_only_when_it_has_one() {
        let peer = |host: &str, port: u16| shekyl_rpc_types::Peer {
            id: 1,
            host: host.to_owned(),
            ip: 0,
            port,
            last_seen: 1_750_000_000,
            pruning_seed: 0,
        };
        let line = |p: &shekyl_rpc_types::Peer| render_peer("white", p, 1_750_000_000);

        assert!(line(&peer("10.32.0.7", 18080)).contains("10.32.0.7:18080"));
        assert!(line(&peer("2001:db8::1", 18081)).contains("2001:db8::1:18081"));

        let tor = line(&peer("abcdefghijklmnop.onion:18080", 0));
        assert!(tor.contains("abcdefghijklmnop.onion:18080"), "{tor}");
        assert!(
            !tor.contains(":18080:0"),
            "the port must not be appended to an address that already carries \
             one; got:\n{tor}"
        );
    }

    /// The address type names the console prints, including the arm the C++
    /// `default:` produced.
    #[test]
    fn address_types_have_their_own_names() {
        assert_eq!(address_type_name(1), "IPv4");
        assert_eq!(address_type_name(2), "IPv6");
        assert_eq!(address_type_name(3), "I2P");
        assert_eq!(address_type_name(4), "Tor");
        assert_eq!(address_type_name(0), "invalid");
        assert_eq!(address_type_name(200), "invalid");
    }

    /// The capacities are a parameter now, so this can be tested against the
    /// values the daemon actually holds. Before the hoist it read
    /// `shekyl_rpc_peerlist_limits` directly, whose unit-test link stub
    /// answers **0** — so a test here would have asserted `0/0` and agreed
    /// with a number no daemon reports, which is precisely what `ffi.rs`'s
    /// comment prohibited and nothing enforced.
    #[test]
    fn the_peerlist_stats_report_real_capacities() {
        let out = render_peer_list_stats(7, 250, 1000, 5000);
        assert!(out.contains("White list size: 7/1000 (0.7%)"), "{out}");
        assert!(out.contains("Gray list size: 250/5000 (5%)"), "{out}");
        // The float noise this rounding exists to stop: 7/1000 is exactly the
        // value that renders `0.7000000000000001` under `{}` on an `f64`.
        assert!(!out.contains("0.7000000000000001"), "{out}");
    }

    /// A zero capacity is what the link stub would have supplied, and the
    /// divide-by-zero guard makes it *survivable* — which is why a test that
    /// touched it would have gone green rather than crashed.
    #[test]
    fn a_zero_capacity_renders_rather_than_dividing_by_zero() {
        let out = render_peer_list_stats(3, 0, 0, 0);
        assert!(out.contains("White list size: 3/0 (0%)"), "{out}");
    }

    /// Every selector the C++ parser can forward, plus the ones it cannot.
    ///
    /// The parser resolves an unqualified `print_pl` to both lists and sends
    /// `both`; `white` and `gray` narrow. The last two rows are the reason
    /// this is a function: an argument in that position that is neither
    /// keyword must not silently select nothing.
    #[test]
    fn the_peer_list_selector_narrows_only_on_its_two_keywords() {
        assert_eq!(peer_list_selection(Some("both")), (true, true));
        assert_eq!(peer_list_selection(None), (true, true));
        assert_eq!(peer_list_selection(Some("white")), (true, false));
        assert_eq!(peer_list_selection(Some("gray")), (false, true));
        assert_eq!(peer_list_selection(Some("0")), (true, true));
        assert_eq!(peer_list_selection(Some("")), (true, true));
    }

    fn net_stats_reply(status: &str) -> String {
        typed_reply(&shekyl_rpc_types::GetNetStatsResponse {
            status: RpcStatus(status.to_owned()),
            start_time: 1_700_000_000,
            total_packets_in: 40,
            total_bytes_in: 4096,
            total_packets_out: 10,
            total_bytes_out: 2048,
        })
    }

    /// `print_net_stats` over its two legs — the native `/get_net_stats` and
    /// the bridged `/get_limit`.
    ///
    /// The command the §2.1.1 note calls covered, finally covered.
    ///
    /// The byte counts come from the native leg and the two limits from the
    /// **bridged** one, so the assertions below cannot both hold unless both
    /// legs arrived. The limits are also asymmetric (8 down, 4 up) because a
    /// single number would pass a renderer that read one field twice — the
    /// defect a missing `#[serde(default)]` cannot catch. Elapsed time is
    /// wall-clock here (`unix_now`), so the averages are deliberately not
    /// asserted; what this test owns is the leg, not the arithmetic.
    #[test]
    fn net_stats_renders_the_bridged_limits_beside_the_native_counters() {
        let address = route_server(vec![
            ("/get_net_stats", net_stats_reply("OK")),
            (
                "/get_limit",
                r#"{"status":"OK","limit_up":4,"limit_down":8}"#.to_owned(),
            ),
        ]);
        let (code, out) = run(&["print_net_stats"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
        assert!(out.contains("Received 4096 bytes"), "{out}");
        assert!(out.contains("Sent 2048 bytes"), "{out}");
        assert!(out.contains("limit of 8.00 kB/s"), "{out}");
        assert!(out.contains("limit of 4.00 kB/s"), "{out}");
    }

    /// A `/get_limit` reply missing a field is **named**, not defaulted.
    ///
    /// This is the assertion that makes `GetLimitReplyProvisional`'s missing
    /// `#[serde(default)]` load-bearing rather than a style choice. With the
    /// attribute this test goes green while printing a limit of `0 B/s` — a
    /// number the daemon never sent — so the failure it guards against is
    /// precisely a passing run. RK-8 renaming the field gets an error naming
    /// it instead of four confident zeros.
    #[test]
    fn a_get_limit_reply_missing_a_field_is_refused_rather_than_defaulted() {
        let address = route_server(vec![
            ("/get_net_stats", net_stats_reply("OK")),
            ("/get_limit", r#"{"status":"OK","limit_up":4}"#.to_owned()),
        ]);
        let (code, out) = run(&["print_net_stats"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST, "{out}");
        assert!(out.contains("malformed get_limit reply"), "{out}");
        assert!(out.contains("limit_down"), "{out}");
    }

    fn info_reply(height: u64) -> String {
        serde_json::json!({
            "status": "OK",
            "height": height,
            "target_height": 0,
            "target": 120,
            "wide_difficulty": "0x1e240",
            "wide_cumulative_difficulty": "0x2dc6c0",
            "testnet": false,
            "stagenet": false,
            "start_time": 1_700_000_000u64,
            "outgoing_connections_count": 8,
            "incoming_connections_count": 3,
            // A field the console does not read, present because the daemon
            // sends about thirty of them: an unknown field must be ignored,
            // since RK-5c *adding* one is not a break.
            "tx_pool_size": 4
        })
        .to_string()
    }

    fn header_at(height: u64) -> shekyl_rpc_types::BlockHeader {
        shekyl_rpc_types::BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1_600_000_000u64.saturating_add(height),
            prev_hash: HashHex::ZERO,
            nonce: 42,
            orphan_status: false,
            height,
            depth: 0,
            hash: HashHex::from_bytes([u8::try_from(height % 256).unwrap(); 32]),
            difficulty: 1000,
            wide_difficulty: "0x3e8".to_owned(),
            difficulty_top64: 0,
            cumulative_difficulty: 1000,
            wide_cumulative_difficulty: "0x3e8".to_owned(),
            cumulative_difficulty_top64: 0,
            reward: 600_000_000_000,
            block_size: 100,
            block_weight: 100,
            num_txes: 1,
            pow_hash: None,
            long_term_weight: 100,
            miner_tx_hash: HashHex::ZERO,
            curve_tree_root: HashHex::ZERO,
            attestation_root: HashHex::ZERO,
        }
    }

    fn headers_range_reply(heights: &[u64]) -> String {
        typed_reply(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "result": shekyl_rpc_types::GetBlockHeadersRangeResponse {
                status: RpcStatus::ok(),
                headers: heights.iter().copied().map(header_at).collect(),
            },
        }))
    }

    /// `print_blockchain_info 2 3` asks for exactly that window and lists it.
    #[test]
    fn blockchain_info_lists_the_window_it_was_given() {
        let address = route_server(vec![(
            "json_rpc:get_block_headers_range",
            headers_range_reply(&[2, 3]),
        )]);
        let (code, out) = run(&["print_blockchain_info", "2", "3"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
        assert!(out.contains("height: 2, timestamp: 1600000002"), "{out}");
        assert!(out.contains("height: 3, timestamp: 1600000003"), "{out}");
        assert!(out.contains("major version: 1, minor version: 0"), "{out}");
        assert!(
            out.contains("difficulty: 1000, nonce 42, reward 600.000000000"),
            "{out}"
        );
        // Entries are separated by a blank line, as the C++ listed them.
        assert!(out.contains("\n\nheight: 3"), "{out}");
    }

    /// The positive form does not read `/get_info` at all.
    ///
    /// Asserted from the log rather than inferred from a passing run: the
    /// route server has no `/get_info` row, so a leg that fired would 404 and
    /// fail — but only for as long as nobody adds that row to this fixture.
    #[test]
    fn a_non_negative_start_needs_no_tip_read() {
        let (address, log) = route_server_recording(vec![
            ("/get_info", info_reply(100)),
            (
                "json_rpc:get_block_headers_range",
                headers_range_reply(&[2, 3]),
            ),
        ]);
        let (code, out) = run(&["print_blockchain_info", "2", "3"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
        let asked = log.lock().unwrap();
        assert!(
            asked.iter().all(|(path, _)| path != "/get_info"),
            "the literal form must not spend a bridged leg: {asked:?}"
        );
        let (_, body) = &asked[0];
        let params: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(params["params"]["start_height"], 2);
        assert_eq!(params["params"]["end_height"], 3);
    }

    /// The negative form resolves its window against the tip, which is the
    /// only reason this command reads `/get_info`.
    ///
    /// Height 100 with `-3` asks for the last three blocks: 97, 98, 99. The
    /// **request** is what this pins, read out of the server's log — a canned
    /// reply arrives whatever window was asked for, so asserting only on the
    /// output would pass a command that resolved the window wrongly.
    #[test]
    fn a_negative_start_counts_back_from_the_tip() {
        let (address, log) = route_server_recording(vec![
            ("/get_info", info_reply(100)),
            (
                "json_rpc:get_block_headers_range",
                headers_range_reply(&[97, 98, 99]),
            ),
        ]);
        let (code, out) = run(&["print_blockchain_info", "-3", "3"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
        assert!(out.contains("height: 97"), "{out}");
        assert!(out.contains("height: 99"), "{out}");

        let asked = log.lock().unwrap();
        let (_, body) = asked
            .iter()
            .find(|(path, _)| path == "/json_rpc")
            .expect("the range was asked for");
        let params: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(params["params"]["start_height"], 97);
        assert_eq!(params["params"]["end_height"], 99);
        // And the tip read came first: resolving the window needs it.
        assert_eq!(asked[0].0, "/get_info");
    }

    /// A window longer than the chain is refused by name.
    ///
    /// The C++ said so and it is worth keeping: an operator who typed a
    /// number too large can act on "larger than blockchain height" and cannot
    /// act on an empty listing.
    #[test]
    fn a_window_longer_than_the_chain_is_refused_by_name() {
        let address = route_server(vec![("/get_info", info_reply(3))]);
        let (code, out) = run(&["print_blockchain_info", "-10", "10"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST, "{out}");
        assert!(out.contains("larger than blockchain height"), "{out}");
    }

    /// A `/get_info` reply missing a field the console reads is named.
    ///
    /// The same assertion as `/get_limit`'s, on the leg RK-5c will actually
    /// move. Without it, a renamed `height` would make this command resolve
    /// its window against a tip of zero and report the chain as empty.
    #[test]
    fn a_get_info_reply_missing_a_field_is_refused_rather_than_defaulted() {
        let mut info: serde_json::Value = serde_json::from_str(&info_reply(100)).unwrap();
        info.as_object_mut().unwrap().remove("height");
        let address = route_server(vec![("/get_info", info.to_string())]);
        let (code, out) = run(&["print_blockchain_info", "-3", "3"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST, "{out}");
        assert!(out.contains("malformed get_info reply"), "{out}");
        assert!(out.contains("height"), "{out}");
    }

    fn fee_reply(fees: [u64; 4]) -> String {
        typed_reply(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "result": shekyl_rpc_types::GetFeeEstimateResponse {
                status: RpcStatus::ok(),
                fees: shekyl_rpc_types::FeeTiers(fees),
                quantization_mask: 10_000,
            },
        }))
    }

    /// epee's median, both parities.
    ///
    /// The even case is the one with a decision in it: epee averages the two
    /// middle elements and floors, which a lower-middle median (the usual
    /// Rust one-liner) would silently change.
    #[test]
    fn the_median_is_epees_including_its_even_length_average() {
        assert_eq!(median(&mut []), 0);
        assert_eq!(median(&mut [7]), 7);
        assert_eq!(median(&mut [3, 1, 2]), 2);
        // (2 + 4) / 2 = 3, not 2.
        assert_eq!(median(&mut [4, 2, 1, 8]), 3);
        // Floors: (1 + 2) / 2 = 1.
        assert_eq!(median(&mut [2, 1]), 1);
        // And it cannot overflow forming the sum.
        assert_eq!(median(&mut [u64::MAX, u64::MAX]), u64::MAX);
    }

    /// The version tallies list ascending, omit versions with no votes, and
    /// separate with `", "` — the string the C++ built by hand.
    #[test]
    fn a_version_tally_lists_only_the_versions_present() {
        let mut counts = [0u32; 256];
        assert_eq!(version_tally(&counts), "");
        counts[2] = 3;
        counts[1] = 1;
        assert_eq!(version_tally(&counts), "1 v1, 3 v2");
    }

    /// `print_blockchain_dynamic_stats` over its four legs, minus the one
    /// this slice deleted.
    ///
    /// The fixture makes every aggregate distinguishable: three blocks with
    /// weights 100/300/200 (median 200, which a mean would report as 200 too,
    /// so the weights are chosen with an even sibling case in the median test
    /// above), one and two transactions, and two block versions.
    #[test]
    fn dynamic_stats_reports_the_window_it_summarized() {
        let mut headers: Vec<shekyl_rpc_types::BlockHeader> =
            [7u64, 8, 9].iter().map(|h| header_at(*h)).collect();
        headers[0].block_weight = 100;
        headers[1].block_weight = 300;
        headers[2].block_weight = 200;
        headers[0].num_txes = 1;
        headers[1].num_txes = 2;
        headers[2].num_txes = 3;
        headers[2].minor_version = 2;
        headers[0].timestamp = 1000;
        headers[1].timestamp = 1120;
        headers[2].timestamp = 1300;
        let range = typed_reply(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "result": shekyl_rpc_types::GetBlockHeadersRangeResponse {
                status: RpcStatus::ok(),
                headers,
            },
        }));
        let (address, log) = route_server_recording(vec![
            ("/get_info", info_reply(10)),
            ("json_rpc:get_fee_estimate", fee_reply([20, 80, 320, 4000])),
            ("json_rpc:get_block_headers_range", range),
        ]);
        let (code, out) = run(&["print_blockchain_dynamic_stats", "3"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");

        // The header line: `wide_difficulty` 0x1e240 is 123456, the
        // cumulative 0x2dc6c0 is 3000000, and the fee is **tier 0** — the
        // value the retired `fee` scalar carried.
        assert!(
            out.contains("Height: 10, diff 123456, cum. diff 3000000, target 120 sec"),
            "{out}"
        );
        assert!(out.contains("dyn fee 0.000000020/byte"), "{out}");

        // avg diff 1000; span 300 / 3 = 100 sec; (1+2+3)/3 = 2 txes;
        // reward is constant so its mean is itself; median weight 200.
        assert!(out.contains("Last 3: avg. diff 1000"), "{out}");
        assert!(out.contains("100 avg sec/block"), "{out}");
        assert!(out.contains("avg num txes 2"), "{out}");
        assert!(out.contains("avg. reward 600.000000000"), "{out}");
        assert!(out.contains("median block weight 200"), "{out}");
        assert!(out.contains("Block versions: 3 v1"), "{out}");
        assert!(out.contains("Voting for: 2 v0, 1 v2"), "{out}");

        // The window: height 10, three blocks, so [7, 9].
        let asked = log.lock().unwrap();
        let range_body = asked
            .iter()
            .filter(|(path, _)| path == "/json_rpc")
            .map(|(_, body)| serde_json::from_str::<serde_json::Value>(body).unwrap())
            .find(|v| v["method"] == "get_block_headers_range")
            .expect("the range was asked for");
        assert_eq!(range_body["params"]["start_height"], 7);
        assert_eq!(range_body["params"]["end_height"], 9);

        // And the deleted leg is not asked for. Asserted, because "the
        // fixture has no row for it" stops being evidence the moment someone
        // adds one.
        assert!(
            asked
                .iter()
                .all(|(path, body)| path != "/hard_fork_info" && !body.contains("hard_fork_info")),
            "the tautological hard-fork leg must be gone: {asked:?}"
        );
    }

    /// A window longer than the chain is clamped to the chain, not refused.
    ///
    /// `nblocks.min(height)` — the C++ clamped too, and the difference from
    /// `print_blockchain_info`'s refusal is deliberate: that command names a
    /// window and this one asks for "the last N", which a shorter chain still
    /// answers.
    #[test]
    fn dynamic_stats_clamps_a_window_longer_than_the_chain() {
        let (address, log) = route_server_recording(vec![
            ("/get_info", info_reply(2)),
            ("json_rpc:get_fee_estimate", fee_reply([20, 80, 320, 4000])),
            (
                "json_rpc:get_block_headers_range",
                headers_range_reply(&[0, 1]),
            ),
        ]);
        let (code, out) = run(&["print_blockchain_dynamic_stats", "500"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
        assert!(out.contains("Last 2:"), "{out}");
        let asked = log.lock().unwrap();
        let range_body = asked
            .iter()
            .filter(|(path, _)| path == "/json_rpc")
            .map(|(_, body)| serde_json::from_str::<serde_json::Value>(body).unwrap())
            .find(|v| v["method"] == "get_block_headers_range")
            .expect("the range was asked for");
        assert_eq!(range_body["params"]["start_height"], 0);
        assert_eq!(range_body["params"]["end_height"], 1);
    }

    fn hash_n(n: u8) -> HashHex {
        HashHex::from_bytes([n; 32])
    }

    fn alt_chains_reply(chains: &serde_json::Value) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "result": {"status": "OK", "chains": chains},
        })
        .to_string()
    }

    fn one_alt_chain(
        tip: u8,
        height: u64,
        length: u64,
        hashes: &[u8],
        parent: u8,
    ) -> serde_json::Value {
        serde_json::json!({
            "block_hash": hash_n(tip),
            "height": height,
            "length": length,
            "difficulty": 1000,
            "wide_difficulty": "0x3e8",
            "difficulty_top64": 0,
            "block_hashes": hashes.iter().map(|h| hash_n(*h)).collect::<Vec<_>>(),
            "main_chain_parent_block": hash_n(parent),
        })
    }

    fn slots_reply(slots: Vec<shekyl_rpc_types::BlockHeaderSlot>) -> String {
        typed_reply(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "result": shekyl_rpc_types::GetBlockHeaderByHashResponse {
                status: RpcStatus::ok(),
                block_headers: slots,
            },
        }))
    }

    fn slot(hash: u8, timestamp: u64) -> shekyl_rpc_types::BlockHeaderSlot {
        let mut header = header_at(0);
        header.timestamp = timestamp;
        header.hash = hash_n(hash);
        shekyl_rpc_types::BlockHeaderSlot {
            hash: hash_n(hash),
            block_header: Some(header),
        }
    }

    /// The listing form: sorted by height, filtered, and each line carrying
    /// the fork point and its depth below our tip.
    #[test]
    fn alt_chain_info_lists_and_filters() {
        let address = route_server(vec![
            ("/get_info", info_reply(100)),
            (
                "json_rpc:get_alternate_chains",
                alt_chains_reply(&serde_json::json!([
                    one_alt_chain(9, 90, 2, &[8, 9], 7),
                    one_alt_chain(5, 50, 1, &[5], 4),
                ])),
            ),
        ]);
        let (code, out) = run(&["alt_chain_info", "", "0", "0"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
        assert!(out.starts_with("2 alternate chains found:"), "{out}");
        // Sorted by height: the height-50 chain first.
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[1].contains("from height 50"), "{out}");
        assert!(lines[2].contains("from height 89"), "{out}");
        // 100 - 89 - 1 = 10 deep; 100 - 50 - 1 = 49.
        assert!(lines[1].contains("(49 deep)"), "{out}");
        assert!(lines[2].contains("(10 deep)"), "{out}");

        // `>1` keeps only chains longer than one block.
        let address = route_server(vec![
            ("/get_info", info_reply(100)),
            (
                "json_rpc:get_alternate_chains",
                alt_chains_reply(&serde_json::json!([
                    one_alt_chain(9, 90, 2, &[8, 9], 7),
                    one_alt_chain(5, 50, 1, &[5], 4),
                ])),
            ),
        ]);
        let (code, out) = run(&["alt_chain_info", "", "1", "0"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
        assert!(out.starts_with("1 alternate chains found:"), "{out}");
        assert!(out.contains("from height 89"), "{out}");
    }

    /// The tip form: the chain's blocks, its parent, and the derived age,
    /// span and hash-rate share.
    #[test]
    fn alt_chain_info_reports_one_chain_by_tip() {
        let tip = hash_n(9).to_string();
        let address = route_server(vec![
            ("/get_info", info_reply(100)),
            (
                "json_rpc:get_alternate_chains",
                alt_chains_reply(&serde_json::json!([one_alt_chain(9, 90, 2, &[8, 9], 7)])),
            ),
            (
                "json_rpc:get_block_header_by_hash",
                // Asked in this order: the chain's blocks, then the parent.
                slots_reply(vec![slot(8, 1000), slot(9, 1240), slot(7, 880)]),
            ),
        ]);
        let (code, out) = run(&["alt_chain_info", &tip, "0", "0"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
        assert!(
            out.contains(&format!("Found alternate chain with tip {tip}")),
            "{out}"
        );
        assert!(
            out.contains("2 blocks long, from height 89 (10 deep)"),
            "{out}"
        );
        assert!(
            out.contains(&format!("Chain parent on main chain: {}", hash_n(7))),
            "{out}"
        );
        // Span 1240 - 880 = 360 s; share = 100 * 120 * 2 / 360 = 66.666667%.
        assert!(out.contains("Time span:"), "{out}");
        assert!(
            out.contains("Approximated 66.666667% of network hash rate"),
            "{out}"
        );
    }

    /// A hash whose header the daemon does not hold is named.
    ///
    /// This is the case the C++ could not express. Its check was
    /// `block_headers.size() != chain.length + 1`, so a reorg between
    /// `get_alternate_chains` and the header batch produced "Failed to get
    /// block header info for alt chain" — true, and naming nothing. The
    /// per-element reply carries a slot for the missing hash, so the console
    /// can say which one moved.
    #[test]
    fn a_hash_with_no_header_is_named_rather_than_counted() {
        let tip = hash_n(9).to_string();
        let missing = hash_n(9).to_string();
        let address = route_server(vec![
            ("/get_info", info_reply(100)),
            (
                "json_rpc:get_alternate_chains",
                alt_chains_reply(&serde_json::json!([one_alt_chain(9, 90, 2, &[8, 9], 7)])),
            ),
            (
                "json_rpc:get_block_header_by_hash",
                slots_reply(vec![
                    slot(8, 1000),
                    shekyl_rpc_types::BlockHeaderSlot {
                        hash: hash_n(9),
                        block_header: None,
                    },
                    slot(7, 880),
                ]),
            ),
        ]);
        let (code, out) = run(&["alt_chain_info", &tip, "0", "0"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST, "{out}");
        assert!(
            out.contains(&format!("no block header for {missing}")),
            "{out}"
        );
    }

    /// A reply of the right length whose slots answer different hashes is
    /// refused — which the count check could not see at all.
    #[test]
    fn a_slot_answering_a_different_hash_is_refused() {
        let requested = vec![hash_n(1), hash_n(2)];
        let slots = vec![slot(1, 10), slot(3, 20)];
        let err = headers_in_correspondence(&slots, &requested)
            .expect_err("slot 1 answers hash 3, not hash 2");
        assert!(err.contains(&hash_n(3).to_string()), "{err}");
        assert!(err.contains(&hash_n(2).to_string()), "{err}");

        // And the length disagreement it replaces.
        let err = headers_in_correspondence(&slots[..1], &requested)
            .expect_err("one slot for two hashes");
        assert!(err.contains("1 of 2"), "{err}");

        // The agreeing case, so this is not a test that only knows how to
        // refuse.
        let good = headers_in_correspondence(&[slot(1, 10), slot(2, 20)], &requested)
            .expect("both slots answer what was asked");
        assert_eq!(good.len(), 2);
    }

    /// Blocks sharing a timestamp get a sentence, not `inf%`.
    ///
    /// The C++ guarded this site with `back().difficulty > 0` — a check on a
    /// value the percentage does not contain, whose message named
    /// `cumulative difficulty` while reading `difficulty`. The reachable
    /// hazard is a zero span, which divided straight through.
    #[test]
    fn a_zero_span_reports_why_rather_than_dividing() {
        let tip = hash_n(9).to_string();
        let address = route_server(vec![
            ("/get_info", info_reply(100)),
            (
                "json_rpc:get_alternate_chains",
                alt_chains_reply(&serde_json::json!([one_alt_chain(9, 90, 2, &[8, 9], 7)])),
            ),
            (
                "json_rpc:get_block_header_by_hash",
                slots_reply(vec![slot(8, 1000), slot(9, 1000), slot(7, 1000)]),
            ),
        ]);
        let (code, out) = run(&["alt_chain_info", &tip, "0", "0"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
        assert!(out.contains("share a timestamp"), "{out}");
        assert!(!out.contains("inf"), "{out}");
    }

    /// A tip that is not a known alt chain says so.
    #[test]
    fn an_unknown_tip_is_named() {
        let tip = hash_n(200).to_string();
        let address = route_server(vec![
            ("/get_info", info_reply(100)),
            (
                "json_rpc:get_alternate_chains",
                alt_chains_reply(&serde_json::json!([])),
            ),
        ]);
        let (code, out) = run(&["alt_chain_info", &tip, "0", "0"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST, "{out}");
        assert!(
            out.contains("is not the tip of any known alternate chain"),
            "{out}"
        );
    }

    fn fork_reply(active: u8, queried: u8, earliest: u64) -> String {
        typed_reply(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "result": shekyl_rpc_types::HardForkInfoResponse {
                status: RpcStatus::ok(),
                queried_version: queried,
                active_version: active,
                enabled: true,
                window: 10080,
                votes: 10080,
                threshold: 0,
                voting: active,
                state: 2,
                earliest_height: earliest,
            },
        }))
    }

    fn mining_reply(active: bool, speed: u64, background: bool) -> String {
        serde_json::json!({
            "status": "OK",
            "active": active,
            "speed": speed,
            "is_background_mining_enabled": background,
        })
        .to_string()
    }

    /// A hash rate for a human, at every prefix boundary the C++ had.
    #[test]
    fn a_mining_speed_picks_the_prefix_the_cpp_picked() {
        assert_eq!(mining_speed(0), "0 H/s");
        assert_eq!(mining_speed(999), "999 H/s");
        // 1000 is the first prefixed value: still under a million, so `k`.
        assert_eq!(mining_speed(1000), "1.00 kH/s");
        // 999999 / 1000 is 999.999, which `%.2f` rounds up — so the largest
        // value that still reads in kilohashes prints as `1000.00 kH/s`.
        // The C++ did this too; it is recorded rather than corrected,
        // because the alternative is a second rounding rule for a console
        // line.
        assert_eq!(mining_speed(999_999), "1000.00 kH/s");
        // A million divides once, then reads as thousands of thousands.
        assert_eq!(mining_speed(1_000_000), "1.00 MH/s");
        assert_eq!(mining_speed(2_500_000_000), "2.50 GH/s");
        // Past every prefix, the raw number — the C++ fell out of its loop
        // with `prefix = 0` and formatted the value it started with.
        assert_eq!(
            mining_speed(10u128.pow(33)),
            format!("{} H/s", 10u128.pow(33))
        );
    }

    /// The sync percentage, including the 99.9 clamp that exists so a daemon
    /// one block short does not read as finished.
    #[test]
    fn the_sync_percentage_never_rounds_up_to_a_hundred() {
        assert!((sync_percentage(50, 100) - 50.0).abs() < f64::EPSILON);
        // Fully synced is a real 100.
        assert!((sync_percentage(100, 100) - 100.0).abs() < f64::EPSILON);
        // A target below our height means we are ahead of it.
        assert!((sync_percentage(100, 50) - 100.0).abs() < f64::EPSILON);
        // 99999/100000 would print as 100.0%; it must not.
        assert!((sync_percentage(99_999, 100_000) - 99.9).abs() < f64::EPSILON);
        // And an empty chain divides by one, not by zero.
        assert!((sync_percentage(0, 0) - 0.0).abs() < f64::EPSILON);
    }

    /// The fork countdown, in each of its units and in the cases that say
    /// nothing.
    #[test]
    fn the_fork_countdown_changes_units_where_the_cpp_did() {
        assert_eq!(fork_extra_info(100, 100, 120), " (forking now)");
        // Already past: nothing to count down to.
        assert_eq!(fork_extra_info(50, 100, 120), "");
        assert_eq!(fork_extra_info(120, 100, 120), " (next fork in 20 blocks)");
        // 720 blocks/day at a 120 s target, so 30 blocks/hour: 100 blocks is
        // under half a day and reads in hours.
        assert_eq!(fork_extra_info(200, 100, 120), " (next fork in 3.3 hours)");
        assert_eq!(fork_extra_info(1_540, 100, 120), " (next fork in 2.0 days)");
        // Past thirty days, nothing.
        assert_eq!(fork_extra_info(100_000, 100, 120), "");
        // A target the daemon reports as zero, or as longer than an hour,
        // divided straight through in the C++.
        assert_eq!(fork_extra_info(200, 100, 0), "");
        assert_eq!(fork_extra_info(200, 100, 90_000), "");
    }

    /// The whole status line, on the remote arm, with all three legs.
    #[test]
    fn the_status_line_reads_the_way_the_daemon_has_always_printed_it() {
        let address = route_server(vec![
            ("/get_info", info_reply(100)),
            ("json_rpc:hard_fork_info", fork_reply(3, 7, 100)),
            ("/mining_status", mining_reply(true, 2500, false)),
        ]);
        let (code, out) = run(&["status"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
        assert!(out.contains("Height: 100/100 (100.0%) on mainnet"), "{out}");
        assert!(out.contains("mining at 2.50 kH/s"), "{out}");
        // net hash = difficulty 123456 / target 120, integer-divided to
        // 1028 H/s, which reads as 1.03 kH/s.
        assert!(out.contains("net hash 1.03 kH/s"), "{out}");
        // **`v3`, not `v7`.** The fixture's queried and active versions
        // differ on purpose: `on_hard_fork_info` set `res.version` from
        // `get_current_hard_fork_version()` regardless of the request, so
        // this line is the active fork. Reading `queried_version` here would
        // invert the reason RK-5b split the two.
        assert!(out.contains("v3 (forking now)"), "{out}");
        assert!(out.contains("8(out)+3(in) connections"), "{out}");
        assert!(out.contains(", uptime "), "{out}");
    }

    /// A restricted daemon discloses no start time, and the uptime clause is
    /// omitted rather than reported as zero.
    #[test]
    fn a_daemon_that_hides_its_start_time_gets_no_uptime_clause() {
        let mut info: serde_json::Value = serde_json::from_str(&info_reply(100)).unwrap();
        info["start_time"] = serde_json::json!(0);
        let address = route_server(vec![
            ("/get_info", info.to_string()),
            ("json_rpc:hard_fork_info", fork_reply(3, 3, 0)),
            ("/mining_status", mining_reply(false, 0, false)),
        ]);
        let (code, out) = run(&["status"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
        assert!(out.contains("not mining"), "{out}");
        assert!(!out.contains("uptime"), "{out}");
    }

    /// A remote daemon that will not serve `/mining_status` still gets a
    /// status line.
    ///
    /// A restricted listener does not serve the route at all — an ordinary
    /// posture, not a fault — so the eight other things the line knows are
    /// still worth printing. The route server has no `/mining_status` row, so
    /// it answers 404.
    #[test]
    fn a_restricted_remote_daemon_still_reports_its_status() {
        let address = route_server(vec![
            ("/get_info", info_reply(100)),
            ("json_rpc:hard_fork_info", fork_reply(3, 3, 0)),
        ]);
        let (code, out) = run(&["status"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
        assert!(out.contains("mining info unavailable"), "{out}");
        assert!(out.contains("Height: 100/100"), "{out}");
    }

    /// A syncing daemon answers `BUSY`, which is neither mining nor idle.
    #[test]
    fn a_busy_mining_status_reads_as_syncing() {
        let address = route_server(vec![
            ("/get_info", info_reply(100)),
            ("json_rpc:hard_fork_info", fork_reply(3, 3, 0)),
            (
                "/mining_status",
                serde_json::json!({
                    "status": "BUSY",
                    "active": false,
                    "speed": 0,
                    "is_background_mining_enabled": false,
                })
                .to_string(),
            ),
        ]);
        let (code, out) = run(&["status"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{out}");
        assert!(out.contains(", syncing,"), "{out}");
    }

    /// A route the daemon no longer serves is a request failure, not a zero.
    ///
    /// The other half of §2.1.1: the acceptor answers `404` for an unrouted
    /// path, which is what a daemon that dropped `/get_limit` would do.
    #[test]
    fn a_bridged_route_the_daemon_stopped_serving_fails_loudly() {
        let address = route_server(vec![("/get_net_stats", net_stats_reply("OK"))]);
        let (code, out) = run(&["print_net_stats"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST, "{out}");
        assert!(!out.contains("limit of 0 B/s"), "{out}");
    }
}
