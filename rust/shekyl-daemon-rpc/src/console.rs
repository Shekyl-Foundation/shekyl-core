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
}
