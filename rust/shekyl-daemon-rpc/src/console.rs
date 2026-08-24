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
