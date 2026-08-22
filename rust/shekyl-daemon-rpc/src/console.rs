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
    fn one_shot(reply: &'static str) -> String {
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

    #[test]
    fn print_height_renders_the_remote_reply() {
        let address = one_shot(r#"{"status":"OK","height":42,"hash":"00"}"#);
        let (code, text) = run(&["print_height"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_OK, "{text}");
        assert_eq!(text, "42");
    }

    #[test]
    fn non_ok_status_is_a_request_failure_with_the_status_as_reason() {
        let address = one_shot(r#"{"status":"BUSY","height":0,"hash":""}"#);
        let (code, text) = run(&["print_height"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST);
        assert_eq!(text, "BUSY");
    }

    /// A daemon that could not answer sends the error envelope (HTTP 500,
    /// body still delivered); the operator sees its reason, not a serde
    /// complaint about the success type.
    #[test]
    fn error_envelope_reason_is_surfaced() {
        let address = one_shot(r#"{"status":"ERROR","error":"chain facts unavailable"}"#);
        let (code, text) = run(&["print_height"], Some(&address));
        assert_eq!(code, SHEKYL_DAEMON_CONSOLE_ERR_REQUEST);
        assert_eq!(text, "get_height failed: chain facts unavailable");
    }

    /// Neither shape: the reply is reported as malformed, with a bounded
    /// excerpt of what arrived.
    #[test]
    fn malformed_reply_is_named_as_such() {
        let address = one_shot(r#"<html>not json</html>"#);
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
