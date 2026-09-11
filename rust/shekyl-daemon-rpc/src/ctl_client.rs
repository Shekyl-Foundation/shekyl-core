// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `shekyld <command>` control client — the outbound half of the daemon's
//! HTTP surface, over the first-party Rust transport.
//!
//! `shekyld status` / `shekyld exit` / … run as a second process that talks
//! to the running daemon over its plaintext loopback RPC (`main.cpp`,
//! `t_command_server` with `is_rpc = true`). That path used epee's
//! `http_simple_client`; this export replaces it so the C++ side keeps only
//! the request/response structs it already owns (Phase 2 of
//! `docs/DAEMON_RPC_RUST.md` owns those) and the transport is
//! [`shekyl_rpc_transport::HttpRpc`] — the same client the wallet dials the
//! daemon with.
//!
//! Scope is exactly the control path's: plaintext, no credentials, no proxy.
//! The daemon registers neither `--rpc-login` nor `--rpc-ssl*`
//! (`DAEMON_RPC_RUST.md` §Auth), so an authenticated or TLS arm here would be
//! an outbound capability with no inbound counterpart to reach.
//!
//! One call, one request, one short-lived current-thread runtime: a control
//! invocation issues a handful of requests and exits, so a runtime per call
//! is cheaper than threading a handle through the C++ executor.

use std::os::raw::c_char;
use std::time::Duration;

use shekyl_rpc_client::Rpc as _;
use shekyl_rpc_transport::HttpRpc;

/// Request completed; `out` holds the response body.
pub const SHEKYL_DAEMON_CTL_OK: i32 = 0;
/// A required pointer was null, or a C string was not UTF-8.
pub const SHEKYL_DAEMON_CTL_ERR_NULL_PTR: i32 = -1;
/// `address` did not form a dialable `http://host:port` endpoint.
pub const SHEKYL_DAEMON_CTL_ERR_ENDPOINT: i32 = -2;
/// Connect, send, receive, or timeout failure; `out` holds the reason.
pub const SHEKYL_DAEMON_CTL_ERR_TRANSPORT: i32 = -3;
/// The runtime could not be started, or the caller is already inside one.
pub const SHEKYL_DAEMON_CTL_ERR_RUNTIME: i32 = -4;

/// Hand `bytes` to C++ as a `(ptr, len)` pair the caller releases with
/// [`shekyl_daemon_ctl_free`]. `len == capacity` by construction
/// (`into_boxed_slice`), which is what the free relies on. An empty
/// buffer is a null/zero pair — not a forgotten empty `Box` — so the
/// caller's free is a no-op and nothing is leaked.
///
/// # Safety
///
/// `out_ptr` and `out_len` are valid for writes (checked non-null by the
/// caller before reaching here).
pub(crate) unsafe fn emit(bytes: Vec<u8>, out_ptr: *mut *mut u8, out_len: *mut usize) {
    if bytes.is_empty() {
        out_ptr.write(std::ptr::null_mut());
        out_len.write(0);
        return;
    }
    let mut boxed = bytes.into_boxed_slice();
    let len = boxed.len();
    let ptr = boxed.as_mut_ptr();
    std::mem::forget(boxed);
    out_ptr.write(ptr);
    out_len.write(len);
}

/// Copy an FFI `(ptr, len)` body into an owned `Vec`. Refuses null-with-
/// nonzero-len and `len > isize::MAX` *before* `from_raw_parts` (rule 40 /
/// SA-R-7: that bound is a language-level precondition, not a courtesy).
/// Owned for the same reason as [`c_string`]: the boundary never mints a
/// borrow whose lifetime is the unconstrained lifetime of a raw pointer.
///
/// # Safety
///
/// A non-null `ptr` must address at least `len` readable bytes for the
/// duration of this call.
unsafe fn body_from_ptr(ptr: *const u8, len: usize) -> Option<Vec<u8>> {
    if len == 0 {
        return Some(Vec::new());
    }
    if ptr.is_null() || len > isize::MAX as usize {
        return None;
    }
    Some(std::slice::from_raw_parts(ptr, len).to_vec())
}

/// Run one POST to completion on a private current-thread runtime.
pub(crate) fn post_blocking(
    address: &str,
    route: &str,
    body: Vec<u8>,
    timeout: Duration,
) -> Result<Vec<u8>, (i32, String)> {
    // `block_on` inside an existing runtime panics; refuse instead (rule 40:
    // refuse, never panic, at the boundary). No production caller is inside
    // one — the control client is its own process — so this is a guard, not
    // a path.
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err((
            SHEKYL_DAEMON_CTL_ERR_RUNTIME,
            "control client invoked from inside an async runtime".to_string(),
        ));
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| (SHEKYL_DAEMON_CTL_ERR_RUNTIME, format!("runtime: {e}")))?;
    rt.block_on(async move {
        let rpc = HttpRpc::with_custom_timeout(format!("http://{address}"), timeout)
            .await
            .map_err(|e| (SHEKYL_DAEMON_CTL_ERR_ENDPOINT, format!("{e}")))?;
        rpc.post(route.trim_start_matches('/'), body)
            .await
            .map_err(|e| (SHEKYL_DAEMON_CTL_ERR_TRANSPORT, format!("{e}")))
    })
}

/// POST `body` to `http://<address>/<route>` on the daemon's plaintext
/// loopback RPC and return the response body.
///
/// * `address` — `host:port` of the daemon RPC listener (no scheme).
/// * `route` — the path, with or without its leading `/` (`/json_rpc`,
///   `/getinfo`, …). The content type follows the route (`.bin` → binary,
///   otherwise JSON), the same rule the wallet transport applies.
/// * `body` / `body_len` — the request body; `body` may be null iff
///   `body_len == 0`.
/// * `timeout_secs` — per-request bound, covering connect through the last
///   body byte.
/// * `out_ptr` / `out_len` — on `SHEKYL_DAEMON_CTL_OK` the response body; on
///   any error that can write (every path except a null `out_ptr`/`out_len`),
///   the UTF-8 reason. Either way the caller releases the buffer with
///   [`shekyl_daemon_ctl_free`] (a null/zero pair is a no-op there).
///
/// Returns one of the `SHEKYL_DAEMON_CTL_*` codes. The HTTP status is not
/// surfaced separately: the daemon's routes answer every request with a JSON
/// body that carries its own `status` / `error`, and the C++ caller decodes
/// that — the transport's job ends at "a response arrived".
///
/// # Safety
///
/// `address` and `route` must be valid NUL-terminated C strings; `body`
/// must be valid for `body_len` reads (or null with `body_len == 0`);
/// `out_ptr` and `out_len` must be valid for writes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_daemon_ctl_post(
    address: *const c_char,
    route: *const c_char,
    body: *const u8,
    body_len: usize,
    timeout_secs: u64,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if out_ptr.is_null() || out_len.is_null() {
        return SHEKYL_DAEMON_CTL_ERR_NULL_PTR;
    }
    // From here every exit writes the out pair, so the caller's free is
    // unconditional.
    out_ptr.write(std::ptr::null_mut());
    out_len.write(0);

    // Owned at the boundary so a later refactor cannot hold an `&str` whose
    // lifetime is the unconstrained `'a` of the C pointer.
    let Some(address) = c_string(address) else {
        emit(b"address was null or not UTF-8".to_vec(), out_ptr, out_len);
        return SHEKYL_DAEMON_CTL_ERR_NULL_PTR;
    };
    let Some(route) = c_string(route) else {
        emit(b"route was null or not UTF-8".to_vec(), out_ptr, out_len);
        return SHEKYL_DAEMON_CTL_ERR_NULL_PTR;
    };
    let Some(body) = body_from_ptr(body, body_len) else {
        emit(
            b"body was null with a non-zero length, or longer than isize::MAX".to_vec(),
            out_ptr,
            out_len,
        );
        return SHEKYL_DAEMON_CTL_ERR_NULL_PTR;
    };

    match post_blocking(&address, &route, body, Duration::from_secs(timeout_secs)) {
        Ok(response) => {
            emit(response, out_ptr, out_len);
            SHEKYL_DAEMON_CTL_OK
        }
        Err((code, reason)) => {
            emit(reason.into_bytes(), out_ptr, out_len);
            code
        }
    }
}

/// Release a buffer returned through [`shekyl_daemon_ctl_post`]'s out pair.
/// A null pointer or zero length is a no-op.
///
/// # Safety
///
/// `(ptr, len)` must be exactly a pair produced by `shekyl_daemon_ctl_post`
/// and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn shekyl_daemon_ctl_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
}

/// Copy a C string into an owned `String`; `None` for null or non-UTF-8.
/// Owned so the FFI boundary does not mint a `&str` whose lifetime is the
/// unconstrained lifetime of a raw pointer.
///
/// # Safety
///
/// `p` must be null or a valid NUL-terminated C string.
pub(crate) unsafe fn c_string(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    std::ffi::CStr::from_ptr(p).to_str().ok().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Call the export the way C++ does and hand back `(code, out bytes)`,
    /// releasing the buffer through the export's own free.
    fn call(address: &str, route: &str, body: &[u8], timeout_secs: u64) -> (i32, Vec<u8>) {
        let address = CString::new(address).unwrap();
        let route = CString::new(route).unwrap();
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        // SAFETY: valid C strings, body slice, and out pointers.
        let code = unsafe {
            shekyl_daemon_ctl_post(
                address.as_ptr(),
                route.as_ptr(),
                body.as_ptr(),
                body.len(),
                timeout_secs,
                &raw mut ptr,
                &raw mut len,
            )
        };
        let out = if ptr.is_null() {
            Vec::new()
        } else {
            // SAFETY: the export produced this pair.
            unsafe { std::slice::from_raw_parts(ptr, len).to_vec() }
        };
        // SAFETY: freeing exactly the pair the export produced.
        unsafe { shekyl_daemon_ctl_free(ptr, len) };
        (code, out)
    }

    /// A one-request HTTP/1.1 acceptor on an ephemeral loopback port: reads
    /// the request, records it, answers `200` with `reply`.
    fn one_shot_server(reply: &'static [u8]) -> (String, std::thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr").to_string();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            // Read until the headers end, then the declared body.
            loop {
                let n = stream.read(&mut buf).expect("read");
                request.extend_from_slice(&buf[..n]);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&request[..end]).to_string();
                    let content_length = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.eq_ignore_ascii_case("content-length")
                                .then(|| v.trim().parse::<usize>().ok())?
                        })
                        .unwrap_or(0);
                    while request.len() < end + 4 + content_length {
                        let n = stream.read(&mut buf).expect("read body");
                        request.extend_from_slice(&buf[..n]);
                    }
                    break;
                }
                if n == 0 {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                reply.len()
            );
            stream.write_all(response.as_bytes()).expect("write head");
            stream.write_all(reply).expect("write body");
            request
        });
        (address, handle)
    }

    /// The happy path end to end: the request goes out as a JSON POST to the
    /// named route with the caller's body, and the response body comes back
    /// verbatim through the out pair.
    #[test]
    fn posts_body_to_route_and_returns_response_body() {
        let (address, server) = one_shot_server(br#"{"status":"OK","height":7}"#);
        let (code, out) = call(&address, "/getheight", br#"{}"#, 10);
        assert_eq!(code, SHEKYL_DAEMON_CTL_OK);
        assert_eq!(out, br#"{"status":"OK","height":7}"#);

        let request = String::from_utf8(server.join().expect("server")).expect("utf8");
        let mut lines = request.lines();
        assert_eq!(
            lines.next(),
            Some("POST /getheight HTTP/1.1"),
            "the leading slash is normalized, not doubled: {request}"
        );
        assert!(
            request
                .lines()
                .any(|l| l.eq_ignore_ascii_case("content-type: application/json")),
            "JSON routes carry the JSON content type: {request}"
        );
        assert!(
            request.ends_with("{}"),
            "the body is sent as given: {request}"
        );
    }

    /// Nothing listening: the transport error is reported as such, with the
    /// reason in the out buffer — never a panic, never an empty failure.
    /// `127.0.0.1:1` is connection-refused without a bind-then-drop race.
    #[test]
    fn refused_connection_is_a_transport_error_with_a_reason() {
        let (code, out) = call("127.0.0.1:1", "/getinfo", b"{}", 10);
        assert_eq!(code, SHEKYL_DAEMON_CTL_ERR_TRANSPORT);
        assert!(!out.is_empty(), "an error must carry its reason");
    }

    /// An address that is not a dialable endpoint refuses at construction
    /// with the endpoint code, before any socket is opened.
    #[test]
    fn malformed_address_is_an_endpoint_error() {
        let (code, out) = call("not a host:port", "/getinfo", b"{}", 10);
        assert_eq!(
            code,
            SHEKYL_DAEMON_CTL_ERR_ENDPOINT,
            "{}",
            String::from_utf8_lossy(&out)
        );
    }

    /// Null out-pointers refuse without writing; every other null-argument
    /// arm writes a UTF-8 reason into the out pair (the documented contract
    /// once `out_ptr`/`out_len` are known non-null).
    #[test]
    fn null_arguments_refuse() {
        let address = CString::new("127.0.0.1:1").unwrap();
        let route = CString::new("/x").unwrap();
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        // SAFETY: exercising the null-argument arms only.
        unsafe {
            assert_eq!(
                shekyl_daemon_ctl_post(
                    address.as_ptr(),
                    route.as_ptr(),
                    std::ptr::null(),
                    0,
                    1,
                    std::ptr::null_mut(),
                    &raw mut len
                ),
                SHEKYL_DAEMON_CTL_ERR_NULL_PTR
            );

            assert_eq!(
                shekyl_daemon_ctl_post(
                    std::ptr::null(),
                    route.as_ptr(),
                    std::ptr::null(),
                    0,
                    1,
                    &raw mut ptr,
                    &raw mut len
                ),
                SHEKYL_DAEMON_CTL_ERR_NULL_PTR
            );
            assert!(len > 0, "a writable out pair carries the reason");
            shekyl_daemon_ctl_free(ptr, len);
            ptr = std::ptr::null_mut();
            len = 0;

            assert_eq!(
                shekyl_daemon_ctl_post(
                    address.as_ptr(),
                    route.as_ptr(),
                    std::ptr::null(),
                    3,
                    1,
                    &raw mut ptr,
                    &raw mut len
                ),
                SHEKYL_DAEMON_CTL_ERR_NULL_PTR
            );
            assert!(len > 0, "a writable out pair carries the reason");
            shekyl_daemon_ctl_free(ptr, len);
        }
    }
}
