// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Daemon ephemeral-onion FFI (PWD-E7 piece 3) — the seam `node_server`
//! calls at init to obtain its overlay inbound posture.
//!
//! Thin marshaling over [`shekyl_tor_control_daemon::BlockingDaemonTor`]: the
//! posture itself (mint in memory, `ADD_ONION` with `DiscardPK`, per-boot
//! address, bounded teardown) lives in the daemon crate; this module owns
//! only the process singleton and the C string plumbing. One instance per
//! process because the daemon has one P2P overlay — a second `start` without
//! a `shutdown` is refused, not stacked.
//!
//! The C++ zone configuration is init-time static, so `start` is a blocking
//! call on the init path (tens of seconds on a cold tor bootstrap: the pin
//! gate, the spawn, bootstrap 100%, SOCKS discovery and the publish all
//! complete before it returns). Failure is a return code plus an error
//! message in the caller's buffer; per PWD-E7's seam table the caller logs
//! loudly and continues outbound-only — no address, no overlay inbound, and
//! the daemon does not abort.

use std::ffi::{c_char, c_int, CStr};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use shekyl_tor_control_daemon::{
    probe_binary, BlockingDaemonTor, BlockingDaemonTorConfig, TorBinaryError,
};

/// The process-wide instance. `Mutex<Option<…>>` rather than `OnceLock`
/// because the lifecycle is start → (queries) → shutdown, and a shutdown
/// genuinely empties the slot (tests restart daemons in-process; production
/// starts once and shuts down once).
static DAEMON_TOR: Mutex<Option<BlockingDaemonTor>> = Mutex::new(None);

/// Bound on each post-bootstrap control round-trip. Not caller-tunable at
/// this seam: an alive tor answers `GETINFO`/`ADD_ONION` instantly, so the
/// value is about wedge detection, not policy (mirrors the wallet
/// supervisor's 30 s default).
const REPLY_DEADLINE: Duration = Duration::from_secs(30);

/// NUL-terminate `text` into the caller's buffer, truncating to fit. A zero
/// `len` writes nothing (the null-pointer case never reaches here — callers
/// gate on it). Truncation is acceptable at this seam: the buffers carry an
/// address (fixed-size) or an error message for a human log line.
///
/// # Safety
///
/// `buf` must point at `len` writable bytes.
unsafe fn write_c_string(text: &str, buf: *mut c_char, len: usize) {
    if buf.is_null() || len == 0 {
        return;
    }
    let take = text.len().min(len - 1);
    // SAFETY: caller contract — `buf` has `len` writable bytes; `take + 1 <= len`.
    unsafe {
        std::ptr::copy_nonoverlapping(text.as_ptr(), buf.cast::<u8>(), take);
        *buf.add(take) = 0;
    }
}

/// Read an optional, possibly-empty C string. `None` for null or empty
/// (both mean "not provided"); `Err(())` for non-UTF-8.
///
/// # Safety
///
/// `ptr`, when non-null, must point at a NUL-terminated string.
unsafe fn read_optional_str<'a>(ptr: *const c_char) -> Result<Option<&'a str>, ()> {
    if ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: caller contract — non-null `ptr` is NUL-terminated.
    let s = unsafe { CStr::from_ptr(ptr) }.to_str().map_err(|_| ())?;
    Ok(if s.is_empty() { None } else { Some(s) })
}

/// Probe the tor-binary discovery-and-pin gate without spawning anything —
/// the default-on posture's log-tone decision. Discovery order when
/// `tor_binary_path` is null/empty: `SHEKYL_TOR_BINARY` env → beside the
/// executable → `PATH`; either way the SP-T0c hash pin must pass.
///
/// Returns 0 when a pinned tor is available (`out_detail` = its path); 1 when
/// no candidate binary exists at all (the calm skip: ephemeral inbound is
/// simply not available on this machine, `out_detail` untouched); 2 when a
/// candidate exists but is unusable — pin mismatch (usually a distro tor that
/// can never hash-match the pinned Expert Bundle), unpinned build target, or
/// unreadable file — with the diagnostic in `out_detail` (recommend ≥ 256
/// bytes). 3 on argument errors (non-UTF-8 override path).
///
/// Advisory only: `shekyl_daemon_tor_start` re-runs the gate itself, so a
/// binary swapped between probe and start still cannot bypass the pin.
///
/// # Safety
///
/// `tor_binary_path`, when non-null, must be NUL-terminated; `out_detail`
/// must be writable for `out_detail_len` bytes (or null to skip the detail).
#[no_mangle]
pub unsafe extern "C" fn shekyl_daemon_tor_probe(
    tor_binary_path: *const c_char,
    out_detail: *mut c_char,
    out_detail_len: usize,
) -> c_int {
    // SAFETY: forwarded caller contract for `tor_binary_path`.
    let override_path = match unsafe { read_optional_str(tor_binary_path) } {
        Ok(v) => v.map(PathBuf::from),
        Err(()) => {
            // SAFETY: caller contract for `out_detail`.
            unsafe { write_c_string("tor binary path is not UTF-8", out_detail, out_detail_len) };
            return 3;
        }
    };
    match probe_binary(override_path.as_deref()) {
        Ok(path) => {
            // SAFETY: caller contract for `out_detail`.
            unsafe { write_c_string(&path.display().to_string(), out_detail, out_detail_len) };
            0
        }
        Err(TorBinaryError::NotFound) => 1,
        Err(other) => {
            // SAFETY: caller contract for `out_detail`.
            unsafe { write_c_string(&other.to_string(), out_detail, out_detail_len) };
            2
        }
    }
}

/// Start the daemon's ephemeral Tor posture: verify the binary (SP-T0c),
/// spawn a managed tor with `data_dir` as its `DataDirectory`, bootstrap,
/// publish a fresh v3 onion (key minted in memory, `Flags=DiscardPK`)
/// forwarding `virtual_port` → `127.0.0.1:local_port`, and return the
/// addresses. Blocks until published or failed (bound:
/// `bootstrap_timeout_secs` plus small constants).
///
/// Outputs (all NUL-terminated):
/// - `out_service_id` (≥ 57 bytes): the 56-char service id, no `.onion`.
/// - `out_socks_addr` (≥ 48 bytes): the managed tor's SOCKS listener
///   (`ip:port`) — the zone's outbound proxy.
/// - `out_error` (recommend ≥ 256 bytes): failure detail for the log line.
///
/// Returns 0 on success; 1 if an instance is already running (refused, not
/// stacked); 2 on argument errors (null/non-UTF-8 where required); 3 when
/// the start sequence failed (binary, spawn, bootstrap, publish — detail in
/// `out_error`; the spawned incarnation was torn down before return).
///
/// # Safety
///
/// String pointers follow the individual contracts above; output buffers
/// must be writable for the stated lengths.
#[no_mangle]
pub unsafe extern "C" fn shekyl_daemon_tor_start(
    tor_binary_path: *const c_char,
    data_dir: *const c_char,
    virtual_port: u16,
    local_port: u16,
    max_streams: u16,
    bootstrap_timeout_secs: u32,
    out_service_id: *mut c_char,
    out_service_id_len: usize,
    out_socks_addr: *mut c_char,
    out_socks_addr_len: usize,
    out_error: *mut c_char,
    out_error_len: usize,
) -> c_int {
    // SAFETY: forwarded caller contracts.
    let (binary_override, data_dir) = unsafe {
        let binary = match read_optional_str(tor_binary_path) {
            Ok(v) => v.map(PathBuf::from),
            Err(()) => {
                write_c_string("tor binary path is not UTF-8", out_error, out_error_len);
                return 2;
            }
        };
        let dir = match read_optional_str(data_dir) {
            Ok(Some(dir)) => PathBuf::from(dir),
            Ok(None) => {
                write_c_string("data_dir is required", out_error, out_error_len);
                return 2;
            }
            Err(()) => {
                write_c_string("data_dir is not UTF-8", out_error, out_error_len);
                return 2;
            }
        };
        (binary, dir)
    };
    if out_service_id.is_null() || out_socks_addr.is_null() {
        // SAFETY: `write_c_string` checks its own pointer.
        unsafe { write_c_string("output buffers are required", out_error, out_error_len) };
        return 2;
    }

    let mut slot = DAEMON_TOR.lock().expect("daemon tor mutex poisoned");
    if slot.is_some() {
        // SAFETY: caller contract for `out_error`.
        unsafe {
            write_c_string(
                "ephemeral tor already running (one instance per process)",
                out_error,
                out_error_len,
            );
        }
        return 1;
    }

    let started = BlockingDaemonTor::start(BlockingDaemonTorConfig {
        tor_binary_override: binary_override,
        data_dir,
        virtual_port,
        local_port,
        max_streams,
        bootstrap_deadline: Duration::from_secs(u64::from(bootstrap_timeout_secs)),
        reply_deadline: REPLY_DEADLINE,
    });
    match started {
        Ok(instance) => {
            // SAFETY: caller contract for the output buffers.
            unsafe {
                write_c_string(
                    instance.service_id().as_str(),
                    out_service_id,
                    out_service_id_len,
                );
                write_c_string(
                    &instance.socks_addr().to_string(),
                    out_socks_addr,
                    out_socks_addr_len,
                );
            }
            *slot = Some(instance);
            0
        }
        Err(err) => {
            // SAFETY: caller contract for `out_error`.
            unsafe { write_c_string(&err.to_string(), out_error, out_error_len) };
            3
        }
    }
}

/// Is the ephemeral tor still up? `false` when never started, already shut
/// down, or died — per PWD-E7 there is no respawn, so a death means the
/// overlay inbound posture is gone for this boot (the caller logs; the node
/// continues on its other zones).
#[no_mangle]
pub extern "C" fn shekyl_daemon_tor_is_alive() -> bool {
    DAEMON_TOR
        .lock()
        .expect("daemon tor mutex poisoned")
        .as_ref()
        .is_some_and(BlockingDaemonTor::is_alive)
}

/// Bounded teardown of the ephemeral posture (`DEL_ONION`, SIGTERM → wait →
/// SIGKILL, reap). Idempotent: returns `true` when an instance was running
/// and is now down, `false` when there was nothing to stop.
#[no_mangle]
pub extern "C" fn shekyl_daemon_tor_shutdown() -> bool {
    let instance = DAEMON_TOR.lock().expect("daemon tor mutex poisoned").take();
    match instance {
        Some(instance) => {
            instance.shutdown();
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The marshaling layer's own edge cases — no tor involved: argument
    /// validation, the buffer writer's truncation and termination.
    #[test]
    fn write_c_string_truncates_and_terminates() {
        let mut buf = [0x7Fi8 as c_char; 8];
        unsafe { write_c_string("abcdefghij", buf.as_mut_ptr(), buf.len()) };
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
        assert_eq!(s.to_str().unwrap(), "abcdefg");

        // Zero-length: untouched, no write.
        let mut tiny = [0x7Fi8 as c_char; 1];
        unsafe { write_c_string("x", tiny.as_mut_ptr(), 0) };
        assert_eq!(tiny[0], 0x7F);
    }

    #[test]
    fn start_refuses_null_required_args() {
        let mut err = [0 as c_char; 128];
        let mut sid = [0 as c_char; 64];
        let mut socks = [0 as c_char; 64];
        // Null data_dir → 2, error text says which argument.
        let rc = unsafe {
            shekyl_daemon_tor_start(
                std::ptr::null(),
                std::ptr::null(),
                11021,
                11022,
                64,
                1,
                sid.as_mut_ptr(),
                sid.len(),
                socks.as_mut_ptr(),
                socks.len(),
                err.as_mut_ptr(),
                err.len(),
            )
        };
        assert_eq!(rc, 2);
        let msg = unsafe { CStr::from_ptr(err.as_ptr()) }.to_str().unwrap();
        assert!(msg.contains("data_dir"), "got: {msg}");
    }

    #[test]
    fn lifecycle_queries_without_start_are_calm() {
        // No test in this process ever starts an instance (that needs a live
        // tor), so the singleton is empty here: is_alive is false, and
        // shutdown reports nothing-to-stop, idempotently.
        assert!(!shekyl_daemon_tor_is_alive());
        assert!(!shekyl_daemon_tor_shutdown());
        assert!(!shekyl_daemon_tor_shutdown());
    }
}
