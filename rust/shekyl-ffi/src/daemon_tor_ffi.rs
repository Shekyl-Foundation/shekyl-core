// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Daemon ephemeral-onion FFI (PWD-E7 piece 3) — the seam `node_server`
//! calls at init to obtain its overlay inbound posture.
//!
//! Thin marshaling over [`shekyl_tor_control_daemon::BlockingDaemonTor`]: the
//! posture itself (unique wiped DataDirectory, mint in memory, `ADD_ONION`
//! with `DiscardPK`, per-boot address, bounded teardown) lives in the daemon
//! crate; this module owns only the process singleton and the C string
//! plumbing. One instance per process because the daemon has one P2P overlay
//! — a second `start` without a `shutdown` is refused, not stacked.
//!
//! The C++ zone configuration is init-time static, so both calls block on
//! the init path. The seam is split where the caller's degrade postures
//! split: `start` (pin gate, unique dir, spawn, bootstrap 100%, SOCKS
//! discovery — tens of seconds on a cold bootstrap) runs *before* the daemon
//! commits any zone state, so its failure means no tor and no zone this
//! boot; `publish` (`ADD_ONION` against the live tor) runs *after* the
//! caller has bound its loopback inbound listener — on an OS-assigned port,
//! which is why the target port cannot be a `start` parameter — and its
//! failure leaves tor up, degrading the zone to outbound-only. Per PWD-E7's
//! seam table the caller logs loudly and continues either way; the daemon
//! does not abort.
//!
//! Start's return codes carry the log-tone classification that used to be a
//! separate `probe` export: `SHEKYL_DAEMON_TOR_NO_BINARY` is the calm skip,
//! `SHEKYL_DAEMON_TOR_BAD_BINARY` is found-but-unusable. Start re-runs the
//! pin gate itself; there is no advisory pass that can disagree with it.

use std::ffi::{c_char, c_int, CStr};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use shekyl_tor_control_daemon::{
    BlockingDaemonTor, BlockingDaemonTorConfig, BlockingStartError, TorBinaryError,
};

/// Matches `SHEKYL_DAEMON_TOR_*` in `shekyl_ffi.h`.
const RC_OK: c_int = 0;
const RC_ALREADY: c_int = 1;
const RC_ARG: c_int = 2;
const RC_NO_BINARY: c_int = 3;
const RC_BAD_BINARY: c_int = 4;
const RC_START_FAILED: c_int = 5;
const RC_NOT_RUNNING: c_int = 1;
const RC_PUBLISH_FAILED: c_int = 3;

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

fn lock_slot() -> std::sync::MutexGuard<'static, Option<BlockingDaemonTor>> {
    DAEMON_TOR
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Start the daemon's managed Tor: verify the binary (SP-T0c), create a unique
/// wiped DataDirectory under `data_dir_parent`, spawn tor, bootstrap to 100%,
/// and return its SOCKS listener. No onion is published yet — that is
/// `shekyl_daemon_tor_publish`, called after the daemon has bound its loopback
/// inbound listener (on an OS-assigned port; a port guessed before binding
/// could already be taken). Blocks until bootstrapped or failed (bound:
/// `bootstrap_timeout_secs` plus small constants).
///
/// The singleton lock is **not** held across the bootstrap. Concurrent starts
/// are refused; a loser of the insert race tears its incarnation down.
///
/// Outputs (all NUL-terminated):
/// - `out_socks_addr` (≥ 48 bytes): the managed tor's SOCKS listener
///   (`ip:port`) — the zone's outbound proxy.
/// - `out_error` (recommend ≥ 256 bytes): failure detail for the log line.
///
/// Returns `SHEKYL_DAEMON_TOR_OK` on success;
/// `SHEKYL_DAEMON_TOR_ALREADY_RUNNING` if an instance is already running;
/// `SHEKYL_DAEMON_TOR_ARG` on argument errors;
/// `SHEKYL_DAEMON_TOR_NO_BINARY` when no candidate exists (calm skip);
/// `SHEKYL_DAEMON_TOR_BAD_BINARY` when a candidate exists but fails the pin
/// (loud);
/// `SHEKYL_DAEMON_TOR_START_FAILED` when spawn/bootstrap failed (the
/// incarnation was torn down before return).
///
/// # Safety
///
/// String pointers follow the individual contracts above; output buffers
/// must be writable for the stated lengths.
#[no_mangle]
pub unsafe extern "C" fn shekyl_daemon_tor_start(
    tor_binary_path: *const c_char,
    data_dir_parent: *const c_char,
    bootstrap_timeout_secs: u32,
    out_socks_addr: *mut c_char,
    out_socks_addr_len: usize,
    out_error: *mut c_char,
    out_error_len: usize,
) -> c_int {
    // SAFETY: forwarded caller contracts.
    let (binary_override, data_dir_parent) = unsafe {
        let binary = match read_optional_str(tor_binary_path) {
            Ok(v) => v.map(PathBuf::from),
            Err(()) => {
                write_c_string("tor binary path is not UTF-8", out_error, out_error_len);
                return RC_ARG;
            }
        };
        let dir = match read_optional_str(data_dir_parent) {
            Ok(Some(dir)) => PathBuf::from(dir),
            Ok(None) => {
                write_c_string("data_dir_parent is required", out_error, out_error_len);
                return RC_ARG;
            }
            Err(()) => {
                write_c_string("data_dir_parent is not UTF-8", out_error, out_error_len);
                return RC_ARG;
            }
        };
        (binary, dir)
    };
    if out_socks_addr.is_null() {
        // SAFETY: `write_c_string` checks its own pointer.
        unsafe { write_c_string("output buffers are required", out_error, out_error_len) };
        return RC_ARG;
    }

    {
        let slot = lock_slot();
        if slot.is_some() {
            // SAFETY: caller contract for `out_error`.
            unsafe {
                write_c_string(
                    "ephemeral tor already running (one instance per process)",
                    out_error,
                    out_error_len,
                );
            }
            return RC_ALREADY;
        }
    }

    let started = BlockingDaemonTor::start(BlockingDaemonTorConfig {
        tor_binary_override: binary_override,
        data_dir_parent,
        bootstrap_deadline: Duration::from_secs(u64::from(bootstrap_timeout_secs)),
        reply_deadline: REPLY_DEADLINE,
    });
    match started {
        Ok(instance) => {
            let mut slot = lock_slot();
            if slot.is_some() {
                drop(slot);
                instance.shutdown();
                // SAFETY: caller contract for `out_error`.
                unsafe {
                    write_c_string(
                        "ephemeral tor already running (one instance per process)",
                        out_error,
                        out_error_len,
                    );
                }
                return RC_ALREADY;
            }
            // SAFETY: caller contract for the output buffers.
            unsafe {
                write_c_string(
                    &instance.socks_addr().to_string(),
                    out_socks_addr,
                    out_socks_addr_len,
                );
            }
            *slot = Some(instance);
            RC_OK
        }
        Err(BlockingStartError::Binary(TorBinaryError::NotFound)) => {
            // SAFETY: caller contract for `out_error`.
            unsafe { write_c_string("no tor binary found", out_error, out_error_len) };
            RC_NO_BINARY
        }
        Err(BlockingStartError::Binary(err)) => {
            // SAFETY: caller contract for `out_error`.
            unsafe { write_c_string(&err.to_string(), out_error, out_error_len) };
            RC_BAD_BINARY
        }
        Err(err) => {
            // SAFETY: caller contract for `out_error`.
            unsafe { write_c_string(&err.to_string(), out_error, out_error_len) };
            RC_START_FAILED
        }
    }
}

/// Publish the per-boot v3 onion on the running managed tor (key minted in
/// memory, `Flags=DiscardPK`), forwarding `virtual_port` (what peers dial) to
/// `127.0.0.1:local_port` (the daemon's already-bound inbound listener), with
/// `MaxStreams=max_streams` per rendezvous circuit.
///
/// Outputs (NUL-terminated):
/// - `out_service_id` (≥ 57 bytes): the 56-char service id, no `.onion`.
/// - `out_error` (recommend ≥ 256 bytes): failure detail for the log line.
///
/// Returns 0 on success; 1 if no instance is running (`start` first); 2 on
/// argument errors; 3 when the publish failed (detail in `out_error`). A
/// publish failure leaves tor running — the ruled degrade is outbound-only
/// on the zone, so the caller keeps the SOCKS proxy and serves no overlay
/// inbound this boot (or calls `shekyl_daemon_tor_shutdown` if it prefers
/// no posture at all).
///
/// # Safety
///
/// Output buffers must be writable for the stated lengths.
#[no_mangle]
pub unsafe extern "C" fn shekyl_daemon_tor_publish(
    virtual_port: u16,
    local_port: u16,
    max_streams: u16,
    out_service_id: *mut c_char,
    out_service_id_len: usize,
    out_error: *mut c_char,
    out_error_len: usize,
) -> c_int {
    if out_service_id.is_null() {
        // SAFETY: `write_c_string` checks its own pointer.
        unsafe { write_c_string("output buffers are required", out_error, out_error_len) };
        return RC_ARG;
    }

    let slot = lock_slot();
    let Some(instance) = slot.as_ref() else {
        // SAFETY: caller contract for `out_error`.
        unsafe {
            write_c_string(
                "no ephemeral tor is running (start first)",
                out_error,
                out_error_len,
            );
        }
        return RC_NOT_RUNNING;
    };

    match instance.publish(virtual_port, local_port, max_streams) {
        Ok(service_id) => {
            // SAFETY: caller contract for `out_service_id`.
            unsafe { write_c_string(service_id.as_str(), out_service_id, out_service_id_len) };
            RC_OK
        }
        Err(err) => {
            // SAFETY: caller contract for `out_error`.
            unsafe { write_c_string(&err.to_string(), out_error, out_error_len) };
            RC_PUBLISH_FAILED
        }
    }
}

/// Is the ephemeral tor still up? `false` when never started, already shut
/// down, or died — per PWD-E7 there is no respawn, so a death means the
/// overlay inbound posture is gone for this boot (the caller logs; the node
/// continues on its other zones).
#[no_mangle]
pub extern "C" fn shekyl_daemon_tor_is_alive() -> bool {
    lock_slot()
        .as_ref()
        .is_some_and(BlockingDaemonTor::is_alive)
}

/// Bounded teardown of the ephemeral posture (`DEL_ONION`, SIGTERM → wait →
/// SIGKILL, reap, DataDirectory wipe). Idempotent: returns `true` when an
/// instance was running and is now down, `false` when there was nothing to
/// stop.
#[no_mangle]
pub extern "C" fn shekyl_daemon_tor_shutdown() -> bool {
    let instance = lock_slot().take();
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
        let mut socks = [0 as c_char; 64];
        let rc = unsafe {
            shekyl_daemon_tor_start(
                std::ptr::null(),
                std::ptr::null(),
                1,
                socks.as_mut_ptr(),
                socks.len(),
                err.as_mut_ptr(),
                err.len(),
            )
        };
        assert_eq!(rc, RC_ARG);
        let msg = unsafe { CStr::from_ptr(err.as_ptr()) }.to_str().unwrap();
        assert!(msg.contains("data_dir_parent"), "got: {msg}");
    }

    #[test]
    fn start_classifies_a_missing_override_as_unusable_binary() {
        let mut err = [0 as c_char; 256];
        let mut socks = [0 as c_char; 64];
        let path = std::ffi::CString::new("/nonexistent/shekyl-tor-override").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let dir_c = std::ffi::CString::new(dir.path().to_str().unwrap()).unwrap();
        let rc = unsafe {
            shekyl_daemon_tor_start(
                path.as_ptr(),
                dir_c.as_ptr(),
                1,
                socks.as_mut_ptr(),
                socks.len(),
                err.as_mut_ptr(),
                err.len(),
            )
        };
        assert_eq!(
            rc, RC_BAD_BINARY,
            "override miss is found-but-unusable, not a calm skip"
        );
    }

    #[test]
    fn publish_without_start_is_refused() {
        let mut err = [0 as c_char; 128];
        let mut sid = [0 as c_char; 64];
        let rc = unsafe {
            shekyl_daemon_tor_publish(
                11021,
                11022,
                8,
                sid.as_mut_ptr(),
                sid.len(),
                err.as_mut_ptr(),
                err.len(),
            )
        };
        assert_eq!(rc, RC_NOT_RUNNING);
        let msg = unsafe { CStr::from_ptr(err.as_ptr()) }.to_str().unwrap();
        assert!(msg.contains("start first"), "got: {msg}");
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
