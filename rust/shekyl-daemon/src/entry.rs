// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The C ABI between the Rust `main()` and the C++ remnant
//! (`DAEMON_CONFIG_CUTOVER.md` §2.1, §2.9).
//!
//! Nothing crosses in either direction but what is here. C++ `main()`
//! hands [`shekyl_daemon_main`] a [`ShekylDaemonEntry`]: its version
//! strings and two function pointers, `run` and `stop`. Rust fills a
//! [`ShekylDaemonSnapshot`], the read-only structure holding exactly the
//! values whose reader is still C++, and calls `run` with it. The C++
//! defines no symbol Rust imports, so every Rust test can drive the entry
//! with a fake pair. This file is the whole C ABI and a signature-gate
//! surface; the two `#[allow(unsafe_code)]` below are its only exceptions
//! to the crate's rule, each on the one item the lint names.
//!
//! **Eleven fields** (§2.9). [`SNAPSHOT_FIELDS`] pins the count and
//! [`shekyl_daemon_snapshot_field_count`] exports it for the C++ to assert;
//! each later slice that moves a reader into Rust deletes its field. The
//! advertised endpoints are not a field: their reader is Rust, the peer
//! lists' own entry (§2.8), where the handshake's port check will read it
//! (Rick, 2026-10-15); no C++ reads them. The
//! snapshot is the whole of what the remnant reads: it parses nothing.
//!
//! **A test's snapshot.** The C++ test binaries construct the remnant too;
//! [`shekyl_daemon_snapshot_parse`] builds a snapshot from a test argument
//! list through the one real parse (rule 26 B2), taking no lock, writing
//! no marker and starting no logging, and
//! [`shekyl_daemon_snapshot_free`] releases it.
//!
//! **One stop path.** [`shekyl_daemon_request_stop`] is how the remnant
//! asks for a stop — the console's `exit` and the RPC's `stop_daemon` —
//! so every trigger reaches the one owner in [`crate::signals`] and the
//! stop runs in §2.2 step 9's order. The remnant never stops itself.

use std::ffi::{c_char, c_int};

/// A list of C strings.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ShekylStringList {
    /// The strings, each NUL-terminated; valid for `len` entries.
    pub items: *const *const c_char,
    /// How many.
    pub len: usize,
}

/// The admin endpoint a client command dials.
///
/// Four octets in network order, so a `memcpy` into a `uint32_t` is the
/// value `inet_addr` would have returned, and the port in host order.
/// `present` is false for a daemon start. One member of the snapshot, so
/// the field count stays eleven.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ShekylClientEndpoint {
    /// The address, network order.
    pub octets: [u8; 4],
    /// The port.
    pub port: u16,
    /// Whether a client command is dialing this endpoint.
    pub present: bool,
}

/// A mining address the configuration already decoded.
///
/// The text is display only. `spend` and `view` are the classical public
/// keys. `ml_kem` is the encapsulation key, not the C++ account layout:
/// the miner derives the X25519 prefix from `view` and assembles the
/// account address from these bytes. The pointers are into the snapshot's
/// owned data and live as long as that data does. One member of the
/// snapshot, so the field count stays eleven.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ShekylMineAddress {
    /// The address text, NUL-terminated. Never parsed.
    pub text: *const c_char,
    /// The spend public key.
    pub spend: [u8; 32],
    /// The view public key.
    pub view: [u8; 32],
    /// The ML-KEM encapsulation key. Null when `ml_kem_len` is 0.
    pub ml_kem: *const u8,
    /// The encapsulation key's length.
    pub ml_kem_len: usize,
}

/// The values whose reader is still C++ (`DAEMON_CONFIG_CUTOVER.md` §2.9),
/// filled once by Rust before the remnant is constructed.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ShekylDaemonSnapshot {
    /// The resolved data directory, NUL-terminated; read by core.
    pub data_dir: *const c_char,
    /// The network, as `cryptonote::network_type`: 0 mainnet, 1 testnet,
    /// 2 stagenet, 3 fakechain (regtest).
    pub network: u8,
    /// Offline: both connectors off; read by core and the protocol handler.
    pub offline: bool,
    /// The fixed difficulty, or 0 for none; read by core.
    pub fixed_difficulty: u64,
    /// The pool's weight bound in bytes; read by core.
    pub txpool_weight_max: u64,
    /// Chain synchronisation on; read by the protocol handler.
    pub sync: bool,
    /// The decoded mining address, or null for none; read by the miner.
    pub mine_address: *const ShekylMineAddress,
    /// The mining thread count, or 0 for `auto`; read by the miner. The
    /// miner chooses the count when this is 0.
    pub mine_threads: u32,
    /// The interactive console on; read by the C++ console.
    pub console: bool,
    /// The console's command words; empty for a daemon start. Read by the
    /// C++ console client.
    pub command: ShekylStringList,
    /// The admin endpoint a client-mode command reaches. `present` is false
    /// for a daemon start. Read by the C++ console client.
    pub client_endpoint: ShekylClientEndpoint,
}

const _: () = assert!(std::mem::size_of::<ShekylClientEndpoint>() == 8);
const _: () = assert!(std::mem::align_of::<ShekylClientEndpoint>() == 2);

/// The snapshot's field count. A gate asserts it against the definition
/// above and the C++ asserts it against [`shekyl_daemon_snapshot_field_count`].
pub const SNAPSHOT_FIELDS: u32 = 11;

/// The remnant's `run`: constructs core, the protocol handler, the node
/// server and the RPC from the snapshot, runs until stopped, and returns
/// the exit status. `noexcept`: every C++ exception is caught inside it.
pub type RunFn = extern "C" fn(*const ShekylDaemonSnapshot) -> c_int;

/// The remnant's `stop`: requests the stop `run` is waiting for and
/// returns at once. `noexcept`.
pub type StopFn = extern "C" fn();

/// What C++ hands the Rust entry.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ShekylDaemonEntry {
    /// `SHEKYL_RELEASE_NAME`, NUL-terminated.
    pub release_name: *const c_char,
    /// `SHEKYL_VERSION_FULL`, NUL-terminated.
    pub version_full: *const c_char,
    /// `SHEKYL_PROTOCOL_VERSION`.
    pub protocol_version: u32,
    /// The remnant's `run`.
    pub run: Option<RunFn>,
    /// The remnant's `stop`.
    pub stop: Option<StopFn>,
}

/// The snapshot's field count, for the C++ to assert against the
/// structure it reads. `no_mangle` is what the `unsafe_code` lint flags
/// here, for the symbol it exports; the body is safe.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn shekyl_daemon_snapshot_field_count() -> u32 {
    SNAPSHOT_FIELDS
}

/// The daemon's one C entry: C++ `main()` builds an entry and calls this,
/// and Rust owns the process from here. Returns the exit status.
///
/// # Safety
///
/// `entry` must be null or point to a `ShekylDaemonEntry` that outlives
/// the call and whose strings are NUL-terminated and static.
#[allow(unsafe_code)]
#[no_mangle]
pub unsafe extern "C" fn shekyl_daemon_main(entry: *const ShekylDaemonEntry) -> i32 {
    if entry.is_null() {
        return crate::run::EXIT_FAILED;
    }
    // SAFETY: the caller's contract above.
    let entry = unsafe { &*entry };
    crate::main(entry)
}

/// Asks for a stop, from the remnant: the console's `exit` and the RPC's
/// `stop_daemon`. Returns at once; the stop runs in step 9's order from the
/// one owner. A request before the owner waits is kept for it; a second
/// request is a no-op.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn shekyl_daemon_request_stop() {
    crate::signals::request_stop();
}

/// A snapshot for a C++ test binary, from `argc` arguments (the program
/// first) through the real parse: the table, the file, the sections and
/// the platform roots, as a start does, but no lock, no marker and no
/// logging. Writes the snapshot's address to `out` and returns 0; a
/// refusal is printed to standard error and returns 2; a null argument
/// returns 1. The snapshot and what it points at live until
/// [`shekyl_daemon_snapshot_free`].
///
/// # Safety
///
/// `argv` points at `argc` NUL-terminated strings and `out` at a writable
/// pointer slot.
#[allow(unsafe_code)]
#[no_mangle]
pub unsafe extern "C" fn shekyl_daemon_snapshot_parse(
    argc: c_int,
    argv: *const *const c_char,
    out: *mut *mut ShekylDaemonSnapshot,
) -> i32 {
    if argv.is_null() || out.is_null() || argc < 1 {
        return crate::run::EXIT_FAILED;
    }
    let Ok(count) = usize::try_from(argc) else {
        return crate::run::EXIT_FAILED;
    };
    // SAFETY: the caller's contract above.
    let args: Vec<std::ffi::OsString> = unsafe { std::slice::from_raw_parts(argv, count) }
        .iter()
        .map(|&p| {
            if p.is_null() {
                std::ffi::OsString::new()
            } else {
                // SAFETY: each pointer is NUL-terminated by the contract.
                std::ffi::OsString::from(
                    unsafe { std::ffi::CStr::from_ptr(p) }
                        .to_string_lossy()
                        .into_owned(),
                )
            }
        })
        .collect();
    match crate::run::snapshot_for_tests(&args, &crate::host()) {
        Ok(leased) => {
            // SAFETY: `out` is writable by the contract.
            unsafe { *out = Box::into_raw(leased).cast::<ShekylDaemonSnapshot>() };
            0
        }
        Err(status) => status,
    }
}

/// Releases a snapshot [`shekyl_daemon_snapshot_parse`] built. A null is
/// ignored.
///
/// # Safety
///
/// `snapshot` is null or was returned by `shekyl_daemon_snapshot_parse`
/// and is freed once.
#[allow(unsafe_code)]
#[no_mangle]
pub unsafe extern "C" fn shekyl_daemon_snapshot_free(snapshot: *mut ShekylDaemonSnapshot) {
    if snapshot.is_null() {
        return;
    }
    // SAFETY: the caller's contract: the pointer is the one `Box::into_raw`
    // of a `Leased` produced, whose first member is the snapshot.
    drop(unsafe { Box::from_raw(snapshot.cast::<crate::run::Leased>()) });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gate: the structure's field count is the pinned count, read off
    /// this file's text so a field added without moving the pin fails here.
    #[test]
    fn the_snapshot_has_exactly_the_pinned_fields() {
        let source = include_str!("entry.rs");
        let start = source
            .find("pub struct ShekylDaemonSnapshot {")
            .expect("the struct");
        let end = source[start..].find("\n}\n").expect("its end") + start;
        let fields = source[start..end]
            .lines()
            .filter(|l| l.trim_start().starts_with("pub ") && l.contains(':'))
            .count();
        assert_eq!(u32::try_from(fields).unwrap(), SNAPSHOT_FIELDS);
        assert_eq!(shekyl_daemon_snapshot_field_count(), SNAPSHOT_FIELDS);
    }
}
