// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The configuration snapshot the C++ remnant reads
//! (`DAEMON_CONFIG_CUTOVER.md` §2.9), and the snapshot export the C++ test
//! binaries and the blockchain importer construct their core from.
//!
//! **Six fields** (§2.9). [`SNAPSHOT_FIELDS`] pins the count and
//! [`shekyl_daemon_snapshot_field_count`] exports it for the C++ to assert;
//! `scripts/ci/check_snapshot_readers.py` holds every field to a C++ reader
//! under `src/`, so a field whose reader moved into Rust fails there until
//! it is deleted. The fixed difficulty, the pool's weight bound, the mining
//! address and the mining threads were deleted with the Rust binary
//! (DC-Q24, §3.7): no C++ read them, and the Rust miner reads
//! `mine-address` from the configuration itself. `dev-sync` is not a field: chain
//! sync's owner reads it from the configuration. The advertised endpoints
//! are not a field: their reader is Rust, the peer lists' own entry (§2.8),
//! where the handshake's port check will read it (Rick, 2026-10-15); no C++
//! reads them. The snapshot is the whole of what the remnant reads: it
//! parses nothing.
//!
//! **Here, in `shekyl-ffi`.** [`shekyl_daemon_snapshot_parse`] sits in the
//! ordinary FFI library on top of `shekyl-daemon-config`, so the importer
//! and `core_tests` link `libshekyl_ffi.a`. *Records-was (to 2026-11-01):*
//! the export once lived in the daemon image, the staticlib the C++
//! `shekyld` linked, whose daemon-RPC objects import C++ symbols only
//! `shekyld` links; those binaries linked on Linux and macOS only because
//! `--gc-sections` / `-dead_strip` dropped the unreferenced RPC code, and
//! MinGW, which keeps it, failed the link (Rick, 2026-10-19). The image is
//! retired with the C++ executable (DC-Q19). The `shekyld` binary carries
//! this module too: `shekyl-daemon` starts the remnant with
//! [`SnapshotData::call`].
//!
//! **A test's snapshot.** [`shekyl_daemon_snapshot_parse`] builds a snapshot
//! from an argument list through the one real parse
//! ([`shekyl_daemon_config::load`], rule 26 B2), taking no lock, writing no
//! marker and starting no logging, and [`shekyl_daemon_snapshot_free`]
//! releases it.

use std::ffi::{c_char, c_int, CString, OsString};

use shekyl_daemon_config::exit::{refuse, EXIT_FAILED};
use shekyl_daemon_config::sections::DaemonConfig;
use shekyl_daemon_config::{load, Platform, TABLE};

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
/// the field count stays six.
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

/// The values whose reader is still C++ (`DAEMON_CONFIG_CUTOVER.md` §2.9),
/// filled once by Rust before the remnant is constructed.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ShekylDaemonSnapshot {
    /// The resolved data directory, NUL-terminated.
    pub data_dir: *const c_char,
    /// The network, as `cryptonote::network_type`: 0 mainnet, 1 testnet,
    /// 2 stagenet, 3 fakechain (regtest). Read by core and the p2p server.
    pub network: u8,
    /// Offline: both connectors off; read by the p2p server.
    pub offline: bool,
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
pub const SNAPSHOT_FIELDS: u32 = 6;

/// The snapshot's field count, for the C++ to assert against the
/// structure it reads. `no_mangle` is what the `unsafe_code` lint flags
/// here, for the symbol it exports; the body is safe.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn shekyl_daemon_snapshot_field_count() -> u32 {
    SNAPSHOT_FIELDS
}

/// The owned data behind a snapshot: built on the calling thread, moved to
/// the run thread, and alive for as long as `run` runs.
pub struct SnapshotData {
    data_dir: CString,
    network: u8,
    offline: bool,
    console: bool,
    command: Vec<CString>,
    client_endpoint: ShekylClientEndpoint,
}

impl SnapshotData {
    /// The owned data for `config`'s snapshot.
    #[must_use]
    pub fn new(config: &DaemonConfig) -> Self {
        let c = |s: &str| CString::new(s.replace('\0', "")).expect("no NUL after the filter");
        let client_endpoint = match config.session.client_endpoint {
            Some(endpoint) => ShekylClientEndpoint {
                octets: endpoint.ip().octets(),
                port: endpoint.port(),
                present: true,
            },
            None => ShekylClientEndpoint {
                octets: [0; 4],
                port: 0,
                present: false,
            },
        };
        Self {
            data_dir: c(&config.data_dir.display().to_string()),
            network: config.network.cryptonote_code(),
            offline: config.offline(),
            console: config.session.console,
            command: config.session.command.iter().map(|w| c(w)).collect(),
            client_endpoint,
        }
    }

    /// Calls `run` with a snapshot over this data, which outlives the call.
    #[must_use]
    pub fn call(&self, run: extern "C" fn(*const ShekylDaemonSnapshot) -> c_int) -> c_int {
        let command = self.command_ptrs();
        let snapshot = self.snapshot(&command);
        run(&raw const snapshot)
    }

    /// The console's command words, as text.
    #[cfg(test)]
    fn command_words(&self) -> Vec<String> {
        self.command
            .iter()
            .map(|w| w.to_string_lossy().into_owned())
            .collect()
    }

    /// The resolved data directory, as text.
    #[cfg(test)]
    fn data_dir(&self) -> String {
        self.data_dir.to_string_lossy().into_owned()
    }

    /// Pointers to the command words. Valid while `self` is borrowed, and
    /// while the returned vector is: the snapshot's `command.items` addresses
    /// this vector's buffer, not `self`.
    fn command_ptrs(&self) -> Vec<*const c_char> {
        self.command.iter().map(|w| w.as_ptr()).collect()
    }

    /// The snapshot over this data and `command`. Both must outlive every
    /// read of the result. `command.items` addresses `command`'s buffer.
    fn snapshot(&self, command: &[*const c_char]) -> ShekylDaemonSnapshot {
        ShekylDaemonSnapshot {
            data_dir: self.data_dir.as_ptr(),
            network: self.network,
            offline: self.offline,
            console: self.console,
            command: ShekylStringList {
                items: command.as_ptr(),
                len: command.len(),
            },
            client_endpoint: self.client_endpoint,
        }
    }
}

/// A snapshot leased to a C++ caller: the structure first, so its address
/// is the lease's, then what it points at.
///
/// The command pointers address `_command`'s buffer, and the data-directory
/// pointer `_data`'s allocation; neither moves when the lease is moved into
/// the box `shekyl_daemon_snapshot_parse` hands to C++. C++ frees the lease
/// on the same thread or any other; the value is not sent between Rust
/// threads.
#[repr(C)]
struct Leased {
    snapshot: ShekylDaemonSnapshot,
    _command: Vec<*const c_char>,
    _data: Box<SnapshotData>,
}

/// A snapshot leased to a C++ caller, from `args` (the program first)
/// through the one real parse.
///
/// # Errors
///
/// The refusal's exit status, once its diagnostics are printed.
fn snapshot_for(args: &[OsString], platform: &Platform) -> Result<Box<Leased>, i32> {
    let rest = args.get(1..).unwrap_or(&[]);
    let cli = shekyl_options::read_cli(&TABLE, rest.iter().cloned()).map_err(|ds| refuse(&ds))?;
    let config = load(cli, platform).map_err(|ds| refuse(&ds))?.config;
    let data = Box::new(SnapshotData::new(&config));
    let command = data.command_ptrs();
    let snapshot = data.snapshot(&command);
    Ok(Box::new(Leased {
        snapshot,
        _command: command,
        _data: data,
    }))
}

/// A snapshot for a C++ test binary, from `argc` arguments (the program
/// first) through the real parse: the table, the file, the sections and
/// the platform roots, as a start does, but no lock, no marker and no
/// logging. Writes the snapshot's address to `out` and returns 0; a
/// refusal is printed to standard error and returns 2; a vector that
/// cannot be read returns 1. The snapshot and what it points at live until
/// [`shekyl_daemon_snapshot_free`].
///
/// # Safety
///
/// `out` is a writable pointer slot. `argc` and `argv` meet
/// [`ArgumentVector::from_narrow_argv`](crate::argument_vector::ArgumentVector::from_narrow_argv)'s
/// contract: `argc` non-null NUL-terminated strings, program first. A null
/// slot, a null `argv`, `argc < 1`, or a byte the platform encoding cannot
/// represent returns 1.
#[allow(unsafe_code)]
#[no_mangle]
pub unsafe extern "C" fn shekyl_daemon_snapshot_parse(
    argc: c_int,
    argv: *const *const c_char,
    out: *mut *mut ShekylDaemonSnapshot,
) -> i32 {
    if out.is_null() {
        return EXIT_FAILED;
    }
    // SAFETY: the caller's contract on `argc` and `argv`.
    let Some(arguments) =
        (unsafe { crate::argument_vector::ArgumentVector::from_narrow_argv(argc, argv) })
    else {
        return EXIT_FAILED;
    };
    match snapshot_for(arguments.as_slice(), &crate::platform::current()) {
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
    drop(unsafe { Box::from_raw(snapshot.cast::<Leased>()) });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gate: the structure's field count is the pinned count, read off
    /// this file's text so a field added without moving the pin fails here.
    #[test]
    fn the_snapshot_has_exactly_the_pinned_fields() {
        let source = include_str!("daemon_snapshot_ffi.rs");
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

    #[test]
    fn the_snapshot_carries_the_six_values() {
        let d = tempfile::tempdir().unwrap();
        let args_v: Vec<OsString> = [
            "--network",
            "regtest",
            "--data-dir",
            d.path().to_str().unwrap(),
            "status",
            "extra",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        let cli = shekyl_options::read_cli(&TABLE, args_v).unwrap();
        let platform = Platform {
            home: Some(d.path().to_path_buf()),
            program_data: None,
        };
        let config = load(cli, &platform).unwrap().config;
        let data = SnapshotData::new(&config);
        assert_eq!(
            data.command_words(),
            vec!["status".to_owned(), "extra".to_owned()]
        );
        assert!(data.client_endpoint.present);
        assert_eq!(data.client_endpoint.octets, [127, 0, 0, 1]);
        assert_eq!(data.client_endpoint.port, 11029);
        assert_eq!(data.data_dir(), d.path().display().to_string());
        assert_eq!(data.network, 3);
        assert!(!data.offline, "regtest keeps the clearnet connector on");
        assert!(!data.console);
    }
}
