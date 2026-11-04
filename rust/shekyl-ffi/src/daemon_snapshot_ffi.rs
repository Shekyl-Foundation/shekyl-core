// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The configuration snapshot the C++ remnant reads
//! (`DAEMON_CONFIG_CUTOVER.md` §2.9), and the snapshot export the C++ test
//! binaries and the blockchain importer construct their core from.
//!
//! **Two fields** (§2.9). [`SNAPSHOT_FIELDS`] pins the count and
//! [`shekyl_daemon_snapshot_field_count`] exports it for the C++ to assert;
//! `scripts/ci/check_snapshot_readers.py` holds every field to a C++ reader
//! under `src/`, with no exemption: a field whose reader moved into Rust
//! fails there until it is deleted (DC-Q19's deletion list). A value whose
//! reader is Rust is not a field: the fixed difficulty, the mining address
//! and threads, `dev-sync`, the data directory (the chain is the Rust
//! store), the advertised endpoints (the peer lists' own entry, §2.8), and
//! the pool's weight bound (a rejected option, IG-Q11). The snapshot is the
//! whole of what the remnant reads: it parses nothing.
//!
//! **Here, in `shekyl-ffi`.** [`shekyl_daemon_snapshot_parse`] sits in the
//! ordinary FFI library on top of `shekyl-daemon-config`, so the importer
//! and `core_tests` link `libshekyl_ffi.a` and carry nothing of the daemon.
//! The `shekyld` binary carries this module too: `shekyl-daemon` starts the
//! remnant with [`SnapshotData::call`].
//!
//! **A test's snapshot.** [`shekyl_daemon_snapshot_parse`] builds a snapshot
//! from an argument list through the one real parse
//! ([`shekyl_daemon_config::load`], rule 26 B2), taking no lock, writing no
//! marker and starting no logging, and [`shekyl_daemon_snapshot_free`]
//! releases it.

use std::ffi::{c_char, c_int, OsString};

use shekyl_daemon_config::exit::{refuse, EXIT_FAILED};
use shekyl_daemon_config::sections::DaemonConfig;
use shekyl_daemon_config::{load, Platform, TABLE};

/// The values whose reader is still C++ (`DAEMON_CONFIG_CUTOVER.md` §2.9),
/// filled once by Rust before the remnant is constructed.
///
/// Aligned to a pointer: [`shekyl_daemon_snapshot_parse`] hands C++ the
/// address of this struct, which is the first member of the lease, and
/// [`shekyl_daemon_snapshot_free`] casts that address back. The lease holds
/// a `Box`, so this struct's alignment is the lease's.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug)]
pub struct ShekylDaemonSnapshot {
    /// The network, as `cryptonote::network_type`: 0 mainnet, 1 testnet,
    /// 2 stagenet, 3 fakechain (regtest). Read by core and the p2p server.
    pub network: u8,
    /// Offline: both connectors off; read by the p2p server.
    pub offline: bool,
}

const _: () = assert!(std::mem::size_of::<ShekylDaemonSnapshot>() == 8);
const _: () = assert!(std::mem::align_of::<ShekylDaemonSnapshot>() == 8);

/// The snapshot's field count. A gate asserts it against the definition
/// above and the C++ asserts it against [`shekyl_daemon_snapshot_field_count`].
pub const SNAPSHOT_FIELDS: u32 = 2;

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
    network: u8,
    offline: bool,
}

impl SnapshotData {
    /// The owned data for `config`'s snapshot.
    #[must_use]
    pub fn new(config: &DaemonConfig) -> Self {
        Self {
            network: config.network.cryptonote_code(),
            offline: config.offline(),
        }
    }

    /// Calls `run` with a snapshot over this data, which outlives the call.
    ///
    /// `run` is the remnant's entry, which dereferences the pointer it is
    /// given; it is `unsafe` so that no safe Rust can hand C++ a pointer to
    /// read (rule 40). This is its one call site.
    #[must_use]
    #[allow(unsafe_code)]
    pub fn call(&self, run: unsafe extern "C" fn(*const ShekylDaemonSnapshot) -> c_int) -> c_int {
        let snapshot = self.snapshot();
        // SAFETY: `snapshot` is a complete, initialised value on this frame
        // and outlives the call, which returns before it is dropped. `run`
        // is `noexcept` on the C++ side.
        unsafe { run(&raw const snapshot) }
    }

    /// The snapshot over this data. It must outlive every read of the result.
    fn snapshot(&self) -> ShekylDaemonSnapshot {
        ShekylDaemonSnapshot {
            network: self.network,
            offline: self.offline,
        }
    }
}

/// A snapshot leased to a C++ caller: the structure first, so its address
/// is the lease's, then the data it was built from.
///
/// Nothing in the snapshot points at `_data`; the data stays so the lease
/// is one allocation the free releases. C++ frees the lease on the same
/// thread or any other; the value is not sent between Rust threads.
#[repr(C)]
struct Leased {
    snapshot: ShekylDaemonSnapshot,
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
    let snapshot = data.snapshot();
    Ok(Box::new(Leased {
        snapshot,
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
        // A checkout with `core.autocrlf` hands this file back with CRLF
        // line ends, and `"\n}\n"` is then not in it (DC-F40).
        let source = include_str!("daemon_snapshot_ffi.rs").replace("\r\n", "\n");
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
    fn the_snapshot_carries_the_network_and_whether_the_node_is_offline() {
        let d = tempfile::tempdir().unwrap();
        let args_v: Vec<OsString> = [
            "--network",
            "regtest",
            "--data-dir",
            d.path().to_str().unwrap(),
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
        assert_eq!(data.network, 3);
        assert!(!data.offline, "regtest keeps the clearnet connector on");
    }
}
