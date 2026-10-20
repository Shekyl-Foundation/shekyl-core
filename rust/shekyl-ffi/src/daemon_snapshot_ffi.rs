// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The configuration snapshot the C++ remnant reads
//! (`DAEMON_CONFIG_CUTOVER.md` §2.9), and the snapshot export the C++ test
//! binaries and the blockchain importer construct their core from.
//!
//! **Eleven fields** (§2.9). [`SNAPSHOT_FIELDS`] pins the count and
//! [`shekyl_daemon_snapshot_field_count`] exports it for the C++ to assert;
//! each later slice that moves a reader into Rust deletes its field. The
//! advertised endpoints are not a field: their reader is Rust, the peer
//! lists' own entry (§2.8), where the handshake's port check will read it
//! (Rick, 2026-10-15); no C++ reads them. The snapshot is the whole of what
//! the remnant reads: it parses nothing.
//!
//! **Here, not in the daemon image.** [`shekyl_daemon_snapshot_parse`] sits
//! in the ordinary FFI library on top of `shekyl-daemon-config`, so the
//! importer and `core_tests` link `libshekyl_ffi.a` and nothing of the
//! daemon's RPC, whose objects import C++ symbols only `shekyld` links. With
//! the export in the daemon image, those binaries linked on Linux and macOS
//! only because `--gc-sections` / `-dead_strip` dropped the unreferenced RPC
//! code; MinGW keeps it and failed the link (Rick, 2026-10-19). The daemon
//! image carries this module too: `shekyl-daemon` starts the remnant with
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

/// The snapshot's field count, for the C++ to assert against the
/// structure it reads. `no_mangle` is what the `unsafe_code` lint flags
/// here, for the symbol it exports; the body is safe.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn shekyl_daemon_snapshot_field_count() -> u32 {
    SNAPSHOT_FIELDS
}

/// The owned bytes of a mining address. The snapshot's header points at
/// these allocations, which do not move when this value moves.
struct MineOwned {
    text: CString,
    spend: [u8; 32],
    view: [u8; 32],
    ml_kem: Vec<u8>,
}

/// The owned data behind a snapshot: built on the calling thread, moved to
/// the run thread, and alive for as long as `run` runs.
///
/// The mining header is not stored here. It holds pointers, and this value
/// is moved onto the run thread before `run` reads it. [`Self::call`] builds
/// the header on that thread, for the duration of `run`. A lease boxes the
/// header so the pointer stays valid after the lease is moved.
pub struct SnapshotData {
    data_dir: CString,
    network: u8,
    offline: bool,
    fixed_difficulty: u64,
    txpool_weight_max: u64,
    sync: bool,
    mine: Option<MineOwned>,
    mine_threads: u32,
    console: bool,
    command: Vec<CString>,
    client_endpoint: ShekylClientEndpoint,
}

impl SnapshotData {
    /// The owned data for `config`'s snapshot.
    #[must_use]
    pub fn new(config: &DaemonConfig) -> Self {
        let c = |s: &str| CString::new(s.replace('\0', "")).expect("no NUL after the filter");
        let mine = config.mine.address.as_ref().map(|address| MineOwned {
            text: c(&address.text),
            spend: address.spend,
            view: address.view,
            ml_kem: address.ml_kem.clone(),
        });
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
            fixed_difficulty: config.dev.difficulty.unwrap_or(0),
            txpool_weight_max: config.txpool_weight_max,
            sync: config.dev.sync,
            mine,
            // 0 is auto. The miner chooses the count; this does not collapse
            // it to one thread.
            mine_threads: config.mine.threads.map_or(0, std::num::NonZeroU32::get),
            console: config.session.console,
            command: config.session.command.iter().map(|w| c(w)).collect(),
            client_endpoint,
        }
    }

    /// Calls `run` with a snapshot over this data, which outlives the call.
    /// The mining header is a local: its pointers address this data's
    /// allocations, and it lives until `run` returns.
    #[must_use]
    pub fn call(&self, run: extern "C" fn(*const ShekylDaemonSnapshot) -> c_int) -> c_int {
        let command = self.command_ptrs();
        let header = self.mine_header();
        let snapshot = self.snapshot(&command, header.as_ref());
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

    /// A view of the mining address. The pointers address `self` and are
    /// valid while `self` is borrowed and the header this returns is alive.
    fn mine_header(&self) -> Option<ShekylMineAddress> {
        self.mine.as_ref().map(|mine| ShekylMineAddress {
            text: mine.text.as_ptr(),
            spend: mine.spend,
            view: mine.view,
            ml_kem: if mine.ml_kem.is_empty() {
                std::ptr::null()
            } else {
                mine.ml_kem.as_ptr()
            },
            ml_kem_len: mine.ml_kem.len(),
        })
    }

    /// The snapshot over this data, `command` and `mine`. All three must
    /// outlive every read of the result. `mine` is null when there is no
    /// address. `command.items` addresses `command`'s buffer.
    fn snapshot(
        &self,
        command: &[*const c_char],
        mine: Option<&ShekylMineAddress>,
    ) -> ShekylDaemonSnapshot {
        ShekylDaemonSnapshot {
            data_dir: self.data_dir.as_ptr(),
            network: self.network,
            offline: self.offline,
            fixed_difficulty: self.fixed_difficulty,
            txpool_weight_max: self.txpool_weight_max,
            sync: self.sync,
            mine_address: match mine {
                Some(header) => header,
                None => std::ptr::null(),
            },
            mine_threads: self.mine_threads,
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
/// The command pointers address `_command`'s buffer. The mining header is
/// boxed so the snapshot's pointer stays valid when the lease is moved into
/// the box `shekyl_daemon_snapshot_parse` hands to C++; the header's own
/// pointers address `_data`'s allocations, which that move does not relocate.
/// C++ frees the lease on the same thread or any other; the value is not
/// sent between Rust threads.
#[repr(C)]
struct Leased {
    snapshot: ShekylDaemonSnapshot,
    _command: Vec<*const c_char>,
    _header: Option<Box<ShekylMineAddress>>,
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
    let header = data.mine_header().map(Box::new);
    // The box's allocation does not move when the box is moved into the lease.
    let mine = header.as_deref();
    let snapshot = data.snapshot(&command, mine);
    Ok(Box::new(Leased {
        snapshot,
        _command: command,
        _header: header,
        _data: data,
    }))
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
        return EXIT_FAILED;
    }
    let Ok(count) = usize::try_from(argc) else {
        return EXIT_FAILED;
    };
    // SAFETY: the caller's contract above: `argv` addresses `argc` pointers.
    let Some(argv) = (unsafe { crate::legacy_util::slice_from_typed_ptr(argv, count) }) else {
        return EXIT_FAILED;
    };
    let args: Vec<std::ffi::OsString> = argv
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
    match snapshot_for(&args, &crate::platform::current()) {
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
    fn the_snapshot_carries_the_eleven_values() {
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
        assert_eq!(data.mine_threads, 0, "auto reaches the miner as 0");
        assert!(data.mine_header().is_none());
        assert_eq!(data.data_dir(), d.path().display().to_string());
        assert_eq!(data.network, 3);
    }
}
