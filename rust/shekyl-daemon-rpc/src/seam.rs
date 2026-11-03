// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The core seam: every C++ function this crate calls, handed in once by
//! the binary (`DAEMON_CONFIG_CUTOVER.md` DC-Q19, DC-F43).
//!
//! Seven functions, all defined in C++ (`src/rpc/core_rpc_ffi.h`,
//! `src/rpc/rpc_facts_ffi.h`): the core handle, the stem tallies, the net
//! statistics and the live connections. The peer lists and the session
//! counts are Rust. They are [`crate::p2p_reads`], installed by
//! `shekyl-daemon`, the crate that sees both this one and `shekyl-ffi`.
//! This crate depends on neither direction of that pair (DC-F30), so a
//! Rust function is never reached by pretending it is a C import.
//!
//! Before this seam, each C++ function was an `extern "C"` import of this
//! library crate: a declaration no compiler on either side checked, which
//! the lib test binary could satisfy only with `#[no_mangle]` link stubs,
//! and which MSVC's `link.exe` refused outright in a crate whose test
//! retained a caller (DC-F39). A library crate now declares no import. The
//! one `extern "C"` block for every C++ function Rust calls is
//! `rust/shekyld/src/main.rs`, which builds a [`CoreSeam`] and hands it to
//! `shekyl_daemon::main`, which [`install`]s it before the remnant runs.
//!
//! A process that installs nothing reads [`ABSENT`]: every call answers
//! "no core here" (a null handle, `SHEKYL_RPC_FACTS_ERR_NULL`), never
//! zeros, so a handler's test in a process with no core reads a node with
//! no core. The peer-list absence is [`crate::p2p_reads::ABSENT`], which
//! is a missing dialer or a missing hub and not this null handle.

use std::ffi::c_void;
use std::os::raw::c_char;
use std::sync::OnceLock;

use crate::ffi::{ConnectionFactsFfi, CoreRpcHandle, NetStatsFactsFfi, SHEKYL_RPC_FACTS_ERR_NULL};

/// The functions, as the binary hands them in. Plain function pointers in
/// a plain Rust struct: nothing on the C++ side ever sees it. Each field's
/// contract is its C declaration's; the pointee types are this crate's
/// twins of the C structs, pinned by layout asserts in [`crate::ffi`].
#[derive(Clone, Copy)]
pub struct CoreSeam {
    /// `core_rpc_ffi_create`: a handle over a live `core_rpc_server`, or
    /// null when the pointer is not one.
    pub create: unsafe extern "C" fn(rpc_server_ptr: *mut c_void) -> *mut CoreRpcHandle,
    /// `core_rpc_ffi_destroy`: releases a handle `create` returned.
    pub destroy: unsafe extern "C" fn(h: *mut CoreRpcHandle),
    /// `core_rpc_ffi_stem_tallies` (§55): relay stem-outcome tallies as a
    /// JSON array, or null. Caller frees with [`Self::free_string`].
    ///
    /// **Transit, not structure** — the tallies are Rust's (the relay zone
    /// owns them) and this consumer is Rust; the hop out to C++ and back
    /// exists only because C++ `net_node` owns the zone handles' lifetime.
    /// It disappears with the p2p migration, at which point this crate reads
    /// the zone directly. Do not build on the round trip. Deleter: RD, with
    /// `levin_notify` (`DRS_X_STORE_FLIP.md` FLIP-Q5).
    pub stem_tallies: unsafe extern "C" fn(h: *mut CoreRpcHandle) -> *mut c_char,
    /// `core_rpc_ffi_free_string`: frees a string `stem_tallies` returned.
    pub free_string: unsafe extern "C" fn(s: *mut c_char),
    /// `shekyl_rpc_net_stats`: fills the net statistics POD.
    pub net_stats: unsafe extern "C" fn(h: *mut CoreRpcHandle, out: *mut NetStatsFactsFfi) -> i32,
    /// `shekyl_rpc_connections`: fills a C++-owned view of the live p2p
    /// connections plus the single instant they were read at; release the
    /// owner with [`Self::connections_free`].
    pub connections: unsafe extern "C" fn(
        h: *mut CoreRpcHandle,
        out_now: *mut u64,
        out: *mut *const ConnectionFactsFfi,
        out_len: *mut usize,
        out_owner: *mut *mut c_void,
    ) -> i32,
    /// `shekyl_rpc_connections_free`.
    pub connections_free: unsafe extern "C" fn(owner: *mut c_void),
}

impl std::fmt::Debug for CoreSeam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if std::ptr::eq(self, &raw const ABSENT) {
            "CoreSeam::ABSENT"
        } else {
            "CoreSeam"
        })
    }
}

/// The seam of a process with no core: a null handle and the NULL fault.
/// Never zeros.
pub static ABSENT: CoreSeam = CoreSeam {
    create: absent::create,
    destroy: absent::destroy,
    stem_tallies: absent::stem_tallies,
    free_string: absent::free_string,
    net_stats: absent::net_stats,
    connections: absent::connections,
    connections_free: absent::connections_free,
};

mod absent {
    use super::{
        c_char, c_void, ConnectionFactsFfi, CoreRpcHandle, NetStatsFactsFfi,
        SHEKYL_RPC_FACTS_ERR_NULL,
    };

    pub(super) unsafe extern "C" fn create(_p: *mut c_void) -> *mut CoreRpcHandle {
        std::ptr::null_mut()
    }
    pub(super) unsafe extern "C" fn destroy(_h: *mut CoreRpcHandle) {}
    pub(super) unsafe extern "C" fn stem_tallies(_h: *mut CoreRpcHandle) -> *mut c_char {
        std::ptr::null_mut()
    }
    pub(super) unsafe extern "C" fn free_string(_s: *mut c_char) {}
    pub(super) unsafe extern "C" fn net_stats(
        _h: *mut CoreRpcHandle,
        _out: *mut NetStatsFactsFfi,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    pub(super) unsafe extern "C" fn connections(
        _h: *mut CoreRpcHandle,
        _out_now: *mut u64,
        _out: *mut *const ConnectionFactsFfi,
        _out_len: *mut usize,
        _out_owner: *mut *mut c_void,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    pub(super) unsafe extern "C" fn connections_free(_owner: *mut c_void) {}
}

static INSTALLED: OnceLock<CoreSeam> = OnceLock::new();

/// Install the process's seam. Once: the binary calls this before the
/// remnant runs and before any RPC is constructed. `false` when a seam is
/// already installed, which the caller treats as a defect; a process that
/// never calls this reads [`ABSENT`].
pub fn install(seam: CoreSeam) -> bool {
    INSTALLED.set(seam).is_ok()
}

/// The installed seam, or [`ABSENT`].
pub(crate) fn seam() -> &'static CoreSeam {
    INSTALLED.get().unwrap_or(&ABSENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A process with no seam reads "no core here", never zeros. The unit
    /// test binary is such a process, so this is also the assertion the
    /// crate's other tests rest on.
    #[test]
    fn the_absent_seam_answers_no_core_here() {
        let s = seam();
        assert!(std::ptr::eq(s, &raw const ABSENT), "{s:?}");
        // SAFETY: the absent seam reads and writes nothing.
        unsafe {
            assert!((s.create)(std::ptr::null_mut()).is_null());
            assert_eq!(
                (s.net_stats)(std::ptr::null_mut(), std::ptr::null_mut()),
                SHEKYL_RPC_FACTS_ERR_NULL
            );
            assert_eq!(
                (s.connections)(
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                ),
                SHEKYL_RPC_FACTS_ERR_NULL
            );
        }
    }
}
