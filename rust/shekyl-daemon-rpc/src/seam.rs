// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The core seam: every function this crate calls that lives outside it
//! and cannot be named as a Rust path, handed in once by the binary
//! (`DAEMON_CONFIG_CUTOVER.md` DC-Q19, DC-F43; the Rust-binary PR's
//! review 3 §2).
//!
//! Seven of these are C++ (`src/rpc/core_rpc_ffi.h`,
//! `src/rpc/rpc_facts_ffi.h`): the core handle, the stem tallies, the net
//! statistics and the live connections. Four are Rust, `shekyl-ffi`'s peer
//! lists and seam board, reached the same way because this crate does not
//! depend on that one. Before this seam, each was an `extern "C"` import of
//! this library crate: a declaration no compiler on either side checked,
//! which the lib test binary could satisfy only with `#[no_mangle]` link
//! stubs, and which MSVC's `link.exe` refused outright in a crate whose test
//! retained a caller (DC-F39). A library crate now declares no import. The
//! one `extern "C"` block for every C++ function Rust calls is
//! `rust/shekyld/src/main.rs`, which builds a [`CoreSeam`] and hands it to
//! `shekyl_daemon::main`, which [`install`]s it before the remnant runs.
//!
//! A process that installs nothing reads [`ABSENT`]: every call answers
//! "no core here" (a null handle, `SHEKYL_RPC_FACTS_ERR_NULL`,
//! `SHEKYL_SEAM_COUNT_ERR_NO_HUB`), never zeros, so a handler's test in a
//! process with no p2p layer reads a node with no core, not a node with no
//! peers. That is what the stubs said; it is now a value, not a link.

use std::ffi::c_void;
use std::os::raw::c_char;
use std::sync::OnceLock;

use crate::ffi::{
    ConnectionFactsFfi, CoreRpcHandle, NetStatsFactsFfi, PeerFactsFfi, SeamSessionCountsFfi,
    SHEKYL_RPC_FACTS_ERR_NULL, SHEKYL_SEAM_COUNT_ERR_NO_HUB,
};

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
    /// `shekyl_rpc_peer_list` (`shekyl-ffi`): white then gray peerlist
    /// entries in one array, discriminated by `white`; release the owner
    /// with [`Self::peer_list_free`]. No core handle.
    pub peer_list: unsafe extern "C" fn(
        public_only: u8,
        out: *mut *const PeerFactsFfi,
        out_len: *mut usize,
        out_owner: *mut *mut c_void,
    ) -> i32,
    /// `shekyl_rpc_peer_list_free` (`shekyl-ffi`).
    pub peer_list_free: unsafe extern "C" fn(owner: *mut c_void),
    /// `shekyl_rpc_peerlist_sizes` (`shekyl-ffi`): how many addresses the
    /// clearnet white and gray lists hold. No core handle.
    pub peerlist_sizes: unsafe extern "C" fn(out_white: *mut u64, out_gray: *mut u64) -> i32,
    /// `shekyl_seam_session_counts` (`shekyl-ffi`): the seam board's
    /// handshaken sessions per direction, from one snapshot.
    pub session_counts: unsafe extern "C" fn(out: *mut SeamSessionCountsFfi) -> i32,
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

/// The seam of a process with no core and no p2p layer: a null handle,
/// the NULL fault, no hub. Never zeros.
pub static ABSENT: CoreSeam = CoreSeam {
    create: absent::create,
    destroy: absent::destroy,
    stem_tallies: absent::stem_tallies,
    free_string: absent::free_string,
    net_stats: absent::net_stats,
    connections: absent::connections,
    connections_free: absent::connections_free,
    peer_list: absent::peer_list,
    peer_list_free: absent::peer_list_free,
    peerlist_sizes: absent::peerlist_sizes,
    session_counts: absent::session_counts,
};

mod absent {
    use super::{
        c_char, c_void, ConnectionFactsFfi, CoreRpcHandle, NetStatsFactsFfi, PeerFactsFfi,
        SeamSessionCountsFfi, SHEKYL_RPC_FACTS_ERR_NULL, SHEKYL_SEAM_COUNT_ERR_NO_HUB,
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
    pub(super) unsafe extern "C" fn peer_list(
        _public_only: u8,
        _out: *mut *const PeerFactsFfi,
        _out_len: *mut usize,
        _out_owner: *mut *mut c_void,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    pub(super) unsafe extern "C" fn peer_list_free(_owner: *mut c_void) {}
    pub(super) unsafe extern "C" fn peerlist_sizes(_w: *mut u64, _g: *mut u64) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    pub(super) unsafe extern "C" fn session_counts(_out: *mut SeamSessionCountsFfi) -> i32 {
        SHEKYL_SEAM_COUNT_ERR_NO_HUB
    }
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
        let mut counts = SeamSessionCountsFfi {
            outbound: u64::MAX,
            inbound: u64::MAX,
        };
        let (mut white, mut gray) = (u64::MAX, u64::MAX);
        // SAFETY: the absent seam reads and writes nothing.
        unsafe {
            assert!((s.create)(std::ptr::null_mut()).is_null());
            assert_eq!(
                (s.net_stats)(std::ptr::null_mut(), std::ptr::null_mut()),
                SHEKYL_RPC_FACTS_ERR_NULL
            );
            assert_eq!(
                (s.session_counts)(&raw mut counts),
                SHEKYL_SEAM_COUNT_ERR_NO_HUB
            );
            assert_eq!(
                (s.peerlist_sizes)(&raw mut white, &raw mut gray),
                SHEKYL_RPC_FACTS_ERR_NULL
            );
        }
        assert_eq!(
            (counts.outbound, white),
            (u64::MAX, u64::MAX),
            "wrote nothing"
        );
    }
}
