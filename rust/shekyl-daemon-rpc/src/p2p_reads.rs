// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The process's peer lists and handshaken sessions.
//!
//! These are Rust (`shekyl-ffi`). This crate does not depend on that one
//! (DC-F30), so it cannot name the functions. The composition root, which
//! sees both, installs them once ([`install`]). A process that installs
//! nothing reads [`ABSENT`]: no lists and no hub, never an empty list and
//! never zero sessions. A null C++ core handle is a different fault and
//! stays on [`crate::seam`].

use std::sync::OnceLock;

use crate::core::PeerEntry;
use crate::info_facts::SessionCounts;

/// Why a read of this process's own p2p state has no answer.
///
/// An empty list and zero sessions are answers. These are the absences
/// those answers must not be used for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P2pFault {
    /// No peer lists are installed. An online daemon with no dialer.
    NoLists,
    /// No seam hub is bound, so there are no session counts.
    NoHub,
}

/// The three reads, as the composition root hands them in.
///
/// Plain function pointers in a plain Rust struct. Nothing outside this
/// process sees it.
#[derive(Clone, Copy)]
pub struct P2pReads {
    /// White then gray. `public_only` is the clearnet lists alone.
    pub peers: fn(bool) -> Result<Vec<PeerEntry>, P2pFault>,
    /// Clearnet white and gray list sizes, as `(white, gray)`.
    pub sizes: fn() -> Result<(u64, u64), P2pFault>,
    /// Handshaken sessions on every connector, from one board snapshot.
    pub sessions: fn() -> Result<SessionCounts, P2pFault>,
}

impl std::fmt::Debug for P2pReads {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if std::ptr::eq(self, &raw const ABSENT) {
            "P2pReads::ABSENT"
        } else {
            "P2pReads"
        })
    }
}

fn absent_peers(_public_only: bool) -> Result<Vec<PeerEntry>, P2pFault> {
    Err(P2pFault::NoLists)
}

fn absent_sizes() -> Result<(u64, u64), P2pFault> {
    Err(P2pFault::NoLists)
}

fn absent_sessions() -> Result<SessionCounts, P2pFault> {
    Err(P2pFault::NoHub)
}

/// The reads of a process with no dialer and no hub.
pub static ABSENT: P2pReads = P2pReads {
    peers: absent_peers,
    sizes: absent_sizes,
    sessions: absent_sessions,
};

static INSTALLED: OnceLock<P2pReads> = OnceLock::new();

/// Install the process's reads. Once: the daemon calls this before the
/// remnant runs and before any RPC is constructed. `false` when reads are
/// already installed, which the caller treats as a defect. A process that
/// never calls this reads [`ABSENT`].
pub fn install(reads: P2pReads) -> bool {
    INSTALLED.set(reads).is_ok()
}

/// The installed reads, or [`ABSENT`].
pub(crate) fn reads() -> &'static P2pReads {
    INSTALLED.get().unwrap_or(&ABSENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No install is "no lists" and "no hub", never an empty list and
    /// never zero sessions. The unit-test binary is such a process.
    #[test]
    fn the_absent_reads_are_faults_not_empty_answers() {
        let installed = reads();
        assert!(std::ptr::eq(installed, &raw const ABSENT), "{installed:?}");
        assert_eq!((installed.peers)(false), Err(P2pFault::NoLists));
        assert_eq!((installed.peers)(true), Err(P2pFault::NoLists));
        assert_eq!((installed.sizes)(), Err(P2pFault::NoLists));
        assert_eq!((installed.sessions)(), Err(P2pFault::NoHub));
        assert_ne!(
            Ok(SessionCounts::NONE),
            Err::<SessionCounts, _>(P2pFault::NoHub)
        );
    }
}
