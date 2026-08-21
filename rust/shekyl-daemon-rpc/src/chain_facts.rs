// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain-tip facts — the store-agnostic seam behind the RK-1 handlers
//! (`docs/design/DAEMON_RPC_KV_CUTOVER.md` §3.2–§3.3, RK-D3 / RK-D7).
//!
//! A handler never touches the FFI: it asks a [`ChainFacts`] for what it
//! needs and decides the rest itself. [`FfiChainFacts`] is today's only
//! implementation, reading the C++ core through `shekyl_rpc_chain_tip` /
//! `shekyl_rpc_hardforks` (`src/rpc/rpc_facts_ffi.h`). When the Rust chain
//! store lands (DRS-E) a second implementation reads it directly and this
//! one is deleted; the handlers and their tests do not move.
//!
//! The shim holds **no policy**: it converts PODs to typed facts and maps
//! return codes onto [`FactsFault`]. "Synchronized ⇒ target height is 0" is
//! the handler's rule, applied in `methods`, not here.

use std::sync::Arc;

use shekyl_types::{BlockHash, BlockHeight};

use crate::core::CoreRpc;
use crate::ffi;

/// What the chain tip looks like right now, plus the one build fact
/// (`release_build`) that rides the same POD because `get_version` reports
/// it and C++'s build system is its only owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainTip {
    /// Chain height: top block height **plus one**.
    pub chain_height: BlockHeight,
    /// Hash of the top block.
    pub top_hash: BlockHash,
    /// Height the node is syncing towards, as the core reports it (raw —
    /// the "0 when synchronized" rule is the handler's).
    pub target_height: BlockHeight,
    /// Whether the protocol layer considers this node synchronized.
    pub synchronized: bool,
    /// `SHEKYL_VERSION_IS_RELEASE`.
    pub release_build: bool,
}

/// One row of the hard-fork schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardFork {
    pub version: u8,
    pub height: BlockHeight,
}

/// Why a facts read could not be served. Each variant is a distinct C return
/// code (rule 40: codes, not booleans), so the transport can choose between
/// "try again" and "this daemon is broken".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactsFault {
    /// The core handle was null — the server is torn down.
    NullHandle,
    /// The core is not initialized yet (`BUSY` on the wire).
    NotReady,
    /// A code outside the documented set — a contract violation, never a
    /// guessed fact.
    Unknown(i32),
}

impl FactsFault {
    pub(crate) fn from_code(code: i32) -> Self {
        match code {
            ffi::SHEKYL_RPC_FACTS_ERR_NULL => Self::NullHandle,
            ffi::SHEKYL_RPC_FACTS_ERR_NOT_READY => Self::NotReady,
            other => Self::Unknown(other),
        }
    }
}

/// The facts the chain-tip / version handlers consume.
pub trait ChainFacts: Send + Sync {
    fn chain_tip(&self) -> Result<ChainTip, FactsFault>;
    fn hardforks(&self) -> Result<Vec<HardFork>, FactsFault>;
}

/// Production [`ChainFacts`] over the C++ core, sharing the daemon's live
/// [`CoreRpc`] handle. Both reads block briefly on the C++ side; the
/// transport dispatches them via `spawn_blocking`.
pub struct FfiChainFacts {
    core: Arc<CoreRpc>,
}

impl FfiChainFacts {
    pub fn new(core: Arc<CoreRpc>) -> Self {
        Self { core }
    }
}

impl ChainFacts for FfiChainFacts {
    fn chain_tip(&self) -> Result<ChainTip, FactsFault> {
        let pod = self.core.chain_tip().map_err(FactsFault::from_code)?;
        Ok(ChainTip {
            chain_height: BlockHeight::from_raw(pod.chain_height),
            top_hash: BlockHash::from_bytes(pod.top_hash),
            target_height: BlockHeight::from_raw(pod.target_height),
            synchronized: pod.synchronized != 0,
            release_build: pod.release_build != 0,
        })
    }

    fn hardforks(&self) -> Result<Vec<HardFork>, FactsFault> {
        let rows = self.core.hardforks().map_err(FactsFault::from_code)?;
        Ok(rows
            .into_iter()
            .map(|r| HardFork {
                version: r.version,
                height: BlockHeight::from_raw(r.height),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_codes_map_one_to_one_and_unknown_is_never_guessed() {
        assert_eq!(
            FactsFault::from_code(ffi::SHEKYL_RPC_FACTS_ERR_NULL),
            FactsFault::NullHandle
        );
        assert_eq!(
            FactsFault::from_code(ffi::SHEKYL_RPC_FACTS_ERR_NOT_READY),
            FactsFault::NotReady
        );
        assert_eq!(FactsFault::from_code(-77), FactsFault::Unknown(-77));
    }
}
