// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Natively-served RPC methods (`docs/design/DAEMON_RPC_KV_CUTOVER.md` §3.3).
//!
//! Each function is the whole method: it takes a facts trait, applies the
//! method's rules, and returns the wire type from `shekyl-rpc-types`. No
//! Axum, no FFI, no JSON — the transport layers (`handlers::json`,
//! `handlers::json_rpc`, `console`) call these and only frame the result.
//! That is what lets one unit test with an in-memory [`ChainFacts`] pin a
//! method's behaviour for every transport at once.

use shekyl_rpc_types::{GetHeightResponse, GetVersionResponse, HardForkEntry, RpcStatus};

use crate::chain_facts::{ChainFacts, FactsFault};

/// Why a native method could not answer. Maps onto the transport's existing
/// error envelopes in the handlers (REST: `status`; JSON-RPC: `-32603`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcFault {
    Facts(FactsFault),
}

impl From<FactsFault> for RpcFault {
    fn from(f: FactsFault) -> Self {
        Self::Facts(f)
    }
}

/// `/get_height` (alias `/getheight`): chain height and top block hash.
///
/// Mirrors `core_rpc_server::on_get_height`: `get_blockchain_top` gives the
/// top block's height, the reply carries **chain** height (top + 1); the
/// facts POD already carries the `+1` (`chain_height`), so no arithmetic
/// happens here twice.
pub fn get_height(facts: &dyn ChainFacts) -> Result<GetHeightResponse, RpcFault> {
    let tip = facts.chain_tip()?;
    Ok(GetHeightResponse {
        status: RpcStatus::ok(),
        height: tip.chain_height.to_raw(),
        hash: tip.top_hash.to_string(),
    })
}

/// `get_version` (JSON-RPC, no params): RPC contract version, release flag,
/// current and target heights, hard-fork schedule.
///
/// Mirrors `core_rpc_server::on_get_version` including its one rule:
/// `target_height` is `0` when the node is synchronized, whatever the core's
/// raw target says.
pub fn get_version(facts: &dyn ChainFacts) -> Result<GetVersionResponse, RpcFault> {
    let tip = facts.chain_tip()?;
    let hard_forks = facts
        .hardforks()?
        .into_iter()
        .map(|hf| HardForkEntry {
            hf_version: hf.version,
            height: hf.height.to_raw(),
        })
        .collect();
    Ok(GetVersionResponse {
        status: RpcStatus::ok(),
        version: shekyl_rpc_types::CORE_RPC_VERSION,
        release: tip.release_build,
        current_height: tip.chain_height.to_raw(),
        target_height: if tip.synchronized {
            0
        } else {
            tip.target_height.to_raw()
        },
        hard_forks,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::chain_facts::{ChainTip, HardFork};
    use shekyl_types::{BlockHash, BlockHeight};

    /// In-memory facts: what a store-backed implementation will look like.
    pub(crate) struct FakeFacts {
        pub tip: Result<ChainTip, FactsFault>,
        pub forks: Result<Vec<HardFork>, FactsFault>,
    }

    impl ChainFacts for FakeFacts {
        fn chain_tip(&self) -> Result<ChainTip, FactsFault> {
            self.tip.clone()
        }
        fn hardforks(&self) -> Result<Vec<HardFork>, FactsFault> {
            self.forks.clone()
        }
    }

    pub(crate) fn patterned_hash() -> BlockHash {
        let mut b = [0u8; 32];
        for (i, byte) in b.iter_mut().enumerate() {
            *byte = u8::try_from((i * 7 + 3) & 0xff).expect("masked to one byte");
        }
        BlockHash::from_bytes(b)
    }

    pub(crate) fn facts(synchronized: bool, target: u64) -> FakeFacts {
        FakeFacts {
            tip: Ok(ChainTip {
                chain_height: BlockHeight::from_raw(1_234_567),
                top_hash: patterned_hash(),
                target_height: BlockHeight::from_raw(target),
                synchronized,
                release_build: false,
            }),
            forks: Ok(vec![HardFork {
                version: 1,
                height: BlockHeight::from_raw(0),
            }]),
        }
    }

    /// The same fixed facts the oracle vectors were captured from produce the
    /// same document — the end-to-end form of the `shekyl-rpc-types` parity
    /// test, through the handler.
    #[test]
    fn get_height_reproduces_the_oracle_vector() {
        let out = get_height(&facts(true, 0)).unwrap();
        let ours: serde_json::Value = serde_json::to_value(&out).unwrap();
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../shekyl-rpc-types/tests/vectors/rpc/get_height_v1.json"
        ))
        .unwrap();
        assert_eq!(ours, oracle);
    }

    #[test]
    fn get_version_reproduces_the_synced_oracle_vector() {
        // Synchronized with a non-zero raw target: the rule zeroes it, and the
        // zero is omitted on the wire exactly as epee omitted it.
        let out = get_version(&facts(true, 999_999)).unwrap();
        assert_eq!(out.target_height, 0);
        let ours: serde_json::Value = serde_json::to_value(&out).unwrap();
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../shekyl-rpc-types/tests/vectors/rpc/get_version_synced_v1.json"
        ))
        .unwrap();
        assert_eq!(ours, oracle);
    }

    #[test]
    fn get_version_reports_the_target_while_syncing() {
        let out = get_version(&facts(false, 2_000_000)).unwrap();
        assert_eq!(out.target_height, 2_000_000);
        assert_eq!(out.version, shekyl_rpc_types::CORE_RPC_VERSION);
    }

    /// A facts fault is a fault, never a fabricated reply.
    #[test]
    fn facts_fault_is_not_answered_with_zeros() {
        let f = FakeFacts {
            tip: Err(FactsFault::NotReady),
            forks: Ok(vec![]),
        };
        assert_eq!(get_height(&f), Err(RpcFault::Facts(FactsFault::NotReady)));
        assert_eq!(get_version(&f), Err(RpcFault::Facts(FactsFault::NotReady)));
    }
}
