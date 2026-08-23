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

use serde::Deserialize;
use shekyl_rpc_types::{
    GetBlockCountResponse, GetBlockHashParams, GetHeightResponse, GetVersionResponse,
    HardForkEntry, RpcStatus, CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT, CORE_RPC_ERROR_CODE_WRONG_PARAM,
};
use shekyl_types::BlockHeight;

use crate::chain_facts::{ChainFacts, FactsFault};

/// Why a native method could not answer. Maps onto the transport's existing
/// error envelopes in the handlers (REST: `status`; JSON-RPC: `-32603`), but
/// is logged by variant so telemetry tells a core that could not supply
/// facts apart from a transport that could not frame them.
///
/// Not `Copy`: [`RpcFault::Refused`] carries the message a client reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcFault {
    /// The facts source refused (a C return code, or no core).
    Facts(FactsFault),
    /// The handler answered but the transport could not deliver it.
    Internal(InternalFault),
    /// The method itself refused: the request was malformed, or the chain
    /// holds no such thing. Carries the JSON-RPC code a client branches on
    /// and the message it reads — normal traffic, not a daemon problem, so
    /// the transport answers with it rather than a generic internal error.
    Refused(RpcRefusal),
}

/// A method-level refusal: the JSON-RPC `code` (see
/// `shekyl_rpc_types::CORE_RPC_ERROR_CODE_*`) and its `message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcRefusal {
    pub code: i64,
    pub message: String,
}

impl RpcRefusal {
    /// Pair `message` with the wrong-parameter code. Each method supplies
    /// its own wording — the C++ handlers' — since the wording is what the
    /// operator reads and it differs per method.
    #[must_use]
    pub fn wrong_param(message: &str) -> Self {
        Self {
            code: CORE_RPC_ERROR_CODE_WRONG_PARAM,
            message: message.to_owned(),
        }
    }
}

/// A failure on the transport's side of a native method — never a fact
/// about the chain, and never reported as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalFault {
    /// `serde_json` could not encode the reply (a type-level bug: every wire
    /// type here is plain data).
    Serialize,
    /// The `spawn_blocking` task that ran the handler did not complete.
    Join,
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

/// `get_block_count` (alias `getblockcount`): the chain height as `count`.
///
/// Mirrors `core_rpc_server::on_getblockcount`, including that it ignores
/// its params — the C++ request was a positional `std::list<std::string>`
/// the handler never read.
pub fn get_block_count(facts: &dyn ChainFacts) -> Result<GetBlockCountResponse, RpcFault> {
    let tip = facts.chain_tip()?;
    Ok(GetBlockCountResponse {
        status: RpcStatus::ok(),
        count: tip.chain_height.to_raw(),
    })
}

/// Parse `on_get_block_hash`'s positional params: exactly one height.
///
/// Every shape the C++ handler refused with `WRONG_PARAM` (`req.size() != 1`)
/// refuses here, structurally — [`GetBlockHashParams`] is `[u64; 1]`.
///
/// **One deliberate divergence** (`DAEMON_RPC_KV_CUTOVER.md` §2, RK-2): the
/// C++ dispatcher hand-parsed the JSON array with `std::stoull`, so a
/// negative height wrapped to a huge `u64` and came back as
/// `TOO_BIG_HEIGHT`. A negative height is a wrong parameter, and that is what
/// it is answered with; the old classification was a parser artifact, not a
/// decision, and no client sends it.
pub fn get_block_hash_height(params: &serde_json::Value) -> Result<u64, RpcFault> {
    GetBlockHashParams::deserialize(params)
        .map(|p| p.0[0])
        .map_err(|_| {
            RpcFault::Refused(RpcRefusal::wrong_param("Wrong parameters, expected height"))
        })
}

/// `on_get_block_hash` (alias `on_getblockhash`): the hash of the block at
/// `height`, as 64 lowercase hex characters.
///
/// The reply is a bare JSON string — no object, no `status` — as the C++
/// path's was. A height at or past the tip is `TOO_BIG_HEIGHT`, whose message
/// names the top height (`chain_height - 1`), read in the same call as the
/// hash so the two cannot disagree.
pub fn get_block_hash(facts: &dyn ChainFacts, height: u64) -> Result<String, RpcFault> {
    let at = facts.block_hash_at(BlockHeight::from_raw(height))?;
    match at.hash {
        Some(hash) => Ok(hash.to_string()),
        None => Err(RpcFault::Refused(RpcRefusal {
            code: CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
            message: format!(
                "Requested block height: {height} greater than current top block height: {}",
                at.chain_height.to_raw().saturating_sub(1)
            ),
        })),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::chain_facts::{BlockHashAt, ChainTip, HardFork};
    use shekyl_types::{BlockHash, BlockHeight};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// In-memory facts: what a store-backed implementation will look like.
    ///
    /// `block_hash_at` applies the **same bound the C++ shim does** rather
    /// than answering a constant, and records the height it was asked for.
    /// A double that ignored the height would be blind on the axis these
    /// tests are about: a handler forwarding `0`, or its own tip, instead of
    /// the caller's height would pass every one of them.
    pub(crate) struct FakeFacts {
        pub tip: Result<ChainTip, FactsFault>,
        pub forks: Result<Vec<HardFork>, FactsFault>,
        /// Tip of the fake chain for `block_hash_at`'s bound.
        pub hash_chain_height: u64,
        /// When set, `block_hash_at` faults instead of answering.
        pub hash_fault: Option<FactsFault>,
        /// The last height `block_hash_at` was asked for.
        pub asked_height: AtomicU64,
    }

    impl ChainFacts for FakeFacts {
        fn chain_tip(&self) -> Result<ChainTip, FactsFault> {
            self.tip.clone()
        }
        fn hardforks(&self) -> Result<Vec<HardFork>, FactsFault> {
            self.forks.clone()
        }
        fn block_hash_at(&self, height: BlockHeight) -> Result<BlockHashAt, FactsFault> {
            self.asked_height.store(height.to_raw(), Ordering::Relaxed);
            if let Some(fault) = self.hash_fault {
                return Err(fault);
            }
            Ok(BlockHashAt {
                hash: (height.to_raw() < self.hash_chain_height).then(patterned_hash),
                chain_height: BlockHeight::from_raw(self.hash_chain_height),
            })
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
            hash_chain_height: 1_234_567,
            hash_fault: None,
            asked_height: AtomicU64::new(u64::MAX),
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
            hash_chain_height: 0,
            hash_fault: Some(FactsFault::NotReady),
            asked_height: AtomicU64::new(u64::MAX),
        };
        assert_eq!(get_height(&f), Err(RpcFault::Facts(FactsFault::NotReady)));
        assert_eq!(get_version(&f), Err(RpcFault::Facts(FactsFault::NotReady)));
        assert_eq!(
            get_block_count(&f),
            Err(RpcFault::Facts(FactsFault::NotReady))
        );
        assert_eq!(
            get_block_hash(&f, 1),
            Err(RpcFault::Facts(FactsFault::NotReady))
        );
    }

    /// The count is the chain height, and it reproduces the epee vector.
    #[test]
    fn get_block_count_reproduces_the_oracle_vector() {
        let out = get_block_count(&facts(true, 0)).unwrap();
        assert_eq!(out.count, 1_234_567);
        let ours: serde_json::Value = serde_json::to_value(&out).unwrap();
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../shekyl-rpc-types/tests/vectors/rpc/get_block_count_v1.json"
        ))
        .unwrap();
        assert_eq!(ours, oracle);
    }

    /// The hash reply is a bare JSON string of 64 lowercase hex characters —
    /// the vector is that document, with no object around it and no `status`.
    #[test]
    fn get_block_hash_reproduces_the_oracle_vector() {
        let f = facts(true, 0);
        let out = get_block_hash(&f, 42).unwrap();
        assert_eq!(
            f.asked_height.load(Ordering::Relaxed),
            42,
            "the handler must ask facts for the height it was given"
        );
        let ours = serde_json::to_value(&out).unwrap();
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../shekyl-rpc-types/tests/vectors/rpc/get_block_hash_v1.json"
        ))
        .unwrap();
        assert_eq!(ours, oracle);
        assert!(oracle.is_string(), "the reply is a bare JSON string");
    }

    /// A height at or past the tip is refused with the C++ code and message,
    /// naming the top height (chain height - 1).
    #[test]
    fn height_past_the_tip_is_refused_with_the_top_height_named() {
        let f = facts(true, 0);
        // The bound is the fake chain's, applied to the height asked for:
        // one below the tip answers, the tip itself does not.
        assert!(get_block_hash(&f, 1_234_566).is_ok());
        assert!(get_block_hash(&f, 1_234_567).is_err());
        let err = get_block_hash(&f, 9_000_000).unwrap_err();
        assert_eq!(
            err,
            RpcFault::Refused(RpcRefusal {
                code: CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
                message: "Requested block height: 9000000 greater than current top block \
                          height: 1234566"
                    .to_owned(),
            })
        );
    }

    /// Params: one height parses; every other shape is WRONG_PARAM, including
    /// the negative the C++ hand-parser used to wrap into TOO_BIG_HEIGHT.
    #[test]
    fn block_hash_params_refuse_everything_but_one_height() {
        assert_eq!(
            get_block_hash_height(&serde_json::json!([1234])).unwrap(),
            1234
        );
        for bad in [
            serde_json::json!([]),
            serde_json::json!([1, 2]),
            serde_json::json!(["1"]),
            serde_json::json!([-1]),
            serde_json::json!(1234),
            serde_json::json!({}),
            serde_json::json!(null),
        ] {
            let err = get_block_hash_height(&bad).unwrap_err();
            assert_eq!(
                err,
                RpcFault::Refused(RpcRefusal::wrong_param("Wrong parameters, expected height")),
                "{bad} must be WRONG_PARAM"
            );
        }
    }
}
