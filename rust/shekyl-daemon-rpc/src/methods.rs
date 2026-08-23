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
    BlockHeader, GetBlockCountResponse, GetBlockHashParams, GetBlockHeaderByHeightRequest,
    GetBlockHeaderByHeightResponse, GetHeightResponse, GetVersionResponse, HardForkEntry, HashHex,
    RpcStatus, CORE_RPC_ERROR_CODE_INTERNAL_ERROR, CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
    CORE_RPC_ERROR_CODE_WRONG_PARAM,
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
        hash: HashHex::from_bytes(tip.top_hash.to_bytes()),
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

/// The refusal message an unusable `get_block_header_by_height` params value
/// earns.
///
/// It shares `on_get_block_hash`'s **code** (`CORE_RPC_ERROR_CODE_WRONG_PARAM`
/// — the two methods must agree on what a bad parameter *means*) but not its
/// text: that method takes one positional height, this one an object of two
/// optional fields, so "expected height" would misdescribe a request whose
/// height was fine and whose `fill_pow_hash` was not. A refusal names the
/// shape the method actually accepts.
const WRONG_HEADER_PARAMS: &str =
    "Wrong parameters, expected an object with optional height (number) \
     and fill_pow_hash (boolean)";

/// The params of `get_block_header_by_height`, or the refusal an unusable
/// params value earns.
///
/// Absent params (`null`, or no `params` member at all) take epee's
/// defaults: its `KV_SERIALIZE` discarded the load's result, so a field that
/// was not there simply stayed zero, and `{}` means height 0. Params that
/// *are* present and do not parse are refused instead — a deliberate
/// divergence from epee, which dropped that case on the floor too and so
/// answered a caller's type error (`{"height": "nope"}`) with a plausible
/// wrong answer: the genesis header. `get_block_hash_height` above already
/// refuses its unparseable params this way, and two sibling methods must not
/// disagree about what a bad parameter means — though not the same text, see
/// [`WRONG_HEADER_PARAMS`]. The params must be an **object**: serde's derive
/// reads a struct out of a sequence too, which would hand this method a
/// positional form nobody designed.
///
/// Pure, so the refusal costs no worker — and so it is testable without a
/// core.
///
/// # Errors
///
/// [`RpcFault::Refused`] with [`CORE_RPC_ERROR_CODE_WRONG_PARAM`] when
/// `params` is present but is not a shape this method accepts.
pub fn block_header_request(
    params: &serde_json::Value,
) -> Result<GetBlockHeaderByHeightRequest, RpcFault> {
    match params {
        serde_json::Value::Null => Ok(GetBlockHeaderByHeightRequest::default()),
        serde_json::Value::Object(_) => serde_json::from_value(params.clone())
            .map_err(|_| RpcFault::Refused(RpcRefusal::wrong_param(WRONG_HEADER_PARAMS))),
        // Anything else, an array included. serde's derive would happily read
        // a struct out of a sequence, which would give this method a second,
        // undesigned positional form — and `on_get_block_hash` is the method
        // whose params are deliberately positional (`[height]`, RK-2). One
        // method, one shape.
        _ => Err(RpcFault::Refused(RpcRefusal::wrong_param(
            WRONG_HEADER_PARAMS,
        ))),
    }
}

/// `on_get_block_hash` (alias `on_getblockhash`): the hash of the block at
/// `height`, as 64 lowercase hex characters.
///
/// The reply is a bare JSON string — no object, no `status` — as the C++
/// path's was. A height at or past the tip is `TOO_BIG_HEIGHT`, whose message
/// names the top height (`chain_height - 1`), read in the same call as the
/// hash so the two cannot disagree.
pub fn get_block_hash(facts: &dyn ChainFacts, height: u64) -> Result<HashHex, RpcFault> {
    let at = facts.block_hash_at(BlockHeight::from_raw(height))?;
    match at.hash {
        Some(hash) => Ok(HashHex::from_bytes(hash.to_bytes())),
        None => Err(too_big_height(height, at.chain_height.to_raw())),
    }
}

/// The refusal a height past the tip earns, naming the top height — one
/// wording, since `get_block_hash` and every header method share it.
fn too_big_height(height: u64, chain_height: u64) -> RpcFault {
    RpcFault::Refused(RpcRefusal {
        code: CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
        message: format!(
            "Requested block height: {height} greater than current top block height: {}",
            chain_height.saturating_sub(1)
        ),
    })
}

/// `get_block_header_by_height` (alias `getblockheaderbyheight`).
///
/// Mirrors `on_get_block_header_by_height` + `fill_block_header_response`:
/// a height past the tip is `TOO_BIG_HEIGHT`; a store that reports a height
/// it cannot produce the block for keeps the C++ contract's
/// `INTERNAL_ERROR` and its wording (the shim has already logged the
/// inconsistency, so the fault is not silent).
///
/// `fill_pow_hash` arrives already ANDed with the listener's entitlement:
/// the restricted listener never sets it, as the C++ handler enforced with
/// `req.fill_pow_hash && !restricted`.
pub fn get_block_header_by_height(
    facts: &dyn ChainFacts,
    height: u64,
    fill_pow_hash: bool,
) -> Result<GetBlockHeaderByHeightResponse, RpcFault> {
    let at = match facts.block_header_at(BlockHeight::from_raw(height), fill_pow_hash) {
        Ok(at) => at,
        Err(FactsFault::Inconsistent) => {
            return Err(RpcFault::Refused(RpcRefusal {
                code: CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
                message: format!("Internal error: can't get block by height. Height = {height}."),
            }))
        }
        Err(other) => return Err(RpcFault::Facts(other)),
    };
    let Some(header) = at.header else {
        return Err(too_big_height(height, at.chain_height.to_raw()));
    };
    Ok(GetBlockHeaderByHeightResponse {
        status: RpcStatus::ok(),
        block_header: block_header(&header),
    })
}

/// The wire's three-field rendering of a 128-bit value — `store_128`'s split:
/// the low word as a number, the whole value as `0x`-prefixed minimal
/// lowercase hex (`cryptonote::hex`), and the high word. The masking is the
/// point, not an accident of casting.
fn split_128(value: u128) -> (u64, String, u64) {
    let low = u64::try_from(value & u128::from(u64::MAX)).expect("masked to 64 bits");
    let top = u64::try_from(value >> 64).expect("a u128 shifted right 64 fits in u64");
    (low, format!("0x{value:x}"), top)
}

/// Project the facts onto the wire's header.
fn block_header(facts: &crate::chain_facts::BlockHeaderFacts) -> BlockHeader {
    let (difficulty, wide_difficulty, difficulty_top64) = split_128(facts.difficulty);
    let (cumulative_difficulty, wide_cumulative_difficulty, cumulative_difficulty_top64) =
        split_128(facts.cumulative_difficulty);
    BlockHeader {
        major_version: facts.major_version,
        minor_version: facts.minor_version,
        timestamp: facts.timestamp,
        prev_hash: HashHex::from_bytes(facts.prev_hash.to_bytes()),
        nonce: facts.nonce,
        orphan_status: facts.orphan_status,
        height: facts.height.to_raw(),
        depth: facts.depth,
        hash: HashHex::from_bytes(facts.hash.to_bytes()),
        difficulty,
        wide_difficulty,
        difficulty_top64,
        cumulative_difficulty,
        wide_cumulative_difficulty,
        cumulative_difficulty_top64,
        reward: facts.reward,
        // The wire carries both, filled from one source; only `block_weight`
        // is omitted at zero.
        block_size: facts.block_weight,
        block_weight: facts.block_weight,
        num_txes: facts.num_txes,
        pow_hash: facts.pow_hash.map(HashHex::from_bytes),
        long_term_weight: facts.long_term_weight,
        miner_tx_hash: HashHex::from_bytes(facts.miner_tx_hash.to_bytes()),
        curve_tree_root: HashHex::from_bytes(facts.curve_tree_root),
        attestation_root: HashHex::from_bytes(facts.attestation_root),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::chain_facts::{BlockHashAt, BlockHeaderAt, BlockHeaderFacts, ChainTip, HardFork};
    use serde_json::json;
    use shekyl_types::{BlockHash, BlockHeight, TxHash};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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
        /// The header the fake chain holds at every in-range height.
        pub header: BlockHeaderFacts,
        /// The last `fill_pow_hash` `block_header_at` was asked for.
        pub asked_pow: AtomicBool,
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

        fn block_header_at(
            &self,
            height: BlockHeight,
            fill_pow_hash: bool,
        ) -> Result<BlockHeaderAt, FactsFault> {
            self.asked_height.store(height.to_raw(), Ordering::Relaxed);
            self.asked_pow.store(fill_pow_hash, Ordering::Relaxed);
            if let Some(fault) = self.hash_fault {
                return Err(fault);
            }
            // Same bound the shim applies, so a handler that forwarded the
            // wrong height is visible here too.
            let header = (height.to_raw() < self.hash_chain_height).then(|| {
                let mut h = self.header.clone();
                h.height = height;
                h.pow_hash = fill_pow_hash.then(|| tagged_bytes(23));
                h
            });
            Ok(BlockHeaderAt {
                header,
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
            header: sample_header(),
            asked_pow: AtomicBool::new(false),
        }
    }

    /// The fixed facts the RK-3 oracle vector was captured from.
    pub(crate) fn sample_header() -> BlockHeaderFacts {
        BlockHeaderFacts {
            hash: tagged_hash(11),
            prev_hash: tagged_hash(3),
            miner_tx_hash: TxHash::from_bytes(tagged_bytes(31)),
            curve_tree_root: tagged_bytes(41),
            attestation_root: tagged_bytes(53),
            pow_hash: None,
            height: BlockHeight::from_raw(1_234_567),
            depth: 42,
            timestamp: 1_700_000_000,
            difficulty: (1u128 << 70) + 12345,
            cumulative_difficulty: (1u128 << 71) + 99,
            reward: 600_000_000_000,
            block_weight: 98765,
            long_term_weight: 87654,
            num_txes: 7,
            nonce: 305_419_896,
            major_version: 1,
            minor_version: 2,
            orphan_status: true,
        }
    }

    /// The emitter's `tagged_hash`: byte i = (i*7 + tag) & 0xff.
    /// The oracle emitter's pattern: byte i = (i*7 + tag) & 0xff. Raw bytes,
    /// so each call site names the kind of hash it is building.
    pub(crate) fn tagged_bytes(tag: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, byte) in b.iter_mut().enumerate() {
            let i = u8::try_from(i).expect("32 fits u8");
            *byte = i.wrapping_mul(7).wrapping_add(tag);
        }
        b
    }

    pub(crate) fn tagged_hash(tag: u8) -> BlockHash {
        BlockHash::from_bytes(tagged_bytes(tag))
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
            header: sample_header(),
            asked_pow: AtomicBool::new(false),
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
        let ours = serde_json::to_value(out).unwrap();
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

    /// A chain whose tip is 42 blocks above the header the oracle vector was
    /// captured at, so `depth` and the bound are both meaningful.
    ///
    /// Whether a pow hash comes back is not a property of the fixture: the
    /// fake computes one exactly when the handler asks for one, so the tests
    /// vary `get_block_header_by_height`'s own `fill_pow_hash` argument.
    fn header_facts() -> FakeFacts {
        let mut f = facts(true, 0);
        f.hash_chain_height = 1_234_610; // 1_234_567 + depth 42 + 1
        f
    }

    fn oracle(name: &str) -> serde_json::Value {
        let raw = match name {
            "full" => include_str!(
                "../../shekyl-rpc-types/tests/vectors/rpc/get_block_header_by_height_full_v1.json"
            ),
            _ => include_str!(
                "../../shekyl-rpc-types/tests/vectors/rpc/get_block_header_by_height_defaults_v1.json"
            ),
        };
        serde_json::from_str(raw).expect("vector is JSON")
    }

    /// The whole header projection reproduces epee's document from the same
    /// fixed facts — every field, the 128-bit split, and the pow hash.
    #[test]
    fn header_reproduces_the_full_oracle_vector() {
        let f = header_facts();
        let out = get_block_header_by_height(&f, 1_234_567, true).unwrap();
        assert!(
            f.asked_pow.load(Ordering::Relaxed),
            "the handler must pass the caller's fill_pow_hash to facts"
        );
        assert_eq!(serde_json::to_value(&out).unwrap(), oracle("full"));
    }

    /// Without `fill_pow_hash` the wire carries an empty `pow_hash`, and the
    /// facts layer is never asked to compute one.
    #[test]
    fn pow_hash_is_empty_and_uncomputed_when_not_requested() {
        let f = header_facts();
        let out = get_block_header_by_height(&f, 1_234_567, false).unwrap();
        assert!(!f.asked_pow.load(Ordering::Relaxed));
        assert_eq!(out.block_header.pow_hash, None);
    }

    /// Absent params keep epee's defaults; `{}` is height 0, as the live
    /// daemon answers. Refusing either of these turns this red.
    #[test]
    fn absent_params_are_the_defaults_not_a_refusal() {
        for absent in [json!(null), json!({})] {
            let request = block_header_request(&absent).expect("absent params are allowed");
            assert_eq!(request.height, 0, "{absent} must mean height 0");
            assert!(!request.fill_pow_hash);
        }
        let given = block_header_request(&json!({"height": 7, "fill_pow_hash": true}))
            .expect("well-formed params parse");
        assert_eq!(given.height, 7);
        assert!(given.fill_pow_hash);
    }

    /// Params that are present but unusable are refused rather than read as
    /// height 0 — epee answered every one of these with the genesis header.
    /// Restoring `unwrap_or_default()` turns this red.
    #[test]
    fn unusable_params_are_refused_not_read_as_genesis() {
        for bad in [
            json!({"height": "nope"}),
            json!({"height": -1}),
            json!({"height": 1.5}),
            // Height fine, the other field not: the refusal must not claim a
            // height was expected.
            json!({"height": 7, "fill_pow_hash": "yes"}),
            json!({"fill_pow_hash": "yes"}),
            // An array is `on_get_block_hash`'s shape, not this method's.
            json!([0]),
            json!([7, true]),
            json!("0"),
            json!(0),
            json!(true),
        ] {
            let refusal = block_header_request(&bad)
                .expect_err(&format!("{bad} is not a usable params value"));
            assert_eq!(
                refusal,
                RpcFault::Refused(RpcRefusal::wrong_param(WRONG_HEADER_PARAMS)),
                "{bad} must be refused, naming this method's own params shape"
            );
        }
    }

    /// The 128-bit split is the wire's: low word, `0x`-hex whole, high word.
    #[test]
    fn difficulty_splits_the_way_the_wire_carries_it() {
        assert_eq!(split_128(1), (1, "0x1".to_owned(), 0));
        assert_eq!(
            split_128((1u128 << 70) + 12345),
            (12345, "0x400000000000003039".to_owned(), 64)
        );
        assert_eq!(
            split_128(u128::MAX),
            (u64::MAX, format!("0x{:x}", u128::MAX), u64::MAX)
        );
    }

    /// A height past the tip is the shared TOO_BIG_HEIGHT refusal, naming the
    /// top height — the same wording `on_get_block_hash` uses.
    #[test]
    fn header_past_the_tip_is_refused() {
        let f = header_facts();
        let err = get_block_header_by_height(&f, 9_000_000, false).unwrap_err();
        assert_eq!(
            err,
            RpcFault::Refused(RpcRefusal {
                code: CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
                message: "Requested block height: 9000000 greater than current top block \
                          height: 1234609"
                    .to_owned(),
            })
        );
    }

    /// A store that cannot produce an in-range block keeps the C++ contract's
    /// INTERNAL_ERROR and wording, rather than the generic internal error a
    /// bare facts fault would get.
    #[test]
    fn header_inconsistent_store_keeps_the_contract_error() {
        let mut f = header_facts();
        f.hash_fault = Some(FactsFault::Inconsistent);
        let err = get_block_header_by_height(&f, 5, false).unwrap_err();
        assert_eq!(
            err,
            RpcFault::Refused(RpcRefusal {
                code: CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
                message: "Internal error: can't get block by height. Height = 5.".to_owned(),
            })
        );
    }

    /// Any other facts fault stays a facts fault (a generic internal error),
    /// never a claim about the caller's height.
    #[test]
    fn header_other_faults_are_not_rendered_as_contract_errors() {
        let mut f = header_facts();
        f.hash_fault = Some(FactsFault::NotReady);
        assert_eq!(
            get_block_header_by_height(&f, 5, false),
            Err(RpcFault::Facts(FactsFault::NotReady))
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
