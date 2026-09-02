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

use crate::core::TxSlot;
use serde::Deserialize;
use shekyl_rpc_types::{
    BlockHeader, GetBlockCountResponse, GetBlockHashParams, GetBlockHeaderByHeightRequest,
    GetBlockHeaderByHeightResponse, GetBlockRequest, GetBlockResponse, GetHeightResponse,
    GetVersionResponse, HardForkEntry, HashHex, RpcStatus, CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
    CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT, CORE_RPC_ERROR_CODE_WRONG_PARAM,
};
use shekyl_rpc_types::{
    ConnectionInfo, ConnectionState, GetConnectionsResponse, GetNetStatsResponse,
    GetPeerListRequest, GetPeerListResponse, Peer, SyncInfoPeer, SyncInfoResponse, SyncSpan,
};
use shekyl_rpc_types::{GetTransactionsRequest, GetTransactionsResponse, TxEntry, TxLocation};
use shekyl_types::BlockHeight;

use crate::chain_facts::{BlockLookup, ChainFacts, FactsFault, P2pFacts};

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

/// The params of `get_block`, or the refusal an unusable value earns.
///
/// Same discipline as [`block_header_request`]: absent params keep epee's
/// defaults, params that are present and unusable are refused, and the value
/// must be an object.
///
/// # Errors
///
/// [`RpcFault::Refused`] with [`CORE_RPC_ERROR_CODE_WRONG_PARAM`] when
/// `params` is present but is not a shape this method accepts.
pub fn block_request(params: &serde_json::Value) -> Result<GetBlockRequest, RpcFault> {
    match params {
        serde_json::Value::Null => Ok(GetBlockRequest::default()),
        serde_json::Value::Object(_) => serde_json::from_value(params.clone())
            .map_err(|_| RpcFault::Refused(RpcRefusal::wrong_param(WRONG_BLOCK_PARAMS))),
        _ => Err(RpcFault::Refused(RpcRefusal::wrong_param(
            WRONG_BLOCK_PARAMS,
        ))),
    }
}

/// The refusal an unusable `get_block` params value earns. Names this
/// method's own shape, not `get_block_header_by_height`'s: it accepts a
/// `hash` as well, and a refusal that omits it would send a caller looking
/// in the wrong place.
const WRONG_BLOCK_PARAMS: &str = "Wrong parameters, expected an object with optional \
     hash (64 hex characters), height (non-negative integer) and \
     fill_pow_hash (boolean)";

/// `get_block` (alias `getblock`): a whole block, named by hash or by height.
///
/// A non-empty `hash` wins and `height` is ignored — the C++ dispatch,
/// preserved. Each refusal keeps its code *and* its wording:
///
/// * an unparseable `hash` is `WRONG_PARAM`, quoting what was sent;
/// * a height past the tip is `TOO_BIG_HEIGHT`, naming the top height;
/// * a block that cannot be produced, or whose coinbase is not a single
///   `txin_gen`, is `INTERNAL_ERROR` with the message the C++ gave.
///
/// The empty-`hash` case in the "can't get block by hash" message is
/// inherited: reached by height, the C++ interpolated `req.hash`, which is
/// empty, so the message ends "Hash = .". Preserved under RK-D8.
///
/// # Errors
///
/// [`RpcFault::Refused`] for the four cases above; [`RpcFault::Facts`] when
/// the facts layer itself failed.
pub fn get_block(
    facts: &dyn ChainFacts,
    request: &GetBlockRequest,
    fill_pow_hash: bool,
) -> Result<GetBlockResponse, RpcFault> {
    let by_hash = !request.hash.is_empty();
    let lookup = if by_hash {
        let parsed = HashHex::from_hex(&request.hash).map_err(|_| {
            RpcFault::Refused(RpcRefusal::wrong_param(&format!(
                "Failed to parse hex representation of block hash. Hex = {}.",
                request.hash
            )))
        })?;
        BlockLookup::Hash(parsed.to_bytes())
    } else {
        BlockLookup::Height(BlockHeight::from_raw(request.height))
    };

    let at = match facts.block_at(lookup, fill_pow_hash) {
        Ok(at) => at,
        Err(FactsFault::Inconsistent) => {
            return Err(RpcFault::Refused(RpcRefusal {
                code: CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
                message: "Internal error: coinbase transaction in the block has the wrong type"
                    .to_owned(),
            }))
        }
        Err(other) => return Err(RpcFault::Facts(other)),
    };

    let Some(block) = at.block else {
        // Past the tip is the height refusal; anything else the lookup could
        // not produce keeps the C++ "can't get block by hash" wording, whose
        // `Hash = .` for a height lookup is inherited, not a slip.
        if !by_hash && request.height >= at.chain_height.to_raw() {
            return Err(too_big_height(request.height, at.chain_height.to_raw()));
        }
        return Err(RpcFault::Refused(RpcRefusal {
            code: CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
            message: format!(
                "Internal error: can't get block by hash. Hash = {}.",
                request.hash
            ),
        }));
    };

    let header = block_header(&block.header);
    Ok(GetBlockResponse {
        status: RpcStatus::ok(),
        // The wire carries this twice; duplication preserved, RK-W's to retire.
        miner_tx_hash: header.miner_tx_hash,
        block_header: header,
        tx_hashes: block
            .tx_hashes
            .into_iter()
            .map(|h| HashHex::from_bytes(h.to_bytes()))
            .collect(),
        // `hex::encode` is lowercase, which is what this wire uses; the
        // crate is already a dependency for the submit path's decode.
        blob: hex::encode(&block.blob),
        json: block.json,
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
///
/// "non-negative integer" rather than "number": `height` is a `u64`, so
/// `-1` and `1.5` are JSON numbers this refuses, and a caller told the
/// accepted type was "number" would have no idea why.
const WRONG_HEADER_PARAMS: &str = "Wrong parameters, expected an object with optional height \
     (non-negative integer) and fill_pow_hash (boolean)";

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
    let at = match facts.block_header_at(
        BlockLookup::Height(BlockHeight::from_raw(height)),
        fill_pow_hash,
    ) {
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

// ─── RK-4c: the transaction read set ─────────────────────────────────────────

/// `RESTRICTED_TRANSACTIONS_COUNT` — the cap a restricted listener applies to
/// `/get_transactions`. It fires for the first time in this tree: the C++
/// gated it on `m_restricted && ctx` while the bridge passed a null `ctx`
/// (#570 fixed the bridge; this carries the constant to the native handler).
pub const RESTRICTED_TRANSACTIONS_COUNT: usize = 100;

/// `RESTRICTED_SPENT_KEY_IMAGES_COUNT` — the same, for `/is_key_image_spent`.
pub const RESTRICTED_SPENT_KEY_IMAGES_COUNT: usize = 5000;

/// The two parse refusals the C++ handler distinguished, kept distinct because
/// they tell the caller different things: the first says "that is not hex",
/// the second says "that is hex, of the wrong length".
pub const TX_PARSE_FAILED: &str = "Failed to parse hex representation of transaction hash";
const SIZE_MISMATCH: &str = "Failed, size of data mismatch";
pub const KI_PARSE_FAILED: &str = "Failed to parse hex representation of key image";

/// Parse request hashes into 32-byte ids, or the status the caller gets.
///
/// `Err` is a *status string*, not an [`RpcFault`]: these routes answer a
/// refusal as HTTP 200 with a non-OK `status`, which is the shape the refusal
/// vector pins.
pub fn parse_request_hashes(hex: &[String], parse_msg: &str) -> Result<Vec<[u8; 32]>, String> {
    let mut out = Vec::with_capacity(hex.len());
    for h in hex {
        let Ok(bytes) = hex::decode(h) else {
            return Err(parse_msg.to_owned());
        };
        // Length is checked after decoding, so hex-of-the-wrong-length gets the
        // size message rather than the parse one — the C++ order.
        let Ok(arr): Result<[u8; 32], _> = bytes.try_into() else {
            return Err(SIZE_MISMATCH.to_owned());
        };
        out.push(arr);
    }
    Ok(out)
}

/// Project gathered slots into the reply, applying the request's
/// `(split, prune, decode_as_json)` matrix.
///
/// `render` is the epee JSON rendering (RK-D11), injected so this stays a pure
/// function: the decision of *whether* and *which* rendering to ask for is
/// here, in Rust, and only the rendering itself is C++.
///
/// **One deliberate divergence.** The C++ echoed the request's hash string
/// back verbatim (`e.tx_hash = *txhi++`), so a caller sending upper-case hex
/// got upper-case back. `HashHex` re-encodes canonically, so the reply is
/// always lower-case. Echoing caller-controlled casing is not a property worth
/// preserving, and pre-genesis there is no client depending on it (RK-D8).
/// A rendering the daemon could not produce.
///
/// The C++ failed the whole request when `parse_and_validate_tx*_from_blob`
/// refused a body it had just read out of its own store, and that is the right
/// answer: a caller who asked for `decode_as_json` and got a successful reply
/// with an empty `as_json` cannot tell "no JSON" from "the daemon's store
/// disagrees with its parser".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderFailed {
    pub txid: String,
    pub code: i32,
}

pub fn project_transactions<R>(
    request: &GetTransactionsRequest,
    ids: &[[u8; 32]],
    slots: &[TxSlot],
    chain_height: u64,
    render: R,
) -> Result<GetTransactionsResponse, RenderFailed>
where
    R: Fn(&[u8], bool) -> Result<String, i32>,
{
    let mut txs = Vec::new();
    let mut missed = Vec::new();

    for (id, slot) in ids.iter().zip(slots.iter()) {
        let (pruned, prunable, prunable_hash, location, pruned_flag) = match slot {
            TxSlot::Missed => {
                missed.push(HashHex::from_bytes(*id));
                continue;
            }
            TxSlot::Chain {
                pruned,
                prunable,
                prunable_hash,
                block_height,
                block_timestamp,
                output_indices,
                pruned_flag,
            } => (
                pruned,
                prunable,
                prunable_hash,
                TxLocation::Mined {
                    block_height: *block_height,
                    // Against the tip read once for the whole gather, so two
                    // entries cannot be counted from two different heights.
                    confirmations: chain_height.saturating_sub(*block_height),
                    block_timestamp: *block_timestamp,
                    output_indices: output_indices.clone(),
                },
                *pruned_flag,
            ),
            TxSlot::Pool {
                pruned,
                prunable,
                prunable_hash,
                double_spend_seen: _,
                relayed,
                received_timestamp,
            } => (
                pruned,
                prunable,
                prunable_hash,
                TxLocation::Pooled {
                    relayed: *relayed,
                    received_timestamp: *received_timestamp,
                },
                // A pooled transaction is never reported pruned: the C++ set
                // this from the store's verification data, which a pool entry
                // has by construction.
                false,
            ),
        };
        let double_spend_seen = matches!(
            slot,
            TxSlot::Pool {
                double_spend_seen: true,
                ..
            }
        );

        // The matrix. `split` or `prune` asked for the halves; so does a
        // transaction the store has no prunable half for, because there is
        // nothing to concatenate.
        let split_form = request.split || request.prune || prunable.is_empty();
        let mut entry = TxEntry {
            tx_hash: HashHex::from_bytes(*id),
            as_hex: String::new(),
            pruned_as_hex: String::new(),
            prunable_as_hex: String::new(),
            prunable_hash: HashHex::from_bytes(*prunable_hash),
            as_json: String::new(),
            pruned: pruned_flag,
            double_spend_seen,
            location,
        };
        if split_form {
            entry.pruned_as_hex = hex::encode(pruned);
            if !request.prune {
                entry.prunable_as_hex = hex::encode(prunable);
            }
            if request.decode_as_json {
                // Base-only rendering when that is all the reply carries.
                let base_only = request.prune || prunable.is_empty();
                let blob: Vec<u8> = if base_only {
                    pruned.clone()
                } else {
                    [pruned.as_slice(), prunable.as_slice()].concat()
                };
                entry.as_json = render(&blob, base_only).map_err(|code| RenderFailed {
                    txid: entry.tx_hash.to_string(),
                    code,
                })?;
            }
        } else {
            let full: Vec<u8> = [pruned.as_slice(), prunable.as_slice()].concat();
            entry.as_hex = hex::encode(&full);
            if request.decode_as_json {
                entry.as_json = render(&full, false).map_err(|code| RenderFailed {
                    txid: entry.tx_hash.to_string(),
                    code,
                })?;
            }
        }

        txs.push(entry);
    }

    Ok(GetTransactionsResponse {
        status: RpcStatus::ok(),
        txs,
        missed_tx: missed,
    })
}

// ── RK-5a: the p2p methods ──────────────────────────────────────────────────

/// epee's ipv4 address type id. `connection_info`'s `ip` and `port` strings
/// are filled only for this arm; every other address type carries them empty.
const ADDRESS_TYPE_IPV4: u8 = 1;

/// The unit `avg_*` and `current_*` report in.
const BYTES_PER_KIB: u64 = 1024;

/// Longest run of gap characters [`render_overview`] will emit for one span.
///
/// A **deliberate divergence** from the C++, which emitted
/// `(gap / nblocks)` underscores with no bound. The gap is derived from a
/// span's `start_block_height`, which comes from peer-advertised heights, so
/// the unbounded form makes the length of a display string a function of what
/// a peer claims — an allocation with no ceiling in a reply any admin caller
/// can ask for. The overview is an ASCII picture for a human; a run longer
/// than this conveys nothing a shorter one does not, and reproducing an
/// unbounded loop faithfully would be reproducing the defect.
const MAX_OVERVIEW_GAP: u64 = 128;

/// Round half up, totally.
///
/// The C++ wrote `(uint32_t)(x + 0.5f)`, which is **undefined** when the
/// result is negative or does not fit — and `rate` is a float the block queue
/// computes from measured byte counts over measured intervals. This clamps
/// instead: NaN and negatives become 0, anything past `u32::MAX` saturates.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the clamp above the cast is what makes it total"
)]
#[deny(clippy::arithmetic_side_effects)]
fn round_half_up(value: f32) -> u32 {
    if !value.is_finite() || value <= 0.0 {
        return 0;
    }
    let rounded = (f64::from(value) + 0.5).floor();
    if rounded >= f64::from(u32::MAX) {
        u32::MAX
    } else {
        rounded as u32
    }
}

/// Bytes per second as whole KiB per second, totally.
///
/// The C++ divided a `double` by 1024 and let the implicit conversion to
/// `uint64_t` truncate. That conversion is **undefined** for a NaN, an
/// infinity, a negative or a value past the integer range, and the input is a
/// rate estimator's output — the same hazard [`round_half_up`] exists for,
/// one field away. The division happens in floating point, as it did, so the
/// answer is `trunc(bytes_per_second / 1024)` and not
/// `trunc(bytes_per_second) / 1024`.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the clamp above the cast is what makes it total"
)]
#[deny(clippy::arithmetic_side_effects)]
fn kib_per_second(bytes_per_second: f64) -> u64 {
    /// `u64::MAX` as the nearest `f64`. Written as a literal rather than
    /// `u64::MAX as f64`, which is itself a lossy cast: the exact value is
    /// 2^64, one past the range, so `>=` here is the right boundary.
    const OUT_OF_RANGE: f64 = 18_446_744_073_709_551_616.0;
    if !bytes_per_second.is_finite() || bytes_per_second <= 0.0 {
        return 0;
    }
    let kib = (bytes_per_second / 1024.0).floor();
    if kib >= OUT_OF_RANGE {
        u64::MAX
    } else {
        kib as u64
    }
}

/// A connection's lifetime average, in KiB/s.
///
/// Two truncating divisions in this order, because that is the value the wire
/// has always carried: bytes per second, then KiB. Written with `checked_div`
/// rather than an `if seconds == 0` guard so it is total **by construction** —
/// a guard is a thing a later edit can move away from its division, and this
/// is not.
fn average_kib(total: u64, seconds: u64) -> u64 {
    total
        .checked_div(seconds)
        .unwrap_or(0)
        .checked_div(BYTES_PER_KIB)
        .unwrap_or(0)
}

/// One connection's raw facts projected onto the wire, against the single
/// instant the whole list was read at.
///
/// Every elapsed value below comes from that one `now`. The C++ read the
/// clock twice per connection — once for the idle times, once for the
/// averages — so a connection could report a `live_time` that disagreed with
/// the divisor its own averages used; with one instant that is not
/// representable.
///
/// The subtractions saturate. A `now` earlier than a connection's `started`
/// means the clock moved backwards, and C++'s unsigned wrap turned that into
/// an idle time of some hundreds of years; zero is the honest answer.
#[deny(clippy::arithmetic_side_effects)]
fn project_connection(c: &crate::core::ConnectionFacts, now: u64) -> ConnectionInfo {
    let live_time = now.saturating_sub(c.started);
    let ipv4 = c.address_type == ADDRESS_TYPE_IPV4;
    ConnectionInfo {
        incoming: c.incoming,
        localhost: c.localhost,
        local_ip: c.local_ip,
        address: c.address.clone(),
        host: c.host.clone(),
        // Only the ipv4 arm carries these, and it carries the host as the ip.
        ip: if ipv4 { c.host.clone() } else { String::new() },
        port: if ipv4 {
            c.port.to_string()
        } else {
            String::new()
        },
        peer_id: format!("{:016x}", c.peer_id),
        recv_count: c.recv_count,
        // Floored at the connection's own age: a peer that has never sent has
        // `last_recv == 0`, and the idle time then means "as long as we have
        // been connected", not "since 1970".
        recv_idle_time: now.saturating_sub(c.started.max(c.last_recv)),
        send_count: c.send_count,
        send_idle_time: now.saturating_sub(c.started.max(c.last_send)),
        state: ConnectionState::from(c.state),
        live_time,
        avg_download: average_kib(c.recv_count, live_time),
        current_download: kib_per_second(c.current_speed_down),
        avg_upload: average_kib(c.send_count, live_time),
        current_upload: kib_per_second(c.current_speed_up),
        support_flags: c.support_flags,
        // `hex::encode` is lowercase and undashed, which is exactly what
        // `epee::string_tools::pod_to_hex` produced for this uuid — and it is
        // the encoder this file already uses four times over.
        connection_id: hex::encode(c.connection_id),
        height: c.height,
        pruning_seed: c.pruning_seed,
        address_type: c.address_type,
    }
}

/// The block queue as an ASCII picture, from the same spans the reply lists.
///
/// Mirrors `block_queue::get_overview`, which the C++ handler called as a
/// **second** read of the queue after the one that produced `spans` — so the
/// picture could describe a queue the span list no longer matched. Rendering
/// both from one snapshot removes that, which is why `filled` is exported
/// rather than inferred: the branch below is the only reader of it.
///
/// `<` is a span already behind the chain; `_` runs are the gap ahead of the
/// last span; `.` is requested-not-yet-arrived, `m` the span at the tip, `o`
/// any other arrived span.
#[deny(clippy::arithmetic_side_effects)]
fn render_overview(spans: &[crate::core::SyncSpanFacts], chain_height: u64) -> String {
    if spans.is_empty() {
        return "[]".to_owned();
    }
    let mut out = String::from("[");
    let mut expected = chain_height;
    for span in spans {
        if expected > span.start_block_height {
            out.push('<');
            continue;
        }
        if expected < span.start_block_height {
            let stride = if span.nblocks == 0 { 1 } else { span.nblocks };
            let gap = span
                .start_block_height
                .saturating_sub(expected)
                .checked_div(stride)
                .unwrap_or(1)
                .clamp(1, MAX_OVERVIEW_GAP);
            for _ in 0..gap {
                out.push('_');
            }
        }
        out.push(if !span.filled {
            '.'
        } else if span.start_block_height == chain_height {
            'm'
        } else {
            'o'
        });
        expected = span.start_block_height.saturating_add(span.nblocks);
    }
    out.push(']');
    out
}

/// `/get_net_stats`: process start plus the global throttle counters.
pub fn get_net_stats(facts: &dyn P2pFacts) -> Result<GetNetStatsResponse, RpcFault> {
    let stats = facts.net_stats()?;
    Ok(GetNetStatsResponse {
        status: RpcStatus::ok(),
        start_time: stats.start_time,
        total_packets_in: stats.total_packets_in,
        total_bytes_in: stats.total_bytes_in,
        total_packets_out: stats.total_packets_out,
        total_bytes_out: stats.total_bytes_out,
    })
}

/// `get_connections` (JSON-RPC, admin-only): the live p2p connections.
pub fn get_connections(facts: &dyn P2pFacts) -> Result<GetConnectionsResponse, RpcFault> {
    let snapshot = facts.connections()?;
    Ok(GetConnectionsResponse {
        status: RpcStatus::ok(),
        connections: snapshot
            .connections
            .iter()
            .map(|c| project_connection(c, snapshot.now))
            .collect(),
    })
}

/// `/get_peer_list` (admin-only): the white and gray peerlists.
///
/// `public_only` chose a different p2p call daemon-side; `include_blocked` is
/// applied **here**, because it is a property of the request rather than of
/// the peerlist, and the facts export reports each entry's blocked state
/// without deciding what to do about it.
pub fn get_peer_list(
    request: &GetPeerListRequest,
    facts: &dyn P2pFacts,
) -> Result<GetPeerListResponse, RpcFault> {
    let entries = facts.peer_list(request.public_only)?;
    let mut white_list = Vec::new();
    let mut gray_list = Vec::new();
    for e in entries {
        if e.blocked && !request.include_blocked {
            continue;
        }
        let peer = Peer {
            id: e.id,
            host: e.host,
            ip: e.ip,
            port: e.port,
            last_seen: e.last_seen,
            pruning_seed: e.pruning_seed,
        };
        if e.white {
            white_list.push(peer);
        } else {
            gray_list.push(peer);
        }
    }
    Ok(GetPeerListResponse {
        status: RpcStatus::ok(),
        white_list,
        gray_list,
    })
}

/// `sync_info` (JSON-RPC, admin-only): where this node is in its download.
///
/// The one method in this slice that reads both fact sources, and it takes
/// them as two arguments so that stays visible. They are not synchronised
/// with each other — the C++ handler read the chain, the connection list and
/// the queue in three separate acquisitions too, and closing that would mean
/// holding a p2p lock across a chain read.
pub fn sync_info(chain: &dyn ChainFacts, p2p: &dyn P2pFacts) -> Result<SyncInfoResponse, RpcFault> {
    let tip = chain.chain_tip()?;
    let connections = p2p.connections()?;
    let queue = p2p.sync_spans()?;
    let height = tip.chain_height.to_raw();
    Ok(SyncInfoResponse {
        status: RpcStatus::ok(),
        height,
        // The same rule `get_version` applies, from the same uncollapsed
        // facts: the raw target survives the seam and is zeroed here.
        target_height: if tip.synchronized {
            0
        } else {
            tip.target_height.to_raw()
        },
        next_needed_pruning_seed: queue.next_needed_pruning_stripe,
        peers: connections
            .connections
            .iter()
            .map(|c| SyncInfoPeer {
                info: project_connection(c, connections.now),
            })
            .collect(),
        spans: queue
            .spans
            .iter()
            .map(|s| SyncSpan {
                start_block_height: s.start_block_height,
                nblocks: s.nblocks,
                connection_id: hex::encode(s.connection_id),
                rate: round_half_up(s.rate),
                // 0..1 on the queue, a percentage on the wire.
                speed: round_half_up(s.speed_fraction * 100.0),
                size: s.size,
                remote_address: s.remote_address.clone(),
            })
            .collect(),
        overview: render_overview(&queue.spans, height),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::chain_facts::{
        BlockAt, BlockFacts, BlockHashAt, BlockHeaderAt, BlockHeaderFacts, ChainTip, HardFork,
        NetStats,
    };
    use crate::core::{ConnectionsSnapshot, SyncSpansSnapshot};
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
        /// When set, the hash arm answers an **alt** block declaring this
        /// height — the state only a hash lookup can reach, and the one the
        /// height arm's bound makes unrepresentable.
        pub alt_declared_height: Option<BlockHeight>,
        /// The last `fill_pow_hash` `block_header_at` was asked for.
        pub asked_pow: AtomicBool,
        /// The hash `block_at` was asked for, when it was asked by hash.
        pub asked_hash: std::sync::Mutex<Option<[u8; 32]>>,
        /// When set, `block_at` faults instead of answering.
        pub block_fault: Option<FactsFault>,
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

        fn block_at(&self, at: BlockLookup, fill_pow_hash: bool) -> Result<BlockAt, FactsFault> {
            self.asked_pow.store(fill_pow_hash, Ordering::Relaxed);
            if let Some(fault) = self.block_fault {
                return Err(fault);
            }
            let chain_height = BlockHeight::from_raw(self.hash_chain_height);
            // The fake applies the same bound the shim does, so a handler that
            // forgets to check one cannot pass by luck.
            let present = match at {
                BlockLookup::Hash(hash) => {
                    *self.asked_hash.lock().expect("not poisoned") = Some(hash);
                    // Only the fake chain's one known hash resolves.
                    hash == patterned_hash().to_bytes()
                }
                BlockLookup::Height(height) => {
                    self.asked_height.store(height.to_raw(), Ordering::Relaxed);
                    height.to_raw() < self.hash_chain_height
                }
            };
            if !present {
                return Ok(BlockAt {
                    block: None,
                    chain_height,
                });
            }
            let mut header = self.header.clone();
            header.pow_hash = fill_pow_hash.then(|| tagged_bytes(23));
            Ok(BlockAt {
                block: Some(BlockFacts {
                    header,
                    blob: vec![0x01, 0x02, 0xab, 0xff],
                    json: "{\n  \"major_version\": 1\n}".to_owned(),
                    tx_hashes: vec![
                        TxHash::from_bytes(tagged_bytes(61)),
                        TxHash::from_bytes(tagged_bytes(67)),
                    ],
                }),
                chain_height,
            })
        }

        fn block_header_at(
            &self,
            at: BlockLookup,
            fill_pow_hash: bool,
        ) -> Result<BlockHeaderAt, FactsFault> {
            self.asked_pow.store(fill_pow_hash, Ordering::Relaxed);
            if let Some(fault) = self.hash_fault {
                return Err(fault);
            }
            let chain_height = BlockHeight::from_raw(self.hash_chain_height);
            // Same two-arm shape as `block_at`, because it answers the same
            // question. **This is a fake chain's own shape, not a copy of the
            // shim's rule** — the fake chain has a height and nothing above it,
            // which is true of any chain. It is deliberately not described as
            // "the bound the shim applies": a double that claims to mirror a
            // rule has to be kept in sync to mean anything, and what the
            // handler actually owes is asserted directly from `asked_height` /
            // `asked_hash` instead.
            let height = match at {
                BlockLookup::Hash(hash) => {
                    *self.asked_hash.lock().expect("not poisoned") = Some(hash);
                    if hash != patterned_hash().to_bytes() {
                        return Ok(BlockHeaderAt {
                            header: None,
                            chain_height,
                        });
                    }
                    // A hash reaches blocks off the main chain, so the height
                    // is the block's own and can sit anywhere — including at
                    // or past the tip, which is the input the height arm
                    // cannot express and the widening made reachable.
                    self.alt_declared_height.unwrap_or(self.header.height)
                }
                BlockLookup::Height(height) => {
                    self.asked_height.store(height.to_raw(), Ordering::Relaxed);
                    if height.to_raw() >= self.hash_chain_height {
                        return Ok(BlockHeaderAt {
                            header: None,
                            chain_height,
                        });
                    }
                    height
                }
            };
            let mut h = self.header.clone();
            h.height = height;
            h.pow_hash = fill_pow_hash.then(|| tagged_bytes(23));
            // Only the alt case overrides it. `sample_header()` carries the
            // value the RK-3 oracle vector was captured with, and clobbering
            // that on the height arm made this fake disagree with the vector
            // it exists to reproduce.
            if self.alt_declared_height.is_some() && matches!(at, BlockLookup::Hash(_)) {
                h.orphan_status = true;
            }
            Ok(BlockHeaderAt {
                header: Some(h),
                chain_height,
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
            alt_declared_height: None,
            asked_pow: AtomicBool::new(false),
            asked_hash: std::sync::Mutex::new(None),
            block_fault: None,
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

    // ── the get_transactions projection matrix ───────────────────────────

    fn chain_slot(prunable: &[u8]) -> TxSlot {
        TxSlot::Chain {
            pruned: vec![0xAA, 0xBB],
            prunable: prunable.to_vec(),
            prunable_hash: [0x11; 32],
            block_height: 7,
            block_timestamp: 1_700_000_000,
            output_indices: vec![3, 4],
            pruned_flag: false,
        }
    }

    /// Renders a marker naming the arguments it was handed, so a test can
    /// assert **what** was rendered and with which `base_only`, not merely
    /// that something was.
    ///
    /// Returns the closure rather than being one: the `Result` is the
    /// projection's bound, not this renderer's own failure mode, and stating
    /// it as `impl Fn(..) -> Result<..>` puts that requirement where a reader
    /// sees it.
    fn echo_render() -> impl Fn(&[u8], bool) -> Result<String, i32> {
        |blob: &[u8], base_only: bool| Ok(format!("{}|base_only={base_only}", hex::encode(blob)))
    }

    fn req(split: bool, prune: bool, decode_as_json: bool) -> GetTransactionsRequest {
        GetTransactionsRequest {
            txs_hashes: vec![],
            decode_as_json,
            prune,
            split,
        }
    }

    /// **The projection matrix, driven across every axis that changes a
    /// field.** This replaced a C++ matrix, and the parity vectors do not
    /// reach it — they build `TxEntry` directly — so without this the
    /// behaviour is unpinned on all three request flags at once.
    #[test]
    fn projection_matrix_over_split_prune_and_decode() {
        const PRUNED_HEX: &str = "aabb";
        const PRUNABLE_HEX: &str = "ccdd";
        let prunable = [0xCC, 0xDD];

        // (split, prune, decode) -> (as_hex, pruned_as_hex, prunable_as_hex, as_json)
        let cases: [(bool, bool, bool, &str, &str, &str, &str); 6] = [
            // Neither flag: the whole transaction, concatenated, one field.
            (false, false, false, "aabbccdd", "", "", ""),
            (
                false,
                false,
                true,
                "aabbccdd",
                "",
                "",
                "aabbccdd|base_only=false",
            ),
            // `split`: the halves, both carried; json still covers both.
            (true, false, false, "", PRUNED_HEX, PRUNABLE_HEX, ""),
            (
                true,
                false,
                true,
                "",
                PRUNED_HEX,
                PRUNABLE_HEX,
                "aabbccdd|base_only=false",
            ),
            // `prune`: the prunable half is withheld, and json is base-only —
            // rendering the full blob here would leak what `prune` withheld.
            (false, true, false, "", PRUNED_HEX, "", ""),
            (false, true, true, "", PRUNED_HEX, "", "aabb|base_only=true"),
        ];

        for (split, prune, decode, as_hex, pruned_as_hex, prunable_as_hex, as_json) in cases {
            let out = project_transactions(
                &req(split, prune, decode),
                &[[0x01; 32]],
                &[chain_slot(&prunable)],
                9,
                echo_render(),
            )
            .expect("render succeeds");
            let e = &out.txs[0];
            let label = format!("split={split} prune={prune} decode={decode}");
            assert_eq!(e.as_hex, as_hex, "as_hex @ {label}");
            assert_eq!(e.pruned_as_hex, pruned_as_hex, "pruned_as_hex @ {label}");
            assert_eq!(
                e.prunable_as_hex, prunable_as_hex,
                "prunable_as_hex @ {label}"
            );
            assert_eq!(e.as_json, as_json, "as_json @ {label}");
        }
    }

    /// **An empty prunable half takes the split form even unasked**, because
    /// there is nothing to concatenate — and its json is base-only for the
    /// same reason. This is the branch the live console test reaches (the
    /// genesis transaction), and the only one it reaches.
    #[test]
    fn an_empty_prunable_half_is_split_form_and_renders_base_only() {
        let out = project_transactions(
            &req(false, false, true),
            &[[0x02; 32]],
            &[chain_slot(&[])],
            9,
            echo_render(),
        )
        .expect("render succeeds");
        let e = &out.txs[0];
        assert!(e.as_hex.is_empty(), "no concatenated form exists");
        assert_eq!(e.pruned_as_hex, "aabb");
        assert!(e.prunable_as_hex.is_empty());
        assert_eq!(e.as_json, "aabb|base_only=true");
    }

    /// Chain, pool and miss land in their own places: the first two become
    /// entries carrying their location, the third only a `missed_tx` id.
    #[test]
    fn chain_pool_and_missed_slots_are_projected_to_their_own_places() {
        let out = project_transactions(
            &req(true, false, false),
            &[[0x01; 32], [0x02; 32], [0x03; 32]],
            &[
                chain_slot(&[0xCC]),
                TxSlot::Pool {
                    pruned: vec![0xAA],
                    prunable: vec![0xCC],
                    prunable_hash: [0x22; 32],
                    double_spend_seen: true,
                    relayed: true,
                    received_timestamp: 1_700_000_001,
                },
                TxSlot::Missed,
            ],
            9,
            echo_render(),
        )
        .expect("render succeeds");

        assert_eq!(out.txs.len(), 2, "the miss must not become an entry");
        assert_eq!(out.missed_tx.len(), 1);
        assert!(matches!(out.txs[0].location, TxLocation::Mined { .. }));
        assert!(matches!(out.txs[1].location, TxLocation::Pooled { .. }));
        assert!(
            out.txs[1].double_spend_seen,
            "the pool's double-spend flag must survive the projection"
        );
        assert!(
            !out.txs[1].pruned,
            "a pooled transaction is never reported pruned"
        );
    }

    /// A renderer failure names the transaction it failed on and fails the
    /// whole reply — it is not swallowed into an empty `as_json`.
    #[test]
    fn a_renderer_failure_names_its_transaction_and_fails_the_reply() {
        let err = project_transactions(
            &req(false, false, true),
            &[[0x09; 32]],
            &[chain_slot(&[0xCC])],
            9,
            |_, _| Err(-7),
        )
        .expect_err("a failing renderer must fail the reply");
        assert_eq!(err.code, -7);
        assert_eq!(err.txid, HashHex::from_bytes([0x09; 32]).to_string());
    }

    #[test]
    fn get_version_reproduces_the_synced_oracle_vector() {
        // Synchronized with a non-zero raw target: the rule zeroes it, and the
        // zero is omitted on the wire exactly as epee omitted it.
        //
        // Against `_v2`: this PR's wire change bumped `CORE_RPC_VERSION` to
        // 3.25, and the vectors are never hand-edited (see their README), so
        // the bump gets a file beside the C++ capture rather than inside it.
        // `get_version_v2_is_v1_with_only_the_version_bumped` is what keeps
        // `_v2` honest — it may differ from the oracle by that constant and
        // nothing else.
        let out = get_version(&facts(true, 999_999)).unwrap();
        assert_eq!(out.target_height, 0);
        let ours: serde_json::Value = serde_json::to_value(&out).unwrap();
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../shekyl-rpc-types/tests/vectors/rpc/get_version_synced_v2.json"
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
            alt_declared_height: None,
            asked_pow: AtomicBool::new(false),
            asked_hash: std::sync::Mutex::new(None),
            block_fault: None,
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

    fn block_req(hash: &str, height: u64) -> GetBlockRequest {
        GetBlockRequest {
            hash: hash.to_owned(),
            height,
            fill_pow_hash: false,
        }
    }

    /// A whole block by height: the header, both copies of the miner tx
    /// hash, the hex blob, the json carried through, and the tx list.
    #[test]
    fn block_by_height_carries_every_part_of_the_reply() {
        let f = header_facts();
        let out = get_block(&f, &block_req("", 1_234_567), false).unwrap();
        assert!(out.status.is_ok());
        assert_eq!(out.block_header.height, 1_234_567);
        assert_eq!(
            out.miner_tx_hash, out.block_header.miner_tx_hash,
            "the wire carries the miner tx hash twice, and they must agree"
        );
        assert_eq!(
            out.blob, "0102abff",
            "the blob is lowercase hex of the bytes"
        );
        assert_eq!(out.json, "{\n  \"major_version\": 1\n}");
        assert_eq!(out.tx_hashes.len(), 2);
        assert_eq!(out.tx_hashes[0], HashHex::from_bytes(tagged_bytes(61)));
    }

    /// A hash wins over a height, and the height is not consulted at all —
    /// passing a past-the-tip height alongside a good hash still answers.
    #[test]
    fn a_hash_wins_over_a_height() {
        let f = header_facts();
        let hash = patterned_hash().to_string();
        let out = get_block(&f, &block_req(&hash, 9_000_000), false).unwrap();
        assert!(out.status.is_ok());
        assert_eq!(
            *f.asked_hash.lock().unwrap(),
            Some(patterned_hash().to_bytes()),
            "the facts layer must be asked by hash, not by the ignored height"
        );
    }

    /// An unparseable hash keeps the C++ diagnostic, which quotes what the
    /// caller sent — the reason the request field is a `String` (RK-D12).
    #[test]
    fn an_unparseable_hash_quotes_what_was_sent() {
        let f = header_facts();
        let err = get_block(&f, &block_req("nonsense", 0), false).unwrap_err();
        assert_eq!(
            err,
            RpcFault::Refused(RpcRefusal::wrong_param(
                "Failed to parse hex representation of block hash. Hex = nonsense."
            ))
        );
    }

    /// Past the tip is the height refusal, naming the top height; a hash the
    /// chain does not have is the C++'s internal-error wording instead.
    #[test]
    fn absence_keeps_the_refusal_that_matches_the_lookup() {
        let f = header_facts();
        assert_eq!(
            get_block(&f, &block_req("", 9_000_000), false).unwrap_err(),
            too_big_height(9_000_000, f.hash_chain_height)
        );

        let unknown = HashHex::from_bytes([9u8; 32]).to_string();
        assert_eq!(
            get_block(&f, &block_req(&unknown, 0), false).unwrap_err(),
            RpcFault::Refused(RpcRefusal {
                code: CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
                message: format!("Internal error: can't get block by hash. Hash = {unknown}."),
            })
        );
    }

    /// A block whose coinbase is not a single `txin_gen` keeps the C++'s own
    /// message rather than becoming a generic internal error.
    #[test]
    fn a_malformed_coinbase_keeps_its_own_message() {
        let mut f = header_facts();
        f.block_fault = Some(FactsFault::Inconsistent);
        assert_eq!(
            get_block(&f, &block_req("", 0), false).unwrap_err(),
            RpcFault::Refused(RpcRefusal {
                code: CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
                message: "Internal error: coinbase transaction in the block has the wrong type"
                    .to_owned(),
            })
        );
    }

    /// The pow hash is asked for only when the caller asked and was allowed.
    #[test]
    fn block_pow_hash_follows_the_entitlement() {
        let f = header_facts();
        let plain = get_block(&f, &block_req("", 1_234_567), false).unwrap();
        assert!(!f.asked_pow.load(Ordering::Relaxed));
        assert_eq!(plain.block_header.pow_hash, None);

        let filled = get_block(&f, &block_req("", 1_234_567), true).unwrap();
        assert!(f.asked_pow.load(Ordering::Relaxed));
        assert_eq!(
            filled.block_header.pow_hash,
            Some(HashHex::from_bytes(tagged_bytes(23)))
        );
    }

    /// This method's params refusal names its own shape — `hash` included,
    /// which `get_block_header_by_height`'s does not have.
    #[test]
    fn block_params_are_refused_naming_this_methods_shape() {
        assert_eq!(
            block_request(&json!(null)).unwrap(),
            GetBlockRequest::default()
        );
        assert_eq!(
            block_request(&json!({})).unwrap(),
            GetBlockRequest::default()
        );
        let parsed = block_request(&json!({"hash": "ab", "height": 7})).unwrap();
        assert_eq!(parsed.hash, "ab", "the handler parses the hash, not serde");
        for bad in [
            json!({"height": -1}),
            json!({"hash": 7}),
            json!([0]),
            json!(0),
        ] {
            let refusal = block_request(&bad).unwrap_err();
            assert_eq!(
                refusal,
                RpcFault::Refused(RpcRefusal::wrong_param(WRONG_BLOCK_PARAMS)),
                "{bad}"
            );
            let RpcFault::Refused(r) = refusal else {
                unreachable!()
            };
            assert!(
                r.message.contains("hash"),
                "the message names this method's hash field"
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

    // ── RK-5a: the p2p methods ─────────────────────────────────────────────

    /// In-memory [`P2pFacts`]. Records `public_only` because that argument
    /// selects a **different p2p call**, not a filter — a handler that
    /// forwarded a constant would pass every assertion about the entries it
    /// got back.
    pub(crate) struct FakeP2p {
        pub net: Result<NetStats, FactsFault>,
        pub connections: Result<ConnectionsSnapshot, FactsFault>,
        pub spans: Result<SyncSpansSnapshot, FactsFault>,
        pub peers: Result<Vec<crate::core::PeerFacts>, FactsFault>,
        pub asked_public_only: AtomicBool,
    }

    impl Default for FakeP2p {
        fn default() -> Self {
            Self {
                net: Ok(NetStats {
                    start_time: 1_788_202_424,
                    total_packets_in: 101,
                    total_bytes_in: 202_020,
                    total_packets_out: 303,
                    total_bytes_out: 404_040,
                }),
                connections: Ok(ConnectionsSnapshot {
                    now: 0,
                    connections: Vec::new(),
                }),
                spans: Ok(SyncSpansSnapshot {
                    next_needed_pruning_stripe: 1,
                    spans: Vec::new(),
                }),
                peers: Ok(Vec::new()),
                asked_public_only: AtomicBool::new(false),
            }
        }
    }

    impl P2pFacts for FakeP2p {
        fn net_stats(&self) -> Result<NetStats, FactsFault> {
            self.net
        }
        fn connections(&self) -> Result<ConnectionsSnapshot, FactsFault> {
            self.connections.clone()
        }
        fn sync_spans(&self) -> Result<SyncSpansSnapshot, FactsFault> {
            self.spans.clone()
        }
        fn peer_list(&self, public_only: bool) -> Result<Vec<crate::core::PeerFacts>, FactsFault> {
            self.asked_public_only.store(public_only, Ordering::SeqCst);
            self.peers.clone()
        }
    }

    /// A connection whose every derived field has a distinct, checkable
    /// input. `started` is 1000 and the tests read it at 1600, so the
    /// connection is 600 seconds old.
    fn connection_facts() -> crate::core::ConnectionFacts {
        crate::core::ConnectionFacts {
            address: "192.0.2.7:18080".to_owned(),
            host: "192.0.2.7".to_owned(),
            peer_id: 0x00ee_3259_4917_a97e,
            connection_id: [
                0x15, 0x1c, 0x23, 0x2a, 0x31, 0x38, 0x3f, 0x46, 0x4d, 0x54, 0x5b, 0x62, 0x69, 0x70,
                0x77, 0x7e,
            ],
            started: 1000,
            last_recv: 1590,
            last_send: 1580,
            // 600 s old, so this is 2048 B/s -> 2 KiB/s after the two
            // truncating divisions.
            recv_count: 600 * 2048,
            send_count: 600 * 1024,
            current_speed_down: 4096.0,
            current_speed_up: 2048.0,
            height: 1_234_567,
            support_flags: 3,
            pruning_seed: 384,
            port: 18080,
            state: 3,
            address_type: ADDRESS_TYPE_IPV4,
            incoming: true,
            localhost: false,
            local_ip: true,
        }
    }

    #[test]
    fn net_stats_reports_the_five_counters() {
        let facts = FakeP2p::default();
        let res = get_net_stats(&facts).expect("net stats");
        assert!(res.status.is_ok());
        assert_eq!(res.start_time, 1_788_202_424);
        assert_eq!(res.total_bytes_in, 202_020);
        assert_eq!(res.total_bytes_out, 404_040);
        assert_eq!(res.total_packets_in, 101);
        assert_eq!(res.total_packets_out, 303);
    }

    /// The derivations that used to be inline C++, each against the one
    /// instant the list was read at.
    #[test]
    fn a_connection_derives_its_times_and_rates_from_one_instant() {
        let facts = FakeP2p {
            connections: Ok(ConnectionsSnapshot {
                now: 1600,
                connections: vec![connection_facts()],
            }),
            ..FakeP2p::default()
        };
        let res = get_connections(&facts).expect("connections");
        let c = &res.connections[0];

        assert_eq!(c.live_time, 600);
        assert_eq!(c.recv_idle_time, 10, "1600 - max(started, last_recv)");
        assert_eq!(c.send_idle_time, 20);
        // bytes / seconds / 1024, in that order and both truncating.
        assert_eq!(c.avg_download, 2);
        assert_eq!(c.avg_upload, 1);
        assert_eq!(c.current_download, 4);
        assert_eq!(c.current_upload, 2);
        // Zero-padded to 16, as `peerid_to_string` pads.
        assert_eq!(c.peer_id, "00ee32594917a97e");
        assert_eq!(c.connection_id, "151c232a31383f464d545b626970777e");
        assert_eq!(c.state, ConnectionState::Normal);
        // ipv4: `ip` echoes the host and `port` is the number as a string.
        assert_eq!(c.ip, "192.0.2.7");
        assert_eq!(c.port, "18080");
    }

    /// A connection younger than a second divides by zero in the naive form.
    /// The averages are 0, not a panic and not a wrapped maximum.
    #[test]
    fn a_brand_new_connection_reports_zero_averages() {
        let facts = FakeP2p {
            connections: Ok(ConnectionsSnapshot {
                now: 1000,
                connections: vec![connection_facts()],
            }),
            ..FakeP2p::default()
        };
        let c = &get_connections(&facts).expect("connections").connections[0];
        assert_eq!(c.live_time, 0);
        assert_eq!(c.avg_download, 0);
        assert_eq!(c.avg_upload, 0);
    }

    /// A clock that moved backwards. The C++ subtracted unsigned and wrapped,
    /// reporting an idle time of some hundreds of years; every elapsed value
    /// here saturates at zero instead.
    #[test]
    fn a_backwards_clock_saturates_rather_than_wrapping() {
        let facts = FakeP2p {
            connections: Ok(ConnectionsSnapshot {
                now: 500,
                connections: vec![connection_facts()],
            }),
            ..FakeP2p::default()
        };
        let c = &get_connections(&facts).expect("connections").connections[0];
        assert_eq!(c.live_time, 0);
        assert_eq!(c.recv_idle_time, 0);
        assert_eq!(c.send_idle_time, 0);
    }

    /// Only the ipv4 arm carries `ip` and `port`; every other address type
    /// carries them empty, and `address` is the whole rendering instead.
    #[test]
    fn a_non_ipv4_connection_carries_no_ip_or_port() {
        let mut raw = connection_facts();
        raw.address_type = 4; // tor
        raw.address = "abcdefghijklmnop.onion:18080".to_owned();
        raw.host = "abcdefghijklmnop.onion".to_owned();
        let facts = FakeP2p {
            connections: Ok(ConnectionsSnapshot {
                now: 1600,
                connections: vec![raw],
            }),
            ..FakeP2p::default()
        };
        let c = &get_connections(&facts).expect("connections").connections[0];
        assert_eq!(c.ip, "");
        assert_eq!(c.port, "");
        assert_eq!(c.address, "abcdefghijklmnop.onion:18080");
        assert_eq!(c.host, "abcdefghijklmnop.onion");
    }

    /// Every state the C++ enum defines, plus the `default:` arm it falls
    /// through to. A raw value outside the enum is `Unknown` and not some
    /// other state's name.
    #[test]
    fn every_protocol_state_maps_to_its_own_name() {
        for (raw, expected) in [
            (0u8, ConnectionState::BeforeHandshake),
            (1, ConnectionState::Synchronizing),
            (2, ConnectionState::Standby),
            (3, ConnectionState::Normal),
            (4, ConnectionState::Unknown),
            (255, ConnectionState::Unknown),
        ] {
            assert_eq!(ConnectionState::from(raw), expected, "raw {raw}");
        }
    }

    /// `include_blocked` is applied here, on the request, and the white/gray
    /// split comes from the entry's own flag.
    #[test]
    fn the_peer_list_splits_by_list_and_filters_blocked_on_request() {
        let peer = |id: u64, white: bool, blocked: bool| crate::core::PeerFacts {
            host: format!("192.0.2.{id}"),
            id,
            last_seen: 1_750_000_000 + id,
            ip: 0,
            pruning_seed: 0,
            port: 18080,
            white,
            blocked,
        };
        let facts = FakeP2p {
            peers: Ok(vec![
                peer(1, true, false),
                peer(2, true, true),
                peer(3, false, false),
                peer(4, false, true),
            ]),
            ..FakeP2p::default()
        };

        let hidden = get_peer_list(
            &GetPeerListRequest {
                public_only: true,
                include_blocked: false,
            },
            &facts,
        )
        .expect("peer list");
        assert_eq!(hidden.white_list.len(), 1);
        assert_eq!(hidden.gray_list.len(), 1);
        assert_eq!(hidden.white_list[0].id, 1);
        assert_eq!(hidden.gray_list[0].id, 3);
        assert!(facts.asked_public_only.load(Ordering::SeqCst));

        let shown = get_peer_list(
            &GetPeerListRequest {
                public_only: false,
                include_blocked: true,
            },
            &facts,
        )
        .expect("peer list");
        assert_eq!(shown.white_list.len(), 2);
        assert_eq!(shown.gray_list.len(), 2);
        assert!(
            !facts.asked_public_only.load(Ordering::SeqCst),
            "public_only reaches the facts call, which chooses a different p2p read"
        );
    }

    /// The lifetime average, including the two inputs that would divide by
    /// zero. Total by construction, so there is no guard to accidentally
    /// move away from the division.
    #[test]
    fn a_lifetime_average_is_total() {
        assert_eq!(average_kib(600 * 2048, 600), 2);
        assert_eq!(average_kib(600 * 1024, 600), 1);
        assert_eq!(average_kib(1023, 1), 0, "truncates to whole KiB");
        assert_eq!(average_kib(u64::MAX, 0), 0, "a zero-length connection");
        assert_eq!(average_kib(0, 0), 0);
    }

    /// The conversion the C++ made with an undefined cast.
    #[test]
    fn a_connection_speed_becomes_whole_kib_totally() {
        assert_eq!(kib_per_second(0.0), 0);
        assert_eq!(kib_per_second(1023.9), 0, "truncates, not rounds");
        assert_eq!(kib_per_second(1024.0), 1);
        assert_eq!(kib_per_second(4096.0), 4);
        // The division is in floating point, as the C++ did it, so this is
        // `trunc(x / 1024)` and not `trunc(x) / 1024`.
        assert_eq!(kib_per_second(2047.9), 1);
        assert_eq!(kib_per_second(-1.0), 0, "negative is clamped, not cast");
        assert_eq!(kib_per_second(f64::NAN), 0);
        assert_eq!(kib_per_second(f64::INFINITY), 0, "not finite");
        assert_eq!(
            kib_per_second(1e30),
            u64::MAX,
            "saturates rather than wraps"
        );
    }

    /// Round half up, on the values the C++ cast was undefined for.
    #[test]
    fn rates_round_half_up_and_never_leave_the_range() {
        assert_eq!(round_half_up(0.0), 0);
        assert_eq!(round_half_up(0.4), 0);
        assert_eq!(round_half_up(0.5), 1);
        assert_eq!(round_half_up(4095.6), 4096);
        assert_eq!(round_half_up(-1.0), 0, "negative is clamped, not cast");
        assert_eq!(round_half_up(f32::NAN), 0);
        assert_eq!(round_half_up(f32::INFINITY), 0, "not finite");
        assert_eq!(round_half_up(1e30), u32::MAX, "saturates rather than wraps");
    }

    fn span(start: u64, nblocks: u64, filled: bool) -> crate::core::SyncSpanFacts {
        crate::core::SyncSpanFacts {
            remote_address: "192.0.2.7:18080".to_owned(),
            start_block_height: start,
            nblocks,
            size: 4096,
            connection_id: [0u8; 16],
            rate: 4096.0,
            speed_fraction: 0.75,
            filled,
        }
    }

    /// Every character the overview can emit, in one picture.
    #[test]
    fn the_overview_renders_each_span_state() {
        // Chain at 100. A span behind it is `<`; the span at the tip that has
        // arrived is `m`; a later arrived span is `o`; an outstanding one is
        // `.`; and the gap before a far span is underscores.
        let spans = vec![
            span(50, 10, true),
            span(100, 10, true),
            span(110, 10, true),
            span(120, 10, false),
        ];
        assert_eq!(render_overview(&spans, 100), "[<mo.]");
        assert_eq!(render_overview(&[], 100), "[]", "an empty queue is `[]`");
    }

    /// The gap run: `(start - expected) / nblocks`, at least one.
    #[test]
    fn the_overview_fills_the_gap_ahead_of_a_span() {
        // Chain at 100, span starts at 150, 10 blocks wide: five underscores.
        assert_eq!(render_overview(&[span(150, 10, true)], 100), "[_____o]");
        // A gap smaller than one span still gets one underscore.
        assert_eq!(render_overview(&[span(105, 10, true)], 100), "[_o]");
    }

    /// The divergence this rendering makes on purpose. A span's
    /// `start_block_height` follows peer-advertised heights, so the C++
    /// `(gap / nblocks)` loop had no ceiling — a peer claiming a height far
    /// ahead sized a string with its claim. The run is clamped.
    #[test]
    fn an_absurd_gap_cannot_size_the_overview() {
        let rendered = render_overview(&[span(u64::MAX / 2, 1, true)], 0);
        assert_eq!(
            u64::try_from(rendered.len()).expect("length fits"),
            MAX_OVERVIEW_GAP + 3,
            "clamped run, plus the brackets and the span's own character"
        );
    }

    /// `sync_info` reads both sources and applies the same synchronized rule
    /// `get_version` does — to the raw target that survived the seam.
    #[test]
    fn sync_info_zeroes_the_target_only_when_synchronized() {
        let p2p = FakeP2p {
            spans: Ok(SyncSpansSnapshot {
                next_needed_pruning_stripe: 7,
                spans: vec![span(100, 10, true)],
            }),
            connections: Ok(ConnectionsSnapshot {
                now: 1600,
                connections: vec![connection_facts()],
            }),
            ..FakeP2p::default()
        };

        let behind = facts(false, 1_234_600);
        let res = sync_info(&behind, &p2p).expect("sync info");
        assert_eq!(res.height, 1_234_567);
        assert_eq!(res.target_height, 1_234_600);
        assert_eq!(res.next_needed_pruning_seed, 7);
        assert_eq!(
            res.peers.len(),
            1,
            "peers carry the connection under `info`"
        );
        assert_eq!(res.spans.len(), 1);
        assert_eq!(res.spans[0].rate, 4096);
        assert_eq!(res.spans[0].speed, 75, "0.75 becomes a percentage");

        let synced = facts(true, 1_234_600);
        let res = sync_info(&synced, &p2p).expect("sync info");
        assert_eq!(res.target_height, 0);
    }
}
