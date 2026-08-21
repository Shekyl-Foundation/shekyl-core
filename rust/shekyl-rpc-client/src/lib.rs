// Provenance: this crate and its modules are forked from monero-oxide
// (Shekyl-Foundation/monero-oxide, fcmp++ lineage), originally `shekyl-oxide/rpc`, last
// vendored at 2753111c50. Relocated to a first-party shekyl-* crate in the shekyl-oxide
// un-vendor (slice 2); no longer upstream-tracked. Transitional: the wallet's daemon
// RPC client `Rpc` trait, slated for replacement by the Axum-side shekyl-daemon-rpc
// cutover (tracked in docs/FOLLOWUPS.md). See docs/design/SHEKYL_OXIDE_UNVENDOR.md.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

use core::{fmt::Debug, future::Future, num::NonZeroU64};
use std_shims::{
    alloc::format,
    io,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use zeroize::Zeroize;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};

use shekyl_curve_io::*;
use shekyl_portable_storage::{
    load_from_binary, store_to_binary, Array, Limits, Section, Value as StorageValue,
};
// Number of blocks the fee estimate will be valid for
// https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c
//   /src/wallet/wallet2.cpp#L121
/// Grace-block horizon for the daemon's `get_fee_estimate` JSON-RPC:
/// the daemon estimates a rate expected to stay above the relay floor
/// for this many blocks. `pub` because this crate is the single owner
/// of the value (inherited from wallet2's constant of the same intent);
/// `shekyl-engine-core`'s snapshot path imports it rather than keeping
/// a shadow copy that could drift.
pub const GRACE_BLOCKS_FOR_FEE_ESTIMATE: u64 = 10;

/// Phase 2a canonical dust threshold (§3.10.2).
pub mod tx_fee;

/// An error from the RPC.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum RpcError {
    /// An internal error.
    #[error("internal error ({0})")]
    InternalError(String),
    /// A connection error with the node.
    #[error("connection error ({0})")]
    ConnectionError(String),
    /// The node is invalid per the expected protocol.
    #[error("invalid node ({0})")]
    InvalidNode(String),
    /// Requested transactions weren't found.
    #[error("transactions not found")]
    TransactionsNotFound(Vec<[u8; 32]>),
    /// The transaction was pruned.
    ///
    /// Pruned transactions are not supported at this time.
    #[error("pruned transaction")]
    PrunedTransaction,
    /// A transaction (sent or received) was invalid.
    #[error("invalid transaction ({0:?})")]
    InvalidTransaction([u8; 32]),
    /// The returned fee was unusable.
    #[error("unexpected fee response")]
    InvalidFee,
    /// The priority intended for use wasn't usable.
    #[error("invalid priority")]
    InvalidPriority,
}

/// A struct containing a fee rate.
///
/// The fee rate is defined as a per-weight cost, along with a mask for rounding purposes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct FeeRate {
    /// The fee per-weight of the transaction.
    per_weight: u64,
    /// The mask to round with.
    mask: u64,
}

impl FeeRate {
    /// Construct a fee rate whose non-zero invariants the caller's own
    /// types already carry.
    ///
    /// Total, so a caller holding the proof — a `Custom` rate that
    /// arrived as [`NonZeroU64`], against the mask of an
    /// already-validated snapshot — gets no unreachable error arm to
    /// misclassify. [`Self::new`] is the fallible edge, for the bare
    /// `u64` fields that come off the daemon wire.
    #[must_use]
    pub const fn from_nonzero(per_weight: NonZeroU64, mask: NonZeroU64) -> FeeRate {
        FeeRate {
            per_weight: per_weight.get(),
            mask: mask.get(),
        }
    }

    /// Construct a new fee rate, rejecting a zero rate or zero mask.
    pub fn new(per_weight: u64, mask: u64) -> Result<FeeRate, RpcError> {
        match (NonZeroU64::new(per_weight), NonZeroU64::new(mask)) {
            (Some(per_weight), Some(mask)) => Ok(Self::from_nonzero(per_weight, mask)),
            _ => Err(RpcError::InvalidFee),
        }
    }

    /// Atomic units charged per weight unit, before mask rounding.
    #[must_use]
    pub fn per_weight(&self) -> u64 {
        self.per_weight
    }

    /// Quantization mask the fee is rounded up to.
    #[must_use]
    pub fn mask(&self) -> u64 {
        self.mask
    }

    /// Write the FeeRate.
    ///
    /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
    /// defined serialization.
    pub fn write(&self, w: &mut impl io::Write) -> io::Result<()> {
        w.write_all(&self.per_weight.to_le_bytes())?;
        w.write_all(&self.mask.to_le_bytes())
    }

    /// Serialize the FeeRate to a `Vec<u8>`.
    ///
    /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
    /// defined serialization.
    pub fn serialize(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(16);
        self.write(&mut res)
            .expect("write failed but <Vec as io::Write> doesn't fail");
        res
    }

    /// Read a FeeRate.
    ///
    /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
    /// defined serialization.
    pub fn read(r: &mut impl io::Read) -> io::Result<FeeRate> {
        let per_weight = read_u64(r)?;
        let mask = read_u64(r)?;
        FeeRate::new(per_weight, mask).map_err(io::Error::other)
    }

    /// Calculate the fee to use from the weight.
    ///
    /// This function may panic upon overflow.
    pub fn calculate_fee_from_weight(&self, weight: usize) -> u64 {
        let fee = self.per_weight
            * u64::try_from(weight).expect("couldn't convert weight (usize) to u64");
        let fee = fee.div_ceil(self.mask) * self.mask;
        debug_assert_eq!(
            Some(weight),
            self.calculate_weight_from_fee(fee),
            "Miscalculated weight from fee"
        );
        fee
    }

    /// Calculate the weight from the fee.
    ///
    /// Returns `None` if the weight would not fit within a `usize`.
    pub fn calculate_weight_from_fee(&self, fee: u64) -> Option<usize> {
        usize::try_from(fee / self.per_weight).ok()
    }
}

/// The priority for the fee.
///
/// Higher-priority transactions will be included in blocks earlier.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(non_camel_case_types)]
pub enum FeePriority {
    /// The `Unimportant` priority, as defined by Monero.
    Unimportant,
    /// The `Normal` priority, as defined by Monero.
    Normal,
    /// The `Elevated` priority, as defined by Monero.
    Elevated,
    /// The `Priority` priority, as defined by Monero.
    Priority,
    /// A custom priority.
    Custom {
        /// The numeric representation of the priority, as used within the RPC.
        priority: u32,
    },
}

/// https://github.com/monero-project/monero/blob/ac02af92867590ca80b2779a7bbeafa99ff94dcb/
///   src/simplewallet/simplewallet.cpp#L161
impl FeePriority {
    pub(crate) fn fee_priority(&self) -> u32 {
        match self {
            FeePriority::Unimportant => 1,
            FeePriority::Normal => 2,
            FeePriority::Elevated => 3,
            FeePriority::Priority => 4,
            FeePriority::Custom { priority, .. } => *priority,
        }
    }
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
    result: T,
}

fn rpc_hex(value: &str) -> Result<Vec<u8>, RpcError> {
    hex::decode(value).map_err(|_| RpcError::InvalidNode("expected hex wasn't hex".to_string()))
}

fn hash_hex(hash: &str) -> Result<[u8; 32], RpcError> {
    rpc_hex(hash)?
        .try_into()
        .map_err(|_| RpcError::InvalidNode("hash wasn't 32-bytes".to_string()))
}

// The submit wire contract is defined once in `shekyl-rpc-types`
// (`docs/design/DAEMON_SUBMIT_VERDICT.md` §2.3's single-Rust-definition
// rule) and re-exported here so wallet-side consumers reach it through
// their existing `shekyl_rpc_client` import without a second direct
// dependency. The legacy `TxRelayResponse` (a lossy projection of the
// deleted `send_raw_transaction` boolean-flag reply) is replaced by the
// typed [`SubmitVerdict`]; see [`Rpc::publish_transaction`].
pub use shekyl_rpc_types::{RejectCause, SubmitTransactionRequest, SubmitVerdict};

/// The HTTP `Content-Type` a daemon route expects: EPEE binary routes (`*.bin`,
/// e.g. `get_o_indexes.bin`, `get_blocks_by_height.bin`) are
/// `application/octet-stream`; everything else (JSON-RPC and plain JSON routes) is
/// `application/json`.
///
/// This is a **protocol invariant** — which routes are EPEE-binary — so it lives
/// once here (the `Rpc` trait's home) and is shared by every transport
/// (`shekyl-rpc-transport`'s `HttpRpc`, the per-`P` `PRpc`) rather than
/// re-derived per impl, where the copies could drift.
pub fn content_type_for(route: &str) -> &'static str {
    if route.ends_with(".bin") {
        "application/octet-stream"
    } else {
        "application/json"
    }
}

/// An RPC connection to a Monero daemon.
///
/// This is abstract such that users can use an HTTP library (which being their choice), a
/// Tor/i2p-based transport, or even a memory buffer an external service somehow routes.
///
/// While no implementors are directly provided here, the first-party
/// `shekyl-rpc-transport` crate (a hyper transport with optional SOCKS5h) is recommended.
pub trait Rpc: Sync + Clone {
    /// Perform a POST request to the specified route with the specified body.
    ///
    /// The implementor is left to handle anything such as authentication.
    fn post(
        &self,
        route: &str,
        body: Vec<u8>,
    ) -> impl Send + Future<Output = Result<Vec<u8>, RpcError>>;

    /// Perform a RPC call to the specified route with the provided parameters.
    ///
    /// This is NOT a JSON-RPC call. They use a route of "json_rpc" and are available via
    /// `json_rpc_call`.
    fn rpc_call<Params: Send + Serialize + Debug, Response: DeserializeOwned + Debug>(
        &self,
        route: &str,
        params: Option<Params>,
    ) -> impl Send + Future<Output = Result<Response, RpcError>> {
        async move {
            let res = self
                .post(
                    route,
                    if let Some(params) = params.as_ref() {
                        serde_json::to_string(params)
                            .map_err(|e| {
                                RpcError::InternalError(format!(
                                    "couldn't convert parameters ({params:?}) to JSON: {e:?}"
                                ))
                            })?
                            .into_bytes()
                    } else {
                        vec![]
                    },
                )
                .await?;
            let res_str = std_shims::str::from_utf8(&res)
                .map_err(|_| RpcError::InvalidNode("response wasn't utf-8".to_string()))?;
            serde_json::from_str(res_str).map_err(|_| {
                RpcError::InvalidNode(format!("response wasn't the expected json: {res_str}"))
            })
        }
    }

    /// Perform a JSON-RPC call with the specified method with the provided parameters.
    fn json_rpc_call<Response: DeserializeOwned + Debug>(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> impl Send + Future<Output = Result<Response, RpcError>> {
        async move {
            // Emit a compliant JSON-RPC 2.0 envelope. The Shekyl daemon RPC
            // server requires `id` (and the spec mandates `jsonrpc`); the
            // response `id` is unused here (only `result` is read).
            let mut req = json!({ "jsonrpc": "2.0", "id": 0, "method": method });
            if let Some(params) = params {
                req.as_object_mut()
                    .expect("accessing object as object failed?")
                    .insert("params".into(), params);
            }
            Ok(self
                .rpc_call::<_, JsonRpcResponse<Response>>("json_rpc", Some(req))
                .await?
                .result)
        }
    }

    /// Perform a binary call to the specified route with the provided parameters.
    fn bin_call(
        &self,
        route: &str,
        params: Vec<u8>,
    ) -> impl Send + Future<Output = Result<Vec<u8>, RpcError>> {
        async move { self.post(route, params).await }
    }

    /// Get the active blockchain protocol version.
    ///
    /// This is specifically the major version within the most recent block header.
    fn get_hardfork_version(&self) -> impl Send + Future<Output = Result<u8, RpcError>> {
        async move {
            #[derive(Debug, Deserialize)]
            struct HeaderResponse {
                major_version: u8,
            }

            #[derive(Debug, Deserialize)]
            struct LastHeaderResponse {
                block_header: HeaderResponse,
            }

            Ok(self
                .json_rpc_call::<LastHeaderResponse>("get_last_block_header", None)
                .await?
                .block_header
                .major_version)
        }
    }

    /// Get the height of the Monero blockchain.
    ///
    /// The height is defined as the amount of blocks on the blockchain. For a blockchain with only
    /// its genesis block, the height will be 1.
    fn get_height(&self) -> impl Send + Future<Output = Result<usize, RpcError>> {
        async move {
            // The wire type is `shekyl-rpc-types`'s (RK-D1): one definition for
            // the daemon that serves it and the wallet that reads it.
            let res = self
                .rpc_call::<Option<()>, shekyl_rpc_types::GetHeightResponse>("get_height", None)
                .await?
                .height;
            let res = usize::try_from(res)
                .map_err(|_| RpcError::InvalidNode("height does not fit usize".to_string()))?;
            if res == 0 {
                Err(RpcError::InvalidNode(
                    "node responded with 0 for the height".to_string(),
                ))?;
            }
            Ok(res)
        }
    }

    /// Get the hash of a block from the node.
    ///
    /// `number` is the block's zero-indexed position on the blockchain (`0` for the genesis block,
    /// `height - 1` for the latest block).
    fn get_block_hash(
        &self,
        number: usize,
    ) -> impl Send + Future<Output = Result<[u8; 32], RpcError>> {
        async move {
            #[derive(Debug, Deserialize)]
            struct BlockHeaderResponse {
                hash: String,
            }
            #[derive(Debug, Deserialize)]
            struct BlockHeaderByHeightResponse {
                block_header: BlockHeaderResponse,
            }

            let header: BlockHeaderByHeightResponse = self
                .json_rpc_call(
                    "get_block_header_by_height",
                    Some(json!({ "height": number })),
                )
                .await?;
            hash_hex(&header.block_header.hash)
        }
    }

    /// Get the currently estimated fee rate from the node.
    ///
    /// This may be manipulated to unsafe levels and MUST be sanity checked.
    ///
    /// This MUST NOT be expected to be deterministic in any way.
    ///
    /// NOTE (2026-08-16): parallel, older consumer path — the engine's
    /// build/quote surfaces use `DaemonClient::get_fee_estimates` (one
    /// atomic snapshot, interim-ceiling-guarded). The remaining
    /// consumer is `shekyl-mobile-wallet`; consolidate onto the
    /// snapshot path when that wallet re-wires against
    /// `shekyl-wallet-rpc`.
    fn get_fee_rate(
        &self,
        priority: FeePriority,
    ) -> impl Send + Future<Output = Result<FeeRate, RpcError>> {
        async move {
            #[derive(Debug, Deserialize)]
            struct FeeResponse {
                status: String,
                fees: Option<Vec<u64>>,
                fee: u64,
                quantization_mask: u64,
            }

            let res: FeeResponse = self
                .json_rpc_call(
                    "get_fee_estimate",
                    Some(json!({ "grace_blocks": GRACE_BLOCKS_FOR_FEE_ESTIMATE })),
                )
                .await?;

            if res.status != "OK" {
                Err(RpcError::InvalidFee)?;
            }

            if let Some(fees) = res.fees {
                // https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c/
                // src/wallet/wallet2.cpp#L7615-L7620
                let priority_idx = usize::try_from(if priority.fee_priority() >= 4 {
                    3
                } else {
                    priority.fee_priority().saturating_sub(1)
                })
                .map_err(|_| RpcError::InvalidPriority)?;

                if priority_idx >= fees.len() {
                    Err(RpcError::InvalidPriority)
                } else {
                    FeeRate::new(fees[priority_idx], res.quantization_mask)
                }
            } else {
                // https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c/
                //   src/wallet/wallet2.cpp#L7569-L7584
                // https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c/
                //   src/wallet/wallet2.cpp#L7660-L7661
                let priority_idx = usize::try_from(if priority.fee_priority() == 0 {
                    1
                } else {
                    priority.fee_priority() - 1
                })
                .map_err(|_| RpcError::InvalidPriority)?;
                let multipliers = [1, 5, 25, 1000];
                if priority_idx >= multipliers.len() {
                    // though not an RPC error, it seems sensible to treat as such
                    Err(RpcError::InvalidPriority)?;
                }
                let fee_multiplier = multipliers[priority_idx];

                FeeRate::new(res.fee * fee_multiplier, res.quantization_mask)
            }
        }
    }

    /// Offer a transaction to the daemon via the typed submit route,
    /// returning the daemon's atomic [`SubmitVerdict`]
    /// (`docs/design/DAEMON_SUBMIT_VERDICT.md` §2).
    ///
    /// `tx_blob` is the **serialized** transaction (the canonical wire bytes); it is
    /// hex-encoded into the `POST /submit_transaction` request's `tx_blob` field. The
    /// caller already holds these bytes, so this takes the blob directly rather than a
    /// parsed transaction (no parse → re-serialize round-trip).
    ///
    /// The response body **is** the serde-tagged verdict: HTTP 200 for
    /// every verdict *including* `Rejected` — a daemon that parses the
    /// transaction and decides to refuse it yields `Ok(Rejected { cause })`,
    /// because the rejection cause drives the caller's per-cause
    /// disposition (§2.5). The [`Err`] arm is reserved for transport- and
    /// protocol-level failures, which are the *absence* of a verdict
    /// (Two Generals): connection drop, timeout, non-JSON body.
    ///
    /// # Version-skew behavior (§2.3, pinned by `shekyl-rpc-types` tests)
    ///
    /// - An unknown `cause` string inside `Rejected` deserializes to
    ///   [`RejectCause::Unrecognized`] — the fail-safe release path.
    /// - An unknown top-level `verdict` tag fails deserialization and
    ///   surfaces as [`RpcError::InvalidNode`] — a verdict this build
    ///   cannot name is not a verdict it can act on, so it lands in the
    ///   same ambiguous arm as a transport drop (hold + TTL + resubmit).
    fn publish_transaction(
        &self,
        tx_blob: &[u8],
    ) -> impl Send + Future<Output = Result<SubmitVerdict, RpcError>> {
        async move {
            self.rpc_call(
                "submit_transaction",
                Some(SubmitTransactionRequest {
                    tx_blob: hex::encode(tx_blob),
                }),
            )
            .await
        }
    }

    /// Generate blocks, with the specified address receiving the block reward.
    ///
    /// Returns the hashes of the generated blocks and the last block's number.
    fn generate_blocks(
        &self,
        address: &str,
        block_count: usize,
    ) -> impl Send + Future<Output = Result<(Vec<[u8; 32]>, usize), RpcError>> {
        let address = String::from(address);
        async move {
            #[derive(Debug, Deserialize)]
            struct BlocksResponse {
                blocks: Vec<String>,
                height: usize,
            }

            let res = self
                .json_rpc_call::<BlocksResponse>(
                    "generateblocks",
                    Some(json!({
                      "wallet_address": address,
                      "amount_of_blocks": block_count
                    })),
                )
                .await?;

            let mut blocks = Vec::with_capacity(res.blocks.len());
            for block in res.blocks {
                blocks.push(hash_hex(&block)?);
            }
            Ok((blocks, res.height))
        }
    }

    /// Get the output indexes of the specified transaction.
    fn get_o_indexes(
        &self,
        hash: [u8; 32],
    ) -> impl Send + Future<Output = Result<Vec<u64>, RpcError>> {
        async move {
            let mut root = Section::new();
            root.insert("txid", StorageValue::Bytes(hash.to_vec()));
            let request =
                store_to_binary(&root).map_err(|e| RpcError::InternalError(e.to_string()))?;

            let indexes_buf = self.bin_call("get_o_indexes.bin", request).await?;
            let decoded = load_from_binary(&indexes_buf, Limits::HTTP_BIN)
                .map_err(|e| RpcError::InvalidNode(format!("invalid binary response: {e}")))?;

            match decoded.get("status") {
                Some(StorageValue::Bytes(status)) if status.as_slice() == b"OK" => {}
                _ => {
                    return Err(RpcError::InvalidNode(
                        "invalid binary response: missing or non-OK status".into(),
                    ));
                }
            }

            match decoded.get("o_indexes") {
                None => Ok(vec![]),
                Some(StorageValue::Array(Array::UInt64(indexes))) => Ok(indexes.clone()),
                Some(_) => Err(RpcError::InvalidNode(
                    "invalid binary response: o_indexes was not a uint64 array".into(),
                )),
            }
        }
    }
}
