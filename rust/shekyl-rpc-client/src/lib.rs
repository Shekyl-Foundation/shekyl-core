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

use core::{fmt::Debug, future::Future};
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
// Number of blocks the fee estimate will be valid for
// https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c
//   /src/wallet/wallet2.cpp#L121
const GRACE_BLOCKS_FOR_FEE_ESTIMATE: u64 = 10;

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
    /// Construct a new fee rate.
    pub fn new(per_weight: u64, mask: u64) -> Result<FeeRate, RpcError> {
        if (per_weight == 0) || (mask == 0) {
            Err(RpcError::InvalidFee)?;
        }
        Ok(FeeRate { per_weight, mask })
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

/// The daemon's verdict on a `send_raw_transaction` broadcast.
///
/// This is **not** a full mirror of the daemon's
/// `on_send_raw_transaction` response (`core_rpc_server.cpp`). The daemon
/// serializes ~10 rejection-class booleans (`double_spend`, `fee_too_low`,
/// `invalid_input`, `invalid_output`, `too_big`, `overspend`,
/// `too_few_outputs`, `sanity_check_failed`, `tx_extra_too_big`,
/// `nonzero_unlock_time`) plus `not_relayed` and a `reason` string. This
/// struct models only the **verdict subset the wallet consumes**:
///
/// - `status` — `"OK"` (accepted into the pool, possibly relay-local only)
///   vs. any rejection status (`"Failed"`);
/// - `double_spend` / `fee_too_low` — the two rejection classes the wallet
///   maps to distinct terminal outcomes.
///
/// Every other daemon rejection class collapses to a generic terminal
/// `Malformed` in the wallet mapping (no dedicated outcome), so modeling
/// the corresponding flags here would be unread state — fields without a
/// consumer (`21-reversion-clause-discipline.mdc`). `#[serde(default)]`
/// (and the absence of `deny_unknown_fields`) means the daemon's
/// unmodeled fields deserialize-and-ignore rather than failing the parse;
/// when a future wallet outcome needs a finer class (e.g. a daemon
/// stale-FCMP++-root flag, `docs/FOLLOWUPS.md`), the field is added here
/// **with** its consumer.
///
/// [`Rpc::publish_transaction`] returns this for a parsed daemon verdict
/// (including rejection); a transport- or protocol-level failure — or a
/// response that omits `status` — is an [`RpcError`] instead, so callers
/// never see a malformed reply masquerading as a daemon rejection.
///
/// **Intentionally not `#[non_exhaustive]`.** `shekyl-rpc` is a
/// Shekyl-owned, in-workspace crate with no out-of-workspace consumers;
/// the only struct-literal constructors are in-workspace tests
/// (production code only deserializes this). Pre-genesis, adding a field
/// later is a bounded in-workspace edit, not a downstream break, so
/// `#[non_exhaustive]` would buy nothing while blocking the cross-crate
/// test literals (`21-reversion-clause-discipline.mdc`: reject now,
/// reopen if an out-of-workspace consumer ever constructs this type).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct TxRelayResponse {
    /// Daemon status string: `"OK"` on accept, otherwise a rejection
    /// status (e.g. `"Failed"`). An empty/absent value is rejected as
    /// [`RpcError::InvalidNode`] by [`Rpc::publish_transaction`], never
    /// surfaced as a rejection verdict.
    pub status: String,
    /// The transaction double-spends an output already spent or in-pool.
    pub double_spend: bool,
    /// The offered fee is below the daemon's required minimum.
    pub fee_too_low: bool,
}

/// The HTTP `Content-Type` a daemon route expects: EPEE binary routes (`*.bin`,
/// e.g. `get_o_indexes.bin`, `get_blocks_by_height.bin`) are
/// `application/octet-stream`; everything else (JSON-RPC and plain JSON routes) is
/// `application/json`.
///
/// This is a **protocol invariant** — which routes are EPEE-binary — so it lives
/// once here (the `Rpc` trait's home) and is shared by every transport
/// (`shekyl-rpc-transport`'s `SimpleRequestRpc`, the per-`P` `PRpc`) rather than
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
/// `shekyl-rpc-transport` crate (the simple-request/hyper transport) is recommended.
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
            #[derive(Debug, Deserialize)]
            struct HeightResponse {
                height: usize,
            }
            let res = self
                .rpc_call::<Option<()>, HeightResponse>("get_height", None)
                .await?
                .height;
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

    /// Broadcast a transaction to the daemon, returning the daemon's
    /// accept-or-reject decision.
    ///
    /// `tx_blob` is the **serialized** transaction (the canonical wire bytes); it is
    /// hex-encoded into the daemon's `send_raw_transaction` `tx_as_hex` field. The
    /// caller already holds these bytes, so this takes the blob directly rather than a
    /// parsed transaction (no parse → re-serialize round-trip).
    ///
    /// The returned [`TxRelayResponse`] carries the daemon's verdict,
    /// including on rejection: an [`Err`] is reserved for transport- or
    /// protocol-level failures, while a daemon that parses the
    /// transaction and decides to reject it yields an [`Ok`] with
    /// `status != "OK"` and the relevant rejection flags set. Callers map
    /// the verdict onto their own submission-outcome type; this method
    /// does not collapse a daemon rejection into an error, because the
    /// rejection class (double-spend, fee-too-low, …) is information the
    /// caller needs.
    ///
    /// A reply that **omits `status`** is a protocol-shape failure, not a
    /// daemon verdict: under `#[serde(default)]` it would otherwise
    /// deserialize as `status == ""` and be indistinguishable from a
    /// rejection. Such a reply is rejected as [`RpcError::InvalidNode`]
    /// so a malformed/incomplete response is never mistaken for a
    /// terminal daemon rejection by higher layers.
    fn publish_transaction(
        &self,
        tx_blob: &[u8],
    ) -> impl Send + Future<Output = Result<TxRelayResponse, RpcError>> {
        async move {
            let res: TxRelayResponse = self
                .rpc_call(
                    "send_raw_transaction",
                    Some(json!({ "tx_as_hex": hex::encode(tx_blob), "do_sanity_checks": false })),
                )
                .await?;

            if res.status.is_empty() {
                Err(RpcError::InvalidNode(
                    "send_raw_transaction reply omitted status".to_string(),
                ))?;
            }

            Ok(res)
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
            // Given the immaturity of Rust epee libraries, this is a homegrown one which is only
            // validated to work against this specific function

            // Header for EPEE, an 8-byte magic and a version
            const EPEE_HEADER: &[u8] = b"\x01\x11\x01\x01\x01\x01\x02\x01\x01";

            // Read an EPEE VarInt, distinct from the VarInts used throughout the rest of the protocol
            fn read_epee_vi<R: io::Read>(reader: &mut R) -> io::Result<u64> {
                let vi_start = read_byte(reader)?;
                let len = match vi_start & 0b11 {
                    0 => 1,
                    1 => 2,
                    2 => 4,
                    3 => 8,
                    _ => unreachable!(),
                };
                let mut vi = u64::from(vi_start >> 2);
                for i in 1..len {
                    vi |= u64::from(read_byte(reader)?) << (((i - 1) * 8) + 6);
                }
                Ok(vi)
            }

            let mut request = EPEE_HEADER.to_vec();
            // Number of fields (shifted over 2 bits as the 2 LSBs are reserved for metadata)
            request.push(1 << 2);
            // Length of field name
            request.push(4);
            // Field name
            request.extend(b"txid");
            // Type of field
            request.push(10);
            // Length of string, since this byte array is technically a string
            request.push(32 << 2);
            // The "string"
            request.extend(hash);

            let indexes_buf = self.bin_call("get_o_indexes.bin", request).await?;
            let mut indexes = indexes_buf.as_slice();

            (|| {
                let mut res = None;
                let mut has_status = false;

                if read_bytes::<_, { EPEE_HEADER.len() }>(&mut indexes)? != EPEE_HEADER {
                    Err(io::Error::other("invalid header"))?;
                }

                let read_object = |reader: &mut &[u8]| -> io::Result<Vec<u64>> {
                    // Read the amount of fields
                    let fields = read_byte(reader)? >> 2;

                    for _ in 0..fields {
                        // Read the length of the field's name
                        let name_len = read_byte(reader)?;
                        // Read the name of the field
                        let name = read_raw_vec(read_byte, name_len.into(), reader)?;

                        let type_with_array_flag = read_byte(reader)?;
                        // The type of this field, without the potentially set array flag
                        let kind = type_with_array_flag & (!0x80);
                        let has_array_flag = type_with_array_flag != kind;

                        // Read this many instances of the field
                        let iters = if has_array_flag {
                            read_epee_vi(reader)?
                        } else {
                            1
                        };

                        // Check the field type
                        {
                            #[allow(clippy::match_same_arms)]
                            let (expected_type, expected_array_flag) = match name.as_slice() {
                                b"o_indexes" => (5, true),
                                b"status" => (10, false),
                                b"untrusted" => (11, false),
                                b"credits" => (5, false),
                                b"top_hash" => (10, false),
                                // On-purposely prints name as a byte vector to prevent printing arbitrary strings
                                // This is a self-describing format so we don't have to error here, yet we don't
                                // claim this to be a complete deserialization function
                                // To ensure it works for this specific use case, it's best to ensure it's limited
                                // to this specific use case (ensuring we have less variables to deal with)
                                _ => Err(io::Error::other(format!(
                                    "unrecognized field in get_o_indexes: {name:?}"
                                )))?,
                            };
                            if (expected_type != kind) || (expected_array_flag != has_array_flag) {
                                let fmt_array_bool =
                                    |array_bool| if array_bool { "array" } else { "not array" };
                                Err(io::Error::other(format!(
                                    "field {name:?} was {kind} ({}), expected {expected_type} ({})",
                                    fmt_array_bool(has_array_flag),
                                    fmt_array_bool(expected_array_flag)
                                )))?;
                            }
                        }

                        let read_field_as_bytes = match kind {
                            /*
                            // i64
                            1 => |reader: &mut &[u8]| read_raw_vec(read_byte, 8, reader),
                            // i32
                            2 => |reader: &mut &[u8]| read_raw_vec(read_byte, 4, reader),
                            // i16
                            3 => |reader: &mut &[u8]| read_raw_vec(read_byte, 2, reader),
                            // i8
                            4 => |reader: &mut &[u8]| read_raw_vec(read_byte, 1, reader),
                            */
                            // u64
                            5 => |reader: &mut &[u8]| read_raw_vec(read_byte, 8, reader),
                            /*
                            // u32
                            6 => |reader: &mut &[u8]| read_raw_vec(read_byte, 4, reader),
                            // u16
                            7 => |reader: &mut &[u8]| read_raw_vec(read_byte, 2, reader),
                            // u8
                            8 => |reader: &mut &[u8]| read_raw_vec(read_byte, 1, reader),
                            // double
                            9 => |reader: &mut &[u8]| read_raw_vec(read_byte, 8, reader),
                            */
                            // string, or any collection of bytes
                            10 => |reader: &mut &[u8]| {
                                let len = read_epee_vi(reader)?;
                                read_raw_vec(
                                    read_byte,
                                    len.try_into().map_err(|_| {
                                        io::Error::other("u64 length exceeded usize")
                                    })?,
                                    reader,
                                )
                            },
                            // bool
                            11 => |reader: &mut &[u8]| read_raw_vec(read_byte, 1, reader),
                            /*
                            // object, errors here as it shouldn't be used on this call
                            12 => {
                              |_: &mut &[u8]| Err(io::Error::other("node used object in reply to get_o_indexes"))
                            }
                            // array, so far unused
                            13 => |_: &mut &[u8]| Err(io::Error::other("node used the unused array type")),
                            */
                            _ => |_: &mut &[u8]| Err(io::Error::other("node used an invalid type")),
                        };

                        let mut bytes_res = vec![];
                        for _ in 0..iters {
                            bytes_res.push(read_field_as_bytes(reader)?);
                        }

                        let mut actual_res = Vec::with_capacity(bytes_res.len());
                        match name.as_slice() {
                            b"o_indexes" => {
                                for o_index in bytes_res {
                                    actual_res.push(read_u64(&mut o_index.as_slice())?);
                                }
                                res = Some(actual_res);
                            }
                            b"status" => {
                                if bytes_res
                                    .first()
                                    .ok_or_else(|| io::Error::other("status was a 0-length array"))?
                                    .as_slice()
                                    != b"OK"
                                {
                                    Err(io::Error::other("response wasn't OK"))?;
                                }
                                has_status = true;
                            }
                            b"untrusted" | b"credits" | b"top_hash" => continue,
                            _ => Err(io::Error::other("unrecognized field in get_o_indexes"))?,
                        }
                    }

                    if !has_status {
                        Err(io::Error::other("response didn't contain a status"))?;
                    }

                    // If the Vec was empty, it would've been omitted, hence the unwrap_or
                    Ok(res.unwrap_or(vec![]))
                };

                read_object(&mut indexes)
            })()
            .map_err(|e| RpcError::InvalidNode(format!("invalid binary response: {e:?}")))
        }
    }
}
