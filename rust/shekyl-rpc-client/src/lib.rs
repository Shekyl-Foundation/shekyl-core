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
use shekyl_rpc_types::core_rpc_version_string;
use shekyl_types::ChainCount;
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
    /// The daemon answered the identity handshake (`VC-4`), and it is not a
    /// daemon this wallet can use: another RPC contract, rule set, network or
    /// chain. Typed, so a caller names the axis and its remedy from the value;
    /// the message is this wallet's own wording of it.
    #[error("{}", identity_refusal(.0))]
    IdentityMismatch(IdentityMismatch),
}

/// What a daemon RPC failure means for whoever has to act on it.
///
/// Classified once, where the failure is raised ([`RpcError::fault`]), so
/// every layer above reads the remedy from this value rather than from a
/// message. Fixed-size and `Copy`: it carries no text the daemon supplied,
/// so it can cross boundaries that must not carry any (the refresh
/// producer's error, `STAGE_1_PR_4_REFRESH_ENGINE.md` §5.4.7 R6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaemonFault {
    /// The daemon could not be reached, or did not answer. Retry, or check
    /// the daemon address.
    Unreachable,
    /// The daemon answered the identity handshake and is not one this wallet
    /// can use. Retrying the same daemon cannot succeed.
    Identity(IdentityMismatch),
    /// The daemon answered with something that breaks the RPC contract: a
    /// malformed, inconsistent or pruned reply. Another daemon may answer
    /// correctly.
    Protocol,
    /// The daemon's fee estimate was unusable.
    FeeResponse,
    /// A failure on this side of the connection: a request this wallet could
    /// not encode, or a priority with no fee tier. A bug, not a daemon fault.
    Internal,
}

impl core::fmt::Display for DaemonFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unreachable => f.write_str("the daemon did not answer"),
            Self::Identity(mismatch) => {
                write!(f, "the daemon was refused on its {}", mismatch.axis())
            }
            Self::Protocol => f.write_str("the daemon's reply broke the RPC contract"),
            Self::FeeResponse => f.write_str("the daemon's fee estimate was unusable"),
            Self::Internal => f.write_str("the request failed on this side of the connection"),
        }
    }
}

impl DaemonFault {
    /// Whether retrying against the same daemon can succeed. An identity
    /// refusal is cached by the client and repeats on every request.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        !matches!(self, Self::Identity(_))
    }
}

impl RpcError {
    /// What this failure means for the remedy. Exhaustive: a new variant
    /// does not compile until its remedy is named.
    #[must_use]
    pub const fn fault(&self) -> DaemonFault {
        match self {
            Self::ConnectionError(_) => DaemonFault::Unreachable,
            Self::IdentityMismatch(mismatch) => DaemonFault::Identity(*mismatch),
            Self::InvalidNode(_)
            | Self::TransactionsNotFound(_)
            | Self::PrunedTransaction
            | Self::InvalidTransaction(_) => DaemonFault::Protocol,
            Self::InvalidFee => DaemonFault::FeeResponse,
            Self::InternalError(_) | Self::InvalidPriority => DaemonFault::Internal,
        }
    }
}

/// This wallet's wording of an identity refusal, one sentence per axis.
///
/// The console words the same verdict its own way
/// (`shekyl-daemon-rpc`'s `console_identity_message`); the axes themselves
/// are compared once, in [`shekyl_rpc_types::IdentityExpectation::check`].
fn identity_refusal(mismatch: &IdentityMismatch) -> String {
    match *mismatch {
        IdentityMismatch::Wire { ours, theirs } => {
            let older = if theirs < ours {
                "daemon"
            } else {
                "this wallet"
            };
            format!(
                "{axis} mismatch: this wallet is {}, the daemon is {} — the {older} is the \
                 older one; update it. Refusing before any wallet operation.",
                core_rpc_version_string(ours),
                core_rpc_version_string(theirs),
                axis = IdentityAxis::Wire,
            )
        }
        IdentityMismatch::WireUnreadable { ours } => format!(
            "this daemon's `get_version` does not match the RPC contract this wallet \
             was built against, so the two are on different RPC versions. This wallet \
             is {}. The reply could not be read, so the daemon's version cannot be \
             named here; align the two builds.",
            core_rpc_version_string(ours),
        ),
        IdentityMismatch::Rules { ours, theirs } => format!(
            "{axis} mismatch: this wallet's digest is {ours}, the daemon's is {theirs}. The \
             RPC contract matches, so neither side is a stale release — the two were built \
             from different consensus configurations, which is a different rule set rather \
             than a version skew. Balances read from it would be computed under rules this \
             wallet does not implement.",
            axis = IdentityAxis::Rules,
        ),
        IdentityMismatch::Network { ours, theirs } => format!(
            "{axis} mismatch: this wallet is a {ours} wallet, the daemon runs {theirs}. \
             Connect to a {ours} daemon; this one is refused before anything is scanned.",
            axis = IdentityAxis::Network,
        ),
        IdentityMismatch::Genesis {
            ours,
            theirs,
            network,
        } => format!(
            "{axis} mismatch: this daemon's chain starts at {theirs}, this wallet's \
             {network} genesis is {ours}. Whatever else agrees, that is a different \
             chain.",
            axis = IdentityAxis::Genesis,
        ),
    }
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
            FeePriority::Priority => 4,
            FeePriority::Custom { priority, .. } => *priority,
        }
    }
}

/// Which fee tier a caller's priority buys.
///
/// Priority `0` and `1` both take the lowest tier (the old index arithmetic
/// reached that by `saturating_sub(1)` on a `u32`), `2` takes the middle,
/// and anything `>= 3` — including a `Custom` priority of a million — takes
/// the highest. Every `u32` maps to a tier.
fn fee_tier_for(priority: FeePriority) -> shekyl_rpc_types::FeeTier {
    match priority.fee_priority() {
        0 | 1 => shekyl_rpc_types::FeeTier::Low,
        2 => shekyl_rpc_types::FeeTier::Normal,
        _ => shekyl_rpc_types::FeeTier::High,
    }
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
    result: T,
}

/// A JSON-RPC `error` member the daemon answered with: the method ran and
/// refused, with a code the caller is meant to branch on.
///
/// [`Rpc::json_rpc_call`] folds this into [`RpcError::InvalidNode`] with
/// the raw body as text, which is right for the calls that have no
/// refusal to read (a missing `result` *is* a protocol fault there). A
/// method whose refusals are part of its contract — `request_archival_shard`'s
/// open / unavailable / absent codes — reads them through
/// [`Rpc::json_rpc_call_or_refusal`] and gets this value instead.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct JsonRpcRefusal {
    /// The daemon's error code (`CORE_RPC_ERROR_CODE_*`).
    pub code: i64,
    /// The daemon's message. Daemon RPC messages are secret-free by
    /// contract; a wallet may show them, never parse them.
    pub message: String,
}

/// The full envelope, for the calls that read `error` as an answer.
#[derive(Debug, Deserialize)]
struct JsonRpcEnvelope<T> {
    result: Option<T>,
    error: Option<JsonRpcRefusal>,
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

// The identity verdict [`RpcError::IdentityMismatch`] and
// [`DaemonFault::Identity`] carry, with the types inside it, for the same
// reason: a consumer that names the verdict reaches it through this crate.
pub use shekyl_rpc_types::{DaemonNetwork, HashHex, IdentityAxis, IdentityMismatch};

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
/// Tor-based transport, or even a memory buffer an external service somehow routes.
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

    /// A JSON-RPC call whose `error` member is an answer, not a fault.
    ///
    /// `Ok(Ok(response))` is a `result`; `Ok(Err(refusal))` is the daemon's
    /// typed refusal, code and message intact; `Err(_)` is the transport or
    /// a body that is neither (no `result` and no `error`, or both). Use this
    /// for a method whose refusal codes the caller maps onto its own
    /// contract; [`Rpc::json_rpc_call`] is for the methods where any
    /// non-`result` reply is a protocol fault.
    fn json_rpc_call_or_refusal<Response: DeserializeOwned + Debug>(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> impl Send + Future<Output = Result<Result<Response, JsonRpcRefusal>, RpcError>> {
        async move {
            let mut req = json!({ "jsonrpc": "2.0", "id": 0, "method": method });
            if let Some(params) = params {
                req.as_object_mut()
                    .expect("accessing object as object failed?")
                    .insert("params".into(), params);
            }
            let envelope = self
                .rpc_call::<_, JsonRpcEnvelope<Response>>("json_rpc", Some(req))
                .await?;
            match (envelope.result, envelope.error) {
                (Some(result), None) => Ok(Ok(result)),
                (None, Some(refusal)) => Ok(Err(refusal)),
                (Some(_), Some(_)) => Err(RpcError::InvalidNode(
                    "JSON-RPC reply carried both result and error".to_string(),
                )),
                (None, None) => Err(RpcError::InvalidNode(
                    "JSON-RPC reply carried neither result nor error".to_string(),
                )),
            }
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

    /// Get the height of the Shekyl blockchain.
    ///
    /// The height is defined as the amount of blocks on the blockchain. For a blockchain with only
    /// its genesis block, the height will be 1. Typed [`ChainCount`] at this
    /// decode (`HEIGHT_SEMANTICS.md` C2); the method name is kept (C7).
    ///
    /// ```compile_fail
    /// // HEIGHT_SEMANTICS.md C9: `get_height` is a count, not `usize`.
    /// fn wants_usize_fut<F>(_: F)
    /// where
    ///     F: core::future::Future<Output = Result<usize, shekyl_rpc_client::RpcError>>,
    /// {
    /// }
    /// fn check<R: shekyl_rpc_client::Rpc>(rpc: &R) {
    ///     wants_usize_fut(rpc.get_height());
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// // HEIGHT_SEMANTICS.md C9: `get_height` is not an ordinal.
    /// fn wants_height_fut<F>(_: F)
    /// where
    ///     F: core::future::Future<
    ///         Output = Result<shekyl_types::BlockHeight, shekyl_rpc_client::RpcError>,
    ///     >,
    /// {
    /// }
    /// fn check<R: shekyl_rpc_client::Rpc>(rpc: &R) {
    ///     wants_height_fut(rpc.get_height());
    /// }
    /// ```
    fn get_height(&self) -> impl Send + Future<Output = Result<ChainCount, RpcError>> {
        async move {
            // The wire type is `shekyl-rpc-types`'s (RK-D1): one definition for
            // the daemon that serves it and the wallet that reads it.
            let reply = self
                .rpc_call::<Option<()>, shekyl_rpc_types::GetHeightResponse>("get_height", None)
                .await?;
            // A non-OK status is a refusal, whatever the other fields hold —
            // the same rule the daemon's own console applies to this reply.
            if !reply.status.is_ok() {
                return Err(RpcError::InvalidNode(format!(
                    "get_height refused: {}",
                    reply.status.0
                )));
            }
            if reply.height == 0 {
                return Err(RpcError::InvalidNode(
                    "node responded with 0 for the height".to_string(),
                ));
            }
            Ok(ChainCount::from_raw(reply.height))
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
            // The wire type is `shekyl-rpc-types`'s (RK-D1).
            let reply: shekyl_rpc_types::GetBlockHeaderByHeightResponse = self
                .json_rpc_call(
                    "get_block_header_by_height",
                    Some(json!({ "height": number })),
                )
                .await?;
            // **A non-OK status is a refusal, whatever the header holds.**
            // The C++ `CHECK_CORE_READY()` answered `status = BUSY` beside a
            // *default-constructed* header, and reading the hash straight
            // through would report 32 zero bytes for a syncing node.
            //
            // The daemon this ships with refuses with `CORE_BUSY`, which
            // arrives here as a JSON-RPC error. This guard is for every
            // *other* daemon: an older build, or one this wallet was merely
            // pointed at. Fixing the producer and trusting every peer to be
            // the fixed producer is not a fix. Pinned by
            // `tests/reply_status.rs`.
            if !reply.status.is_ok() {
                return Err(RpcError::InvalidNode(format!(
                    "get_block_header_by_height refused: {}",
                    reply.status.0
                )));
            }
            // No re-parse: the wire type already validated the hex on the
            // way in (RK-3's `HashHex`), so the edge is just naming the bytes.
            Ok(reply.block_header.hash.to_bytes())
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
            // **The shared wire type, not a local mirror.** This function
            // used to declare its own `FeeResponse` with a required scalar
            // `fee`, and RK-5b's removal of that field from the wire broke it
            // at runtime while everything compiled — the crate already
            // depends on `shekyl-rpc-types` precisely so "wallet and daemon
            // cannot skew", and a hand-rolled duplicate is how the skew got
            // in. Reading the shared type makes the next wire change a
            // compile error here.
            let res: shekyl_rpc_types::GetFeeEstimateResponse = self
                .json_rpc_call(
                    "get_fee_estimate",
                    Some(json!({ "grace_blocks": GRACE_BLOCKS_FOR_FEE_ESTIMATE })),
                )
                .await?;

            if !res.status.is_ok() {
                Err(RpcError::InvalidFee)?;
            }

            // The pre-2021-scaling fallback is gone with the field it read.
            // It multiplied the scalar by one of `[1, 5, 25, 1000]` when the
            // daemon sent no `fees` array — a Monero wallet2 path for a
            // daemon Shekyl has never had. `FeeTiers` is a fixed `[u64; 3]`,
            // so "no tiers" is unrepresentable rather than merely
            // unreachable (rule 60). It also carried the only unchecked
            // multiply in this function, on a daemon-supplied number.
            FeeRate::new(res.fees.get(fee_tier_for(priority)), res.quantization_mask)
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
    ///
    /// Built through the shared `.bin` command map (RK-4a) rather than
    /// assembled here: this used to hand-roll a `Section` and walk the reply
    /// for `status` and `o_indexes`, which is a second definition of a wire
    /// the daemon also defines. A missing `o_indexes` still reads as an
    /// empty list — epee drops an empty sequence — but that rule now lives
    /// in one place, pinned against epee's own bytes.
    fn get_o_indexes(
        &self,
        hash: [u8; 32],
    ) -> impl Send + Future<Output = Result<Vec<u64>, RpcError>> {
        async move {
            let request = shekyl_rpc_types::GetOIndexesRequest { txid: hash }
                .to_bin()
                .map_err(|e| RpcError::InternalError(e.to_string()))?;
            let buf = self.bin_call("get_o_indexes.bin", request).await?;
            let reply = shekyl_rpc_types::GetOIndexesResponse::from_bin(&buf)
                .map_err(|e| RpcError::InvalidNode(format!("invalid binary response: {e}")))?;
            if !reply.status.is_ok() {
                return Err(RpcError::InvalidNode(format!(
                    "get_o_indexes refused: {}",
                    reply.status.0
                )));
            }
            Ok(reply.o_indexes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        fee_tier_for, DaemonFault, DaemonNetwork, FeePriority, HashHex, IdentityMismatch, RpcError,
    };
    use shekyl_rpc_types::FeeTier;

    /// Each failure's remedy class, named once. The identity verdict rides
    /// through unchanged; nothing is classified by its message.
    #[test]
    fn every_failure_is_classified_by_its_remedy() {
        let wrong_network = IdentityMismatch::Network {
            ours: DaemonNetwork::Mainnet,
            theirs: DaemonNetwork::Testnet,
        };
        for (err, fault) in [
            (
                RpcError::ConnectionError("refused".into()),
                DaemonFault::Unreachable,
            ),
            (
                RpcError::IdentityMismatch(wrong_network),
                DaemonFault::Identity(wrong_network),
            ),
            (RpcError::InvalidNode("bad".into()), DaemonFault::Protocol),
            (
                RpcError::TransactionsNotFound(vec![[0; 32]]),
                DaemonFault::Protocol,
            ),
            (RpcError::PrunedTransaction, DaemonFault::Protocol),
            (RpcError::InvalidTransaction([0; 32]), DaemonFault::Protocol),
            (RpcError::InvalidFee, DaemonFault::FeeResponse),
            (
                RpcError::InternalError("encode".into()),
                DaemonFault::Internal,
            ),
            (RpcError::InvalidPriority, DaemonFault::Internal),
        ] {
            assert_eq!(err.fault(), fault, "{err:?}");
            assert_eq!(
                fault.is_retryable(),
                !matches!(fault, DaemonFault::Identity(_)),
                "only an identity refusal is certain to repeat: {err:?}"
            );
        }
    }

    /// The typed variant is the contract. Consumers that still recognise an
    /// identity refusal by its wording (`shekyl-gui-wallet`'s
    /// `engine_errors.rs`) rely on these stems, so they are pinned here
    /// until those consumers read the type.
    #[test]
    fn an_identity_refusal_keeps_its_axis_wording() {
        let digest = |b| HashHex::from_bytes([b; 32]);
        for (mismatch, stems) in [
            (
                IdentityMismatch::Wire {
                    ours: 0x0003_001d,
                    theirs: 0x0003_001c,
                },
                &["RPC contract mismatch:", "the daemon is the older one"][..],
            ),
            (
                IdentityMismatch::WireUnreadable { ours: 0x0003_001d },
                &["does not match the RPC contract", "cannot be named here"][..],
            ),
            (
                IdentityMismatch::Rules {
                    ours: digest(1),
                    theirs: digest(2),
                },
                &["consensus constants mismatch:"][..],
            ),
            (
                IdentityMismatch::Network {
                    ours: DaemonNetwork::Mainnet,
                    theirs: DaemonNetwork::Testnet,
                },
                &["network mismatch:", "the daemon runs testnet"][..],
            ),
            (
                IdentityMismatch::Genesis {
                    ours: digest(3),
                    theirs: digest(4),
                    network: DaemonNetwork::Mainnet,
                },
                &["genesis block mismatch:", "different chain"][..],
            ),
        ] {
            let message = RpcError::IdentityMismatch(mismatch).to_string();
            for stem in stems {
                assert!(message.contains(stem), "{stem:?} in {message}");
            }
        }
    }

    /// Every priority maps to the tier the deleted index arithmetic gave it.
    ///
    /// The old code computed `if p >= 4 { 3 } else { p.saturating_sub(1) }`
    /// and indexed a `Vec`. Naming the tiers removes the index, and this is
    /// what says the rename changed no answer: `0` and `1` share the lowest
    /// tier because `saturating_sub` floored them together, and every value
    /// at or above `4` — a `Custom` priority has no upper bound — takes the
    /// highest, which is why the out-of-range refusal went with the index
    /// rather than being kept as defence.
    #[test]
    fn every_priority_maps_to_the_tier_the_index_arithmetic_gave_it() {
        let custom = |priority| FeePriority::Custom { priority };
        assert_eq!(fee_tier_for(custom(0)), FeeTier::Low);
        assert_eq!(fee_tier_for(FeePriority::Unimportant), FeeTier::Low);
        assert_eq!(fee_tier_for(custom(1)), FeeTier::Low);
        assert_eq!(fee_tier_for(FeePriority::Normal), FeeTier::Normal);
        assert_eq!(fee_tier_for(custom(2)), FeeTier::Normal);
        assert_eq!(fee_tier_for(custom(3)), FeeTier::High);
        assert_eq!(fee_tier_for(FeePriority::Priority), FeeTier::High);
        assert_eq!(fee_tier_for(custom(4)), FeeTier::High);
        assert_eq!(fee_tier_for(custom(u32::MAX)), FeeTier::High);
    }

    /// Every named tier buys a different rate. A mapping that collapsed two
    /// of them would make the tier choice unobservable in every other test.
    #[test]
    fn each_named_tier_buys_a_distinct_rate() {
        let served = shekyl_rpc_types::FeeTiers([10, 20, 40]);
        let low = served.get(fee_tier_for(FeePriority::Unimportant));
        let normal = served.get(fee_tier_for(FeePriority::Normal));
        let high = served.get(fee_tier_for(FeePriority::Priority));
        assert!(
            low < normal && normal < high,
            "tiers must ascend and differ: {low}, {normal}, {high}"
        );
    }
}
