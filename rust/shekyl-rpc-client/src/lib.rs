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
    string::{String, ToString},
    vec::Vec,
};

use zeroize::Zeroize;

use serde_json::{json, Value};

use shekyl_rpc_types::core_rpc_version_string;
use shekyl_types::{BlockHash, ChainCount};

pub mod tx_fee;

/// The operator command that enrolls `fingerprint` on its node.
///
/// One spelling: the wallet wire, the channel's own sentence, and a
/// revocation all name this command.
#[must_use]
pub fn enrollment_command(fingerprint: &[u8; 32]) -> String {
    format!(
        "shekyl-cli rpc client add {} wallet",
        hex::encode(fingerprint)
    )
}

/// What the operator is told when a call exceeds the bound it was opened under.
///
/// Distinct from a handshake timeout and from a connection the node closed.
/// The request is not sent again. A submission may already have been received.
pub const CALL_BUDGET_EXCEEDED: &str = "The call exceeded its time limit. The node may still be \
    working. Check its status before repeating a submission.";

/// A wallet-visible channel failure, safe to carry across engine boundaries.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq, Hash)]
pub enum WalletChannelFault {
    /// This client key needs enrollment on the wallet’s node.
    #[error("Enroll this wallet on your node with: {}", enrollment_command(.0))]
    NotEnrolled([u8; 32]),
    /// The daemon proof does not match daemon-bundle-file. Check the endpoint and obtain the bundle from your node.
    #[error("The daemon proof does not match daemon-bundle-file. Check the endpoint and obtain the bundle from your node.")]
    NotTheDaemon,
    /// The node closed before sending its proof. Check daemon-bundle-file, the network and the channel version against your node.
    #[error("The node closed before sending its proof. Check daemon-bundle-file, the network and the channel version against your node.")]
    NotRecognised,
    /// The channel endpoint did not answer. Check the node, daemon-endpoint and daemon-socks.
    #[error(
        "The channel endpoint did not answer. Check the node, daemon-endpoint and daemon-socks."
    )]
    Unreachable,
    /// The channel handshake timed out. Check the connection to your node.
    #[error("The channel handshake timed out. Check the connection to your node.")]
    TimedOut,
    /// The node is busy. Try again shortly.
    #[error("The node is busy. Try again shortly.")]
    Busy,
    /// All this wallet's channel connections are busy. Wait for an outstanding call to finish.
    #[error(
        "All this wallet's channel connections are busy. Wait for an outstanding call to finish."
    )]
    PoolFull,
    /// This account has reached the node's channel session limit. Close an unused client session.
    #[error("This account has reached the node's channel session limit. Close an unused client session.")]
    SessionCap,
    /// The node closed the connection during the call. Check its status before repeating a submission.
    #[error("The node closed the connection during the call. Check its status before repeating a submission.")]
    Closed,
    /// The node revoked this client's enrollment. Enroll it again with the command.
    #[error(
        "The node revoked this client's enrollment. Enroll it again with: {}",
        enrollment_command(.0)
    )]
    Revoked([u8; 32]),
    /// The call exceeded the bound it was opened under. The request was not sent again.
    #[error("{CALL_BUDGET_EXCEEDED}")]
    Budget,
    /// The wallet could not open the channel. Check its key and daemon bundle files and the local log.
    #[error("The wallet could not open the channel. Check its key and daemon bundle files and the local log.")]
    Local,
}

impl WalletChannelFault {
    /// Whether the same configuration is refused on every attempt.
    #[must_use]
    pub const fn terminal(self) -> bool {
        matches!(
            self,
            Self::NotEnrolled(_)
                | Self::Revoked(_)
                | Self::NotTheDaemon
                | Self::NotRecognised
                | Self::Local
        )
    }
}

/// An error from the RPC.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum RpcError {
    /// The authenticated channel failed. The sentence is the fault. The string
    /// is the leg or the local cause, for a log, and is empty when the
    /// sentence already says everything.
    #[error("{0}")]
    Channel(WalletChannelFault, String),
    /// An internal error.
    #[error("internal error ({0})")]
    InternalError(String),
    /// A connection error with the node.
    #[error("connection error ({0})")]
    ConnectionError(String),
    /// The node is invalid per the expected protocol.
    #[error("invalid node ({0})")]
    InvalidNode(String),
    /// Requested transactions are not in the daemon's chain, and its pool
    /// cannot be read until it restarts (a `null` slot in `tx_list`, IG-Q73):
    /// whether they exist has no answer from this daemon. Not "not found".
    #[error("transactions unavailable: not in the daemon's chain, and its pool is retired")]
    TransactionsUnavailable(Vec<[u8; 32]>),
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
    /// The daemon refused the call (`RPC_WIRE.md` RW-Q3): its class and its
    /// typed diagnostic. A caller branches on the class and the dotted
    /// code, never on the message.
    #[error("the daemon refused: {}", .0.report())]
    Refused(Refusal),
    /// The daemon serves no such method: a client and daemon of different
    /// RPC versions, or a method the daemon was built without.
    #[error("the daemon has no method {0}")]
    NoSuchMethod(&'static str),
    /// Something other than this account's node answers at "this
    /// computer"'s rendezvous (`RPC_CHANNEL.md` RT-15): another account's
    /// socket, a pipe that is not this user's, a file that is not a
    /// rendezvous record. A security failure: never retried, never routed
    /// around. The text is this side's description of what it found.
    #[error(
        "something other than your Shekyl node is answering at its local address; not \
         connecting ({0})"
    )]
    PeerCheck(String),
    /// "This computer"'s node runs as a service (RT-16). A wallet reaches it
    /// on the enrolled channel. `Some` is the view listener the record names,
    /// `None` a service that published no view listener. Nothing was dialled.
    #[error("{}", service_refusal(*.0))]
    Service(Option<core::net::SocketAddr>),
}

/// What a wallet says when "this computer"'s node is a service (Rick,
/// 2026-11-17): the one wording, which every layer that reports it uses.
#[must_use]
pub fn service_refusal(view: Option<core::net::SocketAddr>) -> String {
    let channel = "The node on this computer runs as a service. Leave the daemon endpoint unset \
         to use its channel, and enroll this account if the node asks.";
    match view {
        Some(_) => channel.to_owned(),
        None => format!(
            "{channel} If it has not published a channel, set rpc-listen to a loopback address \
             on the node."
        ),
    }
}

/// A daemon's refusal: its class and its typed diagnostic (RW-Q3).
pub use shekyl_rpc_types::errors::{Diagnostic, ErrorClass, RpcError as Refusal};

/// What a daemon RPC failure means for whoever has to act on it.
///
/// Classified once, where the failure is raised ([`RpcError::fault`]), so
/// every layer above reads the remedy from this value rather than from a
/// message. Fixed-size and `Copy`: it carries no text the daemon supplied,
/// so it can cross boundaries that must not carry any (the refresh
/// producer's error, `STAGE_1_PR_4_REFRESH_ENGINE.md` §5.4.7 R6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaemonFault {
    /// The wallet's authenticated connection to its node.
    Channel(WalletChannelFault),
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
    /// The daemon refused the call as outside this connection's grant. The
    /// same call with the same key repeats the refusal.
    NotPermitted,
    /// Something other than this account's node answers at "this
    /// computer"'s rendezvous: a security failure (RT-15). Never retried.
    PeerCheck,
    /// "This computer"'s node is a service, which a wallet names by its view
    /// listener until RT-W12 ([`RpcError::Service`]). Retrying cannot
    /// succeed until the wallet's setting changes.
    Service(Option<core::net::SocketAddr>),
}

impl core::fmt::Display for DaemonFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Channel(fault) => core::fmt::Display::fmt(fault, f),
            Self::Unreachable => f.write_str("the daemon did not answer"),
            Self::Identity(mismatch) => {
                write!(f, "the daemon was refused on its {}", mismatch.axis())
            }
            Self::Protocol => f.write_str("the daemon's reply broke the RPC contract"),
            Self::FeeResponse => f.write_str("the daemon's fee estimate was unusable"),
            Self::Internal => f.write_str("the request failed on this side of the connection"),
            Self::NotPermitted => {
                f.write_str("the daemon refused the call as outside this connection's grant")
            }
            Self::PeerCheck => {
                f.write_str("something other than this account's node answers at its rendezvous")
            }
            Self::Service(_) => f.write_str("this computer's node runs as a service"),
        }
    }
}

impl DaemonFault {
    /// Whether retrying against the same daemon can succeed. An identity
    /// refusal is cached by the client and repeats on every request.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        if let Self::Channel(fault) = self {
            return !fault.terminal();
        }
        !matches!(
            self,
            Self::Identity(_) | Self::NotPermitted | Self::PeerCheck | Self::Service(_)
        )
    }

    /// The target itself refused: a failed peer check, or a service at
    /// "this computer". The same target answers the same way, so a caller
    /// keeps the fault and does not dial again. Narrower than
    /// [`Self::is_retryable`]: an identity refusal and a grant refusal are
    /// also not retried, and they are not this. A channel fault that can
    /// clear on retry is not this; it still keeps its sentence
    /// ([`Self::has_own_remedy`]).
    #[must_use]
    pub const fn is_target_refusal(self) -> bool {
        if let Self::Channel(fault) = self {
            return fault.terminal();
        }
        matches!(self, Self::PeerCheck | Self::Service(_))
    }

    /// The operator's remedy is this fault's own sentence.
    ///
    /// Every channel fault is this, including one [`Self::is_retryable`]
    /// says may clear: busy, closed, and over budget are channel facts, and
    /// folding them into "the daemon did not answer" names the wrong action.
    /// A peer check and a service at this computer are this, and they are
    /// not retried.
    #[must_use]
    pub const fn has_own_remedy(self) -> bool {
        matches!(self, Self::Channel(_) | Self::PeerCheck | Self::Service(_))
    }
}

impl RpcError {
    /// The leg or local cause carried beside a channel sentence. Empty for
    /// every other failure, whose sentence already includes what a log needs.
    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            Self::Channel(_, detail) => detail,
            _ => "",
        }
    }

    /// The sentence a log records. A channel fault keeps its leg or local
    /// cause beside the sentence; every other failure's sentence already
    /// includes what the log needs.
    #[must_use]
    pub fn log_line(&self) -> String {
        let place = self.detail();
        if place.is_empty() {
            self.to_string()
        } else {
            format!("{self} ({place})")
        }
    }

    /// What this failure means for the remedy. Exhaustive: a new variant
    /// does not compile until its remedy is named.
    #[must_use]
    pub const fn fault(&self) -> DaemonFault {
        match self {
            // A lookup the daemon could not make is one it did not answer:
            // retry once it has restarted, or ask another daemon.
            Self::ConnectionError(_) | Self::TransactionsUnavailable(_) => DaemonFault::Unreachable,
            Self::IdentityMismatch(mismatch) => DaemonFault::Identity(*mismatch),
            Self::InvalidNode(_) | Self::PrunedTransaction | Self::InvalidTransaction(_) => {
                DaemonFault::Protocol
            }
            Self::InvalidFee => DaemonFault::FeeResponse,
            Self::InternalError(_) | Self::InvalidPriority => DaemonFault::Internal,
            Self::NoSuchMethod(_) => DaemonFault::Protocol,
            Self::Channel(fault, _) => DaemonFault::Channel(*fault),
            Self::PeerCheck(_) => DaemonFault::PeerCheck,
            Self::Service(view) => DaemonFault::Service(*view),
            Self::Refused(refusal) => match refusal.class {
                // Asking again later, or another daemon, may succeed.
                ErrorClass::NotReady | ErrorClass::OverResourceBound => DaemonFault::Unreachable,
                ErrorClass::OutsideTheGrant => DaemonFault::NotPermitted,
                // This side sent a request the method could not read.
                ErrorClass::BadParams => DaemonFault::Internal,
                ErrorClass::RefusedByMethod | ErrorClass::StoreFault | ErrorClass::Internal => {
                    DaemonFault::Protocol
                }
            },
        }
    }
}

/// This wallet's wording of an identity refusal, one sentence per axis.
///
/// The shell words the same verdict its own way
/// (`shekyl-cli`'s `identity_line`); the axes themselves are compared once,
/// in [`shekyl_rpc_types::IdentityExpectation::read`].
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
            "this daemon's version read does not match the RPC contract this wallet \
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

/// A fee rate: atomic units per weight unit.
///
/// A fee from a rate is `weight × per_weight` rounded up to the fee lattice
/// ([`shekyl_economics::FEE_QUANTIZATION_MASK`], the daemon's admission
/// lattice); the arithmetic is [`tx_fee::fee_from_weight`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct FeeRate {
    /// The fee per-weight of the transaction.
    per_weight: u64,
}

impl FeeRate {
    /// Construct a fee rate whose non-zero invariant the caller's own type
    /// already carries.
    ///
    /// Total, so a caller holding the proof — a `Custom` rate that arrived
    /// as [`NonZeroU64`] — gets no unreachable error arm to misclassify.
    /// [`Self::new`] is the fallible edge, for the bare `u64` that comes
    /// off the daemon wire.
    #[must_use]
    pub const fn from_nonzero(per_weight: NonZeroU64) -> FeeRate {
        FeeRate {
            per_weight: per_weight.get(),
        }
    }

    /// Construct a new fee rate, rejecting a zero rate.
    pub fn new(per_weight: u64) -> Result<FeeRate, RpcError> {
        match NonZeroU64::new(per_weight) {
            Some(per_weight) => Ok(Self::from_nonzero(per_weight)),
            None => Err(RpcError::InvalidFee),
        }
    }

    /// Atomic units charged per weight unit, before lattice rounding.
    #[must_use]
    pub fn per_weight(&self) -> u64 {
        self.per_weight
    }

    /// The fee for `weight`: [`tx_fee::fee_from_weight`], which fails
    /// closed at `u64::MAX` on overflow rather than panicking.
    #[must_use]
    pub fn calculate_fee_from_weight(&self, weight: usize) -> u64 {
        tx_fee::fee_from_weight(self, weight)
    }
}

// The identity verdict [`RpcError::IdentityMismatch`] and
// [`DaemonFault::Identity`] carry, with the types inside it: a consumer that
// names the verdict reaches it through this crate.
pub use shekyl_rpc_types::{HashHex, IdentityAxis, IdentityMismatch, Network};
// The method table and its types: a caller names a method by its type
// (`client.call::<wire::ChainHeight>(…)`, RW-Q7).
pub use shekyl_rpc_types::method::RpcMethod;
pub use shekyl_rpc_types::wire;
// The submission's verdict, defined once in `shekyl-rpc-types`
// (`DAEMON_SUBMIT_VERDICT.md` §2.3's single-definition rule).
pub use shekyl_rpc_types::wire::tx::{Publication, Rejection, Verdict};

use shekyl_rpc_types::kinds::{Bytes, Count, Height};

/// The route a call is posted on:
/// [`JSON_RPC_PATH`](shekyl_rpc_types::endpoint::JSON_RPC_PATH) relative to the
/// transport's base URL. A transport appends a route as `{url}/{route}`
/// ([`Rpc::post`]), so the path's own leading slash would put `//json_rpc`
/// on the wire, which no router matches.
#[must_use]
pub const fn json_rpc_route() -> &'static str {
    shekyl_rpc_types::endpoint::JSON_RPC_ROUTE
}

/// An RPC connection to a Shekyl daemon.
///
/// Abstract over the transport, so a caller chooses its HTTP library, a
/// Tor-routed transport, or a memory buffer. The first-party
/// `shekyl-rpc-transport` crate implements it over hyper.
///
/// Every call is JSON-RPC 2.0 on `/json_rpc` (`RPC_WIRE.md` RW-Q2). A method
/// is named by its type ([`RpcMethod`]); no method name is a string here.
pub trait Rpc: Sync + Clone {
    /// POST `body` to `route` and return the response body.
    ///
    /// `route` is relative to the transport's base URL, with no leading
    /// slash ([`json_rpc_route`]); the transport appends it as
    /// `{url}/{route}`. The implementor is left to handle anything such as
    /// authentication.
    fn post(
        &self,
        route: &str,
        body: Vec<u8>,
    ) -> impl Send + Future<Output = Result<Vec<u8>, RpcError>>;

    /// Call method `M`, and read a refusal as an answer.
    ///
    /// `Ok(Ok(reply))` is the method's reply; `Ok(Err(refusal))` is the
    /// daemon's typed refusal, class and diagnostic intact; `Err(_)` is the
    /// transport, a method the daemon does not serve, or a body that is
    /// neither a reply nor a refusal this build reads.
    fn call_or_refusal<M: RpcMethod>(
        &self,
        request: M::Request,
    ) -> impl Send + Future<Output = Result<Result<M::Reply, Refusal>, RpcError>>
    where
        M::Request: Send,
    {
        async move {
            let params = serde_json::to_value(&request)
                .map_err(|e| RpcError::InternalError(format!("{} params: {e}", M::NAME)))?;
            let reply_shape = <M::Reply as shekyl_rpc_types::schema::Schema>::shape();
            // The switches this request turned on: the reply carries the
            // fields they select, and no field a switch left off (RW-Q4).
            let on = shekyl_rpc_types::schema::switches_on(&params, &reply_shape);
            let body = serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": 0,
                "method": M::NAME,
                "params": params,
            }))
            .map_err(|e| RpcError::InternalError(format!("{} params: {e}", M::NAME)))?;
            let reply = self.post(json_rpc_route(), body).await?;
            let unreadable = |why: String| {
                RpcError::InvalidNode(format!(
                    "{} reply is not this build's ({why}): {}",
                    M::NAME,
                    String::from_utf8_lossy(&reply)
                ))
            };
            // A JSON-RPC 2.0 reply carries exactly one of `result` and
            // `error`. Read as a map, because a `result` of `null` is an
            // answer (`ban_show` for a host not banned), not its absence.
            let mut envelope: serde_json::Map<String, Value> =
                serde_json::from_slice(&reply).map_err(|e| unreadable(e.to_string()))?;
            match (envelope.remove("result"), envelope.remove("error")) {
                (Some(result), None) => {
                    shekyl_rpc_types::schema::conforms_presence(&result, &reply_shape, &on)
                        .map_err(&unreadable)?;
                    serde_json::from_value::<M::Reply>(result)
                        .map(Ok)
                        .map_err(|e| unreadable(e.to_string()))
                }
                (None, Some(error)) => {
                    if shekyl_rpc_types::errors::is_method_not_found(&error) {
                        return Err(RpcError::NoSuchMethod(M::NAME));
                    }
                    shekyl_rpc_types::errors::read_error_object(&error)
                        .map(Err)
                        .ok_or_else(|| {
                            RpcError::InvalidNode(format!(
                                "{} refusal is not one this build reads: {error}",
                                M::NAME
                            ))
                        })
                }
                _ => Err(RpcError::InvalidNode(format!(
                    "{} reply carries neither one result nor one error",
                    M::NAME
                ))),
            }
        }
    }

    /// Call method `M`. A refusal is [`RpcError::Refused`].
    fn call<M: RpcMethod>(
        &self,
        request: M::Request,
    ) -> impl Send + Future<Output = Result<M::Reply, RpcError>>
    where
        M::Request: Send,
    {
        async move {
            self.call_or_refusal::<M>(request)
                .await?
                .map_err(RpcError::Refused)
        }
    }

    /// The chain's block count: the tip's height plus one.
    ///
    /// The wire carries the tip's height, an ordinal (IG-Q45); this is the
    /// count a caller sizes a scan by, computed here, once.
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
            let tip = self
                .call::<wire::ChainHeight>(shekyl_rpc_types::kinds::NoParams)
                .await?;
            let count = tip.height.0.checked_add(1).ok_or_else(|| {
                RpcError::InvalidNode("chain_height reports the last possible height".to_string())
            })?;
            Ok(ChainCount::from_raw(count))
        }
    }

    /// The hash of the block at `number` (`0` for the genesis block).
    fn get_block_hash(
        &self,
        number: usize,
    ) -> impl Send + Future<Output = Result<BlockHash, RpcError>> {
        async move {
            let height = u64::try_from(number)
                .map_err(|_| RpcError::InternalError("a height wider than u64".to_string()))?;
            let header = self
                .call::<wire::BlockHeaderShow>(wire::block::HeaderSelect(
                    wire::block::BlockSelect {
                        select: wire::shared::Selector::Height(Height(height)),
                        pow: false,
                        prune: None,
                    },
                ))
                .await?;
            Ok(BlockHash::from_bytes(header.hash.to_bytes()))
        }
    }

    /// Offer a transaction to the daemon (`tx_submit`), returning its atomic
    /// [`Verdict`] (`docs/design/DAEMON_SUBMIT_VERDICT.md` §2).
    ///
    /// `tx_blob` is the serialized transaction. A daemon that parses it and
    /// refuses it answers `Ok(Rejected { cause })`: the cause drives the
    /// caller's disposition (§2.5). The [`Err`] arm is the absence of a
    /// verdict (Two Generals): a transport fault, a refusal of the call
    /// itself, or a reply this build cannot read.
    ///
    /// # Version skew (§2.3, pinned by `shekyl-rpc-types`)
    ///
    /// - An unknown cause reads as [`Rejection::Unrecognized`], the
    ///   fail-safe release.
    /// - An unknown `verdict` fails to read and lands in the [`Err`] arm.
    fn publish_transaction(
        &self,
        tx_blob: &[u8],
    ) -> impl Send + Future<Output = Result<Verdict, RpcError>> {
        let body = wire::tx::TxBody {
            body: Bytes(tx_blob.to_vec()),
        };
        async move { self.call::<wire::TxSubmit>(body).await }
    }

    /// Generate `block_count` blocks (an armed lever). The daemon pays its
    /// configured `mine-address`; `address` is not on the wire (N2).
    ///
    /// Returns the new blocks' hashes and the chain's block count after
    /// them: the new tip's height plus one, as [`Self::get_height`].
    fn generate_blocks(
        &self,
        address: &str,
        block_count: usize,
    ) -> impl Send + Future<Output = Result<(Vec<[u8; 32]>, ChainCount), RpcError>> {
        let _ = address;
        async move {
            let count = u64::try_from(block_count)
                .map_err(|_| RpcError::InternalError("a count wider than u64".to_string()))?;
            let generated = self
                .call::<wire::DevBlockGenerate>(wire::block::GenerateCount {
                    count: Count(count),
                })
                .await?;
            let blocks = generated.hash.iter().map(|hash| hash.to_bytes()).collect();
            let chain = generated.height.0.checked_add(1).ok_or_else(|| {
                RpcError::InvalidNode(
                    "dev_block_generate reports the last possible height".to_string(),
                )
            })?;
            Ok((blocks, ChainCount::from_raw(chain)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DaemonFault, HashHex, IdentityMismatch, Network, RpcError};

    /// Each failure's remedy class, named once. The identity verdict rides
    /// through unchanged; nothing is classified by its message.
    #[test]
    fn every_failure_is_classified_by_its_remedy() {
        let wrong_network = IdentityMismatch::Network {
            ours: Network::Mainnet,
            theirs: Network::Testnet,
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
                RpcError::TransactionsUnavailable(vec![[0; 32]]),
                DaemonFault::Unreachable,
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
                    ours: 0x0004_0000,
                    theirs: 0x0003_0046,
                },
                &["RPC contract mismatch:", "the daemon is the older one"][..],
            ),
            (
                IdentityMismatch::WireUnreadable { ours: 0x0004_0000 },
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
                    ours: Network::Mainnet,
                    theirs: Network::Testnet,
                },
                &["network mismatch:", "the daemon runs testnet"][..],
            ),
            (
                IdentityMismatch::Genesis {
                    ours: digest(3),
                    theirs: digest(4),
                    network: Network::Mainnet,
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

    /// A refusal is classified by its class, never by its message.
    #[test]
    fn a_refusal_is_classified_by_its_class() {
        use super::{Diagnostic, ErrorClass, Refusal};
        let refused =
            |class| RpcError::Refused(Refusal::new(class, Diagnostic::new("chain.x", "y")));
        assert_eq!(
            refused(ErrorClass::NotReady).fault(),
            DaemonFault::Unreachable
        );
        assert_eq!(
            refused(ErrorClass::OverResourceBound).fault(),
            DaemonFault::Unreachable
        );
        assert_eq!(
            refused(ErrorClass::OutsideTheGrant).fault(),
            DaemonFault::NotPermitted
        );
        assert!(!DaemonFault::NotPermitted.is_retryable());
        assert_eq!(
            refused(ErrorClass::BadParams).fault(),
            DaemonFault::Internal
        );
        assert_eq!(
            refused(ErrorClass::RefusedByMethod).fault(),
            DaemonFault::Protocol
        );
    }
}
