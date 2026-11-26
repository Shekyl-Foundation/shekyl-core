// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The shell's daemon client.
//!
//! One target (`RPC_CHANNEL.md` RT-15; RT-W10 step 5): "this computer",
//! reached as the enrollment words reach it (a service's console leg when one
//! runs here, otherwise the owner's leg), or a named address through one
//! [`SyncDaemon`]. Connected on the first request. The SOCKS proxy, the
//! down-hint and the timeout are this client's; the bytes are the shared
//! transports'.

use serde_json::Value;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use shekyl_rpc_client::{wire, RpcMethod};
use shekyl_rpc_grants::GrantSet;
use shekyl_rpc_transport::channel::ChannelFault;
use shekyl_rpc_transport::local::LocalFault;
use shekyl_rpc_transport::network_posture::{host_of, is_loopback_host};
use shekyl_rpc_transport::{DaemonTarget, JsonRpcError, PostFault, SyncDaemon, TransportFault};

use crate::node_leg::{LegError, NodeLeg};
use shekyl_rpc_types::kinds::{Count, NoParams};
use shekyl_rpc_types::wire::daemon::DaemonStatus;
use shekyl_rpc_types::wire::node::{MineStart, MineStatus, Threads};
use shekyl_rpc_types::{core_rpc_version_string, IdentityExpectation, IdentityMismatch, Network};

/// Errors from the daemon RPC client with differentiated failure modes.
#[derive(Clone, Debug)]
pub enum DaemonError {
    NotConfigured,
    ConnectionRefused {
        detail: String,
        /// Recovery copy naming the daemon invocation that would fix it
        /// (`shekyld --testnet` + port), filled by the client for loopback
        /// endpoints (CU-1; CLI_USABILITY.md §CU-5 F1). `None` for a remote
        /// daemon, where "start it" would mislead.
        hint: Option<String>,
    },
    SocksFailure(String),
    TlsFailure(String),
    MalformedResponse(String),
    /// The identity handshake refused this daemon. The line is
    /// [`identity_line`].
    Identity(String),
    /// A JSON-RPC refusal. The operator line is [`shekyl_rpc_types::errors::RpcError::report`].
    Refusal(shekyl_rpc_types::errors::RpcError),
    /// The daemon serves no method by this name: it is on another RPC
    /// version than this build.
    NoSuchMethod(String),
    /// Something other than this account's node answers at this computer's
    /// rendezvous (RT-15): a security failure, never retried. The text is
    /// the owner's leg's own.
    PeerCheck(String),
    /// This computer's node is a service. The text is the owner's leg's
    /// own, including the view listener to set. Not a refused connection,
    /// and not a hint to start another daemon.
    Service(String),
    Other(String),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured => write!(
                f,
                "Daemon not configured. Set daemon-endpoint to name the daemon endpoint."
            ),
            Self::ConnectionRefused { detail, hint } => {
                write!(
                    f,
                    "Daemon connection refused (is the daemon running?). Detail: {detail}"
                )?;
                if let Some(hint) = hint {
                    write!(f, "\n{hint}")?;
                }
                Ok(())
            }
            Self::SocksFailure(detail) => write!(
                f,
                "SOCKS/Tor proxy connection failed (check daemon-socks and Tor status). Detail: {detail}"
            ),
            Self::TlsFailure(detail) => write!(
                f,
                "TLS verification failed for daemon (the connection uses the system roots). Detail: {detail}"
            ),
            Self::MalformedResponse(detail) => {
                write!(f, "Daemon returned a malformed response: {detail}")
            }
            Self::Identity(line) | Self::PeerCheck(line) | Self::Service(line) => {
                write!(f, "{line}")
            }
            Self::Refusal(refusal) => write!(f, "{}", refusal.report()),
            Self::NoSuchMethod(method) => write!(
                f,
                "The daemon has no method {method}: it is on another RPC version than this \
                 build; align the two."
            ),
            Self::Other(detail) => write!(f, "Daemon client error: {detail}"),
        }
    }
}

impl std::error::Error for DaemonError {}

/// How long one daemon request waits. The views, mining, `tx show`, the
/// shard reads and the startup check share it.
const DAEMON_TIMEOUT: Duration = Duration::from_secs(30);

/// The shell's one daemon client. The connection is opened on the first
/// request, so a run that never asks the daemon does not dial it. A channel
/// session the node has closed is dropped: the next command opens another
/// and checks identity again. The command that met the close is not sent
/// again — its outcome is unknown.
pub struct DaemonClient {
    /// Where the words go: this computer, or a named address and its SOCKS
    /// proxy, so every request uses the same circuit.
    target: DaemonTarget,
    /// The target as copy names it: the URL, or "this computer".
    label: String,
    /// See [`DaemonError::ConnectionRefused`]: attached to every refused
    /// connection this client reports.
    down_hint: Option<String>,
    /// The network this shell is on. The handshake requires the daemon to
    /// report the same one.
    network: Network,
    connection: Mutex<Option<Arc<Connection>>>,
    /// The handshake, computed once and reused (RK-Q6) until the connection
    /// it was computed on is dropped. `version` does not consult it.
    identity: Mutex<Option<Result<(), DaemonError>>>,
}

/// Normalize a daemon address to the URL form the transports expect: a
/// scheme-less `host:port` is `http://host:port`; a URL is itself. The one
/// reading of `daemon-endpoint`, for the self-hosted server's scan
/// transport and the REPL's direct client alike.
#[must_use]
pub fn daemon_url(daemon_address: &str) -> String {
    shekyl_rpc_transport::daemon_address_url(daemon_address)
}

/// Whether `address` names a loopback host, in any form the CLI accepts
/// (`host:port`, `http://host:port`, `[::1]:port`).
///
/// This is the one loopback predicate: [`host_of`] + [`is_loopback_host`],
/// the same classification the startup disclosure uses. A substring match
/// on `127.0.0.1` would both miss `127.0.0.0/8` / mapped IPv6 and accept
/// `127.0.0.1.evil.com`. Loopback is the silent default, not a force — a
/// remote `daemon-endpoint` is a valid configuration
/// (CLI_USABILITY.md §CU-3 F4).
#[must_use]
pub fn is_loopback_endpoint(address: &str) -> bool {
    is_loopback_host(host_of(address))
}

/// The connection a client opened on its first request.
enum Connection {
    /// A named address.
    Address(SyncDaemon),
    /// This computer's node.
    ThisComputer(NodeLeg),
}

/// How "this computer" is named in copy that names the endpoint.
pub const THIS_COMPUTER: &str = "this computer";

impl DaemonClient {
    /// Build a new daemon client.
    ///
    /// - `target`: "this computer", or a named address (e.g.
    ///   `http://127.0.0.1:11029` or `https://remote:11029`) and its optional
    ///   SOCKS5 proxy, which the transport passes to `SyncDaemon`. An
    ///   `https://` daemon uses the system root store (RT-W12 removes that
    ///   arm).
    /// - `down_hint`: recovery copy attached to refused connections (the
    ///   caller knows whether the endpoint is this machine).
    /// - `network`: this shell's network. One client has one.
    pub fn new(
        target: DaemonTarget,
        down_hint: Option<String>,
        network: Network,
    ) -> Result<Self, DaemonError> {
        let label = match &target {
            DaemonTarget::HttpFixture { url, .. } if url.is_empty() => {
                return Err(DaemonError::NotConfigured)
            }
            DaemonTarget::HttpFixture { url, .. } => daemon_url(url),
            DaemonTarget::Channel { node, .. } => node.leg.to_string(),
            DaemonTarget::Owner(_) | DaemonTarget::ThisComputer { .. } => THIS_COMPUTER.to_owned(),
        };
        Ok(Self {
            target,
            label,
            down_hint,
            network,
            connection: Mutex::new(None),
            identity: Mutex::new(None),
        })
    }

    /// The network this client handshakes against.
    #[must_use]
    pub fn network(&self) -> Network {
        self.network
    }

    /// The shared connection, opened on the first call. No handshake.
    fn connect(&self) -> Result<Arc<Connection>, DaemonError> {
        if let Some(existing) = lock(&self.connection).clone() {
            return Ok(existing);
        }
        let opened = Arc::new(self.open()?);
        let mut slot = lock(&self.connection);
        if let Some(existing) = slot.clone() {
            return Ok(existing);
        }
        *slot = Some(Arc::clone(&opened));
        Ok(opened)
    }

    /// Dial the target. Not stored: [`Self::connect`] stores the one that
    /// won, and a closed channel session is removed rather than reused.
    fn open(&self) -> Result<Connection, DaemonError> {
        match &self.target {
            DaemonTarget::HttpFixture { url, proxy, .. } => Ok(Connection::Address(
                SyncDaemon::connect(daemon_url(url), proxy.clone(), DAEMON_TIMEOUT)
                    .map_err(|error| self.error_of_post(error))?,
            )),
            DaemonTarget::Channel { .. } => self
                .channel_connection(GrantSet::EMPTY)?
                .ok_or(DaemonError::NotConfigured),
            DaemonTarget::Owner(target) => {
                Ok(Connection::ThisComputer(NodeLeg::Owner(target.clone())))
            }
            DaemonTarget::ThisComputer { network, .. } => {
                Ok(Connection::ThisComputer(NodeLeg::Owner(
                    shekyl_rpc_transport::local::LocalTarget::this_computer(*network),
                )))
            }
        }
    }

    /// The node closed `dead`. Forget it, and the handshake taken on it, so
    /// the next command opens a new session and checks identity again.
    /// Another connection stored since is left alone.
    fn forget_closed(&self, dead: &Arc<Connection>) {
        let mut slot = lock(&self.connection);
        let mut identity = lock(&self.identity);
        forget_if_same(&mut slot, &mut identity, dead);
    }

    /// The handshake, once. A later request reuses the verdict.
    ///
    /// A connection failure is not cached: the daemon may be started
    /// between two commands. An identity refusal is cached, because asking
    /// again cannot succeed against the same daemon.
    fn ensure_identity(&self) -> Result<(), DaemonError> {
        if let Some(cached) = lock(&self.identity).clone() {
            return cached;
        }
        let verdict = match self.handshake() {
            Ok(()) => Ok(()),
            Err(error @ DaemonError::Identity(_)) => Err(error),
            Err(other) => return Err(other),
        };
        let mut slot = lock(&self.identity);
        if let Some(cached) = slot.clone() {
            return cached;
        }
        *slot = Some(verdict.clone());
        verdict
    }

    fn handshake(&self) -> Result<(), DaemonError> {
        let connection = self.connect()?;
        self.check_identity_on(&connection)
    }

    fn check_identity_on(&self, connection: &Arc<Connection>) -> Result<(), DaemonError> {
        let result = match self.read_version(connection) {
            Ok(result) => result,
            // A daemon of another RPC major has no `version` (RW-Q6): the
            // version difference itself, said as one.
            Err(DaemonError::MalformedResponse(detail) | DaemonError::NoSuchMethod(detail)) => {
                return Err(DaemonError::Identity(format!(
                    "{} (evidence: {detail})",
                    identity_line(&IdentityMismatch::unreadable(), self.url())
                )));
            }
            Err(other) => return Err(other),
        };
        IdentityExpectation::exact(self.network)
            .read(&result)
            .map(|_| ())
            .map_err(|refusal| {
                let message = identity_line(&refusal.mismatch, self.url());
                DaemonError::Identity(match refusal.evidence {
                    Some(evidence) => format!("{message} (evidence: {evidence})"),
                    None => message,
                })
            })
    }

    /// The `version` read's `result`, undecoded, with no identity check.
    /// The handshake and the `version` word are the two readers; a daemon
    /// the word is willing to describe is one the handshake would refuse.
    /// Undecoded because reading it is `IdentityExpectation`'s (RK-D25).
    fn read_version(&self, connection: &Arc<Connection>) -> Result<Value, DaemonError> {
        let name = <wire::Version as RpcMethod>::NAME;
        match &**connection {
            Connection::Address(rpc) => rpc
                .json_rpc(name, &NoParams)
                .map_err(|error| self.error_of_json_rpc(error)),
            Connection::ThisComputer(leg) => leg.json_rpc(name, &NoParams).map_err(|error| {
                self.note_closed(connection, &error);
                self.error_of_leg(error)
            }),
        }
    }

    /// Attach this client's recovery hint to a refused connection. Applied
    /// at the one seam every request passes through, so each caller's error
    /// display carries the copy without knowing about it.
    fn with_down_hint(&self, err: DaemonError) -> DaemonError {
        match err {
            DaemonError::ConnectionRefused { detail, hint: None } => {
                DaemonError::ConnectionRefused {
                    detail,
                    hint: self.down_hint.clone(),
                }
            }
            other => other,
        }
    }

    fn channel_error(fault: ChannelFault) -> DaemonError {
        let advice = match fault {
            ChannelFault::NotEnrolled { fingerprint } | ChannelFault::Revoked { fingerprint } => {
                shekyl_rpc_client::WalletChannelFault::NotEnrolled(fingerprint).to_string()
            }
            ChannelFault::NotRecognised { .. } => {
                shekyl_rpc_client::WalletChannelFault::NotRecognised.to_string()
            }
            ChannelFault::NotTheDaemon { .. } => {
                shekyl_rpc_client::WalletChannelFault::NotTheDaemon.to_string()
            }
            other => other.to_string(),
        };
        DaemonError::Other(advice)
    }

    fn channel_connection(&self, request: GrantSet) -> Result<Option<Connection>, DaemonError> {
        let target = self.target.channel_target().map_err(Self::channel_error)?;
        target
            .map(|target| {
                shekyl_rpc_transport::channel::ChannelDaemon::connect(&target, request)
                    .map(|daemon| Connection::ThisComputer(NodeLeg::Channel(daemon)))
                    .map_err(Self::channel_error)
            })
            .transpose()
    }

    fn command_channel<M: RpcMethod>(&self) -> Result<Option<Arc<Connection>>, DaemonError> {
        let request = match M::POLICY {
            shekyl_rpc_types::method::Policy::Grant(grant) => GrantSet::of(&[grant]),
            _ => GrantSet::EMPTY,
        };
        self.channel_connection(request)
            .map(|connection| connection.map(Arc::new))
    }

    /// Call method `M` after the handshake.
    pub(crate) fn call<M: RpcMethod>(&self, request: &M::Request) -> Result<M::Reply, DaemonError> {
        if let Some(connection) = self.command_channel::<M>()? {
            self.check_identity_on(&connection)?;
            return self.call_on::<M>(request, &connection);
        }
        self.ensure_identity()?;
        self.call_on::<M>(request, &self.connect()?)
    }

    /// Call method `M` without the handshake. The `version` word reads
    /// `daemon_status` through this: a daemon it is describing is one the
    /// handshake would refuse.
    pub(crate) fn call_unchecked<M: RpcMethod>(
        &self,
        request: &M::Request,
    ) -> Result<M::Reply, DaemonError> {
        let connection = match self.command_channel::<M>()? {
            Some(connection) => connection,
            None => self.connect()?,
        };
        self.call_on::<M>(request, &connection)
    }

    fn call_on<M: RpcMethod>(
        &self,
        request: &M::Request,
        connection: &Arc<Connection>,
    ) -> Result<M::Reply, DaemonError> {
        match &**connection {
            Connection::Address(rpc) => rpc
                .call::<M>(request)
                .map_err(|error| self.error_of_json_rpc(error)),
            Connection::ThisComputer(leg) => leg.call::<M>(request).map_err(|error| {
                self.note_closed(connection, &error);
                self.error_of_leg(error)
            }),
        }
    }

    /// The daemon's state (`daemon_status`). Used by `chain health` and the
    /// mining gates.
    ///
    /// The reply decodes strictly: a member that is absent means the
    /// contract moved, not a safe zero.
    pub fn daemon_status(&self) -> Result<DaemonStatus, DaemonError> {
        self.call::<wire::DaemonStatus>(&NoParams)
    }

    /// The `version` read's `result`, undecoded, with no identity check.
    ///
    /// Undecoded because reading it is `shekyl_rpc_types`' (`RK-D25`): the
    /// handshake hands it to [`IdentityExpectation::read`], and the `version`
    /// word to [`shekyl_rpc_types::daemon_rpc_version`].
    pub fn get_version_result(&self) -> Result<Value, DaemonError> {
        let connection = match self.command_channel::<wire::Version>()? {
            Some(connection) => connection,
            None => self.connect()?,
        };
        self.read_version(&connection)
    }

    /// Operator coverage list (`shard_coverage`); the daemon orders the rows.
    pub fn shard_coverage(&self) -> Result<wire::archival::Coverage, DaemonError> {
        self.call::<wire::ShardCoverage>(&NoParams)
    }

    /// The configured daemon URL, or [`THIS_COMPUTER`], for copy that names
    /// the endpoint (CLI_USABILITY.md §CU-5 F4).
    #[must_use]
    pub fn url(&self) -> &str {
        &self.label
    }

    /// The F1 recovery copy this client was built with (`None` for remote
    /// daemons). For surfaces that report daemon-unreachable through a path
    /// that never dials this client — `status` reads `daemon_height: null`
    /// off the wallet RPC — and still owe the "start shekyld" line.
    #[must_use]
    pub fn down_hint(&self) -> Option<&str> {
        self.down_hint.as_deref()
    }

    /// True when the configured endpoint is this machine: "this computer",
    /// or a loopback address.
    ///
    /// Mining control does **not** refuse non-loopback (F4 is a reminder):
    /// the silent default is this machine, and a named remote daemon is an
    /// advanced configuration the operator is allowed to keep. Classification
    /// uses [`is_loopback_endpoint`].
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        match &self.target {
            DaemonTarget::Owner(_) | DaemonTarget::ThisComputer { .. } => true,
            DaemonTarget::Channel { node, .. } => is_loopback_endpoint(&node.leg.to_string()),
            DaemonTarget::HttpFixture { url, .. } => is_loopback_endpoint(url),
        }
    }

    /// Start the daemon's miner (`mine_start`). It mines to the daemon's
    /// `mine-address`; the request is `{ threads }` (N2).
    pub fn start_mining(&self, threads: u64) -> Result<(), DaemonError> {
        if threads == 0 {
            return Err(DaemonError::Other(
                "thread count is not a positive count".into(),
            ));
        }
        self.call::<wire::MineStart>(&MineStart {
            threads: Threads::Count(Count(threads)),
        })
        .map(|_| ())
    }

    /// Stop mining on the daemon (`mine_stop`, CU-3).
    pub fn stop_mining(&self) -> Result<(), DaemonError> {
        self.call::<wire::MineStop>(&NoParams).map(|_| ())
    }

    /// The daemon's mining state (`mine_status`, CU-3).
    pub fn mining_status(&self) -> Result<MineStatus, DaemonError> {
        self.call::<wire::MineStatus>(&NoParams)
    }
}

/// The shell's wording of an identity refusal, one sentence per axis.
///
/// The wallet words the same verdict its own way. The axes are compared
/// once, in [`IdentityExpectation::read`]. `url` is the daemon this shell
/// reached.
pub(crate) fn identity_line(mismatch: &IdentityMismatch, url: &str) -> String {
    match *mismatch {
        IdentityMismatch::Wire { ours, theirs } => {
            let older = if theirs < ours {
                "daemon"
            } else {
                "this build"
            };
            format!(
                "refusing to render: RPC contract mismatch. This build is {}, the daemon at \
                 {url} is {} — the {older} is the older one; update it.",
                core_rpc_version_string(ours),
                core_rpc_version_string(theirs),
            )
        }
        IdentityMismatch::WireUnreadable { ours } => format!(
            "refusing to render: the daemon at {url}'s `version` does not match the RPC \
             contract this build was compiled against, so the two are on different RPC \
             versions. This build is {}. The reply could not be read, so the daemon's \
             version cannot be named here; align the two builds.",
            core_rpc_version_string(ours),
        ),
        IdentityMismatch::Rules { ours, theirs } => format!(
            "refusing to render: consensus-constant mismatch. This build's digest is {ours}, \
             the daemon at {url} reports {theirs}. The RPC contract matches, so neither side \
             is a stale release — one tree's config/ differs from the other, which is a \
             different rule set rather than a version skew. Compare \
             config/consensus_constants.json and config/economics_params.json between the two \
             builds.",
        ),
        IdentityMismatch::Network { ours, theirs } => format!(
            "refusing to render: network mismatch. This CLI is on {ours}, the daemon at {url} \
             reports {theirs}."
        ),
        IdentityMismatch::Genesis {
            ours,
            theirs,
            network,
        } => format!(
            "refusing to render: genesis mismatch. The daemon at {url} starts at {theirs}, \
             this build's {network} genesis is {ours}. Whatever else agrees, that is a \
             different chain."
        ),
    }
}

impl DaemonClient {
    fn error_of_json_rpc(&self, error: JsonRpcError) -> DaemonError {
        reply_error(error, |fault| self.error_of_post(fault))
    }

    /// A closed channel session is this connection's end. The call that
    /// met it is returned as that error and is not sent again.
    fn note_closed(&self, connection: &Arc<Connection>, error: &LegError) {
        if matches!(
            error,
            LegError::Channel(JsonRpcError::Transport(ChannelFault::Closed))
        ) {
            self.forget_closed(connection);
        }
    }

    /// A failure on this computer's node's leg: the owner's leg's failed
    /// peer check, and a service there, are their own errors. Any other
    /// owner's-leg fault is the node not running or not answering, with
    /// this client's hint. The console leg's faults are the channel's words.
    fn error_of_leg(&self, error: LegError) -> DaemonError {
        match error {
            LegError::Owner(error) => reply_error(error, |fault| self.owner_fault(fault)),
            LegError::Channel(error) => reply_error(error, Self::channel_error),
        }
    }

    /// The owner's leg's fault, in the shell's errors. A service is not a
    /// refused connection: the start-the-daemon hint would name the wrong
    /// remedy.
    fn owner_fault(&self, fault: LocalFault) -> DaemonError {
        match fault {
            LocalFault::PeerCheck(_) => DaemonError::PeerCheck(fault.to_string()),
            LocalFault::Service { .. } => DaemonError::Service(fault.to_string()),
            other => self.with_down_hint(DaemonError::ConnectionRefused {
                detail: other.to_string(),
                hint: None,
            }),
        }
    }

    fn error_of_post(&self, fault: PostFault) -> DaemonError {
        let error = match fault {
            PostFault::Connection(fault) => from_transport(fault),
            PostFault::Protocol(error) => DaemonError::Other(error.to_string()),
        };
        self.with_down_hint(error)
    }
}

/// A JSON-RPC failure on any leg, its transport fault read by `transport`.
fn reply_error<F>(error: JsonRpcError<F>, transport: impl FnOnce(F) -> DaemonError) -> DaemonError {
    match error {
        JsonRpcError::Transport(fault) => transport(fault),
        JsonRpcError::Refusal(refusal) => DaemonError::Refusal(refusal),
        JsonRpcError::NoSuchMethod(method) => DaemonError::NoSuchMethod(method),
        JsonRpcError::Malformed(detail) => DaemonError::MalformedResponse(detail),
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Forget `dead` when it is the stored connection, and the handshake taken
/// on it. A different stored connection is left.
fn forget_if_same(
    slot: &mut Option<Arc<Connection>>,
    identity: &mut Option<Result<(), DaemonError>>,
    dead: &Arc<Connection>,
) {
    if slot.as_ref().is_some_and(|live| Arc::ptr_eq(live, dead)) {
        *slot = None;
        *identity = None;
    }
}

fn from_transport(fault: TransportFault) -> DaemonError {
    match fault {
        TransportFault::Proxy(detail) => DaemonError::SocksFailure(detail),
        TransportFault::Tls(detail) => DaemonError::TlsFailure(detail),
        TransportFault::Unreachable(detail) => {
            DaemonError::ConnectionRefused { detail, hint: None }
        }
        TransportFault::Runtime(detail) => DaemonError::Other(detail),
    }
}

#[cfg(test)]
mod tests {
    use super::{from_transport, is_loopback_endpoint, DaemonError};

    #[test]
    fn loopback_classification_uses_the_canonical_host_check() {
        for addr in [
            "127.0.0.1:11029",
            "http://127.0.0.1:11029",
            "http://localhost:11029",
            "http://[::1]:11029",
            "[::1]:11029",
            "127.0.0.2:11029",
            "http://[::ffff:127.0.0.1]:11029",
        ] {
            assert!(is_loopback_endpoint(addr), "expected loopback: {addr}");
        }
        for addr in [
            "node.example.com:11029",
            "http://127.0.0.1.evil.com:11029",
            "10.0.0.5:11029",
            "http://192.168.1.10:11029",
        ] {
            assert!(
                !is_loopback_endpoint(addr),
                "expected non-loopback (warn, do not refuse): {addr}"
            );
        }
    }

    /// The mining gates read `synchronized` and the grant list from this
    /// reply. One missing either does not decode: a missing `grant` must
    /// not read as "every grant".
    #[test]
    fn daemon_status_refuses_a_missing_gate_field() {
        for gate in ["grant", "synchronized", "height"] {
            let mut reply = crate::console::daemon_status_reply();
            reply.as_object_mut().expect("object").remove(gate);
            assert!(
                serde_json::from_value::<shekyl_rpc_types::wire::daemon::DaemonStatus>(reply)
                    .is_err(),
                "a reply without `{gate}` must not decode"
            );
        }
        let status: shekyl_rpc_types::wire::daemon::DaemonStatus =
            serde_json::from_value(crate::console::daemon_status_reply())
                .expect("a complete daemon_status");
        assert!(status.synchronized);
    }

    /// A proxy fault, a TLS-connector fault, and an unreachable daemon stay
    /// three errors. The variant is the classification; the sentence is not.
    #[test]
    fn a_named_transport_fault_keeps_its_name() {
        use shekyl_rpc_transport::TransportFault;
        let proxy = from_transport(TransportFault::Proxy(
            "invalid daemon-socks for the daemon transport: missing port".into(),
        ));
        assert!(matches!(proxy, DaemonError::SocksFailure(_)), "{proxy}");
        let socks = from_transport(TransportFault::Proxy("socks: refused".into()));
        assert!(matches!(socks, DaemonError::SocksFailure(_)), "{socks}");
        let tls = from_transport(TransportFault::Tls(
            "TLS connector unavailable: no roots".into(),
        ));
        assert!(matches!(tls, DaemonError::TlsFailure(_)), "{tls}");
        let refused = from_transport(TransportFault::Unreachable("connection refused".into()));
        assert!(
            matches!(refused, DaemonError::ConnectionRefused { .. }),
            "{refused}"
        );
    }

    /// A service at this computer is its own error. The start-the-daemon
    /// hint stays on "not running". Red edit: fold `LocalFault::Service`
    /// into `ConnectionRefused`.
    #[test]
    fn a_service_is_not_a_daemon_to_start() {
        use shekyl_rpc_transport::local::LocalFault;
        let client = super::DaemonClient::new(
            shekyl_rpc_transport::DaemonTarget::ThisComputer {
                network: super::Network::Testnet,
                account: Default::default(),
            },
            Some("Start the testnet daemon with: shekyld --network testnet".into()),
            super::Network::Testnet,
        )
        .expect("this computer");
        let service = client.owner_fault(LocalFault::Service {
            node: "testnet".into(),
            view: Some("127.0.0.1:12030".parse().unwrap()),
        });
        let DaemonError::Service(line) = service else {
            panic!("a service is not a refused connection: {service:?}")
        };
        assert!(line.contains("127.0.0.1:12030"), "{line}");
        assert!(!line.contains("Start the testnet daemon"), "{line}");
        let down = client.owner_fault(LocalFault::NotRunning {
            node: "testnet".into(),
        });
        assert!(
            matches!(down, DaemonError::ConnectionRefused { hint: Some(_), .. }),
            "{down:?}"
        );
    }

    /// Forgetting a closed session forgets that session and its handshake,
    /// and not a session stored since. Red edit: clear the slot on any
    /// connection, and a newer session is dropped with the dead one.
    #[test]
    fn a_closed_session_is_forgotten_and_a_later_one_is_not() {
        use std::path::Path;

        use shekyl_rpc_rendezvous::Instance;
        use shekyl_rpc_transport::local::LocalTarget;

        let leg = || {
            std::sync::Arc::new(super::Connection::ThisComputer(
                crate::node_leg::NodeLeg::Owner(LocalTarget::test_override(
                    super::Network::Regtest,
                    &Instance::Default,
                    Some(Path::new("dir")),
                    None,
                )),
            ))
        };
        let dead = leg();
        let later = leg();
        let mut slot = Some(std::sync::Arc::clone(&dead));
        let mut identity = Some(Ok(()));
        super::forget_if_same(&mut slot, &mut identity, &later);
        assert!(slot.is_some() && identity.is_some());
        super::forget_if_same(&mut slot, &mut identity, &dead);
        assert!(slot.is_none() && identity.is_none());
    }
}
