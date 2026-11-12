// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The shell's daemon client.
//!
//! One [`SyncDaemon`](shekyl_rpc_transport::SyncDaemon), connected on the
//! first request. The SOCKS proxy, the loopback down-hint and the timeout
//! are this client's; the bytes are the shared transport's.

use serde_json::Value;
use std::fmt;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use shekyl_rpc_client::{wire, RpcMethod};
use shekyl_rpc_transport::network_posture::{host_of, is_loopback_host};
use shekyl_rpc_transport::{JsonRpcError, PostFault, SyncDaemon, TransportFault};
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
    Other(String),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured => write!(
                f,
                "Daemon not configured. Use --daemon-address to set the daemon endpoint."
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
                "SOCKS/Tor proxy connection failed (check --proxy and Tor status). Detail: {detail}"
            ),
            Self::TlsFailure(detail) => write!(
                f,
                "TLS verification failed for daemon (the connection uses the system roots). Detail: {detail}"
            ),
            Self::MalformedResponse(detail) => {
                write!(f, "Daemon returned a malformed response: {detail}")
            }
            Self::Identity(line) => write!(f, "{line}"),
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
/// request, so a run that never asks the daemon does not dial it.
pub struct DaemonClient {
    url: String,
    /// The SOCKS proxy this client was built with, so every request uses
    /// the same circuit.
    proxy: Option<String>,
    /// See [`DaemonError::ConnectionRefused`]: attached to every refused
    /// connection this client reports.
    down_hint: Option<String>,
    /// The network this shell is on. The handshake requires the daemon to
    /// report the same one.
    network: Network,
    rpc: OnceLock<Arc<SyncDaemon>>,
    /// The handshake, computed once and reused (RK-Q6). `version` does not
    /// consult it.
    identity: OnceLock<Result<(), DaemonError>>,
}

/// Normalize a daemon address to the URL form the transports expect: a
/// scheme-less `host:port` is `http://host:port`; a URL is itself. The one
/// reading of `--daemon-address`, for the self-hosted server's scan
/// transport and the REPL's direct client alike.
#[must_use]
pub fn daemon_url(daemon_address: &str) -> String {
    if daemon_address.contains("://") {
        daemon_address.to_owned()
    } else {
        format!("http://{daemon_address}")
    }
}

/// Whether `address` names a loopback host, in any form the CLI accepts
/// (`host:port`, `http://host:port`, `[::1]:port`).
///
/// This is the one loopback predicate: [`host_of`] + [`is_loopback_host`],
/// the same classification the startup disclosure uses. A substring match
/// on `127.0.0.1` would both miss `127.0.0.0/8` / mapped IPv6 and accept
/// `127.0.0.1.evil.com`. Loopback is the silent default, not a force — a
/// remote `--daemon-address` is a valid configuration
/// (CLI_USABILITY.md §CU-3 F4).
#[must_use]
pub fn is_loopback_endpoint(address: &str) -> bool {
    is_loopback_host(host_of(address))
}

impl DaemonClient {
    /// Build a new daemon client.
    ///
    /// - `daemon_address`: e.g. `"http://127.0.0.1:11029"` or `"https://remote:11029"`.
    /// - `proxy`: optional SOCKS5 proxy address, e.g. `"socks5://127.0.0.1:9050"`.
    ///   The transport passes it to `SyncDaemon`. An `https://` daemon uses
    ///   the system root store (RT-W12 removes that arm).
    /// - `down_hint`: recovery copy attached to refused connections (the
    ///   caller knows whether the endpoint is loopback).
    /// - `network`: this shell's network. One client has one.
    pub fn new(
        daemon_address: &str,
        proxy: Option<&str>,
        down_hint: Option<String>,
        network: Network,
    ) -> Result<Self, DaemonError> {
        if daemon_address.is_empty() {
            return Err(DaemonError::NotConfigured);
        }

        Ok(Self {
            url: daemon_url(daemon_address),
            proxy: proxy.map(str::to_owned),
            down_hint,
            network,
            rpc: OnceLock::new(),
            identity: OnceLock::new(),
        })
    }

    /// The network this client handshakes against.
    #[must_use]
    pub fn network(&self) -> Network {
        self.network
    }

    /// The shared connection, opened on the first call. No handshake.
    fn connect(&self) -> Result<Arc<SyncDaemon>, DaemonError> {
        if let Some(existing) = self.rpc.get() {
            return Ok(Arc::clone(existing));
        }
        let rpc = Arc::new(
            SyncDaemon::connect(self.url.clone(), self.proxy.clone(), DAEMON_TIMEOUT)
                .map_err(|error| self.error_of_post(error))?,
        );
        // A concurrent first request may have stored one. Either client
        // speaks to the same daemon.
        match self.rpc.set(Arc::clone(&rpc)) {
            Ok(()) => Ok(rpc),
            Err(_) => Ok(Arc::clone(
                self.rpc.get().expect("another call stored the client"),
            )),
        }
    }

    /// The handshake, once. A later request reuses the verdict.
    ///
    /// A connection failure is not cached: the daemon may be started
    /// between two commands. An identity refusal is cached, because asking
    /// again cannot succeed against the same daemon.
    fn ensure_identity(&self) -> Result<(), DaemonError> {
        if let Some(cached) = self.identity.get() {
            return cached.clone();
        }
        let verdict = match self.handshake() {
            Ok(()) => Ok(()),
            Err(error @ DaemonError::Identity(_)) => Err(error),
            Err(other) => return Err(other),
        };
        match self.identity.set(verdict.clone()) {
            Ok(()) => verdict,
            Err(_) => self.identity.get().expect("the verdict was stored").clone(),
        }
    }

    fn handshake(&self) -> Result<(), DaemonError> {
        let rpc = self.connect()?;
        let result = match Self::read_version(&rpc) {
            Ok(result) => result,
            // A daemon of another RPC major has no `version` (RW-Q6): the
            // version difference itself, said as one.
            Err(JsonRpcError::Malformed(detail) | JsonRpcError::NoSuchMethod(detail)) => {
                return Err(DaemonError::Identity(format!(
                    "{} (evidence: {detail})",
                    identity_line(&IdentityMismatch::unreadable(), self.url())
                )));
            }
            Err(other) => return Err(self.error_of_json_rpc(other)),
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
    fn read_version(rpc: &SyncDaemon) -> Result<Value, JsonRpcError> {
        rpc.json_rpc(<wire::Version as RpcMethod>::NAME, &NoParams)
    }

    /// The SOCKS proxy, when the client was built with one.
    #[must_use]
    pub fn proxy(&self) -> Option<&str> {
        self.proxy.as_deref()
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

    /// Call method `M` after the handshake.
    pub(crate) fn call<M: RpcMethod>(&self, request: &M::Request) -> Result<M::Reply, DaemonError> {
        self.ensure_identity()?;
        self.call_unchecked::<M>(request)
    }

    /// Call method `M` without the handshake. The `version` word reads
    /// `daemon_status` through this: a daemon it is describing is one the
    /// handshake would refuse.
    pub(crate) fn call_unchecked<M: RpcMethod>(
        &self,
        request: &M::Request,
    ) -> Result<M::Reply, DaemonError> {
        self.connect()?
            .call::<M>(request)
            .map_err(|error| self.error_of_json_rpc(error))
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
        let rpc = self.connect()?;
        Self::read_version(&rpc).map_err(|error| self.error_of_json_rpc(error))
    }

    /// Operator coverage list (`shard_coverage`); the daemon orders the rows.
    pub fn shard_coverage(&self) -> Result<wire::archival::Coverage, DaemonError> {
        self.call::<wire::ShardCoverage>(&NoParams)
    }

    /// The configured daemon URL, for copy that names the endpoint
    /// (CLI_USABILITY.md §CU-5 F4).
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The F1 recovery copy this client was built with (`None` for remote
    /// daemons). For surfaces that report daemon-unreachable through a path
    /// that never dials this client — `status` reads `daemon_height: null`
    /// off the wallet RPC — and still owe the "start shekyld" line.
    #[must_use]
    pub fn down_hint(&self) -> Option<&str> {
        self.down_hint.as_deref()
    }

    /// True when the configured endpoint is a loopback address.
    ///
    /// Mining control does **not** refuse non-loopback (F4 is a reminder):
    /// the silent default is this machine, and a named remote daemon is an
    /// advanced configuration the operator is allowed to keep. Classification
    /// uses [`is_loopback_endpoint`].
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        is_loopback_endpoint(&self.url)
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
        match error {
            JsonRpcError::Transport(fault) => self.error_of_post(fault),
            JsonRpcError::Refusal(refusal) => DaemonError::Refusal(refusal),
            JsonRpcError::NoSuchMethod(method) => DaemonError::NoSuchMethod(method),
            JsonRpcError::Malformed(detail) => DaemonError::MalformedResponse(detail),
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
            "invalid --proxy for the daemon transport: missing port".into(),
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
}
