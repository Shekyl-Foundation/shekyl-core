// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `PRpc` — the per-`P` RPC-over-Tor transport (2d-2 SP-T2, DQ-T2.2).
//!
//! Implements the [`Rpc`] trait by dialing `P`'s daemon over `P`'s **own** Tor
//! circuit, via `shekyl-p-transport`'s [`PTorClient`]. Two §2b build invariants
//! (`ARCHIVAL_BOND_2D2_SP_T2_FETCH.md`) shape it:
//!
//! - **One agent construction site.** `PRpc` does **not** build a `ureq::Agent` —
//!   it holds a [`PTorClient`] and calls that crate's `blocking_post`, so the
//!   single hardened constructor (`PTorClient::for_persona`: `socks5h`,
//!   `resolve_target(false)`, bounded timeouts, the `tor-socks` compile guard) is
//!   the *only* agent-construction path. engine-core does not even depend on
//!   `ureq` — the safe construction is the only construction reachable from here.
//! - **The blocking-pool axis.** `ureq` is synchronous, so `post` bridges via
//!   `spawn_blocking`. A blocking task is not a cancellation point: on shutdown an
//!   in-flight fetch *drains* rather than cancels, bounded by `for_persona`'s
//!   per-`P` timeouts. Per-`P` fetch concurrency is bounded at the scan-loop
//!   wiring (a later slice) so N personas cannot starve tokio's shared blocking
//!   pool.
//!
//! `PRpc` is the `remote`-posture transport; [`LocalNodeRpc`] is the `local`
//! posture (direct loopback, no circuit — its doc carries the choice-site
//! rationale). The posture→impl **selection** is a later slice (DQ-T2.3);
//! this module holds both transports so the [`PersonaIsolatedTransport`] pin
//! and every production implementor sit in one reviewable place.

use std::future::Future;
use std::time::Duration;

use shekyl_p_transport::{PTorClient, PTransportError, RequestErrorKind};
use shekyl_rpc_client::{Rpc, RpcError};
use shekyl_rpc_transport::HttpRpc;

/// Marker for [`Rpc`] transports whose **network identity is the persona's
/// own** — the §7.4 transport pin (`EMISSION_CLAIM_BUILDER.md`): a persona's
/// claim-side traffic must never ride the principal's daemon session, or the
/// query (which carries `p_id`) links `P` to its principal at the daemon —
/// the origin-edge deanonymization the P↔principal firewall exists to
/// prevent.
///
/// The pin is **structural**: `orchestrate_emission_claim` bounds its
/// transport parameter on this trait, so handing it the principal's
/// `DaemonClient` is a compile error, not a review obligation or a
/// caller-discipline comment. Production implementors:
///
/// - [`PRpc`] — the `remote` posture: `P`'s own Tor circuit, one circuit per
///   persona (`for_persona`'s isolation invariants).
/// - [`LocalNodeRpc`] — the `local` posture: direct loopback against the
///   wallet's **own** node (run-your-own-node is the privacy default,
///   SP-T2). Principal and persona share a trusted daemon there, so the
///   shared network identity is not an adversary-observable edge — the
///   deliberate choice-site rationale lives on that type. The posture→impl
///   **selection** remains the DQ-T2.3 slice.
///
/// Test transports may implement it freely; the pin is against production
/// misuse, not test plumbing.
pub(crate) trait PersonaIsolatedTransport: Rpc {}

impl PersonaIsolatedTransport for PRpc {}

/// A per-`P` [`Rpc`] that routes every call over `P`'s Tor circuit.
///
/// `Clone` is a per-`P` clone: it shares the same `Arc`-backed `ureq::Agent`
/// (same connection pool, same circuit), so cloning a `PRpc` for the same
/// persona keeps its traffic on one circuit — the correct isolation semantics.
//
// `allow(dead_code)`: transient — the non-test consumer is the posture selector
// (DQ-T2.3) at the scan-loop wiring, a later slice. The proving test ships with
// the enabler (it is not deferred).
#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct PRpc {
    client: PTorClient,
    /// The daemon base URL (scheme + host + port, no trailing slash), e.g.
    /// `http://<onion>.onion:18081`. The posture selector supplies it.
    ///
    /// **No HTTP authentication is performed.** The remote posture's access
    /// control is the onion address itself (an unguessable capability), so a
    /// daemon behind `--rpc-login` (HTTP digest auth) is out of scope — unlike the
    /// reference `HttpRpc`, which parses `user:pass@` for digest auth. If
    /// an authenticated remote is ever needed, it is a change at the choice site
    /// (the `base_url` carrying credentials) + here, recorded there.
    base_url: String,
}

#[allow(dead_code)]
impl PRpc {
    /// Wrap `P`'s circuit-bound transport as an [`Rpc`] against `base_url`.
    pub(crate) fn new(client: PTorClient, base_url: String) -> Self {
        Self { client, base_url }
    }
}

impl Rpc for PRpc {
    fn post(
        &self,
        route: &str,
        body: Vec<u8>,
    ) -> impl Send + Future<Output = Result<Vec<u8>, RpcError>> {
        // Route → Content-Type via the shared protocol invariant
        // (`shekyl_rpc_client::content_type_for`), so `PRpc` and `HttpRpc`
        // can't drift on which routes are EPEE-binary. Sent for parity + daemon
        // forward-compat, **not** a validation the daemon enforces (its handlers
        // read the body via `String`/`Bytes` extractors that ignore `Content-Type`).
        let content_type = shekyl_rpc_client::content_type_for(route);
        let url = format!("{}/{}", self.base_url, route);
        let client = self.client.clone();
        async move {
            // spawn_blocking: `ureq` is synchronous. The closure owns everything
            // (an `Arc`-cheap client clone, the url, the body), so it is
            // `Send + 'static` with no shared state.
            tokio::task::spawn_blocking(move || client.blocking_post(&url, content_type, &body))
                .await
                .map_err(|e| RpcError::InternalError(format!("per-P fetch task failed: {e}")))?
                .map_err(classify)
        }
    }
}

/// The `local`-posture persona transport: direct **loopback** to the wallet's
/// own trusted node, no Tor circuit.
///
/// # Why this satisfies the §7.4 pin (the choice-site rationale)
///
/// [`PersonaIsolatedTransport`] exists to keep a persona's claim-side traffic
/// off any network identity an adversary can correlate with the principal's.
/// In the `local` posture the wallet talks to its **own** daemon
/// (run-your-own-node, SP-T2's privacy default): principal and persona both
/// dial `127.0.0.1`, the daemon is inside the user's trust boundary, and no
/// packet carrying `p_id` crosses an adversary-observable edge. Sharing the
/// loopback "network identity" is therefore not the origin-edge linkage the
/// pin defends against — it is the one posture where sharing is sound, and
/// this type is the named, documented place where that call is made.
///
/// The soundness is **structural, not caller discipline**: [`Self::new`]
/// refuses any non-loopback URL, so a `LocalNodeRpc` pointed at a remote
/// daemon (where the shared-identity argument collapses) is a construction
/// error, not a silent misuse. Trusted-but-non-loopback nodes (e.g. a LAN
/// node) are rejected today; reopening that is a change **here** plus a
/// threat-model note on the marker trait, triggered by a production caller
/// that needs it — not by convenience.
///
/// `DaemonClient` deliberately does **not** implement the marker: the
/// principal's daemon session object stays a compile error at
/// `orchestrate_emission_claim` even though, in this posture, it happens to
/// dial the same host. The pin binds the *type that made the posture
/// argument*, not any transport that coincidentally resolves to loopback.
//
// `allow(dead_code)`: transient — consumed by the emission regtest e2e and,
// when the DQ-T2.3 posture selector lands, by the scan-loop wiring.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct LocalNodeRpc {
    inner: HttpRpc,
}

impl PersonaIsolatedTransport for LocalNodeRpc {}

#[allow(dead_code)]
impl LocalNodeRpc {
    /// Open a loopback transport against `url`, refusing non-loopback hosts.
    ///
    /// `url` must be `http://` + a loopback host (`127.0.0.1`, `localhost`,
    /// or `[::1]`) + port. `https` is pointless on loopback and rejected to
    /// keep the accepted-input surface minimal; credentials (`user:pass@`)
    /// are rejected because the underlying digest-auth path would issue a
    /// pre-flight request from inside a constructor documented as
    /// side-effect-bounded.
    pub(crate) async fn new(url: String, request_timeout: Duration) -> Result<Self, RpcError> {
        let Some(host_port) = url.strip_prefix("http://") else {
            return Err(RpcError::ConnectionError(
                "local-posture transport requires an http:// loopback URL".to_string(),
            ));
        };
        // The authority ends at the first of `/`, `?`, or `#` (RFC 3986) —
        // terminating on `/` alone would fold a path-less query or fragment
        // into the authority and misread its content as host or credentials.
        let authority = host_port
            .split_once(['/', '?', '#'])
            .map_or(host_port, |(hp, _)| hp);
        // Refuse credentials before any host parse so a rejected URL's
        // error message can never render a password. Scoped to the
        // AUTHORITY: an '@' in the path, query, or fragment is ordinary URL
        // content (e.g. `?tag=user@host`), and refusing on it would assert
        // credentials that are not there.
        if authority.contains('@') {
            return Err(RpcError::ConnectionError(
                "local-posture transport refuses in-URL credentials".to_string(),
            ));
        }
        let host = if let Some(bracketed) = authority.strip_prefix('[') {
            bracketed.split_once(']').map_or("", |(h, _)| h)
        } else {
            authority.rsplit_once(':').map_or(authority, |(h, _)| h)
        };
        // The loopback pin proper: the one loopback predicate the tree has
        // (`localhost`, and any literal the listen side classifies as
        // loopback, IPv4-mapped spellings included) — a literal allowlist
        // would wrongly refuse legitimate loopback forms like `127.0.0.2`.
        if !shekyl_rpc_transport::network_posture::is_loopback_host(host) {
            return Err(RpcError::ConnectionError(format!(
                "local-posture transport refuses non-loopback host {host:?} \
                 (the shared-network-identity argument only holds on the \
                 wallet's own node)"
            )));
        }
        let inner = HttpRpc::with_custom_timeout(url, request_timeout).await?;
        Ok(Self { inner })
    }
}

impl Rpc for LocalNodeRpc {
    fn post(
        &self,
        route: &str,
        body: Vec<u8>,
    ) -> impl Send + Future<Output = Result<Vec<u8>, RpcError>> {
        self.inner.post(route, body)
    }
}

/// Map a per-`P` transport failure to an [`RpcError`], distinguishing **transient**
/// (retry-worthwhile) from **permanent** (terminal bad-node) causes so the scan
/// loop surfaces a real bad-node/protocol problem instead of retrying it as an
/// endless "connecting…". Never renders the SOCKS username — every
/// [`RequestErrorKind`] `Display` is username-free (invariant (a)).
// `dead_code` until the wiring slice consumes `PRpc` (whose `post` calls this).
// Owned `PTransportError` by design — this is a `.map_err(classify)` target, which
// hands ownership of the error (the by-ref form would force `|e| classify(&e)`),
// so `needless_pass_by_value` is a false positive here.
#[allow(dead_code)]
#[allow(clippy::needless_pass_by_value)]
fn classify(e: PTransportError) -> RpcError {
    match e {
        // Connect / proxy / timeout — transient, worth a retry.
        PTransportError::Request(RequestErrorKind::Transport) => {
            RpcError::ConnectionError("per-P transport failure".to_string())
        }
        // 5xx — transient server-side, retry-eligible.
        PTransportError::Request(RequestErrorKind::Http(status))
            if (500..600).contains(&status) =>
        {
            RpcError::ConnectionError(format!("daemon HTTP {status}"))
        }
        // 4xx, or a 3xx surfaced by `max_redirects(0)` — permanent for this
        // request (a retry re-fetches the identical failure): a bad node/route.
        PTransportError::Request(kind @ RequestErrorKind::Http(_)) => {
            RpcError::InvalidNode(format!("daemon {kind}"))
        }
        // Body over `MAX_RESPONSE_BODY_SIZE` or unreadable — permanent.
        PTransportError::Request(RequestErrorKind::Read) => {
            RpcError::InvalidNode("daemon response too large or unreadable".to_string())
        }
        // `blocking_post` never returns `Proxy` (that is a `for_persona`-time
        // construction error); handled defensively for exhaustiveness.
        PTransportError::Proxy { .. } => {
            RpcError::InternalError("per-P proxy misconfiguration".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_p_transport::TorSocksEndpoint;
    use shekyl_types::PCanonicalId;

    #[tokio::test(flavor = "multi_thread")]
    async fn post_through_a_dead_proxy_is_a_username_free_connection_error() {
        // No Tor: dial through a closed SOCKS port (`:1`), which loopback refuses
        // immediately, so the spawn_blocking bridge + error mapping are exercised
        // fast (no timeout). The failure surfaces as a retry-eligible
        // ConnectionError, and its rendering must not leak the SOCKS username.
        let client = PTorClient::for_persona(
            &PCanonicalId::from_bytes([7u8; 32]),
            &TorSocksEndpoint::loopback(1),
        )
        .expect("proxy config is well-formed");
        let username = client.username().as_str().to_owned();
        let rpc = PRpc::new(client, "http://127.0.0.1:18081".to_string());

        let err = rpc
            .post("json_rpc", b"{}".to_vec())
            .await
            .expect_err("a dead SOCKS proxy must fail the call");
        assert!(
            matches!(err, RpcError::ConnectionError(_)),
            "expected ConnectionError, got {err:?}"
        );
        assert!(
            !format!("{err}").contains(&username),
            "invariant (a): an RPC error must never render the SOCKS username"
        );
    }

    /// The local-posture constructor is the structural loopback pin: every
    /// accepted form is genuinely loopback, every refusal is loud, and a
    /// refused URL's error never echoes credentials.
    #[tokio::test(flavor = "multi_thread")]
    async fn local_node_rpc_accepts_only_loopback() {
        for ok in [
            "http://127.0.0.1:48081",
            "http://localhost:48081",
            "http://[::1]:48081",
            "http://127.0.0.1:48081/json_rpc",
            // Loopback is the /8, not one literal address.
            "http://127.0.0.2:48081",
        ] {
            LocalNodeRpc::new(ok.to_string(), Duration::from_secs(1))
                .await
                .unwrap_or_else(|e| panic!("loopback URL {ok} must construct: {e}"));
        }

        // '@' beyond the authority is URL content, not credentials — the
        // credential refusal is scoped to the authority. These forms now
        // refuse at the transport's base-URL shape check (a query/fragment
        // daemon URL was never a joinable base), and the pinned property is
        // that the refusal IS that shape check: never the credential
        // refusal, and never an echo of the '@' content.
        for not_credentials in [
            "http://127.0.0.1:48081/json_rpc?tag=user@host",
            "http://127.0.0.1:48081?tag=user@host",
            "http://localhost:48081#frag@ment",
        ] {
            let err = LocalNodeRpc::new(not_credentials.to_string(), Duration::from_secs(1))
                .await
                .expect_err("a query/fragment URL is not a joinable base");
            let rendered = format!("{err}");
            assert!(
                rendered.contains("query or fragment"),
                "{not_credentials}: expected the base-URL shape refusal, got {err:?}"
            );
            assert!(
                !rendered.contains("credentials"),
                "{not_credentials}: the '@' must not be misread as credentials: {err:?}"
            );
        }

        for (bad, why) in [
            ("http://192.168.1.10:48081", "LAN host"),
            ("http://example.com:48081", "remote host"),
            ("https://127.0.0.1:48081", "https scheme"),
            ("http://[::1:48081", "malformed IPv6 bracket"),
            ("http://127.0.0.1.evil.test:48081", "loopback-prefixed host"),
        ] {
            let err = LocalNodeRpc::new(bad.to_string(), Duration::from_secs(1))
                .await
                .expect_err(why);
            assert!(
                matches!(err, RpcError::ConnectionError(_)),
                "{why}: {err:?}"
            );
        }

        let err = LocalNodeRpc::new(
            "http://user:hunter2@127.0.0.1:48081".to_string(),
            Duration::from_secs(1),
        )
        .await
        .expect_err("in-URL credentials");
        assert!(
            !format!("{err}").contains("hunter2"),
            "a refused URL's error must never render the password"
        );
    }

    /// Construction against an unreachable loopback port succeeds (no
    /// connect attempt in the constructor) and the delegated `post` surfaces
    /// the failure — exercising the [`Rpc`] impl without a live daemon.
    #[tokio::test(flavor = "multi_thread")]
    async fn local_node_rpc_post_delegates_to_inner_transport() {
        let rpc = LocalNodeRpc::new("http://127.0.0.1:1".to_string(), Duration::from_secs(1))
            .await
            .expect("constructor performs no connect attempt");
        rpc.post("json_rpc", b"{}".to_vec())
            .await
            .expect_err("port 1 refuses; the delegated post must surface it");
    }
}
