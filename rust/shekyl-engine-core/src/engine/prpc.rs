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
//! `PRpc` is the `remote`-posture transport only; the `local` posture keeps a
//! direct-localhost `Rpc` (no circuit). The posture→impl selection is a later
//! slice (DQ-T2.3); this module is just the transport.

use std::future::Future;

use shekyl_p_transport::{PTorClient, PTransportError, RequestErrorKind};
use shekyl_rpc_client::{Rpc, RpcError};

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
    /// reference `SimpleRequestRpc`, which parses `user:pass@` for digest auth. If
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
        // Content-type routing mirrors `SimpleRequestRpc`: the EPEE `.bin` routes
        // are `application/octet-stream`, everything else `application/json`. This
        // is sent for parity + daemon forward-compat, **not** a validation the
        // daemon enforces (its handlers read the body via `String`/`Bytes`
        // extractors that ignore `Content-Type`).
        let content_type = if route.ends_with(".bin") {
            "application/octet-stream"
        } else {
            "application/json"
        };
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
}
