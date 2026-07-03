// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-`P` archival-firewall network transport (2d-2 SP-T1, type half).
//!
//! The keystone the gate-6 firewall's network axis rests on: each archival
//! persona `P` reaches its daemon over its **own** Tor circuit, structurally
//! disjoint from the principal's and from every other persona's. The isolation
//! key is a per-`P` SOCKS username (Tor's `IsolateSOCKSAuth`), and this crate
//! makes "`P` rides the principal's circuit" *unrepresentable* rather than merely
//! discouraged — see `ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md` §13 (CX-1) / §15 (SP-T1).
//!
//! Three invariants live on the [`SocksUsername`] derivation, **by construction**
//! (not `debug_assert!`, which is compiled out in release and cannot see a
//! cross-call injectivity break):
//!
//! - **(a) local-only** — the username is host↔Tor, never on the wire; it is not
//!   logged ([`SocksUsername`]'s `Debug` redacts).
//! - **(b) non-empty ⇒ principal-disjoint** — [`SocksUsername`] is a fixed-width
//!   64-byte value, so it cannot be empty; the principal's circuit is the
//!   *empty-username* (no-auth) one, so a persona username cannot collide into it
//!   **while the principal stays no-auth**. The durable guarantee is the deferred
//!   principal-side namespace obligation (FOLLOWUPS): when the principal gains non-empty
//!   usernames they must be namespace-disjoint from this derivation's range.
//! - **(c) per-persona distinct (collision-resistant, not literally injective)** — the
//!   username is a collision-resistant hash of the **full** `p_canonical_id` (no
//!   truncation/modulo), so two personas share a circuit only on a cSHAKE256 collision:
//!   cryptographically negligible at 256-bit width (and an operator runs only a handful
//!   of personas). The circuit-side analogue of GF-9 onion rotation.
//!
//! The *measured* half (control-port circuit-ID disjointness) lands with SP-T0's
//! bundled-Tor harness; this crate is buildable and testable without a running Tor
//! — constructing a [`PTorClient`] configures the SOCKS proxy but does not dial.

// The per-P circuit isolation is worthless if ureq lacks its SOCKS connector: it
// then falls OPEN to a proxy-less TCP dial, deanonymizing every persona with no
// runtime signal. Feature unification means a runtime/CI test in one feature
// config cannot prove production has the feature — so "SOCKS present" is enforced
// at COMPILE time here, not hoped for. `tor-socks` is default-on and forwards
// `ureq/socks-proxy` (see Cargo.toml); its absence fails the build.
#[cfg(not(feature = "tor-socks"))]
compile_error!(
    "shekyl-p-transport requires the `tor-socks` feature (forwards ureq/socks-proxy). \
     Without ureq's SOCKS connector, every per-P request dials the target DIRECTLY, \
     bypassing its Tor circuit — a deanonymization leak. This feature is default-on and \
     load-bearing; do not disable it."
);

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use sha3::digest::core_api::CoreWrapper;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake256, CShake256Core};
use shekyl_types::PCanonicalId;

/// SP 800-185 cSHAKE256 customization string for the per-`P` SOCKS-username
/// derivation (rule 30: explicit label + version suffix; mirrors
/// `derive_output_handle`'s `shekyl/output-handle-v1`). A `-v2` bump cleanly
/// invalidates v1 usernames if the construction ever changes.
const SOCKS_USER_CUSTOMIZATION: &[u8] = b"shekyl/p-socks-user-v1";

/// cSHAKE output length in bytes (→ 64 lowercase-hex chars).
const SOCKS_USER_DIGEST_LEN: usize = 32;

/// A fixed, non-empty SOCKS password. Tor's `IsolateSOCKSAuth` isolates on the
/// `(username, password)` pair; the per-`P` identity is carried entirely by the
/// username, so the password is a constant whose only job is to select SOCKS5
/// user/pass auth so the username is actually sent.
const SOCKS_PASSWORD: &str = "shekyl-p";

/// Per-`P` request timeouts (§2b, the blocking-pool axis). A `spawn_blocking`
/// task in a synchronous `ureq` call is **not** a cancellation point: on
/// shutdown an in-flight fetch drains to completion or its timeout, so an
/// unbounded read on a stalled/half-built Tor circuit would pin a tokio
/// blocking-pool thread indefinitely. `GLOBAL_TIMEOUT` is the whole-call hard cap
/// (the "cannot hang forever" guarantee); `CONNECT_TIMEOUT` bounds the
/// circuit-build dial separately — Tor circuit setup is slower than a direct
/// connect, so it gets its own allowance under the global cap.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const GLOBAL_TIMEOUT: Duration = Duration::from_secs(120);

/// A per-`P` SOCKS username — the Tor `IsolateSOCKSAuth` isolation key.
///
/// **Non-empty by construction** (invariant (b)): it is exactly 64 lowercase-hex
/// bytes, so the empty username — the principal's no-auth circuit — is *not a
/// representable value of this type*. The only constructor is [`derive_socks_user`],
/// so a username can never be supplied free-form, nor left empty.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SocksUsername([u8; 64]);

impl SocksUsername {
    /// The username as an ASCII `&str` (always 64 lowercase-hex chars).
    pub fn as_str(&self) -> &str {
        // The bytes are produced only by `derive_socks_user`, which writes
        // lowercase-hex ASCII — valid UTF-8 by construction.
        core::str::from_utf8(&self.0).expect("hex bytes are valid ASCII")
    }
}

// Invariant (a): never log the username. A redacting `Debug` keeps the type usable
// in `#[derive(Debug)]` contexts without leaking the value.
impl core::fmt::Debug for SocksUsername {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SocksUsername(<redacted>)")
    }
}

/// Derive the per-`P` SOCKS username from the persona's canonical id — the CX-1 closure.
///
/// `username = hex(cSHAKE256(p_canonical_id, customization = "shekyl/p-socks-user-v1"))`,
/// the domain separator carried natively in cSHAKE's customization parameter
/// (mirrors `derive_output_handle`). Collision-resistant over the **full** canonical
/// id (no truncation/modulo), so distinct personas get distinct usernames except with
/// negligible probability of a cSHAKE256 collision (invariant (c)); the 64-hex output
/// is never empty (invariant (b), absolute — a fixed-width value cannot be empty).
pub fn derive_socks_user(id: &PCanonicalId) -> SocksUsername {
    let core = CShake256Core::new(SOCKS_USER_CUSTOMIZATION);
    let mut hasher: CShake256 = CoreWrapper::from_core(core);
    hasher.update(id.as_bytes());
    let mut reader = hasher.finalize_xof();
    let mut digest = [0u8; SOCKS_USER_DIGEST_LEN];
    reader.read(&mut digest);

    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (i, byte) in digest.iter().enumerate() {
        out[i * 2] = HEX[(byte >> 4) as usize];
        out[i * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
    SocksUsername(out)
}

/// The bundled Tor's SOCKS endpoint (SP-T0 owns the running instance; this is the
/// address a [`PTorClient`] dials through).
///
/// A [`SocketAddr`], not a `host: String` — Tor's SOCKS port is always an IP:port,
/// and a `SocketAddr` both renders IPv6 correctly (bracketed, `[::1]:9050`) in the
/// proxy URI and makes a URL-injecting "host" string unrepresentable.
#[derive(Clone, Copy, Debug)]
pub struct TorSocksEndpoint {
    addr: SocketAddr,
}

impl TorSocksEndpoint {
    /// A loopback SOCKS endpoint — the normal case (the wallet's own Tor).
    pub fn loopback(port: u16) -> Self {
        Self {
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        }
    }

    /// An explicit SOCKS address (for a non-loopback test harness).
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    /// The socket address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// Failure constructing or using a [`PTorClient`].
#[derive(Debug)]
pub enum PTransportError {
    /// The SOCKS proxy could not be configured for this endpoint. Carries the
    /// endpoint, **not** the proxy URI — the URI embeds the per-`P` username, and
    /// invariant (a) is that the username never reaches a log, including via an
    /// error message.
    Proxy { endpoint: SocketAddr },
    /// A per-`P` request ([`PTorClient::blocking_post`]) failed. Carries a
    /// **username-free** category only (invariant (a)): the raw `ureq` error is
    /// deliberately dropped because it can echo the proxy URI, which embeds the
    /// SOCKS username.
    Request(RequestErrorKind),
}

/// Coarse, username-free classification of a per-`P` request failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestErrorKind {
    /// Failed below HTTP — connect / proxy / timeout / IO. Retry-eligible.
    Transport,
    /// The daemon returned a non-2xx HTTP status (carried).
    Http(u16),
    /// The response was received but its body could not be read.
    Read,
}

impl core::fmt::Display for RequestErrorKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport => write!(f, "transport failure"),
            Self::Http(status) => write!(f, "HTTP status {status}"),
            Self::Read => write!(f, "unreadable response body"),
        }
    }
}

impl core::fmt::Display for PTransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Proxy { endpoint } => {
                write!(f, "per-P SOCKS proxy configuration failed for {endpoint}")
            }
            Self::Request(kind) => write!(f, "per-P request failed: {kind}"),
        }
    }
}

impl std::error::Error for PTransportError {}

/// A per-`P` daemon transport: a `ureq` agent pinned to `P`'s own Tor circuit.
///
/// **The only constructor is [`PTorClient::for_persona`]** — there is no `Default`,
/// and no constructor that accepts a username or a principal `DaemonClient`. So a
/// `PTorClient` *always* carries a non-empty, persona-derived username (invariants
/// (b)/(c)): "`P` shares the principal's circuit" is unrepresentable here, the
/// write-/read-side analogue of SP-0's no-selective-fetch shape.
#[derive(Clone)]
pub struct PTorClient {
    agent: ureq::Agent,
    username: SocksUsername,
}

impl PTorClient {
    /// Build a transport bound to persona `id`'s own Tor circuit through `socks`.
    ///
    /// Configures the agent's SOCKS proxy with the persona-derived username; it does
    /// **not** dial, so this is callable without a running Tor — the measured
    /// circuit-ID check is SP-T0's job.
    pub fn for_persona(
        id: &PCanonicalId,
        socks: &TorSocksEndpoint,
    ) -> Result<Self, PTransportError> {
        let username = derive_socks_user(id);
        // **SOCKS5h, via the typed builder with an explicit `resolve_target(false)`
        // — not a `socks5://` scheme string.** The persona's target hostname must
        // be resolved by the proxy (Tor), never locally: a client-side resolve
        // leaks the target to the OS resolver (a cross-persona correlation point
        // *above* the SOCKS layer) and breaks `.onion` outright. Two traps this
        // construction closes, both of which bit the original `socks5://` code:
        //   1. A *scheme string* is stringly-typed — `socks5` (resolve-locally)
        //      vs `socks5h` (proxy-resolves) is a one-char silent difference, and
        //      ureq derives resolve-locality from the scheme's default (`socks5` ⇒
        //      true). The `ProxyProtocol` enum makes the wrong choice a compile
        //      error, and `.resolve_target(false)` pins the flag independent of the
        //      scheme's (drifting — ureq's own doc contradicts its code) default.
        //   2. ureq's builder takes host/port separately and does not bracket IPv6
        //      in its internal URI, so the IPv6 host is bracketed here (the
        //      `SocketAddr` Display did this for the string form).
        // Verified sufficient: with `resolve_target(false)`, ureq's `connect()`
        // takes the `resolver.empty()` branch (no target DNS) and hands
        // `uri.host_port()` — the name — to the SOCKS proxy (ureq `run.rs`/`socks.rs`).
        // The ureq error is discarded: it would echo the URI, which embeds the
        // username (invariant (a)).
        let host = match socks.addr.ip() {
            IpAddr::V6(v6) => format!("[{v6}]"),
            IpAddr::V4(v4) => v4.to_string(),
        };
        let proxy = ureq::Proxy::builder(ureq::ProxyProtocol::Socks5h)
            .host(&host)
            .port(socks.addr.port())
            .username(username.as_str())
            .password(SOCKS_PASSWORD)
            .resolve_target(false)
            .build()
            .map_err(|_| PTransportError::Proxy {
                endpoint: socks.addr,
            })?;
        let agent = ureq::Agent::config_builder()
            .proxy(Some(proxy))
            // Bounded timeouts — this is the sole agent constructor, so the
            // §2b blocking-pool guarantee is set here once and inherited by
            // every per-`P` request (`blocking_post`).
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_global(Some(GLOBAL_TIMEOUT))
            // Return the response for any status so `blocking_post` reads the
            // code itself (a non-2xx is a typed `Http(status)`, not an opaque
            // transport error).
            .http_status_as_error(false)
            .build()
            .new_agent();
        Ok(Self { agent, username })
    }

    /// The agent, for the fetch impl (SP-T2 builds `PBlockSource` over this).
    pub fn agent(&self) -> &ureq::Agent {
        &self.agent
    }

    /// This transport's SOCKS username — exposed for SP-T0's control-port
    /// circuit-ID verification test. Do not log it (invariant (a)).
    pub fn username(&self) -> &SocksUsername {
        &self.username
    }

    /// Issue **one** synchronous `POST` over `P`'s circuit and return the
    /// response body.
    ///
    /// This is the **only** place a per-`P` HTTP request is made: the agent —
    /// constructed once in [`Self::for_persona`] with the SOCKS proxy + bounded
    /// timeouts — is used here and nowhere else, so `ureq` stays confined to this
    /// crate and a consumer cannot build or misuse an agent a different way (§2b
    /// invariant 1: the safe construction is the only construction). Synchronous
    /// by design — the async bridge (`spawn_blocking`) lives in the engine's
    /// `PRpc`, keeping this a pure transport primitive.
    ///
    /// `content_type` selects the daemon's body extractor (`application/json` for
    /// JSON(-RPC) routes, `application/octet-stream` for `.bin`). Errors carry a
    /// **username-free** [`RequestErrorKind`] only (invariant (a)).
    pub fn blocking_post(
        &self,
        url: &str,
        content_type: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, PTransportError> {
        let response = self
            .agent
            .post(url)
            .content_type(content_type)
            .send(body)
            .map_err(|_| PTransportError::Request(RequestErrorKind::Transport))?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(PTransportError::Request(RequestErrorKind::Http(status)));
        }
        response
            .into_body()
            .read_to_vec()
            .map_err(|_| PTransportError::Request(RequestErrorKind::Read))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn pid(seed: u8) -> PCanonicalId {
        let mut id = [0u8; 32];
        id[0] = seed;
        PCanonicalId::from_bytes(id)
    }

    #[test]
    fn username_is_non_empty_fixed_width_lowercase_hex() {
        // (b): structurally non-empty + the shape callers rely on.
        let u = derive_socks_user(&pid(1));
        assert_eq!(u.as_str().len(), 64);
        assert!(u
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    #[test]
    fn username_is_deterministic() {
        assert_eq!(derive_socks_user(&pid(9)), derive_socks_user(&pid(9)));
    }

    #[test]
    fn distinct_personas_get_distinct_usernames() {
        // (c): a sampled distinctness/determinism check over 256 single-byte-distinct
        // canonical ids — not an injectivity *proof* (collision resistance is the real
        // property; a literal proof is impossible for a hash). Catches a derivation that
        // ignored its input or collapsed the output space.
        let mut seen = HashSet::new();
        for s in 0u8..=255 {
            let u = derive_socks_user(&pid(s));
            assert!(
                seen.insert(u.as_str().to_owned()),
                "username collision at seed {s}"
            );
        }
        assert_eq!(seen.len(), 256);
    }

    #[test]
    fn pinned_kat_is_an_implementation_tripwire() {
        // rule 30: lock the cSHAKE256 invocation (customization string, input
        // encoding, output length, hex) to exact bytes. These are
        // implementation-stability tripwires, not correctness proofs — the
        // underlying cSHAKE256 is verified by the `sha3` crate's own KAT suite.
        // A change to the label, primitive, or encoding trips these. Unchanged by
        // the `PCircuitTag` → `PCanonicalId` migration: same 32 bytes in, same out.
        assert_eq!(
            derive_socks_user(&PCanonicalId::from_bytes([0u8; 32])).as_str(),
            "7af8ee1cd5f16fcc1fdb9b2ac89ea421cc473c9c85988ad42d961d06f84247ce"
        );
        assert_eq!(
            derive_socks_user(&PCanonicalId::from_bytes([0x11u8; 32])).as_str(),
            "88b7d63a98c4185a4192ed48e6aa7e6e03f0f9add26e0bf847155cdf8c87fe3c"
        );
    }

    #[test]
    fn debug_redacts_the_username() {
        // (a): the value must not appear in a `Debug` rendering.
        let u = derive_socks_user(&pid(7));
        let rendered = format!("{u:?}");
        assert_eq!(rendered, "SocksUsername(<redacted>)");
        assert!(!rendered.contains(u.as_str()));
    }

    #[test]
    fn for_persona_builds_without_tor_and_carries_persona_username() {
        let id = pid(42);
        let client = PTorClient::for_persona(&id, &TorSocksEndpoint::loopback(9050))
            .expect("proxy config is well-formed");
        assert_eq!(client.username(), &derive_socks_user(&id));
    }

    #[test]
    fn for_persona_accepts_ipv6_endpoint() {
        // Regression: a `SocketAddr` brackets IPv6 in the URI, so an IPv6 SOCKS
        // endpoint no longer fails proxy parsing.
        let addr: SocketAddr = "[::1]:9050".parse().expect("valid v6 socket addr");
        let client = PTorClient::for_persona(&pid(3), &TorSocksEndpoint::new(addr))
            .expect("ipv6 proxy config is well-formed");
        assert_eq!(client.username().as_str().len(), 64);
    }

    #[test]
    fn transport_types_are_send_sync() {
        // The scan actor holds a `PTorClient` in its state — it must be `Send + Sync`.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PTorClient>();
        assert_send_sync::<SocksUsername>();
        assert_send_sync::<PCanonicalId>();
    }

    #[test]
    fn proxy_resolves_the_target_at_tor_never_locally() {
        // The DNS-leak regression pin (Axis B). `resolve_target() == false` means
        // ureq hands the persona's target *hostname* to the SOCKS proxy (Tor) and
        // never resolves it via the OS resolver. The original `socks5://` string
        // built a Socks5 proxy whose `resolve_target` defaults to *true* (resolve
        // locally) — which this assertion catches: it fails against that code and
        // passes only for the socks5h / `resolve_target(false)` construction.
        // Asserted through the *real* `PTorClient` construction (the agent's live
        // config), not a re-built proxy, so it pins the production path end-to-end.
        let client = PTorClient::for_persona(&pid(5), &TorSocksEndpoint::loopback(9050))
            .expect("proxy config is well-formed");
        let proxy = client
            .agent()
            .config()
            .proxy()
            .expect("a per-P client always carries a SOCKS proxy");
        assert!(
            !proxy.resolve_target(),
            "per-P transport must resolve the target at the proxy (Tor), never locally — \
             a local resolve leaks the persona's target to the OS resolver and breaks .onion"
        );
    }

    #[test]
    fn blocking_post_maps_a_dead_proxy_to_a_username_free_transport_error() {
        // Dial through a closed SOCKS port (`:1`): loopback refuses immediately,
        // so the error path is exercised fast (no timeout wait). The failure must
        // be the coarse, username-free `Transport` kind — and its rendering must
        // not leak the SOCKS username (invariant (a)).
        let client = PTorClient::for_persona(&pid(8), &TorSocksEndpoint::loopback(1))
            .expect("proxy config is well-formed");
        let err = client
            .blocking_post("http://127.0.0.1:18081/json_rpc", "application/json", b"{}")
            .expect_err("a dead SOCKS proxy must fail the request");
        assert!(
            matches!(err, PTransportError::Request(RequestErrorKind::Transport)),
            "expected a Transport error, got {err:?}"
        );
        assert!(
            !format!("{err}").contains(client.username().as_str()),
            "invariant (a): a request error must never render the SOCKS username"
        );
    }
}
