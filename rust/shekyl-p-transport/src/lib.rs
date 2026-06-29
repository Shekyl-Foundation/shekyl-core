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
//!   *empty-username* (no-auth) one, so a persona username can never collide into it.
//! - **(c) per-persona distinct (collision-resistant, not literally injective)** — the
//!   username is a collision-resistant hash of the **full** `p_canonical_id` (no
//!   truncation/modulo), so two personas share a circuit only on a cSHAKE256 collision:
//!   cryptographically negligible at 256-bit width (and an operator runs only a handful
//!   of personas). The circuit-side analogue of GF-9 onion rotation.
//!
//! The *measured* half (control-port circuit-ID disjointness) lands with SP-T0's
//! bundled-Tor harness; this crate is buildable and testable without a running Tor
//! — constructing a [`PTorClient`] configures the SOCKS proxy but does not dial.

use std::net::{Ipv4Addr, SocketAddr};

use sha3::digest::core_api::CoreWrapper;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake256, CShake256Core};

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

/// The per-`P` circuit identity — the input to the SOCKS-username derivation.
///
/// Minted from the **active persona's** canonical id (`p_canonical_id`, the
/// 32-byte hybrid-bond identity), never free-form: the engine wraps the id it
/// derived from real persona keys (`persona_canonical_id`). It is deliberately not
/// constructible from arbitrary strings a caller picked at the call site.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PCircuitTag([u8; 32]);

impl PCircuitTag {
    /// Wrap a persona's canonical id. The caller is the engine, which obtained
    /// `p_canonical_id` from the active persona's keys.
    pub fn from_canonical_id(p_canonical_id: [u8; 32]) -> Self {
        Self(p_canonical_id)
    }

    /// The wrapped canonical id.
    pub fn canonical_id(&self) -> &[u8; 32] {
        &self.0
    }
}

// Truncated `Debug` (first two bytes), mirroring `SpendPublicKey` in
// `shekyl-crypto-pq`: `p_canonical_id` is public on chain, but the full id in a
// local log or panic backtrace is a correlation artifact — 16 bits disambiguates
// for debugging without reproducing the whole identifier in unsanitised streams.
impl core::fmt::Debug for PCircuitTag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PCircuitTag({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

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

/// Derive the per-`P` SOCKS username from the circuit tag — the CX-1 closure.
///
/// `username = hex(cSHAKE256(p_canonical_id, customization = "shekyl/p-socks-user-v1"))`,
/// the domain separator carried natively in cSHAKE's customization parameter
/// (mirrors `derive_output_handle`). Collision-resistant over the **full** canonical
/// id (no truncation/modulo), so distinct personas get distinct usernames except with
/// negligible probability of a cSHAKE256 collision (invariant (c)); the 64-hex output
/// is never empty (invariant (b), absolute — a fixed-width value cannot be empty).
pub fn derive_socks_user(tag: &PCircuitTag) -> SocksUsername {
    let core = CShake256Core::new(SOCKS_USER_CUSTOMIZATION);
    let mut hasher: CShake256 = CoreWrapper::from_core(core);
    hasher.update(tag.canonical_id());
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

/// Failure constructing a [`PTorClient`].
#[derive(Debug)]
pub enum PTransportError {
    /// The SOCKS proxy could not be configured for this endpoint. Carries the
    /// endpoint, **not** the proxy URI — the URI embeds the per-`P` username, and
    /// invariant (a) is that the username never reaches a log, including via an
    /// error message.
    Proxy { endpoint: SocketAddr },
}

impl core::fmt::Display for PTransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Proxy { endpoint } => {
                write!(f, "per-P SOCKS proxy configuration failed for {endpoint}")
            }
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
pub struct PTorClient {
    agent: ureq::Agent,
    username: SocksUsername,
}

impl PTorClient {
    /// Build a transport bound to persona `tag`'s own Tor circuit through `socks`.
    ///
    /// Configures the agent's SOCKS proxy with the persona-derived username; it does
    /// **not** dial, so this is callable without a running Tor — the measured
    /// circuit-ID check is SP-T0's job.
    pub fn for_persona(
        tag: &PCircuitTag,
        socks: &TorSocksEndpoint,
    ) -> Result<Self, PTransportError> {
        let username = derive_socks_user(tag);
        // `SocketAddr`'s Display brackets IPv6 (`[::1]:9050`), so the URI is always
        // well-formed. The ureq error is deliberately discarded: it would echo the
        // proxy URI, which embeds the username (invariant (a)).
        let proxy_uri = format!(
            "socks5://{}:{}@{}",
            username.as_str(),
            SOCKS_PASSWORD,
            socks.addr
        );
        let proxy = ureq::Proxy::new(&proxy_uri).map_err(|_| PTransportError::Proxy {
            endpoint: socks.addr,
        })?;
        let agent = ureq::Agent::config_builder()
            .proxy(Some(proxy))
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn tag(seed: u8) -> PCircuitTag {
        let mut id = [0u8; 32];
        id[0] = seed;
        PCircuitTag::from_canonical_id(id)
    }

    #[test]
    fn username_is_non_empty_fixed_width_lowercase_hex() {
        // (b): structurally non-empty + the shape callers rely on.
        let u = derive_socks_user(&tag(1));
        assert_eq!(u.as_str().len(), 64);
        assert!(u
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    #[test]
    fn username_is_deterministic() {
        assert_eq!(derive_socks_user(&tag(9)), derive_socks_user(&tag(9)));
    }

    #[test]
    fn username_is_injective_over_distinct_personas() {
        // (c): distinct canonical ids -> distinct usernames (no shared circuit).
        let mut seen = HashSet::new();
        for s in 0u8..=255 {
            let u = derive_socks_user(&tag(s));
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
        // A change to the label, primitive, or encoding trips these.
        assert_eq!(
            derive_socks_user(&PCircuitTag::from_canonical_id([0u8; 32])).as_str(),
            "7af8ee1cd5f16fcc1fdb9b2ac89ea421cc473c9c85988ad42d961d06f84247ce"
        );
        assert_eq!(
            derive_socks_user(&PCircuitTag::from_canonical_id([0x11u8; 32])).as_str(),
            "88b7d63a98c4185a4192ed48e6aa7e6e03f0f9add26e0bf847155cdf8c87fe3c"
        );
    }

    #[test]
    fn debug_redacts_the_username() {
        // (a): the value must not appear in a `Debug` rendering.
        let u = derive_socks_user(&tag(7));
        let rendered = format!("{u:?}");
        assert_eq!(rendered, "SocksUsername(<redacted>)");
        assert!(!rendered.contains(u.as_str()));
    }

    #[test]
    fn for_persona_builds_without_tor_and_carries_persona_username() {
        let t = tag(42);
        let client = PTorClient::for_persona(&t, &TorSocksEndpoint::loopback(9050))
            .expect("proxy config is well-formed");
        assert_eq!(client.username(), &derive_socks_user(&t));
    }

    #[test]
    fn for_persona_accepts_ipv6_endpoint() {
        // Regression: a `SocketAddr` brackets IPv6 in the URI, so an IPv6 SOCKS
        // endpoint no longer fails proxy parsing.
        let addr: SocketAddr = "[::1]:9050".parse().expect("valid v6 socket addr");
        let client = PTorClient::for_persona(&tag(3), &TorSocksEndpoint::new(addr))
            .expect("ipv6 proxy config is well-formed");
        assert_eq!(client.username().as_str().len(), 64);
    }

    #[test]
    fn pcircuittag_debug_is_truncated() {
        // The full canonical id must not appear in a `Debug` rendering.
        let mut id = [0xabu8; 32];
        id[0] = 0xde;
        id[1] = 0xad;
        let rendered = format!("{:?}", PCircuitTag::from_canonical_id(id));
        assert_eq!(rendered, "PCircuitTag(dead..)");
        assert!(!rendered.contains("abab"));
    }

    #[test]
    fn transport_types_are_send_sync() {
        // The scan actor holds a `PTorClient` in its state — it must be `Send + Sync`.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PTorClient>();
        assert_send_sync::<SocksUsername>();
        assert_send_sync::<PCircuitTag>();
    }
}
