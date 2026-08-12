// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `ADD_ONION` / `DEL_ONION` surface — typed arguments for the v3 onion
//! service a persona serves from (SP-T3).
//!
//! # Why the arguments are types rather than validated strings
//!
//! [`Command`](super::actor::Command)'s `to_wire` validates `GETINFO` /
//! `SETEVENTS` tokens by *string-checking* a caller-supplied list: reject empty
//! tokens, spaces, and ASCII controls, because a `\r`/`\n` would split into extra
//! control commands and desync the no-request-ID FIFO correlation.
//!
//! `ADD_ONION` carries a wider and more attacker-adjacent surface than a
//! `GETINFO` key — a 64-byte secret key blob, flag words, and virtport→target
//! mappings — so the same posture is taken one step further: the line is
//! **assembled from typed parts that cannot render an invalid token**, rather
//! than string-checked after the fact. Concretely:
//!
//! - [`OnionKey`] is a fixed 64 bytes and renders as base64 (alphabet
//!   `A–Z a–z 0–9 + / =`), so the blob cannot carry a space or a control byte.
//! - [`OnionPort`] holds a `u16` virtport and a **loopback** [`SocketAddr`]; both
//!   render through `Display` impls whose output is digits, dots/colons and
//!   brackets.
//! - [`ServiceId`] is parsed on the way *in* ([`ServiceId::parse`]) and is 56
//!   lowercase base32 characters, so `DEL_ONION <id>` cannot inject a second line
//!   from a hostile control-port reply.
//! - [`OnionFlags`] is a closed set with **no `Detach` member** (see below).
//!
//! The result is that `to_wire` for the onion variants is total: there is no
//! `ControlError::InvalidCommand` path, because no invalid value exists to
//! reject. That is the rule-preferred shape — unrepresentable over validated.
//!
//! # `Detach` is not a flag this crate can express
//!
//! Tor's `Flags=Detach` keeps a hidden service running after the control
//! connection that created it closes. For a bonded archival persona that is a
//! **privacy defect, not a convenience**: a detached onion outlives the wallet
//! process and keeps advertising the persona's `.onion` — publishing descriptors
//! that say "this persona is online" — after the wallet is gone and can no longer
//! serve a byte. The persona's liveness signal would then be a lie told by an
//! orphan.
//!
//! So `Detach` is not an [`OnionFlags`] variant that callers are asked to avoid;
//! it is **absent from the type**, and [`AddOnion`]'s `to_wire_line` can only render
//! the flags the enum can hold. `onion_line_never_detaches` asserts the rendered
//! wire line for every representable flag combination is `Detach`-free.
//!
//! # Secrets
//!
//! [`OnionKey`] is secret key material — whoever holds it *is* the persona on the
//! network — so it is `ZeroizeOnDrop`, has a redacting `Debug`, and is not
//! `Clone` (rules 35/36). Its base64 rendering is produced into a
//! [`Zeroizing<String>`] so the encoded copy is wiped too; the only place that
//! rendering exists is inside the one control line being written.
//!
//! [`SocketAddr`]: std::net::SocketAddr
//! [`Zeroizing<String>`]: zeroize::Zeroizing

use std::net::SocketAddr;

use zeroize::{Zeroize, Zeroizing};

/// Length of tor's `ED25519-V3` key blob: an **expanded** ed25519 secret key,
/// `clamp(SHA-512(seed)[0..32]) ‖ SHA-512(seed)[32..64]` (RFC 8032 §5.1.5) —
/// *not* the 32-byte seed. See [`OnionKey`].
pub const ONION_KEY_BYTES: usize = 64;

/// Length of a v3 `.onion` service id (the address without the `.onion` suffix):
/// base32 of `pubkey(32) ‖ checksum(2) ‖ version(1)` = 35 bytes → 56 characters.
pub const SERVICE_ID_CHARS: usize = 56;

/// A v3 onion-service secret key in tor's `ED25519-V3` wire form.
///
/// **This is the persona's network identity.** Holding these bytes is sufficient
/// to impersonate the persona's onion service, so the type carries the full
/// secret posture: `ZeroizeOnDrop`, redacting `Debug`, no `Clone`, no
/// `PartialEq` against arbitrary bytes, and no accessor that hands out the raw
/// array. The only way the bytes leave this type is
/// [`AddOnion`]'s `to_wire_line` base64 rendering, which itself lands in a
/// [`Zeroizing<String>`].
///
/// # The 64 bytes are *expanded*, not a seed
///
/// tor's `ED25519-V3` key blob is the expanded secret key — the clamped scalar
/// concatenated with the hash prefix — which is what RFC 8032 §5.1.5 produces
/// from a 32-byte seed via SHA-512 + clamping. Callers that hold a seed must
/// perform that expansion; this type does not, because the expansion belongs
/// with whatever owns the seed (and the seed is a different secret with a
/// different lifetime).
pub struct OnionKey([u8; ONION_KEY_BYTES]);

impl OnionKey {
    /// Wrap an already-expanded `ED25519-V3` secret key.
    ///
    /// Takes the array **by value** so the caller's copy moves in rather than
    /// being borrowed and left behind (rule 35's hand-off discipline: no
    /// `[u8; N]: Copy` temporary surviving outside a `Zeroize` wrapper — the
    /// caller's source should itself be a `Zeroizing` that this consumes).
    #[must_use]
    pub fn from_expanded_bytes(bytes: [u8; ONION_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// Base64 (standard alphabet, padded) of the expanded key — the exact
    /// `KeyBlob` token tor expects after `ED25519-V3:`.
    ///
    /// Returns a [`Zeroizing<String>`] so the encoded copy is wiped on drop
    /// alongside the key itself.
    fn to_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(base64_encode(&self.0))
    }
}

impl Drop for OnionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// Redacting `Debug` (rule 35): the key must not reach a log, an `assert_eq!`
// failure message, or a panic backtrace. Render only the type name.
impl std::fmt::Debug for OnionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OnionKey(<redacted>)")
    }
}

/// A v3 onion service id — the 56-character base32 label of a `.onion` address.
///
/// **Secret-adjacent, and treated as such.** The service id is not a private key,
/// but it *is* the persona's public network identity: a service id in a log ties
/// that log's host to that persona, which is exactly the principal↔persona
/// linkage the archival firewall exists to prevent. So `Debug` redacts, matching
/// [`ControlReply`](super::framing::ControlReply) and `SocksUsername`.
///
/// The only constructor is [`Self::parse`], which enforces the character set, so
/// a `ServiceId` can never carry a space, a control byte, or a second control
/// line — `DEL_ONION` is therefore injection-free by construction rather than by
/// validation at the call site.
#[derive(Clone, PartialEq, Eq)]
pub struct ServiceId(String);

impl ServiceId {
    /// Parse a service id from an `ADD_ONION` reply's `ServiceID=` value.
    ///
    /// Accepts exactly 56 characters from the RFC 4648 lowercase base32 alphabet
    /// (`a–z`, `2–7`). Anything else — including an address that still carries a
    /// `.onion` suffix, or a v2 (16-character) id — is rejected: this is parsing
    /// a value that came off the control port, so it is untrusted input even
    /// though the control port is loopback.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        if raw.len() != SERVICE_ID_CHARS {
            return None;
        }
        if !raw
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        {
            return None;
        }
        Some(Self(raw.to_owned()))
    }

    /// The service id as it appears on the wire (no `.onion` suffix).
    ///
    /// A forensic surface — dial it, never log it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The full `<id>.onion` hostname, for handing to a SOCKS proxy.
    ///
    /// A forensic surface — same discipline as [`Self::as_str`].
    #[must_use]
    pub fn hostname(&self) -> String {
        format!("{}.onion", self.0)
    }
}

impl std::fmt::Debug for ServiceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServiceId(<redacted>)")
    }
}

/// A virtual-port → local-target mapping for an onion service.
///
/// The target is **loopback-only by construction**: [`Self::loopback`] is the
/// only constructor and it refuses a routable address. A persona's serve
/// endpoint that tor forwarded to a LAN or public address would expose the
/// endpoint outside the onion — reachable without the rendezvous, and
/// attributable to the host's IP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OnionPort {
    virtual_port: u16,
    target: SocketAddr,
}

impl OnionPort {
    /// Map `virtual_port` on the onion to a **loopback** target.
    ///
    /// Returns `None` if `target` is not a loopback address — the structural
    /// enforcement of hard invariant 4 (loopback-only bind), checked where the
    /// mapping is *created* rather than trusted at the bind site.
    #[must_use]
    pub fn loopback(virtual_port: u16, target: SocketAddr) -> Option<Self> {
        if !target.ip().is_loopback() {
            return None;
        }
        Some(Self {
            virtual_port,
            target,
        })
    }

    /// The `Port=` argument value: `<virtport>,<target>`.
    fn to_arg(self) -> String {
        format!("Port={},{}", self.virtual_port, self.target)
    }
}

/// The caller-selectable flags an `ADD_ONION` may carry — a **closed set that
/// cannot express `Detach`** (see the module doc).
///
/// `DiscardPK` is the one flag callers choose: the key is supplied by the caller
/// and reproduced on demand from the persona's seed, so there is no reason for
/// tor to hand it back in the reply. Not requesting the private key keeps it out
/// of the reply payload entirely — one fewer copy of the persona's network
/// identity in memory and one fewer thing a mis-logged reply could leak.
///
/// `MaxStreamsCloseCircuit` is deliberately **not** a member: it is emitted
/// unconditionally by [`AddOnion`]'s `to_wire_line`, because it is the enforcement
/// half of the stream cap and must not be independently switchable. See
/// [`AddOnion::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct OnionFlags {
    /// `Flags=DiscardPK` — tor does not echo the private key in its reply.
    pub discard_pk: bool,
}

impl OnionFlags {
    /// The `Flags=` argument.
    ///
    /// Always non-empty: `MaxStreamsCloseCircuit` is unconditional, so — unlike a
    /// caller-driven flag set — there is no "no flags" case to omit the argument
    /// for.
    ///
    /// **`MaxStreamsCloseCircuit` is a `Flag`, not a standalone argument.** The
    /// grammar is `[SP "Flags=" Flag *("," Flag)] [SP "MaxStreams=" NumStreams]`
    /// (control-spec, `ADD_ONION`), and its Flag list is exactly `DiscardPK`,
    /// `Detach`, `BasicAuth`, `V3Auth`, `NonAnonymous`, `MaxStreamsCloseCircuit`.
    /// Rendering it as `MaxStreamsCloseCircuit=1` earns a `512 Syntax error in
    /// command argument` from tor — which is how this was found: the live
    /// round-trip test rejected a line the unit KAT had happily pinned.
    fn to_arg(self) -> String {
        // Unconditional; see the type doc.
        let mut flags: Vec<&str> = vec!["MaxStreamsCloseCircuit"];
        if self.discard_pk {
            flags.push("DiscardPK");
        }
        format!("Flags={}", flags.join(","))
    }
}

/// Onion-service **proof-of-work defenses** — tor's built-in answer to
/// rendezvous flooding (`ADD_ONION`'s `PoWDefensesEnabled` / `PoWQueueRate` /
/// `PoWQueueBurst`).
///
/// # What it actually bounds, and what it does not
///
/// PoW governs the **rendezvous-request priority queue**: how fast tor dispatches
/// *new* client rendezvous, and at what burst. It therefore throttles **arrival**,
/// not **egress** — a client that has already established a rendezvous still pulls
/// a full shard. Aggregate byte-rate is a separate concern and needs a separate
/// bound (the serve endpoint's in-flight connection cap).
///
/// # Why this matters for a shard-serving persona
///
/// A shard read is a ~100-byte request answered with ~3.33 MB, an egress
/// amplification of roughly **33 000×**, where the requester pays only its own
/// circuit. For a *bonded* persona that asymmetry is bounded by the challenge
/// draw — its clients are drawn miners, a finite population. For a **publicly
/// advertised, uncompensated** service (the Foundation's complete-tree `P`) it is
/// bounded by nothing at all, and PoW is the mechanism that puts cost back on the
/// requester.
///
/// # Default is [`Disabled`](Self::Disabled), matching tor
///
/// PoW is not free for honest clients — it is client-side work on every
/// rendezvous — so it is off unless a deployment asks for it, exactly as tor
/// ships it (`PoWDefensesEnabled` "Default if not present is 0, disabled").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum OnionPow {
    /// No PoW defenses. tor's default, and the right choice for a bonded persona
    /// whose client population is bounded by the challenge draw.
    #[default]
    Disabled,
    /// PoW on, with **tor's own queue parameters** (currently 250 req/s sustained,
    /// burst 2500).
    ///
    /// Renders `PoWDefensesEnabled=1` and nothing else, so those numbers stay
    /// tor's to own and version. Restating them here would be a second copy of a
    /// fact this crate does not control — the copy that silently goes stale when
    /// tor retunes its defaults.
    Enabled,
    /// PoW on with explicit queue parameters, for a deployment that has *measured*
    /// its load and has reason to deviate from tor's defaults.
    ///
    /// Prefer [`Enabled`](Self::Enabled) until you have that measurement: tuning a
    /// queue you have not observed is how a defense becomes a self-inflicted
    /// outage.
    EnabledTuned {
        /// Sustained rendezvous requests dispatched per second.
        queue_rate: u32,
        /// Maximum burst dispatched at once.
        queue_burst: u32,
    },
}

impl OnionPow {
    /// The `PoW*` arguments, in the grammar's order (after `MaxStreams`, before
    /// `Port`). Empty when disabled — an absent `PoWDefensesEnabled` *is* tor's
    /// "off", so there is nothing to render.
    fn to_args(self) -> Vec<String> {
        match self {
            Self::Disabled => Vec::new(),
            Self::Enabled => vec!["PoWDefensesEnabled=1".to_owned()],
            Self::EnabledTuned {
                queue_rate,
                queue_burst,
            } => vec![
                "PoWDefensesEnabled=1".to_owned(),
                format!("PoWQueueRate={queue_rate}"),
                format!("PoWQueueBurst={queue_burst}"),
            ],
        }
    }
}

/// A fully-specified `ADD_ONION` request.
///
/// Every field is typed such that the rendered line is well-formed for any
/// value the struct can hold — there is no validation step and no
/// `InvalidCommand` outcome. `ports` is non-empty by construction
/// ([`Self::new`] takes the first port separately), because `ADD_ONION` with no
/// `Port=` is a protocol error.
#[derive(Debug)]
pub struct AddOnion {
    key: OnionKey,
    ports: Vec<OnionPort>,
    flags: OnionFlags,
    max_streams: u16,
    pow: OnionPow,
}

impl AddOnion {
    /// Build a request for `key`, serving at least `first_port`.
    ///
    /// `max_streams` becomes `MaxStreams=<n>`, and the `MaxStreamsCloseCircuit`
    /// flag is emitted **unconditionally alongside it**: when a client exceeds the
    /// per-circuit stream cap, tor closes the circuit rather than silently
    /// refusing the extra stream. Refusing-without-closing would let a client hold
    /// a rendezvous circuit open while probing the cap for free; closing makes
    /// each probe cost the prober a circuit rebuild.
    ///
    /// The two are not independently settable *by construction* — the flag is not
    /// a member of [`OnionFlags`] — because a stream cap without the closing
    /// enforcement is the weaker half of a protection that only works as a pair,
    /// and "remember to set both" is the kind of caller discipline this crate
    /// converts into a type property.
    #[must_use]
    pub fn new(key: OnionKey, first_port: OnionPort, max_streams: u16) -> Self {
        Self {
            key,
            ports: vec![first_port],
            flags: OnionFlags::default(),
            max_streams,
            pow: OnionPow::default(),
        }
    }

    /// Enable onion-service proof-of-work defenses (see [`OnionPow`]).
    ///
    /// Default is [`OnionPow::Disabled`], matching tor. Turn it on for a service
    /// whose client population is **not** bounded by the challenge draw — most
    /// concretely, a publicly advertised uncompensated one.
    #[must_use]
    pub fn with_pow(mut self, pow: OnionPow) -> Self {
        self.pow = pow;
        self
    }

    /// Set the flags (see [`OnionFlags`] — `Detach` is not expressible).
    #[must_use]
    pub fn with_flags(mut self, flags: OnionFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Add a further virtport→target mapping.
    #[must_use]
    pub fn with_port(mut self, port: OnionPort) -> Self {
        self.ports.push(port);
        self
    }

    /// Render the control line (without the trailing CRLF).
    ///
    /// Total — no failure mode: every component renders to a token that is
    /// non-empty, space-free and control-byte-free by its own type. The line
    /// lands in a [`Zeroizing<String>`] because it embeds the base64 key.
    pub(super) fn to_wire_line(&self) -> Zeroizing<String> {
        let blob = self.key.to_base64();
        let mut line = Zeroizing::new(format!("ADD_ONION ED25519-V3:{}", blob.as_str()));
        // Argument order is the grammar's: Flags, then MaxStreams, then Port(s).
        line.push(' ');
        line.push_str(&self.flags.to_arg());
        line.push_str(&format!(" MaxStreams={}", self.max_streams));
        for arg in self.pow.to_args() {
            line.push(' ');
            line.push_str(&arg);
        }
        for port in &self.ports {
            line.push(' ');
            line.push_str(&port.to_arg());
        }
        line
    }
}

/// Parse the `ServiceID=` value out of an `ADD_ONION` reply's payload lines.
///
/// Returns `None` when no well-formed service id is present, so a malformed or
/// hostile reply surfaces as a failure rather than a half-built service record.
#[must_use]
pub fn parse_service_id(lines: &[String]) -> Option<ServiceId> {
    lines
        .iter()
        .find_map(|l| l.trim().strip_prefix("ServiceID="))
        .and_then(ServiceId::parse)
}

/// Why an `ADD_ONION` reply is not an acceptable publish of `expected`.
///
/// Pure control-protocol knowledge: status + `ServiceID=` field. The
/// supervisor maps this into its own publish-failure type; it does not re-
/// interpret the wire shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddOnionReplyError {
    /// Tor answered with a non-250 status.
    Rejected {
        /// The status tor returned.
        status: u16,
    },
    /// A 250 reply with no parseable `ServiceID=` line.
    NoServiceId,
    /// Tor published a different address than the one the caller holds.
    ServiceIdMismatch {
        /// The address the persona advertises / the held identity implies.
        expected: ServiceId,
        /// The address tor reported.
        published: ServiceId,
    },
}

/// Decide whether an `ADD_ONION` reply published the expected service — the
/// pure core of the publish path, so the non-250 / no-id / mismatch
/// fail-stops are unit-testable without a tor.
///
/// The mismatch check is the load-bearing one: tor returning 250 with a
/// *different* `ServiceID` than the address the persona's key implies means
/// the service exists but not at the address the persona advertises —
/// unreachable to every witness, and invisible from the serving side.
pub fn evaluate_add_onion_reply(
    reply: &super::framing::ControlReply,
    expected: &ServiceId,
) -> Result<(), AddOnionReplyError> {
    if reply.status() != 250 {
        return Err(AddOnionReplyError::Rejected {
            status: reply.status(),
        });
    }
    match parse_service_id(reply.lines()) {
        Some(published) if &published == expected => Ok(()),
        Some(published) => Err(AddOnionReplyError::ServiceIdMismatch {
            expected: expected.clone(),
            published,
        }),
        None => Err(AddOnionReplyError::NoServiceId),
    }
}

/// Standard-alphabet, padded base64 (RFC 4648 §4).
///
/// Hand-rolled rather than adding a dependency to this crate: the single call
/// site encodes a fixed 64-byte key, the alphabet is the load-bearing property
/// (it is what makes the blob token structurally injection-free), and the
/// implementation is pinned by RFC 4648 §10 test vectors below. Rule 17's
/// weighing lands on "no new edge" for a dozen lines of table lookup.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn key() -> OnionKey {
        let mut b = [0u8; ONION_KEY_BYTES];
        for (i, x) in b.iter_mut().enumerate() {
            *x = u8::try_from(i).expect("index fits u8");
        }
        OnionKey::from_expanded_bytes(b)
    }

    fn loopback_port() -> OnionPort {
        OnionPort::loopback(80, SocketAddr::from((Ipv4Addr::LOCALHOST, 40001)))
            .expect("127.0.0.1 is loopback")
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        // RFC 4648 §10 — pins the alphabet, the padding, and the bit packing.
        // A drift in any of the three would produce a blob tor rejects (or, worse,
        // a blob tor accepts as a *different* key).
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn add_onion_renders_the_expected_wire_line() {
        // The full KAT: verb, key type, base64 blob, flags, MaxStreams, and the
        // port mapping — in the grammar's argument order (Flags, MaxStreams,
        // Port). Pinned as one exact string so an argument reordering or a
        // re-spelled flag fails here rather than at a live tor.
        let cmd =
            AddOnion::new(key(), loopback_port(), 4).with_flags(OnionFlags { discard_pk: true });
        assert_eq!(
            cmd.to_wire_line().as_str(),
            concat!(
                "ADD_ONION ED25519-V3:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g",
                "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw== ",
                "Flags=MaxStreamsCloseCircuit,DiscardPK MaxStreams=4 Port=80,127.0.0.1:40001"
            )
        );
    }

    #[test]
    fn max_streams_close_circuit_is_unconditional_and_is_a_flag() {
        // Two properties in one assertion, both learned from a live 512:
        //
        // 1. The close-circuit enforcement rides in `Flags=`, NOT as a
        //    `MaxStreamsCloseCircuit=1` argument. tor answers the latter with
        //    `512 Syntax error in command argument`, so the negative half of this
        //    test is what keeps the KAT honest about the grammar.
        // 2. It is emitted for *every* representable value, including the default
        //    flags — a stream cap without it is the weaker half of a pair.
        for discard_pk in [false, true] {
            let line = AddOnion::new(key(), loopback_port(), 1)
                .with_flags(OnionFlags { discard_pk })
                .to_wire_line();
            assert!(line.contains("MaxStreams=1"), "{}", line.as_str());
            assert!(
                line.contains("Flags=MaxStreamsCloseCircuit"),
                "close-circuit must ride in Flags=: {}",
                line.as_str()
            );
            assert!(
                !line.contains("MaxStreamsCloseCircuit=1"),
                "the `=1` argument spelling is a 512 from tor: {}",
                line.as_str()
            );
        }
    }

    #[test]
    fn pow_is_absent_by_default_and_renders_in_grammar_order() {
        // Default must render NOTHING: an absent `PoWDefensesEnabled` is tor's
        // own "off", so the disabled case adds no bytes and cannot change the
        // line a bonded persona sends.
        let plain = AddOnion::new(key(), loopback_port(), 4).to_wire_line();
        assert!(!plain.contains("PoW"), "{}", plain.as_str());

        // Enabled-with-tor-defaults renders the switch only — the 250/2500
        // numbers stay tor's to own, so they cannot go stale here.
        let on = AddOnion::new(key(), loopback_port(), 4)
            .with_pow(OnionPow::Enabled)
            .to_wire_line();
        assert!(on.contains("PoWDefensesEnabled=1"));
        assert!(!on.contains("PoWQueueRate"), "{}", on.as_str());
        assert!(!on.contains("PoWQueueBurst"), "{}", on.as_str());

        // Tuned renders all three, and the grammar's order is
        // Flags, MaxStreams, PoW*, Port — asserted by position, because tor
        // answers an out-of-order argument with a 512 (the same class of failure
        // the MaxStreamsCloseCircuit spelling produced).
        let tuned = AddOnion::new(key(), loopback_port(), 4)
            .with_pow(OnionPow::EnabledTuned {
                queue_rate: 40,
                queue_burst: 400,
            })
            .to_wire_line();
        let flags = tuned.find("Flags=").expect("flags present");
        let streams = tuned.find("MaxStreams=").expect("max streams present");
        let pow = tuned.find("PoWDefensesEnabled=").expect("pow present");
        let rate = tuned.find("PoWQueueRate=40").expect("rate present");
        let burst = tuned.find("PoWQueueBurst=400").expect("burst present");
        let port = tuned.find("Port=").expect("port present");
        assert!(
            flags < streams && streams < pow && pow < rate && rate < burst && burst < port,
            "grammar order violated: {}",
            tuned.as_str()
        );
    }

    #[test]
    fn onion_line_is_never_non_anonymous() {
        // All shard retrieval occurs over a v3 rendezvous — every persona's, the
        // Foundation's included. "Known" describes a persona's published .onion
        // address, never a clearnet endpoint.
        //
        // `NonAnonymous` (tor's single-hop mode) is absent from `OnionFlags`
        // rather than merely unset, so a non-anonymous service is
        // **unrepresentable** — the same posture as `Detach`. Asserted over every
        // representable value, including with PoW on, so adding the flag as a
        // member later fails here rather than shipping quietly.
        //
        // **This test covers only ONE of the two routes into that mode.** The other
        // is torrc (`HiddenServiceNonAnonymousMode` + `SocksPort 0`), which is
        // foreclosed by construction at the spawn site in `actor.rs` — six typed
        // options, no `extra_args` — not by this assertion. A future typed knob
        // added there would re-open it while this test stayed green, so the spawn
        // site carries a matching comment naming the coupling.
        for discard_pk in [false, true] {
            for pow in [
                OnionPow::Disabled,
                OnionPow::Enabled,
                OnionPow::EnabledTuned {
                    queue_rate: 1,
                    queue_burst: 2,
                },
            ] {
                let line = AddOnion::new(key(), loopback_port(), 2)
                    .with_flags(OnionFlags { discard_pk })
                    .with_pow(pow)
                    .to_wire_line();
                let lower = line.to_ascii_lowercase();
                assert!(
                    !lower.contains("nonanonymous"),
                    "non-anonymous serving must be unrepresentable: {}",
                    line.as_str()
                );
                assert!(
                    !lower.contains("singlehop"),
                    "single-hop serving must be unrepresentable: {}",
                    line.as_str()
                );
            }
        }
    }

    #[test]
    fn onion_line_never_detaches() {
        // Hard invariant 3, asserted over *every* representable flag combination —
        // which is the whole point of `Detach` being absent from `OnionFlags`
        // rather than merely unset at the call sites. If someone adds a `Detach`
        // member, this test starts failing for the combination that sets it.
        for discard_pk in [false, true] {
            let line = AddOnion::new(key(), loopback_port(), 2)
                .with_flags(OnionFlags { discard_pk })
                .to_wire_line();
            assert!(
                !line.to_ascii_lowercase().contains("detach"),
                "a detached onion outlives the wallet and keeps advertising the persona: {}",
                line.as_str()
            );
        }
    }

    #[test]
    fn rendered_line_is_single_line_and_injection_free() {
        // The property `to_wire` string-checks for `GETINFO`, obtained here by
        // construction: no component can contribute a CR, LF, or NUL, so the
        // rendered line cannot split into a second control command and desync the
        // FIFO reply correlation.
        let line = AddOnion::new(key(), loopback_port(), 8)
            .with_port(
                OnionPort::loopback(443, SocketAddr::from((Ipv6Addr::LOCALHOST, 9)))
                    .expect("::1 is loopback"),
            )
            .with_flags(OnionFlags { discard_pk: true })
            .to_wire_line();
        assert!(!line.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0));
        // IPv6 targets render bracketed, so the `,`-separated Port= argument stays
        // parseable (an unbracketed `::1:9` would be ambiguous).
        assert!(line.contains("Port=443,[::1]:9"), "{}", line.as_str());
    }

    #[test]
    fn onion_port_refuses_a_routable_target() {
        // Hard invariant 4: the serve endpoint is loopback-only, enforced where
        // the mapping is built. A routable target would make the endpoint
        // reachable *without* the rendezvous and attributable to the host's IP.
        assert!(
            OnionPort::loopback(80, SocketAddr::from((Ipv4Addr::new(10, 0, 0, 5), 80))).is_none()
        );
        assert!(
            OnionPort::loopback(80, SocketAddr::from((Ipv4Addr::new(0, 0, 0, 0), 80))).is_none(),
            "0.0.0.0 is a wildcard bind, not loopback"
        );
        assert!(OnionPort::loopback(
            80,
            SocketAddr::from((IpAddr::V6(Ipv6Addr::UNSPECIFIED), 80))
        )
        .is_none());
        assert!(OnionPort::loopback(80, SocketAddr::from((Ipv4Addr::LOCALHOST, 80))).is_some());
        assert!(OnionPort::loopback(80, SocketAddr::from((Ipv6Addr::LOCALHOST, 80))).is_some());
    }

    #[test]
    fn service_id_parse_accepts_only_v3_base32() {
        let ok = "a".repeat(SERVICE_ID_CHARS);
        assert!(ServiceId::parse(&ok).is_some());
        // Wrong length (v2 was 16 chars).
        assert!(ServiceId::parse(&"a".repeat(16)).is_none());
        assert!(ServiceId::parse(&"a".repeat(55)).is_none());
        // `.onion` suffix not stripped.
        assert!(ServiceId::parse(&format!("{}.onion", "a".repeat(SERVICE_ID_CHARS))).is_none());
        // Outside the base32 alphabet: `0`, `1`, `8`, `9` and uppercase are not.
        for bad in ['0', '1', '8', '9', 'A'] {
            let mut s = "a".repeat(SERVICE_ID_CHARS - 1);
            s.push(bad);
            assert!(ServiceId::parse(&s).is_none(), "{bad} must be rejected");
        }
        // Injection attempt from a hostile reply.
        assert!(ServiceId::parse("aaaa\r\nSETEVENTS STREAM").is_none());
    }

    #[test]
    fn parse_service_id_reads_the_reply_field() {
        let id = "b".repeat(SERVICE_ID_CHARS);
        let lines = vec![format!("ServiceID={id}"), "OK".to_owned()];
        assert_eq!(
            parse_service_id(&lines).expect("reply carries a service id"),
            ServiceId::parse(&id).expect("valid id")
        );
        // No ServiceID= line at all, and a malformed one, both fail closed.
        assert!(parse_service_id(&["OK".to_owned()]).is_none());
        assert!(parse_service_id(&["ServiceID=nope".to_owned()]).is_none());
    }

    #[test]
    fn evaluate_add_onion_reply_status_and_id_are_load_bearing() {
        use super::super::framing::ReplyFramer;

        let expected = ServiceId::parse(&"a".repeat(SERVICE_ID_CHARS)).expect("valid");
        let mut framer = ReplyFramer::new();
        framer.push_bytes(format!("250-ServiceID={}\r\n250 OK\r\n", expected.as_str()).as_bytes());
        let ok = framer.next_reply().expect("framed").expect("reply");
        assert_eq!(evaluate_add_onion_reply(&ok, &expected), Ok(()));

        let mut framer = ReplyFramer::new();
        framer.push_bytes(b"550 collision\r\n");
        let rejected = framer.next_reply().expect("framed").expect("reply");
        assert_eq!(
            evaluate_add_onion_reply(&rejected, &expected),
            Err(AddOnionReplyError::Rejected { status: 550 })
        );
    }

    #[test]
    fn secrets_redact_in_debug() {
        // rule 35: neither the key nor the service id may reach a log, an
        // assertion message, or a panic backtrace via `{:?}`.
        let k = key();
        let rendered = format!("{k:?}");
        assert_eq!(rendered, "OnionKey(<redacted>)");
        assert!(!rendered.contains("AAECAw"));

        let id = ServiceId::parse(&"c".repeat(SERVICE_ID_CHARS)).expect("valid id");
        let rendered = format!("{id:?}");
        assert_eq!(rendered, "ServiceId(<redacted>)");
        assert!(!rendered.contains(id.as_str()));

        // And the whole command, which holds the key, must not leak it either.
        let cmd = AddOnion::new(key(), loopback_port(), 2);
        assert!(!format!("{cmd:?}").contains("AAECAw"));
    }

    #[test]
    fn hostname_appends_the_onion_suffix() {
        let id = ServiceId::parse(&"d".repeat(SERVICE_ID_CHARS)).expect("valid id");
        assert_eq!(
            id.hostname(),
            format!("{}.onion", "d".repeat(SERVICE_ID_CHARS))
        );
    }
}
