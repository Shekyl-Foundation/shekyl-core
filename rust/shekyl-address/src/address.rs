// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shekyl address encoding and decoding.
//!
//! A Shekyl address consists of up to three Bech32m segments joined by `/`:
//!
//! 1. **Classical**:
//!    `<hrp>1<version><spend_key><view_key><msg_sign_pk><ek_bind_tag>` (~220 chars)
//! 2. **PQC-A**: `<pqc_a_hrp>1<first_half_ml_kem_key>` (~960 chars)
//! 3. **PQC-B**: `<pqc_b_hrp>1<second_half_ml_kem_key>` (~960 chars)
//!
//! Each segment stays within Bech32m's proven checksum detection range
//! (~1023 characters) — a per-payload invariant the `const _` asserts below
//! pin at compile time, so a future key-size increase (e.g. a V4 lattice key)
//! becomes a build error rather than a Bech32m checksum that validates but is
//! no longer proven to detect. The classical segment alone (without the tag,
//! 113 B) is sufficient for human identification and view-only wallets; the
//! PQC segments are machine-handled.
//!
//! ## `msg_sign_pk` — the post-quantum signing anchor (fork (ii))
//!
//! The fourth classical-segment field is the wallet's 48-byte
//! SLH-DSA-192s message-signing public key, inline and literal — no
//! commitment scheme, no `alg_id` registry (SM-R-8,
//! `docs/design/WALLET_MESSAGE_SIGNING.md`; freeze-window sign-off
//! 2026-08-13). It is what makes a transferable message signature
//! post-quantum *against the address*: verification takes both keys from
//! the address itself, so a recovered spend scalar cannot substitute its
//! own PQ key (SM-R-6 R6-a). Derived from the master seed scoped by
//! `(network, seed_format)` like every other wallet key (SM-R-4 R4-c) —
//! published keys must not link addresses across networks.
//!
//! ## `ek_bind_tag` — binding the PQC segments to the classical segment
//!
//! Each of the three segments carries its own independent Bech32m checksum,
//! which detects corruption *within* a segment but binds nothing *across*
//! them. Without more, a spliced address — classical from one party, PQC from
//! another — decodes clean and a payer builds an output to a mismatched key
//! (funds lost, undetected). The full-address classical segment therefore
//! carries a 16-byte `ek_bind_tag = cSHAKE256("shekyl/ek-bind-v1",
//! ml_kem_ek)[..16]`; decode reconstructs `ml_kem_ek` from the PQC segments and
//! rejects on mismatch. Each legitimate classical segment commits to *its own*
//! `ek`, so an accidental swap in either direction fails.
//!
//! It is a splice / transcription detector, **not** a cryptographic binding
//! against a preimage adversary: 16 bytes is 2^128 classical / 2^64 Grover, and
//! any adversary who can rewrite half the pasted string can substitute the
//! whole address for free (the compromised-origin limit no tag closes). Sized
//! for accident resistance with generous margin. The short display form
//! (113 B) omits the tag: it is a non-payable label with no PQC segments to
//! bind.

use bech32::{Bech32m, ByteIterExt, Fe32IterExt, Hrp};

use crate::network::{self, Network};

/// Current address version byte.
///
/// Still `0x01` after the 2026-08 layout correction, by ruling: the
/// 48-byte `msg_sign_pk` fourth field was added **in place** before any
/// address was deployed beyond the pre-genesis test estate — the same
/// disposition `MULTISIG_ADDRESS_VERSION` took for its never-deployed
/// draft. The design round that produced the correction called it
/// "address v2"; on the wire there is exactly one version, this one, and
/// the 65-byte draft layout never reaches the frozen record. Stale draft
/// strings fail closed as [`AddressError::BadLength`].
pub const ADDRESS_VERSION_V1: u8 = 0x01;

/// Ed25519 public key size; the classical payload carries a spend key and a
/// view key back to back.
const PUBKEY_LEN: usize = 32;

/// SLH-DSA-192s public key size — the message-signing anchor carried as
/// the fourth classical-segment field (see the module docs). A literal
/// here because this crate deliberately carries no crypto dependency;
/// `shekyl-crypto-pq` const-asserts it against its own crate-derived
/// `SLH_192S_PK_LEN`, so drift is a build error there.
pub const MSG_SIGN_PK_LEN: usize = 48;

/// Classical key-material total: spend + view + msg_sign_pk.
pub const CLASSICAL_PAYLOAD_LEN: usize = 2 * PUBKEY_LEN + MSG_SIGN_PK_LEN;

/// Length of the ek-binding tag carried in the full-address classical segment
/// (a domain-separated cSHAKE256 commitment to the ML-KEM encapsulation key,
/// truncated). See the module docs for the threat model and why 16 bytes.
pub const EK_BIND_TAG_LEN: usize = 16;

// Classical-segment byte layout:
// `version || spend || view || msg_sign_pk || [ek_bind_tag]`.
// Every offset and segment length is derived from the field sizes, so decode
// slicing never hard-codes a literal offset that could drift if the layout
// changes again.
/// Address version prefix length (one byte, `ADDRESS_VERSION_V1`).
const VERSION_LEN: usize = 1;
/// Offset of the spend key (immediately after the version prefix).
const SPEND_OFFSET: usize = VERSION_LEN;
/// Offset of the view key.
const VIEW_OFFSET: usize = SPEND_OFFSET + PUBKEY_LEN;
/// Offset of the message-signing public key (the fourth field).
const MSG_SIGN_PK_OFFSET: usize = VIEW_OFFSET + PUBKEY_LEN;
/// Length of the display/view-only classical segment (`version || spend ||
/// view || msg_sign_pk`); also the offset at which the `ek_bind_tag` begins
/// in the full form.
/// Private: [`BoundClassicalSegment`] is the layout's only owner, so no
/// caller outside this module needs to know where the fields sit.
const CLASSICAL_SEGMENT_LEN: usize = MSG_SIGN_PK_OFFSET + MSG_SIGN_PK_LEN;
/// Length of the full-address classical segment (adds the `ek_bind_tag`).
/// Fixed-width by construction — the message-signing preimage binds this
/// exact byte string (SM-R-3).
pub const CLASSICAL_BOUND_SEGMENT_LEN: usize = CLASSICAL_SEGMENT_LEN + EK_BIND_TAG_LEN;
/// The offset-derived layout must agree with the exported payload length.
const _: () = assert!(CLASSICAL_SEGMENT_LEN == VERSION_LEN + CLASSICAL_PAYLOAD_LEN);

/// Domain separator for the ek-binding tag. Genesis-frozen: a preimage change
/// is a new domain (`-v2`), never a silent reinterpretation. Not a consensus
/// generator DST, so it is intentionally absent from `FROZEN_DOMAIN_SEPARATORS`
/// (that list is for point-deriving DSTs); the freeze is this literal plus the
/// pinned KAT in the tests below.
const EK_BIND_DST: &[u8] = b"shekyl/ek-bind-v1";

/// ML-KEM-768 encapsulation key size.
pub const PQC_PAYLOAD_LEN: usize = 1184;

/// Split point for PQC payload (half of 1184).
const PQC_SPLIT: usize = 592;

/// Bech32m string length for a `payload_bytes`-byte payload under an
/// `hrp_len`-char HRP: `hrp + '1' separator + ceil(bytes*8/5) data chars +
/// 6-char checksum`. `const fn` so the ceiling below is a compile-time fact.
const fn bech32m_char_len(payload_bytes: usize, hrp_len: usize) -> usize {
    hrp_len + 1 + (payload_bytes * 8).div_ceil(5) + 6
}

/// Longest HRP across the PQC segments and networks (`sskpq2` / `tskpq2`).
const MAX_PQC_HRP_LEN: usize = 6;
/// Longest classical HRP across networks (`tshekyl` / `sshekyl`, 7 chars).
const MAX_CLASSICAL_HRP_LEN: usize = 7;

// Bech32m's BCH checksum is proven to detect errors only up to 1023 characters.
// Each segment must stay strictly under that bound, or its checksum can validate
// a corrupted string undetected. These fire at build time if any payload grows
// past what its segment can safely carry — the wall a KAT would otherwise find.
const _: () = assert!(bech32m_char_len(PQC_SPLIT, MAX_PQC_HRP_LEN) < 1023);
const _: () = assert!(bech32m_char_len(PQC_PAYLOAD_LEN - PQC_SPLIT, MAX_PQC_HRP_LEN) < 1023);
const _: () = assert!(bech32m_char_len(CLASSICAL_BOUND_SEGMENT_LEN, MAX_CLASSICAL_HRP_LEN) < 1023);

/// Separator between segments.
pub const SEGMENT_SEPARATOR: char = '/';

/// Errors specific to address encoding/decoding.
#[derive(Debug, thiserror::Error)]
pub enum AddressError {
    #[error("{0}")]
    Encoding(String),

    #[error("wrong HRP: expected '{expected}', got '{got}'")]
    WrongHrp { expected: String, got: String },

    #[error("unsupported address version 0x{version:02x} -- update your wallet")]
    UnsupportedVersion { version: u8 },

    #[error("expected {expected} bytes in {segment}, got {got}")]
    BadLength {
        segment: &'static str,
        expected: usize,
        got: usize,
    },

    #[error("expected 1 or 3 segments, got {0}")]
    BadSegmentCount(usize),

    #[error("network mismatch: address is {addr_net}, expected {expected_net}")]
    NetworkMismatch {
        addr_net: Network,
        expected_net: Network,
    },

    #[error("unrecognized address HRP '{0}'")]
    UnknownHrp(String),

    #[error(
        "ek-binding tag mismatch: the classical and PQC segments do not belong \
         to the same address (spliced or corrupted)"
    )]
    EkBindMismatch,
}

/// A decoded Shekyl address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShekylAddress {
    pub network: Network,
    pub version: u8,
    pub spend_key: [u8; 32],
    pub view_key: [u8; 32],
    /// SLH-DSA-192s message-signing public key — the PQ signing anchor
    /// (fourth classical-segment field, see the module docs).
    pub msg_sign_pk: [u8; MSG_SIGN_PK_LEN],
    pub ml_kem_encap_key: Vec<u8>,
}

fn bech32m_encode(hrp: &Hrp, data: &[u8]) -> String {
    data.iter()
        .copied()
        .bytes_to_fes()
        .with_checksum::<Bech32m>(hrp)
        .chars()
        .collect()
}

fn bech32m_decode(encoded: &str) -> Result<(Hrp, Vec<u8>), AddressError> {
    let (hrp, data) = bech32::decode(encoded)
        .map_err(|e| AddressError::Encoding(format!("bech32m decode: {e}")))?;
    Ok((hrp, data))
}

fn parse_hrp(s: &str) -> Result<Hrp, AddressError> {
    Hrp::parse(s).map_err(|e| AddressError::Encoding(format!("invalid HRP '{s}': {e}")))
}

/// The ek-binding tag: `cSHAKE256("shekyl/ek-bind-v1", ml_kem_ek)` truncated to
/// [`EK_BIND_TAG_LEN`]. Commits the classical segment to the PQC key material.
fn ek_bind_tag(ml_kem_encap_key: &[u8]) -> [u8; EK_BIND_TAG_LEN] {
    let digest = shekyl_crypto_hash::cshake256_32(EK_BIND_DST, ml_kem_encap_key);
    let mut tag = [0u8; EK_BIND_TAG_LEN];
    tag.copy_from_slice(&digest[..EK_BIND_TAG_LEN]);
    tag
}

/// The full bound classical segment: `version ‖ spend ‖ view ‖
/// ek_bind_tag`.
///
/// # Single owner
///
/// This type owns that byte layout for the whole tree. Encoding an
/// address goes through it ([`ShekylAddress::encode_classical_bound`]),
/// and so does the byte string the message-signing preimage binds
/// (`WALLET_MESSAGE_SIGNING.md` SM-R-3). The two must never be assembled
/// independently: SM-R-3 anticipates a v2 layout under fork (ii), and a
/// second copy would keep emitting v1 bytes after the encoder moved,
/// producing signatures no verifier reconstructing from the user's
/// address string could reproduce.
///
/// Fixed-width today because the v1 layout is compile-time fixed; when
/// v2 lands, this type is the one place that changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundClassicalSegment([u8; CLASSICAL_BOUND_SEGMENT_LEN]);

impl BoundClassicalSegment {
    /// Assemble from already-validated field values. Private: the layout
    /// is written here exactly once.
    fn assemble(
        version: u8,
        spend_key: &[u8; PUBKEY_LEN],
        view_key: &[u8; PUBKEY_LEN],
        msg_sign_pk: &[u8; MSG_SIGN_PK_LEN],
        ml_kem_encap_key: &[u8],
    ) -> Self {
        let mut out = [0u8; CLASSICAL_BOUND_SEGMENT_LEN];
        out[0] = version;
        out[SPEND_OFFSET..VIEW_OFFSET].copy_from_slice(spend_key);
        out[VIEW_OFFSET..MSG_SIGN_PK_OFFSET].copy_from_slice(view_key);
        out[MSG_SIGN_PK_OFFSET..CLASSICAL_SEGMENT_LEN].copy_from_slice(msg_sign_pk);
        out[CLASSICAL_SEGMENT_LEN..].copy_from_slice(&ek_bind_tag(ml_kem_encap_key));
        Self(out)
    }

    /// Rebuild from the 65-byte classical address payload and the ML-KEM
    /// encapsulation key — the shape the wallet holds at signing time.
    ///
    /// # Errors
    ///
    /// [`AddressError::BadLength`] if either input is the wrong size,
    /// [`AddressError::UnsupportedVersion`] if the payload does not lead
    /// with a version this build understands. The version check matters:
    /// it is what stops a future v2 payload from being silently
    /// reassembled into a v1-shaped segment here.
    pub fn from_address_parts(
        classical_address_bytes: &[u8],
        ml_kem_encap_key: &[u8],
    ) -> Result<Self, AddressError> {
        if classical_address_bytes.len() != CLASSICAL_SEGMENT_LEN {
            return Err(AddressError::BadLength {
                segment: "classical address bytes",
                expected: CLASSICAL_SEGMENT_LEN,
                got: classical_address_bytes.len(),
            });
        }
        if ml_kem_encap_key.len() != PQC_PAYLOAD_LEN {
            return Err(AddressError::BadLength {
                segment: "ML-KEM encap key",
                expected: PQC_PAYLOAD_LEN,
                got: ml_kem_encap_key.len(),
            });
        }
        let version = classical_address_bytes[0];
        if version != ADDRESS_VERSION_V1 {
            return Err(AddressError::UnsupportedVersion { version });
        }
        let spend: &[u8; PUBKEY_LEN] = classical_address_bytes[SPEND_OFFSET..VIEW_OFFSET]
            .try_into()
            .expect("length checked above");
        let view: &[u8; PUBKEY_LEN] = classical_address_bytes[VIEW_OFFSET..MSG_SIGN_PK_OFFSET]
            .try_into()
            .expect("length checked above");
        let msg_sign_pk: &[u8; MSG_SIGN_PK_LEN] = classical_address_bytes
            [MSG_SIGN_PK_OFFSET..CLASSICAL_SEGMENT_LEN]
            .try_into()
            .expect("length checked above");
        Ok(Self::assemble(
            version,
            spend,
            view,
            msg_sign_pk,
            ml_kem_encap_key,
        ))
    }

    /// The segment bytes — what the message-signing preimage binds.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; CLASSICAL_BOUND_SEGMENT_LEN] {
        &self.0
    }

    /// The address's Ed25519 spend key, read out of the segment rather
    /// than carried alongside it. Verifiers need the spend key *and* the
    /// segment; taking them as independent inputs is what lets a caller
    /// check a signature against one address while naming another.
    #[must_use]
    pub fn spend_key(&self) -> &[u8; PUBKEY_LEN] {
        self.0[SPEND_OFFSET..VIEW_OFFSET]
            .try_into()
            .expect("fixed-width layout")
    }

    /// The address's SLH-DSA-192s message-signing public key, read out
    /// of the segment for the same reason as [`Self::spend_key`]: message
    /// verification must take both keys from the byte string the
    /// signature binds, never from a parameter a caller could point
    /// elsewhere (SM-R-6 R6-a).
    #[must_use]
    pub fn msg_sign_pk(&self) -> &[u8; MSG_SIGN_PK_LEN] {
        self.0[MSG_SIGN_PK_OFFSET..CLASSICAL_SEGMENT_LEN]
            .try_into()
            .expect("fixed-width layout")
    }
}

impl ShekylAddress {
    /// Create a new address for the given network.
    pub fn new(
        network: Network,
        spend_key: [u8; 32],
        view_key: [u8; 32],
        msg_sign_pk: [u8; MSG_SIGN_PK_LEN],
        ml_kem_encap_key: Vec<u8>,
    ) -> Self {
        ShekylAddress {
            network,
            version: ADDRESS_VERSION_V1,
            spend_key,
            view_key,
            msg_sign_pk,
            ml_kem_encap_key,
        }
    }

    /// Encode the full address as `<classical>/<pqc_a>/<pqc_b>`.
    pub fn encode(&self) -> Result<String, AddressError> {
        if self.ml_kem_encap_key.len() != PQC_PAYLOAD_LEN {
            return Err(AddressError::BadLength {
                segment: "ML-KEM encap key",
                expected: PQC_PAYLOAD_LEN,
                got: self.ml_kem_encap_key.len(),
            });
        }

        // Full-address classical segment carries the ek-binding tag; the ek
        // length was validated above, so the tag commits to a well-formed key.
        let classical = self.encode_classical_bound()?;

        let hrp_a = parse_hrp(network::pqc_a_hrp(self.network))?;
        let hrp_b = parse_hrp(network::pqc_b_hrp(self.network))?;

        let pqc_a = bech32m_encode(&hrp_a, &self.ml_kem_encap_key[..PQC_SPLIT]);
        let pqc_b = bech32m_encode(&hrp_b, &self.ml_kem_encap_key[PQC_SPLIT..]);

        Ok(format!(
            "{classical}{SEGMENT_SEPARATOR}{pqc_a}{SEGMENT_SEPARATOR}{pqc_b}"
        ))
    }

    /// Encode just the classical segment (short form for display). This is
    /// the non-payable label form: `version || spend || view || msg_sign_pk`,
    /// no ek-binding tag (there are no PQC segments to bind).
    pub fn encode_classical_display(&self) -> Result<String, AddressError> {
        self.encode_classical()
    }

    fn encode_classical(&self) -> Result<String, AddressError> {
        let hrp = parse_hrp(network::classical_hrp(self.network))?;
        let mut payload = Vec::with_capacity(CLASSICAL_SEGMENT_LEN);
        payload.push(self.version);
        payload.extend_from_slice(&self.spend_key);
        payload.extend_from_slice(&self.view_key);
        payload.extend_from_slice(&self.msg_sign_pk);
        Ok(bech32m_encode(&hrp, &payload))
    }

    /// Encode the full-address classical segment: `version || spend || view ||
    /// ek_bind_tag`. Caller must have validated `ml_kem_encap_key`'s length.
    /// The bound classical segment this address encodes — the byte
    /// string a message signature over this address binds (SM-R-3).
    /// Infallible: every field was validated when the address was built
    /// or parsed.
    #[must_use]
    pub fn bound_classical_segment(&self) -> BoundClassicalSegment {
        BoundClassicalSegment::assemble(
            self.version,
            &self.spend_key,
            &self.view_key,
            &self.msg_sign_pk,
            &self.ml_kem_encap_key,
        )
    }

    fn encode_classical_bound(&self) -> Result<String, AddressError> {
        let hrp = parse_hrp(network::classical_hrp(self.network))?;
        Ok(bech32m_encode(
            &hrp,
            self.bound_classical_segment().as_bytes(),
        ))
    }

    /// Decode a Shekyl address from its encoded form.
    ///
    /// Accepts `<classical>/<pqc_a>/<pqc_b>` (full) or `<classical>` (display-only).
    /// The network is inferred from the classical segment's HRP.
    pub fn decode(encoded: &str) -> Result<Self, AddressError> {
        let parts: Vec<&str> = encoded.split(SEGMENT_SEPARATOR).collect();

        match parts.len() {
            1 => Self::decode_classical_only(parts[0]),
            3 => Self::decode_full(parts[0], parts[1], parts[2]),
            n => Err(AddressError::BadSegmentCount(n)),
        }
    }

    /// Decode and validate that the address belongs to the expected network.
    pub fn decode_for_network(encoded: &str, expected: Network) -> Result<Self, AddressError> {
        let addr = Self::decode(encoded)?;
        if addr.network != expected {
            return Err(AddressError::NetworkMismatch {
                addr_net: addr.network,
                expected_net: expected,
            });
        }
        Ok(addr)
    }

    fn decode_full(classical: &str, pqc_a: &str, pqc_b: &str) -> Result<Self, AddressError> {
        let (c_hrp, c_data) = bech32m_decode(classical)?;
        let net = network::network_from_hrp(&c_hrp.to_string())
            .ok_or_else(|| AddressError::UnknownHrp(c_hrp.to_string()))?;

        let expected_a = parse_hrp(network::pqc_a_hrp(net))?;
        let expected_b = parse_hrp(network::pqc_b_hrp(net))?;

        let (a_hrp, a_data) = bech32m_decode(pqc_a)?;
        if a_hrp != expected_a {
            return Err(AddressError::WrongHrp {
                expected: network::pqc_a_hrp(net).to_string(),
                got: a_hrp.to_string(),
            });
        }

        let (b_hrp, b_data) = bech32m_decode(pqc_b)?;
        if b_hrp != expected_b {
            return Err(AddressError::WrongHrp {
                expected: network::pqc_b_hrp(net).to_string(),
                got: b_hrp.to_string(),
            });
        }

        // Full-address classical segment is `version || spend || view || tag`.
        if c_data.len() != CLASSICAL_BOUND_SEGMENT_LEN {
            return Err(AddressError::BadLength {
                segment: "classical",
                expected: CLASSICAL_BOUND_SEGMENT_LEN,
                got: c_data.len(),
            });
        }

        let version = c_data[0];
        if version != ADDRESS_VERSION_V1 {
            return Err(AddressError::UnsupportedVersion { version });
        }

        let mut spend_key = [0u8; PUBKEY_LEN];
        let mut view_key = [0u8; PUBKEY_LEN];
        let mut msg_sign_pk = [0u8; MSG_SIGN_PK_LEN];
        spend_key.copy_from_slice(&c_data[SPEND_OFFSET..VIEW_OFFSET]);
        view_key.copy_from_slice(&c_data[VIEW_OFFSET..MSG_SIGN_PK_OFFSET]);
        msg_sign_pk.copy_from_slice(&c_data[MSG_SIGN_PK_OFFSET..CLASSICAL_SEGMENT_LEN]);
        let carried_tag = &c_data[CLASSICAL_SEGMENT_LEN..CLASSICAL_BOUND_SEGMENT_LEN];

        let mut ml_kem_encap_key = Vec::with_capacity(PQC_PAYLOAD_LEN);
        ml_kem_encap_key.extend_from_slice(&a_data);
        ml_kem_encap_key.extend_from_slice(&b_data);

        if ml_kem_encap_key.len() != PQC_PAYLOAD_LEN {
            return Err(AddressError::BadLength {
                segment: "PQC total",
                expected: PQC_PAYLOAD_LEN,
                got: ml_kem_encap_key.len(),
            });
        }

        // Bind the PQC segments to this classical segment: the tag committed to
        // `ml_kem_ek` at encode time must match the key reconstructed from the
        // PQC segments. A spliced or corrupted address fails here instead of
        // silently yielding a mismatched encapsulation key.
        if carried_tag != ek_bind_tag(&ml_kem_encap_key) {
            return Err(AddressError::EkBindMismatch);
        }

        Ok(ShekylAddress {
            network: net,
            version,
            spend_key,
            view_key,
            msg_sign_pk,
            ml_kem_encap_key,
        })
    }

    fn decode_classical_only(encoded: &str) -> Result<Self, AddressError> {
        let (c_hrp, c_data) = bech32m_decode(encoded)?;
        let net = network::network_from_hrp(&c_hrp.to_string())
            .ok_or_else(|| AddressError::UnknownHrp(c_hrp.to_string()))?;

        if c_data.len() != CLASSICAL_SEGMENT_LEN {
            return Err(AddressError::BadLength {
                segment: "classical",
                expected: CLASSICAL_SEGMENT_LEN,
                got: c_data.len(),
            });
        }

        let version = c_data[0];
        if version != ADDRESS_VERSION_V1 {
            return Err(AddressError::UnsupportedVersion { version });
        }

        let mut spend_key = [0u8; PUBKEY_LEN];
        let mut view_key = [0u8; PUBKEY_LEN];
        let mut msg_sign_pk = [0u8; MSG_SIGN_PK_LEN];
        spend_key.copy_from_slice(&c_data[SPEND_OFFSET..VIEW_OFFSET]);
        view_key.copy_from_slice(&c_data[VIEW_OFFSET..MSG_SIGN_PK_OFFSET]);
        msg_sign_pk.copy_from_slice(&c_data[MSG_SIGN_PK_OFFSET..CLASSICAL_SEGMENT_LEN]);

        Ok(ShekylAddress {
            network: net,
            version,
            spend_key,
            view_key,
            msg_sign_pk,
            ml_kem_encap_key: Vec::new(),
        })
    }

    /// Whether this address has the full PQC segment (required for sending).
    pub fn has_pqc_segment(&self) -> bool {
        self.ml_kem_encap_key.len() == PQC_PAYLOAD_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_address(net: Network) -> ShekylAddress {
        ShekylAddress {
            network: net,
            version: ADDRESS_VERSION_V1,
            spend_key: [0xaa; 32],
            view_key: [0xbb; 32],
            msg_sign_pk: [0xee; MSG_SIGN_PK_LEN],
            ml_kem_encap_key: vec![0xcc; PQC_PAYLOAD_LEN],
        }
    }

    #[test]
    fn encode_decode_roundtrip_mainnet() {
        let addr = make_test_address(Network::Mainnet);
        let encoded = addr.encode().unwrap();
        let parts: Vec<&str> = encoded.split('/').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[0].starts_with("shekyl1"));
        assert!(parts[1].starts_with("skpq1"));
        assert!(parts[2].starts_with("skpq21"));

        let decoded = ShekylAddress::decode(&encoded).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn encode_decode_roundtrip_testnet() {
        let addr = make_test_address(Network::Testnet);
        let encoded = addr.encode().unwrap();
        let parts: Vec<&str> = encoded.split('/').collect();
        assert!(parts[0].starts_with("tshekyl1"));
        assert!(parts[1].starts_with("tskpq1"));
        assert!(parts[2].starts_with("tskpq21"));

        let decoded = ShekylAddress::decode(&encoded).unwrap();
        assert_eq!(addr, decoded);
        assert_eq!(decoded.network, Network::Testnet);
    }

    #[test]
    fn encode_decode_roundtrip_stagenet() {
        let addr = make_test_address(Network::Stagenet);
        let encoded = addr.encode().unwrap();
        let parts: Vec<&str> = encoded.split('/').collect();
        assert!(parts[0].starts_with("sshekyl1"));
        assert!(parts[1].starts_with("sskpq1"));
        assert!(parts[2].starts_with("sskpq21"));

        let decoded = ShekylAddress::decode(&encoded).unwrap();
        assert_eq!(addr, decoded);
        assert_eq!(decoded.network, Network::Stagenet);
    }

    #[test]
    fn classical_display_shorter() {
        let addr = make_test_address(Network::Mainnet);
        let full = addr.encode().unwrap();
        let classical = addr.encode_classical_display().unwrap();
        assert!(classical.len() < full.len());
        assert!(classical.starts_with("shekyl1"));
    }

    #[test]
    fn classical_only_roundtrip() {
        let addr = make_test_address(Network::Mainnet);
        let classical = addr.encode_classical_display().unwrap();
        let decoded = ShekylAddress::decode(&classical).unwrap();
        assert_eq!(decoded.spend_key, addr.spend_key);
        assert_eq!(decoded.view_key, addr.view_key);
        assert_eq!(decoded.network, Network::Mainnet);
        assert!(!decoded.has_pqc_segment());
    }

    #[test]
    fn decode_for_network_enforces_match() {
        let addr = make_test_address(Network::Mainnet);
        let encoded = addr.encode().unwrap();

        assert!(ShekylAddress::decode_for_network(&encoded, Network::Mainnet).is_ok());
        let err = ShekylAddress::decode_for_network(&encoded, Network::Testnet).unwrap_err();
        assert!(matches!(err, AddressError::NetworkMismatch { .. }));
    }

    #[test]
    fn rejects_wrong_version() {
        let mut addr = make_test_address(Network::Mainnet);
        addr.version = 0x02;
        if let Ok(enc) = addr.encode() {
            assert!(ShekylAddress::decode(&enc).is_err());
        }
    }

    #[test]
    fn rejects_invalid_pqc_length() {
        let addr = ShekylAddress {
            network: Network::Mainnet,
            version: ADDRESS_VERSION_V1,
            spend_key: [0xaa; 32],
            view_key: [0xbb; 32],
            msg_sign_pk: [0xee; MSG_SIGN_PK_LEN],
            ml_kem_encap_key: vec![0xcc; 100],
        };
        assert!(addr.encode().is_err());
    }

    #[test]
    fn has_pqc_segment_check() {
        assert!(make_test_address(Network::Mainnet).has_pqc_segment());

        let partial = ShekylAddress {
            network: Network::Mainnet,
            version: ADDRESS_VERSION_V1,
            spend_key: [0xaa; 32],
            view_key: [0xbb; 32],
            msg_sign_pk: [0xee; MSG_SIGN_PK_LEN],
            ml_kem_encap_key: Vec::new(),
        };
        assert!(!partial.has_pqc_segment());
    }

    #[test]
    fn each_segment_within_bech32m_limit() {
        let addr = make_test_address(Network::Mainnet);
        let encoded = addr.encode().unwrap();
        for (i, part) in encoded.split(SEGMENT_SEPARATOR).enumerate() {
            assert!(
                part.len() < 1023,
                "segment {i} exceeds Bech32m limit: {} chars",
                part.len()
            );
        }
    }

    #[test]
    fn decode_rejects_wrong_segment_count() {
        let result = ShekylAddress::decode("shekyl1abc/skpq1def");
        assert!(result.is_err());
    }

    #[test]
    fn decode_rejects_empty_string() {
        assert!(ShekylAddress::decode("").is_err());
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(ShekylAddress::decode("not_a_valid_address").is_err());
        assert!(ShekylAddress::decode("shekyl1invalidchecksum").is_err());
    }

    #[test]
    fn cross_network_pqc_hrp_mismatch_rejected() {
        let addr = make_test_address(Network::Mainnet);
        let encoded = addr.encode().unwrap();
        let parts: Vec<&str> = encoded.split('/').collect();

        // Construct a frankenstein with mainnet classical + testnet PQC
        let testnet_addr = make_test_address(Network::Testnet);
        let testnet_encoded = testnet_addr.encode().unwrap();
        let testnet_parts: Vec<&str> = testnet_encoded.split('/').collect();

        let mixed = format!("{}/{}/{}", parts[0], testnet_parts[1], testnet_parts[2]);
        assert!(ShekylAddress::decode(&mixed).is_err());
    }

    #[test]
    fn new_constructor_sets_v1() {
        let addr = ShekylAddress::new(
            Network::Mainnet,
            [0x11; 32],
            [0x22; 32],
            [0x44; MSG_SIGN_PK_LEN],
            vec![0x33; PQC_PAYLOAD_LEN],
        );
        assert_eq!(addr.version, ADDRESS_VERSION_V1);
        assert_eq!(addr.network, Network::Mainnet);
    }

    #[test]
    fn different_keys_produce_different_addresses() {
        let addr1 = make_test_address(Network::Mainnet);
        let mut addr2 = make_test_address(Network::Mainnet);
        addr2.spend_key = [0xdd; 32];
        let enc1 = addr1.encode().unwrap();
        let enc2 = addr2.encode().unwrap();
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn different_networks_produce_different_addresses() {
        let main = make_test_address(Network::Mainnet);
        let test = make_test_address(Network::Testnet);
        assert_ne!(main.encode().unwrap(), test.encode().unwrap());
    }

    #[test]
    fn ek_bind_splice_rejected() {
        // Same network (HRP checks pass) but different PQC keys, so the failure
        // is the ek-binding tag, not an HRP mismatch. Splicing Alice's classical
        // segment onto Bob's PQC segments must be rejected — the live burn.
        let alice = ShekylAddress::new(
            Network::Mainnet,
            [0x01; 32],
            [0x02; 32],
            [0x05; MSG_SIGN_PK_LEN],
            vec![0xcc; PQC_PAYLOAD_LEN],
        );
        let bob = ShekylAddress::new(
            Network::Mainnet,
            [0x03; 32],
            [0x04; 32],
            [0x06; MSG_SIGN_PK_LEN],
            vec![0xdd; PQC_PAYLOAD_LEN],
        );

        let alice_enc = alice.encode().unwrap();
        let bob_enc = bob.encode().unwrap();
        let a: Vec<&str> = alice_enc.split('/').collect();
        let b: Vec<&str> = bob_enc.split('/').collect();

        // Alice's classical (tag commits to Alice's ek) + Bob's PQC segments.
        let spliced = format!("{}/{}/{}", a[0], b[1], b[2]);
        assert!(matches!(
            ShekylAddress::decode(&spliced),
            Err(AddressError::EkBindMismatch)
        ));

        // The un-spliced originals still round-trip.
        assert_eq!(ShekylAddress::decode(&alice_enc).unwrap(), alice);
        assert_eq!(ShekylAddress::decode(&bob_enc).unwrap(), bob);
    }

    #[test]
    fn ek_bind_tag_kat() {
        // Genesis-frozen preimage: cSHAKE256("shekyl/ek-bind-v1", ek)[..16].
        // Fixed vector: ek[i] = (i % 256) over the 1184-byte ML-KEM-768 length.
        // Cross-implementer KAT — any change to the DST, the primitive, the
        // truncation, or the ek length moves this and fails the build's tests.
        let ek: Vec<u8> = (0u8..=255).cycle().take(PQC_PAYLOAD_LEN).collect();
        let tag = ek_bind_tag(&ek);
        let hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "f60b83cfc93df3d80757ab13f087bdb1");
    }

    /// The signing-side segment and the encoding-side segment are the
    /// same bytes — checked against the *encoder's* output decoded back
    /// from bech32m, not against a second hand-assembly. This is the
    /// tripwire that fired when the fork-(ii) layout correction landed
    /// (msg_sign_pk as the fourth field), exactly as designed: a layout
    /// move must fail here instead of silently letting the wallet sign
    /// over bytes no verifier can reconstruct from the address string.
    #[test]
    fn signing_segment_matches_the_encoded_address_segment() {
        let addr = make_test_address(Network::Mainnet);
        let encoded = addr.encode().unwrap();
        let classical = encoded.split(SEGMENT_SEPARATOR).next().unwrap();
        let (_hrp, from_encoder) = bech32m_decode(classical).unwrap();

        let mut payload = Vec::with_capacity(CLASSICAL_SEGMENT_LEN);
        payload.push(addr.version);
        payload.extend_from_slice(&addr.spend_key);
        payload.extend_from_slice(&addr.view_key);
        payload.extend_from_slice(&addr.msg_sign_pk);
        let from_signer =
            BoundClassicalSegment::from_address_parts(&payload, &addr.ml_kem_encap_key).unwrap();

        assert_eq!(from_encoder, from_signer.as_bytes());
        assert_eq!(from_signer.spend_key(), &addr.spend_key);
        assert_eq!(from_signer.msg_sign_pk(), &addr.msg_sign_pk);
    }

    /// A payload whose version byte this build does not know is refused,
    /// not silently reassembled into a v1-shaped segment. The payload is
    /// full-length so the refusal is the version check itself, never a
    /// length artifact.
    #[test]
    fn signing_segment_refuses_unknown_address_version() {
        let addr = make_test_address(Network::Mainnet);
        let mut payload = Vec::with_capacity(CLASSICAL_SEGMENT_LEN);
        payload.push(0x02);
        payload.extend_from_slice(&addr.spend_key);
        payload.extend_from_slice(&addr.view_key);
        payload.extend_from_slice(&addr.msg_sign_pk);
        assert!(matches!(
            BoundClassicalSegment::from_address_parts(&payload, &addr.ml_kem_encap_key),
            Err(AddressError::UnsupportedVersion { version: 0x02 })
        ));
    }

    /// The 65-byte draft layout (pre-correction: no msg_sign_pk field)
    /// fails closed as a length error — the ruled disposition for stale
    /// pre-genesis test-estate strings.
    #[test]
    fn draft_65_byte_payload_fails_closed() {
        let addr = make_test_address(Network::Mainnet);
        let mut payload = Vec::new();
        payload.push(addr.version);
        payload.extend_from_slice(&addr.spend_key);
        payload.extend_from_slice(&addr.view_key);
        assert!(matches!(
            BoundClassicalSegment::from_address_parts(&payload, &addr.ml_kem_encap_key),
            Err(AddressError::BadLength { .. })
        ));
    }
}
