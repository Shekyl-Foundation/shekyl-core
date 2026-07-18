// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shekyl address encoding and decoding.
//!
//! A Shekyl address consists of up to three Bech32m segments joined by `/`:
//!
//! 1. **Classical**: `<hrp>1<version><spend_key><view_key><ek_bind_tag>` (~140 chars)
//! 2. **PQC-A**: `<pqc_a_hrp>1<first_half_ml_kem_key>` (~960 chars)
//! 3. **PQC-B**: `<pqc_b_hrp>1<second_half_ml_kem_key>` (~960 chars)
//!
//! Each segment stays within Bech32m's proven checksum detection range
//! (~1023 characters) — a per-payload invariant the `const _` asserts below
//! pin at compile time, so a future key-size increase (e.g. a V4 lattice key)
//! becomes a build error rather than a Bech32m checksum that validates but is
//! no longer proven to detect. The classical segment alone (without the tag,
//! 65 B) is sufficient for human identification and view-only wallets; the PQC
//! segments are machine-handled.
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
//! for accident resistance with generous margin. The short display form (65 B)
//! omits the tag: it is a non-payable label with no PQC segments to bind.

use bech32::{Bech32m, ByteIterExt, Fe32IterExt, Hrp};

use crate::network::{self, Network};

/// Current address version byte.
pub const ADDRESS_VERSION_V1: u8 = 0x01;

/// Ed25519 spend + view key total size.
pub const CLASSICAL_PAYLOAD_LEN: usize = 64;

/// Length of the ek-binding tag carried in the full-address classical segment
/// (a domain-separated cSHAKE256 commitment to the ML-KEM encapsulation key,
/// truncated). See the module docs for the threat model and why 16 bytes.
pub const EK_BIND_TAG_LEN: usize = 16;

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
const _: () = assert!(
    bech32m_char_len(
        1 + CLASSICAL_PAYLOAD_LEN + EK_BIND_TAG_LEN,
        MAX_CLASSICAL_HRP_LEN
    ) < 1023
);

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

impl ShekylAddress {
    /// Create a new address for the given network.
    pub fn new(
        network: Network,
        spend_key: [u8; 32],
        view_key: [u8; 32],
        ml_kem_encap_key: Vec<u8>,
    ) -> Self {
        ShekylAddress {
            network,
            version: ADDRESS_VERSION_V1,
            spend_key,
            view_key,
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

    /// Encode just the classical segment (short form for display). This is the
    /// non-payable label form: `version || spend || view`, no ek-binding tag
    /// (there are no PQC segments to bind).
    pub fn encode_classical_display(&self) -> Result<String, AddressError> {
        self.encode_classical()
    }

    fn encode_classical(&self) -> Result<String, AddressError> {
        let hrp = parse_hrp(network::classical_hrp(self.network))?;
        let mut payload = Vec::with_capacity(1 + CLASSICAL_PAYLOAD_LEN);
        payload.push(self.version);
        payload.extend_from_slice(&self.spend_key);
        payload.extend_from_slice(&self.view_key);
        Ok(bech32m_encode(&hrp, &payload))
    }

    /// Encode the full-address classical segment: `version || spend || view ||
    /// ek_bind_tag`. Caller must have validated `ml_kem_encap_key`'s length.
    fn encode_classical_bound(&self) -> Result<String, AddressError> {
        let hrp = parse_hrp(network::classical_hrp(self.network))?;
        let mut payload = Vec::with_capacity(1 + CLASSICAL_PAYLOAD_LEN + EK_BIND_TAG_LEN);
        payload.push(self.version);
        payload.extend_from_slice(&self.spend_key);
        payload.extend_from_slice(&self.view_key);
        payload.extend_from_slice(&ek_bind_tag(&self.ml_kem_encap_key));
        Ok(bech32m_encode(&hrp, &payload))
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
        let expected_classical_len = 1 + CLASSICAL_PAYLOAD_LEN + EK_BIND_TAG_LEN;
        if c_data.len() != expected_classical_len {
            return Err(AddressError::BadLength {
                segment: "classical",
                expected: expected_classical_len,
                got: c_data.len(),
            });
        }

        let version = c_data[0];
        if version != ADDRESS_VERSION_V1 {
            return Err(AddressError::UnsupportedVersion { version });
        }

        let mut spend_key = [0u8; 32];
        let mut view_key = [0u8; 32];
        spend_key.copy_from_slice(&c_data[1..33]);
        view_key.copy_from_slice(&c_data[33..65]);
        let carried_tag = &c_data[65..65 + EK_BIND_TAG_LEN];

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
            ml_kem_encap_key,
        })
    }

    fn decode_classical_only(encoded: &str) -> Result<Self, AddressError> {
        let (c_hrp, c_data) = bech32m_decode(encoded)?;
        let net = network::network_from_hrp(&c_hrp.to_string())
            .ok_or_else(|| AddressError::UnknownHrp(c_hrp.to_string()))?;

        let expected_len = 1 + CLASSICAL_PAYLOAD_LEN;
        if c_data.len() != expected_len {
            return Err(AddressError::BadLength {
                segment: "classical",
                expected: expected_len,
                got: c_data.len(),
            });
        }

        let version = c_data[0];
        if version != ADDRESS_VERSION_V1 {
            return Err(AddressError::UnsupportedVersion { version });
        }

        let mut spend_key = [0u8; 32];
        let mut view_key = [0u8; 32];
        spend_key.copy_from_slice(&c_data[1..33]);
        view_key.copy_from_slice(&c_data[33..65]);

        Ok(ShekylAddress {
            network: net,
            version,
            spend_key,
            view_key,
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
            vec![0xcc; PQC_PAYLOAD_LEN],
        );
        let bob = ShekylAddress::new(
            Network::Mainnet,
            [0x03; 32],
            [0x04; 32],
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
}
