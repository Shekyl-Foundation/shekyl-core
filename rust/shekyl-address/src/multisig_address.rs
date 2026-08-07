// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Multisig address encoding, fingerprint, and provenance (PQC_MULTISIG.md SS6).
//!
//! Multisig addresses are **file-based**: the canonical payload
//! (`HEADER_LEN + 2 * GROUP_POINT_LEN + N * PER_PARTICIPANT_LEN` = 70 + N * 1216
//! bytes) is written to a file and transferred via an authenticated channel. It
//! is not a Bech32m string — at E′ sizes (~4019 chars for a 2-of-N) it exceeds
//! Bech32m's ~1023-char checksum-validity limit and would not round-trip. What
//! *is* Bech32m-encoded, under the `shekyl1m` / `shekyltest1m` / `sshekyl1m` HRP
//! family, is the fixed-size **fingerprint** (32 B → 67 chars, QR-able): the
//! short, human-verifiable, shareable group identifier. Integrity rides that
//! fingerprint, not a full-address string or a stored checksum.
//!
//! # Option E′: the address carries the group's two points
//!
//! Under E′ a payer constructs `O = ho·G + B_group + y_out·T`
//! (`shekyl-crypto-pq::output`), so the address **must** carry `B_group` and
//! `Y_group` or an output cannot be built at all. Option D never needed them —
//! it derived `O` from `spend_auth_pubkeys[assigned]`, per-output — which is why
//! the D-era payload has neither. They are the group's **long-term** public
//! state, unlike the per-output KEM-derived leaf keys the address deliberately
//! does not carry (MSW-8).
//!
//! `b_group` / `y_group` are opaque 32-byte compressed Edwards points here.
//! Their validity (decompress, non-identity, torsion-free) is checked where they
//! are *used*, by the output constructor in `shekyl-crypto-pq::output` — this
//! crate carries no curve dependency, and stating who validates is the point:
//! an address field with an unstated job is one every independent implementer
//! decides for itself.
//!
//! # The fingerprint is the group's identity
//!
//! `cSHAKE256(canonical(MultisigAddressPayload), "shekyl/multisig-address-v1")` —
//! per-group, computable by every participant from the address alone, and (with
//! `B`/`Y` in the payload) covering the whole of the group's public state: both
//! points, the KEM pubkeys, the versions, and `m`/`n`. This is the artifact the
//! §5.5 setup ritual wanted ("did we all derive the same group?"), and it
//! replaces the deleted `multisig_group_id`, which had no consumer under E′ and
//! computed a per-output hash under a per-group name. See [`address_fingerprint`]
//! for why cSHAKE256 and not the consensus `cn_fast_hash`.

use crate::network::{multisig_hrp, network_and_kind_from_hrp, AddressKind, Network};
use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, ByteIterExt, Fe32IterExt, Hrp};

/// X25519 (32) + ML-KEM-768 (1184).
pub const HYBRID_KEM_PUBKEY_LEN: usize = 1216;

/// Per-participant total. Post-MSW-8 (2026-07-15) this is the KEM pubkey
/// alone. The former `hybrid_sign_pubkeys` (Ed25519 + ML-DSA-65) were a
/// vestigial Solution C fossil — constructed and parsed here but never
/// consumed: leaf hybrid sign keys are derived per-output from the KEM shared
/// secrets in `shekyl-crypto-pq::multisig_receiving`, so the address never
/// needed to carry them (PQC_MULTISIG.md §6.2).
pub const PER_PARTICIPANT_LEN: usize = HYBRID_KEM_PUBKEY_LEN;

/// Maximum multisig participants. Mirrors the authoritative MSW-G cap in
/// `shekyl-crypto-pq::multisig::MAX_MULTISIG_PARTICIPANTS` (2f+1 at f=2). An
/// address that exceeds it is dead-on-arrival — no key container can be built
/// for it — so the two caps must agree; drift is caught at compile time by the
/// cross-crate pin `const _` assert in that crate (MSW-1).
pub const MAX_MULTISIG_PARTICIPANTS: u8 = 5;

/// Header: version + group_version + spend_auth_version + network + n_total + m_required.
///
/// The E′ group points (`B_group`, `Y_group`) follow the header rather than
/// joining it: the header is the payload's scalar preamble, the points are keys.
const HEADER_LEN: usize = 6;

/// A compressed Edwards point (`B_group` / `Y_group`). Two ride in every E′
/// payload, immediately after the header.
pub const GROUP_POINT_LEN: usize = 32;

/// Current multisig address payload version.
///
/// Stays `0x01` across the E′ B/Y addition, on MSW-8's reasoning: nothing is
/// deployed, so the layout is corrected in place rather than versioned. The
/// parser's version check is strict equality, so a `0x01` payload is an E′
/// payload — there is no D-era address to remain compatible with.
pub const MULTISIG_ADDRESS_VERSION: u8 = 0x01;

/// Current group protocol version.
pub const GROUP_VERSION: u8 = 0x01;

/// Current spend-auth version: `0x02` = Option E′ (PQC_MULTISIG.md §6.2).
///
/// `0x01` was the Option-D mandatory-prover scaffold and was **never issued**;
/// E′ is the shipping design, so the constant names it. An address carrying
/// `B_group`/`Y_group` *is* an E′ address — stamping it `0x01` would make the
/// payload lie about its own design.
pub const SPEND_AUTH_VERSION: u8 = 0x02;

/// Errors specific to multisig address operations.
#[derive(Debug, thiserror::Error)]
pub enum MultisigAddressError {
    #[error("participant count {n} out of range 1..={max}", max = MAX_MULTISIG_PARTICIPANTS)]
    InvalidParticipantCount { n: u8 },

    #[error("threshold {m} out of range 1..={n}")]
    InvalidThreshold { m: u8, n: u8 },

    #[error("expected {expected} KEM pubkeys, got {got}")]
    KemPubkeyCount { expected: u8, got: usize },

    #[error("KEM pubkey {index} has wrong length: expected {HYBRID_KEM_PUBKEY_LEN}, got {got}")]
    KemPubkeyLength { index: usize, got: usize },

    #[error("payload too short: need at least {HEADER_LEN} bytes, got {got}")]
    PayloadTooShort { got: usize },

    #[error("unsupported address version 0x{version:02x}")]
    UnsupportedVersion { version: u8 },

    #[error("payload length mismatch: header implies {expected} bytes, got {got}")]
    PayloadLengthMismatch { expected: usize, got: usize },

    #[error("unknown network byte 0x{byte:02x}")]
    UnknownNetwork { byte: u8 },

    #[error("bech32m error: {0}")]
    Encoding(String),

    #[error("HRP '{hrp}' is not a multisig address HRP")]
    WrongHrp { hrp: String },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Canonical multisig address payload (PQC_MULTISIG.md SS6.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultisigAddressPayload {
    pub version: u8,
    pub group_version: u8,
    pub spend_auth_version: u8,
    pub network: Network,
    pub n_total: u8,
    pub m_required: u8,
    /// `B_group` — the group's plaintext view/link key point (`B = b·G`). The
    /// `b` behind it is group-plaintext: every participant holds it, so scan,
    /// balance, and key-image are local and need no ceremony. A payer adds this
    /// point directly into `O = ho·G + B_group + y_out·T`.
    pub b_group: [u8; 32],
    /// `Y_group` — the FROST M-of-N group spend key point (`Y = y·T`). No
    /// participant holds `y`; a spend is a threshold ceremony over it. A payer
    /// needs it to derive the per-output tweak `y_out = y_group + y_kem`.
    pub y_group: [u8; 32],
    pub hybrid_kem_pubkeys: Vec<Vec<u8>>,
}

impl MultisigAddressPayload {
    /// Create a new payload, validating all invariants.
    pub fn new(
        network: Network,
        n_total: u8,
        m_required: u8,
        b_group: [u8; 32],
        y_group: [u8; 32],
        hybrid_kem_pubkeys: Vec<Vec<u8>>,
    ) -> Result<Self, MultisigAddressError> {
        if n_total == 0 || n_total > MAX_MULTISIG_PARTICIPANTS {
            return Err(MultisigAddressError::InvalidParticipantCount { n: n_total });
        }
        if m_required == 0 || m_required > n_total {
            return Err(MultisigAddressError::InvalidThreshold {
                m: m_required,
                n: n_total,
            });
        }
        if hybrid_kem_pubkeys.len() != n_total as usize {
            return Err(MultisigAddressError::KemPubkeyCount {
                expected: n_total,
                got: hybrid_kem_pubkeys.len(),
            });
        }
        for (i, pk) in hybrid_kem_pubkeys.iter().enumerate() {
            if pk.len() != HYBRID_KEM_PUBKEY_LEN {
                return Err(MultisigAddressError::KemPubkeyLength {
                    index: i,
                    got: pk.len(),
                });
            }
        }

        Ok(MultisigAddressPayload {
            version: MULTISIG_ADDRESS_VERSION,
            group_version: GROUP_VERSION,
            spend_auth_version: SPEND_AUTH_VERSION,
            network,
            n_total,
            m_required,
            b_group,
            y_group,
            hybrid_kem_pubkeys,
        })
    }

    /// Expected canonical byte length for this payload.
    pub fn canonical_len(&self) -> usize {
        HEADER_LEN + 2 * GROUP_POINT_LEN + (self.n_total as usize) * PER_PARTICIPANT_LEN
    }

    /// Serialize to canonical bytes.
    ///
    /// Layout: `version(1) || group_version(1) || spend_auth_version(1) ||
    ///          network(1) || n_total(1) || m_required(1) ||
    ///          b_group(32) || y_group(32) ||
    ///          kem_pk[0] || ... || kem_pk[N-1]`
    ///
    /// The points sit after the 6-byte header and before the variable-length KEM
    /// array, so every header offset is unchanged from the D-era layout.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let len = self.canonical_len();
        let mut buf = Vec::with_capacity(len);
        buf.push(self.version);
        buf.push(self.group_version);
        buf.push(self.spend_auth_version);
        buf.push(self.network.as_u8());
        buf.push(self.n_total);
        buf.push(self.m_required);
        buf.extend_from_slice(&self.b_group);
        buf.extend_from_slice(&self.y_group);
        for pk in &self.hybrid_kem_pubkeys {
            buf.extend_from_slice(pk);
        }
        debug_assert_eq!(buf.len(), len);
        buf
    }

    /// Deserialize from canonical bytes.
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self, MultisigAddressError> {
        if data.len() < HEADER_LEN {
            return Err(MultisigAddressError::PayloadTooShort { got: data.len() });
        }

        let version = data[0];
        if version != MULTISIG_ADDRESS_VERSION {
            return Err(MultisigAddressError::UnsupportedVersion { version });
        }

        let group_version = data[1];
        let spend_auth_version = data[2];
        let network_byte = data[3];
        let n_total = data[4];
        let m_required = data[5];

        let network = Network::from_u8(network_byte)
            .ok_or(MultisigAddressError::UnknownNetwork { byte: network_byte })?;

        if n_total == 0 || n_total > MAX_MULTISIG_PARTICIPANTS {
            return Err(MultisigAddressError::InvalidParticipantCount { n: n_total });
        }
        if m_required == 0 || m_required > n_total {
            return Err(MultisigAddressError::InvalidThreshold {
                m: m_required,
                n: n_total,
            });
        }

        let expected_len =
            HEADER_LEN + 2 * GROUP_POINT_LEN + (n_total as usize) * PER_PARTICIPANT_LEN;
        if data.len() != expected_len {
            return Err(MultisigAddressError::PayloadLengthMismatch {
                expected: expected_len,
                got: data.len(),
            });
        }

        // The exact-length check above is what makes these fixed-offset reads
        // sound; every slice below is within `expected_len`.
        let mut offset = HEADER_LEN;
        let b_group: [u8; 32] = data[offset..offset + GROUP_POINT_LEN]
            .try_into()
            .expect("GROUP_POINT_LEN slice is 32 bytes");
        offset += GROUP_POINT_LEN;
        let y_group: [u8; 32] = data[offset..offset + GROUP_POINT_LEN]
            .try_into()
            .expect("GROUP_POINT_LEN slice is 32 bytes");
        offset += GROUP_POINT_LEN;

        let mut hybrid_kem_pubkeys = Vec::with_capacity(n_total as usize);
        for _ in 0..n_total {
            hybrid_kem_pubkeys.push(data[offset..offset + HYBRID_KEM_PUBKEY_LEN].to_vec());
            offset += HYBRID_KEM_PUBKEY_LEN;
        }
        debug_assert_eq!(offset, data.len());

        Ok(MultisigAddressPayload {
            version,
            group_version,
            spend_auth_version,
            network,
            n_total,
            m_required,
            b_group,
            y_group,
            hybrid_kem_pubkeys,
        })
    }

    /// Write the canonical payload to a file.
    pub fn write_to_file(&self, path: &std::path::Path) -> Result<(), MultisigAddressError> {
        std::fs::write(path, self.to_canonical_bytes())?;
        Ok(())
    }

    /// Read and parse a canonical payload from a file.
    pub fn read_from_file(path: &std::path::Path) -> Result<Self, MultisigAddressError> {
        let data = std::fs::read(path)?;
        Self::from_canonical_bytes(&data)
    }

    /// Bech32m-encode the **fingerprint** as the shareable, QR-able group
    /// identifier under the network's multisig HRP (`shekyl1m1…`, ~67 chars).
    ///
    /// The full canonical payload is **not** a Bech32m string: at E′ sizes it is
    /// ~4019 chars for a 2-of-N, past Bech32m's ~1023-char BCH-checksum validity
    /// limit — encode/decode do not round-trip, which is *why* the full address is
    /// file-based and integrity rides the fingerprint (§6.3), not a full-address
    /// string. So `multisig_hrp` names the **fingerprint**: participants exchange
    /// the payload file and compare these short strings (string equality — both
    /// sides encode the same fingerprint bytes under the same HRP).
    pub fn fingerprint_bech32m(&self) -> Result<String, MultisigAddressError> {
        let hrp = Hrp::parse(multisig_hrp(self.network))
            .map_err(|e| MultisigAddressError::Encoding(e.to_string()))?;
        Ok(address_fingerprint(self)
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .chars()
            .collect())
    }

    /// Decode a shareable fingerprint string back to `(network, fingerprint)`,
    /// verifying the HRP is a multisig HRP and the data is exactly 32 bytes. For
    /// robustness (e.g. extracting the bytes); the ritual's equality check needs
    /// only [`Self::fingerprint_bech32m`] string comparison.
    pub fn parse_fingerprint_bech32m(
        encoded: &str,
    ) -> Result<(Network, [u8; 32]), MultisigAddressError> {
        // Enforce the Bech32m variant specifically: `bech32::decode` accepts either
        // Bech32 or Bech32m, but the fingerprint is *encoded* as Bech32m
        // ([`Self::fingerprint_bech32m`]), so a plain-Bech32 string with the same
        // HRP and data is not a fingerprint we produced and must not decode.
        let checked = CheckedHrpstring::new::<Bech32m>(encoded)
            .map_err(|e| MultisigAddressError::Encoding(e.to_string()))?;
        let hrp_str = checked.hrp().to_string();
        // Reverse-map the HRP → (network, kind) via the single ALL_HRPS registry
        // (case-insensitive, and kept in sync with the single-sig HRPs), then
        // require the multisig kind — a single-sig HRP is the wrong HRP here.
        let Some((network, AddressKind::Multisig)) = network_and_kind_from_hrp(&hrp_str) else {
            return Err(MultisigAddressError::WrongHrp { hrp: hrp_str });
        };
        let data: Vec<u8> = checked.byte_iter().collect();
        let fingerprint: [u8; 32] = data.as_slice().try_into().map_err(|_| {
            MultisigAddressError::Encoding(format!("expected 32 bytes, got {}", data.len()))
        })?;
        Ok((network, fingerprint))
    }
}

/// cSHAKE256 customization for [`address_fingerprint`] (SP 800-185).
///
/// Versioned: a change to the canonical payload's preimage takes `-v2`, so it
/// becomes a new domain rather than a silent reinterpretation of the old one.
pub const MULTISIG_ADDRESS_FINGERPRINT_CUSTOMIZATION: &[u8] = b"shekyl/multisig-address-v1";

/// Compute the 32-byte address fingerprint:
/// `cSHAKE256(canonical payload, "shekyl/multisig-address-v1")`.
///
/// This is the primary human-verifiable identifier for a multisig group address
/// (PQC_MULTISIG.md SS6.3) **and, under E′, the group's identity** — the artifact
/// the §5.5 setup ritual actually wanted: every participant computes it from the
/// address alone and compares, or the group is not the same group. It covers the
/// group's whole public state: `B_group`, `Y_group`, the N KEM pubkeys, both
/// version axes, and `m`/`n`.
///
/// It supersedes the deleted `multisig_group_id`, which could not do this job: its
/// preimage was the `MultisigKeyContainer`, whose leaf keys are derived per-output
/// from KEM shared secrets — so it produced a different value for every output
/// while being named for the group, had no consumer under E′, and its only
/// long-term caller (`wallet2::create_pqc_multisig_group`) never executed
/// successfully.
///
/// # Why cSHAKE256 and not `cn_fast_hash`
///
/// The address is on **no consensus path** — no C++ mirror, no FFI, no leaf — so
/// nothing requires byte-identity with the Monero-descended daemon, which is
/// `cn_fast_hash`'s only reason to exist. What the address *does* have is four
/// independent implementers (payer wallet, scanner, exchange, light client), and
/// for them "Keccak-256" is not a function: original Keccak (0x01) and SHA3-256
/// (0x06) differ by one padding byte and fail *silently* — a different fingerprint,
/// no diagnostic. cSHAKE256 has one meaning, and its customization string makes the
/// domain separation structural instead of definitional. This matches the house
/// pattern for every new domain-separated artifact (`shekyl/archival-bond-post-v1`,
/// `shekyl/receive-label-hash-v1`); `cn_fast_hash` keeps exactly the consumers that
/// require parity.
pub fn address_fingerprint(payload: &MultisigAddressPayload) -> [u8; 32] {
    shekyl_crypto_hash::cshake256_32(
        MULTISIG_ADDRESS_FINGERPRINT_CUSTOMIZATION,
        &payload.to_canonical_bytes(),
    )
}

/// Format a fingerprint as grouped hex (4-char blocks separated by spaces).
pub fn fingerprint_hex(fingerprint: &[u8; 32]) -> String {
    let hex: String = fingerprint.iter().map(|b| format!("{b:02x}")).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Format a fingerprint as the structured metadata badge: `(m)-of-(n), spend_auth v(X), group v(Y)`.
pub fn fingerprint_badge(payload: &MultisigAddressPayload) -> String {
    format!(
        "{}-of-{}, spend_auth v{}, group v{}",
        payload.m_required, payload.n_total, payload.spend_auth_version, payload.group_version,
    )
}

/// Address provenance record persisted in the wallet (PQC_MULTISIG.md SS6.3).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AddressProvenance {
    pub address_fingerprint: [u8; 32],
    pub first_imported_at: u64,
    pub imported_from_source: String,
    pub user_assigned_label: String,
    pub last_used_at: u64,
    pub prior_fingerprints: Vec<[u8; 32]>,
}

impl AddressProvenance {
    /// Whether the fingerprint has changed since the initial import.
    pub fn fingerprint_changed(&self) -> bool {
        !self.prior_fingerprints.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_payload(n: u8, m: u8) -> MultisigAddressPayload {
        MultisigAddressPayload::new(
            Network::Mainnet,
            n,
            m,
            [0xB1; 32],
            [0x71; 32],
            (0..n).map(|i| vec![i; HYBRID_KEM_PUBKEY_LEN]).collect(),
        )
        .unwrap()
    }

    #[test]
    fn canonical_roundtrip_2_of_3() {
        let payload = make_test_payload(3, 2);
        let bytes = payload.to_canonical_bytes();
        assert_eq!(
            bytes.len(),
            HEADER_LEN + 2 * GROUP_POINT_LEN + 3 * PER_PARTICIPANT_LEN
        );
        let decoded = MultisigAddressPayload::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn canonical_roundtrip_1_of_1() {
        let payload = make_test_payload(1, 1);
        let bytes = payload.to_canonical_bytes();
        assert_eq!(
            bytes.len(),
            HEADER_LEN + 2 * GROUP_POINT_LEN + PER_PARTICIPANT_LEN
        );
        let decoded = MultisigAddressPayload::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn canonical_roundtrip_5_of_5() {
        let payload = make_test_payload(MAX_MULTISIG_PARTICIPANTS, MAX_MULTISIG_PARTICIPANTS);
        let bytes = payload.to_canonical_bytes();
        assert_eq!(
            bytes.len(),
            HEADER_LEN
                + 2 * GROUP_POINT_LEN
                + (MAX_MULTISIG_PARTICIPANTS as usize) * PER_PARTICIPANT_LEN
        );
        let decoded = MultisigAddressPayload::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn rejects_n_zero() {
        assert!(MultisigAddressPayload::new(
            Network::Mainnet,
            0,
            0,
            [0xB1; 32],
            [0x71; 32],
            vec![]
        )
        .is_err());
    }

    #[test]
    fn rejects_n_over_max() {
        // MSW-1: n = MAX+1 is the boundary-adjacent rejection. The address cap
        // must track the container cap; an over-cap address is unusable.
        let n = MAX_MULTISIG_PARTICIPANTS + 1;
        assert!(MultisigAddressPayload::new(
            Network::Mainnet,
            n,
            3,
            [0xB1; 32],
            [0x71; 32],
            (0..n).map(|i| vec![i; HYBRID_KEM_PUBKEY_LEN]).collect(),
        )
        .is_err());
    }

    #[test]
    fn rejects_m_exceeds_n() {
        assert!(MultisigAddressPayload::new(
            Network::Mainnet,
            2,
            3,
            [0xB1; 32],
            [0x71; 32],
            vec![vec![0; HYBRID_KEM_PUBKEY_LEN]; 2],
        )
        .is_err());
    }

    #[test]
    fn rejects_wrong_kem_pubkey_length() {
        assert!(MultisigAddressPayload::new(
            Network::Mainnet,
            2,
            2,
            [0xB1; 32],
            [0x71; 32],
            vec![vec![0; 100], vec![0; HYBRID_KEM_PUBKEY_LEN]],
        )
        .is_err());
    }

    #[test]
    fn rejects_truncated_payload() {
        let payload = make_test_payload(2, 2);
        let bytes = payload.to_canonical_bytes();
        assert!(MultisigAddressPayload::from_canonical_bytes(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut bytes = make_test_payload(2, 2).to_canonical_bytes();
        bytes[0] = 0xFF;
        assert!(MultisigAddressPayload::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn reserved_spend_auth_version_is_carried() {
        // MSW-5: address carrier disposition (A). The payload transports
        // `spend_auth_version` opaquely — a *reserved* value must round-trip
        // unchanged, never be normalized or rejected, so forward-compatible
        // readers (§8.2) can dispatch on it.
        //
        // This deliberately pokes a value that is NOT `SPEND_AUTH_VERSION`. The
        // canary originally used 0x02 because 0x02 was then the reserved Option-E′
        // marker; E′ shipping made 0x02 the default, at which point poking it would
        // have quietly degraded this test into "the default round-trips" — which
        // proves nothing about opaque carriage. 0x03 is unassigned, so the property
        // under test (an unknown version survives a round trip) is preserved.
        const RESERVED_FUTURE_VERSION: u8 = 0x03;
        const _: () = assert!(
            RESERVED_FUTURE_VERSION != SPEND_AUTH_VERSION,
            "the canary must poke a version the reader does not already produce, or it tests nothing"
        );

        let mut bytes = make_test_payload(2, 2).to_canonical_bytes();
        bytes[2] = RESERVED_FUTURE_VERSION;
        let decoded = MultisigAddressPayload::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded.spend_auth_version, RESERVED_FUTURE_VERSION);
        assert_eq!(decoded.to_canonical_bytes(), bytes);
    }

    #[test]
    fn fingerprint_deterministic() {
        let p = make_test_payload(3, 2);
        let fp1 = address_fingerprint(&p);
        let fp2 = address_fingerprint(&p);
        assert_eq!(fp1, fp2);
        assert_ne!(fp1, [0; 32]);
    }

    #[test]
    fn fingerprint_changes_with_keys() {
        let p1 = make_test_payload(3, 2);
        let mut p2 = make_test_payload(3, 2);
        p2.hybrid_kem_pubkeys[0] = vec![0xFF; HYBRID_KEM_PUBKEY_LEN];
        assert_ne!(address_fingerprint(&p1), address_fingerprint(&p2));
    }

    #[test]
    fn fingerprint_hex_format() {
        let p = make_test_payload(2, 2);
        let fp = address_fingerprint(&p);
        let hex = fingerprint_hex(&fp);
        assert_eq!(hex.len(), 64 + 15); // 64 hex chars + 15 spaces (16 groups of 4)
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() || c == ' '));
    }

    #[test]
    fn fingerprint_badge_format() {
        let p = make_test_payload(3, 2);
        let badge = fingerprint_badge(&p);
        // Literal, not constant-derived: this is the string a user reads off the
        // badge, so it pins both the format and the version it advertises. `v2` is
        // Option E′ — a bump must re-edit this line deliberately rather than track
        // the constant silently.
        assert_eq!(badge, "2-of-3, spend_auth v2, group v1");
    }

    #[test]
    fn provenance_fingerprint_changed() {
        let prov = AddressProvenance {
            address_fingerprint: [0; 32],
            first_imported_at: 1000,
            imported_from_source: "file:///tmp/multisig.addr".into(),
            user_assigned_label: "Alice+Bob".into(),
            last_used_at: 1000,
            prior_fingerprints: vec![],
        };
        assert!(!prov.fingerprint_changed());

        let prov2 = AddressProvenance {
            prior_fingerprints: vec![[1; 32]],
            ..prov
        };
        assert!(prov2.fingerprint_changed());
    }

    #[test]
    fn file_roundtrip() {
        let payload = make_test_payload(2, 2);
        // `tempfile::tempdir()` gives each test invocation a unique
        // directory and handles cleanup on Drop, so concurrent `cargo
        // test` runs and leftover state from previous crashes can't
        // collide the way a fixed `temp_dir().join(...)` name could.
        let dir = tempfile::tempdir().expect("create test tempdir");
        let path = dir.path().join("test_addr.bin");

        payload.write_to_file(&path).unwrap();
        let loaded = MultisigAddressPayload::read_from_file(&path).unwrap();
        assert_eq!(payload, loaded);
    }

    // ── KATs: pin the canonical payload for a second implementer ──────────────
    // The address is the one artifact with independent implementers (payer
    // wallet, scanner, exchange, light client). These fix its size, its
    // fingerprint bytes, and its string form so any of them computes the same
    // value or fails a diff — the anti-drift gate for a payload no compiler spans.

    #[test]
    fn canonical_length_kat() {
        // E′ payload = HEADER_LEN(6) + 2·GROUP_POINT_LEN(64) + N·PER_PARTICIPANT_LEN(1216)
        //            = 70 + N·1216.
        for (n, expected) in [(1u8, 1286usize), (2, 2502), (3, 3718), (5, 6150)] {
            let bytes = make_test_payload(n, 1).to_canonical_bytes();
            assert_eq!(bytes.len(), expected, "canonical length for n={n}");
            assert_eq!(bytes.len(), 70 + (n as usize) * 1216);
        }
    }

    #[test]
    fn address_fingerprint_kat() {
        // Fixed payload → fixed cSHAKE256 fingerprint. This vector *defines* the
        // fingerprint bytes every independent implementer (payer wallet, scanner,
        // exchange, light client) must reproduce, so it is a consensus artifact:
        // the code is tested against it, never it against the code (rule 30). If
        // this fails, the canonical payload preimage, the customization string, or
        // the hash changed — do NOT regenerate the constant to make it pass; that
        // silently moves the identity all implementers rely on. Either revert the
        // change or, if the move is deliberate, bump the customization to `-v2`
        // (a new domain) and re-pin under that version with a recorded rationale.
        let payload = make_test_payload(2, 2);
        let fp = address_fingerprint(&payload);
        assert_eq!(
            fp,
            [
                0xed, 0x49, 0xa8, 0x39, 0xc9, 0xef, 0x73, 0x91, 0x17, 0x70, 0xac, 0x15, 0xcd, 0x5b,
                0x11, 0x10, 0xd0, 0x8b, 0xeb, 0xf6, 0xb3, 0xe7, 0xd9, 0xd6, 0xf2, 0xed, 0x3a, 0xc9,
                0x66, 0x1f, 0x6f, 0x2e,
            ],
        );
    }

    #[test]
    fn fingerprint_bech32m_roundtrip() {
        // The fingerprint (32 B → 67 chars) IS Bech32m-encodable and is the
        // shareable / QR-able group identifier. The full payload is NOT: at ~4019
        // chars a 2-of-N exceeds Bech32m's ~1023-char BCH-checksum validity limit
        // and does not round-trip — hence file-based address + fingerprint string.
        let payload = make_test_payload(2, 2);
        let s = payload.fingerprint_bech32m().unwrap();
        assert!(
            s.starts_with("shekyl1m1"),
            "mainnet multisig HRP + separator"
        );
        assert_eq!(s.chars().count(), 67, "32-byte fingerprint bech32m length");

        let (net, fp) = MultisigAddressPayload::parse_fingerprint_bech32m(&s).unwrap();
        assert_eq!(net, Network::Mainnet);
        assert_eq!(fp, address_fingerprint(&payload));

        // The ritual's equality check is plain string comparison — same bytes,
        // same HRP, same string — needing no decode.
        assert_eq!(s, make_test_payload(2, 2).fingerprint_bech32m().unwrap());
    }

    #[test]
    fn fingerprint_bech32m_rejects_non_multisig_hrp() {
        // A single-sig / unknown HRP must not parse as a multisig fingerprint.
        let s = make_test_payload(2, 2).fingerprint_bech32m().unwrap();
        let mangled = s.replacen("shekyl1m1", "shekyl1", 1);
        assert!(MultisigAddressPayload::parse_fingerprint_bech32m(&mangled).is_err());
    }

    #[test]
    fn fingerprint_bech32m_accepts_uppercase() {
        // Bech32m is case-insensitive (an all-uppercase encoding is valid and
        // carries the same HRP/data). The HRP reverse-map lowercases before
        // matching, so a validly upper-cased fingerprint must still decode —
        // regression guard for the previous case-sensitive open-coded lookup.
        let payload = make_test_payload(2, 2);
        let s = payload.fingerprint_bech32m().unwrap();
        let upper = s.to_uppercase();
        let (net, fp) = MultisigAddressPayload::parse_fingerprint_bech32m(&upper).unwrap();
        assert_eq!(net, Network::Mainnet);
        assert_eq!(fp, address_fingerprint(&payload));
    }

    #[test]
    fn fingerprint_bech32m_rejects_plain_bech32() {
        // The fingerprint is encoded as Bech32m; a same-HRP, same-data string
        // carrying a plain-Bech32 checksum is not a fingerprint we produced and
        // must be rejected (bech32::decode would have accepted either variant).
        use bech32::Bech32;
        let fp = address_fingerprint(&make_test_payload(2, 2));
        let hrp = Hrp::parse(multisig_hrp(Network::Mainnet)).unwrap();
        let as_bech32 = bech32::encode::<Bech32>(hrp, &fp).unwrap();
        assert!(MultisigAddressPayload::parse_fingerprint_bech32m(&as_bech32).is_err());
    }

    #[test]
    fn different_networks_different_payloads() {
        let p_main = MultisigAddressPayload::new(
            Network::Mainnet,
            2,
            2,
            [0xB1; 32],
            [0x71; 32],
            vec![vec![0; HYBRID_KEM_PUBKEY_LEN]; 2],
        )
        .unwrap();
        let p_test = MultisigAddressPayload::new(
            Network::Testnet,
            2,
            2,
            [0xB1; 32],
            [0x71; 32],
            vec![vec![0; HYBRID_KEM_PUBKEY_LEN]; 2],
        )
        .unwrap();
        assert_ne!(p_main.to_canonical_bytes(), p_test.to_canonical_bytes());
        assert_ne!(address_fingerprint(&p_main), address_fingerprint(&p_test));
    }
}
