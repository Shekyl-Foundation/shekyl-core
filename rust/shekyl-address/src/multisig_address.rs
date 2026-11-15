// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Multisig address encoding, fingerprint, and provenance (PQC_MULTISIG.md SS6).
//!
//! Multisig addresses are **file-based**: the canonical payload
//! (`HEADER_LEN + 2 * GROUP_POINT_LEN + (N + 1) * HYBRID_KEM_PUBKEY_LEN` =
//! 70 + (N + 1) * 1216 bytes) is written to a file and transferred via an
//! authenticated channel. It is not a Bech32m string — at E′ sizes it exceeds
//! Bech32m's ~1023-char checksum-validity limit and would not round-trip. What
//! *is* Bech32m-encoded, under the `shekyl1m` / `shekyltest1m` / `sshekyl1m` HRP
//! family, is the fixed-size **fingerprint** (32 B → 67 chars, QR-able): the
//! short, human-verifiable, shareable group identifier. Integrity rides that
//! fingerprint, not a full-address string or a stored checksum.
//!
//! # Option E′: the address carries the group's points and KEM keys
//!
//! Under E′ a payer constructs `O = ho·G + B_group + y_out·T`
//! (`shekyl-crypto-pq::output`), so the address **must** carry `B_group` and
//! `Y_group` or an output cannot be built at all. It also carries the
//! **group** hybrid KEM key, which every member holds the secret for: the
//! output's one `0x06` ciphertext is to it, and the per-output secret behind
//! `ho`, `y_kem`, the amount key and the leaf blind comes from it. Then one
//! KEM key per member, for the per-member ciphertexts in `0x0D` that give
//! each member a per-output signing key the others cannot derive
//! (`docs/PQC_MULTISIG.md` §6–§7). These are all the group's **long-term**
//! public state; the per-output signing keys are derived, never carried
//! (MSW-8).
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
//! `cSHAKE256(len(tag) ‖ tag ‖ canonical(MultisigAddressPayload), "shekyl/multisig-address-v2")`,
//! where `tag` is the network's name (`shekyl/<network>`) — per-group, computable by every participant from the address alone, and (with
//! `B`/`Y` in the payload) covering the whole of the group's public state: both
//! points, the KEM pubkeys, the versions, and `m`/`n`. This is the artifact the
//! §5.4 setup ritual wanted ("did we all derive the same group?"), and it
//! replaces the deleted `multisig_group_id`, which had no consumer under E′ and
//! computed a per-output hash under a per-group name. See [`address_fingerprint`]
//! for why cSHAKE256 and not the consensus `keccak256`.

use crate::network::{multisig_hrp, network_and_kind_from_hrp, AddressKind, Network};
use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, ByteIterExt, Fe32IterExt, Hrp};
use shekyl_network::envelope::NameDomain;

/// X25519 (32) + ML-KEM-768 (1184).
pub const HYBRID_KEM_PUBKEY_LEN: usize = 1216;

/// Per-participant total: the member's KEM pubkey alone (MSW-8). A member's
/// per-output signing key is derived from the KEM secret behind it
/// (`shekyl-crypto-pq::output::construct_multisig_output`), so the address
/// never carries signing keys (PQC_MULTISIG.md §6.2).
pub const PER_PARTICIPANT_LEN: usize = HYBRID_KEM_PUBKEY_LEN;

/// Maximum multisig participants. Mirrors the authoritative MSW-G cap in
/// `shekyl-crypto-pq::multisig::MAX_MULTISIG_PARTICIPANTS` (2f+1 at f=2). An
/// address that exceeds it is dead-on-arrival — no key container can be built
/// for it — so the two caps must agree; drift is caught at compile time by the
/// cross-crate pin `const _` assert in that crate (MSW-1).
pub const MAX_MULTISIG_PARTICIPANTS: u8 = 5;

/// The smallest threshold a group may have, and so the smallest group
/// (R-11, ruled 2026-11-12). With `m = 1` the FROST polynomial is a
/// constant: every member holds the whole spend share, the PQ leg is
/// 1-of-N, and the ceremony has no responder — a shared key under a
/// multisig label, still marked on chain as a multisig output. Mirrored in
/// `shekyl-crypto-pq::multisig::MIN_MULTISIG_THRESHOLD`, pinned equal there
/// at compile time as the participant cap is.
pub const MIN_MULTISIG_THRESHOLD: u8 = 2;

/// Header: version + group_version + spend_auth_version + network + n_total + m_required.
///
/// The E′ group points (`B_group`, `Y_group`) follow the header rather than
/// joining it: the header is the payload's scalar preamble, the points are keys.
const HEADER_LEN: usize = 6;

/// A compressed Edwards point (`B_group` / `Y_group`). Two ride in every E′
/// payload, immediately after the header.
pub const GROUP_POINT_LEN: usize = 32;

/// Current multisig address payload version: `0x02`, the layout with the
/// group KEM key. The parser's version check is strict equality, so a `0x01`
/// payload (the layout without it, which no output can be built from) is
/// refused with [`MultisigAddressError::UnsupportedVersion`].
pub const MULTISIG_ADDRESS_VERSION: u8 = 0x02;

/// Current group protocol version.
pub const GROUP_VERSION: u8 = 0x01;

/// Current spend-auth version: `0x02` = Option E′ (PQC_MULTISIG.md §6.2).
///
/// `0x01` was the Option-D mandatory-prover scaffold and was **never issued**;
/// E′ is the shipping design, so the constant names it. An address carrying
/// `B_group`/`Y_group` *is* an E′ address — stamping it `0x01` would make the
/// payload lie about its own design.
pub const SPEND_AUTH_VERSION: u8 = 0x02;

/// Bytes of the X25519 u-coordinate that begins a hybrid KEM public key.
///
/// Pinned to the width `shekyl-crypto-pq` splits off before encapsulation.
/// The two are the same 32 bytes; a drift would make this check look at
/// the wrong half.
pub const X25519_U_LEN: usize = 32;

/// Little-endian byte `index` of `p = 2^255 - 19`.
const fn montgomery_prime_byte(index: usize) -> u8 {
    match index {
        0 => 0xED,
        31 => 0x7F,
        _ => 0xFF,
    }
}

/// A Montgomery u-coordinate is canonical when the integer is strictly
/// less than `p`. X25519 ignores bit 255 and reduces modulo `p`, so a
/// non-canonical encoding is a second byte string for one point. This is
/// not the Edwards y check: there bit 255 is a sign and is masked, and
/// masking it here would accept the alias.
fn montgomery_u_is_canonical(u: &[u8; X25519_U_LEN]) -> bool {
    for index in (0..X25519_U_LEN).rev() {
        let prime = montgomery_prime_byte(index);
        if u[index] < prime {
            return true;
        }
        if u[index] > prime {
            return false;
        }
    }
    // Equal to `p`.
    false
}

fn kem_x25519_is_canonical(kem: &[u8]) -> bool {
    let Some(head) = kem.get(..X25519_U_LEN) else {
        return false;
    };
    let u = <[u8; X25519_U_LEN]>::try_from(head).expect("the slice length is X25519_U_LEN");
    montgomery_u_is_canonical(&u)
}

/// The group key and every member key are different points. A repeated
/// point collapses two encapsulation slots onto one shared secret: the
/// group secret would open a member's signing key, or two members would
/// hold the same signing key. The X25519 half is compared as bytes, which
/// is the point comparison only when that half is the one canonical
/// encoding.
fn reject_aliased_kem_keys(
    group_kem_pubkey: &[u8],
    hybrid_kem_pubkeys: &[Vec<u8>],
) -> Result<(), MultisigAddressError> {
    if !kem_x25519_is_canonical(group_kem_pubkey) {
        return Err(MultisigAddressError::NonCanonicalGroupKemKey);
    }
    for (second, member) in hybrid_kem_pubkeys.iter().enumerate() {
        if !kem_x25519_is_canonical(member) {
            return Err(MultisigAddressError::NonCanonicalMemberKemKey { index: second });
        }
        if member.as_slice() == group_kem_pubkey {
            return Err(MultisigAddressError::GroupKemKeyRepeatsMember { index: second });
        }
        if let Some(first) = hybrid_kem_pubkeys[..second]
            .iter()
            .position(|earlier| earlier.as_slice() == member.as_slice())
        {
            return Err(MultisigAddressError::DuplicateMemberKemKey { first, second });
        }
    }
    Ok(())
}

/// Errors specific to multisig address operations.
#[derive(Debug, thiserror::Error)]
pub enum MultisigAddressError {
    #[error(
        "participant count {n} out of range {min}..={max}",
        min = MIN_MULTISIG_THRESHOLD,
        max = MAX_MULTISIG_PARTICIPANTS
    )]
    InvalidParticipantCount { n: u8 },

    #[error("threshold {m} out of range {min}..={n}", min = MIN_MULTISIG_THRESHOLD)]
    InvalidThreshold { m: u8, n: u8 },

    #[error("expected {expected} KEM pubkeys, got {got}")]
    KemPubkeyCount { expected: u8, got: usize },

    #[error("KEM pubkey {index} has wrong length: expected {HYBRID_KEM_PUBKEY_LEN}, got {got}")]
    KemPubkeyLength { index: usize, got: usize },
    #[error("group KEM pubkey has wrong length: expected {HYBRID_KEM_PUBKEY_LEN}, got {got}")]
    GroupKemPubkeyLength { got: usize },

    /// The group key's X25519 half is a second encoding of some u-coordinate.
    /// X25519 would treat it as the reduced point, so a member key that
    /// copied it would not look equal as bytes and would still open under
    /// the group secret.
    #[error("group KEM key's X25519 half is not a canonical Montgomery u-coordinate")]
    NonCanonicalGroupKemKey,

    /// A member key's X25519 half is a second encoding of some u-coordinate.
    /// Copied from the group key with bit 255 flipped, it is the group point.
    #[error("member {index}'s X25519 half is not a canonical Montgomery u-coordinate")]
    NonCanonicalMemberKemKey { index: usize },

    /// The group KEM key is also some member's key. That member's per-output
    /// shared secret would equal the group secret, so anyone who holds the
    /// group secret could sign as that member.
    #[error("group KEM key equals member {index}'s KEM key")]
    GroupKemKeyRepeatsMember { index: usize },

    /// Two members were given the same KEM key. Their per-output signing keys
    /// would be identical, and a spend of both would be refused as duplicate
    /// keys.
    #[error("member KEM keys {first} and {second} are the same key")]
    DuplicateMemberKemKey { first: usize, second: usize },

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

/// Canonical multisig address payload (PQC_MULTISIG.md §6.2).
///
/// The fields are private: [`Self::new`] and [`Self::from_canonical_bytes`]
/// are the only ways to make one, and both check every invariant, the KEM
/// key checks included. A payload that exists is valid, so a consumer such
/// as the output constructor does not check it again.
///
/// A field cannot be edited after the checks:
///
/// ```compile_fail,E0616
/// fn edit(p: &mut shekyl_address::MultisigAddressPayload) {
///     p.hybrid_kem_pubkeys[0][31] |= 0x80;
/// }
/// ```
///
/// nor a payload written without them:
///
/// ```compile_fail,E0451
/// let _ = shekyl_address::MultisigAddressPayload {
///     version: 2,
///     group_version: 1,
///     spend_auth_version: 2,
///     network: shekyl_address::Network::Mainnet,
///     n_total: 2,
///     m_required: 2,
///     b_group: [0; 32],
///     y_group: [0; 32],
///     group_kem_pubkey: vec![],
///     hybrid_kem_pubkeys: vec![],
/// };
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultisigAddressPayload {
    version: u8,
    group_version: u8,
    spend_auth_version: u8,
    network: Network,
    n_total: u8,
    m_required: u8,
    /// `B_group` — the group's plaintext view/link key point (`B = b·G`). The
    /// `b` behind it is group-plaintext: every participant holds it, so scan,
    /// balance, and key-image are local and need no ceremony. A payer adds this
    /// point directly into `O = ho·G + B_group + y_out·T`.
    b_group: [u8; 32],
    /// `Y_group` — the FROST M-of-N group spend key point (`Y = y·T`). No
    /// participant holds `y`; a spend is a threshold ceremony over it. A payer
    /// needs it to derive the per-output tweak `y_out = y_group + y_kem`.
    y_group: [u8; 32],
    /// The group's hybrid KEM public key (`X25519 ‖ ML-KEM-768`, 1216 bytes).
    /// Every member holds its secret; a payer encapsulates the output's one
    /// `0x06` ciphertext to it.
    group_kem_pubkey: Vec<u8>,
    /// Each member's own hybrid KEM public key, member order.
    hybrid_kem_pubkeys: Vec<Vec<u8>>,
}

impl MultisigAddressPayload {
    /// Create a new payload, validating all invariants.
    pub fn new(
        network: Network,
        n_total: u8,
        m_required: u8,
        b_group: [u8; 32],
        y_group: [u8; 32],
        group_kem_pubkey: Vec<u8>,
        hybrid_kem_pubkeys: Vec<Vec<u8>>,
    ) -> Result<Self, MultisigAddressError> {
        if !(MIN_MULTISIG_THRESHOLD..=MAX_MULTISIG_PARTICIPANTS).contains(&n_total) {
            return Err(MultisigAddressError::InvalidParticipantCount { n: n_total });
        }
        if !(MIN_MULTISIG_THRESHOLD..=n_total).contains(&m_required) {
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
        if group_kem_pubkey.len() != HYBRID_KEM_PUBKEY_LEN {
            return Err(MultisigAddressError::GroupKemPubkeyLength {
                got: group_kem_pubkey.len(),
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
        reject_aliased_kem_keys(&group_kem_pubkey, &hybrid_kem_pubkeys)?;

        Ok(MultisigAddressPayload {
            version: MULTISIG_ADDRESS_VERSION,
            group_version: GROUP_VERSION,
            spend_auth_version: SPEND_AUTH_VERSION,
            network,
            n_total,
            m_required,
            b_group,
            y_group,
            group_kem_pubkey,
            hybrid_kem_pubkeys,
        })
    }

    /// Canonical byte length for an `n`-member payload:
    /// `70 + (n + 1) · 1216`.
    #[must_use]
    pub const fn canonical_len_for(n_total: u8) -> usize {
        HEADER_LEN
            + 2 * GROUP_POINT_LEN
            + HYBRID_KEM_PUBKEY_LEN
            + (n_total as usize) * PER_PARTICIPANT_LEN
    }

    /// Expected canonical byte length for this payload.
    pub fn canonical_len(&self) -> usize {
        Self::canonical_len_for(self.n_total)
    }

    /// The payload format version (`0x02`).
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// The group format version.
    #[must_use]
    pub const fn group_version(&self) -> u8 {
        self.group_version
    }

    /// The spend-authorization version (`0x02`, Option E′).
    #[must_use]
    pub const fn spend_auth_version(&self) -> u8 {
        self.spend_auth_version
    }

    /// The network this address is for.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// `N`, the number of members.
    #[must_use]
    pub const fn n_total(&self) -> u8 {
        self.n_total
    }

    /// `M`, the signers a spend needs.
    #[must_use]
    pub const fn m_required(&self) -> u8 {
        self.m_required
    }

    /// `B_group`, compressed. Not checked as a point here; the output
    /// constructor checks it is prime-order and not the identity.
    #[must_use]
    pub const fn b_group(&self) -> &[u8; 32] {
        &self.b_group
    }

    /// `Y_group`, compressed. Checked as `B_group` is.
    #[must_use]
    pub const fn y_group(&self) -> &[u8; 32] {
        &self.y_group
    }

    /// The group's hybrid KEM public key, `HYBRID_KEM_PUBKEY_LEN` bytes,
    /// its X25519 half canonical and different from every member's key.
    #[must_use]
    pub fn group_kem_pubkey(&self) -> &[u8] {
        &self.group_kem_pubkey
    }

    /// The members' hybrid KEM public keys, member order: `N` keys of
    /// `HYBRID_KEM_PUBKEY_LEN` bytes, each X25519 half canonical, no two
    /// the same.
    #[must_use]
    pub fn hybrid_kem_pubkeys(&self) -> &[Vec<u8>] {
        &self.hybrid_kem_pubkeys
    }

    /// Serialize to canonical bytes.
    ///
    /// Layout: `version(1) || group_version(1) || spend_auth_version(1) ||
    ///          network(1) || n_total(1) || m_required(1) ||
    ///          b_group(32) || y_group(32) || group_kem_pk(1216) ||
    ///          kem_pk[0] || ... || kem_pk[N-1]`
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let len = self.canonical_len();
        let mut buf = Vec::with_capacity(len);
        buf.push(self.version);
        buf.push(self.group_version);
        buf.push(self.spend_auth_version);
        buf.push(self.network.code());
        buf.push(self.n_total);
        buf.push(self.m_required);
        buf.extend_from_slice(&self.b_group);
        buf.extend_from_slice(&self.y_group);
        buf.extend_from_slice(&self.group_kem_pubkey);
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

        let network = Network::from_code(network_byte)
            .ok_or(MultisigAddressError::UnknownNetwork { byte: network_byte })?;

        if !(MIN_MULTISIG_THRESHOLD..=MAX_MULTISIG_PARTICIPANTS).contains(&n_total) {
            return Err(MultisigAddressError::InvalidParticipantCount { n: n_total });
        }
        if !(MIN_MULTISIG_THRESHOLD..=n_total).contains(&m_required) {
            return Err(MultisigAddressError::InvalidThreshold {
                m: m_required,
                n: n_total,
            });
        }

        let expected_len = Self::canonical_len_for(n_total);
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
        let group_kem_pubkey = data[offset..offset + HYBRID_KEM_PUBKEY_LEN].to_vec();
        offset += HYBRID_KEM_PUBKEY_LEN;

        let mut hybrid_kem_pubkeys = Vec::with_capacity(n_total as usize);
        for _ in 0..n_total {
            hybrid_kem_pubkeys.push(data[offset..offset + HYBRID_KEM_PUBKEY_LEN].to_vec());
            offset += HYBRID_KEM_PUBKEY_LEN;
        }
        debug_assert_eq!(offset, data.len());
        reject_aliased_kem_keys(&group_kem_pubkey, &hybrid_kem_pubkeys)?;

        Ok(MultisigAddressPayload {
            version,
            group_version,
            spend_auth_version,
            network,
            n_total,
            m_required,
            b_group,
            y_group,
            group_kem_pubkey,
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

/// The envelope domain of [`address_fingerprint`] (the signing envelope
/// §2.1), bound to the network's name, with one field: the canonical
/// payload.
///
/// Versioned: a change to the preimage takes a new version, so it becomes a
/// new domain rather than a silent reinterpretation of the old one. `-v3`:
/// the name enters as the envelope's 16-byte `name_id` at position 0, where
/// `-v2` hand-rolled `len(tag) ‖ tag` and `-v1` relied on the payload's
/// one-byte network code.
pub const MULTISIG_ADDRESS_FINGERPRINT: NameDomain<1> =
    NameDomain::new(b"shekyl/multisig-address-v3");

/// Compute the 32-byte address fingerprint:
/// `frame("shekyl/multisig-address-v3", name_id, [canonical payload])`.
///
/// `name_id` is the payload network's name binding (the signing envelope
/// §2.6). A group's address is derived from keys and addresses, which exist
/// before any genesis, so it binds the network's name, not its
/// genesis-derived id (`NETWORK_IDENTITY.md` NI-R10, NI-R15).
///
/// This is the primary human-verifiable identifier for a multisig group address
/// (PQC_MULTISIG.md SS6.3) **and, under E′, the group's identity** — the artifact
/// the §5.5 setup ritual actually wanted: every participant computes it from the
/// address alone and compares, or the group is not the same group. It covers the
/// group's whole public state: `B_group`, `Y_group`, the group KEM pubkey and
/// the N member KEM pubkeys, both version axes, and `m`/`n`. No per-output
/// value can serve as the group's identity, since every per-output key differs.
///
/// # Why cSHAKE256 and not the consensus-parity `keccak256`
///
/// The address is on **no consensus path** — no C++ mirror, no FFI, no leaf — so
/// nothing requires byte-identity with the Monero-descended daemon, which is
/// `shekyl_crypto_hash::keccak256`'s only reason to exist. What the address *does* have is four
/// independent implementers (payer wallet, scanner, exchange, light client), and
/// for them "Keccak-256" is not a function: original Keccak (0x01) and SHA3-256
/// (0x06) differ by one padding byte and fail *silently* — a different fingerprint,
/// no diagnostic. cSHAKE256 has one meaning, and its customization string makes the
/// domain separation structural instead of definitional. This matches the house
/// pattern for every new domain-separated artifact (`shekyl/archival-bundle-root-v1`,
/// `shekyl/receive-label-hash-v1`); `shekyl_crypto_hash::keccak256` keeps exactly
/// the consumers that require parity.
pub fn address_fingerprint(payload: &MultisigAddressPayload) -> [u8; 32] {
    MULTISIG_ADDRESS_FINGERPRINT
        .frame(&payload.network.name_id(), [&payload.to_canonical_bytes()])
        .into_bytes()
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
        // `0x40` keeps bit 255 clear. `0xC0` is the fingerprint pin's fill
        // and is not a key `new` accepts.
        MultisigAddressPayload::new(
            Network::Mainnet,
            n,
            m,
            [0xB1; 32],
            [0x71; 32],
            vec![0x40; HYBRID_KEM_PUBKEY_LEN],
            (0..n).map(|i| vec![i; HYBRID_KEM_PUBKEY_LEN]).collect(),
        )
        .unwrap()
    }

    #[test]
    fn canonical_roundtrip_2_of_3() {
        let payload = make_test_payload(3, 2);
        let bytes = payload.to_canonical_bytes();
        // PQC_MULTISIG.md §6.2's table: 70 + 4 · 1216.
        assert_eq!(bytes.len(), 4934);
        assert_eq!(bytes.len(), MultisigAddressPayload::canonical_len_for(3));
        let decoded = MultisigAddressPayload::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn canonical_roundtrip_2_of_2() {
        let payload = make_test_payload(2, 2);
        let bytes = payload.to_canonical_bytes();
        // PQC_MULTISIG.md §6.2's table: 70 + 3 · 1216.
        assert_eq!(bytes.len(), 3718);
        assert_eq!(bytes.len(), MultisigAddressPayload::canonical_len_for(2));
        let decoded = MultisigAddressPayload::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    /// R-11: a 1-of-N group is a shared key under a multisig label. Neither
    /// the constructor nor the decoder makes one, and a one-member group
    /// is refused as a participant count before its threshold is read.
    #[test]
    fn refuses_a_threshold_of_one_by_name() {
        let keys = |n: u8| (0..n).map(|i| vec![i; HYBRID_KEM_PUBKEY_LEN]).collect();
        let new = |n: u8, m: u8| {
            MultisigAddressPayload::new(
                Network::Mainnet,
                n,
                m,
                [0xB1; 32],
                [0x71; 32],
                vec![0x40; HYBRID_KEM_PUBKEY_LEN],
                keys(n),
            )
        };
        assert!(matches!(
            new(3, 1),
            Err(MultisigAddressError::InvalidThreshold { m: 1, n: 3 })
        ));
        assert!(matches!(
            new(1, 1),
            Err(MultisigAddressError::InvalidParticipantCount { n: 1 })
        ));

        // The decoder reads the same bounds: a 2-of-3 with its threshold
        // byte edited to 1 is refused, not decoded.
        let mut bytes = make_test_payload(3, 2).to_canonical_bytes();
        bytes[5] = 1;
        assert!(matches!(
            MultisigAddressPayload::from_canonical_bytes(&bytes),
            Err(MultisigAddressError::InvalidThreshold { m: 1, n: 3 })
        ));
    }

    #[test]
    fn canonical_roundtrip_5_of_5() {
        let payload = make_test_payload(MAX_MULTISIG_PARTICIPANTS, MAX_MULTISIG_PARTICIPANTS);
        let bytes = payload.to_canonical_bytes();
        // PQC_MULTISIG.md §6.2's table: 70 + 6 · 1216.
        assert_eq!(bytes.len(), 7366);
        assert_eq!(
            bytes.len(),
            MultisigAddressPayload::canonical_len_for(MAX_MULTISIG_PARTICIPANTS)
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
            vec![0xC0; HYBRID_KEM_PUBKEY_LEN],
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
            vec![0xC0; HYBRID_KEM_PUBKEY_LEN],
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
            vec![0xC0; HYBRID_KEM_PUBKEY_LEN],
            vec![
                vec![0; HYBRID_KEM_PUBKEY_LEN],
                vec![1; HYBRID_KEM_PUBKEY_LEN]
            ],
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
            vec![0xC0; HYBRID_KEM_PUBKEY_LEN],
            vec![vec![0; 100], vec![0; HYBRID_KEM_PUBKEY_LEN]],
        )
        .is_err());
    }

    #[test]
    fn rejects_a_group_key_that_repeats_a_member_and_duplicate_member_keys() {
        // `0x40` leaves bit 255 clear, so the refusal here is the repeated
        // point and not the encoding.
        let group_key = vec![0x40; HYBRID_KEM_PUBKEY_LEN];
        let member_a = vec![0x01; HYBRID_KEM_PUBKEY_LEN];
        let overlap = MultisigAddressPayload::new(
            Network::Mainnet,
            2,
            2,
            [0xB1; 32],
            [0x71; 32],
            group_key.clone(),
            vec![group_key.clone(), member_a.clone()],
        );
        assert!(matches!(
            overlap,
            Err(MultisigAddressError::GroupKemKeyRepeatsMember { index: 0 })
        ));

        let duplicated = MultisigAddressPayload::new(
            Network::Mainnet,
            2,
            2,
            [0xB1; 32],
            [0x71; 32],
            group_key.clone(),
            vec![member_a.clone(), member_a.clone()],
        );
        assert!(matches!(
            duplicated,
            Err(MultisigAddressError::DuplicateMemberKemKey {
                first: 0,
                second: 1
            })
        ));

        // The byte parser runs the same check: a payload whose fields were
        // edited after `new` still fails when it is read back.
        let mut payload = make_test_payload(2, 2);
        payload.hybrid_kem_pubkeys[1] = payload.hybrid_kem_pubkeys[0].clone();
        let bytes = payload.to_canonical_bytes();
        assert!(matches!(
            MultisigAddressPayload::from_canonical_bytes(&bytes),
            Err(MultisigAddressError::DuplicateMemberKemKey {
                first: 0,
                second: 1
            })
        ));
        payload.hybrid_kem_pubkeys[0] = payload.group_kem_pubkey.clone();
        let bytes = payload.to_canonical_bytes();
        assert!(matches!(
            MultisigAddressPayload::from_canonical_bytes(&bytes),
            Err(MultisigAddressError::GroupKemKeyRepeatsMember { index: 0 })
        ));
    }

    /// Bit 255 of an X25519 u-coordinate is ignored, and `u >= p` is the
    /// same field element as `u - p`. Either encoding of the group key, as
    /// a member key, would open under the group secret. Both are refused
    /// by `new` and by the byte parser.
    #[test]
    fn rejects_a_noncanonical_montgomery_half() {
        let members = vec![
            vec![0x01; HYBRID_KEM_PUBKEY_LEN],
            vec![0x02; HYBRID_KEM_PUBKEY_LEN],
        ];
        let mut group = vec![0x40; HYBRID_KEM_PUBKEY_LEN];
        group[31] |= 0x80;
        assert!(matches!(
            MultisigAddressPayload::new(
                Network::Mainnet,
                2,
                2,
                [0xB1; 32],
                [0x71; 32],
                group,
                members.clone(),
            ),
            Err(MultisigAddressError::NonCanonicalGroupKemKey)
        ));

        let group = vec![0x40; HYBRID_KEM_PUBKEY_LEN];
        let mut alias = group.clone();
        alias[31] |= 0x80;
        let built = MultisigAddressPayload::new(
            Network::Mainnet,
            2,
            2,
            [0xB1; 32],
            [0x71; 32],
            group.clone(),
            vec![alias, members[1].clone()],
        );
        assert!(matches!(
            built,
            Err(MultisigAddressError::NonCanonicalMemberKemKey { index: 0 })
        ));

        // `p` itself: bit 255 clear, integer equal to `2^255 - 19`.
        let mut at_prime = vec![0x11; HYBRID_KEM_PUBKEY_LEN];
        at_prime[0] = 0xED;
        for byte in &mut at_prime[1..31] {
            *byte = 0xFF;
        }
        at_prime[31] = 0x7F;
        assert!(matches!(
            MultisigAddressPayload::new(
                Network::Mainnet,
                2,
                2,
                [0xB1; 32],
                [0x71; 32],
                at_prime,
                members,
            ),
            Err(MultisigAddressError::NonCanonicalGroupKemKey)
        ));

        let mut payload = make_test_payload(2, 2);
        payload.hybrid_kem_pubkeys[0][31] |= 0x80;
        assert!(matches!(
            MultisigAddressPayload::from_canonical_bytes(&payload.to_canonical_bytes()),
            Err(MultisigAddressError::NonCanonicalMemberKemKey { index: 0 })
        ));
        payload.hybrid_kem_pubkeys[0][31] &= 0x7F;
        payload.group_kem_pubkey[31] |= 0x80;
        assert!(matches!(
            MultisigAddressPayload::from_canonical_bytes(&payload.to_canonical_bytes()),
            Err(MultisigAddressError::NonCanonicalGroupKemKey)
        ));
    }

    #[test]
    fn rejects_truncated_payload() {
        let payload = make_test_payload(2, 2);
        let bytes = payload.to_canonical_bytes();
        assert!(MultisigAddressPayload::from_canonical_bytes(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn rejects_unsupported_version() {
        // 0x01 is the layout without the group KEM key: refused by name.
        for version in [0x01u8, 0xFF] {
            let mut bytes = make_test_payload(2, 2).to_canonical_bytes();
            bytes[0] = version;
            assert!(matches!(
                MultisigAddressPayload::from_canonical_bytes(&bytes),
                Err(MultisigAddressError::UnsupportedVersion { version: v }) if v == version
            ));
        }
    }

    #[test]
    fn rejects_wrong_group_kem_pubkey_length() {
        assert!(matches!(
            MultisigAddressPayload::new(
                Network::Mainnet,
                2,
                2,
                [0xB1; 32],
                [0x71; 32],
                vec![0xC0; HYBRID_KEM_PUBKEY_LEN - 1],
                vec![vec![0; HYBRID_KEM_PUBKEY_LEN]; 2],
            ),
            Err(MultisigAddressError::GroupKemPubkeyLength { got }) if got == HYBRID_KEM_PUBKEY_LEN - 1
        ));
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
        // E′ payload = HEADER_LEN(6) + 2·GROUP_POINT_LEN(64)
        //            + (1 + N)·HYBRID_KEM_PUBKEY_LEN(1216) = 70 + (N + 1)·1216.
        for (n, expected) in [(2u8, 3718usize), (3, 4934), (5, 7366)] {
            let bytes = make_test_payload(n, 2).to_canonical_bytes();
            assert_eq!(bytes.len(), expected, "canonical length for n={n}");
            assert_eq!(bytes.len(), 70 + (n as usize + 1) * 1216);
        }
    }

    /// The vector file every independent implementer reproduces
    /// (`scripts/kat/multisig_fingerprint_oracle.py` recomputes it).
    const FINGERPRINT_VECTORS: &str =
        include_str!("../../../docs/test_vectors/MULTISIG_FINGERPRINT_V3.json");

    #[test]
    fn address_fingerprint_kat() {
        // Fixed payload → fixed cSHAKE256 fingerprint, per network. These
        // vectors *define* the fingerprint bytes every independent implementer
        // (payer wallet, scanner, exchange, light client) must reproduce, so
        // they are the code's test, never the other way round (rule 30). If
        // this fails, the preimage, the customization or the hash changed — do
        // NOT regenerate the vectors to make it pass. Either revert, or bump
        // the customization (a new domain) and re-pin with a recorded
        // rationale, as `-v2` did for the network's name (NI-R15) and `-v3`
        // for the envelope's name binding (2026-11-04).
        let vectors: serde_json::Value =
            serde_json::from_str(FINGERPRINT_VECTORS).expect("vectors parse");
        assert_eq!(
            vectors["customization"].as_str(),
            core::str::from_utf8(MULTISIG_ADDRESS_FINGERPRINT.customization()).ok()
        );
        let mut seen = Vec::new();
        for net in Network::ALL {
            // The pin is these bytes. `0xC0` sets bit 255 of the X25519 half,
            // which `new` now refuses; the fingerprint is of the payload, so
            // the struct is built directly and the hash does not move.
            let payload = MultisigAddressPayload {
                version: MULTISIG_ADDRESS_VERSION,
                group_version: GROUP_VERSION,
                spend_auth_version: SPEND_AUTH_VERSION,
                network: net,
                n_total: 2,
                m_required: 2,
                b_group: [0xB1; 32],
                y_group: [0x71; 32],
                group_kem_pubkey: vec![0xC0; HYBRID_KEM_PUBKEY_LEN],
                hybrid_kem_pubkeys: (0..2).map(|i| vec![i; HYBRID_KEM_PUBKEY_LEN]).collect(),
            };
            assert!(matches!(
                MultisigAddressPayload::new(
                    net,
                    2,
                    2,
                    payload.b_group,
                    payload.y_group,
                    payload.group_kem_pubkey.clone(),
                    payload.hybrid_kem_pubkeys.clone(),
                ),
                Err(MultisigAddressError::NonCanonicalGroupKemKey)
            ));
            let fp = address_fingerprint(&payload);
            let hex: String = fp.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(
                vectors["fingerprints"][net.name()].as_str(),
                Some(hex.as_str()),
                "{net}"
            );
            seen.push(fp);
        }
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            seen.len(),
            Network::ALL.len(),
            "two networks share a fingerprint"
        );
    }

    /// The fingerprint is the envelope over the payload, bound to the
    /// network's name: the same payload under another network's `name_id` is
    /// another fingerprint, and the construction is `frame` itself.
    #[test]
    fn the_fingerprint_is_the_names_frame_of_the_payload() {
        let payload = make_test_payload(2, 2);
        assert_eq!(
            address_fingerprint(&payload),
            MULTISIG_ADDRESS_FINGERPRINT
                .frame(&Network::Mainnet.name_id(), [&payload.to_canonical_bytes()])
                .into_bytes()
        );
        assert_ne!(
            address_fingerprint(&payload),
            MULTISIG_ADDRESS_FINGERPRINT
                .frame(&Network::Testnet.name_id(), [&payload.to_canonical_bytes()])
                .into_bytes(),
            "the name is load-bearing"
        );
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
            vec![0x40; HYBRID_KEM_PUBKEY_LEN],
            vec![
                vec![0; HYBRID_KEM_PUBKEY_LEN],
                vec![1; HYBRID_KEM_PUBKEY_LEN],
            ],
        )
        .unwrap();
        let p_test = MultisigAddressPayload::new(
            Network::Testnet,
            2,
            2,
            [0xB1; 32],
            [0x71; 32],
            vec![0x40; HYBRID_KEM_PUBKEY_LEN],
            vec![
                vec![0; HYBRID_KEM_PUBKEY_LEN],
                vec![1; HYBRID_KEM_PUBKEY_LEN],
            ],
        )
        .unwrap();
        assert_ne!(p_main.to_canonical_bytes(), p_test.to_canonical_bytes());
        assert_ne!(address_fingerprint(&p_main), address_fingerprint(&p_test));
    }
}
