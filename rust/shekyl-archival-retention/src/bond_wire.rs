// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Byte-exact `txin_archival_bond_post` wire (gate-4 §3.4.1).

use core::fmt;
use std::io::{self, Read, Write};

use shekyl_crypto_pq::multisig::SINGLE_KEY_CANONICAL_LEN;
use shekyl_curve_io::{read_byte, read_bytes, read_varint, write_varint};

/// Vin type tag: `txin_archival_bond_post` (gate-4 §3.4.1).
///
/// Dense genesis tag scheme (§2.0, PR #168): `0x03`. Must equal the C++ oracle's
/// `VARIANT_TAG(txin_archival_bond_post)` and shekyl-wire's `TAG_INPUT_BOND_POST`
/// — the same consensus discriminant.
pub const VIN_TYPE_ARCHIVAL_BOND_POST: u8 = 0x03;

/// cSHAKE256 customization for bond-post spend-auth preimage (gate-4 §3.4.1).
pub const BOND_POST_SIG_CUSTOMIZATION: &[u8] = b"shekyl/archival-bond-post-v1";

/// Exact canonical single [`HybridPublicKey`] encoding length; matches
/// `config::PQC_HYBRID_SINGLE_KEY_LEN` in `cryptonote_config.h` (not multisig
/// blob). The wire demands **equality** — a truncated key is not a shorter
/// valid key, it is malformed (PR #229 review; the C++ oracle's structural
/// check was tightened to exact equality in the same change).
pub const HYBRID_PUBKEY_CANONICAL_BYTES: usize = SINGLE_KEY_CANONICAL_LEN;
pub const MAX_HOLDINGS_SHARDS: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BondPostKind {
    JoinMarket = 0,
    Rebond = 1,
    Unbond = 2,
    HoldingsUpdate = 3,
}

impl BondPostKind {
    pub fn from_u8(v: u8) -> Result<Self, WireError> {
        match v {
            0 => Ok(Self::JoinMarket),
            1 => Ok(Self::Rebond),
            2 => Ok(Self::Unbond),
            3 => Ok(Self::HoldingsUpdate),
            _ => Err(WireError::InvalidPostKind(v)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HoldingsKind {
    ShardSetCompact = 0,
    CompleteTree = 1,
}

impl HoldingsKind {
    pub fn from_u8(v: u8) -> Result<Self, WireError> {
        match v {
            0 => Ok(Self::ShardSetCompact),
            1 => Ok(Self::CompleteTree),
            _ => Err(WireError::InvalidHoldingsKind(v)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HoldingsDescriptor {
    pub kind: HoldingsKind,
    pub shard_ids: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivalBondPostVin {
    pub hybrid_public_key: Vec<u8>,
    pub p_canonical_id: [u8; 32],
    pub post_kind: BondPostKind,
    pub holdings: HoldingsDescriptor,
    pub bonded_total_atomic: u64,
    pub bond_credit: u64,
    pub bond_debit: u64,
}

#[derive(Debug)]
pub enum WireError {
    Io(io::Error),
    UnknownVinType(u8),
    HybridPubkeyLenNotCanonical { got: usize },
    HoldingsCountExceeded { got: usize },
    ShardListForbiddenForCompleteTree,
    InvalidPostKind(u8),
    InvalidHoldingsKind(u8),
    TrailingBytes,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::UnknownVinType(t) => write!(f, "unknown archival vin type {t}"),
            Self::HybridPubkeyLenNotCanonical { got } => {
                write!(
                    f,
                    "hybrid pubkey length {got} != canonical single-key length"
                )
            }
            Self::HoldingsCountExceeded { got } => {
                write!(f, "holdings shard count {got} exceeds bound")
            }
            Self::ShardListForbiddenForCompleteTree => {
                write!(f, "CompleteTree must not carry shard ids on wire")
            }
            Self::InvalidPostKind(v) => write!(f, "invalid bond post_kind {v}"),
            Self::InvalidHoldingsKind(v) => write!(f, "invalid holdings kind {v}"),
            Self::TrailingBytes => write!(f, "trailing bytes after bond-post payload"),
        }
    }
}

impl std::error::Error for WireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for WireError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Stream the §3.4.1 holdings encoding straight to a sink (no intermediate Vec).
/// Shared with the emission wire's `write()`; `encode_holdings_descriptor` wraps
/// this for callers that need the bytes (signature preimages / auth digests).
pub(crate) fn write_holdings_descriptor<W: Write>(
    w: &mut W,
    h: &HoldingsDescriptor,
) -> io::Result<()> {
    w.write_all(&[h.kind as u8])?;
    match h.kind {
        HoldingsKind::ShardSetCompact => {
            write_varint(&h.shard_ids.len(), w)?;
            for shard_id in &h.shard_ids {
                write_varint(shard_id, w)?;
            }
        }
        HoldingsKind::CompleteTree => {}
    }
    Ok(())
}

/// Holdings section bytes for §3.4.1 signature preimage (kind byte + optional shard list).
pub fn encode_holdings_descriptor(h: &HoldingsDescriptor) -> Result<Vec<u8>, WireError> {
    let mut out = Vec::new();
    write_holdings_descriptor(&mut out, h)?;
    Ok(out)
}

/// Read a [`HoldingsDescriptor`] (kind byte + optional shard list) — the §3.4.1
/// canonical holdings encoding. Shared with the emission vin
/// ([`crate::emission_wire`], §5.3 "must match bond record"), so the two wires
/// cannot drift on the holdings fragment.
pub fn read_holdings_descriptor<R: Read>(r: &mut R) -> Result<HoldingsDescriptor, WireError> {
    let kind = HoldingsKind::from_u8(read_byte(r)?)?;
    let shard_ids = match kind {
        HoldingsKind::ShardSetCompact => {
            let count: usize = read_varint(r)?;
            if count > MAX_HOLDINGS_SHARDS {
                return Err(WireError::HoldingsCountExceeded { got: count });
            }
            let mut ids = Vec::with_capacity(count);
            for _ in 0..count {
                ids.push(read_varint(r)?);
            }
            ids
        }
        HoldingsKind::CompleteTree => Vec::new(),
    };
    Ok(HoldingsDescriptor { kind, shard_ids })
}

impl ArchivalBondPostVin {
    /// `cSHAKE256` spend-auth preimage for the bond vin (`tx_prefix_hash` is 32 bytes).
    pub fn signature_preimage(&self, tx_prefix_hash: &[u8; 32]) -> [u8; 32] {
        let holdings = encode_holdings_descriptor(&self.holdings).expect("encode holdings");
        let mut input = Vec::with_capacity(32 + 32 + 1 + holdings.len() + 24);
        input.extend_from_slice(tx_prefix_hash);
        input.extend_from_slice(&self.p_canonical_id);
        input.push(self.post_kind as u8);
        input.extend_from_slice(&holdings);
        input.extend_from_slice(&self.bonded_total_atomic.to_le_bytes());
        input.extend_from_slice(&self.bond_credit.to_le_bytes());
        input.extend_from_slice(&self.bond_debit.to_le_bytes());
        crate::hash::cshake256_32(BOND_POST_SIG_CUSTOMIZATION, &input)
    }

    pub fn write<W: Write>(&self, w: &mut W) -> Result<(), WireError> {
        if self.hybrid_public_key.len() != HYBRID_PUBKEY_CANONICAL_BYTES {
            return Err(WireError::HybridPubkeyLenNotCanonical {
                got: self.hybrid_public_key.len(),
            });
        }
        if self.holdings.kind == HoldingsKind::ShardSetCompact
            && self.holdings.shard_ids.len() > MAX_HOLDINGS_SHARDS
        {
            return Err(WireError::HoldingsCountExceeded {
                got: self.holdings.shard_ids.len(),
            });
        }
        if self.holdings.kind == HoldingsKind::CompleteTree && !self.holdings.shard_ids.is_empty() {
            return Err(WireError::ShardListForbiddenForCompleteTree);
        }

        w.write_all(&[VIN_TYPE_ARCHIVAL_BOND_POST])?;
        write_varint(&self.hybrid_public_key.len(), w)?;
        w.write_all(&self.hybrid_public_key)?;
        w.write_all(&self.p_canonical_id)?;
        w.write_all(&[self.post_kind as u8])?;
        write_holdings_descriptor(w, &self.holdings)?;
        write_varint(&self.bonded_total_atomic, w)?;
        write_varint(&self.bond_credit, w)?;
        write_varint(&self.bond_debit, w)?;
        Ok(())
    }

    pub fn serialize(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        self.write(&mut out)?;
        Ok(out)
    }

    pub fn read_payload<R: Read>(r: &mut R) -> Result<Self, WireError> {
        let pk_len: usize = read_varint(r)?;
        if pk_len != HYBRID_PUBKEY_CANONICAL_BYTES {
            return Err(WireError::HybridPubkeyLenNotCanonical { got: pk_len });
        }
        let mut hybrid_public_key = vec![0u8; pk_len];
        r.read_exact(&mut hybrid_public_key)?;
        let p_canonical_id = read_bytes(r)?;
        let post_kind = BondPostKind::from_u8(read_byte(r)?)?;
        let holdings = read_holdings_descriptor(r)?;
        let bonded_total_atomic = read_varint(r)?;
        let bond_credit = read_varint(r)?;
        let bond_debit = read_varint(r)?;
        Ok(Self {
            hybrid_public_key,
            p_canonical_id,
            post_kind,
            holdings,
            bonded_total_atomic,
            bond_credit,
            bond_debit,
        })
    }

    /// Length-delimited parse: reject unread trailing bytes.
    pub fn read_payload_exact<R: Read>(r: &mut R) -> Result<Self, WireError> {
        let vin = Self::read_payload(r)?;
        crate::wire::ensure_payload_fully_consumed(r).map_err(|e| match e {
            crate::wire::ExactParseError::TrailingBytes => WireError::TrailingBytes,
            crate::wire::ExactParseError::Io(err) => WireError::Io(err),
        })?;
        Ok(vin)
    }

    pub fn read<R: Read>(r: &mut R) -> Result<Self, WireError> {
        let tag = read_byte(r)?;
        if tag != VIN_TYPE_ARCHIVAL_BOND_POST {
            return Err(WireError::UnknownVinType(tag));
        }
        Self::read_payload(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::p_canonical_id_from_hybrid_pubkey;

    #[test]
    fn bond_post_roundtrip_shard_set() {
        let hybrid_pk = vec![0xAB; HYBRID_PUBKEY_CANONICAL_BYTES];
        let vin = ArchivalBondPostVin {
            hybrid_public_key: hybrid_pk.clone(),
            p_canonical_id: p_canonical_id_from_hybrid_pubkey(&hybrid_pk).to_bytes(),
            post_kind: BondPostKind::JoinMarket,
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::ShardSetCompact,
                shard_ids: vec![7, 42],
            },
            bonded_total_atomic: 1_500_000_000,
            bond_credit: 1_500_000_000,
            bond_debit: 0,
        };
        let wire = vin.serialize().unwrap();
        assert_eq!(wire[0], VIN_TYPE_ARCHIVAL_BOND_POST);
        let decoded = ArchivalBondPostVin::read(&mut wire.as_slice()).unwrap();
        assert_eq!(decoded, vin);
    }

    #[test]
    fn bond_post_complete_tree_has_no_shard_list_on_wire() {
        let hybrid_pk = vec![0x01; HYBRID_PUBKEY_CANONICAL_BYTES];
        let vin = ArchivalBondPostVin {
            hybrid_public_key: hybrid_pk.clone(),
            p_canonical_id: p_canonical_id_from_hybrid_pubkey(&hybrid_pk).to_bytes(),
            post_kind: BondPostKind::JoinMarket,
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::CompleteTree,
                shard_ids: Vec::new(),
            },
            bonded_total_atomic: 750_000_000,
            bond_credit: 750_000_000,
            bond_debit: 0,
        };
        let wire = vin.serialize().unwrap();
        let decoded = ArchivalBondPostVin::read(&mut wire.as_slice()).unwrap();
        assert_eq!(decoded.holdings.kind, HoldingsKind::CompleteTree);
        assert!(decoded.holdings.shard_ids.is_empty());
    }

    #[test]
    fn signature_preimage_is_stable() {
        let hybrid_pk = vec![0xCD; HYBRID_PUBKEY_CANONICAL_BYTES];
        let vin = ArchivalBondPostVin {
            hybrid_public_key: hybrid_pk.clone(),
            p_canonical_id: p_canonical_id_from_hybrid_pubkey(&hybrid_pk).to_bytes(),
            post_kind: BondPostKind::JoinMarket,
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::ShardSetCompact,
                shard_ids: vec![99],
            },
            bonded_total_atomic: 750_000_000,
            bond_credit: 750_000_000,
            bond_debit: 0,
        };
        let tx_prefix = [0x42u8; 32];
        let h1 = vin.signature_preimage(&tx_prefix);
        let h2 = vin.signature_preimage(&tx_prefix);
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    /// A truncated (or over-long) hybrid pubkey is malformed, not a shorter
    /// valid key — both write and read demand the exact canonical length
    /// (mirrors the emission wire; the C++ oracle enforces the same equality).
    #[test]
    fn bond_post_rejects_non_canonical_pubkey_length() {
        let mut vin = ArchivalBondPostVin {
            hybrid_public_key: vec![0xAB; HYBRID_PUBKEY_CANONICAL_BYTES - 1],
            p_canonical_id: [0x11; 32],
            post_kind: BondPostKind::JoinMarket,
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::CompleteTree,
                shard_ids: Vec::new(),
            },
            bonded_total_atomic: 750_000_000,
            bond_credit: 750_000_000,
            bond_debit: 0,
        };
        assert!(matches!(
            vin.serialize(),
            Err(WireError::HybridPubkeyLenNotCanonical { .. })
        ));
        vin.hybrid_public_key = vec![0xAB; HYBRID_PUBKEY_CANONICAL_BYTES + 1];
        assert!(matches!(
            vin.serialize(),
            Err(WireError::HybridPubkeyLenNotCanonical { .. })
        ));

        // Read side: craft a payload with a truncated pk_len.
        let mut wire = Vec::new();
        write_varint(&(HYBRID_PUBKEY_CANONICAL_BYTES - 1), &mut wire).unwrap();
        wire.extend_from_slice(&vec![0xAB; HYBRID_PUBKEY_CANONICAL_BYTES - 1]);
        assert!(matches!(
            ArchivalBondPostVin::read_payload(&mut wire.as_slice()),
            Err(WireError::HybridPubkeyLenNotCanonical { .. })
        ));
    }

    /// Golden byte vector for the shared holdings codec.
    ///
    /// **Blast radius: TWO consensus wires.** This fragment is byte-identical on
    /// the bond-post wire (`0x03`, this module) **and** the reward-emission wire
    /// (`0x04`, [`crate::emission_wire`], which mirrors this exact pin in
    /// `emission_wire::tests::holdings_codec_golden_vector_shared_with_bond_wire`).
    /// A change that moves these bytes is a consensus change to both surfaces and
    /// must fail both suites loudly — do not "fix" this test by updating the pin
    /// without a genesis-format decision covering both wires.
    #[test]
    fn holdings_codec_golden_vector_shared_with_emission_wire() {
        let shard_set = HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: vec![7, 42],
        };
        assert_eq!(
            encode_holdings_descriptor(&shard_set).unwrap(),
            [0x00, 0x02, 0x07, 0x2A],
            "ShardSetCompact golden bytes moved — consensus change to BOTH wires"
        );
        let complete = HoldingsDescriptor {
            kind: HoldingsKind::CompleteTree,
            shard_ids: Vec::new(),
        };
        assert_eq!(
            encode_holdings_descriptor(&complete).unwrap(),
            [0x01],
            "CompleteTree golden byte moved — consensus change to BOTH wires"
        );
        // Read side of the same pin: the golden bytes decode back exactly.
        assert_eq!(
            read_holdings_descriptor(&mut [0x00u8, 0x02, 0x07, 0x2A].as_slice()).unwrap(),
            shard_set
        );
        assert_eq!(
            read_holdings_descriptor(&mut [0x01u8].as_slice()).unwrap(),
            complete
        );
    }
}
