// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Byte-exact `txin_archival_bond_post` wire (gate-4 §3.4.1).

use core::fmt;
use std::io::{self, Read, Write};

use shekyl_crypto_pq::multisig::SINGLE_KEY_CANONICAL_LEN;
use shekyl_io::{read_byte, read_bytes, read_varint, write_varint};

/// Vin type tag: `txin_archival_bond_post` (gate-4 §3.4.1).
pub const VIN_TYPE_ARCHIVAL_BOND_POST: u8 = 5;

/// cSHAKE256 customization for bond-post spend-auth preimage (gate-4 §3.4.1).
pub const BOND_POST_SIG_CUSTOMIZATION: &[u8] = b"shekyl/archival-bond-post-v1";

/// Canonical single [`HybridPublicKey`] encoding bound; matches
/// `config::PQC_HYBRID_SINGLE_KEY_LEN` in `cryptonote_config.h` (not multisig blob).
pub const MAX_HYBRID_PUBKEY_BYTES: usize = SINGLE_KEY_CANONICAL_LEN;
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
    HybridPubkeyTooLong { got: usize },
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
            Self::HybridPubkeyTooLong { got } => {
                write!(f, "hybrid pubkey length {got} exceeds bound")
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

fn write_holdings_descriptor<W: Write>(w: &mut W, h: &HoldingsDescriptor) -> io::Result<()> {
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
        if self.hybrid_public_key.len() > MAX_HYBRID_PUBKEY_BYTES {
            return Err(WireError::HybridPubkeyTooLong {
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
        if pk_len > MAX_HYBRID_PUBKEY_BYTES {
            return Err(WireError::HybridPubkeyTooLong { got: pk_len });
        }
        let mut hybrid_public_key = vec![0u8; pk_len];
        r.read_exact(&mut hybrid_public_key)?;
        let p_canonical_id = read_bytes(r)?;
        let post_kind = BondPostKind::from_u8(read_byte(r)?)?;
        let holdings_kind = HoldingsKind::from_u8(read_byte(r)?)?;
        let shard_ids = match holdings_kind {
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
        let bonded_total_atomic = read_varint(r)?;
        let bond_credit = read_varint(r)?;
        let bond_debit = read_varint(r)?;
        Ok(Self {
            hybrid_public_key,
            p_canonical_id,
            post_kind,
            holdings: HoldingsDescriptor {
                kind: holdings_kind,
                shard_ids,
            },
            bonded_total_atomic,
            bond_credit,
            bond_debit,
        })
    }

    /// Length-delimited parse: reject unread trailing bytes.
    pub fn read_payload_exact<R: Read>(r: &mut R) -> Result<Self, WireError> {
        let vin = Self::read_payload(r)?;
        crate::wire::ensure_payload_fully_consumed(r).map_err(|e| match e {
            crate::wire::WireError::TrailingBytes => WireError::TrailingBytes,
            crate::wire::WireError::Io(err) => WireError::Io(err),
            _ => WireError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected wire error during bond-post parse",
            )),
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
        let hybrid_pk = vec![0xAB; 64];
        let vin = ArchivalBondPostVin {
            hybrid_public_key: hybrid_pk.clone(),
            p_canonical_id: p_canonical_id_from_hybrid_pubkey(&hybrid_pk),
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
        let hybrid_pk = vec![0x01; 32];
        let vin = ArchivalBondPostVin {
            hybrid_public_key: hybrid_pk.clone(),
            p_canonical_id: p_canonical_id_from_hybrid_pubkey(&hybrid_pk),
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
        let hybrid_pk = vec![0xCD; 48];
        let vin = ArchivalBondPostVin {
            hybrid_public_key: hybrid_pk.clone(),
            p_canonical_id: p_canonical_id_from_hybrid_pubkey(&hybrid_pk),
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
}
