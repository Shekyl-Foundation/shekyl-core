// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Byte-exact `txin_archival_serve_credit_response` wire (gate-2 §5.1).
//!
//! Serialization matches [`shekyl-oxide` transaction input] varint discipline
//! (`shekyl-io`). Signature preimage field encoding uses **fixed-width** `le64` /
//! `le32` where the gate-2 §5.2 preimage specifies it, not the on-wire varints.
//!
//! [`shekyl-oxide` transaction input]: ../../../shekyl-oxide/shekyl-oxide/src/transaction.rs

use core::fmt;
use std::io::{self, Read, Write};

use sha3::digest::core_api::CoreWrapper;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake256, CShake256Core};
use shekyl_crypto_pq::signature::HybridSignature;
use shekyl_io::{read_byte, read_bytes, read_u32, read_varint, write_varint};

/// Upper bound on hybrid signature canonical encoding (Ed25519 + ML-DSA-65 + header).
const MAX_HYBRID_SIGNATURE_BYTES: usize = 16_384;

use crate::challenge::SERVE_CREDIT_RESPONSE_CUSTOMIZATION;
use crate::path::SegmentPathOpening;

/// Vin type tag: `txin_archival_serve_credit_response` (gate-2 §5.1).
pub const VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE: u8 = 4;

/// DoS guard: segment paths are shallow (segment subtree level); full tree depth
/// is bounded by FCMP++ design but this cap is consensus-load-bearing.
pub const MAX_PATH_LAYERS_PER_KIND: usize = 64;

/// DoS guard per branch chunk (generous vs `SELENE_CHUNK_WIDTH` / `HELIOS_CHUNK_WIDTH`).
pub const MAX_BRANCH_SCALARS: usize = 256;

/// Logical vin payload (gate-2 §5.1).
#[derive(Clone, Debug)]
pub struct ArchivalServeCreditResponse {
    pub p_canonical_id: [u8; 32],
    pub shard_id: u64,
    pub settlement_epoch: u64,
    pub segment_subroot_rk: [u8; 32],
    pub leaf_index_in_segment: u32,
    pub leaf_bytes: [u8; 128],
    pub path: SegmentPathOpening,
    pub hybrid_signature: HybridSignature,
}

#[derive(Debug)]
pub enum WireError {
    Io(io::Error),
    UnknownVinType(u8),
    LayerCountExceeded { kind: &'static str, got: usize },
    BranchWidthExceeded { layer: usize, got: usize },
    InvalidHybridSignature(String),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::UnknownVinType(t) => write!(f, "unknown archival vin type {t}"),
            Self::LayerCountExceeded { kind, got } => {
                write!(f, "too many {kind} path layers: {got}")
            }
            Self::BranchWidthExceeded { layer, got } => {
                write!(f, "path branch {layer} too wide: {got} scalars")
            }
            Self::InvalidHybridSignature(msg) => write!(f, "invalid hybrid signature: {msg}"),
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

fn write_fixed32<W: Write>(w: &mut W, bytes: &[u8; 32]) -> io::Result<()> {
    w.write_all(bytes)
}

fn write_branch_layers<W: Write>(
    w: &mut W,
    layers: &[Vec<[u8; 32]>],
) -> Result<(), WireError> {
    write_varint(&layers.len(), w)?;
    for (i, branch) in layers.iter().enumerate() {
        if branch.len() > MAX_BRANCH_SCALARS {
            return Err(WireError::BranchWidthExceeded {
                layer: i,
                got: branch.len(),
            });
        }
        write_varint(&branch.len(), w)?;
        for scalar in branch {
            write_fixed32(w, scalar)?;
        }
    }
    Ok(())
}

fn read_branch_layers<R: Read>(
    r: &mut R,
    kind: &'static str,
) -> Result<Vec<Vec<[u8; 32]>>, WireError> {
    let layer_count: usize = read_varint(r)?;
    if layer_count > MAX_PATH_LAYERS_PER_KIND {
        return Err(WireError::LayerCountExceeded {
            kind,
            got: layer_count,
        });
    }
    let mut layers = Vec::with_capacity(layer_count);
    for i in 0..layer_count {
        let width: usize = read_varint(r)?;
        if width > MAX_BRANCH_SCALARS {
            return Err(WireError::BranchWidthExceeded {
                layer: i,
                got: width,
            });
        }
        let mut branch = Vec::with_capacity(width);
        for _ in 0..width {
            branch.push(read_bytes(r)?);
        }
        layers.push(branch);
    }
    Ok(layers)
}

/// Canonical `encode(path)` bytes shared by wire and §5.2 signature preimage.
pub fn encode_path(path: &SegmentPathOpening) -> Vec<u8> {
    let mut out = Vec::new();
    write_branch_layers(&mut out, &path.c1_layers).expect("Vec write");
    write_branch_layers(&mut out, &path.c2_layers).expect("Vec write");
    out
}

impl ArchivalServeCreditResponse {
    /// Serialize this vin (including the leading type tag).
    pub fn write<W: Write>(&self, w: &mut W) -> Result<(), WireError> {
        w.write_all(&[VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE])?;
        write_fixed32(w, &self.p_canonical_id)?;
        write_varint(&self.shard_id, w)?;
        write_varint(&self.settlement_epoch, w)?;
        write_fixed32(w, &self.segment_subroot_rk)?;
        w.write_all(&self.leaf_index_in_segment.to_le_bytes())?;
        w.write_all(&self.leaf_bytes)?;
        write_branch_layers(w, &self.path.c1_layers)?;
        write_branch_layers(w, &self.path.c2_layers)?;
        let sig_bytes = self
            .hybrid_signature
            .to_canonical_bytes()
            .map_err(|e| WireError::InvalidHybridSignature(e.to_string()))?;
        write_varint(&sig_bytes.len(), w)?;
        w.write_all(&sig_bytes)?;
        Ok(())
    }

    pub fn serialize(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        self.write(&mut out)?;
        Ok(out)
    }

    /// Deserialize a vin after the type tag has been consumed.
    pub fn read_payload<R: Read>(r: &mut R) -> Result<Self, WireError> {
        let p_canonical_id = read_bytes(r)?;
        let shard_id = read_varint(r)?;
        let settlement_epoch = read_varint(r)?;
        let segment_subroot_rk = read_bytes(r)?;
        let leaf_index_in_segment = read_u32(r)?;
        let leaf_bytes = read_bytes(r)?;
        let c1_layers = read_branch_layers(r, "c1")?;
        let c2_layers = read_branch_layers(r, "c2")?;
        let sig_len: usize = read_varint(r)?;
        if sig_len > MAX_HYBRID_SIGNATURE_BYTES {
            return Err(WireError::InvalidHybridSignature(format!(
                "signature length {sig_len} exceeds bound"
            )));
        }
        let mut sig_bytes = vec![0u8; sig_len];
        r.read_exact(&mut sig_bytes)?;
        let hybrid_signature = HybridSignature::from_canonical_bytes(&sig_bytes)
            .map_err(|e| WireError::InvalidHybridSignature(e.to_string()))?;
        Ok(Self {
            p_canonical_id,
            shard_id,
            settlement_epoch,
            segment_subroot_rk,
            leaf_index_in_segment,
            leaf_bytes,
            path: SegmentPathOpening {
                c1_layers,
                c2_layers,
            },
            hybrid_signature,
        })
    }

    /// Read a full input including the type tag (must be [`VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE`]).
    pub fn read<R: Read>(r: &mut R) -> Result<Self, WireError> {
        let tag = read_byte(r)?;
        if tag != VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE {
            return Err(WireError::UnknownVinType(tag));
        }
        Self::read_payload(r)
    }

    /// cSHAKE256 preimage for hybrid signature verification (gate-2 §5.2).
    pub fn signature_preimage(&self) -> [u8; 32] {
        let mut input = Vec::with_capacity(32 + 8 + 8 + 32 + 4 + 128 + 256);
        input.extend_from_slice(&self.p_canonical_id);
        input.extend_from_slice(&self.shard_id.to_le_bytes());
        input.extend_from_slice(&self.settlement_epoch.to_le_bytes());
        input.extend_from_slice(&self.segment_subroot_rk);
        input.extend_from_slice(&self.leaf_index_in_segment.to_le_bytes());
        input.extend_from_slice(&self.leaf_bytes);
        input.extend_from_slice(&encode_path(&self.path));

        let core = CShake256Core::new(SERVE_CREDIT_RESPONSE_CUSTOMIZATION);
        let mut hasher: CShake256 = CoreWrapper::from_core(core);
        hasher.update(&input);
        let mut reader = hasher.finalize_xof();
        let mut out = [0u8; 32];
        XofReader::read(&mut reader, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::SegmentPathOpening;

    fn dummy_hybrid_signature() -> HybridSignature {
        use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, SignatureScheme};
        let scheme = HybridEd25519MlDsa;
        let (_pk, sk) = scheme.keypair_generate().expect("keypair");
        scheme
            .sign(&sk, b"archival-serve-credit-wire-roundtrip")
            .expect("sign")
    }

    #[test]
    fn wire_roundtrip_preserves_fields() {
        let response = ArchivalServeCreditResponse {
            p_canonical_id: [0x11; 32],
            shard_id: 42,
            settlement_epoch: 7,
            segment_subroot_rk: [0x22; 32],
            leaf_index_in_segment: 1_234,
            leaf_bytes: [0x33; 128],
            path: SegmentPathOpening {
                c1_layers: vec![vec![[0x44; 32]; 4]],
                c2_layers: vec![vec![[0x55; 32]; 8], vec![[0x66; 32]; 8]],
            },
            hybrid_signature: dummy_hybrid_signature(),
        };

        let bytes = response.serialize().expect("serialize");
        assert_eq!(bytes[0], VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE);
        let decoded = ArchivalServeCreditResponse::read(&mut bytes.as_slice()).expect("read");
        assert_eq!(decoded.p_canonical_id, response.p_canonical_id);
        assert_eq!(decoded.shard_id, response.shard_id);
        assert_eq!(decoded.settlement_epoch, response.settlement_epoch);
        assert_eq!(decoded.segment_subroot_rk, response.segment_subroot_rk);
        assert_eq!(decoded.leaf_index_in_segment, response.leaf_index_in_segment);
        assert_eq!(decoded.leaf_bytes, response.leaf_bytes);
        assert_eq!(decoded.path, response.path);
        assert_eq!(
            decoded.hybrid_signature.to_canonical_bytes().unwrap(),
            response.hybrid_signature.to_canonical_bytes().unwrap(),
        );
    }

    #[test]
    fn signature_preimage_is_deterministic() {
        let response = ArchivalServeCreditResponse {
            p_canonical_id: [1; 32],
            shard_id: 9,
            settlement_epoch: 3,
            segment_subroot_rk: [2; 32],
            leaf_index_in_segment: 5,
            leaf_bytes: [3; 128],
            path: SegmentPathOpening {
                c1_layers: vec![vec![[4; 32]]],
                c2_layers: vec![],
            },
            hybrid_signature: dummy_hybrid_signature(),
        };
        let a = response.signature_preimage();
        let b = response.signature_preimage();
        assert_eq!(a, b);
    }
}
