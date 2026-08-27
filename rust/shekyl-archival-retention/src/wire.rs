// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Byte-exact `txin_archival_serve_credit_response` wire (gate-2 §5.1).
//!
//! Serialization matches the canonical genesis tx-input varint discipline
//! (`shekyl-wire`'s transaction serializer, over `shekyl-curve-io`). Signature preimage
//! field encoding uses **fixed-width** `le64` / `le32` where the gate-2 §5.2 preimage
//! specifies it, not the on-wire varints.

use core::fmt;
use std::io::{self, Read, Write};

use sha3::digest::core_api::CoreWrapper;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake256, CShake256Core};
use shekyl_crypto_pq::signature::HybridSignature;
use shekyl_curve_io::{read_byte, read_bytes, read_varint, write_varint};

use crate::challenge::SERVE_CREDIT_RESPONSE_CUSTOMIZATION;
use crate::path::{SegmentPathOpening, CHALLENGED_LEAF_LEN};

/// Vin type tag: `txin_archival_serve_credit_response` (gate-2 §5.1).
///
/// Dense genesis tag scheme (§2.0, PR #168): `0x02`. Must equal the C++ oracle's
/// `VARIANT_TAG(txin_archival_serve_credit_response)` and shekyl-wire's
/// `TAG_INPUT_SERVE_CREDIT` — the same consensus discriminant.
pub const VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE: u8 = 0x02;

/// DoS guard: segment paths are shallow (segment subtree level); full tree depth
/// is bounded by FCMP++ design but this cap is consensus-load-bearing.
pub const MAX_PATH_LAYERS_PER_KIND: usize = 64;

/// DoS guard per branch chunk (generous vs `SELENE_CHUNK_WIDTH` / `HELIOS_CHUNK_WIDTH`).
pub const MAX_BRANCH_SCALARS: usize = 256;

/// The classical countersignature leg (RF-D2, kept side).
pub const ED25519_COUNTERSIGNATURE_LEN: usize = 64;
/// The post-quantum countersignature leg (RF-D2, pruned side): ML-DSA-65.
pub const ML_DSA_COUNTERSIGNATURE_LEN: usize = 3309;

/// The **kept** half of a pass record — the serve-credit vin payload
/// (gate-2 §5.1 as partitioned by `CR-D2` / `RF-D1`, `ARCHIVAL_RESPONSE_FORMAT.md` §3.5).
///
/// What identifies the record and lets the classical leg be checked. Every
/// field is fixed-width or a varint; there is no length a writer can get wrong.
///
/// # What is deliberately absent (`RF-D6` / `RF-D8`)
///
/// `segment_subroot_rk`, `leaf_index_in_segment` and `leaf_bytes` are **not**
/// here, under one criterion: *a value the verifier derives locally must not be
/// transported, because transporting it lets the prover choose it.* All three
/// are still **signed** — see [`Self::signature_preimage`], which takes them as
/// verifier-supplied parameters — so a prover that disagrees with the
/// verifier's derivation cannot produce a verifying signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivalServeCreditResponse {
    pub p_canonical_id: [u8; 32],
    pub shard_id: u64,
    pub settlement_epoch: u64,
    pub ed25519_countersignature: [u8; ED25519_COUNTERSIGNATURE_LEN],
}

/// The **pruned** half of a pass record (`RF-D1`), carried inside the
/// transaction's prunable region, one per serve-credit vin in vin order.
///
/// The ML-DSA leg is pruned because at 3,309 B it dominates the record and a
/// pruning node can still check the classical leg.
///
/// **`path` is deletion-bound** (`RF-D8` (i) RETRACTED 2026-08-26; the
/// argument is at `ARCHIVAL_RESPONSE_FORMAT.md`, grep `RF-D8` (i)). This
/// doc previously justified the field as "the only element consensus verifies
/// independently of the witness" — that justification is withdrawn: `P`
/// cannot countersign a preimage naming the challenged leaf without learning
/// which request is the challenge, which defeats the indistinguishability the
/// mechanism depends on. The field goes with the cutover, leaving this struct
/// holding the countersignature alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivalServeCreditPruned {
    pub path: SegmentPathOpening,
    pub ml_dsa_countersignature: [u8; ML_DSA_COUNTERSIGNATURE_LEN],
}

impl ArchivalServeCreditPruned {
    /// Serialize: `encode(path) ‖ ml_dsa(3309)`. No framing — the record is
    /// delimited by its own fixed tail, and the count by the vin count.
    pub fn write<W: Write>(&self, w: &mut W) -> Result<(), WireError> {
        write_branch_layers(w, &self.path.c1_layers)?;
        write_branch_layers(w, &self.path.c2_layers)?;
        w.write_all(&self.ml_dsa_countersignature)?;
        Ok(())
    }

    pub fn serialize(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        self.write(&mut out)?;
        Ok(out)
    }

    pub fn read<R: Read>(r: &mut R) -> Result<Self, WireError> {
        let c1_layers = read_branch_layers(r, "c1")?;
        let c2_layers = read_branch_layers(r, "c2")?;
        let ml_dsa_countersignature = read_bytes(r)?;
        Ok(Self {
            path: SegmentPathOpening {
                c1_layers,
                c2_layers,
            },
            ml_dsa_countersignature,
        })
    }

    /// Length-delimited parse: reject unread trailing bytes (FFI slice).
    pub fn read_exact<R: Read>(r: &mut R) -> Result<Self, WireError> {
        let pruned = Self::read(r)?;
        ensure_payload_fully_consumed(r)?;
        Ok(pruned)
    }
}

/// Reassemble the two countersignature legs into the [`HybridSignature`] the
/// verifier checks. The legs were one container before `RF-D2` split them
/// across the kept/pruned boundary; verification is unchanged.
#[must_use]
pub fn hybrid_countersignature(
    kept: &ArchivalServeCreditResponse,
    pruned: &ArchivalServeCreditPruned,
) -> HybridSignature {
    HybridSignature {
        ed25519: kept.ed25519_countersignature.to_vec(),
        ml_dsa: pruned.ml_dsa_countersignature.to_vec(),
    }
}

/// Split a [`HybridSignature`] into its two fixed-width legs, or `None` if a
/// leg is not the canonical length.
#[must_use]
pub fn split_countersignature(
    sig: &HybridSignature,
) -> Option<(
    [u8; ED25519_COUNTERSIGNATURE_LEN],
    [u8; ML_DSA_COUNTERSIGNATURE_LEN],
)> {
    Some((
        sig.ed25519.as_slice().try_into().ok()?,
        sig.ml_dsa.as_slice().try_into().ok()?,
    ))
}

#[derive(Debug)]
pub enum WireError {
    Io(io::Error),
    UnknownVinType(u8),
    LayerCountExceeded { kind: &'static str, got: usize },
    BranchWidthExceeded { layer: usize, got: usize },
    TrailingBytes,
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
            Self::TrailingBytes => write!(f, "trailing bytes after vin payload"),
        }
    }
}

/// The only two failure modes of [`ensure_payload_fully_consumed`].
///
/// A dedicated 2-variant type (not the module-wide [`WireError`]) so every caller
/// maps it **exhaustively** — the earlier `Result<(), WireError>` return forced
/// each wire module into a lossy `_ =>` catch-all that would have silently
/// swallowed any future variant into a fabricated `InvalidData` error.
#[derive(Debug)]
pub enum ExactParseError {
    /// A byte exists past the canonical field span.
    TrailingBytes,
    /// A non-EOF read error while probing.
    Io(io::Error),
}

/// Reject length-delimited vin payloads that carry bytes outside the canonical field span.
pub fn ensure_payload_fully_consumed<R: Read>(r: &mut R) -> Result<(), ExactParseError> {
    let mut extra = [0u8; 1];
    match r.read_exact(&mut extra) {
        Ok(()) => Err(ExactParseError::TrailingBytes),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
        Err(e) => Err(ExactParseError::Io(e)),
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

impl From<ExactParseError> for WireError {
    fn from(e: ExactParseError) -> Self {
        match e {
            ExactParseError::TrailingBytes => Self::TrailingBytes,
            ExactParseError::Io(err) => Self::Io(err),
        }
    }
}

fn write_fixed32<W: Write>(w: &mut W, bytes: &[u8; 32]) -> io::Result<()> {
    w.write_all(bytes)
}

fn write_branch_layers<W: Write>(w: &mut W, layers: &[Vec<[u8; 32]>]) -> Result<(), WireError> {
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
        // Fixed width: no length prefix, because there is no length to disagree about.
        w.write_all(&self.ed25519_countersignature)?;
        Ok(())
    }

    pub fn serialize(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        self.write(&mut out)?;
        Ok(out)
    }

    /// Deserialize payload fields after the type tag has been consumed.
    ///
    /// For transaction streams where more inputs follow, use this alone. For
    /// length-delimited FFI slices, use [`Self::read_payload_exact`].
    pub fn read_payload<R: Read>(r: &mut R) -> Result<Self, WireError> {
        let p_canonical_id = read_bytes(r)?;
        let shard_id = read_varint(r)?;
        let settlement_epoch = read_varint(r)?;
        let ed25519_countersignature = read_bytes(r)?;
        Ok(Self {
            p_canonical_id,
            shard_id,
            settlement_epoch,
            ed25519_countersignature,
        })
    }

    /// Length-delimited parse: reject unread trailing bytes (FFI vin payload).
    pub fn read_payload_exact<R: Read>(r: &mut R) -> Result<Self, WireError> {
        let response = Self::read_payload(r)?;
        ensure_payload_fully_consumed(r)?;
        Ok(response)
    }

    /// Read a full input including the type tag (must be [`VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE`]).
    pub fn read<R: Read>(r: &mut R) -> Result<Self, WireError> {
        let tag = read_byte(r)?;
        if tag != VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE {
            return Err(WireError::UnknownVinType(tag));
        }
        Self::read_payload(r)
    }

    /// Length-delimited parse of a tagged vin (`canonical_bytes`, tag included).
    pub fn read_exact<R: Read>(r: &mut R) -> Result<Self, WireError> {
        let response = Self::read(r)?;
        ensure_payload_fully_consumed(r)?;
        Ok(response)
    }

    /// cSHAKE256 preimage for hybrid signature verification (gate-2 §5.2).
    ///
    /// # Why two of the terms are parameters rather than fields
    ///
    /// `segment_subroot_rk` and `leaf_index_in_segment` are **still signed** —
    /// the preimage is byte-identical to what it always was — but `RF-D6` took
    /// them off the wire, so they no longer live on this struct. The verifier
    /// supplies them from its **own** derivation:
    ///
    /// | Term | Verifier's source |
    /// | --- | --- |
    /// | `segment_subroot_rk` | `LeafStore::frozen_segment(shard_id)` |
    /// | `leaf_index_in_segment` | `challenge_leaf_index(p_id, shard_id, epoch, …)` |
    ///
    /// **That is what makes the removal sound rather than merely thrifty.** A
    /// prover that lies about either value cannot produce a signature which
    /// verifies, because the verifier builds the preimage from what it derived,
    /// not from what it was told. Transporting the values would have let the
    /// prover choose them *and* sign them consistently; deriving them makes the
    /// signature bind the verifier's view.
    ///
    /// **Parameters, not caller-populated fields.** Leaving them on the struct
    /// for the caller to fill in would recreate precisely the hazard `RF-D5`
    /// rejected when it refused a caller-populated readability flag: a field
    /// someone must remember to set is a field someone will forget, and five
    /// C++ call sites forgot exactly that during `RF-D5`. As parameters the
    /// compiler demands them at every call site.
    ///
    /// **Rule 30 is satisfied by construction**: arity and byte layout of the
    /// preimage are unchanged, so the pinned cross-language vectors re-anchor
    /// without regenerating a signature — the same property preserving `r`'s
    /// arity bought in `RF-D5`.
    ///
    /// `leaf_bytes` joined the parameters under `RF-D8`: the verifier reads the
    /// challenged leaf from its own chunk (`path::challenged_leaf_bytes`), so it
    /// too is derived, signed, and never transported. `path` is the pruned
    /// half's — the one prover-supplied term. The byte layout is unchanged from
    /// the pre-split preimage, which is what keeps every pinned vector valid.
    pub fn signature_preimage(
        &self,
        segment_subroot_rk: &[u8; 32],
        leaf_index_in_segment: u32,
        leaf_bytes: &[u8; CHALLENGED_LEAF_LEN],
        path: &SegmentPathOpening,
    ) -> [u8; 32] {
        let mut input = Vec::with_capacity(32 + 8 + 8 + 32 + 4 + CHALLENGED_LEAF_LEN + 256);
        input.extend_from_slice(&self.p_canonical_id);
        input.extend_from_slice(&self.shard_id.to_le_bytes());
        input.extend_from_slice(&self.settlement_epoch.to_le_bytes());
        input.extend_from_slice(segment_subroot_rk);
        input.extend_from_slice(&leaf_index_in_segment.to_le_bytes());
        input.extend_from_slice(leaf_bytes);
        input.extend_from_slice(&encode_path(path));

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
        let (_pk, sk) = scheme
            .generate_ephemeral_keypair_for_tests()
            .expect("keypair");
        scheme
            .sign(
                &sk,
                shekyl_crypto_pq::signature::SCHEME_DOMAIN_SERVE_CREDIT,
                b"archival-serve-credit-wire-roundtrip",
            )
            .expect("sign")
    }

    #[test]
    fn kept_side_roundtrip_preserves_fields() {
        let response = ArchivalServeCreditResponse {
            p_canonical_id: [0x11; 32],
            shard_id: 42,
            settlement_epoch: 7,
            ed25519_countersignature: [0x66; ED25519_COUNTERSIGNATURE_LEN],
        };
        let bytes = response.serialize().expect("serialize");
        assert_eq!(bytes[0], VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE);
        // tag + 32 + varint(42) + varint(7) + 64: the kept side is ~99 B.
        assert_eq!(bytes.len(), 1 + 32 + 1 + 1 + 64);
        let decoded = ArchivalServeCreditResponse::read(&mut bytes.as_slice()).expect("read");
        assert_eq!(decoded, response);
    }

    #[test]
    fn pruned_side_roundtrip_preserves_fields() {
        let pruned = ArchivalServeCreditPruned {
            path: SegmentPathOpening {
                c1_layers: vec![vec![[0x44; 32]; 4]],
                c2_layers: vec![vec![[0x55; 32]; 8], vec![[0x66; 32]; 8]],
            },
            ml_dsa_countersignature: [0x77; ML_DSA_COUNTERSIGNATURE_LEN],
        };
        let bytes = pruned.serialize().expect("serialize");
        let decoded = ArchivalServeCreditPruned::read_exact(&mut bytes.as_slice()).expect("read");
        assert_eq!(decoded, pruned);
    }

    #[test]
    fn tagged_read_exact_rejects_wrong_tag() {
        let bytes = ArchivalServeCreditResponse {
            p_canonical_id: [0x11; 32],
            shard_id: 1,
            settlement_epoch: 2,
            ed25519_countersignature: [0x66; ED25519_COUNTERSIGNATURE_LEN],
        }
        .serialize()
        .expect("serialize");
        let mut bad = bytes;
        bad[0] = 0xFF;
        assert!(matches!(
            ArchivalServeCreditResponse::read_exact(&mut bad.as_slice()),
            Err(WireError::UnknownVinType(0xFF))
        ));
    }

    #[test]
    fn read_payload_rejects_trailing_bytes() {
        let mut bytes = ArchivalServeCreditResponse {
            p_canonical_id: [0x11; 32],
            shard_id: 1,
            settlement_epoch: 2,
            ed25519_countersignature: [0x66; ED25519_COUNTERSIGNATURE_LEN],
        }
        .serialize()
        .expect("serialize");
        bytes.push(0xFF);
        bytes.remove(0);
        let err = ArchivalServeCreditResponse::read_payload_exact(&mut bytes.as_slice())
            .expect_err("trailing byte");
        assert!(matches!(err, WireError::TrailingBytes));
    }

    #[test]
    fn pruned_read_rejects_trailing_bytes() {
        let mut bytes = ArchivalServeCreditPruned {
            path: SegmentPathOpening {
                c1_layers: vec![],
                c2_layers: vec![],
            },
            ml_dsa_countersignature: [0; ML_DSA_COUNTERSIGNATURE_LEN],
        }
        .serialize()
        .expect("serialize");
        bytes.push(0xFF);
        let err = ArchivalServeCreditPruned::read_exact(&mut bytes.as_slice())
            .expect_err("trailing byte");
        assert!(matches!(err, WireError::TrailingBytes));
    }

    #[test]
    fn countersignature_legs_split_and_reassemble() {
        let sig = dummy_hybrid_signature();
        let (ed, ml) = split_countersignature(&sig).expect("canonical legs");
        let kept = ArchivalServeCreditResponse {
            p_canonical_id: [0; 32],
            shard_id: 0,
            settlement_epoch: 0,
            ed25519_countersignature: ed,
        };
        let pruned = ArchivalServeCreditPruned {
            path: SegmentPathOpening {
                c1_layers: vec![],
                c2_layers: vec![],
            },
            ml_dsa_countersignature: ml,
        };
        assert_eq!(
            hybrid_countersignature(&kept, &pruned)
                .to_canonical_bytes()
                .unwrap(),
            sig.to_canonical_bytes().unwrap()
        );
    }

    #[test]
    fn signature_preimage_is_deterministic_and_binds_every_verifier_input() {
        let response = ArchivalServeCreditResponse {
            p_canonical_id: [1; 32],
            shard_id: 9,
            settlement_epoch: 3,
            ed25519_countersignature: [0; ED25519_COUNTERSIGNATURE_LEN],
        };
        let path = SegmentPathOpening {
            c1_layers: vec![vec![[4; 32]]],
            c2_layers: vec![],
        };
        let a = response.signature_preimage(&[2; 32], 7, &[3; 128], &path);
        assert_eq!(
            a,
            response.signature_preimage(&[2; 32], 7, &[3; 128], &path)
        );
        // Every verifier-supplied term is IN the preimage (RF-D6/RF-D8): a
        // different `R_k`, index or leaf is a different message, which is what
        // makes a prover unable to lie about any of them and still verify.
        assert_ne!(
            a,
            response.signature_preimage(&[9; 32], 7, &[3; 128], &path)
        );
        assert_ne!(
            a,
            response.signature_preimage(&[2; 32], 8, &[3; 128], &path)
        );
        assert_ne!(
            a,
            response.signature_preimage(&[2; 32], 7, &[9; 128], &path)
        );
    }
}
