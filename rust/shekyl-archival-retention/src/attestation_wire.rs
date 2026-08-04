// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Attestation wire + admission verify — the §3 record format and the §4
//! *admission* half of the seam (block-validation time, pre-prune).
//!
//! Design of record: [`ARCHIVAL_CREDIT_WIRE.md`](../../../docs/design/ARCHIVAL_CREDIT_WIRE.md)
//! (TJ-B step 3, shape 4). This module owns the parts admission touches — the
//! kept **header** bytes (`p_id, shard_id, E, kind`), the block-bound **nonce**,
//! the **`attestation_root`** over the signature set, and the **countersignature
//! verify**. Its sibling [`crate::attestation`] owns the settlement fold; the two
//! never share a signature, which is the §4 seam.
//!
//! # What `P` countersigns — resolved to the nonce (flag for ratification)
//!
//! `ARCHIVAL_CREDIT_WIRE.md` is internally inconsistent here: §3 says the
//! signature covers `H(nonce ‖ transfer_digest)`, while §3.3 says "over the
//! nonce". **The nonce-only reading is forced, not chosen:** `transfer_digest`
//! is a digest of the transferred shard bytes, which are not on-chain and not
//! reconstructable by consensus, so a signature over `H(nonce ‖ transfer_digest)`
//! could never be *verified* at admission. Only the nonce —
//! `H(r ‖ cb_out_key ‖ P ‖ s ‖ E)`, every term on-chain or derivable — is
//! consensus-verifiable, and §9.4's topology binding already carries the
//! read-happened property (the bytes traverse `P`'s link by path position, no
//! artifact from `P`). Built to the nonce; the doc's §3 line wants correcting.

use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSignature, SignatureScheme,
};
use shekyl_crypto_pq::CryptoError;

use crate::attestation::AttestationKind;
use crate::hash::cshake256_32;

/// cSHAKE customization for the block-bound challenge nonce (§3, copy-freeride
/// repair: the `cb_out_key` term binds the attestation to *this* block's
/// coinbase output).
pub const ATTESTATION_NONCE_CUSTOMIZATION: &[u8] = b"shekyl/archival-attestation-nonce-v1";

/// cSHAKE customization for `attestation_root` over the ordered signature set.
pub const ATTESTATION_ROOT_CUSTOMIZATION: &[u8] = b"shekyl/archival-attestation-root-v1";

/// Canonical kept-header length: `p_id(32) + shard_id(8) + settlement_epoch(8) +
/// kind(1)` (§3.1). The `kind` byte is the sole prune-surviving discriminant.
pub const ATTESTATION_HEADER_LEN: usize = 32 + 8 + 8 + 1;

/// `kind` byte encodings — fixed, not a bit in a status field, so a decoder
/// rejects anything that is neither (no silent third state).
const KIND_MISS: u8 = 0;
const KIND_PASS: u8 = 1;

/// The kept per-record header (§3.1), the only part that survives the prune.
/// Lives in the coinbase `tx_extra`, committed via `prefix_hash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationHeader {
    pub p_id: [u8; 32],
    pub shard_id: u64,
    pub settlement_epoch: u64,
    pub kind: AttestationKind,
}

/// A header failed to decode from its canonical bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AttestationHeaderError {
    /// Byte length is not [`ATTESTATION_HEADER_LEN`].
    #[error("attestation header wrong length: expected {ATTESTATION_HEADER_LEN}, got {0}")]
    WrongLength(usize),
    /// The `kind` byte is neither [`KIND_MISS`] nor [`KIND_PASS`].
    #[error("attestation header kind byte {0} is neither miss (0) nor pass (1)")]
    BadKind(u8),
}

impl AttestationHeader {
    /// Canonical bytes: `p_id ‖ shard_id_le ‖ settlement_epoch_le ‖ kind`.
    /// Little-endian for the counters, matching the archival lineage
    /// (`challenge.rs` uses `to_le_bytes`); fixed-width so the layout is
    /// position-addressable and never ambiguous.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> [u8; ATTESTATION_HEADER_LEN] {
        let mut out = [0u8; ATTESTATION_HEADER_LEN];
        out[0..32].copy_from_slice(&self.p_id);
        out[32..40].copy_from_slice(&self.shard_id.to_le_bytes());
        out[40..48].copy_from_slice(&self.settlement_epoch.to_le_bytes());
        out[48] = match self.kind {
            AttestationKind::Miss => KIND_MISS,
            AttestationKind::Pass => KIND_PASS,
        };
        out
    }

    /// Decode; rejects a wrong length or an out-of-range `kind` byte (loud, not
    /// a silent default — a malformed header is a block-validity failure).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AttestationHeaderError> {
        if bytes.len() != ATTESTATION_HEADER_LEN {
            return Err(AttestationHeaderError::WrongLength(bytes.len()));
        }
        let mut p_id = [0u8; 32];
        p_id.copy_from_slice(&bytes[0..32]);
        let shard_id = u64::from_le_bytes(bytes[32..40].try_into().expect("8 bytes"));
        let settlement_epoch = u64::from_le_bytes(bytes[40..48].try_into().expect("8 bytes"));
        let kind = match bytes[48] {
            KIND_MISS => AttestationKind::Miss,
            KIND_PASS => AttestationKind::Pass,
            other => return Err(AttestationHeaderError::BadKind(other)),
        };
        Ok(Self {
            p_id,
            shard_id,
            settlement_epoch,
            kind,
        })
    }
}

/// The block-bound challenge nonce `H(r ‖ cb_out_key ‖ p_id ‖ shard_id ‖ E)`
/// (§3). `r` is the producer's revealed randomness (coinbase extra),
/// `cb_out_key` the coinbase output key (the copy-freeride bind). Every term is
/// on-chain or derivable, so admission and any re-check recompute it identically.
#[must_use]
pub fn attestation_nonce(
    r: &[u8; 32],
    cb_out_key: &[u8; 32],
    p_id: &[u8; 32],
    shard_id: u64,
    settlement_epoch: u64,
) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + 32 + 32 + 8 + 8);
    input.extend_from_slice(r);
    input.extend_from_slice(cb_out_key);
    input.extend_from_slice(p_id);
    input.extend_from_slice(&shard_id.to_le_bytes());
    input.extend_from_slice(&settlement_epoch.to_le_bytes());
    cshake256_32(ATTESTATION_NONCE_CUSTOMIZATION, &input)
}

/// `attestation_root` over the block's ordered pass-signatures (§3.2) — the
/// value stored in the block field and mined over as a merkle leaf.
///
/// A flat cSHAKE over the count prefix and each signature's authoritative
/// fixed-length canonical encoding ([`HybridSignature::to_canonical_bytes`]).
/// Reusing the crate's own framing — rather than re-inventing a length-prefix —
/// means a malformed (wrong-length) signature is a loud [`CryptoError`], not a
/// silent truncation. **Defined-empty** (§3.2 invariant): an empty set hashes to
/// the customization over the bare count prefix, a fixed constant, so the leaf
/// is never omitted and the count never desyncs. (A binary merkle could replace
/// this if per-record signature pruning is ever wanted; the flat root is
/// sufficient for set commitment today.)
pub fn attestation_root(signatures: &[HybridSignature]) -> Result<[u8; 32], CryptoError> {
    let mut input = Vec::with_capacity(8 + signatures.len() * HybridSignature::CANONICAL_LEN);
    input.extend_from_slice(&(signatures.len() as u64).to_le_bytes());
    for sig in signatures {
        input.extend_from_slice(&sig.to_canonical_bytes()?);
    }
    Ok(cshake256_32(ATTESTATION_ROOT_CUSTOMIZATION, &input))
}

/// Verify one **pass** record's countersignature at admission (§3.3 step b).
///
/// Recompute the nonce and check it is `P`'s valid hybrid countersignature.
/// (Signed message = the nonce; see the module note on the doc's §3/§3.3
/// inconsistency.) A miss record has no signature and is not passed here.
#[must_use]
pub fn verify_pass_countersignature(
    r: &[u8; 32],
    cb_out_key: &[u8; 32],
    p_pubkey: &HybridPublicKey,
    header: &AttestationHeader,
    signature: &HybridSignature,
) -> bool {
    let nonce = attestation_nonce(
        r,
        cb_out_key,
        &header.p_id,
        header.shard_id,
        header.settlement_epoch,
    );
    HybridEd25519MlDsa
        .verify(p_pubkey, &nonce, signature)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_crypto_pq::signature::HybridSecretKey;

    fn keypair() -> (HybridPublicKey, HybridSecretKey) {
        HybridEd25519MlDsa
            .keypair_generate()
            .expect("keypair generates")
    }

    fn header(kind: AttestationKind) -> AttestationHeader {
        AttestationHeader {
            p_id: [7u8; 32],
            shard_id: 42,
            settlement_epoch: 1000,
            kind,
        }
    }

    #[test]
    fn header_bytes_roundtrip_and_reject_malformed() {
        for kind in [AttestationKind::Pass, AttestationKind::Miss] {
            let h = header(kind);
            let bytes = h.to_canonical_bytes();
            assert_eq!(bytes.len(), ATTESTATION_HEADER_LEN);
            assert_eq!(AttestationHeader::from_canonical_bytes(&bytes), Ok(h));
        }
        // Wrong length and a bad kind byte are loud errors, not silent defaults.
        assert_eq!(
            AttestationHeader::from_canonical_bytes(&[0u8; 10]),
            Err(AttestationHeaderError::WrongLength(10))
        );
        let mut bad = header(AttestationKind::Pass).to_canonical_bytes();
        bad[48] = 2;
        assert_eq!(
            AttestationHeader::from_canonical_bytes(&bad),
            Err(AttestationHeaderError::BadKind(2))
        );
    }

    #[test]
    fn nonce_binds_every_term() {
        let base = attestation_nonce(&[1; 32], &[2; 32], &[3; 32], 4, 5);
        // Changing any input changes the nonce (no term is dead).
        assert_ne!(base, attestation_nonce(&[9; 32], &[2; 32], &[3; 32], 4, 5)); // r
        assert_ne!(base, attestation_nonce(&[1; 32], &[9; 32], &[3; 32], 4, 5)); // cb_out_key
        assert_ne!(base, attestation_nonce(&[1; 32], &[2; 32], &[9; 32], 4, 5)); // p_id
        assert_ne!(base, attestation_nonce(&[1; 32], &[2; 32], &[3; 32], 9, 5)); // shard
        assert_ne!(base, attestation_nonce(&[1; 32], &[2; 32], &[3; 32], 4, 9)); // epoch
                                                                                 // Deterministic.
        assert_eq!(base, attestation_nonce(&[1; 32], &[2; 32], &[3; 32], 4, 5));
    }

    #[test]
    fn a_valid_countersignature_verifies_and_a_wrong_key_or_term_fails() {
        let (pubkey, secret) = keypair();
        let (r, cb) = ([11u8; 32], [22u8; 32]);
        let h = header(AttestationKind::Pass);
        let nonce = attestation_nonce(&r, &cb, &h.p_id, h.shard_id, h.settlement_epoch);
        let sig = HybridEd25519MlDsa
            .sign(&secret, &nonce)
            .expect("P signs the nonce");

        assert!(verify_pass_countersignature(&r, &cb, &pubkey, &h, &sig));

        // A signature over a DIFFERENT block's r must not verify — this is the
        // copy-freeride / cross-block replay defence at the crypto layer.
        assert!(!verify_pass_countersignature(
            &[99; 32], &cb, &pubkey, &h, &sig
        ));
        // Nor a different coinbase output key (the copy bind).
        assert!(!verify_pass_countersignature(
            &r, &[99; 32], &pubkey, &h, &sig
        ));
        // Nor a different pair.
        let mut other = h;
        other.shard_id = 43;
        assert!(!verify_pass_countersignature(
            &r, &cb, &pubkey, &other, &sig
        ));
    }

    #[test]
    fn attestation_root_is_defined_empty_and_set_sensitive() {
        // Defined-empty (§3.2 invariant): the empty set has a fixed root, never
        // omitted, so the merkle leaf and count never desync.
        let empty = attestation_root(&[]).unwrap();
        assert_eq!(empty, attestation_root(&[]).unwrap());

        let (_pk, sk) = keypair();
        let s1 = HybridEd25519MlDsa.sign(&sk, b"a").unwrap();
        let s2 = HybridEd25519MlDsa.sign(&sk, b"b").unwrap();
        // A non-empty set differs from empty, and order/content matter.
        assert_ne!(attestation_root(std::slice::from_ref(&s1)).unwrap(), empty);
        assert_ne!(
            attestation_root(&[s1.clone(), s2.clone()]).unwrap(),
            attestation_root(&[s2, s1]).unwrap()
        );
    }
}
