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
//!
//! Nonce-only is also *complete*, not merely necessary: the shard is named by
//! `s` (`shard_id`) which is already a nonce term, so appending any on-chain
//! shard-content commitment (`R_k`) would add no binding power `s` does not
//! already carry. There is nothing a `transfer_digest` could bind that the
//! nonce does not.

use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSignature, SignatureScheme,
};
use shekyl_crypto_pq::CryptoError;

use crate::attestation::AttestationKind;
use crate::hash::cshake256_32;
use crate::id::p_canonical_id_from_hybrid_pubkey;

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

/// `attestation_root` over the block's pass-records (§3.2) — the value stored in
/// the block field and mined over as a merkle leaf.
///
/// Each record contributes `header_canonical ‖ signature_canonical`, so the root
/// commits the header↔signature **pairing** — not just the signatures, and not
/// in an unstated positional order. Records are **sorted by these canonical
/// bytes** before hashing, giving one defined order that every producer and
/// every re-validating node (reading the signatures back from the pruned side
/// table) reproduces identically; a caller-supplied order would be an unstated
/// obligation whose violation forks consensus. Each signature is in its
/// authoritative fixed-length canonical encoding
/// ([`HybridSignature::to_canonical_bytes`]), so a malformed (wrong-length)
/// signature is a loud [`CryptoError`], not a silent truncation.
///
/// **Defined-empty** (§3.2 invariant): an empty set hashes to the customization
/// over the bare count prefix, a fixed constant, so the leaf is never omitted
/// and the count never desyncs. (A binary merkle could replace this if per-record
/// signature pruning is ever wanted; the flat root is sufficient for set
/// commitment today.)
pub fn attestation_root(
    records: &[(AttestationHeader, HybridSignature)],
) -> Result<[u8; 32], CryptoError> {
    const RECORD_LEN: usize = ATTESTATION_HEADER_LEN + HybridSignature::CANONICAL_LEN;
    let mut record_bytes: Vec<[u8; RECORD_LEN]> = Vec::with_capacity(records.len());
    for (header, sig) in records {
        let mut rec = [0u8; RECORD_LEN];
        rec[..ATTESTATION_HEADER_LEN].copy_from_slice(&header.to_canonical_bytes());
        rec[ATTESTATION_HEADER_LEN..].copy_from_slice(&sig.to_canonical_bytes()?);
        record_bytes.push(rec);
    }
    record_bytes.sort_unstable();

    let mut input = Vec::with_capacity(8 + records.len() * RECORD_LEN);
    input.extend_from_slice(&(records.len() as u64).to_le_bytes());
    for rec in &record_bytes {
        input.extend_from_slice(rec);
    }
    Ok(cshake256_32(ATTESTATION_ROOT_CUSTOMIZATION, &input))
}

/// Verify one **pass** record's countersignature at admission (§3.3 step b).
///
/// Two bindings, both self-contained here so no correctness rides on the caller:
///
/// 1. **`p_id` binds the key.** The header's `p_id` must be *this pubkey's*
///    canonical id ([`p_canonical_id_from_hybrid_pubkey`]) — otherwise any key
///    could countersign an attestation naming a different principal, and a
///    caller that mis-pairs a registry pubkey with a foreign header would not be
///    caught. One hash makes the binding structural.
/// 2. **The signature covers the nonce.** Recompute
///    `H(r ‖ cb_out_key ‖ P ‖ s ‖ E)` and check `P`'s hybrid countersignature
///    over it. (Signed message = the nonce; see the module note on the doc's
///    §3/§3.3 inconsistency.)
///
/// A miss record has no signature and is not passed here.
#[must_use]
pub fn verify_pass_countersignature(
    r: &[u8; 32],
    cb_out_key: &[u8; 32],
    p_pubkey: &HybridPublicKey,
    header: &AttestationHeader,
    signature: &HybridSignature,
) -> bool {
    // Binding 1: the header's p_id must be this pubkey's canonical id.
    let Ok(pubkey_bytes) = p_pubkey.to_canonical_bytes() else {
        return false;
    };
    if p_canonical_id_from_hybrid_pubkey(&pubkey_bytes).as_bytes() != &header.p_id {
        return false;
    }
    // Binding 2: P's countersignature over the block-bound nonce.
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

    /// This pubkey's canonical id — the value the header's `p_id` must equal for
    /// `verify_pass_countersignature`'s binding-1 to hold.
    fn p_id_of(pubkey: &HybridPublicKey) -> [u8; 32] {
        let bytes = pubkey.to_canonical_bytes().expect("canonical pubkey");
        *p_canonical_id_from_hybrid_pubkey(&bytes).as_bytes()
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
        // Binding 1 requires the header's p_id to be this key's canonical id.
        let h = AttestationHeader {
            p_id: p_id_of(&pubkey),
            shard_id: 42,
            settlement_epoch: 1000,
            kind: AttestationKind::Pass,
        };
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
        // Nor a different (shard, epoch) term in the header.
        let mut other = h;
        other.shard_id = 43;
        assert!(!verify_pass_countersignature(
            &r, &cb, &pubkey, &other, &sig
        ));

        // Binding 1 in isolation: a header whose p_id is NOT this key's id fails
        // even when the signature covers that header's own nonce — a key cannot
        // countersign for a principal it is not.
        let foreign_id = AttestationHeader {
            p_id: [0xAB; 32],
            shard_id: h.shard_id,
            settlement_epoch: h.settlement_epoch,
            kind: AttestationKind::Pass,
        };
        let foreign_nonce = attestation_nonce(
            &r,
            &cb,
            &foreign_id.p_id,
            foreign_id.shard_id,
            foreign_id.settlement_epoch,
        );
        let sig_over_foreign = HybridEd25519MlDsa
            .sign(&secret, &foreign_nonce)
            .expect("sign foreign nonce");
        assert!(!verify_pass_countersignature(
            &r,
            &cb,
            &pubkey,
            &foreign_id,
            &sig_over_foreign
        ));
    }

    #[test]
    fn attestation_root_is_defined_empty_order_independent_and_pairing_committed() {
        // Defined-empty (§3.2 invariant): the empty set has a fixed root, never
        // omitted, so the merkle leaf and count never desync.
        let empty = attestation_root(&[]).unwrap();
        assert_eq!(empty, attestation_root(&[]).unwrap());

        let (_pk, sk) = keypair();
        let s1 = HybridEd25519MlDsa.sign(&sk, b"a").unwrap();
        let s2 = HybridEd25519MlDsa.sign(&sk, b"b").unwrap();
        let h1 = header(AttestationKind::Pass);
        let mut h2 = h1;
        h2.shard_id = 43;

        // A non-empty set differs from empty.
        assert_ne!(attestation_root(&[(h1, s1.clone())]).unwrap(), empty);

        // ORDER-INDEPENDENT: the internal sort yields one canonical order, so the
        // two input orders produce the same root. This is the consensus-determinism
        // property — every re-validating node reproduces it without an unstated
        // ordering obligation.
        let ab = attestation_root(&[(h1, s1.clone()), (h2, s2.clone())]).unwrap();
        let ba = attestation_root(&[(h2, s2.clone()), (h1, s1.clone())]).unwrap();
        assert_eq!(ab, ba);

        // PAIRING IS COMMITTED: swapping which signature rides which header
        // changes the root — the header↔signature binding is inside the
        // commitment, not merely positional.
        let swapped = attestation_root(&[(h1, s2), (h2, s1)]).unwrap();
        assert_ne!(ab, swapped);
    }
}
