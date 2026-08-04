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
//! the **`attestation_root`** over the **pass-record** set (header‖signature
//! pairs), and the **countersignature verify**. Its sibling [`crate::attestation`]
//! owns the settlement fold; the two never share a signature, which is the §4
//! seam.
//!
//! # What `P` countersigns — the nonce alone
//!
//! The countersignature covers **the nonce alone**
//! (`H(r ‖ cb_out_key ‖ P ‖ s ‖ E)`). Every term is on-chain or derivable, so
//! admission can recompute and verify it. An earlier draft considered
//! `H(nonce ‖ transfer_digest)`, but `transfer_digest` digests off-chain shard
//! bytes that consensus cannot reconstruct — that reading is not
//! consensus-verifiable. Nonce-only is also *complete*: `shard_id` is already a
//! nonce term, so a content digest adds no binding `s` does not carry. §9.4's
//! topology binding carries the read-happened property.
//!
//! # Pass is a type, not a kind check
//!
//! Root and verify take [`PassRecord`] — identity + terms + signature, with
//! **no `kind` field**. Wire encode materializes `kind = Pass`. A miss is a
//! kept header alone and cannot enter these APIs. That is the admission half of
//! the same make-bad-states-unrepresentable seam settlement already uses
//! (`settle_epoch(&[AttestationKind])`).

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

/// cSHAKE customization for `attestation_root` over the ordered pass-record set.
pub const ATTESTATION_ROOT_CUSTOMIZATION: &[u8] = b"shekyl/archival-attestation-root-v1";

/// Canonical kept-header length: `p_id(32) + shard_id(8) + settlement_epoch(8) +
/// kind(1)` (§3.1). The `kind` byte is the sole prune-surviving *discriminant*
/// on the full kept header (`p_id ‖ s ‖ E ‖ kind` all ride `prefix_hash`).
pub const ATTESTATION_HEADER_LEN: usize = 32 + 8 + 8 + 1;

/// Fixed nonce preimage length: `r(32) ‖ cb_out_key(32) ‖ p_id(32) ‖ s(8) ‖ E(8)`.
const NONCE_INPUT_LEN: usize = 32 + 32 + 32 + 8 + 8;

/// `kind` byte encodings — fixed, not a bit in a status field, so a decoder
/// rejects anything that is neither (no silent third state).
const KIND_MISS: u8 = 0;
const KIND_PASS: u8 = 1;

/// The kept per-record header (§3.1), permanent in the coinbase `tx_extra` and
/// committed via `prefix_hash`. The full header (`p_id, shard_id, E, kind`)
/// survives the signature prune; settlement folds the gathered `kind` values
/// after the scan has already keyed by `(P, s, E)`.
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

/// One **pass** attestation: identity + terms + countersignature.
///
/// There is no `kind` field — Pass is the type. [`Self::to_header`] materializes
/// the kept wire header with `kind = Pass`. Miss records never carry a
/// signature and never appear here, so root/verify cannot represent
/// miss-with-signature.
#[derive(Debug, Clone)]
pub struct PassRecord {
    pub p_id: [u8; 32],
    pub shard_id: u64,
    pub settlement_epoch: u64,
    pub signature: HybridSignature,
}

impl PassRecord {
    /// Kept header for this pass (`kind = Pass`).
    #[must_use]
    pub fn to_header(&self) -> AttestationHeader {
        AttestationHeader {
            p_id: self.p_id,
            shard_id: self.shard_id,
            settlement_epoch: self.settlement_epoch,
            kind: AttestationKind::Pass,
        }
    }

    /// Block-bound nonce for this record's identity and terms.
    #[must_use]
    pub fn nonce(&self, r: &[u8; 32], cb_out_key: &[u8; 32]) -> [u8; 32] {
        attestation_nonce(
            r,
            cb_out_key,
            &self.p_id,
            self.shard_id,
            self.settlement_epoch,
        )
    }
}

/// The block-bound challenge nonce `H(r ‖ cb_out_key ‖ p_id ‖ shard_id ‖ E)`
/// (§3). `r` is the producer's revealed randomness (prunable side table with
/// the signatures — admission/pre-prune only), `cb_out_key` the coinbase output
/// key (the copy-freeride bind; kept). Every term is on-chain or derivable at
/// admission, so verify recomputes it identically.
///
/// Prefer [`PassRecord::nonce`] at call sites that already hold a pass record
/// so the terms cannot drift from the record.
#[must_use]
pub fn attestation_nonce(
    r: &[u8; 32],
    cb_out_key: &[u8; 32],
    p_id: &[u8; 32],
    shard_id: u64,
    settlement_epoch: u64,
) -> [u8; 32] {
    // Fixed-size stack preimage — consensus-adjacent, called per pass at
    // admission; no heap alloc on the hot path.
    let mut input = [0u8; NONCE_INPUT_LEN];
    input[0..32].copy_from_slice(r);
    input[32..64].copy_from_slice(cb_out_key);
    input[64..96].copy_from_slice(p_id);
    input[96..104].copy_from_slice(&shard_id.to_le_bytes());
    input[104..112].copy_from_slice(&settlement_epoch.to_le_bytes());
    cshake256_32(ATTESTATION_NONCE_CUSTOMIZATION, &input)
}

/// `attestation_root` over the block's **pass-records** (§3.2) — the value
/// stored in the block field and mined over as a merkle leaf.
///
/// Each record contributes `header_canonical ‖ signature_canonical`, so the root
/// commits the header↔signature **pairing** — not signatures alone, and not in
/// an unstated positional order. Records are **sorted by these canonical
/// bytes** before hashing, giving one defined order every producer and every
/// re-validating node (reading signatures from the **prunable** side table at
/// admission / pre-prune) reproduces identically. Post-prune the **stored**
/// root is trusted (mined into the block hash); settlement never recomputes it.
///
/// The input type is [`PassRecord`]: miss-with-signature is unrepresentable.
/// Each signature is in its authoritative fixed-length canonical encoding
/// ([`HybridSignature::to_canonical_bytes`]), so a malformed (wrong-length)
/// signature is a loud [`CryptoError`], not a silent truncation.
///
/// **Defined-empty** (§3.2 invariant): an empty set hashes to the customization
/// over the bare count prefix, a fixed constant, so the leaf is never omitted
/// and the count never desyncs.
pub fn attestation_root(records: &[PassRecord]) -> Result<[u8; 32], CryptoError> {
    const RECORD_LEN: usize = ATTESTATION_HEADER_LEN + HybridSignature::CANONICAL_LEN;
    let mut record_bytes: Vec<[u8; RECORD_LEN]> = Vec::with_capacity(records.len());
    for record in records {
        let mut rec = [0u8; RECORD_LEN];
        rec[..ATTESTATION_HEADER_LEN].copy_from_slice(&record.to_header().to_canonical_bytes());
        rec[ATTESTATION_HEADER_LEN..].copy_from_slice(&record.signature.to_canonical_bytes()?);
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
/// Two bindings, both self-contained so no correctness rides on the caller:
///
/// 1. **`p_id` binds the key.** The record's `p_id` must be *this pubkey's*
///    canonical id ([`p_canonical_id_from_hybrid_pubkey`]).
/// 2. **The signature covers the nonce.** Recompute
///    `H(r ‖ cb_out_key ‖ P ‖ s ‖ E)` from the record's terms and check `P`'s
///    hybrid countersignature over it.
///
/// Kind is not checked: a miss cannot be a [`PassRecord`].
#[must_use]
pub fn verify_pass_countersignature(
    r: &[u8; 32],
    cb_out_key: &[u8; 32],
    p_pubkey: &HybridPublicKey,
    record: &PassRecord,
) -> bool {
    // Binding 1: the record's p_id must be this pubkey's canonical id.
    let Ok(pubkey_bytes) = p_pubkey.to_canonical_bytes() else {
        return false;
    };
    if p_canonical_id_from_hybrid_pubkey(&pubkey_bytes).as_bytes() != &record.p_id {
        return false;
    }
    // Binding 2: P's countersignature over the block-bound nonce.
    let nonce = record.nonce(r, cb_out_key);
    HybridEd25519MlDsa
        .verify(p_pubkey, &nonce, &record.signature)
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

    /// This pubkey's canonical id — the value the record's `p_id` must equal.
    fn p_id_of(pubkey: &HybridPublicKey) -> [u8; 32] {
        let bytes = pubkey.to_canonical_bytes().expect("canonical pubkey");
        *p_canonical_id_from_hybrid_pubkey(&bytes).as_bytes()
    }

    fn pass_record(
        p_id: [u8; 32],
        shard_id: u64,
        settlement_epoch: u64,
        signature: HybridSignature,
    ) -> PassRecord {
        PassRecord {
            p_id,
            shard_id,
            settlement_epoch,
            signature,
        }
    }

    #[test]
    fn header_bytes_roundtrip_and_reject_malformed() {
        for kind in [AttestationKind::Pass, AttestationKind::Miss] {
            let h = AttestationHeader {
                p_id: [7u8; 32],
                shard_id: 42,
                settlement_epoch: 1000,
                kind,
            };
            let bytes = h.to_canonical_bytes();
            assert_eq!(bytes.len(), ATTESTATION_HEADER_LEN);
            assert_eq!(AttestationHeader::from_canonical_bytes(&bytes), Ok(h));
        }
        // Wrong length and a bad kind byte are loud errors, not silent defaults.
        assert_eq!(
            AttestationHeader::from_canonical_bytes(&[0u8; 10]),
            Err(AttestationHeaderError::WrongLength(10))
        );
        let mut bad = AttestationHeader {
            p_id: [7u8; 32],
            shard_id: 42,
            settlement_epoch: 1000,
            kind: AttestationKind::Pass,
        }
        .to_canonical_bytes();
        bad[48] = 2;
        assert_eq!(
            AttestationHeader::from_canonical_bytes(&bad),
            Err(AttestationHeaderError::BadKind(2))
        );
    }

    #[test]
    fn pass_record_to_header_is_always_pass() {
        // Structural seam: PassRecord cannot carry Miss; wire kind is Pass.
        let (_pk, sk) = keypair();
        let sig = HybridEd25519MlDsa.sign(&sk, b"x").unwrap();
        let rec = pass_record([1u8; 32], 2, 3, sig);
        assert_eq!(rec.to_header().kind, AttestationKind::Pass);
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
        assert_eq!(base, attestation_nonce(&[1; 32], &[2; 32], &[3; 32], 4, 5));
    }

    #[test]
    fn pass_record_nonce_matches_free_function() {
        let (_pk, sk) = keypair();
        let sig = HybridEd25519MlDsa.sign(&sk, b"n").unwrap();
        let rec = pass_record([3u8; 32], 4, 5, sig);
        let (r, cb) = ([1u8; 32], [2u8; 32]);
        assert_eq!(
            rec.nonce(&r, &cb),
            attestation_nonce(&r, &cb, &rec.p_id, rec.shard_id, rec.settlement_epoch)
        );
    }

    #[test]
    fn a_valid_countersignature_verifies_and_a_wrong_key_or_term_fails() {
        let (pubkey, secret) = keypair();
        let (r, cb) = ([11u8; 32], [22u8; 32]);
        let p_id = p_id_of(&pubkey);
        let nonce = attestation_nonce(&r, &cb, &p_id, 42, 1000);
        let sig = HybridEd25519MlDsa
            .sign(&secret, &nonce)
            .expect("P signs the nonce");
        let rec = pass_record(p_id, 42, 1000, sig);

        assert!(verify_pass_countersignature(&r, &cb, &pubkey, &rec));

        // A signature over a DIFFERENT block's r must not verify — this is the
        // copy-freeride / cross-block replay defence at the crypto layer.
        assert!(!verify_pass_countersignature(&[99; 32], &cb, &pubkey, &rec));
        // Nor a different coinbase output key (the copy bind).
        assert!(!verify_pass_countersignature(&r, &[99; 32], &pubkey, &rec));
        // Nor a different (shard, epoch) term.
        let mut other = rec.clone();
        other.shard_id = 43;
        assert!(!verify_pass_countersignature(&r, &cb, &pubkey, &other));

        // Binding 1 in isolation: a record whose p_id is NOT this key's id fails
        // even when the signature covers that record's own nonce.
        let foreign_id = [0xABu8; 32];
        let foreign_nonce = attestation_nonce(&r, &cb, &foreign_id, 42, 1000);
        let sig_over_foreign = HybridEd25519MlDsa
            .sign(&secret, &foreign_nonce)
            .expect("sign foreign nonce");
        let foreign = pass_record(foreign_id, 42, 1000, sig_over_foreign);
        assert!(!verify_pass_countersignature(&r, &cb, &pubkey, &foreign));
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
        let r1 = pass_record([7u8; 32], 42, 1000, s1.clone());
        let r2 = pass_record([7u8; 32], 43, 1000, s2.clone());

        // A non-empty set differs from empty.
        assert_ne!(attestation_root(std::slice::from_ref(&r1)).unwrap(), empty);

        // ORDER-INDEPENDENT: the internal sort yields one canonical order.
        let ab = attestation_root(&[r1.clone(), r2.clone()]).unwrap();
        let ba = attestation_root(&[r2.clone(), r1.clone()]).unwrap();
        assert_eq!(ab, ba);

        // PAIRING IS COMMITTED: swapping which signature rides which terms
        // changes the root.
        let swapped = attestation_root(&[
            pass_record(r1.p_id, r1.shard_id, r1.settlement_epoch, s2),
            pass_record(r2.p_id, r2.shard_id, r2.settlement_epoch, s1),
        ])
        .unwrap();
        assert_ne!(ab, swapped);
    }
}
