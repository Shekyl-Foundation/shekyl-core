//! M-of-N PQC multisig: containers, group identity, and verification.
//!
//! Wire format uses opaque blobs that embed in the existing `pqc_auth`
//! fields (`hybrid_public_key`, `hybrid_signature`) with `scheme_id = 2`.

use crate::error::PqcVerifyError;
use crate::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSignature, SignatureScheme,
    ML_DSA_65_PUBLIC_KEY_LENGTH, ML_DSA_65_SIGNATURE_LENGTH,
};
use ed25519_dalek::{
    PUBLIC_KEY_LENGTH as ED25519_PUBLIC_KEY_LENGTH,
    SIGNATURE_LENGTH as ED25519_SIGNATURE_LENGTH,
};
use shekyl_crypto_hash::cn_fast_hash;

pub const MAX_MULTISIG_PARTICIPANTS: u8 = 7;
pub const HYBRID_SCHEME_ID_MULTISIG: u8 = 2;

const DOMAIN_SEP: &[u8] = b"shekyl-multisig-group-v1";

/// Size of a single `HybridPublicKey` in canonical encoding.
pub const SINGLE_KEY_CANONICAL_LEN: usize =
    1 + 1 + 2 + 4 + ED25519_PUBLIC_KEY_LENGTH + 4 + ML_DSA_65_PUBLIC_KEY_LENGTH; // 1996

/// Size of a single `HybridSignature` in canonical encoding.
pub const SINGLE_SIG_CANONICAL_LEN: usize =
    1 + 1 + 2 + 4 + ED25519_SIGNATURE_LENGTH + 4 + ML_DSA_65_SIGNATURE_LENGTH; // 3385

// ---------------------------------------------------------------------------
// MultisigKeyContainer
// ---------------------------------------------------------------------------

/// N hybrid public keys packed for on-chain commitment.
///
/// Wire layout: `n_total(1) || m_required(1) || key[0](1996) || ... || key[N-1](1996)`
#[derive(Debug, Clone)]
pub struct MultisigKeyContainer {
    pub n_total: u8,
    pub m_required: u8,
    pub keys: Vec<HybridPublicKey>,
}

impl MultisigKeyContainer {
    pub fn validate(&self) -> Result<(), PqcVerifyError> {
        if self.m_required == 0
            || self.n_total == 0
            || self.m_required > self.n_total
            || self.n_total > MAX_MULTISIG_PARTICIPANTS
        {
            return Err(PqcVerifyError::ParameterBounds);
        }
        if self.keys.len() != self.n_total as usize {
            return Err(PqcVerifyError::KeyBlobLength);
        }
        Ok(())
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, PqcVerifyError> {
        self.validate()?;
        let cap = 2 + (self.n_total as usize) * SINGLE_KEY_CANONICAL_LEN;
        let mut out = Vec::with_capacity(cap);
        out.push(self.n_total);
        out.push(self.m_required);
        for key in &self.keys {
            let kb = key
                .to_canonical_bytes()
                .map_err(|_| PqcVerifyError::DeserializationFailed)?;
            out.extend_from_slice(&kb);
        }
        debug_assert_eq!(out.len(), cap);
        Ok(out)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PqcVerifyError> {
        if bytes.len() < 2 {
            return Err(PqcVerifyError::KeyBlobLength);
        }
        let n_total = bytes[0];
        let m_required = bytes[1];

        if m_required == 0
            || n_total == 0
            || m_required > n_total
            || n_total > MAX_MULTISIG_PARTICIPANTS
        {
            return Err(PqcVerifyError::ParameterBounds);
        }

        let expected_len = 2 + (n_total as usize) * SINGLE_KEY_CANONICAL_LEN;
        if bytes.len() != expected_len {
            return Err(PqcVerifyError::KeyBlobLength);
        }

        let mut keys = Vec::with_capacity(n_total as usize);
        let mut cursor = 2usize;
        for _ in 0..n_total {
            let end = cursor + SINGLE_KEY_CANONICAL_LEN;
            let pk = HybridPublicKey::from_canonical_bytes(&bytes[cursor..end])
                .map_err(|_| PqcVerifyError::DeserializationFailed)?;
            keys.push(pk);
            cursor = end;
        }

        let container = Self {
            n_total,
            m_required,
            keys,
        };
        container.validate()?;
        Ok(container)
    }

    pub fn has_duplicate_keys(&self) -> bool {
        for i in 0..self.keys.len() {
            let a = self.keys[i]
                .to_canonical_bytes()
                .expect("already validated");
            for j in (i + 1)..self.keys.len() {
                let b = self.keys[j]
                    .to_canonical_bytes()
                    .expect("already validated");
                if a == b {
                    return true;
                }
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// MultisigSigContainer
// ---------------------------------------------------------------------------

/// M signatures with signer indices packed for on-chain verification.
///
/// Wire layout: `sig_count(1) || sig[0](3385) || ... || sig[M-1](3385) || idx[0](1) || ... || idx[M-1](1)`
#[derive(Debug, Clone)]
pub struct MultisigSigContainer {
    pub sig_count: u8,
    pub sigs: Vec<HybridSignature>,
    pub signer_indices: Vec<u8>,
}

impl MultisigSigContainer {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, PqcVerifyError> {
        let cap =
            1 + (self.sig_count as usize) * SINGLE_SIG_CANONICAL_LEN + self.sig_count as usize;
        let mut out = Vec::with_capacity(cap);
        out.push(self.sig_count);
        for sig in &self.sigs {
            let sb = sig
                .to_canonical_bytes()
                .map_err(|_| PqcVerifyError::DeserializationFailed)?;
            out.extend_from_slice(&sb);
        }
        out.extend_from_slice(&self.signer_indices);
        debug_assert_eq!(out.len(), cap);
        Ok(out)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PqcVerifyError> {
        if bytes.is_empty() {
            return Err(PqcVerifyError::SigBlobLength);
        }
        let sig_count = bytes[0];
        if sig_count == 0 || sig_count > MAX_MULTISIG_PARTICIPANTS {
            return Err(PqcVerifyError::ParameterBounds);
        }

        let expected_len =
            1 + (sig_count as usize) * SINGLE_SIG_CANONICAL_LEN + sig_count as usize;
        if bytes.len() != expected_len {
            return Err(PqcVerifyError::SigBlobLength);
        }

        let mut sigs = Vec::with_capacity(sig_count as usize);
        let mut cursor = 1usize;
        for _ in 0..sig_count {
            let end = cursor + SINGLE_SIG_CANONICAL_LEN;
            let sig = HybridSignature::from_canonical_bytes(&bytes[cursor..end])
                .map_err(|_| PqcVerifyError::DeserializationFailed)?;
            sigs.push(sig);
            cursor = end;
        }

        let signer_indices = bytes[cursor..].to_vec();
        debug_assert_eq!(signer_indices.len(), sig_count as usize);

        Ok(Self {
            sig_count,
            sigs,
            signer_indices,
        })
    }
}

// ---------------------------------------------------------------------------
// Group identity
// ---------------------------------------------------------------------------

/// Deterministic group identity: `cn_fast_hash(domain || n || m || key[0] || ... || key[N-1])`.
pub fn multisig_group_id(container: &MultisigKeyContainer) -> Result<[u8; 32], PqcVerifyError> {
    container.validate()?;

    let mut preimage = Vec::with_capacity(
        DOMAIN_SEP.len() + 2 + (container.n_total as usize) * SINGLE_KEY_CANONICAL_LEN,
    );
    preimage.extend_from_slice(DOMAIN_SEP);
    preimage.push(container.n_total);
    preimage.push(container.m_required);
    for key in &container.keys {
        let kb = key
            .to_canonical_bytes()
            .map_err(|_| PqcVerifyError::DeserializationFailed)?;
        preimage.extend_from_slice(&kb);
    }

    Ok(cn_fast_hash(&preimage))
}

// ---------------------------------------------------------------------------
// 10-check verification pipeline
// ---------------------------------------------------------------------------

/// Verify an M-of-N PQC multisig against the 10-check adversarial pipeline.
///
/// `expected_group_id`: the group_id committed by the output being spent (check 9).
/// Pass `None` to skip that check (useful for unit tests; consensus *must* supply it).
pub fn verify_multisig(
    scheme_id: u8,
    key_blob: &[u8],
    sig_blob: &[u8],
    message: &[u8],
    expected_group_id: Option<&[u8; 32]>,
) -> Result<bool, PqcVerifyError> {
    // Check 1: scheme match
    if scheme_id != HYBRID_SCHEME_ID_MULTISIG {
        return Err(PqcVerifyError::SchemeMismatch);
    }

    // Check 2 + 3: parameter bounds + key blob length (inside from_canonical_bytes)
    let key_container = MultisigKeyContainer::from_canonical_bytes(key_blob)?;

    // Check 4: sig blob length (inside from_canonical_bytes)
    let sig_container = MultisigSigContainer::from_canonical_bytes(sig_blob)?;

    // Check 5: threshold match
    if sig_container.sig_count != key_container.m_required {
        return Err(PqcVerifyError::ThresholdMismatch);
    }

    // Check 6: index validity
    for &idx in &sig_container.signer_indices {
        if idx >= key_container.n_total {
            return Err(PqcVerifyError::IndexOutOfRange);
        }
    }

    // Check 7: strictly ascending indices
    for i in 1..sig_container.signer_indices.len() {
        if sig_container.signer_indices[i] <= sig_container.signer_indices[i - 1] {
            return Err(PqcVerifyError::IndicesNotAscending);
        }
    }

    // Check 8: key uniqueness
    if key_container.has_duplicate_keys() {
        return Err(PqcVerifyError::DuplicateKeys);
    }

    // Check 9: group_id match
    if let Some(expected) = expected_group_id {
        let computed = multisig_group_id(&key_container)?;
        if &computed != expected {
            return Err(PqcVerifyError::GroupIdMismatch);
        }
    }

    // Check 10: cryptographic verification (M x Ed25519 + M x ML-DSA)
    let scheme = HybridEd25519MlDsa;
    for (sig, &idx) in sig_container
        .sigs
        .iter()
        .zip(sig_container.signer_indices.iter())
    {
        let pk = &key_container.keys[idx as usize];
        let ok = scheme
            .verify(pk, message, sig)
            .map_err(|_| PqcVerifyError::CryptoVerifyFailed)?;
        if !ok {
            return Err(PqcVerifyError::CryptoVerifyFailed);
        }
    }

    Ok(true)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::HybridEd25519MlDsa;

    fn gen_keypairs(n: usize) -> Vec<(HybridPublicKey, crate::signature::HybridSecretKey)> {
        let scheme = HybridEd25519MlDsa;
        (0..n).map(|_| scheme.keypair_generate().unwrap()).collect()
    }

    fn make_key_container(
        pairs: &[(HybridPublicKey, crate::signature::HybridSecretKey)],
        m: u8,
    ) -> MultisigKeyContainer {
        MultisigKeyContainer {
            n_total: pairs.len() as u8,
            m_required: m,
            keys: pairs.iter().map(|(pk, _)| pk.clone()).collect(),
        }
    }

    fn sign_multisig(
        pairs: &[(HybridPublicKey, crate::signature::HybridSecretKey)],
        signer_indices: &[u8],
        message: &[u8],
    ) -> MultisigSigContainer {
        let scheme = HybridEd25519MlDsa;
        let sigs: Vec<HybridSignature> = signer_indices
            .iter()
            .map(|&idx| scheme.sign(&pairs[idx as usize].1, message).unwrap())
            .collect();
        MultisigSigContainer {
            sig_count: sigs.len() as u8,
            sigs,
            signer_indices: signer_indices.to_vec(),
        }
    }

    // -- Canonical round-trip tests --

    #[test]
    fn key_container_roundtrip() {
        let pairs = gen_keypairs(3);
        let kc = make_key_container(&pairs, 2);
        let blob = kc.to_canonical_bytes().unwrap();
        assert_eq!(blob.len(), 2 + 3 * SINGLE_KEY_CANONICAL_LEN);
        let kc2 = MultisigKeyContainer::from_canonical_bytes(&blob).unwrap();
        assert_eq!(kc2.n_total, 3);
        assert_eq!(kc2.m_required, 2);
        assert_eq!(kc2.keys.len(), 3);
    }

    #[test]
    fn sig_container_roundtrip() {
        let pairs = gen_keypairs(3);
        let msg = b"test-roundtrip";
        let sc = sign_multisig(&pairs, &[0, 2], msg);
        let blob = sc.to_canonical_bytes().unwrap();
        assert_eq!(blob.len(), 1 + 2 * SINGLE_SIG_CANONICAL_LEN + 2);
        let sc2 = MultisigSigContainer::from_canonical_bytes(&blob).unwrap();
        assert_eq!(sc2.sig_count, 2);
        assert_eq!(sc2.signer_indices, vec![0, 2]);
    }

    // -- Group ID --

    #[test]
    fn group_id_deterministic() {
        let pairs = gen_keypairs(3);
        let kc = make_key_container(&pairs, 2);
        let id1 = multisig_group_id(&kc).unwrap();
        let id2 = multisig_group_id(&kc).unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn group_id_changes_with_keys() {
        let pairs1 = gen_keypairs(3);
        let pairs2 = gen_keypairs(3);
        let kc1 = make_key_container(&pairs1, 2);
        let kc2 = make_key_container(&pairs2, 2);
        assert_ne!(multisig_group_id(&kc1).unwrap(), multisig_group_id(&kc2).unwrap());
    }

    #[test]
    fn group_id_changes_with_threshold() {
        let pairs = gen_keypairs(3);
        let kc2 = make_key_container(&pairs, 2);
        let kc3 = make_key_container(&pairs, 3);
        assert_ne!(multisig_group_id(&kc2).unwrap(), multisig_group_id(&kc3).unwrap());
    }

    // -- Full verification pipeline --

    #[test]
    fn valid_2_of_3() {
        let pairs = gen_keypairs(3);
        let kc = make_key_container(&pairs, 2);
        let msg = b"tx-payload-hash-2of3";
        let sc = sign_multisig(&pairs, &[0, 2], msg);
        let group_id = multisig_group_id(&kc).unwrap();
        let key_blob = kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        let result = verify_multisig(2, &key_blob, &sig_blob, msg, Some(&group_id));
        assert!(result.unwrap());
    }

    #[test]
    fn valid_1_of_1() {
        let pairs = gen_keypairs(1);
        let kc = make_key_container(&pairs, 1);
        let msg = b"1-of-1-edge-case";
        let sc = sign_multisig(&pairs, &[0], msg);
        let group_id = multisig_group_id(&kc).unwrap();
        let key_blob = kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        assert!(verify_multisig(2, &key_blob, &sig_blob, msg, Some(&group_id)).unwrap());
    }

    #[test]
    fn valid_7_of_7() {
        let pairs = gen_keypairs(7);
        let kc = make_key_container(&pairs, 7);
        let msg = b"7-of-7-max";
        let sc = sign_multisig(&pairs, &[0, 1, 2, 3, 4, 5, 6], msg);
        let group_id = multisig_group_id(&kc).unwrap();
        let key_blob = kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        assert!(verify_multisig(2, &key_blob, &sig_blob, msg, Some(&group_id)).unwrap());
    }

    // -- Adversarial checks --

    #[test]
    fn check1_scheme_mismatch() {
        let pairs = gen_keypairs(2);
        let kc = make_key_container(&pairs, 2);
        let msg = b"bad-scheme";
        let sc = sign_multisig(&pairs, &[0, 1], msg);
        let key_blob = kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        assert_eq!(
            verify_multisig(1, &key_blob, &sig_blob, msg, None).unwrap_err(),
            PqcVerifyError::SchemeMismatch
        );
    }

    #[test]
    fn check2_parameter_bounds() {
        let result = MultisigKeyContainer::from_canonical_bytes(&[0, 2]);
        assert_eq!(result.unwrap_err(), PqcVerifyError::ParameterBounds);

        let result = MultisigKeyContainer::from_canonical_bytes(&[3, 0]);
        assert_eq!(result.unwrap_err(), PqcVerifyError::ParameterBounds);

        let result = MultisigKeyContainer::from_canonical_bytes(&[2, 3]);
        assert_eq!(result.unwrap_err(), PqcVerifyError::ParameterBounds);

        let result = MultisigKeyContainer::from_canonical_bytes(&[8, 2]);
        assert_eq!(result.unwrap_err(), PqcVerifyError::ParameterBounds);
    }

    #[test]
    fn check3_key_blob_truncated() {
        let pairs = gen_keypairs(3);
        let kc = make_key_container(&pairs, 2);
        let mut blob = kc.to_canonical_bytes().unwrap();
        blob.truncate(blob.len() - 1);
        assert_eq!(
            MultisigKeyContainer::from_canonical_bytes(&blob).unwrap_err(),
            PqcVerifyError::KeyBlobLength
        );
    }

    #[test]
    fn check3_key_blob_padded() {
        let pairs = gen_keypairs(3);
        let kc = make_key_container(&pairs, 2);
        let mut blob = kc.to_canonical_bytes().unwrap();
        blob.push(0x00);
        assert_eq!(
            MultisigKeyContainer::from_canonical_bytes(&blob).unwrap_err(),
            PqcVerifyError::KeyBlobLength
        );
    }

    #[test]
    fn check4_sig_blob_truncated() {
        let pairs = gen_keypairs(3);
        let msg = b"truncated-sig";
        let sc = sign_multisig(&pairs, &[0, 1], msg);
        let mut blob = sc.to_canonical_bytes().unwrap();
        blob.truncate(blob.len() - 1);
        assert_eq!(
            MultisigSigContainer::from_canonical_bytes(&blob).unwrap_err(),
            PqcVerifyError::SigBlobLength
        );
    }

    #[test]
    fn check5_threshold_mismatch() {
        let pairs = gen_keypairs(3);
        let kc = make_key_container(&pairs, 2);
        let msg = b"threshold-mismatch";
        let sc = sign_multisig(&pairs, &[0, 1, 2], msg);
        let key_blob = kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        assert_eq!(
            verify_multisig(2, &key_blob, &sig_blob, msg, None).unwrap_err(),
            PqcVerifyError::ThresholdMismatch
        );
    }

    #[test]
    fn check6_index_out_of_range() {
        let pairs = gen_keypairs(3);
        let kc = make_key_container(&pairs, 2);
        let msg = b"idx-oor";
        let scheme = HybridEd25519MlDsa;
        let sc = MultisigSigContainer {
            sig_count: 2,
            sigs: vec![
                scheme.sign(&pairs[0].1, msg).unwrap(),
                scheme.sign(&pairs[1].1, msg).unwrap(),
            ],
            signer_indices: vec![0, 3],
        };
        let key_blob = kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        assert_eq!(
            verify_multisig(2, &key_blob, &sig_blob, msg, None).unwrap_err(),
            PqcVerifyError::IndexOutOfRange
        );
    }

    #[test]
    fn check7_indices_not_ascending() {
        let pairs = gen_keypairs(3);
        let kc = make_key_container(&pairs, 2);
        let msg = b"unsorted-idx";
        let scheme = HybridEd25519MlDsa;
        let sc = MultisigSigContainer {
            sig_count: 2,
            sigs: vec![
                scheme.sign(&pairs[1].1, msg).unwrap(),
                scheme.sign(&pairs[0].1, msg).unwrap(),
            ],
            signer_indices: vec![1, 0],
        };
        let key_blob = kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        assert_eq!(
            verify_multisig(2, &key_blob, &sig_blob, msg, None).unwrap_err(),
            PqcVerifyError::IndicesNotAscending
        );
    }

    #[test]
    fn check8_duplicate_keys() {
        let pairs = gen_keypairs(2);
        let dup_kc = MultisigKeyContainer {
            n_total: 3,
            m_required: 2,
            keys: vec![pairs[0].0.clone(), pairs[1].0.clone(), pairs[0].0.clone()],
        };
        let msg = b"dup-keys";
        let scheme = HybridEd25519MlDsa;
        let sc = MultisigSigContainer {
            sig_count: 2,
            sigs: vec![
                scheme.sign(&pairs[0].1, msg).unwrap(),
                scheme.sign(&pairs[1].1, msg).unwrap(),
            ],
            signer_indices: vec![0, 1],
        };
        let key_blob = dup_kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        assert_eq!(
            verify_multisig(2, &key_blob, &sig_blob, msg, None).unwrap_err(),
            PqcVerifyError::DuplicateKeys
        );
    }

    #[test]
    fn check9_group_id_mismatch() {
        let pairs = gen_keypairs(3);
        let kc = make_key_container(&pairs, 2);
        let msg = b"wrong-group";
        let sc = sign_multisig(&pairs, &[0, 1], msg);
        let wrong_id = [0xFFu8; 32];
        let key_blob = kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        assert_eq!(
            verify_multisig(2, &key_blob, &sig_blob, msg, Some(&wrong_id)).unwrap_err(),
            PqcVerifyError::GroupIdMismatch
        );
    }

    #[test]
    fn check10_crypto_verify_wrong_message() {
        let pairs = gen_keypairs(3);
        let kc = make_key_container(&pairs, 2);
        let msg = b"correct-message";
        let sc = sign_multisig(&pairs, &[0, 1], msg);
        let key_blob = kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        assert_eq!(
            verify_multisig(2, &key_blob, &sig_blob, b"wrong-message", None).unwrap_err(),
            PqcVerifyError::CryptoVerifyFailed
        );
    }

    #[test]
    fn check10_crypto_verify_wrong_signer() {
        let pairs = gen_keypairs(3);
        let kc = make_key_container(&pairs, 2);
        let msg = b"wrong-signer";
        let scheme = HybridEd25519MlDsa;
        let sc = MultisigSigContainer {
            sig_count: 2,
            sigs: vec![
                scheme.sign(&pairs[0].1, msg).unwrap(),
                scheme.sign(&pairs[0].1, msg).unwrap(), // signed with key 0, but index says 1
            ],
            signer_indices: vec![0, 1],
        };
        let key_blob = kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        assert_eq!(
            verify_multisig(2, &key_blob, &sig_blob, msg, None).unwrap_err(),
            PqcVerifyError::CryptoVerifyFailed
        );
    }

    // -- ML-DSA non-determinism test --

    #[test]
    fn ml_dsa_hedged_signing_produces_different_sigs() {
        let pairs = gen_keypairs(1);
        let msg = b"non-determinism";
        let scheme = HybridEd25519MlDsa;
        let sig1 = scheme.sign(&pairs[0].1, msg).unwrap();
        let sig2 = scheme.sign(&pairs[0].1, msg).unwrap();
        // ML-DSA uses hedged signing: same message, same key -> different signature
        // Ed25519 is deterministic so that component should match
        assert_eq!(sig1.ed25519, sig2.ed25519);
        // ML-DSA component should differ (overwhelmingly likely)
        assert_ne!(sig1.ml_dsa, sig2.ml_dsa);
        // Both must verify
        assert!(scheme.verify(&pairs[0].0, msg, &sig1).unwrap());
        assert!(scheme.verify(&pairs[0].0, msg, &sig2).unwrap());
    }

    // -- Edge cases --

    #[test]
    fn valid_1_of_7() {
        let pairs = gen_keypairs(7);
        let kc = make_key_container(&pairs, 1);
        let msg = b"1-of-7";
        let sc = sign_multisig(&pairs, &[3], msg);
        let group_id = multisig_group_id(&kc).unwrap();
        let key_blob = kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        assert!(verify_multisig(2, &key_blob, &sig_blob, msg, Some(&group_id)).unwrap());
    }

    #[test]
    fn skip_group_id_check_with_none() {
        let pairs = gen_keypairs(2);
        let kc = make_key_container(&pairs, 2);
        let msg = b"no-group-check";
        let sc = sign_multisig(&pairs, &[0, 1], msg);
        let key_blob = kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        assert!(verify_multisig(2, &key_blob, &sig_blob, msg, None).unwrap());
    }
}
