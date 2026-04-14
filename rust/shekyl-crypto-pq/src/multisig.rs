//! M-of-N PQC multisig: containers, group identity, and verification.
//!
//! Wire format uses opaque blobs that embed in the existing `pqc_auth`
//! fields (`hybrid_public_key`, `hybrid_signature`) with `scheme_id = 2`.
//!
//! V3.1 extends the container with a `version` byte and per-participant
//! classical spend-auth pubkeys (`spend_auth_pubkeys`). See `PQC_MULTISIG.md`
//! v1.1 for the full specification.

use crate::CryptoError;
use crate::error::PqcVerifyError;
use crate::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSignature, SignatureScheme,
    ML_DSA_65_PUBLIC_KEY_LENGTH, ML_DSA_65_SIGNATURE_LENGTH,
};
use ed25519_dalek::{
    PUBLIC_KEY_LENGTH as ED25519_PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH as ED25519_SIGNATURE_LENGTH,
};
use shekyl_crypto_hash::cn_fast_hash;

pub const MAX_MULTISIG_PARTICIPANTS: u8 = 7;
pub const HYBRID_SCHEME_ID_MULTISIG: u8 = 2;

/// V3.1 container version (first version with spend_auth_pubkeys).
pub const MULTISIG_CONTAINER_VERSION: u8 = 0x01;

/// V3.1 group_id domain separator. Binds group_version, scheme_id,
/// and spend_auth_version into the preimage (PQC_MULTISIG.md SS5.3).
const DOMAIN_SEP_V31: &[u8] = b"shekyl-multisig-group-v31";

/// Classical spend-auth pubkey length (compressed Ed25519 point).
pub const SPEND_AUTH_PUBKEY_LEN: usize = 32;

/// Size of a single `HybridPublicKey` in canonical encoding.
pub const SINGLE_KEY_CANONICAL_LEN: usize =
    1 + 1 + 2 + 4 + ED25519_PUBLIC_KEY_LENGTH + 4 + ML_DSA_65_PUBLIC_KEY_LENGTH; // 1996

/// Size of a single `HybridSignature` in canonical encoding.
pub const SINGLE_SIG_CANONICAL_LEN: usize =
    1 + 1 + 2 + 4 + ED25519_SIGNATURE_LENGTH + 4 + ML_DSA_65_SIGNATURE_LENGTH; // 3385

// ---------------------------------------------------------------------------
// MultisigKeyContainer
// ---------------------------------------------------------------------------

/// N hybrid public keys + N classical spend-auth pubkeys for on-chain commitment.
///
/// V3.1 wire layout:
/// ```text
/// version(1) || n_total(1) || m_required(1) ||
/// key[0](1996) || ... || key[N-1](1996) ||
/// spend_auth_pk[0](32) || ... || spend_auth_pk[N-1](32)
/// ```
#[derive(Debug, Clone)]
pub struct MultisigKeyContainer {
    pub version: u8,
    pub n_total: u8,
    pub m_required: u8,
    pub keys: Vec<HybridPublicKey>,
    pub spend_auth_pubkeys: Vec<[u8; 32]>,
}

impl MultisigKeyContainer {
    pub fn validate(&self) -> Result<(), PqcVerifyError> {
        if self.version != MULTISIG_CONTAINER_VERSION {
            return Err(PqcVerifyError::ParameterBounds);
        }
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
        if self.spend_auth_pubkeys.len() != self.n_total as usize {
            return Err(PqcVerifyError::KeyBlobLength);
        }
        Ok(())
    }

    /// Compute the expected byte length of a V3.1 canonical encoding.
    pub fn expected_blob_len(n: u8) -> usize {
        3 + (n as usize) * SINGLE_KEY_CANONICAL_LEN + (n as usize) * SPEND_AUTH_PUBKEY_LEN
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, PqcVerifyError> {
        self.validate()?;
        let cap = Self::expected_blob_len(self.n_total);
        let mut out = Vec::with_capacity(cap);
        out.push(self.version);
        out.push(self.n_total);
        out.push(self.m_required);
        for key in &self.keys {
            let kb = key
                .to_canonical_bytes()
                .map_err(|_| PqcVerifyError::DeserializationFailed)?;
            out.extend_from_slice(&kb);
        }
        for sa_pk in &self.spend_auth_pubkeys {
            out.extend_from_slice(sa_pk);
        }
        debug_assert_eq!(out.len(), cap);
        Ok(out)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PqcVerifyError> {
        if bytes.len() < 3 {
            return Err(PqcVerifyError::KeyBlobLength);
        }
        let version = bytes[0];
        if version != MULTISIG_CONTAINER_VERSION {
            return Err(PqcVerifyError::ParameterBounds);
        }
        let n_total = bytes[1];
        let m_required = bytes[2];

        if m_required == 0
            || n_total == 0
            || m_required > n_total
            || n_total > MAX_MULTISIG_PARTICIPANTS
        {
            return Err(PqcVerifyError::ParameterBounds);
        }

        let expected_len = Self::expected_blob_len(n_total);
        if bytes.len() != expected_len {
            return Err(PqcVerifyError::KeyBlobLength);
        }

        let mut keys = Vec::with_capacity(n_total as usize);
        let mut cursor = 3usize;
        for _ in 0..n_total {
            let end = cursor + SINGLE_KEY_CANONICAL_LEN;
            let pk = HybridPublicKey::from_canonical_bytes(&bytes[cursor..end])
                .map_err(|_| PqcVerifyError::DeserializationFailed)?;
            keys.push(pk);
            cursor = end;
        }

        let mut spend_auth_pubkeys = Vec::with_capacity(n_total as usize);
        for _ in 0..n_total {
            let end = cursor + SPEND_AUTH_PUBKEY_LEN;
            if end > bytes.len() {
                return Err(PqcVerifyError::KeyBlobLength);
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&bytes[cursor..end]);
            spend_auth_pubkeys.push(pk);
            cursor = end;
        }

        let container = Self {
            version,
            n_total,
            m_required,
            keys,
            spend_auth_pubkeys,
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

        let expected_len = 1 + (sig_count as usize) * SINGLE_SIG_CANONICAL_LEN + sig_count as usize;
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

/// Deterministic group identity (V3.1).
///
/// Preimage: `domain_v31 || group_version(1) || scheme_id(1) || spend_auth_version(1)
///            || n(1) || m(1) || key[0] || ... || key[N-1]
///            || spend_auth_pk[0](32) || ... || spend_auth_pk[N-1](32)`
///
/// `spend_auth_version` is currently 0x01 (Ed25519). Future lattice-only
/// versions (V4) will use a different value.
pub fn multisig_group_id(container: &MultisigKeyContainer) -> Result<[u8; 32], PqcVerifyError> {
    multisig_group_id_with_versions(
        container,
        MULTISIG_CONTAINER_VERSION,
        HYBRID_SCHEME_ID_MULTISIG,
        SPEND_AUTH_VERSION_ED25519,
    )
}

/// Classical spend-auth version byte: Ed25519.
pub const SPEND_AUTH_VERSION_ED25519: u8 = 0x01;

/// Compute group_id with explicit version parameters.
/// Exposed for testing and forward compatibility.
pub fn multisig_group_id_with_versions(
    container: &MultisigKeyContainer,
    group_version: u8,
    scheme_id: u8,
    spend_auth_version: u8,
) -> Result<[u8; 32], PqcVerifyError> {
    container.validate()?;

    let key_data_len = (container.n_total as usize) * SINGLE_KEY_CANONICAL_LEN;
    let sa_data_len = (container.n_total as usize) * SPEND_AUTH_PUBKEY_LEN;
    let mut preimage =
        Vec::with_capacity(DOMAIN_SEP_V31.len() + 5 + key_data_len + sa_data_len);

    preimage.extend_from_slice(DOMAIN_SEP_V31);
    preimage.push(group_version);
    preimage.push(scheme_id);
    preimage.push(spend_auth_version);
    preimage.push(container.n_total);
    preimage.push(container.m_required);
    for key in &container.keys {
        let kb = key
            .to_canonical_bytes()
            .map_err(|_| PqcVerifyError::DeserializationFailed)?;
        preimage.extend_from_slice(&kb);
    }
    for sa_pk in &container.spend_auth_pubkeys {
        preimage.extend_from_slice(sa_pk);
    }

    Ok(cn_fast_hash(&preimage))
}

// ---------------------------------------------------------------------------
// Rotating prover selection (PQC_MULTISIG.md SS11.1)
// ---------------------------------------------------------------------------

/// Deterministic, sender-computable prover selection per output.
///
/// ```text
/// prover_index = first_byte(
///     cn_fast_hash(group_id || u64_le(output_index) || tx_secret_key_hash || reference_block_hash)
/// ) mod n_total
/// ```
///
/// All inputs are known to the sender before broadcasting. The hash-based
/// derivation provides roughly-uniform rotation and grinding resistance.
pub fn rotating_prover_index(
    group_id: &[u8; 32],
    output_index_in_tx: u64,
    tx_secret_key_hash: &[u8; 32],
    reference_block_hash: &[u8; 32],
    n_total: u8,
) -> Result<u8, CryptoError> {
    if n_total == 0 {
        return Err(CryptoError::InvalidKeyMaterial);
    }

    let mut preimage = Vec::with_capacity(32 + 8 + 32 + 32);
    preimage.extend_from_slice(group_id);
    preimage.extend_from_slice(&output_index_in_tx.to_le_bytes());
    preimage.extend_from_slice(tx_secret_key_hash);
    preimage.extend_from_slice(reference_block_hash);

    let hash = cn_fast_hash(&preimage);
    Ok(hash[0] % n_total)
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
// FCMP++ multisig helpers
// ---------------------------------------------------------------------------

/// Compute the PQC leaf hash for a multisig key container.
///
/// In FCMP++ transactions, each curve-tree leaf contains H(pqc_pk). For
/// multisig outputs, pqc_pk is the canonical encoding of the
/// MultisigKeyContainer. This function returns H(container_bytes) as a
/// 32-byte hash suitable for the prover and verifier.
pub fn multisig_pqc_leaf_hash(
    container: &MultisigKeyContainer,
) -> Result<[u8; 32], PqcVerifyError> {
    let canonical = container.to_canonical_bytes()?;
    Ok(cn_fast_hash(&canonical))
}

/// Verify that a set of partial signatures forms a valid M-of-N multisig
/// for an FCMP++ transaction payload.
///
/// This is a convenience wrapper that:
///  1. Builds a MultisigSigContainer from the provided partial signatures.
///  2. Delegates to `verify_multisig` with the given key container and message.
///
/// `partials` is a sorted (ascending by index) slice of (signer_index, signature).
// CLIPPY: partials.len() is checked == m_required (u8) immediately below.
#[allow(clippy::cast_possible_truncation)]
pub fn verify_fcmp_multisig_partials(
    key_container: &MultisigKeyContainer,
    partials: &[(u8, HybridSignature)],
    message: &[u8],
    expected_group_id: Option<&[u8; 32]>,
) -> Result<bool, PqcVerifyError> {
    if partials.len() != key_container.m_required as usize {
        return Err(PqcVerifyError::ThresholdMismatch);
    }

    let sig_container = MultisigSigContainer {
        sig_count: partials.len() as u8,
        sigs: partials.iter().map(|(_, sig)| sig.clone()).collect(),
        signer_indices: partials.iter().map(|(idx, _)| *idx).collect(),
    };

    let key_blob = key_container.to_canonical_bytes()?;
    let sig_blob = sig_container.to_canonical_bytes()?;

    verify_multisig(
        HYBRID_SCHEME_ID_MULTISIG,
        &key_blob,
        &sig_blob,
        message,
        expected_group_id,
    )
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

    fn gen_spend_auth_pubkeys(n: usize) -> Vec<[u8; 32]> {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        (0..n)
            .map(|_| {
                let sk = SigningKey::generate(&mut OsRng);
                sk.verifying_key().to_bytes()
            })
            .collect()
    }

    #[allow(clippy::cast_possible_truncation)]
    fn make_key_container(
        pairs: &[(HybridPublicKey, crate::signature::HybridSecretKey)],
        m: u8,
    ) -> MultisigKeyContainer {
        let n = pairs.len();
        MultisigKeyContainer {
            version: MULTISIG_CONTAINER_VERSION,
            n_total: n as u8,
            m_required: m,
            keys: pairs.iter().map(|(pk, _)| pk.clone()).collect(),
            spend_auth_pubkeys: gen_spend_auth_pubkeys(n),
        }
    }

    #[allow(clippy::cast_possible_truncation)]
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
        assert_eq!(blob.len(), MultisigKeyContainer::expected_blob_len(3));
        let kc2 = MultisigKeyContainer::from_canonical_bytes(&blob).unwrap();
        assert_eq!(kc2.version, MULTISIG_CONTAINER_VERSION);
        assert_eq!(kc2.n_total, 3);
        assert_eq!(kc2.m_required, 2);
        assert_eq!(kc2.keys.len(), 3);
        assert_eq!(kc2.spend_auth_pubkeys.len(), 3);
        assert_eq!(kc2.spend_auth_pubkeys, kc.spend_auth_pubkeys);
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
        assert_ne!(
            multisig_group_id(&kc1).unwrap(),
            multisig_group_id(&kc2).unwrap()
        );
    }

    #[test]
    fn group_id_changes_with_threshold() {
        let pairs = gen_keypairs(3);
        let kc2 = make_key_container(&pairs, 2);
        let kc3 = make_key_container(&pairs, 3);
        assert_ne!(
            multisig_group_id(&kc2).unwrap(),
            multisig_group_id(&kc3).unwrap()
        );
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
        // Too short
        let result = MultisigKeyContainer::from_canonical_bytes(&[0x01, 0]);
        assert_eq!(result.unwrap_err(), PqcVerifyError::KeyBlobLength);

        // Wrong version
        let result = MultisigKeyContainer::from_canonical_bytes(&[0x00, 3, 2]);
        assert_eq!(result.unwrap_err(), PqcVerifyError::ParameterBounds);

        // n_total = 0
        let result = MultisigKeyContainer::from_canonical_bytes(&[0x01, 0, 2]);
        assert_eq!(result.unwrap_err(), PqcVerifyError::ParameterBounds);

        // m_required = 0
        let result = MultisigKeyContainer::from_canonical_bytes(&[0x01, 3, 0]);
        assert_eq!(result.unwrap_err(), PqcVerifyError::ParameterBounds);

        // m > n
        let result = MultisigKeyContainer::from_canonical_bytes(&[0x01, 2, 3]);
        assert_eq!(result.unwrap_err(), PqcVerifyError::ParameterBounds);

        // n > MAX_MULTISIG_PARTICIPANTS
        let result = MultisigKeyContainer::from_canonical_bytes(&[0x01, 8, 2]);
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
        let sa_pks = gen_spend_auth_pubkeys(3);
        let dup_kc = MultisigKeyContainer {
            version: MULTISIG_CONTAINER_VERSION,
            n_total: 3,
            m_required: 2,
            keys: vec![pairs[0].0.clone(), pairs[1].0.clone(), pairs[0].0.clone()],
            spend_auth_pubkeys: sa_pks,
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

    #[test]
    fn valid_subset_signing_3_of_5() {
        let pairs = gen_keypairs(5);
        let kc = make_key_container(&pairs, 3);
        let group_id = multisig_group_id(&kc).unwrap();
        let key_blob = kc.to_canonical_bytes().unwrap();
        let msg = b"subset-signing-3of5";

        let subsets: &[&[u8]] = &[&[0, 1, 2], &[0, 2, 4], &[2, 3, 4]];

        for subset in subsets {
            let sc = sign_multisig(&pairs, subset, msg);
            let sig_blob = sc.to_canonical_bytes().unwrap();
            let result = verify_multisig(2, &key_blob, &sig_blob, msg, Some(&group_id));
            assert!(
                result.unwrap(),
                "subset {subset:?} should verify successfully",
            );
        }
    }

    // -- FCMP++ multisig helpers --

    #[test]
    fn multisig_pqc_leaf_hash_deterministic() {
        let pairs = gen_keypairs(3);
        let kc = make_key_container(&pairs, 2);
        let h1 = super::multisig_pqc_leaf_hash(&kc).unwrap();
        let h2 = super::multisig_pqc_leaf_hash(&kc).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn multisig_pqc_leaf_hash_differs_for_different_groups() {
        let pairs1 = gen_keypairs(3);
        let pairs2 = gen_keypairs(3);
        let kc1 = make_key_container(&pairs1, 2);
        let kc2 = make_key_container(&pairs2, 2);
        assert_ne!(
            super::multisig_pqc_leaf_hash(&kc1).unwrap(),
            super::multisig_pqc_leaf_hash(&kc2).unwrap()
        );
    }

    #[test]
    fn verify_fcmp_multisig_partials_valid_2_of_3() {
        let pairs = gen_keypairs(3);
        let kc = make_key_container(&pairs, 2);
        let msg = b"fcmp-multisig-payload";
        let group_id = multisig_group_id(&kc).unwrap();
        let scheme = HybridEd25519MlDsa;

        let sig0 = scheme.sign(&pairs[0].1, msg).unwrap();
        let sig2 = scheme.sign(&pairs[2].1, msg).unwrap();

        let partials = vec![(0u8, sig0), (2u8, sig2)];
        let result = super::verify_fcmp_multisig_partials(&kc, &partials, msg, Some(&group_id));
        assert!(result.unwrap());
    }

    #[test]
    fn verify_fcmp_multisig_partials_threshold_mismatch() {
        let pairs = gen_keypairs(3);
        let kc = make_key_container(&pairs, 2);
        let msg = b"threshold-mismatch";
        let scheme = HybridEd25519MlDsa;

        let sig0 = scheme.sign(&pairs[0].1, msg).unwrap();
        let partials = vec![(0u8, sig0)];
        let result = super::verify_fcmp_multisig_partials(&kc, &partials, msg, None);
        assert_eq!(result.unwrap_err(), PqcVerifyError::ThresholdMismatch);
    }

    // -- Rotating prover index tests --

    #[test]
    fn rotating_prover_deterministic() {
        let group_id = [0xAB; 32];
        let tx_sk_hash = [0xCD; 32];
        let ref_block = [0xEF; 32];

        let idx1 = rotating_prover_index(&group_id, 0, &tx_sk_hash, &ref_block, 3).unwrap();
        let idx2 = rotating_prover_index(&group_id, 0, &tx_sk_hash, &ref_block, 3).unwrap();
        assert_eq!(idx1, idx2);
    }

    #[test]
    fn rotating_prover_within_bounds() {
        let group_id = [0xAB; 32];
        let tx_sk_hash = [0xCD; 32];
        let ref_block = [0xEF; 32];

        for n in 1..=MAX_MULTISIG_PARTICIPANTS {
            for output_idx in 0..20u64 {
                let prover = rotating_prover_index(
                    &group_id, output_idx, &tx_sk_hash, &ref_block, n,
                ).unwrap();
                assert!(prover < n, "prover index {prover} >= n_total {n}");
            }
        }
    }

    #[test]
    fn rotating_prover_varies_with_inputs() {
        let group_id = [0xAB; 32];
        let tx_sk_hash = [0xCD; 32];
        let ref_block = [0xEF; 32];

        let mut indices = std::collections::HashSet::new();
        for output_idx in 0..100u64 {
            indices.insert(rotating_prover_index(
                &group_id, output_idx, &tx_sk_hash, &ref_block, 7,
            ).unwrap());
        }
        assert!(
            indices.len() > 1,
            "prover index should vary across outputs (got {indices:?})"
        );
    }

    #[test]
    fn rotating_prover_1_of_1() {
        let group_id = [0; 32];
        let tx_sk_hash = [0; 32];
        let ref_block = [0; 32];
        assert_eq!(rotating_prover_index(&group_id, 0, &tx_sk_hash, &ref_block, 1).unwrap(), 0);
        assert_eq!(rotating_prover_index(&group_id, 99, &tx_sk_hash, &ref_block, 1).unwrap(), 0);
    }

    // -- V3.1 group_id tests --

    #[test]
    fn group_id_v31_includes_version_fields() {
        let pairs = gen_keypairs(3);
        let kc = make_key_container(&pairs, 2);

        let id_v31 = multisig_group_id(&kc).unwrap();

        let id_wrong_scheme = multisig_group_id_with_versions(
            &kc,
            MULTISIG_CONTAINER_VERSION,
            0xFF,
            SPEND_AUTH_VERSION_ED25519,
        )
        .unwrap();
        assert_ne!(id_v31, id_wrong_scheme, "scheme_id must affect group_id");

        let id_wrong_sa_ver = multisig_group_id_with_versions(
            &kc,
            MULTISIG_CONTAINER_VERSION,
            HYBRID_SCHEME_ID_MULTISIG,
            0xFF,
        )
        .unwrap();
        assert_ne!(
            id_v31, id_wrong_sa_ver,
            "spend_auth_version must affect group_id"
        );
    }
}
