//! M-of-N PQC multisig: containers, group identity, and verification.
//!
//! Wire format uses opaque blobs that embed in the existing `pqc_auth`
//! fields (`hybrid_public_key`, `hybrid_signature`) with `scheme_id = 2`.
//!
//! V3.1 extends the container with a `version` byte and per-participant
//! classical spend-auth pubkeys (`spend_auth_pubkeys`). See `PQC_MULTISIG.md`
//! v1.1 for the full specification.

use crate::error::PqcVerifyError;
use crate::signature::{HybridEd25519MlDsa, HybridPublicKey, HybridSignature, SignatureScheme};
use shekyl_crypto_hash::keccak256;

/// Largest multisig group served (MSW-G, settled 2026-07-15: 2f+1 at f=2;
/// withdrew the same-day MAX=8 pick). The value is the *correctness* cap —
/// `from_canonical_bytes` rejects `n_total > MAX` — and is deliberately NOT
/// the source of the DoS ceilings below (see `PQC_MAX_*_BLOB`).
pub const MAX_MULTISIG_PARTICIPANTS: u8 = 5;
pub const HYBRID_SCHEME_ID_MULTISIG: u8 = 2;

/// V3.1 container version (first version with spend_auth_pubkeys).
pub const MULTISIG_CONTAINER_VERSION: u8 = 0x01;

/// Classical spend-auth pubkey length (compressed Ed25519 point).
pub const SPEND_AUTH_PUBKEY_LEN: usize = 32;

/// Size of a single `HybridPublicKey` in canonical encoding (1996). Aliased
/// from the type that owns the encoding — one canonical definition (MSW-1).
pub const SINGLE_KEY_CANONICAL_LEN: usize = HybridPublicKey::CANONICAL_LEN;

/// Size of a single `HybridSignature` in canonical encoding (3385). Aliased
/// from the type that owns the encoding — one canonical definition (MSW-1).
pub const SINGLE_SIG_CANONICAL_LEN: usize = HybridSignature::CANONICAL_LEN;

/// DoS pre-bound for the serialized multisig **key** container
/// (`pqc_auth.hybrid_public_key`, scheme 2). A generous, round ceiling
/// **decoupled** from `MAX_MULTISIG_PARTICIPANTS`: correctness (exact byte
/// count, `n ≤ MAX`) is `MultisigKeyContainer::from_canonical_bytes`, not this
/// bound. Bumping it needs a consensus rationale. The `const` assert below
/// makes a ceiling *below* the largest legal container a **compile error** —
/// MSW-1 / F-1: the old `2 + N·LEN` fossil formula silently stopped tracking
/// the real container on every MAX/field change (it omitted both the 3-byte
/// header and the 32-byte-per-participant spend-auth keys).
pub const PQC_MAX_PUBLIC_KEY_BLOB: usize = 16_384;

/// DoS pre-bound for the serialized multisig **signature** container. Same
/// discipline as `PQC_MAX_PUBLIC_KEY_BLOB`.
pub const PQC_MAX_SIGNATURE_BLOB: usize = 32_768;

// Compile-time ceiling ladder (compile errors > runtime guards > reviewer
// discipline). A too-small ceiling can no longer land: the largest legal
// container at MAX must fit under the ceiling, checked at build time.
const _: () = assert!(
    MultisigKeyContainer::expected_blob_len(MAX_MULTISIG_PARTICIPANTS) <= PQC_MAX_PUBLIC_KEY_BLOB,
    "PQC_MAX_PUBLIC_KEY_BLOB below the largest legal MultisigKeyContainer — see MSW-1/F-1"
);
const _: () = assert!(
    MultisigSigContainer::expected_sig_len(MAX_MULTISIG_PARTICIPANTS) <= PQC_MAX_SIGNATURE_BLOB,
    "PQC_MAX_SIGNATURE_BLOB below the largest legal MultisigSigContainer — see MSW-1/F-1"
);

// MSW-1: the participant cap is enforced at two validation surfaces — this
// key container (`from_canonical_bytes`) and the multisig address payload
// (`shekyl-address`). Both express the same MSW-G invariant; an address that
// exceeds the container cap is dead-on-arrival (no container can be built for
// it). crypto-pq already depends on shekyl-address, so the two caps are pinned
// equal here at compile time — the F-1 lesson is that a bound duplicated across
// a boundary must be caught by a mechanism, never by reviewer discipline.
const _: () = assert!(
    MAX_MULTISIG_PARTICIPANTS == shekyl_address::multisig_address::MAX_MULTISIG_PARTICIPANTS,
    "MSW-1: shekyl-crypto-pq and shekyl-address multisig participant caps diverged"
);

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
    ///
    /// `const fn` so the DoS-ceiling ladder (`PQC_MAX_PUBLIC_KEY_BLOB`) can
    /// assert against it at compile time.
    pub const fn expected_blob_len(n: u8) -> usize {
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
    /// Expected byte length of an `m`-signature canonical encoding:
    /// `sig_count(1) || m·sig(3385) || m·idx(1)`. `const fn` so the
    /// `PQC_MAX_SIGNATURE_BLOB` ceiling can assert against it at compile time.
    pub const fn expected_sig_len(m: u8) -> usize {
        1 + (m as usize) * SINGLE_SIG_CANONICAL_LEN + (m as usize)
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, PqcVerifyError> {
        let cap = Self::expected_sig_len(self.sig_count);
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

        let expected_len = Self::expected_sig_len(sig_count);
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

/// Classical spend-auth version byte.
///
/// **E′ = `0x02`.** The never-issued Option-D scaffold was `0x01`; the shipping
/// design is E′, so the constant names it. This is the multisig receive **scan
/// gate**: [`scan_multisig_output_for_participant`](crate::multisig_receiving::scan_multisig_output_for_participant)
/// silently skips any output whose `spend_auth_version` is not this value, so an
/// E′ address (stamped `0x02` by `shekyl-address`) scans and a stale `0x01` one
/// does not. (It formerly also fed the now-deleted `multisig_group_id` preimage —
/// group identity is the address fingerprint, not a per-output container hash.)
pub const SPEND_AUTH_VERSION_ED25519: u8 = 0x02;

// ---------------------------------------------------------------------------
// 9-check verification pipeline
//
// "Check N" is the pipeline *position*, not the error discriminant. Checks 1-8
// happen to return `PqcVerifyError` discriminants 1-8, but check 9 (crypto)
// returns `CryptoVerifyFailed` = discriminant **10**: discriminant 9 (the former
// GroupIdMismatch "check 9") is a retired gap kept so the FFI codes 10/11 do not
// shift under existing C++ consumers (see `error.rs`). Ordinal 9 ≠ code 9.
// ---------------------------------------------------------------------------

/// Verify an M-of-N PQC multisig against the 9-check adversarial pipeline.
///
/// Group-identity is **not** checked here. Under E′ the group's identity is the
/// address fingerprint (`shekyl-address`), not a per-output container hash, and
/// there is no sound on-chain `expected_group_id` for the daemon to supply — the
/// former "check 9" recomputed the id from the *same* `key_blob` the curve-tree
/// leaf `h_pqc = H(blob)` already binds, so it was a self-referential tautology.
/// The consensus caller (the `shekyl-daemon-rpc` submit verifier) and every other
/// caller already passed `None`; the parameter is gone.
///
/// Returns `Ok(())` on success and `Err` on any failure — `Result<()>`, **not**
/// `Result<bool>` (SA-R-1): there is no `Ok(false)` for a caller to mishandle.
/// Do not restore a boolean return.
pub fn verify_multisig(
    scheme_id: u8,
    key_blob: &[u8],
    sig_blob: &[u8],
    message: &[u8],
) -> Result<(), PqcVerifyError> {
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

    // Check 9 (final): cryptographic verification (M x Ed25519 + M x ML-DSA).
    // Returns `CryptoVerifyFailed` = discriminant 10, NOT code 9 (retired gap).
    let scheme = HybridEd25519MlDsa;
    for (sig, &idx) in sig_container
        .sigs
        .iter()
        .zip(sig_container.signer_indices.iter())
    {
        let pk = &key_container.keys[idx as usize];
        // Participants verify under the multisig-specific domain (SA-R-5): a
        // single-signer signature over `message` is not a valid participant
        // signature, and vice versa, even for a caller that passes a bare
        // payload here — see `SCHEME_DOMAIN_PQC_AUTH_TX_MULTISIG`.
        scheme
            .verify(
                pk,
                crate::signature::SCHEME_DOMAIN_PQC_AUTH_TX_MULTISIG,
                message,
                sig,
            )
            .map_err(|_| PqcVerifyError::CryptoVerifyFailed)?;
    }

    Ok(())
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
    Ok(keccak256(&canonical))
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
        (0..n)
            .map(|_| scheme.generate_ephemeral_keypair_for_tests().unwrap())
            .collect()
    }

    /// Multisig participant signatures use the multisig-specific domain, so
    /// they match what `verify_multisig` checks (SA-R-5).
    const MSD: &[u8] = crate::signature::SCHEME_DOMAIN_PQC_AUTH_TX_MULTISIG;

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
            .map(|&idx| scheme.sign(&pairs[idx as usize].1, MSD, message).unwrap())
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

    // -- Full verification pipeline --

    #[test]
    fn valid_2_of_3() {
        let pairs = gen_keypairs(3);
        let kc = make_key_container(&pairs, 2);
        let msg = b"tx-payload-hash-2of3";
        let sc = sign_multisig(&pairs, &[0, 2], msg);
        let key_blob = kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        verify_multisig(2, &key_blob, &sig_blob, msg).unwrap();
    }

    #[test]
    fn valid_1_of_1() {
        let pairs = gen_keypairs(1);
        let kc = make_key_container(&pairs, 1);
        let msg = b"1-of-1-edge-case";
        let sc = sign_multisig(&pairs, &[0], msg);
        let key_blob = kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        verify_multisig(2, &key_blob, &sig_blob, msg).unwrap();
    }

    /// SA-R-5 cross-domain separation (the negative control): a signature made
    /// under the **single-sig** domain (`SCHEME_DOMAIN_PQC_AUTH_TX`, what the
    /// single-signer FFI produces) is **rejected** by `verify_multisig`, which
    /// checks under `SCHEME_DOMAIN_PQC_AUTH_TX_MULTISIG`. Without the distinct
    /// domain a single-signer signature over `msg` would verify here — the
    /// interchangeability this separation exists to remove.
    #[test]
    fn single_sig_domain_signature_rejected_as_multisig_participant() {
        let pairs = gen_keypairs(1);
        let kc = make_key_container(&pairs, 1);
        let msg = b"cross-domain-separation";
        // Sign under the SINGLE-SIG domain instead of the multisig one.
        let scheme = HybridEd25519MlDsa;
        let wrong_domain_sig = scheme
            .sign(
                &pairs[0].1,
                crate::signature::SCHEME_DOMAIN_PQC_AUTH_TX,
                msg,
            )
            .unwrap();
        let sc = MultisigSigContainer {
            sig_count: 1,
            sigs: vec![wrong_domain_sig],
            signer_indices: vec![0],
        };
        let key_blob = kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        assert_eq!(
            verify_multisig(2, &key_blob, &sig_blob, msg).unwrap_err(),
            PqcVerifyError::CryptoVerifyFailed,
            "a single-sig-domain signature must not verify as a multisig participant"
        );
        // And the converse: a correct multisig-domain container still verifies.
        let good = sign_multisig(&pairs, &[0], msg);
        let good_blob = good.to_canonical_bytes().unwrap();
        verify_multisig(2, &key_blob, &good_blob, msg).unwrap();
    }

    #[test]
    fn valid_5_of_5() {
        // MSW-G = 5: the largest legal group verifies end to end.
        let pairs = gen_keypairs(5);
        let kc = make_key_container(&pairs, 5);
        let msg = b"5-of-5-max";
        let sc = sign_multisig(&pairs, &[0, 1, 2, 3, 4], msg);
        let key_blob = kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        verify_multisig(2, &key_blob, &sig_blob, msg).unwrap();
    }

    // MSW-1 cross-seam length KAT. The absence of a test that crossed the
    // container↔wire seam produced F-1. For every legal group size the
    // serialized length equals the single canonical length expression
    // (`expected_*_len`) and the bytes round-trip — the release-safe form of the
    // `debug_assert_eq!(out.len(), cap)` inside `to_canonical_bytes`, and it also
    // pins `from_canonical_bytes` to the same length. `n = MAX + 1` is the DoS-
    // ceiling-independent correctness cap.
    #[test]
    fn msw1_container_lengths_and_roundtrip_over_all_n() {
        for n in 1..=MAX_MULTISIG_PARTICIPANTS {
            let pairs = gen_keypairs(n as usize);
            let kc = make_key_container(&pairs, n); // n-of-n
            let blob = kc.to_canonical_bytes().unwrap();
            assert_eq!(
                blob.len(),
                MultisigKeyContainer::expected_blob_len(n),
                "key container length != expected_blob_len at n={n}"
            );
            let kc2 = MultisigKeyContainer::from_canonical_bytes(&blob).unwrap();
            assert_eq!(kc2.n_total, n);
            assert_eq!(kc2.spend_auth_pubkeys, kc.spend_auth_pubkeys);

            let indices: Vec<u8> = (0..n).collect();
            let sc = sign_multisig(&pairs, &indices, b"msw1-kat");
            let sblob = sc.to_canonical_bytes().unwrap();
            assert_eq!(
                sblob.len(),
                MultisigSigContainer::expected_sig_len(n),
                "sig container length != expected_sig_len at m={n}"
            );
            let sc2 = MultisigSigContainer::from_canonical_bytes(&sblob).unwrap();
            assert_eq!(sc2.sig_count, n);
        }
    }

    #[test]
    fn msw1_parser_rejects_over_max() {
        let pairs = gen_keypairs(MAX_MULTISIG_PARTICIPANTS as usize);
        let kc = make_key_container(&pairs, 1);
        let mut blob = kc.to_canonical_bytes().unwrap();
        blob[1] = MAX_MULTISIG_PARTICIPANTS + 1; // claim one too many participants
        assert_eq!(
            MultisigKeyContainer::from_canonical_bytes(&blob).unwrap_err(),
            PqcVerifyError::ParameterBounds
        );
    }

    // MSW-2: cross-scheme disjointness holds by two independent separators, so a
    // scheme-1 single-key blob can never be reparsed as a scheme-2 container
    // (or vice versa) — even before the tx-level `scheme_id` is consulted. The
    // leaf (scheme-1) encoding is deliberately left untouched (R1-F-2).
    #[test]
    fn msw2_length_primary_disjointness() {
        // Separator 1 (primary): length. The single scheme-1 key length is not
        // any legal scheme-2 container length, and distinct group sizes never
        // collide — `expected_blob_len` is strictly increasing (hence
        // injective) over the legal range. Length alone fixes scheme + size.
        let container_lens: Vec<usize> = (1..=MAX_MULTISIG_PARTICIPANTS)
            .map(MultisigKeyContainer::expected_blob_len)
            .collect();
        assert!(
            !container_lens.contains(&SINGLE_KEY_CANONICAL_LEN),
            "scheme-1 leaf length {SINGLE_KEY_CANONICAL_LEN} collided with a container length",
        );
        for w in container_lens.windows(2) {
            assert!(
                w[0] < w[1],
                "expected_blob_len not strictly increasing: {w:?}"
            );
        }

        // The primary separator is enforced, not merely arithmetic: a blob whose
        // byte length is correct for one group size but whose declared n_total
        // is a *different* legal size is rejected on the length cross-check,
        // never silently reinterpreted. (m = 1 keeps the relabel within m ≤ n so
        // the length check — not the bounds check — is what fires.)
        let pairs = gen_keypairs(MAX_MULTISIG_PARTICIPANTS as usize);
        let kc = make_key_container(&pairs, 1); // n = MAX, m = 1
        let mut relabelled = kc.to_canonical_bytes().unwrap();
        relabelled[1] = MAX_MULTISIG_PARTICIPANTS - 1; // shrink declared n, keep m ≤ n
        assert_eq!(
            MultisigKeyContainer::from_canonical_bytes(&relabelled).unwrap_err(),
            PqcVerifyError::KeyBlobLength
        );

        // Separator 2 (secondary): byte[2] = m_required is ≥ 1 for every legal
        // container (`m_required == 0` ⊥ any valid group), so a reader that
        // reached this byte still distinguishes a container from a reserved-zero
        // leaf byte.
        let mut zero_m = kc.to_canonical_bytes().unwrap();
        zero_m[2] = 0;
        assert_eq!(
            MultisigKeyContainer::from_canonical_bytes(&zero_m).unwrap_err(),
            PqcVerifyError::ParameterBounds
        );
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
            verify_multisig(1, &key_blob, &sig_blob, msg).unwrap_err(),
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
            verify_multisig(2, &key_blob, &sig_blob, msg).unwrap_err(),
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
                scheme.sign(&pairs[0].1, MSD, msg).unwrap(),
                scheme.sign(&pairs[1].1, MSD, msg).unwrap(),
            ],
            signer_indices: vec![0, 3],
        };
        let key_blob = kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        assert_eq!(
            verify_multisig(2, &key_blob, &sig_blob, msg).unwrap_err(),
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
                scheme.sign(&pairs[1].1, MSD, msg).unwrap(),
                scheme.sign(&pairs[0].1, MSD, msg).unwrap(),
            ],
            signer_indices: vec![1, 0],
        };
        let key_blob = kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        assert_eq!(
            verify_multisig(2, &key_blob, &sig_blob, msg).unwrap_err(),
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
                scheme.sign(&pairs[0].1, MSD, msg).unwrap(),
                scheme.sign(&pairs[1].1, MSD, msg).unwrap(),
            ],
            signer_indices: vec![0, 1],
        };
        let key_blob = dup_kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        assert_eq!(
            verify_multisig(2, &key_blob, &sig_blob, msg).unwrap_err(),
            PqcVerifyError::DuplicateKeys
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
            verify_multisig(2, &key_blob, &sig_blob, b"wrong-message").unwrap_err(),
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
                scheme.sign(&pairs[0].1, MSD, msg).unwrap(),
                scheme.sign(&pairs[0].1, MSD, msg).unwrap(), // signed with key 0, but index says 1
            ],
            signer_indices: vec![0, 1],
        };
        let key_blob = kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        assert_eq!(
            verify_multisig(2, &key_blob, &sig_blob, msg).unwrap_err(),
            PqcVerifyError::CryptoVerifyFailed
        );
    }

    // -- Hedged / nested non-determinism test --

    #[test]
    fn nested_hedged_signing_produces_different_sigs() {
        let pairs = gen_keypairs(1);
        let msg = b"non-determinism";
        let scheme = HybridEd25519MlDsa;
        let sig1 = scheme.sign(&pairs[0].1, MSD, msg).unwrap();
        let sig2 = scheme.sign(&pairs[0].1, MSD, msg).unwrap();
        // ML-DSA uses hedged signing: same message, same key -> different σ_pq.
        assert_ne!(sig1.ml_dsa, sig2.ml_dsa);
        // Under the nested combiner the Ed25519 half signs `inner ‖ σ_pq`, so a
        // hedged σ_pq makes the classical half differ too. This is the nesting
        // binding the two halves — the v1 *parallel* construction left Ed25519
        // deterministic here because it signed the bare message independently.
        assert_ne!(sig1.ed25519, sig2.ed25519);
        // Both must verify.
        scheme.verify(&pairs[0].0, MSD, msg, &sig1).unwrap();
        scheme.verify(&pairs[0].0, MSD, msg, &sig2).unwrap();
    }

    // -- Edge cases --

    #[test]
    fn valid_1_of_5() {
        let pairs = gen_keypairs(5);
        let kc = make_key_container(&pairs, 1);
        let msg = b"1-of-5";
        let sc = sign_multisig(&pairs, &[3], msg);
        let key_blob = kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        verify_multisig(2, &key_blob, &sig_blob, msg).unwrap();
    }

    #[test]
    fn skip_group_id_check_with_none() {
        let pairs = gen_keypairs(2);
        let kc = make_key_container(&pairs, 2);
        let msg = b"no-group-check";
        let sc = sign_multisig(&pairs, &[0, 1], msg);
        let key_blob = kc.to_canonical_bytes().unwrap();
        let sig_blob = sc.to_canonical_bytes().unwrap();

        verify_multisig(2, &key_blob, &sig_blob, msg).unwrap();
    }

    #[test]
    fn valid_subset_signing_3_of_5() {
        let pairs = gen_keypairs(5);
        let kc = make_key_container(&pairs, 3);
        let key_blob = kc.to_canonical_bytes().unwrap();
        let msg = b"subset-signing-3of5";

        let subsets: &[&[u8]] = &[&[0, 1, 2], &[0, 2, 4], &[2, 3, 4]];

        for subset in subsets {
            let sc = sign_multisig(&pairs, subset, msg);
            let sig_blob = sc.to_canonical_bytes().unwrap();
            verify_multisig(2, &key_blob, &sig_blob, msg)
                .unwrap_or_else(|e| panic!("subset {subset:?} should verify successfully: {e:?}"));
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
}
