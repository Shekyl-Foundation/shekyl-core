//! Per-output multisig receiving derivations (PQC_MULTISIG.md SS7.1–SS8.4).
//!
//! Domain-separated HKDF expansions from each participant's KEM shared secret
//! to derive ephemeral material for multisig outputs. These functions implement
//! the three-label KDF scheme from §7.2 plus the KEM randomness derivation
//! from §7.3.
//!
//! Also implements output scanning (§8.1). The Option-D output construction
//! (§7.1) and receive-time prover validation (§8.3 / I7) were deleted under E′
//! (they rested on the rotating prover, which E′ removes); the surviving
//! derivations are the E′-shared per-output KDF substrate. Under E′ there is no
//! multisig output constructor here until S2/S4 writes the two-component one.
//!
//! Labels are the single source of truth for domain separation:
//! - `"shekyl-v31-hybrid-sign"`     → ephemeral hybrid signing keypair
//! - `"shekyl-v31-classical-spend"` → classical spend-auth scalar + pubkey
//! - `"shekyl-v31-view-tag"`        → 1-byte view tag hint
//! - `"shekyl-v31-kem-seed"`        → per-output KEM seed
//! - `"shekyl-v31-multisig-kem"`    → per-participant KEM randomness

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::kem::{
    HybridCiphertext, HybridKemSecretKey, HybridX25519MlKem, KeyEncapsulation, SharedSecret,
};
use crate::multisig::SPEND_AUTH_VERSION_ED25519;

// ── KDF labels (must match PQC_MULTISIG.md §7.2 table) ─────────────────

const LABEL_HYBRID_SIGN: &[u8] = b"shekyl-v31-hybrid-sign";
const LABEL_CLASSICAL_SPEND: &[u8] = b"shekyl-v31-classical-spend";
const LABEL_VIEW_TAG: &[u8] = b"shekyl-v31-view-tag";
const LABEL_KEM_SEED: &[u8] = b"shekyl-v31-kem-seed";
const LABEL_MULTISIG_KEM: &[u8] = b"shekyl-v31-multisig-kem";

/// Derive a classical spend-auth scalar and its public key from a KEM shared secret.
///
/// Returns `(y_scalar_bytes, Y_pubkey_bytes)` where `Y = y * G`.
/// `y` is derived via `wide_reduce(HKDF-Expand(ss, "shekyl-v31-classical-spend", 64))`.
pub fn derive_spend_auth_pubkey(
    shared_secret: &[u8],
) -> Result<(zeroize::Zeroizing<[u8; 32]>, [u8; 32]), CryptoError> {
    let hk = Hkdf::<Sha512>::new(None, shared_secret);
    let mut wide = [0u8; 64];
    hk.expand(LABEL_CLASSICAL_SPEND, &mut wide)
        .map_err(|_| CryptoError::KeyGenerationFailed("HKDF-Expand failed".into()))?;

    let y_scalar = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();

    if y_scalar == Scalar::ZERO {
        return Err(CryptoError::KeyGenerationFailed(
            "spend-auth scalar is zero".into(),
        ));
    }

    let y_point = &y_scalar * ED25519_BASEPOINT_TABLE;
    let y_compressed = y_point.compress().to_bytes();

    let mut scalar_bytes = zeroize::Zeroizing::new([0u8; 32]);
    *scalar_bytes = y_scalar.to_bytes();

    Ok((scalar_bytes, y_compressed))
}

/// Derive a 1-byte view tag hint from a KEM shared secret.
///
/// Used for fast scanner pre-filtering on multisig outputs (§7.2, §8.1).
pub fn derive_view_tag_hint(shared_secret: &[u8]) -> Result<u8, CryptoError> {
    let hk = Hkdf::<Sha512>::new(None, shared_secret);
    let mut out = [0u8; 1];
    hk.expand(LABEL_VIEW_TAG, &mut out)
        .map_err(|_| CryptoError::KeyGenerationFailed("HKDF-Expand failed".into()))?;
    Ok(out[0])
}

/// Derive a 64-byte hybrid signing seed from a KEM shared secret.
///
/// The caller uses this seed to derive a per-output ephemeral hybrid
/// signing keypair (Ed25519 + ML-DSA-65) via the standard keygen paths.
pub fn derive_hybrid_sign_seed(
    shared_secret: &[u8],
) -> Result<zeroize::Zeroizing<[u8; 64]>, CryptoError> {
    let hk = Hkdf::<Sha512>::new(None, shared_secret);
    let mut seed = zeroize::Zeroizing::new([0u8; 64]);
    hk.expand(LABEL_HYBRID_SIGN, seed.as_mut())
        .map_err(|_| CryptoError::KeyGenerationFailed("HKDF-Expand failed".into()))?;
    Ok(seed)
}

/// Derive a per-output KEM seed from the transaction secret key (§7.3).
///
/// ```text
/// kem_seed = HKDF-Expand(tx_secret_key, "shekyl-v31-kem-seed" || u64_le(output_index), 32)
/// ```
pub fn derive_multisig_kem_seed(
    tx_secret_key: &[u8; 32],
    output_index: u64,
) -> Result<zeroize::Zeroizing<[u8; 32]>, CryptoError> {
    let hk = Hkdf::<Sha512>::new(None, tx_secret_key.as_slice());
    let mut info = Vec::with_capacity(LABEL_KEM_SEED.len() + 8);
    info.extend_from_slice(LABEL_KEM_SEED);
    info.extend_from_slice(&output_index.to_le_bytes());

    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    hk.expand(&info, seed.as_mut())
        .map_err(|_| CryptoError::KeyGenerationFailed("HKDF-Expand for KEM seed".into()))?;
    Ok(seed)
}

/// Derive per-participant KEM randomness from the output-level KEM seed (§7.1).
///
/// ```text
/// kem_randomness_i = HKDF-Expand(
///     kem_seed,
///     "shekyl-v31-multisig-kem" || u64_le(output_index) || u8(participant_index),
///     64
/// )
/// ```
pub fn derive_participant_kem_randomness(
    kem_seed: &[u8; 32],
    output_index: u64,
    participant_index: u8,
) -> Result<zeroize::Zeroizing<[u8; 64]>, CryptoError> {
    let hk = Hkdf::<Sha512>::new(None, kem_seed.as_slice());
    let mut info = Vec::with_capacity(LABEL_MULTISIG_KEM.len() + 9);
    info.extend_from_slice(LABEL_MULTISIG_KEM);
    info.extend_from_slice(&output_index.to_le_bytes());
    info.push(participant_index);

    let mut randomness = zeroize::Zeroizing::new([0u8; 64]);
    hk.expand(&info, randomness.as_mut())
        .map_err(|_| CryptoError::KeyGenerationFailed("HKDF-Expand for KEM randomness".into()))?;
    Ok(randomness)
}

// ── Scanning (PQC_MULTISIG.md §8.1) ────────────────────────────────────

/// Result of a successful multisig output scan.
#[derive(Debug)]
pub struct ScannedMultisigOutput {
    pub shared_secret: SharedSecret,
    pub my_participant_index: u8,
    pub spend_auth_version: u8,
}

/// Attempt to scan a candidate multisig output for a specific participant (§8.1).
///
/// Returns `None` if the output doesn't belong to us (hint mismatch or decap
/// failure). Returns `Some(ScannedMultisigOutput)` on successful match.
pub fn scan_multisig_output_for_participant(
    my_participant_index: u8,
    my_kem_secret: &HybridKemSecretKey,
    my_ciphertext: &HybridCiphertext,
    expected_view_tag: u8,
    spend_auth_version: u8,
) -> Result<Option<ScannedMultisigOutput>, CryptoError> {
    if spend_auth_version != SPEND_AUTH_VERSION_ED25519 {
        return Ok(None);
    }

    let kem = HybridX25519MlKem;
    let ss = kem.decapsulate(my_kem_secret, my_ciphertext)?;

    let computed_hint = derive_view_tag_hint(&ss.0)?;
    if computed_hint != expected_view_tag {
        return Ok(None);
    }

    Ok(Some(ScannedMultisigOutput {
        shared_secret: ss,
        my_participant_index,
        spend_auth_version,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spend_auth_derivation_deterministic() {
        let ss = [0xab; 32];
        let (y1, pk1) = derive_spend_auth_pubkey(&ss).unwrap();
        let (y2, pk2) = derive_spend_auth_pubkey(&ss).unwrap();
        assert_eq!(*y1, *y2);
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn spend_auth_different_secrets() {
        let ss1 = [0xab; 32];
        let ss2 = [0xcd; 32];
        let (_, pk1) = derive_spend_auth_pubkey(&ss1).unwrap();
        let (_, pk2) = derive_spend_auth_pubkey(&ss2).unwrap();
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn spend_auth_pubkey_on_curve() {
        let ss = [0xab; 32];
        let (_, pk_bytes) = derive_spend_auth_pubkey(&ss).unwrap();
        let point = curve25519_dalek::edwards::CompressedEdwardsY(pk_bytes);
        assert!(
            point.decompress().is_some(),
            "spend-auth pubkey must be a valid curve point"
        );
    }

    #[test]
    fn view_tag_deterministic() {
        let ss = [0xab; 32];
        let t1 = derive_view_tag_hint(&ss).unwrap();
        let t2 = derive_view_tag_hint(&ss).unwrap();
        assert_eq!(t1, t2);
    }

    #[test]
    fn view_tag_different_secrets() {
        let tags: Vec<u8> = (0..16u8)
            .map(|i| {
                let mut ss = [0u8; 32];
                ss[0] = i;
                derive_view_tag_hint(&ss).unwrap()
            })
            .collect();
        let unique: std::collections::HashSet<u8> = tags.iter().copied().collect();
        assert!(
            unique.len() > 1,
            "view tags should vary across different secrets"
        );
    }

    #[test]
    fn hybrid_sign_seed_deterministic() {
        let ss = [0xab; 32];
        let s1 = derive_hybrid_sign_seed(&ss).unwrap();
        let s2 = derive_hybrid_sign_seed(&ss).unwrap();
        assert_eq!(*s1, *s2);
    }

    #[test]
    fn hybrid_sign_seed_differs_from_spend_auth() {
        let ss = [0xab; 32];
        let sign_seed = derive_hybrid_sign_seed(&ss).unwrap();
        let (spend_scalar, _) = derive_spend_auth_pubkey(&ss).unwrap();
        assert_ne!(
            &sign_seed[..32],
            spend_scalar.as_slice(),
            "hybrid-sign and classical-spend must use different domains"
        );
    }

    #[test]
    fn kem_seed_deterministic() {
        let tx_key = [0xab; 32];
        let s1 = derive_multisig_kem_seed(&tx_key, 0).unwrap();
        let s2 = derive_multisig_kem_seed(&tx_key, 0).unwrap();
        assert_eq!(*s1, *s2);
    }

    #[test]
    fn kem_seed_varies_with_index() {
        let tx_key = [0xab; 32];
        let s0 = derive_multisig_kem_seed(&tx_key, 0).unwrap();
        let s1 = derive_multisig_kem_seed(&tx_key, 1).unwrap();
        assert_ne!(*s0, *s1);
    }

    #[test]
    fn participant_kem_randomness_deterministic() {
        let seed = [0xab; 32];
        let r1 = derive_participant_kem_randomness(&seed, 0, 0).unwrap();
        let r2 = derive_participant_kem_randomness(&seed, 0, 0).unwrap();
        assert_eq!(*r1, *r2);
    }

    #[test]
    fn participant_kem_randomness_varies_with_participant() {
        let seed = [0xab; 32];
        let r0 = derive_participant_kem_randomness(&seed, 0, 0).unwrap();
        let r1 = derive_participant_kem_randomness(&seed, 0, 1).unwrap();
        assert_ne!(*r0, *r1);
    }

    #[test]
    fn participant_kem_randomness_varies_with_output() {
        let seed = [0xab; 32];
        let r0 = derive_participant_kem_randomness(&seed, 0, 0).unwrap();
        let r1 = derive_participant_kem_randomness(&seed, 1, 0).unwrap();
        assert_ne!(*r0, *r1);
    }

    #[test]
    fn all_domains_independent() {
        let ss = [0xef; 64];
        let (spend_scalar, _) = derive_spend_auth_pubkey(&ss).unwrap();
        let view_tag = derive_view_tag_hint(&ss).unwrap();
        let hybrid_seed = derive_hybrid_sign_seed(&ss).unwrap();

        assert_ne!(
            spend_scalar.as_slice(),
            &hybrid_seed[..32],
            "spend and hybrid-sign domains must not collide"
        );
        assert_ne!(
            view_tag,
            spend_scalar[0],
            "view tag should generally differ from first byte of spend scalar (not a hard guarantee, but overwhelmingly likely)"
        );
    }

    // -- Scan tests (E′) --
    //
    // Scan is the surviving receive path. The Option-D construct / validate /
    // rotating-prover machinery it used to round-trip against is gone, so these
    // build the scan fixture directly from the KEM — which is all scan needs: a
    // ciphertext and its true view-tag hint.

    fn scan_fixture() -> (HybridKemSecretKey, HybridCiphertext, u8) {
        let kem = HybridX25519MlKem;
        let (pk, sk) = kem.keypair_generate().unwrap();
        let (ss, ct) = kem.encapsulate(&pk).unwrap();
        let hint = derive_view_tag_hint(&ss.0).unwrap();
        (sk, ct, hint)
    }

    #[test]
    fn scan_accepts_own_output() {
        let (sk, ct, hint) = scan_fixture();
        let scanned =
            scan_multisig_output_for_participant(0, &sk, &ct, hint, SPEND_AUTH_VERSION_ED25519)
                .unwrap();
        assert!(
            scanned.is_some(),
            "own output with the matching hint + current version must scan"
        );
        assert_eq!(scanned.unwrap().my_participant_index, 0);
    }

    #[test]
    fn scan_rejects_hint_mismatch() {
        let (sk, ct, hint) = scan_fixture();
        // A hint the ciphertext's decap does not produce → the view-tag
        // pre-filter rejects without touching the rest of the pipeline.
        let result = scan_multisig_output_for_participant(
            0,
            &sk,
            &ct,
            hint.wrapping_add(1),
            SPEND_AUTH_VERSION_ED25519,
        )
        .unwrap();
        assert!(
            result.is_none(),
            "a mismatched view-tag hint must fail the scan"
        );
    }

    #[test]
    fn scan_rejects_non_current_spend_auth_version() {
        // The gate accepts only SPEND_AUTH_VERSION_ED25519 (E′ = 0x02). Both the
        // never-issued Option-D 0x01 and any unknown byte are silently skipped —
        // this pins the 0x01→0x02 bump: an address stamped 0x01 no longer scans.
        let (sk, ct, hint) = scan_fixture();
        for bad in [0x00u8, 0x01, 0xFF] {
            assert_ne!(bad, SPEND_AUTH_VERSION_ED25519);
            let result = scan_multisig_output_for_participant(0, &sk, &ct, hint, bad).unwrap();
            assert!(
                result.is_none(),
                "spend_auth_version 0x{bad:02x} must be skipped"
            );
        }
    }

    /// Cross-platform determinism canary (catches endian bugs, HashMap
    /// iteration, float contamination).  Fixed inputs -> pinned expected
    /// bytes.  Must produce identical output on Linux x86_64 and macOS
    /// ARM64.  If this test fails on any platform, something broke the
    /// canonical derivation path.
    #[test]
    fn cross_platform_determinism_canary() {
        let shared_secret = [0x42u8; 64];

        let (_scalar, pubkey) = derive_spend_auth_pubkey(&shared_secret).unwrap();
        assert_eq!(
            pubkey,
            [
                0xb6, 0x33, 0x9d, 0x98, 0x87, 0x98, 0xa5, 0x47, 0x11, 0x08, 0x58, 0x35, 0x39, 0x81,
                0xcf, 0x30, 0xda, 0x1d, 0x18, 0xb0, 0x10, 0x75, 0x1b, 0x7e, 0x56, 0x37, 0x74, 0x42,
                0x1a, 0x0f, 0x62, 0xb1,
            ],
            "spend_auth_pubkey diverged — platform determinism broken"
        );

        let hint = derive_view_tag_hint(&shared_secret).unwrap();
        assert_eq!(hint, 0x8e, "view_tag_hint diverged");

        let seed = derive_hybrid_sign_seed(&shared_secret).unwrap();
        assert_eq!(
            &seed[..8],
            &[0x17, 0x13, 0x1b, 0xd4, 0xf3, 0x62, 0xae, 0xa8],
            "hybrid_sign_seed prefix diverged"
        );
    }
}
