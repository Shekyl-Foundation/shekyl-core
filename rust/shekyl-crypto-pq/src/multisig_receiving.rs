//! Per-output multisig receiving derivations (PQC_MULTISIG.md SS7.1–SS8.4).
//!
//! Domain-separated HKDF expansions from each participant's KEM shared secret
//! to derive ephemeral material for multisig outputs. These functions implement
//! the three-label KDF scheme from §7.2 plus the KEM randomness derivation
//! from §7.3.
//!
//! Also implements output construction (§7.1), scanning (§8.1), and receive-time
//! validation (§8.3 / invariant I7).
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
    HybridCiphertext, HybridKemPublicKey, HybridKemSecretKey, HybridX25519MlKem,
    KeyEncapsulation, SharedSecret,
};
use crate::multisig::{
    rotating_prover_index, MultisigKeyContainer, MULTISIG_CONTAINER_VERSION,
    SPEND_AUTH_VERSION_ED25519,
};

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

// ── Output construction (PQC_MULTISIG.md §7.1) ─────────────────────────

/// Result of constructing a multisig output for one recipient.
#[derive(Debug)]
pub struct MultisigOutputConstruction {
    pub output_pubkey: [u8; 32],
    pub kem_ciphertexts: Vec<HybridCiphertext>,
    pub view_tag_hints: Vec<u8>,
    pub spend_auth_pubkeys: Vec<[u8; 32]>,
    pub assigned_prover_index: u8,
    pub key_container: MultisigKeyContainer,
}

/// Construct a multisig output for a sender (§7.1).
///
/// Performs N KEM encapsulations (one per participant), derives per-participant
/// ephemeral material, determines the assigned prover, and builds the
/// `MultisigKeyContainer` with all spend-auth pubkeys.
///
/// `kem_pubkeys`: N participant KEM public keys (in canonical participant order).
/// `hybrid_sign_pubkeys`: populated by this function using per-participant KEM derivation.
#[allow(clippy::too_many_arguments)]
pub fn construct_multisig_output_for_sender(
    n_total: u8,
    m_required: u8,
    kem_pubkeys: &[HybridKemPublicKey],
    group_id: &[u8; 32],
    output_index_in_tx: u64,
    tx_secret_key_hash: &[u8; 32],
    reference_block_hash: &[u8; 32],
) -> Result<MultisigOutputConstruction, CryptoError> {
    if kem_pubkeys.len() != n_total as usize {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    if n_total == 0 || m_required == 0 || m_required > n_total || n_total > 7 {
        return Err(CryptoError::InvalidKeyMaterial);
    }

    let kem = HybridX25519MlKem;
    let mut kem_ciphertexts = Vec::with_capacity(n_total as usize);
    let mut shared_secrets = Vec::with_capacity(n_total as usize);
    let mut spend_auth_pubkeys = Vec::with_capacity(n_total as usize);
    let mut view_tag_hints = Vec::with_capacity(n_total as usize);
    let mut hybrid_sign_pks = Vec::with_capacity(n_total as usize);

    for i in 0..n_total as usize {
        let (ss, ct) = kem.encapsulate(&kem_pubkeys[i])?;
        kem_ciphertexts.push(ct);

        let (_, sa_pk) = derive_spend_auth_pubkey(&ss.0)?;
        spend_auth_pubkeys.push(sa_pk);

        let view_tag = derive_view_tag_hint(&ss.0)?;
        view_tag_hints.push(view_tag);

        let hybrid_seed = derive_hybrid_sign_seed(&ss.0)?;
        let ed_seed: [u8; 32] = hybrid_seed[..32].try_into().unwrap();
        let ed_signing = ed25519_dalek::SigningKey::from_bytes(&ed_seed);
        let ml_seed: [u8; 32] = hybrid_seed[32..].try_into().unwrap();
        let (ml_pk, _ml_sk) = crate::derivation::keygen_from_seed(&ml_seed)?;

        let hybrid_pk = crate::signature::HybridPublicKey {
            ed25519: ed_signing.verifying_key().to_bytes(),
            ml_dsa: {
                use fips204::traits::SerDes;
                ml_pk.into_bytes().to_vec()
            },
        };
        hybrid_sign_pks.push(hybrid_pk);

        shared_secrets.push(ss);
    }

    let assigned_prover = rotating_prover_index(
        group_id,
        output_index_in_tx,
        tx_secret_key_hash,
        reference_block_hash,
        n_total,
    );

    let output_pubkey = spend_auth_pubkeys[assigned_prover as usize];

    let key_container = MultisigKeyContainer {
        version: MULTISIG_CONTAINER_VERSION,
        n_total,
        m_required,
        keys: hybrid_sign_pks,
        spend_auth_pubkeys: spend_auth_pubkeys.clone(),
    };

    Ok(MultisigOutputConstruction {
        output_pubkey,
        kem_ciphertexts,
        view_tag_hints,
        spend_auth_pubkeys,
        assigned_prover_index: assigned_prover,
        key_container,
    })
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

// ── Receive-time validation (PQC_MULTISIG.md §8.3, invariant I7) ───────

/// Validate a multisig output at receive time (invariant I7).
///
/// Checks:
/// 1. My own published spend-auth pubkey matches my derivation from the shared secret.
/// 2. The output pubkey `O` matches `spend_auth_pubkeys[rotating_prover_index(...)]`.
///
/// Returns `true` if valid, `false` if griefing/buggy sender detected.
#[allow(clippy::too_many_arguments)]
pub fn validate_multisig_output_at_receive(
    my_shared_secret: &SharedSecret,
    my_participant_index: u8,
    published_spend_auth_pubkeys: &[[u8; 32]],
    output_pubkey: &[u8; 32],
    group_id: &[u8; 32],
    output_index_in_tx: u64,
    tx_secret_key_hash: &[u8; 32],
    reference_block_hash: &[u8; 32],
    n_total: u8,
) -> Result<bool, CryptoError> {
    if my_participant_index as usize >= published_spend_auth_pubkeys.len() {
        return Ok(false);
    }

    let (_, my_computed_pk) = derive_spend_auth_pubkey(&my_shared_secret.0)?;
    if published_spend_auth_pubkeys[my_participant_index as usize] != my_computed_pk {
        return Ok(false);
    }

    let assigned = rotating_prover_index(
        group_id,
        output_index_in_tx,
        tx_secret_key_hash,
        reference_block_hash,
        n_total,
    );

    if assigned as usize >= published_spend_auth_pubkeys.len() {
        return Ok(false);
    }

    if output_pubkey != &published_spend_auth_pubkeys[assigned as usize] {
        return Ok(false);
    }

    Ok(true)
}

// ── Persistence struct (PQC_MULTISIG.md §8.4) ──────────────────────────

/// Per-output persisted multisig state for wallet storage.
#[derive(Clone)]
pub struct PersistedMultisigOutput {
    pub output_id: [u8; 32],
    pub global_output_index: u64,
    pub my_participant_index: u8,
    pub my_shared_secret: [u8; 64],
    pub spend_auth_version: u8,
    pub spend_auth_pubkeys: Vec<[u8; 32]>,
    pub output_pubkey: [u8; 32],
    pub commitment: [u8; 32],
    pub amount: u64,
    pub reference_block_hash: [u8; 32],
    pub output_index_in_tx: u64,
    pub tx_secret_key_hash: [u8; 32],
    pub assigned_prover_index: u8,
    pub received_at_height: u64,
    pub eligible_height: u64,
}

impl std::fmt::Debug for PersistedMultisigOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistedMultisigOutput")
            .field("output_id", &format_args!("{:02x?}", &self.output_id[..4]))
            .field("global_output_index", &self.global_output_index)
            .field("my_participant_index", &self.my_participant_index)
            .field("my_shared_secret", &"[REDACTED]")
            .field("spend_auth_version", &self.spend_auth_version)
            .field("output_pubkey", &format_args!("{:02x?}", &self.output_pubkey[..4]))
            .field("amount", &self.amount)
            .field("assigned_prover_index", &self.assigned_prover_index)
            .field("received_at_height", &self.received_at_height)
            .field("eligible_height", &self.eligible_height)
            .finish()
    }
}

// ── Griefing defense (PQC_MULTISIG.md §7.6) ────────────────────────────

/// Per-sender griefing tracker for scan-time filtering.
///
/// Maintains a rolling 24-hour window of failed-validation counts per sender.
/// See spec §7.6 for thresholds and cooldown periods.
#[derive(Debug, Clone)]
pub struct GriefingTracker {
    pub sender_id: [u8; 32],
    pub failure_count_24h: u32,
    pub window_start_height: u64,
    pub cooldown_until_height: Option<u64>,
}

impl GriefingTracker {
    /// Check if this sender is currently in cooldown.
    pub fn is_in_cooldown(&self, current_height: u64) -> bool {
        self.cooldown_until_height
            .map_or(false, |h| current_height < h)
    }

    /// Register a validation failure and update cooldown state.
    pub fn register_failure(&mut self, current_height: u64) {
        self.failure_count_24h = self.failure_count_24h.saturating_add(1);

        const BLOCKS_PER_DAY: u64 = 720;
        const COOLDOWN_BLOCKS: u64 = 720 * 7;

        if current_height > self.window_start_height + BLOCKS_PER_DAY {
            self.failure_count_24h = 1;
            self.window_start_height = current_height;
        }

        if self.failure_count_24h >= 100 {
            self.cooldown_until_height = Some(current_height + COOLDOWN_BLOCKS);
        }
    }
}

/// Maximum number of garbage (failed-validation) entries to retain per wallet.
pub const MAX_GARBAGE_ENTRIES: usize = 10_000;

/// Default garbage purge interval in blocks.
pub const GARBAGE_PURGE_INTERVAL_BLOCKS: u64 = 10_000;

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

    // -- Construction + scan round-trip tests --

    #[test]
    fn construct_and_scan_round_trip_2_of_3() {
        use crate::kem::{HybridX25519MlKem, KeyEncapsulation};

        let kem = HybridX25519MlKem;
        let mut kem_pks = Vec::new();
        let mut kem_sks = Vec::new();
        for _ in 0..3 {
            let (pk, sk) = kem.keypair_generate().unwrap();
            kem_pks.push(pk);
            kem_sks.push(sk);
        }

        let group_id = [0xAB; 32];
        let tx_sk_hash = [0xCD; 32];
        let ref_block = [0xEF; 32];

        let construction = construct_multisig_output_for_sender(
            3, 2, &kem_pks, &group_id, 0, &tx_sk_hash, &ref_block,
        )
        .unwrap();

        assert_eq!(construction.kem_ciphertexts.len(), 3);
        assert_eq!(construction.view_tag_hints.len(), 3);
        assert_eq!(construction.spend_auth_pubkeys.len(), 3);
        assert!(construction.assigned_prover_index < 3);

        assert_eq!(
            construction.output_pubkey,
            construction.spend_auth_pubkeys[construction.assigned_prover_index as usize]
        );

        construction.key_container.validate().unwrap();

        for i in 0..3u8 {
            let scanned = scan_multisig_output_for_participant(
                i,
                &kem_sks[i as usize],
                &construction.kem_ciphertexts[i as usize],
                construction.view_tag_hints[i as usize],
                SPEND_AUTH_VERSION_ED25519,
            )
            .unwrap();

            assert!(
                scanned.is_some(),
                "participant {i} should successfully scan"
            );

            let scanned = scanned.unwrap();
            assert_eq!(scanned.my_participant_index, i);

            let valid = validate_multisig_output_at_receive(
                &scanned.shared_secret,
                i,
                &construction.spend_auth_pubkeys,
                &construction.output_pubkey,
                &group_id,
                0,
                &tx_sk_hash,
                &ref_block,
                3,
            )
            .unwrap();

            assert!(valid, "participant {i} receive-time validation must pass");
        }
    }

    #[test]
    fn scan_wrong_participant_ciphertext_fails() {
        use crate::kem::{HybridX25519MlKem, KeyEncapsulation};

        let kem = HybridX25519MlKem;
        let (pk0, _sk0) = kem.keypair_generate().unwrap();
        let (pk1, sk1) = kem.keypair_generate().unwrap();
        let (pk2, _sk2) = kem.keypair_generate().unwrap();

        let construction = construct_multisig_output_for_sender(
            3,
            2,
            &[pk0, pk1, pk2],
            &[0; 32],
            0,
            &[0; 32],
            &[0; 32],
        )
        .unwrap();

        let result = scan_multisig_output_for_participant(
            1,
            &sk1,
            &construction.kem_ciphertexts[0], // wrong ciphertext (belongs to participant 0)
            construction.view_tag_hints[1],
            SPEND_AUTH_VERSION_ED25519,
        )
        .unwrap();

        assert!(
            result.is_none(),
            "scanning with wrong ciphertext should fail hint check"
        );
    }

    #[test]
    fn validate_rejects_wrong_output_pubkey() {
        use crate::kem::{HybridX25519MlKem, KeyEncapsulation};

        let kem = HybridX25519MlKem;
        let mut kem_pks = Vec::new();
        let mut kem_sks = Vec::new();
        for _ in 0..2 {
            let (pk, sk) = kem.keypair_generate().unwrap();
            kem_pks.push(pk);
            kem_sks.push(sk);
        }

        let group_id = [0xAB; 32];
        let tx_sk_hash = [0xCD; 32];
        let ref_block = [0xEF; 32];

        let construction = construct_multisig_output_for_sender(
            2, 2, &kem_pks, &group_id, 0, &tx_sk_hash, &ref_block,
        )
        .unwrap();

        let scanned = scan_multisig_output_for_participant(
            0,
            &kem_sks[0],
            &construction.kem_ciphertexts[0],
            construction.view_tag_hints[0],
            SPEND_AUTH_VERSION_ED25519,
        )
        .unwrap()
        .unwrap();

        let wrong_pubkey = [0xFF; 32];
        let valid = validate_multisig_output_at_receive(
            &scanned.shared_secret,
            0,
            &construction.spend_auth_pubkeys,
            &wrong_pubkey,
            &group_id,
            0,
            &tx_sk_hash,
            &ref_block,
            2,
        )
        .unwrap();

        assert!(!valid, "wrong output pubkey must fail validation");
    }

    #[test]
    fn scan_rejects_unknown_spend_auth_version() {
        use crate::kem::{HybridX25519MlKem, KeyEncapsulation};

        let kem = HybridX25519MlKem;
        let (_pk, sk) = kem.keypair_generate().unwrap();
        let ct = HybridCiphertext {
            x25519: [0; 32],
            ml_kem: vec![0; 1088],
        };

        let result =
            scan_multisig_output_for_participant(0, &sk, &ct, 0, 0xFF).unwrap();

        assert!(
            result.is_none(),
            "unknown spend_auth_version should be silently skipped"
        );
    }

    // -- Griefing tracker tests --

    #[test]
    fn griefing_tracker_cooldown_after_100_failures() {
        let mut tracker = GriefingTracker {
            sender_id: [0; 32],
            failure_count_24h: 0,
            window_start_height: 1000,
            cooldown_until_height: None,
        };

        for _ in 0..99 {
            tracker.register_failure(1050);
            assert!(!tracker.is_in_cooldown(1050));
        }

        tracker.register_failure(1050);
        assert!(tracker.is_in_cooldown(1050));
        assert!(!tracker.is_in_cooldown(1050 + 720 * 7));
    }

    /// Cross-platform determinism canary (catches endian bugs, HashMap
    /// iteration, float contamination).  Fixed inputs -> pinned expected
    /// bytes.  Must produce identical output on Linux x86_64 and macOS
    /// ARM64.  If this test fails on any platform, something broke the
    /// canonical derivation path.
    #[test]
    fn cross_platform_determinism_canary() {
        use crate::multisig::rotating_prover_index;

        let shared_secret = [0x42u8; 64];

        let (_scalar, pubkey) = derive_spend_auth_pubkey(&shared_secret).unwrap();
        assert_eq!(
            pubkey,
            [
                0xb6, 0x33, 0x9d, 0x98, 0x87, 0x98, 0xa5, 0x47, 0x11, 0x08, 0x58,
                0x35, 0x39, 0x81, 0xcf, 0x30, 0xda, 0x1d, 0x18, 0xb0, 0x10, 0x75,
                0x1b, 0x7e, 0x56, 0x37, 0x74, 0x42, 0x1a, 0x0f, 0x62, 0xb1,
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

        let prover = rotating_prover_index(
            &[0xAA; 32], 7, &[0xBB; 32], &[0xCC; 32], 3,
        );
        assert_eq!(prover, 0, "rotating_prover_index diverged");
    }

    #[test]
    fn griefing_tracker_window_reset() {
        let mut tracker = GriefingTracker {
            sender_id: [0; 32],
            failure_count_24h: 50,
            window_start_height: 1000,
            cooldown_until_height: None,
        };

        tracker.register_failure(1000 + 721);
        assert_eq!(tracker.failure_count_24h, 1);
        assert_eq!(tracker.window_start_height, 1000 + 721);
    }
}
