//! Hybrid signature scheme: Ed25519 + ML-DSA (CRYSTALS-Dilithium).
//!
//! During the post-quantum transition, both signatures must verify for a
//! transaction to be considered valid. This provides security against both
//! classical and quantum adversaries.

use crate::CryptoError;
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey,
    PUBLIC_KEY_LENGTH as ED25519_PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH as ED25519_SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH as ED25519_SIGNATURE_LENGTH,
};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes as _, Signer as _, Verifier as _};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const HYBRID_KEY_VERSION: u8 = 1;
/// Signature layout version. **2** = the nested combiner (SA-R-1): PQ-inner /
/// Ed25519-outer over a domain-separated preimage. **1** was the legacy
/// weakly-separable *parallel* construction (both halves signed the bare
/// message). The bump is the security boundary of the round: the wire length
/// does not move, so this byte is the only thing distinguishing an old
/// parallel signature from a new nested one, and [`HybridSignature::from_canonical_bytes`]
/// **rejects any version but this** — a v1 signature is refused at parse,
/// before the combiner runs (SA-R-4). Every production verify path decodes
/// through `from_canonical_bytes` (enumerated in `SIGNATURE_ALIGNMENT.md`), so
/// the parse-time gate is uniform; the nested construction additionally
/// rejects a v1 signature cryptographically (its `σ_pq` signed the bare
/// message, not the domained preimage), so there is no in-memory bypass.
/// `HYBRID_KEY_VERSION` stays 1 — the *key* format is unchanged.
pub const HYBRID_SIG_VERSION: u8 = 2;
pub const HYBRID_SCHEME_ID_ED25519_ML_DSA_65: u8 = 1;

/// Scheme-level domain-separation strings (SA-R-2): one distinct string per
/// signing **surface**. Each is the outer domain of the nested combiner — a
/// separate layer from any inner cSHAKE customization the caller already
/// applies to build `message`, and it gets its own string rather than reusing
/// the inner one (a shared string across two layers would create a standing
/// cross-parse proof obligation for no benefit). `sign`/`verify` take the
/// domain as a required parameter so a caller cannot sign a bare message; the
/// FFI exports apply the surface's constant internally so C++ never carries a
/// domain string it could get wrong.
pub const SCHEME_DOMAIN_PQC_AUTH_TX: &[u8] = b"shekyl/pqc-auth-tx-v1";
/// Multisig participant auth (scheme 2), **distinct** from single-sig
/// [`SCHEME_DOMAIN_PQC_AUTH_TX`] (SA-R-5). A multisig participant and a
/// single-signer both produce a `HybridEd25519MlDsa` signature, and the
/// preimage binds only the *hybrid* scheme id (constant 1) — so over the same
/// raw message the two signatures would be byte-identical without a separate
/// domain. The consensus tx path additionally distinguishes them structurally
/// (`PqcAuth::header_write` writes the container scheme_id 1 vs 2 into the
/// signed payload), but that is a caller-side property of the tx builder; the
/// scheme owns its separation here so a signature made in one context cannot be
/// reused in the other even for a caller that passes a bare payload to
/// `verify_multisig`. `verify_multisig` and the (test-support) participant
/// signer both use this constant; production multisig signing is unbuilt.
pub const SCHEME_DOMAIN_PQC_AUTH_TX_MULTISIG: &[u8] = b"shekyl/pqc-auth-tx-multisig-v1";
/// Emission claim-role auth (surface C).
pub const SCHEME_DOMAIN_EMISSION_CLAIM: &[u8] = b"shekyl/archival-emission-claim-scheme-v1";
/// Emission backing-role auth (surface D).
pub const SCHEME_DOMAIN_EMISSION_BACKING: &[u8] = b"shekyl/archival-emission-backing-scheme-v1";
/// Attestation pass countersignature (surface E).
pub const SCHEME_DOMAIN_ATTESTATION: &[u8] = b"shekyl/archival-attestation-scheme-v1";
/// Serve-credit response (surface F).
pub const SCHEME_DOMAIN_SERVE_CREDIT: &[u8] = b"shekyl/archival-serve-credit-scheme-v1";
/// Bond-post vin (surface B) — **parked pending the §2.2 bond-preimage
/// reconciliation round** (rule-21 reopen). The discarded S1 signer
/// (`shekyl-archival-bond-builder`) passes this so it compiles under the
/// mandatory-domain trait; whether it is deleted (generic wins) or activated
/// (design-aligned wins) is that round's decision. Not consumed by any
/// production verifier today — the bond vin's on-chain auth rides
/// [`SCHEME_DOMAIN_PQC_AUTH_TX`] as an ordinary surface-A slot.
pub const SCHEME_DOMAIN_BOND_POST: &[u8] = b"shekyl/archival-bond-post-scheme-v1";
pub const ML_DSA_65_PUBLIC_KEY_LENGTH: usize = ml_dsa_65::PK_LEN;
pub const ML_DSA_65_SECRET_KEY_LENGTH: usize = ml_dsa_65::SK_LEN;
pub const ML_DSA_65_SIGNATURE_LENGTH: usize = ml_dsa_65::SIG_LEN;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridPublicKey {
    pub ed25519: [u8; 32],
    pub ml_dsa: Vec<u8>,
}

// `ZeroizeOnDrop` is the rule-35 canonical wipe-on-drop idiom; it replaces
// the deprecated `#[zeroize(drop)]` attribute with identical behavior.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSecretKey {
    pub ed25519: Vec<u8>,
    pub ml_dsa: Vec<u8>,
}

impl std::fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridSecretKey")
            .field("ed25519", &"[REDACTED]")
            .field("ml_dsa", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    pub ed25519: Vec<u8>,
    pub ml_dsa: Vec<u8>,
}

impl HybridPublicKey {
    /// Canonical wire length, defined once here where the encoding lives:
    /// `version(1) || scheme(1) || reserved(2) || ed_len(4) || ed(32) ||
    /// ml_len(4) || ml(1952)` = 1996. `from_canonical_bytes` is authoritative
    /// (it rejects any other total via `cursor != bytes.len()`); this const is
    /// the value the container layer (`multisig.rs`) and its DoS ceilings
    /// derive from, so the length is never written twice.
    pub const CANONICAL_LEN: usize =
        1 + 1 + 2 + 4 + ED25519_PUBLIC_KEY_LENGTH + 4 + ML_DSA_65_PUBLIC_KEY_LENGTH;

    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.ml_dsa.len() != ML_DSA_65_PUBLIC_KEY_LENGTH {
            return Err(CryptoError::InvalidKeyMaterial);
        }
        Ok(())
    }

    // CLIPPY: lengths validated by `self.validate()` against constants that fit in u32.
    #[allow(clippy::cast_possible_truncation)]
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        self.validate()?;

        let mut out =
            Vec::with_capacity(1 + 1 + 2 + 4 + self.ed25519.len() + 4 + self.ml_dsa.len());
        out.push(HYBRID_KEY_VERSION);
        out.push(HYBRID_SCHEME_ID_ED25519_ML_DSA_65);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(self.ed25519.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ed25519);
        out.extend_from_slice(&(self.ml_dsa.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ml_dsa);
        Ok(out)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut cursor = 0usize;
        let version = read_u8(bytes, &mut cursor)?;
        let scheme = read_u8(bytes, &mut cursor)?;
        let reserved = read_u16(bytes, &mut cursor)?;
        let ed_len = read_u32(bytes, &mut cursor)? as usize;
        let ed_bytes = read_vec(bytes, &mut cursor, ed_len)?;
        let ml_len = read_u32(bytes, &mut cursor)? as usize;
        let ml_dsa = read_vec(bytes, &mut cursor, ml_len)?;

        if cursor != bytes.len()
            || version != HYBRID_KEY_VERSION
            || scheme != HYBRID_SCHEME_ID_ED25519_ML_DSA_65
            || reserved != 0
            || ed_len != ED25519_PUBLIC_KEY_LENGTH
            || ml_len != ML_DSA_65_PUBLIC_KEY_LENGTH
        {
            return Err(CryptoError::SerializationError(
                "invalid canonical hybrid public key".into(),
            ));
        }

        let ed25519: [u8; ED25519_PUBLIC_KEY_LENGTH] = ed_bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        let public_key = Self { ed25519, ml_dsa };
        public_key.validate()?;
        Ok(public_key)
    }
}

impl HybridSecretKey {
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.ed25519.len() != ED25519_SECRET_KEY_LENGTH
            || self.ml_dsa.len() != ML_DSA_65_SECRET_KEY_LENGTH
        {
            return Err(CryptoError::InvalidKeyMaterial);
        }
        Ok(())
    }

    // CLIPPY: lengths validated by `self.validate()` against constants that fit in u32.
    #[allow(clippy::cast_possible_truncation)]
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        self.validate()?;

        let mut out =
            Vec::with_capacity(1 + 1 + 2 + 4 + self.ed25519.len() + 4 + self.ml_dsa.len());
        out.push(HYBRID_KEY_VERSION);
        out.push(HYBRID_SCHEME_ID_ED25519_ML_DSA_65);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(self.ed25519.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ed25519);
        out.extend_from_slice(&(self.ml_dsa.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ml_dsa);
        Ok(out)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut cursor = 0usize;
        let version = read_u8(bytes, &mut cursor)?;
        let scheme = read_u8(bytes, &mut cursor)?;
        let reserved = read_u16(bytes, &mut cursor)?;
        let ed_len = read_u32(bytes, &mut cursor)? as usize;
        let ed25519 = read_vec(bytes, &mut cursor, ed_len)?;
        let ml_len = read_u32(bytes, &mut cursor)? as usize;
        let ml_dsa = read_vec(bytes, &mut cursor, ml_len)?;

        if cursor != bytes.len()
            || version != HYBRID_KEY_VERSION
            || scheme != HYBRID_SCHEME_ID_ED25519_ML_DSA_65
            || reserved != 0
            || ed_len != ED25519_SECRET_KEY_LENGTH
            || ml_len != ML_DSA_65_SECRET_KEY_LENGTH
        {
            return Err(CryptoError::SerializationError(
                "invalid canonical hybrid secret key".into(),
            ));
        }

        let secret_key = Self { ed25519, ml_dsa };
        secret_key.validate()?;
        Ok(secret_key)
    }
}

impl HybridSignature {
    /// Canonical wire length, defined once here (same layout as
    /// `HybridPublicKey::CANONICAL_LEN`, sig-sized) = 3385. The container
    /// layer and its DoS ceilings derive from this const.
    pub const CANONICAL_LEN: usize =
        1 + 1 + 2 + 4 + ED25519_SIGNATURE_LENGTH + 4 + ML_DSA_65_SIGNATURE_LENGTH;

    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.ed25519.len() != ED25519_SIGNATURE_LENGTH
            || self.ml_dsa.len() != ML_DSA_65_SIGNATURE_LENGTH
        {
            return Err(CryptoError::SerializationError(
                "invalid hybrid signature length".into(),
            ));
        }
        Ok(())
    }

    // CLIPPY: lengths validated by `self.validate()` against constants that fit in u32.
    #[allow(clippy::cast_possible_truncation)]
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        self.validate()?;

        let mut out =
            Vec::with_capacity(1 + 1 + 2 + 4 + self.ed25519.len() + 4 + self.ml_dsa.len());
        out.push(HYBRID_SIG_VERSION);
        out.push(HYBRID_SCHEME_ID_ED25519_ML_DSA_65);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(self.ed25519.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ed25519);
        out.extend_from_slice(&(self.ml_dsa.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ml_dsa);
        Ok(out)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut cursor = 0usize;
        let version = read_u8(bytes, &mut cursor)?;
        let scheme = read_u8(bytes, &mut cursor)?;
        let reserved = read_u16(bytes, &mut cursor)?;
        let ed_len = read_u32(bytes, &mut cursor)? as usize;
        let ed25519 = read_vec(bytes, &mut cursor, ed_len)?;
        let ml_len = read_u32(bytes, &mut cursor)? as usize;
        let ml_dsa = read_vec(bytes, &mut cursor, ml_len)?;

        if cursor != bytes.len()
            || version != HYBRID_SIG_VERSION
            || scheme != HYBRID_SCHEME_ID_ED25519_ML_DSA_65
            || reserved != 0
            || ed_len != ED25519_SIGNATURE_LENGTH
            || ml_len != ML_DSA_65_SIGNATURE_LENGTH
        {
            return Err(CryptoError::SerializationError(
                "invalid canonical hybrid signature".into(),
            ));
        }

        let signature = Self { ed25519, ml_dsa };
        signature.validate()?;
        Ok(signature)
    }
}

pub trait SignatureScheme {
    /// Sign `message` under scheme-level `domain` (SA-R-2). The domain is a
    /// required parameter — there is no bare-message signing path — and it is
    /// the outer domain of the nested combiner, distinct from any inner
    /// customization the caller applied to build `message`.
    fn sign(
        &self,
        secret_key: &HybridSecretKey,
        domain: &[u8],
        message: &[u8],
    ) -> Result<HybridSignature, CryptoError>;
    /// Verify a signature, returning `Ok(())` on success and `Err` on any
    /// failure — malformed inputs, a failed component, or a wrong signature.
    ///
    /// The return is `Result<()>`, **not** `Result<bool>` (SA-R-1): there is no
    /// `Ok(false)` for a caller to mishandle, so the accepts-invalid shape a
    /// `.is_err()`-gated caller once produced is unrepresentable. Fails closed.
    /// Do not restore a boolean return.
    fn verify(
        &self,
        public_key: &HybridPublicKey,
        domain: &[u8],
        message: &[u8],
        signature: &HybridSignature,
    ) -> Result<(), CryptoError>;
}

pub struct HybridEd25519MlDsa;

impl HybridEd25519MlDsa {
    /// The scheme's domain-separated inner preimage (SA-R-1 / SA-R-5):
    /// `cSHAKE256(customization = domain, input = scheme_id ‖ message)`.
    ///
    /// Binding the scheme id in the signed bytes closes the cross-scheme
    /// confusion the round found (a signature's input no longer depends only
    /// on the message); the `domain` customization separates surfaces. The PQ
    /// half signs this digest; the classical half signs `digest ‖ σ_pq`.
    fn preimage(domain: &[u8], message: &[u8]) -> [u8; 32] {
        let mut framed = Vec::with_capacity(1 + message.len());
        framed.push(HYBRID_SCHEME_ID_ED25519_ML_DSA_65);
        framed.extend_from_slice(message);
        shekyl_crypto_hash::cshake256_32(domain, &framed)
    }
}

// `keypair_generate` is test-support only (F-7): the old trait method read as a
// production API and risked a non-derived keypair reaching a wallet. Renamed so
// the name announces itself and gated so it cannot be called from production.
#[cfg(any(test, feature = "test-utils"))]
impl HybridEd25519MlDsa {
    pub fn generate_ephemeral_keypair_for_tests(
        &self,
    ) -> Result<(HybridPublicKey, HybridSecretKey), CryptoError> {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        let (ml_dsa_public, ml_dsa_secret) =
            ml_dsa_65::try_keygen().map_err(|e| CryptoError::KeyGenerationFailed(e.into()))?;

        let public_key = HybridPublicKey {
            ed25519: verifying_key.to_bytes(),
            ml_dsa: ml_dsa_public.into_bytes().to_vec(),
        };
        let secret_key = HybridSecretKey {
            ed25519: signing_key.to_bytes().to_vec(),
            ml_dsa: ml_dsa_secret.into_bytes().to_vec(),
        };

        Ok((public_key, secret_key))
    }

    /// Deterministic nested sign for iai benches / KATs. Identical to
    /// [`SignatureScheme::sign`] — same `preimage`, same nesting order — except
    /// the ML-DSA half uses a fixed `ml_dsa_seed` (stable instruction count for
    /// iai) instead of the hedged `OsRng` path. Single-sourced through
    /// `preimage`, so a bench measures the real combiner, never a hand-rolled
    /// shim that could drift from production.
    pub fn sign_with_ml_dsa_seed(
        &self,
        secret_key: &HybridSecretKey,
        domain: &[u8],
        message: &[u8],
        ml_dsa_seed: &[u8; 32],
    ) -> Result<HybridSignature, CryptoError> {
        secret_key.validate()?;
        let ed25519_secret: Zeroizing<[u8; ED25519_SECRET_KEY_LENGTH]> = Zeroizing::new(
            secret_key
                .ed25519
                .clone()
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyMaterial)?,
        );
        let ml_dsa_secret: Zeroizing<[u8; ML_DSA_65_SECRET_KEY_LENGTH]> = Zeroizing::new(
            secret_key
                .ml_dsa
                .clone()
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyMaterial)?,
        );
        let signing_key = SigningKey::from_bytes(&ed25519_secret);
        let ml_dsa_private = ml_dsa_65::PrivateKey::try_from_bytes(*ml_dsa_secret)
            .map_err(|e| CryptoError::SerializationError(e.into()))?;
        let inner = Self::preimage(domain, message);
        let ml_dsa_signature = ml_dsa_private
            .try_sign_with_seed(ml_dsa_seed, &inner, &[])
            .map_err(|e| CryptoError::SerializationError(e.into()))?;
        let mut outer = Vec::with_capacity(inner.len() + ml_dsa_signature.len());
        outer.extend_from_slice(&inner);
        outer.extend_from_slice(&ml_dsa_signature);
        let ed25519_signature = signing_key.sign(&outer);
        Ok(HybridSignature {
            ed25519: ed25519_signature.to_bytes().to_vec(),
            ml_dsa: ml_dsa_signature.to_vec(),
        })
    }
}

impl SignatureScheme for HybridEd25519MlDsa {
    fn sign(
        &self,
        secret_key: &HybridSecretKey,
        domain: &[u8],
        message: &[u8],
    ) -> Result<HybridSignature, CryptoError> {
        secret_key.validate()?;

        let ed25519_secret: Zeroizing<[u8; ED25519_SECRET_KEY_LENGTH]> = Zeroizing::new(
            secret_key
                .ed25519
                .clone()
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyMaterial)?,
        );
        let ml_dsa_secret: Zeroizing<[u8; ML_DSA_65_SECRET_KEY_LENGTH]> = Zeroizing::new(
            secret_key
                .ml_dsa
                .clone()
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyMaterial)?,
        );

        let signing_key = SigningKey::from_bytes(&ed25519_secret);
        let ml_dsa_private = ml_dsa_65::PrivateKey::try_from_bytes(*ml_dsa_secret)
            .map_err(|e| CryptoError::SerializationError(e.into()))?;

        // Nested combiner (SA-R-1): PQ-inner, Ed25519-outer.
        let inner = Self::preimage(domain, message);
        // PQ half signs the domained digest, empty ML-DSA ctx (SA-R-3, KAT-pinned).
        let ml_dsa_signature = ml_dsa_private
            .try_sign(&inner, &[])
            .map_err(|e| CryptoError::SerializationError(e.into()))?;
        // Classical half signs `inner ‖ σ_pq`. A verifier that skips the PQ
        // half cannot reconstruct this outer message, so a degenerate
        // implementation fails to verify rather than verifying insecurely
        // (fails-closed). The nesting order is load-bearing — do not flip it.
        let mut outer = Vec::with_capacity(inner.len() + ml_dsa_signature.len());
        outer.extend_from_slice(&inner);
        outer.extend_from_slice(&ml_dsa_signature);
        let ed25519_signature = signing_key.sign(&outer);

        Ok(HybridSignature {
            ed25519: ed25519_signature.to_bytes().to_vec(),
            ml_dsa: ml_dsa_signature.to_vec(),
        })
    }

    fn verify(
        &self,
        public_key: &HybridPublicKey,
        domain: &[u8],
        message: &[u8],
        signature: &HybridSignature,
    ) -> Result<(), CryptoError> {
        public_key.validate()?;
        signature.validate()?;

        let ed25519_verifying_key = VerifyingKey::from_bytes(&public_key.ed25519)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        let ed25519_signature = Ed25519Signature::try_from(signature.ed25519.as_slice())
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;

        let ml_dsa_public: [u8; ML_DSA_65_PUBLIC_KEY_LENGTH] = public_key
            .ml_dsa
            .clone()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        let ml_dsa_signature: [u8; ML_DSA_65_SIGNATURE_LENGTH] = signature
            .ml_dsa
            .clone()
            .try_into()
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;

        let ml_dsa_public_key = ml_dsa_65::PublicKey::try_from_bytes(ml_dsa_public)
            .map_err(|e| CryptoError::SerializationError(e.into()))?;

        let inner = Self::preimage(domain, message);
        // Verify the PQ inner first (fails-closed order): the classical outer
        // is meaningless if the PQ half it wraps is not itself valid.
        if !ml_dsa_public_key.verify(&inner, &ml_dsa_signature, &[]) {
            return Err(CryptoError::SignatureVerificationFailed);
        }
        let mut outer = Vec::with_capacity(inner.len() + ml_dsa_signature.len());
        outer.extend_from_slice(&inner);
        outer.extend_from_slice(&ml_dsa_signature);
        ed25519_verifying_key
            .verify(&outer, &ed25519_signature)
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;
        Ok(())
    }
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, CryptoError> {
    if *cursor + 1 > bytes.len() {
        return Err(CryptoError::SerializationError(
            "truncated canonical encoding".into(),
        ));
    }
    let v = bytes[*cursor];
    *cursor += 1;
    Ok(v)
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, CryptoError> {
    if *cursor + 2 > bytes.len() {
        return Err(CryptoError::SerializationError(
            "truncated canonical encoding".into(),
        ));
    }
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&bytes[*cursor..*cursor + 2]);
    *cursor += 2;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, CryptoError> {
    if *cursor + 4 > bytes.len() {
        return Err(CryptoError::SerializationError(
            "truncated canonical encoding".into(),
        ));
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[*cursor..*cursor + 4]);
    *cursor += 4;
    Ok(u32::from_le_bytes(buf))
}

fn read_vec(bytes: &[u8], cursor: &mut usize, len: usize) -> Result<Vec<u8>, CryptoError> {
    if *cursor + len > bytes.len() {
        return Err(CryptoError::SerializationError(
            "truncated canonical encoding".into(),
        ));
    }
    let out = bytes[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn scheme() -> HybridEd25519MlDsa {
        HybridEd25519MlDsa
    }

    /// A real surface domain, used for the round-trip tests.
    const D: &[u8] = SCHEME_DOMAIN_PQC_AUTH_TX;

    fn kp() -> (HybridPublicKey, HybridSecretKey) {
        scheme().generate_ephemeral_keypair_for_tests().unwrap()
    }

    #[allow(clippy::cast_possible_truncation)]
    fn from_hex(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0, "hex string must have even length");
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        for i in (0..bytes.len()).step_by(2) {
            let hi = (bytes[i] as char).to_digit(16).expect("invalid hex") as u8;
            let lo = (bytes[i + 1] as char).to_digit(16).expect("invalid hex") as u8;
            out.push((hi << 4) | lo);
        }
        out
    }

    #[test]
    fn keygen_sign_verify_roundtrip() {
        let scheme = scheme();
        let (pk, sk) = kp();
        let msg = b"shekyl hybrid pq signature test";
        let sig = scheme.sign(&sk, D, msg).unwrap();
        scheme.verify(&pk, D, msg, &sig).unwrap();
    }

    /// SA-R-4 frozen v1 negative control (never regenerated).
    /// `PQC_TEST_VECTOR_001.json` pins a **v1 parallel** signature from the
    /// pre-SA-2 construction. After the version bump, `from_canonical_bytes`
    /// must **reject** it at parse (version byte 1 ≠ `HYBRID_SIG_VERSION` = 2)
    /// — the security boundary of the round, proven by a signature that once
    /// verified and now cannot even be constructed into a `HybridSignature`.
    #[test]
    fn frozen_v1_vector_is_rejected_at_parse() {
        let raw = include_str!("../../../docs/PQC_TEST_VECTOR_001.json");
        let v: Value = serde_json::from_str(raw).unwrap();
        let signature_bytes = from_hex(v["hybrid_signature_hex"].as_str().unwrap());

        // The pinned bytes are a well-formed v1 encoding — the first byte is 1.
        assert_eq!(signature_bytes[0], 1, "fixture must be a v1 signature");
        assert!(
            HybridSignature::from_canonical_bytes(&signature_bytes).is_err(),
            "a v1 parallel signature must be refused at parse under HYBRID_SIG_VERSION=2"
        );
    }

    #[test]
    fn reject_when_ed25519_component_fails() {
        let scheme = scheme();
        let (pk, sk) = kp();
        let msg = b"shekyl hybrid pq signature test";
        let mut sig = scheme.sign(&sk, D, msg).unwrap();
        sig.ed25519[0] ^= 0x01;
        assert!(scheme.verify(&pk, D, msg, &sig).is_err());
    }

    #[test]
    fn reject_when_ml_dsa_component_fails() {
        let scheme = scheme();
        let (pk, sk) = kp();
        let msg = b"shekyl hybrid pq signature test";
        let mut sig = scheme.sign(&sk, D, msg).unwrap();
        sig.ml_dsa[0] ^= 0x01;
        assert!(scheme.verify(&pk, D, msg, &sig).is_err());
    }

    /// The domain binds: a signature made under one surface domain does not
    /// verify under another (SA-R-2).
    #[test]
    fn domain_binds() {
        let scheme = scheme();
        let (pk, sk) = kp();
        let msg = b"cross-surface message";
        let sig = scheme.sign(&sk, SCHEME_DOMAIN_PQC_AUTH_TX, msg).unwrap();
        assert!(
            scheme
                .verify(&pk, SCHEME_DOMAIN_EMISSION_CLAIM, msg, &sig)
                .is_err(),
            "a signature must not verify under a different surface domain"
        );
    }

    /// The ML-DSA half is signed with an empty context and the empty context
    /// is load-bearing (SA-R-3): the same PQ signature does not verify under a
    /// non-empty ctx, so a future edit that passed a ctx would break
    /// verification loudly rather than silently change the security surface.
    #[test]
    fn ml_dsa_empty_ctx_is_pinned() {
        use fips204::traits::{SerDes as _, Verifier as _};
        let (pk, sk) = kp();
        let msg = b"empty-ctx pin";
        let sig = scheme().sign(&sk, D, msg).unwrap();

        // Recompute the inner preimage the PQ half signed and check the ML-DSA
        // component directly: empty ctx verifies, a non-empty ctx does not.
        let inner = HybridEd25519MlDsa::preimage(D, msg);
        let ml_pk_bytes: [u8; ML_DSA_65_PUBLIC_KEY_LENGTH] = pk.ml_dsa.clone().try_into().unwrap();
        let ml_sig: [u8; ML_DSA_65_SIGNATURE_LENGTH] = sig.ml_dsa.clone().try_into().unwrap();
        let ml_pk = ml_dsa_65::PublicKey::try_from_bytes(ml_pk_bytes).unwrap();
        assert!(
            ml_pk.verify(&inner, &ml_sig, &[]),
            "the PQ half must verify under the pinned empty ctx"
        );
        assert!(
            !ml_pk.verify(&inner, &ml_sig, b"x"),
            "the PQ half must NOT verify under a non-empty ctx — empty ctx is load-bearing"
        );
    }

    /// A v1-style *parallel* signature (both halves over the bare message)
    /// fails v2 nested verification even with the version byte forced to 2 —
    /// the cryptographic backstop behind the parse-time gate. The PQ half
    /// signed the bare message, not `preimage`, so the nested check rejects it.
    #[test]
    fn parallel_signature_fails_nested_verify() {
        use ed25519_dalek::{Signer as _, SigningKey};
        use fips204::traits::{SerDes as _, Signer as _};
        let (pk, sk) = kp();
        let msg = b"parallel forgery attempt";

        // Hand-build the legacy parallel construction: both halves sign `msg`.
        let ed_secret: [u8; ED25519_SECRET_KEY_LENGTH] = sk.ed25519.clone().try_into().unwrap();
        let ml_secret: [u8; ML_DSA_65_SECRET_KEY_LENGTH] = sk.ml_dsa.clone().try_into().unwrap();
        let ed_key = SigningKey::from_bytes(&ed_secret);
        let ml_key = ml_dsa_65::PrivateKey::try_from_bytes(ml_secret).unwrap();
        let parallel = HybridSignature {
            ed25519: ed_key.sign(msg).to_bytes().to_vec(),
            ml_dsa: ml_key.try_sign(msg, &[]).unwrap().to_vec(),
        };
        assert!(
            scheme().verify(&pk, D, msg, &parallel).is_err(),
            "a parallel signature must fail nested verification"
        );
    }

    #[test]
    fn public_key_canonical_roundtrip() {
        let (pk, _) = kp();
        let encoded = pk.to_canonical_bytes().unwrap();
        let decoded = HybridPublicKey::from_canonical_bytes(&encoded).unwrap();
        assert_eq!(pk.ed25519, decoded.ed25519);
        assert_eq!(pk.ml_dsa, decoded.ml_dsa);
    }

    #[test]
    fn signature_canonical_roundtrip() {
        let scheme = scheme();
        let (_, sk) = kp();
        let msg = b"canonical signature roundtrip";
        let sig = scheme.sign(&sk, D, msg).unwrap();
        let encoded = sig.to_canonical_bytes().unwrap();
        let decoded = HybridSignature::from_canonical_bytes(&encoded).unwrap();
        assert_eq!(sig.ed25519, decoded.ed25519);
        assert_eq!(sig.ml_dsa, decoded.ml_dsa);
    }

    #[test]
    fn secret_key_canonical_roundtrip() {
        let (_, sk) = kp();
        let encoded = sk.to_canonical_bytes().unwrap();
        let decoded = HybridSecretKey::from_canonical_bytes(&encoded).unwrap();
        assert_eq!(sk.ed25519, decoded.ed25519);
        assert_eq!(sk.ml_dsa, decoded.ml_dsa);
    }

    #[test]
    fn malformed_public_key_rejected() {
        let (pk, _) = kp();
        let mut encoded = pk.to_canonical_bytes().unwrap();
        encoded[4] = 0; // corrupt encoded ed25519 length field
        assert!(HybridPublicKey::from_canonical_bytes(&encoded).is_err());
    }

    #[test]
    fn malformed_signature_length_rejected() {
        let sig = HybridSignature {
            ed25519: vec![0u8; ED25519_SIGNATURE_LENGTH - 1],
            ml_dsa: vec![0u8; ML_DSA_65_SIGNATURE_LENGTH],
        };
        assert!(sig.validate().is_err());
    }
}
