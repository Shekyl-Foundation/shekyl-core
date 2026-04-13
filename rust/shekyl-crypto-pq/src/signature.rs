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
use zeroize::{Zeroize, Zeroizing};

pub const HYBRID_KEY_VERSION: u8 = 1;
pub const HYBRID_SIG_VERSION: u8 = 1;
pub const HYBRID_SCHEME_ID_ED25519_ML_DSA_65: u8 = 1;
pub const ML_DSA_65_PUBLIC_KEY_LENGTH: usize = ml_dsa_65::PK_LEN;
pub const ML_DSA_65_SECRET_KEY_LENGTH: usize = ml_dsa_65::SK_LEN;
pub const ML_DSA_65_SIGNATURE_LENGTH: usize = ml_dsa_65::SIG_LEN;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridPublicKey {
    pub ed25519: [u8; 32],
    pub ml_dsa: Vec<u8>,
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
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

        let ed25519: [u8; ED25519_PUBLIC_KEY_LENGTH] =
            ed_bytes.try_into().map_err(|_| CryptoError::InvalidKeyMaterial)?;
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
    fn keypair_generate(&self) -> Result<(HybridPublicKey, HybridSecretKey), CryptoError>;
    fn sign(&self, secret_key: &HybridSecretKey, message: &[u8]) -> Result<HybridSignature, CryptoError>;
    fn verify(&self, public_key: &HybridPublicKey, message: &[u8], signature: &HybridSignature) -> Result<bool, CryptoError>;
}

pub struct HybridEd25519MlDsa;

impl SignatureScheme for HybridEd25519MlDsa {
    fn keypair_generate(&self) -> Result<(HybridPublicKey, HybridSecretKey), CryptoError> {
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

    fn sign(&self, secret_key: &HybridSecretKey, message: &[u8]) -> Result<HybridSignature, CryptoError> {
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

        let ed25519_signature = signing_key.sign(message);
        let ml_dsa_signature = ml_dsa_private
            .try_sign(message, &[])
            .map_err(|e| CryptoError::SerializationError(e.into()))?;

        Ok(HybridSignature {
            ed25519: ed25519_signature.to_bytes().to_vec(),
            ml_dsa: ml_dsa_signature.to_vec(),
        })
    }

    fn verify(&self, public_key: &HybridPublicKey, message: &[u8], signature: &HybridSignature) -> Result<bool, CryptoError> {
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

        let ed25519_ok = ed25519_verifying_key
            .verify(message, &ed25519_signature)
            .is_ok();
        let ml_dsa_ok = ml_dsa_public_key.verify(message, &ml_dsa_signature, &[]);

        Ok(ed25519_ok && ml_dsa_ok)
    }
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, CryptoError> {
    if *cursor + 1 > bytes.len() {
        return Err(CryptoError::SerializationError("truncated canonical encoding".into()));
    }
    let v = bytes[*cursor];
    *cursor += 1;
    Ok(v)
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, CryptoError> {
    if *cursor + 2 > bytes.len() {
        return Err(CryptoError::SerializationError("truncated canonical encoding".into()));
    }
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&bytes[*cursor..*cursor + 2]);
    *cursor += 2;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, CryptoError> {
    if *cursor + 4 > bytes.len() {
        return Err(CryptoError::SerializationError("truncated canonical encoding".into()));
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[*cursor..*cursor + 4]);
    *cursor += 4;
    Ok(u32::from_le_bytes(buf))
}

fn read_vec(bytes: &[u8], cursor: &mut usize, len: usize) -> Result<Vec<u8>, CryptoError> {
    if *cursor + len > bytes.len() {
        return Err(CryptoError::SerializationError("truncated canonical encoding".into()));
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
        let (pk, sk) = scheme.keypair_generate().unwrap();
        let msg = b"shekyl hybrid pq signature test";
        let sig = scheme.sign(&sk, msg).unwrap();
        assert!(scheme.verify(&pk, msg, &sig).unwrap());
    }

    #[test]
    fn documented_vector_verifies() {
        let raw = include_str!("../../../docs/PQC_TEST_VECTOR_001.json");
        let v: Value = serde_json::from_str(raw).unwrap();

        let message_hex = v["message_hex"].as_str().unwrap();
        let public_key_hex = v["hybrid_public_key_hex"].as_str().unwrap();
        let signature_hex = v["hybrid_signature_hex"].as_str().unwrap();

        let message = from_hex(message_hex);
        let public_key_bytes = from_hex(public_key_hex);
        let signature_bytes = from_hex(signature_hex);

        assert_eq!(
            public_key_bytes.len(),
            v["hybrid_public_key_len"].as_u64().unwrap() as usize
        );
        assert_eq!(
            signature_bytes.len(),
            v["hybrid_signature_len"].as_u64().unwrap() as usize
        );

        let pk = HybridPublicKey::from_canonical_bytes(&public_key_bytes).unwrap();
        let sig = HybridSignature::from_canonical_bytes(&signature_bytes).unwrap();
        let scheme = scheme();

        assert!(scheme.verify(&pk, &message, &sig).unwrap());

        let mut tampered = message.clone();
        tampered[0] ^= 0x01;
        assert!(!scheme.verify(&pk, &tampered, &sig).unwrap());
    }

    #[test]
    fn reject_when_ed25519_component_fails() {
        let scheme = scheme();
        let (pk, sk) = scheme.keypair_generate().unwrap();
        let msg = b"shekyl hybrid pq signature test";
        let mut sig = scheme.sign(&sk, msg).unwrap();
        sig.ed25519[0] ^= 0x01;
        assert!(!scheme.verify(&pk, msg, &sig).unwrap());
    }

    #[test]
    fn reject_when_ml_dsa_component_fails() {
        let scheme = scheme();
        let (pk, sk) = scheme.keypair_generate().unwrap();
        let msg = b"shekyl hybrid pq signature test";
        let mut sig = scheme.sign(&sk, msg).unwrap();
        sig.ml_dsa[0] ^= 0x01;
        assert!(!scheme.verify(&pk, msg, &sig).unwrap());
    }

    #[test]
    fn public_key_canonical_roundtrip() {
        let scheme = scheme();
        let (pk, _) = scheme.keypair_generate().unwrap();
        let encoded = pk.to_canonical_bytes().unwrap();
        let decoded = HybridPublicKey::from_canonical_bytes(&encoded).unwrap();
        assert_eq!(pk.ed25519, decoded.ed25519);
        assert_eq!(pk.ml_dsa, decoded.ml_dsa);
    }

    #[test]
    fn signature_canonical_roundtrip() {
        let scheme = scheme();
        let (_, sk) = scheme.keypair_generate().unwrap();
        let msg = b"canonical signature roundtrip";
        let sig = scheme.sign(&sk, msg).unwrap();
        let encoded = sig.to_canonical_bytes().unwrap();
        let decoded = HybridSignature::from_canonical_bytes(&encoded).unwrap();
        assert_eq!(sig.ed25519, decoded.ed25519);
        assert_eq!(sig.ml_dsa, decoded.ml_dsa);
    }

    #[test]
    fn secret_key_canonical_roundtrip() {
        let scheme = scheme();
        let (_, sk) = scheme.keypair_generate().unwrap();
        let encoded = sk.to_canonical_bytes().unwrap();
        let decoded = HybridSecretKey::from_canonical_bytes(&encoded).unwrap();
        assert_eq!(sk.ed25519, decoded.ed25519);
        assert_eq!(sk.ml_dsa, decoded.ml_dsa);
    }

    #[test]
    fn malformed_public_key_rejected() {
        let scheme = scheme();
        let (pk, _) = scheme.keypair_generate().unwrap();
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
