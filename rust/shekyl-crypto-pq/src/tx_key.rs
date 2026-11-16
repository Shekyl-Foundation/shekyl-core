// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The transaction key `r` (R-21; `SECRET_STORAGE.md` SSR-Q3).
//!
//! Every output a transaction carries is built from one secret scalar `r`:
//! the KEM encapsulation to each recipient derives from it, and the
//! transaction's public key `R = r·G` rides in the `0x01` extra field.
//! [`TxKey`] is that scalar, and this module is the only place one is made:
//!
//! - [`TxKey::random`] — every transaction a wallet builds, and the
//!   coinbase template.
//! - [`TxKey::from_genesis_seed`] — the genesis transaction, from the
//!   network's name and its recipients ([`GENESIS_TXKEY`]).
//! - `TxKey::seeded` — only under the TEST_ONLY `seeded-rng` feature, so a
//!   fixture can pin a key.
//!
//! A key never hands out its bytes. It gives `R` ([`TxKey::public`]), it
//! builds outputs (`crate::output::construct_output` and its kin take
//! `&TxKey`), and it has two named exits, each with its own type:
//!
//! - [`StoredTxKey`] — what the wallet keeps inside its sealed record so it
//!   can prove a payment later. Opened back into a key only here
//!   ([`TxKey::open`]).
//! - [`DisclosedTxKey`] — what an OUTBOUND payment proof publishes. The
//!   proof's wire format carries `r` itself, so the verifier can re-derive
//!   each output's encapsulation; once disclosed the scalar is no longer a
//!   secret, and its type says so ([`TxKey::disclose`]).
//!
//! Every key is a canonical scalar: the outbound proof signs with `r` as a
//! scalar and refuses bytes that are not one (alpha.11 bug hunt §A19).

use std::fmt;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use rand::RngCore as _;
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use shekyl_heap_secret::HeapSecret;
use shekyl_network::envelope::{Framed32, NameDomain};
use shekyl_network::NameId;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;
use crate::kem::SharedSecret;
use crate::schnorr;

/// The length of a transaction key's scalar, and of its stored and
/// disclosed forms.
pub const TX_KEY_LEN: usize = 32;

/// The genesis transaction key's frame: `frame(this domain, name_id,
/// [recipients])`, read to 32 bytes and reduced mod ℓ. The recipients field
/// is payment identity (spend key, view key, ML-KEM key) and amount, never
/// an address's spelling; genesis commits to the network's name through
/// `name_id` (NI-R12; the signing envelope §2.4).
pub const GENESIS_TXKEY: NameDomain<1> = NameDomain::new(b"shekyl/genesis-txkey-v3");

/// A transaction's secret key `r`, with its public key `R = r·G`.
///
/// Wiped on drop, never cloned, never printed, and no accessor returns its
/// bytes (module docs). The scalar sits behind a pointer ([`HeapSecret`]),
/// so moving a key copies no secret. A caller that builds from one key more
/// than once borrows it.
pub struct TxKey {
    secret: HeapSecret<TX_KEY_LEN>,
    public: EdwardsPoint,
}

impl TxKey {
    /// The key whose scalar is `r`. The one place a key is assembled.
    fn from_scalar(r: &Zeroizing<Scalar>) -> Self {
        let mut secret = HeapSecret::zeroed();
        *secret.as_array_mut() = r.to_bytes();
        Self {
            secret,
            public: &**r * ED25519_BASEPOINT_TABLE,
        }
    }

    /// A fresh key from the OS's CSPRNG: 64 drawn bytes, reduced mod ℓ, so
    /// the scalar is uniform.
    ///
    /// # Errors
    ///
    /// [`RandomnessUnavailable`] when the OS's random source fails; no key
    /// is made from a partial draw.
    pub fn random() -> Result<Self, RandomnessUnavailable> {
        let mut wide = Zeroizing::new([0u8; 64]);
        rand::rngs::OsRng
            .try_fill_bytes(wide.as_mut())
            .map_err(|e| RandomnessUnavailable(e.to_string()))?;
        Ok(Self::from_scalar(&Zeroizing::new(
            Scalar::from_bytes_mod_order_wide(&wide),
        )))
    }

    /// The genesis transaction's key for the network named `name`, paying
    /// `recipients` (the genesis tool's encoding of its recipient list):
    /// [`GENESIS_TXKEY`]'s frame, reduced mod ℓ. Deterministic: anyone can
    /// rebuild a genesis transaction from its recipients file.
    #[must_use]
    pub fn from_genesis_seed(name: &NameId, recipients: &[u8]) -> Self {
        let seed = Zeroizing::new(GENESIS_TXKEY.frame(name, [recipients]).into_bytes());
        Self::from_scalar(&Zeroizing::new(Scalar::from_bytes_mod_order(*seed)))
    }

    /// The key whose scalar is `bytes` reduced mod ℓ, so a fixture can pin
    /// its transaction key. Only under the TEST_ONLY `seeded-rng` feature,
    /// which no build that ships enables (`CF-R9`).
    #[cfg(feature = "seeded-rng")]
    #[must_use]
    pub fn seeded(bytes: [u8; TX_KEY_LEN]) -> Self {
        let bytes = Zeroizing::new(bytes);
        Self::from_scalar(&Zeroizing::new(Scalar::from_bytes_mod_order(*bytes)))
    }

    /// The key a wallet stored ([`TxKey::store`]).
    ///
    /// # Errors
    ///
    /// [`StoredKeyError::NotCanonical`] when the stored bytes are not a
    /// canonical scalar: a key this module minted always is, so the record
    /// was not written by it.
    pub fn open(stored: &StoredTxKey) -> Result<Self, StoredKeyError> {
        let r: Option<Scalar> = Scalar::from_canonical_bytes(*stored.0.as_array()).into();
        let r = Zeroizing::new(r.ok_or(StoredKeyError::NotCanonical)?);
        Ok(Self::from_scalar(&r))
    }

    /// The transaction's public key `R = r·G`.
    #[must_use]
    pub fn public(&self) -> EdwardsPoint {
        self.public
    }

    /// `R`, compressed: the `0x01` extra field's bytes.
    #[must_use]
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.compress().to_bytes()
    }

    /// The form the wallet keeps so it can prove this transaction's
    /// payments later.
    #[must_use]
    pub fn store(&self) -> StoredTxKey {
        StoredTxKey(HeapSecret::copied_from(self.secret.as_array()))
    }

    /// Publish this key in an OUTBOUND payment proof: the key, disclosed,
    /// and a Schnorr signature by it over `message` under `domain`.
    ///
    /// Disclosing `r` lets anyone who holds the proof re-derive the
    /// encapsulation of every output of the transaction, so it is done only
    /// to prove a payment, and only by the wallet that sent it.
    #[must_use]
    pub fn disclose(&self, domain: &[u8], message: &Framed32) -> Disclosure {
        let r = self.scalar();
        Disclosure {
            key: DisclosedTxKey(*r),
            signature: schnorr::sign(domain, &r, &self.public, message.as_bytes()),
        }
    }

    /// Re-derive output `output_index`'s encapsulation to the recipient's
    /// keys: the combined shared secret, the X25519 ephemeral public key and
    /// the ML-KEM ciphertext the output carries.
    ///
    /// # Errors
    ///
    /// As [`DisclosedTxKey::rederive_combined_ss`].
    pub fn rederive_combined_ss(
        &self,
        x25519_pk: &[u8; 32],
        ml_kem_ek: &[u8],
        output_index: u64,
    ) -> Result<(SharedSecret, [u8; 32], Vec<u8>), CryptoError> {
        crate::output::rederive_combined_ss(self.ikm(), x25519_pk, ml_kem_ek, output_index)
    }

    /// The scalar's bytes, for the derivations in this crate that take the
    /// key as HKDF input (`derivation::derive_kem_seed`).
    pub(crate) fn ikm(&self) -> &[u8; TX_KEY_LEN] {
        self.secret.as_array()
    }

    /// `r` as a scalar. The stored bytes are a canonical encoding
    /// ([`Self::from_scalar`] writes `Scalar::to_bytes`; [`Self::open`]
    /// refuses anything else), so this does not reduce them. Reducing here
    /// would sign with a different scalar from the bytes the encapsulation
    /// consumes.
    fn scalar(&self) -> Zeroizing<Scalar> {
        let canonical: Option<Scalar> = Scalar::from_canonical_bytes(*self.ikm()).into();
        Zeroizing::new(canonical.expect("a transaction key's bytes are a canonical scalar"))
    }
}

impl fmt::Debug for TxKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxKey")
            .field("secret", &"[REDACTED]")
            .field("public", &self.public.compress())
            .finish()
    }
}

/// Why a stored transaction key does not open ([`TxKey::open`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StoredKeyError {
    /// The stored bytes are not a canonical scalar.
    #[error("the stored transaction key is not a canonical scalar")]
    NotCanonical,
}

/// The OS's random source failed, so no fresh key was made
/// ([`TxKey::random`]). Carries the source's own report.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the OS random source failed: {0}")]
pub struct RandomnessUnavailable(pub String);

/// A transaction key as the wallet keeps it ([`TxKey::store`]), opened
/// only by [`TxKey::open`].
///
/// Its serialized form is the 32 bytes as a byte string, the shape the
/// wallet's record has always held. Deserializing does not check the bytes:
/// a record loads whole, and a key that does not open is refused where it
/// is used. Held behind a pointer, wiped on drop, never cloned, never
/// printed; two compare in constant time.
pub struct StoredTxKey(HeapSecret<TX_KEY_LEN>);

impl PartialEq for StoredTxKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_array().ct_eq(other.0.as_array()).into()
    }
}

impl Eq for StoredTxKey {}

impl fmt::Debug for StoredTxKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoredTxKey([REDACTED])")
    }
}

impl Serialize for StoredTxKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0.as_array())
    }
}

impl<'de> Deserialize<'de> for StoredTxKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_bytes(StoredBytes).map(Self)
    }
}

/// Reads a stored key's bytes straight into its heap cell; a buffer the
/// deserializer allocated is wiped before it is freed.
struct StoredBytes;

impl<'de> Visitor<'de> for StoredBytes {
    type Value = HeapSecret<TX_KEY_LEN>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{TX_KEY_LEN} bytes")
    }

    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        if v.len() != TX_KEY_LEN {
            return Err(E::invalid_length(v.len(), &self));
        }
        let mut cell = HeapSecret::zeroed();
        cell.as_array_mut().copy_from_slice(v);
        Ok(cell)
    }

    fn visit_borrowed_bytes<E: serde::de::Error>(self, v: &'de [u8]) -> Result<Self::Value, E> {
        self.visit_bytes(v)
    }

    fn visit_byte_buf<E: serde::de::Error>(self, mut v: Vec<u8>) -> Result<Self::Value, E> {
        let cell = self.visit_bytes(&v);
        v.zeroize();
        cell
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut cell = HeapSecret::zeroed();
        for (i, slot) in cell.as_array_mut().iter_mut().enumerate() {
            *slot = seq
                .next_element()?
                .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
        }
        if seq.next_element::<u8>()?.is_some() {
            return Err(serde::de::Error::invalid_length(TX_KEY_LEN + 1, &self));
        }
        Ok(cell)
    }
}

/// What [`TxKey::disclose`] publishes: the key and its signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disclosure {
    /// The transaction key, disclosed.
    pub key: DisclosedTxKey,
    /// The key's Schnorr signature over the caller's message.
    pub signature: [u8; schnorr::SIG_LEN],
}

/// A transaction key an OUTBOUND payment proof published: no longer a
/// secret, so it reads and prints freely. It re-derives outputs'
/// encapsulations and verifies the proof's signature; it builds nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisclosedTxKey(Scalar);

impl DisclosedTxKey {
    /// The disclosed key a proof carries, or `None` when the bytes are not
    /// a canonical scalar (no wallet discloses one).
    #[must_use]
    pub fn from_bytes(bytes: &[u8; TX_KEY_LEN]) -> Option<Self> {
        Option::from(Scalar::from_canonical_bytes(*bytes)).map(Self)
    }

    /// The bytes a proof carries.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; TX_KEY_LEN] {
        self.0.to_bytes()
    }

    /// The transaction's public key `R`.
    #[must_use]
    pub fn public(&self) -> EdwardsPoint {
        &self.0 * ED25519_BASEPOINT_TABLE
    }

    /// Whether `signature` is this key's over `message` under `domain`.
    #[must_use]
    pub fn signed(
        &self,
        domain: &[u8],
        message: &Framed32,
        signature: &[u8; schnorr::SIG_LEN],
    ) -> bool {
        schnorr::verify(domain, &self.public(), message.as_bytes(), signature)
    }

    /// Re-derive output `output_index`'s encapsulation to the recipient's
    /// keys, as the sender did: the combined shared secret, the X25519
    /// ephemeral public key and the ML-KEM ciphertext.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKeyMaterial`] for an ML-KEM key of the wrong
    /// length, [`CryptoError::LowOrderPoint`] for a low-order X25519 key,
    /// and [`CryptoError::EncapsulationFailed`] for an ML-KEM key that does
    /// not parse.
    pub fn rederive_combined_ss(
        &self,
        x25519_pk: &[u8; 32],
        ml_kem_ek: &[u8],
        output_index: u64,
    ) -> Result<(SharedSecret, [u8; 32], Vec<u8>), CryptoError> {
        let ikm = Zeroizing::new(self.0.to_bytes());
        crate::output::rederive_combined_ss(&ikm, x25519_pk, ml_kem_ek, output_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::{HybridX25519MlKem, KeyEncapsulation};

    const TEST_FRAME: NameDomain<1> = NameDomain::new(b"shekyl/tx-key-disclosure-test");

    fn message(byte: u8) -> Framed32 {
        TEST_FRAME.frame(&NameId::from_bytes([0; 16]), [&[byte]])
    }

    #[test]
    fn a_random_key_is_canonical_and_matches_its_point() {
        for _ in 0..64 {
            let key = TxKey::random().expect("the OS draws a key");
            let r: Option<Scalar> = Scalar::from_canonical_bytes(*key.ikm()).into();
            let r = r.expect("a minted key is a canonical scalar");
            assert_eq!(key.public(), &r * ED25519_BASEPOINT_TABLE);
        }
    }

    #[test]
    fn a_stored_key_opens_to_the_same_key() {
        let key = TxKey::random().expect("the OS draws a key");
        let opened = TxKey::open(&key.store()).expect("a stored key opens");
        assert_eq!(opened.public(), key.public());
        assert_eq!(opened.ikm(), key.ikm());
    }

    #[test]
    fn a_stored_key_that_is_not_canonical_does_not_open() {
        let stored = StoredTxKey(HeapSecret::copied_from(&[0xFF; TX_KEY_LEN]));
        assert_eq!(
            TxKey::open(&stored).err(),
            Some(StoredKeyError::NotCanonical)
        );
    }

    // The wallet record's byte shape is held by `shekyl-engine-state`'s
    // `TxSecretKey` tests, over postcard; these read the sequence form.
    #[test]
    fn a_stored_key_serializes_as_its_bytes_and_reads_back() {
        let key = TxKey::random().expect("the OS draws a key");
        let stored = key.store();
        let json = serde_json::to_string(&stored).expect("serializes");
        let read: StoredTxKey = serde_json::from_str(&json).expect("reads back");
        assert_eq!(read, stored);
        let bytes: Vec<u8> = serde_json::from_str(&json).expect("a byte list");
        assert_eq!(bytes, key.ikm().to_vec());
    }

    #[test]
    fn a_stored_key_of_the_wrong_length_does_not_read() {
        for len in [TX_KEY_LEN - 1, TX_KEY_LEN + 1] {
            let json = serde_json::to_string(&vec![7u8; len]).expect("serializes");
            assert!(serde_json::from_str::<StoredTxKey>(&json).is_err(), "{len}");
        }
    }

    #[test]
    fn no_form_of_the_key_prints_its_secret() {
        let key = TxKey::random().expect("the OS draws a key");
        let secret_hex = hex::encode(key.ikm());
        let printed = format!("{key:?} {:?}", key.store());
        assert!(!printed.contains(&secret_hex), "{printed}");
        assert!(printed.contains("REDACTED"));
    }

    #[test]
    fn a_disclosed_key_is_the_key_and_verifies_its_signature() {
        let key = TxKey::random().expect("the OS draws a key");
        let domain = b"shekyl-tx-key-disclosure-test";
        let signed_over = message(9);
        let disclosure = key.disclose(domain, &signed_over);
        assert_eq!(&disclosure.key.to_bytes(), key.ikm());
        assert_eq!(disclosure.key.public(), key.public());
        assert!(disclosure
            .key
            .signed(domain, &signed_over, &disclosure.signature));
        let other = message(10);
        assert!(!disclosure.key.signed(domain, &other, &disclosure.signature));
        let read = DisclosedTxKey::from_bytes(&disclosure.key.to_bytes()).expect("canonical");
        assert_eq!(read, disclosure.key);
    }

    #[test]
    fn a_disclosed_key_that_is_not_canonical_is_refused() {
        assert_eq!(DisclosedTxKey::from_bytes(&[0xFF; TX_KEY_LEN]), None);
    }

    #[test]
    fn the_key_and_its_disclosure_rederive_the_same_encapsulation() {
        let (pk, _) = HybridX25519MlKem.keypair_generate().expect("a keypair");
        let key = TxKey::random().expect("the OS draws a key");
        let disclosed = key.disclose(b"d", &message(0)).key;
        let (own_ss, own_eph, own_ct) = key
            .rederive_combined_ss(&pk.x25519, &pk.ml_kem, 3)
            .expect("rederives");
        let (ss, eph, ct) = disclosed
            .rederive_combined_ss(&pk.x25519, &pk.ml_kem, 3)
            .expect("rederives");
        assert_eq!(own_ss.0, ss.0);
        assert_eq!(own_eph, eph);
        assert_eq!(own_ct, ct);
    }

    /// A seed above the group order is reduced at the door. Disclosure
    /// publishes the stored scalar, which is that reduction and not the seed.
    #[cfg(feature = "seeded-rng")]
    #[test]
    fn a_seed_above_the_group_order_is_reduced_once() {
        let key = TxKey::seeded([0xFF; TX_KEY_LEN]);
        assert_ne!(key.ikm(), &[0xFF; TX_KEY_LEN]);
        let canonical: Option<Scalar> = Scalar::from_canonical_bytes(*key.ikm()).into();
        assert!(
            canonical.is_some(),
            "the stored bytes are a canonical scalar"
        );
        let disclosure = key.disclose(b"d", &message(1));
        assert_eq!(&disclosure.key.to_bytes(), key.ikm());
    }

    #[test]
    fn the_genesis_key_is_bound_to_the_network_name() {
        let a = TxKey::from_genesis_seed(&NameId::from_bytes([1; 16]), b"recipients");
        let b = TxKey::from_genesis_seed(&NameId::from_bytes([2; 16]), b"recipients");
        let again = TxKey::from_genesis_seed(&NameId::from_bytes([1; 16]), b"recipients");
        assert_ne!(a.public(), b.public());
        assert_eq!(a.public(), again.public());
    }
}
