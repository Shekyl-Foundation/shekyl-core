// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A multisig member's envelope identity: who sent a ceremony file (R-6;
//! `docs/SHEKYL_MULTISIG_WIRE_FORMAT.md` §1.2; `docs/PQC_MULTISIG.md` §12).
//!
//! Every member holds the group transport secret, so a file that opens
//! under it says only that some member sealed it. To say which, each member
//! has a long-term hybrid envelope keypair (Ed25519 + ML-DSA-65) that the
//! dealer mints and writes into the member files: the member's own secret,
//! and every member's public key. It is not derived from any spend secret
//! and it signs nothing but envelopes. Without it a member with a
//! compromised device could send a proposal "from" another member.
//!
//! The signed message is a frame under the signing envelope, network id at
//! position 0, over every field of the file's plaintext except the
//! signature itself:
//!
//! ```text
//! message   = frame(MULTISIG_ENVELOPE, network_id,
//!                   [u64(format_version), address_fingerprint, intent_hash,
//!                    u64(sender_index), u64(message_type), body])        (64 bytes)
//! sender_sig = HybridEd25519MlDsa.sign(envelope_secret,
//!                                      SCHEME_DOMAIN_MULTISIG_ENVELOPE, message)
//! ```
//!
//! Two registered domains, as every hybrid surface has: the frame's
//! customization and the scheme's outer domain (SA-R-2).

use rand::{CryptoRng, RngCore};
use shekyl_network::envelope::{Framed64, IdDomain, W64};
use shekyl_network::NetworkId;
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::multisig_blob::BLOB_FORMAT_VERSION;
use crate::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSignature, SignatureScheme,
    SCHEME_DOMAIN_MULTISIG_ENVELOPE,
};

/// The frame a ceremony file's sender signs (`CRYPTO_DOMAIN_REGISTRY.tsv`,
/// mechanism 1, binding `id`, width 64): six fields, see the module doc.
pub const MULTISIG_ENVELOPE: IdDomain<6, W64> = IdDomain::new(b"shekyl/multisig-envelope-v1");

/// Bytes of a member's envelope secret: an Ed25519 seed and an ML-DSA-65
/// seed, 32 bytes each.
pub const ENVELOPE_SECRET_LEN: usize = 64;

/// A member's long-term envelope secret. The keypair is regenerated from
/// these bytes when the member signs; the bytes are wiped on drop and never
/// printed.
pub struct MultisigEnvelopeSecret(Zeroizing<[u8; ENVELOPE_SECRET_LEN]>);

impl std::fmt::Debug for MultisigEnvelopeSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MultisigEnvelopeSecret([REDACTED])")
    }
}

impl MultisigEnvelopeSecret {
    /// The secret from the bytes a member file stores.
    #[must_use]
    pub fn from_bytes(bytes: Zeroizing<[u8; ENVELOPE_SECRET_LEN]>) -> Self {
        Self(bytes)
    }

    /// The bytes a member file stores.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ENVELOPE_SECRET_LEN] {
        &self.0
    }

    /// The public key every other member verifies this member's envelopes
    /// under.
    ///
    /// # Errors
    ///
    /// The ML-DSA-65 keygen's refusal.
    pub fn public_key(&self) -> Result<HybridPublicKey, CryptoError> {
        Ok(crate::derivation::hybrid_keypair_from_seed(&self.0)?.0)
    }
}

/// Mint one member's envelope keypair from fresh randomness. The dealer
/// calls this once per member when it builds the group.
///
/// # Errors
///
/// The ML-DSA-65 keygen's refusal.
pub fn mint_multisig_envelope_keypair(
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(HybridPublicKey, MultisigEnvelopeSecret), CryptoError> {
    let mut seed = Zeroizing::new([0u8; ENVELOPE_SECRET_LEN]);
    rng.fill_bytes(seed.as_mut());
    let secret = MultisigEnvelopeSecret(seed);
    let public = secret.public_key()?;
    Ok((public, secret))
}

/// The fields of a ceremony file's plaintext that its sender signs: every
/// field but the signature. The format version is
/// [`BLOB_FORMAT_VERSION`], the only one sealed.
#[derive(Debug, Clone, Copy)]
pub struct EnvelopeFields<'a> {
    /// The group's address fingerprint.
    pub address_fingerprint: &'a [u8; 32],
    /// The intent this file belongs to.
    pub intent_hash: &'a [u8; 32],
    /// The sending member's index.
    pub sender_index: u8,
    /// The ceremony message type.
    pub message_type: u8,
    /// The message body.
    pub body: &'a [u8],
}

/// The 64-byte message a file's sender signs, bound to one network.
#[must_use]
pub fn envelope_message(network_id: &NetworkId, fields: &EnvelopeFields<'_>) -> Framed64 {
    MULTISIG_ENVELOPE.frame(
        network_id,
        [
            &u64::from(BLOB_FORMAT_VERSION).to_le_bytes(),
            fields.address_fingerprint,
            fields.intent_hash,
            &u64::from(fields.sender_index).to_le_bytes(),
            &u64::from(fields.message_type).to_le_bytes(),
            fields.body,
        ],
    )
}

/// Sign a file's [`envelope_message`] as its sender.
///
/// # Errors
///
/// The hybrid signer's refusal.
pub fn sign_multisig_envelope(
    secret: &MultisigEnvelopeSecret,
    message: &Framed64,
) -> Result<HybridSignature, CryptoError> {
    let (_, signing) = crate::derivation::hybrid_keypair_from_seed(&secret.0)?;
    HybridEd25519MlDsa.sign(
        &signing,
        SCHEME_DOMAIN_MULTISIG_ENVELOPE,
        message.as_bytes(),
    )
}

/// Verify a file's sender signature over its [`envelope_message`] under
/// the claimed sender's envelope public key.
///
/// # Errors
///
/// The hybrid verifier's refusal: a malformed key or signature, or a
/// signature that is not this member's over this message.
pub fn verify_multisig_envelope(
    public: &HybridPublicKey,
    message: &Framed64,
    signature: &HybridSignature,
) -> Result<(), CryptoError> {
    HybridEd25519MlDsa.verify(
        public,
        SCHEME_DOMAIN_MULTISIG_ENVELOPE,
        message.as_bytes(),
        signature,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    const NET: NetworkId = [0x4E; 16];
    const FINGERPRINT: [u8; 32] = [0x22; 32];
    const INTENT: [u8; 32] = [0x11; 32];

    fn fields(body: &[u8]) -> EnvelopeFields<'_> {
        EnvelopeFields {
            address_fingerprint: &FINGERPRINT,
            intent_hash: &INTENT,
            sender_index: 1,
            message_type: 0x0C,
            body,
        }
    }

    #[test]
    fn a_member_signature_verifies_under_its_own_key_only() {
        let (public, secret) = mint_multisig_envelope_keypair(&mut OsRng).unwrap();
        let (other, _) = mint_multisig_envelope_keypair(&mut OsRng).unwrap();
        let message = envelope_message(&NET, &fields(b"body"));
        let sig = sign_multisig_envelope(&secret, &message).unwrap();
        assert!(verify_multisig_envelope(&public, &message, &sig).is_ok());
        assert!(verify_multisig_envelope(&other, &message, &sig).is_err());
    }

    /// Every signed field binds: another network, fingerprint, intent,
    /// sender, type or body refuses the signature.
    #[test]
    fn every_field_and_the_network_is_signed() {
        let (public, secret) = mint_multisig_envelope_keypair(&mut OsRng).unwrap();
        let sig =
            sign_multisig_envelope(&secret, &envelope_message(&NET, &fields(b"body"))).unwrap();
        let other_fp = [0x23; 32];
        let other_intent = [0x12; 32];
        let refused = |net: &NetworkId, f: EnvelopeFields<'_>| {
            assert!(verify_multisig_envelope(&public, &envelope_message(net, &f), &sig).is_err());
        };
        refused(&[0x4F; 16], fields(b"body"));
        refused(
            &NET,
            EnvelopeFields {
                address_fingerprint: &other_fp,
                ..fields(b"body")
            },
        );
        refused(
            &NET,
            EnvelopeFields {
                intent_hash: &other_intent,
                ..fields(b"body")
            },
        );
        refused(
            &NET,
            EnvelopeFields {
                sender_index: 2,
                ..fields(b"body")
            },
        );
        refused(
            &NET,
            EnvelopeFields {
                message_type: 0x0D,
                ..fields(b"body")
            },
        );
        refused(&NET, fields(b"bodx"));
    }

    /// The secret round-trips through the bytes a member file stores, and
    /// its public key is a function of those bytes alone.
    #[test]
    fn the_secret_is_its_bytes() {
        let (public, secret) = mint_multisig_envelope_keypair(&mut OsRng).unwrap();
        let again = MultisigEnvelopeSecret::from_bytes(Zeroizing::new(*secret.as_bytes()));
        assert_eq!(
            again.public_key().unwrap().to_canonical_bytes().unwrap(),
            public.to_canonical_bytes().unwrap()
        );
        assert_eq!(format!("{again:?}"), "MultisigEnvelopeSecret([REDACTED])");
    }

    /// Not the member's per-output signing surface: an envelope signature
    /// does not verify under the multisig spend domain over the same bytes.
    #[test]
    fn an_envelope_signature_is_not_a_spend_signature() {
        let (public, secret) = mint_multisig_envelope_keypair(&mut OsRng).unwrap();
        let message = envelope_message(&NET, &fields(b"body"));
        let sig = sign_multisig_envelope(&secret, &message).unwrap();
        assert!(HybridEd25519MlDsa
            .verify(
                &public,
                crate::signature::SCHEME_DOMAIN_PQC_AUTH_TX_MULTISIG,
                message.as_bytes(),
                &sig,
            )
            .is_err());
    }
}
