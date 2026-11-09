// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Option E′ multisig outputs: the sender's constructor and the member's
//! receive check (`docs/PQC_MULTISIG.md` §7–§8).
//!
//! A multisig output is a solo output to the group, plus one thing per
//! member:
//!
//! - **The solo part.** [`construct_multisig_output`] runs the solo output
//!   core with spend key `B_group + Y_group` and KEM key `KEM_group`, so
//!   `O = ho·G + B_group + (y_group + y_kem)·T`, the `0x06` ciphertext, the
//!   commitment and the encrypted amount and label are exactly a solo
//!   output's. Every member holds the group KEM secret and `b`, so every
//!   member scans, sees the amount and computes the key image alone.
//! - **The per-member part** (the `0x0D` entry). For each member `i` the
//!   sender encapsulates to `KEM_i`. Member `i` alone recovers `ss_i`, and
//!   its per-output hybrid signing key `pk_i` derives from it, so no member
//!   can sign for another: the PQ leg stays M-of-N. The sender publishes
//!   `h_i = frame(shekyl/multisig-key-hash-v1, network_id, [pk_i])` for every
//!   member, encrypted under the group secret, and forgets `ss_i` and `pk_i`.
//! - **The leaf.** `CM` commits to the committed form
//!   `0x02 ‖ n ‖ m ‖ h_1 … h_n`, blinded from the group secret, not to any
//!   solo per-output key. The solo constructor's per-output key is never
//!   made: every member could derive it, which would make the PQ leg 1-of-N.
//!
//! The hashes are encrypted because in the clear they would equal the
//! committed form a spend reveals, and link the spend to its output.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use hkdf::Hkdf;
use sha2::Sha512;
use shekyl_address::multisig_address::{MultisigAddressPayload, HYBRID_KEM_PUBKEY_LEN};
use shekyl_network::NetworkId;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::derivation::derive_multisig_key_hashes_key;
use crate::encrypted_output_field::EncryptedOutputField;
use crate::error::CryptoError;
use crate::kem::X25519_KEM_CT_LEN;
use crate::leaf_commitment::{pqc_leaf_commitment, PqcLeafCommitment, PQC_LEAF_ENTRY_LEN};
use crate::multisig::{multisig_key_hash, MultisigCommittedForm, MULTISIG_KEY_HASH_LEN};
use crate::output::{construct_output_core, encapsulate_deterministic, recover_combined_ss};
use crate::signature::{HybridPublicKey, HybridSecretKey};

/// The HKDF info label a member's per-output hybrid signing seed expands
/// under, from that member's KEM shared secret `ss_i`
/// (`CRYPTO_DOMAIN_REGISTRY.tsv`, mechanism 2, `local:per-output-secret`).
pub const LABEL_MULTISIG_MEMBER_SIGN: &[u8] = b"shekyl-v31-hybrid-sign";

/// Bytes of the AEAD tag after the encrypted key hashes.
pub const MULTISIG_HASHES_TAG_LEN: usize = 16;

/// The hash list is the only plaintext its key ever encrypts: the key is
/// derived per output from a fresh KEM secret and the output index, so a
/// fixed nonce is never reused under one key.
const HASHES_NONCE: [u8; 12] = [0u8; 12];

/// A member's per-output hybrid signing keypair from its KEM shared secret:
/// a 64-byte seed `HKDF-SHA-512(ikm = ss_i).expand("shekyl-v31-hybrid-sign")`,
/// its first half the Ed25519 seed and its second the ML-DSA-65 seed, the
/// same two-seed shape as a solo output's per-output key.
///
/// # Errors
///
/// [`CryptoError`] if ML-DSA key generation fails.
pub fn derive_multisig_member_keypair(
    member_combined_ss: &[u8; 64],
) -> Result<(HybridPublicKey, HybridSecretKey), CryptoError> {
    use ed25519_dalek::SigningKey;
    use fips204::traits::SerDes;

    let hk = Hkdf::<Sha512>::new(None, member_combined_ss);
    let mut seed = Zeroizing::new([0u8; 64]);
    hk.expand(LABEL_MULTISIG_MEMBER_SIGN, seed.as_mut())
        .map_err(|_| CryptoError::KeyGenerationFailed("HKDF-Expand failed".into()))?;
    let ed_seed: Zeroizing<[u8; 32]> =
        Zeroizing::new(seed[..32].try_into().expect("first half of 64"));
    let ml_seed: Zeroizing<[u8; 32]> =
        Zeroizing::new(seed[32..].try_into().expect("second half of 64"));

    let ed_signing = SigningKey::from_bytes(&ed_seed);
    let (ml_pk, ml_sk) = crate::derivation::keygen_from_seed(&ml_seed)?;
    let public = HybridPublicKey {
        ed25519: ed_signing.verifying_key().to_bytes(),
        ml_dsa: ml_pk.into_bytes().to_vec(),
    };
    let secret = HybridSecretKey {
        ed25519: ed_signing.to_bytes().to_vec(),
        ml_dsa: ml_sk.into_bytes().to_vec(),
    };
    Ok((public, secret))
}

fn split_kem_pubkey(pubkey: &[u8]) -> Result<([u8; 32], &[u8]), CryptoError> {
    if pubkey.len() != HYBRID_KEM_PUBKEY_LEN {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    let (x25519, ml_kem) = pubkey.split_at(X25519_KEM_CT_LEN);
    Ok((x25519.try_into().expect("32 bytes"), ml_kem))
}

fn group_point(bytes: &[u8; 32]) -> Result<EdwardsPoint, CryptoError> {
    let point = CompressedEdwardsY(*bytes)
        .decompress()
        .ok_or(CryptoError::InvalidKeyMaterial)?;
    if point == EdwardsPoint::default() || !point.is_torsion_free() {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    Ok(point)
}

fn hashes_aad(out_idx: u8, n: u8) -> [u8; 2] {
    [out_idx, n]
}

/// A multisig output, as the sender builds it.
///
/// The solo fields mean what they mean on [`crate::output::OutputData`];
/// there is no per-output PQC key (see the module doc). The two encrypted
/// fields are `pub(crate)` with read accessors, as on `OutputData`.
pub struct MultisigOutputData {
    /// `O = ho·G + B_group + (y_group + y_kem)·T`.
    pub output_key: [u8; 32],
    /// `C = z·G + amount·H`.
    pub commitment: [u8; 32],
    pub(crate) enc_amount: EncryptedOutputField,
    pub(crate) enc_label: EncryptedOutputField,
    /// The ML-KEM view tag.
    pub view_tag_prefilter: u8,
    /// The `0x06` ciphertext to the group KEM key: X25519 part.
    pub kem_ciphertext_x25519: [u8; 32],
    /// The `0x06` ciphertext to the group KEM key: ML-KEM part.
    pub kem_ciphertext_ml_kem: Vec<u8>,
    /// The `0x07` entry: `CM` over the committed form, and its record.
    pub pqc_leaf: PqcLeafCommitment,
    /// The `0x0D` entry's member ciphertexts (`x25519 ‖ ml_kem`, 1120
    /// bytes each), member order.
    pub member_kem_ciphertexts: Vec<Vec<u8>>,
    /// The `0x0D` entry's encrypted key hashes and their AEAD tag.
    pub enc_key_hashes: Vec<u8>,
}

impl MultisigOutputData {
    /// The `enc_amount` wire field.
    #[must_use]
    pub fn enc_amount_wire(&self) -> EncryptedOutputField {
        self.enc_amount
    }

    /// The `enc_label` wire field.
    #[must_use]
    pub fn enc_label_wire(&self) -> EncryptedOutputField {
        self.enc_label
    }
}

/// Build an output paying `amount` to the multisig group `address`, at
/// `output_index` in a transaction keyed by `tx_key_secret`, on the chain
/// whose id is `network`.
///
/// # Errors
///
/// [`CryptoError::InvalidKeyMaterial`] for an address point that is not a
/// prime-order, non-identity point, or a KEM key of the wrong shape;
/// [`CryptoError::InvalidInput`] for an output index above 255 (the `0x0D`
/// entry names its output in one byte); the solo core's own errors.
pub fn construct_multisig_output(
    tx_key_secret: &[u8; 32],
    address: &MultisigAddressPayload,
    amount: u64,
    output_index: u64,
    network: &NetworkId,
) -> Result<MultisigOutputData, CryptoError> {
    let out_idx = u8::try_from(output_index)
        .map_err(|_| CryptoError::InvalidInput("multisig output index above 255".into()))?;
    let spend_point = group_point(&address.b_group)? + group_point(&address.y_group)?;
    let spend_key = spend_point.compress().to_bytes();
    let (group_x25519, group_ml_kem) = split_kem_pubkey(&address.group_kem_pubkey)?;

    let core = construct_output_core(
        tx_key_secret,
        &group_x25519,
        group_ml_kem,
        &spend_key,
        amount,
        output_index,
        &crate::label::sentinel_plaintext(),
    )?;

    let mut member_kem_ciphertexts = Vec::with_capacity(address.hybrid_kem_pubkeys.len());
    let mut key_hashes = Vec::with_capacity(address.hybrid_kem_pubkeys.len());
    for member_kem in &address.hybrid_kem_pubkeys {
        let (x25519, ml_kem) = split_kem_pubkey(member_kem)?;
        let member = encapsulate_deterministic(tx_key_secret, &x25519, ml_kem, output_index)?;
        let (member_pk, _member_sk) = derive_multisig_member_keypair(&member.combined_ss.0)?;
        key_hashes.push(multisig_key_hash(network, &member_pk));
        let mut ct = Vec::with_capacity(X25519_KEM_CT_LEN + member.ml_kem_ct.len());
        ct.extend_from_slice(&member.x25519_ct);
        ct.extend_from_slice(&member.ml_kem_ct);
        member_kem_ciphertexts.push(ct);
        // `member` (its shared secrets) and the keypair drop here, wiped.
    }

    let committed = MultisigCommittedForm::new(address.m_required, key_hashes)
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let n = committed.n_total();
    let pqc_leaf = pqc_leaf_commitment(&core.combined_ss.0, output_index, &committed.to_bytes())
        .map_err(|e| {
            CryptoError::KeyGenerationFailed(format!("multisig leaf commitment: {e:?}"))
        })?;

    let key = derive_multisig_key_hashes_key(&core.combined_ss.0, output_index);
    let plaintext: Vec<u8> = committed.key_hashes().concat();
    let enc_key_hashes = ChaCha20Poly1305::new((&*key).into())
        .encrypt(
            &Nonce::from(HASHES_NONCE),
            Payload {
                msg: &plaintext,
                aad: &hashes_aad(out_idx, n),
            },
        )
        .map_err(|_| CryptoError::InvalidInput("key hash encryption failed".into()))?;

    Ok(MultisigOutputData {
        output_key: core.output_key,
        commitment: core.commitment,
        enc_amount: core.enc_amount,
        enc_label: core.enc_label,
        view_tag_prefilter: core.view_tag_prefilter,
        kem_ciphertext_x25519: core.kem_ciphertext_x25519,
        kem_ciphertext_ml_kem: core.kem_ciphertext_ml_kem.clone(),
        pqc_leaf,
        member_kem_ciphertexts,
        enc_key_hashes,
    })
}

/// Why a member's receive check refuses an output it otherwise owns. Every
/// variant leaves the output received but unspendable by this group as
/// published: the sender can always burn an output, and this is how a
/// member sees that it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MultisigReceiveError {
    /// The entry's member count is not the group's, or this member's index
    /// is not below it.
    #[error("the multisig entry is not for a group of this size")]
    GroupSize,
    /// The key hashes do not decrypt under the output's group secret.
    #[error("the multisig entry's key hashes do not decrypt")]
    HashesUndecryptable,
    /// This member's own ciphertext does not decapsulate.
    #[error("this member's multisig ciphertext does not decapsulate")]
    MemberDecap,
    /// The hash at this member's index is not this member's key's.
    #[error("the entry's key hash for this member is not this member's key")]
    MemberKeyHash,
    /// The published leaf entry does not open to the committed form built
    /// from the decrypted hashes: a hash for some other member is wrong.
    #[error("the output's leaf does not commit to the entry's key hashes")]
    LeafMismatch,
}

/// The receive-side context one member brings to an output its group owns.
pub struct MultisigMemberView<'a> {
    /// This member's index, `0..n`.
    pub member_index: u8,
    /// The group's member count.
    pub n_total: u8,
    /// The group's threshold.
    pub m_required: u8,
    /// This member's X25519 KEM secret.
    pub member_x25519_sk: &'a [u8; 32],
    /// This member's ML-KEM-768 decapsulation key.
    pub member_ml_kem_dk: &'a [u8],
    /// The chain's network id (the key hashes bind it).
    pub network: &'a NetworkId,
}

/// One output's `0x0D` entry, as the scanner hands it over.
pub struct MultisigEntryView<'a> {
    /// The entry's output index byte.
    pub out_idx: u8,
    /// The member ciphertexts, member order, each `x25519 ‖ ml_kem`.
    pub member_kem_ciphertexts: &'a [&'a [u8]],
    /// The encrypted key hashes and their tag.
    pub enc_key_hashes: &'a [u8],
}

/// Check, as one member, that an output the group owns can be spent by the
/// group as published (`docs/PQC_MULTISIG.md` §8): decrypt the key hashes
/// under the group secret, check this member's own hash against its key,
/// and check that the published leaf commits to the committed form the
/// hashes make. Returns the committed form, which a spend reveals.
///
/// `group_combined_ss` is the group KEM secret the solo scanner recovered
/// for this output, and `published_leaf` the output's `0x07` entry.
///
/// # Errors
///
/// [`MultisigReceiveError`], naming the first check that failed.
pub fn open_multisig_entry(
    group_combined_ss: &[u8; 64],
    output_index: u64,
    member: &MultisigMemberView<'_>,
    entry: &MultisigEntryView<'_>,
    published_leaf: &[u8; PQC_LEAF_ENTRY_LEN],
) -> Result<MultisigCommittedForm, MultisigReceiveError> {
    let n = member.n_total;
    if entry.member_kem_ciphertexts.len() != usize::from(n) || member.member_index >= n {
        return Err(MultisigReceiveError::GroupSize);
    }

    let key = derive_multisig_key_hashes_key(group_combined_ss, output_index);
    let plaintext = Zeroizing::new(
        ChaCha20Poly1305::new((&*key).into())
            .decrypt(
                &Nonce::from(HASHES_NONCE),
                Payload {
                    msg: entry.enc_key_hashes,
                    aad: &hashes_aad(entry.out_idx, n),
                },
            )
            .map_err(|_| MultisigReceiveError::HashesUndecryptable)?,
    );
    if plaintext.len() != usize::from(n) * MULTISIG_KEY_HASH_LEN {
        return Err(MultisigReceiveError::HashesUndecryptable);
    }
    let key_hashes: Vec<[u8; MULTISIG_KEY_HASH_LEN]> = plaintext
        .chunks_exact(MULTISIG_KEY_HASH_LEN)
        .map(|h| h.try_into().expect("chunks_exact width"))
        .collect();

    let own_ct = entry.member_kem_ciphertexts[usize::from(member.member_index)];
    if own_ct.len() < X25519_KEM_CT_LEN {
        return Err(MultisigReceiveError::MemberDecap);
    }
    let (ct_x25519, ct_ml_kem) = own_ct.split_at(X25519_KEM_CT_LEN);
    let member_ss = recover_combined_ss(
        member.member_x25519_sk,
        member.member_ml_kem_dk,
        ct_x25519.try_into().expect("32 bytes"),
        ct_ml_kem,
    )
    .map_err(|_| MultisigReceiveError::MemberDecap)?;
    let (member_pk, _member_sk) = derive_multisig_member_keypair(&member_ss.0)
        .map_err(|_| MultisigReceiveError::MemberDecap)?;
    let own_hash = multisig_key_hash(member.network, &member_pk);
    if !bool::from(own_hash.ct_eq(&key_hashes[usize::from(member.member_index)])) {
        return Err(MultisigReceiveError::MemberKeyHash);
    }

    let committed = MultisigCommittedForm::new(member.m_required, key_hashes)
        .map_err(|_| MultisigReceiveError::GroupSize)?;
    let leaf = pqc_leaf_commitment(group_combined_ss, output_index, &committed.to_bytes())
        .map_err(|_| MultisigReceiveError::LeafMismatch)?;
    if !bool::from(leaf.entry_bytes().ct_eq(published_leaf)) {
        return Err(MultisigReceiveError::LeafMismatch);
    }
    Ok(committed)
}

#[cfg(test)]
#[path = "multisig_output_tests.rs"]
mod tests;
