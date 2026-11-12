// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The E′ output end to end: a dealer-shaped group, an output built to it,
//! every member opening it, and spends from any `m` members verifying.

use super::*;
use crate::kem::{HybridKemSecretKey, HybridX25519MlKem, KeyEncapsulation};
use crate::multisig::{
    verify_multisig, MultisigKeyBlob, MultisigSigContainer, HYBRID_SCHEME_ID_MULTISIG,
};
use crate::output::recover_recipient_spend_pubkey;
use crate::signature::pqc_leaf_key_bytes;
use curve25519_dalek::scalar::Scalar;
use shekyl_address::Network;
use shekyl_curve_generators::T;
use shekyl_types::SigningPayloadHash;

const NET: NetworkId = [0x4E; 16];

struct Group {
    address: MultisigAddressPayload,
    group_sk: HybridKemSecretKey,
    member_sks: Vec<HybridKemSecretKey>,
}

fn kem_pubkey_bytes(pk: &crate::kem::HybridKemPublicKey) -> Vec<u8> {
    let mut out = pk.x25519.to_vec();
    out.extend_from_slice(&pk.ml_kem);
    out
}

fn group(n: u8, m: u8) -> Group {
    let kem = HybridX25519MlKem;
    let b = Scalar::random(&mut rand::rngs::OsRng);
    let y = Scalar::random(&mut rand::rngs::OsRng);
    let b_group = (curve25519_dalek::constants::ED25519_BASEPOINT_POINT * b)
        .compress()
        .to_bytes();
    let y_group = (*T * y).compress().to_bytes();
    let (group_pk, group_sk) = kem.keypair_generate().unwrap();
    let (member_pks, member_sks): (Vec<_>, Vec<_>) =
        (0..n).map(|_| kem.keypair_generate().unwrap()).unzip();
    let address = MultisigAddressPayload::new(
        Network::Testnet,
        n,
        m,
        b_group,
        y_group,
        kem_pubkey_bytes(&group_pk),
        member_pks.iter().map(kem_pubkey_bytes).collect(),
    )
    .unwrap();
    Group {
        address,
        group_sk,
        member_sks,
    }
}

fn tx_key() -> [u8; 32] {
    Scalar::random(&mut rand::rngs::OsRng).to_bytes()
}

fn group_ss(g: &Group, out: &MultisigOutputData) -> [u8; 64] {
    recover_combined_ss(
        &g.group_sk.x25519,
        &g.group_sk.ml_kem,
        &out.kem_ciphertext_x25519,
        &out.kem_ciphertext_ml_kem,
    )
    .unwrap()
    .0
}

fn member_view<'a>(g: &'a Group, i: u8) -> MultisigMemberView<'a> {
    MultisigMemberView {
        member_index: i,
        n_total: g.address.n_total(),
        m_required: g.address.m_required(),
        member_x25519_sk: &g.member_sks[usize::from(i)].x25519,
        member_ml_kem_dk: &g.member_sks[usize::from(i)].ml_kem,
        network: &NET,
    }
}

fn entry_view<'a>(
    out: &'a MultisigOutputData,
    i: u8,
    out_idx: u8,
    n: u8,
    enc_key_hashes: &'a [u8],
) -> MultisigEntryView<'a> {
    let ct = &out.member_kem_ciphertexts[usize::from(i)];
    let (x25519, ml_kem) = ct.split_at(X25519_KEM_CT_LEN);
    MultisigEntryView {
        out_idx,
        n,
        own_x25519_ct: x25519.try_into().expect("x25519 ciphertext is 32 bytes"),
        own_ml_kem_ct: ml_kem,
        enc_key_hashes,
    }
}

fn open_as(
    g: &Group,
    out: &MultisigOutputData,
    index: u64,
    i: u8,
    n: u8,
    enc_key_hashes: &[u8],
    leaf: &[u8; PQC_LEAF_ENTRY_LEN],
) -> Result<MultisigCommittedForm, MultisigReceiveError> {
    let out_idx = u8::try_from(index).unwrap();
    open_multisig_entry(
        &group_ss(g, out),
        index,
        &member_view(g, i),
        &entry_view(out, i, out_idx, n, enc_key_hashes),
        leaf,
    )
}

/// Member `i`'s signature on `msg`, through the production signer.
fn member_sign(
    g: &Group,
    out: &MultisigOutputData,
    index: u64,
    i: u8,
    msg: &SigningPayloadHash,
) -> Result<MultisigMemberSignature, MultisigSignError> {
    let n = g.address.n_total();
    sign_multisig_member_auth(
        &member_view(g, i),
        &entry_view(out, i, u8::try_from(index).unwrap(), n, &out.enc_key_hashes),
        msg,
    )
}

/// The receive positive and the spend positive together: every member opens
/// the output to the same committed form, that form is what the leaf
/// commits to, and any `m` members' keys make a spend `verify_multisig`
/// accepts.
#[test]
fn every_member_opens_the_output_and_any_m_can_spend() {
    for (n, m) in [(1u8, 1u8), (3, 2), (5, 3)] {
        let g = group(n, m);
        let index = 1u64;
        let out = construct_multisig_output(&tx_key(), &g.address, 7_000, index, &NET).unwrap();

        // The solo part: the group sees its own spend point.
        let spend = curve25519_dalek::edwards::CompressedEdwardsY(*g.address.b_group())
            .decompress()
            .unwrap()
            + curve25519_dalek::edwards::CompressedEdwardsY(*g.address.y_group())
                .decompress()
                .unwrap();
        let ss = group_ss(&g, &out);
        assert_eq!(
            recover_recipient_spend_pubkey(&ss, &out.output_key, index).unwrap(),
            spend.compress().to_bytes()
        );
        assert_eq!(out.member_kem_ciphertexts.len(), usize::from(n));
        assert_eq!(
            out.enc_key_hashes.len(),
            usize::from(n) * MULTISIG_KEY_HASH_LEN + MULTISIG_HASHES_TAG_LEN
        );

        let leaf = out.pqc_leaf.entry_bytes();
        let forms: Vec<MultisigCommittedForm> = (0..n)
            .map(|i| open_as(&g, &out, index, i, n, &out.enc_key_hashes, &leaf).unwrap())
            .collect();
        assert!(forms.windows(2).all(|w| w[0] == w[1]), "{m}-of-{n}");
        let committed = forms[0].clone();
        assert_eq!(committed.m_required(), m);

        // Any m signers: every subset of size m.
        let msg = SigningPayloadHash::from_bytes([0x5A; 64]);
        for mask in 0u8..(1 << n) {
            if mask.count_ones() != u32::from(m) {
                continue;
            }
            let signers: Vec<u8> = (0..n).filter(|i| mask & (1 << i) != 0).collect();
            let signed: Vec<MultisigMemberSignature> = signers
                .iter()
                .map(|&i| member_sign(&g, &out, index, i, &msg).unwrap())
                .collect();
            let key = MultisigKeyBlob::assemble(
                committed.clone(),
                signed
                    .iter()
                    .map(|s| (s.member_index, s.public_key.clone()))
                    .collect(),
            )
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
            let sig = MultisigSigContainer {
                sig_count: m,
                sigs: signed.iter().map(|s| s.signature.clone()).collect(),
                signer_indices: signers.clone(),
            }
            .to_canonical_bytes()
            .unwrap();
            assert_eq!(
                verify_multisig(HYBRID_SCHEME_ID_MULTISIG, &key, &sig, &msg, &NET),
                Ok(()),
                "{m}-of-{n} signers {signers:?}"
            );
            // The leaf the consensus derives k from is the committed form.
            assert_eq!(
                pqc_leaf_key_bytes(HYBRID_SCHEME_ID_MULTISIG, &key).unwrap(),
                committed.to_bytes().as_slice()
            );
        }
    }
}

/// The per-member ciphertexts use distinct randomness: no two share an
/// ephemeral key, and none shares the group ciphertext's.
#[test]
fn member_ciphertexts_never_share_randomness() {
    let g = group(5, 3);
    let out = construct_multisig_output(&tx_key(), &g.address, 1, 0, &NET).unwrap();
    let mut ephemerals: Vec<&[u8]> = out
        .member_kem_ciphertexts
        .iter()
        .map(|ct| &ct[..X25519_KEM_CT_LEN])
        .collect();
    ephemerals.push(&out.kem_ciphertext_x25519);
    let count = ephemerals.len();
    ephemerals.sort_unstable();
    ephemerals.dedup();
    assert_eq!(ephemerals.len(), count);
}

/// A member cannot stand in for another: its own secret on another
/// member's index yields a key whose hash is not the committed one.
#[test]
fn a_member_cannot_open_another_members_slot() {
    let g = group(3, 2);
    let out = construct_multisig_output(&tx_key(), &g.address, 1, 0, &NET).unwrap();
    let mut view = member_view(&g, 0);
    view.member_index = 1;
    assert_eq!(
        open_multisig_entry(
            &group_ss(&g, &out),
            0,
            &view,
            &entry_view(&out, 1, 0, g.address.n_total(), &out.enc_key_hashes),
            &out.pqc_leaf.entry_bytes(),
        ),
        Err(MultisigReceiveError::MemberKeyHash)
    );
}

/// A sender that lies about one member's hash is caught: that member sees
/// its own hash wrong, every other member sees the leaf not open.
#[test]
fn a_lie_about_one_members_hash_is_caught_by_every_member() {
    let g = group(3, 2);
    let index = 2u64;
    let out = construct_multisig_output(&tx_key(), &g.address, 1, index, &NET).unwrap();
    let ss = group_ss(&g, &out);
    let key = derive_multisig_key_hashes_key(&ss, index);
    let cipher = ChaCha20Poly1305::new((&*key).into());
    let aad = hashes_aad(2, 3);
    let mut hashes = cipher
        .decrypt(
            &Nonce::from(HASHES_NONCE),
            Payload {
                msg: &out.enc_key_hashes,
                aad: &aad,
            },
        )
        .unwrap();
    hashes[MULTISIG_KEY_HASH_LEN] ^= 1; // member 1's hash
    let lied = cipher
        .encrypt(
            &Nonce::from(HASHES_NONCE),
            Payload {
                msg: &hashes,
                aad: &aad,
            },
        )
        .unwrap();
    let leaf = out.pqc_leaf.entry_bytes();
    assert_eq!(
        open_as(&g, &out, index, 1, g.address.n_total(), &lied, &leaf),
        Err(MultisigReceiveError::MemberKeyHash)
    );
    for i in [0, 2] {
        assert_eq!(
            open_as(&g, &out, index, i, g.address.n_total(), &lied, &leaf),
            Err(MultisigReceiveError::LeafMismatch)
        );
    }
}

#[test]
fn a_damaged_entry_or_leaf_is_refused_by_name() {
    let g = group(3, 2);
    let index = 0u64;
    let out = construct_multisig_output(&tx_key(), &g.address, 1, index, &NET).unwrap();
    let leaf = out.pqc_leaf.entry_bytes();
    assert!(open_as(
        &g,
        &out,
        index,
        0,
        g.address.n_total(),
        &out.enc_key_hashes,
        &leaf
    )
    .is_ok());

    let mut tampered = out.enc_key_hashes.clone();
    tampered[0] ^= 1;
    assert_eq!(
        open_as(&g, &out, index, 0, g.address.n_total(), &tampered, &leaf),
        Err(MultisigReceiveError::HashesUndecryptable)
    );
    let mut other_leaf = leaf;
    other_leaf[40] ^= 1;
    assert_eq!(
        open_as(
            &g,
            &out,
            index,
            0,
            g.address.n_total(),
            &out.enc_key_hashes,
            &other_leaf
        ),
        Err(MultisigReceiveError::LeafMismatch)
    );
    // The entry's out_idx is authenticated: the hashes do not open as
    // another output's.
    assert_eq!(
        open_multisig_entry(
            &group_ss(&g, &out),
            index,
            &member_view(&g, 0),
            &entry_view(&out, 0, 1, g.address.n_total(), &out.enc_key_hashes),
            &leaf,
        ),
        Err(MultisigReceiveError::HashesUndecryptable)
    );
    // An entry that names a different group size.
    assert_eq!(
        open_multisig_entry(
            &group_ss(&g, &out),
            index,
            &member_view(&g, 0),
            &entry_view(&out, 0, 0, 2, &out.enc_key_hashes),
            &leaf,
        ),
        Err(MultisigReceiveError::GroupSize)
    );
}

/// The constructor refuses what it cannot build an output to.
#[test]
fn the_constructor_refuses_bad_inputs() {
    let g = group(2, 2);
    assert!(matches!(
        construct_multisig_output(&tx_key(), &g.address, 1, 256, &NET),
        Err(CryptoError::InvalidInput(_))
    ));

    // The address carries its points opaque; the constructor checks them.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let bad = rebuild(&g, identity, g.address.hybrid_kem_pubkeys().to_vec()).unwrap();
    assert!(matches!(
        construct_multisig_output(&tx_key(), &bad, 1, 0, &NET),
        Err(CryptoError::InvalidKeyMaterial)
    ));
}

/// The constructor encapsulates to the address's KEM keys unchecked: an
/// address with a repeated or aliased key cannot be made. With this
/// group's own keys, a member key that repeats the group key, repeats
/// another member, or is the group key with bit 255 of its X25519 half set
/// (the same Montgomery point) is refused by the address.
#[test]
fn an_address_with_collapsed_kem_slots_cannot_be_built() {
    use shekyl_address::multisig_address::MultisigAddressError;
    let g = group(2, 2);
    let y = *g.address.y_group();
    let group_key = g.address.group_kem_pubkey().to_vec();
    let members = g.address.hybrid_kem_pubkeys();

    assert!(matches!(
        rebuild(&g, y, vec![group_key.clone(), members[1].clone()]),
        Err(MultisigAddressError::GroupKemKeyRepeatsMember { index: 0 })
    ));
    assert!(matches!(
        rebuild(&g, y, vec![members[0].clone(), members[0].clone()]),
        Err(MultisigAddressError::DuplicateMemberKemKey {
            first: 0,
            second: 1
        })
    ));
    let mut alias = group_key;
    alias[31] |= 0x80;
    assert!(matches!(
        rebuild(&g, y, vec![alias, members[1].clone()]),
        Err(MultisigAddressError::NonCanonicalMemberKemKey { index: 0 })
    ));
}

/// `g`'s address with `y_group` and the member keys replaced.
fn rebuild(
    g: &Group,
    y_group: [u8; 32],
    members: Vec<Vec<u8>>,
) -> Result<MultisigAddressPayload, shekyl_address::multisig_address::MultisigAddressError> {
    MultisigAddressPayload::new(
        g.address.network(),
        g.address.n_total(),
        g.address.m_required(),
        *g.address.b_group(),
        y_group,
        g.address.group_kem_pubkey().to_vec(),
        members,
    )
}

/// A hash list that repeats a member, even when the leaf is recomputed over
/// that list, is refused by every member. The spend verifier would refuse
/// the same bytes as duplicate keys.
#[test]
fn duplicate_decrypted_key_hashes_are_refused() {
    let g = group(3, 2);
    let index = 0u64;
    let out = construct_multisig_output(&tx_key(), &g.address, 1, index, &NET).unwrap();
    let ss = group_ss(&g, &out);
    let key = derive_multisig_key_hashes_key(&ss, index);
    let cipher = ChaCha20Poly1305::new((&*key).into());
    let aad = hashes_aad(0, g.address.n_total());
    let mut hashes = cipher
        .decrypt(
            &Nonce::from(HASHES_NONCE),
            Payload {
                msg: &out.enc_key_hashes,
                aad: &aad,
            },
        )
        .unwrap();
    let width = MULTISIG_KEY_HASH_LEN;
    hashes.copy_within(0..width, width);
    let repeated = cipher
        .encrypt(
            &Nonce::from(HASHES_NONCE),
            Payload {
                msg: &hashes,
                aad: &aad,
            },
        )
        .unwrap();
    let key_hashes: Vec<[u8; MULTISIG_KEY_HASH_LEN]> = hashes
        .chunks_exact(width)
        .map(|chunk| chunk.try_into().unwrap())
        .collect();
    let committed = MultisigCommittedForm::new(g.address.m_required(), key_hashes).unwrap();
    let leaf = pqc_leaf_commitment(&ss, index, &committed.to_bytes()).unwrap();
    for i in 0..g.address.n_total() {
        assert_eq!(
            open_as(
                &g,
                &out,
                index,
                i,
                g.address.n_total(),
                &repeated,
                &leaf.entry_bytes()
            ),
            Err(MultisigReceiveError::DuplicateKeyHash),
            "member {i}"
        );
    }
}

/// The signer's refusals and what `verify_multisig` catches after it: a
/// group-size mismatch is refused before any decapsulation; a member signing
/// from another member's ciphertext gets a key whose hash is not the
/// committed one (ML-KEM's implicit rejection yields a key, not an error);
/// a signature over another message, or filed under another index, does not
/// verify.
#[test]
fn a_member_signature_verifies_only_as_that_member_over_that_message() {
    let (n, m) = (3u8, 2u8);
    let g = group(n, m);
    let index = 2u64;
    let out = construct_multisig_output(&tx_key(), &g.address, 9_000, index, &NET).unwrap();
    let leaf = out.pqc_leaf.entry_bytes();
    let committed = open_as(&g, &out, index, 0, n, &out.enc_key_hashes, &leaf).unwrap();
    let msg = SigningPayloadHash::from_bytes([0x21; 64]);
    let other_msg = SigningPayloadHash::from_bytes([0x22; 64]);

    let verify = |signed: &[MultisigMemberSignature], indices: &[u8], over: &SigningPayloadHash| {
        let key = MultisigKeyBlob::assemble(
            committed.clone(),
            indices
                .iter()
                .zip(signed)
                .map(|(&i, s)| (i, s.public_key.clone()))
                .collect(),
        )
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
        let sig = MultisigSigContainer {
            sig_count: m,
            sigs: signed.iter().map(|s| s.signature.clone()).collect(),
            signer_indices: indices.to_vec(),
        }
        .to_canonical_bytes()
        .unwrap();
        verify_multisig(HYBRID_SCHEME_ID_MULTISIG, &key, &sig, over, &NET)
    };

    let a = member_sign(&g, &out, index, 0, &msg).unwrap();
    let b = member_sign(&g, &out, index, 2, &msg).unwrap();
    assert_eq!(verify(&[a.clone(), b.clone()], &[0, 2], &msg), Ok(()));
    assert!(verify(&[a.clone(), b.clone()], &[0, 2], &other_msg).is_err());
    assert!(
        verify(&[a.clone(), b.clone()], &[0, 1], &msg).is_err(),
        "member 2's key filed as member 1's"
    );

    // Member 0's secret against member 1's ciphertext.
    let crossed = sign_multisig_member_auth(
        &member_view(&g, 0),
        &entry_view(
            &out,
            1,
            u8::try_from(index).unwrap(),
            n,
            &out.enc_key_hashes,
        ),
        &msg,
    )
    .unwrap();
    assert!(verify(&[crossed, b], &[0, 2], &msg).is_err());

    assert_eq!(
        sign_multisig_member_auth(
            &member_view(&g, 0),
            &entry_view(
                &out,
                0,
                u8::try_from(index).unwrap(),
                n + 1,
                &out.enc_key_hashes
            ),
            &msg,
        )
        .err(),
        Some(MultisigSignError::GroupSize)
    );
}
