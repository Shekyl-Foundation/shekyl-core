// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! An Option E′ multisig spend, end to end: a dealer splits a new group,
//! each member's file is written and read back, a sender pays the group
//! twice with slice 1's `construct_multisig_output`, every member scans
//! both outputs alone, and M members sign both inputs' SAL with FROST from
//! their loaded files. The SALs go into one FCMP++ proof, which verifies
//! against the tree that holds the two outputs.
//!
//! `x = ho + b` and `y_kem` are what each member's scan recovers, not
//! synthetic values: this is where slice 1's outputs and slice 2's signing
//! meet.

// CLIPPY(non_snake_case): `O`, `C`, `CM` are the FCMP++ notation.
#![allow(non_snake_case)]

use std::collections::HashMap;

use ciphersuite::group::GroupEncoding;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::Scalar as DalekScalar;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use shekyl_address::multisig_address::MultisigAddressPayload;
use shekyl_address::Network;
use shekyl_crypto_pq::derivation::derive_output_secrets;
use shekyl_crypto_pq::kem::{
    HybridKemPublicKey, HybridX25519MlKem, KeyEncapsulation, X25519_KEM_CT_LEN,
};
use shekyl_crypto_pq::key_image::KeyImage;
use shekyl_crypto_pq::leaf_commitment::pqc_leaf_commitment;
use shekyl_crypto_pq::multisig_envelope::mint_multisig_envelope_keypair;
use shekyl_crypto_pq::multisig_output::{
    construct_multisig_output, open_multisig_entry, MultisigEntryView, MultisigMemberView,
    MultisigOutputData,
};
use shekyl_crypto_pq::output::{compute_output_key_image, recover_combined_ss};
use shekyl_fcmp::frost_sal::{
    complete, dealer_split, preprocess, sign, threshold_keys, Ed25519T, Participant,
    SalSigningParams, SpentOutput, ThresholdKeys, RERANDOMIZATION_SEED_LEN,
};
use shekyl_fcmp::proof::{prove_with_sal, verify, BranchLayer, ProveInputLeafChunk};
use shekyl_fcmp::tree::{
    build_layers, construct_leaf, ed25519_point_to_selene_scalar, key_image_generator,
    selene_point_to_helios_scalar,
};
use shekyl_fcmp::{PqcKeyScalar, SpendAuthAndLinkability};
use shekyl_multisig::{MemberFile, MemberSecrets};
use shekyl_types::{CurveTreeRoot, TxSignableHash};

const NET: [u8; 16] = [0x4E; 16];
const SIGNABLE: TxSignableHash = TxSignableHash::from_bytes([0xC3; 32]);

fn random_scalar() -> DalekScalar {
    let mut wide = [0u8; 64];
    OsRng.fill_bytes(&mut wide);
    DalekScalar::from_bytes_mod_order_wide(&wide)
}

fn kem_bytes(pk: &HybridKemPublicKey) -> Vec<u8> {
    [pk.x25519.as_slice(), &pk.ml_kem].concat()
}

/// A new `m`-of-`n` group: the address, and each member's file as written
/// to disk and read back.
fn found_group(n: u8, m: u8) -> (MultisigAddressPayload, Vec<MemberFile>) {
    let kem = HybridX25519MlKem;
    let b = random_scalar();
    let split = dealer_split(n, m, &mut OsRng).unwrap();
    let (group_pk, group_sk) = kem.keypair_generate().unwrap();
    let (member_pks, member_sks): (Vec<_>, Vec<_>) =
        (0..n).map(|_| kem.keypair_generate().unwrap()).unzip();
    let address = MultisigAddressPayload::new(
        Network::Testnet,
        n,
        m,
        (ED25519_BASEPOINT_POINT * b).compress().to_bytes(),
        split.y_group,
        kem_bytes(&group_pk),
        member_pks.iter().map(kem_bytes).collect(),
    )
    .unwrap();
    let mut transport = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(transport.as_mut());
    let envelope_keys: Vec<_> = (0..n)
        .map(|_| mint_multisig_envelope_keypair(&mut OsRng).unwrap())
        .collect();
    let envelope_publics: Vec<_> = envelope_keys.iter().map(|(pk, _)| pk.clone()).collect();

    let files = (0u8..)
        .zip(envelope_keys)
        .map(|(i, (_, envelope_secret))| {
            let secret = |sk: &shekyl_crypto_pq::kem::HybridKemSecretKey| {
                Zeroizing::new([sk.x25519.as_slice(), &sk.ml_kem].concat())
            };
            let file = MemberFile::new(
                address.clone(),
                i,
                split.verification_shares.clone(),
                envelope_publics.clone(),
                MemberSecrets {
                    b: Zeroizing::new(b.to_bytes()),
                    y_share: split.shares[usize::from(i)].clone(),
                    group_kem_secret: secret(&group_sk),
                    member_kem_secret: secret(&member_sks[usize::from(i)]),
                    transport_secret: transport.clone(),
                    envelope_secret,
                },
            )
            .unwrap();
            MemberFile::from_bytes(&file.to_bytes()).unwrap()
        })
        .collect();
    (address, files)
}

/// A member's FROST keys, from its file alone.
fn load_keys(file: &MemberFile) -> ThresholdKeys<Ed25519T> {
    let address = file.address();
    threshold_keys(
        address.n_total(),
        address.m_required(),
        file.member_index(),
        file.y_share(),
        file.verification_shares(),
        address.y_group(),
    )
    .unwrap()
}

/// What one member recovers from one output by scanning it alone. `x`,
/// `y_kem` and the blind are secrets: they wipe on drop, the type has no
/// `Debug`, and the tests compare with `==`, so a failure prints none of
/// them (rule 50).
#[derive(PartialEq, Eq)]
struct Scanned {
    x: Zeroizing<[u8; 32]>,
    y_kem: Zeroizing<[u8; 32]>,
    z: Zeroizing<[u8; 32]>,
    key_image: KeyImage,
    committed_form: Vec<u8>,
    blind: Zeroizing<[u8; 32]>,
}

fn scan(file: &MemberFile, out: &MultisigOutputData, index: u64) -> Scanned {
    let (group_x25519, group_ml_kem) = file.group_kem_secret().split_at(32);
    let ss = recover_combined_ss(
        group_x25519.try_into().unwrap(),
        group_ml_kem,
        &out.kem_ciphertext_x25519,
        &out.kem_ciphertext_ml_kem,
    )
    .unwrap()
    .0;
    let secrets = derive_output_secrets(&ss, index);
    let y_kem = Zeroizing::new(secrets.y);
    let z = Zeroizing::new(secrets.z);
    assert!(*y_kem == out.y, "the scan recovers the sender's y_kem");
    let spend =
        compute_output_key_image(&ss, index, file.b(), &key_image_generator(&out.output_key))
            .unwrap();

    let address = file.address();
    let (member_x25519, member_ml_kem) = file.member_kem_secret().split_at(32);
    let i = file.member_index();
    let (own_x25519, own_ml_kem) =
        out.member_kem_ciphertexts[usize::from(i)].split_at(X25519_KEM_CT_LEN);
    let committed = open_multisig_entry(
        &ss,
        index,
        &MultisigMemberView {
            member_index: i,
            n_total: address.n_total(),
            m_required: address.m_required(),
            member_x25519_sk: member_x25519.try_into().unwrap(),
            member_ml_kem_dk: member_ml_kem,
            network: &NET,
        },
        &MultisigEntryView {
            out_idx: u8::try_from(index).unwrap(),
            n: address.n_total(),
            own_x25519_ct: own_x25519.try_into().unwrap(),
            own_ml_kem_ct: own_ml_kem,
            enc_key_hashes: &out.enc_key_hashes,
        },
        &out.pqc_leaf.entry().to_bytes(),
    )
    .expect("the output is spendable by the group as published");
    let committed_form = committed.to_bytes().to_vec();
    let leaf = pqc_leaf_commitment(&ss, index, &committed_form).unwrap();
    assert_eq!(
        leaf.point, out.pqc_leaf.point,
        "the member re-derives the published CM"
    );
    Scanned {
        x: spend.spend_secret_x.clone(),
        y_kem,
        z,
        key_image: spend.key_image,
        committed_form,
        blind: Zeroizing::new(leaf.blind),
    }
}

fn others<V: Clone>(map: &HashMap<Participant, V>, me: Participant) -> HashMap<Participant, V> {
    map.iter()
        .filter(|(p, _)| **p != me)
        .map(|(p, v)| (*p, v.clone()))
        .collect()
}

/// `signers` sign one input; every signer's completed SAL, which must agree.
fn sign_input(
    params: &SalSigningParams,
    keys: &HashMap<Participant, ThresholdKeys<Ed25519T>>,
) -> SpendAuthAndLinkability {
    let (mut machines, preprocesses): (HashMap<_, _>, HashMap<_, _>) = keys
        .iter()
        .map(|(&p, k)| {
            let (machine, pre) = preprocess(params, k.clone(), &mut OsRng).unwrap();
            ((p, machine), (p, pre))
        })
        .unzip();
    let (machines, shares): (HashMap<_, _>, HashMap<_, _>) = keys
        .keys()
        .map(|&p| {
            let (machine, share) =
                sign(machines.remove(&p).unwrap(), others(&preprocesses, p)).unwrap();
            ((p, machine), (p, share))
        })
        .unzip();
    let sals: Vec<_> = machines
        .into_iter()
        .map(|(p, machine)| complete(machine, others(&shares, p)).unwrap())
        .collect();
    assert!(
        sals.windows(2).all(|w| w[0] == w[1]),
        "every signer completes the same SAL"
    );
    sals.into_iter().next().unwrap()
}

fn spend(n: u8, m: u8, signer_indices: &[u8]) {
    let (address, files) = found_group(n, m);
    for file in &files {
        assert_eq!(
            load_keys(file).group_key().to_bytes(),
            *address.y_group(),
            "the loaded shares open the address's Y_group"
        );
    }

    // The sender pays the group twice, in two transactions.
    let outputs: Vec<(MultisigOutputData, u64)> = [(500, 0u64), (700, 3u64)]
        .into_iter()
        .map(|(amount, index)| {
            let tx_key = random_scalar().to_bytes();
            (
                construct_multisig_output(&tx_key, &address, amount, index, &NET).unwrap(),
                index,
            )
        })
        .collect();

    // Every member scans both outputs alone and recovers the same values.
    let scans: Vec<Scanned> = outputs
        .iter()
        .map(|(out, index)| {
            let first = scan(&files[0], out, *index);
            for file in &files[1..] {
                assert!(
                    scan(file, out, *index) == first,
                    "every member recovers the same output"
                );
            }
            first
        })
        .collect();

    // The tree holds both outputs, in one leaf chunk.
    let leaf_outputs: Vec<([u8; 32], [u8; 32], [u8; 32])> = outputs
        .iter()
        .map(|(out, _)| {
            (
                out.output_key,
                key_image_generator(&out.output_key),
                out.commitment,
            )
        })
        .collect();
    let leaf_cm_x: Vec<[u8; 32]> = outputs
        .iter()
        .map(|(out, _)| ed25519_point_to_selene_scalar(&out.pqc_leaf.point).unwrap())
        .collect();
    let leaf_scalars: Vec<[u8; 32]> = outputs
        .iter()
        .flat_map(|(out, _)| {
            let leaf =
                construct_leaf(&out.output_key, &out.commitment, &out.pqc_leaf.point).unwrap();
            leaf.chunks_exact(32)
                .map(|c| c.try_into().unwrap())
                .collect::<Vec<_>>()
        })
        .collect();
    // As the daemon builds it: one Selene leaf chunk, and the Helios root
    // over it.
    let layers = build_layers(&leaf_scalars);
    assert_eq!(
        layers.len(),
        2,
        "two leaves: a leaf chunk and the root above it"
    );
    let root = CurveTreeRoot::from_bytes(layers[1][0]);
    let depth = u8::try_from(layers.len()).unwrap();
    let helios_chunk = vec![selene_point_to_helios_scalar(&layers[0][0]).unwrap()];

    // The proposer fixes each input's parameters from its own scan; the
    // signers sign from their loaded files.
    let blinds: Vec<Zeroizing<[u8; 32]>> = outputs
        .iter()
        .map(|_| Zeroizing::new(random_scalar().to_bytes()))
        .collect();
    let params: Vec<SalSigningParams> = outputs
        .iter()
        .zip(&scans)
        .zip(&blinds)
        .map(|(((out, _), s), a)| {
            let mut seed = [0u8; RERANDOMIZATION_SEED_LEN];
            OsRng.fill_bytes(&mut seed);
            let spent = SpentOutput {
                output_key: &out.output_key,
                commitment: &out.commitment,
                spend_scalar: &s.x,
                y_kem: &s.y_kem,
                commitment_mask: &s.z,
            };
            SalSigningParams::new(&seed, &spent, a, SIGNABLE).unwrap()
        })
        .collect();
    let keys: HashMap<Participant, ThresholdKeys<Ed25519T>> = signer_indices
        .iter()
        .map(|&i| {
            let keys = load_keys(&files[usize::from(i)]);
            (keys.params().i(), keys)
        })
        .collect();
    let sals: Vec<SpendAuthAndLinkability> = params.iter().map(|p| sign_input(p, &keys)).collect();

    let chunks: Vec<ProveInputLeafChunk> = outputs
        .iter()
        .zip(&scans)
        .map(|((out, _), s)| ProveInputLeafChunk {
            pqc_leaf_commitment: out.pqc_leaf.point,
            pqc_leaf_blind: *s.blind,
            leaf_outputs: leaf_outputs.clone(),
            leaf_cm_x: leaf_cm_x.clone(),
            c1_branch_layers: vec![],
            c2_branch_layers: vec![BranchLayer {
                siblings: helios_chunk.clone(),
            }],
        })
        .collect();
    let proved = prove_with_sal(
        params
            .iter()
            .map(|p| p.rerandomized().input())
            .zip(sals)
            .collect(),
        &params
            .iter()
            .map(SalSigningParams::output)
            .collect::<Vec<_>>(),
        &params
            .iter()
            .map(|p| p.rerandomized().clone())
            .collect::<Vec<_>>(),
        &chunks,
        depth,
    )
    .unwrap();

    let key_images: Vec<KeyImage> = scans.iter().map(|s| s.key_image).collect();
    let pqc_keys: Vec<PqcKeyScalar> = scans
        .iter()
        .map(|s| PqcKeyScalar::from_pqc_public_key(&s.committed_form))
        .collect();
    let verified = verify(
        &proved.proof,
        &key_images,
        &proved.pseudo_outs,
        &pqc_keys,
        &root,
        depth,
        SIGNABLE,
    );
    assert!(matches!(verified, Ok(true)), "{m}-of-{n}: {verified:?}");

    // Each pseudo-out opens to the blind the assembler chose and the input's
    // amount (`C~ = a·G + amount·H`), so the last one can be balanced.
    for ((pseudo_out, a), amount) in proved.pseudo_outs.iter().zip(&blinds).zip([500u64, 700]) {
        let a = DalekScalar::from_canonical_bytes(**a).unwrap();
        let expected =
            ED25519_BASEPOINT_POINT * a + *shekyl_curve_generators::H * DalekScalar::from(amount);
        assert!(
            *pseudo_out == expected.compress().to_bytes(),
            "{m}-of-{n}: the pseudo-out opens to its chosen blind"
        );
    }

    // The proof is over this transaction's message and no other.
    let other = TxSignableHash::from_bytes([0x3C; 32]);
    let refused = verify(
        &proved.proof,
        &key_images,
        &proved.pseudo_outs,
        &pqc_keys,
        &root,
        depth,
        other,
    );
    assert!(
        !matches!(refused, Ok(true)),
        "{m}-of-{n}: another message must not verify"
    );
}

#[test]
fn two_of_three_members_spend_two_group_outputs() {
    spend(3, 2, &[0, 2]);
}

#[test]
fn three_of_five_members_spend_two_group_outputs() {
    spend(5, 3, &[1, 3, 4]);
}
