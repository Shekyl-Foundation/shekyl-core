// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fixtures shared by the end-to-end tests: a dealt group with its member
//! files, outputs paid to it with slice 1's constructor, each member's scan
//! of them, and the tree that holds them.

// Each test binary uses some of these.
#![allow(dead_code)]
// CLIPPY(non_snake_case): `O`, `C`, `CM` are the FCMP++ notation.
#![allow(non_snake_case)]

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
use shekyl_fcmp::frost_sal::{dealer_split, threshold_keys, Ed25519T, ThresholdKeys};
use shekyl_fcmp::proof::{BranchLayer, ProveInputLeafChunk};
use shekyl_fcmp::tree::{
    build_layers, construct_leaf, ed25519_point_to_selene_scalar, key_image_generator,
    selene_point_to_helios_scalar,
};
use shekyl_multisig::{MemberFile, MemberSecrets};
use shekyl_types::CurveTreeRoot;

pub mod wallet;

/// The network every fixture is on.
pub const NET: [u8; 16] = [0x4E; 16];

pub fn random_scalar() -> DalekScalar {
    let mut wide = [0u8; 64];
    OsRng.fill_bytes(&mut wide);
    DalekScalar::from_bytes_mod_order_wide(&wide)
}

pub fn kem_bytes(pk: &HybridKemPublicKey) -> Vec<u8> {
    [pk.x25519.as_slice(), &pk.ml_kem].concat()
}

/// A new `m`-of-`n` group: the address, and each member's file as written
/// to disk and read back.
pub fn found_group(n: u8, m: u8) -> (MultisigAddressPayload, Vec<MemberFile>) {
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
pub fn load_keys(file: &MemberFile) -> ThresholdKeys<Ed25519T> {
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
pub struct Scanned {
    pub x: Zeroizing<[u8; 32]>,
    pub y_kem: Zeroizing<[u8; 32]>,
    pub z: Zeroizing<[u8; 32]>,
    pub key_image: KeyImage,
    pub committed_form: Vec<u8>,
    pub blind: Zeroizing<[u8; 32]>,
}

pub fn scan(file: &MemberFile, out: &MultisigOutputData, index: u64) -> Scanned {
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

/// Two outputs paid to a group, as every member scans them, and the tree
/// that holds them.
pub struct GroupOutputs {
    /// Each output, its index in its transaction, and its amount.
    pub outputs: Vec<(MultisigOutputData, u64, u64)>,
    /// What every member's scan recovers, per output.
    pub scans: Vec<Scanned>,
    /// The tree's root.
    pub root: CurveTreeRoot,
    /// The tree's layer count.
    pub layers: u8,
    /// Each output's leaf chunk and branch, for the prover.
    pub chunks: Vec<ProveInputLeafChunk>,
}

/// The sender pays the group twice (500 and 700), in two transactions;
/// every member scans both alone and recovers the same values; the tree
/// holds both outputs in one leaf chunk, as the daemon builds it.
pub fn pay_group_twice(address: &MultisigAddressPayload, files: &[MemberFile]) -> GroupOutputs {
    let outputs: Vec<(MultisigOutputData, u64, u64)> = [(500u64, 0u64), (700, 3)]
        .into_iter()
        .map(|(amount, index)| {
            let tx_key = random_scalar().to_bytes();
            (
                construct_multisig_output(&tx_key, address, amount, index, &NET).unwrap(),
                index,
                amount,
            )
        })
        .collect();
    let scans: Vec<Scanned> = outputs
        .iter()
        .map(|(out, index, _)| {
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
    let (root, layers, chunks) = tree(&outputs, &scans);
    GroupOutputs {
        outputs,
        scans,
        root,
        layers,
        chunks,
    }
}

/// The leaf chunks of `paid`'s outputs again: the prover consumes them.
pub fn rebuild_chunks(paid: &GroupOutputs) -> Vec<ProveInputLeafChunk> {
    tree(&paid.outputs, &paid.scans).2
}

/// The tree that holds `outputs`, as the daemon builds it: its root, its
/// layer count, and each output's leaf chunk and branch.
fn tree(
    outputs: &[(MultisigOutputData, u64, u64)],
    scans: &[Scanned],
) -> (CurveTreeRoot, u8, Vec<ProveInputLeafChunk>) {
    let leaf_outputs: Vec<([u8; 32], [u8; 32], [u8; 32])> = outputs
        .iter()
        .map(|(out, _, _)| {
            (
                out.output_key,
                key_image_generator(&out.output_key),
                out.commitment,
            )
        })
        .collect();
    let leaf_cm_x: Vec<[u8; 32]> = outputs
        .iter()
        .map(|(out, _, _)| ed25519_point_to_selene_scalar(&out.pqc_leaf.point).unwrap())
        .collect();
    let leaf_scalars: Vec<[u8; 32]> = outputs
        .iter()
        .flat_map(|(out, _, _)| {
            let leaf =
                construct_leaf(&out.output_key, &out.commitment, &out.pqc_leaf.point).unwrap();
            leaf.chunks_exact(32)
                .map(|c| c.try_into().unwrap())
                .collect::<Vec<_>>()
        })
        .collect();
    let layers = build_layers(&leaf_scalars);
    assert_eq!(
        layers.len(),
        2,
        "two leaves: a leaf chunk and the root above it"
    );
    let root = CurveTreeRoot::from_bytes(layers[1][0]);
    let depth = u8::try_from(layers.len()).unwrap();
    let helios_chunk = vec![selene_point_to_helios_scalar(&layers[0][0]).unwrap()];
    let chunks = outputs
        .iter()
        .zip(scans)
        .map(|((out, _, _), s)| ProveInputLeafChunk {
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
    (root, depth, chunks)
}
