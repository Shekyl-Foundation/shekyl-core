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
    HybridKemPublicKey, HybridX25519MlKem, KeyEncapsulation, MlKemDecapsKey, X25519_KEM_CT_LEN,
};
use shekyl_crypto_pq::key_image::KeyImage;
use shekyl_crypto_pq::leaf_commitment::pqc_leaf_commitment;
use shekyl_crypto_pq::multisig_envelope::mint_multisig_envelope_keypair;
use shekyl_crypto_pq::multisig_output::{
    construct_multisig_output, MultisigMemberView, MultisigOutputData,
};
use shekyl_crypto_pq::multisig_receive::{
    receive_group_output, GroupEntryOnChain, GroupOutputOnChain, GroupReceipt, GroupReceived,
    GroupScanKeys,
};
use shekyl_crypto_pq::output::{compute_output_key_image, recover_combined_ss};
use shekyl_curve_tree::{ChunkLeaf, PathParts};
use shekyl_fcmp::frost_sal::{dealer_split, threshold_keys, Ed25519T, ThresholdKeys};
use shekyl_fcmp::proof::{BranchLayer, ProveInputLeafChunk};
use shekyl_fcmp::tree::{
    build_layers, construct_leaf, ed25519_point_to_selene_scalar, key_image_generator,
    selene_point_to_helios_scalar,
};
use shekyl_multisig::{MemberFile, MemberSecrets};
use shekyl_types::{CommitmentBytes, CurveTreeRoot, OneTimePubkey};

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
            let file = MemberFile::new(
                address.clone(),
                i,
                split.verification_shares.clone(),
                envelope_publics.clone(),
                MemberSecrets {
                    b: Zeroizing::new(b.to_bytes()),
                    y_share: split.shares[usize::from(i)].clone(),
                    group_kem_secret: group_sk.clone(),
                    member_kem_secret: member_sks[usize::from(i)].clone(),
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
    let group = file.group_kem_secret();
    let ss = recover_combined_ss(
        &group.x25519,
        &group.ml_kem,
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

    let receipt = receive(file, out, index);
    assert_eq!(
        receipt.key_image(),
        &spend.key_image,
        "the receipt's key image is the scan's"
    );
    let committed_form = receipt.committed_form().to_bytes().to_vec();
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

/// `file`'s receive of `out`, the output at `index` in its transaction, as
/// the chain carries it: the receipt `shekyl-crypto-pq` returns, the only
/// thing a group coin is made from.
pub fn receive(file: &MemberFile, out: &MultisigOutputData, index: u64) -> GroupReceipt {
    let group = file.group_kem_secret();
    let dk = MlKemDecapsKey::from_bytes(&group.ml_kem).unwrap();
    let address = file.address();
    let point = |bytes: &[u8; 32]| {
        curve25519_dalek::edwards::CompressedEdwardsY(*bytes)
            .decompress()
            .unwrap()
    };
    let spend_key = (point(address.b_group()) + point(address.y_group()))
        .compress()
        .to_bytes();
    let enc_amount = out.enc_amount_wire().to_bytes();
    let enc_label = out.enc_label_wire().to_bytes();
    let leaf = out.pqc_leaf.entry().to_bytes();
    let on_chain = GroupOutputOnChain {
        output_index: index,
        output_key: &out.output_key,
        commitment: &out.commitment,
        enc_amount: enc_amount[..8].try_into().unwrap(),
        amount_tag: enc_amount[8],
        enc_label: enc_label[..8].try_into().unwrap(),
        label_tag: enc_label[8],
        view_tag: out.view_tag_prefilter,
        source_x25519_ct: &out.kem_ciphertext_x25519,
        source_ml_kem_ct: &out.kem_ciphertext_ml_kem,
        leaf_entry: Some(&leaf),
        entry: Some(GroupEntryOnChain {
            out_idx: u8::try_from(index).unwrap(),
            member_cts: out
                .member_kem_ciphertexts
                .iter()
                .map(|ct| {
                    let (x25519, ml_kem) = ct.split_at(X25519_KEM_CT_LEN);
                    (x25519.try_into().unwrap(), ml_kem)
                })
                .collect(),
            enc_key_hashes: &out.enc_key_hashes,
        }),
    };
    let received = receive_group_output(
        &GroupScanKeys {
            view_x25519: &group.x25519,
            view_ml_kem: &dk,
            spend_key: &spend_key,
            b: file.b(),
        },
        &MultisigMemberView {
            member_index: file.member_index(),
            n_total: address.n_total(),
            m_required: address.m_required(),
            member_kem_secret: file.member_kem_secret(),
            network: &NET,
        },
        &on_chain,
    );
    match received {
        Some(GroupReceived::Coin(receipt)) => receipt,
        other => panic!("the output is spendable by the group as published: {other:?}"),
    }
}

/// Two outputs paid to a group, as every member scans them, and the tree
/// that holds them.
pub struct Paid {
    /// Each output, its index in its transaction, and its amount.
    pub outputs: Vec<(MultisigOutputData, u64, u64)>,
    /// What every member's scan recovers, per output.
    pub scans: Vec<Scanned>,
    /// The tree's root.
    pub root: CurveTreeRoot,
    /// The tree's layer count.
    pub layers: u8,
    /// Each output's leaf chunk and branch with its blind, for a prover
    /// outside the ceremony.
    pub chunks: Vec<ProveInputLeafChunk>,
    /// The public path both outputs have in the tree (they share one leaf
    /// chunk), as parts a test batch is built from.
    pub path: PathParts,
}

/// The amounts [`pay_group_twice`] pays, in output order.
pub const AMOUNTS: [u64; 2] = [500, 700];

/// Each paid output's index in its transaction.
const OUTPUT_INDICES: [u64; 2] = [0, 3];

/// The sender pays the group twice ([`AMOUNTS`]), in two transactions;
/// every member scans both alone and recovers the same values; the tree
/// holds both outputs in one leaf chunk, as the daemon builds it.
pub fn pay_group_twice(address: &MultisigAddressPayload, files: &[MemberFile]) -> Paid {
    let outputs: Vec<(MultisigOutputData, u64, u64)> = AMOUNTS
        .into_iter()
        .zip(OUTPUT_INDICES)
        .map(|(amount, index)| {
            let tx_key = shekyl_crypto_pq::TxKey::random().expect("the OS draws a key");
            (
                construct_multisig_output(
                    tx_key
                        .output_positions(usize::try_from(index).unwrap() + 1)
                        .at(index)
                        .unwrap(),
                    address,
                    amount,
                    &NET,
                )
                .unwrap(),
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
    let (root, layers, chunks, path) = tree(&outputs, &scans);
    Paid {
        outputs,
        scans,
        root,
        layers,
        chunks,
        path,
    }
}

/// The tree that holds `outputs`, as the daemon builds it: its root, its
/// layer count, and each output's leaf chunk and branch, with its blind
/// and as the public path both outputs have in it.
fn tree(
    outputs: &[(MultisigOutputData, u64, u64)],
    scans: &[Scanned],
) -> (CurveTreeRoot, u8, Vec<ProveInputLeafChunk>, PathParts) {
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
    // The tree is real and its root is the fold of these branches, but the
    // path is written out rather than assembled from a client, so a batch
    // of it is built through the test-only constructor (R-25, R-26).
    let path = PathParts {
        leaf_chunk: leaf_outputs
            .iter()
            .zip(&leaf_cm_x)
            .map(
                |(&(output_key, key_image_gen, commitment), &cm_x)| ChunkLeaf {
                    output_key: OneTimePubkey::from_bytes(output_key),
                    key_image_gen,
                    commitment: CommitmentBytes::from_bytes(commitment),
                    cm_x,
                },
            )
            .collect(),
        c1_layers: vec![],
        c2_layers: vec![helios_chunk],
    };
    (root, depth, chunks, path)
}
