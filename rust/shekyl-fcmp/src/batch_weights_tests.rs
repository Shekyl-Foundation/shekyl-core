// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The FCMP++ batch weights' seed (ruling R3, 2026-10-15): the preimage
//! pinned, every input kind committed to, the two verifies' domains apart.
//! That a real proof verifies under the derived weights, and a flipped one
//! does not, is `proof::tests::prove_verify_roundtrip`'s; every captured
//! chain's spends verifying is `shekyl-chain-ingest`'s replay.

use super::{
    BatchKind, BatchWeights, FCMP_MEMBERSHIP_ONLY_BATCH_WEIGHTS_CUSTOMIZATION,
    FCMP_PP_BATCH_WEIGHTS_CUSTOMIZATION,
};
use crate::proof::{KeyImage, ShekylFcmpProof};

/// Fixed inputs: two inputs, three layers, each value a distinct byte
/// pattern. The seed reads bytes, never validity.
struct Inputs {
    proof: ShekylFcmpProof,
    layers: u8,
    root: [u8; 32],
    hash: [u8; 32],
    key_images: Vec<[u8; 32]>,
    pqc: Vec<[u8; 32]>,
    pseudo: Vec<[u8; 32]>,
}

fn fixed() -> Inputs {
    Inputs {
        proof: ShekylFcmpProof {
            data: (0..96u8).collect(),
            num_inputs: 2,
            tree_depth: 3,
        },
        layers: 3,
        root: [0x11; 32],
        hash: [0x22; 32],
        key_images: vec![[0x33; 32], [0x34; 32]],
        pqc: vec![[0x44; 32], [0x45; 32]],
        pseudo: vec![[0x55; 32], [0x56; 32]],
    }
}

fn statement<'a>(inputs: &'a Inputs, key_images: Option<&'a [KeyImage]>) -> BatchWeights<'a> {
    BatchWeights {
        proof: &inputs.proof,
        layers: inputs.layers,
        tree_root: &inputs.root,
        signable_tx_hash: &inputs.hash,
        kind: match key_images {
            Some(key_images) => BatchKind::Full { key_images },
            None => BatchKind::MembershipOnly,
        },
        pqc_key_points: &inputs.pqc,
        pseudo_outs: &inputs.pseudo,
    }
}

fn key_images_of(inputs: &Inputs) -> Vec<KeyImage> {
    inputs
        .key_images
        .iter()
        .map(|bytes| KeyImage::from_canonical_bytes(*bytes))
        .collect()
}

fn full_seed(inputs: &Inputs) -> [u8; 32] {
    let key_images = key_images_of(inputs);
    statement(inputs, Some(&key_images)).seed()
}

fn membership_only_seed(inputs: &Inputs) -> [u8; 32] {
    statement(inputs, None).seed()
}

/// The one test call of cSHAKE: the cross-domain check hashes one preimage
/// under a domain the statement did not choose. Production seeding is
/// [`BatchWeights::seed`].
fn hash_under(domain: &[u8], preimage: &[u8]) -> [u8; 32] {
    shekyl_crypto_hash::cshake256_32(domain, preimage)
}

/// The KAT: both seeds for the fixed inputs, pinned, and the full
/// preimage equal to its documented layout built by hand.
#[test]
fn the_seeds_of_fixed_inputs_are_pinned() {
    let inputs = fixed();
    let mut by_hand = 96u32.to_le_bytes().to_vec();
    by_hand.extend(0..96u8);
    by_hand.extend_from_slice(&2u32.to_le_bytes());
    by_hand.push(3);
    by_hand.extend_from_slice(&[0x11; 32]);
    by_hand.extend_from_slice(&[0x22; 32]);
    for list in [
        [[0x33u8; 32], [0x34; 32]],
        [[0x44; 32], [0x45; 32]],
        [[0x55; 32], [0x56; 32]],
    ] {
        by_hand.extend_from_slice(&2u32.to_le_bytes());
        for item in list {
            by_hand.extend_from_slice(&item);
        }
    }
    let key_images = key_images_of(&inputs);
    assert_eq!(statement(&inputs, Some(&key_images)).preimage(), by_hand);
    assert_eq!(
        full_seed(&inputs),
        [
            0x86, 0x11, 0x1a, 0x24, 0x8c, 0xea, 0xa4, 0x0b, 0x25, 0x56, 0xdd, 0x93, 0x04, 0x10,
            0x9e, 0x2f, 0x10, 0x03, 0xc8, 0xa8, 0x56, 0xd1, 0xf1, 0xaf, 0xe2, 0x40, 0x53, 0xc6,
            0x08, 0x26, 0xe3, 0x84,
        ],
        "the full verify's seed moved: a preimage change is a new domain (-v2), not a re-pin"
    );
    assert_eq!(
        membership_only_seed(&inputs),
        [
            0xa0, 0x2d, 0x99, 0x5d, 0x4e, 0x1b, 0x5a, 0xe1, 0xdc, 0x37, 0x84, 0x85, 0xf5, 0xad,
            0x97, 0xf7, 0xd9, 0xa0, 0x5c, 0x3a, 0x22, 0x44, 0x38, 0x62, 0x92, 0x00, 0x23, 0xee,
            0xcb, 0x99, 0x2c, 0x05,
        ],
        "the membership-only seed moved: a preimage change is a new domain (-v2)"
    );
}

/// Every byte of `pick(inputs)` moves both seeds (the membership-only seed
/// does not read key images, so that kind is checked on the full seed
/// alone).
fn every_byte_moves(kind: &str, pick: fn(&mut Inputs) -> &mut [u8], key_image: bool) {
    let base = fixed();
    let (full_base, membership_base) = (full_seed(&base), membership_only_seed(&base));
    let len = pick(&mut fixed()).len();
    assert!(len > 0, "{kind}: no bytes to flip");
    for at in 0..len {
        let mut moved = fixed();
        pick(&mut moved)[at] ^= 1;
        assert_ne!(
            full_seed(&moved),
            full_base,
            "{kind} byte {at}: full seed did not move"
        );
        if !key_image {
            assert_ne!(
                membership_only_seed(&moved),
                membership_base,
                "{kind} byte {at}: membership-only seed did not move"
            );
        }
    }
}

#[test]
fn every_proof_byte_moves_the_seed() {
    every_byte_moves("proof", |inputs| inputs.proof.data.as_mut_slice(), false);
}

/// The proof's input count, every bit of it.
#[test]
fn the_input_count_moves_the_seed() {
    let base = fixed();
    for bit in 0..32 {
        let mut moved = fixed();
        moved.proof.num_inputs ^= 1 << bit;
        assert_ne!(full_seed(&moved), full_seed(&base), "num_inputs bit {bit}");
        assert_ne!(
            membership_only_seed(&moved),
            membership_only_seed(&base),
            "num_inputs bit {bit}"
        );
    }
}

#[test]
fn the_layer_count_moves_the_seed() {
    every_byte_moves(
        "layers",
        |inputs| core::slice::from_mut(&mut inputs.layers),
        false,
    );
}

#[test]
fn every_tree_root_byte_moves_the_seed() {
    every_byte_moves("tree root", |inputs| &mut inputs.root, false);
}

#[test]
fn every_signable_hash_byte_moves_the_seed() {
    every_byte_moves("signable hash", |inputs| &mut inputs.hash, false);
}

#[test]
fn every_key_image_byte_moves_the_full_seed() {
    every_byte_moves("key image", |inputs| &mut inputs.key_images[1], true);
}

#[test]
fn every_pqc_key_point_byte_moves_the_seed() {
    every_byte_moves("pqc key point", |inputs| &mut inputs.pqc[1], false);
}

#[test]
fn every_pseudo_out_byte_moves_the_seed() {
    every_byte_moves("pseudo-out", |inputs| &mut inputs.pseudo[1], false);
}

/// The two verifies are separate messages: the same preimage, under the
/// two domains, is two seeds.
#[test]
fn the_two_verifies_seed_under_separate_domains() {
    let inputs = fixed();
    let preimage = statement(&inputs, None).preimage();
    assert_ne!(
        hash_under(FCMP_PP_BATCH_WEIGHTS_CUSTOMIZATION, &preimage),
        hash_under(FCMP_MEMBERSHIP_ONLY_BATCH_WEIGHTS_CUSTOMIZATION, &preimage),
    );
}
