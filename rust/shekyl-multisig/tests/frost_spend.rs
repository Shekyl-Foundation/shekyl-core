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

mod common;

use std::collections::HashMap;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::Scalar as DalekScalar;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use ciphersuite::group::GroupEncoding;
use common::{found_group, load_keys, pay_group_twice, random_scalar};
use shekyl_crypto_pq::key_image::KeyImage;
use shekyl_fcmp::frost_sal::{
    complete, preprocess, sign, Ed25519T, Participant, SalSigningParams, SpentOutput,
    ThresholdKeys, RERANDOMIZATION_SEED_LEN,
};
use shekyl_fcmp::proof::{prove_with_sal, verify};
use shekyl_fcmp::{PqcKeyScalar, SpendAuthAndLinkability};
use shekyl_types::TxSignableHash;

const SIGNABLE: TxSignableHash = TxSignableHash::from_bytes([0xC3; 32]);

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

    let paid = pay_group_twice(&address, &files);
    let (outputs, scans, root, depth) = (&paid.outputs, &paid.scans, &paid.root, paid.layers);

    // The proposer fixes each input's parameters from its own scan; the
    // signers sign from their loaded files.
    let blinds: Vec<Zeroizing<[u8; 32]>> = outputs
        .iter()
        .map(|_| Zeroizing::new(random_scalar().to_bytes()))
        .collect();
    let params: Vec<SalSigningParams> = outputs
        .iter()
        .zip(scans)
        .zip(&blinds)
        .map(|(((out, _, _), s), a)| {
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

    let chunks = &paid.chunks;
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
        chunks,
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
        root,
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
        root,
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
