// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A torsion component on any point of a Bulletproof+ or its commitments
//! makes the proof fail to verify.
//!
//! Ed25519 has order `8·l`; a point plus a small-order point encodes
//! canonically and decompresses, so nothing at parse time refuses it. The
//! verifier clears the cofactor on the proof's points, which could make a
//! torsioned point verify as its prime-order part, and the proof malleable:
//! the same statement under different bytes. What refuses it is the
//! transcript, which hashes the points' bytes before they are used. This
//! test holds that, for each of the seven non-identity 8-torsion points
//! added to each of the proof's points (A, A1, B, every L and R) and to
//! each commitment.

use curve25519_dalek::constants::EIGHT_TORSION;

use shekyl_curve_io::CompressedPoint;
use shekyl_curve_primitives::Commitment;

use rand_core::{OsRng, RngCore};

use curve25519_dalek::scalar::Scalar;

use crate::{verify_batch, BatchEntry, Bulletproof};

/// A real two-output proof and its commitments.
fn real_entry() -> (Bulletproof, Vec<CompressedPoint>) {
    let openings = (0..2)
        .map(|_| Commitment::new(Scalar::random(&mut OsRng), OsRng.next_u64()))
        .collect::<Vec<_>>();
    let proof = Bulletproof::prove_plus(&mut OsRng, openings.clone()).expect("proves");
    let commitments = openings
        .iter()
        .map(|c| CompressedPoint::from(c.calculate().compress()))
        .collect();
    (proof, commitments)
}

fn verifies(proof: &Bulletproof, commitments: &[CompressedPoint]) -> bool {
    verify_batch(&[BatchEntry { proof, commitments }])
}

/// `bytes` with the torsion point added to the point at `offset`.
fn torsioned(bytes: &[u8; 32], torsion: usize) -> [u8; 32] {
    let point = CompressedPoint(*bytes)
        .decompress()
        .expect("a proof point decompresses");
    let moved = point + EIGHT_TORSION[torsion];
    let out = moved.compress().to_bytes();
    assert!(
        CompressedPoint(out).decompress().is_some(),
        "the torsioned point still encodes canonically, so only the verifier can refuse it"
    );
    out
}

/// The byte offsets of every point in a serialized proof: `A ‖ A1 ‖ B`,
/// three scalars, then `L` and `R`, each a one-byte count and its points.
fn point_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut offsets = vec![0, 32, 64];
    let mut at = 3 * 32 + 3 * 32;
    for _side in 0..2 {
        let count = usize::from(bytes[at]);
        assert!(count < 0x80, "a one-byte varint count");
        at += 1;
        for i in 0..count {
            offsets.push(at + 32 * i);
        }
        at += 32 * count;
    }
    assert_eq!(at, bytes.len(), "the offsets cover the whole proof");
    offsets
}

#[test]
fn a_torsion_component_on_any_proof_point_fails_verification() {
    let (proof, commitments) = real_entry();
    assert!(
        verifies(&proof, &commitments),
        "the untouched proof verifies"
    );
    let bytes = proof.serialize();
    let offsets = point_offsets(&bytes);
    // A, A1, B and seven rounds each of L and R for two outputs.
    assert_eq!(offsets.len(), 3 + 2 * 7, "the points of a two-output proof");
    let with = |offset: usize, torsion: usize| -> Bulletproof {
        let mut tampered = bytes.clone();
        let point: [u8; 32] = tampered[offset..offset + 32].try_into().expect("32 bytes");
        tampered[offset..offset + 32].copy_from_slice(&torsioned(&point, torsion));
        Bulletproof::read_plus(&mut tampered.as_slice())
            .expect("a canonically encoded point parses")
    };
    // The control: the identity (`EIGHT_TORSION[0]`) at every offset leaves
    // the proof verifying, so a refusal below is the torsion's and not the
    // offsets', the re-encoding's or the re-read's.
    for &offset in &offsets {
        assert!(
            verifies(&with(offset, 0), &commitments),
            "the identity at proof byte {offset} must change nothing"
        );
    }
    for torsion in 1..EIGHT_TORSION.len() {
        for &offset in &offsets {
            assert!(
                !verifies(&with(offset, torsion), &commitments),
                "torsion point {torsion} at proof byte {offset} verified"
            );
        }
    }
}

#[test]
fn a_torsion_component_on_any_commitment_fails_verification() {
    let (proof, commitments) = real_entry();
    assert!(
        verifies(&proof, &commitments),
        "the untouched proof verifies"
    );
    for torsion in 1..EIGHT_TORSION.len() {
        for index in 0..commitments.len() {
            let mut tampered = commitments.clone();
            tampered[index] = CompressedPoint(torsioned(&tampered[index].0, torsion));
            assert!(
                !verifies(&proof, &tampered),
                "torsion point {torsion} on commitment {index} verified"
            );
        }
    }
}
