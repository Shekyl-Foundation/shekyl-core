use rand_core::{OsRng, RngCore};

use curve25519_dalek::scalar::Scalar;

use crate::{verify_batch, BatchEntry, Bulletproof, BulletproofError};
use shekyl_curve_primitives::Commitment;

mod derived;
mod plus;

#[test]
fn bulletproofs_plus() {
    let mut proofs = vec![];
    for i in 1..=16 {
        let commitments = (1..=i)
            .map(|_| Commitment::new(Scalar::random(&mut OsRng), OsRng.next_u64()))
            .collect::<Vec<_>>();

        let bp = Bulletproof::prove_plus(&mut OsRng, commitments.clone()).unwrap();

        let commitments = commitments
            .iter()
            .map(Commitment::calculate)
            .map(|p| p.compress().into())
            .collect::<Vec<_>>();
        assert!(verify_batch(&[BatchEntry {
            proof: &bp,
            commitments: &commitments,
        }]));
        proofs.push((bp, commitments));
    }
    let batch = proofs
        .iter()
        .map(|(proof, commitments)| BatchEntry { proof, commitments })
        .collect::<Vec<_>>();
    assert!(verify_batch(&batch));
}

#[test]
fn bulletproofs_plus_max() {
    let mut commitments = vec![];
    for _ in 0..17 {
        commitments.push(Commitment::new(Scalar::ZERO, 0));
    }
    assert_eq!(
        Bulletproof::prove_plus(&mut OsRng, commitments).unwrap_err(),
        BulletproofError::TooManyCommitments,
    );
}
