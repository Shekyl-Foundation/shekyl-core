use rand_core::{RngCore, OsRng};

use curve25519_dalek::scalar::Scalar;

use shekyl_primitives::Commitment;
use crate::{batch_verifier::BatchVerifier, Bulletproof, BulletproofError};

mod plus;

#[test]
fn bulletproofs_plus() {
  let mut verifier = BatchVerifier::new();
  for i in 1 ..= 16 {
    let commitments = (1 ..= i)
      .map(|_| Commitment::new(Scalar::random(&mut OsRng), OsRng.next_u64()))
      .collect::<Vec<_>>();

    let bp = Bulletproof::prove_plus(&mut OsRng, commitments.clone()).unwrap();

    let commitments = commitments
      .iter()
      .map(Commitment::calculate)
      .map(|p| p.compress().into())
      .collect::<Vec<_>>();
    assert!(bp.verify(&mut OsRng, &commitments));
    assert!(bp.batch_verify(&mut OsRng, &mut verifier, &commitments));
  }
  assert!(verifier.verify());
}

#[test]
fn bulletproofs_plus_max() {
  let mut commitments = vec![];
  for _ in 0 .. 17 {
    commitments.push(Commitment::new(Scalar::ZERO, 0));
  }
  assert_eq!(
    Bulletproof::prove_plus(&mut OsRng, commitments).unwrap_err(),
    BulletproofError::TooManyCommitments,
  );
}
