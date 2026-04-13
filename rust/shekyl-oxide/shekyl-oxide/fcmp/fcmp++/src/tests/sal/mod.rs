use rand_core::OsRng;

use ciphersuite::group::Group;
use dalek_ff_group::{EdwardsPoint, Scalar};
use multiexp::BatchVerifier;

use shekyl_generators::T;

use crate::{sal::*, Output};

#[cfg(feature = "multisig")]
mod multisig;

#[test]
fn test_sal() {
    let x = Scalar::random(&mut OsRng);
    let y = Scalar::random(&mut OsRng);

    let O = (EdwardsPoint::generator() * x) + (EdwardsPoint(*T) * y);
    let I = EdwardsPoint::random(&mut OsRng);
    let C = EdwardsPoint::random(&mut OsRng);

    let L = I * x;

    let rerandomized_output = RerandomizedOutput::new(&mut OsRng, Output::new(O, I, C).unwrap());
    let input = rerandomized_output.input();
    let opening = OpenedInputTuple::open(&rerandomized_output, &x, &y).unwrap();
    let (L_, proof) = SpendAuthAndLinkability::prove(&mut OsRng, [0; 32], &opening);
    assert_eq!(L_, L);
    let mut verifier = BatchVerifier::new(1);
    proof.verify(&mut OsRng, &mut verifier, [0; 32], &input, L);
    assert!(verifier.verify_vartime());
}
