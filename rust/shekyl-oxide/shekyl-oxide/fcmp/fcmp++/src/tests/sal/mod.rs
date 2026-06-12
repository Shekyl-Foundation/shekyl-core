use rand_core::OsRng;

use ciphersuite::group::Group;
use dalek_ff_group::{EdwardsPoint, Scalar};
use multiexp::BatchVerifier;

use shekyl_generators::T;

use crate::{sal::*, Output};

#[cfg(feature = "multisig")]
mod multisig;

/// Named guard for the SAL_FULL_DST consensus transcript change: the main spend
/// path's prove -> verify roundtrip must hold with the proof-type tag in the
/// challenge preimage. A regression here is a main-spend-path consensus break.
/// See `docs/design/FCMP_MEMBERSHIP_ONLY.md` §4.
#[test]
fn full_sal_roundtrip_with_dst() {
    let x = Scalar::random(&mut OsRng);
    let y = Scalar::random(&mut OsRng);

    let O = (EdwardsPoint::generator() * x) + (EdwardsPoint(*T) * y);
    let I = EdwardsPoint::random(&mut OsRng);
    let C = EdwardsPoint::random(&mut OsRng);

    let rerandomized_output = RerandomizedOutput::new(&mut OsRng, Output::new(O, I, C).unwrap());
    let input = rerandomized_output.input();
    let opening = OpenedInputTuple::open(&rerandomized_output, &x, &y).unwrap();

    let tx_hash = [0xa5; 32];
    let (L, proof) = SpendAuthAndLinkability::prove(&mut OsRng, tx_hash, &opening);

    let mut verifier = BatchVerifier::new(4);
    proof.verify(&mut OsRng, &mut verifier, tx_hash, &input, L);
    assert!(
        verifier.verify_vartime(),
        "full SAL roundtrip with DST failed"
    );

    // A different tx hash must not verify (the DST does not weaken replay binding).
    let mut verifier = BatchVerifier::new(4);
    proof.verify(&mut OsRng, &mut verifier, [0x5a; 32], &input, L);
    assert!(
        !verifier.verify_vartime(),
        "full SAL verified under wrong tx hash"
    );
}

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
