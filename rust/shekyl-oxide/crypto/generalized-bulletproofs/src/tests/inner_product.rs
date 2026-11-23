// The inner product relation is P = sum(g_bold * a, h_bold * b, g * (a * b))

use rand_core::OsRng;

use ciphersuite::{group::ff::Field as _, Ciphersuite, Ristretto};

use crate::{
    inner_product::{IpProveError, IpStatement, IpWitness},
    tests::insecure_test_generators,
    transcript::*,
    Generators, PointVector, ScalarVector,
};

#[test]
fn test_zero_inner_product() {
    let generators = insecure_test_generators::<_, Ristretto>(&mut OsRng, 1).unwrap();
    let reduced = generators.reduce(1).unwrap();
    let witness = IpWitness::<Ristretto>::new(
        ScalarVector::<<Ristretto as Ciphersuite>::F>::new(1),
        ScalarVector::<<Ristretto as Ciphersuite>::F>::new(1),
    )
    .unwrap();

    let statement = IpStatement::<Ristretto>::new(
        reduced,
        ScalarVector(vec![<Ristretto as Ciphersuite>::F::ONE; 1]),
        <Ristretto as Ciphersuite>::F::ONE,
    )
    .unwrap();

    let proof = {
        let mut transcript = Transcript::new([0; 32]);
        statement.clone().prove(&mut transcript, witness).unwrap();
        transcript.complete()
    };

    let mut verifier = Generators::batch_verifier();
    statement
        .verify(
            <Ristretto as Ciphersuite>::F::ONE,
            &mut verifier,
            &mut VerifierTranscript::new([0; 32], &proof),
        )
        .unwrap();
    assert!(generators.verify(verifier));
}

// A generator vector of a different length is a different statement. `reduce` is how a caller takes
// the prefix it intends to prove against.
#[test]
fn test_inner_product_rejects_a_generator_vector_of_a_different_length() {
    let generators = insecure_test_generators::<_, Ristretto>(&mut OsRng, 2).unwrap();
    let one = <Ristretto as Ciphersuite>::F::ONE;
    let short_generators = generators.reduce(1).unwrap();
    let long_generators = generators.reduce(2).unwrap();
    let short_witness =
        IpWitness::<Ristretto>::new(ScalarVector::new(1), ScalarVector::new(1)).unwrap();
    let long_witness =
        IpWitness::<Ristretto>::new(ScalarVector::new(2), ScalarVector::new(2)).unwrap();

    let mut transcript = Transcript::new([0; 32]);
    let err = IpStatement::<Ristretto>::new(long_generators, ScalarVector(vec![one; 2]), one)
        .unwrap()
        .prove(&mut transcript, short_witness)
        .unwrap_err();
    assert_eq!(err, IpProveError::IncorrectAmountOfGenerators);

    let err = IpStatement::<Ristretto>::new(short_generators, ScalarVector(vec![one; 1]), one)
        .unwrap()
        .prove(&mut transcript, long_witness)
        .unwrap_err();
    assert_eq!(err, IpProveError::IncorrectAmountOfGenerators);
}

#[test]
fn test_inner_product() {
    // P = sum(g_bold * a, h_bold * b)
    let generators = insecure_test_generators::<_, Ristretto>(&mut OsRng, 32).unwrap();
    let mut verifier = Generators::batch_verifier();
    for i in 1..=32 {
        let generators = generators.reduce(i).unwrap();
        let g = generators.g();
        assert_eq!(generators.len(), i.next_power_of_two());
        let mut g_bold = vec![];
        let mut h_bold = vec![];
        for i in 0..i.next_power_of_two() {
            g_bold.push(generators.g_bold(i));
            h_bold.push(generators.h_bold(i));
        }
        let g_bold = PointVector::<Ristretto>(g_bold);
        let h_bold = PointVector::<Ristretto>(h_bold);

        let mut a = ScalarVector::<<Ristretto as Ciphersuite>::F>::new(i.next_power_of_two());
        let mut b = ScalarVector::<<Ristretto as Ciphersuite>::F>::new(i.next_power_of_two());

        for i in 0..i {
            a[i] = <Ristretto as Ciphersuite>::F::random(&mut OsRng);
            b[i] = <Ristretto as Ciphersuite>::F::random(&mut OsRng);
        }

        let P = g_bold.multiexp(&a) + h_bold.multiexp(&b) + (g * a.inner_product(b.0.iter()));

        let witness = IpWitness::<Ristretto>::new(a, b).unwrap();
        let statement = IpStatement::<Ristretto>::new(
            generators,
            ScalarVector(vec![
                <Ristretto as Ciphersuite>::F::ONE;
                i.next_power_of_two()
            ]),
            <Ristretto as Ciphersuite>::F::ONE,
        )
        .unwrap();

        let proof = {
            let mut transcript = Transcript::new([0; 32]);
            statement.clone().prove(&mut transcript, witness).unwrap();
            transcript.complete()
        };

        verifier
            .additional
            .push((<Ristretto as Ciphersuite>::F::ONE, P));
        statement
            .verify(
                <Ristretto as Ciphersuite>::F::ONE,
                &mut verifier,
                &mut VerifierTranscript::new([0; 32], &proof),
            )
            .unwrap();
    }
    assert!(generators.verify(verifier));
}
