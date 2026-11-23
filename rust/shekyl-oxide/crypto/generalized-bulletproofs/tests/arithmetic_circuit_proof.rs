//! Tests for the arithmetic circuit proof.

#![allow(non_snake_case)]

use rand_core::{OsRng, RngCore as _};

use ciphersuite::{group::ff::Field as _, Ciphersuite, Ristretto};

use generalized_bulletproofs::{
    arithmetic_circuit_proof::{
        AcProveError, AcStatementError, ArithmeticCircuitProver, ArithmeticCircuitStatement,
        LinComb, Variable,
    },
    tests::insecure_test_generators,
    transcript::*,
    Generators, NotEnoughGenerators, Openings, PedersenOpening, PedersenVectorOpening,
};

type F = <Ristretto as Ciphersuite>::F;

/// Commit to `openings`, prove `constraints` over them and the multiplication rows, then verify
/// as a verifier does: with a statement formed from the commitments read back out of the proof.
fn prove_and_verify(
    generators: &Generators<Ristretto>,
    n: usize,
    constraints: Vec<LinComb<F>>,
    openings: Openings<Ristretto>,
    aL: Vec<F>,
    aR: Vec<F>,
) {
    let (vector_commitments, commitments) = (openings.vector.len(), openings.scalar.len());
    let mut transcript = Transcript::new([0; 32]);
    let prover_commitments = transcript.write_commitments(openings.commit(generators).unwrap());
    let written = prover_commitments.commitments().clone();
    ArithmeticCircuitProver::new(
        generators.reduce(n).unwrap(),
        constraints.clone(),
        prover_commitments,
        aL,
        aR,
    )
    .unwrap()
    .prove(&mut OsRng, &mut transcript);
    let proof = transcript.complete();

    let mut verifier = Generators::batch_verifier();
    let mut transcript = VerifierTranscript::new([0; 32], &proof);
    let read = transcript
        .read_commitments(vector_commitments, commitments)
        .unwrap();
    assert_eq!(written, read);
    ArithmeticCircuitStatement::<Ristretto>::new(generators.reduce(n).unwrap(), constraints, read)
        .unwrap()
        .verify(&mut OsRng, &mut verifier, &mut transcript)
        .unwrap();
    assert!(generators.verify(verifier));
}

/// Form a prover, returning why it could not be formed.
fn prover_refusal(
    generators: &Generators<Ristretto>,
    n: usize,
    constraints: Vec<LinComb<F>>,
    openings: Openings<Ristretto>,
    aL: Vec<F>,
    aR: Vec<F>,
) -> AcProveError {
    let mut transcript = Transcript::new([0; 32]);
    let prover_commitments = transcript.write_commitments(openings.commit(generators).unwrap());
    ArithmeticCircuitProver::new(
        generators.reduce(n).unwrap(),
        constraints,
        prover_commitments,
        aL,
        aR,
    )
    .unwrap_err()
}

fn no_openings() -> Openings<Ristretto> {
    Openings {
        vector: vec![],
        scalar: vec![],
    }
}

#[test]
fn test_zero_arithmetic_circuit() {
    let generators = insecure_test_generators(&mut OsRng, 1).unwrap();
    prove_and_verify(
        &generators,
        1,
        vec![],
        no_openings(),
        vec![F::ZERO],
        vec![F::ZERO],
    );
}

#[test]
fn test_vector_commitment_arithmetic_circuit() {
    let generators = insecure_test_generators(&mut OsRng, 2).unwrap();

    let v1 = F::random(&mut OsRng);
    let v2 = F::random(&mut OsRng);
    let gamma = F::random(&mut OsRng);

    prove_and_verify(
        &generators,
        2,
        vec![LinComb::empty()
            .term(
                F::ONE,
                Variable::CG {
                    commitment: 0,
                    index: 0,
                },
            )
            .term(
                F::from(2u64),
                Variable::CG {
                    commitment: 0,
                    index: 1,
                },
            )
            .constant(-(v1 + (v2 + v2)))],
        Openings {
            vector: vec![PedersenVectorOpening {
                g_values: vec![v1, v2],
                mask: gamma,
            }],
            scalar: vec![],
        },
        vec![F::ZERO],
        vec![F::ZERO],
    );
}

#[test]
fn a_constraint_the_witness_does_not_satisfy_is_refused_in_every_build() {
    let generators = insecure_test_generators(&mut OsRng, 2).unwrap();
    let value = F::random(&mut OsRng);
    let holds = LinComb::empty()
        .term(F::ONE, Variable::aL(0))
        .constant(-value);
    let fails = LinComb::empty()
        .term(F::ONE, Variable::aR(0))
        .constant(-value);
    assert_eq!(
        prover_refusal(
            &generators,
            2,
            vec![holds, fails],
            no_openings(),
            vec![value],
            vec![F::ONE]
        ),
        AcProveError::UnsatisfiedConstraint { index: 1 },
    );
}

#[test]
fn multiplication_rows_of_different_lengths_are_refused() {
    let generators = insecure_test_generators(&mut OsRng, 2).unwrap();
    assert_eq!(
        prover_refusal(
            &generators,
            2,
            vec![],
            no_openings(),
            vec![F::ONE, F::ONE],
            vec![F::ONE]
        ),
        AcProveError::UnequalMultiplicationRows,
    );
}

#[test]
fn an_opening_longer_than_the_statement_generators_is_refused() {
    let generators = insecure_test_generators(&mut OsRng, 4).unwrap();
    let opening = PedersenVectorOpening {
        g_values: vec![F::ONE, F::ONE, F::ONE],
        mask: F::random(&mut OsRng),
    };
    assert_eq!(
        prover_refusal(
            &generators,
            2,
            vec![],
            Openings {
                vector: vec![opening],
                scalar: vec![]
            },
            vec![F::ZERO],
            vec![F::ZERO],
        ),
        AcProveError::IncorrectAmountOfGenerators,
    );
}

#[test]
fn an_opening_longer_than_the_generators_cannot_be_committed() {
    let generators = insecure_test_generators(&mut OsRng, 2).unwrap();
    let short = PedersenVectorOpening {
        g_values: vec![F::ONE],
        mask: F::ONE,
    };
    let long = PedersenVectorOpening {
        g_values: vec![F::ONE; 3],
        mask: F::ONE,
    };
    assert_eq!(
        Openings::<Ristretto> {
            vector: vec![short, long],
            scalar: vec![]
        }
        .commit(&generators)
        .unwrap_err(),
        NotEnoughGenerators {
            vector_commitment: 1
        },
    );
}

#[test]
fn fuzz_test_arithmetic_circuit() {
    let generators = insecure_test_generators(&mut OsRng, 32).unwrap();

    for i in 0..100 {
        println!("Fuzzing Arithmetic Circuit, iteration {i}");

        // Create aL, aR, aO
        let mut aL = vec![];
        let mut aR = vec![];
        while aL.len() < ((OsRng.next_u64() % 8) + 1).try_into().unwrap() {
            aL.push(F::random(&mut OsRng));
        }
        while aR.len() < aL.len() {
            aR.push(F::random(&mut OsRng));
        }
        let aO = aL
            .iter()
            .copied()
            .zip(&aR)
            .map(|(l, r)| l * r)
            .collect::<Vec<_>>();

        // Create C
        let mut C = vec![];
        while C.len() < (OsRng.next_u64() % 16).try_into().unwrap() {
            let mut g_values = vec![];
            while g_values.len() < ((OsRng.next_u64() % 8) + 1).try_into().unwrap() {
                g_values.push(F::random(&mut OsRng));
            }
            C.push(PedersenVectorOpening {
                g_values,
                mask: F::random(&mut OsRng),
            });
        }

        let mut constraints = vec![];

        // Create V
        let mut V = vec![];
        while V.len() < (OsRng.next_u64() % 4).try_into().unwrap() {
            V.push(PedersenOpening {
                value: F::random(&mut OsRng),
                mask: F::random(&mut OsRng),
            });

            // Ensure this has at least one constraint constraining it
            let mut constraint = LinComb::empty();
            constraint = constraint.term(-F::ONE, Variable::V(V.len() - 1));
            constraint = constraint.constant(V[V.len() - 1].value);
            constraints.push(constraint);
        }

        // Generate random constraints
        for _ in 0..(OsRng.next_u64() % 8).try_into().unwrap() {
            let mut eval = F::ZERO;
            let mut constraint = LinComb::empty();

            for _ in 0..(OsRng.next_u64() % 4) {
                let index = usize::try_from(OsRng.next_u64()).unwrap() % aL.len();
                let weight = F::random(&mut OsRng);
                constraint = constraint.term(weight, Variable::aL(index));
                eval += weight * aL[index];
            }

            for _ in 0..(OsRng.next_u64() % 4) {
                let index = usize::try_from(OsRng.next_u64()).unwrap() % aR.len();
                let weight = F::random(&mut OsRng);
                constraint = constraint.term(weight, Variable::aR(index));
                eval += weight * aR[index];
            }

            for _ in 0..(OsRng.next_u64() % 4) {
                let index = usize::try_from(OsRng.next_u64()).unwrap() % aO.len();
                let weight = F::random(&mut OsRng);
                constraint = constraint.term(weight, Variable::aO(index));
                eval += weight * aO[index];
            }

            for (commitment, C) in C.iter().enumerate() {
                for _ in 0..(OsRng.next_u64() % 4) {
                    let index = usize::try_from(OsRng.next_u64()).unwrap() % C.g_values.len();
                    let weight = F::random(&mut OsRng);
                    constraint = constraint.term(weight, Variable::CG { commitment, index });
                    eval += weight * C.g_values[index];
                }
            }

            if !V.is_empty() {
                for _ in 0..(OsRng.next_u64() % 4) {
                    let index = usize::try_from(OsRng.next_u64()).unwrap() % V.len();
                    let weight = F::random(&mut OsRng);
                    constraint = constraint.term(weight, Variable::V(index));
                    eval += weight * V[index].value;
                }
            }

            constraint = constraint.constant(-eval);

            constraints.push(constraint);
        }

        prove_and_verify(
            &generators,
            16,
            constraints,
            Openings {
                vector: C,
                scalar: V,
            },
            aL,
            aR,
        );
    }
}

fn pedersen_statement(
    commitment_count: usize,
    constraints: Vec<LinComb<F>>,
) -> Result<(), AcStatementError> {
    let generators = insecure_test_generators(&mut OsRng, 1).unwrap();
    let scalar = (0..commitment_count)
        .map(|_| PedersenOpening {
            value: F::random(&mut OsRng),
            mask: F::random(&mut OsRng),
        })
        .collect();
    let mut transcript = Transcript::new([0; 32]);
    let commitments = transcript
        .write_commitments(
            Openings {
                vector: vec![],
                scalar,
            }
            .commit(&generators)
            .unwrap(),
        )
        .commitments()
        .clone();
    ArithmeticCircuitStatement::<Ristretto>::new(
        generators.reduce(1).unwrap(),
        constraints,
        commitments,
    )
    .map(|_| ())
}

fn assert_commitments_rejected(commitment_count: usize, constraints: Vec<LinComb<F>>) {
    assert_eq!(
        pedersen_statement(commitment_count, constraints).unwrap_err(),
        AcStatementError::DidNotConstrainCommitment,
    );
}

#[test]
fn an_unconstrained_commitment_is_rejected() {
    assert_commitments_rejected(1, vec![]);
}

#[test]
fn a_commitment_mixed_with_another_is_not_isolated() {
    let one = F::ONE;
    assert_commitments_rejected(
        2,
        vec![LinComb::empty()
            .term(one, Variable::V(0))
            .term(one, Variable::V(1))],
    );
}

#[test]
fn a_sum_of_terms_and_a_scaled_term_isolate_the_same_commitment() {
    let one = F::ONE;
    let two = one + one;
    let summed = LinComb::from(Variable::V(0)) + &LinComb::from(Variable::V(0));
    let scaled = LinComb::from(Variable::V(0)) * two;
    pedersen_statement(1, vec![summed]).unwrap();
    pedersen_statement(1, vec![scaled]).unwrap();
}

#[test]
fn cancelled_terms_do_not_isolate_a_commitment() {
    let commitment = LinComb::from(Variable::V(0));
    assert_commitments_rejected(1, vec![commitment.clone() - &commitment]);
}

#[test]
fn a_zero_weight_does_not_isolate_a_commitment() {
    let zero = F::ZERO;
    assert_commitments_rejected(1, vec![LinComb::empty().term(zero, Variable::V(0))]);
}

#[test]
fn cancelling_one_commitment_leaves_the_other_isolated() {
    let one = F::ONE;
    let v0 = LinComb::from(Variable::V(0));
    let v1 = LinComb::from(Variable::V(1));
    // V(0) + V(1) - V(1) is V(0) once the partner cancels.
    let isolates_v0 = (v0 + &v1) - &v1;
    let isolates_v1 = LinComb::empty().term(one, Variable::V(1));
    pedersen_statement(2, vec![isolates_v0, isolates_v1]).unwrap();
}
