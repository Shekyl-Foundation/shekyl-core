#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![allow(non_snake_case)]

use std_shims::{vec, vec::Vec};

use subtle::ConditionallySelectable;
use zeroize::Zeroizing;

use ciphersuite::{
    group::ff::{Field as _, FromUniformBytes},
    Ciphersuite,
};

pub use generalized_bulletproofs::arithmetic_circuit_proof::{LinComb, Variable};
use generalized_bulletproofs::{
    arithmetic_circuit_proof::{
        AcProveError, AcStatementError, ArithmeticCircuitProver, ArithmeticCircuitStatement,
        Assignment,
    },
    transcript::{
        Commitments, ProverCommitments, Transcript as ProverTranscript, VerifierTranscript,
    },
    ProofGenerators,
};

mod gadgets;

/// A trait for the transcript, whether proving for verifying, as necessary for sampling
/// challenges.
pub trait Transcript {
    /// Sample a challenge from the transacript.
    ///
    /// It is the caller's responsibility to have properly transcripted all variables prior to
    /// sampling this challenge.
    fn challenge<C: Ciphersuite>(&mut self) -> C::F
    where
        C::F: FromUniformBytes<64>;

    /// Sample a challenge as a byte array.
    ///
    /// It is the caller's responsibility to have properly transcripted all variables prior to
    /// sampling this challenge.
    fn challenge_bytes(&mut self) -> [u8; 64];
}
impl Transcript for ProverTranscript {
    fn challenge<C: Ciphersuite>(&mut self) -> C::F
    where
        C::F: FromUniformBytes<64>,
    {
        self.challenge::<C>()
    }
    fn challenge_bytes(&mut self) -> [u8; 64] {
        self.challenge_bytes()
    }
}
impl Transcript for VerifierTranscript<'_> {
    fn challenge<C: Ciphersuite>(&mut self) -> C::F
    where
        C::F: FromUniformBytes<64>,
    {
        self.challenge::<C>()
    }
    fn challenge_bytes(&mut self) -> [u8; 64] {
        self.challenge_bytes()
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Which side of a proof a [`Circuit`] is built for.
///
/// The gadgets are written once, over every role; what differs is whether a value is known. A
/// proving circuit holds the witness and evaluates linear combinations under it; a verifying
/// circuit holds only the circuit's shape.
pub trait Role<C: Ciphersuite>: sealed::Sealed {
    /// The assignment linear combinations evaluate under, when this role knows one.
    fn assignment(&self) -> Option<Assignment<'_, C>>;
    /// Record the witness of the next multiplication.
    ///
    /// A proving circuit requires it and a verifying circuit refuses it, in every build: a
    /// multiplication without its witness would shift every later row of the prover's assignment.
    fn assign(&mut self, witness: Option<(C::F, C::F)>);
}

/// The prover's side: the commitments with their openings, and the multiplication rows assigned
/// so far.
pub struct Proving<C: Ciphersuite> {
    aL: Zeroizing<Vec<C::F>>,
    aR: Zeroizing<Vec<C::F>>,
    commitments: ProverCommitments<C>,
}

/// The verifier's side: the circuit's shape alone.
pub struct Verifying;

impl<C: Ciphersuite> sealed::Sealed for Proving<C> {}
impl sealed::Sealed for Verifying {}

impl<C: Ciphersuite> Role<C> for Proving<C> {
    fn assignment(&self) -> Option<Assignment<'_, C>> {
        Some(Assignment {
            aL: &self.aL,
            aR: &self.aR,
            openings: self.commitments.openings(),
        })
    }
    fn assign(&mut self, witness: Option<(C::F, C::F)>) {
        let (l, r) = witness.expect("a proving circuit's multiplication carries its witness");
        self.aL.push(l);
        self.aR.push(r);
    }
}

impl<C: Ciphersuite> Role<C> for Verifying {
    fn assignment(&self) -> Option<Assignment<'_, C>> {
        None
    }
    fn assign(&mut self, witness: Option<(C::F, C::F)>) {
        assert!(
            witness.is_none(),
            "a verifying circuit's multiplication carries no witness"
        );
    }
}

/// A circuit: its multiplications and the linear combinations constrained to zero, built for one
/// [`Role`].
pub struct Circuit<C: Ciphersuite, R: Role<C>> {
    muls: usize,
    // A series of linear combinations which must evaluate to 0.
    constraints: Vec<LinComb<C::F>>,
    role: R,
}

impl<C: Ciphersuite> Circuit<C, Proving<C>> {
    /// Create a circuit to prove with, over the prover's transcripted commitments.
    pub fn prove(commitments: ProverCommitments<C>) -> Self {
        Self {
            muls: 0,
            constraints: vec![],
            role: Proving {
                aL: Zeroizing::default(),
                aR: Zeroizing::default(),
                commitments,
            },
        }
    }
}

impl<C: Ciphersuite> Circuit<C, Verifying> {
    /// Create a circuit to verify a proof with.
    pub fn verify() -> Self {
        Self {
            muls: 0,
            constraints: vec![],
            role: Verifying,
        }
    }
}

impl<C: Ciphersuite, R: Role<C>> Circuit<C, R> {
    /// Returns the amount of multiplications used by this circuit.
    pub fn muls(&self) -> usize {
        self.muls
    }

    /// Evaluate a linear combination under the prover's assignment.
    ///
    /// Yields `WL aL + WR aR + WO aO + WCG CG + WV V + c` ([`LinComb::evaluate`]). Returns `None`
    /// for a verifying circuit, which knows no values.
    pub fn eval(&self, lincomb: &LinComb<C::F>) -> Option<C::F> {
        self.role
            .assignment()
            .map(|assignment| lincomb.evaluate(&assignment))
    }

    /// Multiply two values, optionally constrained, returning the constrainable left/right/out
    /// terms.
    ///
    /// The witness is required when proving and refused when verifying ([`Role::assign`]).
    #[allow(clippy::many_single_char_names)]
    pub fn mul(
        &mut self,
        a: Option<LinComb<C::F>>,
        b: Option<LinComb<C::F>>,
        witness: Option<(C::F, C::F)>,
    ) -> (Variable, Variable, Variable) {
        let l = Variable::aL(self.muls);
        let r = Variable::aR(self.muls);
        let o = Variable::aO(self.muls);
        self.muls += 1;
        self.role.assign(witness);

        if let Some(a) = a {
            self.constrain_equal_to_zero(a.term(-C::F::ONE, l));
        }
        if let Some(b) = b {
            self.constrain_equal_to_zero(b.term(-C::F::ONE, r));
        }

        (l, r, o)
    }

    /// Constrain a linear combination to be equal to 0.
    pub fn constrain_equal_to_zero(&mut self, lincomb: LinComb<C::F>) {
        self.constraints.push(lincomb);
    }
}

impl<C: Ciphersuite> Circuit<C, Proving<C>>
where
    C::F: FromUniformBytes<64>,
    C::G: ConditionallySelectable,
{
    /// The prover for this circuit: its statement over the prover's commitments, and the witness
    /// the circuit assigned, every constraint checked ([`ArithmeticCircuitProver::new`]).
    pub fn statement(
        self,
        generators: ProofGenerators<'_, C>,
    ) -> Result<ArithmeticCircuitProver<'_, C>, AcProveError> {
        let Proving {
            mut aL,
            mut aR,
            commitments,
        } = self.role;
        ArithmeticCircuitProver::new(
            generators,
            self.constraints,
            commitments,
            core::mem::take(&mut *aL),
            core::mem::take(&mut *aR),
        )
    }
}

impl<C: Ciphersuite> Circuit<C, Verifying>
where
    C::F: FromUniformBytes<64>,
{
    /// The statement for this circuit, over the commitments read from the proof.
    pub fn statement(
        self,
        generators: ProofGenerators<'_, C>,
        commitments: Commitments<C>,
    ) -> Result<ArithmeticCircuitStatement<'_, C>, AcStatementError> {
        ArithmeticCircuitStatement::new(generators, self.constraints, commitments)
    }
}
