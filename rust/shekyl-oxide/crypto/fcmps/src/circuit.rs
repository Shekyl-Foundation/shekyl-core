use std_shims::{vec, vec::Vec};

use ciphersuite::{group::ff::FromUniformBytes, Ciphersuite};

pub(crate) use generalized_bulletproofs::arithmetic_circuit_proof::{LinComb, Variable};
use generalized_bulletproofs::{
    arithmetic_circuit_proof::{
        AcStatementError, ArithmeticCircuitStatement, ArithmeticCircuitWitness,
    },
    transcript::Commitments,
    PedersenVectorCommitment, ProofGenerators,
};

use generalized_bulletproofs_circuit_abstraction::Circuit as UnderlyingCircuit;
pub(crate) use generalized_bulletproofs_circuit_abstraction::Transcript;

use crate::*;

/// The curves used with the FCMP.
///
/// Every curve is expected to have a 32-byte encoding for scalars and points. Every curve is
/// expected to only use 255 bits to represent scalars. Other bounds asserted at runtime may exist.
pub trait FcmpCurves {
    /// The curve of the leaf elements.
    ///
    /// The amount of bits used to represent scalars must be less than or equal to 253.
    type OC: Ciphersuite;
    /// The Discrete-Log gadget parameters for the curve of the leaf elements.
    type OcParameters: DiscreteLogParameters;

    /// The curve for the first set of branches.
    type C1: Ciphersuite;
    /// The Discrete-Log gadget parameters for the curve of the first set of branches.
    type C1Parameters: DiscreteLogParameters;

    /// The curve for the second set of branches.
    type C2: Ciphersuite;
    /// The Discrete-Log gadget parameters for the curve of the second set of branches.
    type C2Parameters: DiscreteLogParameters;
}

/// A struct representing a circuit.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Circuit<C: Ciphersuite>(pub(crate) UnderlyingCircuit<C>);

impl<C: Ciphersuite> Circuit<C> {
    pub(crate) fn muls(&self) -> usize {
        self.0.muls()
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn prove(commitments: Vec<PedersenVectorCommitment<C>>) -> Self {
        Self(UnderlyingCircuit::prove(commitments, vec![]))
    }

    pub(crate) fn verify() -> Self {
        Self(UnderlyingCircuit::verify())
    }

    pub(crate) fn eval(&self, lincomb: &LinComb<C::F>) -> Option<C::F> {
        self.0.eval(lincomb)
    }

    pub(crate) fn mul(
        &mut self,
        a: Option<LinComb<C::F>>,
        b: Option<LinComb<C::F>>,
        witness: Option<(C::F, C::F)>,
    ) -> (Variable, Variable, Variable) {
        self.0.mul(a, b, witness)
    }

    pub(crate) fn constrain_equal_to_zero(&mut self, lincomb: LinComb<C::F>) {
        self.0.constrain_equal_to_zero(lincomb);
    }
}

impl<C: Ciphersuite> Circuit<C>
where
    C::F: FromUniformBytes<64>,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn first_layer<T: Transcript, Parameters: DiscreteLogParameters>(
        &mut self,
        transcript: &mut T,
        curve: &CurveSpec<C::F>,

        T_table: &GeneratorTable<C::F, Parameters>,
        U_table: &GeneratorTable<C::F, Parameters>,
        V_table: &GeneratorTable<C::F, Parameters>,
        G_table: &GeneratorTable<C::F, Parameters>,
        J_table: &GeneratorTable<C::F, Parameters>,

        O_tilde: (C::F, C::F),
        o_blind: PointWithDlog<Parameters>,
        O: (Variable, Variable),

        I_tilde: (C::F, C::F),
        i_blind_u: PointWithDlog<Parameters>,
        I: (Variable, Variable),

        R: (C::F, C::F),
        i_blind_v: PointWithDlog<Parameters>,
        i_blind_blind: PointWithDlog<Parameters>,

        C_tilde: (C::F, C::F),
        c_blind: PointWithDlog<Parameters>,
        C: (Variable, Variable),

        K: (C::F, C::F),
        k_blind: PointWithDlog<Parameters>,
        CM: (Variable, Variable),

        branch: Vec<Vec<Variable>>,
    ) {
        let (challenge, challenged_generators) = self.discrete_log_challenge(
            transcript,
            curve,
            &[T_table, U_table, V_table, G_table, J_table],
        );
        let mut challenged_generators = challenged_generators.into_iter();
        let challenged_T = challenged_generators.next().unwrap();
        let challenged_U = challenged_generators.next().unwrap();
        let challenged_V = challenged_generators.next().unwrap();
        let challenged_G = challenged_generators.next().unwrap();
        let challenged_J = challenged_generators.next().unwrap();

        let O = self.on_curve(curve, O);
        let o_blind = self.discrete_log(curve, o_blind, &challenge, &challenged_T);
        self.incomplete_add_pub(O_tilde, o_blind, O);

        assert_eq!(
            i_blind_u.dlog, i_blind_v.dlog,
            "first layer passed differing variables for the dlog"
        );

        let I = self.on_curve(curve, I);
        let i_blind_u = self.discrete_log(curve, i_blind_u, &challenge, &challenged_U);
        self.incomplete_add_pub(I_tilde, i_blind_u, I);

        let i_blind_v = self.discrete_log(curve, i_blind_v, &challenge, &challenged_V);
        let i_blind_blind = self.discrete_log(curve, i_blind_blind, &challenge, &challenged_T);
        self.incomplete_add_pub(R, i_blind_v, i_blind_blind);

        let C = self.on_curve(curve, C);
        let c_blind = self.discrete_log(curve, c_blind, &challenge, &challenged_G);
        self.incomplete_add_pub(C_tilde, c_blind, C);

        // The PQC leaf commitment `CM = k·G_k + r·J` opens to the verifier-computed
        // public point `K = k·G_k` under the witness blind `r`: `K + r·J = CM`, the
        // exact shape of the `C` leg above (Shekyl `PL-D3`). `CM.x` is the leaf's
        // 4th scalar; it enters the membership tuple as a witness, never as a public
        // value, which is what closes `PL-D1`.
        let CM = self.on_curve(curve, CM);
        let k_blind = self.discrete_log(curve, k_blind, &challenge, &challenged_J);
        self.incomplete_add_pub(K, k_blind, CM);

        // Membership tuple: `{O.x, I.x, C.x, CM.x}` — width is `LEAF_TUPLE_WIDTH`.
        let member = vec![O.x(), I.x(), C.x(), CM.x()];
        debug_assert_eq!(member.len(), crate::LEAF_TUPLE_WIDTH);
        self.tuple_member_of_list(transcript, member, branch);
    }

    pub(crate) fn additional_layer_discrete_log_challenge<
        T: Transcript,
        Parameters: DiscreteLogParameters,
    >(
        &self,
        transcript: &mut T,
        curve: &CurveSpec<C::F>,
        H_table: &GeneratorTable<C::F, Parameters>,
    ) -> (
        DiscreteLogChallenge<C::F, Parameters>,
        ChallengedGenerator<C::F, Parameters>,
    ) {
        let (challenge, mut challenged_generator) =
            self.discrete_log_challenge(transcript, curve, &[H_table]);
        (challenge, challenged_generator.remove(0))
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn additional_layer<Parameters: DiscreteLogParameters>(
        &mut self,
        curve: &CurveSpec<C::F>,
        discrete_log_challenge: &(
            DiscreteLogChallenge<C::F, Parameters>,
            ChallengedGenerator<C::F, Parameters>,
        ),
        blinded_hash: (C::F, C::F),
        blind: PointWithDlog<Parameters>,
        hash: (Variable, Variable),
        branch: Vec<Variable>,
    ) {
        let (challenge, challenged_generator) = discrete_log_challenge;
        let blind = self.discrete_log(curve, blind, challenge, challenged_generator);
        let hash = self.on_curve(curve, hash);
        self.incomplete_add_pub(blinded_hash, blind, hash);
        self.member_of_list(
            &LinComb::from(hash.x()),
            branch.into_iter().map(Into::into).collect::<Vec<_>>(),
        );
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn statement(
        self,
        generators: ProofGenerators<'_, C>,
        commitments: Commitments<C>,
    ) -> Result<
        (
            ArithmeticCircuitStatement<'_, C>,
            Option<ArithmeticCircuitWitness<C>>,
        ),
        AcStatementError,
    > {
        self.0.statement(generators, commitments)
    }
}
