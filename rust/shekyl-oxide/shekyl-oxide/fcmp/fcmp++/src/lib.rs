#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![allow(non_snake_case)]

use std_shims::{io, sync::LazyLock, vec, vec::Vec};

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use generic_array::typenum::U;

use blake2::{Blake2b512, Digest};

use ciphersuite::{
    group::{ff::PrimeField, GroupEncoding},
    Ciphersuite,
};
use dalek_ff_group::{Ed25519, EdwardsPoint};
use helioselene::{Helios, Selene};

pub use fcmps;
use fcmps::*;
use generalized_bulletproofs_ec_gadgets::*;

use shekyl_generators::{
    FCMP_PLUS_PLUS_U, FCMP_PLUS_PLUS_V, HELIOS_HASH_INIT, SELENE_HASH_INIT, T,
};

/// The Spend-Authorization and Linkability proof.
pub mod sal;
use sal::membership_only::MembershipSpendAuth;
use sal::*;

#[cfg(test)]
mod tests;

/// The discrete-log gadget parameters for Ed25519.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ed25519Params;
impl DiscreteLogParameter for Ed25519Params {
    type ScalarBits = U<{ <<Ed25519 as Ciphersuite>::F as PrimeField>::NUM_BITS as usize }>;
}

/// The discrete-log gadget parameters for Selene.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SeleneParams;
impl DiscreteLogParameter for SeleneParams {
    type ScalarBits = U<{ <<Selene as Ciphersuite>::F as PrimeField>::NUM_BITS as usize }>;
}

/// The discrete-log gadget parameters for Helios.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HeliosParams;
impl DiscreteLogParameter for HeliosParams {
    type ScalarBits = U<{ <<Helios as Ciphersuite>::F as PrimeField>::NUM_BITS as usize }>;
}

/// The curves to use with the FCMP.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Curves;
impl FcmpCurves for Curves {
    type OC = Ed25519;
    type OcParameters = Ed25519Params;
    type C1 = Selene;
    type C1Parameters = SeleneParams;
    type C2 = Helios;
    type C2Parameters = HeliosParams;
    const EXTRA_LEAF_SCALARS: usize = 1;
}

include!(concat!(env!("OUT_DIR"), "/generators.rs"));

/// The parameters for an FCMP.
// TODO(shekyl): Wrap in a safe builder/accessor API. Current LazyLock is immutable and safe;
// encapsulation is a code-quality improvement, not a correctness requirement.
pub static FCMP_PARAMS: LazyLock<FcmpParams<Curves>> = LazyLock::new(|| {
    FcmpParams::<Curves>::new(
        SELENE_FCMP_GENERATORS.generators.clone(),
        HELIOS_FCMP_GENERATORS.generators.clone(),
        // Hash init generators
        *SELENE_HASH_INIT,
        *HELIOS_HASH_INIT,
        // G, T, U, V
        <Ed25519 as Ciphersuite>::generator(),
        EdwardsPoint(*T),
        EdwardsPoint(*FCMP_PLUS_PLUS_U),
        EdwardsPoint(*FCMP_PLUS_PLUS_V),
    )
    .expect("FCMP generator points must not be the identity")
});

/// An input tuple.
///
/// The FCMP crate has this same object yet with a distinct internal layout. This definition should
/// be preferred.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct Input {
    O_tilde: <Ed25519 as Ciphersuite>::G,
    I_tilde: <Ed25519 as Ciphersuite>::G,
    R: <Ed25519 as Ciphersuite>::G,
    C_tilde: <Ed25519 as Ciphersuite>::G,
}

impl Input {
    // Write an Input without the pseudo-out.
    fn write_partial(&self, writer: &mut impl io::Write) -> io::Result<()> {
        writer.write_all(&self.O_tilde.to_bytes())?;
        writer.write_all(&self.I_tilde.to_bytes())?;
        writer.write_all(&self.R.to_bytes())
    }

    fn read_partial(
        C_tilde: <Ed25519 as Ciphersuite>::G,
        reader: &mut impl io::Read,
    ) -> io::Result<Input> {
        Ok(Self {
            O_tilde: Ed25519::read_G(reader)?,
            I_tilde: Ed25519::read_G(reader)?,
            R: Ed25519::read_G(reader)?,
            C_tilde,
        })
    }

    // Write the full pseudo-out.
    fn write_full(&self, writer: &mut impl io::Write) -> io::Result<()> {
        self.write_partial(writer)?;
        writer.write_all(&self.C_tilde.to_bytes())
    }

    fn read_full(reader: &mut impl io::Read) -> io::Result<Input> {
        let mut OIR = [0; 3 * 32];
        reader.read_exact(&mut OIR)?;
        let C_tilde = Ed25519::read_G(reader)?;
        Self::read_partial(C_tilde, &mut OIR.as_slice())
    }

    fn transcript(&self, transcript: &mut Blake2b512, L: <Ed25519 as Ciphersuite>::G) {
        transcript.update(self.O_tilde.to_bytes());
        transcript.update(self.I_tilde.to_bytes());
        transcript.update(self.C_tilde.to_bytes());
        transcript.update(self.R.to_bytes());
        transcript.update(L.to_bytes());
    }

    /// O~ from the input commitment.
    pub fn O_tilde(&self) -> <Ed25519 as Ciphersuite>::G {
        self.O_tilde
    }

    /// I~ from the input commitment.
    pub fn I_tilde(&self) -> <Ed25519 as Ciphersuite>::G {
        self.I_tilde
    }

    /// R from the input commitment.
    pub fn R(&self) -> <Ed25519 as Ciphersuite>::G {
        self.R
    }

    /// C~ from the input commitment (the pseudo-out).
    pub fn C_tilde(&self) -> <Ed25519 as Ciphersuite>::G {
        self.C_tilde
    }
}

/// A FCMP++ output tuple.
pub type Output = fcmps::Output<<Ed25519 as Ciphersuite>::G>;

/// An error encountered when working with FCMP++.
#[derive(Debug)]
pub enum FcmpPlusPlusError {
    /// An invalid quantity of key images was provided.
    InvalidKeyImageQuantity,
    /// An empty input set was provided.
    ///
    /// A membership-only proof over zero inputs must reject, never verify
    /// vacuously-true (`docs/design/FCMP_MEMBERSHIP_ONLY.md` §8.2).
    EmptyInputs,
    /// An invalid quantity of PQC public-key hashes was provided.
    InvalidPqcPkHashQuantity,
    /// A propagated FCMP error.
    FcmpError(FcmpError),
}
impl From<FcmpError> for FcmpPlusPlusError {
    fn from(err: FcmpError) -> FcmpPlusPlusError {
        FcmpPlusPlusError::FcmpError(err)
    }
}

/// A FCMP++ proof for a set of inputs.
#[derive(Clone, Debug, Zeroize)]
pub struct FcmpPlusPlus {
    inputs: Vec<(Input, SpendAuthAndLinkability)>,
    fcmp: Fcmp<Curves>,
}

impl FcmpPlusPlus {
    /// Create a new FCMP++ proof from its components.
    pub fn new(inputs: Vec<(Input, SpendAuthAndLinkability)>, fcmp: Fcmp<Curves>) -> FcmpPlusPlus {
        FcmpPlusPlus { inputs, fcmp }
    }

    /// The size of a FCMP++ proof.
    pub fn proof_size(inputs: usize, layers: usize) -> usize {
        // Each input tuple, without C~, each SAL, and the FCMP
        (inputs * ((3 * 32) + (12 * 32))) + Fcmp::<Curves>::proof_size(inputs, layers)
    }

    /// Write a FCMP++ proof.
    pub fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
        for (input, spend_auth_and_linkability) in &self.inputs {
            input.write_partial(writer)?;
            spend_auth_and_linkability.write(writer)?;
        }
        self.fcmp.write(writer)
    }

    /// Read an FCMP++.
    ///
    /// The pseudo-outs are passed in as Monero already defines a field for them. It's less annoying
    /// to receive them here than to move them into here and expose them to Monero. It also informs
    /// us of how many inputs we're reading a proof for.
    ///
    /// The amount of layers for the FCMP are also passed in here as the FCMP's length is variable to
    /// that.
    pub fn read(
        pseudo_outs: &[[u8; 32]],
        layers: usize,
        reader: &mut impl io::Read,
    ) -> io::Result<Self> {
        let mut inputs = vec![];
        for pseudo_out in pseudo_outs {
            let C_tilde = Ed25519::read_G(&mut pseudo_out.as_slice())?;
            inputs.push((
                Input::read_partial(C_tilde, reader)?,
                SpendAuthAndLinkability::read(reader)?,
            ));
        }
        let fcmp = Fcmp::read(reader, pseudo_outs.len(), layers)?;
        Ok(Self { inputs, fcmp })
    }

    /// Verify an FCMP++.
    ///
    /// See [`Fcmp::verify`] for further context.
    ///
    /// `signable_tx_hash` must be binding to the transaction prefix, the RingCT base, and the
    /// pseudo-outs.
    ///
    /// This only queues the proofs for batch verification. The BatchVerifiers MUST also be verified.
    ///
    /// If this function returns an error, the BatchVerifiers MUST be considered corrupted and
    /// discarded.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        verifier_ed: &mut multiexp::BatchVerifier<(), <Ed25519 as Ciphersuite>::G>,
        verifier_1: &mut generalized_bulletproofs::BatchVerifier<Selene>,
        verifier_2: &mut generalized_bulletproofs::BatchVerifier<Helios>,
        tree: TreeRoot<<Curves as FcmpCurves>::C1, <Curves as FcmpCurves>::C2>,
        layers: usize,
        signable_tx_hash: [u8; 32],
        key_images: Vec<<Ed25519 as Ciphersuite>::G>,
        pqc_pk_hashes: Vec<<Selene as Ciphersuite>::F>,
    ) -> Result<(), FcmpPlusPlusError> {
        if self.inputs.len() != key_images.len() {
            Err(FcmpPlusPlusError::InvalidKeyImageQuantity)?;
        }
        if self.inputs.len() != pqc_pk_hashes.len() {
            Err(FcmpPlusPlusError::InvalidKeyImageQuantity)?;
        }

        let mut fcmp_inputs = Vec::with_capacity(self.inputs.len());
        for (((input, spend_auth_and_linkability), key_image), h_pqc) in
            self.inputs.iter().zip(key_images).zip(pqc_pk_hashes)
        {
            spend_auth_and_linkability.verify(rng, verifier_ed, signable_tx_hash, input, key_image);

            fcmp_inputs.push(fcmps::Input::with_extra_scalars(
                input.O_tilde,
                input.I_tilde,
                input.R,
                input.C_tilde,
                vec![h_pqc],
            )?);
        }

        Ok(self.fcmp.verify(
            rng,
            verifier_1,
            verifier_2,
            &*FCMP_PARAMS,
            tree,
            layers,
            &fcmp_inputs,
        )?)
    }
}

/// A membership-only FCMP++ proof for a set of inputs: spend authority + tree
/// membership, **no key image**.
///
/// Sibling type to [`FcmpPlusPlus`] — the SAL leg is replaced by
/// [`MembershipSpendAuth`] (the `R_O` leg alone); the `Fcmp` membership leg, including
/// the `H(pqc_pk)` extra-leaf-scalar binding, is unchanged. A membership-only proof
/// cannot verify where a full proof is required (and vice versa): at the typed API by
/// construction, at the byte seam by transcript domain separation.
///
/// First consumer: the reward-emission vin (`docs/design/REWARD_EMISSION_LEG.md`
/// §7.2). Statement, wire format, and security argument:
/// `docs/design/FCMP_MEMBERSHIP_ONLY.md`.
#[derive(Clone, Debug, Zeroize)]
pub struct FcmpMembershipOnly {
    inputs: Vec<(Input, MembershipSpendAuth)>,
    fcmp: Fcmp<Curves>,
}

impl FcmpMembershipOnly {
    /// Create a new membership-only FCMP++ proof from its components.
    pub fn new(
        inputs: Vec<(Input, MembershipSpendAuth)>,
        fcmp: Fcmp<Curves>,
    ) -> FcmpMembershipOnly {
        FcmpMembershipOnly { inputs, fcmp }
    }

    /// The size of a membership-only FCMP++ proof.
    pub fn proof_size(inputs: usize, layers: usize) -> usize {
        // Each input tuple, without C~, each MembershipSpendAuth, and the FCMP
        (inputs * ((3 * 32) + (3 * 32))) + Fcmp::<Curves>::proof_size(inputs, layers)
    }

    /// Write a membership-only FCMP++ proof.
    pub fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
        for (input, membership_spend_auth) in &self.inputs {
            input.write_partial(writer)?;
            membership_spend_auth.write(writer)?;
        }
        self.fcmp.write(writer)
    }

    /// Read a membership-only FCMP++ proof.
    ///
    /// As with [`FcmpPlusPlus::read`], the pseudo-outs and the FCMP layer count are
    /// passed in; the pseudo-out count is the input count.
    pub fn read(
        pseudo_outs: &[[u8; 32]],
        layers: usize,
        reader: &mut impl io::Read,
    ) -> io::Result<Self> {
        let mut inputs = vec![];
        for pseudo_out in pseudo_outs {
            let C_tilde = Ed25519::read_G(&mut pseudo_out.as_slice())?;
            inputs.push((
                Input::read_partial(C_tilde, reader)?,
                MembershipSpendAuth::read(reader)?,
            ));
        }
        let fcmp = Fcmp::read(reader, pseudo_outs.len(), layers)?;
        Ok(Self { inputs, fcmp })
    }

    /// Verify a membership-only FCMP++ proof.
    ///
    /// See [`Fcmp::verify`] for further context.
    ///
    /// `signable_tx_hash` must be binding to the transaction prefix, the RingCT base,
    /// and the pseudo-outs. No key images are taken: nothing here is checked against
    /// the spent set. Each input's `H(pqc_pk)` leaf commitment is proven in-circuit;
    /// the ML-DSA authentication against that commitment is the caller's obligation
    /// (`docs/design/FCMP_MEMBERSHIP_ONLY.md` §7 — a hard gate on the emission vin).
    ///
    /// An empty input set is rejected, never vacuously verified.
    ///
    /// This only queues the proofs for batch verification. The BatchVerifiers MUST
    /// also be verified.
    ///
    /// If this function returns an error, the BatchVerifiers MUST be considered
    /// corrupted and discarded.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        verifier_ed: &mut multiexp::BatchVerifier<(), <Ed25519 as Ciphersuite>::G>,
        verifier_1: &mut generalized_bulletproofs::BatchVerifier<Selene>,
        verifier_2: &mut generalized_bulletproofs::BatchVerifier<Helios>,
        tree: TreeRoot<<Curves as FcmpCurves>::C1, <Curves as FcmpCurves>::C2>,
        layers: usize,
        signable_tx_hash: [u8; 32],
        pqc_pk_hashes: Vec<<Selene as Ciphersuite>::F>,
    ) -> Result<(), FcmpPlusPlusError> {
        if self.inputs.is_empty() {
            return Err(FcmpPlusPlusError::EmptyInputs);
        }
        if self.inputs.len() != pqc_pk_hashes.len() {
            return Err(FcmpPlusPlusError::InvalidPqcPkHashQuantity);
        }

        let mut fcmp_inputs = Vec::with_capacity(self.inputs.len());
        for (index, ((input, membership_spend_auth), h_pqc)) in
            self.inputs.iter().zip(pqc_pk_hashes).enumerate()
        {
            // A u32 cannot overflow here: a proof with 2^32 inputs cannot be
            // constructed or deserialized.
            let index = u32::try_from(index).expect("more than u32::MAX inputs");
            membership_spend_auth.verify(rng, verifier_ed, signable_tx_hash, index, input);

            fcmp_inputs.push(fcmps::Input::with_extra_scalars(
                input.O_tilde,
                input.I_tilde,
                input.R,
                input.C_tilde,
                vec![h_pqc],
            )?);
        }

        Ok(self.fcmp.verify(
            rng,
            verifier_1,
            verifier_2,
            &*FCMP_PARAMS,
            tree,
            layers,
            &fcmp_inputs,
        )?)
    }
}
