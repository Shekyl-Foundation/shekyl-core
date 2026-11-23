use std_shims::vec::Vec;

use subtle::ConditionallySelectable;
use zeroize::{Zeroize, ZeroizeOnDrop};

use ciphersuite::Ciphersuite;

use crate::{Generators, PedersenOpening, PedersenVectorOpening, PointVector};

/// Every opening a prover commits to: the vector commitments' (the statement's `C`) and the
/// Pedersen commitments' (the statement's `V`), each in commitment order.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Openings<C: Ciphersuite> {
    /// The vector commitments' openings.
    pub vector: Vec<PedersenVectorOpening<C>>,
    /// The Pedersen commitments' openings.
    pub scalar: Vec<PedersenOpening<C>>,
}

/// A vector commitment's opening holds more values than there are `g` (bold) generators.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NotEnoughGenerators {
    /// The vector commitment's position among [`Openings::vector`].
    pub vector_commitment: usize,
}

/// Commitments computed from the prover's own openings, held with them.
///
/// The only way a prover obtains commitments to transcript: [`Openings::commit`] makes them, and
/// [`crate::transcript::Transcript::write_commitments`] takes nothing else. A commitment can
/// therefore never disagree with the opening the prover's witness carries for it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OpenedCommitments<C: Ciphersuite> {
    pub(crate) C: PointVector<C>,
    pub(crate) V: PointVector<C>,
    pub(crate) openings: Openings<C>,
}

impl<C: Ciphersuite> Openings<C>
where
    C::G: ConditionallySelectable,
{
    /// Commit to every opening under `generators`, the generators the statement is formed over.
    ///
    /// Each commitment is a constant-time multiexp over its opening.
    pub fn commit(
        self,
        generators: &Generators<C>,
    ) -> Result<OpenedCommitments<C>, NotEnoughGenerators> {
        let C = self
            .vector
            .iter()
            .enumerate()
            .map(|(vector_commitment, opening)| {
                opening
                    .commit(generators.g_bold_slice(), generators.h())
                    .ok_or(NotEnoughGenerators { vector_commitment })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let V = self
            .scalar
            .iter()
            .map(|opening| opening.commit(generators.g(), generators.h()))
            .collect();
        Ok(OpenedCommitments {
            C: PointVector(C),
            V: PointVector(V),
            openings: self,
        })
    }
}

impl<C: Ciphersuite> OpenedCommitments<C> {
    /// The vector commitments (the statement's `C`).
    pub fn C(&self) -> &[C::G] {
        &self.C.0
    }
    /// The Pedersen commitments (the statement's `V`).
    pub fn V(&self) -> &[C::G] {
        &self.V.0
    }
}
