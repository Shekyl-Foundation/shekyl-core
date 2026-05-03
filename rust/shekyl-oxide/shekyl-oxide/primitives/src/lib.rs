#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use std_shims::io;
#[allow(unused_imports)]
use std_shims::prelude::*;
#[cfg(feature = "std")]
use std_shims::sync::LazyLock;

use zeroize::{Zeroize, ZeroizeOnDrop};

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{EdwardsPoint, VartimeEdwardsPrecomputation},
    scalar::Scalar,
    traits::{MultiscalarMul, VartimePrecomputedMultiscalarMul},
};
use sha3::{Digest, Keccak256};

use shekyl_generators::H;
use shekyl_io::*;

mod unreduced_scalar;
pub use unreduced_scalar::UnreducedScalar;

#[cfg(test)]
mod tests;

// On std, we cache some variables in statics.
#[cfg(feature = "std")]
static INV_EIGHT_CELL: LazyLock<Scalar> = LazyLock::new(|| Scalar::from(8u8).invert());
/// The inverse of 8 over l, the prime factor of the order of Ed25519.
#[cfg(feature = "std")]
#[allow(non_snake_case)]
pub fn INV_EIGHT() -> Scalar {
    *INV_EIGHT_CELL
}
// In no-std environments, we prefer the reduced memory use and calculate it ad-hoc.
/// The inverse of 8 over l, the prime factor of the order of Ed25519.
#[cfg(not(feature = "std"))]
#[allow(non_snake_case)]
pub fn INV_EIGHT() -> Scalar {
    Scalar::from(8u8).invert()
}

#[cfg(feature = "std")]
static G_PRECOMP_CELL: LazyLock<VartimeEdwardsPrecomputation> =
    LazyLock::new(|| VartimeEdwardsPrecomputation::new([ED25519_BASEPOINT_POINT]));
/// A cached (if std) pre-computation of the Ed25519 generator, G.
#[cfg(feature = "std")]
#[allow(non_snake_case)]
pub fn G_PRECOMP() -> &'static VartimeEdwardsPrecomputation {
    &G_PRECOMP_CELL
}
/// A cached (if std) pre-computation of the Ed25519 generator, G.
#[cfg(not(feature = "std"))]
#[allow(non_snake_case)]
pub fn G_PRECOMP() -> VartimeEdwardsPrecomputation {
    VartimeEdwardsPrecomputation::new([ED25519_BASEPOINT_POINT])
}

/// The Keccak-256 hash function.
pub fn keccak256(data: impl AsRef<[u8]>) -> [u8; 32] {
    Keccak256::digest(data.as_ref()).into()
}

/// Hash the provided data to a scalar via keccak256(data) % l.
///
/// This function panics if it finds the Keccak-256 preimage for [0; 32].
pub fn keccak256_to_scalar(data: impl AsRef<[u8]>) -> Scalar {
    let scalar = Scalar::from_bytes_mod_order(keccak256(&data));
    // Monero will explicitly error in this case
    // This library acknowledges its practical impossibility of it occurring, and doesn't bother to
    // code in logic to handle it. That said, if it ever occurs, something must happen in order to
    // not generate/verify a proof we believe to be valid when it isn't
    assert!(
        scalar != Scalar::ZERO,
        "keccak256(preimage) \\cong 0 \\mod l! Preimage: {:?}",
        data.as_ref()
    );
    scalar
}

/// Transparent structure representing a Pedersen commitment's contents.
#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Commitment {
    /// The mask for this commitment.
    pub mask: Scalar,
    /// The amount committed to by this commitment.
    pub amount: u64,
}

impl core::fmt::Debug for Commitment {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        fmt.debug_struct("Commitment")
            .field("amount", &self.amount)
            .finish_non_exhaustive()
    }
}

impl Commitment {
    /// A commitment to zero, defined with a mask of 1 (as to not be the identity).
    pub fn zero() -> Commitment {
        Commitment {
            mask: Scalar::ONE,
            amount: 0,
        }
    }

    /// Create a new Commitment.
    pub fn new(mask: Scalar, amount: u64) -> Commitment {
        Commitment { mask, amount }
    }

    /// Calculate the Pedersen commitment, as a point, from this transparent structure.
    pub fn calculate(&self) -> EdwardsPoint {
        EdwardsPoint::multiscalar_mul(
            [self.mask, self.amount.into()],
            [ED25519_BASEPOINT_POINT, *H],
        )
    }

    /// Write the Commitment.
    ///
    /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
    /// defined serialization.
    pub fn write<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.mask.to_bytes())?;
        w.write_all(&self.amount.to_le_bytes())
    }

    /// Serialize the Commitment to a `Vec<u8>`.
    ///
    /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
    /// defined serialization.
    pub fn serialize(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(32 + 8);
        self.write(&mut res)
            .expect("write failed but <Vec as io::Write> doesn't fail");
        res
    }

    /// Read a Commitment.
    ///
    /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
    /// defined serialization.
    pub fn read<R: io::Read>(r: &mut R) -> io::Result<Commitment> {
        Ok(Commitment::new(read_scalar(r)?, read_u64(r)?))
    }
}
