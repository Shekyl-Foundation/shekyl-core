#[cfg(feature = "alloc")]
use std_shims::io::{self, Read};
#[cfg(feature = "alloc")]
#[allow(unused_imports)]
use std_shims::prelude::*;

use zeroize::Zeroize;

use blake2::{Blake2b512, Digest};

use crate::{Field25519, HeliosPoint, HelioseleneField, SelenePoint};
use group::Group;
#[cfg(feature = "alloc")]
use group::GroupEncoding;

use ciphersuite::Ciphersuite;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct Helios;
impl Ciphersuite for Helios {
    type F = HelioseleneField;
    type G = HeliosPoint;
    type H = Blake2b512;

    const ID: &'static [u8] = b"Helios";

    fn generator() -> Self::G {
        <HeliosPoint as Group>::generator()
    }

    fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F {
        let mut uniform = [0; 64];
        let mut hash = Blake2b512::digest([dst, msg].concat());
        uniform.copy_from_slice(hash.as_ref());
        let hash_as_mut: &mut [u8] = hash.as_mut();
        hash_as_mut.zeroize();
        let res = HelioseleneField::wide_reduce(uniform);
        uniform.zeroize();
        res
    }

    // We override the provided impl, which compares against the reserialization, because
    // Helios::G::from_bytes already enforces canonically encoded points
    #[cfg(feature = "alloc")]
    #[allow(non_snake_case)]
    fn read_G<R: Read>(reader: &mut R) -> io::Result<Self::G> {
        let mut encoding = <Self::G as GroupEncoding>::Repr::default();
        reader.read_exact(encoding.as_mut())?;

        let point = Option::<Self::G>::from(Self::G::from_bytes(&encoding))
            .ok_or_else(|| io::Error::other("invalid point"))?;
        Ok(point)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct Selene;
impl Ciphersuite for Selene {
    type F = Field25519;
    type G = SelenePoint;
    type H = Blake2b512;

    const ID: &'static [u8] = b"Selene";

    fn generator() -> Self::G {
        <SelenePoint as Group>::generator()
    }

    fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F {
        let mut uniform = [0; 64];
        let mut hash = Blake2b512::digest([dst, msg].concat());
        uniform.copy_from_slice(hash.as_ref());
        let hash_as_mut: &mut [u8] = hash.as_mut();
        hash_as_mut.zeroize();
        let res = Field25519::wide_reduce(uniform);
        uniform.zeroize();
        res
    }

    // We override the provided impl, which compares against the reserialization, because
    // Selene::G::from_bytes already enforces canonically encoded points
    #[cfg(feature = "alloc")]
    #[allow(non_snake_case)]
    fn read_G<R: Read>(reader: &mut R) -> io::Result<Self::G> {
        let mut encoding = <Self::G as GroupEncoding>::Repr::default();
        reader.read_exact(encoding.as_mut())?;

        let point = Option::<Self::G>::from(Self::G::from_bytes(&encoding))
            .ok_or_else(|| io::Error::other("invalid point"))?;
        Ok(point)
    }
}
