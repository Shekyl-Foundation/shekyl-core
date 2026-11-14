// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The signing envelope: the one function every Shekyl-owned hash,
//! signature and proof derives its message through (`NETWORK_IDENTITY.md`
//! §2.6; the signing envelope §2.1, §2.6).
//!
//! ```text
//! framed(b)                       = u64_le(len(b)) ‖ b
//! frame(domain, binding, fields)  = cSHAKE256(S = domain,
//!                                             X = binding ‖ framed(f_1) ‖ … ‖ framed(f_n))
//! ```
//!
//! - **The domain** is a registered constant (`CRYPTO_DOMAIN_REGISTRY.tsv`),
//!   versioned in its own name. It is typed by its binding, its field count
//!   and its output width, so a call site cannot pass the other binding, a
//!   different number of fields, or take a different width than the row
//!   declares: each is a compile error, not a review finding.
//! - **The binding** is 16 bytes at position 0, unframed: the network's
//!   genesis-derived [`NetworkId`] for anything signed or proved against the
//!   chain ([`IdDomain`]), or its [`NameId`] for anything derived from keys
//!   or addresses, which exist before genesis ([`NameDomain`]) (NI-R10,
//!   NI-R15).
//! - **Every field** is length-framed, so a fixed inventory of variable
//!   fields stays unambiguous. A list is one field: the concatenation of its
//!   fixed-width entries. An integer is its `u64_le` bytes, framed like any
//!   other field.
//!
//! The output is the first `W` bytes of the XOF stream: 32 unless the row
//! says 64. A digest that is itself the signed content of a hybrid
//! signature keeps 64 (`shekyl_crypto_hash::cshake256_64`'s reason).

use shekyl_crypto_hash::{cshake256_32, cshake256_64};
use zeroize::Zeroizing;

use crate::{NameId, NetworkId};

/// The binding's width: a [`NetworkId`] or a [`NameId`].
pub const BINDING_LEN: usize = 16;

mod sealed {
    /// Marker. [`super::Width`] is implemented only for [`super::W32`] and
    /// [`super::W64`]. The marker has no methods: a `W: Width` bound must
    /// not be able to hash.
    pub trait Sealed {}
}

/// The output widths a domain may declare: [`W32`] and [`W64`].
///
/// One width is one output type: two domains of the same width share it,
/// which is the ruling (2026-11-07). [`IdDomain::frame`] and
/// [`NameDomain::frame`] are implemented for these two widths and return
/// [`Framed32`] or [`Framed64`]. There is no hash on this trait. A bound
/// `W: Width` cannot build a digest, and a width outside this module
/// cannot exist.
///
/// ```compile_fail,E0599
/// use shekyl_network::envelope::Width;
/// fn unframed<W: Width>() {
///     let _ = W::hash(b"custom", b"not a frame");
/// }
/// ```
///
/// ```compile_fail,E0277
/// struct Other;
/// impl shekyl_network::envelope::Width for Other {}
/// ```
pub trait Width: sealed::Sealed {}

/// 32-byte output, the default.
#[derive(Clone, Copy, Debug)]
pub enum W32 {}

/// 64-byte output, for a digest that is a hybrid signature's signed content.
#[derive(Clone, Copy, Debug)]
pub enum W64 {}

/// A 32-byte frame output: a public digest bound to one network's id or
/// name. Like the other public hashes it orders, hashes and reads as bytes.
/// [`IdDomain::frame`] and [`NameDomain::frame`] are what make one.
///
/// ```compile_fail,E0423
/// let _ = shekyl_network::envelope::Framed32([0u8; 32]);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Framed32([u8; 32]);

/// A 64-byte frame output: a hybrid signature's signed content, bound to one
/// network's id or name. [`IdDomain::frame`] and [`NameDomain::frame`] are
/// what make one.
///
/// ```compile_fail,E0423
/// let _ = shekyl_network::envelope::Framed64([0u8; 64]);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Framed64([u8; 64]);

impl AsRef<[u8]> for Framed32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Framed64 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Framed32 {
    /// The digest's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The digest's bytes, by value.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl Framed64 {
    /// The digest's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// The digest's bytes, by value.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 64] {
        self.0
    }
}

impl sealed::Sealed for W32 {}
impl Width for W32 {}

impl sealed::Sealed for W64 {}
impl Width for W64 {}

/// A domain bound to the network's id: signed or proved against the chain.
/// `N` is its field count, `W` its output width.
#[derive(Debug)]
pub struct IdDomain<const N: usize, W: Width = W32> {
    customization: &'static [u8],
    width: core::marker::PhantomData<W>,
}

/// A domain bound to the network's name: derived from keys or addresses.
#[derive(Debug)]
pub struct NameDomain<const N: usize, W: Width = W32> {
    customization: &'static [u8],
    width: core::marker::PhantomData<W>,
}

macro_rules! domain_common {
    ($ty:ident) => {
        impl<const N: usize, W: Width> $ty<N, W> {
            /// The domain whose customization string is `customization`.
            ///
            /// # Panics
            ///
            /// At compile time, for an empty customization (cSHAKE with an
            /// empty customization is plain SHAKE256) or a domain of no fields.
            #[must_use]
            pub const fn new(customization: &'static [u8]) -> Self {
                assert!(!customization.is_empty(), "a domain has a customization");
                assert!(N > 0, "a domain frames at least one field");
                Self {
                    customization,
                    width: core::marker::PhantomData,
                }
            }

            /// The registered customization string.
            #[must_use]
            pub const fn customization(&self) -> &'static [u8] {
                self.customization
            }
        }

        impl<const N: usize, W: Width> Clone for $ty<N, W> {
            fn clone(&self) -> Self {
                *self
            }
        }
        impl<const N: usize, W: Width> Copy for $ty<N, W> {}
    };
}
domain_common!(IdDomain);
domain_common!(NameDomain);

impl<const N: usize> IdDomain<N, W32> {
    /// The 32-byte frame of `fields` under this domain and `id`.
    #[must_use]
    pub fn frame(&self, id: &NetworkId, fields: [&[u8]; N]) -> Framed32 {
        digest_32(self.customization, id, &fields)
    }
}

impl<const N: usize> IdDomain<N, W64> {
    /// The 64-byte frame of `fields` under this domain and `id`.
    #[must_use]
    pub fn frame(&self, id: &NetworkId, fields: [&[u8]; N]) -> Framed64 {
        digest_64(self.customization, id, &fields)
    }
}

impl<const N: usize> NameDomain<N, W32> {
    /// The 32-byte frame of `fields` under this domain and `name`.
    #[must_use]
    pub fn frame(&self, name: &NameId, fields: [&[u8]; N]) -> Framed32 {
        digest_32(self.customization, name.as_bytes(), &fields)
    }
}

impl<const N: usize> NameDomain<N, W64> {
    /// The 64-byte frame of `fields` under this domain and `name`.
    #[must_use]
    pub fn frame(&self, name: &NameId, fields: [&[u8]; N]) -> Framed64 {
        digest_64(self.customization, name.as_bytes(), &fields)
    }
}

/// `framed(f_1) ‖ … ‖ framed(f_n)`: each field behind its u64-LE length.
/// No binding. The field half of [`input`].
#[must_use]
pub fn framed_fields(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(framed_len(fields));
    push_framed(&mut out, fields);
    out
}

fn framed_len(fields: &[&[u8]]) -> usize {
    fields.iter().map(|f| 8 + f.len()).sum()
}

fn push_framed(out: &mut Vec<u8>, fields: &[&[u8]]) {
    for field in fields {
        let len = u64::try_from(field.len()).expect("a field is shorter than 2^64 bytes");
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(field);
    }
}

/// `X = binding ‖ framed(f_1) ‖ … ‖ framed(f_n)`, in one buffer wiped on
/// drop: a field may be secret-bearing (a multisig ceremony file's body), and
/// this is the only copy the frame makes. The capacity is exact, so the
/// buffer never reallocates and leaves no unwiped copy behind.
fn input(binding: &[u8; BINDING_LEN], fields: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut x = Zeroizing::new(Vec::with_capacity(BINDING_LEN + framed_len(fields)));
    x.extend_from_slice(binding);
    push_framed(&mut x, fields);
    debug_assert_eq!(x.len(), x.capacity());
    x
}

/// The 32-byte digest of one framed input. Private: [`IdDomain::frame`] and
/// [`NameDomain::frame`] are the constructors of [`Framed32`].
fn digest_32(customization: &[u8], binding: &[u8; BINDING_LEN], fields: &[&[u8]]) -> Framed32 {
    Framed32(cshake256_32(customization, &input(binding, fields)))
}

/// The 64-byte digest of one framed input. Private: [`IdDomain::frame`] and
/// [`NameDomain::frame`] are the constructors of [`Framed64`].
fn digest_64(customization: &[u8], binding: &[u8; BINDING_LEN], fields: &[&[u8]]) -> Framed64 {
    Framed64(cshake256_64(customization, &input(binding, fields)))
}

#[cfg(test)]
mod tests;
