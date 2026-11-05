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

use crate::{NameId, NetworkId};

/// The binding's width: a [`NetworkId`] or a [`NameId`].
pub const BINDING_LEN: usize = 16;

/// The output widths a domain may declare.
pub trait Width {
    /// The digest.
    type Out;
    /// `cSHAKE256(S = customization, X = input)`, this many bytes.
    fn hash(customization: &[u8], input: &[u8]) -> Self::Out;
}

/// 32-byte output, the default.
#[derive(Clone, Copy, Debug)]
pub enum W32 {}

/// 64-byte output, for a digest that is a hybrid signature's signed content.
#[derive(Clone, Copy, Debug)]
pub enum W64 {}

impl Width for W32 {
    type Out = [u8; 32];
    fn hash(customization: &[u8], input: &[u8]) -> [u8; 32] {
        cshake256_32(customization, input)
    }
}

impl Width for W64 {
    type Out = [u8; 64];
    fn hash(customization: &[u8], input: &[u8]) -> [u8; 64] {
        cshake256_64(customization, input)
    }
}

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

impl<const N: usize, W: Width> IdDomain<N, W> {
    /// `frame(self, id, fields)`.
    #[must_use]
    pub fn frame(&self, id: &NetworkId, fields: [&[u8]; N]) -> W::Out {
        W::hash(self.customization, &input(id, &fields))
    }
}

impl<const N: usize, W: Width> NameDomain<N, W> {
    /// `frame(self, name_id, fields)`.
    #[must_use]
    pub fn frame(&self, name: &NameId, fields: [&[u8]; N]) -> W::Out {
        W::hash(self.customization, &input(name.as_bytes(), &fields))
    }
}

/// `framed(f_1) ‖ … ‖ framed(f_n)`: each field behind its u64-LE length.
/// No binding. The field half of [`input`].
#[must_use]
pub fn framed_fields(fields: &[&[u8]]) -> Vec<u8> {
    let len = fields.iter().map(|f| 8 + f.len()).sum::<usize>();
    let mut out = Vec::with_capacity(len);
    for field in fields {
        let len = u64::try_from(field.len()).expect("a field is shorter than 2^64 bytes");
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(field);
    }
    out
}

/// `X = binding ‖ framed(f_1) ‖ … ‖ framed(f_n)`.
fn input(binding: &[u8; BINDING_LEN], fields: &[&[u8]]) -> Vec<u8> {
    let framed = framed_fields(fields);
    let mut x = Vec::with_capacity(BINDING_LEN + framed.len());
    x.extend_from_slice(binding);
    x.extend_from_slice(&framed);
    x
}

#[cfg(test)]
mod tests;
