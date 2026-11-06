// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A fixed-length secret that lives on the heap.
//!
//! `Zeroizing<[u8; N]>` wipes the place a secret last rested. It does not
//! follow the secret there: an array is moved by copying it, so every move
//! of a value that holds one inline — into a struct, out of a function, into
//! a map — leaves the previous copy where it was, on a stack nobody wipes.
//! For a secret that sits in a struct which is itself moved, that is one
//! unwiped copy per move.
//!
//! [`HeapSecret`] holds the bytes behind a pointer. Moving it moves the
//! pointer; the bytes stay at the one address they were written to and are
//! wiped there on drop. The length stays in the type.
//!
//! The bytes are borrowed through [`HeapSecret::as_array`] and
//! [`HeapSecret::as_array_mut`]. There is no [`Deref`]: `[u8; N]` is `Copy`,
//! and a deref would let `*secret` rebuild the stack copy this type exists
//! to prevent. A copy is `*secret.as_array()`, which is visible at the call.
//! That is the same boundary [`crate::keys`] draws with `as_canonical_bytes`.
//!
//! It is its own type, and not `Zeroizing<Box<[u8; N]>>`, because `zeroize`
//! implements `Zeroize` for `Box<[Z]>` and not for `Box<[Z; N]>`, and the
//! orphan rule keeps that implementation out of this crate. `Zeroizing<Box<[u8]>>`
//! compiles and loses the length.
//!
//! Crate-private. [`crate::archival_p::ArchivalPKeys::hs_id_seed`] is the
//! public borrow of the one value other crates read. A crate that does not
//! depend on this one does not gain a dependency to hold its own secrets
//! this way; the type moves when such a crate needs it.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// `N` secret bytes at one heap address, wiped on drop. No `Clone`, no
/// `Copy`, and a `Debug` that prints nothing of the contents.
pub(crate) struct HeapSecret<const N: usize>(Box<[u8; N]>);

impl<const N: usize> HeapSecret<N> {
    /// `N` zero bytes, allocated on the heap without an `N`-byte array ever
    /// existing on the stack: the buffer is a zeroed vector first, and
    /// becomes a boxed array by a conversion that checks the length and
    /// moves nothing.
    #[must_use]
    pub(crate) fn zeroed() -> Self {
        let boxed: Box<[u8; N]> = vec![0u8; N]
            .into_boxed_slice()
            .try_into()
            .unwrap_or_else(|_| unreachable!("a vector of N bytes is N bytes long"));
        Self(boxed)
    }

    /// A copy of `bytes` at a fresh heap address. The source is borrowed, so
    /// whoever owns it still owns wiping it.
    #[must_use]
    pub(crate) fn copied_from(bytes: &[u8; N]) -> Self {
        let mut secret = Self::zeroed();
        secret.as_array_mut().copy_from_slice(bytes);
        secret
    }

    /// The buffer. A copy of the secret is `*secret.as_array()`.
    #[must_use]
    pub(crate) fn as_array(&self) -> &[u8; N] {
        &self.0
    }

    /// The buffer, writable in place. Key generation writes through this
    /// rather than returning an array.
    pub(crate) fn as_array_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> Zeroize for HeapSecret<N> {
    fn zeroize(&mut self) {
        // `&mut [u8; N]` into the heap buffer. `*self.0` would copy the
        // array and wipe the copy.
        self.as_array_mut().zeroize();
    }
}

impl<const N: usize> ZeroizeOnDrop for HeapSecret<N> {}

impl<const N: usize> Drop for HeapSecret<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const N: usize> std::fmt::Debug for HeapSecret<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HeapSecret<{N}>([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the type exists for: it is a pointer, whatever `N` is,
    /// so moving it copies no secret byte.
    #[test]
    fn it_is_a_pointer_whatever_its_length() {
        assert_eq!(
            std::mem::size_of::<HeapSecret<32>>(),
            std::mem::size_of::<usize>()
        );
        assert_eq!(
            std::mem::size_of::<HeapSecret<2369>>(),
            std::mem::size_of::<usize>()
        );
    }

    /// A move leaves the bytes at the address they were written to.
    #[test]
    fn a_move_does_not_move_the_bytes() {
        let secret = HeapSecret::<64>::copied_from(&[0x5a; 64]);
        let before = secret.as_array().as_ptr();
        let moved = std::convert::identity(secret);
        let boxed = Box::new(moved);
        let after = boxed.as_array().as_ptr();
        assert_eq!(before, after);
        assert_eq!(boxed.as_array(), &[0x5a; 64]);
    }

    #[test]
    fn zeroed_is_zero_and_copied_from_copies() {
        assert_eq!(HeapSecret::<48>::zeroed().as_array(), &[0u8; 48]);
        let mut secret = HeapSecret::<4>::copied_from(&[1, 2, 3, 4]);
        secret.as_array_mut()[0] = 9;
        assert_eq!(secret.as_array(), &[9, 2, 3, 4]);
    }

    /// `zeroize` writes the heap buffer, not a copy of it.
    #[test]
    fn zeroize_wipes_the_heap_buffer() {
        let mut secret = HeapSecret::<4>::copied_from(&[1, 2, 3, 4]);
        let addr = secret.as_array().as_ptr();
        secret.zeroize();
        assert_eq!(secret.as_array().as_ptr(), addr);
        assert_eq!(secret.as_array(), &[0, 0, 0, 0]);
    }

    #[test]
    fn debug_prints_no_content() {
        let shown = format!("{:?}", HeapSecret::<4>::copied_from(&[0xAB; 4]));
        assert_eq!(shown, "HeapSecret<4>([REDACTED])");
    }
}
