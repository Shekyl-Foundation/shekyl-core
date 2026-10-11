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
//! wiped there on drop. The length stays in the type, so a consumer that
//! wants `&[u8; N]` still gets one.
//!
//! It is its own type, and not `Zeroizing<Box<[u8; N]>>`, because `zeroize`
//! implements `Zeroize` for `Box<[Z]>` and not for `Box<[Z; N]>`, and the
//! orphan rule keeps that implementation out of this crate. `Zeroizing<Box<[u8]>>`
//! compiles and loses the length.

use zeroize::Zeroize;

/// `N` secret bytes at one heap address, wiped on drop. No `Clone`, no
/// `Copy`, and a `Debug` that prints nothing of the contents.
pub struct HeapSecret<const N: usize>(Box<[u8; N]>);

impl<const N: usize> HeapSecret<N> {
    /// `N` zero bytes, allocated on the heap without an `N`-byte array ever
    /// existing on the stack: the buffer is a zeroed vector first, and
    /// becomes a boxed array by a conversion that checks the length and
    /// moves nothing.
    #[must_use]
    pub fn zeroed() -> Self {
        let boxed: Box<[u8; N]> = vec![0u8; N]
            .into_boxed_slice()
            .try_into()
            .unwrap_or_else(|_| unreachable!("a vector of N bytes is N bytes long"));
        Self(boxed)
    }

    /// A copy of `bytes` at a fresh heap address. The source is borrowed, so
    /// whoever owns it still owns wiping it.
    #[must_use]
    pub fn copied_from(bytes: &[u8; N]) -> Self {
        let mut secret = Self::zeroed();
        secret.0.copy_from_slice(bytes);
        secret
    }
}

impl<const N: usize> std::ops::Deref for HeapSecret<N> {
    type Target = [u8; N];

    fn deref(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> std::ops::DerefMut for HeapSecret<N> {
    fn deref_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> Drop for HeapSecret<N> {
    fn drop(&mut self) {
        self.0.zeroize();
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
        let before: *const [u8; 64] = &raw const *secret;
        let moved = std::convert::identity(secret);
        let boxed = Box::new(moved);
        let after: *const [u8; 64] = &raw const **boxed;
        assert_eq!(before, after);
        assert_eq!(**boxed, [0x5a; 64]);
    }

    #[test]
    fn zeroed_is_zero_and_copied_from_copies() {
        assert_eq!(*HeapSecret::<48>::zeroed(), [0u8; 48]);
        let mut secret = HeapSecret::<4>::copied_from(&[1, 2, 3, 4]);
        secret[0] = 9;
        assert_eq!(*secret, [9, 2, 3, 4]);
    }

    #[test]
    fn debug_prints_no_content() {
        let shown = format!("{:?}", HeapSecret::<4>::copied_from(&[0xAB; 4]));
        assert_eq!(shown, "HeapSecret<4>([REDACTED])");
    }
}
