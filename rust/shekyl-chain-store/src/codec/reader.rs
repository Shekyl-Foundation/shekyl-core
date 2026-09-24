// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A strict cursor for variable-width codecs: every read is bounds-checked
//! and a short buffer is a [`CodecError::Invalid`] naming the codec and what
//! ran out — never a panic, never a lenient read.
//!
//! One definition, shared by every variable-width codec in this store
//! (`undo_log`, the archival bond record). It was `undo.rs`'s private cursor
//! until DRS-E1 S-ARCH needed a second one; a second copy would have been
//! two places to keep the same bounds discipline.

use shekyl_store_codec::CodecError;

/// The cursor. `codec` is the [`Canonical::NAME`](shekyl_store_codec::Canonical::NAME)
/// every fault it raises is filed under.
pub(crate) struct Reader<'a> {
    codec: &'static str,
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A cursor over `buf`, faulting as `codec`.
    pub(crate) const fn new(codec: &'static str, buf: &'a [u8]) -> Self {
        Self { codec, buf }
    }

    /// A [`CodecError::Invalid`] in this codec's name.
    pub(crate) const fn invalid(&self, reason: &'static str) -> CodecError {
        CodecError::Invalid {
            codec: self.codec,
            reason,
        }
    }

    /// Whether every byte has been consumed. A codec asserts this last: a
    /// value followed by anything is not one encoding of that value.
    pub(crate) const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The next `n` bytes, or `Invalid(what)` if fewer remain.
    pub(crate) fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], CodecError> {
        if self.buf.len() < n {
            return Err(self.invalid(what));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    /// One byte (a tag, a flag, a kind).
    pub(crate) fn u8(&mut self) -> Result<u8, CodecError> {
        self.take(1, "buffer ends inside a tag or flag byte")
            .map(|b| b[0])
    }

    /// A little-endian `u32` (a count, a length).
    pub(crate) fn u32(&mut self) -> Result<u32, CodecError> {
        self.take(4, "buffer ends inside a u32 field")
            .map(|b| u32::from_le_bytes(b.try_into().expect("take(4) yields 4 bytes")))
    }

    /// A little-endian `u64`.
    pub(crate) fn u64(&mut self) -> Result<u64, CodecError> {
        self.take(8, "buffer ends inside a u64 field")
            .map(|b| u64::from_le_bytes(b.try_into().expect("take(8) yields 8 bytes")))
    }

    /// A fixed-width byte array.
    pub(crate) fn array<const N: usize>(
        &mut self,
        what: &'static str,
    ) -> Result<[u8; N], CodecError> {
        self.take(N, what)
            .map(|b| b.try_into().expect("take(N) yields N bytes"))
    }

    /// A `u32`-length-prefixed byte string, bounded only by the bytes that
    /// remain (the length cannot name more than the buffer holds, so no
    /// allocation is sized past the input).
    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], CodecError> {
        self.bytes_bounded(usize::MAX, "unreachable: usize::MAX cap")
    }

    /// A `u32`-length-prefixed byte string, bounded by `cap` **before** the
    /// length is used for anything — the count is untrusted bytes and never
    /// sizes an allocation past what the codec admits.
    pub(crate) fn bytes_bounded(
        &mut self,
        cap: usize,
        over_cap: &'static str,
    ) -> Result<&'a [u8], CodecError> {
        let len = usize::try_from(self.u32()?)
            .map_err(|_| self.invalid("byte length exceeds the address space"))?;
        if len > cap {
            return Err(self.invalid(over_cap));
        }
        self.take(len, "buffer ends inside a byte field")
    }

    /// A `u32` element count, refused when it names more elements than the
    /// remaining bytes could hold at `min_element_len` each — so no
    /// allocation is ever sized from a count the bytes do not back.
    pub(crate) fn count_bounded(
        &mut self,
        min_element_len: usize,
        cap: usize,
        over_cap: &'static str,
    ) -> Result<usize, CodecError> {
        let count = usize::try_from(self.u32()?)
            .map_err(|_| self.invalid("element count exceeds the address space"))?;
        if count > cap {
            return Err(self.invalid(over_cap));
        }
        if min_element_len > 0 && count > self.buf.len() / min_element_len {
            return Err(self.invalid("element count exceeds what the row's bytes can hold"));
        }
        Ok(count)
    }
}

/// Append a `u32`-length-prefixed byte string — the writer's half of
/// [`Reader::bytes_bounded`].
pub(crate) fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    let len = u32::try_from(b.len()).expect("redb refuses values past 3 GiB; u32 is enough");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(b);
}

/// Append a `u32` element count — the writer's half of [`Reader::count_bounded`].
pub(crate) fn put_count(out: &mut Vec<u8>, n: usize) {
    let count = u32::try_from(n).expect("a stored row holds fewer than 2^32 elements");
    out.extend_from_slice(&count.to_le_bytes());
}
