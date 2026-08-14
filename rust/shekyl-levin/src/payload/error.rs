// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Schema-layer failures. Distinct from framing [`crate::Error`]: a bad
//! command body does not latch [`crate::BucketReader`].

/// Typed-map encode / decode failure (LV-2b).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The portable_storage codec rejected the blob.
    #[error(transparent)]
    Storage(#[from] shekyl_portable_storage::Error),
    /// A required KV field was absent.
    #[error("missing field {0}")]
    MissingField(&'static str),
    /// A field was present with the wrong portable_storage type tag.
    #[error("field {field} is not {expected}")]
    TypeMismatch {
        /// KV key.
        field: &'static str,
        /// Expected tag name (`uint64`, `object`, …).
        expected: &'static str,
    },
    /// A POD-as-blob field was the wrong width.
    #[error("field {field} is {got} bytes, expected {expected}")]
    InvalidLength {
        /// KV key.
        field: &'static str,
        /// Required width.
        expected: usize,
        /// Observed width.
        got: usize,
    },
    /// `network_address.type` was not 1–4.
    #[error("unknown network_address type {0}")]
    UnknownAddressType(u8),
    /// A `std::string` field was not UTF-8.
    #[error("field {0} is not valid UTF-8")]
    NotUtf8(&'static str),
}
