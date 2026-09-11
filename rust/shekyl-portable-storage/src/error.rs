// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

/// Encode / decode failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Input shorter than the 9-byte header, or a read ran off the end.
    #[error("truncated portable_storage blob")]
    Truncated,
    /// Signature or format version did not match.
    #[error("portable_storage header mismatch")]
    BadHeader,
    /// Section key length was 0.
    #[error("section key is empty")]
    EmptyKey,
    /// Encode: key length ≥ 255. Decode: accepted 1..=255.
    #[error("section key longer than 254 bytes")]
    KeyTooLong,
    /// Section keys in Shekyl production maps are ASCII identifiers; this
    /// decoder requires UTF-8 so consumers can use `&str` lookups.
    #[error("section key is not valid UTF-8")]
    KeyNotUtf8,
    /// Two fields in one section shared a name.
    #[error("duplicate section key")]
    DuplicateKey,
    /// Type tag outside 1–12 (or 1–12 with the array flag), excluding the
    /// hard-error tag-13 case.
    #[error("unknown type tag {0}")]
    UnknownType(u8),
    /// `SERIALIZE_TYPE_ARRAY` (13) or array-of-array. Hard error until a
    /// captured C++ body emits one (`LV2_PORTABLE_STORAGE.md` §11).
    #[error("untyped array (tag 13) is not supported")]
    UntypedArray,
    /// Bool byte was not 0 or 1.
    #[error("bool value is not 0 or 1")]
    InvalidBool,
    /// String length ≥ `MAX_STRING_LEN_POSSIBLE` (2_000_000_000).
    #[error("string longer than MAX_STRING_LEN_POSSIBLE")]
    StringTooLong,
    /// Varint value does not fit the C++ `pack_varint` range.
    #[error("varint exceeds encodeable range")]
    VarintTooLarge,
    /// Nested-section count exceeded the caller's object limit.
    #[error("too many objects (limit {limit})")]
    TooManyObjects { limit: usize },
    /// Cumulative field count exceeded the caller's field limit.
    #[error("too many fields (limit {limit})")]
    TooManyFields { limit: usize },
    /// String / string-array element count exceeded the caller's string limit.
    #[error("too many strings (limit {limit})")]
    TooManyStrings { limit: usize },
    /// Nested section/array depth reached 100.
    #[error("portable_storage recursion limit (100) exceeded")]
    RecursionLimit,
    /// Array length vs remaining bytes failed the C++ `ps_min_bytes` check.
    #[error("array size fails remaining-bytes sanity check")]
    ArrayTooLarge,
}
