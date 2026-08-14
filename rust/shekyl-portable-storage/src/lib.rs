// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! Binary **portable_storage** codec — the self-describing KV envelope
//! Levin command bodies and HTTP `.bin` RPC speak.
//!
//! Spec: `docs/PORTABLE_STORAGE.md`. Decision:
//! `docs/design/LV2_PORTABLE_STORAGE.md` (LV-2a). This crate is the
//! format, not epee: no HTTP invoke, no logging, no Levin framing.
//!
//! # Oracle
//!
//! Encode matches C++ `store_to_binary` (`portable_storage_to_bin.h`).
//! Decode matches `load_from_binary` (`portable_storage_from_bin.h`),
//! including: little-endian PODs, lexicographic encode order
//! (`std::map` / `BTreeMap`), duplicate-key reject, trailing bytes
//! ignored, string length `< MAX_STRING_LEN_POSSIBLE`.
//!
//! # Divergences from C++ (enumerated once)
//!
//! - **Recursion.** C++ increments a counter on almost every `read`
//!   (including raw `memcpy`). This decoder counts nested
//!   section/entry/array depth against the same limit of 100. Deep
//!   primitive-only blobs that trip C++ but not structural depth are
//!   not a production shape.
//! - **Section keys** must be UTF-8. Production maps use ASCII
//!   identifiers.
//! - **Tag 13** (`SERIALIZE_TYPE_ARRAY`) and array-of-array are a hard
//!   error until a captured C++ body emits one.
//!
//! Typed command maps (`KV_SERIALIZE` / `OPT` / POD-as-blob) are
//! schema-layer and live in `shekyl-levin` (LV-2b). This codec just
//! has optional keys and `SERIALIZE_TYPE_STRING` blobs.

mod decode;
mod encode;
mod error;
mod limits;
mod value;
mod varint;

pub use error::Error;
pub use limits::Limits;
pub use value::{Array, Section, Value};

/// 9-byte header: `SIGNATUREA` `0x01011101`, `SIGNATUREB` `0x01020101`,
/// version `1`. Little-endian on the wire: `01 11 01 01 01 01 02 01 01`.
///
/// Spelled as a byte-string so the SA-3b domain-registry gate can grep
/// the literal at this defining site (`CRYPTO_DOMAIN_REGISTRY.tsv` mech-x
/// row).
pub const HEADER: [u8; 9] = *b"\x01\x11\x01\x01\x01\x01\x02\x01\x01";

/// `MAX_STRING_LEN_POSSIBLE` — decode rejects `len >=` this.
pub const MAX_STRING_LEN_POSSIBLE: u64 = 2_000_000_000;

/// `EPEE_PORTABLE_STORAGE_RECURSION_LIMIT` default.
pub const RECURSION_LIMIT: usize = 100;

pub(crate) const SERIALIZE_FLAG_ARRAY: u8 = 0x80;

pub(crate) mod ty {
    pub const INT64: u8 = 1;
    pub const INT32: u8 = 2;
    pub const INT16: u8 = 3;
    pub const INT8: u8 = 4;
    pub const UINT64: u8 = 5;
    pub const UINT32: u8 = 6;
    pub const UINT16: u8 = 7;
    pub const UINT8: u8 = 8;
    pub const DOUBLE: u8 = 9;
    pub const STRING: u8 = 10;
    pub const BOOL: u8 = 11;
    pub const OBJECT: u8 = 12;
    pub const ARRAY: u8 = 13;
}

/// Encode `root` as C++ `store_to_binary` would. Limits are a decode
/// concern; encode only rejects empty / overlong keys and oversized
/// varints.
pub fn store_to_binary(root: &Section) -> Result<Vec<u8>, Error> {
    encode::store_to_binary(root)
}

/// Decode a blob. Trailing bytes after the root section are ignored
/// (C++ `load_from_binary` does the same).
pub fn load_from_binary(bytes: &[u8], limits: Limits) -> Result<Section, Error> {
    decode::load_from_binary(bytes, limits)
}
