// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared infrastructure for [`WalletState`](super::WalletState) blocks:
//! error type, `u8`-repr enum macro, `Network`-as-u8 serde, and the
//! 32-byte hex helpers used by secret fields across blocks.

pub use shekyl_address::network::Network;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by [`WalletState`](super::WalletState) (de)serialization.
#[derive(Debug, thiserror::Error)]
pub enum WalletStateError {
    /// The on-disk `format_version` does not match the version this
    /// binary knows how to read. `format_version` is the bundle-shape
    /// version (which blocks exist in the top-level `WalletState`); it
    /// bumps only when blocks are added or removed. Per the rule-81
    /// "no silent migration" stance we refuse rather than migrate.
    #[error(
        "unsupported wallet-state format version: file = {file}, binary = {binary}; \
         no migration path exists in this binary"
    )]
    UnsupportedFormatVersion { file: u32, binary: u32 },

    /// A block's own `block_version` does not match the version this
    /// binary knows how to read for that block. Each block evolves
    /// independently; a mismatch on any block aborts the whole load.
    #[error(
        "unsupported {block} block version: file = {file}, binary = {binary}; \
         no migration path exists in this binary"
    )]
    UnsupportedBlockVersion {
        block: &'static str,
        file: u32,
        binary: u32,
    },

    /// A numeric enum discriminant on disk does not correspond to any
    /// known variant. Loudly refused rather than silently defaulted.
    #[error("unknown {field} variant: {value}")]
    UnknownEnumVariant { field: &'static str, value: u8 },

    /// `serde_json` failure (malformed JSON, missing required field,
    /// type mismatch, etc.).
    #[error("wallet-state JSON decode failed: {0}")]
    Json(#[from] serde_json::Error),

    /// A field whose contents must be exactly `N` bytes had the wrong length.
    #[error("{field} has wrong byte length: got {got}, expected {expected}")]
    BadLength {
        field: &'static str,
        got: usize,
        expected: usize,
    },

    /// `network` on disk does not correspond to a known `Network` variant.
    #[error("unknown network discriminant: {0}")]
    UnknownNetwork(u8),
}

// ---------------------------------------------------------------------------
// `repr_u8_enum!`
//
// Generates a Rust enum with:
//   * `#[serde(into = "u8", try_from = "u8")]` wire format
//   * `From<Self> for u8`
//   * `TryFrom<u8> for Self` returning `WalletStateError::UnknownEnumVariant`
//
// Variants are explicitly valued so the wire format is stable across any
// future reordering of variant declarations.
// ---------------------------------------------------------------------------

macro_rules! repr_u8_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident ($field:literal) {
            $( $variant:ident = $value:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash,
            ::serde::Serialize, ::serde::Deserialize,
        )]
        #[serde(into = "u8", try_from = "u8")]
        $vis enum $name {
            $( $variant = $value, )+
        }

        impl From<$name> for u8 {
            fn from(v: $name) -> u8 { v as u8 }
        }

        impl ::core::convert::TryFrom<u8> for $name {
            type Error = $crate::wallet_state::primitives::WalletStateError;
            fn try_from(v: u8) -> ::core::result::Result<Self, Self::Error> {
                match v {
                    $( $value => Ok(Self::$variant), )+
                    other => Err(
                        $crate::wallet_state::primitives::WalletStateError::UnknownEnumVariant {
                            field: $field,
                            value: other,
                        },
                    ),
                }
            }
        }
    };
}

pub(crate) use repr_u8_enum;

// ---------------------------------------------------------------------------
// `Network` serde: we deliberately serialize `Network` as `u8` rather than
// enabling the `shekyl-address` crate's `serde` feature. Pinning the
// discriminant at this layer avoids dragging the feature flag through the
// dep graph, keeps an integer wire format stable across any textual
// renaming of the enum, and matches the on-FFI discriminant used elsewhere
// in the codebase.
// ---------------------------------------------------------------------------

pub(crate) mod network_as_u8 {
    use super::{Network, WalletStateError};
    use serde::{de::Error as _, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(n: &Network, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(n.as_u8())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Network, D::Error> {
        let v = <u8 as serde::Deserialize>::deserialize(d)?;
        Network::from_u8(v)
            .ok_or_else(|| D::Error::custom(WalletStateError::UnknownNetwork(v).to_string()))
    }
}

// ---------------------------------------------------------------------------
// 32-byte secret hex helpers. Shared across settings blocks and (future)
// cache blocks. Bytes are always wrapped in `Zeroizing` on the Rust side;
// the hex form is text so the surrounding JSON stays text.
// ---------------------------------------------------------------------------

pub(crate) fn encode_hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub(crate) fn decode_hex32(s: &str, field: &'static str) -> Result<[u8; 32], WalletStateError> {
    if s.len() != 64 {
        return Err(WalletStateError::BadLength {
            field,
            got: s.len(),
            expected: 64,
        });
    }
    let mut arr = [0u8; 32];
    let bytes = s.as_bytes();
    for (i, chunk) in bytes.chunks(2).enumerate() {
        let hi = nibble(chunk[0], field)?;
        let lo = nibble(chunk[1], field)?;
        arr[i] = (hi << 4) | lo;
    }
    Ok(arr)
}

fn nibble(c: u8, field: &'static str) -> Result<u8, WalletStateError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(10 + c - b'a'),
        b'A'..=b'F' => Ok(10 + c - b'A'),
        _ => Err(WalletStateError::BadLength {
            field,
            got: 0,
            expected: 64,
        }),
    }
}
