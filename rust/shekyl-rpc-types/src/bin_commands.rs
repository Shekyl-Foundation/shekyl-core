// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `.bin` half of the wire contract — methods that speak
//! **portable_storage** rather than JSON.
//!
//! `shekyl-portable-storage` is the *codec*: it moves a [`Section`] to and
//! from bytes and says nothing about what keys a method carries. Its own
//! docs put the typed command maps in the schema layer, and
//! `shekyl-levin`'s schema layer is for p2p ("RPC maps stay out"). So this
//! module is the RPC schema layer, next to the JSON types rather than in a
//! crate of its own: RK-D1 is one definition per method, whichever encoding
//! it speaks.
//!
//! Two rules the JSON side does not have to think about, both learned from
//! the captures rather than from the C++ declarations:
//!
//! * **`KV_SERIALIZE_VAL_POD_AS_BLOB` is raw bytes, not hex.** A 32-byte
//!   hash crosses as a 32-byte `Bytes` value. On the JSON wire the same
//!   field would be 64 hex characters ([`HashHex`](crate::HashHex)); here
//!   that spelling would be wrong and the daemon would read a different
//!   transaction.
//! * **An empty sequence is absent, not `[]`.** epee drops it from the
//!   document, so a decoder must read a missing key as empty and an encoder
//!   must not write one.

use shekyl_portable_storage::{load_from_binary, store_to_binary, Array, Limits, Section, Value};

/// Why a `.bin` document was not the message it claimed to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinError {
    /// The bytes are not a portable_storage document at all.
    Codec(String),
    /// A key was present but held the wrong type.
    WrongType(&'static str),
    /// A required key was missing.
    Missing(&'static str),
    /// A blob field was the wrong size for what it names.
    BadLength { field: &'static str, len: usize },
}

impl core::fmt::Display for BinError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Codec(e) => write!(f, "not a portable_storage document: {e}"),
            Self::WrongType(k) => write!(f, "field {k} has the wrong type"),
            Self::Missing(k) => write!(f, "required field {k} is missing"),
            Self::BadLength { field, len } => {
                write!(f, "field {field} is {len} bytes, expected 32")
            }
        }
    }
}

impl core::error::Error for BinError {}

/// Request of `/get_o_indexes.bin`: the transaction whose global output
/// indices are wanted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetOIndexesRequest {
    /// The transaction id, as raw bytes — this field is POD-as-blob on the
    /// wire, so it is **not** hex here.
    pub txid: [u8; 32],
}

impl GetOIndexesRequest {
    /// Encode to portable_storage bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BinError::Codec`] if the codec cannot serialize the
    /// document, which for this shape means an allocation failure.
    pub fn to_bin(&self) -> Result<Vec<u8>, BinError> {
        let mut root = Section::new();
        root.insert("txid", Value::Bytes(self.txid.to_vec()));
        store_to_binary(&root).map_err(|e| BinError::Codec(e.to_string()))
    }

    /// Decode from portable_storage bytes.
    ///
    /// # Errors
    ///
    /// [`BinError`] if the bytes are not a document, or `txid` is absent,
    /// not a blob, or not 32 bytes long.
    pub fn from_bin(bytes: &[u8]) -> Result<Self, BinError> {
        let root = load_from_binary(bytes, Limits::HTTP_BIN)
            .map_err(|e| BinError::Codec(e.to_string()))?;
        match root.get("txid") {
            Some(Value::Bytes(raw)) => {
                let len = raw.len();
                let txid: [u8; 32] = raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| BinError::BadLength { field: "txid", len })?;
                Ok(Self { txid })
            }
            Some(_) => Err(BinError::WrongType("txid")),
            None => Err(BinError::Missing("txid")),
        }
    }
}

/// Response of `/get_o_indexes.bin`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetOIndexesResponse {
    pub status: crate::RpcStatus,
    /// Global output indices, in the transaction's output order. **Absent
    /// from the document when empty** — epee drops an empty sequence — so
    /// an encoder must not write one and a decoder reads its absence as
    /// this vector being empty.
    pub o_indexes: Vec<u64>,
}

impl GetOIndexesResponse {
    /// Encode to portable_storage bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BinError::Codec`] if the codec cannot serialize the
    /// document.
    pub fn to_bin(&self) -> Result<Vec<u8>, BinError> {
        let mut root = Section::new();
        root.insert("status", Value::Bytes(self.status.0.clone().into_bytes()));
        if !self.o_indexes.is_empty() {
            root.insert(
                "o_indexes",
                Value::Array(Array::UInt64(self.o_indexes.clone())),
            );
        }
        store_to_binary(&root).map_err(|e| BinError::Codec(e.to_string()))
    }

    /// Decode from portable_storage bytes.
    ///
    /// # Errors
    ///
    /// [`BinError`] if the bytes are not a document, `status` is absent or
    /// not text, or `o_indexes` is present but not a `uint64` array.
    pub fn from_bin(bytes: &[u8]) -> Result<Self, BinError> {
        let root = load_from_binary(bytes, Limits::HTTP_BIN)
            .map_err(|e| BinError::Codec(e.to_string()))?;
        let status = match root.get("status") {
            Some(Value::Bytes(raw)) => crate::RpcStatus(String::from_utf8_lossy(raw).into_owned()),
            Some(_) => return Err(BinError::WrongType("status")),
            None => return Err(BinError::Missing("status")),
        };
        let o_indexes = match root.get("o_indexes") {
            // Absent means empty, which is what epee emits for an empty
            // sequence — not an error and not a missing field.
            None => Vec::new(),
            Some(Value::Array(Array::UInt64(v))) => v.clone(),
            Some(_) => return Err(BinError::WrongType("o_indexes")),
        };
        Ok(Self { status, o_indexes })
    }
}

/// Request of `/get_blocks_by_height.bin` (alias
/// `/getblocks_by_height.bin`): the heights wanted, in the order the reply
/// will carry them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GetBlocksByHeightRequest {
    pub heights: Vec<u64>,
}

impl GetBlocksByHeightRequest {
    /// Encode to portable_storage bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BinError::Codec`] if the codec cannot serialize the
    /// document.
    pub fn to_bin(&self) -> Result<Vec<u8>, BinError> {
        let mut root = Section::new();
        if !self.heights.is_empty() {
            root.insert("heights", Value::Array(Array::UInt64(self.heights.clone())));
        }
        store_to_binary(&root).map_err(|e| BinError::Codec(e.to_string()))
    }

    /// Decode from portable_storage bytes.
    ///
    /// # Errors
    ///
    /// [`BinError`] if the bytes are not a document, or `heights` is present
    /// but is not a `uint64` array.
    pub fn from_bin(bytes: &[u8]) -> Result<Self, BinError> {
        let root = load_from_binary(bytes, Limits::HTTP_BIN)
            .map_err(|e| BinError::Codec(e.to_string()))?;
        let heights = match root.get("heights") {
            None => Vec::new(),
            Some(Value::Array(Array::UInt64(v))) => v.clone(),
            Some(_) => return Err(BinError::WrongType("heights")),
        };
        Ok(Self { heights })
    }
}

/// One block of a `/get_blocks_by_height.bin` reply.
///
/// Deliberately **not** a model of C++'s `block_complete_entry`, which has
/// five KV members. This endpoint's handler sets two, so `pruned` and
/// `block_weight` go out at their OPT defaults and `attestation_witness`
/// empty — none of the three reaches the wire, which the oracle capture
/// shows rather than the declaration.
///
/// The consequence is in `txs`. With `pruned` false the C++ map serializes
/// a `std::vector<blobdata>`, so transactions cross as an **array of
/// strings** and each entry's `prunable_hash` is dropped. The
/// array-of-objects form is reachable only from the p2p path, whose schema
/// lives in `shekyl-levin` — modelling it here would carry a variant this
/// daemon can never emit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockEntry {
    /// The block in its consensus encoding.
    pub block: Vec<u8>,
    /// Its transactions, likewise. Absent from the document when empty.
    pub txs: Vec<Vec<u8>>,
}

/// Response of `/get_blocks_by_height.bin`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetBlocksByHeightResponse {
    pub status: crate::RpcStatus,
    /// One entry per requested height, in request order. Absent from the
    /// document when empty.
    pub blocks: Vec<BlockEntry>,
}

impl GetBlocksByHeightResponse {
    /// Encode to portable_storage bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BinError::Codec`] if the codec cannot serialize the
    /// document.
    pub fn to_bin(&self) -> Result<Vec<u8>, BinError> {
        let mut root = Section::new();
        root.insert("status", Value::Bytes(self.status.0.clone().into_bytes()));
        if !self.blocks.is_empty() {
            let mut entries = Vec::with_capacity(self.blocks.len());
            for entry in &self.blocks {
                let mut section = Section::new();
                section.insert("block", Value::Bytes(entry.block.clone()));
                if !entry.txs.is_empty() {
                    section.insert("txs", Value::Array(Array::Bytes(entry.txs.clone())));
                }
                entries.push(section);
            }
            root.insert("blocks", Value::Array(Array::Object(entries)));
        }
        store_to_binary(&root).map_err(|e| BinError::Codec(e.to_string()))
    }

    /// Decode from portable_storage bytes.
    ///
    /// # Errors
    ///
    /// [`BinError`] if the bytes are not a document, `status` is absent or
    /// not text, or `blocks` holds anything but sections carrying a `block`
    /// blob and an optional array of transaction blobs.
    pub fn from_bin(bytes: &[u8]) -> Result<Self, BinError> {
        let root = load_from_binary(bytes, Limits::HTTP_BIN)
            .map_err(|e| BinError::Codec(e.to_string()))?;
        let status = match root.get("status") {
            Some(Value::Bytes(raw)) => crate::RpcStatus(String::from_utf8_lossy(raw).into_owned()),
            Some(_) => return Err(BinError::WrongType("status")),
            None => return Err(BinError::Missing("status")),
        };
        let blocks = match root.get("blocks") {
            None => Vec::new(),
            Some(Value::Array(Array::Object(sections))) => {
                let mut out = Vec::with_capacity(sections.len());
                for section in sections {
                    let block = match section.get("block") {
                        Some(Value::Bytes(raw)) => raw.clone(),
                        Some(_) => return Err(BinError::WrongType("block")),
                        None => return Err(BinError::Missing("block")),
                    };
                    let txs = match section.get("txs") {
                        None => Vec::new(),
                        Some(Value::Array(Array::Bytes(v))) => v.clone(),
                        Some(_) => return Err(BinError::WrongType("txs")),
                    };
                    out.push(BlockEntry { block, txs });
                }
                out
            }
            Some(_) => return Err(BinError::WrongType("blocks")),
        };
        Ok(Self { status, blocks })
    }
}
