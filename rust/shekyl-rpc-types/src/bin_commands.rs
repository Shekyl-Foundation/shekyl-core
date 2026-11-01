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
/// will carry them, and the form each listed body takes (`SB-Q2`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GetBlocksByHeightRequest {
    pub heights: Vec<u64>,
    /// The pruned form: every listed transaction is its skeleton
    /// ([`BlockTx::Skeleton`]), which every node holds at every horizon.
    /// Off, the full form: whole bodies, with one this node has discarded
    /// carried as [`BlockTx::Archived`]. A switch (IG-4): off by default,
    /// and absent from the document when off.
    pub prune: bool,
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
        if self.prune {
            root.insert("prune", Value::Bool(true));
        }
        store_to_binary(&root).map_err(|e| BinError::Codec(e.to_string()))
    }

    /// Decode from portable_storage bytes.
    ///
    /// # Errors
    ///
    /// [`BinError`] if the bytes are not a document, `heights` is present
    /// but is not a `uint64` array, or `prune` is present but not a bool.
    pub fn from_bin(bytes: &[u8]) -> Result<Self, BinError> {
        let root = load_from_binary(bytes, Limits::HTTP_BIN)
            .map_err(|e| BinError::Codec(e.to_string()))?;
        let heights = match root.get("heights") {
            None => Vec::new(),
            Some(Value::Array(Array::UInt64(v))) => v.clone(),
            Some(_) => return Err(BinError::WrongType("heights")),
        };
        let prune = match root.get("prune") {
            None => false,
            Some(Value::Bool(v)) => *v,
            Some(_) => return Err(BinError::WrongType("prune")),
        };
        Ok(Self { heights, prune })
    }
}

/// The `form` tag of one [`BlockTx`] section: a whole body.
pub const BLOCK_TX_FORM_FULL: u8 = 1;
/// The `form` tag of a skeleton.
pub const BLOCK_TX_FORM_SKELETON: u8 = 2;
/// The `form` tag of an archived slot.
pub const BLOCK_TX_FORM_ARCHIVED: u8 = 3;

/// A transaction's skeleton as the `.bin` wire carries it: the pruned
/// segment and the three txid operands. The same value `get_transactions`
/// carries in hex and the sync wire carries as `shekyl_wire::SkeletonTx`;
/// the store builds all three with one function (`SB-Q2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockTxSkeleton {
    /// The pruned segment, exactly: the prefix and the pruned part of the
    /// CT body, never with `pqc_auths` appended.
    pub unprunable: Vec<u8>,
    /// Digest of the prunable region.
    pub prunable_hash: [u8; 32],
    /// Digest of the `pqc_auths` region; `None` when the txid has no
    /// third operand. Absent from the document when `None`.
    pub pqc_auth_hash: Option<[u8; 32]>,
    /// The archival good's length in bytes.
    pub archival_len: u64,
}

/// One listed transaction of a [`BlockEntry`]: the slot's state, in the
/// block's list order (`SB-Q2`, `PDM-Q10`).
///
/// Each is a section tagged by `form`. A full-form reply carries
/// [`BlockTx::Full`] for a body this node holds whole and
/// [`BlockTx::Archived`] for one it discarded at the archival horizon —
/// a state of that slot, never a failure of the height. A pruned-form
/// reply carries [`BlockTx::Skeleton`] for every slot. A transaction with
/// no archival good (a coinbase) is never archived: its whole body is its
/// skeleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockTx {
    /// The whole body, in its consensus encoding.
    Full(Vec<u8>),
    /// The skeleton.
    Skeleton(BlockTxSkeleton),
    /// Discarded here with the shard it went in; the archive serves the
    /// body, and every daemon answers the skeleton under `prune`.
    Archived { tx_hash: [u8; 32], shard: u64 },
}

impl BlockTx {
    fn to_section(&self) -> Section {
        let mut section = Section::new();
        match self {
            Self::Full(blob) => {
                section.insert("form", Value::UInt8(BLOCK_TX_FORM_FULL));
                section.insert("blob", Value::Bytes(blob.clone()));
            }
            Self::Skeleton(skeleton) => {
                section.insert("form", Value::UInt8(BLOCK_TX_FORM_SKELETON));
                section.insert("unprunable", Value::Bytes(skeleton.unprunable.clone()));
                section.insert(
                    "prunable_hash",
                    Value::Bytes(skeleton.prunable_hash.to_vec()),
                );
                if let Some(hash) = skeleton.pqc_auth_hash {
                    section.insert("pqc_auth_hash", Value::Bytes(hash.to_vec()));
                }
                section.insert("archival_len", Value::UInt64(skeleton.archival_len));
            }
            Self::Archived { tx_hash, shard } => {
                section.insert("form", Value::UInt8(BLOCK_TX_FORM_ARCHIVED));
                section.insert("tx_hash", Value::Bytes(tx_hash.to_vec()));
                section.insert("shard", Value::UInt64(*shard));
            }
        }
        section
    }

    fn from_section(section: &Section) -> Result<Self, BinError> {
        let form = match section.get("form") {
            Some(Value::UInt8(v)) => *v,
            Some(_) => return Err(BinError::WrongType("form")),
            None => return Err(BinError::Missing("form")),
        };
        match form {
            BLOCK_TX_FORM_FULL => Ok(Self::Full(bytes_field(section, "blob")?)),
            BLOCK_TX_FORM_SKELETON => Ok(Self::Skeleton(BlockTxSkeleton {
                unprunable: bytes_field(section, "unprunable")?,
                prunable_hash: hash_field(section, "prunable_hash")?,
                pqc_auth_hash: match section.get("pqc_auth_hash") {
                    None => None,
                    Some(_) => Some(hash_field(section, "pqc_auth_hash")?),
                },
                archival_len: u64_field(section, "archival_len")?,
            })),
            BLOCK_TX_FORM_ARCHIVED => Ok(Self::Archived {
                tx_hash: hash_field(section, "tx_hash")?,
                shard: u64_field(section, "shard")?,
            }),
            _ => Err(BinError::WrongType("form")),
        }
    }
}

fn bytes_field(section: &Section, key: &'static str) -> Result<Vec<u8>, BinError> {
    match section.get(key) {
        Some(Value::Bytes(raw)) => Ok(raw.clone()),
        Some(_) => Err(BinError::WrongType(key)),
        None => Err(BinError::Missing(key)),
    }
}

fn hash_field(section: &Section, key: &'static str) -> Result<[u8; 32], BinError> {
    <[u8; 32]>::try_from(bytes_field(section, key)?.as_slice())
        .map_err(|_| BinError::WrongType(key))
}

fn u64_field(section: &Section, key: &'static str) -> Result<u64, BinError> {
    match section.get(key) {
        Some(Value::UInt64(v)) => Ok(*v),
        Some(_) => Err(BinError::WrongType(key)),
        None => Err(BinError::Missing(key)),
    }
}

/// One block of a `/get_blocks_by_height.bin` reply.
///
/// Deliberately **not** a model of C++'s `block_complete_entry`, which had
/// five KV members of which this handler set two; `pruned`, `block_weight`
/// and `attestation_witness` never reached this wire and are not modelled.
/// Its `txs` crossed as an array of strings. Since 3.64 each listed
/// transaction is a tagged section — the slot's state ([`BlockTx`]) — so a
/// pruned-form reply and an archived body have a place in the list that
/// keeps the block's order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockEntry {
    /// The block in its consensus encoding.
    pub block: Vec<u8>,
    /// Its listed transactions, in the block's order. Absent from the
    /// document when empty.
    pub txs: Vec<BlockTx>,
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
                    let txs = entry.txs.iter().map(BlockTx::to_section).collect();
                    section.insert("txs", Value::Array(Array::Object(txs)));
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
    /// blob and an optional array of [`BlockTx`] sections.
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
                        Some(Value::Array(Array::Object(v))) => v
                            .iter()
                            .map(BlockTx::from_section)
                            .collect::<Result<Vec<_>, _>>()?,
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
