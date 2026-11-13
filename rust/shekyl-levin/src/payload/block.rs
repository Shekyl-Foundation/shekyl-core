// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `tx_blob_entry` / `block_complete_entry` (`cryptonote_protocol_defs.h`).

use shekyl_portable_storage::{Section, Value};

use super::error::Error;
use super::get::{self, HASH_SIZE};
use super::PortableMap;

/// Transport cap on a block's bundle references: one section's,
/// `shekyl_types::archival::MAX_SECTION_REFERENCES` (`W₂`'s ruled upper
/// edge). A reference's own length grows with its bitmaps, which grow with
/// `D`, chain state; the packet caps the bytes. The references are not
/// decoded here: a malformed one is a verdict on the block (CEN-J29), not a
/// framing fault.
pub const MAX_BUNDLE_REFERENCES: usize = shekyl_types::archival::MAX_SECTION_REFERENCES;

/// Refuse a section past [`MAX_BUNDLE_REFERENCES`]: the block codecs check
/// it on both sides, not their callers.
pub(super) fn check_references(references: &[Vec<u8>]) -> Result<(), Error> {
    if references.len() > MAX_BUNDLE_REFERENCES {
        Err(Error::TooManyReferences {
            got: references.len(),
            max: MAX_BUNDLE_REFERENCES,
        })
    } else {
        Ok(())
    }
}

/// `cryptonote::tx_blob_entry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxBlobEntry {
    /// Opaque tx bytes (`shekyl-wire` owns the layout).
    pub blob: Vec<u8>,
    /// `crypto::hash` POD-as-blob. Unpruned `block_complete_entry` load
    /// always fills this with zeros (C++ `crypto::null_hash`).
    pub prunable_hash: [u8; HASH_SIZE],
}

impl PortableMap for TxBlobEntry {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        section.insert("blob", Value::Bytes(self.blob.clone()));
        section.insert("prunable_hash", Value::Bytes(self.prunable_hash.to_vec()));
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            blob: get::bytes(section, "blob")?.to_vec(),
            prunable_hash: get::blob(section, "prunable_hash")?,
        })
    }
}

/// `cryptonote::block_complete_entry`.
///
/// Unpruned `txs` store as an array of blobs (hashes dropped). Pruned `txs`
/// store as an array of [`TxBlobEntry`] objects. Empty arrays omit the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockCompleteEntry {
    /// `KV_SERIALIZE_OPT` default false.
    pub pruned: bool,
    /// Opaque block blob.
    pub block: Vec<u8>,
    /// `KV_SERIALIZE_OPT` default 0.
    pub block_weight: u64,
    /// Transactions. See the pruned / unpruned store split above.
    pub txs: Vec<TxBlobEntry>,
    /// The block's bundle references, undecoded, in the block's order. The
    /// key is omitted when there are none. At most
    /// [`MAX_BUNDLE_REFERENCES`], checked at this codec, not at callers.
    pub bundle_references: Vec<Vec<u8>>,
}

impl PortableMap for BlockCompleteEntry {
    fn to_section(&self) -> Result<Section, Error> {
        check_references(&self.bundle_references)?;
        let mut section = Section::new();
        get::insert_opt_bool(&mut section, "pruned", self.pruned, false);
        section.insert("block", Value::Bytes(self.block.clone()));
        get::insert_opt_u64(&mut section, "block_weight", self.block_weight, 0);
        if self.pruned {
            let mut objs = Vec::with_capacity(self.txs.len());
            for tx in &self.txs {
                objs.push(tx.to_section()?);
            }
            get::insert_object_array(&mut section, "txs", objs);
        } else {
            let blobs: Vec<Vec<u8>> = self.txs.iter().map(|tx| tx.blob.clone()).collect();
            get::insert_bytes_array(&mut section, "txs", &blobs);
        }
        get::insert_bytes_array(&mut section, "bundle_references", &self.bundle_references);
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        let pruned = get::opt_bool(section, "pruned", false)?;
        let txs = if pruned {
            get::object_array(section, "txs")?
                .into_iter()
                .map(TxBlobEntry::from_section)
                .collect::<Result<Vec<_>, _>>()?
        } else {
            get::bytes_array(section, "txs")?
                .into_iter()
                .map(|blob| TxBlobEntry {
                    blob,
                    prunable_hash: [0u8; HASH_SIZE],
                })
                .collect()
        };
        let bundle_references = opt_references(section)?;
        Ok(Self {
            pruned,
            block: get::bytes(section, "block")?.to_vec(),
            block_weight: get::opt_u64(section, "block_weight", 0)?,
            txs,
            bundle_references,
        })
    }
}

/// A block's `bundle_references`, absent when it has none, refused past
/// [`MAX_BUNDLE_REFERENCES`].
pub(super) fn opt_references(section: &Section) -> Result<Vec<Vec<u8>>, Error> {
    let references = get::bytes_array(section, "bundle_references")?;
    check_references(&references)?;
    Ok(references)
}
