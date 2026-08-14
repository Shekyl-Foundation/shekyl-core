// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `tx_blob_entry` / `block_complete_entry` (`cryptonote_protocol_defs.h`).

use shekyl_portable_storage::{Section, Value};

use super::error::Error;
use super::get::{self, HASH_SIZE};
use super::PortableMap;

/// Transport cap for `attestation_witness`, duplicated from
/// `config::ARCHIVAL_ATTESTATION_WITNESS_MAX_BYTES`
/// (`src/cryptonote_config.h`) / `shekyl-archival-retention::MAX_ATTESTATION_WITNESS_BYTES`.
///
/// Formula: `r(32) + count(8) + 256 * 3385` (`PQC_HYBRID_SINGLE_SIG_LEN` /
/// `HybridSignature::CANONICAL_LEN`). This crate does **not** take
/// `shekyl-archival-retention` as a production dependency (that stack is
/// heavier than a framing crate). The numeric identity is pinned below and
/// in `tests/notify_kats.rs`.
pub const ATTESTATION_WITNESS_MAX_BYTES: usize = 32 + 8 + 256 * 3385;

const _: () = assert!(ATTESTATION_WITNESS_MAX_BYTES == 866_600);

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
    /// Opaque attestation witness. `KV_SERIALIZE_OPT` default empty.
    /// Cap-checked at this codec, not at callers.
    pub attestation_witness: Vec<u8>,
}

impl BlockCompleteEntry {
    fn check_witness(bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > ATTESTATION_WITNESS_MAX_BYTES {
            Err(Error::WitnessTooLarge {
                got: bytes.len(),
                max: ATTESTATION_WITNESS_MAX_BYTES,
            })
        } else {
            Ok(())
        }
    }
}

impl PortableMap for BlockCompleteEntry {
    fn to_section(&self) -> Result<Section, Error> {
        Self::check_witness(&self.attestation_witness)?;
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
        get::insert_opt_bytes(
            &mut section,
            "attestation_witness",
            &self.attestation_witness,
        );
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
        let attestation_witness = get::opt_bytes(section, "attestation_witness")?;
        Self::check_witness(&attestation_witness)?;
        Ok(Self {
            pruned,
            block: get::bytes(section, "block")?.to_vec(),
            block_weight: get::opt_u64(section, "block_weight", 0)?,
            txs,
            attestation_witness,
        })
    }
}
