// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Cryptonote notify maps 2002–2004 / 2006–2010 (`cryptonote_protocol_defs.h`).
//!
//! 2011–2014 are the chain-sync commands ([`super::sync`]). They are named
//! here, beside the ids they follow, and they are not admitted at ingress:
//! no handler exists until the cutover.

use shekyl_portable_storage::{Section, Value};

use super::block::BlockCompleteEntry;
use super::error::Error;
use super::get::{self, HASH_SIZE};
use super::PortableMap;

/// `NOTIFY_NEW_TRANSACTIONS`.
pub const NOTIFY_NEW_TRANSACTIONS: u32 = 2002;
/// `NOTIFY_NEW_COMPACT_BLOCK`.
pub const NOTIFY_NEW_COMPACT_BLOCK: u32 = 2008;
/// `NOTIFY_REQUEST_COMPACT_MISSING_TX`.
pub const NOTIFY_REQUEST_COMPACT_MISSING_TX: u32 = 2009;
/// `NOTIFY_GET_TXPOOL_COMPLEMENT`.
pub const NOTIFY_GET_TXPOOL_COMPLEMENT: u32 = 2010;
/// Chain-sync header request. The next free id after 2010. Not a
/// [`crate::DefinedCommand`]: the attached router keeps it for chain
/// sync's owner, and the C++ ingress never sees it. 2003, 2004, 2006 and
/// 2007, the inherited block and chain requests, are retired (CS-5):
/// their ids are not commands this protocol defines.
pub const NOTIFY_REQUEST_HEADERS: u32 = 2011;
/// Chain-sync header response.
pub const NOTIFY_RESPONSE_HEADERS: u32 = 2012;
/// Chain-sync body request.
pub const NOTIFY_REQUEST_BODIES: u32 = 2013;
/// Chain-sync body response.
pub const NOTIFY_RESPONSE_BODIES: u32 = 2014;

/// Body of `NOTIFY_NEW_COMPACT_BLOCK` (2008), the sole block-announce command.
/// Header plus optional tx bodies; omitted txs are fetched via 2009.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCompactBlock {
    /// Block header blob plus any tx bodies the sender included.
    pub b: BlockCompleteEntry,
    /// Advertised chain height.
    pub current_blockchain_height: u64,
}

impl PortableMap for NewCompactBlock {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        section.insert("b", Value::Object(self.b.to_section()?));
        section.insert(
            "current_blockchain_height",
            Value::UInt64(self.current_blockchain_height),
        );
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            b: BlockCompleteEntry::from_section(get::object(section, "b")?)?,
            current_blockchain_height: get::u64_val(section, "current_blockchain_height")?,
        })
    }
}

/// `NOTIFY_NEW_TRANSACTIONS` body.
///
/// `_` padding is **always stored** (even empty). `dandelionpp_fluff` is
/// `KV_SERIALIZE_OPT` default **true** (omit when fluff). Empty `txs` omit
/// the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTransactions {
    /// Opaque tx blobs.
    pub txs: Vec<Vec<u8>>,
    /// Cover-traffic padding.
    pub padding: Vec<u8>,
    /// Fluff (true, default) vs stem (false).
    pub dandelionpp_fluff: bool,
}

impl PortableMap for NewTransactions {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        get::insert_bytes_array(&mut section, "txs", &self.txs);
        section.insert("_", Value::Bytes(self.padding.clone()));
        get::insert_opt_bool(
            &mut section,
            "dandelionpp_fluff",
            self.dandelionpp_fluff,
            true,
        );
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            txs: get::bytes_array(section, "txs")?,
            padding: get::bytes(section, "_")?.to_vec(),
            dandelionpp_fluff: get::opt_bool(section, "dandelionpp_fluff", true)?,
        })
    }
}

/// `NOTIFY_REQUEST_COMPACT_MISSING_TX` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestCompactMissingTx {
    /// Block hash, POD-as-blob.
    pub block_hash: [u8; HASH_SIZE],
    /// Advertised chain height.
    pub current_blockchain_height: u64,
    /// Missing indices, `CONTAINER_POD_AS_BLOB` of `uint64`.
    pub missing_tx_indices: Vec<u64>,
}

impl PortableMap for RequestCompactMissingTx {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        section.insert("block_hash", Value::Bytes(self.block_hash.to_vec()));
        section.insert(
            "current_blockchain_height",
            Value::UInt64(self.current_blockchain_height),
        );
        get::insert_pod_u64s(&mut section, "missing_tx_indices", &self.missing_tx_indices);
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            block_hash: get::blob(section, "block_hash")?,
            current_blockchain_height: get::u64_val(section, "current_blockchain_height")?,
            missing_tx_indices: get::pod_u64s(section, "missing_tx_indices")?,
        })
    }
}

/// `NOTIFY_GET_TXPOOL_COMPLEMENT` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetTxpoolComplement {
    /// Pool hashes, `CONTAINER_POD_AS_BLOB`.
    pub hashes: Vec<[u8; HASH_SIZE]>,
}

impl PortableMap for GetTxpoolComplement {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        get::insert_pod_hashes(&mut section, "hashes", &self.hashes);
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            hashes: get::pod_hashes(section, "hashes")?,
        })
    }
}
