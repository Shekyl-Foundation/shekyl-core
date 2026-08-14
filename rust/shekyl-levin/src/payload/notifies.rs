// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Cryptonote notify maps 2001–2004 / 2006–2010 (`cryptonote_protocol_defs.h`).

use shekyl_portable_storage::{Section, Value};

use super::block::BlockCompleteEntry;
use super::error::Error;
use super::get::{self, HASH_SIZE};
use super::PortableMap;

/// `NOTIFY_NEW_BLOCK` = `BC_COMMANDS_POOL_BASE + 1`.
pub const NOTIFY_NEW_BLOCK: u32 = 2001;
/// `NOTIFY_NEW_TRANSACTIONS`.
pub const NOTIFY_NEW_TRANSACTIONS: u32 = 2002;
/// `NOTIFY_REQUEST_GET_OBJECTS`.
pub const NOTIFY_REQUEST_GET_OBJECTS: u32 = 2003;
/// `NOTIFY_RESPONSE_GET_OBJECTS`.
pub const NOTIFY_RESPONSE_GET_OBJECTS: u32 = 2004;
/// `NOTIFY_REQUEST_CHAIN` — 2005 was never allocated.
pub const NOTIFY_REQUEST_CHAIN: u32 = 2006;
/// `NOTIFY_RESPONSE_CHAIN_ENTRY`.
pub const NOTIFY_RESPONSE_CHAIN_ENTRY: u32 = 2007;
/// `NOTIFY_NEW_FLUFFY_BLOCK`.
pub const NOTIFY_NEW_FLUFFY_BLOCK: u32 = 2008;
/// `NOTIFY_REQUEST_FLUFFY_MISSING_TX`.
pub const NOTIFY_REQUEST_FLUFFY_MISSING_TX: u32 = 2009;
/// `NOTIFY_GET_TXPOOL_COMPLEMENT`.
pub const NOTIFY_GET_TXPOOL_COMPLEMENT: u32 = 2010;

/// Body of `NOTIFY_NEW_BLOCK` (2001) and `NOTIFY_NEW_FLUFFY_BLOCK` (2008).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewBlock {
    /// Complete block (header blob + txs; fluffy peers may omit tx bodies).
    pub b: BlockCompleteEntry,
    /// Advertised chain height.
    pub current_blockchain_height: u64,
}

/// Same map as [`NewBlock`]; distinct command id [`NOTIFY_NEW_FLUFFY_BLOCK`].
pub type NewFluffyBlock = NewBlock;

impl PortableMap for NewBlock {
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

/// `NOTIFY_REQUEST_GET_OBJECTS` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestGetObjects {
    /// Block hashes, `CONTAINER_POD_AS_BLOB`.
    pub blocks: Vec<[u8; HASH_SIZE]>,
    /// `KV_SERIALIZE_OPT` default false.
    pub prune: bool,
}

impl PortableMap for RequestGetObjects {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        get::insert_pod_hashes(&mut section, "blocks", &self.blocks);
        get::insert_opt_bool(&mut section, "prune", self.prune, false);
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            blocks: get::pod_hashes(section, "blocks")?,
            prune: get::opt_bool(section, "prune", false)?,
        })
    }
}

/// `NOTIFY_RESPONSE_GET_OBJECTS` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseGetObjects {
    /// Requested blocks.
    pub blocks: Vec<BlockCompleteEntry>,
    /// Missed hashes, `CONTAINER_POD_AS_BLOB`.
    pub missed_ids: Vec<[u8; HASH_SIZE]>,
    /// Advertised chain height.
    pub current_blockchain_height: u64,
}

impl PortableMap for ResponseGetObjects {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        let mut objs = Vec::with_capacity(self.blocks.len());
        for block in &self.blocks {
            objs.push(block.to_section()?);
        }
        get::insert_object_array(&mut section, "blocks", objs);
        get::insert_pod_hashes(&mut section, "missed_ids", &self.missed_ids);
        section.insert(
            "current_blockchain_height",
            Value::UInt64(self.current_blockchain_height),
        );
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        let blocks = get::object_array(section, "blocks")?
            .into_iter()
            .map(BlockCompleteEntry::from_section)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            blocks,
            missed_ids: get::pod_hashes(section, "missed_ids")?,
            current_blockchain_height: get::u64_val(section, "current_blockchain_height")?,
        })
    }
}

/// `NOTIFY_REQUEST_CHAIN` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestChain {
    /// Locator hashes, `CONTAINER_POD_AS_BLOB`.
    pub block_ids: Vec<[u8; HASH_SIZE]>,
    /// `KV_SERIALIZE_OPT` default false.
    pub prune: bool,
}

impl PortableMap for RequestChain {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        get::insert_pod_hashes(&mut section, "block_ids", &self.block_ids);
        get::insert_opt_bool(&mut section, "prune", self.prune, false);
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            block_ids: get::pod_hashes(section, "block_ids")?,
            prune: get::opt_bool(section, "prune", false)?,
        })
    }
}

/// `NOTIFY_RESPONSE_CHAIN_ENTRY` body.
///
/// `cumulative_difficulty_top64` is store-always / load-OPT, matching
/// `CORE_SYNC_DATA`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseChainEntry {
    /// First height in the returned span.
    pub start_height: u64,
    /// Peer's chain height.
    pub total_height: u64,
    /// Low 64 bits of cumulative difficulty.
    pub cumulative_difficulty: u64,
    /// High 64 bits; stored unconditionally.
    pub cumulative_difficulty_top64: u64,
    /// Returned hashes, `CONTAINER_POD_AS_BLOB`.
    pub m_block_ids: Vec<[u8; HASH_SIZE]>,
    /// Block weights, `CONTAINER_POD_AS_BLOB` of `uint64`.
    pub m_block_weights: Vec<u64>,
    /// First block blob (always stored, may be empty).
    pub first_block: Vec<u8>,
}

impl PortableMap for ResponseChainEntry {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        section.insert("start_height", Value::UInt64(self.start_height));
        section.insert("total_height", Value::UInt64(self.total_height));
        section.insert(
            "cumulative_difficulty",
            Value::UInt64(self.cumulative_difficulty),
        );
        section.insert(
            "cumulative_difficulty_top64",
            Value::UInt64(self.cumulative_difficulty_top64),
        );
        get::insert_pod_hashes(&mut section, "m_block_ids", &self.m_block_ids);
        get::insert_pod_u64s(&mut section, "m_block_weights", &self.m_block_weights);
        section.insert("first_block", Value::Bytes(self.first_block.clone()));
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            start_height: get::u64_val(section, "start_height")?,
            total_height: get::u64_val(section, "total_height")?,
            cumulative_difficulty: get::u64_val(section, "cumulative_difficulty")?,
            cumulative_difficulty_top64: get::opt_u64(section, "cumulative_difficulty_top64", 0)?,
            m_block_ids: get::pod_hashes(section, "m_block_ids")?,
            m_block_weights: get::pod_u64s(section, "m_block_weights")?,
            first_block: get::bytes(section, "first_block")?.to_vec(),
        })
    }
}

/// `NOTIFY_REQUEST_FLUFFY_MISSING_TX` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestFluffyMissingTx {
    /// Block hash, POD-as-blob.
    pub block_hash: [u8; HASH_SIZE],
    /// Advertised chain height.
    pub current_blockchain_height: u64,
    /// Missing indices, `CONTAINER_POD_AS_BLOB` of `uint64`.
    pub missing_tx_indices: Vec<u64>,
}

impl PortableMap for RequestFluffyMissingTx {
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
