// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared handshake / timed-sync maps: `basic_node_data`, `CORE_SYNC_DATA`,
//! `peerlist_entry`.

use shekyl_portable_storage::{Array, Section, Value};

use super::address::NetworkAddress;
use super::error::Error;
use super::get;
use super::PortableMap;

/// `nodetool::basic_node_data` (`p2p_protocol_defs.h`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicNodeData {
    /// `network_id` POD-as-blob (`boost::uuids::uuid`, 16 bytes).
    pub network_id: [u8; 16],
    /// `peerid_type` (`uint64_t`).
    pub peer_id: u64,
    /// Advertised p2p port.
    pub my_port: u32,
    /// `KV_SERIALIZE_OPT` default 0.
    pub rpc_port: u16,
    /// `KV_SERIALIZE_OPT` default 0.
    pub rpc_credits_per_hash: u32,
    /// `KV_SERIALIZE_OPT` default 0.
    pub support_flags: u32,
}

impl PortableMap for BasicNodeData {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        section.insert("network_id", Value::Bytes(self.network_id.to_vec()));
        section.insert("peer_id", Value::UInt64(self.peer_id));
        section.insert("my_port", Value::UInt32(self.my_port));
        get::insert_opt_u16(&mut section, "rpc_port", self.rpc_port, 0);
        get::insert_opt_u32(
            &mut section,
            "rpc_credits_per_hash",
            self.rpc_credits_per_hash,
            0,
        );
        get::insert_opt_u32(&mut section, "support_flags", self.support_flags, 0);
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            network_id: get::blob(section, "network_id")?,
            peer_id: get::u64_val(section, "peer_id")?,
            my_port: get::u32_val(section, "my_port")?,
            rpc_port: get::opt_u16(section, "rpc_port", 0)?,
            rpc_credits_per_hash: get::opt_u32(section, "rpc_credits_per_hash", 0)?,
            support_flags: get::opt_u32(section, "support_flags", 0)?,
        })
    }
}

/// `cryptonote::CORE_SYNC_DATA`.
///
/// `cumulative_difficulty_top64` is **always stored** (even when 0) and
/// `KV_SERIALIZE_OPT` on load — C++ `is_store` branch in the map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreSyncData {
    /// Chain height.
    pub current_height: u64,
    /// Low 64 bits of cumulative difficulty.
    pub cumulative_difficulty: u64,
    /// High 64 bits; stored unconditionally.
    pub cumulative_difficulty_top64: u64,
    /// `crypto::hash` POD-as-blob (32 bytes).
    pub top_id: [u8; 32],
    /// `KV_SERIALIZE_OPT` default 0.
    pub top_version: u8,
    /// `KV_SERIALIZE_OPT` default 0.
    pub pruning_seed: u32,
}

impl PortableMap for CoreSyncData {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        section.insert("current_height", Value::UInt64(self.current_height));
        section.insert(
            "cumulative_difficulty",
            Value::UInt64(self.cumulative_difficulty),
        );
        section.insert(
            "cumulative_difficulty_top64",
            Value::UInt64(self.cumulative_difficulty_top64),
        );
        section.insert("top_id", Value::Bytes(self.top_id.to_vec()));
        get::insert_opt_u8(&mut section, "top_version", self.top_version, 0);
        get::insert_opt_u32(&mut section, "pruning_seed", self.pruning_seed, 0);
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            current_height: get::u64_val(section, "current_height")?,
            cumulative_difficulty: get::u64_val(section, "cumulative_difficulty")?,
            cumulative_difficulty_top64: match section.get("cumulative_difficulty_top64") {
                None => 0,
                Some(Value::UInt64(v)) => *v,
                Some(_) => return Err(get::mismatch("cumulative_difficulty_top64", "uint64")),
            },
            top_id: get::blob(section, "top_id")?,
            top_version: get::opt_u8(section, "top_version", 0)?,
            pruning_seed: get::opt_u32(section, "pruning_seed", 0)?,
        })
    }
}

/// `nodetool::peerlist_entry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerlistEntry {
    /// `network_address` union.
    pub adr: NetworkAddress,
    /// Peer id.
    pub id: u64,
    /// `KV_SERIALIZE_OPT` default 0.
    pub last_seen: i64,
    /// `KV_SERIALIZE_OPT` default 0.
    pub pruning_seed: u32,
    /// `KV_SERIALIZE_OPT` default 0.
    pub rpc_port: u16,
    /// `KV_SERIALIZE_OPT` default 0.
    pub rpc_credits_per_hash: u32,
}

impl PortableMap for PeerlistEntry {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        section.insert("adr", Value::Object(self.adr.to_section()?));
        section.insert("id", Value::UInt64(self.id));
        get::insert_opt_i64(&mut section, "last_seen", self.last_seen, 0);
        get::insert_opt_u32(&mut section, "pruning_seed", self.pruning_seed, 0);
        get::insert_opt_u16(&mut section, "rpc_port", self.rpc_port, 0);
        get::insert_opt_u32(
            &mut section,
            "rpc_credits_per_hash",
            self.rpc_credits_per_hash,
            0,
        );
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            adr: NetworkAddress::from_section(get::object(section, "adr")?)?,
            id: get::u64_val(section, "id")?,
            last_seen: get::opt_i64(section, "last_seen", 0)?,
            pruning_seed: get::opt_u32(section, "pruning_seed", 0)?,
            rpc_port: get::opt_u16(section, "rpc_port", 0)?,
            rpc_credits_per_hash: get::opt_u32(section, "rpc_credits_per_hash", 0)?,
        })
    }
}

pub(crate) fn peerlist_to_value(list: &[PeerlistEntry]) -> Result<Value, Error> {
    let mut objs = Vec::with_capacity(list.len());
    for entry in list {
        objs.push(entry.to_section()?);
    }
    Ok(Value::Array(Array::Object(objs)))
}

pub(crate) fn peerlist_from_section(
    section: &Section,
    key: &'static str,
) -> Result<Vec<PeerlistEntry>, Error> {
    match get::require(section, key)? {
        Value::Array(Array::Object(secs)) => {
            secs.iter().map(PeerlistEntry::from_section).collect()
        }
        _ => Err(get::mismatch(key, "array of object")),
    }
}
