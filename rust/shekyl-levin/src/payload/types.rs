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

/// Handshake / 1007 `support_flags` word. Unknown bits are preserved so a
/// decode/encode round-trip is byte-identical.
///
/// Named bit: [`ZSTD_COMPRESSION`](Self::ZSTD_COMPRESSION) (0x02). 0x01 is
/// unassigned (PWD-B6; former compact-vs-full capability). Do not advertise
/// it and do not reuse it — an old peer's bit must not pick up a new meaning.
/// [`ADVERTISED`](Self::ADVERTISED) is the aggregate a Shekyl node sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SupportFlags(u32);

impl SupportFlags {
    /// `P2P_SUPPORT_FLAG_ZSTD_COMPRESSION`.
    pub const ZSTD_COMPRESSION: SupportFlags = SupportFlags(0x02);
    /// `P2P_SUPPORT_FLAGS` — zstd only.
    pub const ADVERTISED: SupportFlags = SupportFlags(0x02);

    /// Construct from a raw wire value, preserving unknown bits.
    #[must_use]
    pub const fn from_bits(bits: u32) -> SupportFlags {
        SupportFlags(bits)
    }

    /// The raw wire value.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// True if every bit of `other` is set in `self`.
    #[must_use]
    pub const fn contains(self, other: SupportFlags) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// `nodetool::basic_node_data` (`p2p_protocol_defs.h`).
///
/// There is deliberately no node identifier here (the PWD-I1 amendment,
/// `SHEKYL_P2P_PROTOCOL.md`), and no address either (ruled 2026-10-09):
/// the handshake carries no address field on any connector. A node's own
/// dialable address reaches peers only as one uniform member of its
/// disclosure sample. A peer that still sends `address` is decoded with
/// the key ignored; nothing is ever emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicNodeData {
    /// `network_id` POD-as-blob (`boost::uuids::uuid`, 16 bytes).
    pub network_id: [u8; 16],
    /// `KV_SERIALIZE_OPT` default 0.
    pub support_flags: SupportFlags,
}

impl PortableMap for BasicNodeData {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        section.insert("network_id", Value::Bytes(self.network_id.to_vec()));
        get::insert_opt_u32(&mut section, "support_flags", self.support_flags.bits(), 0);
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            network_id: get::blob(section, "network_id")?,
            support_flags: SupportFlags::from_bits(get::opt_u32(section, "support_flags", 0)?),
        })
    }
}

/// `cryptonote::CORE_SYNC_DATA`.
///
/// Carries no stripe seed: the stripe engine is deleted (`PDM-Q7`), and
/// the field was a self-asserted, durable, address-keyed attribute on the
/// wire — the shape `PWD-I1` forbids. An unknown key a peer sends is
/// decoded with the key ignored; nothing is ever emitted.
///
/// Carries no `top_version` either: the block version is the constant 1, so
/// a peer's tip version says nothing a receiver could act on. Same wire
/// treatment — never emitted, ignored when a peer sends it.
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
        })
    }
}

/// `nodetool::peerlist_entry`.
///
/// The address, nothing else: `peer_id` went with `PWD-I1`, the stripe
/// seed with `PDM-Q7` (the stripe engine is deleted), and `last_seen` with
/// PR-3 (Rick, 2026-10-13): a field always sent as 0 and ignored on
/// receipt is a sentinel and a peer-controlled slot. A gossiped entry
/// carrying an unknown key decodes with the key ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerlistEntry {
    /// `network_address` union.
    pub adr: NetworkAddress,
}

impl PortableMap for PeerlistEntry {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        section.insert("adr", Value::Object(self.adr.to_section()?));
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            adr: NetworkAddress::from_section(get::object(section, "adr")?)?,
        })
    }
}

pub(crate) fn insert_peerlist(
    section: &mut Section,
    key: &'static str,
    list: &[PeerlistEntry],
) -> Result<(), Error> {
    // C++ `serialize_stl_container_t_obj`: empty containers omit the key.
    if list.is_empty() {
        return Ok(());
    }
    let mut objs = Vec::with_capacity(list.len());
    for entry in list {
        objs.push(entry.to_section()?);
    }
    section.insert(key, Value::Array(Array::Object(objs)));
    Ok(())
}

pub(crate) fn peerlist_from_section(
    section: &Section,
    key: &'static str,
) -> Result<Vec<PeerlistEntry>, Error> {
    match section.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(Array::Object(secs))) => {
            secs.iter().map(PeerlistEntry::from_section).collect()
        }
        Some(_) => Err(get::mismatch(key, "array of object")),
    }
}
