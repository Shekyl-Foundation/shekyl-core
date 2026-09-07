// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Levin command 1001 / 1002 / 1003 / 1007 request and response maps.

use shekyl_portable_storage::{Section, Value};

use super::error::Error;
use super::get;
use super::types::{
    insert_peerlist, peerlist_from_section, BasicNodeData, CoreSyncData, PeerlistEntry,
};
use super::PortableMap;

/// `COMMAND_HANDSHAKE` = `P2P_COMMANDS_POOL_BASE + 1`.
pub const COMMAND_HANDSHAKE: u32 = 1001;
/// `COMMAND_TIMED_SYNC`.
pub const COMMAND_TIMED_SYNC: u32 = 1002;
// COMMAND_PING (1003) is deleted (PWD-B10 / PWC-B1); the id is retired,
// never reused.
/// `COMMAND_REQUEST_SUPPORT_FLAGS` = `P2P_COMMANDS_POOL_BASE + 7`.
pub const COMMAND_REQUEST_SUPPORT_FLAGS: u32 = 1007;

/// Handshake invoke body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeRequest {
    /// Local node advertisement.
    pub node_data: BasicNodeData,
    /// `CORE_SYNC_DATA`.
    pub payload_data: CoreSyncData,
    /// Self-detection nonce (PWD-T1's token, carried on this request until
    /// the Noise handshake lands): 32 bytes of CSPRNG output, in the clear.
    /// Per-connection, minted fresh, never persisted — its only job is to
    /// be recognised by the node that emitted it, within the zone it was
    /// emitted on.
    pub nonce: [u8; 32],
}

impl PortableMap for HandshakeRequest {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        section.insert("node_data", Value::Object(self.node_data.to_section()?));
        section.insert(
            "payload_data",
            Value::Object(self.payload_data.to_section()?),
        );
        section.insert("nonce", Value::Bytes(self.nonce.to_vec()));
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            node_data: BasicNodeData::from_section(get::object(section, "node_data")?)?,
            payload_data: CoreSyncData::from_section(get::object(section, "payload_data")?)?,
            nonce: get::blob(section, "nonce")?,
        })
    }
}

/// Handshake response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeResponse {
    /// Peer's node advertisement.
    pub node_data: BasicNodeData,
    /// Peer's `CORE_SYNC_DATA`.
    pub payload_data: CoreSyncData,
    /// `local_peerlist_new`.
    pub local_peerlist_new: Vec<PeerlistEntry>,
}

impl PortableMap for HandshakeResponse {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        insert_peerlist(&mut section, "local_peerlist_new", &self.local_peerlist_new)?;
        section.insert("node_data", Value::Object(self.node_data.to_section()?));
        section.insert(
            "payload_data",
            Value::Object(self.payload_data.to_section()?),
        );
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            node_data: BasicNodeData::from_section(get::object(section, "node_data")?)?,
            payload_data: CoreSyncData::from_section(get::object(section, "payload_data")?)?,
            local_peerlist_new: peerlist_from_section(section, "local_peerlist_new")?,
        })
    }
}

/// Timed-sync invoke body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimedSyncRequest {
    /// `CORE_SYNC_DATA`.
    pub payload_data: CoreSyncData,
}

impl PortableMap for TimedSyncRequest {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        section.insert(
            "payload_data",
            Value::Object(self.payload_data.to_section()?),
        );
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            payload_data: CoreSyncData::from_section(get::object(section, "payload_data")?)?,
        })
    }
}

/// Timed-sync response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimedSyncResponse {
    /// Peer's `CORE_SYNC_DATA`.
    pub payload_data: CoreSyncData,
    /// `local_peerlist_new`.
    pub local_peerlist_new: Vec<PeerlistEntry>,
}

impl PortableMap for TimedSyncResponse {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        insert_peerlist(&mut section, "local_peerlist_new", &self.local_peerlist_new)?;
        section.insert(
            "payload_data",
            Value::Object(self.payload_data.to_section()?),
        );
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            payload_data: CoreSyncData::from_section(get::object(section, "payload_data")?)?,
            local_peerlist_new: peerlist_from_section(section, "local_peerlist_new")?,
        })
    }
}

/// Support-flags invoke body — empty map.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SupportFlagsRequest;

impl PortableMap for SupportFlagsRequest {
    fn to_section(&self) -> Result<Section, Error> {
        Ok(Section::new())
    }

    fn from_section(_section: &Section) -> Result<Self, Error> {
        Ok(Self)
    }
}

/// Support-flags response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportFlagsResponse {
    /// Peer's `support_flags`.
    pub support_flags: u32,
}

impl PortableMap for SupportFlagsResponse {
    fn to_section(&self) -> Result<Section, Error> {
        let mut section = Section::new();
        section.insert("support_flags", Value::UInt32(self.support_flags));
        Ok(section)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        Ok(Self {
            support_flags: get::u32_val(section, "support_flags")?,
        })
    }
}
