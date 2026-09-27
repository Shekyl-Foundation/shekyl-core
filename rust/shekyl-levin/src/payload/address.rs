// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Portable-storage codec for [`shekyl_net_address::NetworkAddress`]
//! (`LV2_PORTABLE_STORAGE.md` §6.2).
//!
//! The union lives in `shekyl-net-address`. This module is the Levin
//! framing of that union: the `address_type` tags and the section layout.
//! `m_ip` is the IPv4 octets as a little-endian `uint32` after C++
//! `SWAP32LE` (identity on little-endian hosts). IPv6 `addr` is a 16-byte
//! blob. I2P and Tor sections are `host` + `port`.

use std::net::{Ipv4Addr, Ipv6Addr};

use shekyl_portable_storage::{Section, Value};

use super::error::Error;
use super::get;
use super::PortableMap;

pub use shekyl_net_address::NetworkAddress;

/// `epee::net_utils::address_type` values written as `network_address.type`.
pub const ADDR_IPV4: u8 = 1;
pub const ADDR_IPV6: u8 = 2;
pub const ADDR_I2P: u8 = 3;
pub const ADDR_TOR: u8 = 4;

impl PortableMap for NetworkAddress {
    fn to_section(&self) -> Result<Section, Error> {
        let mut root = Section::new();
        let (type_id, inner) = match self {
            Self::Ipv4 { ip, port } => {
                let mut addr = Section::new();
                addr.insert("m_ip", Value::UInt32(u32::from_le_bytes(ip.octets())));
                addr.insert("m_port", Value::UInt16(*port));
                (ADDR_IPV4, addr)
            }
            Self::Ipv6 { ip, port } => {
                let mut addr = Section::new();
                addr.insert("addr", Value::Bytes(ip.octets().to_vec()));
                addr.insert("m_port", Value::UInt16(*port));
                (ADDR_IPV6, addr)
            }
            Self::I2p { host, port } => (ADDR_I2P, host_port(host, *port)),
            Self::Tor { host, port } => (ADDR_TOR, host_port(host, *port)),
        };
        root.insert("addr", Value::Object(inner));
        root.insert("type", Value::UInt8(type_id));
        Ok(root)
    }

    fn from_section(section: &Section) -> Result<Self, Error> {
        let type_id = get::u8_val(section, "type")?;
        let addr = get::object(section, "addr")?;
        match type_id {
            ADDR_IPV4 => {
                let ip = Ipv4Addr::from(get::u32_val(addr, "m_ip")?.to_le_bytes());
                let port = get::u16_val(addr, "m_port")?;
                Ok(Self::Ipv4 { ip, port })
            }
            ADDR_IPV6 => {
                let ip = Ipv6Addr::from(get::blob::<16>(addr, "addr")?);
                let port = get::u16_val(addr, "m_port")?;
                Ok(Self::Ipv6 { ip, port })
            }
            ADDR_I2P => {
                let (host, port) = host_port_from(addr)?;
                Ok(Self::I2p { host, port })
            }
            ADDR_TOR => {
                let (host, port) = host_port_from(addr)?;
                Ok(Self::Tor { host, port })
            }
            other => Err(Error::UnknownAddressType(other)),
        }
    }
}

fn host_port(host: &str, port: u16) -> Section {
    let mut addr = Section::new();
    addr.insert("host", Value::Bytes(host.as_bytes().to_vec()));
    addr.insert("port", Value::UInt16(port));
    addr
}

fn host_port_from(addr: &Section) -> Result<(String, u16), Error> {
    Ok((get::utf8(addr, "host")?, get::u16_val(addr, "port")?))
}
