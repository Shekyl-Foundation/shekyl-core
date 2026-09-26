// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The address a connector is selected from. The four variants are the
//! Levin address union. I2P selects no connector.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One peer address. The port is part of the address and is not part of
/// a ban key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerAddress {
    /// IPv4 and a port.
    Ipv4 {
        /// Address octets.
        ip: Ipv4Addr,
        /// TCP port.
        port: u16,
    },
    /// IPv6 and a port.
    Ipv6 {
        /// Address octets.
        ip: Ipv6Addr,
        /// TCP port.
        port: u16,
    },
    /// A `.b32.i2p` host. No connector is built for this variant.
    I2p {
        /// Host name.
        host: String,
        /// Port carried for the address union.
        port: u16,
    },
    /// An onion host. The Tor connector accepts a v3 hostname only.
    Tor {
        /// Host name, including the `.onion` suffix when it is one.
        host: String,
        /// Port.
        port: u16,
    },
}

impl PeerAddress {
    /// The IP, when this address has one. Onion and I2P hosts do not.
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ipv4 { ip, .. } => Some(IpAddr::V4(*ip)),
            Self::Ipv6 { ip, .. } => Some(IpAddr::V6(*ip)),
            Self::I2p { .. } | Self::Tor { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PeerAddress;
    use shekyl_levin::{ADDR_I2P, ADDR_IPV4, ADDR_IPV6, ADDR_TOR};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn the_four_variants_are_the_levin_address_union() {
        let samples = [
            PeerAddress::Ipv4 {
                ip: Ipv4Addr::LOCALHOST,
                port: 1,
            },
            PeerAddress::Ipv6 {
                ip: Ipv6Addr::LOCALHOST,
                port: 1,
            },
            PeerAddress::I2p {
                host: "example.b32.i2p".to_owned(),
                port: 0,
            },
            PeerAddress::Tor {
                host: "example.onion".to_owned(),
                port: 1,
            },
        ];
        let bytes: Vec<u8> = samples.iter().map(wire_byte).collect();
        assert_eq!(bytes, vec![ADDR_IPV4, ADDR_IPV6, ADDR_I2P, ADDR_TOR]);
    }

    fn wire_byte(address: &PeerAddress) -> u8 {
        match address {
            PeerAddress::Ipv4 { .. } => ADDR_IPV4,
            PeerAddress::Ipv6 { .. } => ADDR_IPV6,
            PeerAddress::I2p { .. } => ADDR_I2P,
            PeerAddress::Tor { .. } => ADDR_TOR,
        }
    }
}
