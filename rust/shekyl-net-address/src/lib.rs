// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The address a peer is known by.
//!
//! This is the one union. `shekyl-levin` frames it as portable storage.
//! The transport layer selects a connector from it. Neither crate defines
//! a second copy, and this crate does not know about connectors, bans,
//! or the codec.

#![deny(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One peer address. The three variants are the closed address union.
///
/// `Ord` and `Hash` are derived so a list can hold addresses in a set or
/// map keyed by the address itself; the order is the derived one and
/// carries no meaning (`shekyl-peerlist` draws uniformly by index and
/// never walks it as a rank).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkAddress {
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
    /// An onion host and a port.
    ///
    /// `host` includes the `.onion` suffix when it is a hostname. Whether
    /// that hostname is a v3 address is the transport dial rule.
    Tor {
        /// Host name.
        host: String,
        /// Port.
        port: u16,
    },
}

/// The host half of an address: what one machine, or one onion service,
/// is known by whatever port it names.
///
/// Two addresses with one host are the same peer on two ports. The dialer
/// holds one outbound session per host and draws a host no more often for
/// advertising many ports.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Host {
    /// An IPv4 or IPv6 address.
    Ip(IpAddr),
    /// An onion hostname, including `.onion`.
    Onion(String),
}

impl NetworkAddress {
    /// The host this address names, without the port.
    #[must_use]
    pub fn host(&self) -> Host {
        match self {
            Self::Ipv4 { ip, .. } => Host::Ip(IpAddr::V4(*ip)),
            Self::Ipv6 { ip, .. } => Host::Ip(IpAddr::V6(*ip)),
            Self::Tor { host, .. } => Host::Onion(host.clone()),
        }
    }

    /// The IP, when this address has one. An onion name does not.
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ipv4 { ip, .. } => Some(IpAddr::V4(*ip)),
            Self::Ipv6 { ip, .. } => Some(IpAddr::V6(*ip)),
            Self::Tor { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NetworkAddress;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn an_ip_address_has_a_host_and_an_overlay_name_does_not() {
        let v4 = NetworkAddress::Ipv4 {
            ip: Ipv4Addr::LOCALHOST,
            port: 18080,
        };
        assert_eq!(v4.ip(), Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let v6 = NetworkAddress::Ipv6 {
            ip: Ipv6Addr::LOCALHOST,
            port: 18080,
        };
        assert_eq!(v6.ip(), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(
            NetworkAddress::Tor {
                host: "example.onion".to_owned(),
                port: 18080,
            }
            .ip(),
            None
        );
    }
}
