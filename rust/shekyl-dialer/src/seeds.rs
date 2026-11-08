// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The compiled seed addresses (slice 1 brief §3, Rick 2026-10-11).
//!
//! Seeds are ordinary peers: the daemon admits them to gray at each start
//! as operator-named addresses, and they reach white only through a drawn
//! dial. The list is data the dialer reads, not an arm of the fill. It
//! moved here from the C++ `get_ip_seed_nodes`, which the cutover deletes
//! with its callers.
//!
//! The hosts are the network table's (`shekyl-network`'s `seeds` row
//! field): each Foundation host's clearnet octets and, on testnet, its v3
//! onion. Mainnet has no hidden service, so its list is the
//! clearnet hosts alone. Testnet's onions are the canonical Tor bootstrap
//! (Q12-R1, landed 2026-10-21): a node does not hand-configure them. A
//! connector admits only the rows of its own address type, and only after
//! the p2p section is applied, so a closed network is already the
//! population when the first wake draws.

use std::net::Ipv4Addr;

use shekyl_network::Network;
use shekyl_peerlist::NetworkAddress;

/// The seed addresses of `network`, each on that network's p2p port: the
/// row's seed hosts (`NETWORK_IDENTITY.md`, the seed list is a row field).
///
/// The clearnet addresses come first, then the onions, each in the row's
/// order. A network with no seeds returns nothing.
#[must_use]
pub fn seeds(network: Network) -> Vec<NetworkAddress> {
    let port = network.ports().p2p;
    let hosts = network.seeds();
    let mut addresses = Vec::with_capacity(hosts.len() * 2);
    for host in hosts {
        addresses.push(NetworkAddress::Ipv4 {
            ip: Ipv4Addr::from(host.ipv4),
            port,
        });
    }
    for host in hosts {
        if let Some(onion) = host.onion {
            debug_assert!(
                shekyl_onion_v3::is_v3_onion_hostname(onion),
                "a compiled onion must be a v3 hostname the dialer can dial"
            );
            addresses.push(NetworkAddress::Tor {
                host: onion.to_owned(),
                port,
            });
        }
    }
    addresses
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Clearnet rows, then the onion rows, each in the row's order.
    fn paired(network: Network, onions: bool) -> Vec<NetworkAddress> {
        let port = network.ports().p2p;
        let mut addresses: Vec<_> = network
            .seeds()
            .iter()
            .map(|host| NetworkAddress::Ipv4 {
                ip: Ipv4Addr::from(host.ipv4),
                port,
            })
            .collect();
        if onions {
            addresses.extend(network.seeds().iter().map(|host| NetworkAddress::Tor {
                host: host.onion.expect("an onion").to_owned(),
                port,
            }));
        }
        addresses
    }

    #[test]
    fn testnet_pairs_each_clearnet_host_with_its_onion() {
        assert_eq!(seeds(Network::Testnet), paired(Network::Testnet, true));
        for host in Network::Testnet.seeds() {
            let onion = host.onion.expect("testnet pairs each host with its onion");
            assert!(
                shekyl_onion_v3::is_v3_onion_hostname(onion),
                "{} is not a v3 onion the dialer can dial",
                host.place
            );
        }
    }

    #[test]
    fn mainnet_is_the_clearnet_hosts() {
        assert_eq!(seeds(Network::Mainnet), paired(Network::Mainnet, false));
    }

    #[test]
    fn stagenet_and_regtest_have_no_seeds() {
        assert!(seeds(Network::Stagenet).is_empty());
        assert!(seeds(Network::Regtest).is_empty());
    }
}
