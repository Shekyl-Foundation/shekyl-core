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
//! Testnet also carries the six Foundation onion seeds (Q12-R1, landed
//! 2026-10-21). Mainnet has no hidden service yet, so its list is the
//! clearnet hosts alone. A connector admits only the seeds of its own
//! address type, at the moment that connector starts.

use std::net::Ipv4Addr;

use shekyl_peerlist::NetworkAddress;

/// Which network's seeds to admit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedNetwork {
    /// Mainnet, P2P port 11021.
    Mainnet,
    /// Testnet, P2P port 12021.
    Testnet,
    /// Stagenet and regtest: no seeds.
    None,
}

/// The Foundation's six clearnet seed hosts.
const SEED_HOSTS: [([u8; 4], &str); 6] = [
    ([134, 199, 166, 22], "seedaus, Sydney"),
    ([45, 77, 147, 65], "seeduse, US East"),
    ([45, 76, 171, 128], "seedusw, US West"),
    ([45, 77, 66, 189], "seedeu, EU Frankfurt"),
    ([139, 162, 71, 114], "seedjp, Tokyo"),
    ([104, 64, 59, 31], "seedbrz, Brazil"),
];

/// The same six hosts' testnet onion services, in the same order.
/// Virtual port 12021. Mainnet has no onion services.
const SEED_ONIONS: [&str; 6] = [
    "aghoxa757l2wqribeto2hv2rk3wjwcwdqzvu5hjkqdjcm24nuhaszjqd.onion",
    "23dkgevx7qnhrx2wmhmjvhsz2mpp54xomkujcvhuhm3ajgdciwztypad.onion",
    "nqkfnallpz5kaoxkj2y6bmeifk4helrwp5z2fdtayo3rfzbx4q7z2tqd.onion",
    "aks2vbpjb5ojfyqcataqedodws7ardjxczy76bqwmlv55mgfunsxoiyd.onion",
    "e2fafquqkf4jodx6rwh2akgyu2gy3spxcyc2ustnuqw46vrk2xe365qd.onion",
    "mjgznic6uwrccelrq6fqjmmv2f7gaskd3nxcs76hjrrfc4tse7wioqqd.onion",
];

/// The seed addresses of `network`, each with that network's P2P port.
///
/// Testnet returns the six clearnet addresses and then the six onions.
/// Mainnet returns the six clearnet addresses. Stagenet and regtest
/// return nothing.
#[must_use]
pub fn seeds(network: SeedNetwork) -> Vec<NetworkAddress> {
    let (port, with_onions) = match network {
        SeedNetwork::Mainnet => (11021, false),
        SeedNetwork::Testnet => (12021, true),
        SeedNetwork::None => return Vec::new(),
    };
    let mut addresses: Vec<NetworkAddress> = SEED_HOSTS
        .iter()
        .map(|(octets, _)| NetworkAddress::Ipv4 {
            ip: Ipv4Addr::from(*octets),
            port,
        })
        .collect();
    if with_onions {
        addresses.extend(SEED_ONIONS.iter().map(|host| NetworkAddress::Tor {
            host: (*host).to_owned(),
            port,
        }));
    }
    addresses
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_v3_onion(host: &str) -> bool {
        let Some(id) = host.strip_suffix(".onion") else {
            return false;
        };
        id.len() == 56
            && id
                .bytes()
                .all(|byte| matches!(byte, b'a'..=b'z' | b'2'..=b'7'))
    }

    #[test]
    fn testnet_carries_six_clearnet_hosts_and_six_onions() {
        let addresses = seeds(SeedNetwork::Testnet);
        let ipv4: Vec<_> = addresses
            .iter()
            .filter(|address| matches!(address, NetworkAddress::Ipv4 { port: 12021, .. }))
            .collect();
        let onions: Vec<_> = addresses
            .iter()
            .filter_map(|address| match address {
                NetworkAddress::Tor { host, port: 12021 } if is_v3_onion(host) => {
                    Some(host.clone())
                }
                NetworkAddress::Tor { .. } => {
                    panic!("a testnet onion is not a v3 address on 12021")
                }
                _ => None,
            })
            .collect();
        assert_eq!(ipv4.len(), 6);
        assert_eq!(onions.len(), 6);
        assert_eq!(addresses.len(), 12);
        let mut distinct = onions.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), 6, "the six onions are distinct");
        assert_eq!(onions, SEED_ONIONS.map(str::to_owned).to_vec());
    }

    #[test]
    fn mainnet_is_the_six_clearnet_hosts() {
        let addresses = seeds(SeedNetwork::Mainnet);
        assert_eq!(addresses.len(), 6);
        assert!(addresses
            .iter()
            .all(|address| matches!(address, NetworkAddress::Ipv4 { port: 11021, .. })));
    }

    #[test]
    fn stagenet_and_regtest_have_no_seeds() {
        assert!(seeds(SeedNetwork::None).is_empty());
    }
}
