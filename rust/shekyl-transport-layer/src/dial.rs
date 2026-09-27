// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Dial acceptance reads the connector's addressing cell.
//!
//! [`Addressing::OnionV3`] accepts a v3 onion hostname. [`Addressing::Ip`]
//! accepts an IP address. Anything else is [`CloseKind::DialFailed`].
//! No socket is opened here.

use shekyl_net_address::NetworkAddress;
use shekyl_onion_v3::is_v3_onion_hostname;

use crate::declaration::{declaration, Addressing, Assessment, ConnectorId};
use crate::{CloseCause, CloseKind};

const _: () = {
    assert!(matches!(
        declaration(ConnectorId::Tor.column()).addressing(),
        Assessment::Assessed(Addressing::OnionV3)
    ));
    assert!(matches!(
        declaration(ConnectorId::Clearnet.column()).addressing(),
        Assessment::Assessed(Addressing::Ip)
    ));
};

/// Whether `address` satisfies the addressing cell of `connector`.
///
/// A v3 onion hostname satisfies [`Addressing::OnionV3`]. An IPv4 or IPv6
/// address satisfies [`Addressing::Ip`]. Every other pair is
/// [`CloseKind::DialFailed`].
pub fn check_dial(connector: ConnectorId, address: &NetworkAddress) -> Result<(), CloseCause> {
    let Assessment::Assessed(addressing) = declaration(connector.column()).addressing() else {
        return Err(CloseCause::new(CloseKind::DialFailed));
    };
    if endpoint_matches(addressing, address) {
        Ok(())
    } else {
        Err(CloseCause::new(CloseKind::DialFailed))
    }
}

/// Whether `address` is a member of `addressing`.
fn endpoint_matches(addressing: Addressing, address: &NetworkAddress) -> bool {
    match (addressing, address) {
        (Addressing::OnionV3, NetworkAddress::Tor { host, .. }) => is_v3_onion_hostname(host),
        (Addressing::Ip, NetworkAddress::Ipv4 { .. } | NetworkAddress::Ipv6 { .. })
        | (Addressing::B32I2p, NetworkAddress::I2p { .. }) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::check_dial;
    use crate::declaration::ConnectorId;
    use crate::CloseKind;
    use shekyl_net_address::NetworkAddress;
    use shekyl_onion_v3::v3_onion_hostname;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn the_tor_connector_dials_an_onion_v3_hostname() {
        let host = v3_onion_hostname(&[0x11; 32]);
        let address = NetworkAddress::Tor { host, port: 18080 };
        assert_eq!(check_dial(ConnectorId::Tor, &address), Ok(()));
    }

    #[test]
    fn the_addressing_cell_refuses_the_other_families() {
        let onion = v3_onion_hostname(&[0x11; 32]);
        let refused = [
            (
                ConnectorId::Tor,
                NetworkAddress::Ipv4 {
                    ip: Ipv4Addr::new(1, 2, 3, 4),
                    port: 18080,
                },
            ),
            (
                ConnectorId::Tor,
                NetworkAddress::Ipv6 {
                    ip: Ipv6Addr::LOCALHOST,
                    port: 18080,
                },
            ),
            (
                ConnectorId::Tor,
                NetworkAddress::I2p {
                    host: "example.b32.i2p".to_owned(),
                    port: 0,
                },
            ),
            (
                ConnectorId::Tor,
                NetworkAddress::Tor {
                    host: "not-an-onion".to_owned(),
                    port: 18080,
                },
            ),
            (
                ConnectorId::Tor,
                NetworkAddress::Tor {
                    host: "efjprum3peosirjsilqv6lvlns3476t3njpngaexsyhangeb3mjo7sad.ONION"
                        .to_owned(),
                    port: 18080,
                },
            ),
            (
                ConnectorId::Clearnet,
                NetworkAddress::Tor {
                    host: onion,
                    port: 18080,
                },
            ),
        ];
        for (connector, address) in refused {
            let error = check_dial(connector, &address).expect_err("refused");
            assert_eq!(error.kind(), CloseKind::DialFailed);
        }
        let ip = NetworkAddress::Ipv4 {
            ip: Ipv4Addr::LOCALHOST,
            port: 18080,
        };
        assert_eq!(check_dial(ConnectorId::Clearnet, &ip), Ok(()));
    }
}
