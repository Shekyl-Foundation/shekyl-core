// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Tor connector dials onion v3 hostnames only. Anything else is
//! [`CloseKind::DialFailed`](crate::CloseKind::DialFailed). No socket is opened here.

use shekyl_onion_v3::is_v3_onion_hostname;

use crate::address::PeerAddress;
use crate::{CloseCause, CloseKind};

/// Whether `address` is one the Tor connector may dial.
///
/// A v3 onion hostname is accepted. Every other address, including a Tor
/// host that is not a v3 onion, is [`CloseKind::DialFailed`].
pub fn check_tor_dial(address: &PeerAddress) -> Result<(), CloseCause> {
    match address {
        PeerAddress::Tor { host, .. } if is_v3_onion_hostname(host) => Ok(()),
        PeerAddress::Ipv4 { .. }
        | PeerAddress::Ipv6 { .. }
        | PeerAddress::I2p { .. }
        | PeerAddress::Tor { .. } => Err(CloseCause::new(CloseKind::DialFailed)),
    }
}

#[cfg(test)]
mod tests {
    use super::check_tor_dial;
    use crate::address::PeerAddress;
    use crate::CloseKind;
    use shekyl_onion_v3::v3_onion_hostname;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn the_tor_connector_dials_an_onion_v3_hostname() {
        let host = v3_onion_hostname(&[0x11; 32]);
        let address = PeerAddress::Tor { host, port: 18080 };
        assert_eq!(check_tor_dial(&address), Ok(()));
    }

    #[test]
    fn the_tor_connector_refuses_anything_else() {
        let refused = [
            PeerAddress::Ipv4 {
                ip: Ipv4Addr::new(1, 2, 3, 4),
                port: 18080,
            },
            PeerAddress::Ipv6 {
                ip: Ipv6Addr::LOCALHOST,
                port: 18080,
            },
            PeerAddress::I2p {
                host: "example.b32.i2p".to_owned(),
                port: 0,
            },
            PeerAddress::Tor {
                host: "not-an-onion".to_owned(),
                port: 18080,
            },
            PeerAddress::Tor {
                host: "efjprum3peosirjsilqv6lvlns3476t3njpngaexsyhangeb3mjo7sad.ONION".to_owned(),
                port: 18080,
            },
        ];
        for address in refused {
            let error = check_tor_dial(&address).expect_err("refused");
            assert_eq!(error.kind(), CloseKind::DialFailed);
        }
    }
}
