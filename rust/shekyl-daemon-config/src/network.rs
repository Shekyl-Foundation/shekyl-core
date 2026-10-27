// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The network row (`DAEMON_CONFIG_CUTOVER.md` §2.6): the network selects
//! data, never control flow (rule 71). Regtest conforms to production and
//! runs mainnet's ports, as `cryptonote::get_config(FAKECHAIN)` does.

/// The four networks, as `network` spells them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Network {
    /// `mainnet`.
    Mainnet,
    /// `testnet`.
    Testnet,
    /// `stagenet`.
    Stagenet,
    /// `regtest`: the C++ `FAKECHAIN`.
    Regtest,
}

impl Network {
    /// The address network a mining address on this network is decoded
    /// for. Regtest has no prefixes of its own: it takes mainnet's, as the
    /// C++ `FAKECHAIN` does.
    #[must_use]
    pub const fn address_network(self) -> shekyl_address::Network {
        match self {
            Self::Mainnet | Self::Regtest => shekyl_address::Network::Mainnet,
            Self::Testnet => shekyl_address::Network::Testnet,
            Self::Stagenet => shekyl_address::Network::Stagenet,
        }
    }

    /// Every network, in the grammar's order.
    pub const ALL: [Self; 4] = [Self::Mainnet, Self::Testnet, Self::Stagenet, Self::Regtest];

    /// The network a word names.
    #[must_use]
    pub fn from_word(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|n| n.name() == word)
    }

    /// The word the operator writes.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Stagenet => "stagenet",
            Self::Regtest => "regtest",
        }
    }

    /// `cryptonote::network_type`'s code, for the C++ snapshot.
    #[must_use]
    pub const fn cryptonote_code(self) -> u8 {
        match self {
            Self::Mainnet => 0,
            Self::Testnet => 1,
            Self::Stagenet => 2,
            Self::Regtest => 3,
        }
    }

    /// The default P2P port (`src/cryptonote_config.h`, `P2P_DEFAULT_PORT`).
    #[must_use]
    pub const fn p2p_port(self) -> u16 {
        match self {
            Self::Mainnet | Self::Regtest => 11021,
            Self::Testnet => 12021,
            Self::Stagenet => 13021,
        }
    }

    /// The default RPC port (`src/cryptonote_config.h`, `RPC_DEFAULT_PORT`).
    #[must_use]
    pub const fn rpc_port(self) -> u16 {
        match self {
            Self::Mainnet | Self::Regtest => 11029,
            Self::Testnet => 12029,
            Self::Stagenet => 13029,
        }
    }

    /// The subdirectory of the daemon's root the default data directory
    /// is; mainnet is the root itself.
    #[must_use]
    pub const fn subdirectory(self) -> Option<&'static str> {
        match self {
            Self::Mainnet => None,
            Self::Testnet => Some("testnet"),
            Self::Stagenet => Some("stagenet"),
            Self::Regtest => Some("regtest"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ports are the C++ header's. The header is the one source until
    /// the chain store moves; this pins the copy to it.
    #[test]
    fn the_ports_are_the_headers() {
        let header = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../src/cryptonote_config.h"
        ))
        .expect("src/cryptonote_config.h");
        let port = |ns: &str, name: &str| -> u16 {
            let section = match ns {
                "" => &header[..header.find("namespace testnet").expect("testnet")],
                _ => {
                    let start = header.find(&format!("namespace {ns}")).expect(ns);
                    &header[start..]
                }
            };
            let line = section
                .lines()
                .find(|l| l.contains(&format!("{name} = ")))
                .expect(name);
            line.split('=')
                .nth(1)
                .unwrap()
                .trim()
                .trim_end_matches(';')
                .parse()
                .unwrap()
        };
        assert_eq!(Network::Mainnet.p2p_port(), port("", "P2P_DEFAULT_PORT"));
        assert_eq!(Network::Mainnet.rpc_port(), port("", "RPC_DEFAULT_PORT"));
        assert_eq!(
            Network::Testnet.p2p_port(),
            port("testnet", "P2P_DEFAULT_PORT")
        );
        assert_eq!(
            Network::Testnet.rpc_port(),
            port("testnet", "RPC_DEFAULT_PORT")
        );
        assert_eq!(
            Network::Stagenet.p2p_port(),
            port("stagenet", "P2P_DEFAULT_PORT")
        );
        assert_eq!(
            Network::Stagenet.rpc_port(),
            port("stagenet", "RPC_DEFAULT_PORT")
        );
        assert_eq!(Network::Regtest.p2p_port(), Network::Mainnet.p2p_port());
    }

    #[test]
    fn words_round_trip_and_codes_are_the_cryptonote_ones() {
        for (i, n) in Network::ALL.into_iter().enumerate() {
            assert_eq!(Network::from_word(n.name()), Some(n));
            assert_eq!(usize::from(n.cryptonote_code()), i);
        }
        assert_eq!(Network::from_word("fakechain"), None);
    }
}
