// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`MiningAddress`]: the address a node mines to, decoded once and held
//! to the daemon's network.

use shekyl_address::{AddressError, Network, ShekylAddress};
use shekyl_block_template::MinerKeys;
use shekyl_crypto_pq::montgomery::ed25519_pk_to_x25519_pk;

/// Why an address cannot be mined to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MiningAddressRefused {
    /// The text is not a Shekyl address.
    Undecodable(String),
    /// The address belongs to another network.
    OffNetwork {
        /// The address's network.
        address: Network,
        /// The daemon's.
        daemon: Network,
    },
    /// The classical segment alone: no ML-KEM key, so no coinbase output
    /// can be encrypted to it. The full three-segment address is needed.
    NoKemKey,
    /// The view key is not a point the X25519 half of the KEM target can be
    /// derived from.
    ViewKeyNotAPoint,
}

impl core::fmt::Display for MiningAddressRefused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Undecodable(reason) => write!(f, "not a Shekyl address: {reason}"),
            Self::OffNetwork { address, daemon } => write!(
                f,
                "the address is for {address:?} and this node runs {daemon:?}"
            ),
            Self::NoKemKey => {
                f.write_str("the address has no post-quantum segments; mine to the full address")
            }
            Self::ViewKeyNotAPoint => {
                f.write_str("the address's view key is not a valid curve point")
            }
        }
    }
}

impl std::error::Error for MiningAddressRefused {}

/// An address on this node's network that a coinbase can pay: the decoded
/// address, its text as decoded, and the coinbase recipient keys the
/// template producer is built with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiningAddress {
    encoded: String,
    keys: MinerKeys,
}

impl MiningAddress {
    /// Decode `text` for a daemon on `network`.
    ///
    /// # Errors
    ///
    /// [`MiningAddressRefused`]: undecodable, another network's, a
    /// display-only address with no KEM key, or a view key off the curve.
    pub fn decode(text: &str, network: Network) -> Result<Self, MiningAddressRefused> {
        let address = match ShekylAddress::decode_for_network(text, network) {
            Ok(address) => address,
            Err(AddressError::NetworkMismatch {
                addr_net,
                expected_net,
            }) => {
                return Err(MiningAddressRefused::OffNetwork {
                    address: addr_net,
                    daemon: expected_net,
                })
            }
            Err(other) => return Err(MiningAddressRefused::Undecodable(other.to_string())),
        };
        if !address.has_pqc_segment() || address.ml_kem_encap_key.is_empty() {
            return Err(MiningAddressRefused::NoKemKey);
        }
        let x25519_pk = ed25519_pk_to_x25519_pk(&address.view_key)
            .map_err(|_| MiningAddressRefused::ViewKeyNotAPoint)?;
        Ok(Self {
            encoded: text.to_owned(),
            keys: MinerKeys {
                spend_public: address.spend_key,
                x25519_pk,
                ml_kem_ek: address.ml_kem_encap_key,
            },
        })
    }

    /// The address as it was given.
    #[must_use]
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    /// The coinbase recipient: what the template producer pays.
    #[must_use]
    pub const fn keys(&self) -> &MinerKeys {
        &self.keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_address::{MSG_SIGN_PK_LEN, PQC_PAYLOAD_LEN};

    /// The Ed25519 basepoint's encoding: a view key on the curve.
    const BASEPOINT: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];

    fn address(network: Network) -> ShekylAddress {
        ShekylAddress::new(
            network,
            [0x11; 32],
            BASEPOINT,
            [0x22; MSG_SIGN_PK_LEN],
            vec![0x33; PQC_PAYLOAD_LEN],
        )
    }

    #[test]
    fn a_full_address_on_the_network_pays_its_own_keys() {
        let text = address(Network::Testnet).encode().expect("encodes");
        let mining = MiningAddress::decode(&text, Network::Testnet).expect("mineable");
        assert_eq!(mining.encoded(), text);
        assert_eq!(mining.keys().spend_public, [0x11; 32]);
        assert_eq!(mining.keys().ml_kem_ek, vec![0x33; PQC_PAYLOAD_LEN]);
        assert_eq!(
            mining.keys().x25519_pk,
            ed25519_pk_to_x25519_pk(&BASEPOINT).expect("a point")
        );
    }

    #[test]
    fn another_networks_address_is_refused() {
        let text = address(Network::Mainnet).encode().expect("encodes");
        assert_eq!(
            MiningAddress::decode(&text, Network::Testnet),
            Err(MiningAddressRefused::OffNetwork {
                address: Network::Mainnet,
                daemon: Network::Testnet
            })
        );
    }

    #[test]
    fn a_display_only_address_has_no_kem_key_and_is_refused() {
        let text = address(Network::Testnet)
            .encode_classical_display()
            .expect("encodes");
        assert_eq!(
            MiningAddress::decode(&text, Network::Testnet),
            Err(MiningAddressRefused::NoKemKey)
        );
    }

    #[test]
    fn text_that_is_not_an_address_is_refused() {
        assert!(matches!(
            MiningAddress::decode("not an address", Network::Testnet),
            Err(MiningAddressRefused::Undecodable(_))
        ));
    }
}
