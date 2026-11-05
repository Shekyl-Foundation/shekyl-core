// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pinned genesis block, assembled the way `generate_genesis_block`
//! does (`cryptonote_config.h`'s `GENESIS_TX` and `GENESIS_NONCE` through
//! the genesis tool). Regtest uses mainnet's pins, as
//! `get_config(FAKECHAIN)` does.

use shekyl_daemon_config::Network as DaemonNet;
use shekyl_genesis_tool::builder::genesis_block;
use shekyl_genesis_tool::config_pin::parse_config_genesis;
use shekyl_rpc_types::DaemonNetwork;
use shekyl_types::BlockHash;
use shekyl_wire::{Block, Transaction};

use crate::OpenError;

/// The header the binary was built with. The pin test in `shekyl-chain-rules`
/// rebuilds the same block and checks it against [`shekyl_chain_rules::GenesisPin`].
const CONFIG_H: &str = include_str!("../../../src/cryptonote_config.h");

/// The network whose `GENESIS_TX` this daemon connects. Regtest shares
/// mainnet's.
pub(crate) fn pin_network(network: DaemonNet) -> shekyl_address::Network {
    match network {
        DaemonNet::Mainnet | DaemonNet::Regtest => shekyl_address::Network::Mainnet,
        DaemonNet::Testnet => shekyl_address::Network::Testnet,
        DaemonNet::Stagenet => shekyl_address::Network::Stagenet,
    }
}

/// The client identity's name for `network`, including regtest as fakechain.
pub(crate) fn daemon_network(network: DaemonNet) -> DaemonNetwork {
    match network {
        DaemonNet::Mainnet => DaemonNetwork::Mainnet,
        DaemonNet::Testnet => DaemonNetwork::Testnet,
        DaemonNet::Stagenet => DaemonNetwork::Stagenet,
        DaemonNet::Regtest => DaemonNetwork::Fakechain,
    }
}

/// The handshake's network id for `network`: `network_id_from_genesis` of
/// the pinned genesis hash (`SHEKYL_P2P_PROTOCOL.md` PWD-B1). A total
/// derivation: every network this daemon runs has a pinned genesis, so
/// there is no network without an id. Regtest shares mainnet's.
#[must_use]
pub fn network_id(network: DaemonNet) -> [u8; 16] {
    shekyl_p2p_transport::network_id_from_genesis(&shekyl_rpc_types::genesis_hash_for(
        daemon_network(network),
    ))
}

/// The genesis block this build connects, and the hash the release pins.
pub(crate) fn pinned_genesis(network: DaemonNet) -> Result<(Block, BlockHash), OpenError> {
    let pins = parse_config_genesis(CONFIG_H)
        .map_err(|error| OpenError::Genesis(format!("the genesis pins did not parse: {error}")))?;
    let pin = pins.for_network(pin_network(network));
    let bytes = hex::decode(&pin.genesis_tx_hex)
        .map_err(|error| OpenError::Genesis(format!("GENESIS_TX is not hex: {error}")))?;
    let tx = Transaction::from_bytes(&bytes)
        .map_err(|error| OpenError::Genesis(format!("GENESIS_TX did not decode: {error}")))?;
    let block = genesis_block(tx, pin.genesis_nonce).map_err(|error| {
        OpenError::Genesis(format!("the genesis block did not assemble: {error}"))
    })?;
    let hash = block.hash();
    let pinned = BlockHash::from_bytes(shekyl_rpc_types::genesis_hash_for(daemon_network(network)));
    if hash != pinned {
        return Err(OpenError::Genesis(format!(
            "the assembled genesis block is {hash:?}, and this build pins {pinned:?}"
        )));
    }
    Ok((block, hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_p2p_transport::prefix_for;

    /// Recorded output of `network_id(net)`. A regenesis that moves the
    /// hash fails this until the bytes are re-recorded with it. These are
    /// not a second definition of the id.
    const MAINNET_ID: [u8; 16] = [
        0x49, 0xCD, 0xEE, 0x7D, 0xEA, 0x1A, 0x61, 0x29, 0x1C, 0x56, 0xAB, 0xD4, 0xDE, 0x5E, 0x03,
        0x64,
    ];
    const TESTNET_ID: [u8; 16] = [
        0x5E, 0x0B, 0xAD, 0xE9, 0x7E, 0xA2, 0x93, 0x8C, 0xB4, 0x9E, 0x8F, 0x6E, 0x90, 0xF1, 0x5D,
        0x4E,
    ];
    const STAGENET_ID: [u8; 16] = [
        0xE7, 0xE7, 0x70, 0x40, 0x5F, 0x89, 0x8E, 0x61, 0x57, 0xE5, 0xA7, 0x6E, 0xCF, 0xDA, 0x38,
        0xCF,
    ];
    const MAINNET_PREFIX: [u8; 8] = [0xC5, 0xF5, 0xE2, 0xDD, 0x59, 0xB3, 0x53, 0x41];
    const TESTNET_PREFIX: [u8; 8] = [0x69, 0x40, 0xEC, 0x75, 0x97, 0xD7, 0x60, 0x1B];
    const STAGENET_PREFIX: [u8; 8] = [0x42, 0xBB, 0xA1, 0xCC, 0x92, 0xD3, 0xE1, 0x80];

    #[test]
    fn each_genesis_derives_its_recorded_id_and_prefix() {
        let cases = [
            (DaemonNet::Mainnet, MAINNET_ID, MAINNET_PREFIX),
            (DaemonNet::Testnet, TESTNET_ID, TESTNET_PREFIX),
            (DaemonNet::Stagenet, STAGENET_ID, STAGENET_PREFIX),
        ];
        for (net, id_kat, prefix_kat) in cases {
            let id = network_id(net);
            assert_eq!(id, id_kat);
            assert_eq!(prefix_for(&id), prefix_kat);
        }
        assert_eq!(network_id(DaemonNet::Regtest), MAINNET_ID);
        assert_ne!(MAINNET_ID, TESTNET_ID);
        assert_ne!(MAINNET_ID, STAGENET_ID);
        assert_ne!(TESTNET_ID, STAGENET_ID);
        assert_ne!(MAINNET_PREFIX, TESTNET_PREFIX);
        assert_ne!(MAINNET_PREFIX, STAGENET_PREFIX);
        assert_ne!(TESTNET_PREFIX, STAGENET_PREFIX);
    }
}
