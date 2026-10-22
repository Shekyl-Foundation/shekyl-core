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
/// rebuilds the same block and checks it against [`shekyl_chain_rules::ReleaseAnchors`].
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
