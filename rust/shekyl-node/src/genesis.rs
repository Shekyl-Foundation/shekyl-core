// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pinned genesis block: the network table's genesis transaction under
//! the fixed genesis header (`shekyl_network::Genesis`, the genesis tool's
//! [`genesis_block`]), the same assembly on every network
//! (`NETWORK_IDENTITY.md` NI-Q3).

use shekyl_daemon_config::Network;
use shekyl_genesis_tool::builder::genesis_block;
use shekyl_types::BlockHash;
use shekyl_wire::{Block, Transaction};

use crate::OpenError;

/// The genesis block this build connects on `network`, and the hash the
/// table pins.
pub(crate) fn pinned_genesis(network: Network) -> Result<(Block, BlockHash), OpenError> {
    let genesis = network.genesis();
    let bytes = hex::decode(genesis.tx_hex()).map_err(|error| {
        OpenError::Genesis(format!(
            "{network}'s genesis transaction is not hex: {error}"
        ))
    })?;
    let tx = Transaction::from_bytes(&bytes).map_err(|error| {
        OpenError::Genesis(format!(
            "{network}'s genesis transaction did not decode: {error}"
        ))
    })?;
    let block = genesis_block(tx).map_err(|error| {
        OpenError::Genesis(format!("the genesis block did not assemble: {error}"))
    })?;
    let hash = block.hash();
    let pinned = BlockHash::from_bytes(genesis.hash());
    if hash != pinned {
        return Err(OpenError::Genesis(format!(
            "the assembled genesis block is {hash:?}, and this build pins {pinned:?}"
        )));
    }
    Ok((block, hash))
}
