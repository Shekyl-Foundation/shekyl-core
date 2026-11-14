// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pinned genesis block this build connects (`NETWORK_IDENTITY.md`
//! NI-Q3). The assembly is [`shekyl_genesis_tool::builder::pinned_genesis`];
//! this maps its error onto [`crate::OpenError`].

use shekyl_daemon_config::Network;
use shekyl_types::BlockHash;
use shekyl_wire::Block;

use crate::OpenError;

/// The genesis block this build connects on `network`, and the hash the
/// table pins.
pub(crate) fn pinned_genesis(network: Network) -> Result<(Block, BlockHash), OpenError> {
    let block = shekyl_genesis_tool::builder::pinned_genesis(network)
        .map_err(|error| OpenError::Genesis(error.to_string()))?;
    let hash = block.hash();
    Ok((block, hash))
}
