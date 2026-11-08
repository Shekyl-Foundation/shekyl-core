// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The network table's genesis pins (`shekyl_network::Genesis`): rebuild a
//! network's genesis from its recipients file, write the pin files the table
//! compiles in, and check the compiled table against a rebuild
//! (`NETWORK_IDENTITY.md` NI-Q3).
//!
//! Every network goes through the same three steps (NI-R4): its recipients
//! file gives the coinbase (the transaction key derived from the network's
//! name, NI-R12), the coinbase under the fixed header (nonce 0) gives the
//! block, and the block's hash is the chain id. `geblock pin` writes
//! `rust/shekyl-network/genesis/<name>.tx.hex` and `<name>.hash`; a regenesis
//! regenerates them and nothing else edits them.

use std::path::{Path, PathBuf};

use shekyl_address::Network;
use zeroize::Zeroizing;

use crate::builder::{build_genesis_tx, genesis_block};
use crate::recipients::{
    load_and_validate, RecipientEntry, RecipientsFile, GENESIS_RECIPIENT_AMOUNT_ATOMIC,
};
use crate::txkey::{derive_genesis_tx_secret, tx_pubkey};
use crate::wallets::wallets_from_seeds;
use crate::GenesisToolError;

/// Regtest's genesis wallets: committed, published and test-only
/// (`NETWORK_IDENTITY.md` NI-R11). A regtest harness spends regtest's
/// genesis outputs with these; no other network's genesis may pay a key
/// anyone can read here.
pub const REGTEST_GENESIS_SEEDS: [[u8; 32]; 5] = [
    *b"shekyl-regtest-genesis-wallet-01",
    *b"shekyl-regtest-genesis-wallet-02",
    *b"shekyl-regtest-genesis-wallet-03",
    *b"shekyl-regtest-genesis-wallet-04",
    *b"shekyl-regtest-genesis-wallet-05",
];

/// `<repo>/config/genesis_recipients.<name>.json`.
#[must_use]
pub fn recipients_path(repo_root: &Path, net: Network) -> PathBuf {
    repo_root
        .join("config")
        .join(format!("genesis_recipients.{}.json", net.name()))
}

/// The table's pin files for `net`: the transaction hex and the block hash.
#[must_use]
pub fn pin_paths(repo_root: &Path, net: Network) -> (PathBuf, PathBuf) {
    let dir = repo_root.join("rust/shekyl-network/genesis");
    (
        dir.join(format!("{}.tx.hex", net.name())),
        dir.join(format!("{}.hash", net.name())),
    )
}

/// A genesis rebuilt from its recipients file.
pub struct Rebuilt {
    /// The coinbase transaction, hex.
    pub tx_hex: String,
    /// The genesis block hash.
    pub block_hash: [u8; 32],
    /// The coinbase's transaction public key, recomputed from the network's
    /// name and the recipients (NI-R12).
    pub tx_pub: [u8; 32],
}

/// Rebuild `net`'s genesis from the recipients file at `path`.
///
/// # Errors
///
/// The recipients file does not load or validate for `net`, or the
/// coinbase or block does not assemble.
pub fn rebuild(net: Network, path: &Path) -> Result<Rebuilt, GenesisToolError> {
    let recipients = load_and_validate(path, net)?;
    let tx_pub = tx_pubkey(&derive_genesis_tx_secret(net, &recipients));
    let built = build_genesis_tx(net, &recipients)?;
    let block = genesis_block(built.tx)?;
    Ok(Rebuilt {
        tx_hex: built.hex,
        block_hash: *block.hash().as_bytes(),
        tx_pub,
    })
}

/// Regtest's recipients file: the wallets [`REGTEST_GENESIS_SEEDS`] give.
///
/// # Errors
///
/// A seed does not derive an account or its address does not round-trip.
pub fn regtest_recipients() -> Result<RecipientsFile, GenesisToolError> {
    let seeds: Vec<Zeroizing<[u8; 32]>> = REGTEST_GENESIS_SEEDS
        .iter()
        .map(|s| Zeroizing::new(*s))
        .collect();
    let wallets = wallets_from_seeds(Network::Regtest, &seeds)?;
    Ok(RecipientsFile {
        network: Network::Regtest.name().to_owned(),
        recipients: wallets
            .into_iter()
            .map(|w| RecipientEntry {
                label: format!("Regtest test wallet {}", w.index),
                address: w.address,
                amount_atomic: GENESIS_RECIPIENT_AMOUNT_ATOMIC,
            })
            .collect(),
    })
}

/// Rebuild `net`'s genesis from the repository's recipients file and write
/// the table's two pin files.
///
/// # Errors
///
/// The rebuild fails, or a pin file cannot be written.
pub fn write_pins(repo_root: &Path, net: Network) -> Result<Rebuilt, GenesisToolError> {
    let rebuilt = rebuild(net, &recipients_path(repo_root, net))?;
    let (tx_path, hash_path) = pin_paths(repo_root, net);
    std::fs::write(&tx_path, format!("{}\n", rebuilt.tx_hex))?;
    std::fs::write(&hash_path, format!("{}\n", hex::encode(rebuilt.block_hash)))?;
    Ok(rebuilt)
}

/// How the compiled table compares with a rebuild of one network.
pub struct Check {
    /// The network checked.
    pub network: Network,
    /// The table's transaction is the rebuilt one.
    pub tx_matches: bool,
    /// The table's hash is the rebuilt block's.
    pub hash_matches: bool,
}

/// Rebuild `net`'s genesis from the repository's recipients file and compare
/// it with the table this binary was compiled with.
///
/// # Errors
///
/// The rebuild fails.
pub fn verify(repo_root: &Path, net: Network) -> Result<Check, GenesisToolError> {
    let rebuilt = rebuild(net, &recipients_path(repo_root, net))?;
    let genesis = net.genesis();
    Ok(Check {
        network: net,
        tx_matches: genesis.tx_hex() == rebuilt.tx_hex,
        hash_matches: genesis.hash() == rebuilt.block_hash,
    })
}

/// Write regtest's recipients file into the repository.
///
/// # Errors
///
/// The file cannot be generated or written.
pub fn write_regtest_recipients(repo_root: &Path) -> Result<PathBuf, GenesisToolError> {
    let file = regtest_recipients()?;
    let path = recipients_path(repo_root, Network::Regtest);
    let mut body = serde_json::to_string_pretty(&file)?;
    body.push('\n');
    std::fs::write(&path, body)?;
    Ok(path)
}
