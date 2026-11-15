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
//! name, NI-R12), the coinbase under the genesis header (the network's mint
//! time, nonce 0) gives the block, and the block's hash is the chain id.
//!
//! The mint time is the one input no file in the repository derives
//! (NI-R18): `geblock mint` takes it from the clock, for the networks named,
//! and writes it beside the other pins; `geblock pin` and every rebuild read
//! it back. The tool writes `rust/shekyl-network/genesis/<name>.tx.hex`,
//! `<name>.timestamp` and `<name>.hash`; a regenesis regenerates them and
//! nothing else edits them.

use std::path::{Path, PathBuf};

use shekyl_address::Network;
use shekyl_network::GenesisTimestamp;
use zeroize::Zeroizing;

use crate::builder::{build_genesis_tx, genesis_block};
use crate::recipients::{
    load_and_validate, RecipientEntry, RecipientsFile, GENESIS_RECIPIENT_AMOUNT_ATOMIC,
};
use crate::txkey::{derive_genesis_tx_secret, tx_pubkey};
use crate::wallets::wallets_from_seeds;
use crate::{invalid, GenesisToolError};

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

/// The table's pin files for one network.
pub struct PinPaths {
    /// The coinbase transaction, hex.
    pub tx_hex: PathBuf,
    /// The mint time, decimal seconds.
    pub timestamp: PathBuf,
    /// The genesis block hash, hex.
    pub hash: PathBuf,
}

/// The table's pin files for `net`.
#[must_use]
pub fn pin_paths(repo_root: &Path, net: Network) -> PinPaths {
    let dir = repo_root.join("rust/shekyl-network/genesis");
    PinPaths {
        tx_hex: dir.join(format!("{}.tx.hex", net.name())),
        timestamp: dir.join(format!("{}.timestamp", net.name())),
        hash: dir.join(format!("{}.hash", net.name())),
    }
}

/// The earliest mint time the tool accepts: 2026-08-04 00:00 UTC, the day
/// the deterministic genesis pipeline landed. A clock before it is a broken
/// clock, and genesis is exempt from every timestamp rule a later block
/// meets, so the tool refuses to stamp it rather than let the network
/// carry it.
pub const MINT_FLOOR: u64 = 1_785_801_600;

/// The mint time for a genesis stamped at `now` (seconds after the Unix
/// epoch).
///
/// # Errors
///
/// `now` is before [`MINT_FLOOR`].
pub fn mint_time(now: u64) -> Result<GenesisTimestamp, GenesisToolError> {
    if now < MINT_FLOOR {
        return Err(invalid(format!(
            "the clock reads {now}, before {MINT_FLOOR} (2026-08-04 UTC): \
             set the clock before minting a genesis"
        )));
    }
    GenesisTimestamp::new(now).ok_or_else(|| invalid("a mint time is never zero"))
}

/// The mint time recorded in `net`'s timestamp pin.
///
/// # Errors
///
/// The file is missing (the network has not been minted), unreadable, or
/// does not hold one non-zero decimal second.
pub fn recorded_timestamp(
    repo_root: &Path,
    net: Network,
) -> Result<GenesisTimestamp, GenesisToolError> {
    let path = pin_paths(repo_root, net).timestamp;
    let text = std::fs::read_to_string(&path).map_err(|error| {
        invalid(format!(
            "{net} has no mint time at {} ({error}): run `geblock mint --network {net}` first",
            path.display()
        ))
    })?;
    let digits = text.strip_suffix('\n').unwrap_or(&text);
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(format!(
            "{} holds {digits:?}, not a non-zero decimal second",
            path.display()
        )));
    }
    let seconds: u64 = digits
        .parse()
        .map_err(|error| invalid(format!("{}: {error}", path.display())))?;
    GenesisTimestamp::new(seconds).ok_or_else(|| invalid("a mint time is never zero"))
}

/// A genesis rebuilt from its recipients file.
pub struct Rebuilt {
    /// The coinbase transaction, hex.
    pub tx_hex: String,
    /// The mint time the block was assembled under.
    pub timestamp: GenesisTimestamp,
    /// The genesis block hash.
    pub block_hash: [u8; 32],
    /// The coinbase's transaction public key, recomputed from the network's
    /// name and the recipients (NI-R12).
    pub tx_pub: [u8; 32],
}

/// Rebuild `net`'s genesis from the recipients file at `path`, minted at
/// `timestamp`.
///
/// # Errors
///
/// The recipients file does not load or validate for `net`, or the
/// coinbase or block does not assemble.
pub fn rebuild(
    net: Network,
    path: &Path,
    timestamp: GenesisTimestamp,
) -> Result<Rebuilt, GenesisToolError> {
    let recipients = load_and_validate(path, net)?;
    let tx_pub = tx_pubkey(&derive_genesis_tx_secret(net, &recipients));
    let built = build_genesis_tx(net, &recipients)?;
    let block = genesis_block(built.tx, timestamp)?;
    Ok(Rebuilt {
        tx_hex: built.hex,
        timestamp,
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

/// Rebuild `net`'s genesis from the repository's recipients file at
/// `timestamp` and write the table's three pin files.
///
/// # Errors
///
/// The rebuild fails, or a pin file cannot be written.
pub fn write_pins(
    repo_root: &Path,
    net: Network,
    timestamp: GenesisTimestamp,
) -> Result<Rebuilt, GenesisToolError> {
    let rebuilt = rebuild(net, &recipients_path(repo_root, net), timestamp)?;
    let paths = pin_paths(repo_root, net);
    std::fs::write(&paths.tx_hex, format!("{}\n", rebuilt.tx_hex))?;
    std::fs::write(&paths.timestamp, format!("{}\n", timestamp.get()))?;
    std::fs::write(
        &paths.hash,
        format!("{}\n", hex::encode(rebuilt.block_hash)),
    )?;
    Ok(rebuilt)
}

/// How the compiled table compares with a rebuild of one network.
pub struct Check {
    /// The network checked.
    pub network: Network,
    /// The table's transaction is the rebuilt one.
    pub tx_matches: bool,
    /// The table's mint time is the one recorded in the repository.
    pub timestamp_matches: bool,
    /// The table's hash is the rebuilt block's.
    pub hash_matches: bool,
}

/// Rebuild `net`'s genesis from the repository's recipients file at its
/// recorded mint time and compare it with the table this binary was
/// compiled with.
///
/// # Errors
///
/// The mint time is not recorded, or the rebuild fails.
pub fn verify(repo_root: &Path, net: Network) -> Result<Check, GenesisToolError> {
    let recorded = recorded_timestamp(repo_root, net)?;
    let rebuilt = rebuild(net, &recipients_path(repo_root, net), recorded)?;
    let genesis = net.genesis();
    Ok(Check {
        network: net,
        tx_matches: genesis.tx_hex() == rebuilt.tx_hex,
        timestamp_matches: genesis.timestamp() == recorded,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A repository root holding only `net`'s timestamp pin, with `text`.
    fn root_with(net: Network, text: Option<&str>) -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("a temporary directory");
        let dir = root.path().join("rust/shekyl-network/genesis");
        std::fs::create_dir_all(&dir).expect("the genesis directory");
        if let Some(text) = text {
            std::fs::write(pin_paths(root.path(), net).timestamp, text).expect("the pin");
        }
        root
    }

    #[test]
    fn a_clock_before_the_floor_mints_nothing() {
        assert!(mint_time(0).is_err());
        assert!(mint_time(MINT_FLOOR - 1).is_err());
        assert_eq!(
            mint_time(MINT_FLOOR).map(GenesisTimestamp::get).ok(),
            Some(MINT_FLOOR)
        );
    }

    #[test]
    fn a_recorded_time_is_read_back_and_a_bad_one_refused() {
        let net = Network::Regtest;
        let good = root_with(net, Some("1794760828\n"));
        assert_eq!(
            recorded_timestamp(good.path(), net)
                .map(GenesisTimestamp::get)
                .ok(),
            Some(1_794_760_828)
        );
        let missing = root_with(net, None);
        let refused = recorded_timestamp(missing.path(), net)
            .err()
            .expect("an unminted network is refused");
        assert!(refused.to_string().contains("geblock mint"), "{refused}");
        for text in ["0\n", "", "007\n", "12x\n", "-5\n"] {
            let bad = root_with(net, Some(text));
            assert!(
                recorded_timestamp(bad.path(), net).is_err(),
                "{text:?} was read"
            );
        }
    }
}
