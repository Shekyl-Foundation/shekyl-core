// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `src/cryptonote_config.h` genesis-pin parsing and byte-compare verify.
//!
//! Replaces the retired `shekyl-dev/scripts/verify_genesis.py`, which (a)
//! grepped for a `#define GENESIS_TX` that has not existed since the pins
//! moved into namespaces, and (b) could never pass anyway because the C++
//! builder drew a fresh tx key per run. With the deterministic tx key the
//! byte-compare is meaningful: `geblock verify` rebuilds all three networks
//! from `config/genesis_recipients.*.json` and compares against the pins.
//!
//! Parsing is deliberately strict: a pin that cannot be found is an error,
//! never a skip — a silent parse miss would turn the verify gate into
//! theater.

use std::path::Path;

use shekyl_address::Network;

use crate::builder::build_genesis_tx;
use crate::recipients::{load_and_validate, network_str};
use crate::{invalid, GenesisToolError};

/// One network's genesis pins as read from `cryptonote_config.h`.
pub struct ConfigGenesis {
    /// The pinned `GENESIS_TX` hex string.
    pub genesis_tx_hex: String,
    /// The pinned `GENESIS_NONCE`.
    pub genesis_nonce: u32,
}

/// All three networks' pins.
pub struct ConfigPins {
    /// `namespace config` (mainnet) pins.
    pub mainnet: ConfigGenesis,
    /// `namespace config::testnet` pins.
    pub testnet: ConfigGenesis,
    /// `namespace config::stagenet` pins.
    pub stagenet: ConfigGenesis,
}

impl ConfigPins {
    /// The pins for `net`.
    #[must_use]
    pub fn for_network(&self, net: Network) -> &ConfigGenesis {
        match net {
            Network::Mainnet => &self.mainnet,
            Network::Testnet => &self.testnet,
            Network::Stagenet => &self.stagenet,
        }
    }
}

/// Find every `const <name> = ` assignment site in `region`, returning the
/// byte offset just past the `=`. Declarations without an initializer (the
/// `config_t` struct fields) and qualified references (`::config::<name>`)
/// don't match.
fn assignment_sites(region: &str, name: &str) -> Vec<usize> {
    let needle = format!("const {name}");
    let mut sites = Vec::new();
    let mut from = 0;
    while let Some(pos) = region[from..].find(&needle) {
        let after = from + pos + needle.len();
        let rest = region[after..].trim_start();
        if rest.starts_with('=') {
            let ws = region[after..].len() - rest.len();
            sites.push(after + ws + 1);
        }
        from = after;
    }
    sites
}

/// Extract exactly one `const <name> = "<hex>"` string literal from `region`.
fn extract_string(region: &str, name: &str, where_: &str) -> Result<String, GenesisToolError> {
    let sites = assignment_sites(region, name);
    if sites.len() != 1 {
        return Err(invalid(format!(
            "expected exactly one `const {name} = …` in the {where_} region of \
             cryptonote_config.h, found {}",
            sites.len()
        )));
    }
    let rest = region[sites[0]..].trim_start();
    let Some(rest) = rest.strip_prefix('"') else {
        return Err(invalid(format!(
            "`const {name} = …` in the {where_} region is not a string literal"
        )));
    };
    let Some(end) = rest.find('"') else {
        return Err(invalid(format!(
            "unterminated string literal for `{name}` in the {where_} region"
        )));
    };
    let value = &rest[..end];
    if value.is_empty() || value.len() % 2 != 0 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid(format!(
            "`{name}` in the {where_} region is not even-length hex ({} chars)",
            value.len()
        )));
    }
    Ok(value.to_owned())
}

/// Extract exactly one `const <name> = <u32>` integer literal from `region`.
fn extract_u32(region: &str, name: &str, where_: &str) -> Result<u32, GenesisToolError> {
    let sites = assignment_sites(region, name);
    if sites.len() != 1 {
        return Err(invalid(format!(
            "expected exactly one `const {name} = …` in the {where_} region of \
             cryptonote_config.h, found {}",
            sites.len()
        )));
    }
    let rest = region[sites[0]..].trim_start();
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return Err(invalid(format!(
            "`const {name} = …` in the {where_} region is not an integer literal"
        )));
    }
    digits
        .parse::<u32>()
        .map_err(|e| invalid(format!("`{name}` in the {where_} region: {e}")))
}

/// Parse the three networks' `GENESIS_TX` / `GENESIS_NONCE` pins out of the
/// `cryptonote_config.h` source text.
///
/// Region model: mainnet pins live in `namespace config` before
/// `namespace testnet`; testnet pins between `namespace testnet` and
/// `namespace stagenet`; stagenet pins after. Each region must contain
/// exactly one assignment of each pin.
pub fn parse_config_genesis(config_h: &str) -> Result<ConfigPins, GenesisToolError> {
    let testnet_at = config_h
        .find("namespace testnet")
        .ok_or_else(|| invalid("cryptonote_config.h: `namespace testnet` not found"))?;
    let stagenet_at = config_h
        .find("namespace stagenet")
        .ok_or_else(|| invalid("cryptonote_config.h: `namespace stagenet` not found"))?;
    if stagenet_at <= testnet_at {
        return Err(invalid(
            "cryptonote_config.h: `namespace stagenet` precedes `namespace testnet` \
             (region model no longer holds; update the parser)",
        ));
    }

    let regions = [
        ("mainnet", &config_h[..testnet_at]),
        ("testnet", &config_h[testnet_at..stagenet_at]),
        ("stagenet", &config_h[stagenet_at..]),
    ];
    let mut pins = Vec::with_capacity(3);
    for (name, region) in regions {
        pins.push(ConfigGenesis {
            genesis_tx_hex: extract_string(region, "GENESIS_TX", name)?,
            genesis_nonce: extract_u32(region, "GENESIS_NONCE", name)?,
        });
    }
    let [mainnet, testnet, stagenet]: [ConfigGenesis; 3] =
        pins.try_into().map_err(|_| invalid("region count"))?;
    Ok(ConfigPins {
        mainnet,
        testnet,
        stagenet,
    })
}

/// [`parse_config_genesis`] over a file path.
pub fn load_config_pins(path: &Path) -> Result<ConfigPins, GenesisToolError> {
    let body = std::fs::read_to_string(path)
        .map_err(|e| invalid(format!("cannot read {}: {e}", path.display())))?;
    parse_config_genesis(&body)
}

/// Outcome of rebuilding one network against its pin.
pub struct VerifyOutcome {
    /// The network verified.
    pub network: Network,
    /// Whether the rebuilt hex byte-matches the pin.
    pub matches: bool,
    /// Rebuilt hex length (chars).
    pub built_len: usize,
    /// Pinned hex length (chars).
    pub pinned_len: usize,
    /// Char offset of the first difference, when lengths match but bytes
    /// differ.
    pub first_mismatch: Option<usize>,
}

/// Rebuild all three networks from `<recipients_dir>/genesis_recipients.<net>.json`
/// and byte-compare each against the `cryptonote_config.h` pins.
pub fn verify_networks(
    config_h_path: &Path,
    recipients_dir: &Path,
) -> Result<Vec<VerifyOutcome>, GenesisToolError> {
    let pins = load_config_pins(config_h_path)?;
    let mut outcomes = Vec::with_capacity(3);
    for net in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
        let path = recipients_dir.join(format!("genesis_recipients.{}.json", network_str(net)));
        let recipients = load_and_validate(&path, net)?;
        let built = build_genesis_tx(net, &recipients)?;
        let pinned = &pins.for_network(net).genesis_tx_hex;
        let matches = built.hex == *pinned;
        let first_mismatch = if matches {
            None
        } else {
            built
                .hex
                .bytes()
                .zip(pinned.bytes())
                .position(|(a, b)| a != b)
        };
        outcomes.push(VerifyOutcome {
            network: net,
            matches,
            built_len: built.hex.len(),
            pinned_len: pinned.len(),
            first_mismatch,
        });
    }
    Ok(outcomes)
}
