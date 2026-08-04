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
use crate::recipients::load_and_validate;
use crate::{invalid, GenesisToolError};

/// One network's genesis pins as read from `cryptonote_config.h`.
#[derive(Debug, Clone)]
pub struct ConfigGenesis {
    /// The pinned `GENESIS_TX` hex string.
    pub genesis_tx_hex: String,
    /// The pinned `GENESIS_NONCE`.
    pub genesis_nonce: u32,
}

/// All three networks' pins.
#[derive(Debug, Clone)]
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

/// C/C++ identifier character (ASCII letter, digit, or `_`).
fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Find every `const … <name> =` assignment site in `region`, returning the
/// byte offset just past the `=`.
///
/// Accepts both west-const (`const T name =`) and east-const (`T const name =`)
/// — the house style in `cryptonote_config.h` is east-const. Requires a
/// whole-token `name` (so `::config::GENESIS_TX` is only a candidate when
/// followed by `=`, which the qualified references in `config_t` initializers
/// are not) and a `const` keyword on the same declaration fragment (so
/// uninitialized `config_t` fields `std::string const GENESIS_TX;` do not
/// match).
fn assignment_sites(region: &str, name: &str) -> Vec<usize> {
    let bytes = region.as_bytes();
    let mut sites = Vec::new();
    let mut from = 0;
    while let Some(rel) = region[from..].find(name) {
        let start = from + rel;
        let after_name = start + name.len();

        let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        let after_ok = after_name >= bytes.len() || !is_ident_byte(bytes[after_name]);
        if before_ok && after_ok {
            let rest = region[after_name..].trim_start();
            if rest.starts_with('=') {
                // Declaration fragment: from the previous `;`, `{`, or line
                // start up to `name`. Must contain `const` as a token.
                let frag_start = region[..start]
                    .rfind(['\n', '{', ';'])
                    .map(|i| i + 1)
                    .unwrap_or(0);
                let prefix = region[frag_start..start].trim();
                if const_token_present(prefix) {
                    // Offset just past `=`, accounting for whitespace between
                    // name and `=`.
                    let ws = region[after_name..].len() - rest.len();
                    sites.push(after_name + ws + 1);
                }
            }
        }
        from = after_name;
    }
    sites
}

/// True when `prefix` contains a whole-token `const` (not a substring of
/// another identifier).
fn const_token_present(prefix: &str) -> bool {
    let bytes = prefix.as_bytes();
    let mut from = 0;
    while let Some(rel) = prefix[from..].find("const") {
        let start = from + rel;
        let after = start + "const".len();
        let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        let after_ok = after >= bytes.len() || !is_ident_byte(bytes[after]);
        if before_ok && after_ok {
            return true;
        }
        from = after;
    }
    false
}

/// Extract exactly one `const … <name> = "<hex>"` string literal from `region`.
fn extract_string(region: &str, name: &str, where_: &str) -> Result<String, GenesisToolError> {
    let sites = assignment_sites(region, name);
    if sites.len() != 1 {
        return Err(invalid(format!(
            "expected exactly one `const … {name} = …` in the {where_} region of \
             cryptonote_config.h, found {}",
            sites.len()
        )));
    }
    let rest = region[sites[0]..].trim_start();
    let Some(rest) = rest.strip_prefix('"') else {
        return Err(invalid(format!(
            "`const … {name} = …` in the {where_} region is not a string literal"
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

/// Extract exactly one `const … <name> = <u32>` integer literal from `region`.
fn extract_u32(region: &str, name: &str, where_: &str) -> Result<u32, GenesisToolError> {
    let sites = assignment_sites(region, name);
    if sites.len() != 1 {
        return Err(invalid(format!(
            "expected exactly one `const … {name} = …` in the {where_} region of \
             cryptonote_config.h, found {}",
            sites.len()
        )));
    }
    let rest = region[sites[0]..].trim_start();
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return Err(invalid(format!(
            "`const … {name} = …` in the {where_} region is not an integer literal"
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
        let path = recipients_dir.join(format!("genesis_recipients.{}.json", net.as_str()));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal three-region header in house east-const style.
    const EAST_CONST_HEADER: &str = r#"
namespace config
{
  std::string const GENESIS_TX = "aabb";
  uint32_t const GENESIS_NONCE = 10000;
  namespace testnet
  {
    std::string const GENESIS_TX = "ccdd";
    uint32_t const GENESIS_NONCE = 10101;
  }
  namespace stagenet
  {
    std::string const GENESIS_TX = "eeff";
    uint32_t const GENESIS_NONCE = 10002;
  }
}
// config_t fields must not count as assignment sites:
struct config_t {
  std::string const GENESIS_TX;
  uint32_t const GENESIS_NONCE;
};
"#;

    /// West-const form must also parse (defensive; not the house style).
    const WEST_CONST_HEADER: &str = r#"
namespace config
{
  const std::string GENESIS_TX = "aabb";
  const uint32_t GENESIS_NONCE = 1;
  namespace testnet
  {
    const std::string GENESIS_TX = "ccdd";
    const uint32_t GENESIS_NONCE = 2;
  }
  namespace stagenet
  {
    const std::string GENESIS_TX = "eeff";
    const uint32_t GENESIS_NONCE = 3;
  }
}
"#;

    #[test]
    fn parses_east_const_house_style() {
        let pins = parse_config_genesis(EAST_CONST_HEADER).expect("east-const parses");
        assert_eq!(pins.mainnet.genesis_tx_hex, "aabb");
        assert_eq!(pins.mainnet.genesis_nonce, 10000);
        assert_eq!(pins.testnet.genesis_tx_hex, "ccdd");
        assert_eq!(pins.testnet.genesis_nonce, 10101);
        assert_eq!(pins.stagenet.genesis_tx_hex, "eeff");
        assert_eq!(pins.stagenet.genesis_nonce, 10002);
    }

    #[test]
    fn parses_west_const() {
        let pins = parse_config_genesis(WEST_CONST_HEADER).expect("west-const parses");
        assert_eq!(pins.mainnet.genesis_nonce, 1);
        assert_eq!(pins.testnet.genesis_nonce, 2);
        assert_eq!(pins.stagenet.genesis_nonce, 3);
    }

    #[test]
    fn rejects_missing_namespace() {
        let err = parse_config_genesis("namespace config { }").unwrap_err();
        assert!(err.to_string().contains("namespace testnet"), "{err}");
    }

    #[test]
    fn rejects_stagenet_before_testnet() {
        let body = r#"
namespace config {
  namespace stagenet { std::string const GENESIS_TX = "aa"; uint32_t const GENESIS_NONCE = 1; }
  namespace testnet  { std::string const GENESIS_TX = "bb"; uint32_t const GENESIS_NONCE = 2; }
}
"#;
        let err = parse_config_genesis(body).unwrap_err();
        assert!(err.to_string().contains("precedes"), "{err}");
    }

    #[test]
    fn rejects_missing_pin_assignment() {
        let body = r#"
namespace config {
  uint32_t const GENESIS_NONCE = 1;
  namespace testnet {
    std::string const GENESIS_TX = "aabb";
    uint32_t const GENESIS_NONCE = 2;
  }
  namespace stagenet {
    std::string const GENESIS_TX = "ccdd";
    uint32_t const GENESIS_NONCE = 3;
  }
}
"#;
        let err = parse_config_genesis(body).unwrap_err();
        assert!(
            err.to_string().contains("GENESIS_TX") && err.to_string().contains("found 0"),
            "{err}"
        );
    }

    #[test]
    fn rejects_odd_length_hex() {
        let body = r#"
namespace config {
  std::string const GENESIS_TX = "abc";
  uint32_t const GENESIS_NONCE = 1;
  namespace testnet {
    std::string const GENESIS_TX = "aabb";
    uint32_t const GENESIS_NONCE = 2;
  }
  namespace stagenet {
    std::string const GENESIS_TX = "ccdd";
    uint32_t const GENESIS_NONCE = 3;
  }
}
"#;
        let err = parse_config_genesis(body).unwrap_err();
        assert!(err.to_string().contains("even-length hex"), "{err}");
    }

    #[test]
    fn assignment_sites_skip_uninitialized_and_qualified_refs() {
        let region = r#"
  std::string const GENESIS_TX = "aabb";
  std::string const GENESIS_TX;
  ::config::GENESIS_TX,
  FOO_GENESIS_TX = "nope";
"#;
        let sites = assignment_sites(region, "GENESIS_TX");
        assert_eq!(sites.len(), 1, "only the initialized east-const assignment");
    }
}
