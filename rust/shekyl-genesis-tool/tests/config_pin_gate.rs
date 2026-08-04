// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The config-pin CI gate: the committed recipients files must (a) always be
//! valid, and (b) — from the Phase B regen onward — rebuild byte-for-byte
//! into the `GENESIS_TX` pins in `src/cryptonote_config.h`.
//!
//! (b) is what the deterministic tx key exists for: the pinned genesis is
//! reproducible from committed inputs, so drift between the recipients
//! files and the pins is a CI failure instead of a silent lie.

use shekyl_address::Network;
use shekyl_genesis_tool::config_pin::verify_networks;
use shekyl_genesis_tool::recipients::{load_and_validate, network_str};
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Always on: every committed recipients file parses, is for the network its
/// filename claims, and satisfies the 5 × 20,000 SKL allocation invariants
/// with canonical post-#327 addresses.
#[test]
fn recipients_files_are_valid() {
    for net in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
        let path = repo_root()
            .join("config")
            .join(format!("genesis_recipients.{}.json", network_str(net)));
        let recipients =
            load_and_validate(&path, net).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(recipients.len(), 5);
    }
}

/// The byte-compare gate. Ignored until the Phase B regen replaces the
/// placeholder recipients and re-pins `GENESIS_TX`: until then
/// `cryptonote_config.h` still holds the pre-regen genesis built by the
/// retired fresh-txkey C++ tool, which nothing can reproduce.
#[test]
#[ignore = "un-ignore at the Phase B regen: config.h still pins the pre-regen genesis"]
fn genesis_hex_matches_config_pin() {
    let root = repo_root();
    let outcomes = verify_networks(&root.join("src/cryptonote_config.h"), &root.join("config"))
        .expect("verify runs");
    for o in &outcomes {
        assert!(
            o.matches,
            "{}: rebuilt genesis hex does not match the cryptonote_config.h pin \
             (built {} chars, pinned {}, first mismatch {:?})",
            network_str(o.network),
            o.built_len,
            o.pinned_len,
            o.first_mismatch
        );
    }
}
