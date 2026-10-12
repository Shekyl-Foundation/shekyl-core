// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The config-pin CI gate: the committed recipients files must (a) always be
//! valid, and (b) rebuild byte-for-byte into the `GENESIS_TX` pins in
//! `src/cryptonote_config.h`.
//!
//! (b) is what the deterministic tx key exists for: the pinned genesis is
//! reproducible from committed inputs, so drift between the recipients
//! files and the pins is a CI failure instead of a silent lie.
//!
//! The **parser** is gated separately (see
//! [`config_pins_parse_from_real_header`]) so a region-model break — which
//! would make `geblock verify` unable to find the pins at all — fails with a
//! parser diagnostic rather than as a confusing byte-compare miss.

use shekyl_address::Network;
use shekyl_genesis_tool::builder::GENESIS_DRAW_COMMITMENT;
use shekyl_genesis_tool::config_pin::{load_config_pins, verify_networks};
use shekyl_genesis_tool::recipients::load_and_validate;
use shekyl_wire::transaction::Transaction;
use shekyl_wire::tx_extra::{self, TxExtraField, COINBASE_NONCE_BYTES};
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
            .join(format!("genesis_recipients.{}.json", net.as_str()));
        let recipients =
            load_and_validate(&path, net).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(recipients.len(), 5);
    }
}

/// Always on: the real `cryptonote_config.h` must yield exactly three
/// networks' pins with even-length non-empty hex and parseable nonces.
///
/// This is the load-bearing check that the pin scraper still understands
/// the header (east-const house style, namespace regions, config_t fields
/// excluded). Byte-compare against the rebuilt genesis is a separate test
/// below ([`genesis_hex_matches_config_pin`]).
#[test]
fn config_pins_parse_from_real_header() {
    let path = repo_root().join("src/cryptonote_config.h");
    let pins = load_config_pins(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));

    for (net, pin) in [
        (Network::Mainnet, &pins.mainnet),
        (Network::Testnet, &pins.testnet),
        (Network::Stagenet, &pins.stagenet),
    ] {
        assert!(
            !pin.genesis_tx_hex.is_empty(),
            "{}: GENESIS_TX empty",
            net.as_str()
        );
        assert_eq!(
            pin.genesis_tx_hex.len() % 2,
            0,
            "{}: GENESIS_TX odd length {}",
            net.as_str(),
            pin.genesis_tx_hex.len()
        );
        assert!(
            pin.genesis_tx_hex.bytes().all(|b| b.is_ascii_hexdigit()),
            "{}: GENESIS_TX not hex",
            net.as_str()
        );
        // Nonces are network-distinct today; a zero would be a parse miss
        // against the live header (mainnet 10000, testnet 10101, stagenet 10002).
        assert_ne!(
            pin.genesis_nonce,
            0,
            "{}: GENESIS_NONCE parsed as 0",
            net.as_str()
        );
    }
    assert_ne!(
        pins.mainnet.genesis_nonce, pins.testnet.genesis_nonce,
        "mainnet/testnet nonces must differ"
    );
    assert_ne!(
        pins.mainnet.genesis_nonce, pins.stagenet.genesis_nonce,
        "mainnet/stagenet nonces must differ"
    );
    assert_ne!(
        pins.testnet.genesis_nonce, pins.stagenet.genesis_nonce,
        "testnet/stagenet nonces must differ"
    );
}

/// The byte-compare gate: rebuilding every network from the committed
/// recipients files must reproduce the `GENESIS_TX` pins byte for byte. A
/// drift between the recipients files and the pins — in either direction —
/// fails CI instead of shipping a genesis nobody can reproduce.
#[test]
fn genesis_hex_matches_config_pin() {
    let root = repo_root();
    let outcomes = verify_networks(&root.join("src/cryptonote_config.h"), &root.join("config"))
        .expect("verify runs");
    for o in &outcomes {
        assert!(
            o.matches,
            "{}: rebuilt genesis hex does not match the cryptonote_config.h pin \
             (built {} chars, pinned {}, first mismatch {:?})",
            o.network.as_str(),
            o.built_len,
            o.pinned_len,
            o.first_mismatch
        );
    }
}

/// The coinbase writer and the genesis pins are one layout: read the five
/// fields out of each network's pinned genesis extra, hand them to the
/// grammar's one constructor, and require the bytes that come out to be
/// the bytes that went in. A drift in either direction fails here, in the
/// writer or in what was pinned, and so does a genesis the grammar would
/// refuse at connect.
///
/// This is the proof the C++ `mining_parity` test carried through the FFI
/// writer until the `0x0C` draw commitment (`SO-D12` increment 1). That
/// writer now draws its own commitment and takes none from its caller, so
/// it cannot reproduce a fixed extra; [`tx_extra::build_coinbase_extra`] is
/// the pure function it wraps, and the one the daemon's coinbase is laid
/// out by.
#[test]
fn the_pure_writer_reproduces_each_pinned_genesis_extra() {
    let pins = load_config_pins(&repo_root().join("src/cryptonote_config.h")).expect("pins");
    for net in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
        let name = net.as_str();
        let blob = hex::decode(&pins.for_network(net).genesis_tx_hex).expect("pinned hex");
        let tx = Transaction::from_bytes(&blob).unwrap_or_else(|e| panic!("{name}: {e}"));
        let extra = &tx.prefix.extra;
        let n_outputs = tx.prefix.outputs.len();
        assert!(n_outputs > 0, "{name}: genesis pays at least one output");

        let fields = tx_extra::parse(extra).unwrap_or_else(|e| panic!("{name}: {e}"));
        tx_extra::check_coinbase_extra_shape(&fields, n_outputs)
            .unwrap_or_else(|e| panic!("{name}: the pinned genesis fails the grammar: {e}"));
        // Exactly the grammar's five fields, so nothing can survive the
        // round trip below by being dropped.
        let [TxExtraField::PubKey(pubkey), TxExtraField::Nonce(nonce), TxExtraField::DrawCommitment(commitment), TxExtraField::PqcKemCiphertext(kem), TxExtraField::PqcLeafEntries(leaf)] =
            fields.as_slice()
        else {
            panic!("{name}: the pinned genesis extra is not the five-field layout")
        };
        // Genesis was not nonce-searched, and it commits to the ruled value.
        // The commitment is read as a field that is present, like any other
        // block's; this is the pin of its bytes, not a test for absence.
        let nonce: [u8; COINBASE_NONCE_BYTES] = nonce
            .as_slice()
            .try_into()
            .expect("the grammar fixed the width");
        assert_eq!(nonce, [0; COINBASE_NONCE_BYTES], "{name}");
        assert_eq!(*commitment, GENESIS_DRAW_COMMITMENT, "{name}");

        let rebuilt =
            tx_extra::build_coinbase_extra(*pubkey, &nonce, *commitment, n_outputs, kem, leaf)
                .unwrap_or_else(|e| panic!("{name}: the writer refused the genesis fields: {e}"));
        assert_eq!(
            &rebuilt, extra,
            "{name}: the writer does not reproduce the pinned genesis extra"
        );
    }
}
