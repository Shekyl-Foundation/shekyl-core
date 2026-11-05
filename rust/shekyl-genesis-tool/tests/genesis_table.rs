// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The network table's genesis, over all four networks
//! (`docs/design/NETWORK_IDENTITY.md`, NI-Q3 tests (a)–(c), NI-R10, NI-R12).
//!
//! Each network's genesis rebuilds from its recipients file to the table's
//! pin, its coinbase's transaction key recomputes from the row's name, and
//! no two networks share a genesis hash, a network id or a wire prefix. A
//! regenesis moves the pins with `geblock pin`; this test fails until it
//! does.

use std::collections::HashSet;
use std::path::PathBuf;

use shekyl_address::Network;
use shekyl_genesis_tool::builder::GENESIS_DRAW_COMMITMENT;
use shekyl_genesis_tool::recipients::load_and_validate;
use shekyl_genesis_tool::table::{
    rebuild, recipients_path, regtest_recipients, REGTEST_GENESIS_SEEDS,
};
use shekyl_genesis_tool::txkey::{derive_genesis_tx_secret, tx_pubkey};
use shekyl_network::{network_id_from_genesis, prefix_for};
use shekyl_wire::transaction::Transaction;
use shekyl_wire::tx_extra::{self, TxExtraField, COINBASE_NONCE_BYTES};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// (a): every network's genesis, rebuilt from its recipients file, is the
/// table's transaction and hash.
#[test]
fn every_genesis_rebuilds_to_the_tables_pin() {
    for net in Network::ALL {
        let rebuilt = rebuild(net, &recipients_path(&repo_root(), net))
            .unwrap_or_else(|e| panic!("{net}: {e}"));
        assert_eq!(
            net.genesis().tx_hex(),
            rebuilt.tx_hex,
            "{net}: the table's genesis transaction is not the rebuild (run `geblock pin`)"
        );
        assert_eq!(
            net.genesis().hash(),
            rebuilt.block_hash,
            "{net}: the table's genesis hash is not the rebuild (run `geblock pin`)"
        );
    }
}

/// (c), NI-R12: the pinned coinbase's transaction key is the one the row's
/// name and recipients derive. Genesis commits to the network's name
/// through this key.
#[test]
fn every_genesis_commits_to_its_rows_name() {
    for net in Network::ALL {
        let bytes = hex::decode(net.genesis().tx_hex()).expect("the pin is hex");
        let tx = Transaction::from_bytes(&bytes).expect("the pin decodes");
        let fields = tx.prefix.parse_extra().expect("the coinbase extra parses");
        let pinned_pub = fields
            .iter()
            .find_map(|f| match f {
                TxExtraField::PubKey(k) => Some(*k),
                _ => None,
            })
            .expect("the coinbase carries its transaction key");
        let recipients = load_and_validate(&recipients_path(&repo_root(), net), net)
            .unwrap_or_else(|e| panic!("{net}: {e}"));
        let derived = tx_pubkey(&derive_genesis_tx_secret(net, &recipients));
        assert_eq!(pinned_pub, derived, "{net}: the key is not the name's");
        for other in Network::ALL.into_iter().filter(|o| *o != net) {
            assert_ne!(
                pinned_pub,
                tx_pubkey(&derive_genesis_tx_secret(other, &recipients)),
                "{net}: the same recipients under {other}'s name give the same key"
            );
        }
    }
}

/// (b): no two networks share a genesis hash, a network id or a wire prefix.
/// (Names, tags, ports and address prefixes are `shekyl-network`'s own
/// test.)
#[test]
fn genesis_hashes_ids_and_prefixes_are_pairwise_distinct() {
    let mut hashes = HashSet::new();
    let mut ids = HashSet::new();
    let mut prefixes = HashSet::new();
    for net in Network::ALL {
        let hash = net.genesis().hash();
        let id = net.network_id();
        assert_eq!(
            id,
            network_id_from_genesis(&hash),
            "{net}: the id is the hash's"
        );
        assert!(hashes.insert(hash), "{net}: genesis hash");
        assert!(ids.insert(id), "{net}: network id");
        assert!(prefixes.insert(prefix_for(&id)), "{net}: wire prefix");
    }
}

/// Regtest's committed recipients file is what its published test seeds
/// give (NI-R11).
#[test]
fn regtest_recipients_are_its_test_seeds() {
    let generated = regtest_recipients().expect("the test seeds derive");
    let committed: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(recipients_path(&repo_root(), Network::Regtest))
            .expect("the regtest recipients file"),
    )
    .expect("json");
    assert_eq!(
        serde_json::to_value(&generated).expect("json"),
        committed,
        "run `geblock regtest-recipients`"
    );
    assert_eq!(generated.recipients.len(), REGTEST_GENESIS_SEEDS.len());
}

/// NI-R11: mainnet's genesis is provisional until its custodians deliver;
/// every other network's is final for this round.
#[test]
fn only_mainnet_is_provisional() {
    for net in Network::ALL {
        assert_eq!(
            net.genesis().provisional(),
            net == Network::Mainnet,
            "{net}"
        );
    }
}

/// The coinbase writer and the table's genesis are one layout: read the five
/// fields out of each network's pinned genesis extra, hand them to the
/// grammar's one constructor, and require the bytes that come out to be the
/// bytes that went in. A drift in either direction fails here, in the writer
/// or in what was pinned, and so does a genesis the grammar would refuse at
/// connect. The extra nonce and the draw commitment are zero, as genesis was
/// not nonce-searched and has no producer (NI-R4).
#[test]
fn the_pure_writer_reproduces_each_pinned_genesis_extra() {
    for net in Network::ALL {
        let blob = hex::decode(net.genesis().tx_hex()).expect("the pin is hex");
        let tx = Transaction::from_bytes(&blob).unwrap_or_else(|e| panic!("{net}: {e}"));
        let extra = &tx.prefix.extra;
        let n_outputs = tx.prefix.outputs.len();
        assert!(n_outputs > 0, "{net}: genesis pays at least one output");

        let fields = tx_extra::parse(extra).unwrap_or_else(|e| panic!("{net}: {e}"));
        tx_extra::check_coinbase_extra_shape(&fields, n_outputs)
            .unwrap_or_else(|e| panic!("{net}: the pinned genesis fails the grammar: {e}"));
        let [TxExtraField::PubKey(pubkey), TxExtraField::Nonce(nonce), TxExtraField::DrawCommitment(commitment), TxExtraField::PqcKemCiphertext(kem), TxExtraField::PqcLeafEntries(leaf)] =
            fields.as_slice()
        else {
            panic!("{net}: the pinned genesis extra is not the five-field layout")
        };
        let nonce: [u8; COINBASE_NONCE_BYTES] = nonce
            .as_slice()
            .try_into()
            .expect("the grammar fixed the width");
        assert_eq!(nonce, [0; COINBASE_NONCE_BYTES], "{net}");
        assert_eq!(*commitment, GENESIS_DRAW_COMMITMENT, "{net}");

        let rebuilt =
            tx_extra::build_coinbase_extra(*pubkey, &nonce, *commitment, n_outputs, kem, leaf)
                .unwrap_or_else(|e| panic!("{net}: the writer refused the genesis fields: {e}"));
        assert_eq!(
            &rebuilt, extra,
            "{net}: the writer does not reproduce the pinned genesis extra"
        );
    }
}
