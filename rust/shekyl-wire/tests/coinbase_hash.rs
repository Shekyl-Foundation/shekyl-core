// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Live-oracle hash KAT (GENESIS_TX_WIRE_FORMAT.md §11).
//!
//! `Block::hash()` and the coinbase `Transaction::hash()` must equal the C++
//! daemon's `block_header.hash` / `miner_tx_hash` for the same blobs. This is the
//! gold-standard validation of the keccak256 component hashing (3-part coinbase
//! tx hash + the `V(len)`-prefixed block-hash preimage + the single-leaf tree
//! hash) — byte-identical to consensus.
//!
//! The expected hashes are loaded from `vectors/regtest_coinbase_hashes.json` — the
//! **single source of truth**, captured alongside the blobs by
//! `vectors/capture_coinbase.py`. Regenerate the JSON and the `*.block` blobs
//! together; nothing here is hand-copied, so the vectors can't drift out of sync.
//!
//! Genesis (h0) is deterministic and equals `mining_parity`'s mainnet genesis
//! id (CI-enforced below); h1/h2 are mined regtest blocks.
//!
//! Empty-set invariant: every captured height (no pass records yet) must carry
//! `empty_attestation_root()` — live-derived from `shekyl-archival-retention`, not
//! a hand-copied pin — so C++ `empty_attestation_root()` / constructor default and
//! Rust agree without a third hex constant.
//!
//! Mining address note: `capture_coinbase.py` mines to a freshly derived
//! current-format regtest fixture address (`vectors/regtest_mining_recipients.json`),
//! NOT the genesis recipients — a vector concern, not the treasury allocation; see
//! `vectors/README.md` for the full rationale. "Current-format" is **enforced** by
//! `regtest_mining_fixture_is_in_the_current_address_encoding` below, not asserted
//! here: this sentence was true when written, went false when the address encoding
//! gained `msg_sign_pk`, and no test noticed for as long as none of them decoded
//! the file. Note h0 **is** the mainnet genesis
//! (regtest shares `GENESIS_TX`), so any genesis re-pin requires re-capturing this
//! corpus.

use shekyl_archival_retention::empty_attestation_root;
use shekyl_wire::Block;

/// Published mainnet genesis block id (`docs/GENESIS_ALLOCATIONS.md`,
/// `mining_parity` frozen_id for MAINNET). h0 of this corpus must equal it:
/// regtest shares mainnet `GENESIS_TX`, so the live-daemon capture and the C++
/// `generate_genesis_block` path are two independent derivations of one id.
const MAINNET_GENESIS_BLOCK_ID: &str =
    "e623214c06d3ec19a8326c166ff4ee920fe85badbfadd67966c15a315ed7aa12";

fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[test]
fn coinbase_block_and_tx_hashes_match_the_daemon() {
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("vectors/regtest_coinbase_hashes.json"))
            .expect("parse regtest_coinbase_hashes.json");

    let corpus: [(u64, &[u8]); 3] = [
        (0, include_bytes!("vectors/regtest_coinbase_h0.block")),
        (1, include_bytes!("vectors/regtest_coinbase_h1.block")),
        (2, include_bytes!("vectors/regtest_coinbase_h2.block")),
    ];

    let empty_root = empty_attestation_root();

    for (height, blob) in corpus {
        let want = &expected[height.to_string()];
        let block_hash = want["block_hash"]
            .as_str()
            .unwrap_or_else(|| panic!("height {height}: no block_hash in JSON vectors"));
        let miner_tx_hash = want["miner_tx_hash"]
            .as_str()
            .unwrap_or_else(|| panic!("height {height}: no miner_tx_hash in JSON vectors"));

        let block =
            Block::from_bytes(blob).unwrap_or_else(|e| panic!("height {height}: parse: {e}"));
        assert_eq!(
            hex32(&block.miner_transaction.hash()),
            miner_tx_hash,
            "height {height}: miner tx hash (3-part keccak256) must match the daemon"
        );
        assert_eq!(
            hex32(&block.hash()),
            block_hash,
            "height {height}: block hash (keccak256 of V(len)·preimage) must match the daemon"
        );
        // Every height in this corpus has no pass records, so the header must
        // commit the empty-set root — not null_hash. Ties C++ constructor default /
        // create_block_template to Rust empty_attestation_root() without a hex pin.
        assert_eq!(
            block.header.attestation_root, empty_root,
            "height {height}: attestation_root must be empty_attestation_root(), not null_hash"
        );
        if height == 0 {
            // Cross-anchor: daemon-captured h0 must equal the published mainnet
            // genesis id that mining_parity freezes independently via C++.
            assert_eq!(
                block_hash, MAINNET_GENESIS_BLOCK_ID,
                "height 0 block_hash must equal the published mainnet genesis id \
                 (mining_parity MAINNET frozen_id / GENESIS_ALLOCATIONS.md)"
            );
        }
    }
}

/// The mining-address fixture must be in the encoding this file's header calls
/// "current-format" — asserted by DECODING it, not by saying so in a comment.
///
/// This test exists because the claim and its subject had come apart. The
/// header above named `vectors/regtest_mining_recipients.json` a "current-format"
/// address while the committed file held the pre-`msg_sign_pk` encoding, and
/// every test in this crate stayed green throughout — because none of them read
/// it. `capture_coinbase.py` consumes it, so the damage showed up only when
/// someone tried to regenerate the corpus: the daemon's `generateblocks` answers
/// `-4 "Failed to parse wallet address"` and no chain can be produced at all.
///
/// The observable had collapsed: a fixture whose format nothing evaluates
/// cannot fail a format assertion. Refreshing the bytes alone would have left
/// this suite passing for precisely the same reason it passed while broken, so
/// the decode is the point and the fixture refresh is the consequence.
///
/// `ShekylAddress::decode` is the same decoder the daemon uses to parse the
/// mining recipient, so a pass here means `generateblocks` accepts the address
/// rather than merely that the string is well-formed.
#[test]
fn regtest_mining_fixture_is_in_the_current_address_encoding() {
    use shekyl_address::ShekylAddress;

    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("vectors/regtest_mining_recipients.json"))
            .expect("regtest_mining_recipients.json parses");

    let recipients = fixture["recipients"]
        .as_array()
        .expect("fixture has a `recipients` array");
    assert!(
        !recipients.is_empty(),
        "fixture carries no recipients — an empty array would satisfy the loop below \
         without decoding anything, which is the defect this test exists to catch"
    );

    for (i, recipient) in recipients.iter().enumerate() {
        let encoded = recipient["address"]
            .as_str()
            .unwrap_or_else(|| panic!("recipient {i} has no `address` string"));
        if let Err(err) = ShekylAddress::decode(encoded) {
            panic!(
                "recipient {i} does not decode with the current address format: {err:?}\n\
                 The fixture is stale. Regenerate it from the documented emitter:\n\
                 cargo test -p shekyl-wire --test emit_regtest_addr -- --ignored --nocapture\n\
                 See tests/vectors/README.md."
            );
        }
    }
}
