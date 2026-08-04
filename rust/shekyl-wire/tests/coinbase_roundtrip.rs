// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Live-oracle KAT: real regtest coinbase blocks must round-trip byte-identically.
//!
//! The C++ daemon serializer is the genesis wire-format oracle. `Block::from_bytes`
//! must parse a live PQC coinbase, and `Block::serialize` must reproduce the oracle
//! bytes exactly. This is the test the pre-fix vendored reader failed: it skipped
//! the coinbase `Null` ct base (`enc_amounts`/`enc_labels`/`outPk`) and died with
//! `UnexpectedEof`. See `docs/design/GENESIS_TX_WIRE_FORMAT.md` (§9, §11) and
//! `tests/vectors/README.md`.
//!
//! Regenerated for the credit-wire cutover (2026-08-04): the `block_header` gained
//! `attestation_root`, so all three heights were recaptured. h1/h2 are mined to a
//! freshly derived current-format regtest address (the genesis treasury address is
//! pre-#327 stale format) — see `coinbase_hash.rs` for the full rationale.

use shekyl_wire::Block;

#[test]
fn regtest_coinbase_blocks_round_trip_byte_identical() {
    // Output count is height-dependent: h0 **is** the mainnet genesis (regtest
    // shares GENESIS_TX), which pays the five 20,000 SKL founder allocations;
    // mined blocks pay a single miner output.
    let corpus: [(u64, usize, &[u8]); 3] = [
        (0, 5, include_bytes!("vectors/regtest_coinbase_h0.block")),
        (1, 1, include_bytes!("vectors/regtest_coinbase_h1.block")),
        (2, 1, include_bytes!("vectors/regtest_coinbase_h2.block")),
    ];

    for (height, n_outputs, blob) in corpus {
        let block = Block::from_bytes(blob)
            .unwrap_or_else(|e| panic!("height {height}: Block::from_bytes failed: {e}"));

        // The gen input carries the block height.
        assert_eq!(
            block.number(),
            Some(height),
            "height {height}: coinbase gen height mismatch"
        );
        // Coinbase shape: one gen input, tagged_key outputs, Null ct base.
        assert_eq!(block.miner_transaction.prefix.inputs.len(), 1);
        assert_eq!(
            block.miner_transaction.prefix.outputs.len(),
            n_outputs,
            "height {height}: coinbase output count"
        );
        assert!(block.transaction_hashes.is_empty());

        let reserialized = block.serialize();
        assert_eq!(
            reserialized.as_slice(),
            blob,
            "height {height}: re-serialization must be byte-identical to the C++ oracle blob \
             (len {} vs {})",
            reserialized.len(),
            blob.len(),
        );
    }
}
