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

use shekyl_wire::Block;

#[test]
fn regtest_coinbase_blocks_round_trip_byte_identical() {
    let corpus: [(u64, &[u8]); 3] = [
        (0, include_bytes!("vectors/regtest_coinbase_h0.block")),
        (1, include_bytes!("vectors/regtest_coinbase_h1.block")),
        (2, include_bytes!("vectors/regtest_coinbase_h2.block")),
    ];

    for (height, blob) in corpus {
        let block = Block::from_bytes(blob)
            .unwrap_or_else(|e| panic!("height {height}: Block::from_bytes failed: {e}"));

        // The gen input carries the block height.
        assert_eq!(
            block.number(),
            Some(height),
            "height {height}: coinbase gen height mismatch"
        );
        // Coinbase shape: one gen input, one tagged_key output, Null ct base.
        assert_eq!(block.miner_transaction.prefix.inputs.len(), 1);
        assert_eq!(block.miner_transaction.prefix.outputs.len(), 1);
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
