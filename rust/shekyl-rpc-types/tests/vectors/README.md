# Frozen-hex txid KAT vectors (C++ oracle provenance)

`regtest_coinbase_h{0,1}.tx` are **raw transaction blobs** whose txids are
pinned in `../txid_kat.rs`. Provenance chain:

1. The parent blocks were captured from a live `shekyld --regtest` daemon by
   `rust/shekyl-wire/tests/vectors/capture_coinbase.py` (see the README
   there), which records the daemon's own `miner_tx_hash` for each block in
   `regtest_coinbase_hashes.json` — that hash is C++
   `get_transaction_hash` output, straight from the oracle.
2. The tx blobs here are the miner transactions extracted from those blocks
   via `shekyl_wire::Block::from_bytes` and re-serialized (byte-identity of
   that round-trip is proven by `shekyl-wire/tests/coinbase_roundtrip.rs`),
   by the committed emitter
   `shekyl-wire/tests/emit_miner_tx.rs`.
3. The txids pinned in `txid_kat.rs` are copied from the daemon-captured
   JSON, **not** computed by Rust — so the KAT proves
   `shekyl-wire::Transaction::hash()` over these bytes equals the C++
   daemon's `get_transaction_hash`, which is the §3.4 txid-authority
   equivalence (`docs/design/DAEMON_SUBMIT_VERDICT.md`).

Regenerate in three steps — all three artifacts move together; none is
hand-derived:

1. `capture_coinbase.py` (rewrites the shekyl-wire `*.block` vectors and
   `regtest_coinbase_hashes.json`);
2. `cargo test -p shekyl-wire --test emit_miner_tx -- --ignored --nocapture`
   (rewrites the `*.tx` blobs here from those block vectors);
3. update the pinned hex in `txid_kat.rs` from the regenerated JSON.
