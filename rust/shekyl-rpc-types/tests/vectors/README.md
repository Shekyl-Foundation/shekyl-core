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
   that round-trip is proven by `shekyl-wire/tests/coinbase_roundtrip.rs`).
3. The txids pinned in `txid_kat.rs` are copied from the daemon-captured
   JSON, **not** computed by Rust — so the KAT proves
   `shekyl-wire::Transaction::hash()` over these bytes equals the C++
   daemon's `get_transaction_hash`, which is the §3.4 txid-authority
   equivalence (`docs/design/DAEMON_SUBMIT_VERDICT.md`).

Regenerate by re-running `capture_coinbase.py` (which rewrites the
shekyl-wire vectors), re-extracting the miner txs, and updating the pinned
hex in `txid_kat.rs` from the regenerated JSON. All three move together;
none is hand-derived.
