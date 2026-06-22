# Block/tx wire-format vectors (C++ oracle corpus)

`regtest_coinbase_h{0,1,2}.block` are **raw block blobs** captured from a live
`shekyld --regtest --fixed-difficulty 1` via the `get_block` RPC. The C++ daemon
is the genesis wire-format / hashing oracle. Two assertions ride these:

- **Round-trip byte-identity** (`../coinbase_roundtrip.rs`): `Block::from_bytes` →
  `Block::serialize` == blob.
- **Hash identity** (`../coinbase_hash.rs`, §11): `Block::hash()` /
  `Transaction::hash()` == the daemon's `block_header.hash` / `miner_tx_hash`,
  pinned in `regtest_coinbase_hashes.json`.

Each is a coinbase-only block: `vin = [gen]`, ct type `0` (`Null`), one output,
~1.1 KB PQC `tx_extra`. The coinbase ct base carries `enc_amounts` /
`enc_labels` / `outPk` even for `Null` (`src/fcmp/rctTypes.h:209-280`) — the bytes
the pre-fix vendored reader skipped, which this crate consumes.

## Regenerate

```
# coinbase blobs + their consensus hashes (no wallet needed):
SHEKYLD_BIN=<build>/bin/shekyld \
GENESIS_RECIPIENTS=<shekyl-dev>/tools/genesis_builder/genesis_recipients.mainnet.json \
  python3 capture_coinbase.py
```

The FCMP++ spend byte-identity proof needs no captured blob: `../fcmp_spend_e2e.rs`
builds a real, consensus-valid spend in Rust, self-validates it against
`shekyl_fcmp::proof::verify` (the consensus rule), and round-trips it through this
crate's serializer. There is no C++ spend oracle to capture from — the C++ FCMP++
spend path never produced a daemon-accepted transaction.

Blobs carry per-block randomness, so a regenerated blob differs byte-for-byte from
the committed one — the round-trip invariant holds for any valid blob, and
`capture_coinbase.py` rewrites the `*.block` blobs and `regtest_coinbase_hashes.json`
together. `coinbase_hash.rs` loads the expected hashes from that JSON at test time, so
re-running the script needs no hand-edits. The committed blobs are pinned so the KATs
are deterministic without a daemon. See `docs/design/GENESIS_TX_WIRE_FORMAT.md`.
