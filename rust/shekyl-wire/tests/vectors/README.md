# Block/tx wire-format vectors (C++ oracle corpus)

`regtest_coinbase_h{0,1,2}.block` are **raw block blobs** captured from a live
`shekyld --regtest --fixed-difficulty 1` via the `get_block` RPC. The C++ daemon
is the genesis wire-format / hashing oracle. Two assertions ride these:

> **Corpus shape.** h0 **is** the mainnet genesis (regtest shares `GENESIS_TX`) —
> five founder outputs, deterministic, cross-anchored to `mining_parity`'s mainnet
> genesis id. h1/h2 are mined regtest blocks with a single miner output.
>
> **Mining address:** `capture_coinbase.py` mines to a local fixture address in
> `regtest_mining_recipients.json` (reproduce via `cargo test -p shekyl-wire
> --test emit_regtest_addr -- --ignored --nocapture`), **not** the genesis
> recipients in `config/genesis_recipients.*.json`. What gets mined to is a
> vector concern, not the treasury allocation. Any genesis re-pin requires
> re-capturing these vectors (and the shekyl-rpc-types §3.4 oracle txs that
> extract from them) — see `shekyl-dev/docs/GENESIS_WALKTHROUGH.md` §5.
>
> **Empty `attestation_root`:** every captured height has no pass records and must
> carry `empty_attestation_root()` (not `null_hash`). `coinbase_hash.rs` asserts this
> live against `shekyl-archival-retention`.

- **Round-trip byte-identity** (`../coinbase_roundtrip.rs`): `Block::from_bytes` →
  `Block::serialize` == blob; asserts height-dependent output counts (5 / 1 / 1).
- **Hash identity** (`../coinbase_hash.rs`, §11): `Block::hash()` /
  `Transaction::hash()` == the daemon's `block_header.hash` / `miner_tx_hash`,
  pinned in `regtest_coinbase_hashes.json`; h0 block hash must also equal the
  published mainnet genesis id.

Each is a coinbase-only block: `vin = [gen]`, ct type `0` (`Null`), tagged_key
outputs (five on h0, one on h1/h2), PQC `tx_extra`. The coinbase ct base carries
`enc_amounts` / `enc_labels` / `outPk` even for `Null`
(`src/fcmp/rctTypes.h:209-280`) — the bytes the pre-fix vendored reader skipped,
which this crate consumes.

## Regenerate

```sh
# coinbase blobs + their consensus hashes (no wallet needed); defaults to the
# committed regtest_mining_recipients.json address:
SHEKYLD_BIN=<build>/bin/shekyld python3 capture_coinbase.py
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
