# Block/tx wire-format vectors (C++ oracle corpus)

`regtest_coinbase_h{0,1,2}.block` are **raw block blobs** captured from a live
`shekyld --regtest --fixed-difficulty 1` via the `get_block` RPC. The C++
serializer is the genesis wire-format oracle; round-trip **byte-identity**
(`Block::from_bytes` → `Block::serialize` == blob) is the spec assertion
(`../coinbase_roundtrip.rs`).

Each is a coinbase-only block: `vin = [gen]`, ct type `0` (`Null`), one output,
~1.1 KB PQC `tx_extra`. The coinbase ct base carries `enc_amounts` /
`enc_labels` / `outPk` even for `Null` (`src/fcmp/rctTypes.h:209-280`) — the
bytes the pre-fix vendored reader skipped, which this crate now consumes.

Provenance: captured on the `feat/block-wire-format` branch
(`rust/shekyl-oxide/shekyl-oxide/src/tests/vectors/capture_blocks.py`) and copied
here unchanged; the clean crate owns its own corpus. Blobs carry per-block
randomness, so a regenerated blob differs byte-for-byte from the committed one —
the round-trip invariant holds for any valid blob; these are pinned so the KAT is
deterministic without a daemon. See `docs/design/GENESIS_TX_WIRE_FORMAT.md`.
