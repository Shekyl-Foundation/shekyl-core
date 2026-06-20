# Block/tx wire-format vectors (C++ oracle corpus)

`regtest_coinbase_h{0,1,2}.block` are **raw block blobs** captured from a live
`shekyld --regtest --fixed-difficulty 1` via the `get_block` RPC. The C++
serializer is the genesis wire-format oracle (`consensus-port-gates-genesis`);
round-trip **byte-identity** (`Block::read` → `Block::serialize` == blob) is the
spec assertion. See `docs/design/CONSENSUS_PORT_SEQUENCE.md` (Stage 1d) and
`docs/design/TRACK2_REGTEST_PARITY.md`.

Each is a coinbase-only block: `vin = [gen]`, `rct_signatures.type == 0`
(`RCTTypeNull`), one output, ~1.1 KB PQC `tx_extra`. The coinbase rct base
carries `enc_amounts`/`enc_labels`/`outPk` even for `RCTTypeNull`
(`src/fcmp/rctTypes.h:209-280`).

## Regenerate

```
python3 capture_blocks.py            # writes regtest_coinbase_h{0,1,2}.block
```

Requires a built `shekyld` (`SHEKYLD_BIN`, default `build/bin/shekyld`) and the
genesis treasury address at
`shekyl-dev/tools/genesis_builder/genesis_recipients.mainnet.json` (regtest
accepts it for `generateblocks`). Blobs carry per-block randomness (one-time
keys, encrypted amounts), so a regenerated blob differs byte-for-byte from the
committed one — that is expected; the round-trip invariant holds for any valid
blob. The committed blobs are pinned so the KAT is deterministic without a
daemon.
