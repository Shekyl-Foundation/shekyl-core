# CT-2 reconstruct-root KAT fixtures

`ct2_tier_a.json` is the hermetic oracle for the CT-2 Tier-A
reconstruct-root KAT (`../recon_kat.rs`): it pins the wallet's
block-derived `build_layers` root to the C++ consensus header
`curve_tree_root` at every height. See `docs/design/CT2_DRAIN_ORDER.md`
§8.2 for the chain shape and §5 for the small-tree root convention.

## What the fixture contains

A `chains` array; each chain is a list of blocks carrying:

- `height`
- `curve_tree_root` — the consensus header root (the value the wallet
  must reproduce; cross-checked against the `get_curve_tree_root` RPC at
  generation time).
- `miner_tx.pqc_leaf_hashes` — the coinbase `tx_extra` `0x07` blob
  (concatenated per-output `h_pqc`), hex. Only the `0x07` payload is
  recorded, not the whole `tx_extra`.
- `miner_tx.outputs[]` — per output: `output_key` (`O`), `commitment`
  (`C`, present for the `RCTTypeNull` coinbase), and `target` kind.

Three chains exercise S1/S2/S3 (`CT2_DRAIN_ORDER.md` §8):

- `main` — empty window (0..=60), founder drain at 61, a level-0 subtree
  frozen and into level-1 (one coinbase leaf per block to height 210).
- `reorg_deep` — pop 70 (≥ `COINBASE_LOCK`+1): the trim branch (§6),
  re-mined leaves drain past the freeze-lag.
- `reorg_shallow` — pop 5 (< `COINBASE_LOCK`+1): the pending-only
  no-mutation branch (§6).

## Regenerating

The fixture is checked in; CI replays it offline and never runs the
generator. Regenerate only when the consensus leaf or root rules change.

```sh
# from this directory, with a release shekyld built under build/bin/
python3 gen_ct2_fixture.py \
    --daemon ../../../../build/bin/shekyld \
    --out ct2_tier_a.json
```

The generator drives a fresh, throwaway regtest daemon (its own temp
datadir and port), mines the three chains, and records each block from
the daemon's structured block JSON.

### Why daemon JSON rather than a Rust block decode

Shekyl's coinbase serializes a real `outPk` under `RCTTypeNull`
(`rctTypes.h::serialize_rctsig_base`). The old `shekyl-oxide` coinbase model
(`proofs: None`) did not parse this; that crate is now dissolved and `shekyl-wire`
parses the coinbase `Null` committed base correctly (un-vendor slice 1). The fixtures
still source leaf inputs from the daemon's block JSON because it is the authoritative
C++ oracle (it serializes `outPk`/vout/`extra` correctly), not because nothing in Rust
can decode the block.
