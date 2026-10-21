# DRS-X PR 3b — Round 0, ruled

**Ground:** `dev` at `ba0b28379`. **Ruled by Rick, 2026-10-21.** The brief is `claude/DRS_X_PR3B_BRIEF.md`.

## The two global rulings

The twelve questions below were posed first as twelve local fixes. Rick agreed they share one cause, no composition root, and ruled the two moves that replace most of them.

### N1 — The node is built now, not at the flip

- One crate, `shekyl-node`, holds the daemon's one `Node`: the chain store, the connector and ingest service, the pool, the hasher budget, the cache store, the job board, mining control, the `Sockets` value and the stop latch.
- Rust `main` builds it at start, beside the C++ core. The store opens; nothing is routed into it from C++ before the flip, so nothing is written twice.
- `shekyl-daemon-rpc` defines the handle traits it needs (chain reads, pool, door, mining, bans, stop), each with an absent default on the `OptionsHandle` pattern. `Node` implements them. `daemon-rpc` never depends on `chain-ingest`.
- The composition root is the crate holding `main` (`shekyl-daemon`), which builds the `Node`. RT-O26's "`shekyl-daemon-image` is the root" is re-pinned to that; the image crate's shard view is handed in as a trait object.
- **Effect on the line:** PR 3b becomes handlers over a real `Node`, tested end to end in Rust; the flip becomes "route and delete."

### N2 — One template per node, read rather than built

- The node mines to one address: the `mine-address` row (`shekyl-daemon-config/src/sections/mod.rs:237`, decoded as `MineAddress`). `start_mining` takes no address; a change goes through `option_set`.
- The follower builds one template per tip under one snapshot, always reserving the coinbase's `COINBASE_NONCE_BYTES` (8) for an external miner's extra nonce, and posts it on the job board.
- `get_block_template` and `get_miner_data` return the posted job and its offsets. They build nothing.
- `generateblocks(n)` runs the built-in miner until `tip + n`, then stops. There is no second nonce search and no new budget class.
- **Why:** a remote caller can no longer learn or set which key a node mines to; no coinbase is ever built to a key the operator did not configure; one snapshot problem instead of two; a handful of wire types instead of about fifteen (RW-Q8).
- **The trade, accepted:** a solo miner cannot mine to their own address on another operator's node. That use was a leak, and a pool runs its own daemon.

## The twelve, as resolved

| # | Question | Resolution |
| --- | --- | --- |
| Q1 | Five reads die at the flip with no owner (`get_transactions`, `is_key_image_spent`, the two `.bin` methods, `get_miner_data`) | PR 3b builds the four over the node's store and pool at today's names; `get_miner_data` is a read of the posted job (N2). `rpc_facts_ffi.cpp`'s sync half (connection claims, sync spans) deletes at chain sync's cutover, named there. `/get_stem_tallies` is RD's and deletes with `levin_notify`. The three bridged console calls re-point at the flip |
| Q2 | Which fill ships at the flip | **(c):** bodies in `select`'s order while bodies plus the built coinbase stay within the effective median. Derived per template, never penalised, never oversized. The reward-aware fill replaces it under its existing pre-genesis row (`FOLLOWUPS.md:962`). A **Design** row in the register |
| Q3 | One snapshot per template | Absorbed by N2: the follower's one `ReadSnapshot`, built in `spawn_blocking`, no cache. `TemplateFacts` moves off `Writer::inspect` |
| Q4 | The draw commitment | `commit_and_discard` moves to `shekyl-archival-retention` unchanged (`OsRng`, discards); the FFI calls the moved copy until it deletes. `tx_key_secret` is `OsRng` per template. The pair-keeping producer stays SO-D12's at genesis |
| Q5 | Mining address at run time | Dissolved by N2. The address is config; the decode gains C++'s checks (ML-KEM well-formedness, spend key a point) at the config row, once |
| Q6 | A local arrival from outside the crate | One public async entry on the door: wait for the local seat, offer, await the reply. The miner's sink, `submit_block` and `generateblocks` use it |
| Q7 | `pop_blocks` stops ingest at the floor (landed defect) | Fixed in PR 3b as the first caller: bound the count before popping (genesis and the floor), as a reply, never terminal; the target computed inside the write from that batch's tip; popped bodies read before the pop and returned through the door; armed lever only |
| Q8 | The armed-lever switch | PR 3b builds it: one config row, logged at every start, the method table's armed column (RW-Q7). `generateblocks` is N2's |
| Q9 | A lone regtest node's own transactions | No opt-in (rule 71). A test that a lone node's stem entry becomes shown at embargo expiry and is mined; if not, the fix is the relay's |
| Q10 | The pool handlers | One pool, the node's (N1). `flush_txpool` gets a remove verb tagged `Flushed`. Grants see `shown()`; unrelayed and stem entries are host-only. Fields with no Rust state drop, each a register row. `relay_tx` re-offers own entries, host-only |
| Q11 | Bans | The node owns `Sockets` (N1); the handle goes through the hub while bound, which gains `lift` and `remaining`. Tor inbound stays unbannable |
| Q12 | Where the handles live | N1 |

## Not PR 3b

- New-block relay: the flip shell's, through the C++ handler, until chain sync's cutover.
- DX-Q3's stale anchors (mining `:163/:214/:234/:280`, bans `:856/:793/:824`, `stop_daemon` `:347`, RT-O26 `:1495`, the stop row `:648`): re-pinned in PR 3b's docs commit.
