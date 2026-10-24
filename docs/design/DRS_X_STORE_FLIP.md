# DRS-X — the store-of-record flip: Round 0, ruled (`DX-`)

**Families (registered in `IMPLEMENTATION_INDEX.md` §2, rule 94):** **`DX-Q`** (questions, ruled here) and **`DX-F`** (findings). `X-` is taken by the exit-standoff family; `DX-Q` and `DX-F` are free at `d2ac8b45d`.
**Ground:** `dev` at `d2ac8b45d` (2026-10-16); #1088 (Rust `main()`) at its PR head. Counts re-measured at the landing pin, `d2ac8b45d`: two line spans corrected in place (DX-F1's cache block, DX-F6's `RelayState`); every other count and pin held.
**Status:** OPEN — Round 0 RULED, Rick 2026-10-16: DX-Q1…DX-Q9 accepted as recommended, and DX-Q8 amended (§3). DX-Q5's relay seam was grounded the same day (§2, DX-F6). DX-Q10, the fee floor's move at the flip, was ruled with FL PR-C (#1096, 2026-10-16) and is carried here by name. DX-Q3 is amended by PR 3b's Round 0 (N1, N2 and Q1–Q13, ruled by Rick 2026-10-21/22; DX-Q3's amendments below). Implementation proceeds in the order of §4.
**Parent:** `DAEMON_REDB_STORE.md`. This document replaces the plan's one-line DRS-X and DRS-B rows and amends R2 (2026-10-15) where §1 says.

---

## 0. Purpose

**After the flip,** every block the daemon receives is formed, validated and connected by Rust into redb:
- one writer;
- one validator;
- one store;
- no LMDB linked into `shekyld`.

The C++ that has no Rust owner yet — the protocol handler and `levin_notify` — keeps running behind a thin, short-lived shell. Its owners delete it: chain sync and RD.

**Equivalent functionality, not parity (Rick, 2026-10-16).** The C++ is a rough guide. The flip delivers Shekyl's design as implemented, and every difference from the C++ is categorized, never adjudicated toward the C++ (§3).

---

## 1. Rulings

### DX-Q1 — The shim sits at the consumer, not at the store (amends R2's "behind `BlockchainDB`")

**The finding behind it (DX-F1).** `Blockchain` (6,725 lines) is a validator and writer with caches filled by its own `add_new_block` (`blockchain.h:1081–1106`). A redb `BlockchainDB` under it would leave:
- stale caches;
- `check_tx_inputs` and `create_block_template` running beside the Rust validator, which is two validators (rule 19).

**Ruled.**
- `Blockchain`, `BlockchainDB`, `BlockchainLMDB` and `tx_memory_pool` delete at the flip.
- The shim (DEL-002) is a thin C++ `core` shell, one method per call its remaining consumers make, each forwarding to Rust:
  - the protocol handler's chain reads, its block arrivals and its pool calls;
  - `levin_notify`'s `i_core_events`, five methods (§2).
- **Composite questions are one Rust call over one `ReadSnapshot`:**
  - `find_blockchain_supplement`;
  - `handle_get_objects`;
  - the short chain history;
  - the sync payload.

  A sync decision never reads two tips.
- **Falsifier:** after the flip, `rg -n -e 'class Blockchain\b' -e 'class BlockchainDB' -e 'tx_memory_pool' src/` → 0.

### DX-Q2 — The arrival contract

*Amended by PR 2's rulings (PR2-Q1…PR2-Q6, design review 2026-10-18) and CS-Q5 (c) (Rick, 2026-10-18). Built in PR 2 (#1123): `shekyl-chain-ingest`'s `service.rs`, `router.rs`, `admission.rs`, `follower.rs`, and `shekyl-ffi`'s `ingest_ffi.rs`.*

1. **The router (Rust)** places every arrival by its parent, on a `ReadSnapshot` at acceptance:
   - the recorded tip → the pipeline (`Extend`), also for a block the alt table holds: its connect takes it out of the alt table;
   - a recorded or alt block → `OfferAlt` and the switch (#1082);
   - unknown → `Unlinked { at }`, with nothing stored;
   - already held → `AlreadyHeld`.

   **There is no orphan store.** A peer cannot make the node hold a block it cannot place.
   - **The router is not the writer.** The tip can move between a placement and its connect. The seed (CEN-D3), target (CEN-D4) and reference claims are compared by equality in `validate`, so a stale placement comes back as `Stale` or as the connector's `HeightClaim` and is placed again against a new snapshot, never a verdict. An `Extend` whose parent stopped being the tip is placed again as `OfferAlt`.
   - **A block id is in at most one of the main chain and the alt table**, and the store holds it: every connect removes a same-id alt row in its own write, and AL1 refuses a recorded hash (`store/alt.rs`).
   - CEN-A1 and CEN-A4 are held by the router: `held_by_store("shekyl-chain-ingest", …)`, since the router is a crate the validator does not import. The registry cites no C++ test for either.
   - **CEN-A5** is bucket 3: it was the parse-cost bound, not validity, which G6b judges. Its bound is the router's admission, size before parse (PR2-Q2).
   - **A cache is derived only for a seed the chain has earned** (the review of #1123, B1 and B2, Rick 2026-10-19; `cache_window.rs`). Before any permit, cache or hash, `cache_window::spend` judges the fork and where its seed lies. Below a reached checkpoint, or past the cap on an anchored chain, is CEN-E2's verdict. Past the cap on an unanchored chain is the door's `BeyondCap` hint. Inside the cap, a seed **below the fork** is one of the window's two slots, read on the claim's own snapshot; a miss there is this node's defect (`SeedNotInWindow`), never a reply. A seed **above the fork** is the branch's own block: a stored alt row whose proof of work passed, which no block names until 65 or more of its branch's blocks are stored. It is prepared into the transient slot under the arrival's permit (`Substrate::prepare_seed`) and never pinned, and the form hashes with the cache the preparation returned (`longhash_held`), so an eviction in between does not fail it. One branch-seed form runs at a time: the branch gate, then the permit, then the pin lock around the derive alone. The live caches are therefore the canonical, the transient, and at most one evicted cache a form still holds. A switch whose promoted run names its branch's seed prepares it the same way. Two branches alternating cost one derivation per alternation, under the arrival's class, and each costs its sender a fresh block with real proof of work on a branch already past its seed point. Only the main chain (an extending run's seeds, the window installed on each tip) and the miner's next block move the canonical slot. `longhash` looks a cache up and never derives: a miss on a below-fork seed reinstalls the window and places the arrival again, and a miss after a preparation is a fault. The window reaches the cap below the connecting height and `max(cap, 65)` above it, which fits in one seed epoch: a compile-time assertion holds `D_MAX` to it, and `FakechainSchedule::new` holds a lever's cap to it (`ReorgCapOutrunsSeedEpoch`, at most 1023).
2. **One FFI entry, used by the protocol handler only** (`shekyl_ingest_offer_span`). `submit_block` and the miner's found-block sink enter the service's door natively (DX-Q3, DX-Q4).
   - The entry takes a span and returns at once. Every accepted arrival gets exactly one reply, tagged with the arrival, posted to the connection's strand.
   - **Refused before acceptance:** `NoRoom`, `Throttled`, `Oversize`. Never a peer fault; nothing is kept.
   - **Replies after acceptance:** `Connected`, `Refused(InvalidBlock)`, `Unlinked { at }`, `AlreadyHeld`, `Held`, `BeyondCap` (the door's hint: nothing stored or hashed), the switch outcomes (`Switched`, `PromotionRefused`), `CannotFollow` (`BeyondCap` or `BelowFloor`: a stored heavier chain this node cannot follow, item 8), `MissingBodies { indices }`, `Cancelled { by }`, `Stopped`. At the FFI each has a kind of its own, pinned against `shekyl_ffi.h` by an exhaustive test.
   - An unbind (`shekyl_ingest_bind` with a null post) posts every reply already accepted before it returns. On a thread of the replies' own runtime it cannot wait, so it is refused as `SHEKYL_INGEST_REENTRANT` and changes nothing.
   - Built and tested in PR 2; the flip routes the handler's arrivals to it. Chain sync and RD delete it with the handler.
3. **Capacity (chain sync's Round 0 requirement, ruled 2026-10, carried here; PR2-Q5).**
   - The entry reports room. A caller asks before sending.
   - **While the service runs, an accepted arrival is never dropped.** A span offered without room is `NoRoom`, before acceptance, and is never a peer fault.
   - **The seats** (the review of #1123; `room.rs`). One seat of the window is reserved for a block this node mined. Unsolicited announcements hold at most half of the rest. Local arrivals (the miner's, and `submit_block`'s from PR 3b) share that cap with them, plus the reserve. At 32 seats, sync keeps 15 or more whatever peers announce and the RPC submits. A block the miner finds when the local seats are full waits for one, and one that does not join the chain is logged.
   - **A stop or a fault closes the door**, so a caller asking for room reads none.
   - **At a stop** (`TOR_SUPERVISOR.md` §1; DX-Q6), the connector finishes its current message and the store closes; every accepted arrival not yet connected replies `Stopped`. Never a peer fault: sync asks again after the restart.
   - Until the chain-sync cutover the C++ handler's span scheduler asks once per span.
4. **Session close.** `Refused(InvalidBlock)` is the only outcome that closes the serving session (PWD-B7); nothing scores. Automated per-host scoring and bans are deleted (CS-Q5 (c), Rick 2026-10-18): `add_host_fail`, `hit_score` and `shekyl-peer-policy`'s `heavier_score` arm. Bans are operator configuration only (`set_bans` over the transport `BanList`). `Unlinked`, `NoRoom`, `BeyondCap`, `CannotFollow` and stale outcomes never punish (C2-R1 Q1c F-1(a)). `Throttled` lets the handler close a session that keeps announcing past its bucket: a close, never a score.
5. **`TipChanged`, one source.**
   - The connector publishes the tip on a `watch` after every committed connect, pop and switch, and once at start; never before the commit. It carries the dialer's `SyncPayload` fields (the block count, the cumulative difficulty, the top id) and a sequence number. `shekyl_core_publish_tip`'s producer (`blockchain.cpp:5895`) moves to that publication at the flip.
   - **Consumers:**
     - the handshake (the dialer and slice 4);
     - new-block relay;
     - the sync owner;
     - the RPC;
     - **the pool**, reconciled per publication (the service's tip follower);
     - **the miner's template producer**, in the same follower, after the pool. The follower first installs the cache window for the new tip under a chain permit, which pins `seed(tip + 1)` canonical. The producer posts a job only under a seed the window holds, before `JobBoard::publish`, and withdraws the board while the node is behind. A closed sync channel reads as behind. It builds the node's one template itself, on one snapshot, and `get_block_template` reads the posted job (DX-Q3, N2).
   - **The follower's death is the service's fault** (`FollowerEnded`): the service stops, the door closes and the miner's job is withdrawn, so no miner hashes a stale job.
6. **One RandomX budget** (PR2-Q3; `shekyl-hash-budget`). `available_parallelism` permits, read at run time (rule 76), granted by class, highest first: forming on the chain or a solicited span; chain sync's header PoW; unsolicited arrivals; `calc_pow`; chain sync's evidence check; the miner. **The miner never holds a permit a higher class waits for, and never takes the last free one:** it takes one per hash, only while another stays free. On a one-permit budget it would never hash, so `Miner::start` refuses that budget (`MinerStartRefused::OnePermit`). Nice 19 stays, but priority is by permit. A grant that leaves a permit free wakes the waiters, and a wake takes the budget lock, so a stop is never lost. A cache is built only for a seed the chain has earned, under a permit: a pin, or a branch seed's preparation (item 1). `calc_pow` and the miner look up only. **The sixth class, `Class::Evidence`** (Rick, 2026-10-19; chain sync Round 0, CS-Q2 step 3), sits between `calc_pow` and the miner for chain sync's proof-of-work check on a branch forking deeper than `D_max` (the `Diverged` alarm's evidence). It sits above the miner because `grantable` refuses any class while a higher one waits, and miner workers wait whenever fewer than two permits are free, so a class below the miner would never run on a mining node. Its check builds the fork seed's cache outside the cache store's two slots: one check at a time, held only while it runs, never canonical and never pinned, so it never evicts the window's pair or an in-cap branch's seed, and B2's bound stands. It is built with its first caller, chain sync's executor (CS-3, `shekyl_chain_sync_runtime::executor`), and needs one free permit.
7. **Deleted at the flip:** `prepare_handle_incoming_blocks` / `cleanup_handle_incoming_blocks` (Monero's batch preprocessing) and `try_add_next_blocks`' connect loop. The `Form` workers replace them. With them goes the last path that derives a RandomX cache on a miss: `shekyl_pow_randomx_v2_hash` (`pow_randomx_ffi.rs:227`), reached only through `hash_pow_randomx` from `get_block_longhash` (`Blockchain`, the C++ miner, `core_rpc_server`, `rpc_facts_ffi.cpp`), all of which the flip deletes.
8. **`following_degraded` is a Rust latch** (chain sync Round 0, §A coupling 4, Rick 2026-10-18).
   - The flip deletes `Blockchain` (DEL-010), which holds `m_following_degraded` (`blockchain.h:1071`) and sets it when a switch is refused at the prune watermark (`blockchain.cpp:2288`).
   - The field is landed RPC (`get_info.health.following_degraded`, `CORE_RPC_VERSION` 3.26). The wallet's stake engine acts on it as `NotFollowing::Degraded` (`stake_engine/serving/daemon_tip.rs:277`).
   - **What sets it** (design review, 2026-10-19, (a)): every outcome that proves a heavier chain this node refused. These are the store's `Offered::BeyondCap` (`switch.rs:510`), the switch's `Switched::BeyondCap` (`:722`) and `Switched::BelowFloor` (`:867`). It is set in the connector, where they are produced, never from a reply. **One latch, one writer** (Rick, 2026-10-19; chain sync Round 0, CS-Q2 step 3, §A item 7): from the chain-sync cutover the sync owner sets it through the connector. It sends one message carrying its evidence, the fork point and the verified run's tip and work, and the connector writes the latch in its own transaction, as it does for the three outcomes above. The sync owner holds no second flag. The message is the connector's `RaiseAlarm`, and the owner reads the latch back through `WatchLatch` (CS-3). The owner sends it once the chain-sync cutover routes live sessions to it. The RPC reads it in Rust (`info_facts.rs:88`; `store_facts.rs:576` takes it from the sync facts).
   - **The reply split** ((b), built in PR 2): those three outcomes are one reply, `CannotFollow { BeyondCap | BelowFloor }`. The door's past-cap answer stays `BeyondCap`: nothing stored or hashed, earned by one block nobody worked for, so it never sets the latch. It is a hint for sync to ask for headers. The two are different variants and different FFI kinds (13 and 6).
   - **Where it lives** ((c)): in the chain store, cleared only by a resync. The door refuses later past-cap blocks before hashing them, so unlike the C++ latch it would not be set again after a restart, and the death rule retires the evidence. The cell is `following_degraded` (`FollowingDegradedCell`, engine-local, `SCHEMA_VERSION` 32): the fork point, the heavier tip and its work, written once (CS-3). The flip wires ingest's three outcomes to it. `PopBeyondReorgCap` carries the depth and the cap, not the fork, tip and work the cell records, so each outcome must carry them first.
   - It means a heavier chain this node refused at either cap, the undo floor or `D_max`, and it is one-way until a resync (C2-R1b F-1(a)).
   - **The gap that remains** ((d)): a chain that becomes heavier only after its fork is past the cap is invisible to ingest. Its blocks are refused at the door before they are stored, so no outcome above can see it. Chain sync's `Diverged` alarm covers it from that lane's cutover (#1117).

**The door and the pool after the review of #1123** (Rick, 2026-10-19):
- **A pool-file fault retires the pool; block ingest goes on.** The file is discardable (`SPL-Q8`), but a file this process cannot read is refused at open, never deleted, so the remedy is a restart. The retirement is logged as an error, and `Service::pool_retired` reports it for PR 3b's `get_info` and `mining_status`. A chain fault in a pool step still stops the service.
- **Pool verification runs outside the pool lock.** A carried body's step 1 is computed before the lock. Before each reconcile the follower lists, under the lock, the entries with no pass and the passes the new tip no longer supports (`Pool::needing_step1`), and verifies them outside it. The reconcile verifies under the lock only when the tip moves again between the two. **PR 3b's obligation:** `send_raw_transaction` admits through `Pool::admit_judged`, with a pass computed before the lock.

**PR 2's admission and pool rulings** (design review, 2026-10-18):
- **PR2-Q2 — what an arrival costs, and who pays.** A light-mode hash costs about 1.25 s per core on the floor device, and a junk block costs its sender nothing. So: size before parse (the header bound plus twice the ceiling limit `2·S·LTEM`, which no valid block's arrival exceeds at any height a span reaches); unsolicited announcements take a token from a per-session bucket (two per target interval, at most two); solicited spans take none; the first `Refused(InvalidBlock)` in a span cancels its siblings, and no hash starts after it; there is no memory of invalid block ids.
- **PR2-Q4 — compact blocks do not reveal stem possession.** A compact block's bodies are resolved from the entries the pool shows, and only those. A stem entry counts as missing and is asked for (`MissingBodies`).

### DX-Q3 — The C++ RPC server moves to Rust in the flip, whole

The join rule: no FFI built for a C++ handler that dies a PR later. Every method the C++ server answers is moved to Rust, deleted, or another lane's below; none stays in C++ (ruled by Rick, 2026-10-17, retiring the daemon RPC KV lane).

- **Moved to Rust:**
  - **RK-6 (pool)** over the Rust pool.
  - **RK-7 (mining):**
    - `get_block_template` and `get_miner_data`: reads of the node's one posted template (N2);
    - `submit_block` through the local-arrival entry (Q6); `generateblocks` runs the built-in miner (N2);
    - `calc_pow`.
  - **Alt chains and alt hashes** over the alt reads.
  - **`pop_blocks`** as a connector `PopBlocks` message, an armed test lever (Q7, Q8): refused at the undo floor before any pop, its bodies returned to the pool. A live source never emits `Rewind`.
  - **`get_coinbase_tx_sum`.**
  - **RK-9:** curve-tree info and checkpoint, archival claim source, shard coverage.
  - **Mining control:** `start_mining`, `stop_mining` and `mining_status`, over the Rust miner loop (DX-Q4). `set_log_hash_rate` deletes: the hash rate is part of mine status (`INPUT_GRAMMAR.md:640`, §13). The C++ handlers are `core_rpc_server.cpp:163`, `:214`, `:234` and `:280`.
  - **Bans:** `set_bans`, `get_bans` and `banned` (`core_rpc_server.cpp:856`, `:793`, `:824`), over the transport layer's ban list (`rust/shekyl-transport-layer/src/ban.rs:151`, held in the socket table, `admission.rs:270`). They reach it through a handle the composition root supplies, in RT-O26's shape (`RPC_CHANNEL.md:1579`, §6.4). No FFI. The C++ forwarders through `m_p2p` delete.
    - **The one ban path** (Q11): the bans handle bans through `shekyl-ffi`'s `BanPath`, through the hub while one is bound (it closes the sockets a new ban drops) and otherwise on the node's socket table, which the daemon installs as the process table. The hub carries every verb, `lift` and `remaining` included; the `shekyl_ban_*` exports go the same way. Tor inbound has no address to ban.
  - **`stop_daemon`** (`core_rpc_server.cpp:347`) is one more trigger of the one stop path (`TOR_SUPERVISOR.md:60`, §1, ruled 2026-10-14; the stop-trigger row at `:735`). The handler asks Rust `main` to stop; it stops nothing itself.
- **`FfiChainFacts` / `FfiInfoFacts`** are replaced by store-backed implementors (RK-D7's planned second implementation). `rpc_facts_ffi.cpp` deletes.
- **Deleted:** `save_bc` and `flush_cache` (durability is `Immediate`; there is no cache), and `inject_archival_serve_credit` (with DEL-008).
- **Not this lane:** log, limits and peers (#1088's `option_set` / `option_show`).
- **The C++ RPC server is gone whole:** every handler, request and response struct, dispatch table and error-code header, plus the facts and submit FFIs (`rpc_facts_ffi.cpp`, `daemon_submit_ffi.cpp`, `core_rpc_ffi.cpp`). The flip PR lists every file this empties, at its pin. At `b6bdadc3c` the falsifier's patterns match 28 files under `src/`, mixed headers such as `src/shekyl/shekyl_ffi.h` among them.
- **The interim C++ console:** the console commands that read `COMMAND_RPC_*` structs delete with those structs. At #1088's head (`30a27570b`) they are nineteen words over eighteen executor methods (`src/daemon/rpc_command_executor.cpp:167`–`:963`; the words at `src/daemon/command_server.cpp:116`–`:257`): `bans`, `ban`, `unban`, `banned`, `flush_txpool`, `print_coinbase_tx_sum`, `print_pool`, `print_pool_sh`, `mining_status`, `pop_blocks`, `relay_tx`, `save`, `show_hr`, `hide_hr`, `start_mining`, `stop_mining`, `stop_daemon`, `exit` and `flush_cache`. `stop_daemon` and `exit` share one method. They are not ported into the Rust console. Their successors are `shekyl-cli`'s words (`INPUT_GRAMMAR.md` §13, `:617`), built by the R8 slice. Three have none: `pop_blocks` is an armed test lever (IG-Q25, `INPUT_GRAMMAR.md:691`), and `save` and `flush_cache` name LMDB and C++ cache internals.
- **Falsifier:** after the flip, `rg -n -e 'COMMAND_RPC_' -e 'core_rpc_server' src/` returns nothing.

#### DX-Q3's amendments: PR 3b's Round 0 (ruled by Rick, 2026-10-21; Q13 on 2026-10-22)

PR 3b's questions share one cause, no composition root. Two global rulings answer most of them.

**N1 — the node is built now, not at the flip.** One crate, `shekyl-node`, holds the daemon's one `Node`: the chain store, the connector and ingest service, the pool, the hasher budget, the cache store, the job board, mining control, the `Sockets` value and the stop latch. Rust `main` builds it at start, beside the C++ core; the store opens, and nothing is routed into it from C++ before the flip. `shekyl-daemon-rpc` defines the handle traits it needs, each with an absent default that answers not ready; `Node` implements them, and `daemon-rpc` never depends on `chain-ingest`. The composition root is the crate holding `main` (`shekyl-daemon`); RT-O26's "`shekyl-daemon-image` is the root" is re-pinned to it. PR 3b is handlers over a real `Node`, tested end to end in Rust; the flip is "route and delete".

**N2 — one template per node, read rather than built.** The node mines to one address, the `mine-address` row; `start_mining` takes no address. The tip follower builds one template per tip on one snapshot, always reserving the coinbase's eight extra-nonce bytes, and posts it on the job board. `get_block_template` and `get_miner_data` return the posted job and its blob offsets; they build nothing. `generateblocks(n)` runs the built-in miner until the tip is `n` higher. A remote caller can no longer learn or set which key a node mines to, and no coinbase is built to a key the operator did not configure. The trade, accepted: a solo miner cannot mine to their own address on another operator's node; a pool runs its own daemon. The row is read at start: it becomes changeable while the node runs only when the grammar round marks it a runtime row (IG-12), and until then a change is a restart. `mining_status` reports the row.

| # | Question | Resolution |
| --- | --- | --- |
| Q1 | Reads that die at the flip with no owner | PR 3b builds `is_key_image_spent`, `get_blocks_by_height.bin`, `get_o_indexes.bin` and `get_transactions` over the store and the pool at today's names; `get_miner_data` reads the posted job (N2). `get_transactions` is the wallet's block fetch and proofs read (`block_fetch.rs`, `proofs_chain_facts.rs`): its `as_json` is absent, and `decode_as_json` is refused as bad parameters, epee's rendering retiring with RK-W (RW-Q4, IG-Q55; the review of #1165). `rpc_facts_ffi.cpp`'s sync half deletes at chain sync's cutover; `/get_stem_tallies` is RD's and deletes with `levin_notify`. The console's three bridged calls re-point at the flip |
| Q2 | Which fill ships at the flip | `shekyl_block_template::Fill` (#1152), the reward-aware fill, priced at the built coinbase's weight; candidates come in `select`'s order (the brief of 2026-10-23) |
| Q3 | One snapshot per template | The follower's one `ReadSnapshot`, in `spawn_blocking`, no cache: the chain facts, the seed and target, the next seed and the pool's selection. `TemplateFacts` moved off `Writer::inspect` |
| Q4 | The draw commitment | `commit_and_discard` lives in `shekyl-archival-retention` (OS random, nothing kept); the FFI calls it. `tx_key_secret` is OS random per template. The pair-keeping producer stays SO-D12's, at genesis |
| Q5 | The mining address | Config: the row's decode makes the C++ checks once (the spend key a point, the view key to X25519, the ML-KEM key well-formed) |
| Q6 | A local arrival from outside the crate | One public async entry on the door (`Door::offer_local`): wait for the local seat, offer, await the reply. The miner's sink, `submit_block`, `generateblocks` and genesis use it |
| Q7 | `pop_blocks` at the undo floor | Bounded before any pop as a reply, never terminal; the target computed on a read snapshot and the tip it was computed from re-checked inside the write, which under the one writer is the target computed in the write; the popped bodies read before the pop and returned through the pool's door; an armed lever only |
| Q8 | The armed-lever switch | The `dev-rpc` row, announced at every start; the method table's `armed` column (`generateblocks`, `pop_blocks`, and `inject_archival_serve_credit` per RT-O9.2); refused outside the grant while off. Until the flip routes the handlers, the refusal is the `Armed` token each armed handler takes, which only the switch's check makes; dispatch reads the column once it routes them. Today's C++ path is not gated: it is the path the flip deletes |
| Q9 | A lone regtest node's own transactions | No opt-in (rule 71). Once the relay marks the entry shown, the next template lists it; the embargo driver is RD's |
| Q10 | The pool handlers | One pool, the node's. `flush_txpool` removes, tagged `Flushed`. Any caller sees `shown()`; stem entries are the host's. Fields with no Rust state are not on the wire (register rows). `relay_tx` re-offers own entries, host only |
| Q11 | Bans | The node owns `Sockets`; the handle goes through the hub while bound, which gains `lift` and `remaining`. Tor inbound stays unbannable |
| Q12 | Where the handles live | N1 |
| Q13 | The sync watch | The node owns one `watch::Sender<shekyl_chain_sync::SyncState>`, chain sync's own type: `Synced` once genesis connects on regtest, `NoView` elsewhere until chain sync's cutover publishes. The follower posts only on `Synced`, and `mining_status` names the reason while no job is posted. No interim |

### DX-Q4 — The miner loop is Rust

- The local miner becomes a Rust loop over `shekyl-pow-randomx`, the pure-Rust light-cache hasher that already serves production PoW, for verification **and** for the built-in miner: `miner.cpp` hashes each nonce through its `get_block_hash` callback → `get_block_longhash` → `hash_pow_randomx` → `shekyl_pow_randomx_v2_hash` (`src/crypto/pow_randomx.cpp`; `src/cryptonote_core/cryptonote_tx_utils.cpp:242`, `:264`).
- `randomx-v2-sys` does not change. The C reference library is not configured into `shekyld`: it is built only for the differential harness and the miner KATs (`CMakeLists.txt:517–525`).
- A fast miner is an external miner's job, over `get_block_template` / `submit_block`. The built-in miner is a testnet convenience.
- `miner.cpp` (1,107 lines) deletes.

### DX-Q5 — The pool goes live at the flip

- PR-b builds the Rust pool against the store, staged and scenario-tested. It cannot be live before the flip: its door needs the live store.
- **At the flip:**
  - p2p `handle_incoming_tx` → the shell → the Rust pool door;
  - the submit engine's `FfiSubmitShim` is swapped for the Rust pool (DEL-010, the planned reversion);
  - `daemon_submit_ffi.cpp` deletes.
- **The relay seam** is §2.

### DX-Q6 — Where the store opens; genesis; stop

- Rust `main` (`shekyl-daemon`) builds `shekyl-node`'s `Node` after the network marker (#1088 step 4) and before `run(snapshot)` (step 7). The node opens `ChainStore::with_release`, starts the ingest service, and is where the store opens (N1, DX-Q3's amendments). Nothing is routed from C++. The flip still hands the remnant the shell's handle.
- **Genesis.** An empty store connects the pinned genesis through the ingest (`form` → `validate` → `connect`, CEN-E5's pin). `reset_and_set_genesis_block` deletes.
- **Stop.** `Node::stop` is one step of the daemon's `finish`, after the dialer and the RPC and before the managed Tor teardown (`TOR_SUPERVISOR.md` §1): the service stops, the follower withdraws the job board, the connector finishes its current message, and the store closes. `Immediate` durability means there is no flush step.
- **No migration.** A release wipes, and an LMDB directory is ignored. A chain file whose `schema_version` is not this binary's is removed and a fresh store opened, logged with both versions. A corrupt file, an invariant, or an I/O error still refuses: a wipe is for a version the binary does not speak. A pool file this process cannot read stays refused and kept (`SPL-Q8`, the ruling at the pool-file bullet above).

### DX-Q7 — The PR shape

The splinter rule: a mechanism is deleted whole, in one PR. The join rule: no FFI built only to be deleted later.

| # | PR | Live? |
| --- | --- | --- |
| 1 | **PR-b**: the Rust pool (`DRS_E5_POOL_ALT_PRUNE.md` §5 b1–b7, as amended in its brief) | staged; merged 2026-10-18 (#1102) |
| 2 | **Router, arrival entry, `TipChanged`, the shared hasher budget**; the scenario driver is the source in tests | staged; merged 2026-10-20 (#1123) |
| 3 | **The read-only RPC handlers and the store-backed facts (DX-Q3), and the miner loop (DX-Q4)**, unrouted | staged; merged 2026-10-19 (#1106) |
| 3n | **`shekyl-node`**, the daemon's one `Node` (N1): the store, ingest, the pool, the hasher budget, the cache store, the job board and the socket table. Built at start beside the C++ core; genesis through the door; nothing routed | staged; merged (#1147) |
| 3b | **The node's one template (N2) and the methods that read it; mining control; `submit_block`, `generateblocks` and `pop_blocks`; the pool's handlers; the bans and `stop_daemon`; three Q1 reads** (DX-Q3), unrouted | staged (#1165) |
| 4 | **The flip** (below) | live |

**The flip PR:**
- routes every arrival and every handler;
- opens the store in `main`;
- builds the shell;
- deletes:
  - LMDB and `BlockchainDB`;
  - `Blockchain` and `tx_memory_pool` (DEL-010);
  - the archival C++ path (DEL-008). Its gate holds at genesis (Rick, 2026-10-18). Until genesis, testnet archival runs on the Rust path as it stands, carriers included, so passes land on live code;
  - the reorg path (DEL-009);
  - `rpc_facts_ffi.cpp`, `daemon_submit_ffi.cpp` and `miner.cpp`;
  - the C++ RPC server whole (DX-Q3's falsifier), with the interim console's commands that read its structs;
  - the LMDB utilities (FOLLOWUPS, IG-Q26);
  - the C++ fee floor and its FFI (DX-Q10);
  - liblmdb from `shekyld` (DEL-004);
- deletes every LMDB-bound C++ test, each with a sentence naming the rule it tested and where Rust covers it now;
- applies the `DAEMON_REDB_STORE.md` §12.1 gate retirements;
- arms the `dev-rpc` row in the daemon config of every regtest harness that calls `generateblocks` or `pop_blocks` — the engine-core e2e runs, GF-7, the bench scripts and the Python framework — before dispatch reads the `armed` column (the review of #1165, ruling 1);
- hands the submit engine's shim (`RustPoolShim`) the service's `PoolHealth`, so a pool-file fault met on the submit path retires the pool as one met by the service, the pool handle or the chain handle does (the review of #1165, M5);
- runs the RPC on a runtime of its own, never the node's: `pop_blocks` returns its bodies through `offer_carried`, which verifies each body's stateless half on the caller's runtime without a hasher permit (`span.rs`), bounded by the operator only because the lever is armed and the host's;
- restates the two decisions `RPC_WIRE.md` carries that are bound to state the flip ends: RK-D7 (one implementation, `StoreFacts`, once the shims are deleted) and the per-lock-domain rule (over the Rust pool's lock and the store's MVCC snapshot, where today its example is `tx_memory_pool::check_for_key_images`).

PR-b, PR 2 and PR 3 may run in parallel; PR 3n is the node (#1147), and PR 3b builds on it (#1165). The flip needs PR-b, PR 2, PR 3, PR 3n, PR 3b and #1088.

### DX-Q9 — CEN-L14's remaining sites

After SO-D12's deletions remove the serve-credit pass bits and the witness rows, the remaining flag-0 overwrite sites are walked against their Rust write (`InsertTable` / `UpsertTable`):
- bond records;
- budget-accrual rows;
- curve-root heights.

Each site's semantics are named, and L14 closes. Owner: PR 2's first commit, a census-only change.

### DX-Q10 — The fee floor and the served ladder move at the flip (ruled with FL PR-C)

**Ruled (Rick, 2026-10-16):** the Rust floor was built in FL PR-C (#1096, landed) and is wired at the flip. Nothing here needs a ruling; it is listed so the flip PR carries it by name.

**What is built and unwired at `d2ac8b45d`:**
- `shekyl_economics::{relay_floor_from, fee_ladder_from}`, one composition of σ, b, C, R and F from one block's `FeeOperands`;
- `shekyl_chain_rules::{fee_operands_at, relay_floor_at, relay_floor_window}`, which read those operands off a `ChainView`;
- `shekyl_economics::relay_floor_admits(fee, weight, floors)`, FL-R23 on the fee lattice.

**What the flip wires:**
- **Admission.** `fee_clears` (`shekyl-daemon-rpc/src/submit/fee.rs`) is `relay_floor_admits` over the relay-floor window when the shim supplies one (the Rust pool), and `fee_meets_floor` — the same predicate over the snapshot tip floor alone — when it does not (the C++ shim). The flip deletes the C++ shim, so Phase C and Phase D see only the window. Pool admission (DX-Q5's door) calls the same predicate. The `fee_per_byte` submit fact goes with `daemon_submit_ffi.cpp`.
- **The estimate.** `get_fee_estimate`'s store-backed `ChainFacts` implementor (DX-Q3) answers `fee_ladder_from` at the connecting height. The C++ `get_dynamic_base_fee_estimate_2021_scaling` and its FFI go with `rpc_facts_ffi.cpp`.

**What the flip deletes:**
- `relay_floor_ring.cpp` and `relay_floor_ring.h`, with the ring's reorg hooks;
- `Blockchain::{check_fee, get_current_fee_per_byte, relay_floor_at, fee_correction_from, fee_correction_at}`;
- the FFI exports only they used: `shekyl_relay_fee_floor`, `shekyl_fee_correction`, `shekyl_relay_floor_lookback`, `shekyl_corrected_fee_ladder`, `shekyl_relay_floor_admits`.

This discharges FOLLOWUPS "FL-R3-STORE (consumer half)".

**One divergence the flip makes on purpose.** The C++ prices the burn on gross `already_generated_coins`. The Rust owner prices it on the validator's net circulating supply (FL-R16c; `FEE_LADDER_DERIVATION.md` §11.1 item 10). Quote and admission move to the net supply together. It is a **Design** row in DX-Q8's divergence register, citing FL-R16c. Its evidence is a comparison across the E2 corpus: the Rust floor is at most the C++ floor at every height, and equal wherever the burn through the parent is 0. No trace exports the C++ ring's floor today (`rust/shekyl-chain-ingest/src/vectors_tests/relay_floor.rs:18`–`:19`), so the flip PR builds that export and runs the comparison.

**The flip updates FL-R16c's "Not in scope" note** (`FEE_LADDER_DERIVATION.md:1602`): `ChainView::burned_through` (`rust/shekyl-chain-rules/src/view.rs:480`) is the per-height fact the note says no store had, and the ring is deleted.

**Doc comments the flip rewrites.** Each names the deleted C++ (lines read at `09402ea19`):
- `rust/shekyl-tx-weight/tests/weight_gate.rs:9` (`check_fee`);
- `rust/shekyl-economics/src/fee/relay.rs:38` (`get_current_fee_per_byte`);
- `rust/shekyl-economics/src/fee/floor.rs:11` (`relay_floor_ring.cpp`);
- `rust/shekyl-economics-sim/src/fee_floor.rs:43` (`get_current_fee_per_byte`);
- `rust/shekyl-chain-rules/src/relay_floor.rs:142` (`fee_meets_floor`);
- `rust/shekyl-chain-store/src/store/read.rs:490` (`rebuild_relay_floor_ring`);
- `rust/shekyl-chain-store/src/codec/chain.rs:101` (`relay_floor_ring.cpp`);
- `rust/shekyl-daemon-rpc/src/submit/facts.rs:563` (`check_fee`).

The C++ hits are all in files the flip deletes (`blockchain.{h,cpp}`, `tx_pool.cpp`, `relay_floor_ring.cpp`, `daemon_submit_ffi.{h,cpp}`) or in the ring's `CMakeLists.txt` entry. The Rust code hits are `submit/fee.rs` and its callers in `submit/engine.rs`, which the wiring above replaces.

**Falsifier:** after the flip, `rg -n 'relay_floor_ring|check_fee|get_current_fee_per_byte|fee_meets_floor' src rust` returns nothing, with no exceptions.

---

## 2. The relay seam at the flip (DX-Q5, grounded)

**What `levin_notify` asks of the core today** (`i_core_events.h`):
- `get_current_blockchain_height`;
- `is_synchronized`;
- `pool_has_tx(txid)`;
- `on_transactions_relayed(blobs, method, stem_connector)`;
- `on_stem_propagated(txids)`.

**And the other direction.** The core's periodic `get_relayable_transactions` → `relay_transactions` (`cryptonote_core.cpp:1035–1084`) is the pool's relay state machine driving the sends.

**At the flip:**
- The shell implements the five `i_core_events` methods by forwarding: height and sync to `TipChanged` and the sync state; the other three to the Rust pool.
- One Rust → C++ call hands `levin_notify` what the pool's readiness says is due. That is the only new C++ entry, and RD deletes it with `levin_notify`.

**The flip's relay obligations** (carried from the review of #1102):
- The flip drives `Responsibilities::release` from every way an entry leaves the pool — eviction, the reconcile's removals and mining — and asserts `len() ≤ pool.len()`, so the relay never holds a responsibility for a transaction the pool no longer has.
- The relay nudge fires only on `Committed`, never on a concealed `Accepted`.

**DX-F6 — the landed pool record holds the relay state machine, against D++ acceptance criterion 2.**
- `RelayState` (`shekyl-chain-store/src/codec/pool.rs` at the ground, `d2ac8b45d`, lines 155–171; PR-b replaced it with the public bit) stores:
  - a stem/fluff phase;
  - an arrival `zone: NetZone`.
- Criterion 2 (`DAEMON_RELAY_PRIVACY.md:113–125`) rules: "**The pool knows one bit: public yet** … owned by the relay and read by the pool", and that `NetZone` is "not a pool field". There are no zones in Shekyl (2026-09-30).
- It is a projection of the C++ `relay_method` (rule 16). PR-b reshapes it before the pool goes live: the pool record carries the public bit and nothing of the relay's state.
- Stem, fluff, embargo and arrival connector are the relay owner's (criterion 1). Whether the origin's re-broadcast responsibility is pool or relay state is posed in PR-b's brief, which coordinates with the RD lane.

---

## 3. DX-Q8 — the evidence that gates the flip's merge (amended, Rick 2026-10-16)

**The principle.** The goal is equivalent functionality implemented to Shekyl's design, not parity with CryptoNote/Monero. The flip **categorizes** every difference between the C++ and the Rust; it does not grade the Rust against the C++.

### 3.1 The divergence register

**What feeds it.**
- **The E2 corpus**, replayed one last time: the C++ traces against the flip branch.
- **Every testnet chain** both binaries sync.
- **The RPC suites**, run against both binaries.

Each observed difference becomes one row.

**Each row names:**
- the subject;
- what C++ does;
- what Rust does;
- the evidence (trace, height, field);
- **exactly one category:**

| Category | Meaning | Merge condition |
| --- | --- | --- |
| **Design** | Rust implements a Shekyl ruling the C++ never had or had differently | Cite the ruling (date, document). No action |
| **C++ defect** | Rust implements the specification; the C++ is wrong | Cite the specification clause. No C++ change (the C++ is deleted in this PR) |
| **Removed** | A C++ mechanism Shekyl rejected or deleted (hard-fork table, zones, orphan store, scoring, pruning seeds, `kept_by_block` — its floor bypass and the whole reorg retention it served, CEN-K10, deleted 2026-10-17 on #1102) | Cite the ruling |
| **Unbuilt by design** | A staged mechanism with a named owner and PR (chain sync's headers-first) | Owner and PR named, and the C++ behaviour is not needed meanwhile |
| **Rust defect** | Rust is wrong against the design | **Blocks the merge.** Fixed in the flip PR |

**Rules for the register.**
- There is **no "unexplained" category.** A difference that cannot be placed blocks the merge until it is.
- **Serve-credit acceptance is a prerequisite, never a row.** DEL-008 gates genesis (`DAEMON_REDB_STORE.md:2697`; moved from the flip, Rick 2026-10-18): no genesis until SO-D8 Slice C's admission rows are `implemented` in `census.rs`, CEN-J8–J10 are retired, and the secret draw is live (`SO-D11b`). Until then testnet archival runs on the Rust path as it stands, carriers included. Deleting `check_archival_serve_credit_input` removes the only serve-credit acceptance that runs, so its successor (SO-D12's bundle admission) cannot be staged at the flip, and a difference it leaves cannot be placed as **Unbuilt by design**.
- A difference the C++ cannot exhibit (Rust-only state) is not a row.
- The register lives in the flip's design record; the E2 grader's output is its input, not its verdict.
- After the flip the corpus re-baselines from Rust (`DAEMON_REDB_STORE.md` §12.1). The register is the last record that compares the two, kept as records-was at its sha.

**Rows found by PR 3** (#1106; the store-backed facts and read handlers, staged). The flip replays the corpus and walks the suites; these are the rows it starts from, each with its evidence.

*The header and info facts:*

| Subject | C++ | Rust | Category |
| --- | --- | --- | --- |
| `get_block.json` | epee's rendering of the block | omitted | **Removed** (RK-D11; RK-W retires it): no Rust producer, and the field repeats `blob` |
| an alt block's header by hash: difficulty, cumulative difficulty, weights, depth | the main chain's values at the alt block's height (`rpc_facts_ffi.cpp:302`–`:325`) | the alt row's own work and weight; no long-term weight (no chain records its medians); depth 0 | **C++ defect**: an alt block described by another block |
| an empty store | unreachable (LMDB always holds genesis) | `NotReady`, never a zero tip | **Design**; unreachable after the flip, which connects genesis before the RPC serves (DX-Q6) |
| `get_info`'s sync, pool, peers and free-space parts | read from the C++ core | inputs through `NodeFacts`: PR 2's sync owner, PR-b's pool (`PoolScope`'s docs map each count), the p2p board | **Unbuilt by design** until the flip wires them |

*The read handlers:*

| Subject | C++ | Rust | Category |
| --- | --- | --- | --- |
| `get_coinbase_tx_sum` emission | each coinbase's outputs less the block's fees (`cryptonote_core.cpp:634`) | the coins the range minted: the supply accumulator's growth, each block's paid reward | **C++ defect**: the coinbase pays the miner's emission plus only the miner's fee share, so the figure leaves out the staker emission and the burned and staker fee shares, and wraps below zero in a block whose fees exceed its coinbase. It differs at 1,463 of the 1,469 captured heights |
| `get_alternate_chains` order | an unordered map's | the alt table's key order of the tips | **Design** |
| `get_alternate_chains.main_chain_parent_block` | the main chain's block at `height − length` | the parent the chain's lowest block names; the read fails closed when that parent is not a recorded block | **Design**, the same value while the invariant holds. An alternative row leaves by promotion, refusal, the death rule, a rewind or a reset, and every stored chain reaches a main-chain block (`store/alt.rs`). The listing is that walk (`AltChain::build`): a chain that does not reach a recorded block, or that links to itself, is an inconsistent store, not a parent the reply names |
| `get_curve_tree_checkpoint` heights | one every 10,000 blocks | every height through the tip | **Design**: the store records the tree at every height |
| the curve tree's depth | stored | derived from the leaf count (`CTW-Q4`) | **Design** |
| `get_curve_tree_info` on an empty chain | `height` underflows | `NotReady` | **C++ defect**, unreachable after DX-Q6 |
| `calc_pow` with a seed height above the tip | hashes under the null seed and returns it | refused, `WRONG_PARAM` | **C++ defect** |
| `calc_pow` under a seed the cache store does not hold | derives a new cache, evicting the validator's spare, with no limit across concurrent seeds (`core_rpc_server.cpp:578`–`:596`; `pow_randomx_ffi.rs:227`) | refused, `WRONG_PARAM`; the handler calls `CacheStore::lookup` and never derives | **Design** (ruled 2026-10-17) |
| `calc_pow`'s size bound | the cumulative weight limit plus leeway | the largest blob the wire parses (`MAX_BLOCK_BLOB_SIZE`) | **Design**: `calc_pow` admits nothing |
| the claim source's shard rows | leaf segments, `has_segment` / `freeze_height` from the segment registry (`ARCHIVAL_SHARD_COUNT_CUTOVER.md:246`) | the byte-cut shards the Rust validator judges, folded onto the same pair by `ShardClose::to_wire` | **Design** (`SHT-Q2`; CEN-L10, ruled intended) |
| the claim source's `has_budget_row` | the budget row alone; `Σwork` is written with it at the close | the claim verify's citing gate: budget, `Σwork` and close height all rows (`emission_epoch_facts`, CEN-J23); `Σwork` is the slash pass's, an epoch after the budget | **Design** (`SO-D11d`, `SO-D11g`) |
| the coverage list's shards | the frozen leaf segments (`frozen_segment_count` over the leaf count) | the byte-cut shards closed and final, the set CEN-J15 lets a join hold (`ClosedUniverse::final_before`) | **Design** (`SHT-Q2`, `SO-D11f`) |

**Rows found by PR 2** (the arrival path, staged). The p2p wire does not change; these are what a peer's blocks meet.

| Subject | C++ | Rust | Category |
| --- | --- | --- | --- |
| `m_invalid_blocks`, CEN-A1's memory of refused ids | a process-lifetime set of refused block ids, filled at `blockchain.cpp:2802` and consulted to drop a repeat in `have_block_unlocked` (`:2837`) | none: a repeat is judged again and refused by its own verdict | **Removed** (PR2-Q2, design review 2026-10-18): a fresh junk block is a fresh id, so the memo defeats only replays, which cost the attacker as little as fresh junk |
| the size bound before parse (CEN-A5) | the cumulative weight limit plus `BLOCK_SIZE_SANITY_LEEWAY` (100) | the header bound plus twice the ceiling limit `2·S·LTEM` at the tip's successor (`admission::ArrivalBound`), `Oversize` before acceptance | **Design** (PR2-Q2): no valid block's arrival exceeds it at any height a span reaches; CEN-A5 is bucket 3 |
| unsolicited block announcements | no bound per session | two per target interval per session, at most two held; a dry bucket is `Throttled` before parse and never a score | **Design** (PR2-Q2; CS-Q5 (c)) |

**The flip's `CORE_RPC_VERSION` bump.** One minor bump covers every row above that changes what a client reads:
- `get_block.json` disappears;
- an alt block's header carries its own values;
- the coinbase sum's emission changes meaning;
- `calc_pow` gains two refusals: a seed height above the tip, and a seed whose cache is not held;
- a checkpoint answers at every height;
- the claim source's shard rows and `has_budget_row`, and the coverage list's shards, follow the Rust validator.

Its number is read from the tree at the flip's pin, never carried from a plan (`shekyl-rpc-types`' `chain.rs`).

**Rows found by PR 3b** (#1165; staged). The flip starts from these too.
- `get_block_template` takes no address and no reserve size, `start_mining` no address, and a request carrying either is refused as bad parameters; the extra nonce is always reserved: **Design** (N2, 2026-10-21).
- `get_block_template` adds `nonce_offset`; `mining_status` adds the job's `height`, `pool_retired` and the no-template diagnostic, and its `address` is the `mine-address` row whether or not the miner runs: **Design** (N2; Q13).
- `get_miner_data`'s `tx_backlog` is the posted template's listed bodies, not the whole pool: **Design** (N2).
- `generateblocks` takes `count` alone and runs the built-in miner; no `wallet_address`, `starting_nonce` or `prev_block`: **Design** (N2).
- `submit_block` takes `{ body }`, not a positional list, and a block that wins a switch is success: **Design** (the brief of 2026-10-23, b3; a block that is the new tip has joined the chain).
- `pop_blocks` refuses a count whose lowest block is below `max(genesis + 1, undo floor)`, before any pop: **C++ defect** for the missing bound (C++ clamps genesis only), **Design** for the reply shape (Q7).
- The pool listing's `receive_time`, `last_relayed_time`, `get_txpool_backlog`'s `time_in_pool`, and the stats' `oldest`, `num_10m`, `histo` and `histo_98pc`: **Design** (S7, the review of #1102: a receive time across many nodes' listings points at a transaction's origin; the Rust pool keeps none).
- `kept_by_block`: **Removed** (CEN-K10, deleted 2026-10-17 on #1102).
- `double_spend_seen` and the stats' `num_double_spends`: **Design** (CEN-M7: the door refuses a conflicting spend, so no entry is held marked).
- `last_failed_height`, `last_failed_id_hash` and the stats' `num_failing`: **Design** (CEN-M10: an entry the parent refuses is evicted, not kept with a mark).
- `max_used_block_id_hash` and `max_used_block_height`: **Design** (an FCMP++ spend's reference block is its pass's, re-judged on every reconcile; there is no ring's highest block to report).
- `do_not_relay`: **Design** (the stem phase is `relayed: false`; no other relay state).
- `tx_json`, and `get_transactions`' `as_json`: **Removed** (epee's rendering, retiring in RK-W; RW-Q4, IG-Q55). `decode_as_json: true` is refused as bad parameters. The C++-backed server also drops `as_json` when it rendered none, so today's replies lose the field they always sent empty.
- `get_transactions`' pool entry has no `received_timestamp`: **Design** (S7, as the pool listing's).
- `get_transactions` refuses a transaction whose body this node has pruned, naming it: **Design** (the prunable region and `pqc_auths` go together, and the wire cannot be recomposed without them; C++ never discarded a body).
- `inject_archival_serve_credit` is the host's and an armed lever: **C++ defect** (RT-O9.2 ruled it so; the table restated the defect as policy).
- `set_bans` takes no numeric `ip`, an absent `seconds` bans until lifted, and `get_bans` and `banned` add `permanent`: **Design** (Q11; the ban file's permanent bans).
- `relay_tx` answers not ready: **Unbuilt by design**, owner RD (the relay driver).
- A public-network node is not synced, and builds no template, before chain sync's cutover: **Unbuilt by design**, owner chain sync (Q13).

### 3.2 Function

- **Every regtest e2e walk** passes on the flip binary.
- **The five bonded walks un-darken.** The Rust daemon admits a kind-5 JoinMarket post, which is the condition the FOLLOWUPS row names (DEL-008). Each walk asserts the Shekyl behaviour, not a C++ outcome.
- **A testnet node syncs from peers to the tip** over clearnet and over Tor.
- **A switch** happens on regtest with a validating user spend demoted and returned to the pool.

### 3.3 Cost — a measurement, not a parity claim

**DRS-D6's IBD floor** (`DAEMON_REDB_STORE.md` §1.3, pre-registered and frozen):
- ≤ 1.25× passes; > 1.50× after one mitigation cycle fails; peak RSS ≤ 2×.
- Measured on one machine syncing the same testnet chain from the same peers: the pre-flip `dev` binary against the flip binary.
- It compares the cost of the shipping daemon with what it replaces. The artifact says so, and records the durability configuration.

**Plus the floor device**, each figure labelled `RustPath`: initial-sync rate and the writer's busy share.

---

## 4. Order of work

1. **PR-b**, brief issued 2026-10-16; merged 2026-10-18 (#1102).
2. **PR 2** — router, entry, `TipChanged`, hasher budget, L14 walk. Merged (#1123), staged: built and tested, nothing routed.
3. **PR 3** — the read-only RPC handlers, the store-backed facts and the miner loop. Merged (#1106).
4. **PR 3n** — `shekyl-node`, the daemon's one `Node` (N1, DX-Q3's amendments). Merged (#1147). Staged: Rust `main` builds it at start beside the C++ core, an empty store connects the pinned genesis through the ingest door, and nothing is routed.
5. **PR 3b** (#1165) — the node's one template under N2: the tip follower builds it on one snapshot and posts it, and `get_block_template` and `get_miner_data` read the posted job; mining control (`start_mining`, `stop_mining`, `mining_status`); `submit_block` and `generateblocks` through the local-arrival entry; `pop_blocks`; the pool's handlers; the bans and `stop_daemon`; `is_key_image_spent` and the two `.bin` reads (DX-Q3 and its amendments). Staged: built over a real `Node` and tested, nothing routed.
6. **The flip** needs PR-b, PR 2, PR 3, PR 3n, PR 3b and #1088. DEL-008's gate holds at genesis (Rick, 2026-10-18). At genesis the requirements are — SO-D8 Slice C's admission rows `implemented`, CEN-J8–J10 retired, and the secret draw live (`DAEMON_REDB_STORE.md:2697`). Until then testnet archival runs on the Rust path as it stands, carriers included, so passes land on live code. The flip's edit to `try_add_next_blocks` carries its own `UNFREEZE` line in `scripts/ci/dial_path_freeze.tsv` if CS-Q9's shrink-only rows for the protocol handler have landed (CS-Q9, Rick 2026-10-18).
7. **Chain sync's cutover** follows the flip. It deletes the protocol handler's sync half, the complement request included (CS-Q1, Rick 2026-10-18). **RD** deletes its transaction routes, complement serving, `levin_notify` and the relay entry. Whichever lands second deletes the handler file.

**Chain sync CS-F5** (fixed in PR 2): `shekyl-chain-ingest/src/source.rs` states the landed switch — the fork choice is ingest's, and a live source never emits `Rewind`.
