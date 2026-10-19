# DRS-X — the store-of-record flip: Round 0, ruled (`DX-`)

**Families (registered in `IMPLEMENTATION_INDEX.md` §2, rule 94):** **`DX-Q`** (questions, ruled here) and **`DX-F`** (findings). `X-` is taken by the exit-standoff family; `DX-Q` and `DX-F` are free at `d2ac8b45d`.
**Ground:** `dev` at `d2ac8b45d` (2026-10-16); #1088 (Rust `main()`) at its PR head. Counts re-measured at the landing pin, `d2ac8b45d`: two line spans corrected in place (DX-F1's cache block, DX-F6's `RelayState`); every other count and pin held.
**Status:** OPEN — Round 0 RULED, Rick 2026-10-16: DX-Q1…DX-Q9 accepted as recommended, and DX-Q8 amended (§3). DX-Q5's relay seam was grounded the same day (§2, DX-F6). DX-Q10, the fee floor's move at the flip, was ruled with FL PR-C (#1096, 2026-10-16) and is carried here by name. Implementation proceeds in the order of §4.
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

1. **The router (Rust)** places every arrival by its parent:
   - the recorded tip → the pipeline (`Extend`);
   - a recorded or alt block → `OfferAlt` and the switch (#1082);
   - unknown → `Unlinked { at }`, with nothing stored;
   - already held → `AlreadyHeld`.

   **There is no orphan store.** A peer cannot make the node hold a block it cannot place.
   - CEN-A1 and CEN-A4 become `enforced_at` the router. Their `held_by_cxx` entries and the `block_validation.cpp` citations go.
   - **CEN-A5** moves to bucket 3 with its reason recorded: it was the parse-cost bound, not validity, which G6b judges. Its bound is re-homed as the router's admission, size before parse, under "each layer owns its admission".
2. **One FFI entry, used by the protocol handler only.** `submit_block` and the miner enter the router natively (DX-Q3, DX-Q4).
   - The entry takes a span and returns at once. Every arrival gets one reply, tagged with the arrival, posted to the connection's strand.
   - The reply variants: `Connected`, `Refused(InvalidBlock)`, `Unlinked { at }`, `AlreadyHeld`, `Held`, `BeyondCap`, and the switch outcomes.
3. **Capacity (chain sync's Round 0 requirement, ruled 2026-10, carried here).**
   - The entry reports room. A caller asks before sending.
   - An arrival the entry accepted is **never dropped**. A span offered without room is `NoRoom`, before acceptance, and is never a peer fault.
   - Until the chain-sync cutover the C++ handler's span scheduler asks once per span.
4. **Peer scoring.** Only `Refused(InvalidBlock)` is about the peer. `Unlinked`, `NoRoom`, `BeyondCap`, the floor and stale outcomes never punish (C2-R1 Q1c F-1(a)).
5. **`TipChanged`, one source.**
   - The connector publishes the tip after every committed connect, pop and switch. `shekyl_core_publish_tip`'s producer moves from `Blockchain` to that commit.
   - **Consumers:**
     - the handshake (the dialer and slice 4);
     - new-block relay;
     - the miner's template refresh;
     - the sync owner;
     - the RPC.
6. **One RandomX budget.** The pipeline's `Form` workers and chain sync's header PoW draw from one bounded hasher budget, so the two never exceed the scratchpads the floor device holds (chain sync's Round 0 requirement, carried here).
7. **Deleted:** `prepare_handle_incoming_blocks` / `cleanup_handle_incoming_blocks` (Monero's batch preprocessing) and `try_add_next_blocks`' connect loop. The `Form` workers replace them.

### DX-Q3 — The C++ RPC server moves to Rust in the flip, whole

The join rule: no FFI built for a C++ handler that dies a PR later. Every method the C++ server answers is moved to Rust, deleted, or another lane's below; none stays in C++ (ruled by Rick, 2026-10-17, retiring the daemon RPC KV lane).

- **Moved to Rust:**
  - **RK-6 (pool)** over the Rust pool.
  - **RK-7 (mining):**
    - `get_block_template` from `shekyl-block-template` with the pool's selection (PR-b b6);
    - `submit_block` and `generateblocks` into the router;
    - `calc_pow` and `get_miner_data`.
  - **Alt chains and alt hashes** over the alt reads.
  - **`pop_blocks`** as a connector `Rewind` message, an operator action. A live source never emits `Rewind`.
  - **`get_coinbase_tx_sum`.**
  - **RK-9:** curve-tree info and checkpoint, archival claim source, shard coverage.
  - **Mining control:** `start_mining`, `stop_mining` and `mining_status`, over the Rust miner loop (DX-Q4). `set_log_hash_rate` deletes: the hash rate is part of mine status (`INPUT_GRAMMAR.md:632`, §13). The C++ handlers are `core_rpc_server.cpp:222`, `:273`, `:293` and `:347`.
  - **Bans:** `set_bans`, `get_bans` and `banned` (`core_rpc_server.cpp:944`, `:881`, `:912`), over the transport layer's ban list (`rust/shekyl-transport-layer/src/ban.rs:151`, held in the socket table, `admission.rs:270`). They reach it through a handle the composition root supplies, in RT-O26's shape (`RPC_CHANNEL.md:1275`, §6.4). No FFI. The C++ forwarders through `m_p2p` delete.
    - **How Rust reaches the list today:** only through `net_node`. The C++ handlers call `m_p2p` (`net_node.inl:213`–`:345`), which calls the `shekyl_ban_*` exports (`rust/shekyl-ffi/src/seam_ban_ffi.rs:75`–`:233`). Those act on the process's one socket table, a static inside `shekyl-ffi` (`process_sockets`, `seam_ffi.rs:200`–`:201`), or on the hub the C++ zone server binds over it (`zone_server.h:105`). Rust `main` holds no handle to either.
    - **The seam the flip uses:** the composition root owns the process's `Sockets` value (`admission.rs:338`, an `Arc` handle) and hands the bans handle to the RPC from it. The FFI's static becomes a reader of the root's value for as long as the C++ zone server binds through it.
  - **`stop_daemon`** (`core_rpc_server.cpp:436`) is one more trigger of the one stop path (`TOR_SUPERVISOR.md:51`, §1, ruled 2026-10-14; the stop-trigger row at `:612`). The handler asks Rust `main` to stop; it stops nothing itself.
- **`FfiChainFacts` / `FfiInfoFacts`** are replaced by store-backed implementors (RK-D7's planned second implementation). `rpc_facts_ffi.cpp` deletes.
- **Deleted:** `save_bc` and `flush_cache` (durability is `Immediate`; there is no cache), and `inject_archival_serve_credit` (with DEL-008).
- **Not this lane:** log, limits and peers (#1088's `option_set` / `option_show`).
- **The C++ RPC server is gone whole:** every handler, request and response struct, dispatch table and error-code header, plus the facts and submit FFIs (`rpc_facts_ffi.cpp`, `daemon_submit_ffi.cpp`, `core_rpc_ffi.cpp`). The flip PR lists every file this empties, at its pin. At `b6bdadc3c` the falsifier's patterns match 28 files under `src/`, mixed headers such as `src/shekyl/shekyl_ffi.h` among them.
- **The interim C++ console:** the console commands that read `COMMAND_RPC_*` structs delete with those structs. At #1088's head (`30a27570b`) they are nineteen words over eighteen executor methods (`src/daemon/rpc_command_executor.cpp:167`–`:963`; the words at `src/daemon/command_server.cpp:116`–`:257`): `bans`, `ban`, `unban`, `banned`, `flush_txpool`, `print_coinbase_tx_sum`, `print_pool`, `print_pool_sh`, `mining_status`, `pop_blocks`, `relay_tx`, `save`, `show_hr`, `hide_hr`, `start_mining`, `stop_mining`, `stop_daemon`, `exit` and `flush_cache`. `stop_daemon` and `exit` share one method. They are not ported into the Rust console. Their successors are `shekyl-cli`'s words (`INPUT_GRAMMAR.md` §13, `:609`), built by the R8 slice. Three have none: `pop_blocks` is an armed test lever (IG-Q25, `INPUT_GRAMMAR.md:683`), and `save` and `flush_cache` name LMDB and C++ cache internals.
- **Falsifier:** after the flip, `rg -n -e 'COMMAND_RPC_' -e 'core_rpc_server' src/` returns nothing.

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

- Rust `main` opens `ChainStore::with_release` after the network marker (#1088 step 4) and before `run(snapshot)` (step 7). It spawns the connector and hands the remnant the shell's handle.
- **Genesis.** An empty store connects the pinned genesis through the ingest (`form` → `validate` → `connect`, CEN-E5's pin). `reset_and_set_genesis_block` deletes.
- **Stop.** The connector finishes its current message and the store closes before exit. `Immediate` durability means there is no flush step.
- **No migration.** A release wipes, and an LMDB directory is ignored.

### DX-Q7 — The PR shape

The splinter rule: a mechanism is deleted whole, in one PR. The join rule: no FFI built only to be deleted later.

| # | PR | Live? |
| --- | --- | --- |
| 1 | **PR-b**: the Rust pool (`DRS_E5_POOL_ALT_PRUNE.md` §5 b1–b7, as amended in its brief) | staged; merged 2026-10-18 (#1102) |
| 2 | **Router, arrival entry, `TipChanged`, the shared hasher budget**; the scenario driver is the source in tests | staged |
| 3 | **Briefed: the read-only RPC handlers and the store-backed facts (DX-Q3), and the miner loop (DX-Q4)**, unrouted | staged |
| 3b | **The pool's handlers, `get_block_template`, `submit_block`, `generateblocks`, `pop_blocks`, `start_mining` / `stop_mining` (with `mining_status`), the bans and `stop_daemon`** (DX-Q3), unrouted. Briefed after PR-b and PR 2 merge | staged |
| 4 | **The flip** (below) | live |

**The flip PR:**
- routes every arrival and every handler;
- opens the store in `main`;
- builds the shell;
- deletes:
  - LMDB and `BlockchainDB`;
  - `Blockchain` and `tx_memory_pool` (DEL-010);
  - the archival C++ path (DEL-008), only once DEL-008's gate holds: Slice C's admission rows `implemented`, CEN-J8–J10 retired, the draw live;
  - the reorg path (DEL-009);
  - `rpc_facts_ffi.cpp`, `daemon_submit_ffi.cpp` and `miner.cpp`;
  - the C++ RPC server whole (DX-Q3's falsifier), with the interim console's commands that read its structs;
  - the LMDB utilities (FOLLOWUPS, IG-Q26);
  - the C++ fee floor and its FFI (DX-Q10);
  - liblmdb from `shekyld` (DEL-004);
- deletes every LMDB-bound C++ test, each with a sentence naming the rule it tested and where Rust covers it now;
- applies the `DAEMON_REDB_STORE.md` §12.1 gate retirements.

PR-b, PR 2 and PR 3 may run in parallel; PR 3b is briefed after PR-b and PR 2 merge. The flip needs PR-b, PR 2, PR 3, PR 3b and #1088.

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
- **Serve-credit acceptance is a prerequisite, never a row.** DEL-008 gates the flip (`DAEMON_REDB_STORE.md:2697`): no cutover until SO-D8 Slice C's admission rows are `implemented` in `census.rs` and CEN-J8–J10 are retired, and no Rust consensus before the secret draw is live (`SO-D11b`). Deleting `check_archival_serve_credit_input` removes the only serve-credit acceptance that runs, so its successor (SO-D12's bundle admission) cannot be staged at the flip, and a difference it leaves cannot be placed as **Unbuilt by design**.
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
2. **PR 2** — router, entry, `TipChanged`, hasher budget, L14 walk. Briefed after PR-b's door lands, because the entry's pool calls are its shape.
3. **PR 3** — briefed: the read-only RPC handlers, the store-backed facts and the miner loop. Runs beside PR-b.
4. **PR 3b** — the pool's handlers, `get_block_template`, `submit_block`, `generateblocks`, `pop_blocks`, `start_mining` and `stop_mining` (with `mining_status`), and the bans and `stop_daemon` (DX-Q3). Staged. Briefed after PR-b and PR 2 merge.
5. **The flip** needs PR-b, PR 2, PR 3, PR 3b and #1088, and DEL-008's gate: SO-D8 Slice C's admission rows `implemented`, CEN-J8–J10 retired, and the secret draw live (`DAEMON_REDB_STORE.md:2697`).
6. **Chain sync's cutover** follows the flip and deletes the shell's protocol-handler half. **RD** deletes `levin_notify` and the relay entry.

**Docs to fix in PR 2** (chain sync CS-F5):
- `shekyl-chain-ingest/src/source.rs:28` and `:43` still say the p2p source computes the switch and emits `Rewind`.
- The landed switch puts the fork choice in ingest. A live source never emits `Rewind`.
