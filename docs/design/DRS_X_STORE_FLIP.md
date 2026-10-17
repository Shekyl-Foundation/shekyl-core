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
3. **Capacity (chain sync's requirement, `CHAIN_SYNC_ROUND0_DECISIONS.md` §A).**
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
6. **One RandomX budget.** The pipeline's `Form` workers and chain sync's header PoW draw from one bounded hasher budget, so the two never exceed the scratchpads the floor device holds (chain sync §A.3).
7. **Deleted:** `prepare_handle_incoming_blocks` / `cleanup_handle_incoming_blocks` (Monero's batch preprocessing) and `try_add_next_blocks`' connect loop. The `Form` workers replace them.

### DX-Q3 — RPC handlers that read the chain or the pool move to Rust in the flip

The join rule: no FFI built for a C++ handler that dies a PR later.

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
- **`FfiChainFacts` / `FfiInfoFacts`** are replaced by store-backed implementors (RK-D7's planned second implementation). `rpc_facts_ffi.cpp` deletes.
- **Deleted:** `save_bc` and `flush_cache` (durability is `Immediate`; there is no cache), and `inject_archival_serve_credit` (with DEL-008).
- **Not this lane:** log, limits and peers (#1088's `option_set`); bans (P2P); `stop_daemon` (Rust `main`).
- **Falsifier:** no handler left in `core_rpc_server.cpp` reads the chain or the pool.

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
| 1 | **PR-b**: the Rust pool (`DRS_E5_POOL_ALT_PRUNE.md` §5 b1–b7, as amended in its brief) | staged |
| 2 | **Router, arrival entry, `TipChanged`, the shared hasher budget**; the scenario driver is the source in tests | staged |
| 3 | **The Rust RPC handlers (DX-Q3) and the miner loop (DX-Q4)**, unrouted | staged |
| 4 | **The flip** (below) | live |

**The flip PR:**
- routes every arrival and every handler;
- opens the store in `main`;
- builds the shell;
- deletes:
  - LMDB and `BlockchainDB`;
  - `Blockchain` and `tx_memory_pool` (DEL-010);
  - the archival C++ path (DEL-008);
  - the reorg path (DEL-009);
  - `rpc_facts_ffi.cpp`, `daemon_submit_ffi.cpp` and `miner.cpp`;
  - the LMDB utilities (FOLLOWUPS, IG-Q26);
  - the C++ fee floor and its FFI (DX-Q10);
  - liblmdb from `shekyld` (DEL-004);
- deletes every LMDB-bound C++ test, each with a sentence naming the rule it tested and where Rust covers it now;
- applies the `DAEMON_REDB_STORE.md` §12.1 gate retirements.

PRs 1–3 may run in parallel. PR 4 needs all three, plus #1088 merged.

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
- **Admission.** The submit engine's `fee_meets_floor` (`shekyl-daemon-rpc/src/submit/fee.rs`) is replaced by `relay_floor_admits` over `relay_floor_window` at Phase C and Phase D. It currently runs the pre-FL-R23 rule against the tip floor alone with a 2 % buffer. Pool admission (DX-Q5's door) calls the same predicate. The `fee_per_byte` submit fact goes with `daemon_submit_ffi.cpp`.
- **The estimate.** `get_fee_estimate`'s store-backed `ChainFacts` implementor (DX-Q3) answers `fee_ladder_from` at the connecting height. The C++ `get_dynamic_base_fee_estimate_2021_scaling` and its FFI go with `rpc_facts_ffi.cpp`.

**What the flip deletes:**
- `relay_floor_ring.cpp` and `relay_floor_ring.h`, with the ring's reorg hooks;
- `Blockchain::{check_fee, get_current_fee_per_byte, relay_floor_at, fee_correction_from, fee_correction_at}`;
- the FFI exports only they used: `shekyl_relay_fee_floor`, `shekyl_fee_correction`, `shekyl_relay_floor_lookback`, `shekyl_corrected_fee_ladder`, `shekyl_relay_floor_admits`.

This discharges FOLLOWUPS "FL-R3-STORE (consumer half)".

**One divergence the flip makes on purpose.** The C++ prices the burn on gross `already_generated_coins`. The Rust owner prices it on the validator's net circulating supply (FL-R16c; `FEE_LADDER_DERIVATION.md` §11.1 item 10). Quote and admission move to the net supply together. On a chain that has burned, every floor moves at the flip: down, because b falls with supply. It is a **Design** row in DX-Q8's divergence register, citing FL-R16c — expected, not a regression.

**Falsifier:** after the flip, `rg -n 'relay_floor_ring|check_fee|get_current_fee_per_byte|fee_meets_floor' src rust` returns nothing outside history.

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
- `RelayState` (`shekyl-chain-store/src/codec/pool.rs:155–171`) stores:
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
| **Removed** | A C++ mechanism Shekyl rejected or deleted (hard-fork table, zones, orphan store, scoring, pruning seeds, `kept_by_block` floor bypass) | Cite the ruling |
| **Unbuilt by design** | A staged mechanism with a named owner and PR (SO-D12's bundle, chain sync's headers-first) | Owner and PR named, and the C++ behaviour is not needed meanwhile |
| **Rust defect** | Rust is wrong against the design | **Blocks the merge.** Fixed in the flip PR |

**Rules for the register.**
- There is **no "unexplained" category.** A difference that cannot be placed blocks the merge until it is.
- A difference the C++ cannot exhibit (Rust-only state) is not a row.
- The register lives in the flip's design record; the E2 grader's output is its input, not its verdict.
- After the flip the corpus re-baselines from Rust (`DAEMON_REDB_STORE.md` §12.1). The register is the last record that compares the two, kept as records-was at its sha.

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

1. **PR-b**, brief: `claude/DRS_E5_PR_B_POOL_BRIEF.md`. Starts now.
2. **PR 2** — router, entry, `TipChanged`, hasher budget, L14 walk. Briefed after PR-b's door lands, because the entry's pool calls are its shape.
3. **PR 3** — Rust RPC handlers and the miner loop. Starts now, beside PR-b; brief follows.
4. **The flip**, after #1088, PR-b, PR 2 and PR 3.
5. **Chain sync's cutover** follows the flip and deletes the shell's protocol-handler half. **RD** deletes `levin_notify` and the relay entry.

**Docs to fix in PR 2** (chain sync CS-F5):
- `shekyl-chain-ingest/src/source.rs:28` and `:43` still say the p2p source computes the switch and emits `Rewind`.
- The landed switch puts the fork choice in ingest. A live source never emits `Rewind`.
