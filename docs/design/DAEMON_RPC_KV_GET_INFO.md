# RK-5c — `get_info`, the hub: rule-26 pre-flight

**Status:** OPEN — R0, **DRAFT for ratification** (2026-10-08). §1's rulings
are recorded as ruled. §4–§5 are proposed and authorize no implementation
until the open questions in §8 are ruled.
**Ground:** `shekyl-core` `dev` **`98fbd20ac`** (#1005 merge, 2026-10-08);
`shekyl-gui-wallet` `dev` **`447908f`**. Every `file:line` below was read at
those commits. Open work on the hard-fork mechanism's deletion also edits
`on_get_info`; if it merges first, the handler's line numbers move and the
content cited does not.
**Parent:** [`DAEMON_RPC_KV_CUTOVER.md`](DAEMON_RPC_KV_CUTOVER.md) §2 row
RK-5c, §2.1.1, §5. Family `RK-` (registered); this document mints
**RK-D13…RK-D22** (decisions) and **RK-Q1…RK-Q8** (open questions) inside
it, added to the family's index row in the commit that lands this file
(rule 94).
**Sibling round:** [`RPC_CHANNEL.md`](RPC_CHANNEL.md), round R1. Its §6.1
is cited here **at #1006's head `f331b31e0`**, which is not merged: `dev`
carries an earlier R1 text. Three things this document relies on exist
only at that head — the phrase "absent, never zero", the paragraph "What
the incident's consumer gets", and the ruling that RK-5c lands before
RT-W10. If #1006 changes them before it merges, this document follows.
The grant assigned to each part in §2.1 is that head's table, direction
given 2026-10-08 and still to be confirmed there (RT-O9).
**Process:** [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
— this slice moves the FFI boundary for the widest reply on the surface.
**Decision authority:** Rick.

---

## 0. Why this slice is not a plain port

RK-1…RK-5b each moved a method whose C++ handler was a thin reader. `get_info`
is not. Its handler (`src/rpc/core_rpc_server.cpp:199-305`) holds policy:

- **A sentinel that reads as data.** `target_height = 0` when synchronized
  (`:208`), for every caller. `0` is also what the core reports when it has
  no target, so the two states are one value.
- **Four restricted stand-ins that read as data.** For a restricted caller
  only: `0` for every hidden count — `alt_blocks_count`, both connection
  counts, the four socket counts, both peerlist sizes, `start_time`
  (`:213-232`, `:245`); `free_space = u64::MAX` (`:246`); `database_size`
  rounded up to 5 GiB (`:248-250`); `version = ""` (`:251`). Each is a
  value that means "not this value".
- **Three sources for one quantity.** `incoming_connections_count` is
  `total − outgoing` (`:214-216`): `total` from the clearnet zone's epee
  `m_connects`, `outgoing` from the Rust seam board. Two stores, unsigned
  subtraction, no shared lock.
- **Clearnet-only counts.** `get_public_connections_count` and
  `get_public_outgoing_connections_count` look up `connector_id::clearnet`
  only (`src/p2p/net_node.inl:1250-1256`, `:2211-2217`). Tor sessions are not
  counted.
- **Torn reads.** The tip is read at `:205`; the cumulative difficulty,
  coins generated and economics are read later at `res.height - 1` with no
  common lock (`:239`, `:266`, `:269`, `:274`). `synchronized` is read twice
  (`:208` via `is_synchronized()`, `:253` via `check_core_ready()` — the same
  predicate, two reads).
- **A retired idea still on the wire.** `emission_era` is four labels cut by
  `double` thresholds 0.30 / 0.60 / 0.85 of the asymptote (`:294-302`).
  There is no emission era: the idea was retired and the field outlived it
  (RK-D21).

And the wallet already depends on two of those quirks (§3). So RK-5c is
designed, not transcribed.

**Governing principle (Rick, 2026-10-08): each data element has one source.**
Two encodings of one fact, or one field fed by two stores, is unintelligible
and unmaintainable. Every decision below is that principle applied.

---

## 1. Rulings recorded — RULED (Rick, 2026-10-08)

| ID | Ruling (RULED 2026-10-08) |
| --- | --- |
| **RK-D13** | **Port with parity first.** The final form of `get_info` is not known; the slice keeps the wire in its first native commit and pins it with oracle vectors. Internally the reply is already granular (RK-D18), because it feeds both health and node status. |
| **RK-D14** | **`has_peers: bool` belongs to health.** The number of peers is node status and stays out of health. |
| **RK-D15** | **The `target_height` sentinel is retired.** `0` stops meaning "synchronized" on `get_info`, as 3.40 already did on `get_version` and `sync_info` (`rust/shekyl-rpc-types/src/chain.rs:53-55`). Synchronization is `synchronized`; the target is the core's target or absent. |
| **RK-D16** | **Economics fields are ported, not redesigned**, into a flexible typed Rust structure the economics lane evolves on its own (EUP is in assessment; no parameter or field-meaning changes are authorized here). |
| **RK-D17** | **RK-5c lands before RT-W10.** Recorded in `RPC_CHANNEL.md` §6.1 at #1006's head. |
| **RK-D21** | **`emission_era` is removed, not ported.** There never was an emission era: the chain is pre-genesis and the idea was retired. The field, its four labels and its thresholds are deleted from the C++ reply **before** the oracle capture, so nothing in Rust — no type, no enum, no function, no fixture — ever carries it. |

---

## 2. Census at source

### 2.1 Fields, by part, with their one source

The reply is assembled from typed parts (RK-D18). Each field has exactly one
source; where today it has more, the column says which survives. The table
accounts for all 47 fields `COMMAND_RPC_GET_INFO::response` serializes beside
its response base (`src/rpc/core_rpc_server_commands_defs.h:274-320`).

| Part → grant | Field(s) | Source after RK-5c | Today |
| --- | --- | --- | --- |
| **Health** → `health` | `height`, `top_block_hash` | chain facts snapshot (§4.2) | `get_blockchain_top` `:205`, separate from every other chain read |
| | `target_height` | core target, `Option<ChainCount>` (`rust/shekyl-daemon-rpc/src/chain_facts.rs:115`) | overwritten to `0` when synced `:208` |
| | `synchronized` | protocol `is_synchronized()`, read **once** | read twice `:208`, `:253` |
| | `busy_syncing`, `offline`, `following_degraded` | node facts | `:257`, `:247`, `:256` |
| | `has_peers` (**new**, RK-D14) | the seam board, every connector | — |
| **Identity** → `health` (duplicates of `get_version`) | `nettype`, `mainnet`, `testnet`, `stagenet` | `shekyl_rpc_identity` (`src/rpc/rpc_facts_ffi.h:56-62`) — RK-Q6 | `:234-238` |
| | `protocol_version` | constant | `:252` |
| **Chain** → `chain` | `difficulty` / `wide_difficulty` / `difficulty_top64` | one `u128`, three renderings (RK-Q1) | `:209` |
| | `cumulative_difficulty` / `wide_…` / `…_top64` | one `u128`, three renderings (RK-Q1) | `:239-240` |
| | `target` | `SHEKYL_DAA_TARGET_SECONDS` (RK-D9) | `:210` |
| | `tx_count` | chain facts | `:211` |
| | `block_weight_limit` = `block_size_limit` | one value, two names (RK-Q1) | `:241` |
| | `block_weight_median` = `block_size_median` | one value, two names (RK-Q1) | `:242` |
| | `adjusted_time` | chain facts | `:243` |
| **Economics** → `chain` | `already_generated_coins`, `release_multiplier`, `burn_pct`, `total_burned`, `staker_emission_share_effective` | one projection function in `shekyl-economics` (RK-D19) | computed inline `:264-292` |
| **Pool** → `pool` | `tx_pool_size` | pool facts, broadcast-only for a restricted caller | `:212` |
| **Status** → `status` | `start_time`, `free_space`, `database_size`, `version` | node facts / build | `:245-251` |
| | `outgoing_connections_count`, `incoming_connections_count` | the seam board, per direction (RK-Q3) | epee total − board outgoing, clearnet only |
| | `alt_blocks_count` | chain facts snapshot (§4.2) | `:213`, `0` when restricted |
| | `rpc_connections_count` | Rust connection tracker, natively | C++ writes `0` (`:230`); Rust patches the JSON afterwards (`rust/shekyl-daemon-rpc/src/handlers/json.rs:82-100`, `handlers/json_rpc.rs:136-146`) |
| **Peers** → `peers` | four `*_socket_count` | transport (`shekyl_seam_socket_count`) | `:219-222` |
| | `white_peerlist_size`, `grey_peerlist_size` | peerlist facts | `:231-232` |
| **Transitional** | `restricted` | the listener flag | `:258`; retired by RT-W10, not here |
| **Removed** (RK-D21) | `emission_era` | none — deleted before capture | `:294-302` |

**A part is a unit of disclosure, not a unit of source.** Every field of a
part is seen under the same grant, so a grant selects whole parts. That is
why the aggregate connection counts and `alt_blocks_count` sit in Status
though one is read from the seam board and the other from the chain store:
each describes this node rather than the network (its connectivity posture,
the forks it saw), which is the sibling round's reason for keeping `status`
out of `view`. Where a part's facts come from is §4.2's concern. Two parts
may share a grant — Identity with Health, Economics with Chain — and stay
separate types because each has its own owner (RK-Q6, RK-D19).

Four fields the sibling round's table does not place: `has_peers` (new
here, `health`), `target` and `adjusted_time` (`chain`), and `restricted`
itself. The duplicate names of RK-Q1 and the three network booleans of
RK-Q6 follow the field they duplicate.

### 2.2 Readers — every one, by symbol and by quoted string

A remote arm calls by string, so this sweep includes `"get_info"`,
`/get_info` and `/getinfo` literals. The **untyped `Value` readers** are the
dangerous class: a field whose meaning moves does not fail to compile there.

| Reader | Where | Reads | Shape today | RK-5c disposition |
| --- | --- | --- | --- | --- |
| Wallet sync predicate | `engine/daemon/synced_chain_facts.rs:672-713`, `:730`, `:769` | `height`, `target_height`, both connection counts, `synchronized`, `top_block_hash` | `Value` | Onto the shared type (RK-D1); predicate `:284-291` simplifies with RK-D15; `connections` replaced by `has_peers` |
| Wallet `get_health` | `engine/daemon/mod.rs:425` | same decoder | `Value` | same |
| P's tip poller | `stake_engine/serving/daemon_tip.rs:274`, `:285-305`, `:325` | `status`, `offline`, `following_degraded`, `restricted`, connection counts | `Value` | Onto the shared type; reads `has_peers`; **stops reading `restricted`** |
| Submit watchdog | `submit_watchdog.rs:244-246`, `:311` | `DaemonHealth.connections` | via the decoder | `has_peers` |
| Regtest e2e | `engine/regtest_e2e.rs:401-443` | `GetInfoResp` (local struct) | local struct | shared type |
| Observability probe | `engine/daemon_observability.rs:289`, `:311` | success only | `Value` | unchanged |
| CLI | `shekyl-cli/src/daemon.rs:95-111` (`DaemonInfo`), `commands/chain.rs:15-60`, `commands/mine.rs:65-150` | height, target, difficulty, tx count, counts, `restricted`, `nettype`, `synchronized` | local struct + `Value` | shared type; `show_chain` stops inferring "syncing" from `target != height` (`chain.rs:39`) and reads `synchronized`; `DaemonInfo.difficulty: u64` goes with the struct, so RK-Q1 costs the CLI nothing further |
| Rust console (bridged leg) | `shekyl-daemon-rpc/src/console/info.rs:46-60`; users `status.rs:130-134`, `:245`, `:277`, `mod.rs:1236`, `blockchain.rs`, `alt_chain.rs:154` | height, wide difficulties, target, testnet, stagenet, start time, counts | `GetInfoReplyProvisional` | replaced by the shared type and a native call; the four §5 bridged-leg rows close |
| C++ console | `src/daemon/rpc_command_executor.cpp:250` (`show_difficulty`), `:646` (`print_transaction_pool_stats`), `:1351` (`version`) | various | C++ struct | ported to Rust (RK-D5); `print_transaction_pool_stats` keeps a bridged leg to `get_transaction_pool_stats` (RK-6, §2.1.1) |
| Levin harness tests | `shekyl-levin/tests/dual_stack.rs:175-196`, `inbound_cost_bench.rs` | `height`, `top_block_hash` | string scan | unchanged (names kept) |
| Python framework | `utils/python-rpc/framework/daemon.py`; `tests/stressnet/monitor.py`, `load_generator.py` | height, difficulty, status, pool size | dict | unchanged by parity; RK-Q1/Q6 changes listed per field |
| Scripts | `scripts/check_testnet_genesis_consensus.py:75-83` (four economics names), `scripts/bench/drs_bench.py:157-341` (height, status), `scripts/bench/wss_q1b_regtest_open_edge.sh:61` | named | dict | unchanged by parity |
| Fixture generators | `shekyl-curve-tree/tests/fixtures/gen_ct2_fixture.py`, `shekyl-wire/tests/vectors/capture_coinbase.py` | height | dict | unchanged |
| **GUI** (another repository) | `src-tauri/src/daemon_rpc.rs:97-123` (`GetInfoResponse`), `commands.rs:110-120`, `daemon_connection.rs:130-150`, `daemon_manager.rs:94`, `:185` (liveness) | height, target, top hash, difficulty, tx count, pool size, db size, version, synchronized, economics, `emission_era`, plus `stake_ratio` and `staker_pool_balance` | own struct | cannot move in this PR; each wire change names its GUI pair (RK-D22, §5.1) |

Nothing in this tree reads `emission_era`: the C++ handler writes it and
the struct serializes it, and that is all. Its readers are the GUI
(`src-tauri/src/daemon_rpc.rs:122-123`, `daemon_connection.rs:110`, `:156`,
`src/components/ChainHealthPanel.tsx:61`, `:103`, `src/types/daemon.ts:19`)
and the website consumer; both treat it as optional.

The website consumer from the RPC-channel incident is outside both trees;
its fields are listed in `RPC_CHANNEL.md` §6.1 at #1006's head ("What the
incident's consumer gets").

---

## 3. Defects the census found (live on `dev` at the ground commit)

### 3.1 The wallet derives "has peers" from fields a restricted daemon zeroes

`health_from_get_info` sums `outgoing_connections_count` and
`incoming_connections_count` (`synced_chain_facts.rs:695-708`). A restricted
listener writes `0` for both (`core_rpc_server.cpp:214-216`).

- **Submit watchdog.** `has_peers()` is checked **before** the sync check
  and the rung-1 resubmit probe (`submit_watchdog.rs:307-313`). Against a
  restricted daemon — a public remote node — a held send never gets its
  probe; it raises a false `DaemonPeerless` operator alarm instead. Rule 82:
  an alarm that is false is worse than none, and the probe it suppresses is
  the recovery.
- **P's tip poller** avoids this only by also reading `get_info.restricted`
  (`daemon_tip.rs:299`). `RPC_CHANNEL.md` §6.1 retires that field. Without
  RK-D14, every `view`-grant connection would read `NotFollowing::NoPeers`
  and P would stop serving.

### 3.2 Peer counts are clearnet-only and fed by two stores

§0's third and fourth bullets. A node whose sessions are all on Tor reports
`0` connections through `get_info`, and so the §3.1 consequences follow for
it on the **unrestricted** listener too. `has_peers` must therefore be read
from the seam board over every connector (§4.2), not derived from these
counts.

### 3.3 The GUI cannot decode a 3.42 reply

`GetInfoResponse.already_generated_coins` is `Option<String>`
(gui `daemon_rpc.rs:109`); #1005 emits a JSON number
(`KV_SERIALIZE(already_generated_coins)` over a `uint64_t`,
`core_rpc_server_commands_defs.h:265`, `:315`). The 3.41 reply decodes
because the field is absent; the 3.42 reply is a type error.
`get_wallet_status` maps the error to `connected: false`
(gui `commands.rs:121-129`); `get_chain_health` fails. **Not RK-5c's to
fix** — it needs a fix now, and its home is the `FOLLOWUPS.md` item this
document owns, blocked on RK-Q2. It is also RK-Q2's evidence, in one
direction only: the GUI expects a string for `already_generated_coins` and
a number for `total_burned` (gui `daemon_rpc.rs:116-117`), so RK-Q2 as
recommended repairs the first and moves the second (§5.1).

The GUI also reads `stake_ratio` and `staker_pool_balance` under
`#[serde(default)]` (gui `daemon_rpc.rs:114-119`). The daemon sends neither;
both render as a confident `0` (rule 82). Recorded for the GUI lane.

### 3.4 The GUI shows "daemon height 0" on every synchronized node

`daemon_height: info.target_height` (gui `commands.rs:119`). With the
sentinel, a synchronized daemon reports `0`. RK-D15 makes a synchronized
node with a target report that target, which this line then shows.

It does not finish the job without a GUI change. A node whose core reports
no target — peerless at startup — has no value to send. Under RK-Q7 as
recommended the field is omitted, and the GUI's `target_height: u64` is
required, so that reply would fail to decode and read as "disconnected".
The GUI pair for the RK-D15 commit makes the field optional and renders the
absence (§5.1).

---

## 4. Design — PROPOSED

### 4.1 Types (`shekyl-rpc-types`) — RK-D18

**RK-D18: one response type composed of named parts, flattened onto today's
wire.**

```text
GetInfoResponse {
    status: RpcStatus,
    #[serde(flatten)] health:    InfoHealth,               // grant: health
    #[serde(flatten)] identity:  InfoIdentity,             // grant: health; RK-Q6
    #[serde(flatten)] chain:     InfoChain,                // grant: chain
    #[serde(flatten)] economics: InfoEconomics,            // grant: chain; RK-D19
    #[serde(flatten)] pool:      InfoPool,                 // grant: pool
    #[serde(flatten)] status:    Hidden<InfoStatus>,       // grant: status
    #[serde(flatten)] peers:     Hidden<InfoPeers>,        // grant: peers
    restricted: bool,                                      // transitional, RT-W10
}
```

- Each part is seen under exactly one of the grants `RPC_CHANNEL.md` §6.1
  proposes (`health`, `chain`, `pool`, `status`, `peers`; §2.1). When
  RT-W10 lands, a grant selects parts; the handler is not rewritten, and
  the grant never crosses the FFI (RT-O9's last bullet dissolves).
- **The type says which parts a caller may be refused.** `Hidden<T>` is
  either the part or its absence; the two parts outside the `view` preset
  carry it and the rest cannot be withheld. What an absent part *writes* is
  the serializer's: today's stand-ins under parity, nothing once RK-Q8 is
  ruled. No handler code changes between the two.
- **One field, one value, even where the wire has two names.** Where today's
  wire repeats a value (`block_size_limit` / `block_weight_limit`, the
  difficulty triplets), the part holds the value **once** and the extra wire
  names are produced by its serializer. A second struct field for the same
  value is not allowed — that is the drift RK-D1 exists to prevent. Whether
  the extra names survive on the wire is RK-Q1.
- The caller's authority reaches the builder as a value, `Disclosure`, not
  as a boolean: today it has two inhabitants, `Full` and `View`, mapped
  from the listener flag, and RT-W10 supplies a richer one. Under parity,
  `View` withholds Status and Peers, written as the four restricted
  stand-ins of §0's second bullet, `alt_blocks_count` among the zeroed
  counts. `tx_pool_size` is not withheld under `View`; it counts relayed
  entries only. The `target_height` sentinel is **not** one of
  them: it does not depend on the caller, and RK-D15 retires it in this
  slice. RT-W10 replaces the input with the connection's grant. Replacing
  the stand-ins with absence (`RPC_CHANNEL.md` §6.1: "absent, never zero")
  is a wire change the sibling round asks of this slice; when it lands is
  RK-Q8.

### 4.2 Facts — RK-D3 / RK-D7, one snapshot per family

**RK-D20: the chain part is read in one snapshot that carries its own tip.**
One coarse export, `shekyl_rpc_info_chain_facts`, reads under one chain lock:
chain count, top hash, next difficulty (u128), cumulative difficulty at the
tip (u128), total transactions, weight limit and median, adjusted time,
coins generated at the tip, total burned, the tx-volume window (sum,
blocks), the NG activation height, and the alt-block count. Health's
`height` / `top_block_hash` come from **this** snapshot, never from a second
`shekyl_rpc_chain_tip` call, so a reply cannot pair one tip's hash with
another tip's difficulty. `synchronized` and the target come from the same
adapter call (`src/rpc/rpc_facts_ffi.cpp:1179-1186` is the pattern).

Behind traits (`InfoChainFacts`, `PoolFacts`, `PeerFacts`, `NodeFacts`),
with the FFI shim as today's only implementation:

| Trait | Facts | Notes |
| --- | --- | --- |
| `InfoChainFacts` | above | DRS-E's store implementation reads the same set; `database_size` and `free_space` are the chain store's on-disk size and the volume's free space, whatever the store |
| `PoolFacts` | pool count, full and broadcast-only | |
| `PeerFacts` | per-connector, per-direction session counts (feeding Health's `has_peers` and Status's two counts); peerlist sizes; per-connector socket counts | **Session counts from the seam board** (`shekyl_seam_board_count`), the one store; no subtraction. Whether `daemon-rpc` reads the hub directly or through the FFI is an implementation detail for rule 25 |
| `NodeFacts` | offline, busy syncing, following degraded, start time, free space, database size | |

`rpc_connections_count` is the Rust connection tracker read natively; the
two JSON-patch sites (`handlers/json.rs:82-100`, `json_rpc.rs:136-146`) are
deleted.

`has_peers` = at least one **handshaken** session on any connector. The
board export does not read the handshake flag today
(`rust/shekyl-ffi/src/seam_board_ffi.rs:69-74`); the facts read needs the
handshaken count (RK-Q4).

### 4.3 Economics — RK-D19

**RK-D19: one projection function in `shekyl-economics` produces the
economics part from typed inputs.** The handler calls it and does nothing
else with economics.

- Inputs: coins generated at the tip, total burned, tx-volume window, chain
  height, NG activation height — all from the §4.2 snapshot.
- Output: a domain struct in `shekyl-economics` with five fields; the wire
  part in `shekyl-rpc-types` converts from it (rule 18: the wire type lives
  with the wire). Adding a field is a change to those two structs and a
  `CORE_RPC_VERSION` bump. The handler, facts and FFI do not move. That is
  the "flexible" the ruling asks for.
- The three C functions the handler calls today
  (`shekyl_calc_release_multiplier`, `shekyl_calc_burn_pct_at`,
  `shekyl_calc_emission_share`) are already Rust; the projection calls them
  directly.
- **No era.** RK-D21 deletes `emission_era` before this function is
  written. The projection takes no asymptote, cuts no thresholds and
  returns no label.
- The burn-refusal path (`:280-287`) keeps its behaviour: the field reports
  `0` and the refusal is logged. Whether that `0` should become absence is
  the economics lane's question, not this slice's.

### 4.4 Oracle capture for a handler that computes

Prior slices captured vectors by serializing a response built from fixed
facts (`tests/vectors/rpc/README.md`). For `get_info` that pins only the
serializer: the policy in §0 would not be exercised, and #1005's new test
(`tests/unit_tests/rpc_target_wire_contract.cpp:116-138`) has exactly that
limitation — it says so in its own comment.

So the capture commit extracts the C++ handler's computation into a pure
`build_get_info(facts, restricted)` that `on_get_info` calls after reading
its facts. It is behaviour-preserving, exists only to be captured, and is
deleted with the handler (the same lifecycle as each slice's
`rpc_oracle_vectors.cpp`). It is extracted **after** RK-D21's deletion, so
no vector carries `emission_era`. Fixtures:

| Fixture | Exercises |
| --- | --- |
| synced, unrestricted | the sentinel (`target_height = 0`), full disclosure |
| syncing, unrestricted | real target |
| peerless startup (target 0, not synchronized) | the case the sentinel collides with |
| synced, restricted | each of the four restricted stand-ins in §0, `alt_blocks_count` included |
| burn refusal (`total_burned > already_generated`) | the logged-zero path |

---

## 5. Commit plan — PROPOSED (one PR; each commit bisects)

| # | Commit | Gate |
| --- | --- | --- |
| 0 | This document + index row (rule 94) + §2 row note in the parent + the `FOLLOWUPS.md` item for §3.3 | docs gates |
| 1 | **Origin-guard re-anchor** on `include_sensitive`, own diff, before the route leaves (parent §5 row; needs the two-node regtest the row names) | regtest |
| 2 | **RK-D21:** `emission_era` deleted — the struct field and its `KV_SERIALIZE` (`core_rpc_server_commands_defs.h:270`, `:320`), the computation (`core_rpc_server.cpp:294-302`), and the "Emission Era" row of `docs/DESIGN_CONCEPTS.md:673` | `CORE_RPC_VERSION` bump; `git grep emission_era` → this document and CHANGELOG only |
| 3 | **Capture:** `build_get_info` extraction + oracle vectors for §4.4's fixtures | C++ unit + vectors committed |
| 4 | **Native port at parity:** types (§4.1), facts export + layout twin (§4.2), economics projection (§4.3), handler, both routes and the JSON-RPC name native; Rust parity test green against commit 3's vectors; all in-tree readers in §2.2 onto the shared type (RK-D1); console readers ported (RK-D5), four bridged legs closed; RK-D9 re-pin of `target` and a value-shaped `already_generated_coins` test against the snapshot; `following_degraded` value-shaped test (C2-R1 obligation) | parent §4 gate |
| 5 | **Delete C++:** `on_get_info`, `on_get_info_json`, `COMMAND_RPC_GET_INFO`, three dispatch rows (`src/rpc/core_rpc_ffi.cpp:174-175`, `:268`), `build_get_info`, the `get_info` cases in `rpc_target_wire_contract.cpp` (`check_core_ready` stays: `:636` and `:727` still call it) | `git grep COMMAND_RPC_GET_INFO` → this doc and CHANGELOG only |
| 6 | **RK-D15:** sentinel retired; wallet predicate simplified; CLI `show_chain` reads `synchronized`; the "`get_info` still writes `0`" statements corrected (§6) | `CORE_RPC_VERSION` bump; `_v2` derived from `_v1` (README rule); GUI pair (§5.1) |
| 7 | **RK-D14:** `has_peers` in health; watchdog and P's poller switch to it; `daemon_tip` stops reading `restricted`; fixes §3.1 | bump; a test that a restricted reply with peers yields no `DaemonPeerless` and no `NoPeers` |
| 8+ | Each of RK-Q1, Q2, Q3, Q6, Q8 as ruled, one commit each | bump each; GUI pair where §5.1 names one |

Commit 2 changes the wire before parity and commits 6–8 change it after,
each deliberately and each in its own diff — the RK-4c / RK-5b precedent
(parent RK-D8). Commit 2 goes first because the alternative is to capture,
port and parity-test a field whose ruling is deletion.

### 5.1 The GUI pair — RK-D22

**RK-D22: a commit that changes a field the GUI decodes names the GUI
change it needs, and the GUI change is opened against that commit before
the core PR leaves draft.** The GUI is another repository, so RK-D1's
"readers move in the same diff" cannot hold for it; this is the substitute.
The GUI's fields are read at `447908f` (`src-tauri/src/daemon_rpc.rs:97-123`).

| Core commit | Wire change | GUI today | GUI change needed |
| --- | --- | --- | --- |
| 2 (RK-D21) | `emission_era` gone | `#[serde(default)] String`; the panel renders it only when non-empty | none to keep decoding; the dead field, its type and the two panel blocks are deleted |
| 6 (RK-D15) | `target_height` is the core's target, omitted when there is none (RK-Q7) | required `u64`, shown as "daemon height" | optional; absence rendered as no target, not `0` |
| 8+ (RK-Q1) | `difficulty` and `difficulty_top64` retired, `wide_difficulty` kept | required `difficulty: u64` | reads `wide_difficulty` (decimal string) |
| 8+ (RK-Q2) | `already_generated_coins`, `total_burned` become decimal strings | `Option<String>` and `u64` | `total_burned` becomes a string; the first already is |
| 8+ (RK-Q6) | `nettype` and the three booleans retired | not read | none |
| 8+ (RK-Q8) | a restricted reply omits Status and Peers | required `database_size: u64` and `version: String` | both optional; a remote node that withholds them renders as withheld, not as an empty version and a rounded size |

The other in-tree-external reader, the website consumer, is the RPC-channel
round's (`RPC_CHANNEL.md` §6.1 at #1006's head).

---

## 6. Obligations RK-5c discharges (owed from elsewhere)

| Obligation | Owed by | Commit |
| --- | --- | --- |
| `following_degraded` migrates with a value-shaped test | C2-R1 (`docs/completed/CONSENSUS_C2_R1_REORG.md:854-860`) | 4 |
| `get_info.nettype` kept or retired | VC (`CLIENT_VERSION_CONSTANTS_VALIDATION.md:479-486`) | RK-Q6 |
| `rpc_connections_count` literal and the two JSON patches | parent §2 / `core_rpc_server.cpp:223-230` | 4–5 |
| Origin guard re-anchor before the route leaves | parent §5 | 1 |
| Four bridged `get_info` console legs | parent §5 | 4 |
| `target` re-pinned as a value (RK-D9) | parent §1 | 4 |
| Wallet sync predicate simplification | #792 / WSS-Q14 | 6 |
| "`get_info` still writes `0` when synchronized" — the `HEIGHT_SEMANTICS.md` index row and the comment at `rust/shekyl-daemon-rpc/src/chain_facts.rs:112-116` | height-semantics Phase 2f | 6 |
| CLI `DaemonInfo` and engine `GetInfoResp` duplicates retired | RK-D1 | 4 |

---

## 7. What this slice does not do

- **Grants.** RT-W10 replaces `Disclosure`'s two inhabitants with the
  connection's grant. RK-5c makes that a selection of parts and threads no
  grant through C++.
- **`status` as an error channel**, positional params, aliases (`/getinfo`):
  RK-W.
- **Economics fields' meaning.** The EUP lane owns them (RK-D16). RK-D21 is
  not an exception: it deletes a field whose idea was already retired, and
  changes no parameter and no surviving field.
- **The GUI fix** for §3.3: needed now, independently, and tracked in
  `FOLLOWUPS.md`.

---

## 8. Open questions for ratification — OPEN

| ID | Question (OPEN) | Recommendation |
| --- | --- | --- |
| **RK-Q1** | **Duplicate wire names** — `block_size_limit`/`block_weight_limit`, `block_size_median`/`block_weight_median`, `difficulty` + `wide_difficulty` + `difficulty_top64` (and the cumulative triplet). Retire the extras in RK-5c (commit 8+) or leave them to RK-W? | **RK-5c.** One value already has one source internally (RK-D18); keeping several wire names for it is the same mess one layer up, and RK-W's reason to wait — redesign once — doesn't apply to a pure deletion. Keep `wide_*` (the u128 decimal string) and the `weight` names. Costs the GUI its `difficulty: u64` (§5.1). |
| **RK-Q2** | **Atomic-unit encoding.** `already_generated_coins` and `total_burned` exceed 2^53 once about 9.0M coins have been emitted (asymptote 4.29·10¹⁸, `config/economics_params.json:3`); a JSON number loses precision in every JS reader. The wallet RPC already encodes amounts as decimal strings (`docs/api/wallet_rpc.yaml:1419-1425`). | **Decimal string, one `AtomicUnits` wire encoding for both RPCs.** This changes how two economics fields are written, not what they mean, so it sits inside RK-D16 as worded; if RK-D16 is meant to cover encoding too, this question is the EUP lane's. The GUI already expects a string for `already_generated_coins` and a number for `total_burned` (§3.3, §5.1). |
| **RK-Q3** | **Peer counts** — the per-direction counts become sums over every connector from the board, or stay clearnet-only? | **Every connector.** Today's clearnet-only value is not a decision anyone made; it is `get_public_*` surviving the zone deletion. Per-connector detail stays in the socket counts. |
| **RK-Q4** | **`has_peers` = a handshaken session, or any board row?** | **Handshaken.** A row before handshake cannot relay, which is what every reader asks. |
| **RK-Q5** | `restricted` stays until RT-W10? | **Yes.** It is RT-W10's to retire; P's poller stops depending on it in commit 7. |
| **RK-Q6** | **`nettype`, `mainnet`, `testnet`, `stagenet`** duplicate `get_version.nettype`, the identity source (VC-2). Retire all four from `get_info`? | **Retire.** Readers move to `get_version`: the CLI mining gate (`mine.rs`, network match), the console (`testnet`/`stagenet`). |
| **RK-Q7** | **How is an absent target written?** RK-D15 says the target is the core's target or absent, and does not say what absent looks like on the wire. | **Omitted, exactly as `get_version` writes it** (`rust/shekyl-rpc-types/src/chain.rs:390-393`: `0` and omitted only when the core reported none). One fact, one encoding on every method that carries it. The cost is the GUI's required `target_height` (§3.4, §5.1). |
| **RK-Q8** | **When do the restricted stand-ins become absence?** The sibling round asks that a part the caller may not see is absent from the reply, not zeroed. Parity keeps the stand-ins; the type already distinguishes the two (§4.1). | **In RK-5c, after RK-D14** (commit 8+). The stand-ins are the defect §3.1 traces — `0` peers that means "not told" — and once `has_peers` exists no in-tree reader depends on them. Leaving the flip to RT-W10 would have that slice change a wire it otherwise only re-keys. Costs the GUI two required fields (§5.1). |
