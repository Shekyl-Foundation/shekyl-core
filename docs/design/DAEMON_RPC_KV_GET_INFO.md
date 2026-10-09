# RK-5c — `get_info`, the hub: rule-26 pre-flight

**Status:** OPEN — R0, **RATIFIED 2026-10-09** (Rick); implementation open,
starting at commit 1 of §5. Drafted 2026-10-08. §1's rulings
are recorded as ruled; **RK-Q1…RK-Q9 were ruled 2026-10-09** and RK-Q10
2026-10-08, confirmed 2026-10-09 (§8).
**Ground:** `shekyl-core` `dev` **`98fbd20ac`** (#1005 merge, 2026-10-08);
`shekyl-gui-wallet` `dev` **`447908f`**. Every `file:line` below was read at
those commits. Open work on the hard-fork mechanism's deletion also edits
`on_get_info`; if it merges first, the handler's line numbers move and the
content cited does not.
**Parent:** [`DAEMON_RPC_KV_CUTOVER.md`](DAEMON_RPC_KV_CUTOVER.md) §2 row
RK-5c, §2.1.1, §5. Family `RK-` (registered); this document mints
**RK-D13…RK-D23** (decisions) and **RK-Q1…RK-Q10** (open questions) inside
it, added to the family's index row in the commit that lands this file
(rule 94).
**Sibling round:** [`RPC_CHANNEL.md`](RPC_CHANNEL.md), round R1. Its §6.1
is cited here **at #1006's head `28e485ce9`**, which is not merged: `dev`
carries an earlier R1 text. Three things this document relies on exist
only at that head — the phrase "absent, never zero", the paragraph "What
the incident's consumer gets", and the ruling that RK-5c lands before
RT-W10. If #1006 changes them before it merges, this document follows.
The grant assigned to each part in §2.1 is that head's table. Four
rulings are recorded there as RULED 2026-10-08 (its RT-O9.1…RT-O9.4); one of them,
RT-O9.3, reaches this document: unrelayed pool entries are **host-only data**,
served to the host's administrator and to no grant, `admin` included
(§4.1, RK-Q10).
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
  value that means "not this value" — the same defect as the sentinel
  above, not a second kind. `free_space = u64::MAX` is the plainest case:
  a number standing where RK-D23 puts an absence. RK-Q8 removes all four.
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
- **One key, two quantities.** `tx_pool_size` is
  `get_pool_transactions_count(!restricted)` (`:212`): relayed entries for
  a restricted caller, relayed plus not-yet-relayed for any other. The
  caller changes what the number counts, not whether it is shown.
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
| **RK-D23** | **`0` is a value; "no result" is `None` / `null`.** Zero is a valid answer for most quantities, so using it to mean "there is no answer" is ambiguous. In Rust the absence is `Option`; on the JSON wire it is `null`. This is RK-D15's principle stated generally, and it decides how every absence in this slice is written (§4.1, RK-Q7). RK-Q9 is the case it does not cover: a refused computation is a fault, not an absence. A standing rule for it is being drafted separately; this document cites RK-D23 either way. |

RK-D15's "or absent" was written before RK-D23. It means the core has no
target, which RK-D23 and RK-Q7 write as `null`; it does not mean the field
is left off the reply.

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
| **Pool** → `pool` | `tx_pool_size` | pool facts. **Two quantities under one key today** — relayed entries for a restricted caller, relayed plus unrelayed for any other (RK-Q10) | `:212`, `get_pool_transactions_count(!restricted)` |
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
| Regtest e2e | `engine/regtest_e2e.rs:401-443` | `GetInfoResp` (local struct): `version` (`:430-435`, a Status field) and `tx_pool_size` (`:439-444`) among them | local struct | shared type; a host caller, so it keeps Status and the unrelayed count (RK-Q10) |
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
(gui `commands.rs:121-129`); `get_chain_health` fails.

**No interim fix (Rick, 2026-10-08).** The repair is RK-Q2's commit in
this slice, with its GUI pair. Until it lands the GUI cannot read a
post-#1005 daemon; that is accepted, because testnet is not exercising the
GUI now. The two interim fixes were both refused as churn: editing the C++
handler this slice deletes to write one field as a string, or having the
GUI accept a number and then switch back. The `FOLLOWUPS.md` item this
document owns tracks it until then.

The failure is also RK-Q2's evidence, in one
direction only: the GUI expects a string for `already_generated_coins` and
a number for `total_burned` (gui `daemon_rpc.rs:116-117`), so RK-Q2
repairs the first and moves the second (§5.1).

The GUI also reads `stake_ratio` and `staker_pool_balance` under
`#[serde(default)]` (gui `daemon_rpc.rs:114-119`). The daemon sends neither;
both render as a confident `0` (rule 82). Recorded for the GUI lane.

### 3.4 The GUI shows "daemon height 0" on every synchronized node

`daemon_height: info.target_height` (gui `commands.rs:119`). With the
sentinel, a synchronized daemon reports `0`. RK-D15 makes a synchronized
node with a target report that target, which this line then shows.

It does not finish the job without a GUI change. A node whose core reports
no target — peerless at startup — has no value to send. Under RK-Q7 the
field is `null`, and the GUI's `target_height: u64` is
required, so that reply would fail to decode and read as "disconnected" —
as it would on an omitted field. The GUI pair for the RK-D15 commit makes
the field `Option<u64>` and renders `null` as no target (§5.1).

---

## 4. Design — RATIFIED 2026-10-09

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
    #[serde(flatten)] node:      Hidden<InfoStatus>,       // grant: status
    #[serde(flatten)] peers:     Hidden<InfoPeers>,        // grant: peers
    restricted: bool,                                      // transitional, RT-W10
}
```

- `status` is the reply's `RpcStatus`, as on every method; the node-status
  part is the field `node`, of type `InfoStatus`, and is flattened, so its
  name never reaches the wire.
- Each part is seen under exactly one of the grants `RPC_CHANNEL.md` §6.1
  proposes (`health`, `chain`, `pool`, `status`, `peers`; §2.1). When
  RT-W10 lands, a grant selects parts; the handler is not rewritten, and
  the grant never crosses the FFI (RT-O9's last bullet dissolves).
- **The type says which parts a caller may be refused.** `Hidden<T>` is
  either the part or its absence; the two parts outside the `view` preset
  carry it and the rest cannot be withheld. What an absent part *writes* is
  the serializer's: today's stand-ins under parity, nothing from RK-Q8's commit
  on. No handler code changes between the two.
- **One field, one value, even where the wire has two names.** Where today's
  wire repeats a value (`block_size_limit` / `block_weight_limit`, the
  difficulty triplets), the part holds the value **once** and the extra wire
  names are produced by its serializer. A second struct field for the same
  value is not allowed — that is the drift RK-D1 exists to prevent. Whether
  the extra names survive on the wire was RK-Q1: they do not.
- The caller's authority reaches the builder as a value, `Disclosure`, not
  as a boolean, and it has **two axes**: which parts the caller's grants
  select, and whether the caller is the **host's administrator**. The
  second is not a grant and no grant implies it (`RPC_CHANNEL.md` §6.1,
  "Two classes that are not grants", RT-O9.3): it is what admits host-only
  data, which on this reply is the unrelayed pool count. Naming the axis
  now is what stops RT-W10 from reading "`admin`" as "may see unrelayed
  entries". Today both axes are mapped from the one listener flag — the
  unrestricted listener is every part plus host, the restricted listener
  is the `view` parts and not host — written below as `Full` and `View`;
  RT-W10 maps a grant set and a host flag onto the same value. Under
  parity,
  `View` withholds Status and Peers, written as the four restricted
  stand-ins of §0's second bullet, `alt_blocks_count` among the zeroed
  counts. `tx_pool_size` is not withheld under `View`, but under parity it
  is not one quantity either: `View` counts relayed entries and `Full`
  adds the unrelayed ones. That is one key whose meaning depends on who
  asks, which the governing principle forbids; RK-Q10 splits it. The
  difference between the two counts is the host axis, not a part.
  them: it does not depend on the caller, and RK-D15 retires it in this
  slice. RT-W10 replaces the input with the connection's grant. Replacing
  the stand-ins with absence (`RPC_CHANNEL.md` §6.1: "absent, never zero")
  is a wire change the sibling round asks of this slice; when it lands is
  RK-Q8.

#### Two wire types that keep the three states apart

serde's defaults merge the states the table below separates, in both
places this reply needs them distinct.

- **`Nullable<T>` — required, and may be `null`.** `Option<T>` decodes a
  `null` field and a **missing** field to the same `None`, so a field
  dropped by contract drift would read as "no answer". That is the
  fail-open the wallet decoder guards against by hand
  (`rust/shekyl-engine-core/src/engine/daemon/synced_chain_facts.rs:677-690`).
  `Nullable<T>` lives in `shekyl-rpc-types`; its deserializer **errors on
  a missing key** and maps `null` to `None`, and it always serializes the
  key. Every field RK-D23 makes nullable uses it. A bare `Option<T>` with
  serde's default is not allowed on a reply field whose absence means
  something different from its nullness.
- **`Hidden<T>` — a part is wholly present or wholly absent.** A
  flattened optional struct decodes to `None` whenever the struct cannot
  be built from the keys that remain, so a Status part that arrives with
  **one** field missing would read as "withheld" with no error — contract
  drift turned into a grant decision. `Hidden<T>`'s deserializer returns
  `None` only when **none** of `T`'s keys are present, `Some` when all
  are, and an error otherwise.

Both are tested per field in commit 4: `{}` fails and `{"f": null}`
decodes for each `Nullable` field; a full reply with one Status key
removed, and one with one Peers key removed, is an error and not `None`.

#### The three wire states — RK-D23

A field on this reply is in exactly one of three states, and each means one
thing:

| On the wire | Meaning |
| --- | --- |
| a value, including `0` | the answer |
| `null` | there is no answer (the core has no target) |
| field absent | not disclosed to this caller (a `Hidden` part) — or, for any other field, contract drift |

A refusal is none of the three. A computation that refuses because the
store contradicts itself is an error and the method does not reply
(RK-Q9); it is not a value state of a field.

Parity (commit 4) does not have these yet: it writes today's sentinel and
stand-ins. Each later commit that changes the wire moves fields onto this
table, and none moves a field off it.

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
| `PeerFacts` | per-connector, per-direction session counts (feeding Health's `has_peers` and Status's two counts); peerlist sizes; per-connector socket counts | **Session counts from the seam board**, the one store; no subtraction. **Every read returns `Result<_, FactsFault>`, never a bare `u64`** (below). Whether `daemon-rpc` reads the hub directly or through new exports is an implementation detail for rule 25 |
| `NodeFacts` | offline, busy syncing, following degraded, start time, free space, database size | |

`rpc_connections_count` is the Rust connection tracker read natively; the
two JSON-patch sites (`handlers/json.rs:82-100`, `json_rpc.rs:136-146`) are
deleted.

`has_peers` = at least one **handshaken** session on any connector. The
board export does not read the handshake flag today
(`rust/shekyl-ffi/src/seam_board_ffi.rs:69-74`); the facts read needs the
handshaken count (RK-Q4).

**A missing hub is a fault, not zero peers.** Today's exports cannot say
so. `shekyl_seam_board_count` returns `0` for a missing hub, `0` for an
index that is not a connector or a direction, and `u64::MAX` when the
count does not fit (`seam_board_ffi.rs:69-85`);
`shekyl_seam_socket_count` returns `0` for the same three cases
(`rust/shekyl-ffi/src/seam_ffi.rs:526-539`). Read through them, a daemon
whose hub is not up would report `has_peers = false` — the false
`DaemonPeerless` of §3.1, rebuilt one layer down (RK-D23: that `0` is not
an answer). So `PeerFacts` distinguishes them: a missing hub is a
`FactsFault` (`rust/shekyl-daemon-rpc/src/chain_facts.rs:196`); zero
sessions is `Ok(0)`; an index that is not a connector or direction is a
programming error at the call site and is not representable as a count.

**The type lands at parity; the refusal does not.** The C++ handler
answers a missing hub with zero counts and status OK, so a native handler
that refused in commit 4 would differ from the oracle on a state no
vector can express — a behaviour change inside the parity commit, which
RK-D13 and the parent's RK-D8 forbid. In commit 4 `PeerFacts` already
returns `Result`, and the handler maps the missing-hub fault to today's
zeros in one named arm, as the serializer writes today's stand-ins. Commit
7 deletes that arm: it is the commit that introduces `has_peers`, the
first field for which the zero is a false answer, and it carries the
version bump. From there a missing hub makes `get_info` refuse.

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
- The burn-refusal path (`:280-287`) keeps its behaviour through parity:
  the field reports `0` and the refusal is logged. `0` % is a legitimate
  burn, so that reply cannot be told from an answer. After parity the
  refusal is a **store fault** (RK-Q9): the projection checks the supply
  invariant on the snapshot and returns the violation, the handler maps
  it to the fault, and `get_info` refuses with an error that names the
  invariant and its operands. `burn_pct` is never `null`.

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
| burn refusal (`total_burned > already_generated`) | the logged-zero path — kept so parity matches; RK-Q9's commit replaces the behaviour |

One case is not an oracle vector, because the C++ handler cannot express
it — it reads the same zero-on-missing exports. It is a pair of Rust
handler tests, one on each side of the behaviour change (§4.2):

| Rust-only case | Commit | Asserts |
| --- | --- | --- |
| hub absent, parity | 4 | `PeerFacts` returns a `FactsFault`; the handler's parity arm answers the zero counts the C++ handler answers |
| hub absent, refusal | 7 | the parity arm is gone: `get_info` refuses, and does not answer `has_peers = false` or zero counts |

---

## 5. Commit plan — RATIFIED 2026-10-09 (one PR; each commit bisects)

| # | Commit | Gate |
| --- | --- | --- |
| 0 | This document + index row (rule 94) + §2 row note in the parent + the `FOLLOWUPS.md` item for §3.3 | docs gates |
| 1 | **Origin-guard re-anchor** on `include_sensitive`, own diff, before the route leaves (parent §5 row). **This commit builds the two-node rig; it does not reuse one** — none exists on `dev`, and the parent's 2026-08-27 entry records the single-node form passing one run in three. The rig's verdict must be deterministic, and the commit states how: what holds the transaction in the stem or embargo window for the whole of the assertion | the two-node regtest, green on repeated runs |
| 2 | **RK-D21:** `emission_era` deleted — the struct field and its `KV_SERIALIZE` (`core_rpc_server_commands_defs.h:270`, `:320`), the computation (`core_rpc_server.cpp:294-302`), and the "Emission Era" row of `docs/DESIGN_CONCEPTS.md:673` | `CORE_RPC_VERSION` bump; `git grep emission_era` (the identifier, not the era names) → this document and CHANGELOG only. The era names also label the phases of the burn-rate table at `docs/DESIGN_CONCEPTS.md:299-303`; that table is not the field and is out of this commit's scope |
| 3 | **Capture:** `build_get_info` extraction + oracle vectors for §4.4's fixtures | C++ unit + vectors committed |
| 4 | **Native port at parity:** types (§4.1), facts export + layout twin (§4.2), economics projection (§4.3), handler, both routes and the JSON-RPC name native; Rust parity test green against commit 3's vectors; all in-tree readers in §2.2 onto the shared type (RK-D1); console readers ported (RK-D5), four bridged legs closed; RK-D9 re-pin of `target` and a value-shaped `already_generated_coins` test against the snapshot; `following_degraded` value-shaped test (C2-R1 obligation) | parent §4 gate; the `Nullable` missing-key and `Hidden` partial-part tests of §4.1; the hub-absent parity test of §4.4 |
| 5 | **Delete C++:** `on_get_info`, `on_get_info_json`, `COMMAND_RPC_GET_INFO`, three dispatch rows (`src/rpc/core_rpc_ffi.cpp:174-175`, `:268`), `build_get_info`, the `get_info` cases in `rpc_target_wire_contract.cpp` (`check_core_ready` stays: `:636` and `:727` still call it) | `git grep COMMAND_RPC_GET_INFO` → this doc and CHANGELOG only |
| 6 | **RK-D15:** sentinel retired on `get_info`; under RK-Q7, `target_height` becomes nullable on `get_info`, `get_version` and `sync_info` together, and `get_version.current_height` stops being omitted when zero; wallet predicate simplified; CLI `show_chain` reads `synchronized`; the "`get_info` still writes `0`" statements corrected (§6) | one `CORE_RPC_VERSION` bump; a `_vN` vector for each of the three methods, derived from its predecessor (README rule); GUI pair (§5.1) |
| 7 | **RK-D14:** `has_peers` in health; watchdog and P's poller switch to it; `daemon_tip` stops reading `restricted`; fixes §3.1; the handler's missing-hub parity arm is deleted, so a missing hub refuses (§4.2) | bump; a test that a restricted reply with peers yields no `DaemonPeerless` and no `NoPeers`; the hub-absent refusal test of §4.4 |
| 8+ | Each of RK-Q1, Q2, Q3, Q6, Q8, Q9, Q10 as ruled, one commit each | bump each; GUI pair where §5.1 names one |

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
| 6 (RK-D15) | `target_height` is the core's target, `null` when there is none (RK-Q7) | required `u64`, shown as "daemon height" | `Option<u64>`; `null` rendered as no target, not `0` |
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
| `get_version` and `sync_info` still encode "no target" as an omitted or zero `target_height` (`rust/shekyl-rpc-types/src/chain.rs:386-393`, `p2p.rs:280-283`) | RK-D23 | 6 |
| "`get_info` still writes `0` when synchronized" — the `HEIGHT_SEMANTICS.md` index row and the comment at `rust/shekyl-daemon-rpc/src/chain_facts.rs:112-116` | height-semantics Phase 2f | 6 |
| CLI `DaemonInfo` and engine `GetInfoResp` duplicates retired | RK-D1 | 4 |

---

## 7. What this slice does not do

- **Grants.** RT-W10 maps the connection's grant set and its host flag
  onto `Disclosure`, in place of today's listener flag. RK-5c makes that a selection of parts and threads no
  grant through C++.
- **`status` as an error channel**, positional params, aliases (`/getinfo`):
  RK-W.
- **Economics fields' meaning.** The EUP lane owns them (RK-D16). RK-D21 is
  not an exception: it deletes a field whose idea was already retired, and
  changes no parameter and no surviving field.
- **An interim fix for §3.3.** The GUI stays unable to read a post-#1005
  daemon until RK-Q2's commit; ruled acceptable (§3.3).

---

## 8. Questions — RK-Q1…RK-Q9 RULED 2026-10-09, RK-Q10 RULED 2026-10-08 (Rick)

RK-Q1…RK-Q8 were ruled as recommended, in one pass, and RK-Q10 as
recommended; the reasoning beside each is the recommendation's, kept as
the record of why. RK-Q9 was held back from that pass and ruled
separately, against the first recommendation.

| ID | Question | Ruling |
| --- | --- | --- |
| **RK-Q1** | **Duplicate wire names** — `block_size_limit`/`block_weight_limit`, `block_size_median`/`block_weight_median`, `difficulty` + `wide_difficulty` + `difficulty_top64` (and the cumulative triplet). Retire the extras in RK-5c (commit 8+) or leave them to RK-W? | **RULED 2026-10-09 (Rick).** **RK-5c.** One value already has one source internally (RK-D18); keeping several wire names for it is the same mess one layer up, and RK-W's reason to wait — redesign once — doesn't apply to a pure deletion. Keep `wide_*` (the u128 decimal string) and the `weight` names. Costs the GUI its `difficulty: u64` (§5.1). |
| **RK-Q2** | **Atomic-unit encoding.** `already_generated_coins` and `total_burned` exceed 2^53 once about 9.0M coins have been emitted (asymptote 4.29·10¹⁸, `config/economics_params.json:3`); a JSON number loses precision in every JS reader. The wallet RPC already encodes amounts as decimal strings (`docs/api/wallet_rpc.yaml:1419-1425`). | **RULED 2026-10-09 (Rick).** **Decimal string, one `AtomicUnits` wire encoding for both RPCs.** This changes how two economics fields are written, not what they mean, so it sits inside RK-D16; the ruling places it in this slice. There is no interim fix for the GUI before this commit (§3.3). The GUI already expects a string for `already_generated_coins` and a number for `total_burned` (§3.3, §5.1). |
| **RK-Q3** | **Peer counts** — the per-direction counts become sums over every connector from the board, or stay clearnet-only? | **RULED 2026-10-09 (Rick).** **Every connector.** Today's clearnet-only value is not a decision anyone made; it is `get_public_*` surviving the zone deletion. Per-connector detail stays in the socket counts. |
| **RK-Q4** | **`has_peers` = a handshaken session, or any board row?** | **RULED 2026-10-09 (Rick).** **Handshaken.** A row before handshake cannot relay, which is what every reader asks. |
| **RK-Q5** | `restricted` stays until RT-W10? | **RULED 2026-10-09 (Rick).** **Yes.** It is RT-W10's to retire; P's poller stops depending on it in commit 7. |
| **RK-Q6** | **`nettype`, `mainnet`, `testnet`, `stagenet`** duplicate `get_version.nettype`, the identity source (VC-2). Retire all four from `get_info`? | **RULED 2026-10-09 (Rick).** **Retire.** Readers move to `get_version`: the CLI mining gate (`mine.rs`, network match), the console (`testnet`/`stagenet`). |
| **RK-Q7** | **How is an absent target written?** RK-D15 says the target is the core's target or absent, and does not say what absent looks like on the wire. The fact already has two encodings: `get_version` omits it when the core reports none and every Rust reader decodes the omission back to `0` (`rust/shekyl-rpc-types/src/chain.rs:390-393`), and `sync_info` writes a bare `0` (`rust/shekyl-rpc-types/src/p2p.rs:280-283`). Both are the sentinel, relocated. | **RULED 2026-10-09 (Rick).** **`null`, on all three methods** (RK-D23). `target_height` is `Option<ChainCount>` in Rust and `null` on the wire when the core reports none, on `get_info`, `get_version` and `sync_info`, all in commit 6. One fact, one encoding — and not the encoding either method has today. `get_version.current_height` (`chain.rs:386-389`, the same omit-when-zero) is folded into that commit so `get_version` carries no zero sentinel. The cost is the GUI's required `target_height` (§3.4, §5.1). **`get_version` is the compatibility endpoint**: a client reads it to learn whether it can talk to this daemon at all, so its shape change ships whole — one commit, one bump, every in-tree decoder with it, and the GUI pair opened against that commit — never piecemeal. A client older than the bump fails to decode the reply instead of reading a version it could report as too new; whether the version fields must stay decodable on their own is a failure-mode point (rule 82) the ruling did not address; it is settled in commit 6's design, before that commit is written. |
| **RK-Q8** | **When do the restricted stand-ins become absence?** The sibling round asks that a part the caller may not see is absent from the reply, not zeroed. Parity keeps the stand-ins; the type already distinguishes the two (§4.1). | **RULED 2026-10-09 (Rick).** **In RK-5c, after RK-D14** (commit 8+). The stand-ins are the defect §3.1 traces — `0` peers that means "not told" — and once `has_peers` exists no in-tree reader depends on them. Leaving the flip to RT-W10 would have that slice change a wire it otherwise only re-keys. Costs the GUI two required fields (§5.1). |
| **RK-Q9** | **How is a refused burn computation written?** `shekyl_calc_burn_pct_at` refuses when `total_burned` exceeds `already_generated_coins`; the reply then carries `burn_pct = 0` and the refusal is logged (`core_rpc_server.cpp:280-287`). `0` % is a legitimate burn. | **RULED 2026-10-09 (Rick). A refused burn computation is a store fault, and the refusal is verbose.** Not as first recommended (`null`), and not part of the batch ruling: this question was held back. The only reachable refusal is the supply invariant, `total_burned > coins_generated` (`rust/shekyl-ffi/src/economics_ffi.rs:204-226`; the null-out arm is a caller bug). That is the store contradicting itself — the class `FactsFault::Inconsistent` exists for (`rust/shekyl-daemon-rpc/src/chain_facts.rs:205-217`: a contradiction with a plausible-looking fallback that must not reach the caller as a fact). It is not "no answer". **(1)** The economics projection checks the invariant on the RK-D20 snapshot and returns the violation; the handler maps it to the store fault and `get_info` refuses. No partial reply. **(2)** Verbose: the refusal the caller receives names the violated invariant and carries its operands — coins generated, total burned, and the tip the snapshot was read at. All three are public chain facts the reply already carries, so nothing is disclosed that a successful reply would not show. The same text is logged. `FactsFault` is `Copy` with a payload-free `Inconsistent` today; whether the detail rides a payload on that variant or a dedicated variant is the implementation's call — the requirement is that the caller's error says what contradicted what. **(3)** `burn_pct` stays a plain number, never `null`. **(4)** Its own commit after parity (8+). The capture keeps its "burn refusal → logged zero" fixture so parity matches; this commit replaces that behaviour, and its test is Rust-side: a snapshot with `total_burned > coins_generated` makes `get_info` refuse with an error naming the invariant and all three operands. |
| **RK-Q10** | **`tx_pool_size` carries two quantities.** Raised from the RPC-channel round's review of this document. Split it? | **RULED 2026-10-08 (Rick; given through the RPC-channel lane and confirmed in this lane 2026-10-09).** **Split, in commit 8+.** `tx_pool_size` counts relayed entries only and is a value for every caller, in `pool`. The unrelayed count is its own field in its own one-field `Hidden` part, present only for the host's administrator and absent for every other caller, `admin` included (`RPC_CHANNEL.md` §6.1, RT-O9.3, at `28e485ce9`). Before RT-W10 there is no host identity and the unrestricted listener stands in for it, so nothing a caller sees today is withdrawn. **Readers:** `rust/shekyl-engine-core/src/engine/regtest_e2e.rs:439-444` reads the **sum** of the two fields — its drain loop and its return-to-pool observable (`:437-438`) mean "everything this daemon holds", and it is a host caller. `tests/stressnet/monitor.py:142` reads the **relayed** count, a cross-node metric, and stops defaulting a missing key to `0`. |
