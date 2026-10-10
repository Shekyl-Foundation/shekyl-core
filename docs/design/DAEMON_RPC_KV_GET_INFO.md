# RK-5c — `get_info`, the hub: rule-26 pre-flight

**Status:** OPEN — R0, **RATIFIED 2026-10-09** (Rick); implementation open.
**Commits 1–6 of §5 have landed** (1 and 2 on 2026-10-09, 3 to 6 on 2026-10-10); commit 7 is next. Drafted 2026-10-08. §1's rulings
are recorded as ruled; **RK-Q1…RK-Q9 were ruled 2026-10-09** and RK-Q10
2026-10-08, confirmed 2026-10-09 (§8). **RK-Q11 was ruled 2026-10-10**, with
two additions; the first is minted as RK-D25 (§1).
**Ground:** `shekyl-core` `dev` **`98fbd20ac`** (#1005 merge, 2026-10-08);
`shekyl-gui-wallet` `dev` **`447908f`**. Every `file:line` below was read at
those commits. Open work on the hard-fork mechanism's deletion also edits
`on_get_info`; if it merges first, the handler's line numbers move and the
content cited does not.
**Parent:** [`DAEMON_RPC_KV_CUTOVER.md`](DAEMON_RPC_KV_CUTOVER.md) §2 row
RK-5c, §2.1.1, §5. Family `RK-` (registered); this document mints
**RK-D13…RK-D25** (decisions) and **RK-Q1…RK-Q11** (questions) inside
it, added to the family's index row in the commit that lands this file
(rule 94).
**Sibling round:** [`RPC_CHANNEL.md`](RPC_CHANNEL.md), round R1, merged
to `dev` by #1006 (`ea43d1d2b`). Its §6.1 is cited here by heading and by
quoted phrase, not by line: "absent, never zero", "Two classes that are
not grants", "Prerequisite: `get_info` moves to Rust first (RK-5c)" and
"What the incident's consumer gets" are all on `dev`. The grant assigned
to each part in §2.1 is that section's table. Its four RT-O9 rulings are
RT-O9.1…RT-O9.4; one of them, RT-O9.3, reaches this document: unrelayed
pool entries are **host-only data**, served to the host's administrator
and to no grant, `admin` included (§4.1, RK-Q10). **Status of that round:**
`dev`'s copy still reads "DRAFT for ratification"; its ratification
(RULED 2026-10-09) is written on #1020 and is not on `dev` yet. This
document was first drafted against #1006's unmerged heads, and earlier
commits of it name them.
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
| **RK-D17** | **RK-5c lands before RT-W10.** Recorded in `RPC_CHANNEL.md` §6.1, "Prerequisite: `get_info` moves to Rust first (RK-5c)". |
| **RK-D21** | **`emission_era` is removed, not ported.** There never was an emission era: the chain is pre-genesis and the idea was retired. The field, its four labels and its thresholds are deleted from the C++ reply **before** the oracle capture, so nothing in Rust — no type, no enum, no function, no fixture — ever carries it. |
| **RK-D23** | **`0` is a value; "no result" is `None` / `null`.** Zero is a valid answer for most quantities, so using it to mean "there is no answer" is ambiguous. In Rust the absence is `Option`; on the JSON wire it is `null`. This is RK-D15's principle stated generally, and it decides how every absence in this slice is written (§4.1, RK-Q7). RK-Q9 is the case it does not cover: a refused computation is a fault, not an absence. A standing rule for it is being drafted separately; this document cites RK-D23 either way. |
| **RK-D24** | **(RULED 2026-10-10.) The native handler gathers by part: a part the caller will not receive is not read.** Status and Peers are not read for a restricted caller, and the unrelayed pool count is not read without the host axis. Commit 3's C++ gather makes every read for every caller. That costs a public caller reads it never sees, and it lets a failure in one of them — `boost::filesystem::space` throwing inside `core::get_free_space`, for one — refuse a caller who would not have received that fact. The native handler carries a test of exactly that: with the Status facts set to fail, a `View` caller gets a full reply and a `Full` caller gets the refusal (§4.2). |
| **RK-D25** | **(RULED 2026-10-10, with RK-Q11.) The version read is the one permanent part of the wire.** Three things about `get_version`'s reply are frozen across every future shape change, RK-W's `CORE_RPC_VERSION` 4.0 included: the key is `version`; its value is a JSON integer; the integer is `(major << 16) \| minor`. Everything else in the reply, and every other reply, may change at a version bump. A client reads this one field through one function in `shekyl-rpc-types` before it decodes anything else, and that function is **the only lenient reader of a daemon reply in the tree**: both handshakes (the wallet's and the console's) and the console's `version` command call it, and no second decode that tolerates an unknown shape remains. **Why:** the check that diagnoses version skew has to survive the skew. If the field that names the version could itself move, a client older than the move could not say "this daemon is newer"; it could only say "unreadable". Pinned by a test that `{"version": N}` alone reads through the function. |

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
| **GUI** (another repository, parked) | `src-tauri/src/daemon_rpc.rs:97-123` (`GetInfoResponse`), `commands.rs:110-120`, `daemon_connection.rs:130-150`, `daemon_manager.rs:94`, `:185` (liveness) | height, target, top hash, difficulty, tx count, pool size, db size, version, synchronized, economics, `emission_era`, plus `stake_ratio` and `staker_pool_balance` | own struct | does not move in this PR; §5.1 records what each wire change will require of it (RK-D22) |

Nothing in this tree reads `emission_era`: the C++ handler writes it and
the struct serializes it, and that is all. Its readers are the GUI
(`src-tauri/src/daemon_rpc.rs:122-123`, `daemon_connection.rs:110`, `:156`,
`src/components/ChainHealthPanel.tsx:61`, `:103`, `src/types/daemon.ts:19`)
and the website consumer; both treat it as optional.

The website consumer from the RPC-channel incident is outside both trees;
its fields are listed in `RPC_CHANNEL.md` §6.1 ("What the
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

**No interim fix (Rick, 2026-10-08).** The daemon's side of the repair is
RK-Q2's commit in this slice; the GUI's side waits for the GUI lane
(§5.1). Until both land the GUI cannot read a
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
as it would on an omitted field. §5.1 records the GUI's change for the
RK-D15 commit: the field becomes `Option<u64>` and `null` renders as no
target.

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
  carry it and the rest cannot be withheld. **At parity nothing is absent
  yet.** A restricted reply today carries every key, and one of them —
  `database_size`, rounded up — is derived from a real read, so no
  constant written for an absent part could reproduce it. Until RK-Q8's
  commit the handler therefore builds a restricted caller's Status and
  Peers as *present parts holding the stand-ins* (zeros, `u64::MAX`, the
  empty string, the rounded size), and the absent arm of `Hidden` is
  reached only by a decoder. RK-Q8's commit is where the handler starts
  returning it. (Amended 2026-10-10; this bullet first said an absent
  part's serializer would write the stand-ins.)
- **How the composition is written.** serde does not support
  `deny_unknown_fields` together with `flatten`, on the outer struct or the
  flattened one, and every reply type in `shekyl-rpc-types` refuses unknown
  fields. `Hidden`'s whole-part rule needs a hand-written decoder in any
  case. So both directions go through one private flat struct that is the
  wire: it names every key and refuses any other, and it is converted to
  and from the parts, where the whole-part rule and the agreement of
  repeated names are checked. The crate's property is kept without the
  attribute. (As built in commit 4. This bullet first described a derived
  serializer beside a hand-written deserializer; one struct for both
  directions keeps the wire's names in one place.)
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
  parity, `View` withholds Status and Peers, written as the four
  restricted stand-ins of §0's second bullet, `alt_blocks_count` among the
  zeroed counts. `tx_pool_size` is not withheld under `View`, but under parity it
  is not one quantity either: `View` counts relayed entries and `Full`
  adds the unrelayed ones. That is one key whose meaning depends on who
  asks, which the governing principle forbids; RK-Q10 splits it. The
  difference between the two counts is the host axis, not a part.
- **The `target_height` sentinel is not one of the restricted
  stand-ins.** The stand-ins depend on the caller; the sentinel is written
  for every caller, and RK-D15 retires it in this slice. RT-W10 replaces
  `Disclosure`'s input with the connection's grant set and host flag. Replacing
  the stand-ins with absence (`RPC_CHANNEL.md` §6.1: "absent, never zero")
  is a wire change the sibling round asks of this slice; when it lands is
  RK-Q8.

#### Two wire types that keep the three states apart

serde's defaults merge the states the table below separates, in both
places this reply needs them distinct.

- **`Nullable<T>` — required, and may be `null`.** `Option<T>` decodes a
  `null` field and a **missing** field to the same `None`, so a field
  dropped by contract drift would read as "no answer". That is the
  fail-open the wallet's decoder in `engine/daemon/synced_chain_facts.rs`
  guarded against by hand, field by field, until commit 4 moved it onto
  the shared type.
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

`Hidden` is tested in commit 4: a full reply with one Status key removed,
and one with one Peers key removed, is an error and not an absent part.
`Nullable` had no field to carry until commit 6 made the target
nullable, so the type and its test — `{}` fails and `{"f": null}` decodes,
per field — landed there (`rust/shekyl-rpc-types/src/nullable.rs`), not as
an unused type in commit 4. It decodes through `deserialize_any` and not
`deserialize_option`: serde's derive answers a missing member with a
stand-in that says "none" to an option and "missing field" to anything
else, which is the whole difference between this type and `Option`.

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

Parity (commit 4) did not have these: it wrote the sentinel and the
stand-ins. Each later commit that changes the wire moves fields onto this
table, and none moves a field off it. Commit 6 moved `target_height`, on
all three methods that carry it, and `get_version.current_height`.

### 4.2 Facts — RK-D3 / RK-D7, one snapshot per family

**RK-D20: the chain part is read in one snapshot that carries its own tip.**
One coarse export, `shekyl_rpc_info_chain_facts`, reads under one chain lock:
chain count, top hash, next difficulty (u128), cumulative difficulty at the
tip (u128), total transactions, weight limit and median, adjusted time,
coins generated at the tip, total burned, the tx-volume window (sum,
blocks). (The NG activation height was on this list until 2026-10-10: the
hard-fork table it was read from is deleted, and the emission share is a
function of the height alone. The alt-block count was on it too, and left
under RK-D24: it is a Status field, so it is read with Status and not for
every caller.) Health's
`height` / `top_block_hash` come from **this** snapshot, never from a second
`shekyl_rpc_chain_tip` call, so a reply cannot pair one tip's hash with
another tip's difficulty. `synchronized` and the target come from the same
adapter call (`src/rpc/rpc_facts_ffi.cpp:1179-1186` is the pattern).

**As built in commit 4** these are five reads on one trait, `InfoFacts`
(`rust/shekyl-daemon-rpc/src/info_facts.rs`): `chain`, `pool_count`,
`store_size`, `status` and `peers`. The grouping below is by what is read
and for whom, which is what matters; the split into five traits was a
sketch and bought nothing a second implementation needs yet. `NodeFacts`'
three flags ride the chain snapshot, since they are read for every caller
with it. At parity the session counts are still the C++ ones — the
clearnet zone's total and its outbound count — carried in the Status read;
reading them from the seam board is RK-Q3's commit.

Behind traits (`InfoChainFacts`, `PoolFacts`, `PeerFacts`, `NodeFacts`, `StatusFacts`),
with the FFI shim as today's only implementation:

| Trait | Facts | Notes |
| --- | --- | --- |
| `InfoChainFacts` | above | DRS-E's store implementation reads the same set; `database_size` and `free_space` are the chain store's on-disk size and the volume's free space, whatever the store |
| `PoolFacts` | pool count over the broadcast set; the unrelayed count | The broadcast count is read for every caller. The unrelayed count is read only with the host axis (RK-D24) |
| `PeerFacts` | per-connector, per-direction session counts (feeding Health's `has_peers` and Status's two counts); peerlist sizes; per-connector socket counts | **Session counts from the seam board**, the one store; no subtraction. **Every read returns `Result<_, FactsFault>`, never a bare `u64`** (below). Whether `daemon-rpc` reads the hub directly or through new exports is an implementation detail for rule 25 |
| `NodeFacts` | offline, busy syncing, following degraded | Health's, read for every caller |
| `StatusFacts` | start time, free space, alt-block count, and the store's on-disk size | Read only for a caller who receives Status (RK-D24), with one exception below |

**Gathering by part — RK-D24.** The handler asks `Disclosure` which parts
the caller receives and reads only those. Health, Identity, Chain,
Economics and Pool's broadcast count are read for every caller. Status and
Peers are read only for a caller who receives them, so their reads cannot
fail a caller who was never going to see them, and a public caller costs
the node no filesystem or peer-registry read. `PeerFacts`'s session counts
feed two parts: Status's two aggregate counts are read with Status, and
Health's `has_peers`, from commit 7, is read for everyone.

*Where the version string comes from.* The build's version string exists
only in C++ (`SHEKYL_VERSION_FULL`); nothing in `rust/` has it. It is a
Status field, so it rides the Status facts export as a string, one source,
and is not read for a caller who will be shown the empty stand-in.

*One exception, for as long as parity lasts.* A restricted reply carries
`database_size` today — rounded up to 5 GiB, but derived from the real
size. The caller receives it, so it is read for that caller, and a failure
of that one read refuses a `View` caller as it does a `Full` one. It joins
the not-read set in RK-Q8's commit, when a restricted reply stops carrying
Status at all. The other restricted stand-ins need no read: zero,
`u64::MAX` and the empty string are constants.

*The size read must be able to fail, and say so (ruled 2026-10-10,
RK-D23).* `BlockchainLMDB::get_database_size`
(`src/blockchain_db/lmdb/db_lmdb.cpp:4253-4260`) swallows the `file_size`
error and returns `0` — a zero that means "could not read". Read through
it, the "size read failing" case below would test a path production cannot
reach. So the size is its own facts export and its own trait method, apart
from the other Status facts, and it does not call that getter: it stats
the store's data file itself and carries a failure out as a distinct
return code, mapped to its own `FactsFault`, never as a size of `0`. No
method is added to the store's C++ interface for this (the daemon-side
LMDB code is frozen during the store cutover); the export asks the store
for its file names, which the interface already answers. An FFI-level case
pins it: an unreadable data file yields the fault, not `0`. (As built, the
stat and its failure are entirely in Rust and are tested there, and the
C++ side is tested for the name that crosses. Ruled 2026-10-10: no live
test spanning the boundary is wanted.)

*The test this decision requires* (commit 4): with `StatusFacts`' start
time, free space and alt-block count set to fail, a `View` caller gets a
full reply and a `Full` caller gets the refusal. A second case pins the
exception: with the size read failing, both are refused.

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
  height — all from the §4.2 snapshot.
- Output: a domain struct in `shekyl-economics` with five fields; the wire
  part in `shekyl-rpc-types` converts from it (rule 18: the wire type lives
  with the wire). Adding a field is a change to those two structs and a
  `CORE_RPC_VERSION` bump. The handler, facts and FFI do not move. That is
  the "flexible" the ruling asks for.
- The three C functions the handler calls today
  (`shekyl_calc_release_multiplier`, `shekyl_calc_burn_pct_at`,
  `shekyl_emission_share_at`) are already Rust; the projection calls them
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
serializer: the policy in §0 would not be exercised, and #1005's test of
`already_generated_coins` in `tests/unit_tests/rpc_target_wire_contract.cpp`
had exactly that limitation — it said so in its own comment. (That test
went with the handler in commit 5.)

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

That is the table as captured, at parity. Since commit 6 the two
synchronized fixtures and the burn-refusal one carry the core's target
(1234567) and the peerless one carries `null`, in `_v2` files derived from
these; the syncing fixture did not move.

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
| 1 | **Origin-guard re-anchor** on `include_sensitive`, own diff, before the route leaves (parent §5 row). **LANDED 2026-10-09** as `restricted_listener_hides_a_transaction_this_node_has_not_broadcast` (`rust/shekyl-engine-core/src/engine/regtest_e2e.rs`). **The rig is two daemons, an origin and a sink, and the holder is the origin** — not a second node holding what the first stemmed to it, which is what this row pictured. A relay node's hold rests on its epoch draw and on having somewhere to stem onward; the origin's does not, because a local origin takes the stem slot whatever the epoch. The sink runs `--no-sync` and drops what it is sent, so nothing fluffs the transaction back. **What is not fixed is the origin's embargo**, a draw with no lever: the restricted reads are bracketed by a read of the relay state on the unrestricted listener, held before and held after, and an attempt whose bracket does not close is discarded and retried with a new transaction. **No lever was added to the relay**; pinning the epoch and the embargo on regtest was the alternative, and it would have put a test switch in the code that decides when a transaction is published. Four reads are judged (the three bridged pool routes and native `/get_transactions`), then the transaction is mined and popped back into the broadcast set and the restricted listener must show it (parent §7, 2026-10-09) | armed in `scripts/ci/run_live_daemon_gates.sh`; green on twelve consecutive runs (62–72 s each); observed red twice by daemon sabotage, each naming exactly the routes it should; the discard-and-retry path and the exhausted-attempts failure each observed once |
| 2 | **RK-D21:** `emission_era` deleted. **LANDED 2026-10-09** at `CORE_RPC_VERSION` 3.45 (written as 3.43, and moved twice as `dev` took 3.43 and then 3.44 first): the struct field and its `KV_SERIALIZE`, the `double`-threshold computation in `on_get_info`, and, in `docs/DESIGN_CONCEPTS.md`'s chain-health dashboard table, the "Emission Era" row, the "Emission forecast" row ("Maturity Era begins in ~X years"; nothing in core or the GUI implements it, and a forecast, if one is wanted, belongs to the economics sim lane) and the words "with era boundaries" on the Emission progress row. The handler lines cited elsewhere in this document as `:294-302` are the ones removed; the ground commit still shows them | **The sweep covers the four era names in live design text, not only the identifier.** `git grep emission_era` → this document, the CHANGELOG, and the version history that records the bump (`rust/shekyl-rpc-types/src/chain.rs`, `tests/rpc_parity.rs`). `git grep -i -E "(founding|growth|maturity|tail) era" -- docs/DESIGN_CONCEPTS.md` → two things, both left as they are: the burn-rate table under "Burn rate behavior across chain lifecycle", which records how burn was once projected by phase, and one sentence that says "tail era" for the period of tail emission. That second sense, which other documents under `docs/` also use, is a different thing from the retired label and is not swept. `get_version_synced_v22.json` derived from `_v21` |
| 3 | **Capture.** **LANDED 2026-10-10.** `on_get_info` gathers `get_info_facts` and calls `build_get_info(facts, restricted, res)` (`src/rpc/get_info_build.h`; defined beside the handler). The builder is the handler's computation with each read replaced by a fact; rewriting the old handler's reads into facts mechanically and diffing against the builder leaves only the lines that moved to the gather. **One thing differs, and it is not in any reply:** the gather reads everything whoever is asking, where the handler skipped a restricted caller's hidden reads and counted the pool one way; the builder decides what a restricted caller is shown from the same facts, which is the shape §4.1 gives the native handler. `tests/unit_tests/rpc_oracle_vectors.cpp` runs the builder over fixed facts for §4.4's five fixtures and pins `get_info_{synced,syncing,peerless_startup,synced_restricted,burn_refusal}_v1.json`, stored LF | the emitter is in `unit_tests` and green; observed red by breaking the connection-count subtraction in the builder — the three vectors with peers and full disclosure drifted, the restricted and peerless ones did not |
| 4 | **Native port at parity**, landed as bisectable pieces (types, facts and handler with their parity tests; then the Rust readers; then the console): types (§4.1), facts export + layout twin (§4.2), economics projection (§4.3), handler, both routes and the JSON-RPC name native; Rust parity test green against commit 3's vectors; all in-tree readers in §2.2 onto the shared type (RK-D1); console readers ported (RK-D5), four bridged legs closed; RK-D9 re-pin of `target` and a value-shaped `already_generated_coins` test against the snapshot; `following_degraded` value-shaped test (C2-R1 obligation) **LANDED 2026-10-10** in six pieces: the wire type; the economics projection; the facts by part and the method over them; the native routes; the Rust readers; the console. **Notes on what was built.** (a) The store's size is read in Rust: only the data file's path crosses, and `store_file_size` returns `StoreUnreadable` for a file it cannot stat — the same code whichever store names the file, which is the form that survives the store cutover. (b) The build's version string and `SHEKYL_PROTOCOL_VERSION` exist only in C++ and cross as facts. (c) `diff`, `version` and `print_pool_stats` are rendered in Rust. `version` asks without the identity handshake and reads its one member leniently, because it is for telling an operator what they reached, a daemon of another version included; the fuller form `CLIENT_VERSION_CONSTANTS_VALIDATION.md` §3.6.2 describes (both sides and the verdict) is left to the console's retirement slice. (d) **One behaviour changes at a version skew:** a reply that omitted `offline`, `following_degraded` or `restricted` used to read as false in the persona's tip poller; it is now not a reply and reads as unusable, which holds the tip and lets it age out. (e) `restricted_listener_applies_request_caps_through_the_ffi_bridge` is renamed `restricted_listener_gets_stand_ins_and_caps_from_native_handlers`: both its legs are native, and the bridge's guard is commit 1's test | parent §4 gate; the `Hidden` partial-part tests of §4.1; the hub-absent parity test of §4.4; RK-D24's gather-by-part test, both cases; the FFI-level case that an unreadable data file is a fault and not a size of `0`; all five oracle vectors reproduced by the type and by the method; two live gates observed red by daemon sabotage (the listener's posture mapped to full disclosure; `diff` cut off from the method) |
| 5 | **Delete C++.** **LANDED 2026-10-10.** Gone: `on_get_info`, `on_get_info_json`, `COMMAND_RPC_GET_INFO`, the three dispatch rows, `build_get_info` and `get_info_facts` with their header, the handler-only `round_up`, the oracle emitter, and the two `get_info` cases in `rpc_target_wire_contract.cpp`. `check_core_ready` stays: two other handlers call it. Comments that cited lines of the handler are rewritten to say what the daemon does, and the bridge's header comment names its current guard | `git grep` for `COMMAND_RPC_GET_INFO`, `on_get_info` and `build_get_info` outside `docs/` → only the vectors' README, which records how the capture was made |
| 6 | **RK-D15.** **LANDED 2026-10-10** at `CORE_RPC_VERSION` 3.46, in two pieces: the version-first read, then the wire change. Sentinel retired on `get_info`; under RK-Q7, `target_height` becomes nullable on `get_info`, `get_version` and `sync_info` together, and `get_version.current_height` stops being omitted when zero; wallet predicate simplified; CLI `show_chain` reads `synchronized`; the "`get_info` still writes `0`" statements corrected (§6); under RK-Q11 as ruled, the version is read before the full decode through one function, which lands first in this commit; both handshakes and the console's `version` command call it (RK-D25). **Notes on what was built.** (a) The reader is `daemon_rpc_version` and the single decode-and-compare entry is `IdentityExpectation::read` (`rust/shekyl-rpc-types/src/identity.rs`); `check` is gone, so the version cannot be compared in two places. The reader is written by hand: a derived struct would also accept a JSON array positionally, and the key is part of what is frozen. (b) `version`, against a daemon of another RPC version, prints the two RPC versions and fails; it printed the daemon's software version from a lenient decode of `get_info`, which is deleted. (c) **The wallet's predicate is the `synchronized` flag alone.** The height comparison is deleted, with the persona poller's `BehindItsTarget` arm and the `target_height` member of the wallet's two health types. A synchronized daemon now reports its real target, which is the tallest chain a peer has claimed, so comparing against it would let one peer stop the submit watchdog and the persona's serving. No behaviour changes: under the sentinel the comparison never decided anything (Rick, 2026-10-10). (d) The wire type keeps `u64` for the target, as for every height in `shekyl-rpc-types`, which does not depend on the unit types; it is `Option<ChainCount>` inland. (e) The console's `status` and `sync_info` lines show the core's target on a synchronized node too, where `status` showed the node's own height. (f) Vectors: `get_version_synced_v23` (the chain's link, members unchanged), `get_version_absent_target_v2`, `get_version_all_defaults_v3`, `sync_info_empty_v3`, and a `_v2` of four `get_info` fixtures; `get_version_syncing_v3`, `sync_info_v3` and `get_info_syncing_v1` carried a target already and have no successor | one `CORE_RPC_VERSION` bump; a `_vN` vector for each of the three methods, derived from its predecessor (README rule); `Nullable` and its missing-key test (§4.1); RK-D25's test that `{"version": N}` alone reads through the function; the derivation test that each new vector is its predecessor with only the target (and `current_height`) restated; a test that a target above the height neither withholds nor grants the wallet's facts, and one that it does not stop the persona's poller |
| 7 | **RK-D14:** `has_peers` in health; watchdog and P's poller switch to it; `daemon_tip` stops reading `restricted`; fixes §3.1; the handler's missing-hub parity arm is deleted, so a missing hub refuses (§4.2) | bump; a test that a restricted reply with peers yields no `DaemonPeerless` and no `NoPeers`; the hub-absent refusal test of §4.4 |
| 8+ | Each of RK-Q1, Q2, Q3, Q6, Q8, Q9, Q10 as ruled, one commit each. **Two carry-forwards, ruled 2026-10-10.** *RK-Q1's commit:* the weight names it keeps (`block_weight_limit`, `block_weight_median`) lose their inherited omit-at-zero — the `default` and `skip_serializing_if = "is_zero"` that mirror `KV_SERIALIZE_OPT` — so they are always present; `0` is a value (RK-D23). *RK-Q3's commit:* the parity `wrapping_sub` on `incoming_connections_count` is deleted and replaced by per-direction counts from the board, not by a checked subtraction: there is no subtraction left to check | bump each |

Commit 2 changes the wire before parity and commits 6–8 change it after,
each deliberately and each in its own diff — the RK-4c / RK-5b precedent
(parent RK-D8). Commit 2 goes first because the alternative is to capture,
port and parity-test a field whose ruling is deletion.

### 5.1 What each wire change will require of the GUI — RK-D22, REVISED 2026-10-09 (Rick)

**RK-D22: a commit that changes a field the GUI decodes records, in the
table below, the GUI change it will require. Nothing is owed in the GUI
before this PR leaves draft.** The GUI is parked and untested until the
daemon is stable, so a GUI change opened against each commit would be
work against a moving target that nobody runs. As first written this
decision made that a gate ("opened against that commit before the core PR
leaves draft"); the gate is dropped and the table stays as the record the
GUI lane picks up when it resumes. The reader that moves in the same diff
as each wire change is the CLI, under RK-D1.
The GUI's fields are read at `447908f` (`src-tauri/src/daemon_rpc.rs:97-123`).

| Core commit | Wire change | GUI today | GUI change when its lane resumes |
| --- | --- | --- | --- |
| 2 (RK-D21) | `emission_era` gone | `#[serde(default)] String`; the panel renders it only when non-empty | none to keep decoding; the dead field, its type and the two panel blocks are deleted |
| 6 (RK-D15) | `target_height` is the core's target, `null` when there is none (RK-Q7), on `get_info` and on `get_version`; `get_version.current_height` is always present | required `u64`, shown as "daemon height" | `Option<u64>`; `null` rendered as no target, not `0`; its `get_version` handshake reads the version first through `daemon_rpc_version` (RK-D25) |
| 8+ (RK-Q1) | `difficulty` and `difficulty_top64` retired, `wide_difficulty` kept | required `difficulty: u64` | reads `wide_difficulty` (decimal string) |
| 8+ (RK-Q2) | `already_generated_coins`, `total_burned` become decimal strings | `Option<String>` and `u64` | `total_burned` becomes a string; the first already is |
| 8+ (RK-Q6) | `nettype` and the three booleans retired | not read | none |
| 8+ (RK-Q8) | a restricted reply omits Status and Peers | required `database_size: u64` and `version: String` | both optional; a remote node that withholds them renders as withheld, not as an empty version and a rounded size |

The other in-tree-external reader, the website consumer, is the RPC-channel
round's (`RPC_CHANNEL.md` §6.1).

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
| Wallet sync predicate simplification | #792 / WSS-Q14 | 6 — **done** |
| `get_version` and `sync_info` still encode "no target" as an omitted or zero `target_height` (`rust/shekyl-rpc-types/src/chain.rs:386-393`, `p2p.rs:280-283`, as cited when this row was written) | RK-D23 | 6 — **done** |
| "`get_info` still writes `0` when synchronized" — the `HEIGHT_SEMANTICS.md` index row and the comment at `rust/shekyl-daemon-rpc/src/chain_facts.rs:112-116` | height-semantics Phase 2f | 6 — **done** |
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

## 8. Questions — RK-Q1…RK-Q9 RULED 2026-10-09, RK-Q10 RULED 2026-10-08, RK-Q11 RULED 2026-10-10 (Rick)

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
| **RK-Q7** | **How is an absent target written?** RK-D15 says the target is the core's target or absent, and does not say what absent looks like on the wire. The fact already has two encodings: `get_version` omits it when the core reports none and every Rust reader decodes the omission back to `0` (`rust/shekyl-rpc-types/src/chain.rs:390-393`), and `sync_info` writes a bare `0` (`rust/shekyl-rpc-types/src/p2p.rs:280-283`). Both are the sentinel, relocated. | **RULED 2026-10-09 (Rick).** **`null`, on all three methods** (RK-D23). `target_height` is `Option<ChainCount>` in Rust and `null` on the wire when the core reports none, on `get_info`, `get_version` and `sync_info`, all in commit 6. One fact, one encoding — and not the encoding either method has today. `get_version.current_height` (`chain.rs:386-389`, the same omit-when-zero) is folded into that commit so `get_version` carries no zero sentinel. The cost is the GUI's required `target_height` (§3.4, §5.1). **`get_version` is the compatibility endpoint**: a client reads it to learn whether it can talk to this daemon at all, so its shape change ships whole — one commit, one bump, every in-tree decoder with it — never piecemeal. The GUI's decoder is the exception RK-D22 records: it is parked, and moves when its lane resumes. A client older than the bump fails to decode the reply instead of reading a version it could report as too new; that failure mode is RK-Q11, ruled 2026-10-10: the version is read first, so such a client reports the version difference. |
| **RK-Q8** | **When do the restricted stand-ins become absence?** The sibling round asks that a part the caller may not see is absent from the reply, not zeroed. Parity keeps the stand-ins; the type already distinguishes the two (§4.1). | **RULED 2026-10-09 (Rick).** **In RK-5c, after RK-D14** (commit 8+). The stand-ins are the defect §3.1 traces — `0` peers that means "not told" — and once `has_peers` exists no in-tree reader depends on them. Leaving the flip to RT-W10 would have that slice change a wire it otherwise only re-keys. Costs the GUI two required fields (§5.1). |
| **RK-Q9** | **How is a refused burn computation written?** `shekyl_calc_burn_pct_at` refuses when `total_burned` exceeds `already_generated_coins`; the reply then carries `burn_pct = 0` and the refusal is logged (`core_rpc_server.cpp:280-287`). `0` % is a legitimate burn. | **RULED 2026-10-09 (Rick). A refused burn computation is a store fault, and the refusal is verbose.** Not as first recommended (`null`), and not part of the batch ruling: this question was held back. The only reachable refusal is the supply invariant, `total_burned > coins_generated` (`rust/shekyl-ffi/src/economics_ffi.rs:204-226`; the null-out arm is a caller bug). That is the store contradicting itself — the class `FactsFault::Inconsistent` exists for (`rust/shekyl-daemon-rpc/src/chain_facts.rs:205-217`: a contradiction with a plausible-looking fallback that must not reach the caller as a fact). It is not "no answer". **(1)** The economics projection checks the invariant on the RK-D20 snapshot and returns the violation; the handler maps it to the store fault and `get_info` refuses. No partial reply. **(2)** Verbose: the refusal the caller receives names the violated invariant and carries its operands — coins generated, total burned, and the tip the snapshot was read at. All three are public chain facts the reply already carries, so nothing is disclosed that a successful reply would not show. The same text is logged. `FactsFault` is `Copy` with a payload-free `Inconsistent` today; whether the detail rides a payload on that variant or a dedicated variant is the implementation's call — the requirement is that the caller's error says what contradicted what. **(3)** `burn_pct` stays a plain number, never `null`. **(4)** Its own commit after parity (8+). The capture keeps its "burn refusal → logged zero" fixture so parity matches; this commit replaces that behaviour, and its test is Rust-side: a snapshot with `total_burned > coins_generated` makes `get_info` refuse with an error naming the invariant and all three operands. |
| **RK-Q10** | **`tx_pool_size` carries two quantities.** Raised from the RPC-channel round's review of this document. Split it? | **RULED 2026-10-08 (Rick; given through the RPC-channel lane and confirmed in this lane 2026-10-09).** **Split, in commit 8+.** `tx_pool_size` counts relayed entries only and is a value for every caller, in `pool`. The unrelayed count is its own field in its own one-field `Hidden` part, present only for the host's administrator and absent for every other caller, `admin` included (`RPC_CHANNEL.md` §6.1, RT-O9.3). Before RT-W10 there is no host identity and the unrestricted listener stands in for it, so nothing a caller sees today is withdrawn. **Readers:** `rust/shekyl-engine-core/src/engine/regtest_e2e.rs:439-444` reads the **sum** of the two fields — its drain loop and its return-to-pool observable (`:437-438`) mean "everything this daemon holds", and it is a host caller. `tests/stressnet/monitor.py:142` reads the **relayed** count, a cross-node metric, and stops defaulting a missing key to `0`. |
| **RK-Q11** | **Does a client read the daemon's version before it decodes the rest of `get_version`?** Today it does not. `fetch_get_version` decodes the whole reply into `GetVersionResponse` and only then compares versions (`rust/shekyl-engine-core/src/engine/daemon/mod.rs:242-251`, `:279-281`), and that type refuses unknown fields (`rust/shekyl-rpc-types/src/chain.rs:378-380`). So **any** change to the reply's shape — RK-Q7's `null`, or a field added by a later version — makes a client older than the change report an unreadable reply, where the true statement is "this daemon is newer than this client". The check that exists to diagnose skew is the first thing skew breaks. RK-Q7 does not create this; it is the first commit to run into it. | **RULED 2026-10-10 (Rick): yes, as recommended, and the function lands first in commit 6 — with two additions.** *(1)* The version-first read is the one permanent part of the wire: the `version` key, its JSON integer type and the `(major << 16) \| minor` encoding are frozen across every future shape change, RK-W's 4.0 included (minted as RK-D25, §1; recorded on the parent's RK-W row), and pinned by a test that `{"version": N}` alone reads through the function. *(2)* One lenient reader: the console's `version` command, the wallet's handshake and the console's handshake all call the function, and no second lenient decode remains. **The recommendation, as ruled:** One function in `shekyl-rpc-types` reads `version` alone from the reply and compares it with `CORE_RPC_VERSION`; a mismatch is reported as a version mismatch, naming both versions, and the full strict decode runs only when the versions agree. Every caller of the daemon handshake uses it — the wallet's (`engine/daemon/mod.rs:242`) and the console's (`rust/shekyl-daemon-rpc/src/console/identity.rs:23`) today — so there is one definition of "too new" (RK-D1). The identity tuple's strictness (VC-D14) is untouched: nothing is trusted from a reply whose version differs; it is only named. The alternative, accepting an unreadable-reply error because every client ships with its daemon before genesis, leaves the defect for the first post-genesis shape change, which is when it costs an operator. The GUI adopts the same function when its lane resumes (§5.1). |
