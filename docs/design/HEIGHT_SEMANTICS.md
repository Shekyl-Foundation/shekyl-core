# Height semantics — ordinal vs count

**Status:** OPEN — Phase 1 walked 2026-09-19; height-semantics Phase 2a
RULED 2026-09-20 (census, wire table, naming/difference convention);
height-semantics Phase 2b RULED 2026-09-20 (dispatch-clock retype to
`ChainCount`, no numeric change; `PENDING_POST_VERSION` 10 → 11). Remaining:
Phase 2c (wire/FFI decode), Phase 2d (inland bare-`u64` tail). Numerics
are frozen as pinned (Rick, 2026-09-19).

<!-- claim-audit: citations -->

Owner: the count-versus-height FOLLOWUPS row. Spawned from
[`WALLET_SIDE_STORE.md`](WALLET_SIDE_STORE.md) `WSS-Q14` / the
`daemon_claimed_tip` wrap. Read the consumer, not the producing wrapper.

## 1. Two quantities, one inherited name

Every `u64` on the block axis is one of these, or a **difference** (an
age / depth / window — neither):

| Quantity | Meaning | Genesis-only chain | Type today |
| --- | --- | --- | --- |
| Ordinal height | which block; genesis = 0 | tip = 0 | `BlockHeight` |
| Chain count | how many blocks; = tip + 1 | 1 | `ChainCount` (`rust/shekyl-types/src/lib.rs:352-377`) |
| Difference | span between two instants | n/a | `BlockCount` (`rust/shekyl-types/src/lib.rs:334-340`) |

C++ overloads "height" for the count (`m_db->height()`, `get_height`,
`get_info.height` after `++res.height` at
`src/rpc/core_rpc_server.cpp:206-207`). The Rust vocabulary already
splits the types; the remaining tax is callers that wrap a count in
`BlockHeight`.

Named conversions, already on `ChainCount`
(`rust/shekyl-types/src/lib.rs:922-935`):

- `tip()` — newest existing block (`count − 1`); spendability / reference.
- `next_height()` — height the next block will carry (numerically the
  count); earliest inclusion.

`SyncedChainFacts` (`WSS-Q14`, PR #792) is the pattern: `chain_height()`
returns `ChainCount`, `.tip()` is the named conversion, and the type
refuses an unsynced view. It is not a special case of this audit.

## 2. Phase 1 — the consensus-adjacent walk

Ground: `daemon_claimed_tip`
(`rust/shekyl-engine-core/src/engine/pscan/block_source.rs:181-199` on
this tree) wraps `Rpc::get_height` — documented as **the amount of
blocks**, genesis-only = 1 (`rust/shekyl-rpc-client/src/lib.rs:380-384`).
At the Phase 1 walk it wrapped that count into `BlockHeight::from_raw`.
PR #792 froze the numeric (`facts.chain_height()`, not `.tip()`) and
pins it with `a_synchronized_daemon_reports_the_unchanged_clock`
(3-block chain reports 3). Height-semantics Phase 2b retyped the return
to `ChainCount`; the identifier still says "tip"; the value is still a
count.

The six consumers named in that finding, plus the stamps they feed, plus
the two adjacent surfaces the handoff listed that do **not** go through
this function.

### 2.1 Anchor-gate convention (checked first)

This is the one with a counterparty. It is **not** a `daemon_claimed_tip`
consumer. The two clocks must not be conflated.

The countersign pre-sign gate is
`anchor ∈ [own_height − 720 − L, own_height − 720 + L]`, `L = 4`
(`rust/shekyl-p-serve/src/countersign.rs:137-151`). Admission is
`anchor ∈ [predecessor − 720 − L, predecessor − 720]`
(`SF-D8`;
`rust/shekyl-archival-retention/src/pass_anchor.rs:76-81`).

| Side | Quantity today | Evidence |
| --- | --- | --- |
| Daemon admission | **ORDINAL** predecessor | `get_tail_id` returns the tip's index; `++blockchain_height` converts to count; `predecessor_height = blockchain_height - 1` is the tip ordinal (`src/cryptonote_core/blockchain.cpp:5420-5465`). Window hashes are looked up with `height >= m_db->height()` as the exclusive **count** bound and `get_block_hash_from_height(height)` as the **ordinal** index (`src/cryptonote_core/blockchain.cpp:5277-5281`). Fixtures: `shape_for_predecessor(H)` last = `H − 720` (`rust/shekyl-archival-retention/src/pass_anchor.rs:324-333`); `SIG_ANCHOR_HEIGHT = SIG_PREDECESSOR_HEIGHT - 720` (`rust/shekyl-archival-retention/tests/attestation_wire_kat.rs:525-528`). |
| Witness (`P`) `own_height` | **ORDINAL** | `HostSigner::own_height` is `ServingReader::sync_tip_height` (`rust/shekyl-p-host/src/signer.rs:96-100`). A fresh store reports `0` (`rust/shekyl-p-host/src/signer.rs:117-125`). Ingest is consecutive from genesis `0, 1, 2, …` (`rust/shekyl-curve-tree/src/client.rs:752-756`). PR #791 (OPEN) converts `get_info.height` (count) → top-block ordinal once at decode, so a future daemon-tip source for this gate stays ordinal. |
| Requester mint | protocol **ORDINAL**; production mint **unwired** | Header contract: "hash of its block at `tip − 720`" (`rust/shekyl-p-fetch/src/header.rs:25-28`). `RequestHeader::fresh` is not on the daemon production fetch path. |

**Verdict: shared ORDINAL.** A shared off-by-one would be absorbed by `L`.
A one-sided one would eat 1 of `L = 4` silently. None is live today on
two production sides. When the requester mint lands, it must convert like
#791 (count → ordinal at decode), not stamp raw `get_height`. That is a
ruled-fix item for **that** PR, not a Phase 1 value change.

### 2.2 `daemon_claimed_tip` consumers

| Site | file:line | Protocol quantity | Stamped today | Evidence | Disposition |
| --- | --- | --- | --- | --- | --- |
| Producer | `rust/shekyl-engine-core/src/engine/pscan/block_source.rs:186-199` | n/a (wrapper) | COUNT as `ChainCount` | `get_height` is count (`rust/shekyl-rpc-client/src/lib.rs:380-384`); returns `facts.chain_height()` (no `.tip()`). | RULED 2026-09-20 (height-semantics Phase 2b): `ChainCount`; numeric pin unchanged. |
| `BlockSource::tip_height` | `rust/shekyl-engine-core/src/engine/pscan/block_source.rs:94-109`; DaemonBlockSource `rust/shekyl-engine-core/src/engine/pscan/block_source.rs:237-239`; PBlockSource `rust/shekyl-engine-core/src/engine/pscan/block_source.rs:288-291` | **COUNT** (claimed chain size; exclusive end of `0 .. count` is `next_height()`) | COUNT as `ChainCount` | Method name kept (WI-3 named clock); return type is the quantity. `block_at` valid on `0 .. count`. | RULED 2026-09-20. `block_at` args stay ordinal. |
| `block_at` / `block_number` | `rust/shekyl-engine-core/src/engine/pscan/block_source.rs:130-133`, `rust/shekyl-engine-core/src/engine/pscan/block_source.rs:202-211` | **ORDINAL** (which block) | `BlockHeight` used as a 0-indexed fetch number | `get_block_hash` `number` is "zero-indexed position" (`rust/shekyl-rpc-client/src/lib.rs:410-413`). | Already the right type; keep. |
| P-scan sweep exclusive end | `rust/shekyl-engine-core/src/engine/pscan/task.rs:243-252`, `rust/shekyl-engine-core/src/engine/pscan/task.rs:282` | bound = COUNT; index = ORDINAL | COUNT − `reorg_depth` as exclusive ordinal (`saturating_sub_count` then `next_height()`); loop calls `block_at(ordinal)` | Half-open range over a count. Flipping the bound to `.tip()` without changing the loop **skips the last block**. | RULED 2026-09-20: types split; numeric unchanged. |
| `anchor_t0` stamp | `rust/shekyl-engine-core/src/engine/bond_orchestrator.rs:555-557`; field `rust/shekyl-engine-state/src/pending_post_block.rs:147-151` | same-clock threshold (WI-3 R2-1) | COUNT as `ChainCount` | Spec name is "tip height at assemble time" (`ARCHIVAL_BOND_WI2_ASSEMBLY.md:250-268`); the consuming rule is `due = anchor_t0 + offset` compared to the **same** `daemon_claimed_tip` read. Arithmetic never indexes a block. | RULED 2026-09-20: `ChainCount`. Converting to ordinal is only legal if stamp, due-check, and alarm move together. |
| Due-check | `rust/shekyl-engine-core/src/engine/pscan/dispatch.rs:260-263`, `rust/shekyl-engine-core/src/engine/pscan/dispatch.rs:291` | same clock as `anchor_t0` | COUNT vs COUNT (`ChainCount`) | `due_height(p) <= tip`. WI-3 R2-1: stamp and due-check switch together or offsets change meaning. | RULED 2026-09-20: both ends `ChainCount`. |
| Alarm / resubmit horizon | `rust/shekyl-engine-core/src/engine/pscan/dispatch.rs:296-297` | same clock as dispatch `at` | COUNT vs COUNT (`ChainCount`) | `tip < at.saturating_add(horizon)`. `at` is the dispatch stamp. | RULED 2026-09-20. Same as due-check. |
| Claim dispatch `at` | `rust/shekyl-engine-core/src/engine/claim_dispatch.rs:369` | "when dispatched" vs a later same-clock tip | COUNT as `ChainCount` | Comment: same named clock as bond dispatch (WI-3 R2-1). | RULED 2026-09-20 with the clock. |
| Drain dispatch `at` | `rust/shekyl-engine-core/src/engine/drain_dispatch.rs:397` | same | COUNT as `ChainCount` | Same clock comment (`rust/shekyl-engine-core/src/engine/drain_dispatch.rs:394-396`). | RULED 2026-09-20. |
| Release dispatch `at` | `rust/shekyl-engine-core/src/engine/release_dispatch.rs:606` | same | COUNT as `ChainCount` | Same clock comment (`rust/shekyl-engine-core/src/engine/release_dispatch.rs:604-605`). | RULED 2026-09-20. |
| Emission claim gather | `rust/shekyl-engine-core/src/engine/emission_source.rs:259-270`, `rust/shekyl-engine-core/src/engine/emission_source.rs:546-549` | already split | `ChainCount` | Decode names the type; consumers take `next_height()` (inclusion) or `tip()` (spendability). **Does not** call `daemon_claimed_tip`. | Pattern, not a finding. |
| Claim orchestrator reference | `rust/shekyl-engine-core/src/engine/claim_orchestrator.rs:198-206` | `ChainCount::tip` for spendability | typed | Same pattern. | Pattern, not a finding. |
| `release.rs` record predicates | `rust/shekyl-engine-core/src/engine/stake_engine/release.rs` | record facts from the claim source | `ChainCount` on the source; predicates are not a block-axis stamp | Not a `daemon_claimed_tip` consumer. | Out of this walk. |

### 2.3 Phase 1 conclusion — RULED by this walk, 2026-09-19

**All six `daemon_claimed_tip` consumers carry COUNT and compare it only
to COUNT.** Shared off-by-one, absorbed. **Rename honestly. No site
needs a one-sided value change.**

The spec *name* for `anchor_t0` is "tip height". The consuming rule is
same-clock threshold arithmetic. That is COUNT-as-clock, not ordinal-as-
index. Flipping `daemon_claimed_tip` to `.tip()` alone would (a) fire
due one block late against already-stamped posts and (b) make the pscan
`0 .. tip` loop skip the last block. That is why Rick froze the numeric
first.

No Phase 1 finding routes to a value-change PR. Two items that are
**not** this PR, named so they are not silent:

1. **Optional later, both ends, own ruling:** convert the whole stamp
   clock (assemble `anchor_t0`, due-check, alarm, dispatch `at`) from
   count to ordinal **together**, and change the pscan exclusive-end in
   the same PR. Identifier-matches-tip. Not owed: the honest rename is
   count.
2. **When the requester mint lands:** convert count → ordinal at decode
   (the #791 shape). Not live today.

## 3. Height-semantics Phase 2a — census, wire table, convention (RULED 2026-09-20)

This slice classifies. It does not retype. Discharge of *this* slice:
every block-axis family has a quantity and a remaining-work phase; the
unclear set is empty. The `compile_fail` per conversion boundary is
owned by the retype slice that creates that boundary (height-semantics
Phase 2b onward), not by a docs PR.

Ground: `origin/dev` at the walk (`85071a24f`, merge of PR #801). PR
#792 was OPEN at Phase 2a's close. **UPDATE 2026-09-20 (#792):** merged;
height-semantics Phase 2b is RULED on this tree (dispatch-clock retype).

### 3.1 Convention — RULED 2026-09-20

The choice the Phase 1 stub left open ("newtype everywhere" vs
"documented bare-`u64` for ages") is the first of these:

- **C1 Wire stays raw.** JSON, Levin, C FFI, and C++ daemon glue keep
  `u64`. The wire's identity is the field name plus this table, not a
  Rust type on the DTO.
- **C2 Decode once.** Inland Rust never carries a block-axis quantity
  as a bare `u64`. Conversion is a named constructor
  (`ChainCount::from_raw`, `BlockHeight::from_raw`,
  `BlockCount::from_raw`) at the decode site. Re-wrapping a count as
  `BlockHeight` inland is the Phase 1 defect.
- **C3 Three inland types.** `BlockHeight` is ordinal. `ChainCount` is
  count. `BlockCount` is a difference. COUNT is never wrapped in
  `BlockHeight`.
- **C4 Differences are `BlockCount` inland.** Not "documented
  bare-`u64` for ages." Constants such as `PASS_ANCHOR_DEPTH_BLOCKS`
  stay `u64` at the FFI/C++ edge and become `BlockCount` when they
  participate in inland arithmetic with a typed height.
  `BlockHeight − BlockHeight` already yields `BlockCount`
  (`rust/shekyl-types/src/lib.rs:39-41`,
  `rust/shekyl-types/src/lib.rs:813-825`). Height-semantics Phase 2b
  added the same shape for the count clock: `ChainCount ± BlockCount`
  yields `ChainCount`; `ChainCount − ChainCount` yields `BlockCount`.
- **C5 Sentinels are not counts.** `target_height == 0` means
  synchronized, not a genesis-only chain. Decode to
  `Option<ChainCount>` (`None` = synchronized). The *wire* sentinel
  deletion stays the daemon-RPC lane's item; inland typing does not
  wait for that deletion and does not encode 0 as `ChainCount`.
- **C6 Template height is `ChainCount::next_height()`.**
  `create_block_template` sets `height = m_db->height()`
  (`src/cryptonote_core/blockchain.cpp:1718`). Numerically the count;
  semantically the ordinal the next block will carry
  (`rust/shekyl-types/src/lib.rs:933-935`).
- **C7 Naming, new inland fields.** Never a bare identifier `height`.
  `tip_height` (ordinal), `chain_count`, `anchor_height` (ordinal),
  ages as `*_blocks`. Existing JSON/Levin keys are the wire and stay.
  Exception (kept, not renamed): `BlockSource::tip_height` is the WI-3
  named clock and returns `ChainCount` (height-semantics Phase 2b).
- **C8 C++ daemon glue stays `u64`.** Rule 20: this campaign does not
  retype C++. The wire table still names those producers so a Rust
  consumer cannot guess.
- **C9 `compile_fail` per conversion boundary** lands in the retype PR
  that creates that boundary. The deliberate wrong-mix that no longer
  compiles is the proof the type is load-bearing. Height-semantics
  Phase 2b landed three crate-doc `compile_fail`s on `shekyl-types`
  (count as height, height as count, `ChainCount + BlockHeight`).

### 3.2 One `BlockHeight`

`shekyl-curve-tree` re-exports `shekyl_types::BlockHeight` (RTN-4,
`rust/shekyl-curve-tree/src/types.rs:131-137`). Confirmed on this tree:
no second definition. FFI replica internals remain out of scope beyond
that name check.

### 3.3 Wire table

Conversion at decode, once. Raw `u64`s do not travel inland. C++
producers cited at source.

**JSON / JSON-RPC DTOs (`shekyl-rpc-types`):**

| Surface | Field | Quantity | Producer / decode |
| --- | --- | --- | --- |
| `GET /get_height` | `GetHeightResponse.height` (`rust/shekyl-rpc-types/src/chain.rs:179`) | COUNT | Facts POD already `+1` (`src/rpc/rpc_facts_ffi.cpp:73-75`); handler copies (`rust/shekyl-daemon-rpc/src/methods.rs:102-108`). Wallet client documents "amount of blocks", genesis-only = 1 (`rust/shekyl-rpc-client/src/lib.rs:380-384`). |
| `get_block_count` | `GetBlockCountResponse.count` (`rust/shekyl-rpc-types/src/chain.rs:191`) | COUNT | Same chain-height as `/get_height`, honest field name. |
| `GET /get_info` | `height` | COUNT | C++ still serves: `get_blockchain_top` then `++res.height` (`src/rpc/core_rpc_server.cpp:206-207`). |
| `GET /get_info`, `get_version`, `sync_info` | `target_height` | COUNT or 0-synced | Handler rule, not the core scalar: C++ `is_synchronized() ? 0 : get_target_blockchain_height()` (`src/rpc/core_rpc_server.cpp:209`); Rust `get_version` the same (`rust/shekyl-daemon-rpc/src/methods.rs:114-116`, `rust/shekyl-daemon-rpc/src/methods.rs:137-142`). Core stores the advertised remote count (`src/cryptonote_core/cryptonote_core.cpp:1755-1762`). Inland: `Option<ChainCount>` (C5). Wire sentinel deletion is not this campaign. |
| `get_version` | `current_height` (`rust/shekyl-rpc-types/src/chain.rs:353`) | COUNT | `tip.chain_height.to_raw()` (`rust/shekyl-daemon-rpc/src/methods.rs:137`). |
| `get_block_hash` number / `GetBlockRequest.height` (`rust/shekyl-rpc-types/src/chain.rs:275`) / `GetBlockHeaderByHeightRequest.height` (`rust/shekyl-rpc-types/src/chain.rs:319`) / `GetBlocksByHeightRequest.heights` (`rust/shekyl-rpc-types/src/bin_commands.rs:165`) | those fields | ORDINAL | Zero-indexed position (`rust/shekyl-rpc-client/src/lib.rs:410-413`). Bound vs COUNT is `height >= chain_height` (`src/rpc/rpc_facts_ffi.h:82`). |
| `BlockHeader.height` (`rust/shekyl-rpc-types/src/chain.rs:225`) | `height` | ORDINAL | Header of that block. |
| `BlockHeader.depth` (`rust/shekyl-rpc-types/src/chain.rs:227`) | `depth` | DIFFERENCE | `chain_height - height - 1` (`src/rpc/rpc_facts_ffi.h:105`). Inland: `BlockCount`. |
| `HardForkEntry.height` (`rust/shekyl-rpc-types/src/chain.rs:338`) / `HardForkInfoResponse.earliest_height` (`rust/shekyl-rpc-types/src/headers.rs:186`) | those fields | ORDINAL | Activation / earliest-voted height. |
| `GetBlockHeadersRangeRequest.start_height` / `end_height` (`rust/shekyl-rpc-types/src/headers.rs:117-119`) | those fields | ORDINAL inclusive | Range of header lookups. |
| `ConnectionInfo.height` (`rust/shekyl-rpc-types/src/p2p.rs:240`) | `height` | COUNT | Peer's claimed blockchain height. |
| `SyncInfoResponse.height` (`rust/shekyl-rpc-types/src/p2p.rs:289`) | `height` | COUNT | Local chain height. |
| `SyncSpan.start_block_height` (`rust/shekyl-rpc-types/src/p2p.rs:270`) | `start_block_height` | ORDINAL | Span origin. |
| `getblocktemplate.height` (`src/rpc/core_rpc_server_commands_defs.h:441`) | `height` | next-block ordinal (= COUNT numeric) | `height = m_db->height()` (`src/cryptonote_core/blockchain.cpp:1718`); RPC writes `res.height` (`src/rpc/core_rpc_server.cpp:689`). Inland: `ChainCount::next_height()` (C6). |
| `getblocktemplate.seed_height` | `seed_height` | ORDINAL | Seed block index. |
| `get_curve_tree_info.height` | `height` | ORDINAL | `get_current_blockchain_height() - 1` (`src/rpc/core_rpc_server.cpp:1426`) — already converted to the tip ordinal. |
| `pop_blocks.height` | `height` | COUNT | `res.height = get_current_blockchain_height()` after the pop (`src/rpc/core_rpc_server.cpp:1288`). |

**FFI PODs (stay `uint64_t` / `u64`; named decode on the Rust side):**

| POD | Field | Quantity |
| --- | --- | --- |
| `shekyl_rpc_chain_tip_facts` (`src/rpc/rpc_facts_ffi.h:35-37`) | `chain_height` | COUNT (`top_height + 1`, `src/rpc/rpc_facts_ffi.cpp:73-75`) |
| same | `target_height` | raw core target; 0-when-synced is the handler's (C5) |
| `shekyl_rpc_block_hash_facts` (`src/rpc/rpc_facts_ffi.h:81`) | `chain_height` | COUNT |
| `shekyl_rpc_block_header_facts` (`src/rpc/rpc_facts_ffi.h:104-106`) | `height` ORDINAL; `depth` DIFFERENCE; `chain_height` COUNT | as named in the header |
| `ChainTipFactsFfi` (`rust/shekyl-daemon-rpc/src/ffi.rs:337-342`) | twins of the C POD | stay raw |

**Levin:** `CORE_SYNC_DATA.current_height` (`rust/shekyl-levin/src/payload/types.rs:93-94`,
`src/cryptonote_protocol/cryptonote_protocol_defs.h:174`) is COUNT
("Chain height"). Stays `u64` on the wire (C1). Dual-stack fixtures
copy `get_info.height`, which is COUNT.

**C++ store primitives (the producers the names above rest on):**

| Call | Quantity |
| --- | --- |
| `BlockchainLMDB::height()` / `Blockchain::get_current_blockchain_height()` (`src/cryptonote_core/blockchain.cpp:257-264`) | COUNT |
| `BlockchainLMDB::top_block_hash` out-param (`src/blockchain_db/lmdb/db_lmdb.cpp:3179-3185`) / `Blockchain::get_tail_id(height)` (`src/cryptonote_core/blockchain.cpp:815-819`) | ORDINAL (`m_height - 1`) |

### 3.4 Inland family census

Families, not a dump of every `*height*: u64`. A site belongs to exactly
one family. **Unclear: none.**

| Family | Quantity | Type today | Ruled inland | Remaining |
| --- | --- | --- | --- | --- |
| Dispatch clock (`daemon_claimed_tip` + six consumers, §2.2) | COUNT | `ChainCount` | `ChainCount` | RULED 2026-09-20 (height-semantics Phase 2b); schema v11 |
| Wallet ledger (`TransferDetails.block_height` / `spent_height` / `eligible_height`, `rust/shekyl-engine-state/src/transfer.rs:226-237`, `rust/shekyl-engine-state/src/transfer.rs:328`) | ORDINAL | `BlockHeight` | `BlockHeight` | keep |
| Emission / claim source | COUNT split at decode | `ChainCount` | `ChainCount` | keep (pattern) |
| Daemon-RPC facts inland (`ChainTip.chain_height` / `target_height`, `BlockHashAt.chain_height`, `rust/shekyl-daemon-rpc/src/chain_facts.rs:47-54`, wrap at `rust/shekyl-daemon-rpc/src/chain_facts.rs:439-442`) | COUNT (target: COUNT-or-sentinel) | COUNT as `BlockHeight` | `ChainCount` and `Option<ChainCount>` | height-semantics Phase 2c |
| Wallet RPC client `Rpc::get_height` → `usize` | COUNT | bare | `ChainCount` at the client decode | height-semantics Phase 2c |
| Submit ref-age (`ref_age_window(chain_height, ref_height)`, `rust/shekyl-daemon-rpc/src/submit/engine.rs:118`) | COUNT vs ORDINAL | both `u64` | `ChainCount` vs `BlockHeight` | height-semantics Phase 2c |
| Countersign / pass-anchor (`own_height`, `anchor_height`, `predecessor_height`) | ORDINAL | `u64` | `BlockHeight` | height-semantics Phase 2d |
| Anchor depth / lag (`PASS_ANCHOR_DEPTH_BLOCKS`, `PASS_ANCHOR_LAG_BLOCKS`, `max_reorg_depth`, `BlockHeaderFacts.depth`) | DIFFERENCE | `u64` | `BlockCount` | height-semantics Phase 2d |
| Curve-tree ingest / `block_at` / DAA timestamps | ORDINAL | `BlockHeight` (RTN-4 re-export) | `BlockHeight` | keep |
| C++ daemon, p2p, mining RPC producers | as §3.3 | `uint64_t` | stay `uint64_t` (C8) | none in this campaign |
| Wire DTOs / FFI PODs | as §3.3 | `u64` | stay `u64` (C1); decode at the consumer | consumer work is Phase 2c/2d |

**Not block-axis (named so they are not unclear):** curve-tree
positions, gindex, leaf indices (`Gindex` is `GlobalOutputIndex`,
`rust/shekyl-curve-tree/src/types.rs:139-142`). Epoch numbers derived
from a height are epoch indices; the *input* height is the classified
quantity.

### 3.5 Remaining slices

- **Height-semantics Phase 2b — dispatch-clock retype — RULED 2026-09-20.**
  `daemon_claimed_tip` returns `ChainCount`; `BlockSource::tip_height` is
  `ChainCount` (method name kept: WI-3 named clock); `block_at` stays
  `BlockHeight`; `anchor_t0` / due / alarm / dispatch `at` retyped
  together (WI-3 R2-1). No numeric change (Phase 1 pin: a 3-block chain
  still reports 3). Persisted stamp fields took schema bump
  `PENDING_POST_VERSION` 10 → 11 (rule 42; postcard bytes identical).
  C9 `compile_fail`s land in `shekyl-types` crate docs. Offsets
  (`bond_post_offset_blocks`, `reorg_depth`, `alarm_horizon_blocks`)
  stay `u64` until Phase 2d (C4: convert at inland arithmetic only).
- **Height-semantics Phase 2c — wire/FFI inland decode.**
  `ChainTip` / `BlockHashAt` / client `get_height` / submit ref-age.
  `compile_fail` at each new boundary.
- **Height-semantics Phase 2d — remaining inland bare `u64`.**
  Countersign clocks and difference constants. Same `compile_fail` bar.

**Out of scope of the whole audit:** any stamp value change (none from
Phase 1); the daemon-RPC `target_height` *wire* sentinel deletion
(daemon lane); the curve-tree FFI replica's internals beyond the
type-name check; C++ retyping (C8).

## 4. How a reader uses this page

"Which `h`?" — §1 for the two quantities, §2.2 for the six stamps, §3.1
for the inland/wire split, §3.3 for a named RPC/FFI field, §3.4 for
which family a site belongs to. After height-semantics Phase 2b–2d the
types make a wrong mix a compile error.
