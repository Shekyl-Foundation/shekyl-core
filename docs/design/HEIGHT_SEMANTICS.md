# Height semantics — ordinal vs count

**Status:** OPEN — Phase 1 walked 2026-09-19 (this file); Phase 2 (workspace
census, wire table, retype + `compile_fail`) is the remaining work. Numerics
are frozen as pinned (Rick, 2026-09-19). This file does not change any stamp.

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
| Chain count | how many blocks; = tip + 1 | 1 | `ChainCount` (`rust/shekyl-types/src/lib.rs:328-352`) |
| Difference | span between two instants | n/a | `BlockCount` (`rust/shekyl-types/src/lib.rs:310-315`) |

C++ overloads "height" for the count (`m_db->height()`, `get_height`,
`get_info.height` after `++res.height` at
`src/rpc/core_rpc_server.cpp:206-207`). The Rust vocabulary already
splits the types; the remaining tax is callers that wrap a count in
`BlockHeight`.

Named conversions, already on `ChainCount`
(`rust/shekyl-types/src/lib.rs:894-911`):

- `tip()` — newest existing block (`count − 1`); spendability / reference.
- `next_height()` — height the next block will carry (numerically the
  count); earliest inclusion.

`SyncedChainFacts` (`WSS-Q14`, PR #792) is the pattern: `chain_height()`
returns `ChainCount`, `.tip()` is the named conversion, and the type
refuses an unsynced view. It is not a special case of this audit.

## 2. Phase 1 — the consensus-adjacent walk

Ground: `daemon_claimed_tip`
(`rust/shekyl-engine-core/src/engine/pscan/block_source.rs:180-198` on
this tree) wraps `Rpc::get_height` — documented as **the amount of
blocks**, genesis-only = 1 (`rust/shekyl-rpc-client/src/lib.rs:380-384`)
— into `BlockHeight::from_raw`. PR #792 freezes that numeric
(`facts.chain_height().to_raw()`, not `.tip()`) and pins it with
`a_synchronized_daemon_reports_the_unchanged_clock` (3-block chain
reports 3). The identifier says "tip"; the value is a count.

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
| Producer | `rust/shekyl-engine-core/src/engine/pscan/block_source.rs:180-198` | n/a (wrapper) | COUNT as `BlockHeight` | `get_height` is count (`rust/shekyl-rpc-client/src/lib.rs:380-384`); wrap is `from_raw`. | Pin; retype in Phase 2. |
| `BlockSource::tip_height` | `rust/shekyl-engine-core/src/engine/pscan/block_source.rs:94-105`; DaemonBlockSource `rust/shekyl-engine-core/src/engine/pscan/block_source.rs:237-239`; PBlockSource `rust/shekyl-engine-core/src/engine/pscan/block_source.rs:288-291` | **COUNT** (claimed chain size; exclusive end of `0 .. tip`) | COUNT as `BlockHeight` | Trait doc already: "the *count* of blocks"; `block_at` valid on `0 .. tip_height`. | Rename honestly (`ChainCount`). `block_at` args stay ordinal. |
| `block_at` / `block_number` | `rust/shekyl-engine-core/src/engine/pscan/block_source.rs:130-133`, `rust/shekyl-engine-core/src/engine/pscan/block_source.rs:201-210` | **ORDINAL** (which block) | `BlockHeight` used as a 0-indexed fetch number | `get_block_hash` `number` is "zero-indexed position" (`rust/shekyl-rpc-client/src/lib.rs:410-413`). | Already the right type; keep. |
| P-scan sweep exclusive end | `rust/shekyl-engine-core/src/engine/pscan/task.rs:245-248`, `rust/shekyl-engine-core/src/engine/pscan/task.rs:295-297` | bound = COUNT; index = ORDINAL | COUNT − `reorg_depth` as exclusive end; loop `for height in start..end` calls `block_at(ordinal)` | Half-open range over a count. Flipping the bound to `.tip()` without changing the loop **skips the last block**. | Split types at retype. No numeric change. |
| `anchor_t0` stamp | `rust/shekyl-engine-core/src/engine/bond_orchestrator.rs:555-557`; field `rust/shekyl-engine-state/src/pending_post_block.rs:137-143` | same-clock threshold (WI-3 R2-1) | COUNT as `BlockHeight` | Spec name is "tip height at assemble time" (`ARCHIVAL_BOND_WI2_ASSEMBLY.md:250-268`); the consuming rule is `due = anchor_t0 + offset` compared to the **same** `daemon_claimed_tip` read. Arithmetic never indexes a block. | COUNT. Rename honestly. Converting to ordinal is only legal if stamp, due-check, and alarm move together. |
| Due-check | `rust/shekyl-engine-core/src/engine/pscan/dispatch.rs:256-264`, `rust/shekyl-engine-core/src/engine/pscan/dispatch.rs:292` | same clock as `anchor_t0` | COUNT vs COUNT | `due_height <= tip.to_raw()`. WI-3 R2-1: stamp and due-check switch together or offsets change meaning. | Shared. Rename both ends together. |
| Alarm / resubmit horizon | `rust/shekyl-engine-core/src/engine/pscan/dispatch.rs:296-298` | same clock as dispatch `at` | COUNT vs COUNT | `tip < at + alarm_horizon`. `at` is the dispatch stamp. | Shared. Same as due-check. |
| Claim dispatch `at` | `rust/shekyl-engine-core/src/engine/claim_dispatch.rs:369` | "when dispatched" vs a later same-clock tip | COUNT | Comment: same named clock as bond dispatch (WI-3 R2-1). | COUNT. Rename with the clock. |
| Drain dispatch `at` | `rust/shekyl-engine-core/src/engine/drain_dispatch.rs:397` | same | COUNT | Same clock comment (`rust/shekyl-engine-core/src/engine/drain_dispatch.rs:394-396`). | COUNT. Rename with the clock. |
| Release dispatch `at` | `rust/shekyl-engine-core/src/engine/release_dispatch.rs:606` | same | COUNT | Same clock comment (`rust/shekyl-engine-core/src/engine/release_dispatch.rs:604-605`). | COUNT. Rename with the clock. |
| Emission claim gather | `rust/shekyl-engine-core/src/engine/emission_source.rs:258-269`, `rust/shekyl-engine-core/src/engine/emission_source.rs:545-548` | already split | `ChainCount` | Decode names the type; consumers take `next_height()` (inclusion) or `tip()` (spendability). **Does not** call `daemon_claimed_tip`. | Pattern, not a finding. |
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

## 3. Phase 2 — census, convention, retype (OPEN)

Out of this PR. Seed rows so the census does not rediscover them:

**Wire (conversion at decode, once; raw `u64`s do not travel inland):**

| RPC field | Quantity | Provenance (this walk) |
| --- | --- | --- |
| `get_height` | COUNT | `rust/shekyl-rpc-client/src/lib.rs:380-384` |
| `get_info.height` | COUNT | `src/rpc/core_rpc_server.cpp:206-207` (`++res.height`) |
| `get_info.target_height` | **determine, do not assume** | zero-sentinel is a separate FOLLOWUPS row (daemon-RPC lane, filed with #792) |
| block-header / `get_block_hash` number | ORDINAL | `rust/shekyl-rpc-client/src/lib.rs:410-413` |

**Two types named `BlockHeight`:** on this tree they are one type.
`shekyl-curve-tree` re-exports `shekyl_types::BlockHeight` (RTN-4,
`rust/shekyl-curve-tree/src/types.rs:131-137`). Phase 2 confirms no
second definition remains (FFI replica internals are out of scope
beyond this name check).

**Differences:** `BlockCount` already exists. Phase 2 picks "newtype
everywhere" vs "documented bare-`u64` for ages" and enforces it.
`height − height` silently yielding a value that then adds to a count
is the mix the types must refuse — `BlockHeight − BlockHeight` already
yields `BlockCount` (`rust/shekyl-types/src/lib.rs:39-41`).

**Naming rule (lands with the convention):** `height` never appears
bare. `tip_height` (ordinal), `chain_count`, `anchor_height` (ordinal),
ages as `*_blocks`.

**Red-bite:** at least one `compile_fail` doc-test per conversion
boundary. The deliberate wrong-mix that no longer compiles is the proof
the type is load-bearing.

**Out of scope of the whole audit:** any stamp value change (none from
Phase 1); the daemon-RPC `target_height` sentinel deletion (filed,
daemon lane); the curve-tree FFI replica's internals beyond the
type-name check.

## 4. How a reader uses this page

"Which `h`?" — §1 for the two quantities, §2.2 for the six stamps, §3
for the wire seed. After Phase 2 the wire table in §3 is complete and
the types make a wrong mix a compile error.
