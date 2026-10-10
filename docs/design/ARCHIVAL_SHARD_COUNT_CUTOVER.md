# The shard-count cutover — census and tracking

**Status:** OPEN — **Round 0 executed 2026-09-27 at `9d549ead2`** (census and
tracking). **AMENDED the same day** on the design owner's review: `SCC-4` widened
from two definitions to **six** and **fixed here** (the one code change this round
carries, `SCC-Q5`), and `SCC-Q1`, `SCC-Q3`, `SCC-Q4`, `SCC-Q5` answered — `SCC-Q2`
stands as Rick's ruling. **AMENDED 2026-09-29 by `SHT-Q2` (RULED): shards are cut by
archival length, bound through the txid** — family 1's boundary function changes from a
count to `⌊cum_before / W⌋` over a cumulative archival-length cell; the consumers are the
same, and three rows join the census (the stored length, the cell, the txid mixer).
Identifier families **`SCC-`** (findings) and
**`SCC-Q`** (questions), registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 with this file (rule 94
§1; `check_index_prefix_uniqueness.py` branch (a) — `SCC` parses as its own
prefix and is clear of `SCW`, `SCE` and `SCU`).

**Design owner:** Claude (claude.ai, Shekyl project). **Rick authorizes and
ratifies.** No consensus change lands without a rule-07 ratification.

**This document is the effort's durable record.** Anything decided in the
design-owner lane that is not written here does not exist. That is the whole
point of it: the rulings below were taken across several sessions, and a
conversation is not a record.

**One sentence.** The shard partition was re-defined by `SHT-Q1` and the segment
geometry it inherited is retiring, so every consumer that counts shards, closes
them, or reads a constant calibrated in *segment* units has to be found,
classified and cut over — in two atomic groups, because one of those constants
feeds the coinbase's fee split — harmlessly today, since the escalation ships
flat, and decisively the moment the GF-7 ceremony turns the ramp on.

---

## A. Scope and ruled inputs

Three rulings are inputs here, not questions. Each is recorded in full at its own
home; the operative consequences are restated only as far as this census needs.

| input | ruling | home |
|---|---|---|
| **`SHT-Q1`** | **RULED (Rick, 2026-09-27, design-owner lane): the partition is over transactions that carry archival good** — a non-empty prunable region or `pqc_auths`, decided from the **rows recorded at ingest**, never recomputed from a possibly-pruned body. Shard `k` is the domain's transactions `[k·T, (k+1)·T)` in chain order. **Shards close on count only; there is no clock.** The coinbase is outside by the definition, not by exclusion. Closed shards never change membership; any later change to what counts as good activates by height. The equality with the non-coinbase set is an **invariant, not a definition**, pinned by `rules::tx::tx_domain_tests` and leg (f). | [`ARCHIVAL_SHARD_T_DERIVATION.md`](../completed/ARCHIVAL_SHARD_T_DERIVATION.md) §2 |
| **`SHT-8`** | D2's operand `n` and `g(age)`'s no-segment branch are keyed on the **retired** segment count. `n` reaches consensus, and a shard-unit re-key would move `escalation_knee_n` ~65× sooner and make `T` a clock on monetary policy — **once the escalation is switched on**. It is flat at the shipped parameters (§G `SCC-Q2`), so the re-key is behaviour-neutral today. | same doc, §6 and §5 |
| **`SHT-Q2`** | **RULED (Rick, 2026-09-29): shards are cut by archival length, bound through the txid.** Each in-domain transaction's archival length (prunable + `pqc_auths` bytes) is folded into its txid and stored as a skeleton row — never declared or signed, supplied by storage-pruned forms like the prunable hash. Membership `⌊cum_before / W⌋` over the cumulative archival length: global multiples of `W`, no table; static `max archival length < W`. `W = 3,000,000 B` PROVISIONAL (same day). `SHT-Q1`'s domain unchanged. | [`ARCHIVAL_SHARD_T_DERIVATION.md`](../completed/ARCHIVAL_SHARD_T_DERIVATION.md) §8.6, §9 |
| **`L2`** | **RULED and withdrawn as a bound on `T`.** `MAX_HOLDINGS_SHARDS` is a **list-size bound** on one bond record and one transaction, not bond-size policy; personas are free (G-1) and splitting is rational, so no per-persona limit binds. The 13.6/13.7 GB byte products are retired from reasoning. Two couplings survive, owed **only if the cap's own value moves** (§E). | same doc, §3 `L2` |

**Out of scope for this round:** any code change, any re-derivation of a
constant's value, and the `PDM-Q-F34` sim arms (their own FOLLOWUPS rows).

---

## B. The census

**Method, and why it is grep-driven.** `PDM-Q6` item 4 produced a nine-row
re-key table by hand and **missed both D2's `n` and `escalation_knee_n`**
(`SHT-8`) — an economics operand in another crate was not on anyone's list. So
every hand-made list is treated as incomplete, **including this one**, and each
row below is a grep result at `9d549ead2` rather than a recollection.

### `SCC-1` — the census's own first hazard: "segment" is two different words

A bare grep for `segment` conflates two unrelated things:

- **curve-tree J-segments** — the retiring geometry: `SEGMENT_LEAF_COUNT`,
  `leaves_per_segment()`, `SEGMENT_LAYER_J`, `frozen_segment_count`.
- **transaction body segments** — permanent and unrelated: `write_segments()`,
  `TxPrunedSegment`, `TxPqcAuthsSegment`
  (`rust/shekyl-chain-store/src/store/connect.rs:403-414`, re-read
  2026-09-29 after E6 slice 7 wave B shortened the file).

This is not pedantry: it is how a seeded row in this round's own brief acquired a
false premise (`SCC-2`). Family 2's greps below therefore key on the **specific
symbols**, never on the word.

### Family 1 — shard closure and the domain

What changes under `SHT-Q1`: **which ids are in the domain**, and therefore which
ids a boundary falls between. Nothing here needs a shard to close by height —
verified as `SHT-Q1`'s own falsifier.

**What changes under `SHT-Q2` (2026-09-29): the boundary function, not the consumers.**
A shard is no longer `T` domain transactions but the domain transactions whose
cumulative archival length **before** them lies in `[k·W, (k+1)·W)`, so membership is
`⌊cum_before / W⌋` over a cumulative archival-length cell, where it was `⌊ordinal / T⌋`.
Every consumer below keeps its job; the rows marked **`SHT-Q2`** change the function
behind it, and the last three rows are new.

**Rust half BUILT 2026-09-29 (PR #910).** The partition constant, the discard range, the
id→shard map, the last closed shard, `h_scarce`, the archival-length row and the
cumulative cell are built as the rows below describe, with two differences from the
text. The storage-id arithmetic keeps its coinbase term, because ids stay storage ids
and the boundary is an archival offset. The shard's opening height is found by a descent
that checks every block it passes against its parent (SI-13, and SI-24: its length rows
sum to its cell), not by the binary search the `h_scarce` row names. The rows' `file:line` cites are the census pin's; `store/prune.rs` is the live
statement. **Held:** the txid mixer row, on the pruned-form blocker (FOLLOWUPS "Build
`SHT-Q2`").

| consumer | file:line at the pin | what it computes | class | changes under `SHT-Q1` | old-unit constant |
|---|---|---|---|---|---|
| the partition constant | `rust/shekyl-types/src/archival/mod.rs:94`, generated by `rust/shekyl-types/build.rs:70`, `> 0` assert at `:101` | `T`, the one home | consensus | value only (`T` is a count either way). **`SHT-Q2`:** the **unit** changes — `W` in bytes, `3,000,000 B` provisional; the key and both generated names are renamed, and the `> 0` assert becomes the static relation `max archival length < W` | `archival_shard_tx_count` |
| storage-id arithmetic | `rust/shekyl-types/src/archival/mod.rs:111` (`storage_ids_through`) | ids through a height = `listed + height + 1` | consensus | **yes** — the coinbase term is what the domain excludes | — |
| the discard range | `rust/shekyl-chain-store/src/store/prune.rs:267` | `shards.start·T .. shards.end·T` | consensus (node-local effect) | **yes** — the range is over domain ordinals, not storage ids. **`SHT-Q2`:** over archival-length offsets — the transactions whose `cum_before` lies in `[start·W, end·W)` | — |
| the id→shard map | `rust/shekyl-chain-store/src/store/prune.rs:415-416` | `⌊id / T⌋` for the boundary pair | consensus | **yes** — becomes `⌊ordinal / T⌋`. **`SHT-Q2`:** becomes `⌊cum_before / W⌋` | — |
| the last closed shard | `rust/shekyl-chain-store/src/store/prune.rs:490`, `:493` | `⌊hi_id / T⌋ − 1`, then its last id | consensus | **yes**. **`SHT-Q2`:** `⌊cum_through / W⌋ − 1` over the cell, then its last transaction by the same search `h_scarce` already uses | — |
| `first_tx_id` | `rust/shekyl-chain-store/src/store/prune.rs:434`, callers `:411-412`, `:489` | adds the coinbase term | consensus | **yes** — the addition **goes away** under the domain (`cumulative_tx_count` *is* the non-coinbase ordinal, `listed_before` at `:421-428`) | — |
| `h_scarce` | `rust/shekyl-chain-store/src/store/prune.rs:477`, public at `:380` and `:548` | the last discarded shard's close height, via `height_of_tx_id`'s binary search (`:498`) | node-local | **yes** (its operand) — but the search itself already exists and is reused | — |
| the domain predicate | `rust/shekyl-wire/src/transaction/txid.rs` (`carries_archival_good`), production path `rust/shekyl-chain-store/src/store/read.rs:735` → `tx_reads.rs` | domain membership from the two ingest rows | consensus | **landed** — this is `SHT-Q1` as built. **`SHT-Q2`:** unchanged; `archival_len > 0 ⇔ carries_archival_good` joins it as a pinned invariant | — |
| shard identity and holdings | `rust/shekyl-archival-retention/src/**` — 156 `shard_id`, 103 `shards`, 51 `shard_ids`, 36 `shard_age_milli`, 18 `r_market_by_shard` | bond holdings, admission, challenge draw, settlement | consensus | **yes, by enumeration** — every site that names or iterates shard ids | `segment_leaf_count` via `shard_age_milli` (family 2) |
| wallet-side serve sets | `rust/shekyl-engine-core/src/engine/curve_tree_actor.rs:201`, `:378` (`pin_serve_set`), `rust/shekyl-engine-core/src/engine/bond_assembly.rs:584`, `rust/shekyl-engine-core/src/engine/bond_orchestrator.rs:427` | which shards a persona pins and posts | wallet | **yes** | — |
| the FFI archival shims | `rust/shekyl-ffi/src/archival_ffi/*` (bond, emission, attestation, epoch_close, ct_balance, codes), `archival_admission_ffi.rs` | the C++ boundary for all of the above | consensus | **yes, wherever a shard id crosses** | — |
| **new (`SHT-Q2`)** the archival-length row | `rust/shekyl-chain-store` schema, beside `txs_prunable_hash` / `txs_pqc_auth_hash` | each in-domain transaction's archival length (prunable + `pqc_auths` bytes, as `write_segments` emits them) | consensus | **new** — written at connect from the body; supplied by storage-pruned and skeleton forms like the prunable hash; a rule-42 schema bump | — |
| **new (`SHT-Q2`)** the cumulative archival-length cell | `block_info`, beside `cumulative_tx_count` (`rust/shekyl-chain-store/src/codec/chain.rs`) | running total of archival length through each block, `checked_add` under SI-8 | consensus | **new** — the operand of every boundary above; `cumulative_tx_count` stays, because it feeds the fee ladder (CEN-F20) | — |
| **new (`SHT-Q2`)** the txid mixer | Rust `mix` (`rust/shekyl-wire/src/transaction/txid.rs`) — **the one mixer**, reached from a parsed body (`Transaction::txid_parts`), from a pruned or skeleton body with its components supplied (`hash_with_supplied_prunable`, `hash_with_supplied_components`), and from a serialized body's byte ranges (`TxidSegments::txid`); C++ `calculate_transaction_hash` (`src/cryptonote_basic/cryptonote_format_utils.cpp`) **calls the last over FFI** (`shekyl_txid_from_segments`), its hashing deleted (row 3 = (b), RULED 2026-09-29 — the length term is never written in C++) | the transaction id | consensus | **new operand** — the archival length is folded in, so **every non-coinbase txid changes**; the coinbase's 3-part form is unchanged | — |

**`SCC-2` — a correction to the brief's family-1 list.** It named
archival-retention's `bond_duration`, `failure_window`, `serve_credit_decisions`,
`emission_verify` and `consensus_state` under *shard closure*. What those read is
**`epoch_close_height`** (`rust/shekyl-archival-retention/src/consensus_state.rs:67`; callers `rust/shekyl-archival-retention/src/bond_duration.rs:112`,
`rust/shekyl-archival-retention/src/emission_verify.rs:471`) — the **settlement-epoch** close, `H_close(E) = (E+1)·SEB`,
which has nothing to do with a shard closing. Two different "close" notions share
a word. Those files are in family 1, but through **shard identity**
(`shard_age_milli`, `r_market_by_shard`), not through closure. Recorded because a
cutover that re-keys `epoch_close_height` would be changing the settlement
calendar by accident.

### Family 2 — the segment geometry and D2's operand

**Round 0, re-run at `3319c54d82` (2026-10-04).** This replaces the table taken at
`9d549ead2` on 2026-09-27, most of whose rows no longer describe the tree. The greps
key on symbols (`SCC-1`): `frozen_segment_count`, `FrozenSegmentCount`,
`leaves_per_segment`, `SEGMENT_LAYER_J`, `segment_leaf_count` / `SEGMENT_LEAF_COUNT`,
`SegmentId` and the `FrozenSegment*` types in `shekyl-curve-tree`.

Each consumer has one class:

- **A** — archival-partition use with no C++ caller: delete or re-key now.
- **B** — an FFI export, or what it is built on, backing the C++ path that row 3 = (b)
  leaves alone (§F). Kept. **It dies with the engine swap.**
- **C** — a curve-tree use that is not archival (the tree's own storage tiers and
  proof topology). Kept, with a proposed name.
- **H** — fits none of the three, or its class depends on a ruling or on another
  lane's unbuilt work. **Halted and reported**, not executed.

**Ruled (design owner, 2026-10-04, at `16820f455b`):** the classes stand as
censused. Class C's names are approved and land as their own PR; class H is not
re-keyed here and its two replacements are named; class B gains the verifier's
successor. Each ruling is recorded under its class below.

**Landed since the 2026-09-27 table** (a census delta is a set difference, so each
missing row is named with what removed it):

| What | Now | Removed or landed by |
|---|---|---|
| D2's operand `n` | `ClosedShardCount` (`rust/shekyl-economics/src/escalation.rs:62`; `staker_pool_share_at` at `:283`), fed by `closed_shards_before` in `shekyl-chain-rules` (CEN-F17). `SCC-Q1` was superseded on 2026-10-01: the operand is closed shards at parent state | `45e0a49d8d` (E4 commit 3) |
| `FrozenSegmentCount`, the type | no hit in the tree | the same commit |
| the block template's operand (`shekyl-block-template/src/lib.rs:142`) and the ingest scenario's `FrozenSegmentCount::ZERO` (`shekyl-chain-ingest/src/scenario.rs:414`) | no hit in either crate | the same commit |
| `g(age)`'s no-segment branch | `ShardClose::{Open, ClosedAt(h)}` on the fold | PR #928 |

**Class B — kept, dies with the engine swap.**

| Consumer | Sites at the pin | Backs |
|---|---|---|
| the frozen-segment count | `shekyl_archival_frozen_segment_count` (`rust/shekyl-ffi/src/archival_ffi/schedule.rs:221-222`) over `frozen_segment_count` (`rust/shekyl-archival-retention/src/segment_freeze.rs:98`) | `Blockchain::parent_frozen_segment_count` and the fee split (`src/cryptonote_core/blockchain.cpp:1494-1508`); the registry's pop revert (`src/blockchain_db/lmdb/db_lmdb.cpp`) |
| the economics exports' operand name | `rust/shekyl-ffi/src/economics_ffi.rs:127`, `:172`, `:265` take `frozen_segment_count: u64` and wrap it in `ClosedShardCount::new` (`:133`, `:186`, `:268`) | the C++ feeds its segment count there: the ruled CEN-L10 divergence, not a missed rename |
| serve-credit verification | `challenge_leaf_index` (`rust/shekyl-archival-retention/src/challenge.rs:129`, which takes `segment_leaf_count`); `LeafChunkBounds`, `challenged_leaf_offset_in_chunk`, `challenge_leaf_chunk_bounds` (`segment_freeze.rs:105-160`); `verify_segment_path` (`path.rs`); the context field `segment_leaf_count` (`rust/shekyl-ffi/src/archival_ffi/codes.rs:618`, offset pinned at `:644`). Exported as `shekyl_archival_challenge_leaf_index` (`serve_credit.rs:76`), `shekyl_archival_challenge_leaf_chunk_bounds` (`schedule.rs:232`) and `shekyl_archival_verify_serve_credit_vin` (`serve_credit.rs:123-236`) | the live serve-credit arm (`blockchain.cpp:4909`, `:4921`; CEN-J9, CEN-J10) |
| the constant | `segment_leaf_count` (`config/consensus_constants.json:58-59`); its generators (`rust/shekyl-archival-retention/build.rs:231-251`, `cmake/generate_consensus_constants.py:85-89`, `:272-281`); `SEGMENT_LEAF_COUNT` and the compile-time tie `SEGMENT_LEAF_COUNT == leaves_per_segment()` (`segment_freeze.rs:52-88`) | every row above, and the C++ consumers below. **It stays in `consensus_constants.json` and leaves with the engine swap.** The tie stays too: it binds the class-B operand to the class-C topology for as long as both exist |
| the KATs and FFI tests | `rust/shekyl-archival-retention/tests/{gate2_serve_credit_kat,gate4_lifecycle_kat,tj_red_challenge_scope,assembled_path_crosscheck}.rs`; `rust/shekyl-ffi/src/archival_ffi/tests.rs:1045`, `:1091` | hold the rows above |
| the C++ side | `src/cryptonote_core/blockchain.{cpp,h}`, `src/cryptonote_core/cryptonote_tx_utils.{cpp,h}`, `src/blockchain_db/{blockchain_db.{cpp,h},shekyl_types.h,lmdb/db_lmdb.{cpp,h}}`, `src/rpc/archival_shard_coverage.cpp:34`, `src/shekyl/{economics.h,shekyl_ffi.h}`, and their tests under `tests/` | row 3 = (b): not this cutover's |
| the gates over them | `scripts/ci/check_segment_freeze_sites.sh`, `scripts/ci/check_consensus_invariants.sh:250` | key on these symbol names; a rename would turn them into silent no-ops |
| **the serve-credit verifier's successor** (ruled 2026-10-04) | the verifier is the serve-credit row above, on both sides of the FFI: the C++ `check_archival_serve_credit_input` and the three exports it calls | **It dies with the engine swap, and it is not ported.** Its successor is SO-D8 Slice C (authorized at `4149c7a4d7`; [`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`](ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md) §8.0). CEN-J8's second clause, *"the shard's frozen segment must exist at `H_fire`"*, is stated on the leaf segment. Slice C's Round 0 must re-base it on the ruled partition (`SHT-Q1`, `SHT-Q2`), with possession proved on transaction bodies, not leaf chunks. **Possession is verified against what the txid binds** (added 2026-10-05): the digests `txs_prunable_hash` and `txs_pqc_auth_hash`, and the length `txs_archival_len` (`SHT-Q2`). The Rust store keeps all three after pruning (`rust/shekyl-chain-store/src/store/prune.rs:51-52`, `:99-100`), so a pruned validator can check a whole-shard read. **Slice C is a precondition of the engine swap:** `DEL-008` ([`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §12; `SCV-Q5`) allows no genesis and no cutover until Slice C's admission rows are `implemented` in `census.rs` and J8–J10 are retired. The same note sits in Slice C's Round-0 inputs as a cross-reference |

**Class C — kept. The curve tree's own segment.** A level-2 subtree of the tree is a
unit of *tree* storage: the store freezes it once buried, keeps its sub-root `R_k`,
and can drop its leaves. That is how a wallet holds the tree, and it would exist with
no archival market.

| Consumer | Sites at the pin | Proposed name |
|---|---|---|
| the topology definition | `SEGMENT_LAYER_J` (`rust/shekyl-fcmp/src/tree.rs:650`), `leaves_per_segment()` (`:678`, pinned `== 25_992` at `:690`); re-exported at `rust/shekyl-curve-tree/src/segment.rs:20`, `:112` and `lib.rs:77-79` | `TREE_SEGMENT_LAYER`, `leaves_per_tree_segment()` |
| the segment id and its freeze tier | `SegmentId` (`segment.rs:106`), `segment_freeze_eligible`; in `store/redb_backend.rs`: `FROZEN_SEGMENTS_TABLE` (`:31`), `FrozenSegmentRecord` (`:151`), `maybe_freeze_segments` (`:1509`), `prune_frozen` (`:2129`), `frozen_segment` (`:2189`), `verify_frozen_tail` (`:2256`) | `TreeSegmentId`; the `FrozenSegment*` names keep their shape with the `Tree` prefix |
| the sub-root | `store/ops.rs:8-199` (`try_extract_r_k`, the layer-J build); `tests/upper_layers_kat.rs` | follows the definition |
| the verify hot path | `client.rs:2346` (`root_at_count` over complete, unfrozen segments) | follows the definition |
| the verify-edge benchmark | `rust/shekyl-wss-q1b-bench/src/{verifyedge.rs,verifyedge_tests.rs,bin/verify_edge.rs}`: it times `root_at_count` (CT-6 F3(a)). **Not archival-shaped** | follows the definition |

*On the names.* None of these symbols says "shard" today. What they collide with is
`SCC-1`'s other word, the transaction-body segment, so the proposal is a `tree`
prefix. The rename touches `shekyl-fcmp`, `shekyl-curve-tree`, the benchmark and
every importer, and the two gates in the class-B table grep for the current names.

**Names APPROVED (design owner, 2026-10-04):** `TREE_SEGMENT_LAYER`,
`leaves_per_tree_segment()`, `TreeSegmentId`; the freeze tier's names follow the
prefix. `scripts/ci/check_segment_freeze_sites.sh` and
`scripts/ci/check_consensus_invariants.sh` are updated in the same commit as the
rename, so neither gate spends a commit matching nothing. **The rename is its own
PR, not this one.** It lands once the curve-tree worktrees open on 2026-10-04 have
merged; Rick names the window. Its `FOLLOWUPS.md` row carries that trigger.

**Class H — halted. The wallet-side serving unit.** On this path a frozen segment
*is* the shard (`rust/shekyl-p-serve/src/provider.rs:261`: *"Shard ids are segment
indices"*). It has no C++ caller, so it is class A by the definition. It is not
executable as class A:

| Consumer | Sites at the pin | Why it halts |
|---|---|---|
| the store's pins and served bodies | `rust/shekyl-curve-tree/src/store/redb_backend.rs`: `PINNED_SEGMENTS_TABLE` (`:35`), `pin_segment_for_serving` (`:1928`), `pin_serve_set` (`:2023`), `pinned_shard_ids` (`:2056`), `release_pins` (`:2091`), `members_missing_pins` (`:319`, `:1066`), `pruned_frozen_segments` (`:363`, `:1001`), `open_frozen_segment_body` (`:269`, `:2221`), `FrozenSegmentBody` (`:405`) | its replacement is the archiver serving-store rebuild, a wallet-lane design round that `FOLLOWUPS.md` records as unbuilt by design (`PDM-Q12`; `WALLET_SIDE_STORE.md`). And the C++ daemon still verifies pass records against these leaf segments (class B), so deleting it removes what the live path is served by |
| the served frame — DELETED 2026-10-08 | `rust/shekyl-curve-tree/src/served_frame.rs@f317d979c:177`, `:287` (`leaf_count ≤ leaves_per_segment()`) at the pin | its successor, fetch Sub-PR 2's tx-range body (`shekyl_wire::shard_frame`), landed and the module is gone; the serve loop is body-agnostic |
| the provider and the serve set | `rust/shekyl-p-serve/src/provider.rs:261-288`; `rust/shekyl-p-host/src/serve_set/witness.rs:125`, `:235` (`pruned_frozen_segments()`), `set.rs:75`, `report.rs:206` (`CompleteTreePrefix { frozen_count }`); their tests (`rust/shekyl-p-host/tests/composition.rs`, `rust/shekyl-p-serve/tests/store_axis.rs`, `rust/shekyl-p-serve/src/serve_tests.rs:101`, `rust/shekyl-engine-core/src/engine/stake_engine/serve_set_source_tests.rs:144-151`) | as above. The two doc comments that contrast the freeze cursor with `frozen_segment_count` stay accurate while that helper is class B |
| the fetch client's body ceiling | `max_body_bytes()` (`rust/shekyl-p-fetch/src/client.rs:85-91`, test at `:633`; `Cargo.toml:14`) | it is `SF-D6`'s pre-read `content-length` ceiling, bound to the served unit, which is still the leaf-segment frame. **`N × MAX_TX_SIZE` is `SF-D7`'s memory leg, a different quantity.** Lowering the ceiling to it refuses every response today's server sends. A valid maximum for the tx-range unit is Sub-PR 2's to derive (`ARCHIVAL_SHARD_FETCH.md`, `SF-D7` amendment 2026-10-03) |
| the sim's response-size figure | `RESPONSE_BYTES` (`rust/shekyl-economics-sim/src/proxy.rs:66-92`) | it prices the class-B retention proof (leaf chunk and branch layers). Its successor's record layout is not stated anywhere (`SERVE_CREDIT_VERIFIER.md`, `SCV-3`) |
| **the view RPC's `shard_hash` (added 2026-10-08) — DELETED 2026-10-08** | `src/rpc/archival_shard_fetch.cpp` copied the scheduler's 32 bytes into a `crypto::hash` named `rk`; `rust/shekyl-archival-fetch-sched/src/lib.rs` held `ShekylArchivalShardAggregateOut::shard_hash`, the C ABI struct the shim read. Both deleted with `SV-D3` (step 3) | the field was the retired partition's root; a `W`-byte shard has no stored hash. Its successor, `SV-D1`'s fold over the fetched archival bytes ([`SHARD_VIEW_FETCH.md`](SHARD_VIEW_FETCH.md)), is `shekyl_types::ShardView::shard_hash`, projected onto the wire by `shekyl_rpc_types::RequestArchivalShardResponse::shard_hash` from `shekyl-daemon-rpc`'s native method |
| the measurement rig's object | `rust/shekyl-sp-t3-spike/src/fixture.rs` (`ShardFixture`, `SHARD_BYTES`), `bins/extract_shard.rs` | the rig serves the leaf-segment unit because the server does. It follows the serving unit |

**Class H is not re-keyed here (design owner, 2026-10-04).** The archival serving
and fetch stack is built on leaf bodies, the unit `PDM-Q6` retired. It is replaced,
not converted, and both replacements must target byte-cut shards of transaction
bodies (`SHT-Q1`, `SHT-Q2`) read whole (`SF-D1`):

| Replacement | Owner | Replaces |
|---|---|---|
| the archiver serving-store rebuild | the wallet lane: [`WALLET_SIDE_STORE.md`](WALLET_SIDE_STORE.md) (`WSS-`; `PDM-Q12`) | the store's pins and served bodies, the provider, the serve set |
| fetch Sub-PR 2 | [`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md) (`SF-D7` as amended 2026-10-03) | the served frame, the fetch client's body ceiling |

The sim's response-size figure follows the record layout Slice C's Round 0 writes
(`SCV-3`), and the rig's object follows the serving unit.

**`shard_id` has two meanings until family 1's cutover** (design owner's review of
`4fca05e32b`, 2026-10-05). One integer type names two different objects:

| Where | Shard `k` is | Sites |
|---|---|---|
| the Rust store and `shekyl-chain-rules` | the `k`-th byte-cut range of transactions (`SHT-Q2`) | `closed_shards_before` (`rust/shekyl-chain-rules/src/rules/miner.rs:564`); the close and the slash universe (`rust/shekyl-chain-rules/src/archival/close.rs:136`, `rust/shekyl-chain-rules/src/archival/slash.rs:127`); the retention prune (`rust/shekyl-chain-store/src/store/prune.rs`); the bond-admission predicate when it is built |
| the serving stack and the live C++ verifier | leaf segment `k` | *"Shard ids are segment indices"* (`rust/shekyl-p-serve/src/provider.rs:261`); the wallet pins segment `k` for each held shard id (`rust/shekyl-engine-core/src/engine/curve_tree_actor.rs:379`, `rust/shekyl-engine-core/src/engine/stake_engine/serve_set_source.rs:218`); the serve-credit arm challenges leaf chunks of segment `k` (`src/cryptonote_core/blockchain.cpp:4867-4883`); the coverage list (`src/rpc/archival_shard_coverage.cpp:34`) |

This is the E3 handoff's falsifier, *"two shard geometries"* (§C, `SCC-3`), live
and known: not in one constants file, but in one identifier. **It is safe only
while no `shard_id` crosses from one meaning to the other.** Closure is family 1's
atomic cutover (§F).

*The crossing check, at `e0fb3eaa80` (2026-10-06).* Each path below was read at
source. No id passes from the Rust store or `shekyl-chain-rules` to the serving
stack, or to any RPC a wallet reads.

| Path checked | Finding |
|---|---|
| the Rust store's bond records (`bond_record`, `bond_records`, `served_shards`; `rust/shekyl-chain-store/src/store/read.rs:900-989`) | read only by `shekyl-chain-rules` (`archival/close.rs:344`), by `shekyl-chain-ingest`'s connector and scenarios, and by tests. No serving crate and no wallet crate depends on `shekyl-chain-store`: `shekyl-p-serve`, `shekyl-p-host`, `shekyl-p-fetch`, `shekyl-curve-tree`, `shekyl-wallet-rpc` and `shekyl-cli` do not name it, and `shekyl-engine-core` names `shekyl-chain-rules` and `shekyl-chain-ingest` as dev-dependencies only (`regtest_e2e.rs`) |
| `shard_coverage.rs` (`rust/shekyl-archival-retention/src/shard_coverage.rs`) | it belongs to the C++ path, not the Rust store: the C++ fills its operands from LMDB's segment registry, with `freeze_height` (`src/rpc/archival_shard_coverage.cpp`), and it ranks them. Its ids are segment indices, read by `shekyl-cli`'s shard list. Both ends hold the segment meaning |
| the wallet's holdings source (`get_archival_emission_claim_source`; `rust/shekyl-engine-core/src/engine/emission_source.rs:485`) | served by the C++ daemon from the LMDB bond record (`src/rpc/archival_claim_source.cpp:46`). Its per-shard rows are the segment pair `has_segment` / `freeze_height`, folded on arrival (`emission_source.rs:412-422`). Segment meaning end to end |
| the Rust RPC server (`shekyl-daemon-rpc`) | a front for the C++ core through `core_rpc_ffi`. It does not depend on `shekyl-chain-store`, so no Rust-store id reaches an RPC |
| the operator's shard fetch (`request_archival_shard`, served natively by `shekyl-daemon-rpc` since 2026-10-08; the C ABI entry `shekyl_daemon_operator_shard_fetch` is deleted) | the method reads a `ShardId` through `shekyl_daemon_rpc::shard_view::ShardViewFacts`, whose one shipped implementation (`SkeletonAbsent`) refuses every id as `-25` without touching a store. The Rust scheduler (`FetchScheduler::read`, 2026-10-08) names shards by `ShardId` through its `ShardFacts` / `HolderSource` traits, whose production adapter does not exist yet (`SV-D9`): no production caller hands `shekyl-p-fetch` a target; the scheduler's callers are its own loopback tests and the measurement rig |
| the serve set (`rust/shekyl-p-host/src/serve_set/`) | compares the wallet's held ids against the wallet store's frozen segments. Both sides are the segment meaning |
| the snapshot digest (`rust/shekyl-ffi/src/e2_trace_ffi.rs:37`) | C++ state is marshalled into the Rust store's snapshot type to be hashed. Ids are compared as integers and interpreted by neither side |
| **the captured-chain replay** (`shekyl-chain-ingest`; `rust/shekyl-chain-ingest/src/archival_corpus_tests.rs`) | **the one place an integer is read under both meanings.** A chain the C++ daemon produced, whose bond holdings and injected credit name segment ids (the corpus carries shard `0`), is judged by `shekyl-chain-rules` on the byte-cut partition. This is CEN-L10's ruled divergence (row 3 = (b); `CONSENSUS_STORE_RECONCILIATION.md` §5.4.1, whose pass condition is that the two name different shards). It is a conformance path: nothing it computes is served or returned to a wallet. **Not a halt.** **Forward consequence (design owner, 2026-10-06):** today the two sides differ only in how they *read* an id, because the Rust validator has no bond-admission predicate. Once family 1 builds it, a captured C++ chain whose bond holdings name segment ids diverges on **validity**: the Rust rules can refuse a block the C++ accepted. **Family 1's cutover therefore regenerates the captured corpora** on the byte-cut partition. The alternative, extending CEN-L10's expected-outcome rule to admission, is not taken: the C++-produced chains die with the engine swap anyway, and a rule that expects refusals would outlive its only subject |

**What would make it cross, and the falsifier's two arms.** Either arm, before
family 1's cutover, is a crossing:

- **(a)** a serving or wallet crate naming `shekyl-chain-store` in its manifest:
  `rg -l 'shekyl[-_]chain[-_]store' rust/*/Cargo.toml` listing one;
- **(b)** a wallet-read RPC served from `shekyl-chain-store` state:
  `get_archival_emission_claim_source`, the archival shard coverage list, or any
  successor that returns shard ids.

**Arm (b) is the likelier crossing.** It is the engine swap's own route: the swap
moves the daemon's RPCs onto the Rust store one at a time, and the first of these
to move hands a wallet on leaf segments a list cut by bytes.

**Class A at this pin** is one small item: the rig's two literal copies of the
segment leaf count (`fixture.rs:70`, `extract_shard.rs:56-58`, both `25_992`) are a
second home for a number `shekyl_fcmp::tree::leaves_per_segment()` owns. They are
pointed at it.

**Where the census contradicted this round's brief.** The design owner acknowledged
each on 2026-10-04 and ruled against the tree as it is:

1. *The challenge leaf-chunk bounds are class B, not A.* The condition was "no live
   caller"; there are two, both in the live serve-credit arm.
2. *The fetch client's sizing cannot move to `N × MAX_TX_SIZE` now*, and that figure
   is the wrong quantity for the constant in question (the table above).
3. *The serve-set's segment terms halt* with the rest of the serving unit.
4. *The economics `FrozenSegmentCount` re-key is already landed.* Only the FFI
   parameter name remains, and it is the ruled divergence.
5. *The benchmark is class C.*
6. *`segment_leaf_count` cannot leave `consensus_constants.json`:* class B needs it.

---

## C. Seeded rows, each verified at the pin

Two of the five seeded rows did not survive verification as written.

| row | verdict at `9d549ead2` |
|---|---|
| **D2 `n` / `knee_n` (`SHT-8`)** | **CONFIRMED.** Re-key `n` to a `T`-independent burden count — listed transactions in closed shards, from `cumulative_tx_count` — and re-derive `knee_n` **once, in transactions**. Never shard units. It is monetary policy (`FL-V4`: the escalation splits the *burned* amount and cannot move a fee rung). **Corrected 2026-09-27:** the earlier "it changes coinbase validity" is true only **once the ramp is on** — at the shipped neutral parameters the split is 25 % whatever `n` is (§G `SCC-Q2`), so the re-key is behaviour-neutral now. The atomicity requirement is unchanged and its reason is sharper: the operand is computed on **both** sides, and a mismatch that is harmless while flat becomes a chain split the moment the ceremony raises the asymptote. |
| **`g(age)`** | **CONFIRMED; LANDED 2026-10-01 (Rust-side).** At the pin, `shard_age_milli`'s no-segment branch was segment-keyed (`rust/shekyl-archival-retention/src/admission.rs:305-341`, function at `rust/shekyl-archival-retention/src/consensus_state.rs:235-252`). Re-keyed under `SHT-Q1`: the operand is `ShardClose::{Open, ClosedAt(h)}` (`consensus_state.rs`), `h` placed by `shekyl_chain_rules::shard_close_height` on the fold and wrapped by `archival/close.rs::shard_close`, which takes a `ClosedUniverse` — the count `closed_shards_before` read and the parent it was read through, one value (closed below that count, open at or beyond it); the admission gather takes one `&[ShardClose]` column. The C++ LMDB validator's `has_segment`/`freeze_height` pair (CEN-L10) crosses the admission C ABI, `ArchivalEpochCloseShardFfi` and the `archival_claim_source` RPC **unchanged** and is folded at each edge by `ShardClose::from_wire`, the one divergence site (verify: `rg 'ShardClose::from_wire' rust/`). `SHT-Q1`'s falsifier (i) **run, does not fire**: `shard_close_is_the_fold_height_below_the_universe_and_open_at_it` (`shekyl-chain-rules/src/archival_tests.rs`) — no height closes a shard. Behaviour-neutral: same ages from the same inputs. |
| **`CompleteTree` challenge/slash** | **CONFIRMED, mechanical only.** Enumerates via the segment registry (`src/blockchain_db/lmdb/db_lmdb.cpp:5720-5728`). Re-key to closed **domain** shards. Landed semantics to preserve: a failure **demotes the whole record** to `ShardSetCompact` and clears its shards (`src/blockchain_db/lmdb/db_lmdb.cpp:5515-5520`), and **`Reinstate` is refused** on a `CompleteTree` record (`rust/shekyl-archival-retention/src/bond_post.rs:75-76`, `:159-162`). `CompleteTree` is a non-economic backstop by construction — no shard ids, so nothing to claim. |
| **The segment-geometry deletion, incl. the E3 handoff** | **PARTLY REFUTED — `SCC-3`.** The deletion row stands (the JSON's own prose at `:52` already says `segment_leaf_count` "leaves this file when E4 / S-ARCH deletes the freeze"), and the falsifier *"two shard geometries in `consensus_constants.json`"* is right. But the handoff's premise does **not** hold: `connect.rs` carries **no** segment-geometry comment to correct. `:22` is the module doc's *"3. tree — the verdict's drain → `curve_tree_leaves`"* and `:409` is `// ---- 4. root ----`; the only `segment` tokens in that file are **transaction body** segments (`:556-568`). `SCC-1`'s overloaded word produced this row. **What survives:** the deletion must also remove `rust/shekyl-archival-retention/src/segment_freeze.rs:63`'s compile-time assert and the JSON key, and the digest re-pins when it goes. |
| **`SHARD_BYTES` / 3.33 MB residue** | **CONFIRMED, line numbers corrected.** `rust/shekyl-economics-sim/src/burden.rs:36` and `:168-170` (the 13.6 GB honest-cost figure), `rust/shekyl-economics-sim/src/proxy.rs:56-60` (`max_holdings_bytes`). Docs: `ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md:528`, `:543`; `ARCHIVAL_CHALLENGE_MECHANISM.md:1896`. (The brief's `:243`/`:585` and `:653`/`:1894` do not resolve to those figures.) |
| **The `F-A` anti-sybil argument** | **CONFIRMED.** `ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md:139` leans on `MAX_HOLDINGS_SHARDS = 4096` and `:145` concludes a bulk holder *"needs **≥ 4 bonds**, not one"*; `:544` makes it conditional on the cap never rising, and `:596` carries it into W1's disposition. Under `L2`'s ruling the cap bounds a **list**, so that argument must stand on the curve, not on a list bound. A finding for that round's owner. Note its cite points at `rust/shekyl-archival-retention/src/bond_wire.rs:33`, which is a **re-export**, not the definition. |
| **The equivalence invariant (`SHT-Q1`)** | **CONFIRMED and pinned.** The domain equals the non-coinbase transactions today; `tx_domain_tests` pins it class by class with an exhaustive `match` (no wildcard), and leg (f) pins the production path across a real prune. The **serve-credit end-to-end gap** is tracked in FOLLOWUPS. |

### `SCC-4` — the holdings cap had **six** definitions. FIXED here.

**As first written this row said two.** The design owner's review found four
more, and the corrected count is **six**:

| # | site | guarded? |
|---|---|---|
| 1 | `rust/shekyl-types/src/archival/mod.rs:73` — `pub const MAX_HOLDINGS_SHARDS` | the canonical Rust home |
| 2 | `rust/shekyl-wire/src/transaction.rs:104` — crate-private `const`, and **it is what enforces the wire bound** (`:529`, `:745`) | **no** — tied to nothing |
| 3 | `src/blockchain_db/shekyl_types.h:1129` — `ArchivalBondValue::kMaxHoldings` | the C++ authority |
| 4–6 | `src/blockchain_db/shekyl_types.h:781`, `:899`, `:989` — the three revert-value codecs | **yes**, `static_assert` against site 3 (`:1461`, `:1466`, `:1469`) |

**The precise shape of the defect, which decides the fix.** The C++ four *could
not* drift from each other — three are `static_assert`-pinned to the authority.
What nothing tied was **the Rust pair to each other** and **either language to
the other**. So a re-pin would have moved one side silently: a holdings set the
store accepts and the wire refuses, which is a consensus split arriving through a
private literal. Delete-the-duplicate, not synchronize-it — and, as the design
owner observed, **not the one-line fix this row first claimed**.

**FIXED in this PR.** The value now has one authority and two generated readers:

1. **`config/consensus_constants.json`** gains `archival_max_holdings_shards =
   4096`, with both membership tests argued at the key: a different value admits a
   different set of bond posts (**a different chain**), and it is a **resource
   cap** — the `CEN-I4` input-count case this file's own rule names as passing the
   nameable-differently test, not a proof-system structural parameter.
2. **Rust** reads it through `rust/shekyl-types/build.rs`, which emits it as
   **`usize`** rather than `u64` like its neighbour: the consumer bounds a `Vec`
   length, so emitting the consumer's width leaves no cast to lint, and a value
   exceeding `usize` on a 32-bit target fails to compile **at the generated
   literal** instead of wrapping into a *smaller* bound — which is the direction
   that would make a decoder refuse holdings the store accepts.
3. **C++** reads `SHEKYL_ARCHIVAL_MAX_HOLDINGS_SHARDS` from
   `cmake/generate_consensus_constants.py`; **all four** `kMaxHoldings` are now
   defined from it, and the three `static_assert`s stay as belts against a
   hand-edit rather than as the only tie.
4. All five literals are deleted, and `git grep` finds no remaining copy under any
   name. The other `4096` hits in the tree are prose or
   `rust/shekyl-shard-visual/src/lib.rs:58`'s unrelated pixel cap.

**No behaviour change**: every definition already carried 4096. The
consensus-constants digest moved because the **binding grew**, and
`rust/shekyl-rpc-types/build.rs`'s `PINNED_DIGEST` is re-pinned with the
added-key case answered in place, as `VC-D12` requires.

---
## D. Calibrated constants whose units change

| constant | value | unit **today** | where it was derived | on cutover |
|---|---|---|---|---|
| `escalation_knee_n` | **`2250000` — RE-DERIVED 2026-10-01** (`config/economics_params.json`; was `100000`) | **closed byte shards** (`closed_shards_before`, `W = 3,000,000 B`). *Was:* J-segments (`frozen_segment_count`) ⇒ ~2.6 × 10⁹ leaves | **sim-derived: the middle of the re-swept `KNEE_BAND = [500_000, 2_250_000, 10_000_000]`** (`rust/shekyl-economics-sim/src/escalation.rs`: baseline `n` at ~10 y, sustained-growth's final `n`, their geometric mean), swept against `ASYMPTOTE_BAND` but **still never selected** — the ceremony picks it with the asymptote. *Was* the middle of `[25_000, 100_000, 250_000]` in J-segments | **DONE (§F step 3; `ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §12.13)**: re-derived in the operand the validator consumes, not converted; digest re-pinned `885f700d… → 05a1ba28…`. Inert today — the ramp is flat. See `SCC-Q2`'s 2026-10-01 note on the unit the sweep ran in |
| `segment_leaf_count` | `25992` (`config/consensus_constants.json:53`) | leaves per level-2 subtree (`38·18·38`) | the curve-tree widths, const-asserted to the proof topology | **leaves the JSON** with the freeze; the digest re-pins |
| `T` (`archival_shard_tx_count`) → **`W`** | `200`, PROVISIONAL → **`3,000,000 B`, PROVISIONAL (2026-09-29)** | transactions per shard → **archival bytes per shard** | `3.33 MB ÷ 16.7 KB/tx`, where 3.33 MB is the **retired leaf segment's** size (`SHT-1`) → **re-derived in bytes** (`ARCHIVAL_SHARD_T_DERIVATION.md` §9): the smallest `W` within the overshoot tolerance with `U1a` clear at the heavy end | **the unit changes (`SHT-Q2`)**: renamed with its key and generated names; re-pinned at the Round-2 gate by the tolerance (5 %, confirmed), the multi-size W₂ run (read 2026-10-02: `U1a` does not bind, `ARCHIVAL_SHARD_T_DERIVATION.md` §10.5) and `U1b` (read 2026-10-03: does not bind, `ARCHIVAL_SHARD_T_DERIVATION.md` §10.8) — it rests on no open measurement |
| `L` (`archival_attestation_anchor_lag`) | `4` blocks | blocks | its fetch-span component was sized on "~20 s for 3.33 MB" — the same retired byte count (`SHT-7`), which its own page's W₂ measurement contradicts 2.4–4.3× | restate the span **per byte**, or re-pin with `T` — **restated per byte 2026-10-02** on the worse measured day (56.1 s at the heaviest shard); `L = 4` holds (`ARCHIVAL_SHARD_T_DERIVATION.md` §10.6) |
| `SHARD_BYTES` (sim only) | **DELETED as a literal 2026-10-01** — `burden.rs` reads `shekyl_types::SHARD_LENGTH.to_raw()` (`3,000,000`); *was* `3.33e6` | bytes per **closed shard** (*was* per leaf segment) | the production constant, not a modelling mean; the sim's per-tx archival length comes from `shekyl_tx_weight::predict_archival_len` and its shard count from `shekyl_types::shard_of` — no `/ W` in the sim | **DONE (§F steps 2–3)**: `frozen_shards` deleted, the sims re-baselined and the Stage-2 arms re-measured (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §12.13) |
| `MAX_HOLDINGS_SHARDS` | `4096` (`config/consensus_constants.json`, `archival_max_holdings_shards`) | **list entries** — not bytes, not operators (`L2`) | the list budget; **no recorded derivation of the 4096 itself** | unchanged by this cutover. Since `SCC-4` it has **one** authority and two generated readers, so §E's couplings can now hold |

---

## E. Couplings owed if `MAX_HOLDINGS_SHARDS`'s value moves

Not owed if `T` moves — that coupling was struck by `L2`'s ruling.

1. **Re-anchor `m_min`.** The failure window's `m_min` is floor-set on the
   operator axis *at* the cap — *"false-slash at MAX_HOLDINGS <= target … every
   held pair is independently exposed; per-pair alone understates it by up to
   {MH}x"* (`rust/shekyl-economics-sim/src/mn_feasibility.rs:844-852`; the exposure at `:269-273`). Re-anchor to
   a **deliberately stated "largest honest operator holding"**, not a list bound,
   and re-run `mn_feasibility`.
2. **Re-point the sim populations** that read the cap as "the big archiver":
   `rust/shekyl-economics-sim/src/stranding.rs:51`, `rust/shekyl-economics-sim/src/stage2.rs:1205`, `rust/shekyl-economics-sim/src/cartel.rs:702-703`, `rust/shekyl-economics-sim/src/burden.rs:168-170`,
   `rust/shekyl-economics-sim/src/proxy.rs:56-60` — at that same stated figure.
3. ~~`SCC-4` first, or the wire will not move with it.~~ **Done** (`SCC-4`): the
   cap is one JSON key read by both languages, so a re-pin now moves every reader
   together instead of leaving the wire refusing at the old value.

---

## F. Atomic cutover boundaries (rule 07)

Two groups, each landing as one ratified change, because each contains a
consensus verdict that would otherwise disagree with itself mid-flight.

**Family 2 — validator + template + FFI + sim calibration, as one.** The binding
reason: `n` feeds `validate_miner_transaction` under a read-point assert that
*template and connect must read the same parent state*
(`src/cryptonote_core/blockchain.cpp:1494-1505`). A template built on one operand
definition and a connect validating on the other disagree about the coinbase's
fee split.

**Corrected 2026-09-27:** that disagreement is **latent, not live**. At the
shipped parameters the escalation is flat — `shekyl_escalation_asymptote_share`
equals the floor `shekyl_staker_pool_share` (`config/economics_params.json:16-18`,
*"the DELIBERATE pre-ceremony NEUTRAL value"*) — so the split is 25 % whatever `n`
is and a mismatched operand changes no coinbase's validity today. **The atomicity
requirement stands, and this is the better argument for it:** a split operand is
harmless while the ramp is flat and becomes a chain split the moment the GF-7
ceremony raises the asymptote, which is exactly the kind of defect that ships
unnoticed and detonates later. `escalation_knee_n`'s re-expression rides the same
change so the ceremony is never handed a number in the wrong unit.

**Family 1 — these components, as one, at or before the engine swap** (boundary
restated 2026-10-05; it read "daemon + wallet"). What moves together:

- **the bond-admission predicate** (closed-and-final shard; ruled, unbuilt);
- **SO-D8 Slice C**, the serve-credit admission rows and the settlement writer's
  call site;
- **the archiver serving-store rebuild** (`WSS-`, the wallet lane);
- **fetch Sub-PR 2**;
- **the wallet's holdings and serve-set source**;
- **the regenerated captured corpora**: once the admission predicate exists, the
  C++-produced chains diverge on validity, not only on reading (§B family 2).

Bond admission checks domain membership, and the wallet posts the holdings it will
be judged on, pins what it holds and serves what it pinned. A validator on the
byte-cut partition and a serving stack on leaf segments name different shards with
the same integer (§B family 2, *`shard_id` has two meanings*), so none of them
moves alone.

**Amended 2026-09-29 (`SHT-Q2`): family 1 now also carries the txid change, and that
makes it the larger group.** Everything below lands in the one ratified change,
because each half would otherwise disagree with the other about which transaction or
which shard an id names:

- **the txid mixer, once, in Rust** — `hash_from_components` and
  `hash_with_supplied_components`. C++ `calculate_transaction_hash`, and any other C++
  site that computes a txid part, becomes an FFI call into it with its hashing deleted
  (row 3 = (b), RULED 2026-09-29). A daemon and a wallet cannot then mix different
  operands for the same transaction, because there is no second mixer to disagree;
- **the archival-length row** and every pruned or skeleton transport that supplies it;
- **the cumulative archival-length cell** and the boundary function over it;
- **the `W` constant**, renamed, with the static relation `max archival length < W`;
- **the regenerated parity pins and corpora** — `pruned_tx_hash_parity`,
  `serve_credit_tx_parity`, `live_oracle_spend_v1.json` and the captured chains —
  because every txid moves.

**How a pruned form supplies the length — RULED 2026-10-01 (design owner, relayed by
Rick): option (iv).** C++ passes full segments to Rust; Rust measures the length and
computes the txid; the FFI entry has no length parameter. Verified at source, with two
premises corrected ([`ARCHIVAL_SHARD_T_DERIVATION.md`](../completed/ARCHIVAL_SHARD_T_DERIVATION.md)
§10.3):

- the C++ pruned-txid path (`get_pruned_transaction_hash`, and the `allow_pruned` arm
  of the P2P block-entry path) is **unreachable** — a pruned entry is refused as a
  protocol violation first — so this cutover **deletes** it rather than porting it;
- the one pruned **wire** is the daemon RPC's pruned `get_transactions`. C++ already
  hands it the full prunable bytes, so the Rust server measures the length at serve
  time and the reply carries it; the wallet's block fetch and the console supply it to
  the mixer.

**Built (the txid-length cutover).** Of the list above, the mixer, the regenerated pins
and corpora, and every pruned or skeleton transport **that has a reader** are built —
the store's skeleton rebuild, the daemon RPC reply, the wallet's block fetch and the
console; the row, the cell, the boundary function and `W` were the Rust-half PR's
(#910). **One transport is not grown, and is named:** the P2P block entry
(`tx_blob_entry` / `TxBlobEntry`). Nothing reads a pruned entry on that wire — the C++
arm that did was unreachable and is deleted — so a length field there would have no
reader and no writer. The skeleton sync wire is `PDM-Q-F28`'s, unbuilt, and owes the
`pqc_auths` digest and the length together (FOLLOWUPS, "Skeleton block payload"). The mixer's word
encoding, its three arities, the shape of the FFI entry and the RPC field are the
build's choices and are recorded for ratification in
[`ARCHIVAL_SHARD_T_DERIVATION.md`](../completed/ARCHIVAL_SHARD_T_DERIVATION.md) §10.3 ("As
built"). One consequence is the engine swap's: the Rust store, unlike LMDB, discards
prunable halves, so when it backs the daemon RPC its transaction slot must carry the
`txs_archival_len` row — the serve path cannot measure bytes it no longer holds.

**The prunable digest is Rust's too (design owner, 2026-10-02).** The build above left
two C++ region digests as plain `keccak`. One of them is a txid operand that travels
on its own — the `txs_prunable_hash` row and the `prunable_hash` a pruned
`get_transactions` reply carries, which the wallet mixes — so it is now computed by
the function the mixer uses (`shekyl_wire::prunable_hash_of`, over
`shekyl_tx_prunable_hash`). `calculate_transaction_prunable_hash` finds the range and
hashes nothing; its second derivation, a separate write of the prunable fields, is
deleted. Pinned per transaction class by `prunable_digest_parity`.

**What the txid still takes from C++, until the engine swap.** Three things remain on
the C++ side of the boundary. Each is transitional, and each ends the same way: when
Rust holds the parsed transaction, it derives them and nothing is supplied.

1. **The stored archival length on the serve path.** As above: a transaction slot fed
   from `shekyl-chain-store` carries the `txs_archival_len` row. `TxRecord`'s rows are
   as recorded, not as verified (a lost length row reads zero), so the slot's producer
   rebuilds the id from the record and compares it to the hash it asked by before
   serving, as `leaf_reads::outputs_at` does.
2. **`get_transaction_prefix_hash`.** C++ hashes the prefix itself, in
   `blockchain.cpp`: for the signature-verification input, for the emission claim's
   signed hash (the prefix with that input removed), and to spot a duplicate
   transaction in an incoming batch. It does not feed a txid, but on a whole prefix
   it is the same bytes as the txid's first word, hashed by a second implementation.
3. **Two facts the FFI entry is told and does not check.**
   `shekyl_txid_from_segments` takes `first_input_is_spend` and `pqc_auth_count` from
   the caller, because it parses nothing. They decide the mix's arity, and C++ is
   their only source.

**`g(age)`'s segment-keyed no-segment branch is this cutover's (RULED 2026-10-01,
`SHT-8`) — LANDED the same day, Rust-side.** It is a row of this census, owned by the
design-owner lane; it is not part of the family-1 txid change, and it is not a rule-07
cutover: the C++ side and every wire surface are unchanged, the Rust library's
vocabulary moved from the segment pair to `ShardClose` (§C's `g(age)` row).
`escalation_knee_n` stays the sim lane's (`SCC-Q2`).

**The C++ LMDB archival path does not move (row 3 = (b), RULED 2026-09-29).** No new
LMDB tables, cells or archival logic: LMDB's shards stay the frozen leaf segments
(CEN-L10; `src/cryptonote_core/blockchain.cpp:1494-1505`,
`src/rpc/archival_shard_coverage.cpp:34`), so the C++ consumers in the table above keep
their segment partition. The difference from the Rust store's length partition is
ruled an **intended conformance divergence** under CSR-3a, registered against CEN-L10
in [`CONSENSUS_STORE_RECONCILIATION.md`](CONSENSUS_STORE_RECONCILIATION.md) §5.4.1 with
the build. **The engine swap must complete before genesis, or this is revisited.** The
fee-split `n` in `blockchain.cpp` is untouched. The one C++ change is the FFI call
above.

**Order within the effort:**

1. **Counts defined once** in `shekyl-types` — one home for the domain
   ordinal, the way the partition input already has one: `SHARD_LENGTH`
   (`W`, archival bytes — a length, not a count or an ordinal) is defined
   once there and read everywhere (*it replaced `SHARD_TX_COUNT` for `T`,
   which the `SHT-Q2` build deleted, PR #910*). `SCC-4`'s duplicated cap
   folds into the same home.
2. **Constants re-derived** in their new units (§D) — `knee_n` in transactions
   before anything reads it. **DONE 2026-10-01**: `knee_n = 2,250,000` closed
   shards, re-derived by the re-swept band (§D row; §G `SCC-Q2` note).
3. **Sims re-baselined** against the re-derived constants, so the economics
   verdicts are not measured in retired units. **DONE 2026-10-01**: the sim
   calls `shekyl_types::shard_of` / `SHARD_LENGTH` and the `shekyl-tx-weight`
   predictors; every Stage-2 arm re-measured in
   `ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §12.13 — including one verdict
   that **flipped** (A1, high-history / low-activity, now cleared by no
   candidate), which is the design owner's, not this cutover's.
4. **Then the two cutovers**, family 2 before family 1: family 2 owns the operand
   family 1's economics read.

---

## G. Open questions for the design owner

Numbered, and none resolved here.

1. **`SCC-Q1` — `n`'s replacement burden count. ANSWERED (design owner,
   2026-09-27): transactions below the discard frontier, not transactions
   archived — SUPERSEDED 2026-10-01 (design owner): the burden is locked
   capital, borne at close + freeze, so the operand is closed shards at parent
   state, a pure fold; see the `SCC-Q2` note below.** *Records-was — the
   2026-09-27 rationale, SUPERSEDED, kept so the reversal is legible:* that
   answer held the burden to start when bodies **leave ordinary daemons**,
   not when shards close, on the ground that inside the retention window every
   daemon still holds them; its operand was `cumulative_tx_count` against
   `D(E)` at the parent state, moving in epoch steps like the segment count.
   *Why it was superseded:* the archiver's burden is the **bond** — capital
   locked at close + freeze, before and regardless of when daemons discard —
   so the retention window is not a grace period for the burden, and the
   premise fails. The current operand is closed shards at parent state (the
   `SCC-Q2` ruling below carries the full reasoning).
2. **`SCC-Q2` RULED (Rick, 2026-09-27, design-owner lane): `knee_n` is
   re-expressed, not ported.**
   - The Stage-2 escalation sweep (`KNEE_BAND × ASYMPTOTE_BAND`,
     `rust/shekyl-economics-sim/src/escalation.rs:63`) is **re-run with the knee
     band in transactions below the discard frontier** — the `SCC-Q1` unit —
     derived from `ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §6.0's
     *wide-but-slow* constraint in that unit, as part of the sim re-baseline.
   - The config carries **that sweep's middle candidate**, provisional.
   - The escalation **stays neutral** (asymptote = floor = 250,000,
     `config/economics_params.json:16-18`) until the **GF-7 ceremony** (§11.4) pins
     both numbers.
   - Converting the old band (~13k transactions per J-segment) is a **sanity check
     only, not a derivation**: segments counted coinbase leaves and were never a
     burden measure.

   **UPDATE 2026-10-01 — the sweep re-ran; the knee is `2,250,000`; and the
   unit it ran in is disclosed, not ruled.** The sweep re-derived
   `KNEE_BAND = [500_000, 2_250_000, 10_000_000]` and the config carries the
   middle (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §12.13). Its unit is
   **closed shards at parent state** — `shekyl_chain_rules::closed_shards_before`,
   the operand the landed validator consumes (CEN-F17) and the unit
   `economics_params.json`'s own comment has named since 2026-09-30 — **not**
   `SCC-Q1`'s *"transactions below the discard frontier"*. The two differ by the
   retention window (a closed shard is below the frontier only once its bodies
   leave ordinary daemons) and by unit (byte shards, not transactions). The sim
   measures what the chain reads; so either `SCC-Q1`'s answer is superseded by the
   operand that landed, or the operand owes a frontier lag. **That is the design
   owner's ruling, filed here as a finding**; the re-derivation holds under
   either reading because the band was swept, not selected. The sanity check
   above also held: ~13k transactions per J-segment ≈ 43 byte shards, so the old
   middle `100,000` segments ≈ 4.3 M shards — inside the new band.

   **Recommended disposition (#929 review, 2026-10-01): supersede `SCC-Q1`'s
   answer, for a reason `SCC-Q1` did not have in hand.** `SCC-Q1` dated the
   burden from *discard* — bodies leaving ordinary daemons. Under **F-G** the
   burden the escalation compensates is **locked capital**, and capital locks
   at **close + freeze**, when the shard's bond is posted — *before* discard.
   `closed_shards_before` therefore counts the burden from the moment it is
   borne, which is what `SCC-Q1` asked for; a frontier lag would count it
   late. The operand stays a pure fold, with no frontier term and no `D(E)`
   read. **RULED 2026-10-01 (design owner): `SCC-Q1`'s answer is SUPERSEDED
   on the locked-capital reason; the operand stays a pure fold.** The
   `SCC-Q1` entry above is the records-was answer; this paragraph is the
   ruling of record.

   **Provenance correction.** `100,000` **is** sim-derived — it is the middle of
   the Stage-2 `KNEE_BAND = [25_000, 100_000, 250_000]`, swept against
   `ASYMPTOTE_BAND` but **never selected**, because Stage 2 recommends and Stage 3
   freezes, and Stage 3 froze the **shape** only. This round's earlier *"no
   recorded derivation"* was wrong: what is missing is a **selection**, not a
   derivation. The band's own doc comment carries the reasoning (*"a larger knee is
   a slower ratchet"*; `25_000` ≈ baseline traffic at ~10 y, `250_000` only
   saturates deep in a sustained-growth chain).
3. **`SCC-Q3` — does `g(age)`'s re-keyed form need a shard's close height?
   ANSWERED: no, and the question conflated two things (design owner,
   2026-09-27).** `SHT-Q1`'s falsifier (i) is about a shard needing **to close by
   height** — a clock. *Reading* the close height of a shard that closed **on
   count** is not that: under the domain it is the height of the block containing
   the domain's `((k+1)·T)`th transaction, found by the **existing** binary search
   over `cumulative_tx_count` (`rust/shekyl-chain-store/src/store/prune.rs:498`).
   An open shard has no age, so the explicit `age_milli = 0` branch carries over
   unchanged. **The ruling does not reopen.**
4. **`SCC-Q4` — the `F-A` anti-sybil argument. HANDED OFF (design owner,
   2026-09-27): not this effort's.** It goes to the owner of the `F-A` round as a
   **genesis-relevant finding** — under `L2` the argument can no longer rest on
   "≥ 4 bonds to plateau" and must stand on the curve — and **it does not block
   this cutover**. Recorded as handed off.
5. **`SCC-Q5` — is `SCC-4` in scope? ANSWERED: in scope, and landed here**
   (design owner, 2026-09-27) — as corrected, since it is six sites across two
   languages rather than the one line this round first claimed. See `SCC-4` for
   what shipped. It was a precondition of §E's couplings holding, and §E item 3 is
   now discharged.

**Standing after Round 0: every question is closed.** `SCC-Q1`, `SCC-Q3`,
`SCC-Q4`, `SCC-Q5` answered; **`SCC-Q2` RULED** 2026-09-27. Nothing in §G is open.
