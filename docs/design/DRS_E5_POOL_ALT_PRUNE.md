# DRS-E5 — pool, alt chain, prune: the store's consuming increment (`E5-`)

**Status:** OPEN — **Round 1 ruled in full 2026-10-10; `E5-Q4` ruled β
2026-10-11** (no CEN-B4 at the cheap tier, promotion does the check: the
cheap tier makes no chain-state read, and a check whose operand is chain
state — a persona's bonded key — is promotion-tier on the ground §2.1
already gives CEN-B5's root, an unexecuted alt chain cannot answer it; §8);
**PR #1026 (a1–a4: the header partition, the cheap tier, AL1, the census
arms, and the Slice C transport-handoff docs, §2.2/§2.3) merged
2026-10-12. The switch PR is split (maintainer, 2026-10-15): its reorg
half — a5's closure, a6's refusals, fixtures and Rust self-differential,
a8's docs — is on `feat/drs-e5-switch`; a7's C++ capture is withdrawn
(`E5-Q9`); the bundle legs (B10, the pre-closure body fetch, `BundleView`
on `BatchView`, the bundle verifier inside `validate` at the switch) land
with SO-D12's merged increment, which puts the bundle section on the block
wire (`ARCHIVAL_SETTLEMENT_WRITER.md` §16.3 item 3; the wire's `Block`
carries no section, `shekyl-wire/src/block.rs:117–124`). PR-b (b1–b7,
#1102, `feat/drs-e5-pool-prb`) builds the Rust pool staged for the DRS-X
flip: the door is the validator's own judgement at `TxSlot::Lone`, the pool
record knows one relay fact (DX-F6), the bundle work is SO-D12's (§2.2,
§5). This file stays open for the residue §9 names for its owners.** Round 0 posed
2026-10-10 at `dev@14d68c00fc`, merged to `dev@ac95d6d04` before the PR
opened. Pre-flight in §1.1, findings `E5-1…E5-18` (`E5-13…E5-15` are PR-a
commit 1's measurement, §1.7; `E5-16` and `E5-17` are the review's;
`E5-6` and `E5-17` are dissolved under `E5-Q4`'s β, `E5-16` stands with no
consumer; `E5-18` is a3's — the census registry could not name a
store-homed property, ruled `held_by_store` in a4); questions `E5-Q1…E5-Q11` in §8, each with its ruling under its
default. a4's census amendment (CEN-K4's row describes the C++ ladder in
its landed order and names no attestation step for the Rust tier; CEN-B4's
site pin re-pinned) landed in a4's census-arms commit, 2026-10-11. **The
"prune" in this file's name is not an increment of this lane:** the
retention prune is DRS-E1's and landed 2026-09-25 (S-PRUNE,
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §3's surface table;
[`DRS_E1_SPRUNE.md`](DRS_E1_SPRUNE.md) §14), and the C++ pruning engine
was deleted 2026-09-21 (`DRS_E1_SPRUNE.md` §1); E5 owns only the
**reorg × floor interaction** (§4: `PopBelowFloor` as a local refusal, the
pruned-row asymmetry `E5-9`). Identifier families **`E5-`** (findings) and **`E5-Q`**
(questions), registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 with this file (rule
94 §1; `check_index_prefix_uniqueness.py` branch (a): `E5` and `E5-Q`
distinct, clear of the 126 registered families). Parent plan:
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) (`E5[DRS-E5 pool alt prune]`
in the §7 graph, `E2 --> E3 --> E4 --> E5`, `E5 --> X`; table 3's "4.K …
slice 9" and "4.M … slice 10 with E5" rows). Inherits from
[`DRS_E1_SALT.md`](DRS_E1_SALT.md) §2.3 (SAL-7, SAL-13, SAL-14) and
[`DRS_E1_SPOOL.md`](DRS_E1_SPOOL.md) §2.3 (SPL-7…SPL-10, `SPL-Q5`); the
reorg rulings it builds under are
[`CONSENSUS_C2_R1_REORG.md`](../completed/CONSENSUS_C2_R1_REORG.md) §4b
(Q1a–Q1c) and §5.5 (Q1a–Q3b), closed as record. Owns no FOLLOWUPS row at
this commit; the two deletions it owes are register rows (§7), not queue
rows.

**One sentence.** The store's alt half and pool half are built and have no
consumer; the validator's one-validator contract names a `PoolView` that no
crate defines; the census carries twenty-five rows pending on "an alt
`ChainView`" that cannot exist as a `ChainView`; and the C++ reorg path —
the one piece of consensus machinery with no deletion-register row — is
the template for all of it. This round decides the shapes (an alt view that
is a *header* view, a pool decorator that is a *key-image* decorator, a
switch that is one `store.write` closure) before any of the twenty-five rows
is given a Rust site.

---

## 0. Why a round, and why this round opens with one

DRS-E1 landed S-ALT and S-POOL as store halves with the explicit statement
that their consumers are E5's (`DRS_E1_SALT.md` §2.3 "carried to E5",
`DRS_E1_SPOOL.md` §2.3). DRS-E4 landed the writer that a reorg must reverse
(`undo_log`). E6's slices 1–8 landed the validator every alt block will be
re-validated through. So E5 **consumes; it does not build** a store, a
validator or a writer. What it builds is the orchestration that was never
Rust: alt-block admission, the switch, the pool's admission door, the pool's
life after admission, and the open-time reconciliation `SPL-Q5` left to it.
**Not the prune.** The parent plan's node reads `E5[DRS-E5 pool alt
prune]` and this file carries the word, but the prune is E1's, landed
(S-PRUNE, 2026-09-25; the C++ engine deleted 2026-09-21): none of the
twenty-five rows, the commits in §5, or `DEL-009`/`DEL-010` is a prune
item. E5 owns only the reorg × floor interaction (§4) — a reader who
arrives expecting a prune increment should stop here (rules 23/91; the
lane keeps its name because the roadmap node is the parent plan's and
other documents point at it — a rename ripples further than this
sentence).

Three reasons this is a design round and not an implementation slice:

1. **4.K is the reorg family.** Every row in it is a rule about state that
   does not exist yet when the rule runs (an alt branch), and C2-R1 spent
   three sub-rounds ruling what the C++ had done by accident. A slice that
   started from `blockchain.cpp:1974` would transcribe the ladder
   (`05-system-thinking.mdc`, "the C++ is a template, not a source").
2. **The lane inherits three contracts it did not write.** `PoolView` is
   named in `shekyl-chain-rules` (`lib.rs:92`, `rule_set.rs:577`), in
   `CHAIN_RULES_CRATE.md` (`:51`, `:74`, `:790`, `:1746`) and in the store
   (`store/view.rs:19–20`), and defined nowhere (`E5-1`). SAL-13/SAL-14 fix
   the switch's read-before-pop and the rollback's shape. `SPL-Q5` fixes
   chain-first/pool-second. A round that did not re-read these at the tree
   would build against prose.
3. **Two things must die and neither has a register row.** The C++ reorg
   path (`switch_to_alternative_blockchain`,
   `rollback_blockchain_switching`, `handle_alternative_block`,
   `build_alt_chain`, `pop_block_from_blockchain`) and the C++ mempool
   (`tx_pool.cpp`) are cutover deletions of the same class as `DEL-008`, and
   `DAEMON_REDB_STORE.md` §12 has `DEL-001…DEL-008` and no row for either
   (`E5-4`). §7 mints them here, in the register, because the register is
   where rule 94 says a deletion persists.

**Review-round denominator.** This is Round 0 of a round-numbered design
process (rule 26). Round 0 is the pre-flight and the posing: it ends when
this file is reviewed. Round 1 is the ruling on `E5-Q1…E5-Q11`; a question
not ruled stays `POSED` and blocks the commit that would build it, not the
round. The count of rounds is not a budget to spend down: one ruling round is
the expectation, and a second is owed only if a ruling refutes a finding in
§1.1 (the reopen shape of rule 21).

---

## 1. What is built, read at the tree (`dev@14d68c00fc`)

### 1.0 The validator's contract

- `validate<'id, V: ChainView<'id>>` (`validate.rs:362`) is the one path to
  `ChainValid<'id, V>` (`verdict.rs:62`); `mint` is `pub(crate)` with the G9
  coverage panic (`verdict.rs:90`); `connect` takes
  `ChainValid<'id, BatchView<'_, 'id>>` by value (`store/connect.rs`). The
  brand is the **view type**, not only the lifetime: `GrownTree`
  (`chain-ingest/src/test_support/tree.rs:329`) implements `ChainView<'id>`
  for every `'id` and still cannot feed `connect`, because `V ≠ BatchView`.
  A brandless view is therefore a view whose type `connect` does not name
  — nothing has to be sealed.
- `tx_form(tx, slot, rule_set)` (`validate.rs:571`) and
  `tx_against(tx, slot, view, rule_set)` (`validate.rs:641`) are `pub`; the
  rule order inside `tx_against` is the C++'s `check_tx_inputs` order (key
  image first, then the class arm). **No production caller outside the crate
  calls either**: `validate` is the only caller, and `validate`'s only
  production caller is `connector.rs:572`. `TxSlot::Lone` (`verdict.rs:145`)
  is the pool's slot and `validate` never passes it.
- `ChainView<'id>` (`view.rs:246`) has twenty-eight methods. Four are facts
  of the chain's *shape* (`tip`, `block_at`, `height_of`, `depth_at`) — by
  method; `block_at`'s *record* mixes the two, `E5-13` — the
  rest are facts of an *executed* chain — tree roots, outputs, leaf counts,
  key images, transaction membership, burned total, and the archival
  family (`bond_record` … `issued_digest`). `BatchView` (`store/view.rs:147`)
  is the only production implementor; its module doc already reserves the
  next one: "A `ReadSnapshot`-backed view (RPC-side re-validation, DRS-E5's
  pool decorator) is a later, separate implementor. It carries no batch
  brand" (`store/view.rs:19–20`).
- Which rule files read which view methods (grep of `view.` in
  `rules/*.rs`): `anchors.rs` — `block_at`, `tip`; `header.rs` — `root_at`;
  `body.rs` — `has_transaction`; `miner.rs` — `total_burned`;
  `attestation.rs` — `bond_record`; `tx_against.rs` — `depth_at`,
  `has_key_image`, `height_of`, `root_at`, `tip`; `tx_bond.rs` and
  `tx_emission_against.rs` — the archival family. The PoW and difficulty
  rules read through `rules/mod.rs`'s `block_at`/`tip`. **UPDATE
  2026-10-10 (Round 1, `E5-13`):** this grep is a *method*-level
  partition and the method-level answer is incomplete — `block_at` returns
  `RecordedBlock` (`view.rs:166`), which carries three executed facts
  (`coins_generated`, `cumulative_tx_count`, `cumulative_archival_len`)
  beside the header facts (`hash`, `header`, `cumulative_difficulty`), and
  `miner.rs:469/:523/:668` and `archival/close.rs:75` read the executed
  three through it. The field-level partition is `E5-13`.
- `AdmissionPolicyId(u8)` with `GENESIS = 1` and `AdmissionPolicy { id }`
  (`rule_set.rs:555–597`): "Consumer: DRS-E5 (`PoolView`, `PolicyCoverage`).
  Its parameters populate there." `PolicyCoverage = Coverage<PolicyRow>`;
  `PolicyRow`'s doc: "Applied by `AdmissionPolicy` (DRS-E5)". The policy
  gate reads `implemented 0 / validator-enforced 9` at the pin.
- `RuleSet::reorg_cap()` (`rule_set.rs:215`) is the cap in force; `D_MAX`
  (`reorg.rs:70`) is its `GENESIS` value, inherited from
  `ARCHIVAL_REORG_DEPTH_BLOCKS` and asserted below
  `SETTLEMENT_EPOCH_BLOCKS` — so a reorg within the cap crosses **at most
  one** settlement boundary.

### 1.1 S-ALT, as landed (`store/alt.rs`, `codec/alt.rs`)

AL1 `insert_alt_block(&self, AltValid<'_, AltView<'_>>)` — **the cheap tier's verdict is
the only thing that writes an alt row** (a4; at open the signature was
`(&self, id, &AltBlock)` with an `IdentityMismatch` belt, which lost its
producer when the key became `AltValid::hash` and was deleted). The row is
built from the verdict (`AltBlock::admitted`: the derived height and
cumulative difficulty, the measured weight, the block and its witness);
`AlreadyHeld` is CEN-K3's belt. AL2 `remove_alt_block` (`NotHeld`); AL3
`drop_alt_blocks -> u64`; AL4 `alt_block`; AL5 `has_alt_block`; AL6
`alt_block_count`; AL7 `alt_blocks -> Vec<AltEntry>`. `alt_table` asserts
`!journal().is_recording()` — alt rows are **not journaled and not in the
digest**. `AltBlock { block, witness, facts }`, `AltBlockFacts { height,
block_weight: BlockWeight, cumulative_difficulty }`
(`codec/alt.rs`; the supply word `coins_generated` the record carried at
open was deleted at a4, `SCHEMA_VERSION` 24 — K8, §2.1; the weight's
presence byte went in the same unreleased layout — zero is a codec
refusal, not an absence; `AltBlock::checked`
still builds a row from bare facts for the codec's tests, the schema
snapshot and the store's planted-row fixtures — it is not AL1's input).
`AltChain::fork()` names the fork the tier judges against (root and
recorded tip, one snapshot), and `AltView` hands it to the tier as its
`AltChainView::fork` (§2.1). The module doc's switch sketch is one
`store.write` closure: judge the demoted blocks over the pre-pop snapshot
→ `pop()`×N → `insert_alt_block`×N → `connect`×M → `remove_alt_block`×M.
The hand-offs this round binds itself to:

- **SAL-7** — alt data never reaches `ChainView`; "no `ChainView` accessor
  is minted" for alt membership. (`DRS_E1_SALT.md:400–406`.)
- **SAL-13** — demotion reads the tip's bytes, facts and witness through the
  batch's view *before* `pop()`; with AL1 taking a verdict (a4), the read
  is the tier judging the demoted block over the pre-pop snapshot. A demoted
  block re-enters *through the tier* — the C++'s shape
  (`handle_alternative_block` from the switch, CEN-K7) and the only door
  that mints an alt row; there is no demotion constructor (§2.3).
- **SAL-Q4** — `block_weight: Option<BlockWeight>` was ruled for the C++'s
  zero sentinel ("not yet validated far enough to have a weight"). Closed
  2026-10-12, inside the unreleased schema-24 layout: `admitted` always
  measured a weight, no other writer produced an absence, and a5 does not
  inherit an absence arm. The field is `BlockWeight`; zero is a codec
  refusal. A later writer that needs an absent weight bumps
  `SCHEMA_VERSION` and re-pins `alt_block.snap`.
- **SAL-14** — `rollback_blockchain_switching` (`blockchain.cpp:980`) is a
  deletion: the redb transaction is the rollback; falsifier
  `git grep rollback_blockchain_switching src/` → 0 after cutover; and the
  ordering rule — pool returns and template-cache invalidation are applied
  from the closure's `Ok`, chain first, pool second (`SPL-Q5`).
- **SAL-8** — the cutover starts empty: `core::init` drops every alt block
  unless `--keep-alt-blocks` (`cryptonote_core.cpp:185`, the drop at
  `:650` at this pin; SAL-8 cited `:653` at its own).

### 1.2 S-POOL, as landed (`pool/`, `codec/pool.rs`)

`PoolStore::{create, write(|batch| …), begin_read}`; `PoolBatch::{insert,
update, remove}` (P1–P3); `PoolSnapshot::{record, blob, len, is_empty,
entries}` (P4–P7). `PoolRecord { weight, fee, receive_time, relay_state:
RelayState, relayed, double_spend_seen, readiness: Readiness, fcmp_cache:
Option<FcmpVerificationHash> }` (`codec/pool.rs:407`), with
`Origin`/`OriginatedPhase`/`Responsibility` (`codec/pool.rs:76–142`) and
`RelayMethod`/`RelayCategory`/`NetZone` in `shekyl-types/src/relay.rs`.
SPL-7 / `SPL-Q5`: chain commit first, pool second, **reconcile at open** —
named as E5's and not built. SPL-9: the pool is reconstructible from P7.
SPL-10: M8's hash is `fcmp_cache`. The pool store is its own redb; nothing
makes a chain write and a pool write one transaction.

### 1.3 `connect` and `pop`

`connect(&self, valid, in_force) -> Result<Connected, StoreError>`,
`Connected { height, journaled, pruned: Option<Pruned> }`, the horizons
checked against the rule set in force (SCW-7). `pop(&self) -> Result<Popped,
StoreError>`, `Popped { height, reversed }`; `PopBelowFloor { tip, floor }`
(`store/pop.rs:113`) from the `undo_floor` cell — C2-R1 Q1c's persisted,
monotonic watermark, exempt from reversal (F-2). The connector's
`Rewind { to }` (`source.rs:91`) is executed as `pop` until the tip is `to`
(`connector.rs:636`); a `Rewind` is a barrier the formation never reorders
across.

### 1.4 Fork choice and the alt window are already Rust

`shekyl-difficulty::fork_choice` (`fork_choice.rs:48`, verdict enum `:30`)
and `alt_window_plan` (`alt_window.rs:52`) are the C2-R1 Q1a/Q1b crossings;
the C++ calls them through the FFI at `blockchain.cpp:1244` (the window
plan) and `:2283` (the choice). E5 consumes both natively; the two FFI
exports lose their only callers at cutover (§7).

### 1.5 The C++ template (read for facts, not transcribed)

- `handle_alternative_block` (`blockchain.cpp:1974`): the admission ladder
  — K1b's height-0 claim (`:1983`), the checkpoint window (`:1993`), B1/B2,
  `build_alt_chain` (`:1913`; K2), the alt window plan, the timestamp check,
  the checkpoint match, alt difficulty (D5), the attestation witness
  (`:2135`; K5b), `prevalidate_miner_transaction` (`:2141`), cumulative
  difficulty (K8's bookkeeping), the supplement's NIC (`:2166`; K9) and its
  pool entry under `relay_method::block` (`:2184`; K10), `add_alt_block`,
  then the fork choice (`:2283`; K6) and the switch (`:2334`).
- `switch_to_alternative_blockchain` (`:1029`): pops with the witness read
  off each height row before the pop (SAL-13's source), demoted blocks
  re-enter through `handle_alternative_block` when the disconnected chain is
  kept (K7), each promoted block through `handle_block_to_main_chain`, and a
  failed promote rolls back through `rollback_blockchain_switching` (`:980`).
- `pop_block_from_blockchain` (`:597`), `flush_txes_from_pool` (`:5067`);
  `tx_memory_pool::add_tx` (`tx_pool.cpp:269`) with `kept_by_block =
  (tx_relay == relay_method::block)`; `fill_block_template`
  (`tx_pool.cpp:2077`) under `create_block_template`
  (`blockchain.cpp:1540`).
- K9's three producers and the import (`blockchain_import.cpp:157`,
  `relay_method::block`) are as C2-R1 §5.5 Q1c enumerated them.

### 1.6 The submit engine is a second validator on the pool path

`SubmitEngine<FfiSubmitShim, DaemonTxVerifier>` (`shekyl-daemon-rpc/src/submit/`)
runs phases A–D over the C++ pool through the FFI. Its own contract names the
reversion: "`SubmitStateShim` over C++ FFI | The Rust mempool lands | Swap
the trait impl; engine, contract, wallet untouched" (`DAEMON_SUBMIT_VERDICT.md:1930`).
`retention_vin` is spelled twice — `rules/tx_bond.rs:672` (the validator's)
and `submit/verifier.rs:853` (the engine's) — and `docs/FOLLOWUPS.md:800`
carries the second spelling's deletion with owner `CHAIN_RULES_CRATE.md`.

### 1.7 Pre-flight findings

- **E5-1 — `PoolView` is a name in three places and a type in none.**
  `lib.rs:92`, `rule_set.rs:577`, `store/view.rs:19–20`,
  `CHAIN_RULES_CRATE.md:51/:74/:790/:1746`; `rg -n 'PoolView' rust/` returns
  the two comment lines and nothing else. The lane inherits a contract: the
  pool's admission is `tx_form` + `tx_against(TxSlot::Lone)` over a
  decorator that answers `has_key_image` from the chain **or** the pool, and
  it is defined by the pool, not by the rules crate (G10: no
  pre-provisioning).
- **E5-2 — `tx_against` has no caller outside the crate, and `BatchView` is
  the only production `ChainView`.** The pool decorator is the first
  non-batch implementor and the first `ChainView` that `connect` cannot be
  fed from. §1.0's brand argument says this needs no sealing: the decorator's
  type is not `BatchView`.
- **E5-3 — the denominator is 25 / 42, not 22 / 39 and not 24 / 42.**
  `census.rs` carries 42 `pending` arms (`rg -c ' pending' census.rs`, read
  arm by arm): 4.K is **twelve** — K1a, K1b, K2, K3, K4, K5, K5b, K6, K7,
  K8, K9, K10 (`census.rs:535–546`); 4.M is eleven across both flags (M2,
  M8 consensus; M1, M3–M7, M9–M11 policy); D5 (`:359`) and E2 (`:372`).
  12 + 11 + 2 = **25**. The brief's 22 / 39 counted K2–K10 as nine and
  skipped the three lettered rows (+3 on both sides: 39 + 3 = 42, 22 + 3 =
  25 — the two corrections are the same three rows). The pre-flight
  message's 24 / 42 was an arithmetic slip (eleven for twelve) on the
  corrected set and is superseded here. §7 carries all three so nobody
  re-derives any of them.
- **E5-4 — the reorg path has no deletion-register row.**
  `DAEMON_REDB_STORE.md` §12 holds `DEL-001…DEL-008`; `DEL-008` is the
  archival C++ path and its FFI seam. No row names
  `switch_to_alternative_blockchain`, `rollback_blockchain_switching`,
  `handle_alternative_block`, `build_alt_chain`, `pop_block_from_blockchain`
  or the alt LMDB operations; none names `tx_pool.cpp`. SAL-14 names one
  function's deletion with a falsifier, in a design doc. §7 mints the rows.
- **E5-5 — an alt view cannot be a `ChainView`.** Twenty-four of the
  trait's twenty-eight methods are facts of an executed chain. An alt branch
  is not executed until promotion; above the fork point there is no tree
  root, no output set, no key-image set, no archival row to answer with.
  "Re-validation over an alt `ChainView`" (REDB table 3; `census.rs:353`,
  `:369`) is therefore two different things that one phrase hid: the
  *cheap tier* (C2-R1 §5.5 Q1a; K4) reads only shape facts (measured at
  `E5-14`: `tip` and the header record — two, not four; the attestation's
  `bond_record` read Round 0 listed here as a third is **not made**:
  CEN-B4 is not ported to the alt tier, `E5-Q4` β, §8), and the
  *promotion tier* (K5) is `validate`
  over the batch's own `BatchView` after the pops. The alt view is a
  **header view** (§2.1, `E5-Q3`). SAL-7 is not contradicted — it forbids
  an accessor that tells a rule "this hash is an alt block", and a stitched
  `block_at` is not that.
- **E5-6 — the cheap tier reads archival state from the wrong chain, and
  the C++ accepts it.** `verify_block_attestation(b, prev_height,
  &alt_chain, witness)` (`blockchain.cpp:2135`) reads bond records from
  `m_db` — the current main tip — for an alt block whose fork point may be
  up to `D_max` below it. A bond slashed between the fork point and the tip
  makes an honest alt block fail the cheap tier. The error is one-sided
  (promotion re-validates against the true state; a wrong refusal is a
  liveness cost, never a wrong admission) and bounded by `D_max`.
  **Dissolved 2026-10-11** under `E5-Q4`'s β (§8): the Rust cheap tier
  makes no chain-state read — a bond's state is a promotion-tier operand,
  read after the alt chain executes — so there is no chain, right or
  wrong, for the cheap tier to read it from. The read exists only in the
  C++ alt path, which is frozen (`DEL-009`). Neither inherited nor fixed.
- **E5-7 — the switch's rollback is the transaction.** SAL-14 is confirmed
  at the tree: `store.write`'s closure returning `Err` discards every pop,
  insert and connect; there is nothing to "roll back" and nothing to
  re-connect. `rollback_blockchain_switching`'s 48 lines (`:980–1027`) have
  no Rust shape. The one thing the transaction does **not** undo is the
  `undo_floor` cell (F-2), which is read before the first pop, not written
  by it.
- **E5-8 — `SPL-Q5`'s reconciliation at open is unbuilt and has a
  specification.** The pool store and the chain store commit separately, so
  a crash between a chain commit and the pool's follow-up leaves pool
  entries whose key images are spent on chain or whose transactions are on
  chain. SPL-9 says the pool is reconstructible from P7, so the reconcile is
  a pass over `entries()` against the chain snapshot's `has_key_image` /
  `has_transaction` — the same two reads the admission door makes. One
  function, two callers (open and admission), rule 05's "a formula two lanes
  need is a function".
- **E5-9 — the pruned-row asymmetry does not reach a reorg within the cap,
  and the reason is a constant that must stay asserted.**
  `failure_window.rs:232–245`: a pruned settlement row reads as a *miss*
  against the serve-credit ledger and as *non-observation* against the
  settlement table. A reorg pops at most `D_max` blocks (the switch refuses
  deeper up front, `E5-Q6`) and `pop` refuses below `undo_floor`
  (`pop.rs:113`); `reorg.rs:70`'s assertion keeps the floor above the body
  horizon. So no reorg re-runs a settlement gather over a row the prune
  removed. The asymmetry is priced in §4 as the fixture that would notice
  if either constant moved — not as E5 work.
- **E5-10 — the corpus has no reorg.** DRS-E2's replay produces no alt
  block (`DRS_E1_SALT.md` SAL-8, "§11.2"); `IngestEvent` (`source.rs:88–99`)
  is `Extend`, `Rewind { to }`, `Inject`. `Rewind` is a pop, not a switch:
  nothing in the trace carries an alt block, a fork choice or a promotion.
  The oracle that grades E4's writer cannot grade E5's switch until a
  capture does (`E5-Q9`).
- **E5-11 — K10 composes with M8 through a field that exists.** C2-R1 §5.5
  Q2a ruled K10 (`kept_by_block` admission) composed with M8 (the
  verification cache) as an armed dependency. `PoolRecord.fcmp_cache` is
  that arm (SPL-10). What is *not* recorded anywhere is a verified proof's
  hash for a transaction that was on chain: a demoted block's transactions
  return to the pool with no cache entry, and re-admission re-verifies.
  `E5-Q8` asks whether to seed the cache on demotion; the default is no.
- **E5-12 — the fork choice has one Rust home, and its verdict does not
  carry the arm K7 keys on.** `ForkChoiceVerdict` (`fork_choice.rs:30`) is
  `KeepCurrent | Switch` — two arms. The C++ reads `Switch`
  (`blockchain.cpp:2291`) and then decides *discard* from its own
  `is_a_checkpoint` (`:2334`): the checkpoint-forced switch that discards the
  demoted chain — K7's terminator of the flip-flop — is a fact the function
  computed (`checkpoint_match` is its third argument) and then threw away,
  so the caller recomputes it. One mechanism, two jobs
  (`05-system-thinking.mdc`). In Rust the terminator is a third arm,
  `ForcedSwitch`, and K7 is a match on it, not a boolean beside it; `E5-Q5`
  fixes the shape and prices the FFI consumer that reads the `repr(i32)`
  until DEL-009.

The three findings below are PR-a commit 1's measurement (Round 1 ruled
`E5-Q3` with "the partition of `header.rs`'s rules between the tiers is
unknown; commit 1 owes it rule by rule"), read at `dev@ac95d6d04`.

- **E5-13 — `block_at` is a header fact by method and a mixed fact by
  field; the honest header view returns a header record.** `RecordedBlock`
  (`view.rs:166–190`) is `{hash, header, cumulative_difficulty,
  coins_generated, cumulative_tx_count, cumulative_archival_len}`. The
  first three are shape facts an alt entry has (`AltBlockFacts`,
  `codec/alt.rs:114`: `height`, `block_weight`, `cumulative_difficulty`,
  `coins_generated`); the last two an alt entry **cannot** have — nothing
  has executed its body — and `coins_generated` is K8's bookkeeping, which
  SAL-7 says no rule reads. A stitched `block_at` returning `RecordedBlock`
  would therefore have to invent `cumulative_tx_count` for alt rows or
  fault *inside a field*, and the fallback `E5-Q3` priced ("twenty-four
  faulting methods") is weaker than Round 0 wrote: the fault would sit
  inside the one method the cheap tier does call. The split is at the
  type: `HeaderRecord { hash, header, cumulative_difficulty }` and
  `HeaderView::header_at(h) -> AtHeight<HeaderRecord>`; `RecordedBlock`
  embeds a `HeaderRecord` and `ChainView::block_at` keeps returning it.
  Readers move by what they read: `difficulty.rs:240–266`
  (`cumulative_difficulty`, `header.timestamp`), `pow.rs:152` (`hash`),
  `timestamps.rs:144/:149` (`header.timestamp`), `anchors.rs:144`
  (`hash`), `attestation.rs:203` (`hash`, the anchor window) read
  `header_at`; `miner.rs:469/:523/:668` and `close.rs:75` stay on
  `block_at`. K8 gains its type-level witness (§3's row corrected): the
  view an alt rule can be bound on has no `coins_generated` to read.
  UPDATE 2026-10-11 (a4): and the record has none to offer — the field
  is deleted (§2.1, "no supply figure"); K8's witness moves from the
  view's type to the row's layout.
- **E5-14 — `header.rs` is three form rows and one promotion row; the
  cheap tier re-bounds five rule files and `header.rs` is not one of
  them.** Rule by rule: **B1** (`:57`) and **B2** (`:76`) are `FormRule`s
  — no view, already run by `form` before any tier, so the cheap tier gets
  them by calling `form`; **B6** (`:149`) is the identity `form` derives,
  no view; **B5** (`:108`) reads `root_at(cx.connecting)` — the curve-tree
  state after the parent connected — an executed fact no alt chain has:
  **promotion tier**, with the consequence written in §2.1. So the
  re-bounding touches `anchors.rs` (E1 `:143–144`, E2), `timestamps.rs`
  (C1, C2, C3's window `:131–149`), `pow.rs` (D1, D3's seed `:142–152`),
  `difficulty.rs` (D4's window and `cumulative_after` `:227–266`) and
  `attestation.rs` (B4's `anchor_window` `:188–203` — a header fact, bound
  on `HeaderView` as one; B4 itself is a main-chain rule only, `E5-Q4`):
  five, and a different five from §1.0's (version out, attestation in). Beside them: `rules/mod.rs` (the trait and the
  `recorded` helper), `view.rs` (the split), the nine `ChainView`
  implementors (`BatchView`, the chain-rules harness views, the ingest
  test tree) each gaining `HeaderView`, and
  `scripts/ci/check_block_rule_corrupt_sites.py`, whose `IMPL_RE` reads
  `impl BlockRule for X` (`:101`) and must read the header-rule impl too
  or its enumerated set shrinks under its floor (measured at a2: it did,
  15 → 11 under a floor of 10, green; a2 derives the trait set from the
  blanket impl instead — §5). The measured
  `HeaderView` is **two methods, not four**: `tip` and `header_at`.
  `height_of` and `depth_at` are header facts by classification and have
  no cheap-tier caller (`tx_against.rs:259/:424` only — I-rows, promotion);
  a method with no caller is pre-provisioning (rule 21), so they stay on
  `ChainView`. The `E5-Q3` falsifier did not fire on count and did fire on
  membership; the split stands, re-measured. UPDATE 2026-10-11 (a4): the
  count is **six** rule files, not five — `miner.rs`'s F4/F5/F6 read
  `cx.connecting` and nothing of the view, and the alt ladder runs them
  (`prevalidate_miner_transaction`'s checks, §2.1), so a4 re-bounds them
  `HeaderRule` (15 rules read: 8 + 7). The five-file measurement was of
  the files a2 touched, not of the rows the tier runs. The a2 falsifier's
  count clause ("more than these five rule files … is the fallback")
  **fired** on this; the fallback (`AltView` as a faulting `ChainView`)
  is not taken, because the clause was a proxy for the split sprawling,
  and a sixth file re-bound under the same blanket impl, with no new
  view method and no change to `run`, is the mechanism working, not
  sprawl. Recorded so the clause is not read as unfired. UPDATE
  2026-10-12 (review finding on #1026): **seven** — `topology.rs`'s A2
  reads the tip's hash and nothing else, and the alt ladder runs it first
  (§2.1): the tier cannot see that the view was built from the
  candidate's `previous`, so it checks the link as `validate` does (15
  rules read: 7 `BlockRule` + 8 `HeaderRule`). Same mechanism, same
  reading of the count clause.
- **E5-15 — CEN-K4 names CEN-B4 in the admission tier; a K-row does
  require the attestation check before storage.** The ratified row
  (`CONSENSUS_RULE_CENSUS_3.md:395`): "alt blocks are accepted into storage
  after: version (CEN-B1 …), **attestation (CEN-B4)**, timestamp vs
  alt-window median (CEN-C2), checkpoint, PoW at alt difficulty
  (CEN-D1/D5), and prevalidate-only miner-tx checks";
  `CONSENSUS_STORE_RECONCILIATION.md:787` holds it CHECKED-CONFORMANT with
  the attestation step at `:2264`. B4 (`attestation.rs:85–148`) makes two
  view reads: the **anchor window** (`anchor_window`, `recorded(view,
  height).hash` over the connecting chain — a header fact the stitched
  view answers honestly, and the C++ passes `alt_chain` to
  `fill_pass_anchor_window` for the same reason, `blockchain.cpp:5034`) and
  the **bond's committed hybrid key** (`committed_hybrid_key`,
  `view.bond_record(persona)` — the archival read `E5-6` was about). This
  is the fact `E5-Q4`'s pricing turned on (§8); β makes the factoring
  moot — the second read is chain state, so the whole rule is promotion's.
  What the finding still decides: the ratified K4 row
  names a step the Rust tier does not run, so a4's census amendment
  rewrites it — the C++ ladder in its landed order, no attestation step
  for the Rust tier (§5).
- **E5-16 — the as-of-fork-point bond read exists today; `E5-Q4`'s
  "no table supports it" was false.** (Review finding, 2026-10-10, from
  the pruning lane; verified at the tree before this entry was written.)
  `E5-Q4`'s *why* priced the alternative to the wrong-chain read as "an
  as-of-height archival read … that no table supports", costed as a
  settlement-writer change. But `undo_log[height]` (`codec/undo.rs`,
  `store/undo.rs`) journals the **pre-image** of every chain-state write
  made through a batch handle, for every block above `undo_floor`, and
  `ARCHIVAL_BOND` has exactly two write sites, both journaling verbs:
  `open_insert_table(ARCHIVAL_BOND, …)` (`archival_write.rs:164`, SI-19)
  and `open_replace_table(ARCHIVAL_BOND, …)` (`:177`, SI-20) — the
  module's own ladder says so at `:27`. `UndoEntry` has three arms and
  each carries what a reverse replay needs: `Replaced { prior: Option<…> }`,
  `Removed { prior }`, and `Inserted` (absent before — itself the
  answer); nothing is digest-only in the direction a reconstruction reads
  (`post` is the forward check). So `bond_record(p)` **as of the fork
  point** is a read-only reverse replay of `undo_log[fork+1 ..= tip]`
  filtered to the `ARCHIVAL_BOND` ordinal: no new table, no writer change,
  and not `PDM-Q3`'s subject (Q3 ruled the residual consensus-read set
  empty; it ruled nothing about as-of reads). The window is guaranteed:
  `Horizons::new` refuses `undo_retention < reorg_cap`
  (`prune.rs:199–203`, `RetentionBelowReorgCap`), and the switch's cap
  check (`E5-Q6`) runs before anything else, so every fork point a switch
  can reach has its rows. **The one way this is silently wrong, checked:**
  the retention prune's deletions are un-journaled (`retire_undo_rows`
  and `discard_range` open tables raw, `prune.rs:391`, `:736`), so a
  reverse replay over a table the prune reaps would reconstruct a record
  that looks complete and is not. `rg ARCHIVAL_BOND store/prune.rs` → 0:
  the prune touches `UNDO_LOG`, `PROPERTIES` and the two shard tables, not
  bonds. **The finding stands with no consumer:** δ was built on this read
  and rejected with `E5-Q4`'s β (2026-10-11) — the question δ answers at
  admission, promotion answers for free. Rule 05 for
  whoever next needs an as-of-fork archival read: `replay`
  (`store/undo.rs:504`) is the function, and the read is that function in
  read-only mode, not a second walker.
- **E5-17 — δ's fork-point read cannot see a bond that joins in the alt
  chain's own blocks, and that case is reachable at admission.** Found
  drafting a4's row text: the C++ comment above the alt path's attestation
  verify (`blockchain.cpp:2131–2133`) names it — "a pass from a bond that
  joined only on this alt chain is refused here" — and `docs/FOLLOWUPS.md`
  carried it as *"Alt-chain attestation verify resolves bond pubkeys from
  main-chain state"*. A join in an unexecuted alt block above the fork is
  in no view the admission tier can read. **Reachability, measured:**
  admission checks no epoch arithmetic on a pass record —
  `AttestationSet::verify_countersignatures` judges the anchor window and
  the key (`attestation_admission.rs:78–96`: four refusals, none about
  epochs), `settlement_epoch` is carried on the 49-byte record and
  compared to nothing at B4, and the C++ body (`verify_block_attestation`,
  `blockchain.cpp:4979–5066`) reads no join epoch; `J5` is claim-time,
  `J15` governs the join's own admission. A pass under a bond joined at
  `j` is admissible in block `j + 1`, inside `D_max = 720`. Not moot.
  **Dissolved 2026-10-11** under `E5-Q4`'s β (§8), directly: a key bonded
  only inside the alt chain's own unexecuted blocks is read at promotion,
  after those blocks execute — the case is the one a chain-state check at
  the cheap tier cannot answer and promotion answers for free. The
  FOLLOWUPS row closes on that ground: the Rust tier holds it by where the
  check sits, and the C++ path that refuses it is frozen (`DEL-009`).
- **E5-18 — the census registry cannot name a store-homed by-construction
  property.** (a3, 2026-10-11, found while landing `AltChain`.) §3
  projects K3, K8, K1a and K2 leaving `pending` as `by_construction`
  (`by-construction 16 → 20`). The registry form is
  `by_construction(path, "falsifier")`: the macro pins the path with
  `use $path as _` (`census.rs:202–205`), and
  `check_chain_rules_coverage.py`'s `check_by_construction` requires the
  falsifier to be a `#[test]` (or `doctest:`/`trybuild:`) **in the rules
  crate's own `src/` and `tests/`**. `AltChain`, `AltView` (K8's absent
  `block_at`) and AL1's `AlreadyHeld` (K3) all live in
  `shekyl-chain-store`, which `shekyl-chain-rules` must not import
  (DRS-D12 (i): no store handle, neither `shekyl-chain-store` nor
  `redb`); the dependency runs the other way. So neither the path nor the
  falsifier can be named from the registry as it stands. a3 lands the
  construction and its tests in the store (§3 K1a/K2 witness cells) and
  leaves the four arms `pending`; a4's "census arms" commit resolves the
  form — a registry variant that credits a falsifier by crate and test
  name with the gate reading that crate's sources, or §3's projection
  revised to count these rows as held-by-store rather than
  by-construction. Not a deferral past the increment: a4 is the next
  commit and already owns the arm flips.
  **RULED 2026-10-11 (a4, census-arms commit): `held_by_store(crate,
  test)`**, a `RowStatus::HeldByStore` mirroring `HeldByCxx`. The form
  names *who enforces the row* — the store, which is what DRS-D12 (i)'s
  dependency direction makes true — and the gate asserts the named
  `#[test] fn` is **defined** in that crate's `src/` or `tests/`
  (`check_held_by_store`; the crate must be a workspace crate other than
  `shekyl-chain-rules`, since a row this crate holds is `enforced_at` or
  `by_construction`). Not `by_construction`: that is a claim about a type
  **in this crate** with a falsifier **in this crate**, and a runtime test
  in another crate is neither. Not `enforced_at`: that site is this
  crate's. Counted as Rust-enforced (`implemented`), printed as its own
  figure (`held-by-store S`), excluded from `RuleSet::enforced` (per-block
  `E − H − O − B − S`); unlike a C++ hold it has no expiry. Four rows at
  mint: K1a, K2, K3, K8, each citing its `shekyl-chain-store` test. §3's
  projection is revised accordingly (`by-construction` stays 16;
  `held-by-store 0 → 4`).

---

## 2. The shapes

### 2.1 The alt view is a header view (`E5-Q3`)

Ruled 2026-10-10 (the split), re-measured by `E5-13`/`E5-14`. Round 0's
shape is kept below as records-was; the ruled shape is:

```text
pub struct HeaderRecord { hash, header, cumulative_difficulty }       // what an alt entry has
pub struct RecordedBlock { header: HeaderRecord, coins_generated, cumulative_tx_count, cumulative_archival_len }
pub trait HeaderView<'id> { type Fault; fn tip(); fn header_at(h) -> AtHeight<HeaderRecord>; }
pub trait ChainView<'id>: HeaderView<'id> { fn block_at(h) -> AtHeight<RecordedBlock>; fn height_of(hash); fn depth_at(h); …the twenty-four executed-chain methods… }   // 27 own + 2 inherited
pub trait HeaderRule: Rule { fn check<H: HeaderView>(cx, &H) -> …; }   // blanket `impl<R: HeaderRule> BlockRule for R`
```

*Round 0 wrote (SUPERSEDED by `E5-13`/`E5-14`):* `HeaderView { tip,
block_at, height_of, depth_at }` with "the PoW, difficulty, timestamp,
version and anchor rules re-bounded … their reads are already only
`block_at`/`tip`". Two corrections: `block_at` returns executed fields an
alt row cannot carry, so the header view returns a `HeaderRecord`; and the
re-bounded files are `anchors.rs`, `timestamps.rs`, `pow.rs`,
`difficulty.rs`, `attestation.rs` — not `header.rs`, whose only view-bound
rule (B5) is promotion's. `height_of`/`depth_at` have no cheap-tier caller
and stay on `ChainView`.

`BatchView` implements both from the one row read it already does; the new
`AltView<'s>` in the store — a `ReadSnapshot` plus an `AltChain` (the alt
entries from the fork point to the candidate's parent, AL4 walked to a
main-chain row; K2) — implements **`HeaderView` only**, stitched:
`header_at(h)` is the main chain's row below the fork point and the alt
entry's header, hash and cumulative difficulty above it; `tip` is the alt
chain's last entry. It carries no brand (its type is not `BatchView`), no
`block_at` and no archival method, so a rule that needs an executed fact
cannot be bound on it — the compiler, not a fault, is the belt
(`05-system-thinking.mdc`, "a type defends the call"). K8 is the first
beneficiary: no supply figure is a field the alt-bound view has, and since
a4 none is a field the alt row has either (below).

The alternative — `AltView` implementing the full `ChainView` with the
executed-chain methods returning a fault — was Round 0's fallback. `E5-13`
prices it lower than Round 0 did: `block_at` is the one method the cheap
tier calls, and its `RecordedBlock` has two fields an alt row cannot fill,
so the fault would live inside a returned value, not behind an uncalled
method. It stays on the table only if the `HeaderRule` blanket impl turns
out not to compose with `run`'s coverage recording; a2 reports either way.

**CEN-B5 at the cheap tier — written down because the reason it is safe
is structural.** B5 is promotion-tier (`E5-14`), so **an alt block is
stored without its `curve_tree_root` commitment checked.** This is the
C++'s own disposition (K4's row: "the curve-root check [is] deferred to
promotion", `CONSENSUS_RULE_CENSUS_3.md:395`) and it is fine for exactly
two reasons, both of which E5 builds rather than inherits: (1) nothing
reads an alt block's root until promotion, and promotion is `validate`
over `BatchView` — `AltValid` is not `ChainValid`, nothing converts it,
and `connect` takes only `ChainValid` (§2.1's brand argument, `E5-5`), so
a wrong root in the alt table cannot reach the tree; (2) what an
unchecked root costs is a stored row, and K4's PoW floor bounds how many an
adversary can buy (`E5-Q7`, rule-21 reopen in §4). Without (1) the
deferral would be a hole; with it the deferral is the `AltValid`/`ChainValid`
separation doing its one job. The same sentence covers every promotion-tier
row — G1's `has_transaction`, the F-rows' emission reads, the I-rows — and
the attestation witness's bond read (next paragraph). B5
is named because a committed root reads as the alarming case. The cheap
tier has one cost, a stored row, and K4's PoW floor bounds it.

**CEN-B4 is not ported to the alt tier (`E5-Q4`, β ruled 2026-10-11).**
The cheap tier makes no chain-state read. Any check whose operand is chain
state — a persona's bonded key, a bond snapshot — is promotion-tier, on
the ground the B5 paragraph above already gives the root: an unexecuted
alt chain cannot answer it, and promotion validates against executed
state, where the read is correct and costs nothing extra. B4's second
read is the bond's committed hybrid key (`E5-15`), which is chain state,
so B4 is not given an alt-tier site and an as-of-fork-point bond
reconstruction (`E5-16`) answers at admission a question promotion
answers for free. For the record: B4 exists in Rust
(`rules::attestation::B4`, `26bc5b994`) and runs on the main chain; an
alt block's witness travels in `AltBlock` (SAL-13; K5b) and is judged at
promotion by main-chain B4 over `BatchView` — the tier whose view has
executed the chain the pass depends on. The C++ alt ladder keeps its
`verify_block_attestation` step (`blockchain.cpp:2135`, behind PoW since
`4932b769b`) until `DEL-009` retires the path. Its tip-snapshot read
(`E5-6`) and its join-in-the-fork case (`E5-17`) are facts about the
frozen path, not shapes the Rust tier inherits or corrects: under β both
reads happen after the blocks they depend on execute.

The cheap tier is `alt_against(formed, &alt_view, &rule_set, &trust)
-> Result<Verdict<AltValid<'id, H>>, Fault>` (`shekyl-chain-rules`
`alt.rs`, landed a4 2026-10-11; the view-type brand is 2026-10-12), where
`formed` is `form`'s token — B1/B2, B6, D2, the 4.F form rows
F1/F3/F7/F9/F10 and G2 ride in on it — and `alt_view: impl AltChainView`
is the stitched header view (`E5-Q3`) that also names the fork it
describes (`AltChainView::fork() -> Fork`; `Fork::new(root, recorded_tip)`
is the only constructor and refuses a root above the tip as
`InvertedFork`, so `pops()` is a `BlockCount` — the store reports that
pair as SI-7 on `block_heights` before a `Fork` exists). The store's
`AltView` answers from the `AltChain` it stores, so E2's operands and the
headers come from one snapshot by type, not by the caller's care. Its
ladder, in the C++'s order where the order is a rule:
**K1b** (the height-0 claim, a `FormRule` run first, before any header
read); **E2** over the view's `Fork` — the anchor floor (`root <
current()` refused) and the rolling cap (`recorded_tip − root >
reorg_cap` refused), the cap binding only when anchored (`PDM-Q11`'s
binding condition), neither band reading a header; then the definitions
over the stitched chain — D3's seed, C3's window, D4's target (D6 the
zero guard; **D5** records its row only when that derivation produced a
target, beside D4/D6/D7 — a D6 refusal is D4's verdict and records no
D5) and its check against the target `form` judged CEN-D1 against
(`Stale::Target` on a mismatch, never a verdict), `cumulative_after`,
D1b — and the header predicates, three segments shared with `validate`:
**A2**; C1, C2; E1, F4, F5, F6. CEN-D1 is `form`'s since #1081's review
(item 1): it runs before any body work against a claimed target, so an
alt arrival's `form` takes the target claim the stitched chain derives
(`target_claim`). `validate`
inserts B5, B4 and G1 between those segments; the alt tier does not. A2
(`topology.rs`) is a `HeaderRule` since 2026-10-12 and the ladder's first
predicate, as it is `validate`'s: on the store's path
the view's tip *is* the candidate's parent by construction
(`AltChain::build` from `previous`), but `alt_against` sees a view and a
token, not that derivation, and a view handed over for another block
would otherwise mint an `AltValid` for a chain the block is not on
(review finding, 2026-10-12; `16-architectural-inheritance.mdc`, a claim
about the construction is not the function's contract). F4–F6
(`miner.rs`) are `HeaderRule`s since a4: they read `cx.connecting` and
nothing else of the chain, so the re-bounded files are seven, `E5-14`'s
five plus `miner.rs` and `topology.rs` (14 rules read since D1 and H19
moved to `form`: 7 `BlockRule` + 7 `HeaderRule`). No
attestation step, no B5, no body rule, no slot loop. K1a is the store's
(`AltChain` construction; registered `held_by_store` in the census-arms
commit, `E5-18`). The row set is pinned by
`alt_tests::the_cheap_tier_evaluates_the_header_ladder_and_the_alt_arms_and_nothing_else`
(form's rows — D1 among them — + {A2, C1, C2, C3, D1b, D3, D4, D5, D6,
D7, E1, E2, F4, F5, F6, K1b, K4}, and `covers_landed` false; K4 is the tier itself — recorded
by `alt_against` after the last header predicate, so an `AltValid` carries
it iff every step ran, and registered `enforced_at` that site with the
row-set pin as its test, census-arms commit). `AltValid<'id, V>` carries the block, its derived height, cumulative
difficulty and wire weight — no supply figure (K8) — and is what AL1
stores. It is branded as `ChainValid` is (`'id` invariant, `V` the view
type), and `insert_alt_block` takes `AltValid<'_, AltView<'_>>`, so a
verdict minted over any other view does not unify with the row. It is not
`ChainValid`, nothing converts it, and no `covers_landed` is asked of it
(the tier's completeness is the row-set pin, not the per-block gate). The
tier and the write stay two operations: a5's switch judges on the
pre-pop snapshot, then pops, then inserts, and the snapshot stays live
through the write.

**K8: the alt row carries no supply word** (a4, 2026-10-11,
`SCHEMA_VERSION` 22 → 23 at the commit; 24 once merged with `dev`, where
23 is `SO-D12`'s draw tables — §10, 2026-10-12). The C++ `alt_block_data_t` carried
`already_generated_coins` per alt block, advanced by the coinbase paid
rather than the subsidy — an approximation C2-R1b ratified as *kept*
because "deleting the field would change the persisted `alt_block_data_t`
layout (rule 42 fence)". That reason was about the C++ store's layout,
which is frozen (`DEL-009`); for the Rust store rule 42's fence **is** the
version bump, not a prohibition on the change. The substrate the ruling
stood on has shifted, so the disposition is re-anchored (rule 21), not
inherited: the Rust tier that admits an alt block reads no executed-chain
fact and derives none (above), promotion re-derives supply by executing
the chain, and a field with no reader is not stored (rule 15). `AltBlock`
and `AltBlockFacts` lose `coins_generated`; `alt_block.snap` re-pins eight
bytes shorter; the FOLLOWUPS row *"Alt-chain supply accumulation advances
by the coinbase, not the emission subsidy"* closes — nothing accumulates.
The falsifier is a layout pin,
`codec::alt_tests::an_alt_row_has_no_supply_word`: a re-minted word of any
name lengthens the record and fails it. K8's registry form is therefore
the store's (`held_by_store`, `E5-18`), not a rules-crate
`by_construction`: the property is the row's layout, and the row is the
store's.

The promotion tier is `validate` over `BatchView` inside the switch closure
after the pops, exactly as any block connects. There is no "promotion view".

### 2.2 The pool decorator is a key-image decorator (`E5-Q1`, `E5-Q2`)

```text
pub struct PoolView<'v, V> { chain: &'v V, pool_key_images: &'v KeyImageSet }
impl<'id, V: ChainView<'id>> ChainView<'id> for PoolView<'_, V> { has_key_image = chain || pool; everything else delegates }
```

Under FCMP++ a pool transaction's outputs are not in the tree, so the pool
adds nothing a rule can reference except spent key images (M6 against the
chain, M7 against the pool — one `has_key_image`).

**The door is the validator's own judgement, at `TxSlot::Lone`** (PR-b
brief, 2026-10-16). Three calls, in order:

1. `judge_slot_stateless(tx, TxSlot::Lone, rule_set, &claims)` — the one
   public function `form` runs per slot: `tx_form` (M2: the full NIC set),
   the signatures (CEN-I17/I18), the proofs against the caller's reference
   claims (CEN-I15, J26, J27's verify half), and — at `Lone` only — CEN-H19's
   range-proof batch over the transaction's own proof. `form` never passes
   `Lone`; its listed proofs are one block batch after the slot loop, so a
   block's proofs are still verified once. The claims are read off the
   pool's tip snapshot, as the ingest driver reads them off its header
   ledger (`ReferenceClaims`, the third claim).
2. `tx_against(tx, TxSlot::Lone, &pool_view, rule_set, verified, attempt)`
   — the view-bound half `validate` runs per slot, over the decorator; it
   compares the chain's `(height, root)` at the reference with the claim
   step 1 verified, and a disagreement is the `Stale::Reference` fault (the
   tip moved between snapshot and view), answered by judging again.
3. `policy_form(tx, &AdmissionPolicy, …)` for the `PolicyRow`s (M3 fee
   floor, M4 extra cap, M5 unlock ban), which populates `PolicyCoverage`
   and lifts the policy gate off `implemented 0`.

No proof or signature is verified anywhere in `shekyl-mempool`: the
crate calls the two validator functions and holds no rule (`E5-Q2`'s
condition). **Every transaction runs the whole door, policy included** — a
transaction returned from a popped block (K10) as much as a relayed one
(`E5-Q1`, reopened in part 2026-10-11, §8: the `kept_by_block` policy skip
was the fee-floor bypass for block-carried transactions that the
2026-10-02 reopening of C2-R2 Q9 names as a bug). K10's retention of a
returned transaction that the chain-bound half refuses — kept, not
relayable, never selected, evicted by M10 — is unaffected.

**An alternative block's bodies are the store's, not the pool's** (K9;
the review of #1102, B1, 2026-10-17). A switch connects the promoted
blocks' listed bodies, so they are consensus data. A pool refuses,
evicts and discards by local policy, and a fee floor no consensus rule
sets moves every block, so a body left to the pool could leave a heavier
valid chain unpromotable. AL1 writes an alt row's bodies to
`alt_block_bodies` beside it, from the cheap tier's verdict (whose
candidate `form` paired with its header, CEN-G2), for an offered
alternative and for a demoted block alike; AL2 and AL3 remove them with
the row; AL8 reads them back, held to the row's listed hashes. The pool
is offered them (`Pool::supplement`, which takes the stored `AltBodies`,
and `Pool::returned`) for relay and templates only: its refusal costs a
transaction its relay, never the chain its switch. A held transaction a
block carries is made public — a block published it, and a pool that kept
it in its stem phase would answer peer sync differently for a stem
transaction it held, which anyone able to send an alternative block could
read.

M11 ("zero-fee
never relayed") is not a row of this door: with the serve-credit carriers
gone there is no zero-fee family to exempt from M3, and a second mechanism
for M3's job is deleted (`05-system-thinking.mdc`, one mechanism one job;
§3's M11 row).

**The pool knows one relay fact: public yet** (DX-F6, 2026-10-16;
`DAEMON_RELAY_PRIVACY.md` D++ acceptance criterion 2). A transaction that
is not public is absent from the pool listing, from peer pool sync and
from a block template. The relay's fluff event sets the bit, and so does a
block carrying the transaction. Stem, fluff, embargo, the arrival connector and the originator's
re-broadcast responsibility (F-10's disarm) are `shekyl-relay`'s:
`Responsibility` moved there, keyed by transaction hash beside the stem
watch, staged for the DRS-X flip's relay wiring. The pool record keeps
only what the transaction's bytes cannot say and admission, eviction or
template selection reads — the receive time to the hour, the public bit,
and a standing (admitted, or kept under K10 with the height it was
returned at) — and nothing else (`codec/pool.rs`'s module docs give the
reason per field; `SCHEMA_VERSION` 27). The file is not trusted (the
review of #1102, S2): an open re-derives the weight and fee from the
bytes, drops each row that does not read, does not parse or is not the
transaction its key names, clamps a receive time from the future, and
runs every entry through the whole door; M8's anchor lives in memory
only. The listing carries no receive time (S7), and a layout recreate
overwrites the old file before unlinking it. The API enforces criterion 2
(S6): the block arrivals are crate-private, reached only through
`Pool::returned` and `Pool::supplement`, so no caller can admit a peer's
transaction as public; every read that sees the stem phase — a record,
the key-image map, the count — is `RelayView`'s, named for the relay and
the submit shim, while everything that answers a peer or a foreign
caller reads `shown`. A transaction the pool holds only as kept is no
duplicate to a submitter: the door judges it again. Responsibility is in memory: after a restart the relay cannot tell
this node's unpublished transactions from arrivals still in stem, and
treats every non-public entry alike — the uniform handling is the privacy
property. What the relay does with them at open is the relay's to decide
at the flip.

The decorator and the pool live in a **new crate `shekyl-mempool`**
(default, `E5-Q2`): admission, the key-image conflict map, the relay
interface (the public bit), M10 eviction, template selection
(`fill_block_template`'s successor), and the open-time reconcile (`E5-8`).
It depends on `shekyl-chain-rules` and `shekyl-chain-store`, and
`shekyl-chain-ingest` depends on it for the switch's returns. **No FFI
crate depends on it** (DX-Q5, DX-Q7): the Rust daemon wires the pool at
the DRS-X flip, and C++ never reaches it through the FFI. It
never implements `connect`'s view type, so rule 23's STAGED surface is
clean: every symbol it mints has a caller in the same PR, and the crate is
staged whole for the flip.

**Bundles are not transactions, and their queue is not the pool.** The
bundle body store (O1), the bundle queue (O2) and the template's bundle
section left this lane on 2026-10-16 (the PR-b brief): they are SO-D12's,
built with the bundle section on the block wire and `drawable_epoch`'s
data source (`ARCHIVAL_SETTLEMENT_WRITER.md` §16.3 items 2 and 3) against
Slice C's verifier view trait and kept projection (`BundleView`,
`archival/bundle.rs`; `Admitted`; #1047). None of it touches C++: the C++ sidecar path —
`cryptonote_protocol_defs.h:71` (`attestation_witness`), the
demote/promote witness handling in `blockchain.cpp` (`:995–1065`),
`db_lmdb`'s witness table — is a `DEL-008` deletion.

### 2.3 The switch is one closure (`E5-Q5`, `E5-Q6`)

**The death rule.** An alternative row at height `h` can be promoted only
by a switch that pops `tip − h + 1` blocks at least, and the cap refuses
any switch deeper than it before a pop (`E5-Q6`); the tip only rises. So
the connect that advances the tip to `t` removes, in its own write, every
alt row at or below `t − cap`, with its bodies — after the journal's seal,
since alt rows are not chain state — and the writer removes, beside it,
every row at or below the last anchor at or below `t`, which CEN-E2 would
refuse. A row's lifetime is the cap: no constant of its own. A switch
removes each promoted row as it connects that block, so a promoted chain
longer than the cap never has a row swept before its own removal.

```text
// On the actor, before any write. The actor is the only writer, so nothing
// moves the chain between these steps and the closure.
// 0. the cap (E5-Q6): depth > rule_set.reorg_cap() refuses here, locally,
//    before any RandomX — PopBeyondReorgCap, never a verdict
// 1. form what the switch judges: the M alt entries and, unless the verdict
//    is ForcedSwitch, the N demoted blocks — off the actor, through the PoW
//    this node recorded when it first judged each (block_pow, the alt row):
//    no RandomX unless a seed claim differs from the recorded one
// 2. SAL-13: each demoted block step 1 formed — the Switch arm — judged by
//    the cheap tier — alt_against over an AltView on a ReadSnapshot taken
//    here, where its history is exactly the chain below it; a refusal is
//    SI-27 and the writer halts. ForcedSwitch formed none of them (step 1)
//    and discards them (K7), so the tier does not run and SI-27 does not arm
store.write(|batch| {
    // 3. pop() × N        — PopBelowFloor surfaces here as F-1 fail-stop, never peer-punishable
    // 4. SI-5 over the tree the pops left
    // 5. insert_alt_block(AltValid) × N   (K7: Switch keeps the demoted chain; ForcedSwitch discards it)
    // 6. for each alt entry: validate(formed, &batch.view(), in_force, trust) → connect  (K5; K5b's witness travels in the AltBlock)
    // 7. remove_alt_block × M
    Ok(Switched { demoted, promoted })
})?;   // Err → the transaction is the rollback (E5-7, SAL-14); a promotion
       // verdict then removes the failing alt suffix in a write of its own (K5)
pool.returns(demoted_txs); pool.evict(promoted_txs); template.invalidate();
       // SPL-Q5: chain first, pool second, from Ok — PR-b's; until then the
       // switch returns the demoted Vec<Transaction> and its one caller drops it (E5-Q10)
```

The switch lives in `shekyl-chain-ingest` beside the connector that owns
`Rewind`. An alt arrival is formed off the actor, as every block is; on the
actor the tier judges it and AL1 stores it, and the fork choice's verdict is
the reply. A winning verdict names the blocks step 1 forms — off the actor,
where the RandomX workers already run — and the switch message carries them
back with the tip it was planned against; a tip that moved in between is a
driver defect, never a switch. K6 is the match on `ForkChoiceVerdict`
(strictly greater switches, equal keeps, checkpoint-forced forces); K7's
discard is the checkpoint-forced arm (`E5-12`); K8 has no field to read —
the alt row carries no supply word since a4 (§2.1), so the switch carries
none and promotion derives supply by executing. K3 is AL1's `AlreadyHeld`,
by construction. `Rewind` stays a replay event: a live source never emits
one, because the fork choice decides reorgs and a source does not (the
DRS-X Round 0 makes that a type).

**Demoted blocks re-enter through the cheap tier (ruled 2026-10-15).** Only
the tier's verdict mints an alt row; a demotion constructor would be a
second admission path. Judging before the closure keeps RandomX out of the
write transaction: `insert_alt_block` takes the verdict minted on the
snapshot (`AltValid<'_, AltView<'_>>`), and the snapshot stays alive
through the write. A recorded block the tier refuses is **SI-27**, a
store-integrity fault: the tier is a subset of `validate`, evaluated over
the same history under the same rule set by height, and the one input that
differs — the local clock — only moves the future-time limit in the
block's favour, so a refusal means the store holds a chain that fails its
own rules.

**The switch does not re-hash what this node already hashed (ruled
2026-10-15).** Measured first: at the genesis cap the re-form was 1 441
RandomX hashes — 114 s on 16 threads, 684 s on one — against a store
share of 21 s. Every one had been computed when the block was first
judged, so the proof-of-work hash is recorded beside the block as a
derived fact, as its cumulative difficulty is: `block_pow[h]` at
`connect`, and the alt row's PoW field at AL1 (`RecordedPow`, seed ‖ pow;
layout 26). The switch forms through a substrate that answers from that
record (`substrate::Recalled`) keyed by **(block identity, seed)**, never
identity alone, so a seed claim that differs from the recorded one
recomputes and then meets CEN-D3 as it would without a record; ordinary
arrivals use the plain substrate. The record is written only by this node,
after D2 computed it and D1 accepted it, under the store-integrity belts
the recorded cumulative difficulty sits under; a peer cannot reach it, and
a corrupted value can touch only a block this node already accepted once.

**The switch supplies three claims, and the closure verifies no proof
(round 3, 2026-10-16; `CHAIN_RULES_CRATE.md` §4.6).** Re-measured after
the recorded PoW, the floor device held the write transaction for 109.6 s
on a cap-depth switch with one spend per promoted block — almost all of it
spend-proof verification inside `validate`. Each `PlannedBlock` now
carries its **target** beside its seed (CEN-D4 through `target_claim`
over the stitched `AltView` for an alt entry, over the recorded chain
below it for a demoted block; a D6 refusal on an entry is that block's
verdict at offer, `Offered::Refused`, and the refused entry with every
entry above it leaves the alt table in a write of its own, as a
promotion verdict's suffix does (K5); on a demoted block it is SI-27),
and the plan carries the post-switch **header chain** a promoted block
may reference — CEN-I11's window below the first promoted height and the
entries themselves, each with its header's root (`SwitchPlan::headers`).
The plan carries each promoted block's bodies from the store (AL8), and
the caller claims each promoted block's references off its header chain
(`SwitchPlan::references_for`) and `form` verifies the proofs and
signatures off the actor; inside the closure `validate` compares the
claim with the chain and faults `Stale::Reference` — `RunFault::StaleReference`,
a driver defect like a stale target, the transaction rolled back and the
writer up (`a_reference_or_target_claim_the_switch_cannot_make_is_a_driver_defect`).
Measured at `dca5d66ad` / `3e0d72313` (decision log, 2026-10-16): with
one spend per promoted block the write transaction went from 21.4 s to
1.93 s on the development host and from 109.6 s to 11.1 s on the floor
device; the proofs are now `form`'s, 3.0 s across sixteen threads and
62 s across four, off the actor.
Demoted blocks are formed with **no** reference claims: the cheap tier
compares none, and the chain verified their proofs when it connected
them — a claim there would cost N blocks' proofs verified again and buy no
verdict (reported to the brief as the one discrepancy: Part 1 named the
snapshot as the demoted target's source and Part 2 named no reference
source for demoted blocks). An alt row's header root is a claim until
promotion runs CEN-B5 on it, which happens before any successor's claim
over it is compared. A promoted block that `form` refuses under those
claims is not a reorganization: `RefusePromotion` removes the failing
suffix and does not pop. A refusal under claims the plan did not derive
is the driver's, observed before that message, and the alternative stays.

**SI-5 recomputes the tree's right edge (ruled 2026-10-15).** After the
pops — the switch's and `Rewind`'s — the store rebuilds each layer's last
chunk from its stored children with `shekyl_fcmp::tree`'s primitives, leaf
layer first, carrying each rebuilt chunk up as the last child of the layer
above. Each rebuilt chunk must equal the stored one, and the top must equal
`curve_tree_roots[h + 1]` for the tip `h`. A pop only trims leaves at the
end, so the chunks a pop can change are exactly each layer's last chunk:
rebuilding them checks the whole trim, at chunk width × depth reads. SI-12
compares the summary with the same recorded root, and both come back from
one undo log, so it cannot see a bad trim; SI-5 can. An empty tree has no
chunk to rebuild; its top is `CurveTreeRoot::EMPTY`, which the two stored
roots can agree on not being.

**Bundles at the switch land with SO-D12's merged increment (ruled
2026-10-15).** Until then the alt row keeps the attestation witness and
CEN-B4 runs at promotion through the full `validate` (`E5-Q4` β).
**`BundleView` has one implementation, on `BatchView`:** the switch's batch
view is the store's batch view, so this section and
`ARCHIVAL_SETTLEMENT_WRITER.md` §16.3 describe the same impl, built once,
with that increment. What it brings to the switch: an alt block stores
bundle *references* `(h, kept bytes, prunable hash)` in place of the
witness (B10, rule 42's bump); arrival checks over references are
stateless (well-formed; root equals header; the budget sum when `D` is
known at or below the fork point, else at the switch); before the closure
every referenced body is fetched and checked against its hash, and an
unfetchable body means no switch, a local outcome; inside the closure
`validate` runs the bundle verifier, and an invalid bundle fails the switch
(`E5-7`).

---

## 3. Dispositions — the twenty-five rows

Per row: the disposition (**rule** = a Rust rule with a `census.rs`
`implemented` arm; **by construction** = the type or the store refuses it
and a test pins that; **sequencing / writer behaviour** = orchestration in
the switch or the pool, witnessed by a test, not a census arm), the crate
and site it lands in, and the witness. "slice 9" is the alt increment
(PR-a, §5), "slice 10" the pool increment (PR-b).

| Row | Rule (short) | Disposition | Crate / site | Witness |
| --- | --- | --- | --- | --- |
| CEN-K1a | alt-chain derived height ≥ 1 | by construction — `AltChain`'s root is a main-chain row, so the candidate's derived height is `root + 1 + len` ≥ 1 | `shekyl-chain-store` `AltChain::candidate_height` (slice 9 a3, landed 2026-10-11) | a candidate whose `prev_id` is unknown is K2, not K1a; the constructor test is `a_chain_through_two_alt_entries_reaches_a_recorded_row` (`store/alt_view_tests.rs`: every chain built, including the one over genesis, sits at ≥ 1 — the one over genesis at exactly 1). The census arm is a4's (§5). UPDATE 2026-10-11 (a4 census arms): registry `held_by_store("shekyl-chain-store", "a_chain_through_two_alt_entries_reaches_a_recorded_row")` (`E5-18`) |
| CEN-K1b | a miner-tx claiming height 0 is refused | rule in `alt_against` — the claim read against the derived height, `Locus::Block` | `shekyl-chain-rules` `rules/alt` (slice 9) | mutation: a height-0 claim at derived height ≥ 1 refused. UPDATE 2026-10-11 (a4 census arms): registry `enforced_at(crate::rules::alt::K1b, "a_height_zero_claim_is_refused_before_anything_is_read")` — not per block, the alt tier's |
| CEN-K2 | alt linkage: the chain must connect to the main chain | by construction — `AltChain::build(snapshot, prev_id)` returns `Err(AltCannot::Unlinked { at })` and no view exists; each row's recorded height is held to the height its position derives (the C++ rebuild's assertion), a disagreement SI-7 | store `AltChain::build` (slice 9 a3, landed 2026-10-11) | `the_orphan_is_unlinked_at_the_first_unheld_hash` (the orphan, named at the first unheld hash — also on an empty store); `a_chain_through_two_alt_entries_reaches_a_recorded_row`; `a_row_whose_height_disagrees_with_its_chain_is_si7` (`store/alt_view_tests.rs`). The census arm is a4's (§5). UPDATE 2026-10-11 (a4 census arms): registry `held_by_store("shekyl-chain-store", "the_orphan_is_unlinked_at_the_first_unheld_hash")` (`E5-18`) |
| CEN-K3 | an alt block already stored is refused | by construction — AL1 `AlreadyHeld` (the belt E1 landed) | store `alt.rs` (landed) | the existing AL1 test. UPDATE 2026-10-11 (a4 census arms): the census arm flips to `held_by_store("shekyl-chain-store", "insert_of_a_held_hash_and_remove_of_an_absent_one_are_refusals")`, not `by_construction` (`E5-18`: the construction is the store's) |
| CEN-K4 | alt blocks stored after version, timestamp, checkpoint, PoW | rule — `alt_against` is the tier; what it holds is the row; no attestation step (`E5-Q4` β — B4's bond read is chain state, promotion's; the C++ ladder's step is frozen, `DEL-009`) | rules `alt_against` (slice 9) | each sub-check mutated once; the order pinned. UPDATE 2026-10-11 (a4 census arms): `rules::alt::K4` is a marker rule with no predicate, recorded by `alt_against` after the last header predicate (an `AltValid` carries it iff every step ran); registry `enforced_at(crate::rules::alt::K4, "the_cheap_tier_evaluates_the_header_ladder_and_the_alt_arms_and_nothing_else")` — the row-set pin is the test, `the_fork_is_judged_before_the_header_ladder` the order's |
| CEN-K5 | promotion re-validates every block through the full validator | sequencing — step 4 of §2.3 is `validate` + `connect`, nothing else connects | `shekyl-chain-ingest` switch (slice 9) | an alt chain carrying a body `validate` refuses leaves the store at the pre-switch digest Built (switch PR): `switch.rs` `switch`; held by `shekyl-chain-ingest`, test `a_promoted_block_that_fails_validate_rolls_back_and_removes_its_suffix`. |
| CEN-K5b | each promoted block's attestation witness travels and is checked | sequencing — the witness is in `AltBlock`; `validate`'s attestation rule reads it | ingest switch + `AltBlock` (slice 9) | a tampered witness on an alt entry fails promotion. UPDATE 2026-10-11 (Slice C bundle redesign, §2.3): the alt row carries bundle **references**, not the witness; the bodies are fetched before the closure and the bundle verifier runs inside it over `BatchView` — the witness cell becomes "a body that does not hash to its reference stops the switch before the closure; an invalid bundle fails it inside" (a5) Built (switch PR) with the bundle legs out (§2.3): the alt row keeps the witness; `switch` refuses a formed block whose witness is not its row's; test `a_tampered_witness_on_an_alt_row_fails_promotion_k5b` (CEN-B4 refuses a planted witness). |
| CEN-K6 | switch iff alt cumulative difficulty strictly greater (checkpoint forces) | rule — `fork_choice`'s verdict matched; the crossing is Q1b's | `shekyl-difficulty` (landed) + ingest match (slice 9) | equal keeps; greater switches; checkpoint-forced promotes a lighter chain Built (switch PR): the match in `switch.rs` (`offer`, re-derived in `switch`); test `a_heavier_branch_switches_and_equals_the_branch_connected_directly`; the checkpoint arm in `a_checkpoint_forced_switch_discards_the_demoted_chain`, reachable once CEN-E2 floors on the last anchor the tip has reached. |
| CEN-K7 | demoted blocks re-enter as alt blocks; discard on checkpoint-forced | sequencing — step 3 under the verdict's arm (`E5-12`) | ingest switch (slice 9) | after a switch AL7 lists the demoted blocks; after a forced switch it does not Built (switch PR): the demoted rows from the tier's verdicts on the `Switch` arm, none on `ForcedSwitch` (AL6 = 0); a refusal of a recorded block is SI-27, by ruling (§2.3), not the C++'s log-and-continue; test `a_checkpoint_forced_switch_discards_the_demoted_chain`. |
| CEN-K8 | alt `already_generated_coins` is bookkeeping, not a consensus read | held by store — the alt row carries no supply word (a4, `SCHEMA_VERSION` 24, §2.1); the row's layout is the witness, pinned by `codec::alt_tests::an_alt_row_has_no_supply_word` | store `codec/alt.rs` (landed a4) | UPDATE 2026-10-11: the field is deleted; the a2 witness below (the view's type) stands and is no longer the only one; the registry flips `pending` → `held_by_store` in the census-arms commit (`E5-18`). UPDATE 2026-10-10: Round 0's witness (`rg coins_generated rust/shekyl-chain-rules/` → 0) was wrong at the pin — `RecordedBlock.coins_generated` is F13's operand (`view.rs:177`, `miner.rs:469`). The witness is the type: `rg 'coins_generated' rust/shekyl-chain-rules/src/view.rs` names only `RecordedBlock`'s field, never `HeaderRecord`'s, and `AltView` implements `HeaderView` only |
| CEN-K9 | supplement txs must pass NIC or the block is rejected | sequencing — `form` judges every listed body on its bytes at its slot before the cheap tier runs, so a body that fails NIC refuses the alternative there; AL1 stores the bodies beside the row and the switch promotes from them (§2.2, the review of #1102 B1, 2026-10-17); the pool is offered them for relay only | store + ingest (slice 10) | an alternative listing a body below the floor, one the main branch mined and one held in stem is promoted with the pool file discarded; a demoted body the door refused is promoted on a switch back |
| CEN-K10 | `kept_by_block` admission skips policy, keeps consensus | writer behaviour — the returned transaction runs the **whole** door, `policy_form` included; `fcmp_cache` consulted (`E5-11`); what `kept_by_block` keeps is the retention — a returned transaction that cannot currently be verified stays, not relayable, until M10 evicts it. UPDATE 2026-10-11 (`E5-Q1` reopened in part, §8): *was* "`policy_form` skipped, `tx_form`/`tx_against` not" — the policy skip was the fee-floor bypass for block-carried transactions (C2-R2 Q9's 2026-10-02 reopening names it a bug), and with the carriers gone no family needs it | `shekyl-mempool` (slice 10) | a below-floor demoted tx is refused by the same door that refuses it on relay; a returned tx that cannot be verified is kept and never relayed, and M10 evicts it. *Was:* "a zero-fee demoted tx is admitted and not relayed (M11)". **Requirement (2026-10-11, subject-neutral):** a pop must not strand serve-credit evidence on the nodes that connected the popped block. What the evidence is, the mechanism that re-includes it, and which store holds it across the pop are Slice C's (under its direction the evidence may not be a pool transaction at all); K10 builds the pool's half of the pop's return path and no evidence-specific admission. The frozen C++'s behaviour — a popped zero-fee entry kept under `kept_by_block` past the ordinary lifetime, never relayed, re-mined only by a node that held it — is read in FOLLOWUPS ("A popped serve-credit carrier survives the C++ pool's pop path") as evidence for that round, not as a shape this row inherits |
| CEN-D5 | alt-chain difficulty: the same LWMA-1 over the stitched window | rule — D4 over `AltView::header_at` (the subsumption `census.rs:353` wrote; `block_at` → `header_at` per `E5-13`) | rules `difficulty.rs` bound on `HeaderView` (slice 9) | a fixture drives D4 over a stitched view and over the main chain to the same target when the branches agree, different when they do not. UPDATE 2026-10-11 (a4 census arms): the site is `rules::alt::D5::target` wrapping `D4::target` (D4 records its own row); registry `enforced_at(crate::rules::alt::D5, "the_alt_target_follows_the_window_it_is_fed")` — recorded at the one site that feeds D4 an alt view, not per block |
| CEN-E2 | an alt block at or below the last anchor is refused | rule in `alt_against` — `anchors.rs`'s E2 arm given its alt home | rules `anchors.rs` (slice 9) | a candidate forking below the anchor floor refused; above it admitted. UPDATE 2026-10-11 (a4 census arms): the site is `rules::alt::E2::check` (both bands over `Fork`, the cap through `RuleSet::reorg_cap()`); registry `enforced_at(crate::rules::alt::E2, "an_alternative_rooted_below_the_anchor_is_refused_and_one_at_or_above_it_is_not")` — the main chain satisfies both bands by construction, so the row is the alt tier's alone |
| CEN-M1 | a tx already in the pool or on chain is refused | rule — `has_transaction` through `PoolView` (chain) and the pool's own set | `shekyl-mempool` (slice 10) | duplicate refused, the held entry unchanged |
| CEN-M2 | pool admission runs the full NIC set | rule — `tx_form(TxSlot::Lone)` is the set | rules (landed) + mempool call (slice 10) | one NIC mutation refused at the door |
| CEN-M3 | relay fee floor | rule — `policy_form`, `PolicyRow`; **no exemption** — the door is one for relayed and returned transactions alike (`E5-Q1` reopened in part 2026-10-11, §2.2), and with the serve-credit carriers gone (§2.2's redesign) there is no zero-fee family to carve out | rules `AdmissionPolicy` (slice 10) | below-floor refused, on relay and on return from a popped block. *Was* (2026-10-10): "admitted under `kept_by_block`" |
| CEN-M4 | relay cap on `tx.extra` | rule — `policy_form` | rules (slice 10) | mutation at the cap |
| CEN-M5 | relay ban on nonzero `unlock_time` | rule — `policy_form`; `kept_by_block` exempt | rules (slice 10) | nonzero refused for relay |
| CEN-M6 | relay-side double-spend pre-check against the chain | rule — `tx_against`'s I7 through `PoolView.chain` | rules (landed) + decorator (slice 10) | a chain-spent key image refused |
| CEN-M7 | pool-side key-image conflict tracking | rule — the same I7 through `PoolView.pool_key_images`; the map is the pool's | mempool (slice 10) | two pool txs on one key image: second refused, the first unchanged |
| CEN-M8 | FCMP++ verification cache | writer behaviour — the door's `StatelessPass`, held in memory beside each entry and reused while the transaction's rule set and claim hold, so the bytes are judged once per process (the review of #1102, S1) | mempool (slice 10) | a connect under the pool verifies no signature, range proof or FCMP++ proof again; an open verifies afresh |
| CEN-M9 | engine-attested local submit | writer behaviour — the submit engine's trait impl swapped (§1.6's planned reversion); `retention_vin`'s second spelling deleted | `shekyl-daemon-rpc` + mempool (slice 10) | `rg -n 'fn retention_vin' rust/` → one site |
| CEN-M10 | pool lifetime / eviction | writer behaviour — the limits derive from the chain: `REFERENCE_BLOCK_MAX_AGE` blocks at the block weight limit for the pool, the reorg cap's blocks of it for kept entries, kept for the reorg cap's blocks; an admitted entry leaves when its reference leaves CEN-I11's window; the bound holds at admission, kept entries first, then the cheapest admitted, a rising minimum refused before the door (the review of #1102, B3) | mempool (slice 10) | the genesis limits; a kept entry gone the cap's blocks after its return; a full pool refuses at or below its cheapest and evicts the cheapest for a better payer in one write; kept before admitted; an entry gone when its reference leaves the window |
| CEN-M11 | zero-fee txs never flagged for relay | **DELETED (2026-10-11)** — redundant with M3: a zero-fee transaction is below any fee floor, so M3 refuses it at the one door and nothing reaches relay to be flagged; two mechanisms for one job (`05-system-thinking.mdc`). The row existed for the zero-fee carrier family, which the Slice C bundle redesign removes (§2.2). b1 retires the census row and the `PolicyRow` entry (policy denominator `9 → 8`, `check_chain_rules_coverage.py`'s figure moves with the census). *Was* (2026-10-10): "rule — `policy_form`'s relay flag; `Readiness` never reaches relay" | — (b1 deletes) | the `PolicyRow` registry has no `M11`; `rg -n 'M11' rust/shekyl-chain-rules/src/census.rs` → 0. *Was:* "zero-fee admitted under `kept_by_block`, never relayed" |

Expected gate movement (written now, before measurement — slice 7 §5.1's
rule): consensus `implemented 118 / validator-enforced 151` → `130 / 151`
with K3, K8 and K1a, K2 leaving `pending` as `by_construction`
(`by-construction 16 → 20`) and K1b, K4, K5, K5b, K6, K7, K9, K10, D5, E2,
M2, M8 as `implemented` (+12 — K5/K5b/K7/K9/K10 are sequencing rows whose
census arm names the switch's or the door's test); policy `0 / 9` → `9 / 9`.
If the measured movement differs, the difference is a finding.

**Measured 2026-10-11 (a4 census-arms commit, `check_chain_rules_coverage.py`
on the branch at `dev` `834471689`):** consensus `implemented 118 / 151` →
**`126 / 151`**, `at-open 1 → 5`, `by-construction 16` (unchanged),
`held-by-store 0 → 4`, `enforced 153` (unchanged); policy `0 / 9`
(unchanged). The difference from the projection is three findings, none a
regression:

- **The projection counted slice 10's rows.** K5, K5b, K6, K7, K9, K10,
  M2, M8 and policy's nine are the switch's and the pool door's (PR-b);
  a4 flips no row it did not build. `+8`, not `+12 + 4`: K1b, K4, D5, E2
  and K1a, K2, K3, K8. The projection line should have been split by
  increment; it was not, and the split is recorded here rather than
  rewritten there.
- **`by_construction` was the wrong form for the store's four** — `E5-18`;
  `held-by-store` moves instead of `by-construction`. Same `implemented`
  count, a different column, and a status the gate checks in the holder
  crate rather than this one.
- **The alt tier's four are `enforced_at`, not `implemented`.** The
  projection wrote `implemented` for K1b, K4, D5, E2; `implemented` is the
  per-block form (`RuleSet::enforced` counts it toward
  `Coverage::is_complete_for`), and `validate` never runs the tier. So
  the per-block denominator fell `E − 19 → E − 27` while `implemented`
  rose — the reading the gate prints as `at-open` exists for exactly this.

**Measured 2026-10-17 (PR-b, `check_chain_rules_coverage.py` on
`feat/drs-e5-pool-prb`):** consensus `implemented 139 / 161` → **`143 /
161`** — M2, M8, K9, K10 `held_by_store`, cited at the tests in
`shekyl-chain-ingest` that witness them (`held-by-store 9 → 13`); policy
`0 / 9` → **`8 / 8`** — M11 deleted (`9 → 8`), M3, M4, M5 `implemented`
(`policy_form`), M1, M6, M7, M9, M10 `held_by_store`. The slice-10 half of
the 2026-10-11 projection was `+4` consensus and `9 / 9` policy; the
policy denominator is the one difference, and it is M11's deletion, which
the projection preceded.

---

## 4. What this round does not do, and what it braces against

Not done here: no code; no FOLLOWUPS row; no change to the census document
(its 4.K/4.M/D5/E2 rows are re-pinned by the landing commits, never by the
posing). The appendix items (§9) are findings outside the lane, recorded for
whoever owns them.

Adversarial items, each with the fixture that would notice:

- **Reorg across a settlement boundary.** `reorg.rs:70` asserts
  `SETTLEMENT_EPOCH_BLOCKS > D_MAX`, so a switch within the cap crosses at
  most one close. E4 dissolved the revert logs into `undo_log`, so `pop`
  reverses the close (SI-25's fold included) — the claim is E4's, and this
  round does not inherit it as a property (`16-architectural-inheritance.mdc`,
  "a claim is not the code"). Fixture: a chain of `epoch + 1` blocks, a
  switch popping back across the close, the digest after re-connecting the
  original blocks equal to the never-switched digest (the E2 oracle's
  shape); the settlement writer's `SO-D10` family is the comparison
  (`ARCHIVAL_SETTLEMENT_WRITER.md`).
- **Reorg across the prune floor.** `PopBelowFloor` (`pop.rs:113`) is F-1's
  fail-stop; in the switch it must surface as a *local* refusal (the node
  cannot follow) and never as a verdict against the alt block (C2-R1 Q1c
  F-1(a); `blockchain.cpp:1046–1052` is the C++'s statement of the same).
  Fixture: an alt chain forking below `undo_floor`; the alt block stays in
  the alt table, the main chain is unchanged, no peer-facing refusal is
  emitted. The up-front cap check (`E5-Q6`) means the floor belt is reached
  only when the floor sits *above* `tip − reorg_cap` — which is the prune
  having advanced past the cap, SI-6's state — so the fixture also asserts
  the two refusals are distinguishable.
- **The pruned-row asymmetry (`E5-9`).** Not reachable within the cap. The
  fixture is a `const` assertion that already exists (`reorg.rs:70`) plus
  one test: a reorg to `tip − D_max` re-runs the settlement gather and reads
  no row below `undo_floor`. If either constant moves, the fixture, not a
  reorg, is what fails.
- **Alt-block flooding.** The cheap tier's cost floor is K4's PoW; the C++
  has no count or age bound on alt storage and drops the table at open
  (SAL-8). Default (`E5-Q7`): inherit — PoW is the bound, `drop_alt_blocks`
  at open is the lifetime, AL6 is the metric. Rejected-with-reopen (rule 21):
  a count cap re-enters when a stressnet measurement of AL6 under adversarial
  mining shows storage growth the PoW cost does not bound. Fixture: a
  stressnet run recording AL6 over time; the number is the reopen's
  evidence either way.
- **K10 `verification_impossible`.** A demoted block's transaction may
  reference a tree root the pops just removed. Under FCMP++ the reference is
  to a root by height (`root_at`), and after a pop the root at that height
  is the alt chain's — the transaction is not *invalid*, it is
  *unverifiable against the new chain* until re-built against a new root.
  The C++ returns such transactions to the pool and lets them age out. Rust:
  the returned transaction runs the whole door (§2.2); when the chain-bound
  half refuses it — its reference is not on the new chain (CEN-I10) or has
  aged out of the window (CEN-I11) — the pool keeps it as
  `Standing::Kept`, never relayed and never selected, and M10 evicts it. A
  stateless or policy refusal is refused outright, as it is on relay.
  Fixture: the demoted tx is in P7 after the switch and not in any
  template.
- **The cheap tier's wrong-chain archival read (`E5-6`) — dissolved.** No
  fixture: the Rust cheap tier makes no chain-state read (`E5-Q4` β), and
  the read exists only in the frozen C++ alt path (`DEL-009`). What is
  testable is K5b's row (§3): a tampered witness on an alt entry fails
  promotion.
- **A `PoolView` that reaches `connect`.** Negative control: a test that
  tries `connect(validate(.., &pool_view, ..))` and does not compile — as
  a `trybuild` program beside a2's brand pins (`tests/trybuild/`), not a
  `compile_fail` doctest: its stub can drift, and a2 found the two
  `validate` doctests green on E0046 for eleven days (`CHAIN_RULES_CRATE.md`
  §8.3). `AdmissionPolicyId`'s existing pin has no stub and stays a doctest.

---

## 5. Commit plan — Round 0 (proposed), two increments; PR-a cut in two 2026-10-12

Two increments, matching REDB table 3's slices. **PR-a — slice 9 (alt,
switch; 4.K less K9/K10, D5, E2).** **PR-b — slice 10 (pool; 4.M, K9,
K10).** K9 and K10 are STAGED out of PR-a with their consumer named (rule
23): they are pool rows, and PR-a has no pool. The order is a question
(`E5-Q10`): the default is a-then-b because the switch's pool returns are
the only thing PR-a cannot test without PR-b, and PR-a can land them as a
`Vec<Transaction>` the caller drops, with PR-b the caller.

**UPDATE 2026-10-12 — PR-a lands as two PRs (maintainer).** PR #1026 is
**cut at a4**: it carries a1–a4 and the Slice C
transport-handoff docs (§2.2, §2.3, the 2026-10-11 rows below) and goes to
review, so this file's rulings — the cheap-tier rule, the `E5-Q4`
dissolution, the transport handoff — land on `dev` as a file the Slice C
round can cite. **a5–a8 are the switch PR**: the closure (a5), the refusals
and fixtures (a6), the reorg capture (a7) and its docs (a8), cut from `dev`
after #1026 merges. Where this file says "PR-a" of the switch's work — the
`Vec<Transaction>` return and its single caller (`E5-Q2`, `E5-Q10`), the
DRS-X cutover's trigger (§7), SAL-13/14's carried-and-built flip — it names
the switch PR. Bundle transport (O1, O2, B10) and the template's bundle section are SO-D12's (2026-10-16), built with the bundle section on the block wire and `drawable_epoch`'s data source (`ARCHIVAL_SETTLEMENT_WRITER.md` §16.3 items 2 and 3). **The switch PR
is split (maintainer, 2026-10-15):** a5 without the bundle legs, a6, a8;
a7 withdrawn (`E5-Q9`); the bundle legs land with SO-D12's merged increment
(§2.3).

| # | commit | cost | falsifier applies |
| --- | --- | --- | --- |
| a1 | this file on review; index rows; the §12 register rows (DEL-009, DEL-010). UPDATE 2026-10-10: Round 1's rulings recorded; the `header.rs` partition measured (`E5-13…E5-15`); `E5-Q4` priced | 1 | — |
| a2 | `HeaderView { tip, header_at }` + `HeaderRecord` (`E5-13`); `HeaderRule` with the blanket `BlockRule` impl; `anchors.rs`, `timestamps.rs`, `pow.rs`, `difficulty.rs`, `attestation.rs` re-bounded (`E5-14` — not `header.rs`); `BatchView` and the eight test implementors gain `HeaderView`; `check_block_rule_corrupt_sites.py` reads both impl forms; the store's conformance suite split. UPDATE 2026-10-10: landed as measured — `HeaderRecord { hash, header, cumulative_difficulty }` embedded in `RecordedBlock` (`E5-13`, no `Deref`); `HeaderView { tip, header_at }` with `ChainView: HeaderView` (`E5-14`); D1, C1, C2, E1 are `HeaderRule`s under `impl<R: HeaderRule> BlockRule for R`, the window and seed helpers (`C3::window`, `mtp_median_at`, `D4::target`, `D3::expected_seed`, `E5::conflict_with`, `anchor_window`) bound on `HeaderView`; `recorded_header` lifts a hole to `Corrupt::HoleBelowTip { record: PerHeightRecord::Header }`; the gate **derives** the rule-trait set from the blanket impl and refuses a rule-shaped `check` under a trait it cannot reach (15 rules read: 11 + 4; the user's three probes red on D1). The falsifier did not fire: five rule files, the blanket impl composes with `run`. Beside it, a wrong-subject finding: `validate.rs`'s two brand `compile_fail` doctests had passed since `5fb2132fa` (2026-09-29) on E0046 — the stubs no longer implemented `ChainView` — not at `connect`; replaced by a `trybuild` suite with stderr snapshots and a positive control (`CHAIN_RULES_CRATE.md` §8.3) | 2 | yes — more than these five rule files, or the blanket impl not composing with `run`, is the fallback |
| a3 | `AltChain::build` (K2), `AltView` over `ReadSnapshot` + chain (`HeaderView` only), K1a by construction, the stitched-view conformance test. UPDATE 2026-10-11: landed as specified — `store/alt_view.rs`: `AltChain::build(&ReadSnapshot, &prev_id)` walks `previous` from the parent (recorded hash → root, alt row → entry, neither → `AltCannot::Unlinked { at }`, the new refusal variant), then holds each entry's recorded height to `root + 1 + i` (the C++ rebuild's assertion; a disagreement is SI-7 under `alt_blocks`, reason `alt block's recorded height disagrees with its chain`); `AltView<'s>` implements `HeaderView` and nothing else — `header_at` is `chain_reads::block_body` at or below the root (one body with `BatchView`) and the entry's `{ hash, header, cumulative_difficulty }` above, `tip` the parent; `candidate_height() = parent + 1 ≥ 1` (K1a). Four tests in `store/alt_view_tests.rs`, including the stitched-view conformance test against `BatchView::header_at` below the fork with the negative control that the recorded reader still answers `main[2]` where the view answers `a`; the height check was mutation-tested (disabled → the SI-7 test fails). Finding `E5-18`: the census registry's `by_construction` form cannot name a store-homed property or credit a store-crate falsifier, so K1a/K2 stay `pending` in `census.rs` until a4's census-arms commit chooses the form | 2 | yes |
| a4 | **first commit, ruled before it lands:** the census amendment (`CONSENSUS_RULE_CENSUS.md`; the registry entry is unchanged) — CEN-K4's row stops describing a ladder the Rust tier will not run: the C++ ladder is recorded in its landed order (version, timestamp, checkpoint, PoW, then attestation since `4932b769b`, 2026-09-13, then prevalidate) as the frozen path `DEL-009` retires, and the Rust tier's steps name no attestation step (`E5-Q4` β); CEN-B4's site pin re-pinned to `verify_block_attestation` 4979–5066 (signature to closing brace; `:4978` is the separator comment). **Then** `alt_against` (K1b, K4's tier, D5 via D4, E2's arm); `AltValid` → AL1; census arms. The `docs/FOLLOWUPS.md` rows *"Alt-chain attestation verify resolves bond pubkeys from main-chain state"* and *"Validate `prev_id` before attestation verify on the alt-chain path"* were closed with the ruling (2026-10-11), not by this commit. UPDATE 2026-10-11: `alt_against` landed (`alt.rs`, `rules/alt.rs`; §2.1 has the ladder): K1b a `FormRule` run before any header read; E2 a two-band function over `Fork { root, recorded_tip }`, the cap read from `RuleSet::reorg_cap` and binding only when anchored; D5 wrapping `D4::target`; F4/F5/F6 re-bound `HeaderRule` (`E5-14` amended: six files, 15 rules = 8 + 7); `AltValid` with no supply field; twelve tests, the row set pinned. Registry entries unchanged in this commit — K1b/E2/D5/K4 flip to `enforced_at` in the census-arms commit, with K1a/K2/K3 (`held_by_store`, `E5-18`) and K8. UPDATE 2026-10-11 (second commit): the alt row loses its supply word — `coins_generated` deleted from `AltBlock`/`AltBlockFacts`, `SCHEMA_VERSION` 22 → 23 (24 after the `dev` merge; §10, 2026-10-12), `alt_block.snap` re-pinned, layout pin `an_alt_row_has_no_supply_word`, the FOLLOWUPS supply-accumulation row closed (§2.1 "K8"). UPDATE 2026-10-11 (third commit): `AltValid` → AL1 — `insert_alt_block(&self, AltValid)`; the row from the verdict (`AltBlock::admitted`, infallible; key = `AltValid::hash`, CEN-B6); `AltCannot::IdentityMismatch` deleted with its producer; `AltChain` reads the recorded tip first (an empty store: `Unlinked` before any walk) and offers `fork()`; the store's alt tests admit rows through `form` + `alt_against` over the stitched `AltView` and plant only what the tier would never write (SI-7, the orphan); `connect_fixtures::{formed, expected_seed}` widened to `HeaderView`. No layout change. Two questions handed to a5 and written at §1.1: demotion re-entry's constructor, and SAL-Q4's `Option`. UPDATE 2026-10-11 (fourth commit, census arms): `E5-18` ruled `held_by_store(crate, test)` — `RowStatus::HeldByStore`, the registry macro arms, `check_chain_rules_coverage.py`'s `check_held_by_store` (holder a workspace crate other than the rules crate; the `#[test]` defined in it) and its `held-by-store` figure; `rules::alt::K4` the marker rule the tier records when its ladder ends (`ALT_TIER_ROWS` 16 → 17); eight registry flips — K1b, K4, D5, E2 `enforced_at`, K1a, K2, K3, K8 `held_by_store`; `RuleSet::enforced` and every status match site widened; the census rows D5, E2, K1a, K1b, K2, K3 carry their Rust sites (K1b's C++ pin `2153–2158` → `1982–1988`, K1a's `:1449` → `:1209`/`:1244`); measured `implemented 118 → 126 / 151` (§3, the three findings against the projection). CEN-K4's order and CEN-B4's re-pin landed in this row's first commit (`9294c1083`), as the row records. UPDATE 2026-10-12: the header ladder is three segments shared with `validate` (A2; C1, C2, D1; E1, F4, F5, F6), and `validate` inserts B5, B4 and G1 between them. D5 records only when derivation produced a target. `AltValid` is branded to the view type (`insert_alt_block` takes `AltValid<'_, AltView<'_>>`). `Fork::new` refuses an inverted pair. SAL-Q4's `Option` is deleted in the same unreleased layout, 24 (weight mandatory; zero refused); demotion re-entry's constructor remains a5's | 3 | yes |
| a5 | the switch closure in `shekyl-chain-ingest` (§2.3): the cap before anything else (`E5-Q6`); the M alt entries re-formed off the actor, and the N demoted blocks only when the verdict is not ForcedSwitch; SAL-13 — each demoted block the plan formed judged by the cheap tier over a pre-closure `ReadSnapshot` and inserted from its verdict, no demotion constructor, a refusal SI-27; pops; SI-5 over the tree the pops left; K7 under the verdict arm (`ForcedSwitch`, `E5-Q5`, the C++ shim beside it); K5 promotion through the full `validate`, K5b's witness in the alt row; removes; `Switched` and the demoted `Vec<Transaction>`, dropped by its one caller until PR-b (`E5-Q10`). Not this row's: the bundle legs (SO-D12's merged increment, §2.3) and the arrival router's other arms — the orphan (`AltCannot::Unlinked` as the reply, nothing stored) and already-held — which the DRS-X Round 0 designs with A1/A4's Rust holder Landed in the switch PR: `shekyl-chain-ingest/src/switch.rs` (`OfferAlt` → `SwitchPlan`, `Reorganize`); store reads `candidate_at` and `table_rows`; SI-5 (`store/edge.rs`) and SI-27 built; `ForcedSwitch` with the C++ shim as a same-line edit; CEN-E2's floor read at or below the recorded tip (the decision log's 2026-10-15 rows). | 4 | yes |
| a6 | the three refusals distinguished — the cap (local, before any pop, `PopBeyondReorgCap`), the floor (`StoreCannot::PopBelowFloor`, F-1 fail-stop), the verdict (a promoted block refused: the transaction rolls back, the main chain stays, the failing alt suffix is removed) — with §4's boundary and floor fixtures; SI-5's mutation control; the Rust self-differential that replaces a7 (`E5-Q9`): the digest after A then a switch to B equals the digest of B connected directly, A carrying a validating user spend, at the cap depth and at a shallow depth, one corrupted undo row as the mutation control; the cap-depth switch timed, coinbase-only and with spends, each figure with its basis Landed in the switch PR: fourteen switch tests and three ignored timing tests (`switch_timing_tests.rs`); the measured switch at the genesis cap is in the decision log's 2026-10-15 measurement row. | 3 | yes |
| a7 | withdrawn (`E5-Q9`, 2026-10-15): no C++ capture; a6's self-differential is the switch's oracle | — | — |
| a8 | docs: census K5, K5b, K6, K7 carry their Rust sites and the registry flips with them; D5/E2 re-pinned; `DRS_E1_SALT.md` SAL-13/14 carried-and-built; DEL-009's trigger restated at the store flip (the DRS-X Round 0); SI-5 and SI-27 `built` in the register; FOLLOWUPS' reorg-around-a-spend row's falsifier amended; index; CHANGELOG | 1 | yes |
| b1 | `shekyl-mempool` crate, its `//!` doc stating `E5-Q2`'s never-a-rule condition; `PoolView` decorator (`has_key_image` = chain ∨ pool, every other read delegates) with its `compile_fail` negative control; `policy_form` and the `PolicyRow`s M3, M4, M5 in the rules crate, `PolicyCoverage` populated; **M11 deleted** with its census row (policy `0 / 9 → 0 / 8`; redundant with M3, §3). The first commit of the PR is the record's design commit ahead of it: `PoolRecord` carries `public: bool` and a standing, `Responsibility` moves to `shekyl-relay` keyed by transaction hash (DX-F6, §2.2), `SCHEMA_VERSION` 27 | 2 | yes |
| b2 | admission (M1, M2, M6, M7) through the door (§2.2): `judge_slot_stateless` public and shared with `form`, at `TxSlot::Lone` with claims from the pool's tip snapshot (H19 verified there as a batch of one), then `tx_against(Lone)` over `PoolView`, then `policy_form`; the key-image conflict map; P1–P3 after the chain's `Ok`; M3 for every transaction, returned ones included | 3 | yes |
| b3 | the relay interface: the public bit, set only by the relay's fluff event; a non-public transaction absent from the listing, peer sync and the template (D++ acceptance criterion 2); M9 — the submit engine's `SubmitStateShim` over the Rust pool prepared, not routed; `retention_vin`'s second spelling deleted | 3 | yes |
| b4 | M8 cache (the `(reference hash, height, root)` triple; `E5-Q8` stands — no seeding), M10 eviction, K10 returns and K9 supplement: `SwitchDone::returned` gets its caller — a returned transaction runs the whole door, policy included; one the chain-bound half refuses is kept, not relayable, never selected, and evicted by M10 | 2 | yes |
| b5 | reconcile at open (`E5-8`) — one function, called at open and reused by the door; the pool file stays discardable | 1 | yes |
| b6 | template selection from P7 (`fill_block_template`'s successor) as a pure function: each selected transaction re-runs `tx_against(Lone)` against the template's parent; a transaction whose reference has aged out is not selected, and M10 evicts it. No bundle section (SO-D12's) | 2 | yes |
| b7 | docs: census 4.M re-pinned (CEN-M11 retired, K9/K10 Rust sites); `DRS_E1_SPOOL.md` SPL-7/`SPL-Q5` built; `DAEMON_SUBMIT_VERDICT.md` §11 row marked prepared; FOLLOWUPS rows closed; index; CHANGELOG | 1 | yes |

**Expectation: fifteen commits, 8 + 7, costs 17 + 15** (2026-10-11; *was*
16 + 14 before the Slice C bundle redesign raised a5 and b1 by one each —
estimates revised before landing, not overruns). **Across three PRs since
the 2026-10-12 cut: #1026 a1–a4 (cost 8 = 1 + 2 + 2 + 3, no overrun
written on any row), the switch PR a5, a6, a8 (cost 8 since the 2026-10-15 split), PR-b b1–b7 (cost
14 since the bundle work left it for SO-D12, 2026-10-16).** Every commit after a1/b1 carries the falsifier: if a landed cost
exceeds its estimate the overrun is written into the row as a finding,
not absorbed (slice 7 §5.1). Each PR is under the rule-06 ceiling.

---

## 6. Documentation owed (rule 91)

At each increment's last commit: `CONSENSUS_RULE_CENSUS.md` 4.K / 4.M / D5
/ E2 rows gain their `Rust (E5 slice n row m, date)` clauses;
`DRS_E1_SALT.md` and `DRS_E1_SPOOL.md` flip their carried items;
`CHAIN_RULES_CRATE.md`'s four `PoolView` mentions point at the type;
`store/view.rs:19–20`'s reservation becomes a reference;
`DAEMON_REDB_STORE.md` table 3's two E5 rows and §12's DEL-009/DEL-010
statuses; `IMPLEMENTATION_INDEX.md` §2 and §7; `docs/FOLLOWUPS.md:800`
removed when b3 lands; `CHANGELOG.md` for the user-visible deltas (the
mempool, the alt-block admission semantics, the removed `--keep-alt-blocks`
flag). This file: archive-or-contract at PR-b's close — it is a plan, so it
moves to `docs/completed/` with inbound links repaired.

---

## 7. The two deletions, the register, and the denominator

**The register is the register.** Rule 94 persists identifier families and
dispositions in one place so the next reader does not reconstruct them from
plan prose; `DAEMON_REDB_STORE.md` §12 is where every cutover deletion since
`DEL-001` lives, and `DEL-008` — the archival path — is this class's
precedent. E5's §3 table is a *plan*: it is archived when the work lands
(rule 95), and an archived table is exactly the place a deletion goes to be
forgotten. So the rows are minted **in §12**, in this commit, with `Planned`
status; E5's table points at them. The argument the other way — "E5's table
is the register for E5's deletions" — fails rule 94 twice: the table is not
indexed by the family the register is indexed by, and it does not survive
the plan's closure.

- **DEL-009 — the C++ reorg path.** `blockchain.cpp`:
  `handle_alternative_block` (`:1974`), `build_alt_chain` (`:1913`),
  `switch_to_alternative_blockchain` (`:1029`),
  `rollback_blockchain_switching` (`:980`), `pop_block_from_blockchain`
  (`:597`); the alt LMDB operations (`add_alt_block`, `remove_alt_block`,
  `get_alt_block`, `drop_alt_blocks` and their `blockchain_db` pure
  virtuals); the `--keep-alt-blocks` flag and its `core::init` arm
  (`cryptonote_core.cpp:185`, `:650`); the two FFI exports
  `shekyl_difficulty_fork_choice` and `shekyl_difficulty_alt_window_plan`,
  whose only callers are here. Trigger: the store flip — the DRS-X
  cutover PR the DRS-X Round 0 designs, which deletes the C++ reorg path;
  not the switch PR, which builds the Rust one beside it (the C++ shim
  for `ForcedSwitch` at `blockchain.cpp:2323` dies with it).
  Falsifier: `git grep -E 'rollback_blockchain_switching|switch_to_alternative_blockchain|handle_alternative_block|build_alt_chain' src/`
  → 0 (SAL-14's, widened); `rg 'shekyl_difficulty_(fork_choice|alt_window_plan)' src/`
  → 0 while the Rust symbols are read natively.
- **DEL-010 — the C++ mempool.** `tx_pool.cpp` whole (`add_tx` `:269`,
  `fill_block_template` `:2077`, the relay FSM, the key-image map);
  `flush_txes_from_pool` (`blockchain.cpp:5067`); the `FfiSubmitShim` trait
  impl in `shekyl-daemon-rpc/src/submit/` (the §11 reversion executed, not
  a deletion of the engine). `retention_vin`'s second spelling is not in
  it: PR-b deleted it (b3), the engine reading the validator's marshal
  (`shekyl_chain_rules::bond_post_vin`). Trigger: the DRS-X cutover, after
  PR-b. Falsifier: `git grep tx_memory_pool src/` → 0.

Both rows are in `DAEMON_REDB_STORE.md` §12 as of this commit.

**The denominator, carried so nobody re-derives it.** E5's share of the
census is **25 / 42** — measured at `census.rs` on `dev@14d68c00fc`: 42
`pending` arms; 12 in 4.K (K1a, K1b, K2, K3, K4, K5, K5b, K6, K7, K8, K9,
K10), 11 in 4.M (M2, M8 on the consensus flag; M1, M3, M4, M5, M6, M7, M9,
M10, M11 on the policy flag), D5, E2. **22 / 39 — SUPERSEDED**: the brief
counted K2–K10 as nine and did not see K1a, K1b, K5b (the lettered rows
C2-R1 §5.5 Q1b and Q1a minted); the three rows are the whole of both
corrections. **24 / 42 — SUPERSEDED**: the pre-flight message's arithmetic
on the corrected set (eleven for twelve K rows); the denominator was right,
the numerator was not.

---

## 8. Questions for Round 1 (`E5-Q1…E5-Q11`), each with its default

Shape per question: the question; the default; why; what the other answer
changes; the falsifier.

### E5-Q1 — Is the pool's door `tx_form` + `tx_against(TxSlot::Lone)` over a key-image decorator, and nothing more?

**Default.** Yes. `PoolView` adds pool key images to `has_key_image` and
delegates everything else; admission is the two validator functions plus
`policy_form` for the `PolicyRow`s. **Why.** The one-validator contract
(C2-R8 §9.1) says the pool runs the same rules the connector runs; under
FCMP++ the pool contributes no referencable output, so key images are the
only pool fact a rule can read. **What changes otherwise.** A second
admission function in the rules crate (G10 forbids it), or a pool that
projects outputs (wrong under FCMP++). **Falsifier.** A `tx_against` rule
that reads a view method other than `has_key_image` and whose answer should
differ between chain and chain+pool — none exists at the pin (§1.0's grep).

**Ruled 2026-10-10 — yes, as defaulted.** The FCMP++ premise is
load-bearing: pool contents cannot move I10's reference lookup, so the
decorator has exactly one override.

**Reopened in part 2026-10-11 (rule 21) and re-ruled.** The 2026-10-10
ruling carried, in §2.2, "`kept_by_block` (K10) skips `policy_form` and
nothing else" — a clause the question did not pose and the ruling did not
argue. Its substrate was the frozen C++'s fee-floor bypass for
block-carried transactions, and the 2026-10-02 reopening of C2-R2 Q9
(FOLLOWUPS, "is a consensus fee floor wanted?") names that bypass a bug:
the exemption let a below-floor transaction re-enter the pool because a
block once carried it. The clause is deleted. **A transaction returned
from a popped block runs the same door as any other, policy included.**
K10's retention — a returned transaction that cannot currently be verified
is kept, not relayable, until M10 evicts it — is unaffected; it never
rested on the policy skip. With the serve-credit carriers gone (§2.2's
redesign) M3 needs no carrier exemption, and M11 is redundant with M3 and
is deleted (§3). The rest of the ruling stands: the door is `tx_form` +
`tx_against(Lone)` over the key-image view, and the bundle queue is not
this door — it is Slice C's verifier, called, not held (§2.2, `E5-Q2`).
*Reopening criterion, going forward:* a ruled admission difference between
returned and relayed transactions that is not retention — none is known.

### E5-Q2 — Does the pool live in a new `shekyl-mempool` crate?

**Default.** Yes; the switch stays in `shekyl-chain-ingest`. **Why.** The
pool is a state machine with its own store (S-POOL), its own FSM and its own
open-time pass; the connector already owns `Rewind` and the write closure.
Rule 25's single-FFI-crate rule is unaffected. **Otherwise.** The pool in
`shekyl-chain-ingest` grows that crate past the ratchet and couples the
replay harness to relay state. **Falsifier.** A circular dependency between
the two (the switch needs the pool for returns, the pool needs the switch
for nothing) — the switch PR's `Vec<Transaction>` return is the cut.

**Ruled 2026-10-10 — yes, with a condition.** `shekyl-mempool` holds the
FSM and the store wiring, **never a rule**: G10 forbids a second admission
function, and the crate's own `//!` doc says so at its top (b1), so the
reader who opens the crate meets the constraint before any code — the
place a constraint has to be written to survive the next author
(`16-architectural-inheritance.mdc`, "write the constraint where the
replacement's author will read it").

### E5-Q3 — Is the alt view a `HeaderView` supertrait split, or a faulting full `ChainView`?

**Default.** The split (§2.1). **Why.** A type refuses the read at compile
time; a fault refuses it at run time; `05-system-thinking.mdc` prefers the
type when two lanes share a representation and differ by a convention —
here "a view over an executed chain" and "a view over a shape". **Otherwise.**
No trait surgery; the twenty-four methods return `Fault::NotAHeaderFact`;
the hazard is a tier-1 rule that quietly reads one and refuses honest
blocks. **Falsifier.** The re-bounding touches rule files beyond the five
§1.0 names, or a header rule turns out to read `root_at`
(`header.rs` does — and that rule is promotion-tier, which the split makes
explicit: the question is which of `header.rs`'s rules are B-rows).

**Ruled 2026-10-10 — the split, with commit 1 owing the measured
partition.** The ruling's own words: the falsifier says `header.rs` reads
`root_at`, which is not a header fact, so "the partition of `header.rs`'s
rules between the cheap and promotion tiers is unknown"; commit 1 owes it
rule by rule, and if the re-bounding exceeds five files the fallback is on
the table. **Measured (`E5-13`, `E5-14`):** `header.rs` is B1/B2/B6 form
and B5 promotion — zero re-bounding there; the five re-bounded files are
`anchors.rs`, `timestamps.rs`, `pow.rs`, `difficulty.rs`,
`attestation.rs`; `HeaderView` is two methods; `block_at` splits into
`header_at`/`HeaderRecord` because its record carries executed fields. The
count held and the membership moved — the falsifier fired on the half it
was written for. The B5 consequence (an alt block stored without its root
checked, safe because of the `AltValid`/`ChainValid` separation and the PoW
bound) is written in §2.1.

### E5-Q4 — Does the cheap tier inherit the C++'s wrong-chain archival read (`E5-6`)?

**Default.** Yes, named, with the fixture in §4 measuring the liveness
cost. **Why.** The alternative — reading `bond_record` *as of the fork
point* — needs an as-of-height archival read that `PDM-Q3`'s re-key ruled
out of the slash log and that no table supports; the error is one-sided and
bounded by `D_max`. **Otherwise.** A new as-of read on the archival tables,
which is a settlement-writer change, not E5's. **Falsifier.** The fixture
refuses an honest chain in a shape stressnet produces (a slash within
`D_max` of a fork).

**Ruled 2026-10-11 (maintainer) — β: no B4 at the cheap tier; promotion
does the check.** The ground is CEN-B5's (§2.1): **the cheap tier makes no
chain-state read.** Any check whose operand is chain state — a persona's
bonded key, a bond snapshot — is promotion-tier, because an unexecuted alt
chain cannot answer it; promotion runs validate against executed state, so
the read is correct there and costs nothing extra. B4's bond-key read
(`E5-15`) is chain state, so B4 is not given an alt-tier site. The ruling
was first closed the same morning on a ground outside this lane (a Slice C
ruling the Slice C round has since reopened) and re-grounded in a4 the same
day: the conclusion stands, and its reason does not depend on where Slice C
puts the pass. For the record: B4 exists in Rust (`rules::attestation::B4`,
`26bc5b994`), runs on the main chain, and judges an alt block's witness at
promotion over `BatchView` (K5b); the C++ alt gate stays until `DEL-009`.
**`E5-17` dissolves directly:** a key bonded only inside the alt chain's
own unexecuted blocks is read at promotion, after those blocks execute.
**`E5-6` dissolves the same way:** there is no cheap-tier bond read to make
from the wrong chain. `E5-16` stands as a finding with no consumer. The
census amendment this leaves for a4 is CEN-K4's row (§5), not CEN-B4's.

**Rejected — the other three shapes, priced 2026-10-10, none built:**

- **α** — B4 whole at the cheap tier, the bond read from the tip snapshot
  (the C++'s read, `E5-6`). The question's default: a chain-state read at
  the tier that cannot answer it, taken from a chain that is not the
  candidate's.
- **γ** — B4 split B4a/B4b across the tiers. B4b at promotion is β; B4a at
  the cheap tier buys a refusal promotion makes anyway, for a second
  census row (ruled, superseded by δ the same day on `E5-16`).
- **δ** — B4 whole at the cheap tier, the bond read as of the fork point
  by read-only reverse replay of `undo_log` (`E5-16`), the no-bond arm
  deferring to promotion (`E5-17`). Correct read, wrong tier:
  reconstructing executed state to answer a question promotion answers
  for free — and still blind to a bond that joins in the alt chain's own
  blocks (`E5-17`), which is the arm β has no case for.

**Reopen (rule 21):** β rests on the cheap tier having no chain-state
view and on nothing judging an alt block's pass before the block executes
(§2.1's (1)). If `AltView` gains a chain-state read — falsify by
`rg '^impl.* for AltView' rust/shekyl-chain-store/src/store/alt_view.rs`
naming a trait other than `HeaderView` — or a consumer appears that must
judge an alt block's pass at admission, the question reopens at δ's
pricing, and the as-of-fork read is still `replay` (`store/undo.rs:504`)
in read-only mode.

### E5-Q5 — Does `ForkChoiceVerdict` gain a `ForcedSwitch` arm, and is K7's discard a match on it?

**Default.** Yes: `KeepCurrent | Switch | ForcedSwitch`; `Switch` keeps the
demoted chain as alt blocks, `ForcedSwitch` discards it. The C++ FFI
consumer (`difficulty_ffi.rs:457`, `blockchain.cpp:2291`) compares against
`SHEKYL_FORK_CHOICE_SWITCH` only, so until DEL-009 it reads the new arm as
*not switch* — the C++ shim therefore maps `ForcedSwitch` to its existing
switch path (one line, `:2291`) in the same commit, keeping its own
`is_a_checkpoint` for discard until it dies. **Why.** `E5-12`: the function
is told `checkpoint_match` and discards what it computed from it; the
caller re-derives. **Otherwise.** The verdict stays two-armed and the Rust
switch carries a boolean beside it — the C++'s shape, inherited. **Falsifier.**
A caller that needs *forced* and *switch* to be the same arm — the C++ is
the only one, and its reading is the line the default changes.

**Ruled 2026-10-10 — yes, as defaulted:** `ForcedSwitch`, with the
one-line C++ shim beside it (`blockchain.cpp:2323`; built in the switch
PR, which landed the arm ahead of a5's closure).

### E5-Q6 — Is the reorg cap checked before the first pop, as a local refusal?

**Default.** Yes: `depth > rule_set.reorg_cap()` refuses before step 1 of
§2.3, with a refusal type distinct from `PopBelowFloor` and from any
verdict; neither is peer-punishable (C2-R1 Q1c F-1(a)). **Why.** A refusal
after N pops inside the closure is still rolled back, but it did N reads for
nothing and conflates "too deep" with "below the floor". **Otherwise.** The
floor belt alone, which cannot tell the two apart. **Falsifier.** §4's
floor fixture cannot distinguish the refusals.

**Ruled 2026-10-10 — yes, as defaulted, with the reason in one line:**
the cap is a **policy** limit and `PopBelowFloor` is a **capability**
limit, and two independent operands earn two refusals — the same
discriminator as SLK-2 and the `PopBeyondReorgCap` refusal, its third
application. The line goes in the refusal type's doc (a6).

### E5-Q7 — Does E5 add a bound on alt-block storage beyond K4's PoW?

**Default.** No (rule 21: rejected with the reopen in §4). **Why.** The C++
has none, SAL-8 drops the table at open, AL6 is the metric. **Otherwise.** A
count or age cap, with its own eviction order to rule. **Falsifier.** A
stressnet AL6 series under adversarial mining that PoW cost does not bound.

**Ruled 2026-10-10 — no, as defaulted** (rule-21 rejection; the §4 reopen
is the AL6 series).

### E5-Q8 — Is `fcmp_cache` seeded for a demoted block's transactions?

**Default.** No; re-admission re-verifies. **Why.** Nothing on chain records
a verified proof's hash; seeding would mean trusting the pop's own reading
of a block the switch is in the act of refusing. The cost is bounded by
`D_max` blocks of proofs. **Otherwise.** The switch computes and seeds the
hash from the demoted bytes. **Falsifier.** A measured switch at `D_max` on
the floor device exceeding the block interval.

**Ruled 2026-10-10 — no, as defaulted:** seeding is a provenance
violation — the cache would record a verification nobody performed.

### E5-Q9 — Does the lane extend the E2 corpus with a reorg capture?

**Default.** Yes, one capture (a7): the C++ driven through one switch, the
trace carrying the alt block, the choice and the promotion; the grader
compares digests after the switch. **Why.** `E5-10`: the oracle cannot see
a switch today; a switch is the one operation whose correctness is the
*absence* of a difference. **Otherwise.** Unit fixtures only; the C++'s
switch is never compared to the Rust's. **Falsifier.** The capture's
digest after the switch differs from the never-switched chain's — which is
a finding either way.

**Ruled 2026-10-15 — no C++ capture (maintainer).** The C++ is not the
spec: a divergence is settled against the spec, so a Rust switch that
matched the C++ would show only that Monero's switch was reproduced,
defects included. And LMDB leaves at the store flip, when the E2 corpus
re-baselines from Rust (`DAEMON_REDB_STORE.md` §12.1), so a C++-derived
fixture would be among the first retired. The oracle is a Rust
self-differential (a6): a store that went A → switch → B equals a store
that connected B directly. No exporter change, no `alt_blocks` read, no
corpus arrival event — the scenario driver feeds arrivals straight to the
actor, and the DRS-X Round 0 designs the arrival event for live sources.

### E5-Q10 — PR-a before PR-b?

**Default.** Yes (§5). **Otherwise.** b-then-a, with K9/K10 landing in
their own PR and the pool's returns path untestable until the switch exists.
**Falsifier.** PR-a's `Vec<Transaction>` return has a second caller before
PR-b — then it is a silent interface, and b goes first.

**Ruled 2026-10-10 — yes, PR-a first.** Since the 2026-10-12 cut (§5) the
order reads #1026 (a1–a4), then the switch PR (a5–a8, where the
`Vec<Transaction>` return lands), then PR-b; the falsifier is the switch
PR's.

### E5-Q11 — Does `--keep-alt-blocks` die with DEL-009?

**Default.** Yes; the Rust store drops the alt table at open
unconditionally. **Why.** SAL-8: the C++'s own default is empty-at-open; a
flag that preserves alt blocks preserves nothing a rule reads. **Otherwise.**
A Rust flag with the same semantics. **Falsifier.** A production consumer of
alt blocks across a restart — none exists (`CEN-K8`'s enumeration).

**Ruled 2026-10-10 — yes, as defaulted.**

---

## 9. Appendix — outside this lane, recorded for its owners

Not E5's; found while reading the census at the pin.

- **CEN-B3** is `pending` against the deleted hard-fork mechanism
  (`census.rs:333`, `60-no-monero-legacy.mdc` 2026-10-08): the row's subject
  is gone; it wants a disposition, not a site.
- **CEN-A5 / A6 / A7** are bucket 4 with class `none`: whether they are
  rows at all is a census question.
- **CEN-J1** may be satisfied by a landed slice-8 row; worth a re-read.
- **CEN-H19's verification half is a block fold, not a `tx_form` row**
  (landed 2026-10-15, [`CHAIN_RULES_CRATE.md`](CHAIN_RULES_CRATE.md) §4.6).
  `tx_form` judges only the proof's layout. The pool door does not call
  the bulletproof verifier itself: it calls `judge_slot_stateless` at
  `TxSlot::Lone`, which verifies a lone transaction's proof as a batch of
  one, and `form`'s listed slots keep the block batch (§2.2). The door ==
  validator test holds a bad range proof refused on H19 both ways.

- **CEN-M9's seam over the Rust pool, prepared (PR-b b3): three things the
  DX round decides at the swap.** `shekyl_daemon_rpc::RustPoolShim`
  implements `SubmitStateShim`; its commit is the pool door, not the
  certificate (`E5-Q2`'s one validator), and the archival facts it hands
  the engine come from the validator's own gathers
  (`release_last_served`, `emission_epoch_facts`). (a) The engine's
  Phase C verifies what the door verifies again at commit: the swap
  either retires Phase C's crypto for the door's verdict or keeps the
  engine as the pre-lock filter it is today, and that choice is the DX
  round's. (b) The engine's fee gate is the door's over the Rust pool:
  the shim hands the engine the relay floor window (`fee_floor_window`)
  and the engine judges by `relay_floor_admits`, CEN-M3's predicate, so
  one transaction gets one fee verdict from both (the review of #1102,
  S5); the C++ shim gives no window, and its tip-floor `needed/50` rule
  stands until the flip deletes it (DX-Q10). (c) `relay()` is a no-op: the relay driver
  takes the pool's unpublished entries at the flip.

- **The public submit endpoint discloses nothing the stem phase holds**
  (the review of #1102, B2). A conflict against a spender this node holds
  unpublished is `KeyImageConflict::Embargoed`: the owner tier is told
  (`DoubleSpendConflict`), a foreign caller is answered as a fresh accept
  and the transaction is not admitted; once the spender is fluffed it is
  `Other`, disclosed to both. Every concealed answer does a fresh accept's
  verification: the shim runs the door's step 1 before the pool's lock for
  every submit, a duplicate it holds unpublished included (S1). The C++
  shim never reports `Embargoed`; it has the same gap and is deleted at the
  flip (`DEL-010`).

- **For the flip (recorded here, built there):** the relay's
  `Responsibilities` is an unbounded map released only by a `release()`
  nothing calls yet — the flip drives `release` from eviction (`Evicted`,
  and `Admission::Admitted { evicted }`), the reconcile's removals and
  mining, and asserts `len() ≤ pool.len()`; and the relay nudge stays on
  `CommitOutcome::Committed` only (`engine.rs`), never on a concealed
  `Accepted` — a peer's stem transaction resubmitted over RPC must never
  make this node its originator.

---

## 10. Decision log

| Date | Entry |
| --- | --- |
| 2026-10-10 | Round 0 posed at `dev@14d68c00fc`. Pre-flight `E5-1…E5-12` (§1.7); questions `E5-Q1…E5-Q11` (§8) with defaults. Families `E5-`/`E5-Q` registered (index §2). `DEL-009` and `DEL-010` minted in `DAEMON_REDB_STORE.md` §12, `Planned`. Denominator corrected to 25 / 42 (`E5-3`; §7). No code. Halt for Round 1. |
| 2026-10-10 | **Round 1 ruled apart from `E5-Q4`.** Q1, Q5, Q7–Q11 as defaulted; Q2 with the never-a-rule condition on the crate doc; Q3 the split, commit 1 owing the `header.rs` partition; Q6 with the policy-vs-capability line. 25 / 42 accepted; `DEL-009`/`DEL-010` `Planned` approved. Branch merged to `dev@ac95d6d04` (one conflict, `DAEMON_REDB_STORE.md` §12, both sides kept; coverage 118/151 and inland-height 151/151 unchanged on the merged tree); draft PR #1026 opened. **PR-a commit 1** measured the partition: `E5-13` (`block_at`'s record carries executed fields → `HeaderRecord`/`header_at`), `E5-14` (`header.rs` is B1/B2/B6 form + B5 promotion; the five re-bounded files are anchors, timestamps, pow, difficulty, attestation; `HeaderView` is `tip` + `header_at`), `E5-15` (CEN-K4 names CEN-B4 at admission). `E5-Q4` HELD, priced α/β/γ in §8: by the ruling's criterion the default stands; the §4 fixture asserts and names the refusal. §2.1 carries the CEN-B5 statement. a4 blocked on `E5-Q4`. |
| 2026-10-10 | **`E5-Q4` ruled γ — B4 split into B4a (stateless + anchor window, cheap tier) and B4b (bond-key countersignature, promotion).** `E5-15` decides it: two reads of different kinds in one row is the defect, not the wrong-chain read. The "census splits none of them" objection refuted by the K1a/K1b precedent (C2-R1c); the split test stated once in §8 (two operands of different kinds → transcription artifact). B4b's deferral cost written beside B5's in §2.1. a4 unblocked; its first commit is the census amendment, drafted for ruling before it lands. a2 authorized and started. **SUPERSEDED the same day by δ (next row); B4a/B4b were never built.** |
| 2026-10-10 | **`E5-Q4` re-ruled δ, replacing γ — B4 whole at the cheap tier, its bond read made as of the fork point by read-only reverse replay of `undo_log` (`E5-16`).** The pruning lane's review of #1026 refuted γ's premise at the tree: `undo_log` journals every `ARCHIVAL_BOND` pre-image above `undo_floor`, the retention never falls below `reorg_cap`, the prune does not touch bonds — the as-of-height read existed, so the split, the stored-forgery cost and the liveness cost all leave. Cost: a journal scan ≤ `D_max` rows per alt block, after PoW. Reopen: a prune that reaps `ARCHIVAL_BOND` un-journaled. a4's amendment shrinks to one sentence on CEN-B4's row (§5). Same review: the prune half of the lane's name is empty — said in §0, the index row and the parent plan's §7 (the prune is E1's, landed 2026-09-25; E5 owns only the reorg × floor interaction, §4); `E5-9`, the `failure_window.rs` asymmetry and `PopBelowFloor` confirmed carried correctly. Lesson recorded in §8: a cost claim in a question's *why* is checked at the tree like any finding, the "nothing supports X" ones first. |
| 2026-10-10 | **`E5-17` ruled (a) — δ's no-bond arm defers to promotion, on the B5 precedent.** Drafting a4's row text surfaced the case the C++ comment (`blockchain.cpp:2131–2133`) and the FOLLOWUPS row already named: a bond that joins in the alt chain's own unexecuted blocks is in no view the admission tier can read. Measured reachable — admission runs no epoch arithmetic on a pass record, so `[join(P), pass(P)]` fits in two blocks, far inside `D_max = 720` (`SEB = 10_000 > D_max`, `reorg.rs:73`); not moot. A cheap-tier refusal stores nothing and would refuse an honest heaviest chain on every delivery — a permanent fork — so the arm defers, stores, and is PoW-bounded as B5; signature invalid under a bonded key, or forged under a bonded key, refuse. Priced in §2.1 beside B5's statement, as the third instance of one cost. a4's census commit carries the three arms on CEN-B4's row, corrects CEN-K4's pre-`4932b769b` ladder order, and removes the FOLLOWUPS row. §4's fixture gains a fifth arm. |
| 2026-10-11 | **`E5-Q4` RULED β — no B4 at the cheap tier, promotion does the check (maintainer); `E5-6` and `E5-17` dissolved under it.** Ground: the cheap tier makes no chain-state read; any check whose operand is chain state — a persona's bonded key, a bond snapshot — is promotion-tier, on the ground §2.1 already gives CEN-B5's root (an unexecuted alt chain cannot answer it; promotion validates against executed state, where the read is correct and free). `E5-17` dissolves directly — a key bonded only inside the alt chain's own unexecuted blocks is read at promotion, after those blocks execute; `E5-6` the same way; `E5-16` stands with no consumer. β is the choice, made for B5's reason; α, γ and δ rejected in §8 with one line each (δ: correct read, wrong tier — reconstructing executed state to answer a question promotion answers for free). Framing: B4 exists in Rust (`26bc5b994`) and is not ported to the alt tier; main-chain B4 and the C++ gate stay until `DEL-009`. The question was first closed that morning on a ground outside this lane (a Slice C ruling the Slice C round has since reopened) and re-grounded in a4 the same day; the conclusion did not move, and E5's reason now depends on no Slice C design. a3 loses its δ UPDATE (`AltView` stays `HeaderView`-only); a4 loses the CEN-B4 sentence, the replay read, "B4 whole" and the `E5-6` fixture arms — `alt_against` = K1b, D5 via D4, E2's arm; a4's census commit keeps CEN-K4's order correction (the C++ ladder in its landed order, no attestation step for the Rust tier) and CEN-B4's site re-pin. FOLLOWUPS rows "Alt-chain attestation verify resolves bond pubkeys from main-chain state" and "Validate `prev_id` before attestation verify on the alt-chain path" closed with the ruling: the first is `E5-17`, held in Rust by where the check sits; the second orders against a step the Rust tier has not got, and already held at the tree (`prev_id` resolves at `blockchain.cpp:2012–2019`, attestation runs at `:2135`). Out of this lane, with the Slice C round: the serve-credit spec's stale §2 B4 row and "nothing built" banner, the SO-D8 §2.2 restatement, serve-credit evidence's reorg survival. Branch merged to `dev@258b4d851` first (clean; inland 150/150, coverage 118/151 unchanged), and to `dev@834471689` before the re-grounding (clean; inland 148/148, coverage 118/151, 15 block rules, unchanged). |
| 2026-10-11 | **The Slice C bundle redesign hands transport to E5 (maintainer); `E5-Q1` reopened in part and re-ruled.** Ground: #1026 @ `bacdd62b4`, `dev@834471689`; lands before b1 and a5; a3, a4 and the `E5-Q4` B4 dissolution are unaffected. *What changed:* serve-credit carriers (`serve_credit_only` transactions) are gone; each block `h` has one bundle (reveal + every pass record for `h`), admitted whole in a block section committed by the header root — not a transaction (no fee, key images or inputs). Slice C owns the verifier (pure chain-rules function, bundle × view → verdict + kept projection) and defines the verifier view trait and the kept projection type in its spec PR; SO-D12 owns the recorded state and the cutover; E5 owns transport, built against the two contracts once they land (blocker named in §2.2 and the b1 row; falsify by both existing under `rust/shekyl-chain-rules/`). *What E5 builds* (§2.2, §2.3, §5): O1 the body store keyed by hash in `shekyl-mempool` with the holder rule and the register invariant; O2 the bundle queue, not a `PoolRecord` arm, admitted by Slice C's verifier through the view trait (`E5-Q2`'s condition met: the crate calls the rule), keyed by `h`, bounded `W₂` (500), three evictions, re-checked after a reorg by the same verifier, persisted and reconciled at open, no Dandelion++ (B12); b6 the bundle section, earliest `h` first to `c · 9·D/SEB` (`c = 2`, provisional), outside fee median and penalty; B10 the alt row stores references only (the folded `archival_alt_attestation_witness` field replaced, rule 42) with stateless arrival checks; a5 the pre-closure body fetch (unfetchable → no switch, local outcome), the view trait on `BatchView`, invalid bundle fails the switch (`E5-7`). Costs a5 `3 → 4`, b1 `2 → 3`; expectation 17 + 15. *`E5-Q1`:* "`kept_by_block` skips `policy_form`" deleted from §2.2 — a returned transaction runs the same door, policy included, on the 2026-10-02 ruling that the fee-floor bypass for block-carried transactions is a bug (C2-R2 Q9's reopening, FOLLOWUPS); K10's retention of an unverifiable returned transaction (kept, not relayable, M10 evicts) unaffected; M3 needs no carrier exemption; **M11 deleted**, redundant with M3 (b1 retires the census row and `PolicyRow`, policy `0 / 9 → 0 / 8`). *No C++:* the sidecar path (`cryptonote_protocol_defs.h:71`, `blockchain.cpp` demote/promote, `db_lmdb`'s witness table) is a `DEL-008` deletion. *Not E5's:* the Levin block payload carrying references (its owning lane; flagged, not built); the verifier, view trait and kept projection (Slice C); the draw state (SO-D12). Docs only; no code — the previous "no carrier or bundle cites in E5" direction is superseded by this handoff. |
| 2026-10-12 | **PR-a cut at a4 (maintainer).** Ground: #1026 at `07f9f0f77`, three behind `dev`. #1026 carries a1–a4 and the Slice C transport-handoff docs and goes to review, so this file's rulings — the cheap-tier rule, the `E5-Q4` dissolution, the transport handoff — land on `dev` as a file the Slice C round can cite rather than a chat ruling. a5–a8 become the switch PR (closure, refusals and fixtures, reorg capture, docs), cut from `dev` after #1026 merges; PR-b unchanged (§5's UPDATE; `E5-Q10`'s order re-read; §7's DRS-X trigger re-pointed). Costs by PR: 8 + 9 + 15. `origin/dev` merged (`adb2013da`, the v3.1.0-alpha.10 cut; one conflict, `CHANGELOG.md`'s Unreleased head — E5's K8 entry kept under Unreleased above the new alpha.10 section); both ratchets re-derived on the merged tree and unchanged: `consensus: implemented 126 / validator-enforced 151 … held-by-store 4 … enforced 153`, `policy 0 / 9`, inland height 148/148. The `shekyl-seam` hub-test hang (two occurrences, the second on this lane's verify run of `2da6ec3ab`) is raised with its owner (P2P-3, #1037) and recorded in FOLLOWUPS with the backtrace; not E5's. Bundle transport stays blocked on Slice C's spec PR as recorded. |
| 2026-10-12 | **Review findings on #1026 (four), addressed.** (1) *`alt_against` could mint an `AltValid` for a view and fork unrelated to the block* — valid in substance: "the parent is the view's tip by construction" was a claim about `AltChain::build`, not about the function's contract (`16-architectural-inheritance.mdc`, a claim about the code is not the code). Two changes, neither the reviewer's suggested shape: A2 (`topology.rs`) re-bound `HeaderRule` — it reads the tip's hash and nothing else — and run first in the tier's ladder, the belt `validate` already wears, so a view handed over for another block refuses at CEN-A2 with the same verdict `validate` gives and mints nothing (rejected: a new `Corrupt` arm — `Corrupt` maps exhaustively to a store invariant and this is a caller's mismatch; `Stale` — the form's premise is intact; a panic — `validate` does not); and the fork is read **from the view** (`AltChainView: HeaderView { fn fork(&self) -> Fork }`, the store's `AltView` answering from its `AltChain`), so `alt_against` loses its `fork` parameter and a fork from one read beside a chain from another is unrepresentable (`05-system-thinking.mdc`, a type defends the call; a check of `recorded_tip` against a stitched view would be partial, so the pairing is by type, not by a comparison). `ALT_TIER_ROWS` 17 → 18; a wrong-parent test; `E5-14` seven files (§2.1, the E5-14 UPDATE). (2), (4) *The schema-23 upgrade note understated the cost* — valid: `header::verify` refuses a `22` file at open before AL3's alt-table drop can run, so the path is a rebuild from the block corpus (rule 15's pre-genesis path), not a restart; `schema_version.rs`'s `23` entry and the CHANGELOG line corrected. (3) *The FOLLOWUPS seam row is a report, not a one-liner* — the row was four physical lines inside rule 95's twenty, and the maintainer ruled the backtrace rides in the row (2026-10-12, 12:57); the body prose tightened to the finding, the two dated occurrences, the diagnosis and the falsifiers; the backtrace sub-bullet stays. Ratchets unchanged (A2 was `implemented` already). |
| 2026-10-12 | **Review findings on #1026 (three more), addressed.** (1) *The header ladder was written three times* — `validate`, `alt_against` and `ALT_TIER_ROWS` each named the membership. The rules are now three segments (`A2`; `C1, C2, D1`; `E1, F4, F5, F6`) called from both ladders; `validate` inserts B5, B4 and G1 between the calls. D5 records only when the shared derivation produced a target; a D6 refusal is D4's verdict. (2) *Schema 23 kept a weight absence nothing writes* — deleted inside the same unreleased layout, not minted as 24. `block_weight` is `BlockWeight`; zero is a codec refusal; a5 does not inherit an absence arm. (3) *An inverted fork was admitted* — `Fork::new` is the only constructor and returns `InvertedFork` when the root is above the recorded tip; `AltChain` stores a `Fork`, and `build` reports that pair as SI-7 on `block_heights` before a `Fork` exists. Beside those: `AltValid` is branded to the view type, as `ChainValid` is, so `insert_alt_block` accepts only a verdict over that store's `AltView`. The tier and the write stay two operations — collapsing them would put chain-store into chain-rules (G1) and would close the shape a5's switch needs, which judges, then pops, then inserts. |
| 2026-10-12 | **Merge with `dev` (#1032, #1034): the alt-row layout is `SCHEMA_VERSION` 24, not 23.** Both lanes cut a layout bump from 22: `SO-D12` increment 1 appended the two draw-state tables as 23 and landed first; this round's alt-row change (K8's supply word gone, SAL-Q4's presence byte gone) is 24. One tree carries both; the merge ordered them by landing. Every live sentence here, in `DRS_E1_SALT.md`, the census K8 row, the index SAL-Q and E5 rows, `codec/alt.rs` and the CHANGELOG now says 24; `schema_version.rs` has both entries, and a 23 file is refused at open the way a 22 file was. The commit-table rows for a4 keep "22 → 23" as what the commit did, with the merge noted beside it. No code moved: the fixture, the layout pins and the refusal are the same bytes under the next number. |
| 2026-10-15 | **The switch PR split; five rulings (maintainer).** Ground: `dev@a0d3ebcb1`, #1026 merged. (1) The bundle legs leave a5 — B10, the pre-closure body fetch, `BundleView` on `BatchView`, the bundle verifier inside `validate` at the switch — for SO-D12's merged increment, which puts the bundle section on the block wire; the alt row keeps the attestation witness; CEN-B4 at promotion (`E5-Q4` β). (2) `BundleView` has one implementation, on `BatchView`, with that increment; `ARCHIVAL_SETTLEMENT_WRITER.md` §16.3 says the same. (3) Demoted blocks re-enter through the cheap tier, judged before the write closure over a `ReadSnapshot`; no demotion constructor; a refusal is SI-27, store-integrity, the writer halts; the switch's N + M RandomX is measured and reported. (4) `E5-Q8` stands. (5) `E5-Q9` re-ruled: no C++ capture; a6 carries a Rust self-differential. SI-5 is built in this PR as a right-edge recompute (§2.3). a7 withdrawn; costs a5 4, a6 3, a8 1. |
| 2026-10-15 | **The switch PR's build: what it found.** (1) **CEN-E2's floor was the anchor table's last entry, not the last anchor the recorded tip has reached** — the census row's "last anchor preceding the current height" and the cited C++ both read the latter; the former refused the very block a not-yet-reached anchor names, so CEN-K6's checkpoint arm and K7's discard were unreachable through the tier. Fixed in `rules/alt.rs` (`ReleaseAnchors::last_at_or_below`), red-checked. (2) **K5–K7 are `held_by_store` with `shekyl-chain-ingest` as the holder**: the status names a crate the validator does not import, and the switch is the store's single writer; `check_chain_rules_coverage.py` reads `#[tokio::test] async fn` as a test definition (selftest cases added). (3) **The journal checks its own post-images**: a corrupted pre-image above the fork point is caught by the next pop (SI-6, `PostImageMismatch`); only the lowest popped row's pre-image becomes state unread, which is the one the self-differential's mutation control corrupts. (4) **The redb digest v0 is too narrow for "nothing left over"** (block hashes, spent keys, live root), so the differential compares every table byte for byte (`ReadSnapshot::table_rows`), the alt table excepted. (5) **FOLLOWUPS' reorg-around-a-spend row closes**: its falsifier named an E2 corpus store or a `regtest_e2e` case; amended to the instrument that exists — the scenario switch differential with a validating spend on the losing branch (`the_self_differential_holds_at_a_shallow_depth_with_a_spend`, `…_at_the_cap_depth_with_a_spend`), whose switch back re-derives the spend's block's rewards — it holds, and the row is removed. |
| 2026-10-15 | **The switch at the genesis cap, measured** (`switch_timing_tests.rs`, ignored lane; release build on the development host, 16 hardware threads, shared with other sessions' work; N = 720 demoted, M = 721 promoted; each run also holds the switched store to the directly connected one, every table). FreeHash, coinbase-only: offer 34 ms, form 0.15 s, `Reorganize` 1.09 s, **total 1.27 s** — the store's own cost. RandomX (the Rust verifier, light mode), coinbase-only, forming serial: form **682 s** (0.47 s per hash × 1 441), `Reorganize` 1.16 s, total 684 s. RandomX, coinbase-only, forming across the host's threads: form 109 s, `Reorganize` 3.2 s, **total 114 s**. RandomX, one validating spend per promoted block, forming across the threads: form 70 s, `Reorganize` **21.3 s** (721 FCMP++ verifications in promotion's `validate`), **total 91.5 s**. Reading: the switch's cost is the re-form — every demoted block and every promoted one hashed again (the ruled shape; the M were hashed at arrival too) — not the store; on 16 threads it sits just under one block interval (120 s). **Floor device not measured**: it is under another lane's `quiet` claim until 2026-10-15 23:59Z. At four cores and a slower hash it will exceed the interval by a multiple, which is `E5-Q8`'s falsifier shape (a switch at `D_max` on the floor device exceeding the block interval) — measured, it reopens `E5-Q8`'s cost premise and the re-form-versus-store-the-formed-result trade the 2026-10-15 ruling made. |
| 2026-10-15 | **Review rulings on the switch PR (maintainer).** (1) **CEN-E2's floor is the last anchor at or below the recorded tip**, kept as built; the C++'s `≤ tip + 1` is the count-versus-height confusion, recorded in the census row as a divergence adjudicated against the specification. (2) **SI-27 stays a halt; anchors cannot reach it**: CEN-E5 at open and E2 at offer under the same tip (`StalePlan` otherwise) stand between an anchor table and a demoted block; the register row names both mechanisms, and a test reopens the store under an agreeing release and sees the pending alternative refused at offer (E2) with the writer up. (3) **The switch must not re-hash blocks this node already hashed**: the proof-of-work hash is recorded beside the block (at `connect` and at AL1) and the switch forms through a substrate that answers from it, keyed by (identity, seed) — built in this PR, then re-measured. The floor-device run follows it. |
| 2026-10-16 | **The switch at the genesis cap, re-measured after the recorded PoW** (`switch_timing_tests.rs`, release; every run also holds the switched store to the direct one, every table, the alt table exactly). **Development host** (16 threads, at `92c0a4403`): RandomX coinbase-only — form 0.085 s (was 109 s), `Reorganize` 1.9 s, **total 2.7 s** (was 114 s); RandomX with one validating spend per promoted block — form 0.047 s (was 70 s), `Reorganize` 21.4 s, **total 21.9 s** (was 91.5 s); FreeHash 1.26 s and 19.8 s. **Floor device** (4 threads, same commit; FreeHash, which with the recorded PoW is the same switch — it calls RandomX zero times — and spares the device hours of RandomX chain-building): coinbase-only **7.0 s** (`Reorganize` 6.5 s); with spends **110.1 s**, of which `Reorganize` **109.6 s**. Reading: the re-hash is gone; what is left is the closure, and with spends the closure holds the write transaction for ~110 s on the floor device — almost all of it promoted blocks' spend-proof verification inside `validate`, which needs the chain and so stays on the writer (the chain-independent checks move off it in #1081). At a 120 s block interval that is the figure `E5-Q8`'s falsifier names the shape of; it is recorded here as measured, not adjudicated. |
| 2026-10-16 | **Round 3 (maintainer's consolidated brief): the switch claims targets, and every verification that needs no store runs in `form`.** Part 1: each `PlannedBlock` carries `target` beside `seed`, claimed through `target_claim` over the stitched `AltView` (promoted) or the recorded chain below (demoted); a D6 refusal is the entry's verdict at offer (the entry and its successors removed, K5's shape) or SI-27 on a demoted block; `Stale::Target` during a switch is `RunFault::StaleTarget`. Part 2: `form` takes `references: &ReferenceClaims` and runs the signature sequence and the verify rows (CEN-I15, J26, J27) per slot; `validate` compares the chain's `(height, root)` with the token's claim and faults `Stale::Reference` (`RunFault::StaleReference`), never verifying; the plan carries the post-switch header chain (`SwitchPlan::headers`) the caller claims off; the sequencer claims off its widened target ledger. Demoted blocks are formed with no reference claims (§2.3, the one discrepancy reported). **Re-measured on the development host** (16 threads, release, `dca5d66ad`; every run holds the switched store to the direct one, the alt table exactly): RandomX coinbase-only — offer 0.36 s, form 0.063 s, `Reorganize` 0.93 s, **total 1.35 s** (was 2.7 s); RandomX with one validating spend per promoted block — offer 0.34 s, form 3.0 s (the 721 proofs and their signatures, off the actor), `Reorganize` **1.93 s** (was 21.4 s), **total 5.3 s** (was 21.9 s); FreeHash 1.04 s and 4.9 s (`Reorganize` 0.94 s / 1.87 s). **Floor device** (4 threads, release, fresh clone at `3e0d72313`, FreeHash — the same switch, zero RandomX calls): coinbase-only — offer 0.13 s, form 1.05 s, `Reorganize` 5.34 s, **total 6.5 s** (was 7.0 s); one validating spend per promoted block — offer 0.17 s, form **62.0 s** (the 721 proofs and their signatures across four threads, off the actor), `Reorganize` **11.1 s** (was 109.6 s), total 73.3 s (was 110.1 s). The write transaction with spends on the floor device, the brief's success measure: 11.1 s against 109.6 s. What is left inside the closure is the pops with SI-5, 720 cheap-tier verdicts and alt rows, and 721 `validate` + `connect` verifying no proof. |
| 2026-10-16 | **PR-b brief (design review): three scope changes, and the record's design commit.** Ground: `origin/dev` at `d2ac8b45d`. (1) **Bundles leave PR-b** — O1, O2 and the template's bundle section are SO-D12's; b1 and b6 carry none of it (b1 cost `3 → 2`, PR-b `15 → 14`). (2) **The door is the validator's own stateless judgement** — `judge_slot_stateless` becomes the one public function `form` and the door both call, at `TxSlot::Lone` with claims from the pool's tip snapshot, then `tx_against(Lone)` over `PoolView` (which compares the claims), then `policy_form` (§2.2). *Found while grounding:* the function as it stood verified no BP+ proof — CEN-H19's verification half is `form`'s block fold after the slot loop — so it verifies a `Lone` slot's proof as a batch of one, and `form`, which never passes `Lone`, keeps its block batch; §9's note is discharged by that, not by the function as it stood. (3) **DX-F6** — `RelayState` is refused by D++ acceptance criterion 2 and the no-zones ruling: `PoolRecord` carries `public: bool` and a standing (admitted with M8's `(reference, height, root)` anchor, or kept under K10); `relayed`, `double_spend_seen` and `Readiness` go, each with its reason in `codec/pool.rs` (no admission, eviction or template reader); `Responsibility` moves to `shekyl-relay` keyed by transaction hash, STAGED for the DRS-X flip; in memory, so after a restart every non-public entry is handled alike. `SCHEMA_VERSION` 27, refuse-not-migrate (the pool file recreates, `SPL-Q8`). `RelayCategory` and `FcmpVerificationHash` deleted with their last reader; `RelayMethod` / `NetZone` stay in `shekyl-types` because the C++ seam names that path until the flip. Also: CEN-I12's code doc and census row state the three-claim design; §2.2's FFI dependency is gone (DX-Q5, DX-Q7). *Not available to this lane:* the DRS-X Round 0 document — DX-Q5, DX-Q7 and DX-F6 are applied as the brief quotes them. |
