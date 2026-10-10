# DRS-E5 — pool, alt chain, prune: the store's consuming increment (`E5-`)

**Status:** OPEN — **Round 1 ruled in full 2026-10-10** (`E5-Q4` last,
γ: B4 split into B4a/B4b, §8); PR-a building (#1026, draft). Round 0 posed
2026-10-10 at `dev@14d68c00fc`, merged to `dev@ac95d6d04` before the PR
opened. Pre-flight in §1.1, findings `E5-1…E5-15` (`E5-13…E5-15` are PR-a
commit 1's measurement, §1.7); questions `E5-Q1…E5-Q11` in §8, each with
its ruling under its default. a4's census amendment (B4a/B4b row text) is
drafted for ruling before it lands. Identifier families **`E5-`** (findings) and **`E5-Q`**
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

AL1 `insert_alt_block(&self, id, &AltBlock)` refusing `IdentityMismatch`
and `AlreadyHeld` (the latter is CEN-K3's belt); AL2 `remove_alt_block`
(`NotHeld`); AL3 `drop_alt_blocks -> u64`; AL4 `alt_block`; AL5
`has_alt_block`; AL6 `alt_block_count`; AL7 `alt_blocks -> Vec<AltEntry>`.
`alt_table` asserts `!journal().is_recording()` — alt rows are **not
journaled and not in the digest**. `AltBlock { block, witness, facts }`,
`AltBlockFacts { height, block_weight: Option<BlockWeight>,
cumulative_difficulty, coins_generated }` (`codec/alt.rs:99–139`). The
module doc's switch sketch is one `store.write` closure: read the demoted
tip → `pop()`×N → `insert_alt_block`×N → `connect`×M →
`remove_alt_block`×M. The hand-offs this round binds itself to:

- **SAL-7** — alt data never reaches `ChainView`; "no `ChainView` accessor
  is minted" for alt membership. (`DRS_E1_SALT.md:400–406`.)
- **SAL-13** — demotion reads the tip's bytes, facts and witness through the
  batch's view *before* `pop()`.
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
  `bond_record` read Round 0 listed here is B4b's, promotion's, under
  `E5-Q4`'s ruling), and the *promotion tier* (K5) is `validate`
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
  liveness cost, never a wrong admission) and bounded by `D_max`. §4 prices
  it; `E5-Q4` asked whether to inherit it and ruled γ: the read is B4b's,
  promotion's; the cheap tier makes no archival read.
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
  `attestation.rs` (B4's `anchor_window` `:188–203`, under any `E5-Q4`
  option — see `E5-15`): five, and a different five from §1.0's (version
  out, attestation in). Beside them: `rules/mod.rs` (the trait and the
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
  membership; the split stands, re-measured.
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
  `view.bond_record(persona)` — the archival read `E5-6` is about). Under
  every `E5-Q4` option B4's body is factored so the cheap tier can hand the
  window read one view and the bond read another (or none); the `BlockRule`
  impl passes its one view to both. This is the fact `E5-Q4`'s pricing
  turns on (§8).

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
beneficiary: `coins_generated` is not a field the alt-bound view has.

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
row — G1's `has_transaction`, the F-rows' emission reads, the I-rows — B5
is named because a committed root reads as the alarming case.

**CEN-B4b at the cheap tier is the second instance of the same cost, not
a separate one.** Under `E5-Q4`'s ruling (γ) the bond-key countersignature
check is promotion's, so **an alt block whose attestation witness is
forged under a key nobody bonded is stored** — its root recomputes (B4a
holds the `attestation_root` commitment and the anchor window before
storage), but the signatures under it are unverified until promotion
`validate` runs B4b over `BatchView`. Safe for the same two reasons as B5,
in the same order: (1) nothing reads an alt block's attestation until
promotion, and `AltValid` never becomes `ChainValid`; (2) a stored row is
what it costs, PoW-bounded (`E5-Q7`). A reader who finds B5's statement
and B4b's apart would take one for an oversight; they are one cost with
two instances, and K4's amended admission list (a4) names B4a and defers
B4b in the words of this paragraph.

The cheap tier is then `alt_against<H: HeaderView>(block, &alt_view,
rule_set) -> Result<AltValid, Verdict>` (the `&snapshot_view` parameter
Round 0 wrote left with `E5-Q4`'s ruling — nothing in the tier reads
archival state): B1/B2, the
timestamp rule over `alt_window_plan`, E1/E2 (an alt block at or below the
last anchor refused — E2's home), D1–D3 PoW against D4's difficulty read
through the stitched `header_at` (= D5, as `census.rs:353` anticipated),
K1a/K1b, `prevalidate_miner_transaction`'s form rows, and K4's attestation
step as **B4a** (`E5-Q4` ruled γ, 2026-10-10): the stateless half and the
anchor window from the alt view; no snapshot view is passed and no
archival read is made — B4b is promotion's. *Round 0 and commit 1 wrote
(SUPERSEDED):* "the attestation's witness check (K5b) reading
`bond_record` from the snapshot view passed alongside — the C++'s
approximation, named". The row set is fixed. `AltValid`
carries `AltBlockFacts` and is what AL1 stores; it is not `ChainValid` and
nothing converts it.

The promotion tier is `validate` over `BatchView` inside the switch closure
after the pops, exactly as any block connects. There is no "promotion view".

### 2.2 The pool decorator is a key-image decorator (`E5-Q1`, `E5-Q2`)

```text
pub struct PoolView<'v, V> { chain: &'v V, pool_key_images: &'v KeyImageSet }
impl<'id, V: ChainView<'id>> ChainView<'id> for PoolView<'_, V> { has_key_image = chain || pool; everything else delegates }
```

Under FCMP++ a pool transaction's outputs are not in the tree, so the pool
adds nothing a rule can reference except spent key images (M6 against the
chain, M7 against the pool — one `has_key_image`). Admission is
`tx_form(tx, TxSlot::Lone, rule_set)` then `tx_against(tx, TxSlot::Lone,
&pool_view, rule_set)` — the same two functions `validate` runs per slot (M2:
the full NIC set is `tx_form`), then `policy_form(tx, &AdmissionPolicy)` for
the `PolicyRow`s (M3 fee floor, M4 extra cap, M5 unlock ban, M11 zero-fee
never relayed), which populates `PolicyCoverage` and lifts the policy gate
off `implemented 0`. `kept_by_block` (K10) skips `policy_form` and nothing
else.

The decorator and the pool live in a **new crate `shekyl-mempool`**
(default, `E5-Q2`): admission, the key-image conflict map, the relay FSM
over `RelayState`/`Readiness`, M10 eviction, template selection
(`fill_block_template`'s successor), and the open-time reconcile (`E5-8`).
It depends on `shekyl-chain-rules` and `shekyl-chain-store` and is depended
on by `shekyl-chain-ingest` (the switch's pool returns) and `shekyl-ffi`
(the daemon's door until the C++ is gone). It never implements `connect`'s
view type, so rule 23's STAGED surface is clean: every symbol it mints has a
caller in the same PR.

### 2.3 The switch is one closure (`E5-Q5`, `E5-Q6`)

```text
store.write(|batch| {
    // 0. the cap, before anything is popped (E5-Q6; C2-R1 Q1c F-1(a): a refusal here is local, never a verdict)
    // 1. SAL-13: read tip bytes + facts + witness through batch.view(), N times
    // 2. pop() × N          — PopBelowFloor surfaces here as F-1 fail-stop, not as a peer-punishable failure
    // 3. insert_alt_block × N   (K7: demoted blocks re-enter as alt blocks — unless the verdict's arm says discard)
    // 4. for each alt entry: validate(formed, &batch.view(), in_force, trust) → connect  (K5; K5b's witness travels in the AltBlock)
    // 5. remove_alt_block × M
    Ok(Switched { demoted, promoted })
})?;                                   // Err → the transaction is the rollback (E5-7, SAL-14)
pool.returns(demoted_txs); pool.evict(promoted_txs); template.invalidate();   // SPL-Q5: chain first, pool second, from Ok
```

The switch lives in `shekyl-chain-ingest` beside the connector that already
owns `Rewind`: an alt block that wins the fork choice is a new
`IngestEvent::Switch`-shaped event the actor executes as the closure above.
K6 is the match on `ForkChoiceVerdict` (strictly greater switches, equal
keeps, checkpoint-forced forces); K7's discard is the checkpoint-forced arm
(`E5-12`); K8's `coins_generated` is `AltBlockFacts` bookkeeping that no
rule and no `ChainView` reads (the row's disposition is an enumeration, as
C2-R1 left it). K3 is AL1's `AlreadyHeld`, by construction.

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
| CEN-K1a | alt-chain derived height ≥ 1 | by construction — `AltChain`'s root is a main-chain row, so the candidate's derived height is `root + 1 + len` ≥ 1 | `shekyl-chain-store` `AltChain` (slice 9) | a candidate whose `prev_id` is unknown is K2, not K1a; the K1a arm is `by_construction` with the constructor test |
| CEN-K1b | a miner-tx claiming height 0 is refused | rule in `alt_against` — the claim read against the derived height, `Locus::Block` | `shekyl-chain-rules` `rules/alt` (slice 9) | mutation: a height-0 claim at derived height ≥ 1 refused |
| CEN-K2 | alt linkage: the chain must connect to the main chain | by construction — `AltChain::build(snapshot, prev_id)` returns `Err(Unlinked)` and no view exists | store `AltChain` (slice 9) | the orphan case; a chain through two alt entries to a main row |
| CEN-K3 | an alt block already stored is refused | by construction — AL1 `AlreadyHeld` (the belt E1 landed) | store `alt.rs` (landed) | the existing AL1 test; the census arm flips to `by_construction` |
| CEN-K4 | alt blocks stored after version, timestamp, checkpoint, PoW | rule — `alt_against` is the tier; what it holds is the row | rules `alt_against` (slice 9) | each sub-check mutated once; the order pinned |
| CEN-K5 | promotion re-validates every block through the full validator | sequencing — step 4 of §2.3 is `validate` + `connect`, nothing else connects | `shekyl-chain-ingest` switch (slice 9) | an alt chain carrying a body `validate` refuses leaves the store at the pre-switch digest |
| CEN-K5b | each promoted block's attestation witness travels and is checked | sequencing — the witness is in `AltBlock`; `validate`'s attestation rule reads it | ingest switch + `AltBlock` (slice 9) | a tampered witness on an alt entry fails promotion |
| CEN-K6 | switch iff alt cumulative difficulty strictly greater (checkpoint forces) | rule — `fork_choice`'s verdict matched; the crossing is Q1b's | `shekyl-difficulty` (landed) + ingest match (slice 9) | equal keeps; greater switches; checkpoint-forced promotes a lighter chain |
| CEN-K7 | demoted blocks re-enter as alt blocks; discard on checkpoint-forced | sequencing — step 3 under the verdict's arm (`E5-12`) | ingest switch (slice 9) | after a switch AL7 lists the demoted blocks; after a forced switch it does not |
| CEN-K8 | alt `already_generated_coins` is bookkeeping, not a consensus read | by construction — `AltBlockFacts.coins_generated` has no reader through the view an alt rule can be bound on: `HeaderRecord` has no such field (`E5-13`); the row is an enumeration | store `codec/alt.rs` (landed) + `view.rs` `HeaderRecord` (a2) | UPDATE 2026-10-10: Round 0's witness (`rg coins_generated rust/shekyl-chain-rules/` → 0) was wrong at the pin — `RecordedBlock.coins_generated` is F13's operand (`view.rs:177`, `miner.rs:469`). The witness is the type: `rg 'coins_generated' rust/shekyl-chain-rules/src/view.rs` names only `RecordedBlock`'s field, never `HeaderRecord`'s, and `AltView` implements `HeaderView` only |
| CEN-K9 | supplement txs must pass NIC or the block is rejected | sequencing — the supplement goes through the pool door (§2.2) under `kept_by_block`; a refusal refuses the block | `shekyl-mempool` + ingest (slice 10) | a supplement tx failing `tx_form` refuses the alt block |
| CEN-K10 | `kept_by_block` admission skips policy, keeps consensus | writer behaviour — `policy_form` skipped, `tx_form`/`tx_against` not; `fcmp_cache` consulted (`E5-11`) | `shekyl-mempool` (slice 10) | a zero-fee demoted tx is admitted and not relayed (M11) |
| CEN-D5 | alt-chain difficulty: the same LWMA-1 over the stitched window | rule — D4 over `AltView::header_at` (the subsumption `census.rs:353` wrote; `block_at` → `header_at` per `E5-13`) | rules `difficulty.rs` bound on `HeaderView` (slice 9) | a fixture drives D4 over a stitched view and over the main chain to the same target when the branches agree, different when they do not |
| CEN-E2 | an alt block at or below the last anchor is refused | rule in `alt_against` — `anchors.rs`'s E2 arm given its alt home | rules `anchors.rs` (slice 9) | a candidate forking below the anchor floor refused; above it admitted |
| CEN-M1 | a tx already in the pool or on chain is refused | rule — `has_transaction` through `PoolView` (chain) and the pool's own set | `shekyl-mempool` (slice 10) | duplicate refused; `double_spend_seen` not set for a duplicate |
| CEN-M2 | pool admission runs the full NIC set | rule — `tx_form(TxSlot::Lone)` is the set | rules (landed) + mempool call (slice 10) | one NIC mutation refused at the door |
| CEN-M3 | relay fee floor | rule — `policy_form`, `PolicyRow` | rules `AdmissionPolicy` (slice 10) | below-floor refused for relay, admitted under `kept_by_block` |
| CEN-M4 | relay cap on `tx.extra` | rule — `policy_form` | rules (slice 10) | mutation at the cap |
| CEN-M5 | relay ban on nonzero `unlock_time` | rule — `policy_form`; `kept_by_block` exempt | rules (slice 10) | nonzero refused for relay |
| CEN-M6 | relay-side double-spend pre-check against the chain | rule — `tx_against`'s I7 through `PoolView.chain` | rules (landed) + decorator (slice 10) | a chain-spent key image refused |
| CEN-M7 | pool-side key-image conflict tracking | rule — the same I7 through `PoolView.pool_key_images`; the map is the pool's | mempool (slice 10) | two pool txs on one key image: second refused, `double_spend_seen` set on the first |
| CEN-M8 | FCMP++ verification cache | writer behaviour — `fcmp_cache` written on admission, consulted on re-admission (SPL-10) | mempool (slice 10) | a re-admitted tx with a cache hit skips proof verification; a mismatched hash does not |
| CEN-M9 | engine-attested local submit | writer behaviour — the submit engine's trait impl swapped (§1.6's planned reversion); `retention_vin`'s second spelling deleted | `shekyl-daemon-rpc` + mempool (slice 10) | `rg -n 'fn retention_vin' rust/` → one site |
| CEN-M10 | pool lifetime / eviction | writer behaviour — age and weight eviction over P7; `kept_by_block` exempt from age | mempool (slice 10) | an aged relay tx evicted; an aged `kept_by_block` tx kept |
| CEN-M11 | zero-fee txs never flagged for relay | rule — `policy_form`'s relay flag; `Readiness` never reaches relay | mempool (slice 10) | zero-fee admitted under `kept_by_block`, never relayed |

Expected gate movement (written now, before measurement — slice 7 §5.1's
rule): consensus `implemented 118 / validator-enforced 151` → `130 / 151`
with K3, K8 and K1a, K2 leaving `pending` as `by_construction`
(`by-construction 16 → 20`) and K1b, K4, K5, K5b, K6, K7, K9, K10, D5, E2,
M2, M8 as `implemented` (+12 — K5/K5b/K7/K9/K10 are sequencing rows whose
census arm names the switch's or the door's test); policy `0 / 9` → `9 / 9`.
If the measured movement differs, the difference is a finding.

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
  `tx_against` over `PoolView` refuses with the root-mismatch verdict; the
  pool keeps the entry under `kept_by_block` with `Readiness` marking it
  not-relayable; M10 evicts it. Fixture: the demoted tx is in P7 after the
  switch and not in any template.
- **The cheap tier's wrong-chain archival read (`E5-6`).** Fixture: a bond
  slashed at `tip − 1`, an alt chain forking at `tip − 3` whose block
  attests under that bond; the same chain presented one block longer (past
  the switch threshold). *Round 0 wrote (SUPERSEDED by Round 1's `E5-Q4`
  instruction):* "the fixture is the measurement `E5-Q4`'s ruling reads".
  The fixture does not measure; it **asserts** the ruling. `E5-Q4` ruled γ
  (2026-10-10): both presentations are **stored** — B4a holds at the cheap
  tier (the root recomputes, the window is on the stitched chain) and no
  archival read is made — and the switch's promotion `validate` runs B4b
  by the alt chain's own record and **admits** them, because on the alt
  chain the bond was never slashed. A second arm plants the forged case —
  a witness signed under a key nobody bonded — and asserts it is stored
  too and refused at promotion with `B4b` at `Locus::Block`, which is the
  §2.1 cost statement as a test. The fixture's name carries `E5-6`.
  *(Commit 1's α arm — "refuses both presentations with `B4` … a bond
  change within `D_max` of the fork refuses an honest alt block" — is the
  liveness cost γ removed; retained here as the shape the ruling rejected.)*
- **A `PoolView` that reaches `connect`.** Negative control: a test that
  tries `connect(validate(.., &pool_view, ..))` and does not compile
  (`compile_fail`), beside `AdmissionPolicyId`'s existing one.

---

## 5. Commit plan — Round 0 (proposed), two increments

Two PRs, matching REDB table 3's slices. **PR-a — slice 9 (alt, switch; 4.K
less K9/K10, D5, E2).** **PR-b — slice 10 (pool; 4.M, K9, K10).** K9 and K10
are STAGED out of PR-a with their consumer named (rule 23): they are pool
rows, and PR-a has no pool. The order is a question (`E5-Q10`): the default
is a-then-b because the switch's pool returns are the only thing PR-a cannot
test without PR-b, and PR-a can land them as a `Vec<Transaction>` the caller
drops, with PR-b the caller.

| # | commit | cost | falsifier applies |
| --- | --- | --- | --- |
| a1 | this file on review; index rows; the §12 register rows (DEL-009, DEL-010). UPDATE 2026-10-10: Round 1's rulings recorded; the `header.rs` partition measured (`E5-13…E5-15`); `E5-Q4` priced | 1 | — |
| a2 | `HeaderView { tip, header_at }` + `HeaderRecord` (`E5-13`); `HeaderRule` with the blanket `BlockRule` impl; `anchors.rs`, `timestamps.rs`, `pow.rs`, `difficulty.rs`, `attestation.rs` re-bounded (`E5-14` — not `header.rs`); `BatchView` and the eight test implementors gain `HeaderView`; `check_block_rule_corrupt_sites.py` reads both impl forms; the store's conformance suite split. UPDATE 2026-10-10: landed as measured — `HeaderRecord { hash, header, cumulative_difficulty }` embedded in `RecordedBlock` (`E5-13`, no `Deref`); `HeaderView { tip, header_at }` with `ChainView: HeaderView` (`E5-14`); D1, C1, C2, E1 are `HeaderRule`s under `impl<R: HeaderRule> BlockRule for R`, the window and seed helpers (`C3::window`, `mtp_median_at`, `D4::target`, `D3::expected_seed`, `E5::conflict_with`, `anchor_window`) bound on `HeaderView`; `recorded_header` lifts a hole to `Corrupt::HoleBelowTip { record: PerHeightRecord::Header }`; the gate **derives** the rule-trait set from the blanket impl and refuses a rule-shaped `check` under a trait it cannot reach (15 rules read: 11 + 4; the user's three probes red on D1). The falsifier did not fire: five rule files, the blanket impl composes with `run`. Beside it, a wrong-subject finding: `validate.rs`'s two brand `compile_fail` doctests had passed since `5fb2132fa` (2026-09-29) on E0046 — the stubs no longer implemented `ChainView` — not at `connect`; replaced by a `trybuild` suite with stderr snapshots and a positive control (`CHAIN_RULES_CRATE.md` §8.3) | 2 | yes — more than these five rule files, or the blanket impl not composing with `run`, is the fallback |
| a3 | `AltChain::build` (K2), `AltView` over `ReadSnapshot` + chain (`HeaderView` only), K1a by construction, the stitched-view conformance test | 2 | yes |
| a4 | **first commit, ruled before it lands:** the census amendment — B4 → B4a/B4b (`census.rs`, `CONSENSUS_RULE_CENSUS.md`), K4's admission list naming B4a, the reconciliation register rows, the `attestation.rs:77–78` sentence (rule 91); **then** `alt_against` (K1b, K4's tier, D5 via D4, E2's arm, B4a from the alt view); `AltValid` → AL1; census arms. UPDATE 2026-10-10: unblocked by `E5-Q4` ruled γ | 3 | yes |
| a5 | the switch closure in `shekyl-chain-ingest` (§2.3): cap check, SAL-13 reads, pops, K7 under the verdict arm, K5 promotion, removes; K6 on `ForkChoiceVerdict`; `Switched` | 3 | yes |
| a6 | the three refusals distinguished (cap, floor, verdict) and the §4 fixtures for the boundary and the floor | 2 | yes |
| a7 | a reorg capture for the corpus (`E5-Q9`): the C++ produces one switch, the trace gains the event, the grader compares | 2 | yes |
| a8 | docs: census 4.K/D5/E2 re-pinned; `DRS_E1_SALT.md` SAL-13/14 marked carried-and-built; index; CHANGELOG | 1 | yes |
| b1 | `shekyl-mempool` crate; `PoolView` decorator; `compile_fail` negative control; `policy_form` and the `PolicyRow`s (M3, M4, M5, M11); `PolicyCoverage` populated | 2 | yes |
| b2 | admission (M1, M2, M6, M7) over `tx_form`/`tx_against(Lone)`; the key-image map; P1–P3 after the chain's `Ok` | 3 | yes |
| b3 | relay FSM over `RelayState`/`Readiness`; M9 — the submit engine's shim swapped, `retention_vin`'s second spelling deleted | 3 | yes |
| b4 | M8 cache, M10 eviction, K10 returns and K9 supplement (PR-a's `Vec` consumed) | 2 | yes |
| b5 | reconcile at open (`E5-8`) — one function, called at open and reused by the door | 1 | yes |
| b6 | template selection from P7 (`fill_block_template`'s successor) behind the existing template FFI | 2 | yes |
| b7 | docs: census 4.M re-pinned; `DRS_E1_SPOOL.md` SPL-7/`SPL-Q5` built; `DAEMON_SUBMIT_VERDICT.md` §11 row executed; FOLLOWUPS `:800` removed; index; CHANGELOG | 1 | yes |

**Expectation: fifteen commits, 8 + 7, costs 16 + 14.** Every commit after
a1/b1 carries the falsifier: if a landed cost exceeds its estimate the
overrun is written into the row as a finding, not absorbed (slice 7 §5.1).
Eight is under the rule-06 ceiling for each PR.

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
  whose only callers are here. Trigger: the DRS-X cutover, after PR-a.
  Falsifier: `git grep -E 'rollback_blockchain_switching|switch_to_alternative_blockchain|handle_alternative_block|build_alt_chain' src/`
  → 0 (SAL-14's, widened); `rg 'shekyl_difficulty_(fork_choice|alt_window_plan)' src/`
  → 0 while the Rust symbols are read natively.
- **DEL-010 — the C++ mempool.** `tx_pool.cpp` whole (`add_tx` `:269`,
  `fill_block_template` `:2077`, the relay FSM, the key-image map);
  `flush_txes_from_pool` (`blockchain.cpp:5067`); the `FfiSubmitShim` trait
  impl in `shekyl-daemon-rpc/src/submit/` (the §11 reversion executed, not
  a deletion of the engine); `retention_vin`'s second spelling
  (`verifier.rs:853`, FOLLOWUPS `:800`). Trigger: the DRS-X cutover, after
  PR-b. Falsifier: `rg -n 'fn retention_vin' rust/` → one site;
  `git grep tx_memory_pool src/` → 0.

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

### E5-Q2 — Does the pool live in a new `shekyl-mempool` crate?

**Default.** Yes; the switch stays in `shekyl-chain-ingest`. **Why.** The
pool is a state machine with its own store (S-POOL), its own FSM and its own
open-time pass; the connector already owns `Rewind` and the write closure.
Rule 25's single-FFI-crate rule is unaffected. **Otherwise.** The pool in
`shekyl-chain-ingest` grows that crate past the ratchet and couples the
replay harness to relay state. **Falsifier.** A circular dependency between
the two (the switch needs the pool for returns, the pool needs the switch
for nothing) — PR-a's `Vec<Transaction>` return is the cut.

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

**HELD 2026-10-10 — a third option to price, and the pricing** *(the
ruling follows the pricing, below)*. The
ruling's reasoning: the default refuses honest alt blocks, which is a
consensus-liveness cost, and `16-architectural-inheritance.mdc` says
migrate the inherited approximation rather than rationalize it. The third
option: drop the witness check from the cheap tier entirely and let
promotion do the real one. Two things to price — what the cheap tier loses
by not checking, and whether any K-row requires the check before storage;
if one does, the default stands and the §4 fixture asserts and names the
refusal. The pricing, against `E5-15`:

- **α — the default.** Both B4 reads in the cheap tier; the bond read
  from the tip snapshot. *Keeps:* CEN-K4 whole (its ratified admission list
  names CEN-B4, `CONSENSUS_RULE_CENSUS_3.md:395`; CHECKED-CONFORMANT at
  `CONSENSUS_STORE_RECONCILIATION.md:787`). *Costs:* the one-sided
  refusal — an alt block attesting under a bond the **main** chain slashed,
  released or never had within `D_max` of the fork is refused at the cheap
  tier though honest on its own chain; bounded by `D_max`, and gone once
  the alt chain is longer than the divergence (the main chain's record is
  then the alt chain's). The reverse error (a bond the main chain has and
  the alt chain lacks) admits a row promotion refuses — the same class as
  B5's deferral, PoW-bounded.
- **β — drop B4 from the cheap tier.** *Keeps:* liveness clean — no
  honest alt block is refused for an archival fact. *Costs:* a block whose
  attestation is malformed, whose root does not recompute, or whose
  countersignatures are forged is **stored** and refused at promotion —
  PoW-bounded like B5, and no worse in kind. *But:* **CEN-K4 names CEN-B4
  in the admission tier (`E5-15`), so a K-row does require the check
  before storage.** β is not a tier choice E5 can default; it is an
  amendment to a ratified census row, and the row's own note calls the
  deferral set "the reorg path's central unexamined design decision" —
  which is to say the row is exactly where that decision was recorded.
- **γ — split B4 across the tiers.** The stateless half (extra parse,
  49-byte records and cap, witness decode and pairing, root recompute, the
  A3 empty-witness arm) and the anchor window (a header fact the stitched
  view answers honestly, as the C++'s `fill_pass_anchor_window(…,
  alt_chain, …)` does) in the cheap tier; the bond-key countersignature
  verification — the one archival read — promotion's. *Keeps:* liveness
  clean, the `attestation_root` commitment checked before storage, the
  window checked before storage. *Costs:* a forged-signature block under a
  key nobody bonded is stored, PoW-bounded. *But:* it still amends K4 (B4
  is no longer whole at admission), and it contradicts B4's own contract —
  "every one is this row at `Locus::Block` — the census splits none of
  them" (`attestation.rs:77–78`): a cheap tier that records B4 after half
  of B4 has run makes coverage say a row ran when it did not, so γ needs a
  B4a/B4b census split as well. Smaller than β in what it defers, larger
  in what it touches.

*Commit 1 wrote (SUPERSEDED by the ruling below):* "by the ruling's own
criterion the default stands (a K-row requires the check; `E5-15`) … the
question stays HELD until the ruling confirms or chooses β/γ".

**Ruled 2026-10-10 — γ, the split.** `E5-15` decides it: B4 makes two
view reads that differ in kind — the anchor window is a header fact the
stitched view answers *honestly*, the bond key is the archival read that is
*wrong* on an alt chain — so B4 as one row conflates a read that works with
one that does not, and **that conflation, not the wrong-chain read, is the
defect**. α inherits a broken check, β discards a working one; γ treats the
measurement as the finding: liveness is clean and the half of B4 that can
be honestly checked before storage still is. The anchor-window half stays
at the cheap tier on its own merits — a header fact, honestly answerable on
the stitched view, cheap, refusing before storage — not because the C++
checks it there; had the C++ deferred it, it would still belong early.

The objection commit 1 raised against γ does not hold. `attestation.rs:77–78`'s
"the census splits none of them" describes the census as it stood; it is
not a prohibition — were it one, CEN-K1a/K1b could not exist. C2-R1c split
K1 because "the census row conflated claimed and derived"
(`CONSENSUS_C2_R1_REORG.md:1033–1034`): one row, two operands of different
kinds, split to match — the same shape on all fours. Rule 91 applies: a
finding that refutes a sentence's premise edits the sentence, and `E5-15`
refutes that one (a4 edits it).

**The rows.** **B4a** — the stateless half (extra parse, 49-byte records
and cap, witness decode and pairing, root recompute, the A3 empty-witness
arm) plus the anchor window: cheap tier, `HeaderRule`. **B4b** — the
bond-key countersignature verification: promotion tier, `BlockRule`. One
fact for a4, read at source: today `verify_countersignatures(window,
pubkey_of)` (`attestation.rs:140`) judges the window arms (below the
threshold, outside the window) and the key arms (no bond, bad signature)
in one call, so B4a needs `AttestationSet` to expose window membership on
its own — a4's first commit measures that seam before the row text is
ruled. K4's admission list names B4a; what B4b's deferral costs is written in §2.1
beside CEN-B5's statement — one cost, two instances. **The census
amendment** (B4 → B4a/B4b in `census.rs` and `CONSENSUS_RULE_CENSUS.md`,
K4's admission list, the reconciliation register rows, the
`attestation.rs` sentence) is **a4's first commit**, drafted for ruling
before it lands — the row text is ruled first, built second. a4 is
unblocked on that.

**The pattern, stated once so the fourth instance is not re-argued.** The
census's granularity is inherited: a row says "here is one rule" and its
boundary was drawn where the C++ put a check — often where a function
ended. Every split so far has been that discovery: K1 (claimed vs derived
height, C2-R1c), the per-class splits I9/H21 carry, now B4 (header read
vs archival read). Three instances, one cause. Rule 16's corollary applies
to the census as to any inherited grouping — it is a claim about its
members, and the claim is testable. **The test:** does this row's
statement have two operands of different kinds? If yes, the row is a
transcription artifact, not a rule. This is not a licence to re-cut the
census for tidiness; a split needs a measured finding of `E5-15`'s shape.

**Reopen (rule 21):** an as-of-height archival read landing in the
settlement writer (`PDM-Q3`'s re-key reversed) would let B4b run honestly
at the cheap tier too — then the tiers' row sets re-merge for B4 and this
question reopens on that read's landing, not before.

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
one-line C++ shim at `:2291` in the same commit (a5).

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

**Ruled 2026-10-10 — yes, one capture (a7).**

### E5-Q10 — PR-a before PR-b?

**Default.** Yes (§5). **Otherwise.** b-then-a, with K9/K10 landing in
their own PR and the pool's returns path untestable until the switch exists.
**Falsifier.** PR-a's `Vec<Transaction>` return has a second caller before
PR-b — then it is a silent interface, and b goes first.

**Ruled 2026-10-10 — yes, PR-a first.**

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
- **CEN-H19-verify** is unblocked by E6 slice 8.

---

## 10. Decision log

| Date | Entry |
| --- | --- |
| 2026-10-10 | Round 0 posed at `dev@14d68c00fc`. Pre-flight `E5-1…E5-12` (§1.7); questions `E5-Q1…E5-Q11` (§8) with defaults. Families `E5-`/`E5-Q` registered (index §2). `DEL-009` and `DEL-010` minted in `DAEMON_REDB_STORE.md` §12, `Planned`. Denominator corrected to 25 / 42 (`E5-3`; §7). No code. Halt for Round 1. |
| 2026-10-10 | **Round 1 ruled apart from `E5-Q4`.** Q1, Q5, Q7–Q11 as defaulted; Q2 with the never-a-rule condition on the crate doc; Q3 the split, commit 1 owing the `header.rs` partition; Q6 with the policy-vs-capability line. 25 / 42 accepted; `DEL-009`/`DEL-010` `Planned` approved. Branch merged to `dev@ac95d6d04` (one conflict, `DAEMON_REDB_STORE.md` §12, both sides kept; coverage 118/151 and inland-height 151/151 unchanged on the merged tree); draft PR #1026 opened. **PR-a commit 1** measured the partition: `E5-13` (`block_at`'s record carries executed fields → `HeaderRecord`/`header_at`), `E5-14` (`header.rs` is B1/B2/B6 form + B5 promotion; the five re-bounded files are anchors, timestamps, pow, difficulty, attestation; `HeaderView` is `tip` + `header_at`), `E5-15` (CEN-K4 names CEN-B4 at admission). `E5-Q4` HELD, priced α/β/γ in §8: by the ruling's criterion the default stands; the §4 fixture asserts and names the refusal. §2.1 carries the CEN-B5 statement. a4 blocked on `E5-Q4`. |
| 2026-10-10 | **`E5-Q4` ruled γ — B4 split into B4a (stateless + anchor window, cheap tier) and B4b (bond-key countersignature, promotion).** `E5-15` decides it: two reads of different kinds in one row is the defect, not the wrong-chain read. The "census splits none of them" objection refuted by the K1a/K1b precedent (C2-R1c); the split test stated once in §8 (two operands of different kinds → transcription artifact). B4b's deferral cost written beside B5's in §2.1. a4 unblocked; its first commit is the census amendment, drafted for ruling before it lands. a2 authorized and started. |
