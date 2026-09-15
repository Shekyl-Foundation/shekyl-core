# DRS-E1 S-CHAIN-W — the connect/pop write set: increment plan and Round-0 pre-flight

**Status:** OPEN — **Round 0 (pre-flight) executed 2026-09-15** at `dev`
`65e7be450` against `shekyl-chain-rules` as it stands on PR #753
(`f03b44452`; the API read here is unchanged since `0bb238896`); **round-1
rulings taken 2026-09-15** on every §10 question (each entry carries its
ruling line-local). §3 is the contract as ruled; §7 the substrate findings
with dispositions; §8 the commit sequence, of which commits 1–3 may start
before #753 merges. Implements *from*
[`CONSENSUS_C2_R8_STORE_PLACEMENT.md`](../completed/CONSENSUS_C2_R8_STORE_PLACEMENT.md)
(Q3–Q6, §7.3, §9, §11 — the ruling, CLOSED-as-record),
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §3.6.2–§3.6.3 and §7 (the
S-CHAIN-W row and DRS-D12), and
[`STORE_INVARIANT_REGISTER.md`](STORE_INVARIANT_REGISTER.md) (SI-1…SI-8).
Nothing in this document re-opens any of them; where the substrate disagrees
with a ruling's *wording* the disagreement is a §7 finding with a disposition,
not a silent override.

**Why a separate document.** The S-CHAIN-W row in DRS §7 is one table line.
The increment it names is the largest single write surface in the store (17
LMDB tables, two funnels, a journal that replaces five C++ journals, three
consensus rows arriving surface-bound, and the writer halt the RPC exposes).
Rule 26's pre-flight pass is a re-check of substrate and execution of
artifacts between design closure and production code; the ruling closed the
*shape* (Q3–Q6), and this is the pass that turns the shape into a write set
with a file:line beside every row. It is the same instrument DRS-E6 used for
its scaffold (`docs/design/CHAIN_RULES_CRATE.md`, PR #753) and it stays in
`docs/design/` while the increment is open.

**Identifier family.** Findings and questions here are **SCW-n** (registered
in [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 by this document's
PR; prefix `SCW` checked distinct against the registry with
`check_index_prefix_uniqueness.py`). One series, numbered in order of
surfacing; a question and the finding that raised it share a number where they
are the same item.

---

## 1. Preconditions, as found at the pin

| Precondition (DRS §7 S-CHAIN-W row) | State at `65e7be450` | Evidence |
| --- | --- | --- |
| DRS-E1 increment 2.5 — `WriteBatch<'store, 'id>` brand, `StoreError::class()`, `StoreInvariant`, `InsertTable`/`UpsertTable`, `StoreCannot`, poison-on-`InvariantViolated` | **landed** (PR #752, merged 2026-09-15) | `rust/shekyl-chain-store/src/store/{write,keyed,error,invariant}.rs`; DRS §3.6.3 |
| DRS-E6 increment 1 — `shekyl-chain-rules` scaffold: `ChainView<'id>` + `AtHeight`/`RecordedBlock`, `RuleSet`/`RuleSetId`/`RuleSchedule`, `ChainValid<'id, V>`/`InvalidBlock`/`Verdict`, `Candidate`/`ValidatedBlock`, `validate` | **open** — PR #753 at `f03b44452`, retargeted to `dev` 2026-09-15, `MERGEABLE`; the crate has no store dependency (`Cargo.toml`: `shekyl-types`, `shekyl-wire`, `shekyl-address` only) | `git show pr/753:rust/shekyl-chain-rules/src/{view,verdict,block,rule_set}.rs` |
| DRS-D12 — replay-that-validates is the Rust store's only writer before cutover | ratified 2026-09-15 (DRS §7 decision table) | S-CHAIN-W is therefore a **callee**; its production caller is DRS-E2's replay. Rule 22 is satisfied by staging with a named consumer, provided this increment's own tests exercise `connect`/`pop` through the public API (§8) |

**Hard dependency.** `connect` takes a `ChainValid<'id, V>` that only the rules
crate mints. Every store-side commit in §8 that does not name that type
(§8 commits 1–3) can land before #753 merges; commits 4–7 cannot. The branch
for this increment is cut from `dev` **after** #753 lands — not stacked on it.
The stacked-PR shape cost a base-deleted auto-close on #753 this week and is
not repeated.

---

## 2. Scope

### 2.1 In

- The two funnels `BlockchainDB::add_block` (`src/blockchain_db/blockchain_db.cpp:435`–`:709` at `65e7be450`) and `BlockchainDB::pop_block` (`:724`–`:927`), **minus** the E3 (curve tree) and E4 (archival) sub-calls, which arrive as hooks (§2.3).
- The six `BlockchainDB` methods of the DRS §7 row that are connect/pop writes: `add_block`, `pop_block`, `add_block_burn`, `remove_block_burn`, `set_hard_fork`, `set_total_burned`. The seventh, `set_settlement_epoch_blocks_pin`, is **not** a connect/pop write and is re-homed (SCW-2).
- The 17 tables of §4, their canonical value codecs (rule 42), and the one Rust-only table this increment adds (`undo_log`, §5).
- Store invariants **SI-1, SI-2, SI-3, SI-4, SI-6, SI-8** flip `ruled → built` (§6). SI-5 stays with S-CURVE (the trim is E3's).
- The surface-bound consensus rows DRS §7.5 table 2 assigns here: **CEN-L1** (the `SI-1` belt beneath the validator's rule), **CEN-H5** (dissolves into the typed `Input` enum — nothing to port), **CEN-B3** (`set_hard_fork`'s discard belt, §3.5).
- The writer halt: `ConnectState` on the store, `ChainTip.connect` on the RPC (DRS §3.6.2), because this increment is the only producer of the `Halted` arm.
- Coverage provenance (C2-R8 §9.4: coverage is "persisted with anything it writes") — the `RuleCoverage` encoding `CHAIN_RULES_CRATE.md` G10 leaves to the store, as a header cell (§3.8, SCW-17).

### 2.2 Out (named, so it is not scope shed by omission)

- **Deriving** any consensus-visible value: cumulative difficulty, coins generated, block weight, long-term weight, burned amount, the curve-tree root. Ruled out by C2-R8 Q4 ("the store computes nothing consensus-visible"). They arrive as inputs (§3.2, SCW-1).
- The curve-tree grow/trim (S-CURVE, E3) and every archival journal, epoch close, slash and segment-freeze hook (S-ARCH, E4). `connect`/`pop` leave a typed seam for them (§2.3).
- The pruning path: `txs_prunable_tip` (ruled not to port, DRS §7 "E1's target is 46 tables"), `output_metadata` (written by the depth prune only — `LMDB_WRITE_ATOMICITY_AUDIT.md` §10 row), `prune_tx_data`, and `pop_target_allowed` as a *method* (it dissolves, SCW-7).
- The read surface S-CHAIN-R (23 methods). This increment defines the codecs S-CHAIN-R will decode with; it does not ship the getters.
- `total_bonded_atomic` (S-ARCH's cell) and `archival_budget_accrual` (an E4 input, not a core-chain fact).
- The consensus rules themselves (all E6). This increment ports **zero** rules; it ports belts.

### 2.3 The E3/E4 seam

`add_block` today interleaves core-chain writes with curve-tree and archival
sub-calls at fixed points (`:623`–`:664` tree; `:681` witness; `:692`–`:704`
accrual/slash/epoch-close). The Rust `connect` keeps the *order* as a
sequence of named phases so E3 and E4 attach at the same points without
re-opening this contract:

```text
connect(valid, facts, in_force):
  1. belts        SI-2 (parent = recorded tip), rule set in force (B3), SI-6 (undo top)
  2. transactions miner tx then listed txs → tx_indices, txs_*, tx_outputs, output_txs,
                  output_amounts, spent_keys                                 (SI-3, SI-9, SI-1)
  3. [E3 hook]    pending leaves → drain → grow → segment freeze            (S-CURVE)
  4. root         curve_tree_roots[h+1] = facts.root_after                  (SI-4)
  5. [E4 hook]    attestation witness                                       (S-ARCH)
  6. block        blocks[h], block_heights[hash], block_info[h]             (SI-2)
  7. rule set     hf_versions[h] = in_force                                 (B3 belt)
  8. burn         block_burn[h] (if nonzero), total_burned += burned        (SI-8)
  9. [E4 hook]    accrual row, slash, epoch close                           (S-ARCH)
 10. journal      undo_log[h] = entries recorded by 2–9                     (SI-6)
```

Each `[hook]` is a phase with no body in this increment; E3/E4 land bodies,
not new phases. `pop` has no phase list: it is the reverse replay of step 10's
entry (§5), which is why the hooks owe nothing on the pop side (C2-R8 Q5).

---

## 3. The contract proposed for freezing (round 1)

### 3.1 `connect`

```rust
// rust/shekyl-chain-store/src/store/connect.rs (new)
impl<'store, 'id> WriteBatch<'store, 'id> {
    /// Project this batch as the view a rule reads. `'id` is the batch brand,
    /// so a `ChainValid` minted against it cannot be handed to another batch.
    pub fn chain_view(&self) -> BatchView<'_, 'id>;

    /// Record a validated block at tip+1.
    pub fn connect(
        &self,
        valid: ChainValid<'id, BatchView<'_, 'id>>,
        facts: ConnectFacts,
        in_force: RuleSetId,
    ) -> Result<Connected, StoreError>;
}
```

- `ChainValid<'id, BatchView<'_, 'id>>` — both brands, per `CHAIN_RULES_CRATE.md` G4 as tightened at #753 review: the lifetime binds the verdict to *this* batch, the view type binds it to *the store's* projection (a verdict minted against the rules crate's test mock does not unify).
- `in_force` — the rule set the schedule names for `tip+1`. `connect` refuses `valid.rule_set_id() != in_force` as `StoreCannot::RuleSetNotInForce { height, judged, in_force }` (`rule_set.rs` doc on `RuleSetId`: "compared to `RuleSchedule::rules_at` on connect; a mismatch is refused there as `StoreCannot`"). The store does **not** hold a `RuleSchedule`: resolving height → rule set is the driver's, and handing the resolved id keeps the store free of a `Network` (rule 71: nettype selects data; the store sees only the datum).
- `Connected` — the height written and the number of undo entries journaled. Nothing consensus-visible.
- Multi-block batches are supported by construction: `connect` may be called repeatedly on one batch (redb tables opened in a write transaction observe that transaction's own writes, so the view for block *h+1* sees block *h*); each call journals its own `undo_log[h]`. This is the C++ `batch_start` shape without the `bool` spin (DRS-W17 closes at the port boundary: a second live batch is `StoreCannot::WriteInProgress`).

### 3.2 `ConnectFacts` — the asserted inputs

```rust
/// Where a consensus-visible value came from. The same mechanism as
/// `RuleCoverage` (rows actually checked) and increment 2's `Provenance`
/// (families actually applied), a third time: the store records what it is
/// handed, and stamps how it got it.
pub enum Origin { Derived, PassedThrough }

/// One asserted value with its origin.
pub struct Fact<T> { pub value: T, pub origin: Origin }

/// Consensus-visible values the store records and never derives (C2-R8 Q4).
pub struct ConnectFacts {
    pub weight: Fact<u64>,
    pub long_term_weight: Fact<u64>,
    pub cumulative_difficulty: Fact<u128>,
    pub coins_generated: Fact<u64>,
    /// This block's destroyed amount. 0 writes no `block_burn` row (LMDB's
    /// absent-reads-as-0 convention, kept so the digest domain matches).
    pub burned: Fact<u64>,
    /// The tree root after this block — `curve_tree_roots[h+1]` (SI-4).
    pub root_after: Fact<CurveTreeRoot>,
}
/// Which census rows derive a fact — and so delete its `Fact` wrapper.
/// Named on the type, so the store shows its own E6 dependency rather
/// than only E6's plan showing it.
pub struct DeletedBy {
    pub field: &'static str,
    /// The census rows whose landing makes this field `Derived`.
    pub rows: &'static [&'static str],
    /// The DRS §7.5.2 E6 slice those rows arrive in.
    pub slice: &'static str,
}

impl ConnectFacts {
    /// The fields still passed through, each with the rows that will
    /// delete it. Empty when every field is derived — the moment `Fact`
    /// and `Origin` themselves are deleted. `count()` is the progress
    /// number; the items are the critical path.
    pub fn passed_through(&self) -> impl Iterator<Item = DeletedBy> + '_;
}
```

| Field | Derived by (deletes the `Fact`) | E6 slice (DRS §7.5.2) |
| --- | --- | --- |
| `cumulative_difficulty` | CEN-D4 (LWMA-1 next difficulty; cumulative = parent's + this block's), CEN-D5 on the alt path | slice 2 — 4.D, body in `shekyl-difficulty` |
| `coins_generated` | CEN-F13 (base subsidy from `already_generated`), CEN-F14/F14b (weight penalty) | slice 4 — 4.F, body in `shekyl-economics` |
| `burned` | CEN-F17 (fee-burn split's destroyed share), recorded per CEN-G11 | slice 4 — 4.F; the G11 recording is this increment's own row |
| `weight`, `long_term_weight` | CEN-G6/G6b (long-term window, effective median) over the tx-weight function CEN-H3 / CEN-F14 share | slice 7 — 4.G, aggregating 4.F/4.H |
| `root_after` | CEN-B5 (header root = tip root) and CEN-I12 (anchor at `ref_height`) — the value itself is S-CURVE's (E3) grow, checked by those rows | slice 1 (B5) / slice 6 (I12), through the curve-tree crate |

So `block_info` becomes parity evidence when slices 2, 4 and 7 have landed
and S-CURVE grows the tree — a named critical path, not a countdown.

These are exactly the values `Blockchain` hands `BlockchainDB::add_block`
today (`blockchain_db.cpp:435`–`:440`: `block_weight`,
`long_term_block_weight`, `cumulative_difficulty`, `coins_generated`;
`:664` the root; `blockchain.cpp:6157` the burn), minus
`archival_budget_accrual` (E4's).

**Ruled 2026-09-15 (SCW-1): the driver supplies them, stamped.** Under
DRS-E2's parity replay the source is the LMDB `block_info` row being replayed
and every field is `PassedThrough`; once E6's DAA / emission / weight rows
land, `ChainValid` carries the value (`view.rs`: "cumulative difficulty and
weight arrive with 4.D / 4.G — never ahead of them") and the field is
`Derived`. `connect` widens the file's `Provenance` (§3.8) with the set of
pass-through field names inside the committing batch — exactly as increment
2 widens it with stubbed families — so `is_parity_evidence()` is `false`
while any field is pass-through and **`block_info`'s diff rows are not parity
evidence until `passed_through()` is empty**. The alternative — blocking
S-CHAIN-W on E6's DAA / emission / weight increments — was rejected: it puts
the store's write path behind the largest E6 increments for values the store
only records, and the stamp makes the deferral visible instead of trusted.
When every field is `Derived` the `Fact` wrapper and `Origin` are deleted,
not left as a permanent `Derived` (rule 15).

### 3.3 `pop`

```rust
impl<'store, 'id> WriteBatch<'store, 'id> {
    /// Remove the tip by replaying its undo entry in reverse (C2-R8 Q5).
    pub fn pop(&self) -> Result<Popped, StoreError>;
}
```

- Belt **SI-6**: the top `undo_log` key equals the recorded tip height, else `StoreInvariantViolated(UndoTopNotTip)`.
- Floor: no entry for the tip → `StoreCannot::PopBelowFloor { tip, floor }` (§5.4, SCW-7). Genesis is never poppable: `pop` refuses `tip == 0` before consulting the journal (`floor ≥ 1` always), which is the C++ `pop_blocks` guard made structural. **Until S-PRUNE lands nothing deletes undo rows, so the floor is 1 and `PopBelowFloor` is reachable only at genesis** — the refusal exists from this increment, its retention arm arrives with S-PRUNE (§5.4).
- `Popped` carries the popped height and the block as recorded (the C++ signature returns `blk` and `txs` to the caller for alt-chain handoff; the Rust caller reads them through the view **before** popping, as the reorg already does for the witness — audit R-5).

### 3.4 `BatchView` — the `ChainView` projection

| `ChainView<'id>` method | Reads | Note |
| --- | --- | --- |
| `has_key_image(ki)` | `spent_keys.get(ki).is_some()` | the chain half of CEN-L1 / CEN-I7 |
| `block_at(h)` | `block_info[h]` → `RecordedBlock { hash, header }`; absent → `AtHeight::AboveTip` | `RecordedBlock` grows with E6 rows, never ahead of them |
| `root_at(h)` | `curve_tree_roots[h + 1]` | **off-by-one is the contract**: the trait documents `root_at(h)` as the root *after* the block at *h*; LMDB keys that root at *h+1* (`store_curve_tree_root_at_height(prev_height + 1, …)`, `blockchain_db.cpp:664`). One place maps it, with a test at both ends |
| `type Fault` | `StoreError` | opaque to every rule (the trait puts no bound on it) |

`BatchView<'txn, 'id>` is a `WriteBatch` projection, not a `ReadSnapshot`
one: `validate` for block *h+1* in a multi-block batch must see block *h*.
A `ReadSnapshot`-backed view (for RPC-side re-validation, DRS-E5's pool
decorator) is a later, separate impl that carries no batch brand — and
therefore cannot mint a `ChainValid` that `connect` accepts, which is the
point.

### 3.5 The CEN-B3 belt and `hf_versions`

C++ `HardFork::add` computes an accept/reject verdict for the block's vote
and **discards** it at the DB call site; the table then records the
schedule's version at *h*, not the block's (`hardfork.cpp:141`). The Rust
port keeps the datum and drops the discard:

- `hf_versions[h]` is **the rule set in force at *h*** — typed `RuleSetId` (`rule_set.rs:53`, `u8` raw; `GENESIS = 1`), written with `insert` (belt SI-2: one block per height). Its byte coincides with LMDB's table today (both `1`) so the `small`-class digest over it is unchanged. **Ruled 2026-09-15 (SCW-16).** The belt is now written against landed code, not a planned signature: per write, `connect` refuses `valid.rule_set_id() != in_force` (§3.1); over a file, `RuleSchedule::for_network(net).rules_at(h) == hf_versions[h]` for every recorded *h* (`rule_set.rs:169`, `:180`) is the walk the E2 harness / `--check` runs — the store itself never holds the schedule or the `Network` (rule 71).
- The vote *window* (`HardFork::add`'s state) is a rule, R4's, and is not here (DRS §7.5 table 2: "body as R4 rules the vote window"). Until R4 lands, there is no incremental window to keep, and **DRS-W15** ("rows above the new tip are not deleted on pop") closes structurally: the undo log deletes them.
- The one thing the C++ discards — "this block was judged under rules not in force here" — becomes `StoreCannot::RuleSetNotInForce` (§3.1). That is a capability refusal, not a verdict: the block may be valid under the rules it was judged by; it was handed to the wrong height.

### 3.6 The writer halt

Per DRS §3.6.2, a `StoreInvariantViolated` on `connect` or `pop` poisons the
batch (increment 2.5), `complete` refuses with the row, and this increment
adds what happens *next*:

```rust
pub enum ConnectState { Live, Halted { at_height: BlockHeight, row: StoreInvariant } }

impl ChainStore {
    pub fn connect_state(&self) -> ConnectState;
}
```

- `ChainStore` records the halt in memory (a `OnceLock`-shaped cell) when a batch completes with `InvariantViolated`. Every subsequent `ChainStore::write` refuses with `StoreCannot::WriterHalted { at_height, row }`; reads stay open.
- Not persisted, re-derived on restart (DRS §3.6.2's ruling, with its reopener). The operator path is the engine's `--check` (SI-7/SI-8) or the file-restore path.
- RPC: `ChainTip.connect: ConnectState` in `shekyl-rpc-types::chain`, with `Halted { at_height, row: StoreInvariantRow(u32) }` — the ordinal newtype, not the store's enum (PR #751 disposition). `CORE_RPC_VERSION` minor bump. The daemon still serves LMDB at this pin, so the field's producer is wired at cutover; the type and the store-side state land here so the E2 harness can assert on them.

### 3.7 Types this increment adds to the store crate

| Item | Where | Why |
| --- | --- | --- |
| `BlockInfo` (canonical, 96 B: height, timestamp, coins, weight, cumulative difficulty as `u128`, hash, cumulative RCT outputs, long-term weight) | `codec/block_info.rs` | `block_info` value; today `&[u8]` with no writer |
| `TxIndex` (tx id, unlock time, height) | `codec/tx_index.rs` | `tx_indices` value under the hash key (zerokval collapse) |
| `OutTx` (tx hash, local index) | `codec/output.rs` | `output_txs` value under the output-id key |
| `OutKey` (amount index ‖ output id ‖ pubkey ‖ unlock time ‖ height ‖ commitment) | `codec/output.rs` | `output_amounts` multimap value (`U64PrefixBytes` — the amount index is the sort prefix) |
| `TxOutputIndices` (`Vec<u64>` amount indices) | `codec/tx_index.rs` | `tx_outputs` value |
| `CurveTreeRoot` codec | `codec/primitives.rs` | `curve_tree_roots` value |
| `TotalBurnedCell` — `KEY = "total_burned"`, `Scope = ChainState`, `Value = u64` | `codec/property.rs` `property_cells!` | the one chain-state cell this increment writes; `upsert_property` already bounds to `ChainState` |
| `CoverageGapsCell` — `KEY = "rule_coverage_gaps"`, `Scope = EngineLocal`, `Value = RowSet` (sorted, deduplicated `CenRow::as_str()` names, length-prefixed) | `codec/property.rs`, `codec/row_set.rs` | §3.8; the `Provenance` pattern applied to coverage (C2-R8 §9.4) |
| `UndoEntry` / `undo_log` table + `TableOrdinal` | `schema.rs`, `store/undo.rs` | §5 |
| `StoreInvariant::{KeyImageNotFresh, TipMismatch, TxHashNotFresh, RootRewritten, UndoTopNotTip, FoldOverflow, IdNotFresh}` | `store/invariant.rs` | SI-1/2/3/4/6/8 + SI-9 (§6) |
| `StoreCannot::{RuleSetNotInForce, PopBelowFloor, WriterHalted}` | `store/error.rs` | §3.1, §3.3, §3.6 |
| `ConnectFacts`, `Connected`, `Popped`, `ConnectState`, `BatchView` | `store/connect.rs`, `store/view.rs` | §3.1–§3.6 |

Every codec is a rule-42 layout change: `SCHEMA_VERSION` bumps once for the
increment, the snapshot tests move with it, and `catalogue()` gains one row.

### 3.8 Coverage provenance

C2-R8 §9.4 rules that coverage is persisted with anything the verdict writes,
**in the `Provenance` pattern** — `ApplyPolicy` is what a session applies,
`Provenance` is what the file has *ever* skipped, only `Full` is parity
evidence. Applied to coverage: `connect` computes
`gaps = in_force.enforced() − valid.coverage()` and, if non-empty, widens the
`rule_coverage_gaps` header cell by union **inside the batch's own
transaction** (so abort/drop leave no taint, and a later complete validator
cannot narrow it). The same widening records `facts.passed_through()`'s field
names into a sibling `passed_through_facts` cell (§3.2). `Provenance::is_parity_evidence()` becomes
`stubbed.is_empty() && coverage_gaps.is_empty() && passed_through_facts.is_empty()`;
the artifact stamp carries all three.

**Ruled 2026-09-15 (SCW-17), with the consequence stated plainly:** the floor
is monotone per file, so **a single partial-coverage or pass-through `connect`
permanently disqualifies that file as parity evidence.** That is correct and it
is severe. The practical trap it sets: the DRS-E2 harness must start every
evidential run from a **fresh file**, never a reused dev datadir — otherwise
the first run is non-evidential and the reason is invisible until someone
reads the stamp. §8 carries that line. Not journaled per height: a popped
block's verdict is still evidence the file once accepted it. Names, not bitset indices, are persisted (`coverage.rs` doc: the slot
shifts when the census inserts a row), which is why the cell is
`EngineLocal` and outside the digest domain: two correct stores of one chain
validated by validators of different completeness hold the same chain state
and different evidence. Under `RuleSet::GENESIS` (zero rules) `enforced()` is
empty, gaps are empty, and the cell is never written — so the E2 harness at
this pin stamps parity evidence honestly: nothing was skipped because nothing
was required.

---

## 4. The write set, table by table

Read at `65e7be450`. "C++ writer" is the `BlockchainLMDB` helper the funnel
reaches; "verb" is the declared Rust write (C2-R8 §7.3: `insert` errors on a
present key and binds an SI row, `upsert` is the declared overwrite);
"class" is `LMDB_WRITE_ATOMICITY_AUDIT.md` §10's accumulator class. Every row
is journaled (§5); pop is not a column because pop is the same for all.

| Table | Key → value (redb, `schema.rs`) | C++ writer (connect) | Rust verb · SI row | Class | Note |
| --- | --- | --- | --- | --- | --- |
| `blocks` | `u64` h → block blob | `add_block` `db_lmdb.cpp:955` (`MDB_APPEND`) | `insert` · SI-2 | append-mostly | blob is `valid.block()` re-serialized by `shekyl-wire`, not the candidate bytes — identity is CEN-B6's (Q4) |
| `block_heights` | `LmdbHashKey` hash → h | `add_block` | `insert` · SI-2 | set-shaped | zerokval collapse; the hash is `valid.hash()` |
| `block_info` | `u64` h → `BlockInfo` | `add_block` | `insert` · SI-2 | append-mostly | `cum_rct` is a store-maintained count (`prev.cum_rct + outputs in block`), a storage index like `tx_id`, not a Q4 value |
| `tx_indices` | `LmdbHashKey` tx hash → `TxIndex` | `add_transaction_data` `:1070` | `insert` · **SI-3** | set-shaped | the hash-keyed tx table (SCW-3) |
| `txs_pruned` | `u64` tx id → prefix ‖ ct base | `add_transaction_data` `:1149` | `insert` · SI-9 | append-mostly | segment boundaries: SCW-9 |
| `txs_pqc_auths` | `u64` tx id → pqc auths | `add_transaction_data` `:1156` (v≥3, non-coinbase, inputs) | `insert` · SI-9 | append-mostly | absent for the miner tx |
| `txs_prunable` | `u64` tx id → prunable | `add_transaction_data` `:1162` | `insert` · SI-9 | excluded (pruned) | |
| `txs_prunable_hash` | `u64` tx id → `Hash32` | `add_transaction_data` `:1177` (v>1) | `insert` · SI-9 | append-mostly | the hash is a Q4 value: the validator derives it (SCW-10) |
| `tx_outputs` | `u64` tx id → `TxOutputIndices` | `add_tx_amount_output_indices` `:1341` | `insert` · SI-9 | append-mostly | |
| `output_txs` | `u64` output id → `OutTx` | `add_output` `:1274` | `insert` · SI-9 | set-shaped | zerokval collapse |
| `output_amounts` | `u64` amount ⇉ `OutKey` (multimap) | `add_output` `:1314`–`:1326` | multimap `insert` · SI-9 | set-shaped | amount-0 keying verbatim; R8b-2 open (SCW-8) |
| `spent_keys` | `LmdbHashKey` key image → `()` | `add_spent_key` `:1429` (`MDB_NODUPDATA`) | `insert` · **SI-1** | set-shaped (v0) | the belt beneath CEN-L1 / CEN-I7 |
| `curve_tree_roots` | `u64` h+1 → `CurveTreeRoot` | `store_curve_tree_root_at_height` `:9733` | `insert` · **SI-4** | set-shaped | written from `facts.root_after` |
| `hf_versions` | `u64` h → `u8` | `set_hard_fork_version` `:4702` (via `hardfork.cpp:141`) | `insert` · SI-2 | small | §3.5; W15 closes |
| `block_burn` | `u64` h → `u64` | `add_block_burn` `:4878` (`blockchain.cpp:6157`, nonzero only) | `insert` · SI-2 | set-shaped | inside the funnel — W9 closes |
| `properties` · `total_burned` | `TotalBurnedCell` | `set_total_burned` `:5066` (`blockchain.cpp:6160`) | `upsert_property`, `checked_add` · **SI-8** | small (`ChainState` fold) | inside the funnel — W6/W9 close |
| `undo_log` (**new**) | `u64` h → `Vec<UndoEntry>` | — (replaces five C++ journals) | `insert` · **SI-6** | excluded (engine-local; named reason: derivable from the write set) | §5 |

Not written by `connect` and therefore not in the set: `txs` (dead, DRS-W4),
`txs_prunable_tip` (ruled not to port), `output_metadata` (depth prune only),
`hf_starting_heights` (dropped at open), every `archival_*`, `curve_tree_*`
other than `roots`, `pending_tree_*`, `block_pending_additions`,
`output_to_leaf`/`leaf_to_output` (E3/E4 hooks), `txpool_*`, `alt_blocks`.

**Storage ids.** `tx_id`, `output_id` and the per-amount `amount_index` are
LMDB's `mdb_stat` entry counts at write time (`:1078` `get_tx_count()`,
`:1284` `num_outputs()`, `:1314` `num_elems`). The Rust port derives them the
same way (`Table::len()`), so the ids are dense and pop-symmetric without a
counter cell. A collision on any of them is not a consensus fact and not
SI-3's set-ness; it is a corrupted index and gets its own row (**SI-9**, §6).

---

## 5. Pop as reverse replay — the undo log

C2-R8 Q5 ruled pop a reverse replay of one journal. The C++ pop funnel walks
five journals with three different height bases (audit §3 table: slash /
epoch-close at *h*, emission-claim / unbond / holdings / rebond at *h−1*,
plus the drain journal), each with its own revert function. The Rust
mechanism replaces all of them with one entry per connect.

### 5.1 Recording

Every declared write records its pre-image into the batch's in-flight
journal **as a side effect of the verb**, so a write that is not journaled is
not expressible:

```rust
enum UndoEntry {
    /// `insert` succeeded: the key was absent; undo deletes it.
    Inserted { table: TableOrdinal, key: Box<[u8]> },
    /// multimap `insert`: undo removes exactly this (key, value).
    MultiInserted { table: TableOrdinal, key: Box<[u8]>, value: Box<[u8]> },
    /// `upsert` / `upsert_property`: undo restores `prior` (or deletes if `None`).
    Replaced { table: TableOrdinal, key: Box<[u8]>, prior: Option<Box<[u8]>> },
}
```

`KeyedTable::insert` / `upsert`, the multimap insert, and
`WriteBatch::upsert_property` each push one entry. `connect` step 10 writes
the accumulated `Vec<UndoEntry>` as `undo_log[h]` (itself an `insert`, SI-6,
and itself the last thing journaled — so the row's own entry is *not* in the
row, and pop deletes the row explicitly after replay).

### 5.2 Replay

`pop` reads `undo_log[tip]`, replays the entries **in reverse order**, then
deletes the row. Replay is the only deleter in the store: `KeyedTable` has no
public `remove`, and does not gain one here (SCW-6). Dispatch from
`TableOrdinal` to a typed table is generated by the `tables!` macro
(`schema.rs`) — one arm per declaration — so an ordinal that names no table
is unrepresentable and the raw key/value bytes are decoded by redb's own
`Value::from_bytes` for that table's `K`/`V`. No `unsafe`, no
string-named tables.

### 5.3 Ordinal stability

`TableOrdinal` is the declaration index in `tables!`. Reordering declarations
would make old undo rows replay into the wrong table — and is a layout change,
so it bumps `SCHEMA_VERSION`, and the header seal already refuses to open a
file of another version. The undo row therefore carries **no** per-row
version tag; the file-level seal is the guard, and a test pins the ordinal of
every table against the catalogue order so a reorder without a bump is red
before it is a file.

### 5.4 The floor

A pop of height *h* is possible iff `undo_log[h]` exists. That makes the pop
floor **structural**: the retention prune (S-PRUNE / E4), when it destroys
rows below the watermark epoch's open height, deletes the undo rows below
it in the same transaction, and `pop_target_allowed`'s predicate — "is the
target above the floor the prune receipt establishes" — becomes "does the
undo row exist" with the receipt's height as the floor's name in the refusal.
DRS §7 assigned `pop_target_allowed` to S-PRUNE with the falsifier "if E1
finds the pop path cannot be extracted without it, it moves". This pre-flight
found a third outcome — it **dissolves** — and **it was ruled so 2026-09-15
(SCW-7)**, with the coupling it creates recorded in both places it lands:

- **Maximum pop depth is the undo-log retention horizon.** If pop-ability is
  "does `undo_log[h]` exist", then S-PRUNE deleting below its watermark *sets*
  the deepest legal reorg the store can execute. Therefore **undo-log
  retention ≥ `D_max`** — S-PRUNE's watermark may not go shallower than
  `D_max` blocks below the tip — where `D_max` is the consensus reorg cap,
  `ARCHIVAL_PRUNED_DAEMON_MODE.md` **PDM-Q11, OPEN at `65e7be450`**. PDM-Q11's
  answer is now a store constraint as well as a discard one; both documents
  carry the inequality (DRS §7 `pop_target_allowed` paragraph; PDM-Q11's
  section).
- Get it wrong and a legal reorg returns `StoreCannot::PopBelowFloor` — the
  correct error class, which is exactly what makes it read as a capability
  limit rather than a defect or a verdict. Falsifier once both constants
  exist: a retention constant `< D_max` is a red test, not a review note.
- **The floor is vacuous today, and that is the hazard, not the comfort.**
  Nothing deletes undo rows until S-PRUNE lands, so the floor is genesis and
  the retention arm of `PopBelowFloor` is unreachable. S-PRUNE's own row
  (DRS §7, "NOT EXTRACTED … `pop_target_allowed` needs a home") is the line
  whoever starts that work reads first — so the inequality has a **third
  copy on that row** (this PR), not only in the `pop_target_allowed`
  paragraph and PDM-Q11. A constant settled by whichever implementation
  arrives first, because the round that owns it was never dispatched, is
  R8's shape exactly; the row is where it is prevented.

### 5.5 Size

Inserts journal a key only (8–32 bytes plus the ordinal); the only
`Replaced` entry per block is `total_burned`. A block with *n* outputs and
*m* inputs journals roughly `5 + 3n + m + txs` entries; at Shekyl block sizes
that is kilobytes per height and it is deleted on pop or prune. It is
out of the digest domain with a named reason (it is a function of the
journaled writes, and two correct stores of one chain agree on it by
construction).

---

## 6. Store invariants this increment builds

| Row | Bound at | Variant | Status change |
| --- | --- | --- | --- |
| SI-1 | `spent_keys` insert | `KeyImageNotFresh` | `ruled → built` |
| SI-2 | `blocks` / `block_heights` / `block_info` / `hf_versions` / `block_burn` inserts; the parent-is-tip pre-check in step 1 | `TipMismatch` | `ruled → built` |
| SI-3 | `tx_indices` insert | `TxHashNotFresh` | `ruled → built` (table cell corrected, SCW-3) |
| SI-4 | `curve_tree_roots` insert | `RootRewritten` | `ruled → built` |
| SI-6 | `undo_log` insert; pop's top-is-tip check | `UndoTopNotTip` | `ruled → built` |
| SI-8 | `total_burned` fold (`checked_add`) | `FoldOverflow` | `ruled → built` |
| **SI-9** | `txs_*[tx_id]`, `tx_outputs[tx_id]`, `output_txs[output_id]`, `output_amounts` inserts | `IdNotFresh` | **minted `ruled` 2026-09-15** in the register (SCW-4 ruled) — "store-derived ids (`tx_id`, `output_id`, `amount_index`) are dense and fresh: the next id equals the table length and its slot is absent"; `ruled → built` at §8 commit 6 |
| SI-5 | — | — | stays `ruled` (the trim is S-CURVE's) |
| SI-7 | — | `CellCorrupt` | already `built` |

`check_store_invariant_register.py` holds the register to the enum in both
directions over `built` rows; each flip lands in the commit that opens the
table with the row (§8), never ahead of it.

---

## 7. Round-0 findings

Each finding names what the substrate says, what the design of record says,
and the disposition this document proposes. "Fix here" means in this
document's PR (docs / one-line comments); "S-CHAIN-W" means in the
implementation increment; "ruling" means §10.

**SCW-1 — `ChainValid` carries no derived facts.** `ValidatedBlock` at
`f03b44452` carries `hash`, `block`, `miner_tx_hash`, `transactions:
Vec<(TxHash, Transaction)>` and nothing else; `RecordedBlock` is hash +
header, growing "never ahead of" the rows that read more. `block_info` needs
cumulative difficulty, coins, weight, long-term weight; the roots table needs
the root after; the burn pair needs the burned amount. The store may not
derive any of them (Q4). → `ConnectFacts` (§3.2) as an explicit asserted-input
struct with per-field `Origin`; **ruled 2026-09-15**: the driver supplies it,
pass-through widens the file's `Provenance`, `passed_through()` is the E6
progress count (§10 SCW-1).

**SCW-2 — `set_settlement_epoch_blocks_pin` is not a connect/pop write.**
`db_lmdb.cpp:5023`: an **init-time** write in its own short transaction,
called once from `Blockchain::init` under `m_nettype == FAKECHAIN`
(`blockchain.cpp:509`–`:530`), pinning the settlement-epoch schedule a
datadir was built under and refusing to reopen under another. It is a
datadir identity pin — the same shape as the store's `apply_policy` header
cell (written at `create`, compared at `open`, refused loudly on mismatch).
→ Re-home as a third `EngineLocal` header cell (`settlement_epoch_blocks`),
written by `ChainStore::create` from a parameter and checked by `open`; a
small S-TXN-territory commit in the S-CHAIN-W PR (§8 commit 3). The DRS §7
S-CHAIN-W row's method list shrinks to six; the row is edited in the same
PR. Fix: S-CHAIN-W.

**SCW-3 — SI-3 names the dead table.** The register row reads "`txs` is
keyed by tx hash" with table `txs`. `txs` is `u64 → blob`, opened and never
written or read (`LMDB_WRITE_ATOMICITY_AUDIT.md` §10 row; DRS-W4), and is one
of the three tables E1 does not port. The hash-keyed transaction table —
the one whose set-ness SI-3 protects — is **`tx_indices`** (`LMDB_SCHEMA.md`
"Transaction Indices": `txindex` under the zerokval pattern; redb
`TableDefinition<LmdbHashKey, &[u8]>`). `keyed.rs:80` carries the same name.
→ **Fix here**: register row SI-3's Invariant and Table cells, and the
`keyed.rs` doc comment, say `tx_indices`. Not a change of ruling — C2-R8 §7.1
ruled the invariant, not the LMDB name — so no reversion clause is touched.

**SCW-4 — storage-id freshness has no row.** `tx_id` / `output_id` /
`amount_index` are entry counts at write time (§4 "Storage ids"). An `insert`
under one of them that finds the key present is neither SI-3 (hash set-ness)
nor SI-2 (one block per height). Binding those sites to SI-3 would overload a
row with a second invariant (rule 23: one row, one property). → **SI-9 minted `ruled` 2026-09-15** in the register (§6); `built` at the
commit that opens `txs_pruned` with it. The reason that matters: SI-3 has a
consensus twin and SI-9 has none — R8-Q1's three-arm test only works while the
register keeps rule-twinned belts and pure invariants distinguishable, and
overloading a row is how that distinction erodes without anyone deciding to.

**SCW-5 — the burn pair sits outside the C++ funnel.** DRS-W9 (connect,
`blockchain.cpp:6157`–`:6160`) and DRS-W6 (pop, `:768`–`:775`) are both
"the burn pair is a second logical unit". In Rust both are inside `connect` /
the undo replay by construction; `total_burned` on pop is a `Replaced` entry
(pre-image restore, **no arithmetic**), so the C++ pop-side saturating
subtract has no Rust counterpart and SI-8's "never a saturate" needs no
pop-side site. → Record both DRS-W rows as closed-at-port in the audit's
disposition column when the increment lands. Fix: S-CHAIN-W docs commit.

**SCW-6 — `KeyedTable` has no `remove`, and should not gain one here.**
Increment 2.5 shipped `insert`/`upsert` only. The pop path deletes; but the
only deleter is the undo replay (§5.2), which is private to the store. The
E3 drain (`drain_pending_tree_leaves`: delete + re-insert inside connect) will
need a **declared, journaling** `remove` verb — that is S-CURVE's to mint,
with its own SI binding, when it opens the table. → No public `remove` in
S-CHAIN-W. Recorded so S-CURVE does not find the verb missing by surprise.

**SCW-7 — `pop_target_allowed` dissolves.** §5.4. DRS §7's falsifier
("cannot be extracted without it → it moves") does not fire; the predicate
becomes a property of the journal. But the consequence lands on S-PRUNE (it
must delete undo rows below the watermark in the prune's transaction) and on
the `archival_prune_watermark_epoch` cell (it stays the floor's *name* in
`PopBelowFloor`, and stays exempt from pop reversal — it is written by the
prune, never by connect, so it is never journaled). → **Ruled 2026-09-15**: dissolves; the coupling (undo-log retention ≥
`D_max`, PDM-Q11) is written into DRS §7 and PDM-Q11 (§5.4).

**SCW-8 — `output_amounts` keying is arm C.** CEN-L6's amount-0 indexing
question is routed to R8b-2 and unruled (`CONSENSUS_C2_R8_STORE_PLACEMENT.md`
§12). The store must write the table now. → Port LMDB's keying **verbatim**
(amount as key, `0` for committed outputs, `amount_index` = per-amount entry
count): under DRS-E2 the LMDB store is the parity oracle, so any other shape
fails parity before R8b-2 could rule either way. Whatever R8b-2 rules changes
whether `amount_index` is *exposed* as a consensus fact, not how the store
records it. Recorded as records-was with R8b-2 as the reopener. Fix:
S-CHAIN-W (a doc comment on `OutKey`).

**SCW-9 — the tx blob's three-way split is not exposed by `shekyl-wire`.**
`txs_pruned` / `txs_pqc_auths` / `txs_prunable` are byte ranges of one blob
at `unprunable_size` and `pqc_auths_offset` (`db_lmdb.cpp:1113`–`:1162`).
`shekyl-wire::Transaction::write` serialises the whole; it exposes no
segment boundaries. → Add `Transaction::write_segments` (or a
`Segments { prefix_and_base, pqc_auths, prunable }` accessor) to
`shekyl-wire` — layout, not consensus, so it is the store increment's to
add, in the wire crate, with a round-trip test that `concat(segments) ==
write()`. Fix: S-CHAIN-W (§8 commit 2).

**SCW-10 — the prunable hash is a Q4 value the verdict does not carry.**
`txs_prunable_hash[tx_id]` is `H(prunable section)` — one of the three
component hashes of the tx hash (CEN-B6). The validator derives the tx hash
and so has this value; `ValidatedBlock` exposes `(TxHash, Transaction)` only.
→ `ValidatedBlock::transactions` carries a `TxIdentity { hash, prunable_hash
}` (and the miner tx its own), minted once in `validate`. A rules-crate
change, owed to this consumer the way `CHAIN_RULES_CRATE.md` Q12-2 owes
`tip()` to E6 slice 1 — methods and fields grow with the increment that
consumes them. Fix: S-CHAIN-W (§8 commit 4, the first commit that names the
rules crate).

**SCW-11 — the Rust-only table breaks the 49↔49 bijection gate.**
`check_redb_schema_bijection.py` demands every `TableDefinition` have an
X-macro twin. `undo_log` has none and should not (it replaces C++ journals
that *are* LMDB tables — the four `archival_*_log` pre-image journals stay,
being E4's data, but the mechanism they journal *for* is now one row).
→ Extend the gate with a **named map `{table: reason}`** of Rust-only tables
(the same shape as `AccumulatorClass::Excluded`'s reason), **never a mode
switch**: `undo_log` is the first redb-only table and the moment the gate's
mirror assumption retires, and the extra-leg's own error text — *"this is how
a plausible concept becomes an invented table"* — has to survive that
transition. So: any `TableDefinition` not in the X-macro **and** not in the
map is still red with that text; a map entry naming a table that *is* in the
X-macro, or that has no definition, is red (rule 47: the map asserts its own
subject); the census leg and the accumulator-class leg are unchanged. Fix:
S-CHAIN-W (§8 commit 1, same commit as the table).

**SCW-12 — `shekyl-wire/src/block.rs:63` contradicts CEN-B5.** The
`curve_tree_root` doc comment says the root commits to "the chain's outputs
after this block". CEN-B5 as corrected 2026-09-05 says the header root must
equal the tip root **at the block's own height** — the tree grown through the
parent, before this block's outputs. The comment is the pre-correction
wording. A writer implementing §3.4's `root_at` off-by-one from that comment
would key the roots table one height wrong. → **Fix here** (one line; the
doc/comment sweep rule 91 mandates, and this pre-flight is the reader it
would have misled).

**SCW-13 — `BatchView` must be a `WriteBatch` projection, not a snapshot.**
§3.4. Recorded because the obvious implementation (validate against a
`ReadSnapshot`, then write) is wrong for multi-block batches — block *h+1*'s
`has_key_image` must see block *h*'s spent keys — and the failure is silent
(a double-spend across two blocks in one batch would pass validation and then
be caught only by SI-1's belt, as a *fatal*). The test for it is a two-block
batch with a cross-block double spend asserting `InvalidBlock`, not
`StoreInvariantViolated`.

**SCW-14 — the store crate gains a dependency on `shekyl-chain-rules`.**
Direction: store → rules (for `ChainValid`, `ChainView`, `RuleSetId`,
`Candidate`-free types). Rules → store stays absent (its `Cargo.toml` has no
store path). The conversion-ban gate's clause 2 ("`shekyl-chain-store` never
names `InvalidBlock`") is unaffected: `connect` takes the `Valid` arm only;
the `Verdict` match is the driver's. Recorded so the dependency is added with
that clause in view.

**SCW-17 — coverage persistence is ruled and unlisted** (approved
2026-09-15; consequence in §3.8 and §8). C2-R8 §9.4 rules
coverage "persisted with anything it writes"; `CHAIN_RULES_CRATE.md` G10
assigns the `RuleCoverage` encoding to the store at S-CHAIN-W; the DRS §7
S-CHAIN-W row's method list (ported C++ methods) has no slot for it because
the C++ has no such thing. → §3.8: a `Provenance`-shaped `EngineLocal` cell
widened by `connect`, names not indices, `is_parity_evidence()` extended.
Fix: S-CHAIN-W (§8 commit 6). Per-file and monotone, ruled; the
per-height-journaled alternative rejected (`Provenance` is deliberately
monotone, and a popped block's verdict is still evidence the file once
accepted it).

**SCW-18 — the rules crate's `implemented(path)` pin checks existence, not
identity** (found 2026-09-15 verifying #753; **shape decided the same day**,
lands in E6 with the first real rule). The G9 pin `use $path as _;` refuses
a path that does not exist — verified: a claim pointing at the test-only
probe fails `cargo check` — but accepts any item that does, so
`implemented(crate::rules::cen_c2)` would compile and count toward CEN-C1's
row. A typed pin binding the path to a rule *signature* closes signature,
not identity. The shape that closes both is the one the C2-R8 exchange
sketched: `trait Rule { const ROW: CenRow; fn check(…) }`, the registry
entry takes a **type**, and the pin asserts `<T as Rule>::ROW == CenRow::C1`
at compile time — row binding becomes structural instead of nominal. →
Decided now so the first real rule is written against it; deciding it after
would make the migration 153 call sites instead of one. Owner: DRS-E6
(`CHAIN_RULES_CRATE.md`; handed over on PR #753). Not this increment's
code.

---

## 8. Commit sequence (rule 90; one PR, ≤ 10 commits, cut from `dev` after #753)

| # | Subject | Lands | Gate / test |
| --- | --- | --- | --- |
| 1 | `store: undo log — table, UndoEntry codec, journaling verbs, reverse replay` | `undo_log`, `TableOrdinal`, journaling inside `insert`/`upsert`/`upsert_property`, replay dispatch from `tables!`; SI-6 `built`; `SCHEMA_VERSION` bump; bijection gate gains the named `{table: reason}` map, extra-leg text and refusal preserved (SCW-11) | snapshot tests; ordinal-pin test; replay round-trip on synthetic tables; register gate |
| 2 | `store+wire: canonical codecs for the connect write set` | `BlockInfo`, `TxIndex`, `OutTx`, `OutKey`, `TxOutputIndices`, `CurveTreeRoot`; `Transaction::write_segments` (SCW-9) | rule-42 snapshots pinned against the `LMDB_SCHEMA.md` byte layouts; segments concat test |
| 3 | `store: TotalBurned chain-state cell; settlement-epoch pin as a header cell` | `TotalBurnedCell`; `settlement_epoch_blocks` `EngineLocal` cell at `create`/`open` (SCW-2) | property-catalogue snapshot; open-mismatch refusal test |
| 4 | `rules: ValidatedBlock carries TxIdentity { hash, prunable_hash }` | SCW-10 — in `shekyl-chain-rules`, the owed-to-consumer item | existing rules tests + one identity test |
| 5 | `store: BatchView — ChainView<'id> over WriteBatch` | §3.4; store → rules dependency (SCW-14) | `root_at` off-by-one test at both ends; two-block-batch visibility test (SCW-13) |
| 6 | `store: connect(ChainValid, ConnectFacts, RuleSetId) — the write set` | §3.1/§3.2/§3.5/§3.8; SI-1/2/3/4/8 + SI-9 `built`; `RuleSetNotInForce`; `Fact<T>`/`Origin` with `Provenance` widening on pass-through (SCW-1); `CoverageGapsCell` + `PassedThroughFactsCell` + `RowSet` codec (SCW-17); CEN-L1/H5/B3 arrive | per-table write test against `LMDB_SCHEMA.md` layouts; every SI belt fires from a hand-built violation; conversion-ban gate; E6-partition gate row statuses |
| 7 | `store: pop() by reverse replay; PopBelowFloor; writer halt + ChainTip.connect` | §3.3/§3.6; `StoreCannot::{PopBelowFloor, WriterHalted}`; `ConnectState`; `shekyl-rpc-types` field + `StoreInvariantRow`, `CORE_RPC_VERSION` minor | connect→pop→digest-equal round-trip; halt-then-refuse test; RPC type snapshot |
| 8 | `docs: S-CHAIN-W landed — DRS §7 row + §3.6.3, register flips, index, audit W6/W9/W15/W17, CHANGELOG` | rule 91 sweep; this document's banner → landed, §7 dispositions → done | docs gates |

Tests in 5–7 build blocks with `shekyl-wire` fixtures and validate them
through the real `validate` with `RuleSet::GENESIS` (zero rules → coverage
complete, every well-formed candidate `Valid`), so `connect` is exercised
through its public signature. **Every evidential run — these tests and the
DRS-E2 harness — starts from a fresh file** (SCW-17: the provenance floor is
monotone per file; a reused datadir is non-evidential from its first
partial-coverage or pass-through connect, and the stamp is the only place
that says so). **DRS-TLB is not a blocker**: it is the
better fixture source and will replace hand-built candidates when it lands
(falsify by: `rust/shekyl-test-ledger` exists on `dev`).

Working days: ~5 (commits 1–3 can start on `dev` today; 4–7 wait for #753).
If the increment overruns, the split point is after commit 3 (a self-contained
"journal + codecs + cells" PR with no rules dependency), never after 6 (a
`connect` without `pop` is the C++ shape this increment exists to end).

---

## 9. Denominator — what must stay green, what must be extended

| Gate | Effect of this increment | Owed |
| --- | --- | --- |
| `check_redb_schema_bijection.py` | one Rust-only table | Rust-only allowlist with named reason (SCW-11) |
| `check_redb_schema_key_types.py` | new value types on existing keys | none expected — keys unchanged |
| `check_store_invariant_register.py` | six flips + one new row | each in the commit that binds it |
| `check_store_error_conversion_ban.py` | store gains rules dep | clause 2 must stay clean (SCW-14) |
| `check_drs_e6_partition.py` | CEN-L1/H5/B3 "arrives with S-CHAIN-W" | verify whether table-2 status tokens change on landing; if the gate pins them, it is edited in commit 8 |
| rule-42 snapshot tests | codecs + `undo_log` + one cell | `SCHEMA_VERSION` bump once; snapshots moved |
| `check_doc_status_banners.py` / `check_index_table_shape.py` / `check_index_prefix_uniqueness.py` | this document; `SCW` family | registered by this PR |
| `cargo fmt --check`, `clippy --all-targets -D warnings`, `cargo test --workspace`, rustdoc doctests (`compile_fail` brands) | as CI runs them | before every commit |

---

## 10. Round-1 questions — RULED 2026-09-15 (default taken unless stated)

**SCW-1 — who supplies `ConnectFacts`? RULED: the driver, stamped per field (§3.2).** *Default was:* the driver. Under
DRS-E2's parity replay that is the LMDB `block_info` row of the block being
replayed (records-was, and exactly what parity means); once E6 lands the
rows that derive each field, `ChainValid` carries it and the corresponding
`ConnectFacts` field is **deleted**, not shadowed — the struct shrinks to
empty and is removed. The alternative — block S-CHAIN-W on E6's DAA / emission
/ weight increments — puts the store's write path behind the largest E6
increments for a value the store only records. Rule 22: the deferral of
derivation is E6's scheduled work, not this increment's shed scope.

**SCW-4 — SI-9 wording. RULED: minted as §6, in the register.** *Default was:* as §6. Alternative: fold into SI-3 as
"the transaction tables are consistent". Rejected by default because SI-3's
twin is CEN-G1/CEN-F5 (a consensus rule makes it hold) while SI-9 has **no
consensus twin** — it is pure storage integrity — and the register's
"Consensus twin" column is the reason the rows exist separately.

**SCW-7 — does `pop_target_allowed` dissolve into the undo log? RULED: yes,
with the `D_max` coupling recorded in DRS §7 and PDM-Q11 (§5.4).** *Default was:*
yes. The cost lands on S-PRUNE: the retention prune deletes
`undo_log` rows below the watermark in its own transaction, and
`PopBelowFloor` names the watermark's open height as `floor`. If S-PRUNE's
owner prefers the predicate stays a method, the undo log still gates
existence and the method gates policy — two refusals with one name each, no
contradiction; the DRS §7 falsifier text is edited either way.

**SCW-15 — where does `connect` live: `WriteBatch` or `ChainStore`? RULED:
not a question — the type already ruled it.** `ChainValid<'id>` is brand-bound
to the batch; `connect` on `ChainStore` would break the brand. *Default was:*
`WriteBatch` (§3.1). The brand argument settles it: `ChainValid`
is branded with the batch's `'id`, which only exists inside
`ChainStore::write`'s closure. A `ChainStore::connect` convenience that opens
a batch, validates, connects and completes is a *driver* helper and belongs in
DRS-E2's crate, not the store's.

**SCW-16 — is `hf_versions[h] = in_force` the right identification? RULED:
yes; checkable against `rule_set.rs` as landed on #753 (§3.5).** *Default was:*
yes. It is the value the C++ writes (the table's version,
not the vote), the digest over the table is unchanged, and it is what makes
`RuleSetId` "persisted beside the verdict" as `rule_set.rs` promises. The
alternative — persist `valid.rule_set_id()` — is the same byte unless
`RuleSetNotInForce` fires, in which case nothing is written at all.

---

## 11. Documentation owed by the increment (rule 91)

- `DAEMON_REDB_STORE.md`: banner (E1 increment 3 landed); §7 S-CHAIN-W row (methods 7 → 6; preconditions → landed; `pop_target_allowed` text per SCW-7); §3.6.3 implementation pointers; decision-log row.
- `STORE_INVARIANT_REGISTER.md`: SI-3 cell (this PR, SCW-3); six flips + SI-9 (increment).
- `LMDB_WRITE_ATOMICITY_AUDIT.md`: DRS-W6/W9/W15/W17 disposition column → closed-at-port with the mechanism named.
- `CONSENSUS_STORE_RECONCILIATION.md` / `CONSENSUS_RULE_CENSUS.md`: CEN-L1/L2/L3/L4/L5/L15/B3/H5 S-CHAIN-W column → landed (the *rules* stay E6's).
- `IMPLEMENTATION_INDEX.md`: `SCW` family and §7 doc row (this PR); the DRS row `UPDATE` is the increment PR's (rule 94 §6 — PR #753's lane is editing that row now).
- `docs/CHANGELOG.md`: one Unreleased line at landing (`ChainTip.connect` is API-visible).
- `shekyl-wire/src/block.rs:63` (this PR, SCW-12).
- This document: banner flips to *implemented*, §7 dispositions to *done*, then archive-or-contract per index §8 once S-CHAIN-R has consumed the codecs (the reopening condition for keeping it in `design/`).

---

## 12. Decision log

| Date | Entry |
| --- | --- |
| 2026-09-15 | Round 0 executed at `dev` `65e7be450` / #753 `f03b44452`. Fifteen findings (SCW-1…SCW-14, SCW-17) and two questions minted as such (SCW-15, SCW-16); two findings fixed in this PR (SCW-3, SCW-12), six items routed to the round (SCW-1/4/7/15/16 and SCW-17's one point — SCW-7 carrying its S-PRUNE consequence), the rest dispositioned into §8's commits. Contract §3 **proposed, not ruled**. |
| 2026-09-15 | **Round 1 rulings (maintainer, same day):** SCW-1 driver-supplied `ConnectFacts` with per-field `Origin`, pass-through widens `Provenance`, `passed_through()` is the E6 progress count; SCW-4 SI-9 minted `ruled`; SCW-7 dissolves, coupling **undo-log retention ≥ `D_max`** written into DRS §7 and PDM-Q11; SCW-15 ruled by the brand, not a question; SCW-16 belt written against `rule_set.rs` as landed; SCW-17 approved, fresh-file rule stated in §8; SCW-11 allowlist is a named `{table: reason}` map that keeps the extra-leg refusal, never a mode switch. §3 is the contract as ruled. Commits 1–3 authorised to start before #753 merges; the increment branch still cuts from `dev` after it. |
| 2026-09-15 | **Round-1 follow-ups (maintainer, same day):** `passed_through()` names the rows that delete each `Fact`, not only a count (§3.2 table); the SCW-7 inequality gets its third copy on the S-PRUNE row itself, and the vacuous-today floor is recorded as the hazard (§3.3, §5.4); **SCW-18** minted — the `implemented(path)` pin's shape decided (`trait Rule { const ROW }`, structural row binding) ahead of the first real rule, owner E6; ordinal *removal* recorded as a bump in the increment's codec docs (commit 1). |
