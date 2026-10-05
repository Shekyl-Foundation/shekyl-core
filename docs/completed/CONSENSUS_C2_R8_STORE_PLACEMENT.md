# C2-R8 — Storage-layer enforcement placement design round

**Status:** **CLOSED-as-record (2026-09-14)** — eight rulings (`C2-R8-Q1…Q8`)
signed by merging this landing PR; this document is the round's finished
ruling record (rule 95 closed-plan class; archived per index §8 in the
landing PR). It owns no open work: DRS-E1 increment 2.5 and the DRS plan
amendment (E6, validation crate, `ChainTip.connect`) have named carriers in
§14; batch R8b lives in the census §10 queue. The store-invariant register
([`STORE_INVARIANT_REGISTER.md`](../design/STORE_INVARIANT_REGISTER.md)) stays
in `docs/design/` as a living contract. The landing PR carries the ruling
text, the census and CSR effects the signature reviews (§10 — every moved
cell is listed), the register with its gate, and the conversion-ban gate
(§3.3).
**Pinned sha:** C++ read at **`c405fac0a`** (`dev` tip 2026-09-14, containing
PR #747); the Rust store read at **`943592a61`** (PR #749's head, this
branch's base). Every `file:line` below was re-located at those pins; where a
census citation had drifted, both numbers are recorded.
**Identifier family:** `C2-R8-Q1…Q8` (the `C2-R` row of
[`IMPLEMENTATION_INDEX.md`](../design/IMPLEMENTATION_INDEX.md) §2, appended this PR) and
the new **`SI-1…SI-N`** family (store invariants; registered this PR,
uniqueness checked with `check_index_prefix_uniqueness.py`). Census rows in
scope: **CEN-L1, L2, L3, L4, L5, L6, L13, L14** — the §10 R8 batch. CSR-1
names CEN-K3 and CEN-B3 as the two other store-enforcing rows; both are read
here as inputs to Q1 (K3 is bucket 2 since R1c; B3 is R4's) and neither is
re-ruled.
**Authority chain:** census §10 R8 + §4.L + §6 ("validation completed by a
side effect of the write path"); CSR-1 (R8 is the ruling instrument, the
DRS-C surface map is its input) and CSR-5 (R8 before R6) in
[`CONSENSUS_STORE_RECONCILIATION.md`](../design/CONSENSUS_STORE_RECONCILIATION.md);
[`DAEMON_REDB_STORE.md`](../design/DAEMON_REDB_STORE.md) D10/D11 (replay is the Rust
store's only writer before cutover); rules 00 / 05 / 16 / 21 / 22 / 23 / 47 /
50.

**Scope fence.** This round rules *placement* and the machinery placement
needs: a category test, an error taxonomy, the transaction scoping of the
validator's view, the pop symmetry, the shape of the validation crate, and
the instrument that measures its coverage. It does **not** rule the *content*
of any consensus rule (R4/R5/R6/R7/R9 own their rows and are cited, not
pre-empted), does not choose redb table layouts (DRS-E1), and does not name
behaviours the tree exhibits that no document has ever named — those go to
arm C of the test and are dispatched as batch **R8b** (§12), which is a
routing, not a deferral.

---

## 1. Ground at the pin

The eight rows share one shape: a chain rule whose only, or only
connect-path, enforcement is a storage-engine side effect. Two further
instances of the same fusion sit in `add_block`/`pop_block` and are in **no**
census row; this round names them because a faithful port of the eight rows
alone would rebuild both.

| Row | What the store enforces today (at `c405fac0a`) | Upstream twin | What a faithful port inherits |
| --- | --- | --- | --- |
| CEN-L1 | `add_spent_key`'s `mdb_cursor_put(…, MDB_NODUPDATA)` throws `KEY_IMAGE_EXISTS` (`lmdb/db_lmdb.cpp:1429–1440`; census cited :1411–1425), caught in `handle_block_to_main_chain` at `blockchain.cpp:6115` (census cited :6397) → block rejected | **Chain-wide:** CEN-I7 (bucket 1) — `check_tx_inputs`' per-input lookup, :3559/:3607. **Intra-block:** *none* — the per-input lookup cannot see a sibling tx of the same block (nothing is written yet); `check_for_double_spend` is dead (:5773 commented out); `prepare_handle_incoming_blocks` :6761–6787 dedups across an *incoming batch* as a drop verdict, not a consensus verdict | A storage flag as the only intra-block double-spend rule |
| CEN-L2 | `prev_id` must sit at height−1 (`BLOCK_PARENT_DNE` :962; missing parent `DB_ERROR` :959) | CEN-A2 (bucket 2, R1c): main-chain connect re-checks `prev_id == top_hash` fail-closed | `BLOCK_PARENT_DNE` as a consensus outcome |
| CEN-L3 | `BLOCK_EXISTS` / `TX_EXISTS` at write (:948–949, :1071–1074) | CEN-G1 (bucket 4, R5) for *listed* txs; **the miner tx has no upstream check at all** | Miner-tx uniqueness that exists only as a DB exception |
| CEN-L4 | Base `add_block` recomputes the block hash but stores txs under the header's *claimed* hashes; `blk.tx_hashes.size() == txs.size()` asserted at store time (`blockchain_db.cpp:455–480`) | Content/identity binding lives upstream (CEN-B6 identity; CEN-G2 resolution) | Two sources of truth for one fact, no rule about which wins |
| CEN-L5 | Input-type whitelist re-checked at write (:398–402); unknown bond-post kinds fatal (:363–366) | CEN-H5 | A duplicated check that can drift from its twin |
| CEN-L6 | Every stored output carries an outPk commitment; loud coinbase/emission amounts index as amount-0 (:424–434; `db_lmdb.cpp:1274–1277`, :1361–1368) | CEN-H8 (outPk count, R5), CEN-H17 (mask canonicity, bucket 1) | The amount-0 indexing choice — **named by no document** |
| CEN-L13 | Corruption/desync guards on write and pop paths (serve-credit re-parse, bond-counter overflow, journal-vs-tip belts, trim bounds, pruned-pop refusal) | — (not chain rules) | Sanity checks mixed into the rule set, some misfiled as rejections |
| CEN-L14 | Five write sites are flag-0 overwrites: serve-credit pass bits, bond records, budget accrual rows, witness rows, curve-root heights (`db_lmdb.cpp:5168–5181`, :5591–5615, :4916–4928, :9663–9672, :9618) | — | Silent overwrite as an unnamed semantic; the PC-D4 comment (`blockchain_db.cpp:775–786`) records the bug class it once masked |

**Fusion 1 — the store computes a consensus operand (no census row).**
`BlockchainDB::add_block` grows the curve tree and stores the next root
(`blockchain_db.cpp:641` `grow_curve_tree`, `:659–660`
`save_curve_tree_checkpoint` / `prune_curve_tree_intermediate_layers`, `:664`
`store_curve_tree_root_at_height(prev_height + 1, ct_root)`). CEN-B5 (bucket
1) then compares the *next* block's header root against that stored value
(`blockchain.cpp:5588` mismatch reject). The value a consensus rule compares
against is produced inside the storage layer. Principle "the validator
computes, the store persists" applied naively to the eight rows would leave
this exactly as it is.

**Fusion 2 — pop has the same shape and no validator (no census row).**
`BlockchainDB::pop_block` (`blockchain_db.cpp:724–927`) reverts six
independent journals whose order is load-bearing — the comment at `:786–794`
says so verbatim ("ORDER IS LOAD-BEARING … Reordering these two reverts …
makes `holdings_update_pop` … abort the pop") — and then computes
`trim_curve_tree(drained_count)` (`:899`). Nothing is *validated* on pop;
state is *undone*. A connect-shaped ruling has no pop analogue unless one is
written, and S-CHAIN-W's pop half would then get one by implementation
convenience — the accident R8 exists to prevent, arriving on the other half
of the same surface.

**The Rust store at the pin.** `shekyl-chain-store` has a lifecycle and a
write batch (S-TXN, PR #740) and increment 2's codecs, schema seal,
`Provenance`, and typed `properties` cells (PR #749). It has no connect, no
pop, no `spent_keys` table, and one live write at a time
(`store/shared.rs:15` `write_held: AtomicBool`; a second batch is
`StoreError::WriteInProgress`, `store/mod.rs:268`). Nothing here is
contradicted by the ruling; Q3 names what the ruling *adds* before a consumer
exists.

---

## 2. Q1 — the category test (RULED: standing, three arms, any rule, any surface)

**The test.** For any statement the tree enforces, ask: **would this still
have to hold if the consensus rules changed?**

- **Yes → arm B, a store invariant.** A statement about the store's own
  coherence — a table that is a set, a foreign key, a cell that decodes, an
  accumulator that does not wrap. Not versioned, not forkable, true under any
  rule set. Home: the store, as a **fatal** check (Q2), registered as an
  `SI-` row ([`STORE_INVARIANT_REGISTER.md`](../design/STORE_INVARIANT_REGISTER.md)).
- **No, and a ratified or ratifiable document names it → arm A, a consensus
  rule.** A statement about block legality — versioned, forkable, defined by
  the protocol, meaningful with no database. Home: the validation crate
  (Q8); the store never evaluates it and never produces its verdict.
- **No, and no document names it → arm C, unspecified.** A behaviour the tree
  exhibits that nobody decided. Home: **routed to a spec round as a named
  question** (here: batch R8b, §12). Arm C is not a deferral — it has no
  blocker and needs none; it is the ruling saying "this has never been
  named" without inventing an answer.

A statement can be A **and** B at once (key-image uniqueness is both — a
rule about spends *and* the fact that `spent_keys` is a set). That is not a
tie; it is the ordinary case, and it is exactly the case where the C++
collapsed both into one implementation and only the storage half survived.
Both halves are built, each in its home, and the B half is a belt that never
decides anything (Q2).

**Binding.** The test is a **standing rule for any rule on any surface**,
applied by the surface's owner at design time without convening a round. A
row the test cannot decide goes to **arm C**, never to a round — a round is
where arm-C questions get *answered*, not where the test gets *applied*.
This is what keeps R9 from arriving with the next eight rows.

**Worked on the two cases that motivated arm C.** "A second freeze of the
same shard is refused" (CEN-L10, `MDB_NOOVERWRITE`): the registry row is
CREATE-only under any rule set → B, and the ratified spec also names it → A;
both exist and both stay. "A bond record written twice overwrites silently"
(CEN-L14): it would not *have* to hold under a rule change (nothing depends
on overwrite), and no document names overwrite as intended → **C**. Forcing
it into A or B would manufacture a decision.

---

## 3. Q2 — three error classes and the conversion ban (RULED)

### 3.1 The taxonomy

| Class | Meaning | Produced by | Visibility | Handling |
| --- | --- | --- | --- | --- |
| **`InvalidBlock { rule: CenRow, … }`** | A consensus verdict: the block is illegal under `RuleSet` (Q7). Carries the census row it fails | the validation crate **only** | caller-visible, expected, peer-attributable | rejected; the store is never reached |
| **`StoreInvariantViolated(StoreInvariant)`** | The store was handed something that breaks an `SI-` row: either the validator has a hole or the file is corrupt. Carries the `SI-` id | the store, at the write | **fatal, internal** | connect **halts** (§9.6); debug builds panic; **never** caught and converted |
| **`StoreCannot`** | A capability refusal: read-only session, write in progress, pop below the retained undo log / prune watermark | the store, before the write | operator-visible | retry or operator action; **not** a verdict on the block, **not** a coherence failure |

The third class exists so that a refusal is not mapped onto either of the
other two: "cannot pop that deep" is neither an invalid block nor a corrupt
store, and the first person who needs an error for it will otherwise reach
for the nearest one.

### 3.2 Why the belt stays and what it now means

A store-side constraint that produces a user-visible "invalid block" is a
**hidden rule** — L1 at `db_lmdb.cpp:1438` is the instance. The same
constraint producing a fatal is a **belt**: the validator owns the rule and
the store cannot be made incoherent, and the store's copy never decides an
outcome anyone downstream sees. One source of truth *and* defence in depth,
without two sources of truth, because the second is never allowed to speak
to the caller.

### 3.3 The ban, and its gate (lands with this PR)

1. No `From`/`Into`/`TryFrom`/`TryInto` between any two classes. `InvalidBlock`
   is a validation crate type; `StoreError` (whose variants class as invariant
   or cannot — the mapping is in the register's §3) is a store crate type;
   neither converts into the other.
2. **`shekyl-chain-store` never names `InvalidBlock`.** The store crate does
   not know the consensus verdict type exists.
3. No `match` arm anywhere maps a `StoreError` / `StoreInvariant` value onto
   an `InvalidBlock` value.

`scripts/ci/check_store_error_conversion_ban.py` asserts (1)–(3) over
`rust/` and asserts its own subject first (`pub enum StoreError` parsed with
≥ 1 variant; rule 47). (1) and (2) are live today; (3)'s pattern is armed now
and has nothing to match until the validation crate exists — the gate reports
which. Wired into `docs-gates.yml`; `--selftest` proves each clause red.

The code form of the taxonomy — `StoreError::class()` returning
`Invariant | Cannot | Engine`, and the `StoreInvariant` enum as the payload of
the invariant arm — lands with **DRS-E1 increment 2.5** (§14), the same
increment that gives them their first producer. Rule 23: no variant before
its producer.

---

## 4. Q3 — one transaction, one brand (RULED)

**The requirement.** The `ChainView` the validator reads is **projected from
the write transaction that will apply the block.** Open the write batch,
project a read view from it, validate against that view, apply inside the
same batch. A design in which validation takes one snapshot and the write
takes another is **rejected**, including when a single-threaded block
processor makes it work today: the defect is a concurrency property, invisible
to the comparator (the same blind spot as `write_held` and A4's flags), and it
surfaces only when someone adds the parallelism.

**The type.** `ChainValid<'id>` is minted only inside
`ChainStore::connect(|batch: WriteBatch<'id>| …)` where the closure is
higher-ranked over `'id` and `WriteBatch<'id>` carries an **invariant brand**
(`PhantomData<fn(&'id ()) -> &'id ()>`). A `ChainValid` from one batch handed
to another's `apply` is a **compile error**. The plain-lifetime version
(`WriteBatch::view(&'b self) -> ChainView<'b>`) is rejected: with two batches
alive, `&batch1` and `&batch2` coerce to a common shorter region and the
cross-handoff type-checks.

**The recorded dependency.** At the pin, one-live-write (`write_held`,
`store/shared.rs:15`) is what makes even the plain-lifetime version sound —
two batches cannot coexist. With the brand, one-live-write is a **liveness**
property only (a second writer waits or is refused); it is no longer what the
TOCTOU guarantee rests on. This is written down because it is the thing the
first parallel-read optimisation would otherwise silently delete
(reversion trigger 2, §13).

**Lands as DRS-E1 increment 2.5**, before any consumer of `WriteBatch`
exists (§14).

---

## 5. Q4 — the store computes nothing consensus-visible (RULED)

Every value a consensus rule compares against — a block hash, a tx hash, a
key image, the curve-tree root, a weight, a cumulative difficulty — is
produced by the validation crate (or a crypto crate it calls) and **handed**
to the store. The store derives **indexes** (height → hash, output id → tx)
and nothing a rule reads. `ChainView` exposes **recorded** facts (the root
stored at height *h*), never computed ones.

**Fusion 1 resolved.** The curve tree is state the store *persists*; the
**state transition** — growing the tree with this block's matured leaves and
producing the root the *next* block's CEN-B5 will be checked against — is a
consensus-owned function in the validation crate (it calls the curve-tree
crate), run inside the same batch after validation. `connect` stores the
root it is handed. The store's belt: the recorded root at height *h*+1 is
written **once** (declared `insert`, Q6c) — `SI-4`.

**L4 resolved.** The store-side block-hash recompute is **deleted, not
moved**: CEN-B6 defines identity and the validator derives it once from the
header; a `ValidatedBlock` carries its txs as `(TxHash, Tx)` pairs, so the
count belt is the type, and "claimed hash vs content" cannot diverge because
there is one value.

---

## 6. Q5 — pop is reverse replay (RULED)

**The rule.** `connect` writes, into **one** LIFO **undo log** keyed by
height, the pre-image of every cell it overwrites and the tombstone of every
key it inserts. `pop` replays the log entry for the tip height **in reverse
and computes nothing.** The six journals and two height conventions of
`pop_block` (`blockchain_db.cpp:724–927`) collapse into one sequence, and the
`:786–794` ordering comment has no successor because the order *is* the log's
order.

**The one computed inverse, checked not trusted.** The curve tree's trim is
the single operation whose inverse is computed rather than replayed
(`trim_curve_tree(drained_count)`, `:899`). After trim to height *h*, the
tree's root must equal the **recorded** root at *h* — `SI-5`, fatal. The
recorded root is the oracle for the computed trim; the trim never becomes an
oracle for anything.

**Depth is a capability.** The undo log is retained to the store's pop depth
(the prune watermark). A pop below the retained log is **`StoreCannot`**,
never a partial pop and never an invariant violation. Pop at genesis is
`StoreCannot`. The log's top entry is always the tip height — `SI-6`.

This also dissolves the archival pre-image journals' *ordering* problem
without touching their *content*: what they record is exactly what the undo
log needs, recorded once at connect in write order.

---

## 7. Q6 — the eight rows (RULED), the intra-block table, and declared writes

### 7.1 Per-row disposition

| Row | Arm | Placement | Belt | Census move (this PR) |
| --- | --- | --- | --- | --- |
| **CEN-L1** | A + B | **Rule minted:** *no key image may appear twice among a block's inputs* (the intra-block half; the chain-wide half is CEN-I7's clause, evaluated against the same `ChainView`) — validator, block-level set pass | `SI-1` `spent_keys` insert-unique, fatal | **4 → 2**, class `ratified` (this round). CSR register row added, UNREVIEWED |
| **CEN-L2** | B | The rule is CEN-A2's (bucket 2, R1c); nothing to mint | `SI-2` parent is the block recorded at height−1 **and** the tip, fatal. `BLOCK_PARENT_DNE` stops being a consensus outcome | **4 → 3** (absorbed into A2; belt registered) |
| **CEN-L3** | B + corollary | Main-chain block-hash uniqueness follows from `SI-2` (one block per height, parent = tip). Listed-tx uniqueness is CEN-G1's (R5). **Miner-tx uniqueness is a corollary of CEN-F5** (coinbase height binding, bucket 4, R5): two main-chain miner txs cannot share a hash while F5 holds. Alt blocks are stored whole (K3's idempotent put), so `txs` never sees an alt miner tx — the same-height alt collision does not reach this table | `SI-3` `txs` insert-unique, fatal | **4 → 3** with a **reversion clause: if R5 rules F5 other than as-is, L3's miner-tx half is re-derived and a validator rule minted.** Until R5 rules, `SI-3` holds regardless — the corollary is not implemented before its parent |
| **CEN-L4** | A (upstream) | Identity is CEN-B6's; the validator derives every hash once; the store recompute is **deleted** | none (the count belt is the `(TxHash, Tx)` type) | **4 → 3** |
| **CEN-L5** | — (dissolves) | `ValidatedBlock`'s inputs are a Rust `enum`; the whitelist is match exhaustiveness. CEN-H5 remains the rule | none | **4 → 3** |
| **CEN-L6** | A (upstream) + **C** | Presence: the typed output carries a `Commitment` by construction (CEN-H8/H17 remain the rules). **Amount-0 indexing of loud amounts: arm C → R8b-2** | none | **4 → 3** (the store constraint leaves; R8b may mint a new row if the indexing is ruled consensus-visible) |
| **CEN-L13** | B | Not chain rules. Classed: cell decode → `SI-7`; accumulator arithmetic → `SI-8`; journal-vs-tip → `SI-6`; trim bounds → `SI-5`; **pruned-pop refusal → `StoreCannot`** (a capability, misfiled as a guard) | as classed | **4 → 3** (register owns them) |
| **CEN-L14** | **C** ×5 | Each absence is an unnamed semantic → **R8b-3…7**. The **mechanism** is ruled now (§7.3): after R8b each site is a declared `insert` or `upsert`; silent overwrite is unrepresentable | — | stays **4**, class `examined-disposition` (R8 examined; R8b names) |

### 7.2 The intra-block table

Every store uniqueness invariant currently enforced by sequential
`MDB_NODUPDATA` puts inside one transaction has an intra-block twin that the
split **removes** rather than relocates. One line per invariant:

| Store invariant | Chain-wide rule (validator) | Intra-block rule (validator, block-level set pass) |
| --- | --- | --- |
| `SI-1` `spent_keys` is a set | CEN-I7 | **CEN-L1 as minted** — no key image twice in one block |
| `SI-3` `txs` keyed by hash | CEN-G1 (listed), F5-corollary (miner) | no listed tx hash twice in one block (today only `prepare_handle_incoming_blocks` :6779's batch drop verdict sees it) |
| `SI-2` one block per height | CEN-A2 | — (one block) |
| `SI-4` one root per height | CEN-B5 reads it | — |
| **output keys** | **none** — Monero permits duplicate output public keys and the tree leaf is `key ‖ commitment ‖ …` | **arm C → R8b-1.** A decision, not a placement |

### 7.3 Declared writes (mechanism, RULED)

The store exposes exactly two write verbs on keyed tables: **`insert`**
(fatal on an existing key — the `SI-` row names which) and **`upsert`**
(declared: the call site states that overwrite is intended). There is no
third verb and no flag. A site that has not chosen is a compile error, not a
silent overwrite. This is what makes the five R8b answers **implementable as
one word each** and what permanently kills the L14 class.

---

## 8. Q7 — `RuleSet` is an explicit input (RULED)

`validate(candidate, &view, &rule_set)`. A `ChainValid` is valid **under the
rule set it was checked against** and carries its `RuleSetId`; `connect`
asserts `rule_set.id == schedule.version_at(height)` and refuses otherwise
(`StoreCannot`, not `InvalidBlock` — the block was not judged). The hardfork
version is an explicit input in the C++ too
(`prevalidate_miner_transaction(b, height, hf_version)`, `blockchain.cpp:1393`;
`ver_non_input_consensus(tx, tvc, version)`, `tx_pool.cpp:237`); it is **not**
a `ChainView` fact today, and the shipped schedule is one entry
(`hardforks.cpp:35–36`, `{1, 1, 0, …}`), so its absence from a design could
not manifest — the `on_block_popped` shape.

**Coupling to R4.** Whether activation becomes state-dependent (signalling)
is R4's question. If R4 rules it so, `RuleSet` becomes derivable from
`ChainView` and `ChainValid` still carries the id it was checked under. This
round fixes only *where the version enters*.

**`AdmissionPolicy` is a separate input**, never folded into `RuleSet`: the
nine policy-flagged census rows (relay/pool policy) are not consensus and do
not fork the chain. The flag partitions first (§9.4).

---

## 9. Q8 — the validation crate, the transition, and the coverage instrument (RULED)

### 9.1 Shape

One crate. Input: the candidate, a `ChainView` (narrow, read-only trait:
`has_key_image`, `block_at`, `output_at`, `root_at`, …), a `RuleSet`.
Output: `ChainValid<'id>` or `InvalidBlock { rule: CenRow, … }`. **No store
handle, no redb types, no `ChainStore` import.** Every rule is unit-testable
against a mock view with no database — the capability the C++ never had and
the reason CEN-L11-class defects survive.

**Pool admission uses the same crate.** `tx_form(tx, &rule_set)` (stateless)
and `tx_against(tx, &view, &rule_set)` (stateful) are the two functions block
connect calls per tx; the pool calls the same two with a `PoolView` decorator
over `ChainView` (chain + pool spends) and applies `AdmissionPolicy`
separately. The C++ already shares these two stages between pool and connect
(`tx_pool.cpp:237` / `:312`); the ruling keeps that and gives it one home. A
second validator for the pool is "validation all over the place" reintroduced
at the moment it was removed.

### 9.2 Transition — replay-that-validates, no shim

D10 already requires derived state to be rebuildable by replaying local
blocks, so replay is the Rust store's **only writer before cutover** (D11).
Replay-that-validates is the same work with the validator attached: every
canonical block passes through `validate` before `connect`. Therefore:

- the validation crate is on the critical path **ahead of S-CHAIN-W**, not
  behind it; the DRS plan amendment (§14) schedules it so;
- an FFI shim over the C++ validator to construct `ValidatedBlock` is
  **rejected** — the private constructor would be a fiction at that boundary;
- rules arrive as surfaces port (surface-bound) **and** as their own
  increment (surface-free; §9.5), never bolted on afterwards.

### 9.3 The oracle is graded, not compared

Agreement with the C++ on a CHECKED-CONFORMANT row is evidence; agreement on a
DIVERGENT row is **`Failed(ReproducedKnownDefect)`** — `conformance.rs`'s
`grade()` already implements the inversion, and the validator's oracle points
at the same grader (its second consumer). A canonical block the Rust
validator **rejects** is a *finding of undetermined direction* — Rust bug,
C++ defect, or genuine divergence — and routes in as **UNREVIEWED**; recording
it as DIVERGENT on arrival presumes the C++ is right.

**Replay sees only blocks the C++ accepted, so it can catch over-rejection
and never under-rejection.** The negative fixture is therefore the
deliverable per rule, the replay run the regression check. Three disciplines,
rule 47 at rule granularity: **assert the row** (`InvalidBlock { rule }`
equals the CEN id, not "some rejection"); **boundary pairs** (the last
accepted and first rejected value); **mock view** (no database).
Implementation proceeds in **dependency order** — a corollary implemented
before its parent passes for the wrong reason and no replay surfaces it
(CEN-L3 ⇐ F5 is the standing example).

### 9.4 Coverage: the type and the gate

`ChainValid` carries **`RuleCoverage`** — the set of CEN rows checked — and
coverage is **persisted with anything it writes** (the `Provenance` pattern:
`ApplyPolicy` is what the session applies, `Provenance` is what the file has
ever skipped, only `FULL` is parity evidence). A validator implementing 30
rules and one implementing all of them therefore produce **different**
evidence, and only complete coverage counts as parity evidence.

The **completeness gate** computes from the census, never declares, and
**partitions by flag first**: consensus (`C`) and policy (`P`) rows are
separate denominators, because `implemented / 130` would have counted five
relay-policy rows toward consensus coverage — proximity promotion arriving
through the measurement. For each flag it emits **two numbers together,
always** — a format constraint, not a process:

```text
consensus: implemented I / enforced E   ratified R / enforced E   (E = C-rows − bucket 3)
policy:    implemented I / enforced E   ratified R / enforced E   (E = P-rows − bucket 3)
```

and prints the definition of `E` it used. Quoting the first number carries
the second, so "parity achieved, ratification pending N" is what travels.
Figures at this PR are in §10.

### 9.5 Parity first — and why the port is the enabler of R6/R7/R9, not a detour

Parity is the starting point and correctness is the destination; you cannot
ratify a rule you have not characterised, and porting a rule into a pure
function with a mock view and a boundary pair **is** how you characterise it.
The bucket-4 consensus rows are today buried in `blockchain.cpp` where
ratifying one means reading around it; after the port each is an isolated
function with a fixture pair. **The port converts the unratified rows from
ratify-by-reading-around into ratify-an-isolated-function-with-a-boundary-pair.**
That is an accurate claim about what changes; it does not claim ratification;
and it gives R6/R7/R9 an input format they do not currently have.

**Surface-bound vs surface-free.** Only the rows that name a store file have a
storage surface to arrive with (nineteen rows at the pin; R8's eight are most
of them). Weight limits, fee floors, unlock windows, PoW, attestation have
nothing in the store to port, so "each migration inputs its rules" delivers
roughly the store-adjacent subset and leaves the rest with no arrival event.
The fix is one partition inside the same family: surface-free rules get
their own increment, **DRS-E6**, so they have a named home and a schedule.
The completeness gate is what forces E6 before a D2-closed cutover; the
partition itself is the DRS plan amendment's (§14).

### 9.6 Halt visibility

A `StoreInvariantViolated` halts connect. A node halted on connect while
still serving reads presents a stale tip as current. `ChainTip` therefore
carries `connect: ConnectState::Live | Halted { at_height, class }`, exposed
through `get_info`, so a wallet can tell "safe" from "silently wrong". No
peer penalty, no process exit.

---

## 10. Effects on the census figures (computed, this PR)

Cross-tab at `c405fac0a` before this ruling, C = consensus-flagged,
P = policy-flagged, columns = buckets 1/2/3/4:

```text
before   C [86, 39, 5, 34] = 164     P [1, 4, 0, 4] = 9     total 173
moves    L1 4→2 · L2 L3 L4 L5 L6 L13 4→3 · L14 stays 4      (all C)
after    C [86, 40, 11, 27] = 164    P [1, 4, 0, 4] = 9     total 173
```

| Figure | Before | After | Where quoted |
| --- | --- | --- | --- |
| live bucket-1/2 (all flags) | 130 (87 + 43) | **131** (87 + 44) | census §1 (re-derived this PR) |
| bucket 4 (all flags) | 38 | **31** | census §1/§10 |
| bucket 3 (all flags) | 5 | **11** | census §1 |
| consensus enforced `E` | 159 | **153** | gate definition (§9.4) |
| consensus ratified / `E` | 125 / 159 | **126 / 153** | gate output |
| consensus unratified (bucket 4, C) | 34 | **27** | §9.5 |
| policy ratified / `E` | 5 / 9 | 5 / 9 | unchanged |
| CSR register tally (CONFORMANT / DIVERGENT / UNREVIEWED) | 126 / 2 / 2 | **126 / 2 / 3** (CEN-L1 born UNREVIEWED) | CSR §5.4.1 tally comment; `check_conformance_coverage.py` derives it |

**A stale figure found while re-deriving.** Census §1 read *"twenty-seven of
them are UNREVIEWED until P0f reviews them"* at the pin. The register's own
count was 2 (CEN-L8 failed closed, CEN-I19 re-amended by PL-D3): P0f slices 9
and 10 closed the 27-row backlog on 2026-09-11 at `eb1b60198` (CSR §5.4.1,
"the backlog closes"), and the census sentence — which asserts-is, not
records-was — was not re-derived. Corrected in this PR with the derivation
named, per rule 91's sweep; the register is the owner of that figure, the
census header a quotation of it.

Every cell the PR moves is in §7.1's last column; the row-level `UPDATE` in
the census carries this doc's section. The gate follows silently; the
documents do not — which is why the figures are re-derived here, in the
landing PR, and not three weeks out.

---

## 11. The store-invariant register (new artifact, gated at birth)

[`STORE_INVARIANT_REGISTER.md`](../design/STORE_INVARIANT_REGISTER.md) is the arm-B
home: one `SI-` row per invariant with the table it constrains, the rule
that makes it hold, the row it came from, a `Status` (`ruled` → `built`;
`retired` when the table is deleted), and an `Anchor` (the
`StoreInvariant::` variant once built; empty while `ruled` or `retired`).
Eight rows at birth
(SI-1…SI-8, from §7.1 and §5–§6).

**Its gate, `scripts/ci/check_store_invariant_register.py`,** is the
bijection `check_redb_schema_bijection.py` already has, on a different pair:
every `built` row's anchor resolves to a `StoreInvariant` variant in
`shekyl-chain-store`, and every variant is named by exactly one `built` row.
Subject assertions (rule 47): the register parses with ≥ 1 row, ids are
`SI-1…SI-n` dense and unique, statuses are from the closed vocabulary, and if
any row is `built` the enum must exist. At birth all rows are `ruled` and the
enum does not exist; the first S-CHAIN-W increment that flips a row to
`built` must add the variant or the gate is red. `--selftest` proves each
failure class.

---

## 12. Arm C — batch R8b, "unnamed write semantics" (routed, not deferred)

Seven questions the test could not decide because no document has ever named
the behaviour. Added to census §10 as batch **R8b**; each answer is one word
at a declared write site (§7.3) or one new census row.

| Id | Question | Origin |
| --- | --- | --- |
| R8b-1 | Is output-public-key uniqueness a consensus rule? (Monero permits duplicates; the tree leaf is `key ‖ commitment ‖ …`, so duplicates make distinct leaves only if commitments differ) | §7.2 |
| R8b-2 | Is amount-0 indexing of loud coinbase/emission amounts a consensus-visible fact or a storage index choice? | CEN-L6 |
| R8b-3 | Serve-credit pass bits: is a second write `insert` (fatal) or `upsert` (intended)? | CEN-L14 |
| R8b-4 | Bond records (JoinMarket `p_id`): same question | CEN-L14 |
| R8b-5 | Budget accrual rows: same question | CEN-L14 |
| R8b-6 | Witness rows: same question | CEN-L14 |
| R8b-7 | Curve-root heights: Q4 already ruled **`insert`** (`SI-4`, §5). This question confirms that ruling at the L14 write site, or names a legitimate rewrite — which is a **reversion of SI-4** (§13), not a silent override | CEN-L14 / Q4 |

---

## 13. Reversion clause for this ruling (rule 21)

The ruling is rejected-now-with-reopeners in the same shape as what it
disposes. Two named triggers; re-evaluation is a census §10 batch, not a
drive-by:

1. **The store gains a constraint that a consensus rule *cites* as its
   mechanism.** Then the rule/invariant separation has blurred — a rule is
   again "implemented by" a table property — and Q1's test needs
   re-anchoring for that row. Falsify by: a census row's `site(s)` column
   naming a `shekyl-chain-store` path as the rule's enforcement, or an `SI-`
   row whose "consensus twin" cell is empty while a rule depends on it.
2. **One-live-write is relaxed** (a second concurrent `WriteBatch` becomes
   representable). Then the brand's soundness changes class from type-level
   to runtime-dependent and the TOCTOU guarantee of Q3 must be re-derived.
   Falsify by: `store/shared.rs`'s `write_held` gate removed or made
   per-table, or `StoreError::WriteInProgress` deleted.

Absent either trigger, the ruling stands; the passage of time discharges
nothing (rule 22).

---

## 14. What lands with this ruling, and what it hands on

| Lands in **this PR** | Carrier for what it hands on |
| --- | --- |
| This document; census row moves + re-derived figures (§10); §10 R8 → RULED, R8b added; §7 decision-log entry; CSR §6.2/§8/§9 + register row CEN-L1 | — |
| [`STORE_INVARIANT_REGISTER.md`](../design/STORE_INVARIANT_REGISTER.md) + `check_store_invariant_register.py` (wired) | rows flip `ruled → built` in the S-CHAIN-W increments that build them |
| `check_store_error_conversion_ban.py` (wired; clauses 1–2 live, clause 3 armed) | the PR that mints `InvalidBlock` turns `verdict_defs == 0` into a failure (today the gate prints 0 so green-with-zero is not silent); falsify by that raise *[2026-09-15: **fired** — DRS-E6 increment 1 minted `InvalidBlock` in `rust/shekyl-chain-rules/src/verdict.rs` and raised the gate in the same PR; zero definitions is now `subject absent`, `CHAIN_RULES_CRATE.md` §7]* |
| Index §2: `C2-R` row appended (Q1…Q8), `SI-` family registered, DRS row (S-CHAIN-W's R8 blocker discharged; increment 2.5 named as its precondition) | — |
| **DRS-E1 increment 2.5** (named, not built here): brand-via-closure `WriteBatch<'id>` + higher-ranked `connect`, `StoreError::class()`, `StoreInvariant` enum, `insert`/`upsert` verbs, `StoreCannot` shape | the next `shekyl-chain-store` PR, **before any consumer of `WriteBatch`**; falsify by `rg "PhantomData<fn\(&'" rust/shekyl-chain-store/src` |
| **DRS plan amendment** (named, not written here): the validation crate + `ChainView` + `RuleCoverage` + completeness gate on the critical path ahead of S-CHAIN-W; replay-that-validates as D11's mechanism; **DRS-E6** surface-free rules row; the E6 partition table (surface-bound 19 / surface-free rest, from the census location column); `ChainTip.connect` in `get_info` | a `DAEMON_REDB_STORE.md` PR following this one; falsify by the DRS §11 plan table carrying an E6 row *[2026-09-15: the work-breakdown table is DRS **§7**, not §11 — §11 is format migration; the row landed there as **DRS-E6** with **DRS-D12** and **§7.5**, and the falsifier fired as written apart from the section number]* |

Neither carried item is a deferral in rule 22's sense: both have a named
home, a named PR, and a falsifier, and neither was scoped into *this* PR —
this PR's scope is the ruling and the gates the ruling itself names.

---

## 15. Round log

| Date | Event |
| --- | --- |
| 2026-09-14 | R8 surfaced as the blocker for S-CHAIN-W during DRS-E1 increment 2 (PR #749's sequencing disclosure; falsifier: this row RULED). |
| 2026-09-14 | **Pass 1 (Rick → agent).** Frame: rule vs invariant; validation is a type; store computes nothing; keep the belt, relabel it fatal; TOCTOU scoping; per-row starting positions; three outputs so there is no R9. Agent verified anchors, endorsed, and added: fusion 1 (curve root, `blockchain_db.cpp:641–664`); L3 is a corollary of F5; pop has the same fusion (fusion 2); intra-block duplicates are a category; fork version is absent from the context; pool admission and the transition are scope questions; three error classes not two; halt visibility. |
| 2026-09-14 | **Pass 2 (Rick → agent).** Plain lifetimes overstate — brand via closure, one-live-write dependency recorded; undo log instead of a revert function (agent) accepted; graded oracle not comparison; replay catches over-rejection only → negative fixture per rule; partial validator must not produce a fully-trusted type → `RuleCoverage`; denominator computed not declared. Count discrepancy (130 / 168 / ≈159) resolved by cross-tabulating flag × bucket: C `[86, 39, 5, 34] = 164`, P `[1, 4, 0, 4] = 9`; **flag partitions first.** E6 partition; parity-first rationale ("the port is the enabler of R6/R7/R9"). |
| 2026-09-14 | **Draft instructions (Rick).** Third arm for the test; standing test binding future rows; re-derive figures in the landing PR; register gated at birth; conversion-ban gate lands with the ruling; reversion clause with two triggers. This document. |
| 2026-09-14 | **Landing PR closeout (rule 95 / index §8).** Banner `CLOSED-as-record`; file moved to `docs/completed/` in the same change. Merge of the landing PR is the signature. |
