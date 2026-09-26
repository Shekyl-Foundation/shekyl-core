# DRS-E3 — the curve-tree writer: pre-flight

**Status:** OPEN — Round 0 executed 2026-09-26 at `dev@1aa48eff9` (#864
merged; #861 merged); **Round 1 RULED 2026-09-26 (maintainer, on PR #873)** —
`CTW-Q1` ruled with a corrected justification, `CTW-Q2` **dissolved** (the
table it asked about does not survive), `CTW-Q3` default, `CTW-Q4` ruled with
a different primitive, `CTW-Q5` ruled with a different justification,
`CTW-Q6` ruled against the default; `CTW-Q7` posed on this round. Each row of
§8 carries its ruling line-locally. Identifier families **`CTW-`** (findings)
and **`CTW-Q`** (questions), registered in `IMPLEMENTATION_INDEX.md` §2 with
this file (rule 94 §1; `check_index_prefix_uniqueness.py` branch (a)). Parent
plan: [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) — the **DRS-E3** node of
the lane graph (`E1 → E2 → E3 → E4 → E5`), *"curve storage only"*; the
boundary statement it builds against is [`DRS_E1_SCURVE.md`](DRS_E1_SCURVE.md)
§2.3. Template: the DRS-E1 pre-flight shape (`CHAIN_RULES_CRATE.md` §7.5.1
applied to a store increment), as `DRS_E1_SCURVE.md` used it.

**One sentence.** The daemon store's connect has an empty `[E3 hook]` at
phase 3 and records a curve-tree root it was *handed* (`facts.root_after`,
borrowed from the LMDB record on replay — `DRS_E2_REPLAY_DRIVER.md` RD-Q9);
E3 makes the Rust stack **grow the tree itself** — the matured outputs of
blocks `h − 60` and `h − 10` drained in order, `hash_grow` over the frontier
into the typed `curve_tree_*` tables S-CURVE froze — so the root is derived
by the validator, the borrowed one becomes an oracle for the replay, and the
consumers waiting on a real tree (E6's CEN-I13 / I15 / H19-verify, CEN-F17,
DRS-D3c) get one.

**The line this document is written on.** We are building our own store in
Rust. The C++ is evidence about what the chain *requires*, not a
specification for how to store it: LMDB's tables answer LMDB's constraints
(one integer key, no journal, expensive reverse lookups), written by Monero
for Monero. Where a requirement is a pure function, it is a function here,
not a table; where a table duplicates facts the store already holds, it is a
query or a checked view. Three of the C++'s five pending-side tables and its
pop-time tree recompose do not survive that test (§3.7).

---

## 0. Ground

Read at `dev@1aa48eff9`. Every citation below is against that tree unless it
says otherwise — re-read them, do not diff around them. Rulings this
document is downstream of and does not re-open: `PDM-Q6` (the transaction
unit), `PDM-Q12` (the freeze pipeline retires), `PDM-Q11` (`D_max`'s shape),
C2-R8 principle 3 (*the store may persist a consensus fact computed by a
consensus-owned function inside the write transaction; it never computes
one*), S-CURVE `SCU-Q1…Q3` (the three typed tables and their keys), `SCW-19`
(`curve_tree_roots[h+1]` written on every connect, grown or not — a recorded
divergence from the C++ with its pass condition; E3 changes where the
*value* comes from, never whether the row is written), E6 slice 6 Q8 (I13's
operand is the depth *at* `ref_height`).

---

## 1. Preconditions, as found at the pin

1. **The hook is one comment line, and it names a retired step.**
   `store/connect.rs:409` — `// ---- 3. [E3 hook] pending leaves → drain →
   grow → segment freeze --`; nothing else. Step 4 at `:411–412` writes
   `curve_tree_roots[height + 1] = facts.root_after` unconditionally through
   `open_insert_table(CURVE_TREE_ROOTS, StoreInvariant::RootRewritten)`
   (SI-4). "Segment freeze" is `PDM-Q12`'s retirement (2026-09-18): *"the
   segment freeze has nothing left to freeze under this unit"* — so
   `process_archival_segment_freezes_at_height` (`blockchain_db.cpp:632`) is
   not ported, and the comment is corrected **before** any body lands, or
   the first reader implements a retired phase (CTW-1).
2. **The root is borrowed, and the file says so.** `ConnectFacts.root_after:
   Fact<CurveTreeRoot>` (`connect.rs:187`) with `Origin::PassedThrough`
   (`:109–116`); `shekyl-chain-ingest`'s facts table (`facts.rs:56`) lists it
   as *"no source yet — nothing here grows the tree"*; the scenario supplies
   `placeholder_root_after` (`scenario.rs:167`, `:305`). `Provenance::
   passed_through` decomposes to **six** — four composed, two no-source-yet
   — and `root_after` is one of the two (`facts.rs:29–57`). A file with that
   bit set is, by `connect.rs` §3.8's contract, not parity evidence.
3. **The three tree tables exist, typed, written by nothing.** `schema.rs:524`
   `curve_tree_leaves: u64 → Coded<TreeLeaf>`, `:531` `curve_tree_layers:
   (u8, u64) → Coded<LayerHash>` (the tuple key `SCU-Q3` ruled — the C++'s
   `(layer << 56) | chunk` packing is gone with no KAT to maintain; **do not
   reintroduce it**), `:537` `curve_tree_meta: () → Coded<CurveTreeState>`.
   `CurveTreeState`'s doc (`codec/curve.rs:126–138`) is written *for E3*:
   *"Once the grow path replaces EMPTY, this field is that live root … and
   the summary read refuses a disagreement (SI-12)."* That refusal is the
   first belt E3 arms.
4. **The pending side is five untyped tables**, all C++-shaped:
   `pending_tree_leaves`, `pending_tree_drain`, `block_pending_additions`
   (`schema.rs:504–513`, `&[u8] → Unshaped`, BE composite keys),
   `output_to_leaf`, `leaf_to_output` (`:516`, `:519`, `u64 → Unshaped`).
   §3.7 disposes of each.
5. **The reads E3 must satisfy are landed.** `ReadSnapshot::curve_tree()`
   (C1), `root_at(h)` (C2), `leaf(pos)` (C3) — `store/curve_reads.rs`; SI-11
   (dense leaves) and SI-12 (a grown summary's root is the live root) are
   minted (`store/invariant.rs:140`, `:159`) with no writer to hold them
   against.
6. **The arithmetic exists in Rust, outside the store's reach.**
   `shekyl_fcmp::tree::{hash_grow_selene, hash_grow_helios, construct_leaf}`
   (`tree.rs:102`, `:158`, `:506`). The daemon store cannot take
   `shekyl-curve-tree` or `shekyl-fcmp` (S-CURVE §3.4; `chain-store/Cargo.toml`
   has neither); `shekyl-chain-rules` takes `shekyl-crypto-pq` and not
   `shekyl-fcmp` (`chain-rules/Cargo.toml:25–52`). `construct_leaf(O, C, CM)`
   takes the output key, the commitment and the `0x07` entry's point
   (`PL-D3`) — **the leaf derivation is unchanged by `PDM-Q6`**: the unit
   ruling re-keyed the archival good (prunable bodies), and a leaf is made
   from the output's points, which live in the permanent prefix and output
   rows. Confirmed at source, not assumed.
7. **Maturity is a pure function of `(height, is_miner)`.**
   `blockchain_db.cpp:554–567`: both output-target arms compute
   `height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW` (60) for the miner tx and
   `height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE` (10) otherwise; the third
   arm is unreachable (CEN-L11). **No per-output `unlock_time` enters** —
   `tx.unlock_time` reaches `add_output` (`:402`, `:409`), never the
   maturity. So at connect height `h` the drain set is exactly *the coinbase
   outputs of block `h − 60`* and *the listed outputs of block `h − 10`*,
   both readable from tables `connect` already writes (`block(h)`, the
   output rows, the retained prefix for `CM`), both inside every retention
   (`60, 10 ≪ D_max`). The pending table stores nothing the store does not
   already hold (CTW-10; §3.7).
8. **The C++ path's remaining mechanics, read** (`blockchain_db.cpp:560–656`,
   `db_lmdb.cpp:8028–8060`, `:8403`, `:8616`, `:9285–9291`): drain in
   `(maturity, output_id)` key order assigning `TreePosition = leaf_count +
   i`, with `pending_tree_drain` and `block_pending_additions` as pop
   journals (*"tracked by its global output index for exact reversal"*,
   `:539`); grow if anything drained; every 10,000 blocks a checkpoint row
   and a prune of layer chunks `1..depth−2` fully below the previous
   checkpoint, because *its pop recomposes those layers from layer 0*
   (`trim_curve_tree`, `:878`). The C++'s own TODO at `:640–645` records the
   checkpoint work as latency work.
9. **Grading** (`PDM-Q1` §9.2, `ARCHIVAL_PRUNED_DAEMON_MODE.md:1873–1889`):
   `curve_tree_roots` KEEP-C; layer 0 KEEP-C (set A); layers `1..depth−2`
   CACHE, *already pruned by every node*; `curve_tree_leaves` CACHE;
   `curve_tree_meta` / `curve_tree_checkpoints` CACHE / KEEP-C. CACHE means
   re-derivable: nothing depends on those rows for correctness.
10. **Consumers queued by name** (§7): FOLLOWUPS `:702` (CEN-I13), `:706`
    (CEN-I15 / H19-verify), `:675` (CEN-F17), `:221` (DRS-D3c).
11. **The lane's precedent for "who derives".** E6 slice 2 removed
    `cumulative_difficulty` from `ConnectFacts` because *a rule checks it*
    (D4 computes the value the header must carry); `long_term_effective_median`
    is passed through *"until CEN-G6 derives it"* (`connect.rs:193`). §3.1
    says why the root's case is different and stronger.
12. **Two findings this writer inherits.** **SOK-10**: the C++ path
    assembler paired `leaf(pos)` with `get_output_key(0, pos)` — a tree
    position used as a global output index; the RPC was deleted rather than
    fixed (`PHASE_2A_SEND_PATH.md` §3.0.1). **The `curve_tree_roots` gap**:
    the C++ wrote the root only when the tree grew, heights below the first
    maturity had no row, and the reader returned an all-zero root that
    `helioselene` maps to the identity — fixed on the Rust side by SCW-19's
    unconditional write. Both are drain-order facts (CTW-11).

---

## 2. Scope

### 2.1 In

- **The phase-3 body** (§3.2): drain the matured outputs of `h − 60` and
  `h − 10` in order → write leaves and the position maps → write the grow
  delta the verdict carries → update the summary and **check it** (SI-12
  live). Every write through a journaled handle bound to its SI row.
- **The root derived by the validator** (`CTW-Q1` RULED): `validate` grows
  the tree over a frontier read of the view and `ChainValid` carries the
  growth; `connect` persists what it was handed. `ConnectFacts.root_after`
  flips from passed-through to gone — after the replay oracle moves
  (`CTW-Q6` RULED, §3.8).
- **Per-height leaf count** as the primitive behind `ChainView::depth_at`
  (`CTW-Q4` RULED, §3.4) and CEN-F17's operand.
- **`RuleSet::tx_spendable_age`** beside `mined_money_unlock_window`
  (`CTW-Q5` RULED, §3.6).
- **The E2 oracle** (CTW-5, §3.8): on every replayed height of all four
  captured chains, the trace's recorded root is asserted equal to the
  derived root — in the driver, which holds the trace — before the field
  that carried it is deleted.
- **The pending side dissolved and the position maps typed** (§3.7): three
  tables deleted, two typed with an SI row over their bijection, one new
  small table (`curve_tree_leaf_counts`), a layout bump.
- **`placeholder_root_after` deleted** (`CTW-Q-C`), in the named commit
  (§6, commit 6), falsifier `rg placeholder_root_after rust/` → nothing.

### 2.2 Out (named, so it is not scope shed by omission)

- **The segment freeze** — retired (`PDM-Q12`); no step, no table, no call.
- **The wallet-side proving store** (`WSS-`) — a different unit and lane;
  DRS-D3c consumes what E3 writes.
- **Checkpoints and intermediate-layer pruning** — not ported (`CTW-Q3`).
- **RPC / `shekyl-fcmp::rpc_path`** — readers; unchanged.
- **E2's testnet leg and LWMA-past-`N` run** — blocked on a network.
- **CEN-I13 / I15 / H19-verify themselves** — E6 lands the rules on the
  operand and substrate this lands.
- **The `archival_reorg_depth_blocks` split** — E4's (FOLLOWUPS row).
- **A `Mock*` tree** — not written (§5.2).

### 2.3 What E6 gets

`ChainView::depth_at(h) -> AtHeight<TreeDepth>` with a `BatchView` impl
(I13's falsifier), derived from the per-height leaf count; a tree with real
leaves so a `shekyl-tx-builder` spend against `root_at(ref)` can be judged by
I15 and a block's proofs by H19-verify; `curve_tree().leaf_count` real for
F17.

### 2.4 What E2 gets

The strongest verification this increment will ever have, available **only
while the LMDB trace exists**: the trace's root converted from a source into
an oracle, asserted against the derived root at every height of every
captured chain (CTW-5). `placeholder_root_after` gone; `passed_through`
decomposes to five with one no-source-yet remaining (§7).

### 2.5 What DRS-D3c gets

A daemon-side leaf table and layer 0 written by the same `shekyl_fcmp::tree`
arithmetic the wallet side uses — two Rust producers to compare instead of
one and an LMDB record.

---

## 3. The contract (Round 1 rulings folded in)

### 3.1 Who derives the root — `CTW-Q1` RULED: the verdict, for the right reason

C2-R8 principle 3: the store may persist a consensus fact computed by a
consensus-owned function inside the write transaction; it never computes
one. `blockchain_db.cpp:663–664` — `get_curve_tree_root()` then
`store_curve_tree_root_at_height()` inside `add_block` — is the fusion that
principle exists to prevent, and the tempting Rust shape (a method on
`WriteBatch` that returns a root) reproduces it. **If step 3 ends up calling
anything that returns a root, the arrangement is wrong.**

The Round-0 default (the verdict carries it) stands; its justification does
not. `cumulative_difficulty` rides the verdict because *a rule checks it* —
the block claims a difficulty and D4 computes the one it must equal. The
census has no equivalent for the root: I12 *reads* the anchor at
`ref_height`, I13 bounds depth, nothing checks a claimed root against
computed growth. So `root_after` is not a verdict output in that sense. The
argument that holds is stronger: **the root determines future validity** —
every later I12 resolves `root_at(ref_height)` against it, so a wrong root
does not fail loudly, it silently invalidates proofs. A value with that
reach is carried by the thing holding authority over validity and backed by
a judgment, not assembled alongside one. That is also what lets
`Provenance::is_parity_evidence` treat it as `Derived` with a verdict behind
it.

And the alternative is ruled out by name: `Composed` in `shekyl-chain-ingest`
**assembles** values their owners computed; making it compute a
consensus-visible one would mint a third site of consensus authority, in the
ingest crate. Assembling is not computing.

Shape: `shekyl-chain-rules` takes `shekyl-fcmp` (which I15 requires
regardless — `FOLLOWUPS:706` names `shekyl_fcmp::proof::verify` as its
body); `ChainView` gains the reads the grow needs (§3.2); `validate` derives
`TreeGrowth { drained: Vec<(GlobalOutputIndex, TreeLeaf)>, layer_writes:
Vec<(LayerChunk, LayerHash)>, root_after, leaf_count_after }` over the
view's frontier and the two matured blocks; `ChainValid` carries it; a
block whose frontier or matured blocks the view cannot serve is
`Fault::View` / `Corrupt`, never a guess.

### 3.2 The phase-3 body

```text
 3a. drain     the verdict's TreeGrowth.drained, in its order (§3.3):
                 position = leaf_count + i
                 curve_tree_leaves[position] = leaf
                 output_to_leaf[output_id] = position; leaf_to_output[position] = output_id
 3b. grow      for (chunk, hash) in TreeGrowth.layer_writes: curve_tree_layers[chunk] = hash
 3c. summary   curve_tree_meta = { root: growth.root_after, depth: depth_of(leaf_count'), leaf_count' }
               curve_tree_leaf_counts[h + 1] = leaf_count'                      (§3.4)
               check: meta.root == growth.root_after; leaves.last() + 1 == leaf_count'  (SI-12, SI-11 live)
 4.  root      curve_tree_roots[h + 1] = growth.root_after                       (unchanged; SCW-19)
```

No pending table is read or written (§3.7). The drain's *inputs* are read by
the validator: block `h − 60`'s coinbase outputs and block `h − 10`'s listed
outputs — `O`, `C` from the output rows, `CM` from the `0x07` entries of the
retained prefix (`shekyl_wire::tx_extra` leaf entries, one per output) — and
`construct_leaf` runs there. **This is a read dependency on two older heights
that the current connect does not have**; both are committed, immutable,
inside the write transaction, and the reads are stated here so they are
designed, not discovered: `ChainView::matured_outputs_at(h) ->
AtHeight<Vec<(GlobalOutputIndex, LeafInputs)>>` (or the two block reads and
the fold, if the view prefers primitives) and `ChainView::tree_frontier() ->
Frontier { leaf_count, chunk_per_layer }`.

`pop` is the journal's reverse replay (`pop.rs`): every row 3a–3c and 4
wrote is restored to its pre-image. **No derivation runs on pop**, so
`trim_curve_tree` has no port (CTW-2) and the drain is not re-run backwards
— the journal holds what the drain did.

### 3.3 The drain order, stated as the invariant it is (CTW-11)

**Leaf position is assigned in drain order; nothing may index a leaf by
output id.** The two orders diverge from the first block that carries a
transaction: a block's coinbase (lower global output index) enters the tree
fifty blocks *after* the same block's listed outputs. At height `h` the
drain order is the C++'s key order made explicit — block `h − 60`'s coinbase
outputs in output order, then block `h − 10`'s listed outputs in output
order (the coinbase block is earlier, so its global ids are lower; the
C++'s `(maturity, output_id)` cursor walk yields the same sequence). SOK-10
and the roots gap (§1 item 12) are what happens when this is left implicit.
**Pinned by a test on a chain that carries at least one transaction** — a
coinbase-only chain cannot exhibit the divergence; the captured vectors
under `shekyl-chain-ingest/tests/vectors/` (`spend-1in-2out`, `spend-depth3`,
`bond-post`, `emission-claim`) do.

### 3.4 The height-keyed depth — `CTW-Q4` RULED: store the primitive

Own table, but **leaf count per height, not depth**. Depth is a function of
leaf count; a per-height depth table stores a derived value that can
disagree with its primitive. `curve_tree_leaf_counts[h] → LeafCount`,
written at 3c beside the root (the count *after* the block at `h − 1`
drained, keyed exactly as `curve_tree_roots[h]` is), and
`depth_at(h) = depth_of(leaf_counts[h])`. One table, two consumers — I13's
operand and CEN-F17's `leaf_count > 0` falsifier read directly rather than
by inference — and no derived-value drift. `curve_tree_roots`' value shape
does not move (KEEP-C, in digest v0).

### 3.5 Checkpoints and intermediate layers — `CTW-Q3` RULED: port neither

`hash_grow` takes one chunk hash and the child it replaces (`tree.rs:102`);
a filled chunk below the frontier is never an input (CTW-8). With pop as
journal replay the recompose that read those layers is gone, so layers
`1..depth−2` are cache the Rust grower never reads either — which is what
the grading already says. `curve_tree_checkpoints` was the C++ integrity
check's reader and a second source for the summary row (rule 05): deleted.
The C++'s TODO (`blockchain_db.cpp:640–645`) confirms the checkpoint work was
latency work, not correctness.

### 3.6 Maturity is rule-set data — `CTW-Q5` RULED, with the right reason

`RuleSet::tx_spendable_age: BlockCount`, `GENESIS` = 10, beside
`mined_money_unlock_window` (60, `rule_set.rs:108`, landed with slice 4
because F6 reads it). The reason is **coherence with F6's window, not
schedule variance**: both decide when an output becomes usable, both are
maturity operands, and they are a pair — if F21 ever forces the window out of
`RuleSet`, both move together. A test that `GENESIS` carries the C++ define,
as `the_unlock_window_is_the_cxx_define` does. `Fault` width: +8 bytes, absorbed
by the boxed `Stale::RuleSet` payload (PR #861).

### 3.7 Fact, or a view of facts I already hold? — the question asked of every inherited table

The third instance of one pattern in this lane in two days: `undo_log_floor`
duplicating `UNDO_LOG.first()` (S-PRUNE review), `CURVE_TREE_META` duplicating
derivable state, a per-height depth duplicating leaf count, a pending set
duplicating the block index. **A view becomes a query. If performance later
argues for materialising one, it materialises *with* a check against its
source** — that is what makes the redundancy safe rather than authoritative.
A stored pending set is a second source that can disagree with the block
data, and no belt catches it because the pending table *is* the authority; a
derived one cannot disagree, because the block data is the authority, which
is what it actually is.

| Table | Verdict | Disposition |
| --- | --- | --- |
| `curve_tree_leaves` | **fact** — a leaf's position is assigned by drain order and nothing else records it | kept; written at 3a |
| `curve_tree_layers` | **fact** — hashes that exist only because they were computed | kept; written at 3b (frontier and layer 0 only, §3.5) |
| `curve_tree_roots` | **fact** per height, load-bearing for I12 | kept; unchanged |
| `curve_tree_meta` | **view** (`root` = `roots[tip+1]`, `leaf_count` = `leaves.last()+1`, `depth` = f(`leaf_count`)) | kept **with the check** its own doc promises (SI-12; SI-11 on the count), because C1 is a one-row read the RPC and the digest take |
| `curve_tree_leaf_counts` | **fact** per height — the count at `h` is not otherwise recorded once the tree has grown past it | new (§3.4) |
| `pending_tree_leaves` | **view** — `f(height, is_miner)` over blocks the store holds (§1 item 7) | **dissolved** (CTW-10); `CTW-Q2` dissolves with it |
| `pending_tree_drain`, `block_pending_additions` | C++ pop journals | **deleted** (CTW-3); the undo log is ours |
| `curve_tree_checkpoints` | view of the summary at intervals | **deleted** (§3.5) |
| `output_to_leaf`, `leaf_to_output` | **fact** — the drain-order assignment, and its inverse | typed `Coded<TreePosition>` / `Coded<GlobalOutputIndex>`; SI-16 over the bijection (CTW-4) |

Net: three tables deleted, one dissolved, two typed, one new; layout bump;
`tables.snap` moves by −3 (the bijection gate's set follows).

### 3.8 The replay oracle — `CTW-Q6` RULED: build the comparison before the field goes

CTW-5's assertion needs the trace's root as its comparison input; if
`ConnectFacts.root_after` is the field carrying it, deleting the field in
the same commit removes the thing being compared. Two clean shapes; the
second is ruled: **the comparison lives in the replay driver**, which holds
the `Trace` separately (`facts.rs:15`, the `Trace` / `Composed` seam) and
does not need the field. The driver asserts `derived == trace` per block —
a DIVERGE under the grader's law (RD-Q6), never a silent pass — across **all
four captured chains at every height, not a sample**, because this
comparison exists only while the LMDB trace does. Sequence: the oracle
lands (commit 5) before the field is deleted (commit 6). `Origin::PassedThrough`
for `root_after` then has no producer and the variant's doc narrows to the
one field left.

---

## 4. Store invariants this increment builds or restates

| Row | Statement | Status after E3 |
| --- | --- | --- |
| SI-4 | `curve_tree_roots[h+1]` written exactly once per connect | built; unchanged |
| SI-11 | `curve_tree_leaves` dense over `[0, leaf_count)` | minted → **built**: 3a writes `leaf_count + i` in order; 3c checks `leaves.last() + 1 == leaf_count'` |
| SI-12 | a grown summary's root is the live root | minted → **built**: 3c checks `meta.root == growth.root_after`; the read's refusal (`curve.rs:132`) becomes reachable |
| SI-16 (new, CTW-4) | `output_to_leaf` and `leaf_to_output` are inverse bijections over drained outputs | minted and built at 3a |
| SI-17 (new) | `curve_tree_leaf_counts[h+1] − leaf_counts[h] == growth.drained.len()` | minted and built at 3c |

Every one is a *store* property (holds regardless of what the rules say);
which root is correct is the validator's (§3.1).

---

## 5. Round-0 findings

| Finding | Statement |
| --- | --- |
| **CTW-1** | **The hook comment names a retired step.** `connect.rs:22`, `:409` "→ segment freeze" — retired by `PDM-Q12` and never a phase of *this* store. Corrected before any body lands. |
| **CTW-2** | **`trim_curve_tree` has no port.** The C++ pop recomposes layers from layer 0 because LMDB's tree writes had no journal. The Rust store journals every write (`open_insert_table`, `write.rs:391`; SCW-7); pop restores 3a–3c's pre-images and derives nothing. A recompose would be a second mechanism for a fact the journal holds (rule 05). |
| **CTW-3** | **Two of the five pending-side tables are C++ pop journals.** `pending_tree_drain`, `block_pending_additions` — *"tracked by its global output index for exact reversal"* (`blockchain_db.cpp:539`). Dead on arrival under CTW-2; deleted, not typed. |
| **CTW-4** | **The position maps are a bijection nothing asserts.** Written pairwise, read singly; SI-16 makes the pair a check that can fail at 3a. |
| **CTW-5** | **The corpus is already a root KAT — and the only oracle E3 will ever have.** Every captured chain carries `root_after` per height (RD-Q2's fact tag `0x01`, `DRS_E2_REPLAY_DRIVER.md:417`). Derived-vs-trace at every height of every chain is the strongest verification available, and it is available only while the trace exists (§3.8). |
| **CTW-6** | **The listed-output spendable age has no Rust home.** `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE = 10` (`cryptonote_config.h:49`) appears in Rust only in `shekyl-curve-tree` and two spikes; `RuleSet` has the miner window and not its sibling (§3.6). |
| **CTW-7** | **S-CURVE's `TreePosition` move is still owed.** §3.4 defaulted to moving `shekyl_curve_tree::types::TreePosition` to `shekyl-types`; the leaf table is keyed `u64` today (`schema.rs:524`). E3 keys three tables by it and pays. |
| **CTW-8** | **The grow reads only the frontier.** `hash_grow_selene(existing_hash, offset, existing_child_at_offset, new_children)` (`tree.rs:102`). The property the C++'s intermediate-layer prune relied on without stating; what makes §3.5 sound. |
| **CTW-9** | **The chunk arities arrive from a library.** `SELENE_CHUNK_WIDTH = fcmps::LAYER_ONE_LEN`, `HELIOS_CHUNK_WIDTH = fcmps::LAYER_TWO_LEN` (`shekyl-fcmp/src/tree.rs:48`, `:51`) — the tree's shape, consensus, with no Shekyl-named source and no ratification; `PHASE_2A_SEND_PATH.md:236` restates the equality. The `shekyl_fcmp::MAX_INPUTS` shape (FOLLOWUPS `:33`): a cap nobody ratified became consensus. `CTW-Q7`. |
| **CTW-10** | **The pending table is a view.** Maturity is `f(height, is_miner)` (§1 item 7); the drain set at `h` is two blocks' outputs the store already holds. The C++ table answered LMDB's constraints (no cheap reverse lookup; exact reversal by output id for its pop). Dissolved; the block data is the authority it always was (§3.7). |
| **CTW-11** | **Drain order is an invariant the writer owns, not a detail.** Positions are assigned in drain order; nothing indexes a leaf by output id; the orders diverge from the first block with a transaction (§3.3). SOK-10 and the roots gap are its two prior costs; a test on a transaction-bearing captured chain pins it. |

### 5.1 Reproduced deviations on this surface (DRS §7.6 item 1)

None reproduced: nothing writes these tables yet. C++ behaviours **not**
carried: the pop-time recompose (CTW-2), the two pop journals (CTW-3), the
pending table (CTW-10), the checkpoint row and intermediate-layer prune
(§3.5), the grow-gated root write (SCW-19, already ruled). Each replaced with
its reason; none is a deviation to grade, because none is consensus.

### 5.2 Things not done here, each with the instance that taught it

- **No `Mock*` tree.** A tree's subject is the chain; `50-testing.mdc`'s
  three-job charter and its line — *a rule's own witness comes from the
  driver or the captured chains* — apply. E3's witness is a driven or
  replayed chain with real outputs, never a constructed `LEAVES` table.
- **No filled leaf bytes.** `[0x80; 32]` keys and `[fill; 32]` images each
  caused a cascade. The point table (`fixture_points_are_what_they_claim`,
  `chain-rules/src/harness/fixture.rs`) exists; CEN-I15 will refuse whatever
  does not derive.
- **No constant from a library** (CTW-9, `CTW-Q7`).
- **No deferral to an unscheduled owner.** Every FOLLOWUPS row this increment
  touches names a live doc, branch or PR.
- **No `REWRITE-NOTE` that instructs.** The register records what is; what
  the rewrite owes is in this plan (§6).

---

## 6. Commit sequence and the expectation, written before the work (rule 90; one PR)

The signal: **past eight is the signal that the substrate was not as
finished as this table claims.** The producer substrate — driver, block
template, facts seam, captured chains — is built; E3 has no slice-6-shaped
excuse.

| # | Commit | Cost | What would make it larger |
| --- | --- | --- | --- |
| 1 | **Types and tables.** `TreePosition` → `shekyl-types` (CTW-7); position maps typed; `pending_tree_leaves`, `pending_tree_drain`, `block_pending_additions`, `curve_tree_checkpoints` deleted; `curve_tree_leaf_counts` added; layout bump; snapshots; SI-16/17 minted. | S | a hidden reader of a deleted table (falsify: `rg` each name outside `schema.rs` before cutting) |
| 2 | **Rule-set data.** `RuleSet::tx_spendable_age` (§3.6) with the C++-define test. | S | none expected |
| 3 | **`shekyl-fcmp` enters `shekyl-chain-rules`**; `CTW-Q7`'s arity source pinned (§8). | S | a dependency cycle (`shekyl-fcmp` must not reach `shekyl-chain-rules`; verify with `cargo tree`) |
| 4 | **The derivation.** `ChainView::{tree_frontier, matured_outputs_at, depth_at}` on the trait, `BatchView`, `MockView` (held to each other); `TreeGrowth` derived in `validate`, carried on `ChainValid`; the drain-order test on `spend-1in-2out` (§3.3); a `Fault::View` fixture for an unservable frontier. | **L** | the frontier read's shape (chunk-per-layer over the tuple key is one `range` per layer; if it is not, this commit is where the table shape was wrong) |
| 5 | **The replay oracle.** The driver asserts `derived == trace` at every height of all four chains (§3.8); the connect stays on the passed-through field this one commit. | M | a divergence from the C++ on any chain — which is the finding this commit exists to produce, and stops the PR until adjudicated against the spec (E2 §0: never toward C++) |
| 6 | **The phase-3 body** (§3.2) with SI-11/12 built and SI-16/17 built; `ConnectFacts.root_after` deleted; `placeholder_root_after` deleted; `Origin::PassedThrough`'s doc narrowed. | M | `pop` on a grown tree — the journal's restore of `curve_tree_layers` rows written under the tuple key (a `Restorable` impl the table did not need until now) |
| 7 | **Scenario spend.** A `mine_listing` scenario admitting a `shekyl-tx-builder` spend against the grown tree — the object FOLLOWUPS `:706` waits for. | M | the tx-builder's proof against `root_at(ref)` not verifying: that is I15's job, and if it fails here the fault is in the tree, which is the point |
| 8 | **Docs** (§9). | S | — |

Eight commits, one PR, inside the 5-day ceiling. Exempt from the count:
none. Commit 5 is the one that may stop the PR, by design.

---

## 7. What E3 unblocks, and the measurable

| Waiting | Falsifier |
| --- | --- |
| E6 CEN-I13 | `rg 'fn depth_at' rust/shekyl-chain-rules/src/view.rs` → the trait method, `BatchView` impl in `store/view.rs` |
| E6 CEN-I15, H19-verify | a scenario spend judged against a real tree (commit 7) |
| CEN-F17 | `curve_tree().leaf_count > 0` after replaying a chain with outputs; `curve_tree_leaf_counts` read directly |
| DRS-D3c | named in its FOLLOWUPS row (`:221`) |
| `placeholder_root_after` | `rg placeholder_root_after rust/` → nothing |
| `root_after`'s origin | **`Provenance::passed_through` decomposes from six (four composed, two no-source-yet) to five (four composed, one no-source-yet: `long_term_effective_median`, waiting on G6)** — the number the increment's record states, the way slice 6's §5.1 stated its commit count |

Denominator at the pin: `cargo test -p shekyl-chain-store --lib` 360,
`-p shekyl-chain-rules --lib` 241, `-p shekyl-chain-ingest` 82;
`check_redb_schema_bijection.py` / `check_redb_schema_key_types.py` (the set
moves by −3 + 1); `check_store_invariant_register.py` (SI-16/17); the
chain-rules coverage gate if the growth gets a coverage row; the doc gates.
Extended: the E2 conformance run with the root oracle on (commit 5).

---

## 8. Round-1 questions — RULED 2026-09-26 (maintainer, PR #873); each row line-local

| Q | Question | Ruling |
| --- | --- | --- |
| **CTW-Q1** | Who derives the root — the verdict, or a grower between validator and store? | **RULED: the verdict** — not because a rule checks it (none does; the `cumulative_difficulty` analogy is wrong) but because the root determines future validity and a value with that reach is carried by the authority over validity, backed by a judgment (§3.1). `Composed` assembles; it never computes a consensus-visible value. |
| **CTW-Q2** | Pending key: redb tuple or packed integer? | **DISSOLVED** — the table does not survive (CTW-10, §3.7). The question was about carrying a Monero artifact forward. |
| **CTW-Q3** | Checkpoints and intermediate-layer pruning: port neither, or both? | **RULED: neither** (§3.5). CACHE means re-derivable; the C++'s own TODO says latency. |
| **CTW-Q4** | The height-keyed depth: own table, or widen `curve_tree_roots`? | **RULED: own table, storing the primitive** — `curve_tree_leaf_counts[h]`, depth derived (§3.4). |
| **CTW-Q5** | `RuleSet::tx_spendable_age`? | **RULED: yes**, as F6's window's sibling — a maturity pair that moves together; not on schedule variance (§3.6). |
| **CTW-Q6** | Delete `ConnectFacts.root_after` in the same PR? | **RULED: not as a plain yes** — the replay oracle moves into the driver first (commit 5), the field goes after (commit 6) (§3.8). |
| **CTW-Q7** *(posed on the round, from CTW-9)* | The chunk arities are `fcmps::LAYER_ONE_LEN` / `LAYER_TWO_LEN` re-exported. What is their Shekyl-named source? | **POSED, default:** Shekyl-named constants in `shekyl-fcmp` with `const _: () = assert!(SELENE_CHUNK_WIDTH == fcmps::LAYER_ONE_LEN)` — the library value checked against ours, not ours read off the library — recorded in the census sweep's fourth ground (which library constants would refuse a shape independently), and behaviourally pinned by CTW-5's oracle (a wrong arity produces a wrong root on the first grown chunk). Whether the pair also belongs in `consensus_constants.json` (it is the tree's shape) is for the maintainer. |

---

## 9. Documentation owed by the increment (rule 91)

`DAEMON_REDB_STORE.md` (the `[E3 hook]` phase text; the `curve_tree_*` and
pending rows of the table inventory — three deleted, one dissolved, one
added; DRS-D3c's row); `DRS_E1_SCURVE.md` §2.3 (the ask answered);
`CHAIN_RULES_CRATE.md` (`shekyl-fcmp` dependency; `TreeGrowth` on the
verdict); `CONSENSUS_RULE_CENSUS.md` F6 / I13 sites and the sweep's fourth
ground (CTW-9); `shekyl-chain-ingest/src/facts.rs`'s table (`root_after` row
deleted); the FOLLOWUPS rows `:675`, `:702`, `:706` closed or narrowed to
E6's half; `IMPLEMENTATION_INDEX.md` (`CTW-`, `CTW-Q`, this document,
`DRS_E1_SCURVE.md`'s status); `CHANGELOG.md` (layout bump; the root derived;
the maturity rule-set field; the deleted tables); this file's banner →
LANDED, staying in `design/` while E4's hook phases cite §3.2.

---

## 10. Decision log

| Date | Entry |
| --- | --- |
| 2026-09-26 | Round 0 executed at `dev@1aa48eff9` after #861 and #864 merged. Findings CTW-1…CTW-8; questions CTW-Q1…CTW-Q6 posed with defaults. Families registered at birth. No code. |
| 2026-09-26 | **Round 1 RULED on PR #873 (maintainer).** Q1 the verdict, justification corrected (the root's reach, not a rule that checks it; `Composed` assembles, never computes); Q2 dissolved with the pending table (CTW-10 — maturity is `f(height, is_miner)`, verified at `blockchain_db.cpp:554–567`); Q3 neither; Q4 the primitive, `curve_tree_leaf_counts`; Q5 yes, as F6's sibling; Q6 the oracle moves into the driver before the field goes. CTW-9 (library arities) and CTW-11 (drain order as invariant) added from the round; CTW-Q7 posed. §3.7's test — *fact, or a view of facts I already hold?* — recorded as the question asked of every table this lane inherits. Commit table with costs and the signal (§6) written before the work. |
