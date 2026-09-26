# DRS-E3 — the curve-tree writer: pre-flight

**Status:** OPEN — Round 0 executed 2026-09-26 at `dev@1aa48eff9` (#864
merged; #861 merged). Round-1 questions `CTW-Q1…CTW-Q6` posed, not ruled.
Identifier families **`CTW-`** (findings) and **`CTW-Q`** (questions),
registered in `IMPLEMENTATION_INDEX.md` §2 with this file (rule 94 §1;
`check_index_prefix_uniqueness.py` branch (a): distinct from each other and
from the 103 registered families). Parent plan:
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) — the **DRS-E3** node of the
lane graph (`E1 → E2 → E3 → E4 → E5`), *"curve storage only"*; the boundary
statement it builds against is [`DRS_E1_SCURVE.md`](DRS_E1_SCURVE.md) §2.3.
Template: the DRS-E1 pre-flight shape (`CHAIN_RULES_CRATE.md` §7.5.1 applied
to a store increment), as `DRS_E1_SCURVE.md` used it.

**One sentence.** The daemon store's connect has an empty `[E3 hook]` at
phase 3 and records a curve-tree root it was *handed* (`facts.root_after`,
borrowed from the LMDB record on replay — `DRS_E2_REPLAY_DRIVER.md` RD-Q9);
E3 makes the Rust stack **grow the tree itself** — pending leaves at
ingest, drain at maturity, `hash_grow` into the typed `curve_tree_*` tables
S-CURVE froze — so the root is derived, the borrowed one becomes an
assertion, and the three consumers waiting on a real tree (E6's CEN-I13 /
I15 / H19-verify, CEN-F17, DRS-D3c) get one.

---

## 0. Ground

Read at `dev@1aa48eff9`. Every citation below is against that tree unless it
says otherwise. Rulings this document is downstream of and does not
re-open: `PDM-Q6` (the transaction unit), `PDM-Q12` (the freeze pipeline
retires), `PDM-Q11` (`D_max`'s shape), C2-R8 Q4 (the store records
consensus-visible values and never derives them), S-CURVE `SCU-Q1…Q3`
(the three typed tables and their keys), `SCW-19` (`curve_tree_roots[h+1]`
written on every connect), E6 slice 6 Q8 (I13's operand is the depth *at*
`ref_height`).

---

## 1. Preconditions, as found at the pin

1. **The hook is empty and mis-labelled.** `store/connect.rs:22` lists phase
   3 as *"pending leaves → drain → grow → segment freeze"* and `:409` is the
   comment with no body. The fourth step is retired (`PDM-Q12`, ruled
   2026-09-18): the segment-freeze pipeline "existed to commit `R_k` over a
   segment so served bytes were content-verifiable"; under Q6 nothing is
   left to commit. **E3's phase has three steps, not four** (CTW-1).
2. **The root is borrowed.** `ConnectFacts.root_after: Fact<CurveTreeRoot>`
   (`connect.rs:187`) is passed through and stamped as such in the file's
   provenance; the replay driver's scenario supplies `placeholder_root_after`
   (`shekyl-chain-ingest/src/scenario.rs:167`, `:305`). A file whose
   provenance carries `root_after` as passed-through is, by `connect.rs`'s
   own §3.8 contract, *not parity evidence*.
3. **The tables exist, typed, and are written by nothing.** `schema.rs:524`
   `curve_tree_leaves: u64 → Coded<TreeLeaf>`, `:531`
   `curve_tree_layers: (u8, u64) → Coded<LayerHash>`, `:537`
   `curve_tree_meta: () → Coded<CurveTreeState>` — S-CURVE's shapes (§3.4).
   The pending side is still `Unshaped` with composite BE keys:
   `pending_tree_leaves`, `pending_tree_drain`, `block_pending_additions`
   (`:504`–`:513`), and the two position maps `output_to_leaf` /
   `leaf_to_output` (`:516`, `:519`) are `INTEGERKEY → Unshaped`.
4. **The reads E3 must satisfy are landed.** `ReadSnapshot::curve_tree()`
   (C1, one `CurveTreeState` row; `EMPTY` is a real row), `root_at(h)`
   (C2), `leaf(pos)` (C3) — `store/curve_reads.rs`; SI-11 (dense leaves)
   and SI-12 (a grown summary's root is the live root) are minted
   (`store/invariant.rs:140`, `:159`) and **have no writer to hold them
   against** — SI-12's own doc says the seal's `EMPTY` "is not a claim about
   that live root".
5. **The arithmetic exists in Rust, outside the store's reach.**
   `shekyl_fcmp::tree::{hash_grow_selene, hash_grow_helios, construct_leaf}`
   (`tree.rs:102`, `:158`, `:506`) — the C++ calls the same bodies through
   `shekyl_construct_curve_tree_leaf` and the grow FFI. The daemon store
   **cannot** depend on `shekyl-curve-tree` or `shekyl-fcmp` (S-CURVE §3.4:
   they pull `shekyl-crypto-pq`, `shekyl-consensus`; `chain-store/Cargo.toml`
   has neither), and `shekyl-chain-rules` has `shekyl-crypto-pq` but not
   `shekyl-fcmp` (`chain-rules/Cargo.toml:25–52`).
6. **The C++ path, read (`blockchain_db.cpp:560–656`).** Per block: (i)
   **drain** every `pending_tree_leaves` entry with `maturity ≤ current
   height` in key order, assigning `TreePosition = leaf_count + i`, writing
   `pending_tree_drain` (the pop journal for the drain) and the
   `output ↔ leaf` maps (`db_lmdb.cpp:8028–8060`); (ii) **collect** this
   block's outputs as pending leaves at `maturity = height + 60` (miner,
   `CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW`) or `height + 10` (listed,
   `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE`; `cryptonote_config.h:45`, `:49`),
   with `block_pending_additions` as *its* pop journal; (iii) **grow** if
   anything drained (`grow_curve_tree`, `:8403`); (iv) every 10,000 blocks
   `save_curve_tree_checkpoint` + `prune_curve_tree_intermediate_layers`
   (`FCMP_CURVE_TREE_CHECKPOINT_INTERVAL`, `cryptonote_config.h:313`);
   (v) `store_curve_tree_root_at_height(h + 1, root)` **outside** the grow
   gate (SCW-19). Pop runs `trim_curve_tree(drained_count)` (`:878`), which
   *recomposes* layers 1..depth−2 from layer 0 (`:8776`, `:9289`).
7. **What the daemon's tree tables are, by grading** (`PDM-Q1` §9.2,
   `ARCHIVAL_PRUNED_DAEMON_MODE.md:1873–1889`): `curve_tree_roots` KEEP-C
   (every proof verify reads it; the root chain must stay);
   `curve_tree_layers` layer 0 KEEP-C (set A, the tree's own commitment);
   layers `1..depth−2` **CACHE — already pruned by every node**;
   `curve_tree_leaves` CACHE; `curve_tree_meta` / `curve_tree_checkpoints`
   CACHE / KEEP-C (root layer). D10 (reconstructible mandatory) reaches all
   of them from the outputs.
8. **Three consumers are queued on this increment by name.** FOLLOWUPS
   `:702` (CEN-I13 — a height-keyed depth read, the ask written into
   S-CURVE §2.3), `:706` (CEN-I15 and CEN-H19-verify — a scenario spend
   against a tree the store grew; falsifier `rg placeholder_root_after
   … scenario.rs` empty), `:675` (CEN-F17 — `curve_tree().leaf_count > 0`
   after replaying a chain with an output), and `:221` (DRS-D3c,
   root-and-frontier parity, re-scoped by `WSS-Q1`(b)).
9. **The lane's own precedent for "who derives".** E6 slice 2 removed
   `cumulative_difficulty` from `ConnectFacts` because *the verdict carries
   it* (`DAEMON_REDB_STORE.md:631`); `long_term_effective_median` is passed
   through *"until CEN-G6 derives it"* (`connect.rs:193`). Passed-through
   facts are the temporary shape; derived-by-the-validator is the ruled
   destination (C2-R8 Q4, `DRS-D12`).

---

## 2. Scope

### 2.1 In

- **The phase-3 body**: drain at maturity → collect this block's outputs
  as pending leaves → grow; `curve_tree_meta`'s one row updated; the
  `output ↔ leaf` maps written; every write through a journaled handle
  bound to its SI row (`open_insert_table`, `write.rs:391`).
- **The root, derived** — where and by whom is `CTW-Q1`; what is not in
  question is that after this increment `root_after` is no longer a
  passed-through fact on a chain the Rust stack connected, and the
  borrowed root on E2's replay becomes an **assertion** (`CTW-Q1`,
  §3.1; RD-Q9's edge resolved in the direction the driver's grader already
  states: a borrowed value is never evidence).
- **The height-keyed depth** S-CURVE §2.3 asks for (`ChainView::depth_at`),
  as the per-height record the same connect writes that writes the root
  (`CTW-Q4` on shape).
- **Typing the pending side** (`pending_tree_leaves`, `pending_tree_drain`,
  `block_pending_additions`, `output_to_leaf`, `leaf_to_output`): `Unshaped
  → Coded`, tuple keys by SOK-Q1's delegated-compare mechanism where the C++
  packed composites. A layout bump.
- **The maturity constants' Rust home** (CTW-6): the listed-output spendable
  age is consensus data with no Rust home; it joins `RuleSet` beside
  `mined_money_unlock_window` (`CTW-Q5`).
- **The E2 driver**: `placeholder_root_after` deleted; the scenario grows a
  tree; the captured chains' `root_after` compared against the computed
  root at every height (a KAT the corpus already carries — CTW-5).

### 2.2 Out (named, so it is not scope shed by omission)

- **The segment freeze** — retired (`PDM-Q12`); no hook step, no table, no
  epoch-close call. Its dependents re-pointed there, not here.
- **The wallet-side proving store** (`WSS-`; `WALLET_SIDE_STORE.md`) — a
  different unit and a different lane. DRS-D3c's parity KAT *consumes* what
  E3 writes; the wallet side is not written here.
- **Checkpoints and intermediate-layer pruning as a cutover behaviour** —
  disposed in `CTW-Q3` (kept as a grow-path detail, or not ported); either
  way not a consensus surface.
- **RPC / `shekyl-fcmp::rpc_path`** — readers of the tables; unchanged.
- **E2's testnet leg and LWMA-past-`N` run** — E2's own open items, blocked
  on a network, not on this increment.
- **CEN-I13 / I15 / H19-verify themselves** — E6's rows; this increment
  lands their operand and their substrate, and E6 lands the rules.
- **The `archival_reorg_depth_blocks` split** — E4's (FOLLOWUPS row);
  unrelated to the tree.

### 2.3 What E6 gets

`ChainView::depth_at(h) -> AtHeight<TreeDepth>` with `BatchView`'s impl
(I13's operand, S-CURVE §2.3's falsifier); a tree with leaves, so a
`shekyl-tx-builder` spend against `root_at(ref)` can be judged by I15 and a
block's proofs by H19-verify; `curve_tree().leaf_count` real, so F17's
operand `frozen_segment_count(leaf_count)` reads a table something writes.

### 2.4 What E2 gets

`root_after` stops being borrowed on replay: the driver hands `connect` a
**derived** root and asserts it equals the corpus's recorded one (a
DIVERGE, not a silent pass, when they differ — the grader's law, RD-Q6).
Four captured chains × every height is the KAT (CTW-5). `placeholder_root_after`
deleted (FOLLOWUPS `:706`'s first falsifier goes green).

### 2.5 What DRS-D3c gets

A daemon-side leaf table and layer 0 written by a Rust grower over
`shekyl_fcmp::tree` — the same arithmetic the wallet side uses — so the
cross-store position/root KAT has two Rust producers to compare instead of
one and an LMDB record.

---

## 3. The contract proposed for freezing (Round 1)

### 3.1 Who derives the root (`CTW-Q1`)

C2-R8 Q4: the store records consensus-visible values and never derives
them. The root is consensus-visible (CEN-B5 checks the next header carries
it; CEN-I12 anchors spends to it). So the store does not compute it. Two
shapes satisfy the ruling:

- **(a) The verdict carries it.** `validate` grows a *shadow* of the tree
  over `ChainView` (a frontier read: the last chunk of each layer, the leaf
  count, the pending set due at `h`) and `ChainValid` carries `root_after`
  and the grow delta, as it carries `cumulative_difficulty`. `connect` writes
  the delta and asserts the resulting `curve_tree_meta.root == verdict.root`
  (SI-12 made live). Cost: `shekyl-chain-rules` takes `shekyl-fcmp` (it
  already takes `shekyl-crypto-pq`; `shekyl-fcmp` is the proof crate I15 will
  need in any case — `FOLLOWUPS:706` names `shekyl_fcmp::proof::verify` as
  I15's body).
- **(b) A grower between validator and store.** A crate (`shekyl-tree-grow`,
  or `shekyl-curve-tree` if its dependency set permits — it does not today,
  S-CURVE §3.4) the *driver* calls with the view's frontier; it returns
  `(delta, root)`; the driver hands `connect` the root as `Fact::derived`
  and the delta; `connect` writes and asserts as in (a).

Default **(a)**, on three grounds: it is the shape slice 2 already took for
`cumulative_difficulty`; I15 needs `shekyl-fcmp` in the rules crate
regardless, so (a) adds no dependency (b) would avoid; and it puts the
consensus derivation where the validator's completeness gate can see it
(a `RuleCoverage` row for the grow, so a block whose root the validator
could not derive is `Fault`, not a store write). Against (a): `validate`
gains state arithmetic it has not had — every rule so far is a predicate
over the view — and the frontier read widens `ChainView` by three methods.
The maintainer rules.

### 3.2 The phase-3 body

```text
 3a. drain     for (maturity, output_id) in pending_tree_leaves with maturity ≤ h, key order:
                 position = meta.leaf_count + i; curve_tree_leaves[position] = leaf
                 output_to_leaf[output_id] = position; leaf_to_output[position] = output_id
                 delete the pending row  (journaled: pop restores it — no pending_tree_drain table)
 3b. collect   for each output of the miner tx then listed txs, in order:
                 leaf = construct_leaf(O, C, CM); maturity = h + window(kind, in_force)
                 pending_tree_leaves[(maturity, output_id)] = leaf  (journaled — no block_pending_additions table)
 3c. grow      if drained > 0: hash_grow per layer over the frontier chunks;
                 curve_tree_layers[(layer, chunk)] = hash; curve_tree_meta = { root, depth, leaf_count }
                 assert root == verdict.root_after  (SI-12, live)
```

`pop` is the journal's reverse replay (`pop.rs`): every row 3a–3c wrote is
restored to its pre-image, **so `trim_curve_tree` has no port** (CTW-2) —
and neither do the two C++ pop-journal tables `pending_tree_drain` and
`block_pending_additions`, whose only job was to make the C++ pop possible
(CTW-3). Layout: three tables deleted, two typed, one bumped version.

### 3.3 Types and tables (`CTW-Q2` on the tuple keys)

| Table | Today | Proposed | Note |
| --- | --- | --- | --- |
| `pending_tree_leaves` | `&[u8] → Unshaped` (BE `maturity ‖ output_id`) | `(u64, u64) → Coded<TreeLeaf>` — `(MaturityHeight, GlobalOutputIndex)`, layer-major by delegated compare | drain is `range(..=(h, u64::MAX))` in key order — the C++'s cursor walk, typed |
| `pending_tree_drain` | `&[u8] → Unshaped` | **deleted** | C++ pop journal; the undo log is ours (CTW-3) |
| `block_pending_additions` | `&[u8] → Unshaped` | **deleted** | same |
| `output_to_leaf` | `u64 → Unshaped` | `u64 → Coded<TreePosition>` | `GlobalOutputIndex → TreePosition` |
| `leaf_to_output` | `u64 → Unshaped` | `u64 → Coded<GlobalOutputIndex>` | inverse; SI candidate: bijection over drained outputs (CTW-4) |
| `curve_tree_leaves` / `_layers` / `_meta` | typed (S-CURVE) | unchanged | E3 writes what C1–C3 read |
| `curve_tree_checkpoints` | `u64 → Unshaped` | `CTW-Q3` | see §3.5 |
| `curve_tree_roots` | `u64 → Coded<CurveTreeRoot>` | unchanged; **plus** the depth record (`CTW-Q4`) | KEEP-C, in digest v0 — its value shape does not move |

`TreePosition` already lives in `shekyl_curve_tree::types` and the store
cannot take that crate (S-CURVE §3.4's default: move it to `shekyl-types`;
not yet done — CTW-7).

### 3.4 The height-keyed depth (`CTW-Q4`)

S-CURVE §2.3's ask is the *keying*, not the shape. Two shapes: (a) a second
table `curve_tree_depths[h] → TreeDepth`, written at step 4 beside the root
and read by `depth_at`; (b) widen `curve_tree_roots`' value to `(root,
depth)`. (b) moves `digest_v0`'s root family (it reads the roots table) and
re-keys the KEEP-C table E2 grades against LMDB; (a) adds one small table
and nothing moves. Default **(a)**.

### 3.5 Checkpoints and intermediate layers (`CTW-Q3`)

The C++ saves `{root, depth, leaf_count}` every 10,000 blocks and prunes
layer chunks `1..depth−2` fully below the previous checkpoint, because its
*pop* recomposes those layers from layer 0 and nothing else reads them
(`db_lmdb.cpp:9285–9291`). With pop as journal replay (CTW-2) the
recompose is gone, and `hash_grow` needs **only the frontier** — the last,
partial chunk of each layer — never a full chunk below it. So the pruned
layers are cache the Rust grower never reads either. Options: (a) port
neither — write only frontier chunks per layer plus layer 0 whole (set A,
KEEP-C), and delete `curve_tree_checkpoints` (the meta row is the
checkpoint at every height, since it is journaled); (b) port both as
written. Default **(a)**: it is what the grading already says the tables
are, and a checkpoint table whose only reader was the C++ integrity check
is a second source for the meta row (rule 05).

### 3.6 Maturity is rule-set data (`CTW-Q5`)

The miner window is `RuleSet::mined_money_unlock_window` (60, CEN-F6).
The listed-output age, `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE = 10`, has **no
Rust home** outside `shekyl-curve-tree` and two spikes (CTW-6). When an
output enters the tree decides which root a spend can anchor to — consensus
— so the age is a `RuleSet` field read by the grow (3b), not a constant in
the store. Default: `RuleSet::tx_spendable_age: BlockCount`, `GENESIS` = 10,
with the same `Fault` width note as `reorg_cap` (it adds 8 bytes; the boxed
payload absorbs it).

---

## 4. Store invariants this increment builds or restates

| Row | Statement | Status after E3 |
| --- | --- | --- |
| SI-4 | `curve_tree_roots[h+1]` written exactly once per connect | built (S-CHAIN-W); unchanged |
| SI-11 | `curve_tree_leaves` dense over `[0, leaf_count)` | minted; **becomes holdable** — 3a writes positions `leaf_count + i` in order |
| SI-12 | a grown summary's root is the live root | minted; **becomes live** — 3c's assert against the verdict's root |
| SI-16 (candidate, CTW-4) | `output_to_leaf` and `leaf_to_output` are inverse bijections over drained outputs | new |
| SI-17 (candidate) | a pending row's maturity is `> h` for every row standing after the connect of `h` | new — the drain is exhaustive |

Every one is a *store* property (holds regardless of the rules); the
question of *which* root is correct is the validator's (§3.1).

---

## 5. Round-0 findings

| Finding | Statement |
| --- | --- |
| **CTW-1** | **The hook comment names a retired step.** `connect.rs:22` "→ segment freeze" — retired by `PDM-Q12` (2026-09-18) and never a phase of *this* store. Three steps, not four. Corrected with the body. |
| **CTW-2** | **`trim_curve_tree` has no port.** The C++ pop recomposes layers from layer 0 because LMDB's tree writes had no journal. The Rust store journals every write (`open_insert_table`; SCW-7's structural floor) — pop restores 3a–3c's pre-images. A recompose would be a second mechanism for a fact the journal holds (rule 05). |
| **CTW-3** | **Two of the five pending-side tables are C++ pop journals.** `pending_tree_drain` and `block_pending_additions` exist so `pop_block` can undo the drain and the collect. Under CTW-2 they are dead on arrival; deleted, not typed. Denominator: the redb bijection gate's table set moves by two (`check_redb_schema_bijection.py`, `tables.snap`). |
| **CTW-4** | **The position maps are a bijection nothing asserts.** `output_to_leaf` / `leaf_to_output` are written pairwise and read singly; an SI row (SI-16 candidate) makes the pair a check that can fail at 3a. |
| **CTW-5** | **The corpus is already a root KAT.** Every captured chain carries `root_after` per height (RD-Q2's fact tag `0x01`, `DRS_E2_REPLAY_DRIVER.md:417`). Once the grower runs on replay, equality at every height is a free KAT over four chains — and the first place a grow-arithmetic divergence from the C++ would show. RD-Q9's borrowed root becomes exactly this assertion. |
| **CTW-6** | **The listed-output spendable age has no Rust home.** `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE = 10` (`cryptonote_config.h:49`) appears in Rust only in `shekyl-curve-tree` and two spikes; `RuleSet` has the miner window and not this. It decides when an output becomes anchorable — consensus data (`CTW-Q5`). |
| **CTW-7** | **S-CURVE's `TreePosition` move is still owed.** §3.4 defaulted to moving `shekyl_curve_tree::types::TreePosition` to `shekyl-types` so both stores key on one word; the leaf table is keyed `u64` today (`schema.rs:524`). E3 keys three tables by it and is the increment that pays. |
| **CTW-8** | **The grow reads only the frontier.** `hash_grow_selene(existing_hash, offset, existing_child_at_offset, new_children)` (`tree.rs:102`) takes one chunk hash and the child it replaces; a filled chunk below the frontier is never an input. This is what makes `CTW-Q3` (a) sound and is the property the C++'s intermediate-layer prune relied on without stating. |

### 5.1 Reproduced deviations on this surface (DRS §7.6 item 1)

None reproduced: nothing writes these tables yet, so there is no Rust
behaviour to deviate. The C++ behaviours **not** carried over are CTW-2
(recompose on pop) and CTW-3 (two journal tables) — replaced, not deviated
from, each with its reason above.

---

## 6. Commit sequence (rule 90; one PR, cut from `dev` after the rulings)

1. **Types and tables.** `TreePosition` → `shekyl-types` (CTW-7);
   `MaturityHeight`; the pending side typed; `pending_tree_drain` and
   `block_pending_additions` deleted (CTW-3); `curve_tree_checkpoints` per
   `CTW-Q3`; `curve_tree_depths` per `CTW-Q4`; layout bump; snapshots.
2. **Rule-set data.** `RuleSet::tx_spendable_age` (`CTW-Q5`); a test that
   `GENESIS` carries the C++ define, as `mined_money_unlock_window`'s does.
3. **The derivation.** Per `CTW-Q1`: the frontier read on `ChainView`
   (`BatchView` + `MockView`), the grow in the ruled crate, `root_after`
   carried; `depth_at` on `ChainView`. Negative fixture: a block whose
   pending set the view cannot serve is `Fault::View`, never a guess.
4. **The phase-3 body** (§3.2) with SI-11/SI-12 live and SI-16/17 minted;
   `ConnectFacts.root_after` deleted (the verdict carries it) — the
   passed-through set narrows by one, as slice 2 narrowed it.
5. **E2.** `placeholder_root_after` deleted; the driver's grader asserts the
   recorded root equals the derived one at every height (CTW-5); the
   scenario grows a tree; a `mine_listing` scenario admitting a
   `shekyl-tx-builder` spend — the object FOLLOWUPS `:706` waits for.
6. **Docs** (§9).

Estimated as one PR of six commits inside the 5-day ceiling; if commit 3's
ruling is (a) and `shekyl-fcmp` enters `shekyl-chain-rules`, the dependency
change is its own commit and the sequence is seven.

---

## 7. Denominator — what must stay green, what must be extended

`cargo test -p shekyl-chain-store --lib` (360 at the pin), `-p shekyl-chain-rules --lib`
(241 at the pin), `-p shekyl-chain-ingest` (82); `check_redb_schema_bijection.py`
and `check_redb_schema_key_types.py` (the table set moves by CTW-3 and
`CTW-Q3`/`Q4`); `check_store_invariant_register.py` (SI-16/17 minted →
built); `check_chain_rules_coverage` if `CTW-Q1` (a) adds a coverage row;
`check_wire_raw_hash_surface`; the doc gates. Extended: the E2 conformance
run over the four captured chains with the root assertion on (CTW-5).

---

## 8. Round-1 questions — posed 2026-09-26, not ruled

| Q | Question | Default and why |
| --- | --- | --- |
| **CTW-Q1** | Who derives the root: the verdict (a) or a grower between validator and store (b)? | **(a)**, §3.1 — slice 2's shape; I15 needs `shekyl-fcmp` in the rules crate anyway; the completeness gate sees it. |
| **CTW-Q2** | Pending key `(MaturityHeight, GlobalOutputIndex)` as a redb tuple by delegated compare (SOK-Q1's mechanism), or a packed `u128`? | **tuple** — SCU-Q3 ruled the same for `LayerChunk`: the packing was LMDB's need, not ours. |
| **CTW-Q3** | Checkpoints and intermediate-layer pruning: port neither (frontier-only layers above 0, meta row as the checkpoint, table deleted) or both as written? | **neither**, §3.5 — CTW-8 makes it sound; the grading already says CACHE; the checkpoint table is a second source for the meta row. |
| **CTW-Q4** | The height-keyed depth: a `curve_tree_depths[h]` table, or widen `curve_tree_roots`' value? | **table**, §3.4 — the roots table is KEEP-C and in digest v0; its shape does not move for a reader's convenience. |
| **CTW-Q5** | The listed-output spendable age as `RuleSet::tx_spendable_age`? | **yes**, §3.6 — it decides anchorability; the miner window already lives there. |
| **CTW-Q6** | Does E3 delete `ConnectFacts.root_after` in this PR (commit 4), or keep it one increment as a passed-through cross-check? | **delete** — a passed-through fact beside a derived one is two sources; the cross-check E2 needs is CTW-5's assertion against the *corpus*, not against the caller. |

---

## 9. Documentation owed by the increment (rule 91)

`DAEMON_REDB_STORE.md` (the `[E3 hook]` phase text at `connect.rs` and the
E3 node; the `curve_tree_*` rows of the table inventory; DRS-D3c's row);
`DRS_E1_SCURVE.md` §2.3 (E3 landed — the ask answered); `CHAIN_RULES_CRATE.md`
if `CTW-Q1` (a); `CONSENSUS_RULE_CENSUS.md` F6/I13 sites; the three
FOLLOWUPS rows (`:675`, `:702`, `:706`) closed or narrowed to E6's remaining
half; `IMPLEMENTATION_INDEX.md` rows (`CTW-`, `CTW-Q`, this document, the
S-CURVE doc's status); `CHANGELOG.md` (layout bump; the root derived; the
maturity rule-set field); this file's banner → LANDED, and archive-or-stay
per §8 of the index (it stays while E4's hook phases cite its phase body).

---

## 10. Decision log

| Date | Entry |
| --- | --- |
| 2026-09-26 | Round 0 executed at `dev@1aa48eff9` after #861 and #864 merged. Findings CTW-1…CTW-8; questions CTW-Q1…CTW-Q6 posed with defaults. Families registered at birth. No code. |
