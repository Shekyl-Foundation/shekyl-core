# Archival forcing corpus (AFC)

**Status:** scoping round. Pin: `638bb05c3`.
**Owner:** this lane. **Consumer:** DRS-E1 / E2 (`shekyl-chain-store`).
**Companion data:** [`archival_forcing_cells.tsv`](archival_forcing_cells.tsv) — the 34-cell register.
The register carries its own pin (`a6160a4bd`, re-anchored 2026-09-14 after four
SF-D8 commits shifted the anchored C++). This document's prose citations are
stated against the pin above, except where a paragraph says otherwise: the
`ApplyPolicy` section below cites its subject as SPECIFIED, not resolved, at
that pin.

---

## 1. What this is, and the reading that under-builds it

**The corpus is the block sequence that populates BOTH stores for the E2
diff.** It is not archival work that happens to produce test data. Anyone
reading it as an archival chore will under-build it: the diff needs one
sequence driving LMDB and redb through the same connects and pops, so the
corpus and the comparator cannot be designed separately and reconciled
afterwards.

It is also the answer to a specific open bar. `DAEMON_REDB_STORE.md` §7.1.1
holds that we do not extract or port S-ARCH *"until digest coverage includes
the archival journal families (or an explicit, named exclusion with a
replacement KAT that forces apply/revert to run)"*, because — in the same
section's words — **"a backend can omit all apply/revert hooks and still pass
core digests."** `LMDB_WRITE_ATOMICITY_AUDIT.md` records that
*"the replacement KAT that rule requires does not exist yet."* **That still
holds for all sixteen families**, and §3.5 says precisely why it holds for
settlement even though a KAT exists: the KAT forces the **revert** through a
production hook but only ever seeds the **apply** side through the writer,
which is not the apply path.

**The diff does not discharge that bar; it consumes it.** Empty-vs-empty
passes a digest comparison. The corpus is the half that makes the comparison
mean something, and is therefore the discharge itself. (Raised by 7b,
unprompted, against an earlier framing in which the diff discharged §7.1.1.)

---

## 2. The denominator is 34, not 17

17 tables, derived from the `X(LMDB_ARCHIVAL_...)` X-macro at
`src/blockchain_db/lmdb/db_lmdb.cpp:350-366` rather than hand-listed, each
with **two** cells: an apply half and a revert half. Every cell resolves to
`FORCED-BY:<event>` or `EXCLUDED:<reason>`.

| | |
| --- | --- |
| Cells | 34 |
| `FORCED-BY` | 28 |
| `EXCLUDED` | 6 |

The register is emitted as TSV so it can be gated rather than parsed from
prose: assert 34 cells, assert every table appears exactly twice, assert the
table set equals the X-macro's. Those three checks pass at this pin, and the
set difference against the X-macro is empty.

"N forceable" is a **derived** figure here. It is not asserted anywhere in
this document independently of the rows.

**A figure that looks like an off-by-one is two denominators, and both are
right.** `LMDB_WRITE_ATOMICITY_AUDIT.md` §10 marks **17** `archival_*` rows
`excluded` on the Digest v0 axis, while the P0e paragraph in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) says "16 archival
journals under §7.1.1". Parsed **by column** — the token `excluded` appears in
both the Digest v0 and Accumulator class columns, so a row-wise grep
over-counts — §10's Digest v0 axis is 21 `excluded`, 24 `uncovered`, 3
`v0-partial`, 1 `v0`, summing to 49. The 21 decompose exactly as P0e states:

| Group | Members |
| --- | --- |
| 16 archival journals | the 17 `archival_*` rows **less** `archival_alt_attestation_witness` |
| 4 outside the main-chain domain | `alt_blocks`, `archival_alt_attestation_witness`, `txpool_blob`, `txpool_meta` |
| 1 dead | `txs` — "opened, never written or read through its handle" (DRS-W4) |

So **17 counts the `archival_` prefix; 16 counts archival journals by role**,
with the alt witness grouped beside `alt_blocks` in §5 because that is where
its divergence lives. Nothing to correct. Recorded because this lane first
filed it as a discrepancy: the flag was raised on a row-wise match, and 7b's
column-wise recount is what dissolved it. The 34-cell denominator is unaffected
either way — the diff needs all 17 tables populated.

---

## 3. The six exclusions, across three families

**Three tables, two blocker categories** — the distinction the six-cell count
turns on. All three are excluded for the **same structural reason**, that the
tree has no producer for them, and in all three the revert half is **vacuous**
over a table nothing writes. They separate only by what would unblock them:

| Table | Apply excluded because | Blocker |
| --- | --- | --- |
| `archival_settlement` (§3.1–3.2) | `set_archival_settlement` has no production caller | **SO-D8** |
| `archival_attestation_witness` (§4.1) | no emitter exists; the supplement is never populated locally | **Phase 2/3 template writer** |
| `archival_alt_attestation_witness` (§4.1) | same emitter gap, alt-chain side | **Phase 2/3 template writer** |

Two blockers, so they discharge separately rather than together. The witness
pair was found by answering a question this round had first filed as open.

### 3.1 `archival_settlement` apply — no production caller

`set_archival_settlement` has no production caller; `db_lmdb.cpp:7668` says so
in terms. **No block sequence can fire its apply path**, so this is a
pre-existing exclusion that the corpus inherits, not a corpus defect. It is
held under the writer round's §5.1 pending SO-D8.

### 3.2 `archival_settlement` revert — vacuous, which is the subtler half

`delete_archival_settlement_for_epoch` *does* execute: it is reached from
`revert_archival_slashes_at_height` (`db_lmdb.cpp:6433`, defined `:7506`).
Reachability is not the question. **Discriminability is.** Over a table
nothing ever writes, "ran and deleted nothing" and "never ran" leave
identical stores, so no diff can tell an implemented revert from an absent
one.

That is **empty-vs-empty reproducing inside the instrument built to prevent
empty-vs-empty** — §7.1.1's own failure, one level in.

The ruling does not rest on analogy, because the analogy would have broken
it. 7b checked the sibling and reported that `put_archival_shard_segment`
maintains a persisted pop-symmetric counter alongside its table; had
settlement's revert done the same, "ran and deleted nothing" would have been
discriminable and this exclusion would be wrong. It does not — its only write
is `mdb_cursor_del` on `archival_settlement` itself, no counter, no
`properties` write, no side effect.

**Both halves are excluded under one named exclusion, discharged together when
SO-D8 lands.**

### 3.3 A refused shortcut, and the tree's own precedent

A test-only raw writer that forced settlement rows would make both cells
forceable. **Refused**, and the tree has already refused it in this exact
place. The note at `db_lmdb.cpp:7486-7494` sits just above
`delete_archival_settlement_for_epoch` itself and reads:

> ... this CALL SITE is a corruption tripwire with no red-side test --
> `set_archival_settlement` cannot write a row that fails it, so the state is
> **not constructible through any accessible interface**, and deleting this
> call fails nothing. A test-only raw writer would add a way to STORE invalid
> rows in order to prove invalid rows are rejected; **the honest note is the
> better trade.**

That is the same shape one level out. Adding a write path production does not
have, in order to exercise the revert of writes production does not make, buys
a green that describes the harness rather than the store. The honest exclusion
is the better trade here too, and it is the tree's own standing precedent
rather than this lane's preference.

### 3.4 What already exists, and what it is missing

A replacement KAT for settlement is **not** absent.
`tests/unit_tests/archival_settlement_table.cpp` reaches both halves, but
**not equally**, and the difference is what §3.5 turns on. Its **revert** runs
through production: `SlashRevertDropsEveryEpochInTheFoldedSpanAndRewindsBelowIt`
(`:207`) performs a real `process_archival_slash_at_height` fold and then calls
`revert_archival_slashes_at_height` (`:251`), which reaches
`delete_archival_settlement_for_epoch`. Its **apply** does not: all twelve
`set_archival_settlement` calls go straight onto the store handle, which is the
writer rather than the apply path.

This lane first proposed making that fixture backend-parametric — it is
`TempArchivalLMDB<DBT>`, already a template — and **E1's owner declined, on
grounds this document adopts.** The fixture's comment scopes the template to
"a `BlockchainLMDB` subclass", and its constructor drives `open`,
`set_batch_transactions`, `batch_start`: the C++ `BlockchainDB` API.
`shekyl-chain-store` is a Rust crate with no such interface, so "a redb-backed
`DBT`" means a C++ class implementing `BlockchainDB` over redb through the
FFI — the façade **DRS-D1** refuses. D1's word is *permanent* and a test-only
shard is arguably not that, so the refusal does not rest on the letter. It
rests on what the green would mean: the KAT would force apply/revert through
an adapter written for the test, so passing would prove the adapter works.
That is a shim standing between the oracle and its subject, built to satisfy
the very rule that exists because a backend can omit its hooks and still pass.

### 3.5 Two gates, and why settlement passes neither yet

**RULED 2026-09-13 (Rick, at `37accf6f9`).** This section replaces an earlier
reading that this lane published and that was wrong in both directions. Both
errors are recorded rather than edited away, because both were acted on.

**§7.1.1 defines two gates, not one bar.** Separating them is what makes the
sequencing legible:

| Gate | Question it answers | Granularity |
| --- | --- | --- |
| **Extraction** | may archival apply be written in `shekyl-chain-store`? | **per family**, lands incrementally as KATs arrive |
| **Parity** | may DRS-E2 claim those rows ported correctly? | **all families at once** — it is one harness |

So extraction proceeds family by family, and parity waits once, at the end, on
the corpus through the dual-population path, both backends, diffed per row
against the register.

**Correction 1 — settlement does NOT pass the extraction gate.** This lane
first reported that it did. The gate wants *"a replacement KAT that forces
apply/revert to run"*, and the evidence splits:

- **Revert: genuinely forced.** `archival_settlement_table.cpp` runs a real
  `process_archival_slash_at_height` fold, then calls the production hook
  `revert_archival_slashes_at_height`, which reaches
  `delete_archival_settlement_for_epoch`, and asserts the folded span's rows
  drop while the neighbouring epoch survives.
- **Apply: not forced, and cannot be.** All twelve `set_archival_settlement`
  calls go straight onto the store handle. **That is the writer, not the apply
  path** — and it cannot be the apply path, because the writer has no
  production caller (§3.1). A direct store-method invocation is not apply.

The rule asks for apply **and** revert, so settlement is **half met and
therefore unmet**, and stays so until **SO-D8**. Other families may genuinely
meet the gate; settlement is the one that cannot. Its being the family that
fails every bar today is not coincidence — it is the same missing writer each
time.

**Correction 2 — the trailing clause is reference-side, not cross-backend.**
This lane read *"digests must still see production LMDB behavior for those
paths before claiming parity"* as a cross-backend requirement. It names
**LMDB**. It asks that the oracle has watched LMDB actually run those paths,
which a C++-only KAT satisfies on the literal text. The instinct that the
clause is weaker than its rationale was right; the diagnosis of why was not.

**Why the gap exists, which explains it rather than patching it.** When
§7.1.1 was written **the digest WAS the comparator** — one instrument computed
over both stores — so "coverage includes the archival journal families"
implied both sides **by construction**. Covering LMDB implied covering redb.
**That implication died when the comparator became a diff.** The cross-backend
reach was never stated because it never had to be.

**The tightening therefore belongs on the comparison side, not in the
definition of "replacement KAT".** That term is doing separate work in the
extraction leg and in DRS-E2's DIVERGENT row, and overloading it breaks both.
The proposed shape, carried in this branch's PR body as a **recommendation**
with §7.1.1 itself untouched:

> ...digests must still see production LMDB behavior for those paths before
> claiming parity, **and the comparison must reach the same paths in the
> ported backend** — a corpus that exercises apply/revert against LMDB alone
> establishes the **reference**, not parity.

## 4. Three forceability findings from the scoping pass

All three were found by checking rather than assuming. Two are costs that
change the corpus's build; the third removes one. Surfaced here so none of
them is discovered at test time.

**4.1 The attestation-witness question is ANSWERED, and the answer moved four
cells out of `FORCED-BY`.** This round first filed it as open — whether witness
bytes must be valid to survive the verify. Chased to the end, the question
dissolves into a stronger one.

Start with what is true of the input path. `blockchain_db.cpp:673` writes the
row only `if (!attestation_witness.empty())`, and the bytes arrive on
`block_connect_supplement`, which is zero-initialised on the ordinary connect
path; the populated producers are p2p and verifying import. So a mined corpus
forces no row by default, and the alt-chain counterpart at
`blockchain.cpp:2368` is empty for the same reason.

**Attaching arbitrary bytes does not work, and is a named reject shape.**
`verify_block_attestation` (`blockchain.cpp:2126`) is a hard gate on the
connect path. Its own comment lists **unsolicited witness bytes** as one of
three shapes on which it is deliberately *stricter* than the interim, so a
witness riding a block whose coinbase commits to the empty attestation root is
rejected rather than stored.

**Replaying the pinned KAT does not work either.** A frozen valid vector exists
(`archival_attestation_verify.cpp`, `pinned_valid_vector_verifies_ok`), but its
countersignature binds the **coinbase output key** (`[0x09; 32]`) and the
**predecessor block hash** (`[0x07; 32]`, the RF-D3 nonce term). A corpus block
has neither, so the vector cannot be lifted into a real chain.

**And generating a fresh one is not available: there is no emitter.** The
attestation FFI exposes exactly two entry points — `shekyl_archival_verify_attestation`
and `shekyl_archival_attestation_pass_p_ids`. Both verify. Nothing in the tree
**constructs** a witness: every `attestation_witness =` in `src/` is a copy from
the database, a wire entry, or a bootstrap record. The tree says so plainly at
`blockchain.cpp:6048` — *"Empty on local mine and until the **Phase 2/3
template writer** populates it"* — and `shekyl-p-host` still calls the
countersignature a format-round decision.

**So both witness families are excluded for want of a producer**, exactly as
`archival_settlement` is, and both revert halves are vacuous by the §3.2
argument: `remove_archival_attestation_witness_at_height` (`db_lmdb.cpp:9764`)
and `remove_archival_alt_attestation_witness` (`db_lmdb.cpp:9809`) are each a
lone `mdb_del` with no counter and no side effect, so neither can be
discriminated over a table nothing writes. The named blocker is the **Phase 2/3
template writer**, not SO-D8.

This is the round's most consequential correction, because the cost it removes
is not the one it looked like. The family was scoped as expensive construction
work; it is in fact **not constructible at all at this pin**, which is cheaper
to build and more important to know.

**4.2 The two slash tables are forceable, but not by the same event, and
neither depends on settlement.** Worth stating because the coupling looks
plausible and is not there: `delete_archival_settlement_for_epoch` is called
from the slash *revert*, which invites the reading that the slash pass writes
only against settled outcomes. It does not.
`archival_challenge_failed_at_height` reads serve-credit pass counts and
`has_archival_slash_applied`, never the settlement table, so neither slash cell
inherits settlement's exclusion.

They are forced by **different** events, and the register says so rather than
collapsing them. `archival_slash_log`'s epoch marker is written
**unconditionally**, once per height that passes an epoch's slash deadline —
cheap. `archival_slash_applied` needs a bonded P that actually fails a
challenge. The complete-tree branch of that scan reaches
`archival_shard_segment` and would drag in §4.3's 25,992-leaf cost, but the
`else` branch iterates `bond.held_shard_ids` directly, so a non-complete-tree
bond forces the row **without** a frozen segment. The corpus should take that
branch.

**4.3 The 25,992-leaf freeze gates ONE family, not the corpus — so the build
tiers.** Measured rather than assumed: of the apply hooks, only
`process_archival_slash_for_epoch` references `archival_shard_segment` at all,
and only down its complete-tree branch. `process_archival_epoch_close_at_height`
(which writes `archival_r_market`, `archival_sigma_work`, `archival_budget` and
`archival_epoch_close_log`), `apply_archival_emission_claim`,
`apply_archival_unbond`, `apply_archival_reinstate`, `put_archival_bond_record`
and `add_archival_budget_accrual` reference it **zero** times.

| Tier | Families | Precondition |
| --- | --- | --- |
| **Cheap** | every forceable family except one — bond, both slash tables, emission, the three bond journals, the four epoch-close tables, serve credit, budget accrual | ordinary blocks, a bond, an epoch boundary |
| **Expensive** | `archival_shard_segment` alone | 25,992 curve-tree leaves |

**This is the round's best scheduling news.** Extraction can unblock for
almost every family long before the leaf count is reachable, and the corpus
should be staged so the cheap tier lands first. `archival_slash_applied` is
the proof the tiering is real rather than tidy: it *looks* segment-coupled and
is not, because the `else` branch over `bond.held_shard_ids` forces the row
without a frozen segment.

**The remaining cost is genuine and unavoidable: `archival_shard_segment`
needs 25,992 leaves and the cheap path is
foreclosed by design.** Segment freeze fires on first crossing of
`SEGMENT_LEAF_COUNT = 25_992`. There is no regtest override, and
`config/consensus_constants.json:43` states the reason: it is **"NOT a
tunable"**, with a compile-time assert in
`rust/shekyl-archival-retention/src/segment_freeze.rs` tying it to
`shekyl_fcmp::tree::leaves_per_segment()`, the partition derivation both
stores take from that crate (since 2026-09-18; before that, to the width
product directly), so a width change cannot silently strand it.
Forcing this pair means ~26k outputs in the corpus. That is a scoped cost, not
a blocker, and it is the single largest item in the build.

---

## 5. Controls — and which one actually reaches the hazard

The three controls are usually listed as a menu of increasing strength. They
are not. **They have three different subjects, and only one of them has
§7.1.1's stated hazard as its subject.** The hazard, in that section's own
words, is that *"a backend can omit all apply/revert hooks and still pass core
digests."*

| Control | Subject | Shape | What a pass establishes | Reaches the hazard? |
| --- | --- | --- | --- | --- |
| **Coverage assertion** | the corpus, against LMDB | after the apply segment each forceable table is non-empty; after the pop segment each returns to its pre-apply state | the corpus reaches what it claims to reach | **No** — redb is not in it |
| **Necessity** | the corpus, against the diff | full redb, corpus **minus** family X → diff stays green | the corpus is load-bearing; demonstrates empty-vs-empty | **No** — the backend is held at full |
| **Sufficiency** | **redb's apply** | full corpus, redb with X's apply **stubbed** → diff goes **RED** | the comparator **can fail** when a hook is missing | **Yes — and it is the only one** |

The first two are **preconditions** for the third meaning anything, not weaker
versions of it. A corpus that does not reach a family makes every later
statement about that family vacuous, and a corpus whose removal changes
nothing was never load-bearing. But neither one can detect redb omitting a
hook, because neither one varies redb.

**The consequence, which E1's owner has taken and will state at the policy
stamp:** a green diff over the archival families is parity evidence **only if
redb's apply actually ran**, and the thing that establishes that is the policy
of the run, not the colour of the diff. So the comparator's green is
**conditional on a `Full`-policy run** and will be reported that way rather
than as parity standing alone.

**The switch is built and landed.** *Superseded text, retained:* at `638bb05c3`
`ApplyPolicy` was cited as SPECIFIED on an unpushed branch. It landed with
DRS-E1 increment 1 (PR #740, 2026-09-13) and was **re-shaped by increment 2
(2026-09-14)** into two types, because the first shape stamped the wrong
subject — see below.

The landed surface, in `rust/shekyl-chain-store`:

- `ApplyPolicy::{Full, StubbedFamilies(FamilySet)}` via `with_apply_policy`
  is the **session's intent**: `applies(family)` is what `WriteBatch` consults
  to refuse a stubbed family's table (`StoreCannot::FamilyStubbed`). An empty
  stub is rejected at construction. `ArchivalFamily` carries **17** variants,
  one per `archival_*` table, with `table()` giving the X-macro name and `ALL`
  in macro order; `FamilySet` is the `Copy` bitset over them.
- `Provenance` is the **file's history**: the union of every committed batch's
  stubbed set, persisted in the `properties` cell `apply_policy` and widened
  **inside the batch's own transaction** — so a closure `Err` (which aborts
  the batch) and drop leave no taint, a stubbed commit with zero rows still
  taints (the event is the commit under a stub, not the row count), and a
  later `Full` session reads and cannot narrow it. `is_parity_evidence()` is
  false for any non-empty union; `artifact_stamp()` carries
  `NOT-PARITY-EVIDENCE`. `ChainStore::provenance()` reports it on writable
  **and read-only** handles; a committing `ChainStore::write` publishes the
  widened record to that mirror under the same lock as the engine commit.

Why the split: the stamp's subject is *whether redb's apply ran for the rows
this file holds*, and a session's policy cannot answer that for rows an earlier
session wrote. Under increment 1 a `Full` reopen of a file built under a stub
would have stamped its artifacts as parity evidence; under increment 2 it
cannot, because the stamp reads the file. The `ApplyPolicy::Unknown` variant
increment 1 used for "file predates the cell" is deleted — the cell is sealed
in a fresh file's first transaction, so its absence is corruption
(`CellCorrupt`), not age.

It remains a **runtime value rather than a cargo feature** — because a
`#[cfg(feature)]` switch compiles the store differently under test, which would
make the sufficiency control evidence about a *differently compiled* store
rather than the one that ships. The store always reports its provenance, and
every comparator artifact carries the stamp, so a non-`Full` history is
structurally unusable as §8.1 parity evidence rather than merely discouraged.

The coverage assertion has its own red control: drop one corpus segment and
that family's assertion must fail.

**Two gates now pin the same 17, and that is a hazard with a cheap cure.**
E1's owner gate-pins `ArchivalFamily` bijectively against the X-macro; this
lane's gate pins the register's table set against the X-macro. Both are
anchored to the same construct, so the agreement is transitive and a third
cross-check would be redundant — **provided both read that construct the same
way.** They did not. This gate's first extractor scanned the whole file for
`X(LMDB_ARCHIVAL_...` with no digits in the name class, where the established
`check_lmdb_schema_coverage.py` scopes to the `SHEKYL_LMDB_TABLES` macro body
and allows digits. Both returned 17 today, which is how the divergence would
have stayed invisible. A future `archival_r2_market` would have been missed
here, hence absent from **both** sides of the set difference, and this gate
would have gone **green over a table nothing covers** — §7.1.1's own hazard
reappearing through the instrument built to close it. The extractor is now
character-identical to the established one, and the digit case is a red-bite.

---

## 6. Reuse, and the artifact question

Existing archival test assets at this pin: **one** `core_tests` generator
(`archival_budget_conservation`) and **fifteen** `unit_tests` files, including
`archival_serve_credit_equivalence`, `archival_emission_ct_balance`,
`archival_segment_freeze`, `archival_attestation_verify`,
`archival_settlement_table`, and the shared `archival_lmdb_test_helpers.h`.

The unit tests are mostly **direct-call** KATs over a temp LMDB, not block
sequences, so they fill cells the way §3.4 does — by reaching a hook without a
corpus — rather than by contributing corpus events. `archival_budget_conservation`
is the one existing block-sequence generator and is the natural starting point.

**DRS-TLB is the same artifact, and the corpus should extend it rather than
sit beside it.** `DAEMON_REDB_STORE.md:950` lists TestLedgerBuilder as
"Critical path E2/B" with `TLB --> E2` in the work-breakdown graph, and
`CONSENSUS_STORE_RECONCILIATION.md:324` already speaks of "DRS-TLB-generated
corpora" feeding exactly this comparison. A second corpus builder would be a
duplicate to synchronise, whose failure mode is the two drifting until a green
in one means nothing about the other. 7b owns TLB, has said it would rather
widen TLB than maintain a sibling, and takes the consequence on that side.

---

## 7. Harness constraint: arming order is process-level

The corpus needs short epochs, and the existing lever is the
`SHEKYL_SETTLEMENT_EPOCH_BLOCKS` override
(`rust/shekyl-archival-retention/src/constants.rs:202` onward), which refuses
in two typed ways: `Invalid` (`:218`) and `ArmedTooLate` — arming after the
latch.

A gtest binary runs every test in one process, so any earlier test, fixture, or
static initialiser that touches epoch arithmetic latches the value first and
turns a correct override into `ArmedTooLate`. **Set it before the process
starts** — a CMake test property or a wrapper, not `setenv` mid-run — and have
the corpus fixture assert the effective epoch length equals the armed value as
its first line. The typed refusal is the instrument working; it should not be
fought.

Pop depth is a **scoped parameter**, not a default: the reorg segments must pop
deeper than one epoch to reach `revert_archival_epoch_close_at_height`, and
shallower than the retention horizon per the ratified refusal.

**Never use genesis as a `referenceBlock`** (added 2026-09-15, CEN-I12's
absent-key walk, `CONSENSUS_STORE_RECONCILIATION.md` §5.4.1). `curve_tree_roots`
is dense from key 1 but has **no row at key 0**; `get_curve_tree_root_at_height(0)`
returns 32 zero bytes, which decode to the identity point, so a spend whose
`referenceBlock` is genesis is rejected inside `shekyl_fcmp_verify` at
`blockchain.cpp:3767` / `:3916` / `:4178` with a **proof-verification error that
says nothing about a missing root row**. No honest wallet does this (the tree at
height 0 is empty), so it only bites a hand-built fixture — and it costs an
afternoon when it does. The only chain-length constraint that follows is the one
the maturity window already imposes: the first coinbase (height 1) matures at
`1 + 60`, its leaf is in the state at `62`, and `ref_height ≤ tip − 5`, so the
first FCMP spend on a fresh regtest chain is possible from `tip ≥ 67` — a
`generateblocks` call, not a design constraint.

---

## 8. What this round does and does not build

**Does:** the 34-cell register and the **four** legs that gate it (shape,
denominator, disposition, anchors) plus its self-test; the two exclusions with
their evidence; the two forceability costs; the reuse inventory; the interface
agreement with 7b on `ApplyPolicy`; the TLB decision.

**Does not, with named blockers:**

- Four cells it had first scoped as buildable — the two attestation-witness
  families — now excluded for want of any producer (§4.1), blocked on the
  **Phase 2/3 template writer**.

- The corpus sequence itself — blocked on the TLB shape, since it extends TLB
  rather than duplicating it.
- The sufficiency control — blocked on `ApplyPolicy` landing in
  `shekyl-chain-store` (ruled in, not yet built).
- Settlement's two **corpus** cells, **and its extraction gate** — both
  blocked on **SO-D8**, which is the writer landing. Nothing in this round
  moves them. Its revert is already forced through a production hook; the
  apply half is what SO-D8 unblocks.
- The attestation-witness families — **no longer an open validity question.**
  §4.1 answers it: there is no producer at this pin, so the blocker is the
  **Phase 2/3 template writer**, not the cost of constructing valid bytes.

**Withdrawn during the round:** the backend-parametric settlement fixture.
Proposed here, declined by E1's owner on the DRS-D1 façade ground and on the
stronger one that the KAT would then be testing its own adapter (§3.4). It is
replaced by the routed question of §3.5, which is cheaper than the thing it
replaces and does not need the fixture at all.
