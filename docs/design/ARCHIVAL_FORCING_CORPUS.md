# Archival forcing corpus (AFC)

**Status:** scoping round. Pin: `638bb05c3`.
**Owner:** this lane. **Consumer:** DRS-E1 / E2 (`shekyl-chain-store`).
**Companion data:** [`archival_forcing_cells.tsv`](archival_forcing_cells.tsv) — the 34-cell register.

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
core digests."** `LMDB_WRITE_ATOMICITY_AUDIT.md:1235` records that *"the
replacement KAT that rule requires does not exist yet."*

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
| `FORCED-BY` | 32 |
| `EXCLUDED` | 2 |

The register is emitted as TSV so it can be gated rather than parsed from
prose: assert 34 cells, assert every table appears exactly twice, assert the
table set equals the X-macro's. Those three checks pass at this pin, and the
set difference against the X-macro is empty.

"N forceable" is a **derived** figure here. It is not asserted anywhere in
this document independently of the rows.

**One figure disagrees and is flagged rather than corrected.**
`LMDB_WRITE_ATOMICITY_AUDIT.md` §10 marks **17** distinct `archival_*` rows
`excluded` on the Digest v0 axis — counted from the rows, not from a prior
figure — while the P0e paragraph in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) describes "16 archival
journals under §7.1.1". The 34-cell denominator does not depend on which is
right: the diff needs all 17 tables populated either way. But §7.1.1's
exclusion set is what this corpus discharges, so the off-by-one belongs to
whoever owns that paragraph. Not silently rewritten here.

---

## 3. The two exclusions, both on `archival_settlement`

### 3.1 Apply — no production caller

`set_archival_settlement` has no production caller; `db_lmdb.cpp:7667` says so
in terms. **No block sequence can fire its apply path**, so this is a
pre-existing exclusion that the corpus inherits, not a corpus defect. It is
held under the writer round's §5.1 pending SO-D8.

### 3.2 Revert — vacuous, which is the subtler half

`delete_archival_settlement_for_epoch` *does* execute: it is reached from
`revert_archival_slashes_at_height` (`db_lmdb.cpp:6433`, defined `:7505`).
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
place. The note at `db_lmdb.cpp:7485-7493` sits just above
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
`tests/unit_tests/archival_settlement_table.cpp` forces both halves directly:
seven tests call `set_archival_settlement`, and `EpochRevertDropsOnlyThatEpoch`
(`:120-131`) calls `delete_archival_settlement_for_epoch` and asserts on the
result.

What it is missing is **backend reach**. Its fixture is
`TempLMDB = TempArchivalLMDB<cryptonote::BlockchainLMDB>` — already a template
over the DB type, whose own comment anticipates substituting another subclass.
That template parameter is the seam. Making this file backend-parametric
discharges §7.1.1 for settlement **without** a block sequence and **without** a
raw writer, and is the cheapest real item in this round.

---

## 4. Two forceability costs found while scoping

Both were found by checking rather than assuming, and both change the corpus's
cost profile. Surfaced here so they are not discovered at test time.

**4.1 `archival_attestation_witness` is not produced by local mining.**
`blockchain_db.cpp:673` writes the row only `if (!attestation_witness.empty())`,
and the bytes arrive on `block_connect_supplement`, which is zero-initialised
(`block_connect_supplement connect{}`) on the ordinary connect path. The
populated producers are p2p
(`make_block_connect_supplement_from_block_entry`, from
`arg.b.attestation_witness`) and verifying import. A chaingen-mined corpus
therefore forces **no** witness row by default.

The hash-keyed alt-chain counterpart carries the **same** caveat and for the
same reason: its only producer is `blockchain.cpp:2504`, which stores
`connect.attestation_witness` beside the alt block, so an unpopulated
supplement leaves both tables empty.

The corpus must populate the supplement, which is the **production input
path** and so is legitimate — this is not a raw writer. **Open question for
the build phase:** whether the bytes must be valid `r`-plus-pass-signatures to
survive B4's attestation verify. If they must, construction is real work and
needs its own scoping; `tests/unit_tests/archival_attestation_verify.cpp` is
where that answer lives.

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

**4.3 `archival_shard_segment` needs 25,992 leaves and the cheap path is
foreclosed by design.** Segment freeze fires on first crossing of
`SEGMENT_LEAF_COUNT = 25_992`. There is no regtest override, and
`config/consensus_constants.json:43` states the reason: it is **"NOT a
tunable"**, with a compile-time assert in
`rust/shekyl-archival-retention/src/segment_freeze.rs` tying it to the
`shekyl-fcmp` width constants so a width change cannot silently strand it.
Forcing this pair means ~26k outputs in the corpus. That is a scoped cost, not
a blocker, and it is the single largest item in the build.

---

## 5. Controls — what each one would establish

| Control | Shape | Establishes | Available |
| --- | --- | --- | --- |
| **Necessity** | full redb, corpus **minus** family X → diff stays green | the corpus is load-bearing; demonstrates empty-vs-empty | with E1 |
| **Sufficiency** | full corpus, redb with X's apply **stubbed** → diff goes **RED** | the comparator **can fail** | with E1 + `ApplyPolicy` |
| **Coverage assertion** | LMDB alone: after the apply segment each forceable table is non-empty; after the pop segment each returns to its pre-apply state | the corpus reaches what it claims to reach | **now** |

Necessity alone is the weaker bar and would have to be labelled as such.
Sufficiency is the one §7.1.1 actually asks for, and it depends on a switch
this lane does not own.

**7b has ruled that switch in and it can be cited.** `shekyl-chain-store` will
expose `ApplyPolicy::{Full, StubbedFamilies(&[ArchivalFamily])}` via
`with_apply_policy`, as a **runtime value rather than a cargo feature** —
because a `#[cfg(feature)]` switch compiles the store differently under test,
which would make the sufficiency control evidence about a *differently
compiled* store rather than the one that ships. The store always reports its
policy, and every comparator artifact carries the stamp, so a non-`Full` run is
structurally unusable as §8.1 parity evidence rather than merely discouraged.

The coverage assertion has its own red control: drop one corpus segment and
that family's assertion must fail.

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

---

## 8. What this round does and does not build

**Does:** the 34-cell register and its three gates; the two exclusions with
their evidence; the two forceability costs; the reuse inventory; the interface
agreement with 7b on `ApplyPolicy`; the TLB decision.

**Does not, with named blockers:**

- The corpus sequence itself — blocked on the TLB shape, since it extends TLB
  rather than duplicating it.
- The sufficiency control — blocked on `ApplyPolicy` landing in
  `shekyl-chain-store` (ruled in, not yet built).
- Settlement's two cells — blocked on **SO-D8**; the backend-parametric
  fixture of §3.4 is the part that is *not* blocked.
- The attestation-witness validity question of §4.1 — open, and it gates how
  much construction that family needs.
