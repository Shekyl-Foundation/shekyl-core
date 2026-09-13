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

### 3.5 The routed question: is settlement's bar already met?

**Routed, not ruled here — §7.1.1 belongs to the DRS-0 document, not to this
lane.** The rule has two sentences and they gate different things:

> **Rule:** do **not** extract/port **S-ARCH** (or implement archival apply in
> `shekyl-chain-store`) until digest coverage includes the archival journal
> families (**or an explicit, named exclusion with a replacement KAT that
> forces apply/revert to run**). ... digests must still *see* production LMDB
> behavior for those paths **before claiming parity**.

The parenthetical gates **extraction**. The trailing clause gates **parity**.
Read that way, both of the following are true at once, and the register should
say which bar it is talking about:

- **Extraction, for `archival_settlement` only: arguably met today.** The
  escape clause wants a named exclusion plus a KAT that forces apply/revert to
  run. §3.1–3.2 are the named exclusion; `archival_settlement_table.cpp` is
  the KAT, against production `BlockchainLMDB`, with no redb, no façade and no
  corpus. This also breaks a circularity worth naming: §7.1.1 bars
  *implementing archival apply in `shekyl-chain-store`*, so "write the Rust
  apply, then KAT it" cannot be the order. KAT-first against the C++ is the
  only direction that opens.
- **Parity: not met, and not by this KAT.** §7.1.1's own first paragraph names
  the hazard as *"a backend can omit all apply/revert hooks and still pass core
  digests."* A KAT that exercises **LMDB's** hooks cannot detect **redb**
  omitting **its** hooks — it does not touch redb at all. So the KAT satisfies
  the clause's letter without addressing the hazard its preamble states. What
  addresses that hazard is the corpus, the diff, and the `ApplyPolicy`
  sufficiency control of §5.

**Recommendation to whoever owns §7.1.1:** treat the existing KAT as
discharging the **extraction** bar for the settlement family, keep the
exclusion named, and keep the parity bar owed against the corpus. If instead
"replacement KAT" was always meant to imply cross-backend reach, then the
clause as written is weaker than its rationale and should be tightened — which
is a one-sentence edit, and better made deliberately than discovered at a
green.

---

## 4. Three forceability findings from the scoping pass

All three were found by checking rather than assuming. Two are costs that
change the corpus's build; the third removes one. Surfaced here so none of
them is discovered at test time.

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

**The switch is ruled in and can be cited.** `shekyl-chain-store` exposes
`ApplyPolicy::{Full, StubbedFamilies(&[ArchivalFamily])}` via
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
- Settlement's two **corpus** cells — blocked on **SO-D8**, which is the
  writer landing. Nothing in this round moves them.
- The attestation-witness validity question of §4.1 — open, and it gates how
  much construction that family needs.

**Withdrawn during the round:** the backend-parametric settlement fixture.
Proposed here, declined by E1's owner on the DRS-D1 façade ground and on the
stronger one that the KAT would then be testing its own adapter (§3.4). It is
replaced by the routed question of §3.5, which is cheaper than the thing it
replaces and does not need the fixture at all.
