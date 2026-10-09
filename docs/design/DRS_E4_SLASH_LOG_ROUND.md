# DRS-E4 slash-log round — the log's horizon and its key (`SLK-`)

**Status:** OPEN — **Round 0 posed 2026-10-02 (DRS-E4 commit 10), not yet
ruled; no code.** **UPDATE 2026-10-09: Round-0 pre-flight run at
`dev@6b23eab315` (after E6 slice 8, PR #953), recorded in §1.1 — five
findings `SLK-1…SLK-5`, two of which re-shape `SLK-Q1`'s default (the
assertion moves from the writer to the read; the depth term is the store's
own); awaiting the maintainer's ruling on Q1 and Q2 before any code (rule
26).** A short round after DRS-E4's PR-b, scoped to one table
(`archival_slash_log`), one writer (`write_slashes`, `store/archival_write.rs`)
and two readers. It was born carrying a question rather than minting one:
`ARW-Q19` ([`DRS_E4_ARCHIVAL_WRITER.md`](../completed/DRS_E4_ARCHIVAL_WRITER.md)
§8, POSED 2026-10-02) is **re-homed here as `SLK-Q1` and `SLK-Q2`** at the
maintainer's direction — *a document kept live for one open question becomes
the place that question hides, and the round that owns it should carry it
from the start* — so DRS-E4 could close as record the same day. Identifier
families **`SLK-`** (findings) and **`SLK-Q`** (questions), registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 with this file (rule
94 §1; `check_index_prefix_uniqueness.py` branch (a): `SLK` and `SLK-Q`
distinct, clear of the 111 registered). Owns FOLLOWUPS' *Journal horizon
asserted at the journals' retirement site* row. Parent plan:
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) (the S-ARCH row, write half
LANDED 2026-10-02); the horizon's record is
[`ARCHIVAL_PRUNED_DAEMON_MODE_ROUND.md`](../completed/ARCHIVAL_PRUNED_DAEMON_MODE_ROUND.md)
`PDM-Q-F16` / `PDM-Q-F19` (closed as record) and its function is S-PRUNE's
([`DRS_E1_SPRUNE.md`](DRS_E1_SPRUNE.md) §12).

**One sentence.** The slash log is the one archival journal that survived
`ARW-Q2` as history, it is stored as if it were read forever when every
consensus read of it is bounded, and its key names *when* a slash was
written while its one production reader asks *who held what at `h`* — the
first is a retention assertion this round owes before genesis, the second a
re-key it may or may not take, and the order is fixed: **horizon first,
then key**, because the horizon's answer may decide the key's shape.

---

## 0. Why a round, and why this order

Two questions arrived in one `ARW-Q19` row because neither is free of the
other, and DRS-E4 did not rule them for a reason of record (rule 19): a key
change and a retention floor are a different validation surface from the
oracle's, the same reasoning that sent the forty-signature retype to its own
slice (`ARW-Q16`). The round is cheap because nothing has shipped — the
writer has exactly one caller and the table one reader — and it is **owed
before genesis** for one reason that is not an optimisation: retirement is
node-local, so adding it later is not itself a hard fork, but a reader added
later that reaches **below** the horizon would be one, and the assertion at
the retirement site is what turns F19's *emergent* bound into a *contract*.

**Horizon first.** The maintainer's correction on commit 8's report fixes
the order and the shape: the horizon is **an assertion at the contract
side, not a pruner** — `write_slashes`' batch asserts `journal_horizon`,
and rows below it are retired in the same batch S-PRUNE's body discard
already runs in. With the horizon enforced the table is small either way
(slashes are events; F19's window is `14·SEB + D_max` blocks), so neither
scan is the argument for the key. The argument is which read the key's
shape makes **unspellable-wrong**: strict-above and the denomination (the
query), or the retirement boundary (the horizon). A table with a retention
floor may want the height leading after all — which is why the key waits.

## 1. What is built (read at the tree, 2026-10-02)

| Piece | Where | Shape |
| --- | --- | --- |
| The table | `schema.rs` `ARCHIVAL_SLASH_LOG` | `(u64, u32) → Coded<SlashLogEntry>` — `(height, seq)`, height-led |
| The writer | `store/archival_write.rs` `write_slashes(connecting: BlockHeight, &ArchivalDelta)` | appends dense at the **connecting height** (`ARW-Q17`, RULED: the connecting height, from the fold predicate the log exists for); refuses a prior append at `h` (`StoreInvariant::SlashLogNotDense`, SI-22) |
| The consensus reader | `shekyl-chain-rules` `archival/slash.rs` → `holds_shard_at` | asks *did `P` hold `s` at `h`*; reads one range from `(h + 1, 0)` over **every persona's** slashes, filtered to `P` in `slash_log_after` (`store/archival_reads.rs`, `entry.persona == *persona`) and to `s` inside the fold |
| The oracle reader | `ReadSnapshot::archival_snapshot` (`store/read.rs`) | walks the **whole** table into the `0x04` trace record's `slash_log` family |
| The invariant | `STORE_INVARIANT_REGISTER.md` SI-22 | *dense per height; every row's `(persona, shard, epoch)` is a key of `archival_slash_applied`* |
| The digest preimage | `DRS_E4_ARCHIVAL_WRITER.md` §3.8.1 (`../completed/`) | `u64 height ‖ u32 seq ‖ Canonical(SlashLogEntry)` — the key is in it |
| The horizon function | `shekyl-chain-rules` `reorg.rs` `journal_horizon(tip) -> Option<BlockHeight>`, `journal_horizon_under(tip, epoch_blocks, reorg_cap)` | `tip − ((k + n)·SEB + D_max)`, `k = SLASH_GRACE_EPOCHS = 1`, `n = FAILURE_WINDOW_N = 13`; `None` while the chain is shorter; the session form takes the store's `Horizons` pair (rule 71) |
| The retirement site | — | **not built.** No caller of `journal_horizon` exists; `prune.rs` names no archival table |

Facts the proposal below must not hide (carried from `ARW-Q19`, each for
this round to rule rather than meet):

- **(a)** `SlashedHolding::CompleteTree` (`shekyl-types` `archival/slash.rs`)
  proves `P` held **every** shard while the row names the one challenged — a
  `(p, s, ·)` range sees only slashes challenged on `s`, so the complete-tree
  arm needs a second seek (a sentinel shard, or a `(p, h)` key with the shard
  filtered as now).
- **(b)** `(p, s, h)` is **not unique** — one deadline scan settles several
  epochs' misses on one pair at one connecting height, which is what `seq`
  disambiguates today (`archival_slash_applied` is keyed `(p, s, E)`; the key
  would need `E` or keep `seq`).
- **(c)** the key is in the v1 digest preimage and in SI-22's *dense per
  height* wording, so a re-key is a layout bump, a digest bump and an
  invariant restated — all pre-genesis, none free.

### 1.1 Round-0 pre-flight — 2026-10-09 at `dev@6b23eab315` (rule 26)

Run after E6 slice 8 landed (PR #953, merge `687580e6e3`), the condition
the 2026-10-04 next-step answer set for opening this round's code. Every
row of §1 re-read at the pin; the two readers walked to their callers; the
retirement template (`store/prune.rs`) read whole. **No premise of §1
failed; five findings are minted about the *shape* the defaults took.**

**§1 re-verified, with cites.**

| §1 row | At the pin | Holds |
| --- | --- | --- |
| Table | `schema.rs:591` `ARCHIVAL_SLASH_LOG: TableDefinition<(u64, u32), Coded<SlashLogEntry>>`; key type `SlashLogKey` (`ids.rs`), `above(h)` = `(h + 1, 0)..`, `None` at the last height (`ids.rs:570-574`) | yes |
| Writer | `store/archival_write.rs:402-466` `write_slashes(connecting, &ArchivalDelta)`: `open_insert_table(ARCHIVAL_SLASH_LOG, SlashLogNotDense)` (`:417`), density ranged from `(connecting, 0)..` (`:422`), `ARCHIVAL_SLASH_APPLIED` via `insert_observing` (`:441`), watermark cell last; gated per family by `ApplyPolicy` (`:408-409`). Rows land at the **connecting** height only (`ARW-Q17`) | yes |
| Consensus reader | `store/archival_reads.rs:138-158` `slash_log_after` — one range from `SlashLogKey::above(height)`, `entry.persona == *persona` at `:154`; reached from `ChainView::slash_log_after` (`store/view.rs:278`, `chain-rules/src/view.rs:414`, `harness/views.rs:331`) by **one** production caller, `baseline_observed` (`chain-rules/src/archival/slash.rs:224-231`), fed to `holds_shard_at` (`shekyl-archival-retention/src/held_at_height.rs:104-125`) | yes |
| Oracle reader | `store/archival_reads.rs:489-499` walks the whole table into `SnapshotFamily::SlashLog`; the `0x04` witness pins the family's bytes (`store/slash_scan_bench_tests.rs:504-521`) | yes |
| Invariant | `STORE_INVARIANT_REGISTER.md:73` SI-22, *dense per height; every row's `(persona, shard, epoch)` is a key of `archival_slash_applied`*; `StoreInvariant::SlashLogNotDense { height, observed: SlashFault }` (`store/invariant.rs:256-261`), register ordinal 22 (`:395`), last row SI-24 (`:75`) | yes |
| Horizon function | `chain-rules/src/reorg.rs:100-123` `journal_horizon(tip)` / `journal_horizon_under(tip, epoch_blocks, reorg_cap)` — `(SLASH_GRACE_EPOCHS + FAILURE_WINDOW_N)·epoch_blocks + reorg_cap`, checked throughout, `None` while the chain is shorter; `D_MAX` at `:70`, `SEB > D_MAX` const-asserted `:72-76`. `rg journal_horizon rust/shekyl-chain-store/src/` — **no caller** | yes |
| Retirement template | `store/prune.rs:353-370` `prune_at_boundary(height)` → body `discard_range` (`:731-741`, un-journaled `retain_in`) then `retire_undo_rows` (`:378-417`: floor `height − undo_retention`, monotone, `retain_in::<u64,_>(..floor)`, `UndoLogFloorCell` put, first-key check SI-6). `Horizons { epoch, undo_retention }` (`:180-183`), `new` refusing `undo_retention < reorg_cap` (`:193-216`), `production`/`under` setting both to the cap (`:224-246`). Pop reverses slash-log inserts through the journal — `(u64, u32)` is `Restorable` (`store/undo.rs:102-107`) | yes |
| Facts (a)–(c) | (a) `removed_holding`'s `CompleteTree` arm is `true` for any shard (`held_at_height.rs:133-138`); (b) `SlashAppliedKey` is `(persona, shard, epoch)`, the log's `seq` is the per-height ordinal (`ids.rs`, `undo.rs:102-105`); (c) the witness encodes `height ‖ seq ‖ Canonical(entry)` (`slash_scan_bench_tests.rs:513-521`) and SI-22 says *dense per height* | yes |

**The bound, derived from the Rust reader rather than inherited from
F19's C++ read** (`16-architectural-inheritance` — a claim is a hypothesis
until read at the implementation). The scan at connecting height `c`
settles epoch `E` once `c > slash_deadline_height(E) = last_block(E + k)`
(`slash.rs:105-108`, `:199`), so in steady state `c = (E + k + 1)·SEB`;
the watermark advances on every connect, so the scan is never behind. The
failure window walks back to epoch `E − (n − 1)` (`:254-260`); for each,
`baseline_observed` computes `h_fire ∈ (h_open, h_close]`
(`challenge.rs:158-178`) and reads the log **above** `h_fire` (`:224-227`).
The deepest row any read reaches is therefore at height
`≥ (E − n + 1)·SEB + 2 = c − (k + n)·SEB + 2`. The boundary batch at `T`
retires rows below `T − (k + n)·SEB − r`, `r` the undo retention; `pop`
cannot take the tip below `T − r` (the floor `retire_undo_rows` just
wrote), so the lowest connecting height that can follow is `T − r + 1`,
whose deepest read is `≥ T − r − (k + n)·SEB + 3` — **three blocks above
the retired range**. The same holds for a cold-watermark replay, because
the retirement is recomputed at every historical boundary from the same
tip the scan reads at. F19's formula is confirmed from the Rust, with
`D_max`'s role made exact: it is the depth `pop` can move the tip, which
the store names `undo_retention`.

*After PR #1007* the reader is shallower, not deeper: its slash pass
deletes `baseline_observed` and the per-epoch fire-height read — the
failure window walks **settlement rows** (`outcome`, A14) for the earlier
epochs — and the log is read only while settling epoch `E` itself:
`after_open` above `h_open(E)` once per persona, and above a draw's own
issuing height `at ≥ h_open(E)` when the persona was slashed during or
after the epoch (`slashed_after` / `counted`, the PR's `slash.rs`). The
deepest read becomes `≥ E·SEB + 1 = c − (k + 1)·SEB + 1`, twelve epochs
inside F19's window. The window is **not** re-pinned to match: F19's
expression is ratified (`PDM-Q-F19`, `DRS_E1_SPRUNE.md` §3) and names the
depth a reader *may* reach, the table is events either way, and tightening
a retention to one reader's current shape is the inherited-figure move
rule 16 warns against. Reopen criterion (rule 21): a ruling that the
settlement rows, not the log, are the only history the window may consult
— then `(k + 1)·SEB + D_max` is the expression and `journal_horizon`'s doc
changes with it.

**Findings.**

- **`SLK-1` — `SLK-Q1`'s default puts the assertion where it cannot
  fail.** §2 says *"a slash row the delta would place at or below the
  horizon is a refused write."* Rows are written at `connecting`
  (`ARW-Q17`, `archival_write.rs:422`), and `horizon(tip) ≤ tip − window
  < connecting` by the function's own arithmetic — the refusal is
  unreachable, a defence that cannot fail and consumes the attention that
  would find the gap (`16-architectural-inheritance` §corollary, item 2).
  F19's record places the check elsewhere, in its own words: *"`at_height
  ≥ retirement_floor` asserted where the scan **starts**, going red before
  the scan reads a retired range"*
  (`ARCHIVAL_PRUNED_DAEMON_MODE_ROUND.md` `PDM-Q-F19`, closing paragraph).
  The contract the horizon protects is a **reader's** (§2, *Why the writer
  and not only the pruner*), so the contract-side assertion is on the
  read: `slash_log_after(persona, height)` refuses when its range start
  `(height + 1, 0)` lies below the floor — a new `StoreInvariant` arm, the
  reader's defect named as the store's refused read (fatal, never
  `InvalidBlock`; C2-R8 arm B: it would have to hold whatever the
  consensus rules said). The maintainer's two corrections stand as made —
  *an assertion, not a pruner*; depth `(k + n)·SEB + D_max` — only the
  site moves: the assertion to the read, the retirement to the boundary
  batch, both through the one function. **Proposed re-shape of Q1's
  default; for the maintainer to rule.**
- **`SLK-2` — the depth term is the store's own, not a rule set's.** The
  store holds `Horizons { epoch, undo_retention }` and no rule set (rule
  71); `undo_retention ≥ reorg_cap` at construction, equal to it under
  `production`/`under`, and it is the depth `pop` can actually rewind the
  tip (the undo floor is `tip − undo_retention`). F19's `D_max` term is
  defined as exactly that depth, so the store-side call is
  `journal_horizon_under(tip, horizons.epoch().get(), horizons.undo_retention())`
  — exact in meaning, `D_max` in production, deeper (the safe side) only
  when a test opens a store with a retention above its cap. No plumbing of
  `RuleSet::reorg_cap` into the store is needed, and §2's
  `journal_horizon_under(tip, SEB, D_max)` is read as this.
- **`SLK-3` — derived floor, not a second cell.** The undo journal keeps
  `UndoLogFloorCell` because `pop` must tell *pruned below* from *lost*
  once `block_info` rows are gone (SPR-4, `prune.rs:17-29`), and because
  the journal is dense so its first key can be checked against the cell
  (SI-6). Neither reason transfers: the slash log is sparse (rows only at
  slashing heights), so a first-key check means nothing, and no caller
  needs to tell *retired* from *never slashed* — an empty range above the
  floor is a legitimate answer, and the read check of `SLK-1` refuses a
  range that starts below it before it looks. What a derived floor costs:
  after a pop of depth `d ≤ r` the recomputed floor sits `d` blocks under
  the one the rows were retired at, and a read into that band would pass
  the check and find nothing — F19's silent-read shape, confined to `r`
  blocks that the derivation above shows no read enters (margin three).
  **Default: derive from the tip, no cell; the margin is the falsifier's
  test (below).** Reopen (rule 21) if a reader appears whose depth is
  within `undo_retention` of the window — then the cell is the exact
  check and is added as `SlashLogFloorCell` beside the undo cell.
- **`SLK-4` — sequencing: this round's code lands after PR #1007.** The
  open settlement-writer PR (`feat/settlement-writer`, `SO-D10`) edits
  `store/archival_write.rs`, `store/archival_reads.rs`,
  `store/invariant.rs`, `store/error.rs`, `store/undo.rs`, `read.rs`,
  `view.rs` and `STORE_INVARIANT_REGISTER.md`, mints **SI-25**, and
  re-shapes the one production consumer of `slash_log_after` (the
  fire-height read goes; `slashed_after` reads above the settled epoch's
  first block and above each counted draw's height — the bound paragraph
  above). Landing before it would conflict on every file this round
  touches, collide on the SI ordinal, and pin a test to a reader about to
  be deleted. So: the horizon's row is **SI-26**, §1's reader row is
  re-read against #1007's `slash.rs` when the code opens (the
  `held_at_height.rs:81-85` premise — *`ChainView::slash_log_after` is the
  only producer* — stays true either way), and this round opens its code
  after #1007 merges.
- **`SLK-5` — the oracle family's bound and the witness's read.**
  `archival_snapshot` walks the whole table (`archival_reads.rs:489`); once
  a chain outgrows the window a retiring node's `0x04` `slash_log` family
  is *rows at or above the floor*, which the round states as the family's
  bound (§5, `DAEMON_REDB_STORE.md`). None of the six corpus chains or the
  bench witness reaches it: the witness runs `SEB 100 / cap 50` to
  `(m + 2)·SEB − 1 = 1 299` blocks (`slash_scan_bench_tests.rs:116, :652`)
  against a window of `14·100 + 50 = 1 450`, so its `slash_log_after(p, 0)`
  read (`:413`) passes `SLK-1`'s check only because the floor is `None`
  there. A witness that grows past the window reads from the floor, not
  from `0` — a test-impact row, not a defect, recorded so the first longer
  witness does not read the refusal as a regression.

**Q1's build shape under `SLK-1…3`** (one PR, four commits, after #1007):

| # | Commit | Where | Cost |
| --- | --- | --- | --- |
| 1 | The floor and the read check: `WriteBatch`/`ReadSnapshot` compute `journal_horizon_under(tip, epoch, undo_retention)`; `slash_log_after` refuses a range start below it with `StoreInvariant::SlashLogReadBelowFloor { asked: BlockHeight, floor: BlockHeight }` (ordinal 26); the fault flows through `ReadFault` as every SI-7 arm does | `store/archival_reads.rs`, `store/invariant.rs`, `chain-rules/src/reorg.rs` (first caller) | small; the typed payload is two heights |
| 2 | Retirement: `retire_slash_rows(height)` in `prune_at_boundary` after `retire_undo_rows`, one `retain_in::<(u64, u32), _>(..SlashLogKey::new(floor, 0).key(), \|_, _\| false)`, un-journaled like the body discard (the boundary row carries none of the prune's writes; the range is `(k + n)·SEB` below any pop), no-op under a stubbed `ApplyPolicy` and while the floor is `None`; `Pruned` gains `slash_floor: Option<BlockHeight>` | `store/prune.rs` | small |
| 3 | Tests — F19's falsifiers made runnable: a fakechain pair short enough to cross the window in the unit lane (`SEB 10 / cap 5`: window 145) shows rows below the floor gone after the boundary and present above it; a pop across the boundary and re-connect re-runs the retirement idempotently and the scan never trips the arm (the margin); removing the check and asserting the test still passes is the *check's* falsifier, stated in the test's doc | `store/prune_tests.rs`, `store/archival_read_tests.rs` | moderate — the chain builder exists (`connect_fixtures.rs`) |
| 4 | Docs (§5): SI-26 row; `DRS_E1_SPRUNE.md` §3 / §12 retirement site *built*; `DAEMON_REDB_STORE.md` S-ARCH line and the `0x04` family's bound; FOLLOWUPS journal-horizon row **removed**; index rows; CHANGELOG one line (node-local retention of the slash log); this file LANDED | docs | small |

The seam between 1 and 2 is the function: both call `journal_horizon_under`
with the store's pair; neither spells the expression.

**Q2 under this shape** (§3): the retirement is one range `..(floor, 0)` and
the read check is one comparison on the range start — both read off the
height-led key; a persona-led key would make the retirement a scan and the
floor check per row, and facts (a)–(c) stand unchanged. The pre-flight's
recommendation is **not re-keyed**, with the ruling recorded at
`archival_reads.rs:154`'s filter as §3 requires; #1007's re-shaped reader
(`slashed_after`, `counted`) still filters by persona through the same
read above a height, which the height-led key serves without a second
shape.

**Review-round denominator.** Surfaces examined that yielded nothing:
`store/pop.rs` and `store/connect.rs` name no slash-log table (the pop path
reaches the rows only through the journal); `chain-ingest/src/trace.rs`
carries the family by `SnapshotFamily`, not by name — no trace-side bound
to state; `ApplyPolicy`'s `SlashLog` family gating at the writer
(`archival_write.rs:408-409`) leaves the retirement a no-op on an empty
table and the read check unaffected; `DRS_E1_SPRUNE.md` §3 and `reorg.rs`'s
doc carry the 2026-10-02 premise correction, and the one other "no Rust
writer" sentence (`DRS_E1_SPRUNE.md:417-418`, *the journals have no Rust
writer **here***) is a dated 2026-09-22 correction scoped to S-PRUNE and
true as written; the FOLLOWUPS row's falsifiers read as the row says
(`rg journal_horizon rust/shekyl-chain-store/src/` empty; the
`SLASH_GRACE_EPOCHS + FAILURE_WINDOW_N` sum appears in `reorg.rs` only, its
own tests recomputing it on purpose). Not examined: the C++ side
(`DEL-008`'s, §4).

## 2. `SLK-Q1` — the horizon: an assertion at the writer's batch, and retirement beside the body discard

**The question.** Where is F19's bound asserted, and where are rows below it
retired?

**Default.** `write_slashes`' batch computes `journal_horizon_under(tip, …)`
for the session's schedule and **asserts** it — a slash row the delta would
place at or below the horizon is a refused write, not a silent one (a
violated horizon is a refused retirement, FOLLOWUPS' own words). Retirement
of rows below the horizon runs in **the same batch S-PRUNE's body discard
runs in** (`store/prune.rs`), after the undo-row retirement it already does
at `tip − D_max`, through the one function — never a literal
(`05-system-thinking` §"a formula two lanes need is a function"). Under the
height-led key that retirement is one range deletion `..(horizon, 0)`.

*Pre-flight 2026-10-09 — default re-shaped, NOT YET RULED (§1.1):* the
writer-side refusal above is unreachable (`SLK-1`), so the proposed
assertion site is the **read** — `slash_log_after` refuses a range start
below the floor (SI-26) — with the retirement in the boundary batch as
stated; the depth term is the store's `undo_retention` (`SLK-2`); the floor
is derived from the tip, no cell (`SLK-3`). The paragraph above stands as
the question was posed; the ruling edits it.

**Why the writer and not only the pruner.** Six of the seven F16 journals
dissolved into `undo_log` (`ARW-Q2`) and S-PRUNE retires that at
`tip − D_max`; the slash log is the **only** F16 journal with a retirement
left to build, and the contract it protects is a *reader's*: both consensus
reads reach back a bounded distance — the fold is asked at
`h_fire ∈ (H_seal, H_close]` and the deadline scan at its own deadline — so
the deepest row any consensus read reaches is F19's, **not**
`tip − (W + 1)·SEB` (`MAX_CLAIM_AGE_W_EPOCHS` bounds the claim set, which
does not read the log). An assertion where rows are *written* is what a
future reader that reaches deeper would trip over at design time; a pruner
alone would let that reader exist and simply find nothing.

**What it changes for the oracle.** The C++ walker exports the whole log and
`archival_snapshot` walks the whole table, so a retiring node's `slash_log`
family diverges from a non-retiring one's once a chain outgrows the window.
None of the six corpus chains does (~1 300 blocks at `SEB 100` against a
window of `14·100 + D_max`), and the C++ walker is `DEL-008`'s
(`DAEMON_REDB_STORE.md` §12), so the comparison is unaffected before the C++
goes. The round states which snapshot the `slash_log` family covers after it
— the default is *rows at or above the horizon*, the snapshot taking the same
bound the reads take.

**Falsifier.** FOLLOWUPS' journal-horizon row still open after this round
rules; or `rg 'journal_horizon' rust/shekyl-chain-store/src/` returning no
caller while `rg 'ARCHIVAL_SLASH_LOG' rust/shekyl-chain-store/src/store/prune.rs`
returns nothing.

## 3. `SLK-Q2` — the key: by its query, or height-led with the horizon

**The question.** `archival_slash_log[(height, seq)]` is keyed by *when*;
its one production reader asks *who held what at `h`*. Does the key follow
the query?

**The case for the query.** Keyed `(PersonaId, ShardId, BlockHeight)` the
read is a prefix range — seek to `(p, s, h + 1)`, walk forward — and redb
carries the tuple natively, as `(TreeLayer, ChunkIndex)`, `(u8, u64)` and
`ServeCreditKey` already do. Strict-above then reads off the range and the
denomination lands at one site, which is what made `ARW-26` small.

**The case against, once `SLK-Q1` exists.** Retirement is a range deletion
under a height-led key and a full scan under a persona-led one; the table is
small either way with the horizon enforced, so the scans are not the
argument. Facts (a)–(c) of §1 are: the complete-tree arm needs a second seek,
`(p, s, h)` is not unique without `E` or `seq`, and the re-key is a layout
bump, a digest bump and SI-22 restated.

**Default — not taken here.** Rule the horizon first; then choose the key
for the two reads that remain, by which read it makes unspellable-wrong. If
the key stays height-led, `slash_log_after`'s filter stays and the round
records *why the query shape was not followed* in its own row, so the next
reader of `entry.persona == *persona` finds a ruling and not an omission.

**Falsifier.** `rg 'entry.persona == \*persona' rust/shekyl-chain-store/src/store/archival_reads.rs`
still matching after this round rules **for** the re-key; or a second key
shape for the same rows appearing anywhere (`rg 'ARCHIVAL_SLASH_LOG'
rust/shekyl-chain-store/src/schema.rs` returning two definitions).

## 4. What this round does not do

- It does not make the slash families corpus-exercised. That was `ARW-Q18`
  (`DRS_E4_ARCHIVAL_WRITER.md` §8, `../completed/`), ruled 2026-10-02:
  refused, the stamp's declared red standing, and the `0x04` record's
  slash-family encoding pinned at non-empty in the slash witness instead
  (`slash_scan_bench_tests.rs`). Not reopened here.
- It does not touch the C++ side of the key. `ARW-27`'s count-keyed row is a
  live off-by-one against its own height-denominated reader and is a deletion
  target under `DEL-008`, not a fix.
- It does not re-key `archival_slash_applied` (`(p, s, E)`), whose key is
  already its query.

## 5. Documentation owed by the round (rule 91)

`STORE_INVARIANT_REGISTER.md` (SI-22 restated if `SLK-Q2` rules for the
re-key; a new SI row for the horizon assertion if `SLK-Q1` lands as one);
`DRS_E1_SPRUNE.md` §3 / §12 (the retirement site named as built);
`DAEMON_REDB_STORE.md` (the S-ARCH row's slash-log line; the `0x04`
`slash_log` family's bound); FOLLOWUPS (the journal-horizon row **removed**
when `SLK-Q1` lands — resolved items are removed, rule 95);
`IMPLEMENTATION_INDEX.md` (`SLK-`, `SLK-Q`, this document); `CHANGELOG.md`
(the layout bump if any; the retirement). This file: LANDED, then
CLOSED-as-record and archived when both rows are ruled and built — it owns
nothing else.

## 6. Decision log

| Date | Entry |
| --- | --- |
| 2026-10-02 | **Round minted by DRS-E4 commit 10; `ARW-Q19` re-homed as `SLK-Q1` (horizon) and `SLK-Q2` (key), both POSED, neither ruled.** The re-homing is the maintainer's: DRS-E4 archives as record rather than staying live for one open question. The order of the two is fixed from `ARW-Q19`'s posing and the maintainer's two corrections on commit 8's report — the horizon is an assertion at the contract side, not a pruner, and its depth is F19's `tip − ((k + n)·SEB + D_max)` = `tip − (14·SEB + D_max)`, not `(W + 1)·SEB`. The rule-22 finding the round inherits: FOLLOWUPS' journal-horizon row read *pending* from 2026-09-22 while its condition (*"when those writers land"*) fired at DRS-E4 commit 5b (2026-09-30, `write_slashes`) and was noticed at commit 8 — and this round's own first draft wrote "landed at commit 8", the noticing date for the landing one, corrected at `git log -S'fn write_slashes'`; the premise's own text is edited in the same commit this round is minted in — `reorg.rs`'s `journal_horizon` doc and `DRS_E1_SPRUNE.md` §3 no longer say the journals have no Rust writer (rule 91's refuted-premise bullet, added this commit's sibling). |
| 2026-10-09 | **Round-0 pre-flight run at `dev@6b23eab315` (post E6 slice 8, PR #953) — §1.1; `SLK-1…SLK-5` minted; nothing ruled.** §1's eight rows and facts (a)–(c) re-verified at source with cites; F19's bound re-derived from the Rust scan (deepest read `c − (k + n)·SEB + 2`; three blocks of margin over the retired range across the deepest pop), and found shallower still after PR #1007's settlement pass (`c − (k + 1)·SEB + 1`) — the window is kept at F19's ratified expression with a rule-21 reopen named. Findings: `SLK-1` Q1's writer-side refusal cannot fail, the contract-side assertion belongs on the read (F19's own "where the scan starts"); `SLK-2` the depth term is the store's `undo_retention`, which *is* F19's `D_max` by definition; `SLK-3` derived floor, no second cell, with the band it leaves named and bounded; `SLK-4` code opens after PR #1007 (file overlap, SI-25 → this round's row is SI-26, the reader it would pin is being deleted); `SLK-5` the `0x04` family's bound is *rows at or above the floor* and the bench witness reads from `0` only because its 1 299-block chain is under the 1 450-block window. Build shape for Q1 tabled (four commits, one PR); Q2's pre-flight recommendation is *not re-keyed* with the ruling to be recorded at the filter. **Halt per rule 26 until `SLK-Q1` and `SLK-Q2` are ruled.** |
