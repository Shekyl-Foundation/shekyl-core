# DRS-E4 slash-log round — the log's horizon and its key (`SLK-`)

**Status:** OPEN — **Round 0 posed 2026-10-02 (DRS-E4 commit 10), not yet
ruled; no code.** A short round after DRS-E4's PR-b, scoped to one table
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

- It does not make the slash families corpus-exercised. That is `ARW-Q18`
  (`DRS_E4_ARCHIVAL_WRITER.md` §8, `../completed/`), posed on the stamp's
  declared red and not reopened here.
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
