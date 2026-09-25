# DRS-E1 S-PRUNE — the retention prune: plan and as-built record (`PDM-Q-F31`)

**Status:** LANDED — **implemented 2026-09-25** on the S-PRUNE increment PR
(four commits off `dev` `fc6d87ca5`; layout **13 → 14**): `shekyl_chain_rules::D_MAX`
(derived from `archival_reorg_depth_blocks`, `SEB > D_MAX` const-asserted)
and `journal_horizon`, `shekyl_types::SHARD_TX_COUNT` (`T`); the boundary
batch inside `connect` (`store/prune.rs`: `D(E)` named by the epoch, whole
shards' `txs_prunable` + `txs_pqc_auths` discarded through the raw tables,
undo rows below `tip − retention` retired, the `undo_log_floor` cell);
`Horizons { epoch, undo_retention }` as the store's session parameter with
`0 < retention < SEB` refused at open; `pop` refusing below the persisted
floor; `TxRecord.pqc_auths` as `Option<PqcAuths { Retained, Discarded }>`;
`h_scarce` on the snapshot and the batch. **As built** — §14: the skeleton's
`first_tx_id` primitive was off by the coinbases; the §7 pop belt is
unreachable by arithmetic and was not minted; the `D_max` blocker below was
rule 22's unfalsifiable shape and is dissolved by the build. Round-0
findings `SPR-1 … SPR-6` are §14's rows (family registered in
`IMPLEMENTATION_INDEX.md` §2).
*Skeleton history, retained:* OPEN — **SKELETON, not a plan.** Written 2026-09-18 at
`dev@20ebdf1e5`, **re-keyed 2026-09-22 at `dev@5b2d4c6d6` to `PDM-Q2`'s
re-ruling** (the body horizon is the epoch boundary after the freeze epoch;
`W` retired), by the pruning charter's lane
([`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md),
`PDM-Q-F31`) for the **DRS-E lane to fill**: every section below names the
contract it consolidates and where that contract is ruled, so that the
three homes the prune's obligations are scattered across today (`PDM-Q-F10`,
`PDM-Q-F26`/`F32`, `SCW-7`) become one document before the first increment
is cut (rule 26: design closure precedes any cut; E1 got
[`DRS_E1_SCHAIN_W.md`](../completed/DRS_E1_SCHAIN_W.md) before its writers).
**Nothing here is proposed as new design**; where a section's contract is
not yet ruled it says so and names the question. The increment ordinal and
the Round-0 pre-flight are DRS-E's; the filename is provisional until DRS
numbers the increment (`FOLLOWUPS.md`'s F31 row is the falsifier). **The
Q1 gate is cleared:** `PDM-Q1` RULED 2026-09-18 (§9 of the charter graded
against the tx unit), so the plan **may open**; its Round-0 pre-flight owes
Q1's journal-horizon check alongside (§9 below). **One dependency this plan
cannot discharge itself, stated on its face (2026-09-23, on PR #840):** the
undo-log retention floor this surface inherits from `SCW-7` /
`pop_target_allowed` is bounded below by **`D_max`, whose numeric is
PROVISIONAL** (`PDM-Q11` RULED 2026-09-17 — shape frozen, `720` provisional,
home `CEN-E2`). A watermark fixed before that constant is confirmed is picked
by implementation convenience and inherited as if ruled — R8's shape exactly.
~~So the plan may be *written* now, but its watermark section names `D_max` as
an operand, not a number, until `PDM-Q11`'s numeric is confirmed; the
increment does not cut before then.~~ **DISSOLVED 2026-09-25 (rule 22): the
falsifier this sentence named could only fire after the work it blocked —
`D_max` is confirmed by running the mechanisms that consume it, and the
mechanism is this increment. Built with `D_max` as a parameter
(`Horizons::undo_retention`, production `D_MAX`); the numeric stays
PROVISIONAL in `PDM-Q11`, now testable.**

**Family:** none minted here. Findings and questions this document raises
at pre-flight take DRS-E's next free series (rule 94 §1), not a `PDM-` id.

---

## 1. Charter

S-PRUNE is the **Rust-only successor to the Monero-era stripe engine**, per
`PDM-Q-S0` (no C++ landing before the cutover) and `PDM-Q7` (**RULED
2026-09-18: the engine is removed completely; nothing of it survives as
design**; **the C++ engine was deleted 2026-09-21**, `feat/pruning-seed-wire-deletion`,
with both flags and the `pruning_seed` wire field — `S0` forbids
*implementing* in C++, not deleting, and the wire half did not die with the
store). Not an extraction and not a port: four of its six methods were
the stripe engine and are gone; `prune_tx_data` (Shekyl's C++ tx-data
discard, a different mechanism) went 2026-09-22 with its `output_metadata`
cache, its watermark and `txs_prunable_tip` (LMDB v15, redb v10) — S-PRUNE
starts from a store with no discard mechanism to inherit;
`PDM-Q-F17`'s triple — assignment /
advertisement / coverage — is **not** read from, because each has a
successor that is not the engine (the bond, the bond, price). S-PRUNE reads
nothing from `src/common/pruning.{h,cpp}`. [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md)
§7's S-PRUNE row is **NOT EXTRACTED** for that reason and already carries two
contracts (§5 below) with no home; this document is the home.

## 2. The predicate

`PDM-Q2` (RE-RULED 2026-09-22, shape), verbatim:

> `discard(k) ⇔ current_epoch ≥ close_epoch(k) + 2`, with
> `current_epoch = settlement_epoch_at_height(tip)` and
> `close_epoch(k) = settlement_epoch_at_height(close_height(k))`.

Shard `k` — **`T` transactions by `tx_id`, `[k·T, (k+1)·T)`, `k = ⌊tx_id / T⌋`**
(`PDM-Q6` item 5, RULED 2026-09-23; F32's byte bound superseded) — has its
prunable regions and `pqc_auths` discarded **atomically, as a
whole**, at the epoch boundary after its **freeze epoch**
`close_epoch(k) + 1`. There is no per-daemon input (`PDM-Q9`: all daemons
prune uniformly; the `k ∉ exceptions` conjunct of the first draft was
struck on #775). *Superseded 2026-09-22:* the 2026-09-18 form
`b_{k+1} ≤ first_tx_id(tip − W) ∧ close_height(k) + SEB < tip` — its first
conjunct is deleted with `W`, and the epoch floor became the predicate.

**Enforcement point:** the per-epoch batch (§4). Asserted there, never
discovered downstream — a violated predicate is a refused discard, not a
corrupted write, and it is evaluated **at discard time**: a reorg across an
epoch boundary may move `current_epoch` back by one after a discard, and
that shard is not "wrongly discarded" (Q2; pops are §7's business).
~~`first_tx_id(h)` is `block_info[h−1].cumulative_tx_count` for `h ≥ 1`~~
**CORRECTED as built (SPR-1):** `first_tx_id(h)` for `h ≥ 1` is
`shekyl_types::storage_ids_through(block_info[h−1].cumulative_tx_count, h−1)`,
which is `cumulative_tx_count(h−1) + h` — the running total counts a block's
**listed** transactions (`connect.rs`), while storage ids are dense over every
recorded transaction, coinbase included, one per block; and
**`first_tx_id(0) = 0`** (FL-R3-STORE, `BlockInfo`, landed on #772);
`close_height(k)` is `height((k+1)·T − 1)` — the last **included**
transaction's height, since `(k+1)·T` is the first of `k+1` and need not
exist yet — a binary search over the same running total. **Both primitives
stay** (the first draft of this re-key struck `first_tx_id`; it is how
`close_height`, and so `close_epoch`, is found). No new state for either.
**Genesis guard:** the batch runs the predicate **only when
`current_epoch ≥ 2`**, a branch — `current_epoch − 2` underflows in epochs
0 and 1 and is never formed (the store's `BlockHeight − BlockCount` panics
on such a boundary, and that is correct: a launch-window discard is a bug,
not a zero). The frontier shard has no `close_epoch` and is never a
candidate.

## 3. Two horizons and a floor

| Horizon | Retires | When | By |
| --- | --- | --- | --- |
| Bodies (prunable + `pqc_auths`) | shard `k`, whole | the epoch boundary after `k`'s freeze epoch: `tip = (close_epoch(k) + 2)·SEB` | `PDM-Q2` (RE-RULED 2026-09-22) |
| Pop-undo journal | rows below `tip − D_max` | retention `≥ D_max` | `SCW-7` / `PDM-Q11` |
| Slash log and the six other window-retired journals (`PDM-Q-F16`) | rows below `tip − (CRB + n·SEB + D_max)` | F19's expression, unchanged | `PDM-Q-F19` |

**Two horizons by design, not one by coincidence.** Bodies and journals
are separate horizons and neither is a tunable of the other: the body
horizon is a rule of the epoch calendar (no constant exists to name), the
journal horizon is F19's expression. `W` — the 2026-09-18 constant that
made them one number — is **retired**. The undo floor `D_max` is a lower
bound both clear and is not a third horizon: every discarded body is
`≥ SEB + 1` blocks old and `SEB > D_max` (const-asserted at `D_max`'s home
when that constant is built — owed, FOLLOWUPS).

**Who deletes what.** S-PRUNE's batch discards bodies. **Undo-row
retirement below `tip − D_max` is also this surface's** — `pop.rs` says the
floor is `1` "until the retention prune lands", so the retirement has no
other owner; it runs in the same batch, after the body discard, and is
what makes `StoreCannot::PopBelowFloor` reachable above genesis. The seven
F16 journals are **S-ARCH's** to retire (they have no Rust writer yet), at
F19's horizon, through the one function this surface mints for it (§12).

## 4. The batch — an enumeration from `close_height`; no retention exceptions

**The batch — the set is named by the epoch; nothing is searched.** The
daemon has no holdings and no frontier of its own: it has bodies for every
shard that has not reached its boundary, uniformly. The batch runs **inside
the connect transaction of the block at `E·SEB`** — not on "the tip
reaching a boundary", and not after the connect commits — on the
single-writer path (`shekyl-chain-ingest`'s connector is the natural site,
the store exposes the op); for `E ≥ 2`, the set to discard is **named by
`E`**:

> `D(E) = { k : close_epoch(k) + 2 ≤ E ≤ close_epoch(k) + 3 }`

— the shards whose `close_height` falls in `[max(E−3, 0)·SEB, (E−1)·SEB)`
(that interval is the *reading*; the predicate is the additive form), a
contiguous range of `k` read off `cumulative_tx_count` alone (item 5: no
`b_*` table, no length rows). **Every epoch comparison in this document is written additively —
`close_epoch(k) + 2 ≤ E`, never `close_epoch(k) ≤ E − 2` — because
`settlement_epoch_at_height` returns a `u64` and `E − 2` wraps in epochs 0
and 1** (Bugbot, 2026-09-23: the first draft's `E−3` wrapped at `E = 2`,
and its `h_scarce` covered every closed shard for the whole free regime).
The same page's branch-not-arithmetic discipline, applied to itself. **One redb transaction per boundary connect**, holding the block's
write set, every `discard(k)` for `k ∈ D(E)` (delete every `txs_prunable`
and `txs_pqc_auths` row in `[k·T, (k+1)·T)`; not journaled in `undo_log` —
a discard is not pop-reversible by design, §7) and the undo-row retirement
below `tip − D_max` (§3), **or the connect rolls back**. So "connected past
`E·SEB` with `D(E)` un-run" is **unrepresentable** — a structural property,
not a belt over a race (rule 16). Stop. **No frontier, no
`k*`, no search over presence, no search over anything on disk** — the
epoch already states the boundary, and the same `D(E)` is computed on
every node whether it discarded last epoch, skeleton-synced, or just
booted. *(Superseded 2026-09-22, same day: a first draft enumerated from a
frontier `k*` found by binary search over segment presence. On a band-1
node — which never held bodies — every segment is absent, so that search
names the newest shard and the answer is node-local exactly where it must
not be. Withdrawn.)*

**Why two epochs (`+ 3` as well as `+ 2`) and not one — belt, and said to be belt.** With
`D(E)` inside the connect transaction there is no crash state for the
widening to cover: a batch that dies takes its connect with it, and the
block reconnects. The extra epoch is kept because range-deleting an
already-empty range is near-free in redb and it costs nothing to say
`D(E)` twice; it is **not** what makes the mechanism safe. (The reason it
mattered before the transaction pin, for the record: a node that missed
**two** consecutive boundaries would carry a body set no other node has —
exactly the disk fingerprint #775 forbids — and the widening covered only
one.) **A node down two or more boundaries needs
nothing more — this is one mechanism, not two.** At its old tip in
`E_old` it had already discarded every shard with `close_epoch ≤ E_old − 2`;
returning, it *connects* every missed block, so it crosses the boundaries
`E_old + 1 … E_now` in order and `D(E)` fires at each, covering
`close_epoch` from `E_old − 2` to `E_now − 2` contiguously. Pruning
backwards before the outage and forwards through the resync are the same
hook on the same connect path; there is no startup sweep, and the bodies
it lacks it refetches through band 2 (Q4). **The hook can fire twice for
one `E` in exactly one way:** a reorg that pops back across the boundary
block and reconnects it, or replaces it with a different block at
`E·SEB`. Either reconnects *some* block at that height, the hook fires,
and `D(E)` runs again. Idempotence covers it — the ranges are already
empty, and undo-row retirement below `tip − D_max` is monotone in `tip`, so
re-running it deletes nothing new. Nothing to special-case; §8 makes it a
test. *(A startup catch-up sweep was
added and withdrawn the same day: it solved a case the forward pass
already covers.)*

**`h_scarce`** (`PDM-Q5`'s band-2 edge, and §7's pop floor) is likewise
named, not searched: **defined only for `E ≥ 2`**, as **the `close_height`
of the last shard with `close_epoch(k) + 2 ≤ E`** — equivalently
`max { close_height(k) : close_height(k) + SEB < E·SEB }`. Stated as
`+ 2 ≤ E` rather than `+ 2 = E` so an epoch in which no shard closed (low tx
rate) still yields the honest edge. **Empty cases, both:** in epochs 0 and 1
there is no `h_scarce` by definition (nothing can have discarded), and
before any shard has closed the set is empty — in either case `h_scarce` is
**none**, band 2 is empty and the pop floor is `1` (genesis). A subtractive
`E − 2` would have wrapped here and named every closed shard. **Block `h_scarce` is
mixed:** the shard boundary falls mid-block, so transactions at that height
with `tx_id < b_{k_max+1}` are discarded and later ones in the same block
are held — which is why the band-2 interval is `(C, h_scarce]` (inclusive)
and the pop floor is `h_scarce + 1`. Chain-derived, identical on every
node, zero disk reads.

**No retention exceptions — the archiver's store is the wallet's.**

`PDM-Q9` RULED 2026-09-18 on PR #775 (`PDM-Q-F33`): the daemon holds
archival **consensus** state only and **no archival serving state, ever**;
the fingerprint criterion is *persistent, posture-correlated*; **all
daemons prune uniformly**. The daemon-storage candidate this section was
first written for — `retain(k)` / `release(k)` over the operator leg — is
**REJECTED and withdrawn**. S-PRUNE therefore has **no exception set, no
operator input, and no per-node state**. The archiver's shards live in the
**wallet-side store** (`shekyl-curve-tree`'s store rebuilt around bodies,
served by `shekyl-p-serve`; PR #775's two-stores-by-obligation). **The
specified-to-scarce window is when the wallet fills that store from the
local daemon:** shard `k` closes at `b_{k+1}` in `close_epoch(k)`; for the whole of the
**freeze epoch** `close_epoch(k) + 1` every daemon holds it and the
archiver's wallet pulls `k`'s bodies over the operator leg through the
ordinary split transaction read (`PDM-Q10`) — pull before bond (Q9,
amended 2026-09-22); S-PRUNE then discards `k` at the boundary into
`close_epoch(k) + 2` on that daemon like every other. After the window,
acquisition is an episodic daemon fetch from another archiver (the daemon
retains nothing). Lapse is the wallet-side store's (#775's FOLLOWUPS row).
Unbonded retention (`PDM-Q7`) lives in the same wallet-side store, never
the daemon.

## 5. Store contracts in force

- **The store invariant: three legs landed, a fourth owed.**
  `DAEMON_REDB_STORE.md` §7.7 as it stands (F26, landed with A3 on #772):
  (i) hash row ⇔ 4-part txid, permanent, written at connect, never deleted;
  (ii) segment present ⇒ hash row present; (iii) hash row ∧ segment absent ⇔
  *discarded* — the shard's boundary has passed, or never held (band 1) —
  one store state with one meaning. ~~Owed with S-CHAIN-W amendment A4:
  (iv) the length rows, pairwise~~ **WITHDRAWN 2026-09-23 — `PDM-Q6` item 5:
  shards are fixed-cardinality `T`, there are no length rows, A4 is not
  owed, and §7.7 has three legs.**
- **Hash rows are outside every prune surface**, permanent.
  `txs_prunable_hash` (exists), `txs_pqc_auth_hash` (A3, #772).
- **`StoreCannot::PopBelowFloor`** as the pop refusal; the undo-log
  watermark `≥ D_max` (SCW-7, landed).
- **Body-absent is one state** for discarded and never-held; S-PRUNE writes
  nothing to mark the difference and reads nothing that depends on it.

## 6. `PDM-Q3`'s instrument

`ChainView` exposes no recorded-body accessor (`PDM-Q-F29`;
[`CHAIN_RULES_CRATE.md`](CHAIN_RULES_CRATE.md) §13). **S-PRUNE adds none.**
Any body read S-PRUNE itself needs is on its own trait (the batch currently
needs **none** — it deletes named ranges; "presence, never bytes" states
what it *may* read if it ever must, and §8 makes a presence read that
*selects* what to discard red), marked above-horizon (F29 wrote "above-`W`"; the
horizon is now the body horizon), and never reachable from
`shekyl-chain-rules`. Falsifier: a `ChainView` method returning recorded tx
bytes with no `CenRow`, or an S-PRUNE type imported by the rules crate
(`check_chain_rules_no_store.sh` is the belt).

## 7. Pops — the check, and what S-PRUNE does not do

**As built (SPR-2): the pop check reads the persisted undo floor; the belt
below was not minted.** `h_scarce` is a `close_height` below `(E−1)·SEB ≤
tip − SEB < tip`, so `tip ≤ h_scarce` has no instance under *any*
retention — not only while `SEB > D_max` — and a defence that cannot fail
consumes the attention that would find the gap (rule 16). `pop` refuses a
tip below the `undo_log_floor` cell (`StoreCannot::PopBelowFloor`); the
inequality `SEB > retention` is still refused at open
(`StoreCannot::RetentionNotInsideEpoch`) and const-asserted on the
production pair, because it is what keeps the undo floor above the body
horizon. `h_scarce` itself is built, as `PDM-Q5`'s band-2 edge
(`ReadSnapshot::h_scarce`, `WriteBatch::h_scarce`). *The skeleton's text,
retained as the record of what was posed:* ~~The pop check reads `close_height` only.~~ The **floor is the lowest
height whose block may be popped**: `h_scarce + 1`, with `h_scarce` the
`close_height` of the last shard with `close_epoch(k) + 2 ≤ current_epoch`
(§4; none in epochs 0–1 or before any shard closes, and then the floor is
`1`); a `pop` of the block at any height `≤ h_scarce` is
`StoreCannot::PopBelowFloor { floor: h_scarce + 1 }` (block `h_scarce`
itself is mixed, §4, so it is not poppable). Chain-named — no stored
frontier, no presence read; the floor is the same number on a node that
has discarded and on one that never held a body. **It is belt, on every
nettype.** The guarantee is `SEB > D_max`, const-asserted on the production
constants (§3, §12) and an invariant of every valid configuration; and
undo rows are retired at `tip − D_max` each boundary while
`h_scarce < (E−1)·SEB ≤ tip − SEB`, so the `SCW-7` undo floor sits
**strictly above** `h_scarce + 1` and this arm is unreachable by
construction. It stays because a check that can fail is worth one that
cannot (rule 16); its test constructs the unreachable case artificially —
a store with a discarded shard above the undo floor — and proves the arm
fires. One posture, not "belt on mainnet, binding on regtest" (§12).
Together with the const-assert it replaces the 2026-09-18 inequality
`W ≥ D_max`, which was argued and asserted nowhere.

**What S-PRUNE does not do.** Never touches `spent_keys`. Never touches a hash row. Never reads a byte length to place a boundary (item 5).
**Never varies per node** — inside or outside `W` (`PDM-Q7`/`Q8`/`Q9`,
#775's corollary: all daemons prune uniformly; there are no exceptions on
any daemon). Never advertises: what a node retains reaches no wire (`PDM-Q8`, serve-side
uniformity); the bond is the advertisement.

## 8. Falsifiers

Q2's (RE-RULED 2026-09-22): a shard discarded at a `tip` with
`current_epoch < close_epoch(k) + 2` (evaluated at discard time); a shard
*retained* on any daemon past the boundary into `close_epoch(k) + 2`; a
shard discarded partially on an ordinary node; **`SEB ≤ D_max`**; a `pop`
succeeding on a target `≤ close_height` of a discarded shard; a
body-horizon **constant** in any crate (the horizon is the epoch calendar).
SCW-7's one (`undo_log` retention `< D_max`), F29's one (§6), plus: any
durable archival serving state on a daemon — a body past its shard's
boundary, a persona id, a retention list (#775 / Q9); a discard that runs
while the serve-credit admission verifier still derives `R_k` from a frozen
segment (§11 — moot before the E3 cutover, and stated so the sequencing is
the mechanism); **a stored discard watermark or frontier cell, or any batch
read of segment presence that selects what to discard** — the set is named
by the epoch (§4), and either would be a second, node-local source; a
node holding a body for a shard whose `close_epoch + 2 ≤ current_epoch`
once its connect path has crossed that shard's boundary; **any epoch
comparison written as a subtraction on a `u64`** (`E − 2`, `E − 3`) in the
batch, the pop floor or `h_scarce`; **a store whose
tip is `≥ E·SEB` with `D(E)` un-run** — the batch is inside the boundary
block's connect transaction, so this state is unrepresentable and any
instance is a transaction-boundary bug; **a nettype or override
configuration with `SEB ≤ D_max`** — not a valid Shekyl configuration on
any nettype (rule 71; §12); and **the hook firing twice for one `E` (a
reorg across the boundary block) producing a different store than firing
once** — idempotence is the property, and it is cheap to test.

## 9. Sequencing

`PDM-Q1` RULED 2026-09-18 — §9 is graded against the tx unit, so the
retained set is known and the plan **may open**. Its Round-0 pre-flight
owes Q1's one implementation item first or alongside: the journal horizon
asserted at the journals' retirement site (F19's "the check"). Its first increment cannot land before: `#772` (A3, the second
hash row, `cumulative_tx_count` — landed); `PDM-Q6` item 5 — **RULED
2026-09-23 (e): no A4, no length rows; the partition is `⌊tx_id / T⌋`**;
**the constants commit — `T`'s production home, `D_MAX` at `CEN-E2` with
`SEB > D_MAX`, and the journal-horizon function of §12 — the plan's
commit 1 or a precursor PR**; and §11's
precondition, which the E3 cutover ordering discharges. *Corrected
2026-09-22:* Q1's journal-horizon assertion is **S-ARCH's** (the journals
have no Rust writer here); what this surface owes it is the function.

## 10. Replay and the digest (`DRS-D10`, `DRS-D11`)

- **Replay from the skeleton is load-bearing** (`PDM-Q-F13`, now a ruling's
  ground): every leaf-derivation input is in the unprunable base, so
  `apply_block` replay rebuilds every derived table without a byte from
  either discarded region. S-PRUNE's existence is what makes that claim
  testable — the negative control is a replay over a store S-PRUNE has run
  on. `PDM-Q6`'s reversion (b) is the falsifier.
- **The body horizon and the digest.** *Corrected 2026-09-22:* the first
  draft cited `DAEMON_REDB_STORE.md` §11.2 for "a uniform discard yields a
  floor-defined accumulator"; §11.2 carries no such sentence, so the claim
  is **demoted to a recorded assumption** until DRS states it. What is
  checkable now: digest v0 (`logical_state_digest_v0`) reads neither
  `txs_prunable` nor `txs_pqc_auths`, so a discard cannot move it; and the
  accumulator matrix grades `txs_pqc_auths` **`AppendMostly`** while this
  surface deletes its rows — that row re-grades to **`Excluded`** (as
  `txs_prunable` already is; the permanent `txs_pqc_auth_hash` row is the
  append-mostly one) in the plan's own commit, audit §10 row edited with it
  (`table_classes_match_the_audit_matrix` reads it). **Done 2026-09-25**
  (the mechanism commit; `class.rs`, audit §10).

## 11. The serve-credit transaction and the verifier precondition

- **Pass records fall under the predicate.** A serve-credit transaction's
  prunable region holds its pass records (`RF-D1`, `PDM-Q-F15`); once its
  shard's boundary passes it is discarded like any other. Any settlement,
  slash or reward read of a pass record after that is a band-2 read — the SO contact (`PDM-Q-F26`;
  `ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`). SO states per read which it is.
- **Precondition, not a section to fill:** S-PRUNE **cannot discard a
  shard while a live verifier derives `R_k` from its frozen segment.** The
  serve-credit admission verifier signs two verifier-derived leaf terms
  today (`wire.rs:345-360`; `blockchain.cpp:5085-5125`); `PDM-Q6` item 4
  row 1 reopens it as consensus and lands its tx-unit restatement at E4 /
  S-ARCH. Until that lands, the first real discard is refused by §8's last
  falsifier.

## 12. Named inputs

| Input | Value / source | Status |
| --- | --- | --- |
| Body horizon | the epoch boundary after the shard's freeze epoch — `close_epoch(k) + 2 ≤ current_epoch`; the batch's set at `E` is `{k : close_epoch(k) + 2 ≤ E ≤ close_epoch(k) + 3}` (additive on `u64`, never `E − 2`); a rule, **no constant, no frontier** | ruled (`PDM-Q2`, 2026-09-22); `W` retired |
| `SEB` | `settlement_epoch_blocks = 10,000`; `settlement_epoch_at_height(h) = h / SEB` (`consensus_state.rs:27`) | pinned |
| `D_max` | 720, **PROVISIONAL** (`PDM-Q11`). Built 2026-09-25 as `shekyl_chain_rules::D_MAX`, derived from `config/consensus_constants.json`'s `archival_reorg_depth_blocks` (one source; its comment names PDM-Q11's gate as a consumer). `SEB > D_MAX` is const-asserted beside the constant. A session pair with `retention` zero or `≥ SEB` is refused at open (`StoreCannot::RetentionNotInsideEpoch`), on a writer and on `open_read_only` — both take a checked `Horizons`. A shortened epoch names its own retention through `Horizons::new`. `SEB = 2` with retention 720 is not a configuration (rule 71). | PROVISIONAL numeric; constant built (`shekyl_chain_rules::reorg`) |
| Journal-horizon function | `tip − (CRB + n·SEB + D_max)` (F19) — `CRB`, `SEB`, `FAILURE_WINDOW_N` live in `shekyl-archival-retention`; `D_max` does not | **built** 2026-09-25 as `shekyl_chain_rules::journal_horizon(tip) -> Option<BlockHeight>` beside `D_MAX`, consumed by S-ARCH when its journal writers land (`shekyl_archival_failure_window_params` is *not* it — it returns the m-of-n `(m, n, serve_budget)`) |
| `T` | **200 transactions per shard, PROVISIONAL** — the one consensus constant of the partition, one const-asserted home (the discipline `SHARD_BYTES` carried, FOLLOWUPS `:72`); chosen so a typical shard at ~16.7 KB/tx lands near 3.33 MB | ruled (`PDM-Q6` item 5, 2026-09-23); **built** 2026-09-25 as `shekyl_types::SHARD_TX_COUNT`; numeric on the Round-2 gate with `n`, `D_max`, `w_launch` |
| Shard boundaries | `k·T` — no table, no rows, no prefix sum; `close_height(k) = height((k+1)·T − 1)` by binary search over the storage-id total | derived, never received (item 5) |
| `first_tx_id(h)`, `cumulative_tx_count` | `cumulative_tx_count` is the listed-transaction fold. `first_tx_id(0) = 0`; for `h ≥ 1`, `first_tx_id(h) = storage_ids_through(cumulative_tx_count(h−1), h−1)` — listed plus one coinbase per block (`shekyl_types::storage_ids_through`, SPR-1). The primitive under `close_height`, and so under `close_epoch` | landed on #772 as the listed fold — **the coinbase term is SPR-1** |
| `w_launch` | flat in-window commitment weight through epochs 0–1; superseded by the derived scarce-set median at the first `discard(k)` | **reward leg's** (Q6 item 3 amendment) — on the Round-2 gate with `n`, `D_max`; S-PRUNE's `discard(k)` event defines the scarce set |

**No byte length is read anywhere in this surface (`PDM-Q6` item 5, RULED
2026-09-23).** The 2026-09-22 draft of this paragraph put per-tx lengths on
F28's skeleton wire and called them safe under band-1 trust; Bugbot
(#832, high) refuted the safety — nothing the checkpoint reaches binds a
length, and `b_*` was consensus — and item 5 then asked what the count was
*for*: SF's memory ceiling (dissolved by per-tx streaming verification;
the buffer is `MAX_TX_SIZE`) and per-shard pricing (already weight-based,
not byte-based). Neither survives, so the partition is `⌊tx_id / T⌋` with
zero new data: no A4, no `CtSigBase` change, no `SHARD_BYTES`, no wire
growth on F28. If the reward leg ever names a byte-proportional term, the
named alternative is (g) — one `cumulative_prunable_bytes` varint per
block in the coinbase `tx_extra` — not per-tx lengths. **Falsifier for
this surface:** any read of a segment's byte length to place, find or
discard a shard.

## 13. C++ deletions and their timing

`process_archival_segment_freezes_at_height`, `archival_shard_segment`,
`frozen_segment_count`, `get_archival_shard_segment_at_height`,
`SEGMENT_LEAF_COUNT` (`PDM-Q12`) **die at `DRS-E*`** with the C++ store,
under `PDM-Q-S0`. The stripe engine's four methods (`check_pruning`,
`get_blockchain_pruning_seed`, `prune_blockchain`, `update_pruning`;
`PDM-Q7`), `src/common/pruning.{h,cpp}`, `CRYPTONOTE_PRUNING_*` and
`--prune-blockchain` **were deleted 2026-09-21** — gated by
`scripts/ci/check_no_stripe_engine.sh`; `prune_tx_data` and its two tables
followed on 2026-09-22 (`feat/delete-cxx-tx-data-prune`). Nothing is left
for this surface's increments to delete. The `u32` seed
arithmetic (`PDM-Q-F17`) is **not** read from — `PDM-Q7` refuted the triple;
the holdings advertisement is the bond. `--sync-pruned-blocks` **was deleted
with them (2026-09-21), under `PDM-Q5`'s rejection**
(trust-the-txid with no anchor), recorded on its own FOLLOWUPS row so the
reason outlives the engine.

## 14. As built (2026-09-25) — the increment, and what building it found

Four commits on the S-PRUNE increment PR, off `dev` `fc6d87ca5`: (1) the
constants — `D_MAX`, `SEB > D_MAX`, `journal_horizon`, `SHARD_TX_COUNT`;
(2) a dev-red fix carried first — `store::alt_tests` spent to one output
under CEN-I1, which slice 6 landed past it; (3) the mechanism; (4) this
record. The skeleton's sections stand as the specification; where the
build disagreed, the section carries the correction in-line and this table
carries the finding.

| Finding | Statement |
| --- | --- |
| **SPR-1** | **`first_tx_id` was off by the coinbases.** §2 wrote `first_tx_id(h) = block_info[h−1].cumulative_tx_count`; that total counts a block's *listed* transactions (`connect.rs`, "the parent's plus this block's listed transactions") while storage ids are dense over every recorded transaction, the miner transaction first. Built as `cumulative_tx_count(h−1) + h` (one coinbase per block). Found by the first test that closed a shard: `D(3)` came back empty. Read at the code, not the plan — the rule-16 corollary, in the plan's own primitive. |
| **SPR-2** | **The §7 pop belt is unreachable by arithmetic, not by `SEB > D_max`, and was not minted.** `h_scarce` is the `close_height` of a shard with `close_epoch + 2 ≤ E`, so `h_scarce < (E−1)·SEB ≤ tip − SEB < tip` at every tip; `tip ≤ h_scarce` has no instance to build "by hand". A check that cannot fire is not a belt (rule 16); the inequality it was said to depend on is still enforced — at open, as `StoreCannot::RetentionNotInsideEpoch`, and at compile time on the production pair — because it is what keeps the undo floor above the body horizon. `h_scarce` is built for its other consumer, `PDM-Q5`'s band-2 edge. |
| **SPR-3** | **The retention is a session parameter, not a second constant.** The skeleton's rule-71 ask ("one knob that overrides both and preserves the ratio, or a parse that refuses") is met at the store: `Horizons { epoch, undo_retention }`, `0 < retention < SEB` or the open is refused; `create` / `with_apply_policy` run `D_MAX`, `with_horizons` is the regtest knob. `OTHER_EPOCH = 50` in the header tests had to name a retention — the refusal firing where it should. The retention is not pinned in the header (the `undo_log_floor` cell records what it retired); the schedule is. |
| **SPR-4** | **The undo floor is persisted; the body frontier is not.** §5.4 of S-CHAIN-W asked S-PRUNE to persist the floor it establishes so `pop` can tell *pruned below* from *lost*; §4 of this plan forbids a stored discard watermark. Both hold: `undo_log_floor` (layout 14, `EngineLocal`) is the journal's retention mark, monotone, written by the batch; the body discard's set is `D(E)`, computed and stored nowhere. `pop` below the cell is `PopBelowFloor`; above it, a missing row is SI-6. |
| **SPR-5** | **A discarded `pqc_auths` region is a state.** `TxRecord` carried `pqc_auths: Option<SegmentBytes>` with a hash row and no segment classified SI-7 (§7.7 leg ii read pairwise). Under `PDM-Q6` the region is discarded with the shard, so that combination is leg (iii)'s one state: `Option<PqcAuths { Retained, Discarded }>`, `wire_bytes` → `None` for a discarded region, and the pairwise test now asserts *discarded* in one direction and SI-7 (a segment without its permanent hash row) in the other. |
| **SPR-6** | **`D_max` is derived, not re-typed.** `config/consensus_constants.json` already carries `archival_reorg_depth_blocks = 720` and its comment names PDM-Q11's gate as a consumer; `D_MAX = BlockCount::from_raw(ARCHIVAL_REORG_DEPTH_BLOCKS)` — one source in `config/`, no second 720 to drift. The blocker this file carried ("the increment does not cut before the numeric is confirmed") had a falsifier that could only fire after the increment — rule 22's shape — and is dissolved by the build; the numeric stays PROVISIONAL in `PDM-Q11`, now with a mechanism to test it against. |

**What the tests hold** (`store/prune_tests.rs`, 300-block chains under a
100-block epoch and a 50-block retention — `T = 200` closes a shard only
after two hundred transactions, and the shared fixtures pack the height
into a `u8`, so the module carries its own long-chain header and facts):
`D(2)` empty and the floor at 150; `D(3)` = shard 0 with its prunable and
`pqc_auths` regions `Discarded`, hash rows standing, shard 1 held, undo rows
exactly `[250, 300]`; epochs 0–1 run no batch; fifty-one pops land and the
fifty-second is `PopBelowFloor { 249, 250 }` with the writer live; the hook
fires again on a reorg across 300 and the store is the same store;
`h_scarce` at each epoch, on the batch and the snapshot. A planted
decrease in the storage-id total refuses the boundary connect as SI-13
and leaves the writer halted with the block uncommitted. A read-only
open reports the `Horizons` it was given. `Horizons`' refusals; `D_MAX`,
`SEB > D_MAX` and `journal_horizon` in `shekyl-chain-rules`. 355 + 14
chain-store, 32 + 7 `shekyl-types`, 207 chain-rules; every `scripts/ci`
gate green at the mechanism commit, and the review fix re-ran the store
and types libs (355, 32).

**What stays E4's / E5's / S-ARCH's**, unchanged by this build: the
journals' retirement at `journal_horizon` (S-ARCH's writers, when they
land); §11's serve-credit precondition (the E3 cutover ordering; nothing in
production reads this store yet); the reward leg's `w_launch`.

