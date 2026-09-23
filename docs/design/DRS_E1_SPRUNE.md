# DRS-E1 S-PRUNE — the retention prune: plan-doc skeleton (`PDM-Q-F31`)

**Status:** OPEN — **SKELETON, not a plan.** Written 2026-09-18 at
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
Q1's journal-horizon check alongside (§9 below).

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

Shard `k` — a byte-bounded `tx_id` range `[b_k, b_{k+1})` (`PDM-Q-F32`) —
has its prunable regions and `pqc_auths` discarded **atomically, as a
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
`first_tx_id(h)` is `block_info[h−1].cumulative_tx_count` for `h ≥ 1` and
**`first_tx_id(0) = 0`** (FL-R3-STORE, `BlockInfo`, landed on #772);
`close_height(k)` is `height(b_{k+1} − 1)` — the last **included**
transaction's height, since `b_{k+1}` is the first of `k+1` and need not
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
contiguous range of `k` read off `cumulative_tx_count` and the `b_*`
table. **Every epoch comparison in this document is written additively —
`close_epoch(k) + 2 ≤ E`, never `close_epoch(k) ≤ E − 2` — because
`settlement_epoch_at_height` returns a `u64` and `E − 2` wraps in epochs 0
and 1** (Bugbot, 2026-09-23: the first draft's `E−3` wrapped at `E = 2`,
and its `h_scarce` covered every closed shard for the whole free regime).
The same page's branch-not-arithmetic discipline, applied to itself. **One redb transaction per boundary connect**, holding the block's
write set, every `discard(k)` for `k ∈ D(E)` (delete every `txs_prunable`
and `txs_pqc_auths` row in `[b_k, b_{k+1})`; not journaled in `undo_log` —
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
  one store state with one meaning. **Owed with S-CHAIN-W amendment A4 (`PDM-Q-F32`), not yet
  in §7.7:** (iv) the length rows, **pairwise** — prunable-length row
  present ⇔ `txs_prunable_hash` row present; `pqc_auths`-length row
  present ⇔ `txs_pqc_auth_hash` row present. The plan may not present
  (iv) as in force until A4 lands.
- **Hash rows and length rows are outside every prune surface**, permanent.
  `txs_prunable_hash` (exists), `txs_pqc_auth_hash` (A3, #772), the two
  `u32` length rows (A4, owed).
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

**The pop check reads `close_height` only.** The **floor is the lowest
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

**What S-PRUNE does not do.** Never touches `spent_keys`. Never touches a hash row or a length row.
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
hash row, `cumulative_tx_count` — landed); **A4 (the length rows — owed;
the plan's commit 1 or a precursor PR, with `SHARD_BYTES`'s production
home and the `D_max` / journal-horizon function of §12)**; and §11's
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
  (`table_classes_match_the_audit_matrix` reads it).

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
| `D_max` | 720; **`SEB > D_max` const-asserted beside it, on the production constants — the only assertion.** The invariant holds on **every nettype** (rule 71: nettype selects data, the data satisfies the same invariant): the regtest `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` override (`constants.rs:257`, today `2..=SETTLEMENT_EPOCH_BLOCKS` in isolation) must not admit `SEB ≤ D_max` — one knob that overrides both and preserves the ratio, or a parse that refuses. `SEB = 2` with `D_max = 720` is a rejected configuration, not a supported one | PROVISIONAL, Round-2 gate (`PDM-Q11`); **constant unbuilt — owed** at `CEN-E2`; **fakechain conformance owed with it** |
| Journal-horizon function | `tip − (CRB + n·SEB + D_max)` (F19) — `CRB`, `SEB`, `FAILURE_WINDOW_N` live in `shekyl-archival-retention`; `D_max` does not | **owed**, minted by this surface's A4 commit, consumed by S-ARCH (`shekyl_archival_failure_window_params` is *not* it — it returns the m-of-n `(m, n, serve_budget)`) |
| `SHARD_BYTES` | 3.33 MB (`RF-D6`'s, as the boundary metric) | ruled (`PDM-Q-F32`); production home minted with A4 (FOLLOWUPS `:71`) |
| Length rows (A4) | two `u32` per tx, sparse — **original state**, not derived: ingest-time facts of the body; `b_*` derives from them | **owed** to S-CHAIN-W; on a band-1 skeleton they arrive on F28's wire (below) |
| `b_*` | derived from the length rows, binary-searched | derived, never received |
| `first_tx_id(h)`, `cumulative_tx_count` | `BlockInfo.cumulative_tx_count`; `first_tx_id(0) = 0`; the primitive under `close_height`, and so under `close_epoch` | landed on #772 — **kept** (the horizon expression `first_tx_id(tip − W)` is gone; the primitive is not) |
| `w_launch` | flat in-window commitment weight through epochs 0–1; superseded by the derived scarce-set median at the first `discard(k)` | **reward leg's** (Q6 item 3 amendment) — on the Round-2 gate with `n`, `D_max`; S-PRUNE's `discard(k)` event defines the scarce set |

**The length rows on the skeleton wire (F28) are unverifiable without the
body — and that is safe for exactly one reason.** `txs_prunable_hash`
commits to the prunable *bytes*, not separately to their length, so a
band-1 receiver of `TxBlobEntry` cannot check `prunable_len` against
anything it holds. It does not need to: band 1 is **trusted with the
binary** (`Trust::BelowAnchor`, `PDM-Q5` / `CHAIN_RULES_SLICE_3.md`), and
every band above it has the bodies and derives the lengths itself. Do not
"fix" this by verifying lengths in band 1 — there is nothing to verify them
against, by construction. F28's `TxBlobEntry` therefore grows **two
`u32`s** beside `pqc_auth_hash`; that is `LV-`/`PWC-`'s row (FOLLOWUPS
`:1046`, amended 2026-09-22), not this surface's.

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
