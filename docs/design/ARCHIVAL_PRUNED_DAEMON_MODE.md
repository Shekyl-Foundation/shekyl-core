# Pruned-daemon mode — set-B discard (PDM)

**Status: LIVING CONTRACT** — last verified 2026-09-22 at `dev@5b2d4c6d6` (Q2 RE-RULED: the body horizon is the epoch boundary after the freeze epoch, `W` retired; Q4/Q5/Q9 amended; Q5 earlier the same day: `assumevalid = 0` is no anchor)
with PR #774 and PR #775 read at their heads. **Every `PDM-Q*` question is
RULED or CLOSED** (Q1–Q3, Q5–Q12 RULED; Q4 CLOSED; `PDM-Q-S0` RULED). This
file is the contract: the rulings as they bind, the dispositions of the
adversarial items, the findings register, the data-element inventory, and
what carries on past the round by owner. **The argument is not here.** The
round's opening narrative, the pre-ruling analysis under each question, the
§3 walks in full and the findings' full text are the record,
[`ARCHIVAL_PRUNED_DAEMON_MODE_ROUND.md`](../completed/ARCHIVAL_PRUNED_DAEMON_MODE_ROUND.md)
(CLOSED-as-record, 2026-09-18); every `PDM-Q-F*` cited here resolves there
by ID. Contracted 2026-09-18 on steering's read: three things in it are read
live for the next year — the §9 inventory (S-PRUNE's plan reads it), Q2's
predicate and falsifiers (the plan asserts it), and Q6 item 4's re-key table
(four lanes execute it) — so the rulings stay at this path and the reasoning
moves.

**What this document is for.** Nothing here is built while DRS is in
progress — the implementation waits on the C++→Rust daemon cutover
(`DRS-E*`, `PDM-Q-S0`). This is the **reference for the DRS build** (uniform
body horizon — the epoch boundary after a shard's freeze epoch, Q2 — hash and
length rows forever, no archival serving state on any daemon), for the **archiver serving-store round** the wallet lane owes (§8),
and for the lanes executing item 4's re-keys.

**Grounded at** `dev@edb35dbb1` (2026-09-12, the round's opening pin);
rulings grounded `4bc378d68` (2026-09-17) and `20ebdf1e5` (2026-09-18), with
#768 / #770 / #774 / #775 read at their heads as recorded in each block.
Line-number citations carry their sha; re-verify before relying on one.

**Family:** `PDM-Q` — tokens `PDM-Q1`…`PDM-Q12` (questions), `PDM-Q-F1`…`F33`
(findings), `PDM-Q-S0` (sequencing constraint). Registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 (rule 94). Distinct
from `**PD-A…PD-F**`.

**Process:** [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
governed the round; rule 21 shapes every ruling (rejection, reopening
criteria, re-evaluation shape); rule 23 governs what each disposition left
visible.

---

## 0. Sequencing constraint — RULED 2026-09-12 (steering)

### `PDM-Q-S0` — implementation waits on the daemon C++→Rust cutover

**The rejection.** Do not implement set-B discard (or any successor of
`--prune-blockchain`) in the inherited C++ daemon. The landing site is
the Rust daemon after the store/engine swap (`DRS-E*`,
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md); engine-swap **not started**
as of this pin, banner line 11).

**Why, under current substrate.** Steering, 2026-09-12: this design will
not be implemented until after the C++→Rust daemon cutover. Independently,
rule 20 already sends new daemon logic to Rust — a C++ `prune_worker`
extension would be debt the rewrite re-creates. DRS-D5's
decompose-in-C++-first rationale is already retired (2026-09-01
countermand).

**Launch sequencing.** Genesis does not precede this design's
implementation; steering, 2026-09-12. `DRS-E*` is therefore on the
critical path to launch, because the first implementation waits on it.
That may already have been true; it was not written in the documents a
reader walks, and a launch-state fork — genesis shipping while the C++
daemon still retains everything — was inferred from trajectory to fill
the gap. There is no such window to design a policy for.

This is not a claim that the pruning *mode* needs a coordinated
activation. TJ's node-local sentence is about activation not needing a
hard fork; `PDM-Q-F8` has already shown leaf discard is not node-local
*today*. The remaining `PDM-Q3` question is the residual consensus-read
set after TJ-A. It is a claim that V3 does not ship a daemon that still
cannot discard set B.

**Reopening criteria.** Two, independently:

1. Steering names a C++ landing window *before* `DRS-E*`, in writing,
   with a reviewer-map of the C++ surface.
2. Steering names, in writing, a genesis window that precedes this
   design's implementation.

"The rewrite slipped" is not a criterion for either. Trajectory inference
is how the dissolved launch-state fork was minted; it is not a
criterion.

**Re-evaluation shape.** An amendment to this section, in this file, citing
the steering note. Not a silent C++ PR. Not an allow-comment in
`db_lmdb.cpp`. Not a silent genesis that ships the C++ daemon.

This constraint is **not** a ruling on `PDM-Q3`'s residual-set question
and **not** a ruling that retracts TJ's activation sentence. `PDM-Q-S0`
answers *which codebase the first implementation may touch* and *that
genesis does not precede that implementation*. `PDM-Q-F8` has already
answered that the shape is not node-local *today*.

---

---

## 1. Substrate, as verified

Four premises were verified at source when the round opened and stand
(record §1): (1) the market's product was scoped as set-B scarcity; (2) that
product did not exist — every daemon retained every leaf, and that retention
was consensus-required by the serve-credit verify path; (3) Foundation
posture is unpruned as policy, not a flag; (4) three prune mechanisms
existed, none discarding leaves. `PDM-Q-F12`/`F13` then moved the good from
leaves (a cache) to the transaction's prunable region and `pqc_auths`
(original, admission-only, replay-compatible), which is what Q6 ruled.

---

## 2. The rulings

Each block is the ruling as it binds, with its grounding, reversion criteria and falsifiers. The analysis each was taken on is in the record under the same heading.

### `PDM-Q1` RULED 2026-09-18 — The retained set is §9 graded against the byte-bounded `tx_id` unit

**Grounded at** `dev@20ebdf1e5`, on Q6 (items 1–4, F32), Q2, Q11.

**Ruling.** §9 already grades every element that reaches the chain store
(KEEP-C / KEEP-W / KEEP-D / CACHE / GOOD / LOCAL-BOUNDED). Q1 applies the
ruled unit to that table, and nothing in it changes class: **GOOD** is
the prunable region and `pqc_auths` per transaction (Q6 items 1–2),
discarded per shard by Q2's predicate; **KEEP-C** gains the two hash
rows (A3, #772) and the two length rows (A4, F32) — permanent, on every
skeleton; **CACHE** rows (leaves, layers, `output_metadata`,
`output_to_leaf` / `leaf_to_output`) are rebuilt by replay from the base
(F12, F13 — load-bearing, `DRS-D10`); **LOCAL-BOUNDED** — the seven
window-retired journals (F16) — retire at the journal horizon
`tip − (CRB + n·SEB + D_max)` (F19) — **a second horizon beside the body
horizon, by design** (Q2 RE-RULED 2026-09-22; the 2026-09-18 text had made
it equal to `W`, and `W` is retired). *Corrected 2026-09-22:* the expression
has **no computing function yet** — `shekyl_archival_failure_window_params`
returns the m-of-n slash window's `(m, n, serve_budget)`, i.e. one operand,
not the horizon; the function is owed with `D_max`'s constant (FOLLOWUPS). The two readers left undetermined at the opening are both
resolved (`scan_outputkeys_for_indexes` — residue, F18;
`archival_slash_removed_holding_after` — bounded on both paths, F19);
no new ones were found at this sha. **Owed as implementation, not
ruling (F19: "what remains owed is the check"):** the journal horizon
asserted at the journals' own retirement site, the same discipline as
Q2's predicate — FOLLOWUPS row.

**Reversion.** Reopens if a §9 row is shown mis-graded against the tx
unit — falsifier: a replay from the skeleton that cannot rebuild a
row graded CACHE (this is also Q6's reversion (b)).

### `PDM-Q2` RE-RULED 2026-09-22 (rule-21 reopen, **shape**; first RULED 2026-09-18) — The discard predicate is the epoch boundary after the freeze epoch; `W` is retired as a bodies constant

**Grounded at** `dev@5b2d4c6d6`; read at source:
`rust/shekyl-archival-retention/src/consensus_state.rs:27`
(`settlement_epoch_at_height(h) = floor(h / SEB)`; epoch `E` covers
`[E·SEB, (E+1)·SEB)`), `rust/shekyl-chain-store/src/store/pop.rs:17-27`
(the undo floor is `1` until a prune deletes undo rows),
`rust/shekyl-archival-retention/src/bond_wire.rs:47-51` (`BondPostKind` is
`JoinMarket | Reinstate | Release`). Q6 items 1–4 and item 5 (shards
`[k·T, (k+1)·T)` — fixed cardinality since 2026-09-23, F32's byte bound
superseded — discarded whole) and Q11 (`D_max`) stand beneath this ruling.

**Why a re-ruling and not an amendment.** The 2026-09-18 ruling fixed the
shape as `b_{k+1} ≤ first_tx_id(tip − W) ∧ close_height(k) + SEB < tip` — a
block-count horizon `W` on the shard's last transaction, with an epoch
floor as a guard — and its reopen clause let `W` *fall* and the horizons
*separate* as the numeric's gate. What happens here is that the first
conjunct is **deleted** and the predicate's domain moves from block-count
to epoch-count. That is the shape (rule 21), so this is a reopen, not a
horizon move; and three of that ruling's premises are **refuted**, not
narrowed — named here so the next reader does not re-litigate them from
surviving text (rule 16):

1. *"`W` is set by coincidence with the slash-log retirement floor."*
   **Refuted.** Bodies and journals are **two horizons by design**
   (table below). Nothing about bodies is set by the journals.
2. *"One horizon removes a drift pair."* **Refuted.** There are two,
   deliberately, and they are not a drift pair: neither is a tunable of
   the other. The body horizon is a rule of the epoch calendar; the
   journal horizon is F19's expression; the store asserts each at its
   own site.
3. *"A shorter `W` puts running nodes into band 2 on ordinary outages."*
   **No longer a cost — accepted as the casual posture** (Q4 and Q5
   amended the same day). A node down for more than one epoch rebuilds
   the bodies of shards whose boundary passed through band 2 like any
   other returning node; band-2 egress includes every casual return and
   is the reward leg's to price, not this ruling's to prevent.

**The predicate.** `close_height(k) = height((k+1)·T − 1)` (Q6 item 5;
written `height(b_{k+1} − 1)` under F32) — the shard's last **included**
transaction, found by binary search over
`BlockInfo.cumulative_tx_count` (`first_tx_id(h) = block_info[h−1].cumulative_tx_count`
for `h ≥ 1`, `first_tx_id(0) = 0`; landed on #772; no new state). Let
`close_epoch(k) = settlement_epoch_at_height(close_height(k))`. The
**freeze epoch** of shard `k` is `close_epoch(k) + 1` — the whole epoch
after the one it closed in. Shard `k` has its prunable regions and
`pqc_auths` discarded **atomically, as a whole**, iff

> `discard(k) ⇔ current_epoch ≥ close_epoch(k) + 2`, with
> `current_epoch = settlement_epoch_at_height(tip)`

— the same statement as `close_epoch(k) ≤ current_epoch − 2`, **which is
never written that way**: `settlement_epoch_at_height` returns a `u64` and
the subtraction wraps in epochs 0 and 1, so every epoch comparison in this
contract and the skeleton is additive (`+ 2 ≤`), and the batch's set is
`{k : close_epoch(k) + 2 ≤ E ≤ close_epoch(k) + 3}`.
**The genesis guard is `current_epoch ≥ 2`**, a branch, never
arithmetic — the discipline the 2026-09-18 text had for `tip − W`, kept
(the store's `BlockHeight − BlockCount` panics on this boundary, and that
stays correct: a launch-window discard is a bug, not a zero). Bodies
retire **at the epoch boundary after the freeze epoch**: at the first
block of `close_epoch(k) + 2`, every daemon discards `k`. There is no
per-daemon input (Q9: no exceptions). The frontier shard — tx `(k+1)·T`
not yet recorded — has no `close_epoch` and is never a candidate.

**Enforcement point** unchanged: asserted where the discard is decided —
S-PRUNE's per-epoch batch, whose set at boundary `E` is **named by `E`** —
`{k : close_epoch(k) + 2 ≤ E ≤ close_epoch(k) + 3}`, read off
`cumulative_tx_count`;
no frontier, no search over disk — and which runs **inside the boundary
block's connect transaction**, so "connected past `E·SEB` with the batch
un-run" is unrepresentable (skeleton §4) — never discovered downstream; a violated predicate is a
refused discard, not a corrupted write. **The predicate is evaluated at
discard time and the discard is irreversible.** A reorg across an epoch
boundary (`≤ D_max` blocks) can move `current_epoch` back by one after a
shard has discarded; that shard is not "wrongly discarded" — the
falsifier below is stated at the moment of discard, and pops are protected
by their own check, next.

**Pops — checked, not argued.** The youngest body a discard removes is at
`close_height(k) ≤ (close_epoch(k) + 1)·SEB − 1` and the discard runs at
`tip ≥ (close_epoch(k) + 2)·SEB`, so every discarded body is **at least
`SEB + 1` blocks old**, and `SEB = 10,000 > D_max = 720`. The 2026-09-18
text argued the corresponding `W ≥ D_max` and asserted nothing (rule 16's
corollary: a guarantee with no gate that can fail). This ruling asserts
it, and names the belt: (a) **`SEB > D_max` is const-asserted at `D_max`'s
home, on the production constants** (`CEN-E2`, Q11 — the constant is
unbuilt, so the assertion is owed with it; FOLLOWUPS) **and is an invariant
of every valid configuration on every nettype** (rule 71: nettype selects
data; the data satisfies the same invariant). The regtest
`SHEKYL_SETTLEMENT_EPOCH_BLOCKS` override admits `2..=SEB` in isolation
today (`constants.rs:257`) — that is a **rejected configuration** when it
puts `SEB ≤ D_max`, not a supported one; the fakechain conforms, through
one knob that moves both and preserves the ratio or a parse that refuses.
There is no arm-time assertion and no nettype-specific story. (b) **Belt:**
`pop` refuses the block at any height `≤ h_scarce` — `h_scarce` the
`close_height` of the last shard with `close_epoch(k) + 2 ≤ current_epoch`,
defined only for `current_epoch ≥ 2` and none before any shard closes (then
the floor is `1`) — as `StoreCannot::PopBelowFloor { floor: h_scarce + 1 }`, the floor being
the lowest height whose block may be popped, chain-named from
`close_height` only (skeleton §7). It is **unreachable by construction on
every conformant nettype** — the `SCW-7` undo floor at `tip − D_max` sits
strictly above it — and is kept because a check that can fail is worth one
that cannot; its test constructs the case artificially.

**Two horizons and a floor, by design.** Bodies and journals are the two
horizons; the undo journal's `D_max` is a floor both clear, not a third
horizon.

| Horizon | Retires | When | By |
| --- | --- | --- | --- |
| Bodies (prunable + `pqc_auths`) | shard `k`, whole | the epoch boundary after `k`'s freeze epoch: `tip = (close_epoch(k) + 2)·SEB` | this ruling |
| Pop-undo journal | rows below `tip − D_max` | retention `≥ D_max` | `SCW-7` / Q11 |
| Slash log and the six other window-retired journals (F16) | rows below `tip − (CRB + n·SEB + D_max)` | F19's expression, unchanged | Q1 / F19 |

**`W` is retired as a name.** Nothing is "the universal bytes window" any
more; F19's journal horizon keeps its own expression and is **not** called
`W`; the undo floor is a lower bound the body horizon clears by
construction (`SEB > D_max`) and is not the same number as either. A
body-horizon *constant* appearing in any crate is a falsifier — the
horizon is the epoch calendar and there is nothing to name.

**The freeze epoch is the pull window** (Q9, amended today). Shard `k`
closes at tx `(k+1)·T` during `close_epoch(k)`; for the whole of
`close_epoch(k) + 1` every daemon still holds its bodies, and the
archiver's wallet pulls them over the operator leg through the ordinary
split read (Q10) — **pull before bond**. At the boundary into
`close_epoch(k) + 2` the bodies are gone from every daemon and `k` is
**scarce**; from then on acquisition is a fetch from another archiver or
from the Foundation `CompleteTree` (Q9). The specified-to-scarce window is
therefore between one and two epochs long depending on where in its epoch
`k` closed, and **never less than one full epoch**.

**The free regime.** In epochs 0 and 1 nothing is scarce; the first
discard is at the boundary into epoch 2 **at the earliest** — about four
weeks at genesis parameters, not ~195 days — and later on a chain too quiet
to close a shard (~200 transactions at 3.33 MB) in epoch 0. Bonds, challenges and the possession test are
live from block 1 and answerable by any synced node — the ruled bootstrap
subsidy (§3), not a defect. `w_launch` (Q6 item 3's routing note) governs
until the first `discard(k)` — at least those two epochs — and is
superseded by the derived scarce-set median then. Beyond launch this is every shard's
own: bondable from `close_height(k)`, universally held through its freeze
epoch, scarce from the boundary after — the window in which the
archiver's wallet pulls it.

**Uniformity.** The body horizon is a rule of the epoch calendar, not a
constant, so there is nothing to ship as a coordinated release, and the
2026-09-18 "bounded Q8 uniformity exception" for a `W` rollout is **void**
— there is no `W` to roll. The horizon decides no verdict and is not
consensus; every daemon evaluates it identically (Q8).

**Round-2 gate.** `n`, `D_max`, `w_launch` — and, from Q6 item 5
(2026-09-23), `T`. `W` leaves the gate with the constant; `T` takes its
seat, so the gate is four numerics.

**Closed rulings touched.** `RF-D6` (reopened per Q6 item 4, unchanged);
the seven window-retired journals keep F19 — now explicitly a second
horizon; `SF-D10`'s organic-need lifetime inherits the body horizon (a
need becomes band 2 at the boundary after its shard's freeze epoch); the
serve-credit transaction's *own* prunable region — the pass records —
discards under this predicate like any other, so a settlement read of a
pass record after its shard's boundary is band 2 (the SO contact, F26);
and S-PRUNE **cannot** discard a shard while a live verifier still
derives `R_k` from its frozen segment (Q6 item 4 row 1) — moot before the
cutover, since the redb store is not the production daemon until E3, and
stated so the sequencing is the mechanism rather than a guard.

**Reversion (rule 21).** Shape reverts to OPEN — a block-count horizon on
bodies comes back — if band-2 egress from casual returns is shown to
exceed what the reward leg prices archivers to serve. Falsifier: the
reward leg's Round-2 egress model (its number, not this ruling's) with
the casual-return term dominating paid serving. Numeric: nothing is
left here to re-pin; `n`, `D_max`, `w_launch` revert at their own gate.

**Falsifiers.** A shard discarded at a `tip` with
`current_epoch < close_epoch(k) + 2` is red (evaluated at discard time).
A shard *retained* on any daemon past the boundary into
`close_epoch(k) + 2` is red (#775's corollary — there are no exceptions).
A partially discarded shard on an ordinary node is red. `SEB ≤ D_max` is
red. A `pop` succeeding on a target `≤ close_height` of a discarded shard
is red. A body-horizon constant in any crate is red.

**Superseded (RE-RULED 2026-09-22) — what the 2026-09-18 text ruled, for
the record.** Predicate `b_{k+1} ≤ first_tx_id(tip − W) ∧ close_height(k)
+ SEB < tip`; `W = CRB + n·SEB + D_max ≈ 140,720` blocks ≈ 195 days,
PROVISIONAL, "set by coincidence with the slash-log retirement floor" so
bodies and journals were one horizon; honest downtime satisfied "with a
wide margin as a consequence"; the genesis guard `tip ≥ W`; a bounded Q8
uniformity exception for a `W` rollout; reversion on the Round-2 outage
CDF's tail exceeding the candidate. The exceptions conjunct had already
been struck on #775 (Q9). Premises 1–3 above are the ones refuted; the
rest re-keys line-locally in this document and the skeleton.

### `PDM-Q3` RULED 2026-09-18 — The residual set is empty in the Rust validator by construction; the C++ residual is the serve-credit verifier and dies at E4

**Grounded at** `dev@20ebdf1e5`.

**Ruling, two sentences.** *Rust:* the instrument is `PDM-Q-F29` — `ChainView`
has no recorded-body accessor (`rust/shekyl-chain-rules/src/view.rs`, the
trait surface), so every rule is one a body-less node can run; it is a
property of a type that exists in code, held as a standing property in
`CHAIN_RULES_CRATE.md` §13 with a compile-shaped falsifier. *C++:* the one
residual consensus reader is `PDM-Q-F8`'s site — the **serve-credit
admission verifier** reading the leaf chunk (`get_curve_tree_leaf_chunk` in
`blockchain.cpp`, `:5327` at the pin, `:5099` today — cite the function,
the line has moved once). That is Q6 item 4 **row 1**, reopened as
consensus and deleted at **E4 / S-ARCH** when the preimage is re-keyed —
*not* the stripe engine's deletion under Q7 (done 2026-09-21): different site,
different lane, different reason. TJ's "node-local" sentence is true once
that verifier is the Rust one, and false before it (F8), as this charter
has said since the opening.

**Falsifier.** A `ChainView` method returning recorded tx bytes without a
`CenRow` and an above-horizon mark (the mark F29 names "above-`W`" at its
pin; the horizon is now the body horizon, Q2 re-ruled 2026-09-22); or the
C++ leaf read still live after E4's
verifier lands.

### `PDM-Q4` CLOSED 2026-09-18, AMENDED 2026-09-22 (downtime tolerance is one epoch) — Collapsed by F20 / F23 / F24; the TJ-F re-bind is stated

Nothing left to decide. No chain-following read reaches an archiver for a
node with downtime under **one epoch** (F24, re-keyed 2026-09-22 from
"under `W`" — Q2's body horizon is the epoch boundary after a shard's
freeze epoch, so a node that misses at most one full epoch returns to
peers that still hold every body it lacks); the daemon's fetches — band-2
fill, recovery, history read-back — are episodic and optional (#775 admits
exactly these); and TJ-F is re-bound to the per-tx verify: a body-fill
read that does not hash to the retained rows fails loudly, never skipped.
Closed as a record.

**AMENDMENT 2026-09-22 — beyond one epoch, band 2 by accepted posture.** A
node down for longer than one epoch returns to find the bodies of every
shard whose boundary passed gone from every peer; it rebuilds them through
band 2 (archiver fill, verified per tx against the retained hash rows)
exactly as a cold syncer does above `C`. This is **the casual posture**,
not a failure mode: Q2's 2026-09-18 premise that ordinary outages must be
kept out of band 2 is refuted there (premise 3), and band-2 egress
includes every casual return (Q5, same amendment). The node's *consensus*
state needs nothing from anyone — the skeleton, hash rows and length rows
were never discarded; only bodies are refetched.

### `PDM-Q5` RULED 2026-09-18, AMENDED 2026-09-22 twice (`assumevalid = 0` is no anchor; genesis is in no band — and band 2 under the epoch horizon) — The anchor, the bands, the launch window; `Trust::BelowAnchor` confirmed

**Grounded at** `dev@20ebdf1e5`; `connect.rs:281-329` and `error.rs:273` read
at source.

**Ruling.** The anchor model as restated 2026-09-13 stands: a release-carried
checkpoint `C` on the `assumevalid` argument; three bands (`≤ C` skeleton,
trusted with the binary; `(C, h_scarce]` filled from archivers, where
`h_scarce` is the `close_height` of the last shard with
`close_epoch(k) + 2 ≤ current_epoch`, none in epochs 0–1 (*re-keyed
2026-09-22 from `(C, tip − W]`*, second amendment below); above from
peers); the tip-relative trust horizon and the operator trust-below
fallback **REJECTED**. The items it owed:

- **Launch window** — ~~narrowed by Q2: band 2 is empty until the chain is
  `W` old, so the item is *first checkpoint release before day ~195, then
  release cadence `≤ W`*~~ **SUPERSEDED 2026-09-22 (second amendment):**
  band 2 is empty only through epoch 1 and non-empty from the boundary
  into epoch 2; the checkpoint cadence is a **cost** knob (cold-sync
  egress `(h_scarce − C)` × rate × 16.7 KB), not a correctness one, and
  is the release flow's to choose against the reward leg's egress price.
- **Release-gate full-verify step** — a process sentence: the release that
  carries `C` is built from a node that verified every proof to `C` with
  `assumevalid = 0` — **no anchor, `Trust::Full` from height 0, band 1
  empty** (amendment below); recorded in `SIGNING.md`'s release flow when
  the first checkpoint ships.
- **Band-2 egress** — a formula, not a decision: cold sync `(h_scarce − C)`
  × tx rate × ~16.7 KB/tx (F24) **plus every casual return**
  `(h_scarce − h_offline)` × rate × 16.7 KB for each node down longer than
  one epoch (Q4). *Re-keyed 2026-09-22:* the `W` × rate upper bound is gone
  with `W`; the total is the reward leg's number (Q2 re-ruling's reversion
  clause reads it).
- **The anchor check's home** — `CEN-E1` (Q11: the equality rule is the
  anchor's own; `CEN-E2` is `D_max`'s), re-keyed in F27's PR (F30).
- **The Q11 ordering** — discharged by Q11 (the anchor is `D_max`'s
  precondition).
- **F27's mode — CONFIRMED: `Trust::Full | BelowAnchor(anchor)`, an input
  to `validate` orthogonal to `RuleSet`.** Nearly forced: `connect` refuses
  any verdict judged under a set that is not `rules_at(height)` —
  `StoreCannot::RuleSetNotInForce`, `rust/shekyl-chain-store/src/store/connect.rs:281-329`,
  `error.rs:273` — so a *below-anchor `RuleSet`* would be refused by the
  store's own check; the orthogonal input is the only shape that does not
  touch it. Under `BelowAnchor` the proof rows are not run, their absence is
  recorded in `RuleCoverage` and `connect`'s provenance (so a band-1 file is
  never parity evidence), and the `in_force` check is untouched. E6's, to
  land in slice 3 or 6 with the `CEN-E1`/`E2` re-key.

**AMENDMENT 2026-09-22 — `assumevalid = 0` is "no anchor", not "genesis is
the anchor"; genesis belongs to no trust band.** Asked by the E6 lane
(`CHAIN_RULES_SLICE_3.md`, the `Trust` input): the two readings coincide in
*verification work* — genesis is coinbase-only, `CTTypeNull`, so there are no
proof rows for `BelowAnchor(0)` to skip — and diverge the moment anyone asks
whether band 1 is empty at first release, or reads the store: under
`BelowAnchor(0)` height 0 would be connected with its proof rows *not run*,
their absence recorded in `RuleCoverage` and `connect`'s provenance, and the
genesis file marked "never parity evidence". Ruled:

1. **`assumevalid = 0` ≡ no anchor ≡ `Trust::Full` from height 0; band 1 is
   `∅`.** This is the only reading under which the release-gate sentence
   above is not circular: a node that "verified every proof to `C`" ran
   `Full` at every height, including 0. First release ships in this state.
2. **Genesis is in no band.** It is not *trusted with the binary* (band 1's
   defining property); it is *defined by* the binary — a hash-pinned
   constant checked by equality, never by assumption. The launch-window
   bullet's `(0, h_scarce]` (was `(0, tip − W]` before the same day's second
   amendment) reads accordingly: the excluded `0` is "height 0 is not in
   band 2", not "`C = 0`".
3. **"Genesis is the anchor" is made unrepresentable, not merely
   unintended:** `Trust::BelowAnchor(anchor)` carries `anchor ≥ 1` (a
   non-zero height; the constructor refuses 0). `assumevalid = 0` can then
   only map to `Full`, and the `Trust` input has exactly two constructible
   states — E6 lands the refusal with `Trust` (slice 3 / slice 6, its
   choice), and the first-release node is the one where `BelowAnchor` cannot
   be built at all.

Falsifier for item 3: a `BelowAnchor(0)` constructed anywhere in the tree —
`rg 'BelowAnchor\(0\)' rust/` — is a regression of this ruling, not a
configuration.

**AMENDMENT 2026-09-22 (second) — band 2 under the epoch horizon.** With
Q2 re-ruled the same day, band 2's upper bound is no longer `tip − W` but
**`h_scarce`, the `close_height` of the last shard with
`close_epoch(k) + 2 ≤ current_epoch`** (additive, never `− 2` on a `u64`;
none in epochs 0–1) — named by the epoch, not read off any disk (a band-1 node has never held a body and must get the same number);
exact, identical on every node, and blurred only by shard granularity (a
shard that closed in epoch `E−1` may hold transactions from `E−2`; those
are held too, so `h_scarce` is the honest edge, not `(current_epoch − 1)·SEB`).
Consequences, each already re-keyed in the bullets above: (i) band 2 is
non-empty from the boundary into epoch 2, so the launch-window item is
superseded and the checkpoint cadence becomes a **posture** knob (below);
(ii) the egress formula loses its `W` bound and gains a term for every
casual return — **downtime tolerance is one epoch** (Q4), beyond which a
node fills through band 2 by accepted posture; (iii) nothing about the
anchor, the `Trust` input or the first amendment moves — band 1 was never
about bodies. `h_scarce` has an empty case (no shard closed yet: band 2
empty) and block `h_scarce` is mixed (the shard boundary falls mid-block),
which is why the interval is inclusive. The two-horizon table in Q2 is the
reference; this ruling names no horizon of its own.

**Follow, then verify backward, report synced at `C`.** The chain
**validates as a skeleton** (F20(c), this ruling's decomposition): every
node holds the headers, every tx prefix (`vin` key images, `vout` keys),
`CtSigBase` (`outPk`, `enc_amounts`, `txnFee`, `referenceBlock`;
`ct_types.h:172-179`) and both hash rows, so a fresh node validates PoW and
difficulty, the txid chain, no-double-spend, fee and emission accounting,
and every state transition — and rebuilds every derived table — to tip
with **zero** archiver contact. What it cannot do without bodies is
**re-run the proof rows** (4.I: FCMP++ membership, BP+ range, `pseudoOuts`
balance, PQC authorisation, serve-credit pass verification —
`CtSigPrunable`, `ct_types.h:298-309`, plus `pqc_auths`), which is
precisely what `Trust::BelowAnchor` already names as not run. So: **full
verification of `(C, h_scarce]` depends on archivers; chain-following does
not.** Fill runs **backward from `h_scarce` toward `C`** — the newest
proofs first, the region nearest `D_max` and the only one a running node
could be asked to revert into; each block's proofs verify against
skeleton-derived state at its `referenceBlock`, so blocks are independent
and the fill parallelises across shards. At every moment the node can
state "everything above `X` is fully verified" for a descending `X`.
**Two states, not one:** the node **follows** from the moment its skeleton
validates, but it does not **report synced** — and does not act as a
validator for anyone else — until fill reaches `C`. Until then it is on
PoW alone for `(C, X]`, the trust-below posture this ruling rejected as a
*permanent* state; the heavier-invalid-chain attack lives exactly in that
gap, and only backward fill finds the invalid proof. Under
`assumevalid = 0` (first amendment) the same mechanism runs with `C = 0`:
fill to genesis before reporting synced. The **checkpoint cadence** is
therefore a posture knob with its consequence named — a longer gap is a
longer following-but-not-synced window for a fresh node and a larger
region it verifies on trust until fill closes it — not a security floor,
because the node claims nothing it has not earned.

**Reversion.** As restated 2026-09-13, plus: the `Trust` shape reverts if
`connect`'s `in_force` check is shown to admit a second set per height —
falsifier: `RuleSetNotInForce` removed or widened. The second amendment
reverts with Q2's shape.

### `PDM-Q6` RULED 2026-09-17 (items 1–3), item 3 AMENDED and item 4 RULED 2026-09-18, **item 5 RULED 2026-09-23 — shards are fixed-cardinality `T`; no byte accounting anywhere; F32's byte bound is superseded** — The prunable region and `pqc_auths` are the archival good; a shard is a byte-bounded `tx_id` range, discarded whole

**Grounded at** `dev@4bc378d68` (2026-09-17); `#768` (E6 slice 1 —
`TxIdentity.pqc_auth_hash` and the wire's txid module; read at head
`245a60761` when ruled, **merged the same evening as `398d85e7b`**)
and `#770` (§3 walk; merged `071dfd2f5`) read at their heads and
treated as authoritative per steering. Cites below were re-verified on
`dev@eac99894a` after #768 and #771 merged. Items 1–3 ruled 2026-09-17;
**item 3 amended (`PDM-Q-F32`) and item 4 ruled 2026-09-18** at
`dev@20ebdf1e5`, after a source read of `wire.rs`, `codec/chain.rs` and
the serve-credit call site that the first item-4 draft had skipped.

**Item 1 — the good.** The archival subject is the transaction's
prunable region (`CtSigPrunable`, `src/fcmp/ct_types.h:333`) for every
transaction below Q2's body horizon (*re-keyed 2026-09-22 from "`W`"*). The unit of possession is one transaction's
`CtSigPrunable` bytes; the unit of verification is its
`txs_prunable_hash`, a txid component every node retains forever.
Grounds: `PDM-Q-F12` (leaves are a cache of the base) and `PDM-Q-F13`
(the prunable region is original, admission-only, and every byte replay
needs lives in the other half). Nothing else in §9 is scarce.

**Item 2 — the second occupant.** `pqc_auths` enter the good on
identical terms, verified by `txs_pqc_auth_hash` — the txid's third
component, count-prefixed (`rust/shekyl-wire/src/transaction/txid.rs`,
`Transaction::txid_parts()` / `pqc_auth_hash()`), `Option`-shaped (`None` ⇔ 3-part txid), never a
sentinel. This **ratifies a landed default**: `TxIdentity { hash,
pqc_auth_hash: Option<PqcAuthHash>, prunable_hash }`
(`rust/shekyl-chain-rules/src/block.rs:52-59`), and the
store row `txs_pqc_auth_hash` landed by `DAEMON_REDB_STORE.md` §7.7
item 3 on S-CHAIN-R's layout commit (PR #772). Items 1 and 2 are one ruling: ~95 % of transaction
bytes jointly, neither defensible alone (`PDM-Q-F14`). No tx blob byte
and no txid changes.

**Item 3 — shard membership.** A shard is a **`tx_id` range**
`[k·T, (k+1)·T)` over the store's monotone transaction index
(`tx_id = get_tx_count()` at insert, KEEP-C). Membership is derived —
`tx ∈ s ⇔ ⌊tx_id / T⌋ = k` — and nothing joins the retained set for
it. `height(tx)` for the F10 discard predicate is one `tx_indices`
lookup. Chosen over the height range (byte size floats with
throughput, breaks per-shard pricing) and the leaf segment (needs
`output_to_leaf`, graded CACHE, to become load-bearing). Keeps
`RF-D6`'s fixed cardinality without keeping a mapping. **One unit,
three surfaces:** the bond's `holdings`, `PDM-Q-F17`'s wire echo, and
the challenge draw all name the same `tx_id` range; §3's stripe/shard
item discharges on that identity and reopens if any of the three names
a different unit.

**Item 3 AMENDED 2026-09-18 (`PDM-Q-F32`) — boundaries by bytes, from
a retained length row; discard is shard-granular. THE BYTE BOUND IS
SUPERSEDED IN TURN by item 5 (RULED 2026-09-23): shards return to fixed
cardinality `T`, and each of the four reasons below is dispositioned
there. Shard-granular discard stands.** The fixed
cardinality `T` above was **superseded** here on 2026-09-18 (kept for the
record; item 5 restores it). It was
chosen because it was derivable for free, and that was the wrong
property to fix: `T` was never given a value, `T × MAX_TX_SIZE`
(`MAX_TX_SIZE = 1_000_000`, `rust/shekyl-wire/src/transaction.rs:135`)
makes the worst-case shard `T` megabytes and `max_body_bytes()` a
multi-gigabyte in-flight ceiling at `SF-D7`'s `N = 8`, `SF`'s `N` and
`L` were measured against a fixed 3.33 MB (§9.1 (c), PR #746), and
cardinality pricing mis-prices shard compositions by up to ~60× while
a discarded shard's true size is unrecoverable. So:

- **Length rows.** At connect the store writes, beside the hash rows
  and sparse on the same predicates, the byte length of each
  transaction's prunable region (`u32`, present ⇔ **the transaction
  carried a prunable region at ingest** — i.e. ⇔ its `txs_prunable_hash`
  row) and of its `pqc_auths` segment (`u32`, present ⇔ **its txid is
  4-part** — i.e. ⇔ its `txs_pqc_auth_hash` row). Both predicates are
  ingest-time facts, not current segment presence: after `discard(k)`
  the segments are gone and the length rows **remain** — they are what
  the boundary is derived from. Permanent, never discarded, journaled,
  SI-9-fresh. ~8 B per
  transaction against the ~16.7 KB they let a node discard. **S-CHAIN-W
  amendment A4**, same rung as A3 (the hash row); the §7.7 invariant
  gains a **fourth leg, stated pairwise**: prunable-length row present ⇔
  `txs_prunable_hash` row present; `pqc_auths`-length row present ⇔
  `txs_pqc_auth_hash` row present.
- **Boundaries.** Shard `k` is `[b_k, b_{k+1})` where `b_0 = 0` and
  **`b_{k+1} = min { t > b_k : Σ_{b_k ≤ i < t} (prunable_len(i) +
  pqc_auths_len(i)) ≥ SHARD_BYTES }`** — each boundary is measured **from
  the previous boundary**, not from a global multiple (corrected
  2026-09-18 on review: a global-prefix target `(k+1)·SHARD_BYTES` lets
  overshoot at `b_k` carry forward — with 1 MB transactions the first
  boundary lands at 4 MB and the second at 7 MB, so shard 1 is 3 MB —
  and the floor below would not hold). The transaction that crosses the
  threshold is the **last member of shard `k`** (it is `t − 1`), not the
  first of `k+1`; membership is unambiguous for every `tx_id`; and every
  closed shard's size lies in **`[SHARD_BYTES, SHARD_BYTES + MAX_TX_SIZE)`**
  — the floor is what makes a whole-shard read mean at least
  `SHARD_BYTES` of the good, and the ceiling is `max_body_bytes()` (no
  single transaction reaches `SHARD_BYTES`: `MAX_TX_SIZE` = 1 MB <
  3.33 MB). `b_*` is derived in one forward pass at ingest and cached;
  it is not a closed-form function of the cumulative sum, and does not
  need to be — the table is one `u64` per ~3.33 MB of history. `SHARD_BYTES` keeps `RF-D6`'s 3.33 MB; a shard's *actual*
  size is known from the rows. Cardinality floats. `max_body_bytes()` is
  `SHARD_BYTES + MAX_TX_SIZE`; `SF`'s `N` and `L` stand as measured.
- **Derivability — the reason for the rows.** A first draft defined
  `b_*` over cumulative *prunable bytes* and called the table KEEP-C.
  A band-1 node never had those bytes, and replay-that-validates from
  the skeleton (DRS-D10, `S0`'s only writer) could not recompute them
  — derived consensus state the skeleton cannot rebuild, which is
  this ruling's own reversion criterion (b), written a day earlier.
  With the length rows retained, `b_*` is derivable from retained
  state on every node including skeleton-only, and (b) holds by
  construction. Membership is a binary search over `b_*`
  (recomputed or cached; either way derived, never received).
- **`height(tx)` is not a `tx_indices` lookup** — `tx_indices` is
  keyed by tx *hash* (`codec/chain.rs:126-135`), so from a `tx_id` the
  lookup needs the body it is deciding whether to delete. The
  primitive is `first_tx_id(h) = block_info[h−1].cumulative_tx_count`
  for `h ≥ 1`, `first_tx_id(0) = 0` (the FL-R3-STORE running total,
  `BlockInfo.cumulative_tx_count`, landed on #772), and `tx_id` is
  monotone in height. *Re-keyed 2026-09-22 (Q2 re-ruled):* the horizon is
  the epoch boundary after the shard's freeze epoch, evaluated only when
  `current_epoch ≥ 2`; in epochs 0 and 1 nothing discards (Q2's genesis
  guard).
- **Shard-granular discard** (Q2 restates the predicate): shard `k` is
  discarded **atomically** at the epoch boundary after its freeze epoch —
  `current_epoch ≥ close_epoch(k) + 2` (*re-keyed 2026-09-22 from
  `b_{k+1} ≤ first_tx_id(tip − W)`*) — never a transaction at a
  time. On an ordinary node a shard is entirely present or entirely
  absent, which is what `get_prunable_range`, Q10's "not retained"
  answer, the whole-shard read and the three-leg invariant all
  assume. Pops are unaffected: a discarded shard's youngest body is
  `≥ SEB + 1` blocks old and `SEB > D_max` (*re-keyed 2026-09-22; Q2 now
  asserts this at `pop` and at `D_max`'s home rather than arguing it*).
  **Consequence for the market:** a shard is
  **specified** when `b_{k+1}` closes (membership final, bondable from
  `close_height(k) = height(b_{k+1} − 1)`, the last included
  transaction's height — `b_{k+1}` itself is the first of `k+1` and may
  not exist yet — a binary search over `cumulative_tx_count`, no new
  state) and becomes **scarce** only at
  `discard(k)`, at the boundary after its freeze epoch — `≥ SEB + 1`
  blocks later (*re-keyed 2026-09-22 from "`≥ W` blocks later"*). Between the two every ordinary daemon still holds it, so
  the archiver's **wallet pulls `k`'s bodies from its local daemon** over
  the operator leg into the wallet-side store, with nothing to fetch
  from the network (amended 2026-09-18 on #775 / Q9 — the daemon itself
  retains nothing); "shard `k` is now scarce" is one chain-derivable
  event every node agrees on; and the **open frontier shard** (no
  `b_{k+1}` yet) is **not bondable** — a clean admission rule the per-tx
  model did not give (*`HoldingsUpdate` struck 2026-09-22: that post kind
  was REJECTED 2026-09-20 under the immutable bond; the mechanism that
  names holdings is `JoinMarket`, Q9*). Every shard therefore has its own
  window — at least one full epoch — of being bondable while universally
  held (*re-keyed 2026-09-22 from "`≥ W`"*);
  the launch free regime (§3) is the first instance.

  **Routed to the reward leg (`REWARD_EMISSION_LEG.md`), with the trade
  and a proposed mechanism — not ruled here.** *Why this is not the case
  the bootstrap ruling covered:* the launch free regime is one window,
  once, and Component 4's ruling that it is a subsidy was a ruling about
  *launch*. Under shard-granular discard every shard the chain ever
  produces has its own freeze-epoch window of being bondable while
  universally held (*re-keyed 2026-09-22 from "`≥ W`"*) — **steady state,
  recurring, not bootstrap** — so the §3 `bond_duration ≥ W` withdrawal
  (itself withdrawn; the relation named a constant that no longer
  exists) does not reach it, and the reward leg is
  asked a question the bootstrap ruling did not answer: at what weight
  does channel 1 pay a bond on an in-window shard? *The trade:* **from
  bond**, a single early bonder earns maximum scarcity weight
  (`1/R_market` with `R_market = 1`) on a good every node holds, for
  the length of the freeze-epoch window (*re-keyed 2026-09-22 from
  "`≥ W`"*), on every shard — it overpays, but it is *exactly the incentive
  the specified-to-scarce window exists to create*: commit to `k` before
  it is scarce so that scarcity arrives with holders; pay nothing early
  and every shard reaches `discard(k)` with zero bonds and the Foundation
  `CompleteTree` is the first and only holder of every freshly scarce
  shard, permanently — the structural floor doing the market's job.
  **From discard**, no overpay, no early bonders, and the window is a
  window nobody uses. **The window is load-bearing on this answer:** if
  channel 1 pays from discard, shard-granular discard still buys atomic
  scarcity and clean "not retained" semantics, but the staker-window
  rationale above does not hold. *A second gap, same place:* during the
  window `R_market(k)` counts **bonders**, not holders — every node holds
  it — so the self-dilution that discharged §3's Sybil item does not
  operate on in-window shards by itself; a `k`-persona bonder dilutes
  only against other bonders, of whom there may be none. The Sybil
  argument was made for scarce shards; the reward leg confirms it holds
  in-window or says what does.

  *Proposed mechanism (for the reward leg to rule or replace): a derived
  commitment weight, the median of what scarce shards are paying this
  epoch.* At each epoch boundary, for a closed shard `k` not yet at
  `discard(k)`:

  > `w(k, E) = median_{s scarce at E} ( g(age_s) / R_market(s, E) ) · 1 / R_market(k, E)`

  It prices a new shard at what a typical scarce shard pays *this epoch*,
  so it tracks the market rather than guessing it — under-held history
  raises the median and new shards pay well; good coverage lowers both —
  and it keeps `1/R_market(k)` on the new shard, so the self-dilution
  operates in the window too: a `k`-persona bonder splits the median `k`
  ways rather than earning it `k` times, which closes the second gap.
  **Where the constant lives:** before any shard is scarce there is no
  median — that is the launch window, epochs 0 and 1 (*re-keyed
  2026-09-22 from "chain younger than `W`"*) — and only there is a flat
  **`w_launch`** needed, superseded by the derived median the epoch the
  first shard discards. So the tweakable governs two epochs (~4 weeks;
  was ~195 days under `W`)
  once, not every shard forever. *Bounds, adversary first:* **upper** —
  `w` must not outcompete the median scarce shard or marginal capital
  flows to new shards (free to hold, no fetch) and abandons old history,
  the harm that actually matters; the median enforces this by
  construction, `w_launch` must be set below where scarce shards will
  settle, which is the part needing judgement. **Lower** — `w` must
  exceed the cost of committing (bond lock + disk) or nobody bonds early
  and the floor is first holder of everything. **Adversarial** — moving
  the median means bonding many scarce shards, which is paying to hold
  history, the honest act; low leverage. *Deriving `w_launch`:* sim for
  the band where neither failure occurs (bounding, a legitimate sim use),
  then **Round-2 pins it with `n` and `D_max` on the same gate — the
  third numeric there** (*re-keyed 2026-09-22: `W` left the gate with the
  constant; was "a fourth"*), not an entry of a different kind. *Two
  things so the reward leg does not lose them:* (a) the median is over
  **scarce** shards only, and "scarce" is now one chain-derivable event
  (`discard(k)` at the boundary after `k`'s freeze epoch — *re-keyed
  2026-09-22 from `b_{k+1} ≤ first_tx_id(tip − W)`*), so the set is
  unambiguous and identical on every node — computable in the settlement
  writer without a new consensus object; (b) at the epoch of the first
  `discard(k)` the scarce set is **one shard**, so the median is a single
  sample for some epochs — the leg says when `w_launch` hands over (first
  discard, or a minimum scarce-set size). *Consensus:* `w` is computed by
  the settlement writer and every node must agree, so the **shape is
  genesis-frozen and the numeric provisional**, the same discipline as
  the other three — and it lands in `shekyl-chain-rules` under DRS-D12 /
  SO-D8 Q15, never in the C++ path.
- **The preimage terms** (item 4's consensus row): the serve-credit
  signature signs `shard_id` and `(k·T, (k+1)·T)`, each **read by the
  verifier** from `cumulative_tx_count` and `T` (*re-keyed 2026-09-23,
  item 5: no length rows*), never carried — the discipline `wire.rs:345-360` states today for the
  leaf terms, so nobody re-argues whether the prover could have chosen
  them.

**Item 3, the credit-wire collision — not reopened.**
`ARCHIVAL_CREDIT_WIRE.md` §3's `transfer_digest` rejection stands.
Under this unit a digest over the shard's *hash rows* is
admission-reconstructible — and therefore computable by any node that
possesses nothing, so it proves nothing about possession; a digest over
the shard's *bytes* remains non-reconstructible, so the original ground
holds. For any signed digest, admission-reconstructibility and
possession-discrimination are in opposition; the only escape is
reveal-and-check, which this unit supplies per-tx and which the
whole-shard topology read ([`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md)
§9, *"the test IS a read"*) already uses. No signed content
artifact is added to the wire. Reopens only if the credit wire abandons
the topology read for a sampled test — in which case `PC-D3`'s draw
problem returns with it, and that is the credit wire's round to rule.

**Consequences, now in force.**

- `PDM-Q1` may be ruled; it grades §9 against this unit.
- `PDM-Q12` may be ruled; the commitment exists at ingest, and the
  segment freeze has nothing left to freeze under this unit (candidate:
  retires; `LeafStore` is a deletion target).
- `SF` sub-PR 2 is unblocked: frame codec and `ContentVerify` are
  per-tx against the two hash rows; `recompute_segment_r_k` does not
  survive (`PDM-Q-F25`). ~~`SHARD_BYTES` **does** — as the boundary
  metric (F32)~~ **retired as consensus 2026-09-23 (item 5)** — 3.33 MB is
  now only `T`'s sizing heuristic.
- `PDM-Q-F28` (skeleton wire carries `pqc_auth_hash`) is no longer
  gated on this question.
- `DAEMON_REDB_STORE.md` §7.7's three-leg invariant is the store's
  contract for this good: hash row ⇔ 4-part txid, permanent; segment
  present ⇒ hash row present; hash row present ∧ segment absent ⇔
  discarded or never held (band 1).

**Item 4 RULED 2026-09-18 — what the unit change re-keys and what it
reopens.** Grounded at `dev@20ebdf1e5`; `wire.rs`, `codec/chain.rs`
and the serve-credit call site read at source (the first draft did
not, and was wrong where it mattered — row 1 of the table).

*Rule.* A closed ruling is **re-keyed** when its argument survives
with "leaf segment" → "`tx_id` range" and "`R_k`" →
"`txs_prunable_hash` + `txs_pqc_auth_hash`"; it is **reopened** when
its argument depended on a shared root, a fixed 128-byte claim, or leaf
addressing. Re-keys land as line-local edits under rule 23 in the
owning doc with a pointer here; reopenings get a dated sub-section in
the owning doc. **"Retired by ruling" and "retired in code" are
different states and the table says which.**

| Ruling | Disposition | Substitute |
| --- | --- | --- |
| **Serve-credit admission verifier** — `CEN-J*` / `CEN-L7–L10`; `shekyl_archival_verify_serve_credit_vin`; C++ site `src/cryptonote_core/blockchain.cpp:5085-5125` | **Reopened — consensus.** The hybrid-signature preimage signs two *verifier-derived* leaf terms, `segment_subroot_rk` and `leaf_index_in_segment` (`rust/shekyl-archival-retention/src/wire.rs:345-360`): `RF-D6` took them off the wire *because* the verifier rebuilds them from `LeafStore::frozen_segment` and `challenge_leaf_index`, and the C++ site does exactly that today (reads the leaf chunk, fills `ctx.registry_segment_subroot_rk` / `segment_leaf_count`). Under the tx unit neither exists. So the signed message of every pass record changes, and the admission rule changes with it. **"The wire sees no change" was true of bytes and false of the signed message, and the signed message is the rule.** | Preimage restated over `shard_id` and `(k·T, (k+1)·T)`, each read by the verifier from `cumulative_tx_count` and `T` (item 5, 2026-09-23; *was* `(b_k, b_{k+1})` from the length rows under the item 3 amendment); FFI contract (`registry_segment_subroot_rk`, `segment_leaf_count`, `leaf_layer_scalars_*`) replaced. **Landing site: E4 / S-ARCH in `shekyl-chain-rules`** — never `blockchain.cpp` (`S0`; SO-D8 Q14). No record signed under the leaf preimage verifies under the tx preimage; a genesis-frozen rule written before genesis, not migrated. CEN rows re-keyed in that PR. |
| `RF-D1` — `leaf_bytes`, 128 B on the kept vin (`ARCHIVAL_RESPONSE_FORMAT.md` §3.5) | **Reopened.** The claim was *one leaf*; under a whole-shard read there is no claimed transaction and no `tx_id` to claim — the identifier is `shard_id`, already on the vin. Kept side loses 128 B. | `RF-D1` re-prices the kept side (~230 B → ~100 B). The pruned half is the pass record's own `CtSigPrunable`, unchanged in kind. |
| `RF-D6` — `SHARD_BYTES = 25,992 × 128`; `segment_subroot_rk`/`leaf_index_in_segment` off the wire | **Reopened, and half survives** — ~~the fixed byte *size* survives as the boundary metric (F32)~~ **retired entirely 2026-09-23 (item 5: fixed cardinality `T`; 3.33 MB is `T`'s sizing heuristic only)**; the "leaves × 128" derivation and the two off-wire leaf terms do not. | `RF-D6` restates (item 5): a shard is `T` transactions, `[k·T, (k+1)·T)`; no byte metric and no byte bound — the fetcher streams and verifies per transaction, buffer `MAX_TX_SIZE`; the off-wire terms become `(k·T, (k+1)·T)`, verifier-derived from `cumulative_tx_count` and `T`. 3.33 MB survives only as `T`'s sizing heuristic. |
| `challenge_leaf_index` + fire schedule; `c1_layers`/`c2_layers` path in the pruned record | **Retired by ruling (`RF-D8` (i) retracted 2026-08-26) — live in code.** `challenge.rs`, `path.rs`, `segment_freeze.rs`, `serve_credit_decisions.rs`, `wire.rs` (the `c1_layers` write at `:90`), the fuzz target, and the consensus call site all carry it. | **Deleted at E4 / S-ARCH** with the verifier row above. Not "no action". |
| `LeafStore::frozen_segment` + the freeze pipeline | **Retired → Q12; the store itself is rebuilt, not deleted** (amended on #775). | Derivable membership — `k = ⌊tx_id / T⌋` (item 5; item 3's original shape, F32's byte bound superseded); a body store keyed by shard over `[k·T, (k+1)·T)` (was `[b_k, b_{k+1})`). |
| `SF-D7` — memory floor `N × SHARD_BYTES` | **Re-keyed, then re-keyed again 2026-09-23 (item 5).** The floor is a cap on in-flight bytes; with per-tx streaming verification nothing materialises a shard, so the floor is **`N × MAX_TX_SIZE`** — one transaction per in-flight fetch. `N = 8` and the `L` candidate were measured at 3.33 MB and **stand as approximate** under `T`; re-measurement is the spike lane's. | Line-local in `ARCHIVAL_SHARD_FETCH.md`. |
| `SF-D8` — verify seam "local `R_k` + countersignature" | **Reopened (content half); re-keyed (countersignature half).** Content-verify is per-tx via `Transaction::txid_parts()` against the two hash rows, plus membership against `[k·T, (k+1)·T)` (item 5; was `(b_k, b_{k+1})`), streaming one transaction at a time; the `SF-D8` request countersignature (72-byte anchor header ‖ `shard_id`) is unchanged and lives in sub-PR 1 (`PDM-Q-F25`). | Sub-PR 2's `ContentVerify`, `expected = (txs_prunable_hash, Option<txs_pqc_auth_hash>)` per `tx_id` in `[k·T, (k+1)·T)` (item 5). |
| `SF-D1` — addressing clause ("no leaf addressing; materialise the segment") | **Re-keyed.** No per-tx addressing on the route either; the read is still whole-shard. The clause's *reason* (`R_k` needs the whole segment) is gone; its *conclusion* (one resource, one path) stands on `RF-R1` alone. | Line-local. |
| `CR-D2` — carrier (pass-record partition) | **Re-keyed, kept side re-priced by `RF-D1`'s row** (~230 B → ~100 B). The partition itself is unchanged; the pruned half is inside the good (`PDM-Q-F15`). | Pointer, plus the re-price. |
| `TJ-D` — this charter as design home | **Re-keyed.** TJ-D named leaves; the home is the same, the subject moved. | The two reconciliations TJ-D owes are restated against the tx unit in its own row. |

*Consequence.* SF sub-PR 2 is unblocked with its verify seam's
`expected` named; the credit wire's **bytes** need no edit and its
**signed message and admission rule do** (row 1), which is E4's.

*Reversion.* A reopened row reverts to re-keyed if its owning doc shows
the argument never depended on the leaf property — falsifier: the
owning doc's dated sub-section cites no leaf-specific premise. A
re-keyed row reverts to reopened if a line-local edit fails to
type-check against the unit — falsifier: an `SF-D7` or `RF-D6`
constant still named in bytes-of-leaves after the edit. Row 1 reverts
to "no change" only if `wire.rs`'s preimage is shown not to include the
two derived terms — falsifier: `wire.rs:345` read again.

**Item 5 — RULED 2026-09-23: shards are fixed-cardinality `T`; no byte
accounting anywhere; the byte bound (F32) is superseded.** Surfaced by
Bugbot on #832 (high; the thread was auto-resolved by a later push, the
finding was not): item 3's byte-bounded `b_*` is a prefix sum of every
transaction's `prunable_len + pqc_auths_len` from genesis, bond admission
validates `shard_id` against closed shards — so **`b_*` is consensus** —
and nothing the checkpoint reaches binds a *length*: `C` → block hashes →
txids → `H(prefix) · H(base) · prunable_hash · pqc_auth_hash`
(`txid.rs:55`). A peer serving the skeleton below `C` can state any
length; one wrong value shifts every later boundary on that node and it
forks at admission. The A4 rows' "original state" and the skeleton §12's
"safe because band 1 is trusted" (2026-09-22) are **refuted**.

*The question the binary skipped: what is the byte count **for**?*
Byte-bounded shards existed for two consumers, and under a per-tx verifier
neither remains:

- **SF's memory ceiling** (`SF-D7`, `max_body_bytes`, `N × …`) was a
  property of `R_k`, which needed the whole segment in hand. `R_k` is gone
  (item 4). A fetch client verifies **each transaction against its retained
  hash row and aborts on the first miss**; its buffer is one transaction —
  `MAX_TX_SIZE`, 1 MB — regardless of shard size. Nothing materialises a
  shard.
- **Per-shard pricing** (`REWARD_EMISSION_LEG.md` channel 1,
  `scarcity = g(age) / R_market(s)`) is already not byte-proportional. A
  large shard costs more egress for the same weight; archivers avoid it;
  `R_market` falls; weight rises. The curve absorbs size variance as it
  absorbs everything else.

The settlement writer prices by weight, the fetcher streams, the wallet
store knows what it holds. **No one in consensus needs the count.**

*Ruling — (e).* A shard is **`T` transactions by `tx_id`**:
`k = ⌊tx_id / T⌋`, `[k·T, (k+1)·T)` — item 3's original 2026-09-17 shape,
restored. Membership and `close_height(k) = height((k+1)·T − 1)` derive
from `cumulative_tx_count` on every node with **zero new data**: no length
in the base, no length on the wire, no A4 rows, no `CtSigBase` change, no
`SHARD_BYTES` constant, no prefix sum. The Bugbot finding has nothing to
bind because nothing is claimed. **`T` is the one consensus constant of
the partition**, with the one-home discipline `SHARD_BYTES` carried
(FOLLOWUPS `:72`, re-keyed): **`T = 200`, PROVISIONAL**, chosen so a
typical shard at ~16.7 KB/tx lands near `RF-D6`'s 3.33 MB and `SF`'s
measurements stay approximately right; pinned at the Round-2 gate with
`n`, `D_max`, `w_launch` (four numerics again, `T` in `W`'s old seat).
The worst case is bounded **per transaction by streaming**, not per shard
by a constant.

*F32's four reasons, each dispositioned (rule 16 — refuted or answered,
not superseded in silence):*

1. *"`T` was never given a value."* **Answered:** `T = 200`, PROVISIONAL,
   Round-2 gate.
2. *"`T × MAX_TX_SIZE` makes `max_body_bytes()` a multi-gigabyte in-flight
   ceiling at `SF-D7`'s `N = 8`."* **Refuted:** the ceiling was `R_k`'s;
   per-tx streaming verification holds one transaction; `SF-D7` re-keys
   to `N × MAX_TX_SIZE` (the SF lane's, item 4's row).
3. *"`SF`'s `N` and `L` were measured against a fixed 3.33 MB."*
   **Answered:** they stand as approximate under `T`; re-measurement is the
   spike lane's own, as F33 (i) already says of model constants.
4. *"Cardinality pricing mis-prices shard compositions by up to ~60×
   while a discarded shard's true size is unrecoverable."* **Answered:**
   the 60× is a lottery over which shards are cheap to hold, and the
   weight curve is the mechanism that turns a lottery into a market; no
   consumer needs the discarded shard's true size. The possession-test
   read still reads the whole shard, and its egress varies with the shard
   — an honest holder's real cost, self-selected at bond, priced
   correctly.

*Alternatives, for the record:* **(a)** lengths as base fields — solves
the binding, but on the strength of a memory ceiling that no longer
exists, at the cost of a spend-format change every wallet and serializer
carries; **rejected** as the wrong fix for a need that dissolved.
**(b)** shards over retained bytes — rejected (bounds nothing served).
**(c)** `b_*` committed on chain — rejected (commits a derived value where
the inputs are unbound). **(d)** trust the wire — rejected (a consensus
partition on an unbound field). **(g) — the named alternative:** if the
reward leg establishes a byte-proportional term, commit
`cumulative_prunable_bytes` **once per block in the coinbase `tx_extra`**
under a new tag — the coinbase txid commits it, the merkle root the
coinbase, the block hash the root, the anchor the block; body-holding
nodes recompute at connect and reject a wrong value (one rule row);
skeleton nodes read it. ~4 bytes per *block* against (a)'s per
*transaction*; a derived scalar in the place the chain already puts those
(`attestation_root` is the precedent), not a new consensus structure.

*Consequences:* **A4 is not owed** — its FOLLOWUPS row closes; §7.7 gains
no fourth leg. **F28 grows one field** (`pqc_auth_hash`), as first ruled.
`SHARD_BYTES` is retired as consensus; 3.33 MB survives only as `T`'s
sizing heuristic. `RF-D6`'s fixed byte size is retired entirely; `SF-D1`'s
whole-shard *read* stands (the possession test), its whole-shard
*materialise* does not. The skeleton's §2, §4, §5, §12 re-key; the
wallet-side store keys by `k` over `[k·T, (k+1)·T)`.

*Reopen (rule 21):* to **(g)** if `REWARD_EMISSION_LEG.md` establishes a
byte-proportional weight term — that is the one question that decides
between them and it is the reward leg's; falsifier: a channel-1 term
taking a byte count as an operand. To OPEN if any consensus consumer of a
shard's byte size is found that neither streaming nor the weight curve
serves. **Falsifiers now:** any shipped Rust deriving a shard boundary
from a byte length; a second `T` in any crate or in
`consensus_constants.json`; a fetch client materialising more than one
transaction to verify.

**Reversion criteria (rule 21).** This ruling reverts to OPEN if any
of: (a) a consensus reader of the prunable region or `pqc_auths`
appears outside admission — falsifier: `PDM-Q-F29`'s `ChainView`
surface acquires a body accessor without an above-horizon mark, or a rule
in `shekyl-chain-rules` reads a recorded body; (b) replay through
`apply_block` is shown to need a byte from either region — falsifier: a
derived table that `DRS-D10` replay cannot rebuild from the skeleton
alone; (c) the `tx_id` index stops being monotone or KEEP-C in the Rust
store — falsifier: `tx_indices` graded CACHE or below in DRS's
accumulator classes.

**Falsifiers on the ruling as landed.** A `TxIdentity` whose
`pqc_auth_hash` is `Some` for a 3-part txid or `None` for a 4-part one
is red (KAT on S-CHAIN-R's row). A bond `holdings`, wire echo, or
challenge draw expressed in a unit other than `tx_id` range is red. A
shard whose byte size is used for pricing without being bounded by
`SHARD_BYTES + MAX_TX_SIZE` is red (*superseded form, 2026-09-17:*
~~`T × max_tx_size`~~ — F32 retired `T`).

### `PDM-Q7` RULED 2026-09-18 — The Monero-era stripe engine is removed completely; nothing of it survives as design

**Grounded at** `dev@20ebdf1e5`; anchors re-verified at source
(`shekyl-levin/src/payload/types.rs:104,149`,
`shekyl-rpc-types/src/p2p.rs:125,241,295`, `cryptonote_core.cpp:127`,
`cryptonote_protocol_handler.inl:1979` / `:2810`).

**Ruling.** The stripe engine's purpose — a node-local, seed-assigned
partition of history with a wire advertisement and complement-seeking
peer selection — is **superseded by the archival staking system**, and
its implementation is not carried forward in any form. **Nothing of the
engine survives as design.** Its three transferable parts
(`PDM-Q-F17`'s triple) each have a successor that is not it:
**assignment is the bond** (`holdings` on-chain — Q9's source ruling:
the chain, not the wire, is authoritative); **advertisement is the
bond**; **coverage is price** (`1/R_market`, `REWARD_EMISSION_LEG.md`
channel 1). F17's "worth taking" is **refuted** as a candidate and kept
as the record of one considered and refused; Q9's
holdings-advertisement sub-question closes as *none on the wire*.

**What "completely" is, by surface.**

| Surface | What | Disposition |
| --- | --- | --- |
| C++ engine | `prune_worker`; `check_pruning`, `get_blockchain_pruning_seed`, `prune_blockchain`, `update_pruning`; `CRYPTONOTE_PRUNING_*`; `src/common/pruning.{h,cpp}`; `--prune-blockchain`; stripe-aware sync and peer selection | **DELETED 2026-09-21** (`feat/pruning-seed-wire-deletion`). The first draft scheduled this "at `DRS-E*` with the C++ store" citing `PDM-Q-S0`; S0 forbids *implementing* set-B discard in C++, not deleting the inherited engine, and the wire half (next row) does not die with the store — so it went now. Not ported: S-PRUNE is a *refusal* to port. **Then the rest (2026-09-22, `feat/delete-cxx-tx-data-prune`):** `prune_tx_data` / `get_last_pruned_tx_data_height` / `CRYPTONOTE_TX_PRUNE_DEPTH` — Shekyl's C++ tx-data discard past the reorg depth, a different mechanism reached only through the stripe path and therefore a callee with no caller after #821 — deleted with its `output_metadata` cache, its watermark property, `get_info.tx_prune_height` (RPC 3.36) and the write-never `txs_prunable_tip` table: LMDB v15, redb `SCHEMA_VERSION` 10. S-PRUNE inherits no discard mechanism of either shape. |
| C++ sync | `--sync-pruned-blocks` (`arg_sync_pruned_blocks`) | **DELETED 2026-09-21, under `PDM-Q5`'s rejection, not under this ruling's "engine"** — it is trust-the-txid-skip-the-proofs with *no anchor*: Q5 REJECTED trust-below-`D_max` as a posture *with* a reorg bound, and this flag is that posture with none — a live implementation of a rejected ruling. Band 1 under the anchor (Q5, F28) is the successor and the only skeleton-sync path the design admits. Recorded here so the reason survives the engine's deletion. |
| P2P wire | `pruning_seed` on `CORE_SYNC_DATA` and every peerlist entry; Rust mirror `shekyl-levin/src/payload/types.rs` | **DELETED 2026-09-21, both languages** — superseding the first draft's *retire-by-zeroing* ("send `0`, ignore non-zero"). The finding that changed it (2026-09-21): the field was a durable, address-keyed, self-asserted attribute gossiped in every peerlist — the shape `PWD-I1` deleted `peer_id` for, two lines below the comment saying why — and with a uniformly-zero honest fleet (23/23 handshakes at `seedbrz`) the eight accepted non-zero values were free markers for topology tracing through `get_peerlist_head`, which `net_node.inl`'s candidate selection *acted on*. Zeroing keeps the slot and the nine-valued validator; deletion removes the class. Interop-safe: both homes were `KV_SERIALIZE_OPT(…, 0)` (absent reads as 0, unknown keys are skipped); the positional VARINT form had no caller. `shekyl-levin` decodes a stale key with the key ignored (tested). Peerlist store v8 → v9. Closes `PDM-Q8`'s residue: retention reaches no wire. CI: `scripts/ci/check_no_stripe_engine.sh`. |
| RPC | `pruning_seed`, `next_needed_pruning_seed`; method `prune_blockchain` | **DELETED 2026-09-21** at `CORE_RPC_VERSION` 3.35 (`get_peer_list`, `get_connections`, `sync_info`; `_v3` vectors); **`prune_blockchain` REJECTED** in the daemon method registry (rule 23 namespace protection — a refused name stays in its table; `DAEMON_RPC_KV_CUTOVER.md` RK-8 marked). *Corrected 2026-09-18 on review:* `get_blockchain_pruning_seed` is **not** an RPC method — it is the core getter `on_prune_blockchain` calls to fill its response (`:1441`); it dies with the C++ engine row above, not as a registry entry. |
| Rust successor | S-PRUNE ([`DRS_E1_SPRUNE.md`](DRS_E1_SPRUNE.md) §1) | Reads nothing from the engine. The seed arithmetic is not the shard definition (F32's byte-bounded `tx_id` ranges are); the wire slot is not the advertisement (the bond is); peer preference is not coverage (price is). |

**The other half — unbonded retention: PERMITTED, in the wallet-side
store, never the daemon** (amended 2026-09-18 on #775 / Q9: a keep-all
*daemon* is a fingerprint under the uniformity corollary — all daemons
prune; the reasoning here stands, the home moves). Retention and
serving are different acts. An unbonded operator fills a wallet-side
store exactly as a bonded one does, reaches no wire under `PDM-Q8`, and
is the structural floor Q9 and Q5 name (Foundation `CompleteTree`
behind a Foundation persona, explorers, an altruistic keep-all store). Adversarially: a hazard would have to be
either a wire-visible difference (Q8's indistinguishability test says
no) or a way to earn without a bond (serving needs the persona and the
countersignature, so no). An unbonded full archive is a node that paid
its own disk to hold history and cannot be paid for it. That is a
floor, not a hazard. The 2026-09-12 sequencing rulings stand: the
**opt-in flag is rejected** for the *universal* set (every daemon
discards identically); *exceptions* exist only above the body horizon,
in the wallet-side store (*re-keyed 2026-09-22 from "above `W`"*), and
are not what makes a node an archiver.

**Reversion (rule 21).** The engine half reopens only if a band-2
fetch path is shown to need holder discovery from anywhere other than
the on-chain bond table — falsifier: a `PFetchClient` caller that reads
a peer-advertised holdings hint. The unbonded half reopens if an
unbonded wallet-side store is shown to reach the wire — falsifier: Q8's
indistinguishability test red on a host with such a store and no bond.

**Falsifiers** (gated: `scripts/ci/check_no_stripe_engine.sh`, grep-gates).
A `pruning_seed` key on any wire map, in either language, is red. Any
stripe-engine identifier in code in `src/` or `rust/` is red. A
`--prune-blockchain` or `--sync-pruned-blocks` flag in any daemon's CLI
is red. `prune_blockchain` routed in any daemon RPC is red; a
`pruning_seed` field in any daemon RPC response or current vector is red. An unbonded wallet-side store distinguishable on the wire is red; an
unbonded *daemon* retaining a shard past the boundary after its freeze
epoch is red (Q9, #775; *re-keyed 2026-09-22 from "past `W`"*).

### `PDM-Q8` RULED 2026-09-18 — Serve-side uniformity (ruled 2026-09-13) and the fetch side, closed by citation

**Grounded at** `dev@20ebdf1e5`.

**Serve side (ruled 2026-09-13, stands, and #775 strengthens it):** P2P
body-serving is uniform inside the body horizon on every daemon
(*re-keyed 2026-09-22 from "inside `W`"*); beyond-window serving
is wallet-fronted over onion only; retention never selects wire behaviour
— and, per #775, never selects *disk* either: no archival serving state on
any daemon, all daemons prune uniformly (Q9).

**Fetch side — walked (§3, this thread) to no standing adversary, closed by
citation.** The fetcher is a Tor client with no address (`SF-D3`, SOCKS5h);
challenge and organic reads are indistinguishable on the wire —
`ARCHIVAL_CHALLENGE_MECHANISM.md` §9 (*"the test IS a read"*) with the
`SF-D5` / `SF-D8` nonce-anchor header as the mechanism, and organic
selection a uniform memoryless draw (`SF-D10`); the **persona** never
fetches — its **daemon** does, episodically, as that Tor client, so
serve-and-fetch are co-located at the host and unjoinable on the wire;
visualiser traffic is organic cover; `P → shards` is public by design
(the bond post). Every one of those is a ruling or a code property.

~~**Bounded exception, named:** two releases with different `W` are
distinguishable during a rollout (Q2).~~ **VOID 2026-09-22** — Q2 re-ruled:
the body horizon is the epoch calendar, not a constant; there is no `W` to
roll and no rollout window in which two daemons differ. **Falsifier:** Q8's
indistinguishability test red on any host — bonded or not, serving or
fetching.

### `PDM-Q9` RULED 2026-09-18 — The archiver's retention set lives in the wallet-side store; the daemon holds no archival serving state

**Grounded at** `dev@20ebdf1e5` and PR #775 (`docs/two-store-daemon-uniformity`,
head `e2b6b87f6`, **OPEN at ruling**, read in full — `PDM-Q-F33`).
**Decision anchor (rule 94, clarified 2026-09-18 on review):** the closing
edit is **this contract's, on #774** — the maintainer read #775 and ruled
here. #775 is the *criterion's source*, not the anchor. **#775 landed
`e685ef1cd` and #774 landed `eee838d4d` fifteen minutes after it, so F33's
re-key fell to PDM and is done** (`docs/pdm-f33-rekey-775`: #775's
partition and CT-1 FOLLOWUPS rows, its serving-route paragraph, and a dated
amendment on its decision-log entry). Reopen criterion for Q9: the
*persistent-and-posture-correlated* test itself refuted.

**The argument that decides it is #775's; the ruling is this round's.** The daemon
holds **archival consensus state** — bonds, serve credits, settlement,
slash — because every daemon validates those and they are uniform by
definition. It holds **no archival serving state, ever**: the daemon is
the one publicly addressed process, and any *persistent,
posture-correlated* state in it is a fingerprint for as long as a bond
lives. **Episodic** actions any daemon takes — a shard fetch to inspect
the visualiser, to confirm a transaction, or as the witness verifying a
challenge it drew — carry no posture signal and are admitted. And the
**corollary, RULED with #775: all daemons prune uniformly** — if
archiver operators tended to run full daemons, "runs a full node" would
be the fingerprint with no archival code involved. PDM owns the default
and carries that constraint.

**The candidate this charter carried is REJECTED and withdrawn.**
*"The daemon holds the shard as a retention exception on the universal
discard predicate"* (2026-09-13, Q9's pre-ruling body, in the record; Q12's `FrozenSegmentPruned`
substitute; F32's staker sentence; Q2's `k ∉ exceptions` conjunct; the
skeleton's §4) is durable, bond-correlated state on the daemon — the
fast path by another name: the daemon keeps bytes so the wallet can
serve them, and every form of it makes an archiver-backed daemon differ
from a plain one. Rejected under #775's own reopening criterion (only
archival serving becoming *universal* dissolves the line). Q8's
uniformity test would have passed it because it looked only at the
wire; #775's criterion looks at the disk, and is the stronger one.

**What remains of Q9 under the line — almost everything dissolves.**

- *Source* (ruled 2026-09-13, stands): shard retention is the bond
  process; `holdings` are on-chain.
- *Binding:* **nothing.** The wallet holds the bond and the store. No
  `p_canonical_id` on the daemon, no `retain(k)` / `release(k)`, no
  operator-leg configuration of retention. The keys-versus-ranges fork
  the previous pass set up does not exist.
- *RPC:* **no new surface.** `get_prunable_range` is **withdrawn**. The
  wallet reads in-window bodies from its own daemon through the
  ordinary transaction-body read every wallet already makes
  (`get_transactions`' split form, `shekyl-daemon-rpc/src/methods.rs:552-605`)
  — uniform because every daemon serves its operator that way.
- *Lapse:* the wallet-side store's — how long a shard is held after a
  release, and what enforces it. #775 routes it: *"retention has two
  owners now"*, FOLLOWUPS row, owner named there
  (`ARCHIVAL_SERVING_ROUTE.md`; enforcing site `shekyl-curve-tree`'s
  store).
- *Coverage floor:* **structural and counts personas** (§3 Sybil walk,
  Q7) — Foundation `CompleteTree` **in a wallet-side store behind a
  Foundation persona**, never on a daemon; #775's review record folds
  archiver-store durability as an operator's trade, not the network's
  floor (`FOUNDATION_ARCHIVAL_DISCLOSURE.md:196`, `V3_STAKER_ARCHIVAL.md:120`).
- *Recovery:* the ordinary primitive. The daemon fetches
  **episodically** (`PFetchClient`, as a Tor client with no address —
  witness, visualiser, recovery are indistinguishable on the wire),
  hands the shard to its wallet over the operator leg, **retains
  nothing**.
- *Advertisement:* none on the wire (Q7 closed it; the bond is the
  advertisement).

**The one sentence Q9 still owed — the specified-to-scarce window is
when the wallet fills its store from the local daemon.** Shard `k`
closes at tx `(k+1)·T` (item 5; `b_{k+1}` under F32); the archiver's
wallet pulls `k`'s bodies over the operator leg while its daemon still
holds them in-window; the daemon
then discards `k` at the boundary after its freeze epoch like every other
daemon (*re-keyed 2026-09-22 from "at `W`"*). After the window,
acquisition is a fetch from another archiver (recovery, above). That is
the grace window doing something concrete, and it replaces F32's
"retains from in-window bytes with nothing to fetch" — same mechanism,
right owner.

**AMENDMENT 2026-09-22 — the freeze epoch is the pull window; the
`Market` archiver's lifecycle; `CompleteTree` outside the market.** With
Q2 re-ruled the same day the window has an exact shape, and the archiver's
lifecycle follows from it plus what the bond wire already is
(`BondPostKind` = `JoinMarket | Reinstate | Release`,
`bond_wire.rs:47-51`; `HoldingsUpdate` REJECTED 2026-09-20 — the bond is
immutable):

- **The pull window is shard `k`'s freeze epoch, `close_epoch(k) + 1`.**
  Every daemon holds `k` for the whole of it; the wallet pulls over the
  operator leg through the ordinary split read (Q10) and verifies against
  the txid (`WSS-Q5`). **Pull before bond**: a `JoinMarket` naming `k` is
  posted only once `k` is **final** (`close_height(k) + D_max ≤ tip`; the
  frontier's closing transaction can move under a reorg, and admission is
  consensus —
  FOLLOWUPS `:74`'s "valid, closed, final") **and** in the wallet-side
  store. The pull can start at finality, at most `D_max` blocks into the
  freeze epoch, leaving `≥ SEB − D_max` blocks of window. (This supersedes
  `WSS-Q4`'s deadline — *"the next epoch's open, which may be one block
  away"* — the window is the whole freeze epoch; the wallet lane re-keys
  §6.5.)
- **One `JoinMarket` per batch of closed shards.** An archiver on the
  `Market` leg bonds the shards that closed in an epoch as one post at the
  end of their freeze epoch (or earlier, once pulled); **`holdings` are
  frozen at post** — there is no in-place update, that mechanism is
  rejected — and the next epoch's closed shards are the next post.
  **Named consequence, not implied:** an archiver's bond count grows by one
  per epoch for the life of its tenure, and capital per bond, the
  settlement writer's per-bond work and the `Release` tail per batch scale
  with it. This ruling fixes the lifecycle; pricing it is the reward leg's
  and `ARCHIVAL_BOND_CONSTRUCTION.md`'s.
- **A new persona per batch.** Each `JoinMarket` carries its own
  `bond_spend_pk` and serving `endpoint` (`EU-D3`); the persona is the
  bond's, so a batch is a persona and personas are not linked across
  batches by the wire.
- **`Release` is the only exit**, and the wallet-side store's **lapse tail
  runs from it** (`WSS-Q8`'s two-epoch pin-release gate is that tail).
  `Reinstate` is re-entry after a slash-emptied record, not an exit; a
  slash empties, it does not release.
- **`CompleteTree` is the Foundation's genesis obligation, outside the
  market.** It pulls **every** shard in **every** epoch during that
  shard's freeze epoch, holds all of them behind a Foundation persona in a
  wallet-side store (never on a daemon — the floor above), is not bonded
  or paid through the market, and is the **unpaid backstop for a missed
  window**: a shard no `Market` archiver pulled in its freeze epoch is
  still acquirable from `CompleteTree` after the boundary, so the chain
  never loses a body to a missed pull. Its activation is
  `COMPLETETREE_ACTIVATION.md`'s; this amendment fixes only what it
  pulls and when.

**Consequences this ruling forces elsewhere (amended in this pass):**
Q2's predicate loses its `k ∉ exceptions` conjunct — the daemon has no
exceptions; Q7's *permitted* unbonded retention lives in a wallet-side
store, never the daemon; Q12's `LeafStore` is **rebuilt around bodies,
not deleted** — the leaf-shaped internals go, the serving store stays,
and `StoreShardProvider` keeps reading it; the skeleton's §4 and its
exception falsifiers go.

**`PDM-Q-F33` — #775 is written against the leaf unit, and re-keys
under Q6 / Q12.** Its *architecture* (two stores by obligation; the
partition is consensus) is unit-independent and stands. Its
*consequences* re-key: the partition is `⌊tx_id / T⌋` from
`cumulative_tx_count` (*re-keyed 2026-09-23, item 5; was `b_*` from
retained length rows* — consensus by the same argument: admission
validates `shard_id` against closed shards, a divergent partition forks at
admission, which is why nothing unbound may feed it);
`R_k` becomes the two hash rows on the daemon's skeleton; the served
frame is **whole-shard** (`WSS-Q7`: `SF-D1` keeps the read whole-shard —
it is *verification* that is per-tx); hash rows and `b_*` on the daemon (consensus,
uniform), bodies in the wallet store, frame shared. Its FOLLOWUPS
"partition tie" row (`SEGMENT_LEAF_COUNT == leaves_per_segment()`
compile-time assert; *"E3 consumes `frozen_segment_count` / `SegmentId`
and defines PDM's discard unit in them"*) is refuted by Q12 (the freeze
retires) and F32 (the unit is `b_*`); the hazard it names — a
provisional marker / config door on the partition constant — survives
unchanged and applies to **`SHARD_BYTES`**: one home, const-asserted,
not editable as a tune. #775's *"memory-only seed ring of Q10"* is
**SO-D8's** Q10, not this round's. ~~Whichever of #774 / #775 lands
second owes the re-key~~ **— #775 landed `e685ef1cd`, #774 landed
`eee838d4d` fifteen minutes later; PDM re-keyed (2026-09-18,
`docs/pdm-f33-rekey-775`): #775's partition and CT-1 FOLLOWUPS rows in
place, its serving-route paragraph, a dated amendment on its decision-log
entry. DISCHARGED.**

*Dispositions the re-key fixed, so the FOLLOWUPS rows can stay
one-liners:* (i) **Scope of the one-home claim.** It binds the
**production** `SHARD_BYTES` — the crates the daemon and wallet ship
(`BuildRust.cmake`'s roots: `shekyl-chain-store`, `shekyl-chain-rules`,
`shekyl-archival-retention`, `shekyl-curve-tree`, `shekyl-p-serve` /
`-fetch`) — and not measurement code: `shekyl-sp-t3-spike`'s fixture
constant (`fixture.rs:74`, derived from the leaf count) and
`shekyl-economics-sim`'s `f64` model constant (`burden.rs:39`, which says
it is not consensus) are intentional and stay. A production `SHARD_BYTES`
appearing in a second shipped crate or in `consensus_constants.json` is
the violation; the model constants tracking a moved production value is
the spike/sim lanes' own re-measurement, not this contract's.
(ii) **The leaf partition's interim tie.** `SEGMENT_LEAF_COUNT`,
`frozen_segment_count`, `SEGMENT_LAYER_J`, `outputs_per_node` are a
deletion surface at E4 / S-ARCH (Q12) but live consensus until then, so
#775's tie assert `const _: () = assert!(leaves_per_segment() as u64 ==
SEGMENT_LEAF_COUNT)` in `shekyl-archival-retention` stands as scoped —
one line that dies with the freeze — while its `const fn` rewrite and
marker removal are not worth doing on a deletion target (rule 15); a
`#[test]` tie is an acceptable fallback there. Owner: the wallet lane,
same PR as the CT-1 dedup assert. (iii) **Who derives `b_*`.** S-PRUNE's
forward pass over the A4 rows, once; E3 S-CURVE, the wallet-side store
(Q12's rebuild) and the verifier *read* it (Q6 item 4), none mints a
partition of its own — that is the re-keyed form of #775's "E3 consumes
`frozen_segment_count`, never a partition of its own".

**Reversion (rule 21).** Reopens only if #775's line is redrawn — its
own reopener: archival serving becomes universal. Falsifiers: any
durable archival serving state on a daemon (a shard body retained past
the boundary after its freeze epoch, a persona id, a `retain(k)`); a
`get_prunable_range` or any
archival-serving RPC on the daemon; an archiver-backed daemon
distinguishable from a plain one by disk or by wire.

### `PDM-Q10` RULED 2026-09-18 — "Not retained" is the existing split transaction read; no new RPC

**Grounded at** `dev@20ebdf1e5`; `shekyl-daemon-rpc/src/methods.rs:552-605`
read at source.

**Ruling.** Decided by rulings that already exist: Q2 makes retention
per-shard and uniform; Q9 / #775 remove every daemon-side archival
serving surface (`get_prunable_range` withdrawn); `RF-R1` collapses
whatever a wallet learns to one identical 404 at the onion. So the
contract is **the ordinary transaction read's split form**:
`get_transactions` with `prune` / `split` returns, per tx, `pruned`,
`prunable`, `prunable_hash` and a `pruned_flag` (the
`(split, prune, decode_as_json)` matrix at `methods.rs:552-605`). "Not
retained" is that response with `prunable` empty, `prunable_hash` (and,
after A3, `pqc_auth_hash`) present, `pruned_flag` set — **identical on
every daemon**, inside the body horizon (it has the body, returns it) and
outside (no daemon has it; *re-keyed 2026-09-22 from "inside `W`"*). A discarded body and a never-held one are one
state (F32 leg (iii)) and the response does not distinguish them. The
wallet-side store answers the onion; the daemon answers its operator.
Nothing to design.

**Falsifier.** A daemon RPC that reports archival retention, holdings, or
a per-shard "not retained" variant; or two daemons at the same height
answering the same split read differently.

### `PDM-Q11` RULED 2026-09-17 — `D_max`: shape frozen, numeric provisional, home `CEN-E2`

**Grounded at** `dev@4bc378d68`. Not archival-scoped; closes by
reference if a consensus-constants family rules it.

**What it is.** `D_max` is the maximum reorg depth a node with an
anchored chain will accept. It is a **detectability boundary**, not a
security margin: it does not raise attack cost, it converts a deep
rewrite from a silent reorg into a visible split. Any depth below
`D_max` is bought silently by an adversary who can afford it; the
requirement is `D_max < d_afford` for the rentable-RandomX adversary
positioned in the candidate derivation (record, Q11).

**Home.** `CEN-E2` — `is_alternative_block_allowed` — one function,
two bands: the anchor floor (refuse any alternative at or below the
last release-carried checkpoint) and the rolling cap (refuse any
alternative deeper than `D_max` below tip). `CEN-E1` (hash equality at
a checkpointed height) is the anchor's own rule, not this one. Both
census rows are re-keyed in the PR that lands `Trust::BelowAnchor`
(`PDM-Q-F30`), because that PR moves checkpoint state into Rust and
fires the reopening trigger both rows named.

**Binding condition.** `D_max` binds only once a node has an anchored
chain. A fresh node's exposure is bounded by the anchor `C` and not by
`D_max` at any value; a node with an empty checkpoint table has no cap
at all, which is the pin today (`init_default_checkpoints` is a
rule-71-shaped no-op, `src/checkpoints/checkpoints.cpp:136-145`). The anchor
is therefore a **precondition** of `D_max`, not a sibling, and
`PDM-Q5`'s ordering item is discharged by this sentence.

**Numeric.** `D_max = 720` blocks (24 h at 120 s), **PROVISIONAL**, on
the `bond_duration` precedent. *Built 2026-09-25 as
`shekyl_chain_rules::D_MAX`, derived from `archival_reorg_depth_blocks`
(one source, `config/consensus_constants.json`), with `SEB > D_MAX`
const-asserted beside it and the retention prune consuming it
(`DRS_E1_SPRUNE.md` §14, SPR-6) — the numeric now has a mechanism to be
tested against, which is what "provisional until tested" needed.* The argument for 720 is coordination
with the archival domain's frozen assumptions and is recorded as such
(record, Q11). Two independent arguments for shallower are recorded beside it
and are not overridden: (i) 720 sits at the top of the honest-partition
floor and plausibly above `d_afford` in the first year; (ii) a deep
`D_max` widens the window in which a syncing node above `C` trusts
proofs it has not verified. Re-pinned at the Round-2 testnet gate
together with `archival_failure_window_n` ~~and `W`~~ — **one gate item,
three numerics** at this ruling; **`w_launch` joined the same gate
2026-09-18** and **`W` left it 2026-09-22** (Q2 re-ruled: the body
horizon is the epoch calendar, not a constant), so the gate is `n`,
`D_max`, `w_launch` (Q6 item 3 amendment, the commitment-weight
routing note: the flat in-window weight before any shard is scarce,
superseded by the derived median once one is); a re-pin task that
names fewer than three is incomplete. *Editorial, line-local (rule 23):* the ruling as delivered
named a **fourth** entry, the relation `bond_duration ≥ W`. That
relation was drawn by the §3 free-riding walk and **withdrawn by
steering the same morning** (the free-regime reward is the ruled
bootstrap subsidy; #770 landed the gate at three). Landed here at
three, consistent with the withdrawal; if the withdrawal was not meant
to reach this block, reinstating is one sentence in this paragraph and
the gate paragraph (record, Q11).

**Derivations that now bind.** Q2's discard predicate (`SEB > D_max`,
*re-keyed 2026-09-22 from `W ≥ D_max`* — const-asserted at this
constant's home when it is built); Q1's journal retirement floor
`tip − (CRB + n·SEB + D_max)` (*corrected 2026-09-22: no function computes
it yet — `shekyl_archival_failure_window_params` returns only the m-of-n
`n`; the function is owed here with the constant*)
(F19); S-PRUNE's undo-log watermark `≥ D_max` (SCW-7,
`StoreCannot::PopBelowFloor` as the refusal); and — the fourth, added
by this ruling — `Trust::BelowAnchor(anchor)` is mintable only from the
release-carried table (`PDM-Q-F27`), so `D_max` never has to defend a
node below its anchor.

**Reversion criteria (rule 21).** Numeric reverts to OPEN at the
Round-2 gate by construction. Shape reverts to OPEN if: (a) a
consensus-constants family rules a reorg cap with different semantics —
then this closes by reference and the derivers re-point; (b) the anchor
model in `PDM-Q5` is rejected, since without a precondition the
fresh-node argument returns to `D_max` and the detectability framing no
longer holds for syncing nodes.

**Falsifiers.** A fork of depth `D_max + 1` accepted on an anchored
node is red. A fork below `C` accepted on any node is red. `undo_log`
retention constant `< D_max` is red (SCW-7). A second reorg-depth
constant in any consensus or store crate that is not `D_max` by
reference is red — the drift pair the constants policy forbids.

### `PDM-Q12` RULED 2026-09-18, amended the same day on #775 — The freeze pipeline retires; `LeafStore` is rebuilt around bodies, not deleted

**Grounded at** `dev@20ebdf1e5`. A consequence of Q6 (items 1–3, F32),
not a new argument.

**Ruling.** The segment-freeze pipeline retires. It existed to commit
`R_k` over a segment so served bytes were content-verifiable. Under Q6
every txid already commits `prunable_hash` and `pqc_auth_hash` at
ingest, and membership is derivable from the retained length rows
(F32); there is no height at which a range *becomes* verifiable and
nothing left to commit. **Not a migration:** no chain, no successor
object. The freeze's retirement stands on Q6 alone; what is
*conditional* is only where its dependents re-point.

**Dependents and substitutes.**

- `TJ-D`'s "segment" → the byte-bounded `tx_id` range (Q6 item 3, F32).
- `RF-D6`'s segment → reopened per item 4 (half survives as the
  boundary metric).
- `SF-`'s serve-set pin (`StoreError::FrozenSegmentPruned`,
  `redb_backend.rs:464`) → ~~the daemon's retention exception is the
  pin~~ **SUPERSEDED (Q9 RULED on #775): the daemon holds no serving
  state.** The pin is the wallet-side store's own: a shard is present
  in it or it is not, and "pruned mid-serve" is a store fault the
  rebuilt store reports, not a segment state. The retirement itself
  does not move.
- `PDM-Q-F11`'s three curve-tree accumulator rows → unchanged; layer 0
  is still never pruned and still the tree's own commitment. The freeze
  was never the accumulator's source.

**Deletion surface — amended 2026-09-18 on #775: the store stays, its
leaf-shaped internals go.** The wallet-side store is *the* serving
store (#775: two stores by obligation) and it is **kept**; what Q6
changes is its **unit** — leaves to prunable bodies — not its
existence. *Rust, deleted:* `rust/shekyl-curve-tree/src/store/redb_backend.rs:164-183`
(`open_frozen_segment_body`, `ServingReader`, leaf-order streaming),
`StoreError::FrozenSegmentPruned`; `shekyl-archival-retention`'s
`segment_freeze.rs` and the freeze half of `challenge.rs` / `path.rs`
(item 4's "retired by ruling, live in code" row — deleted at E4 /
S-ARCH with the verifier). *Rust, rebuilt:* `LeafStore` becomes a
body store keyed by shard `k` over `[k·T, (k+1)·T)` (*re-keyed 2026-09-23,
item 5; was `[b_k, b_{k+1})`*), filled from the
local daemon during the specified-to-scarce window (Q9), served
**whole-shard** (`WSS-Q7`; verification is per-tx, the read is not);
`shekyl-p-host`'s `StoreShardProvider` **keeps reading it** — the
earlier "swaps its reader to the daemon's `get_prunable_range`" is
**withdrawn** with that method. **The rebuild has an owner (added
2026-09-18 on review): the wallet lane, as its own design round —
unbuilt by design, not by omission.** It is where the design's weight
now sits. **Its decisions were ruled 2026-09-19 (PR #790); what follows is the
list this charter owed, each now answered in that contract:** fill from the local
daemon during the grace window (Q9) and verify on fill **against the
txid** — *amended 2026-09-19 by the wallet lane's `WSS-Q5` ruling
([`WALLET_SIDE_STORE.md`](WALLET_SIDE_STORE.md) §6.4): a filler holds the whole
transaction, so it recomputes the consensus commitment itself rather than
trusting a supplied digest; the hash rows remain the **discarding daemon's**
own need for `DRS-D10` skeleton replay*; key by shard over `[k·T, (k+1)·T)` (item 5, 2026-09-23; `[b_k, b_{k+1})` at ruling); serve **whole-shard**
(`WSS-Q7`, 2026-09-19 — `SF-D1`'s whole-shard read stands; it is *verification*
that Q6 made per-tx)
through `shekyl-p-serve` (`SF-D8`'s content half, sub-PR 2); carry its
own lapse tail (#775's retention row); receive recovery shards the
daemon hands across and retain them; hold the Foundation `CompleteTree`
behind a persona (Q9's floor). The round registers its family at birth
(rule 94) and cites this contract for its inputs; FOLLOWUPS row with the
falsifier. **Collision, recorded 2026-09-18:** the wallet lane's active
store round — `CTS-` ([`CURVE_TREE_STORE_SHAPES.md`](CURVE_TREE_STORE_SHAPES.md),
PR #776, Round 1 ruled the same day) — is a typed-shape rewrite of the
**leaf-unit** store: its CTS-Q1 types the return of
`open_frozen_segment_body` and keeps `FrozenSegmentPruned`, both on this
ruling's deletion surface. Both lanes are right at their own pin; the
body-unit rebuild is **not in CTS-'s scope as of #776**. The CTS- round
is the natural home for it and owes either a scope amendment naming the
body unit or a successor round; this ruling does not decide which
(FOLLOWUPS row). **DECIDED 2026-09-18 (steering): a successor round.**
[`WALLET_SIDE_STORE.md`](WALLET_SIDE_STORE.md) (family `WSS-`, Round 0 at
`dev@8494f2a27`) opens as the wallet-side store's umbrella contract; `CTS-`
closes as record and its work is partitioned by unit there (§8). **Two
corrections that round returned to this ruling, recorded line-locally:**
(a) ~~The curve tree's *verification-side* leaf store, if any, is Q1's to
grade.~~ `PDM-Q1` grades **§9**, the daemon's chain-store inventory, where
`curve_tree_leaves` is graded CACHE (§9.2) — so that sentence's referent is
the **daemon's** leaf table, and the **wallet-side proving store is ungraded
by this charter** and is the successor round's (`WSS-3`). (b) This ruling's
deletion surface is B-shaped and correct as to symbols, but the freeze has one
**proving-side** consumer it does not name: the wallet store's `root_at_count`
reads `frozen_segments.r_k` as a root-composition cache
(`redb_backend.rs:1214`, `:1235-1247`; `store/ops.rs:39`) — `WSS-4`. **The
retirement stands** — the read has a recompute-from-leaves fallback and
nothing prunes in production, so the cache is **dispensable for
correctness**. It is **load-bearing for cost**, though: `verify_root` runs on
every ingested block, so without it every complete segment is recomputed from
its leaves once per block and sync becomes quadratic (`WSS-14`). What the successor round takes from it is narrower than a
survival claim: the composition boundary is a leaf-count geometry that
**cannot be tied to `b_*`**, so `F33` (ii)'s interim assert dies with the
freeze and is not re-pointed at `SHARD_BYTES`; whether obligation A keeps any
subroot cache at all is that round's `WSS-Q2` (`WSS-9`). Line cites in this ruling have drifted at later shas
(`FrozenSegmentPruned` is `:470`; the two `open_frozen_segment_body` are
`:216` and `:1877`) — the symbols are right, and each increment re-pins
(`WSS-10`). *C++:*
`process_archival_segment_freezes_at_height`, `archival_shard_segment`,
`frozen_segment_count`, `get_archival_shard_segment_at_height`,
`SEGMENT_LEAF_COUNT` — **die at `DRS-E*`** (`S0`: no C++ landing before
the cutover; Q7's engine went earlier, 2026-09-21, because its wire half
did not die with the store — the freeze's does), not "go with it".

**What changes on the wire — see item 4, row 1.** The serve-credit
admission verifier derives `R_k` from the frozen-segment registry today
(`blockchain.cpp:5099-5121`); retiring the freeze retires that
derivation, so the pass record's signed message and its consensus rule
change. That is item 4's consensus row and E4's landing; this ruling
does not claim wire invariance.

**Reversion.** No reversion criterion beyond Q6's own: the only
consumer that could need a *range-level* commitment the per-tx rows
cannot supply would be one that must check "these transactions are
exactly shard `k`" without deriving it — and under F32 that derivation
is a binary search over `b_*`, so the criterion is vacuous by
construction and is recorded as such rather than dressed as a
falsifier.

---

## 3. Adversarial work required before any `PDM-Q*` ruling is recorded

Named so they cannot be discovered after a ruling. Not answered here.

**Status and owner (added 2026-09-17, `4bc378d68`; walked the same
day).** Q6 is the critical path, and its ruling is "a transcription of
F13/F14/F17 against these six items" — so the *walk of the six against
the tx-range unit* is the actual gate on Q6, not the transcription.
Owner for every row is **steering (the ruling pass)**; a row cannot be
closed by a code lane. The walk was taken by steering on 2026-09-17
against the design as it stands — tx-range unit, two hash rows, uniform
`W` (*the body horizon since 2026-09-22*), wallet-fronted serving,
three-band sync, `D_max` — positioning `T`
before saying what `T` gains. (The walk was taken with *daemon retention
exceptions* in the design; Q9 on #775 removed them and nothing in the six
dispositions depended on their being on the daemon rather than in the
wallet-side store.) The record's §3 carries each original question and
the walk under it; this table is the disposition. **A "DISCHARGED" here is a steering
disposition on the design's *shape*; it is not a `PDM-Q*` ruling, and
the conditions named on each row are owed to the questions named.**

| Item | Walked? | Disposition (2026-09-17) | Owes |
| --- | --- | --- | --- |
| Withholding | Yes | **DISCHARGED** on four properties: request indistinguishability, requester anonymity, per-tx verify, timeout = miss. Collapses to unreliability, which the m-of-n window prices | Per-shard detection latency on a large holder → the credit wire's draw design; honest-P-behind-flaky-Tor false positive → Round-2 numerics |
| Free-riding in the free regime | Yes | **DISCHARGED on the ruled bootstrap subsidy** (`DESIGN_CONCEPTS.md` Component 4 / `ECONOMY_EXPLAINED.md` Loop 4): the free regime is the window the staker emission share exists for; favouring early adopters is the intent; a bond releasing before scarcity is the subsidy working, and re-bonding at scarcity is the market's test. The `bond_duration(0) · SEB ≥ W` condition first written here is **WITHDRAWN** (steering, same day); arithmetic kept as record on the bullet | Nothing on `bond_duration` vs `W`. Q2 states `W` and names the regime's market behaviour as *bootstrap* |
| Eclipse and fetch | Yes | **DISCHARGED.** Running node inside the body horizon (*re-keyed 2026-09-22 from "under `W`"*): never fetches to verify — identical to today. Band-2 syncer: anchor below `C`, PoW + verified bodies over Tor from the bond table above; residual is nuisance (wasted egress, tip lies) and already P2P-2's | Nothing PDM-shaped |
| Stripe / shard interaction | Yes | **DISCHARGED conditional** on Q6 item 3 and F17 naming **one unit**: whatever the wire echoes as holdings commits `T` to the same unit the bond names and the challenge draws from | Q6 item 3 / F17 one-unit requirement |
| Sybil economics | Yes | **Economics DISCHARGED, no residual**, on the **self-diluting scarcity reward** — `scarcity(s,E) = (1/R_market(s,E)) · g(age)`, [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) channel 1 — which makes same-shard Sybil and inefficiency the same act. **Correlated-failure residual DISCHARGED conditional** on Q9 ruling the coverage floor *structural* (Foundation / explorers holding `CompleteTree`, Foundation work outside `Σwork`, `:310`) — Q9 is OPEN on that item today | Q9: rule the floor structural, and say it counts **personas**, not hosts (Model D cannot see the difference) |
| Reorg | Yes | **DISCHARGED conditional** on Q11 existing (which is Q11's point): `D_max` caps depth (`CEN-E2`); discard only at the boundary after a shard's freeze epoch, `≥ SEB + 1` blocks deep with `SEB > D_max` (*re-keyed 2026-09-22 from `tip − W`, `W ≥ D_max`*); undo-log floor `≥ D_max` + `PopBelowFloor` (SCW-7); pops within `D_max` re-pool full bodies; trim's leaf reads regenerate from the skeleton (F12) and the `:9361` throw dies with the C++ | The predicate asserted where retirement is decided — S-PRUNE's row (F31), not discovered at revert |

**What falls out across the six that sits in no single item.** Q9's
coverage floor needs to be ruled **structural** and to say it **counts
personas** — a persona count can overstate hosts and Model D forbids
seeing it, which is why a market-derived floor cannot carry the Sybil
residual. (A second cross-cutting output — a `bond_duration` vs `W`
relation for the Round-2 gate — was proposed and **withdrawn** the same
day: the free-regime reward is the ruled bootstrap subsidy, and the
walk had re-derived a constraint against a decided incentive. The
free-riding bullet keeps the record.) Everything else discharges on
properties already in the design, which is evidence the shape is right
rather than a reason to stop checking.

*The six walks in full — positioned `T`, what `T` controls, what `T` gains — are in the record, §3.*

---

## 4. Do not re-derive

Read, cite, build on. A disagreement is a finding, not a premise.

- Genesis-frozen decisions in `principles-and-learnings` and the
  consensus census.
- The retention prune's consensus scheduling and un-journaled deletions
  ([`CONSENSUS_C2_R1_REORG.md`](../completed/CONSENSUS_C2_R1_REORG.md)).
- Segment freeze semantics
  ([`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md)),
  including the §6.2 reversion clause this round is named to discharge
  or refine.
- Challenge / response format and deadline structure
  ([`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md),
  [`ARCHIVAL_RESPONSE_FORMAT.md`](ARCHIVAL_RESPONSE_FORMAT.md)).
- Bond construction and slashing
  ([`ARCHIVAL_BOND_CONSTRUCTION.md`](ARCHIVAL_BOND_CONSTRUCTION.md),
  [`PRINCIPAL_STAKE_LIFECYCLE.md`](PRINCIPAL_STAKE_LIFECYCLE.md)).
- R2 itself, including two-legged necessity. `PDM-Q-F12` is a
  disagreement with R2's premise that leaf discard is scarcity — recorded
  as a finding, per this section's first sentence, not as a re-derivation.
- TJ-F's two faces (soundness test vs type-level "response + `R_k`, no
  store handle").
- TJ's sequencing claim that the pruning *mode* is node-local (Q3
  confirms; it does not get to pretend the claim was never made).

---

---

## 5. Downstream that will be disturbed

Named now so they are not discovered later.

- **`SO-D8`** — settlement writer's production wiring, still OPEN,
  assigned out of [`ARCHIVAL_SETTLEMENT_WRITER.md`](ARCHIVAL_SETTLEMENT_WRITER.md)
  to the credit-wire §5 cutover. Scope addition 2026-09-12
  (`ba4b3c73a`): promote the settlement write path onto `BlockchainDB`.
  **UPDATE 2026-09-16 (`PDM-Q-F26`):** the in-flight re-homing of
  SO-D8/D9 onto `shekyl-chain-rules` (DRS-D12) is the right move; what
  it inherits from this round is (a) the serve-credit tx's prunable
  region is F13's good — the witness pk + signature SO-D8's batching
  puts there is not on an ordinary node below the body horizon (*re-keyed
  2026-09-22 from "below `W`"*), so every settlement
  read must be stated as admission-time or not, and (b) a settlement
  write set landing on the Rust store before Q6 rules fixes by
  construction what a pruned node persists about a serve-credit tx —
  the same ordering that binds DRS-E2 binds its writer. F26 carries
  the detail.
- **`DRS-0` / `DRS-D10`** — redb store port. D10 still reads universally
  at [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) line 310: *All
  non-block-corpus tables must be rebuildable by replaying local blocks
  through `apply_block`*. §11.2 (lines 1088–1123, pinned at `ba4b3c73a`)
  already records that that wording does not hold, and names a
  **node-local by prune policy** group (`txs_prunable`,
  `txs_prunable_tip`, `output_metadata`). Slice A (PR #720, this pin)
  is the cross-check instrument. A pruning design that changes what a
  node retains changes what "rebuildable by replaying local blocks" can
  mean. D10's binding sentence is not this round's to edit; Q1's
  retained set is the input that round will need. Sharper than the
  wording issue: slice A's **class assignments** for the three
  curve-tree tables assume universal leaf retention (`PDM-Q-F11`) —
  `curve_tree_leaves` append-mostly, `curve_tree_layers` and
  `curve_tree_checkpoints` derived *from the leaves*. Those three rows
  are re-graded by the DRS-0 lane once Q1 rules; this charter names
  the dependency and does not edit `class.rs`.
  **UPDATE 2026-09-13 (`4da609cbd`, PR #726):** the DRS lane has since
  stated *how* it will absorb the ruling
  (`DAEMON_REDB_STORE.md:1105-1275`, §11.2 amendment chain): a digest
  cares whether nodes agree, not whether bytes are present, so a
  **uniform** discard yields a floor-defined accumulator and lifts
  exclusions rather than re-pointing them. The handoff is therefore
  **the boundary, not a grade** — the body horizon (Q2, re-ruled
  2026-09-22; was `W`) and Q1's journal horizon —
  and its reopening conjunct *"followed by a node-variable daemon
  discard"* does not fire under Q7/Q8: only the surplus is
  node-variable, and it is outside the digest domain by DRS's own
  definition. F11 UPDATE carries the detail; the same block
  independently confirms F18's `output_metadata` grading (its read
  chain `get_output_metadata → is_output_pruned` has no call site,
  `:1255-1266`).
- **The credit wire** — [`ARCHIVAL_CREDIT_WIRE.md`](ARCHIVAL_CREDIT_WIRE.md)
  prunable-residence row: *Header kept; 3.43 KB countersignature on the
  coinbase-tx prunable side*. If `PDM-Q6` rules that side into the
  archival subject, `CR-D2` reopens and the carrier decision changes.
  Second point of contact (Q6 item 3): §3's `transfer_digest`
  rejection rests on *"admission could never reconstruct the signed
  message"* — true of off-chain shard bytes, not of a digest over
  retained `txs_prunable_hash` rows. Q6 says whether that reopens.
  Read §2's deletion surface before citing anything leaf-shaped from
  [`ARCHIVAL_PER_CHALLENGE_RECORD.md`](ARCHIVAL_PER_CHALLENGE_RECORD.md):
  `PC-D1`…`PC-D7` are RULED and the leaf-opening cluster they hardened
  is on that surface (`RF-D8` (i) retracted 2026-08-26).
- **`LV-` / P2P-2 (`PWC-`) — the skeleton block payload** (`PDM-Q-F28`,
  2026-09-16). `tx_blob_entry { blob, prunable_hash }` and its
  KAT-pinned Rust mirror `shekyl-levin::payload::block::TxBlobEntry`
  carry one txid component; under Q6 item 2 a skeleton needs two. A
  wire-census row and a KAT change, owned there, gated on Q6 item 2.
- **DRS-E6 (`shekyl-chain-rules`)** — `RuleSet` issuance and `ChainView`'s
  surface (`PDM-Q-F27`, `F29`, 2026-09-16): band 1 needs an issued
  below-anchor set or it has no writer under DRS-D12; Q3's instrument
  is the trait having no recorded-body accessor without a row and an
  above-horizon marking (F29 names it "above-`W`"; re-keyed 2026-09-22). Both written to `CHAIN_RULES_CRATE.md` §13 and the
  DRS-E6 row.
- **`tests/unit_tests/tx_prunable_region_sole_occupant.cpp`** — the
  prunable region has exactly one occupant; blob vs re-serialize hash
  paths agree only *positionally*. Read this test before proposing
  anything that adds to or reorders that region.
- **Every leaf-shaped archival ruling** (`PDM-Q-F13` item 4 of Q6) —
  [`ARCHIVAL_RESPONSE_FORMAT.md`](ARCHIVAL_RESPONSE_FORMAT.md) `RF-D1`
  (the 128 B `leaf_bytes` claim) and `RF-D6` (`SHARD_BYTES = 25,992 ×
  128`, `challenge_leaf_index`, `LeafStore::frozen_segment`),
  [`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md)'s
  draw, [`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md)'s
  segment as the unit of holding, and the bond's `holdings` descriptor
  ([`ARCHIVAL_BOND_CONSTRUCTION.md`](ARCHIVAL_BOND_CONSTRUCTION.md) line
  349). All define possession over a good `PDM-Q-F12` shows is not
  scarce. If Q6 rules the prunable region in, the unit of possession
  becomes a transaction's `CtSigPrunable` and the verifier its
  `txs_prunable_hash`; each of those rulings is either re-keyed with
  the unit substituted or reopened. Q6 names which.
- **V11 retention rule** (`db_lmdb.cpp:128-136`) and
  **`txs_pqc_auths`** (`PDM-Q-F14`) — the rule keeps the PQC slice
  because it lacks a hash table. A Q6 ruling that adds
  `txs_pqc_auth_hash` changes what V11 protects and is a schema bump on
  the C++ side that this round does **not** make (`PDM-Q-S0`); it is
  the Rust store's to carry at `DRS-E*`, and slice A's `AppendMostly`
  grade on `txs_pqc_auths` (`class.rs:161`) re-grades with the three
  curve-tree rows. **UPDATE 2026-09-16 (`PDM-Q-F26`):** the Rust store
  has begun carrying the identity without it — `TxIdentity` is
  `{ hash, prunable_hash }` (S-CHAIN-W). The row is requested of the
  DRS-E lane now, on SCW-7's precedent, not at "`DRS-E*`" in general;
  the bijection-gate blocker that made it a second change has expired
  (SCW-11's `RUST_ONLY_TABLES` map).
- **`CURVE_TREE_CLIENT.md` remaining (b)** — store-backed / pruned-tree
  assembly (F5). A PDM ruling that wallets assemble against `R_k` +
  fetched chunks is that item's substrate.
- **Pass-record carrier `CR-D2`** — ~88 GB/year is the ML-DSA-65-only
  *floor*, already corrected in-round to whole-record arithmetic; RF-D6
  refined the kept side. Do not quote 88 GB as the number. Q7's
  "every node prunes" premise is this round's to make true or to
  withdraw from under CR-D2.

---

---

## 6. Findings register

Every `PDM-Q-F*` this contract or the tracking index cites, one line
each; the full text of each is in the record
([`ARCHIVAL_PRUNED_DAEMON_MODE_ROUND.md`](../completed/ARCHIVAL_PRUNED_DAEMON_MODE_ROUND.md) §6,
or the question block named). Grades as recorded there.

| ID | Finding (one line) | Where argued |
| --- | --- | --- |
| F1 | Set-B discard is specified and unbuilt; universal leaf retention is consensus-required at the pin | record §6 |
| F2 | `--no-prune` is documentation for "do nothing" | record §6 |
| F3 | Three live prune paths; none discards curve-tree leaves | record §6 |
| F4 | D10's universal reconstructibility wording already known not to hold | record §6 |
| F5 | Implementation is forbidden in C++ (`PDM-Q-S0`) | record §6 |
| F6 | **RETRACTED** — the launch-state fork; genesis does not precede this design (`S0`) | record §6 |
| F7 | The intermediate-layer prune already runs on every node; leaves are the boundary | record §6 |
| F8 | Q3 is not node-local today: the serve-credit verifier reads leaves (`get_curve_tree_leaf_chunk`) | record §6; Q3 |
| F9 | Silent zero-fill of a missing leaf in the RPC path — fixed PR #733; the RPC path itself was removed 2026-09-18 (`SOK-10` Q7 → A, path-FFI lane) — moot thereafter | record §6 |
| F10 | `trim_curve_tree` reads the boundary chunk on pop; discard floor `≥ D_max` and a defined failure both owed | record §6; Q2, Q11 |
| F11 | DRS-0 slice A's accumulator grades assumed universal leaf retention — handed as the boundary (then `W`; since 2026-09-22 the epoch boundary after the freeze epoch), not re-grades | record §6 |
| F12 | Leaves are a cache of a pure function of the block corpus; set-B scarcity as scoped does not exist | record §6; Q6 |
| F13 | The transaction's prunable region is scarce, original, admission-only and replay-compatible — the good | record §6; Q6 |
| F14 | `pqc_auths` (~60 % of tx bytes) kept only for want of a hash row — the second occupant | record §6; Q6 |
| F15 | The `serve_credit_pruned` self-reference is benign | record §6 |
| F16 | Seven archival journals are node-local, window-bounded in principle, unbounded on disk | record §6; Q1 |
| F17 | The stripe engine's transferable triple partitions F13's good — **"worth taking" REFUTED by Q7** | record §6; Q7 |
| F18 | `scan_outputkeys_for_indexes` is rule-60 residue; `output_metadata` is CACHE | record §6 |
| F19 | The slash log's forward reader is bounded on every path, enforced on none; horizon `tip − (CRB + n·SEB + D_max)` | record §6; Q1, Q11 |
| F20 | Under Q6's unit sync is the read — band 2 only, after the anchor correction | record §6; Q5 |
| F21 | `P` serves from a wallet-side store; serving beyond-window over P2P would unmask the persona | record §6; Q8 |
| F22 | Coinbase `prunable_hash` boundary facts; `txs_pqc_auths` re-grade withdrawn under DRS-0a | record §6 |
| F23 | The checkpoint table is empty; `is_alternative_block_allowed` is cap and anchor in one function | record §6; Q5, Q11 |
| F24 | The universal bytes window had inherited `D_max`; `W` minted as Q2's variable — **`W` RETIRED 2026-09-22** (Q2 re-ruled; the body horizon is the epoch boundary after the freeze epoch) | record §6; Q2 |
| F25 | The `SF-` round closed on the leaf unit mid-round; client survives, codec and `R_k` verify do not | record §6; Q6 item 4 |
| F26 | The Rust store was shaped for one of Q6's two occupants; `pqc_auth_hash` owed on the identity and as a row (landed #768, row #772) | record §6; Q6 |
| F27 | `RuleSet` needs a below-anchor mode — `Trust::BelowAnchor`, confirmed by Q5. **The `Trust` parameter landed 2026-09-20 (E6 slice 3, [`CHAIN_RULES_SLICE_3.md`](CHAIN_RULES_SLICE_3.md) Q1): `validate(…, trust: &Trust)`, carrying `ReleaseAnchors`; the `BelowAnchor` arm is slice 6's, by a second constructor, meaning band 1's skeleton (`:293`)** | record §6; Q5 |
| F28 | Band-1 sync needs both txid components on the wire (`TxBlobEntry`) | record §6; Q5 |
| F29 | Q3's instrument is `ChainView`'s surface — no body accessor | record §6; Q3 |
| F30 | Q11's home is `CEN-E2`; F27 fires both census rows' reopening trigger. **Fired 2026-09-20: E6 slice 3 moved checkpoint state into Rust (`ReleaseAnchors`) and re-keyed CEN-E1, E2 and E5 in the census** — E1 landed (the anchor's rule), E2 subsumed behind the alt view *and* `D_max`'s numeric (slice 9), E5 at writer open | record §6; Q11 |
| F31 | S-PRUNE had no plan doc — skeleton `DRS_E1_SPRUNE.md` | record §6 |
| F32 | Byte-bounded shards over retained length rows — **byte bound SUPERSEDED 2026-09-23 by Q6 item 5 (fixed cardinality `T`; no length rows)**; shard-granular discard stands (Q6 item 3 amendment) | Q6 |
| F33 | PR #775 draws the daemon line; the Q9 candidate rejected; #775's leaf-shaped rows re-key — **discharged 2026-09-18** (#775 landed first; PDM re-keyed its partition row, CT-1 row, route paragraph, decision-log amendment on `docs/pdm-f33-rekey-775`) | record §6; Q9 |


---

## 7. Disposition summary

| ID | Question | State |
| --- | --- | --- |
| `PDM-Q-S0` | Implementation site + genesis sequencing | **RULED 2026-09-12** — after `DRS-E*`; no C++; genesis does not precede this design's implementation |
| `PDM-Q1` | Retained set (layer 0 boundary, F7; widened to leaf derivation inputs, F12; §9 inventory; journal horizon `tip − (CRB + n·SEB + D_max)`, F19) | **RULED 2026-09-18** — §9 graded against the byte-bounded `tx_id` unit: GOOD = prunable region + `pqc_auths` (Q6), discarded per shard (Q2); KEEP-C gains the hash rows (A3) and length rows (A4); CACHE rebuilt by replay from the base (F12/F13, D10); LOCAL-BOUNDED journals retire at F19's horizon — a second horizon beside the body horizon since Q2's 2026-09-22 re-ruling (was "= `W`"; and *corrected 2026-09-22:* `shekyl_archival_failure_window_params` yields only `n`, the horizon function is owed). Both undetermined readers resolved (F18, F19). Owed as implementation: the horizon asserted at the journals' retirement site (FOLLOWUPS) |
| `PDM-Q2` | Trigger, depth, free-regime duration, discard predicate on `eligible_height` (F10); **`W`, the universal bytes window** — floor `D_max`, honest-downtime argument, economic ceiling, candidate F19's retirement floor (~195 days) so bodies and journals retire together (F24); the free regime's market behaviour is **bootstrap** — the ruled staker emission share (`DESIGN_CONCEPTS.md` Component 4) favours early adopters by intent; the `bond_duration` vs `W` relation proposed by the §3 walk on 2026-09-17 is WITHDRAWN the same day, no gate entry | **RE-RULED 2026-09-22 (rule-21 reopen, shape)** — `discard(k) ⇔ current_epoch ≥ close_epoch(k) + 2`: bodies retire at the epoch boundary after the shard's freeze epoch; **`W` retired**; two horizons by design (bodies; F19's journals); `SEB > D_max` asserted at `D_max`'s home and `pop` floored at the highest discarded shard's `close_height`; genesis guard `current_epoch ≥ 2` as a branch; Round-2 gate `n`, `D_max`, `w_launch`; three 2026-09-18 premises refuted in the ruling. *Was:* **RULED 2026-09-18 (shape; numeric PROVISIONAL)** — shard-granular predicate `b_{k+1} ≤ first_tx_id(tip − W) ∧ close_height(k) + SEB < tip` (the `k ∉ exceptions` conjunct struck on #775 / Q9 — no exceptions on any daemon; genesis guard: evaluated only for `tip ≥ W`), asserted at S-PRUNE's per-epoch batch; `W` set by coincidence with F19's journal floor (`CRB + n·SEB + D_max` ≈ 140,720 ≈ 195 days), honest downtime satisfied as a consequence, the day-195 no-scarce-byte cost stated as an argument; every shard has its own `≥ W` bondable-while-universal window; the two-`W` rollout is a bounded Q8 exception; pass records fall under the predicate; item 4 row 1 is a precondition of the first real discard. Numeric to the Round-2 gate with `n`, `D_max`, `W`, `w_launch` (four numerics) |
| `PDM-Q3` | Residual consensus reads after TJ-A; **the instrument is `ChainView`'s surface (F29)** | **RULED 2026-09-18** — Rust: empty by construction (F29, `ChainView` has no body accessor; standing property in `CHAIN_RULES_CRATE.md` §13). C++: the one residual reader is the serve-credit verifier's leaf read (F8; `get_curve_tree_leaf_chunk`, `blockchain.cpp:5099` today) — Q6 item 4 row 1, dies at E4 / S-ARCH, not with the stripe engine |
| `PDM-Q4` | Reconstruction path — collapsed: no chain-following read reaches an archiver for a node with downtime under `W`; the daemon's fetches (band-2 fill, own-exception recovery, history read-back) are all optional; TJ-F rebinds to the per-tx verify (a body-fill read that does not hash to the retained row fails loudly, never skipped) | **CLOSED 2026-09-18, AMENDED 2026-09-22** — downtime tolerance is **one epoch**; beyond it a node rebuilds bodies through band 2 by accepted posture (Q2 premise 3 refuted). Collapsed (F20/F23/F24); TJ-F re-bound to the per-tx verify; the daemon's fetches are episodic and optional (#775). A record |
| `PDM-Q5` | Cold sync and bootstrap — the anchor question: release-carried checkpoint on the `assumevalid` argument, three bands (`≤ C` trusted with the binary; `(C, tip − W]` filled from archivers; above from peers, `W ≥ D_max` per F24); trust-below fallback REJECTED; owes the launch window, the release-gate full-verify step, the JSON-channel deletion, band-2 egress, and the Q11 ordering; **band 1 needs a below-anchor `RuleSet` (F27) and both txid components on the skeleton wire (F28)** | **RULED 2026-09-18, AMENDED 2026-09-22 ×2** — anchor model stands; ~~launch window = first checkpoint release before day ~195, cadence `≤ W`~~ **superseded:** band 2 is `(C, h_scarce]`, non-empty from epoch 2, cadence a cost knob, egress includes every casual return (downtime tolerance one epoch); full-verify a release-flow sentence; band-2 egress a formula; anchor check at `CEN-E1`; Q11 ordering discharged; **`Trust::Full \| BelowAnchor(anchor)` CONFIRMED** — forced by `StoreCannot::RuleSetNotInForce` (`connect.rs:281-329`); **AMENDED 2026-09-22:** `assumevalid = 0` ≡ no anchor ≡ `Trust::Full`, band 1 `∅` at first release; genesis is in no band (defined by the binary, not trusted with it); `BelowAnchor(anchor)` carries `anchor ≥ 1` so "genesis is the anchor" is unrepresentable (E6 lands the refusal with `Trust`) |
| `PDM-Q6` | The prunable region as the archival good; `pqc_auths` second occupant; shard membership (height / leaf-segment / `tx_id` range); leaf→tx unit change (F13, F14, F15, F22); **the store identity carries both occupants' hashes (F26)**; **item 3 names one unit for bond `holdings`, F17's wire echo and the challenge draw alike (§3 stripe/shard walk, 2026-09-17)** | **RULED 2026-09-17 (items 1–3)** — the good is the prunable region + `pqc_auths` for every tx below `W`, verified by `txs_prunable_hash` + `txs_pqc_auth_hash` (item 2 ratifies F26's landed default, #768 merged `398d85e7b`); a shard is a **byte-bounded `tx_id` range** `[b_k, b_{k+1})` closing at cumulative `SHARD_BYTES` over retained per-tx length rows (**item 3 AMENDED 2026-09-18, F32** — fixed `T` superseded; S-CHAIN-W A4 length row owed; discard is shard-granular at `b_{k+1} ≤ first_tx_id(tip − W)`), one unit for bond `holdings`, wire echo and draw; the credit-wire `transfer_digest` collision is **not reopened**. **Item 4 RULED 2026-09-18**: nine-row re-key/reopen table — the serve-credit admission verifier is **reopened as consensus** (the signed preimage derives `R_k` + leaf index today, `wire.rs:345`; lands at E4 / S-ARCH); `challenge_leaf_index` is retired by ruling, live in code, deleted at S-ARCH; `RF-D1`/`RF-D6`/`SF-D8` reopened, `SF-D7`/`SF-D1`/`CR-D2`/`TJ-D` re-keyed. Before DRS-E2's first writer, as F26 required. `TxIdentity` carries both occupants' hashes since #768 (`{ hash, pqc_auth_hash: Option<_>, prunable_hash }` from `Transaction::txid_parts()`, DRS §7.7 items 1–2); the `txs_pqc_auth_hash` **row** landed on PR #772 (S-CHAIN-W amendment A3, DRS §7.7 item 3); the A4 length rows are owed (FOLLOWUPS). Item 4 was OPEN by name until its ruling above |
| `PDM-Q7` | Stripe engine / `--prune-blockchain`; unbonded retention exceptions | **RULED 2026-09-18** — removed completely; nothing of the engine survives as design (F17's "worth taking" refuted: assignment, advertisement and coverage are the bond, the bond, and price); **C++ engine, both flags, and the `pruning_seed` wire field DELETED 2026-09-21** (`feat/pruning-seed-wire-deletion`; the first draft's "dies at `DRS-E*`" misread `S0`, which forbids *implementing* in C++, not deleting — and the wire half did not die with the store; the "send `0`, ignore non-zero" retirement was superseded by deletion once the field was seen to be `PWD-I1`'s shape with eight free marker values against a uniformly-zero fleet), nothing ported into S-PRUNE; `--sync-pruned-blocks` deleted **under Q5's rejection** (trust-the-txid with no anchor); gated by `scripts/ci/check_no_stripe_engine.sh`; `prune_blockchain` REJECTED in the daemon RPC registry (`get_blockchain_pruning_seed` is a core getter, not a method — dies with the engine); RPC seed fields dropped at the cutover's `CORE_RPC_VERSION` bump. **Unbonded retention exceptions PERMITTED** — retention and serving are different acts; a floor, not a hazard |
| `PDM-Q8` | Privacy (density vs query; serve-side uniformity) | **RULED 2026-09-18** — serve side as ruled 2026-09-13, strengthened by #775 (no serving state on any daemon; all daemons prune); fetch side closed by citation: Tor client with no address (`SF-D3`), test-is-a-read indistinguishability (`ARCHIVAL_CHALLENGE_MECHANISM.md` §9; `SF-D5`/`SF-D8`; `SF-D10` draw), the persona never fetches — its daemon does, episodically; ~~two-`W` rollout the one bounded exception~~ VOID 2026-09-22 (no `W` to roll; Q2 re-ruled) |
| `PDM-Q9` | Archiver's retention set: source, binding, lapse, coverage floor, recovery fetch | **RULED 2026-09-18 on #774, adopting #775's criterion (`PDM-Q-F33`; #775 OPEN at ruling, landed `e685ef1cd` before #774 — F33's re-key done by PDM, `docs/pdm-f33-rekey-775`)** — the daemon holds archival *consensus* state only and **no serving state, ever**; all daemons prune uniformly. **The daemon-storage candidate is REJECTED and withdrawn.** Binding: nothing (wallet holds bond + store); RPC: none new (`get_prunable_range` withdrawn); lapse: the wallet-side store's (#775 FOLLOWUPS row); floor: Foundation `CompleteTree` behind a persona, structural, counts personas; recovery: episodic daemon fetch, retains nothing; advertisement: none. **The specified-to-scarce window is when the wallet fills its store from the local daemon.** #775's leaf-shaped rows re-keyed under Q6/Q12 by PDM (F33 discharged 2026-09-18) |
| `PDM-Q10` | RPC contract for "not retained" | **RULED 2026-09-18** — no new RPC: "not retained" is `get_transactions`' existing split form (`methods.rs:552-605`) with `prunable` empty, hash rows present, `pruned_flag` set — identical on every daemon; discarded and never-held are one state (F32); the wallet-side store answers the onion, the daemon answers its operator |
| `PDM-Q11` | `D_max`, the consensus reorg cap — the one constant F10 (Q2), F19 (Q1) **and the store's undo-log retention (S-CHAIN-W SCW-7, 2026-09-15: retention ≥ `D_max`)** all derive from; home is `is_alternative_block_allowed` above the checkpoint — census row **`CEN-E2`** (F30; `CEN-E1` is the equality rule, the band-1 trust assertion) — so the checkpoint (Q5) is its precondition; not archival-scoped, carried here until ruled | **RULED 2026-09-17** — shape frozen (a *detectability boundary*, home `CEN-E2`, the anchor a precondition), **numeric `720` PROVISIONAL** on the `bond_duration` precedent with the two shallower arguments recorded beside it, re-pinned at the Round-2 gate with `n`, `W` and `w_launch` (four numerics; `w_launch` joined 2026-09-18); the owner ask is discharged by the ruling itself; `CEN-E1`/`CEN-E2` re-key still owed in F27's PR (F30) |
| `PDM-Q12` | The freeze pipeline and the wallet-side `LeafStore` under Q6's unit — does the freeze retire when the commitment exists at ingest; `LeafStore` as deletion target (F21) | **RULED 2026-09-18, amended the same day on #775 (Q9 RULED; the conditional is discharged)** — the freeze retires (commitment exists at ingest; membership derivable, F32), not a migration; dependents re-point to the **wallet-side store rebuilt around bodies** (the daemon holds no serving state); `LeafStore`'s leaf-shaped internals (`open_frozen_segment_body`, `ServingReader`, `FrozenSegmentPruned`), `segment_freeze.rs`, the freeze half of `challenge.rs`/`path.rs` are a Rust deletion surface at E4 / S-ARCH — **the store itself is rebuilt, not deleted**; `StoreShardProvider` keeps reading it; `get_prunable_range` withdrawn; the C++ freeze symbols die at `DRS-E*` under Q7's precedent; no wire-invariance claim — the verifier change is item 4 row 1; no reversion criterion beyond Q6's own |

When this round proposes a test, it will name the edit that makes that
test red. A red test that cannot be made red by a specific edit is not
a test (rule 50 / the opening prompt).

---

---

## 8. What carries on past the round

**Third pass, same day — the round closes on the design side.** PR #775
(`PDM-Q-F33`) drew the daemon line and **Q9** is ruled on it: the
daemon-storage candidate is REJECTED and withdrawn, the wallet-side store
is the archiver's, the daemon retains nothing durable, and the
specified-to-scarce window is when the wallet fills its store from the
local daemon. That forced amendments to Q2 (no exceptions conjunct — all
daemons prune), Q7 (unbonded retention in the wallet-side store), Q12
(`LeafStore` rebuilt, not deleted; `get_prunable_range` withdrawn) and
F32. **Q1, Q3, Q5, Q8, Q10 RULED and Q4 CLOSED** as transcriptions of
what was already landed, with three corrections made at source before
writing: Q10 has no typed refusal (discarded and never-held are one
state; the existing split read is the contract), Q3's C++ residual is the
serve-credit verifier and dies at E4, not the stripe engine at `DRS-E*`,
and Q8's fetch half cites §9 of the challenge mechanism, not `SF-D10`,
for indistinguishability. **Q5's one confirmation** — `Trust::Full |
BelowAnchor(anchor)` — is forced by `StoreCannot::RuleSetNotInForce`.
**Every `PDM-Q*` is now RULED or CLOSED.** What carries on past the
round, by owner: **the wallet lane** — the **archiver serving-store
rebuild** (Q12: `LeafStore` around bodies — fill-from-daemon in the grace
window, verify-on-fill **against the txid** (`WSS-Q5`, 2026-09-19),
shard-keyed, **whole-shard serve** (`WSS-Q7`: `SF-D1` kept the read
whole-shard; it is *verification* that is per-tx),
lapse tail, recovery intake, the Foundation floor), a design round of its
own — **the largest unbuilt thing this charter names**; ~~the lane's active
`CTS-` round (#776) is a leaf-unit shape rewrite and does not yet scope
it (Q12 block)~~ **— DISCHARGED as to ownership 2026-09-18: the round
exists.** [`WALLET_SIDE_STORE.md`](WALLET_SIDE_STORE.md) (family `WSS-`,
registered at birth) is the wallet-side store's umbrella; `CTS-` closes as
record and is partitioned by unit there. Its `WSS-Q1` — one store with two
obligations, or two files — is the axis every one of Q12's unmade decisions
inherits, and it is posed, not yet ruled; **DRS-E** — S-PRUNE's **plan** (the skeleton `DRS_E1_SPRUNE.md` landed; the plan — increment ordinal, Round-0 pre-flight, commit sequence — is still owed, after Q1's
horizon check lands), A3 (#772), A4, the daemon-uniformity constraint in
`DAEMON_REDB_STORE.md` (#775's row); **E4 / S-ARCH** — the serve-credit
verifier re-key (consensus) and the leaf-cluster deletion; **E6** — the
`Trust` mode and the `CEN-E1`/`E2` re-key; **the reward leg** — the
in-window commitment weight and `w_launch`; **`LV-`/`PWC-`** — the
skeleton wire field (F28) (the `pruning_seed` deletion under Q7 is done, 2026-09-21);
**`RK-`** — the two REJECTED methods; **RF-/SF-/TJ- lanes** — item 4's
line-local re-keys; **#774 / #775** — the mutual re-key (F33); **Round-2**
— `n`, `D_max`, `w_launch` (`W` left the gate 2026-09-22). **Steering** — archive-or-contract for
this document (rule 95): it is the design home TJ-D named and it now
holds twelve rulings; whether it flips to `LIVING CONTRACT` or a
contract-of-record is extracted and the round archived is the last
decision the round itself does not make.

---

---

## 9. Data-element inventory at the pin (`edb35dbb1` + this round's reads)

The pass the user asked for: every element that reaches the chain
store, graded on two axes — **derivable?** (F12's test: a pure
function of bytes a pruned node keeps) and **read after admission?**
(by consensus, by wallets, by nothing). Classes:

- **KEEP-C** — consensus reads it after admission. Universal. Not
  negotiable by this round.
- **KEEP-W** — consensus does not need it after admission; **wallets
  do** (restore-from-seed scans every output ever). Universal unless a
  ruling gives wallets an archiver-served path — which is Q5's
  centralisation question wearing a different costume. Default KEEP.
- **KEEP-D** — derivation input for a `Derived` / `CACHE` table under
  D10's replay premise. Kept because dropping it makes something else
  unrebuildable.
- **CACHE** — pure function of KEEP-C/KEEP-W/KEEP-D bytes. Discard is a
  performance choice, never scarcity (F12). Q1's rows.
- **GOOD** — original, non-derivable, admission-only, hash-committed.
  The archival subject candidate (F13, F14). Q6's rows.
- **LOCAL-BOUNDED** — node-local; readable only within a window
  (reorg, retention, tip). Retire on the window; never scarce (F16).

Sizes are per unit at the pin; the transaction figures are
`FCMP_PLUS_PLUS.md` §13's 2-in/2-out budget (~17–18 KB), which does
**not** itemise the `0x06` KEM ciphertexts (1120 B/output,
`POST_QUANTUM_CRYPTOGRAPHY.md:153`) — they are in the prefix and are
added here. "Readers" lists post-admission readers only; every element
is read at admission.

### 9.1 The transaction (the block corpus, `blocks` + `txs_*`)

| Element | Wire home | Store home | Bytes (2-in/2-out) | Post-admission readers | Derivable from | Class |
| --- | --- | --- | ---: | --- | --- | --- |
| prefix: `version`, `unlock_time`, `vin` (key images, archival vins), `vout` (`O`), `extra` sans `0x06`/`0x07` | tx prefix | `txs_pruned` | ~0.5 KB | consensus (key images → `spent_keys` rebuild; archival vins → archival tables rebuild; `RF-D1` kept vin read by settlement / slash), wallets | — (original) | KEEP-C |
| `tx_extra` `0x07` PQC leaf entries (`CM ‖ record`, `PL-D3`) | prefix | `txs_pruned` | 64 B/output | replay (`blockchain_db.cpp:528-557` → leaf) | — | KEEP-D |
| `tx_extra` `0x06` hybrid KEM ciphertexts | prefix | `txs_pruned` | 1120 B/output (~2.2 KB) | wallets only (scan / restore) | — | KEEP-W |
| `CtSigBase`: `type`, `txnFee`, `referenceBlock`, `enc_amounts`, `enc_labels`, `outPk` | ct base (`ct_types.h:197`) | `txs_pruned` | ~256 B | replay (`outPk` → commitment → leaf, `:597`; fee → burn / emission), wallets (`enc_amounts`, `enc_labels`) | — | KEEP-C / KEEP-D |
| `pqc_auths` (hybrid pk + hybrid sig per input) | between base and prunable (`cryptonote_basic.h:492`) | `txs_pqc_auths` | ~5.3 KB/input (~10.6 KB) | **none** — every reader is in `check_tx_inputs` (`blockchain.cpp:3717-4351`); txid uses only `pqc_auth_hash` | — (original) | **GOOD** candidate (F14) — needs a 32 B hash row it does not have |
| `CtSigPrunable`: `bulletproofs_plus` | prunable (`:349`) | `txs_prunable` | ~1.5 KB | none; hash in `txs_prunable_hash` | — (witness gone) | **GOOD** (F13) |
| `CtSigPrunable`: `fcmp_pp_proof` + `curve_trees_tree_depth` | prunable (`:367`) | `txs_prunable` | ~2.5 KB/input (~4.5 KB) | none; hash in `txs_prunable_hash` | — (witness gone) | **GOOD** (F13) |
| `CtSigPrunable`: `pseudoOuts` | prunable (`:384`) | `txs_prunable` | 32 B/input | none | — | **GOOD** (F13) |
| `CtSigPrunable`: `serve_credit_pruned` (RF-D1 pruned half: ML-DSA leg + `path` incl. the leaf chunk) | prunable (`:402`) | `txs_prunable` | ~9,965 B per serve-credit vin (`ARCHIVAL_RESPONSE_FORMAT.md:78-81`) | none (`blockchain.cpp:3807` is admission; F15) | — | **GOOD** (F13, F15) |
| `txs_prunable_hash` | — | `txs_prunable_hash` | 32 B/tx | txid recompute (`get_pruned_transaction_hash`); **the GOOD's verifier** | H(prunable) — but only if you hold the prunable | KEEP-C |
| `pqc_auth_hash` | — | **no table** (V11: *"neither has a hash table"*) | 32 B/tx if minted | would be `txs_pqc_auths`'s verifier | H(pqc_auths) | Q6 item 2 |
| `tx_indices` (hash → id, height, unlock) | — | `tx_indices` | ~56 B/tx | consensus (tx lookup, reorg), RPC | rebuild from `blocks` | CACHE (kept; index) |
| `tx_outputs` (tx → global output indices) | — | `tx_outputs` | 8 B/output | reorg pop (`remove_output`), RPC | rebuild | CACHE |
| `txs` (inherited) | — | `txs` | 0 (unused at v3; `Excluded`, `class.rs`) | none | — | deletion target (rule 60), not this round's |
| ~~`txs_prunable_tip`~~ | — | — | — | inherited stripe engine only; write-never after Q7 (2026-09-21), **table DELETED 2026-09-22** (LMDB v15 / redb v10) | — | — |

Totals for the 2-in/2-out transaction, at the pin: **~20 KB on the
wire; ~3 KB is KEEP-C/KEEP-W/KEEP-D (prefix + base + KEM ct + leaf
hashes); ~6 KB is GOOD today (the prunable region); ~10.6 KB is GOOD
pending a hash row (F14).** A ruling that takes both GOOD rows retains
~15 % of transaction bytes universally.

### 9.2 Per output — the derived layer (all CACHE under F12)

| Table | Bytes/output | Post-admission readers | Derivable from | Class |
| --- | ---: | --- | --- | --- |
| `curve_tree_leaves` | 128 | serve-credit verify **today** (`blockchain.cpp:5327`, F8 — goes with TJ-A); `trim_curve_tree` boundary chunk on pop (`:9361`, F10); RPC `shekyl-fcmp::rpc_path` | `O`, `C`, `CM` → `shekyl_construct_curve_tree_leaf` (`blockchain_db.cpp:608`) | CACHE (F12) |
| ~~`output_metadata`~~ (**DELETED 2026-09-22**, LMDB v15 / redb v10 — the C++ tx-data prune's scan cache; the retained prefix carries what a scanner needs) | 80 | none in consensus — `scan_outputkeys_for_indexes` deleted with `check_tx_input` (`PDM-Q-F18`); RPC `chunk_outputs` via `shekyl-fcmp::rpc_path` | `vout` + `outPk` + block height | CACHE (`Excluded` in slice A, `class.rs:149`) |
| `output_txs`, `output_amounts` | ~40, ~48 | reorg pop, RPC | rebuild | CACHE |
| `output_to_leaf`, `leaf_to_output` | 16, 16 | leaf ↔ output mapping on pop and RPC | rebuild (insertion order) | CACHE |
| `pending_tree_leaves`, `pending_tree_drain`, `block_pending_additions` | 128 + index, transient | maturity drain at unlock height (consensus) | rebuild from `unlock_time` | KEEP-C while pending; self-bounding (empties at maturity) |

### 9.3 Per block and per input — consensus state that is not a cache

| Table | Bytes/unit | Post-admission readers | Derivable | Class |
| --- | ---: | --- | --- | --- |
| `blocks` (header incl. `attestation_root` + miner tx + tx hashes) | ~0.3 KB + miner tx (KEM ct per coinbase output) | PoW / difficulty window, reorg, sync serving, replay root | — | KEEP-C |
| `block_info`, `block_heights` | ~100, 40 | difficulty, cumulative weight, hash → height | rebuild from `blocks` | CACHE (kept; index) |
| `spent_keys` | 32 B/input | **every** FCMP++ input check (double spend) | rebuild from `vin` | KEEP-C — the one permanently unbounded set; not prunable at any depth |
| `curve_tree_roots` | 32–64 B/block | every FCMP++ proof verify (`referenceBlock` → root) | rebuild from leaves… which are CACHE — root chain must stay | KEEP-C |
| `curve_tree_layers` layer 0 (`R_k` chunks) | 32 B/chunk | recompose on trim (F7); TJ-F verify target | recompute from leaves (CACHE) — kept as the set-A boundary | KEEP-C (set A) |
| `curve_tree_layers` layers 1..depth−2 | 32 B/chunk | none after seal | recompose from layer 0 | CACHE — **already pruned** by every node (`prune_curve_tree_intermediate_layers`) |
| `curve_tree_meta`, `curve_tree_checkpoints` | small | trim, integrity check (`Derived`, F11) | from leaves (F11) — re-grade | CACHE / KEEP-C (root layer) |
| `block_burn` | 8–16 B/block | emission / burn accounting | rebuild from fees | CACHE (kept; small) |
| `hf_versions`, `hf_starting_heights`, `properties` | small | consensus versioning, receipts (V12 prune watermark) | — | KEEP-C (constant size) |

### 9.4 Archival / staking state (the 18 `archival_*` tables + `block_burn`)

Everything here is **populated from kept prefix bytes** (archival vins
are opaque canonical blobs in the tx prefix, `cryptonote_basic.h:190`,
`:257`, `:288`) and is therefore rebuildable by replay from the pruned
corpus. Nothing here is GOOD; the question is only which rows a node
must keep to *verify new blocks* versus which it may retire.

| Table | Class (slice A) | Post-admission readers | Bounded by | Class (this round) |
| --- | --- | --- | --- | --- |
| `archival_bond` | SetShaped | every bond / challenge / settlement / slash rule (live bond set) | live bonds | KEEP-C |
| `archival_shard_segment` | SetShaped | freeze pipeline, challenge target (`R_k` per shard) | segments ever frozen | KEEP-C (unit changes if Q6 rules the good is transactions — §5) |
| `archival_slash_applied` | SetShaped | slash dedupe | slashes ever | KEEP-C |
| `archival_serve_credit`, `archival_settlement`, `archival_r_market`, `archival_sigma_work`, `archival_budget`, `archival_budget_accrual`, `archival_attestation_witness` | Small | settlement / epoch close within `W` | **retention prune at `tip − W`** (`db_lmdb.cpp:7704-7739`, un-journaled) | LOCAL-BOUNDED — already retired; nothing owed |
| `archival_alt_attestation_witness` | Excluded | alt-chain reconnect | alt blocks | LOCAL-BOUNDED (alt) |
| `archival_bond_unbond_log`, `archival_bond_holdings_update_log`, `archival_bond_reinstate_log`, `archival_emission_claim_log`, `archival_epoch_close_log` | AppendMostly | pop path only (`revert_*_at_height`) | **nothing today** | LOCAL-BOUNDED in principle (reorg window); unbounded on disk (F16) — Q1 |
| `archival_slash_log` | AppendMostly | pop path + `archival_slash_removed_holding_after` (`:5243`, scans above `at_height`); `at_height = h_fire` on both entry paths, bounded by credit deadline / watermark + window, not by a check (F19) | **nothing today** | LOCAL-BOUNDED — horizon `tip − (CRB + n·SEB + reorg)`, minted with its check (F19) — Q1 |

### 9.5 Node-local, never chain state

`alt_blocks`, `txpool_meta`, `txpool_blob` (all `Excluded`). Bounded by
their own eviction. Not this round's.

### 9.6 What the inventory says

1. **The only scarce goods at the pin are the transaction's prunable
   region and — pending a 32-byte hash row — its `pqc_auths` slice.**
   Together ~85 % of transaction bytes. Everything else is either
   consensus-required forever (`spent_keys`, roots, headers, the
   prefix), wallet-required (KEM ciphertexts), a derivation input for
   the tree (`0x07`, `outPk`, `vout`), or a cache.
2. **Nothing in the archival / staking *tables* is prunable in the
   scarcity sense**, and nothing there needs to be: the seven
   window-bounded tables are already retired by the retention prune,
   the three set-shaped tables are live consensus state, and the seven
   journals (F16) are node-local with a window nobody has yet applied.
   The archival domain's bytes are in the **transaction**: the pass
   record's pruned half is ~10 KB per serve-credit vin against ~230 B
   kept (`RF-D1`), which is `CR-D2`'s ~88 GB/yr floor — and under F13
   that stream is GOOD, not overhead. The archival system's own
   evidence is the bulk of what it sells (F15 says that is benign).
3. **The one permanent, unbounded, unprunable table is `spent_keys`**
   — 32 B per input, forever, on every node. Any storage projection
   that omits it is wrong; any pruning design that touches it breaks
   double-spend detection.
4. **Discarding the derived layer (§9.2) saves ~340 B/output against
   ~1.3 KB/output of bytes that regenerate it.** It is a cache policy
   (Q1) and buys no scarcity (F12). Whether a pruned node keeps
   `curve_tree_leaves` is a latency question about spend-path
   assembly and TJ-A's verify path, not a product question.
