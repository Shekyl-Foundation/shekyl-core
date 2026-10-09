# The settlement writer — design round (SO)

**Status:** OPEN — round opened 2026-08-23. `SO-D1`…`SO-D5` **RULED**;
**`SO-D6` CLOSED 2026-08-24** by grounding (recompute, no alt twin — the
mechanism is named, not just leaned toward); **`SO-D7` CORRECTED 2026-08-24 —
it re-derived a constraint the tree already enforced**; **`SO-D8` OPENED** and
assigned out of this round. **`SO-D10` RULED 2026-10-08** — the writer's
wiring ahead of the secret draw, §14.

**Implementation began 2026-08-24 and the first hour changed two dispositions.**
That is the intended use of the round, not a failure of it: the ruling that the
irreversible surfaces get design-first and the reversible ones get built and
pivoted is what made cutting the writer the right next move. §12 records what
contact with the code did to each disposition.

**Unblocked by** — all four upstreams are closed, which is why this round can
open now rather than wait:

| Upstream | State |
|---|---|
| Derivation granularity (fork §7.1) | **RULED 2026-08-10** — exact-min urn |
| Settlement threshold (§4.4) | **RATIFIED 2026-08-11** — absolute-2 |
| Pass-record carrier | **RULED 2026-08-18** (`ARCHIVAL_PASS_RECORD_CARRIER.md`) |
| Response format (`RF-D1`…`RF-D10`) | **LANDED 2026-08-21**, PR #522 |

**Freezes:** consensus-visible settlement semantics and a new LMDB table.
Pre-genesis, so the table is not a migration — but the *semantics* it records
are what the outer window slashes on, and those are frozen.

**Process:** [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc).
Disposition IDs **`SO-D1` … `SO-Dn`**, registered at birth per
[`94-tracking-index`](../../.cursor/rules/94-tracking-index.mdc). Prefix `SO-`
checked unique against CB/CR/CT/CW/DS/GF/LV/MR/MS/MSW/OA/PF/PR/RP/RF/SA/SH/SP/
TJ/VG/WI/WP/WS. **`SO` rather than `SW`** — `SW`/`WS` are transpositions of each
other and `WS-1` is a live constraint id; a prefix a reader can mis-key is a
prefix that eventually indexes the wrong round.

---

## 1. The inputs, verified at source

Grounded on `dev@cbba3e261`, 2026-08-23. Every row was read, not recalled.

| # | Input | Where it is settled | Verified at |
|---|---|---|---|
| 1 | New table, never a widened bit | `ARCHIVAL_CHALLENGE_MECHANISM.md` §4.3 | four presence-reading consumers, §1.1 below |
| 2 | Three-valued: Served / Missed / NonObservation | §4 | `attestation.rs:142` `settle_epoch(passes, issued)` |
| 3 | Absolute-2; row keys on **issued**, not drawable | §4.4, ratified 2026-08-11 | `attestation.rs:142` |
| 4 | Absent-row ⇒ non-observation ⇒ not-drawable | §4.2 | *conditional in §4.2 — resolved by `SO-D1`* |
| 5 | Expiry ⇒ miss | fork §7.3, closed 2026-08-08 | §7 preamble |
| 6 | Urn state derives, never stores | §7.1 + `ARCHIVAL_CREDIT_WIRE.md` §3 | §7.1 "urn bookkeeping" |
| 7 | Prune horizon ≥ window | `failure_window.rs:90–124,178–210` (re-anchored 2026-09-13, SO-D5 discharge) | const-assert present; names both failure directions |

### 1.1 Why the existing table cannot be widened (re-verified, not inherited)

§4.3 rules it out "by construction, not convention". The construction is four
consumers that read **key presence** as "served", so any key written for any
reason becomes a serve credit:

- old-vin dedup — `blockchain.cpp:5351`, `archival_serve_credit_pass_count > 0`
  (pair-epoch-wide over the 48-byte prefix since `PC-D4`)
- slash-window walk — `db_lmdb.cpp:5908`, the same prefix count per epoch
- fast-path miss check — `db_lmdb.cpp:5940`, the same prefix count
- emission gather — `db_lmdb.cpp:8134`, a **pure presence cursor-walk**
  (no value-byte gate) folding per-challenge rows to one credit per
  pair-epoch (`PC-D6`) and feeding `r_market`/`σ_work`

The table's own declaration states the shape it can never carry more than:
`m_archival_serve_credit` is `P_id[32]‖BE(shard)‖BE(E)‖BE(height)` (56 B,
`PC-D4`) → `uint8_t 0x01` (`db_lmdb.h:922`). Writing a **Missed** cell there
corrupts vin-dedup and emission simultaneously — presence under the pair-epoch
prefix means pay, whichever block's key carries it — a settlement outcome and
a payment authorisation would share a key space where presence means pay.

**This is not a "keep them separate for tidiness" argument.** The two tables
answer different questions and one of them is a *negative*: a table whose
presence semantics are "pay this pair" structurally cannot also record "this
pair failed". The ruling stands as written.

---

## 2. What `RF-D10` actually changed — the budget, re-derived

§4.4 says the under-issuance branch "becomes live only in the capped regime
(`k_cap` binding …), i.e. **only if the tx-carrier prunable-residence work does
NOT land**." That work landed as `RF-D10` (PR #522). So the branch's own stated
trigger has resolved, and this round must say which way — because the schema
differs between the two regimes.

**It does not resolve cleanly, and the reason is worth stating: `RF-D10` moved
the binding axis rather than removing it.** Three axes, each recomputed here
from landed figures rather than carried:

| Axis | Before `RF-D10` | After `RF-D10` | Direction |
|---|---|---|---|
| Permanent chain storage / record | 3,430 B (all kept) | **99 B kept** | **34.6× better** |
| Bytes relayed + verified / record | 3,430 B | **5,204 B** (99 kept + 5,107 pruned) | **1.52× worse** |
| Block occupancy at `k = 30` | 103 KB | **156 KB** | **worse** |

Sources: 3.43 KB/record and the chain-growth finding, `FOLLOWUPS.md` §"ADDITION
FROM CHECKING IT"; 99 B kept / 5,107 B pruned / ≈5,204 B record, the `RF-D10`
row in `IMPLEMENTATION_INDEX.md` and `SERVE_CREDIT_PRUNED_MAX_BYTES`
(`ct_types.h:318–321`).

**The record got bigger and the chain got smaller** — because `RF-D8` ruling
(i) kept the ~1,920 B opening *additively*, and `RF-D10` put the 5,107 B
countersignature half on the prunable side. Both are correct and they push
opposite ways.

> **SUPERSEDED IN ITS FIRST HALF — `RF-D8` (i) was RETRACTED 2026-08-26
> (recorded here 2026-09-11, so this paragraph stood on a withdrawn premise
> for 16 days).** The opening does not survive, so "the record got bigger"
> no longer holds: the record is ~3,411 B, not ~5,331 B, and every figure
> below derived from the ~1,920 B opening — including §2.1's arithmetic
> — wants re-deriving before anything is sized against it. `RF-D10`'s half
> is untouched. The two-forces framing survives; only the first magnitude
> falls. Kept rather than recomputed in place, because this section is the
> record of what the round priced, and a silently updated number would make
> the round look like it had foreseen the retraction. Restating the second row as "prunability fixed `k_cap`" would be
true only on the axis that stopped binding.

### 2.1 The arithmetic, with `SEB = 10,000` (`constants.rs:202`)

At 2-minute blocks, one epoch = 13.9 days and a year is 26 epochs ≈ 260,000
blocks — the figures `FOLLOWUPS` uses.

*Chain-growth axis.* The old ceiling that produced `k_cap = 30` was 26.7 GB/yr
of retained signature data (3,430 B × 30 × 260,000). At 99 B kept, that same
annual budget admits **k ≈ 1,040**. On this axis `λ_eff = min(3,
k_cap·SEB/D) = min(3, 32.1) = 3` even at the TJ-extreme `D ≈ 324,000` —
**10.7× headroom. The chain-growth ceiling is genuinely gone.**

*Block-occupancy axis, which now binds first.* `λ_target = 3` at `D` needs
`k = 3·D/SEB`:

| Regime | `D` | required `k` | block occupancy @ 5,204 B | vs 300 KB free-reward zone |
|---|---|---|---|---|
| Genesis-era | ~4,096 | **2** | ~10 KB | 3 % — free |
| Mid | ~100,000 | **30** | 156 KB | 52 % — free |
| Maturity (TJ extreme) | ~324,000 | **98** | ~506 KB | **1.7×** — penalised |

`CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 = 300000`
(`cryptonote_config.h:58`) is a **penalty threshold, not a hard cap** — so
maturity-scale exact coverage is an *economic* cost (a standing block-reward
penalty), not an impossibility. That is a materially different finding from
"the mechanism does not scale past ~10⁵ pairs", and it is better news, but it
is not "the budget is solved".

*Bandwidth axis.* Unmeasured. `FOLLOWUPS` closes the prunability item with
"`k_cap` is bandwidth-bound rather than chain-growth-bound, and both PR gates
reduce to the one real measurement: the PoW-enabled rig run." That run has not
happened. **This round does not need it** — see `SO-D1`.

### 2.2 The finding that decides the schema

> **Exact coverage is free at genesis and priced at maturity. It is therefore
> not an invariant the storage layer may assume.**

§4.2 offers two branches — assume exact-3 and get absent-row ⇒ non-observation
"by construction", or enumerate and write a row per pair. The first branch is
conditioned on a property that holds today and degrades continuously as `D`
grows, with no discrete event marking the crossing. A storage invariant whose
truth depends on an unmeasured axis and a reward-penalty trade-off is an
invariant that will be false in production before anyone notices.

**This is the same class as the `RF-D7` finding** (a bound "held by
circumstance" having no name and no test) and `RF-D5`'s validated-predecessor
constraint. The fix is the same shape: state it as a constraint on the writer,
not as a property of a regime.

---

## 3. `SO-D1` — RULED: the writer enumerates the issued set and writes one row per issued pair

> **Specification:** [`ARCHIVAL_SERVE_CREDIT_SPEC.md`](ARCHIVAL_SERVE_CREDIT_SPEC.md) §9.2–§9.3 and §10. "Issued" means revealed; the writer reads the stored issued-draw index and selects each pair's three counted draws by beacon. "The writer enumerates; it is not record-driven" is this ruling's and stands.

**The forcing case is a drawable pair that passes nothing.** All three of its
challenges expire; expiry ⇒ miss (fork §7.3); the epoch settles **Missed**. And
there are **zero on-chain artifacts** — no pass record, no vin, nothing — to
trigger a write. A writer driven by arriving records writes nothing, the row is
absent, and absence means non-observation. *The pair that failed completely is
the pair that gets the most forgiving settlement.* That is a slash escape, and
it is the exact inverse of the §4.1 bias the drawability relocation fixed.

So the writer cannot be record-driven. It must enumerate.

**Ruled:** when the closing epoch is settled — **inside the slash scheduler's
per-epoch pass**, per `SO-D7` below, not at a separate epoch-close event — the
writer reads that epoch's issued draws and writes **one row per
`(P, s)` with `issued ≥ 1`**, carrying its observed pass count. Pairs with
`issued = 0` are not written.

(This paragraph said "at epoch close" until 2026-08-25. `SO-D7` moved the
timing and this earlier ruling was not moved with it, leaving two
authoritative timings in one record — the reader who stopped here got the
superseded one.)

This is §4.2's second branch, adopted **unconditionally** rather than as the
fallback for a §7.1 variant that did not win. Three reasons, in priority order:

1. **It is the only branch that is correct in both regimes.** The first branch
   is correct exactly when coverage is exact, which §2.1 shows is a
   scale-dependent economic outcome, not a guarantee.
2. **It costs nothing extra at genesis**, where `D` is small — and the maturity
   cost is "the same cardinality the emission gather already walks" (§4.2),
   i.e. a walk the block already performs.
3. **It makes the absent-row invariant total.** With every issued pair written,
   *absent ⇒ no live obligation in E* is a theorem about the writer, not an
   inference about a regime. **UPDATE 2026-09-16 (Q3):** *SUPERSEDED: absent
   ⇒ never issued ⇒ not drawable ⇒ non-observation.* The restated chain
   covers both never-issued and issued-then-exited (a drop or slash whose
   settlement filter writes no row — proposal §7.4). `SO-D5`'s inversion
   (absent ⇒ non-observation ⇒ the denominator shrinks) is unchanged.

**Keyed on issued, not drawable** — §4.4's re-keying, preserved. A drawable pair
the draw never reached is not a pair that failed, and writing it as anything
would be recording an observation that did not occur. The `issued ≥ 1`
condition is where that distinction lives.

**Under-issuance is specified, not assumed away** (§4.4's own instruction):
fewer than 3 issued settles **NonObservation** (specification §9.3), and it
gets a **row** rather than an absence. Absence and NonObservation are then no longer
synonymous — absence means *no live obligation in E* (never issued, or
issued-then-exited; Q3 2026-09-16), a written NonObservation means *issued
but unreachable*. **This is deliberate and it is the auditability argument
winning over absence-consistency:** a regime that degrades silently is one
nobody measures. The row is how the share of pairs the draw did not reach
becomes visible on-chain.

**The writer reads stored state.** The issued-draw index is consensus state,
written at admission and reverted with its blocks (specification §10). A
count that depends on which seeds were revealed is not a function of block
hashes, so derive-don't-store does not reach `issued`.

---

## 4. `SO-D2` — RULED: key and value

> **Specification:** [`ARCHIVAL_SERVE_CREDIT_SPEC.md`](ARCHIVAL_SERVE_CREDIT_SPEC.md) §9.3 item 4. The row's key and three-byte value stand; `passes` counts the selected draws that passed (0 to 3), and `issued` saturates at 255 (`SCS-P8`).

**Key — 48 B, byte-identical in shape to `m_archival_serve_credit`:**

```text
P_id[32] ‖ BE(shard_id)[8] ‖ BE(settlement_epoch)[8]
```

Same shape deliberately: the slash-window walk and the emission gather already
seek on this layout, so a reader holding one key can probe the other table
without re-encoding. Big-endian is load-bearing — it is what makes an LMDB
range scan over `(P_id, shard)` return epochs in order, which is exactly the
outer-window walk's access pattern.

**PC-D4 (2026-08-26):** `m_archival_serve_credit` widened to 56 B
(`BE(block_height)` appended, one row per challenge), so "byte-identical"
expired — the 48-byte shape above survives as `ArchivalPairEpochKey`, now this
table's key type (`ARCHIVAL_PER_CHALLENGE_RECORD.md` §5.2). The
probe-either-table rationale holds as a prefix relation: a settlement key is
byte-identical to a serve-credit key's first 48 bytes, exactly the prefix
`archival_serve_credit_pass_count` counts over.

**Value — 3 B:**

```text
outcome[1] ‖ passes[1] ‖ issued[1]
```

`outcome` ∈ {`0x01` Served, `0x02` Missed, `0x03` NonObservation}. **Not
`0x00`** for any live value — a zero first byte is what a partially-written or
zero-filled cell looks like, and this table's whole job is to make absence mean
something specific.

**`passes` and `issued` are stored, not just `outcome`** — and this is the
round's one forward-looking decision. §7.1's wave-tail analysis states that
under absolute-2 **"the issued-count histogram is an `(m, n)` derivation
input"** (the per-epoch miss rate becomes a mixture). The re-pin is blocked on
a stressnet outage-duration CDF and cannot be derived at a desk; but the
histogram it also needs *is* producible, and this table is its natural source.
**Two bytes now is the only `(m, n)`-serving artifact that can be landed
today.** Deriving `outcome` from the other two at read time was considered and
rejected: the threshold is a consensus rule, and re-deriving a consensus verdict
at every read is how two readers come to disagree.

`issued` saturates at 255 (`SCS-P8`): the byte needs only to say "at least
3", and the list of issued draws is the selection's operand, not the byte.

**The duplicate is deliberate, so it gets an uncrossable boundary.** `outcome`
is derivable from `(passes, issued)` — storing all three duplicates the fold.
Keeping it is ruled above (a consensus verdict must not be re-derived per
read); what makes the duplicate safe is that **the writer asserts
`outcome` equals the fold of `(passes, issued)` on the write path**, and the
enforcing site is the only site that can produce a row.

---

## 5. `SO-D3` — RULED: the writer runs once per epoch, as one derivation

> **Specification:** [`ARCHIVAL_SERVE_CREDIT_SPEC.md`](ARCHIVAL_SERVE_CREDIT_SPEC.md) §9.3.

The alternative — accumulate incrementally as records arrive and finalise at
close — was considered and **rejected**: it needs the close-time enumeration
anyway (that is `SO-D1`'s forcing case), so it buys nothing and adds a second
write path that can disagree with the first.

**Cost.** The writer makes one pass over the epoch's issued draws and one
selection per pair with at least three (specification §9.3). It runs once
per 10,000 blocks, in the slash scheduler's pass (`SO-D7`), off the
transaction-admission path. It is not measured.

*Where* it runs was the open half, and the obvious answer was the wrong one —
`SO-D7`.

### 5.1 The writer ahead of the draw — SUPERSEDED 2026-10-08

> **Superseded by `SO-D10` (§14).** This section ruled that the writer
> could not be live before the cutover, because a beacon-era wiring would
> write a constant from inputs that change source. The writer is wired
> ahead of the draw on the issued-draw index, which is empty until the
> draw lands, so no beacon-era input exists and nothing changes source.
> No C++ writer is added (Q15).

**The C++ revert of the table is wired**, as pure cleanup with no
dependency on a writer; it is the half `SO-D6` was open about, proven by a
pop round-trip.

---

## 6. `SO-D7` — CORRECTED 2026-08-24: the constraint was already ruled and const-asserted; only the *writer's home* was open

**The opening draft presented this as a finding. It was a rediscovery, and the
tree states it verbatim.** `constants.rs:190-199`:

```rust
// The slash fold for epoch E must not run before the response window of E's
// last-issued challenge closes, or in-flight responses read as misses. The fold
// runs strictly above the deadline (`failure_window.rs`), so `>=` is exact.
const _: () = assert!(
    CHALLENGE_RESOLUTION_BLOCKS >= CHALLENGE_RESPONSE_BLOCKS,
    ...
);
```

*(Since 2026-09-30 the grace is `k · SEB` and W₂ is `SEB / 20` on
`SettlementSchedule`, both from one epoch. **UPDATE 2026-10-01:** a window
is `Option<NonZeroU64>` — an epoch below the divisor has none — and the
production comparison is `SLASH_GRACE_EPOCHS * SETTLEMENT_EPOCH_BLOCKS >=
CHALLENGE_RESPONSE_BLOCKS`. `k * W2_EPOCH_DIVISOR >= 1` stayed true while
the division yielded 0. The margin and the argument are unchanged, and
`CHALLENGE_RESOLUTION_BLOCKS` below is the name the grace had.)*

*"or in-flight responses read as misses"* is `SO-D7`'s entire argument, written
before this round opened, **enforced by a const-assert** rather than left to
prose. `CHALLENGE_RESOLUTION_BLOCKS`'s own doc goes further and states the
scenario I thought I had found — *"a challenge issued at the epoch's **last**
block, `(E+1)·SEB − 1`, must be resolvable before the slash fold reads the
epoch"* — and prices the slack: **one epoch dominates W₂ by a factor of
twenty.**

**This is the same dissolve-on-grounding class the `RF` round logged three
times** (the W₂ floor check, the Pi-4 device question, `RF-D3`), now inside a
round that cited those instances while committing the same error. The
mechanism is identical each time: a residual carried into a new round and
re-reasoned from the doc instead of re-grounded at source. The round's own §1
discipline — *read every input at source* — was applied to the seven inputs in
the table and **not** to the constraint the round believed it was deriving
fresh.

### 6.1 What survives, and the ruling that replaces it

The constants pin **when evidence is final**. They do not say **where the
writer lives**, and that was the genuinely open half.

The opening draft answered it with a new event at `h_close + W₂`. Grounding
says that is unnecessary and more expensive than the alternative:

- The **slash fold already is** a scheduled per-epoch event
  (`process_archival_slash_for_epoch`, `db_lmdb.cpp:5996`), gated on
  `block_height > h_slash_deadline(E)` where
  `h_slash_deadline(E) = h_close(E) + CHALLENGE_RESOLUTION_BLOCKS`.
- It runs **20× past** `h_close + W₂`, so evidence is final by the
  const-asserted margin — the `SO-D7` requirement is met without asserting it
  again.
- It processes epochs in **ascending order** (stated at `db_lmdb.cpp:6040`),
  so epoch `E`'s row exists before any later epoch's window walk reads it.
- It already has a revert (`revert_archival_slashes_at_height`), which is what
  closes `SO-D6`.

**RULED: the writer runs inside the slash scheduler's per-epoch pass — write
the row, then fold it, in one hook.** A separate `h_close + W₂` event would
have added a second scheduled event, a second height→epoch log, and a second
revert path, to buy a margin the tree already guarantees.

### 6.2 The precondition survives the correction, and is now free

`SO-D1`'s theorem still needs *absent ⇒ non-observation* to hold only where the
writer has run. Under this ruling that is no longer a constraint anyone must
remember: **the only reader is the fold that just wrote the row**, in the same
pass, so an unsettled epoch cannot be observed by its consumer. An invariant
held by construction beats the same invariant held by a documented rule — which
is the `RF-D7` lesson the opening draft invoked while writing the weaker form.

---

## 7. `SO-D4` — RULED: `maxdbs` becomes derived, in the same commit

**The new table is the 49th, and `maxdbs` is 48.**
`mdb_env_set_maxdbs(m_env, 48)` (`db_lmdb.cpp:1599`) against exactly 48
unconditional `lmdb_db_open(txn, …)` calls — verified by count, not by reading
the comment. **The table lands at the ceiling with zero headroom.**

The hazard is that this **fails at runtime only**. Adding a 49th
`lmdb_db_open` compiles, links, passes every unit test that does not open a
fresh environment, and fails when a node opens its database.

**Ruled: the bump is not a bump.** Hardcoding 49 re-arms the same trap for the
50th table. `maxdbs` becomes **derived from the table list** — the
`LMDB_*` name constants gathered so the count is computed, not maintained, and
`mdb_env_set_maxdbs` takes **exactly that count**. This is
`45`/`47` discipline applied to a runtime ceiling: a gate that cannot notice its
own subject is not a gate, and a hand-maintained count of a list that lives
three hundred lines away will drift.

**No headroom margin — corrected 2026-08-25, and the correction is the
ruling's own logic applied one step further.** The draft said "that count plus
a stated headroom margin", and the implementation passes the exact count; a
reviewer reasonably flagged the disagreement. The *code* is right and the
clause was the stale half.

Headroom exists to absorb drift between a ceiling and a list. Deriving the
ceiling **from** the list removes the drift, so the margin buys nothing — and
it is worse than nothing, because the only thing it can absorb is a table
opened **outside** the list, which is exactly the case that must fail loudly.
With the exact count, such a table hits `MDB_DBS_FULL` at open; with a margin,
it opens silently and the derived count is quietly wrong until the margin runs
out. That is the "gate that cannot notice its own subject" failure this ruling
was written to remove, re-created by its own safety clause.

**Not sequenced behind the credit-wire deletion.** Deleting the old credit wire
frees `archival_attestation_witness` and `archival_alt_attestation_witness`
(`db_lmdb.cpp:304–305`), which is exactly the two slots needed — but the ruled
order is *writer live first, then deletion* (the deletion's §5 atomic cutover
depends on the writer existing). Taking the free slots would invert it. And
`maxdbs` is a ceiling, not an allocation: it does not need to shrink back.

---

## 8. `SO-D5` — RULED: the prune const-assert survives, with its failure direction inverted

`failure_window.rs:93–104` records why the horizon assert exists: for
`m_archival_serve_credit`, **"a pruned bit reads as a MISS, so this window would
slash archivers for epochs whose evidence the database no longer has"**
(`:181`).

For the settlement table the direction **flips**. A pruned row reads as
*absent*, and absence is now **non-observation** (`SO-D1`). So a window reaching
past the prune horizon does not manufacture misses — it silently **shrinks its
own denominator**, reading a fully-evidenced failure as an unobserved epoch.

**Both directions are wrong and the same assert catches both**, so it stays —
but its rationale string must be rewritten, because a maintainer reading
"slashes honest archivers" while debugging a *missed* slash will conclude the
assert is unrelated. **Failing safe is not the same as failing correctly**, and
an assert that describes the wrong failure is one that gets relaxed by whoever
proves that failure cannot happen.

> **DISCHARGED 2026-09-13.** `failure_window.rs` now names both directions in
> the module doc (`:90–124`, one bullet per table, with which read is live
> today and which is the ruled future), in the assert's doc and its message
> (`:178–210`), and in the margin test's name and comment
> (`the_window_fits_inside_the_archival_retention_horizon`). The claim the
> rewrite rests on — both tables prune at one horizon — was verified at
> `prune_archival_epochs_before` (`db_lmdb.cpp:7726,7728`), not inherited
> from this section. The `:93–104` / `:181` anchors quoted above are the
> pre-rewrite line numbers and are left as written; the §2 row is updated.

---

## 9. `SO-D6` — CLOSED 2026-08-24: recompute, no alt twin, and the revert already exists

Held open in the opening draft on an explicit unread path: *"the argument
assumes a reorg crossing a close boundary always re-runs the writer before any
reader sees stale rows, an ordering claim about `pop_block`/emission-gather
that I have not read at the depth the claim needs."* Read now.

**The lean was right and the codebase already contains the pattern, twice
over.** `BlockchainDB::pop_block` (`blockchain_db.cpp:638`) is a chain of
`revert_*_at_height` hooks, and they split exactly along the line `SO-D6`
guessed at:

| Kind of data | Revert shape | Example |
|---|---|---|
| **Received** evidence, unreproducible on a losing branch | pre-image **journal**, restored on pop | `archival_attestation_witness` + its alt twin; the release / holdings / reinstate journals |
| **Derived** from final chain state | **delete**, recompute on re-connect | `revert_archival_epoch_close_at_height` drops `r_market`, `sigma_work`, `budget` |

A settlement row is the second kind — it is a fold over evidence that is
itself already on chain. So it deletes and recomputes, and needs no twin.

**And the ordering claim resolves without needing to be assumed**, because of
`SO-D7`'s correction below: the writer runs **inside the slash scheduler's own
per-epoch pass**, so its rows revert through `revert_archival_slashes_at_height`
— a hook that already exists, already runs first in the pop chain, and already
carries the ordering rationale for why it must. There is no second event to
order against a reader, which is the strongest form of the answer: not "the
writer runs first", but "there is no separate writer to run".

**One consequence worth stating, since it was the reason the question felt
hard:** `m_archival_epoch_close_log` is keyed at `(E+1)·SEB`, so it could not
have driven the revert of rows written at a different height. Joining an
existing scheduled event dissolves that problem rather than solving it — no new
height→epoch log, and no second table against the `maxdbs` ceiling `SO-D4`
already found.

---

## 10. What "proven live" means here — the shadow cutover is **not** available

The old plan proved a settlement cutover by running a shadow cell against the
vin-written bit and flipping readers once they agreed. **That comparison is
meaningless by design now** (`ARCHIVAL_CHALLENGE_MECHANISM.md` §4-neighbourhood,
"the Phase-4 equivalence KAT is superseded"): 2-of-3 over derived challenges is
*supposed* to disagree with the self-served vin. Agreement would be evidence of
a bug.

So the writer's evidence is **pinned vectors and red tests**, not agreement with
its predecessor:

1. **The forcing case as a red test** — a drawable pair, three issued
   challenges, zero passes, zero records: assert a written **Missed** row.
   Under a record-driven writer this test is red because the row is absent.
   Per rule 50 and `every-check-must-be-able-to-fail`: the edit that makes it
   red is deleting the enumeration.
2. **The absent-row theorem as a test**, not a comment: for a derived epoch,
   every pair with `issued ≥ 1` has a row and no other key exists.
3. **A pinned issued-count histogram** at genesis `D`, which is simultaneously
   the `(m, n)` sweep's input format — so the vector is not written twice.
4. **A pass landing in the epoch's last `W₂` blocks is counted, not missed** —
   the `SO-D7` axis. A challenge issued at epoch-relative block 9,999 that
   passes 400 blocks later must produce a **pass**, not a miss. The edit that
   makes this red is moving the writer to `h_close`.
5. **An unsettled epoch is excluded, not counted as non-observation** — a
   window walk evaluated inside `[h_close(E), h_close(E) + W₂)` must skip `E`.
6. **The prune-horizon assert**, re-argued per `SO-D5`.

---

## 11. Corrections to other documents (found while grounding this round, fixed in this PR)

Grounding this round turned up **five** documents describing settled work
incorrectly. They are fixed here, in their own commits, rather than filed:
each one, read today, sends the next person to build something that exists or
delete something that is load-bearing — which is not hypothetical, since two
of them are how this round started.

1. **`ARCHIVAL_RESPONSE_FORMAT.md`** read "`RF-D1`/`RF-D2`/`RF-D4` drafted
   2026-08-20 …, implementation pending", with two disposition headings still
   marked `(OPEN)`. All of `RF-D1`…`RF-D10` landed by PR #522 on 2026-08-21.
   The doc led the PR per that round's own practice, and nothing updated the
   header when the code landed behind it.
2. **`IMPLEMENTATION_INDEX.md`'s `RF` row** opened with "**Round OPEN
   (2026-08-18…)**" while its own tail already recorded both artifacts landed
   — the row contradicted itself, and the leading status is the half a reader
   trusts. Fixed with (1): correcting the prose and leaving the index is how
   the next reader still gets the wrong answer.
3. **`ARCHIVAL_CHALLENGE_MECHANISM.md` §9.6 item 2** (2026-08-11; grep
   `RF-D8` if that number has since moved) called
   `verify_segment_path` / `challenge_leaf_index` "fossil — do not build
   against it" and put them on §2's deletion surface; **`challenge.rs:9–19`**
   said the module "deletes wholesale with that round's deletion surface",
   naming the format round as the trigger. **That round landed and ruled the
   opposite way** — `RF-D8` ruling (i) kept the opening, so both symbols are
   permanent consensus admission code (`blockchain.cpp:5412` →
   `serve_credit.rs`). **The dangerous one: the stated trigger has fired, and
   acting on it deletes live consensus code.** `path.rs` had carried the
   correction since 2026-08-20 and `challenge.rs` had not, so the two modules
   disagreed and the stale one is the one a reader reaches first. The doc's
   item 2 is **struck in place, not rewritten** — someone who already followed
   the instruction needs the correction where they read it.

   > **REVERSED 2026-09-11 — this item is now wrong in exactly the way it
   > warns about, and it is the SOURCE the index was projecting.** `RF-D8`
   > ruling (i) was **retracted 2026-08-26**, five days after the RF round's
   > CLOSED stamp (`ARCHIVAL_RESPONSE_FORMAT.md`, grep `RF-D8` (i)): the
   > countersignature preimage names the challenged leaf, so `P` cannot sign
   > it without learning which request is the challenge — defeating
   > `ARCHIVAL_CHALLENGE_MECHANISM.md` §9's *"the test IS a read"*. The
   > witness-computed rescue branch is redundant (a witness holding the bytes
   > recomputes `R_k` in full), so both branches collapse.
   >
   > **Consequence: every bolded conclusion above is inverted.**
   > `verify_segment_path` and `challenge_leaf_index` are **deletion-bound**
   > on `ARCHIVAL_CREDIT_WIRE.md` §2's surface, not permanent consensus
   > admission code. `ARCHIVAL_CHALLENGE_MECHANISM.md` §9.6 item 2 and
   > `challenge.rs:9–19` **read correctly as they stand — do not "fix"
   > them.** The fifth fix this item describes landed at `aee2477d9d`
   > (2026-08-24) and was undone in effect by `52f61476bb` (2026-08-26);
   > `challenge.rs` now carries the retraction and `path.rs` the
   > deletion-bound annotation, so the two modules agree again.
   >
   > **`challenge.rs` still deletes only in its leaf-opening half.** The
   > module stays live as the serve-credit admission path into
   > `blockchain.cpp` until the assignment cutover — "deletes wholesale"
   > was over-broad in both directions.
   >
   > Left in place under this document's own rule, one level up: someone who
   > followed *this* item needs the reversal where they read it. This was
   > found from the projection — `IMPLEMENTATION_INDEX.md`'s
   > `SO-D1…SO-Dn` row, reconciled in its own change — which is the
   > reverse of the usual direction and only worked because the index row
   > quoted this one instead of citing it.
4. **`FOLLOWUPS.md` §"PRUNABILITY RESOLVED"** said the records ride *the
   coinbase transaction's* prunable region. `RF-D10` landed them in the
   **serve-credit transaction's** (`serialize_ctsig_prunable`, `ct_types.h`).
   The `k_cap` conclusion survives; the residence does not. Corrected rather
   than struck, with §2's real magnitudes recorded beside the prediction.
5. **A dangling anchor, found only by chasing it.** Both §9.6 item 2 and
   `path.rs` cited the sampled-leaf-insufficiency finding as
   "`ARCHIVAL_CHALLENGE_MECHANISM.md` §5.6". **That document has no §5.6**,
   and no other doc in the tree carries it. Dropped rather than repaired: the
   substance is restated at the one site that keeps it, and a section number
   that has already drifted once is not worth pinning a second time. **The
   replacement is a `RF-D8` grep, not another section number** — a rule-94
   disposition ID is stable because the rule forbids renaming it, whereas a
   section number is stable only until someone inserts a section, which is
   exactly how §5.6 became unreachable. (The first cut of this fix *did*
   point at "§9.6 item 2", reproducing the defect at a later date; review
   caught it.) Worth noting how the original surfaced — it was invisible
   until the correction *quoted* it, which is the argument for restating a
   cited claim rather than passing the citation along.

**§9.5's HOLD list is discharged with them.** Pass-record serialization
cleared 2026-08-18 (the carrier round) and the response format 2026-08-21;
`EndpointUpdate` stayed held until it was REJECTED 2026-09-13, and the
settlement writer is now held on a round
rather than a blocker. Discharged in place following the `settle_epoch` entry
already below it — a HOLD list silently pruned as items clear loses the
evidence that the sequencing was right.

**The pattern across all five is one thing:** every site was written by
someone who *had* the correct information, at a moment when it was correct.
None is a mistake; all are the same omission — the status half of a document
not updated when the substance half landed. That is what makes them invisible
to review and findable only by grounding, and it is why this round's §1 reads
every input at source instead of citing what the last round concluded.

---

## 12. `SO-D8` — OPEN, and assigned OUT of this round: cross-epoch admission

Grounding `SO-D7` surfaced a real gap, narrower than it first looked and **not
this round's to rule.**

The live admission gate refuses a serve-credit response once
`current_height > h_close` (`SHEKYL_ARCHIVAL_VERIFY_ERR_CREDIT_DEADLINE`,
`serve_credit.rs:176`). Under derived assignment a challenge issued in the
epoch's last `W₂` blocks resolves *after* `h_close`, so its response names
epoch `E` while landing in `E+1`'s blocks.

**That gate belongs to the interim beacon path**, the cluster the `challenge.rs`
correction deliberately left unruled — under the beacon shape there was one
challenge per pair-epoch and `h_close` was a sound deadline. The ruled
per-challenge deadline already exists and is per-challenge, not per-epoch:
W₂ is defined as *"blocks after a challenge's **issuing block** to accept its
serve-credit response"* — which is precisely why
`CHALLENGE_RESOLUTION_BLOCKS ≥ W₂` had to be asserted at all.

**What is genuinely open** is the arithmetic at the boundary: a response naming
`E` admitted during `E+1`, and what dedup and the emission gather do with it.

**Scope addition 2026-09-12 (`ba4b3c73a`):** `SO-D8` also **promotes the settlement write path onto `BlockchainDB`**. *Its original coupling — "so the wiring and the interface change arrive together" — is SUPERSEDED 2026-09-13: the interface landed alone (`a6f602d33`, next paragraph) while the production caller stays on the §5.1 hold; the promotion was pulled forward precisely so the base-class change is off the cutover's critical path.* **PRE-PROMOTION:** it lived only on `BlockchainLMDB` (`src/blockchain_db/lmdb/db_lmdb.h`; zero hits in `blockchain_db.h` and `testdb.h`), so if the cutover landed without it, either the base-class change would happen on the consensus-cutover critical path or the redb store (DRS-0) would silently ship without a write path LMDB has.

**LANDED 2026-09-13 (`a6f602d33`).** The four methods are pure virtuals on `BlockchainDB`, `override` on `BlockchainLMDB`. `BaseTestDB` throws on write (absence is SO-D1 non-observation, so a silent no-op is fail-open); working-store KATs stay on `TempLMDB`. The production caller remains the §5.1 hold.

**Why it is not ruled here, stated as a rule-22 blocker rather than a
deferral:** this is **consensus-visible admission timing on a genesis-frozen
surface** — a wrong byte is permanent. It is the design-first category, and it
belongs to the old credit wire's §5 atomic cutover, which owns the admission
path this round does not touch. **No admission code changes in this round's
implementation.** **UPDATE 2026-09-16 (Q15):** that cutover itself waits
until `shekyl-chain-rules` is the live validator and S-ARCH has the write;
no C++ admission or writer code is added in the interim
([`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`](ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md) Q15).

**UPDATE 2026-10-04: the rule-22 hold on the writer's call site is lifted.**
SO-D8 Slice C is authorized and owns the call site together with the
admission rows
([`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`](ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md)
§8.0; [`SERVE_CREDIT_VERIFIER.md`](../completed/SERVE_CREDIT_VERIFIER.md)
`SCV-Q3`). The hold's blocker ("S-ARCH has the write") had been scoped out
by DRS-E4 as waiting on this same admission cutover, so it could not clear
(`SCV-1`). The call site lands in Rust with Slice C. No C++ writer code is
added (Q15).

---

## 13. Disposition summary

| ID | Disposition | State |
|---|---|---|
| `SO-D1` | Writer enumerates the issued set; one row per pair with `issued ≥ 1` | **RULED** |
| `SO-D2` | Key `P_id‖BE(shard)‖BE(E)` (48 B); value `outcome‖passes‖issued` (3 B) | **RULED** |
| `SO-D3` | One derivation per epoch, not incremental accumulation (home is `SO-D7`) | **RULED** |
| `SO-D4` | `maxdbs` derived from the table list, same commit | **RULED** |
| `SO-D5` | Prune const-assert kept, failure direction inverted in its rationale | **RULED** |
| `SO-D6` | Reorg: recompute, **no alt twin** — derived rows delete and recompute; reverts via the existing slash revert | **CLOSED 2026-08-24** |
| `SO-D7` | ~~Writer runs at `h_close + W₂`~~ → **writer runs inside the slash scheduler's per-epoch pass**; the `≥ W₂` constraint was already const-asserted | **CORRECTED 2026-08-24** |
| `SO-D8` | Cross-epoch admission (response naming `E` landing in `E+1`). **Direction ratified 2026-09-13 — shape R-B:** the record names and validates its issuing block `h`, `E = epoch(h)`, deadline `h_incl ≤ h + CHALLENGE_RESPONSE_BLOCKS`; `PC-D2` reversed; dedup widens to `(P,s,E,h)`; the emission gather joins the writer in the slash pass (this doc's `SO-D7` applied to its second consumer). `SO-D8a`/`b`/`c` RULED 2026-09-16 (transcriptions of R-B / PC-D4 / SO-D7); `SO-D8d` RULED 2026-09-16 (three local layers, halt not clamp, on-chain digest REJECTED; proposal §6); `SO-D8e` RULED 2026-09-16 (proposal §7.2); Q9 carrier semantics RULED (B) same day; Q9's set-commitment bytes (PROPOSED) remain to be ruled in [`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`](ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md) §9. *SUPERSEDED: "and the witness-key / batching questions remain to be ruled" — Q8 and Q9 RULED 2026-09-16.* **Reconciled 2026-09-14 against `PL-D3` (PR #745):** the witness key must not be a spendable output's own key, because `PL-D3` holds only while the per-output key is published once, at spend (proposal §2.2); `SO-D8` builds on `dev` after #745 and touches none of its surfaces. The §12 hold on the writer call site stands until then. **UPDATE 2026-09-16 (Q15 RULED):** wait until SO can be written directly in Rust; no C++ mirroring. **S-CHAIN-W increment 3 landed 2026-09-15** (PR #757); DRS is one increment from a validator. Deadline and SO-D9 are surface-free E6 rows; witness verification is bound to the block/tx surface; membership and dedup wait on S-ARCH with the writer — not the whole port. Wait's load-bearing reason is re-derivation plus a second bite at a genesis-frozen wire (`h`, 117 → ~125, rule 42), not only the shim prohibition. Beacon-era §5.1 interim-writer stays closed. *SUPERSEDED: Q12 sequenced behind F5.* Q3 RULED 2026-09-16 (`DrawableSet::at_epoch_open`; drop stays in `D`; filter at settlement). **UPDATE 2026-09-16 (Q8 RULED):** dedicated non-output hybrid key from coinbase output 0's `combined_ss`; 32-B commitment under `0x0C` (not `0x0B` — no version prefix, `k × 49` B). Combined_ss does not cross the FFI. **UPDATE 2026-09-16 (Q8 pins):** `0x0C` mandatory-present (commitment 2); `combined_ss` uniqueness is a derivation requirement with a fixture; Q10 RULED: memory-only ZeroizeOnDrop; persist-encrypted REJECTED. Q12 RULED independently (proposal §7.9); Q13 writes the CEN row and does not re-open optionality. **UPDATE 2026-09-16 (Q9 RULED):** *records-was, amended below:* Merkle-root batching; fail-whole refused (authorship ≠ incidence); serve-credit is fee-less by construction; 300,000 is `get_min_block_weight` (a floor); prunable bytes count toward weight. Against `TX_WEIGHT_LIMIT` the 97-record set splits 39 / 39 / 19 (≈365 KB/block; 39:1). Unpaid inclusion and any prunable-weight discount belong to a fee-and-weight round. **UPDATE 2026-09-16 (Q10 RULED):** accept-loss; memory-only ZeroizeOnDrop ring; persist-encrypted REJECTED. File promptly; evict on inclusion; log dropped in-flight on restart. Named fallback: re-derivable `tx_key`, not persist. **UPDATE 2026-09-16 (Q13 RULED):** 0x0C content is one CEN row, five fixtures, genesis-unconditional; dedicated parser must not copy 0x0B empty-set; length is WITNESS_COMMITMENT_BYTES. **UPDATE 2026-09-16 (Q12 RULED):** 0x0C is a bare 32-B cSHAKE256 of witness_pk under shekyl/archival-witness-key-v1, independent of F5; hiding is theater (reveal publishes pk); reopen if h is removed in order to conceal the issuing block. **UPDATE 2026-09-16 (SO-D8a/b/c RULED):** transcriptions — fire gate dies, `h_close` replaced by per-challenge W₂ (`CHALLENGE_RESPONSE_BLOCKS` FOLLOWUPS discharged); dedup `(P,s,E,h)` exact-get because `h` is in the past and in the DB (what PC-D4 could not do); emission gather to slash pass (SO-D7's second consumer). **UPDATE 2026-09-16 (`SO-D8d` RULED, amended same day vs `dev@5fde3b1ce`):** three local layers — assignment equality (streamed); **persisted** local 32-B `D` digest written in the connect batch at `h_open(E)`, compared against a re-walk at every slash pass; `passes ≤ issued` backstop (strictly dominated). The harmful direction (`NonObservation → Missed`; the free exit) is layer 2's alone. Desync is a **store-invariant Fault** with a new `SI-` row (Slice C) — `poison().arm(row)` → `ConnectState::Halted`; never `CenRow`/`InvalidBlock`; the block at the slash height is unwritten *because the writer halted*, not because it is invalid. Q7 collapsed: cache drops at `h_close + W₂`; the writer is a pure function of chain data (`SO-D1` §4.2, `SO-D6`). §7.4 pin 4 reconciled by call site. On-chain `D`-digest REJECTED on four grounds (ground 3 withdrawn); issued-from-records REJECTED. Q4 is a coverage precondition (λ divergence passes layer 2). **UPDATE 2026-09-16 (Q15 residue):** #761/#762/#764 landed; falsifier unchanged and unfired (LMDB serves production; `held_by_cxx` rows). **UPDATE 2026-09-16 (review):** Q9's byte construction (proposal §7.6.1, PROPOSED) and carrier semantics (§7.6.2, OPEN — the inherited contract refuses a whole carrier on one bad vin; per-vin admission vs fail-whole + resubmission, recommendation (B)) are ruled before Slice C; Q3's drop-safety argument corrected (a dropped pair writes no row — zero bad observations, not one); fee-and-weight round now a FOLLOWUPS row. **UPDATE 2026-09-16 (`SO-D8e` RULED):** forward urn + `W₂` ring of self-contained pairs (~1.9 MB); no checkpoints — rewind replays from the hash-independent wave boundary; one `DrawableSet` live; lifetime `[h_open, h_close + W₂]`, settlement never reads it; one persisted carve-out (32-B `D` digest at `h_open`, undo-logged); ~16 MB at maturity; stateless draws-with-replacement FORECLOSED; owed `SI-10` (SI-5 exists, reuse refused) and 720-not-`D_max`. **UPDATE 2026-09-16 (Q9 amended):** Merkle-root batching SUPERSEDED same day — its isolation-at-admission premise was false under the carrier contract; ruled form is one signature per carrier over a set commitment (`cSHAKE256_32` of the length-framed records, bytes PROPOSED), **carrier fail-whole + resubmission within `W₂`** ((B) RULED; (A) per-vin admission REJECTED — free-weight channel); no inclusion paths (−22 KB/block); split 42 / 42 / 13, ≈ 347 KB/block, 42:1. **UPDATE 2026-09-17 (Q4 RESOLVED, `fix/so-q4-pin-lambda`):** `ChallengeUrn::new` reads `CHALLENGES_PER_PAIR_PER_EPOCH`; `assign_epoch` feeds that constructor; explicit λ is `#[cfg(test)]`; FOLLOWUPS `lambda_target` row removed. Open: Q9 set-commitment vectors. Q12–Q13 RULED; Q14 resolved by Q15 plus the tautology-repair prohibition. **UPDATE 2026-10-04:** Slice C AUTHORIZED, owned by this round with the writer's call site; the §12 hold lifted (proposal §8.0; `SERVE_CREDIT_VERIFIER.md` `SCV-Q3`). | **DIRECTION RATIFIED 2026-09-13 — a–e RULED 2026-09-16; placement RULED 2026-09-16 (Q15)**, consensus-visible |
| `SO-D9` | `ERR_EPOCH_MISMATCH` (`serve_credit.rs:168`) was a tautology — `ctx.settlement_epoch` (`blockchain.cpp:5304`) was the record's own epoch (`:5124`). Ruled **(i)**: populate it at that single site from `shekyl_archival_settlement_epoch_at_height(·)` of the block whose epoch the record claims — `current_height` on the **pre-cutover R-A path** (the connecting block), the **validated issuing block `h`** under **R-B** (proposal §1 "what is ruled is the site", §2.1 item 3) — making "the record's epoch is the block's epoch" an explicit enforced rule rather than a bound on *when* implicit in `h_close`. The *site* is independent of `SO-D8`'s shape; the *operand* is not, and the two pre-FFI C++ bounds (`h_close`, `challenge_seal_on_chain`) mean (i) on the R-A operand flips exactly one block per epoch (proposal §1 "Ordering", Q14). **Implementation not yet built** and **not to be built on the C++ path** (Q15, 2026-09-16): the row lands in `shekyl-chain-rules` with the R-B cutover, operand `h`. **Prohibition:** do not repair the tautology in `blockchain.cpp` — that would be a consensus tightening on the live LMDB daemon for a path being replaced. FOLLOWUPS row. Proposal: [`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`](ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md) §1 / Q15 | **RULED 2026-09-13 — (i)**; site **re-homed 2026-09-16 (Q15)** |
| `SO-D10` | Wiring the writer ahead of the secret draw: it reads the issued-draw index, empty until the draw lands; the walk-back skips an unobserved epoch inside a standing run; the pass fact lives on the draw's index entry; accrual follows as its own change and gates the draw (§14) | **RULED 2026-10-08** |

**Not blocked on the stressnet.** Everything above is desk-derivable, and
`SO-D2`'s `issued` byte is deliberately the artifact that makes the eventual
`(m, n)` sweep interpretable. The measurement this round does **not** need is
the PoW rig run: §2 shows the chain-growth ceiling is gone by 34.6× and the
block-occupancy cost is a reward penalty rather than a wall, and `SO-D1` is
correct in both regimes precisely so the schema does not depend on which one
the network is in.

---

## 14. `SO-D10` — wiring the writer ahead of the secret draw — RULED 2026-10-08

**Status:** RULED 2026-10-08, all seven sub-items (§14.5). Nothing in it
is built except the two pure functions of §14.4 items 1 and 2. Grounded at
`dev@98fbd20acb`; every `file:line` below is at that commit.

**The charge.** [`ARCHIVAL_SERVE_CREDIT_SPEC.md`](ARCHIVAL_SERVE_CREDIT_SPEC.md) §11 item 2: "The
settlement writer is wired before the secret draw goes live. The slash fold
and accrual read the settlement row with its NonObservation floor." The
reason is its §9.4: under the secret draw, a reader of "any pass" counts
every pair the draw did not reach as a miss.

### 14.1 What the code does today

| Subject | State | Where |
| --- | --- | --- |
| The fold | `settle_pair(beacon, P, shard, E, draws)`: takes a pair's counted draws in `(h, j)` order, selects three by the beacon (`select_counted`), and counts the passes among them. No row for no draws; NonObservation below three. Called by the slash pass for every pair with a draw in the epoch. The count fold `settle_epoch` it replaces is deleted (`SO-D10e`) | `rust/shekyl-archival-retention/src/settlement_select.rs`; `rust/shekyl-chain-rules/src/archival/slash.rs` (`settle`) |
| The row | `shekyl_types::archival::SettlementRow`, built by `settle(passes, issued)` with `passes` counted among the three selected draws, floor 3, `issued` saturating at 255, `issued = 0` refused. Decoding re-settles the counts and refuses an outcome they do not give. It is the only `SettlementRow`: the count fold's type and its FFI are deleted | `rust/shekyl-types/src/archival/settlement.rs`; codec in `rust/shekyl-store-codec/src/archival.rs` |
| The tables | `archival_settlement` is `([u8; 32], u64, u64) → Coded<SettlementRow>` at ordinal 19, sealed, written by the slash pass. The issued-draw index is `archival_issued_draw`, `(E, P, shard, h, j) → Coded<IssuedDraw>` (reveal height and the pass bit), and its digest is `archival_issued_digest`, `E → Coded<IssuedDigest>`; both Rust-only, ordinals 38 and 39. Layout 22. No block writes the index or the digest until admission lands; the Fakechain door is their one producer | `rust/shekyl-chain-store/src/schema.rs` (`ARCHIVAL_SETTLEMENT`, `ARCHIVAL_ISSUED_DRAW`, `ARCHIVAL_ISSUED_DIGEST`); `src/ids.rs` (`SettlementKey`, `IssuedDrawKey`); `src/store/archival_write.rs` (`write_settlements`, `regtest_issue_draws`) |
| The slash fold | Settles the epoch, then decides on rows. A pair is a candidate only if its row for the epoch is Missed; Served, NonObservation and no row are each no slash. The window walks back through earlier rows, passing over an unobserved epoch (`SO-D10b`), and stops where the record's standing ends, at `n` observations, past the serve budget, and at the retention horizon (§14.4 step 3). The one-challenge beacon geometry is gone from the Rust pass | `rust/shekyl-chain-rules/src/archival/slash.rs` (`scan_epoch`, `settle`, `challenge_failed`, `window_slashable`) |
| Accrual | The epoch close credits a shard on any pass | `rust/shekyl-chain-rules/src/archival/close.rs:399-418` |
| When each runs | The close for `E` runs at connecting height `(E+1)·SEB − 1`. The slash pass settles `E` one epoch later, at `(E+2)·SEB − 1`, before that block's own close | `archival/mod.rs:159-184`; `archival/slash.rs:94-115`; `rust/shekyl-archival-retention/src/consensus_state/settlement_schedule.rs:190-193` |
| `issued` | The length of a pair's counted draws in the stored index: those issued while it held the shard, read as `holds_shard_at` reads it. Nothing issues a draw on a block path yet, so the index is empty off Fakechain and the Rust pass settles and slashes nothing (`SO-D10a`) | `archival/slash.rs` (`counted`); `rust/shekyl-archival-retention/src/challenge_assignment.rs` (the urn, still without a caller outside its crate) |
| A pass, per draw | The index row's `passed` bit is its home (`SO-D10c`), and settlement reads it. Only the Fakechain door sets it. The serve-credit pass row is still keyed `(P, shard, epoch, including height)` and names no draw; it is re-keyed or deleted when admission lands, and until then feeds accrual and the Release's served anchor, not the slash | `rust/shekyl-chain-store/src/schema.rs`; `store/archival_write.rs:183-211` |
| The block's archival writes | `ArchivalDelta::settlements()` carries the rows the pass derived, by epoch, persona and shard; the store writes them in phase 9 ahead of the slash writes (`SO-D7`), insert-once. `ChainView` reads the row (A14), one epoch's issued draws in `(P, shard, h, j)` order (A15) and the epoch's digest (A16) | `archival/delta.rs` (`Settlement`); `rust/shekyl-chain-rules/src/view.rs`; `rust/shekyl-chain-store/src/store/archival_write.rs` (`write_settlements`) |
| Pruning | The Rust store prunes no archival table by epoch. `prune_archival_epochs_before` is C++ only | `rust/shekyl-chain-store/src/store/prune.rs:132` |
| The C++ side | No writer and no reader: `set_`/`get_archival_settlement`, the two FFI exports they called and their unit tests are deleted (`SO-D10e`). The table's handle, its revert and its prune remain and run over a table nothing writes, until `DEL-008` | `src/blockchain_db/lmdb/db_lmdb.cpp` (`delete_archival_settlement_for_epoch`, `delete_archival_settlement_before_epoch`); `docs/design/archival_forcing_cells.tsv` |

### 14.2 The defect this pre-flight exists for

**§5.1 says the writer cannot be live before the cutover; the
specification says it is wired before the draw goes live. Neither cites the
other.** §5.1's three reasons were about a beacon-era wiring: every row
would say NonObservation, the rows would store a constant, and both inputs
would change source at the cutover.

The writer has two inputs: the issued draws of a pair, and which of them
have a pass. Neither exists in the Rust path today (§14.1). So "wired" cannot
mean "producing rows from live inputs", and it must not mean a beacon-era
stand-in, which is what §5.1 refused.

### 14.3 The shape (`SO-D10a`)

**The writer reads the issued-draw index from its first commit, and the
index is empty until the draw lands.**

- The Rust store gains the index the specification rules (its §10): the
  per-pair list of issued draws and the per-epoch digest cell. They are
  shaped, journaled and readable, and nothing writes them yet except a
  Fakechain-only test hook.
- The writer runs in the slash pass (`SO-D7`), reads the index, and writes
  one row per pair with `issued ≥ 1` (`SO-D1`). With an empty index it
  writes nothing.
- The slash fold reads the row. An absent row is "no live obligation in
  `E`" (§3), so nothing is slashed.

§5.1's three reasons do not arise: no row is written at `issued = 0`, so
nothing stores a constant, and the input is the index from the start, so
nothing changes source when the draw lands. The draw's admission then
populates the index and the writer does not move.

**The consequence, stated so it is not discovered: from the change that
switches the readers until the draw lands, the Rust validator slashes
nothing.** That is the point of the ordering. The Rust path is not the
live validator; the C++ daemon stays consensus, on the beacon, until
`DEL-008`.

### 14.4 Build order

1. **Tables and the view read. LANDED** (§14.1 rows *The row*, *The
   tables*, *The block's archival writes*). `archival_settlement` shaped
   as `([u8; 32], u64, u64) → Coded<SettlementRow>`, the tuple form of the
   48-byte key (`SO-D2`), in the order the store already uses for
   `archival_slash_applied`. The issued-draw index, each row with its pass
   fact, and the epoch's digest cell. `SCHEMA_VERSION` 21 → 22. The view
   reads for all three.

   The index is keyed **epoch first**, `(E, P, shard, h, j)`. Every reader
   takes one epoch: the settlement walk, the digest it checks, which must
   cover every stored draw of the epoch and not only those of pairs a walk
   of `D` reaches, and the prune. Each is one contiguous range, and inside
   it one pair's draws are adjacent in the `(h, j)` order the selection is
   defined over.
2. **The list fold, and the `SO-D10e` deletions. LANDED** (§14.1 rows
   *The fold*, *The row*, *The C++ side*). The selection of three counted
   draws by beacon, the fold over them (`settle_pair`) and the digest term
   are in `rust/shekyl-archival-retention/src/settlement_select.rs`, with
   the specification's vectors. The count fold, its row type, its two FFI
   exports, the C++ writer and reader and their unit tests are deleted.
   The urn's per-pair target is asserted equal to the draws settlement
   counts while both exist.
3. **The slash fold reads the row. LANDED** (§14.1 rows *The slash fold*,
   *`issued`*, *The block's archival writes*). The writer in the slash
   pass, the delta field, the store write in phase 9 ahead of the slash
   writes (`SO-D7`), the walk-back of `SO-D10b`, and the test door of
   `SO-D10f`. The integrity checks that have an operand are one
   store-invariant row, `SI-25` (`STORE_INVARIANT_REGISTER.md`): the index
   against its digest, the fold's count, and a row written once. `SO-D8d`
   named `SI-10`; that row is cumulative work.

   Four things the build settled that the rulings did not spell:

   - **The walk-back stops at the retention horizon, for ratification.**
     `SO-D10b` says stop only where the record says the run began. While
     the walk stopped at the first unobserved epoch it read at most
     `n − 1` epochs back, which `failure_window.rs` const-asserts inside
     the horizon. A walk that passes over unobserved epochs can go
     further, to rows a store may have deleted, and a deleted row reads
     the same as an absent one: the verdict would depend on what a node
     had pruned. The walk reads no epoch below
     `SettlementSchedule::prune_below_epoch_at_height` at the connecting
     height. Cost: at most `MAX_CLAIM_AGE_W_EPOCHS` reads per Missed pair.
     Effect on the rule: `m` misses within the last `n` observations
     **inside the retained window**. A pair with ten misses, then more
     than a retention window unobserved, then one miss, is not slashed.
   - **The check is `passes ≤ counted`.** The row type holds `passes` to
     the draws that were counted — three, or none below three issued —
     which implies §9.5's `passes ≤ issued`. The fold cannot overcount, so
     the fault names a defect of the fold; it halts and is never clamped.
   - **A schedule with no response window settles on the epoch's last
     block.** A levered epoch shorter than the `W₂` divisor has no `W₂`;
     its beacon is `block_hash(h_close(E))`.
   - **A stored draw naming a persona with no bond record is not
     counted.** Admission is what holds an index row to a bonded persona;
     the read-side belt lands with it.

   Tests: `slash_scan_bench_tests` (the witness re-driven through the
   door; the empty index; the skip, the serve budget and which draws
   count; the horizon; index drift three ways; a second settlement; the
   pop) and the levered chain in `shekyl-chain-ingest`
   (`archival_slash_tests`, live lane). **The LMDB comparison
   (`archival_fixture_replica_tests`) is retired** as ruled: it held the
   Rust slash against the one slash the C++ decided on the one-challenge
   beacon, and the Rust pass no longer decides that way. The committed
   capture stays as a record and goes with the capture tooling
   (`DEL-008`).
4. **`SO-D10d`**: accrual reads the row.
5. **Admission and the draw.**

### 14.5 Rulings (maintainer, 2026-10-08)

| # | Question | Ruling |
| --- | --- | --- |
| `SO-D10a` | What the writer reads before the draw exists | **The empty issued-draw index** (§14.3). Not a beacon-era stand-in. The Rust validator slashes nothing until the draw lands; the C++ daemon stays consensus until `DEL-008` |
| `SO-D10b` | The window walk-back over a row that is NonObservation or absent, inside a standing run. Before this ruling the walk stopped at the first epoch that is not an observation (`rust/shekyl-archival-retention/src/failure_window.rs:53-56`), which is how the join, add and reinstate boundaries fall out | **Skip it; stop only where the record says the run began** (`good_through` false: before the join, or across a reinstatement). Inside the run, Served and Missed are observations and a NonObservation or absent row is passed over. **Stopping is exploitable:** a colluding producer can withhold one reveal, push a non-server's pair below 3 issued draws in that epoch, and clear its window. Skipping is what the genesis-frozen rule says: `m` misses within the last `n` observations |
| `SO-D10c` | How a pass is tied to a draw before admission is built. The writer counts passes among the three selected draws; the pass row today names no draw | **The draw's index entry carries the pass fact.** Condition: **the pass fact has exactly one home.** When admission lands, the `(P, s, E, h)` serve-credit table is re-keyed or deleted; it is never kept beside the index's pass bit. **The issued-index digest covers issuance only**: a pass is set later, inside `W₂`, and is not part of what the digest folds |
| `SO-D10d` | Accrual. The close for `E` runs an epoch before the slash pass settles `E`, so it cannot read `E`'s row where it stands. `SO-D8c` rules the emission gather into the slash pass | **Its own change, after the slash fold reads the row and before the draw.** Until it lands, accrual stays on any pass while slashing reads the row. **Gate:** the draw cannot go live until `SO-D10d` has landed — no Rust consensus that pays on any pass while it slashes on rows. Slash timing stays as designed: the slash pass for `E` at `(E+2)·SEB − 1` |
| `SO-D10e` | The count fold `settle_epoch(passes, issued)` with its floor of 2, its two FFI exports, the C++ `set_`/`get_archival_settlement` and their unit tests. None has a production caller, and they state the superseded fold | **Delete them with the list fold** (rule 15). The LMDB table's handle, revert and prune stay for `DEL-008`. `SettlementRow` keeps its bytes; its floor becomes 3 |
| `SO-D10f` | Tests that slash through any pass: `slash_writes_land_at_the_m_epoch_deadline`, `the_levered_slash_chain`, and `the_lmdb_slash_fixture`, which compares the Rust slash with the one slash the C++ ever wrote under test | **A Fakechain-only hook that issues draws and marks passes**, beside the serve-credit injector. The first two are re-driven through it. **The LMDB comparison is retired**, with the reason recorded: the C++ is not canonical, and keeping the any-pass fold alive to feed the comparison is the wrong trade |
| `SO-D10g` | The `D` check (`SO-D8d` layer 2). It needs the drawable-set enumerator and the digest cell written at `h_open(E)`; neither exists, and admission is their first consumer | **Lands with admission.** Named blocker: no `D` exists for the writer to re-walk |

**Settlement timing is not moved here.** Whether settling `E` at
`h_close(E) + W₂ + 1`, where every reveal for `E` is in, is better than the
inherited `(E+2)·SEB − 1` is a sim question (`ESR-12`,
[`ECONOMICS_SIM_PRODUCTION_REBASE.md`](ECONOMICS_SIM_PRODUCTION_REBASE.md)
§5.16). It does not block the writer. A material gain comes back as a
re-pin of slash timing and the grace coupling, not as a move.

### 14.6 Defects found while grounding

Doc against code or doc against doc. Fixed with the implementing change
unless noted.

- **§5.1 against the specification's §11**, above.
- **`SO-D8`'s plan says the writer and the admission rows land as one
  unit** (proposal §8.0); the sequencing ruled 2026-10-07 puts the writer
  first. The specification governs.
- **The proposal's plan row gives `passes` as the per-pair-epoch pass
  count**; the specification gives it as the passes among the three
  selected draws, and the proposal's own §6.5 lists the first as a defect
  class.
- **The index row for `SO-D` says `issued = 1` settles NonObservation,
  that the writer asserts on `issued > 255`, and that no draw state
  persists.** The specification says fewer than 3, saturate, and stored.
- **CEN-L8 says a fold refusal aborts the block's write.** `SO-D8d` rules a
  writer halt that is never a verdict on the block. **Fixed:** the census
  row carries the Rust form, `Corrupt::SettlementIntegrity` → `SI-25`.
- **`SO-D8d` names `SI-10` for its Fault.** `SI-10` is cumulative-work
  monotonicity. **Fixed:** the row is `SI-25`.
- **The Rust store never prunes an archival table by epoch**, and
  `failure_window.rs`'s prune assert is written as if it did
  (`:202-211`). Not this change's: the settlement rows and the index join
  whatever prune the store gains.
- **Two test modules described observations as "settled 2-of-3"** while
  the code they drove was any pass. **Fixed** in
  `slash_scan_bench_tests.rs`, which now issues the draws it settles. The
  other, `archival_write_tests.rs`, drives accrual, which stays on any
  pass until `SO-D10d`.
