# The settlement writer — design round (SO)

**Status:** OPEN — round opened 2026-08-23. `SO-D1`…`SO-D5` **RULED**;
**`SO-D6` CLOSED 2026-08-24** by grounding (recompute, no alt twin — the
mechanism is named, not just leaned toward); **`SO-D7` CORRECTED 2026-08-24 —
it re-derived a constraint the tree already enforced**; **`SO-D8` OPENED** and
assigned out of this round.

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
| 7 | Prune horizon ≥ window | `failure_window.rs:93–104,181` | const-assert present |

### 1.1 Why the existing table cannot be widened (re-verified, not inherited)

§4.3 rules it out "by construction, not convention". The construction is four
consumers that read **key presence** as "served", so any key written for any
reason becomes a serve credit:

- old-vin dedup — `blockchain.cpp:5307`
- slash-window walk — `db_lmdb.cpp:5763`
- fast-path miss check — `db_lmdb.cpp:5793`
- emission gather — `db_lmdb.cpp:7801`, a **pure presence cursor-walk**
  (`:7804`, no value-byte gate) feeding `r_market`/`σ_work`

The table's own declaration states the shape it can never carry more than:
`m_archival_serve_credit` is `P_id[32]‖BE(shard)‖BE(E)` → `uint8_t 0x01`
(`db_lmdb.h:881`). Writing a **Missed** cell there corrupts vin-dedup and
emission simultaneously — a settlement outcome and a payment authorisation
would share a key space where presence means pay.

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
opposite ways. Restating the second row as "prunability fixed `k_cap`" would be
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

**The forcing case is a drawable pair that passes nothing.** All three of its
challenges expire; expiry ⇒ miss (fork §7.3); the epoch settles **Missed**. And
there are **zero on-chain artifacts** — no pass record, no vin, nothing — to
trigger a write. A writer driven by arriving records writes nothing, the row is
absent, and absence means non-observation. *The pair that failed completely is
the pair that gets the most forgiving settlement.* That is a slash escape, and
it is the exact inverse of the §4.1 bias the drawability relocation fixed.

So the writer cannot be record-driven. It must enumerate.

**Ruled:** at epoch close the writer runs the assignment derivation over the
closing epoch and writes **one row per `(P, s)` with `issued ≥ 1`**, carrying
its observed pass count. Pairs with `issued = 0` are not written.

This is §4.2's second branch, adopted **unconditionally** rather than as the
fallback for a §7.1 variant that did not win. Three reasons, in priority order:

1. **It is the only branch that is correct in both regimes.** The first branch
   is correct exactly when coverage is exact, which §2.1 shows is a
   scale-dependent economic outcome, not a guarantee.
2. **It costs nothing extra at genesis**, where `D` is small — and the maturity
   cost is "the same cardinality the emission gather already walks" (§4.2),
   i.e. a walk the block already performs.
3. **It makes the absent-row invariant total.** With every issued pair written,
   *absent ⇒ never issued ⇒ not drawable ⇒ non-observation* is a theorem about
   the writer, not an inference about a regime.

**Keyed on issued, not drawable** — §4.4's re-keying, preserved. A drawable pair
the urn never reached is not a pair that failed, and writing it as anything
would be recording an observation that did not occur. The `issued ≥ 1`
condition is where that distinction lives.

**Under-issuance is specified, not assumed away** (§4.4's own instruction):
`issued = 1` settles **NonObservation** by absolute-2, and it gets a **row**
rather than an absence. Absence and NonObservation are then no longer
synonymous — absence means *not issued*, a written NonObservation means *issued
but unreachable*. **This is deliberate and it is the auditability argument
winning over absence-consistency:** the capped regime is the one where the
mechanism's teeth degrade (§7.1: 72 % unobservable at `k_cap = 30`,
`D = 324 k`), and a regime that degrades silently is one nobody measures. The
row is how the degradation becomes visible on-chain.

**No derivation state is stored** — the writer *runs* the urn, it does not read
a persisted urn. §7.1's derive-don't-store ruling and the
`ArchivalSealHashCache` precedent are preserved: the enumeration is a pure
function of (epoch-open snapshot, `block_hash(h_open..h_close−1)`).

---

## 4. `SO-D2` — RULED: key and value

**Key — 48 B, byte-identical in shape to `m_archival_serve_credit`:**

```text
P_id[32] ‖ BE(shard_id)[8] ‖ BE(settlement_epoch)[8]
```

Same shape deliberately: the slash-window walk and the emission gather already
seek on this layout, so a reader holding one key can probe the other table
without re-encoding. Big-endian is load-bearing — it is what makes an LMDB
range scan over `(P_id, shard)` return epochs in order, which is exactly the
outer-window walk's access pattern.

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

`u8` is sufficient and checked: `CHALLENGES_PER_PAIR_PER_EPOCH = 3`, and the
band variant that would have produced 4 was **rejected** (§7.1, 2026-08-10).
A writer producing `issued > 255` is a mechanism change, and it should fail
loudly at the write rather than silently truncate — stated here so the
implementation asserts rather than casts.

**The duplicate is deliberate, so it gets an uncrossable boundary.** `outcome`
is derivable from `(passes, issued)` — storing all three duplicates the fold.
Keeping it is ruled above (a consensus verdict must not be re-derived per
read); what makes the duplicate safe is that **the writer asserts
`outcome == settle_epoch(passes, issued)` on the write path**, in the same
place as the `issued > 255` assert. One assert, two invariants, and the
enforcing site is the only site that can produce a row.

---

## 5. `SO-D3` — RULED: the writer runs once per epoch, as one derivation

The alternative — accumulate incrementally as records arrive and finalise at
close — was considered and **rejected**: it needs the close-time enumeration
anyway (that is `SO-D1`'s forcing case), so it buys nothing and adds a second
write path that can disagree with the first.

**Cost, priced rather than waved past.** At maturity the close-block derivation
is ~972,000 assignments (`3 × 324,000`) in one block, once per 10,000 blocks.
That is a real latency spike and it is named here so it is not discovered as a
bug. Two properties keep it acceptable: it is a **pure function of already-final
chain state**, so it is memoisable and parallelisable on the same
`ArchivalSealHashCache` pattern; and it is off the transaction-admission path
entirely — no incoming transaction waits on it.

**Reopening criterion** (rule 21): if a rig run shows the derivation exceeding
the block-propagation budget at any `D` the network actually reaches, the fix
is to amortise it across the blocks preceding the fold — not to move it
off-chain and not to persist urn state.

*(The spike lands on the fold block, not the close block: `SO-D7`'s correction
moved the writer into the slash scheduler's pass. The `~972,000` figure and the
argument for why it is tolerable are unchanged — both turn on the derivation
being a pure function of final chain state and off the admission path, neither
of which depended on which scheduled block it runs in.)*

*Where* it runs was the open half, and the obvious answer was the wrong one —
`SO-D7`.

### 5.1 It cannot be live before the cutover, and that is a property of the mechanism

Interim issuance is **one** beacon challenge per pair-epoch. Under absolute-2,
`settle_epoch(passes, issued = 1)` settles **NonObservation for every pair,
always** — correctly, by `SO-D1`'s own rule that a pair the urn could not reach
twice is not a pair that failed.

So until the cutover wires per-challenge admission, the writer would emit rows
that are uniformly `NonObservation` and carry no information. **The rows must
therefore have no consumer until derived assignment is live** — the writer
lands with its KATs and its forcing-case red test, and the slash window keeps
reading what it reads today.

Stated here rather than discovered later, because "the writer is built" and
"the writer is authoritative" are different claims, and the gap between them is
exactly the §5 cutover (`SO-D8`).

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
`mdb_env_set_maxdbs` takes that count plus a stated headroom margin. This is
`45`/`47` discipline applied to a runtime ceiling: a gate that cannot notice its
own subject is not a gate, and a hand-maintained count of a list that lives
three hundred lines away will drift.

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
| **Received** evidence, unreproducible on a losing branch | pre-image **journal**, restored on pop | `archival_attestation_witness` + its alt twin; the unbond / holdings / rebond journals |
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
`EndpointUpdate` stays held, and the settlement writer is now held on a round
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

**Why it is not ruled here, stated as a rule-22 blocker rather than a
deferral:** this is **consensus-visible admission timing on a genesis-frozen
surface** — a wrong byte is permanent. It is the design-first category, and it
belongs to the old credit wire's §5 atomic cutover, which owns the admission
path this round does not touch. **No admission code changes in this round's
implementation.**

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
| `SO-D8` | Cross-epoch admission (response naming `E` landing in `E+1`) | **OPEN — assigned to the §5 cutover**, consensus-visible |

**Not blocked on the stressnet.** Everything above is desk-derivable, and
`SO-D2`'s `issued` byte is deliberately the artifact that makes the eventual
`(m, n)` sweep interpretable. The measurement this round does **not** need is
the PoW rig run: §2 shows the chain-growth ceiling is gone by 34.6× and the
block-occupancy cost is a reward penalty rather than a wall, and `SO-D1` is
correct in both regimes precisely so the schema does not depend on which one
the network is in.
