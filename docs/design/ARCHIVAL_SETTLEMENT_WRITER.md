# The settlement writer — design round (SO)

**Status:** OPEN — round opened 2026-08-23. `SO-D1`…`SO-D5` and `SO-D7`
**RULED** in this draft; `SO-D6` (reorg disposition) carries a lean and is the
round's one genuinely open item.

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

**Reopening criterion** (rule 21): if a rig run shows the close-block
derivation exceeding the block-propagation budget at any `D` the network
actually reaches, the fix is to amortise the derivation across the epoch's
final `W₂` blocks — not to move it off-chain and not to persist urn state.

*When* it runs is a separate question with a wrong obvious answer — `SO-D7`.

---

## 6. `SO-D7` — RULED: the writer runs at `h_close + W₂`, not at `h_close`

**Pass evidence is not final when the epoch closes.**
`CHALLENGE_RESPONSE_BLOCKS = SEB / 20 = 500` (`constants.rs:147`), and
`assign_epoch` issues on **every block of the epoch** — `prev_hashes.len()` *is*
the epoch length (`challenge_assignment.rs:262–279`), with no cutoff near the
end. So a challenge drawn at epoch-relative block 9,999 has a response window
running 500 blocks into epoch `E+1`.

A writer running at `h_close` therefore counts every in-flight challenge as
zero passes. **Up to `W₂/SEB = 5 %` of each epoch's issuance would settle as
missed purely because the writer ran too early** — a slash bias against
archivers who were serving normally, which is the same class of defect as the
§4.1 finding this mechanism already fixed once.

Two fixes were available and only one is this round's to take:

- *Stop issuing at `SEB − W₂`.* This makes `h_close` final, but it truncates
  the urn's draw window by 5 %, which perturbs the redraw floor and the
  wave-tail exposure arithmetic — both **ruled** on the full-epoch assumption
  (§7.1, 2026-08-10). Re-opening a closed parameter to simplify a writer is
  backwards.
- **Run the writer at `h_close + W₂`.** `W₂` is the maximum response latency
  *by construction*, so at that height every challenge issued in `E` has
  either passed or expired. Evidence is final, nothing upstream moves.

**Ruled: the second.** Settlement for epoch `E` lands 500 blocks (~16.7 h)
into `E+1`.

### 6.1 The lag is not free — the absent-row theorem gains a precondition

`SO-D1`'s theorem (*absent ⇒ never issued ⇒ non-observation*) is now true only
**after** the writer has run for that epoch. Between `h_close(E)` and
`h_close(E) + W₂`, epoch `E`'s rows are absent because they have not been
written yet — and a reader applying the theorem in that window reads a fully
challenged epoch as unobserved.

**So the theorem carries its precondition explicitly, and readers enforce it:**
epoch `E` is only settled-readable at height `h ≥ h_close(E) + W₂`. A window
walk must **exclude** any epoch not yet settled rather than count it as
non-observation. This is stated as a constraint on the reader, not as a
property of "the writer usually runs first" — the `RF-D7` lesson, applied a
third time.

**Verified, not assumed:** the emission gather does not read this table. It is
a pure presence cursor-walk over `m_archival_serve_credit` (`db_lmdb.cpp:7801`,
`:7804`), written at *admission*, so emission timing is untouched by the
settlement lag. The consumer that does care is the slash-window walk, and the
precondition above is exactly what it must respect.

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

## 9. `SO-D6` — OPEN (lean: recompute, no alt twin)

`archival_attestation_witness` carries a reorg-survival twin,
`archival_alt_attestation_witness` (`db_lmdb.cpp:304–305`,
`ARCHIVAL_CREDIT_WIRE.md` §3.2/§4). Does the settlement table need one?

**Lean: no — recompute at close.** Settlement rows are a *memoised derivation*
over final chain state, not received data. A reorg past an epoch boundary
invalidates the rows for that epoch, and the correct response is to drop and
recompute — behaviour-identical to `ArchivalSealHashCache`'s
recompute-on-reorg, and the same reasoning §7.1 used to keep urn state out of a
table. The alt twin exists for the witness table because a witness record is
**received evidence** that would be *lost* on the losing branch and is not
reproducible from chain state; a settlement row is reproducible by definition.

**Why it stays open rather than ruled:** the argument above assumes an epoch
close is never re-entered with *different* pass evidence — i.e. that a reorg
crossing a close boundary always re-runs the writer before any reader observes
the stale rows. That is an ordering claim about `pop_block` and the emission
gather, and I have not read those paths at the depth the claim needs.
**Naming the unread path rather than asserting the conclusion**, per the
round's own §1 discipline. This is the disposition to close before
implementation starts.

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
3. **`ARCHIVAL_CHALLENGE_MECHANISM.md` §9.6 item 2** (2026-08-11) called
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
   that has already drifted once is not worth pinning a second time. Worth
   noting how it surfaced — it was invisible until the correction *quoted* it,
   which is the argument for restating a cited claim rather than passing the
   citation along.

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

## 12. Disposition summary

| ID | Disposition | State |
|---|---|---|
| `SO-D1` | Writer enumerates the issued set; one row per pair with `issued ≥ 1` | **RULED** |
| `SO-D2` | Key `P_id‖BE(shard)‖BE(E)` (48 B); value `outcome‖passes‖issued` (3 B) | **RULED** |
| `SO-D3` | One derivation per epoch, not incremental accumulation (timing is `SO-D7`) | **RULED** |
| `SO-D4` | `maxdbs` derived from the table list, same commit | **RULED** |
| `SO-D5` | Prune const-assert kept, failure direction inverted in its rationale | **RULED** |
| `SO-D6` | Reorg: recompute vs alt twin | **OPEN** — lean recompute; blocked on reading `pop_block`/gather ordering |
| `SO-D7` | Writer runs at `h_close + W₂`; absent-row theorem gains a settled-readable precondition | **RULED** |

**Not blocked on the stressnet.** Everything above is desk-derivable, and
`SO-D2`'s `issued` byte is deliberately the artifact that makes the eventual
`(m, n)` sweep interpretable. The measurement this round does **not** need is
the PoW rig run: §2 shows the chain-growth ceiling is gone by 34.6× and the
block-occupancy cost is a reward penalty rather than a wall, and `SO-D1` is
correct in both regimes precisely so the schema does not depend on which one
the network is in.
