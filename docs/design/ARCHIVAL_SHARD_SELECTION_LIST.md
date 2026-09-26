# The shard selection list — design steers (SL)

**Status:** LIVING CONTRACT — last verified 2026-09-14. `SL-D1`…`SL-D8`
**RULED**; implementation opened (profit-hint RPC + operator fetch-request
RPC; GUI picker). `SL-D6` payout-floor filter stays FOLLOWUPS. Market
`first_stake` posting stays a typed refusal this round.

**Scope:** how a market staker's wallet decides which shards to bond. Nothing
here is consensus-visible: no wire field moves, no admission rule changes, no
LMDB table is added. The whole surface is one read-only daemon RPC plus wallet
presentation, so it is **build-and-pivot**, not design-first.

**Grounded on `dev@37accf6f`, 2026-09-13.** Every row below was read at source.
Where a claim could not be verified in code it is marked as such rather than
asserted.

**Process:** disposition IDs `SL-D1` … `SL-Dn`, registered at birth per
[`94-tracking-index`](../../.cursor/rules/94-tracking-index.mdc). Prefix `SL-`
checked tree-wide across `docs/`, `src/`, `rust/`, `.cursor/` — **zero hits**
before this document. `SA-` was the obvious choice and is **taken** by the
signature-alignment round (`SA-R-1`…`SA-R-7`).

---

## 1. The inputs, verified at source

| # | Input | Verified at |
|---|---|---|
| 1 | Shard holdings are **operator-declared**, bounds-checked only | `bond_wire.rs:70`; `MAX_HOLDINGS_SHARDS = 4096` |
| 2 | Consensus does **not** assign or constrain shards | `serve_eligibility.rs` is epoch-only (`E_first = E_join + 1`); no eligibility/overlap/ownership rule exists in `archival-retention` |
| 3 | Scarcity is **per shard** | `r_market_by_shard`, `consensus_state.rs:480–486` |
| 4 | A holder earns `g(age_s) / r_market[s]` | `scarcity_micro`, `reward_arithmetic.rs:71–82`; `shard_contribution_micro`, `consensus_state.rs:536–556` |
| 5 | `r_market` counts pairs that **served**, folded at epoch close | `r_market_count`, `consensus_state.rs:151`; a bond is invisible to it for a full `SETTLEMENT_EPOCH_BLOCKS = 10_000` |
| 6 | Segments freeze **sequentially**, `⌊leaf_count / SEGMENT_LEAF_COUNT⌋` | `segment_freeze.rs:63–72` |
| 7 | `SEGMENT_LEAF_COUNT = 25_992` (`38 × 18 × 38`; `LEAF_BYTES = 128`) | `segment_freeze.rs` (`SEGMENT_LEAF_COUNT` partition assert); `segment.rs` (`LEAF_BYTES`) |
| 8 | CompleteTree is market-excluded from the gather | `bond.is_complete_tree()` membership filter, `consensus_state.rs:475–478` |

### 1.1 The identity that decides this round

Sum input 4 over a shard's holders and `r_market` cancels:

```text
Σ_holders  g(age_s) / r_market[s]  =  g(age_s)
```

**A shard contributes exactly `g(age_s)` to Σwork regardless of how many copies
exist.** Coverage *depth* does not enter the emission denominator; only coverage
*breadth* does — a shard with zero servers contributes zero, and covering it for
the first time adds `g(age_s)` to Σwork and dilutes every other staker.

Three consequences, each load-bearing below:

1. Redundancy is **free to the protocol**. The 1001st holder costs the emission
   nothing and takes a `1/1001` slice from the thousand already there.
2. The steering gradient already exists and is steep: joining a 1-covered shard
   pays `g/1`, joining a 1000-covered shard pays `g/1000`.
3. There is therefore **nothing to "stop paying"** — see `SL-D6`.

---

## 2. `SL-D1` — RULED: consensus assigns nothing; selection stays with the operator

Re-affirms the 2026-07-02 ruling on the evidence of §1.1 rather than on
recollection. The free coverage market is correct: scarce shards pay more,
operators chase the gap, and the gradient is self-correcting because piling onto
a shard raises its own `r_market`.

Consensus assignment is **rejected** and stays rejected. It would replace a
self-correcting market with an allocation queue, and it would need an admission
rule where none exists (§1 input 2).

**Rule-21 reopen:** a measured coverage failure the gradient does not correct —
a shard persistently at zero market coverage while the list shows it at the top.

---

## 3. `SL-D2` — RULED: the list reads BONDED holdings at the tip, not served counts

`r_market` is an epoch-close fold over **served** pairs (§1 input 5), so the
freshest coverage figure anyone can read is up to 10,000 blocks stale and a new
bond is invisible until it has served a whole epoch. A list ordered on it cannot
respond to the bonds being placed against it.

**Ruled:** the list is built from `held_shard_ids` across bond records at the
current tip — the same walk `process_archival_slash_for_epoch` already performs.
The map then moves at **connect**, block-granular.

**Why this dissolves the herd.** Under a stale signal every operator reads the
same under-covered shard and acts on it inside the same two-week window, with
nobody's action visible to anyone else — lagged feedback, and coverage
oscillates. Under a tip-fresh signal, two stakers collide only if they post
inside the same block, and each bond is its own visible dequeue. The queue
drains in order without coordination.

**Strict scarcity ordering becomes safe precisely because the list is
responsive.** It is unsafe only when stale.

---

## 4. `SL-D3` — RULED: derived, never stored

The map is a fold over bond records at the tip. **No table, no journal, no
revert path, nothing to desync on a reorg** — it rebuilds from chain state on
every request. Same posture as the urn's derive-don't-store ruling and the
`ArchivalSealHashCache` precedent.

This is what keeps the whole feature off the genesis-frozen surface.

---

## 5. `SL-D4` — RULED: order by the payout function, with the bonded count as operand

Scarcity is `g(age) / r_market` — **shard age is in the payout**. A list ordered
by bonded count alone disagrees with what actually pays wherever ages differ:
the operator takes the top row, earns less than a row further down, and stops
trusting the list.

**Ruled:** order by the payout function, with the bonded count as operand.
**UPDATE 2026-09-14 (join-adjusted hint):** the displayed profit is
`scarcity_micro(bonded_count + 1, age_milli, age_weight)` — the same function
consensus uses to **pay**, with the tip-bonded count as operand, join-adjusted
so the card answers “what I earn if I take this shard.” `r_market == 0` scores
`0` in `scarcity_micro`, so a zero-bonded Foundation-only shard would otherwise
show zero profit; `+ 1` is the first-holder reading. The GUI projects that
micro figure into expected SKL per epoch (rule 81: money, not `scarcity_micro`).
Cards sort by that figure. The user picks. Nothing consensus-visible moves.

**The property this buys:** the ordering cannot drift from the money as the
curve changes, because there is one definition of the curve. A separate
count-based rule would be a second definition, and two definitions of one
quantity is how two readers come to disagree.

---

## 6. `SL-D5` — RULED: two columns — bonded and served — and the divergence is the signal

The list shows both:

- **bonded** — tip-fresh, responsive, **steers**
- **served** — epoch-closed, proof-backed, **pays**

Their divergence is the most informative cell in the table. A shard with high
bonded and low served is a shard where holders are not serving, which is exactly
where the yield is for whoever does.

**This also bounds the one attack the responsive list opens** (see §9,
suppression): bonding without serving degrades the *hint* while enriching
anyone who disregards it, because `r_market` counts serves and a non-serving
holder is not one. Payment must therefore **never** move off the serve gate —
that constraint is what keeps the attack self-defeating rather than profitable.

---

## 7. `SL-D6` — RULED: filter by a PAYOUT threshold; no coverage cap, no era table

**Rejected: a coverage cap that stops paying** (the proposed 1000 / 2000 / 3000
by era). Three grounds, in priority order:

1. **It saves nothing.** By §1.1 the protocol already pays a fixed `g(age_s)`
   per covered shard. There is no over-payment for redundancy to control.
2. **The cliff is a griefing weapon.** At `r_market = CAP + 1` either every
   holder on the shard goes to zero — one bond floor buys the ability to zero a
   thousand honest stakers for an epoch, repeatable, with no defence available
   to the victims — or consensus must select *which* `CAP` holders are paid,
   which is a new consensus ordering rule over personas and hands persona
   grinding an objective it does not currently have.
3. **The accidental version was already a bug.** `consensus_state.rs:488–493`
   records the D1 fix: a per-shard milli floor applied before summation "zeroed
   every shard past the co-holder cliff." A cap re-introduces that zeroing
   deliberately, with a parameter attached.

A fourth, weaker point, recorded because it is checkable: the challenge math is
sized around `D ≈ 324k` drawable pairs at maturity, which at `k ≈ 3000` shards
is roughly 100 holders per shard. A cap of 1000–3000 needs `D` in the millions —
an order of magnitude beyond what neighbouring mechanisms are provisioned for,
so the parameter would sit unreachable on a frozen surface.

**Ruled instead:** the list is filtered by a **payout threshold** — drop shards
whose expected per-epoch payout at their current bonded count falls below a
floor.

Three properties that decided it:

- **Same units as the decision.** `g(age)/r_market` folds coverage and age
  together, so a deeply-covered old shard and a thinly-covered new one are
  compared on the thing the operator cares about, not on a count that merely
  correlates with it.
- **Self-adjusting across eras.** An absolute coverage number needs a schedule,
  needs revision as the corpus grows, and is wrong between revisions. A payout
  floor has no schedule to maintain and produces a bounded list at any corpus
  size.
- **A non-arbitrary denomination is available.** A shard whose expected epoch
  payout does not clear the cost of bonding and serving it is genuinely not
  worth showing. That floor derives from something real and moves correctly as
  the corpus and the emission move.

**Advisory, not enforced.** The threshold is a wallet number. It carries no
consensus meaning, can be tuned without a fork, and is free to be wrong. The
divergence between "list says don't" and "money says a little, still" is
negligible at the depths where the filter bites: at 1000 copies the money is
saying `g/1000`.

**Rule-21 reopen:** if a filtered shard is later shown to need coverage the
gradient is not delivering, the threshold is the thing to move — never the
reward.

---

## 8. `SL-D7` — RULED: the hint is never an input to anything consensus checks

The list will normally be served by the operator's own daemon, so the
identifiability concern that governs the per-`P` claim source does not apply
here — the answer is identical for every caller, cacheable, and leaks nothing by
being asked.

The residual is a **remote or lying daemon**, which joins the 2d-2
remote-daemon reopen family. A false coverage map steers a bond onto a
well-covered shard.

**The consequence is bounded and self-detecting:** the operator earns less than
expected, and their actual scarcity next epoch disagrees with what they were
shown. What keeps it bounded is that the hint never becomes an input to
anything consensus verifies. **That is a constraint on the RPC, recorded as a
constraint rather than left as a property it happens to have today.**

---

## 9. Wargamed

**Suppression by non-serving bonds.** Bond shard `s` with a throwaway persona
and never serve; `s` reads as covered on the bonded column for up to the slash
horizon (`m = 11` of `n = 13` observed epochs). Coverage guidance is steered
away from a shard that is actually under-served. Cost: one bond floor plus the
eventual slash. **Self-defeating by `SL-D5`** — the reward stays serve-gated, so
whoever ignores the list and bonds `s` earns maximum scarcity. The attack
degrades a hint and advertises a yield.

**Herding.** Addressed by `SL-D2` (responsiveness) and, within equal-value
bands, by randomised tie-break. The genesis form of the tie problem does **not**
arise: segments freeze sequentially (§1 input 6), so a large block of
simultaneously-zero shards is a state the pipeline cannot produce. A new shard
appears alone at the top and stays there until taken. What remains is equal-count
bands among mature shards, which the responsive list drains one at a time.

**Foundation-only shards.** A shard only CompleteTree nodes hold still reads as
uncovered to the market (§1 input 8), so the gradient points at it at full
strength. No special case needed.

**Shard-set overlap between personas.** **Not a finding.** Linkage is `P` →
Principal. "`P` is serving these shards" is public by design — `shard_ids` ride
the bond-post wire in cleartext and
[`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) records that shard
assignments are allowed to be visible. Overlap between two personas' declared
sets is therefore not a linkage channel and must not be priced as one.

**The residual worth naming once.** Persona succession is banned because it
clusters `P1` with `P2` structurally and provably. Shard overlap also clusters
personas, but ambiently and weakly — replication is the design and thousands of
personas share sets, so the channel carries very few bits. The distinction is
one of signal strength, not category. **Parked, not live:** if a `P` → Principal
channel ever opens on one persona, anything that clusters personas generalises
that break across the cluster. Conditional on multi-persona operation being
common, which `1/R` economics argue against.

---

## 10. `SL-D8` — RULED 2026-09-14: reading 1 (all shards remain legal)

Two readings, and they are different systems:

- **Reading 1 — all shards, with an ordering and an advisory payout display.**
  Pure presentation. Leaves `SL-D1` untouched. Any shard remains a legal
  declaration; the list only decides what is *shown* and in what order.
- **Reading 2 — under-covered shards only, as an admissible set.** Restricts
  what is declarable. Creates an admission race that does not exist today —
  the set is derived per height, so a bond assembled at `h` can be inadmissible
  at `h+1` because someone else covered the pick — and would need a
  reference-block pin plus a tolerance rule.

**Ruled: reading 1.** Reading 2 is **rejected** for this round: it would *add*
consensus machinery (an admission rule, an eligible-set, a fork). Do not add
an admission rule, an eligible-set, a persisted coverage table, or a consensus
read of this list (`SL-D3`, `SL-D7`). A lying daemon can only steer a bond onto
a worse-paying shard; payment still uses served `r_market`.

**Rule-21 reopen:** a measured coverage failure the gradient does not correct
that reading 1 cannot present (the `SL-D1` reopen), not a desire to make the
list an admission gate.

### 10.1 Operator picker vs CompleteTree D-3

`first_stake` still takes a **posture**, never a raw `HoldingsKind`. When the
assignment follow-on lands, Market **posts the operator-selected `ShardSet`**.
This round does **not** change `Engine::first_stake` and does **not** discharge
`NoShardsAvailable`. Selection lives in GUI session state only.

### 10.2 GUI never fetches (`SF-D1`)

The GUI never retrieves shard bytes. It only **requests a fetch**. The daemon
is the only process that speaks Tor and `GET /shard/{id}` (`EU-D1`, `SF-D1`:
no wallet-side client). `shekyl-p-fetch` already exists; a GUI-initiated read
is another **scheduler** of the same `fetch(&FetchTarget, &header)` entry
(`SF-D7`), not a second client, not a caller tag on the wire, and not a wallet
SOCKS stack. The only shard-content verb is a daemon JSON-RPC that names
`shard_id`. Destination `P` is the daemon’s organic-style draw (`SF-D10`),
never a GUI parameter. Same in-flight cap `N`; no priority over
challenge/organic (`SF-D7`).

---

## 11. Deliberately not in scope

- **Bootstrap economics at `k = 1`.** At genesis the corpus is one shard
  (`SEGMENT_LEAF_COUNT = 25_992` outputs per shard, roughly one shard every one
  to three weeks at early volume), so every market persona holds the same shard,
  scarcity is `g(age)/N` identically for everyone, and there is nothing to
  select. **Priced and settled elsewhere; not reopened here.** It does mean this
  is a **maturity feature** with no content until `k` is well above 1, and
  therefore not on the genesis critical path.
- **Consensus assignment.** `SL-D1`.
- **Anything touching the reward function.** `SL-D6`.

---

## 12. Rejected alternatives

| Alternative | Rejected because |
|---|---|
| Consensus assigns shards | Replaces a self-correcting market with an allocation queue; no admission rule exists to carry it (`SL-D1`) |
| Parity split — odd slots assigned, even slots chosen | Wallet-side, so unenforceable against anyone not running the default wallet; and it taxes discretion in collateral, the resource an adversary is long of |
| Coverage cap that stops paying | Saves nothing (§1.1); the cliff is a one-bond-floor griefing weapon; re-introduces a zeroing bug already fixed once (`SL-D6`) |
| Absolute coverage thresholds by era (1000 / 2000 / 3000) | Needs a schedule, needs revision, wrong in between; a payout floor self-adjusts (`SL-D6`) |
| Ordering by bonded count alone | Diverges from the payout wherever ages differ; two definitions of one quantity (`SL-D4`) |
| Ordering by served counts | Two weeks stale; cannot respond to the bonds placed against it (`SL-D2`) |
| Dispersive-by-default shard selection for privacy | Defends a property not in the threat model — shard holdings are public by design (§9) |

---

## 13. Disposition summary

| ID | Disposition | State |
|---|---|---|
| `SL-D1` | Consensus assigns nothing; operator selects | **RULED** |
| `SL-D2` | List reads bonded holdings at the tip, not served counts | **RULED** |
| `SL-D3` | Derived from bond records, never stored | **RULED** |
| `SL-D4` | Ordered by join-adjusted `scarcity_micro(bonded_count + 1, age, age_weight)` — RULED 2026-09-14 | **RULED** |
| `SL-D5` | Two columns, bonded and served; payment never leaves the serve gate | **RULED** |
| `SL-D6` | Payout threshold, not a coverage cap; advisory, no era table — filter stays FOLLOWUPS | **RULED** |
| `SL-D7` | The hint never feeds a consensus-checked input | **RULED** |
| `SL-D8` | Available set = all shards (reading 1); reading 2 rejected — RULED 2026-09-14 | **RULED** |

---

## 14. Implementation (opened 2026-09-14)

1. **`get_archival_shard_coverage`** — local fold over bond records; empty
   request; profit hint is `join_scarcity_micro`. No bodies, no aggregates,
   never persisted (`SL-D3`).
2. **`request_archival_shard { shard_id }`** — fourth scheduler of
   `shekyl-p-fetch` (`SF-D1`). Shard bodies sit below the prune window
   (staker hold, or a temporary view-cache after this fetch). Freeze-row
   `R_k` is not a body. GUI names `shard_id` only.
3. **Client-side shuffle** of equal join-profit bands (per-process RNG; not
   consensus).
4. **`SL-D6` payout-floor arithmetic** stays FOLLOWUPS — profit is shown, not
   used as a hide-filter yet.
5. **`SL-D8` reading 1 RULED** 2026-09-14.
