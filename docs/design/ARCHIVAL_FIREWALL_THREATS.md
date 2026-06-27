# Archival firewall — adversary model & attack catalog (`how-would-I-attack-this`)

**Status:** DRAFT — first dedicated adversary pass. Prior rounds (cover, standoff,
2d-1 P-scan) established mechanism *correctness*; this doc establishes what a
*named, resourced, patient* adversary actually does, and where the firewall is
currently exposed.
**Scope:** the principal ↔ `P` unlinkability firewall (gate-6) across `P`'s
**operational lifetime**, not a single transaction.
**Parent designs:** `ARCHIVAL_FIREWALL_GATE6.md`, `ARCHIVAL_COVER_DRAW.md`,
`ARCHIVAL_BOND_2D1_PSCAN_PLAN.md`, `shekyl-standoff` (timing draw).
**Process rule:** `26-sub-pr-design-discipline.mdc` (firewall-load-bearing).

---

## 0. Why this doc exists (the reframe)

Every prior analysis answered *"is this mechanism internally sound?"* and almost
all of them answered it **for a single event** — one funding, one bond, one
window. The cover's anonymity set, the standoff's timing draw, the 2d-1 isolation
boundary: each was evaluated against a chain observer looking at *one moment*.

A real adversary does not look at one moment. The adversary is **patient**,
**runs infrastructure**, **participates economically**, and **intersects
observations across `P`'s entire lifetime**. Against that adversary, the relevant
quantity is not "the anonymity set of this funding event" but "the anonymity set
of `P` after the attacker has watched for a year." That quantity is
**monotonically decreasing** and **unmodeled**.

The cryptography is not the exposure. Nobody breaks ML-KEM to find `P`; the hybrid
PQC, the FCMP++ proofs, the burning-bug-immune scanner, and the CT signing path
are the parts an attacker *skips*. Privacy coins are deanonymized through
**metadata, economics, availability, and accumulation** — the soft tissue around
the hard crypto. This doc looks where the keys aren't.

---

## 1. Security goal (stated precisely, with the lifetime qualifier)

> For an adversary holding capabilities **C0–C5** (§2), and for any principal,
> the probability of correctly linking **any** of that principal's `P`-personas
> to the principal — **integrated over `P`'s full operational lifetime** — stays
> below the target unlinkability bound.

Two consequences the per-event analyses missed:

- **Lifetime, not per-event.** A mechanism that gives a large single-window set
  but leaks a little each window fails this goal by accumulation. "Safe per event"
  ≠ "safe."
- **Persona-clustering is itself a partial break.** Linking `P`'s *own* personas
  to each other (without yet reaching the principal) hands the attacker `P`'s
  aggregate footprint — the input that makes every Stage-2 attack work. It must be
  in the goal, not treated as harmless because the principal is still hidden.

---

## 2. The named adversary (capability tiers)

Capabilities are cumulative-ish and independently realistic; rank a concrete
attacker by which tiers they hold. **The patience multiplier (§2.x) applies to all
of them** and is the capability the prior analyses omitted.

| Tier | Capability | What it sees / does | Realistic as | Cost |
| --- | --- | --- | --- | --- |
| **C0** | Global passive chain observer | Every block, the full tx graph, **all public bond data** (`p_canonical_id`, `bond_floor` cleartext — `bond_wire.rs:73`), **all claim txs and their amounts**, all on-chain timing. Retroactive over history. | Anyone. Always assume. | ~0 |
| **C1** | Principal-side out-of-band knowledge | A target principal's real identity + a subset of its spend **amounts and times** (exchange withdrawal logs, KYC desk, chain-analysis clustering of the principal). | Exchanges, regulators, analytics firms | low |
| **C2** | Network observer | Connection existence, source, timing, traffic **volume and pattern**. *C2a* guard-level; *C2b* timing-correlation across the network (the case Tor does not fully defeat). | Guard operators, ISPs, well-resourced passive | low–med |
| **C3** | Infrastructure operator | Runs a daemon/seed node `P` or the principal connects to. Logs requests, **withholds blocks (lies by omission)**, serves stale/partial views, injects a false tip. | Anyone — running a popular seed node is cheap | low |
| **C4** | Bond counterparty | Participates in `P`'s JoinMarket bonds. Sees join coordination metadata, `P`'s signing timing, the join's input/output structure, possibly `P`'s endpoint. Can **Sybil-flood the join**. | Any staker | capital |
| **C5** | Economic adversary | Stakes alongside `P`; observes pool dynamics; **actively moves the cover's standing-bond count** (posts/withholds bonds); stuffs the chain (scan-DoS / inflates apparent inflow). | Any staker with capital | capital |
| **C6** | Local / co-resident | Times or reads `P`'s process (cache/timing side channels). | Malware, shared-cloud co-tenant | varies |

**C6 is largely out of scope, deliberately** (third-option resolution,
`ARCHIVAL_BOND_2D1_PSCAN_PLAN.md` §2 DQ1): a memory-reading co-resident defeats
*everything* (the keys are in the process), so CT-everything scanning only matters
in the narrow timing-without-memory case (shared-cloud staking-as-a-service),
whose mitigation is dedicated hardware, not an all-wallet tax. Named, reopen-gated.

### 2.x The patience multiplier (the omitted capability)

Any of **C0–C5 applied across `P`'s operational lifetime, intersecting
observations**. This is not a new tier — it is the *time dimension* on the others,
and it is where the design is least armored, because no prior analysis modeled more
than one event. Every entry below is evaluated **with** patience, not without.

---

## 3. The kill chain (how the attacker actually sequences this)

An attacker does not link a single persona to a principal in one shot. The chain is:

- **Stage 1 — cluster `P`'s personas into one operator footprint** (Attack A0).
  Without this, intersection has only isolated personas to work with (weak). With
  it, the attacker has `P`'s *aggregate* behavior to match against the principal
  (strong). **This is the precondition for every Stage-2 attack**, and it is
  unaddressed.
- **Stage 2 — link the footprint to the principal**, via intersection (A1),
  induced re-link (A2), economic fingerprint (A3), counterparty (A4), or network
  (A5).
- **Amplifiers** — active moves that shrink the sets Stage 2 works over: cover-
  statistic manipulation (A6), block withholding (A2 is itself active), join
  Sybil-flood (A4).

The defensive implication: **if Stage 1 fails for the attacker — if `P`'s personas
are genuinely unlinkable from each other — the entire intersection attack
starves.** That makes A0 the highest-leverage thing to get right, and it is
currently not analyzed at all.

---

## 4. Attack catalog

Each entry: **capability needed · mechanism targeted · intended defense · actual
efficacy (with patience) · residual · disposition.** Findings are `TM-#`.

### A0 — Cross-persona clustering (Stage-1 enabler) — **UNADDRESSED**

- **Capability:** C0 (+ patience).
- **Targets:** the `p_slot` persona rotation (the forward-secrecy claim).
- **Intended defense:** rotation gives `P` fresh personas; a retired persona's
  identity is not reused (`p_slot` monotone, scan-reconciled).
- **Actual efficacy:** rotation hides *one persona's future*; it does **not**
  hide that several personas share an operator. Candidate correlates an attacker
  clusters on, none currently denied: a **common funding source** (if `P`'s
  personas are funded from a shared pool or in a correlated pattern), **temporal
  exclusivity** (personas that are never simultaneously active — the rotation
  itself implies a hand-off pattern), **shard-selection** similarity (do `P`'s
  personas serve overlapping or patterned shard sets?), **claim-batching rhythm**
  (§A3), and the **`W`-tail lifecycle shape** (every persona unbonds and then
  claims for ~`W` epochs — a recognizable signature). If any of these clusters
  `P`'s personas, the attacker reconstructs `P`'s full footprint *before*
  attempting the principal link.
- **Residual / finding — `TM-1` (highest leverage):** the firewall analyzes a
  single persona's unlinkability to the principal; it has **no analysis of whether
  `P`'s personas are unlinkable from each other**. This is the precondition for
  A1–A5. The rotation machinery is necessary but not sufficient — forward-secrecy
  of one persona is not anonymity of the set.
- **Disposition:** open. Needs its own analysis: enumerate every on-chain and
  behavioral correlate shared across an operator's personas, and show each is
  either absent or independent. Until then, assume the attacker *can* cluster, and
  evaluate A1–A5 against `P`'s **aggregate** footprint, not a lone persona.

### A1 — Intersection / co-occurrence across windows — **UNADDRESSED**

- **Capability:** C0 + C1 (+ patience). The one I'd run first.
- **Targets:** the cover (amount decorrelation) and the standoff (timing
  decorrelation) — by going *around* both.
- **Intended defense:** the cover breaks the single-window *amount* match
  (`A ≠ bond_floor + cover` for a clean `bond_floor`); the standoff breaks the
  single-window *timing* match (≥1-SEB spacing + jitter).
- **Actual efficacy:** both are **single-window** defenses. The attacker watches a
  known principal's activity windows (C1) and, for each, notes the set of personas
  whose funding/bond activity correlates. One window → large candidate set. But the
  principal does **not** rotate, and `P`'s funding cadence is driven by the same
  treasury/human behind it, so **intersecting the candidate sets across many
  windows converges**. This is precisely how Bitcoin clustering and real-world
  privacy-coin deanonymization work — not one transaction, the **accumulation**.
  The cover makes each window's set larger; it does **not** make the intersection
  non-converging.
- **Residual / finding — `TM-2`:** the multi-window intersection set is unmodeled.
  Every cover/standoff analysis was single-event. The real defense is not a bigger
  cover but whether `P`'s funding events are **independent enough across time** that
  the intersection does not converge — and that independence is neither designed
  nor measured.
- **Disposition:** open. Needs a *temporal* anonymity model: the intersection set
  as a function of (#windows observed, cover entropy, funding-cadence
  independence). The lever is funding-event independence over time, not per-event
  entropy.

### A2 — Induced re-link via block withholding — **ADDRESSED in 2d-1 (SP-7)**

- **Capability:** C3 (+ C0 to observe the result).
- **Targets:** the 2d-1 funding reader; the cover's cold-start protection.
- **Intended defense:** SP-6's reconcile reader already has the "don't GC on
  absence" rule (covered-range). Cold-start cover means principal→`P` funding is
  amount/timing-decorrelated.
- **Actual efficacy:** the SP-6 rule protects the **reconcile** reader; the
  **funding** reader has no equivalent. The attacker runs the daemon/seed node `P`
  scans against (C3) and **selectively withholds the block carrying `P`'s cover
  output**. `P`'s funding scan never sees the cover, `P` concludes its funding has
  not arrived, and `P` **re-funds from the principal** — a *second* cold-start
  event, on the attacker's infrastructure, correlated with the first. The attacker
  has **induced** the exact re-link the cover exists to prevent, by controlling
  availability rather than breaking anything.
- **Residual / finding — `TM-3`:** the funding reader needs the same adversarial-
  incompleteness assumption as the reconcile reader. "`P` didn't find its funding"
  must **never** auto-trigger a principal re-fund without `P` first confirming its
  view is **complete against the consensus header root** (which it can — headers
  chain). A missing output must be distinguishable from an unscanned one, on the
  funding side too. This is the funding-side twin of the SP-6 rule and it is not in
  the design.
- **Disposition:** **addressed** — built into 2d-1 as **SP-7** (the funding-side
  completeness gate) plus the root-anchored cursor (SP-2):
  `ARCHIVAL_BOND_2D1_PSCAN_PLAN.md` §6. The cold-start re-fund decision now takes a
  typed `CoverDiscovery::AbsentVerified(VerifiedRange)` only — header-root-complete +
  finality-deep — so a withheld block reads as `Incomplete` (wait), never as absence;
  and even `AbsentVerified` surfaces to the operator rather than auto-re-funding (a
  confirmed-absent cover means the original funding tx failed, so re-fund would *be*
  the second cold-start link). Residual: the header-chain trust itself (false-tip /
  stale-headers) leans on 2d-2's multi-source transport — named there.

### A3 — Economic / earnings-scale fingerprint — **UNADDRESSED**

- **Capability:** C0 (+ C1 to correlate, + patience).
- **Targets:** the reward/claim structure — a surface no scan defense touches.
- **Intended defense:** none specific. The cover standardizes *funding* amounts;
  nothing standardizes *earnings*.
- **Actual efficacy:** rewards are a function of work (shards served), and claim
  transactions reveal **how much** a persona earned → how much work it did → how
  much capital/shard-commitment it has. A large staker has a distinctive earnings
  fingerprint. Cross-referenced with C1 (a principal that withdrew ~`X` capital)
  and A0 (the persona cluster), the **magnitude and cadence of `P`'s economic
  activity is a side channel on the principal's scale**. Monero has no analogue
  because it has no staking; Shekyl's staking *publishes a continuous signal about
  every staker's scale*.
- **Residual / finding — `TM-4`:** the cover standardized the funding *inflow*; the
  earnings *footprint* (claim amounts, claim cadence) is unstandardized and leaks
  `P`'s scale — the same class of leak on the other side of `P`'s lifecycle. Note
  the symmetry with `TM-2`: even if each claim is single-window-safe, the **claim
  stream over time** is a scale-and-rhythm fingerprint feeding A0 and A1.
- **Disposition:** open. Evaluate whether claim amount/cadence should be
  standardized/batched the way funding was (e.g., claim at standardized epochs in
  standardized increments), and whether the `W`-tail claim pattern is itself an
  operator signature (ties to A0).

### A4 — Malicious bond counterparty / join Sybil-flood — **UNDER-ANALYZED**

- **Capability:** C4.
- **Targets:** the JoinMarket bond's collaborative anonymity.
- **Intended defense:** the firewall protects `P` from the *chain observer*.
- **Actual efficacy:** a JoinMarket bond's privacy is only as good as the
  participant set. A co-participant (C4) sees coordination metadata, `P`'s signing
  timing, and the join structure that a pure chain observer does not — and a Sybil
  attacker who **fills the join with their own inputs shrinks the real anonymity
  set toward `P` alone**. The firewall's threat model has, throughout these rounds,
  assumed a *chain* observer; the **counterparty** is a different, closer observer
  that no round has modeled.
- **Residual / finding — `TM-5`:** the counterparty threat model is absent. What
  does a malicious co-bonder learn (coordination endpoint, timing, structure)? Is
  the join's anonymity set against a Sybil-flooding participant ever bounded? This
  is a distinct observer from C0 and needs its own analysis.
- **Disposition:** open. Define the C4 observer explicitly; bound the join's
  anonymity set against a participant fraction `f` of Sybil inputs; confirm
  coordination metadata (timing, endpoint) does not cross to `P`'s identity.

### A5 — Network traffic-pattern correlation — **PARTIALLY ADDRESSED (2d-2-gated)**

- **Capability:** C2 (+ patience).
- **Targets:** the 2d-2 isolated transport; the 2d-1 scan cadence (which constrains
  what 2d-2 can defend).
- **Intended defense:** 2d-2 Arti transport isolates `P`'s network identity. 2d-1
  already pins fetch-everything (no output-selectivity) and the sequential-fetch
  forward-note.
- **Actual efficacy:** Tor hides *content* and *endpoint* but **not traffic
  *pattern*** from a guard-running or timing-correlating observer (C2). If `P`'s
  scan is tick-driven, or bursts after a relevant bond lands, or has a persistent
  connection rhythm, the **pattern** correlates with `P`'s lifecycle even though no
  single request is selective. This is the lowest-skill, highest-real-world-success
  deanonymization of "private" coins (the Lightning lesson: the pattern leaks even
  when each message is encrypted).
- **Residual / finding — `TM-6`:** 2d-1 must not *foreclose* 2d-2's defense. The
  scan **cadence** is a fingerprint surface; SP-5's task must expose cadence as an
  injectable parameter (constant-rate / jitterable by the transport layer), never a
  hardwired wall-clock tick or activity-triggered burst. Cheap now, expensive to
  retrofit once the task hardcodes a timer.
- **Disposition:** carried to 2d-2 for the *fix*; **must be enforced in 2d-1** as a
  no-hardcoded-cadence constraint on SP-5 so the fix remains possible.

### A6 — Active cover-statistic manipulation — **ADDRESSED (residual named)**

- **Capability:** C5.
- **Targets:** the cover response function `f`'s standing-bond-count input.
- **Intended defense:** `f` reads a **count** (not a per-rung histogram) at the
  **last-closed epoch** (slow, finality-deep aggregate). Count-uniform was chosen
  *specifically* because the per-rung histogram was measured to be rung-locally
  targetable (`--cover-targeting`: histogram halves a chosen victim in 5 bonds,
  count needs >8 and only moves global width).
- **Actual efficacy:** the slow last-closed-epoch count is **expensive to move** —
  an attacker must suppress bonds across a full ~10k-block epoch, forgoing real
  staking yield and visibly. The count-uniform response means a manipulator can
  only shift the *global* width, not sculpt one victim's. This attack is the one
  the cover work *did* model adversarially, and the design choice closed the
  surgical version.
- **Residual:** the global-width shift is still a (broad, expensive, visible)
  capability; and the manipulation cost is measured against honest *standing
  occupancy*, which depends on the `EpochCloseInputs.bonds[]` stock read being the
  true standing set (the §correction already made — serving-subset would have
  measured against churn instead).
- **Disposition:** **addressed**; residual is the bounded global shift, accepted
  with the count-uniform + slow-aggregate posture. Reopen if the standing-count
  read regresses to a flow/serving quantity.

### A7 — Bootstrap-cohort exposure — **KNOWN / CONCEDED**

- **Capability:** C0 + C1.
- **Targets:** the earliest stakers (epochs 0–1), where the cover envelope
  `K_sat(C)` is in its `k=0` tail (cover ≈ `C_min`).
- **Actual efficacy:** the genesis cohort has the thinnest anonymity sets — smallest
  live-bond population, narrowest cover. An attacker focusing on epoch 0–1 has the
  best odds across `P`'s whole history.
- **Disposition:** **conceded by design** — the bootstrap tail hands the earliest
  stakers to the `N_P`-independent seams (network isolation + funder-scope), on the
  record (`ARCHIVAL_COVER_DRAW.md` §8.5). Cataloged here as a *known exposure
  window*, not a new finding. Worth a user-facing disclosure: earliest stakers run
  with reduced cover.

### A8 — Cover outflow fingerprint — **UNADDRESSED**

- **Capability:** C0 (+ patience).
- **Targets:** the cover's *spend*, not its receipt.
- **Intended defense:** cover-stays-with-`P` decorrelates the funding **inflow**.
- **Actual efficacy:** the cover becomes `P`'s working capital and is eventually
  **spent** (steady-state funding draws on it). The spend's change outputs, amounts,
  and timing are a fresh on-chain event. The cover decorrelated the inflow; the
  **outflow** may re-introduce a linkable amount/timing pattern, especially if `P`
  spends the cover in a recognizable way (round amounts, fixed cadence) feeding A0/A3.
- **Residual / finding — `TM-7`:** the cover analysis stops at receipt. The
  *spending* of the cover (the steady-state funding draw) is a separate event with
  its own decorrelation requirement, currently unanalyzed.
- **Disposition:** open; folds into the steady-state funding design (2d-1 reader-(a)
  consumer), not cold-start.

---

## 5. Exposure ranking (what I'd actually lose sleep over)

1. **A0 — cross-persona clustering (`TM-1`).** The Stage-1 enabler. If `P`'s
   personas cluster, every other attack works on the aggregate footprint; if they
   don't, the intersection attack starves. Highest leverage, zero current analysis.
2. **A1 — lifetime intersection (`TM-2`).** Goes around the cover and standoff by
   accumulating across windows. The single-event analyses do not bound it. This is
   how privacy coins actually fall.
3. **A2 — induced re-link via withholding (`TM-3`).** A C3 attacker *causes* the
   re-link the cover prevents, cheaply, by controlling availability. Was concrete and
   actionable — **now built (SP-7)**; header-chain trust residual carried to 2d-2.
4. **A3 — earnings-scale fingerprint (`TM-4`).** Staking publishes a continuous
   scale signal the cover never touches.
5. **A4 — join counterparty / Sybil (`TM-5`).** A closer observer than any round
   modeled.
6. **A5 — network pattern (`TM-6`).** 2d-2's job, but 2d-1 must not foreclose it.

A6 (cover manipulation) and A7 (bootstrap) are **addressed/conceded**; A8 (cover
outflow, `TM-7`) is real but routes into steady-state funding.

**The throughline:** the cryptography holds. The exposure is **accumulation,
availability, economics, and the participant set** — the soft tissue. Three of the
top four (`TM-1`, `TM-2`, `TM-4`) are *not crypto problems*, so none of the crypto
armor helps, and *none of them is addressed anywhere in the design*.

---

## 6. The cross-cutting finding (single-window vs lifetime)

Every quantitative analysis in the firewall — the cover's effective anonymity set,
the standoff's draw, the saturation knee — was computed **for one event**. The
adversary integrates over **`P`'s lifetime**. The single-event set is an *upper
bound* on lifetime unlinkability and, for an intersecting adversary, a loose one.

**`TM-8` (meta):** the firewall needs a **temporal** anonymity model — the
linkability probability as a function of observation duration — not a set of
per-event set sizes. Until that exists, "the cover gives set ≈ 10" is a statement
about a moment, not a security guarantee about `P`.

---

## 7. Recommendations

1. **Stand up A0 (`TM-1`) as its own analysis first** — enumerate every shared
   correlate across an operator's personas (funding source, temporal exclusivity,
   shard-selection, claim rhythm, `W`-tail shape) and show each absent or
   independent. It gates the realism of A1–A5.
2. **[Done] Funding-side completeness gate (`TM-3`)** — built into 2d-1 as SP-7
   (`CoverDiscovery` + root-anchored cursor): cold-start re-fund gated on a
   header-root-confirmed-complete view, never on absence, and surfaced rather than
   auto-triggered.
3. **Pin SP-5 cadence as injectable (`TM-6`)** in 2d-1 now — a no-hardcoded-timer
   constraint, so 2d-2 can make the pattern constant-rate.
4. **Open the lifetime/intersection model (`TM-2`, `TM-8`)** — the temporal
   anonymity metric; the lever is funding-event independence over time.
5. **Evaluate earnings standardization (`TM-4`)** and the **counterparty model
   (`TM-5`)** as dedicated passes before genesis.

Each opens with a rule-21 reopen anchor; `TM-3` and `TM-6` are buildable inside the
current 2d-1 round, the rest are pre-genesis analyses parallel to the consensus
path.

## 8. Explicitly out of scope (with reasons)

- **C6 local/co-resident** beyond the CT-compare + seam (third-option resolution);
  a memory-reading adversary defeats the keys directly, so timing-only defense is
  the narrow shared-cloud case → dedicated hardware, rule-21-reopen.
- **Breaking the primitives** (ML-KEM, ML-DSA, FCMP++ soundness, the divisor
  argument) — tracked separately (`AUDIT_SCOPE.md`); this doc assumes the crypto
  holds and attacks around it.
- **Principal-side deanonymization that does not touch `P`** (the principal was
  already KYC'd) — outside the firewall's charter; the firewall protects the link,
  not the principal's own privacy.

## Revision history

- **2026-06-27:** Created. Named adversary (C0–C6 + patience), kill chain (A0
  Stage-1 enabler → A1–A5 Stage-2), attack catalog with `TM-1..8`. Pushes hardest
  on the unaddressed cluster: cross-persona clustering, lifetime intersection,
  induced re-link, earnings fingerprint.
