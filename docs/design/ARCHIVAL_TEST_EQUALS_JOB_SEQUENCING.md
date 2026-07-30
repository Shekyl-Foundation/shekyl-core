# Test ≡ job, and pruning is upstream — the archival market's sequencing ruling

**Status:** Round 0 **closed**; **Round 1 OPEN on the witness problem (§8,
opened 2026-07-29)**. Both maintainer rulings binding, census verified at
source. **R1's necessity and sufficiency are both now argued with a
measurement under them** — deliverable 2 landed (§6.2, PR #379), and the
ledger's three legs are *located* rather than pooled: leg 1 price-contingent
(§5.3, within-class per F-1), leg 2 `T_risk` structural and **measured**
(§5.4/§6.2, `q_risk* ≈ 0.10`), and leg 3 build cost **split into its two
incompatible quantities** (§5.7) — 3a acquisition *bytes*, which raise the bar
in the metered cells and go quiet at flat-rate, and 3b engineering/operational
*labor*, which survives flat-rate but is payoff-proportional and
commoditizable and must not be leaned on. Test gates landed
(PR #378): `tj_g_…` red on challenge scope, `tj_f_forged_material…` green on
soundness, the summand weld under the ledger; TJ-F's liveness face carried as
a **type-level obligation** on TJ-A's output, not a test. **Round 1's
witness population is RULED (§8.2, 2026-07-29): miners, not the bonded set.**
Both required properties are already proven rather than designed — indifference
by §12.11.1 Leg 1 (`miner_fee_income` is invariant to the staker share, and
serve credit only redistributes a budget it cannot resize), and liveness by
PoW itself (being selected *is* proof of being online, the only population with
that property). Two rounds of bonded-set mitigation — co-holder exclusion,
denial-tolerant quorums, the `1/r` analysis — are **retracted as design and
retained as diagnosis**: they were engineering around a threat the population
choice manufactured. TJ-A3 **collapses** with it (verification is
deterministic, so disagreement is *evidence*, not a judgment call). **The one
open gate this round does not own:** whether `q ≥ 0.10` is forceable on a
3.33 MB Tor-borne fetch — PD-F-2's dispersion measurement (§8.3).
**Family:** `TJ-*` (registered in `IMPLEMENTATION_INDEX.md` at birth, rule 94).
**Supersedes in part:** the reopen-(d) fork as dispositioned
(`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §12.6) and the reopen-(d)
feasibility probe's charter (`ARCHIVAL_REOPEN_D_FEASIBILITY_PROBE.md`, now
paused — see §4). Records retained, not deleted.

---

## 0. The two rulings

**R1 — the test is the job.** The retention challenge must demand what a
client demands: **the shard**. A ~3 KB `VerifyPath` opening is a synthetic
micro-demand no client makes, and pricing the test three orders of magnitude
below the service is what manufactured the free-rider margin (A5's own
numbers: re-fetch beats holding 4–40× *because* the payload is 3 KB against a
~3.3 MB shard). There is no functional difference between serving the shard to
a client and serving the test — that identity is what the challenge exists to
enforce. This does not overturn gate-2 §0's "fetch-on-demand at test time IS
the service" ruling; it corrects the payload that ruling was applied to. A
proxy that re-fetches the full shard and serves it in-deadline **did** provide
the service — and paid full freight for it.

**R2 — pruning is upstream of the market.** The archival market's product is
**set-B scarcity**: ordinary nodes collapse deep segments to their sub-root
commitment `R_k` and discard the leaves; archivers hold the leaves so deep
spend-path assembly stays possible without universal retention
(`V3_STAKER_ARCHIVAL.md`, set A/B/C table + "Normal nodes vs archivers").
That product is specified but **does not exist yet**: pruned-daemon mode is
unbuilt, every daemon today retains every leaf forever
(`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` fact §2.5, restated at its §6.2
soundness argument), and the foundation's own posture is `--no-prune`
(`V3_STAKER_ARCHIVAL.md` §Problem-2). Until pruning exists, "do you hold set
B for shard `s`" is a question every node answers for free — the possession
test cannot discriminate, and "proxy" is not a coherent category.

**The two-legged necessity (neither ruling suffices alone):** pruning without
a real test pays proxies who re-fetch from the foundation's surviving
`--no-prune` nodes; a real test without pruning pays everyone for bytes they
already have. Pruning makes the good scarce; serving the actual shard makes
the payment for it honest.

## 1. The verified substrate, including the coupling that runs both ways

- Set **A** (wallet-minimum: `R_k` frontiers, owned-output chunks, active
  frontier segment) is held by **every** syncing wallet and lean node, and is
  explicitly "**Not** archiver retention challenges." Set **B** (deep segment
  leaves + shard auxiliary) is the archiver good. Verified at the
  `V3_STAKER_ARCHIVAL.md` normative table.
- "**The daemon retains every leaf forever**" — and this is currently
  **consensus-required**, not incidental: *"serve-credit vin verification
  needs leaf scalars at arbitrary challenged indices"* (fact §2.5). The
  current challenge design does not merely coexist with the unpruned world —
  it **structurally forces** it. No daemon can prune while verification reads
  arbitrary local leaves.
- The segment-freeze reversion clause already names the reconciliation a
  pruned-daemon mode owes (exclude frozen-segment leaves from pruning, or
  reintroduce a materialized chunk store with a designed writer) — it is the
  only place pruned-daemon mode is tracked at all, and it is tracked there as
  a hypothetical.
- The open DRS round (`DAEMON_REDB_STORE.md`) — the daemon storage redesign —
  does not treat pruning. The mode has no design home today.

## 2. What re-classifies (records annotated, never deleted)

- **W10 / A5** — the margin model compared a proxy re-fetch cost against an
  honest storage cost **neither of which exists pre-pruning**: every daemon
  already holds every leaf, so the "honest archiver's" 13.6 GB is not an
  incremental cost and the "proxy's" re-fetch sources are every node on the
  network. The FAIL verdict is re-classified as a **pre-pruning artifact
  measured under a mis-specified payload** — not an incentive-design defect.
  The arm's machinery (absorbing-Markov aggregation, production-predicate
  absorption table) is sound and is retained; it re-runs post-pruning at
  shard-size payload when TJ lands.
- **Reopen (d)** — the fork (grace-tightening vs PoRep) dissolves as
  premature: its premise was a real free-rider margin, which pre-pruning does
  not exist, and post-pruning the R1 payload correction is expected to close
  on cost alone (~3.3 MB re-fetch per challenge versus holding a 3.3 MB
  shard; the §12.6 grace/`q*` machinery becomes deadline-hygiene, not the
  load-bearing deterrent). §11.1's original "whole-shard/PoRep" reopen named
  the whole-shard branch; §12.6's disposition collapsed it to "grace or
  PoRep" — R1 restores the dropped branch. PoRep returns to its original
  posture: independent durable storage, non-genesis.
- **The reopen-(d) feasibility probe** (`PD-*`) — **PAUSED**. Its charter
  presumed the 3 KB-payload `q*` band. Everything ratified in it survives for
  reuse: the parameterized window predicate (PD-D) serves any future
  `(m, n)` re-pin; the conditional-map form and PD-F-2's total-latency/
  dispersion framing feed TJ's deadline design (a 3.3 MB serve over two Tor
  legs needs exactly that analysis). Resumption condition: TJ's challenge
  spec ratified + pruned-daemon mode designed + A5 re-measured under both.
- **The joint grace + `m`/`n` round** (FOLLOWUPS) — its **deterrence
  objective** (`q*` reachability) is suspended with (d); its **false-slash
  objective** (honest transient outages vs the m-of-n window, the
  confirmation pin's §3.2 Round-2 criteria) **survives untouched** — honest
  archivers still have outages and the slash must still not fire on them,
  under any challenge design.

## 3. The sequencing resolution — what is genesis-frozen and what is free

The two rulings split cleanly across the consensus boundary:

- **Challenge-verification semantics are consensus** — wire format, what the
  response contains, what validators check. These freeze at genesis. The
  genesis-critical work is therefore a challenge design that (a) tests the
  full-shard job (R1) and (b) **does not require validator leaf retention**
  — verification against `R_k` (which every node keeps in set A) with the
  leaf-and-path material supplied **by the responder**, so a pruned validator
  can verify what it no longer stores.
- **Pruning itself is node-local storage behavior** — not consensus. Once
  verification stops reading arbitrary local leaves, any daemon can prune (or
  not) **without coordination**, on its own schedule, per rule 75. The mode's
  design home is the DRS round (storage) + the segment-freeze reconciliation
  (its own reversion clause).

This is the answer to "when must each land": **verify semantics pre-genesis;
the pruning mode whenever after** — no coordinated upgrade, no consensus
change post-genesis.

## 4. TJ design questions (Round 0 — open)

- **TJ-A — post-pruning verification mechanism.** The verification substrate
  is settled (responder-supplied leaves + paths verified against `R_k`, which
  every node holds); the open question is what the response must prove — and
  **the two candidates are not equally sound, and 8C §4 already settles the
  asymmetry**: *"`m` independent indices per `(P,s,E)`… bounds partial
  deletion… It does not bound the zero-storage + reacquire adversary, who
  fetches exactly the `m` named leaves (+ siblings) on demand — cost Θ(`m`),
  not Θ(`|segment|`). Raising `m` does not help that adversary until
  reacquisition of one sample is expensive. `m` is the wrong lever until
  §7.5 closes."* That is precisely the sampling candidate: `f^k` bounds a
  responder who holds a fraction and cannot fetch — **partial deletion** — and
  does nothing against `f = 0` with fetch, because `k` unpredictable
  positions are still `k` cheap fetches. Sampling therefore achieves
  test≡job **only if single-sample reacquisition is expensive — a deadline
  argument, i.e. grace-tightening, i.e. the mechanism reopen (d) was
  dissolved for depending on.** **Receipt-attested full transfer is the only
  candidate that gets test≡job structurally** rather than by latency margin;
  its cost is the **witness problem** — consensus stops observing the act
  directly and must trust an attestation of it (challenger honesty,
  collusion, receipt forgery are its threat surface). The round's question is
  therefore not "which of two options" but "is the witness problem solvable
  at consensus grade" — with sampling-plus-deadline as the named fallback
  whose soundness dependency (deadline pressure + reacquisition-source
  behavior) must be priced explicitly if taken.
  **Standing constraint on whatever witness shape wins (TJ-F liveness,
  type-level):** the verify entry point takes **the response (leaf-layer
  chunk included) and `R_k` and nothing else** — no store handle in scope at
  the assembly site. This is a design obligation on TJ-A's output, not a
  branch input: both witness shapes must satisfy it, and it is satisfied by
  exactly the correct fix.
  **Sequencing (ruled 2026-07-29): the A5 shard-payload re-measurement runs
  BEFORE this design pass, not after.** `T_risk` is independent of the
  witness question — it is a function of payload size against the deadline
  and the m-of-n window, not of how the transfer is attested — but its result
  feeds this pass directly: a **large** `T_risk` at 3.33 MB means the
  deterrent is carried structurally and the witness mechanism can be chosen
  on other grounds; a **small** one means the receipt branch is doing more
  work than it looks. Running it first turns TJ-A from a two-way argument
  into a decision with a number under it. **The number is under it (§6.2,
  measured 2026-07-29, within-class per review F-1):** bandwidth closes the
  margin decisively for metered-egress fetchers, **marginally (~1.1×) in the
  within-cloud cheap-transit cell** (the §5.3 reopen's watch-cell), and not
  at all for flat-rate actors — where the deterrent needs
  `q_risk* ≈ 0.10` (+reward) on the whole-shard fetch. The receipt branch
  does real work precisely in the flat-rate cell, and TJ-C's deadline
  question determines whether that cell is reachable: whether `q ≥ 0.10` is
  forceable on 3.33 MB over Tor is exactly PD-F-2's dispersion question,
  now with the threshold it must answer against. **§5.6 settles the same
  asymmetry independently and quantitatively**, which removes this branch's
  dependence on §4's assertion: sampling reaches parity with the full
  transfer only at `k ≈ 26k` — the segment's entire leaf count — so no
  interior `k` buys test≡job. The question is therefore how to **witness a
  full transfer compactly**, not whether a compact test can substitute for
  one.
- **TJ-B — the serve/verify split.** The full-shard serve is off-chain (to
  the challenger at the rendezvous, R1); the consensus artifact proves it
  happened. What binds the off-chain serve to the on-chain proof — the
  sampling indices' unpredictability (drawn at challenge time, answerable
  only with the shard in hand), a challenger receipt, or both.
- **TJ-C — deadline and cadence.** A ~3.3 MB serve over two Tor legs replaces
  a ~3 KB one: `CHALLENGE_RESOLUTION_BLOCKS` and the honest-latency analysis
  re-run at the corrected payload. PD-F-2's dispersion framing transfers
  directly — the proxy's extra leg is now a full-shard transfer, so the mean
  displacement grows ~1000× and dispersion stops swamping it. **The
  bandwidth arithmetic that makes R1 obviously affordable, stated rather
  than left implicit:** at one challenge per `(P, s, E)` — which §5.5 verifies
  is structural, not a coverage policy — a maximal bond
  (`MAX_HOLDINGS_SHARDS` = 4,096 × ~3.3 MB ≈ 13.5 GB) serves over one
  settlement epoch (`SEB` = 10,000 blocks × ~120 s ≈ 13.9 days) —
  **≈ 11 KB/s sustained worst case**, trivial against any serving-capable
  link. The full-shard test costs the honest archiver effectively nothing in
  bandwidth; what it costs the zero-storage responder is the point. The
  profitability threshold this feeds is **marginal, not total** — see §5.1,
  which corrects a 2× form of it.
- **TJ-D — pruned-daemon mode's design home and its two reconciliations.**
  DRS coupling (storage side), segment-freeze reversion clause (frozen-leaf
  exclusion or materialized chunk store), and the serve-credit verify rewire
  (fact §2.5's consensus-required retention must be dissolved by TJ-A before
  any pruning is possible).
- **TJ-E — foundation-source classification (downstream of TJ-A, not
  independent).** Post-pruning, a re-fetcher's source of last resort is the
  foundation's `CompleteTree` nodes — and **what kind of input foundation
  serving policy is depends on which TJ-A branch is taken**. Under
  **sampling**, the foundation is the reacquisition source that makes `k`
  fetches cheap: its serving policy (rate, priority) becomes a **soundness
  input** — the branch's security depends on it. Under **receipt-attested
  transfer**, re-fetching full freight through the foundation is just an
  expensive way to do the job, and serving policy stays an **economics
  question** outside consensus. TJ-E is resolved after TJ-A, in TJ-A's
  terms.
- **TJ-F — verification must fail against a poisoned leaf store.** *(Referred to
  as **RED-2** in review; that label has no registered family and no prior home
  in `docs/`, so it is registered here in `TJ-*` — rule 94 — with the alias kept
  for traceability.)* The property: a responder supplying leaf-and-path material
  must not be able to make verification **succeed** against leaves that are not
  the committed ones. Post-pruning this *is* the scheme's soundness — the
  validator no longer holds the leaves, so `R_k` is the only thing standing
  between a supplied response and an accepted lie.
  **Three properties make this the item to do first, ahead of TJ-A:**
  1. **Genesis-frozen** — a property of what validators check, so it freezes
     with the wire semantics (§3).
  2. **Testable against current code today** — the `R_k`-anchored verify
     machinery already exists (8C §§2–4, 6, retained by the reversal as the
     verification substrate). It does not wait on pruned-daemon mode.
  3. **Independent of TJ-A** — it holds identically whether the response is a
     sampled opening or a receipt-attested full transfer. Both supply material
     checked against `R_k`; both are unsound if a poisoned store verifies.

  TJ-F therefore **freezes behaviour rather than concept** — the opposite posture
  from TJ-A/TJ-B, where the concept is unresolved and behaviour is not yet
  freezable. It is the genesis-critical work that is blocked on nothing.
  **The property has two faces, and their artifacts differ in kind**
  (2026-07-29, corrected same day — the first cut hedged a question that was
  never open):
  - **Soundness face** (a test, GREEN, frozen): responder-supplied material
    must not verify against non-committed leaves — holds at the pure-function
    level today (`recompute_subroot != R_k` rejects, tampered leaf-layer
    material rejects); `tj_f_forged_material_does_not_verify` pins it so the
    rewire inherits it.
  - **Liveness face** (a **type-level constraint, not a test**): the verify
    entry point takes **the response (leaf-layer chunk included) and `R_k`
    and nothing else** — no store handle in scope at the assembly site.
    **The chunk's origin was never open**: if the validator could derive the
    chunk from what it retains, there would be no archival market — the
    market exists precisely because validators pruned the leaves down to
    `R_k`. "Responder supplies the chunk" is the premise the system rests
    on, not a TJ-A branch; TJ-A's actual open question is only **how a full
    transfer is witnessed compactly** (receipt-attested vs
    sampling-with-priced-deadline). With the origin fixed, local-leaf reads
    become *unrepresentable* rather than tested-against — the same move as
    numerics-as-data and the admission predicate — and the constraint is
    satisfied by exactly the correct fix.
  **Why the liveness face is not a red test (recorded so it is not
  re-attempted):** an empty-material "store-free verification succeeds"
  assertion is **un-greenable by the correct fix** — the corrected assembly
  site definitively passes a *populated* chunk from the response, so success
  against `Vec::new()` can only be achieved by a verifier that skips the
  leaf-in-layer check, which the soundness test then catches. The pair is
  jointly unsatisfiable; such a test was cut from the PR #378 branch. The
  sharper fact the hedge obscured: **`verify_segment_path` is not the broken
  component** — its signature (`leaf_bytes, leaf_layer_scalars, path, rk`)
  already takes material as arguments with no store handle; it is already
  pruned-validator-compatible, and the fix may not touch it at all. What is
  broken is **upstream**: today the caller fills `leaf_layer_scalars` from
  local leaf reads (fact §2.5 in code form); tomorrow it fills them from the
  response bytes. Same function, different source — enforced by signature.
- **TJ-G — the challenge's scope is the whole segment.** *(Alias **RED-1**;
  registered here per rule 94, same motion as TJ-F.)* Phrased at the
  **challenge-construction** level, not the response level: a challenge for
  `(P, s, E)` names **all `SEGMENT_LEAF_COUNT` = 25,992 leaves**, not a
  subset. That phrasing survives both TJ-A branches — under receipt-attested
  transfer the on-chain artifact is compact by design, so "response payload ≥
  segment bytes" would be the wrong assertion and would break the moment the
  right answer landed; **scope-of-challenge is the invariant, witnessing is
  what TJ-A decides**. The test mechanically rejects sub-shard sampling: any
  `k < 25,992` leaves it red, which converts §5.6's finding (sampling fails
  on its own cost ledger) from a paragraph someone must re-derive into a CI
  gate. RED today: `challenge_leaf_index` derives exactly one index per
  `(P, s, E)`. `#[ignore]`d with TJ-A's landing as the un-ignore trigger —
  the D1 red-test pattern.

## 5. The ROI ledger — why R1 closes it, and what the closure rests on

R1 is justified by an ROI argument, and this is where that argument lives. Other
records **cite** this section rather than restating it (8C's Round-2 reversal
already does).

The bar is deliberately soft: **free-riding does not have to be impossible, only
unprofitable.** Impossible would be better; it is a higher bar than the market
needs and a much higher one than any mechanism here reaches.

### 5.1 The threshold is marginal, not total

The honest holder pays a local read (free) plus the upload. The free-rider pays a
download **plus the same upload**. The uploads cancel. So the free-rider's total
is ~2× the test's bandwidth, but its *marginal* cost over the honest party is the
**download alone**:

> **Free-riding wins iff `cost(1 shard transferred) < cost(1 shard stored for one
> epoch)`.**

Stated once, precisely, because an earlier formulation of this ruling used the
free-rider's **total** (2×) in a comparison that is inherently marginal. Anyone
deriving a break-even from that version would inherit a **2× safety margin that
does not exist**. The verdict is unchanged; the margin is half what the 2× form
implies.

### 5.2 Why R1 wins is not why the opening lost

Worth separating, because they are different mechanisms and only one of them
carries a premise:

| | Opening (3 KB) | R1 (full shard) |
| --- | --- | --- |
| bytes moved vs bytes avoided | ~1 : 1000 | **1 : 1** |
| decided by | **quantity** | **price per byte** |

The opening failed on a quantity ratio — three orders of magnitude in the
cheater's favour. **R1 does not win on quantity**: transferring 3.3 MB to avoid
storing 3.3 MB is one-to-one in bytes. Removing that 1000× is the whole of what
R1 does, and it is necessary. It is **not sufficient**, because at equal
quantities the decision passes to price per byte — and §5.3 shows that
comparison is **ambiguous**, not favourable. The load-bearing margin is
elsewhere (§5.4).

### 5.3 Leg 1 — the bandwidth-vs-storage comparison is **ambiguous**, not favourable

**Correction (2026-07-29).** An earlier version of this section claimed a
transfer "costs far more per byte" than an epoch of storage, and an earlier
framing of the ruling put free-riding "two orders of magnitude underwater."
**Both overclaim.** The ratio is

```text
T / S  =  (transfer $/GB)  /  (storage $/GB-month × epoch-in-months)
```

with the epoch ≈ 13.9 days ≈ 0.457 months. Worked at three plausible
infrastructure assumptions:

| Free-rider transfer | Honest storage | `S` per GB-epoch | `T / S` | who wins |
| --- | --- | --- | --- | --- |
| clearnet egress ~$0.01/GB | cloud ~$0.02/GB-month | ~$0.0091 | **≈ 1.1** | ~tie |
| clearnet egress ~$0.01/GB | amortized consumer disk ~$0.0002/GB-month | ~$0.000091 | **≈ 100** | honest |
| flat-rate residential (marginal ≈ $0) | any | — | **→ 0** | **free-rider** |

So this leg spans roughly **0 to 100 depending on whose infrastructure you
assume**, and it *inverts* in the flat-rate case. It is not a margin; it is a
coin-flip that depends on facts outside the protocol's control.

The Tor framing narrows but does not rescue it. Tor capacity is scarce and
donated, so effective cost per byte sits above clearnet — but that makes the
premise **transport-dependent as well as price-dependent**, and it can be
falsified two ways:

> 1. Either term moves by ~3 orders of magnitude (storage becomes costly, or
>    anonymous bulk transfer becomes ~free).
> 2. **Serving moves off Tor** — which can fire with **no economic input
>    changing at all**, purely from a transport decision taken elsewhere in the
>    program.

**Verdict: this leg cannot carry the ruling.** It is retained as context, not as
justification. R1's necessity does not depend on it — removing the 1000×
quantity asymmetry (§5.2) is required regardless — but R1's *sufficiency* has to
come from §5.4.

### 5.4 Leg 2 — **risk**, not caching. (And why the caching leg was withdrawn.)

**Withdrawn (2026-07-29): the caching argument is not an independent leg.** It
was recorded here as one, and it does not survive its own algebra.

The argument ran: storage is cheap, so once a shard is fetched, discarding it is
irrational; `held(P,E)` changes only by bond/unbond so the same shards recur
every epoch; therefore the rational free-rider converges on holding, and the
attacker *category* dissolves. The failure is that **"keep after fetch is
rational" and "free-riding is unprofitable" are the same inequality**:

| Question | Condition |
| --- | --- |
| Is keeping a fetched shard rational? | `S < T` |
| Is free-riding unprofitable? | `S < T` |

where `S` = storage for one epoch, `T` = one transfer. So in the only world where
the caching argument is *needed* — `T < S`, transfer cheap enough that
free-riding pays — discarding after each fetch is **also** optimal, and nothing
converges. The leg assumed "storage is cheap" in an absolute sense, but the
operative comparison is storage *relative to transfer*, which is the profitability
test itself. It restated the conclusion as if it were evidence for it.

This matters beyond the local claim: the same reasoning was briefly generalized
as a technique across reopen (c) and §12.11.1. Those two survive — **reopen (c)
is negative-sum by accounting and §12.11.1 is monotone by construction**, both
structural. TJ's convergence was **contingent on prices**, and it does not belong
in that family.

**The genuinely independent leg is risk.** The free-rider bears an exposure the
holder does not:

```text
T_effective = T_bandwidth + T_risk
```

`T_risk` is the expected cost of fetch failures — a fetch that misses the
challenge deadline against the m-of-n window, and the bond that a sustained
failure run slashes. A holder answering from local disk simply does not have
this term: a local read cannot miss a deadline the way a Tor-borne 3.33 MB
transfer can, and it has no dependence on a third party's availability.

`T_risk` is **structural — it exists at any byte price**, which is precisely what
§5.3 lacks. It is also the term R1 *inflates*, and by much more than the payload
ratio suggests: PD-F-2's total-latency/dispersion framing transfers directly, and
a 3.33 MB Tor-borne fetch inside a fixed deadline has a **far heavier tail** than
a 3 KB one. The free-rider does not merely move 1000× more bytes; it moves them
through a two-leg anonymous path against a deadline, every shard, every epoch,
with a slashable bond behind it.

**So the ROI conclusion rests on `T_risk`, and `T_risk` is not yet quantified.**
That is deliverable 2's job (§6), which is therefore **decisive rather than
confirmatory** — it is not re-running a corrected number, it is measuring the
term the ruling now stands on. The retained A5 machinery (absorbing-Markov
aggregation, production-predicate absorption table) is the right instrument for
exactly this.

**Honest interim status of R1:** its *necessity* is established — the 1000×
quantity asymmetry is real and removing it is required. Its *sufficiency* is
**argued but unmeasured**, resting on a `T_risk` term whose magnitude is
predicted (heavier tail at 1000× payload) but not computed.

### 5.5 Coverage is per-`(P,s,E)` **structurally** — it cannot be coarsened to per-`P`

The whole ledger assumes every claimed shard is tested every epoch. If a bond
claiming 4,096 shards faced one challenge per epoch, the arithmetic inverts and
coverage — not payload — would be the fix. **Verified, and it is not a policy
knob:**

```text
work_P(E) = Σ_{s ∈ held(P,E)} scarcity(s,E) · serve_credit_bit(P,s,E)
```

Per-shard is the **summand index of the emission formula**. Each held shard
contributes only if its own `serve_credit_bit(P,s,E)` is set, so a bond claiming
4,096 shards that produces one passing proof **earns on one shard** — the other
4,095 terms are multiplied by zero. Answering fewer shards is not a weaker test
evaded; it is reward forfeited.

Independently welded in two places:

- *"Per-`(P,s,E)` granularity | Emission `work_P(E)` | **Cannot coarsen without
  breaking `R_market` / Σwork**"* — `ARCHIVAL_CORPUS_FOSSIL_SWEEP.md` §granularity table.
- *"a fixed **shard** axis (per-`(P,s,E)`) — **not coarsenable without breaking
  Σwork / `R_market`**"* — `ARCHIVAL_TIMING_CONSTANTS.md`.

This is the same property the escalation's operand has: **the thing that would
have to break for the argument to fail is load-bearing elsewhere**, so it cannot
drift silently. Coarsening coverage is not a weaker deterrent — it is a broken
emission formula.

At full coverage the honest cost is the bandwidth arithmetic already in TJ-C
(≈ 11 KB/s sustained worst case); the free-rider pays that **again as download,
every epoch, forever**, to avoid a standing 13.6 GB.

### 5.6 Consequence — TJ-A's sampling candidate fails on its own cost ledger

8C §4 rejects sampling by assertion (*"`m` is the wrong lever until §7.5
closes"*). The ROI ledger settles it **independently and quantitatively**, which
matters because it removes the dependence on that assertion.

Grounded units: the leaf is **128 bytes** (8C §6.2 PQC note) and a level-2
segment is **≈ 26k leaves** (§7.2.2) — consistent with the ~3.3 MB shard, since
26,000 × 128 B ≈ 3.33 MB.

A free-rider answering `k` sampled positions fetches `k` leaves per shard per
epoch:

| `k` | fetched per epoch (4,096 shards) | vs 13.6 GB storage avoided | verdict |
| --- | --- | --- | --- |
| 100 | ~52 MB | ~1 : 260 | free-riding **wins** |
| 1,000 | ~520 MB | ~1 : 26 | free-riding **wins** |
| **≈ 26,000** | **~13.6 GB** | **1 : 1** | parity — **and this is every leaf** |

Sampling reaches parity only when `k` approaches the segment's entire leaf count,
at which point **it is the full transfer**. There is no interior `k` that buys
test≡job.

**So TJ-A's question is narrower than "two comparable options."** The compact
on-chain artifact is not a rival branch that trades soundness for succinctness —
it fails its own cost ledger at every `k` short of the whole shard. The real
question is:

> **How is a full transfer witnessed compactly?** — not whether a compact *test*
> can substitute for one.

Sampling survives only in the form §4 already named: sampling **plus a deadline**
that makes single-sample reacquisition expensive — i.e. grace-tightening, the
mechanism reopen (d) was dissolved for depending on. If that is taken, it is
taken as a latency argument with its soundness dependency priced, not as a
structural achievement of test≡job.

### 5.7 Leg 3 — **build cost**, which is *two* thresholds, not one

**An equivocation cleared before the legs are stated (2026-07-29).** "Build
cost" was used for two incompatible quantities, and they behave differently
across the ledger's cells, so they are separated here and never pooled:

- **3a — acquisition bytes.** The 13.6 GB moved to *obtain* the holding.
  Denominated in **transferred bytes**, therefore ~0 at flat-rate.
- **3b — engineering and operational labor.** Building and running the
  free-rider subsystem at all. Denominated in **labor**, therefore *not*
  zeroed by a flat-rate link.

Neither subsumes the other: 3a is a bytes-horizon asymmetry, 3b is a
threshold on whether the tooling gets written. They cover different cells.

#### 5.7a — Acquisition bytes, and the horizon error they fix

**What it is.** An archiver must *acquire* set B before it can hold it: one
inbound pass over `MAX_HOLDINGS_SHARDS · SHARD_BYTES` ≈ **13.6 GB**. Call that
`B`. Under test≡job, a challenge round for a maximal holding moves the **same
13.6 GB** — so `B ≈ T`, one full rebuild, and the free-rider pays it **every
epoch**.

**The horizon error this fixes.** §5.3 compares one transfer against one epoch
of storage. That is the right *ratio* on the wrong *time-base*, because the two
sides amortize differently. Over `N` epochs:

```text
honest      =  B  +  N · S          (build once, store forever)
free-rider  =  N · B                (rebuild every epoch, store nothing)
```

Free-riding wins iff `N·B < B + N·S`, i.e. `B < S · N/(N−1)`. At `N = 1` the
free-rider always wins; as `N` grows the condition tightens to **`B < S`** —
and the honest side's *average* per-epoch cost falls to `S` while the
free-rider's stays at `B` forever. So the honest build is a **one-time barrier
to entry that the free-rider pays perpetually**. That is the threshold-raiser:
free-riding must beat storage not once but every epoch, against a competitor
whose entry cost is already sunk.

**The scaling inversion.** The honest archiver pays `B` at the chain size when
it joins, and thereafter only the **marginal** build — the newly frozen
segments, one increment per freeze. The free-rider's rebuild is over the
**accumulated** holding, which grows without bound (the very growth D2's
escalation exists to fund). So the two costs diverge with chain age: honest
marginal cost collapses toward storage-only, free-rider cost grows linearly in
history. The leg is weakest at genesis and strongest exactly where the archival
market is load-bearing — the opposite slope from a bound that decays.

**Commoditization caveat (the reopen).** `B` is denominated in the same
transfer price as §5.3, so it inherits that section's contingency and adds one
of its own: if bulk set-B transfer becomes **commoditized** — a caching or
re-serve layer, or foundation `CompleteTree` nodes serving cheaply at scale —
then `B` falls toward zero and the leg weakens with it. That second path is
**TJ-E's** question, which is why TJ-E is a *soundness* input and not only an
economics one: the source of last resort can commoditize the rebuild it is
supposed to make expensive.

**Scope — profit-motivated free-riders only.** This leg closes the *economic*
category: an actor who free-rides **because it is cheaper**. It says nothing
about an actor who pays the rebuild for non-economic reasons (Sybil reach,
censorship positioning, or to appear as an archiver while holding nothing). That
adversarial category is bounded elsewhere — the bond floor, the m-of-n slash,
and the GF-7 reach analysis — and must not be treated as covered here. Naming
what an argument covers is the same discipline §5.4 applied when the caching leg
was withdrawn.

**What 3a does NOT do.** Because `B` is priced in transferred bytes, it **does
not rescue the flat-rate cell**: where marginal transfer ≈ 0, `B ≈ 0` too, and
the perpetual-rebuild argument goes quiet exactly where §5.3 inverted. In that
cell the surviving *byte-priced* barrier is not cost but **capacity against a
deadline** — 4,096 rebuilds inside `CHALLENGE_RESOLUTION_BLOCKS` — which is
**TJ-C's** question, not an independent leg.

#### 5.7b — The labor threshold (and why it is a threshold, not a defense)

The honest archiver's marginal engineering cost is **zero**: it runs the
shipped daemon, retains, and serves. The free-rider must build a **subsystem
that does not exist** — suppressing retention while appearing to retain,
intercepting challenges, maintaining a live source map over a *churning* bonded
set, deadline-bound fetch with retry and failover, and local verification
before submit. That is engineer-months plus ongoing operations, set against a
payoff measured in **single-digit dollars per bond-year**.

Denominated in **labor**, so it survives the flat-rate cell that zeroes 3a: a
residential ISP makes transfer free; it does not make software free to write or
a real-time distributed fetcher free to operate. Its **scaling inversion** runs
the same direction as 3a's — the honest path's effort stays flat as holdings
grow while the free-rider's source map, failover surface, and operational
burden grow with the holding.

**But it is explicitly a barrier *proportional to payoff*, not an absolute one
— and it must not be leaned on.** It is commoditizable (one competent
implementation, published once, drops every subsequent free-rider's cost to
running it) and it is **no defense at all against a determined builder**. It
raises the threshold at which the tooling gets written; it does not decide
anything above that threshold. Same scoping as 3a: **profit-motivated actors
only** — an adversary with non-economic motives pays the engineering and the
labor leg says nothing.

#### 5.7c — The ledger, per cell, with every leg located

| cell | leg 1 (price) | leg 3a (acquisition bytes) | leg 3b (labor) | leg 2 (`T_risk`) |
| --- | --- | --- | --- | --- |
| metered retail | decisive (~11×) | **raises it further** (perpetual vs sunk) | raises the entry bar | not needed |
| metered cheap transit | marginal (~1.1×) | **converts the coin-flip into a standing asymmetry** | raises the entry bar | backup |
| flat-rate | inverted | ~0 — quiet, with leg 1 | the only surviving *cost* leg, but payoff-proportional and commoditizable | **carries the cell**, `q_risk* ≈ 0.10` |

So the flat-rate cell rests on **`T_risk` + TJ-C's deadline + a labor threshold
nobody should lean on.** That is why §8.3 treats the deadline as a **named
gate** rather than an assumption: it is load-bearing, and the labor leg
underlines that rather than softening it.

## 6. First deliverables

1. ~~This record, registered (index row, FOLLOWUPS annotations, probe pause).~~
   **DONE 2026-07-29** — `IMPLEMENTATION_INDEX.md` `TJ-A…TJ-E` row (registered
   at birth, rule 94); `ARCHIVAL_REOPEN_D_FEASIBILITY_PROBE.md` status
   `⏸ PAUSED`; `FOLLOWUPS.md` grace + `m`/`n` entry annotated
   `⏸ SUPERSEDED IN PART`; `ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md` status
   `⚠️ REVERSED IN PART`, citing this record rather than restating it.
2. ~~**A5 re-measurement at shard-size payload**~~ **✅ MEASURED (2026-07-29,
   `feat/a5-shard-payload`, `tj_shard_payload_report` — payload threaded as
   the explicit operand; the opening-payload report retained as the labeled
   pre-pruning artifact; existing test pins are the inertness check).** The
   numbers, at the modeled bands (per-shard slash scope, `m=11/n=13`,
   `SKL_FIAT_PRICE_BAND[1]`):
   - **Bandwidth alone flips the margin at both band ends** (`q* = 0`) — but
     the honest headline is **within-class** (review F-1: one actor has one
     infrastructure class, and the cross-class 26–263× paired the cheapest
     storage against the dearest bandwidth): **decisive for a metered-egress
     fetcher** (retail ~11× within cloud-class), **marginal (~1.1×) for a
     cheap-transit cloud actor** — the cell that quietly inverts if either
     term moves, and the one the §5.3 price-contingency reopen watches — and
     **not at all for a flat-rate one**, where `T_risk` decides.
   - **Break-even fetch price `$0.0004/GB`** (26× below bulk transit) — the
     §5.3 price-contingency as one number: only a flat-rate/residential
     fetcher below it escapes the bandwidth closure.
   - **`T_risk(q)` (the price-independent leg, sub-break-even world):** ~0
     through `q = 0.05` (the m-of-n window absorbs isolated misses), then
     steep — `$0.0046`/epoch at `q = 0.10` (+reward), `$175`/epoch at
     `q = 0.278`. **`q_risk* = 0.1011` (+reward) / `0.2792` (bond-only)** —
     near the old `q*` band, with the residual **attributed** (review F-2):
     A5's crossover solves `T_risk(q) = S − T_bw(opening)` and its band ends
     were quoted at specific fetch prices; `q_risk*` solves `T_risk(q) = S`
     exactly. The slash model is payload-independent *inputs aside*, and the
     zero-payload crossover equals `q_risk*` identically — welded by test.
   - **TJ-A steering readout:** the deterrent is band-wide structural at
     modeled prices; in the sub-break-even world it needs `q ≥ 0.10` on a
     3.33 MB Tor-borne fetch inside the TJ-C deadline — far more forceable
     than the same `q` on 3 KB (PD-F-2 dispersion), but *whether* the
     deadline forces it is PD-F-2's measurement; the sim sweeps `q` and
     asserts no Tor-tail parameter. The R2 caveat applies to every number
     here: neither cost exists until pruned-daemon mode ships.
3. **TJ-F (RED-2) — poisoned-leaf-store verification**, sequenced **ahead of**
   TJ-A: genesis-frozen, testable against current code today, and independent of
   which TJ-A branch is taken. It freezes behaviour rather than concept and is
   blocked on nothing.
4. **TJ-G (RED-1) + the per-`(P,s,E)` summand weld** — the challenge-scope red
   test (`#[ignore]`d, TJ-A un-ignore trigger) and a green test pinning that a
   bond claiming `n` shards with serve-credit on `j` earns work on **exactly
   `j`** — the granularity §5.5 rests on, currently asserted by adjacent tests
   (`bonded_without_serve_credit_not_in_r_market`,
   `drop_after_serve_credit_counts_toward_work`) but not as the summand
   property directly.

## 7. Implementation blast radius — so TJ-A scopes as what it is

The challenge change is a **four-surface change, not a Rust-local one**, and
the TJ-A design pass must specify it as such: **Rust**
(`shekyl-archival-retention`: `wire.rs` response format, `path.rs` opening
verification, `serve_credit_decisions.rs` decision logic), the **FFI**
surface those cross, and **C++** (`blockchain.cpp` `txin_archival_serve_credit_response`
verification, ~:3190) — plus KAT regeneration and whatever rule-42
version-constant surface the wire change touches. dev's code currently does
the thing dev's docs call the defect, and nothing fails; TJ-G's red test,
TJ-F's soundness test, and TJ-F's entry-point signature obligation (the
liveness face, enforced type-level at implementation) are what close that
gap until the implementation round lands.
4. The TJ-A/TJ-B challenge-spec design pass — the rest of the genesis-frozen
   half, now scoped by §5.6 to *witnessing* a full transfer rather than choosing
   between a compact test and a full one.

## 8. TJ-A/TJ-B Round 1 — **the witness problem** (charter, opened 2026-07-29)

Opened on the strength of deliverable 2 (§6.2 measured) and the landed test
gates (§7). This round designs **how a full transfer is witnessed compactly**.
It does not re-open what the ledger already settled.

### 8.1 Inherited, not re-litigated

The round starts from these as **closed**, and a cycle spent rediscovering any
of them is wasted:

1. **The branches are not comparable.** Sampling at any `k < SEGMENT_LEAF_COUNT`
   fails **three independent ways**: on its own cost ledger (§5.6 — ~52 MB/epoch
   at `k = 100` against 13.6 GB of storage avoided, ~1:260), on 8C §4's
   zero-storage-plus-reacquire text (cost `Θ(m)`, not `Θ(|segment|)`; *"`m` is
   the wrong lever"*), and **in CI** — `tj_g_red_challenge_names_every_segment_leaf`
   is red at every `k` short of 25,992. The round is therefore **not** choosing
   between receipt and sampling.
2. **Sampling survives only as sampling-plus-a-priced-deadline** — which
   reintroduces the latency dependency reopen (d) was dissolved for needing. If
   taken, it is taken as a *latency argument with its soundness dependency
   priced*, never as a structural achievement of test≡job.
3. **The material's origin is not open.** The responder supplies the leaf-layer
   chunk; a validator that could derive it from retained state would have no
   market to price (§4 TJ-F). The **standing constraint** on whatever shape wins:
   the verify entry point takes **the response and `R_k` and nothing else** — no
   store handle in scope at the assembly site.

### 8.2 The witness population: **miners**, not the bonded set

**Ruled 2026-07-29, superseding this section's first two drafts.** Round 1
opened by proposing challengers drawn from the **bonded persona set**, then
spent two rounds designing mitigations — co-holder exclusion, denial-tolerant
quorums, the `1/r` denial-to-monopolize analysis. Those mitigations were the
tell. **The bonded set is the population whose members have a financial
interest in the verdict**, and every one of those mechanisms was engineering
around a threat the population choice *manufactured*. Same shape as the ~3 KB
opening (§5.2): an efficiency-looking choice that creates the problem, followed
by machinery to contain it.

**Process note, recorded because the failure mode is named in the rules:** the
error survived two rounds of review because each round verified the *execution*
of the population choice and never re-grounded the *choice*. That is
`reground-the-whether-not-just-the-how` — verifying a costly decision's
mechanics while assuming its necessity.

#### The witness is a **miner**, and both required properties are already proven

**1 — Indifference, proven at source by our own prior work.** §12.11.1's Leg 1
established that `staker_pool_share` applies to `burned_amount` while
`miner_fee_income = total_fees − burned_amount`, so the staker share **never
enters miner income** — pinned across the whole `n` domain by
`escalating_the_share_never_touches_miner_income` (`shekyl-ffi`). We proved that
to show the D2 escalation could not harm the security budget. It now does
**double duty as the witness-indifference proof**: serve credit moves value only
*within* the archival budget's distribution (`reward_share_floor` is
`credited/Σwork` over a budget the credit does not resize — and §8.2's earlier
conservation finding shows a denial merely *redistributes* a shard's fixed
pool), so **a miner's income is invariant to whether `P` passes or fails.**
Structural, by the arithmetic — not policy, not an exclusion rule. This is the
property the co-holder-exclusion machinery was trying to *manufacture*, sitting
in the tree already.

**2 — Liveness, and this is the property no other population has.** A witness
drawn from a set with no liveness signal can be **offline at challenge time**,
and an offline witness produces a stalled challenge that is
**indistinguishable from a denial** — the prior scheme's failure mode was a
liveness fault wearing the costume of the attack it defended against. A bonded
archiver up 99 % of the time is down 1 % of the time, with nothing on-chain
saying which. **Miners are the only population where being selected *is* proof
of being online at that instant**, because PoW is a liveness attestation:
block production is the one thing on this chain an absent party cannot fake.
Not the best available option — **the only population with the property at
all.**
*Precision (do not over-read):* a block proves liveness at the **selection
instant**; the transfer window that follows still needs the witness to stay up.
Recently-mined is the highest-probability-online population available, not a
guarantee across the window — which is an argument for `m`-of-`n` and for the
selection window's width, not against miners.

#### TJ-A3 **collapses** — deterministic verification leaves nothing to adjudicate

Verification is deterministic: recompute the sub-root from the served bytes and
compare to `R_k`. Two consequences, and together they dissolve the dispute
*problem* while keeping a dispute *path*:

- **Honest witnesses cannot disagree.** There is no measurement to disagree
  about; there is a hash comparison.
- **`P` cannot serve two different valid responses**, because exactly one
  byte-string reproduces `R_k` — any correct response is *the* correct
  response.

So disagreement is **not a judgment call to adjudicate; it is itself evidence**
that either a witness misreported or `P` **served selectively** (a newly named
and newly *detectable* attack: serving honestly to one witness and not another).
With a quorum, **majority resolves and the outlier is a signal rather than a
puzzle** — the dispute path's job shrinks from "who is right about a contested
measurement" to "identify which party misreported a deterministic computation,"
and attribution is mechanical.

#### What remains — a smaller and different set

- **TJ-A1 — miner selection.** Which miners, over what window, derived how?
  The beacon idiom (`challenge.rs`) now applies to a set that is **already
  enumerable from block headers**, so the "membership over a permissionless
  population" obstacle is gone: recent block producers are consensus-visible by
  construction. Open: window width (recency buys liveness confidence, breadth
  buys unpredictability), and whether selection is per-challenge or per-epoch.
- **TJ-A2 — miner/bonder overlap, and the quorum's much weaker job.** A miner
  who also bonds *does* carry the denial interest, and it **cannot be excluded
  structurally**: excluding it would require linking miner identity to persona,
  which the privacy architecture forbids (**G-1** — cross-identity linkage is
  unavailable, and buying it here would be a priority-#2 regression to purchase
  a priority-#3 property). So the quorum no longer defends against a
  *systematically misaligned* witness population — only against the **fraction
  that happens to overlap.** That is a far weaker requirement, and it is the
  argument for `m`-of-`n` over a single witness. The overlap *rate* is the
  quantity to bound, and it is bounded by economics (bonding is capital-gated)
  rather than by exclusion.
- **TJ-A2b — witness obligation, with one shape ruled out now.** Indifference
  cuts both ways: an indifferent miner has no reason to *bother*.
  - **Paid** — gives a stake in *witnessing* without a stake in the *verdict*.
    Compatible with the indifference proof; the shape to develop.
  - **Optional** — risks nobody doing it; a liveness fault by another route.
  - **Block-validity requirement — RULED OUT EARLY (hazard).** It would couple
    block production to a 3.33 MB Tor transfer completing inside the block
    interval, putting **archival serving latency on the mining critical path**.
    That is the invalid-blocks failure class the template/connect `n` agreement
    was careful about (§7): a consensus rule whose satisfaction depends on a
    network transfer produces unmineable-or-invalid blocks under ordinary
    latency variance. Do not revisit without a mechanism that decouples the
    validity condition from the transfer's completion time.
- **TJ-A2c — quorum size, where the trade INVERTS from the earlier reading.**
  Every witness receives the full shard, so `n` witnesses mean `n` transfers —
  and the sizing question lands on **miners**, who are latency-sensitive in a
  way archivers are not, so the ceiling may be lower than it looks. Scale as a
  formula rather than an invented number: `challenges/block = (bonded (P,shard)
  pairs × CHALLENGES_PER_EPOCH) / SEB`, times `3.33 MB` times `n`, against the
  L11 population envelope (`N_P` lean ≈ 79 / thick ≈ 154 / fee-era-thin 17–62)
  and the holdings distribution — the product spans trivial to several MB/s and
  the round must sweep it, not assume it.
  **The finding that inverts the trade:** raising `n` **dilutes the deterrent**.
  Honest `P` pays `n` egress; free-riding `P` pays `n` egress **plus one
  ingress** — the differential is *one fetch, constant in `n`*, while the shared
  cost grows linearly. So the cost ratio falls from ~2:1 at `n = 1` toward
  ~1:1 as `n` grows: **large quorums erode the very asymmetry §5.7a
  establishes.** Combined with denial-tolerance wanting `n` large (§8.2's
  retained analysis) and miner bandwidth wanting `n` small, that is a
  **three-way tension with two of three pushing small.**
- **TJ-A2d — the escape worth evaluating first: `k`-of-`n` over SEQUENTIAL
  challenges, not `n` simultaneous witnesses.** Make the epoch carry `n`
  challenges, each witnessed by **one** miner, and require `k` passes.
  Properties, each of which addresses one arm of the tension above:
  1. **Deterrent ratio preserved** — each challenge is one transfer, so the
     free-rider pays one ingress *per challenge* rather than one per epoch.
  2. **Denial tolerance without simultaneity** — a single denier costs `P` one
     challenge, not the epoch; denial needs `n − k + 1` denials across
     independently-drawn witnesses.
  3. **Miner bandwidth spread** across the epoch instead of concentrated.
  4. **And it multiplies the deterrent directly:** `CHALLENGES_PER_EPOCH` is
     **`1` today** (`constants.rs:11`), which is the rate deliverable 2's
     measurement assumed. Raising it to `n` multiplies the free-rider's
     per-epoch transfer by `n` while honest storage is unchanged — which is
     exactly the lever that could lift **§5.7c's marginal cheap-transit cell**
     (~1.1×) out of coin-flip territory. **This is a measurable claim, not an
     argument:** it re-runs through the same `tj_shard_payload_report` machinery
     by changing one operand, and Round 1 should measure it rather than assert
     it.
  *Caveat to check, not to wave away:* a free-rider who **holds between**
  sequential challenges pays one ingress for `n` challenges, collapsing (1) —
  but holding between challenges **is archiving**, which is the honest
  behaviour. That is a *mechanism* observation and must not be restated as the
  withdrawn caching *argument* (§5.4): it does not prove free-riding
  unprofitable, it observes that the cheapest way to pass `n` sequential
  challenges is to become an archiver.

#### Retained, as diagnosis rather than design (retraction hygiene)

The bonded-set analysis is **not deleted** — it is why that population was
wrong, and it stays correct on its own terms:

- **False denial is the strictly easier attack.** False attestation makes `P`
  earn, raising `Σwork` and diluting the attester — costly, so it must be
  **purchased**. False denial lowers `r_market(s)`, raising the denier's own
  `scarcity_micro = g/r` **unilaterally, no counterparty, no bribe.**
- **It scales as `1/(r−1)`** — ~0.1 % at `r = 1000`, **100 % at `r = 2`** —
  strongest exactly where stakes are highest, enabling
  **denial-to-monopolize**: deny co-holders on a scarce shard until the m-of-n
  window slashes them out, then hold the maximal scarcity term alone;
  self-reinforcing, since each departure raises the next denial's payoff.
- **Per-shard pool conservation.** Shard `s` contributes `C·g` to `Σwork`
  regardless of `r`, so denial *redistributes* rather than inflates — which is
  what makes a **non-interested** witness (a miner) indifferent by
  construction, and what made a co-holder witness structurally interested.
  ("No incentive," not "bit-exact invariance": two flooring stages leave a
  residue in the rounds-against-the-claimant direction.)
- **The indirect channel** (a slash's bad interval excludes the bond from
  `r_market` **everywhere** — `epoch_close_bad_interval_excludes_bond_everywhere`)
  is why co-holder exclusion could never have been sufficient: a challenger
  sharing *any* shard with `P` profits from `P`'s exit. Under miner selection
  this collapses to the overlap fraction (TJ-A2).


### 8.3 The named gate — TJ-C's deadline is a dependency, not this round's answer

The round **does not pin its own answer** to a question it does not own — the
same discipline PD-F applied when it named a band obligation without inventing
the number:

> **Gate (open):** is `q ≥ 0.10` forceable on a **3.33 MB Tor-borne fetch**
> inside `CHALLENGE_RESOLUTION_BLOCKS`? The **threshold** comes from
> deliverable 2 (`q_risk* = 0.1011` with the reward forfeit, §6.2); whether the
> deadline **forces** it is **PD-F-2's dispersion measurement** (total
> challenge→response latency, two Tor legs, circuit-latency dispersion as the
> load-bearing parameter) — **unmeasured**.

The gate's two outcomes are different rounds:

- **Forceable** ⇒ sampling-plus-priced-deadline becomes live again and the fork
  genuinely has two options; TJ-A weighs them.
- **Not forceable** ⇒ receipt-attested transfer is the **only** branch, and this
  round is really *a design of the attestation* — §8.2 is then the whole scope.

Either way the flat-rate cell (§5.7's table) is where the receipt branch does
its real work, and this gate determines whether that cell is reachable.
