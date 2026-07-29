# Test ≡ job, and pruning is upstream — the archival market's sequencing ruling

**Status:** Round 0 — two maintainer rulings recorded as binding (2026-07-29);
census verified at source; TJ design questions open.
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
  behavior) must be priced explicitly if taken. **§5.6 settles the same
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
storing 3.3 MB is one-to-one in bytes. It wins because, at equal quantities, the
*price* asymmetry decides — and a transfer costs far more per byte than fourteen
days of disk for the same volume.

### 5.3 Leg 1 — the price argument, and its two falsifiers

The relevant premise is **not** generic bandwidth-vs-storage. It is
**Tor-borne transfer vs storage**, which is a stronger premise than cloud-egress
pricing: Tor capacity is scarce and donated, so its effective cost per byte sits
far above clearnet. That strength is also its narrowness — the premise is
**transport-dependent**, not merely price-dependent.

> **Falsifiers, both of which reopen this leg:**
>
> 1. Either term moves by ~3 orders of magnitude (storage becomes costly, or
>    anonymous bulk transfer becomes ~free).
> 2. **Serving moves off Tor.** The margin is computed against Tor's cost per
>    byte; a clearnet or subsidised-transport serve path is a different ledger.
>    Note this one can fire with **no economic input changing at all** — purely
>    from a transport decision taken elsewhere in the program.

### 5.4 Leg 2 — caching makes the free-rider category *unstable*

The stronger leg, and it does not depend on §5.3's premise at all — only on
storage being cheap, which is the same condition that motivated free-riding.

1. Storage is cheap ⇒ once a shard is fetched to answer a challenge, **discarding
   it is irrational** — retention costs ~nothing and eliminates every future
   fetch for that shard.
2. `held(P,E)` changes only by bond/unbond, so a bond faces **the same shards
   every epoch**. The fetches recur; the cache pays off immediately and forever.
3. Therefore the optimal free-rider strategy **converges on holding**.

So the attack is not blocked — **its own optimum is the honest behaviour.** The
"cheat helper" that downloads and writes to a storage device *is an archiver*,
with extra steps and worse latency.

This is the same closure shape the program has used elsewhere, and the pattern is
worth naming: reopen (c) closed because stuffing is negative-sum *for the
stuffer*; §12.11.1 closed because the mechanism is monotone, leaving no
oscillation to arbitrage. A threat whose rational play is the honest play does
not need a deterrent.

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

## 6. First deliverables

1. ~~This record, registered (index row, FOLLOWUPS annotations, probe pause).~~
   **DONE 2026-07-29** — `IMPLEMENTATION_INDEX.md` `TJ-A…TJ-E` row (registered
   at birth, rule 94); `ARCHIVAL_REOPEN_D_FEASIBILITY_PROBE.md` status
   `⏸ PAUSED`; `FOLLOWUPS.md` grace + `m`/`n` entry annotated
   `⏸ SUPERSEDED IN PART`; `ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md` status
   `⚠️ REVERSED IN PART`, citing this record rather than restating it.
2. **A5 re-measurement at shard-size payload** (sim-side, own branch) — the
   corrected margin *in the pruned world*, as TJ's economic baseline; the
   pre-pruning artifact number retained alongside for the record. §5 is the
   analytic prediction it re-measures against, threshold in §5.1's marginal
   form.
3. The TJ-A/TJ-B challenge-spec design pass — the genesis-frozen half, now
   scoped by §5.6 to *witnessing* a full transfer rather than choosing
   between a compact test and a full one.
