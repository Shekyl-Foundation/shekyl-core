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
  behavior) must be priced explicitly if taken.
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
  than left implicit:** at one challenge per `(P, s, E)`, a maximal bond
  (`MAX_HOLDINGS_SHARDS` = 4,096 × ~3.3 MB ≈ 13.5 GB) serves over one
  settlement epoch (`SEB` = 10,000 blocks × ~120 s ≈ 13.9 days) —
  **≈ 11 KB/s sustained worst case**, trivial against any serving-capable
  link. The full-shard test costs the honest archiver effectively nothing in
  bandwidth; what it costs the zero-storage responder is the point.
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

## 5. First deliverables

1. This record, registered (index row, FOLLOWUPS annotations, probe pause).
2. **A5 re-measurement at shard-size payload** (sim-side, own branch) — the
   corrected margin *in the pruned world*, as TJ's economic baseline; the
   pre-pruning artifact number retained alongside for the record.
3. The TJ-A/TJ-B challenge-spec design pass — the genesis-frozen half.
