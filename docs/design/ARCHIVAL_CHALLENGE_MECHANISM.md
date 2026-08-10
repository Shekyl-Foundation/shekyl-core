# Archival challenge mechanism — design round (2026-08-07)

**Status:** **Design-round output. Direction ratified; mechanism NOT ratified
for implementation.** The ruling of record from this round: challenge
assignment is **derived, not committed** (§2, ruled 2026-08-07 — "the more the
system regulates itself, the better"; derivation makes challenges verifiable
by anyone and scope-limited against DDoS). Everything else here is the round's
grounded state: settled constraints, one schema-gating finding (§4), and the
open forks (§7) that must be resolved **in this document or a successor, not
implicitly in code**. Do not cut consensus code from this document until it is
marked ratified.
**Revised 2026-08-07 (same round, after full-doc review + TJ/FOLLOWUPS
grounding):** §3 quantitative case; §4.2 under-coverage collapse into expiry;
§4.4 Phase-4 equivalence-KAT supersession; §6 no-pay-lemma recast; §7 fork 2
restructured to witness selection with standing-record statuses (open-witness
struck); §8 standing-record reconciliation; §9 order-statistic W₂ target.
**Revised 2026-08-08:** attribution impossibility ruled (§7 preamble) —
forks 3 (expiry⇒miss) and 6 (no pay, forced) and the obligation half of
fork 2 (routine duty, norm-borne) are CLOSED; the peer-contrast penalty is
withdrawn; the (m, n) re-pin is promoted to sole surviving enforcement
instrument, carrying the common-mode-β constraint.
**Revised 2026-08-08 (later): TJ-H RULED** — padding field reserved, no
scheme specified, mitigation moved to the Tor layer (full vanguards +
Bandguards re-derive + fetch rate-limiting); guard-holding active
confirmation recorded as accepted residual; the circuit-construction
oracle named as the real exposure. TJ-H no longer gates the round.
**Revised 2026-08-10: fork 1 RULED — exact-min urn**, tail accepted with
the arithmetic on the record (both curves at 10⁻⁷ and below against the
outer window); band and adaptive band not built; prunability merits
answered at source; the capped-regime figure (72 % unobservable)
relocated to §8 as the tx-carrier justification. **Live remainder:
fork 2's selection + nonce anchor (with TJ-B's format spec), W₂, (m, n)
re-pin.**

**Lineage.** Successor to the Phase 3 (settlement writer) scope of
`ARCHIVAL_CREDIT_WIRE.md` (TJ-B step 3). The credit-wire admission surface
(CW-1..CW-3, PR #410) is landed and unaffected. This round replaces the
settlement fold's *inputs* (pass-priority over reported records → 2-of-3
majority over derived challenges) and therefore reshapes Phase 3 before it is
built. Anchors below verified against `dev` (2026-08-07, ≥ `ba223846`); per
standing rules, re-verify at file:line before planning — docs drift.

---

## 1. Problem and settled doctrine

Archivers post bonds under personas (`p_id`) and earn emission for storing and
serving shards (3,326,976-byte deterministic partitions). The unit of
obligation is the pair `(P, s)`. The system must test that archivers actually
store what they claim:

- **Serving earns:** `work_P(E) = Σ_s scarcity(s,E) · serve_credit_bit(P,s,E)`
  (`ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md` §5.5;
  `rust/shekyl-archival-retention/src/reward_arithmetic.rs`).
- **Sustained failure slashes:** per-`(P, s)` sliding window over observed
  epochs; misses ≥ m of the last n observations trigger a slash
  (`apply_archival_slash_one`, `db_lmdb.cpp:5836`). The real penalty is loss
  of the emission position; at ~14-day epochs
  (`SETTLEMENT_EPOCH_BLOCKS = 10_000`), a slash requires ~6 months of
  sustained failure.

**Settled doctrine (do not redesign):** coverage is exhaustive, not sampled —
every bonded pair is challenged every epoch. Structural: the emission formula
indexes per shard (§5.5; welded in `ARCHIVAL_CORPUS_FOSSIL_SWEEP.md`,
`ARCHIVAL_TIMING_CONSTANTS.md`).

## 2. The lifecycle under derived assignment (the ratified direction)

**Selection is a pure function of chain state.** The assignment for block h —
which pair is challenged, and the window in which the read must resolve — is
derived from block h−1's hash over the epoch's drawable set (§4 defines
drawable). Every node computes it identically; nothing is recorded for
selection. Grinding the assignment costs discarding a valid block (a full
block reward), as in the TJ round.

**There is no commitment record.** The prior design's Phase B (an explicit
in-block "I am challenging (P, s)" record, with window W₁ between selection
and commitment) is **superseded**: since assignment is derivable, the block
*is* the commitment, and W₁ dissolves. Recorded as considered-and-superseded,
not deleted, because the commitment record was the previous answer to putting
the denominator on-chain — the denominator is now derived (§4).

**Grounding note — this ruling dissolves a documented dead-end.** The
audit-by-omission retraction (FOLLOWUPS, credit-wire round, 2026-08-02) found
that a commitment riding the same block as the records is post-hoc — the
miner picks its pair list *after* learning outcomes — and that fixing it
needed the commitment on-chain **before** the reads: "a two-block protocol
requiring the miner to win twice — dead on arrival." Derived assignment is
that fix without the obstacle: the assignment is public at h−1's publication,
before any read, with no second win required.

The read itself (unchanged from the TJ round):

1. The witness pulls the **entire shard** over P's onion rendezvous.
2. The witness verifies the bytes against the shard's leaf hash `R_k` — the
   response is self-authenticating.
3. P countersigns the session nonce, proving the read reached P's link
   (nonce construction: `attestation_wire.rs:191` — the anchor key is fork
   §7.2, see below).
4. The pass record is broadcast as a transaction; any miner may include it
   within the resolution window **W₂**.

**A miss is never asserted.** It is the expiry of a derived challenge with no
pass recorded within W₂. No miss record exists on the wire; no party attests
failure; there is no 49-byte fabrication path. To manufacture a miss you must
suppress a pass for W₂ blocks — a censorship capability, not a write.

**Satisfaction does not drain the pool, and the redraw floor (both
ratified):** a pair whose epoch requirement is already met (two passes)
**remains drawable** and can receive its third test — it doesn't have to,
but it can (maintainer, 2026-08-07: "this is not an OR"). Settlement is
monotone, so a post-satisfaction result cannot change a settled epoch. What
continued drawability buys: P stays obligated and indistinguishable for the
whole epoch (it can never infer "done for E; further reads are organic"),
and — structurally — the draw derivation **never reads outcomes**:
concentration onto under-covered pairs keys on challenges *issued* (itself
derived), never on pass records, so the drawable set stays the epoch-open
snapshot all epoch and mid-epoch records never feed the draw function
(which is also what keeps the set reorg-stable, per the note below).
*Ledger note (trade knowingly made, 2026-08-07):* the earlier
drain-on-pass shape concentrated remaining draws onto non-servers as
servers exited — an incentive nicety this refinement gives up (everyone
converges to 3 issued regardless of outcomes). It was never load-bearing,
and extending indistinguishability through the epoch tail is worth
strictly more: a P that can detect "done for E" can de-provision for the
tail. The
scheduling floor, in the form the maintainer ratified: **a pair that fails
its first challenge must be re-drawn before the epoch closes, with high
probability.** That is what makes the epoch's settlement an observation
rather than a coin flip, and it is the floor any §7.1 variant is measured
against. It also gives the anti-evasion exponent: a colluding witness must
intercept *every* draw a pair receives, succeeding with probability q^k
rather than q — at q = 0.1, one draw per epoch is a 10 % shield, two is
1 %.

**Anti-DDoS scope property (part of the ruling):** deriving from the
*previous block's hash* strictly limits how far ahead challenge windows are
knowable, so an attacker cannot precompute P's obligated-to-serve schedule.
This property is in tension with exact-coverage scheduling — that tension is
fork §7.1, not something to resolve silently.

**Reorg semantics fall out for free:** a `pop_block` leaves nothing to void —
assignments re-derive on the new chain; a pass record anchored to a reorged
block loses its anchor. The prior round's open item 3 answers itself. Two
refinements: consensus-free is not cost-free — a voided pass means the
witness's read is wasted and P re-serves under the re-derived assignment (an
economic residual, not a consensus one). And §4.1's quantization quietly buys
a property worth naming: drawability is evaluated at epoch open, which is
deep history relative to any plausible reorg, so the **drawable set is
reorg-stable** — only assignments churn, never the set.

## 3. Nested measurement: 2-of-3 within an epoch, m-of-n across epochs

Two nested systems, and the nesting is load-bearing:

- **Inner (per epoch):** each drawable pair receives 3 derived challenges in
  E, ideally distinct witnesses. `serve_credit_bit(P,s,E)` is set iff **≥ 2
  of 3 resolve as passes**. Replaces landed pass-priority (an OR gate and a
  biased estimator): liar containment ~3f²(1−f)+f³ (0.134 at reference
  f≈0.23 vs 0.54 under any-pass-of-3); honest availability a=0.90 survives at
  0.972; unanimity rejected (converts service test into uptime test).
- **Outer (across epochs):** the failure window counts **epoch outcomes** —
  m misses of the last n *observed epochs* slashes
  (`failure_window.rs`, `archival_failure_window_slashable`,
  `db_lmdb.cpp:5714`).

The quantitative case (run at §9.6's f ≈ 0.23 — stale, but the shape holds
for any f):

| rule | liar passes an epoch | honest P at a = 0.90 |
| --- | --- | --- |
| 1-of-1 (today) | 0.23 | 0.90 |
| 1-of-3 (pass-priority at n = 3) | 0.54 | 0.999 |
| **2-of-3** | **0.134** | **0.972** |
| 3-of-3 | 0.012 | 0.729 |

Pass-priority is an OR gate — a *biased* estimator that reports Served on the
best single sample — which is why raising n under it more than doubles the
liar's rate (the 1-of-3 row is the trap). Majority-of-three is unbiased and
variance-reducing, improving both directions at once. Against the outer
window it is decisive: the liar needs 3 effective passes in 13 epochs —
expected 13 × 0.23 = 2.99 under one draw (sitting exactly on the threshold),
1.74 under 2-of-3; in collusion-fraction terms the rule holds to f ≈ 0.32
rather than 0.23. Unanimity is rejected because it converts the service test
into an uptime test: at availability a = 0.60 (degraded but still serving),
3-of-3 expects ~10.2 misses against a threshold of 11 — inside tripping
noise — while 2-of-3 expects 4.6. Two further axes: the free-rider deterrent
`n·I − S` rises from ~1.09× to ~2.09× at n = 3 (S/I ≈ 0.91, §9.5), and a
single colluding entity needs two friendly witnesses per epoch — per-epoch
success ≈ 3q²(1−q)+q³ at hashrate share q (0.10 at q = 0.2, vs 0.20 under
one draw).

Consequence for parameter work: the outer window's per-observation error
rates are the **2-of-3 tail probabilities**, not raw per-challenge rates. A
Missed epoch is now the stronger claim "failed a majority," so
**(m, n) = (11, 13) must be re-derived, not carried forward** (with §9.6
attestation-resistance as a co-objective).

## 4. Three-valued settlement, drawability, and the schema-gating finding

Per `(P, s, E)`, settlement is one of **Served** (≥2 of 3 passed), **Missed**
(challenged, <2 passed — an observation, counts in the outer window), or
**Non-observation** (not legitimately challengeable in E — the outer window
never sees the epoch).

### 4.1 The finding that gates the schema (verified at source)

The round's draft sourced non-observation from bond state
(`market_member_at_epoch`, `consensus_state.rs:126`) and retired the beacon
`archival_baseline_observed_at_epoch` (`db_lmdb.cpp:5631`). **That is a type
gap:** `market_member_at_epoch(join_epoch, settlement_epoch, bad_intervals,
is_foundation)` takes **no `shard_id` and no height** — it is structurally
incapable of the beacon's decisive third leg,
`archival_bond_holds_shard_of(p_id, bond, shard_id, h_fire)`
(`db_lmdb.cpp:5711`): the per-shard, as-of-fire-height holdings read that
enforces **P2B-7 Pin 5** ("the partial add epoch is forfeited in both
directions", `db_lmdb.cpp:5648`). Re-sourcing from bond state alone flips a
mid-epoch-added shard's epoch from non-observation to Missed — a slash bias
against a not-yet-obligated pair.

**Resolution (part of the derived-assignment ruling): the leg relocates; it
does not vanish.** Drawability is quantized to epoch boundaries — a pair is
drawable in E iff it held the shard at E's open. A mid-epoch add is not
drawable until E+1, which *is* Pin 5, enforced in the draw-set derivation
instead of checked at settlement. Evaluation at a fixed pre-challenge height
also satisfies the WS-1 constraint (no tip-holdings read that would let P
drop the shard after the fire and escape — `db_lmdb.cpp:5654`).

With that, the beacon **retires with nothing lost**: leg 1 (`good_through`)
is subsumed by the drawable-set definition, leg 2 (settledness timing) is
implicit at settlement time, leg 3 lives in drawability. The property the
beacon defended — **the observation boundary is chain-derived, never
producer-reported** — is preserved and is the fabrication/omission
containment (formerly finding F-4).

### 4.2 Under-coverage and absent-row semantics

The prior round's item 2 ("if only 2 of 3 commitments materialize…") and the
Pin 5 question were one item pulling opposite directions on the same epoch:
not-drawable must settle non-observation; drawable-but-unchallenged must
**not** (or omission is a slash escape). Under derived assignment the two
cases live in different sets by construction: not-drawable pairs have no
assignments; drawable pairs have a derived schedule. Whether the schedule
guarantees exactly 3 is fork §7.1; **if** it does, "under-covered epoch"
stops existing as a settlement state and **absent-row ⇒ non-observation ⇒
not-drawable holds by construction**, which defuses the prune-horizon hazard
(`failure_window.rs` prune const-assert) cleanly. If §7.1 lands on a variant
without exact coverage, the settlement writer must instead enumerate drawable
pairs and write a row per pair (explicit Missed on zero passes), restoring
the same absent-row invariant at the cost of one row per drawable pair per
epoch — the same cardinality the emission gather already walks.

One property holds across every §7.1 variant and disposes of the suppression
worry (a colluding witness shrinking the denominator being cheaper than
winning two of three): the denominator is **derived, never counted from
records**. What was posed is a pure function of chain state, so suppression
cannot shrink it — a challenge that produced no pass is not missing from the
denominator, it is an **expired challenge**, and what an expired challenge
counts as is exactly fork §7.3. "Under-covered epoch" is therefore not a
separate settlement state (and "2-of-2 vs non-observation" is the wrong
dichotomy): it collapses into expiry semantics.

### 4.3 Storage: a new table, never a widened bit

Settlement outcomes go to a **new settlement-outcome table**. Widening
`m_archival_serve_credit` is ruled out **by construction, not convention**:
it has four consumers, all reading key-presence as "served" —

- old-vin dedup (`blockchain.cpp:5307`),
- slash-window walk (`db_lmdb.cpp:5763`),
- fast-path miss check (`db_lmdb.cpp:5793`),
- emission gather (`db_lmdb.cpp:7801`) — a **pure presence cursor-walk**
  (`:7804`, no value-byte gate): any key written becomes a `credit_pairs`
  entry feeding `r_market`/`σ_work`.

Writing a Missed cell there corrupts vin-dedup and emission simultaneously.

### 4.4 Landed-code casualties (expected, not discoveries)

- `settle_epoch` (`attestation.rs:75`) rewrites: a majority rule needs the
  derived denominator, not a pass multiset. Pass-priority retires. The
  rewrite carries a named sub-decision (fork §7.1): the threshold under
  variable issued-count — **absolute ≥ 2 passes (the lean)** vs
  majority-of-issued — with under-issued (< 2) epochs settling
  non-observation under the lean.
- `EpochSettlement::to_observation` **deletes** (not re-documents): its
  "sole bridge to the m-of-n machinery" role belonged to the superseded
  design.
- `CHALLENGES_PER_EPOCH = 1` (`constants.rs:11`) retires **as a
  guarantee**: it is the rate the TJ deliverable-2 measurement assumed and
  it is consumed by the economics sim's bandwidth arithmetic
  (`shekyl-economics-sim/src/proxy.rs`). Moving to 3 changes the *meaning*
  of the window's input, not a tuning value — re-derive alongside (m, n)
  and re-run the sim arithmetic that scales with it.
- `archival_baseline_observed_at_epoch` retires per §4.1 — on the Half-B
  deletion surface, after drawability lands.
- **The Phase-4 equivalence KAT is superseded with them.** The prior plan's
  cutover proof compared a shadow settlement cell against the vin-written
  bit, flipping the readers only after the two agreed. That comparison is
  now meaningless *by design*: 2-of-3 over derived challenges is supposed
  to disagree with the self-served vin. Pre-genesis there is no live chain
  to migrate — the cutover is code lineage — so the proof obligation
  becomes KATs against this mechanism's **own spec** (boundary epochs, the
  §4.1 drawability edge, the fold exercised through the actual slash scan,
  per the CW-3 block-through-the-shim discipline), never agreement with the
  path being deleted. `ARCHIVAL_CREDIT_WIRE.md` carries the old sequencing
  and now points here.

## 5. Ordering: fold-before-gather, plus one uncovered assert

Settlement for E must be written at epoch close **before**
`gather_archival_epoch_rows` (`db_lmdb.cpp:7660`) computes
`r_market`/`σ_work` — the gather runs at close(E); the slash scan trails by
`SLASH_SETTLEMENT_TIP_LAG_EPOCHS = 2`. Design toward a **structural gate**
(the reader requires a settlement witness token as an argument) rather than
call-sequence ordering.

**Standalone catch, wanted regardless of everything else:** the connect
order is slash-then-close (`blockchain_db.cpp:579-580`), safe only because
the slash lag is 2 epochs — and the existing const-assert
(`ARCHIVAL_FAILURE_WINDOW_N + lag ≤ MAX_CLAIM_AGE_W + 1`,
`failure_window.rs`) bounds the **prune horizon**, not this coupling. The
slash-reads-what-close-wrote ordering has **no static assert coupling the
two derivations**. Add one when this lands.

## 6. Economics (context; nothing here is derived yet)

- **Witness compensation — a standing lemma applies; this is NOT a simple
  gap to fill.** `reward_arithmetic.rs` has no witness term, and the
  2026-08-02 record (FOLLOWUPS, credit-wire round) rules **no witness pay,
  as a lemma**: every pay conditioning that fixed one abuse reopened the
  other, *because the miss was the only free record and the outcome the
  only discriminator* — pay-withheld-on-contradiction gives the witness a
  stake in P's failure (funds flood-to-slash); unconditional pay subsidizes
  padding. Coverage was ruled **norm-borne** with `λ_eff` as its loud
  tripwire. **This round deletes the lemma's premises:** the miss record no
  longer exists (a miss is expiry, §2), sets are public and derived (no
  secret-set steering; no set choice for pay to bias). Whether the lemma
  survives premise deletion is an **on-record reopening question** — argue
  it against the sealed 2026-08-02 text, not past it — and fork §7.2's
  abandonment penalty cannot be sized until it is answered.
- **Resolution candidate (2026-08-08): routine duty, no payment, penalty on
  demonstrated abandonment.** The duty case: challenge cost scales with
  hashrate exactly as the block reward does — a 1 % miner performs 1 % of
  challenges for 1 % of the reward, no cross-subsidy, nothing to arbitrage —
  the signature of a duty already priced into the block reward, like
  validation, relay, and chain storage; and consensus penalizes invalid
  blocks rather than paying for valid ones, while explicit payment creates
  the discretionary market whose conditionings the lemma catalogued. The
  honest disanalogy, stated so the duty framing doesn't overclaim:
  validation is self-enforcing (skip it and you build on garbage);
  challenging is not — a block ignoring its derived assignment is valid —
  which is why 2026-08-02 landed on norm-borne. **What is new under 2-of-3
  is a discriminator requiring no assertion:** three witnesses read the
  same pair in the same epoch, so two passes plus one silence is evidence
  of the silent witness's inaction, not P's failure. The lemma's dilemma
  was conditioning on *outcome* versus not conditioning at all;
  peer-contrast conditions on neither — the witness cannot manufacture its
  peers' passes, and P cannot frame the third without serving two and
  thereby earning its own credit. If the checks below hold, the lemma
  resolves **without being overturned**: its premise was single-witness
  observation, which 2-of-3 replaced. Checks gating the ruling:
  1. **§9.4 license — VERIFIED at source, and it constrains the shape.**
     TJ-A5(i): adjudication is "statistical, over repetition, not forensic
     over a single disputed event." A penalty firing on one epoch's
     contradiction is forensic and unlicensed; firing on a cross-epoch
     pattern is licensed — converging with what check 2 independently
     forces.
  2. **Correlated timing / path flakiness:** P dying mid-epoch, or Tor
     flakiness, produces the same two-passes-one-silence signature as
     abandonment — so the penalty must fire on a pattern across epochs,
     never a single contradiction.
  3. **Framing:** a colluding P serving exactly two witnesses to frame the
     third gains nothing (the epoch settles Served either way) —
     self-defeating as evasion but available as griefing; price it, don't
     assume it away.
  4. **The aggregation-subject problem (found verifying check 1; gates the
     licensed form):** a cross-epoch pattern needs a persistent subject,
     and miners are pseudonymous by design — coinbase keys are unlinkable
     across blocks, and linking them is the cross-identity purchase the
     privacy architecture forbids (G-1). So under §7.2(a)/(b) the witness
     has no cross-epoch identity: the licensed pattern form has no
     subject, while the implementable per-event form (natural vehicle: the
     assignment block's own coinbase, still inside its lock window at
     settlement) is exactly the forensic shape check 1 forbids and check 2
     breaks. Candidate escapes — a bonded witness set (reopens §8.2's
     population analysis and loses PoW-as-liveness) or per-event penalties
     with a tolerance calibrated to measured failure rates (a priced risk
     premium on honest miners) — are design work, not footnotes.
  One boundary holds regardless of how the checks land: **the
  discriminator must never feed P's settlement.** "Expiry-with-peer-pass ⇒
  uncounted" would let one friendly witness per epoch shield a dark P
  (one pass + two uncounted = Served) — resurrecting the single-draw
  shield 2-of-3 exists to kill. Witness enforcement and P settlement stay
  separate channels.
  **OUTCOME (2026-08-08, same round): the penalty arm is WITHDRAWN by its
  proposer — the attribution impossibility (§7 preamble) reaches it.**
  Peer contrast shifts a prior; it cannot found a penalty (P can
  selectively refuse one witness, die between reads, or one Tor path can
  fail — and check 4's missing aggregation subject stands independently).
  The duty framing survives as the ruling: **routine duty, norm-borne,
  `λ_eff` the tripwire — the only reachable answer.** The four checks stay
  on the record as the wreckage map: any future enforcement proposal must
  first state which check it escapes and where its attribution comes from.
- **Abandonment:** an assigned witness that never resolves burns the slot
  for W₂ blocks (phrasing contingent on §7.1: exact under per-block/urn
  variants; under epoch-seed exact coverage the three assignments are fixed
  regardless). Penalty sizing target: exceed (position value × attacker
  hashrate share) ÷ (interceptions needed), floored by honest tolerance of
  genuine read failures. Bond-sized and reward-sized are both wrong (former
  deters all honest witnessing; latter ~3 orders above target). The property
  that keeps the number tractable is drain-on-satisfaction (§2): a pair that
  never serves never leaves the pool, so evasion must hold across every draw
  for months — the attacker pays per interception, repeatedly, against a
  one-time avoided loss. The penalty need not be punitive alone; it must
  make the **accumulated** cost cross the position value before the window
  closes. Both terms are estimable from landed constants: position value
  from `reward_share_floor` and the budget schedule; draw count from pool
  size, `SETTLEMENT_EPOCH_BLOCKS`, and the (m, n) window. The floor on the
  other side — the penalty at which an honest miner stops committing, given
  a genuine read-failure rate it cannot control — needs **measurement, not
  derivation**. **CLOSED (2026-08-08): no penalty is derivable** — the
  attribution impossibility (§7 preamble) deletes the "demonstrated"
  any penalty needs. The sizing arithmetic above is retained as the record
  of what a penalty would have had to achieve, not as pending work; the
  attack it targeted is contained instead by the 2-of-3 quadratic plus the
  outer window (fork 1's update).
- **DDoS on P:** the derived window is the targeting surface; §2's
  limited-scope property plus 2-of-3 redundancy plus long-W₂ (a *defense*
  here — more completion chances) are the mitigations. Converting DDoS to a
  slash requires sustained suppression across m of n epochs.
- **Foundation CompleteTree nodes** are outside this economy by design
  (`market_member_at_epoch` returns false). Do not design incentives for
  them — and do not exempt them from the slash side either (examined and
  closed 2026-08-07): a Foundation node down long enough to cross the
  window is not serving, and a backstop that is not serving is not a
  backstop; clearing its holdings is an accurate statement of reality, and
  Rebond is the re-entry path for an operator who fixes the box.

## 7. Open forks — resolve on this record, never implicitly in code

**The attribution impossibility (ruled 2026-08-08) — the result that closes
forks 3 and 6 and the obligation half of fork 2.** A miner cannot prove P
didn't serve, and nobody can prove a miner didn't try. A positive proof
works because it needs the counterparty's cooperation — P's countersignature
exists only if P participated, so a pass is self-proving. A negative has no
such anchor: the only evidence of "didn't serve" is absence of evidence of
serving, and absence is consistent with refusal, darkness, never-asked,
dropped request, dropped response, or received-and-discarded. Every artifact
a witness could offer is unilaterally producible by a witness sitting in the
dark doing nothing — which is the definition of not being evidence. This is
the unreliable-failure-detector result; no cryptography moves it, because
the missing thing is a signature from a party that, by hypothesis, isn't
signing. Every enforcement mechanism this round considered — the abandonment
penalty, contradiction-pricing, peer-contrast (withdrawn by its proposer) —
covertly assumed such a proof exists; each produced a new abuse when it
fixed the last, because all were deriving attribution from artifacts that
cannot carry it. Two consequences. First, the 2026-08-02 no-pay lemma is
**forced, not chosen** — pay must condition on something, every
discriminator reduces to attribution that does not exist, and the identical
argument kills every penalty. Second, **the window is the attribution
mechanism**: one expiry proves nothing about anyone; eleven of thirteen
epochs, each settled 2-of-3 over independently derived witnesses, is a
pattern no honest P produces — not because any event was proven, but
because the conjunction has negligible probability under the honest
hypothesis. §9.4 said this from the start ("statistical, not forensic");
the round kept trying to add forensics underneath it.

1. **Derivation granularity** (coverage vs targeting window). Epoch-seed
   permutation gives denominator = 3 by construction but publishes every
   window 10,000 blocks ahead (DDoS surface). Per-block derivation keeps the
   one-block scope but yields a random draw — under-coverage returns and
   §4.2's row-per-drawable-pair fallback becomes mandatory. Candidate
   synthesis: per-block seed selecting among the *least-covered* drawable
   pairs (a deterministic urn) — coverage converges to exactly 3, targeting
   window stays one block, at the cost of pending/complete bookkeeping in
   the derivation. **Choose explicitly.** Coupled sub-decision, decided with
   this fork: **is a pair drawable while a challenge on it is outstanding?**
   If not, the clock-burn attack works: a dangling challenge occupies the
   pair for W₂ blocks, so a colluding witness commits and sits — each
   abandonment buys W₂ blocks of immunity for one penalty, draws per epoch
   are bounded by (blocks remaining)/W₂, and the attacker shifts from
   intercepting draws to consuming the epoch's clock. If yes, concurrency
   must be capped — unbounded is §7.2(c)'s thundering herd in miniature —
   but at a small cap the wasted work is bounded and occurs only when P is
   actually serving — and there is **no supersession state at all** (ruled
   2026-08-07): a challenge, once issued, runs to pass or expiry regardless
   of whether the epoch requirement is already met. Settlement is monotone,
   so a post-satisfaction result changes nothing, and no credit is ever
   owed twice. Whether the abandonment penalty (§6) still attaches to a
   post-satisfaction challenge is decided with this fork. Candidate: **cap
   of 2 concurrent plus redraw-on-expiry**, which makes clock-burn cost
   scale with the cap instead of buying blanket immunity. (The concurrency
   analysis was first run under pass-priority, where the first pass settled
   the epoch and later challenges needed a supersession rule; under 2-of-3
   with monotone settlement and satisfaction-does-not-drain, the
   supersession machinery dissolves.) **Update under fork 3's closure
   (expiry⇒miss): the clock-burn's *shield* direction is dead** — an
   unresolved challenge trends to a miss, which hurts P, so sitting on an
   assignment cannot protect a dark P. What remains is the griefing
   direction (deliberate abandonment manufacturing misses against an
   honest P), which is the flood-to-slash channel: quadratically contained
   by 2-of-3 (moving an epoch needs 2 of its 3 draws) and priced by the
   outer window. The outstanding-challenge drawability *sub-decision* is
   therefore pure scheduling now — but that claim is scoped to the
   sub-decision alone; see the correction below.
   **The fork's dominant term (correction, 2026-08-08): lookahead
   survives as an adversarial axis, and two later rulings made it
   heavier.** What died with expiry⇒miss was the clock-burn *shield*; the
   DDoS targeting window did not die, and it is the axis the three
   variants differ most on — epoch-seed publishes every assignment
   ~10,000 blocks (~14 days) ahead; per-block gives one block; the urn
   sits between, by how much of its state is predictable. Two rulings
   now load this leg: under **expiry⇒miss**, a successful availability
   attack converts directly into a miss with no attribution possible —
   the very property that made expiry⇒miss safe at the window level makes
   the per-epoch cost of unreachability unambiguous; and the **TJ-H
   guard-discovery finding** makes P's reachability window the thing an
   adversary most wants to know, since forced circuit builds during a
   known window beat random probing. The epoch-seed variant's
   coverage-by-construction is genuinely attractive and must not win on
   the coverage argument alone without the lookahead cost priced against
   this threat picture.
   **Acceptance test, stated identically for all three variants — the
   redraw floor:** a pair that fails its first challenge must be re-drawn
   before the epoch closes, with high probability. Epoch-seed satisfies
   it deterministically. The urn satisfies it by construction *if* the
   draw is uniform over the least-covered set. Per-block satisfies it
   only probabilistically: P(redraw | first challenge failed at block b)
   ≈ 1 − e^(−λ_eff·(1 − b/SEB)), where λ_eff = k·SEB/D for k draws per
   block over a drawable set of size D — and that number, not an
   argument, decides whether per-block survives.
   **Pool-size regimes (the input λ_eff is a function of):** D = bonded
   (P, s) pairs. Genesis-era: ~10³–4×10³ (fee-era-thin/lean `N_P` 17–79
   with partial holdings; the FOLLOWUPS small case ran at 4,096 pairs).
   Maturity: ~10⁵–3.2×10⁵ (the FOLLOWUPS stress case at 100 k; the TJ
   extreme at lean `N_P` ≈ 79 × `MAX_HOLDINGS_SHARDS` = 4,096 ≈ 324 k).
   The coupling that decides per-block at maturity: k is chain-growth-
   bound (`k_cap` — each pass record ≈ 3.43 KB, FOLLOWUPS), so
   λ_eff = min(λ_target, k_cap·SEB/D) falls below the redraw floor as D
   grows unless records ride the prunable side; at D ≈ 324 k and
   k_cap = 30, λ_eff ≈ 0.93 — under one expected draw, floor dead.
   **Urn bookkeeping — priced now so the variant is comparable:** the
   urn's pending/complete state must live **in the derivation, not a
   table** — it is a pure function of (epoch-open snapshot, block hashes
   h_open..h−1), so it is recomputable, and the standing derive-don't-
   store principle (`ARCHIVAL_CREDIT_WIRE.md` §3, maintainer 2026-08-03)
   plus the `ArchivalSealHashCache` precedent (memoize per height;
   recompute-on-reorg is behaviour-identical) already rule the shape. A
   persisted table would inherit `pop_block` revert obligations the other
   two variants do not have — a cost the urn must carry on its face if
   anyone proposes the table form.
   **Correction (2026-08-08, review): the budget shortfall is
   variant-independent, and it relocates the decision.** λ_eff =
   min(λ_target, k_cap·SEB/D) is a property of the challenge *budget*,
   not the derivation method: at D ≈ 324 k and k_cap = 30 there are
   ~300 k challenge slots per epoch against ~972 k needed (three per
   pair). Epoch-seed does not escape — over-subscribed, its permutation
   degrades to a partial one (coverage below 3, per-block's failure made
   deterministic); the urn converges to 3 only when the budget admits 3.
   **The variants differ in how they degrade, not in whether they do**,
   and the acceptance test above discriminates only in the genesis-scale
   regime where the problem is easy. The binding constraint is `k_cap`,
   chain-growth-bound at ~3.43 KB per hybrid-countersigned pass record —
   and the mitigation is already named and marked design-not-assume in
   FOLLOWUPS: attestation records are needed only until the epoch
   settles and the claim window closes (exactly the ledger
   `prune_archival_epochs_before` already drops), so they should ride
   the **prunable side** of the block. **That question is upstream of
   this fork:** if prunable residence lands, `k_cap` relaxes and all
   three variants clear the floor at maturity; if it does not, none do
   and the mechanism does not scale past ~10⁵ pairs — fork 1 becomes
   triage, not scheduling. Note 2-of-3 made this harder, not easier: 3×
   the draw on the same budget the earlier λ_target figures assumed.
   **The round's lean, assuming the budget resolves (2026-08-08): the
   urn — for a narrower reason than "it sits between."** Epoch-seed's
   14-day window is not merely long; it is **enumerable in advance
   across all pairs simultaneously**, so an adversary picks targets by
   convenience rather than opportunity and schedules a campaign — and
   under expiry⇒miss plus the guard-discovery finding, discovery and
   availability attack compose in the same known window.
   Coverage-by-construction does not pay for that.
   **Check gating the urn ruling — tail predictability, now with its
   structure derived:** the least-covered set is a deterministic
   function of chain history, so the adversary always knows the
   *candidate set* exactly; only the within-set selection is one-block
   blind. The urn invariant (draw from minimum coverage) makes coverage
   advance in **waves** — all pairs reach count 1, then 2, then 3 — so
   the candidate set drains from D to ~0 **three times per epoch**, and
   the narrow-set exposure recurs at each wave tail, not just near
   close. Advance notice on pair X is "within ~m/k blocks" for current
   min-set size m: wide (unpredictable) through most of a wave,
   effectively pre-announced once m ≲ k·(attack ramp + W₂). The check
   to run before ruling: what fraction of draws occur at m below that
   threshold, at genesis and maturity D. Candidate mitigation if the
   tail is fat: widen the candidate set to a coverage *band* (min and
   min+1), trading exact-3 convergence for tail anonymity — a knob the
   fork can size, not a redesign.
   **Band-as-default inversion (2026-08-10, review — check, don't
   carry as contingency):** the band may be the ruling rather than the
   fallback. The budget correction already conceded exact-3 does not
   survive maturity, so the property the band trades away is one the
   mechanism cannot hold in the regime that matters — the trade is
   nearly free there and only "costs" at genesis, where D is small and
   the wave-tail problem is worst. That reads as strictly better at
   both ends, which would make the band the default and exact-min the
   special case — and the wave-tail check must then be **run against
   the band**, not exact-min, or its number measures a variant we may
   not ship. One sharpening from checking it: the band's apparent
   genesis cost — a variable issued-count per pair (2/3/4) — is a cost
   the settlement rule **already owes**, because the maturity budget
   shortfall forces variable issuance under *every* variant. So the
   fold's threshold must be restated for variable denominators
   regardless (e.g. "Served iff ≥ 2 passes" absolute vs
   majority-of-issued — a named sub-decision for the `settle_epoch`
   rewrite, §4.4), and the band adds no semantic obligation the budget
   had not already created.
   **The settlement sub-decision, analyzed (2026-08-10, review — lean:
   absolute-2):** the rules diverge precisely where issuance is short,
   which is the maturity norm. Majority-of-issued makes the *threshold*
   a function of issued-count — derivable, but a consensus input that
   couples settlement correctness to every node reproducing the
   derivation identically, and it lets 2-of-2 and 1-of-1 settle Served
   on thinner evidence exactly where the budget is tightest. Absolute-2
   needs only the pass count — smaller surface, and the epoch bit means
   one fixed thing across the whole D range. The cost, recorded not
   argued away: a pair issued < 2 can never be Served, so under-issued
   epochs must settle **non-observation** (a pair the urn couldn't
   reach is not a pair that failed) — which re-keys §4.2's writer on
   **issuance, not drawability**. At exact budget this never binds (see
   the numbers below: min issued = 2 in every run); it binds only in
   budget-short regimes, where it is the correct behaviour.
   **Wave-tail numbers (2026-08-10; scratchpad sim, 3 seeds at genesis;
   the executable derivation lands in `shekyl-economics-sim` with the
   ruling per the derive-don't-hardcode pattern):**
   - **Exact-min exposure has a closed form and it is scale-invariant:**
     exposure(τ) = k_avg·τ/D = **3τ/SEB** (λ_target = 3) — 0.75 % of
     draws at ≤ 25 blocks notice, 3.0 % at ≤ 100, 6.0 % at ≤ 200;
     identical at D = 4,096 and D = 324,000, matching simulation to
     three digits. The tail is thin but real, and independent of scale.
   - **The band cuts exposure ~2.5×** at every τ, both regimes (τ100:
     3.0 % → 1.1–1.2 %) — structurally, the min+1 bucket keeps the
     candidate set large through wave transitions.
   - **The band's issued-count variance is the heavy side of the
     trade — and the fraction is realization-dependent even at maturity
     scale** (found porting the sim to `shekyl-economics-sim`: 23.3 %
     at issued-2 under the first sampler, 30.0 % under the crate's
     deterministic sampler, same D and budget; genesis runs ranged
     8–25 %). The wave dynamics leave the straggler fraction
     high-variance, so the honest statement is **roughly a fifth to a
     third of pairs at issued-2, symmetric with issued-4 by draw
     conservation** — a distribution, not a point, per the round's own
     §9 discipline. The ruling is unaffected: the per-pair survival
     arithmetic (a² = 0.81 at a = 0.9 vs a²(3−2a) = 0.972 for
     issued-3) does not depend on the fraction, and the band is
     rejected under any realization. Under absolute-2 **the
     issued-count histogram is an (m, n) derivation input** (the
     per-epoch miss rate becomes a mixture), exactly as anticipated —
     now noted as a distribution input.
   - **The redraw floor holds under both variants at exact budget:**
     minimum issued = 2 in every run; 1st→2nd-draw gap p99 ≈ 6,200
     blocks < SEB.
   - **The capped regime, for the record (k_cap = 30, D = 324 k):**
     issued counts {0: 35 %, 1: 37 %, 2: 28 %} — under absolute-2 with
     under-issued ⇒ non-observation, 72 % of pairs are unobservable per
     epoch and retention teeth degrade proportionally. Triage made
     concrete; this is what the prunable-carrier work prevents.
   - **Candidate worth sizing, not ruling here — the adaptive band:**
     exact-min while the min bucket is large, widening to the band only
     when it thins below m*. Keeps exact-3 for most pairs and buys tail
     anonymity only where the exposure lives; m* becomes the knob that
     trades the two curves above against each other.
   **RULED (2026-08-10): exact-min urn. The tail is accepted, with the
   arithmetic on the record.** Both curves live at 10⁻⁷ and below:
   - *Exposure buys the adversary nothing.* For guard discovery, zero —
     shard pulls are open and unauthenticated, so the circuit-
     construction oracle is available 24/7 on demand; knowing when a
     *challenge* lands adds no capability to the attack this round
     identified as the serious one. For availability attacks, almost
     nothing — moving one epoch needs 2 of the pair's 3 draws killed:
     at 3 % exposure per draw, P(≥ 2 of 3 exposed) ≈ 0.26 % per epoch,
     and reaching a slash needs that in 11 of 13 epochs — order 10⁻²⁷
     (τ = 200: ~10⁻²⁰). An adversary who can sustain a DDoS for a full
     13.9-day epoch needs no lookahead at all; the tail only helps an
     attacker who can strike for hours but not weeks, and that attacker
     needs ~22 precisely-timed strikes across six months.
   - *The band's cost was equally absorbed* (23.3 % at issued-2 → ~2.5
     expected misses vs a threshold of 11, slash probability ~6×10⁻⁷) —
     but it buys 1.8 percentage points on an attack path already
     dominated by three orders of magnitude, and pays with a knob
     needing its own derivation, tests, and reorg reasoning.
   - **The adaptive band is NOT built**: a real mechanism with real
     complexity solving a problem measurement showed isn't there; a
     tuning knob in a consensus derivation is not a cheap thing to
     carry.
   - *Correction owned on the record:* the lookahead-as-dominant-term
     argument was right that the axis survived expiry⇒miss and
     guard-discovery, wrong that it dominated fork 1 — exposure is
     scale-invariant and thin, and the open-pull oracle means the
     guard-discovery leg gains nothing from timing. The measurement
     corrected the argument, which is what it was for.
2. **Who reads — witness selection and obligation.** The decision the rest
   of the stack prices against: W₂, the abandonment penalty, the reward
   question, and the nonce anchor are all functions of who performs the
   read and what happens when they fail. Ruled already: derivability means
   *anyone can verify* a challenge is legitimate, and P serves only
   derived-legitimate reads. The options, each with its standing-record
   status so none is re-derived from scratch:
   - **(a) Producer-of-block-h** (implicit assignment): one reader, no
     stampede. Compulsion is unresolved by construction — and the standing
     answer on the record is the 2026-08-02 ruling: coverage is
     **norm-borne** (default-client behaviour), `λ_eff` its tripwire — an
     accepted residual with an instrument, not an oversight. Choosing (a)
     means re-accepting that residual under the new fold, knowingly — but
     see §6's routine-duty resolution candidate, which adds enforcement to
     the norm if its four checks hold.
   - **(b) Derived nominee, single servicer:** the draw names the pair
     *and* who must service it. This is TJ-A1's anticipated shape — recent
     block producers are consensus-enumerable from headers — and §8.2's two
     population properties (structural indifference; PoW as liveness
     attestation) carry to nominees drawn from that set. §8.2's precision
     note applies: a block proves liveness at the selection instant, not
     across the window — an argument for m-of-n and window width, not
     against nominees. Zero-warning targetability if drawn from the current
     block's own hash. Requires the abandonment penalty (§6), which
     requires the reward-lemma question.
   - **(c) Open witness (bounty race) — STRUCK (2026-08-07),** with the
     objection on its face so it is not re-derived later: any-party-reads
     is the thundering-herd shape — N volunteers race, P absorbs N
     full-shard transfers, one is credited, N−1 are pure burn, and P has no
     cheap way to refuse the losers. The redundancy is the mechanism
     working as designed, not a failure mode to tune away; disqualifying
     before the anchor tension is even reached. Any future proposal in this
     family must first answer bounded concurrency and amplification on P.
   - **(d) Archiver-initiated (the landed vin) — the fallback, priced
     honestly:** killed by TJ §9.2 not on proof *quality* but on proof
     *subject* — `P` signs its own response, and self-attestation proves
     **capability** ("I can produce the opening"), never **service** ("I
     served someone"); service needs a counterparty. Reopening it means
     overturning test≡job (R1) and its ROI ledger (TJ §5), not re-judging
     one artifact. It remains the only option with a landed implementation
     and no coverage problem; knowing the fallback's true price calibrates
     how much pressure (a) and (b) must survive.
   The **nonce anchor** (what replaces `cb_out_key` when the reader is not
   the including block's producer) is subordinate to this fork and touches
   the frozen response wire — decide with TJ-B's format specification,
   which also carries TJ-H's framing constraint (§7.4).
   **Obligation half CLOSED (2026-08-08, impossibility):** no pay and no
   penalty are both forced, so coverage is **routine duty, norm-borne,
   `λ_eff` the tripwire** — now as the *only reachable answer*, not the
   preferred one. What stays open in this fork is selection ((a) vs (b))
   and the nonce anchor — noting that (b)'s distinguishing feature was the
   penalizable nominee, which the impossibility deletes, leaving (a) the
   natural default unless selection has some other reason to name a
   non-producer.
   **P-side anchor + endpoint discovery — resolution shape (2026-08-10).**
   A prior gap, verified at source, that had to be answered regardless of
   key choice: `ArchivalBondPostVin` (`bond_wire.rs:205-222`) carries
   `hybrid_public_key`, `p_canonical_id`, `post_kind`, `bond_spend_pk`,
   holdings, and three amounts — **no reachability field. Nothing on
   chain tells a witness where to connect; discovery was unspecified.**
   The shape that answers discovery and binding at once: **publish the
   persona's v3 onion address in the bond record** — the address *is* its
   Ed25519 verification key, so one field publishes both the endpoint and
   a verification key — while the countersignature **stays hybrid**
   (Ed25519-only would be the one classical-only signature on a consensus
   path; forging it forges attestations — an integrity failure
   hybrid-from-genesis exists to stop). What this buys that neither key
   alone does: the hybrid key proves "I am P," the onion key proves "I am
   the service you just connected to," and bound together they prove
   those are the same entity — **today nothing does** (a persona could
   publish someone else's onion address undetectably).
   **Key hierarchy — ruled shape, three tiers, written for operators
   because the blast radius of a compromised serving box is exactly what
   they need told:**
   - **Cold — bond authority.** `bond_spend_pk` (the immutable debit
     authorizer every later `bond_debit` verifies against,
     `bond_wire.rs:217`) lives under a **separate root, cold custody,
     never in the serving tree** — compromising a serving host must yield
     impersonation of the serving function, never a bond drain.
   - **Hot — per-persona serving root** (one entropy draw per persona) →
     **siblings by labeled derivation** (rule 30: distinct labels +
     version suffixes): the onion Ed25519 identity, the
     `HybridEd25519MlDsa` attestation keypair, and the SOCKS username
     (already built exactly this way — cSHAKE256/SP 800-185 over the full
     `p_canonical_id` in `shekyl-p-transport`; `keygen_from_seed`,
     `derivation.rs:40`, deterministic ChaCha20 expansion, is the
     established seeded pattern). **Root → siblings, not
     onion-key-as-parent:** siblings rotate independently; deriving the
     signing key from the Tor key couples the consensus signing identity
     to service re-keying.
   - Hot-tree exposure is accepted and stated: P signs every request, so
     the attestation key is necessarily hot on the internet-facing host,
     and host compromise already yields serve-and-sign-as-P. Custody
     note: `shekyl-tor` generates the onion keypair and hands it via
     `ADD_ONION` — our process holds it, a different exposure than
     Tor-native key handling, stated and accepted.
   Correlation risk, sized honestly: properly generated independent keys
   do not correlate — the exposure is generation-side (shared RNG state,
   batch generation, weak KDF), which the single root removes as defence
   in depth. The dominant cross-persona linkage is **operational** —
   co-residency and correlated uptime remain unaddressed (the circuit
   axis is already unrepresentable via `shekyl-p-transport`) and are
   worth more to an adversary than key-material statistics.
   **Mutability — RULED (2026-08-10): rotation-in-place via
   `EndpointUpdate`.** The reasoning of record: every endpoint-burn case
   (compromised host, discovered address, lost onion key) leaves the
   persona's economic position untouched — bond, holdings, join epoch,
   earnings history, and the `[E, MAX)` interval state are all
   unaffected; **only the routing field is spoiled**. Forcing an unbond
   would destroy a clean record to fix a network address — and worse,
   push the operator into a new persona with fresh principal funding,
   which is precisely the clustering edge. Rotation-in-place is the
   privacy-preserving option as well as the operationally sane one.
   **The invariant the spec must state explicitly, because it reads as
   obviously wrong once stated and gets implemented wrong when it
   isn't: rotation resets NOTHING the window or the market reads.**
   `good_through`, `join_settlement_epoch`, the bad-interval list, and
   the failure-window history all survive an `EndpointUpdate`
   untouched — otherwise rotation launders bad standing (a persona
   approaching 11-of-13 rotates and buys a clean window for the price
   of one transaction). Shape: **routing-only mutation, no economic or
   standing side effects, authorized by the persona's attestation key,
   fee-funded from persona earnings, effective at epoch boundary** so
   the drawable snapshot (§4.1) and the endpoint move together.
   **Residuals carried as stated, not solved:** the pre-first-claim
   funding gap (bounded at one epoch); timing correlation if an
   operator rotates many personas at once; and the compromise window
   between host-takeover and the update landing, during which the
   attacker can serve and countersign as P — survivable precisely
   because serving and countersigning honestly is what P wanted, so the
   attacker's best move is impersonation rather than damage.
   **Open checks before the P-side closes:** (i) **The same-entity
   binding artifact**: whether the attestation Ed25519 leg *is* the
   onion key (endpoint-binding per-signature, but rotation-coupled) or
   a sibling with an onion-key proof-of-possession over the bond record
   at post/update (rotation-free; the PoP is the binding) — a
   TJ-B-adjacent format decision landing on the **bond wire**, hence
   (ii) a persisted-wire change ⇒ version-constant bump (rule 42) when
   built. (iii) Whether **emission-claim authorization** (the bond
   `hybrid_public_key` the PR-E3 auth gate verifies) sits hot or cold —
   this decides whether "impersonate, never drain" covers the *earnings
   stream* as well as the bond principal. Pose the tier explicitly in
   the spec; do not let the hot key inherit it by default.
   **Carrier — RULED (2026-08-10): `EndpointUpdate` rides the bond-post
   vin as `BondPostKind::EndpointUpdate = 4`, same family as
   `HoldingsUpdate`, deliberately different mutation class.** The
   four-way decomposition on the record:
   1. *Economics:* `HoldingsUpdate` is defined by its amount arms
      (exactly ±FLOOR, one shard, `bonded_total` recomputed,
      retention-horizon gate on drop). `EndpointUpdate` has **zero
      credit, zero debit, `bonded_total` untouched** — nonzero amounts
      on it are made unrepresentable on the wire, the same enforcement
      idiom as the `bond_spend_pk` iff-`JoinMarket` coupling. The
      endpoint field itself is present iff `JoinMarket` (born at post —
      a bond without an endpoint was the discovery gap) or
      `EndpointUpdate` (rotation).
   2. *Standing effects — the two variants are opposites:*
      `HoldingsUpdate` legitimately mutates what the market and window
      read; `EndpointUpdate` touches nothing they read. Stated at
      family level precisely because a maintainer seeing two siblings
      in one enum will reach for the shared record-update path — and
      the sibling's path *does* carry standing-mutation code.
   3. *Authorization — COLD, and the family precedent is explicitly
      BROKEN (ruled 2026-08-10).* The family splits debit vs non-debit,
      but that split is a **proxy**: debit arms touch value, so they
      get the cold key. `EndpointUpdate` touches no value, so the proxy
      routes it hot — and the proxy is wrong here, because the thing
      being protected is not value but **the persona's ability to
      escape a compromised host**. Hot authorization gives the escape
      hatch to exactly the key the host attacker already holds: the
      attacker rotates to an address it controls, the operator rotates
      back with the *identical* derived key — an unbounded flapping
      contest between parties with equal authority, decided by whoever
      posts last. Not a hijack window; a **permanent stalemate**, in
      exactly the case the mutation exists for — so it cannot be filed
      as a residual. Two of the three burn cases (compromise,
      deanonymization) mean the hot key is in enemy hands, so
      `EndpointUpdate` needs authority the compromised host does not
      have: **the cold tier, despite being a non-debit post.** The cost,
      stated honestly in the operator-facing text: rotation requires
      reaching for the same custody used for unbonding — the escape is
      not automatable from the serving box. That is the correct
      trade — an escape hatch a compromised host can operate isn't
      one — but it is a real burden. It also cleans up the funding
      residual: with cold authority the principal is already involved,
      so fee-from-earnings becomes a nicety and the pre-first-claim
      gap stops being a hard corner. Spec detail to resolve: which
      cold key a non-`JoinMarket`-posted record verifies against
      (`bond_spend_pk` is present iff `JoinMarket` on the wire).
   4. *Timing — one family-level rule:* `EndpointUpdate` is ruled
      effective at epoch boundary, and Pin-5 quantization already
      lands `HoldingsUpdate`'s *drawable* effect at epoch open
      regardless of when the record mutates — so both variants share
      one statement: **record-effect at connect, mechanism-effect at
      epoch open.** Neither carries its own timing rule.
   **The laundering invariant is a TEST, not a sentence (ruled
   2026-08-10):** prose will not stop the shared-path mistake, because
   the sibling legitimately carries standing-mutation code. Two KATs
   land with the implementation: (a) a record's
   `join_settlement_epoch`, bad-interval list, `bonded_total`, and
   holdings are **byte-identical** across an `EndpointUpdate`; (b) a
   failure-window vector in which a persona at 10 accumulated misses
   **still slashes after rotating** — the attack stated as a test, the
   one that fails loudly if rotation is wired into the wrong branch.
3. **Expiry semantics — CLOSED (2026-08-08): expiry ⇒ miss.** The
   temptation under unattributable expiry is to discard it
   (expiry⇒uncounted); that is precisely wrong — a durably dark P
   generates *only* unattributable events, so discarding them means it
   never misses, never slashes, and retention teeth die (corner 2's cost,
   already ruled unacceptable). Expiry⇒miss is safe **not because a miss
   attributes fault but because the two nested aggregations convert
   unattributable events into an attributable pattern**: witness laziness
   is absorbed at the inner layer (one lazy witness of three does not move
   the epoch), and residual noise is priced at the outer layer — which is
   what the (m,n) re-pin is for. One derivation constraint carried to
   fork 7, because "priced at the outer layer" has a boundary: the honest
   failure rate splits into an **idiosyncratic** component (Tor weather —
   roughly independent across epochs, which the window prices) and a
   **common-mode** component (the persistent non-witnessing fraction β —
   common across every epoch in the window, which the window does NOT
   launder: at β persistently near ½, per-epoch miss ≈ 0.5 and the
   13-epoch tail is ~1 % per window position, no longer negligible). The
   window prices the first; the `λ_eff` tripwire guards the second. The
   under-coverage question collapsed here (§4.2) and closes with this.
   The sealed precedent "a committed-but-unfiled nonce is a
   non-observation the settlement absorbs" is superseded by this closure:
   it was ruled for the mandate design, and under 2-of-3 its logic would
   discard exactly the events a dark P produces.
4. **TJ-H — RULED (2026-08-08): reserve the padding field in the frozen
   response format; specify no padding scheme. The mitigation moves to the
   Tor layer.** Working the actual attack path re-framed SPIKE-F-19: the
   adversary does not begin as the guard — guard *discovery* runs first
   (force the service to build rendezvous circuits until an adversary
   middle relay is chosen, confirm the position via a protocol side
   channel, then compromise/coerce/NetFlow the guard), so the fixed
   payload's real role is **middle-relay position confirmation in phase
   one**, not persona identification in phase two — and the larger
   exposure the size question never named is the **circuit-construction
   oracle**: any node may pull a shard for its own verification, so
   archivers expose an unlimited, free, unauthenticated circuit-build
   primitive — exactly what guard discovery consumes.
   **Padding rejected, four legs:** it cannot defeat a triggered probe
   (the adversary receives the padded response over its own circuit and
   knows the delivered size — the same bytes crossed P's guard leg, and
   the correlation survives); size is the weakest feature on the vector
   (Tor's fixed 514-byte cells already normalize size; working attacks key
   on timing, burst structure, direction, duration — a bulk unidirectional
   transfer is identifiable from any hop regardless of byte count); every
   padded byte crosses two Tor legs and inflates W₂, the budget already
   absorbing PoW-under-attack latency; and it does not touch the
   circuit-construction oracle. Residual benefit against a *passive*
   observer (a fixed size is a one-observation tell needing no classifier)
   justifies **reserving the field**: a length header plus the option to
   pad zero — omitting it forecloses permanently, reserving forecloses
   nothing. **Framing constraint (structural, settled when TJ-B specifies
   the format, not deferred with the distribution):** the padding region
   must sit outside the bytes hashed against `R_k`, or content-addressed
   self-authentication breaks.
   **Mitigation actions, none genesis-frozen:** (1) pin **full vanguards**
   (not lite) for serving personas, with L2/L3 set sizes and rotation
   periods derived against our pull rate rather than inherited (rotation
   rate is not a lever in either direction — each build is an independent
   draw, so over-rotation volunteers the attack's own mechanism; the lever
   is selection entropy per build, which saturates the oracle's yield);
   (2) re-derive Bandguards' per-circuit cap (its ~100 MB guidance assumes
   a service that does not move bulk content — the exact case an archiver
   isn't); (3) rate-limit shard fetches per requester alongside the pinned
   `HiddenServicePoW`, attacking the query count guard discovery needs.
   **Accepted residual, recorded so padding is never mistaken for having
   solved it:** active confirmation by an adversary already holding the
   guard is NOT mitigated; the honest bound is SPIKE-F-19's own (research
   accuracies under controlled conditions, degraded in the open world) —
   the claim is that a guard operator who cares can find out cheaply, not
   that guards know. **Withdrawn:** onion-address rotation (the guard is a
   property of the running Tor client, not the address). **Sequencing:
   TJ-H no longer gates the round** — fork 1 is promoted to first
   position; the Tor-layer hardening runs independently.
5. **W₂ derivation** — see §9; not guessable, and **gated on fork 2** (a
   response deadline prices "long enough that an honest P serving a bulk
   read is not timed out, short enough that a dishonest P cannot stall,"
   and both terms are functions of who reads, how many readers there are,
   and what happens when they fail — none of which exists before forks 1–3
   settle). Deriving W₂ first would be picking a number and back-filling
   the justification.
6. **Witness reward residence — CLOSED (2026-08-08, impossibility): no
   pay, forced.** Pay must condition on something, and every discriminator
   reduces to attribution that does not exist. The §6 reopening question
   resolves in the lemma's favour on deeper grounds than the lemma gave:
   the premise deletion (miss record, secret sets) did not matter, because
   the impossibility never depended on either — it is the negative-proof
   problem itself.
7. **(m, n) re-pin — now THE instrument: the sole surviving enforcement
   layer.** Size the outer window against the 2-of-3 tail probabilities
   and the *measured* honest failure rate, under fork 3's constraint:
   treat the persistent non-witnessing fraction β as **common-mode across
   epochs**, never as i.i.d. noise the window launders — the window prices
   idiosyncratic failure; the `λ_eff` tripwire guards common-mode drift.
   Everything now hangs on this derivation. It is a measurement-and-
   derivation problem, which is the right place for a design round to
   end.

## 8. Preconditions

- **Witness-capable hashrate** (fork §7.2 variant (a) only): honest epoch
  survival requires ≳ ⅔ of hashrate willing and able to perform reads —
  coupling this mechanism to mining decentralization (§9.5(5) of the TJ
  round, now a named precondition). Variant (b) trades this for the
  open-anchor question. **This assumption must not live only in a
  conversation** — it is recorded here precisely so it is not rediscovered
  expensively.
- **TJ-B read/serve protocol is unbuilt** (SP-T3 supplies payload and
  consumer; promoted to challenge substrate). The mechanism has no transport
  until it lands. Its format specification carries two frozen obligations
  from this round: the reserved padding field with its framing constraint
  (TJ-H, §7.4) and the nonce anchor (§7.2).
- **Prunable residence — the merits question is ANSWERED (2026-08-10,
  verified at source): nothing downstream of settlement reaches raw pass
  records.** Three independent layers: (1) `shekyl_emission_vin_verify`'s
  inputs (`blockchain.cpp:4128`) are the canonical vin, the bond record,
  claimed epochs, and the epoch **snapshots** (σ_work / budget / bonds /
  shards / credit_pairs, gathered from `m_archival_serve_credit`) — the
  work recompute runs over materialized credit pairs, and the auth gate
  verifies the *claimant's* signature on the vin; no attestation record or
  countersignature appears anywhere in the signature. (2) The settlement
  fold is structurally incapable of reaching one — `settle_epoch` takes
  `&[AttestationKind]` (the §4 type seam). (3) LMDB-side pruning is
  already landed: `delete_archival_attestation_witness_before_height`
  drops the admission-only `r` + signatures beyond the reorg window, its
  comment naming the seam ("Settlement reads the kept tx_extra headers,
  never this witness"). **Consequence: `k_cap` relaxes on the merits and
  fork 1 is the scheduling choice it was framed as.** What remains is
  carrier work, not a merits question: wire-side prunable residence was
  ruled for the OLD carrier (credit-wire authority row — header kept,
  3.43 KB countersignature prunable-side of the coinbase tx), but this
  round moved pass records to **transactions** (§2 step 4), so the
  residence ruling must be **re-instantiated for the tx carrier in TJ-B's
  format spec, deliberately** — it is genesis-frozen in character (which
  side of the block a record rides is consensus-visible, no migration
  path pre-genesis), the padding-field asymmetry argument applies, and
  the one real risk is ordering discipline: it must not fall out of TJ-B
  by default. Carrier-specific check to carry there: the old coinbase
  finding (`prunable_hash` hardcoded null under `CTTypeNull`) was
  coinbase-specific — the tx carrier needs its own
  commitment-of-the-prunable-region check. **The number that justifies
  this work (measured, fork §7.1's capped run):** at maturity D = 324 k
  under the chain-growth-bound k_cap = 30, issued counts are
  {0: 35 %, 1: 37 %, 2: 28 %} — **72 % of pairs unobservable per
  epoch**. That is not a tail; it is the system failing, and it is the
  only figure in the fork-1 measurement set operating at system scale.
  Without the carrier ruling there are not enough challenges to
  schedule, and no scheduling choice matters.

**Standing-record reconciliation** — 2026-08-02 FOLLOWUPS rulings (credit-wire
round) whose premises this round changes; each must be revisited on the
record, none silently:

- **No-witness-pay lemma** → §6: premises (free miss record; secret,
  witness-chosen sets) are deleted by this design; reopening is legitimate
  but must engage the sealed text.
- **Mandatory-k ("mandate on the CHALLENGE, never the verdict")** →
  dissolves *upward* into derivation: assignments are derived, so the
  compelled nonce-commitment has nothing left to compel — the mandate
  becomes structural rather than enforced. Consistent, no conflict.
- **Step-1 plaintext-`r` residence** ("`r` rides in the winning block's
  coinbase extra alongside the records") → needs rework: there is no
  commitment carrier anymore. Where `r` (or its successor) lives is part of
  fork §7.2's anchor question.
- **Secret-set estimators** (`β̂` from pass/miss conflicts; "sets are
  secret, so a padder cannot steer") → moot: with no miss records there is
  nothing to conflict, and sets are public by design. `λ_eff` as the
  coverage statistic **survives, shape-changed** — passes per derived
  challenge, still robust-quantile not mean.
- **Audit-by-omission retraction** (two-block protocol "dead on arrival") →
  dissolved by derived assignment (§2) — the confirmation, not a conflict.
- **`ARCHIVAL_CREDIT_WIRE.md` authority rows** ("Miner-chosen set,
  coinbase-revealed — no schedule, no beacon"; "Miss fact — pass/miss
  discriminant on the wire") → superseded in part by this round; pointer
  added there.

## 9. Parameter discipline (binding on implementation)

- **W₂ must not be guessed.** It prices whole-shard transfer over the
  rendezvous path + verification + inclusion margin. Requirements imported
  from the relay-privacy round (PR #418, `verify_cost.rs`, `params.rs`):
  measured on the **Pi 4 spec floor** with provenance asserted by test (a
  below-spec archiver missing deadlines loses capital, silently); measured
  **forward-to-forward** (RTT rigs omit verification and err in the failure
  direction); field work yields a **distribution**, not a point; and the
  sizing target is the **second-order statistic of three transfer draws**,
  not the marginal tail — under 2-of-3 the epoch needs the second of three
  completions, so per-transfer completion ~0.94 delivers 0.99 epoch
  survival, whereas sizing W₂ at the marginal p99 overshoots materially and
  every extra block of W₂ widens the clock-burn window §6 prices (the §66
  per-hop-vs-sum lesson, one level up — the doc imports §66's discipline
  and must import this instance of it). The landed shape is likely a lookup
  table that refuses outside its domain — never a scalar or fitted curve.
- **Derive-don't-hardcode:** every constant this mechanism lands (challenges
  per epoch, majority threshold, W₂, penalty) follows the `DandelionParams`
  pattern — design inputs in, derived value as a method, executable
  derivation. Cautionary precedent: the inherited 39 s embargo was its own
  formula evaluated with `log10` instead of `ln`, carried for years as a
  `#define`.
- **2-of-3's reference inputs are stale:** the f ≈ 0.23 liar-containment
  figure predates this rework; re-derive alongside (m, n).

## 10. Standing rules for any agent working this

Verify every claim at file:line against `dev` **before** planning — including
this document's. Priority order: privacy > security > correctness >
performance > features. Design ratification precedes consensus code.
Genesis-irreversible decisions (TJ-H, response wire format, nonce anchor)
require their own reviewable surfaces. No pushes without explicit per-push
authorization.
