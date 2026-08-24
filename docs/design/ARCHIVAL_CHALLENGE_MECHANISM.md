# Archival challenge mechanism — design round (2026-08-07)

**Status (landed on `dev` 2026-08-11 — this file is now the record; the
branch snapshot and its superseded-in-place banner are retired):**
**Design-round output. Direction ratified; the mechanism as a whole is NOT
ratified for implementation, with one named exception — the §9.5 BUILD list,
ratified to exactly its scope** (derivation module, persona key hierarchy, the
Tor inbound half; landed as PRs #442 / #445 / #447). §9.5 *narrows* the
"do not cut consensus code" gate below rather than repealing it: everything on
the §9.5 HOLD list — pass-record serialization, the response format,
`EndpointUpdate` on the bond wire, the settlement writer — still waits on the
format round. The ruling of record from this round: challenge
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
relocated to §8 as the tx-carrier justification.
**Revised 2026-08-10 (later): fork 2 CLOSED in full** — witness =
producer of block h (the only party with a liveness oracle; a nominee
cannot be compelled post-impossibility), anchor = that block's
`cb_out_key` as a consequence; P-side already ruled (onion-bound
identity, three-tier custody, cold-authorized `EndpointUpdate`).
**Live remainder: ONE consolidated format round** (response wire,
pass-record tx carrier + prunable residence, bond-wire fields, binding
artifact, key tiers; nonce re-pinned as
`H(block_hash(h−1) ‖ cb_out_key ‖ P ‖ s ‖ E)` — `r` deleted) **then the
three derivations** (W₂; (m, n); the `λ_eff` tripwire *response*). Note
λ_target itself is **not** among them — it is ruled by §3 (= 3, landed
2026-08-11), and *k* (draws per block) is derived by the urn as λ·D/E;
the earlier "k/λ_target" framing was mandate-era, when k was a tuned
coverage parameter rather than a computed one. The `λ_eff` *statistic*
is already ruled (FOLLOWUPS: measured directly as records per pair per
epoch, robust quantile not mean, `β̂` as a correction term never a
divisor — the indirect `λ_nom·(1−β_lazy)` estimator is blind to a lazy
witness that signs and never reads); the genuine remainder is narrower
than "define the tripwire": **the response** — what the network does
when the measurement says the norm has decayed (`β_lazy → 1`,
`λ_eff → 0` is stated in the sealed record with no defined
consequence, and a measured statistic with no consequence is a
dashboard). Post-impossibility the honest candidate set is small:
client-side defaults, release-gating, possibly a consensus-visible
coverage floor. Read FOLLOWUPS' loop-check section in full before that
round.

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
  derived denominator, not a pass multiset. Pass-priority retires.
  **The threshold sub-decision is RATIFIED (2026-08-11): absolute-2.**
  `settle_epoch(passes, issued)`, three-valued: Served iff passes ≥ 2,
  full stop; issued < 2 settles **NonObservation** (a pair the urn could
  not reach twice is not a pair that failed — the §4.2 distinction), so
  the settlement-outcome row keys on *issued*, not drawable.
  Majority-of-issued is rejected because it makes the threshold a
  function of a derived quantity — a node must reproduce the urn
  derivation identically to agree on the bit; absolute-2 needs only a
  pass count, the smaller consensus surface. `to_observation` /
  `is_observation` **delete** (not demote), per the earlier ruling.
  **Stated so nobody later misreads the branch:** under the exact-min
  urn at exact budget every drawable pair receives exactly λ = 3, so
  the under-issuance branch is **unreachable** — it becomes live only
  in the capped regime (`k_cap` binding, the §8 72 %-unobservable
  case), i.e. only if the tx-carrier prunable-residence work does NOT
  land. It is specified defensively, not as evidence the mechanism
  tolerates short issuance by design.
- `EpochSettlement::to_observation` **deletes** (not re-documents): its
  "sole bridge to the m-of-n machinery" role belonged to the superseded
  design.
- `CHALLENGES_PER_EPOCH = 1` — **DONE (2026-08-11), and the framing here
  was wrong in a way worth recording.** This bullet read as though λ were
  *gated* on the (m, n) re-derivation; it is not. λ = 3 is ruled by §3,
  which carries its own derivation — the (m, n) re-pin and the sim re-run
  are **consequences** of the change, not preconditions on it. Read as a
  gate, it manufactured a "cutover" that does not exist: pre-genesis there
  is no deployed chain, so a stale constant naming the retired fire-beacon
  mechanism is legacy to delete, not state to migrate. Landed as
  `CHALLENGES_PER_PAIR_PER_EPOCH = 3` (renamed because the urn derives a
  *second* challenges-per-X quantity — per block, λ·D/E — that the old
  name invited confusion with), jointly const-asserted with
  `SERVE_THRESHOLD_PASSES` on two properties §3 ruled: the threshold must
  be reachable, and it must be a strict majority. **The sim re-run
  collected TJ-A2d's lever:** the cheap-transit watch-cell lifts
  1.095× → 3.285×, so it is no longer marginal. The (m, n) re-pin remains
  open — as it already was.
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
  that keeps the number tractable is **persistent drawability (§2 — the pool
  does *not* drain on satisfaction)**: no pair leaves the pool, served or
  not, so evasion must hold across every draw for months — the attacker
  pays per interception, repeatedly, against a one-time avoided loss. The
  penalty need not be punitive alone; it must
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
   preferred one.
   **Selection + anchor CLOSED (2026-08-10): the witness is the producer
   of block h; the anchor is that block's `cb_out_key`.** This was
   settled, not chosen — §8.2's liveness argument already decided it
   ("miners are the only population where being selected *is* proof of
   being online at that instant; block production is the one thing on
   this chain an absent party cannot fake"), and a derived nominee names
   a party that may not be mining, may not exist, may be offline, and —
   after the impossibility removed penalties — **cannot be compelled**.
   There is no oracle for anyone else's liveness; the only entity
   provably present and provably selected at height h is whoever
   produced block h. Option (b) was a conclusion re-listed as a
   question. The nonce anchor then follows as a consequence, not a
   separate decision: block h's `cb_out_key` is on chain, controlled by
   exactly the party that did the read, and it makes the
   countersignature non-transferable — nobody can use a signature bound
   to a coinbase key they don't hold.
   **The nonce's `r` term DELETES; `block_hash(h−1)` substitutes
   (checked at source, 2026-08-10).** `attestation_wire.rs:191-195`
   assigns the roles: `cb_out_key` is "the copy-freeride bind; kept,"
   `r` is "the producer's revealed randomness" — its only job is nonce
   unpredictability, stopping P from pre-signing a countersignature it
   hands out without ever being contacted. It cannot do that job: both
   `r` and `cb_out_key` are chosen by the same party, so a producer
   willing to leak one is equally willing to leak the other — a second
   producer-chosen random term does not strengthen a property that
   fails exactly when the producer defects. And the attack is *worse*
   under this round's design: under miner-chosen challenges P did not
   know whether it would be challenged; under exhaustive coverage P
   knows with certainty it gets exactly three, so pre-signing is
   strictly more attractive now. `block_hash(h−1)` closes it at zero
   cost: unpredictable to everyone before it exists, not choosable by
   block h's producer, on chain, and already fetched for the assignment
   derivation. Stated at its honest strength: the substituted nonce
   **cannot exist before block h−1 does**, regardless of any party's
   behaviour — collusive pre-signing narrows from unbounded lead time
   to one block, while fully-collusive passes remain possible (P can
   countersign whatever a colluding producer shows it at block time —
   nothing prevents that) and stay priced where they always were, by
   the 2-of-3 quadratic and the outer window. `cb_out_key` distinctness
   is enforced independently by the epoch-windowed uniqueness consensus
   rule (`ARCHIVAL_CREDIT_WIRE.md` authority row). Format-round ruling:
   nonce = `H(block_hash(h−1) ‖ cb_out_key ‖ P ‖ s ‖ E)`, and the
   property bought is **pre-signing resistance against a colluding
   producer — which `r` never provided**.
   **The residue this ruling does not settle, on its face so item 12
   does not rediscover it:** challenge servicing is available only to
   parties that win blocks, so the coverage rate is bounded by **how
   many distinct miners run the default client** — that is the `λ_eff`
   tripwire's actual subject. And a large miner performs proportionally
   many challenges: the load-concentration coupling to mining
   decentralization (§8's precondition), now a property of the ruled
   mechanism rather than a footnote.
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
   approaching 11-of-13 rotates and buys a clean window for the price <!-- doc-literal-gate-allow: archival failure-window m-of-n (slash observations), not multisig operator config -->
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
   built. (iii) **RESOLVED — no change (2026-08-11, verified at
   source): `hybrid_sign` hot is safe, because the emission claim is
   two-of-two and only one factor is the identity hybrid.**
   `emission_vin_verify_auth` requires Auth-P (hybrid signature under
   `p_pubkey`) AND Auth-B (leaf-gated:
   `hash_pqc_public_key(backing_pubkey) == pqc_pk_hash` checked FIRST —
   order pinned, `emission_verify.rs:670/:703` — then the hybrid
   signature under `backing_pubkey`), with `reward_commits` +
   `signable_tx_hash` binding the destination. A compromised serving
   host holding `hybrid_sign` produces Auth-P and nothing else: the
   backing key is the funding output's per-output PQC key, not in
   `ARCHIVAL_P_DERIVE_V1` and not on the serving box. No earnings-theft
   path; GF-1 separation plus the leaf gate were already doing the
   work, one layer down. Every hot-key surface accounted:
   countersigning-as-P harmless (the priced q² case); emission claims
   blocked by Auth-B; `EndpointUpdate` cold by ruling; debit/Unbond
   under cold `bond_spend_pk`.
   **The custody proviso the resolution rests on (verified):** the
   backing secret IS reachable from `master_seed_64` — via the
   receive-address KEM bundle (`kem_d_z` → decap → per-output
   `combined_ss` → the output's PQC seed) — but NOT from the two
   serving-side bundles (`hs_id_seed`; the identity-hybrid seeds),
   which are independent HKDF children. So the resolution holds iff
   **the serving host receives derived bundles only — never
   `master_seed_64`, never the receive/KEM bundle.** Ship the master
   seed to the box for convenience and Auth-B's protection silently
   evaporates. This is a MUST in the operator-facing text, and the
   export surface should have no path that puts the master seed in a
   serving config.
   **Consequence for §9.5 item 2:** the key-hierarchy build re-scopes
   to a delta — `ARCHIVAL_P_DERIVE_V1` already carries the ruled
   three-tier shape (debit authority, identity hybrid, `hs_id` serving
   identity — GF-1/GF-9 labels, KAT-frozen). No new labels, no corpus
   rotation. The only derivation delta is the **`hs_id` rotation
   index**, an `EndpointUpdate` prerequisite rather than a serving-path
   one: the daemon creates its service at index 0 today.
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

   **Mechanism ruling — PR-C (2026-08-11): build the path-selection half in
   Rust as typed knobs; do NOT adopt the Python addon; defer the
   circuit-killing half (Bandguards + Rendguards) entirely.** Four grounds:
   (a) the upstream `vanguards` addon is a **dropped dependency** — removed
   from Debian Trixie, disabled by default in Whonix after connection-drop
   bugs on tor 0.4.8.x — and is not a supply chain to attach a privacy
   coin's serving path to; (b) the addon runs as a **second process holding
   full control-port authority** (cookie file, `ADD_ONION`, `SETCONF`),
   which breaches the crate's no-passthrough control-plane invariant *more
   thoroughly* than the torrc escape hatch that policy already forbids;
   (c) two of the addon's three subsystems **fight our traffic profile** —
   Bandguards' ~100 MB cap is tuned for services that do not move bulk
   content, and a cap that closes a circuit mid-transfer yields an
   incomplete read, which under expiry⇒miss is an *unattributed miss that
   accrues toward a slash*: importing them wholesale installs a self-DoS on
   the exact path whose failure costs capital; (d) our own supervisor makes
   *lite* worse — Vanguards-Lite does not persist guards to disk, so a
   per-incarnation restart (backoff from 1 s, `degrade_after: 5`) re-draws
   the L2 set every flap, and every re-draw is an independent adversary
   landing chance — the over-rotation failure named above. Full vanguards
   persists the selection + rotation timestamps, which fixes this, so
   **restart-survival is a guard-topology concern, not only an `ADD_ONION`
   re-publish concern.** A bonded archiver is also the **long-lived** case
   the spec says lite does not protect (lite targets ≤ ~1 month; full
   targets services meant to run longer), and the spec sanctions the split:
   Vanguards-Lite MUST be the default, full SHOULD be available as optional
   service configuration.

   **PR-C scope, therefore:** a typed `Vanguards` knob on `ManagedTor`; a
   validated `Command::SetConf` emitting `HSLayer2Nodes`/`HSLayer3Nodes`
   over the crate's closed-set path (typed `RelayFingerprint`,
   unrepresentable-invalid, mirroring the `SetEvents` shape — never a
   free-form key=value); our **own** relay selection (bandwidth-weighted,
   from the consensus over the control port) and rotation manager with
   **on-disk persistence** reloaded by the supervisor on restart; and the
   spec's published parameters as **spec-pins, not provisional** (corrected
   2026-08-11): `NUM_LAYER2_GUARDS = 4`, `NUM_LAYER3_GUARDS = 6`, L2 lifetime
   uniform over 30–60 days (mean 45), L3 lifetime `max(X₁, X₂)` where `X₁` and
   `X₂` are **two independent** uniform draws over 1–48 hours inclusive
   (mean 31.5 — max-of-two skews longer than the 24.5 a single uniform gives;
   the spec writes this `max(X, X)`, which reads as self-equaling, so it is
   spelled out here rather than left for an implementer to take literally).
   These come from the **Sybil rotation table** — a property of
   the Tor network's adversary model (with `NUM_LAYER3_GUARDS = 6`, 50 %
   Sybil success takes ~15.75 d at 1 %, ~4 d at 5 %, ~2.62 d at 10 %), not of
   our traffic. What the rig derives is **capacity** (whether a 4-node L2 set
   carries a serving persona's concurrent rendezvous load) — a different
   question. (Divergence recorded in code: the spec *text* gives L2 uniform
   while its reference impl uses `max(X, X)` for both layers; we follow the
   analyzed spec text.) It is us implementing a Tor subsystem —
   accepted here only because the alternative is a distro-dropped Python
   package holding a second control connection. **Bandguards and Rendguards
   stay OUT** (reopen criterion, rule 21): they need CIRC-event parsing and
   a `CloseCircuit` command the crate does not have, and their thresholds
   are the **rig's** output — shipping them guess-tuned would arm a
   circuit-killer against our own bulk transfers. Because it is a
   multi-week, multi-validation-surface build, PR-C decomposes (rules
   19/26): **C1** the `SETCONF` wire path (injection-safe, closed-set);
   **C2** consensus retrieval + weighted L2/L3 selection; **C3** rotation +
   persistence + supervisor reload + the knob threaded through.

   **Accepted residual, recorded so padding is never mistaken for having
   solved it:** active confirmation by an adversary already holding the
   guard is NOT mitigated — L2/L3 pinning raises the cost of *reaching* that
   position, it does not close it; the honest bound is SPIKE-F-19's own
   (research accuracies under controlled conditions, degraded in the open
   world) — the claim is that a guard operator who cares can find out
   cheaply, not that guards know. **Withdrawn:** onion-address rotation (the guard is a
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
  coinbase extra alongside the records") → **RESOLVED by deletion
  (2026-08-10, fork §7.2's closure): `r` is removed from the nonce
  entirely and `block_hash(h−1)` substitutes.** No residence question
  remains — the term is on chain by construction, and the prunable side
  table sheds its `r` entry.
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

- **W₂ is RULED, not measured — `SETTLEMENT_EPOCH_BLOCKS / 20` = 500 blocks
  (≈16.7 h), settled 2026-08-15 and not provisional.** This bullet used to
  open "W₂ must not be guessed" and import a sizing program from the
  relay-privacy round (PR #418, `verify_cost.rs`, `params.rs`): measure on the
  **Pi 4 spec floor** with provenance asserted by test; measure
  **forward-to-forward** (RTT rigs omit verification and err in the failure
  direction); field work yields a **distribution**, not a point; size to the
  **second-order statistic of three transfer draws** rather than the marginal
  tail, since under 2-of-3 the epoch needs the second of three completions and
  per-transfer completion ~0.94 delivers 0.99 epoch survival.

  **That program is retired for W₂** (the requirements remain sound for any
  parameter that is actually sized from a distribution — they are retired
  *here*, not refuted). W₂ has pressure on **one side only**: too short slashes
  honest archivers on transfer time they do not control, and nothing at all
  pushes back on long. A number under one-sided pressure does not need finding,
  it needs to be large enough — sixteen hours against a transfer that takes
  minutes obviously is — and a measurement program would have confirmed what
  the asymmetry already guaranteed. Full reasoning on
  `CHALLENGE_RESPONSE_BLOCKS` in `constants.rs`.

  **The failure mode this cost, named because it will recur:** a discipline
  that is right in general (derive-don't-hardcode, immediately below) applied
  without first asking whether *this instance* needs it. Derivation earns its
  keep between two competing pressures where being wrong either way costs
  something. Applied to a one-sided constraint it manufactures work and, worse,
  keeps a settled question reading as open. Same category as inheriting a
  default because the pattern has one.

  **Correction (2026-08-15): the clause that used to follow —
  "every extra block of W₂ widens the clock-burn window §6 prices" — is
  retired, and with it the framing that W₂ is a two-sided optimization.**
  Clock-burn required a commitment record and an abandonment penalty;
  derived assignment superseded the first and the impossibility result
  killed the second, which is why §6 now keeps its sizing arithmetic "as
  the record of what a penalty would have had to achieve, not as pending
  work". Under derived assignment there is **no occupancy to extend** — the
  witness is the producer of block `h`, and if it does nothing, nothing is
  held. A witness that sits on its assignment wastes exactly one of the
  pair's three draws whether W₂ is 500 blocks or 5,000: clock-burn is a
  *draw-count* attack, not a *duration* one, contained by the 2-of-3
  quadratic plus the outer window. The sentence is corrected rather than
  deleted because a silent gap here is what let this keep circling — every
  re-derivation read it and reconstructed an upper bound that no longer
  exists. **The "landed shape is likely a lookup table … never a scalar"
  clause is retired with it (2026-08-15):** it presumed W₂ would be *sized
  from* this distribution, which is what a lookup table is for. Under the
  pin-by-ruling it is a scalar (`SETTLEMENT_EPOCH_BLOCKS / 20`), and a table
  would now be a lookup with one answer. **Further (2026-08-15): the
  distribution has no job here at all.** It was demoted to a floor *check*
  before the ruling was followed through; a one-sided constraint does not owe
  a check either, and leaving one standing is what kept this reading as open.
  **CONCURRENCY, not bandwidth, is the W₂ unit (pinned 2026-08-11, from
  reading the derivation module — decided before the rig is built because
  it changes what gets instrumented).** The schedule assigns λ·D/E pairs
  to each block's producer: at maturity ~97 pairs land on one block at
  once, so that producer must fetch ~323 MB **concurrently** inside W₂.
  The aggregate is unchanged and fine (a 1 % miner sustains ~32 GB/epoch
  ≈ 27 KB/s), but the shape is bursty and highly concurrent — a
  single-transfer rig under-estimates badly, missing circuit-establishment
  throughput, Tor client memory, and guard capacity. This also feeds the
  Bandguards cap and the vanguards L2/L3 sizing directly: a pinned L2 set
  carries ~97 concurrent rendezvous circuits from the same client. Any rig
  built for this must measure the **concurrent-batch completion
  distribution**, not the single-transfer one.

  **Corrected (2026-08-15) — read the addressee off the sentence above.**
  `λ·D/E` is *draws per block assigned to that block's **producer***, so the
  ~97 figure describes a **miner**, and this paragraph's own "from the same
  client" says so. It was first re-addressed to a "device-requirement question"
  — *can a rule-76 floor device carry ~97 concurrent circuits* — which closed
  the same day as **incoherent**: nobody mines on a Pi 4, so the floor device
  is never in that role. The two sides do not share a floor. Rule 76
  provisions the anonymity of the node being protected, the staker running `P`,
  which is the **serving** side: many readers on one persona, a handful at a
  time once the block's draws spread across the pair population, and already
  measured with margin by `SP_T3_SKELETON_MEASUREMENT.md` §18 (4→32 readers,
  p50 10.9 s → 14.8 s).

  So the Bandguards cap and the vanguard L2/L3 sizing are sized against the
  *serving* load, which the schedule bounds and §18 covers — not against 97,
  and not against a pending run. The producer/serving distinction is real even
  where the question built on it was not; it does not need a type in a
  disposable spike to stay true.
- **Derive-don't-hardcode, *where it earns its keep*:** the constants this
  mechanism lands (challenges per epoch, majority threshold, penalty) follow
  the `DandelionParams` pattern — design inputs in, derived value as a method,
  executable derivation. Cautionary precedent: the inherited 39 s embargo was
  its own formula evaluated with `log10` instead of `ln`, carried for years as
  a `#define`.

  **W₂ was struck from that list (2026-08-15), and the qualifier added because
  of it.** Derivation is what you reach for when a number sits between two
  competing pressures and being wrong in either direction costs something —
  which is precisely the 39 s embargo's shape. W₂ has pressure on one side
  only: a hard lower bound (honest archivers slashed on transfer time they do
  not control) and, since clock-burn lost its prerequisites, no upper bound at
  all. Under a one-sided constraint the question is not *what is the value* but
  *is this large enough*, and an executable derivation would reproduce the
  asymmetry's own answer at the cost of holding a settled parameter open. The
  rule applied without asking whether the instance needs it is the same defect
  as inheriting a default because the pattern has one — the failure it was
  written to prevent, arriving through the rule itself.
- **2-of-3's reference inputs are stale:** the f ≈ 0.23 liar-containment
  figure predates this rework; re-derive alongside (m, n).

## 9.5 Build/hold split (ruled 2026-08-11) — what implements now

The frozen-wire decisions gate anything that **serializes or validates**;
they do not gate transport, storage, key management, or derivation. The
items below are **ratified for implementation** to exactly this scope —
this narrows the status header's "do not cut consensus code" gate rather
than repealing it:

**BUILD now:**

1. **The derivation module** — `assignment(h) = f(block_hash(h−1),
   drawable_set)` plus the exact-min urn. Pure computation with no wire
   surface (under derived assignment nothing is recorded — exactly why it
   is unblocked); everything else calls it; fully KAT-able today. Highest
   value on the list. Three determinism pins it forces, decided here so
   the module does not decide them silently:
   - **Canonical pair ordering (stated exactly — the original "bytes"
     wording was ambiguous, caught in #435 review):** lexicographic by
     `p_id` bytes, then by `shard_id` **numerically** — equivalently,
     memcmp over `p_id ‖ shard_id_be` (big-endian). **NOT** the
     little-endian wire encoding of `shard_id`, under which 256 sorts
     before 1 — a second implementation sorting by the wire bytes
     would derive a divergent candidate list. Every node must index
     the same list identically; the module pins the 1-vs-256 case by
     test.
   - **Per-draw randomness:** a domain-separated cSHAKE stream (rule 30:
     explicit customization label + version) seeded by
     `block_hash(h−1)`, with the draw index within the block as a stream
     counter — never a general-purpose PRNG.
   - **λ_target is a parameter** (derive-don't-hardcode): the module
     takes challenges-per-pair as input; 3 is the 2-of-3 ruling's value,
     supplied by the caller (landed 2026-08-11 as
     `CHALLENGES_PER_PAIR_PER_EPOCH = 3`), and the legacy constant retires
     with
     its consumers (§4.4).
2. **The persona key hierarchy** — cold bond root separate; hot serving
   root with onion/attestation/SOCKS as labeled siblings under
   `keygen_from_seed`. Ruled, no wire dependency, prerequisite for the
   serving daemon existing at all.
3. **The Tor inbound half — premise corrected against source
   (2026-08-11):** the `ADD_ONION`/`DEL_ONION` surface is BUILT
   (`shekyl-tor/src/control/onion.rs`, SP-T3 — typed-parts wire
   assembly, `Detach` unrepresentable, `PoWDefensesEnabled`/queue-rate
   params in place) and the SP-T3 spike harness already drives the full
   inbound path end-to-end with `shekyl-p-transport`'s read-side twin.
   The genuinely unbuilt production half: **the persona serving loop**
   (loopback listener answering shard-by-id from the store; the
   self-authenticating-against-`R_k` response; provisional framing,
   THROWAWAY per the discipline above), **its lifecycle wiring** into
   `TorService` with the wallet-derived `hs_id` bundle (index 0 today;
   derived-bundles-only custody per §7.2 check (iii)), and **the
   vanguards-full / Bandguards launch pins** (addon-level, not
   `ADD_ONION` arguments). A W₂ concurrent-batch extension of the spike
   harness was the next step when W₂ was still a measurement. W₂ was
   ruled rather than measured, so that step is not a dependency of
   anything downstream and was not landed — a provenance type with no
   measurement to stamp is scaffolding (rule 15). **Rig expectations, set
   before it exists (2026-08-11), retained because they are how a
   measurement ships if a ruling premise returns:** off-floor hardware gives *shape, not the
   governing figure* — batch-concurrency scaling, the knees, vanguards'
   pinned-L2 behaviour under ~97 simultaneous rendezvous circuits, and
   whether Bandguards' cap trips are structural and largely
   hardware-independent, but the absolute quantile W₂ derives from
   comes from the Pi floor (rule 76) — **build the rig so a floor run
   is a re-run, not a rewrite**. Measure on the **real Tor network**,
   never a local test net (chutney has none of the latency structure
   that makes the distribution heavy-tailed); synthetic
   3,326,976-byte payloads are fine. And the sharpest form of the
   throwaway-framing discipline: a streaming or chunked serving loop
   makes **resumability** feel natural — resumability is a *format
   property* with real W₂ consequences, decided on its merits in the
   format round, never inherited from what was convenient to build.

   > **How these three get enforced, if a rig is ever scoped (revised
   > 2026-08-16 — see §9.7 item 6).** Not as three flags, and *also* not as
   > "one type carrying these three": that shape was implemented to spec and
   > still faded open through a fourth field nobody had listed. The rule is
   > **every field of the provenance record is derived from the apparatus that
   > ran, none declared by the caller** — which holds for fields nobody
   > anticipated, and an enumeration cannot.

   **The rig MUST run with `VanguardsMode::Managed` (ruled 2026-08-11,
   written before the rig exists rather than discovered afterward).** Full
   vanguards adds a guard layer, and the spec is explicit that this costs
   longer paths and higher latency — latency on exactly the path W₂
   measures. A rig run against a non-vanguards instance therefore measures a
   **shorter path than production ships**, and it under-estimates *in the
   failure-causing direction*: the same shape as the already-pinned
   forward-delay-vs-RTT rule. The failure mode is silent — the numbers come
   back looking good. So the measurement's **provenance must record the
   vanguards mode alongside the Pi-4 floor**, and a run without it is not a
   W₂ datum.
4. The two standalone PRs (#433 ordering assert, #434 coverage sim) —
   in flight.

**HOLD (correctly blocked on the format round):** pass-record
serialization; the response format; `EndpointUpdate` on the bond wire;
the settlement writer (item 9's schema is genuinely open).

**No longer held — the `settle_epoch` rewrite LANDED** (PR #437, merged):
this list previously carried it as "blocked on a ratification doable in a
sitting," §7.1 then ratified absolute-2 (2026-08-11), and the fold shipped
as `settle_epoch(passes, issued)` in `attestation.rs`. Recorded rather than
silently deleted, because the entry's own framing — a hold whose blocker was
a *decision*, not a design round — is what let it clear in one sitting.

**The strategic point:** building the serving path is what unblocks W₂ —
the measurement program needs a working transfer, not a frozen format
(3.33 MB over two Tor legs takes what it takes regardless of header
layout), and W₂ is the round's longest pole. The Bandguards cap and
vanguards parameters, both consumed by the W₂ derivation, land on the
same path.

> **Moot (2026-08-15), retained because the sequencing judgement was sound
> for its premise.** W₂ was pinned by ruling, so it was never the longest
> pole and nothing about it was blocked on the serving path. The second
> sentence goes with it: the Bandguards cap and the vanguard L2/L3 parameters
> are sized against a *serving* persona's concurrent load, which the schedule
> bounds to a handful and `SP_T3_SKELETON_MEASUREMENT.md` §18 already measured
> — they were never consumers of a W₂ derivation, and they are not consumers
> of a pending measurement either.

**The discipline that comes with it, written here and into the serving
PR's description rather than trusted to memory: the provisional framing
is THROWAWAY and gets no vote in the format round.** The failure mode is
building it and then discovering the frozen format has been quietly
shaped by what was convenient to implement — precisely the
design-precedes-consensus-code rule; the serving transport is the one
part of this that is not consensus code, and it stays that way.

## 9.6 Build-round review dispositions (2026-08-11)

Findings from the serving-path build review, recorded where the build
slices will look for them. PR-A (`shekyl-p-serve` + the store read) and
PR-B (the `TorService` onion surface + relocated v3 identity) are landed
against these.

1. **Custody boundary is *which secret crosses the process boundary*,
   not the derivation tree — resolved in PR-B.** The flat HKDF siblings
   are independent, but they all derive from `master_seed`, so a serving
   process holding `master_seed` (or holding the derived `hs_id_seed`,
   one convenient edit from the master seed) also holds `bond_spend_pk`'s
   authority — the exposure is **bond authority** (Unbond, the debit
   arms, `EndpointUpdate`), not the emission claim (Auth-B stays
   leaf-gated on `backing_pubkey`, which is not in `ARCHIVAL_P_DERIVE_V1`
   — check (iii) still resolves "no change" on *that* axis). The build
   constraint: the serving side receives the **expanded onion identity**,
   derived once wallet-side, never a seed. Made unrepresentable —
   `OnionServiceSpec::new` takes an `OnionIdentity`, not a seed.

2. ~~**The sampled-leaf verification path is fossil — do not build against
   it.**~~ **SUPERSEDED 2026-08-20 by `RF-D8` ruling (i); the correction is
   recorded here rather than the text deleted, because the original named a
   deletion trigger that has since fired.**

   *What it said:* `verify_segment_path` / `verify_leaf_index` (replaying a
   single derived-index leaf opening) belong to the retired fire-beacon design
   and sit on §2's deletion surface alongside `challenge_leaf_index`; and
   `path.rs` should be annotated onto that same surface "so a future reader
   does not resurrect sampled PoR through the implementation door."

   *What is true.* The premise held — whole-shard fetch **remains the
   mechanism**, and `recompute_segment_r_k` is still what verifies it. What
   changed is that the opening is now carried **additively on top**, which
   the standing sampled-leaf finding never argued against — it found
   sampled-leaf insufficient as a ***standalone*** mechanism, which says
   nothing against an opening carried additively on top. *(That finding was
   cited as "§5.6" by `path.rs` and by the struck text above; **this document
   no longer has a §5.6** and the anchor resolves nowhere in the tree. The
   citation is dropped rather than repaired, since the substance is restated
   here and a section number that has already drifted once is not worth
   pinning a second time.)* `RF-D8` ruling (i)
   kept the ~1,920 B opening as **the one element consensus verifies
   independently of the witness** — every other element of a pass record
   depends on witness honesty, so a witness colluding with `P` can manufacture
   a pass with `P` holding zero bytes, and the opening raises the floor from
   "`P` may hold nothing" to "`P` must hold at least the challenged leaf and
   its path". Weak and cheaply outsourced, but non-zero.

   **Consequence: `verify_segment_path` and `challenge_leaf_index` came OFF
   the deletion surface and are permanent consensus admission code**
   (`blockchain.cpp:5412` → `shekyl-ffi`'s `serve_credit.rs`), where the index
   and `R_k` are **verifier-derived** and never read off the wire — which is
   what makes them soundness-bearing rather than vestigial. The hygiene
   instruction inverts with it: `path.rs` carries the `RF-D8` ruling instead
   of a deletion annotation, and the `challenge.rs` banner was corrected
   2026-08-23 (it had kept the fired trigger and disagreed with `path.rs`).

   **Acting on the struck text would delete live consensus code.** That is why
   it is struck in place — a reader who has already followed it needs to find
   the correction where they read the instruction.

3. **The shard universe grows without bound; `D` is a moving number, not
   a maturity plateau.** `SegmentId` is dense and `segment_freeze_eligible`
   is a pure height gate, so one shard freezes per `SEGMENT_LEAF_COUNT`
   outputs, forever; `MAX_HOLDINGS_SHARDS = 4096` caps a *bond's*
   holdings, not the universe. Three unpriced consequences: challenge
   load `λ·D/E` per block rises monotonically with `D`; an archiver must
   post `HoldingsUpdate` **continuously** to keep covering new segments (a
   recurring on-chain cost, with a recurring principal-funding question
   attached — and it interacts with the cold-authorized `EndpointUpdate`
   family); and the Foundation `CompleteTree` node's holdings grow forever
   by definition. **The `D ≈ 324k` figure the round sized against is a
   snapshot, not a ceiling** — the concurrency inputs (and the
   `max_streams` / `MAX_INFLIGHT` placeholders) must be treated as
   functions of a growing `D`, not constants. *Open for the round; not a
   build blocker.*

4. **The pin set must be *derived from the bond record*, not maintained
   alongside it.** Nothing structural binds `held_shard_ids` in the
   consensus bond record to local `pin_segment` state, so a `P` that posts
   holdings and forgets to pin has *its own node* prune the leaf bytes it
   is obligated to serve — then fails challenges, then slashes, an epoch
   later, for a local bookkeeping mismatch. PR-A already shaped
   `pin_serve_set(&[u64])` to take the serve-set as an **input**; the
   **daemon-composition slice** must feed it `record_held_shard_ids` from
   the bond record (re-pinning as shards freeze), never a
   separately-maintained list. Build-list requirement, recorded so the
   composition cannot forget it.

5. **The retention economy closes cleanly, and it should be stated.** The
   witness verifies a `SEGMENT_LEAF_COUNT·128`-byte response against a
   56-byte `FrozenSegmentRecord`, and `prune_frozen` keeps `R_k` while
   discarding leaves — so a pruning full node retains exactly what it
   needs to *challenge* and nothing it needs to *serve*. **Verification is
   free; storage is the scarce thing; the asymmetry is structural**, which
   is what makes challenge coverage cheap for miners (the property GF-7
   and the coverage sim implicitly rely on). Worth stating as a first-class
   property rather than leaving implicit.

6. **The witness-side fetch-and-recompute path is equally unbuilt.** The
   build survey's "net for a serving loop" was entirely `P`-side; the
   witness leg (fetch the whole shard over the rendezvous,
   `recompute_segment_r_k`, compare to the on-chain `R_k`) is the other
   half, and it is **W₂-rig scope** — the rig measures both legs of the
   3.33 MB transfer.

## 9.7 The composition slice (SH-1, landed 2026-08-12)

§9.5 item 3's "lifecycle wiring" and §9.6 items 1/4 land together in
`rust/shekyl-p-host`, because they are the same object: the serve-set's
provenance, the pin, the onion, and the listener have one lifetime or they
have none. Six dispositions worth the record — the last two are **open
hazards SH-1 does not close**, written here rather than left for SH-2 to
decide implicitly.

**1. The composition is entirely Rust, and nothing crosses the FFI.** The
serving host's three inputs are all already wallet-side: the shard bytes are
the wallet's redb `LeafStore` (the daemon's LMDB curve tree is the consensus
copy and is not involved), the onion is the wallet's own `TorService`, and
the connected `held_shard_ids` come back over the **existing**
`get_archival_emission_claim_source` RPC, whose wallet-side decode already
exists in Rust and already rides the persona transport. Recorded because the
rule-20 question was asked explicitly and the honest answer is *no C++ was
added and none needed deleting* — the boundary did not move because this
slice never reaches it.

**2. Pinning is a store write, so it cannot live on the serving side.** The
`LeafStore` is single-writer redb, and its single writer is the wallet's
curve-tree actor — that is what the actor is *for*. §9.6 item 4's "feed
`pin_serve_set` from the bond record" therefore could not be implemented by
handing the serving host a store handle: that is a second writer beside the
one whose message loop is the serialization. The split: the host holds a
read-only `ServingReader` (redb readers are MVCC snapshots, so serving reads
run concurrently with block ingest at no cost), and the pin runs on the
actor's own object behind a `ServeSetPinner` seam. The serving side now has
no write to reach.

**3. The serve-set's provenance is closed against drift, not against
forgery — stated rather than implied.** `ServeSet`'s only constructor takes
a decoded `ClaimantBondRecord`, so there is no way to start a serving host
from a list maintained alongside the record; it also stamps the chain height
it was read at, so a stale set is distinguishable rather than merely wrong.
What that does **not** close: `ClaimantBondRecord` is an ordinary struct, so
a caller determined to fabricate one can. The accidental path — the drifting
parallel list — is the one §9.6 item 4 names, and it is gone. Making the
fabricated path unrepresentable too needs a sealed decoder type minted only
by the claim-source decode; **that is SH-2's, on the crate that owns the
decode**, and is written here so it is owed rather than discovered.

*Why it is owed rather than tolerated:* with `ClaimantBondRecord`
constructible by anyone, the drift invariant rests on **the production chain
being the only one anyone uses** — which is convention, and convention is
what the rest of this slice refuses everywhere else. The reachability check
makes it a live gap rather than a hypothetical: the fabrication site would be
an ordinary-looking struct literal in the wiring, indistinguishable at review
from the correct call.

**Closure criterion (SH-2).** A type minted **only** by
`EmissionClaimSource::from_json` — a private-field newtype over the decoded
record, or `BondContext::record()` returning it — such that
`ServeSet::from_connected_record` cannot be called with a hand-assembled
value. Discharged when no path to a `ServeSet` exists that does not pass
through the claim-source decode, provable by the constructor's visibility
rather than by inspecting call sites.

**Reopen criterion (if SH-2 declines it).** The gap stops being tolerable the
moment a *second* production caller derives a serve-set — today there is
exactly one planned (the wiring's refresh path), and one call site is
reviewable by reading it. A second consumer, a test-support constructor that
escapes `#[cfg(test)]`, or any FFI surface that accepts holdings from outside
the decode all re-open this item at its full weight.

**4. A new load-bearing invariant, in the same class as the vanguards
one: a serving host must never rebind its listener.** `TorService`
republishes the onion on every incarnation from one `OnionServiceSpec`
holding one loopback target. A listener rebound under an unchanged spec
(`:0` picks a fresh ephemeral port) leaves the published descriptor pointing
at a dead port — the persona looks healthy, publishes at its advertised
address, and answers nothing, until the slash. So the endpoint binds once,
the host owns it for its whole life, there is no rebind method, and teardown
stops tor *before* the listener so no descriptor outlives the port it names.
Exactly the shape of "a tor restart must not cause a rotation" (§7.4), and
silent in exactly the same way.

**5. CLOSED (2026-08-15) — deriving the pin set from the connected record
makes it reorg-sensitive, and the type system cannot reach this one.** Items 3 and 4
are about *how* a value is constructed, which a type can settle. This is
about *when* it is recomputed, which no signature can express. Verified at
source, and the state of it is worse than "needs reconciliation":

- `PinnedServeSet` is minted **once, at `start`**. Nothing in SH-1
  recomputes it. `ServeSet::as_of_height` makes staleness *detectable*, and
  nothing yet reads it.
- The store clears pins on **tree** rollback only —
  `truncate_from_tree_position` deletes pins at and above the truncation
  point, which is what `rollback_to_fork` drives. Holdings live in the bond
  record, not the leaf store, so a reorg that changes `held_shard_ids`
  **without moving the tree** is invisible to every pin-clearing path there
  is.
- There is **no unpin path at all**. Pins are cleared by truncation and by
  nothing else.

Two directions, and they are not symmetric:

*Gained shard (the direction that slashes).* A reorg — or an ordinary
`HoldingsUpdate`, which §9.6 item 3 says an archiver must post
**continuously** to keep covering new segments — puts a shard in the
connected record that the running host never pinned. A `prune_frozen` in that
window discards its bytes, `AlreadyPruned` is terminal (the remedy is a chain
replay, not a retry), and the persona is now obligated to serve a shard it
provably cannot. Exactly §9.6 item 4's hazard, re-entering through the
refresh axis after the construction axis closed it.

*Departed shard (the direction that leaks).* A shard leaving holdings leaves
its pin forever. At `MAX_HOLDINGS_SHARDS = 4096` and
`SEGMENT_LEAF_COUNT · 128 ≈ 3.33 MB` per shard, unbounded churn against a
growing `D` retains up to ~13.6 GB the node is no longer obligated to hold —
on a rule-76 Pi-4 floor. Not a rounding error, and not self-correcting.

**The asymmetry that should govern the fix, ruled here so SH-2 does not
decide it implicitly: acquiring a pin needs no finality; releasing one
does.** Acquisition is idempotent, additive, and already designed to run
ahead of the freeze — re-pinning a superset on *every* serve-set refresh
costs a bounded write and closes the slashing direction completely. Release
is the dangerous verb: a holdings change that is later reorged back can, if
the pin was already released, have let a prune discard bytes no re-pin
restores. So the release path needs a finality depth (and the reclaim it
buys is disk, which is recoverable; the loss it risks is a slash, which is
not). Today's "never release" is the *safe* default and the correct one to
ship SH-1 on — it fails toward retention — but it is a leak, not a policy.

**Closure criterion (SH-2).** Re-derive and re-pin on every claim-source
refresh, unconditionally; and either implement release behind a stated
finality depth or record "never release" as a **ruled** disposition with its
retention cost priced against the provisioning floor. A refresh that reads
`as_of_height` and re-pins is the whole of the slashing-direction fix.

**CLOSED (2026-08-15).** Both halves. The slashing direction closed with
SH-2a's unconditional re-pin, driven every refresh by SH-2b-2. The leaking
direction is now an implemented **release behind a finality depth**, taking
the first of the two exits rather than the "never release" ruling — the
maintainer's call, on the grounds that the space has to come back.

**The gate is epoch-shaped, not reorg-shaped, and the review that caught it
is worth recording.** The first implementation gated on
`ARCHIVAL_REORG_DEPTH_BLOCKS` (720) — "has this departure settled on the
chain". That is the wrong quantity. §4 quantizes drawability to epoch
boundaries: a pair is drawable in E iff it held the shard at **E's open**,
and that fixed pre-challenge evaluation is the WS-1 constraint — no
tip-holdings read that would let `P` drop the shard after the fire and
escape. So a mid-epoch drop does not end the obligation for E; the pair
stays drawable, and challengeable, through E's close — roughly 9,280 blocks
after a 720-block gate would have released.

It bites at the pin rather than one layer up because
`StoreShardProvider` is **serve-set-blind**: it holds only a `ServingReader`
and answers for any shard whose bytes are in the store. So the leak is
currently what *keeps the obligation met* — a dropped-but-still-pinned shard
is still served. Releasing on a reorg depth would have converted a disk leak
into a miss, then a slash: §9.7's own asymmetry pointed the wrong way.

**The condition is two consecutive epoch opens of absence.** Then the shard
was not drawable in the current epoch or the one before, so the last epoch it
could have been drawn in closed a full epoch ago. Two rather than one because
one is too tight — absent at only the current open leaves the previous epoch
as the last drawable one, and a challenge issued in its final block still has
to resolve; the extra epoch is that slack.

**W₂ is deliberately not an operand.** The window is now a landed scalar
(`CHALLENGE_RESPONSE_BLOCKS` = 500, item 6a) and one epoch of slack still
covers it by a factor of twenty, which at ~14 days against a window measured
in minutes-to-hours is not a close call. **Reopen (rule 21):** if
`SETTLEMENT_EPOCH_BLOCKS` is re-pinned such that W₂ is no longer strictly
shorter than one epoch, this gate is wrong and must take W₂ as an operand.

The reorg question the naive gate answered is subsumed, not dropped: §2 notes
drawability is evaluated at epoch open, "deep history relative to any
plausible reorg, so the drawable set is reorg-stable". Two epoch boundaries
is far deeper than 720 blocks.

`LeafStore` gained the two verbs it never had (`pinned_shard_ids`,
`release_pins`); the pin table was previously written by `pin_serve_set` and
cleared by truncation and *nothing else*, which is what made a departed
shard's pin permanent. `EngineServeSetPinner` holds the departure ledger and
owns the gate, and **clears a shard's entry if it returns** — so a departure
that reverses inside the window leaves no trace and restarts the clock if it
leaves again.

Two residuals, both stated rather than discovered:

- **The ledger is in memory, per session.** A restart forgets the clock and
  restarts it, so a wallet that reopens often reclaims more slowly. It never
  releases *early*, which is the only direction that is irreversible, and it
  is why persisting it was refused: the reclaim is disk (recoverable) and the
  price would be a schema version plus a migration.
- **Release lags the pin by one refresh.** The reconcile learns the store's
  pin set from the reply it is answering, so the difference is acted on next
  time. Against a 720-block gate that is not a lag that means anything, and
  it keeps the refresh at one actor round trip.

The store deliberately does **not** enforce the gate — it has no clock, no
view of the record, and no memory of when a shard left one. A half-check
there would look guarded while the real condition went unenforced.

**6a. W₂ IS PINNED (2026-08-15) — ruled, closed, no measurement owed.**
`CHALLENGE_RESPONSE_BLOCKS = SETTLEMENT_EPOCH_BLOCKS / 20` (500 blocks,
≈16.7 h), collapsed from its `Option<u64> = None` staging slot per the pin
shape that slot specified. What made it pinnable is not a measurement but a
**ruling: W₂ has no surviving upper bound.**

Every argument for keeping it small was clock-burn, which required a
commitment record (superseded by derived assignment) and an abandonment
penalty (killed by the impossibility result). Under derived assignment there
is no occupancy to extend — the witness is the producer of block `h`, and if
it does nothing, nothing is held. Clock-burn is a draw-count attack, not a
duration one. The remaining candidates are slack: settlement bookkeeping
already grants `CHALLENGE_RESOLUTION_BLOCKS` = one full epoch of grace;
outstanding-challenge count is bookkeeping; `P`'s availability burden is
unchanged; and DDoS makes a **longer** window a defense, as §6 already
lists. One candidate raised in review and rejected — **outsourcing
resistance** — fails because the economics invert it, half of it is not an
attack, and decisively because a short W₂ does not prevent the cheap (local)
form anyway.

The lower bound is hard (too short slashes honest archivers on transfer time
they do not control) and the upper bound is absent, so the shape is *pick
generous, not optimal*. The band ≈200–500 is the ruled part; the divisor is a
consequence, written as a fraction so it tracks if `SETTLEMENT_EPOCH_BLOCKS`
is ever re-pinned.

**The rig is owed nothing, and W₂ is closed.** This paragraph previously
demoted the rig to a floor check — "does the honest concurrent-batch p99 on
the Pi-4 floor, on the real Tor network under `VanguardsMode::Managed`, fit
inside 500 blocks with room to spare?" — which was a half-step: a check that
can only move a value in the safe direction, applied to a constraint that is
already one-sided, confirms what the asymmetry guarantees. **Correction
(2026-08-15): W₂ is ruled and not provisional; no measurement is owed.**

**Reopen (rule 21)** is now about the ruling's *premises*, not about a run:
clock-burn regains both a commitment record and an abandonment penalty
(restoring an upper bound where none survives), or `SETTLEMENT_EPOCH_BLOCKS`
is re-pinned and carries W₂ out of its ≈200–500 band. Either means re-running
the ruling and widening the band deliberately.

**The Pi-4 residual turned out not to exist.** Whether a floor device is
CPU-bound on Tor crypto at ~97 concurrent circuits was first split out as a
**device-requirement** question — filed in `docs/FOLLOWUPS.md`, then **closed
the same day as incoherent**. `λ·D/E` ≈ 97 is draws per block assigned to that
block's *producer*, and a producer is a miner; nobody mines on a Pi 4, so the
floor device is never asked the question. A serving persona sees a handful of
concurrent readers once those draws spread across the pair population, which
`SP_T3_SKELETON_MEASUREMENT.md` §18 already measured at 4→32 with room to
spare.

The split itself was still right — the residual had to leave W₂, because
keeping it attached is what dragged a settled parameter back open twice. What
the split then exposed is that the residual was assembled out of two facts that
belong to different machines. Retiring a mandate does not sanitise the premises
it carried.

**6. CLOSED as not owed (2026-08-16) — a provenance type with no measurement
to stamp is scaffolding; the REQUIREMENT was revised on the way out and is
reusable: derive every field from the apparatus, do not enumerate three.** Item 6a's ruling means no W₂ run is pending, so
the three-attestation type was not landed. A first cut did land it in
`shekyl-sp-t3-spike` (`RunProvenance`, `w2-measure`, a third `bring_up`
wrapper, a producing shape of 97 onions on one tor) and then had to invent
`is_floor_datum` / `MeasuredSide` / a "floor check" verdict to give the
scaffolding something to say. That is the half-step item 6a already named:
a check whose only possible outcome is a safe-direction move, applied to a
one-sided constraint, confirms what the asymmetry already settled — and the
implementation failed open besides (`ARCH == "aarch64"` certified any Apple
Silicon box as a rule-76 floor datum; the producing shape measured the
co-activation layout this harness already forbids). Rule 15 deletes unused
callees; the type is gone with the rig. The requirement below is retained
as written because the reasoning is what generalises, not because a run is
owed. If a ruling premise returns and a measurement is scoped, this is how
it ships — not before.

*Original text, retained:* **the W₂ rig's three provenance requirements are
stated in §9.5 but not wired.** `VanguardsMode::Managed`, the rule-76 Pi-4 floor, and the
real Tor network (never chutney) are today three sentences of prose in three
places. Each one's failure mode is silent and points the same way: a
non-vanguards run measures a shorter path than production ships, an off-floor
run measures faster hardware than the floor, and a chutney run has none of the
latency structure that makes the distribution heavy-tailed. All three come
back *looking good*. Prose cannot stop a run that violates one from producing
a number that then gets cited.

### Requirement, REVISED (2026-08-16) — derive every field, do not enumerate three

**The finding that forced the revision: indivisibility was necessary and it
was not sufficient.** The first cut implemented the original requirement *to
spec* — one type, three attestations, no constructor taking fewer — and the
gate still **faded open**. `is_floor_datum()` certified any `aarch64` box as a
rule-76 floor datum, so a producer-shaped batch run on a floor device would
have stamped "rule-76 provisioning input" on the wrong machine's number. That
is precisely the laundering this item exists to prevent, and it arrived
**through a field nobody had listed**.

That is the generalisable lesson, and it is not "make it indivisible":

> **An indivisible-value requirement is only as strong as the completeness of
> its field list, and completeness is not checkable from inside the
> requirement.** Enumerating the fields that must travel together says nothing
> about the field you did not think of — and the omitted field is where the
> defect lives, because a field nobody listed is a field nobody reasoned about.

What actually caught it was not the enumeration. It was **deriving** the
missing field (`MeasuredSide`, read off the apparatus's own persona count)
rather than accepting it as an argument the caller supplies. A declaration can
be wrong or absent; a value read off the apparatus that ran cannot disagree
with the run. Evidence over assertion, the same call as the vanguards witness
being mintable only from a confirmed `SETCONF`.

**So the requirement, restated as the stronger property:**

> The provenance record is a single value **every field of which is derived
> from the apparatus that ran** — none declared by the caller, none defaulted.
> A W₂ datum is a value of that type, so an incomplete run yields no datum
> rather than an unlabelled one.

This does not depend on having enumerated correctly. A field that is derived
is one the run cannot misreport whether or not anyone anticipated it, and a
requirement that admits no declared field has nothing for an unlisted one to
slip through. Where a fact genuinely originates outside the apparatus (the
batch width, which only the caller ran), take *that* and derive everything the
apparatus can supply from the apparatus itself.

*Superseded text, retained:* "The rig's provenance record is a **single type
that cannot be constructed without all three**… Three separate flags checked
at three points is the shape that fails, because it makes 'record the mode' a
step someone can skip; one indivisible value is the shape that holds." Correct
as far as it goes — three-flags-at-three-points is still the shape that fails,
and `ServingPosture::Serving` carrying the onion and the vanguards mode as one
value is still the same call. It is retained rather than deleted because
"necessary but not sufficient" is only legible next to what it was.

This lands with a rig if one is ever scoped, not before — a provenance type
with no measurement to stamp is scaffolding.

## 10. Standing rules for any agent working this

Verify every claim at file:line against `dev` **before** planning — including
this document's. Priority order: privacy > security > correctness >
performance > features. Design ratification precedes consensus code.
Genesis-irreversible decisions (TJ-H, response wire format, nonce anchor)
require their own reviewable surfaces. No pushes without explicit per-push
authorization.
