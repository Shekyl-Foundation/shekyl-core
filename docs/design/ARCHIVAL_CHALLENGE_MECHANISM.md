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
  derivation**.
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
   supersession machinery dissolves.)
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
     means re-accepting that residual under the new fold, knowingly.
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
   the frozen response wire — decide with TJ-H (§7.4).
3. **Expiry semantics** — the irreducible residue of "a miss is never
   asserted," and (per §4.2) the under-covered epoch collapses into it.
   On-chain, "witness abandoned" and "P failed to serve" are the same
   absence, and with no miss record the per-challenge outcome space is only
   {pass, expired}. The 2026-08-02 record bears on both branches:
   **expiry⇒miss re-creates laziness-poisons** — the failure mode whose
   analysis killed the record-mandate ("the mandate converts laziness from
   silence into noise"), now without even a fabrication step: mere witness
   inaction damages P, coupling honest P's slash risk to non-witnessing
   hashrate (2-of-3 tolerates one abandonment; beyond ~⅓ non-witnessing,
   honest archivers start failing epochs). **Expiry⇒uncounted inherits
   laziness-empties** plus corner 2's documented cost: a durably dark P is
   never observed, never misses, never slashes — "retention teeth die
   (already ruled unacceptable)" — though a colluding P now shields itself
   only at visible, penalized abandonments per epoch, forever. The sealed
   precedent "a committed-but-unfiled nonce is a non-observation the
   three-valued settlement already absorbs" was ruled for the
   mandate-on-the-challenge design and must be re-examined under 2-of-3
   rather than assumed. Either branch leaves evasion priced, partial, and
   auditable (vs the superseded design's free/total/invisible). Choose
   together with the §6 penalty and the (m,n) re-pin — the outer window is
   where either branch's failure probability is actually priced.
4. **TJ-H (genesis-frozen — decide FIRST):** fixed shard payload size is a
   guard→persona traffic-confirmation oracle; variable-length padding is a
   wire-format property of the frozen response format
   (`SP_T3_SKELETON_MEASUREMENT.md` §20). Cannot be added later.
5. **W₂ derivation** — see §9; not guessable, and **gated on fork 2** (a
   response deadline prices "long enough that an honest P serving a bulk
   read is not timed out, short enough that a dishonest P cannot stall,"
   and both terms are functions of who reads, how many readers there are,
   and what happens when they fail — none of which exists before forks 1–3
   settle). Deriving W₂ first would be picking a number and back-filling
   the justification.
6. **Witness reward residence** — gated on the §6 lemma reopening; not a
   simple emission-split question.
7. **(m, n) re-pin** under the nested measurement (§3), jointly with fork 3
   (the outer window prices whichever expiry branch is chosen).

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
  until it lands.

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
