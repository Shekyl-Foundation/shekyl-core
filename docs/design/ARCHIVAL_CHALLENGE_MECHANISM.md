# Archival challenge mechanism — design round (2026-08-07)

> **THIS COPY IS THE ROUND'S OPENING SNAPSHOT (2026-08-07) AND IS
> SUPERSEDED IN PLACE.** The round iterates on the
> `design/archival-challenge-mechanism` branch per the WIP-design-doc
> policy and lands here once, when it closes. Rulings made since this
> snapshot live there — including the fork closures (attribution
> impossibility, expiry⇒miss, exact-min urn, producer-witness), TJ-H,
> the `EndpointUpdate` rulings, the §9.5 build/hold split, and the
> **§7.1 `settle_epoch` threshold ratification (absolute-2,
> 2026-08-11)** that `attestation.rs` implements. Where this snapshot
> and the branch disagree — e.g. §7's "open forks" framing or §3's
> majority wording — **the branch is the record.**

**Status:** **Design-round output. Direction ratified; mechanism NOT ratified
for implementation.** The ruling of record from this round: challenge
assignment is **derived, not committed** (§2, ruled 2026-08-07 — "the more the
system regulates itself, the better"; derivation makes challenges verifiable
by anyone and scope-limited against DDoS). Everything else here is the round's
grounded state: settled constraints, one schema-gating finding (§4), and the
open forks (§7) that must be resolved **in this document or a successor, not
implicitly in code**. Do not cut consensus code from this document until it is
marked ratified.

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

**Anti-DDoS scope property (part of the ruling):** deriving from the
*previous block's hash* strictly limits how far ahead challenge windows are
knowable, so an attacker cannot precompute P's obligated-to-serve schedule.
This property is in tension with exact-coverage scheduling — that tension is
fork §7.1, not something to resolve silently.

**Reorg semantics fall out for free:** a `pop_block` leaves nothing to void —
assignments re-derive on the new chain; a pass record anchored to a reorged
block loses its anchor. The prior round's open item 3 answers itself.

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
- `archival_baseline_observed_at_epoch` retires per §4.1 — on the Half-B
  deletion surface, after drawability lands.

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

- **Witness compensation: no reward term exists** (`reward_arithmetic.rs`
  has scarcity, reward-share, `r_market` — no witness leg). Load-bearing
  gap: the abandonment penalty and honest participation both hang off it.
- **Abandonment:** an assigned witness that never resolves burns the slot
  for W₂ blocks. Penalty sizing target: exceed (position value × attacker
  hashrate share) ÷ (interceptions needed), floored by honest tolerance of
  genuine read failures. Bond-sized and reward-sized are both wrong (former
  deters all honest witnessing; latter ~3 orders above target).
- **DDoS on P:** the derived window is the targeting surface; §2's
  limited-scope property plus 2-of-3 redundancy plus long-W₂ (a *defense*
  here — more completion chances) are the mitigations. Converting DDoS to a
  slash requires sustained suppression across m of n epochs.
- **Foundation CompleteTree nodes** are outside this economy by design
  (`market_member_at_epoch` returns false). Do not design incentives for
  them.

## 7. Open forks — resolve on this record, never implicitly in code

1. **Derivation granularity** (coverage vs targeting window). Epoch-seed
   permutation gives denominator = 3 by construction but publishes every
   window 10,000 blocks ahead (DDoS surface). Per-block derivation keeps the
   one-block scope but yields a random draw — under-coverage returns and
   §4.2's row-per-drawable-pair fallback becomes mandatory. Candidate
   synthesis: per-block seed selecting among the *least-covered* drawable
   pairs (a deterministic urn) — coverage converges to exactly 3, targeting
   window stays one block, at the cost of pending/complete bookkeeping in
   the derivation. **Choose explicitly.**
2. **Witness identity and nonce anchor.** Ruled: derivability means *anyone
   can verify* a challenge is legitimate, and P serves only derived-
   legitimate reads. Open: is the witness (a) the assigned block producer
   (nonce anchors that block's `cb_out_key`, non-transferability as landed) or
   (b) **open** — any party performs the read within the window and any miner
   includes the pass? (b) dissolves most of the witness-capable-hashrate
   precondition (§8) and softens expiry semantics (a volunteer can complete an
   abandoned challenge), but reopens what replaces `cb_out_key` as the
   session's non-transferability anchor. The nonce format touches the frozen
   response wire — decide with TJ-H (§7.4).
3. **Expiry semantics** — the irreducible residue of "a miss is never
   asserted": on-chain, "witness abandoned" and "P failed to serve" are the
   same absence. Expiry⇒miss couples honest P's slash risk to
   non-witnessing hashrate (2-of-3 tolerates one abandonment; > ~⅓
   non-witnessing hashrate starts failing honest archivers). Expiry⇒uncounted
   lets a colluding P shield itself at three visible, penalized abandonments
   per epoch, forever. Either way evasion is now priced, partial, and
   auditable (vs the superseded design's free/total/invisible) — but the
   branch, and the penalty that prices it, must be chosen together with §6.
4. **TJ-H (genesis-frozen — decide FIRST):** fixed shard payload size is a
   guard→persona traffic-confirmation oracle; variable-length padding is a
   wire-format property of the frozen response format
   (`SP_T3_SKELETON_MEASUREMENT.md` §20). Cannot be added later.
5. **W₂ derivation** — see §9; not guessable.
6. **Witness reward residence** in the emission split (§6).
7. **(m, n) re-pin** under the nested measurement (§3).

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

## 9. Parameter discipline (binding on implementation)

- **W₂ must not be guessed.** It prices whole-shard transfer over the
  rendezvous path + verification + inclusion margin. Requirements imported
  from the relay-privacy round (PR #418, `verify_cost.rs`, `params.rs`):
  measured on the **Pi 4 spec floor** with provenance asserted by test (a
  below-spec archiver missing deadlines loses capital, silently); measured
  **forward-to-forward** (RTT rigs omit verification and err in the failure
  direction); field work yields a **distribution**, not a point; the landed
  shape is likely a lookup table that refuses outside its domain — never a
  scalar or fitted curve.
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
