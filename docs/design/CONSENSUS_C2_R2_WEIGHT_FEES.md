# C2-R2 — Block-weight / reward-zone / fee constants design round

**Status:** **SIGNED (Rick, 2026-09-06), with amendments recorded per
ruling:** Q1/Q2/Q4/Q6/Q7/Q8/Q9/Q10/Q11 ratified (Q1 with the GAP-7
condition discharged in the passing direction — floor figure in the census
notes; Q10 with corrected headroom and the 0x0A rule-15 row); **Q3
amended — the window/hysteresis half ratified, the ×50 surge factor
REFUTED-NOT-SUPERSEDED by GAP-7's floor measurement** (§3 Q3 carries the
strike-through, the named refuter, and the re-derived bound's numbers for
signature); **Q2 COUNTERSIGNED on the corrected two-regime rationale** — its own
mandated instrument refuted the early-chain half of the first signed
reason; the corrected text, Rick's account of the refutation, the
embedded trace, and the load-bearing Q2↔Q3 coupling are all in §3 Q2.
**Numbering note (family C2-R2-Q1…Q11): Q5 does not exist as a heading —
it was allocated to the `margin` deliverable and DISSOLVED into §6 when
that was reclassified as a derivation (a consequence of Q2/Q3), not a
ruling. Recorded rather than renumbered so every cross-reference stays
valid.** On close this document moves to `docs/completed/` as the round's
ruling record (rule 95).

Third design round of the C2 program
([`CONSENSUS_RULE_CENSUS.md`](CONSENSUS_RULE_CENSUS.md) §10 batch R2, 8
rows). The round is **ratification-only** (steering constraint, program-wide):
no in-round crossings to Rust, no C++ mechanism changes — docs and gates only.
Where a ruling implies mechanism, it is **recorded and specified for the Rust
store port**, which consumes these rows; it is not built ahead of it.

**Pinned sha:** `ab4693d0e8` (`dev` tip at dispatch). Every `file:line` in
this document was located at this pin.

**Fee-ladder citations:** [`FEE_LADDER_DERIVATION.md`](FEE_LADDER_DERIVATION.md)
is ON DEV (PR #614 merged 2026-09-05, `d82fcf31c`) — the plain-text pins the
draft carried (`ccfb85c72`) are converted to links in this PR, per the
sequencing rule the draft recorded: lifting the eight `R2 DEFERRED` census
markers is a state change on dev asserting the reopen condition is met, and
the evidence now IS on dev. During the window between #614's merge and this
PR, dev deliberately carried the inconsistency (FL-R12′ signed there, census
still deferred) — the recorded cost of refusing a premature clear.

**Reopen conjuncts, verified at the artifacts (not relayed):**
(a) FL-R12′ **SIGNED** — FEE_LADDER_DERIVATION.md §8 (commit `6689b0cff`,
review round 8): composition `paid = max(M_r·curve(remaining), TAIL) ·
penalty(x)`, penalty **after** the floor, build authorization YES. (A stale
§0.1 passage in that document read "conjunct (a) is OPEN" — written at
review round 4, never updated after the round-8 signature; found here via
`git log -S`, routed to the fee lane, and **fixed on #614 at `2e29f67d1`**,
verified at that sha: §0.1 now records was-open-until-round-8-signed and
"census-R2 is unblocked per its own criterion.")
(b) The exhaustion-boundary test `terminal_reward_legs_agree` — **also
branch-only**: it lives in `emission.rs` on the fee-ladder branch
(FETCH_HEAD `ccfb85c72` :318), not on dev (grepped at the pin: zero hits;
the census §10 text describing it is describing a branch artifact). Green
through the new owner per the §8 BUILT record. Both conjuncts therefore
share the same detectability profile — evidence on an unmerged branch —
which is the sequencing rationale above applied twice, not once.

**Identifier family:** `C2-R2-Q1…Q11` (registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) this PR, rule 94).

**Authority chain:** census §10 R2 + rows CEN-G6, G6b, F14b, H1, H3, M3, M4,
M10; census §12 GAP-6/GAP-7/GAP-8; FEE_LADDER_DERIVATION.md (FL-R12′, FL-R13,
FL-D4, FL-D5 — pinned `ccfb85c72`); `DAEMON_SUBMIT_VERDICT.md` §8 rows N3, P2,
P3; [`CONSENSUS_C2_R1_REORG.md`](CONSENSUS_C2_R1_REORG.md) (round-shape
precedent); rules 00 / 06 / 16 / 19 / 20 / 21 / 22 / 42 / 50 / 60 / 71 / 76 /
90 / 94 / 95.

**Scope fences (all explicit; see §7 for the GAP-6 decision):**

- **FL-R13** (fee-floor basis calibration — whether `Fl ∝ R` is the right
  permanent tail-era anti-spam floor) stays in the fee-ladder lane. This round
  ratifies or re-derives the *relay fee machinery's* constants (CEN-M3); it
  does not touch the floor-basis question, which has its own pre-registered
  round.
- **R7** owns mempool **admission semantics** — census rows CEN-M1, M2, M6,
  M7, M11 (pool idempotency, NIC caching, relay-side spend pre-checks, U-4's
  pool-vs-Dandelion++ timing question). This round takes only M10's **numeric
  policy constants** (livetime, pool weight cap, eviction ordering as an
  economics choice); the semantics of admission around them are R7's.
- **Credit-wire lane** keeps M4's canonical-form arbitration (per the SA index
  row) — deferred there, not done here. This round rules only the 24 576
  bound.
- **GAP-6** (launch-phase emission ramp) is not one of the eight rows and is
  **not ruled here** — §7 records the fence as a decision with reasons, not a
  default.
- **A consensus fee floor does not exist today** (CEN-M3: "no consensus fee
  floor"). Introducing one would **mint a new consensus rule**, which exceeds
  ratification-only and is the maintainer's ruling to make. §5 Q9 poses and
  analyses the census §6 question and **stops at a recommendation**.

---

## 1. Round structure — three groups, split by validation surface

The census's own C/P column is the discriminating axis, and the split is a
**validation-surface split, not a topic split** (rule 19's criterion —
consensus rows and relay-policy rows fail differently, are tested differently,
and are ratified against different artifacts). This is stated so a later
reader does not "tidy" the three groups back into one fee-and-weights topic.

| Group | Rows | Surface | The decision |
| --- | --- | --- | --- |
| **R2a** | CEN-G6, G6b, F14b (+ GAP-7 leg, + the `margin` deliverable, §6) | Consensus (block connect / reward function) | The block-size governance contract: zone, clamps, window, surge, penalty curve — one system, ruled as one |
| **R2b** | CEN-H1, H3 | Consensus (per-tx static caps) | The per-transaction bounds, including the verification-cost leg they were never derived against |
| **R2c** | CEN-M3, M4, M10 | Relay policy (pool admission values) | The fee-formula and pool-policy constants, plus the census §6 consensus-fee-floor question (analysis → recommendation only) |

Sequencing inside the round: **R2a rules before R2b's H3 is valued**, because
H3's 149 400 is mechanically derived from R2a's zone
(`300 000 / 2 − 600`, §4 Q7) — a value ratification of H3 before the zone is
ruled would be circular.

---

## 2. Ground at the pin (the machinery, verbatim)

All weight/fee machinery constants are hand-maintained in
`src/cryptonote_config.h`, **not** in `config/consensus_constants.json` — the
file whose own header declares it "single source of truth for
consensus-affecting constants whose drift between C++ and Rust would cause
silent wrong-output." Several already have free-floating Rust mirrors
(`rust/shekyl-wire/src/transaction.rs:126–150`: `MAX_TX_EXTRA`, `MAX_TX_SIZE`,
`MIN_BLOCK_WEIGHT`, `COINBASE_BLOB_RESERVED_SIZE`, `TX_WEIGHT_LIMIT`) —
documented as mirrors but asserted only against themselves, i.e. the exact
drift-pair class `consensus_constants.json` exists to kill. §8 carries the
record-and-specify consequence.

**Weight-limit system** (`blockchain.cpp:6540–6597`,
`cryptonote_config.h:55–61`):

```text
LTEM  = max(300 000, median(long-term weights over min(100 000, height)))    # long-term effective median
stored long-term weight = min(max(w, LTEM·10/17), LTEM·17/10)                # the 1.7× clamps (6548–6552)
EM    = max(min(max(LTEM, ST_median), 50·LTEM), 300 000)                     # effective median (6580–6588)
        where ST_median = median of the last 100 block weights (CRYPTONOTE_REWARD_BLOCKS_WINDOW)
limit = 2 · EM                                                               # next block's weight limit (6591)
```

Constants: zone `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 = 300 000`
(:58), long-term window `100 000` blocks (:59), surge factor `50` (:60),
short-term window `100` blocks (:55), coinbase reserve `600` (:61).
`get_min_block_weight(version)` ignores its argument and always returns the
V5 zone (`cryptonote_basic_impl.cpp:81–85`) — the vestigial version arm is
CEN-G6b's recorded residue, rule-60 material for the port.

**Penalty curve** (`rust/shekyl-economics/src/emission.rs:150–176`, the sole
owner; C++ marshals): median soft-raised to the zone; `w ≤ m` ⇒ full base;
`m < w ≤ 2m` ⇒ `base·(2m−w)·w/m²` in u128, checked-mul fail-closed;
`w > 2m` ⇒ `BlockTooBig` (inclusive bound at exactly `2m` — CEN-F14's recorded
divergence). Under FL-R12′'s signed composition the curve multiplies the
**floored** paid reward: `paid = max(M_r·curve(remaining), TAIL) · penalty(x)`
— the penalty never dies at the tail.

**Per-tx caps** (`tx_verification_utils.cpp:66, 82, 203–210`): blob size ≤
`CRYPTONOTE_MAX_TX_SIZE = 1 000 000` (Rule 1); weight ≤
`get_transaction_weight_limit` = `300 000/2 − 600 = 149 400` (Rule 4). The
limit function still carries a dead pre-`HF_VERSION_PER_BYTE_FEE` else-arm
(:208–209) — rule-60 deletion residue for the port, recorded here.

**Relay fee floor** (`blockchain.cpp:4363–4405`, `tx_pool.cpp:243–259`):

```text
fee_per_byte = max(1, ⌊ 0.95 · base_reward · 3000 / fee_median² ⌋)           # 0.95 = "lo -= lo/20" (4367)
               with fee_median = min(limit/2, LTEM)                          # (4377, 4385)
needed_fee   = ceil(weight · fee_per_byte / mask) · mask,  mask = 1 000 atomic  # 10^(9−6) (blockchain.h:598–601)
accept iff fee ≥ needed_fee − needed_fee/50                                  # the 2 % buffer (4399)
kept_by_block exempt (tx_pool.cpp:250) — NO consensus fee floor exists.
```

Reference weight `DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT = 3 000`
(`cryptonote_config.h:70`); quantization `PER_KB_FEE_QUANTIZATION_DECIMALS =
6` against display precision 9 (:333).

**tx_extra cap** (`tx_pool.cpp:261–269`): ≤ `MAX_TX_EXTRA_SIZE = 24 576`
(:353), `kept_by_block` exempt; consensus side has no extra bound beyond H1.

**Pool lifetime/weight** (`tx_pool.cpp:1070–1071, 532, 211`): livetime
3 days (`86 400·3`, `cryptonote_config.h:97`), `kept_by_block` 7 days (:98),
pool cap `DEFAULT_TXPOOL_MAX_WEIGHT = 648 000 000` (:336) — the comment says
"3 days at 300000", which is true **only at a 120 s block target**
(`648e6 = 2 160 × 300 000`; `2 160 = 3·86 400/120`). Shekyl's target is 120 s
(`config/consensus_constants.json` `daa_target_seconds: 120`), so the value is
currently coherent — but the coupling is undocumented at the constant, and a
target change would silently falsify the "3 days" claim. Eviction: lowest
fee/byte first (`prune`).

**Consumer sweeps** (run at the pin; the instrument for every "sole consumer"
claim below): each constant's full file set —
`SURGE_FACTOR`: config.h, blockchain.cpp, `rust/shekyl-economics-sim/swing.rs`
(sim-only). `LONG_TERM_WINDOW`: config.h, blockchain.cpp. `ZONE_V5`: config.h,
cryptonote_basic_impl.cpp, blockchain.cpp + 5 Rust files (sim, wire, ffi
tests, emission, fee_policy). `MAX_TX_SIZE`: config.h,
cryptonote_basic_impl.cpp, shekyl-wire. `MAX_TX_EXTRA_SIZE`: config.h,
cryptonote_tx_utils.cpp, tx_pool.cpp, shekyl-wire. `MEMPOOL_TX_LIVETIME`:
config.h, tx_pool.cpp, relay-privacy tests, engine submit_watchdog.
`DEFAULT_TXPOOL_MAX_WEIGHT`: config.h, cryptonote_core.cpp, tx_pool.cpp.
`REWARD_BLOCKS_WINDOW`: config.h, blockchain.cpp.
`COINBASE_BLOB_RESERVED_SIZE`: config.h, tx_verification_utils.cpp,
tx_pool.cpp, shekyl-wire.

---

## 3. R2a — the block-size governance contract (CEN-G6, G6b, F14b)

The five values (zone 300 000; clamps ×1.7 / ×10⁄17; window 100 000; surge
×50; ST window 100) plus the quadratic penalty are **one control system**:
the zone sets the guaranteed floor, the penalty prices expansion inside
`[m, 2m]`, the ST median lets demand raise `m`, the surge cap and the
long-term clamps bound how fast, and the long-term window sets the era over
which "normal" is measured. They are ruled as one contract because a value
change in any one re-derives the others (the census's charge — that they
"fossilize as Shekyl economics without ever having been derived for Shekyl" —
is a charge against the *system*, not five separate numbers).

### Q1 — the 300 000-byte penalty-free zone (the "fossil flag" arbitration)

**The punt, located:** `GENESIS_TX_WIRE_FORMAT.md:806–811` explicitly punted
the zone's arbitration "to the economics doc"; no economics doc, decision-log
entry, or FOLLOWUPS row (pre-#584) received it. 300 000 is consumed as given
at `ARCHIVAL_SETTLEMENT_WRITER.md:130` and decision log :4686. This round is
the arbitration the flag has waited for.

**Derivation for Shekyl (what the zone must satisfy):**

1. **Tx-capacity leg.** The zone must hold a useful number of
   worst-case transactions. The per-tx weight cap is derived *from* the zone
   (H3: `zone/2 − 600`), so the zone guarantees ≥ 2 maximal transactions per
   penalty-free block by construction — the real constraint is the typical
   FCMP++ tx. Bounds at the pin (`GENESIS_TX_WIRE_FORMAT.md` §10: 8 inputs,
   16 outputs): the per-output PQC extra alone is ≈ 1 120 B (0x06 KEM
   ct) plus 32 B (0x07 leaf hash), so a typical 2-output spend runs **≈ 4–8 kB**
   (an estimate — prefix + extra + BP+ + FCMP proof; not a measured
   corpus), putting the zone at roughly **35–75 typical transactions per
   free block** (≈ 17–37 tx/min at T = 120 s). A launch-adequate floor
   with the penalty pricing expansion beyond it, and demand-driven growth
   (Q2/Q3) unbounded above.
2. **Throughput-floor leg.** At T = 120 s the zone yields a guaranteed
   ~2.5 kB/s of penalty-free chain growth (≈ 79 GB/year worst-case at the
   permanent free floor) — storage-viable on the rule-76 floor device's
   storage class, and the archival-retention economics (bond floor, horizon)
   were calibrated against chains of this order.
3. **Verification-cost leg (GAP-7) — the leg no inherited record has.** The
   zone is also a *work* bound: the largest penalty-free block must verify on
   the Pi 4 floor comfortably inside T. **This leg cannot be discharged at
   this pin: no floor-provisioned verify-time measurements exist** (§7). The
   two legs above stand on their own; this leg is a named blocker.

**Proposed ruling (Q1):** ratify **300 000**, *conditionally* — the economic
legs (1–2) support it as a launch value and nothing in Shekyl's design pulls
toward a different number, but the ratification is **incomplete until the
GAP-7 floor measurement (§7) is on record**, and the ruling text must carry
that condition rather than silently dropping the leg (dropping it would
re-create the exact `pinned-not-re-derived` state this round exists to end).
Class on signature: `ratified` — **the GAP-7 condition DISCHARGED in the
passing direction, and the census note carries the FLOOR figure, not the
fastest-machine figure** (Rick's condition): the zone-point worst-case
cold block measures **7.23 s ≈ 6.0 % of T = 120 s on the Pi 4 floor
itself** (canonical flagless capture, PR #625's archived record) — the
permanent penalty-free operating point is comfortable on the stated
minimum spec. No new evidence class was minted (census §2 owns the
taxonomy; the discharge is a note on `ratified`).
**Fossil-flag discharge, in full:** the flag (`GENESIS_TX_WIRE_FORMAT.md`
:805–811) is not only the value — it is the **V1/V2/V5 variant lineage**
(20 000 / 60 000 / 300 000, version-gated getters referencing Monero forks
that never happened here). The ruling therefore also specifies, for the
port (rule 60, record-and-specify): **one** `REWARD_ZONE` constant, V1/V2
variants and the version-gated `get_min_block_weight(version)` deleted.

**Falsifiers:** (defect) a floor-device measurement showing a 300 000-byte
worst-case block verifying in a substantial fraction of T = 120 s falsifies
the ratification and forces the zone (or the verifier) to be re-derived —
this is precisely what §7's instrument can produce; (fix) the ruling is
falsified as *recorded* if, after signature, `GENESIS_TX_WIRE_FORMAT.md`'s
fossil-flag passage still reads as an open punt — the same PR must land the
cross-reference discharging it.

### Q2 — the 1.7× long-term clamps and the 100 000-block window

**What they do:** the stored long-term weight is `clamp(w, LTEM·10/17,
LTEM·1.7)`, so the 100 000-block median (LTEM) can move at most ×1.7 per
half-window reached — the **slow governor**. Growth to a sustained new level
is bounded by ×1.7 per ≥ 50 000 blocks (≈ 69 days at T = 120): full
saturation multiplies capacity by at most ~1.7 every ~10 weeks. The
symmetric lower clamp (10/17) prevents a withholding miner coalition from
deflating LTEM faster than it can grow.

**Shekyl-specific check:** the clamps' *rate* interacts with two Shekyl
surfaces the Monero lineage never had: (i) the archival-retention horizon
(`retention_horizon_blocks: 420 000`) — a 1.7×/50 k-block growth curve can
multiply stored-chain size by ≤ 1.7⁸ ≈ 70× inside one horizon, which the
bond economics must (and per the D3/R2 linear-work record, does) price as
work rather than assume away; (ii) the P2P lane's `entry_max` (§6), which
needs exactly this rate.

**Ruling (Q2) — SIGNED, RATIONALE UNDER CORRECTION (its own mandated
instrument refuted half of it; countersignature pending):** the clamp pair
and window were ratified with the reason "a doubling time of ~2
half-windows (≈ 20 weeks sustained)". **Running the signature-mandated
saturating trace against the exact `blockchain.cpp:6540–6566` machinery
falsified that reason for the EARLY CHAIN: the window is
`min(height, 100 000)`, so below height 100 000 the median lags by half
the CHAIN, not half of 100 000 — under saturation LTEM compounds to
≈ 1 944× the zone by block 20 000 and ≈ 6 657× by 100 000.** At full
window the claim is exact (a monotone window's median is its midpoint
element: LTEM_n = 1.7·LTEM_{n−50 000}). **Corrected rationale proposed
for countersignature:** ratify the clamp pair and window with the honest
two-regime statement — asymptotic ×1.7 per 50 000 blocks once the window
is full; a RAMP-IN regime for the first 100 000 blocks (≈ 4.6 months)
where the long-term governor is structurally weak and **the binding
early-chain protection is Q3's re-derived verification-time bound**,
which caps EM directly and does not lean on LTEM's slowness. The
symmetric-clamp deflation argument stands unrefuted.

**COUNTERSIGNED (Rick, 2026-09-06), with his own account carried rather
than smoothed:** *"I ratified Q2 on 'doubling ~2 half-windows ≈ 20
weeks,' and the instrument I mandated shows that reason is false for the
first 100,000 blocks — min(height, 100 000) means the median lags half
the chain below full window, so saturation compounds to ~1,944× the zone
by block 20,000. My stated reason was wrong precisely where a new chain
lives, and it took running the check to see it."* The trace did the job
the falsifier existed to do; recorded as such.

**LOAD-BEARING COUPLING (in both this row and Q3's, so neither can be
revisited alone):** the ramp-in regime's protection is load-bearing, not
incidental — **Q3's verification-time bound at surge_max = 4 is the ONLY
thing bounding early-chain weight growth** while the window fills, so
**any future loosening of surge_max REOPENS Q2, not just Q3.** (Rick:
*"that coupling is exactly the kind that goes silent otherwise, and it's
the third time this week a bound has turned out to be the sole remaining
guard on a property something else was assumed to cover."*)

**The mandated saturating trace (embedded per the falsifier — this run
is the record):** instrument = the exact `blockchain.cpp:6540–6566`
machinery (stored weight = clamp(w, LTEM·10/17, LTEM·17/10); LTEM =
max(zone, median of last min(height, 100 000) stored weights); miner
saturates at the pre-refutation ceiling each block; 160 000 blocks):

```text
n=  20 000   LTEM/zone =  1 943.98   (claimed envelope: 1.7)
n=  40 000   LTEM/zone =  3 304.70   (1.7)
n=  60 000   LTEM/zone =  4 527.66   (2.89)
n=  80 000   LTEM/zone =  5 617.94   (2.89)
n= 100 000   LTEM/zone =  6 657.46   (2.89)     <- window full here
n= 120 000   LTEM/zone =  8 666.88   (4.913)
n= 140 000   LTEM/zone = 10 434.05   (4.913)
n= 160 000   LTEM/zone = 13 084.77   (8.352)
```

Every pre-100k point refutes the old claim; the post-100k slope tends to
the exact ×1.7/50 000 asymptote (a monotone window's median is its
midpoint element: LTEM_n = 1.7·LTEM_{n−50 000}). The ratified two-regime
statement is what this trace supports.

**Falsifier:** the rate claim is checkable by construction — a simulated
weight trace saturating every block must show LTEM ≤ LTEM₀·1.7^⌈n/50 000⌉.
The instrument is a simulation of the §2 formulas (the same instrument as
§6's, which was run at draft time; `swing.rs` carries the constants but no
trace generator — the simulation accompanies the signature record). A
trace exceeding the bound falsifies the governor reading, and therefore
the ratification's stated reason.

### Q3 — the ×50 surge factor and the 100-block short-term window

**What they do:** EM may exceed LTEM by up to ×50 on the strength of the
100-block median alone — the **fast governor**: short bursts (a market
event, a settlement-epoch boundary, an embargo release) clear at up to 50×
the long-term norm without waiting weeks, while the long-term clamps keep
the burst from becoming the new baseline unless sustained. The ST median of
100 (≈ 3.3 hours) is what makes the burst *demand-priced*: 51 of the last
100 blocks must actually fill for the median to move (§6 derivation).

**Shekyl-specific check:** ×50 against a 300 000 zone means a worst-case
transient block of `2·50·LTEM` — at launch (LTEM = zone), 30 MB. The
pre-parse blob cap admits `limit + 100` (CEN-A5), so the surge factor **is**
the DoS ceiling on a single block's parse cost at the connect surface. This
binds the surge ratification to GAP-7's cost model harder than any other
value in the round: the economics can absorb a 30 MB transient; whether the
floor device can *verify* one inside useful time is exactly the unmeasured
leg.

**Ruling (Q3), AS SIGNED WITH AMENDMENT (Rick, 2026-09-06):** the
**100-block ST window and the 51-block hysteresis are RATIFIED** (the
order-statistic definition was checked independently at signature). The
second half is **NOT ratified**: ~~ratify ×50 as the transient ceiling
conditional on GAP-7~~ — **the ×50 surge factor is REFUTED, not
superseded: GAP-7's floor measurement fired against it** (the surge-
ceiling cold block ≈ 316 % of T on the Pi 4 — the named refuter is the
GAP-7 record, PR #625's archived captures). The condition's own text
named the re-derivation target correctly: the surge factor, not the zone.

**The re-derived bound, numbers on this diff for signature** (all from
the canonical flagless floor capture and the signed f = 1/3):

> `surge × (max_tx_count × verify_floor) ≤ f·T`, with
> **verify_floor = 128.77 ms per argmax tx = 9.90 µs/weight-byte**;
> zone-point worst cold block **7.23 s ≈ 6.0 % of T** on the floor.
> **surge_max ≈ 6.5 at depth 2** (an UPPER bound — omitted acceptance-
> path residue only lowers it); batch bracket **[≈6.0, ≈6.5]** (free,
> conservative); **DEPTH TIERS: ≈6.5 @ d2 / ≈5.7 @ d7 / ≈4.0 @ the
> consensus-max d24** (composed from the relay bench's floor-measured
> per-layer slope). Never quote 6.5 without its depth.

**SIGNED (Rick, 2026-09-06): surge_max = 4 — the d24 CONSENSUS-MAX
figure.** His reason, in the ruling: *"a constant signed at today's depth
is a gate whose subject decays with the chain, silently, with nothing
firing. Same class as `RETENTION_HORIZON_BLOCKS` and the doc-links
coupling."* Derivation inputs, on the row: verify_floor = 128.77 ms/tx
(9.90 µs/weight-byte), f = 1/3, f·T = 40 s, depth d24. **And so the next
reader sees the choice rather than the number: d2/d7 would have signed
6.5/5.7 — the difference between those figures and the signed 4 IS the
decay the reason names.** The ×50 strike-through above stands as
refuted-by-measurement; ×4 is its re-derivation, not its successor by
assertion. **LOAD-BEARING COUPLING (mirrored in Q2's row): during the
first ~100 000 blocks this bound is the ONLY protection against
early-chain weight growth — the long-term governor is structurally weak
while its window fills (Q2's corrected rationale) — so any future
loosening of surge_max reopens Q2, not just this row.**

**Falsifier (defect):** the hysteresis claim ("51 full blocks minimum to
move EM") is falsified by exhibiting a 100-value multiset where fewer than
51 elements ≥ X yields median ≥ X — impossible for the order-statistic
median (`epee::misc_utils::median` of 100 averages the 50th/51st order
statistics; both ≥ X requires ≥ 51 elements ≥ X). Recorded as checked by
inspection of `median()`'s definition at the pin.

### Q4 — the ArticMine quadratic penalty curve (CEN-F14b)

**Class today:** `KAT-port` — an 81-vector KAT asserts the Rust port equals
the C++ curve (`docs/CHANGELOG.md:1178`), but a KAT proves fidelity to the
inherited curve, not that the curve is right for Shekyl (Survey A's claimed
"A3 fee round" examination has no locatable record — census finding, and this
round does not resurrect it).

**What FL-R12′ did and did not examine (steering correction, folded):**
FL-R12′'s signed content is **placement** — the composition
`paid = max(M_r·curve, TAIL) · penalty(x)` with the penalty **after** the
floor — plus, through its W5 disposition, one endpoint of the curve:
`penalty(1)` forfeits the whole paid reward, so expansion to the cap costs
the full `TAIL` forever. It did **not** examine the curve's *form* between
the endpoints; the fee-ladder rung derivation *consumed* the shape as an
operand (its §5 derives the rungs "from Shekyl's own penalty function" —
consumption, not examination, the same distinction the census applies to
CEN-M10's livetime). An earlier draft of this section let the placement
ruling stand in for the shape examination; that would have closed the
census's actual charge under cover of a signature. The shape is examined
here instead.

**Derivation of the form, for Shekyl.** Write the curve as paid-fraction
`P(x)` over the expansion ratio `x = (w−m)/m ∈ [0,1]`. **The derived curve
and the shipped formula are identical, not merely compatible** —
substituting `w = m(1+x)` into the inherited form:

```text
(2m − w)·w/m² = (2m − m(1+x)) · m(1+x) / m² = m(1−x) · m(1+x) / m² = 1 − x²
```

This identity is load-bearing twice: it is the bridge from the derivation
to the code it ratifies (the curve derived in `x`-space *is* the formula
at `emission.rs:150–176`, checkable by the substitution above), and it
makes the verdict **"examined, value unchanged"** — no consensus change,
no migration, no rule-42 trigger; the strongest outcome a
`pinned-not-re-derived` row can reach. Three boundary conditions on
`P(x) = 1 − x²`, each independently motivated:

1. **`P(0) = 1`** — a block at the median pays nothing: the zone/median is
   the *guaranteed* capacity (Q1), so the penalty must vanish there or the
   guarantee is false.
2. **`P′(0) = 0`** (smooth entry) — the median is a *noisy order
   statistic* of 100 samples (§6's machinery): honest miners sit at `m ± ε`
   through no choice of their own, and any curve with a first-order term at
   `x = 0` taxes that jitter. The penalty must be second-order small for
   small overshoots.
3. **`P(1) = 0`** (cap confiscation) — this is the leg FL-R12′'s W5 *did*
   examine and now depends on: composed with the inclusive `2m` bound
   (CEN-F14's recorded divergence), the cap is economically self-enforcing
   before it is structurally enforced, permanently at the tail.

Within the exactly-integer-computable power family `P(x) = 1 − xⁿ`
(consensus arithmetic must be exact — u128, checked-mul, no
transcendentals; the port's fail-closed arithmetic is already the
correctness half), conditions (2)+(3) admit every `n ≥ 2`, and **`n = 2`
uniquely maximizes the mid-range congestion price** (`x² ≥ xⁿ` for all
`n ≥ 2` on `[0,1]` — arithmetic, checkable by inspection): among
smooth-entry curves that confiscate at the cap, the quadratic is the one
that prices the surge region hardest, which is exactly where the fast
governor (Q3) needs the price to live. Scope stated honestly: this selects
within exact polynomial curves satisfying (1)–(3); it does not compare
against fundamentally different governance mechanisms, which are out of
this round's scope.

**Proposed ruling (Q4):** ratify the **quadratic penalty** for Shekyl on
the derivation above. Class on signature: `KAT-port` → `ratified`, with
**this section as the shape examination**, FL-R12′ §8 as the placement +
cap-endpoint examination (pinned `ccfb85c72`), and the 81-vector KAT as
the port-fidelity limb — three limbs, each named for what it actually
covers. Coupling recorded both directions: a shape change reopens the
fee-ladder rung numbers (they are derived from this curve), and FL-R12′'s
W5 disposition depends on leg (3).

**Falsifiers, per limb:** (fidelity) the KAT — instrument
`cargo test -p shekyl-economics`, observed green at the pin (79 passed);
a red run falsifies the port limb and blocks signature. (shape) the
max-bite claim is arithmetic (`x² ≥ xⁿ` for `n ≥ 2` on `[0,1]`) —
checkable by inspection, falsified by exhibiting a counterexample.
(premise reopeners, rule 21, tied to premises not magnitudes) any change
that makes the effective median noise-free removes condition (2)'s
motivation and reopens the convexity choice; a measured mainnet episode
of mid-range expansion the quadratic demonstrably failed to price reopens
it from the other side.

---

## 4. R2b — the per-tx static caps (CEN-H1, H3)

### Q6 — the 1 MB serialized-size cap (CEN-H1)

**What it is:** a pre-semantic parse/DoS cap, three sites
(`tx_verification_utils.cpp:66`, `cryptonote_core.cpp:728`,
`cryptonote_basic_impl.cpp:88–90`). It is **not** the binding tx bound —
H3's 149 400 weight cap binds ~6.7× tighter for any tx whose weight tracks
its size. The 1 MB cap's live job is bounding the parse of a *malformed or
padding-heavy* blob before weight is even computed.

**Derivation for Shekyl:** the cap needs to be (i) comfortably above the
largest well-formed tx (≈ 149 400 weight-limited — margin ~6.7×, so no
well-formed tx ever meets it: the cap never governs honest traffic); (ii)
small enough that parsing one costs the floor device negligible work
relative to T. Parse cost at 1 MB is linear deserialization — orders of
magnitude below verify cost — so leg (ii) holds on any device that can run
the node at all; this cap is the one row whose GAP-7 exposure is negligible
by construction.

**Proposed ruling (Q6):** ratify **1 000 000** with its job stated: a
parse-bound sanity cap deliberately ~6.7× above the semantic weight cap so
that exactly one bound (H3) governs well-formed transactions. Class:
`pinned-not-re-derived` → `ratified`. The hand-maintained constant and its
free-floating shekyl-wire mirror migrate to `consensus_constants.json` at
the port (§8) — recorded, not built.

**Falsifier:** the "H3 binds tighter" premise is arithmetic
(`149 400 · max_weight_to_size_ratio < 1 000 000` for any tx where weight ≥
blob size; weight ≥ blob size holds by `get_transaction_weight`'s
construction — weight adds BP+ clawback to blob size, never subtracts).
Exhibiting a well-formed tx with blob size > 1 MB and weight ≤ 149 400
falsifies the premise and re-opens the ruling. (Construction verified at
the pin: `get_transaction_weight` returns `blob_size` or `blob_size +
bp_clawback`, never less — `cryptonote_format_utils.cpp:321–331`.)

### Q7 — the tx weight cap 149 400 = zone/2 − 600 (CEN-H3)

**Formula, not literal:** `get_transaction_weight_limit` computes
`get_min_block_weight()/2 − CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE`
(`tx_verification_utils.cpp:203–210`); shekyl-wire's `TX_WEIGHT_LIMIT`
re-derives it and compile-asserts 149 400. The value is **downstream of Q1's
zone** — this ruling ratifies the *formula* (the "inherited scaling" the
census flagged) and inherits the value from Q1.

**Derivation of the formula's two terms:** `/2` guarantees any two maximal
transactions fit one penalty-free block — equivalently, no single tx can
demand more than half the guaranteed free capacity, so a full-weight tx can
never be censored-by-arithmetic when a competing full-weight tx exists, and
no tx *requires* the penalty region to clear at all (a tx that could only
clear via penalty would price its inclusion off other users' reward, an
externality). `− 600` reserves the coinbase blob so "two maximal txs +
coinbase" genuinely fits: 600 bounds the coinbase's weight contribution
(one tagged-key output + reward-emission structure at genesis rules; the
constant's adequacy for Shekyl's loud-emission coinbase is checkable at the
wire format and holds at the pin — a Shekyl coinbase serializes well under
600 bytes).

**The never-examined block-connect side (the census's finding):** the exam
on record (`DAEMON_SUBMIT_VERDICT.md` §8 N3) covered the **submit path**.
The connect-side reachability at the pin: `ver_non_input_consensus` (Rule 4,
`tx_verification_utils.cpp:82`) runs on relay admission *and* on the
pool-supplement path at connect (the CEN-H5 corrected walk, census §5.4.1),
and `kept_by_block` entries bypass `check_fee` but **not** Rule 4 — so the
weight cap is enforced on every tx that reaches a block through any live
path at this pin. Recorded here as the missing connect-side statement; the
port's Rust store must preserve exactly this property (a connect path that
skips Rule 4 would admit a >149 400 tx into a block whose own weight limit
still holds, silently shifting the bound from per-tx to per-block).

**Proposed ruling (Q7):** ratify the **formula** `zone/2 −
coinbase_reserve` with the two-maximal-txs rationale, the value riding Q1;
ratify **600** as the coinbase reserve with its adequacy stated against
Shekyl's coinbase wire format. Class: `examined-disposition` → `ratified`
(both paths now on record). Rule-60 residue recorded: the dead
pre-per-byte-fee else-arm (:208–209) deletes at the port.

**Falsifier (defect):** the connect-side claim ("no live path reaches a
block without Rule 4") is the load-bearing statement — its instrument is the
CEN-H5 corrected walk (census §5.4.1) plus the `kept_by_block` arm at
`tx_verification_utils.cpp:82` showing Rule 4 carries no `kept_by_block`
exemption (verified at the pin: the exemption exists only in the fee and
tx_extra checks, `tx_pool.cpp:250, 262`). Exhibiting a connect path that
admits a pool-absent tx without `ver_non_input_consensus` falsifies it.

---

## 5. R2c — relay-policy constants (CEN-M3, M4, M10)

### Q8 — the fee-formula constants (CEN-M3)

The four unexamined choices, each now examined **as a choice**:

1. **The 0.95 factor** (`lo -= lo/20`): a deliberate 5 % undershoot of the
   theoretical fee so that fee-per-byte quotes computed from *slightly stale*
   reward/median snapshots still clear admission — it prices the snapshot
   race, not the transaction. Keep: the race it prices is structural
   (wallet quotes then submits).
2. **The 2 % acceptance buffer** (`fee ≥ needed − needed/50`): the same
   tolerance applied at the acceptor's side for quantization boundary cases.
   Together with (1) the total tolerance is ~7 % — small against the ×4
   fee-ladder rung spacing (pinned `ccfb85c72` §5), so the buffers cannot
   move a tx between rungs; they only stop spurious rejects at rung edges.
3. **The reference weight 3 000**: the normalization making
   `fee_per_byte · 3000` ≈ the fee of a "reference tx" at one median — a
   scaling constant whose value cancels out of relative fees; its only
   requirement is stability, and it is KAT-covered via `check_fee`
   (`DAEMON_SUBMIT_VERDICT.md` P2).
4. **The quantization mask 1 000 atomic** (10⁹⁻⁶): fee precision 10⁻⁶ SKL
   against display precision 10⁻⁹ — a fee-fingerprinting reduction (coarser
   fees = smaller fee-value anonymity partition) that costs a user at most
   999 atomic per tx. The privacy direction is right; the magnitude is
   consistent with the fee-ladder's quantize-the-whole-scalar amendment
   (FL-R12′ §8, pinned `ccfb85c72`).

**Proposed ruling (Q8):** ratify all four as **relay-policy values with the
jobs stated above**, explicitly *not* consensus (the census's "no consensus
fee floor" finding stands; see Q9). The fee **median's** own machinery
(`min(limit/2, LTEM)`) rides R2a's rulings. Class: `examined-disposition` →
`ratified` (policy). The unpayable-reward reject-all state named in the
census row **exists at this pin** (`get_current_fee_per_byte`'s failure-arm
`return 0` at `blockchain.cpp:4380–4381` → `check_fee` rejects all); its
removal is FL-R16a, **BUILT on `feat/fee-ladder-impl-1` — a separate PR
after #614**, so this row's ruling records the retirement as *specified and
in flight*, not present.

**Falsifier:** claim (2)'s "cannot move a tx between rungs" rests on the
premise **minimum adjacent fee-rung ratio > ×1.07**. At the pin the tier
contracts (fee-ladder §5.5, pinned `ccfb85c72`; three tiers per FL-R17)
space rungs at ×4 in the drafted ladder — note the §5.5 area's
×1.25/×6.7/×20 figures are *candidate-set divisors* (inverse usage
shares), not fee ratios, and must not be read as rung spacing. The
reopener is tied to the premise: any fee-lane adoption of adjacent rungs
closer than ×1.07 falsifies claim (2).

### Q9 — the census §6 question: is a consensus fee floor wanted?

**Boundary (restated from the fence):** a "yes" mints a new consensus rule;
that exceeds this round's ratification-only mandate and is the maintainer's
ruling. This section analyses and **recommends only**.

**The ground:** today the fee floor exists only at relay admission
(`kept_by_block` exempt) — a miner may include zero-fee transactions of its
own choosing. The census §6 notes serve-credit txs *rely* on this exemption.
What a consensus floor would buy: spam resistance that does not depend on
every miner's relay policy. What it would cost: (i) it breaks the
zero-fee-by-design archival families (serve-credit; reward-emission) unless
they are exempted *in consensus*, which turns a clean vin-taxonomy rule into
a fee-taxonomy rule; (ii) it hard-couples consensus validity to the reward
snapshot (a tx valid in one block's fee climate becomes invalid in
another's — reorg-fragile validity, the exact class the unlock_time rulings
avoided); (iii) the threat it addresses (miner self-dealing spam) already
pays the penalty curve past `m` and the storage bond economics below it —
the attack is priced twice without a floor.

**Recommendation:** **no consensus fee floor.** The relay floor plus the
penalty curve plus archival bonds price the spam surfaces a floor would
target, without making tx validity climate-dependent or complicating the
archival vin taxonomy. **Proposed reopening criteria (rule 21):** (a) a
measured mainnet episode of miner-included spam at sustained volume the
penalty curve demonstrably failed to price, or (b) any consensus change that
removes the `kept_by_block` relay exemption's justification (the archival
zero-fee families leaving the protocol). Put to the maintainer as a
recommendation with these reopeners; not ruled here.

### Q10 — the tx_extra relay cap 24 576 (CEN-M4)

**Derivation:** tx_extra is the only unstructured payload surface a
transaction carries; 24 576 = 24 KiB ≈ 16 % of the weight cap. The cap's job
is bounding chain-storage graffiti and the fee-free data channel at relay,
while `kept_by_block` exemption keeps historical/reorg blocks valid — the
consensus side deliberately has no extra bound beyond H1 (a consensus extra
bound would be a canonical-form rule, and *that* arbitration is the
credit-wire lane's, per the fence). Headroom, computed rather than
asserted (`GENESIS_TX_WIRE_FORMAT.md` §9.6a, §10): the largest
protocol-legitimate extra at the pin is a 16-output tx's PQC fields —
16 × ≈ 1 120 B (0x06 KEM ciphertexts) + 16 × 32 B (0x07 leaf hashes)
≈ **18 432 B**, plus the 0x05 ownership entries the first computation
omitted (34 B each, ≈ **544 B** at 16 outputs — signing-round
correction), leaving ≈ **5 600 B (~23 %)** for payment metadata and
future fields — the figure the falsifier is checked against. Adequate,
**not** generous: any new per-output extra field of ≥ ~350 B exhausts it
at 16 outputs, which is exactly why the canonical-form arbitration
(credit-wire) matters. **Rule-15 row found at signature: 0x0A
(`PQC_SPEND_AUTH_PUBKEYS`) has NO PRODUCER** — declared (`tx_extra.h:48`,
`tx_extra.rs:50`), parsed (`tx_extra.rs:233`), picked
(`cryptonote_format_utils.cpp:540`), but nothing anywhere constructs it;
the only write arm is the codec's generic branch. Delete or justify at
the port (FOLLOWUPS row).

**Proposed ruling (Q10):** ratify **24 576** as a relay-policy bound with the
job stated; the canonical-form question stays deferred to credit-wire
(deferred-not-done, restated). Class: `examined-disposition` → `ratified`
(policy).

**Falsifier:** the headroom claim is falsified if any protocol-legitimate
extra payload at the pin exceeds 24 576 bytes — instrument: the wire-format
bounds table (`GENESIS_TX_WIRE_FORMAT.md` §10), whose per-field maxima sum
well under the cap at the pin.

### Q11 — pool lifetime and weight cap (CEN-M10)

**The livetime pair (3 d / 7 d):** 3 days ≈ 2 160 blocks is the re-relay
bound the submit round consumed (`DAEMON_SUBMIT_VERDICT.md:942–943`); its
Shekyl-specific check is against the **FCMP++ reference-age window**
(`fcmp_reference_block_max_age: 100` blocks ≈ 3.3 h): a spendable tx's proof
goes stale ~20× faster than the pool evicts it, and the reference-age
eviction sweep (`tx_pool.cpp:441` area) already handles that — so the 3-day
value governs only *unmineable residue*, not live transactions, and its
exact value is load-light. 7 days for `kept_by_block` covers reorg-returned
txs across the archival reorg depth (720 blocks ≈ 1 day) with margin.

**The pool weight cap (648 000 000):** derived, not arbitrary — `3 days of
maximal penalty-free blocks at T = 120 s` (`2 160 × 300 000`). It is
therefore a **function of two other ruled values** (zone, block target) and
one policy horizon (3 d). Recorded consequence: the port stores it as the
derivation `livetime_blocks(T) × zone`, not as a literal — a zone or target
change must move it (rule: indivisible values get derived fields).

**Proposed ruling (Q11):** ratify **3 d / 7 d / derived-648 MB** as
relay-policy values with the couplings stated (reference-age window makes
the livetime load-light; the weight cap is a derived quantity). Class:
`none` → `ratified` (policy). Eviction ordering (lowest fee/byte first) is
ratified as the economically consistent choice under the ladder — the pool
sheds exactly what a rational miner would shed last… **admission-semantics
questions around it stay R7's** (fence).

**Falsifier:** the "load-light" claim rests on the reference-age sweep
actually evicting stale-proof txs ahead of the 3-day sweep — instrument: the
sweep's own gate in `tx_pool.cpp` (`remove_stuck_transactions`, :1070) and
DSV §6 leg 1; a pool observed answering `AlreadyInPool` for a
stale-reference tx past the reference window (without the sweep firing)
falsifies it.

---

## 6. The `margin` deliverable (owed to P2P-2 / PWD-B3, blocks PWC-A2)

**The debt** (`docs/FOLLOWUPS.md:715`, input (2)): the P2P lane's
`entry_max` needs *how fast the block-weight limit can grow per block* — a
consensus-lane quantity the P2P round correctly refused to invent.

**Shape (per the P2P-2 lane's answer, which also shrank the horizon):**
`entry_max` has exactly one consumer — the tip announcement
(`NOTIFY_NEW_FLUFFY_BLOCK`, 2008); the sync path's `n × entry_max` form is
retired in favor of a byte budget (P2P-2's own correction, recorded on
`design/p2p2-b-drop-semantics`). The value wanted is a **dimensionless
multiplier on the receiver's own live limit**, recomputed at evaluation
time, that must dominate limit growth **across the receiver's announce-lag
`k`** (a few blocks by construction — an announce is not sync), not across
all reachable states.

**Derivation from the §2 machinery** (a consequence of Q2/Q3, not a
separate ruling). Let `L_n = 2·EM_n` be the limit after block *n*, and let
the receiver hold state through block *h* while the announced block's
parent chain extends `k` blocks past it.

1. **The single-step bound, proved:** `EM_{h+1} ≤ 2·EM_h`. One block
   replaces one window sample; the median of 100 is the average of the
   50th/51st order statistics (`contrib/epee/include/misc_language.h:58–66`),
   the shifted order statistics are bounded by their neighbours, and the
   new sample is limit-bounded at `≤ 2·EM_h` — case analysis shows the new
   50th/51st statistics never exceed `2·EM_h`. Verified by adversarial
   search over bimodal windows at draft time: max observed one-step factor
   **1.961** (approaching 2, never exceeding it).
2. **The 51-block hysteresis is a *monotone-history* property, NOT the
   worst case — a draft-time falsifier run killed the naive bound.** An
   earlier draft claimed `margin(k) = 2^{⌈k/51⌉}` from "the median needs
   51 fresh samples to cross." The simulation falsified it: a
   **crash-preloaded window** — 49 stale high-weight samples left in the
   100-window from a past saturation era, with EM since fallen to a valley
   — lets each new block climb the median up a ladder *between* the stale
   highs, no 51-sample wait: observed `margin(k)` = 1.5, 2.5, 4.0, 6.5,
   10.5, 17.0, 27.5 for k = 1…7, saturating at the stale highs' level.
   The receiver shares this window (it is chain state, not a sender lie),
   but its *limit* is the valley limit — so a transport cap derived from
   the honest-history rate under-admits legal announces after a
   demand crash. This is recorded prominently because the wrong bound
   survived one commit and reads plausibly.
3. **The sound bound, both operands receiver-local:**
   **`margin(k) = min(2^k, S·LTEM/EM)`, S = the ratified surge factor** —
   the proved single-step bound iterated, cut by the surge clamp's
   absolute ceiling (`EM ≤ S·LTEM`; S = 50 in today's code, but Q3's
   amendment REFUTED ×50 and **the signed re-derivation is S = 4 (d24
   denomination)** — carry the symbol, never the literal,
   so no legal announce ever exceeds `2·50·LTEM` regardless of lag). The
   receiver computes both `EM` (its `m_current_block_cumul_weight_limit/2`)
   and `LTEM` live, so the cap needs no protocol constant beyond the ×50
   and the lag bound `k` the P2P row states. At typical announce-lag
   `k ≤ 2`: **×4**, already dominating the observed adversarial ladder
   (2.5 at k = 2); at the crossover `k ≥ 6`-ish the clamp term takes over.
4. **Genesis-era note:** at chain height `H < 100` the windows are
   `H`-sized and the hysteresis reasoning shifts, but bound (1) and the
   clamp term are window-size-independent, so `min(2^k, 50·LTEM/EM)`
   holds from block 1 (with `EM` floored at the zone, limit ≥ 600 000
   while real blocks are tiny — the additive `entry_max` terms dominate).
5. **Ceiling (reference):** `L ≤ 100·LTEM` (30 MB at launch LTEM); LTEM
   itself moves ≤ ×1.7 per 50 000 blocks (Q2).

**Handoff:** `margin(k) = min(2^k, 50·LTEM/EM)`, computed live; the P2P
row states its assumed announce-lag `k` (for `k = 2`: multiplier 4).
**The clamp arm is load-bearing, not a safety belt** (P2P-2 lane's
grounding, verified at this pin): the announce path ignores announces
unless `state_normal` and `is_synchronized()`
(`cryptonote_protocol_handler.inl:536–542`), but `is_synchronized()` is a
**latched boolean** (`!no_sync() && m_synchronized`,
`cryptonote_protocol_handler.h:111`), not a within-`k`-of-tip check — a
synced-then-partitioned node processes announces while arbitrarily far
behind, so no code enforces a numeric `k` and `50·LTEM/EM` is what holds
when the lag assumption fails. **Error direction, for the reviewer when
the falsifier fires:** a bound that is too tight here **rejects a legal
announce** (the receiver's EM is the crash valley while the announced
block is legally larger) — a *liveness* failure, not a safety one; an
oversized hostile announce is rejected downstream by consensus (CEN-A5 /
F14) regardless of this cap. The derivation and any future change to it
live **here** (single owner); the P2P doc cites this section.

**Falsifier (RUN at draft time — this is the instrument that corrected the
section):** simulate the §2 formulas (ST median over 100, clamps, floor,
limit = 2·EM) under (i) adversarial bimodal windows for the single-step
bound and (ii) crash-preloaded windows for the ladder; any trace exceeding
`min(2^k, 50·LTEM/EM)` at any `k` falsifies the bound. Draft-time run:
single-step max 1.961 ≤ 2 ✓; ladder ≤ 2^k at every k and saturates at the
clamp ✓. `swing.rs` is *not* this instrument (it carries the constants and
throughput helpers, no trace generator) — the simulation must accompany
the signature record.

---

## 7. GAP rows — the named blocker and the fence

### GAP-7 — the verification-cost leg (named blocker, rule 22)

**The gap:** nothing binds weight to verification time on the rule-76 floor
(Pi 4). This round's Q1/Q3 ratifications are **conditional** on it.

**Why it cannot be discharged at this pin:** rule 76 §4 — *"Values AND
INCREMENTS for the floor device are measured ON it, never scaled to it"* — a
dev-box measurement times a ratio is a diagnostic, not a spec input. No
floor-provisioned verify-time measurements exist in the tree (the verify
benches — `shekyl-ffi/benches/relay_admission_verify.rs`,
`shekyl-pow-randomx/benches/*`, `shekyl-scanner/benches/*` — are dev-box
artifacts; the only floor-adjacent number on record is research-lab#144's
~1.5 s RandomX share-verify figure, which covers PoW, not tx verification).

**The named blocker and its discharge instrument:** floor measurements of
(i) worst-case penalty-free block verify (300 000 bytes of maximal-input
FCMP++ txs), and (ii) the Q3 transient unit (`2·50·LTEM` at launch =
30 MB), both **run on a Pi 4 Model B**. Instrument state at the pin,
precisely: `shekyl-ffi/benches/relay_admission_verify.rs` measures the
**per-tx pool-admission verify** through the same FFI calls
`blockchain.cpp` makes, and by its own design (its §72.4 note) treats
batch depth as an analytical multiplier (`N` for the worst-placed tx), so
an N-tx block's admission-path cost is derivable from it; but the **block
path proper is a deliberately cheaper traversal** (admission already
verified — the bench's own doc comment), and **no full-block traversal
bench exists** — that instrument is part of what the discharge must
define, not only run. Discharge = the two numbers recorded beside the
constants with the machine named
(rule 76 §1). Until then: Q1/Q3 sign as `ratified` **with the GAP-7
condition recorded in the census rows' notes column** (no new evidence
class — census §2 owns the taxonomy) — the condition is *in the ruling
text and the row*, loud, with this section as its record.
**What the condition means operationally:** if measurement shows the 30 MB
transient cannot verify inside a useful fraction of T on the floor, the
×50 surge factor is the named re-derivation target (Q3); if even the 300 k
zone-block is slow, the verifier (CEN-H19's inherited BP+ path, §10 R6
territory) is implicated before the zone is.

### GAP-6 — the launch-phase emission ramp (fence, decided not defaulted)

GAP-6 is the **launch** end of the emission curve; FL-R12′ ruled the
**terminal** end. This round rules weight/fee constants and touches emission
only through the penalty's *composition* (Q4). **Decision: GAP-6 does not
merge into this round, and the reasons are:** (i) a subsidy ramp is an
emission-schedule question with its own stakeholder (the economics lane per
the census row) and no coupling to any of the eight rows' values — none of
Q1–Q11 would change under any ramp answer; (ii) merging it here would ride
it on a weight round's signature, exactly the silent-merge the GAP row was
written to prevent. It stays an open economics-lane question with its census
row as owner. This paragraph is the recorded decision the row demanded.

---

## 8. Record-and-specify for the store port (consumed, not built)

Ratification-only means these are **specifications the port consumes**:

1. **Constant migration:** every §2 constant (zone, windows, surge, clamps
   as 17/10-shaped rationals, tx size, weight-limit formula terms, extra
   cap, livetimes, pool cap as its derivation) moves from hand-maintained
   `cryptonote_config.h` + free-floating shekyl-wire mirrors into
   `config/consensus_constants.json` codegen — one authority, drift pair
   deleted (the file's own charter). The pool cap is stored as
   `livetime_blocks(T) × zone`, not a literal (Q11).
2. **Rule-60 deletions at the port:** `get_min_block_weight`'s vestigial
   version arg (G6b); the dead pre-per-byte-fee arm in
   `get_transaction_weight_limit` (Q7).
3. **Connect-side invariant (Q7):** every path that can place a tx in a
   block passes Rule 4 (the weight cap carries no `kept_by_block`
   exemption). The Rust store's admission surface must preserve this
   property and gate it.
4. **GAP-7 instrument:** the floor bench run (§7) is a program deliverable
   with named entry points; its numbers land beside the constants.

---

## 9. Round log

- Dispatch (steering, shekyl-core-43): eight rows + ratification-only
  constraint + the `margin` cross-lane debt (verified at FOLLOWUPS:715).
- Reopen conjuncts (a)/(b) verified at the artifacts (header); stale §0.1
  passage in FEE_LADDER_DERIVATION.md found via `git log -S`, routed to the
  fee lane.
- Structure (three groups by validation surface, rule 19) proposed by this
  round, adopted by steering; sequencing-after-#614 adopted with the
  premature-clear rationale.
- Shape request for `margin` sent to the P2P-2 lane (shekyl-core-04);
  §6 records all three characterizations pending the answer.
- Consumer sweeps run at the pin before being cited (§2); the KAT suite
  observed green at the pin (79 passed, `cargo test -p shekyl-economics`);
  `epee` median, `get_transaction_weight`, the fee-arm `return 0`, and the
  GTWF §9.6a/§10 byte arithmetic each read at their sites before citation.
- **Draft-time falsifier run corrected §6:** the first committed margin
  bound (`2^{⌈k/51⌉}`, from the 51-sample hysteresis) was falsified by its
  own named simulation — a crash-preloaded window climbs the median
  between stale high samples with no 51-block wait (observed ×6.5 at
  k = 4). Replaced with the proved-and-simulated
  `min(2^k, 50·LTEM/EM)`; the wrong bound and the instrument that killed
  it are both recorded in §6 point 2.
- Advisor/steering review corrections folded: conjunct (b) re-grounded as
  branch-only (header); FL-R16a retirement rephrased to in-flight, not
  present (Q8); tx_extra headroom computed, not asserted (Q10 — ≈ 25 %,
  not "an order of magnitude"); no new evidence class minted (Q1/Q3
  conditions ride the notes column); fossil-flag discharge extended to the
  V1/V2/V5 variant collapse (Q1).
- **Q4 rewritten on steering's placement-vs-shape finding:** FL-R12′
  examined the penalty's *placement* (and, via W5, the `P(1) = 0`
  endpoint), never its *form* — the earlier draft let a placement ruling
  stand in for the shape examination, which would have closed the census's
  charge under cover of a signature. The shape is now derived for Shekyl
  in Q4 itself (three boundary conditions + max mid-range bite within the
  exactly-computable power family), with three evidence limbs each named
  for what it covers.
- **P2P-2 lane grounding folded into §6** (their finding, verified at this
  pin): no code enforces a numeric announce-lag — `is_synchronized()` is a
  latched boolean, so the clamp arm of `margin` is load-bearing; error
  direction recorded (too-tight ⇒ liveness failure, legal announce
  rejected; safety is downstream consensus's regardless).
