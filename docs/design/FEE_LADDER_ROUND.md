# FL Round Record — Fee Ladder Derivation

**Status:** OPEN — design round RULED. §8 is signed (FL-R12′ / FL-R17;
FL-R14 ruled). Implementation is in flight on `feat/fee-ladder-impl-1`.
All substance lives in [`FEE_LADDER_DERIVATION.md`](FEE_LADDER_DERIVATION.md);
this file is the thin round-state record only (rule 95 — one owner per
claim, no restatement). Consensus behavior changes live in the
implementing PRs, not here.

Family: `FL-*` (index row: [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md)).
Branch: `design/fee-ladder-derivation`, off `dev` 6d2f49a5c, merged with
`dev` a566a466 at review round 2. Instrument:
`shekyl-economics-sim --fee-ladder` (`rust/shekyl-economics-sim/src/fee_ladder.rs`).

## Commit log (this branch, in order)

| Commit | What |
| --- | --- |
| fb02e4b7c | Pre-registration: FL-C1…C8 criteria + FL-V1…V6 verifications, committed **before the instrument existed** (the brief's pre-registration mandate; the ordering is the method) |
| 8a55415b5 | Instrument + derivation + unsigned §8 (3-rung state-computed proposal) |
| fc6018803 | Adversarial-review corrections (12.5× not 6.25×; ceil quantization, register untouched + deviation disclosed; unbuffered clamp) |
| 1a7390674 | FL-V7 minted (perpetual-tail contradiction, escalated at steering) |
| a8a01b950 | FL-V7 first restatement (superseded at review round 2 — see below) |
| 99aefbc24 + b05ddbaf6 (+1) | Review round 2: dev merge to a566a466; FL-V7 re-restated per maintainer ruling; FL-V8…V11 minted; FL-R12′/FL-R13/FL-D5/W7; red test observed red; this file (+ census-queue routing note) |
| (review round 3) | dev merge to c1010b70a; self-review findings fixed (banners, measurement integrity re-run, drift pairs, conventions — §Review round 3); red test re-homed to `emission.rs` |

## Review rounds

| Round | Reviewer | Outcome |
| --- | --- | --- |
| 1 | advisor (in-round) | 4 findings, all fixed in fc6018803; ruling shape unchanged |
| steering | shekyl-core-00 | Approved for maintainer decisions; census-R2 collision flagged and §0.1 hold adopted; FL-V7 escalation requested and delivered |
| 2 | **maintainer (Rick), fresh clone at a566a46** | P-1…P-4 process findings + F-1…F-6 technical findings. Dispositions below |

### Review-round-2 dispositions

- **P-1 (round conducted outside the tree):** complied — this file is the
  in-tree round record. Factual clarification on the record: the three
  files named in the review (`consensus-census-precedes-rewrite.md`,
  `consensus-drs-reconciliation-csr.md`, `p2p2-design-round.md`) and the
  17 238-byte artifact are **Claude-harness session-memory files outside
  any repository** — continuity pointers, never the round record. The
  round's record (design doc, instrument, index row) has been tree
  content on this branch throughout, unpushed because rule 06 holds each
  push for exactly the authorization review round 2 is deciding.
  Consequently there is **no P2P-2 repo change on this branch to split
  out** — that ask dissolves with the memory/repo distinction.
- **P-2 (size gate unfalsifiable):** the rule-47 point is accepted in
  general; the gate in question was a harness maintenance target on a
  session-memory file, not a project gate.
- **P-3 (scope drift):** the ladder is untouched by charter (design-only
  round; §8 unsigned). The housekeeping in the report was harness-side,
  not repo-side.
- **P-4 (strengthening went the wrong direction):** accepted in full.
  FL-V7 restated: refuted line is `ECONOMY_EXPLAINED.md:49-50`; `:18`
  and `:35`'s formula are faithful; the instrument of refutation is the
  code (FL-V8), not a doc-vs-doc reading; 2²¹ labeled an identity.
- **F-1 → FL-V8** (opposite-policy clamps, both live; verified at
  `blockchain.cpp:6410-6420` / `cryptonote_basic_impl.cpp:168`).
- **F-2 → FL-V9** (cap gated on `SHEKYL_TX_VOLUME_BASELINE > 0`,
  `cryptonote_basic_impl.cpp:153`). No behavior edit on an unsigned
  branch — deliberate; ships with FL-R12′'s implementation.
- **F-3 → FL-V10** (canonical-crate blindness; 286× test pinned green;
  red companion `terminal_reward_legs_agree` added `#[ignore]`d, observed
  red: legs 600 000 000 vs 599 999 999 at the first diverging block).
- **F-4 → FL-V11 + FL-R13 + FL-D5** (3 413× floor decay; the instrument
  had printed `[20, 80, 320, 4000]` and the round failed to name the
  finding; §5.2 inherits the decay; genesis-blocking if the cap wins).
- **F-5** — already in the record as FL-V1's terminal form / §4.6.
- **F-6 → wargame W7** (single-tier + coarse quantization dispositioned
  through registered FL-C2, with the FCMP++ metadata-share point quoted,
  and a named reopen).

## Review round 3 (self-review before push, 2026-09-03)

Push authorized for review (no PR yet); dev merged to c1010b70a. A
high-effort `/code-review` before pushing returned 10 consolidated
findings; all fixed on-branch, the load-bearing ones being:

- **CI**: both new docs' status banners were blockquoted and failed the
  rule-95 banner gate — reformatted; gate re-run green (165 files).
- **Measurement integrity**: the §4.4 dwell table carried stale
  round-to-nearest output as the adopted-rule row; "distinct values" was
  a churn count (~84× overstated — the true raw-`C` wire alphabet is 2–3
  values flickering every 3–6 blocks); the ramp gate's whole-trace median
  structurally could not fail (replaced by a min-dwell-of-runs-starting-
  in-ramp statistic); the FL-C7 feedback verdict was measured on the
  raw-`C` map with the fixed point pinned away from the pow2 boundary.
  All re-measured: both snap rules are now instrument modes (the
  register-vs-adopted audit is reproducible from the branch), and
  feedback runs on the served quantized map across demand scales that
  cross the boundary — **all 80 cells converge**. New result: on the
  reachable grid the ceiling rule's `C_q = 1` in every quiet state, so
  the served ladder equals today's at launch and the FL-C6 clamp is a
  belt, not a live fix (§4.2/§5.4).
- **Drift pairs**: `terminal_reward_legs_agree` re-homed into
  `shekyl-economics` `emission.rs` tests with a projection-leg assertion
  (conjunct (b) of the census-R2 criterion now names a function the test
  calls); `emission_speed_factor`/`tail_subsidy_per_block` made `pub` and
  consumed instead of local re-derivations; `TX_VOLUME_WINDOW` codegen'd
  from `config/economics_params.json`; the zone constant read from
  `shekyl-wire`'s owner copy; float `log2` quantization replaced with
  exact integer snap (KAT'd, both rules).
- **Convention**: the instrument now renders and `main.rs` writes
  (stage2 precedent); the phantom "rule 11" citations are re-anchored to
  the brief's pre-registration mandate (no `.cursor/rules/11-*` exists);
  `cryptonote_basic_impl.cpp` cap refs corrected `:169`→`:168`; FL-R/FL-D
  series enumerated in the index family cell.

Deferred from this round's review, each with the blocker named: RNG
unification (a shared in-crate `SplitMix64` home is an instrument-side
refactor with no behavioral stake — rides the FL-R12′ implementation PR
or the instrument's retirement, whichever first) and a shared
`round_money_up` owner (the wallet copy is private to `shekyl-engine-core`
and a sim→engine-core dependency is the wrong direction; the daemon-side
Rust rounding gets a real owner in the §7 implementation, which is where
one home for all three copies is decided).

## Review round 5 (maintainer, 2026-09-03): the single-tier re-argument

The record dispositioned the wrong single-tier design: W7 assumed a
*static* rate, and the round's own machinery yields a state-computed
single rate that does both registered jobs. The same principle that
deleted `Fm` — privacy is lexicographically prior — stopped one rung
early. Dispositions:

- **FL-C9 minted** (post-registration, birth-stamped): fee signal bits —
  what an observer recovers from `(fee, weight, height)` beyond weight,
  conditioned on the registered dwell measurements. Measured on the
  instrument (§4.7): rung ladders 1.361 bits/tx under the registered
  traffic model (4-rung ≡ 3-rung — `Fm` is 0%), priority marker 3.32
  bits with a ×0.1ⁿ set-measure for habitual payers; the state-computed
  single rate **0 bits** by construction; confidential fees recorded as
  the theoretical floor (FCMP++ surface, out of scope).
- **W7 revised** (round-2 text struck, kept as record) + **W8 minted**
  (miner fee-rank ordering leak — exists today under any multi-rate
  ladder; uniform rates make hash-ordered inclusion cheap to require,
  flagged rule-71-adjacent).
- **FL-R4 contested → FL-R17**: rung count reopened as the explicit
  C9-vs-C2(b) trade, C2(b)'s cost restated as selectable urgency (a
  feature), recommendation (b) single-rate *labeled as a
  recommendation*; empirical gate = the median-dynamics instrument
  (loop stability + security budget under elastic demand, both
  unmeasured; coupling signal deliberately undesigned pending its own
  criteria).
- **Independence note:** FL-R17 does not gate the FL-R12′ F-1 amendment
  — the amendment concerns the floor's composition, FL-R17 concerns how
  many rates sit above it. Two open signatures, separate decisions.

## Review round 8 (maintainer, 2026-09-04): FL-R12′ SIGNED — the full composition

The maintainer verified the shipped composition
(curve → tail floor → penalty → multiplier → cap), found the F-1 draft
right in direction and silent on the penalty's placement — the operator
that decides whether block-size governance survives the ruling — and
signed the complete form in-channel, verbatim:
**`paid = max(M_r·curve(remaining), TAIL) · penalty(x)`**, `remaining`
floored at zero, cap retired. Placed on the record with it: the
multiplier-pacing rationale (nothing to defer at a perpetual tail; a
tail-modulated floor pays least when fees are lowest), the ordering rule
(**floors belong to emission; penalties apply to the paid quantity**),
the pre-split-total note, the ladder-operand redefinition
(`R_eff = max(M_r·curve, TAIL)`, `C′ = (1−σ)/(1−b)` — no double-counted
multiplier, no `[0,0,0]` ladder at exhaustion; FL-R1/R3/R5 updated),
**FL-D1 closed as answered** (the ruling abolishes the era it deferred
to; the signed order penalizes the tail like any other reward — had the
penalty composed before the floor, D1 would have been undeferrable),
and W5 resolved. Oracle re-oriented to the signed contract, red three
ways: 480 000 000 vs 600 000 000 (floor at `x = 0` under dormancy),
360 000 000 vs 450 000 000 (penalty-after-floor at `x = ½` on the
tail), and the operand-equality leg mid-curve.

**Build authorization: YES from the maintainer, upon this record.**
The implementing PR's bundle (one validation surface — the reward
path): the signed composition with one owner and no flag path
(FL-V8/V9/FL-R16a), the FL-R14 build-time assertion, the FL-R15 rename
sweep with FL-R16b/c, the FL-V7 doc corrections (`:18` rewritten;
`:35/:49-50/:162/:667` become true), the ladder-operand change, and the
graduated (un-ignored) oracle. Sequencing note: the design branch
remains un-PR'd per the maintainer's standing "no PR just yet" — the
natural order (design PR merges, implementation cites it) waits on him
lifting that hold.

## Review round 9 (maintainer, at the design tip `6689b0c`): T-1, hold lifted, two-PR split

Verified the signed record in full (composition verbatim, every §8 row
disposed, FL-D1's undeferrable counterfactual, the 360/450 arithmetic
re-derived by hand). Red-by-reading confirmed; **red-by-run is owed
before the implementing PR merges** — the runs exist in this branch's
commit messages, and the reviewer re-runs them once the branches are
visible.

- **T-1 (Moderate): oracle leg 3 pinned a function, not a contract** —
  as written at the design tip it forced folding `M_r` into
  `base_block_reward`, dragging every caller. **Resolved in the build by
  exactly the prescribed shape**: a *named operand function* exists —
  `effective_emission(ag, v)` is the payer's pre-penalty quantity, and
  leg 3 asserts `paid_block_reward(…, weight 1) == effective_emission`
  plus the dormancy-modulation inequality; no caller was dragged. One
  deliberate divergence from the in-message prescription, disclosed:
  `base_block_reward` did NOT become the pure curve — under the ADOPTED
  round-8 amendment the estimator's operand is the **M_r-neutral view**
  `max(curve, TAIL)`, which is what `base_block_reward` now is (totalized,
  documented as not-a-pipeline-stage); the pure curve exists as the
  private `curve_emission`. The floor stays in the neutral view because
  the amendment made that view the operand.
- **Sequencing ruled: hold LIFTED, design PR first** — the implementing
  diff cites a merged document at `dev`.
- **The bundle splits in two after the design PR** (the built branch had
  interleaved them and is being restructured): **PR one, atomic (rule
  07)**: the signed composition + one owner + no flag path; the ladder
  operand move; FL-R16c (consensus via `compute_fee_burn`); the FL-R14
  assertion; the FL-V7 doc corrections (under the names the reviewer
  knows); the oracle graduated. **PR two, mechanical, after**: the
  FL-R15 rename sweep + FL-R16b — so the consensus diff is reviewed
  under known names and a 400-line rename cannot dilute the one
  composition line that matters.

## Review round 10 (maintainer, at the PR #614 head `ccfb85c72`): T-2/T-3/T-4 — the oracle's own failure axes

Scope re-verified independently (design-only against `origin/dev`,
merge-base `f9ab906`); the PR round-two fixes accepted; two High
findings against the restored oracle, both ruled in-scope for this PR
and both landed on this branch:

- **T-2 (High): leg 4 could not fail on the defect it names.** The
  restored projection leg computed `ag` and asserted only the paid
  value — but a SATURATED projection lands exactly on the asymptote,
  where the correct composition pays TAIL anyway, so the census-R2
  conjunct's property ("accrues THROUGH the asymptote") was invisible
  to the assertion. Fixed on the projection's own axis: `ag > s`
  asserted directly, then the exact accrual RATE —
  `projected(H + k) == ag + k·TAIL`. **One disclosed substitution**:
  the prescribed stronger form `ag == s + (H − h_exhaust)·TAIL`
  presumes the trajectory hits the asymptote exactly, but the tail
  floor cuts in while `remaining > 0`, so `ag` skips PAST `s`
  mid-stream, and an integer-exact `h_exhaust` has no derivation that
  is not the projection's own recurrence — the oracle must not iterate
  its subject to produce its expected. The rate delta pins the same
  through-asymptote property with a contract-derived expected.
- **T-3 (High): every leg ran on the dormancy rail only**, so a
  floor-inside-the-operand rebuild — `max(M_r·base(ag), TAIL)`, a
  natural misreading once leg 3 pins the tail floor inside
  `base_block_reward` — would agree at 0.8 (`max(0.8·TAIL, TAIL) =
  TAIL`) and pay `1.3·TAIL` on the surge rail, unseen. Fixed: legs 1,
  2 and the projection-fed paid limb run over BOTH rails (`v = 0` and
  `2·baseline`), the rail setup asserted (`m_r == release_min/max`)
  rather than assumed, and TAIL asserted exactly — under the signed
  contract the terminal value is rail-independent, which is precisely
  the property worth pinning. Leg 2 joins the loop beyond the
  prescription (penalty-after-floor is rail-independent too; same
  loop, no extra machinery); leg 3 stays outside — the estimate
  operand is M_r-NEUTRAL by contract and has no rail.
- **Per-axis red-by-run** (each new assertion observed firing ALONE,
  earlier axes temporarily neutralized and then restored — an
  assertion that can go red for two reasons can go green for the
  wrong one, so each axis earns its own observation):
  - axis A (`ag > s`): red, `ag = 4294967296000000000` — exactly the
    asymptote; the saturation is now visible on its own line;
  - axis B (accrual rate): red, `4294967296000000000` vs
    `4294967896000000000` (`+ 1000·TAIL`);
  - leg 1, dormancy rail: red, `480000000` vs `600000000` (the
    documented modulated floor);
  - leg 1, surge rail: red, `599999999` vs `600000000` (the
    remaining-cap — the same shipped defect's other face).

  The restored full run fires at axis A first; the rest of the
  economics suite is 79 green with the oracle `#[ignore]`d.
- **T-4 (Low): §8's BUILT pointer named an unpushed branch.**
  `feat/fee-ladder-impl-1` pushed at `581dc27fc` (authorized in the
  same message), so the pointer is verifiable; no §8 edit needed. The
  graduated oracle there carries the same two strengthenings, observed
  green through the one owner (economics 84/84; full workspace 4,569
  passed excluding the randomx differential's unlinkable C oracle) —
  which also settles T-3's hypothesis empirically: the implementation
  multiplies the curve, not the base. **Tense disclosure:** the first
  revision of this section (commit `0c2acebb3`) wrote this bullet
  ahead of the observation — "pushed" and "kept green" before either
  had happened — the same defect class as round two's "BUILT on this
  branch." Corrected here in the commit made after both observations.

## Review round 11 (PR #614 bot cycle three + maintainer sweep, 2026-09-04)

Copilot's third pass: 9 open threads + 23 suppressed comments
(deduplicating to one code finding and two clusters). Dispositions:

- **Record currency (the largest cluster).** The round-8 signature had
  outrun the doc in a dozen more places than the round-two/round-10
  passes swept — §4.6's caveat, the §8 preamble, the FL-R13/FL-D1/
  FL-D4/FL-D5 rows, the round-record banner, and the index FL row were
  **fixed by the maintainer directly** (`2917de8e0`, which also closed
  the corresponding open threads). This commit takes the remainder the
  same class-sweep found: §0.1's pre-ruling hold paragraph (present
  tense on a hold the round-2 ruling ended), the §5 heading (still
  "proposed, unsigned" over a signed ruling), §5.4's "held for the
  sequencing decision", and FL-D2 (its first reopen criterion FIRED at
  rounds 2/8 — re-routed to CEN-M3's resumed round rather than left as
  a deferral whose trigger already fired). Lesson honored from the
  morning: each hit classified asserts-is / records-was — the round-4
  provenance narrative, commit-log rows, and measured tables stay.
- **Registered priority order (suppressed, VALID, High):** §1's
  "privacy > security" line inverts `00-mission`'s canonical hierarchy.
  The register is committed history, so the line stays and a
  post-registration correction paragraph lands under it, with the audit
  Copilot asked for: all three invocation sites adjudicated
  privacy-vs-economics; no privacy-vs-security conflict was ever
  resolved here; no disposition changes.
- **One table repair:** the maintainer's FL-D1 rewrite dropped a cell
  (MD056); re-split into blocker/reopen without content change.
- **Instrument findings (suppressed cluster, VALID — and the sweep found
  a real registered-gate failure).** Verified at source, fixed, and
  re-measured (all numbers below are from the re-run at this commit):
  - *Served-order pin (the one open code thread — proposed fix
    REJECTED with evidence):* the instrument's correction scales the
    already-truncated rung, which is bit-exact with the SERVED
    arithmetic (`corrected_fee_ladder` truncates first; 210-vs-220 at
    10 SKL/1.5 MB/`C_q` = 16 discriminates, the `C_q` = 2 KAT does
    not). The real defect was the comment's false one-atomic-unit
    bound (< `C_q` atomic pre-rounding is the true bound); a
    discriminating pin now fails any "fix" toward the algebraic form,
    falsifier observed.
  - *Genesis parity:* `GENESIS_NG_HEIGHT = 1` (production's hardfork
    table), replacing a hard-coded 0 — σ was one fixed-point unit low
    (135000 vs 135001 at age 1); no reported value moves at the doc's
    precision; declared exception naming the C++ authority.
  - *Penalty coupling:* §1.9 registered the KAT-pinned penalty via the
    crate's block-reward entry point; the instrument never called it.
    `degenerate_pins` now pins `block_reward_with_penalty` at the
    FL-C8 tail state, `x = ½` → 450 000 000.
  - *Interior-grid sweep — the substantive one:* dwell and feedback
    were pinned to (age 4, zone median) while §1.8/FL-C7 register the
    interior grid, and the pow2-boundary demand probe was hard-coded at
    the age-4 value 230. Swept (200 dwell runs, 2 400 feedback cells,
    boundary scale computed per state: 59/55/221/60/52), the
    **un-hysteretic served map 2-cycles at 18 boundary cells at full
    `C_q`-step amplitude — failing FL-C7's registered bar** that the
    round-3 single-state grid had reported clean. §1.7's registered
    remedy applied: the §7 hysteresis construction (impl-1's
    `fee_correction_quantized`, transliterated as a declared
    exception) converges **all 800 cells** and passes every dwell gate
    (min in-ramp 274 ≥ 240). §4.4/§4.5/W3/§7 regenerated; hysteresis
    promoted from belt to **load-bearing**. The cross-age ramp claim
    is honest now: zero steps at ages ≤ 4, 2–3 steps at ages 12/30
    within the gate.

## Review round 12 (PR #614 bot cycles four and five, 2026-09-04 late)

**Cycle four — the gui-drift red, diagnosed as cross-PR skew, no #614
defect.** The failing check builds wallet@`dev` against
`refs/pull/614/merge`. The wallet's `dev` (`shekyl-gui-wallet`
`04b9c78`) already follows core PR **#617** (shard-visual ruling A,
OPEN), which moves `dominant_regime` off `ShardAggregate` onto
`PreviewFixture` — so the wallet reads `f.dominant_regime`, a field
that exists only in #617's tree. Every core PR fails this check
identically until #617 merges (the GUI repo's own dev CI went red on
the same push, same minute), and #614's wallet-consumed crates
compiled clean in the failing run. Nothing in this PR can or should
fix it (patching shard-visual here would double-land #617); the
resolution is sequencing — merge #617, then re-run the check. While
this red stands, a genuine drift introduced by any core PR is
invisible — the standing stale-cross-repo-red hazard, inverted: an
EARLY companion turns every producer PR red.

**Cycle five (Copilot, two findings, both valid, both taken):**

- **`HysteresisCq` had no direct test while being load-bearing** — the
  no-test-means-write-the-test rule applied to this round's own
  round-11 addition. `hysteresis_band_boundaries_are_exact` now pins
  initialization, retention at BOTH band edges (strictly-outside
  escape: the edge itself holds), the transitions one unit outside
  each margin, held-step history preservation, and the same-step
  short-circuit. Falsifiers observed per axis: margin drift
  (`MARGIN_MILLI` 30 → 0) and inequality drift (`>` → `>=`) each fire
  the upper-edge retention assert; restored green.
- **§5.1's criteria-disposition table was stale against rounds 8/11**:
  FL-C4a still said "passes all scenarios" unqualified, FL-C7 said
  "pass, no smoothing needed beyond `C_q`" (contradicting §4.5's
  18-cell failure of the un-hysteretic map), FL-C8 still deferred
  exhaustion governance to an FL-D1 that round 8 closed. All three
  rows now carry the current verdicts with their round provenance.

Also this cycle: `origin/dev` (#612) merged in; one
`IMPLEMENTATION_INDEX.md` conflict resolved hunk-wise (dev's updated
C2-R row + this branch's FL row).

## Build (authorized round 8; executed 2026-09-04 on `feat/fee-ladder-r12-impl`)

The reward-path bundle, one validation surface, built Rust-first (rule
20: C++ reduced to marshaling). **The C++ diff direction, as a
measurement, not a reading** (steering correction — an earlier report
said "thinner," which does not survive measurement): the formula bodies
genuinely left C++ (the whole `Fl/Fn/Fm/Fh` ladder computation and its
rounding deleted; the multiplier/cap/flag block deleted), yet `src/`
mechanism is **net +19 non-comment lines** (+54/−35; +169/−100 raw with
the design-sourced comments). The +19 is the cost of the seam: a second
overload signature, the `c_q` parameter threaded through, the FFI call
plus its assert, the delegating wrapper, and the mandated clamp.
**Structural note, bigger than this lane:** this is a *good* crossing —
real logic deleted, owner in Rust — and C++ still grew, because
rule-by-rule crossing pays a marshaling seam every time; the C++ tree
does not shrink until whole surfaces cross and their marshals retire.
Steering is carrying that number to the maintainer as evidence in the
crossing-strategy question. (The build commit c89364816's message
carries the uncorrected "THINNER" claim; commits are additive here — this
paragraph is the correction of record.)

Bundle contents:

- **Composition (FL-R12′ as signed):** `shekyl-economics` gains the one
  owner `paid_block_reward` = `apply_weight_penalty(effective_emission)`;
  `effective_emission = max(M_r·curve(remaining), TAIL)`; `remaining`
  saturating at zero; `cap_reward_to_remaining_supply` DELETED;
  accumulator advances through the asymptote (u64-rail saturation only).
  `block_reward_with_penalty` survives as the documented M_r-neutral
  delegation, which keeps the 81-vector cross-language KAT pinned without
  re-derivation. C++ `get_block_reward`: 6-arg = marshal only (no
  multiplier, no cap, **no flag path** — FL-V9 discharged); 5-arg = the
  documented neutral view (relay floor's deliberate operand, CEN-M3
  held).
- **FL-R16a first, as instructed:** the past-asymptote error arm is
  gone; both dead-letters closed (estimate path returns the tail via
  totality; relay floor tail-derived instead of failure-arm 0). FL-R16b
  (ActivityMetric guard) and FL-R16c (supply-ratio saturation +
  the gross-emission note) landed with it. FL-R14's build-time
  assertion lives in `params.rs` (≥10 000-year headroom floor,
  range-proof width and wrap-un-saturation named).
- **Estimate side (round-8 amendment as adopted):** `fee.rs` —
  `corrected_fee_ladder` (three tiers, `fees[2]` bridge, `Fh` main arm
  unconditional) + `fee_correction_quantized` (whole-scalar `C_q`,
  exact-integer ceiling snap, 3% hysteresis band) + `round_money_up_2`
  (first Rust production owner). C++ 4-arg = marshal; the 2-arg wrapper
  computes `C_q` inputs from the SAME sources validation uses and
  **clamps the served economy rung at `get_current_fee_per_byte()`** —
  the round-8 rider as an identity: *the estimate can only err toward
  acceptance* (relay tier, per CEN-M3: there is no consensus floor).
- **Oracles:** `terminal_reward_legs_agree` graduated (un-ignored, green
  through the one owner; contract values unchanged — 600 000 000 /
  450 000 000 / operand-equality; the pre-implementation reds are in the
  commit history). New FFI marshal pin with `M_r ≠ 1` and both tail
  boundaries. Heritage `scaling_2021` pins updated to the signed shape
  (`[340, 1400, 1400, 67000]`-class; the surge case's 22 000 → 67 000
  deliberately) + a `C_q = 2` case. Wallet cap re-derived (FL-R9):
  14 000 000 → **28 000 000** (served sweep max), KAT re-pinned.
- **FL-R15 rename executed:** `money_supply` →
  `emission_curve_asymptote` across the JSON authority, both codegen
  paths, the Rust field/const surface (incl. the engine snapshot field
  `emission_curve_asymptote_atomic` — no out-of-workspace consumer), and
  the C++ macro (`SHEKYL_EMISSION_CURVE_ASYMPTOTE`, rule 93 prefix).
  Doc hits classified: asserting-is updated (`DESIGN_CONCEPTS`
  constants/mechanism, `ECONOMY_EXPLAINED` big-picture + Loop 1 to the
  signed composition, readiness matrix, perf baseline);
  records-was left standing with a rename note (`GENESIS_TRANSPARENCY`
  genesis derivation); census/CHANGELOG untouched (records-was).
- **FL-V7 resolution as ruled:** `ECONOMY_EXPLAINED.md` big-picture now
  carries the exactly-true sentence (asymptotic gross issuance +
  perpetual tail + burn-governed net supply); Loop 1 states the signed
  order; the emission table is marked neutral-trajectory.

Gates at the build tip: rustfmt; CI-exact workspace clippy `-D warnings`;
full Rust workspace suite; C++ configured with tests, full `unit_tests`
battery (31-test reward path incl. re-pinned KATs verified first);
`check_archival_reward_gates.sh`; all four doc gates. The dwell/feedback
instrument re-run unchanged (the adopted design is the measured one).

## Review round 7 (maintainer, 2026-09-03): FL-R17 SIGNED — three tiers

**Signed in-channel, this session, direct message** ("sign it as three
tier") — the provenance class the FL-R12′ episode established as the
consumable one. Rationale as signed: no privacy argument applies to the
default case, and the non-default case does not significantly degrade
privacy — a smaller set that is still, arguably, much larger than Monero
RingCT's ring-16, the de facto standard (the round's arithmetic: the
smallest tier's anchored set beats ring-16 for any anchor looser than
~13 minutes at baseline volume). Recorded with the signature:

- §5.5 tier contracts + **standard as the default** (on rule-82
  failure-mode UX, bounded 4×-floor cost, and shipped GUI behavior —
  the privacy argument for the default choice explicitly discounted by
  the maintainer and recorded as such).
- §4.7 gains the **defaulted 15/80/5 operative model** (economy ×6.7 /
  standard ×1.25 / priority ×20; instrument row added — the invocation
  originally swapped economy and standard's shares, caught at PR #614
  review and fixed with the attribution).
- Candidate (b) rejected with rule-21 reopeners (tier share < 5%;
  anchor precision beating the ring-16 crossover; FL-D6 work showing
  single-rate revenue dominance).
- FL-R4 resolved (confirmed via FL-R17); W8 re-homed as **FL-D7**
  (fee-rank ordering leak stands under three tiers; ladder-compatible
  mitigation—intra-tier shuffle—named as a reopener path).
- **Follow-up in the same round:** W7's rationale REPLACED on the
  maintainer's direction (the static-rate argument is retired; the
  durable reason is partition-without-linkage + bounded inverse-share
  cost + urgency as a widely used feature), the FL-R17 reopeners
  replaced with his canonical two (FL-C4b's registered mechanism; any
  on-chain linkage primitive), the proportionality frame recorded in
  the row ("the kind of cost a proportionality judgment handles, not
  the kind the priority order was written for"), and the remaining
  three-tier mechanics (`C_q`, `Fm` deletion, unconditional `Fh` main
  arm, unbuffered floor clamp) endorsed as read-sound.
- **Obligation created and handed off (steering flag):** the ruling puts
  a privacy cost behind a user-facing choice, so the tier-picker surface
  owes a rule-81 disclosure in non-protocol terms — §7 row added, owner
  = wallet/GUI lane, carried with the engine tier-mapping change. An
  obligation with no owner is how a ruling's consequence goes
  unimplemented while the ruling reads as complete.

## Review round 6 (maintainer, 2026-09-03): the honest attack model

The maintainer corrected his own round-5 framing downward, with the
method stated: FCMP++ puts **no linkage primitive on the wire** — you
cannot cluster a user's transactions from chain data; the real attack is
**anchored candidate-set reduction** (off-chain anchor → height window →
filter by public fields), and the fee rung's contribution is a
`1/usage_share` divisor applied **once per anchored transaction**.
Dispositions:

- **FL-C9 re-labeled** to "anchored-attack candidate-set reduction."
  The measured numbers survive (surprisal = log2 of the divisor):
  ×2/×2.5/×10 at the registered shares, ×20 at 5% priority; single rate
  ×1.0. The "persistent per-user marker / linkable pseudonym / ×0.1ⁿ"
  claims are **struck** — cross-transaction linkage requires an
  adversary who already holds the user's transactions from outside, at
  which point tier habit is weak confirmation on a stronger leak;
  without the anchor, "all priority fees" is a partition, not a
  cluster. FL-C4's original framing is noted as having been right all
  along.
- **FL-R17's recommendation downgraded** to a weak lean (b): the
  privacy side is real but an order smaller than round 5 pitched it —
  bounded, anchored-only, once-per-transaction, minority-borne,
  non-optable — and **the maintainer records no strong prior on the
  trade's direction**. Both axes now carry the honest state: privacy a
  bounded constant factor, stability/revenue unmeasured pending the
  median-dynamics instrument. W8's possibility argument survives
  untouched (it never depended on the bit-count).

## FL-R12′ (2026-09-03; provenance corrected at review round 4)

**Direction: plain perpetual tail — accepted by the maintainer
in-channel at review round 4; NOT SIGNED.** An earlier revision of this
section recorded "signed, relayed via steering"; review round 4 could
not confirm that signature, and the record is demoted accordingly (the
empty §8 signature line — kept empty precisely because a relayed ruling
is not a signature — is what made this a wording correction rather than
a retraction). Hard cap rejected on the priority-order derivation; the fee-fed
burn-recycling floor declined, with the maintainer's dormancy rationale
on the record (a maturing monetary asset is mostly high-value/low-volume
— exactly when the opportunity-cost attacker is cheapest and a fee-fed
pool is empty; a floor that vanishes under the conditions it was built
for is not a floor). Ruled build shape, consequences FL-R14/FL-R15, the
FL-V7 polarity flip (`:18` becomes the false line), FL-D1's shrink,
FL-R13's de-escalation to a calibration round, and the FL-D6
smoothing-pool row are all recorded in the derivation doc's §8/§9. The
red test is re-oriented to the ruled oracle (`reward == TAIL` on both
sides of the boundary; observed red against the capped path:
599 999 999 vs 600 000 000). *The §8 signature line remains empty for
the in-tree countersignature; provenance of this entry is the steering
relay.*

## Review round 4 (maintainer, on the pushed branch, 2026-09-03)

Verified the branch (14 commits, signed; consensus-crate delta = two
`fn → pub fn`, one generated const, one `#[ignore]`d red test — "no
consensus code touched" holds), then found two queued items built on
claims that did not survive source, and asked the provenance question
directly. Dispositions:

- **F-1 (High) → FL-R12′ amendment drafted:** the shipped order floors
  `base` *before* the release multiplier, so under dormancy the chain
  pays 0.48 SKL/block against the ruling's named 0.6 floor — in exactly
  the regime the dormancy argument exists for. Drafted:
  `paid = max(M_r·curve(remaining), TAIL)` (floor on the PAID reward);
  oracle re-oriented to assert that contract against the shipped
  composition; signature waits on the amendment.
- **F-2 (High) → FL-R16 rejected as written, re-minted FL-R16a/b/c:**
  the original row's live-consumer claim was a `#[cfg(test)]` fixture,
  the burn never touches `ActivityMetric`, and the date conflated onset
  with exhaustion. **Ownership, precisely: three relayed claims entered
  a §8 row unverified — the one row in this round that skipped the
  ground-cross-session-claims discipline is the one that was
  demolished.** The real build-blocker (FL-R16a) is the past-asymptote
  error arm: estimator dead-letter (no wallet can quote) *and* relay
  dead-letter (`get_current_fee_per_byte` → 0 → `check_fee` rejects the
  mempool) at ≈ yr 73.
- **F-3 (Moderate) → FL-R16c:** `supply_ratio` saturation +
  the `circulating = gross emission` definitional bug named for the
  sweep.
- **F-4 (process) → provenance corrected everywhere:** every "since
  FL-R12′" downgrade was consuming a signature not in the tree; all
  consumer rows re-scoped to "pending the amended signature," each
  naming what restores it if the direction reverses. Answer to the
  direct question, on the record: **no signature from the maintainer
  ever reached this session** — the sole source was the steering lane's
  "FL-R12′ IS SIGNED" relay.
- **Provenance evidence (steering's answer, recorded):** the word
  "Signed" was the maintainer's own, in the steering session — after
  proposing burn-recycling and declining to impose it ("it's your call
  between them"), he answered steering's plain-perpetual recommendation
  with, verbatim: *"Your argument holds, and it holds against mine on
  the merits. Signed: plain perpetual tail."* So the decision statement
  exists in the maintainer's words, **in-channel to an intermediary** —
  which is exactly what an in-tree countersignature exists to
  disambiguate, and why the demoted state ("direction accepted; NOT
  SIGNED") remains correct until he signs §8 himself: he can confirm or
  repudiate that exchange either way. Steering's propagation audit:
  exactly one artifact over-claimed (its headline to this lane); the
  census routing text and its own queue already said
  blocked-on-signature. FL-R16's defect is owned on both sides of the
  relay: steering asserted reachability from a grep without classifying
  cfg-gate or prose ("consumer confirmed live" — two of its three hits
  were doc comments); this lane minted the row without
  source-verifying the relay.
- **FL-R14 RULED (b) in-channel** — `u64` persisted; binding bound is
  the genesis-frozen 64-bit range-proof width; build-time assertion
  obligation recorded with the wrap-un-saturation failure mode named.
- **Build authorization: NO** until the row text matches the number the
  chain pays.

## Decisions pending (all with the maintainer)

1. ~~FL-R12′ signature~~ — **SIGNED at round 8**; FL-D1 closed; build
   authorized and **EXECUTED** (§Build above) on
   `feat/fee-ladder-r12-impl`, stacked on this design branch, local
   only; steering reviewed. **Round 9: hold LIFTED — design PR opened
   against dev; the implementation restructures into the ruled two-PR
   split (atomic composition under old names, then the mechanical
   rename) and follows the design PR's merge.**
2. ~~FL-R17~~ — **SIGNED (a) three tiers at review round 7**, standard
   as default (§5.5); single-rate rejected with named reopeners.
3. **FL-R13 / FL-D5** — fee-floor basis calibration round: its FL-R12′
   gate is SATISFIED (signed round 8, amendment adopted), so the round is
   simply open — non-blocking (the perpetual-tail ruling retired the
   genesis-blocking escalation), scheduled on its own merits.
4. **PRs** — the design PR is **this PR (#614)**; the implementation
   follows as the round-9 split: `feat/fee-ladder-impl-1` (atomic
   bundle, built and gated) then `-impl-2` (mechanical rename), each
   opened after this document merges.
5. Census-R2: **both resume conjuncts are SATISFIED** — FL-R12′ signed
   (round 8) and the red test extant (graduated green on impl-1). R2 can
   resume per its own criterion; the routing to the consensus lane
   (C2-R0 phase 2, which edits `CONSENSUS_RULE_CENSUS.md` §10) carries
   the criteria, and this file records their satisfaction.
