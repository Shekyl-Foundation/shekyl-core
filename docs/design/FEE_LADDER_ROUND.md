# FL Round Record — Fee Ladder Derivation

**Status:** OPEN — held at design-doc stage. All substance lives in
[`FEE_LADDER_DERIVATION.md`](FEE_LADDER_DERIVATION.md); this file is the
thin round-state record only (rule 95 — one owner per claim, no
restatement). Nothing lands in consensus until that doc's §8 is signed.

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
  "FL-R12′ IS SIGNED" relay; whether anything behind it exists is now a
  question put back to the steering lane.
- **FL-R14 RULED (b) in-channel** — `u64` persisted; binding bound is
  the genesis-frozen 64-bit range-proof width; build-time assertion
  obligation recorded with the wrap-un-saturation failure mode named.
- **Build authorization: NO** until the row text matches the number the
  chain pays.

## Decisions pending (all with the maintainer)

1. **FL-R12′ signature** — the F-1 amendment (pre-/post-multiplier) is
   drafted in the row and the oracle matches it; the maintainer signs
   the amended row or corrects the draft. Build authorization is **NO**
   until then (review round 4).
2. **FL-R13 / FL-D5** — fee-floor basis calibration round (non-blocking
   since the ruling).
3. **PR** — branch is pushed for review (review round 3); **PR remains
   unopened** per the maintainer's instruction.
4. Census-R2: **deferred per review-round-2 ruling** — resumes on
   FL-R12′ signature (red-test conjunct already discharged). The deferral
   + resume criteria were also routed by the steering lane to the
   consensus lane (C2-R0 phase 2, which edits `CONSENSUS_RULE_CENSUS.md`
   §10) so the queue itself carries them; with the branch now pushed the
   criteria are additionally reachable at this file.
