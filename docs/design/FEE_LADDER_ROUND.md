# FL Round Record — Fee Ladder Derivation

> **STATUS: OPEN, HELD AT DESIGN-DOC STAGE.** All substance lives in
> [`FEE_LADDER_DERIVATION.md`](FEE_LADDER_DERIVATION.md); this file is the
> thin round-state record only (rule 95 — one owner per claim, no
> restatement). Nothing lands in consensus until that doc's §8 is signed.

Family: `FL-*` (index row: [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md)).
Branch: `design/fee-ladder-derivation`, off `dev` 6d2f49a5c, merged with
`dev` a566a466 at review round 2. Instrument:
`shekyl-economics-sim --fee-ladder` (`rust/shekyl-economics-sim/src/fee_ladder.rs`).

## Commit log (this branch, in order)

| Commit | What |
| --- | --- |
| fb02e4b7c | Pre-registration: FL-C1…C8 criteria + FL-V1…V6 verifications, committed **before the instrument existed** (rule-11 register; the ordering is the method) |
| 8a55415b5 | Instrument + derivation + unsigned §8 (3-rung state-computed proposal) |
| fc6018803 | Adversarial-review corrections (12.5× not 6.25×; ceil quantization, register untouched + deviation disclosed; unbuffered clamp) |
| 1a7390674 | FL-V7 minted (perpetual-tail contradiction, escalated at steering) |
| a8a01b950 | FL-V7 first restatement (superseded at review round 2 — see below) |
| (review round 2) | dev merge to a566a466; FL-V7 re-restated per maintainer ruling; FL-V8…V11 minted; FL-R12′/FL-R13/FL-D5/W7; red test `terminal_reward_legs_agree` observed red; this file |

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
  `blockchain.cpp:6410-6420` / `cryptonote_basic_impl.cpp:169`).
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

## Decisions pending (all with the maintainer)

1. **FL-R12′** — terminal emission-state ruling (lean recorded: cap;
   unsigned).
2. **FL-R13 / FL-D5** — fee-floor basis round (genesis-blocking if cap).
3. **Push/PR authorization** — **HELD** per review round 2; branch stays
   local until lifted.
4. Census-R2: **deferred per review-round-2 ruling** — resumes on
   FL-R12′ signature (red-test conjunct already discharged). Because this
   branch is held and unpushed, the deferral + resume criteria were also
   routed by the steering lane to the consensus lane (C2-R0 phase 2,
   which edits `CONSENSUS_RULE_CENSUS.md` §10) so the queue itself
   carries them — a deferral whose conditions are invisible to a census
   reader would read as a queue item still waiting its turn.
