# LANE: FL-R3 time-grid round

**Branch:** `design/fl-r3-time-grid` (off `origin/dev` `c1709cf2f`)
**Worktree:** `~/shekyl/wt-fl-r3`
**Opened:** 2026-09-08

## What this round is

FL-R3 was RULED at review round 17: the hysteresis band **stays** and
FL-R3 closes by **restoring it to the served path** — not by persisting
`C_q` as chain state, not by retiring the band. The daemon currently
serves the un-banded pow2 ceiling because `blockchain.cpp` passes
`prev_cq = 0`.

The blocker is that the band needs history: `C_q(h) = f(C(h), C_q(h−1))`
is a recurrence. The ruling puts the restoration on the **time-grid**
branch — a "previous" taken from a grid-aligned anchor rather than from
unbounded history.

## Binding constraints (from the ruling, not negotiable in this round)

1. **Pure function of chain state.** No per-node held state. A
   restoration that acquires state repeals FL-R18 rather than restoring
   FL-R3.
2. **Single owner.** The band's arithmetic lives in one place; the
   instrument transliterates nothing.

## Two attempts already ruled out — do not re-derive them

- **Daemon-local remembered value.** Makes the served rate track the
  process's query history. Archived at tag
  `archive/fee-ladder-r12-impl-rejected-2026-09-08`
  (`blockchain.h` `mutable uint64_t m_fee_correction_cq{0}`).
- **Previous block's UNSEEDED snap.** A one-step approximation, not the
  recurrence, and it inverts the result.

## Process

Rule 26 (`26-sub-pr-design-discipline`) is cited: consensus-adjacent
surface, multi-round, design before implementation. Rule 22 —
anything deferred needs a named blocker.

## Related

- `docs/design/FEE_LADDER_DERIVATION.md` §8 FL-R3 (the ruling), FL-R18
  (derivability), §9 FL-D8 (boundary-cell occupancy — the owed
  measurement that would inform the grid period)
- `docs/design/FEE_LADDER_ROUND.md` (round record)
- Owner: `rust/shekyl-economics/src/fee.rs` `hysteresis_step`
- Call site: `src/cryptonote_core/blockchain.cpp` (`prev_cq = 0` today)
