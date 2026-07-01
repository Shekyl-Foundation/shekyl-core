# Legacy claim-era staking retirement — verified inventory + PR decomposition

**Status:** audit complete 2026-07-01 (4-agent whole-workspace sweep, every claim
below verified at source). This is the **map** the deletion PRs are cut from — not a
deletion in itself. Motivation: DQ1 retired confidential claim/tier staking in favour
of plain-transfer `stake_in` + archival bonds; the dead machinery lingers, and one dead
element (`StakingMeta` on `WalletOutput`) sits in the exact type where the emission
`MintLineageOutput` provenance seam must land ([`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md)
§8.0.3 / [`PRINCIPAL_STAKE_LIFECYCLE.md`](PRINCIPAL_STAKE_LIFECYCLE.md) §3 GF-4b).

Retired era = **Tier-A** (confidential stake/claim/unstake + lock-tier weighting).
Live era = **Tier-B** (archival bonds: `StakeEngine`, `ArchivalBondRecord`, work-based
`Curve` economics). The two are structurally isolated — no archival crate depends on
`shekyl-staking`; zero symbol-name collisions (`staked`/`StakeTier`/`StakeEntry` = 0 in
archival crates).

---

## Tier 1 — dead, zero external consumers, safe Rust-only deletion NOW

All four verified to have **zero** consumers outside `shekyl-staking` itself (grep of the
whole `rust/` workspace, production + tests). The kept modules (`tiers`, `meta`) are
independent of these — no dependency edge in either direction.

| Symbol / module | Lines | Purpose (retired) |
|---|---|---|
| `entitlement.rs` (whole module) | 432 | confidential-claim entitlement arithmetic / precision sweep |
| `registry.rs` (`StakeEntry`, `StakeRegistry`) | 148 | in-RAM stake registry (sim infra) |
| `rewards.rs` (`distribute_staker_rewards`, `StakerReward`) | 137 | pool-division reward split |
| `error.rs` (`StakingError`) | 15 | error type used only by registry/rewards |
| `property_tests.rs` | 271 | conservation tests over the above (dead) |
| `fuzz/fuzz_claim_reward.rs` | — | fuzzes `distribute_staker_rewards` (dead) |

→ **PR-1** below.

## Tier 2 — dead claim-era, but ENTANGLED (staged retirement, not interim)

Real deletion targets, but removal crosses a persisted-schema and/or the C++ FFI boundary,
so each needs its own staged PR.

**2a — claim-path cluster** (spans engine-core/engine-state/scanner). Reachable only via the
public-but-**retired** workflow `workflow::plan_claim_and_unstake` (claim/unstake is exactly
what DQ1 replaced) — not a genesis-live entry point.
- `claim_builder` (`ClaimTxBuilder`, `ClaimTxPlan`), `plan_claim_and_unstake`.
- `staker_pool` (`StakerPoolState`, `AccrualRecord`, `estimate_reward`), scanner `ClaimableInfo`.
- **Before deleting:** re-read `chain_economics_source` (uses `StakerPoolState::handle_reorg`)
  to confirm no genesis-live dependency.
- **Collision-risk:** `staker_pool_share` is a **frozen economics-digest param** (byte 41,
  live — KEEP), a *different thing* from the dead `StakerPoolState` accrual cache. Do not conflate.

**2b — tier machinery + `StakingMeta` (cross-language + rule-42).**
- `tiers.rs` (`LockTier`, `StakeTier`, `TIERS`, `TierTable`, `tier_by_id`, `MAX_CLAIM_RANGE`),
  `meta.rs` (`StakingMeta`).
- **FFI → C++:** `shekyl_stake_weight` / `_lock_blocks` / `_yield_multiplier` / `_max_claim_range`
  (shekyl-ffi). Removal needs the paired C++ caller cleanup (`07`-style consensus-adjacent care).
- **Persisted (rule-42 bump):** `TransferDetails.{staked, stake_tier, stake_lock_until,
  last_claimed_height}` + `WalletOutput` `StakingMeta` tag `0x04` → `LEDGER_BLOCK_VERSION`
  6→7 + regenerate `ledger_block.snap` (CI `schema-snapshot.yml` enforces the pairing).
- **Consumers to update:** economics snapshot (`TIERS`/`TierTable`), `set_staking_info`, scanner deser.
- This is where the emission `MintLineageOutput` provenance seam lands clean in `WalletOutput`
  once `StakingMeta` is gone (a provenance enum upgrading the `is_miner` bool at the scan seam).

## Tier 3 — live archival, KEEP (fully isolated, zero collisions)

`shekyl-archival-retention`, `shekyl-archival-bond-builder`, `shekyl-crypto-pq::archival_p`,
`shekyl-engine-core::engine::{stake_engine, pscan, stake_persist, stake_timing}`,
`reward_arithmetic` / `consensus_state`, archival `claimed_epochs_check_and_set`, and the
`StakingBlock` / `PScanState` / `PScanCursor` persistence. The frozen `staker_pool_share`
economics param.

---

## Never-shipped (0 refs — nothing to delete)

`StakeInstance` (comment-only), `StakeId` / `shekyl/stake-id-v1`, `N_S`/`G_S`/`N_arch`/`G_arch`,
`h_bind` / 3C subtree / 5-scalar leaf, `Locked`/`Accruing` states, `RegisterPendingStake` /
`StakeOpening` / `StakeView` / `RateEpochRecord`. `ADMISSION_MIN` is sim-label-only.

## C++ (out of scope for the Rust sweep)

`txin_stake_claim` / `txout_to_staked_key` live in `src/cryptonote_core/blockchain.cpp` etc.
Shekyl is v3-from-genesis with **no Monero chain history** ([`60-no-monero-legacy`](../../.cursor/rules/60-no-monero-legacy.mdc)),
so the "reorg-replay of old blocks" caveat does not hold — these are deletable, but as a
separate C++ consensus effort coordinated with 2b/2c, not this Rust cleanup.

---

## PR decomposition

- **PR-1 (interim, safe now):** delete the Tier-1 modules (`entitlement`/`registry`/`rewards`/
  `error` + `property_tests` + the fuzz target); trim `lib.rs`. Rust-only, **no schema bump,
  no FFI/C++ touch, no consumer updates**. ~1000 lines gone, each gate green. Leaves
  `shekyl-staking` as just the entangled tier-table + `StakingMeta`, clarifying what remains.
- **PR-2 (staged):** Tier-2a claim-path cluster, after the `chain_economics_source` re-read.
- **PR-3 (staged, cross-language + rule-42):** Tier-2b tier machinery + `StakingMeta` + the
  persisted claim fields (the `LEDGER_BLOCK_VERSION` bump + FFI export removal + C++ caller
  cleanup) — unblocks `MintLineageOutput` landing in a `StakingMeta`-free `WalletOutput`.

Ordering: dead → entangled → cross-language; each PR independently green. PR-1 is unblocked
and disjoint from in-flight PRs #223 (shekyl-tor) and #224 (shekyl-fcmp/ffi) — no merge
ordering constraint.
