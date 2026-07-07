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
- **Collision-risk:** `staker_pool_share` is a **frozen economics-digest param** (byte 41,
  live — KEEP), a *different thing* from the dead `StakerPoolState` accrual cache. Do not conflate.

> **Verified at source 2026-07-01 — 2a is NOT one clean deletion; it splits.** The
> `chain_economics_source` re-read (the map's gate) confirmed the cluster is dead: the feared
> genesis-live consumer `StakeEngine::projected_yield` **does not exist** (a hypothetical `e.g.`
> in a docstring — no definition, no call site). But the boundary is more interwoven than the
> tier-based audit assumed:
> - **2a-i — claim-tx-building surface (clean):** `claim_builder` + `workflow`
>   (`plan_claim_and_unstake`). No production caller. **Landed — PR #226.**
> - **2a-ii — pool-division economics (cascades into a trait):** `StakerPoolState` /
>   `AccrualRecord` / `estimate_reward` + `chain_economics_source` feed the **`EconomicsEngine`
>   trait** method `pool_weighted_total` — whose *only* consumer is a differential **test**, and
>   whose engine slot is production-instantiated but "stays unconsumed" (`lifecycle.rs`). This is
>   the **R0-D5 "Stage 3"** economics retirement (trait-method removal + `LocalEconomics` +
>   lifecycle rewiring). Folds into the batched final PR below.
> - **2a-iii — `ClaimableInfo` / `has_claimable_rewards` / `claimable_outputs`** tie into the
>   persisted **staked-fields**, so they belong with 2b, not 2a.

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

## PR decomposition (revised 2026-07-01 — batch, don't drip)

> **Process correction:** full CI here is ~2h/PR, so the earlier one-PR-per-module drip
> (#225/#226/#227) was wasteful. Remaining work is **batched into as few PRs as the
> boundaries allow** — split only on a real reason (schema/consensus boundary, base-skew).

- **PR-1 — LANDED (#225):** Tier-1 zero-consumer modules (`entitlement`/`registry`/`rewards`/
  `error` + `property_tests` + fuzz). Left an orphaned `entitlement/` subdir → **cleanup #227**
  (couldn't fold into #226: that branch predates #225, so `entitlement.rs` still declares the
  subdir there).
- **PR-2 — LANDED (#226):** Tier-2a-i, the claim-tx-building surface (`claim_builder` +
  `workflow`). Verified dead (`projected_yield` is a phantom). Rust-only.
- **PR-3 (#231, the PR carrying this map update) — Rust-complete, FFI quarantined; scope
  adjusted at source.** The mapped "paired C++ caller cleanup" turned out to be the full
  claim-era C++ consensus surface (the `shekyl_stake_*` callers sit inside the stake-ratio
  cache, `txout_to_staked_key` maturity/validation, and claim-range validation in
  blockchain.cpp/blockchain_db.cpp — a rule-07 consensus-boundary cutover, not thin call
  sites), so C++ split off as **PR-4**. PR-3 delivers the complete Rust sweep: 2a-ii
  (staker_pool + `chain_economics_source` +
  `EconomicsEngine::pool_weighted_total` removal; `LocalEconomics` de-genericized to a pure
  constants rulebook; `ScanResult::stake_events`/`StakeEvent` + `RefreshSummary.stake_events`
  gone) and 2b (`StakingMeta` + `WalletOutput.staking` + `TransferDetails.{staked, stake_tier,
  stake_lock_until, last_claimed_height}` + `ClaimableInfo` + the staked `LedgerBlock` queries
  + `BalanceSummary` staked buckets + the four claim-era RPC methods). **Rule-42:**
  `LEDGER_BLOCK_VERSION` 6→7 **and** `WALLET_LEDGER_FORMAT_VERSION` 8→9 (both snaps moved);
  economics snapshot digest format 0x01→0x02 (tier table left the digest). `shekyl-staking`
  survives **quarantined** (tiers.rs + build.rs only, banner in lib.rs): sole consumer =
  shekyl-ffi's four `shekyl_stake_*` C ABI exports that back the not-yet-deleted C++ paths.
  Unblocks `MintLineageOutput` landing in a `StakingMeta`-free `WalletOutput`.
- **PR-4 (this PR, the C++ consensus cutover — rule-07 atomic):** the claim-era wire and
  everything reachable from it, in one cut. Wire types `txin_stake_claim` + `txout_to_staked_key`
  (variants, boost/json/debug serialization, VARIANT_TAGs 0xf2/0xf3 retired unreassigned) and
  `check_output_types` narrowed to tagged-key-only — the actual acceptance flip. Blockchain:
  the stake-ratio cache + unlock schedules, `get_stake_ratio`/`get_total_staked`,
  `check_stake_claim_input`, the claim-only tx path, the block-aggregate pool check. The burn
  curve's stake-ratio input is pinned 0 (identical behavior — no staked output could exist);
  the staker inflow (emission share + fee-pool share) is now unconditionally burned, with the
  2b reward-emission C-1 cutover named in-code as the redirect point. DB: `staker_accrual`
  (5-field record) replaced by a purpose-true per-height `block_burn` u64 (the live
  `total_burned` pop-rollback bookkeeping it was smuggling); `staker_pool_balance` property +
  `staker_claims` watermark table deleted. RPC: `get_staking_info` + `estimate_claim_reward`
  gone; `get_info` drops `stake_ratio`/`staker_pool_balance`. Wallet: transfer_details stake
  fields (cache version 3→4), claim/unstake/stake tx builders, watermark staging, 5 wallet-RPC
  methods, 5 FFI dispatchers. Rust: `shekyl-staking` crate deleted; the 8 quarantined
  `shekyl_stake_*`/`shekyl_calc_*` FFI exports + header decls gone; curve-tree
  `TargetKind::StakedKey` retired (store schema 3→4, tag 2 unreassigned). Config: the 8 dead
  stake-tier keys left `economics_params.json` + the generator (`staker_pool_share` +
  `staker_emission_*` stay — live burn/emission split). Bonus fix-on-find: the store rollback
  property-test fixture drained `maturity == H` at H, diverging from the pinned
  `drained_through(H) = H − 1` convention — invisible until the claim-era fixture entropy
  shifted; fixed to the production mapping.

Ordering: dead → entangled → cross-language — complete. With PR-4 merged the claim-era
system is fully retired; genesis staking is archival bonds (gate 4/7) + the 2b
reward-emission leg.
