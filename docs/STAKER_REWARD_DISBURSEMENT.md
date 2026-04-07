# Staker Reward Disbursement Model

> **Last updated:** 2026-04-07

## Decision

Shekyl adopts a **claim-based** staker reward disbursement model (not direct
coinbase fan-out).

## Why Claim-Based

- keeps coinbase compact and deterministic
- avoids variable-size miner tx growth tied to staker-set cardinality
- decouples staking payout cadence from block template construction
- simplifies pool/node compatibility during the HF17 rollout
- makes anti-double-claim a watermark check rather than a coinbase audit

## Economic Flow

Per block, consensus computes:

- the staker emission share (Component 4)
- the staker fee-pool allocation from the adaptive burn (Component 2)

These amounts accrue to a global staker-reward accounting pool keyed by block
height. Eligible staked outputs claim their share of accrued rewards via
explicit claim transactions. The claim does not move the underlying staked
output; it draws only from the pool.

## Core Principle: Principal Lock vs. Reward Claimability

Shekyl draws a hard distinction between two concepts that other staking designs
often conflate:

1. **The principal lock.** The staked output itself is unspendable until
   `lock_until` is reached. This is enforced when the output is consumed by an
   unstake transaction (i.e. spent as a normal input). It is the user's
   commitment to the network.
2. **Reward claimability.** Accrued rewards belong to the staker as soon as
   they accrue. They can be claimed at any time after the staked output is
   created and before that output is consumed by an unstake transaction,
   regardless of whether `lock_until` has passed.

A claim transaction never touches the principal. It draws from the global pool
and is gated only by the watermark, not by the lock state of the staked
output. The lock applies to the principal; it does **not** apply to rewards.

This asymmetry is what makes the long-tier multipliers economically meaningful:
a 208-day commitment can yield throughout those 208 days rather than only at
the end.

## Accrual Lifecycle and the `lock_until` Cap

Although a staked output remains *claimable* for the entire window between
creation and the unstake spend, it only **accrues** rewards while it is within
its committed lock period. Specifically:

- An output accrues for blocks in the range `(creation_height, lock_until]`.
- For blocks where `block_height > lock_until`, the output is excluded from
  the per-block `total_weighted_stake` computation. It contributes nothing to
  the denominator and earns nothing from the numerator.
- A claim transaction may still be submitted after `lock_until` to drain the
  backlog accumulated during the lock window. The cap on `to_height` (see
  validation rules below) bounds how far that drain can reach.

### Why the cap is necessary

Without this rule, a "matured but never unstaked" output would behave as a
free perpetual stake at the highest tier multiplier. A user could lock at the
Long tier (2.0×) for 208 days, never unstake, and continue collecting at 2.0×
indefinitely with no further commitment. This would:

- defeat the economic purpose of tiered locks
- distort the `stake_ratio` signal that Component 3 governance reads
- create a strict incentive to never unstake, hollowing out the unstake path

Capping accrual at `lock_until` keeps the contract symmetric: the staker earns
exactly what they committed to and nothing more, but they can claim that
backlog on their own schedule.

### Wallet UX implication

`estimate_claimable_reward` and `get_staked_outputs` MUST surface "frozen at
`lock_until`" as a distinct state from "still accruing." Otherwise users will
observe their claimable amount stop growing and assume the daemon is broken.

## Consensus Requirements

- deterministic accrual accounting keyed by staked output identity
- per-block `total_weighted_stake` excludes outputs where
  `block_height > lock_until`
- claim validation must NOT reject on `lock_until > current_height`
- claim validation MUST enforce `to_height ≤ min(current_height, lock_until)`
- anti-double-claim protections via a monotonic per-output watermark
- bounded per-claim work to preserve block validation performance

## Implementation Status

The full claim-based staking system is implemented and active from
`HF_VERSION_SHEKYL_NG` (hardfork 17).

### Transaction types

| Type | Description |
|---|---|
| `txout_to_staked_key` | Output target for locked staking outputs. Contains `key`, `view_tag`, `lock_tier`, `lock_until`. |
| `txin_stake_claim` | Input type for claiming accrued rewards. Contains `amount`, `staked_output_index`, `from_height`, `to_height`, `k_image`. The `k_image` is a synthetic identifier used solely for double-claim prevention against the watermark; it is unrelated to the staked output's spend image. |

### On-chain storage (LMDB)

| Table | Key | Value | Purpose |
|---|---|---|---|
| `staker_accrual` | block height (uint64) | `staker_accrual_record` (emission, fee pool, total weighted stake) | Per-block accrual accounting |
| `staker_claims` | staked output index (uint64) | last claimed height (uint64) | Watermark for anti-double-claim |
| (property) `staker_pool_balance` | — | uint64 | Running total of unclaimed pool balance |

### Staking tiers

| Tier | Lock duration | Yield multiplier |
|---|---|---|
| 1 (Short) | ~1,000 blocks (~33 hours) | 1.0× |
| 2 (Medium) | ~25,000 blocks (~35 days) | 1.5× |
| 3 (Long) | ~150,000 blocks (~208 days) | 2.0× |

No minimum stake amount. Any amount can be staked.

### Claim transaction validation rules

A claim input is valid if and only if all of the following hold:

1. `from_height` equals the claim watermark + 1 for the staked output, or the
   output's creation height + 1 for the first claim.
2. `to_height ≤ min(current_chain_height, lock_until)`. This is the
   asymmetric cap: the claim window may extend up to either the present or
   the end of the lock period, whichever is earlier.
3. `to_height - from_height` does not exceed `MAX_CLAIM_RANGE` (10,000
   blocks). Multiple sequential claims are required to drain longer backlogs.
4. The claimed `amount` matches the deterministic per-block reward
   computation summed over `[from_height, to_height]`, using the historical
   `total_weighted_stake` recorded for each block in `staker_accrual`.
5. The synthetic `k_image` has not already been used (anti-double-claim).
6. Pure claim transactions (all inputs are `txin_stake_claim`) use
   `RCTTypeNull` signatures.
7. **Pool sufficiency, batch and sequential.** The total of all claim
   amounts in a single transaction must not exceed `staker_pool_balance`
   (intra-tx batch check, enforced in `check_tx_inputs`). Additionally,
   when validating multiple claim transactions within the same block, each
   tx is checked against the running `staker_pool_balance` *after* prior
   txs in that block have been applied. This prevents two individually
   valid claim txs from collectively overdrawing the pool.

There is **no** check on `lock_until > current_height`. Claims are valid both
during the lock period and after maturity, up until the staked output is
consumed by an unstake transaction.

Reward computation uses 128-bit integer arithmetic (`mul128` / `div128_64`)
throughout. Floating-point is forbidden in this path because tiny rounding
divergences would cause consensus failures across nodes built with different
compilers or standard libraries.

### Accrual computation per block

Each block after HF17 activation, the consensus layer derives the accrual
record deterministically from chain state at `block_height`. The computation
is **not** carried in any field of the block produced by the miner; validators
recompute it independently and reject any divergence.

```
# 1. Pool contributions for this block
staker_emission = shekyl_calc_emission_share(block_emission, year)
staker_fee_pool = shekyl_calc_fee_pool(block_fee_burn)
block_pool      = staker_emission + staker_fee_pool

# 2. Weighted stake denominator (tier multipliers applied INLINE)
total_weighted_stake = 0  # 128-bit accumulator
for staked in active_staked_outputs:
    if staked.lock_until < block_height:
        continue  # frozen outputs do not accrue (see Accrual Lifecycle)
    # mul_num / mul_den is the tier multiplier as an exact rational
    # sourced from rust/shekyl-staking/src/tiers.rs via FFI
    mul_num, mul_den = shekyl_stake_tier_multiplier(staked.tier)
    total_weighted_stake += mul_div_128(staked.amount, mul_num, mul_den)

# 3. Record and accumulate
staker_accrual[block_height] = {
    staker_emission,
    staker_fee_pool,
    total_weighted_stake,
}

if total_weighted_stake == 0:
    # No active stakers — pool contribution is BURNED, not carried.
    # See "Empty-staker-set behavior" below.
    pass
else:
    staker_pool_balance += block_pool
```

The per-claim reward computation MUST use the same multiplier source. The
formula

```
reward_for_block = block_pool * (amount * mul_num / mul_den) / total_weighted_stake
```

is conservative — that is, `∑ rewards_at_block ≤ block_pool` for all valid
claims against that block — if and only if the same `(amount × multiplier)`
expression is summed in the denominator at accrual time. **Filling
`total_weighted_stake` from raw amounts is a critical bug** that causes
proportional over-distribution at the rate `(weighted_sum / raw_sum) − 1`,
worst-case +100% when all stakers are in the Long tier.

#### Single source of truth for tier multipliers

Tier multipliers live in **one place only**: `rust/shekyl-staking/src/tiers.rs`.
Both the per-block accrual scan and the per-claim reward computation MUST
read multipliers via the FFI export from that module. No hardcoded
multiplier constants are permitted in C++ consensus code, in the wallet, or
in RPC handlers. Tests in `rust/shekyl-staking/src/tiers.rs` enforce
contiguous tier IDs, ordering invariants, and positive parameters.

Multipliers are represented as exact rationals (numerator/denominator pairs),
never as floating-point. All weighted-stake arithmetic uses `mul_div_128` to
avoid overflow at large staker sets and to avoid floating-point rounding
divergence between nodes.

#### Conservation invariant (consensus-enforced)

For every block height `h`, the following invariant MUST hold:

```
sum_over_all_valid_single_block_claims_at(h) ≤ staker_emission(h) + staker_fee_pool(h)
```

A consensus-level test reproduces this by simulating one full claim per
active staked output covering exactly block `h`, summing the resulting claim
amounts, and asserting the inequality (allowing only for floor-division dust
remainder). This test runs against every block in core test fixtures and
should be added to the fuzzing harness in `rust/shekyl-staking/fuzz/`.

In addition, a hard sanity check rejects any `staker_accrual` record where
`total_weighted_stake < sum_of_active_staked_amounts(h)`. This is impossible
for a correctly computed record (multipliers are all ≥ 1.0), so any
violation is unambiguous evidence of corruption or a regression.

#### Empty-staker-set behavior

If `total_weighted_stake == 0` at block `h` — i.e. no active staked outputs
exist at that height — the block's `staker_emission + staker_fee_pool`
contribution is **burned**, not carried forward. Specifically:

- `staker_pool_balance` is not incremented
- the `staker_accrual` record is still written, with
  `total_weighted_stake = 0` and the contribution amounts recorded for
  audit purposes
- the burned value is reported in `get_staking_info` as
  `lifetime_pool_burned_no_stakers`

Burning rather than carrying is chosen for two reasons. First, it preserves
the property that the very first staker after a no-staker interval does not
receive an unbounded windfall — they earn only from blocks during which
they were actually staked. Second, it removes the need for any
"carry pool" state, which would otherwise have to be reorg-aware and
double-spend-protected. The cost is modest: the no-staker condition only
arises in pathological early-chain or post-collapse scenarios, and the burn
contributes (correctly) to the deflationary objective.

### Reorg handling

When blocks are popped (reorg), the corresponding accrual records are removed
and the pool balance is decremented by the reversed accrual amount. Watermark
entries that referenced reverted blocks are rolled back atomically within the
same LMDB transaction as the block pop.

## Wallet and RPC Support

### Simplewallet commands

| Command | Description |
|---|---|
| `stake <tier> <amount>` | Create a staking transaction locking coins for the specified tier |
| `unstake` | Spend all matured staked outputs back to the wallet. Drains any unclaimed backlog first. |
| `claim_rewards` | Claim accrued rewards from all claimable staked outputs (locked or matured) |
| `staking_info` | Display current staking status, including any outputs frozen at `lock_until` |

### Wallet RPC

| Method | Description |
|---|---|
| `stake` | Create a staking transaction (params: `tier`, `amount`, `priority`, `account_index`) |
| `unstake` | Unstake all matured outputs (params: `priority`). Drains backlog first. |
| `get_staked_outputs` | List all staked outputs with tier, lock state, accrual state (active / frozen-at-`lock_until`), and last-claimed watermark |
| `get_staked_balance` | Total staked principal |
| `claim_rewards` | Claim all available staking rewards |

### Wallet behavior

- `get_claimable_staked_outputs` returns any staked output that is
  `not_yet_unstaked` AND `last_claimed_height < min(current_height, lock_until)`.
  It does **not** filter by lock state.
- `create_claim_transaction` accepts both locked and matured-but-unspent
  outputs. The historical "claim before unstaking" guard is preserved as a
  workflow nudge in `unstake` (it drains the backlog first), not as a state
  check inside `create_claim_transaction`.
- `estimate_claimable_reward` calls the daemon RPC
  `estimate_claim_reward`, which uses the accrual database to compute the
  reward server-side and respects the `min(current_height, lock_until)` cap.

### Daemon RPC

| Method | Description |
|---|---|
| `get_staking_info` | Returns current staking metrics: height, stake ratio, pool balance, emission share, tier lock durations, `lifetime_pool_burned_no_stakers` |
| `estimate_claim_reward` | Per-output reward computation using the accrual database |
| `get_info` | Extended with `stake_ratio` and `staker_pool_balance` fields |

## Privacy Considerations

Staker claims (`txin_stake_claim`) create on-chain events that can be
correlated with specific accrual periods and staking outputs:

- **Claim timing.** Frequent claims (e.g. every block) create a regular
  on-chain heartbeat that may be linkable to a staker's identity. Wallets
  should default to batched claiming at longer intervals. This is the primary
  reason claimability is decoupled from the lock — users need the latitude to
  schedule claims for privacy reasons rather than being forced into a
  one-shot reveal at unlock.
- **Amount correlation.** Claim amounts are proportional to stake size and
  lock tier. Over multiple claims, the pattern may narrow the set of
  possible stakers. Future protocol versions may introduce claim batching
  at the consensus level (see `DESIGN_CONCEPTS.md` Section 14, Research
  Appendix).
- **Staked output visibility.** `txout_to_staked_key` outputs are
  distinguishable from regular outputs on-chain. The lock duration is
  publicly visible. This is an inherent trade-off of transparent staking and
  cannot be mitigated without a full PQ privacy redesign (V4).
- **Frozen-at-`lock_until` outputs.** A matured-but-unspent output that is
  still draining its backlog produces claims that are on-chain
  indistinguishable from any other claim. The frozen state introduces no new
  observable.

## Operator Notes

- Staking economics are active from HF17 block height onward.
- The accrual pool accumulates per-block regardless of whether claims are made.
- Outputs past their `lock_until` neither contribute to nor draw from new
  per-block accrual; they may still claim previously accumulated backlog.
- Node operators should monitor `staker_pool_balance` via `get_staking_info`
  RPC.
- Wallet implementations that support staking must handle
  `txout_to_staked_key` outputs in transaction scanning, and must surface the
  "frozen at `lock_until`" state distinctly from "actively accruing."
