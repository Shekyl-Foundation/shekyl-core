# Staker Reward Disbursement Model

## Decision

Shekyl adopts a **claim-based** staker reward disbursement model (not direct
coinbase fan-out).

## Why Claim-Based

- keeps coinbase compact and deterministic
- avoids variable-size miner tx growth tied to staker-set cardinality
- decouples staking payout cadence from block template construction
- simplifies pool/node compatibility during HF1 rollout

## Economic Flow

- Per block, consensus computes:
  - staker emission share (component 4)
  - staker fee-pool allocation from adaptive burn (component 2)
- These amounts accrue to a global staker-reward accounting pool.
- Eligible staked outputs claim accrued rewards via explicit claim txs.

## Consensus Requirements

- deterministic accrual accounting keyed by staked output identity
- lock-state checks at claim time (`lock_until`, ownership proof)
- anti-double-claim protections (monotonic claim index/height watermark)
- bounded per-claim work to preserve block validation performance

## Implementation Status

The full claim-based staking system is implemented and active from
HF_VERSION_SHEKYL_NG (hardfork 1).

### Transaction types

| Type | Description |
|---|---|
| `txout_to_staked_key` | Output target for locked staking outputs. Contains `key`, `view_tag`, `lock_tier`, `lock_until`. |
| `txin_stake_claim` | Input type for claiming accrued rewards. Contains `amount`, `staked_output_index`, `from_height`, `to_height`, `k_image`. |

### On-chain storage (LMDB)

| Table | Key | Value | Purpose |
|---|---|---|---|
| `staker_accrual` | block height (uint64) | `staker_accrual_record` (emission, fee pool, total weighted stake) | Per-block accrual accounting |
| `staker_claims` | staked output index (uint64) | last claimed height (uint64) | Watermark for anti-double-claim |
| (property) `staker_pool_balance` | — | uint64 | Running total of unclaimed pool balance |

### Staking tiers

| Tier | Lock duration | Yield multiplier |
|---|---|---|
| 1 (Short) | ~1,000 blocks (~33 hours) | 1.0x |
| 2 (Medium) | ~25,000 blocks (~35 days) | 1.5x |
| 3 (Long) | ~150,000 blocks (~208 days) | 2.0x |

No minimum stake amount. Any amount can be staked.

### Claim transaction validation rules

1. `from_height` must equal the claim watermark + 1 for the staked output (or the output's creation height for the first claim).
2. `to_height` must not exceed the current chain height.
3. `to_height - from_height` must not exceed `MAX_CLAIM_RANGE` (10,000 blocks).
4. The claimed `amount` must match the deterministic per-block reward computation summed over `[from_height, to_height]`.
5. The `k_image` must not already be spent (anti-double-claim).
6. Pure claim transactions (all inputs are `txin_stake_claim`) use `RCTTypeNull` signatures.
7. The pool balance must be sufficient to cover the claim amount.

### Accrual computation per block

Each block after HF1 activation:
1. Compute `staker_emission` from the block emission via FFI (`shekyl_calc_emission_share`).
2. Compute `staker_fee_pool` from the block's fee burn via FFI (`shekyl_calc_fee_pool`).
3. Compute `total_weighted_stake` by scanning all staked outputs and applying tier multipliers.
4. Store the accrual record and increment `staker_pool_balance`.

### Reorg handling

When blocks are popped (reorg), the corresponding accrual records are removed
and the pool balance is decremented by the reversed accrual amount.

## Wallet and RPC Support

### Simplewallet commands

| Command | Description |
|---|---|
| `stake <tier> <amount>` | Create a staking transaction locking coins for the specified tier |
| `unstake` | Spend all matured staked outputs back to the wallet |
| `claim_rewards` | Claim accrued rewards from all claimable staked outputs |

### Wallet RPC

| Method | Description |
|---|---|
| `stake` | Create a staking transaction (params: `tier`, `amount`, `priority`) |
| `unstake` | Unstake all matured outputs (params: `priority`) |
| `get_staked_outputs` | List all staked outputs with tier, lock info, and maturity status |
| `claim_rewards` | Claim all available staking rewards |

### Daemon RPC

| Method | Description |
|---|---|
| `get_staking_info` | Returns current staking metrics: height, stake ratio, pool balance, emission share, tier lock durations |
| `get_info` | Extended with `stake_ratio` and `staker_pool_balance` fields |

## Privacy Considerations

Staker claims (`txin_stake_claim`) create on-chain events that can be
correlated with specific accrual periods and staking outputs. Privacy
implications:

- **Claim timing:** Frequent claims (e.g., every block) create a regular
  on-chain heartbeat that may be linkable to a staker's identity. Wallets
  should default to batched claiming at longer intervals.
- **Amount correlation:** Claim amounts are proportional to stake size and
  lock tier. Over multiple claims, the pattern may narrow the set of
  possible stakers. Future protocol versions may introduce claim batching
  at the consensus level (see `DESIGN_CONCEPTS.md` Section 14, Research
  Appendix).
- **Staked output visibility:** `txout_to_staked_key` outputs are
  distinguishable from regular outputs on-chain. The lock duration is
  publicly visible. This is an inherent trade-off of transparent staking
  and cannot be mitigated without a full PQ privacy redesign (V4).

## Operator Notes

- Staking economics are active from HF1 (genesis) onward.
- The accrual pool accumulates per-block regardless of whether claims are made.
- Node operators should monitor `staker_pool_balance` via `get_staking_info` RPC.
- Wallet implementations that support staking must handle `txout_to_staked_key` outputs in transaction scanning.
