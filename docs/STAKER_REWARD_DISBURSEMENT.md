# Staker Reward Disbursement Model

## Decision

Shekyl adopts a **claim-based** staker reward disbursement model (not direct
coinbase fan-out).

## Why Claim-Based

- keeps coinbase compact and deterministic
- avoids variable-size miner tx growth tied to staker-set cardinality
- decouples staking payout cadence from block template construction
- simplifies pool/node compatibility during HF17 rollout

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

## Implementation Phasing

1. **HF1 baseline**
   - compute and track `stake_ratio`
   - compute emission/burn splits (already wired)
   - defer actual claim transaction type to follow-up hardfork
2. **Claim activation hardfork**
   - add claim transaction/output grammar
   - add accrual and claim-validation paths
   - expose wallet RPC for claim estimation/submission

## Operator Notes

- no immediate coinbase-format change is required for HF1
- reward accounting metrics should be exposed in node RPC before claim
  activation to validate economics in production
