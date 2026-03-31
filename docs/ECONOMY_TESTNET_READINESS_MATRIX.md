# Economy Testnet Readiness Matrix

This matrix compares current implementation against:

- `docs/DESIGN_CONCEPTS.md`
- `docs/GENESIS_TRANSPARENCY.md`
- `docs/RELEASE_CHECKLIST.md`
- `shekyl-dev/docs/TESTNET_MINER.md`
- `shekyl-dev/docs/TESTNET_REHEARSAL_CHECKLIST.md`

Status labels:

- `implemented`
- `partial`
- `missing`

Drift labels:

- `doc_correction`
- `code_fix_required`
- `needs_decision`

## Core Economy Model

1. **Constants source of truth (`money_supply`, `coin`, decimal point, burn/release/staking params)**
   - Docs intent: canonical economics constants define testnet economics behavior.
   - Code: generated from `config/economics_params.json` into build-time headers (`src/cryptonote_config.h` includes generated params).
   - Status: `implemented`
   - Drift: `doc_correction` (some docs still imply direct literals in `cryptonote_config.h`)

2. **Component 1: release multiplier**
   - Code paths: `rust/shekyl-economics/src/release.rs`, FFI exports in `rust/shekyl-ffi/src/lib.rs`, applied in `src/cryptonote_basic/cryptonote_basic_impl.cpp`.
   - Status: `implemented`
   - Drift: none

3. **Component 2: adaptive burn + split**
   - Code paths: `rust/shekyl-economics/src/burn.rs`, `src/shekyl/economics.h`, use in `src/cryptonote_core/blockchain.cpp` and `src/cryptonote_core/cryptonote_tx_utils.cpp`.
   - Status: `implemented`
   - Drift: none

4. **Component 3: stake-ratio governance signal**
   - Code paths: stake ratio read and fed into burn computations in `blockchain.cpp`.
   - Status: `implemented`
   - Drift: none

5. **Component 4: staker emission share + decay**
   - Code paths: `rust/shekyl-economics/src/emission_share.rs`, split used in miner tx construction.
   - Status: `implemented`
   - Drift: none

## RPC/Test Visibility

1. **Economy observability fields in daemon RPC (`get_info`/staking info)**
   - Present: release multiplier, burn pct, stake ratio, pool totals, emission share fields.
   - Status: `implemented`
   - Drift: `partial` docs mention annualized yield field; daemon does not currently expose `staker_yield_annualized` directly.
   - Drift label: `needs_decision` (add field to code vs adjust docs wording)

2. **Operator testnet runbook and rehearsal gates**
   - Present in `shekyl-dev/docs/TESTNET_MINER.md` and `shekyl-dev/docs/TESTNET_REHEARSAL_CHECKLIST.md`.
   - Status: `implemented` (ops docs exist)
   - Drift: none

## Automation/Test Coverage

1. **Rust unit tests for economics formulas**
   - Present in `shekyl-economics` crate modules.
   - Status: `implemented`
   - Drift: none

2. **Rust sim parity with canonical config**
   - Current sim defaults are hardcoded in `rust/shekyl-economics-sim/src/engine.rs`.
   - Status: `partial`
   - Drift label: `code_fix_required` (add config parity tests to prevent drift)

3. **Rehearsal automation checks in Shekyl core**
    - `TESTNET_REHEARSAL_CHECKLIST.md` references `scripts/check_testnet_genesis_consensus.py`; not present in this repo.
    - Status: `missing`
    - Drift label: `needs_decision` (import/add script here vs keep only in shekyl-dev)

4. **Automated end-to-end economy assertions (live chain + RPC)**
    - Existing tests are mostly formula/unit-level or specific parity checks.
    - Status: `partial`
    - Drift label: `code_fix_required` (add economy-focused functional assertions)

## High-Impact Mismatch Notes

- **Block-time assumptions in docs vs current HF behavior**
  - Design/genesis references use 2-minute assumptions for day-count examples.
  - Runtime now aligns with that design target by consistently using `DIFFICULTY_TARGET_V2` (`120s`) in active HF1 difficulty target, block reward scaling, unlock-time leeway, RPC block target reporting, and sync ETA output.
  - Drift label: resolved (`code_fix_required` completed)

- **HF naming in rehearsal checklist**
  - `TESTNET_REHEARSAL_CHECKLIST.md` said "post-HF17 rules" for v3 tx checks.
  - Shekyl reboot policy is HF1-only.
  - Drift label: resolved (docs updated to HF1 across V3_ROLLOUT, PQC,
    PQC_MULTISIG, and STAKER_REWARD_DISBURSEMENT)

## Immediate Pre-Testnet Blockers

1. Missing automated parity guard between `economics_params.json` and simulation defaults.
2. Missing scripted rehearsal verifier in this repo for checklist hard gates (genesis consistency RPC checks).
3. No single automated economy smoke test that validates key RPC economics fields over chain progression.

## Next Actions

1. Add Rust parity and boundary tests (`code_fix_required`).
2. Add/port testnet rehearsal check script (`needs_decision` if it should live in shekyl-dev only).
3. Correct stale wording in docs where facts are wrong (`doc_correction` only; no design changes).
