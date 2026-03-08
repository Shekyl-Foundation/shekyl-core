# Shekyl Design Concepts

## Monetary Supply and Denomination Policy (Next Generation Shekyl)

This document proposes a concrete monetary design set for next-generation Shekyl, with rationale grounded in:

- Shekyl current implementation constraints.
- Comparative cryptocurrency monetary models.
- Mechanism-design research on long-run security budgets.
- UX goals for everyday currency use ("no satoshi-like pain").

---

## 1) Design Goals

Shekyl monetary policy should satisfy four constraints at once:

1. **Usability-first denomination**
   - Everyday users should rarely handle very long decimals.
   - Wallet defaults should feel natural for normal payment amounts.

2. **Long-run security budget**
   - Consensus participants must retain robust incentives after early issuance declines.
   - Design must avoid a brittle fee-only end state.

3. **Predictability and credibility**
   - Emission schedule should be simple enough to reason about.
   - Monetary policy should not require frequent governance intervention.

4. **Implementation safety**
   - Supply and atomic-unit arithmetic must remain safe under `uint64_t` accounting.
   - No overflow-prone parameter combinations.

---

## 2) Current Shekyl Baseline and Problem Statement

Current constants in `src/cryptonote_config.h`:

- `MONEY_SUPPLY = 2^32`
- `COIN = 10^12`
- `CRYPTONOTE_DISPLAY_DECIMAL_POINT = 12`
- `FINAL_SUBSIDY_PER_MINUTE = 3 * 10^11` atomic units

### Critical interpretation detail

In Cryptonote-family code, `MONEY_SUPPLY` is interpreted in **atomic units**, not whole coins. Therefore:

- Current effective whole-coin supply is `2^32 / 10^12 = 0.004294967296` SHEKYL.
- This is not economically meaningful for a production chain.

Reward logic in `src/cryptonote_basic/cryptonote_basic_impl.cpp`:

- `base_reward = (MONEY_SUPPLY - already_generated_coins) >> emission_speed_factor`
- `base_reward` is clamped to a minimum via `FINAL_SUBSIDY_PER_MINUTE`

Given the mismatch above, the chain effectively enters minimum-subsidy behavior immediately.

### Technical limit with `uint64_t`

If the target is `2^32` **whole coins**, then with atomic accounting:

- `MONEY_SUPPLY_ATOMIC = 2^32 * 10^decimals`
- Must satisfy `MONEY_SUPPLY_ATOMIC <= 2^64 - 1`

For `2^32` whole supply, the maximum safe decimal precision under `uint64_t` is:

- `decimals <= 9`

So `2^32` whole + 12 decimals is not representable in `uint64_t`.

---

## 3) Proposed Design Set (Recommended)

### Recommendation A (primary): Fixed headline supply + bounded tail emission

#### Parameters

- **Headline supply target:** `2^32` whole SHEKYL (`4,294,967,296`)
- **Atomic precision:** `9` decimals
- **Atomic unit constant:** `COIN = 10^9`
- **Display precision default:** `6` for typical wallet views (advanced mode can show full 9)
- **Long-run subsidy:** retain bounded non-zero terminal subsidy (tail emission), with periodic review only via hard-fork governance process

#### Why this set

1. **No satoshi-style UX pressure**
   - Very large whole-unit count avoids forcing users into tiny fractions for normal amounts.

2. **`uint64_t` safe**
   - `2^32 * 10^9 = 4.294967296e18`, within `2^64 - 1`.

3. **Security-budget resilience**
   - Tail emission avoids abrupt transition to pure fee-only incentives.
   - Aligns with research warning that fee-only miner incentives can become unstable.

4. **Predictable and simple**
   - Users and operators can reason about issuance.
   - Keeps policy transparent while preserving long-run liveness incentives.

---

## 4) Alternative Policy Options

### Option B: Hard cap + fee burn + tiny terminal floor

#### Option B structure

- Keep fixed cap narrative.
- Add adaptive fee mechanism where part of fees are burned.
- Preserve a very small terminal subsidy floor for security continuity.

#### Option B pros

- Strong scarcity narrative.
- Can dampen fee-market volatility and offset issuance.

#### Option B cons

- More complexity and tuning requirements.
- Harder to communicate and validate economically.

### Option C: Constant annual issuance (linear inflation model)

#### Option C structure

- Fixed number of new coins per year indefinitely.

#### Option C pros

- Operationally simple.
- Naturally declining percentage inflation over time.

#### Option C cons

- Weaker scarcity narrative.
- Market perception may undervalue "store-of-value" positioning.

---

## 5) Quantitative Denomination Framework

To avoid uncomfortable tiny fractions in user-facing payments, choose decimal precision `d` using:

- `coin_price = market_cap / circulating_supply`
- `d >= ceil(log10(coin_price / min_payment_value))`

Where:

- `min_payment_value` is smallest practical payment denomination in fiat terms (e.g., `$0.01` or `$0.001`).

### Example with `supply = 2^32` whole

Approximate coin price by market cap:

- `$1B` cap: `~$0.233` per coin
- `$100B` cap: `~$23.28` per coin
- `$1T` cap: `~$232.83` per coin

Implication:

- 4-6 decimals already support cent-scale payments over a very wide market-cap range.
- 9 decimals offers ample protocol safety margin without forcing users to see tiny fractions.

---

## 6) Security-Budget Rationale (Why avoid fee-only end state)

Mechanism-design and mining-incentive literature indicates:

- Fee-only regimes can induce unstable strategic behavior (e.g., undercutting and profitable forking in certain conditions).
- Transaction-fee mechanism design is non-trivial, especially with active block producers and MEV-like incentives.

Design implication for Shekyl:

- Maintain a bounded, predictable terminal issuance floor.
- Treat fees as complementary incentive and congestion signal, not sole long-run security source.

---

## 7) Migration and Compatibility Guidance

If this design is adopted:

1. **Hard-fork activation**
   - Use a single, explicit activation height.

2. **Versioned monetary semantics**
   - Keep pre-fork validation semantics intact.
   - Activate new supply/precision constants only for post-fork blocks.

3. **Wallet/UI migration**
   - Preserve legacy display compatibility where needed.
   - Introduce user-facing denomination aliases (e.g., milli-SHEKYL) if useful.

4. **RPC and API compatibility**
   - Ensure all amount fields remain atomic-unit based.
   - Add explicit metadata for display precision in docs and client SDKs.

5. **Test coverage**
   - Unit tests for reward curve and tail state.
   - Property tests for overflow boundaries (`uint64_t` limits).
   - Integration tests for pre-/post-fork chain sync.

---

## 8) Final Recommendation

Adopt **Recommendation A**:

- `2^32` whole SHEKYL headline supply
- `9` decimal atomic precision
- bounded non-zero terminal subsidy
- wallet-first denomination presentation

This best balances usability, implementation safety, and long-run network security.

---

## 9) References

### Protocol and ecosystem docs

- Bitcoin BIP process (BIP-42 context): <https://bips.dev/42>
- Monero technical specs: <https://docs.getmonero.org/technical-specs/>
- Monero tail emission rationale: <https://web.getmonero.org/resources/moneropedia/tail-emission.html>
- Ethereum EIP-1559 specification: <https://eips.ethereum.org/EIPS/eip-1559>
- Cardano monetary policy: <https://docs.cardano.org/about-cardano/explore-more/monetary-policy>
- Cardano rewards/reserve flow: <https://docs.cardano.org/about-cardano/learn/pledging-rewards>
- Avalanche token model overview: <https://avax.network/about/tokens>
- Dogecoin inflation rationale: <https://dogecoin.com/dogepedia/faq/dogecoin-inflation/>

### Research and mechanism design

- Carlsten et al. discussion summary (with paper link): <https://freedom-to-tinker.com/2016/10/21/bitcoin-is-unstable-without-the-block-reward/>
- Roughgarden, "Transaction Fee Mechanism Design" (arXiv 2106.01340): <https://arxiv.org/abs/2106.01340>
- Bahrani, Garimidi, Roughgarden, "Transaction Fee Mechanism Design with Active Block Producers" (arXiv 2307.01686): <https://arxiv.org/abs/2307.01686>

### Denomination and unit-bias context

- Example summary on crypto unit bias: <https://www.nofreelunch.co.uk/blog/unit-bias-crypto/>
