# Genesis Block Transparency

## Purpose

This document provides a complete, verifiable account of the original Shekyl
chain and the rationale for the Shekyl NG reboot. It is intended to be read by
anyone evaluating the fairness and integrity of the Shekyl NG genesis
distribution.

The founding team is committed to the same standard of transparency that
motivates the Shekyl name itself: trust through verifiability, not through
authority.

---

## 1) The Original Chain — Verified Statistics

The original Shekyl blockchain data has been preserved and independently
verified. The LMDB database containing the full chain was inspected directly
using standard tooling (`mdb_stat`, Python `lmdb` library) against the raw
`data.mdb` file. The following statistics are derived from the `block_info`
table's cumulative emission field and the `tx_indices` table entry count:

| Metric | Value |
|---|---|
| Total blocks | 168,947 |
| Total transactions | 168,981 |
| Non-coinbase transactions | 34 |
| Total atomic units emitted | 2,745,081,907,831,749,734 |
| Total whole coins (12-decimal basis) | ~2,745,081 SHEKYL |
| Chain start | ~January 2018 |
| Chain end (last block) | ~March 2026 |

The raw database schema confirmed the chain used the original CryptoNote
`txs` table structure, predating the pruning-era `m_txs_pruned` /
`m_txs_prunable` split introduced in later Monero releases. The data is
intact and readable.

---

## 2) Why the Original Parameters Were Broken

The original chain launched with a critical misconfiguration in
`src/cryptonote_config.h`:

```
MONEY_SUPPLY = 2^32          // interpreted as atomic units, not whole coins
COIN = 10^12                 // 12-decimal precision
CRYPTONOTE_DISPLAY_DECIMAL_POINT = 12
```

In CryptoNote-family code, `MONEY_SUPPLY` is expressed in **atomic units**.
With 12-decimal precision, the effective whole-coin supply ceiling was:

```
2^32 / 10^12 = 0.004294967296 SHEKYL
```

This means the chain crossed its nominal supply ceiling almost immediately
after genesis and entered minimum-subsidy (tail emission) behavior for its
entire operational lifetime. Every block reward paid since approximately
the first few blocks was the `FINAL_SUBSIDY_PER_MINUTE` floor — not a
meaningful geometric emission curve.

In addition, `2^32` whole coins with 12-decimal atomic accounting is not
representable in `uint64_t`:

```
2^32 * 10^12 = 4.294967296 × 10^21  >  2^64 - 1 = 1.844 × 10^19
```

The original configuration was therefore not only economically
non-functional but would have caused integer overflow had the intended
supply ever been approached. The chain was, in a technical sense, broken
by design from its first block.

---

## 3) What the Chain Actually Was

Given the verified statistics above, the original Shekyl chain is accurately
characterized as:

- **A proof-of-concept mining chain.** 168,947 blocks were mined over
  approximately eight years by a small group of participants keeping the
  network alive.

- **Economically inactive.** Only 34 non-coinbase transactions occurred in
  the chain's entire history. There was no meaningful commerce, no token
  market, and no user base beyond the founding miners.

- **Running entirely on tail emission.** Every block reward was the minimum
  subsidy floor. The intended geometric emission curve never operated as
  designed.

- **Not recoverable as a balance snapshot.** CryptoNote's privacy model
  uses one-time stealth addresses, meaning the chain records outputs against
  one-time public keys — not wallet addresses. There is no mechanism to
  extract a per-wallet balance from chain data without the private view key
  of every recipient. Even if such a snapshot were technically possible, the
  34-transaction history means the UTXO set is trivially small and entirely
  held by the founding miners.

---

## 4) Why a Clean Reboot Is Justified

The founding team considered several options for the Shekyl NG launch:

**Option A: Proportional snapshot airdrop.** Attempt to map original chain
outputs to Shekyl NG genesis allocations. Rejected because: (1) CryptoNote
privacy makes wallet-level balances unextractable without private key
cooperation; (2) the original emission was entirely tail-emission subsidy,
making the "earned" framing difficult to justify; (3) the 34-transaction
history means the UTXO set is de facto a small founder allocation by another
name.

**Option B: View-key submission.** Ask original holders to submit their
view keys to prove balances. Rejected as privacy-invasive and operationally
impractical.

**Option C: Clean genesis with founder allocations.** Treat Shekyl NG as a
fresh start with an explicit, transparent founder allocation at genesis and
the new Four-Component economic model governing all subsequent emission.
**Adopted.**

A clean reboot is justified on the following grounds:

1. The original monetary parameters were technically misconfigured and
   produced no functional emission curve.
2. The original chain had no real economic activity or user base.
3. The Shekyl NG design (documented in `DESIGN_CONCEPTS.md`) introduces
   a fundamentally different and carefully validated economic architecture
   that cannot be meaningfully grafted onto the old parameter set.
4. All founding participants have reviewed the original chain data and
   voluntarily agreed to accept genesis allocations that are substantially
   reduced relative to what a naive proportional snapshot would suggest —
   in the interest of a fair, clean launch with no legacy overhang.

---

## 5) Founder Allocation Principles

The founding team has agreed to the following principles governing the
genesis allocation:

- **No hidden pre-mine.** The genesis block distribution is published in
  full before launch. Every address and amount is publicly visible on-chain
  from block zero.

- **Reduced relative to legacy claim.** Founders accept materially less
  than a proportional interpretation of their original mining rewards would
  imply. This is a deliberate act of good faith toward future participants
  who had no involvement in the original chain.

- **Emission-earned going forward.** Beyond the genesis allocation, founders
  participate in the same emission, staking, and fee mechanisms as all other
  participants. There is no ongoing preferential treatment.

- **Lock commitments.** Founding allocations are subject to the same staking
  lock tiers available to all participants. Founders are expected to
  demonstrate conviction through the long lock tier (150,000 blocks, ~208
  days) for the majority of their genesis allocation, making the commitment
  public and verifiable on-chain.

- **Transparency over time.** The founding team commits to publishing their
  genesis addresses publicly so that any participant can verify lock status,
  unlock timing, and subsequent on-chain behavior.

### Specific Genesis Allocations

### Specific Genesis Allocations

| Recipient | Amount | Notes |
|---|---|---|
| Founder 1 | 20,000 SHEKYL | Equal share |
| Founder 2 | 20,000 SHEKYL | Equal share |
| Founder 3 | 20,000 SHEKYL | Equal share |
| Founder 4 | 20,000 SHEKYL | Equal share |
| Founder 5 | 20,000 SHEKYL | Equal share |
| **Total** | **100,000 SHEKYL** | **0.002329% of total supply** |

All five allocations are identical. There is no tiered or preferential
distribution among founders.

For context: the total genesis allocation represents less than 2.4 thousandths
of one percent of the 2^32 whole SHEKYL supply ceiling. The remaining
99.997671% of all SHEKYL that will ever exist must be earned through
proof-of-work mining under the Four-Component emission model described in
`DESIGN_CONCEPTS.md`.

There is no foundation allocation at genesis. Should the community choose to
establish a Shekyl Foundation in the future, that body would be a community-
governed institution funded voluntarily — whether through founder donations,
community fundraising, or other means decided at that time. No coins are
reserved or earmarked for this purpose at launch.

The specific genesis addresses for each founder will be published in
`docs/GENESIS_ALLOCATIONS.md` at the time of mainnet launch.

---

## 6) The Shekyl Name and the Standard It Implies

The Shekyl project takes its name from the historical shekel — a unit of
weight-based monetary measure whose trustworthiness derived from physical
verifiability, not from the authority of any issuer. Anyone could weigh a
shekel. The standard was in the measure, not in the declaration.

This document is written in that spirit. The original chain data is
preserved and independently verifiable. The parameter misconfiguration is
documented precisely, not elided. The founding team's decision to accept
reduced allocations is stated plainly, not dressed up as generosity.

Shekyl NG's monetary policy — a mathematically defined, open-source
emission curve with no governance override — is the modern equivalent of
that weight standard. The numbers are the policy. Anyone can verify them.

---

## 7) Verifying This Document's Claims

The original chain database (`data.mdb`) is preserved. The statistics in
Section 1 can be independently verified by anyone with access to the file
using standard LMDB tooling:

```bash
# Install LMDB utilities
apt install lmdb-utils python3-lmdb

# Inspect named databases
mdb_stat -a /path/to/shekyl/lmdb

# Verify emission and transaction counts
python3 - <<'EOF'
import lmdb, struct
env = lmdb.open('/path/to/shekyl/lmdb', readonly=True, max_dbs=64, lock=False)
block_info_db = env.open_db(b'block_info', create=False)
tx_indices_db = env.open_db(b'tx_indices', create=False)
with env.begin() as txn:
    cur = txn.cursor(block_info_db)
    cur.last()
    val = cur.value()
    last_coins = struct.unpack_from('<Q', val, 16)[0]
    block_count = struct.unpack_from('<Q', val, 0)[0]
    tx_count = txn.stat(tx_indices_db)['entries']
print(f"Blocks:             {block_count:,}")
print(f"Transactions:       {tx_count:,}")
print(f"Total atomic units: {last_coins:,}")
print(f"Total whole coins:  {last_coins / 1e12:.6f}  (12-decimal basis)")
env.close()
EOF
```

Expected output:
```
Blocks:             168,947
Transactions:       168,981
Total atomic units: 2,745,081,907,831,749,734
Total whole coins:  2745081.907832  (12-decimal basis)
```

The SHA-256 hash of the original `data.mdb` file will be published alongside
the mainnet launch to allow anyone to verify they are working from the same
dataset.

---

## 8) References

- Original chain parameter analysis: `docs/DESIGN_CONCEPTS.md`, Section 2
- Shekyl NG economic design: `docs/DESIGN_CONCEPTS.md`, Sections 3–13
- CryptoNote emission formula: `src/cryptonote_basic/cryptonote_basic_impl.cpp`
- Genesis allocation details: `docs/GENESIS_ALLOCATIONS.md` *(published at mainnet launch)*
- `uint64_t` overflow analysis: `docs/DESIGN_CONCEPTS.md`, Section 2
