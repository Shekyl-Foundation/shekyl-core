# Shekyl NG Genesis Strategy

## Overview

Shekyl NG uses a snapshot-based genesis approach to honor early miners from the
2018-2019 chain while rebasing on a modern Monero v0.18.4.5 codebase.

## Approach

### Phase 1: Snapshot Collection (Pre-Fork)

1. Identify the last valid block from the original Shekyl chain (2018-2019 era).
2. Extract the full UTXO set at that block height.
3. Compute a Merkle root commitment over all unspent outputs.
4. Publish the UTXO snapshot hash for community verification.

### Phase 2: New Genesis Block

The NG genesis block embeds:
- A standard coinbase transaction (no block reward -- this is genesis).
- The UTXO snapshot Merkle root in the tx_extra field.
- A unique genesis nonce (already configured: 10000).
- The Shekyl network ID to prevent cross-chain contamination.

### Phase 3: Balance Restoration

At chain launch, a special "airdrop" mechanism in the first N blocks creates
outputs matching the snapshot UTXO set. This uses a deterministic process:
- Each original UTXO maps to a new output with the same one-time address.
- Original key holders can spend these outputs with their existing keys.
- No new keys are needed -- backward compatibility preserved.

### Phase 4: Hard Fork Activation

- Block height 0: New genesis block with snapshot commitment.
- Block height 1+: New consensus rules (RandomX PoW, modern Monero features).
- All post-genesis blocks use v2.0 transaction format with hybrid PQ signatures
  (once the PQ crypto module is complete).

## Testnet Strategy

For development, the testnet uses:
- A fresh genesis (no snapshot needed).
- The existing testnet config (ports 12021/12029/12025).
- Accelerated difficulty adjustment for faster block times during testing.

## Emission Economics (TODO)

The original Shekyl MONEY_SUPPLY was set to 2^32 (4,294,967,296) but this value
is in atomic units with 12 decimal places, resulting in a total supply of only
~0.004 coins. This needs redesign before mainnet:

Options:
- Reduce decimal places (e.g., 8 like Bitcoin) so 2^32 coins fit in uint64.
- Choose a different total supply that fits 12 decimal places.
- Redesign emission curve parameters (speed factor, final subsidy).

Currently using Monero's default supply (uint64 max) for testnet development.

## Timeline

1. Stand up testnet with fresh genesis -- DONE.
2. Locate and extract original Shekyl UTXO set -- requires chain data.
3. Design final emission economics -- before mainnet.
4. Implement snapshot restoration logic -- Phase 2 development.
5. Mainnet launch with snapshot genesis -- after full testing.
