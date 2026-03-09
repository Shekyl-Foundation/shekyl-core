# Shekyl NG Genesis Strategy

## Overview

Shekyl NG uses a new-genesis reboot approach while retaining the option to honor
early miners from the 2018-2019 chain through a snapshot-derived allocation.

Important distinction:

- economic/accounting continuity may be preserved through snapshot data
- runtime consensus and transaction validation do not need legacy-chain
  backward compatibility on the rebooted network

## Approach

### Phase 1: Optional Snapshot Collection

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

### Phase 3: Optional Balance Restoration

If snapshot honoring is retained for mainnet, a special allocation mechanism in
the first N blocks can create outputs matching the agreed snapshot set. This is
an accounting migration, not a requirement to preserve legacy transaction rules.

Possible approaches:

- deterministic outputs derived from the snapshot set
- claim-based restoration using agreed proofs/keys
- a governance-decided partial allocation honoring only specific balances

Final mechanism remains to be chosen before mainnet.

### Phase 4: Reboot Activation

- Block height 0: New genesis block with snapshot commitment.
- Block height 1+: New consensus rules (RandomX PoW, modern CryptoNote/Shekyl features).
- PoW execution is modularized behind a schema interface so future proof modules
  can be added without changing core validation call sites.
- All user transactions on the rebooted chain use the new PQ-enabled
  transaction format (TransactionV3) defined in `docs/POST_QUANTUM_CRYPTOGRAPHY.md`.
- Legacy transaction coexistence is not required on the rebooted runtime.

## Testnet Strategy

For development, the testnet uses:
- A fresh genesis (no snapshot needed).
- The existing testnet config (ports 12021/12029/12025).
- Accelerated difficulty adjustment for faster block times during testing.
- The reboot-only transaction model and PQC work can be developed here without
  carrying legacy transaction compatibility logic.

## Emission Economics (TODO)

The original Shekyl MONEY_SUPPLY was set to 2^32 (4,294,967,296) but this value
is in atomic units with 12 decimal places, resulting in a total supply of only
~0.004 coins. This needs redesign before mainnet:

Options:
- Reduce decimal places (e.g., 8 like Bitcoin) so 2^32 coins fit in uint64.
- Choose a different total supply that fits 12 decimal places.
- Redesign emission curve parameters (speed factor, final subsidy).

Currently using the same default supply as upstream (uint64 max) for testnet development.

## Timeline

1. Stand up testnet with fresh genesis -- DONE.
2. Finalize reboot-only transaction and PQC specification.
3. Decide whether snapshot honoring remains part of mainnet launch.
4. Design final emission economics -- before mainnet.
5. If retained, implement snapshot restoration/allocation logic.
6. Mainnet launch with new genesis -- after full testing.
