# Shekyl v3 Rollout (HF1)

> **Last updated:** 2026-03-31

## Scope

This note is for operators and wallet integrators rolling out `TransactionV3`
on Shekyl NG.

## Activation

- Consensus gate: `HF_VERSION_SHEKYL_NG = 1` (active from genesis)
- From genesis:
  - All user (non-coinbase) transactions must be version `3`
  - Coinbase (miner) transactions remain version `2`
  - `pqc_auth` (hybrid Ed25519 + ML-DSA-65) verification is mandatory for
    non-coinbase v3 txs
  - Minimum transaction version is enforced: `min_tx_version = 3` for
    non-coinbase transactions
- Coinbase txs remain outside `pqc_auth` requirements

## v3-First Test Strategy

The `core_tests` suite has been fully adapted for v3-from-genesis:

- All transaction construction helpers (`construct_tx_to_key`,
  `construct_tx_rct`) produce v3 transactions with PQC authentication
- Test framework amount checks use RCT-aware decryption (ecdhInfo)
- Hard fork version is set to 1 for all test block construction
- Fixed difficulty (`--fixed-difficulty=1`) is injected for FAKECHAIN tests
- Mixin requirements are relaxed for FAKECHAIN to support test ring sizes
- Coinbase outputs are correctly indexed under amount=0 for RCT spending
- The following legacy/incompatible tests were disabled:
  - `gen_block_invalid_nonce` (incompatible with fixed-difficulty)
  - `gen_block_invalid_binary_format` (requires hours with unlock window=60)
  - `gen_block_late_v1_coinbase_tx` (no late-v1 era in Shekyl)
  - `gen_ring_signature_big` (prohibitively slow)
  - `gen_uint_overflow_1` (relies on pre-RCT economics)
  - `gen_block_reward` (hardcoded Monero emission curve)
  - `gen_bpp_tx_invalid_before_fork` / `gen_bpp_tx_invalid_clsag_type`
    (test pre-fork rejection which doesn't apply at HF1)

## Transaction Size Impact

Measured canonical component sizes (phase 1):

- `HybridPublicKey`: `1996` bytes
- `HybridSignature`: `3385` bytes
- `pqc_auth` body contribution (single-signer): `5385` bytes (`4` byte header + key + signature)

### Multisig Size Impact (scheme_id = 2)

Multisig transactions carry N public keys and M signatures. Per-configuration
overhead (see `docs/PQC_MULTISIG.md` for full specification):

| Configuration | Auth overhead | vs single-signer |
|---|---|---|
| 2-of-3 | ~12,769 bytes | +7,384 (~2.4x) |
| 3-of-5 | ~20,153 bytes | +14,768 (~3.7x) |
| 5-of-7 | ~30,921 bytes | +25,536 (~5.7x) |

Multisig usage is expected to be well under 1% of transaction volume.
Aggregate chain growth impact is negligible.

Practical effect:

- larger mempool footprint
- higher relay bandwidth usage
- larger RPC/ZMQ transaction payloads

## Wallet Migration Notes

- Wallets must construct v3 payload first, then sign and attach `pqc_auth`.
- Wallet scanners should continue handling classical tx metadata (`extra`) and
  treat `pqc_auth` as authorization material, not scan metadata.
- Restored wallets should have PQ key material generated and persisted.
- Hardware-wallet PQ support remains deferred; software wallets are the
  supported v3 path for now.
- **Multisig wallets:** V3 multisig (`scheme_id = 2`) requires each
  participant to generate their own hybrid keypair. No DKG protocol is
  needed. The wallet assembles the multisig group from exchanged public keys
  and coordinates M-of-N signing over the shared canonical payload. See
  `docs/PQC_MULTISIG.md` for full specification.
- **Staking with multisig:** Multisig staked outputs and claim transactions
  are supported with `scheme_id = 2`. This is the recommended configuration
  for long-duration (150,000 block) staking positions with significant value.

## Payload Limit Guidance

Operators and indexers must accommodate the increased per-transaction size:

- **Minimum recommended mempool tx limit:** 6 KB above current median user tx
  size (covers the ~5,385 byte `pqc_auth` body plus serialization overhead).
- **Multisig headroom:** multisig transactions (`scheme_id = 2`) can reach
  ~31 KB of `pqc_auth` overhead for 5-of-7 configurations. While rare,
  operators should not reject transactions solely based on pre-PQC size
  assumptions.
- **ZMQ/RPC consumers:** adjust any hardcoded maximum payload buffers to at
  least 150 KB per transaction (typical 2-input/2-output tx + PQC auth).
  For multisig, budget up to 200 KB.
- **Levin relay:** the existing 100 MB default message limit is sufficient, but
  per-message transaction count assumptions should be revisited if batching
  relay payloads.
- **Monitoring dashboards:** alert thresholds tied to tx size should be
  rebased against post-v3 norms, not pre-PQC averages. Consider separate
  alerting bands for `scheme_id = 1` (single) and `scheme_id = 2` (multisig).

## Node/Infrastructure Checklist

- Ensure all validating nodes run HF1-capable binaries from launch.
- Verify custom RPC clients/indexers accept larger tx payloads.
- Update any tx-size assumptions in monitoring/alerting and mempool dashboards.
- Confirm seed/boot nodes are upgraded first to avoid propagation asymmetry.
- Verify that transaction validation correctly handles both `scheme_id = 1`
  (single-signer) and `scheme_id = 2` (multisig signature list).
- Test multisig transaction relay and mempool acceptance at realistic sizes
  (2-of-3 through 5-of-7 configurations).
