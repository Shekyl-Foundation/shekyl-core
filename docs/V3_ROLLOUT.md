# Shekyl v3 Rollout (HF17)

## Scope

This note is for operators and wallet integrators rolling out `TransactionV3`
on Shekyl NG.

## Activation

- Consensus gate: `HF_VERSION_SHEKYL_NG = 17`
- At/after HF17:
  - user tx max version: `3`
  - `pqc_auth` verification is required for non-coinbase v3 txs
- Coinbase txs remain outside `pqc_auth` requirements

## Transaction Size Impact

Measured canonical component sizes (phase 1):

- `HybridPublicKey`: `1996` bytes
- `HybridSignature`: `3385` bytes
- `pqc_auth` body contribution: `5385` bytes (`4` byte header + key + signature)

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

## Payload Limit Guidance

Operators and indexers must accommodate the increased per-transaction size:

- **Minimum recommended mempool tx limit:** 6 KB above current median user tx
  size (covers the ~5,385 byte `pqc_auth` body plus serialization overhead).
- **ZMQ/RPC consumers:** adjust any hardcoded maximum payload buffers to at
  least 150 KB per transaction (typical 2-input/2-output tx + PQC auth).
- **Levin relay:** the existing 100 MB default message limit is sufficient, but
  per-message transaction count assumptions should be revisited if batching
  relay payloads.
- **Monitoring dashboards:** alert thresholds tied to tx size should be
  rebased against post-v3 norms, not pre-PQC averages.

## Node/Infrastructure Checklist

- Ensure all validating nodes run HF17-capable binaries before activation.
- Verify custom RPC clients/indexers accept larger tx payloads.
- Update any tx-size assumptions in monitoring/alerting and mempool dashboards.
- Confirm seed/boot nodes are upgraded first to avoid propagation asymmetry.
