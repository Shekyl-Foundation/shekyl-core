# Shekyl v3 Rollout (HF1)

> **Last updated:** 2026-04-03

## Scope

This note is for operators and wallet integrators rolling out `TransactionV3`
on Shekyl NG.

## Activation

- Consensus gate: `HF_VERSION_SHEKYL_NG = 1`
- At/after HF1:
  - user tx max version: `3`
  - `pqc_auth` verification is required for non-coinbase v3 txs
- Coinbase txs remain outside `pqc_auth` requirements

## Transaction Size Impact

Measured canonical component sizes:

- `HybridPublicKey`: `1996` bytes
- `HybridSignature`: `3385` bytes
- `pqc_auth` body contribution (single-signer, per input): `5385` bytes (`4` byte header + key + signature)
- FCMP++ membership proof: ~3-4 KB per input
- ML-KEM ciphertext (per output): `1088` bytes (stored in `tx_extra` tag `0x06`)

With per-input `pqc_auths` (`pqc_auths.size() == vin.size()`), a typical
2-in/2-out transaction is approximately **~23 KB** total (per-input pqc_auths
at ~5.4 KB each dominate the size).

Operators can achieve **~95% storage reduction** by running `--prune-blockchain`,
which strips prunable transaction data while retaining headers and recent blocks.

### Multisig Size Impact (scheme_id = 2)

Classical Monero-style multisig (secret-splitting) is removed from the
rebooted chain. All multisig uses PQC-only authorization via `scheme_id = 2`.
See `docs/PQC_MULTISIG.md` for full specification.

Multisig transactions carry N public keys and M signatures. Consensus cap:
`MAX_MULTISIG_PARTICIPANTS = 7`. Per-configuration overhead:

| Configuration | Auth overhead | vs single-signer |
|---|---|---|
| 2-of-3 | ~12,769 bytes | +7,384 (~2.4x) |
| 3-of-5 | ~20,153 bytes | +14,768 (~3.7x) |
| 5-of-7 (typical max) | ~30,921 bytes | +25,536 (~5.7x) |
| 7-of-7 (worst case) | ~37,680 bytes | +32,295 (~7.0x) |

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
- **Classical multisig removed:** Monero-style secret-splitting multisig is
  not carried forward to the rebooted chain. The `make_multisig` code path,
  MMS transport, and classical multisig wallet state are deleted. All
  multisig uses PQC-only authorization (`scheme_id = 2`).
- **Multisig wallets:** Each participant generates their own hybrid keypair.
  The FCMP++ layer uses a single classical key (coordinator-held).
  M-of-N authorization lives in the `pqc_auth` layer. Signing coordination
  uses file-based export/import of payload and signature blobs. See
  `docs/PQC_MULTISIG.md` for full specification.
- **Staking with multisig:** Multisig staked outputs and claim transactions
  are supported with `scheme_id = 2`. This is the recommended configuration
  for long-duration (150,000 block) staking positions with significant value.
  Note: GUI staking integration depends on the Tauri↔wallet2 FFI bridge
  being completed for single-signer staking first.

## Payload Limit Guidance

Operators and indexers must accommodate the increased per-transaction size:

- **Minimum recommended mempool tx limit:** The ~5,385 byte `pqc_auth` figure
  is per-input, not per-transaction. With 2 inputs, that is ~10.8 KB of
  pqc_auth alone, plus ~3-4 KB per input for FCMP++ proofs and ~1 KB per
  output for ML-KEM ciphertexts. Budget at least 25 KB above current median
  user tx size.
- **Multisig headroom:** the consensus cap `MAX_MULTISIG_PARTICIPANTS = 7`
  bounds the worst-case `pqc_auth` overhead to ~37 KB (7-of-7). Typical
  configurations (2-of-3, 3-of-5) are well under this. Operators should not
  reject transactions solely based on pre-PQC size assumptions.
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

- Ensure all validating nodes run HF1-capable binaries before activation.
- Verify custom RPC clients/indexers accept larger tx payloads.
- Update any tx-size assumptions in monitoring/alerting and mempool dashboards.
- Confirm seed/boot nodes are upgraded first to avoid propagation asymmetry.
- Verify that transaction validation correctly handles both `scheme_id = 1`
  (single-signer) and `scheme_id = 2` (multisig signature list).
- Test multisig transaction relay and mempool acceptance at realistic sizes
  (2-of-3 through 5-of-7 configurations).
