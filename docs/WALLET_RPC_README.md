# Shekyl wallet RPC (`shekyl-wallet-rpc`)

Operator-facing entry point for the Shekyl-native wallet JSON-RPC server
(Phase 4 of `docs/design/WALLET_REWRITE_PLAN.md`).

## Contract

**[`docs/api/wallet_rpc.yaml`](api/wallet_rpc.yaml) is the contract.**
Method names, request/response shapes, and error codes live there. The
binary conforms to the OpenAPI spec; the reverse is never true.

Transport: JSON-RPC 2.0 over HTTP (basic auth) or a Unix domain socket
(filesystem-permission auth — preferred for local tooling and the CLI's
in-process spawn).

## Running

See [`EXECUTABLES.md`](EXECUTABLES.md) §3 for binary flags, wallet-dir
layout, and daemon connectivity. Ports / nets match `shekyld`
conventions (mainnet / testnet / stagenet).

## Shape vs Monero

Shekyl-native only — no Monero `wallet-rpc` compatibility. Amounts are
atomic `u64` decimal strings; send is `build_pending_tx` →
`submit_pending_tx` / `discard_pending_tx`; receiving uses payment
requests + URIs (no subaddresses).

## Status

Phase 4b SPECIFIED methods, WI-RPC-1 (receiving / fees / staking reads),
WI-RPC-2a (`restore_wallet`), WI-RPC-3 (proofs), and Phase 4c
(`rescan_blockchain` via `Engine::start_rescan`) are live. RESERVED
methods (`unstake` / `claim` / `sign` / `verify` / air-gapped bundles)
remain Engine-gated — see the OpenAPI header registry and
`docs/FOLLOWUPS.md`.

One Phase 4b quality FOLLOWUP remains design-gated: `abandon_tx`
(PR-SJ-3). Honest `OUTGOING` transfer history landed with PR-SJ-2
(send-journal projection). The other two quality items closed earlier:
`build_pending_tx` runs under a read lock (serialized by the
engine-owned build permit), and `submit_pending_tx` reports the real
daemon verdict (`ACCEPTED` / `ALREADY_IN_POOL` / `ALREADY_IN_CHAIN` with
verdict-scoped `confirmed_height`).
