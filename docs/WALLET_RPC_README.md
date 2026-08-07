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

Honest `OUTGOING` transfer history landed with PR-SJ-2 (send-journal
projection), closing the Phase 4b `get_transfers` OUTGOING-filter
FOLLOWUP. `submit_pending_tx` reports the real daemon verdict
(`ACCEPTED` / `ALREADY_IN_POOL` / `ALREADY_IN_CHAIN` with verdict-scoped
`confirmed_height`), closing another.

One Phase 4b quality item stays open by decision rather than by
omission: the build concurrency permit stays at 1, a rule-21 rejection
whose reopening criterion is anonymized segment fetch (raising it emits
a correlated burst of segment fetches an unanonymized segment server can
count). `build_pending_tx` itself no longer stalls read RPCs — it runs
under a read lock, serialized by that engine-owned permit.

Beyond Phase 4b, `abandon_tx` is design-gated to Phase 4d (PR-SJ-3).
See `docs/FOLLOWUPS.md` for both, and `docs/design/WALLET_SEND_RECORD.md`
for the send-journal design round.
