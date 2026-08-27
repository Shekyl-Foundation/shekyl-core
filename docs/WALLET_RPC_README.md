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
WI-RPC-2a (`restore_wallet`), WI-RPC-3 (proofs), Phase 4c
(`rescan_blockchain` via `Engine::start_rescan`), WI-RPC-4
(`get_wallet_info` + `Transfer.attribution` / `get_transfers.attribution`
filter), PR-SM-2 (`sign_message` / `verify_message`), PR-SJ-3
(`abandon_tx`), SJ-DQ-7 (`get_tx_note` / `set_tx_note`), and WI-RPC-5
(archival principal staking actions: `stake_in`, `get_drain_balance`,
`drain`; `get_balance.staked` / `claimable_rewards` are live projections,
no longer hardcoded zeros — and structurally absent, never `"0"`, when
the staking seal is unreadable, with `get_wallet_info.staking` degrading
alongside while the liquid fields stay served) are live. `stake_in`
builds under a read lock like `build_pending_tx` (one funding build never
stalls the read RPCs), and `get_drain_balance` reports the active
persona's own drainable pool — the set a `drain` can actually spend.

RESERVED methods remain Engine-gated: `unstake` and
`match_transfer_to_request` (the latter gated on an Engine match
method). `unstake` is no longer gated on a *missing producer* — PR-P4
built the `Unbond` producer. Remaining gates: reachability (no RPC/CLI
until the regtest walk), dispatch of the assembled bytes, and native
`/submit_transaction` still refusing Unbond (`BondPostKind::Other`)
until the Unbond submit fact set lands. The claim-era names `claim`
and `get_stakes` are REJECTED, not pending (emission claims are
engine-side; `principal_stakes()` is RPC-forbidden as the P↔principal
edge). See the OpenAPI header registry and `docs/FOLLOWUPS.md`.

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

One WI-RPC-5 caveat, disclosed rather than hidden: `drain` dispatches a
sealed drain, but the confirmation/prune driver that settles it is still
a named FOLLOWUPS item (WI-3 sibling) — the receipt is a dispatch fact,
not a settlement fact. See `docs/FOLLOWUPS.md`, and
`docs/design/WALLET_SEND_RECORD.md` for the send-journal design round.
