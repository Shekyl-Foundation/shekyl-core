<!--
Copyright (c) 2025-2026, The Shekyl Foundation

All rights reserved.
BSD-3-Clause
-->

# 15 — Ledger violates `INV_TX_KEYS_NO_ORPHANS`

**Layer:** wallet-ledger / invariants
(`shekyl-wallet-state::invariants`)
**Test:** `ledger_invariant_orphan_tx_key_is_refused`
**Expected refusal:** `WalletFileError::Ledger(WalletLedgerError::InvariantFailed)`

## Construction

1. Build a `WalletLedger` whose per-block version gates and
   postcard shape are all valid, but whose aggregate state
   violates `INV_TX_KEYS_NO_ORPHANS`: a `TxMetaBlock.tx_keys`
   entry keyed by a transaction hash that does **not** appear in
   any `scanned_pool_txs` map or any on-chain transfer record.
2. Serialize to postcard, wrap in SWSP, seal as region 2.
3. Open.

## Rationale

Orphan `tx_keys` are the canonical cross-block invariant
violation: each layer in isolation validates (the block versions
are all current, the postcard decodes, the SWSP frame is
well-formed), but the *aggregate* is inconsistent. The only
layer with enough context to see it is
`WalletLedger::check_invariants`, which is the gate added in
commit 3.6 of the hardening pass.

This test is the one that justifies the invariant gate: without
it, an attacker (or a bug) that injects orphan key entries could
silently poison the scanner's lookup tables with keys that refer
to nonexistent transactions. Refusing at open time turns a
silent data-integrity bug into a typed refusal.
