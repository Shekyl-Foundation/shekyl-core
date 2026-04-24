<!--
Copyright (c) 2025-2026, The Shekyl Foundation

All rights reserved.
BSD-3-Clause
-->

# 13 — Per-block `block_version` bumped to an unknown value

**Layer:** wallet-ledger (`shekyl-wallet-state::wallet_ledger`)
**Test:** `ledger_block_version_bump_is_refused`
**Expected refusal:** `WalletFileError::Ledger(WalletLedgerError::UnsupportedBlockVersion)`

## Construction

1. Build a real `WalletLedger`.
2. Serialize to postcard, locate a specific inner block's
   `block_version` byte (one of `LEDGER_BLOCK_VERSION`,
   `BOOKKEEPING_BLOCK_VERSION`, `TX_META_BLOCK_VERSION`, or
   `SYNC_STATE_BLOCK_VERSION`), and rewrite it to an unsupported
   value.
3. Wrap in SWSP and seal as region 2.
4. Open.

## Rationale

Each ledger block (`LedgerBlock`, `BookkeepingBlock`,
`TxMetaBlock`, `SyncStateBlock`) carries its own version number
independently of the bundle `format_version`, so that individual
blocks can evolve without forcing a full bundle-format bump. This
attack verifies that the per-block gate is actually reached — not
shadowed by the bundle gate — and that the refusal is typed
separately.
