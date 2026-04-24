<!--
Copyright (c) 2025-2026, The Shekyl Foundation

All rights reserved.
BSD-3-Clause
-->

# 12 — `WalletLedger.format_version` bumped to an unknown value

**Layer:** wallet-ledger (`shekyl-wallet-state::wallet_ledger`)
**Test:** `ledger_format_version_bump_is_refused`
**Expected refusal:** `WalletFileError::Ledger(WalletLedgerError::UnsupportedFormatVersion)`

## Construction

1. Build a real `WalletLedger` in memory.
2. Serialize to postcard, then locate and rewrite the leading
   `format_version` byte to a value greater than
   `WALLET_LEDGER_FORMAT_VERSION`.
3. Wrap in a valid SWSP frame and seal as region 2.
4. Open.

## Rationale

This is the ledger layer's version gate — distinct from (and
nested below) the SWSP `payload_version` and the envelope
`state_version`. The three versions advance independently:

- `state_version`: the on-disk file layout / AEAD framing.
- `payload_version`: the SWSP frame kind/header shape.
- `WalletLedger.format_version`: the postcard-serialized ledger
  bundle shape.

Refusing an unknown bundle version forces a human decision at
upgrade time instead of trying (and silently failing) to decode
the bundle with the wrong schema.
