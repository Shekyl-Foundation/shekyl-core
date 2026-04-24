<!--
Copyright (c) 2025-2026, The Shekyl Foundation

All rights reserved.
BSD-3-Clause
-->

# 14 — Truncated postcard body inside a valid SWSP frame

**Layer:** wallet-ledger (`shekyl-wallet-state::wallet_ledger`)
**Test:** `ledger_postcard_truncated_is_refused`
**Expected refusal:** `WalletFileError::Ledger(WalletLedgerError::Postcard)`

## Construction

1. Build a real `WalletLedger`.
2. Serialize to postcard, truncate the last few bytes of the
   serialized buffer.
3. Wrap the (now short) postcard buffer in a valid SWSP frame
   whose `body_len` matches the truncated length (so the SWSP
   gate passes — we want the ledger layer to be the one that
   refuses).
4. Seal and open.

## Rationale

This is the ledger's deserialization gate. The SWSP frame only
carries length, not structure; the postcard parse is where
structural mismatch is detected. Truncation on a serde_postcard
stream must surface as `WalletLedgerError::Postcard` rather than
being absorbed into an earlier layer.

Note that the SWSP layer is *not* responsible for noticing the
truncation — by construction, the `body_len` in the frame matches
the short buffer. The layering works because:

- The envelope authenticated the region-2 bytes.
- The SWSP decoder accepted the frame (the length is internally
  consistent).
- The postcard decoder rejected the body (structure is broken).

Each layer refuses only what it is responsible for.
