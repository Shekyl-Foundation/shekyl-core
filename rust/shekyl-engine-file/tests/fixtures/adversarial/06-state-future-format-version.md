<!--
Copyright (c) 2025-2026, The Shekyl Foundation

All rights reserved.
BSD-3-Clause
-->

# 06 — `.wallet` with a future `state_version`

**Layer:** envelope (`shekyl-crypto-pq::wallet_envelope`)
**Test:** `state_file_future_format_version_is_refused`
**Expected refusal:** `WalletFileError::Envelope(WalletEnvelopeError::FormatVersionTooNew { got: 0xFF, max: STATE_FILE_FORMAT_VERSION })`

## Construction

1. Create a valid wallet pair.
2. Overwrite byte `8` (`state_version`) of `.wallet` with `0xFF`.
3. Open.

## Rationale

Mirrors attack 03 on the state-file side. The `.wallet` file carries
its own format version independent of the keys file — they
advance on different cadences — so this gate has its own constant
(`STATE_FILE_FORMAT_VERSION`) and its own refusal. A future-format
`.wallet` opened by an older binary must be rejected *before* AAD
assembly so the error is useful ("your state file is newer than
this binary supports") rather than a generic AEAD refusal.
