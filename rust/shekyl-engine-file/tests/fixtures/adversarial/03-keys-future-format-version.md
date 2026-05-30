<!--
Copyright (c) 2025-2026, The Shekyl Foundation

All rights reserved.
BSD-3-Clause
-->

# 03 — `.wallet.keys` with a future `file_version`

**Layer:** envelope (`shekyl-crypto-pq::wallet_envelope`)
**Test:** `keys_file_future_format_version_is_refused`
**Expected refusal:** `WalletFileError::Envelope(WalletEnvelopeError::FormatVersionTooNew { got: 0xFF, max: WALLET_FILE_FORMAT_VERSION })`

## Construction

1. Create a valid wallet pair.
2. Overwrite byte `8` (`file_version`) of `.wallet.keys` with `0xFF`.
   Because `file_version` is inside the region-1 AAD, the region-1
   AEAD would also fail — but the version check runs *first*, so
   that failure is never reached.
3. Open.

## Rationale

The version gate exists so that a downgraded binary cannot silently
open a file written by a newer format. Surfacing the version
explicitly in the error payload (`got` + `max`) lets the UX tell the
user "install a newer build" rather than the generic "wrong
password." The check must precede AAD assembly; otherwise a future
format would be indistinguishable from a wrong password at the
failure site.
