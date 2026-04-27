<!--
Copyright (c) 2025-2026, The Shekyl Foundation

All rights reserved.
BSD-3-Clause
-->

# 11 — SWSP `body_len` disagrees with trailing bytes

**Layer:** payload / SWSP (`shekyl-wallet-file::payload`)
**Test:** `swsp_body_len_mismatch_is_refused`
**Expected refusal:** `WalletFileError::Payload(PayloadError::BodyLenMismatch)`

## Construction

1. Build a real SWSP frame via `encode_payload(...)`.
2. Overwrite the `body_len` field in the header with a value larger
   than (or smaller than) the actual number of body bytes remaining
   after the header.
3. Seal as region 2 and open.

## Rationale

`body_len` is the explicit length prefix that prevents the SWSP
decoder from having to read bytes implicitly to EOF. Allowing a
mismatch would reopen two classes of bug:

- **Short `body_len`:** trailing bytes after the declared body
  would be silently discarded, which hides partial writes.
- **Long `body_len`:** the decoder would read past the end of
  region 2 and either panic, hang, or — worst case — interpret
  adjacent AAD / nonce / tag bytes as payload body.

Refusing with a typed `BodyLenMismatch` collapses both into a
single unambiguous error.
