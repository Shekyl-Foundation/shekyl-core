<!--
Copyright (c) 2025-2026, The Shekyl Foundation

All rights reserved.
BSD-3-Clause
-->

# 09 — SWSP frame with wrong magic inside region 2 plaintext

**Layer:** payload / SWSP (`shekyl-wallet-file::payload`)
**Test:** `swsp_bad_magic_in_region2_is_refused`
**Expected refusal:** `WalletFileError::Payload(PayloadError::BadMagic)`

## Construction

1. Assemble a synthetic region-2 plaintext whose first 4 bytes are
   *not* `SWSP` (e.g. `XXXX`) but which is otherwise a plausible
   SWSP-like frame.
2. Seal that plaintext into a fresh `.wallet` via
   `shekyl_crypto_pq::wallet_envelope::seal_state_file` against a
   freshly-generated companion `.wallet.keys`.
3. Open.

## Rationale

The SWSP magic is the first thing the payload layer reads once the
envelope has decrypted region 2. Without it, the payload decoder
would fall through to speculative parsing of the bytes it was
handed — a recipe for confusing decode errors further down the
stack. The magic is a 4-byte framing gate, not a security gate
(the envelope has already authenticated the bytes), but a typed
refusal here keeps the error chain meaningful.
