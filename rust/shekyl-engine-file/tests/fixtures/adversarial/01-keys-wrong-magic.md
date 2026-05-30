<!--
Copyright (c) 2025-2026, The Shekyl Foundation

All rights reserved.
BSD-3-Clause
-->

# 01 — `.wallet.keys` with wrong magic

**Layer:** envelope (`shekyl-crypto-pq::wallet_envelope`)
**Test:** `keys_file_wrong_magic_is_refused`
**Expected refusal:** `WalletFileError::Envelope(WalletEnvelopeError::UnknownMagic)`

## Construction

1. Call `WalletFile::create(...)` on a temp path, producing a
   valid `.wallet.keys` + `.wallet` pair.
2. Overwrite byte `0` of `.wallet.keys` with `0x00`, corrupting the
   7-byte magic `SHKW1\0K`.
3. Call `WalletFile::open(...)`.

## Rationale

The magic is the very first gate the envelope consults — before any
KDF work, AAD assembly, or AEAD call. Misclassifying a random 7-byte
prefix as a malformed-ciphertext error (or, worse, allowing the
opener to proceed) would turn the magic check into an oracle. The
refusal must be unambiguous and come *before* any keyed work.
