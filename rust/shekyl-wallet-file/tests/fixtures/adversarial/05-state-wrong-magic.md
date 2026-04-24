<!--
Copyright (c) 2025-2026, The Shekyl Foundation

All rights reserved.
BSD-3-Clause
-->

# 05 — `.wallet` with wrong magic

**Layer:** envelope (`shekyl-crypto-pq::wallet_envelope`)
**Test:** `state_file_wrong_magic_is_refused`
**Expected refusal:** `WalletFileError::Envelope(WalletEnvelopeError::UnknownMagic)`

## Construction

1. Create a valid wallet pair.
2. Overwrite byte `0` of `.wallet` with `0x00`, corrupting the
   7-byte magic `SHKW1\0S`.
3. Open.

## Rationale

The `.wallet` magic is deliberately distinct from `.wallet.keys`
(trailing byte `'S'` vs `'K'`) so that swapping the two files is
caught by magic check alone, without consulting the cross-file
`seed_block_tag` AAD. Keeping this gate typed means a cross-wire
operator mistake (e.g. passing the wrong path into `open`) surfaces
as a precise error instead of falling through to a confusing AEAD
failure.
