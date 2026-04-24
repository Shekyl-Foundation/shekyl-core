<!--
Copyright (c) 2025-2026, The Shekyl Foundation

All rights reserved.
BSD-3-Clause
-->

# 08 — `.wallet` swapped from another wallet pair

**Layer:** envelope (cross-file AAD binding)
**Test:** `state_file_swapped_from_another_wallet_is_refused`
**Expected refusal:** `WalletFileError::Envelope(WalletEnvelopeError::StateSeedBlockMismatch)`

## Construction

1. Create two wallet pairs A and B (same password, independent
   entropy).
2. Overwrite A's `.wallet` with B's `.wallet`.
3. Open wallet A.

## Rationale

Both halves of a wallet pair are bound by the last 16 bytes of the
`.wallet.keys` region-1 Poly1305 tag, which is fed as AAD into the
`.wallet` region-2 AEAD. Swapping just the `.wallet` file breaks
the binding and the AEAD fails under the *correct* `file_kek`.
This is the only case that `StateSeedBlockMismatch` was originally
defined for; the envelope also reuses the variant for attack 07
(see `07-state-region2-bit-flip.md`).

This attack is the one that justifies the anti-swap AAD in the
first place: without it, a compromised storage layer could swap
state files between wallets sharing the same password and the
swap would decrypt cleanly into the wrong wallet's state.
