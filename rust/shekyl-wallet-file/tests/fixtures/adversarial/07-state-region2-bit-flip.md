<!--
Copyright (c) 2025-2026, The Shekyl Foundation

All rights reserved.
BSD-3-Clause
-->

# 07 — `.wallet` with a single-bit flip inside region 2 ciphertext

**Layer:** envelope (`shekyl-crypto-pq::wallet_envelope`)
**Test:** `state_file_region2_bit_flip_is_refused`
**Expected refusal:** `WalletFileError::Envelope(WalletEnvelopeError::StateSeedBlockMismatch)`

## Construction

1. Create a valid wallet pair.
2. XOR `0x01` into a byte inside `region2_ct` (past the 24-byte
   `region2_nonce` at offset `33`, and before the trailing 16-byte
   Poly1305 tag).
3. Open.

## Rationale

A natural reading would expect `InvalidPasswordOrCorrupt` here. The
envelope deliberately maps this case to `StateSeedBlockMismatch`
instead: at the failure site, the opener has already verified
region 1 against `file_kek`, so the only remaining causes of a
region-2 AEAD failure are a tampered `region2_ct` or a
`seed_block_tag` that does not match the `.wallet.keys` companion.
Both collapse into the same refusal because the opener cannot tell
them apart without running the full region-2 verification twice
against two different AADs. The trade-off is:

- **Gained:** a single, stable error that works the same whether
  the file was corrupted on disk or swapped from another wallet.
- **Lost:** fine-grained telemetry for bit rot vs. file swap.

If this mapping is ever split, this test must be updated in the
same commit and the rationale in `docs/WALLET_FILE_FORMAT_V1.md`
§5 updated to match.
