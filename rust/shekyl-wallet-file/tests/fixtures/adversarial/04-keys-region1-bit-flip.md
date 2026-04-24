<!--
Copyright (c) 2025-2026, The Shekyl Foundation

All rights reserved.
BSD-3-Clause
-->

# 04 — `.wallet.keys` with a single-bit flip inside region 1 ciphertext

**Layer:** envelope (`shekyl-crypto-pq::wallet_envelope`)
**Test:** `keys_file_region1_bit_flip_is_refused`
**Expected refusal:** `WalletFileError::Envelope(WalletEnvelopeError::InvalidPasswordOrCorrupt)`

## Construction

1. Create a valid wallet pair.
2. XOR `0x01` into a byte inside `region1_ct` (past the 24-byte
   `region1_nonce` at offset `126`, and before the trailing
   16-byte Poly1305 tag).
3. Open.

## Rationale

`InvalidPasswordOrCorrupt` is a *deliberately coarse* error. The
opener cannot distinguish a wrong password (derives the wrong
`file_kek`, Poly1305 rejects) from a correct password against a
tampered ciphertext (right `file_kek`, Poly1305 rejects). Both map
to the same refusal by design so that neither path can be used as
an oracle against the password guess. The corpus pins that mapping:
any future change that splits the two cases would leak strictly
more than the current build does and must be argued for explicitly
in review.
