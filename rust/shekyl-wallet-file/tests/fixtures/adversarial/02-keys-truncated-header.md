<!--
Copyright (c) 2025-2026, The Shekyl Foundation

All rights reserved.
BSD-3-Clause
-->

# 02 — `.wallet.keys` truncated below the AAD header

**Layer:** envelope (`shekyl-crypto-pq::wallet_envelope`)
**Test:** `keys_file_truncated_header_is_refused`
**Expected refusal:** `WalletFileError::Envelope(WalletEnvelopeError::FileTooShort)`

## Construction

1. Create a valid wallet pair.
2. Truncate `.wallet.keys` to a length short enough that the fixed
   AAD-prefix region cannot even be read — in practice, the first
   16 bytes.
3. Open.

## Rationale

The envelope reads the magic, `file_version`, the KDF-params block,
and the `region1_nonce` before any AEAD work. A truncated header
short-circuits into `FileTooShort` rather than a downstream
`InvalidPasswordOrCorrupt`, so the UX can tell "the file is empty /
truncated" apart from "the password is wrong." Misclassifying this
case as an AEAD failure is a usability regression, not a security
one, but the distinction is worth keeping typed.
