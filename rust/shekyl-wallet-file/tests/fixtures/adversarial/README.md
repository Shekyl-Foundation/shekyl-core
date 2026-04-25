<!--
Copyright (c) 2025-2026, The Shekyl Foundation

All rights reserved.
BSD-3-Clause
-->

# Adversarial wallet-file corpus

This directory documents the adversarial corpus exercised by
`rust/shekyl-wallet-file/tests/adversarial_corpus.rs`. Each attack row
below is reproduced in-process by the matching test function; the
`.md` files in this directory narrate the *shape* of the malformed
input and the exact typed refusal the orchestrator must surface.

The corpus is **programmatic, not binary.** The wallet envelope seals
every region with fresh Argon2id entropy and a fresh region-2 nonce,
so pinning byte-for-byte ciphertexts would require a deterministic-seal
escape hatch in `shekyl-crypto-pq` that exists only for this test.
Instead every test:

1. Calls `WalletFile::create(...)` to produce a real,
   properly-sealed pair of files on disk.
2. Performs narrow byte-level surgery on one of those files, or
   re-seals region 2 against a synthetic plaintext through the public
   `shekyl_crypto_pq::wallet_envelope::seal_state_file` helper.
3. Calls `WalletFile::open(...)` and matches the returned
   `WalletFileError` against the expected variant.

This keeps the corpus robust to future format-field renames and AEAD
parameter changes — the *shape* of each attack is encoded in code
that is re-typed against the current format on every compile, not
buried in a hex blob that silently drifts out of date.

## Attack matrix

Every row is enforced by a named `#[test]` in `adversarial_corpus.rs`
and described narratively in a `.md` file below.

| # | Attack | Target layer | Expected refusal | Test |
|---|--------|--------------|------------------|------|
| 1 | Wrong magic in `.wallet.keys` | envelope / `.wallet.keys` | `Envelope(UnknownMagic)` | `keys_file_wrong_magic_is_refused` |
| 2 | Truncated `.wallet.keys` header (< AAD bytes) | envelope / `.wallet.keys` | `Envelope(FileTooShort)` | `keys_file_truncated_header_is_refused` |
| 3 | `file_version = 0xFF` in `.wallet.keys` | envelope / `.wallet.keys` | `Envelope(FormatVersionTooNew)` | `keys_file_future_format_version_is_refused` |
| 4 | Single-bit flip inside region 1 ciphertext | envelope / `.wallet.keys` | `Envelope(InvalidPasswordOrCorrupt)` | `keys_file_region1_bit_flip_is_refused` |
| 5 | Wrong magic in `.wallet` | envelope / `.wallet` | `Envelope(UnknownMagic)` | `state_file_wrong_magic_is_refused` |
| 6 | `state_version = 0xFF` in `.wallet` | envelope / `.wallet` | `Envelope(FormatVersionTooNew)` | `state_file_future_format_version_is_refused` |
| 7 | Single-bit flip inside region 2 ciphertext | envelope / `.wallet` | `Envelope(StateSeedBlockMismatch)` * | `state_file_region2_bit_flip_is_refused` |
| 8 | Swap `.wallet` from another wallet pair | envelope / cross-file AAD | `Envelope(StateSeedBlockMismatch)` | `state_file_swapped_from_another_wallet_is_refused` |
| 9 | SWSP magic wrong inside region 2 plaintext | payload (SWSP) | `Payload(BadMagic)` | `swsp_bad_magic_in_region2_is_refused` |
| 10 | SWSP `payload_version = 0xFF` | payload (SWSP) | `Payload(UnsupportedPayloadVersion)` | `swsp_future_payload_version_is_refused` |
| 11 | SWSP `body_len` disagrees with trailing bytes | payload (SWSP) | `Payload(BodyLenMismatch)` | `swsp_body_len_mismatch_is_refused` |
| 12 | Bundle `format_version` bumped to an unknown value | wallet-ledger | `Ledger(UnsupportedFormatVersion)` | `ledger_format_version_bump_is_refused` |
| 13 | Per-block `block_version` bumped to an unknown value | wallet-ledger | `Ledger(UnsupportedBlockVersion)` | `ledger_block_version_bump_is_refused` |
| 14 | Truncated postcard body inside a valid SWSP frame | wallet-ledger | `Ledger(Postcard)` | `ledger_postcard_truncated_is_refused` |
| 15 | Valid-per-block bundle that violates `INV_TX_KEYS_NO_ORPHANS` | wallet-ledger / invariants | `Ledger(InvariantFailed)` | `ledger_invariant_orphan_tx_key_is_refused` |
| 16 | Capability-shape mismatch (mode ↔ `cap_content` length) | envelope / region 1 | `Envelope(CapContentLenMismatch)` ** | `capability_payload_mismatch_is_covered_by_envelope_tests` |

\* The envelope deliberately collapses two observationally identical
failure modes — a region-2 ciphertext mutation and a seed-block-tag
mismatch — into the same refusal. Rationale is in the test's doc
comment and in `docs/WALLET_FILE_FORMAT_V1.md` §2.5.

\*\* Plan rows B and C are covered by the existing envelope-level
`CapContentLenMismatch` check rather than a new
`CapabilityPayloadMismatch` variant. The `.md` file for this row
explains why no new error variant was added.

## Layer separation

The rows above are grouped by the layer that *first* refuses the
input:

1. **Envelope** (`shekyl-crypto-pq::wallet_envelope`) — magic,
   version, AEAD tag, and the `(mode, cap_content_len)` shape
   check. Rows 1–8, 16.
2. **Payload / SWSP** (`shekyl-wallet-file::payload`) — frame magic,
   `payload_version`, declared `body_len`. Rows 9–11.
3. **Wallet ledger** (`shekyl-wallet-state::wallet_ledger` +
   `invariants`) — bundle `format_version`, per-block
   `block_version`, postcard decode, cross-block invariant gate.
   Rows 12–15.

The orchestrator (`shekyl-wallet-file::handle`) must preserve this
layering end-to-end: a refusal that originates at the envelope layer
must surface as `WalletFileError::Envelope`, a SWSP refusal as
`WalletFileError::Payload`, and a ledger refusal as
`WalletFileError::Ledger`. The corpus exercises that wiring directly.

## Extending the corpus

When adding a new attack:

1. Add a `#[test]` to `adversarial_corpus.rs` that constructs the
   input programmatically and matches the expected `WalletFileError`
   variant.
2. Add a row to the table above.
3. Drop a short `.md` file in this directory describing the shape of
   the attack, the layer that refuses it, and any non-obvious
   rationale (especially if the refusal collapses with another
   variant, as in row 7).
4. If the attack targets a new error variant, update
   `docs/WALLET_FILE_FORMAT_V1.md` §5 (error taxonomy) in the same
   commit so the on-disk contract and the corpus stay in lockstep.
