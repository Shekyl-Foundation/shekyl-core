# Shekyl Wallet File Format v1

**Status:** in-tree spec (`rust/shekyl-crypto-pq/src/wallet_envelope.rs`
is the normative reference implementation; this document is the narrative
surface).
**Scope:** on-disk layout of `<name>.wallet.keys` + `<name>.wallet`, the
two-file envelope that replaces the Monero-lineage single-file wallet
blob. Covers byte offsets, capability modes, KDF/AEAD choices, and the
operational properties the envelope guarantees.
**Related rules:**
[30-cryptography.mdc](../.cursor/rules/30-cryptography.mdc) ·
[35-secure-memory.mdc](../.cursor/rules/35-secure-memory.mdc) ·
[36-secret-locality.mdc](../.cursor/rules/36-secret-locality.mdc) ·
[40-ffi-discipline.mdc](../.cursor/rules/40-ffi-discipline.mdc).

## 1. Design goals

1. **Split the write surface.** Seed material lives in a file that is
   written exactly twice over the wallet's life: once at creation, and
   again only if the user rotates the wrapping password. Every other
   persistent wallet mutation (refresh progress, transfers cache,
   subaddresses, UI prefs, …) lives in a second file that is overwritten
   on every auto-save. An attacker who has a write window on one file
   therefore cannot corrupt the other; a fsck/backup tool cannot destroy
   seed material while racing with a save; and cold-backup tooling can
   snapshot only `.wallet.keys` when that is all the user needs.

2. **Stance Minimum-Leak.** The AAD of every AEAD carries only what a
   reader needs *before* the password is entered: magic, format version,
   KDF parameters, and the wrap salt. Everything privacy-sensitive (even
   network and capability mode) lives inside a ciphertext. Anyone
   grepping a filesystem sees "this is some Shekyl V3 wallet file"; they
   do not see whether it is mainnet or stagenet, FULL or VIEW_ONLY,
   hardware-offload-bound or not.

3. **Two-level KEK for fast password rotation.** The password stretches
   to a `wrap_key` via Argon2id. `wrap_key` decrypts a random 32-byte
   `file_kek`. `file_kek` in turn encrypts the seed region (region 1) of
   `.wallet.keys` and every save of `.wallet`. Password rotation
   rewrites only the wrap layer of `.wallet.keys`; region 1 ciphertext,
   region 1 Poly1305 tag, and every byte of `.wallet` are
   byte-identical. No re-encryption, no Argon2 against the new password
   on every save.

4. **Anti-swap binding across files.** The Poly1305 tag of region 1 of
   `.wallet.keys` is included as AAD when sealing `.wallet`. Opening
   `.wallet` therefore re-reads `.wallet.keys` and confirms the
   companion files belong to each other. The binding survives password
   rotation (rotation changes only the wrap layer; region 1's tag is
   stable) and survives arbitrary re-orderings of auto-saves.

5. **Capability-discriminated seed block.** The seed block is a
   self-describing tagged union; V3 supports `FULL`, `VIEW_ONLY`, and
   `HARDWARE_OFFLOAD`. `RESERVED_MULTISIG` is claimed by V3.1 and parsed
   with a dedicated error message in V3.0. The discriminator lives
   inside the ciphertext (per Minimum-Leak), not in AAD, but is
   length-self-describing so a V3.0 parser that refuses an unknown mode
   does not accidentally read past the end of cap_content.

## 2. `<name>.wallet.keys` layout

| Range        | Bytes | Field                   | Visibility                              |
|--------------|-------|-------------------------|-----------------------------------------|
| `[0..8)`     | 8     | `magic = "SHEKYLWT"`    | Plaintext. AAD to every AEAD in file.   |
| `[8..9)`     | 1     | `file_version = 0x01`   | Plaintext. AAD to every AEAD.           |
| `[9..10)`    | 1     | `kdf_algo = 0x01`       | Plaintext. AAD to wrap AEAD only.       |
| `[10..11)`   | 1     | `kdf_m_log2`            | Plaintext. AAD to wrap AEAD only.       |
| `[11..12)`   | 1     | `kdf_t`                 | Plaintext. AAD to wrap AEAD only.       |
| `[12..13)`   | 1     | `kdf_p`                 | Plaintext. AAD to wrap AEAD only.       |
| `[13..29)`   | 16    | `wrap_salt`             | Plaintext. AAD to wrap AEAD only.       |
| `[29..30)`   | 1     | `wrap_count = 0x01`     | Plaintext.                              |
| `[30..54)`   | 24    | `wrap_nonce`            | Plaintext.                              |
| `[54..102)`  | 48    | `wrap_ct \|\| wrap_tag` | 32 B ciphertext of `file_kek` + 16 B tag. |
| `[102..126)` | 24    | `region1_nonce`         | Plaintext.                              |
| `[126..N-16)`| var   | `region1_ct`            | Ciphertext under `file_kek`.            |
| `[N-16..N)`  | 16    | `region1_tag`           | Poly1305 tag. `seed_block_tag` value.   |

AEAD for all ciphertexts is XChaCha20-Poly1305 (192-bit nonce).
KDF is Argon2id; V3.0 defaults are `m_log2 = 0x10` (64 MiB), `t = 3`,
`p = 1` per OWASP 2024 memory-constrained profile. `wrap_count` is a
forward-looking reserved byte; V3.0 enforces `wrap_count == 1`.

### 2.1 `wrap_key` and `file_kek`

```
wrap_key  = Argon2id(password, wrap_salt, m=2^kdf_m_log2 KiB, t=kdf_t, p=kdf_p)
            → 32 B
wrap_ct   = XChaCha20-Poly1305(key = wrap_key,
                               nonce = wrap_nonce,
                               aad = bytes[0..29),
                               plaintext = file_kek_32)
file_kek  = 32 B random, generated fresh at wallet creation and never
            regenerated for the life of the wallet (unless the wallet is
            reseeded).
```

Password rotation generates a fresh `wrap_salt` and `wrap_nonce`,
re-derives `wrap_key` under the new password and new salt, and
re-encrypts the unchanged `file_kek` under that new wrap. Region 1 is
untouched.

### 2.2 Region 1 plaintext layout

Region 1 is the seed block; its plaintext is a self-describing tagged
union:

| Offset in region 1 | Bytes | Field                      |
|--------------------|-------|----------------------------|
| `[0..1)`           | 1     | `mode_byte`                |
| `[1..2)`           | 1     | `network`                  |
| `[2..3)`           | 1     | `seed_format`              |
| `[3..68)`          | 65    | `expected_classical_address` |
| `[68..70)`         | 2     | `cap_content_len` (u16 LE) |
| `[70..70+L)`       | L     | `cap_content`              |
| `[70+L..78+L)`     | 8     | `creation_timestamp` (u64 LE) |
| `[78+L..82+L)`     | 4     | `restore_height_hint` (u32 LE) |

`expected_classical_address` is the canonical 65-byte classical address
(`version(1) || spend_pk(32) || view_pk(32)`). A loader that
successfully decrypts region 1 compares this field against the address
it would derive from `cap_content` under the declared
`(network, seed_format)`; a mismatch is treated as corruption.
`restore_height_hint` is the block height at wallet creation; the lost
`.wallet` recovery path uses it as the rescan floor.

Region 1 ciphertext is `XChaCha20-Poly1305(key = file_kek, nonce =
region1_nonce, aad = bytes[0..9), plaintext = region-1-plaintext)`.
Only `magic || file_version` is AAD-bound here: the wrap-layer fields
(`kdf_*`, `wrap_salt`, `wrap_*`) are *not* AAD to region 1, because we
want password rotation to be a wrap-layer-only rewrite. If those fields
were AAD-bound to region 1, rotation would require re-encrypting region
1.

### 2.3 Capability modes

| `mode_byte` | Name                | `cap_content` layout                                   | `cap_content_len` |
|-------------|---------------------|--------------------------------------------------------|-------------------|
| `0x01`      | `FULL`              | `master_seed[64]`                                      | 64                |
| `0x02`      | `VIEW_ONLY`         | `view_sk[32] \|\| ml_kem_dk[2400] \|\| spend_pk[32]`   | 2464              |
| `0x03`      | `HARDWARE_OFFLOAD`  | as `VIEW_ONLY` then `dev_desc_len(u16 LE) \|\| dev_desc[..]` | 2466 + len      |
| `0x04`      | `RESERVED_MULTISIG` | — reserved for V3.1 —                                  | —                 |
| other       | unknown             | parser refuses with `UnknownCapabilityMode`            | —                 |

**FULL** is the canonical mode: a 64-byte `master_seed` from which the
entire Shekyl key tree (`spend_sk`, `view_sk`, `ml_kem_dk`) is derived
per [POST_QUANTUM_CRYPTOGRAPHY.md](POST_QUANTUM_CRYPTOGRAPHY.md). Every
wallet open re-runs the derivation; `ml_kem_dk` is not stored.

**VIEW_ONLY** omits `spend_sk`. `view_sk` and `ml_kem_dk` are persisted
verbatim because they cannot be re-derived without `master_seed`.
`spend_pk` is stored so the loader can construct the full public
classical address.

**HARDWARE_OFFLOAD** extends `VIEW_ONLY` with a `device_desc` blob
identifying the external spend-signer. The wallet behaves like
VIEW_ONLY for every operation that does not need `spend_sk`; spend
operations are dispatched to the device. `device_desc` layout is
specific to the device driver and opaque to the envelope.

`RESERVED_MULTISIG` is reserved. V3.0 parses mode `0x04` and emits a
precise error (`RequiresMultisigSupport`, rendered by the C++ layer as
"this wallet file requires Shekyl V3.1 or later"). The reserved
designation is not a feature flag; it is a forward-compatibility guard
ensuring V3.0 cannot accidentally open a multisig wallet with pieces
missing.

### 2.4 Argon2id defaults

OWASP Password Storage Cheat Sheet (2024 revision), memory-constrained
profile:

- `m_log2 = 0x10` → 2^16 KiB = 64 MiB
- `t = 0x03`
- `p = 0x01`

These produce ≈1 s derivation on a 2024-era laptop. The KAT profile
clamps `m_log2 = 0x08` (256 KiB) so the test suite runs in seconds; KATs
explicitly flag this relaxation as KAT-only.

### 2.5 Capability decode posture

The `(mode_byte, cap_content_len, cap_content)` triple inside region 1
is read in this order, with each step refusing in a typed way rather
than falling back:

1. **Successful AEAD.** Region 1's Poly1305 tag verifies against
   `file_kek` and the `[magic || file_version]` AAD. Any byte tamper
   on the AAD, the ciphertext, or the tag surfaces as
   `InvalidPasswordOrCorrupt` — deliberately indistinguishable from a
   wrong-password guess so the decryption path cannot be used as an
   oracle.
2. **`mode_byte` is decoded first.** Before a single byte of
   `cap_content` is interpreted, the mode byte is mapped through
   `from_envelope_byte` (FULL / VIEW_ONLY / HARDWARE_OFFLOAD /
   reserved-multisig / unknown). Unknown bytes fail with
   `UnknownCapabilityMode`; the reserved-multisig placeholder fails
   with `RequiresMultisigSupport`. No other capability's decoder runs
   on a byte it was not handed.
3. **`cap_content_len` is validated against the declared mode.**
   `validate_cap_content` enforces:
   - FULL: `cap_len == 64` exactly.
   - VIEW_ONLY: `cap_len == 32 + ML_KEM_768_DK_LEN + 32 = 2464`
     exactly (no trailing bytes, no truncation).
   - HARDWARE_OFFLOAD: `cap_len >= 32 + ML_KEM_768_DK_LEN + 32 + 2 =
     2466` (the `+2` is the u16 `device_desc_len` prefix; the device
     descriptor itself is length-prefixed and consumed by the
     dispatched decoder, not skipped).
   Any mismatch fails with `CapContentLenMismatch { mode, len }`
   which is the typed equivalent of the audit plan's
   "CapabilityPayloadMismatch" refusal. No capability-shape fallback
   runs on a length-check failure.
4. **Per-capability interpretation happens above the envelope.** The
   `OpenedKeysFile` produced by `open_keys_file` hands `cap_content`
   out as opaque bytes tagged with `capability_mode`. The caller
   (for FULL, the key-tree rederivation in `shekyl-account`; for
   VIEW_ONLY / HARDWARE_OFFLOAD, the scanner's session-key layer)
   owns the mode-specific parse. That parse runs against bytes whose
   `(mode, len)` pair is already known to be consistent with the
   declared capability — it does not re-check the mode, because the
   envelope has already refused every `(mode, len)` shape that is
   not a member of the closed set above.

**Review rule.** Any code path in this layer that uses `read_to_end`,
`take_while`, or similar unbounded patterns against `cap_content` —
or that silently truncates/pads a mode's content region — is a
deviation from this posture and must be called out in review. The
length check is the authoritative gate; no decoder is permitted to
"tolerate" trailing bytes or short content, because tolerating them
reopens the very attack shape the length check was written to
close.

The adversarial corpus in
`rust/shekyl-engine-file/tests/adversarial_corpus.rs` locks this
posture in at the integration layer: every `(mode, len)` shape
outside the closed set is expected to surface a typed refusal, not a
fallback.

## 3. `<name>.wallet` layout

| Range       | Bytes | Field                 | Visibility          |
|-------------|-------|-----------------------|---------------------|
| `[0..8)`    | 8     | `magic = "SHEKYLWS"`  | Plaintext. AAD.     |
| `[8..9)`    | 1     | `state_version = 0x01`| Plaintext. AAD.     |
| `[9..33)`   | 24    | `region2_nonce`       | Plaintext.          |
| `[33..M-16)`| var   | `region2_ct`          | Ciphertext.         |
| `[M-16..M)` | 16    | `region2_tag`         | Poly1305 tag.       |

```
region2_aad = bytes[0..9)                             // "SHEKYLWS" || 0x01
            || seed_block_tag                          // 16 B Poly1305 tag of
                                                      //   region 1 of .wallet.keys
region2_ct  = XChaCha20-Poly1305(key = file_kek,
                                 nonce = region2_nonce,
                                 aad = region2_aad,
                                 plaintext = state-serialization-bytes)
```

`seed_block_tag` is not stored inside `.wallet`; it is recovered from
`.wallet.keys` at open time. A mismatch (someone swapped
companion-file pairings) fails with `StateSeedBlockMismatch`.

The state plaintext is opaque to the envelope layer. V3.0 consumes it as
UTF-8 JSON per the existing `wallet2` state schema, but the envelope
imposes no constraint on the contents.

## 4. Operational properties

### 4.1 Write-once seed file

`.wallet.keys` is written at wallet creation and on password rotation
only. The reference implementation asserts this in DEBUG builds by
hashing the file bytes on load and refusing any save path that is not
explicitly a rotation or a restore. The asymmetry matters because auto-
save runs with the wallet unlocked; a bug that wrote seed bytes on every
save would give an attacker with an ephemeral write window many chances
to substitute seed material.

### 4.2 Password rotation

```
inputs : old_password, new_password, old_bytes [, new_kdf]
output : new_bytes such that
           new_bytes[OFF_REGION1_NONCE..] == old_bytes[OFF_REGION1_NONCE..]
           new_bytes[OFF_WRAP_SALT..OFF_WRAP_COUNT] != old_bytes[OFF_WRAP_SALT..OFF_WRAP_COUNT]
           new_bytes[OFF_WRAP_NONCE..OFF_WRAP_CT]   != old_bytes[OFF_WRAP_NONCE..OFF_WRAP_CT]
           open_keys_file(new_password, new_bytes)   = open_keys_file(old_password, old_bytes)
           open_keys_file(old_password, new_bytes)   = InvalidPasswordOrCorrupt
```

A fresh `wrap_salt` and `wrap_nonce` on rotation is defense-in-depth
against an attacker who may have precomputed any wrap brute-force work
against the old values.

### 4.3 Auto-save

```
inputs : password, current .wallet.keys bytes, new state plaintext
output : new .wallet bytes with a fresh region2_nonce
guarantees : .wallet.keys bytes on disk are untouched by auto-save
             region2_nonce changes on every call, even with identical plaintext
```

Each auto-save re-runs the Argon2id wrap derivation. The design accepts
this per-save latency in exchange for the invariant that `file_kek`
never leaves its scoped use inside a single `seal_state_file` /
`open_state_file` / `open_keys_file` call. No cached `file_kek`, no
cached password.

### 4.4 Wallet creation ordering

```
1. tmp_write(.wallet.keys.tmp, keys_bytes) ; fsync file ; rename to .wallet.keys ; fsync parent dir
2. tmp_write(.wallet.tmp,      state_bytes); fsync file ; rename to .wallet      ; fsync parent dir
```

A crash between step 1 and step 2 leaves a `.wallet.keys` alone on
disk. The next open finds the lost-`.wallet` case below and triggers a
full rescan from `restore_height_hint`.

### 4.5 Lost `.wallet`, `.wallet.keys` intact

```
open_keys_file(password, .wallet.keys)       = Ok(opened)
open_state_file(password, .wallet.keys, ..)  = NotFound or cannot-open
action : log "state cache missing or unreadable; rebuilding from chain
              (restore_height_hint=X)"
         clear in-memory state containers
         set refresh_from_block_height = opened.restore_height_hint
         proceed with normal refresh loop
```

### 4.6 Lost `.wallet.keys`

The wallet is dead. `.wallet` alone is undecryptable: `file_kek` only
lives wrapped inside `.wallet.keys`. A mainnet / stagenet user restores
from their BIP-39 seed phrase; a testnet / fakechain user restores from
the 32-byte raw seed hex. V3 does not attempt silent recovery.

### 4.7 Pre-v1 refusal

V3 refuses every file that does not begin with `SHEKYLWT`. There is no
silent migration from Monero-lineage keys-file formats. The C++ layer
surfaces the refusal as `wallet_incompatible` with a message pointing
at the BIP-39 / raw-seed restore flow.

## 5. Error taxonomy

Opaque to userspace; the C++ layer maps each to a specific message:

| Rust variant                 | FFI code | C++ message surface |
|------------------------------|----------|---------------------|
| `TooShort`                   | 1        | "wallet file truncated" |
| `BadMagic`                   | 2        | "not a Shekyl V3 wallet file — please restore from seed" |
| `FormatVersionTooNew`        | 3        | "wallet file written by a newer Shekyl; please upgrade" |
| `UnsupportedKdfAlgo`         | 4        | "unknown KDF algorithm id" |
| `KdfParamsOutOfRange`        | 5        | "KDF parameters out of policy range" |
| `UnsupportedWrapCount`       | 6        | "unexpected wrap-key count" |
| `CapContentLenMismatch`      | 7        | "capability content length does not match mode" |
| `UnknownCapabilityMode`      | 8        | "unknown capability mode" |
| `RequiresMultisigSupport`    | 9        | "this wallet requires Shekyl V3.1 or later" |
| `InvalidPasswordOrCorrupt`   | 10       | "wrong password, or wallet file corrupt" |
| `StateSeedBlockMismatch`     | 11       | "this .wallet does not belong to the .wallet.keys next to it" |
| `Internal`                   | 12       | "internal wallet-file error" |

Wrong-password and tamper paths both return `InvalidPasswordOrCorrupt`
so the error code cannot be used as an oracle.

## 6. Threat model annotations (per field)

**`magic`, `file_version` (plaintext AAD).** These are the minimum a
parser needs to decide whether the file is "ours" and which code path
to run. Hiding them would mean brute-force-trying every decryption
strategy for every possible file in `~`; that is a regression.

**`kdf_*` parameters and `wrap_salt` (plaintext AAD to wrap).** The
parser must know these *before* the password is entered to derive
`wrap_key`. They leak nothing a filesystem-observing attacker couldn't
compute from timing, so we expose them directly.

**`wrap_nonce` (plaintext).** Opaque bytes. Per-rotation fresh; no
cross-file reuse.

**`wrap_ct` (ciphertext of `file_kek`).** Opaque. An offline
password-cracking attacker must do `#candidates × Argon2id(params)`
work, then `XChaCha20-Poly1305-Verify` per candidate, to confirm a
guess. Choose `m_log2` and `t` to make that cost multiplicative
expensive against feasible adversaries.

**`region1_nonce`, `region1_ct`, `region1_tag`.** Opaque. Region 1's
plaintext includes the `mode_byte` and `network` — deliberately hidden
from filesystem scans so "is this a VIEW_ONLY stagenet wallet?" is not
answerable without the password.

**`expected_classical_address` (inside region 1).** Loader uses this
both for sanity (derivation agrees) and for UX (displayable before any
derivation work). Being inside region 1 means an attacker who does not
have the password cannot query what address this wallet holds.

**`state_tag_of_seed_block` (AAD to region 2).** Binds `.wallet` to a
specific `.wallet.keys`. Not stored anywhere in `.wallet`; recovered at
open time from `.wallet.keys`'s last 16 bytes.

## 7. Reference implementation

- [`rust/shekyl-crypto-pq/src/wallet_envelope.rs`](../rust/shekyl-crypto-pq/src/wallet_envelope.rs)
  — the normative envelope module. `seal_keys_file`, `inspect_keys_file`,
  `open_keys_file`, `rewrap_keys_file_password`, `seal_state_file`,
  `open_state_file`.
- [`rust/shekyl-ffi/src/wallet_envelope_ffi.rs`](../rust/shekyl-ffi/src/wallet_envelope_ffi.rs)
  — C-ABI surface for the above. Two-call sizing, zeroize-on-failure,
  narrow-error discipline per
  [.cursor/rules/40-ffi-discipline.mdc](../.cursor/rules/40-ffi-discipline.mdc).
- [`src/shekyl/shekyl_ffi.h`](../src/shekyl/shekyl_ffi.h) — the C-side
  prototypes. Constants and struct layouts pinned by `static_assert`
  against the Rust `#[repr(C)]` definitions.
- [`docs/test_vectors/WALLET_FILE_FORMAT_V1/`](test_vectors/WALLET_FILE_FORMAT_V1/)
  — Tier-3 KATs: three sealed blobs (`full.hex`, `view_only.hex`,
  `hardware_offload.hex`) plus a `manifest.json` describing the inputs
  that produced each blob. The KAT generator runs Argon2id at
  `m_log2 = 0x08` (256 KiB) so the `cargo test` cycle stays fast; the
  production wallets always use the defaults in §2.4.
