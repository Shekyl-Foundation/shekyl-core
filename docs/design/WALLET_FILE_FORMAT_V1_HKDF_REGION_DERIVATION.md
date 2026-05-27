# Wallet file format v1 — per-region HKDF wrap keys

**Status:** ratified; reference implementation in
`rust/shekyl-crypto-pq/src/wallet_envelope.rs`.
**Scope:** normative derivation prescription for AEAD keys protecting region 1
(`.wallet.keys` seed block) and region 2 (`.wallet` state cache). Does not
change on-disk byte layout, `file_version`, or wrap-layer semantics.
**Parent spec:** [`WALLET_FILE_FORMAT_V1.md`](../WALLET_FILE_FORMAT_V1.md) §2.6.
**Related:** [`WALLET_PREFS.md`](../WALLET_PREFS.md) §2.2,
Stage 1 PR 6 PersistenceEngine / F5(b) steady-state wrap-key caching.

## 1. Problem statement

Pre-amendment v1 prescribed `XChaCha20-Poly1305(key = file_kek, …)` for both
regions. `prefs_hmac_key` already used HKDF-Expand from `file_kek` with a
domain-separated `info` string and address binding. Regions 1 and 2 were the
exception.

F5(b) steady-state caching requires region-isolated wrap keys. Sharing
`file_kek` as the AEAD key for both regions collapses blast radius in
memory-disclosure scenarios that AAD does not address.

## 2. Disposition

**Amend v1 in place.** No `file_version` bump. On-disk **layout** unchanged;
**ciphertext** from raw-`file_kek` AEAD does not decrypt under this prescription.
Pre-genesis: regenerate KATs; `rm -rf ~/.shekyl` for local wallets.

## 3. Normative derivation

All expansions use **HKDF-SHA-256 in expand-only mode** with `file_kek` as the
PRK (`HKDF-Expand`; no Extract step; no salt). Same pattern as
`shekyl-engine-prefs`.

**`file_kek` provenance (normative).** `file_kek` MUST be generated from a
cryptographically secure random source at wallet creation. It MUST NOT be
derived from the user's password, seed phrase, or any other reproducible input.
Two wallets sharing a `file_kek` value collapse the security properties of
per-region HKDF labels.

**Normative info labels** (byte-exact; see parent spec §2.6):

| Constant | Value |
|----------|-------|
| Region 1 | `b"shekyl-region1-aead-v1"` (22 bytes) — label only |
| Region 2 prefix | `b"shekyl-region2-aead-v1"` (22 bytes) `\|\| addr` |

Let `addr` be the 65-byte `expected_classical_address` in region 1 plaintext.

```
wrap_key_region_1 = HKDF-Expand(
    prk  = file_kek,
    info = b"shekyl-region1-aead-v1",
    L    = 32,
)

wrap_key_region_2 = HKDF-Expand(
    prk  = file_kek,
    info = b"shekyl-region2-aead-v1" || addr,
    L    = 32,
)
```

Region 1 is label-only so open derives the decrypt key before reading `addr`
from ciphertext (Minimum-Leak: no address bytes outside region 1).

### 3.1 Rationale

1. **One key, one purpose.** Independent 32-byte AEAD keys per region.
2. **F5(b) blast radius.** Cache `wrap_key_region_2` + `prefs_hmac_key`; zeroize
   `file_kek` and `wrap_key_region_1` after open.
3. **Label-only region 1.** Cross-wallet region-1 swap was never practical with
   CSPRNG-random per-wallet `file_kek`; addr binding on region 1 was redundant
   under per-region HKDF and blocked bootstrap ordering.

## 4. Operational consequences

### 4.1 Open path

1. Argon2 → unwrap `file_kek`.
2. HKDF → `wrap_key_region_1` (label-only) → decrypt region 1 → read `addr`.
3. HKDF → `wrap_key_region_2` + `prefs_hmac_key` → decrypt region 2 (if present).
4. Zeroize `file_kek` and `wrap_key_region_1` (PR 6 / F5(b)).

### 4.2 Password rotation

Unchanged: wrap layer only; `file_kek` and region ciphertexts unchanged.

### 4.3 Auto-save

Derive or cache `wrap_key_region_2` directly (PR 6 `StateWrapKey`); the cached
key incorporates `file_kek` and `addr` at derivation time — do not retain `addr`
separately on the orchestrator solely for re-derivation.

## 5. Implementation checklist

- [x] `wallet_envelope.rs` — `derive_wrap_key_region_{1,2}` per §3
- [x] Tier-3 KAT regeneration
- [ ] Stage 1 PR 6 — `StateWrapKey`, session cache, F5(b) zeroization
  (substrate pins in [`STAGE_1_PR_6_PERSISTENCE_ENGINE.md`](STAGE_1_PR_6_PERSISTENCE_ENGINE.md))

## 6. Reversion clause

Reopen only if production wallets exist under raw-`file_kek` region AEAD **and**
a migration budget is approved post-genesis.
