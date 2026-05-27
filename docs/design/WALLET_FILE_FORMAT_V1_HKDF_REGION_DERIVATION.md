# Wallet file format v1 — per-region HKDF wrap keys

**Status:** ratified spec amendment (doc-only; implementation tracked separately).
**Scope:** normative derivation prescription for AEAD keys protecting region 1
(`.wallet.keys` seed block) and region 2 (`.wallet` state cache). Does not
change on-disk byte layout, `file_version`, or wrap-layer semantics.
**Parent spec:** [`WALLET_FILE_FORMAT_V1.md`](../WALLET_FILE_FORMAT_V1.md).
**Related:** [`WALLET_PREFS.md`](../WALLET_PREFS.md) §2.2 (prefs HMAC HKDF pattern),
Stage 1 PR 6 PersistenceEngine / F5(b) steady-state wrap-key caching.

## 1. Problem statement

`WALLET_FILE_FORMAT_V1.md` (pre-amendment) prescribed
`XChaCha20-Poly1305(key = file_kek, …)` for both region 1 and region 2.
`prefs_hmac_key` already uses HKDF-Expand from `file_kek` with a domain-separated
`info` string and address binding. Region 1 and region 2 were the exception, not
the rule.

That shape is inherited wallet2 thinking (one envelope key encrypts everything)
applied to a split-file design with different threat tiers:

| Region | Content | Impact if AEAD key leaks |
|--------|---------|--------------------------|
| 1 | Spend/view seeds, PQC decap material | Catastrophic — funds at risk |
| 2 | Ledger cache, refresh progress | Privacy-sensitive — not spend authority |

AEAD AAD (`magic || version`, plus `seed_block_tag` for region 2) prevents
**ciphertext swapping** between regions. AAD does **not** provide **key-purpose
separation**: an attacker who holds `file_kek` decrypts both regions regardless
of AAD.

F5(b) steady-state caching intends to keep only region-2 wrap capability in
memory after open. That property is impossible when region 1 and region 2 share
`file_kek` directly.

## 2. Disposition

**Amend v1 in place.** No `file_version` bump. No on-disk layout change.

| Property | Unchanged | Changed |
|----------|-----------|---------|
| Header offsets, nonces, ciphertext+tag placement | yes | |
| `wrap_key` / `file_kek` wrap layer | yes | |
| AEAD primitive (XChaCha20-Poly1305) | yes | |
| Per-region AEAD **key** input | | `file_kek` → HKDF-derived subkeys |

### 2.1 Pre-genesis ciphertext note

Wallets or KAT blobs sealed with the pre-amendment prescription (AEAD keyed by
raw `file_kek`) do **not** decrypt under the amended prescription. This is
expected pre-genesis: migration path is `rm -rf ~/.shekyl` and re-create; Tier-3
KATs in `docs/test_vectors/WALLET_FILE_FORMAT_V1/` are regenerated when the
reference implementation lands (separate commit from this doc).

"Byte-compatible" means **layout-compatible**, not "old ciphertext decrypts
without re-seal."

## 3. Normative derivation

All expansions use **HKDF-SHA-256** with `file_kek` as the PRK (`HKDF-Expand`
with no Extract step — same pattern as `shekyl-engine-prefs`).

Let `addr` be the 65-byte `expected_classical_address` committed in region 1
plaintext (`version(1) || spend_pk(32) || view_pk(32)`).

```
wrap_key_region_1 = HKDF-Expand(
    prk  = file_kek,
    info = b"shekyl-region1-aead-v1" || addr,
    L    = 32,
)

wrap_key_region_2 = HKDF-Expand(
    prk  = file_kek,
    info = b"shekyl-region2-aead-v1" || addr,
    L    = 32,
)
```

Region AEAD calls become:

```
region1_ct = XChaCha20-Poly1305(key = wrap_key_region_1, …)
region2_ct = XChaCha20-Poly1305(key = wrap_key_region_2, …)
```

`prefs_hmac_key` remains per [`WALLET_PREFS.md`](../WALLET_PREFS.md); it is a
third independent expansion from the same `file_kek` PRK with label
`b"shekyl-prefs-hmac-v1"`.

### 3.1 Rationale (reviewer-facing)

1. **One key, one purpose.** Spend-authority region and ledger-cache region get
   independent 32-byte AEAD keys.
2. **F5(b) blast radius.** After open, the orchestrator may cache
   `wrap_key_region_2` (and `prefs_hmac_key`) for steady-state saves while
   zeroizing `file_kek` and `wrap_key_region_1`. Memory disclosure during session
   does not yield region-1 decrypt capability from cached steady-state material
   alone.
3. **Nonce-space isolation.** Independent keys give independent XChaCha20 nonce
   spaces under the standard "never reuse (key, nonce)" rule.
4. **Future asymmetric hardening.** Region 1 can adopt a stronger derivation or
   AEAD policy without touching region 2.
5. **Auditor consistency.** Matches per-output HKDF discipline in
   `shekyl-crypto-pq` and prefs integrity derivation.

Address binding in `info` mirrors prefs HMAC: defense-in-depth if two wallets
ever shared a `file_kek` (KDF degeneracy or implementation bug).

## 4. Operational consequences

### 4.1 Open path

1. Derive `wrap_key` from password; decrypt `file_kek`.
2. Decrypt region 1 with `wrap_key_region_1`; read `expected_classical_address`.
3. Derive `wrap_key_region_2`; decrypt `.wallet` region 2.
4. Derive `prefs_hmac_key` when loading prefs.

`OpenedKeysFile` may continue to expose `file_kek` as the PRK for subkey
derivation, or expose only derived subkeys — implementation choice. Exposed
`file_kek` still grants both regions if retained; F5(b) requires dropping
`file_kek` and `wrap_key_region_1` after region 1 decrypt completes.

### 4.2 Password rotation

Unchanged: only the wrap layer of `.wallet.keys` is rewritten. Region 1
ciphertext, region 1 tag, and `.wallet` bytes stay identical because `file_kek`
is unchanged.

### 4.3 Auto-save

Each `seal_state_file` derives `wrap_key_region_2` from `file_kek` (or uses a
session-cached `wrap_key_region_2` per F5(b)). Argon2id per save remains as today
for wrap-layer re-derivation policy in §4.3 of the parent spec.

## 5. Implementation checklist (out of scope for this doc)

- [ ] `rust/shekyl-crypto-pq/src/wallet_envelope.rs` — derive and use
      `wrap_key_region_{1,2}`; shared helper with `shekyl-engine-prefs` HKDF
      shape.
- [ ] `docs/test_vectors/WALLET_FILE_FORMAT_V1/` — regenerate three sealed blobs +
      manifest.
- [x] Stage 1 PR 6 — F5(b) narrative updated in
      [`STAGE_1_PR_6_PERSISTENCE_ENGINE.md`](STAGE_1_PR_6_PERSISTENCE_ENGINE.md)
      §5.9 (substrate amendment pin; `StateWrapKey` = `wrap_key_region_2`).

## 6. Reversion clause

Reopen only if a production deployment exists with wallets sealed under raw
`file_kek` region AEAD **and** a migration budget is approved post-genesis.
Pre-genesis default remains: amend now, regenerate KATs, no migration code.
