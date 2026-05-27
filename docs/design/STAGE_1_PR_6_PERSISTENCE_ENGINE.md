# Stage 1 PR 6 — `PersistenceEngine` extraction — design (substrate)

**Status.** Substrate pins only (HKDF region wrap keys, open ritual, session
cache policy). Full Round 1+ design rounds for the per-trait PR are **not**
started; this file records load-bearing dispositions that the HKDF
implementation PR and PR 6 implementation must agree on.

**Parent spec:** [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
§2.6, [`WALLET_FILE_FORMAT_V1.md`](../WALLET_FILE_FORMAT_V1.md) §2.6,
[`WALLET_FILE_FORMAT_V1_HKDF_REGION_DERIVATION.md`](WALLET_FILE_FORMAT_V1_HKDF_REGION_DERIVATION.md).

---

## 6.3 Prerequisites

**HKDF region wrap keys** (`torvaldsl/wallet-hkdf-region-keys` → `dev`) MUST
merge before cutting `feat/stage-1-pr6-persistence-engine`. PR 6 session
caching, `StateWrapKey`, and F5(b) zeroization assume
`wallet_envelope` derives per-region AEAD keys per format spec §2.6 — not raw
`file_kek` for regions 1 and 2.

---

## 5.9 Key material table (steady-state session)

| Key | Derivation | Cached on orchestrator after open? | Zeroized when? |
|-----|------------|-----------------------------------|----------------|
| `file_kek` | Argon2 unwrap of wrap layer | **No** (PR 6) | Immediately after open ritual completes |
| `wrap_key_region_1` | HKDF-Expand(`file_kek`, `b"shekyl-region1-aead-v1"`) — **label only** | **No** | With `file_kek` post-open |
| `wrap_key_region_2` | HKDF-Expand(`file_kek`, `b"shekyl-region2-aead-v1" \|\| addr`) | **Yes** — as `StateWrapKey` | Wallet handle drop / close |
| `prefs_hmac_key` | HKDF-Expand per [`WALLET_PREFS.md`](../WALLET_PREFS.md) §2.2 | **Yes** — as `PrefsHmacKey` | Wallet handle drop / close |

`addr` is the 65-byte `expected_classical_address` from decrypted region 1
plaintext (not duplicated outside region 1 ciphertext).

### P5 — address caching policy (implement in PR 6)

PR 6 caches **`wrap_key_region_2` directly** (as `StateWrapKey`); the cached
key already incorporates `file_kek` and `addr` at derivation time. The
orchestrator MUST NOT retain `expected_classical_address` as a separate
steady-state field solely for re-derivation of region-2 AEAD keys.

### Honest-scope note (post-HKDF PR, pre-PR-6 zeroization)

After the HKDF PR lands and PR 6 implements F5(b) zeroization, the
orchestrator session cache holds **`wrap_key_region_2`** (and
`prefs_hmac_key`), not universal `file_kek`. The F5(b) ledger-only blast
radius claim becomes **true** once `file_kek` and `wrap_key_region_1` are
zeroed post-open — not merely aspirational. Residual disclosure surface until
V3.2 handle slimming: `keys_file_bytes` on the handle and any password re-entry
for operations that still call `seal_state_file(password, …)` before PR 6
wires `save_state_with_key`.

---

## 5.12 L9 — address binding closure

**Region 2 and prefs HMAC** bind `addr` (65-byte `expected_classical_address`
from region 1 plaintext after decrypt).

**Region 1** uses **label-only** HKDF (`b"shekyl-region1-aead-v1"`) for
bootstrap ordering: open must derive the region-1 decrypt key before reading
`addr` from ciphertext. Address binding on region 1 was redundant under
CSPRNG-random per-wallet `file_kek` and is omitted per
[`WALLET_FILE_FORMAT_V1.md`](../WALLET_FILE_FORMAT_V1.md) §2.6.

---

## Round 2 — §2h open ritual (ordering pin)

Wallet open (keys + state hydration) MUST follow this key-derivation order:

1. Argon2 → unwrap `file_kek`.
2. HKDF → `wrap_key_region_1` (label-only) → decrypt region 1 → read `addr`.
3. HKDF → `wrap_key_region_2` and `prefs_hmac_key` (both use `addr`).
4. Decrypt region 2 (if present) under `wrap_key_region_2`.
5. Zeroize `file_kek` and `wrap_key_region_1` (PR 6 F5(b); not in HKDF PR).

Steady-state auto-save uses cached `wrap_key_region_2` (`StateWrapKey`) once
PR 6 lands; until then, `seal_state_file` re-derives via steps 1–3 on each
save (acceptable interim cost).
