# FA-6 — ML-KEM-keyed view-tag pre-filter (T6 closure)

**Status.** Specification draft (2026-06-01). **Disposition:** adopt at V3.0
genesis — re-key the on-wire 1-byte view tag from `x25519_ss` to `ml_kem_ss`.
**Implementation:** separate PR after spec review; not bundled with FA-11
(`enc_label` wire) or subaddress-removal (FA-2).

**Provenance.** Threat objective **T6** (`docs/design/SUBADDRESS_UNDER_PQC.md`
§4.3, §4.4). Parallel **adversary** track (§4.7–§4.8); not closed by
End-state 5, 5-T, or R2-F2. Product reasoning and code audit:
`rust/shekyl-crypto-pq/src/output.rs`, `derivation.rs`.

**Related.**

| Doc | Role |
|-----|------|
| `docs/design/SUBADDRESS_UNDER_PQC.md` | T6 impossibility shape (§4.4); FA-6 pointer (§3.7) |
| `docs/POST_QUANTUM_CRYPTOGRAPHY.md` | HKDF registry — **update on implementation** (§ view-tag) |
| `docs/FOLLOWUPS.md` | Work-item queue; FA-9 propagation after FA-6 lands |
| `docs/design/STAGE_2_KEY_ENGINE_ACTOR.md` | Scan/claim path uses same `scan_output_recover` primitive |

**Process.** Spec review before code. Benchmark gate (§8) is a merge
requirement, not advisory.

---

## 1. Problem statement

### 1.1 What the view tag does today

Each v3 output carries a **1-byte** `view_tag` in `txout_to_tagged_key`
(`cryptonote_basic.h`). The wallet scanner uses it as a **pre-filter** before
full hybrid recovery:

1. Compute `x25519_ss = view_scalar · R_eph` (Montgomery ECDH).
2. `expected_tag = HKDF(x25519_ss, …)` (see §4).
3. If `expected_tag ≠ view_tag_on_chain`, reject (no ML-KEM decap).
4. On match: ML-KEM decap → combine → HKDF → amount/label tags → `B'`
   recovery → commitment check.

Reference: `scan_output` / `scan_output_recover` in
`rust/shekyl-crypto-pq/src/output.rs` (X25519 block before decap).

### 1.2 Why it leaks (T6)

The tag is **cheap because it avoids ML-KEM** — and **leaks for the same
reason**:

| Attacker capability | Can recompute today's tag? |
|-------------------|----------------------------|
| **Quantum** observer + victim's public address | **Yes** — recover view scalar `a` from public view key (classical DL on the curve used for view derivation); recompute `x25519_ss` per output from on-chain `R_eph`. |
| **Classical** thief of view-half only (no `ml_kem_dk`) | **Yes** — same computation as the honest scanner's first step. |

The tag partitions the chain into “consistent with wallet W's view material”
(all of W's receives plus ~1/256 noise). That is **account-level receive
clustering** — coarser than subaddress identity, but sensitive for T6.

### 1.3 What cannot work in place

“You cannot encrypt the view tag in place.” The tag's **leak** and its
**usefulness** are the same property: anything the scanner can compute
cheaply from public tx data + wallet secrets the attacker also holds (or
will hold post-quantum) is not secret from them.

Hardening the tag without changing **which secret** it depends on is
impossible. The move must change the filter's keying material.

---

## 2. Threat model

### 2.1 In scope — T6 (closes on adoption)

**Adversary:** Holds the victim's **public** hybrid address (or a leaked
receive address / QR) and either:

- a **quantum** computer (recover view scalar from public view key), or
- a **classical** copy of the **view secret** without `ml_kem_dk`.

**Goal:** Cluster the victim's **incoming** outputs on-chain using only the
1-byte wire tag.

**Outcome after FA-6:** Adversary cannot compute the wire tag at any width
(**zero** information from the tag, not 8-bit noisy), because `ml_kem_ss`
requires `ml_kem_dk` and ML-KEM decap is post-quantum.

### 2.2 Explicitly out of scope (FA-6 does not claim)

Record these in FA-9 / threat-model docs so receive-side closure is not
mistaken for full post-quantum anonymity.

| Surface | Why FA-6 does not address it |
|---------|------------------------------|
| **Spend-side dust / key images** | Uses **spend** secret `b` (from `B`), not view tag. Quantum adversary locates dust spends via key image. |
| **FCMP++ membership** | Curve-tree proofs rest on **classical** discrete-log hardness; which output was spent degrades post-quantum regardless of view tag. |
| **T2 counterparty collusion** | Byte-compare of address / PQC segment — off-chain, not view tag. |
| **Address substitution (phishing)** | Channel integrity — R2-F9 pin (`SUBADDRESS_UNDER_PQC.md` §5.7.12). |
| **Passive observer without address** | Never had clustering power via view tag alone (needed `R_eph` + view material). |

**Honest framing:** Hybrid PQC protects **confidentiality** post-quantum
(amounts, ownership after full scan). FA-6 extends that to close the
**cheapest receive-side linkability leak** (T6). Spend linkability and
FCMP++ membership remain **classical** problems — deeper, separate tracks.

### 2.3 Pit-of-success boundary

Per `SUBADDRESS_UNDER_PQC.md` §4.7–§4.8: End-state 5 and sentinel-only launch
**do not** relax T6. FA-6 is **adversary-track** work, not user-behavior
mitigation.

---

## 3. Design decision

**Adopt:** Re-key the on-wire pre-filter tag to **ML-KEM shared secret**
`ml_kem_ss` (32 bytes from ML-KEM-768 decap / encaps), with a **new** HKDF
salt and label (§4).

**Reject:**

| Alternative | Reason |
|-------------|--------|
| Keep classical X25519-keyed tag | T6 remains open (quantum + view-half theft). |
| Drop the tag entirely | PQ-safe but **no** pre-filter — full hybrid path on every output (~256× more decap+recovery work vs filtered path, not a small constant). |
| Use `view_tag_combined` (HKDF over **combined** SS) on wire | PQ-safe after decap, but checking it requires **both** legs before compare — cannot filter before X25519; strictly more expensive than `ml_kem_ss`-only for the same protection. |
| Encrypt / blind the classical tag | Does not change keying; attacker with `a` still learns the same partition. |

**Necessary, not sufficient** for post-quantum unlinkability — but shuts the
window that is both **cheapest to exploit** and **exploitable today** (partial
view-key theft).

---

## 4. Cryptographic specification

### 4.1 Wire format (unchanged)

| Field | Location | Size | Consensus |
|-------|----------|------|-----------|
| `view_tag` | `txout_to_tagged_key.view_tag` | **1 byte** | **Not validated** — wallet convention only; network cannot check (no secrets). |

No transaction version bump. No change to `enc_amounts`, `enc_labels`, KEM
ciphertext layout, or FCMP++ proofs.

**Genesis lock:** All nodes and wallets from genesis must derive the tag
identically. Post-genesis tag re-keying would require a coordinated dual-check
transition; pre-genesis this is a **derivation-only** swap.

### 4.2 New derivation (normative)

Replace `derive_view_tag_x25519` for **on-wire** tags with:

```text
view_tag_ml_kem = first_byte(
  HKDF-Expand(
    prk = HKDF-Extract(salt = HKDF_SALT_VIEW_TAG_ML_KEM, ikm = ml_kem_ss),
    info = LABEL_VIEW_TAG_ML_KEM || output_index_le64,
    len = 32
  )
)
```

**Constants (new):**

| Symbol | Value | Length |
|--------|-------|--------|
| `HKDF_SALT_VIEW_TAG_ML_KEM` | `shekyl-view-tag-ml-kem-v1` | 24 bytes |
| `LABEL_VIEW_TAG_ML_KEM` | `shekyl-view-tag-ml-kem` | 22 bytes |
| `output_index_le64` | Output index, little-endian | 8 bytes |

**Hash:** HKDF-SHA512 (same as existing output derivations).

**Input `ml_kem_ss`:** 32-byte ML-KEM-768 shared secret bytes (FIPS 203
`encaps` / `decaps` output), same encoding as today in `combine_shared_secrets`.

### 4.3 Deprecated derivation (remove from wire path)

| Symbol | Status after FA-6 |
|--------|-------------------|
| `HKDF_SALT_VIEW_TAG_X25519` | **Deleted** from wire-tag path (grep-clean) |
| `derive_view_tag_x25519` | **Deleted** or test-only shim until KAT removal |
| `view_tag_x25519` field in `OutputData` / FFI | Renamed → `view_tag` / `view_tag_ml_kem` |

### 4.4 Unchanged: `view_tag_combined`

`view_tag_combined` remains derived from **combined** shared secret inside
`derive_output_secrets` — post-decap cross-check material, **not** the wire
pre-filter. FA-6 does **not** put `view_tag_combined` on wire.

Optional future hardening (not FA-6): after a successful pre-filter match,
compare `secrets.view_tag_combined` to an internal expectation — integrity
only; does not affect T6.

### 4.5 Sender (`construct_output`)

Order after per-output KEM seed derivation (unchanged through encaps):

1. X25519 ephemeral + `x25519_raw_ss` (still required for combine).
2. ML-KEM encaps → `ml_kem_ss`, `ml_kem_ct`.
3. **`view_tag = derive_view_tag_ml_kem(ml_kem_ss, output_index)`** ← **change**
4. `combined_ss = combine(x25519_raw_ss, ml_kem_ss)`.
5. `derive_output_secrets(combined_ss, …)` — remainder unchanged.

Sender already holds `ml_kem_ss` at step 2; no new capability.

### 4.6 Scanner (`scan_output`, `scan_output_recover`)

**New order** (leg-swap vs today):

| Step | Operation | Every output? |
|------|-----------|----------------|
| 1 | Validate ML-KEM ciphertext length; **ML-KEM decap** with account `ml_kem_dk` | **Yes** |
| 2 | `expected = derive_view_tag_ml_kem(ml_kem_ss, output_index)`; compare to `view_tag_on_chain` | **Yes** |
| 3 | On mismatch: **return** (no X25519, no combine) | — |
| 4 | X25519 ECDH: `x25519_raw_ss = view_scalar · R_eph` (low-order rejection unchanged) | **Match only** |
| 5 | `combined_ss = combine(x25519_raw_ss, ml_kem_ss)` | Match only |
| 6 | HKDF, amount/label tags, decrypt, `B'` recovery, commitment check | Match only |

**Account keys:** Unchanged — account `view_sk` (as X25519 scalar) + account
`ml_kem_dk` (`local_keys.rs`, `wallet2` → `shekyl_scan_and_recover`).

**False positives:** Wrong outputs still incur ML-KEM decap (~255/256 reject
at tag). Inherent to any fixed-width filter. **Adversarial clustering:** gone
(tag not computable without `ml_kem_dk`).

### 4.7 Cost model (benchmark gate)

Not a 256× blowup. **Swap** which leg is universal:

| | Today | FA-6 |
|---|--------|------|
| Per-output universal | ~1 X25519 variable-base mult | ~1 ML-KEM-768 decap |
| On ~1/256 match | + ML-KEM decap + recovery | + X25519 mult + recovery |

ML-KEM-768 decap and X25519 variable-base mult are **same order of magnitude**
(often faster decap on x86 AVX2; plausibly 2–4× slower decap on non-vectorized
mobile — **measure**).

**Merge gate (§8):** Benchmark must show acceptable ratio on **worst-case**
target (non-AVX2 mobile class), not only x86.

### 4.8 Constant-time posture

FA-6 moves **CT ML-KEM decap** into the per-output universal path (today
decap runs only on tag match). Shekyl's posture (64-bit, KyberSlash-era):
production scan relies on CT ML-KEM implementation — reliance **broadens** to
every output; document in FA-9.

X25519 mult remains CT on the **match** path only (unchanged discipline in
`output.rs` comments).

### 4.9 Tag width

Wire remains **1 byte** at genesis (byte-cost choice). Under ML-KEM keying,
adversaries cannot compute the tag at any width, so **privacy no longer caps**
width — widening is a performance tradeoff only and requires a **future HF**
if more than one byte is desired (`crypto::view_tag` is 1 byte today).

---

## 5. Multisig and out-of-scope surfaces

### 5.1 v31 multisig (`tx_extra_pqc_view_tag_hints`)

`multisig_receiving::derive_view_tag_hint` uses a **different** HKDF
(shared secret, no `output_index`). **FA-6 V3.0 scope:** account-output scan
path only (`construct_output` / `scan_output*`).

**Follow-up (FA-6b or multisig PR):** Align multisig hints with ML-KEM-keyed
discipline or document why hints remain on a separate derivation.

### 5.2 C++ / FFI naming

| Artifact | Action |
|----------|--------|
| `ShekylOutputData.view_tag_x25519` | Rename → `view_tag` (FFI + struct) |
| `shekyl_derive_view_tag_x25519` | Replace → `shekyl_derive_view_tag_ml_kem` |
| `shekyl_construct_output` | Emit new derivation |
| `shekyl_scan_and_recover` | Reorder internally (Rust) |

---

## 6. Verification and test vectors

### 6.1 KAT requirements

1. **`docs/test_vectors/PQC_OUTPUT_SECRETS.json`** — replace `view_tag_x25519`
   with `view_tag_ml_kem` per vector; regenerate from reference script.
2. **`tools/reference/derive_output_secrets.py`** — implement
   `derive_view_tag_ml_kem`; remove wire-path `view_tag_x25519`.
3. **Rust KAT tests** — `derivation.rs` / `output.rs` vector tests updated.
4. **Genesis coinbase** — if any fixture embeds view tags, regen per
   `CHANGELOG.md` genesis regen discipline.

### 6.2 Functional tests

| Test | Intent |
|------|--------|
| Round-trip construct → scan | Tag match, full recovery |
| Wrong `ml_kem_dk` | Decap yields wrong ss → tag mismatch → no X25519 |
| View-half only (simulated) | Cannot predict tag without decap secret |
| Low-order Montgomery point | Still rejected before decap (or at X25519 step per ordering) |
| `scan_output_recover` / engine claim | `engine_trait_bench_key_dispatch_baseline_iai` workload still correct |

### 6.3 Negative tests (production guard)

Stub all-zero wire tag must **not** appear from production `construct_output`
(non-fake device). Existing `genRct` stub discipline is orthogonal (enc_label).

---

## 7. Documentation updates (implementation PR)

| File | Update |
|------|--------|
| `docs/POST_QUANTUM_CRYPTOGRAPHY.md` | Replace § view-tag pre-filter; registry row for `view_tag_ml_kem`; remove X25519 wire-tag row |
| `docs/design/SUBADDRESS_UNDER_PQC.md` | §3.7, §4.4 — T6 **closed** by FA-6; cite this spec |
| `docs/FOLLOWUPS.md` | Close FA-6 item; FA-9 propagation sub-item |
| `docs/FCMP_PLUS_PLUS.md` | Cross-ref if view-tag mentioned |
| `CHANGELOG.md` | User-visible: scan cost / privacy posture note |

---

## 8. Benchmark gate (merge requirement)

Before FA-6 implementation merges to `dev`:

1. **iai-callgrind** — new baseline: per-output **decap + tag** vs archived
   per-output **X25519 + tag** (`engine_trait_bench_key_dispatch_baseline_iai`
   family). Document instruction-count ratio.
2. **criterion** — wall-clock on x86 AVX2 **and** one non-AVX2 target
   (document which runner represents “worst wallet target”).
3. **Acceptance** — ratio ≤ agreed bound (propose **≤ 4×** decap-vs-X25519
   on worst target until measured; tighten after first data). If bound
   exceeded: re-evaluate (not: revert to classical tag without T6 waiver in
   `FOLLOWUPS.md`).

Update `docs/PERFORMANCE_BASELINE.md` and `scripts/bench/capture_rust_baseline.sh`
with new row names.

---

## 9. Implementation checklist

| Area | Files (indicative) |
|------|-------------------|
| Derivation | `rust/shekyl-crypto-pq/src/derivation.rs` |
| Construct / scan | `rust/shekyl-crypto-pq/src/output.rs` |
| FFI | `rust/shekyl-ffi/src/lib.rs`, `src/shekyl/shekyl_ffi.h` |
| C++ tx utils | `src/cryptonote_core/cryptonote_tx_utils.cpp`, `wallet2.cpp` |
| Tests | `output.rs` tests, `chaingen` if coinbase paths embed tags |
| Reference | `tools/reference/derive_output_secrets.py` |
| Vectors | `docs/test_vectors/PQC_OUTPUT_SECRETS.json` |

**Pre-genesis migration path:** `rm -rf ~/.shekyl` — no in-wallet tag
transition code.

---

## 10. Reversion clause

**Rejected:** Revert to X25519-keyed wire tag after genesis without a
documented T6 waiver — would reopen quantum and view-half clustering.

**Reopen FA-6 disposition only if:**

1. Benchmark gate (§8) fails on all acceptable targets **and** no
   implementation path meets the bound (e.g. portable decap > 4× X25519
   with no hardware mitigation), **and**
2. Explicit threat-model amendment records accepted T6 residual risk, **and**
3. `AUDIT_SCOPE.md` / FA-9 updated.

**Does not reopen** because “scan felt slow” without §8 data.

---

## 11. Sign-off checklist (spec review)

| # | Item | Pass |
|---|------|------|
| S1 | T6 adversary model matches §2 | ☐ |
| S2 | Out-of-scope surfaces explicit (§2.2) — no oversell | ☐ |
| S3 | HKDF constants in §4.2 accepted | ☐ |
| S4 | Scanner order §4.6 accepted (leg-swap) | ☐ |
| S5 | Benchmark gate §8 binding | ☐ |
| S6 | Multisig deferral §5.1 acceptable for V3.0 | ☐ |
| S7 | FA-9 owner assigned for propagation PR | ☐ |

**After S1–S7:** Implementation PR(s) permitted. Spec changes during
implementation require re-review of affected sections only.
