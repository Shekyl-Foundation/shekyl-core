# FA-6 — PQ-safe view-tag pre-filter (T6 closure)

**Status.** Specification reviewed (2026-06-02): §11 S1–S4, S6–S9 signed; **S5
ratified** (§8.4.1 / §11.1 pins, 2026-06-02). **§3.1 / FA-6b wire locks re-verified
2026-06-07** (§3.1.1, §5.4.1). **§8.7 outcome recorded (2026-06-08):** **fail**
on §8.4 budget (scenarios A and B); **ship FA-6** at genesis per §10 (T6 closed
on verified §3.1 account path). **§10.1 T6 waiver rejected** — Pi 4 classical
counterfactual is slower than FA-6, not faster (§8.7.1). Post-genesis perf
(birthday / checkpointing, faster ML-KEM decap within `fips203` pin) is
wire-preserving follow-up, not a waiver. **Disposition:** adopt at V3.0 genesis —
re-key the on-wire 1-byte pre-filter from classical (`x25519_ss`) to hybrid-leg
(`ml_kem_ss`). **Implementation:** separate PR after spec review; not bundled
with FA-11 (`enc_label` wire) or subaddress removal (FA-2).

**Naming discipline.** APIs and HKDF symbols use **`view_tag_prefilter`** —
the **role** (pre-decap filter byte), not the derivation implementation.
The C++ wire field remains `txout_to_tagged_key.view_tag` (consensus layout
unchanged). Do **not** name symbols `view_tag_ml_kem` (becomes a lie if
keying ever changes again).

**Closure condition (load-bearing).** T6 does not close when “the view tag”
is re-keyed. It closes when **no per-output wire value is computable from a
quantum-recoverable secret** (view scalar `a` or anything recomputable from
it). §3.1 is the **completeness artifact** — every candidate field classified;
implementation must not ship until each row is **verified**, not assumed.

**Provenance.** Threat objective **T6** (`docs/design/SUBADDRESS_UNDER_PQC.md`
§4.3, §4.4). Parallel **adversary** track (§4.7–§4.8); not closed by
End-state 5, 5-T, or R2-F2. Code audit: `rust/shekyl-crypto-pq/src/output.rs`,
`derivation.rs`.

**Related.**

| Doc | Role |
|-----|------|
| `docs/design/SUBADDRESS_UNDER_PQC.md` | T6 impossibility shape (§4.4); FA-6 pointer (§3.7) |
| `docs/POST_QUANTUM_CRYPTOGRAPHY.md` | HKDF registry — **update on implementation** |
| `docs/FOLLOWUPS.md` | Work-item queue; FA-9 propagation after FA-6 lands |
| `docs/design/STAGE_2_KEY_ENGINE_ACTOR.md` | Scan/claim path uses `scan_output_recover` |

**Process.** Spec review before code. Benchmark gate (§8) is a merge
requirement, not advisory.

---

## 1. Problem statement

### 1.1 What the pre-filter does today

Each v3 output carries a **1-byte** `view_tag` in `txout_to_tagged_key`
(`cryptonote_basic.h`). The wallet scanner uses it as a **pre-filter** before
full hybrid recovery:

1. Compute `x25519_ss = view_scalar · R_eph` (Montgomery ECDH).
2. `expected = derive_view_tag_prefilter_classical(x25519_ss, …)` (today:
   `derive_view_tag_x25519`; see §4).
3. If `expected ≠ view_tag_on_chain`, reject (no ML-KEM decap).
4. On match: ML-KEM decap → combine → HKDF → amount/label tags → `B'`
   recovery → commitment check (`C == z·G + amount·H`).

Reference: `scan_output` / `scan_output_recover` in
`rust/shekyl-crypto-pq/src/output.rs` (X25519 block before decap).

### 1.2 Why it leaks (T6)

The tag is **cheap because it avoids ML-KEM** — and **leaks for the same
reason**:

| Attacker capability | Can recompute today's tag? |
|-------------------|----------------------------|
| **Quantum** observer + victim's public address | **Yes** — recover view scalar `a` from public view key; recompute `x25519_ss` per output from on-chain `R_eph`. |
| **Classical** thief of view-half only (no `ml_kem_dk`) | **Yes** — same computation as the honest scanner's first step. |

The tag partitions the chain into “consistent with wallet W's view material”
(all of W's receives plus ~1/256 noise). That is **account-level receive
clustering** — coarser than subaddress identity, but sensitive for T6.

The T6 adversary does **not** care which field leaks — only that **some**
per-output byte is a function of `a`. Re-key the view tag but leave another
classical-derived per-output byte on the wire and clustering moves to that
field (same attack, different column).

### 1.3 What cannot work in place

“You cannot encrypt the view tag in place.” The tag's **leak** and its
**usefulness** are the same property: anything the scanner can compute
cheaply from public tx data + secrets the attacker also holds (or will hold
post-quantum) is not secret from them.

Hardening the tag without changing **which secret** it depends on is
impossible. The move must change the filter's keying material — and must be
checked against **all** per-output wire fields (§3.1).

---

## 2. Threat model

### 2.1 In scope — T6 (closes on full inventory + FA-6)

**Adversary:** Holds the victim's **public** hybrid address (or a leaked
receive address / QR) and either:

- a **quantum** computer (recover view scalar from public view key), or
- a **classical** copy of the **view secret** without `ml_kem_dk`.

**Goal:** Cluster the victim's **incoming** outputs on-chain using any
per-output wire byte computable from `a` (not only the view tag).

**Outcome after FA-6 + verified §3.1:** No such byte remains on the
**account-output** main path. The pre-filter tag gives **zero** information
without `ml_kem_dk` because `ml_kem_ss` requires ML-KEM decap.

### 2.2 Explicitly out of scope (FA-6 does not claim)

Record these in FA-9 / threat-model docs so receive-side closure is not
mistaken for full post-quantum anonymity.

| Surface | Why FA-6 does not address it |
|---------|------------------------------|
| **Spend-side dust / key images** | Uses **spend** secret `b` (from `B`), not view tag. |
| **FCMP++ membership** | Classical DL hardness; spend linkability degrades post-quantum. |
| **T2 counterparty collusion** | Off-chain address compare — not view tag. |
| **Address substitution (phishing)** | R2-F9 pin (`SUBADDRESS_UNDER_PQC.md` §5.7.12). |
| **Passive observer without address** | Never had clustering via tag alone. |
| **v31 multisig `view_tag_hints`** | Separate surface — §5.1 (may be classical linkability **today**, independent of T6). |

**Honest framing:** FA-6 closes the **cheapest account-output receive leak**
when §3.1 is verified. Spend linkability and FCMP++ remain separate tracks.

### 2.3 Pit-of-success boundary

Per `SUBADDRESS_UNDER_PQC.md` §4.7–§4.8: End-state 5 and sentinel-only launch
**do not** relax T6. FA-6 is **adversary-track** work, not user-behavior
mitigation.

---

## 3. Design decision

### 3.1 Per-output wire inventory (completeness artifact)

**Rule:** Classify every per-output value on the wire (or in the RCT binding
blob counted as per-output) by which leg derives it. **Classical-leg** =
recomputable from view scalar `a` without `ml_kem_dk` → **must re-key or
remove** for T6. **Hybrid-leg** = requires `ml_kem_ss` (hence decap) or
`combined_ss` after both legs → **PQ-safe for T6** if check order is
post-decap (or decap is universal).

| Wire field | Location | Leg (today / target) | Derived from | Check order (scanner) | T6 (view-half / quantum `a`) | FA-6 disposition |
|------------|----------|----------------------|--------------|------------------------|------------------------------|------------------|
| **`view_tag`** (pre-filter) | `txout_to_tagged_key` | Classical → **hybrid** | `x25519_ss` → **`ml_kem_ss`** | **Pre-decap** (today) | **Leaks** | **Re-key** (`derive_view_tag_prefilter`) |
| **`amount_tag`** | `rctSigBase` / `enc_amounts` pair | Hybrid | `combined_ss` (`prk` in `derive_output_secrets`) | **Post-decap** | Safe | **Verify** — no change |
| **`enc_amount` (8 B)** | `rctSigBase` | Hybrid | `k_amount` from `combined_ss` | Post-decap decrypt | Opaque XOR; not a tag | **Verify** — no change |
| **`label_tag`** (FA-11) | `rctSigBase` / `enc_labels` | Hybrid (spec) | `combined_ss` — same discipline as `amount_tag` (`SUBADDRESS_UNDER_PQC.md` §5.7.11) | **Post-decap** (must **not** be pre-decap) | Safe **iff** verified post-decap | **Verify** at FA-11 review — **do not assume**; ambiguity “before decrypt” = pre-decap filter → would require re-key |
| **`enc_label` (8 B)** (FA-11) | `rctSigBase` | Hybrid | `k_label` from `combined_ss` | Post-decap decrypt | Opaque ciphertext | **Verify** — no change |
| `view_tag_combined` | **Not on wire** | Hybrid | `combined_ss` | Internal only | N/A | No wire action |
| KEM CTs (`R_eph`, ML-KEM) | `tx_extra` | Public / ciphertext | — | — | No clustering via tag alone | No FA-6 change |
| `output_key`, commitment, `pqc_pk`, `h_pqc` | tx / RCT | Public | — | — | No | No FA-6 change |

**Implementation gate:** Before FA-6 merges, sign off §3.1 rows marked
**Verify** with code pointers (`dev` post–PR #100 for `label_tag` /
`enc_label`; `output.rs` + `derivation.rs` for `amount_tag`). A single
classical pre-decap byte left on the wire **defeats** the view-tag re-key.

#### 3.1.1 Code verification record (2026-06-07, `dev` post–PR #101)

Re-audit traced each on-wire tag to live derivation + scanner order (not
table-only). `derive_view_tag_x25519` is **absent** from `rust/`; account path
uses `derive_view_tag_prefilter` (`derivation.rs`, `output.rs`).

| §3.1 row | Leg | Scanner order (evidence) | T6 disposition |
|----------|-----|---------------------------|----------------|
| `view_tag` | Hybrid (`ml_kem_ss`) | `ml_kem_decap_prefilter_with_parsed_dk` → tag compare → reject wipes `ml_kem_ss` (`output.rs:486–516`, `600–607`) | **Verified — re-keyed** (`derive_view_tag_prefilter`, construct `output.rs:278`) |
| `amount_tag` | Hybrid (`combined_ss`) | Decap → X25519 → `derive_output_secrets` → compare (`output.rs:626–631`) | **Verified safe** |
| `label_tag` | Hybrid (`combined_ss`) | Same; compare before `decrypt_label_plaintext` (`output.rs:634–637`, `650`) | **Verified safe** |
| `enc_label` | Hybrid (`k_label`) | Post-decap decrypt only | **Verified safe** |
| `view_tag_hints` (FA-6b) | Hybrid (`ss_i`) | Multisig: decap → `derive_view_tag_hint` compare (`multisig_receiving.rs:269–274`) | **Separate audit — §5.4.1** |

Derivation anchors: `amount_tag` / `label_tag` from `derive_output_secrets`
(`derivation.rs:223–232`, salt `shekyl-output-derive-v1`); `view_tag_prefilter`
from `HKDF_SALT_VIEW_TAG_PREFILTER` + `ml_kem_ss` only (`derivation.rs:263–265`).
C++ wire: `od.view_tag_prefilter` (`cryptonote_tx_utils.cpp`, `wallet2.cpp`).

**S2 sign-off:** no reopened row; no further design unless a new classical
pre-decap byte is found in code review.

### 3.2 Multisig hints (separate track — do not fold into FA-6 closure)

| Surface | Location | Concern |
|---------|----------|---------|
| **`tx_extra_pqc_view_tag_hints`** | `tx_extra` blob (`PQC_MULTISIG.md` §7.1) | `derive_view_tag_hint(ss_i)` — **no `output_index` in HKDF**; one byte per participant per output. **Not** the same as account `view_tag`, but may be **classical linkability today** if hints are predictable without decap or **constant across a wallet's outputs** (present-day 1/256 linker — **no view key required**). |

**Disposition:** **FA-6b** (or dedicated multisig PR) — standalone audit:
per-output variation, decap requirement, classical computability from `a`.
Worse-than-T6 if per-wallet-constant. **FA-6 V3.0 account path does not
close multisig hints.**

### 3.3 Adopt / reject (pre-filter)

**Adopt:** Re-key the on-wire pre-filter to **`ml_kem_ss`** with new HKDF
salt/label (§4.2); scanner leg-swap (§4.6).

**Reject:**

| Alternative | Reason |
|-------------|--------|
| Keep classical X25519-keyed pre-filter | T6 remains open. |
| Drop pre-filter entirely | PQ-safe but no filter — still need decap per output for PQ-safe ownership (§4.7); does not avoid universal decap. |
| Put `view_tag_combined` on wire | Requires `combined_ss` → decap + X25519 before compare; no pre-decap win. |
| Post-match `view_tag_combined` compare | **Rejected** — redundant with commitment opening (§4.4). |
| Encrypt / blind classical tag | Does not change keying. |
| Widen tag to 2+ bytes for sync speed | Decap dominates; width does not fix initial-sync cost (§4.7, §8). |

---

## 4. Cryptographic specification

### 4.1 Wire format (unchanged)

| Field | Location | Size | Consensus |
|-------|----------|------|-----------|
| `view_tag` | `txout_to_tagged_key.view_tag` | **1 byte** | **Not validated** — wallet convention only. |

No transaction version bump. No change to `enc_amounts`, `enc_labels`, KEM
layout, or FCMP++ proofs.

**Genesis lock:** Derivation is a **network-wide convention from block 0**.
Genesis coinbase outputs carry view tags; changing derivation changes those
bytes and therefore the **genesis block hash**. This is **strictly
pre-genesis** work — not a post-launch migration.

### 4.2 Pre-filter derivation (normative)

Replace `derive_view_tag_x25519` on the wire path with:

```text
view_tag_prefilter = first_byte(
  HKDF-Expand(
    prk = HKDF-Extract(salt = HKDF_SALT_VIEW_TAG_PREFILTER, ikm = ml_kem_ss),
    info = LABEL_VIEW_TAG_PREFILTER || output_index_le64,
    len = 32
  )
)
```

**Constants (new):**

| Symbol | Value | Length |
|--------|-------|--------|
| `HKDF_SALT_VIEW_TAG_PREFILTER` | `shekyl-view-tag-prefilter-v1` | 28 bytes |
| `LABEL_VIEW_TAG_PREFILTER` | `shekyl-view-tag-prefilter` | 24 bytes |
| `output_index_le64` | Output index, little-endian | 8 bytes |

**Hash:** HKDF-SHA512 (same as existing output derivations).

**Input `ml_kem_ss`:** 32-byte ML-KEM-768 shared secret (FIPS 203), same
encoding as `combine_shared_secrets`.

**Byte identity (encaps vs decaps):** The wire tag uses the raw 32-byte
`SharedSecret::into_bytes()` from FIPS 203 ML-KEM-768 — the same encoding
`construct_output` takes from `encaps_from_seed` / encaps and `derive_view_tag_prefilter`
takes from `try_decaps`. `combine_shared_secrets` already requires encaps and
decaps halves to match; FA-6 now keys the pre-filter on that half **independently**,
so the encoding must stay identical across construct, scan, and KAT vectors (not
an inherited assumption from `combined_ss` alone).

**Rust API:** `derive_view_tag_prefilter(ml_kem_ss, output_index) -> u8`.

### 4.3 Deprecated (wire path)

| Symbol | Status after FA-6 |
|--------|-------------------|
| `HKDF_SALT_VIEW_TAG_X25519` | **Deleted** (grep-clean) |
| `derive_view_tag_x25519` | **Deleted** or test-only until KAT removal |
| `view_tag_x25519` in `OutputData` / FFI | → `view_tag_prefilter` (semantic rename) |

### 4.4 `view_tag_combined` — not on wire; no post-match check

`view_tag_combined` stays in `derive_output_secrets` from **`combined_ss`**
— internal HKDF material, **not** the wire pre-filter. FA-6 does **not** put
it on wire.

**Do not** add a post-match `view_tag_combined` integrity compare. After a
pre-filter match the scanner derives `combined_ss`, then `z`, then verifies
`C == z·G + amount·H`. A wrong `combined_ss` yields wrong `z` and the
commitment **does not open** — `combined_ss` correctness is already bound.
An extra HKDF compare is redundant cost and “more crypto” without threat-model
gain (same discipline as rejecting AEAD on `enc_label` for integrity).

### 4.5 PRF domain separation (prefilter vs `combined_ss` expansions)

The pre-filter byte and `combined_ss`-derived secrets (`amount_tag`,
`label_tag`, `k_amount`, `z`, …) are **all** functions of key material that
includes `ml_kem_ss`, but **must not** be treated as interchangeable.

**Constants are pinned** in §4.2 (`HKDF_SALT_VIEW_TAG_PREFILTER`,
`LABEL_VIEW_TAG_PREFILTER`) — not TBD.

**Distinct derivation paths (load-bearing):**

| Wire / internal | IKM | HKDF-Extract salt | Expand label prefix |
|-----------------|-----|-------------------|---------------------|
| **Pre-filter** (`view_tag` on wire) | `ml_kem_ss` only | `shekyl-view-tag-prefilter-v1` | `shekyl-view-tag-prefilter` |
| **`combined_ss` secrets** (`amount_tag`, `label_tag`, `z`, …) | `combined_ss` | `shekyl-output-derive-v1` | `shekyl-output-*` family |

The pre-filter never uses `HKDF_SALT_OUTPUT_DERIVE` or `combined_ss` as IKM;
`combined_ss` expansions never use the pre-filter salt/label. `bare x25519_ss`
does not feed any wire tag after FA-6.

**Argument (load-bearing for reviewers):** They are **independent HKDF-Expand
instances** under distinct `(salt, info)` pairs — standard PRF domain
separation. Revealing **one byte** of the pre-filter expansion (the wire tag)
does **not** weaken sibling secrets derived from `combined_ss`, because the
Expand inputs differ: different IKM, Extract salt, and `info` labels. This is
the same discipline as today (distinct labels under `HKDF_SALT_OUTPUT_DERIVE`);
FA-6 adds a **separate** Extract domain keyed on `ml_kem_ss` only.

**Implementation obligations:**

1. `HKDF_SALT_VIEW_TAG_PREFILTER` must be **distinct** from
   `HKDF_SALT_OUTPUT_DERIVE` (`shekyl-output-derive-v1`) and from
   `HKDF_SALT_VIEW_TAG_X25519` (removed).
2. `LABEL_VIEW_TAG_PREFILTER` must be **distinct** from
   `LABEL_OUTPUT_VIEW_TAG_COMBINED`, `LABEL_OUTPUT_AMOUNT_TAG`, and every
   other `LABEL_*` over `combined_ss` in `derivation.rs`.
3. Registry row in `POST_QUANTUM_CRYPTOGRAPHY.md` on implementation.

### 4.6 Sender (`construct_output`)

1. X25519 ephemeral + `x25519_raw_ss`.
2. ML-KEM encaps → `ml_kem_ss`, `ml_kem_ct`.
3. **`view_tag = derive_view_tag_prefilter(ml_kem_ss, output_index)`** ← change
4. `combined_ss = combine(x25519_raw_ss, ml_kem_ss)`.
5. `derive_output_secrets(combined_ss, …)` — unchanged.

### 4.7 Scanner (`scan_output`, `scan_output_recover`)

| Step | Operation | Every output? |
|------|-----------|----------------|
| 1 | Validate ML-KEM CT length; **ML-KEM decap** with account `ml_kem_dk` | **Yes** |
| 2 | `expected = derive_view_tag_prefilter(ml_kem_ss, output_index)`; compare to wire `view_tag` | **Yes** |
| 3 | On mismatch: return (no X25519, no combine) | — |
| 4 | X25519 ECDH (low-order rejection unchanged) | **~1/256 match** |
| 5 | `combined_ss = combine(…)` | Match only |
| 6 | `amount_tag` / `label_tag` check, decrypt, `B'`, **commitment open** | Match only |

**False positives:** ~255/256 outputs still pay **decap** — inherent to any
fixed-width filter keyed on a secret only the owner has.

### 4.8 Initial-sync cost (what the constant multiplies)

“Leg swap” is accurate but **undersells** the cost: the expensive operation
moves from **~1/256 of outputs** (classical mult) to **every output**
(ML-KEM decap). For a privacy coin there is **no server-side filtering** — a
fresh wallet scans **full chain history**. **Initial sync time** on a
realistic chain size is the metric that matters, especially on **non-AVX2
mobile** where decap-per-output can turn a multi-minute sync into much longer.

| | Today | FA-6 |
|---|--------|------|
| Universal per output | ~1 X25519 variable-base mult | ~1 ML-KEM-768 decap |
| On ~1/256 match | + decap + full recovery | + X25519 mult + recovery |

**No cheaper PQ filter:** Any owner-checkable per-output pre-filter requires
a PQ-safe secret. The only PQ-safe receive secret is **`ml_kem_dk`**; using
it means **decap**. Decap-per-output is **intrinsic**, not an implementation
shortcut. Widening the tag does **not** materially help — decap dominates;
width only trims the already-rare X25519-on-match step.

**Tradeoff (pre-genesis, effectively irreversible):** **PQ receive
unlinkability (close T6 on the main path)** vs **initial-sync wall-clock** on
worst wallet targets. Genesis-locks the convention; failing the bench does
**not** mean “skip FA-6” — it means choose **slow sync** or **accept T6 as a
~permanent property** (closable later only via coordinated hard fork).

### 4.9 Constant-time posture and decap totality

FA-6 runs **CT ML-KEM decap on every output** (today decap runs on ~1/256).
Document broadened reliance in FA-9.

**Load-bearing:** FIPS-203 decaps must be **total** on arbitrary 1088-byte
ciphertexts (implicit rejection → pseudorandom `ss`, tag mismatch, continue).
Universal decap exposes **adversary-authored** garbage CT on every scan;
`try_decaps` must **never panic**. Existing `fuzz_kem_decapsulate` is
baseline; add explicit **scan-path** KAT: random/garbage CT → no panic, clean
reject (§6.4).

X25519 mult stays CT on the **match** path only.

### 4.10 Tag width

Wire stays **1 byte** at genesis. Under PQ keying, adversaries cannot compute
the tag at any width — widening is a **performance-only** future HF, not a
T6 knob.

---

## 5. Multisig and FFI

### 5.1 v31 multisig (`tx_extra_pqc_view_tag_hints`) — FA-6b

See §3.2. Account-output FA-6 **does not** close this surface. Schedule
standalone review: hint derivation, per-output entropy, classical
computability, present-day linking without view key.

### 5.2 C++ / FFI naming

| Artifact | Action |
|----------|--------|
| `ShekylOutputData.view_tag_x25519` | → `view_tag_prefilter` (FFI may keep wire alias comment) |
| `shekyl_derive_view_tag_x25519` | → `shekyl_derive_view_tag_prefilter` |
| `shekyl_construct_output` / `shekyl_scan_and_recover` | Emit / consume new derivation |

### 5.3 Derivation single-site (Rust) — no C++ re-derive

Per Shekyl policy: new crypto lives in Rust; C++ orchestrates via FFI and must
**not** hold a second derivation of the wire tag.

**Canonical Rust sites (construct, scan, genesis must all use these):**

| Operation | Site | Notes |
|-----------|------|-------|
| Wire tag derivation | `shekyl_crypto_pq::derivation::derive_view_tag_prefilter` | Only HKDF definition |
| Construct path | `output::construct_output` | After ML-KEM encaps |
| Scan path | `output::ml_kem_decap_prefilter_with_parsed_dk` → `scan_output_with_ml_kem_dk` / `scan_output_recover_with_ml_kem_dk` | Universal decap first |
| C++ coinbase / transfer | `shekyl_construct_output` (FFI) | Returns `view_tag_prefilter` in `ShekylOutputData` |
| C++ wallet scan | Rust engine / `shekyl_scan_*` FFI | Consumes wire tag; no local HKDF |
| Test reference | `tools/reference/derive_output_secrets.py` | Must match Rust byte-for-byte |

**C++ must not** call `local_derive_view_tag` / Keccak view-tag paths for v3
account outputs. Production coinbase and transfer construction use
`shekyl_construct_output` and copy `od.view_tag_prefilter` onto the wire
(`cryptonote_tx_utils.cpp`, `chaingen` manual coinbase). A genesis builder that
re-derived in C++ with the old salt would produce tags the FA-6 scanner rejects —
genesis regen is only valid when construction goes through the Rust FFI path above.

**Drift class:** Same failure mode as `FCMP_REFERENCE_BLOCK_MIN_AGE` /
cbindgen-constant skew — Rust writes new tag, C++ checks old tag. Grep gate:
no production `derive_view_tag` / `HKDF_SALT_VIEW_TAG_X25519` outside deletion
targets and test-only legacy.

### 5.4 Multisig genesis posture (FA-6 vs FA-6b)

FA-6 closes T6 on the **account-output** path only. **FA-6b**
(`tx_extra_pqc_view_tag_hints`) remains open.

**V3.0 genesis posture (conscious acceptance, not silent inheritance):**

- **Single-sig / account outputs:** T6 closed by FA-6 at genesis (PQ-keyed
  `view_tag` pre-filter).
- **Multisig:** Full FROST multisig ship-readiness is **V3.1** per
  `WALLET_REWRITE_PLAN.md` and `AUDIT_SCOPE.md` (multisig-specific audit surface
  post-genesis). V3.0 may carry scaffold / non-user-facing multisig code, but
  **no genesis asymmetry** for end-user multisig wallets at launch — there is no
  “multisig wallet type” shipping at V3.0 with a weaker T6 surface than
  single-sig.
- **FA-6b** must land **before** multisig is user-shippable (V3.1), not before
  single-sig genesis.

If multisig were ever promoted to V3.0 user-shippable without FA-6b, that would
be an explicit product/security decision recorded in `V3_WALLET_DECISION_LOG.md`,
not an accident of scheduling.

#### 5.4.1 FA-6b genesis wire disposition (2026-06-07)

Code audit of `tx_extra_pqc_view_tag_hints` / `derive_view_tag_hint`
(`multisig_receiving.rs`, `PQC_MULTISIG.md` §7.1). **Genesis-visible wire**
(format + inclusion in multisig scaffold); **not** folded into FA-6 T6 closure.

| Question | Finding |
|----------|---------|
| Computable from view scalar `a` without decap? | **No** — hint compare after `kem.decapsulate` |
| Per-output variation? | **Yes** — per-output KEM randomness includes `output_index_in_tx` + participant index (`LABEL_MULTISIG_KEM`) |
| Passive 1-byte wire linker without view key? | **Possible** — public metadata; distinct from T6 (quantum-recoverable secret) |
| V3.0 user-shippable multisig? | **No** — FROST multisig V3.1 per `WALLET_REWRITE_PLAN.md` |
| Genesis posture | Scaffold may emit hints; **conscious acceptance** at genesis; hint re-key (if needed) before V3.1 multisig ships |

**Round-3 wire-lock artifact:** this table + §5.4 bullets. **Implementation /
re-key** of hints remains V3.1 (FA-6b track), not deferred as an unsigned
genesis decision.

---

## 6. Verification and test vectors

### 6.1 KAT requirements

1. **`PQC_OUTPUT_SECRETS.json`** — `view_tag_prefilter` per vector (replace
   `view_tag_x25519`).
2. **`tools/reference/derive_output_secrets.py`** — `derive_view_tag_prefilter`.
3. **Rust KAT tests** — `derivation.rs` / `output.rs`.
4. **Genesis coinbase** — regen if fixtures embed tags (`CHANGELOG.md`).

### 6.2 Functional tests

| Test | Intent |
|------|--------|
| Construct → scan round-trip | Pre-filter match + recovery |
| Wrong `ml_kem_dk` | Wrong `ml_kem_ss` → tag mismatch |
| View-half only (simulated) | Cannot predict tag without decap |
| Low-order Montgomery point | Rejected on match path |
| §3.1 verification tests | `amount_tag` / `label_tag` checked only after decap in code |
| §6.5 tag-mismatch wipe | `ml_kem_ss` zeroized on universal-decap reject |

### 6.3 Negative tests (production guard)

Stub all-zero wire tag must not ship from production `construct_output`.

### 6.4 Decap robustness (adversarial CT)

| Test | Intent |
|------|--------|
| Garbage / random 1088-byte CT | `scan_output*` returns `Err`, **no panic** |
| Fuzz target extension | Align with `fuzz_kem_decapsulate`; document scan entry |
| Wrong-length CT | Rejected before decap (existing) |

### 6.5 Universal-decap path zeroization (merge gate — not §6.4)

§6.4 covers panic-freedom on adversarial ML-KEM ciphertext. It does **not**
cover the FA-6-specific residue regression: after FA-6, **every** scanned output
runs ML-KEM decap; **~255/256** reject at the tag compare. Pre-FA-6, decap ran
on ~1/256 outputs — an early-return that skipped wiping `ml_kem_ss` was rare;
post-FA-6 it is the **dominant** path.

**Requirement (implementation PR, before merge):**

1. `ml_kem_ss` on the universal-decap path is `Zeroizing<[u8; 32]>` (or
   equivalent `ZeroizeOnDrop`).
2. Tag-mismatch `Err` **explicitly** zeroizes `ml_kem_ss` before return (not
   only reliance on drop order).
3. Test: wrong-key / tag-mismatch scan asserts pre-filter `Err` **and**
   observability that wipe ran (`output.rs`:
   `ml_kem_ss_wiped_on_view_tag_prefilter_mismatch`).

Functional tests still pass if wipe is broken; this gate is memory-discipline,
not correctness.

---

## 7. Documentation updates (implementation PR)

| File | Update |
|------|--------|
| `docs/POST_QUANTUM_CRYPTOGRAPHY.md` | Pre-filter registry; domain-separation row |
| `docs/design/SUBADDRESS_UNDER_PQC.md` | §3.7 — T6 closed on **verified** §3.1 + FA-6 |
| `docs/FOLLOWUPS.md` | Close FA-6; FA-6b multisig hints; FA-9 propagation |
| `CHANGELOG.md` | Initial-sync / privacy tradeoff (user-visible) |
| `docs/design/WALLET_REWRITE_PLAN.md` | Genesis-affecting wire lock before Phase 7.7 stressnet (§ cross-cutting) |

---

## 8. Benchmark gate (merge requirement)

Per-output micro-benchmarks are **necessary but not sufficient**. The merge
gate is a **pre-committed absolute UX budget** on a **forward-dated mature
chain** and a **fixed slow reference device**. FA-6 either fits under that
budget or triggers an explicit §10 choice — it does **not** set the budget
from whatever the benchmark returns.

### 8.1 Anti-patterns (rejected ceilings)

| Rejected | Why |
|----------|-----|
| “≤ N× classical baseline” | Self-justifying — if FA-6 is 3× slower, gravity sets N=3 after the fact. Measures the change against itself, not human tolerance. |
| Genesis-era chain size only | Cost is ~linear in outputs scanned; benching a tiny chain hides year-3 pain. |
| “Non-AVX2 mobile” without a floor | ~10× spread; passes on a flagship, fails on the low-end device privacy users actually carry. |
| Single sync number for all cases | FA-6 cost hits **deep restore** hardest; incremental sync stays cheap. One number over-constrains restore or under-protects incremental. |
| `O_per_block` chosen to make bench pass | Same gravity as N× baseline, relocated: lowering chain size after seeing restore time protects the budget while leaving the scenario soft. |
| Computing implied restore time before ratifying `O_per_block` | Lets chain assumptions absorb bench results. Pin `O_per_block` **blind**, same as §8.4 ceilings. |

### 8.2 Reference device (conservative floor)

**Pinned class:** **Raspberry Pi 4 Model B, 4 GB RAM** (Cortex-A72, ARMv8.0-A,
stock 1.5 GHz — **not** Pi 5).

**Why Pi 4, not a phone or Pi 5:**

- **Fixed floor that ages well.** Phone references drift upward every product
  cycle; Pi 4 is a stationary slow point. Faster user hardware improves UX
  under the same committed budget; the budget does not silently tighten as
  flagships get faster.
- **Conservative ML-KEM path.** A72 has v8.0 crypto extensions (AES, SHA2) but
  **not** ARMv8.2 SHA3; ML-KEM’s SHAKE/Keccak runs in software. Workspace
  `fips203 = 0.4.3` is portable Rust with no hand-tuned NEON path in-tree —
  **confirm on hardware during bench** (do not assume; measure). If decap is
  acceptable on Pi 4, faster SHA3/AVX2 targets are expected to beat the floor.

**Thermal condition (mandatory for reproducibility):** active cooling
(heatsink + fan) or documented equivalent; state ambient. Sustained full-restore
load throttles a bare Pi 4 within minutes — uncooled runs are **worse** than
the gate; budget headroom must cover throttled real hardware.

**Environment pins** (extend `docs/PERFORMANCE_BASELINE.md` frozen-baseline
discipline): OS (Pi OS 64-bit **or** Ubuntu 22.04+ ARM64 — pick one at bench
start and hold), `rustc` target `aarch64-unknown-linux-gnu`, documented
`RUSTFLAGS` / `target-cpu`, **no overclock**.

**Node + wallet co-residence:** Many self-hosters run `shekyld` and the wallet
on the same Pi 4. The **gate** benches **wallet scan only** (clean, reproducible).
The spec **requires** stating that node+wallet on one board is slower and that
absolute budgets include headroom for that deployment — not discovered only
after sign-off.

### 8.3 Mature chain scenario (forward-dated, pre-FA-6)

Bench against a **synthetic mature chain**, not genesis size. Privacy cost
scales with outputs the wallet must scan; the chain users restore against in
year 3+ is the honest workload.

**Illustrative arithmetic only (not load-bearing):** 5-year horizon and
`T_block = 120` s (Shekyl HF1 `DIFFICULTY_TARGET_V2`) imply
`N_blocks ≈ 1.31×10⁶`. The **ratified** values are `H_horizon`, `T_block`, and
`O_per_block` in the S5 record — not this worked example.

| Symbol | Meaning | Ratification |
|--------|---------|--------------|
| `H_horizon` | Calendar horizon from genesis | S5 sign-off |
| `T_block` | Target block time (consensus) | S5 sign-off (must match HF1) |
| `N_blocks` | `⌊ H_horizon_seconds / T_block ⌋` | Derived from above |
| `O_per_block` | **Stress** v3 outputs scanned per block (see §8.3.1) | S5 sign-off **before** any restore-time back-calculation |

**Total outputs in mature scenario:** `N_outputs = N_blocks × O_per_block`.

#### 8.3.1 `O_per_block` — same hindsight-proofing as §8.4

The wall-clock ceilings are armored against rewrite; **`O_per_block` is the
soft underbelly** if it can be tuned after bench results. It must be pinned with
the **same discipline** as the §8.4.1 ceilings (45 s / 20 min).

**Required at S5** (written record in this doc or a one-page addendum — same
artifact as §8.4 ceilings):

1. **Independent derivation** — `O_per_block` comes from an external basis,
   documented in the S5 ratification artifact, e.g.:
   - Shekyl economic / throughput projections (`docs/` economics models,
     block-fullness assumptions), **stress-inflated**; and/or
   - A stated multiple of a **comparable chain’s mature** outputs-per-block
     (cite source + multiple).
   Not a round number chosen because it makes restore math pass.

2. **Pessimistic pin, not median** — The chain only grows; the tag is
   genesis-locked; you cannot tighten `O_per_block` later without a hard fork.
   **Underestimating** `O_per_block` ⇒ budget violated by year 3 with no
   fork-free fix. **Overestimating** ⇒ headroom you did not strictly need.
   Asymmetry favors the **high stress** value.

3. **Blind ordering** — Pin `O_per_block` and derive `N_outputs` **before**
   anyone computes “implied restore time on Pi 4” from FA-6 micro-benches.
   Same rule as §8.4: scenario inputs are not reverse-engineered from outcomes.

**Birthday / restore-height (product mitigation, not gate assumption):** Normal
wallets default to scanning from `restore_height` / wallet birthday — far
fewer outputs than scenario B. That mitigation **reduces** user-visible restore
time but **does not** replace pinning the gate to the worst case (§8.4 B).

### 8.4 Pre-committed absolute budgets (before FA-6 numbers exist)

These are **product requirements**, pinned at S5 **before** FA-6 bench results
are used for a merge decision. Compare measured time to these ceilings
**without renegotiating the ceilings** to match the measurement.

**Ratified ceilings** (§8.4.1 — pinned 2026-06-02 before any FA-6 decap bench):

| Scenario | What it models | Who cares | Ratified ceiling (Pi 4, mature `N_outputs`) |
|----------|----------------|-----------|---------------------------------------------|
| **A — Incremental sync** | Outputs since last successful sync (`W_offline = 7` days → `A_outputs = 5,040 × O_per_block`; see §8.4.1) | Every app open | **≤ 45 s** wall-clock |
| **B — Deep restore (genesis worst case)** | **`restore_height = 0`** (genesis-era wallet): scan **all** `N_outputs` from chain start — true genesis restore, not a recent birthday | Rare, one-time; worst case for FA-6 | **≤ 20 min** wall-clock |

Scenario A must remain “snappy”; scenario B may be minutes because users
tolerate one-time restore but not per-open delay. FA-6’s universal decap targets
**B**; **A** should pass with margin if `ΔN` is small.

**Note (A only, not ratified):** A **20 s** ceiling for scenario A was flagged
for consideration if daily-reopen UX matters more than the 7-day offline window;
the ratified value remains **45 s** until an explicit S5 amendment.

#### 8.4.1 Ratification record — FA-6 sync budgets (pinned before bench harness)

**Pinned by:** radawson  
**Date:** 2026-06-02

**Sequencing attestation:** These values were fixed **before** any FA-6 decap
benchmark existed. They were **not** derived from, adjusted to, or anchored
against any measured FA-6 cost. Amendment after this date requires a dated note
stating the reason; “the benchmark exceeded the ceiling” is **not** a valid
reason to raise a ceiling or lower `O_per_block`.

**Chain inputs**

| Symbol | Ratified value | Citation / derivation |
|--------|----------------|---------------------|
| `T_block` | **120 s** | `config/consensus_constants.json` → `daa_target_seconds`; generated `SHEKYL_DAA_TARGET_SECONDS` (`static_assert` in `tests/core_tests/block_reward.cpp`, RPC wire contract in `tests/unit_tests/rpc_target_wire_contract.cpp`) |
| `H_horizon` | **5 years** | S5 calendar horizon (forward-dated mature chain) |
| `N_blocks` | **1,314,900** | `⌊ (5 × 365.25 × 86,400) / T_block ⌋` |
| `B_cap` | **600,000 B** | Sustained cumulative block-weight cap at long-term median floor: `m_current_block_cumul_weight_limit = 2 × effective_median` (`src/cryptonote_core/blockchain.cpp` ~5195); at HF1 minimum median `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5` = **300,000** B (`src/cryptonote_config.h` ~60) ⇒ **600 KiB** stress cap |
| `W_out` | **1,500 B** | **Stress lower bound** on marginal **scanned** bytes per v3 account output in a full block (pin-high-`O_per_block` direction per §8.3.1): hybrid KEM material **1,120 B** per output in `tx_extra` tag `0x06` (`docs/CHANGELOG.md`, `docs/POST_QUANTUM_CRYPTOGRAPHY.md`) plus `txout` + RCT row lower bound — **not** a measured prototype tx; revisit only via dated S5 amendment if FA-11 wire audit shows higher marginal |
| `O_per_block` | **400** | `⌊ B_cap / W_out ⌋` = `⌊ 600,000 / 1,500 ⌋` |
| `N_outputs` (scenario B) | **525,960,000** | `N_blocks × O_per_block` |

**Scenario A — incremental**

| Symbol | Value |
|--------|-------|
| `W_offline` | **7 days** |
| `A_outputs` | **2,016,000** (= `5,040 × O_per_block`; `5,040 = ⌊ 7 × 86,400 / T_block ⌋`) |
| `T_ceil_A` | **45 s** |

**Scenario B — deep restore (true genesis, no birthday)**

| Symbol | Value |
|--------|-------|
| Outputs | Full `N_outputs` = **525,960,000** |
| `T_ceil_B` | **20 min** |

Birthday / `restore_height` is a named mitigation for the common case; **B**’s
budget must hold for genesis restore regardless.

**Gate**

| Symbol | Value |
|--------|-------|
| `M_margin` | **20%** (clean pass: `T_meas ≤ T_ceil × 0.80`; marginal: `0.80 < T_meas / T_ceil ≤ 1.00` → §10.2 record) |
| Reference device | §8.2 Pi 4 4GB, active cooling, USB3 SSD, stock 1.5 GHz, pinned toolchain, wallet-only; node co-residence headroom in `M_margin` |
| Measure / accept separation | **Temporal** — this record predates the harness |

**Implied clean-pass targets (derived, not separate pins):** scenario A **≤ 36 s**;
scenario B **≤ 16 min** wall-clock.

**Scenario B is intentionally the conservative floor** (parallel to Pi 4):
pin “genesis wallet, restore from genesis on Pi 4.” A wallet created recently
with a high birthday scans less — that is a **named product mitigation**, not
an assumption baked into B. Under-protecting B by silently assuming recent
birthday would leave genesis-era restores unbounded at year 3+.

**Scope — account path only (FA-6):** These ceilings apply to **single-sig
account-output** scan (`construct_output` / `scan_output*`). **FA-6b**
(multisig `view_tag_hints`, possible extra decaps on multisig scan) is
**budgeted separately** when FA-6b lands — do not assume multisig inherits
Scenario A/B silently.

### 8.5 Measurement protocol (two benches)

Run **both**; neither alone is sufficient.

1. **Micro — decap + pre-filter (FA-6-specific)**  
   Inputs in memory; loop `N_outputs` (or `ΔN` for scenario A) of ML-KEM decap
   + `derive_view_tag_prefilter` + compare; no daemon, no disk. Isolates CPU.
   **Harness:** `cargo run --release -p shekyl-crypto-pq --bin fa6_decap_prefilter_gate`
   (`--scenario smoke|a|b`); Pi capture via `scripts/bench/fa6_pi4_gate.sh`.
   Archive as `fa6_decap_prefilter_throughput_pi4` in `PERFORMANCE_BASELINE.md`.

2. **End-to-end restore (integration)**  
   Wallet scan path over synthetic or replayed chain data on **USB3 SSD**
   (not slow SD-card I/O — otherwise I/O swamps decap). Same scenarios A/B.
   Reports wall-clock for the gate record.

**Secondary regression guards** (do not set the UX ceiling):

- **iai-callgrind** — per-output decap+tag vs archived X25519+tag instruction
  count (drift detector).
- **criterion** — per-output decap on Pi 4 (supports extrapolation sanity-check).

### 8.6 Process (artifact discipline, not headcount)

Pre-genesis team size does not change the anti-hindsight rule. One developer
can perform every step; what matters is **order** and **written pins**:

1. Record §8.4 ceilings + §8.3.1 `O_per_block` derivation + `N_outputs` in writing.
2. Run §8.5 benches.
3. Compare results to the recorded pins **without** revising pins to fit.

Self-justification is blocked by **dated artifacts**, not by assigning different
people to “producer” and “acceptor.”

### 8.7 Gate outcome (clean pass, marginal pass, fail)

**`M_margin`** ratified at **20%** (§8.4.1): required headroom below the ceiling
so a “pass” is not a deferred failure as the chain grows past `H_horizon` or
under throttled hardware.

For each scenario, let `T_meas` = measured wall-clock, `T_ceil` = §8.4 ceiling.

| Outcome | Condition | Action |
|---------|-----------|--------|
| **Clean pass** | `T_meas ≤ T_ceil × (1 − M_margin)` | FA-6 merge permitted (both scenarios). |
| **Marginal pass** | `T_ceil × (1 − M_margin) < T_meas ≤ T_ceil` | **Not** a silent green. Requires **margin-acceptance record** on file (same formality as §10.1): states measured time, ceiling, `M_margin`, `N_outputs` / `O_per_block` pinned, and that thin headroom is **consciously accepted** because chain growth past horizon may exceed budget without fork-free remedy. Security + product sign-off. |
| **Fail** | `T_meas > T_ceil` | **Not** “defer FA-6.” Choose §10: ship FA-6 (accept cost) **or** §10.1 T6 waiver. |

#### 8.7.1 Recorded outcome (2026-06-08)

Micro gate (§8.5.1) on reference device **skl-pi** (Pi 4 Model B, 4 GB, active
cooling, USB3 SSD host, wallet-only). Harness:
`rust/shekyl-crypto-pq/examples/fa6_decap_prefilter_gate.rs` with
`--path fa6|classical`; Pi capture via `scripts/bench/fa6_pi4_gate.sh`. Full
matrix in `PERFORMANCE_BASELINE.md` §FA-6.

| Host | Path | Scenario | `T_meas` | ns/out | `T_ceil` | `gate_outcome` |
|------|------|----------|----------|--------|----------|----------------|
| skl-pi | fa6 | smoke | — | 271,505 | — | informational |
| skl-pi | fa6 | A | 550.4 s | 273,023 | 45 s | **fail** |
| skl-pi | fa6 | B | *(pending capture)* | ~273,000 (extrap. from A) | 20 min | **fail** (expected) |
| skl-pi | classical | smoke | — | 639,791 | — | informational |
| skl-pi | classical | A | 1,289.9 s | 639,834 | 45 s | **fail** |
| skl-pi | classical | B | *(pending capture)* | ~640,000 (extrap. from A) | 20 min | **fail** (expected) |

Classical counterfactual captures used `RUSTFLAGS=-C target-cpu=cortex-a72`
per §8.2; FA-6 scenario A used default `RUSTFLAGS` on Pi (ratio ~2.3× still
decisive). Laptop (**le7560**, x86_64) scenario A also exceeds ceilings on
both paths; FA-6 remains faster than classical with matched `native` flags —
§8.4 pins are not reachable on tested hardware.

**Disposition (fail branch):** **Ship FA-6** (§10). §8.7 is a **budget fail**,
not a T6 wire verdict. **§10.1 rejected** — waiver assumed “fast classical,
slow PQ”; measurements invert this on Pi 4. When scenario B capture completes,
update `T_meas` / ns/out in `PERFORMANCE_BASELINE.md` only; disposition
unchanged.

Both scenarios A and B must be **clean pass** for an unqualified FA-6 merge.
**One marginal pass** ⇒ margin-acceptance record **before** merge (genesis
irreversibility: a 96%-of-budget pass is a decision, not a default).

Record outcomes in `PERFORMANCE_BASELINE.md` + `CHANGELOG.md`.

Update `scripts/bench/capture_rust_baseline.sh` with new row names when the
bench harness exists.

---

## 9. Implementation checklist

| Area | Files (indicative) |
|------|-------------------|
| Derivation | `rust/shekyl-crypto-pq/src/derivation.rs` |
| Construct / scan | `rust/shekyl-crypto-pq/src/output.rs` |
| FFI | `rust/shekyl-ffi/src/lib.rs`, `src/shekyl/shekyl_ffi.h` |
| C++ | `cryptonote_tx_utils.cpp`, `wallet2.cpp` |
| Vectors | `docs/test_vectors/PQC_OUTPUT_SECRETS.json` |

**Pre-genesis migration:** `rm -rf ~/.shekyl` — no in-wallet tag transition.

---

## 10. Reversion clause

**Rejected:** X25519-keyed pre-filter after genesis without T6 waiver.

**Benchmark failure does not mean “skip FA-6.”** Genesis locks tag derivation
(§4.1). Failing §8 forces an explicit product/security choice — **both branches
must be equally deliberate** so neither is the path of least resistance.

| Choice | Consequence | Sign-off |
|--------|-------------|----------|
| **Ship FA-6** | Accept §8.4 sync cost on Pi 4 floor (and documented headroom for node co-residence); T6 closed on verified §3.1 account path. | Recorded decision (PR / `PERFORMANCE_BASELINE.md`). |
| **Ship without FA-6 (T6 waiver)** | Classical pre-filter remains; T6 **open** on account path until coordinated HF. | **T6 waiver document** (§10.1) — not an informal default. |
| **Ship FA-6 with marginal pass** | At or under ceiling but below `M_margin` headroom (§8.7). | **Margin-acceptance record** (§10.2) — not a silent merge. |

### 10.1 T6 waiver document (required if bench fails and fast-sync wins)

**Disposition (2026-06-08): REJECTED.** §8.7 fail does **not** authorize this
branch. Pi 4 counterfactual (`--path classical`, §8.7.1) is **slower** than FA-6
at equal `N_outputs`; the “sync wall-clock outweighs T6” tradeoff does not
apply. Reopen only if §8.5 data on Pi 4 shows FA-6 strictly slower than
classical at matched `RUSTFLAGS` **and** product/security signs the waiver per
(1)–(4) below.

If §8.4 is exceeded and the project chooses **not** to ship FA-6 at genesis,
the waiver is a **named artifact** (section in `AUDIT_SCOPE.md` or
`docs/THREAT_MODEL_WALLET.md` amendment) that states **all** of:

1. **Present-day risk, not only quantum:** receive-side activity clustering is
   exploitable by a **quantum** adversary with the victim’s address **and** by a
   **classical** adversary who holds only the view-half (no `ml_kem_dk`) — same
   as today’s X25519-keyed pre-filter.
2. **Irreversibility:** closing T6 later requires a **coordinated hard fork**;
   genesis coinbase and all outputs use the classical tag derivation (§4.1).
3. **Named tradeoff:** explicit statement that **sync wall-clock** on the Pi 4
   reference device (§8.2) for scenarios A/B (§8.4) was judged to outweigh T6
   closure — cite measured times and the pre-committed ceilings that were exceeded.
4. **Scope:** account-output path only; FA-6b multisig hints remain a separate
   open item.

A waiver without (1)–(4) is not sufficient — it must not be a soft escape hatch.

Reopen FA-6 disposition only with:

1. §8 data on Pi 4 per §8.5 showing no path under §8.4, **and**
2. T6 waiver per §10.1 **or** recorded decision to ship FA-6 anyway, **and**
3. `AUDIT_SCOPE.md` / FA-9 updated, **and**
4. §3.1 still signed off (no accidental classical byte left on wire).

**Does not reopen** on anecdotal slowness without §8.5 measurements.

### 10.2 Margin-acceptance record (required for §8.7 marginal pass)

If any scenario is **marginal pass** (under ceiling, below `M_margin` headroom),
merge requires a **named artifact** (same homes as §10.1) stating:

1. **Measured vs committed:** `T_meas`, `T_ceil`, `M_margin`, scenario (A or B).
2. **Pinned scenario:** `N_outputs`, `O_per_block` derivation reference (§8.3.1),
   scenario B = genesis restore.
3. **Conscious thin headroom:** explicit acceptance that chain growth past
   `H_horizon`, node co-residence, or thermal throttle may exceed the budget
   without a fork-free remedy — not a default “pass.”
4. **Recorded decision** (same bar as §10 ship-FA-6): cite measurements and pins.

Marginal pass is **not** a T6 waiver; FA-6 still ships and T6 closes on §3.1.

---

## 11. Sign-off checklist (spec review)

**Record date:** 2026-06-02. **Gate:** S1–S4, S6–S9 complete; implementation
landed on branch `torvaldsl/fa6-view-tag-prefilter`. FA-6 **merge** to `dev`
requires §8.7 against §11.1 pins when benches are run.

| # | Item | Pass | Notes |
|---|------|------|-------|
| S1 | T6 model + **§3.1 inventory** (not tag-only) | ✅ | Closure = no wire byte from quantum-recoverable secret; §3.1 completeness artifact. |
| S2 | §3.1 **Verify** rows closed — §3.1.1 re-audit 2026-06-07 post–PR #101 | ✅ | `view_tag` re-keyed (`derive_view_tag_prefilter` post-decap); hybrid tags verified; FA-6b row → §5.4.1. |
| S3 | HKDF constants §4.2 + **domain separation** §4.5 | ✅ | Constants pinned §4.2; distinctness table + one-byte PRF argument §4.5 (not TBD). |
| S4 | Scanner order §4.7; **no** `view_tag_combined` post-check §4.4 | ✅ | Leg-swap order; `view_tag_combined` internal only — no scan gate. |
| S5 | §8 ratified: §8.4 ceilings + §8.3.1 `O_per_block`, `M_margin`, scenario B | ✅ | Chain pins + ceilings ratified §8.4.1 / §11.1 (2026-06-02); §8.7 recorded fail (2026-06-08). |
| S6 | §10 branches explicit (ship / waiver / marginal §10.2) | ✅ | **Ship FA-6** selected; §10.1 waiver rejected per §8.7.1 counterfactual. |
| S7 | **FA-6b** sync budget **not** inherited — §8.4 scope note | ✅ | Account path only; multisig hints separate (§2.2, §5.1). |
| S8 | Decap totality / fuzz §4.9, §6.4; §6.5 universal-decap wipe | ✅* | *§6.4/§6.5 merge gates: decap totality on adversarial CT + `ml_kem_ss` wipe on tag-mismatch reject (`output.rs` tests). |
| S9 | FA-9 owner for propagation PR | ✅ | **Rick Dawson**, ClockWorX LLC. |

### 11.1 S5 pins (ratified 2026-06-02 — §8.4.1)

Pins are fixed **before** bench results are used for merge (§8.6). Full record:
§8.4.1.

| Pin | Ratified value | Derivation / notes |
|-----|----------------|-------------------|
| Scenario A ceiling (`T_ceil_A`) | **45 s** | 7-day offline window; clean pass ≤ **36 s** |
| Scenario B ceiling (`T_ceil_B`) | **20 min** | Genesis `restore_height = 0`; clean pass ≤ **16 min** |
| `M_margin` | **20%** | §8.4.1 |
| `H_horizon` | **5 years** | §8.4.1 |
| `T_block` | **120 s** | `config/consensus_constants.json` → `daa_target_seconds` |
| `N_blocks` | **1,314,900** | `⌊ H_horizon_seconds / T_block ⌋` |
| `B_cap` | **600,000 B** | `2 × CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5` at median floor |
| `W_out` | **1,500 B** | Stress marginal lower bound (§8.4.1) |
| `O_per_block` | **400** | `⌊ B_cap / W_out ⌋` — §8.3.1 pessimistic pin |
| `N_outputs` | **525,960,000** | `N_blocks × O_per_block` |
| `W_offline` (scenario A) | **7 days** | `A_outputs` = **2,016,000** |

Scenario B = genesis `restore_height` (§8.4). Exploratory benches may run in
parallel; they do **not** set these pins.

### 11.2 Implementation and merge gates

| Gate | When |
|------|------|
| **Implementation PR** | After S5 artifact filed and S5 row → ✅ (PR #101) |
| **§8.5.1 gate binary** | `fa6_decap_prefilter_gate` — Pi 4 capture selects §8.7 branch |
| **Merge to `dev`** | §8.7 vs S5 numbers (clean / marginal §10.2 / fail §10) + S8 merge deliverables (§6.4 fuzz/KAT, decap totality check, §6.5 wipe test) — **impl merged; §8.7 fail → ship FA-6 (2026-06-08)** |
| **Re-review** | Implementation deltas only — section-scoped |

### 11.3 Implementation checklist (blind spots — ranked)

Not duplicated as S1–S9 sign-off rows; these are **merge gates** and
**do-not-refactor** invariants for the implementation PR.

| Rank | Item | Gate / disposition |
|------|------|------------------|
| **1** | **Universal-decap zeroization** | §6.5 — `Zeroizing` + explicit wipe on tag-mismatch `Err`; test required. **Must-fix in PR** (invisible to functional tests). |
| **2** | **Rust/C++ derivation coherence** | §5.3 — single Rust HKDF site; C++ only via `shekyl_construct_output` / scan FFI; genesis regen through same path. |
| **3** | **Genesis → stressnet sequencing** | Program: `WALLET_REWRITE_PLAN.md` cross-cutting — FA-6 (and any genesis-affecting wire change) locks before Phase 7.7 stressnet genesis. |
| **4** | **Prefilter IKM = `ml_kem_ss` only** | **Do not refactor** tag derivation to use `derive_output_secrets(combined_ss, …)` — defeats leg-swap silently (still scans, just slow). §8 bench: per-output cost ≈ decap-only on reject path, not decap+X25519 on every output. |
| **5** | **Reference tool + byte-exact KAT** | `derive_output_secrets.py` updated in same PR as Rust; `PQC_OUTPUT_SECRETS.json` carries `view_tag_prefilter` per vector (byte-exact wire convention). |
| **6** | **Multisig genesis posture** | §5.4 — V3.0: single-sig T6 closed; multisig user-ship V3.1+ with FA-6b before multisig ships. |

**Clerical confirmations (cheap):**

- `T_block = 120 s` citation: `config/consensus_constants.json` →
  `daa_target_seconds` (§8.4.1).
- `ml_kem_ss` byte encoding identical on encaps and decaps paths (§4.2).
