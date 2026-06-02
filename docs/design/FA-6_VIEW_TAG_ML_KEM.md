# FA-6 — PQ-safe view-tag pre-filter (T6 closure)

**Status.** Specification draft (2026-06-01, revised). **Disposition:** adopt at
V3.0 genesis — re-key the on-wire 1-byte pre-filter from classical
(`x25519_ss`) to hybrid-leg (`ml_kem_ss`). **Implementation:** separate PR
after spec review; not bundled with FA-11 (`enc_label` wire) or subaddress
removal (FA-2).

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
**Verify** with code pointers (FA-11 branch for `label_tag` / `enc_label`;
`output.rs` + `derivation.rs` for `amount_tag`). A single classical pre-decap
byte left on the wire **defeats** the view-tag re-key.

**Likely outcome (hypothesis, not closure):** Main-path `amount_tag` /
`label_tag` / `enc_label` are already hybrid-derived; the view tag is the
**deliberate** classical exception because it is the **only** pre-decap
filter. **“Likely” is not “verified.”** §3.1 exists to force verification.

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

**Argument (one line, load-bearing for reviewers):** They are **independent
HKDF-Expand instances** under distinct `(salt, info)` pairs — standard PRF
domain separation. Publishing one byte of the pre-filter expansion does **not**
weaken `combined_ss` derivations because the Expand inputs differ.

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

### 6.3 Negative tests (production guard)

Stub all-zero wire tag must not ship from production `construct_output`.

### 6.4 Decap robustness (adversarial CT)

| Test | Intent |
|------|--------|
| Garbage / random 1088-byte CT | `scan_output*` returns `Err`, **no panic** |
| Fuzz target extension | Align with `fuzz_kem_decapsulate`; document scan entry |
| Wrong-length CT | Rejected before decap (existing) |

---

## 7. Documentation updates (implementation PR)

| File | Update |
|------|--------|
| `docs/POST_QUANTUM_CRYPTOGRAPHY.md` | Pre-filter registry; domain-separation row |
| `docs/design/SUBADDRESS_UNDER_PQC.md` | §3.7 — T6 closed on **verified** §3.1 + FA-6 |
| `docs/FOLLOWUPS.md` | Close FA-6; FA-6b multisig hints; FA-9 propagation |
| `CHANGELOG.md` | Initial-sync / privacy tradeoff (user-visible) |

---

## 8. Benchmark gate (merge requirement)

Per-output micro-benchmarks are **necessary but not sufficient**. The merge
gate is **initial-sync wall-clock** on a **worst-class wallet target**
(non-AVX2 mobile or documented equivalent), at a **realistic pre-genesis
chain-size scenario** (document block/output counts — use project stress
fixture or scaled testnet replay).

**Required measurements before merge:**

1. **End-to-end scan benchmark** — full-chain (or agreed fraction) recover
   scan with FA-6 ordering vs archived classical pre-filter baseline.
   Report **total sync time**, not only per-op ratio.
2. **iai-callgrind** — per-output decap+tag vs archived X25519+tag (regression
   guard for instruction drift).
3. **criterion** — per-output decap on worst target (supports extrapolation).

**Acceptance (proposal — tighten after first data):**

- **Primary:** initial-sync time ≤ **agreed wall-clock ceiling** on worst
  target (set at spec sign-off S5 — e.g. multiple of today's baseline, not
  “≤ 4× per-op” alone).
- **Secondary:** per-output decap ≤ **4×** X25519 mult on same target (until
  measured).

**If the gate fails:** Re-evaluate per §10 — **not** silent revert to
classical tag. Choices are documented **slow sync** vs **T6 waiver** — not
“defer FA-6.”

Update `docs/PERFORMANCE_BASELINE.md` and `scripts/bench/capture_rust_baseline.sh`.

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
(§4.1). Failing §8 forces an explicit product/security choice:

| Choice | Consequence |
|--------|-------------|
| **Ship FA-6** | Accept initial-sync cost on worst targets; T6 closed on verified §3.1 main path. |
| **Do not ship FA-6** | T6 remains a **~permanent** receive-clustering property (fixable later only via coordinated HF). |

Reopen FA-6 disposition only with:

1. §8 data on all agreed targets showing no acceptable sync path, **and**
2. Threat-model amendment accepting T6 residual on main path, **and**
3. `AUDIT_SCOPE.md` / FA-9 updated, **and**
4. §3.1 still signed off (no accidental classical byte left on wire).

**Does not reopen** on anecdotal slowness without §8 measurements.

---

## 11. Sign-off checklist (spec review)

| # | Item | Pass |
|---|------|------|
| S1 | T6 model + **§3.1 inventory** (not tag-only) | ☐ |
| S2 | §3.1 rows **verified** in code (amount_tag, label_tag order) | ☐ |
| S3 | HKDF constants §4.2 + **domain separation** §4.5 | ☐ |
| S4 | Scanner order §4.7; **no** `view_tag_combined` post-check §4.4 | ☐ |
| S5 | **Initial-sync** benchmark ceiling named (§8) | ☐ |
| S6 | §10 tradeoff accepted (bench fail ≠ defer) | ☐ |
| S7 | Multisig **FA-6b** deferral explicit (§3.2, §5.1) | ☐ |
| S8 | Decap totality / fuzz §4.9, §6.4 | ☐ |
| S9 | FA-9 owner for propagation PR | ☐ |

**After S1–S9:** Implementation PR permitted. Section-scoped re-review on
implementation deltas only.
