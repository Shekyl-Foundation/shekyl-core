# FA-6 close-out — T6 wire disposition (2026-06-08)

**Status:** closed for genesis wire. This document is the **named artifact** that
prevents re-litigation of a counterintuitive measurement: the pre-FA-6 classical
view-tag pre-filter is **slower** than the FA-6 ML-KEM decap path on the Pi 4
reference device, not faster. Someone who reads only "T6 closed, scan slow" six
months later will propose the obvious-looking §10.1 waiver; this file is the
cheapest guard against reopening a settled call.

**Authoritative spec:** [`FA-6_VIEW_TAG_ML_KEM.md`](FA-6_VIEW_TAG_ML_KEM.md).
**Measurement matrix:** [`PERFORMANCE_BASELINE.md`](../PERFORMANCE_BASELINE.md)
§FA-6. **Subaddress round handoff:**
[`SUBADDRESS_UNDER_PQC.md`](SUBADDRESS_UNDER_PQC.md) §10 (Round 3 closed).

---

## 1. Genesis wire decision (consensus-visible — closed)

| Item | Disposition | Round |
|------|-------------|-------|
| Account-output `view_tag` pre-filter | Re-key to `derive_view_tag_prefilter(ml_kem_ss)` at genesis | Round 3 |
| §3.1 wire inventory | Verified post–PR #101 (`§3.1.1`, 2026-06-07): `view_tag`, `amount_tag`, `label_tag` post-decap hybrid-leg | Round 3 |
| §11 sign-off | S1–S9 complete; S5 ratified; §8.7 outcome recorded | Round 3 |
| Scanner order | Universal ML-KEM decap → tag compare → X25519 on match (`§4.7`) | Round 3 |

**T6 on the account-output path closes at genesis.** No per-output wire byte is
computable from quantum-recoverable view material on the single-sig main path.

---

## 2. §8.7 budget outcome (UX gate — fail, ship anyway)

§8.4 pins are **forward-dated chain stress** budgets on the Pi 4 floor device.
They are not reachable on tested hardware today. That is a **budget fail**, not
a wire or T6 verdict.

### 2.1 Measured micro gate (Pi 4, skl-pi, USB3 SSD)

Harness: `fa6_decap_prefilter_gate` (`--path fa6|classical`, scenario A =
2,016,000 outputs). Classical captures used
`RUSTFLAGS=-C target-cpu=cortex-a72` per §8.2.

| Path | `T_meas` | ns/out | `T_ceil_A` | `gate_outcome` |
|------|----------|--------|------------|----------------|
| **fa6** | 550.4 s | **273,023** | 45 s | **fail** |
| **classical** (counterfactual) | 1,289.9 s | **639,834** | 45 s | **fail** |

Scenario B (525,960,000 outputs, `T_ceil_B` = 20 min): capture pending on Pi;
extrapolation from scenario A (~273 µs/out FA-6, ~640 µs/out classical) yields
~40 h and ~94 h respectively — **fail (expected)**. Update measured `T_meas` in
`PERFORMANCE_BASELINE.md` when capture completes; **disposition unchanged**.

### 2.2 Disposition branch selected

Per FA-6 §10 row **Ship FA-6:** accept §8.4 sync cost; T6 closed on §3.1.
**Not** §10.1 T6 waiver. **Not** §10.2 marginal pass (both paths exceed
ceiling by orders of magnitude, not thin headroom).

---

## 3. §10.1 waiver rejection (dominance-based)

The waiver branch assumes a tradeoff: **fast classical pre-filter vs slow PQ
pre-filter**, accepting classical linkability to win sync wall-clock.

**Measured data inverts the tradeoff on the reference device:**

- Classical counterfactual: X25519 ECDH + cofactor check + HKDF + tag compare
  **before** the expensive path is skipped — still **~2.3× slower** than FA-6
  ML-KEM decap + `derive_view_tag_prefilter` on Pi 4 (273,023 vs 639,834 ns/out).
- Laptop (x86_64) confirms FA-6 faster than classical under matched `native`
  flags — not a Pi-specific artifact.

Therefore §10.1 is **rejected**, not merely unused:

| Waiver premise | Finding |
|----------------|---------|
| Classical path is faster | **False** on Pi 4 and laptop |
| PQ path is the scan-cost driver | **False** — classical pre-filter is slower |
| Waiver buys sync time at privacy cost | **No bargain** — slower **and** leakier |

**Reopen §10.1 only if:** §8.5 data on Pi 4 shows FA-6 strictly **slower** than
classical at matched `RUSTFLAGS`, **and** product/security signs waiver per
FA-6 §10.1 (1)–(4).

---

## 4. Consensus-invisible perf (defer / community — not a genesis gate)

Faster ML-KEM decap, birthday / `restore_height` / checkpointing (reduce-N),
and §8.5.2 end-to-end restore benchmarking are **wire-preserving**. They can land
anytime, from anyone, without a fork — the PQ-safe pre-filter byte is already
locked.

This is the **consensus-visible-now / consensus-invisible-later** split doing
its job: pin the correct wire at genesis; let speed improve whenever and by
whomever. Shared scan budget with 2B stake-mirror refresh (`PHASE_2B_STAKE_LIFECYCLE.md`
§8.4.1) means reduce-N benefits both wallet refresh and stake scan.

**Target:** V3.1+ follow-ups in `docs/FOLLOWUPS.md` (not Round 3 blockers).

---

## 5. FA-6b genesis posture (wire locked; no V3.0 user leak)

FA-6 closes T6 on the **account-output** path only. Multisig
`tx_extra_pqc_view_tag_hints` is **FA-6b** — separate track. Two terms that are
easy to conflate:

| Term | Meaning |
|------|---------|
| **Genesis-lock status** | Hint **wire format and inclusion** in multisig scaffold are consensus-visible at genesis (`PQC_MULTISIG.md` §7.1, `§5.4.1` audit 2026-06-07). The byte layout is pinned; re-key before V3.1 multisig ships if audit requires it. |
| **No V3.0 user leak** | **No end-user multisig wallet** ships at V3.0 (`WALLET_REWRITE_PLAN.md`, `AUDIT_SCOPE.md`). Single-sig users get FA-6 T6 closure. Scaffold may emit hints; that is **conscious acceptance**, not "multisig wallet type at launch with weaker T6 than single-sig." |

| FA-6b question | Finding (`§5.4.1`) |
|----------------|---------------------|
| Computable from view scalar without decap? | **No** — compare after `kem.decapsulate` |
| Per-output variation? | **Yes** — KEM randomness + `output_index_in_tx` |
| Passive 1-byte wire linker without view key? | **Possible** — public metadata; **distinct from T6** (quantum-recoverable secret) |
| V3.0 user-shippable multisig? | **No** — FROST multisig V3.1+ |
| Hint re-key implementation | V3.1 (FA-6b track), not unsigned genesis deferral |

**Round 3 wire-lock artifact:** this table + FA-6 `§5.4` bullets. **FA-6b
implementation / re-key** remains V3.1 before multisig is user-shippable.

---

## 6. FA-9 propagation (parallel — Round 4)

FA-9 is **consensus-invisible** documentation: propagate §4.6–§4.8, R2-F9
phishing tier, T6 framing **after** this close-out, pit-of-success vs adversary,
reuse-without-rotation product principle. Owner: Rick Dawson, ClockWorX LLC.

FA-9 does **not** reopen FA-6 wire disposition. It explains the settled decision
to users, auditors, and threat-model readers.

---

## 7. Reversion clauses (summary)

| Disposition | Reopen when |
|-------------|-------------|
| Ship FA-6 at genesis | Coordinated HF to revert tag derivation (not planned) |
| §10.1 waiver rejected | Pi matched-bench shows FA-6 slower than classical + signed waiver |
| §8.7 budget fail accepted | N/A — perf improvements are consensus-invisible |
| FA-6b scaffold at genesis | Multisig promoted to V3.0 user-shippable without FA-6b audit (explicit product decision only) |

---

## 8. Checklist (close-out complete when all ✅)

- [x] §3.1 inventory verified (`§3.1.1`, 2026-06-07)
- [x] §8.7 fail recorded with Pi A measurements + B placeholder
- [x] §10.1 rejected with dominance numbers (§2.1, §3)
- [x] Ship-FA-6 disposition named (§2.2)
- [x] FA-6b genesis-lock vs no-V3.0-user-leak disambiguation (§5)
- [x] Consensus-invisible perf deferred with reversion shape (§4)
- [x] FA-9 scoped to Round 4 parallel (§6)
- [ ] Pi scenario B measured `T_meas` filled in `PERFORMANCE_BASELINE.md` (disposition unchanged)
