# Wallet privacy threat model (V3.0)

> **Last updated:** 2026-06-09  
> **Status:** Round 4 propagation (FA-9). Genesis wire is closed — this doc
> explains settled decisions; it does not reopen consensus.

## Purpose and scope

This document is the **user-, auditor-, and reviewer-facing** adjunct to the
subaddress design round ([`docs/design/SUBADDRESS_UNDER_PQC.md`](design/SUBADDRESS_UNDER_PQC.md)).
It records what Shekyl's wallet privacy claims are, what they are not, and how
**pit-of-success** (user-behavior) surfaces differ from **adversary** surfaces.

**Authoritative wire and crypto specs:**

- [`docs/POST_QUANTUM_CRYPTOGRAPHY.md`](POST_QUANTUM_CRYPTOGRAPHY.md) — hybrid
  KEM, output derivation, cooperative attribution foundation pin (FA-10)
- [`docs/design/FA-6_CLOSEOUT.md`](design/FA-6_CLOSEOUT.md) — T6 account-path
  closure at genesis; §10.1 classical pre-filter waiver rejected
- [`docs/design/SUBADDRESS_UNDER_PQC.md`](design/SUBADDRESS_UNDER_PQC.md) §5.7.8
  — reusable-address UX constraints (FA-4, closed via FA-7)

**Out of scope here:** consensus rule changes, RCT byte layout (FA-11), engine
implementation, GUI string copy (Phase 4b per
[`WALLET_REWRITE_PLAN.md`](design/WALLET_REWRITE_PLAN.md)).

---

## Priority hierarchy (what binds by default)

Per [`00-mission.mdc`](../.cursor/rules/00-mission.mdc), Priority 2 (*privacy is
the product*) is read as **pit of success**, not "no behavior-dependent guarantees
anywhere":

> The **casual path must be the private path.** Deanonymizing yourself must
> require **deliberate work**, not casual accident.

**True by default (market honestly):**

- Your receive address is **private against the chain** no matter how carelessly
  you reuse it (per-output `ho`, hybrid KEM gating — R2-F1).
- Passive chain observers cannot link your receipts from address reuse alone.

**Deliberate, not casual (disclose when relevant):**

- Keeping separate parts of your life unlinkable **from each other** (counterparty
  collusion, T2) is **deliberate opsec** — seed-derived multi-account is P3, not
  a V3.0 default guarantee (§4.6 pin in SUBADDRESS).

**Priority 1 still binds adversary surfaces.** User-behavior framing does not
relax T6/T7 (§4.7).

---

## Pit of success vs adversary (do not conflate)

| Class | Example | Pit-of-success applies? | Track |
|-------|---------|-------------------------|-------|
| User-behavior | T2 collusion (you handed both addresses) | Yes → deliberate, not mandatory | T2 **optional** (P3 accounts) |
| User-behavior | Network hygiene, amount/timing | Educate; not a platform mandate | Out of this doc |
| **Adversary** | **T6** view-tag clustering (quantum + your address) | **No** — diligent user still clustered pre-FA-6 | **Closed** on account path (FA-6 genesis) |
| **Adversary** | **T7** leaked address / phishing | **No** — publication + harvest are adversary-driven | **R2-F9 pinned**; this doc |

**Forbidden anti-pattern:** "We can't stop a careless user" → "we can't stop a
determined attacker, so why try." T6 and T2 stay on **separate pins**.

**UX (FA-4, closed):** Reusable primary address is the safe default. Do not
import Bitcoin-style rotation nudges — see
[`SUBADDRESS_UNDER_PQC.md`](design/SUBADDRESS_UNDER_PQC.md) §5.7.8.

---

## Adversary surface index

Tracks that **do not** close when End-state 5 ships (pit-of-success governs
user-behavior only):

| ID | Surface | V3.0 disposition | Detail |
|----|---------|------------------|--------|
| **T6** | Quantum observer + off-chain address → view-tag receive clustering | **Closed on account-output path** at genesis (FA-6 PQ-keyed `view_tag_prefilter`) | FA-6b multisig hints are a **separate** V3.1 track; no end-user multisig at V3.0 |
| **T7** | Leaked receive address — phishing, dust, substitution, liveness | **R2-F9 pinned** | Dust **receive/spend oracle closed** (FCMP++); substitution + T6 harvest + app-layer probes **named** below |

### T6 after FA-6

- **Account path:** `view_tag` is derived from `ml_kem_ss` after ML-KEM decap
  (`derive_view_tag_prefilter`). A quantum adversary who recovers only classical
  view material from the address cannot replay view-tag clustering on archived
  chain data for account outputs.
- **§10.1 waiver rejected:** Classical X25519 pre-filter was measured **slower**
  than FA-6 on Pi 4 and laptop — no privacy-for-speed trade to accept
  (`FA-6_CLOSEOUT.md` §3).
- **Phishing is the concrete harvest step:** Collecting a public receive address
  today enables **future** quantum recovery of view secret from `V = a·G`, then
  view-tag replay on archived chain — **without** breaking the wallet today.
  Framing: *phishing + patience deanonymizes receive history post-quantum*.

### T7 — address-knowledge / phishing (R2-F9)

**Passive chain adversary with only `(B, V, x25519_pk, ml_kem_ek)` gets nothing
on-chain** — no view secret, no decap, no output detection, no amounts.

**Ranked threats** (address leak is not harmless, but dust is not a tracker):

| Rank | Threat | V3.0 disposition |
|------|--------|------------------|
| 1 | **Address substitution** (QR/URI/email swap) | Publication-channel authenticity; signed publication, OOB verify for high-value |
| 2 | **Post-quantum harvest (T6)** | Mitigated on account path (FA-6); phishing remains harvest step |
| 3 | **Dust spam / DoS** | Wallet dust threshold; not deanonymization |
| 4 | **Liveness oracle** (auto-POST on receipt) | Passive receipt: detect locally, emit nothing by default |
| 5 | **Label injection** (5-T) | Treat decrypted labels as **untrusted** at UI/export boundaries |

**Dust disposition:** Eve who sends dust learns only *"this output is mine."*
She cannot see your other receives or detect when you spend the dust (FCMP++ has
no rings; key image needs spend secret). **Leaked address + dust is not a
receive- or spend-tracking oracle** classically.

**Victim playbook (summary):**

| Compromise | Classical on-chain risk | Remediation |
|------------|-------------------------|-------------|
| Address published | Third-party payments not visible; spam/dust possible | No key rotation for address-only leak; stop using hostile context |
| View key / wallet file stolen | Full receive history | New seed, new wallet, sweep |
| Spend key / seed stolen | Full loss | New seed immediately |
| Separate identity from untrusted counterparty | T2 off-chain compare | P3 multi-account or separate wallet file — not address rotation |

Full pin: [`SUBADDRESS_UNDER_PQC.md`](design/SUBADDRESS_UNDER_PQC.md) §5.7.12.

---

## Cooperative attribution (pointer)

Every output carries mandatory `enc_label` + `label_tag` on wire (5-T-substrate).
Sentinel-only wallets are consensus-valid at launch; meaningful payment-request
tags and reconcile UX ship behind a **product flag**. Wire details and foundation
pin: [`POST_QUANTUM_CRYPTOGRAPHY.md`](POST_QUANTUM_CRYPTOGRAPHY.md) §Cooperative
attribution foundation pin (FA-10).

---

## Reversion clauses

This doc **does not** reopen genesis wire. Reopen only per named criteria in
[`SUBADDRESS_UNDER_PQC.md`](design/SUBADDRESS_UNDER_PQC.md) §7 and
[`FA-6_CLOSEOUT.md`](design/FA-6_CLOSEOUT.md) §7:

| Topic | Reopen when |
|-------|-------------|
| T2 mandatory scope | Mission text amended to elevate counterparty collusion to Priority-2 default |
| FA-6 ship at genesis | Coordinated HF to revert tag derivation (not planned) |
| §10.1 T6 waiver | Pi matched-bench shows FA-6 slower than classical **and** signed waiver per FA-6 §10.1 |
