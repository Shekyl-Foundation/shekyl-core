# PHASE_2B §7 — Threat model re-center (P2B-6 draft)

**Status:** **Review round 1 incorporated (2026-06-07).** Ready to land into
[`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §7 (claim-era §7.4–§7.5 → §7.A).

**Authority chain:** [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) P2B-6;
[`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md); [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md)
§4.5; [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md);
[`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md).

---

## 1. Substrate change — what moved

| Retired with claim wire | Rebased threat focus |
|-------------------------|----------------------|
| F0 `{tier × creation}` cohort on confidential claim | **Deleted** — model removal, not mitigation (PHASE_2B status block) |
| Nullifier dedup / `N_S = x·G_S` / DDH claim↔unstake split | **Deleted** — consensus `claimed_settlement_epochs` on bond record |
| `h_bind` + entitlement 8a / tier-forgery 8b | **Deleted** — loud emission amounts + work vector |
| `StakeOpening` / sealed `claimed_epochs` reorg replay | **Deleted** — P2B-5 re-fetch bond record |
| Band cohort / `ρ_e` × secret weight yield | **Deleted** — `Σwork` servo + per-shard bonds |

**Carried forward (reframed):**

- Priority-1 **silent inflation** — now emission mint + **bond_credit/debit** conservation
  (G11 extended).
- Priority-2 **firewall discipline** — `P`↔principal correlation (gate 6), not hidden rewards.
- A1 daemon, A3 memory, A5 economic actor — retained with archival semantics.
- Wider-substrate audit habit — historical failure modes dispositioned, not assumed N/A.

---

## 2. Identity framing (do not collapse)

Three mechanisms — same as PHASE_2B status block; §7 must not shorthand this as "P solves
privacy."

1. **F0 dissolved** — confidential claim wire not shipped; no `{tier × creation}` cohort.
2. **`P` is public by function** — reachability, persistence, challengeability require a
   stable holder; goal is **firewalled pseudonymity**, not claim-style anonymity.
3. **Gate 6 is the unbuilt privacy work** — failure = long-lived correlation of `P`'s public
   timeline against principal + **cross-pseudonym intersection**. Bonds carry Sybil cost;
   multi-`P` is hygiene, not security.

---

## 3. Adversary models

Run each T-item against every applicable model; mark N/A explicitly.

| ID | Model | Archival instantiation |
|----|-------|------------------------|
| **A1** | Adversary-controlled daemon | Stale/wrong `ArchivalBondRecord`, `Σwork`, `R_market`; withholds join-Market confirm; selective challenge delivery |
| **A2** | Passive chain / network analyst | Correlates `P_id` retention timeline, emission cadence, bond events, drain/Unbond outputs |
| **A3** | Memory-disclosure | `master_seed_64`, HKDF-derived `P` keys, emission build state, prover bundles |
| **A4** | A1 + A2 collusion | Timing oracle on emission/drain composed with public `P` timeline |
| **A5** | Rational economic actor | Slash-evasion, bond floor gaming, workload split across `P`, lapse/forfeit arbitrage |
| **A6** | Archival peer / challenger | Grief challenges, false retention disputes, reachability probing (gate 2 interface) |

---

## 4. Seed threat table (quick reference)

| Threat | Mitigation pin (draft) |
|--------|------------------------|
| **F1 — epoch-granularity retention fingerprint** | Shard axis **fixed** at per-`(P,s,E)` (Σwork / `R_market` scarcity). **Structural resolution = `SETTLEMENT_EPOCH_BLOCKS` (SEB)** — only protocol dial on epoch-axis granularity. Hygiene (rotation/lapse/firewall) buys down **residual** after SEB is pinned. **Disposition:** provisionally accepted, **gated on T-A1 sim sign-off** at pinned SEB + defaults. |
| **A6 — challenge grief** | Flood challenges / DoS rendezvous / false-dispute — see T-A16; couples to `CHALLENGE_RESOLUTION_BLOCKS` + L16 + consensus-witnessed challenge delivery. |
| **`P`↔principal long-lived correlation** | Four firewall layers + bond-funding (gate 6 §2). Tor/onion serving (L16); decorrelated drains; no clearnet production fallback. |
| **Cross-pseudonym intersection** | Per-`P` network path, emission batching, rotation discipline; bonds do **not** make multi-`P` free. |
| **Emission timing tell** | Default batch ≤ `MAX_SETTLEMENT_EPOCHS_PER_EMISSION`; settlement-epoch cadence; wallet jitter / Dandelion++ (round-open). |
| **Bond-funding correlation** | Principal→`P` admission transfers must not become a standing linkage channel (gate 6 §2.5). |
| **Unbond refund linkage** | Release refund is loud `bond_floor` into FCMP++ set — same decorrelation discipline as rewards (gate 6 §2.4). |
| **Silent inflation (emission)** | Loud amounts on vin; verifier recomputes `reward_P(E)` from public `Σwork`, `R_market`; wallet must not mask local accounting bugs (G11). |
| **Silent inflation (bond terms)** | `bond_credit`/`bond_debit` in RCT balance equation; conservation law (gate-4 §4.5); `total_bonded_atomic` audit scalar. |
| **Double emission / dedup bypass** | `claimed_settlement_epochs` on bond record; consensus rejects duplicate `E` (P2B-2). |
| **Work forgery on emission** | Gate 2 retention proofs + `good_through(E)`; out of wallet §7 except non-masking. |
| **Daemon misreports economics** | Wallet recomputes claimable from fetched public state + own `P` keys; warn on stale bond record vs tip. |
| **Reorg desync** | Re-fetch `ArchivalBondRecord`; refresh cache; clear `emission_pending_epochs`; join-Market disconnect → `AdmissionPending` (P2B-5). |
| **Memory exposure of `P` keys** | HKDF labels; never persist `P` secrets at rest (gate-6 §9.4); zeroize session material (A3). |
| **Slash rewriting history** | Slash mutates bond only; **does not** rewrite finalized `R_market`/`Σwork` for past epochs (E-3). |
| **Over-bond / under-bond fingerprint** | `bonded_total == bond_floor(holdings)` (not `≥`) — closes over-bond Sybil signal (gate-4). |
| **Join-Market lag bypass** | Bundling first mint with join **consensus-impossible** (gate-4 §1) — closed by ordering. |

---

## 5. Threat-exhaustion agenda (archival T-items)

Each item needs a disposition before §7 lands: **mitigated-in-design** / **FOLLOWUP** /
**cross-track** / **priority-reject** (per [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)).

| ID | Vector | Wargame question |
|----|--------|------------------|
| **T-A1** | **F1 — retention timeline fingerprint (GATE)** | At **pinned SEB**, quantify within-shard epoch-timeline identifiability under L10–L16 + hygiene defaults. **F1 is not accepted until T-A1 passes** — burden on accept, not reopen-after-fact. If SEB is not a genuine emission-cadence lock, F1 gets a **vote on coarser SEB** before accepting hygiene-only residual. |
| **T-A2** | **E-4 — cosmetic rotation** | `P_old → P_new` with same storage, adjacency epochs, same network path — re-linkage proof obligation. What wallet defaults force a real break? |
| **T-A3** | **Firewall — network path** | Under A2/A4, does onion rendezvous (L16) contain principal↔`P` for production serving? Seeding relaxation bounded? |
| **T-A4** | **Firewall — timing** | Emission batching + drain/Unbond spacing — standing correlation channel vs principal spends? Pin jitter defaults. |
| **T-A5** | **Firewall — output graph** | Reward receipts + Unbond refund + terminal drain — FCMP++ membership sufficient, or pinned min-delay / output-count discipline needed? |
| **T-A6** | **Firewall — bond funding** | Admission stake-in pattern — correlation channel size vs ordinary transfer hygiene? |
| **T-A7** | **Cross-pseudonym intersection** | One principal, N `P` without per-`P` hygiene — intersection via retention timeline + network fingerprint. |
| **T-A8** | **Silent inflation — emission** | Wallet constructs emission only from recomputed public `reward_P(E)`; never trusts daemon-supplied mint total. Loud vin check matches vouts. |
| **T-A9** | **Silent inflation — bond** | Wallet never treats `bond_credit` as "free mint"; local preview matches verifier balance equation. Conservation law in node audit. |
| **T-A10** | **Dedup / double-emit** | `emission_pending_epochs` runtime reservation + consensus `claimed_settlement_epochs` backstop — same Hybrid-B shape as retired claim pending (§3.4). |
| **T-A11** | **Reorg** | Re-fetch path under adversarial reorg shapes; join-Market disconnect only when join block popped (gate-4 §5). |
| **T-A12** | **Daemon lie — bond record** | Stale `good_standing`, wrong `claimed_settlement_epochs`, false `bonded_total` — wallet refuses emit build; loud error. |
| **T-A13** | **Memory — `P` key material** | Session-only derivation; no RPC/plaintext `ask` payloads; HW-wallet path for `P` signing (round-open). |
| **T-A14** | **Economic — slash / lapse** | Rational `P` lets epochs lapse past `W` for decorrelation — forfeiture vs privacy trade explicit in UI? |
| **T-A15** | **Economic — bond floor gaming** | Sybil split across `P` — `total bond = shards × FLOOR`; CompleteTree `×1` exception only (G4-7). |
| **T-A15b** | **Economic — HoldingsUpdate slash evasion (A5)** | `P` drops shard *s* via HoldingsUpdate the instant before challenge would slash — escapes penalty unless release cooldown blocks (gate-4 §4.4). Pin: per-shard last-served epoch + cooldown inheritance on dropped shard. |
| **T-A16** | **A6 — challenge grief** | **(i) Forced slash via liveness:** flood challenges faster than `P` can answer, or DoS onion rendezvous → miss response window → slash. Mitigation: `CHALLENGE_RESOLUTION_BLOCKS` > L16 latency + transient-DoS margin; **bounded challenge rate**. **(ii) Challenger-position deanonymization:** interactive challenger sees response timing/path — sharper than passive A2/T-A3. **(iii) False dispute:** challenge issuance must be **consensus-witnessed** — A6 cannot claim non-response to undelivered challenge. |
| **T-A17** | **A1 — join-Market censorship** | Daemon withholds join-Market confirm / bond-post propagation. General censorship-resistance surface; lowest priority in archival §7. |

**A6 coverage rule:** every declared adversary model (§3) must map to ≥1 T-A item. T-A16
closes the A6 gap.

**Retired — do not re-open on genesis path:**

| Old ID | Disposition on rebased substrate |
|--------|----------------------------------|
| T1–T4, T7, T14 (claim sequence / DDH) | **N/A** — claim wire deleted |
| T6 (nullifier reorg) | **Superseded by T-A11** |
| T8 (entitlement inflation) | **Split → T-A8 + T-A9** |
| T9 (fake `StakeEvent` / nullifier match) | **Superseded** — events from bond/emission confirm handlers |

---

## 6. Wider-substrate audit (G-items, rebased)

| ID | Failure mode | Draft disposition |
|----|--------------|-------------------|
| **G1** | Slashing / penalty tracking | **Mitigated-in-design (reopened).** Three surfacing tiers — **(a) pre-slash grace (priority):** `good_standing = false`, slash pending, blocks emit-new; wallet shows "challenge failure pending, N blocks to respond" (P2B-4 R4) — actionable cure window. **(b) partial slash:** shard *s* forfeited, `holdings` shrinks, `P` **stays `Bonded`** in Market on remaining shards (gate-4 §4.2) — not `Slashed`. **(c) terminal slash:** last-shard or CompleteTree whole → `bonded_total → 0` → **`Slashed`**; surface slash cause (which shard failed) for re-bond hygiene. |
| **G2** | Validator / delegation UX | **N/A** — not delegated PoS; document closure. |
| **G3** | Lock-up / unbonding surprise | **Reframed.** Tier lock → **bond + release cooldown + `W` backlog**. Wallet must surface: collateral in cooldown, forfeit horizon, Unbond availability ([`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) §2.1). |
| **G4** | Fee-starved emission | Emission tx fee vs loud reward — warn when uneconomic; batch default reduces fee drag. |
| **G5** | Resync during in-flight emission | **Mitigated-in-design.** `emission_pending_epochs` runtime-only; consensus dedup backstop (§3.4). |
| **G6** | Mempool eviction | Emission path duplicates spend staleness gate (~10 lines) or shares primitive — **FOLLOWUP** if soundness-load-bearing check lacks consensus backstop (§8.9 reversion shape). |
| **G7** | Long-range reorg | **Mitigated-in-design** via P2B-5 re-fetch; daemon pop atomicity assumed (gate-4 §5). |
| **G8** | HW-wallet latency | `P` emission sign path — **OPEN** until gate-6 §9 HW boundary pinned. |
| **G9** | Wallet locked during emit window | UX vs security — **FOLLOWUP** (same shape as claim era). |
| **G10** | Fee-bump / replacement | **Priority-reject** for emission unless FCMP++ fingerprint analysis reopens (PR 5 G3 precedent). |
| **G11** | Proof / accounting inflation | **Extended (priority-1).** Consensus: emission soundness + retention verifier (gate 2) + **conservation law** (gate-4 §4.5). Wallet: **positive KAT-backed preview invariants** (§8.2) before broadcast — not prohibition-only. **Reopen:** consensus audit finding or wallet skips a preview invariant. |
| **G12** | Malicious remote node (Monero class) | **Split by client mode.** Full node: recomputes from validated state (strong non-masking). Light client: recomputes from daemon-supplied public state — A1 can lie; **warn on inconsistency + consensus backstop** (weaker; do not over-promise). |
| **G13** | Temporal analysis / wallet fingerprint | **FOLLOWUP V3.1+** for GUI/RPC fingerprint; staking path must not add per-`P` diagnostic fields that undo firewall (§7.3). |

**Historical analogs (audit record):** Zcash 2018 counterfeiting, Monero 2017 RingCT inflation →
G11. Monero wallet2 fingerprint → G13. MimbleWimble graph reconstruction → **mitigated** for
unlinkable FCMP++ drain (PHASE_2B §2.4 carry-over) — **re-verify** on emission vout layout.

---

## 7. F1 — first-class analysis (retention fingerprint vs rotation)

**Problem statement.** Archival state publishes a **settlement-epoch-resolution timeline**:
which `(P, shard, E)` retention bits were set. That is not a bug — it is how work is scored.
It is also a **persistent public fingerprint** of `P`'s serving pattern.

**What F1 is not.**

- Not F0 — no confidential claim cohort; amounts on emission are loud.
- Not "hide retention" — bits must be public for `Σwork` and challenges.

**Structural vs hygiene axes (load-bearing).**

| Axis | Coarsenable? | Why |
|------|--------------|-----|
| **Shard** (`s`) | **No** | Per-shard `R_market` scarcity; `Σwork` needs per-`(P,s,E)` granularity (emission work formula). |
| **Epoch** (`E`) | **Yes — protocol dial** | `SETTLEMENT_EPOCH_BLOCKS` (SEB) sets epoch-axis resolution. |

**SEB is the structural F1 lever.** [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md)
pins SEB at **10_000** (~13.9 d at 120 s blocks) as **inherited** from confidential-staking
emission cadence — not TBD. Two branches:

1. **If SEB = 10_000 is a genuine lock** for emission-cadence / servo reasons, then F1's
   **structural resolution is fixed at SEB**; what remains is a **hygiene-only residual**
   (rotation, lapse, firewall) — not fixable by operator discipline alone, but also not
   fixable without breaking Σwork if you hide bits.
2. **If "inherited" is a placeholder**, F1 gets a **vote on coarser SEB** before accepting
   hygiene-only residual — coarser epochs are protocol-level fingerprint reduction and
   outrank operator discipline per priority order (privacy-priority property).

**Hygiene mitigations (E-4, gate 6).** Rotation, lapse > `W`, network/output/timing firewall
layers buy down residual **after** SEB is pinned. Incrementing `p_slot` only helps if
observable behavior changes — not cosmetic `P_id` swap.

**Disposition (tightened):** **Provisionally accepted** — category "accepted residual, not
fix-by-hiding" is correct. **Not finally accepted until T-A1 sim sign-off** at pinned SEB +
hygiene defaults. T-A1 is a **gate** (burden on accept), not a reopen trigger fired after
the fact. Failing T-A1 blocks §7 F1 closure and may force SEB reconsideration (branch 2).

---

## 8. G11 — inflation and conservation (extended)

### 8.1 Conservation law (consensus)

```text
already_generated_coins == circulating + bonded + burned
```

Bond events move value between **circulating** and **bonded**; slash moves **bonded → burned**.
Emission mint increases **circulating** via `already_generated`. See gate-4 §4.5.

**Audit obligation:** `total_bonded_atomic == Σ_P bonded_total_atomic` on full nodes.

### 8.2 Wallet preview invariants (priority-1 — positive, KAT-backed)

Prohibitions alone test for absence (regression-prone). For the Zcash/Monero inflation class,
the wallet **asserts** before broadcast — each invariant has a **wallet-internal KAT** tied to
gate-4 §8 / archival-state §9 checklist items:

| ID | Invariant (assert before broadcast) | KAT obligation |
|----|-------------------------------------|----------------|
| **G11-E1** | Emission: `loud_vin_total == Σ recomputed reward_P(E)`; each `E ∈ eligible` where `eligible = [E_join, tip−W] \ claimed_settlement_epochs` ∧ `good_through(E)` | Recompute-match vector; daemon figure must not be authoritative |
| **G11-E2** | Bond-post: `bond_credit == bond_floor(holdings)` (or `bond_debit == bonded_total` on Unbond); balance equation closes with exactly one bond term direction | Floor equality + term rigidity |
| **G11-E3** | Per-tx conservation neutrality: mint/credit/debit terms balance inputs/outputs/fee for this tx preview | Cross-check against conservation law row for tx class |

**Client-mode split (G12 — do not over-promise):**

| Mode | Non-masking strength |
|------|---------------------|
| **Full node** | Recomputes from **validated** chain state — invariants are strong pre-broadcast checks. |
| **Light client** | Recomputes from **daemon-supplied** public state — A1 can lie. Invariants become **warn + refuse build on inconsistency**; ultimate backstop is consensus rejection, not local proof. |

**Corollary prohibitions** (derived from failed invariant — loud-fail, never silent):

- Never broadcast when G11-E1/E2/E3 preview fails.
- Never treat "verifier will catch it" as reason to proceed after preview failure.

### 8.3 Retired 8a / 8b

Entitlement-proof soundness (8a) and tier-declaration binding (8b) applied to the confidential
claim wire. **Archived** with §7.A — not load-bearing on genesis path.

---

## 9. Diagnostic RPC projection (rebase of §7.3)

**Two redaction classes** (carry discipline, rebase fields):

| Class | Archival rule |
|-------|---------------|
| **Secret** | No `P` spend/view/KEM material; no `master_seed`; no principal spend secrets |
| **Correlation** | No field that joins principal graph to `P_id` in one query — no "which principal owns this `P`" |

**Removed (claim-era):** per-stake `claimable` derived from confidential principal;
per-stake `claimed_epochs` pattern (wallet-sealed).

**Archival specifics:**

- Owner `ArchivalPView` may show `claimed_epochs_cache`, cooldown flags, `good_standing`,
  **grace-window pending slash** (shard + blocks remaining — G1a), partial-slash holdings
  reduction — **owner-only**; not exported to lens-3 diagnostics.
- Lens-3: global totals + coarse `P` state counts only; no per-`P` retention bit export
  (already public on chain — wallet must not amplify via off-chain correlation store).

---

## 10. Draft dispositions summary

| Tier | Items | Status |
|------|-------|--------|
| **Closed in design** | Join-Market lag; dedup on bond record; conservation law; `== bond_floor`; slash no history rewrite; P2B-5 reorg fetch; F0 substrate deleted | Cite gate-4, emission §6, P2B-5 |
| **Gated on sim** | **F1 (T-A1)** at pinned SEB + hygiene defaults | `STAKER_ARCHIVAL_SIM.md` — blocks F1 accept |
| **Mitigated pending defaults pin** | Firewall layers; emission batching; T-A16 challenge bounds | Gate-6 rounds + timing cluster values + gate-2 8c |
| **OPEN wargame** | T-A3–T-A7 firewall quantification; T-A5 output min-delay; T-A16 (A6); G8 HW path | Soundness pass step 3–5 |
| **FOLLOWUP** | G6 staleness abstraction; G9 locked wallet; G13 GUI fingerprint | Named targets in FOLLOWUPS |
| **Priority-reject** | G10 fee-bump for emission | PR 5 precedent |

---

## 11. Landing plan (after review)

1. Replace PHASE_2B §7 intro table + §7.3 with §4 + §9 of this draft.
2. Replace §7.4–§7.5 with §5–§6 + §7–§8 (condensed); move old §7.4–§7.5.3 to **§7.A**
   (~50-line archive pointer, not full text).
3. Update §9 closure checklist and §10 Round 3 box to reference T-A* / G11 extended.
4. Gate-6 §2.4 round plan item "Rebase PHASE_2B §7" → closed.
5. CHANGELOG entry on land.

---

## 12. §7.A — Archive pointer (claim-era wargame)

The 2026-06-05 Round 3 wargame (PHASE_2B §7.4–§7.5.3) executed against the **confidential
entitlement claim wire**. Load-bearing historical record for:

- F0 analysis and bucketing option-2 (moot on genesis substrate).
- T8 split 8a/8b entitlement soundness (retired).
- DDH / nullifier / `StakeOpening` threat rows (retired).

**Do not implement** F0 bucketing, `txin_stake_claim_v2`, or nullifier dedup on the genesis
path. Full text: git history pre-P2B-6 land.

---

## 13. FSM rebase assessment + remaining risk (review synthesis)

**How the FSM landed:** by **subtraction** — each round removed claim-era machinery
(`StakeId`, nullifier scan, three of seven states, `BondAttestation`, UTXO-lock families)
rather than accumulating archival complexity. Four states, consensus balance, no dedup
nullifier — signature of a correct rebase.

**Structural discovery (not cleanup):** settlement lag forcing **join-Market distinct from first
mint** (R1). Missed, this ships a subtly-wrong "first emission creates everything" spec that
breaks on `Σwork(E)` finalization trace.

**Risk has moved off shape** onto:

1. **Values** — drain-vs-forfeit, reorg horizon, release cooldown contingent on timing cluster
   §2 inequalities at pinned numbers (not yet sim-run).
2. **Gate-2 slash trigger** — `Slashed` transition and T-A16 hang on 8c (last open Tier-1
   soundness item).

**Substrate verification (doc-ahead-of-code):** consensus-balance bond validated against
precedent (`staker_pool_balance`, `already_generated_coins`) and docs — **not** against live
LMDB integration on current `main`. Single verify-before-branch item: bond balance integrates
with actual schema and `get_block_reward` / `already_generated_coins` accounting as cleanly as
conservation law assumes. Design hole if false; integration task if true-but-unwired.

---

## Revision history

- **2026-06-07 (r1):** Review round 1 — F1 SEB structural lever + T-A1 gate; T-A16 (A6);
  T-A15b HoldingsUpdate evasion; G11 positive KAT invariants + light/full split; G1 three-tier
  surfacing; FSM risk synthesis §13.
- **2026-06-07:** P2B-6 initial draft for review.
