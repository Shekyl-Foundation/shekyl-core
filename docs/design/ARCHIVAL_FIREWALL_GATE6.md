# Archival firewall — gate 6 (`P` lifecycle + pseudonym hygiene)

**Status:** **Rounds 1–2 closed; Round 3 open (2026-07-11).** Not soundness-closed (R5 pending).

- **Round 1 closed (2026-06-13)** — crypto layer + `P` hybrid derivation pinned (§9); GF-1
  per-tx-type verifier contract resolved, GF-2 dual-scan enforcement made architectural, reviewer
  sign-off (§9.8), post-sign-off refinements C-1/C-2/C-3 folded in. **Lone carry discharged:** the
  `ARCHIVAL_P_DERIVE_V1` KAT + `archival_p` module **landed** (Bond-PR 0 #152 — verified at source:
  [`archival_p.rs`](../../rust/shekyl-crypto-pq/src/archival_p.rs) carries all seven §9.3 labels
  incl. the `bond_spend_*` pair; [`kat_archival_p_derive_v1.rs`](../../rust/shekyl-crypto-pq/tests/kat_archival_p_derive_v1.rs)).
  **C-1 dependency discharged:** the emission vin-layer ML-DSA equality check **landed** (PR #277,
  `dev` `13c368707`; `emission_verify.rs`) — quantum spend-authority no longer classical-only.
- **Round 2 closed (2026-07-11)** — network + transport (§10). All §10.10 exit dispositions
  ratified against the round's defense-in-depth bar (§10.0); closure disposition + carried items
  with rule-21 criteria at §10.13. **One carry is a not-yet-frozen crypto surface:** the GF-9
  seed-derived HS-identity HKDF label is *pinned as a disposition* (§10.7) but is **not yet in the
  derivation/KAT** (verified at source — absent from `archival_p.rs`), and §10.7's proposed label
  string uses dot separators against §9.3's hyphen convention; §10.13 carries it armed with the
  normalization flag so it cannot freeze wrong.
- **Round 3 designed + adversarial pass run (2026-07-11)** — timing + rotation + `W`/epoch-length
  (§11). **GF-10** pinned as a *mechanism + structural window + a-priori advantage claim* (§11.3–11.5);
  numeric width **routed to the R4/GF-4 CB-3 joint grade**, not graded standalone (per-axis-multiplication
  error avoided). Rotation dispositions ratified; R2 timing hand-forwards resolved (§11.6). The
  claim-jitter draw + scheduler are unbuilt (verified) — pinned pre-code, M1-armed. The adversarial
  pass (§11.8) found no break; its four findings are folded as re-pins into §11.3–11.5. Remaining for
  close: fold GF-10 into the R4/GF-4 joint grade and clear the pre-committed advantage claim (§11.7).
  **UPDATE 2026-07-16 (§12.9 decision 3):** the joint grade dissolved by axis attrition; GF-10's
  width now grades **standalone** against its §11.5 pre-committed advantage claim — R3 closes when
  that single-axis grade runs.
- **Round 4 drafted (2026-07-11, §12) — the drain-event firewall.** GF-7 (funding-in) already built +
  graded PROVISIONAL-PASS (`r = 1.86`); GF-4 (value-out) drafted as one event with three co-triggered
  channels graded jointly: **F-D1** drain-amount taint-carve (complete pre-code pin — (a)+strip),
  **F-D2** UI-default, **F-D3/F-D4** one-sided cooldown-anchored exit standoff (**FSM gate FIRED
  2026-07-15** — §12.5; F-D4 derivation committed + reviewed rounds 1–3; **F-D3 BUILT 2026-07-16**
  against the F-D4 sentinel — `draw_exit_gap`, F-D6-derived anchor; sealing owed at Phase 7.7),
  **F-D5** → ~~§14.4~~ *(dangling — re-pointed 2026-07-17 to the §12.7-chartered disposition
  round)*, **F-D6** anti-drift (**DONE 2026-07-16**, §12.7). GF-10 (R3) folds into
  the joint grade. The rebond/unbond FSM blocker is discharged (landed PR #303/#307).
  **UPDATE 2026-07-16 (R4 decision round — §12.9, RATIFIED at review-at-source):** the F-D4 §15.5
  hand-forward is **answered**:
  the exit seam **re-homes** to the principal↔user crossing (WI-4 §18.13; both halves reduce —
  timing phantom per F-W7/F-W9, amount already class-3 of that seam); the four-axis joint grade
  **dissolves by axis attrition** — ratification added the fourth row the draft's walk had
  silently omitted (**F-W10: output-count is phantom** — under FCMP++ the drain is not an
  identifiable transaction, so its output count is not an observable; the §2.4 pin was a
  CryptoNote-lineage carry never re-walked across the crypto change) — and GF-10 grades
  standalone (decision 3); the F-D4 §16.4 funding
  default is **accepted** as F-D2-class (self-fund default, loud override routed through the entry
  standoff); the exit-standoff mechanism deletion PR is scoped (decision 5 — `exit.rs` wholesale;
  F-D6 and `release_cooldown_elapsed` out of scope) — **landed 2026-07-17** (close condition (iii)
  satisfied). R4's re-formed close: F-D1 + F-D2 (incl. the
  funding default) + ~~the deletion PR~~ *(landed)* + ~~F-D5's §14.4 disposition~~ *(the §14.4
  target was dangling — condition (iv) re-worded 2026-07-17: the F-D5 disposition round runs its
  structural-derivation attempt and records grid-ships / no-grid, band registered as an S-2 ledger
  row either way; charter at §12.7, amendment at §12.9)*. **UPDATE 2026-07-17 (same day): the
  F-D5 disposition round RAN — the structural attempt failed at source (no population-free
  lattice below the `Curve`'s shape constants; the value spacing is `budget(E)/Σwork(E)`;
  reachable-collision ≠ delivered cover), so NO GRID ships at genesis and condition (iv) is
  discharged (§12.7 OUTCOME). R4 is open on F-D1 + F-D2 only.** **UPDATE 2026-07-17
  (later): F-D1 BUILT (§12.3 build note — `drain_orchestrator`/`drain_amount`/
  `drain_select`, M1 arm proven-to-bite then armed) and F-D2's core-side
  aggregate-only surface LANDED (§12.4 build note); `plan_drain` lands as a
  correctly-carved planner with no data source and no consumer yet. F-D2's
  remaining half is NOT a pending UI default and NOT gated on RPC (the GUI links
  the engine in-process): it is a whole unbuilt `P`-value-out (drain-send)
  subsystem in `shekyl-gui-wallet` — a `P`-scan data source feeding the planner +
  a drain tx assemble→sign→broadcast path + the round-number/random-split default
  on top (§12.4 build note). R4 close: that subsystem is the last open item.**
- **Round 5 planned** — the cross-layer soundness sign-off for Stage 3 (S-2 exposure ledger + S-3
  exit/value-seam adversary sim, §10.12). First registered S-2 ledger row: the
  lifetime-aggregate (drain-all) band at the §18.13 crossing (F-D5 disposition, 2026-07-17;
  §12.7 OUTCOME).

**GF-1-carve resolved (2026-06-16):** bond-debit authority is a dedicated `bond_spend_pk` (gate-4
§3.5 step 5 / §4.1 / §3.4.1; §9.3 labels), not the account identity key. Per
[`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc),
adversarial rounds run before Stage 3 `StakeEngine` production code.

**Global PQC policy:** Hybrid genesis stack (Ed25519 + ML-DSA-65 spend auth; X25519 +
ML-KEM-768 output encryption) is **not** re-litigated here — see
[`POST_QUANTUM_CRYPTOGRAPHY.md`](../POST_QUANTUM_CRYPTOGRAPHY.md). Gate 6 pins only the
**archival `P` fork** of that stack: domain-separated HKDF labels, account-level
`HybridPublicKey` for the bond record, and firewall coupling.

**Scope:** Everything required so a **firewalled pseudonym `P`** — public by function
for archival — does **not** re-link to the principal across crypto, network, timing,
output, and bond-funding surfaces over `P`'s whole life.

**Upstream:** [`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md) §*Firewalled-pseudonym
identity model*; [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §2.4
(transfer-shaped admission); [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) (emission
cadence, batching, `good_through`); [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md)
(public retention timeline at settlement-epoch resolution).

**Out of scope here (interface only):**

| Item | Owner |
|------|-------|
| Retention-proof construction / 8c verifier bytes | Gate 2 soundness |
| `ArchivalBondRecord` slash wire, `good_through` interval log | Gate 4 |
| `Σwork` servo, admission principal economics | Gate 1 / gate 7 |
| Full `ArchivalEngine` query-serving | Stage 5 |
| Entitlement / `C_stake` / 3C subtree | Deleted |

**Why now:** Emission Layer 1 and the archival read contract pin **what is public**
(`P_id`, per-`(P, shard, E)` retention bits, shard-set, performance timeline).
Gate 6 pins **what must stay hidden** (`P` ↔ principal) and the **wallet/daemon/network
obligations** that maintain the firewall — including rotation, lapse, and transport
discipline named in the honest residual and F1 epoch-length coupling.

---

## 1. Public vs hidden — the contract gate 6 enforces

| Consensus-public (by function) | Must remain hidden (gate 6) |
|--------------------------------|-----------------------------|
| `P_id`, holdings descriptor, bond posture | Principal identity, spend graph, view key |
| Shard-set, longevity, per-epoch retention bits | Which human/entity operates `P` |
| `R_market`, `Σwork`, reward amounts (loud) | Correlation of multiple `P` to one principal |
| Challenge reachability (peers must find `P`) | Network path from principal device to `P` rendezvous |

**Priority binding ([`00-mission.mdc`](../../.cursor/rules/00-mission.mdc)):** Priority-2
on the reward path is **firewall discipline**, not hidden reward amounts. Failure mode:
long-lived correlation of `P`'s public activity against the principal, plus **cross-
pseudonym intersection** when one principal runs multiple `P`s without per-`P` hygiene.

**Not a security claim:** Multi-`P` per principal is **privacy hygiene**, not Sybil
defense — per-shard bonds carry Sybil cost ([`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md)
§*Per-shard retention bonds*).

---

## 2. Four firewall layers + bond-funding

Gate 6 is maintained across **five surfaces** (four classic layers plus bond-funding).
Each surface has **wallet**, **daemon**, and **network/ops** obligations; this doc
names invariants first — wire-level hooks land in later rounds.

### 2.1 Crypto layer

**Goal:** `P` keys and signing paths are **cryptographically independent** of principal
spend keys — not algebraic offsets, not shared nonce streams, not shared scan tags.

**Genesis pin (carry from V3 / PHASE_2B):**

- `P` = **HKDF-derived sub-wallet** from master seed (independent keypair; dual scan:
  principal + `P`).
- Principal→`P` stake-in, `P`→principal unstake drain, reward sweeps = **ordinary
  `CTTypeFcmpPlusPlusPqc` transfers** on the main tree; base FCMP++ privacy is necessary
  but **not sufficient** (timing/output still leak). *(UPDATE 2026-07-16 — method-note-5
  re-walk, §11.8: the "not sufficient" residue is now scoped to the **entry leg only** —
  the funding spend's existence and timing, the GF-7 seam (F-D4 §16.1). On the exit leg
  both named leaks were found phantom: exit timing has no observable event (F-W7/F-W9)
  and the drain's output shape is not an observable (F-W10). Base FCMP++ privacy is
  sufficient for the exit leg by construction.)*
- Reward emission = **membership-only control** on `P`'s backing UTXOs — no published
  dedup tag; no stake-keyed nullifier on the emission path.

**Round 1 pin:** §9 — hybrid `P` derivation, `P_canonical_id`, dual-scan contract.
**Still open:** multisig `P` (V3.1 defer), hardware-offload `P` signing boundaries.

### 2.2 Network layer

**Goal:** Peers reach `P` for challenges and fetches **without** learning where the
principal lives or which clearnet IP serves archival bytes.

**Genesis posture (sim-backed — L16):**

- Heavy archival fetch path → **onion-service ↔ Tor-client rendezvous** (slowest Tor
  config). `P`'s location must not link to the principal → **no clearnet fallback** for
  production archival serving under the firewall threat model.
- Operating regime: L10 `L2–L6` latency band is **by construction**, not a stress corner
  ([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) L16).

**Contained sub-questions (soundness pass step 2):**

- Archiver **seeding-path** transport relaxation — smaller than clearnet-serving; must
  not re-introduce principal↔`P` linkage ([`FOLLOWUPS.md`](../FOLLOWUPS.md) gate-6 transport
  items).

**Round-open:** Arti integration surface, peer handshake that presents `P` without
principal metadata, challenge-delivery path vs fetch path separation. **→ now drafted in
§10 (Round 2, open):** GF-12 Arti capability confirmed (§10.3), GF-3 challenge class
(§10.4), GF-5 pre-join presentation (§10.5), GF-6 wire-size fingerprint (§10.6), GF-9 HS
key lifecycle (§10.7), heavy-path lever (§10.8).

### 2.3 Timing layer

**Goal:** Principal financial activity and `P` archival activity are **not alignable**
by an observer — emission cadence, claim batching, unstake drains, and rotation events
must not form a standing correlation channel.

**Couplings already pinned elsewhere:**

| Mechanism | Source | Gate-6 role |
|-----------|--------|-------------|
| Settlement-epoch emission cadence (~14 d default) | Emission leg §3 | Batches work claims; reduces drip timing tell |
| `MAX_SETTLEMENT_EPOCHS_PER_EMISSION = 15` per `P` | Emission leg §3 | Default batch; single-epoch claim = test-only |
| Per-epoch serve-credit ledger resolution | Archival state / F1 | **Public liveness fingerprint** at epoch granularity |
| `MAX_CLAIM_AGE_W` | Archival state §2.4 | Forfeiture horizon + hot-state bound (not decorrelation — F1 T-A1) |

**`W` vs. batch cap (GF-11, no new pin):** `MAX_CLAIM_AGE_W = 26 >
MAX_SETTLEMENT_EPOCHS_PER_EMISSION = 15` is already pinned in
[`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) §1. The **batch cap (15)**, not
the forfeiture horizon (26), is therefore the binding constraint on how many settlement epochs a
single emission may claim — a `P` cannot legally widen its claim window to the forfeiture horizon
to thin its timing fingerprint. This ordering is a consensus fact, not a gate-6 decorrelation
lever.

**E-4 threat (named):** Fine-grained per-epoch retention timeline + shard-set adjacency
across **`P_old` → `P_new` rotation** re-links identities if rotation is cosmetic
(same storage, same shard set, adjacent epochs). **Rotation must change observable
behavior**, not only `P_id`.

**T-A1 update (2026-06-07).** At lean equilibrium, scarcity-spread produces **unique
portfolios** (~98% singleton) — the privacy shadow of coverage working correctly. Timeline
re-linkage is a **non-channel**; **portfolio = public identity** when rotation preserves
storage (rational for scarce-shard income). Rotation does **not** reset the observation
window: effective `T_obs` = operator **lifetime**. T-A3–T-A7 must hold against that window;
see [`F1_TA3_TA7_LIFETIME_WINDOW.md`](F1_TA3_TA7_LIFETIME_WINDOW.md).

**Honest disclosure:** re-linkability across rotation is portfolio-bound; decorrelation
requires abandoning scarce-shard income. Forced cohort portfolios price ~97% deep
under-coverage — not a viable mitigation without Form-C / reward-shape reopen.

**F1 disposition:** conditionally finally accepted (qual wargame §9.8). Form-C reopen **not
triggered**. Wallet disclosure draft: [`F1_TA3_TA7_LIFETIME_WINDOW.md`](F1_TA3_TA7_LIFETIME_WINDOW.md) §10.

**Round-open:** jitter policy; drain-spacing defaults (consensus cluster pinned —
[`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) §7).

### 2.4 Output layer

**Goal:** Reward receipts and principal returns do **not** create spend-graph links
between `P` and principal beyond what a disciplined user already avoids on ordinary
transfers.

**Genesis pin (carry from PHASE_2B §2.4)** — *bullets preserved as carried; per-bullet
dispositions from the 2026-07-16 re-walk below are marked inline:*

- Rewards → **stealth outputs `P` controls** (loud amounts; privacy is firewall not
  hiding reward size). *(HOLDS, re-anchored — see re-walk.)*
- ~~Terminal unstake = **decorrelated drain** `P`→principal — not a lump sweep that
  ties reward history to a single principal output cluster in one block.~~ *(RETIRED as
  phantom — F-W10, §12.9 decision 2; see GF-4 status below.)*
- **Unbond refund** ([`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §2.4): ~~release
  creates a P-attributed output at public `bond_floor` amount; mixes in the FCMP++ set like
  any output — same decorrelated-drain discipline as reward receipts (amount is public;
  spend anonymity is tree membership).~~ *(HALF-PHANTOM, corrected — the tx is
  `P`-attributed and the amount publicly derivable, but the refund is ordinary hidden
  vouts; no identifiable refund output exists. See re-walk; gate-4 §2.4 corrected at
  source.)*

**Method-note-5 re-walk (2026-07-16, night) — the other two carries, asked the same
question.** F-W10 retired the middle bullet at ratification; per §11.8 method note 5 the
remaining two carries of this pin were re-walked against what FCMP++ actually emits in the
same sitting, instead of waiting to be caught one at a time:

- **Rewards → stealth outputs `P` controls: HOLDS — but the load-bearing property is
  §2.1's, not this layer's.** What the bullet actually delivers is key/scan-boundary
  independence: rewards are scannable and spendable only under `P`'s HKDF-independent
  keypair, so disclosure of either wallet's scan capability reaches nothing of the
  other's income. That is a *creation-side* mechanism — whose keys the mint pays — and
  it is substrate-independent, true under both lineages. The graph-side half of its
  lineage-era justification ("stealth so the reward can't be traced onward to the
  principal") is met by construction under FCMP++ on F-W10's grounds: reward-output
  spends are unenumerable and carry no `P`-typing on the wire
  ([`ARCHIVAL_EXIT_STANDOFF_FD4_WINDOW.md`](ARCHIVAL_EXIT_STANDOFF_FD4_WINDOW.md) §16.1).
  **Re-anchored, not retired** — the bullet survives because its mechanism never needed
  the graph.
- **Unbond refund: HALF-PHANTOM — the factual phrasing is the visible-graph intuition
  written down, and the discipline tail retires with F-W10.** "Release creates a
  P-attributed **output** at public `bond_floor` amount" is wrong at the output layer:
  the *transaction* is `P`-attributed and the *debit amount* is public, but the refund
  enters as **ordinary hidden vouts**, CT-balanced against the public `bond_debit`
  source term ([`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §2.4 release-refund
  note, §3.5 connect semantics) — there is no identifiable "refund output" for any
  observer to follow, which is why F-D4 §2.1's T-2 graded the watch-the-refund channel
  **structurally unrepresentable** before this re-walk reached the bullet. A phrasing
  that names an output an observer could track presupposes the graph that would let
  them track it. The tail — "same decorrelated-drain discipline as reward receipts" —
  cites the discipline F-W10 retired and **retires with it**. What survives is what the
  wire actually emits: the `Unbond` post itself, `P`-side public by design, an exit
  event with no principal-side referent (F-D4 §16.1 lifecycle table). No wallet output
  rule is owed here either.

Scorecard for the pin as a whole: one bullet retired (F-W10), one re-anchored to its
real mechanism, one corrected to the wire and stripped of its retired tail. The layer's
goal statement stands — met by construction on the graph side, by §2.1 key independence
on the creation side.

**Round-open:** minimum delay / output-count discipline between last emission and
drain; change-output handling on bond-funding transfers.

**GF-4 status:** the drain **delay floor** is already pinned (`≥ RELEASE_COOLDOWN ×
SETTLEMENT_EPOCH_BLOCKS`, [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) §7), so
"how long after last emission" is closed. The genuinely-open piece is the **terminal-drain
output-count discipline** — a single lump sweep still re-links the reward history to one
principal cluster even with the delay satisfied. That output-count discipline is the **Round 4
hard exit** (§6), not a Round-1 carry. **UPDATE 2026-07-16 (F-W10 — Gate-6 §12.9 decision 2,
at ratification): the output-count discipline is phantom under FCMP++ and is retired.** The
lump-sweep attack this pin defends against is real in the CryptoNote/ring-signature lineage
this pin was carried from (partially visible spend graph: ring members, key images, traceable
output clusters); under FCMP++'s full-chain membership proofs the drain is **not an
identifiable transaction** — the spend set is unenumerable, reward-output spends carry no
`P`-typing on the wire — so its output count is not an observable, and this section's own
goal ("beyond what a disciplined user already avoids on ordinary transfers") is met by
construction. The pin was carried across the crypto change without being re-walked against
it; §11.8 method note 5 records the lesson.

**GF-4b — emission backing-output lineage (mandatory, firewall-class; 2026-07-01).** The emission
vin reveals the backing output's `pqc_pk` in cleartext (the quantum spend-authority gate,
[`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §7.3), which — leaf extra-scalars being publicly
enumerable — **deterministically identifies that one output** (per-output one-time key, so scoped to
exactly it) and its creating tx. Per the §7.3 invariant this is safe (principal↔P rests on
input-anonymity + amount-decorrelation; identification does not reach the funder) **only** when the
backing is not a raw pre-bond-post funding output. Backing-output selection is therefore a
**mandatory** firewall policy, not optional hygiene — the lineage ladder, most→least safe:

1. **mint/earned lineage** — reward outputs P earned; provenance terminates at consensus, so
   identification reveals nothing beyond P's own public emission history.
2. **bond-post-change lineage** — cover/working-capital change returned by the bond-post tx; its
   creating tx is already P-public and its backward lineage (which funding it consumed) is
   FCMP++-hidden, so the bond post is itself one churn hop.
3. **raw pre-bond-post funding lineage** — **FORBIDDEN**: the only rung whose reveal newly
   identifies the funding tx and its **timing** (funding height → off-chain-principal correlation).

**Named threat:** emission `pqc_pk` reveal → funding-tx identification → funding-timing correlation.
**The forbidden rung is made structurally empty** by the sweep rule in
[`PRINCIPAL_STAKE_LIFECYCLE.md`](PRINCIPAL_STAKE_LIFECYCLE.md) (bond post / re-bond consume P's
entire spendable funding set → nothing raw survives backing-eligible; first-emission backing is
necessarily bond-post change) — this policy is **enforced by construction**, not left to per-tx
discipline.

**DQ4 cross-note (two-regime = privacy-exposure transition).** The DQ4 fund-from-earnings transition
([`PRINCIPAL_STAKE_LIFECYCLE.md`](PRINCIPAL_STAKE_LIFECYCLE.md)) is **also** a privacy-exposure
transition: the first renewal funded from earnings moves P permanently onto **mint-clean** backing
(rung 1), off even the one-hop bond-post-change rung. Bootstrap sits at rung 2 by construction;
steady state converges to rung 1.

### 2.5 Bond-funding layer (fifth surface)

**Goal:** Posting per-shard bonds does not become a **principal→`P` correlation channel**
(lump funding from a fresh principal output immediately before first emission).

**Gate-7 input (closed bonds-only, 2026-06-11):** there is **no consensus admission
minimum** — `ADMISSION_MIN_ATOMIC` was deleted from the emission leg
([`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §10.2;
[`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) ledger G7). Bond sufficiency at
join-Market (gate 4) is the **only** consensus-checked funding obligation on `P`. Any
funding minimum or ramp shape is therefore **this layer's policy alone**, owned here
end-to-end; nothing upstream constrains it.

**Policy pin (2026-06-11): no funding minimum, at any layer.** The wallet imposes **no
minimum** on principal→`P` transfers. Rationale, by surface: *consensus* — admission
amounts do no consensus work (gate 7); *Sybil pricing* — market identities are priced
by `bond_floor × shards` at join-Market, not by `P`'s balance; *economics* — the
gate-7 sim showed admission-side locks macro-immaterial at every tested magnitude;
*privacy* — stake-in amounts are confidential (ordinary FCMP++ transfer), so a
prescribed minimum is unobservable on-chain and does no firewall work — this layer's
real threats are funding **shape and timing** (lump-vs-ramp, join-Market adjacency),
which a minimum does not address. A floor with no load-bearing surface is optionality
debt. **Reversion (rule 21):** reopen iff a named gate-6 threat or V3.x consensus
change makes an amount floor load-bearing (e.g., a future emission rule that reads
`P`-balance, or a demonstrated dust-funding attack on wallet scan performance);
re-evaluation is a §2.5 round with the threat named, not a reflex re-derivation.

**Open disposition (joint with gate 4 join-Market):** **fund-from-earnings ramp** vs lump
initial bond vs mixed — wallet hygiene spec, not consensus rule. Consensus sees bond
sufficiency at join-Market; **how** `P` acquired collateral and **when** join-Market
fires relative to principal activity is observability the firewall must address
([`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §6).

---

## 3. `P` lifecycle — events gate 6 must cover

```text
[seed] → derive P → announce/backing (off-chain) → join-Market (on-chain bond anchor)
       → serve + challenges → paying emissions → bond updates / slash / re-bond
       → optional rotation P_old → P_new (portfolio-changing) → lapse / forfeit
       → terminal drain → retire P
```

| Phase | Consensus-visible? | Gate-6 load-bearing |
|-------|-------------------|---------------------|
| HKDF derive `P` | No | Independent material; scan isolation |
| Off-chain announce + backing presentation | Peers see | Backing before join-Market; no principal metadata |
| **join-Market** | Yes (bond record create, `E_join`) | **Standing timing event** — defang via §2.3/§2.5; cannot hide in mint |
| First **paying** emission | Yes (mint + dedup) | Decorrelate from principal funding |
| Ongoing service | Yes (retention bits, holdings) | Network path; epoch-timeline fingerprint |
| Rotation | Yes (new `P_id`, holdings transfer) | Portfolio change only — cosmetic swap insufficient (T-A1) |
| Deliberate lapse > `W` | Yes (forfeiture) | Forfeiture economics — does not decorrelate without portfolio change |
| Terminal drain | Yes (transfer) | Output decorrelation |

**Registration fusion:** No separate *registration tx type*; **join-Market** is the
on-chain anchor ([`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md)). Off-chain backing
**precedes** join; first **paying** emission follows by ≥ one settlement-epoch lag.

**"Rotation" is not a mechanism (corrected root:
[`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) P2B-1; do not re-litigate).** Neither sense of
"rotation" is a decorrelation lever:

- **Backing-output "rotation" is not a mechanism.** A persona designates a (possibly different)
  output from its **own `funding_outputs` pool** per emission (membership-only) — there is **no
  `backing_outputs` field** in the code and **no consensus rotation rule**
  ([`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §7.3, "consensus does not require
  backing-output rotation"). No backing output is shared between personas (each is scanned under one
  `P`'s view key). `P_canonical_id` is **unchanged** — the only point here: key the instance on it,
  never on an output.
- **Pseudonym "rotation" is unlink-and-relink, and it *correlates*.** Retire `P_old` (`Unbond` +
  drain) + create `P_new` (fresh `JoinMarket`): two independent lifecycle ops, **no bond migration**
  (S-5, §10.12). It provides **correlation, not decorrelation** (T-A1 portfolio re-linkage), which
  is exactly why **long-lived `P` is the committed architecture** (S-5). `p_slot` (§9.2) derives a
  *fresh* persona — **not** a rotation of an existing one; the sim's step-0 "over-enumeration (new
  slot; burn old)" is that same unlink-relink (reversion: per-root subkey only, never
  cross-authorizing master — [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §*Step 0*).

---

## 4. Invariants (load-bearing)

1. **No principal material on `P` wire paths** — addresses, view tags, enc labels, and
   scan hooks for `P` must not reuse principal derivation labels or linkable tags.
2. **Reachability without location** — any peer that must challenge `P` can do so via
   the agreed rendezvous layer without learning clearnet operator location.
3. **Emission timing ≠ principal timing** — a watcher cannot align principal spends and
   `P` emissions to a single clock better than chance + public epoch boundaries, under
   stated wallet discipline.
4. **Rotation is not cosmetic (network leg)** — `P_new` must not share principal clearnet
   path / network fingerprint. **Portfolio/timeline leg superseded by T-A1:** cosmetic
   rotation with fixed storage is rational and re-linkable on public holdings (F1 residual);
   see [`F1_TA3_TA7_LIFETIME_WINDOW.md`](F1_TA3_TA7_LIFETIME_WINDOW.md) §9.7.
5. **Cross-`P` hygiene** — multiple `P` from one principal require **per-`P`** network,
   timing, and output discipline; intersection is the residual class named in V3 honest
   residual.
6. **Bond funding does not default-link** — wallet default must not fund bonds from a
   traceable fresh principal→`P` pattern without an documented alternative path.

Violations are **privacy failures**, not consensus faults — but genesis ships with
wallet/daemon defaults that **enforce** the invariants or loud-fail into unsafe posture
(pre-genesis: loud fail per user-absent-context discipline).

---

## 5. Consumer map — who implements what

| Component | Gate-6 responsibilities |
|-----------|-------------------------|
| **`shekyl-wallet-core` / `StakeEngine`** | `P` HKDF; build emission/drain txs; rotation ceremony; bond-funding UX defaults; local jitter |
| **`StakeEngine` — `P`-scan identification context** | **Sole owner of `P.view_sk` and the `P`-scan pipeline** — a Gate-6 forward requirement on the PHASE_2B FSM retool, not inherited from claim-era §4.6 (§9.6 ownership-boundary clause). `P`-output identification descends from `P`'s `combined_ss`/decap, structurally disjoint from the principal `LedgerEngine` scan; outputs route by which decap matched, never cross-assigned |
| **`LedgerEngine` — principal-scan context** | Owns principal `view_sk`; **must not** receive `P.view_sk` or `P` decap material; principal scan never claims a `P`-destined output |
| **`shekyld` (daemon)** | Peer reachability to `P`; challenge routing; optional policy hooks — **must not** require principal identity for archival RPC |
| **Transport stack** | Onion rendezvous for serving; seeding-path rules (step 2) |
| **GUI / mobile** | Surface rotation/lapse warnings; no principal↔`P` linking in logs or RPC |

**Stage 3 blocker:** `StakeEngine` replaces `is_active_staker(entity_id)` — gate 6 **is**
the staking identity surface ([`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §2).

---

## 6. Design rounds

Status of record is this table; the round-detail sections (§9 R1, §10 R2, §11 R3) and the
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) landed-code stamps are the reconciled sources
each cell points at. **"Closed" means the round met its own exit bar** — for the network round that
bar is defense-in-depth (§10.0: every leak vector named, mitigation specified and testable, residual
written down), **not** "linkage impossible" and **not** "all implementation landed" — so a closed
round may carry named implementation/tuning items with rule-21 criteria (R1 closed with its impl
carried; R2 the same).

| Round | Focus | Exit criterion |
|-------|-------|----------------|
| **0** | Scaffold + invariant frame + consumer map | **Done** |
| **1** | HKDF/`P_id` wire + crypto layer hooks | **Closed (2026-06-13)** — §9 GF-1 dual-key verifier contract resolved; GF-2 dual-scan enforcement made architectural; reviewer sign-off (§9.8). **Carry discharged (2026-07-11 reconciliation):** `ARCHIVAL_P_DERIVE_V1` KAT + `archival_p` module **landed** (Bond-PR 0 #152; `archival_p.rs` + `kat_archival_p_derive_v1.rs`, seven §9.3 labels incl. `bond_spend_*` verified at source). C-1 emission vin ML-DSA equality check **landed** (#277). §7 checklist reconciled to landed state. |
| **2** | Network + transport (L16 → production shape) | **Closed (2026-07-11) — §10; closure disposition §10.13.** Rendezvous path specified; seeding relaxation bounded. **Entry gates (all dispositioned):** challenge-response Levin class → anonymity-routable set (GF-3, §10.4); pre-join backing-presentation transport (GF-5, §10.5); Arti HS-hosting capability confirmed, at-source pin carried (GF-12, §10.3); `P`-tx wire-size fingerprint characterization + dummy/fragmentation policy (GF-6, §10.6); HS key lifecycle `p_slot`-bound + seed-derived (GF-9, §10.7). **Exit dispositions (§10.11, passes 1–4):** bonded-verifier challenges, broadcast announce, `P`↔principal circuit/guard isolation (§10.9), pure-rendezvous + I2P-closed. **Carries (§10.13, rule-21):** at-source Arti pin → transport PR; dummy/frag tuned ratio → testnet; **GF-9 HS-id HKDF label → §9.3 amendment (armed: not yet in derivation; dot-vs-hyphen format flag)**; announce↔anchor + cadence timing → R3. Transport code partial-landed (2d-2: SP-T1 #204/#209, SP-T4a #254 — inert). |
| **3** | Timing + rotation + `W` / epoch-length joint pin | **Designed + adversarial pass run (2026-07-11) — §11; closes on the R4/GF-4 joint grade (§11.7).** **GF-10** pinned as *mechanism + structural window* (uniform-independent claim-broadcast-height draw via audited `bounded_uniform`; floor = `h_close + reorg_depth(720)`, ceiling = `(E_oldest+W)·SEB − submit_guard`; a-priori `S_min ≥ SEB`); **numeric width routed to R4/GF-4 CB-3 joint grade** (not standalone — per-axis error avoided). Draw + scheduler **unbuilt** (verified) → pinned pre-code, M1-armed. Rotation leg ratified (T-A1 timeline non-channel; network leg §10.7/§10.9); R2 timing hand-forwards resolved (announce↔anchor = entry standoff; emission-cadence = GF-10). Adversarial pass (§11.8) found no break — four findings folded as re-pins, one retraction (max-age misread). Two frame/pass assumptions overturned at source (epoch-crossing §11.4; max-age semantics §11.8). UPDATE 2026-07-16 (§12.9 decision 3): the R4 joint grade **dissolved by axis attrition** — GF-10's width now grades **standalone** against the §11.5 pre-committed advantage claim (mechanism-class, method note 3); R3 closes when that grade runs. |
| **4** | Output + bond-funding hygiene (**recurring** — rebond/unbond at genesis) | **Drafted (2026-07-11) — §12, the drain-event firewall.** **GF-7 (funding-in) built + graded PROVISIONAL-PASS** (`r = 1.86`, local-daemon; standoff #255, WI-4, §14.4 partition arm RATIFIED #291, leg-(b) sealing form: first PASS withdrawn 2026-07-18 (§19.9.1), hardened re-run graded PASS 2026-07-19 (§19.9.2), seal-input status withdrawn same day on scope review (WI-4 §19.10 — premise design-foreclosed; instrument retained as dispersal tripwire)) — not an open design question. **GF-4 (value-out) drafted:** the drain is one event, three co-triggered channels graded jointly (§12.1). **F-D1** drain-amount taint-carve — complete pre-code pin ((a)+strip; strip `{lineage,epoch,height}` + aggregate-scalar amount stage; §12.3); **F-D2** UI-default (§12.4); **F-D3/F-D4** one-sided cooldown-anchored exit standoff — **FSM gate FIRED 2026-07-15** (§12.5–12.6; `bond_post.rs:369`/`:627`); **F-D5** quantization → §14.4; **F-D6** anti-drift derive-don't-hardcode (§12.7). GF-10 (R3) folds into the joint grade. UPDATE 2026-07-15: both former blockers discharged — the rebond/unbond FSM landed (PR #303 `HoldingsUpdate`/`Unbond` + Pin-4/Pin-5 closure 2026-07-14; PR #307 `Rebond`) and the age-stratified sim reconciliation is DONE, seal cleared (`STAKER_ARCHIVAL_SIM.md` §L18). F-D3/F-D4 open for build: F-D4 a-priori window derivation first (committed before any sweep runs, §12.6), then `draw_exit_gap` (§12.5) with the F-D6 derived anchor. UPDATE 2026-07-16: derivation committed + reviewed (rounds 1–3, sentinel + frozen rule); **`draw_exit_gap` BUILT** against the sentinel with the F-D6 anchor derived (`release_cooldown_anchor_height`) — F-W5 `N_t` re-derivation, sweep, and Phase 7.7 seal remain. UPDATE 2026-07-16 (later): round-4 premise audit RATIFIED deletion-with-tripwire (F-D4 §15.4 — the timing channel's observable is phantom, F-W7/F-W8; the seal obligation is removed, the sentinel never shipped a value); F-W9 bounded the repetition premise (F-D4 §16). **R4 decision round run + RATIFIED (§12.9):** exit seam **re-homed** to the principal↔user crossing (WI-4 §18.13); joint grade **dissolved by four-axis attrition** (ratification added the fourth row: **F-W10 — output-count phantom**, the drain is not an identifiable transaction under FCMP++; §2.4's CryptoNote-lineage pin retired, method note 5); §16.4 funding default **accepted** (F-D2-class); deletion PR scoped (`exit.rs` wholesale; F-D6 + consensus predicate out of scope). Re-formed close: F-D1 + F-D2 (incl. funding default) + deletion PR + F-D5 §14.4 disposition. UPDATE 2026-07-17: the **deletion PR landed** at decision 5's scope — close condition (iii) satisfied; remaining: F-D1, F-D2 (incl. funding default), F-D5 §14.4 disposition. UPDATE 2026-07-17 (later): **F-D5's "→ §14.4" was dangling** (WI-4 §14.4 is the closed partition arm, no economics agenda) — close condition (iv) re-worded by dated amendment (§12.9): the **F-D5 disposition round** (charter at §12.7) runs a **structural-derivation attempt first** (grid width from reward-curve structure, X-3-shaped, mechanism-class) — width derives ⇒ grid ships at genesis + S-2 grades the residual; width doesn't ⇒ **no grid at genesis** (genesis-frozen consequence named, pass-4 banding rejection reconciled); the lifetime-aggregate band registers as an R5 S-2 ledger row either way. UPDATE 2026-07-17 (same day): **the F-D5 disposition round RAN — width does not derive, NO GRID at genesis** (harm survives F-D1 — the grid targeted §18.12's drain-all floor — but the derivation fails at three source-anchored population entry points: `r_market` inside `scarcity_milli`, the `budget(E)/Σwork(E)` value spacing, and reachable-collision ≠ delivered cover; the grid's cost side is derivable, its benefit side is not; §12.7 OUTCOME). Close condition (iv) **discharged**; R4 open on **F-D1 + F-D2 only**. UPDATE 2026-07-17 (later): **F-D1 BUILT** (`drain_orchestrator`/`drain_amount`/`drain_select`; (a)+strip; M1 arm proven-to-bite then armed as `fd1_arm_*` tests; §12.3 build note) and **F-D2 core-side surface LANDED** (aggregate-only `DrainBalance`/`drain_balance`, scalar-only `plan_drain`; §12.4 build note) — `plan_drain` lands as a correctly-carved planner with **no data source and no consumer yet**. **F-D2's remaining half is NOT a pending UI default and NOT gated on RPC** (the GUI links the engine in-process, not via a wallet-RPC server): it is a whole **unbuilt `P`-value-out (drain-send) subsystem** in `shekyl-gui-wallet` — a `P`-scan data source feeding the planner + a drain tx assemble→sign→broadcast path + the round-number/random-split default on top (§12.4 build note). **R4 open on that subsystem.** |
| **5** | Cross-layer adversarial pass | **Planned.** Soundness-depth sign-off for Stage 3. Build the S-2 fused exposure ledger (first) + the S-3 exit/value-seam adversary sim (§10.12), then sign off. **Registered S-2 ledger rows so far:** the lifetime-aggregate (drain-all) band at the §18.13 crossing (from the F-D5 disposition round, 2026-07-17 — per-observer, off-chain, graded against measured post-genesis exposure; §12.7 OUTCOME); R5 also inherits F-W9's finite domain and the §16.3 re-formed cross-persona job (linking-key search, pre-registered as code). |

**Parallel (not gated on gate-6 closure):** [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md)
schema implementation; PHASE_2B §3–§7 FSM retool off rebased §2.4.

**Round-2 scope expansion — rebond/unbond at genesis (R-1/R-2/R-3).** Bond is consensus-tracked
balance under a gate-4 conservation law, not a UTXO; every balance change is a consensus
transition, so completing the bond FSM post-genesis is a **hard fork**. Genesis already carries
`JoinMarket` / `Rebond`-after-slash / full `Unbond` + a release cooldown
(`RELEASE_COOLDOWN_EPOCHS = 2 < W`) and a `bond_duration(age)` retention horizon; **voluntary
partial-unbond (`HoldingsUpdate`, gate-4 §4.4) is promoted to genesis scope (V3.0, decided
2026-06-15)** — add-shard covers the voluntary holdings-*increase* / top-up direction (the §9.6
"no dedicated wire" gap is closed by the add-shard credit path). Pinning the
**full** lifecycle at genesis (the gate-4 / FSM-retool call) turns three **one-time** firewall
events into **recurring** ones — GF-7 funding-linkage, GF-4 decorrelated-drain, GF-10
within-epoch timing each get *many* correlation shots instead of one (R4 re-scoped above).
**Genesis-seal dependency (R-3):** the staker-archival sim **explicitly abstracts the release
cooldown ("sim still unmodeled"), partial slashing, and capital-lockup opportunity cost to "a
flat seating cost"** ([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §*steady-state frame*
item 6), modeling only the `bond_duration` commitment (L9/L10). The genesis-seal `r_target_deep`
redundancy-floor re-derivation is already a reopen criterion against (a) the **integer** backend
and (b) a **+1 deep-tail replica margin** (`ARCHIVAL_SIM_ECONOMICS_VERDICT.md` tail-margin; sim
§L12). Because real bond mobility under cooldown + duration is **lower than the sim's myopic
per-epoch acquire/drop** exactly on the **deep tail where the +1 margin lives**, R-3 adds (c): a
**sim bond-mobility model reconciled to the rebond/unbond FSM's frictions.** (c) cannot be
computed until the FSM (the now-genesis-scoped lifecycle, promoted 2026-06-15) is pinned — so the
**rebond/unbond FSM is a pre-genesis-seal dependency for the sim reconciliation, not merely a
consensus deliverable.**
**The reconciliation must be age-stratified, not a re-tuned flat scalar.** The sim's "flat
seating cost" is a uniform scalar standing in for a friction (cooldown, partial-slash, lockup,
`bond_duration(age)`) that is itself **age-stratified — worst on the deep tail**. Merely
recalibrating the flat cost to a network *average* stays structurally optimistic precisely on the
binding constraint, because the deep tail's friction is *above* the average and that is where
recovery mobility matters most. So the pre-seal requirement is **"model the friction
age-stratified,"** not "add the frictions" — a re-tuned flat cost will *look* reconciled while
shipping an optimistic sealed floor on top of the very +1 margin it is meant to protect.

*(UPDATE 2026-07-15 — this dependency chain is discharged end-to-end: the FSM frictions were pinned
(P2B-7) and landed as enforced consensus (PR #303 `HoldingsUpdate`/`Unbond` + Pin-4/Pin-5 closure;
PR #307 `Rebond`), and the age-stratified reconciliation (c) is DONE, seal cleared —
`STAKER_ARCHIVAL_SIM.md` §L18, adversarially confirmed to clear the "age-stratified, not a re-tuned
flat scalar" bar 2026-07-12. The paragraph above stands as the reasoning record.)*

---

## 7. Implementation checklist (pre-code)

Reconciled to landed code 2026-07-11 (`dev` `75c3cae1d`; status-of-record is
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) — this list marks each item's round and
whether its design pin and its code have landed, and does not restate the index's detail). A `[x]`
here means **the gate-6 design pin is discharged**; a trailing "code:" clause states the landed
artifact where one exists.

- [x] Pin `P` HKDF labels + `P_canonical_id` alignment with emission leg (§9). **code:** `archival_p.rs`.
- [x] Pin per-tx-type verifier contract — account `hybrid_sign_pk` is bond-record identity only;
      per-input auth is per-output (GF-1, §9.6).
- [x] **Land `ARCHIVAL_P_DERIVE_V1` KAT vectors + `shekyl-crypto-pq` `archival_p` module** —
      incl. the `shekyl-archival-p-bond-spend-{ed25519,ml-dsa-65}-v1` labels → `bond_spend_pk`
      (GF-1; §9.3 / §9.4). **code (Bond-PR 0 #152, verified 2026-07-11):**
      [`archival_p.rs`](../../rust/shekyl-crypto-pq/src/archival_p.rs) (7 labels present),
      [`kat_archival_p_derive_v1.rs`](../../rust/shekyl-crypto-pq/tests/kat_archival_p_derive_v1.rs).
- [ ] Pin off-chain announce/backing presentation wire (daemon + wallet). **R2 transport half
      pinned** (GF-5 broadcast, §10.5 / §10.13); the *wire* half is the residual (§10.13 carry).
- [ ] Pin rotation ceremony (over-enumeration; holdings/bond migration). **→ R3** (§11; §2.3 P2B-1
      two-rotation split + `p_slot` over-enumeration already pinned, §9.2).
- [x] Pin network rendezvous requirement for production archival serving — **R2** (§10.2 heavy-path
      onion-rendezvous, no clearnet fallback; §10.9 isolation). **code:** partial, inert (2d-2).
- [ ] Pin wallet defaults: emission batching, drain decorrelation, bond-funding ramp
      (T-A4/T-A6 conditional passes; [`F1_TA3_TA7_LIFETIME_WINDOW.md`](F1_TA3_TA7_LIFETIME_WINDOW.md) §9).
      **Split:** batching **landed** (`MAX_SETTLEMENT_EPOCHS_PER_EMISSION = 15`); **drain decorrelation +
      ramp → R4**; **within-epoch claim jitter → R3 (GF-10, un-pinned).**
- [ ] Land wallet disclosure §10 in UX copy. **→ R3/R4 (F1 disclosure draft §10, UX).**
- [x] SEB pinned (10_000) — joint gate-2 cadence + epoch-granularity fingerprint (`ARCHIVAL_TIMING_CONSTANTS.md` §1.2).
- [ ] Rebase PHASE_2B §7 threat model — draft:
      [`PHASE_2B_SECTION7_DRAFT.md`](../completed/PHASE_2B_SECTION7_DRAFT.md) (review → land).
- [ ] Stage 3 test vectors: cross-layer linkability negatives — **including the GF-2
      cross-pipeline non-cross-assignment test** (no output emitted to both principal and `P`
      scan contexts; §9.6). **→ R5.**
- [x] **C-1 forgery negative (emission vin ML-DSA equality check):** a backing input that
      proves leaf membership while supplying a `pqc_pk` whose `H(pqc_pk)` does **not** equal the
      leaf-committed extra scalar is **rejected** by the emission vin verifier. **code (PR #277,
      `dev` `13c368707`):** `emission_verify.rs`; quantum spend-authority no longer classical-only
      (§9.8 C-1 discharged). The honest-path stressnet "staking lifecycle completes 100 full
      cycles" criterion + the blob-boundary arm remain the **regtest e2e residue** (E4/E5 gate,
      `FOLLOWUPS.md`), not a gate-6 deliverable.

---

## 9. Round 1 — `P` hybrid derivation (genesis pin — Round 1 CLOSED 2026-06-13)

### 9.1 Design disposition

| Question | Disposition |
|----------|-------------|
| Hybrid vs classical-only `P`? | **Hybrid** — same FIPS 203/205 stack as V3 genesis; `ArchivalBondRecord.P_pubkey` is `HybridPublicKey` ([`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §6.2). |
| Same algorithms as principal? | **Yes** — independence is **HKDF domain separation**, not different primitives. |
| Where does code live? | New module in `shekyl-crypto-pq` (e.g. `archival_p.rs`). **Do not** mutate frozen [`account.rs`](../../rust/shekyl-crypto-pq/src/account.rs) v1 / `ADDRESS_DERIVATION_V1` KATs. |
| Principal `AllKeysBlob` shape? | **Unchanged.** `P` material is a **parallel** derivation path from the same `master_seed_64`. |
| Account-level ML-DSA for `P`? | **Yes** — bond record and `pqc_auths` need a stable per-`P` `HybridPublicKey`. Principal account keys carry Ed25519 + ML-KEM only; per-output ML-DSA stays on the output path. `P` adds **account-level** ML-DSA via deterministic seeded keygen (same helper as [`derivation.rs`](../../rust/shekyl-crypto-pq/src/derivation.rs) `keygen_from_seed`). |

### 9.2 Inputs and slot index

```text
master_seed_64   // wallet file — same as principal ([account.rs](../../rust/shekyl-crypto-pq/src/account.rs))
network, format  // DerivationNetwork + SeedFormat — same salt_for() as principal
p_slot: u32      // rotation slot; genesis default 0; increment on pure over-enumeration rotation
```

**Slot rule:** `p_slot` is wallet-persisted stake metadata (not consensus). Rotation burns the
old slot's operational use and derives `P_new` at `p_slot' = p_slot + 1` (or next free slot
per wallet policy — numeric rule pinned at implementation; minimum requirement: **new slot ⇒
new keys**). Consensus sees only the resulting `P_canonical_id`.

### 9.3 HKDF pipeline (mirrors `account.rs`)

Reuse the principal salt and wide-reduce discipline:

```text
salt = salt_for(network, format)
       // e.g. b"shekyl-master-derive-v1-mainnet-bip39"

HKDF-SHA-512(salt, ikm = master_seed_64, info = LABEL || 0x00 || p_slot.to_le_bytes(), L = per-row)
```

The single-byte `0x00` separator in `info` is **genesis-frozen** (see the info-string note
below); it is not optional and is part of every row's derivation.

`L` is **pinned per output** in the table below (it is not a free parameter). Two
representations are in play and the distinction is load-bearing (see the **scalar-vs-seed**
note below): `64` for the **wide-reduce-to-scalar** paths (Ed25519 *address* spend/view and
ML-KEM `d_z`) and `32` for the **deterministic-seed** paths (ML-DSA-65 keygen seed and the two
Ed25519 hybrid-half RFC 8032 seeds). This matches
[`account.rs`](../../rust/shekyl-crypto-pq/src/account.rs) (`L=64` wide-reduce → address
scalars) and [`derivation.rs`](../../rust/shekyl-crypto-pq/src/derivation.rs)
(`L=32` → `keygen_from_seed(seed: &[u8; 32])` for ML-DSA, and `L=32` `ed25519_pqc_seed` →
`SigningKey::from_bytes(seed)` for the Ed25519 half of a hybrid key).

| Output | Info label (`LABEL`) | `L` | Consumer |
|--------|----------------------|-----|----------|
| `spend_wide` | `shekyl-archival-p-ed25519-spend-v1` | 64 | `wide_reduce_to_scalar` → Ed25519 **address** spend scalar (`P` receive address, §9.4 "Receive address") |
| `view_wide` | `shekyl-archival-p-ed25519-view-v1` | 64 | `wide_reduce_to_scalar` → Ed25519 **address** view scalar (+ `montgomery(view_pk)` → x25519 scan path, §9.6) |
| `kem_d_z` | `shekyl-archival-p-ml-kem-768-v1` | 64 | `ml_kem_chacha_seed_from_d_z` → ML-KEM-768 KG (same SHA3-ChaCha intermediary as principal; **separate `d_z`** from label) |
| `account_sign_seed` | `shekyl-archival-p-ed25519-account-sign-v1` | 32 | `SigningKey::from_bytes` (RFC 8032 seed) → Ed25519 half of `hybrid_sign_pk` / `hybrid_bond_id` (**identity**, dedicated seed — *not* the address spend scalar) |
| `ml_dsa_seed` | `shekyl-archival-p-ml-dsa-65-v1` | 32 | `keygen_from_seed` → ML-DSA-65 half of `hybrid_sign_pk` (ChaCha20Rng seeded) |
| `bond_spend_ed_seed` | `shekyl-archival-p-bond-spend-ed25519-v1` | 32 | `SigningKey::from_bytes` (RFC 8032 seed) → Ed25519 half of `bond_spend_pk` (GF-1; gate-4 §4.1) |
| `bond_spend_ml_dsa_seed` | `shekyl-archival-p-bond-spend-ml-dsa-65-v1` | 32 | `keygen_from_seed` → ML-DSA-65 half of `bond_spend_pk` (GF-1) |

**Scalar-vs-seed resolution (2026-06-17, genesis-frozen).** The hybrid signing scheme
`HybridEd25519MlDsa` ([`signature.rs`](../../rust/shekyl-crypto-pq/src/signature.rs)) is
**seed-keyed**: `SigningKey::from_bytes` treats its 32-byte input as an RFC 8032 seed and
derives the signing scalar as `clamp(SHA512(seed))`. A `wide_reduce_to_scalar` output is a
*scalar*, not a seed; feeding scalar bytes in as a seed would re-hash them into a different
key and is a category error. Every other hybrid key in the codebase (per-output
`derivation.rs`, multisig) derives its Ed25519 half as a **dedicated 32-byte seed** under its
own label; the `P` identity and bond-spend halves follow that precedent. The earlier draft's
`ed25519 = spend` (reusing the address spend scalar) was an artifact of that confusion and is
removed. Consequences, all checked at source before freezing:

- **`spend_wide` / `view_wide` stay `64`/`wide_reduce`** — they feed the `P` *receive address*
  (`spend_pk`, `view_pk`; §9.4 "Receive address"), which is genuinely a scalar consumer
  (`spend·B`, `montgomery(view)`). They are *not* reused for any hybrid half.
- **The identity hybrid gets its own `account_sign_seed`** (new `L=32` label) — independent of
  the address spend scalar. Nothing requires `hybrid_sign_pk.ed25519 == spend_pk`: §9.5
  `p_canonical_id` only hashes the hybrid pubkey, and §9.6 puts the identity on the wire only
  as `P_pubkey`. `hybrid_bond_id == hybrid_sign_pk` still holds.
- **`bond_spend_ed_seed` converts to `32`/seed** — `bond_spend_pk` is *only* a hybrid debit
  authorizer (§9.4, §9.6), with no address/scalar consumer, so the row is now a seed.

**Privacy rationale (why independence, not just hygiene).** Under the old reuse,
`hybrid_sign_pk.ed25519 == spend·B == the receive-address spend pubkey`, and `hybrid_sign_pk`
rides the wire as the public `P_pubkey` (§9.6). The public identity therefore leaked the
receive-address spend pubkey to every bond-table observer for free — not a critical leak (the
spend pubkey alone doesn't enable scanning; that needs the view secret), but a gratuitous
public-identity → reward-address coupling that expanded the blast radius of any view-key
disclosure. The dedicated `account_sign_seed` removes that coupling: identity, receive
address, and debit authority are now three independently-derived bundles under distinct
labels — the same GF-1-carve separation principle that made `bond_spend_pk` dedicated, applied
to the identity/address boundary §9.5 already calls "a separate presentation layer."

**`bond_spend_pk` is the dedicated bond-debit authorizer (GF-1, §9.6), not the identity key.**
Its two rows above derive a full hybrid keypair (`scheme_id = 1`) under labels domain-separated
from both the identity (`account_sign_seed` / `ml_dsa_seed`) and the per-output tree, so a
bond-spend-key compromise is isolated from `P`'s identity and from individual-output spend. It
is committed into the bond record at `JoinMarket` (gate-4 §3.4.1 / §4.1) and authorizes every
later `bond_debit`.

**Forbidden info labels on the `P` path:** `shekyl-ed25519-spend`, `shekyl-ed25519-view`,
`shekyl-ml-kem-768`, and the entire `shekyl-output-derive-v1` / `shekyl-pqc-output` tree.

**Info-string concatenation note (micro, KAT-authoring).** `info = LABEL || p_slot.to_le_bytes()`
is **not length-prefixed**. It is unambiguous under the current label set — the labels are
non-prefix-free with respect to each other and `p_slot` is fixed-width (4 B LE) — so no two
`(LABEL, p_slot)` pairs collide. The only way to break this is **adding a new label** whose bytes
are a prefix of an existing label's `LABEL || slot` concatenation. **Disposition (now
implemented, 2026-06-17):** the single-byte separator `info = LABEL || 0x00 ||
p_slot.to_le_bytes()` is locked into the `ARCHIVAL_P_DERIVE_V1` derivation and KAT, so the
wire is fixed before any label is ever added. This is the genesis-frozen `info` construction
for every row in §9.3's table.

**ML-KEM intermediary (unchanged function, archival-only input):**

```text
chacha_seed = SHA3-256( b"shekyl-mlkem-chacha-seed" || kem_d_z )
(ek, dk)    = ML-KEM-768.KeyGen(ChaCha20Rng::from_seed(chacha_seed))
```

The SHA3 prefix is **shared** with principal — collision resistance comes from distinct
`kem_d_z` bytes from distinct HKDF info labels.

### 9.4 Wallet-side key bundle (`ArchivalPKeys`)

Logical struct the wallet holds in `StakeEngine` session state (names illustrative;
exact Rust types follow `shekyl-crypto-pq` wrappers):

```text
ArchivalPKeys {
  p_slot:                    u32,
  spend_pk, spend_sk:         Ed25519 spend (typed SpendPublicKey / SpendSecret),
  view_pk, view_sk:           Ed25519 view   (typed ViewPublicKey / ViewSecret),
  ml_kem_ek, ml_kem_dk:       ML-KEM-768 account keys,
  x25519_pk:                  montgomery(view_pk),   // same map as principal
  hybrid_sign_pk, hybrid_sign_sk: Hybrid{ed25519=account_sign_seed, ml_dsa=account ML-DSA},  // IDENTITY; dedicated seed (§9.3), NOT the address spend scalar
  hybrid_bond_id:             HybridPublicKey,       // == hybrid_sign_pk; bond-record IDENTITY only
  bond_spend_pk, bond_spend_sk: Hybrid{ed25519=bond_spend_ed_seed, ml_dsa=bond_spend ML-DSA},  // GF-1 debit authorizer; dedicated seed (§9.3)
  p_canonical_id:             [u8; 32],              // §9.5
}
```

**`hybrid_bond_id` is identity-only.** It is the on-wire `P_pubkey` that keys the bond record
and `p_canonical_id`; it is **never** used as a per-input `PqcAuthentication.hybrid_public_key`.
Per-input spend authority — including emission backing inputs and the terminal drain — is the
**per-output** `shekyl-pqc-output` derivation (the §9.6 GF-1 contract). The account ML-DSA key
inside `hybrid_sign_sk` signs bond-record / emission-identity material, not individual inputs.

**`bond_spend_pk` is the GF-1 bond-debit authorizer (distinct from identity).** Derived under
the §9.3 `shekyl-archival-p-bond-spend-*` labels, it is committed into the `ArchivalBondRecord`
at `JoinMarket` (gate-4 §4.1) and signs the bond vin on **debit** paths (`Unbond`,
`HoldingsUpdate` drop). It exists so that authorizing a *value-out* never requires the identity
key, keeping `hybrid_bond_id`'s compromise surface "reveals nothing spendable." Same
not-persisted-at-rest discipline as the other secrets: `bond_spend_sk` re-derives from
`master_seed_64` + `p_slot` on wallet open.

**Not persisted at rest:** secret fields are re-derived from `master_seed_64` + `p_slot` on
wallet open (same discipline as `AllKeysBlob` ML-KEM decap key). Persist only `p_slot` and
public `p_canonical_id` / holdings metadata in stake ledger state.

**Receive address:** `P`'s Shekyl address uses `(spend_pk, view_pk, ml_kem_ek)` — same
encoding as principal ([`account.rs`](../../rust/shekyl-crypto-pq/src/account.rs) public
layout), different bytes. Peers challenge the **`p_canonical_id`** / bond record identity;
payment address is a separate presentation layer.

### 9.5 `P_canonical_id` (consensus alignment)

Must match emission leg §6.1 exactly:

```text
bond_bytes = HybridPublicKey::to_canonical_bytes()   // scheme_id = 1 (ed25519_ml_dsa_65)
p_canonical_id = cSHAKE256(
  customization = "shekyl/archival-p-id-v1",
  input         = bond_bytes
)[0..32]
```

**Verifier rule:** wallet, daemon, and consensus must compute the same `bond_bytes` from the
same `HybridPublicKey`. Any encoding drift between wallet derivation and emission vin is a
consensus fault.

**Customization versioning:** `shekyl/archival-p-id-v1` is independent of HKDF label
versioning — both bump only on a documented hard-fork / migration (V4 or identity redesign).

### 9.6 Signing and scanning contracts

**Signing surfaces by transaction type (`pqc_auths`) — GF-1 contract:**

`P` transactions use `scheme_id = 1` (`ed25519_ml_dsa_65`). The account-level `hybrid_sign_pk`
(= `hybrid_bond_id`, §9.4) is the **bond-record identity**: it appears on the wire **only** as
the `P_pubkey` field feeding `P_canonical_id` (§9.5), and is **never** a per-input
`PqcAuthentication.hybrid_public_key`. Per-input authentication always uses the **per-output**
`shekyl-pqc-output` derivation, exactly as principal spends do. The earlier draft conflated the
container identity with the per-input auth key; they are distinct surfaces and the verifier
checks each against a different key.

| `P` tx type | Account `hybrid_sign_pk` role | Per-input `pqc_auths.hybrid_public_key` | Verifier |
|-------------|-------------------------------|------------------------------------------|----------|
| **bond-post, collateral-in** (gate 4 `txin_archival_bond_post`: `JoinMarket` / `Rebond` / **top-up**) | `P_pubkey` **identity** — creates/keys the bond record by `P_canonical_id` | **per-output** (funding inputs; key image present) | create/lookup `ArchivalBondRecord`; funding inputs via standard key-image path; `bond_credit` term-rigidity + floor-equality ([`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §3.5) |
| **bond-post, collateral-out** (gate 4 `txin_archival_bond_post`: full **`Unbond`** / **`HoldingsUpdate`** partial-unbond) | `P_pubkey` **identity** on the bond vin — record lookup + mutation keying (**never** the debit authorizer) | **single bond vin** authorizes the `bond_debit` against the record's committed **`bond_spend_pk`** (dedicated debit key, §9.3 labels; gate-4 §3.5 step 5 + §4.1). **GF-1-carve RESOLVED (2026-06-16):** gate-4 §3.5 step 5 re-worded to verify debit paths against `bond_spend_pk`, not `P_pubkey` — identity stays identity-only, bond-debit authority compromise-isolated. `bond_debit == bonded_total` (full) or partial; **P-attributed refund output(s)** | §3.5 verify order; bond-debit auth = committed `bond_spend_pk` (resolved at gate-4 source before the verifier lands) |
| **reward emission** ([`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §5.3) | `P_pubkey` **identity** on the emission vin — bond lookup + dedup keying | **backing inputs:** ML-DSA verifies against the **`pqc_pk` committed in the *same proven leaf, at the same input index*** — the membership proof commits `H(pqc_pk)` as an in-circuit extra leaf scalar (`with_extra_scalars`, index-bound), and the vin recomputes `H(pqc_pk)` from the supplied key and demands equality with **that** leaf's committed scalar ([`FCMP_MEMBERSHIP_ONLY.md`](../completed/FCMP_MEMBERSHIP_ONLY.md) §7), **no key image**. **fee inputs** (`txin_to_key`): **per-output**, key image present | §7.1 emission order; backing auth is membership-only + the vin-layer ML-DSA equality check (**C-1 carried dependency, §9.8** — not yet landed); fee inputs standard |
| **ordinary transfer / terminal drain / reward-output spend** | **none on wire** | **per-output**, key image present | standard FCMP++ path — **no `P`-typing** |

**Bond-post is the recurring self-identifying class (Round-2 scope; rebond/unbond at genesis).**
All four bond mutations are one `txin_archival_bond_post` discriminated by `post_kind`
(`0=JoinMarket, 1=Rebond, 2=Unbond, 3=HoldingsUpdate` — [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md)
§3.2). Genesis already carries `JoinMarket`, `Rebond`-after-slash, and full `Unbond`;
**voluntary partial-unbond (`HoldingsUpdate`) is promoted to genesis scope (V3.0, decided
2026-06-15)** (gate-4 §3.2 / §4.4 G4-6), with the add-shard credit path covering the voluntary
holdings-*increase* / top-up direction. The **full** lifecycle ships at genesis (create /
rebond-topup / partial-unbond / full-unbond) — so completing the consensus FSM later is not a
hard fork. **That promotion is a gate-4 / FSM-retool call** (recorded here, not executed in this
doc); its Gate-6 consequence is that the previously **one-time** firewall
events become **recurring** (§6 Round-2 scope note: GF-7 funding-linkage, GF-4 decorrelated
drain, GF-10 within-epoch timing).

**GF-1-carve — RESOLVED 2026-06-16 (dedicated bond-spend key; gate-4 §3.5 step 5 / §4.1 / §3.4.1).**
The analysis below stands as the *why*; the disposition is no longer open. Gate-4 now commits a
dedicated `bond_spend_pk` at `JoinMarket` and verifies `bond_debit` paths against it, so the
account identity key never authorizes a value-out. The custody model (gate-4 §3.2) was **not**
reopened — the receipt-UTXO direction floated below was declined as a Round-1-seal reopen, not the
minimal fix.

**GF-1-carve — not a symmetric fork; the carve is the default trajectory by omission.** The
collateral-out direction authorizes a *reduction of consensus-tracked bonded balance*, and it is
the **only `P` path with neither a key image (ordinary spend) nor a leaf to bind (emission's
membership-only `R_O` PoK)** — the bond is a consensus balance, so there is genuinely nothing to
authorize the debit except a key the record commits. That is exactly why the account
`hybrid_sign_pk` is "right there" and tempting, and why gate-4 §3.5 step 5 already reads "`P`
hybrid signatures on vin" — phrasing written before the Round-1 identity-only invariant existed.
**If gate-4 implements that sentence at face value, the carve happens silently — by the path of
least resistance, not by a decision.** That is the "absence of the claim is a claim of absence"
trap: the doc must not present this as a balanced fork when the source text tilts it toward the
carve. **Security ordering argues against the carve:** carving changes the account key's
compromise surface from what Round 1 fought to keep minimal — *identifier; compromise reveals
nothing spendable* — to *compromise drains the bond*. That spends the cleanest invariant in the
crypto layer to save one derived key.

**Resolution (landed at gate-4 source, 2026-06-16):** a **dedicated bond-spend key
(`bond_spend_pk`) committed in the bond record at post time** — its own HKDF labels (§9.3
`shekyl-archival-p-bond-spend-{ed25519,ml-dsa-65}-v1`) + KAT entry, domain-separated from the
identity — authorizes debits. Identity-only is preserved; bond-spend authority is
compromise-isolated. No key image is needed: non-replay comes from balance-accounting
(`bond_debit ≤ bonded_total`) plus standard tx-height / input binding (the post sig-preimage
binds `tx_prefix_hash`), which is sufficient. Gate-4 §3.5 step 5 was re-worded to verify debit
paths against `bond_spend_pk` and credit paths against `P_pubkey`; the key is committed at
`JoinMarket` and bound into the sig-preimage (gate-4 §3.4.1 / §4.1).
**Declined (recorded, per `21-reversion-clause-discipline.mdc`):** a *receipt-UTXO* custody model
— mint a non-transferable receipt at bond-post, unbond by spending it on the standard per-output +
key-image path (replay protection for free, partial-unbond = receipt split, value-movement leg
**byte-indistinguishable**). It is attractive but **reopens the Round-1-sealed §3.2 consensus-balance
custody model** and unwinds the implemented `bond_credit`/`bond_debit` RCT verifier — a
custody-architecture reversal, not the minimal GF-1 fix. **Reopen criterion:** revisit only if a
later requirement makes the bond value-leg's byte-distinguishability a measured privacy breach
(an S-2/S-3 exposure-ledger finding), at which point the receipt-UTXO model is the named
candidate — via a fresh gate-4 custody-model round, not by inference.

**Why ordinary `P` transfers carry no identity field:** they are byte-shaped identically to
principal transfers, so a verifier cannot (and must not) tell a `P` drain from any other
transfer — that indistinguishability is the firewall property (§4 invariant 1), not a gap.
Only emission and bond-post transactions self-identify, via the `P_pubkey` field and the
archival-bond-table lookup. There is no "is this a `P` spend?" branch on the ordinary spend
path, and so no account-level key on it.

**Dual scan (wallet) — GF-2 architectural enforcement:**

| Scan path | View material | Output derivation | Owner | Must not share |
|-----------|---------------|-----------------|-------|----------------|
| Principal | principal `view_sk` | `combined_ss` from principal decap | `LedgerEngine` | — |
| `P` | `P.view_sk` | `combined_ss` from `P` decap | `StakeEngine` | principal view tags, principal `enc_label` domain |

The firewall here is **structural, not a naming convention.** Its soundness rests on the crypto,
not on which actor runs the scan: each pipeline's per-output secrets descend from a **distinct
`combined_ss`** (distinct ML-KEM decap key + distinct Ed25519 ECDH), so an output that matches
one pipeline's `combined_ss` **cannot** match the other's at the full one-time-key check — the
discriminator is the decap layer, not a downstream label. The output-derive labels
(`shekyl-pqc-output`, `enc_label`) are **shared by construction**; the domain separation that
makes them safe lives entirely in the upstream `combined_ss` / decap material, which is why
pinning that is the load-bearing requirement.

**Ownership boundary (Gate-6 forward requirement on the PHASE_2B retool).** The dual-scan pipeline
(principal + `P`) is an authoritative genesis pin
([`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §2.1 carry-over — "`P` HKDF
sub-wallet … dual scan"). Assigning sole ownership of `P.view_sk` to `StakeEngine` (separate from
the principal `LedgerEngine` scan) is a Gate-6 **requirement the FSM retool must honor**, not a
fact inherited from current PHASE_2B text: §4.6's `StakeEngine` trait surface is **claim-era /
pending retool** (flagged STRATUM in the PHASE_2B header; authority is
[`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md)), so it is not yet a binding ownership pin. The
crypto basis above holds regardless of the actor assignment; this clause pins the assignment so
the retool lands it rather than leaving it implicit.

A **single shared scan loop is acceptable only** if each candidate output is routed by which
`combined_ss`/decap matched, with no cross-assignment — an output is emitted to exactly one
pipeline. Merging the two into one identification context keyed on a single view secret, or
allowing an output to be tried-then-claimed by both contexts, is a firewall violation.

**Negative test (Round-1 named, folded into §7 cross-layer linkability negatives):** no output
is ever emitted to both the principal and `P` pipelines; a `P`-destined output presented to the
principal scan context produces no match, and vice versa. This is the cross-pipeline
non-cross-assignment test. **Defensive invariant (C-3):** "exactly one pipeline" is cryptographically
guaranteed at the full one-time-key check (distinct `combined_ss` ⇒ at most one match), so a
double-match is impossible by construction — the implementation must therefore **loud-fail**
(not silently pick one) if both pipelines' full-key checks ever pass for a single output. Assert
the double-match-is-unreachable invariant rather than assuming it.

**Membership-only emission:** Backing UTXOs are spent under `P`'s **per-output** key material
(not the account key); the verifier omits the key image from the spent set per the emission
leg. Because there is **no key image** on this path, the entire quantum spend-authority property
rests on one binding: the membership proof and the ML-DSA check must reference the **same proven
leaf at the same input index**, not merely each reference *a* leaf. The mechanism that delivers
this ([`FCMP_MEMBERSHIP_ONLY.md`](../completed/FCMP_MEMBERSHIP_ONLY.md) §7, verified at source 2026-06-13): the
`Fcmp` membership leg commits `H(pqc_pk)` as an **in-circuit extra leaf scalar**
(`fcmps::Input::with_extra_scalars`) on the proven leaf, and the per-input challenge binds the
input index (§4.2/§8.2); the vin layer recomputes `H(pqc_pk)` from the supplied key and demands
equality with *that leaf's* committed scalar. An attacker who proves membership of a victim's
leaf cannot substitute their own `pqc_pk` (its hash would not match the leaf-committed scalar),
and cannot forge ML-DSA under the victim's `pqc_pk`. **Caveat (C-1):** the in-circuit half is
implemented in `FcmpMembershipOnly`; the **vin-layer ML-DSA equality check is a not-yet-landed
hard merge blocker** (§9.8 carried dependency). Until it lands, backing ownership reduces to
classical security. Only the bond-record **identity** (`P_pubkey`) is `P`'s account-level hybrid
material; the spend authority is per-output, per the table above.

**"Classical security only" is accurate — there *is* a classical spend-authority belt
(verified at source 2026-06-13).** "Membership-only" omits the **key image / nullifier** (the
linkability tag), **not** the spend authority. The `MembershipSpendAuth` `R_O` leg is a
two-generator Schnorr proof that proves **knowledge of the proven leaf's spend secret `x`**
([`FCMP_MEMBERSHIP_ONLY.md`](../completed/FCMP_MEMBERSHIP_ONLY.md) §5.1: (a) a verifying `R_O` proof implies
knowledge of the specific `x` via the rewinding extractor; (b) that `x` is the `G`-component of a
**real tree leaf**; (c) `x = Hs + b` bakes in the recipient spend scalar `b` — i.e. ownership). So
a **classical** attacker cannot forge a backing claim over a victim's leaf: they cannot produce
the leaf's `x` (discrete-log hardness). The PQ gap is precisely that a **quantum** attacker can
recover `x` from on-chain `O` (Shor), which the leaf-bound ML-DSA equality check forecloses. The
interim is therefore PQ-weak, **not** authority-free — emission may scaffold against the classical
belt, but the vin ML-DSA check must land before any quantum spend-authority claim holds.

### 9.7 V4 reversion clause (per `21-reversion-clause-discipline.mdc`)

| Artifact | Current | Reopen when | Re-evaluation |
|----------|---------|-------------|---------------|
| HKDF info labels `…-v1` | §9.3 table | V4 lattice-only migration specifies successor primitives | New labels `…-v2`; new KAT suite; hybrid `scheme_id` coexistence per [`VERSIONING.md`](../VERSIONING.md) |
| `shekyl/archival-p-id-v1` | §9.5 | `HybridPublicKey` canonical encoding changes | New customization string; bond-record migration doc |
| `scheme_id = 1` on `P` spends | §9.6 | `scheme_id = 3` (lattice threshold) ships for archival spends | PHASE_2B + emission leg amendment; multisig `P` (V3.1) may precede |

**Not a reopening criterion:** "uncertainty about long-term PQC posture" — that is why V3 is
hybrid and V4 is gated; gate 6 does not ship a classical-only `P` escape hatch.

### 9.8 Round 1 exit checklist

- [x] HKDF label table with `-v1` suffixes and `p_slot` binding.
- [x] Account-level ML-DSA disposition for bond `HybridPublicKey`.
- [x] `P_canonical_id` wire aligned to emission leg §6.1.
- [x] Dual-scan and signing-surface separation stated (GF-1 per-tx-type contract; GF-2 architectural enforcement).
- [x] V4 reversion clauses named.
- [x] Reviewer sign-off on Round 1 draft (2026-06-13 — GF-1 resolved, GF-2 made architectural, GF-8/11/4 corrected, downstream round criteria named).
- [x] `ARCHIVAL_P_DERIVE_V1` KAT manifest (fixed `master_seed` + `p_slot` → known `p_canonical_id`
      **and `bond_spend_pk`** — the §9.3 `shekyl-archival-p-bond-spend-*` labels, GF-1). **Landed**
      (Bond-PR 0 #152): [`kat_archival_p_derive_v1.rs`](../../rust/shekyl-crypto-pq/tests/kat_archival_p_derive_v1.rs).
- [x] `shekyl-crypto-pq::archival_p` implementation + unit tests. **Landed:**
      [`archival_p.rs`](../../rust/shekyl-crypto-pq/src/archival_p.rs) (seven §9.3 labels present,
      verified at source 2026-07-11).

**Carried dependencies — DISCHARGED (confirm-at-source status, 2026-07-11):**

- **C-1 — emission backing-input quantum spend-authority binding.** The GF-1 §9.6 emission
  contract rests entirely on the membership proof and the ML-DSA check binding the **same
  proven leaf at the same input index**. **Verified at source (2026-06-13,
  [`FCMP_MEMBERSHIP_ONLY.md`](../completed/FCMP_MEMBERSHIP_ONLY.md) §7/§8.2/§9):** the in-circuit
  `H(pqc_pk)` extra-leaf-scalar binding (`with_extra_scalars`) is index-bound and **implemented**
  in `FcmpMembershipOnly`; the **vin-layer ML-DSA equality check** (recompute `H(pqc_pk)` from
  the supplied key, demand equality with the leaf-committed scalar) is a **hard merge blocker**
  named in `FCMP_MEMBERSHIP_ONLY.md` §7/§9 and `REWARD_EMISSION_LEG.md` §12 — **not yet landed**.
  **Obligation:** the emission vin verifier must implement and test this equality check before
  the `archival_p` impl is wired into emission construction; until it lands, no quantum
  spend-authority guarantee exists on the backing path (classical security only — the
  `MembershipSpendAuth` `R_O` leg still proves classical spend-secret knowledge per
  `FCMP_MEMBERSHIP_ONLY.md` §5.1; "membership-only" omits the key image, not the authority). This
  is a dependency Gate 6 leans on, not a Gate-6 deliverable — it discharges in the emission vin PR.
  **Discharge is test-enforced, not memory-enforced:** the §7 `pqc_pk`-mismatch forgery negative
  (a backing input whose supplied `pqc_pk` does not hash to the leaf-committed extra scalar must be
  **rejected**) **fails** until the vin equality check lands — so the dependency cannot silently
  fail to discharge.
  **DISCHARGED (PR #277, merged `dev` `13c368707`, verified 2026-07-11):** the vin-layer ML-DSA
  equality check landed in the emission verify module (`emission_verify.rs`; index §4 PR-E rows) —
  the backing path now carries the quantum spend-authority guarantee, not classical-only. The
  honest-path stressnet 100-cycle criterion + the blob-boundary arm remain the **regtest e2e
  residue** (E4/E5 gate, `FOLLOWUPS.md`), which is emission-track scope, not a Gate-6 deliverable.

---

## 10. Round 2 — network + transport layer (CLOSED 2026-07-11)

**Status:** **Closed 2026-07-11** (opened 2026-06-13; four adversarial passes §10.11; closure
disposition §10.13). Round 2 specifies how peers reach `P` and how `P` broadcasts, such that `P`'s
network *location* and *traffic shape* never link to the principal. It threads the R1-named entry
gates (GF-3/5/6/9/12, §6) into one transport spec rather than re-deriving surface. Closed against
the round's defense-in-depth bar (§10.0), **not** "linkage impossible": every named leak vector has
a specified, testable mitigation and a written residual; implementation/tuning items are carried
with rule-21 criteria (§10.13). The §10.10 exit checklist below is ticked to its closure basis.

### 10.0 How Round 2 differs from Round 1 (the bar is different)

Round 1 closed on **algebraic separation** — distinct `combined_ss`/decap make principal/`P`
outputs uncrossable *by construction* (§9.6). The network layer has **no such clean
separation**. The firewall here is **defense-in-depth**: a named fingerprint, a bounded +
*measurable* mitigation, and an **honest residual**. The Round-2 exit bar is therefore *"every
leak vector is named, the mitigation is specified and testable, and the residual is written
down,"* **not** *"linkage is impossible."* Treating a probabilistic traffic-analysis surface as
if it were a proof is the failure mode this round guards against — and it is why the network
round, not the crypto round, is the harder one.

### 10.1 Threat model (the live observer)

| Adversary | Capability | Must not learn |
|-----------|------------|----------------|
| Local / ISP | principal clearnet link timing + volume | that a clearnet link serves/answers for `P` |
| Malicious peer | initiates challenges, fetches, handshakes vs `P` | `P`'s clearnet IP; any principal-correlated metadata |
| HS-side observer (rendezvous) | sees `P`'s onion traffic shape + timing | which clearnet node is `P`; correlation to principal txs |
| Partial passive (GPA-lite) | correlates entry/exit timing on a relay fraction | principal↔`P` circuit co-residency |

**Property:** over `P`'s whole life, no network observer links `P`'s serving / challenge /
broadcast traffic to (a) the principal's clearnet identity or (b) the principal's wallet
traffic. Anonymity-network source privacy is **experimental with known residuals**
([`ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md) §*Privacy Limitations*); Round 2 **inherits
those residuals** and adds the `P`-specific ones — it does not re-solve Tor.

### 10.2 Two traffic classes (inherited frame)

| Class | Traffic | Transport (proposed) | Latency posture |
|-------|---------|----------------------|-----------------|
| Light / privacy-critical | bond announce, emission/drain broadcast, liveness re-proofs, challenge responses | anonymity-routed Levin (Tor) | latency-tolerant; battle-tested fit |
| Heavy / archival serving | deep-shard fetch responses | **onion-service ↔ Tor-client rendezvous; no clearnet fallback** | worst-case L-regime **by construction** (L16) |

The heavy path's worst-case latency is **not** a Round-2 open question — it is pinned by §2.2
and the L10/L16 sim findings ([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md)). Round 2's
transport work is the **light-class routing**, the **serving-path reachability + key
lifecycle**, and the single heavy-path lever in §10.8.

### 10.3 GF-12 — Arti onion-service hosting (entry gate: capability confirmed; at-source pin carried)

Per [`17-dependency-discipline.mdc`](../../.cursor/rules/17-dependency-discipline.mdc), the
"embed Arti in-process" fork ([`ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md) §*Forks* #1)
cannot be pinned on training-data recall. **Published-capability check (web, 2026-06 — not yet
the at-source pin):**

- Arti supports **service-side onion-service hosting** (full vanguards, restricted discovery,
  client auth) — **done / stable since Arti 1.2.0 (2024-03)**; the older "client-only" notes are
  stale.
- Gated by the **`onion-service-service`** feature on `arti-client` (current `0.43.0`,
  2026-06-01; MSRV 1.89). API: `TorClient::launch_onion_service` /
  `launch_onion_service_with_hsid`. **Vanguards** require `onion-service-client | -service`;
  **restricted-discovery** is available (client-auth-gated HS resolution — load-bearing for
  §10.4 / §10.7). Relay / dir-auth side is *not* done — irrelevant, `P` hosts a service, it is
  not a relay.

**Disposition (proposed):** the capability question that made GF-12 an entry gate is
**answered — service-side hosting is stable and feature-flagged.** What remains is the
**at-source pin** deferred to the transport PR per the dependency-discipline relaxation clause:
exact workspace version, `onion-service-service` (+ `vanguards`, + `restricted-discovery`)
feature plumbing, MSRV vs. workspace, and the **`launch_onion_service_with_hsid` key-injection
API shape** (load-bearing for §10.7). **Embed-vs-external (Fork #1) is therefore decidable in
Round 2** — embed Arti, Rust-canonical per
[`20-rust-vs-cpp-policy.mdc`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc) — **conditional on**
that at-source pin, with the external-daemon-over-SOCKS fallback held as the reversion clause
([`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc))
if the at-source check fails.

### 10.4 GF-3 — the challenge-response message class must be anonymity-routable

Inherited Shekyl routes only **handshakes, timed syncs, and tx broadcast** over the anonymity
network ([`ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md) §*P2P Commands*). The archival
**challenge-response** (a peer challenges `P` to prove retention/liveness; `P` answers) and the
**liveness re-proof** are a **new Levin message class** that does **not** exist in that
allowlist. If it falls back to the clearnet P2P path, the exchange **links `P`'s clearnet IP** —
on the exact traffic the firewall exists for.

**Disposition (proposed):**

- The challenge-response + liveness-re-proof commands are **added to the anonymity-routable
  command set** as a first-class member; `P` **refuses to answer a challenge that did not arrive
  over the anonymity transport** — loud refusal, *not* clearnet fallback (the user-absent-context
  default inversion per [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)).
- Challenges arrive **inbound over `P`'s onion service** (Arti restricted-discovery can gate
  *who* may resolve `P`'s HS, §10.3); responses return over the **same rendezvous circuit**.
- **Pin the Levin command IDs** for the new class so the allowlist is enumerable, not "whatever
  the archival module happens to send."

**Disposition (pass — bonded-verifier-only).** Challenges originate from a **bonded verifier
set, not an open market.** The exposure axis is the **{`.onion` ↔ `P_canonical_id` ↔ shard}
map**: an open market lets *anyone who challenges* build it; bonded-verifier-only **+ Arti
restricted-discovery** (§10.3 gates who may resolve `P`'s HS) bounds map exposure to the
verifier set and enforces it cryptographically. Two conditions ride with it: **(a)** the verifier
set is then a concentrated deanonymization chokepoint (compromise the set → the whole map) → it
must itself **rotate and be firewall-aware**, not a static registry; **(b)** the choice must
match the **L14b failure-confirmation** challenger-population assumption
([`ARCHIVAL_FAILURE_CONFIRMATION_PIN.md`](../completed/ARCHIVAL_FAILURE_CONFIRMATION_PIN.md); sliding-window
`m`-of-`n`, `11/13` provisional). **Sharpened (verified at source):** the L14 oversight *volume*
homeostasis (read-credit confines oversight to the cold tail; **challenge ≡ retrieval**, keyed
on read-credit + retrieval SLA — [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §*L14×L15*)
is **challenger-population-independent**, so the traffic result transfers regardless. What must
be re-checked against L14b is **challenger availability/liveness** — does a *bonded* set sustain
the `m`-of-`n` recheck cadence on the cold tail it must cover — plus condition (a)'s chokepoint.
Same sim-consistency family as R-3, not the volume axis.

**Spec-level model (proposed, 2026-06-16).** The bonded-verifier disposition is recorded as a
concrete model so the structural shape is settled pre-seal; the *quantitative* piece (the
availability margin) is routed to the Round-2 stressnet gate, where gate-2/gate-4 ratify it.

- **Membership = the bonded archival staker set itself (mutual oversight).** The verifier
  population *is* the set of bonded `P`s, each a potential challenger of the others — not a
  separate privileged registry. This is the minimal-surface choice: it ties challenge authority
  to on-chain bonded skin-in-the-game (a misbehaving verifier has collateral at risk under the
  same FSM), avoids inventing a second trust tier with its own Sybil/capture surface, and makes
  the verifier set's size and liveness a function of the staker set the sim already models.
  No new membership credential exists — bond-record membership *is* the credential.
- **Rotation = consensus-seeded, per-epoch, firewall-aware.** The per-epoch verifier→target
  assignment is derived deterministically from a **consensus beacon** (the epoch seed), so it is
  auditable after the fact but **unpredictable in advance** (a verifier cannot pre-position
  against a known future target), and it **rotates every epoch** so no verifier accumulates a
  standing view of any target's `{.onion ↔ P_canonical_id ↔ shard}` map — directly discharging
  condition (a)'s "must rotate, not a static registry." **Firewall-aware** means the assignment
  function **excludes** any verifier↔target pair that would itself leak the map (e.g. a verifier
  whose principal correlation with the target is known, or an assignment that violates the §10.9
  `P`↔principal isolation): the rotation is constrained by the firewall, not blind to it. The
  beacon-seeded draw reuses the determinism discipline of the standoff draw (consensus-seeded,
  reproducible, no wallet-side discretion).
- **`m`-of-`n` availability = routed to the Round-2 CDF gate.** Whether a *bonded* set sustains
  the L14b sliding-window recheck cadence (`m`-of-`n`, `11/13` provisional —
  [`ARCHIVAL_FAILURE_CONFIRMATION_PIN.md`](../completed/ARCHIVAL_FAILURE_CONFIRMATION_PIN.md)) on the cold
  tail it must cover is a **quantitative availability question**, not a structural one. It is
  **not answered here** — it is handed to the Round-2 stressnet **availability CDF gate**, which
  measures the bonded verifier population's liveness against the recheck cadence under modeled
  churn and sets `m`/`n` from the measured CDF rather than the provisional `11/13`. The seal
  rests on the structural model above; the gate ratifies the parameter.

This is a **disposition, not a ratification**: it records membership/rotation/firewall-awareness
as the committed structural model (reopen only on a Round-2 finding that the bonded set cannot
sustain the cadence, or that the firewall-aware rotation cannot be made deterministic without
leaking the assignment), and defers the `m`/`n` value to the gate that can measure it.

### 10.5 GF-5 — pre-join backing presentation is `P`'s first network appearance

Before `P` anchors its bond on-chain (join-Market), it **presents backing** (announce-before-
anchor: the membership-only backing proofs + the announce). This is **`P`'s first time on the
network.** If the announce traverses clearnet, or a circuit/stream shared with the principal's
wallet traffic (stream-reuse leak, [`ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md) §*Stream
Used Twice*), it links principal↔`P` **at birth** — before any later-layer mitigation can
matter.

**Disposition (proposed):**

- The pre-join announce/backing presentation **traverses the anonymity transport on a fresh
  circuit**, with **no principal-correlated stream reuse** and no principal metadata in the
  payload.
- The §7 checklist item "pin off-chain announce/backing presentation wire" is the *wire* half;
  **GF-5 adds the *transport* half** — wire and transport are pinned together, not separately.
- **Announce-before-anchor** ordering stands, but the announce↔anchor **timing gap** is a
  standing correlation channel if deterministic → **handed to Round 3** (timing/rotation).

**Disposition (pass — broadcast; it diverges from §10.4 by event sensitivity).** The announce is
a **P2P broadcast over the tx-broadcast anonymity path (dilute), not a directed presentation to
a coordinator.** The two forks pull opposite *for a reason*: a **challenge is routine and
repeated** → bound the audience (§10.4 narrows to bonded verifiers); the **announce is
once-per-`P` and maximally linkage-sensitive** — first network appearance, backing presentation,
and temporal proximity to funding, all at once. A directed presentation concentrates the **richest
linkage moment in `P`'s life at a single observer** (the worst-placed observer for GF-5/GF-7);
broadcast dilutes it among all peers. Treating both as a uniform "narrow vs wide" is the trap.
**Sequencing hazard (decides it):** §10.5 hands announce↔funding **timing** to R3; picking
*directed* in R2 **pre-commits a constraint R3 must then satisfy** (the directed observer sees
the timing whether or not R3 decorrelates it), whereas **broadcast is robust to the timing
question** and mortgages nothing to R3. Broadcast wins on both linkage-dilution and
round-sequencing grounds.

### 10.6 GF-6 — `P`-tx wire-size fingerprint + dummy/fragmentation policy

PQC inflates tx size: a 2-in/2-out FCMP++ tx grows ~2–3 KB → ~7–8 KB — **~14–16 Tor cells** vs
~4–6 pre-PQC, ~7–8 I2P fragments ([`ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md) §*Measured
v3 Impact*). **`P`-typed txs (emission, bond-post, terminal drain) carry additional
consensus-special material** (`P_pubkey` vin identity; membership-only backing proofs; the
carried ML-DSA equality material per §9.8 C-1) — a **distinctive broadcast burst shape** on top
of the v3 baseline.

**Distinction that must not blur:** on-chain `P`-typing is **public by function** — emission
txs are consensus-special and anyone parsing the chain sees they are emission txs (by design,
gate-1/emission-leg). **GF-6 is not about on-chain identifiability.** It is about the
**broadcast-origin fingerprint**: an observer watching the anonymity transport must not be able
to say "*that* large archival-shaped burst on *this* circuit is `P`," and pivot to the
principal.

**Disposition (proposed):**

- **Characterize** the `P`-tx-type burst distribution at **cell (Tor) / fragment (I2P)
  granularity** for each `P`-tx type, against the ambient v3 mix — i.e. *is a `P` emission burst
  separable from an ordinary large v3 transfer?*
- **Decide the policy shape:** fragmentation + dummy padding tuned to a **measured
  real-to-dummy ratio** that makes `P` bursts statistically indistinguishable from the ambient
  large-v3 class ([`ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md) §*Recommended Testing* #2).
  This is **measure-then-tune** — Round 2 names the measurement obligation; the tuned constant
  lands with the testnet replay (carried).
- **Honest residual:** dummy traffic cannot conceal a large burst unless dummy volume scales
  with it (same §); the cost/coverage trade is the residual — written down, not papered over.

**Disposition (pass — the axis was mislabeled; the real pin is §10.9 circuit/guard isolation).**
Own-node-vs-generic-broadcast is leverage on **origin**, and the **GF-6 burst *shape* is
orthogonal to it** — Dandelion-style dilution changes *who/where* originated, not *what* a
7–8 KB PQC burst looks like, so it does not shrink the §10.6 fingerprint. And origin-dilution
only matters for principal-linkage **if `P`'s broadcast circuit could correlate to the
principal's in the first place**: with **independent Tor clients / guards** for `P` vs principal,
origin is already unlinkable and the own-node/Dandelion choice is second-order; with a **shared
guard**, a guard-level observer correlates them *regardless* of own-node or Dandelion. So the
load-bearing pin is **per-`P` outbound-broadcast circuit/guard isolation from the principal
(§10.9)** — pinned first; own-node-vs-Dandelion is then a secondary dilution refinement carried
to the transport PR, **not** the structural fork.

### 10.7 GF-9 — Tor HS key lifecycle (couples to §2.3 rotation)

`P` hosts a `.onion` to serve archival bytes + accept challenges. Its identity key
(`ks_hs_id.ed25519_expanded_private` in Arti's keystore, §10.3) **is** `P`'s reachability
identity. Two failure modes:

1. **Stable across `P` rotation → the `.onion` is a cross-`P_old`→`P_new` linker** that defeats
   the §2.3 rotation decorrelation (E-4 threat): rotating `P`'s keys while keeping the same
   `.onion` is **cosmetic rotation**.
2. **Rotating mid-life → breaks reachability:** peers hold `P`'s `.onion` as the bond-record
   reachability field; it must be **stable within a single `P`'s life.**

**Disposition (proposed):**

- The HS identity key is **bound to `p_slot`** (§9.2): **stable within a `P`'s life, rotates
  with `P`.** On rotation, `P` stands up a **new HS under a new key**, migrates the reachability
  field, and retires `P_old`'s `.onion` on the same schedule as `P_old`'s keys.
- **Derive the HS ed25519 identity from `master_seed`+`p_slot`** (a §9.3-style HKDF label, e.g.
  `b"shekyl.archival.p.hs_id.v1"`), injected via `launch_onion_service_with_hsid` (§10.3)
  rather than Arti-autogenerated. **Why:** the `.onion` becomes **deterministic +
  seed-recoverable** (survives device loss; fits wallet recovery) and **provably `p_slot`-scoped**
  (rotation is structural, not operational discipline). This **adds an HKDF label to §9.3 → it
  must be in the `ARCHIVAL_P_DERIVE_V1` KAT.**
- **Honest residual:** the live HS private key is a **long-term secret resident on the serving
  device**; its compromise links `P`'s *location* (not the principal, but `P`'s box). This is
  the **irreducible serving-side residual** — named, not mitigated away.

**Disposition (pass — the crypto over-coupling is foreclosed; the real risk is restore-flow
co-activation).** Seed-derivation creates **no public linkage**: HKDF label-separation makes the
public `.onion` Ed25519 key **one-way from the master seed**, so it cannot be tied to the
principal without the seed, and "the same `.onion` reappears on restore" is just the **accepted
`.onion` ↔ `P_canonical_id` baseline** — no new leak, and `p_slot` rotation is *not* what closes
it (it was already closed cryptographically). The real over-coupling is **restore-flow
co-activation**: one restore re-derives and re-launches **both** principal and `P` from one
device/session, **co-timing their network reappearance** — an observer at the restore moment
sees principal-sync and `P`-`.onion`-reanimation co-occur from one origin. **`p_slot` rotation
does not foreclose this** (it changes the address, not the co-activation). **Fix = restore-flow
discipline (§10.9):** `StakeEngine` must **not** auto-launch `P`'s HS in lockstep with
`LedgerEngine`'s principal sync — independent scheduling, isolated circuits. This is the **same
isolation pin fork 1 needs**, surfacing from the restore angle — the convergence is the tell
that it is the real §10 gap.

### 10.8 The one heavy-path lever that feeds the sim

[`ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md) §*The one question that feeds the sim*:
**does the heavy serving path stay pure-rendezvous (worst-case L-regime, maximal firewall), or
is there a relaxation that buys bandwidth without linking `P`?** This is the **only** transport
parameter that moves the staker-archival sim's L-curve position. Round 2 **names and bounds**
it; it does **not** relax the firewall to chase bandwidth (priority hierarchy per
[`00-mission.mdc`](../../.cursor/rules/00-mission.mdc): privacy > performance). Any proposed
relaxation (e.g. a seeding-path leg over a lighter transport for **public, non-`P`-attributable**
bytes) must **prove it carries no `P`-attributable metadata** before it is admissible — the
seeding-path relaxation already flagged in §2.2 and [`FOLLOWUPS.md`](../FOLLOWUPS.md).

**Pass lean:** **pure-rendezvous *is* the genesis commitment**; any relaxation is a
**post-testnet reversion clause, not a genesis option.** And "public, non-`P`-attributable bytes"
is an **insufficient** bar on its own — the **seeding request pattern** can be `P`-attributable
even when the bytes are not, so the burden is "prove the *access pattern*, not just the payload,
carries no `P`-attributable metadata" (§10.11 #5).

### 10.9 `P` ↔ principal client/circuit isolation (forks 1 + 4 convergence — §10 exit pin)

Forks 1 (§10.6) and 4 (§10.7) converge on the **single most load-bearing thing §10 had not
pinned**: §10.7 pins `P`'s *inbound* HS identity-key lifecycle, but §10 said nothing about
**isolation between `P`'s network activity and the principal's** — *outbound* broadcast, and
*restore-time* launch. That isolation dominates both forks; it is pinned here as a Round-2 exit
item, not left as an open question.

- **Independent Tor clients / guard sets.** `P`'s serving HS, `P`'s outbound broadcast, and the
  principal wallet's traffic use **separate Arti client instances with non-overlapping guard
  sets**. A shared guard lets a guard-level observer correlate `P` and principal **regardless**
  of own-node-vs-Dandelion (fork 1) — so isolation is the structural pin and origin-dilution
  (Dandelion / own-node) is a refinement on top of it, not a substitute.
- **No principal-correlated stream reuse** on any `P` circuit — extends the §10.5 fresh-circuit
  rule from the announce to *all* `P` traffic
  ([`ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md) §*Stream Used Twice*).
- **Restore-flow discipline (fork 4's real attack).** On wallet restore, `StakeEngine` **must not
  auto-launch `P`'s HS in lockstep with `LedgerEngine`'s principal sync.** Co-activation co-times
  principal-sync and `P`-`.onion`-reanimation from one origin — a correlation `p_slot` rotation
  does **not** foreclose (it changes the address, not the co-timing). Independent scheduling +
  isolated circuits foreclose it; this is a **wallet-orchestration requirement on the PHASE_2B
  engines**, not a crypto pin.
- **Honest residual:** isolation is **operational** — it holds only as far as the two client
  instances are genuinely independent (separate guards, no shared exit, no co-timed activation).
  A host-level observer that compromises the *device* sees both regardless; that is the §10.7
  serving-side residual, not re-solved here.

**Why an exit item, not an open question:** the two forks that looked like independent transport
choices both reduce to this pin; leaving it unpinned would let the Round-2 transport spec land
with the principal-linkage gap still open under a different name.

### 10.10 Round 2 exit criteria + carried items

**Exit (all met at close 2026-07-11; a `[x]` means the *design disposition* is discharged — see
§10.13 for the closure basis and the implementation carries that ride each one):**

- [x] **GF-3** — challenge/response + liveness-re-proof Levin class **added to the
      anonymity-routable set**, command IDs pinned, clearnet fallback **refused (loud)** (§10.4,
      bonded-verifier disposition).
- [x] **GF-5** — pre-join announce/backing-presentation **transport** pinned (**broadcast** over the
      tx-broadcast anonymity path, fresh circuit, no principal stream reuse; §10.5); announce↔anchor
      timing gap **handed to R3**.
- [x] **GF-6** — `P`-tx burst **characterization obligation** pinned (cell/fragment granularity,
      per `P`-tx type) + dummy/fragmentation **policy shape** decided (§10.6); tuned ratio **carried
      to testnet replay** (§10.13). Structural pin is §10.9 circuit/guard isolation (burst shape is
      orthogonal to origin-dilution).
- [~] **GF-9** — HS identity key **`p_slot`-bound + seed-derived** disposition **pinned** (§10.7),
      serving-side key-compromise residual **named**. **The "new HKDF label added to §9.3 +
      `ARCHIVAL_P_DERIVE_V1` KAT" is a carry, not done** — verified at source, the label is absent
      from [`archival_p.rs`](../../rust/shekyl-crypto-pq/src/archival_p.rs) (seven §9.3 labels, no
      `hs_id`). Carried armed at §10.13 with the **dot-vs-hyphen format flag** (§10.7's proposed
      `shekyl.archival.p.hs_id.v1` violates §9.3's hyphen convention and its non-prefix-free
      safety argument — normalize before freezing). Disposition closes R2; the label-freeze is a
      §9.3 amendment.
- [x] **GF-12** — embed-Arti fork **decided conditional on the at-source pin**
      (version/feature/MSRV/`with_hsid` API; §10.3); external-daemon reversion clause recorded.
- [x] **Forks 1+4 / §10.9** — `P`↔principal **client/circuit isolation** pinned (independent
      Arti clients + non-overlapping guard sets; no principal stream reuse; **restore-flow
      co-activation discipline** — `StakeEngine` does not co-launch `P`'s HS with principal sync).
      Operational residual named. **Enforcement mechanism (Arti config vs. policy) carried** to the
      transport PR (§10.13). Extended to **key locality** by S-6 (§10.12).
- [x] **Rebond/unbond recurring-surface** — §6 R4 re-scope acknowledged: GF-4 (drain output-count)
      and GF-7 (bond-funding separation) carried as **recurring** (partial-unbond / rebond-topup),
      not one-time; the **rebond/unbond FSM (promoted to genesis / V3.0, 2026-06-15)** named as the
      **pre-genesis-seal dependency** for the R-3 sim bond-mobility reconciliation.

**Legend:** `[x]` disposition discharged; `[~]` disposition discharged but an implementation/freeze
carry rides it (GF-9 label). No box is `[ ]` at close.

**Carried out of Round 2 (named, not silently deferred — per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)):**

- **At-source Arti pin** → transport PR (§10.3).
- **Dummy/fragmentation tuned ratio** → testnet replay (§10.6).
- **Announce↔anchor + emission-cadence timing** → Round 3.
- **Heavy-path relaxation decision** → bounded in §10.8; lands with the sim's post-testnet
  L-curve measurement.

### 10.11 Pass dispositions + remaining open questions

**Resolved this pass (dispositions in §§10.4–10.9):**

1. **§10.4** — challenge market → **bonded-verifier-only** + restricted-discovery (rotating,
   firewall-aware set; L14b challenger-*liveness* check carried, not the volume axis).
2. **§10.5** — announce → **P2P broadcast** (dilute the once-per-`P` linkage moment; robust to
   the R3 timing question, where *directed* would mortgage a constraint to R3).
3. **§10.6** — own-node-vs-Dandelion is **secondary**; the structural pin is **§10.9
   circuit/guard isolation** (the GF-6 burst *shape* is orthogonal to origin-dilution).
4. **§10.7** — seed-derived `.onion` **does not over-couple cryptographically** (HKDF
   one-wayness); the real risk is **restore-flow co-activation**, fixed by **§10.9** restore
   discipline.

**Leans (pass to confirm; reversion-clause shaped):**

5. **§10.8** — **pure-rendezvous is the genesis commitment** (privacy > bandwidth); any
   heavy-path relaxation is a **post-testnet reversion clause, not a genesis option**, and the
   bar is the *access pattern* not just the payload (§10.8 pass lean).
6. **Cross-cutting — I2P secondary door: lean closed-at-genesis** (reopen post-audit). The cost
   of keeping it open is **not the door** — it **doubles the GF-6 characterization surface**
   (every `P`-tx burst shape characterized on **I2P fragments *and* Tor cells**, §10.6). The one
   cheap way to keep it open: pin the new message classes (§10.4 challenge, §10.5 announce)
   **transport-agnostic now** so reopening is config, not redesign.

**Still genuinely open (carried):**

- **§10.4 condition (b)** — L14b challenger availability/liveness under a *bonded* set
  (sim-consistency, R-3 family). **Routed (2026-06-16):** the §10.4 spec-level model commits
  the structural shape (membership = bonded staker set, consensus-seeded firewall-aware per-epoch
  rotation) and hands the `m`-of-`n` availability margin to the **Round-2 stressnet availability
  CDF gate** (gate-2/gate-4 ratify the value; provisional `11/13` until measured). Condition (a)'s
  chokepoint is discharged structurally by the per-epoch rotation.
- **§10.6** — dummy/fragmentation tuned ratio (measure-then-tune → testnet replay).
- **§10.9** — guard-isolation enforcement mechanism (Arti config vs. policy) → transport PR.
- **GF-1-carve — RESOLVED (2026-06-16).** Bond-debit authorization is a **dedicated
  `bond_spend_pk`** committed at `JoinMarket`, domain-separated from the identity key (§9.3 labels;
  gate-4 §3.5 step 5 / §4.1 / §3.4.1). The account `P_pubkey` never authorizes a value-out;
  identity-only invariant preserved. Custody model (§3.2) not reopened; the receipt-UTXO
  alternative was declined and given a reopen criterion (§9.6).
- **Rebond/unbond FSM** — `HoldingsUpdate` promoted V3.1→genesis (V3.0, decided 2026-06-15); the
  add-shard credit path covers top-up (gate-4 §4.4 / FSM retool); **blocks the R-3 sim
  reconciliation and thus the genesis seal** (§6 scope note); the reconciliation must be
  **age-stratified, not a re-tuned flat cost**.

**Critical path out of Round 2 (these two, not the transport tuning):** (1) the GF-1-carve
resolves at gate-4 source — **done 2026-06-16** (dedicated `bond_spend_pk`; gate-4 §3.5 step 5 /
§4.1 / §3.4.1), so the bond-post verifier can now be built against a named debit key; and
(2) the rebond/unbond FSM promotion gates the R-3 age-stratified sim reconciliation, which gates
the genesis seal. The transport-tuning carries (§10.4(b), §10.6, §10.9) correctly defer to testnet
replay.

### 10.12 Pass 3 — end-to-end trace: cross-layer / model-level findings

The per-round decomposition (R1 crypto, R2 network, R3 timing, R4 value) hardens each layer in
isolation and is **blind to cross-layer fusion by construction**. An end-to-end trace of `P`'s
lifecycle (key-gen → announce → bond-post → serving → emission → bond-adjustment → terminal exit)
surfaced findings that **no single layer owns**. These are model-level and **pre-genesis-seal**,
distinct from the per-round transport dispositions above; several are bigger than this gate and are
cross-referenced to their home docs.

- **S-1 — the money seams are orphaned by the round structure.** GF-7 (funding-in) and GF-4
  (value-out) are the *only* findings that protect the property the firewall exists for —
  principal↔`P` unlinkability — and the only two still deferred (R3/R4). They sit at the
  **conjunction** on-chain-value ∧ network-broadcast ∧ timing, which no single layer owns, so the
  decomposition routes around them. **Deferral is not ownership.** Disposition: make the seam a
  first-class artifact (S-2), not a per-round residual. The layers that got the most rigor (crypto
  separation, network isolation, challenge market) protect properties that are **conceded public
  anyway** (the pseudonym's coherence and reachability); the load-bearing seam is the
  least-developed *because* it is cross-layer.
- **S-2 — fused, per-observer, whole-life exposure ledger (build first — cheapest, highest
  leverage).** §10.1 is per-adversary "must *not* learn"; there is no artifact for what each
  observer **does** learn when it fuses join-tx + serving + emissions + bond-adjustments + drain
  over `T_obs`. Shape: a matrix (observer type × lifecycle event) plus a **per-observer fusion
  closure** (transitive linkage across the row). It must mark **conceded** cells
  (onion↔`P_canonical_id` for the verifier-set observer; public claim history) **distinctly from
  leaked** cells, or it reads as alarming when most of it is intended-public; its value is isolating
  the **non-conceded principal↔`P` fusion** (= S-1's GF-7/GF-4). Qualitative, cheap, and it tells
  you whether the layers compose or whether fusion defeats them. Home: this doc + reconciled with
  [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md).
- **S-3 — privacy must be *measured*, not only *named*.** The economic side has 325 scenarios and
  "measure it"; the privacy side has 0 and "name the residual" (§10.0). For a *privacy > everything*
  chain that ordering is backwards. The named properties — sybil-map build-rate, funding-seam
  timing-correlation, bridge propagation under partial observation — are exactly the probabilistic
  class that simulates against a **modeled observer** the same way agent behavior does. This is the
  **privacy axis of the R-3 reconciliation already obligated pre-seal** (§6 scope note), not new
  scope. Deliverable: a minimal adversary sim on the funding/exit timing seams — `P(link | T_obs)`
  as a function of standoff window / entry jitter / batch size. Home:
  [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md). *(Progress 2026-07-05: the evidence
  pipeline for the GF-7 funding-seam instance exists — hook spec
  [`ARCHIVAL_BOND_2C_GF7_HOOKS.md`](ARCHIVAL_BOND_2C_GF7_HOOKS.md) landed with the 2c-2b
  scheduler wiring, PR #255: injected observer seam in the production scheduler + the
  `--gf7-timeline` joint three-axis scenario with a funding-seam-blind grading arm. The graded
  measurement round itself is still open — it is the genesis gate tracked in
  `docs/FOLLOWUPS.md`.)*
- **S-4 — the bridge (onion↔`P_canonical_id`) is an inherited staking-model cost, conceded by
  design.** Serve-credit must attribute to `P_canonical_id`, and the obvious attribution signs the
  response with the consensus key; the only escape (a challenger verifies a *valid* response without
  learning *which* `P`, `P` self-reports credit) is the **confidential-staking machinery that was
  rejected**. So the entire serving-layer exposure is downstream of that earlier decision and
  **cannot be closed at the network layer** — it must be labeled traceable-to-that-decision so no
  further R3/R4 cycles are spent trying to fix it where it cannot be fixed. Home: the staking-model
  decision record (confidential-staking rejection).
- **S-5 — RESOLVED 2026-06-16 (long-lived `P` is the committed architecture).** *Was:*
  longevity-vs-privacy is a model-level question to answer before the seal (not an R3/R4
  mitigation). The economics reward a **long-lived `P`** (serve-credit accrual to a stable id,
  lock tiers, `bond_duration`) — the worst possible structure for the bridge: a permanent handle
  with a monotonically growing fusion surface. We inherited long-lived `P` from the staking model
  without asking. **One branch reopens the FSM just pinned:** a
  short-lived `P` *relocates* the seam (value-out fusion → repeated value-in funding, a fresh GF-7
  per rotation) and collides with bond-as-consensus-balance — rotating `P` means *migrating bond
  between identities*, a new consensus operation, not a wallet choice (reopens §6 / R-1). The answer
  space also includes "long-lived but with uniform per-epoch behavior and a large set."

  **Disposition (consciously closed, per `21-reversion-clause-discipline.mdc`).** The
  long-lived-vs-short-lived *architectural* fork is **closed in favor of long-lived `P`**. This
  ratifies what every downstream commitment already assumes — serve-credit accrual to a stable id,
  lock tiers, `bond_duration` (gate-4 §4.4), the L18 freeze-friction seal
  ([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md)), and bond-as-consensus-balance (gate-4 §3.2)
  — so it is now a **decided** architecture, not an inherited-unexamined one. The decision-by-
  accumulation is hereby made explicit rather than left latent. **Short-lived / rotating `P` is
  out of scope for V3.0:** it would relocate the seam and require bond-migration-between-identities
  as a new consensus op (reopening the §6/R-1 FSM and the gate-4 §3.2 custody seal), and the unwind
  cost grows with every commitment built on the long-lived assumption. **What remains is not a
  re-fork but the privacy *characterization* of the long-lived handle's fusion surface**, which
  folds into **S-2** (fused exposure ledger) + **S-3** (funding/exit adversary sim) and the
  operator-behavior levers (uniform per-epoch activity, large serving set) routed to the S-2
  exposure ledger + opsec guide — documentation and ops, not a protocol change. **Reopen
  criterion:** reopen the architectural fork *only* if the S-2/S-3 characterization **measures**
  public per-`P` attribution exposure severe enough to reconsider the confidential-staking
  rejection (the §10 pass-4 framing) — a measured-breach finding, not a design preference.
  **Reopen shape:** a fresh model-level round in the staking model / `PHASE_2B` that owns the
  bond-migration consensus-op design short-lived `P` requires, before any V-next seal. Home:
  staking model / `PHASE_2B`.
- **S-6 — key locality: the always-on serving box must hold only the `P`-subtree, never the master
  seed.** Everything-from-one-seed, run-from-one-wallet puts the **most-exposed machine** (always-on
  `.onion` server) on the **most-sensitive root**. This is fixable **without surrendering
  recoverability**: derive the `P`-subtree (`P` spend/view, the `bond_spend_pk` keypair, the HS
  onion key) on a **cold device** and provision *only* the `P`-subtree secrets to the serving box.
  HKDF one-wayness means `P`-subtree compromise never reaches the master seed or principal keys;
  recoverability is preserved by re-deriving on the cold device. This **extends the §10.9 isolation
  pin from circuits to key locality** and should be *pinned*, not merely named (per
  `35-secure-memory.mdc` / `36-secret-locality.mdc`).

**Pass-4 organizing principle — conceded *function* vs. protected *linkage*.** The firewall's
charter is **P ↔ principal**, not **P ↔ its own rewards**. `P_canonical_id` is a *conceded-public
earner*: public bond, shard assignments, and emission history are allowed to be visible. Mitigations
that obscure the **earning function** — reward-magnitude *banding* (quantizing/grouping earnings to
blur per-`P` magnitude; *distinct from* the sealed `g` operating-band in
[`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md)), and pay-every-block — spend the anti-whale /
trilemma budget *twice* to protect a property the firewall does not protect, by piling a second
distortion onto the contribution→reward map. The seam mitigations (**standoff + inversion**) operate
on **transaction scheduling**, touch **no economic quantity**, and hide a **linkage** rather than a
function of contribution — so they are not *cheaper* in the trilemma, they are **off its axis
entirely**. Two refinements: (i) the one residual that *looks* like steady-state magnitude is
**cross-`P` sybil correlation** (one principal, several `P`s), but its signature is funding/exit
*timing and pattern*, not magnitude — so it resolves to **seam protection too**, making banding
*doubly* misdirected (useless single-`P`, weak multi-`P`); (ii) at the seam, amount-correlation is
already blunted by **FCMP++ CT** on the principal side (the funding inputs and drain outputs are
commitment-hidden), so the public seam leak is **timing + origin** — exactly and only what
standoff + inversion targets. **Principle: obscuring the conceded earning-function is trilemma-costly
and misdirected; hiding the principal-linkage is trilemma-free and load-bearing.**

**Pass-4 dispositions on the pass-3 scenarios:**

- **BUILD — funding-seam entry standoff + inversion (S-3 sim, the door).** Decoupling
  principal-funding / bond-post / `P`-network-instantiation by a randomized window, **and letting
  `P` appear before its bond is staked**, attacks GF-7 — the load-bearing seam. The inversion is the
  prize: it doesn't just enlarge the candidate set, it **removes the ordering prior** the adversary
  relies on ("the bond-post follows a recent principal spend"; "find the funding spend just before
  the bond"). Feasible because the announce is membership-only backing over *principal outputs* that
  exist pre-bond — `P` proves it *could* back before it *does* — with the bonded-verifier gate
  bounding the unbonded-announcer DoS/sybil angle. **Sim question, sharpened past "smooth vs surge":**
  (a) **candidate-set sizing, not window width** — the metric is *candidate principal-spends-per-window
  for the targeted principal*; a window wide in wall-clock but containing one suspect spend gives zero
  cover. (b) **the worst case is a low-activity principal** (funds one bond, rarely spends): set-enlargement
  cannot help them, so the inversion is the *only* lever that does — sweep it explicitly. (c)
  **clustering = trigger independence** (uniform-independent draws smooth; jitter off a shared epoch
  boundary clusters) — the knob to sweep. (d) **enumerate the separable events first** (prep-spend vs.
  announce vs. the bond-post tx carrying collateral-in) — a standoff only buys cover for events an
  observer sees as distinct (ties to the S-2 ledger). Sim the inversion as its own arm.
  **BUILT + RUN (2026-06-13)** — `shekyl-staking-sim --standoff`
  (`STAKER_ARCHIVAL_SIM.md` §*Funding-seam entry standoff*). Findings: anonymity is **rate-driven,
  not width-driven** (the background funding-spend rate is the load-bearing, *unmeasured* input —
  swept like `fetch_latency`); the **inversion carries the low-activity worst case** (link
  `0.52→0.32`, thin-cover `56%→20%` where width alone can't help); a **shared trigger is
  catastrophic** (set `16→1.01` — uniform-independent draws mandatory); and the standoff is
  **homeostasis-free ≤ ~1000 blocks** (economic dynamics are epoch-quantized at 10_000 blocks, so a
  minutes-to-hours window is off the economic axis — the pass-4 principle, confirmed). **Recommended:
  600-block (~20 h) uniform-independent window, inversion on.** Four conditionalities bound the
  number (`STAKER_ARCHIVAL_SIM.md` §*Funding-seam entry standoff* → *Conditionality and caveats*); the
  first two change what it *means*: (i) **the cap is anti-griefing, not privacy** — a max
  announce↔bond separation is a liveness *ceiling*; the privacy floor (minimum spread + the
  uniform-independent draw) is **wallet-only and consensus-unenforceable** (consensus sees neither the
  FCMP++-hidden funding nor off-chain principal activity), so the draw is a **hard conformance
  requirement with a published test vector**, not a default — with an open consensus question of a
  per-block bond-post smoothing rate-limit as a *partial* (chain-side only) and *non-free*
  (liveness-griefing) backstop; (ii) **cover is conditional on §10.9 isolation, multiplicatively** —
  the numbers are `P(link | isolation holds)`, the standoff is a multiplier on isolation, never
  additive, and the rate that actually drives cover is the **network-event rate post-isolation, not
  the on-chain funding-spend rate** the sim proxied; (iii) **cold-start is the structural worst case**
  — thinnest genesis traffic + longest-lived foundational `P`s coincide, foundation-injected decoys
  are self-undercutting (attributable → discounted per (iv)), so weak early cover is a **named pre-seal
  residual** (L12); (iv) the measured set is **nominal honest-traffic cover, an upper bound** —
  effective cover against an observe-and-inject adversary (the S-3 modeled observer, the testnet
  target) is lower and unquantified. **Construction + geometry (conformance-critical):** the gap
  must be **drawn directly** (`s ~ U[0,600]`, fair order-coin: place event 1 at the private intent
  `t0`, event 2 at `t0+s`) — *not* by independently jittering two event-times around a common anchor,
  whose *difference* is triangular/zero-peaked and clusters the events (a conformance trap the test
  vector must reject, since the draw is unenforceable). The **600 is per-seam**: the ±600 symmetric
  envelope is the **entry** seam (announce↔bond, inversion-eligible, 1200-block search width); the
  **exit** seam (terminal drain + recurring partial-unbond) is a *separate, one-sided* standoff (no
  inversion — collateral isn't spendable before the 20_000-block release cooldown) whose latency is
  measured **from cooldown expiry** (it breaks the deterministic fixed-offset cooldown tell), so
  symmetric entry/exit = two independent 600-block draws, each free on its own seam — state the exit
  one explicitly. **Width is the expensive axis** (proven rate-driven); the cheap thin-regime levers
  are biasing the gap toward the max (600 is already free) and the inversion, not a wider window.
  **Executable conformance reference (2026-06-16):** single-sourced into the `shekyl-standoff` crate
  (float-free `draw::draw_entry_gap` in the default build + feature-gated `conformance` instruments
  and the RNG-generic `certify_draw` self-cert harness a wallet runs against its own CSPRNG), with
  the generic goodness-of-fit primitives in `shekyl-stats`. The published vector is split along the
  determinism boundary — the **integer** `(spread, order)` golden vector is bit-identical and verified
  on the aarch64 CI lane; the float grading is x86-only (float is not cross-arch bit-identical).
  Conformance is **wallet self-test, not consensus enforcement** (the anchor is consumer-side and
  FCMP++-hidden). See `FOLLOWUPS.md` §funding-seam carry 2.
- **CLOSE — pay-every-block / implicit accumulator emission (corrects the pass-3 over-claim).** The
  pass-3 entry claimed accumulator credit "deletes GF-6/GF-10." **That was wrong.** The borrowed
  intuition (a quiet validator lost in the crowd) needs an *anonymous* crowd; Shekyl staker payments
  are a **roll-call** — every accrual is keyed to `P_canonical_id` because dedup demands it (confidential
  staking was rejected). In a roll-call, continuous attributed payment makes an absence *more*
  conspicuous: a per-block tick that stops is a one-block edge at the GF-4 exit, whereas sporadic
  claims have natural gaps. And it cannot be built the way the intuition needs — **consensus holds no
  ephemeral secret, so it cannot mint a hidden-recipient output** (the coinbase is private only because
  the miner is sender-to-self). So a per-block reward is either (a) a publicly-derivable push → every
  `P`'s reward stream becomes output-by-output traceable to `P_canonical_id` (privacy destroyed), or
  (b) an invisible accrual `P` must later claim — which *is* the current model, and the claim is the
  exposure; auto-compounding it to exit only **concentrates** everything into the terminal event (worse
  GF-4) and destroys the claim-timing decorrelation lever. The periodic-claim model is the better spot
  given public attribution: claims are individually timing-decorrelatable and decoupled from unstake
  (R0-D6 — accrued epochs stay claimable after `FullyUnstaked`). **The obfuscation being reached for is
  reachable only with membership-hiding claims = the confidential-staking machinery already rejected**
  — so this is not a cadence question; it is the public-attribution bridge cost (**S-4**) in disguise.
  Disposition: close the cadence path; the real, conscious model-level question is **"is public per-`P`
  attribution exposure high enough to reopen the confidential-staking rejection?"** (folds into **S-5**),
  not a payment-schedule tweak.

**Quick dispositions (pass 4):**

- **Terminal-lump softening — no consensus mechanism needed.** Wallet-side claim/drain fragmentation
  is the GF-4 output-count discipline already on the books (§6 R4); fragment the materialization
  voluntarily. *(UPDATE 2026-07-16: that discipline is retired as phantom — F-W10, §12.9 decision 2;
  the "no consensus mechanism" half of this disposition stands a fortiori.)*
- **"Derive each block" rejected — backwards on a privacy chain.** Per-block accrual is *more* state
  churn (every staker row updated every block vs. epoch-batched) and *more* reorg surface (more frequent
  consensus transitions to reverse atomically), for the **same** claim exposure. Epoch-batched accrual
  is the simpler and lower-exposure path.
- **Seed compromise — named residual, not an engineering target.** Total restorability and total
  compromise are the same coin: no recoverability without the seed as a single point of failure. Accept
  as the named residual; weight goes to user key hygiene (the S-6 key-locality pin bounds the *serving
  box's* surface, but the cold-side seed remains the root).

**Prioritization (pre-seal):** (1) build the fused exposure ledger (S-2 — cheap, tells you whether
the seams compose); (2) put a minimal adversary sim on the funding/exit timing seams (S-3 — the
actual linkage). The **S-5 longevity fork is consciously closed** (long-lived `P` committed,
2026-06-16); its surviving privacy *residual* is exactly (1)+(2) — characterize the long-lived
handle's fusion surface, do not re-fork the architecture. The walls (crypto + network) are in good
shape; the **doors (GF-7/GF-4)** are where the remaining privacy work is. S-2 and S-3 are the
privacy axis of the R-3 reconciliation that already gates the seal.

### 10.13 Round 2 closure disposition (2026-07-11)

**Closed against the §10.0 bar.** The network round does not admit algebraic separation, so the
close is *not* "principal↔`P` linkage is impossible." It is: **every named leak vector (GF-3, GF-5,
GF-6, GF-9, GF-12, the fork-1+4 isolation gap) has a specified, testable mitigation and a written
residual** (§§10.3–10.9), the four adversarial passes (§10.11) resolved the forks and the
critical-path items, and the §10.12 end-to-end trace surfaced and homed the cross-layer S-1…S-6
findings. R2's job was to *name the transport firewall and its residuals*; it has. What remains is
implementation and measurement, carried below — the same closure posture R1 took with its `archival_p`
impl carried.

**What R2 does *not* claim.** It does not close GF-7 or GF-4 (the money seams — S-1); those are R4
and are conceded-deferred here, not covered. It does not measure effective (vs. nominal) cover; that
was filed as the testnet S-3 obligation *(re-split 2026-07-16 by §11.8 method note 3: the observer
machinery stays a testnet obligation; the cover **level** is economics, cannot close pre-genesis, and
is reclassified into the WI-4 §13.5 conditional register — see §12.8)*. It does not freeze the GF-9
HS-id label (below). Association with a
disposition is not coverage of its implementation.

**Carried items (rule-21 — each names its completion/reopen criterion and its home):**

| Carry | Home | Completion / reopen criterion |
|-------|------|-------------------------------|
| **GF-9 HS-id HKDF label** — seed-derived `p_slot`-bound `.onion` identity | **§9.3 amendment + `ARCHIVAL_P_DERIVE_V1` KAT** | **Armed:** label absent from `archival_p.rs` at close (verified). Pin the label into the §9.3 table (L=32 seed → ed25519 HS identity, consumer `launch_onion_service_with_hsid`) **normalized to the hyphen convention** — §10.7's `shekyl.archival.p.hs_id.v1` (dots) must become `shekyl-archival-p-hs-id-*-v1` before it enters the KAT, or the §9.3 non-prefix-free safety argument does not cover it. Freezing the label is a deliberate crypto-surface act, not a side effect — do it as its own pin. |
| **At-source Arti pin** — exact version/feature/MSRV/`with_hsid` API shape | Transport PR (§10.3) | Embed-Arti fork holds; external-daemon-over-SOCKS reversion clause fires iff the at-source check fails. |
| **Dummy/fragmentation tuned ratio** | Testnet replay (§10.6) | Measure-then-tune: the real-to-dummy ratio that makes `P` bursts indistinguishable from ambient large-v3; honest cost/coverage residual. **Instrument proviso (method note 3, 2026-07-16):** the `P`-burst side is mechanism (software-generated, testnet-faithful); the **ambient large-v3 distribution must be observed from the live Tor network** — real external-world data that exists independent of Shekyl's economics — never synthesized by the replay itself, or the ratio is tuned against the load generator. |
| **§10.9 isolation enforcement mechanism** (Arti config vs. policy) + **S-6 key-locality** provisioning | Transport PR + PHASE_2B engines | Independent guard sets + restore-flow non-co-activation must be *structural*, and the serving box gets only the `P`-subtree (never the master seed). Reopen if a host-level compromise model is added. |
| **Heavy-path relaxation** | §10.8; post-testnet sim L-curve | Pure-rendezvous is the genesis commitment; any relaxation is a post-testnet reversion clause and must prove the *access pattern* (not just the payload) carries no `P`-attributable metadata. |

**Handed forward (not carries — scope transfers):**

- **To R3 (§11):** announce↔anchor timing gap (§10.5) and emission-cadence timing (§10.6) — the
  *timing* of the transport events R2 pinned the *shape* of.
- **To R4 (§6):** GF-4/GF-7 recurring surfaces under the genesis rebond/unbond FSM; the exit-seam
  standoff (FOLLOWUPS 2b).
- **To R5 (§10.12):** the S-2 fused exposure ledger and S-3 exit/value-seam adversary sim.

**Landed transport code at close (status-of-record: [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §4):**
2d-2 is *partially built, inert* — SP-T1 circuit isolation (#204/#209), SP-T4a `BroadcastSubmitter`
(#254, `Local` posture live via the WI-3 dispatch driver); `shekyl-p-transport` (`PTorClient`,
`PBlockSource`) on `dev` but `dead_code`; the `PerP` posture + block-timed remote dispatch await the
2d-2 completion. R2's *design* is closed; its *wiring* tracks the Bond-PR 2d-2 front.

---

## 11. Round 3 — timing + rotation + `W`/epoch-length (DESIGNED + adversarial pass run 2026-07-11)

**Status:** **Design pass + adversarial pass both run (2026-07-11); mechanism pinned, closes when
folded into the R4/GF-4 joint grade.** GF-10 (the sole un-pinned exit gate) is pinned as a
**mechanism + structural window + a-priori advantage claim**; its **numeric width is routed to the
R4/GF-4 CB-3 joint grade**, not graded standalone — grading GF-10 alone would re-commit the
per-axis-multiplication error CB-3 forbids (§11.5). The **adversarial pass (§11.8)** found no break
but two unstated assumptions + one wrong-tool error — folded as re-pins into §11.3–11.5 (freeze-epochs
hold; `S_min` rationale re-derived; correct one-sided negative controls) — and produced **one clean
retraction on the merits** (the `REFERENCE_BLOCK_MAX_AGE` "verifiable-only-≤100-blocks" misread; §11.8).
Rotation dispositions ratified (§11.6); R2 timing hand-forwards resolved. All pins source-grounded at
`dev` `75c3cae1d`. Two frame/pass assumptions were overturned at source (epoch-crossing, §11.4;
max-age semantics, §11.8) — both recorded as corrections, not silently dropped.

### 11.1 Scope and the seam it defends

Scope (§6): **timing + rotation + the `W`/epoch-length joint pin.** The property (§4 invariant 3):
a watcher cannot align principal spends and `P` emissions to a single clock better than chance +
public epoch boundaries, under stated wallet discipline. The bridge is **`P`→principal timing** —
a sub-epoch alignment channel between `P`'s emission-claim broadcasts and principal wallet activity.
It is *not* principal→user, and *not* the amount channel (loud by design, §2.4). This is the inner
seam's *timing* face; the entry/exit *funding* seams (GF-7/GF-4) are R4.

### 11.2 The adversary (name it)

A **passive timing observer** with the public per-epoch retention/serve-credit timeline (F1
liveness fingerprint, §2.3) and a candidate set of principal on-chain activity, attempting to align
`P`'s within-epoch emission-claim broadcasts to principal spends. Two sub-adversaries:

1. **Sub-epoch claim-timing correlator** — the settlement-epoch batch (§2.3) already coarsens claim
   cadence to epoch granularity, but *within* an epoch the claim's broadcast instant is currently
   unconstrained. If it is deterministic (e.g. always at epoch open, or a fixed offset), it is a
   standing alignment channel. **This is what GF-10 closes.**
2. **Rotation-timeline linker (E-4)** — `P_old`→`P_new` re-linkage via fine-grained retention
   timeline + shard-set adjacency across a rotation (§2.3 E-4). Largely **already dispositioned** —
   see §11.6.
3. **Batch-cap-forced determinism (wargame finding, this pass).** The jitter mechanism has an
   unstated assumption: it decorrelates only if the scheduler *chooses* the broadcast height. If the
   scheduler lets backlog accumulate to `MAX_SETTLEMENT_EPOCHS_PER_EMISSION = 15`, the claim is
   **forced** at the block the 15th epoch settles — deterministic on epoch settlement, defeating any
   jitter. The mechanism is only as strong as the scheduler's discipline to claim *before* backlog
   forces it. §11.3 pins that discipline as part of GF-10, so the assumption is armed, not implicit.

### 11.3 GF-10 disposition — the claim-jitter mechanism (pinned)

**Where it lives (source, not memory).** Claim cadence is a **scheduler** concern, *not* the claim
builder: CB-3 (RATIFIED 2026-07-09, [`EMISSION_CLAIM_BUILDER.md`](EMISSION_CLAIM_BUILDER.md) §CB-3)
pins that the builder takes an explicit `claim_epochs` input and **does not self-schedule**, and the
Engine claim orchestrator returns the assembled reply **unbroadcast** (`claim_orchestrator.rs`, index
§4). So GF-10 governs the **claim scheduler**, which is **unbuilt** — verified at source 2026-07-11:
`shekyl-standoff` exposes `draw_entry_gap` only; there is **no `draw_exit_gap` and no claim-jitter
symbol** anywhere under `rust/`, and `ARCHIVAL_TIMING_CONSTANTS.md` §7 still lists "Emission jitter —
± fraction of `SEB`" as unlanded. This is therefore a **pre-code structural pin** — arm the mechanism
before the identifier exists (the M1 discipline; [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)).
(UPDATE 2026-07-16: `draw_exit_gap` now exists — F-D3, §12.5, `shekyl-standoff/src/exit.rs` —
but it is the *exit-seam* draw, not GF-10's claim jitter; the claim-jitter symbol remains absent
and this pin's status is unchanged. UPDATE 2026-07-17: `draw_exit_gap` deleted with the F-D4
exit mechanism — §12.9 decision 5 — so the 2026-07-11 source read is true again verbatim:
`shekyl-standoff` exposes `draw_entry_gap` only. This pin's status remains unchanged.)

**Mechanism (pinned):**

- The claim scheduler draws each emission-claim tx's **broadcast height** by a **direct
  uniform-independent draw** through the audited `bounded_uniform` (`rust/shekyl-standoff/src/draw.rs:31`,
  the single unbiased sampler), wrapped in a typed `ClaimJitterGap` mirroring the entry
  `draw_entry_gap` / `NetworkGap` pattern (`draw.rs:81`).
- **Per-claim independent** — no shared trigger. The entry sim measured a shared trigger as
  catastrophic (`16 → 1.01`, §10.12); a scheduler that fires every claim off one epoch-boundary tick
  clusters identically. **Independence is the load-bearing property, not the width.**
- **Drawn directly** as a single `bounded_uniform` over the window. **GF-10 is one-sided** — one
  draw, no order coin — so unlike the entry gap it has **no double-jitter failure mode**; the entry
  `draw_entry_gap_double_jitter_trap` (`conformance.rs:177`) guards the two-sided
  *difference-of-two-uniforms* construction and does **not** transfer here (G-10.C, adversarial pass
  §11.8). GF-10's real failure modes are the two below, which get their own armed controls (§11.5).
- **No self-scheduling to the batch cap** (§11.2 finding) — the scheduler must claim opportunistically
  within the jitter window *before* backlog reaches the 15-cap, so the broadcast height is
  jitter-determined, not backlog-forced. Part of the GF-10 pin. **Bounded residual (G-10.D, §11.8):**
  a persona returning from `> 15`-epoch dormancy wakes with backlog already `>` cap, so its next
  claim is backlog-forced — "claim before the cap" is not always achievable; the residual is
  named, not closed.
- **Freeze the epoch set across the jitter hold (G-10.A, §11.8).** A `≥ SEB` hold means carrying an
  in-flight claim across the daemon acceptance window (`REFERENCE_BLOCK_MAX_AGE = 100`,
  `reference.rs:181` — an *inclusion-freshness* window, **not** a verifiability expiry), so its FCMP
  proof must be **re-anchored** (`REBUILD_AT = 50`, `reference.rs:106` — local, non-observable) one
  or more times before broadcast. Each re-anchor must be **proof-only**: fresh reference + rebuilt
  membership proof, with `claim_epochs` **frozen at the single source-fetch**. Re-running the
  gather / `derive_claimable_epochs` at a newer tip would pull in freshly-finalized epochs and
  re-couple the epoch set to the broadcast timing — reopening exactly what §11.4 closes. **Anchored
  at source:** the claim orchestrator (`claim_orchestrator.rs::orchestrate_emission_claim`) is
  **single-shot** — fetch `source` once (:230), anchor once via `two_sided_reference_height` (:241),
  assemble once, hand off **unbroadcast** (:335, CB-3); the hold/rebuild/dispatch loop is the
  **unbuilt CB-3 dispatch seam** (the same seam GF-10's jitter lives in), so this is a forward pin on
  that seam, not a change to landed code.

### 11.4 The `W`/epoch-length joint pin — the structural window

**Source correction (this pass overturned the frame).** The 2026-07-11 frame posited that the jitter
"must not push a claim across a settlement-epoch boundary (which would change *which* epoch it
claims)." **Verified false at source:** which epochs a claim covers is the tx payload `claim_epochs`
(`emission_claim.rs::derive_claimable_epochs`), **independent of the broadcast height** — broadcasting
later does not re-select epochs. The real bounds are finalization (below) and forfeiture (above):

- **Floor** `H_lo = h_close(E_oldest) + G_final`, `G_final ≥ ARCHIVAL_REORG_DEPTH_BLOCKS = 720`
  (`config/consensus_constants.json:23`). A claim cannot broadcast before its oldest batched epoch is
  finalized — verify's `NotFinalized` predicate is `chain_height > h_close(E)`
  (`emission_claim.rs:335-342`); the reorg-depth guard keeps the claim valid across a reorg.
- **Ceiling** `H_hi = (E_oldest + W)·SEB − G_submit`, with `W = 26`, `SEB = 10_000`
  (`config/consensus_constants.json:19,21`), `G_submit` ≥ mempool + confirmation depth. The claim
  must confirm before its oldest epoch forfeits at `E_oldest + W`; oldest-first batch drain already
  guarantees no epoch is pushed past forfeiture (`emission_claim.rs:429`).
- **Minimum spread** `S_min ≥ SEB` (a-priori floor, this pass). **Rationale re-derived (G-10.B,
  §11.8) — the original "F1 is epoch-granular so finer jitter is pointless" premise is false at
  source** and is withdrawn: F1 is epoch-granular only because §2.3 *defines* it as the per-epoch
  serve-credit ledger; it is **not** the finest public liveness signal — the challenge fire/response
  is **sub-epoch, block-granular** (`challenge_fire_height` puts `H_fire ∈ (H_open, H_close]` via a
  beacon offset, `challenge.rs:56-76`). The floor stands on the **stronger, granularity-independent**
  basis: a claim's **epoch set is already fully public** (`claim_epochs` rides the tx), and the
  broadcast height is directly on-chain, so sub-epoch jitter of the broadcast instant carries **no
  marginal `P`→principal alignment bits** regardless of any channel's granularity. `S_min ≥ SEB` is
  then chosen not because finer is *useless* but because ≥ one epoch is the spread at which a
  broadcast is decorrelated from any single principal event across a full settlement period. **The
  exact width above `S_min` is NOT pinned here** — it is the R4 joint-grade output (§11.5).

This is the "joint" pin: the window `[H_lo, H_hi]` is denominated in `SEB` and bounded jointly by `W`
(forfeiture horizon) and `ARCHIVAL_REORG_DEPTH_BLOCKS` (finalization); the three constants compose,
which is what the round title names.

### 11.5 Grading is R4's (CB-3 joint grade), not standalone; conformance; coverage boundary

**Grading routed, not performed here — and this is load-bearing.** CB-3 (RATIFIED 2026-07-09) routes
claim-cadence grading to the GF-4 round under a **rule-21 joint-grading obligation**: claim timing
must be graded **jointly** with the reward-amount sequence and the holdings stratum, because the three
are co-present on one persona and an independent per-axis grade multiplies as if independent (the
per-axis-multiplication error WI-4 §11 / CB-3 both flag). **R3 therefore pins GF-10's mechanism +
structural window + the a-priori advantage claim, and stops** — it does **not** standalone-grade the
width. Grading GF-10 alone here would be exactly the error CB-3 forbids. Same split the entry seam
used: the standoff *draw* is the mechanism (R2/R4), the WI-4 sim is the joint *grade*.

**A-priori advantage claim (pre-committed, before any R4 sweep — GF7_HOOKS §5.1 discipline).** Under
a uniform-independent draw over `[H_lo, H_hi]` with `S_min ≥ SEB`, a passive timing observer holding
the F1 fingerprint and a candidate principal-activity set gains **no better-than-epoch-prior**
alignment of a claim broadcast to a principal spend. A failed R4 grade against this claim is a
**redesign signal** (widen `S_min`, revisit independence), *never* a move-the-bar signal.

**Conformance (wallet self-test, consensus-unenforceable).** The broadcast height is consumer-side;
consensus sees only that the claim landed inside `[H_lo, H_hi]` (the claimable window it already
enforces via the `NotFinalized` / forfeiture predicates). So GF-10 ships as a **published wallet
conformance vector**, not a consensus rule: an integer golden vector on the aarch64 lane
(bit-identical, like the standoff `golden_vector.rs`), strict-alpha chi-square uniformity + lag-1
independence (`shekyl-stats`). **Negative controls corrected (G-10.C, §11.8):** the arming negatives
must be GF-10's own failure modes, **not** the entry double-jitter trap (which detects a two-sided
construction GF-10 does not have) — (a) a **shared-trigger control** (all claims drawn off one tick →
assert the clustering is caught) and (b) a **backlog-at-cap control** (backlog `≥ 15` on wake →
assert the forced-determinism is caught). Grade the property, not the PRNG.

**Sub-epoch challenge channel — scope line (G-10.B, §11.8).** The challenge fire/response is a public
`P`-serving-liveness signal at **block granularity** (`challenge_fire_height`, `challenge.rs:56-76`),
finer than F1. It is **beacon-driven** (the fire height is consensus-seeded, not `P`-chosen), so it
is neither a `P`→principal channel nor a claim-alignment lever, and GF-10 does not touch it.
**Residual routed:** if the challenge *response*-broadcast instant is `P`-chosen and network-observable,
it is a distinct timing surface → routed to the **S-2 exposure ledger** (R5), not folded into GF-10.

**Coverage boundary (state it — never let association read as coverage):**

- **Bites against:** a *deterministic / predictable* claim-broadcast cadence (fixed offset,
  epoch-open, or backlog-forced) an observer could align to principal timing.
- **Does NOT cover:** *which epochs* `P` served (roll-call, attributed, public by function — F1); the
  sub-epoch challenge fire/response liveness channel (beacon-driven; S-2 for the response instant);
  the *joint* composition with amount / holdings / exit-timing (R4/GF-4); the entry funding seam
  (GF-7, built) or exit funding seam (GF-4). GF-10 is one channel of the drain/claim event, not the event.
- **Multiplicative on §10.9 isolation**, never additive — the number is `P(align | isolation holds)`.

### 11.6 Inherited dispositions ratified + R2 hand-forwards resolved

- **Rotation timeline leg → non-channel (T-A1, §2.3).** At lean equilibrium ~98% singleton portfolios
  ⇒ portfolio = public identity; cosmetic rotation with fixed storage is rational and re-linkable, so
  timeline re-linkage is *not* the channel and decorrelation would require abandoning scarce-shard
  income. F1 **conditionally finally accepted** (§2.3). Ratified into the round; reopen only on a
  Form-C / reward-shape change (§2.3).
- **Rotation network leg → pinned in R2.** `P_new` must not share principal clearnet path (§4
  invariant 4): HS key `p_slot`-bound + seed-derived (§10.7), independent guards + restore-flow
  non-co-activation (§10.9). R3 owns only the *timing/portfolio* face of rotation.
- **`p_slot` over-enumeration ceremony** — two-rotation split (backing-UTXO vs. `P` pseudonym
  rotation) + `new slot ⇒ new keys` pinned (§3, §9.2).
- **Epoch batching + `W` vs cap (GF-11, no new pin)** — `MAX_SETTLEMENT_EPOCHS_PER_EMISSION = 15`
  blunts drip cadence; `W = 26 > 15` so the **batch cap binds** — a `P` cannot widen its claim window
  to the forfeiture horizon to thin its fingerprint (§2.3). Consensus fact, not a lever R3 spends.
- **R2→R3 timing hand-forwards resolved:**
  - **§10.5 announce↔anchor timing gap → covered by the entry standoff** (GF-7 mechanism,
    `draw_entry_gap`, built #255): the announce↔bond-post gap *is* the entry standoff's target. R3
    ratifies; it does **not** build a second mechanism.
  - **§10.6 emission-cadence timing → GF-10** (§11.3–11.5) mechanism + the CB-3/R4 joint grade.
- **F1 wallet disclosure copy** ([`F1_TA3_TA7_LIFETIME_WINDOW.md`](F1_TA3_TA7_LIFETIME_WINDOW.md) §10)
  — operator-facing statement that rotation does **not** reset `T_obs` (= operator lifetime); a UX
  task routed to the wallet disclosure surface.

### 11.7 What R3 closes, defers, and its reopen criteria

**Closes (adversarial pass run 2026-07-11 — §11.8, re-pins folded into §11.3–11.5):** the GF-10
claim-jitter **mechanism** + structural window (§11.3–11.4, now incl. the freeze-epochs pin) + the
a-priori advantage claim (§11.5, rationale re-derived); the ratified rotation dispositions and R2
timing hand-forwards (§11.6).

**Defers (named, rule-21):**

- **GF-10 numeric width** above `S_min` → R4/GF-4 CB-3 joint grade (jointly with amount + holdings +
  exit-timing). Reopen the mechanism only if the joint grade cannot meet the pre-committed advantage
  claim at any structurally-admissible width. **UPDATE 2026-07-16 (§12.9 decision 3): the joint
  grade dissolved by axis attrition — the width now grades standalone against the same §11.5
  pre-committed claim; the reopen clause carries over with "joint grade" read as "single-axis
  grade."**
- **Extension to bond ops** — GF-10 reused for partial-unbond / rebond-topup claim timing in R4 (§6);
  the mechanism is pinned so the extension is mechanical.
- **Build** — the `ClaimJitterGap` draw + the claim scheduler/dispatch seam (CB-3) are unbuilt. Land
  the draw the M1 way: a CI grep that the claim scheduler routes through `bounded_uniform` with no
  deterministic-cadence fallback, armed **before** the scheduler identifier exists. **Plus the
  freeze-epochs pin (G-10.A):** the dispatch seam must rebuild a held claim's proof **proof-only**
  (re-anchor reference, never re-fetch `source` / re-run `derive_claimable_epochs`) — arm a
  grep/test that the dispatch rebuild path does not call the gather/derivation.

**Out of scope (do not fold in):** the L17 synchronized-exit wargame (crisis cadence blows through
jitter windows) is the **exit seam** — R4/GF-4 ([`FOLLOWUPS.md`](../FOLLOWUPS.md) swan-2/W8). R-3
reward-magnitude quantization is R4 / ~~§14.4 economics~~ *(the §14.4 target was dangling —
re-pointed 2026-07-17 to the F-D5 disposition round chartered at §12.7)*.

**Reopen (rule-21):** the GF-10 window reopens on any change to `SEB`, `W`,
`ARCHIVAL_REORG_DEPTH_BLOCKS`, or `MAX_SETTLEMENT_EPOCHS_PER_EMISSION`; the mechanism reopens if the
R4 joint grade fails the pre-committed advantage claim.

**Remaining for close:** the adversarial pass has run (§11.8) and its four findings are folded as
re-pins. R3 is at its exit bar as a *mechanism* round: the mechanism + structural window + a-priori
claim are pinned and source-anchored, the negatives are the right ones, and the residuals (dormancy,
sub-epoch challenge) are named. **The one item that keeps R3 formally "designed, not closed" is
external to the mechanism:** the a-priori advantage claim is only *graded* in the R4/GF-4 joint
sweep (CB-3), so R3 closes when GF-10 is folded into that grade and the grade clears the
pre-committed claim — the same mechanism-then-joint-grade split the entry seam used.

### 11.8 Adversarial pass (2026-07-11) — findings, re-pins, and one retraction

**Verdict:** the pass did not find a break, but it found the two unstated assumptions the mechanism
rested on and one wrong-tool error — folded above as re-pins, not move-the-bar edits (per §11.5's own
discipline). All four are source-anchored at `dev` `75c3cae1d`.

**Retraction (clean, on the merits).** The pass first raised **G-10.A as a mechanism-infeasibility**
finding — that `fcmp_reference_block_max_age = 100` made a claim "verifiable only ≤ 100 blocks," so a
`≥ SEB` hold was impossible. **That was a reviewer construction resting on an unverified premise —
the constant's semantics were asserted from its name, not traced to its consumer** (the exact failure
mode this track holds the line against). Traced at source: `REFERENCE_BLOCK_MAX_AGE` is a **daemon
inclusion-freshness window** (`proof_submittable`, `reference.rs:181`), **not** a verifiability
expiry — a mined claim is validated once at inclusion and stands; `PROOF_VALIDITY_HORIZON = 94`,
`REBUILD_AT = 50`, and re-anchor is explicitly local + non-observable (`reference.rs:102-106`). The
"infeasible / 100 ≪ SEB / ~200-rebuilds-observable" claims are **withdrawn**. What survives is the
narrow, correct pin below.

| # | Finding | Status | Source anchor | Re-pin (where folded) |
|---|---------|--------|---------------|-----------------------|
| **G-10.A** | A `≥ SEB` jitter hold must rebuild the proof; a rebuild that re-derives `claim_epochs` re-couples the epoch set to broadcast timing (reopens §11.4) | **Pin** (was infeasibility — retracted) | `claim_orchestrator.rs` single-shot (:230 fetch, :241 anchor, :335 unbroadcast); hold/rebuild = unbuilt CB-3 seam | **§11.3** freeze-epochs bullet; **§11.7** Build item — proof-only rebuild, forward pin on the unbuilt dispatch seam |
| **G-10.B** | The `S_min` rationale ("F1 is epoch-granular so finer jitter is pointless") is false — challenge fire/response is sub-epoch block-granular | **Load-bearing correction** | `challenge_fire_height` → `H_fire ∈ (H_open, H_close]`, `challenge.rs:56-76` | **§11.4** rationale re-derived on the "epoch set is already public" basis (stronger, granularity-independent); **§11.5** sub-epoch channel scope line (beacon-driven; response instant → S-2) |
| **G-10.C** | The cited negative control (`draw_entry_gap_double_jitter_trap`) is the wrong one — it guards a two-sided construction GF-10 does not have | **Correction** | `conformance.rs:177` (two-sided); GF-10 is one-sided (§11.3) | **§11.3 / §11.5** — swapped for GF-10's real failure-mode controls (shared-trigger + backlog-at-cap) |
| **G-10.D** | "Claim before the cap forces it" is not always achievable — return-from-`>15`-epoch-dormancy wakes with backlog `>` cap | **Bounded residual** | `MAX_SETTLEMENT_EPOCHS_PER_EMISSION = 15` (`emission_wire.rs:53`) | **§11.3** — named as a residual (correlates with the persona's own liveness gap, ~public via F1/challenge), not closed |

**Method note (for the next reviewer):** G-10.A's retraction is the load-bearing lesson of this pass
— a constant's meaning is its consumer, not its identifier. The `REFERENCE_BLOCK_MAX_AGE` /
`PROOF_VALIDITY_HORIZON` / `REBUILD_AT` semantics (`reference.rs:85-106`) are the anchor for any
future reasoning about how long a claim can be held; do not re-derive them from the name.

**Method note 2 (added 2026-07-16, from the F-D4 round-4 premise audit — the same lesson one
level up): a channel's meaning is its observable.** Four rounds of prose review on the F-D4
exit window audited the arithmetic and never the existential — "principal-side re-appearance"
survived as a phrase for four rounds because prose never has to populate its nouns. The §8
sweep harness did: the observer, written as code, had to declare a variable for the event it
correlates against, and "what populates this?" became unavoidable — the channel was found
empty (`ARCHIVAL_EXIT_STANDOFF_FD4_WINDOW.md` §2.1/§15, F-W7/F-W8). Standing requirement
proposed there and adopted as this doc's method posture: **every graded seam pre-registers
its observer as executable code before any row runs.** A methods paragraph can quantify over
a phantom indefinitely; an executable observer cannot.

**Method note 3 (added 2026-07-16, extracted at the F-D4 round-4 ratification — the
instrumental half of note 2): before queuing any constant for a stressnet seal, classify
the measurement as mechanism or economics.** *Mechanism* — does the partition fire, is the
draw unbiased, does the determinism KAT hold on aarch64, does timing behave under load. A
testnet reproduces these faithfully, because the software doesn't know the money is fake.
*Economics* — exit rate, churn, profit-taking cadence, panic cohort size, mobility. A
testnet **cannot** produce these: every one is a function of real value at risk, so a
"read" returns a measurement of the test plan, echoed back with the authority of
"measured." If a constant needs an economics number, the stressnet is the wrong instrument
and the honest exits are three: derive it structurally, design the constant away, or don't
ship the genesis-frozen value at all (F-D4 §15.8 has the full statement and the motivating
case — two of `DEFAULT_EXIT_GAP_WINDOW`'s three seal inputs were economics, unmeasurable in
principle *before* the phantom-`T` finding). **Filter run across the PF-9 / Phase 7.7 queue
at adoption:** `K_COVER` is the only seal queued behind stressnet entry and passes (the
§14.4 partition run is mechanism — a pre-registered partition-adversary arm); the remaining
Phase 7.7 entries (F11-S Windows-midrange bench, historical reference-block/reorg exercise,
archival multi-staker path, `tests/stressnet/README.md` acceptance criteria) are mechanism
exercises; the FA-6 wire lock is a sequencing pin, not a measurement. **Filter extended
across this doc's named residuals (2026-07-16, same day):** one live hit and one proviso.
The hit — GF-7's effective-vs-nominal-cover residual was misfiled as a testnet obligation:
the observer *machinery* is mechanism and stays testnet-dischargeable, but the cover
**level** is post-isolation network-event rate — economics, unfalsifiable pre-genesis —
so it is **reclassified as the fifth WI-4 §13.5 standing conditional** (§12.8; verified at
source that the `1.86` was computed on nominal cover, so the conditional is load-bearing
against the 7% margin). **The hit's follow-through (same day): the conditional's *shape*
was then measured, because the sensitivity sweep is mechanism even though the level is
economics** — `shekyl-staking-sim --gf7-breakeven` sweeps the model's own `r(N)` at the
gate posture (a property of the model, not the world). Result: worst-arm `r` is flat
≈1.86 across `N ∈ [2, 16]` — **`r < 2` is structurally blind to cover**, so cover was
never gated by `r` and no per-event monitoring threshold exists to derive (the candidate
`P(link) ≤ 0.2` is the ratio bar evaluated at nominal cover, back-derived — an arithmetic
identity, not a committed bound; full reading at §12.8 and WI-4 §13.5). This is the
filter's constructive half demonstrated with an honest output: the same classification
that removes an unmeasurable read from the seal queue also names which *derivable*
measurement exists — and takes its answer even when the answer is "no per-event monitor
exists; the conditional's instrument is the S-2 lifetime ledger." The proviso — the GF-6
dummy/fragmentation tuned ratio (§10.13 carry): the `P`-burst side is mechanism
(protocol-determined wire sizes, testnet-faithful), but the ambient large-v3 distribution
must come from live-Tor observation — real external-world data that exists independent of
Shekyl's economics — never the replay's own synthesis. The rest classify cleanly:
leg-(b) wall-clock and the §14.4 partition run are mechanism (buildable, as WI-4 §13.5
already says); isolation conditioning is already correctly filed as permanently
conditional; the L12 cold-start residual passes because its disposition is already the
design-away exit (§14 refuses to enter the regime rather than measure it); G-10.D's
dormancy-backlog residual is mechanism-shaped (correlates with the public liveness gap);
the GF-9 label freeze and Arti at-source pin are acts, not measurements.

**Method note 4 (adopted 2026-07-16, from F-D4 §16 / F-W9 — the compositional half of
note 2): before grading a composition, enumerate the events that compose.** F-D4 §13.3's
intersection argument carried its exponent — `m`, the observation count — as "grows"
through four review rounds while those rounds sharpened the *base* (`q`); the exponent
dominates, and nobody counted it. Walked against the landed FSM, `m` is a lifecycle
**count**: one mandatory observable crossing (`JoinMarket`), two wallet-default-closeable
optional classes, zero observable exits (F-D4 §16). Two corollaries. First, an event
enumeration is mechanism-class under note 3 — readable from the state machine, no
economics input — so "the count is a pre-testnet unknown" never excuses an uncounted
exponent (`E[m]` being economics does not make the *mandatory floor* of `m` economics).
Second, the same check catches compositions whose **linking key** is unnamed: intersecting
observations requires knowing which observations share a cause (§13.3's key was the public
`P_id`), and a composition asserted across a partition the adversary cannot know
(cross-persona `q^k`, raised and withdrawn at F-D4 §16.3 for want of a key) is note 2's
phantom-observable failure wearing composition clothes. The near-miss was caught at draft,
one turn after the lesson was named — the check works on its own authors, which is the
property that earns it a standing note.

**Method note 5 (adopted 2026-07-16, from F-W10 — §12.9 decision 2's ratification
amendment; extended same night with the generative pattern and first application): a pin
carried across a substrate change re-walks against the new substrate at carry time; a
provenance line reading "carry from X" is a re-walk trigger, not an exemption.** The
GF-4 output-count discipline (§2.4) defended against the lump-sweep attack — real and
well-documented in the CryptoNote/ring-signature lineage, where the spend graph is
partially visible. The pin was carried forward across the ring-signature →
FCMP++ cutover, under which the attack has no substrate (the drain is not an identifiable
transaction; the spend set is unenumerable), and four Gate-6 rounds inherited it without
re-walking it — it survived the F-W7 audit precisely because it *looked* on-chain and
didn't route through `T`. The check is notes 1–4's question pointed at inheritance:
for every "carry from" pin, name the observable it presupposes and verify the current
chain still emits it. This is `16-architectural-inheritance.mdc`'s inherited-architecture
rule applied to *threat-model* inheritance: an inherited defense presupposing an
observable the chain no longer emits is inherited drift, not inherited protection.

**The generative pattern (named at ratification review): F-W10 is the fifth instance of
one failure, and the note above is the pattern behind all five.** Phantom `T` (F-W7 —
the principal-side re-appearance nobody could name), the cross-persona k-collapse
(F-D4 §16.3, raised and withdrawn — an intersection re-homed without its linking key),
X-3's harm model (F-W8 — a partition harm whose assignment step was `T` again), `σ_L`
(a spread parameter for a distribution over events that don't exist), and now
output-count (F-W10) — **each is a privacy intuition imported from a chain with a
visible spend graph into a chain that doesn't have one.** Output-count is the cleanest
specimen because its provenance is written in the document: a Monero-lineage pin,
inherited verbatim, defending against a graph FCMP++ deleted. The other four were the
same import at one remove — mechanisms whose observables (a traceable re-appearance, a
followable refund, a linkable persona set) are spend-graph observables that this chain
structurally does not emit. An inherited pin is a claim about the chain it was written
for; re-walk every CryptoNote-lineage carry against what FCMP++ actually emits, the
same way a constant re-walks against its consumer (note 2's neighborhood), an observer
against its code (note 3), and a composition against its enumerated events (note 4).

**First application (2026-07-16, night):** §2.4's other two pin bullets — the only
other "carry from PHASE_2B §2.4" content in the same paragraph as the retired
discipline — were re-walked immediately rather than left for the sixth and seventh
instances to surface adversarially. Verdicts recorded at §2.4: rewards→stealth-outputs
**holds, re-anchored** (its real mechanism is §2.1 key/scan-boundary independence,
creation-side and substrate-independent; the graph-side half of its old justification
is by-construction under FCMP++); the Unbond-refund bullet is **half-phantom** (the
"P-attributed output at public amount" phrasing named an output no observer can
identify — the refund is ordinary hidden vouts against a public `bond_debit` source
term, T-2's structural-unrepresentability; the "same decorrelated-drain discipline"
tail retires with F-W10). The §2.1 crypto-layer carry ("carry from V3 / PHASE_2B") was
checked in passing: its content is key derivation and scan separation — creation-side
mechanisms with no graph presupposition — and stands without amendment.

**Method note 6 (adopted 2026-07-17, from the F-D5 "§14.4 economics" finding — a failure
shape distinct from note 5's five instances): a referent can be minted by summarization.**
"GF-4/§14.4 economics" was not an inherited pin, not a phantom observable, not a stale
row — at source, everyone wrote something right. WI-4 routed *quantization* to a GF-4-round
design candidate (§18.10 R-3) and routed its *strata + lifetime* riders to the §14.4
partition arm (discharged with that arm, PR #291). Both referents were real. The fusion
happened at the summary layer: the index's WI-4 row and this doc's §11.7/§12 prose
concatenated the two into "GF-4/§14.4 economics" — a round that never existed — and three
documents then cited it as authoritative; R4's close condition (iv) was ratified against
it (found undischargeable 2026-07-17, §12.7 charter). The shape is dangerous precisely
because it survives verification-by-grep: **both halves check out if you grep them
separately** — the grep confirms the parts and never tests the join. The check is
source-first over summaries, stated as a rule: a routing target cited from a summary
surface (an index row, a status cell, a close-condition clause, a §-header digest)
verifies against the source document's own words before anything is dispositioned
against it — and a summary that joins two source claims into one is a **new claim**,
carrying a new claim's burden of proof.

---

## 12. Round 4 — output + bond-funding hygiene: the drain-event firewall (OPEN — drafted 2026-07-11)

**Status:** **Open — drafted; F-D3/F-D4 activation FIRED 2026-07-15.** Scope, adversary, and the
drain-event findings (F-D1…F-D6) pinned, source-grounded at `dev` `75c3cae1d`. **F-D1** (amount
channel) is a **complete pre-code pin**, buildable now; **F-D2** (UI-default) buildable now;
**F-D3/F-D4** (exit-timing) were FSM-gated spec-stubs whose activation criterion **fired 2026-07-15**
(§12.5 — the cooldown is now an enforced spendability gate, `bond_post.rs:369`/`:627`), so both are
**open for build**; **F-D5** (quantization) is routed out to ~~§14.4 economics~~ *(dangling —
re-pointed 2026-07-17 to the disposition round chartered at §12.7, which **ran the same day**:
width does not derive, no grid at genesis, band registered as an R5 S-2 ledger row — §12.7
OUTCOME)*;
**F-D6** is the anti-drift pin. R4's other half — **GF-7 (funding-in)** — is already built + graded
PROVISIONAL-PASS (`r = 1.86`; §6 R4 cell); this section is the **value-out (GF-4)**. The channels are
**graded jointly, not per-axis** (§18.10 R-4 + CB-3).

### 12.1 Scope — the drain is one event with three co-triggered channels

The on-chain value legs are dead by construction: reward mint is loud-but-exact
([`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §5.5/§9, a priority-1 inflation-audit disposition;
CT-committing it is foreclosed), amounts are FCMP++/CT-hidden with an unenumerable spend set (§18.11).
What survives is **one event — the drain (`P`→principal value-out)** — carrying three channels that
S-1 says no single layer owns:

| Channel | Finding | Buildable? |
|---------|---------|-----------|
| **Amount** (off-chain subsum match) | F-D1 (+F-D2 UI) | **now** |
| **Timing** (exit-seam standoff) | F-D3 + F-D4 | **BUILT 2026-07-16 against the F-D4 sentinel** (§12.5); sweep + seal owed |
| **Output-count** (decorrelated drain) | §6 R4 hard exit (lineage-blind, §12.3-sibling) | FSM landed (#303/#307) — buildable |

They are **co-triggered** on one event, so they must be **graded jointly** — an independent per-axis
grade multiplies as if the channels were independent (the CB-3 / WI-4 §11 per-axis-multiplication
error). Grading is the R4 joint sweep, into which GF-10's claim-jitter mechanism (§11) folds.
**UPDATE 2026-07-16 (§12.9, at ratification):** the timing channel is phantom (F-W7) and the
output-count channel is phantom (F-W10 — the drain is not an identifiable transaction under
FCMP++, so its output count is not an observable); the joint sweep dissolved by axis attrition
and GF-10 grades standalone. The table stands as the round's opening frame; §12.9 is its
disposition.

### 12.2 The exit anchor — a source correction

The exit standoff anchors on **`RELEASE_COOLDOWN_EPOCHS = 2`** (~28 days), **not**
`RETENTION_HORIZON_BLOCKS = 420_000` (42 epochs). Verified at source: retention-horizon is "min
block-span archival derived state survives before prune **sweep** … audit/sweep only"
([`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) §1/§4) — it governs **data pruning**,
not collateral spendability. An earlier reviewer note that retention "dominates the exit anchor" is
**withdrawn** on that read. The spendability chain: collateral is a **consensus balance** (not a
UTXO); `Unbond` fires after the release cooldown (grace after last serve) and returns the balance
via the `bond_debit` source term. *(Superseded detail, noted 2026-07-19: the earlier
"mints a `P`-attributed refund output at public `bond_floor`" wording is corrected by
[`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §3.4/§4.3 (2026-07-16): **no identifiable
refund output exists on the wire** — the Unbond *event* names `P` and the released amount is
publicly derivable, but the refund enters as ordinary hidden vouts CT-balanced against the
public `bond_debit` term.)* The refund value then matures like any output. The deterministic tell F-D3 breaks is that this
earliest-spend moment is **cooldown-pinned**.

### 12.3 F-D1 — drain-amount taint-carve (amount channel; complete pre-code pin)

The forbidden read is the **reward-sequence decomposition** (per-epoch `reward_P(E)`, subsums, epoch
counts — `reward_P(E)` is public-derivable ex ante (§18.10), so a drain amount equal to a reward
subsum is off-chain-matchable). The permitted read is the **aggregate** spendable balance (a scalar;
the §18.12 lifetime-band floor, already irreducible).

**Encoding — (a)+strip, over the capability-token (b) and module+grep (c) forks** (source overturned
the shared (b) lean, 2026-07-11): lineage is **backing-only** — `MintLineageOutput`
(`pscan_state.rs:93`, a 3-way rung tag, no epoch/amount in the tag) has exactly one production
reader-for-a-decision, `BackingSet` (`backing_set.rs:143,158`); the writer is `scan_step.rs`, the type
home `pscan_state.rs`; **no drain/spend/selection path reads it** (every other hit is `#[cfg(test)]`).
The drain doesn't need lineage, and the codebase's own selection principle is already **lineage-blind**
("a lineage preference would add a distinguishable … signal", `backing_set.rs:171-176`).

**Two-part trust boundary** (stripping the tag is necessary but not sufficient — per-output *amounts*
are the reward *values*, so a stripped-but-per-output-amount view still admits a subsum pick):

1. **Strip `{lineage, epoch, height}`** from the drain view. Dropping `lineage` breaks reward-output
   *identification* (the load-bearer); dropping `epoch`/`height` closes the residual that for a
   **reward-dominated persona** (the typical long-lived staker, S-5) `Σ amount` grouped by `epoch` ≈
   `reward_P(E)` **even without the tag**. Keep `spendable_height` (a different axis —
   maturity/provability). Fields verified at `pscan_state.rs:169-210`.
2. **The amount stage reads the aggregate scalar only**, never the per-output amount vector — the
   vector carries the reward values; the scalar (one `AtomicUnits` sum) does not decompose.

**Three stages, each reading the minimum:**

- **Amount:** `{user target, cadence, RNG}` → `DrainAmount`; the aggregate scalar is consulted for an
  **affordability check only** (`amount ≤ total`), never as a computation input — so the amount is
  provably not any subsum.
- **Select:** coin-selection over the stripped `{output_id, amount, spendable_height}` vector to meet
  the fixed amount; FCMP++-hidden on-chain, so lineage-blind fungible selection is fine.
- **Project (the single trust boundary):** `PFundingOutputRecord` → the two operands (scalar +
  stripped vector) lives **upstream in the drain orchestrator** — the engine gather that holds
  `PScanState.funding_outputs`, the established "orchestrator prepares operands, downstream receives
  prepared values" seam (`claim_orchestrator.rs:9-14`). The drain amount + selection modules never
  name `MintLineageOutput` / `PFundingOutputRecord`.

**Arm (M1, pre-code — drain path unbuilt):** (i) an import-check that the **drain amount + selection
modules** (not the orchestrator, which must hold the record) import neither lineage type — the
`sweep_funding_outputs`-sole-primitive grep template (`bond_assembly.rs:722-727`); (ii) a signature
check that the amount-stage fn takes `AtomicUnits`, not the output vector. Both fail before the drain
identifier exists.

**Coverage boundary:** closes the **automated off-chain amount-match** (the R-1 residual). Does **not**
touch the lifetime-aggregate floor (§18.12 — drain-all reveals the lifetime total, irreducible),
user-eye manual reconstruction (F-D2 mitigates, does not close), or the timing/output-count channels
(F-D3/F-D4). F-D1 is the amount channel only. UPDATE 2026-07-16 (§12.9): the boundary's other two
channels are both phantom — timing per F-W7, output-count per F-W10 — so "does not touch" is now
"nothing there to touch"; F-D1's scope is unchanged either way.

**Build (2026-07-17) — F-D1 LANDED (code).** The (a)+strip encoding is in
`shekyl-engine-core/src/engine/`, three modules mirroring the three stages:

- `drain_orchestrator.rs` — the single trust boundary. The **only** drain-path
  site that names/holds `PFundingOutputRecord` (which carries `MintLineageOutput`)
  — so the only site *permitted to observe* `{lineage, epoch, height}`;
  `project_drain_operands` drops all three (it reads only `spendable_height` to
  filter and copies `gindex`/`amount`), keeps the mature subset, and reduces to
  the aggregate scalar (`DrainBalance`) + the stripped
  `{output_id, amount, spendable_height}` vector. `plan_drain` composes the
  three stages; it is the public API the eventual drain command calls.
- `drain_amount.rs` — the amount stage. `choose_drain_amount(request,
  affordable: AtomicUnits)`: the scalar is an **affordability check only**
  (`target ≤ affordable`), never a computation input.
- `drain_select.rs` — the select stage. Lineage-blind largest-first coin
  selection over the stripped vector.

**Arm fired, then armed (per the pre-code sequencing pin).** The M1 grep-template
arm landed on a skeleton first (`0de7116cc`); a deliberately-wrong
`MintLineageOutput` import into `drain_amount.rs` was proven to fail the arm
(exit 101) and reverted before the real logic went in — the check prevents the
path rather than confirming it. The arm now lives as `fd1_arm_*` unit tests in
both guarded modules (run under `cargo test`, so CI-enforced): each greps its
own production source and refuses if it names `PFundingOutputRecord` /
`MintLineageOutput` (`drain_select.rs`) or those plus `DrainCandidate`
(`drain_amount.rs`, which reads the scalar, not the vector), and asserts the
amount fn's `affordable: AtomicUnits` signature.

### 12.4 F-D2 — UI-default (defaults are firewall-class; kept in gate-6)

F-D1 makes the *function* incapable of a subsum; F-D2 covers the *default the wallet offers*, which
§18.12 doesn't reach. Per the safe-by-default-for-the-uneducated-user principle:

- **Aggregate-only balance surface.** The drain UI's `P`-balance is the **aggregate scalar**
  (mirroring the principal `LedgerEngine::balance() -> BalanceSummary` aggregate discipline,
  `local_ledger.rs:341`), never a per-epoch/per-reward decomposition. **Largely structural by
  inheritance from F-D1:** the projection means the reward decomposition never reaches the drain
  subsystem, UI included.
- **No reward-derived pre-fill.** The drain-amount field is never seeded from a reward-derived value —
  no "drain epoch-E reward" affordance, no default = reward subsum. Default = empty / user-typed (or
  round-number / random-split if a default is wanted). Consistent with the existing explicit-amount
  send path (no send-max/pre-fill exists).
- **Coverage boundary:** bites against **automated/default** subsum reconstruction (the UI never hands
  the user a reward-shaped number to accept); does **not** cover a user *intentionally* reconstructing
  by eye from public reward history → that residual routes to the enumerated mistake-set (§18.13
  boundary class 3) + the opsec guide.

**Build (2026-07-17) — core-side half LANDED; GUI drain-send subsystem UNBUILT.**
The build lands only the piece that lives in `shekyl-core`:

- **Aggregate-only balance surface — LANDED.** `drain_orchestrator::DrainBalance`
  (one `AtomicUnits` scalar) and `drain_balance()` are the F-D2 core-side
  surface; `plan_drain` takes a single scalar `target`. The projection means the
  reward decomposition never reaches the drain subsystem, so a UI built on this
  surface **structurally cannot** pre-fill a reward-shaped decomposition — the
  breakdown never arrives. This is the "largely structural by inheritance from
  F-D1" half made concrete.
- **The wallet-flow default — NOT LANDED, and larger than a "default".** "Never
  seed a reward-derived amount; offer round-number / random-split" is a
  `shekyl-gui-wallet` affordance against *user-eye* reconstruction. It has **not**
  been touched — and the blocker is **not** RPC. The GUI is a Tauri app that
  **links the engine crates in-process** (`shekyl-gui-wallet/src-tauri/Cargo.toml`
  path-deps `shekyl-engine-core`) and calls them directly from
  `#[tauri::command]` handlers → `wallet_bridge`; `shekyl-engine-rpc` is linked
  as an FFI library, **not** run as a wallet-RPC server
  (`shekyl-gui-wallet/docs/WALLET_STARTUP.md`), and the `shekyl-rpc-*` crates are
  the *daemon* (node) RPC, a different axis. So `plan_drain` is reachable from a
  Tauri command directly — no wallet-RPC layer is a prerequisite.

  What **is** a prerequisite is a **`P`-value-out (drain-send) subsystem in the
  GUI that does not exist yet**, on which the default is merely the top affordance:

  1. **A `P`-scan data source.** `plan_drain` needs `&[PFundingOutputRecord]` from
     `PScanState.funding_outputs`. The GUI today runs C++ `wallet2` + the
     *principal* `shekyl-scanner`; it does not load or maintain `P`-scan state at
     all. Feeding the planner is Engine/P-scan adoption in the GUI process.
  2. **A drain tx-assembly path.** `plan_drain` returns a `DrainPlan` (amount,
     input gindices, change) — **not** a signed/broadcast transaction. The
     assemble→sign→broadcast follow-on (the claim-assembly analog) is wired
     nowhere.

  So `plan_drain` lands here as a **correctly-carved planner with no data source
  and no consumer** — reachable API, not yet load-bearing. That is the right F-D1
  deliverable (the carve holds the instant anyone builds drain-send), but it means
  **F-D2's open status is a whole unbuilt subsystem, not a pending UI default.**
  **F-D2 is not recorded as landed** until that subsystem + its default exist; the
  R4 close keeps the user-eye residual visibly open, not quietly absorbed.

  **UPDATE 2026-07-19: the drain-send subsystem design round OPENED** —
  [`ARCHIVAL_DRAIN_SEND_FD2.md`](ARCHIVAL_DRAIN_SEND_FD2.md) (Round 1 DRAFT,
  DS-1…DS-7; rule 26 cited). The round scopes the three layers above against
  the verified substrate (the GUI holds no `Engine` and no `P`-scan state;
  the claim pipeline is the assembly analog; the §7.4 persona-transport pin
  applies to drain fetch/broadcast), proposes the sub-PR slicing, and
  carries the FOLLOWUPS "P-drain mechanism re-walk" riders (fee/change
  mechanics, shape-era sweep, amount-channel-only confirmation) and the
  accepted §16.4 funding default. F-D2's status is unchanged (open on the
  subsystem); the round is its build path.

### 12.5 F-D3 — exit-seam standoff mechanism (one-sided, cooldown-anchored; gate FIRED 2026-07-15)

The exit seam's dominant adversary is **correlated mass-unbonding** (§18.1): a market event fires
correlated drains, and the linkage is the **co-trigger**, not the amount — so F-D1 is inert against
it; the defense is an independent per-`P` exit-timing draw, exactly the entry finding's "shared
trigger is catastrophic, `16→1.01`."

- **`draw_exit_gap`** — a sibling of `draw_entry_gap`, **one-sided**: a single `bounded_uniform`
  (`draw.rs:31`), **no order coin, no inversion** — collateral isn't spendable before the cooldown, so
  there is no "which came first" to draw (the one-sidedness is *forced by the cooldown*, which is also
  why the entry double-jitter trap does not apply here — §11.3/§11.8). Typed `ExitGap`, mirroring
  `NetworkGap`.
- **Anchored at the cooldown-pinned earliest-spend height** — `Unbond`-height-derived
  `+ RELEASE_COOLDOWN_EPOCHS × SEB` (F-D6: **derived, never hardcoded `20_000`**). The draw adds a
  random one-sided latency *after* that point, breaking the deterministic fixed-offset cooldown tell.
- **Per-event independent**, applied to **both terminal drain and recurring partial-unbond
  (`HoldingsUpdate`)** — each its own draw (the shared-trigger lesson; correlated unbonding is the
  adversary).
- Wallet self-test conformance (the anchor is consumer-side/off-chain, consensus-unenforceable),
  integer golden vector on the aarch64 lane — the `draw_entry_gap` discipline.
- **FSM gate (rule-21) — FIRED 2026-07-15.** The activation criterion recorded here ("open F-D3
  build/measurement when a verify path reads `RELEASE_COOLDOWN_EPOCHS` as a spendability gate") is
  met at source: `release_cooldown_elapsed` is **enforced consensus** with two verify consumers —
  `bond_post.rs:369` (`HoldingsUpdate`-drop, per-shard last-served anchor) and `bond_post.rs:627`
  (`Unbond`, whole-record anchor) — landed with the rebond/unbond FSM (PR #303 `HoldingsUpdate` +
  `Unbond` verify/connect/pop and the Pin-4/Pin-5 closure, 2026-07-14; PR #307 `Rebond`). The
  deterministic cooldown tell this standoff exists to break is now real; F-D3 is **open for build
  and measurement**.
- **Per-event independence armed with its own negative control (pinned at activation, 2026-07-15).**
  The entry seam's `double_jitter_trap` guards a **two-sided** construction (order coin + inversion)
  that the one-sided exit draw does not have, so it cannot be borrowed. The exit draw's conformance
  harness gets a **shared-trigger arm**: a cohort of exit draws keyed to one anchor / one simulated
  market event must be *caught* as clustered (clustering-detection, not inversion-detection). A
  `draw_exit_gap` whose independence claim has no negative control is not conformance-armed.
- **UPDATE 2026-07-16 — BUILT (against the F-D4 sentinel; sealing still owed).**
  `shekyl-standoff/src/exit.rs`: `draw_exit_gap` one-sided through the shared unbiased
  `bounded_uniform`, no order coin; typed `ExitGap`; `ExitGapWindow` capability newtype whose
  `wallet_default()` reads `DEFAULT_EXIT_GAP_WINDOW` — a **provisional sentinel** (`0`,
  `K_COVER` pattern per F-D4 §5.4: compile-refusal unless the consumer enables the grep-able
  `provisional-exit-gap-window` feature, deleted at the Phase 7.7 seal). Golden vector on a
  synthetic KAT window (10 007) with a seal tripwire forcing the re-freeze at seal; the pinned
  shared-trigger negative control landed (`conformance.rs` `exit_release_population` +
  two-property exit grade — uniformity, serial independence, no order axis). The anchor is
  F-D6-derived: `shekyl_archival_retention::release_cooldown_anchor_height` computes `H_cd`
  from `RELEASE_COOLDOWN_EPOCHS × SETTLEMENT_EPOCH_BLOCKS`, boundary-tested against
  `release_cooldown_elapsed`. F-W5 resolved same day (F-D4 §13: exit-seam `N_t = 10`, derived
  not inherited). Open: the X-1/X-2 sweep and the Phase 7.7 seal.
- **UPDATE 2026-07-16 (later same day) — DELETION RATIFIED (F-D4 round 4, §15).** The premise
  audit (F-D4 §2.1/§15, F-W7) found the correlated observable `T` — the "principal-side
  re-appearance" every channel above quantifies over — has **no population within this seam**:
  the refund leaves as hidden outputs inside the posting tx itself (structural,
  `bond_connect.rs`); rotation is dead by S-5/T-A1 + in-place `HoldingsUpdate` (policy +
  economics); network is spent as §10.9 conditioning; the off-chain crossing is §18.13's seam.
  Disposition ratified: **delete the mechanism, keep the tripwire** (reopen criteria at F-D4
  §15.4 — rotation in scope, refund moved out of the posting tx, new public principal-keyed
  term, isolation weakened). The mechanism-deletion PR's reviewer-map is F-D4 §15.4 item 1;
  the cooldown and the F-D6 anchor derivation are out of scope (they predate this analysis and
  stand on slashability/anti-drift reasons). The seal entry is removed from
  `RELEASE_CHECKLIST.md`; nothing was ever shipped — the F-W3 sentinel held the system frozen
  in the correct state by construction (F-D4 §15.7).
- **UPDATE 2026-07-17 — DELETED (the decision-5 PR landed).** Everything the BUILT update
  above describes is removed at the §12.9 decision-5 scope: `exit.rs` wholesale, both
  features with every consumer acknowledgment line, the conformance exit arms, and the
  golden-vector/seal-tripwire tests (inventory at F-D4 §15.4 item 1's landing update). The
  F-D6 anchor and `release_cooldown_elapsed` stand, out of scope. This section is archival
  from here. *(Post-landing follow-up, same day: the anchor's out-of-scope status did not
  survive the landing — the deletion removed its only production consumer, and it was deleted
  by its own decision per rule 15; §12.7 and §12.9 decision 5's landing update carry the
  disposition. `release_cooldown_elapsed` stands.)*

### 12.6 F-D4 — a-priori exit window (activation FIRED with F-D3, 2026-07-15)

The exit window **cannot borrow the entry `600`**. That number was derived rate-driven against the
**background funding-spend rate**; the exit seam's driving rate is the **correlated-unbond /
market-event rate** (§18.1), which is worse and different. A **separate a-priori window derivation**
from a stated adversary-advantage claim is required, **committed before any exit sweep runs**
(GF7_HOOKS §5.1: threshold before grading; a failed sweep is a redesign signal, never a move-the-bar).
The exit draw is one-sided (600-block search width, not the entry's 1200), so the thin-regime
**gap-toward-max** bias matters more (§10.12). This is the exit-seam analogue of the entry `1.86` and
the sealing-path measurement WI-4 §18.1 flags as owed. **Couples to L17:** the correlated-unbond model
is exactly the L17 synchronized-exit wargame (does `RELEASE_COOLDOWN = 2` **smear** the cohort or
merely **delay** it; is a release-cooldown *queue* needed — [`FOLLOWUPS.md`](../FOLLOWUPS.md)
swan-2/W8), so F-D4's rate model and the L17 wargame are one obligation. **Activation:** the F-D3 FSM
gate — **FIRED 2026-07-15** (§12.5). The window derivation is the build sequence's first artifact,
committed **before** any exit sweep runs and before `draw_exit_gap` code lands (GF7_HOOKS §5.1:
threshold before grading; a failed sweep is a decorrelation-redesign signal, never a move-the-bar
signal). **The derivation is committed:**
[`ARCHIVAL_EXIT_STANDOFF_FD4_WINDOW.md`](ARCHIVAL_EXIT_STANDOFF_FD4_WINDOW.md) (2026-07-15) —
anchor formula from named consts (§1.1), two-regime split (steady-state X-1 lower bound vs
crisis-cohort X-2 upper bound), the anchor-quantization lemma (a-priori: the cooldown delays and
*quantizes*, does not smear), the §5.3 predicate making the W8 question decidable,
pre-registered sweep arms. **Rate-model review rounds 1–2 run 2026-07-15** (derivation doc
§10–§11): F-W1/F-W2 (round 1) — the draft `2 × SEB` candidate failed its own X-1 planning
bound while §5.4 said "clears"; `σ_L` reclassified as a design lever, the §5.3 predicate a
joint constraint over `(W, σ_L)` with the wallet-discipline lever costed against the
release-queue. F-W3/F-W4/F-W5 (round 2, superseding round 1's re-picked candidate) — the X-1
bound is a **~19× planning box**, so no pre-measurement value is derivable;
`DEFAULT_EXIT_GAP_WINDOW` adopts the **`K_COVER` provisional-sentinel pattern** (M1 §9.3:
sentinel `0`, compile-time refusal absent explicit acknowledgment) with the **decision rule frozen**
(smallest `SEB` multiple ≥ `max(` X-1 bound at the committed 10th percentile of the joint
`(N_P, c)` stressnet read with exit-derived `N_t` per F-W5, `2 × SEB` `)`) and the value
**sealed by the Phase 7.7 stressnet rate read** (`RELEASE_CHECKLIST.md` entry beside
`K_COVER`/PF-9). F-W5 resolved 2026-07-16 (derivation doc §13): **exit-seam `N_t = 10`** —
equal to the entry anchor by derivation, not inheritance (every seam-variant fact lands on
`W`, a graded arm, or its own regime row; the repetition asymmetry — the binding observed
repeatedly, keyed to the public `P_id` — cannot be priced into a per-event anchor and routes
to the `σ_L` discipline and the S-2 exposure ledger as a named residual; routing since
corrected by **F-W9**, F-D4 §16 — `m` is a bounded lifecycle count, the `σ_L` half is dead,
the S-2 half survives narrowed). F-W6 (round 3) — the `2 × SEB` structural argument made precise as **X-3**,
a rate-independent anchor-merge lower bound derived from the quantization lemma (cohort
windows overlap iff `W > SEB`; at `1 × SEB` the adversary partitions the crisis cohort by
exit height, invisible to X-1), folded into the rule with its cost stated: the queue
predicate's LHS acquires a hard `20_000` floor, making the F-W2 lever-vs-queue costing
load-bearing in every measured world. Mixes-at-all, never "merged" (`50 %` mixed fraction at
the cliff). Lemma, X-1 shape, X-2 form, and the one-window pin survived all rounds.
**`draw_exit_gap` is unblocked, written against the sentinel** — compiles for testnet under
explicit arming, refuses to ship unsealed. **UPDATE 2026-07-16 — round 4 (F-D4 §15) closed
the derivation's subject: F-W7 found the observable unpopulated (no principal-side event
exists on the chain as designed), F-W8 retracted X-3's harm model (cohort membership is
`last_served_epoch`, already public). Deletion-with-tripwire ratified; the §5.4 rule, the
§13 `N_t`, and the §14 sweep numbers survive as the archived re-run template for the F-D4
§15.4 tripwire. No value is sealed; the checklist entry is removed.**

### 12.7 F-D5 (disposition round — RAN 2026-07-17, no grid at genesis) and F-D6 (anti-drift pin)

- **F-D5 — reward-magnitude quantization: disposition round chartered and RUN here (2026-07-17)
  — width does not derive, NO GRID at genesis; see the OUTCOME below.** The entry's original
  routing — ~~→ §14.4 economics, not this round~~ — was a summary-minted referent (the dated
  UPDATE below is the finding), and its original reopen clause — ~~graded in the GF-4/§14.4
  economics round~~ — is superseded by the charter's rule-21 clause (post-genesis reopening
  requires a hard fork per [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc) + an S-2 ledger row showing the band exploited in
  practice). What the original bullet got right stands unrevised: Layer-2 CT-severing breaks the
  off-chain sequence surface first (§18.10/§18.11), so the grid's threat model is the
  **lifetime-aggregate band only** — a consensus economics change (grid width interacts with
  dust/budget conservation) and a **defense-in-depth candidate**, not R4's structural work.

  **UPDATE 2026-07-17 — the "§14.4" routing target was dangling; re-pointed to a named F-D5
  disposition round (this entry is its charter).** The finding first: **"→ §14.4 economics" named
  no real round.** WI-4's §14.4 is the partition-adversary arm — a mechanism measurement spec,
  implemented, graded PARTITION-PASS, and RATIFIED via PR #291 on 2026-07-11; it never carried a
  quantization or economics agenda and it is closed. The provenance is a **summary-layer
  conflation of two distinct WI-4 routings**: WI-4 §18's scope pin routed *strata + lifetime* to
  the §14.4 round — real, and **discharged** (those riders landed with the partition arm, PR
  #291) — while WI-4 routed *quantization* to "a GF-4-round design candidate" (§18.10 R-3, grid
  width a-priori derived). The fusion "GF-4/§14.4 economics" first appears in the index's WI-4
  row summary and this doc's §11.7/§12 prose, and propagated into R4's close condition as though
  it named a real round. Close condition (iv) as ratified was undischargeable. Note the shape:
  **not a dangling pointer at source — WI-4 never wrote it** — but a referent minted at the
  summary layer by joining two true routings into a false one, which then read as authoritative
  because both halves check out if grepped separately. Distinct from method note 5's five
  instances (no inherited pin, no phantom observable); recorded as **§11.8 method note 6**:
  summary-cited routing targets verify against the source document's own words, and a summary
  that joins two source claims is a new claim.

  **F-D5 survives the substance filters that killed the rest of this track.** Its observer is the
  off-chain counterparty who receives a drain payment (real, not phantom — F-W7's failure mode
  does not apply); its observable is the received amount matched against `reward_P(E)`, which is
  publicly derivable ex ante from public state (verified at source in the WI-4 §18.10 round); and
  the leak does not route through a spend graph, so the method-note-5 FCMP++ re-walk does not
  dissolve it. The rare premise on this track that holds.

  **Refused: a fresh economics/measurement round (the "(b)" option).** Its central number — the
  grid's privacy benefit — is a behavioral quantity a testnet cannot produce in principle (method
  note 3). Building that round is `DEFAULT_EXIT_GAP_WINDOW` with a new name: build the harness,
  discover at the stressnet that the read measures the load generator. §14.4 being dead is not
  the problem with (b); (b)'s replacement would be dead on arrival.

  **Adopted: the band routes to R5's S-2 ledger, and the F-D5 disposition round opens here, under
  three pre-conditions:**

  1. **The genesis-frozen consequence is named, not implied.** The grid is a consensus economics
     change (width interacts with dust + budget conservation), therefore genesis-frozen; S-2's
     exposure read is post-genesis. So "graded at R5 against a measured exposure" resolves to
     **the grid does not ship at genesis and becomes a hard fork if ever wanted** — method note
     3's third exit, which for a genesis-frozen constant means *don't ship*. Legitimate as a
     decision; not legitimate as an implication. The pre-genesis discount cuts against deferral
     (right now the grid is free; after genesis it's a fork) — whoever ratifies the deferral is
     spending that window, not deferring the bill.
  2. **Pass-4 is reconciled first, or this is the fossil shape one class over.** The pass-4
     organizing principle (§10.12, landed 2026-06-13) graded reward-magnitude banding "*doubly*
     misdirected" and trilemma-costly. F-D5 targets a different linkage (the off-chain
     lifetime-aggregate band at the §18.13 crossing, not `P`↔its-own-rewards) — but the **cost
     argument transfers intact**: the grid distorts the contribution→reward map regardless of
     which linkage it's bought for. A dispositioned mitigation re-entering a later round without
     citing its rejection is exactly what method note 5 was written for. The round opens by
     quoting pass-4 and stating what's different, or it repeats it.
  3. **The structural derivation is attempted before "unmeasurable" is accepted** (method note
     3's first honest exit). Because `reward_P(E)` is publicly derivable ex ante, the band's
     shape is a **property of the reward curve, not of behavior**. If the grid's width can be
     derived from the curve's own structure the way X-3 derived from anchor geometry —
     rate-independent, no testnet, mechanism-class — the grid is decidable today, at the free
     end of the window. X-3 is the precedent: the structural derivation was the right instinct
     even when its harm model turned out empty. **The round's first act is this attempt, not the
     S-2 hand-off.** Width derives ⇒ the grid ships at genesis and S-2 grades the residual.
     Width doesn't derive ⇒ no grid ships, recorded plainly as a pre-genesis window spent on a
     mitigation whose benefit couldn't be established — which, given pass-4 already rejected it
     on cost, is probably the right answer anyway.

  **Reopen (rule-21, superseding the entry's original clause):** the disposition round's outcome
  (grid ships / no grid) is recorded here; post-genesis reopening requires a hard fork reviewed
  per [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc) and an S-2 ledger row showing the band is exploited in practice.

  **OUTCOME 2026-07-17 — the structural attempt ran and failed at source: width does not
  derive; NO GRID ships at genesis.** The round executed in the ratified order — harm first,
  width second — and the two halves resolved oppositely, which is the X-3 lesson applied in
  the right order this time (X-3 was correct geometry over an empty harm; F-D5 is a real harm
  over an underivable width).

  **Act 1 — the harm survives F-D1, in one sentence:** *the grid protects the
  lifetime-aggregate (drain-all) band — §18.12's floor, which F-D1's coverage boundary names
  as untouched ("drain-all reveals the lifetime total, irreducible") — not the subsum match
  F-D1 closes.* The sentence writes cleanly; the target is precisely the residual F-D1 leaves
  open by design, at a counterparty that already knows the user (a `P`→user bridge). The round
  proceeded.

  **Act 2 — the derivation attempt, walked bottom-up through the landed pipeline**
  (`reward_arithmetic.rs`, `consensus_state.rs`, `emission_verify.rs`,
  `ARCHIVAL_BUDGET_SCHEDULE.md` §1):

  ```text
  reward_P(E) = floor( budget(E) · Curve(work_P(E)) / Σwork(E) )   // Form C, gate-1 pin
  work_P(E)   = Σ_shards  g(age) / r_market                        // scarcity_milli
  budget(E)   = staker_emission (release-scaled, weight-penalized) + fee share
  ```

  Three independent failure points, each ineliminable:

  1. **There is no population-free lattice anywhere below the `Curve`'s shape constants.**
     `scarcity_milli` divides by `r_market` — the shard's live replication count — so even
     the *work-space* value set is population-valued before the divide. The curve's fixed
     geometry (breakpoints, slopes, plateau) maps work→credited-work with both endpoints
     population-dependent.
  2. **The atomic-value spacing is a quotient of two economics quantities.** Adjacent
     reachable rewards are separated by `budget(E)/Σwork(E)` per credited-work-milli;
     `budget(E)` floats with fees and the release multiplier (`ARCHIVAL_BUDGET_SCHEDULE.md`
     §1 — the fee share is "not recomputable from schedule alone"), and `Σwork(E)` is the
     live cohort's sum. Contrast the X-3 precedent this attempt was shaped on: X-3's bound
     lived entirely in block-height space, where `SEB` and reorg depth are consensus
     constants — no population quotient in the path. Here rate-independence dies at the
     divide.
  3. **Even granting a width, reachable-collision is not delivered cover.** The strongest
     variant considered — a rate-*adaptive* relative grid (quantize `Curve(work_P)` into `K`
     buckets before the divide; consensus-deterministic from public close rows,
     zero-tolerance-compatible, `K` genuinely derivable from the curve alone) — delivers
     "≤ `K` distinct rewards per epoch," but lifetime aggregates collide only for personas
     with identical epoch sets *and* identical bucket trajectories. The epoch set is
     published per claim (`settlement_epochs`, WI-4 §18.7), and every `reward_P(E)` is a
     loud `P`-attributed mint vout (WI-4 §18.11) — the grid can only try to make
     *already-published sums* equal, and whether any two live personas' sums coincide under
     a width is **occupancy of the actual population**: the pre-named failure mode, and the
     GF-7 nominal-vs-effective finding again (the derivable quantity is nominal cover; the
     protective quantity is effective cover).

  **The sharpest form of the failure: the grid's cost side is derivable and its benefit side
  is not.** Cost: dust ≤ Δ−1 atomic per claim (the §4-pinned burn-the-dust interaction) plus
  the contribution→reward distortion pass-4 priced — computable from the curve today.
  Benefit: the delivered anonymity-set enlargement — population occupancy, computable by
  nobody at genesis. A decision inequality with one computable side cannot be optimized
  structurally. The attempt also pinned the distinction that let F-D5's premise pass the
  filters while its width fails: `reward_P(E)` is derivable **by the observer at match time**
  (public close rows — why the observable is real, F-W7 does not apply), but the
  **distribution over its values** is derivable by nobody pre-genesis (why the width is
  economics under method note 3). Observer-real, width-underivable.

  **Precondition discharge.** (1) The genesis-frozen consequence is spent knowingly: no grid
  at genesis; any future grid is a hard fork per the reopen clause above. Stated plainly per
  the charter: the pre-genesis window was spent on a mitigation whose benefit could not be
  established. (2) Pass-4 reconciled: §10.12 (landed 2026-06-13) graded reward-magnitude
  banding "*doubly* misdirected" for the `P`↔its-own-rewards linkage; F-D5 targeted a
  *different* linkage (the §18.13 crossing — which is why it wasn't dismissed on pass-4's
  authority alone), but pass-4's **cost half transfers intact** (the grid distorts the
  conceded contribution→reward map regardless of which linkage it's bought for) — with the
  benefit now shown underivable and the cost standing, no-grid is the answer pass-4's prior
  already predicted. (3) The structural attempt ran first and its failure is *derived*, not
  defaulted: the population term enters at three named, source-anchored points, not "we
  didn't find a derivation."

  **Hand-off:** the lifetime-aggregate (drain-all) band registers as an **R5 S-2 ledger
  row** — per-observer, off-chain, graded against measured post-genesis exposure; F-D2's
  aggregate-drain default remains the wallet-layer mitigation of the drain-all mistake
  class. R4 close condition (iv) is **discharged** (§12.9 amendment); R4 remains open on
  F-D1 + F-D2 only.
- **F-D6 — single-source + derive (anti-drift). Named-const half STANDS; anchor helper
  DELETED 2026-07-17 (rule 15).** UPDATE 2026-07-15: the FSM
  landed and the named const half is **done** — `RELEASE_COOLDOWN_EPOCHS` is config-generated
  (`config/consensus_constants.json` `release_cooldown_epochs: 2` → `shekyl-archival-retention`
  `build.rs` → `bond_floor`), consumed by `release_cooldown.rs`. What remained of F-D6 was the
  consumer-side derivation: `draw_exit_gap`'s anchor **derives
  `RELEASE_COOLDOWN_EPOCHS × SETTLEMENT_EPOCH_BLOCKS`** from those named consts, never a hardcoded
  `20_000` — the anti-drift rule `consensus_state.rs` already enforces for `SEB` ("do not re-derive
  by hand and risk drift"). UPDATE 2026-07-16: that half landed with F-D3 —
  `release_cooldown_anchor_height` (`release_cooldown.rs`) is the derivation's single home,
  boundary-tested against `release_cooldown_elapsed` (the two cannot disagree at `H_cd`), and the
  `20_000` doc-comment integer in staking-sim `standoff.rs` — the named drift vector — is purged,
  pointing at the derivation instead. UPDATE 2026-07-17: **the anchor helper is deleted.**
  Decision 5 executing orphaned it — `draw_exit_gap` was its only production consumer, and
  post-deletion every call site was a test, a re-export, or a doc-comment: the armed-primitive-
  with-no-trigger pattern this track opened on. The drift vector F-D6 was minted against is also
  gone (the `standoff.rs` fossil was the fossil; post-purge the sim comment pointed at the anchor,
  so the anchor survived only to be citable). Deleted per rule 15 rather than kept as speculative
  generality; the maintainer declined the keep-and-document branch — a future caller needing an
  earliest-spend height re-derives from the named consts at its own site and boundary-tests
  against `release_cooldown_elapsed` (reopen note at `release_cooldown.rs`; git history is the
  reference). What F-D6 permanently delivered stands: the config-generated constant and the
  derive-don't-hardcode rule, now enforced by the absence of any restated integer.

### 12.8 Round 4 status, joint-grading obligation, and what closes it

- **GF-7 (funding-in):** built + graded **PROVISIONAL-PASS** (`r = 1.86`, local-daemon; §6 R4 cell) —
  not an open design question; its residuals (effective-vs-nominal cover, cold-start) are testnet
  obligations already tracked ([`FOLLOWUPS.md`](../FOLLOWUPS.md) funding-seam carries).
  **Reclassified (method note 3, 2026-07-16): the effective-cover *level* is a standing
  conditional, not a testnet obligation.** The testnet grades the residual's observer
  *machinery* (does the observe-and-inject adversary's decoy injection get discounted; does
  the S-3 correlator behave) — a mechanism measurement, which stays on the testnet list.
  The effective cover **level** is driven by the post-isolation network-event rate (§11's
  own (ii)), an economics number a testnet cannot produce; a cover-level read would measure
  the load generator. "Open" would imply it closes when someone does the work — it cannot
  close pre-genesis, so it is filed as the **fifth member of the WI-4 §13.5 conditional
  register** (unfalsifiable pre-genesis, carried as a stated assumption with a
  post-genesis monitoring plan). Verified at source: the `1.86` was computed on
  **nominal** cover (`gf7_timeline.rs` seeds `N = TARGET_ANON_SET = 10` at full honest
  strength; §11 (iv) already names the measured set an upper bound), so the conditional is
  load-bearing — effective cover below nominal moves realized per-event exposure
  `P(link)` up (the sweep below shows `r` itself is cover-blind, so the harm never
  registers gate-side), and per WI-4's no-cross-subsidy pin it cannot borrow the gate's
  margin.
  **Kind sharpened + sensitivity sweep run (2026-07-16, later same day; reading corrected
  same day, per review).** Two amendments to the filing above, recorded at WI-4 §13.5 in
  full. (1) *Kind:* "the isolation-conditioning kind" got the permanence right and the
  shape wrong — isolation conditions a **channel** (fails ⇒ a new channel opens,
  qualitative change); effective cover conditions **the number itself** (`1.86` was
  computed at nominal cover, an upper bound). The honest characterization is **stacked
  marginals of opposite sign**: pessimistic adversary (the stress arm is an oracle-union
  panel, stronger than S-3) against optimistic cover (nominal) — F-W4's hygiene applied
  on this side. Scope narrowing: thin-cover-as-regime is already L12 with a design-away
  disposition (M1 reward-gate refuses the regime), so what this conditional carries is
  effective-vs-nominal **at steady state**. (2) *Sweep:* `shekyl-staking-sim
  --gf7-breakeven` (mechanism-class under method note 3: a property of the model, no
  economics input) sweeps `r(N)` at the gate posture, `N ∈ [2, 16]`. Finding: worst-arm
  `r` clears the bound at every row (≈1.46–1.83) and never trends toward the bar as
  cover thins — **`r < 2` is structurally blind to cover**. The ratio renormalizes by
  the degraded baseline, so thin-cover harm cannot move it (at `N = 2` the worst arm
  links 72.9% and still "clears"); the hit probability and the `1/N` baseline shrink
  together. Consequences: the filing's "no lower bound on the truth" framing is
  retracted as to `r` (the true `r` does not degrade as cover thins);
  **cover was never gated** — the ~7% margin is margin on the mechanism's fixed relative
  leak, never margin against cover, which is what made this section's own misfiling
  possible; and **no per-event monitoring threshold exists to derive** — the candidate
  `P(link) ≤ 0.2` is the ratio bar evaluated at nominal cover (back-derived; under flat
  `r` the parity point sits at `N ≈ nominal · r/bound` *by identity*, the run's parity
  row landing at `P = 0.199`/`N = 9` vs `0.179`/`N = 10`), and pinning it as an absolute bar would
  commit a bound backwards from the number it must certify — refused. Per-event
  `P(link)` also does not bound the aspiration's quantity — the aspiration is per-observer
  whole-life exposure whose live channel is the off-chain counterparty crossing, outside
  any on-chain per-event number's reach (citation corrected 2026-07-16: originally
  "intersection collapses geometrically, F-D4 §13.3/F-W5"; F-W9 — F-D4 §16 — bounded `m`
  to a lifecycle count, so the collapse does not occur on-chain; conclusion unchanged on
  the narrower ground): the conditional's
  instrument is the **S-2 lifetime exposure ledger**, not any per-event number.
  Explicitly rejected as a reading of the measurement: "only a state actor sees
  post-isolation timing, and they have KYC anyway" — a scope decision that could be made
  and recorded, but not made here, and never to be used to make `1.86` comfortable (KYC
  yields principal→user; GF-7 protects `P`→principal; both broken yields `P`→user).
- **GF-4 (value-out):** this section. F-D1 + F-D2 buildable now; F-D3 + F-D4 **gate FIRED
  2026-07-15 — open for build** (§12.5, `bond_post.rs:369`/`:627`); output-count
  discipline lineage-blind (an F-D1-sibling). UPDATE 2026-07-16: F-D3 **BUILT** against the
  F-D4 sentinel (§12.5) and F-W5 resolved (F-D4 §13: `N_t = 10` derived); the timing channel
  enters the joint grade via the X-1/X-2 sweep, which is now unblocked. UPDATE 2026-07-16
  (same day): the **§8 sweep instrument was built and run** (`shekyl-staking-sim --exit-standoff`,
  `exit_standoff.rs`) — X-1 N-sweep + X-2 cohort/anchor/`σ_L` grid + X-3 coverage-boundary
  grade + §8.3 negative control + thin-regime arm, all against the committed `r < 2`, worst
  row reported. Pre-seal structural findings recorded at F-D4 §14: delivered X-1 cover is
  latency-gated (`ρ_x · σ_L`, not `ρ_x · W`) and the §5.3 lever is priced by the exact
  observer inversion (`required_sigma_l`), so the Phase 7.7 read seals both `W` (frozen
  rule) and the lever-vs-queue decision through the same instrument. The timing channel's
  joint-grade input exists; **what remains for R4 close is the joint grade itself**
  (four axes, correlated-trigger on) plus F-D1/F-D2 arms. UPDATE 2026-07-16 (later same
  day): **superseded by the F-D4 round-4 premise audit** — the timing channel is phantom
  (F-W7: no principal-side observable exists within the seam; F-D4 §2.1/§15).
  F-D3/F-D4 deletion-with-tripwire **ratified**; the sweep's numbers are archived as the
  tripwire's re-run template, and the hand-forward below is what R4 now owes.
- **HAND-FORWARD from F-D4 §15.5 (received 2026-07-16, audit attached) — is GF-4's exit seam
  in the right gate?** On the F-D4 §2.1 audit, the only live channel is the **off-chain
  counterparty crossing** (T-4) — §18.13's principal↔user seam, posture *widen, not close*,
  instrument the S-2 ledger. F-D1's surviving amount concern (the off-chain subsum match at
  a counterparty — the on-chain amount channel was always closed by construction) lands at
  the same crossing. If both halves of GF-4's exit seam reduce to it, GF-4 is substantially
  a principal↔user finding wearing a `P`↔principal label — **re-homed, not re-scoped**. The
  consequence R4 must decide structurally: the four-axis joint grade **loses its on-chain
  timing axis**, and with a phantom timing input the joint grade is not "run with one fewer
  term" — it is a different grade over a different seam with a different posture. The
  `--exit-standoff` harness's deletion is sequenced behind this answer (F-D4 §15.4 item 1):
  if re-homed, it re-parameterizes on the crossing observer; if not, it is deleted (a
  harness grading a phantom channel is a trigger with no gate — it will produce a report,
  and reports get believed). **Landing disposition (2026-07-16): the harness never landed
  on `dev`** — the round-4 record shipped docs-only, and the instrument is preserved at
  `archive/feat/fd4-exit-sweep-2026-07-16`; "deleted" reduces to "not resurrected." The
  mechanism (`exit.rs`, PR #313) *did* land and its deletion PR is real work (reviewer-map
  F-D4 §15.4 item 1). **UPDATE 2026-07-16 (F-W9 rides this hand-forward — F-D4 §16):**
  §13.3's repetition premise is corrected before R4 takes the question: `m` is a bounded
  lifecycle count (one mandatory observable crossing — `JoinMarket`, GF-7's seam; two
  wallet-default-closeable optional classes — `HoldingsUpdate`-add and credit-bearing
  `Rebond`; zero observable exits on either branch), so the on-chain composition a
  re-homed grade would inherit is **finite and GF-7-shaped**, not an open-ended
  intersection — at the mandatory `m = 1`, GF-7's per-event grade *is* the on-chain
  lifetime grade per persona per observer class, at nominal cover. Cross-persona
  intersection was raised and withdrawn (no linking key exists across `P_id`s — F-D4
  §16.3); the surviving composition surfaces are the T-4 counterparty ledger (its own
  books are the key; subsumes that observer's cross-persona view) and shared-trigger
  funding clusters (the entry standoff's existing graded case). R4 also receives the
  §16.4 proposal: aim the GF-4b lineage filter at the optional-crossing funding paths —
  an honest-wallet default, not a consensus invariant, with its growth-gating cost
  (portfolio expansion gated on accumulated rewards ≥ FLOOR) stated up front.
- **Joint grade (the round's exit bar, per §18.10 R-4 + CB-3):** the drain event is graded on
  **{amount-band ∧ claim/exit-timing ∧ holdings-stratum ∧ output-count}** jointly, correlated-trigger
  modeled on — never per-axis-multiplied. GF-10's claim-jitter mechanism (§11) folds in here; **R3
  closes when it does.** UPDATE 2026-07-16: the axis set is under the hand-forward above —
  the exit-timing axis is phantom per F-W7, and whether the grade re-forms as three-axis
  on-chain + S-2-ledger crossing or re-homes wholesale is the R4 structural decision that
  now precedes running it. UPDATE 2026-07-16 (night — §12.9, at ratification): **decided —
  the grade dissolves by four-axis attrition** (exit-timing phantom F-W7; amount
  structural-armed; holdings public; output-count phantom F-W10); GF-10 grades standalone
  and the correlated-trigger obligation relocates to the crossing as an S-2 row.
- **Pre-seal blocker — DISCHARGED 2026-07-15:** the rebond/unbond FSM (genesis-scoped, 2026-06-15)
  gated F-D3/F-D4 activation *and* the age-stratified sim bond-mobility reconciliation (§6 scope
  note). Both halves are done: the FSM frictions were pinned
  ([`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) P2B-7, all pins closed — Pin-4/Pin-5 at
  PR #303 2026-07-14) and landed as enforced consensus (`HoldingsUpdate`/`Unbond` #303, `Rebond`
  #307), and the sim reconciliation is DONE, seal cleared (`STAKER_ARCHIVAL_SIM.md` §L18). The exit
  seam is measurable.
- **Closes when:** F-D1/F-D2 land with their arms; F-D5 is dispositioned in §14.4; and the
  §15.5 hand-forward is answered (seam re-homing + the joint grade's axis set). UPDATE
  2026-07-16: the F-D3/F-D4 clause is discharged by deletion, not by grading — the a-priori
  window was derived, audited through four rounds, and its premise found empty (F-D4 §15);
  what replaces "pass the joint grade on the timing axis" is the hand-forward decision
  above. Until then R4 is **drafted, not closed**. UPDATE 2026-07-16 (evening): the
  hand-forward is **answered — §12.9**; the close condition re-forms per §12.9's decision 5.
  UPDATE 2026-07-17: the F-D5 clause's "§14.4" was **dangling** — re-worded by the §12.9
  dated amendment (disposition round chartered at §12.7; structural attempt first, band to
  the R5 S-2 ledger either way). UPDATE 2026-07-17 (same day): the F-D5 clause is
  **discharged** — the attempt ran, width does not derive, **no grid at genesis** (§12.7
  OUTCOME); what remains of the close is F-D1 + F-D2.

### 12.9 R4 decision round (2026-07-16) — the §15.5 answer: the seam re-homes, the joint grade dissolves

**Status: RATIFIED 2026-07-16 (night), at review-at-source.** Decisions 1, 4, and 5
ratified as drafted. Decisions 2–3 (the dissolution pair) were **rejected as drafted and
ratified as amended**: the draft's axis walk covered three of §12.8's four named axes and
disposed the fourth — output-count — in half a sentence, in the wrong direction ("an
F-D1-sibling structural arm": F-D1's carve governs the *inputs* the amount computation
may read; output-count shapes the *outputs* the drain creates — different pin, different
arm, no coverage). Ratification supplied the missing disposition: **output-count is the
fourth attrition row, phantom on the same grounds as `T` (F-W10, below)** — and the
dissolution stands strengthened, decision 3's discharge argument inheriting the fourth
row (still nothing left to multiply, now with all four axes walked). The review
also named the failure shape for the record: an axis silently absent from an
axis-by-axis walk that concludes "one live axis" is the same fossil pattern as the
exponent nobody counted (F-W9) and the observable nobody named (F-W7) — the unexamined
term is where the finding lives. The inputs — the F-D4 §2.1/§15 audit and the F-W9
premise correction (F-D4 §16) — were already ratified. Four decisions plus the amended
second, and a re-formed close condition; the downstream sweeps landed with the draft and
were re-swept by the ratification edit (sites enumerated in the revision-history entry).

**Decision 1 — the exit seam re-homes to the principal↔user crossing (WI-4 §18.13).**
The hand-forward's own test: do both halves of GF-4's exit seam reduce to the off-chain
crossing? Walked with F-W9 in hand:

- *Timing half.* The on-chain `P`↔principal exit-timing channel does not exist — F-W7
  found the principal-side observable phantom, and the F-W9 enumeration counts **zero
  observable exits on either branch** (voluntary refund CT-hidden in-tx; terminal slash
  emits no transaction). What the chain shows is the `P`-side `Unbond` post — a public,
  `P`-attributed *event with no principal-side counterpart to correlate against*. Exit
  timing's only live harm surface is a counterparty's own books (deposit arrival vs the
  public unbond/claim record) — T-4, §18.13's seam.
- *Amount half.* Closed on-chain by construction (CT at first spend — WI-4 §18.11; the
  refund is the in-tx `bond_debit` source term). F-D1's forbidden read — the reward-subsum
  match — realizes **only at a counterparty**, and WI-4 §18.13 already files drain subsums
  as **boundary class 3 of the principal↔user seam**, "closed by safe-by-default coverage,
  template: the §18.12 input-level pin." F-D1/F-D2 *are* that closure.

Both halves reduce. **GF-4's exit seam is a principal↔user finding; posture *widen, not
close*; instrument the S-2 per-observer ledger.** F-D1/F-D2 remain GF-4's buildable
content, correctly re-labeled as the class-3 mistake-set closure they always were —
nothing about their build or arms changes. The corollary is worth stating plainly: **after
this round, the on-chain `P`↔principal surface is the entry seam alone (GF-7)** — one
seam, already measured (`r = 1.86` at nominal cover, five standing conditionals), and per
F-W9's mandatory `m = 1`, its per-event grade is the on-chain lifetime grade.

**Decision 2 (as amended at ratification) — the four-axis joint grade dissolves; no
grade re-forms in its place.** Axis by axis, all four of §12.8's named axes:
**exit-timing** — phantom, deleted (F-D4 §15.4). **Amount-band** — closed by
construction on-chain; the off-chain match is closed by F-D1/F-D2's *structural arms*
(import-check, signature check, UI default — pass/fail CI facts, not graded rates).
**Holdings-stratum** — public by design (T-A1: the portfolio is `P`'s public identity); a
posture fact, not a leak to grade. **Output-count — phantom (F-W10, the fourth attrition
row, added at ratification): the drain is not an identifiable transaction, so its output
count is not an observable.** The §2.4 pin exists so reward receipts and principal
returns "do not create spend-graph links between `P` and principal" — but **FCMP++ has
no spend graph**. The spend set is unenumerable (§12.1, WI-4 §18.11): an output cannot be
followed to its spend, and reward-output spends carry no `P`-typing on the wire (F-D4
§16.1 table; §10 tx-type table). There is no way to say "this transaction is `P`'s
drain" — it is an ordinary hidden spend, indistinguishable from every other transaction
on the chain — and you cannot count the outputs of a transaction you cannot identify.
The provenance line is the giveaway: "Genesis pin (carry from PHASE_2B §2.4)" — the
lump-sweep attack is real and well-documented in the CryptoNote/ring-signature lineage,
where the spend graph is *partially visible* (ring members, key images, traceable output
clusters); the pin was carried forward across the crypto change to FCMP++'s full-chain
membership proofs and never re-walked against them. Under FCMP++ the attack has no
substrate, and §2.4's own goal statement admits the bar: "beyond what a disciplined user
already avoids on ordinary transfers" — on ordinary FCMP++ transfers there are no
spend-graph links to avoid; **the goal is met by construction.** (The one countable
thing nearby is the *claim's* output count — the claim is `P`-typed with loud plain
amounts — but that is `P`-side only, and `reward_P(E)` is already publicly derivable, so
it links `P` to information the chain already publishes; no principal is reachable from
it either.)

With all four axes attrited, the dissolution needs no residual carrier: a joint grade
needs a seam with an observer and a rate; the re-homed seam's observer is off-chain and
its instrument is a **ledger**. Running a rate model over counterparty arrival mixing
would be an economics measurement a testnet cannot produce (§11.8 method note 3 refuses
it pre-genesis). The correlated-trigger obligation (§18.10 R-4 + CB-3) does not dissolve
with it — it **relocates**: on-chain, a mass-unbond cohort is a set of public `P`-side
events with no principal side to link to; at the crossing, cohort-arrival compression is
an S-2 row (the counterparty sees the cohort; its books are the linking key — F-D4
§16.3's surviving surface (b)).

**Decision 3 — the CB-3 joint-grading obligation is discharged by axis attrition;
GF-10's grade un-blocks as a single-axis grade.** CB-3's rule-21 obligation (§11.5)
forbade grading claim timing standalone *because* three graded quantities were co-present
on one persona and per-axis grades multiply as if independent. After this round the
co-axes are no longer graded quantities: exit-timing is deleted (phantom), the amount
axis is closed by structural arms (pass/fail, not a rate), the holdings stratum is a
public posture fact, and output-count is phantom (F-W10 — the drain is not an
identifiable transaction under FCMP++). A "joint" grade over one live axis **is** that
axis's grade — the
per-axis-multiplication error needs a second axis to multiply by. GF-10's numeric width
therefore grades **standalone against its own pre-committed advantage claim** (§11.5 —
no-better-than-epoch-prior alignment), mechanism-class under method note 3 (a property
of the draw and the model, no economics input), with the GF-7 measurement round's
instrument discipline (a-priori bound committed before grading code; §11.5's
redesign-not-move-the-bar clause carries over verbatim). **R3's close condition re-forms
accordingly** (§11.7's defer list pointed at a joint grade that no longer exists): R3
closes when the GF-10 single-axis grade runs and clears the advantage claim.

**Decision 4 — the F-D4 §16.4 proposal is ACCEPTED as an F-D2-class wallet default.**
The honest-wallet builder self-funds `HoldingsUpdate`-add and credit-bearing `Rebond`
from reward-lineage outputs — the GF-4b `BackingSet` machinery already classifies exactly
this. External funding for growth is never silently built: it is an explicit, **loud**
override treated as what it is — a `JoinMarket`-class principal crossing — and routed
through the entry-standoff draw (`draw_entry_gap`), inheriting GF-7's per-event
treatment. Cost accepted with eyes open (F-D4 §16.4 constraint 2): default-path portfolio
growth is gated on accumulated rewards ≥ FLOOR; the young persona that cannot wait uses
the loud override and gets standoff treatment for it. Under this default the honest-path
enumeration is **`m = 1` exactly**, and every deviation is named, loud, and
standoff-treated — F-D2's "default safe, opt-out explicit and loud" pattern applied to
funding lineage. (Consensus-layer enforcement remains rejected per §16.4 constraint 1:
consensus cannot classify FCMP++-hidden funding inputs, and in-circuit lineage is the
opposite of F-D1's strip direction.)

**Decision 5 — the harness is deleted, not re-parameterized; the deletion PR's scope is
pinned here.** §15.4 item 1's fork read "if re-homed, it re-parameterizes on the crossing
observer" — but the crossing observer's instrument is the S-2 ledger, and a rate harness
over counterparty arrivals fails the method-note-3 filter. **Re-homed AND deleted** is
the consistent answer: the fork's re-parameterize branch assumed the re-homed seam would
still want a rate model, and it does not. The harness never landed on `dev`
(`archive/feat/fd4-exit-sweep-2026-07-16` stands; "deleted" = not resurrected). The one
deletion PR at this round's scope removes the landed mechanism:
`shekyl-standoff/src/exit.rs` wholesale — `draw_exit_gap`, `ExitGap`, `ExitGapWindow`,
the `DEFAULT_EXIT_GAP_WINDOW` sentinel, the golden vector + seal tripwire, the
shared-trigger conformance arm — plus its exports and conformance references
(reviewer-map: F-D4 §15.4 item 1). **Out of scope:** `release_cooldown_anchor_height`
(F-D6 — anti-drift/slashability, predates the audit), `release_cooldown_elapsed`
(enforced consensus), everything entry-side. The F-D4 §15.4 tripwire and its archived
re-run template are unchanged. **UPDATE 2026-07-17: LANDED at exactly this scope**
(deletion inventory recorded at F-D4 §15.4 item 1's landing update; both features and
every consumer acknowledgment line went with the mechanism, and the F-D6 anchor's doc
comment was re-anchored on its own grounds). **Follow-up decision (2026-07-17, post-landing):
the out-of-scope call on `release_cooldown_anchor_height` was consumer-relative, and decision
5 executing is what removed the consumer** — post-landing the anchor had no production call
site (tests, a re-export, and a sim doc-comment only). That is a consequence of the deletion,
not a pre-existing exclusion, so it got its own decision rather than inheriting this one: the
anchor is **deleted** (rule 15; §12.7's F-D6 entry carries the disposition and the reopen
note). Decision 5's scope stands as written — this is a consequent deletion, not scope creep.
`release_cooldown_elapsed` remains enforced consensus, untouched.

**The re-formed close condition (supersedes the §12.8 line):** R4 closes when (i) F-D1
lands with both arms, (ii) F-D2 lands with the §12.9-decision-4 funding default folded
in, (iii) the deletion PR lands at decision 5's scope (**satisfied 2026-07-17**), and
(iv) the F-D5 disposition round is recorded (**re-worded and discharged 2026-07-17** — the
original "§14.4 disposition" phrasing was a dangling pointer; see the amendment below and
§12.7's OUTCOME: width does not derive, no grid at genesis). The S-2 build is **R5's opening item**, not an R4 close
condition — but R5 inherits it with F-W9's finite domain and the §16.3 re-formed
cross-persona job (linking-key search, pre-registered as code). GF-7's PROVISIONAL-PASS
and its five standing conditionals are untouched by this round.

**Amendment (2026-07-17) — condition (iv) re-worded; "→ §14.4 economics" was a dangling
pointer.** The round-4 close as ratified pointed F-D5's disposition at a "GF-4/§14.4
economics round" that does not exist: WI-4's §14.4 is the partition-adversary arm
(RATIFIED PR #291, 2026-07-11, closed — no quantization or economics agenda). The pointer
is a summary-layer conflation of two distinct WI-4 routings (strata/lifetime → §14.4
riders, discharged with the arm; quantization → "a GF-4-round design candidate", §18.10
R-3) that propagated through the index's WI-4 row and this doc's §11.7/§12 prose as
though it named something — this amendment is dated rather than silent for exactly that
reason. **Condition (iv) now
reads:** *the F-D5 disposition round (chartered at §12.7's 2026-07-17 UPDATE) has run
its structural-derivation attempt and recorded its outcome — grid ships at genesis, or
no grid, stated plainly — with the lifetime-aggregate band registered as an S-2 ledger
row for R5 either way.* A fresh measurement round was refused (the grid's privacy
benefit is a behavioral quantity a testnet cannot produce — method note 3); the
disposition round opens by reconciling the §10.12 pass-4 banding rejection and naming
the genesis-frozen consequence of any deferral. Conditions (i)–(iii) are unchanged;
decisions 1–5 stand as ratified. **UPDATE 2026-07-17 (same day): condition (iv) is
DISCHARGED** — the structural attempt ran and failed at source (three named population
entry points; §12.7 OUTCOME), so **no grid ships at genesis**; the band is registered as
an R5 S-2 ledger row. R4 remains open on conditions (i) and (ii) only — F-D1 and F-D2.

---

## 13. Related documents

| Doc | Relationship |
|-----|----------------|
| [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) | Parent wallet scope; §2.4 admission shape |
| [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) | Emission timing, batching, `P` id |
| [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) | Public retention timeline |
| [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) | L16 transport; soundness pass step 3 |
| [`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) | Phase 2b `phase2b_gate6_p_registration` |
| [`POST_QUANTUM_CRYPTOGRAPHY.md`](../POST_QUANTUM_CRYPTOGRAPHY.md) | Global hybrid policy; `HybridPublicKey` encoding |

---

## Revision history

- **2026-07-17 (F-D5 disposition round RAN — width does not derive; NO GRID at genesis;
  close condition (iv) discharged):** executed in the ratified order and the halves
  resolved oppositely — the harm survives F-D1 in one sentence (the grid protects §18.12's
  lifetime-aggregate drain-all floor, not the subsum match F-D1 closes; a real `P`→user
  bridge), but the width derivation fails at source at three ineliminable population entry
  points: (1) no population-free lattice exists below the `Curve`'s shape constants
  (`scarcity_milli` divides by `r_market`, the shard's live replication count); (2) the
  atomic-value spacing is `budget(E)/Σwork(E)` — a quotient of two economics quantities
  (fees + release-scaled emission over the live cohort's work; X-3's derivation had no such
  quotient in its path); (3) even a rate-adaptive relative grid (quantize `Curve(work_P)`
  into `K` curve-derivable buckets — the strongest variant, consensus-deterministic and
  zero-tolerance-compatible) delivers reachable-collision, not cover: epoch sets are
  published per claim and every `reward_P(E)` is a loud `P`-attributed mint vout, so
  collisions among *published sums* are population occupancy — nominal-vs-effective cover
  again. Sharpest form: the grid's cost side is derivable today (dust + the pass-4-priced
  distortion), its benefit side is derivable by nobody pre-genesis; an inequality with one
  computable side cannot be optimized structurally. Preconditions discharged: genesis-frozen
  consequence spent knowingly (any future grid is a hard fork); pass-4 reconciled (different
  target linkage, but the cost half transfers intact — no-grid is the answer its prior
  predicted); the attempt's failure is derived, not defaulted. The band registers as the
  first R5 S-2 ledger row. Full record at §12.7 OUTCOME; R4 open on F-D1 + F-D2 only.
- **2026-07-17 (F-D5 re-pointed — the "§14.4 economics" routing target was dangling):**
  close condition (iv) re-worded by dated amendment (§12.9), the disposition round
  chartered at §12.7's UPDATE. The finding: WI-4's §14.4 is the partition-adversary arm
  (RATIFIED PR #291 2026-07-11, closed, no quantization agenda); "→ §14.4 economics" is a
  summary-layer conflation of two distinct WI-4 routings (strata/lifetime → §14.4 riders,
  discharged with the arm; quantization → "a GF-4-round design candidate", WI-4 §18.10
  R-3) that propagated through this doc (§11.7/§12/§12.7/§12.8) and the index as though
  it named something — every propagation site now carries a dated annotation.
  F-D5 itself **survives the substance filters** (observer: the off-chain counterparty;
  observable: received amount vs publicly-derivable `reward_P(E)`; no spend graph in the
  path — method note 5 does not dissolve it). A fresh measurement round was **refused**
  (the grid's privacy benefit is behavioral, testnet-unproducible — method note 3;
  `DEFAULT_EXIT_GAP_WINDOW` with a new name). The chartered round's pre-conditions:
  (1) the genesis-frozen consequence named — deferral to a post-genesis S-2 read means
  no grid at genesis, a hard fork if ever wanted; (2) the §10.12 pass-4 banding rejection
  reconciled explicitly, not re-entered silently; (3) **the structural-derivation attempt
  runs first** (grid width from reward-curve structure, rate-independent, X-3-shaped) —
  width derives ⇒ grid ships at genesis + S-2 grades the residual; width doesn't ⇒ no
  grid, recorded plainly. The lifetime-aggregate band registers as an R5 S-2 ledger row
  either way.
- **2026-07-17 (consequent deletion — F-D6 anchor helper removed, rule 15):** decision 5
  executing orphaned `release_cooldown_anchor_height`: `draw_exit_gap` was its only
  production consumer, and post-landing every call site was a test, the crate re-export, or
  the staking-sim doc-comment — the armed-primitive-with-no-trigger pattern this track
  opened on. The out-of-scope call was consumer-relative, so the orphaning got its own
  decision rather than inheriting the exclusion (maintainer, 2026-07-17): **deleted**, with
  the keep-as-derivation-home branch declined as speculative generality — a future
  earliest-spend-height caller re-derives from the named consts at its own site and
  boundary-tests against `release_cooldown_elapsed`. Removed: the function, its four unit
  tests, the `lib.rs` re-export; the staking-sim `standoff.rs` exit-seam paragraph rewritten
  to cite the consensus predicate and the F-D4 deletion instead of the deleted symbol (and
  to stop describing the exit standoff as a live separate mechanism). F-D6's named-const
  half stands (config-generated `RELEASE_COOLDOWN_EPOCHS`; no restated integer anywhere).
  Statuses swept: §12.5 archival note, §12.7 F-D6 entry, §12.9 decision-5 landing update,
  index row 95, F-D4 §15.4 landing update, CHANGELOG.
- **2026-07-17 (decision-5 mechanism-deletion PR landed):** the F-D4 exit-standoff
  mechanism removed at exactly the §12.9 decision-5 scope — `shekyl-standoff/src/exit.rs`
  wholesale, the `provisional-exit-gap-window` + `exit-window-kat` features with every
  consumer acknowledgment line, the conformance exit arms, and the exit tests; F-D6
  anchor + `release_cooldown_elapsed` untouched (out of scope), the F-D6 anchor's doc
  comment re-anchored on its own anti-drift/slashability grounds. R4's re-formed close
  condition (iii) satisfied (§12.9); §12.5 marked archival; the GF-10 source-read
  parenthetical (§11.5) updated — `shekyl-standoff` exposes `draw_entry_gap` only,
  again verbatim. Inventory at F-D4 §15.4 item 1's landing update.
- **2026-07-16 (night — method note 5 extended: the generative pattern + first
  application; §2.4's other two carries re-walked):** F-W10 was recognized at
  ratification review as the **fifth instance of one failure** — phantom `T` (F-W7),
  the cross-persona k-collapse near-miss (F-D4 §16.3), X-3's harm model (F-W8), `σ_L`,
  and output-count (F-W10) are each a privacy intuition imported from a
  visible-spend-graph chain into a chain without one; output-count is the cleanest
  specimen because its provenance is written in the document. §11.8 method note 5
  extended with the pattern and applied immediately to the two remaining
  PHASE_2B-§2.4 carries sitting in the same §2.4 paragraph: **rewards→stealth-outputs
  holds, re-anchored** (real mechanism is §2.1 key/scan-boundary independence,
  creation-side; the graph-side justification half is by-construction);
  **Unbond-refund is half-phantom** (the "P-attributed output at public amount"
  phrasing named an output no observer can identify — the refund is ordinary hidden
  vouts against a public `bond_debit` source term, F-D4 T-2's
  structural-unrepresentability — and the "same decorrelated-drain discipline" tail
  retires with F-W10). §2.1's transfer-leg pin scoped: "timing/output still leak" now
  reads entry-leg-only. `PHASE_2B_STAKE_LIFECYCLE.md` §2.4 tx-leg rows and the
  §7 Unbond-refund threat row corrected at source. No new F-W tokens minted — both
  verdicts are dispositions of existing pin prose under an adopted method note, not
  blocking findings.

- **2026-07-16 (night — §12.9 RATIFIED; F-W10 added at ratification; method note 5):**
  Review-at-source ratified decisions 1, 4, 5 as drafted and **rejected the dissolution
  pair (decisions 2–3) as drafted**: the axis walk covered three of §12.8's four named
  axes and mis-disposed the fourth (output-count) as an F-D1-sibling structural arm —
  F-D1's carve governs the amount computation's *inputs*; output-count shapes the drain's
  *outputs*. Different pin, different arm, and silently absent from a walk concluding
  "one live axis" — the same fossil shape as the exponent nobody counted (F-W9) and the
  observable nobody named (F-W7). Ratification supplied the disposition: **F-W10 —
  output-count is phantom.** Under FCMP++ the drain is not an identifiable transaction
  (no spend graph; spend set unenumerable per §12.1/WI-4 §18.11; reward-output spends
  carry no `P`-typing per F-D4 §16.1), so its output count is not an observable; the §2.4
  pin defends a lump-sweep attack real only in the CryptoNote/ring-signature lineage it
  was carried from, and §2.4's own goal ("beyond what a disciplined user already avoids
  on ordinary transfers") is met by construction. The one countable neighbor — the
  claim's own output count, `P`-typed and loud — links `P` only to `reward_P(E)`, already
  publicly derivable. Decision 2 amended in place (fourth attrition row), decision 3's
  enumeration extended, **§11.8 method note 5** adopted (*a pin carried across a
  substrate change re-walks at carry time; "carry from X" is a re-walk trigger, not an
  exemption*). Swept: §2.4 GF-4 status (discipline retired), §12.1 channel table, §12.3
  coverage boundary, §14.4 terminal-lump quick disposition, header + §4 round-table row
  4, §12.8 joint-grade bullet, F-D4 banners, index rows 95/97/98, CHANGELOG; downstream
  consumers of the retired discipline updated in place — `PRINCIPAL_STAKE_LIFECYCLE.md`
  (§1 drain row, §2 `drain()` shape constraint, §3 GF-4 bullet, DQ3 closed without a
  count rule, §7 ordered-gates item 1), `F1_TA3_TA7_LIFETIME_WINDOW.md` §9.3 T-A5
  residual/disposition, `V3_STAKER_ARCHIVAL.md` output-layer bullet,
  `PHASE_2B_STAKE_LIFECYCLE.md` §2.1 carry-over row. With the
  fourth row in, the dissolution stands strengthened and the round is closed as ratified.

- **2026-07-16 (R4 decision round — §12.9: the F-D4 §15.5 hand-forward answered):**
  Four decisions and a re-formed close condition. **(1) The exit seam re-homes** to the
  principal↔user crossing (WI-4 §18.13): the timing half is phantom (F-W7; F-W9 counts
  zero observable exits on either branch), the amount half is closed on-chain by
  construction with the surviving off-chain match already filed as that seam's boundary
  class 3 — F-D1/F-D2 *are* the class-3 closure, re-labeled, build and arms unchanged.
  Corollary recorded: the on-chain `P`↔principal surface is the entry seam alone (GF-7;
  per F-W9's mandatory `m = 1` its per-event grade is the on-chain lifetime grade).
  **(2) The four-axis joint grade dissolves by axis attrition** — exit-timing deleted,
  amount structural-armed (pass/fail), holdings a public posture fact — so CB-3's
  joint-grading obligation is discharged (nothing left to multiply) and **GF-10 grades
  standalone** against its §11.5 pre-committed advantage claim (mechanism-class, method
  note 3); R3's close re-forms to "the single-axis grade runs and clears the claim." The
  correlated-trigger obligation relocates to the crossing as an S-2 row (the
  counterparty's books are the linking key). **(3) The F-D4 §16.4 funding default is
  ACCEPTED as F-D2-class:** self-funding via GF-4b lineage is the honest-wallet default;
  external growth-funding is a loud override treated as a `JoinMarket`-class crossing and
  routed through the entry-standoff draw; the growth-gating cost accepted with eyes open;
  consensus enforcement stays rejected (FCMP++-hidden inputs unclassifiable). **(4) The
  harness is deleted, not re-parameterized** (a rate model over counterparty arrivals
  fails method note 3; never landed, not resurrected) and the mechanism-deletion PR is
  scoped: `shekyl-standoff/src/exit.rs` wholesale + exports/conformance references;
  F-D6's anchor derivation and `release_cooldown_elapsed` out of scope. **Re-formed R4
  close:** F-D1 + F-D2 (incl. the funding default) + the deletion PR + F-D5's §14.4
  disposition; the S-2 build is R5's opening item, inheriting F-W9's finite domain.
  Swept: header + §4 round-table rows 3–4, §11 R3-close pointers, §12.8 close line, F-D4
  §15.4/§15.5/§16.4 ANSWERED banners, WI-4 §18.13 re-homing note, FOLLOWUPS L17-wargame
  closure rider, index rows 95/97/98.

- **2026-07-16 (F-W9 — F-D4 §13.3's repetition premise corrected; method note 4
  adopted):** The exit-track premise audit's last clause re-walked: §13.3 quantified over
  a growing `m` (observation count) that was never counted against the state machine.
  F-D4 §16 counts it: **one** mandatory observable principal↔`P` crossing per bonded life
  (`JoinMarket` — `verify_join_market_bond_post` rejects an existing record), two optional
  wallet-default-closeable crossing classes (`HoldingsUpdate`-add, credit-bearing
  `Rebond`; the common standing-only `Rebond` moves no value by Pin 2), **zero**
  observable exits (voluntary refund CT-hidden in-tx; terminal slash emits no transaction),
  rejoin unmodeled (self-harm class, slot-indexed derivation). The geometric-collapse
  clause and §13.3's `σ_L` routing do not survive; the S-2 routing survives narrowed. A
  near-miss is recorded in the same section (§16.3): cross-persona intersection (`q^k`)
  was raised and withdrawn for want of a linking key — funding sources FCMP++-hidden,
  amounts publicly determined by the wire, timing per-event decorrelated, network
  isolated — clustering over an unknown partition, not intersection; F-W7's shape caught
  at draft. §12.8's hand-forward extended (the re-homed composition is finite and
  GF-7-shaped; the §16.4 GF-4b-filter proposal rides with its growth-gating cost);
  **§11.8 method note 4** adopted (*enumerate the events that compose*); WI-4 §13.5 and
  FOLLOWUPS carry-4 geometric-collapse citations swept to the narrower surviving ground
  (the aspiration's quantity is per-observer and off-chain, not geometrically collapsing
  on-chain). F-W family extended F-W1…F-W8 → F-W9 (index row 97).

- **2026-07-16 (GF-7 fifth conditional: kind sharpened, sensitivity sweep run —
  `--gf7-breakeven`; reading corrected same day, per review):** Follow-through on the
  reclassification below. (1) *Kind corrected:* "the isolation-conditioning kind" got
  permanence right and shape wrong — isolation conditions a channel; effective cover
  conditions **the number itself** (`1.86` was computed at nominal cover, an upper bound;
  honest characterization is stacked marginals of opposite sign — pessimistic adversary
  panel × optimistic cover). Scope narrowed: thin-cover-as-regime is already
  L12/design-away; the conditional carries effective-vs-nominal **at steady state**.
  (2) *Sweep run* (`shekyl-staking-sim --gf7-breakeven`, `gf7_breakeven.rs` —
  mechanism-class under method note 3, a property of the model): worst-arm `r`
  **clears the bound at every row of `N ∈ [2, 16]`, never trending toward the bar as
  cover thins** — **`r < 2` is structurally blind to cover** (hit probability and
  `1/N` baseline shrink together). Cover was therefore **never
  gated**: the ~7% margin is relative-leak margin, not cover margin — the structural
  fact that made this section's misfiling possible. The pre-sweep "true `r` ≥ 1.86,
  unknown" framing is retracted; and **no per-event monitoring threshold was
  discovered** — the candidate `P(link) ≤ 0.2` is the ratio bar evaluated at nominal
  cover, back-derived (under flat `r` the parity point sits at `N ≈ nominal · r/bound`
  *by identity*, the run's parity row at `P = 0.199`/`N = 9` vs `0.179`/`N = 10`); pinning it as an
  absolute bar is refused as commitment-backwards-from-the-number. Per-event `P(link)`
  does not bound the aspiration's quantity in any case (repetition + geometric
  intersection collapse, F-D4 §13.3/F-W5). (3) *Aspiration-vs-gate framing pinned* at
  WI-4 §13.5: the register is the aspiration's ledger — the standing statement of what
  stands between "every gate passed" and "the aspiration holds"; the aspiration's
  instrument is the **S-2 fused exposure ledger** (R5, "build first," unbuilt — its
  permanent deferral is now itself recorded as a finding on the ledger). The
  "state actor has KYC anyway" scope argument is explicitly rejected as a reading of the
  measurement (recorded at WI-4 §13.5). Statuses swept: §12.8 GF-7 cell, §11.8 method
  note 3 (constructive-half demonstration corrected to its honest output), WI-4 §13.5,
  FOLLOWUPS carry 4, CHANGELOG.

- **2026-07-16 (method-note-3 residual sweep; GF-7 effective-cover reclassified to the
  WI-4 §13.5 register):** The §12.8 caveat is upgraded from "stays open on the level" to
  a **standing conditional** — "open" implies dischargeable, and the cover level is
  unfalsifiable before real value is at risk, the same shape as isolation conditioning.
  Verified at source: the `1.86` was computed on **nominal** cover (`gf7_timeline.rs`
  seeds `N = TARGET_ANON_SET = 10` at full honest strength; §11 (iv) names the measured
  set an upper bound), so the conditional is load-bearing against the 7% margin and per
  the no-cross-subsidy pin cannot borrow it. WI-4 §13.5 ledger extended four → five
  conditionals; the seal-time verdict line now carries three permanent clauses
  (isolation, GF-4 promotion, effective cover). FOLLOWUPS funding-seam carry 4 split
  (machinery = testnet obligation; level = register + post-genesis monitoring plan);
  R2's "testnet S-3 obligation" non-claim line re-split. Filter then run across this
  doc's remaining named residuals — one proviso placed (GF-6 dummy-ratio: ambient
  large-v3 must be live-Tor-observed, never replay-synthesized); the rest classify
  cleanly (§11.8 method note 3 records the sweep).

- **2026-07-16 (method note 3 — mechanism-vs-economics measurement filter; GF-7 residual
  caveat):** Second lesson extracted at the F-D4 round-4 ratification, recorded at §11.8
  method note 3 with the full statement at F-D4 §15.8: two of `DEFAULT_EXIT_GAP_WINDOW`'s
  three Phase 7.7 seal inputs (`N_x`, `ρ_x`; `σ_L` was empty outright) were **economics
  measurements a testnet cannot produce in principle** — the read would have sealed a
  genesis constant on an echo of the test plan, and that was true before the phantom-`T`
  finding. Standing posture adopted: classify every stressnet-seal candidate as mechanism
  (testnet-faithful) or economics (requires real value at risk); economics ⇒ derive
  structurally, design the constant away, or don't ship it. Filter run across the PF-9 /
  Phase 7.7 queue: `K_COVER` passes (mechanism, §14.4 partition run); remaining Phase 7.7
  entries are mechanism exercises; caveat placed at §12.8 on GF-7's
  effective-vs-nominal-cover residual (observer machinery testnet-dischargeable, cover
  level not). `RELEASE_CHECKLIST.md` stressnet-entry section gains the queueing rule.

- **2026-07-16 (F-D4 round 4 RATIFIED — premise audit; F-D3/F-D4 deletion-with-tripwire;
  §15.5 hand-forward received):** The F-D4 premise audit (F-W7/F-W8,
  `ARCHIVAL_EXIT_STANDOFF_FD4_WINDOW.md` §2.1/§15) found the correlated observable `T` —
  the "principal-side re-appearance" all three exit-seam channels quantify over —
  **unpopulated within the seam**: structural for the refund (hidden outputs inside the
  posting tx, `bond_connect.rs`), policy + economics for rotation (S-5/T-A1 + in-place
  `HoldingsUpdate`), conditioning for network (§10.9), re-homed for the off-chain crossing
  (§18.13/S-2). F-W8 retracted X-3's harm model (cohort membership already public via
  `last_served_epoch`). **Ratified disposition: delete the mechanism, keep the tripwire**
  (reopen criteria named at F-D4 §15.4; mechanism-deletion PR's reviewer-map is §15.4
  item 1; the `--exit-standoff` harness is sequenced behind the §15.5 answer). The
  `RELEASE_CHECKLIST.md` `DEFAULT_EXIT_GAP_WINDOW` seal entry is removed; the F-W3 sentinel
  held the system frozen correctly throughout — nothing to un-ship (`K_COVER` pattern
  vindicated, F-D4 §15.7). §12.8 receives the **§15.5 hand-forward**: whether GF-4's exit
  seam re-homes to §18.13 wholesale (F-D1's surviving amount concern lands at the same
  crossing), and what the four-axis joint grade becomes without its on-chain timing axis —
  R4's structural decision, now preceding the grade. Method note 2 added beside §11.8:
  *a channel's meaning is its observable* — observer-as-code, pre-registered before any row
  runs, adopted as method posture. Statuses swept: §12.5, §12.6, §12.8 (GF-4 cell,
  joint-grade bullet, closes-when clause); F-D4 doc §2.1/§5.2a/§5.4/§9/§13/§14/§15; index
  rows 95–98; FOLLOWUPS swan-2/W8; `RELEASE_CHECKLIST.md`; CHANGELOG.

- **2026-07-16 (F-D4 §8 sweep instrument built and run; pre-seal findings recorded —
  instrument never landed on `dev`, preserved at `archive/feat/fd4-exit-sweep-2026-07-16`
  per the round-4 landing disposition):** The
  pre-registered X-1/X-2 sweep built and run as `shekyl-staking-sim --exit-standoff`
  (`rust/shekyl-staking-sim/src/exit_standoff.rs`) — all five §8 items to the bar before any
  row ran; `EXIT_TARGET_ANON_SET` minted at this consumer (F-D4 §13.4's concrete carrier);
  the §5.4 frozen rule encoded once as `frozen_rule_window` with the planning-box corners as
  its KAT. Observer pre-registered: support-gated exact Bayes under `L ~ U[0, σ_L]`. Two
  structural findings, recorded at F-D4 §14: **(1)** delivered X-1 cover is latency-gated —
  `ρ_x · σ_L`, W-independent (asserted as a harness test) — so the `σ_L` lever is priced by
  the exact inversion `E[1/(1 + Pois(ρ_x σ_L))] ≤ 2/N_t` (31 425 / 12 413 / 1 613 blocks at
  the sparse/planning/dense corners), not the §5.3 spacing form, which under-delivers at the
  sparse corner and over-pays at the dense one; **(2)** marginal confusability is not
  `r < 2` — the X-2 trough needs support ≈ `N_x/2` (`σ_L` on the `W/2` scale), 71/72 swept
  rows fail and are reported failing per GF7 §5.1 (the pre-committed
  decorrelation-redesign/costing surface, never a bar move). Certified: X-3 mixed fraction
  measured = predicted `(W − SEB)/W` at all three windows (mixes-at-all only); the §8.3
  negative control catches the skipped draw via clustering (and the assignment observer is
  provably blind to it — why the control keys on clustering); thin-regime gap positions
  unbiased. §12.8 GF-4 cell updated: the timing channel's joint-grade input exists; R4 close
  now awaits the joint grade itself plus F-D1/F-D2 arms. Statuses swept: §12.8; index rows
  95/96/98; FD4 §9 step 4 + new §14; CHANGELOG.

- **2026-07-16 (F-W5 resolved — exit-seam `N_t` derived):** The F-D4 §5.4 rule-3 obligation
  discharged a-priori, before the sweep grades
  (`ARCHIVAL_EXIT_STANDOFF_FD4_WINDOW.md` §13): **`N_t(exit) = 10`** — numerically equal to
  the entry posture anchor **by derivation, not inheritance**. Method: the committed bar is
  WI-4's N-invariant ratio bound (`r < 2` per regime row), and `N_t` is only the posture
  anchor the window is sized to deliver; each seam-variant structural fact was examined for
  whether it moves the anchor — cover class (moves `ρ_x`, hence `W`; already spent),
  one-sidedness (moves `W` and a graded §8 arm), the trough cohort (its own X-2 regime row
  per WI-4 regime-splitting; never averaged into steady state) — and none moves the anchor's
  own determinants (protected secret, bar, advantage semantics), which are seam-invariant.
  The one real asymmetry — the binding observed **repeatedly, keyed to the public `P_id`**
  (recurring drops + terminal drain + entry∩exit intersection) — provably cannot be priced
  into a per-event anchor (intersection collapses geometrically; a finite `N_t` cannot hold
  a lifetime floor, and inflating it re-imports F-W3 via the pre-testnet `E[m]`), so it
  routes to the `σ_L` re-appearance discipline (which widens the per-observation candidate
  fraction — the base of the geometric collapse) and the S-2 exposure ledger (R5), as a
  named residual with reversion criteria. Consequences: the §5.4 rule's X-1 term is
  `9/ρ_x`; the §8.1 arm grades at `10` and carries the WI-4 N-sweep form; the exit anchor
  is minted as its own constant (`EXIT_TARGET_ANON_SET`) when the sweep harness lands —
  numerically equal, independently movable. The `N_t = 9 ⇒ 20_000 exact` re-cut trap noted
  at F-W5's minting did not bind: `9` has no model support in the derivation. Statuses
  swept: §12.5 BUILT block, §12.6, §12.8; index F-W row; FD4 doc §5.4/§8.1/§9/§11.
  Docs-only.

- **2026-07-16 (F-D3 built against the sentinel; F-D6 done):** `draw_exit_gap` landed in
  `shekyl-standoff/src/exit.rs` per §12.5 — one-sided through the shared unbiased
  `bounded_uniform` (no order coin), typed `ExitGap`, `ExitGapWindow` capability newtype whose
  `wallet_default()` reads the F-D4 §5.4 provisional sentinel (`DEFAULT_EXIT_GAP_WINDOW = 0`,
  provisional ⇔ 0 const-asserted, compile refusal unless the consumer enables the grep-able
  `provisional-exit-gap-window` acknowledgment feature — deleted at the Phase 7.7 seal).
  Golden vector at a synthetic KAT window (10 007, not an SEB multiple) with a seal tripwire
  that fails at seal time to force the re-freeze; the §12.5 pinned shared-trigger negative
  control landed (`conformance.rs` `exit_release_population`, clustering-detection) beside a
  two-property exit grade (uniformity + serial independence — no order axis; the entry's
  order/inversion axes don't exist here). F-D6's remaining half closed:
  `release_cooldown_anchor_height` (`shekyl-archival-retention`) is the single home for
  `H_cd = (last_served + RELEASE_COOLDOWN_EPOCHS) × SEB` from named consts, boundary-tested
  against `release_cooldown_elapsed` (agree at `H_cd`, disagree one block before); the
  staking-sim `standoff.rs` `20_000` doc fossil purged. Statuses swept: header summary, §6 R4
  cell, §11.3 verified-at-source note (exit draw exists; claim-jitter still absent — pin
  unchanged), §12.1 channel table, §12.5 BUILT block, §12.7 F-D6 DONE, §12.8. Open on the
  F-D4 §9 order: F-W5 exit-seam `N_t` re-derivation, then the X-1/X-2 sweep into the R4 joint
  grade, then the Phase 7.7 seal.

- **2026-07-15 (F-D4 review round 3 — F-W6, X-3 anchor-merge bound):** Round 3 graded round
  2's disposition of the `2 × SEB` structural argument: refusing a preference-shaped
  `max(2 × SEB, …)` floor was correct (F-W1's error through the back door), but parking the
  argument as tiebreak narrative was not — made precise it is a **derived bound**, from the
  anchor-quantization lemma with no rate input: adjacent anchors sit `SEB` apart, cohort
  windows overlap iff `W > SEB` (measure-zero at equality), so at `1 × SEB` the adversary
  reads cohort membership off the exit height — a clean partition of the crisis cohort that
  X-1 (background cover, not cohort integrity) never sees. Minted **X-3**
  (`ARCHIVAL_EXIT_STANDOFF_FD4_WINDOW.md` §5.2a) and folded into the §5.4 rule:
  `W := smallest SEB multiple ≥ max((N_t − 1)/ρ_x, 2 × SEB)`. Carried with it: the coverage
  boundary (2 × SEB *opens* the split — 50 % mixed fraction, continuous improvement, no
  second cliff; the sweep's two-anchor arm grades the actual fraction) and the cost, stated
  beside the benefit: the queue predicate's LHS gains a hard `20_000` floor in every
  measured world, so the F-W2 lever-vs-queue costing no longer evaporates on a dense `ρ_x`
  read. Sentinel, F-W4 percentile, F-W5 `N_t` obligation untouched.

- **2026-07-15 (F-D4 review round 2 — F-W3/F-W4/F-W5, sentinel reshape):** Round 2 reviewed
  the round-1 amendment and found its `3 × SEB` fix repeated the category error: the X-1
  bound spans a ~19× planning box over the doc's own ranges (`N_P ∈ 79–154`, `c ∈ [0.02,
  0.2]`; corners `2_922`–`56_962`), so no pre-measurement value is derivable — any picked
  point can be narrated as "within" something. Resolution (`ARCHIVAL_EXIT_STANDOFF_FD4_WINDOW.md`
  §5.4/§11): `DEFAULT_EXIT_GAP_WINDOW` adopts the `K_COVER` M1 §9.3 provisional-sentinel
  pattern (sentinel `0`, compile-time refusal absent explicit acknowledgment, dev-only arming), the value
  sealed by the Phase 7.7 stressnet rate read (`RELEASE_CHECKLIST.md` entry beside
  `K_COVER`/PF-9 — a wallet default sizing an anonymity set is soft-frozen: post-ship change
  is the §16.1 partition trap as a flag day). Frozen now instead: the decision rule (smallest
  `SEB` multiple ≥ the X-1 bound), the conservatism level (10th percentile of the joint
  `(N_P, c)` read — F-W4 killed the round-1 instance's stacked marginal worst cases), and the
  F-W5 obligation that the exit-seam `N_t` be re-derived a-priori before the seal (the
  entry-inherited `10` is not the exit constant; `N_t = 9` would have made `20_000` exact —
  the re-cut temptation the ordering forecloses). `2 × SEB`'s structural argument survives
  independent of X-1 and may win at the seal on structure plus measurement. §12.6 pointer
  updated; **`draw_exit_gap` unblocked against the sentinel**.

- **2026-07-15 (F-D4 review round 1 — F-W1/F-W2):** The rate-model adversarial review ran
  against the committed derivation (`ARCHIVAL_EXIT_STANDOFF_FD4_WINDOW.md` §10). F-W1
  (blocking): the draft candidate `2 × SEB` failed its own X-1 planning bound and was
  described as clearing it — re-derived to `3 × SEB = 30_000` (33 % margin); §12.6 pointer
  text updated. F-W2 (load-bearing): `σ_L` reclassified as a design lever; the §5.3 predicate
  reframed as a joint constraint over `(W, σ_L)` with the wallet-discipline lever costed
  against the release-queue on the shared capital-idle axis. The anchor-quantization lemma,
  both regime forms, and the one-window pin survived. `draw_exit_gap` remains gated.

- **2026-07-15 (F-D3/F-D4 activation FIRED — fossil sweep):** The §12.5 rule-21 activation
  criterion ("a verify path reads `RELEASE_COOLDOWN_EPOCHS` as a spendability gate") fired at
  source: `release_cooldown_elapsed` is enforced consensus with two verify consumers —
  `bond_post.rs:369` (`HoldingsUpdate`-drop, per-shard last-served anchor) and `:627` (`Unbond`,
  whole-record anchor) — landed with the rebond/unbond FSM (PR #303 `HoldingsUpdate`/`Unbond` +
  the P2B-7 Pin-4/Pin-5 closure, 2026-07-14; PR #307 `Rebond`; #309 ShardSet newtype). Statuses
  swept: header summary, §6 R4 cell + scope-note discharge, §12 status header, §12.1 channel
  table, §12.5/§12.6 headings + gate/activation blocks, §12.7 F-D6 (named const half done —
  config-generated `RELEASE_COOLDOWN_EPOCHS`; consumer-side derivation + the staking-sim
  `standoff.rs:93` `20_000` doc-comment purge remain with the F-D3 build), §12.8 pre-seal blocker
  DISCHARGED. Same sweep: `IMPLEMENTATION_INDEX.md` Round-N row,
  `PHASE_2B_FSM_RETOOL.md` P2B-7 residuals row (the fossil that said "open" against its own exit
  checklist's "closed" — one artifact, two meanings; a closure is not done until every row that
  claimed the gap is swept). New §12.5 pin: `draw_exit_gap`'s per-event independence must be armed
  with its own **shared-trigger negative control** (clustering-detection; the entry
  `double_jitter_trap` guards a two-sided construction the one-sided exit draw doesn't have).
  Build order pinned: F-D4 a-priori window derivation committed **before** any sweep runs or draw
  code lands (GF7_HOOKS §5.1). Docs-only.
- **2026-07-11 (R4 drafted — the drain-event firewall, §12):** Opened Round 4 as §12 (Related
  documents → §13), source-grounded at `dev` `75c3cae1d`. Framed the drain as **one event with three
  co-triggered channels** (amount / timing / output-count) graded **jointly**, not per-axis (§18.10
  R-4 + CB-3). **Source correction (§12.2):** the exit anchor is `RELEASE_COOLDOWN_EPOCHS = 2`, not
  `RETENTION_HORIZON_BLOCKS` (42 epochs) — the latter is data-pruning/sweep-only
  (`ARCHIVAL_TIMING_CONSTANTS`), so the earlier "retention dominates the exit anchor" note is
  withdrawn. **F-D1** (§12.3) — drain-amount taint-carve, complete pre-code pin: **(a)+strip** chosen
  over the capability-token/module-grep forks after source overturned the shared (b) lean (lineage is
  backing-only — `MintLineageOutput` read only by `BackingSet`, `backing_set.rs:143/158`; writer
  `scan_step.rs`; no drain path reads it); **two-part boundary** (strip `{lineage,epoch,height}` +
  amount stage reads the aggregate scalar only, since per-output amounts *are* the reward values);
  three-stage shape; projection is the single trust boundary upstream in the drain orchestrator
  (`claim_orchestrator.rs:9-14` seam); M1-armed import + signature checks. **F-D2** (§12.4) UI-default
  (aggregate-only balance, no reward-derived pre-fill; largely structural by inheritance from F-D1).
  **F-D3/F-D4** (§12.5–12.6) — one-sided (`draw_exit_gap`, no inversion — forced by the cooldown),
  cooldown-expiry-anchored exit standoff + a-priori window that cannot borrow the entry `600`
  (correlated-unbond rate; L17-coupled); **FSM-gated** (the cooldown is committed-but-unenforced —
  no `verify_unbond_release` consumer). **F-D5** quantization → §14.4; **F-D6** anti-drift (derive
  `RELEASE_COOLDOWN_EPOCHS × SEB`, never hardcode `20_000`). GF-10 (R3) folds into the joint grade.
  §6 R4 cell + status header updated. Docs-only.
- **2026-07-11 (R3 adversarial pass — findings folded, one retraction):** Ran the adversarial pass
  over §11.3–11.5 (new §11.8). No break; two unstated assumptions + one wrong-tool error, folded as
  re-pins, all source-anchored at `dev` `75c3cae1d`. **G-10.A** (was raised as mechanism-infeasibility,
  **retracted on the merits** — `REFERENCE_BLOCK_MAX_AGE = 100` is a daemon inclusion-freshness
  window, not a verifiability expiry; `reference.rs:181`/`85-106`): collapsed to a **freeze-epochs
  pin** on the unbuilt CB-3 dispatch seam — a held claim's proof rebuilds proof-only (re-anchor
  reference, never re-fetch `source`/re-derive `claim_epochs`); anchored to the **single-shot** claim
  orchestrator (`claim_orchestrator.rs:230/241/335`). **G-10.B** (load-bearing): the `S_min` rationale
  "F1 is epoch-granular so finer jitter is pointless" is **false at source** — challenge fire/response
  is sub-epoch block-granular (`challenge.rs:56-76`); re-derived `S_min ≥ SEB` on the stronger
  "claim epoch-set is already public" basis, added the sub-epoch-challenge scope line (beacon-driven;
  response instant → S-2). **G-10.C**: the cited negative control (`draw_entry_gap_double_jitter_trap`)
  guards a two-sided construction GF-10 (one-sided) does not have — swapped for shared-trigger +
  backlog-at-cap controls. **G-10.D**: return-from-`>15`-epoch-dormancy forces a deterministic claim
  — named as a bounded residual. Status: mechanism pinned; R3 closes when GF-10 folds into the R4
  joint grade. Docs-only.
- **2026-07-11 (R3 design pass — GF-10 mechanism pinned):** Converted §11 from frame to designed
  round, source-grounded at `dev` `75c3cae1d`. **GF-10 pinned as a mechanism, not a standalone
  graded gate:** a uniform-independent claim-broadcast-height draw through the audited
  `bounded_uniform` (`shekyl-standoff` draw.rs:31), typed `ClaimJitterGap`, per-claim independent
  (the `16→1.01` shared-trigger lesson), drawn directly (double-jitter trap avoided), with
  no-self-schedule-to-the-batch-cap discipline. **W/epoch-length joint pin:** window `[h_close +
  reorg_depth(720), (E_oldest+W)·SEB − submit_guard]`, a-priori `S_min ≥ SEB` (tied to F1's
  epoch-granularity fingerprint); constants verified at source (`config/consensus_constants.json`:
  SEB 10_000, W 26, reorg 720, batch cap 15, `release_cooldown_epochs = 2` ⇒ the "20 000-block
  cooldown" is derived `2·SEB`). **Grading correctly routed to R4/GF-4's CB-3 joint grade** (RATIFIED
  2026-07-09) — NOT graded standalone, which would re-commit the per-axis-multiplication error CB-3
  forbids; a-priori advantage claim pre-committed. **Source overturned a frame assumption:** the
  "epoch-boundary non-crossing" constraint is false — broadcast height does not re-select
  `claim_epochs` (recorded as a correction, §11.4). **Wargame finding:** batch-cap-forced determinism
  (backlog to the 15-cap forces the claim height) — armed into the mechanism, not left implicit.
  Draw + scheduler verified **unbuilt** → pinned pre-code, M1-armed (CI grep before the identifier
  exists). Status: designed, pending one adversarial pass (§11.7). Docs-only.
- **2026-07-11 (R2 closed, R3 opened, landed elements reconciled — this pass):** Brought the doc up
  to its own status-of-record so the round record is self-contained rather than reconstructed from
  scattered docs. **R1 carry discharged:** verified at source that `archival_p` + the
  `ARCHIVAL_P_DERIVE_V1` KAT landed (Bond-PR 0 #152; seven §9.3 labels incl. `bond_spend_*` present
  in `archival_p.rs`) and the C-1 emission vin ML-DSA equality check landed (#277); §7 checklist
  reconciled to landed state per item (round + code anchor). **R2 formally closed** against its
  §10.0 defense-in-depth bar (not "linkage impossible", not "all implementation landed"): §10.10
  boxes ticked to closure basis, new **§10.13 closure disposition** (ratification + carried items
  with rule-21 criteria + R3/R4/R5 hand-forwards + landed-transport-code pointer). **GF-9 honesty
  correction:** the HS-id HKDF label is *not* in the derivation (verified — absent from
  `archival_p.rs`), so its box is `[~]` (disposition pinned, label-freeze carried) and the carry is
  armed with the **dot-vs-hyphen format flag** (§10.7's `shekyl.archival.p.hs_id.v1` violates
  §9.3's hyphen convention + non-prefix-free safety argument — normalize before freezing).
  **R3 opened** as a draft *frame only* (new §11): scope, adversary, entry gate (GF-10 within-epoch
  claim jitter — un-pinned, no landed code, verified), inherited dispositions (T-A1 rotation
  non-channel, epoch-batch, GF-11 `W`-vs-cap, R2 rotation network leg), what it owes, and the
  steps-forward — with the coverage boundary that the standoff (GF-7/R4) is **not** GF-10 coverage.
  §6 round table rewritten to true status; §11 Related documents renumbered §12. No design pinned
  this pass. Docs-only.
- **2026-06-16 (S-5 consciously closed — long-lived `P` committed):** The last genuinely-structural
  fork (long-lived vs. short-lived `P`) is closed in favor of **long-lived `P`** per
  `21-reversion-clause-discipline.mdc` — ratifying what serve-credit accrual, lock tiers,
  `bond_duration`, the L18 freeze seal, and bond-as-consensus-balance already assume, so the
  decision-by-accumulation is now explicit rather than latent. Short-lived/rotating `P` is out of
  scope for V3.0 (would require a bond-migration consensus op, reopening §6/R-1 + gate-4 §3.2). The
  surviving privacy residual is *characterization*, not a re-fork: folds into S-2 (exposure ledger)
  + S-3 (adversary sim) + operator-behavior levers. Named reopen criterion: a **measured** S-2/S-3
  per-`P` attribution breach severe enough to reconsider the confidential-staking rejection, via a
  fresh `PHASE_2B` model-level round. §10 S-5 bullet + Prioritization prose updated. Docs-only.
- **2026-06-16 (GF-1-carve resolved — dedicated bond-spend key):** Bond-debit authorization is a
  dedicated **`bond_spend_pk`** (hybrid `scheme_id = 1`), committed into `ArchivalBondRecord` at
  `JoinMarket` and immutable, **never** the account identity key — so authorizing a value-out no
  longer touches `hybrid_bond_id` (Round-1 identity-only invariant preserved). §9.3 gains the
  `shekyl-archival-p-bond-spend-{ed25519,ml-dsa-65}-v1` HKDF labels (+ KAT obligation, §7); §9.4
  gains the `bond_spend_pk`/`bond_spend_sk` bundle field; §9.6 carve note + table row + §10.11
  open item flipped to resolved. Custody model (gate-4 §3.2) **not reopened** — still
  consensus-balance; the receipt-UTXO direction was declined with a named reopen criterion (§9.6).
  Source change lands in gate-4 (§3.4 vin, §3.4.1 wire + sig-preimage, §3.5 step 5 verify order,
  §4.1 record, §8 checklist). Docs-only here. Closes the §10.11 critical-path item (1).
- **2026-06-15 (`HoldingsUpdate` promoted to genesis scope):** Resolved R-1's open
  V3.1→genesis call: the full bond lifecycle (`JoinMarket / Rebond / HoldingsUpdate /
  Unbond`) ships at **V3.0** (gate-4 §4.4 revision 2026-06-15). Rationale: bond balance is
  consensus-state-machine state, so mid-life shard adjustment added post-genesis is a hard
  fork; and without it the only way to add/shed one shard is `Unbond` + re-`JoinMarket`,
  tearing down a working multi-shard operation to swap one slot — operationally untenable.
  The add-shard credit path covers the top-up direction (closes the §9.6 "no dedicated wire"
  gap). All bond-lifecycle verify/connect logic is **Rust-native** (`shekyl-archival-retention`),
  C++ daemon thin-glue + FFI delegation moved where needed; wallet-side construction is Rust.
  Consequences unchanged from the pass-1/2 scope notes: GF-4/GF-7/GF-10 are **recurring**
  surfaces (§6 R4), and the **age-stratified sim bond-mobility reconciliation remains the
  pre-genesis-seal dependency** (now unblocked to proceed once the FSM frictions are pinned in
  `PHASE_2B_FSM_RETOOL.md`). Docs-only; FSM-friction pin and sim reconciliation tracked
  separately (FOLLOWUPS V3.0 lifecycle item).
- **2026-06-13 (Round 2 adversarial pass 4 — cadence/standoff dispositions):** Added the
  organizing principle behind the close: the firewall protects **P ↔ principal (a linkage)**, not
  **P ↔ its own rewards (a conceded-public function of contribution)**. Earning-function obfuscation
  (reward-magnitude *banding* — distinct from the sealed `g` operating-band — and pay-every-block) is
  **trilemma-costly and misdirected**; the seam mitigation (standoff + inversion) touches no economic
  quantity and is **off the trilemma's axis**. Cross-`P` sybil correlation resolves to seam
  protection too (its signature is timing/pattern, not magnitude), and FCMP++/RingCT already hides
  seam *amounts*, leaving **timing + origin** as the public seam leak the standoff targets. Resolved
  the two live pass-3 §10.12 scenarios. **CLOSED pay-every-block / implicit accumulator emission, and
  corrected the pass-3 over-claim** that accumulator credit "deletes GF-6/GF-10": on an
  attributed chain staker payments are a **roll-call** (`P_canonical_id` dedup), so continuous
  payment makes an absence a **one-block edge** at the GF-4 exit, not crowd-cover; and **consensus
  cannot mint a hidden-recipient output** (no ephemeral secret — the coinbase is sender-to-self), so
  a per-block reward is either publicly-derivable (traceable, privacy destroyed) or invisible accrual
  that concentrates into the terminal event (worse GF-4, kills claim-timing decorrelation). The
  periodic-claim model is the better spot; the obfuscation needs membership-hiding = confidential
  staking, so this is the **S-4 bridge cost in disguise** and the real question (reopen confidential
  staking?) folds into **S-5**. **BUILD the funding-seam entry standoff + inversion** (the door,
  GF-7) into the S-3 sim, sharpened past "smooth vs surge": candidate-set sizing *for the targeted
  principal* (not window width), the **low-activity principal** as the worst case (where only the
  inversion helps), trigger-independence as the clustering knob, and **enumerate the separable
  funding events first** (prep-spend vs. announce vs. bond-post tx — ties to the S-2 ledger). Quick
  dispositions: terminal-lump → existing wallet-side GF-4 fragmentation (no consensus mechanism);
  per-block accrual rejected (more churn + reorg surface, same exposure); seed compromise = named
  residual (recoverability ⟺ single-point-of-failure), weight on key hygiene. Docs-only.
- **2026-06-13 (Round 2 adversarial pass 3 — end-to-end trace):** An end-to-end `P`-lifecycle
  trace surfaced **cross-layer / model-level findings the per-round decomposition is blind to by
  construction** (new §10.12, S-1…S-6). **S-1:** the money seams (GF-7 funding-in, GF-4 value-out)
  are the only findings protecting principal↔`P` unlinkability and the only two still deferred —
  they sit at the on-chain ∧ network ∧ timing conjunction no single layer owns; deferral ≠
  ownership. **S-2 (build first):** there is no fused, per-observer, whole-life exposure ledger
  (the §10.1 table is per-adversary "must not learn"); specified one (observer × event matrix +
  per-observer fusion closure, conceded vs. leaked cells marked). **S-3:** privacy is named, not
  measured (325 economic scenarios, 0 adversary) — reframed as the **privacy axis of the R-3
  reconciliation already gating the seal**, deliverable = adversary sim on the funding/exit timing
  seams. **S-4:** labeled the onion↔`P_canonical_id` bridge a **conceded staking-model cost** traceable
  to the confidential-staking rejection (not fixable at the network layer). **S-5:**
  longevity-vs-privacy named a **model-level pre-seal question** — long-lived `P` is the worst bridge
  structure, but rotation relocates the seam and reopens the bond FSM (answer open). **S-6:** pinned
  **key locality** — the always-on serving box holds only the `P`-subtree, never the master seed
  (cold-derive + provision; HKDF one-wayness preserves recoverability), extending the §10.9 isolation
  pin from circuits to keys. Recorded three sim scenarios (variable announce↔funding standoff;
  randomized 0–9-block entry incl. `P`-before-bond; **implicit accumulator emission** — deterministic
  Σwork credit with no broadcast claim deletes GF-6/GF-10 by folding them into GF-4, vs. literal
  per-block pay which *sharpens* the unbond cessation edge). Prioritization: ledger → adversary sim
  → longevity question, all pre-seal. Docs-only; the ledger/sim/model calls live in their home docs.
- **2026-06-13 (Round 2 adversarial pass 2):** Two sharpenings on the pass-1 landings. **GF-1-carve
  is asymmetric, not a balanced fork:** gate-4 §3.5 step 5's existing wording ("`P` hybrid
  signatures on vin") already presumes the account `hybrid_sign_pk`, so the carve is the
  default-by-inertia — it happens unless explicitly chosen against ("absence of the claim is a
  claim of absence"). Reframed the §9.6 collateral-out cell + note: collateral-out is the only `P`
  path with neither key image nor bindable leaf, which is why the account key tempts; carving it
  trades the cleanest Round-1 invariant (account key = identifier, compromise reveals nothing
  spendable) for "compromise drains the bond." **Recommended disposition:** a dedicated bond-spend
  key committed in the record (own HKDF label + KAT, domain-separated; non-replay from
  `bond_debit ≤ bonded_total` + tx-height/input binding, no key image). Recorded a *receipt-UTXO*
  custody direction (non-transferable receipt spent on the standard per-output+key-image path —
  replay-free, partial-unbond = receipt split, value-leg byte-indistinguishable) as a gate-4 call,
  not a prescription. Concrete action pinned: **re-word gate-4 §3.5 step 5 to name the key** before
  the verifier lands. **R-3 reconciliation must be age-stratified, not a re-tuned flat scalar:** the
  "flat seating cost" stands in for a friction that is worst on the deep tail, so recalibrating it
  to a network average stays optimistic exactly on the binding constraint — pre-seal requirement is
  "model friction age-stratified." Added a **critical-path-out-of-Round-2** note to §10.11 (the
  GF-1-carve wording fix + the FSM→age-stratified-reconciliation→seal chain; transport tuning
  defers to testnet). Docs-only.
- **2026-06-13 (Round 2 adversarial pass 1):** Worked the §10 forks + the rebond/unbond scope
  question, **verifying the load-bearing claims at source** before landing (per the Round-1
  C-1/C-2 verify-don't-infer discipline). **R-1 (reframed at source):** the bond FSM already
  carries `JoinMarket` / `Rebond`-after-slash / full `Unbond` + release cooldown
  (`RELEASE_COOLDOWN_EPOCHS = 2 < W`) + `bond_duration(age)` horizon at genesis; **voluntary
  partial-unbond is `HoldingsUpdate` (`post_kind=3`), specified but flagged "V3.1 wire"**
  (`ARCHIVAL_BOND_GATE4.md` §3.2/§4.4) — so R-1 is a **V3.1→genesis promotion** (+ top-up wire),
  a gate-4/FSM-retool call recorded here. **R-2:** §9.6 bond-post row split into collateral-in
  (inherits the contract) / collateral-out, with the **GF-1-carve open question** named (does the
  bond-debit vin authenticate via the account `hybrid_sign_pk` — carving identity-only — or a
  per-output key?); resolve at gate-4 source. §6 R4 re-scoped to **recurring** GF-4/GF-7, GF-10
  extended to bond ops. **R-3 (verified + strengthened):** sim **explicitly abstracts release
  cooldown ("sim still unmodeled"), partial slash, capital-lockup to "a flat seating cost"**
  (`STAKER_ARCHIVAL_SIM.md` §steady-state #6); seal carry is integer + **+1 deep-tail margin**
  (`ARCHIVAL_SIM_ECONOMICS_VERDICT.md`); since `bond_duration` peaks on the deep tail where the
  margin lives, the FSM-friction reconciliation (c) compounds the tail-margin finding → the
  **rebond/unbond FSM is a pre-genesis-seal dependency** for the R-3 sim reconciliation (§6 scope
  note). **§10 fork dispositions:** §10.4 bonded-verifier-only + restricted-discovery (condition
  (b) sharpened — L14 oversight *volume* is challenge≡retrieval / population-independent; the
  real check is challenger *liveness* vs L14b `m`-of-`n`); §10.5 announce → broadcast (event-
  sensitivity divergence + R3 sequencing hazard); §10.6 own-node/Dandelion is secondary, GF-6
  shape orthogonal; §10.7 crypto over-coupling foreclosed (HKDF one-wayness), real risk is
  restore co-activation. New **§10.9 `P`↔principal client/circuit isolation** exit pin (forks 1+4
  convergence: independent Arti clients/guards + restore-flow discipline — `StakeEngine` must not
  co-launch `P`'s HS with principal sync). §10.8 pure-rendezvous genesis lean (access-pattern
  bar); §10.11 I2P-closed-at-genesis lean. Exit §10.9→§10.10 (isolation + recurring-surface
  items added); open questions §10.10→§10.11 (dispositions + remaining carries).
- **2026-06-13 (Round 2 draft opened):** Drafted §10 — network + transport layer — as the
  opening position for the Round 2 adversarial pass (OPEN, not closed). Framed the round's
  bar as **defense-in-depth** (named fingerprint + measurable mitigation + honest residual),
  not algebraic separation. Threat model (live observer); two traffic classes (light/Tor,
  heavy/onion-rendezvous, no clearnet fallback). Threaded the five R1-named entry gates:
  **GF-12** — Arti **service-side onion-service hosting confirmed** (done/stable since 1.2.0,
  `onion-service-service` feature on `arti-client` 0.43.0; web-verified, **at-source pin
  carried** to the transport PR per dependency-discipline), embed-Arti fork decidable on that
  pin; **GF-3** — challenge/liveness Levin class added to the anonymity-routable set, clearnet
  fallback refused (loud); **GF-5** — pre-join backing presentation pinned to a fresh anonymity
  circuit (no principal stream reuse), announce↔anchor timing handed to R3; **GF-6** — `P`-tx
  broadcast-origin fingerprint characterization obligation + dummy/fragmentation policy shape
  (on-chain `P`-typing is public-by-function and explicitly *not* the concern), tuned ratio
  carried to testnet replay; **GF-9** — HS identity key `p_slot`-bound + **seed-derived via a
  new §9.3 HKDF label** (`launch_onion_service_with_hsid`), serving-side key-compromise residual
  named. Added the heavy-path relaxation lever (§10.8, privacy > bandwidth) and six open
  questions for the pass (§10.10, since renumbered §10.11 by pass 1). §6 round table + §2.2
  pointers updated; old §10 Related documents renumbered §11.
- **2026-06-13 (Round 1 C-1 second-order confirmation):** Pressure-test on the C-1 interim
  characterization. Verified at source ([`FCMP_MEMBERSHIP_ONLY.md`](../completed/FCMP_MEMBERSHIP_ONLY.md) §5.1
  (a)/(b)/(c)) that the `MembershipSpendAuth` `R_O` leg proves **classical knowledge of the leaf's
  spend secret `x`** (= ownership) — "membership-only" omits the **key image/nullifier**, not the
  spend authority. So "reduces to classical security" is **accurate** (the interim is PQ-weak, not
  authority-free); added the §9.6 belt clarification. Wired the C-1 dependency to a **failing
  test**: the §7 `pqc_pk`-mismatch forgery negative (membership proven, non-matching `pqc_pk` ⇒
  must reject) fails until the vin-layer ML-DSA equality check lands, plus a stressnet negative-case
  obligation alongside the honest-path 100-cycle criterion.
- **2026-06-13 (Round 1 post-sign-off review refinements):** Closure-review items on the
  sign-off itself. **C-1** — recorded the emission backing-input quantum spend-authority binding
  as a **named carried dependency** (§9.8) rather than a citation that read as closed; verified
  at source ([`FCMP_MEMBERSHIP_ONLY.md`](../completed/FCMP_MEMBERSHIP_ONLY.md) §7/§8.2/§9) that the membership
  proof and ML-DSA check bind the **same proven leaf at the same input index** (in-circuit
  `H(pqc_pk)` extra scalar, index-bound — implemented), and that the **vin-layer ML-DSA equality
  check is a not-yet-landed hard merge blocker** that must precede the `archival_p` impl + emission
  verifier; sharpened the §9.6 emission row and membership-only paragraph accordingly. **C-2** —
  re-anchored the GF-2 ownership boundary: the dual-scan pipeline is the authoritative §2.1 genesis
  pin, but `StakeEngine`'s sole ownership of `P.view_sk` is a Gate-6 **forward requirement on the
  PHASE_2B FSM retool**, not inherited from claim-era §4.6 (flagged STRATUM); the crypto basis
  (distinct `combined_ss`/decap) is independent of the actor assignment. **C-3** — added the
  loud-fail defensive invariant to the cross-pipeline negative test (double-match is unreachable
  by construction; the impl must assert it, not assume it). Micro — recorded the §9.3 info-string
  non-prefix-free safety argument + the separator-byte-at-KAT-authoring disposition (no wire change
  now).
- **2026-06-13 (Round 1 closed):** Adversarial pass disposition. GF-1 — rewrote §9.6 with a
  per-tx-type verifier-contract table: account `hybrid_sign_pk` is bond-record **identity only**
  (`P_pubkey`), never a per-input auth key; emission backing inputs authenticate against the
  leaf-committed per-output `pqc_pk` (membership-only); fee inputs / ordinary transfers / drains
  use per-output keys; ordinary `P` transfers carry no `P`-typing. §9.4 `hybrid_bond_id` note
  strengthened to identity-only. GF-2 — made dual-scan firewall **architectural**: `StakeEngine`
  owns `P.view_sk` as a separate identification context, separation rests on distinct
  `combined_ss`/decap (not a naming convention), shared scan loop allowed only with
  match-routing; named the cross-pipeline non-cross-assignment negative test; added `P`-scan
  ownership rows to the §5 consumer map. Corrections — GF-8 (§9.3 `L = …` placeholder fixed; `L`
  values were already pinned in the table), GF-11 (§2.3 cross-ref that `W=26 > 15` is pinned in
  `ARCHIVAL_TIMING_CONSTANTS` §1), GF-4 (§2.4 note: delay floor already pinned, output-count is
  the open R4 hard exit). §6 round table + §7 checklist updated; remaining findings folded as
  named R2/R3/R4 entry/exit criteria. Reviewer sign-off recorded (§9.8); KAT manifest +
  `archival_p` impl remain the lone carry.
- **2026-06-07 (Round 1 draft):** §9 — `P` hybrid derivation (HKDF labels, `ArchivalPKeys`,
  `P_canonical_id`, dual-scan, account-level ML-DSA, V4 reversion clauses).
- **2026-06-07 (Round 0 open):** Initial scaffold — four layers + bond-funding; `P`
  lifecycle; invariants; round plan; E-4 / epoch-length / L16 couplings named.
