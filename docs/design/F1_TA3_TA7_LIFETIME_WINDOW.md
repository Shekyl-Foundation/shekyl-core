# F1 disposition + T-A3–T-A7 lifetime-window wargame spec

**Status:** **Qualitative wargame complete (2026-06-07).** T-A3/T-A5/T-A6/T-A7 pass
under wallet-default discipline + lifetime `T_obs`. T-A4 **conditional** — shape pass,
quantitative thresholds blocked on timing-cluster pin. F1 **conditionally finally accepted**
pending T-A4 numeric pin + gate-6 Round 3–4 wallet-default landing.

**Authority chain:** T-A1/T-A2 sim
([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §*T-A1 / T-A2*);
gate-3 holdings publicity ([`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md));
firewall layers ([`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md));
timing cluster ([`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md)).

---

## 1. What T-A1 established (no further cohort sweeps)

The cohort instrument is **complete**. Further sweeps do not move the decision.

| Finding | Evidence |
|---------|----------|
| Lean equilibrium → **unique portfolios** | `ta1_cohort_lean`: mean cohort 1.0, singleton 0.982 |
| Timeline channel **empty** at lean eq | baseline 0.959, lapse 0.928 — rotation harder than chance |
| Instrument **valid** | `ta1_cohort_shared`: cohort 92.6, singleton 0.075 |
| Forced cohorts **price coverage** | shared pin: `deep_und` 0.973 |
| Distinctive negative control **inconclusive** | lean baseline already ~100% singleton |

**Mechanism (the actual finding).** Scarcity pricing (`1/R_market`) rewards holding
*under-replicated* deep shards. Archivers diversify into different deep shards to capture
scarcity → **partitions deep space into unique portfolios**. The mechanism that produces
good coverage (spread across under-covered shards) is **identically** the mechanism that
produces the re-linkage fingerprint (unique portfolios). Coverage and rotation-anonymity sit
at **opposite** portfolio distributions; the lean attractor sits at the spread/unique end
because that is what the reward pays for.

F1-FAIL-on-cohort at lean eq is **not** a metric bug. It is the **privacy shadow of the
coverage mechanism working correctly.**

---

## 2. What F1 is (gate-3 viewed through rotation)

F1 is not a fresh threat. It is the **gate-3 Form-C holdings-publicity decision** viewed
through pseudonym rotation.

Gate-3 dissolution conceded that Form C makes per-`P` holdings **consensus-public** by
construction (derived `R_market`; no `ν` hide primitive). T-A1 quantifies the rotation
consequence:

- **Portfolio = public identity** (~98% singleton at lean eq).
- An operator that rotates `P` **while keeping storage** — the rational move that preserves
  scarce-shard income — is **re-linkable on the portfolio alone**; timeline is irrelevant.
- Decorrelation requires re-storing a **different** shard-set → abandons scarce-shard income
  and pays re-sync cost.
- **The reward mechanism actively disincentivizes the only move that decorrelates.**

**Honest residual (landed, disclosed):** re-linkability across rotation is portfolio-bound;
a distinctive archival portfolio is a persistent public identity by function.

---

## 3. Load-bearing consequence — observation window

Rotation was E-4's tool for **bounding the observation window** against the principal: rotate
so a long correlation cannot build on one `P_id`.

**F1 removes that tool** for fixed-portfolio operators. An adversary tracks one operator's
**portfolio** across every rotation as a single continuous identity. The effective observation
window for the `P`↔principal firewall is therefore:

```text
T_obs  =  operator operational lifetime
       ≠  one rotation period
       ≠  one settlement epoch
       ≠  W  (forfeiture horizon — governs reward lapse, not portfolio persistence)
```

This does **not** break the primary firewall (gate-6 §2: onion path, decorrelated
funding/drains do not traverse the public portfolio). It sets the **duration those layers
must survive.**

**Premise for T-A3–T-A7 (mandatory, not optional):** each wargame assumes an adversary who
can correlate observations across **all `P` rotations of one operator** for the operator's
entire archival lifetime. **Rotation does not reset the window.** Wargames that assume
per-rotation window reset are **invalid** for F1 disposition.

---

## 4. Closed option space

| Mitigation | Why closed |
|------------|------------|
| Partial overlap / decoy shards | Unique subset still fingerprints; shared decoys do not erase it |
| Coarser shard granularity | Breaks `Σwork` per-shard `1/R_market` scarcity (same reason gate-3 `ν` dissolved) |
| Hide holdings | Dissolved `ν` / full Form-C reopen |
| Force cohorts (reward-shape change) | ~97% deep under-coverage in positive control — anonymity trades almost all coverage |

Decision tree is genuinely **accept-and-harden** vs **reopen Form C**:

| Branch | Condition |
|--------|-----------|
| **F1 accepted** (residual, disclosed) | T-A3–T-A7 **pass** against lifetime-length `T_obs` |
| **Form-C reopen becomes live** | T-A3–T-A7 **fail** — need window-bounding tool; only portfolio rotation works; rotation needs cohorts; cohorts need reward-shape change that buys anonymity with coverage |

**F1 final disposition is downstream of T-A3–T-A7**, not of further cohort instrumentation.

---

## 5. Timing-cluster coupling — draft now or wait?

**Draft premise + pass/fail shape now.** The lifetime-window premise does not require numeric
`W` or drain cadence — it is a *threat-model upgrade*, not a constant pin.

**Quantitative T-A4 thresholds wait** on the timing-cluster value pass
([`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md)): `W`,
`MAX_SETTLEMENT_EPOCHS_PER_EMISSION`, release cooldown, drain/Unbond spacing. Those set
*secondary* correlation cadences inside the lifetime window (emission drip rate, lapse
forfeiture rhythm) but do not shorten `T_obs` below operator lifetime.

| Item | Can open now | Blocked on timing values |
|------|--------------|--------------------------|
| T-A3 network path | **Yes** — qualitative + L16 transport band | Quantitative rendezvous latency margin vs challenge window |
| T-A4 timing | **Shape only** — lifetime window + cadence inventory | Jitter defaults, batch cap vs `W`, drain spacing pins |
| T-A5 output graph | **Yes** — FCMP++ sufficiency vs min-delay need | Min-delay numeric pin if required |
| T-A6 bond funding | **Yes** — admission pattern correlation size | Cooldown vs `W` inequality at pin time |
| T-A7 cross-`P` intersection | **Yes** — portfolio tracking across rotations | Timeline leg de-weighted per T-A1; portfolio intersection primary |

**Recommendation:** open the firewall wargame round **now** with this premise baked in; run
T-A3/T-A5/T-A6/T-A7 qualitatively; hold T-A4 quantitative pass/fail until timing cluster
lands. Do **not** silently run T-A3–T-A7 against per-rotation windows.

---

## 6. Per-item wargame spec

### Shared adversary model (T-A3–T-A7)

| Field | Value |
|-------|-------|
| **A2/A4** | Passive chain + timing analyst; daemon collusion where noted |
| **`T_obs`** | Operator archival lifetime (years-scale; parameterize in sim/docs) |
| **Portfolio tracking** | Adversary maintains persistent **portfolio identity** across `P` rotations |
| **Rotation assumption** | Cosmetic rotation with fixed storage is **in scope** and **rational** |
| **NOT in scope** | Hiding holdings (Form-C reopen); forced cohort reward-shape |

### Pass / fail shape (shared)

**PASS:** under `T_obs`, no layer in the item's scope yields a **practical** principal↔`P`
link beyond what ordinary transfer hygiene already accepts — with explicit bound on
correlation strength or window *inside* the lifetime (e.g., funding event not joinable to
every drain across 10 years).

**FAIL:** a disciplined operator following wallet defaults can be linked principal↔`P` (or
`P_i`↔`P_j` as same operator) with **non-negligible confidence** over `T_obs` using only
public chain data + network observation allowed by the item's model.

**CONTINGENT FAIL → Form-C reopen:** if FAIL and the only available fix is portfolio
hiding or cohort-forcing reward shape, escalate per §4 decision tree.

---

### T-A3 — Firewall: network path

**Question.** Under A2/A4, does onion rendezvous (L16) contain principal↔`P` for production
serving over `T_obs`?

| Demonstrate | Method |
|-------------|--------|
| Onion path does not admit stable principal↔`P` network fingerprint | Threat pass on rendezvous; seeding relaxation bounded |
| Portfolio-public identity does not collapse into principal network identity | Even with lifetime portfolio tracking, path layer stays independent |

**Pass:** rendezvous + transport discipline sufficient for lifetime window.
**Fail:** path correlation compounds with portfolio identity → effective deanonymization.

**Coupling:** L16 transport band; `CHALLENGE_RESOLUTION_BLOCKS` (quantitative margin later).

---

### T-A4 — Firewall: timing

**Question.** Emission batching + drain/Unbond spacing — standing correlation channel vs
principal spends over `T_obs`?

| Demonstrate | Method |
|-------------|--------|
| Emission cadence does not create joinable timing signature across rotations | Batch cap + jitter defaults |
| Drain/Unbond decorrelation sufficient vs principal spend graph | Min-delay / output-count if needed (feeds T-A5) |

**Pass:** timing channel does not bridge portfolio-tracked `P` lifetime to principal over
`T_obs`.
**Fail:** standing timing correlation survives rotation + portfolio persistence.

**Blocked:** numeric jitter/batch/`W` pins — inventory now, thresholds at timing-cluster pass.

---

### T-A5 — Firewall: output graph

**Question.** Reward receipts + Unbond refund + terminal drain — FCMP++ membership
sufficient, or pinned min-delay / output-count discipline needed for `T_obs`?

| Demonstrate | Method |
|-------------|--------|
| Stealth outputs do not link reward history to principal cluster across operator lifetime | Output-graph analysis |
| Terminal drain discipline holds over many rotations | Decorrelated drain pattern vs lump sweep |

**Pass:** output layer holds for lifetime observation.
**Fail:** graph links compound with public portfolio identity.

---

### T-A6 — Firewall: bond funding

**Question.** Admission stake-in pattern — correlation channel size vs ordinary transfer
hygiene over `T_obs`?

| Demonstrate | Method |
|-------------|--------|
| Principal→`P` funding not joinable to every archival epoch / drain | Funding pattern analysis |
| Multi-`P` funding does not amplify intersection (feeds T-A7) | Per-`P` hygiene defaults |

**Pass:** funding channel bounded to ordinary-transfer risk class over lifetime.
**Fail:** funding pattern is a standing principal↔operator link stronger than transfer hygiene.

**Coupling:** release cooldown vs `W` at timing pin.

---

### T-A7 — Cross-pseudonym intersection

**Question.** One principal, N `P` without per-`P` hygiene — intersection over `T_obs`?

| Channel | T-A1 weight |
|---------|-------------|
| Retention timeline | **De-weighted** — empty at lean eq |
| **Portfolio intersection** | **Primary** — public holdings persist across rotations |
| Network fingerprint | Secondary — T-A3 scope |

**Pass:** without per-`P` hygiene, adversary cannot merge `P_i`↔`P_j` as same operator
over `T_obs` beyond portfolio coincidence base rate.
**Fail:** portfolio intersection alone re-links rotations / pseudonyms.

---

## 7. F1 disposition record

| State | Meaning |
|-------|---------|
| **Provisionally accepted** | Category + honest residual landed (gate-3 consequence) |
| **Conditionally finally accepted** | T-A3/T-A5/T-A7 pass qualitatively; T-A4/T-A6 conditional on timing + wallet-default pins (§9.8) |
| **Finally accepted (full)** | Above + T-A4 numeric pin + gate-6 Round 3–4 defaults landed |
| **Form-C reopen** | **Not triggered** — no layer fails under disciplined defaults |

**Disclosure (wallet / FOUNDATION):** re-linkability across rotation is bounded by your
shard-set's co-holder cohort; at lean equilibrium portfolios are ~unique by construction;
rotation without storage change does not decorrelate; the reward pays for the spread that
fingerprints.

**Cohort instrumentation:** closed — no further sweeps required for F1 disposition.

---

## 8. Landing checklist

- [x] T-A1/T-A2 sim complete — [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md)
- [x] This spec — lifetime premise + per-item pass/fail
- [x] T-A3–T-A7 qualitative wargame — §9
- [ ] T-A4 quantitative pass after timing-cluster value pin
- [x] F1 conditional final accept recorded — §9.8, PHASE_2B §7.10
- [x] Wallet disclosure draft — §10

---

## 9. Qualitative wargame results (lifetime `T_obs`)

**Method.** Adversarial pass per §6 under `T_obs` = operator archival lifetime.
Portfolio tracking across all `P` rotations is **in adversary capability** (T-A1).
**Disciplined operator** = wallet genesis defaults for emission batching, decorrelated
drains, fund-from-earnings bond ramp, per-`P` multi-`P` hygiene, onion-only production
serving (no clearnet fallback). Deliberate hygiene violation is **out of scope** for
protocol pass — it is operator error, not a Form-C reopen trigger.

### 9.1 T-A3 — Network path

| | |
|--|--|
| **Question** | Does onion rendezvous admit principal↔`P` linkage over `T_obs`? |
| **Analysis** | Production serving is pinned to onion-service ↔ Tor-client rendezvous (L16).
Portfolio is chain-public; the network layer must prevent clearnet operator location and
principal device fingerprint from collapsing into `P`'s reachability endpoint. Over years,
adversary sees stable **portfolio identity** on-chain but **not** principal IP/ASN if: (a)
serving never falls back to clearnet, (b) challenge and fetch paths do not embed principal
metadata, (c) seeding-path relaxation stays bounded (smaller surface than serving). Portfolio
tracking does **not** grant network identity — it grants **operator continuity**, which is
the F1 residual, not a network-layer breach. |
| **Residual** | Long-horizon Tor circuit reuse / operator opsec; challenger-position timing
(sharper than passive A2 — scoped to T-A16). Arti embed verification per dependency
discipline. |
| **Disposition** | **PASS (qualitative)** — primary firewall holds for lifetime window
under L16 posture. |

### 9.2 T-A4 — Timing

| | |
|--|--|
| **Question** | Do emission/drain cadences bridge portfolio-tracked `P` lifetime to
principal spends over `T_obs`? |
| **Analysis** | **Standing events:** join-Market (unhideable), periodic emission batches
(`SEB` × batch cap), occasional drains/Unbond. Over lifetime these produce many samples —
rotation does **not** reset portfolio identity, so timing must not be a **joinable clock**
between principal graph and `P` activity. **Mitigations (designed, not all numerically
pinned):** settlement-epoch batching (not per-epoch drip); `MAX_SETTLEMENT_EPOCHS_PER_EMISSION
= 15`; fund-from-earnings ramp spacing join-Market from principal funding
([`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §6); wallet-local emission jitter;
decorrelated drains (T-A5). `W` governs forfeiture, not `T_obs` shortening. **Gap:** jitter
magnitude, min spacing join-Market↔principal spend, drain spacing defaults — need timing-cluster
pin. |
| **Residual** | Quantitative pass/fail thresholds; daemon-assisted vs wallet-local jitter
policy. |
| **Disposition** | **CONDITIONAL PASS (shape)** — no design hole identified; numeric
defaults **blocked** on timing-cluster pin. Form-C reopen **not** triggered. |

### 9.3 T-A5 — Output graph

| | |
|--|--|
| **Question** | Do reward receipts + drains link `P` to principal over `T_obs` beyond
ordinary FCMP++ transfer hygiene? |
| **Analysis** | Rewards land in `P`-controlled stealth outputs (loud amounts; privacy is
firewall not amount hiding). Principal return uses **decorrelated** FCMP++ spends — not lump
sweeps tying full reward history to one principal cluster in a single block. Unbond refund is
loud `bond_floor` into the public set — same discipline. Over lifetime: many emissions and
drains increase graph **attempt** surface, but each leg is indistinguishable from ordinary
RingCT transfer class if decorrelation default holds. Portfolio public identity does not
collapse output-graph anonymity — amounts and membership are already the public/leaky parts;
the firewall claim is **no extra** principal↔`P` edge beyond transfer hygiene. |
| **Residual** | Pin min-delay / output-count between last emission and terminal drain
(gate-6 §2.4 round-open). Wallet must loud-fail on lump-sweep UX. |
| **Disposition** | **PASS (qualitative)** — FCMP++ membership + decorrelated-drain default
sufficient for `T_obs`; numeric drain spacing pins with gate-6 Round 4. |

### 9.4 T-A6 — Bond funding

| | |
|--|--|
| **Question** | Does admission funding pattern link principal↔operator over `T_obs`? |
| **Analysis** | Lump principal→`P`→immediate join-Market is a **named** correlation beacon
(gate-6 §2.5, gate-4 §6). Over lifetime, repeated admissions or re-bonds could compound if
every bond posts from a fresh principal output adjacent to join. **Mitigation (designed):**
fund-from-earnings ramp — `P` accumulates operating outputs before join-Market; spacing from
principal activity; ordinary FCMP++ stake-in privacy on each leg. Multi-`P` admissions must
not share a single visible funding pattern (feeds T-A7). Portfolio tracking is orthogonal —
funding layer must not add a **stronger** link than one-time transfer hygiene accepts. |
| **Residual** | Exact ramp policy (epochs of earnings before join, min outputs) — wallet
default pin with gate-6 Round 4. Release cooldown vs `W` at timing pin. |
| **Disposition** | **CONDITIONAL PASS (shape)** — fund-from-earnings ramp defangs standing
join beacon; numeric ramp **pending** gate-6 Round 4. |

### 9.5 T-A7 — Cross-pseudonym intersection

| | |
|--|--|
| **Question** | Without per-`P` hygiene, can adversary merge `P_i`↔`P_j` as one operator
over `T_obs` beyond portfolio coincidence? |
| **Analysis** | **Channels:** (1) **Portfolio** — if same operator rotates `P` with fixed
storage, portfolios match exactly → merge is **certainty** (F1 honest residual; not a
firewall failure). (2) **Simultaneous multi-`P`** without hygiene — shared funding beacon,
shared network endpoint, aligned emission clocks → trivial merge; gate-6 invariant 5
requires **per-`P`** discipline. (3) **Timeline** — de-weighted (T-A1 empty at lean eq).
**Under wallet defaults** (per-`P` network/timing/output/funding hygiene for multi-`P`):
distinct `P` instances present as independent public actors; portfolio coincidence base rate
at lean eq is ~unique portfolios — accidental merge probability negligible. Deliberate
no-hygiene multi-`P` is **operator error** — documented unsafe posture, not protocol gap. |
| **Residual** | Wallet must loud-fail or warn when user operates multiple `P` without
hygiene separation. |
| **Disposition** | **PASS (qualitative)** under per-`P` hygiene defaults. Portfolio-equal
merge across cosmetic rotation is **in-scope F1 residual**, excluded from T-A7 fail. |

### 9.6 T-A2 — E-4 cosmetic rotation (closure)

Cosmetic rotation with fixed storage: **portfolio re-link confirmed** (`ta1_f1_cosmetic`,
overlap 0.957). Timeline irrelevant. This is **F1 residual disclosure**, not a T-A3–T-A7
failure. E-4's *network/timing/output* break requirements remain load-bearing for
principal↔`P` firewall; portfolio persistence is the accepted public-identity consequence
of gate-3 Form C.

### 9.7 Gate-6 invariant 4 — T-A1 supersession note

Invariant 4 ("rotation is not cosmetic" via epoch-adjacent retention + shard-set) is
**superseded on the portfolio/timeline leg** by T-A1: cosmetic rotation with fixed storage
is rational and re-linkable on portfolio. The **network fingerprint** leg of invariant 4
remains load-bearing — `P_new` must not share principal clearnet path. Amend at gate-6 Round 3
land; do not re-litigate portfolio publicity.

### 9.8 Aggregate F1 disposition

| Item | Result |
|------|--------|
| T-A3 | PASS (qualitative) |
| T-A4 | CONDITIONAL PASS — timing-cluster pin |
| T-A5 | PASS (qualitative) — drain spacing pin with Round 4 |
| T-A6 | CONDITIONAL PASS — funding ramp pin with Round 4 |
| T-A7 | PASS (qualitative) — per-`P` hygiene default |
| **Form-C reopen** | **Not triggered** — no layer fails under disciplined defaults |
| **F1 final accept** | **Conditionally accepted** — lands when T-A4 numeric pin + gate-6
Round 3–4 wallet defaults are pinned. Until then: **provisionally accepted + disclosed residual**. |

**Decision tree outcome:** accept-and-harden. The primary `P`↔principal firewall survives
lifetime-length observation **provided** wallet defaults ship as designed. F1 portfolio
residual is **disclosed**, not mitigated by rotation or cohort forcing.

---

## 10. Wallet / FOUNDATION disclosure (draft)

> **Archival pseudonym hygiene**
>
> Your deep shard holdings are **public on chain** (by protocol design). At typical operating
> conditions, archivers hold **distinct** shard portfolios; your portfolio functions as a
> **persistent public identity** for your archival operation.
>
> - Rotating `P` **without changing** what you store does **not** decorrelate you — an
>   observer can link rotations by portfolio.
> - Decorrelation requires changing your stored shard set, which abandons scarce-shard
>   income and pays a re-sync cost.
> - The `P`↔principal firewall (onion serving path, decorrelated funding/drains, emission
>   batching) is designed to prevent linking your **personal wallet** to your **archival
>   pseudonym** over your full operating lifetime — not just one rotation period.
> - Operating **multiple** `P` without per-`P` hygiene (separate funding, network path,
>   timing) allows cross-pseudonym intersection.

Pin in gate-6 Round 4 + wallet UX; cite [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md).
