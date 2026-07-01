# Principal stake / unstake / drain lifecycle (design — Round 1)

**Status:** Round 1 — DQ closure (advanced 2026-07-01 from the 2026-07-01 Round-0
scoping). Round 0 named the surface and enumerated DQ1–DQ6; Round 1 **closes DQ1,
DQ2, DQ5, DQ6 on already-pinned substrate** and **re-gates DQ3, DQ4 to gate-6 Round
4** (with named reopening criteria), freezes the method signatures (A1), sketches the
PR map, and pins the discipline citations. **No implementation is authorized by this
doc.** The *method-surface contract* closes at Round 1; *code* for the value-bearing
legs (bond-post / drain) remains gated on **Gate-6 R4 + the bond connect-path code**
(not the FSM/sim — that is sealed; §5). This is the plan-home for the **user-facing**
economic staking surface named unscoped in `WALLET_REWRITE_PLAN.md` Phase-2.
**Closure posture:** the Round-0-opened DQ set is closed (DQ1/2/5/6) or deferred with named
gates (DQ3/4) — this is the closure milestone; the single Round-1 entry question (§3.1
one-shared-derivation) and inherited carries are enumerated in §5.1. The **Round-1 opening read
(§5.2, 2026-07-01)** has since resolved §3.1 toward "already structural — wire it, don't unify"
(the shared draw exists in `shekyl-standoff`); the residual is `C_min` single-sourcing, gated on 2d-1.

Process discipline: [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
(cited explicitly — consensus-adjacent multi-round surface). A2 (audit-against-actual-code)
is load-bearing here: every "built / not built" claim below was **verified against
`dev` at Round-1 open**, and three Round-0 claims were falsified by substrate (§0.1).

**What this is / is not.** This is the **principal** (human-facing) lifecycle: stake
in, top up / partially unbond, unbond, drain rewards back to yourself. It is **not**
the archival persona `P` bond/scan machinery — that is
[`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §3 (the `P`-state FSM),
[`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md), and the **built** `StakeEngine`
actor. This doc sits one layer up, at the orchestrator.

## 0. Binding framing (do not re-litigate)

- **Write against the rebased §2.4/§3 model, never the claim-era body.** The
  confidential-principal design (`StakeInstance`, `stake()` / `claim()` /
  `unstake()`, tiers, entitlement, nullifiers) is a **deletion target**
  ([`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §2.1 *Delete* table;
  §4–§6 body is stale — `SECTION_4_CLAIM_ERA`). A method carrying `claim` / `tier` /
  `StakeInstance` is wrong by construction.
- **The principal has no consensus FSM of its own.** Its lifecycle is **ordinary
  `RCTTypeFcmpPlusPlusPqc` transfers** to/from `P` plus firewall discipline. The only
  consensus-special legs belong to `P`: the gate-4 `txin_archival_bond_post` (bond
  post/debit) and the reward-emission mint. The consensus FSM belongs to `P`
  (`AdmissionPending / Bonded / Slashed / Exited`; FSM-retool P2B-4).
- **Secret-locality (rule 36 / gate-6 §9.6).** `P.view_sk`, `P`'s spend material, and
  `bond_spend_sk` never leave the `StakeEngine` actor — a property now **confirmed in
  code** (§0.1), not aspirational. Principal-side transfer building routes through
  `KeyEngine` / `PendingTxEngine`; only signed vins / public views / scalar
  projections cross the boundary.
- **No consensus or wallet minimum on admission** (gate-7 closed bonds-only; gate-6
  §2.5 no-minimum-at-any-layer pin). Stake-in is value movement, not a consensus action.

### 0.1 Substrate re-check (A2 — Round-1 open, `dev`)

Three Round-0 claims were **overstated on the "unbuilt" side** and are corrected here
so Round 1 designs against what exists, not against the scoping doc's caution:

| Round-0 claim | Substrate finding (`dev`) | Correction |
|---------------|---------------------------|------------|
| "None of [the method surface] exists today (only three `StakeInstance` future-work comments)" | `StakeEngine` actor is substantially built: `StakeEngineHandle::spawn` + `impl Message` for `MintPersonaHandle` / `ActivatePersona` / `ActivePersona` / `SignBond`→`JoinMarketVin` / `ScanStep` / `RetireBondedPersona` ([`stake_engine.rs`](../../rust/shekyl-engine-core/src/engine/stake_engine.rs) L915–L1169) | The **`P` persona/bond substrate is landed**; what is missing is only the **principal orchestrator surface** (`stake_in` … `drain` / queries) |
| `P` HKDF derivation is a gate-6 Round-1 lone carry ("not yet built") | `ArchivalPKeys` + derivation **built** in [`archival_p.rs`](../../rust/shekyl-crypto-pq/src/archival_p.rs) (23 KB); `bond_spend_sk` present; `BondPostKind::JoinMarket { bond_spend_pk }` serializer in [`shekyl-wire`](../../rust/shekyl-wire/src/transaction.rs) | `P` derivation + the bond-post **wire serializer** are not a blocker; the gap is the non-JoinMarket **connect-path** verify + the principal driving methods (§5 gate 2) |
| Secret-locality of `P` keys is a forward requirement on the retool | `StakeEngine` already **owns** `spend_sk`/`view_sk`/`ml_kem_dk`/`hybrid_sign_sk`/`bond_spend_sk` (ArchivalPKeys, never `Clone`, `ZeroizeOnDrop`); emits `JoinMarketVin` / `ScanStepResult`, never keys | DQ2 is **confirmed by the built actor**, not a design still to make |

The orchestrator is `Engine<S,D,L,E,R,P,F>` ([`engine/mod.rs`](../../rust/shekyl-engine-core/src/engine/mod.rs) L403), holding `key: KeyEngineHandle` (L452), `pending: P` (L522), `stake: Option<StakeEngineHandle>` (L681). Principal transfers already build through `Engine::build_pending_tx_async` → `PendingTxEngine::build` → `KeyEngine` sign ([`pending.rs`](../../rust/shekyl-engine-core/src/engine/pending.rs) L841). **The principal surface is a composition layer over primitives that already exist**, not a new engine.

### 0.2 Structural principle — projection-and-gate over `P`'s observed FSM (the design spine)

The principal has no consensus FSM (§0); the **positive, load-bearing** statement is
stronger: **the principal lifecycle is a projection-and-gate over `P`'s scan-observed
consensus FSM, not an independent state machine.** The orchestrator is a **read-model**
over `P`'s public FSM (`AdmissionPending / Bonded / Slashed / Exited`, derived by the
`StakeEngine` scan) **plus a validity gate** on human actions — it *observes* `P`'s
consensus state and *refuses* actions `P`'s state does not permit; it never drives that
state. Every principal action is gated on the observed state: `unbond()` is valid only
when `P` is `Exited` post-cooldown; `drain()` reads `P`'s non-escrowed outputs;
`unbond_readiness(P)` is a countdown off `P`'s observed exit + the cooldown constant.

**Make-bad-states-unrepresentable target (rule 05 / rule 18).** A principal action must be
**constructible only from a `P`-FSM-state token that permits it**, so "unbond a still-`Bonded`
`P`" is *unrepresentable*, not runtime-checked. This is **already the built actor's
discipline**, not a new invention: `RetireBondedPersona` is constructible only with a
`RetirementWitness` ([`stake_engine.rs`](../../rust/shekyl-engine-core/src/engine/stake_engine.rs)
L274 / L1151), and `SignBond` consumes a **single-use** `PersistedBondTicket` (L400 / L1040).
Round 1 extends the same pattern to the principal surface — e.g. `unbond()` takes an
`ExitedConfirmed` witness minted from the scan-observed FSM, the sibling of
`RetirementWitness`. This principle sharpens **DQ2** (orchestrator = read-model + gate;
actor = secrets + bond path) and **DQ5** (the queries *are* that read-model).

## 1. The four principal↔`P` legs (all transfers except the bond post)

Per [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §2.4 tx-legs table:

| Leg | Tx shape | Notes |
|-----|----------|-------|
| **Stake-in** | ordinary FCMP++ transfer, principal → `P` stealth outputs (main tree) | privacy = base FCMP++; **no minimum** (DQ1); GF-7 funding shape/timing discipline applies |
| **join-Market / re-bond / holdings-update / unbond** | `txin_archival_bond_post` (gate 4, the only consensus-special `P`-identity leg) | `post_kind` table in [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §3.2 |
| **Reward emission** | special mint leg (membership-only backing + work payload) | **not a principal action** — consensus mints to `P`; see [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) |
| **Reward sweep / terminal drain** | ordinary FCMP++ transfer(s) `P` → principal | **decorrelated, output-count-disciplined** (GF-4, DQ3); bond returns via gate-4 `Unbond`, **not** the drain |

## 2. Method surface (Round-1 — signatures frozen per A1, bodies gated)

Layered on the orchestrator `Engine<…>` over the built `StakeEngineHandle`
(`spawn` / `mint_persona_handle` / `activate_persona` / `active_persona` / `sign_bond`
→ `JoinMarketVin` / `scan_step` / `retire_bonded_persona`). **A1 function-body
replacement contract:** the signatures below freeze **now**; each lands as an
`unimplemented!()` / NOP body behind its gate (§5) and is filled in place by the PR
that owns it (§4a PR map) — no signature churn between "surface" and "implement."

- **`stake_in(amount) -> PendingTx`** — ordinary FCMP++ transfer principal → the active
  `P`'s stealth receive address (from `ActivePersona`/`PersonaIdentity`). No band /
  range-proof / tier / minimum (DQ1). Composes `build_pending_tx` + `KeyEngine`;
  **touches no `P` secret** (`P` appears only as a public recipient address). GF-7
  funding-shape hygiene (DQ4) is a wallet-local default, not a consensus gate. **Cold-start
  bond funding is structured `bond_floor + cover`** (not arbitrary) and originates the SP-7
  cover the built `CoverDiscovery` must later detect — cross-surface contract in §3.1.
- **`fund_bond` / `join_market(shards) -> PendingTx`** — drives the **existing**
  `StakeEngine::SignBond` → `JoinMarketVin` (built; `#[allow(dead_code)]`/inert until
  the driving path is activated) + submit. Signs with `P`-identity + funding inputs
  **inside** `StakeEngine`; only the signed vin crosses the boundary.
- **`partial_unbond(shard) -> PendingTx`** — voluntary `HoldingsUpdate` drop (gate-4
  `post_kind = 3`, `bond_debit = FLOOR`). **NEW** `StakeEngine` bond-debit message op
  (signs against committed `bond_spend_sk`, gate-6 §9.6). **Genesis-scope (V3.0)** —
  see §5.
- **`unbond() -> PendingTx`** — terminal collateral return (gate-4 `post_kind = 2`),
  only from `Exited` post-cooldown; refund at `bond_floor`. **NEW** `StakeEngine`
  bond-debit op (signs `bond_spend_sk`).
- **`drain(to_principal) -> Vec<PendingTx>`** — the decorrelated `P` → principal exit.
  **Not a single tx** — multiple outputs / txs under GF-4 output-count discipline
  (DQ3). Consumes `P`'s **non-escrowed** outputs only. **NEW** `StakeEngine` `P`-spend
  op (uses `view_sk`/per-output spend from the `ScanStep` identification) feeding
  `PendingTxEngine`.
- **Query surface** — owner-grade, secret-free projections returning **View** structs:
  `principal_stakes()`, `bonded_holdings(P)`, `drainable_balance(P)`,
  `unbond_readiness(P)` (cooldown countdown). Report emission **receipts**, not claim
  entitlements. Secret-locality per DQ5.

## 3. Firewall discipline this surface must enforce (load-bearing)

- **GF-4 — decorrelated-drain output-count discipline.** The delay floor is pinned
  (`≥ RELEASE_COOLDOWN_EPOCHS × SETTLEMENT_EPOCH_BLOCKS` ≈ 28 days,
  [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) §7); the **open** piece
  is the output-count rule — *a single lump sweep re-links reward history to one
  principal cluster even with the delay satisfied* (gate-6 §2.4). **Recurring** exit
  (terminal drain **and** `HoldingsUpdate`), gate-6 Round 4. Blocks `drain()`/`unbond()`
  — DQ3.
- **GF-7 — principal→`P` bond-funding structural distinguishability.** Lump funding
  from a fresh principal output immediately before first emission/join is a correlation
  channel (gate-6 §2.5). Disposition (fund-from-earnings ramp vs lump) is gate-6 Round 4
  — DQ4. **No funding minimum at any layer** is already pinned (gate-6 §2.5).
- **GF-10 — within-epoch timing** now applies to bond ops, not just emission (gate-6
  §6 Round-4 re-scope).

### 3.1 Cover-form cross-surface contract — `stake_in` ↔ SP-7 `CoverDiscovery`

**Wire-frozen dissociation (GENESIS §2.0, Q11).** The bond floor is **public but
covered-and-dissociated**: the principal sends `bond_floor + cover (+ operating capital)` to
`P`; `P` stakes the floor and holds the **`cover`** as a **confidential change-to-`P`
output**. So `stake_in`'s cold-start bond funding is **not an arbitrary-amount transfer** —
its amount is structured, and the `cover` output it originates **is** the SP-7 **cold-start
cover** whose absence induces the **TM-3 re-link** and which the **built** `CoverDiscovery`
([`cover_discovery.rs`](../../rust/shekyl-engine-core/src/engine/pscan/cover_discovery.rs))
detects on the `P` side. `stake_in` is the **origination** of that cover; `CoverDiscovery`
is its **detection** — one design split across two surfaces, which must agree by construction.

**Verified at source — the contract is a recovery-path + window + entropy-draw agreement,
NOT a shared wire type.** The intuitive "one shared cover type" target does **not** hold, and
*why* is load-bearing: the wire deliberately gives the cover **no special field** — it is "an
ordinary confidential `tagged_key` output" (GENESIS §2.0) — for the **identical
anti-fingerprint reason DQ1 rejects `C_stake`** (a special cover field would itself
distinguish the funding tx). Consequently:

- `CoverDiscovery::classify(cover_window, cover_found: Option<BlockHeight>, covered)`
  consumes an **`Option<BlockHeight>`**, not a cover struct; the cover output is recovered
  **generically** by `P`'s dual-scan (`scan_output_recover_with_ml_kem_dk`) like *any* `P`
  output — SP-7 does not build or type the cover (module docs, `cover_discovery.rs`).
- So the cross-surface invariant is that the cover `stake_in` emits must be **(a)** recoverable
  by the same `P` dual-scan `CoverDiscovery` reads (automatic — it is an ordinary output to
  `P`'s address), **(b)** landed in the `cover_window` `CoverDiscovery` classifies over, and
  **(c)** dissociating by the **entropy of the cover-amount draw** (`shekyl-standoff`; GENESIS
  §2.0 "the cover defense reduces entirely to the entropy of the cover draw" — a
  genesis-adjacent security crux to pin before bond-tx assembly). *Which* output is the cover
  is the principal's **owner-local bookkeeping** (DQ5 `principal_stakes()`), not an on-wire
  marker.

**Make-bad-states-unrepresentable (rule 05) — corrected target.** Because the cover has no
special form, there is no cover struct to get wrong; the seam's robustness comes from "any
output `stake_in` sends to `P` is recovered by the same scan," so a `stake_in` cover the scan
cannot see is nearly unrepresentable. The residual is **window/timing + the entropy draw** —
and the built `CoverDiscovery` already forecloses the *silent* re-link: a wrong `Found` trips
a `debug_assert` (recovered cover outside the window), and `AbsentVerified` authorizes only a
re-fund **consideration** — never an auto-re-fund — and only with a `TipCurrencyToken` +
operator decision (`refund_consideration`; TM-3). So the Round-1 obligation here is to **pin
the cover-draw entropy and funding-window semantics as the shared parameters** (jointly with
2c-2b bond-request assembly, [`ARCHIVAL_BOND_REQUEST_2C2B_PLAN.md`](ARCHIVAL_BOND_REQUEST_2C2B_PLAN.md)
§SP-2.d), **not** to invent a shared cover type.

**One shared derivation, not two-plus-a-KAT (the Round-1 entry question).** The relocated
unrepresentability is subtler than a witness type: with no cover type, the target is not
"forbid a bad cover value" but **"forbid the send path and the scan path from drifting"** —
the output `stake_in` builds and the output `P`'s dual-scan recovers must derive from **one
shared construction**, not two that happen to agree. If they are **one** tagged-key
constructor both sides call, the sameness is *structural* (unrepresentable); if they are two
functions with a KAT asserting agreement, that is the *weaker* form — drift compiles clean
between KAT runs (the Track-B generator-KAT failure mode). §3.1's contract must pin **which**,
and the **cover-amount entropy draw specifically wants the single-shared-derivation
treatment**, not assert-two-agree: an entropy draw the send and scan/window paths compute even
slightly differently is a silent correlation or a missed cover that no type check catches.
**This is the Round-1 entry question for this surface** (§5.1).

## 4. Round-1 dispositions (DQ1–DQ6)

### DQ1 — no principal-side committed-stake wire survives. **CLOSED (plain transfer).**

**Decision.** Stake-in is a **plain ordinary `RCTTypeFcmpPlusPlusPqc` transfer**,
principal → `P` stealth outputs on the main tree. **No `C_stake`, no range proof, no
band, no minimum.** The §2.1 "principal role open" reopen-pointer is **retired**. This is
**not merely a reasoned Round-1 disposition — it is the frozen genesis wire**:
[`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) §2.0/§2.1 (**Q11, locked
2026-06-20**) sheds cleartext `txout_to_staked_key` + `txin_stake_claim` and makes staking
transfer-shaped admission under `P` — transfer legs + the gate-4 bond post, **nothing
else**. The bond floor is public but **covered-and-dissociated**, not a hidden stake (§3.1).

**Rationale — the committed-stake alternative is *strictly dominated*, not merely
disfavoured (four independent legs, any one sufficient):**

1. **The consumer is deleted.** `C_stake` / range-proof / band existed only to serve
   the confidential-yield / entitlement superstructure (exact-yield = secret-weight ×
   public rate). The rebase replaces reward with a work-scored mint to `P` (emission
   leg §4); no reward path reads a principal stake amount. `band` + `band_sum` are on
   the *Delete* table (PHASE_2B §2.1).
2. **No consensus predicate reads the amount.** Gate-7 closed **bonds-only** with no
   `ADMISSION_MIN_ATOMIC` and no admission proof (emission §7.4/§10.2; sim ledger G7).
   A range proof proves `amount ≥ min` — with no minimum, it proves nothing. Sybil
   pricing is `bond_floor × shards` at join-Market, not `P`-balance.
3. **A committed-stake wire *breaks* the firewall it would purport to serve.** Stake-in
   must be **byte-indistinguishable from an ordinary transfer** (§2.4 "indistinguishable
   from normal transfers on-chain"; gate-6 §9.6 invariant 1). A `C_stake` artifact is a
   *distinguisher* that fingerprints stake-in, converting a private funding transfer
   into a labelled one. The amount is already hidden by the transfer's own output
   commitment (base FCMP++/RingCT amount privacy) — `C_stake` is redundant *and*
   harmful.
4. **It is spec-only debt.** `C_stake` has **no C++ symbol** (REWARD_EMISSION_VIN_PLAN
   §5; gate-6 §1 "Entitlement / `C_stake` / 3C subtree — Deleted"). Retiring it deletes
   *planned* work, not shipped code (rule 16 — inherited-from-own-prior-design flow that
   contradicts the rebased threat model is *migrated, not rationalized*).

**Reversion clause (rule 21) — at genesis-tag level.** Reopen **iff a future V3.x consensus
rule reads the principal stake amount** (e.g., an emission rule keyed on principal balance,
or a demonstrated need to prove a per-principal stake bound). Not reopened by "uncertainty
about future flexibility" — that is the rule-21 optionality-debt anti-pattern that gate-7 /
gate-6 §2.5 already rejected on the sibling admission-minimum question. **Bar note:** because
plain-transfer *is* the frozen Q11 genesis tag decision (above), reopening it is a
**genesis-seal / genesis-tag change**, not a Round-1 design edit — a materially higher bar
than "reopen if a minimum emerges."

**Forward-action (A5 — doc sweep).** [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md)
Q11 (`0x04 txout_to_staked_key`) still described the principal as "a `C_stake` Pedersen
commitment kept off-wire in the wallet's `StakeInstance`" — **stale claim-era text this
decision falsifies**. Corrected in the Round-1 doc sweep to "no principal commitment on-
or off-wire; stake-in is a plain FCMP++ transfer" (retraction hygiene — a decision is
not closed until every artifact reflects it).

### DQ2 — attachment point. **CLOSED (orchestrator method surface; `P`-secret legs delegate to `StakeEngine`).** Confirmed by substrate.

**Decision.** The method surface **attaches at the orchestrator** (`Engine<…>`), which
holds the engine handles and *sequences* them. The orchestrator holds **no secrets**.
Secret-touching work splits by *whose* secret it is, and executes inside the owning
actor:

| Method | Secret touched | Executes in | Crosses boundary as |
|--------|----------------|-------------|---------------------|
| `stake_in` | principal spend/view | `KeyEngine` + `PendingTxEngine` (built path) | signed principal tx; `P` = public recipient address |
| `fund_bond`/`join_market` | `P`-identity + funding inputs | `StakeEngine::SignBond` (built) | `JoinMarketVin` (signed) |
| `partial_unbond`/`unbond` | `bond_spend_sk` (debit authorizer) | `StakeEngine` bond-debit op (NEW) | signed bond-debit vin |
| `drain` | `P.view_sk` + `P` per-output spend | `StakeEngine` `P`-spend op (NEW), from `ScanStep` id | signed `P` spend vin(s) |
| queries | `P.view_sk` (only `drainable_balance`) | `StakeEngine` | scalar / View struct (§DQ5) |

**Refinement of the Round-0 sketch.** Round-0 said principal methods attach at the
orchestrator "**not** on the `StakeEngine` actor." That is right for `stake_in` but
incomplete for the bond-debit and drain legs: those are **`P`-secret operations that
must execute *inside* `StakeEngine`** (rule 36 — `P.view_sk`/`bond_spend_sk` never
leave the actor). The correct statement: the *methods* attach at the orchestrator; the
*`P`-secret sub-steps* delegate to `StakeEngine`, which returns signed vins / views —
never raw `P` keys pulled up to the orchestrator. This is **already the built shape**
(`SignBond`→`JoinMarketVin`, `ScanStep`→`ScanStepResult`; §0.1) — Round 1 only extends
it with two new debit/spend message ops.

**Rationale.** Rule 36 (secrets in Rust, held by their owning actor) + rule 00
priority-1 (security): compromise of the orchestrator reveals no `P` key; compromise of
`P`-identity reveals nothing spendable (bond debits go through the domain-separated
`bond_spend_sk`, gate-4 §4.1 / gate-6 §9.6). No new secret ever lands in the orchestrator.

### DQ3 — drain output-count discipline (GF-4). **RE-GATED to gate-6 Round 4.**

**Decision.** Cannot close at Round 1 — the numeric/shape pin is a **gate-6 Round-4
hard exit** (gate-6 §6). This is a firewall-**design** gate, **not** an FSM or sim gate:
the rebond/unbond FSM design is pinned (P2B-1..7) and the R-3 age-stratified
bond-mobility sim that gated the seal is **CLOSED** (sealed 2026-06-16, zero parameter
change, [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §L18) — see §5. `drain()`/
`unbond()` bodies stay `unimplemented!()` until GF-4 is pinned (shipping a lump sweep
before GF-4 ships a correlation beacon, gate-6 §2.4).

**Second and third dependencies — the emission output shape *and* its wire freeze (F3).**
DQ3's *concrete count rule* is also co-sequenced with the reward-emission leg (§5 gate 3):
the drain **consumes emission outputs**, so their form (how many, what stealth shape,
escrowed vs non-escrowed) is what GF-4's output-count discipline operates *over*. Sharper
still, the emission vin is a **deferred sub-freeze (F3)** — its genesis tag is pinned
(`0x04` dense / `0x06` C++) but the **leg is not in code yet**, "a forward promise, not a
freeze" ([`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) §2.1; layout owned by
[`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md)), so the count rule cannot be
finalized against an **unfrozen output byte-shape**. The firewall **intent** (no lump sweep,
decorrelated temporal spacing) is designable now; the concrete count rule waits on **gate-6
R4 *and* the emission output shape *and* the emission wire freeze (F3)** — a **three-way**
deferral, with F3 the tightest (it is on the critical path to the drain).

**Sequencing consequence.** Because F3 (the emission output byte-shape) is the tightest and
its leg is **not in code**, DQ3 is not merely deferred but **sequenced last** of the three:
gate-6 R4 and the emission output *shape* can both be pinned while F3 stays open, but F3 cannot
close until the emission leg **exists**. So DQ3's critical path runs **through the emission
leg's implementation** ([`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md) **PR-E3**),
**downstream** of it — not parallel. Do not scope DQ3 as closeable before the emission leg lands.

**Axes R4 must decide** (named now so R4 is a decision, not a discovery):
`fixed-count` (a fixed `N` is itself a fingerprint and does not scale with amount) vs
`amount-scaled` (leaks magnitude via count) vs `jittered-within-band` (best, but must
not mint dust or an identifiable "`P`-drain" size signature).

**Round-1 lean (for R4, not binding).** Because Shekyl has a **single static principal
address** (FA-1, no subaddresses), all drain outputs share one recipient — so
output-count-across-addresses buys nothing; the decorrelation that matters is **temporal
spread across multiple txs** (each independently mixed in the FCMP++ set) plus the pinned
delay floor, not a per-tx output fan-out. Lean: **jittered tx-count over the release
window**, output count per tx bounded to avoid a size fingerprint; the `HoldingsUpdate`
partial-unbond refund rides the same discipline (gate-6 §2.4). This is **non-consensus
wallet-local**, so it can be prototyped as a default as soon as GF-4 pins its shape.
**Joint-with-rotation (from §5.1 item 2):** because drain-and-rotate co-triggers GF-4 and the
persona-rotation network break, the concrete count rule must be **jointly** uncorrelated with
the new-`P` first-on-network timing — not merely independently well-behaved.

### DQ4 — bond-funding shape (GF-7). **RE-GATED to gate-6 Round 4.**

**Decision.** The **no-minimum-at-any-layer** half is already **closed** (gate-6 §2.5);
the **ramp-vs-lump** half is a gate-6 Round-4 hard exit (recurring — first join *and*
rebond-topup), a firewall-**design** exit (the FSM/sim is sealed, §5). Re-gated with a
named lean.

**Round-1 lean (for R4, non-binding, non-consensus).** Two regimes:
- **First join (bootstrap).** `P` has no earnings yet, so the first bond *must* come
  from principal funding. Discipline: **≥ 1 settlement-epoch separation** between the
  principal→`P` funding transfer and join-Market (timing-constants §7) + sourcing jitter
  — not a fresh principal output spent immediately into the bond.
- **Recurring rebond-topup.** Prefer **fund-from-earnings ramp** (≥ 2 settlement epochs
  of `P`-local earnings, timing-constants §7 / T-A6) over a fresh principal→`P` lump, so
  top-ups do not re-open the principal→`P` correlation channel each rebond.

`stake_in` (DQ1) is the wallet primitive both regimes drive; the *timing/shape policy*
sits above it and is what R4 pins.

### DQ5 — query-surface secret-locality. **CLOSED.**

**Decision.** All four queries return **owner-grade View structs**, never openings or
keys (inheriting the claim-era R0-D3 discipline: list/query messages return `*View`
only). Disposition per projection:

| Query | Data source | Secret? | Boundary crossing |
|-------|-------------|---------|-------------------|
| `bonded_holdings(P)` | public `ArchivalBondRecord` (P_canonical_id-keyed consensus state) | **No** — public | bond-record cache read; no actor round-trip needed |
| `unbond_readiness(P)` | `last_served_epoch` (public bond field) + `RELEASE_COOLDOWN_EPOCHS` | **No** — public + arithmetic | derived countdown |
| `drainable_balance(P)` | `P`'s non-escrowed output set (needs `P.view_sk` scan) | **Yes** | computed **inside `StakeEngine`**; returns an **aggregate `Amount` scalar** — `view_sk` and per-output secrets never leave |
| `principal_stakes()` | wallet-local bookkeeping (which `P`s the principal funded) | **Owner-grade** | **the P↔principal linkage itself** — owner-local only; **must never cross RPC / diagnostic / log surfaces** (gate-6 §5 / §9.6 invariant) |

**Rationale.** All four queries *are* the §0.2 read-model — projections, never drivers.
Three project **public bond state + the principal's own ledger** (`bonded_holdings`,
`unbond_readiness`, `principal_stakes`); `drainable_balance` projects the `StakeEngine`'s
**`P`-scanned ledger** — `P.view_sk` is used at *scan* time (`ScanStep`), never at query
time, and only the aggregate scalar crosses. **No query crosses a `P` secret.**
**Wire-confirmed (two-paths-one-answer):** the split maps onto the frozen wire —
`bonded_holdings` projects on-chain public state (`bonded_total_atomic == bond_floor` on the
bond-post arm, GENESIS §2.5), while rewards are stealth emission outputs to `P`, so
`drainable_balance` needs the scan. The wire produces the same split reasoning did.
`principal_stakes()` *is* the firewalled edge (P↔principal↔human) — it is
the one projection whose leakage defeats the whole model, so it is owner-local and
RPC-forbidden, matching the recalled principle that the firewall protects **only** the
P↔principal edge (`P`'s own shards/rewards are public by design). The single
secret-dependent computation (`drainable_balance`) executes in the actor that owns
`P.view_sk` and emits a scalar — the same "secret work in, projection out" shape the
built `ScanStep` already uses. **Report receipts, not entitlements** — there is no
claim-era entitlement projection to expose.

### DQ6 — `shekyl-staking` deletion sequencing (rule 15). **CLOSED (two-phase schedule).**

**Substrate (A2, `dev`):** `shekyl-staking` is a compiled workspace member with **mixed**
dependents — the deletion is not uniform:

| Symbol | Non-crate production refs | Disposition |
|--------|---------------------------|-------------|
| `StakeRegistry`, `StakeEntry` (`registry.rs`) | **0** | **Tier A — dead now** |
| `distribute_staker_rewards` (`rewards.rs`) | **0** | **Tier A — dead now** |
| `entitlement.rs` | **0** (one doc-comment mention) | **Tier A — dead now** |
| `StakingMeta` (`meta.rs`) | **36** (shekyl-scanner `WalletOutput.staking`, engine-core) | **Tier B — live; migrate consumers first** |
| `LockTier` / `StakeTier` / `TierTable` (`tiers.rs`) | 30 / 1 / 6 (scanner, `economics_snapshot.rs`) | **Tier B — live; migrate consumers first** |

**Schedule.**
- **Tier A (buildable now, rule 15 removal).** `registry.rs`, `rewards.rs`,
  `entitlement.rs` and their re-exports have **zero production dependents** → delete as a
  standalone removal PR **now**. This is dead confidential-era superstructure (reserve-DLEQ,
  pool-division rewards); keeping it is optionality debt and an accidental-reintroduction
  hazard (R0-D7 spirit).
- **Tier B (sequenced after the transfer-shaped-admission cutover).** `StakingMeta` /
  `LockTier` / `TierTable` are the **cleartext-tier** model wired into the scanner's
  per-output staking metadata and the economics tier-table snapshot. Under the rebase,
  staker-wide **tier** machinery is replaced by per-shard **bonds** (gate 4), and there is
  **no on-chain staked-output type** (GENESIS_TX_WIRE_FORMAT Q11 — outputs are ordinary
  stealth). So `StakingMeta`/`lock_tier` scanner recognition is **claim-era architectural
  inheritance to migrate** (rule 16), but its consumers must be cut **first** (scanner
  output path, economics snapshot) — that removal sequences with the emission/admission
  cutover (REWARD_EMISSION_VIN_PLAN PR-E4/E5 doc-sweep), **not** with this surface. **Do
  not build any principal method on Tier-A or Tier-B symbols.**

**Quarantine-then-delete, not delete-someday (ratified).** The live risk is *not* that the
targets linger — it is that the **new** principal surface accretes a dependency on them (an
`import StakeInstance`, a `tier` field) and re-entrenches them, making the rule-15 removal
harder. So Round 1 ratifies a **build-time guard**: the new principal module must not import
the claim-era types (`StakeInstance` / `claim` / `tier` / entitlement), turning "a method
carrying `claim`/`tier`/`StakeInstance` is wrong by construction" (§0) into a **mechanical**
check — a `clippy.toml` `disallowed-types` entry or a module-boundary import test, not a
review-time discipline. Tier-B symbols are re-pointed off their live consumers, *then* deleted.

**Rule-15 discipline:** per-commit build cleanliness (B5) — Tier A deletes cleanly today
(no dependents); Tier B is gated on its consumer migration so no intermediate SHA breaks
`cargo build`.

## 4a. PR-decomposition sketch

A1 freezes the §2 signatures; PRs fill bodies in place. Bundled by **validation surface**
(rule 19), not by method topic. "Buildable now" = behind the frozen contract only;
"blocked" names the gate.

| PR | Scope | Validation surface | Gate |
|----|-------|--------------------|------|
| **PR-P0** *(this doc)* | Round-1 ratification: DQ closes, frozen signatures, GF defaults as *directions*, GENESIS_TX_WIRE_FORMAT Q11 doc-sweep | design | **buildable now** — commit-direct-to-dev |
| **PR-P1** | `shekyl-staking` **Tier-A** deletion (`registry.rs` / `rewards.rs` / `entitlement.rs`) | removal (rule 15) | **buildable now** — 0 production deps |
| **PR-P2** | `stake_in(amount)` — ordinary principal→`P` transfer; **end-test = `P` dual-scan recognizes the funded output** (GF-2, real end-test not a unit stub) | ordinary-transfer + dual-scan boundary | frozen contract only; **first unblocked code cut**. Its worth is the GF-2 boundary test, not standalone user value |
| **PR-P3** | `fund_bond`/`join_market` — drive built `SignBond`→`JoinMarketVin` + submit | JoinMarket bond-post | **lightly gated** — JoinMarket **verify is built** ([`bond_post.rs`](../../rust/shekyl-archival-retention/src/bond_post.rs)); remaining = C++ transport/FFI wiring + activating the inert driving path. The lightest of the bond legs |
| **PR-P4** | `partial_unbond` + `unbond` — NEW `StakeEngine` bond-debit ops (sign `bond_spend_sk`) | bond-debit wire + release cooldown | **blocked** — non-JoinMarket **connect-path code** (`bond_post.rs` rejects them today, `PostKindNotJoinMarket`) + `bond_spend_pk` debit-auth verify + **gate-6 R4 GF-4/GF-7** (recurring) |
| **PR-P5** | `drain` — NEW `StakeEngine` `P`-spend op → `PendingTxEngine`, multi-tx | reward-output spend | **blocked** — **reward-emission leg** (outputs to drain don't exist until PR-E3 ML-DSA hard gate) **+ gate-6 R4 GF-4** |
| **PR-P6** | query surface (View structs); `bonded_holdings`/`unbond_readiness` read public cache; `drainable_balance` = `StakeEngine` scalar | owner-grade projection | rides its data sources (public-cache queries buildable with PR-P3; `drainable_balance` with PR-P5) |
| **PR-P7** | `shekyl-staking` **Tier-B** deletion (`StakingMeta`/`LockTier`/`TierTable`) after consumer migration | removal (rule 15) | **blocked** — scanner/economics consumer migration (emission/admission cutover) |

Forward-actions (A5): DQ3→gate-6 R4 GF-4 scaffold; DQ4→gate-6 R4 GF-7 scaffold;
Tier-B deletion → REWARD_EMISSION_VIN_PLAN PR-E4/E5 doc-sweep.

## 4b. Discipline citations (which principle binds which decision)

| Decision | Binding principle | Why |
|----------|-------------------|-----|
| DQ1 retire `C_stake`/band; retire reopen-pointer | **rule 16** + **rule 21** | inherited-from-own-prior-design flow contradicting the rebased threat model is *migrated, not rationalized*; the reopen-pointer is retired with a named reopening criterion, not kept as pre-provisioned flexibility |
| DQ1 amount hidden by base transfer, not `C_stake` | **rule 00 priority-2** | privacy is the firewall/indistinguishability property, not a redundant amount-hiding artifact |
| DQ2 orchestrator holds no secrets; `P`-legs in `StakeEngine` | **rule 36** + **rule 00 priority-1** | `P.view_sk`/`bond_spend_sk` stay in the owning actor; only signed vins/views cross |
| DQ3/DQ4 re-gate with reopening criteria | **rule 21** (via **rule 26** A5) | reject-now-with-reopening-criteria over pre-provisioned flexibility; forward-action to the gate-6 R4 scaffold |
| DQ5 queries return Views; `principal_stakes` RPC-forbidden | **rule 36** + **rule 00 priority-2** | the P↔principal edge is the one firewalled surface; secret computation returns a scalar |
| DQ6 delete dead staking stack; migrate live tier consumers | **rule 15** + **rule 16** | delete Tier-A dead code now; migrate Tier-B claim-era inheritance, don't build on either |
| §2 frozen signatures / NOP bodies | **rule 26** A1 | freeze the contract; body-replacement in place, no signature churn |
| §4a bundling by validation surface | **rule 19** | ordinary-transfer / bond-wire / reward-output are distinct validation surfaces |
| §0.2 projection-and-gate over `P`'s FSM; witness-typed actions | **rule 05** + **rule 18** | orchestrator is a read-model + validity gate, never a driver; bad states unrepresentable via `P`-FSM-state tokens (the built `RetirementWitness`/`PersistedBondTicket` pattern) |

## 5. Gates — determination and buildable-now slice

**Can the design close now, or is it gated on the FSM pin advancing first?**

**Determination: the design closes now — and it is *not* gated on the FSM/sim.**
Grounded against `dev` (correcting the coarse "blocked on the FSM pin" framing):

- The rebond/unbond **FSM design is pinned** — [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md)
  P2B-1..P2B-7 closed: the 4-state graph, all four `post_kind`s on one
  `txin_archival_bond_post`, custody-as-consensus-balance, the supply-conservation law,
  the cooldown-vs-`W` asymmetry, and the friction pins (per-shard cooldown,
  slashable-through-cooldown anti-dodge).
- The **sim reconciliation that gated the seal is CLOSED** — the R-3 age-stratified
  bond-mobility reconciliation was run, adversarially stressed, and **sealed 2026-06-16
  with zero parameter change** (genesis `c2` cleared all three seal gates; the deep-band
  floor held at `r_target_deep = 6`; [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md)
  §L18). **This surface is not waiting on more sim.**

So the DQ closures (DQ1/DQ2/DQ5/DQ6) ride on already-pinned substrate, and the two
re-gated DQs wait on **Gate-6 R4 firewall design**, not the FSM. The real remaining
gates, ordered:

1. **Gate-6 R4 firewall — the true remaining DESIGN gate for this surface.** GF-4
   decorrelated-drain **output-count** discipline and GF-7 principal→`P` bond-funding
   separation are open Round-4 exits, now **recurring** (a `HoldingsUpdate`/rebond fires
   them at every mid-life adjustment, not once); GF-10 jitter bounds is the Round-3 exit.
   These — **not** the FSM — block **DQ3** (drain output-count) and **DQ4** (bond-funding
   shape). Authority: [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) §2.4/§2.5,
   §6 R4.
2. **V3.0 connect-path CODE (not design).** Today only **JoinMarket** is implemented — the
   `BondPostKind` enum + wire codec round-trip all four, but
   [`bond_post.rs`](../../rust/shekyl-archival-retention/src/bond_post.rs) **rejects** any
   non-JoinMarket kind (`PostKindNotJoinMarket`). Rebond / Unbond / HoldingsUpdate each
   need a `verify_*` + FFI error cluster + builder; plus the `bond_spend_pk`
   debit-authorizer wire+commit+verify and the `archival_p` HKDF-label/KAT (GF-1), and the
   C++ `has_archival_bond_shard` `at_height` read fix (Pin 4). **This code IS most of the
   principal lifecycle's `fund_bond` / `partial_unbond` / `unbond` — same work, two
   labels.** Authority: [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §8.
3. **Reward-emission leg — paying-side cross-dependency only.** The drain consumes reward
   outputs that do not exist until emission is built, and the C-1 ML-DSA check gates
   *verifying* the `Bonded→emit` path — but **not** the bond-lifecycle connect paths
   themselves ([`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md); C-1 = PR-E3
   step 8). Blocks `drain`.

**BUILDABLE NOW (most of the Round-1 design round is unblocked):**

- **DQ1 / DQ2 / DQ5 / DQ6** — none depend on Gate-6 R4 or the connect-path code; the FSM
  shape they ride on is already pinned + sealed. Closed in this round.
- **This Round-1 ratification** (PR-P0) — pure design, incl. the GENESIS_TX_WIRE_FORMAT
  Q11 doc-sweep.
- **`shekyl-staking` Tier-A deletion** (PR-P1) — zero-dependent dead code, rule 15.
- **`stake_in` + its GF-2 dual-scan end-test** (PR-P2) — the thin unblocked edge: an
  ordinary transfer over built primitives + the real boundary test; gated only on the
  frozen contract.
- **Firewall-hygiene default *directions*** (DQ3/DQ4 leans) — non-consensus wallet-local;
  buildable as soon as GF-4/GF-7 pin their shape (gate 1), itself a design task, not a sim
  or code gate.

**Only DQ3 and DQ4 wait — and on Gate-6 R4 (GF-4/GF-7), not on the FSM.**

## 5.1 Round-1 entry questions & inherited carries (A5)

The Round-0-opened DQ set is **closed** (DQ1/2/5/6) or **deferred with named gates**
(DQ3/4); this is the closure milestone. What Round 1 inherits:

1. **§3.1 cover contract — one shared derivation vs two-plus-a-KAT (the entry question).**
   Pin whether the cover's send path (`stake_in`) and scan path (`CoverDiscovery`) are **one**
   shared tagged-key constructor (sameness *structural*) or two functions asserted equal by a
   KAT (sameness *tested*, drift-prone). The **cover-amount entropy draw** wants the
   single-shared-derivation treatment specifically. This is the line between "unrepresentable"
   and "tested." **→ Resolved by the Round-1 opening read (§5.2): already structural
   (`shekyl-standoff` exists) — the obligation is *wiring* + `C_min` single-sourcing, not a
   constructor unification.**
2. **Reward realization = drain-at-exit/rotation; there is *no* non-terminal sweep.** The built
   FSM treats **drain as terminal** (`Bonded`/`Slashed` → `Exited`, FSM-retool transition
   graph) — so a staker realizes returns by **draining-and-rotating** (new `p_slot`, gate-6),
   **not** a recurring in-place "sweep while still serving." This is deliberate: repeated
   non-terminal sweeps from one long-lived `P` to the principal build exactly the correlation
   trail GF-4 exists to prevent. Named so the §1 "reward sweep / terminal drain" leg is not
   mis-scoped as a standalone recurring method — the *only* realization primitive is `drain`,
   gated on `P` exiting.
   **Sim input (not just UX):** profit-taking = rotation, so **profit-taking cadence =
   persona-churn rate** — a **modeling input** to the pre-genesis-seal age-stratified
   bond-mobility reconciliation ([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §L18 / R-3),
   not a UX note: collect-in-place would hold one `P` indefinitely, drain-and-rotate cycles
   `P`s at a liquidity-driven cadence — different bond-age distributions, anonymity-set
   dynamics, and GF-7 load. Whoever re-runs the reconciliation must read "profit-taking =
   rotation" as an assumption, not rediscover it.
   **Second-order — co-triggered firewalls:** because every profit-taking drain **is** a
   rotation, GF-4 (decorrelated-drain output-count) and the persona-rotation firewall (per-`P`
   .onion / SOCKS isolation / sequential-succession break, 2d-2) fire on the **same event** and
   must be **jointly** uncorrelated, not merely independently well-behaved — if the drain
   spacing and the new-`P` first-on-network appearance are each fine but *jointly* correlated
   (the new `P` surfaces exactly as the old `P`'s drain completes), that linkage is a gap
   **neither firewall catches alone**. DQ3-adjacent: fold it into the GF-4 concrete rule when
   gate-6 R4 + the emission shape pin it.
3. **Witness-typed signatures (§0.2 made concrete).** Round 1 pins the `P`-FSM-state witness
   set the frozen §2 signatures consume — e.g. `unbond(ExitedConfirmed)`,
   `drain(DrainableConfirmed)` (valid from `Bonded`/`Slashed`) — the sibling of the built
   `RetirementWitness`.
4. **G1a grace-window surfacing in the query read-model (DQ5).** The read-model should surface
   the slash-grace / challenge-failure-pending **cure window** (FSM-retool R4 **G1a**,
   priority-1 UX) — a principal-facing read of `P`'s observed `good_standing`, not yet in the
   DQ5 query set. Failure-mode UX (rule 82) for refused actions is a Round-1+ concern.
5. **Multi-`P` portfolio — explicit scope boundary.** This doc scopes the **single-`P`**
   lifecycle. Multi-`P` orchestration (rotation ceremony, portfolio-wide drain, cross-`P`
   hygiene per gate-6 §4 invariant 5) is **out of scope here**, deferred to the rotation round.

## 5.2 Round-1 opening read — §3.1 resolved by substrate (2026-07-01)

The two §5.1-item-1 substrate reads were run at source. **Result: the entry question resolves
toward "already structural, use it," not "unify two call sites."**

- **The cover-amount entropy draw already exists as a single shared derivation.**
  `shekyl-standoff::draw_cover_amount` / `cover_dial_span_atomic`
  ([`cover.rs`](../../rust/shekyl-standoff/src/cover.rs)) is the single source, and the crate's
  own contract **is** the structural form: "the simulator, the published conformance vector, and
  (when the V3.0 funding flow is built) the wallet all import the **same** draw, so 'what we
  validated is what ships' holds **by construction rather than by vigilance**"
  ([`lib.rs`](../../rust/shekyl-standoff/src/lib.rs)). Pure-integer, golden-vector-pinned,
  build-float-free. So §3.1 is **not** a structural-vs-tested *choice* to make in the abstract —
  the structural form is built.
- **The output form is the standard construct/recover pair**, not a cover-specific type:
  `construct_output` ↔ `scan_output_recover_with_ml_kem_dk`
  ([`output.rs`](../../rust/shekyl-crypto-pq/src/output.rs) L193 / L811), round-trip
  byte-identity KAT'd (`scan_output_kat.rs`). The cover rides it like any output — confirming
  §3.1's no-special-field at the code layer.
- **The obligation is therefore *wiring*, not derivation-unification.** `draw_cover_amount` has
  **no production consumer yet** (only `shekyl-staking-sim`, a dev-dep + cross-checked copy; the
  V3.0 wallet funding flow is unbuilt). When it lands, `stake_in`'s cold-start cover **must
  import `shekyl-standoff`, never an ad-hoc draw** — a discipline 2c-2b already encodes
  ([`ARCHIVAL_BOND_REQUEST_2C2B_PLAN.md`](ARCHIVAL_BOND_REQUEST_2C2B_PLAN.md): "`shekyl-standoff`,
  never an ad-hoc draw; the check forbids any inherited jitter", plus an RNG-degeneracy guard
  and `!Clone` unrepresentability tokens).

**Residual — the real load-bearing agreement is an *input* coupling, not the draw.**
`draw_cover_amount(count, c_min, rng)`'s **`c_min`** = `COVER_RUNWAY_FLOOR_ATOMIC`, **provisional
pending the 2d-1 earnings-ramp `C_min` sizing** (`pscan/accrual.rs` SP-7; a partial funding read
mis-sizes `C_min` — a DQ7-class firewall-parameter risk). The **same `C_min`** (and `count` =
live-bond `C`) must feed the send-side draw **and** the SP-7 / `CoverDiscovery` detection side; it
is single-sourced as one const that re-freezes the golden vector when 2d-1 lands. So the
cross-surface agreement is **`C_min`/`count` single-sourcing** — input plumbing, cleaner than a
constructor unification, and **gated on 2d-1**.

**Funding-regime confirmation (DQ4).** 2c-2b's SP-2.d *correction* confirms the two-regime split
this doc's DQ4 lean named: cold-start = **principal-funded** + ≥ 1-SEB-spaced + standoff-
decorrelated; steady-state = `P`-local fund-from-earnings ramp (≥ 2 settlement epochs). The
firewall *logic* is built + fixture-validated; **neither real funding source is wired** yet
(principal-output access = SP-2.d, `P`-scanning = SP-2.e).

**Convergence — the remaining thread is one gate with three readers, not a list.** Everything
still open downstream converges on the **2d-1 earnings-ramp sizing**: (a) `stake_in` importing
`shekyl-standoff` + `construct_output`; (b) `C_min` single-sourcing for the cover draw; (c)
DQ4's steady-state funding sources. These are **not independent items** — they are **one
dependency (2d-1 earnings-ramp: `C_min` + funding sources) with multiple readers**, so 2d-1
unblocks the cover contract *and* DQ4's steady-state regime in one move.

**`C_min` has one author and three readers (a small, non-vicious circularity).** `C_min` feeds
the send draw (`stake_in`), the SP-7 / `CoverDiscovery` detection side, **and** — because
`COVER_RUNWAY_FLOOR_ATOMIC` *is* the cover-runway floor — the earnings-ramp economics that size
it: the ramp sizes `C_min`, and `C_min` sizes the cover the ramp is meant to fund during
cold-start. Not vicious (the ramp sizing is the **author**; the cover draw is a **consumer** of
its output), but it means `C_min` **cannot be pinned independently** on the wallet and sim
sides — it is pinned **once, in the 2d-1 sizing, and read everywhere else**. So the
single-sourcing discipline is stronger than send-vs-detection congruence: **the 2d-1 sizing is
the sole author of `C_min`; all consumers are readers.** This relocates the residual to the
*tractable* side of the same line — a shared-input **value** risk (one constant, single-sourced,
agreement definitional) rather than a **code** risk (two derivations kept congruent).

**Verify-at-source when 2d-1's earnings-ramp lands:** that `C_min` is **authored once there and
read everywhere else** — not recomputed from ramp parameters on any consuming surface while the
constant is read on another. That single check is what turns the whole cover-and-funding
contract from *provisional, mechanism-sound* to *final*.

## 6. References (authoritative — reference, do not restate)

- [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §2.4 (tx-legs), §3
  (`P`-state FSM), §2.1 (retain/delete).
- [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) P2B-1..7 (FSM authority; P2B-7
  `HoldingsUpdate` genesis pin).
- [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) (bond wire, `post_kind`, `bond_spend_pk`,
  Slash/Unbond/HoldingsUpdate §4.2–§4.4; §8 connect-path checklist).
- [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) §2.4/§2.5 (GF-4/GF-7), §6 R4,
  §9.4/§9.6 (`ArchivalPKeys`, secret-locality).
- [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) (cooldown / delay floors; §7
  wallet defaults).
- [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §L18 (R-3 sim reconciliation sealed
  2026-06-16, zero param change).
- [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) / [`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md)
  (the emission the drain is downstream of; ML-DSA hard gate).
- Code reality (verified `dev`, Round-1 open): [`stake_engine.rs`](../../rust/shekyl-engine-core/src/engine/stake_engine.rs),
  [`archival_p.rs`](../../rust/shekyl-crypto-pq/src/archival_p.rs),
  [`bond_post.rs`](../../rust/shekyl-archival-retention/src/bond_post.rs),
  [`engine/mod.rs`](../../rust/shekyl-engine-core/src/engine/mod.rs),
  [`shekyl-wire/transaction.rs`](../../rust/shekyl-wire/src/transaction.rs);
  `shekyl-staking` (`registry.rs`/`rewards.rs`/`entitlement.rs` dead; `meta.rs`/`tiers.rs` live).
