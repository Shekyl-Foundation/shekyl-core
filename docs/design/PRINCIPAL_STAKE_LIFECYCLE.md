# Principal stake / unstake / drain lifecycle (design — Round 1)

**Status:** Round 1 — DQ closure (advanced 2026-07-01 from the 2026-07-01 Round-0
scoping). Round 0 named the surface and enumerated DQ1–DQ6; Round 1 **closes DQ1,
DQ2, DQ5, DQ6 on already-pinned substrate** and **re-gates DQ3, DQ4 to gate-6 Round
4** (with named reopening criteria), freezes the method signatures (A1), sketches the
PR map, and pins the discipline citations. **No implementation is authorized by this
doc.** The *method-surface contract* closes at Round 1; *code* for the value-bearing
legs (bond-post / drain) remains genesis-seal-blocked per §5. This is the plan-home
for the **user-facing** economic staking surface named unscoped in
`WALLET_REWRITE_PLAN.md` Phase-2.

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
| `P` HKDF derivation is a gate-6 Round-1 lone carry ("not yet built") | `ArchivalPKeys` + derivation **built** in [`archival_p.rs`](../../rust/shekyl-crypto-pq/src/archival_p.rs) (23 KB); `bond_spend_sk` present; `BondPostKind::JoinMarket { bond_spend_pk }` serializer in [`shekyl-wire`](../../rust/shekyl-wire/src/transaction.rs) | `P` derivation + the bond-post **wire serializer** are not a blocker; the gap is the consensus **verify** path + the principal driving methods |
| Secret-locality of `P` keys is a forward requirement on the retool | `StakeEngine` already **owns** `spend_sk`/`view_sk`/`ml_kem_dk`/`hybrid_sign_sk`/`bond_spend_sk` (ArchivalPKeys, never `Clone`, `ZeroizeOnDrop`); emits `JoinMarketVin` / `ScanStepResult`, never keys | DQ2 is **confirmed by the built actor**, not a design still to make |

The orchestrator is `Engine<S,D,L,E,R,P,F>` ([`engine/mod.rs`](../../rust/shekyl-engine-core/src/engine/mod.rs) L403), holding `key: KeyEngineHandle` (L452), `pending: P` (L522), `stake: Option<StakeEngineHandle>` (L681). Principal transfers already build through `Engine::build_pending_tx_async` → `PendingTxEngine::build` → `KeyEngine` sign ([`pending.rs`](../../rust/shekyl-engine-core/src/engine/pending.rs) L841). **The principal surface is a composition layer over primitives that already exist**, not a new engine.

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
  funding-shape hygiene (DQ4) is a wallet-local default, not a consensus gate.
- **`fund_bond` / `join_market(shards) -> PendingTx`** — drives the **existing**
  `StakeEngine::SignBond` → `JoinMarketVin` (built; `#[allow(dead_code)]`/inert until
  the gate-4 verify path lands) + submit. Signs with `P`-identity + funding inputs
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

## 4. Round-1 dispositions (DQ1–DQ6)

### DQ1 — no principal-side committed-stake wire survives. **CLOSED (plain transfer).**

**Decision.** Stake-in is a **plain ordinary `RCTTypeFcmpPlusPlusPqc` transfer**,
principal → `P` stealth outputs on the main tree. **No `C_stake`, no range proof, no
band, no minimum.** The §2.1 "principal role open" reopen-pointer is **retired**.

**Rationale (four independent legs, any one sufficient):**

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

**Reversion clause (rule 21).** Reopen **iff a future V3.x consensus rule reads the
principal stake amount** (e.g., an emission rule keyed on principal balance, or a
demonstrated need to prove a per-principal stake bound). Not reopened by "uncertainty
about future flexibility" — that is the rule-21 optionality-debt anti-pattern that
gate-7 / gate-6 §2.5 already rejected on the sibling admission-minimum question.

**Forward-action (A5 — doc sweep).** [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md)
Q11 (`0x04 txout_to_staked_key`) still describes the principal as "a `C_stake` Pedersen
commitment kept off-wire in the wallet's `StakeInstance`" — **stale claim-era text this
decision falsifies**. Corrected in the Round-1 doc sweep to "ordinary stealth output to
`P`; no principal commitment on- or off-wire" (retraction hygiene — a decision is not
closed until every artifact reflects it).

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
hard exit** (gate-6 §6), and Round 4 is downstream of the FSM-pin's age-stratified sim
(§5). Re-gated with a named lean for R4 to ratify; **`drain()` and `unbond()` bodies
stay `unimplemented!()` until GF-4 is pinned** (shipping a lump sweep before GF-4 ships
a correlation beacon, gate-6 §2.4).

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
wallet-local**, so it can be prototyped as a default once the FSM shape is pinned.

### DQ4 — bond-funding shape (GF-7). **RE-GATED to gate-6 Round 4.**

**Decision.** The **no-minimum-at-any-layer** half is already **closed** (gate-6 §2.5);
the **ramp-vs-lump** half is a gate-6 Round-4 hard exit (recurring — first join *and*
rebond-topup), downstream of the FSM pin. Re-gated with a named lean.

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

**Rationale.** `principal_stakes()` *is* the firewalled edge (P↔principal↔human) — it is
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
| **PR-P3** | `fund_bond`/`join_market` — drive built `SignBond`→`JoinMarketVin` + submit; NOP until gate-4 verify accepts the vin | consensus bond-post wire | **blocked** — gate-4 `txin_archival_bond_post` **verify** path (wire serializer built; verify not) |
| **PR-P4** | `partial_unbond` + `unbond` — NEW `StakeEngine` bond-debit ops (sign `bond_spend_sk`) | bond-debit wire + release cooldown | **blocked** — gate-4 debit verify + **gate-6 R4 GF-4/GF-7** (recurring) |
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

## 5. Gates — determination and buildable-now slice

**Can the design close now, or is it gated on the FSM pin advancing first?**

**Determination: the design closes now.** The method-surface *contract* (DQ1/DQ2/DQ5/DQ6)
rests entirely on **already-pinned** substrate — the rebond/unbond FSM is pinned
(FSM-retool P2B-4/P2B-7 landed 2026-06-15; gate-4 §4.4), gate-6 §9 secret-locality is
Round-1-closed, the bond wire + `P` derivation are **built** (§0.1), and gate-7 is
bonds-only. **Nothing the FSM *pin* still owes moves these four decisions.** What the FSM
pin's *remaining open* (the age-stratified sim reconciliation → genesis-seal redundancy
floor, gate-6 §6 R-3) gates is narrower: (a) the **numeric** close of DQ3/DQ4 via gate-6
Round 4, and (b) **implementation authorization** of the bond-debit and drain legs. So the
*design* is not FSM-pin-gated; the *value-bearing code* is.

**BLOCKED (genesis-seal / consensus-gated) — do not build the value legs yet:**

1. **Gate-6 Round 4 (GF-4 output-count + GF-7 funding shape)** — DQ3/DQ4; recurring
   (rebond/unbond at genesis, gate-6 §6); downstream of the FSM-pin age-stratified sim.
   Blocks `partial_unbond` / `unbond` / `drain`.
2. **Gate-4 `txin_archival_bond_post` verify path** — the wire serializer is built
   ([`shekyl-wire`](../../rust/shekyl-wire/src/transaction.rs)) but the consensus verify /
   connect is not. Blocks `fund_bond`/`join_market` acceptance and the bond-debit ops.
3. **Reward-emission leg** — the drain consumes reward outputs that do not exist until
   emission is built ([`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md); C-1
   ML-DSA hard gate = PR-E3 step 8). Blocks `drain`.

**BUILDABLE NOW (design + non-consensus enabling work):**

- **This Round-1 ratification** (PR-P0) — pure design, commit-direct-to-dev, incl. the
  GENESIS_TX_WIRE_FORMAT Q11 doc-sweep.
- **`shekyl-staking` Tier-A deletion** (PR-P1) — zero-dependent dead code, rule 15.
- **`stake_in` + its GF-2 dual-scan end-test** (PR-P2) — the thin unblocked edge: an
  ordinary transfer over built primitives + the real boundary test; gated only on the
  frozen contract, not on genesis-seal.
- **Firewall-hygiene default *directions*** (DQ3/DQ4 leans) — non-consensus wallet-local;
  prototypable as defaults once the FSM shape is pinned (it is), numeric pin waits on R4.
- **Persona/bond driving-path completion** (2c-2b) — `SignBond`/`JoinMarketVin` exist but
  are inert; wiring the driving path forward is buildable ahead of the gate-4 verify cut.

## 6. References (authoritative — reference, do not restate)

- [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §2.4 (tx-legs), §3
  (`P`-state FSM), §2.1 (retain/delete).
- [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) P2B-1..7 (FSM authority; P2B-7
  `HoldingsUpdate` genesis pin).
- [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) (bond wire, `post_kind`, `bond_spend_pk`,
  Slash/Unbond/HoldingsUpdate §4.2–§4.4).
- [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) §2.4/§2.5 (GF-4/GF-7), §6 R4,
  §9.4/§9.6 (`ArchivalPKeys`, secret-locality).
- [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) (cooldown / delay floors; §7
  wallet defaults).
- [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) / [`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md)
  (the emission the drain is downstream of; ML-DSA hard gate).
- Code reality (verified `dev`, Round-1 open): [`stake_engine.rs`](../../rust/shekyl-engine-core/src/engine/stake_engine.rs),
  [`archival_p.rs`](../../rust/shekyl-crypto-pq/src/archival_p.rs),
  [`engine/mod.rs`](../../rust/shekyl-engine-core/src/engine/mod.rs),
  [`shekyl-wire/transaction.rs`](../../rust/shekyl-wire/src/transaction.rs);
  `shekyl-staking` (`registry.rs`/`rewards.rs`/`entitlement.rs` dead; `meta.rs`/`tiers.rs` live).
