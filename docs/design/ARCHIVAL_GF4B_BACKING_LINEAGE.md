# GF-4b — Backing-lineage wiring: sweep, `MintLineageOutput`, `BackingSet`

> **Status: design round 1, 2026-07-08.** The short spec-first round (rule
> `05-system-thinking`: specification first) for the wallet-side half of the
> [`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md) §8.0.3 C-1
> activation precondition: the gate-6 backing-lineage **ladder + sweep**,
> already specified
> ([`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) §2.4 GF-4b;
> [`PRINCIPAL_STAKE_LIFECYCLE.md`](PRINCIPAL_STAKE_LIFECYCLE.md) §3 GF-4b),
> **wired in the wallet's pre-join path** (the `BackingSet` type + the
> zero-pre-bond-output test). This is an *addendum* to those two GF-4b
> sections and to [`ARCHIVAL_BOND_WI2_ASSEMBLY.md`](ARCHIVAL_BOND_WI2_ASSEMBLY.md)
> §3.2 (whose D-A2 selection policy §3.1 below reconciles) — not a fresh
> 4–6-round design cycle. No new identifier family is minted (rule 94):
> dispositions are referenced by section number of this doc.
>
> **Timeframes (rule 05):** *now* — the pre-genesis wallet pre-join path;
> discharges the §8.0.3 wallet half so C-1's precondition check is mechanical.
> *Mining-era end* — the lineage vocabulary already carries both rung-1 mint
> forms (`MinerReward`, `EmissionReward`); the rung structure is unchanged by
> the reward transition to fee-plus-terminal-subsidy. *V4* — lineage
> classification is structural (transaction shape: coinbase position,
> `BondPost` input presence), with no cryptographic-primitive coupling; it
> survives the lattice-only migration unmodified.

## 1. Scope

Land the three wallet-side GF-4b artifacts, smallest coherent cuts:

1. **`MintLineageOutput`** — the scan-provenance enum, classified at the
   SP-3 dual-extract seam, propagated into the persisted funding records
   (`PSCAN_STATE_VERSION` 4 → 5, rule 42).
2. **Sweep conversion** — `select_funding_outputs` (oldest-first greedy
   *subset* accumulation, WI-2 D-A2) becomes `sweep_funding_outputs`
   (full-unreserved-set consumption; no subset parameter exists).
3. **`BackingSet`** — the constructor-gated pre-join type over
   lineage-typed records (`JoinMarketVin` mint pattern), plus the
   zero-pre-bond-output test.

Out of scope (**C-1**, enumerated with criteria in §5): the arity-1
designated-backing *selector* consuming `BackingSet`, the `EmissionReward`
classification arm, and the emission-path integration test. Out of scope
(**SP-R0**, unchanged): durable removal of confirmed-spent funding records
(FOLLOWUPS "2d-1 WI-2"); §3.2 re-pins the dead-code invariant that sequencing
rests on. Out of scope entirely: `stake_in` (unbuilt; §3.5 preserves its
design constraints untouched).

## 2. Substrate (verified at source on `dev` = `c72d2ecdb`, 2026-07-08)

| Fact | Where |
| --- | --- |
| `select_funding_outputs` is oldest-first greedy accumulation that **stops at `sum ≥ required`** — a subset selector; `#[allow(dead_code)]`, zero production callers (the WI-2 Engine-side orchestrator never landed) | `rust/shekyl-engine-core/src/engine/bond_assembly.rs` (`select_funding_outputs`, break-on-satisfied loop) |
| The `AssembleBond` handler is likewise `#[allow(dead_code)]` with no production caller; sweep conversion has **zero call-site rewires** | `rust/shekyl-engine-core/src/engine/stake_engine.rs` (`AssembleBond`) |
| `PScanState::funding_outputs` is append-only — `PScanAccrual::ingest` only extends; nothing prunes on confirmed spend | `rust/shekyl-engine-core/src/engine/pscan/accrual.rs`; FOLLOWUPS "2d-1 WI-2" |
| **No lineage provenance at any seam**: `FundingOutputMatch` and `PFundingOutputRecord` carry no kind/lineage field; `OwnedTxLeaves::is_miner` (`scan.rs`) does **not** propagate into the pscan pipeline | `engine/pscan/scan_step.rs` (`FundingOutputMatch`), `shekyl-engine-state/src/pscan_state.rs` (`PFundingOutputRecord`) |
| Zero matches in `rust/` or `src/` for `BackingSet`, `BondPostChange`, `MintLineageOutput`; no zero-pre-bond-output test exists | `rg` over the workspace |
| The scanner scans the **inline miner transaction** alongside non-miner txs, paired with its hash; `ScannableBlock.block.transaction_hashes` is positionally paired with `.transactions` | `rust/shekyl-scanner/src/scan.rs` (miner tx pushed first into `txs_with_hashes`) |
| `run_dual_extractor` sees the full `ScannableBlock` (header + miner tx + non-miner txs) and already iterates `Input::BondPost` against the bonded union's id set — the classification seam exists | `engine/pscan/scan_step.rs` (`run_dual_extractor`) |
| `PSCAN_STATE_VERSION` is **4**; loads refuse on mismatch (no migration, rule 15); snapshot check is CI-enforced | `shekyl-engine-state/src/pscan_state.rs`, `schema_snapshot.rs`, `.github/workflows/schema-snapshot.yml` |
| Backing **arity is exactly 1** (wire pin); "the GF-4b sweep design feeds exactly one designated backing output (bond-post change at bootstrap, mint output at steady state)" | `rust/shekyl-archival-retention/src/emission_wire.rs` (single-input pin) |
| **Q11 ratified ACCEPT** (E3 gating round §2.2): backing validity anchors at the reference tree root, **not** "output still unspent"; consensus is lineage-blind *and* spend-blind for backing | [`REWARD_EMISSION_E3_GATING_ROUND.md`](REWARD_EMISSION_E3_GATING_ROUND.md) §2.2 |

### 2.1 Discrepancy list (docs ↔ code, the Phase-0 deliverable)

1. **WI-2 D-A2 ↔ GF-4b — unreconciled divergence between two ratified
   docs.** `ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.2 rule 3 ("greedy accumulation
   until `sum ≥ floor + fee`", 2026-07-05) post-dates and contradicts the
   GF-4b pin ("sweep, not coin-select … no subset parameter — the non-sweep
   state is a function that never gets written", 2026-07-01) and never cites
   GF-4b. The landed `select_funding_outputs` implements D-A2. Resolved by
   §3.1; WI-2 §3.2 is amended in this PR.
2. **Lifecycle-doc citation nit.** `PRINCIPAL_STAKE_LIFECYCLE.md` §3 GF-4b
   cites `scan.rs:507` for a "provenance" comment; that comment is about
   **wire-parse provenance** (the `MAX_OUTPUTS` gate / `ParsedTransaction`
   newtype reopen), a different concept from mint lineage. Amended in this
   PR alongside the wired-state update.
3. **"Upgrading the `is_miner` bool" is aspirational, not descriptive.**
   `is_miner` exists on `OwnedTxLeaves` but never reaches the pscan
   pipeline; there is nothing at the funding-record seam to "upgrade." The
   enum lands as a **new** classification at the dual-extract seam (§3.3),
   not a widening of an existing field. The lifecycle doc's sequencing claim
   ("can land ahead of everything else") is confirmed correct.

## 3. Dispositions

### 3.1 (a) WI-2 D-A2 ↔ GF-4b reconciliation — convert to sweep

**Decision.** `select_funding_outputs` converts to **sweep semantics** and is
renamed `sweep_funding_outputs` (the rename makes the non-sweep state
grep-dead — `select_funding_outputs` ceases to exist, satisfying the GF-4b
"a function that never gets written" pin as nearly as a landed function can).
The function consumes the **full** unreserved, slot-scoped eligible set:

- **Keeps:** slot scoping (load-bearing for single-persona key derivation),
  reserved-gindex exclusion (the pending record stays the single source of
  reservation truth), the `InsufficientFunding { available, required }` ramp
  refusal (a sweep whose total cannot cover `bond_floor + fee` still
  refuses), checked amount arithmetic, and the deterministic oldest-first
  `(height, gindex)` ordering — D-A2's determinism/auditability rationale
  survives as the ordering of the swept input list.
- **Removes:** the early break at `sum ≥ required`. The signature keeps
  `required` (the ramp check needs it) but there is **no way to express a
  subset**: every unreserved eligible record is in the returned selection.
- **Change math:** unchanged. `funding == change + fee + credit` (WI-2 §3.2
  rule 4, `verify_credit_funding`) absorbs the larger remainder; the
  two-output change split is unaffected.

**Why selection is indefensible (the recorded argument).** D-A2's rationale
addressed selection *order* (oldest-first vs randomized — correct: these are
P-local outputs spent to P's own cleartext-named bond, so input-selection
unlinkability pressure does not apply). It never addressed selection
*extent*, and extent is what GF-4b constrains: a subset selector leaves
unswept funding outputs alive in P's spendable set, and before this PR the
funding set carries **no provenance typing whatsoever** — a leftover output
is unboundable; it is exactly the raw pre-bond-post funding (rung 3) whose
emission-backing reveal newly identifies the funding tx and its timing.
Even *with* lineage typing (§3.3), subsetting preserves rung-3 survivors and
GF-4b's structural-emptiness claim ("nothing raw survives
backing-eligible") fails: the whole design rests on the bond post/re-bond
consuming everything. Priority-2 (privacy is the product) binds over D-A2's
convenience; GF-4b is firewall-class. Divergence resolved in favor of GF-4b.

**Reversion clause (rule 21).** Reopens **iff** gate-6 amends or retires the
GF-4b sweep pin itself (a gate-6 round with threat-model review — e.g. a
future backing primitive that stops revealing `pqc_pk`). Re-evaluation
shape: a gate-6 round entry amending §2.4 GF-4b, cascading here and to WI-2
§3.2. Not reopenable on assembly-convenience or fee-optimization grounds.

### 3.2 (b) Sweep ↔ spent-record-pruning sequencing

**What lands in this PR:** the sweep conversion (§3.1), as dead code — the
same `#[allow(dead_code)]` posture the subset selector had; zero call-site
rewires (§2).

**What stays SP-R0-gated (unchanged):** durable removal of confirmed-spent
records from `PScanState::funding_outputs` (FOLLOWUPS "2d-1 WI-2"), riding
SP-6/SP-R0's confirmed-absence-within-`covered` discipline. Not pulled
forward: pruning built on a "saw our own bond post" seam would violate the
SP-6 "absence ≠ unscanned" rule this project already rejected once.

**The invariant that keeps the path dead (re-pinned, strengthened).** The
WI-2 assemble/dispatch path **must not go live** until either (a) durable
spent-record removal lands, or (b) the reservation set durably retains
confirmed-spent gindexes. Sweep makes this *harder*-load-bearing, and the
code comment at `sweep_funding_outputs` is updated to say so: under subset
selection a stale spent record was re-selected only when it was among the
oldest sufficient records; under sweep **any single** stale spent record is
in *every* subsequent selection, so one confirmed post poisons every later
bond post for that persona (daemon-rejected duplicate key image) until
pruning lands. The FOLLOWUPS entry is annotated with the sweep semantics in
this PR.

**Orthogonality note (new substrate, Q11).** Spent-record pruning is a
double-spend-correctness concern only, **not** a GF-4b concern: backing
validity anchors at the reference tree root (E3 gating round §2.2), so an
output's spent status never affects its backing *provability* — which is
precisely why lineage gating cannot be replaced by "just use unspent
outputs" and the `BackingSet` (§3.4) is the enforcement layer.

### 3.3 (c) `MintLineageOutput` — the scan-provenance enum

**Variants** (the GF-4b ladder, most→least safe):

| Variant | Rung | Meaning | Constructed by |
| --- | --- | --- | --- |
| `MinerReward` | 1 | Recovered from the block's inline miner (coinbase) transaction | this PR (scan classification) |
| `EmissionReward` | 1 | Recovered from a transaction carrying `P`'s own `txin_archival_reward_emission` | **reserved — C-1** (see below) |
| `BondPostChange` | 2 | Recovered from a transaction carrying a `BondPost` input whose `p_canonical_id` is the recovered output's **own persona** | this PR (scan classification) |
| `ExternalTransfer` | 3 | Everything else — raw pre-bond-post funding; **forbidden as emission backing** | this PR (the conservative default) |

**Home.** `shekyl-engine-state::pscan_state`, alongside
`PFundingOutputRecord` — it is persisted vocabulary (`Serialize` /
`Deserialize` / `postcard_schema::Schema`), and engine-core already imports
that module. Plain derived `Debug` (a rung tag is not a secret; the records
carrying it stay redacted wholesale).

**Classification seam: `run_dual_extractor`,** per block, before the scan
loop:

1. Compute the miner-tx hash once (`block.block.miner_transaction.hash()`).
2. Build the per-block map *tx-hash → set of our persona slots posting a
   `BondPost` in that tx*, from the existing `Input::BondPost` iteration —
   `block.block.transaction_hashes` is positionally paired with
   `.transactions`, so no non-miner tx is hashed.
3. Classify each recovered output by its carrying tx:
   `tx == miner` → `MinerReward`; else *our own slot posted a `BondPost` in
   this tx* → `BondPostChange`; else `ExternalTransfer`.

To attribute a bond post to the recovered output's **own** persona, the
extractor's id input widens from `BTreeSet<PCanonicalId>` to
`BTreeMap<PCanonicalId, u32>` (id → slot); the caller
(`bonded_scan_inputs`) already computes both halves in the same loop. A tx
carrying a *different* held persona's bond post classifies the output
`ExternalTransfer` — the assemble path never routes change cross-persona,
so the case is conservative-by-default, not modeled.

**Fail-toward-the-forbidden-rung rule (load-bearing).** Anything not
*structurally proven* rung 1/2 classifies `ExternalTransfer`. A
misclassification in this direction can only **exclude** a safe output from
backing eligibility; it can never admit an unsafe one. The dual is never
acceptable.

**Propagation.** `FundingOutputMatch` and `PFundingOutputRecord` each gain a
`lineage: MintLineageOutput` field; both `From` impls are exhaustive struct
literals, so the compiler forces the twin update (the documented
duplication guard doing its job).

**Rule-42 schema impact.** `PFundingOutputRecord` is persisted state:
`PSCAN_STATE_VERSION` **4 → 5**, snapshot regenerated, CI snapshot check
covers it. Pre-genesis: loads refuse on mismatch, no migration code,
`rm -rf ~/.shekyl` is the path (rules 15/16).

**`EmissionReward` reserved-variant justification (rule-21 check: this is
not pre-provisioning-for-flexibility).** The consumer is **named and
scheduled** — C-1, whose activation precondition this doc discharges; the
emission vin type exists on the wire (`emission_wire.rs`, landed PR-E2) but
is not yet parsed on the scan path, so the classification arm *cannot* be
written yet. Adding the variant later would force a **second**
persisted-schema bump for a change already fully specified today. Invariant,
documented at the variant: `EmissionReward` is **never constructed** until
C-1's emission-vin scan arm lands; the C-1 residue list (§5) carries the
arm. Reopening: if C-1 lands without the arm, or the emission leg is
retired, the variant is deleted with the next scheduled schema bump.

**Sequencing.** GF-4b's "independently useful, can land ahead of everything
else" is confirmed (§2.1 item 3); this is commit 1 of the implementation.

### 3.4 (d) `BackingSet` — scope split and the zero-pre-bond-output test

**What lands now.** `BackingSet`, a constructor-gated type in
`shekyl-engine-core` (`engine/backing_set.rs`), following the
`JoinMarketVin` constructor-mint pattern (private field, sole constructor,
sibling shape `RetirementWitness`):

- `BackingSet::from_spendable(records)` **filters** to the backing-eligible
  rungs — `MinerReward`, `EmissionReward`, `BondPostChange` — and drops
  `ExternalTransfer`. Possession of a `BackingSet` is proof every member is
  rung 1/2; a rung-3 record inside one is unrepresentable.
- **Filter, not fail-closed, on rung-3 input — deliberately.** Post-bond,
  `P` may legitimately hold *new* raw funding outputs awaiting the next
  re-bond sweep (the multi-tranche exception, §3.5); their presence in the
  wallet is legal. What must be impossible is their presence in the backing
  candidate set — the constructor is the boundary that makes the bad state
  unrepresentable rather than an error to handle (contrast: a fail-closed
  constructor would turn a legal wallet state into a runtime error on every
  between-sweeps emission).
- `#[allow(dead_code)]` transient, annotated with the C-1 consumer by name
  — the same posture as `select_funding_outputs`/`AssembleBond`, and the
  same review discipline applies.

**Why the wallet type is the *only* enforcement layer (record this; it is
the C-1 review anchor).** Consensus is lineage-blind (§8.0.3: unenforceable
by construction) **and** spend-blind for backing (Q11: tree-root-anchored
membership — even a *spent* rung-3 output remains provable). No daemon-side
check can ever reject a rung-3 backing. Therefore the C-1 designated-backing
selector **must obtain its candidate exclusively through `BackingSet`** —
named in §5 as a C-1 merge-review item, so the property is checked at the
PR boundary rather than remembered.

**What lands with C-1 (the split's far half, enumerated §5):** the arity-1
selector (`emission_wire.rs` pin: exactly one designated backing output —
bond-post change at bootstrap, mint output at steady state), the
`EmissionReward` scan arm, and the emission-path integration test.

**The zero-pre-bond-output test (definition).** State-level, against the
sweep + the funding-record set (the bond-post path's data plane; the
`AssembleBond` handler stays dead code, so no end-to-end tx is built):

- **State inspected:** a mixed-lineage `PFundingOutputRecord` set for one
  persona slot (raw funding = `ExternalTransfer`, plus a miner-reward
  record), the sweep's returned selection, and the modeled post-confirmation
  spendable set (records minus swept gindexes — the reservation/spent
  exclusion applied, since durable pruning is SP-R0-gated).
- **Asserts:** (1) the sweep selection **is** the full unreserved eligible
  set — including records a greedy subset selector would have left behind;
  (2) the post-sweep spendable remainder is **empty** — in particular, zero
  `ExternalTransfer` records survive; (3) the post-bond state (the bond-post
  change record, lineage `BondPostChange`) yields a `BackingSet` containing
  it, and an `ExternalTransfer` record injected into the same input set is
  **not** in the resulting `BackingSet`.

### 3.5 (e) Wargamed residuals — preserved, untouched

1. **Single structured `bond_floor + cover` funding output** (lifecycle §3 /
   §3.1): the input-*count* signal on the P-public bond post is mitigated by
   `stake_in` funding each admission as **one** structured output, so the
   sweep consumes one input in the common case. `stake_in` is unbuilt; this
   remains a design constraint on it, restated here so the sweep PR is not
   read as weakening it. The sweep is the mechanism that makes "consume
   everything" and "consume one input" the same statement in the common case.
2. **Multi-tranche funding stays a conscious exception**, to be noted in
   `stake_in`'s design when it exists — not a default this PR normalizes.
   The `BackingSet` filter (§3.4) is what keeps between-sweeps tranches
   harmless in the meantime.
3. **GF-7 timing unchanged.** Funding↔bond-post *timing* decorrelation stays
   the standoff machinery's job; nothing here touches it. The sweep composes
   with the `stake_engine.rs` funding↔bond-post decorrelation reasoning and
   the SP-3/SP-5 dual-extract (funding + bond-post as two scanned events) —
   beside, not against.

## 4. Test plan (gates)

1. **Lineage classification KATs** (`scan_step.rs`): miner-tx output →
   `MinerReward`; output in a tx carrying the *same* persona's `BondPost` →
   `BondPostChange`; plain transfer → `ExternalTransfer`; output in a tx
   carrying a *different* held persona's `BondPost` → `ExternalTransfer`
   (conservative default); lineage survives the
   `FundingOutputMatch ↔ PFundingOutputRecord` round-trip.
2. **Sweep KATs** (`bond_assembly.rs`): full-set consumption (the
   multi-record case greedy would have truncated); reserved exclusion
   retained; slot scoping retained; `InsufficientFunding` ramp refusal
   retained; deterministic oldest-first ordering of the swept list.
3. **Zero-pre-bond-output test + `BackingSet` gates** (§3.4 definition):
   the three assertions, plus the constructor filter (rung-3 in, not
   present) and standard redaction/`Debug` discipline if the type carries
   record contents.
4. **Schema**: `PSCAN_STATE_VERSION` 5 load-refusal test (the existing
   version-gate test pattern); snapshot regenerated; CI snapshot check.

## 5. C-1 residue (named criteria — the mechanical precondition check)

After this PR, the §8.0.3 precondition state is: ladder **specified** ✓,
sweep **specified + implemented** ✓ (go-live dead-code-gated per §3.2),
pre-join wiring (`BackingSet` + zero-pre-bond-output test) **landed** ✓.
The residue riding C-1, citable by the C-1 PR:

| # | Item | Criterion (checkable at C-1 review) |
| --- | --- | --- |
| 1 | Designated-backing selector | Consumes candidates **exclusively through `BackingSet`** (no direct `funding_outputs` read on the backing path); selects exactly **one** output (the `emission_wire.rs` arity-1 pin) |
| 2 | `EmissionReward` scan arm | `run_dual_extractor` classifies outputs of txs carrying `P`'s own emission vin; the reserved variant gains its first constructor site |
| 3 | Emission-path integration test | First-emission backing is `BondPostChange` (bootstrap); a rung-3 record cannot reach the vin builder |
| 4 | Go-live gate (§3.2) | WI-2 assemble/dispatch stays dead until SP-R0 spent handling lands — independent of C-1, restated so C-1 does not accidentally wire it live |

## 6. Round closure

Round 1 closes with dispositions §3.1–§3.5 ratified by landing. Reopening
criteria are per-disposition (each §3.x carries its own rule-21 clause);
substrate findings, not sequential numbering, reopen the round.
