# GF-4b — Backing-lineage wiring: sweep, `MintLineageOutput`, `BackingSet`

> **Status: design round 1 + review round, 2026-07-08.** Review-round
> findings GF4b-1…GF4b-6 (§6) are incorporated into §3.1–§3.6 and §5; the
> ladder and sweep conversion were verified correct as designed and are
> unchanged, except that GF4b-6 tightens the sweep's eligible-set
> definition to *spendable* eligible (§3.6). The short spec-first round (rule
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
> *Mining-era end* — `P` is a shard-serving persona **only**; mining happens
> under the principal in every era, so the reward transition to
> fee-plus-terminal-subsidy never touches the ladder (rung 1 is `P`'s own
> emissions, which persist as long as archival serving does). *V4* — lineage
> classification is structural (transaction shape: `BondPost` / emission-vin
> input presence), with no cryptographic-primitive coupling; it survives the
> lattice-only migration unmodified.

## 1. Scope

Land the three wallet-side GF-4b artifacts, smallest coherent cuts:

1. **`MintLineageOutput`** — the scan-provenance enum, classified at the
   SP-3 dual-extract seam, propagated into the persisted funding records
   alongside the `spendable_height` field (§3.6)
   (`PSCAN_STATE_VERSION` 4 → 5, rule 42).
2. **Sweep conversion** — `select_funding_outputs` (oldest-first greedy
   *subset* accumulation, WI-2 D-A2) becomes `sweep_funding_outputs`
   (full-unreserved-**spendable**-set consumption, §3.1/§3.6; no subset
   parameter exists).
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
The function consumes the **full** unreserved, slot-scoped, **spendable**
eligible set:

- **Keeps:** slot scoping (load-bearing for single-persona key derivation),
  reserved-gindex exclusion (the pending record stays the single source of
  reservation truth), the `InsufficientFunding { available, required }` ramp
  refusal (a sweep whose total cannot cover `bond_floor + fee` still
  refuses), checked amount arithmetic, and the deterministic oldest-first
  `(height, gindex)` ordering — D-A2's determinism/auditability rationale
  survives as the ordering of the swept input list.
- **Adds (GF4b-6, §3.6):** spendability exclusion — a record whose
  `spendable_height` exceeds the sweep's reference height is not in the
  eligible set. "Consume everything" means everything *spendable*;
  consuming an unspendable output is a bug regardless of how it arrived
  (§3.6 records both the ordinary-flow and adversarial arrival paths).
- **Removes:** the early break at `sum ≥ required`. The signature keeps
  `required` (the ramp check needs it) but there is **no way to express a
  subset** of the spendable eligible set: every unreserved spendable
  eligible record is in the returned selection.
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

**The gate is structural, not review-discipline (GF4b-5).** A discipline
note guarding a poison-every-subsequent-post failure is the
armed-gate-with-no-trigger shape this project keeps catching, so the gate
gets a type-level bite: `sweep_funding_outputs` takes a
`SpentRecordsDurablyPruned` **witness token** — a zero-sized type with a
private constructor, whose sole production constructor site is the SP-R0
durable-pruning code (which does not exist yet). "Assemble goes live
without pruning" therefore **fails to compile** rather than fails review.
KATs exercise the sweep through a `#[cfg(test)]` constructor, documented at
the type as the only non-SP-R0 mint. §5 item 4's C-1 review obligation
becomes a confirmation ("the witness still has zero production
constructors") instead of a thing the reviewer must remember.
**Chokepoint completeness (review round, minor note):** the witness gates
`sweep_funding_outputs`, which is the right chokepoint only while sweep is
the *sole* funding-selection path into bond assembly — the gate is exactly
as complete as sweep's monopoly. Implementation carries a grep check
(recorded in the test-plan gate, §4 item 2) that no other funding-selection
entry reaches the assemble path around the witness, and the C-1 §5 item 4
confirmation re-runs it. Reversion
clause (rule 21): the token is deleted by the SP-R0 PR itself if SP-R0
chooses disposition (b) above (durable reservation retention), which makes
the precondition unconditional; otherwise SP-R0 adds the sole production
constructor and the token stays.

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
| `EmissionReward` | 1 | Recovered from a transaction carrying `P`'s own `txin_archival_reward_emission` | **reserved — C-1** (see below) |
| `BondPostChange` | 2 | Recovered from a transaction carrying a `BondPost` input whose `p_canonical_id` is the recovered output's **own persona** | this PR (scan classification) |
| `ExternalTransfer` | 3 | Everything else — raw pre-bond-post funding; **forbidden as emission backing** | this PR (the conservative default) |

**There is no miner/coinbase rung (owner ruling, review round).** `P` is a
shard-serving persona **only**; mining is conducted under the principal, as
it always has been — adding capability to `P` adds identification surface,
and gate-6's rung-1 text ("reveals nothing beyond P's own public *emission*
history") never covered coinbase. A coinbase output recovered by `P`'s
scanner is therefore an **anomaly, not a lineage**: either a wallet bug or
an adversarial tag (`P`'s hybrid pubkey is on-chain in the bond post, so a
third party *can* mine to it). It needs no dedicated classifier arm — a
coinbase tx carries only `Input::Gen`, never a `BondPost` input, so it
falls to `ExternalTransfer` **structurally** under the
fail-toward-the-forbidden-rung rule, which is exactly where an
unmodeled-origin output belongs (never backing-eligible; a KAT pins this).

**Home.** `shekyl-engine-state::pscan_state`, alongside
`PFundingOutputRecord` — it is persisted vocabulary (`Serialize` /
`Deserialize` / `postcard_schema::Schema`), and engine-core already imports
that module. Plain derived `Debug` (a rung tag is not a secret; the records
carrying it stay redacted wholesale).

**Classification seam: `run_dual_extractor`,** per block, before the scan
loop:

1. Build the per-block map *tx-hash → set of our persona slots posting a
   `BondPost` in that tx*, from the existing `Input::BondPost` iteration —
   `block.block.transaction_hashes` is positionally paired with
   `.transactions`, so no non-miner tx is hashed.
2. Classify each recovered output by its carrying tx: *our own slot posted
   a `BondPost` in this tx* → `BondPostChange`; else `ExternalTransfer`
   (which structurally covers the anomalous coinbase-to-`P` case — a
   coinbase tx cannot carry a `BondPost` input).

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
`lineage: MintLineageOutput` field **and a `spendable_height` field
(GF4b-6, §3.6)**; both `From` impls are exhaustive struct literals, so the
compiler forces the twin update (the documented duplication guard doing
its job).

**Rule-42 schema impact.** `PFundingOutputRecord` is persisted state:
`PSCAN_STATE_VERSION` **4 → 5** (one bump covers both new fields),
snapshot regenerated, CI snapshot check covers it. Pre-genesis: loads refuse on mismatch, no migration code,
`rm -rf ~/.shekyl` is the path (rules 15/16).

**`EmissionReward` reserved-variant justification (rule-21 check: this is
not pre-provisioning-for-flexibility).** The variant is there for
**ladder-completeness**: the GF-4b ladder is a closed vocabulary of mint
provenances, and shipping it minus one rung would make the persisted
lineage vocabulary a *partial* encoding of the spec — every consumer would
carry an implicit "and one more rung is coming" caveat. The consumer is
**named and scheduled** — C-1, whose activation precondition this doc
discharges; the emission vin type exists on the wire (`emission_wire.rs`,
landed PR-E2) but is not yet parsed on the scan path, so the classification
arm *cannot* be written yet. (That completeness also avoids a second
persisted-schema bump, but pre-genesis that is nearly free — it is not the
justification.) Invariant, documented at the variant: `EmissionReward` is
**never constructed** until C-1's emission-vin scan arm lands; the C-1
residue list (§5) carries the arm **and binds the fail-toward-forbidden
rule to it as an acceptance criterion (GF4b-4)**. Reopening: if C-1 lands
without the arm, or the emission leg is retired, the variant is deleted
with the next scheduled schema bump.

**Sequencing.** GF-4b's "independently useful, can land ahead of everything
else" is confirmed (§2.1 item 3); this is commit 1 of the implementation.

### 3.4 (d) `BackingSet` — scope split and the zero-pre-bond-output test

**What lands now.** `BackingSet`, a constructor-gated type in
`shekyl-engine-core` (`engine/backing_set.rs`), following the
`JoinMarketVin` constructor-mint pattern (private field, sole constructor,
sibling shape `RetirementWitness`):

- `BackingSet::from_spendable(records, last_sweep_height)` **filters** to
  the backing-eligible lineages — `EmissionReward` and `BondPostChange` —
  and drops `ExternalTransfer`. Possession of a `BackingSet` is proof every
  member is backing-eligible; an ineligible record inside one is
  unrepresentable.
- **Why there is no coinbase rung to weigh (GF4b-1, resolved by owner
  ruling).** GF4b-1 flagged a miner-reward rung as admitted-but-unwargamed:
  the backing reveal deterministically identifies exactly one output
  (`emission_wire.rs` arity-1 pin), so a coinbase backing would publish
  "persona `P` solo-mined block N" — an identity-class disclosure
  (hashrate-set narrowing; rig-uptime timing bridge) that no standoff
  surface covers. The resolution is stronger than exclusion: **the rung
  does not exist** (§3.3) — `P` is shard-serving only, mining stays under
  the principal, and gate-6 rung 1 never covered coinbase. The eligible set
  is `{EmissionReward, BondPostChange}` — both reveal only facts already
  `P`-public (`P`'s loud emissions; `P`'s loud bond posts). Reversion
  clause (rule 21): a mining capability is added to `P` **only** via a
  gate-6 round that wargames the mining-participation disclosure above and
  amends §2.4 GF-4b; absent that, coinbase-to-`P` stays an anomaly that
  classifies rung 3.
- **Filter, not fail-closed, on rung-3 input — deliberately.** Post-bond,
  `P` may legitimately hold *new* raw funding outputs awaiting the next
  re-bond sweep (the multi-tranche exception, §3.5); their presence in the
  wallet is legal. What must be impossible is their presence in the backing
  candidate set — the constructor is the boundary that makes the bad state
  unrepresentable rather than an error to handle (contrast: a fail-closed
  constructor would turn a legal wallet state into a runtime error on every
  between-sweeps emission).
- **The survivor check is armed (GF4b-3).** Silent filtering is
  privacy-right but would make a sweep regression — a rung-3 that should
  have been consumed but survived — indistinguishable from a legitimate
  between-sweeps tranche. The two cases are mechanically separable: a
  legitimate tranche has `height > last_sweep_height`; a survivor has
  `height ≤ last_sweep_height`. The constructor therefore takes
  `last_sweep_height` (at the C-1 call site: the max height of the
  persona's own confirmed bond posts, already durable in
  `bond_post_matches`) and `debug_assert!`s that no `ExternalTransfer`
  record at or below it is present — the sweep-bug case fails loudly in
  debug/test builds, the legal tranche case is untouched, and release
  builds keep filter semantics (a wallet must not crash on a state it can
  filter). **The assert's premise is not airtight (review round, minor
  note on GF4b-3):** because `P`'s funding set is adversary-influenceable
  (§3.3 — anyone can mine or send to `P`'s public pubkey), a rung-3 output
  at `height ≤ last_sweep_height` can also arrive *legitimately after* the
  sweep — a reorg-resurfaced output, or an adversarial low-height output
  discovered late. The assert's doc-comment says "a fire means a sweep bug
  **or** a late-surfaced low-height output — investigate, do not assume
  the sweep," rather than asserting the bug unconditionally. The GF4b-6
  spendability filter (§3.6) removes the *immature* subset of these false
  positives before they reach the constructor; the mature-but-late subset
  remains a benign, debug-only false positive and is accepted as the cost
  of keeping the sweep-regression tripwire armed.
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
  persona slot (raw funding = `ExternalTransfer`, plus a `BondPostChange`
  record from a prior post), the sweep's returned selection, and the
  modeled post-confirmation spendable set (records minus swept gindexes —
  the reservation/spent exclusion applied, since durable pruning is
  SP-R0-gated).
- **Asserts:** (1) the sweep selection **is** the full unreserved
  *spendable* eligible set (§3.6) — including records a greedy subset
  selector would have left behind; (2) the post-sweep **spendable**
  remainder is **empty** — in particular, zero spendable
  `ExternalTransfer` records survive (an immature record may survive a
  sweep by design, §3.6, and is a between-sweeps tranche `BackingSet`
  already drops); (3) the post-bond state (the bond-post
  change record, lineage `BondPostChange`) yields a `BackingSet` containing
  it, while an `ExternalTransfer` record (above `last_sweep_height` — the
  legal-tranche case) injected into the same input set is **not** in the
  resulting `BackingSet`; (4) a rung-3 record at or below
  `last_sweep_height` trips the GF4b-3 survivor `debug_assert!`
  (`#[should_panic]` in debug builds).

### 3.5 (e) Wargamed residuals — preserved, untouched

1. **Single structured `bond_floor + cover` funding output** (lifecycle §3 /
   §3.1): the input-*count* signal on the P-public bond post is mitigated by
   `stake_in` funding each admission as **one** structured output, so the
   sweep consumes one input in the common case. `stake_in` is unbuilt; this
   remains a design constraint on it, restated here so the sweep PR is not
   read as weakening it. The sweep is the mechanism that makes "consume
   everything" and "consume one input" the same statement in the common case.

   **Launch-window disposition (GF4b-2, priority-1 — answered, not
   deferred).** Until `stake_in` lands, every bond post exposes the raw
   funding-input count, and the count correlates to how the principal
   funded `P` (a principal→user-adjacent signal, same class as WI-4's V-2a
   amount prior). The disposition splits by window:

   - **C-1 merge does not gate on `stake_in`.** C-1 activates the emission
     leg in a pre-genesis codebase — no chain, no principals, no bond posts
     exist for the count to leak from. Gating the merge on an unbuilt
     component would buy nothing.
   - **Genesis readiness does gate.** The exposure is **not acceptable at
     launch**: mainnet principals would leak their funding pattern on
     every admission from day one, and per `00-mission.mdc` priority-2 the
     leak cannot be traded for launch schedule. `stake_in`'s
     single-structured-output funding (or an equivalent input-count
     discipline reviewed against the same threat) must land **before
     genesis**. Recorded in `docs/FOLLOWUPS.md`'s V3.0 pre-genesis queue in
     this PR, criterion: "common-case bond-post sweep consumes exactly one
     funding input."

   Reversion clause (rule 21): the genesis gate reopens **iff** a gate-6
   round scores the input-count exposure and accepts it explicitly (e.g.
   finds the count carries no marginal bits over the already-public
   holdings descriptor); re-evaluation shape: gate-6 round entry plus
   FOLLOWUPS-item closure citing it.
2. **Multi-tranche funding stays a conscious exception**, to be noted in
   `stake_in`'s design when it exists — not a default this PR normalizes.
   The `BackingSet` filter (§3.4) is what keeps between-sweeps tranches
   harmless in the meantime.
3. **GF-7 timing unchanged.** Funding↔bond-post *timing* decorrelation stays
   the standoff machinery's job; nothing here touches it. The sweep composes
   with the `stake_engine.rs` funding↔bond-post decorrelation reasoning and
   the SP-3/SP-5 dual-extract (funding + bond-post as two scanned events) —
   beside, not against.

### 3.6 (f) Sweep × spendability — the eligible set is the *spendable* set (GF4b-6)

**The finding.** The sweep's defining property — consume everything, no
subset — collides with output maturity, and nothing in the funding path
catches it: `select_funding_outputs` filters on `p_slot` and `reserved`
only (verified §2), with no maturity/spendability check anywhere between
scan ingestion and selection. Two arrival paths for an unspendable record,
one mundane, one adversarial:

- **Ordinary flow, no adversary (substrate check — stronger than the
  finding as raised).** Shekyl's maturity model is **universal deferred
  tree insertion** (`cryptonote_config.h` FCMP++ parameters;
  `shekyl-curve-tree` `recon.rs::maturity_height`): an output enters the
  curve tree only at `height + COINBASE_LOCK_WINDOW` (60, coinbase) or
  `height + DEFAULT_LOCK_WINDOW` (10, regular). *Regular outputs carry a
  lock too* — so `P` funded within 10 blocks of bonding holds an immature
  record, and the sweep must include it, with **zero** adversarial input.
  The subset selector masked this by accident (an immature record was
  selected only when among the oldest sufficient); the sweep's rigidity
  converts "an immature output exists in `P`'s set" into "`P` cannot
  bond."
- **Adversarial (the §3.3 anomaly's second-order consequence).** The same
  fact the coinbase-anomaly classification leans on — `P`'s hybrid pubkey
  is on-chain, so a third party can mine to it — means `P`'s funding set
  is adversary-influenceable. An adversary mines a coinbase to `P` (cost:
  one block of PoW); the scanner recovers it; accrual ingests it as an
  `ExternalTransfer` funding record (no coinbase filter, and per §3.3 none
  is wanted — lineage is not spendability); the next sweep must consume
  it, and the bond is denied for up to 60 blocks. Cost-bounded targeted
  griefing, but real, and *introduced by the sweep conversion*.

**The failure locus (daemon-side confirmation, as requested).** The
reviewer's chain assumed a daemon `unlock_time` rejection; the substrate
is one step harsher. Under deferred tree insertion the immature output's
**leaf is not in the curve tree at all** until maturity, so the bond
post's membership path cannot be constructed against any reference block
that precedes maturity — assembly fails client-side before a rejectable
tx even exists. (The daemon-side coinbase-maturity rule also exists:
`blockchain.cpp` enforces coinbase `unlock_time = height + 60`, and
nonzero `unlock_time` on regular txs is pool-rejected, so the lock
windows above are the entire spendability surface.) Either locus yields
the same denial; deferred insertion just moves it earlier.

**Decision.** The sweep's eligible set is defined as the full unreserved
**spendable** eligible set (§3.1 Adds). Mechanism: **share the
already-landed transfer-path computation — one function, not a parallel
formula** (review-round sharpening; two mirrors of tree-insertion would
be the derive-don't-cache anti-pattern, and the sweep's copy drifting is
silent because the transfer path's tests would not catch it):

- `TransferDetails` already carries `eligible_height =
  max(height + SPENDABLE_AGE, timelock_block)` (`ledger_ext.rs` X5/CT-5c),
  documented as *agreeing with the tree-insertion height by construction*.
  The X5 expression is **extracted into a shared
  `pub fn eligible_height(block_height, additional_timelock)`** whose home
  is `shekyl_engine_state::transfer`, beside `SPENDABLE_AGE` — the deepest
  crate both consumers already depend on directly (`shekyl-scanner` and
  `shekyl-engine-core` each dep `shekyl-engine-state`; `Timelock` is
  `shekyl-types`, which it also deps). X5's `ledger_ext.rs` call site
  converts to call it (mechanical, exact-expression extraction), and
  `PFundingOutputRecord`'s **`spendable_height`** field stores *literally*
  the same function's result. The sweep-filter's correctness thereby
  reduces transitively to the guarantee the transfer path already tests
  (X5 == tree-insertion): if `maturity_height` ever changes, X5 breaks the
  transfer path loudly and the sweep inherits the fix — one definition of
  "in the tree," caught in one place.
- **The constant unifies too (the residual drift seam under the shared
  formula, closed).** `SPENDABLE_AGE` is today an independent literal
  `10` in `shekyl-engine-state`, while tree insertion
  (`recon.rs::maturity_height`) uses `shekyl_consensus::DEFAULT_LOCK_WINDOW`
  — two constants that happen to agree. `shekyl-engine-state` gains the
  `shekyl-consensus` dep (featherweight: `thiserror` + `serde` only, no
  reverse dep, no cycle — rule-17 verified at source) and `SPENDABLE_AGE`
  is redefined as `DEFAULT_LOCK_WINDOW as u64`, so the regular-output
  insertion age has exactly one definition. The coinbase +60 remains
  *contingent* on two consensus invariants — coinbase
  `unlock_time == height + 60` exactly (`blockchain.cpp:1534`) and regular
  `unlock_time == 0` (pool-rejected otherwise) — which is inherent to the
  timelock channel; the contingency is recorded once, in the shared
  function's doc-comment, not copied per call site.
- **Computation site: `run_dual_extractor`,** which already holds both
  inputs: the block height, and the recovered output's
  `additional_timelock()` (the scanner captures `tx.prefix.unlock_time`,
  which for a coinbase *is* the +60 lock — consensus-enforced shape — so
  **no miner-tx-hash comparison returns**; the deleted lineage arm stays
  deleted, and coinbase maturity arrives through the timelock channel).
  The seam calls the shared `eligible_height`, never a local formula.
- **Filter site: `sweep_funding_outputs`,** which takes the reference
  height the assembly anchors at and excludes records with
  `spendable_height > reference_height`. The exclusion is *deferral*, not
  loss: an excluded record stays in the funding set and is consumed by the
  next sweep after maturity — exactly the multi-tranche legal state §3.5
  item 2 already models.
- **GF-4b interaction — none, by the fail-toward-forbidden shape.** An
  immature record excluded from the sweep is a between-sweeps rung-3
  tranche; `BackingSet` (§3.4) already drops it from backing eligibility.
  Spendability filtering can only *shrink* the swept set, never lift
  anything onto rungs 1/2, so the firewall property is untouched. The
  structural-emptiness claim is refined, not weakened: "nothing raw
  survives backing-eligible" was always enforced by `BackingSet`, not by
  the sweep's totality; the sweep's totality claim is now "nothing raw
  *and spendable* survives," which is the strongest claim a consensus-
  valid transaction can deliver.

**Reversion clause (rule 21).** The `spendable_height` mechanism reopens
**iff** the deferred-insertion maturity parameters change (a consensus
change to `COINBASE_LOCK_WINDOW`/`DEFAULT_LOCK_WINDOW` or the insertion
rule itself); re-evaluation shape: the consensus PR amends the shared
`eligible_height` function — there is exactly one computation to amend,
by construction (the lockstep is structural, not discipline; a divergence
would recreate the unprovable-spend bug X5 exists to prevent). Not
reopenable on wallet-convenience grounds.

## 4. Test plan (gates)

1. **Lineage classification KATs** (`scan_step.rs`): output in a tx
   carrying the *same* persona's `BondPost` → `BondPostChange`; plain
   transfer → `ExternalTransfer`; output in a tx carrying a *different*
   held persona's `BondPost` → `ExternalTransfer` (conservative default);
   a coinbase output recovered by `P`'s scanner → `ExternalTransfer` (the
   anomaly pin, §3.3 — `P` never mines, so a coinbase-to-`P` must land on
   the forbidden rung); lineage **and `spendable_height`** survive the
   `FundingOutputMatch ↔ PFundingOutputRecord` round-trip; a
   timelocked (coinbase-shaped, `unlock_time = height + 60`) recovery
   yields `spendable_height = height + 60` while a plain transfer yields
   `height + SPENDABLE_AGE` (both values produced by the *shared*
   `eligible_height` function, §3.6 — the KAT pins the seam calls it, not
   a local formula).
2. **Sweep KATs** (`bond_assembly.rs`): full-set consumption (the
   multi-record case greedy would have truncated); reserved exclusion
   retained; slot scoping retained; `InsufficientFunding` ramp refusal
   retained; deterministic oldest-first ordering of the swept list;
   **spendability exclusion (GF4b-6): an immature record (coinbase-shaped
   `spendable_height` above the reference height) in the record set is
   excluded from the sweep and the returned selection is otherwise the
   full spendable set — the bond post stays buildable with the injected
   record present**. KATs mint the `SpentRecordsDurablyPruned` witness
   through its `#[cfg(test)]` constructor (§3.2 GF4b-5); a compile-time
   check that no production constructor exists is the witness's own
   doc-comment contract. Implementation-time grep gate (§3.2 chokepoint
   note): no funding-selection entry other than `sweep_funding_outputs`
   reaches the assemble path.
3. **Zero-pre-bond-output test + `BackingSet` gates** (§3.4 definition):
   the four assertions, plus the constructor filter (`ExternalTransfer`
   in, not present), the survivor `debug_assert!` firing on a pre-sweep
   rung-3 (GF4b-3), and standard redaction/`Debug` discipline if the type
   carries record contents.
4. **Schema**: `PSCAN_STATE_VERSION` 5 load-refusal test (the existing
   version-gate test pattern); snapshot regenerated; CI snapshot check.

## 5. C-1 residue (named criteria — the mechanical precondition check)

After this PR, the §8.0.3 precondition state is: ladder **specified** ✓,
sweep **specified + implemented** ✓ (go-live dead-code-gated per §3.2),
pre-join wiring (`BackingSet` + zero-pre-bond-output test) **landed** ✓.
The residue riding C-1, citable by the C-1 PR:

> **Status (2026-07-11, claim-builder PR-3 — `feat/emission-claim-handler`).**
> Items **1, 2, 3, and 6 discharged** by PR-3
> (`EMISSION_CLAIM_BUILDER.md` §8): the arity-1 designated-backing
> selector (`BackingSet::designate_backing`, exclusivity by shape — the
> backing record is private to the set), the `EmissionReward` scan arm
> (fail-toward-forbidden per GF4b-4; first-emission backing classifies
> `BondPostChange`), the emission-path integration test (orchestrator
> end-to-end over a real curve tree), and the reference-height freshness
> contract (the claim orchestrator derives designation and assembly from
> the same gather tip; the handler's item-6 same-tip check refuses
> mismatches at runtime). Items **4 and 5 remain open**: item 4 held —
> PR-3 added no production `SpentRecordsDurablyPruned` constructor (the
> orchestrator takes the witness by reference; the sole production mint
> stays reserved to SP-R0) — and continues to bind every future caller;
> item 5 is bond-path scope (`AssembleBond` wiring), untouched by the
> claim path.

| # | Item | Criterion (checkable at C-1 review) |
| --- | --- | --- |
| 1 | Designated-backing selector | Consumes candidates **exclusively through `BackingSet`** (no direct `funding_outputs` read on the backing path); selects exactly **one** output (the `emission_wire.rs` arity-1 pin) |
| 2 | `EmissionReward` scan arm | `run_dual_extractor` classifies outputs of txs carrying `P`'s own emission vin; the reserved variant gains its first constructor site. **The arm obeys fail-toward-forbidden (GF4b-4): anything not structurally proven to carry `P`'s own emission vin classifies `ExternalTransfer`** — a misclassification may only exclude a safe output, never admit an unsafe one into the eligible-but-previously-unpopulated rung |
| 3 | Emission-path integration test | First-emission backing is `BondPostChange` (bootstrap); a rung-3 record cannot reach the vin builder |
| 4 | Go-live gate (§3.2, structural per GF4b-5) | The `SpentRecordsDurablyPruned` witness still has **zero production constructors** — C-1 must not add one; the sole production mint belongs to SP-R0. The review item is a confirmation, not a memory burden. **DISCHARGED 2026-07-18: SP-R0 arm #1 minted the sole production constructor (`arm1_watch_pruning_live`; key-image watch + prune-at-ingest landed, logic-discharged per the DQ-F split — production-firing gated on the staker-activation round); the tripwire now asserts exactly-one production constructor** |
| 5 | Assemble change-split / tx-size bound (correctness facet of GF4b-2) | The sweep consumes the **entire** spendable eligible set with no expressible subset (§3.1), so the assemble path C-1 wires around `FundingSelection` must fold an arbitrarily large remainder into the single change output **and** keep the assembled tx within the daemon's per-tx input-count / size limit. Criterion: a persona with many small funding outputs cannot produce a bond tx the daemon rejects as oversize — the assemble path bounds or splits rather than trusting the swept cardinality. (Distinct from GF4b-2, which is the *privacy* input-count leak; this is the *rejection* facet) |
| 6 | `reference_height` freshness contract | `sweep_funding_outputs` filters `spendable_height ≤ reference_height`; a `reference_height` that lags the height the tx is actually built against silently shrinks the swept set into a spurious `InsufficientFunding` (an undiagnosable bonding denial — the funds exist and are mature). Criterion: the C-1 caller derives `reference_height` from the same tip it assembles against, never a stale snapshot |

## 6. Review round (2026-07-08)

Substrate re-verified at `c72d2ec` with zero Phase-0 drift; the ladder and
sweep conversion were confirmed correct as designed. Six findings, all
dispositioned in place:

| Finding | Class | Disposition |
| --- | --- | --- |
| GF4b-1 — a miner-reward rung admitted without its own wargame | privacy, priority-1 | **Resolved by owner ruling, strongest form: the rung does not exist** (§3.3/§3.4). `P` is shard-serving only; mining stays under the principal (adding capability to `P` adds identification surface), and gate-6 rung 1 ("public *emission* history") never covered coinbase. Coinbase-to-`P` is an anomaly that classifies rung 3 structurally; the GF-7-reduction check (fails: identity-class vs timing-class) is recorded at §3.4 as the wargame any future readmission must answer |
| GF4b-2 — sweep input-count leak live until `stake_in` | privacy, priority-1 | **Answered directly** (§3.5 residual 1): tolerable for the pre-genesis C-1 window (no principals exist), **not acceptable at genesis** — `stake_in` (or equivalent input-count discipline) gates genesis readiness; FOLLOWUPS V3.0 pre-genesis-queue item added |
| GF4b-3 — filter-not-fail-closed masks sweep regressions | correctness / silent-failure | **Accepted**: survivor check armed (§3.4) — `debug_assert!` that no rung-3 with `height ≤ last_sweep_height` reaches `BackingSet` construction; tranche case untouched |
| GF4b-4 — reserved `EmissionReward` eligible before its classifier exists | privacy / firewall | **Accepted**: fail-toward-forbidden bound to the C-1 arm as a checkable acceptance criterion (§5 item 2) |
| GF4b-5 — go-live gate was review-discipline against poison-severity | structural preference | **Accepted**: `SpentRecordsDurablyPruned` witness token, sole production constructor reserved to SP-R0 (§3.2); §5 item 4 becomes compiler-enforced |
| GF4b-6 — sweep totality collides with spendability; adversary-influenceable funding set | correctness + cost-bounded griefing | **Accepted, and strengthened at source** (§3.6): the substrate check found the bug fires with *zero* adversary (regular outputs carry the +10 `DEFAULT_LOCK_WINDOW` under deferred tree insertion, so a fresh funding transfer is immature too), and the failure locus is client-side (the immature leaf is absent from the curve tree — no membership path — before any daemon rejection). Fix: `PFundingOutputRecord` gains `spendable_height`, stored at the scan seam as the result of the **shared** X5 `eligible_height` computation — extracted to `shekyl_engine_state::transfer` and called by both the transfer path and the seam, never re-implemented (single-source sharpening, this round); `SPENDABLE_AGE` is unified onto `shekyl_consensus::DEFAULT_LOCK_WINDOW` to close the two-constants-both-10 drift seam. The sweep's eligible set is the *spendable* eligible set. KATs added (§4 items 1–2). Two minor notes absorbed: the GF4b-3 survivor assert's doc-comment names its adversarial/reorg false-positive mode (§3.4), and the witness gate carries a chokepoint-monopoly grep check (§3.2, §4 item 2) |

Hygiene: the WI-2 §3.2 amendment carried a design-doc fossil-sweep — the
one live dependent found is `ARCHIVAL_BOND_WI4_MEASUREMENT.md`'s
amount-leak trace ("greedily selects … until `sum ≥ bond_floor + fee`"),
amended in this PR alongside WI-2 §3.2 (other grep hits are CHANGELOG
history and unrelated selection semantics in the send-path/sim docs). The
`EmissionReward` justification now leads with ladder-completeness (§3.3);
bump-avoidance is demoted to a parenthetical.

## 7. Round closure

Round 1 + review round close with dispositions §3.1–§3.6 (as amended by
§6) ratified by landing. Reopening criteria are per-disposition (each §3.x
carries its own rule-21 clause); substrate findings, not sequential
numbering, reopen the round.
