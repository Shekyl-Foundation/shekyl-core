# Wallet-side emission claim builder (E4-gate, part 1 of 2)

**Status: design round 1 — OPEN (2026-07-09).**

**Provenance.** C-1 (the emission activating cut) merged to `dev` 2026-07-09
via PR #277 (`13c368707`); consensus now accepts authed
`txin_archival_reward_emission` transactions — but **no production path can
build one**. This doc is the spec-first round for that builder, the first
half of the E4 merge gate:

> E4 merges only on **emission accepted-and-applied on a regtest chain
> through the real C-1 consensus path** — not E3's Rust KAT.
> ([`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md) §3.0)

The regtest e2e (part 2, [`REWARD_EMISSION_E3_GATING_ROUND.md`](REWARD_EMISSION_E3_GATING_ROUND.md)
§9.5 item 8) is **blocked on this builder** because a hand-rolled test
builder would exercise a parallel path — the opposite of what the e2e
exists to prove (`docs/FOLLOWUPS.md`, V3.0 queue, "Emission regtest
end-to-end — the E4/E5 gate").

**Timeframes (rule 05).** Now: unblocks E4/E5 and the Track-2 e2e.
Mining-era end: the claim path is the staker-reward payout rail for the
fee-transition era — the recompute-sourcing decision (CB-1) must not bake
in a genesis-only data path. V4: signing rides `HybridSignature`
(Ed25519 + ML-DSA-65) and inherits the V4 lattice-only migration like every
other hybrid surface; nothing here adds a new V4 dependency.

---

## 1. Substrate — verified at source, `dev` = `13c368707`

Everything the builder composes already exists; the builder is assembly,
custody, and sourcing — not new cryptography.

| Piece | Where | State |
| --- | --- | --- |
| Vin wire struct + canonical encode + `validate()` | `rust/shekyl-archival-retention/src/emission_wire.rs` (`ArchivalRewardEmissionVin`) | Landed (E2); wire positivity (`reward_amount_plain[i] > 0`) enforced at `validate()` |
| Both auth binding messages | `emission_wire.rs` `auth_msgs` (one shared R1.A inventory, two cSHAKE customizations) | Landed; builder signs what verify checks — no second message builder |
| Hybrid sign | `rust/shekyl-crypto-pq/src/signature.rs` (`SignatureScheme::sign`) | Landed |
| Membership-only prover | `rust/shekyl-fcmp/src/proof.rs:488` `prove_membership_only` (KAT'd against `verify_membership_only`) | Landed |
| Backing-eligibility gate | `rust/shekyl-engine-core/src/engine/backing_set.rs` (`BackingSet`, constructor-mint, GF4b-6 spendability filter inside) | Landed, `dead_code` — **this builder is the named consumer** (GF-4b §5 item 1) |
| Verifier-exact share math | `rust/shekyl-archival-retention/src/reward_arithmetic.rs` (`reward_share_floor`), `consensus_state.rs` (`as_of_e_served_work`, `capped_work_milli`, `shard_contribution_milli`) | Landed (WS-1); the builder must call **these**, not fork them |
| Claim-window predicates | `claimed_epochs.rs` (`claim_window_floor`, `epoch_is_claim_expired`, `claimed_epochs_contains`) | Landed; `stake_engine.rs` already consumes `epoch_is_claim_expired` for retirement |
| Key custody + P-side signing precedent | `rust/shekyl-engine-core/src/engine/stake_engine.rs` (`SignBond` handler: seed-owning actor, secrets never cross the actor boundary) | Landed |
| Track-2 regtest harness | `rust/shekyl-engine-core/src/engine/regtest_e2e.rs` (real `shekyld --regtest`, `SHEKYLD_BIN`, serialized daemons) | Landed; the e2e rides this family |

---

## 2. What the builder does (the assembly spec)

One entry point, persona-side, producing a fully-signed emission
transaction (or a typed refusal). Steps in dependency order; each step
names the landed function it must reuse:

1. **Claimable-epoch derivation** — the pinned obligation
   (`docs/FOLLOWUPS.md` M1 round-1 record): claimable epochs are derived
   from **the same positive-share recompute** the verifier runs. For each
   candidate `E` in `[claim_window_floor(settled), settled]`, not already
   in the bond record's claimed set: recompute the share via
   `as_of_e_served_work` → `capped_work_milli` → `reward_share_floor`;
   claimable ⇔ share `> 0`. No `K_COVER` consultation (the vin never
   consults it — M1 wire-positivity resiting), no row-absence proxies.
   Batch up to `MAX_SETTLEMENT_EPOCHS_PER_EMISSION = 15`, strictly
   increasing.
2. **Work-claim assembly** — per epoch, the `WorkEpochClaim` /
   `ShardWorkEntry` rows (`shard_id`, `serve_credit_bit`,
   `scarcity_milli`) exactly as the verifier will recompute them
   (integer-exact, tolerance zero). Sourcing is **CB-1** (§3).
3. **Backing selection** — exactly one output, obtained **exclusively
   through `BackingSet::from_spendable`** (GF-4b §5 item 1; no direct
   `funding_outputs` read on the backing path), with `reference_height`
   derived from the same tip the tx is assembled against (item 6 — a
   stale snapshot silently shrinks the set into a spurious
   `InsufficientFunding`).
4. **Membership proof** — `prove_membership_only` over the selected
   backing output against the reference block's tree root.
5. **Reward vouts + fee inputs** — the ordered `RewardCommit` set
   (commitment, loud `amount_plain`, one-time key) for the per-epoch
   amounts; fee inputs are ordinary FCMP++ `txin_to_key` spends
   (verify step 7 is the existing tx layer). Amounts are the step-1
   recomputed shares — the builder never invents an amount.
6. **Dual auth** — `auth_msgs` over the R1.A inventory + reward-commit
   set digest + signable tx hash (F-C1c exclusion rule), then two
   `HybridSignature::sign` calls (backing role, claim role) inside the
   key-custody boundary (CB-2).
7. **Self-check before broadcast** — run the landed
   `emission_vin_verify_claims`/`_backing`/`_auth` against the assembled
   vin. A builder/verifier disagreement is a bug surfaced **loudly at
   build time**, never a mempool rejection to diagnose post-hoc. This is
   the differential test made a production invariant (M1's
   walk-vs-counter idiom applied to assembly).

Everything above is deterministic given (claimable set, backing choice,
fee inputs) — the builder is KAT-able end-to-end at the Rust layer before
the regtest e2e composes it with consensus.

---

## 3. Design questions (round 1) — CB-1…CB-5

Identifier family `CB-N`, registered in `IMPLEMENTATION_INDEX.md` §2 in
this PR (rule 94 prefix-uniqueness check run against
Phase/Stage/M/Bond-PR/SP/SP-T/PR-A/PR-B/PR-E/CT/GF/S/R/F/DQ/SCE/WI/M1: passes).

### CB-1 — recompute sourcing: where does the wallet read archival state?

**The question that gates everything.** Steps 1–2 need, per epoch: the
persona's serve-credit bits per shard, `scarcity_milli` inputs, the frozen
`Σwork_milli` denominator, and `budget(E)` — data the **daemon's LMDB**
owns (`archival_bond_record`, `archival_budget`, epoch-close rows). The
verifier reads it in-process; the wallet cannot.

Candidate paths, with the constraint set each must satisfy
(**verifier-exactness** — WS-1's bits-sourcing conjunct applies to the
builder too, a near-miss recompute is an invalid-tx generator;
**gate-6** — persona-side reads must not link `P` to the principal's
daemon identity; **mining-era end** — the path must survive as the
long-term payout rail):

- **(a) New daemon RPC** exposing the as-of-`E` snapshot per `(P, E)`
  (the same gather `shekyl_archival_emission_epoch_work` marshals for
  verify). Pro: single source of truth, byte-identical operands. Con: a
  new public RPC surface; persona-side calls must ride the `P`-isolated
  transport (`PTorClient`/`PRpc`) under the 2d-2 posture rules — under
  the **local-daemon posture** (WI-4's graded assumption) this collapses
  to loopback and is clean.
- **(b) Extend the `P`-scan pipeline** to accrue serve-credit/work state
  wallet-side (as `pscan/accrual.rs` does for funding inflows). Pro: no
  new RPC; offline-capable. Con: it adds a **fourth evaluator** of the
  consensus work arithmetic. `capped_work_milli`
  (`consensus_state.rs:182-188`) is the *single definition* of the
  per-`P` contribution to `Σwork(E)`, and its doc comment is explicit
  that it is sourced once so the three existing consumers — the persisted
  denominator (`sigma_work_milli`), the emission numerator FFI
  (`shekyl_archival_emission_epoch_work`), and the verify body
  (`emission_verify`) — **cannot drift**: "the M-2 sourcing-divergence the
  WS-1 design makes *unrepresentable rather than tested-against*." A
  wallet-side re-derivation is a fourth evaluator that is *not* sourced
  from that definition (different crate, reading raw chain state), which
  resurrects the WS-1 M-2 divergence as a **consensus-divergence** class:
  the wallet computes a share the daemon's verifier rejects, surfacing as
  an undiagnosable rejected claim. Rejected — not because it is a
  divergence *risk*, but because it violates a single-evaluator invariant
  the landed code already structurally enforces (reversion: rule 21, only
  if (a) is shown unviable).
- **(c) Regtest-only shortcut** (direct LMDB read or test RPC) to unblock
  the e2e now, deferring the production path. Rejected: the e2e exists
  to prove **the production path**; a test-only sourcing path is the
  parallel-builder anti-pattern the FOLLOWUPS entry names.

**Round-1 disposition: (a) — RATIFIED (2026-07-09).** The RPC response is
shaped as the existing verify-side gather struct (one marshaling shape,
two consumers — the WS-1 "one accessor" idiom at the RPC boundary). The
ratifying reason is **structural, not preference**: the operands
(`serve_credit` bits, frozen `Σwork`, `budget(E)`) are consensus-
authoritative values the daemon — the *sole* authoritative evaluator —
has already computed and frozen; (a) makes the wallet *consume* those
frozen operands, so the only arithmetic the wallet does is the share
division over already-consensus-final values. (a) therefore **preserves**
the single-evaluator invariant `capped_work_milli` enforces; (b) breaks
it. That is the durable justification (it forecloses a future reviewer's
"why not recompute wallet-side to avoid the RPC dependency" — the answer
is that the RPC is not avoiding a hazard, it is preserving an invariant).

Ratification residue (round 2): the RPC's exact field set enumerated
against `EpochCloseInputs` + `emission_verify.rs`'s `EmissionEpochSource`,
and the gate-6 review of the query's linkability surface (a `(P, E)` query
names `P` — public by role, but the *transport* must be the persona's,
never the principal's session).

**Trust bound — the lying-daemon wargame (pinned).** The RPC sources
consensus-authoritative operands from the daemon, so it inherits a trust
posture. A daemon that returns *wrong* operands makes the wallet build a
claim the real network rejects — a **denial-of-claim (liveness)**, never a
theft or a false mint: every other verifier recomputes the share
independently and rejects a bad one, so `P` **cannot be made to
over-claim**. The RPC is therefore *safe-by-recomputation* against
false mint and a *claim-liveness* dependency on the daemon — the same
posture as the WI-3 tip clock, sound under the recommended local-daemon
posture (loopback). It **joins the 2d-2 remote/untrusted-daemon reopen
family** (the tip-clock invariant; WI-3 D-B6; WI-4 §11 named residual): a
remote/untrusted daemon reopens "can the daemon deny my claims by feeding
bad operands," mitigated in the same class (cross-check operands against
independently-observable chain state where possible, else accept claim-
liveness as a local-posture assumption). The step-7 build-time self-check
is **necessary-not-sufficient** against this: it catches operands that
produce a *self-inconsistent* claim, but not operands that are internally
consistent yet wrong (a daemon lying *consistently*) — the same shape as
the F41 tripwire being necessary-not-sufficient for the full constant-work
claim (`DAEMON_SUBMIT_VERDICT.md` §F41).

### CB-2 — locus: which actor owns assembly?

The auths sign with `P`-side keys whose custody lives in the seed-owning
`StakeEngine` actor (`SignBond` precedent: secrets never cross the actor
boundary; rules 35/36). Recommendation: assembly runs **inside the
StakeEngine actor** as a sibling of the `SignBond` handler — message in:
claim intent + sourcing handle; message out: signed tx bytes (public) —
with the pure assembly steps (1, 2, 5, 7) in a new
`engine/emission_claim.rs` module the actor calls, so the KAT surface
does not need an actor harness. The membership-prover input (the backing
output's opening) is already persona-side state.

### CB-3 — claim cadence and the GF-7/GF-4 seams

*When* to claim is a privacy parameter: claim timing is an entry-seam
adjacent channel (WI-4 §18.10 routes claim-cadence/amount grading to the
GF-4 round; quantization is a named candidate). Round-1 disposition:
the builder takes an explicit `claim_epochs` input and **does not
self-schedule**; scheduling policy (which epochs, when, batched how)
is a separate seam that the GF-4 round grades — same shape as WI-3's
dispatch driver consuming WI-2's sealed posts. The builder must not
foreclose quantization (batching is already first-class via the
15-epoch cap). Reversion: if GF-4 grades a mandatory cadence rule, it
lands in the scheduler, not here.

### CB-4 — fee sourcing for the claim tx

The claim tx needs fee inputs (verify step 7: ordinary FCMP++ over
`txin_to_key`). Whose outputs? Using `P`'s own funding/change outputs
keeps the tx persona-pure (no principal linkage) but consumes
backing-eligible mass; Q11 (ratified ACCEPT) already permits same-tx
backing + key-imaged fee double-use, with the balance-exclusion KAT as
its reopen. Round-1 recommendation: fees from `P`'s spendable set via the
existing selection machinery, **excluding** the designated backing output
from the fee-selection candidate set only when the Q11 same-output case
would otherwise be exercised unintentionally — make the Q11 case an
explicit choice, not an accident.

### CB-5 — refusal taxonomy

Rule 82: every refusal is a named, actionable error — `NoClaimableEpochs`
(all shares zero or window-expired: not an error, an idle state),
`AlreadyClaimed`, `InsufficientBacking` (empty `BackingSet` — distinct
from `InsufficientFunding` for fees), `WindowExpired` (per epoch),
`SelfCheckFailed` (step 7, loud, bug-class). The zero-share case must
**not** surface as "gated" vs "no work" — gatedness is publicly
computable ex ante but the share recompute doesn't distinguish the causes
(M1: the vin never consults `K_COVER`), and the builder must not either.

---

## 4. Inherited obligations (pinned elsewhere, discharged here)

The **landed-anchor** column names the file:line the reviewer verifies the
landed substrate against (confirmed at source, `dev` `13c368707`); the
**discharged-by** column names where this builder's forward code satisfies
the obligation. The two are distinct on purpose — a criterion can have
landed substrate (verifiable now) and a forward discharge (this builder's
PR).

| Obligation | Source | Landed anchor (verify at source) | Discharged by |
| --- | --- | --- | --- |
| Claimable epochs from the positive-share recompute | `docs/FOLLOWUPS.md` M1 round-1 forward pin | `reward_arithmetic.rs:129` `reward_share_floor`; `consensus_state.rs:190` `capped_work_milli` (single evaluator) | §2 step 1 |
| Backing exclusively through `BackingSet`, arity 1 | GF-4b §5 item 1 | `backing_set.rs:44` (private `records`), `:90` (`from_spendable` sole constructor), `:103` (spendability filter); arity-1 pin `emission_wire.rs:116-125` (Q3 vacuous at arity 1) | §2 step 3 |
| `EmissionReward` scan arm, fail-toward-forbidden | GF-4b §5 item 2 | `pscan_state.rs:89` (`MintLineageOutput`; `:98` `EmissionReward`, `:103` `BondPostChange`, `:109` `ExternalTransfer`); `scan_step.rs:401` `run_dual_extractor`, `:501-511` fail-toward-forbidden default. **`EmissionReward` has zero production constructor sites today** (verified: only the enum def) — this is exactly the "gains its first constructor site" claim | Companion piece: the arm's first constructor lands with this builder's PR chain (its absence would strand claim change in rung-3) |
| First-emission backing is `BondPostChange` | GF-4b §5 item 3 | `pscan_state.rs:103` (`BondPostChange` variant) | Integration test (§5) |
| No `SpentRecordsDurablyPruned` production mint | GF-4b §5 item 4 | `bond_assembly.rs:231` (struct), `:238` (`for_test()` — **sole** constructor, no production mint) | Review confirmation at PR boundary (C-1 must not add one) |
| Change-split / tx-size bound | GF-4b §5 item 5 | `bond_assembly.rs:311` `sweep_funding_outputs`, `:488` "oldest-first — no early break at required, no expressible subset" (the entire-set consumption the bound must fold/split) | §2 step 5 sizing rule (bound or split; a many-outputs persona cannot build a daemon-rejected oversize tx) |
| `reference_height` freshness | GF-4b §5 item 6 | `backing_set.rs:96-103` (`spendable_height <= reference_height` filter, applied by the constructor itself) | §2 step 3 (same-tip derivation) |
| Wire positivity (`reward_amount_plain[i] > 0`) | M1 round 2 (M1-1, wire resiting) | `emission_wire.rs:400` `validate()`, `:440` rejects any `reward_amount_plain[i] == 0` (the zero-row beacon unencodable) | §2 step 1 (share `> 0` is the claimability predicate) + `validate()` at step 7 |

---

## 5. Test plan (gates)

- **Rust unit/KAT:** builder-vs-verifier differential (assemble → the
  three landed verify functions accept; mutate any operand → reject);
  claimable-epoch derivation against fixture close states (zero-share,
  window-floor, already-claimed, 15-cap batching); CB-5 refusal taxonomy;
  GF-4b item-3 integration test (first-emission backing =
  `BondPostChange`; rung-3 unreachable).
- **The e2e itself (part 2):** rides `regtest_e2e.rs` — mine to an epoch
  close with served work, build via **this** path, submit over the real
  RPC, assert accepted-and-applied (claimed-set row + vout shape), then
  the reorg/pop leg. Green e2e ⇒ E4 unblocks
  (`REWARD_EMISSION_VIN_PLAN.md` §3.0 gate).
- Standard gates per rules 45/50: `cargo fmt --check`,
  `clippy --all-targets -- -D warnings`, workspace tests.

## 6. What this unblocks

Builder + e2e green → **PR-E4** (delete `txin_stake_claim`/`C_stake`,
the one irreversible step) → **PR-E5** (constants + KAT completion +
audit-scope + doc sweep) → the emission leg closes.

Round-1 review requests: ratify CB-1(a) (or name the unviability),
CB-2 locus, CB-4 fee-exclusion shape; confirm CB-3's
builder/scheduler split and CB-5's cause-blind zero-share refusal.
