# Wallet-side emission claim builder (E4-gate, part 1 of 2)

**Status: design round 2 — CLOSED (2026-07-09).** §7.1/§7.2/§7.3/§7.4
ratified and §8 endorsed, with two record-sharpenings applied at
ratification: the §7.1 single-gather pin is recorded as CB-1(b) itself
(one invariant, two faces — wallet doesn't re-derive, RPC doesn't
re-gather), and the §7.3 `frozen_shard_count` exclusion (formerly
`k_cover`/`frozen_shard_count`) is recorded as CB-5-structural, not
payload-minimization — re-anchored 2026-07-20 after the `K_COVER`
retirement, and still armed: `frozen_shard_count` now separates a live
zero-cause on its own. The one open
verification (the §2 low-boundary anchor) resolved clean-for-a-structural-reason:
the low end anchors to `epoch_is_claim_expired`, which is single-sourced
through `claim_window_floor` (§7.2 bottom-boundary record), and the
builder is pinned to consume the predicate functions rather than
re-derive boundary arithmetic. Implementation is underway on the §8
chain: PR 1 (daemon RPC), PR 2 (pure assembly module), and PR 3
(StakeEngine handler + Engine-side claim orchestrator; see the §8
PR-3 status) are implemented — the production path assembles a signed
emission claim end-to-end; PR 4 (regtest e2e + blob-boundary arm) is
the chain's only open item, gated on #281. PR-2 review produced one
post-closure sharpening, the
§2 step-1 **fourth boundary** (strict finalization at the earliest
inclusion height; the connect window admits the youngest epoch one
count before verify accepts it — see the step-1 text and the §8 PR-2
status). PR-1 review watch items are
named at the end of §8. Round 1
CLOSED (2026-07-09): CB-1…CB-5 all ratified at source (§3): CB-1 (new
daemon RPC as `EmissionEpochSource`, single-evaluator invariant the
ratifying reason); CB-2 (StakeEngine actor,
sign-within-seed-gone-after-`assemble()` pin); CB-3 (routing-not-closure,
joint-grading reopen); CB-4 (structural three-leg exclusion ratified; arming
KAT strengthened to production operand functions + E3/rationale doc fixes
done in-PR; blob-boundary arm homed to §8 PR-4); CB-5 (cause-blind
refusal, `SelfCheckFailed`-blind pin). Round 2 (§7) is the CB-1
ratification residue — the RPC field enumeration + gate-6 linkability
review — plus the implementation-plan PR chain (§8). Implementation is
held until round 2 closes.

**Provenance.** C-1 (the emission activating cut) merged to `dev` 2026-07-09
via PR #277 (`13c368707`); consensus now accepts authed
`txin_archival_reward_emission` transactions — but **no production path can
build one**. This doc is the spec-first round for that builder, the first
half of the E4 merge gate:

> E4 merges only on **emission accepted-and-applied on a regtest chain
> through the real C-1 consensus path** — not E3's Rust KAT.
> ([`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md) §3.0)

The regtest e2e (part 2, [`REWARD_EMISSION_E3_GATING_ROUND.md`](../completed/REWARD_EMISSION_E3_GATING_ROUND.md)
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
| Backing-eligibility gate | `rust/shekyl-engine-core/src/engine/backing_set.rs` (`BackingSet`, constructor-mint, GF4b-6 spendability filter inside) | Landed; **consumed by PR-3** (GF-4b §5 item 1 — the claim orchestrator constructs, the handler designates; staging allows deleted) |
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
   from **the same positive-share recompute** the verifier runs. The
   candidate range is bounded by the two rejection predicates of
   `claimed_epochs_check_and_set`, **each end anchored to the predicate
   that rejects, never to a described window** (round-2 correction,
   §7.2): **top** — `E < current_settled_epoch`, strict
   (`E ≥ settled` rejects `NotSettled`, `claimed_epochs.rs:123`);
   **bottom** — `!epoch_is_claim_expired(E, settled)`
   (`claimed_epochs.rs:130`), which is `E ≥ claim_window_floor(settled)`
   *by definition* — expiry resolves **through** the floor
   (`claimed_epochs.rs:83-85`), one definition, no parallel copy. The
   builder consumes the landed predicates (`epoch_is_claim_expired`,
   `claimed_epochs_contains`) directly and never re-derives boundary
   arithmetic inline — the predicate functions are the boundary's single
   source; inline `≥ floor` arithmetic would be a second copy that can
   drift if the predicate ever changes.
   **Fourth boundary — strict finalization (post-closure sharpening,
   PR 2, 2026-07-10; rule 21 named pin, does not reopen round 2):**
   the connect window is one count looser than the verify window, and
   the builder's product must satisfy **verify's**. Verified at daemon
   source: the close of `E` runs while connecting `E`'s *last* block
   (`blockchain_db.cpp:504-514`, hook operand
   `prev_height + 1 = (E+1)·SEB`), so at the one gather count
   `chain_height == h_close(E)` the budget row for `E` already exists
   and `settled = E + 1` (both derived from one `db.height()` read,
   `archival_claim_source.cpp:30-32`) — the connect predicate admits
   `E`, but verify's step-1 strict `current_block_height > h_close(E)`
   (`emission_verify.rs:384`) rejects a claim of `E` in the very next
   block. The derivation therefore also consumes verify's finalization
   predicate — via `epoch_close_height`, the literal function verify
   calls — at the earliest inclusion height (`chain_height`), and
   defers the epoch one block (`EpochSkip::NotFinalized`). The window
   contract is **four** consumed boundaries (top, bottom, dedup,
   finalization), not three; an earlier PR-2 revision recorded this
   edge as foreclosed by the missing close row — wrong per the daemon
   trace above, and corrected in place in the module doc. For each in-range `E` not
   already in the bond record's claimed set: recompute the share via
   `as_of_e_served_work` → `capped_work_milli` → `reward_share_floor`;
   claimable ⇔ share `> 0`. No gate consultation of any kind — the
   predicate reads the recomputed share's sign and no cause operand
   (as written: "no `K_COVER` consultation"; that gate was retired
   2026-07-19, PR #346, so the condition is now trivially met and the
   predicate is unchanged) (the vin never
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

**Disposition: RATIFIED (2026-07-09), verified at source.** The Model-D
header (`stake_engine.rs:16-50`) is the rule-35/36 shape: the master seed
is borrowed at `assemble()`, derives the bundles, and is dropped at
function end (`:18-22`); the actor holds only *derived* bundles and never
re-acquires the seed, so there is "no re-auth/KEK machinery" — no
session-long secret to re-authenticate (`:26-28`). The secret-locality
note (`:43-50`) is the make-bad-states-unrepresentable form: the custody
boundary is enforced by the seed **not existing past `assemble()`** and the
bundle type having no secret field, not by the handler being careful.
Locating emission-claim signing in this same actor inherits that property
structurally. **Builder-PR pin (the one thing that would break the
inherited property):** the claim-signing path must sign **within** the
seed-gone-after-`assemble()` discipline — it must use a *derived bundle*
like every other handler and must **not** re-borrow the master seed.
Checkable at the builder's PR: does the claim-signing path re-acquire the
seed, or does it consume a derived bundle?

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

**Disposition: RATIFIED AS A ROUTING, NOT A CLOSURE (2026-07-09).** Claim
cadence is precisely the recurring-timing residual (R-4 from the WI-4 exit
arc: per-epoch claim-submission timing against principal rhythm, the
accumulation surface); routing it to the GF-4 round is correct, but the
routing *defers* the grading — it does not discharge it. **Joint-grading
reopen (rule 21):** the GF-4 round must grade claim cadence **jointly**
with the reward-amount sequence and the holdings stratum, **not**
independently — those three are co-present on one persona, and an
independent per-axis grade multiplies as if they were independent (the
per-axis-multiplication error WI-4 §11 already flags). CB-3 is "named and
routed with a joint-grading obligation," not "closed."

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

**Disposition: RATIFIED ON THE STRUCTURAL EXCLUSION; the arming KAT is
necessary-not-sufficient (2026-07-09, verified at source).** The Q11 ACCEPT
(same-tx backing + key-imaged fee) is correct, but its verified strength is
**structural**, not the arming KAT. Source pass:

- **The exclusion is structural, and strong — a three-leg guard.** The
  backing pseudo-out lives inside the emission vin's opaque
  `canonical_bytes` blob (`emission_wire.rs`
  `MembershipOnlyBacking.pseudo_out`); the CT-balance path reads only
  `rv.p.pseudoOuts`. Routing the backing into the balance is not a
  line-removal — it is a blob-parse **plus** an append **plus** a lockstep
  bump of *both* size checks, coordinated across three legs:
  - **(i) blob boundary** — **nothing deserializes `canonical_bytes` into
    `rv.p.pseudoOuts`.** The backing bytes never reach the balance-relevant
    pseudo-out set.
  - **(ii) dispatch size check** — `tx_verification_utils.cpp:175`
    (`rv.p.pseudoOuts.size() != spend_input_count`).
  - **(iii) leaf size check** — `ct_semantics.cpp:362`
    (`rv.p.pseudoOuts.size() == fee_input_count`).

  This is a make-bad-states-unrepresentable guard: the double-use isn't
  *prevented by a test*, it is *unrepresentable* without a coordinated
  multi-site change, exactly like CB-1's single-evaluator
  `capped_work_milli`.
- **The arming KAT (`tests/unit_tests/archival_emission_ct_balance.cpp`) is
  the tripwire on the guard — necessary-not-sufficient — and its coverage
  boundary is now stated per arm** (`50-testing.mdc` "Test rationales state
  their coverage boundary"). Both arms call the leaf
  `verCtSemanticsEmission` / balance FFI, not the full dispatch:
  - Arm 1 (`backing_identity_O_vs_O_prime`) **now bites** against a refactor
    that parsed the blob into the balance *operands* (leg i, operand side):
    strengthened this PR to derive `spend_input_count`/`total_reward` through
    the **same production functions the dispatch uses** (`classify_archival_tx`
    + `shekyl_checked_sum_amounts`) — the prior test-local mirror was replaced
    (`50-testing.mdc` "Test the production code, not a local
    re-implementation") — and asserts the operands do not move when the
    backing bytes change. It also pins leg (iii): `EXPECT_TRUE(verdict_O)`
    (`:199`) fails if the leaf size check is bumped to `+ 1`. **Does NOT
    cover:** the `verdict_O == verdict_O_prime` identity is
    **green-by-construction** — `verCtSemanticsEmission`'s signature has no
    parameter the blob-resident backing can enter, so it documents the
    signature-level exclusion, it is not the coordinated-regression catch the
    E3 doc previously claimed.
  - Arm 2 (`backing_inclusion_shape_rejects_in_production`) bites against
    **weakening the balance equation** (leg iii, value side): the
    short-by-backing fixture must reject, and the second half proves the
    fixture is a genuine backing-closes-it shape, not an unrelated
    malformation. **Does NOT cover:** the blob boundary (leg i,
    `pseudoOuts` side) or the dispatch check (leg ii).
  - **Armed status:** leg (iii) is armed (arm 1 + arm 2); leg (i) *operand
    side* is armed (arm 1, production classifier); leg (i) *`pseudoOuts`
    side* and leg (ii) are **not** armed here — no test drives the full
    dispatch (`tx_verification_utils.cpp:151-183`) with a valid emission tx.
    That is the follow-up.
- **Ratification.** CB-4 ratifies on the **structural** exclusion (the
  separate opaque field + two redundant size checks), *not* on the KAT —
  holding ratified-*pending* the follow-up would treat the test as the
  guard, the inversion this round corrects. The guard is present and
  verified now; the KAT is its tripwire. Same posture as CB-1's
  single-evaluator invariant with its step-7 self-check
  necessary-not-sufficient. The Q11 ACCEPT stands.
- **Done in this PR.** (b) The E3 §2.2 arm-1 rationale is corrected (it
  claimed a green-by-construction identity proved the mechanism; it does
  not — the biting assertion is `EXPECT_TRUE(verdict_O)` + the production
  operand-invariance). (c) The general discipline that let a leaf-check
  test be credited with a dispatch-level proof is pinned in
  `50-testing.mdc` ("Test rationales state their coverage boundary"). Both
  are known-false / known-incomplete doc fixes with zero bisect risk, fixed
  in the flow that found them.
- **Follow-up — homed to §8 PR-4 (regtest e2e + blob-boundary arm), not
  deferred to a queue.**
  (a) Add the arm that protects the **blob-boundary invariant** directly:
  drive the full production dispatch (`ver_non_input_consensus_templated`)
  with a valid FCMP++ emission tx and assert the **CT-balance verdict is
  invariant under `canonical_bytes` variation** — i.e., the balance-relevant
  `pseudoOuts` set is exactly the fee inputs and is *unaffected* by the blob
  contents. This is the arm that fails if a future deserialization change
  parsed the backing out of the blob into `pseudoOuts` (leg i `pseudoOuts`
  side + leg ii) — the actually-dangerous refactor, which the size-check
  arms cannot catch because they only fire once something is already in
  `pseudoOuts`. It is **harness-gated** on a valid-proof emission-tx builder,
  which PRs 1–3's production path provides (landed 2026-07-11) — so it lands
  in PR-4 where the regtest harness is born, not in an undrained queue; the
  §8 PR-4 scope row names the arm explicitly as in-scope work. **Not** a
  consensus change (the Q11 reversion clause is untouched);
  tripwire-completeness, not a safety gate.

### CB-5 — refusal taxonomy

Rule 82: every refusal is a named, actionable error — `NoClaimableEpochs`
(all shares zero or window-expired: not an error, an idle state),
`AlreadyClaimed`, `InsufficientBacking` (empty `BackingSet` — distinct
from `InsufficientFunding` for fees), `WindowExpired` (per epoch),
`SelfCheckFailed` (step 7, loud, bug-class). The zero-share case must
**not** surface as "gated" vs "no work" — gatedness is publicly
computable ex ante but the share recompute doesn't distinguish the causes
(M1: the vin never consults `K_COVER`), and the builder must not either.

**Disposition: RATIFIED (2026-07-09), verified at source. Strengthened by
the `K_COVER` retirement (2026-07-19, PR #346) — see the amendment below.**
The named-error set exists (`EpochAlreadyClaimed` at
`emission_verify.rs:107,416`; the rest per §3), and the load-bearing
property — the cause-blind zero-share — is structural.

*Amendment (2026-07-20).* As ratified, this disposition rested on
`K_COVER` being compared at exactly one site, `epoch_close_compute`
(`k_cover.rs:11`, `consensus_state.rs:470`, "the **only** `K_COVER`
comparison site"): the vin/claim path never consulted it, so the wallet
could not tell "zero because pre-`K_COVER` gate" from "zero because no
serve credit," and neither could an observer of the refusal. Branching on
`K_COVER` would have leaked whether the epoch was gated — a launch-window
observable. **Both cited source locations are now dead**, and there is no
gatedness left to leak. The requirement does **not** become vacuous,
because gatedness was never the only cause of a zero share: the builder
must still not distinguish "zero because no serve credit" from "zero
because the shards were unfrozen and scored no age" from "zero because
membership had not onset". Cause-blindness across the *surviving* zero
causes is what CB-5 now requires, and it holds for the same structural
reason — the claim path recomputes a share and reads its sign, consulting
no cause operand at all. That is a stronger position than the ratified
one, which depended on a single comparison site staying single (the same
one-evaluator discipline as CB-1's `capped_work_milli`). **Builder-PR pin:**
`SelfCheckFailed` (step-7 self-check) must **also** refuse cause-blind — it
must not emit *which* operand the assembled vin failed verify on in any
form an observer can read, since "self-check failed on operand X" leaks
which operand the daemon mis-sourced. Refuse-blind, log-local: the refusal
is visible, the cause is not (same shape as the cause-blind zero-share, and
necessary-not-sufficient against the lying daemon per CB-1's wargame).
**Pin discharged (PR 2, 2026-07-10):** `EmissionClaimError::SelfCheckFailed`
is a unit variant (structurally payload-free — unrepresentable, not
withheld); the verifier's rejection detail goes to local tracing only.
The PR-2 taxonomy as landed: `NoClaimableEpochs` (idle, cause-blind —
`AlreadyClaimed`/`WindowExpired`/zero-share are per-epoch skip
diagnostics, never surfaced), `SourceInvalid`, `ScarcityConversion`,
`SizeBoundExceeded`, `RowsUnencodable`, `SelfCheckFailed`;
`InsufficientBacking` lands with its constructor in PR 3 (staged
completeness, not a missing arm).

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
| Claimable epochs from the positive-share recompute | `docs/FOLLOWUPS.md` M1 round-1 forward pin | `reward_arithmetic.rs:129` `reward_share_floor`; `consensus_state.rs:190` `capped_work_milli` (single evaluator) | §2 step 1 — **discharged (PR 2)**: `emission_claim.rs` `derive_claimable_epochs`, claimable ⇔ recomputed share `> 0`, no `K_COVER` read anywhere in the module |
| Backing exclusively through `BackingSet`, arity 1 | GF-4b §5 item 1 | `backing_set.rs:44` (private `records`), `:90` (`from_spendable` sole constructor), `:103` (spendability filter); arity-1 pin `emission_wire.rs:116-125` (Q3 vacuous at arity 1) | §2 step 3 |
| `EmissionReward` scan arm, fail-toward-forbidden | GF-4b §5 item 2 | `pscan_state.rs:89` (`MintLineageOutput`; `:98` `EmissionReward`, `:103` `BondPostChange`, `:109` `ExternalTransfer`); `scan_step.rs:401` `run_dual_extractor`, `:501-511` fail-toward-forbidden default. **`EmissionReward` gained its first production constructor site in PR-3's scan arm** (own emission vin ⇒ vout lineage classification) — the "gains its first constructor site" claim, discharged | Companion piece landed with PR-3 (claim change no longer strands in rung-3) |
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

Round-1 closure (2026-07-09): CB-1(a) ratified (RPC as
`EmissionEpochSource`); CB-2 locus ratified (StakeEngine actor, sign-within
the seed-gone-after-`assemble()` discipline); CB-3 ratified as a routing
with the joint-grading reopen named; CB-4 ratified on the structural
three-leg exclusion, with the arming KAT strengthened to production operand
functions (leg-i operand side + leg-iii armed in-PR), the E3 §2.2 rationale
and the `50-testing.mdc` coverage-boundary discipline corrected in-PR, and
the blob-boundary invariant arm homed to §8 PR-4 (§3 CB-4 +
`FOLLOWUPS.md` Q11-KAT item); CB-5 ratified with the
`SelfCheckFailed`-blind pin. Builder-PR pins to carry: sign within
seed-gone-after-`assemble()` (CB-2); `SelfCheckFailed` refuses cause-blind
(CB-5); the E4-gate GF-4 round grades cadence jointly with amount +
holdings stratum (CB-3).

---

## 7. Round 2 — the CB-1 RPC surface (ratification residue)

CB-1's round-1 ratification left two named items for round 2: *"the RPC's
exact field set enumerated against `EpochCloseInputs` +
`emission_verify.rs`'s `EmissionEpochSource`, and the gate-6 review of the
query's linkability surface."* This round discharges both. Substrate
re-verified at `dev` = `21da28864` (post-#282).

### 7.1 The load-bearing discovery: the gather already exists

The daemon-side work is smaller than round 1 assumed. The per-`(P, E)`
frozen-operand gather is **already landed as a single-sourced function**:
`BlockchainDB::gather_archival_emission_epoch_snapshot(p_id,
settlement_epoch, out)` (`blockchain_db.h:2134`), returning
`ArchivalEmissionEpochSnapshot` (`blockchain_db.h:408`) — the exact struct
the verify shim marshals into the FFI
(`ShekylArchivalEmissionEpochSnapshot`, `archival_ffi.rs:871`) and the
Rust verify body consumes as `EmissionEpochSource`
(`emission_verify.rs:223`). The RPC is therefore a **serializer over the
landed gather**, not a new gather.

**Pin (single-gather) — RATIFIED (2026-07-09).** The RPC handler must
call `gather_archival_emission_epoch_snapshot` — the same function the
verify dispatch calls — and must not re-implement any row read. A second
gather is the same drift class WS-1's single accessor and CB-1's
single-evaluator invariant foreclose: if the RPC gathered differently
from verify, the wallet would build against operands the verifier never
sees, resurrecting M-2 divergence at the RPC boundary.

**Recorded as CB-1(b) itself, not a new pin.** This is the same
invariant as round 1's CB-1(b) rejection, applied on the other side of
the wire: the wallet does not re-derive (CB-1(b)), and the RPC does not
re-gather (this pin) — **one invariant, two faces**, closing the
single-evaluator property on both ends of the transport. A future PR
cannot weaken one face while citing the other: weakening either side
reopens the same M-2 divergence class and therefore reopens CB-1's
ratification, not a payload or implementation detail.

**Windowed form (PR-1 review hardening, 2026-07-09).** The handler calls
`gather_archival_emission_window_snapshots(p_id, floor, settled, out)` —
a width-N form of the *same* gather, not a second one: the one
row-selection routine (`gather_archival_epoch_rows_window`,
`db_lmdb.cpp`) now takes an epoch window, the per-epoch
`gather_archival_emission_epoch_snapshot` is its width-1 delegate, and
the epoch close funnels through the same routine, so the single-gather
pin holds by construction. The motivation is a per-request work bound:
the serve-credit key is `p_id | shard | epoch` (epoch is the *suffix*),
so a per-epoch range seek is impossible and a full-table cursor pass is
inherent — paying that pass once per window epoch (26×) on an
unauthenticated public endpoint was attacker-drivable CPU amplification;
the windowed form pays it once per request. The same review round moved
the archival read helpers off their bare `if (m_write_txn)` fast path
onto the thread-aware `block_rtxn_start` selection, so an RPC-thread
caller can never touch the writer thread's live write transaction (LMDB
write txns are single-thread; the old fast path let a claim-source query
race a block connect toward crash or DB corruption).

### 7.2 Query shape — one composite RPC, window-batched

One new endpoint, tentatively `get_archival_emission_claim_source`:

- **Request:** `p_id` (32-byte persona id). Nothing else. No epoch list,
  no range.
- **Response:** the claim context (§7.3 part A) + one per-epoch snapshot
  (§7.3 part B) for **every** epoch in
  `[claim_window_floor(current_settled_epoch), current_settled_epoch − 1]`
  that has a close row — the full claim window, unconditionally.

Why window-batched rather than per-`(P, E)`:

1. **Uniform query shape (gate-6).** A per-epoch query sequence reveals
   *which* epochs the wallet considers live candidates — an observable
   correlated with the persona's serve history. The full-window batch is
   shape-invariant: every claimer asks the identical question, so the
   query leaks only "`P` ran a claim check," never the claimable subset.
   This is CB-5's cause-blindness discipline applied at the transport
   (the query must not encode the answer).
2. **Chicken-and-egg.** Step 1's candidate filter needs the bond record's
   `claimed_settlement_epochs` — which lives in the same response. A
   per-epoch shape would force two round trips with a coherence seam
   between them (claimed-set read at tip `T1`, snapshots at tip `T2`).
   One composite response is one read at one tip.
3. **Bounded.** The window is `MAX_CLAIM_AGE_W = 26`
   (`config/consensus_constants.json`, wired via
   `shekyl-archival-retention/build.rs`), so the response carries at most
   27 epoch snapshots. Each snapshot's rows are the epoch-close gather
   rows (bonds with credit in `E`, shards, credit pairs) — the same
   volume the close itself processes. The response is DoS-bounded by
   consensus constants, no caller-controlled amplification (the request
   has no size knob at all).

**Disposition: RATIFIED (2026-07-09).** The load-bearing argument is
item 1: the query cannot encode the claimable subset, so the observable
is identical for a claimant with zero claimable epochs and one with all
of them — CB-5's cause-blindness pushed to the transport layer. A
request shape that could ask "give me my claimable epochs" would leak
the claimable set to any RPC observer (the daemon under remote posture,
a network observer of un-isolated transport), and that set is exactly
what the cause-blind refusal taxonomy exists to not reveal. The
transport cannot distinguish what the claim path cannot distinguish.

The in-progress epoch and the not-yet-settled boundary epoch are
excluded daemon-side by the same predicate the connect path enforces:
`claimed_epochs_check_and_set` rejects `epoch >= current_settled_epoch`
as `NotSettled` (`claimed_epochs.rs:123`), so the claimable range is
`[floor, settled − 1]`, top-exclusive. **Round-2 correction to §2
step 1 (top boundary):** the round-1 text wrote the candidate range as
`[claim_window_floor(settled), settled]`, inclusive at the top — an
off-by-one against source (a builder that claimed `E = settled` would
assemble a tx the connect path rejects `NotSettled`). §2 step 1 is
corrected in this round; the coverage-boundary lesson from CB-4 applies
(the range was stated by association with the window, not verified
against the predicate).

**Bottom boundary — verified against the predicate on review
(round-2 closure item).** The review asked whether §2's low end anchors
to `epoch_is_claim_expired` (the rejecting predicate,
`claimed_epochs.rs:130`) or to `claim_window_floor` (the pruning floor,
`:135`) — the same association-vs-predicate trap one level deeper.
Verified at source: the two quantities **cannot diverge today**, because
expiry is *defined through* the floor —
`epoch_is_claim_expired = epoch < claim_window_floor(settled)`
(`claimed_epochs.rs:83-85`), one definition, no parallel copy (the
`claim_window_floor` doc comment's "single source of the claim-window
boundary" names exactly this). So there is no live off-by-one at the
bottom; `E ≥ floor` is predicate-exact. The discipline correction is
still applied: §2 step 1 now anchors **both** ends to their governing
rejection predicates and pins the builder to **consume the landed
predicate functions** (`epoch_is_claim_expired`,
`claimed_epochs_contains`) rather than re-deriving `≥ floor` inline —
an inline copy is a second boundary source that drifts silently if the
predicate ever changes independently of the floor.

### 7.3 Field enumeration

**Part A — claim context** (once per response):

| Field | Type | Source of truth (daemon-side) | Consumer (wallet-side) |
| --- | --- | --- | --- |
| `chain_height` | u64 | tip at gather time | staleness check against the wallet's own scan tip (§2 step 3 same-tip rule); not an operand |
| `current_settled_epoch` | u64 | `shekyl_archival_settlement_epoch_at_height` over tip (`archival_ffi.rs:520`) — the same helper consensus uses, never a second derivation | step 1 window bounds: `claim_window_floor(settled)` … `settled − 1` |
| `has_bond_record` | bool | `archival_bond_record` row existence for `p_id` | absent ⇒ `NoClaimableEpochs` refusal (idle, not error) |
| `join_settlement_epoch` | u64 | bond record | step 1 `E ≥ E_join + 1` filter; vin field |
| `holdings` | `HoldingsDescriptor` (wire form) | bond record | vin holdings-equality field (§5.3/§6.4.1 — verify step 2 demands record equality; the builder copies the record's descriptor, never recomputes one) |
| `claimed_settlement_epochs` | u64[], strictly increasing | bond record | step 1 dedup filter (`claimed_epochs_contains`); mirrors `ClaimantBondRecord.claimed_settlement_epochs` (`emission_verify.rs:217`) |

**Part B — per-epoch snapshot** (0–27 entries; mirrors
`ArchivalEmissionEpochSnapshot` field-for-field — the RPC adds **no**
field the landed struct lacks and drops none):

| Field | Mirrors | Note |
| --- | --- | --- |
| `settlement_epoch` | `.settlement_epoch` | echo of the row's `E` |
| `close_block_height` | `.close_block_height` | the close-**processing** height `(E+1)·SEB`. Carries the landed struct's lookalike hazard verbatim: sourced from `shekyl_archival_epoch_close_processing_height`, **never** `shekyl_archival_epoch_close_height` (= `(E+1)·SEB − 1`). The RPC doc comment must repeat this pin |
| `sigma_work_milli` | `.sigma_work_milli` | **persisted** `Σwork(E)` — the stored denominator, never a recompute (M1 gate outcome reaches the wallet only through this value, same as verify) |
| `budget_atomic` | `.budget_atomic` | frozen close-row `budget(E)` |
| `has_budget_row` | `.has_budget_row` | absent close row ⇒ wallet treats `E` as unclaimable (mirrors the verify shim's reject); present-and-zero is rejected downstream by wire positivity |
| `bonds[]` | `.bonds` (`BondRow`) | `join_settlement_epoch`, `is_foundation_complete_tree`, `bad_intervals_flat[]` — flattened pairs, as landed |
| `shards[]` | `.shards` (`ShardRow`) | `shard_id`, `freeze_height`, `has_segment` |
| `credit_pairs[]` | `.credit_pairs` (`CreditPair`) | `(bond_idx, shard_idx)` index pairs into the two arrays above |
| `claimant_bond_idx` | `.claimant_bond_idx` | `SIZE_MAX` sentinel → `Option<usize>` at the Rust decode, exactly as the verify shim does |

**Deliberately NOT carried** (each exclusion is load-bearing):

| Excluded | Why |
| --- | --- |
| `settlement_epoch_blocks`, `age_weight_milli`, `curve` (`BandedCurveParams`) | Consensus constants, already single-sourced in the shared constants pipeline (`archival_ffi.rs:820-822` builds them crate-locally). Carrying them over RPC would mint a second source that can drift from the wallet's compiled constants — the wallet must construct `EpochCloseInputs` from its own pipeline, byte-identical to the verify shim's construction |
| `frozen_shard_count` (and formerly `k_cover`) | **CB-5-structural, not payload-minimization** (re-recorded per round-2 ratification; re-anchored 2026-07-20 after the `K_COVER` retirement, PR #346). **The exclusion stands and its justification is now more direct.** As written, the argument was that a wallet holding `k_cover` + `frozen_shard_count` could reconstruct the gate decision; `k_cover` no longer exists, but `frozen_shard_count` does, and it now distinguishes a *live* zero-cause on its own. Under the amended CB-5 the builder must not distinguish "zero because no serve credit" from "zero because the shards were unfrozen and scored no `shard_age_milli`" — and `frozen_shard_count` is precisely the operand that separates them. Sending it would make **representable** the cause-distinguishing wallet branch that CB-5 makes **unrepresentable**. The pin therefore remains armed and can still fire correctly: a future "include `shard_count` for diagnostics" PR reopens the cause-distinguishing branch and **trips this pin** — it is a CB-5 reopen, not a payload question |
| per-epoch holdings descriptor | WS-1 §5: the work channel carries no holdings; the held-and-served set is the credit rows. The vin's holdings field comes from the bond record (part A), the only place verify reads it |
| tree root / membership path for the backing output | Not this RPC's concern: sourced through the existing spend-path machinery (`curve_tree_decode.rs` / `signing_assembly.rs` family), same as every FCMP++ spend the wallet builds |

**Decode locus.** The Rust response decode lands beside the wire structs
in `shekyl-archival-retention` (or the engine's daemon-client layer —
implementer's choice at PR time), producing exactly
`EmissionEpochSource<'_>` + `ClaimantBondRecord<'_>` — the structs verify
already consumes. No builder-private mirror of either struct is
permitted (the §2 step-7 self-check must consume the same decoded values
the assembly consumed, or the self-check tests a copy).

**Disposition: RATIFIED (2026-07-09), with the `k_cover` /
`frozen_shard_count` exclusion re-recorded as CB-5-structural** (see the
exclusion table row): the WS-1 holdings exclusion and the
consensus-constants exclusion are existing-invariant applications (WS-1
§5 and CB-1's no-second-source respectively); the tree-paths exclusion
is clean scope; the gate-operand exclusion is the load-bearing one and
carries its own trip-wire framing so a future diagnostics-motivated
inclusion trips CB-5, not a payload rationale.

### 7.4 Gate-6 linkability review

The query names `P`. `P` is public by role (WI-4 §18.8: only the
`P`→user/principal link is protected, not `P` itself) — so the reviewed
surface is the *transport* and the *timing*, not the query content:

- **Transport pin.** Persona-side reads ride the persona's transport
  (`PTorClient`/`PRpc`, `engine/prpc.rs`) under the 2d-2 posture rules —
  **never** the principal's daemon session. Under the recommended
  local-daemon posture (WI-4's graded assumption) this collapses to
  loopback and is clean. A remote daemon sees `(P, claim-check, time)`;
  that observation joins the **2d-2 remote/untrusted-daemon reopen
  family** alongside CB-1's lying-daemon liveness bound (round 1) and the
  WI-3 tip clock — same posture, same reopen, no new class.
- **Shape pin.** §7.2's uniformity argument: the request carries no
  epoch selection, so the daemon-visible query is identical for every
  claimer regardless of serve history or claimable subset.
- **Timing residual (routed, not closed).** *When* the wallet runs the
  claim check is claim-cadence-adjacent: a check immediately followed by
  a claim tx is a correlated pair on the persona's timeline. This is
  CB-3's seam — the builder does not self-schedule, and the query fires
  once per explicit claim intent (no background poll loop in the
  builder; any polling belongs to the scheduler seam GF-4 grades). The
  GF-4 joint-grading obligation (CB-3) therefore covers query timing as
  a component of claim cadence; no separate grading track is opened.
- **DoS/public posture.** The response is consensus-public state (bond
  records and close rows any full node can enumerate); no wallet secret
  exists daemon-side. The endpoint can be public-RPC class; response
  size is consensus-bounded (§7.2 item 3). Restricted-mode placement is
  an implementation detail at PR time — nothing here is
  privacy-sensitive *content*, only privacy-sensitive *linkage*, which
  the transport pin owns.

**Disposition: RATIFIED (2026-07-09).** PRpc-never-principal-session is
the held persona-transport pin; remote posture joins the existing 2d-2
reopen family (no new class). Routing query timing into CB-3's GF-4
joint-grading obligation rather than opening a fourth independent axis
is the correct shape — the RPC query is another per-epoch-cadenced
observable on the same persona and belongs in the joint
cadence+amount+holdings grade (the per-axis-multiplication error
avoided).

### 7.5 Trust posture (inherited, unchanged)

Round 1's lying-daemon wargame carries over verbatim: wrong operands ⇒
denial-of-claim (liveness), never over-claim (every verifier recomputes
independently). The step-7 self-check stays necessary-not-sufficient
against a consistently-lying daemon. Nothing in the field enumeration
changes that bound; the batch shape does not widen it (a daemon that
can lie per-epoch can lie per-window identically).

---

## 8. Implementation plan — the PR chain

Four PRs, each within the 5-day/10-commit ceiling (`06-branching.mdc`),
split by validation surface (rule 19), ordered by dependency. Branch
`feat/emission-claim-builder-impl` (this doc's round-2 commit is its
first).

| PR | Scope | Validation surface | Gates / pins carried |
| --- | --- | --- | --- |
| **1 — daemon RPC** | The §7 endpoint: C++ handler as a marshaling shim over `gather_archival_emission_epoch_snapshot` (rule 20: transport C++, no new logic) + bond-record context read; Rust client decode to `EmissionEpochSource`/`ClaimantBondRecord`; wire tests (round-trip, sentinel decode, window bounds) | RPC wire + operand fidelity (RPC-sourced operands byte-equal the verify shim's in-process gather on the same DB state) | §7.1 single-gather pin; §7.3 exclusion table; close-processing-height lookalike pin |
| **2 — pure assembly module** | `engine/emission_claim.rs`: step 1 claimable-epoch derivation (verifier-exact via `reward_share_floor` over RPC-sourced frozen operands), step 2 work-claim rows, step 5 vouts + fee sizing (GF-4b item-5 bound-or-split), step 7 self-check, CB-5 refusal taxonomy. KAT-able with a fixture `EmissionEpochSource` — no live daemon, no actor harness | Builder-vs-verifier differential (assemble ⇒ the three landed verify functions accept; mutate any operand ⇒ reject) + refusal taxonomy (zero-share, window-floor, already-claimed, 15-cap batching) | CB-5 `SelfCheckFailed`-blind; wire positivity as the claimability predicate; no `K_COVER` read anywhere in the module *(pin now trivially met — gate retired PR #346; the live form of this pin is CB-5 cause-blindness across the surviving zero-causes, per §7.3)* |
| **3 — StakeEngine handler** | The `SignBond`-sibling message (CB-2): backing selection via `BackingSet::from_spendable` (first live consumer — un-deadens GF-4b §5 item 1), membership proof (`prove_membership_only`), dual auth via a **derived bundle**, tx assembly + fee inputs through the existing spend machinery; the `EmissionReward` scan arm's first constructor site (§4 companion — without it claim change strands in rung-3) | Custody boundary (the checkable CB-2 pin: no master-seed re-borrow on the claim path) + scan classification (GF-4b item-3 integration test: first-emission backing = `BondPostChange`) | CB-2 sign-within-`assemble()`; GF-4b §5 items 1/2/3/6; reference-height same-tip rule |
| **4 — regtest e2e + blob-boundary arm** | Part 2 of the E4 gate, **after #281 lands** (reuses `economics_chain_helpers.h`): mine to an epoch close with served work, build via PRs 1–3's production path, submit over real RPC, assert accepted-and-applied (claimed-set row + vout shape), pop/reorg leg; plus the CB-4 blob-boundary KAT arm (drive full dispatch, assert CT-balance verdict invariant under `canonical_bytes` variation) — landing where its harness is born | End-to-end consensus acceptance (the E4 merge gate, `REWARD_EMISSION_VIN_PLAN.md` §3.0) + CB-4 leg-i/leg-ii tripwire completeness | Q11-KAT FOLLOWUPS item closes here; e2e also carries the conservation KAT's fee-leg residue disclosed in #281 |

Ordering: 1 → 2 (fixture shape) → 3 → 4 (needs 1–3 and #281). Standard
gates per rules 45/50 on every PR; docs (index CB row, FOLLOWUPS,
CHANGELOG) update per PR per rule 91.

**Chain disposition: ENDORSED (2026-07-09), PR-4 gated on #281.** The
gating is the same harness-locality sequencing settled for the CB-4
blob-boundary arm — the arm and PR-4 both land where the harness
(`economics_chain_helpers.h`) is born.

**PR 2 implemented (2026-07-10, `feat/emission-claim-assembly`).**
`engine/emission_claim.rs`, five commits: the dead `EngineCoreError`
module deletion (FOLLOWUPS discharge, separated out of the builder's
bisect surface); the step-1 derivation (scratch-oracle boundary
verdicts with the purity pin, M1 positive-share discharge, 15-cap
batching); step-2/5 assembly (canonical minimal rows, `u64→u32`
scarcity guard armed at the builder's conversion site with the
compile-time const-assert as the production guarantee, entry-sum
hard check, bound-or-split sizing measured by the production encoder
at structural maxima); the step-7 self-check (`self_check_claims`
drives the literal `emission_vin_verify_claims`; `SelfCheckFailed`
cause-blind per the CB-5 builder pin, verify detail log-local;
differential KAT with six vin mutation arms + three context arms,
each proven to flip accept → refuse); and the close-boundary fix
below. **Adversarial-review finding (the §2 step-1 fourth-boundary
sharpening):** review refused an in-module "structurally foreclosed"
claim about the strict-finalization edge; the daemon trace disproved
it (the close of `E` runs connecting `E`'s last block, so at
`chain_height == h_close(E)` the budget row exists and the connect
window admits `E` while verify rejects it next-block) — a real
once-per-epoch spurious-refusal window, closed in the derivation by
consuming verify's own predicate (`EpochSkip::NotFinalized`, armed by
a premise-asserted boundary KAT). Deferred to PR 3 with their
constructors: `InsufficientBacking`, real backing/auth legs of the
self-check (claims-leg coverage boundary recorded in the module doc),
the staleness comparison, and the remaining `emission_source.rs`
staging allows.

**PR 2 review round (2026-07-10, high `/code-review` + Copilot).**
Three confirmed correctness defects fixed, plus the cleanup set:

1. **Size budget re-based on the binding relay bound.** The claims
   budget was derived from `MAX_TX_SIZE` (the 1 MB parse cap); the
   binding constraint is the per-tx **weight limit**
   (`get_transaction_weight_limit` = min-block-weight/2 − 600 =
   149 400 B) — a batch bounded against the parse cap could pass
   assembly and the size-blind step-7 self-check yet be permanently
   unsubmittable, re-assembled identically on every retry until the
   window's rewards expired. `shekyl_wire::TX_WEIGHT_LIMIT` now pins
   the C++ value (const-asserted); the non-claims reserve is re-derived
   against it (48 KiB: 16 vouts + KEM ciphertexts, two max-depth fee
   inputs + hybrid auths, Bp+ + its weight clawback), and a const
   assert keeps the budget above the vin's fixed cryptographic legs.
2. **Verify step 2's join bound applied at derivation.** The
   derivation never read the record's `E_join`; a retire-then-rejoin
   record (join newer than the frozen rows') admitted a pre-join epoch
   and wedged the whole batch behind the cause-blind `SelfCheckFailed`
   until the offender aged out of the window. Fixed by extracting the
   predicate (`epoch_is_before_join`, called by the verify body and the
   derivation — one definition), a `BeforeJoin` skip, and a KAT whose
   premise arm proves the skip is load-bearing.
3. **The settled/height pair is decode-enforced consistent.** The
   builder's window verdicts consumed the daemon's
   `current_settled_epoch` while the self-check recomputed settled from
   `chain_height`; an inconsistent reply split the two boundary systems
   (deflated ⇒ whole-batch `SelfCheckFailed`; inflated ⇒ claimable
   epochs silently forfeited as `WindowExpired`). PR 1's decode now
   rejects the inconsistent pair as `Malformed`
   (`settlement_epoch_at_height`, the daemon's own derivation). The
   Copilot finding rides the same posture: a window epoch with no close
   height (`(E+1)·SEB` overflow) is `SourceInvalid`, not a transient
   `NotFinalized`.

Cleanups in the same round: the scratch-clone oracle **retired** (the
V3.1 FOLLOWUPS extraction landed early on its named reopening trigger —
a second consumer needed the top boundary read-only; all boundary
verdicts now resolve through read-only predicates, purity pin deleted);
the steps-4/5 recompute single-sourced (`claimant_reward_share`, the
shared evaluation head both the verify body and the derivation call);
`ClaimableEpochs` now borrows the source's bond context and carries the
canonical rows built in the admitting scope (stale derived/source
pairing is unrepresentable; the `snapshot_idx`/`expect` panic surface
for PR 3's refetch loop is gone, and the per-epoch views are built
once); the vin has **one** construction site (`claims_vin` — the sizing
measurement, the emitted content, and the KAT vins cannot drift) with
the bound-or-split loop popping legs off a single vin instead of
rebuilding per iteration; `size_deferred` narrowed to `Vec<u64>` (the
verdict is definitional); the module-wide staging `dead_code` allow
narrowed to item level (rule 45); the two-bond/two-shard KAT fixture
shape single-sourced (`EMISSION_KAT_SHAPE` in the retention crate,
consumed by both the verify KATs and the builder KATs); and the two
intentional-design calls documented in place (batch-cap check after the
recompute = whole-window loud validation; the linear first-position
shard scan = byte parity with verify's lookup).

**PR 3 implemented (2026-07-11, `feat/emission-claim-handler`).**
Six commits: the wire emission-input arm (`0x04`, closing the latent
scanner break the pre-flight surfaced); the `EmissionReward` scan arm
(GF-4b item 2 — first-emission backing classifies `BondPostChange`);
the designated-backing selector (`BackingSet::from_spendable` →
`designate_backing`, GF-4b §5 item 1 — exclusivity and the Q11
fee-exclusion land as type properties: the backing record is private,
`fee_sweep` inserts its gindex into the exclusion set before
delegating); the `AssembleEmissionClaim` handler (CB-2 sibling of
`AssembleBond`: derive + assemble via the PR-2 module, F-C1c assembly
order — signable hash over the vin-less prefix → membership proof
(`prove_backing_membership`, offloaded to `spawn_blocking`) → dual
auths (Auth-B backing key, Auth-P identity hybrid key) → full prefix
hash → fee-side FCMP++ proof + tx PQC auths — with the daemon-side
differential KAT re-deriving the whole verify chain over the produced
bytes); the Engine-side claim orchestrator
(`engine/claim_orchestrator.rs`: fetch → reference-height anchoring
reconciling the daemon's two-sided age gate with `REF_ANCHOR_AGE` →
provable-record filter → designate → fee sweep → path assembly →
handler dispatch, reply returned unbroadcast per CB-3; end-to-end
integration test over a real 30k-block `CurveTreeClient`, a canned
RPC transport, and the real actor, with daemon-side re-derivation
against the real root); and the staging-allow deletion pass (every
PR-1/PR-2 allow whose named consumer was PR-3 is gone; the one
remaining claim-surface allow is `orchestrate_emission_claim` +
its reply's fields, staged narrowly against the CB-3 dispatch seam).
Pins carried: CB-2 no-seed-re-borrow (secrets re-derived from
`(ciphertext, index)` inside the actor; the orchestrator handles
public material only), GF-4b §5 items 1/2/3/6, the item-6 same-tip
rule (stored designation anchor == assembly tip, refuse-and-refetch
on mismatch), CB-5 cause-blind refusals (skip diagnostics log-local).
PR-4 (regtest e2e + blob-boundary arm) is now the chain's only open
item, gated on #281.

**PR 3 review round (2026-07-11, high `/code-review` + Copilot).**
All verified findings fixed (correctness first, then the full cleanup
set including the report-cap remainder):

1. **Slot-filtered backing designation.** `BackingSet::from_spendable`
   consumed the all-slot `funding_outputs` union with no `p_slot`
   filter while the fee sweep filtered — in a rotation-overlap window
   the most-recent-eligible comparator designated the OTHER slot's
   record, the claimant's re-derivation failed the pre-flight leaf
   gate, and the persona was deterministically unable to claim. The
   slot filter now lives inside the constructor (with the spendability
   filter, ahead of the survivor tripwire — which also makes the
   tripwire per-persona), KAT'd with a foreign-slot-newer fixture.
2. **Tip, never count.** The designation/sweep spendability anchor and
   the handler's same-tip operand were `source.chain_height` (a block
   COUNT, one past the tip) — records admitted one block early behind
   the provable-records mask, and `InsufficientBacking` reported a
   height that did not exist yet. Anchor = `chain_height − 1`
   everywhere; the same-tip check compares against the derived tip;
   the count-as-anchor case is a KAT'd refusal.
3. **`check_money_overflow` parity.** The wire's context-free
   validator deferred output-sum overflow as "trivial (amounts are 0)"
   — an invariant the emission arm's loud reward vout removed. The
   checked sum now runs; hostile `[u64::MAX, 1]` loud amounts reject
   exactly as the C++ daemon does.
4. **§7.4 transport pin made structural.** PR-1's "the handler is the
   call site that enforces this" had regressed to caller-discipline
   prose; `orchestrate_emission_claim` is now bounded on the
   `PersonaIsolatedTransport` marker (`prpc.rs`; `PRpc` implements it,
   the local-posture transport implements it at DQ-T2.3 as a
   documented choice site) — a principal-session fetch is a compile
   error.
5. **Q11 runtime half at the handler.** The operand-driven handler
   re-verified same-tip but trusted the backing∉fee-set pairing; a
   mispaired message would sign a consensus-valid double-use no daemon
   rejects (spend-blind backing). `BackingInFeeSet` now refuses beside
   the same-tip check, KAT'd.
6. **Structural refusal for zero fee inputs.** The empty-fee-set arm
   reused `InsufficientFunding { available: 0, required: fee }` —
   self-contradictory at `fee == 0` (rule 82). New
   `ClaimFeeInputsRequired` names the actual requirement (pseudoOuts +
   FCMP++ fee-side anchor need ≥ 1 spendable input regardless of fee).

Cleanups, same round: the two-sided reference gate single-sourced as
`shekyl_curve_tree::two_sided_reference_height` (transfer re-anchor +
claim orchestrator both consume it; the hand-rolled
`tip − REF_ANCHOR_AGE` copies are gone, discharging both Copilot
duplication findings); the backing leg re-derives through the same
`derive_spend_parts` as the fee spends (the step-10 twin of
`prepare_funding_inputs` deleted); one output-construction loop
(`construct_vouts_to_base`) and one `SpendInput → ProveInput`
conversion (`prove_input_from_spend`, with exactly-one pseudo-out
enforced on the membership-only leg — Copilot) serve bond + claim
paths; the P-scan rung-1 pre-pass became the lazy memoized
`OwnEmissionSlots` classifier (the eager form parsed every emission
vin on chain — full-scan cost scaling with chain-wide claim volume);
one test-side wire encoder (`emission_claim::test_fixtures::
source_json`, epee omit-empty faithful) feeds the decode tests and the
orchestrator e2e; fetch and ingested-tip awaits joined; the
debug_assert shadowing an identical typed refusal, the dead/duplicate
clones, and the `&[0, 0]` output-amounts literal removed; rule 22
(`22-no-lazy-deferral`) added to CLAUDE.md's rule index.

**Review follow-through — the count/height newtype (landed same
round).** The tip/count fixes above were three sightings of one unit
family, so the family got its type: `shekyl_types::ChainCount` (the
daemon's `db.height()` operand) with exactly two `BlockHeight` bridges
— `tip()` (count − 1, `None` on the empty chain: the
spendability/anchoring operand) and `next_height()` (the count *is*
the next block's height: the earliest-inclusion / verify-context
operand). `EmissionClaimSource.chain_height` and
`SubmitFacts.chain_height` (which was a documented count stored in a
`BlockHeight` — the same laundering, latent) are now `ChainCount`;
`BlockHeight::from_raw(count)` is unwritable, and each call site names
which chain fact it means. The ledger-tip audit that came with it:
`LedgerBlock::height()` **is** a tip instant (set to the ingested
block's own height) while the P-scan cursor's same-named
`synced_height` is a count — conventions now pinned in the accessor
doc; no bug.

**Named forward item (rule 22 form) — the `SweptFeeInputs` designation
witness, scoped to the CB-3 dispatch seam / PR 4.** The handler's two
step-2 runtime refusals (`StaleClaimAnchor`, `BackingInFeeSet`) are one
invariant — *these operands came from one designation event* —
enforced as two comparisons because `AssembleEmissionClaim`'s fields
are freely constructible. The witness form (a fee selection minted
only by `DesignatedBacking::fee_sweep`, carrying the designation's
gindex + anchor privately, the message taking the pair sealed) makes
the cross-pairing unrepresentable and deletes both refusal arms — the
house witness-token shape. **Named blocker, disclosed here:** the
threat is a *retry/cached-selection* path, which first exists at the
CB-3 dispatch seam, and the witness reshapes the exact message that
seam consumes (fee records currently leave `fee_sweep` as a plain
`FundingSelection` and are re-wrapped with membership paths in the
orchestrator — the witness must survive that zip). Landing it with the
seam is one message-shape change instead of two. Until then the
runtime refusals are KAT'd and load-bearing. *Reopen sooner if:* any
second caller of `assemble_emission_claim` appears before the seam, or
a fee-selection cache is introduced anywhere in the claim path.

**PR 4 split (2026-07-12): 4a / 4b / 4c — a daemon submit gap the
harness surfaced.** Driving the PR-4 harness live exposed that "submit
over real RPC, assert accepted-and-applied" is unreachable today for
*both* transaction kinds the e2e needs: the daemon's Rust submit engine
has no bond-post Phase-C battery (`shekyl-daemon-rpc`'s
`DaemonTxVerifier` refuses `SubmitTxKind::BondPost` as `Malformed`
unconditionally — and its stale module docs claim bond posts cannot
clear Phase A, which the harness disproved live: an underfunded fee
draws `FeeTooLow`, a verdict only Phase C emits, so the arm's rule-21
reopening criterion — the §13 wire reshape — has fired), and Phase A
rejects `Input::ArchivalRewardEmission` outright (the emission submit
leg — kind classification, fee/vout statics, verifier rows — never
landed). Implementing both batteries is daemon-submit-engine work — a
different validation surface (rule 19) and its own crate — and would
push this PR past the 10-commit ceiling. Split per `06-branching.mdc`:

- **PR-4a (implemented 2026-07-12, `feat/emission-regtest-e2e`, ten
  code commits + docs).** Everything harness-side plus the enablers: the CB-4
  blob-boundary KAT arm (fixture made valid under the full
  `ver_non_input_consensus` dispatch + the invariance arm — the
  Q11-KAT FOLLOWUPS item closes here); the FAKECHAIN-only
  settlement-epoch-blocks override (SEEDHASH-shaped env lever,
  fail-closed off FAKECHAIN) and serve-credit-bit injection RPC
  (WS-1 bits-only form; direct poke, **not** pop-symmetric — the e2e's
  pop leg must never rewind below the injection height); the
  local-posture `PersonaIsolatedTransport` (`LocalNodeRpc`, fail-closed
  loopback validation); the `SweptFeeInputs`/`ClaimOperands`
  designation-event witness (the named forward item above, landed with
  the seam as scoped) and the CB-3 dispatch seam
  (`engine/claim_dispatch.rs`: activate → orchestrate → posture→submit
  choke point); the staker regtest harness (staker wallet lifecycle,
  persona funding over a production FCMP++ transfer, P-scan discovery,
  production bond assembly, dispatch — with a **tripwire** pinning the
  daemon's exact Phase-C refusal, which fails loudly and promotes to
  accepted-and-applied when 4b lands); and two production bugs the
  harness surfaced and fixed with unit KATs: the payment path
  encapsulated to raw Edwards view-key bytes instead of
  `montgomery(view_pk)` (every cross-wallet payment unrecoverable by
  its recipient's scanner), and the P-scan exhaustiveness gate fetched
  pruned bodies whose FCMP++ spends can never re-hash to their
  committed hashes (scan permanently wedged at the first spend-bearing
  block).
- **PR-4b (next): daemon submit legs.** The bond-post Phase-C battery
  (BP rows: SP-T4a statics + funding-arm K checks against
  `SubmitFacts`) and the emission submit leg (Phase-A classification
  for `Input::ArchivalRewardEmission`, its fee/vout statics, verifier
  rows over the landed `emission_vin_verify_*` FFI). Carried by the
  FOLLOWUPS "daemon Rust submit engine: bond-post + emission
  batteries" item (V3.0 queue).
  **UPDATE 2026-07-18 — the bond-post half landed** (PR-4b as shipped:
  `DAEMON_SUBMIT_VERDICT.md` §8.7.1 closure note; the stale "§13 wire
  reshape / cannot clear Phase A" framing corrected — no wire
  contradiction existed; the PR-4a tripwire promoted to
  accepted-and-applied, surfacing + fixing two latent production bugs:
  the transfer path's missing `0x07` leaf-hash blob — every transfer
  output unspendable — and `prepare_handle_incoming_blocks`'s
  `bad_variant_access` on archival-vin blocks; `docs/CHANGELOG.md`).
  The **emission submit leg remains open** on the same FOLLOWUPS item
  and still gates PR-4c.
  **UPDATE 2026-07-19 — PR-4b COMPLETE: the emission submit leg landed**
  (§8.7.2 E-rows in `DAEMON_SUBMIT_VERDICT.md`; Phase-A
  `SubmitTxKind::Emission` + statics; the E6/E7 fact bundle; the native
  verifier battery over the `emission_vin_verify_*` minters; the E6
  Phase-D claim-slot re-probe). The daemon submit engine now accepts
  both transaction kinds the e2e needs — **PR-4c is unblocked** and
  carries the emission arm's live acceptance coverage (this PR's
  coverage is the Phase-A/engine/shim batteries + the shared-function
  argument; a full crypto-valid emission claim requires the epoch-close
  substrate only the PR-4c harness builds).
- **PR-4c (after 4b): the e2e proper.** Mine to an epoch close with
  injected served work under the SEB lever, build via PRs 1–3's
  production path through the CB-3 seam, submit over real RPC, assert
  accepted-and-applied (claimed-set row + vout shape), the pop/reorg
  leg (bounded above the injection height), and the conservation KAT's
  fee-leg residue (#281). Rides the PR-4a harness; the E4 merge gate
  closes here.
  **LANDED 2026-07-19** (`e2e_emission_claim_accepted_and_applied`,
  `regtest_e2e.rs`; the E4 merge gate closes — FOLLOWUPS "Emission
  regtest end-to-end" item CLOSED, §4 item 5's E4/E5 precondition
  fired with zero `C_stake` code residue). Geometry: `SEB = 512`, the
  whole confirmed-bond substrate inside epoch 0 ⇒ **epoch 1 is the
  first claimable epoch** (onset stagger, `good_through`), inject <
  reference < close < claim within `REF_ANCHOR_AGE` of the close;
  single claimant holding all Σwork ⇒ loud vout `== budget_atomic(1)`
  **byte-exact** (the conservation identity live; fee-pool-half
  positivity is regtest-infeasible by the integer volume-mean law —
  pinned executably as `total_burned == 0`, positive-pool coverage
  stays with the B5 KATs). Pop legs: A5a depth-1 idempotency (claimed
  row clears, claim re-mines, operands byte-identical), A5b
  epoch-straddling (close undone + re-closed **byte-identically from
  the pop-surviving credit bits**, floor above the non-pop-symmetric
  inject), A5c deep pop through the claim's reference (chain
  re-converges, stranded claim inert; the replacement-claim half is
  the retire/resubmit FOLLOWUPS item). Composition findings, both
  fixed or pinned in-PR: the daemon **arm-order bug** (fresh-datadir
  genesis add latched the schedule before the `Blockchain::init` SEB
  arm ⇒ every levered spawn died `ArmedTooLate`; gate moved above the
  genesis add) and the **market-bond wallet entry gap**
  (`first_stake`'s CompleteTree genesis posture is foundation-flagged
  and market-excluded (E-2) ⇒ no wallet-postable bond can earn; the
  e2e claims through the composed production steps
  (`FixtureStake::MarketBond`), and the entry is a FOLLOWUPS item
  gated on gate-6 serving / SA-R2). The `staker_emission_decay` leg
  stays unit-pinned (year-scale horizon; 14 KATs,
  `shekyl-economics/src/emission_share.rs`).

**PR-4a review round (2026-07-12, high-effort workflow review — 29
verified findings, all addressed in one round; the dominant theme was
the SEB override's guard living daemon-only).** The load-bearing
outcomes, recorded here because each changed a §8 surface:

1. **The SEB override is now armed, not ambient.**
   `effective_settlement_epoch_blocks()` returns the override **only in
   a process that explicitly armed it**
   (`arm_settlement_epoch_override_for_regtest`); an unarmed process —
   every wallet today, every public-net daemon — computes the genesis
   schedule no matter what the environment says, and the wallet's
   stake-engine spawn warns once when it ignores a set lever. The
   daemon arms only on FAKECHAIN behind its `Blockchain::init` gate,
   which now refuses on the lever's *presence* (public nets), refuses
   an *invalid value* loudly (no silent clamp-to-genesis — a typo'd
   lever would otherwise surface as an unexplained harness timeout),
   and **pins the effective schedule into the fakechain datadir**
   (LMDB `properties`): reopening a regtest datadir under a different
   schedule than its epoch-derived rows were written with is a loud
   startup refusal naming the remedy, not silently mislabeled join
   epochs.
2. **The CB-3 seam is persist-before-dispatch.** `PendingEmissionClaim`
   (pending-post block **v4**) seals the claim bytes, its fee-gindex
   reservation, and its claimed epochs before any network send — the
   bond path's pin-P-2 discipline, sibling-for-sibling. The record's
   fee gindexes join the shared `reserved_gindexes` union (bond sweeps
   and claim sweeps read one exclusion set) and one-live-claim-per-
   persona is the in-flight epoch dedup (`ClaimPending` refusal;
   `push_claim` under the write lock is the authoritative
   serialization). Retirement + byte-identical resubmit = the claim
   dispatch driver, the WI-3-sibling slice (named, next).
3. **The seam no longer rotates.** The claimant id derives from a
   read-only actor projection (`PersonaIdentityOf` /
   `StakeEngineHandle::persona_identity`) instead of
   `activate_persona`: a claim is read-and-sign, and rotating on it
   would invalidate in-flight handles *and wipe a retired ephemeral
   persona* as a side effect of an unrelated request. The e2e's bond
   loop dropped its copied activation dance for the same reason
   (assembly authorizes on the handle alone).
4. **Taxonomy fixes with structural carriers.** The sweep refuses an
   empty eligible set with the typed `NoSpendableFunding` (never
   `InsufficientFunding{0, req}` — eligible-but-zero-amount records
   are a genuine shortfall with a different remedy, and the claim
   path's `ClaimFeeInputsRequired` mapping now keys on the typed arm,
   not a value shape). The reference-tree drain lag is the typed
   `OutputNotYetDrained{gindex}` across the assembly boundary (the
   harness's `detail.contains("OutputNotDrained")` substring match is
   gone). The P-scan's full-body fetch names the storage-pruned-daemon
   cause and remedy when a split body is exactly a canonical pruned
   spend (rule 82 — previously a generic "invalid transaction" against
   the operator's own node).
5. **URL grammar fixed at the source.** `HttpRpc` scopes its
   credential parse to the URL *authority* (a whole-URL `@` split
   misparsed path/query content as credentials); `LocalNodeRpc`'s
   refusal is likewise authority-scoped and its loopback pin is
   `IpAddr::is_loopback` (+ `localhost`), not a literal allowlist.
6. **Single-override/single-source consolidations.**
   `DaemonEngine::fetch_scannable_block_in_form` is the one fetch
   override point (the pruned/full pair are provided wrappers — the
   override-both-in-lockstep hazard is unrepresentable);
   `BroadcastSubmitter::local` is the one pre-bound ①-posture
   construction (three drifting copies deleted);
   `EpochCloseInputs::close_view` single-sources the pinned params the
   close FFI and `verify_view` previously restated in lockstep;
   `EmissionClaimReceipt` embeds `AssembledEmissionClaim` whole;
   `CORE_RPC_VERSION` → 3.19 for the injection RPC. One judgment call
   kept: the seam's brief-read prologue still *mirrors*
   `assemble_bond_post`'s shape (documented) rather than sharing a
   helper — the two tuples differ (tip clock vs. snapshot closure) and
   a forced abstraction would cost more than the mirror; the three
   independent reads it feeds are now `tokio::join!`ed.

Round-2 closure criteria: the §7.3 field enumeration ratified (including
the four exclusions), the §7.2 window-batch shape ratified, the §7.4
transport/shape/timing pins ratified, and the §8 chain shape accepted.
All four ratified 2026-07-09; the one open verification (the §2
low-boundary anchor) resolved in §7.2's bottom-boundary record.
**Round 2 CLOSED 2026-07-09.**

**PR-1 review watch items** (named at closure so they're checked at the
code, not assumed from the design — the two places a PR-1
implementation could silently weaken a ratified invariant while looking
correct, both grep-checkable at the handler):

1. **Single-gather trace (§7.1, the CB-1(b) daemon face).** The RPC
   handler must be a serializer over
   `gather_archival_emission_epoch_snapshot` with no second gather path
   and no operand reconstruction. Check: grep the gather call sites,
   assert exactly one new call (the RPC handler's), and read the handler
   for any row read or arithmetic that isn't marshaling — the same
   checkable shape as the wallet-side single-evaluator trace.
2. **Transport cause-blindness (§7.2).** The request struct carries
   `p_id` only — no field that can encode an epoch selection or the
   claimable subset — and the handler branches on nothing
   claimable-set-derived (the full window is serialized
   unconditionally). Check: read the request/response types and the
   handler's control flow; any claimability-dependent branch is a CB-5
   transport regression.
