# Reward-emission E3 gating round — pre-flight audit + policy-trio closure

**Status:** Round 3 (policy-trio closure) — **open for ratification** (2026-07-07).
**Process:** [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
(A2 audit-against-actual-code; the pre-flight substrate re-check).
Dispositions follow [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc).
**Spec of record:** [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md);
**plan:** [`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md) §8.

This round exists because the pre-flight substrate re-check of the reward-emission
leg (opened as a "PR-E2 design round") found the premise stale: **PR-E2 has
landed, and the E3 keystone design closed on 2026-07-01.** The only genuinely
open *design* work is the §8 policy trio (Q3 / Q11-F-E7 / Q12-F-E8), which the
plan itself marks "round-closable; not deep." This doc records the audit, closes
the trio against landed code, and enumerates the (implementation-only) PR-E3
scope the closure unblocks.

---

## 1. Pre-flight substrate audit (A2) — leg state at `dev` `1f67652b0`

The reward-emission leg is **substantially further along than the plan's linear
E0→E1→E2→E3 narrative and the `IMPLEMENTATION_INDEX` reflect.** Reconciled against
source at the pin:

| Sub-PR | Plan status | **Landed reality** | Evidence |
|--------|-------------|--------------------|----------|
| **PR-E0** bond-state write path | LANDED | LANDED | plan §3 PR-E0 |
| **PR-E1** membership-only FFI seam + ML-DSA/hybrid auth primitive | landed | **LANDED** | `shekyl_fcmp_membership_only_verify`, `shekyl_emission_hybrid_auth_verify` (`shekyl-ffi`); header decls |
| **PR-E2** emission-vin codec + wire freeze (field set A) | "opens when cluster closes" | **LANDED** | `rust/shekyl-archival-retention/src/emission_wire.rs` (full codec + KATs); commits `c6b4d0ab6`, `1a759a803`, `9f748e0d5`, `cc28bee37` |
| PR-E2 **C++ transport shim** | part of E2 | **reassigned to C-1** (not a gap) | `emission_wire.rs:44–46`: the C++ `VARIANT_TAG 0x06` "lands with the C-1 dispatch, not this codec" |
| **E3 keystone design** (M-2/Q7/Q9/Q1/Q10) | "open" | **DESIGN CLOSED 2026-07-01** | plan §8.0/§8.0.1/§8.0.2 |
| **E3 verify body** `shekyl_emission_vin_verify` | not started | **not started** (implementation) | no symbol in `rust/` or `src/` |
| **C-1** activating cut | not started | **not started** (implementation) | — |

**Keystone design closure (Round 2, 2026-07-01), verified against code:**

| Item | Disposition | Built substrate |
|------|-------------|-----------------|
| **Q9 / F-E3** intra-block `(P,E)` dedup atomicity | **PINNED** — fused check/set in the tx-connect LMDB scope; mark rolls back with the tx | `claimed_epochs_check_and_set` (`rust/shekyl-archival-retention/src/claimed_epochs.rs:99`) |
| **Q1 / F-E4** auth count + algorithm | **PINNED** — two hybrid (Ed25519+ML-DSA-65) auths, rotation-forced; drove E2's wire freeze | `emission_wire.rs` `auth_backing`/`auth_claim`; `shekyl_emission_hybrid_auth_verify` |
| **Q7** FFI seam | **resolved by house pattern** — snapshot-by-value | `archival_ffi.rs:346` (`shekyl_archival_verify_*` marshal-by-value) |
| **M-2** numerator as-of-E sourcing | **design closed** — snapshot field set (B) enumerated (§8.0.2); source is the frozen E-close materialization (invariant 2), never live | `consensus_state.rs` `EpochCloseOutputs`; `market_member_at_epoch:98` |
| **Q10 / F-E6** `held(P,E)` frozen-at-E | **two-condition pinned** — straddle-safe verified; one build item remains (the as-of-E interval marshaling) | `good_through` straddle-close (`consensus_state.rs:84–92`) |

### 1.1 Stale-doc corrections (this round lands them)

- **`IMPLEMENTATION_INDEX.md:153`** — "Reward-emission leg (PR-E1…E3, C-1
  verifier) | **Missing**" is wrong: E0/E1/E2 have landed. Corrected to reflect
  E0/E1/E2 landed, keystone design closed, E3 body + C-1 the open implementation.
- **`REWARD_EMISSION_VIN_PLAN.md` §3 PR-E2 tag prose** — describes the C++
  struct at binary `0x06` as a PR-E2 deliverable. The landed codec pins the Rust
  wire tag `0x04` and reassigns the C++ `VARIANT_TAG 0x06` to C-1
  (`emission_wire.rs:44–46`). Annotated so the two tags (Rust wire `0x04` /
  C++ oracle `0x06`) and the C-1 ownership are not misread as a gap.

### 1.2 PR-E2 C++ transport shim — boundary disposition (A4)

**Rejection.** A standalone inert C++ transport shim as residual PR-E2 work.
**Substrate.** Under gate-last (§3.0) the whitelist `check_inputs_types_supported`
default-rejects the emission vin on **both** the mempool (`tx_pool.cpp:171`) and
block-verify (`blockchain.cpp:2371`) paths, so an early inert C++ struct buys
zero relay/parse benefit and only adds surface ([`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc)).
The C++ transport is only *needed* where the dispatch consumes it — at C-1. The
landed codec already recorded this disposition (`emission_wire.rs:44–46`).
**Reopening (rule 21).** Reopens only if a pre-C-1 consumer emerges that must
parse the vin from C++ without the Rust codec (e.g., an explorer path landing
before C-1) — decided in that consumer's PR, not by default.

---

## 2. Policy trio — dispositions (the residual open design)

The trio is the last open *design* on the leg (plan §8 table row
`Q3 / Q11 (F-E7) / Q12 (F-E8)` — "acceptance-path policy; round-closable; not
deep"). Two are resolved-by-landed-substrate; one (Q11) is a genuine — if
shallow — decision, marked **PROPOSED** for human ratification because it is
consensus-acceptance-path (priority-1).

### 2.1 Q3 — backing-input distinctness — RESOLVED (vacuous at arity 1)

**Disposition.** No vin-layer input-distinctness rule. The backing carries
**exactly one** input (the arity-1 pin, `emission_wire.rs:115–124`), so the
membership-doc §8.2 multi-input distinctness concern has no surface: "the §8 open
item 3 (backing-input distinctness) is vacuous at arity 1" (same source).
**Rejection.** A multi-input dedup/distinctness rule at the vin layer.
**Reopening (rule 21).** Reopens **iff** backing arity rises above 1 — which
*first* reopens the §8.0.1 two-auth arity pin (per-output one-time keys ⇒ *n*
inputs need *n* auths, contradicting the frozen two-auth wire). Q3 therefore
cannot reopen without the auth-arity pin reopening ahead of it.
**Re-evaluation shape.** Design-round 1 of the PR that raises backing arity, with
the auth-arity reopen and call-graph evidence.

### 2.2 Q11 / F-E7 — same-tx backing + key-imaged fee double-use — **PROPOSED: ACCEPT**

**Threat (plan §8 open item 11).** §5.2 permits ≥0 fee `txin_to_key` inputs (with
key images) alongside the one membership-only backing; the threat model names
"mixing to launder a key-image spend" — i.e., one underlying output used as both
membership-only backing **and** a key-imaged fee spend in the same tx.

**Proposed disposition: ACCEPT — no vin-layer exclusion.** Three substrate-anchored
reasons:

1. **No value path.** Membership-only backing publishes **no key image** and
   **moves no value** (`REWARD_EMISSION_LEG.md` §7.3). The fee `txin_to_key`
   carries its own key image and rides the FCMP++ balance/inflation check, which
   prevents value double-spend **independently of** the backing. Using the same
   output as backing adds no mintable value.
2. **Unenforceable by construction.** An "exclude same-tx-spent output from the
   backing" rule keys on the backing↔fee identity that **consensus is blind to**:
   the membership proof hides the leaf, so consensus cannot correlate the backing
   with a fee key image. This is the exact shape of the §7.3 lineage disposition
   ("consensus is **blind to lineage** … unenforceable by construction").
3. **Already inside the accepted model.** §7.5's intra-epoch unbacked lemma
   already accepts that `P` spends funding outputs while serving; backing validity
   is anchored at the **reference tree root**, not at "output still unspent at tx
   time." The mix changes nothing the model does not already permit.

**Rejection.** A consensus rule requiring the backing output to be excluded from
the same tx's key-imaged spend set.
**Reopening (rule 21).** Reopens iff a concrete construction shows the mix yields
either (a) value double-use surviving the FCMP++ balance check, or (b) a
`(P,E)` dedup / anti-replay bypass (dedup is bond-record state, independent of
the backing output — so no path is known). Also reopens if the backing primitive
ever publishes a key image.
**Re-evaluation shape.** Threat-model addendum carrying the concrete construction;
if real, the mitigation lands at the **gate-6 wallet-policy** layer first
(consensus cannot enforce it), escalating to consensus only if wallet policy is
demonstrably insufficient.
**Ratification flag.** This is the one trio item that is a genuine decision rather
than a substrate readout; it is consensus-acceptance-path (priority-1). Recorded
**PROPOSED** pending sign-off.

### 2.3 Q12 / F-E8 — zero-work / zero-reward emission — RESOLVED (foreclosed)

**Threat (plan §8 open item 12).** §4.3's R-ceiling dead zone (`R > 1000·g(age)`
→ `scarcity_milli = 0`) plus `Curve(0)` lets a `P` with all shards in the dead
zone recompute `work_P = 0`, `reward = 0` — block-space spam if accepted with a
zero vout.

**Disposition: REJECT — already foreclosed, no new acceptance-path branch.**

1. **Structural (wire).** The landed codec enforces **strict per-epoch
   positivity**: `reward_amount_plain[i] == 0` is unencodable on both write and
   read (`WireError::RewardAmountZero`, `emission_wire.rs` §2.3 —
   `validate()` :436–441, `read_payload` :606–614), and an empty claim is
   rejected (`EpochCountOutOfRange`, ≥1 epoch). A zero-total emission **cannot be
   built.**
2. **Economic (verify).** The §5.4 zero-tolerance recompute rejects a claimed
   *positive* amount whose recompute is 0 (all-dead-zone → `work_P = 0` →
   `reward = 0` ≠ claimed positive). So the dead-zone case fails the equality
   check regardless.

Width is already u128-safe (`mul_div_floor`; plan §8 item 12, confirmed at
source).
**Rejection.** An accept-with-zero-vout policy branch.
**Reopening (rule 21).** Reopens iff the wire positivity invariant is relaxed, or
a legitimate non-spam zero-reward use emerges (none known). The §4.3 dead-zone
*scale* reopen (gate 3/5 permitting `R` large enough to zero most shards) is a
separate scale concern, not a policy reopen.
**Re-evaluation shape.** If wire positivity is ever relaxed, this disposition
reopens in the same PR.

---

## 3. Unblocked PR-E3 scope (implementation, not design)

On trio ratification the leg has **zero open design items.** What remains is
implementation, in dependency order:

1. **`held(P,E)` as-of-E interval marshaling — the "one build item" (§8.0).**
   C++ reads `P`'s persisted bond intervals + `join_settlement_epoch`, marshals
   them **by value** into the snapshot; Rust runs the already-built
   `market_member_at_epoch` (`consensus_state.rs:98`). **Not** a tip-read (the
   C++ `has_archival_bond_shard` is tip-relative, `db_lmdb.cpp:5054`); there is
   no `BondEventLog` reader in the Rust crate yet. Reuse the logic; build the
   accessor.
2. **M-2/Q7 as-of-E snapshot struct (field set B, §8.0.2).** Marshaled by value,
   each field from the frozen E-close materialization (invariant 2), never live;
   carries the two Q1 auth fields.
3. **`shekyl_emission_vin_verify` — verify body, steps 1–7** (KAT-tested; **not**
   on the consensus dispatch — still unwhitelisted). Recompute `work_P(E)` ==
   `work_claim`; `reward_P(E)` via `reward_arithmetic` == `reward_amount_plain` +
   Σvout; dedup via `claimed_epochs_check_and_set`; backing via membership-only +
   the two hybrid auths. The auth result enters as an **unforgeable
   `AuthVerified` witness** the body cannot mint itself (fail-closed by type,
   §3.0) — E3 physically cannot accept an authed emission.
4. **C-1 — the activating cut** (separate PR; [`07-consensus-atomic-cutovers.mdc`](../../.cursor/rules/07-consensus-atomic-cutovers.mdc)):
   ML-DSA witness minter + `check_inputs_types_supported` whitelist flip + C++
   shim dispatch + `VARIANT_TAG 0x06`. Merge blocker = ML-DSA present/tested **and**
   the gate-6 backing-lineage ladder + sweep wired in the wallet pre-join path
   (§8.0.3 C-1 precondition).
5. **E4/E5** — delete `txin_stake_claim`/`C_stake` only after emission is
   accepted-and-applied on a regtest chain through the real C-1 path; constants,
   KATs, audit-scope, docs.

---

## 4. Round status

- **Q3** — RESOLVED (vacuous at arity 1).
- **Q12 / F-E8** — RESOLVED (foreclosed by wire positivity + zero-tolerance recompute).
- **Q11 / F-E7** — **PROPOSED: ACCEPT** — awaiting ratification (the one
  consensus-acceptance-path decision).

On Q11 ratification, **the reward-emission leg has no open design items** and
PR-E3 becomes an implementation sequence (§3). Next action after ratification:
open the PR-E3 implementation pre-flight against §3's build list.
