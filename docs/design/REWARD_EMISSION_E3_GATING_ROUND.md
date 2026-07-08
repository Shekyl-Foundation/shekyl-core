# Reward-emission E3 gating round — pre-flight audit + policy-trio closure

**Status:** Round 3 **CLOSED** (2026-07-07). Q3/Q12 resolved; **Q11 ACCEPT
ratified**; **WS-1 (Q10/M-2/Q7 two-conjunct held-sourcing) ratified** (§5);
**WS-2 (Q9/F-E3 dedup atomicity) ratified** (§6: block-level `(P,E)` pass +
journaled claimed-set revert, severity-upgraded — the prune straddle is a
**double-mint**, journal row = pre-image delta `{inserted E, evicted members}`).
The leg's design is complete; the PR-E3 implementation pre-flight runs against
current `dev` (§7.1, §8).
**Process:** [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
(A2 audit-against-actual-code; the pre-flight substrate re-check).
Dispositions follow [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc).
**Spec of record:** [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md);
**plan:** [`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md) §8.

This round exists because the pre-flight substrate re-check of the reward-emission
leg (opened as a "PR-E2 design round") found the premise stale: **PR-E2 has
landed, and the E3 keystone design mostly closed on 2026-07-01.**

The re-check then found **one keystone item was closed too early.** A source
wargame of Q10 (`held(P,E)` frozen-at-E) against the supply-conservation
adversary (§5) showed the Round-2 "one build item: as-of-E interval marshaling"
disposition conflated two different quantities: **standing** (`bad_intervals`,
genuinely interval-semantic and as-of-E correct) and **held-shard-set** (the
`held_shard_ids` bond descriptor, which is *tip-mutable* — mid-life add/drop is
genesis-scoped V3.0 — and whose only accessor is the documented M2-1 tip-read at
`db_lmdb.cpp:4984–4990`). So the leg has **two** open design surfaces, not the
one the opening assumed:

1. **WS-1 — the Q10→M-2→Q7 held-sourcing correction (§5).** The as-of-E `held`
   ground truth is the per-`(P,s,E)` serve-credit bits, not the mutable
   descriptor — but the bits only *mean* held-at-E because acceptance gates on
   holding, and that gate (`:4307`) uses the same broken tip accessor. So M-2
   closes under **bits-sourcing ∧ as-of-fire-height acceptance** (§5.4), one
   shared sourcing function and one shared accessor: the supply-conservation
   hard blocker, and the keystone with no backstop underneath it (§5.5).
2. **The §8 policy trio** (Q3 / Q11-F-E7 / Q12-F-E8) — "round-closable; not deep"
   (§2), unchanged from the opening.

Q9/F-E3 dedup atomicity is a third, *parallel* surface (WS-2): pinned at the
function, open in the load-at-verify / write-at-connect plumbing (§6). This doc
records the audit, closes the trio (§2), settles the WS-1 sourcing question at
source (§5), and enumerates the PR-E3 scope (§3) the closures unblock.

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
| **E3 keystone design** (M-2/Q7/Q9/Q1/Q10) | "open" | **MOSTLY closed 2026-07-01; Q10/M-2 held-sourcing reopened by the §5 source audit** — Q1/Q7 pinned; Q9 pinned-at-function/plumbing-open (WS-2); M-2/Q10 held-term needs the bits-sourcing correction (§5) | plan §8.0/§8.0.1/§8.0.2; **corrected §5** |
| **E3 verify body** `shekyl_emission_vin_verify` | not started | **not started** (implementation) | no symbol in `rust/` or `src/` |
| **C-1** activating cut | not started | **not started** (implementation) | — |

**Keystone design closure (Round 2, 2026-07-01), verified against code — with two
rows corrected by the Round-3 §5 source audit:**

| Item | Disposition | Built substrate |
|------|-------------|-----------------|
| **Q9 / F-E3** intra-block `(P,E)` dedup atomicity | **PINNED** at the function; **plumbing open** (WS-2) — the fused check/set is atomic on its *passed* set, but the load-at-verify / write-at-connect straddle lets two same-block same-`(P,E)` emissions both pass (§6) | `claimed_epochs_check_and_set` (`rust/shekyl-archival-retention/src/claimed_epochs.rs:99`) |
| **Q1 / F-E4** auth count + algorithm | **PINNED** — two hybrid (Ed25519+ML-DSA-65) auths, rotation-forced; drove E2's wire freeze | `emission_wire.rs` `auth_backing`/`auth_claim`; `shekyl_emission_hybrid_auth_verify` |
| **Q7** FFI seam | **resolved by house pattern** — snapshot-by-value | `archival_ffi.rs:346` (`shekyl_archival_verify_*` marshal-by-value) |
| **M-2** numerator as-of-E sourcing | **design closed *conditional on bits-sourcing ∧ as-of-fire-height acceptance* (§5.4) — the conjunction.** `R_market(s,E)`/`Σwork(E)` frozen-persisted (invariant 2). The `held(P,E)` term is sound **only if** (1) sourced from the per-`(P,s,E)` serve-credit bits, not the mutable descriptor, **and** (2) those bits were populated by an acceptance gate reading as-of-fire-height (`:4307`, currently the broken tip accessor). Round-2 "snapshot field set (B)" omitted both; corrected in §5 | `consensus_state.rs` `EpochCloseResult`; `market_member_at_epoch:98`; `archival_serve_credit`; `blockchain.cpp:4307` |
| **Q10 / F-E6** `held(P,E)` frozen-at-E | **CORRECTED (§5): not a marshaling pin — a sourcing correction + one accessor build.** The "as-of-E interval marshaling" framing conflated **standing** (`bad_intervals`, genuinely interval/as-of-E) with **held** (no interval log; `held_shard_ids` is tip-mutable — M2-1 at `db_lmdb.cpp:4975`/`4984–4990`). As-of-E held ground truth = the serve-credit bits; the one `at_height`-honoring accessor serves **both** :4307 acceptance and the V3.0 mutable-holdings read (**Open**, FOLLOWUPS P2B-7 Pin 4) | `good_through` straddle-close (`consensus_state.rs:84–92`) is the **standing** half; held half in §5 |

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
deep"). Two are resolved-by-landed-substrate; one (Q11) was a genuine — if
shallow — decision, proposed for human ratification because it is
consensus-acceptance-path (priority-1), and **ratified** (§7).

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

### 2.2 Q11 / F-E7 — same-tx backing + key-imaged fee double-use — **RATIFIED: ACCEPT**

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
**Ratification.** **RATIFIED (2026-07-07)** — the one trio item that is a genuine
decision rather than a substrate readout (consensus-acceptance-path, priority-1),
signed off with its arming KAT below.
**Arming KAT (backing-pseudo-out balance-exclusion).** The ACCEPT rests on
reason 1 (no value path): the membership-only backing contributes **no
pseudo-output** to the FCMP++ balance/inflation check. A KAT pins exactly that —
a tx mixing the same output as backing **and** a key-imaged fee spend balances
**identically** to one with a distinct backing, i.e. the backing adds nothing to
the summed pseudo-outs. If the backing primitive ever contributes a pseudo-out
(so the mix could add mintable value), the KAT breaks — that is the reopen
signal, made mechanical rather than prose.

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

With the trio, WS-1, and WS-2 all ratified (§7), everything below is
implementation, in dependency order:

1. **`held(P,E)` as-of-E sourcing — the WS-1 build item (§5, corrects §8.0's
   "one build item").** M-2 closes under the **two-conjunct** rule (§5.4). Four
   concrete pieces: **(a)** a single `as_of_E_served_work(frozen_ledger, P, E)`
   sourcing function called by **both** `epoch_close_compute` (denominator) and
   the verify body (numerator) — divergence unrepresentable, M-3 pushed one layer
   deeper (§5.5-1); **(b)** **remove `held_shard_ids` from the work-channel
   input type** (not merely delete the `consensus_state.rs:386–389` filter line —
   remove the field from work's scope so a re-filter does not compile, §5.5-2),
   sourcing the shard set from `archival_serve_credit` (keyed
   `ArchivalServeCreditKey(P,shard,E)`), marshaled by value at the claimed `E`
   (keyed by `E` — point read, no reconstruction); **(c)** the **one
   `at_height`-honoring accessor** (FOLLOWUPS P2B-7 Pin 4) fixing conjunct 2,
   **with two consumers to satisfy, not one** — both currently ride the broken
   tip read: `blockchain.cpp:4307` (serve-credit *acceptance*) **and**
   `db_lmdb.cpp:5270` in `archival_challenge_failed_at_height` (slash
   *eligibility* — a challenge counts as failed/slashable only if `P` held at
   `h_fire`; the tip read under-slashes a held-then-dropped `P` and wrongfully
   slashes an acquired-after-fire `P`). The corrected accessor must be validated
   against **both** meanings (credit-admit and slash-eligibility), and is shared
   with the V3.0 mutable-holdings read — co-designed in the bond-lifecycle
   connect-path work, not a duplicate emission-only reader; **(d)** the **three armed KATs** (§5.6:
   drop-after-serve, acceptance-gate, ledger reorg-symmetry). **Standing** stays
   as-is: `bad_intervals` + `join` → `market_member_at_epoch`
   (`consensus_state.rs:98`) is genuinely as-of-E.
2. **M-2/Q7 as-of-E snapshot struct.** Marshaled by value, each field from the
   frozen E-close materialization (invariant 2: `R_market(s,E)`, `Σwork(E)`,
   shard `freeze_height`) **plus** the per-`(P,s,E)` serve-credit bits for the
   claimed epoch (the §5 held source); never the live bond descriptor; carries
   the two Q1 auth fields.
3. **`shekyl_emission_vin_verify` — verify body, steps 1–7** (KAT-tested; **not**
   on the consensus dispatch — still unwhitelisted). Recompute `work_P(E)` ==
   `work_claim`; `reward_P(E)` via `reward_arithmetic` == `reward_amount_plain` +
   Σvout; dedup per the WS-2 layering (§6.2): verify does the **read-only**
   `claimed_epochs_contains` against the pre-block bond record; backing via
   membership-only + the two hybrid auths. The auth result enters as an
   **unforgeable `AuthVerified` witness** the body cannot mint itself
   (fail-closed by type, §3.0) — E3 physically cannot accept an authed emission.
3a. **WS-2 dedup plumbing (§6).** The block-level `(P,E)` uniqueness pass in
   `handle_block_to_main_chain` (mirror of `:4882`, every `(P, E_i)` pair);
   connect-path `claimed_epochs_check_and_set` FFI wrapper as the single writer
   (`Ok(false)` at connect = hard error); the claimed-set revert **journal** +
   pop-path restore (slash-log idiom, §6.3) — **the journal row is the
   pre-image delta `{inserted E, evicted set members}` as one unit** (an
   insert-only journal leaves the §6.3 double-mint alive), covering
   `first_paying_emission_height`; the three §6.4 KATs (prune-straddle KAT
   asserts post-reorg re-claim **rejection**).
4. **C-1 — the activating cut** (separate PR; [`07-consensus-atomic-cutovers.mdc`](../../.cursor/rules/07-consensus-atomic-cutovers.mdc)):
   ML-DSA witness minter + `check_inputs_types_supported` whitelist flip + C++
   shim dispatch + `VARIANT_TAG 0x06`. Merge blocker = ML-DSA present/tested **and**
   the gate-6 backing-lineage ladder + sweep wired in the wallet pre-join path
   (§8.0.3 C-1 precondition).
5. **E4/E5** — delete `txin_stake_claim`/`C_stake` only after emission is
   accepted-and-applied on a regtest chain through the real C-1 path; constants,
   KATs, audit-scope, docs.

---

## 5. WS-1 — `held(P,E)` as-of-E sourcing (Q10 → M-2 → Q7 keystone)

**This section reopens and re-closes the Q10/M-2 held-term that Round 2 closed
too early.** It is the supply-conservation hard blocker; it is settled here at
source.

### 5.1 The wargame — Q10 against the supply-conservation adversary

`work_P(E)` sums `shard_work_milli(R_market(s,E), age, …)` over the shards `P`
**held and served** at `E` (`consensus_state.rs:381–409`). `R_market(s,E)` is
frozen-persisted at close (`archival_r_market`, §4 invariant 2), so the
denominator side is as-of-E by construction. The adversary target is the
**numerator's held term**: if PR-E3's verify recomputes `work_P(E)` with a
`held` set that differs from the frozen as-of-E truth, the reward drifts from
the finalized `Σwork(E)` denominator — the plan's named silent-mint failure.

Verify runs up to `MAX_CLAIM_AGE_W` epochs after `E`, so "held as-of-E" ≠ "held
at verify-time tip" whenever `P` mutated holdings in between. Mid-life add/drop
(`HoldingsUpdate`) is **genesis-scoped V3.0** (`FOLLOWUPS.md:1317–1319`;
`ARCHIVAL_BOND_GATE4.md` §4.4), so the gap is live, not hypothetical.

### 5.2 Standing vs. held — the asymmetry Round 2 conflated

The bond record (`ArchivalBondValue` v4, `shekyl_types.h`) carries the two
temporal quantities with **different shapes**:

| Quantity | Storage | As-of-E? |
|----------|---------|----------|
| **Standing** (`good_through` / market membership) | `bad_intervals: [{start_epoch, end_exclusive}]` — interval-semantic | **Yes** — `market_member_at_epoch(join, E, bad_intervals, …)` (`consensus_state.rs:98`) evaluates it at any `E` |
| **Held shard set** | `held_shard_ids: Vec<u64>` — a **flat, tip-current** vector, mutated in place by add/drop | **No** — no epoch dimension; the pre-mutation set as-of-E is overwritten |

The only C++ hold accessor takes `at_height` and **ignores it**, reading the
tip descriptor — the documented M2-1 defect, verbatim in the source:

```4984:4990:src/blockchain_db/lmdb/db_lmdb.cpp
  // NOTE: returns tip holdings (ignores at_height). This was sound while holdings were
  // immutable, but HoldingsUpdate is now genesis-scoped (V3.0, 2026-06-15) — a P can add/drop
  // shards mid-life, so "holds shard now" no longer implies "held shard at at_height". The
  // serve-credit window check must be reconciled with mutable holdings when the
  // Rebond/Unbond/HoldingsUpdate connect paths land (PHASE_2B_FSM_RETOOL.md; FOLLOWUPS V3.0
  // bond-lifecycle item). Behavior unchanged here pending that work.
```

Round 2's "as-of-E interval marshaling" disposition applied the **standing**
shape (correct, interval-based) to the **held** term (wrong: there is no held
interval log to marshal). That is the conflation this section corrects.

### 5.3 The ground truth exists — table identity settled at source

The spec already pins the correct source against exactly this failure:

> `work_P(E)` is derived from per-`(P,s,E)` **retention bits**, not the mutable
> holdings descriptor. HoldingsUpdate cannot corrupt historical work; descriptor
> = current membership, **bits = per-epoch ground truth.**
> — `ARCHIVAL_BOND_GATE4.md:479–481` (§4.4)

Enumerated at source, the archival LMDB tables are `archival_serve_credit`,
`archival_bond`, `archival_shard_segment`, `archival_slash_applied/_log`,
`archival_r_market`, `archival_sigma_work`, `archival_epoch_close_log`
(`db_lmdb.cpp:1632–1646`). **There is no separate retention-bit table and no
`archival_held` table.** Therefore the "per-`(P,s,E)` retention bits" the spec
names *are* the serve-credit bits in `archival_serve_credit`, keyed
`ArchivalServeCreditKey(P_id, shard_id, E)` (`db_lmdb.cpp:4893–4935`). Those bits
are **set on connect / removed on disconnect** (`blockchain_db.cpp:224` / `:586`)
— reorg-symmetric by the same pop-ordering discipline as invariant 2.

**`credit(P,s,E) ⟹ held(P,s,E)`-as-of-E — cryptographically, not by convention.**
Setting the bit requires a `txin_archival_serve_credit_response` that passes
`verify_segment_path(&leaf_bytes, …, &segment_subroot_rk)` against the **frozen
registry segment subroot**, gated on `registry_segment_subroot_rk` match
(`archival_ffi.rs:295–297, 337–344`). The leaf binds `(P_canonical_id, shard_id,
E)` to the frozen registry — i.e., the bit cannot be set unless `P`'s shard `s`
was a registry leaf as-of-E. So the serve-credit bit is a *sound* as-of-E
held-and-served witness; the descriptor filter adds nothing it doesn't already
imply, except drift.

### 5.4 Disposition — the two conjuncts of supply conservation

M-2 is *literally* the supply-conservation keystone: there is **no independent
per-epoch cap** — no `Σ minted(E) ≤ budget(E)` enforced separately from the
share formula. `reward_share_floor(budget, capped_milli, sigma_work_milli)`
(`reward_arithmetic.rs:129`) takes `budget` as an **input** (set by the emission
schedule + tx-responsive release, *work-independent*), and conservation is
purely structural: `reward_P = budget · capped_P / Σwork_stored` sums to `budget`
**iff every verify-time numerator `capped_P` equals P's exact frozen term in the
stored denominator `Σwork(E)`**. `VIN_PLAN:495–523` spells out the failure: a
live- or tip-descriptor-sourced numerator exceeds P's frozen term (R_market has
drifted up since close), `Σ > budget`, **real inflation** breaking R1.B. That
same passage names `held(P,E)` as the still-open *fourth* input gated on Q10 —
the correction below is that it is **not a fourth input**: it collapses into the
E-indexed serve-credit bit (input #2, §5.3), and the descriptor was a phantom
fifth source.

**RATIFIED (consensus sourcing rule; priority-1):** M-2 closes under
**bits-sourcing ∧ as-of-fire-height acceptance** — the conjunction, not
bits-sourcing alone.

- **Conjunct 1 — bits-sourcing.** `work_P(E)`'s held-and-served shard set is
  sourced from the per-`(P,s,E)` serve-credit bits (`archival_serve_credit`),
  never from `held_shard_ids`.
- **Conjunct 2 — as-of-fire-height acceptance.** The bit only *means*
  "held-and-served as-of-E" because acceptance gates on holding at fire height —
  and that gate uses the **same broken accessor**: `blockchain.cpp:4307` calls
  `archival_bond_holds_shard(resp.p_canonical_id, resp.shard_id, h_fire)`
  (verified this round), which ignores `at_height` and reads tip
  (`db_lmdb.cpp:4975`, the M2-1 defect). Under immutable holdings tip ≡ h_fire,
  so every extant credit is a sound as-of-E bit; under **V3.0 mutable holdings**
  it is not — :4307 can admit a credit for a shard `P` acquired *after* the
  challenge fired, or reject one `P` held-at-fire-then-dropped.

**Both conjuncts, or the conflation returns.** Bits-sourcing *without* fixing
:4307 merely moves the as-of-E defect one layer up: the ledger you would trust
was itself populated by a tip-descriptor gate. Stating conjunct 1 alone
reproduces the exact M2-1 shape the original defect was — a sound-looking
sourcing rule resting on an unsound populate path.

**One build, not two.** The `at_height`-honoring accessor (FOLLOWUPS P2B-7
Pin 4) discharges conjunct 2 at :4307 **and** is the identical read the V3.0
mutable-holdings rule needs — one accessor, one as-of-E semantics, one
implementation. Retiring the descriptor filter (conjunct 1) is *sound only
because* that accessor makes the bit trustworthy; neither change is correct in
isolation. That is the coupling made precise: not "share one source," but "the
ledger only *means* held-at-E once acceptance reads as-of-fire-height."

### 5.5 Make the single path unbreakable by construction

Deleting the filter promotes the credit ledger to the **sole** gate on
`work_P(E)`. That is correct — the descriptor filter was never sound
defense-in-depth; it was a *second, silently-wrong source of "held,"* and that
wrong source is precisely what manufactures the over-mint. Collapsing to one
path genuinely reduces attack surface. But the honest blast radius is that the
path is **unbackstopped**: the §5.4 zero-tolerance recompute (leg step 5) catches
a *wallet* lying about the amount, and per-`(P,E)` dedup caps one claim per
epoch — **neither catches a consensus-rule sourcing inconsistency.** Both sides
recompute with the same rule, so if the rule mis-sources, *consensus itself*
mints the inflated amount and the zero-tolerance compare passes it. Sourcing is
the one correctness obligation with nothing underneath it; the protection must
therefore be structural, not a second checker. Three moves, all
make-bad-states-unrepresentable:

1. **One sourcing function, both sides.** A single
   `as_of_E_served_work(frozen_ledger, P, E)` that **close** calls to build
   `Σwork` and **verify** calls to build `capped_P`. Then the numerator is P's
   exact term in the denominator *by construction* — same code, same frozen data
   — and divergence is **unrepresentable**, not tested-against. This is M-3's
   single-source idiom (`reward_arithmetic`/`Curve`, both sides) pushed one layer
   deeper: from same-arithmetic to same-input-sourcing.
2. **Descriptor out of the work-channel type.** Not "delete the filter line" —
   **remove `held_shard_ids` from the input the work computation sees**, so a
   future "shouldn't we re-check they still hold it?" edit does not compile. The
   descriptor keeps its real job (current membership: bond-floor, gate-4 connect)
   elsewhere; it is simply unreachable from work.
3. **Reorg-symmetry inherited, not bespoke.** The bits' set-on-connect /
   remove-on-disconnect (`blockchain_db.cpp:224`/`:586`, verified this round —
   keyed `(P, shard, E)`, E-indexed) is an instance of the **M1 O-3
   pop-symmetric discipline that just landed** (`CHANGELOG.md`; `LMDB_SCHEMA.md`
   v8; `ARCHIVAL_REWARD_GATE_M1.md:89`), not a hand-rolled parallel path — one
   reorg mechanism, many tables. And the frozen snapshot is **one marshaled
   struct passed to both readers**, so **Q7 falls out as "one snapshot, two
   readers"** (`archival_ffi.rs:346` house pattern) — resolved as Round 2 held,
   but now over the *correct* source, and with no new schema or revert path.

### 5.6 The three armed KATs (triggers, not prose invariants)

Because the deletion promotes the ledger to the sole work gate, its correctness
rests on (acceptance-time membership at :4307) + (ledger reorg-symmetry). Three
KATs arm that — the load-bearing test set the WS-1 build lands with:

1. **Drop-after-serve KAT (regression guard on the deletion).** `P` holds `s` at
   `h_fire`, serves (credit accepted), **drops `s` before close** → `work_P(E)`
   counts `s`. This is the case the descriptor filter got wrong; it guards the
   deletion against re-introduction.
2. **Acceptance-gate KAT (the :4307 fix's boundary).** Credit **rejected** when
   `P` did not hold at `h_fire` (even if held at tip); **accepted** when `P` held
   at `h_fire` (even if dropped by tip). Forecloses the only case that could put
   a credit in the ledger without a real as-of-E hold.
3. **Ledger reorg-symmetry KAT (now load-bearing, not corroborating) — pins the
   *composition*, not a duplicate that can occur.** The unconditional set/remove
   has **no refcount**, and that is *sound because duplicates are structurally
   unreachable*: `(P,s,E)` multiplicity is provably ≤ 1 on any canonical chain —
   `blockchain.cpp:4247` rejects a credit whose `(P,s,E)` bit is already set
   ("Duplicate archival serve-credit", against pre-block DB state), and
   `blockchain.cpp:4882` rejects two `(P,s,E)` credits across txs in one block
   (48-byte `(P,shard,E)` block set). So the block whose connect set the bit is
   the *only* block whose disconnect can clear it; a refcount would be dead
   machinery. The KAT therefore proves the composition: **(a)** a second
   `(P,s,E)` credit is rejected both intra-block (`:4882`) and against prior DB
   state (`:4247`), **and** **(b)** given that rejection, the single credit's bit
   round-trips **bit-identically** across a pop spanning its set height
   (`blockchain_db.cpp:224` set / `:586` remove, keyed `(P,s,E)`). It proves
   duplicates are *unreachable* and that their unreachability is the load-bearing
   reason no-refcount is sound — not that a duplicate is handled.

### 5.7 Reopening (rule 21)

Reopens iff (a) a serve-credit bit can be set for a shard `P` did **not** hold
as-of-E — i.e., the §5.3 segment-path binding **or** conjunct-2 acceptance is
ever weakened so `credit ⇏ held` (then the descriptor filter, or a dedicated
held interval log, returns as a real requirement); or (b) `work_P` is redefined
to count held-but-**unserved** shards (none such today — work requires credit).

**No-refcount ↔ dedup coupling (armed trigger).** The bit's reorg-symmetry
(§5.6) is not self-contained — it is a theorem with a dependency on the two
dedup guards. **Reopens iff serve-credit dedup at `blockchain.cpp:4247` or
`:4882` is ever relaxed to admit multiple `(P,s,E)` credits:** the unconditional
remove-on-disconnect then becomes a reorg **under-count** (pop the second
crediting block → its disconnect clears a bit the first block's still-live credit
justifies → `work_P(E)` silently drops it), so **the bit must gain a refcount or
the disconnect must become conditional.** Recording this ties the two decisions
together; without it the coupling lives only in review and a future dedup change
breaks reorg-symmetry with nothing biting.

**Proof-carrying acceptance — named reopen, not now.** The purist "derive, don't
hold state" would have the serve-credit response **carry a proof** it held `s` at
fire height against a committed **per-P holdings-history root** — acceptance
verifies an in-tx witness and there is *no stateful accessor at all*. It is
cleaner in principle but needs new commitment machinery (the holdings-history
root), i.e. more complexity and surface, against the very preference it serves.
The height-honoring accessor + one-sourcing-function gets essentially all the
conservation benefit at a fraction of the cost. **Build the accessor for
genesis; record proof-carrying acceptance as this reopen,** triggered iff
mutable-holdings behavior makes the stateful accessor's as-of-E reads a
demonstrated correctness or performance problem.
**Re-evaluation shape.** Design-round 1 of the PR that weakens the segment-path
binding, weakens :4307 acceptance, or redefines `work_P`'s shard predicate, with
the credit-implies-held proof re-examined at source.

---

## 6. WS-2 — Q9/F-E3 dedup atomicity — **RATIFIED**

Independent of WS-1 (different mechanism; shared only in the PR-E3
verify/connect split). Closed here at source (operands re-verified at `dev`
`90e790c9c`; the `1f67652b0→90e790c9c` delta touched only CI config + CHANGELOG
— zero operand drift).

### 6.1 The straddle, at source — architectural, not accidental

**The function is not where the bug is.** `claimed_epochs_check_and_set(&mut
set, …)` (`claimed_epochs.rs:99`) is atomic on its *passed-in* set and correctly
returns `Ok(false)` on the second call for the same epoch (its own tests,
`:137–138`). The straddle is in the **plumbing**, and it is by design:

- The set is an **inline field on the per-P bond record** —
  `ArchivalBondValue::claimed_settlement_epochs` (`shekyl_types.h:613`, v4
  codec: at-rest cap/order/span validation only; semantics live in Rust,
  mirroring the `good_through` split).
- The mutation site is **connect**: "The FFI wrapper lands with its first
  caller, the emission vin's **connect path**" (`claimed_epochs.rs:16`).
- Verify therefore reads the bond record from **pre-block DB state** — which is
  exactly what the ratified Q7 pin demands (verify = pure function of the
  marshaled pre-block frozen snapshot).

So two same-block emissions from the same `P` claiming the same `E` both load
the same pre-state set, both check their own copy, both see `E` unset — the
double-mint window, purely intra-block.

### 6.2 Disposition — the block-level `(P,E)` pass (option 2); option 1 foreclosed by Q7

**RATIFIED (consensus acceptance rule; priority-1):** dedup is delivered by
**three layers, one per scope**, of which only the middle one is new:

| Scope | Mechanism | Status |
|-------|-----------|--------|
| **Intra-tx** | Wire: `settlement_epochs` strictly increasing ⇒ duplicates **unencodable** (`emission_wire.rs:427–428`/`:564–565`, `EpochsNotStrictlyIncreasing`) | **Landed** |
| **Intra-block, cross-tx** | **Block-level `(P,E)` uniqueness pass** in `handle_block_to_main_chain`, over every `(P, E_i)` of every emission vin in the block, before connect | **The WS-2 build item** |
| **Cross-block** | Verify: read-only `claimed_epochs_contains` against the pre-block bond record; connect: `claimed_epochs_check_and_set` as the single writer | Function landed; FFI wrapper lands with connect |

**Option 2 is not merely preferred — it is the landed house idiom for this exact
straddle.** The serve-credit leg hit the identical shape and solved it with the
identical pass: `blockchain.cpp:4882–4901` in `handle_block_to_main_chain`
(`:4504`), commented verbatim "Per-tx serve-credit idempotency checks run
against pre-block DB state; reject duplicate (P, shard, E) credits across
multiple txs in the same block." The emission pass mirrors it with key `(P,E)`
instead of `(P,s,E)`, with one difference that widens the loop: an emission vin
claims a **vector** of epochs, so the pass inserts every `(P, E_i)` pair, not
one key per vin.

**Option 1 (intra-block write-visibility) is rejected on keystone coherence,
not taste:** letting tx2's verify see tx1's connect-scope write makes the verify
**order-dependent within the block**, destroying the Q7-ratified
pure-function-of-frozen-snapshot property that the supply-conservation audit
argument rests on (§5.5 — one sourcing function over one frozen input set).
The pass keeps per-tx verify order-independent and pushes the ordering question
into one structural, auditable site.

**Connect-time `Ok(false)` is an invariant breach, not a reject.** With the
three layers in place, `claimed_epochs_check_and_set` returning `Ok(false)` at
connect is unreachable (verify's contains-check + the block pass already
foreclosed it). The connect path treats it as a hard error (`throw`, matching
the connect-path `FATAL:` style at `blockchain_db.cpp:230`), never a soft skip
— a silent skip would connect a block whose emission paid without marking `E`.

### 6.3 The prune-resurrection double-mint — the journal is mandatory, not hygiene

The connect mutation is **insert `E` + prune entries below the window floor**
(`claimed_epochs.rs:114–116`), and the floor keys on `current_settled_epoch` —
**a quantity that is non-monotonic under reorg.** Verified at source: the
epoch-close revert **definalizes `E`** when its boundary block pops
(`ARCHIVAL_CONSENSUS_STATE.md:224–239`, "a pop sequence removes all of them
before `revert_archival_epoch_close_at_height` definalizes `E` at
`h_close(E)`"). The failure is therefore **not** a bit-identity blemish; it is
a **double-mint**, the same priority-1 supply-violation class as the WS-1
keystone:

1. `E_old` is claimed and its reward **mints** (block long since connected).
2. A later claim of `E_new` connects in a boundary-crossing region; its
   `check_and_set` prunes `E_old` at the then-current window edge
   (`E_old < floor(S)`).
3. A pop spanning the boundary definalizes a settled epoch → `S′ < S` → the
   floor lowers → **`E_old` re-enters the claim window** (a one-block pop past
   a boundary suffices: `E_old = floor(S) − 1 ≥ floor(S−1)`).
4. Under the naive inverse ("remove the inserted `E`"), `E_old` is absent from
   the restored set → a fresh emission claiming `E_old` passes dedup → **the
   reward mints twice.** (The module's own prune-safety note — reorg depth
   720 ≪ epoch length 10 000 — answers pruned-entry *claimability at tip*,
   not resurrectability under a floor-lowering pop; and `:224–239`'s
   no-stranded-emission argument covers citing emissions above `h_close`,
   not the pruned dedup state.)

**Disposition (RATIFIED): journaled revert, inheriting the slash-log
precedent — and the journal row is pinned as the pre-image delta, one unit:
`{inserted E, evicted set members}`.** A journal that reverses only the insert
still leaves the pruned-already-claimed `E_old` gone and the double-mint alive
— the *point* of the journal is restoring what the prune removed. The slash
path already carries full pre-image revert rows (`m_archival_slash_log`,
"BE(height)‖BE(seq) → revert journal", `db_lmdb.h:694`;
`revert_archival_slashes_at_height` in the pop path, `blockchain_db.cpp:478`);
the emission journal rides the same idiom, keyed by height, restored exactly on
disconnect. One reorg mechanism, many tables — the same O-3 inheritance §5.5-3
uses for the serve-credit bits. (`first_paying_emission_height`, set-once per
`shekyl_types.h:614–619`, rides the same journal row: unset on pop iff this
emission was the setter.)

### 6.4 Armed KATs

1. **Same-block double-claim KAT (the double-mint trigger).** Two txs from the
   same `P`, overlapping claimed epoch `E`, same block → block **rejected** by
   the `(P,E)` pass. The direct regression test on the straddle.
2. **Cross-block double-claim KAT.** `E` claimed at height `h`; a second claim
   of `E` at `h' > h` → tx rejected at verify (`claimed_epochs_contains`
   against the connected bond record).
3. **Prune-straddle double-mint KAT (the journal's load-bearing case — a
   property test, not a mechanism test).** Claim `E_new` in a
   boundary-crossing block whose connect **prunes** the already-claimed
   `E_old`; pop past the boundary (floor lowers, `E_old` re-enters the
   window); submit a fresh emission claiming `E_old` → **rejected**
   (`Ok(false)` / vin-reject). Byte-identity of the restored
   `claimed_settlement_epochs` (and `first_paying_emission_height`) is
   asserted as a corollary, but "no second mint of `E_old` post-reorg" is the
   property — it is the assertion the naive remove-inverse fails (§6.3 step
   4) and the reason the journal exists.

### 6.5 Reopening (rule 21)

- **Prune-against-finalized retires the journal** — reopens iff a
  **reorg-immune finalized settled epoch becomes a first-class quantity
  plumbable to the prune site** (e.g. a checkpoint/finality boundary lands
  for other reasons). The §6.3 root cause is that the prune keys on the tip
  settled epoch, which is non-monotonic under reorg; pruning against a
  reorg-immune floor instead would make the resurrectable state
  **unrepresentable** (the prune only ever evicts epochs no legal reorg can
  bring back into the window), the naive remove-inverse becomes correct, and
  the journal, its bond-record row, and its KAT all retire. **Rejected now**
  because the invariant it needs does not currently exist: settled epochs
  themselves definalize under reorg (`ARCHIVAL_CONSENSUS_STATE.md:224–239`),
  so "finalized settled epoch" is not reorg-immune without a hard *enforced*
  reorg-depth limit — and none is plumbed to the prune site
  (`claimed_epochs_check_and_set` receives only `current_settled_epoch`,
  `claimed_epochs.rs:99`; `ARCHIVAL_REORG_DEPTH_BLOCKS` = 720 is a wallet-side
  scan-ceiling constant, not a consensus pop bound). The journal is correct
  for **any** reorg depth; prune-against-finalized is correct only up to a
  bound it would newly depend on — in a priority-1 double-mint context,
  self-contained-and-depth-independent beats clever-but-coupled.
  **Re-evaluation shape:** design round of the PR that lands the finality
  boundary, with the §6.3 straddle re-run against the new floor.
- Reopens iff a **second claimer** of `claimed_settlement_epochs` appears (any
  vin type other than the emission vin writing the set): the block pass is
  scope-bounded to emission vins and must widen to the union of writers, or the
  intra-block window reopens between claimer types.
- Reopens iff per-tx verify is ever made **order-dependent within a block**
  (option-1 shape) — which *first* reopens the Q7 pure-function pin (§5.5);
  WS-2 cannot flip to option 1 without the keystone reopening ahead of it,
  the same dependency shape as Q3's arity coupling (§2.1).
- The window constants (`MAX_CLAIM_AGE_W = 26`, cap 32, reorg depth 720 ≪
  epoch 10 000) are load-bearing for the prune-safety argument; the
  `claimed_epochs.rs:39–43` const assertion is the armed guard, and a change
  to any of the three re-runs §6.3's double-mint straddle analysis in its own
  PR.
**Re-evaluation shape.** Design-round 1 of the PR introducing the second
claimer / the ordering change / the constant move, with this section's
straddle analysis re-run at source.

---

## 7. Round status

- **Q3** — RESOLVED (vacuous at arity 1).
- **Q12 / F-E8** — RESOLVED (foreclosed by wire positivity + zero-tolerance recompute).
- **Q11 / F-E7** — **RATIFIED: ACCEPT** — with the backing-pseudo-out
  balance-exclusion arming KAT as its reopen (§2.2).
- **WS-1 (Q10 → M-2 → Q7)** — **RATIFIED: M-2 closes under bits-sourcing ∧
  as-of-fire-height acceptance (§5.4, the conjunction); one shared
  `as_of_E_served_work` sourcing function both sides; `held_shard_ids` out of
  the work-channel type; one `at_height` accessor with two consumers
  (`:4307` acceptance + `:5270` slash-eligibility); reorg-symmetry inherited from
  M1 O-3 with the no-refcount↔dedup coupling armed (§5.7); three armed KATs
  (§5.6, reorg KAT pins the composition).** The supply-conservation keystone,
  the one obligation with no backstop under it (§5.5). Corrects the Round-2
  Q10/M-2 closure.
- **WS-2 (Q9 / F-E3)** — **RATIFIED (§6), with a severity upgrade:** three
  dedup layers (wire strictly-increasing landed; **block-level `(P,E)`
  uniqueness pass** mirroring the landed `:4882` serve-credit idiom; per-tx
  contains-check at verify + connect `check_and_set` single writer). Option 1
  (intra-block write-visibility) rejected on Q7 pure-function coherence.
  The prune-straddle is a **double-mint** (the floor keys on
  `current_settled_epoch`, non-monotonic under reorg — a pop resurrects a
  pruned already-claimed epoch into the window), so claimed-set
  reorg-symmetry is via **journaled revert** with the row pinned as the
  pre-image delta `{inserted E, evicted members}` as one unit (slash-log
  idiom); three armed KATs (§6.4, the prune-straddle KAT asserts re-claim
  **rejection**, the property, not byte round-trip, the mechanism);
  prune-against-finalized recorded as the rule-21 reopen that retires the
  journal (§6.5). **The round's design work is complete.**

### 7.1 Next action — PR-E3 implementation pre-flight (re-pin to current `dev`)

All design on the leg is ratified (Q3/Q12 resolved, Q11 accepted, WS-1 and
WS-2 ratified); the full §3 build list is unblocked. The PR-E3 implementation
pre-flight opens against the §3 build list and **runs against the current
`dev` head, not the `1f67652b0` round pin** — `dev` has already moved to **`90e790c9c`** (twice mid-round in
this arc; the WS-2 closure's operands were re-verified at `90e790c9c` and the
delta was CI/CHANGELOG-only, §6). The **§11.1 pattern — read every operand at
its production site** — is precisely what turned the last two "closed" premises
(PR-E2's landed-not-open state; Q10's descriptor-vs-bits conflation), so the
pre-flight re-verifies the §3 file:line anchors (`consensus_state.rs:386–389`,
`:4307`, `:5270`, `:4882`, `blockchain_db.cpp:224`/`:586`,
`claimed_epochs.rs:99`, `shekyl_types.h:613`, `archival_serve_credit`) at the
branch head before the build lands. **Executed in §8.**

---

## 8. PR-E3 implementation pre-flight — anchors confirmed at `dev` `90e790c9c`

Run 2026-07-07, after round closure. `origin/dev` fetched and confirmed
**unmoved at `90e790c9c`** (the head the WS-2 operands were already
re-verified against). Every §3 operand read at its production site at that
commit — all **confirmations**, no discoveries, plus one path correction:

| §3 item | Operand | At `90e790c9c` |
|---------|---------|----------------|
| 1(b) deletion target | `held_shard_ids` filter | **Present** at `consensus_state.rs:386–389` (`.held_shard_ids.contains(&shard.shard_id)` inside the `credit_pairs` loop at `:381`) — the WS-1 build removes the field from the work-channel input type |
| 1(c) consumer 1 | serve-credit acceptance gate | `blockchain.cpp:4307` — `archival_bond_holds_shard(p, shard, h_fire)`, `h_fire` passed |
| 1(c) consumer 2 | slash eligibility | `db_lmdb.cpp:5270` — forwards `h_fire` to the same accessor |
| 1(c) defect site | tip accessor | `db_lmdb.cpp:4975–4976` — parameter literally `uint64_t /*at_height*/` (ignored) |
| 1(d)/§5.7 coupling | duplicate-bit guard | `blockchain.cpp:4247` — `has_archival_serve_credit_bit` reject |
| 3a block-pass idiom | serve-credit cross-tx pass | `blockchain.cpp:4880–4886` — `block_serve_credits` set over `txs`, the mirror template |
| 3a single writer | `check_and_set` | `claimed_epochs.rs:99` — signature `(set, epoch, current_settled_epoch)`; prune-on-insert at `:114–116` (`set.retain(|&e| e >= window_floor)`) |
| 3a journal substrate | claimed set + set-once height | **`src/blockchain_db/shekyl_types.h`** `:613` / `:619` — *path correction: the file is `src/blockchain_db/`, not `src/cryptonote_basic/`; line anchors unchanged* |
| 3a revert slot | pop-path revert order | `blockchain_db.cpp:478–480` — `revert_archival_slashes_at_height` → `revert_archival_epoch_close_at_height` → `remove_block()`; the emission-claim journal revert slots into this per-height sequence |
| 1(d)/§5.6 KAT 3 | bit set/remove symmetry | `blockchain_db.cpp:224` (connect set) / `:586` (disconnect remove) |

**Build order** is §3's dependency order: item 1 (WS-1 sourcing: accessor +
`as_of_E_served_work` + field removal + 3 KATs) → item 2 (snapshot struct) →
items 3/3a (verify body + dedup plumbing + journal + 3 KATs), with item 4
(C-1 activating cut) and item 5 (E4/E5 deletions) as separate PRs per their
own gates. Test gates per `45`/`50`: `cargo fmt --check`, `clippy -D
warnings`, workspace tests, plus the six armed KATs (§5.6 + §6.4) and the
Q11 balance-exclusion KAT (§2.2). Implementation proceeds on fresh
short-lived branches off `dev` per `06-branching.mdc`; this round branch
carries docs only.
