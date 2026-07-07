# Reward-emission E3 gating round — pre-flight audit + policy-trio closure

**Status:** Round 3 — policy trio + **Q10/M-2 held-sourcing (§5, reopened by
source audit)** — **open for ratification** (2026-07-07).
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
   descriptor. This is a sourcing + accessor decision, the supply-conservation
   hard blocker.
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
| **M-2** numerator as-of-E sourcing | **design closed *conditional on bits-sourcing* (§5).** `R_market(s,E)`/`Σwork(E)` are frozen-persisted (invariant 2). The `held(P,E)` term is sound-as-written **only if** sourced from the per-`(P,s,E)` serve-credit bits, **not** the mutable bond descriptor — the Round-2 "snapshot field set (B)" framing omitted this and is corrected in §5 | `consensus_state.rs` `EpochCloseResult`; `market_member_at_epoch:98`; `archival_serve_credit` bit table |
| **Q10 / F-E6** `held(P,E)` frozen-at-E | **CORRECTED (§5): not a marshaling pin — a sourcing correction + accessor build.** The "as-of-E interval marshaling" framing conflated **standing** (`bad_intervals`, genuinely interval/as-of-E) with **held** (no interval log; the `held_shard_ids` descriptor is tip-mutable — the documented M2-1 defect at `db_lmdb.cpp:4984–4990`). As-of-E held ground truth = the serve-credit bits; the `at_height`-honoring read is **Open** (FOLLOWUPS P2B-7 Pin 4) | `good_through` straddle-close (`consensus_state.rs:84–92`) is the **standing** half; held half in §5 |

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

On trio **and §5 WS-1** ratification, WS-2 (§6 dedup plumbing) is the only design
item left; everything below is implementation, in dependency order (the verify
body's dedup step, item 3, additionally awaits WS-2):

1. **`held(P,E)` as-of-E sourcing — the WS-1 build item (§5, corrects §8.0's
   "one build item").** Source the `work_P(E)` shard set from the per-`(P,s,E)`
   serve-credit bits (`archival_serve_credit`, keyed
   `ArchivalServeCreditKey(P,shard,E)`), **not** the mutable `held_shard_ids`
   descriptor. Two concrete pieces: **(a)** drop the descriptor `held_shard_ids`
   filter from `epoch_close_compute`'s work loop (`consensus_state.rs:386–389`)
   — it is redundant with the credit bits as-of-E (§5) and actively wrong under
   mid-life drop; **(b)** the verify gather does a **point read** of the
   `(P,s,E)` bits at the claimed `E` (they are keyed by `E` — no reconstruction),
   marshaled by value. **Standing** stays as-is: `bad_intervals` + `join` →
   `market_member_at_epoch` (`consensus_state.rs:98`) is genuinely as-of-E. The
   `at_height`-honoring hold read remains **Open** (FOLLOWUPS P2B-7 Pin 4) and
   co-designs with the V3.0 mutable-holdings read rule so verify and the
   serve-credit-window membership check share one bit source.
2. **M-2/Q7 as-of-E snapshot struct.** Marshaled by value, each field from the
   frozen E-close materialization (invariant 2: `R_market(s,E)`, `Σwork(E)`,
   shard `freeze_height`) **plus** the per-`(P,s,E)` serve-credit bits for the
   claimed epoch (the §5 held source); never the live bond descriptor; carries
   the two Q1 auth fields.
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

### 5.4 Disposition — source `work_P` from the bits; retire the descriptor

**PROPOSED (consensus sourcing rule; priority-1, awaiting ratification):**
`work_P(E)`'s held-and-served shard set is sourced from the per-`(P,s,E)`
serve-credit bits (`archival_serve_credit`), never from `held_shard_ids`. Two
concrete changes:

1. **Drop the descriptor filter** at `consensus_state.rs:386–389`
   (`held_shard_ids.contains(shard.shard_id)`). It is redundant with the credit
   bits as-of-E (§5.3) and *actively wrong* under mid-life drop — at close it
   under-counts a shard served-then-dropped within `E`; on verify the tip read
   compounds the error. Work is already gated by `credit_pairs`; the credit bit
   is the correct and sufficient gate.
2. **Verify gather = point read of the `(P,s,E)` bits at the claimed `E`** (keyed
   by `E`; not a bond-history reconstruction), marshaled by value into the M-2
   snapshot (§3 item 2). Standing continues via `bad_intervals` + `join`.

**Reorg-symmetry.** Already satisfied — the bits set/remove on connect/disconnect
(`blockchain_db.cpp:224`/`:586`); the marshaling reads bits, never the descriptor,
so it inherits the symmetry. No new schema, no new revert path.

**Q7 falls out.** With the frozen values being the bits + invariant-2 snapshot,
Q7 is "extend the epoch-close snapshot-marshal idiom to the verify path"
(`archival_ffi.rs:346` house pattern) — resolved, as Round 2 held, but now over
the *correct* source.

**Coupling (do not build twice).** The `at_height`-honoring hold read is Open
(FOLLOWUPS P2B-7 Pin 4) and is the same as-of-E question the serve-credit-window
membership check faces under mutable holdings. Emission-verify held-sourcing and
that membership check **must share one bit-sourced accessor**; co-design in the
bond-lifecycle connect-path work, not a duplicate emission-only reader.

**Reopening (rule 21).** Reopens iff (a) a serve-credit bit can be set for a
shard `P` did **not** hold as-of-E — i.e., the §5.3 segment-path binding is ever
weakened so `credit ⇏ held` (then the descriptor filter, or a dedicated held
interval log, returns as a real requirement); or (b) `work_P` is redefined to
count held-but-**unserved** shards (none such today — work requires credit). The
descriptor `held_shard_ids` remains load-bearing for *current-membership*
questions (bond-floor, gate-4 connect) and is not deleted, only removed from the
as-of-E work path.
**Re-evaluation shape.** Design-round 1 of the PR that weakens the segment-path
binding or redefines `work_P`'s shard predicate, with the credit-implies-held
proof re-examined at source.

---

## 6. WS-2 — Q9/F-E3 dedup atomicity (parallel; open)

Independent of WS-1 (different mechanism; shared only in the PR-E3 verify/connect
split). Recorded here as the second open surface; its detailed pin is its own
closure.

**The function is not where the bug is.** `claimed_epochs_check_and_set(&mut set,
…)` (`claimed_epochs.rs:99`) is atomic on its *passed-in* set and correctly
returns `Ok(false)` on the second call for the same epoch (its own tests,
`:137–138`). The double-mint is in the **plumbing**: the set is loaded from LMDB
at verify-time and written back at connect-time, so two same-block emissions from
the same `P` claiming the same `E` both load the same pre-state set, both
check-and-set their own copy, both see `E` unset, both commit.

**Two structural options** (the plan's §8 pair), to be settled in WS-2's closure:
(1) the set is applied within the connecting tx's LMDB scope so tx2 sees tx1's
mark; or (2) an explicit block-level `(P,E)` uniqueness pass across all emission
vins before connect. Both are tx-scoping designs, not sourcing ones — hence
parallelizable with WS-1.

---

## 7. Round status

- **Q3** — RESOLVED (vacuous at arity 1).
- **Q12 / F-E8** — RESOLVED (foreclosed by wire positivity + zero-tolerance recompute).
- **Q11 / F-E7** — **PROPOSED: ACCEPT** — awaiting ratification (consensus-acceptance-path).
- **WS-1 (Q10 → M-2 → Q7)** — **PROPOSED: source `work_P` held-set from the
  per-`(P,s,E)` serve-credit bits; retire the descriptor filter (§5.4)** —
  awaiting ratification (consensus sourcing rule; the supply-conservation hard
  blocker). Corrects the Round-2 Q10/M-2 closure.
- **WS-2 (Q9 / F-E3)** — OPEN, parallel; two options enumerated (§6), own closure.

On Q11 **and** WS-1 ratification, the leg's remaining open design is WS-2 (dedup
plumbing). PR-E3 body items depending on WS-1 (held-sourcing, §3 items 1–2) are
ratified; the verify body (§3 item 3) additionally depends on WS-2's closure for
the dedup step. Next action after ratification: close WS-2, then open the PR-E3
implementation pre-flight against §3's build list.
