# V3.1 Multisig — Rust engine integration design

**Status.** **Round 1 OPEN — cannot close (2026-07-14 adversarial
review).** Doc-only design branch `docs/v31-multisig-rust-engine-plan`.
This document is the **engine-integration** carrier for V3.1 multisig
(**Track B**) and the **finding ledger + Track A split** for
pre-genesis **consensus wire** defects that the Round 1 review
surfaced. Protocol crypto remains
[`PQC_MULTISIG.md`](../PQC_MULTISIG.md) (DRAFT v1.1).

**Verdict (Round 1 adversarial, verified locally).** The eight MS leans
are mostly defensible for Track B. Round 1 **still cannot close**:
§2.3's opening substrate table omitted always-compiled consensus
surfaces and a coexisting FROST lineage, which inverted **MS-8** and
falsified the safety rationale behind Hard Scope Pin #2 (feature gate
protects wallet orchestration only — not `PQC_MAX_*_BLOB` bounds).

**F-2 retraction (2026-07-14, same reviewer, pin `b23cdaff0`).**
Changing the leaf preimage is **not** free and **not** needed:
cross-scheme confusion is already impossible by **prefix
disjointness** (`reserved == 0` ⊥ `m_required ≥ 1` at byte[2]), with
length as a second separator. Track A shrinks to a constant-family
correction + KATs + misattribution fixes. Leaf preimage **left alone**.

**Process.** Cites
[`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md) and
[`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc).
**Halt condition (Track B only):** no Track B implementation commits
until design closure **and** the named pre-flight pass discharge.
**Track A** (V3.0 wire bounds) is **not** held by that halt — F-1 is
a fund-loss deserialize ceiling lying about an existing container —
but still requires an **explicit implementation go-ahead** (separate
short-lived branch off `dev`).

**Trigger fired.**
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
§10.3.1 (2026-07-14).

**Identifier families (rule 94).**

| Family | Owns |
| --- | --- |
| **MS-1…MS-N** | Track B engine-integration Round 1 questions |
| **MSW-1…MSW-N** | Track A V3.0 pre-genesis multisig **wire** work (revised): bound-family reconcile + cross-seam KAT + scheme-disjointness pin + misattribution fix; **not** a leaf-preimage change |
| **R1-F-N** | Round 1 adversarial findings (doc-scoped; this file) |

Prefix `MS` / `MSW` uniqueness: registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2.

**Pin discipline (R1-F-10 — accepted).** Verification pins are
**`dev`-at-time-of-recording**, not "this branch tip." Design-branch
HEAD diverges immediately. Re-pin at Round 0 / Track A pre-flight.
§2.3 rows name the pin they were verified against.

| What | Pin |
| --- | --- |
| Design branch opened | `dev` = `13bd508c7` (2026-07-14) |
| Round 1 adversarial verification (reviewer) | `dev` = `b23cdaff0` (2026-07-14; +9 archival commits, no multisig surface move) |
| Local re-check of R1-F-1 arithmetic + F-2-retraction prefix layout | this design-branch tree |
| F-2 retraction / blast-radius / size Q&A | reviewer pin `b23cdaff0` (2026-07-14) |

---

## §0 Structural disposition — Track A / Track B split

Accepted from Round 1 adversarial review (2026-07-14), **revised**
same day after F-2 retraction + blast-radius / size Q&A.

### Track A — V3.0 pre-genesis wire (**revised: constant fix, not design change**)

Always-compiled deserialize / verify ceilings. Ship whether or not
`multisig` flips. **No Track B design-round debt.** **No wallet /
engine / archival / emission-wire contact** for the bound fix (F-1
consumer set is config + wire + two verify sites + two symbolic
negative tests). Curve tree / leaf size **unaffected** (`h_pqc` is
always 32 bytes).

**Nothing gets bigger.** A 7-of-7 key container has always been
14,199 bytes (`expected_blob_len`); the bound was written for a
pre-V3.1 two-byte-header container. F-1 raises
`13,974 → 14,199` (and the sig twin) so the ceiling stops rejecting
the artifact it claims to describe.

One validation surface (rule 19):

| ID | Work |
| --- | --- |
| **MSW-1** | Reconcile `PQC_MAX_PUBLIC_KEY_BLOB` / `PQC_MAX_SIGNATURE_BLOB` / `MULTISIG_KEY_HEADER_LEN` against `MultisigKeyContainer::expected_blob_len` / sig layout. Single-source across `cryptonote_config.h` / `shekyl-wire` / `shekyl-crypto-pq`; **delete** the `tx_pqc_verify.cpp:49-52` local shadow (and keep `submit/verifier.rs` in lockstep — R1-F-8). Cross-seam KAT: every `n ∈ 1..=MAX_MULTISIG_PARTICIPANTS` real container round-trips **both** deserializers. |
| **MSW-2** | **Pin scheme-disjointness as a load-bearing consensus invariant** (doc + KAT): no byte string parses as both `HybridPublicKey::from_canonical_bytes` and `MultisigKeyContainer::from_canonical_bytes`. **Primary separator today: length** (1996 ∉ `{3+n·2028}`). **Secondary / header-level:** byte[2] scheme-1 `reserved == 0` ⊥ scheme-2 `m_required ≥ 1`. **Leaf preimage left alone.** Rule-21 reopen: any use of `reserved`, any `MULTISIG_CONTAINER_VERSION` bump, any new scheme id / V4 lattice container (must re-prove length non-collision too). |
| **MSW-3** | Fix `"output committed="` misattributions (`tx_pqc_verify.cpp:191-192`, `tx_pqc_verify.h:30-31`) — consumer is intra-tx `pqc_auths[0]` consistency (`blockchain.cpp:4260`), not output binding. Record **MS-8 retirement**: `group_id = f(key_blob)` already leaf-bound; wiring `shekyl_pqc_verify_with_group_id` is a no-op. |

**Genesis-adjacent (not MSW code, but answer before seal):** whether
`MAX_MULTISIG_PARTICIPANTS = 7` is the right frozen number given
full-reward-zone economics (8×7-of-7 `pqc_auths` alone ≈ 303 KiB vs
`CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 = 300_000`). Track as
**MSW-G** decision / sim input — may lower `MAX` before genesis;
does **not** reopen leaf preimage.

### Track B — V3.1 engine (MS-1…MS-7, gated, unhurried)

Feature-gated wallet orchestration. Rule-26 halt remains correct
**here**. Round 1 closure prerequisites: **R1-F-3…F-7** (+ F-6 CI).
**MS-8 retired** (redundancy; independent of leaf-preimage choice).

**Size / fee items belong here (not Track A):**

- Fee model is scheme-1-only (`tx_fee_model.rs:151-158`
  `pqc_auth_weight`) — underpays multisig → R-B / MS-5.
- `v31` `MAX_INPUTS = 128` vs consensus `FCMP_MAX_INPUTS_PER_TX = 8`
  — bad-states-representable → R-C / intent type.
- Per-input wire size table (2-of-2…7-of-7) informs fee + UX, not
  the tree.

### Hard scope pins (amended 2026-07-14; pin-2 revised after F-2 retraction)

1. **No Track B production code on this branch** until design closure
   + pre-flight + explicit go-ahead.
2. **Feature gate protects wallet orchestration only.** It does
   **not** protect `PQC_MAX_*_BLOB` (always-compiled; **R1-F-1**).
   Cross-scheme leaf safety is prefix-disjointness (**MSW-2**), not
   the feature gate. Default packages still must not enable
   `multisig`.
3. **Rust owns new wallet multisig logic.** C++ = LMDB / chain-DB +
   verify FFI. **Existing** `wallet2` PQC multisig group surface
   (`create_pqc_multisig_group`, `m_pqc_multisig_*`,
   `shekyl_pqc_multisig_group_id` at `:9828-9852`) is acknowledged
   substrate — MS-2 forbids *thickening* it; deletion/migration is
   Phase 5 / rewrite fodder, not Track A.
4. **Archival out of scope** for Track B (and for revised Track A).
5. **Track A (revised)** lands off `dev` on `feat/msw-*` when
   go-ahead is given — not held behind Track B rounds.

---

## §0.1 Round 1 adversarial findings (R1-F-N)

Reviewer verification pin: `dev` = `b23cdaff0`. Local arithmetic /
path confirmation on this branch. Disposition column is **this
design's acceptance**, not implementation.

| ID | Sev | Finding (one line) | Disposition |
| --- | --- | --- | --- |
| **R1-F-1** | CRITICAL | `PQC_MAX_*_BLOB` uses fossil `2+N·LEN`; V3.1 container is `3+n·2028` / `1+M·3385+M`. **N=7 (and M=7) unserializable** at deserialize. Fund-loss: output can land; spend never parses. Bound raise is a **correction** (container already that size), not growth. Consumers: config + wire + verify shadows + two symbolic tests — **zero wallet/engine/archival**. | **Accepted → MSW-1.** |
| **R1-F-2** | CRITICAL → **retracted as leaf change** | Original: change leaf preimage / treat length as sole cross-scheme separator. **Retraction:** leaf is shared scheme-1+2; changing it touches wallet2 receive, blockchain verify×3, emission Auth-B, stake_engine, FFI C ABI, test vectors, submit verifier — emission-wire risk. Cross-scheme confusion already impossible by **byte[2] prefix disjointness**; length is second separator. MS-8 still redundant. Dual `DOMAIN_PQC_LEAF` remains hygiene debt (not Track A blocking). | **Leaf change REJECTED.** **MSW-2 = disjointness invariant doc+KAT.** **MS-8 RETIRED** (redundancy). Misattribution fix → MSW-3. |
| **R1-F-3** | HIGH | Coexisting FROST **coordinator** lineage under same `multisig` gate (`multisig/{dkg,group,signing}.rs`) vs coordinator-less `v31/`. | **Accepted.** Round 1 closure prerequisite: name fate (delete vs `frost-sal-v4`-only vs quarantine). Blocks MS-1/MS-3/MS-5. |
| **R1-F-4** | HIGH | Two `group_id` defs: deterministic `multisig_group_id` vs caller-supplied `dkg.rs` context. | **Accepted.** Round 2 / F-3 co-dispose: one canonical type; delete or newtype the other. |
| **R1-F-5** | HIGH | `MultisigGroup` Serialize hex of secrets; un-zeroized `Vec` reassign; not a `WalletLedger` extension — falsifies "confirm R6". | **Accepted.** MS-7 lean **withdrawn**; R6 re-opened against actual shape. |
| **R1-F-6** | HIGH | No CI job builds `--features multisig`. Gate armed, no positive compile trigger. | **Accepted.** **Prerequisite for Round 1 closure:** CI lane `check/clippy/test` for engine-core + engine-rpc + ffi with `--features multisig`. |
| **R1-F-7** | MEDIUM | §3.1 "associated items only on multisig kind" is a compile error; `EngineSignerKind` has zero associated items; marker is aspiration. | **Accepted.** Correct framing: first associated item = trait-surface amend touching `SoloSigner` (`SigningCeremony = Infallible`). |
| **R1-F-8** | MEDIUM | Second verify site + five independent bound defs; folds into MSW-1 lockstep + MSW-3 misattribution. | **Accepted → MSW-1/MSW-3.** |
| **R1-F-9** | MEDIUM | FROST `sign_own` nonce-reuse; unauthenticated `participant` claims. | **Accepted.** Evaporates if F-3 deletes lineage; else hard gates before compile-into-product. |
| **R1-F-10** | LOW | Pin discipline: `dev`-at-recording ≠ branch tip. | **Accepted.** Banner + this table. |

### Wargame table (accepted)

| # | Adversary | Armed at source? |
| --- | --- | --- |
| A1 | N=7 output lands; spend never serializes | **No** — R1-F-1 |
| A2 | Present scheme-2 blob against scheme-1 leaf (or reverse) | **Armed by construction** — byte[2] `reserved==0` ⊥ `m_required≥1` (+ length). Original "length only" claim **retracted**. Guard with MSW-2 KAT. |
| A3 | Spender lies about `group_id` | **Vacuous** — already in leaf; MS-8 retired |
| A4 | Mix scheme 1/2 across inputs | Self-referential intra-tx only |
| A5 | Malicious DKG steers `group_id` | **No** — R1-F-4 |
| A6 | Replay `sign_own` / nonce reuse | **No** — R1-F-9 |
| A7 | Forge FROST `participant` index | **No** on FROST lineage |
| A8 | Flip ships never-compiled code | **Wrong-direction gate** — R1-F-6 |

**A2 + MSW-1:** raising bounds does **not** remove length disjointness
(1996 ∉ {2031…14199}); MSW-2 KAT remains belt-and-suspenders after
MSW-1. No leaf change.

---

## §0.2 Independent code audit of the findings (maintainer/agent)

Reviewed against this tree (same formulas as pin `b23cdaff0` for
multisig surfaces). Disposition: **confirm / sharpen / push back**.

### R1-F-1 — **CONFIRMED**

- `expected_blob_len(7) = 14199`; `PQC_MAX_PUBLIC_KEY_BLOB = 13974`
  (`cryptonote_config.h:290`, `shekyl-wire` twin). Sig twin:
  `23703 > 23697`. Arithmetic matches the review.
- Reject site is deserialize (`cryptonote_basic.h:458`), before verify.
- **"Correction, not growth"** holds: container layout already encodes
  14199; the ceiling was written for a pre-version/`spend_auth`
  formula.
- Local shadow `MULTISIG_MAX_KEY_BLOB = 2 + 7*1996` in
  `tx_pqc_verify.cpp:50-52` is the **same fossil**, and is wrong in
  *two* ways (header claimed as `n‖m` only — omits `version`; max
  omits `n·32` spend-auth). A naive "fix" of `3 + 7*1996 = 13975`
  would **still** reject N=7. MSW-1 must single-source
  `expected_blob_len` / the sig twin, not invent a third formula.
- Fund-loss shape holds: creating a payment *to* a multisig address
  does not put the key container in the creator's `pqc_auths`; the
  spend does. Output can land; spend fails to parse.

### R1-F-2 / leaf change — **RETRACTION HOLDS; byte[2] oversold**

- **Leaf change not needed / not free:** confirmed. `PqcLeafScalar`
  hashes raw `pqc_pk` bytes for scheme 1 and 2; retargeting the
  preimage is a cross-cutting ABI/vector/emission Auth-B change.
- **Dual-parse of one byte string as both `HybridPublicKey` and
  `MultisigKeyContainer` is already impossible by length alone:**
  solo is exactly 1996; scheme-2 lengths are `3+n·2028`
  (`2031…14199`). No integer `n` yields 1996. Both parsers require
  exact length (`cursor == len` / `expected_blob_len`).
- **Byte[2] `reserved==0` ⊥ `m_required≥1`:** real as a *header-level*
  check when a solo key blob is fed to `MultisigKeyContainer::from_canonical_bytes`
  (`bytes[2]==0` → `m_required==0` reject at `multisig.rs:120`). It is
  **secondary** to length for the actual parsers. Calling it "the"
  separator overstates; MSW-2 is still worth pinning as a rule-21
  invariant (reserved must not gain meaning; container version bumps
  must re-prove non-collision), not as the sole A2 defense.
- **A2 (lie about `scheme_id`):** with leaf-bound bytes, scheme-1
  verify requires `len==1996`; scheme-2 requires a container parse.
  Cross-scheme auth fails at length/parse without a leaf change.
  Blockchain comment that scheme binding "relies on the leaf hash"
  (`blockchain.cpp:4251-4253`) is imprecise — the leaf binds **bytes**;
  scheme is enforced by how those bytes parse under `scheme_id`.

### MS-8 retirement — **CONFIRMED**

`verify_multisig` check 9 recomputes `multisig_group_id(container)`
from the same blob the leaf already commits. Optional
`expected_group_id` cannot add binding the leaf lacks. Redundancy
argument does **not** depend on changing the leaf.

### Reward-zone / `MAX=7` — **MATH CONFIRMED; rhetoric trim**

- Per-input 7-of-7 `PqcAuth` ≈ **37911** bytes (header + varints +
  14199 + 23703). `8 * 37911 = 303288 > 300000`
  (`CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5`). Correct.
- Prefer: "a single legal maxed multisig spend **exceeds the
  penalty-free zone by itself**" over "unprofitable to mine" (penalty
  ≠ necessarily unprofitable once fees are counted).
- Corner case (8-in × 7-of-7), but still a fair **MSW-G** genesis
  question.

### Fee model / `MAX_INPUTS` — **CONFIRMED (Track B)**

- `pqc_auth_weight()` hardcodes solo lengths
  (`tx_fee_model.rs:151-158`).
- `v31/intent.rs MAX_INPUTS = 128` vs `shekyl_fcmp::MAX_INPUTS = 8` /
  `FCMP_MAX_INPUTS_PER_TX`. Note: `cryptonote_config.h:200-207`
  comments about intent.rs/`build.rs` sync refer to **reference-block
  age** constants, **not** this 128 — so 128 is real drift, not a
  synced authority.

### `wallet2` PQC multisig surface — **CONFIRMED**

`create_pqc_multisig_group` / `m_pqc_multisig_*` at
`wallet2.cpp:9828-9852` uses `shekyl_pqc_multisig_group_id` (correct
derivation). MS-2 "don't thicken" stands; §2.3 must not claim C++ has
no multisig surface.

### R1-F-3…F-7, F-6 CI — **not re-litigated here**

Still Round 1 closure blockers for Track B; this audit focused on the
Track A / F-2 / size claims that decide whether Track A is a constant
fix.

**Net:** proceed with **revised Track A** as documented in §0. Record
MSW-2 as invariant+KAT with the sharpened "length primary, prefix
secondary" wording. Do not reopen leaf preimage.

---

## §1 Mission posture

Per [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc):

| Priority | How this design touches it |
| --- | --- |
| **1 — Security** | **Track A first (revised):** correct lying deserialize ceilings (F-1); pin prefix-disjointness (MSW-2). **Not** a leaf-preimage cut. Track B: threshold authority, DKG secrets, wipe-on-drop (`35`/`36`), honest-signer invariants. |
| **2 — Privacy** | Track B receive path (Option C / FA-6b). Spend must not weaken FCMP++ vs solo. |
| **3 — System longevity** | Feature-gated V3.1; Stage 4 swap-in; V4 FROST-SAL only after F-3 names the in-tree FROST lineage's fate. |

**Three timeframes.** Now: Track A bound correction + disjointness
KAT before genesis; **MSW-G** on whether `MAX=7` survives reward-zone
math. V3.1: Track B behind `multisig`. V4: lattice container must
re-prove MSW-2 reopen criteria.

---

## §2 Scope

### §2.1 In scope

**Track A (this doc owns the finding → MSW map; implementation is a
separate go-ahead):** MSW-1, MSW-2, MSW-3.

**Track B:** MS-1…MS-7 (MS-8 retired); map protocol onto engines;
Rust-owns-logic; feature-gate discipline; Phase 0 doc amends after
rounds close.

### §2.2 Out of scope / deferred

| Item | Carrier |
| --- | --- |
| Protocol crypto redesign | `PQC_MULTISIG.md` |
| Cryptographer / external wargame (protocol Phases 5–6) | FOLLOWUPS; after enough surface |
| Headless co-signer / HW wallet / GUI | FOLLOWUPS / sibling repos |
| Archival | Separate |
| Enabling `multisig` in release packages | Named flip PR |
| Wiring `shekyl_pqc_verify_with_group_id` as the primary fix | **Retired** (MS-8 redundancy); do not schedule as ship-gate |
| Changing `DOMAIN_PQC_LEAF ‖ …` preimage | **Rejected** (F-2 retraction); not free, not needed |

### §2.3 Substrate table (corrected)

**Opening pin:** `13bd508c7`. **Adversarial re-verify pin:**
`b23cdaff0` (rows below that the review touched). Multisig surfaces
unchanged across the 9-commit archival drift.

| Surface | State | Pin |
| --- | --- | --- |
| Cargo `multisig` on engine-core / rpc / ffi | `default = []` | both |
| Production wallet-rpc / cli | do not enable `multisig` | both |
| Envelope `CAPABILITY_RESERVED_MULTISIG` | refused | both |
| `EngineSignerKind` / `SoloSigner` | marker only; **zero associated items**; `MultisigSigner` type **absent** | both |
| **`multisig/{dkg,group,signing}.rs`** | **FROST coordinator lineage** under same gate (~493+152 LOC) | **omitted at open — R1-F-3** |
| `multisig/v31/` | equal-participants scaffold; no `construction.rs` / `transport/` | both |
| `shekyl-crypto-pq::multisig` | **always compiled**; V3.1 container `expected_blob_len = 3+n·2028` | both |
| `PQC_MAX_PUBLIC_KEY_BLOB` | `2+7·1996 = 13974` — **N=7 canonical 14199 fails** | **R1-F-1 → MSW-1** |
| `PQC_MAX_SIGNATURE_BLOB` | `2+7·3385 = 23697` — **M=7 canonical 23703 fails** | **R1-F-1 → MSW-1** |
| `MULTISIG_KEY_HEADER_LEN` | still `2` in `tx_pqc_verify.cpp` + `submit/verifier.rs` | **R1-F-1 → MSW-1** |
| Leaf preimage | `DOMAIN ‖ pqc_pk` — **leave alone** (F-2 retraction) | shared scheme 1+2 |
| Scheme blob prefix | byte[2]: `reserved==0` ⊥ `m_required≥1` | **MSW-2 invariant** |
| `DOMAIN_PQC_LEAF` | dual def fcmp + crypto-pq; hygiene debt, not Track A blocking | note |
| Daemon `tx_pqc_verify.cpp` | `scheme_id=2`; misattribution `"output committed="` | **MSW-3** |
| **`shekyl-daemon-rpc/.../verifier.rs`** | second verify site; header shadow | **MSW-1 lockstep** |
| **`wallet2.cpp:9828-9852`** | **existing** `create_pqc_multisig_group` / `m_pqc_multisig_*` / correct `shekyl_pqc_multisig_group_id` | **MS-2:** don't thicken; third group_id consumer (vs F-4 DKG) |
| `MultisigGroup` (engine) | Serialize hex secrets; claims "wallet file encrypted" | **R1-F-5** |
| `tx_fee_model::pqc_auth_weight` | scheme-1 lengths only | **Track B R-B** |
| `v31/intent.rs MAX_INPUTS` | 128 vs consensus `FCMP_MAX_INPUTS_PER_TX=8` | **Track B R-C** |
| CI `--features multisig` | **no job** | **R1-F-6** |
| Protocol §16.4 | superseded note (Rust-owns-logic) | design branch |

---

## §3 Pre-flight discipline (citation-paying)

### §3.1 Engine identification (corrected per R1-F-7)

- §10.3.1 still open for MS-1.
- **Honest framing:** adding the first associated item to
  `EngineSignerKind` is a **trait-surface amendment that touches
  `SoloSigner`** (e.g. `type SigningCeremony = Infallible`), not a
  silent feature flip. Module docs describing "eventual" associated
  types are aspiration, not substrate (`signer.rs:60-64`, `:65`).
- `#[cfg(feature = "multisig")]` on inherent/`Engine` methods remains
  valid for bodies that must not exist in V3.0 builds.

### §3.2–§3.4

Unchanged in applicability (principles 4–8; lenses bounded; no
Monero `wallet2` inheritance). **Add:** fossil-sweep obligation for
the FROST coordinator lineage (R1-F-3) — same shape as superseded
docs left standing beside replacements.

### §3.5 Branch posture

- Design docs: this branch.
- **Track A impl:** `feat/msw-*` off current `dev` after go-ahead
  (not blocked on Track B rounds).
- **Track B impl:** `feat/ms-*` after Round 1–3 + pre-flight +
  go-ahead.

### §3.6 Conformance lenses

Deferred to Round 2 after MS-1 **and** F-3 lineage fate.

---

## §4 Phase 0 candidates (Track B doc amends — after Round 1 close)

| ID | Target | Intent |
| --- | --- | --- |
| **P0-a** | `PQC_MULTISIG.md` §16 | Align feature name; list modules; keep §16.4 superseded |
| **P0-b** | `V3_ENGINE_TRAIT_BOUNDARIES.md` | MS-1 + SoloSigner associated-item amend (§8.2) |
| **P0-c** | `WALLET_REWRITE_PLAN.md` | Feature-flip checklist → this doc |
| **P0-d** | Persistence / ledger | **Re-open R6** against post-F-3/F-5 group shape |
| **P0-e** | INDEX | MS / MSW status rows |
| **P0-f** | FA-6b FOLLOWUPS | V3.1 engine ship gate |
| **P0-g** | FOLLOWUPS "wire group_id into consensus" | **Close as superseded by MSW-2** |

Track A may land code before P0-* if go-ahead is given; P0-g should
still close in the same docs train so FOLLOWUPS stops lying.

---

## §5 Load-bearing questions (Track B)

Criteria unchanged. Status reflects adversarial review.

### MS-1 — Trait identity — **OPEN (blocked on R1-F-3)**

Lean **MS-1(c)** remains the preferred shape **for the v31
lineage**, but is **unanswerable until F-3** names which lineage
`MultisigSigner` dispatches to. Adding associated items requires the
R1-F-7 SoloSigner amend.

**Reopen.** §1.5 failure for standalone engine → MS-1(b).

### MS-2 — C++ / Rust boundary — **OPEN (lean holds; substrate corrected)**

New wallet multisig logic: Rust-only. C++: LMDB + verify FFI.
**Do not claim C++ has no multisig surface** — `wallet2.cpp:9828-9852`
already has group create / `m_pqc_multisig_*` using the **correct**
`shekyl_pqc_multisig_group_id` (contrast F-4 DKG caller-supplied id).
MS-2 forbids thickening that surface; migration/deletion is rewrite /
Phase 5. Track A bound fixes are consensus ceiling corrections, not
wallet logic.

### MS-3 — Feature gate — **OPEN (lean amended)**

Keep Cargo feature name `multisig`. Flip checklist **amended**:

1. Rounds + pre-flight (Track B).
2. Receive + spend + regtest gate.
3. FA-6b disposed.
4. Capability un-reserve in flip PR only.
5. **Positive CI:** `cargo check/clippy/test -p shekyl-engine-core
   -p shekyl-engine-rpc -p shekyl-ffi --features multisig` green in
   CI (**R1-F-6** — Round 1 closure prerequisite, not Round 3).
6. **Negative CI:** default/release builds do not enable `multisig`;
   no simple-mode symbols.
7. **F-3:** flip must not ship the coordinator lineage unless that
   is the explicit product decision.

### MS-4 — Receive path — **OPEN (lean holds)**

MS-4(a) Refresh/scanner arm. FA-6b gate unchanged.

### MS-5 — Spend path — **OPEN (blocked on R1-F-3 / R1-F-7)**

Gaps restated: no v31 `construction.rs`; **there is** a
`MultisigSigningSession` with a **conflicting** coordinator model
(R1-F-3). `EngineSignerKind` has no ceremony associated type yet
(R1-F-7). Lean MS-5(a)/(c) after F-3.

### MS-6 — Transport — **OPEN (lean holds)**

Pure wire in `v31`; I/O via adapter. File-first.

### MS-7 — Persistence — **OPEN — lean WITHDRAWN (R1-F-5)**

Do **not** "confirm R6" against the protocol table alone.
**Re-open R6** against `MultisigGroup`'s actual Serialize-hex secret
shape (and whatever F-3 replaces it with). Secret hygiene
(`35`/`36`) is a closure prerequisite for any group-persist path.

**Reopen triggers.** Existing PR 6 §5.4.1 triggers, plus: any durable
secret field that is not `Zeroizing`/`ZeroizeOnDrop` end-to-end.

### MS-8 — Daemon `group_id` verify — **RETIRED (redundancy; F-2 retraction compatible)**

**Rejection.** Wiring `shekyl_pqc_verify_with_group_id` buys a no-op:
`group_id = f(key_blob)` and the leaf already binds the blob. No
sound daemon-side `expected_group_id` from the creating output.
**This conclusion does not depend on changing the leaf preimage.**

**Replacement (Track A / MSW-2–3).** Pin prefix-disjointness; fix
`"output committed="` misattributions; do not change leaf hash.

**Re-evaluation shape.** Only if a future scheme breaks MSW-2 reopen
criteria *and* leaf binding is shown insufficient — new design round,
not a quiet reopen of MS-8.

---

## §6 Round 1 disposition status

| ID | Status | Notes |
| --- | --- | --- |
| MS-1 | **OPEN** | Lean (c); blocked on F-3 |
| MS-2 | **OPEN** | Lean holds |
| MS-3 | **OPEN** | Amended: positive CI + F-3 |
| MS-4 | **OPEN** | Lean holds |
| MS-5 | **OPEN** | Blocked on F-3 / F-7 |
| MS-6 | **OPEN** | Lean holds |
| MS-7 | **OPEN** | Confirm-R6 **withdrawn**; re-open vs `MultisigGroup` |
| MS-8 | **RETIRED** | redundancy; leaf change not required |

**Round 1 still cannot close until:**

- [ ] **R1-F-6:** CI lane compiles/tests `--features multisig` (or
      documented equivalent gate on the design branch's follow-on).
- [ ] **R1-F-3:** Written fate for FROST coordinator lineage.
- [ ] **R1-F-4:** Canonical `group_id` named (with F-3).
- [ ] **R1-F-5 / MS-7:** R6 re-opened against real persist shape.
- [ ] **R1-F-7:** §3.1 / SoloSigner associated-item framing accepted
      into Phase 0 plan.
- [ ] Maintainer sign-off on revised Track A (constant fix) + MS-8
      retirement + F-2 leaf-leave-alone.
- [ ] Lens-1 re-test after MS-1; R-residuals pointed at Round 2.

**Round 2 residuals (updated).**

- R-A…R-F as before (engine surface, construction, regtest, FA-6b,
  capability, griefing storage).
- R-B **extends:** multisig arm in `pqc_auth_weight` / fee model
  (scheme-1-only today).
- R-C **extends:** pin `SpendIntent::MAX_INPUTS` to
  `FCMP_MAX_INPUTS_PER_TX` (128 → 8); refuse unserializable intents.
- R-G: MSW-2 KAT remains green after MSW-1 bound raise; flip must not
  assume length-only separation.
- R-H: F-3 lineage deletion/quarantine PR shape.
- R-I: F-5 zeroize + ledger migration for group secrets.
- R-J / **MSW-G:** pre-genesis decision — is `MAX_MULTISIG_PARTICIPANTS
  = 7` viable under full-reward-zone (sim); lower `MAX` if not.

---

## §7 Implementation gates

### §7.1 Track A (MSW-*) — priority 1 (revised)

1. Explicit user go-ahead for Track A implementation.
2. Short-lived `feat/msw-*` off current `dev`.
3. One validation surface: MSW-1 (bounds + single-source + cross-seam
   KAT + delete local shadows) + MSW-2 (disjointness doc+KAT) +
   MSW-3 (misattribution + MS-8 retirement record).
4. **Do not** change leaf preimage / FFI leaf hash ABI / emission
   Auth-B / test-vector corpus as part of Track A.
5. **Not** blocked on Track B Round 1–3.
6. **MSW-G** may land as a docs/sim decision in the same train or
   immediately after; if `MAX` drops, MSW-1 formulas follow.

### §7.2 Track B (MS-*) — rule-26 halt

1. Satisfy §6 Round 1 closure prerequisites (including F-6 CI).
2. Round 2 → Round 3 → pre-flight (Round 0 / R0-D#).
3. Explicit go-ahead; then `feat/ms-*`.

This design branch remains **documentation only**.

---

## §8 Appendix — Grep pins (adversarial set)

```text
# F-1 fossil bounds
src/cryptonote_config.h:290  PQC_MAX_PUBLIC_KEY_BLOB = 2 + 7*1996
src/cryptonote_config.h:293  PQC_MAX_SIGNATURE_BLOB = 2 + 7*3385
rust/shekyl-wire/src/transaction.rs:167-170  same formulas
rust/shekyl-crypto-pq/src/multisig.rs:85-87  expected_blob_len = 3+n*2028
rust/shekyl-crypto-pq/src/multisig.rs:198-201  sig = 1+M*3385+M

# F-2 leaf / domain
rust/shekyl-fcmp/src/leaf.rs:29-33
rust/shekyl-fcmp/src/lib.rs:36 DOMAIN_PQC_LEAF
rust/shekyl-crypto-pq/src/derivation.rs:27 DOMAIN_PQC_LEAF (duplicate)

# F-3 lineage
rust/shekyl-engine-core/src/multisig/mod.rs  "FROST" + v31/
rust/shekyl-engine-core/src/multisig/signing.rs  coordinator ceremony

# F-8 second verifier
rust/shekyl-daemon-rpc/src/submit/verifier.rs:322-386
src/cryptonote_core/tx_pqc_verify.cpp  MULTISIG_KEY_HEADER_LEN = 2
```

---

## §9 Document history

| Date | Event |
| --- | --- |
| 2026-07-14 | Round 1 opened; MS-1…MS-8 posed |
| 2026-07-14 | Adversarial review recorded (R1-F-1…F-10); Track A/B split; MS-8 retired; Round 1 closure blocked on F-3…F-7 + F-6 CI; MSW family registered |
| 2026-07-14 | **F-2 retraction:** leaf preimage left alone; Track A revised to constant-family fix + prefix-disjointness KAT + misattribution; size/fee/`MAX_INPUTS` → Track B; `wallet2` group surface acknowledged; **MSW-G** on whether `MAX=7` survives reward-zone |
| 2026-07-14 | **§0.2 independent audit:** F-1 confirmed (shadow formula must use `expected_blob_len`, not `3+N*1996`); F-2 retraction holds but byte[2] oversold — length is primary separator; reward-zone math confirmed with rhetoric trim; fee/`MAX_INPUTS`/wallet2 confirmed |
