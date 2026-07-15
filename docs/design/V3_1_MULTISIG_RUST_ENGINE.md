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
protects wallet logic only — not blob bounds, leaf preimage, or
`scheme_id` binding).

**Process.** Cites
[`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md) and
[`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc).
**Halt condition (Track B only):** no Track B implementation commits
until design closure **and** the named pre-flight pass discharge.
**Track A** (V3.0 wire) is **not** held by that halt — it is a
fund-loss / genesis-freeze consensus defect class and ships whether or
not multisig ever flips — but still requires an **explicit
implementation go-ahead** (separate short-lived branch off `dev`).

**Trigger fired.**
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
§10.3.1 (2026-07-14).

**Identifier families (rule 94).**

| Family | Owns |
| --- | --- |
| **MS-1…MS-N** | Track B engine-integration Round 1 questions |
| **MSW-1…MSW-N** | Track A V3.0 pre-genesis multisig **wire** work items (from R1-F-1 / R1-F-2 / R1-F-8) |
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
| Local re-check of R1-F-1 / R1-F-2 arithmetic + cited paths | this design-branch tree (crypto-pq / wire / config formulas unchanged by archival drift) |

---

## §0 Structural disposition — Track A / Track B split

Accepted from Round 1 adversarial review (2026-07-14). Two tracks were
fused; the fusion inverted priority order (rule `00-mission` priority 1).

### Track A — V3.0 pre-genesis wire (unblocked from engine design rounds)

Consensus / always-compiled surfaces. Ship whether or not the
`multisig` feature ever flips. **No Track B design-round debt.**
Rule-19: F-1 bounds, F-2 leaf preimage, and F-8 dual verify sites are
**one validation surface** — jointly reconcile (A2+A8 co-trigger:
fixing lengths without fixing leaf `scheme_id` moves the only
current cross-scheme separator).

| ID | From | Work |
| --- | --- | --- |
| **MSW-1** | R1-F-1 | Reconcile `PQC_MAX_{PUBLIC_KEY,SIGNATURE}_BLOB` + `MULTISIG_KEY_HEADER_LEN` to V3.1 container (`3 + n·2028` keys; `1 + M·3385 + M` sigs). Single-source constant family across C++ / `shekyl-wire` / `shekyl-crypto-pq`. Cross-seam KAT: every `n ∈ 1..=MAX` round-trips both deserializers. |
| **MSW-2** | R1-F-2 | Decide leaf preimage before genesis: keep `DOMAIN_PQC_LEAF ‖ pqc_pk` **or** extend to `DOMAIN_PQC_LEAF ‖ scheme_id ‖ container_version ‖ pqc_pk`. Single-source `DOMAIN_PQC_LEAF` + wide-reduce; cross-crate KAT. **Retires MS-8.** |
| **MSW-3** | R1-F-8 | Move `tx_pqc_verify.cpp` **and** `shekyl-daemon-rpc/src/submit/verifier.rs` together under MSW-1/MSW-2. |

### Track B — V3.1 engine (MS-1…MS-7, gated, unhurried)

Feature-gated wallet orchestration. Rule-26 halt remains correct
**here**. Round 1 closure prerequisites: **R1-F-3, R1-F-4, R1-F-5,
R1-F-6, R1-F-7** (below). **MS-8 retired** → Track A / MSW-2.

### Hard scope pins (amended 2026-07-14)

1. **No Track B production code on this branch** until design closure
   + pre-flight + explicit go-ahead.
2. **Feature gate protects wallet orchestration only.** It does
   **not** protect `PQC_MAX_*_BLOB`, leaf preimage, or `scheme_id`
   binding — those are always-compiled and genesis-frozen (**R1-F-1**,
   **R1-F-2**). Default packages still must not enable `multisig`.
3. **Rust owns wallet multisig logic.** C++ = LMDB / chain-DB of
   consensus-visible bytes + verify FFI marshaling. No `wallet2` /
   `cryptonote_tx_utils` multisig logic.
4. **Archival out of scope** for Track B.
5. **Track A is in scope for the project now**, tracked as MSW-*,
   implemented off `dev` on a separate branch when go-ahead is given —
   not held behind Track B rounds.

---

## §0.1 Round 1 adversarial findings (R1-F-N)

Reviewer verification pin: `dev` = `b23cdaff0`. Local arithmetic /
path confirmation on this branch. Disposition column is **this
design's acceptance**, not implementation.

| ID | Sev | Finding (one line) | Disposition |
| --- | --- | --- | --- |
| **R1-F-1** | CRITICAL | `PQC_MAX_*_BLOB` uses fossil `2+N·LEN`; V3.1 container is `3+n·2028` / `1+M·3385+M`. **N=7 (and M=7) unserializable** at deserialize (`cryptonote_basic.h:458`, `shekyl-wire` bounds). Fund-loss: output can land; spend never parses. | **Accepted → MSW-1.** V3.0 wire. Not held by Track B halt. |
| **R1-F-2** | CRITICAL | Leaf is `H(DOMAIN ‖ pqc_pk)` only (`leaf.rs:29-33`). `group_id` binding is redundant (pure fn of blob already in leaf). Real gap: **spender-supplied `scheme_id`** only intra-tx consistent; cross-scheme safety is length-disjointness coincidence. Dual `DOMAIN_PQC_LEAF` defs, no cross-crate KAT. | **Accepted → MSW-2.** **MS-8 RETIRED.** Joint with MSW-1. |
| **R1-F-3** | HIGH | Coexisting FROST **coordinator** lineage under same `multisig` gate (`multisig/{dkg,group,signing}.rs`) vs coordinator-less `v31/`. | **Accepted.** Round 1 closure prerequisite: name fate (delete vs `frost-sal-v4`-only vs quarantine). Blocks MS-1/MS-3/MS-5. |
| **R1-F-4** | HIGH | Two `group_id` defs: deterministic `multisig_group_id` vs caller-supplied `dkg.rs` context. | **Accepted.** Round 2 / F-3 co-dispose: one canonical type; delete or newtype the other. |
| **R1-F-5** | HIGH | `MultisigGroup` Serialize hex of secrets; un-zeroized `Vec` reassign; not a `WalletLedger` extension — falsifies "confirm R6". | **Accepted.** MS-7 lean **withdrawn**; R6 re-opened against actual shape. |
| **R1-F-6** | HIGH | No CI job builds `--features multisig`. Gate armed, no positive compile trigger. | **Accepted.** **Prerequisite for Round 1 closure:** CI lane `check/clippy/test` for engine-core + engine-rpc + ffi with `--features multisig`. |
| **R1-F-7** | MEDIUM | §3.1 "associated items only on multisig kind" is a compile error; `EngineSignerKind` has zero associated items; marker is aspiration. | **Accepted.** Correct framing: first associated item = trait-surface amend touching `SoloSigner` (`SigningCeremony = Infallible`). |
| **R1-F-8** | MEDIUM | Second verify site: `shekyl-daemon-rpc/.../verifier.rs` also `verify_multisig(..., None)`. Five independent `MAX_MULTISIG_PARTICIPANTS` / bound defs. | **Accepted → MSW-3.** Bundle with MSW-1/2. |
| **R1-F-9** | MEDIUM | FROST `sign_own` nonce-reuse; unauthenticated `participant` claims. | **Accepted.** Evaporates if F-3 deletes lineage; else hard gates before compile-into-product. |
| **R1-F-10** | LOW | Pin discipline: `dev`-at-recording ≠ branch tip. | **Accepted.** Banner + this table. |

### Wargame table (accepted)

| # | Adversary | Armed at source? |
| --- | --- | --- |
| A1 | N=7 output lands; spend never serializes | **No** — R1-F-1 |
| A2 | Scheme-2 blob vs scheme-1 leaf (or reverse) | **No** — only length coincidence; R1-F-2 |
| A3 | Spender lies about `group_id` | **Vacuous** — already in leaf; MS-8 retired |
| A4 | Mix scheme 1/2 across inputs | Self-referential intra-tx only |
| A5 | Malicious DKG steers `group_id` | **No** — R1-F-4 |
| A6 | Replay `sign_own` / nonce reuse | **No** — R1-F-9 |
| A7 | Forge FROST `participant` index | **No** on FROST lineage |
| A8 | Flip ships never-compiled code | **Wrong-direction gate** — R1-F-6 |

**A2 + A8 co-trigger:** MSW-1 and MSW-2 must land in one validation
surface (or sequenced with an explicit disjointness proof after the
bound change).

---

## §1 Mission posture

Per [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc):

| Priority | How this design touches it |
| --- | --- |
| **1 — Security** | **Track A first.** Blob bounds + leaf/`scheme_id` are genesis-frozen fund-loss / confusion surfaces. Track B: threshold authority, DKG secrets, wipe-on-drop (`35`/`36`), honest-signer invariants. |
| **2 — Privacy** | Track B receive path (Option C / FA-6b). Spend must not weaken FCMP++ vs solo. |
| **3 — System longevity** | Feature-gated V3.1; Stage 4 swap-in; V4 FROST-SAL only after F-3 names the in-tree FROST lineage's fate. |

**Three timeframes.** Now: Track A before genesis. V3.1: Track B
behind `multisig`. V4: lattice-only / FROST-SAL — not an excuse to
leave the coordinator fossil under the V3.1 feature name.

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
| Wiring `shekyl_pqc_verify_with_group_id` as the primary fix | **Retired** (R1-F-2); do not schedule as ship-gate |

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
| `PQC_MAX_PUBLIC_KEY_BLOB` | `2+7·1996 = 13974` — **N=7 canonical 14199 fails** | **R1-F-1** |
| `PQC_MAX_SIGNATURE_BLOB` | `2+7·3385 = 23697` — **M=7 canonical 23703 fails** | **R1-F-1** |
| `MULTISIG_KEY_HEADER_LEN` | still `2` in `tx_pqc_verify.cpp` + `submit/verifier.rs` | **R1-F-1** |
| Leaf preimage | `DOMAIN ‖ pqc_pk` only; no `scheme_id` / version | **R1-F-2** |
| `DOMAIN_PQC_LEAF` | dual def fcmp + crypto-pq; comment-tied, no KAT | **R1-F-2** |
| Daemon `tx_pqc_verify.cpp` | `scheme_id=2`; `shekyl_pqc_verify` (no group_id) | both |
| **`shekyl-daemon-rpc/.../verifier.rs`** | **second** `verify_multisig(..., None)` | **omitted at open — R1-F-8** |
| `MultisigGroup` | Serialize hex secrets; claims "wallet file encrypted" | **R1-F-5** |
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

### MS-2 — C++ / Rust boundary — **OPEN (lean holds)**

Wallet logic: Rust-only. C++: LMDB + verify FFI. Track A wire fixes
**are** consensus C++/Rust constant + deserialize + leaf changes —
that is not "wallet multisig logic."

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

### MS-8 — Daemon `group_id` verify — **RETIRED (R1-F-2)**

**Rejection.** Wiring `shekyl_pqc_verify_with_group_id` buys a no-op
consensus rule: `group_id = f(key_blob)` and the leaf already binds
the blob. No sound daemon-side `expected_group_id` from the creating
output (`blockchain.cpp` cannot locate it).

**Replacement question (Track A / MSW-2).** Does
`DOMAIN_PQC_LEAF ‖ pqc_pk` need to become
`DOMAIN_PQC_LEAF ‖ scheme_id ‖ container_version ‖ pqc_pk` before
genesis?

**Re-evaluation shape.** Track A design note or MSW-2 PR description
records the choice with a cross-crate KAT; FOLLOWUPS group_id item
closes as superseded (P0-g).

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
| MS-8 | **RETIRED** | → MSW-2 |

**Round 1 still cannot close until:**

- [ ] **R1-F-6:** CI lane compiles/tests `--features multisig` (or
      documented equivalent gate on the design branch's follow-on).
- [ ] **R1-F-3:** Written fate for FROST coordinator lineage.
- [ ] **R1-F-4:** Canonical `group_id` named (with F-3).
- [ ] **R1-F-5 / MS-7:** R6 re-opened against real persist shape.
- [ ] **R1-F-7:** §3.1 / SoloSigner associated-item framing accepted
      into Phase 0 plan.
- [ ] Maintainer sign-off on Track A / Track B split + MS-8 retirement.
- [ ] Lens-1 re-test after MS-1; R-residuals pointed at Round 2.

**Round 2 residuals (updated).**

- R-A…R-F as before (engine surface, construction, regtest, FA-6b,
  capability, griefing storage).
- R-G: **replaced** — MS-8 sequencing → MSW-2 sequencing vs flip
  (flip must not rely on length coincidence post-MSW-1).
- R-H: F-3 lineage deletion/quarantine PR shape.
- R-I: F-5 zeroize + ledger migration for group secrets.

---

## §7 Implementation gates

### §7.1 Track A (MSW-*) — priority 1

1. Explicit user go-ahead for Track A implementation.
2. Short-lived `feat/msw-*` off current `dev`.
3. Single validation surface (or tightly sequenced PRs with
   disjointness proof): MSW-1 + MSW-2 + MSW-3.
4. Cross-seam KATs mandatory before merge.
5. **Not** blocked on Track B Round 1–3.

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
| 2026-07-14 | Adversarial review recorded (R1-F-1…F-10); Track A/B split; MS-8 retired → MSW-2; Round 1 closure blocked on F-3…F-7 + F-6 CI; MSW family registered |
