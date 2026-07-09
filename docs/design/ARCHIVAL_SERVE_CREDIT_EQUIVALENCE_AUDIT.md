# Archival serve-credit — C++ decision equivalence audit (V3.0)

**Status:** design rounds CLOSED (§10, round 3 + post-closure pins);
**implementation go issued 2026-07-09** — mirrors + standing KAT + fuzz land in
the follow-on implementation PR.
**Created:** 2026-07-08
**Branch / worktree:** `chore/serve-credit-equivalence-audit`
**Substrate verified at:** `origin/dev` = `ca8edce6b` (PR #273 merged).
**Anchors:** `FOLLOWUPS.md` "Serve-credit C++ consensus decisions — Rust
equivalence audit" (V3.0 queue); `REWARD_EMISSION_E3_GATING_ROUND.md` §9.5
(decision-placement pin, audit/flip decoupling ratified 2026-07-08).

This is a **verification task**, not a consensus change. It puts no new
consensus code on the genesis critical path. It gates genesis only on
*finding* divergences while they are still free to fix (`20-rust-vs-cpp-policy.mdc`
"Rust if any of" #2/#3: a C++ decision can be protected only by convention +
KAT + review, not by the type system).

---

## 0. The one-paragraph shape

Three archival serve-credit consensus decisions are C++ `if`-checks made
directly against LMDB. Mirror each as a **pure Rust function over marshaled
inputs**, prove **behavior equivalence** against the live C++ with a shared-vector
KAT plus Rust fuzzing, and leave the mirror + proof installed as a **standing
equivalence KAT** that locks the frozen C++ behavior against drift. The
decision-site *flip* (Rust becomes authoritative, C++ `if` deleted) is a separate
V3.1 item and is **out of scope here**. Ordering is **mirror-then-fix,
mandatory**: the mirror reproduces the C++ *as it is today, including any
reachable bad state*; if the audit finds a bug, the fix lands in the C++ as its
own commit (pre-genesis, free) and the mirror re-proves against the fixed C++.

---

## 1. Scope and non-goals

### 1.1 In scope (this PR, V3.0)

The three C++-decided serve-credit sites, all in
`src/cryptonote_core/blockchain.cpp`:

| ID | Site | Decision |
| --- | --- | --- |
| **D-SC-A** | `:4247` | per-tx `(P, shard, E)` dedup vs **pre-block LMDB** state (`has_archival_serve_credit_bit`) — the key-construction + dedup verdict unit; **composes into D-SC-B as its step-2 predicate** (round 2) |
| **D-SC-B** | `:4224–4396` | the **full per-tx acceptance-gate decision** `check_archival_serve_credit_input` — the ordered predicate sequence, incl. `H_fire` derivation, `(0, H_close]` guard, and holds-at-`H_fire` (`:4312`) at its core (**wide scope ratified round 2**) |
| **D-SC-C** | `:4889–4910` | block-level cross-tx `(P, shard, E)` **uniqueness** pass (in-memory set) |

**Round-2 scope note.** D-SC-B was ratified at **wide** scope: rather than the
minimal derivation-guard-holds triple at `:4297–4317`, the mirror reproduces the
**entire ordered predicate sequence** of `check_archival_serve_credit_input`
(§2.2), which pins every reject branch and the branch *ordering*. D-SC-A's dedup
is one predicate inside that sequence; it stays a **named sub-unit** (the mirror
composes it) because its `(P,s,E)` key is the object of finding SCE-1 and is
shared conceptually with D-SC-C's key.

Deliverables: pure-Rust mirrors, a shared KAT fixture + Rust standing KAT, Rust
fuzz targets, a C++-side equivalence exercise over the same vectors, a findings
ledger (family **SCE-N**, registered), and the tracking-index row.

### 1.2 Non-goals (named, per rule 21 / the FOLLOWUPS decoupling)

- **The C-1 block-level *emission* `(P,E)` pass** (`REWARD_EMISSION_E3_GATING_ROUND.md`
  §9.5 item 6). It is new C-1 code with **no C++ predecessor**, built
  Rust-decided from the start. The two block-level passes will look nearly
  identical in code (serve-credit dedups `(P,s,E)` at `:4904`; emission dedups
  `(P,E)`) — **only the serve-credit pass is an audit candidate here.** This is
  the load-bearing scope boundary; conflating them re-imports the exact ambiguity
  §9.5 was written to kill.
- **The decision-site flip** (Rust becomes primary, C++ `if` deleted). V3.1,
  filed separately. A behavior-preserving flip buys genesis nothing on safety and
  would put three fresh consensus decision-sites on the genesis critical path,
  replacing the most battle-tested code in the archival path. The genesis
  double-mint property is already carried by the WS-2 journal regardless of which
  language decides.
- **LMDB mutation, serialization, and network.** These stay C++. The mirror
  consumes *already-marshaled inputs*; over-extraction adds FFI surface with its
  own bug class.
- **The crypto/path/signature verify** (`shekyl_archival_verify_serve_credit_vin`)
  is *already* Rust and already KAT'd (gate-2). Not re-audited here.

### 1.3 The precedent this audit follows

`recon.rs` / `collect_outputs` (Rust mirror of C++ consensus math, named in the
FOLLOWUPS item). Additional in-repo patterns the equivalence proof draws on:

- **`serve_eligibility.rs::serve_credit_epoch_ok`** — the `:4261` epoch check is
  *already* a pure-Rust mirror called from C++ via FFI. It is the shape the three
  remaining decisions converge to, and a live proof the pattern works here.
- **`claimed_epochs.rs::claimed_epochs_check_and_set`** — the "C++ stores bytes,
  Rust decides" `(P,E)` dedup. D-SC-C is its direct `(P,s,E)` analog.
- **gate-2 serve-credit KAT** — `gate2_serve_credit_kat.rs` (Rust) +
  `archival_serve_credit_integration.cpp` (C++) over a **shared JSON fixture**
  (`gate2_serve_credit_kat_v1.json`). The standing-KAT delivery shape.
- **economics C2a′ dual-leg** — a C++ gtest runs both the C++ decision and the
  FFI-into-Rust leg on identical inputs and asserts equality. The strongest
  equivalence assertion available; considered in §6 as an option.

---

## 2. The three decisions — precise mirror spec

The mirror boundary is: **C++ keeps the I/O and marshaling; Rust makes the
decision.** Each mirror is a `#[must_use]` pure function; no LMDB handle, no
globals, no clock. "Marshaled input" = exactly the values the C++ already has in
hand at the decision point.

### 2.1 D-SC-A — per-tx `(P,s,E)` dedup vs pre-block LMDB (`:4247`)

```cpp
if (m_db->has_archival_serve_credit_bit(resp.p_canonical_id, resp.shard_id, resp.settlement_epoch))
  return false;  // "Duplicate archival serve-credit for (P, shard, E)"
```

- **Decision content that is mirror-worthy:** the *key construction*
  `(P_id ‖ shard_id ‖ E)` and the membership verdict. The LMDB lookup itself
  stays C++.
- **Marshaled inputs:** `p_canonical_id: [u8;32]`, `shard_id: u64`,
  `settlement_epoch: u64`, and a membership oracle — modeled in the mirror as
  "is this key present in the provided pre-block key set?" (`&BTreeSet<[u8;48]>`
  or a `contains` closure). The audit value is that the *key bytes the mirror
  builds* are asserted identical to what `ArchivalServeCreditKey` builds
  (`shekyl_types.h:405–412`).
- **Faithful-reproduction note:** `ArchivalServeCreditKey` encodes `shard_id`
  and `E` **big-endian** (`store_be64`). The mirror reproduces BE for the
  A-path key. **See finding SCE-1 (§6): the block-level pass builds the same
  logical key native-endian** (`memcpy` of the `u64`s — little-endian on all
  supported platforms).

### 2.2 D-SC-B — the full per-tx acceptance-gate decision (`check_archival_serve_credit_input`, `:4224–4396`)

**Wide scope (round 2).** The mirror reproduces the gate's ordered predicate
sequence and returns the **first failing branch** (as a reason enum) or `Accept`.
Reproducing the *ordering* is itself audited: a reorder is a behavior change (it
changes which `MERROR_VER` a malformed vin trips, and can change accept/reject
when two conditions disagree). The ordered predicates:

| # | Site | Predicate | Marshaled input to the mirror |
| --- | --- | --- | --- |
| 1 | `:4224–4245` | path-layer / branch-scalar bounds | `c1_layers.len`, `c2_layers.len`, per-branch scalar counts; the `ARCHIVAL_MAX_*` consts |
| 2 | `:4247` | **(P,s,E) dedup vs pre-block LMDB** (D-SC-A) | the `(P,s,E)` key + `preblock_present: bool` |
| 3 | `:4254` | bond-record substrate present for `P` | `bond_substrate_present: bool` (C++ backs with `get_archival_bond_hybrid_pubkey`) |
| 4 | `:4261` | epoch-ok (`E ≥ E_join + 1`) | `settlement_epoch`, `join_epoch` — **reuse `serve_credit_epoch_ok`** (already the Rust mirror) |
| 5 | `:4269` | `good_through` at `E` | `good_through: bool` (C++ backs with `archival_bond_good_through`) |
| 6 | `:4279` | `H_close` credit-deadline (`current_height ≤ H_close`) | `current_height`, `h_close` (from `shekyl_archival_epoch_close_height`) |
| 7 | `:4288` | seal block hash loadable at `H_seal` | `seal_load_ok: bool` (C++ backs with `get_block_hash_from_height`) |
| 8 | `:4297–4310` | `H_fire` derivation + `(0, H_close]` guard | `h_open`, `h_close`, `seal_hash`, `P_id`, `shard_id`, `E` → **call `challenge_fire_height`** (do not re-derive) |
| 9 | `:4312` | **holds-shard-at-`H_fire`** | `held_at_fire: bool` (C++ backs with `archival_bond_holds_shard(P, shard, H_fire)`) — the WS-1 tip-vs-as-of site |
| 10 | `:4321` | shard-registry substrate at `H_fire` | `registry_present: bool` (C++ backs with `get_archival_shard_segment_at_height`) |
| 11 | `:4336` | challenge leaf-chunk bounds in range | `shard_id`, `leaf_index_in_segment` → **call `shekyl_archival_challenge_leaf_chunk_bounds`** |
| 12 | `:4353` | leaf-chunk read ok | `leaf_chunk_ok: bool` (C++ backs with `get_curve_tree_leaf_chunk`) |
| 13 | `:4371` | vin wire tag `== 0x02` | derivable / provided |
| 14 | `:4387` | **crypto/path/sig FFI verify** | `verify_ok: bool` — **already Rust + already KAT'd (gate-2); provided as a bool, not re-audited here** |

- **The WS-1 as-of semantics** (step 9: holds evaluated at `H_fire`, never at
  tip) become explicit and fuzzable in the mirror — this is the audit's sharpest
  target, the site where the tip-vs-as-of bug historically lived. Note the
  substrate at the pinned commit is already the WS-1-**corrected** as-of
  reconstruction (see the §5 step-9 substrate note): the mirror snapshots the
  corrected behavior, and the reconstruction's strictly-above slash boundary is
  audited through seeded-state verdict vectors on the C++ leg.
- **Single-source, no re-derivation:** steps 4, 8, 11, 14 are *already* Rust; the
  mirror **calls the same functions** rather than re-implementing them (GF4b-6
  derive-don't-cache discipline). The mirror's own new logic is the **ordering**
  and the **first-failing-branch** selection over booleans/values C++ marshals.
- **Boundary held:** the mirror decides accept/reject *up to and including* the
  crypto-verify boolean; it does **not** re-implement the crypto verify, the LMDB
  I/O, or the wire (de)serialization — those stay C++ (and, for verify, existing
  Rust). This is the "decision moves, marshaling stays" line the V3.1 flip entry
  draws, applied to the audit.

### 2.3 D-SC-C — block-level `(P,s,E)` uniqueness (`:4889–4910`)

```cpp
std::unordered_set<std::string> block_serve_credits;
for (tx : txs) for (vin : tx.vin if serve_credit) {
  key = P_id(32) ‖ memcpy(shard_id,8) ‖ memcpy(E,8);   // 48 bytes, NATIVE endian
  if (!block_serve_credits.insert(key).second) return false;  // duplicate in block
}
```

- **Decision content that is mirror-worthy:** the whole pass — a pure function
  over the **ordered list** of `(P,s,E)` triples extracted from the block's
  serve-credit vins → `Ok(())` or "first duplicate at index i". This is the
  cleanest mirror of the three; direct `(P,s,E)` analog of
  `claimed_epochs_check_and_set`'s in-set dedup.
- **Marshaled inputs:** `&[(p_canonical_id, shard_id, settlement_epoch)]` in
  block/tx/vin iteration order. Output preserves "first collision wins" (the C++
  returns on first `insert().second == false`).
- **Faithful-reproduction note:** the C++ key here is **native-endian**
  (`memcpy` of the `u64`s), *not* the BE `ArchivalServeCreditKey`. Since this set
  is self-contained (built and queried with the same encoding inside one block),
  endianness is behavior-irrelevant *for C in isolation* — but the mirror must
  still reproduce C's actual bytes for the equivalence proof, and the A-vs-C
  encoding split is the substance of SCE-1.

---

## 3. Mirror module — placement and shape

**Placement:** new module in `rust/shekyl-archival-retention/` (where
`serve_eligibility.rs`, `challenge.rs`, `claimed_epochs.rs` already live). Working
name `serve_credit_decisions.rs`. No new crate; no new workspace dependency
(rule 17 — nothing to add).

**Shape (illustrative signatures, subject to review — not yet written):**

```rust
/// D-SC-A sub-unit: the (P,s,E) LMDB dedup key (BE) + membership verdict.
pub fn serve_credit_key_be(p_id: &[u8; 32], shard_id: u64, settlement_epoch: u64) -> [u8; 48];

/// D-SC-B (wide): the full per-tx acceptance-gate decision as the ordered
/// predicate sequence over marshaled inputs; returns the first failing branch
/// or Accept. Composes the D-SC-A dedup as step 2 and reuses
/// `serve_credit_epoch_ok` as step 4; calls (not re-derives) `H_fire`,
/// leaf-chunk bounds, and takes the crypto-verify result as a bool.
pub fn serve_credit_gate_decision(inputs: &ServeCreditGateInputs) -> GateVerdict;

/// D-SC-C: block-level (P,s,E) uniqueness over the ordered vin list
/// (native-endian key in the C++ — the mirror pins LE explicitly, which is
/// what native resolves to on every supported platform; the §5 SCE-1
/// decision-invariance fuzz covers the encoding's irrelevance to the verdict;
/// first-collision-wins).
pub fn serve_credit_block_unique(triples: &[(/*P*/[u8;32], /*s*/u64, /*E*/u64)]) -> BlockUniqueVerdict;
```

`ServeCreditGateInputs` is the round-2 §2.2 table as a struct (the values/booleans
C++ marshals at each step). `GateVerdict` and `BlockUniqueVerdict` carry the
*reason* — one variant per C++ `MERROR_VER` branch — so the KAT asserts not just
accept/reject but **which branch fired and in what order**, a strictly stronger
equivalence than a bool.

---

## 4. Mirror-then-fix discipline (mandatory)

Straight from the FOLLOWUPS item, restated because it is the load-bearing rule:

1. **The mirror reproduces the C++ exactly, including any reachable bad state.**
   Never mirror a "cleaned up" version — then the "equivalence" is against a thing
   the C++ never did.
2. **If the audit finds a bug**, the fix is a **behavior change**: it lands in the
   **C++** as its **own commit** (pre-genesis, free), and the mirror then
   **re-proves against the fixed C++**.
3. The mirror + proof stay installed as a **standing equivalence KAT**, which also
   locks the frozen C++ behavior against accidental drift.

This keeps the free-pre-genesis-correction and the deferrable-refactor cleanly
separated (blurring them is how a "refactor" silently ships a behavior change).

---

## 5. Equivalence-proof mechanism — the standing KAT

**Shared fixture:** `serve_credit_equivalence_kat_v1.json` (new), one vector per
row: marshaled inputs + expected verdict (incl. reason branch) for each decision.
Vectors cover: fresh accept; A dedup hit; C in-block collision (first-wins,
ordering-sensitive); B guard boundaries (`H_fire == 0`, `H_fire == H_close`,
`H_fire == H_close + 1`); B holds/not-holds at fire — including the step-9
slash-boundary rows below; and the SCE-1 A-vs-C key-encoding cross-check.

**Fixture staleness guards (post-closure pins, 2026-07-09):**

- **The fixture header pins the substrate commit** the expected-reason column
  was authored against (`substrate_commit` field; first authoring is
  `ca8edce6b`). The reason column is a snapshot of a specific C++ predicate
  ordering: if `dev` reorders `check_archival_serve_credit_input` or inserts a
  predicate before the mirror lands, the bool equivalence still holds but the
  branch assertions go silently stale — the header makes the anchor explicit
  and re-authoring a deliberate act.
- **The C++ gate carries a guard comment naming this fixture** (implementation
  deliverable): a one-liner at the top of `check_archival_serve_credit_input`
  and at the `:4889` block pass stating the predicate order is audited by
  `serve_credit_equivalence_kat_v1.json`, so a future edit to the decision
  order trips a "you changed an audited decision" signal at the edit site, not
  at KAT-failure time.

**Step-9 substrate note (post-closure pin, 2026-07-09).** The holds accessor at
the pinned substrate is **already the WS-1-corrected as-of-`H_fire`
reconstruction**, not a tip read: `archival_bond_holds_shard`
(`db_lmdb.cpp:5040–5072`, landed with the WS-1 held-sourcing correction, PR
#269) answers at `at_height` via the two-step read — held at tip ⇒ held at every
height back to join (holdings shrink-only at the current substrate); not held at
tip ⇒ held at `at_height` iff a logged slash **strictly above** `at_height`
removed it (a slash *at* `at_height` means already-removed). Mirror-then-fix
therefore snapshots the **corrected** behavior; the fixture's step-9
`held_at_fire` expectations say so explicitly. The strictly-above boundary is
the off-by-one seam worth vectors of its own: the C++ leg seeds a slash at
exactly `H_fire` (expect reject) and at `H_fire + 1` (expect accept) and asserts
the verdict flips. The reconstruction logic itself stays C++-side marshaling
(it is entangled with the slash-log scan); its boundary is audited through
these seeded-state verdict vectors, not by re-implementing the scan in the
mirror. Reopen trigger: voluntary `HoldingsUpdate` landing breaks the
shrink-only premise (the accessor's own doc comment names this; FOLLOWUPS V3.0
bond-lifecycle item) — the fixture re-authors when that lands.

**Two legs, both green on the shared fixture — with an explicit
leg-responsibility split (pinned round 3, SCE-B-1):**

The C++ gate returns a bare `bool`; its reject reasons exist only as
`MERROR_VER` **log strings**, not as a return value. The equivalence harness
must therefore never parse log text — a reworded message would break
branch-detection with zero behavior change. The split that follows from what
each side actually exposes:

- **C++ leg asserts the verdict (`bool`) only.** That is the whole of what the
  C++ contract exposes, and it is the consensus-relevant property — accept/reject
  is what forks. The fixture's expected-verdict column is anchored to what the
  live C++ does.
- **The reason/branch is asserted on the Rust mirror only**, against an
  **authored** expected-reason column — authored by *source inspection* of which
  `MERROR_VER` branch each vector trips at the pinned substrate commit, never
  extracted from running-C++ log output. This is a **mirror-fidelity check** (it
  catches ordering bugs and wrong-branch divergence), layered on top of the
  verdict equivalence, with no log-parser anywhere.

*Rejected mechanisms for C++-side reason confirmation* (named so the harness is
built right the first time): log-parsing `MERROR_VER` output (couples equivalence
to message text; would additionally require KAT-pinning the strings themselves),
and audit-only reason-enum instrumentation of the C++ (touches the frozen C++ for
a test convenience). Reopen only if a divergence investigation needs
branch-level C++ evidence that the bool + seeded-state construction cannot give.

- **Leg mechanics:** `tests/serve_credit_equivalence_kat.rs` (Rust) runs each
  mirror over the fixture, asserting verdict **and** reason. A C++ gtest drives
  the live C++ decision over the same vectors, asserting verdict. D-SC-C is
  trivially isolatable (pure, no DB). The wide D-SC-B gate and its D-SC-A dedup
  touch `m_db`, so the C++ leg runs them through the existing
  `archival_serve_credit_integration.cpp` harness (real DB, seeded state) rather
  than in isolation. Any boundary vector the harness cannot reach is recorded in
  §10 as an escalation trigger, **not** silently dropped.

  *Rejected (kept for the record):* the economics-C2a′ **dual-leg FFI** shape
  (export mirrors via test-only FFI; C++ gtest asserts `cpp == mirror` on
  identical inputs, incl. fuzz). Strongest, but adds FFI surface now; the flip
  (V3.1) owns FFI, so the audit stays FFI-free. Reopen only if a boundary vector
  proves unreachable through the integration harness.

**Fuzz (Rust side, `20-rust-vs-cpp-policy.mdc` #3):** fuzz targets over each
mirror hunting panics and invariant violations (e.g. D-SC-C: no false-negative on
a planted duplicate; permutation of a dup-free list stays accepting). Cross-language
differential fuzz (mirror vs live C++) is noted as a V3.1/flip-adjacent
strengthening, not a V3.0 deliverable.

---

## 6. Findings ledger — family **SCE-N**

This doc mints the `SCE-` family (serve-credit equivalence), so per rule 94 §1
("new identifier families register at birth") the `IMPLEMENTATION_INDEX.md` §2
registry row lands **in this same design PR** — see §8 for the exact split of
which bookkeeping rides this PR vs the implementation PR. Collision check:
`SCE-` up to its first digit is unique against the §2 registry
(Phase/Stage/M/Bond-PR/SP/SP-T/PR-A/PR-B/PR-E/CT/GF/S/R/F/DQ/WI/M1) — no token
of `SCE-N` can parse as a token of an existing family.

### SCE-1 (candidate) — two byte encodings for the `(P,s,E)` key

- **Observed:** the persistent LMDB path (D-SC-A) builds the key via
  `ArchivalServeCreditKey` = `P ‖ BE64(shard) ‖ BE64(E)` (`shekyl_types.h:410–411`,
  used by `has/set/remove`). The block-level pass (D-SC-C) builds the logically
  same key via raw `memcpy` = `P ‖ LE64(shard) ‖ LE64(E)` (`blockchain.cpp:4902–4903`,
  native-endian on x86).
- **Is it a live bug?** No. The two sets never compare keys across the boundary
  (A = persistent BE set; C = per-block in-memory LE set), and each is internally
  consistent, so each detects its own duplicates correctly.
- **Why it's a finding anyway:** it is precisely the *drift hazard* this audit
  exists to surface — two byte-level specs for "the `(P,s,E)` key." It also means
  the mirror cannot have one canonical key encoding for free; under §4 it
  reproduces **both** (BE for A, LE for C) faithfully first.
- **Disposition (ratified round 2 — unify-after):** raise as SCE-1; **do not
  normalize in the mirror** (mirror-then-fix — the mirror reproduces BE for A and
  LE for C faithfully first). Once the standing equivalence KAT is green against
  today's split, land a **standalone behavior-preserving C++ commit** unifying
  D-SC-C's inline key onto `ArchivalServeCreditKey` so one type owns the encoding
  (C's set stays internally consistent; the change removes the latent drift hazard
  and is free pre-genesis). The unify's value is not mere consistency: a
  native-endian `memcpy` of `u64`s in consensus-adjacent key construction is the
  exact representation smell the DB layer deliberately forbids for its own
  composite keys (`db_lmdb.cpp:1657–1659`: "composite keys are multi-field
  big-endian byte arrays, not native-endian integers" — the guard against
  `MDB_INTEGERKEY` silently breaking sort order on little-endian machines);
  unifying onto the BE `ArchivalServeCreditKey` removes the one remaining
  native-endian construction of this key shape. The mirror's C-path key then
  re-points to the BE encoding and the KAT re-proves against the unified C++.
  Sequencing is load-bearing: **equivalence-proof-first, unify-second** keeps the
  free pre-genesis correction distinct from the mirror.

Further findings append here as SCE-2, SCE-3, … as the mirror + fuzz surface
them.

---

## 7. Test / gate plan

- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test -p shekyl-archival-retention` (rule 45 / 50).
- New Rust unit tests co-located with the mirrors (per-decision, per-reason-branch).
- New standing KAT test over the shared fixture (Rust leg).
- C++ leg per the §5 decision (gtest; ctest).
- Fuzz targets build and run a smoke corpus in CI (mirror the existing archival
  fuzz wiring).
- No schema change, no wire change, no consensus behavior change ⇒ **no
  `PSCAN_STATE_VERSION` / persisted-schema snapshot bump**, no serialization-policy
  (rule 42) trigger. (If SCE-1's C++ hygiene fix is taken, it is behavior-preserving
  and rides its own commit with its own justification.)

## 8. Tracking-index registration (rule 94) — what lands where

**This design PR** (rule 94 §1 birth-registration + rule 94 §5 start-registered,
since implementation begins on the go):

1. **§2 registry row:** `**SCE-N** | serve-credit C++-decision equivalence-audit
   findings | ARCHIVAL_SERVE_CREDIT_EQUIVALENCE_AUDIT.md`.
2. **§5 inventory row:** "Serve-credit C++ decision equivalence audit
   (D-SC-A/B/C mirrors + standing KAT) — *verification only, no consensus
   change*; design rounds closed, implementation starting; flip deferred to
   V3.1 FOLLOWUPS."
3. **§7 doc-directory row** for this file.
4. `CHANGELOG.md` unreleased entry for the design.

**The implementation PR** (rule 91 doc task):

5. Inventory-row status `UPDATE` when the mirrors + standing KAT land.
6. FOLLOWUPS V3.0 item updated with the standing-KAT pointer.
7. `CHANGELOG.md` entry for the landed mirrors/KAT; SCE-1 unify commit noted
   when it lands.

## 9. Decisions (resolved round 2, 2026-07-08)

1. **D-SC-B scope** — **WIDE.** Mirror the full `check_archival_serve_credit_input`
   ordered predicate sequence (§2.2), with D-SC-A composing in as step 2. ✓
2. **Equivalence mechanism** — **6-A shared-JSON-KAT, no new FFI** (§5). Dual-leg
   FFI rejected; reopen only on an unreachable boundary vector. ✓
3. **SCE-1 disposition** — **unify-after** (§6): mirror faithfully → prove
   equivalence → standalone behavior-preserving C++ unify commit → re-prove. ✓
4. **Identifier family** — `SCE-` (collision-free vs §2 registry). **Confirmed
   at go (2026-07-09)**; registered in `IMPLEMENTATION_INDEX.md` §2 in this PR.
5. **Module/name** — `shekyl-archival-retention::serve_credit_decisions`.
   **Confirmed at go (2026-07-09).**

## 10. Review rounds (rule 26 scaffold)

| Round | Date | Outcome |
| --- | --- | --- |
| 1 | 2026-07-08 | Draft. Substrate verified at `ca8edce6b`; SCE-1 surfaced on first read. |
| 2 | 2026-07-08 | Design decisions resolved (§9): D-SC-B **wide** (full gate mirror), equivalence via **shared-JSON KAT** (no FFI), SCE-1 **unify-after**. Doc updated §1.1/§2.2/§3/§5/§6/§9. |
| 3 | 2026-07-09 | PR #274 review (SCE-B-1..B-3). **SCE-B-1 pinned (§5):** leg-responsibility split made explicit — C++ leg asserts the verdict `bool` only (all the C++ contract exposes; the consensus-relevant property); reason/branch asserted on the Rust mirror against a source-inspection-authored expected column; no `MERROR_VER` log-parsing anywhere (rejected mechanisms named with reopen criterion). **SCE-B-2 conceded by reviewer** (step-1 grouping of the `:4224–4245` bounds is internally consistent; reason enum keeps the sub-branches distinct) — no change. **SCE-B-3 addressed (§6):** SCE-1 unify rationale sharpened — the native-endian `memcpy` is the representation smell `db_lmdb.cpp:1657–1659` deliberately forbids for composite DB keys, not mere consistency. **Round CLOSED — implementation go issued.** |
| 3a (post-closure pins) | 2026-07-09 | Copilot findings on PR #274 resolved: §6/§8 wording made accurate by **doing** the rule-94 birth registration in this PR (registry + inventory + doc-directory rows in `IMPLEMENTATION_INDEX.md`, CHANGELOG entry) rather than deferring; §2.1 cross-ref §7→§6 fixed; LE→native-endian wording corrected in §2.1/§3 (mirror pins LE explicitly; decision-invariance fuzz covers it). Reviewer markers carried into §5 as post-closure pins: fixture `substrate_commit` header + C++ gate guard comment (staleness guards), and the **step-9 substrate correction** — the holds accessor at the pinned commit is already the WS-1-corrected as-of-`H_fire` reconstruction (`db_lmdb.cpp:5040–5072`, PR #269), so the mirror snapshots the corrected behavior, with strictly-above slash-boundary vectors on the C++ leg. Not a design reopen (rule 21: substrate-completeness amendments). |
