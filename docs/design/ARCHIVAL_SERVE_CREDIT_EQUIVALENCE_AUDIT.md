# Archival serve-credit — C++ decision equivalence audit (V3.0)

**Status:** design round 1 (draft for review) — *no implementation yet; awaiting
go.*
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
| **D-SC-A** | `:4247` | per-tx `(P, shard, E)` dedup vs **pre-block LMDB** state (`has_archival_serve_credit_bit`) |
| **D-SC-B** | `:4297–4317` | derive `H_fire`, guard `H_fire ∈ (0, H_close]`, then **holds-shard-at-`H_fire`** (`archival_bond_holds_shard`) |
| **D-SC-C** | `:4889–4910` | block-level cross-tx `(P, shard, E)` **uniqueness** pass (in-memory set) |

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
  A-path key. **See finding SCE-1 (§7): the block-level pass builds the same
  logical key little-endian.**

### 2.2 D-SC-B — `H_fire` derivation + guard + holds-at-`H_fire` (`:4297–4317`)

```cpp
h_fire = shekyl_archival_challenge_fire_height(h_open, h_close, seal_hash, P_id, shard_id, E);
if (h_fire == 0 || h_fire > h_close) return false;
if (!m_db->archival_bond_holds_shard(P_id, shard_id, h_fire)) return false;
```

- **Decision content that is mirror-worthy:** the `(0, H_close]` guard and the
  *as-of-`H_fire`* holds decision. This is where the **WS-1 tip-vs-as-of bug**
  lived (the holds must be evaluated at `H_fire`, never at tip); a mirror makes
  the as-of semantics explicit and fuzzable.
- **`H_fire` derivation itself is already Rust** (`challenge.rs::challenge_fire_height`,
  reached via `shekyl_archival_challenge_fire_height`) and the epoch heights are
  Rust (`shekyl_archival_epoch_{open,close}_height`). The mirror **calls the same
  functions** — it does not re-derive `H_fire` (single-source; re-implementing it
  would be a second copy to drift, the anti-pattern GF4b-6 caught for
  `eligible_height`).
- **Marshaled inputs:** `h_open`, `h_close`, `seal_hash: [u8;32]`,
  `p_canonical_id`, `shard_id`, `settlement_epoch`, and the holdings-as-of query
  result — modeled as "the set of shards `P` held at height `H_fire`" (a
  `&BTreeSet<u64>` or a `holds(shard, height) -> bool` closure the C++ backs with
  `archival_bond_holds_shard`).
- **Boundary question for review (§10):** how much of the surrounding gate
  (`:4276–4283` `H_close`-deadline, the `:4261` epoch-ok, `:4269` `good_through`)
  is part of D-SC-B's mirror vs. left as separate C++ predicates? The FOLLOWUPS
  item names `:4312` specifically (holds-at-fire); the minimal faithful mirror is
  the derivation-guard-holds triple. Larger scope = more of the gate audited, but
  more marshaled surface.

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
/// D-SC-A: the (P,s,E) LMDB dedup key + membership verdict.
pub fn serve_credit_key_be(p_id: &[u8; 32], shard_id: u64, settlement_epoch: u64) -> [u8; 48];
pub fn serve_credit_dedup_a(key: &[u8; 48], preblock_present: bool) -> DedupVerdict;

/// D-SC-B: guard + holds-at-fire, over an as-of-H_fire holdings oracle.
pub fn serve_credit_holds_at_fire(inputs: &FireHoldsInputs, held_at_fire: bool) -> HoldsVerdict;

/// D-SC-C: block-level (P,s,E) uniqueness over the ordered vin list.
pub fn serve_credit_block_unique(triples: &[(/*P*/[u8;32], /*s*/u64, /*E*/u64)]) -> BlockUniqueVerdict;
```

The verdict enums carry the *reason* (mirroring each C++ `MERROR_VER` branch) so
the KAT can assert not just accept/reject but which branch fired — a stronger
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
`H_fire == H_close + 1`); B holds/not-holds at fire; and the SCE-1 A-vs-C
key-encoding cross-check.

**Two legs, both green on the shared fixture:**

- **Rust leg (standing KAT):** `tests/serve_credit_equivalence_kat.rs` runs each
  mirror over the fixture, asserts the expected verdict + reason.
- **C++ leg (live-behavior anchor):** the fixture's "expected" column is what the
  **live C++ actually does**. Two sub-options — a **decision for review (§10)**:
  - **(6-A) Shared-JSON-KAT** (the gate-2 shape): a C++ gtest drives the live C++
    decision over the same vectors and asserts the same expected column. D-SC-C is
    trivially isolatable (pure, no DB). D-SC-A/B touch `m_db`, so the C++ leg runs
    them through the existing `archival_serve_credit_integration.cpp` harness
    (real DB, seeded state) rather than in isolation. **No new FFI.**
  - **(6-B) Dual-leg FFI** (the economics C2a′ shape): export the mirrors via a
    test-oriented FFI and have a C++ gtest assert `cpp_decision == ffi_mirror` on
    identical marshaled inputs — including fuzz-generated ones. **Strongest**
    equivalence, but adds FFI surface now (the flip warns against exactly this;
    for an *audit* the surface is test-only and does not route production
    decisions through Rust, so it stays on the audit side of the audit/flip line).

  **Recommendation:** 6-A for A/B (no premature FFI; the flip owns FFI), plus a
  direct C++ unit for C. Revisit toward 6-B only if the integration harness can't
  reach a boundary vector.

**Fuzz (Rust side, `20-rust-vs-cpp-policy.mdc` #3):** fuzz targets over each
mirror hunting panics and invariant violations (e.g. D-SC-C: no false-negative on
a planted duplicate; permutation of a dup-free list stays accepting). Cross-language
differential fuzz (mirror vs live C++) is noted as a V3.1/flip-adjacent
strengthening, not a V3.0 deliverable.

---

## 6. Findings ledger — family **SCE-N** (to register)

Per rule 94 §1 this PR registers a new identifier family. `SCE-` (serve-credit
equivalence) up to its first digit is unique against the §2 registry
(Phase/Stage/M/Bond-PR/SP/SP-T/PR-A/PR-B/PR-E/CT/GF/S/R/F/DQ/WI/M1) — no token
collision. Registry row and this doc land in the same PR.

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
- **Disposition (proposed, for review):** raise as SCE-1; **do not normalize in
  the mirror** (mirror-then-fix). Candidate C++ hygiene fix — unify D-SC-C onto
  `ArchivalServeCreditKey` so one type owns the encoding — is a **behavior-preserving**
  change (C's set stays internally consistent) and, being free pre-genesis and a
  latent-hazard removal, is a reasonable standalone commit *after* the mirror
  proves equivalence against today's split. Alternatively: document the two sets
  as deliberately independent and leave the encodings. **Owner call.**

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

## 8. Tracking-index registration (rule 94)

Same PR adds:

1. **§2 registry row:** `**SCE-N** | serve-credit C++-decision equivalence-audit
   findings | ARCHIVAL_SERVE_CREDIT_EQUIVALENCE_AUDIT.md`.
2. **Inventory row** (§4 front table or a §5 note): "Serve-credit C++ decision
   equivalence audit (D-SC-A/B/C mirrors + standing KAT) — *verification only, no
   consensus change*; V3.0; flip deferred to V3.1 FOLLOWUPS."
3. **§7 doc-directory row** for this file.
4. `CHANGELOG.md` unreleased entry.
5. FOLLOWUPS V3.0 item updated to "in progress / landed" with the standing-KAT
   pointer when it lands (rule 91).

## 9. Open decisions for review (the go/no-go questions)

1. **D-SC-B scope** (§2.2): minimal derivation-guard-holds triple, or fold in the
   surrounding `H_close`-deadline / epoch-ok / `good_through` predicates?
2. **Equivalence mechanism** (§5): 6-A shared-JSON-KAT (recommended, no new FFI) vs
   6-B dual-leg FFI (strongest, adds test-only FFI now)?
3. **SCE-1 disposition** (§6): unify the C++ key encoding (standalone
   behavior-preserving commit, after equivalence proof) vs document-and-leave?
4. **Identifier family**: confirm `SCE-` (vs folding findings into an existing
   family).
5. **Module/name**: `shekyl-archival-retention::serve_credit_decisions` acceptable?

## 10. Review rounds (rule 26 scaffold)

| Round | Date | Outcome |
| --- | --- | --- |
| 1 | 2026-07-08 | This draft. Substrate verified at `ca8edce6b`; SCE-1 surfaced on first read. **Awaiting review + go.** |
