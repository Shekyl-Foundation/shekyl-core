# `shekyl-chain-rules` — the consensus-validation crate (DRS-E6 increment 1)

**Status:** OPEN — increment 1 **implemented 2026-09-15** (branch
`feat/drs-e6-inc1-chain-rules-scaffold`). Round 1 ruled §11; round 2's three
questions (§12) **ruled at PR #753 review** (defaults kept; G4 tightened to
`ChainValid<'id, V>`). §4 reflects what landed. Stays in `docs/design/` while
increments 2+ are open (it owns their template, §7.5.1). Implements *from*
[`CONSENSUS_C2_R8_STORE_PLACEMENT.md`](../completed/CONSENSUS_C2_R8_STORE_PLACEMENT.md)
(the ruling, CLOSED-as-record) and
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §7.5.1 (the deliverable list).
Nothing in this document re-opens either; the three questions the round-1
rulings surfaced are in §12 with a proposed default each, not decided silently.

**Scope of increment 1.** The scaffold only. Zero consensus rules land here
(DRS-D12; §7.5.1 "Zero rules may land in increment 1"). The crate is
**STAGED** (rule 23) with **S-CHAIN-W** as its named consumer: S-CHAIN-W
projects a `ChainView<'id>` from the store's `WriteBatch<'_, 'id>` and takes a
`ChainValid<'id, V>` into `connect`. Increments 2+ port the 141 surface-free rules
one census subsystem at a time (DRS §7.5.2 table 3).

**Sibling lane.** DRS-E1 increment 2.5 (PR #752) built the store side; this
branch stacks on it. This crate and `rust/shekyl-chain-store` share **no Rust**;
the interface the two must agree on later (`'id` spelled and invariant,
`ChainValid<'id, V>` and `RuleSetId` handed to `connect`, the view's fault channel
§4.3) is stated here and wired by S-CHAIN-W, not by either lane.

---

## 1. What the crate is, in one paragraph

One crate. Input: a candidate block (header + miner tx + the listed
transactions' bodies), a `ChainView<'id>` (narrow, read-only trait over
**recorded** chain facts), and a `RuleSet`. Output: `ChainValid<'id, V>` or
`InvalidBlock { rule: CenRow, locus }` — or, when the view's substrate could not
answer, the view's own fault, which is neither. No store handle, no redb type,
no `ChainStore` import — every rule is unit-testable against a mock view with no
database (ruling §9.1). Pool admission (DRS-E5) calls the **same** `tx_form` /
`tx_against` over a `PoolView` decorator it defines; there is no second
validator. Every `ChainValid` carries the set of census rows that were actually
evaluated (`RuleCoverage`), and only complete coverage is parity evidence
(ruling §9.4).

---

## 2. Contract — the hard constraints as stated guarantees

Each guarantee names the mechanism that holds it. A guarantee with no mechanism
is a hope; none of these is.

| # | Guarantee | Held by |
| --- | --- | --- |
| G1 | **No store handle.** The crate reaches neither `shekyl-chain-store` nor `redb`, directly or transitively, in normal or dev dependencies. | Two `compile_fail` doctests in `lib.rs` (intent; a direct `use` fails to resolve); the coverage gate refuses either package in any dependency table of the crate's `Cargo.toml`; **the belt** `scripts/ci/check_chain_rules_no_store.sh` (in `rust-audit-test.yml`) captures the crate's `cargo tree -e normal,dev --target all` closure and refuses either package in it (§6.5) — the belt is what sees *transitive* arrival, which the doctest cannot (round-1 ruling). |
| G2 | **The conversion ban.** No `From`/`Into`/`TryFrom`/`TryInto` between any `StoreError`/`StoreInvariant`/`StoreCannot` and `InvalidBlock`; no `match` arm maps a store token onto `InvalidBlock`. This crate never *names* a store error type; the store's fault reaches `validate` only as the opaque `V::Fault` (§4.3), which has no bound a rule could inspect. | `check_store_error_conversion_ban.py` clauses 1 and 3, **raised in this PR** so `verdict_defs == 0` is a failure now that the subject exists (§7); genericity of `Fault`. |
| G3 | **The verdict names the row.** `InvalidBlock { rule: CenRow, locus: Locus }` — a typed census row id, never a string, never "some rejection". | `CenRow` is a closed `enum`; `InvalidBlock` has no string field. |
| G4 | **One transaction, one brand.** `ChainValid<'id, V>` carries an *invariant* `'id` and is parameterized by the view type `V` that minted it. An unbranded `impl<'id> ChainView<'id> for Evil` can pick up a batch's `'id`, but produces `ChainValid<'id, Evil>`, which does not unify with the `ChainValid<'id, StoreView<'_, 'id>>` `connect` will demand. | `PhantomData<fn(V) -> V>` plus `'id`; `validate` returns `ChainValid<'id, V>`; two `compile_fail` doctests (cross-`'id` and unbranded-`V`) (§8.3). |
| G5 | **Private constructor.** Nothing outside the crate can build a `ChainValid` or a `ValidatedBlock`. | Fields private; no `pub` constructor; `compile_fail` doctest. The FFI-shim construction path is rejected by the ruling (§9.2) and does not exist. |
| G6 | **Coverage is carried, not declared.** Every `ChainValid` carries `RuleCoverage` (rows actually evaluated) and the `RuleSetId` it was checked under. With zero rules, coverage is empty and `is_complete_for` is `false`. Mint additionally requires `covers_landed` — every *implemented* row the rule set enforces is in coverage — so a forgotten `validate` call cannot produce the token during porting. | Struct fields, set only by `validate`; `ChainValid::mint` panics if `covers_landed` is false; unit tests pin empty/`is_complete_for`/`covers_landed`. |
| G7 | **The flag partitions first — by type.** Consensus rows and policy rows are **sibling enums** (`CenRow`, `PolicyRow`); a policy row cannot be inserted into a `RuleCoverage`, and `RuleSet` cannot name a `PolicyRow`. `implemented / enforced` and `ratified / enforced` are computed per flag; `E = rows of that flag − bucket 3`; both numbers always printed together with the definition of `E`. | Two enums, two `Coverage<R>` instantiations, two denominators (round-1 ruling Q4); `scripts/ci/check_chain_rules_coverage.py` (§6). |
| G8 | **Bijection registry ↔ census.** Every enforced census row (bucket ≠ 3) has exactly one entry in the enum of its flag; no entry lacks a row; bucket-3 rows are absent. | The same gate (§6.2); rule 47 subject assertions and `--selftest`. |
| G9 | **`implemented` is a compile-checked claim — of existence *and* identity.** An entry marked `implemented(path)` names a rule **type** (`rules::Rule`, one unit struct per row — slice 1, SCW-18; *records-was:* increment 1 wrote "names a rule function" and pinned existence only); a stale path is a **compile error**, and a type bound to another row's `ROW` is a **compile error** (`const _: () = assert!(matches!(<T as Bound<Name>>::ROW, Name::Var))`, forced red once at PR #762: `E0080 … bound to a different census row (SCW-18)`). The gate reads the same `census_rows!` invocations the compiler compiled. Runtime half: `covers_landed` at mint (G6). | Macro emits `use $path as _;` (§5.2); mint panic; unit test pins the generic form. |
| G10 | **No pre-provisioning.** No `PoolView` (E5's), no fork version on `ChainView` (ruling Q7), no `Canonical`/codec impl for `RuleCoverage` (the store's, at S-CHAIN-W under rule 42), no second verdict type, no view method without a census row that reads it (Q3 ruling). | This document's API list is exhaustive; anything not in §4 is not in the crate. |
| G11 | **Absence is matched, never propagated.** A by-height lookup returns `AtHeight<T>` — `Recorded(T)` or `AboveTip` — not `Option<T>`. There is no `?`, `map`, `unwrap_or_*`, or `is_none_or` on it: a rule that reaches `AboveTip` writes its refusal at that arm. A substrate that cannot answer surfaces as `V::Fault`, a different thing from absence (§4.3). | `AtHeight<T>` has no combinator surface and no `Default`; `CurveTreeRoot`/`RecordedBlock` have no `Default`. |
| G12 | **Hygiene.** `#![deny(unsafe_code)]`; no `println!`/`eprintln!`/`dbg!` outside `#[cfg(test)]`; `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` clean. | Crate attribute; `build.yml`'s debug-macro lint; rule 45. |
| G13 | **No recorded transaction body crosses `ChainView`.** The trait's reads are the recorded chain's *permanent* facts — a key image's presence, a block's identity and header, a root, the tip — never a recorded transaction's bytes. Under `PDM-Q6` bodies below the retention watermark `W` are discarded, so a rule that read one would be an above-`W`-only rule with nothing marking it so; with no accessor, every rule in this crate is by construction one a body-less node can run, and Q3's owed instrument ("a consensus read reaches a discarded body") is a property of the trait's surface rather than a grep over `src/`. **Reopening (rule 21):** a census row that reads a *recorded* body — none does today; 4.I reads the *candidate's* bodies, which are in `Candidate`, and CEN-I12 reads a root — arrives with an accessor that is `Option`-shaped (`None` ⇔ discarded, never a sentinel) and a rule type marked above-`W` in the registry, both in that row's slice pre-flight. Shaping request from the pruning lane's review of `PDM-Q-F26` (PR #765), taken 2026-09-16. | The Q3 ruling (every `ChainView` method is justified by a named row) already refuses an unjustified accessor; this row names the *kind* of method that needs the extra mark. `RecordedBlock { hash, header }` — no body field (§4.3). |

---

## 3. Pre-flight audit — workspace types, verified at source

Rule 17: every reuse below was read in the crate's `src/` and `Cargo.toml` in
this worktree (`feat/drs-e6-inc1-chain-rules-scaffold`, stacked on
`feat/drs-e1-inc2-5-brand-taxonomy`), not recalled.

### 3.1 Types reused

| Need | Type | Home (verified) | Notes |
| --- | --- | --- | --- |
| block height | `BlockHeight` | `shekyl-types` (`scalar_u64!`) | `from_raw`/`to_raw`/`ZERO`; deps: `serde`, `zeroize`, optional `postcard-schema`. |
| block identity | `BlockHash` | `shekyl-types` (`hash32!`) | `from_bytes`/`to_bytes`/`as_bytes`; hex `Display`. |
| tx identity | `TxHash` | `shekyl-types` (`hash32!`) | The `(TxHash, Tx)` pair type (ruling Q4/L4). |
| key image | `KeyImage` | **`shekyl-types`** — moved there in this PR (round-1 ruling Q1; §3.4) | `hash32! { KeyImage, redact, no_display }`: truncated `Debug`, **no `Display`**, `from_canonical_bytes` retained. `shekyl-crypto-pq` re-exports it; the computation `I = x · H_p(O)` stays there. |
| curve-tree root | `CurveTreeRoot` | **`shekyl-types`** — minted in this PR (round-1 ruling Q2; §3.4) | `hash32!` default arm. The tree's root *computation* stays in `shekyl-curve-tree`; the name lives where names live. |
| network | `Network` | `shekyl-address/src/network.rs` | The workspace's one nettype enum (`Mainnet | Testnet | Stagenet`; used by `shekyl-wire` tests, `shekyl-crypto-pq`, `shekyl-engine-*`, `shekyl-genesis-tool`). Selects a `RuleSchedule` (rule 71: nettype selects data). Deps: `shekyl-encoding`, `shekyl-crypto-hash`, `bech32`, `thiserror`; no `redb` — the G1 belt confirms. See **Q12-3**. |
| block / header / tx / input | `Block`, `BlockHeader`, `Transaction`, `Input`, `Output` | `shekyl-wire/src/{block,transaction}.rs` | Verdict §3.2. |

**Explicitly not reused:** `shekyl-curve-tree::BlockHeight` (the crate depends
on `redb` — G1 forbids the edge; `shekyl-types::BlockHeight` is the canonical
one anyway); `shekyl-consensus::{ChainState, BlockHeader}` (the pluggable-proof
crate's own types — the handoff names them as a confusion hazard; they are
`u64`/`[u8; 32]`-shaped and not the wire header); `shekyl-types::
{GlobalOutputIndex, OutputIndexInTx}` (no view method reads them — §3.3).

### 3.2 `shekyl-wire` candidate-type verdict: **SUITABLE**, with two recorded deltas

- `Block { header: BlockHeader, miner_transaction: Transaction, transaction_hashes: Vec<TxHash> }`
  and `Block::hash() -> BlockHash` (consensus Keccak-256 via
  `shekyl-crypto-hash`) — the identity derivation CEN-B6 defines, computed once
  by the validator (ruling Q4/L4). *(The verdict was recorded 2026-09-15
  against raw `[u8; 32]` returns and fields; RTN-7 typed them 2026-09-18 —
  the shapes here are the current ones. RTN-7 also wrote in this crate —
  `A2::GENESIS_PREVIOUS` aliases `BlockHash::NULL` — a sibling-lane write
  under rule 94 §6; the E6 lane re-verified at `dev` = `51d7f2416` the same
  day: coverage record unchanged, crate tests green, stamp moved in
  [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md).)*
- `BlockHeader { major_version: u8, minor_version: u8, timestamp: u64, previous: BlockHash, nonce: u32, curve_tree_root: CurveTreeRoot, attestation_root: AttestationRoot }`.
- `Transaction::hash() -> TxHash`, `prefix_hash() -> PrefixHash`, `pqc_signing_payload_hashes() -> Vec<[u8; 32]>` (per-input signing messages, not identities — allowlisted in `check_wire_raw_hash_surface.py`).
- `Input` is an `enum` — L5's whitelist dissolves into match exhaustiveness.
- Dependency graph: `shekyl-crypto-hash`, `shekyl-curve-generators` directly.
  No `redb`, no store. **Measured at commit 4** (`cargo tree -e normal
  --prefix none | sort -u | wc -l`): `shekyl-types` 13, `shekyl-address` 21,
  `shekyl-wire` 73 — of which `shekyl-curve-generators` is 70, the whole
  helioselene / generalized-bulletproofs / dalek stack behind the `tx_extra
  0x07` leaf-point check. The rules crate's closure is therefore 85 packages
  (170 with dev edges), not "almost none". Recorded rather than fought: the
  candidate type has one home, and the 4.I rows (CEN-I12's anchor, the
  leaf-point rows) will need that stack in this crate legitimately when they
  land — so the belt's subject is *which* packages, not how many.

**Delta 1 — five `Input` variants, not four.** The handoff lists
`Gen | ToKey | ServeCredit | BondPost`; the source has a fifth,
`ArchivalRewardEmission { canonical_bytes }` (`transaction.rs:354`). Not a
problem for the crate (exhaustive `match` is the point), recorded so the
handoff's count is not copied into a doc.

**Delta 2 — bare arrays at the wire edge.** `previous`, `curve_tree_root`,
`attestation_root`, `transaction_hashes[i]`, `Input::ToKey.key_image` are
`[u8; 32]`, and `timestamp` is `u64`. The crate lifts them into the typed
domain at *its* edge (`BlockHash::from_bytes`, `TxHash::from_bytes`,
`KeyImage::from_canonical_bytes`, `CurveTreeRoot::from_bytes`) and never passes
bare arrays across `ChainView`. Retyping `shekyl-wire` itself is out of scope
and not proposed.

### 3.3 `output_at` is not in increment 1 — the Q3 condition, applied

Round 1 ruled that every field of a view payload must be justified by a named
CEN row when it is introduced. Applied to `output_at(GlobalOutputIndex) ->
RecordedOutput`: **no enforced census row reads an output by chain-wide
index.** FCMP++ inputs carry no ring references, so there is no referenced
output to look up; maturity is enforced at leaf insertion (CEN-L12), not at
spend; CEN-L6/L11/L12 read the *candidate's own* outputs, which are in
`ValidatedBlock`. The C++ `get_output_key` / `get_output_tx_and_index` reads
were CLSAG-era decoy fetches (census §4 notes on `get_output_key_mask_unlocked`
— "the other caller is dead"). A `RecordedOutput` would therefore have zero
justified fields, so the method is not introduced.

**Recorded so it is not re-litigated:** when the undecided output-key-uniqueness
row is ruled, it needs `has_output_key(&OutputKey) -> bool` — a membership
query, the shape of `has_key_image` — **not** `output_at` by global index.
Dropping `output_at` forecloses nothing; it is a different method, and it
arrives with that row (§13).

### 3.4 Two relocations into `shekyl-types` (round-1 rulings Q1, Q2) — verified

**`KeyImage`.** *Pre-flight, records-was at `cb5a4a5e9` (dev before this PR
moved the type):* `shekyl-crypto-pq/src/key_image.rs` line 89 was
`pub struct KeyImage([u8; 32])` with `Clone, Copy, PartialEq, Eq, Hash,
PartialOrd, Ord, Zeroize, Serialize, Deserialize`, `#[serde(transparent)]`,
a **truncated `Debug`** (`KeyImage(0000..)`, first two bytes) and **no
`Display`** — both deliberate, documented at its lines 33–40 as a
wallet-correlation defence (a key image links on-chain spends to a wallet).
*Now:* the type is `hash32! { KeyImage, redact, no_display }` at
`shekyl-types/src/lib.rs:484`, and that file is the 35-line re-export
described under *Zero breakage* below. `shekyl-types`'
`hash32!` has a `redact` arm (minted for `PCanonicalId`) whose `Debug` is
byte-identical (`debug_tuple().field(format_args!("{:02x}{:02x}.."))`), but
its shared `@body` derives a full-hex `Display` for every arm — which would add
the stringly-typed boundary `key_image.rs` refuses. `PCanonicalId`'s threat is
the origin edge; a key image's is spend↔wallet; "no use case has emerged" was
the stated condition for a `Display`, and none has. So this PR adds a third
arm, **`redact, no_display`**, by splitting `@body` into the derive/accessor
core and an opt-in `@display`, and mints `KeyImage` with it. `from_canonical_bytes`
is kept as an inherent constructor beside the family's `from_bytes`: "canonical"
is a genuine predicate for a curve point and not for a hash, and 260 call sites
across 67 files are not churned for symmetry. A `compile_fail` doctest pins
"no `Display`".

*Wire check (rule 42).* The current type is `#[serde(transparent)]` over
`[u8; 32]`; the family is the same, plus `#[repr(transparent)]` (ABI, not
serialisation) and an opt-in `postcard_schema::Schema` derive.
`TransferDetails` (`shekyl-engine-state`) holds `Option<KeyImage>`; its
snapshot-checked schema is produced through a wire-mirror struct (`transfer.rs`
§"postcard-schema support") that does not name `KeyImage`. The
`schema_snapshot` tests are run before and after the move (§8.6); if any `.snap`
moves, the move is a versioned-format event and lands as its own PR with the
bump — not as a line in this scaffold.

*Zero breakage.* `shekyl-crypto-pq` gains `shekyl-types` as a dependency
(`shekyl-types` depends on `serde`, `zeroize`, optional `postcard-schema` — no
cycle) and `key_image.rs` becomes `pub use shekyl_types::KeyImage;` under the
existing module docs (computation-side notes stay; type-placement paragraph
rewritten). Every `shekyl_crypto_pq::key_image::KeyImage` path and every
`from_canonical_bytes` / `as_bytes` call resolves unchanged.

**`CurveTreeRoot`.** No root newtype exists anywhere (`shekyl-curve-tree`
`tree_root: [u8; 32]`, `shekyl-wire` `curve_tree_root: [u8; 32]`,
`shekyl-fcmp`, `shekyl-types` — all bare). Minted with `hash32!`'s default arm
(public, non-correlating; full hex `Debug`). No consumer is retyped in this PR;
the rules crate reads it from `root_at`, and the store writes it at S-CHAIN-W.

---

## 4. Public API

Module map (one concern per file, sibling `*_tests.rs` per the store crate's
style, `#[cfg(test)] #[path = "…"] mod …;`):

```text
rust/shekyl-chain-rules/
├── Cargo.toml            shekyl-types, shekyl-wire, shekyl-address
└── src/
    ├── lib.rs            //! crate docs (staging note, consumer map, graded-oracle hook), compile_fail pins
    ├── census.rs         Flag, RowStatus, Row (sealed), census_rows!, CenRow, PolicyRow
    ├── coverage.rs       Coverage<R: Row>; RuleCoverage, PolicyCoverage
    ├── view.rs           ChainView<'id>, AtHeight<T>, RecordedBlock
    ├── rule_set.rs       RuleSetId, RuleSet, RuleSchedule; AdmissionPolicyId, AdmissionPolicy
    ├── block.rs          Candidate (input), ValidatedBlock (payload)
    ├── verdict.rs        ChainValid<'id, V>, InvalidBlock, Locus, TxSlot, Verdict<T>, refused
    ├── validate.rs       validate, tx_form, tx_against
    ├── harness.rs        #[cfg(test)] MockChain / MockView<'_, 'id> / FaultingView<'id>, assert_refused, boundary_pair, fixture::*
    └── *_tests.rs        census_tests, coverage_tests, rule_set_tests, verdict_tests, validate_tests, harness_probe_tests
```

### 4.1 `Flag`, `RowStatus`, `Row`, `CenRow`, `PolicyRow` (`census.rs`)

```rust
/// Which census denominator a row belongs to. Partitions first (ruling §9.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Flag { Consensus, Policy }

/// How a row is held: not yet; by a rule type the per-block stages run; by a
/// rule type this crate enforces at another site (slice 3 Q4 — CEN-E5 at
/// writer open; A1/A4 take it at cutover); by construction — the type system
/// or the wire's parser makes the violation unrepresentable, with a falsifier
/// the gate asserts (slice 4 Q4 — CEN-F2, F8, F19, F21); by the C++ ingest
/// driver until cutover (slice 1 Q2). `EnforcedAt`, `ByConstruction` and
/// `HeldByCxx` all leave `RuleSet::enforced()` (no per-block coverage can
/// contain them); the first two count as implemented — the enforcement is
/// Rust's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RowStatus {
    Pending,
    Implemented,
    EnforcedAt,     // unit: the path and the proof test stay on the registry entry
    ByConstruction, // unit: the property path and the falsifier stay on the entry
    HeldByCxx,
}

/// A census row identity. **Sealed**: implemented only by the two registry
/// enums; generic code (`Coverage<R>`, the harness) is written once over it.
pub trait Row: sealed::Sealed + Copy + Eq + Ord + Hash + fmt::Debug + fmt::Display + 'static {
    const FLAG: Flag;
    const ALL: &'static [Self];               // census order
    fn as_str(self) -> &'static str;          // register form: "CEN-A1"
    fn status(self) -> RowStatus;
    fn index(self) -> u8;                     // position in ALL == discriminant
}

// Generated by `census_rows!` (§5): one variant per enforced row of the flag.
#[repr(u8)] pub enum CenRow    { A1, A2, /* … */ M8 }   // 152 variants, Flag::Consensus (153 until CEN-F12 → bucket 3, 2026-09-21)
#[repr(u8)] pub enum PolicyRow { M1, M3, /* … */ M11 }  // 9 variants,   Flag::Policy
```

Each enum also gets the same surface as **inherent** `pub const fn`s
(`ALL`, `as_str`, `flag`, `status`, `index`) so `CenRow::A1.as_str()` needs no
trait import and is usable in `const` context; the `Row` impl delegates. `index`
is `self as u8` — `#[repr(u8)]` makes it the declaration position, and an enum
that outgrew 256 rows would fail to compile rather than wrap.

Variant naming: strip `CEN-`; `CEN-D1b` → `D1b` (six suffixed ids exist:
`D1b F14b G6b K1a K1b K5b`; all valid camel-case idents).

**Sibling enums, not one enum with a flag field** (round-1 ruling Q4). A
`Flag` field makes the partition a check someone can forget; two enums make a
policy row in consensus coverage unrepresentable. Two enums, two coverage
bitsets, two denominators — the two-line record the gate emits. `Flag` survives
as the trait constant the gate and `Coverage` read.

### 4.2 `RuleSetId`, `RuleSet`, `RuleSchedule`; `AdmissionPolicyId`, `AdmissionPolicy` (`rule_set.rs`)

```rust
/// Identifies the consensus rule set a `ChainValid` was checked under (ruling Q7).
/// **Its own space** — not `BlockHeader.major_version` (round-1 ruling Q5).
/// `connect` compares it to `RuleSchedule::rules_at(height)` and refuses a
/// mismatch as `StoreCannot` — the block was not judged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RuleSetId(u8);
impl RuleSetId {
    pub const GENESIS: Self = RuleSetId(1);
    pub const fn from_raw(v: u8) -> Self; pub const fn to_raw(self) -> u8;
}

/// The consensus rules as an explicit input. A named, **issued** value: `for_id`
/// resolves an id to one and nothing else constructs one. Parameters populate
/// as rules land; the first is `enforced` — the rows this rule set holds a
/// block to, and the denominator `Coverage::is_complete_for` measures against.
/// The header version a rule set *admits* will be another — a parameter, never
/// the identity.
#[derive(Clone, Copy, PartialEq, Eq)]                 // Debug by hand: prints the row *count*
pub struct RuleSet { id: RuleSetId, enforced: &'static [CenRow], header_major_version: u8, difficulty: DifficultyRule }
pub enum DifficultyRule { Lwma1, Fixed(Target) } // `Fixed` only via `RuleSet::fakechain(NonZeroU128)` — CEN-D7 as data (slice 2 §4.5); `RuleSetId` is then NOT a proxy for rule-set equality
impl RuleSet {
    pub const GENESIS: Self;                           // enforced: CenRow::ALL
    const ISSUED: &'static [Self];                     // every rule set a schedule may name
    /// The rule set an id names; `None` for an id no schedule has issued.
    pub fn for_id(id: RuleSetId) -> Option<Self>;
    pub const fn id(&self) -> RuleSetId;
    /// The consensus rows this rule set enforces, in census order.
    pub fn enforced(&self) -> impl Iterator<Item = CenRow> + '_;
}

/// Height → rule set, per network. Nettype selects **data** (rule 71): three
/// schedule values, one `rules_at`, no `match network` anywhere a rule runs.
/// Seeded as the identity schedule today (every network, every height →
/// `GENESIS`), which is what the shipped one-entry hardfork table means; the
/// function exists so R4's state-dependent activation has a place to land
/// without touching a caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleSchedule {
    genesis: RuleSetId,                                // in force from ZERO — not optional
    steps: &'static [(BlockHeight, RuleSetId)],        // later activations, strictly ascending, none at ZERO
}
impl RuleSchedule {
    pub const fn for_network(network: shekyl_address::Network) -> Self;
    /// The rule set in force at `height`: the last step at or below it, else `genesis`.
    pub fn rules_at(&self, height: BlockHeight) -> RuleSetId;
}
// `const fn well_formed(&RuleSchedule) -> bool` — steps ascending, none at ZERO
// (it would shadow `genesis`), every named id in `RuleSet::ISSUED` — is
// `const`-asserted for each schedule `for_network` can return: a malformed
// schedule is a compile error, never a height at which `rules_at` has no answer.

/// Relay/pool policy. A separate input with a separate id, never merged into
/// `RuleSet` (ruling §8). Consumer: DRS-E5. Staged here because §7.5.1 lists it;
/// increment 1 stages the identity only (`GENESIS`, `id()`), E5 adds parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AdmissionPolicyId(u8);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionPolicy { id: AdmissionPolicyId }
impl AdmissionPolicy { pub const GENESIS: Self; pub const fn id(&self) -> AdmissionPolicyId; }
```

No `From<RuleSetId> for AdmissionPolicyId` or the reverse, ever; no
`From<u8>`/`PartialEq<u8>` on `RuleSetId` — the 1:1 with `major_version` is a
fact about today's table, not a definition, and equality would erase the
distinction the function preserves. Both refusals are pinned by `compile_fail`
doctests on the id types.

*Implementation delta (commit 4).* The round-2 sketch carried the schedule as a
non-empty `steps` slice with `steps[0].0 == ZERO` as a documented invariant;
the landed shape splits `genesis` out as a non-optional field so "no rule set
in force at genesis" is unrepresentable rather than asserted, and `rules_at`
has no `expect`. `RuleSet` gained its first parameter, `enforced`, so
`enforced()` reads data rather than returning `CenRow::ALL` regardless of
`self`. Same public API.

### 4.3 `ChainView<'id>`, `AtHeight<T>`, `RecordedBlock` (`view.rs`)

```rust
/// A by-height lookup against the recorded chain. Matched exhaustively;
/// deliberately **no** `Option`-shaped combinators (no `?`, `map`,
/// `unwrap_or_*`, `is_none_or`) and no `Default` — an absent block is a
/// refusal the rule writes at the `AboveTip` arm, never a pass it falls into.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtHeight<T> {
    /// The chain recorded `T` at that height.
    Recorded(T),
    /// No block has ever been recorded at that height (it is above the tip).
    /// Heights at or below the tip are dense — the store's invariant, not a
    /// view fact — so this is the *only* absence a view can report.
    AboveTip,
}

/// A block the chain has **recorded** (ruling Q4). Fields justified per Q3:
/// `hash` — CEN-A2 (`prev_id == top_hash`), CEN-A4 (parent is known);
/// `header` — CEN-C2/C3 (the timestamps of the 11 preceding blocks).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedBlock { pub hash: BlockHash, pub header: shekyl_wire::BlockHeader, pub cumulative_difficulty: CumulativeDifficulty } // the third field landed with 4.D (slice 2): the LWMA-1 window's work

/// The narrow, read-only view a rule consumes. Implemented by the store over
/// its `WriteBatch<'_, 'id>` (S-CHAIN-W) and by `MockView<'id>` in this crate's
/// tests. `'id` is the transaction brand: a `ChainValid<'id, V>` is minted
/// only against the `V: ChainView<'id>` it names, of the same `'id`.
pub trait ChainView<'id> {
    /// What the view's **substrate** can fail with: the store's engine error
    /// for the projection, `Infallible` for the mock. Opaque to every rule —
    /// no bound, so nothing in this crate can inspect, match, or convert it
    /// (G2 by genericity). A fault is not a verdict: `validate` returns it
    /// *outside* the `Result<ChainValid, InvalidBlock>` and the caller halts.
    type Fault;

    /// CEN-I7 (chain-wide key-image uniqueness); CEN-L1's chain half.
    fn has_key_image(&self, key_image: &KeyImage) -> Result<bool, Self::Fault>;
    /// CEN-A2, CEN-A4, CEN-C2, CEN-C3.
    fn block_at(&self, height: BlockHeight) -> Result<AtHeight<RecordedBlock>, Self::Fault>;
    /// CEN-I12 (the membership anchor is the tree state at `ref_height`).
    fn root_at(&self, height: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Self::Fault>;
    /// CEN-A2 (`hash`); B5 (and 4.C, CEN-F5 later) via `Tip::connecting_height`.
    /// B1 does not read the tip: the rule set is an input. `None` is the empty
    /// chain — slice 1, Q1.
    fn tip(&self) -> Result<Option<Tip>, Self::Fault>;
}

/// The last recorded block. `Option`, not a bespoke absence enum: an empty
/// chain has no valid-looking alternative, so `None` cannot read as data
/// (`CHAIN_RULES_SLICE_1.md` §2). Composed by the store's `RecordedTip`.
pub struct Tip { pub height: BlockHeight, pub hash: BlockHash }
```

Three of the ruling's illustrative four (`output_at` — §3.3) plus `tip()`,
added by slice 1 with CEN-A2 and CEN-B5 (**Q12-2 discharged**; *records-was:*
increment 1 shipped without it, "not added here without its row"). No
`fork_version()` / `rule_set()` on the view (ruling Q7). The trait has no
`'id`-carrying method — the brand lives in the implementor's type and in
`ChainValid<'id, V>`; the trait's parameter is what ties the two in
`validate`'s signature, and `V` names the implementor itself.

**Why a fault channel (Q12-1).** The store's projection reads a redb
transaction; reads can fail. An infallible trait would leave the projection
two bad options — panic through the validator, or answer wrongly and hope the
caller checks a side flag before honouring the verdict. `Result<_, Self::Fault>`
makes the three ruled error classes three *positions* in one signature
(§4.6): `Err(fault)` the substrate could not answer; `Ok(Err(InvalidBlock))`
judged and refused; `Ok(Ok(ChainValid))` judged and passed. The mock's `Fault =
Infallible` costs rules nothing; the store's is `StoreError`, which this crate
never names.

### 4.4 `Candidate`, `ValidatedBlock` (`block.rs`)

```rust
/// The untrusted input to `validate`. Public fields; `#[non_exhaustive]` so a
/// later component is a constructor-site addition, not a breaking literal.
#[non_exhaustive]
pub struct Candidate { pub block: shekyl_wire::Block, pub transactions: Vec<shekyl_wire::Transaction> }
impl Candidate { pub fn new(block: shekyl_wire::Block, transactions: Vec<shekyl_wire::Transaction>) -> Self; }

/// The typed payload a `ChainValid` wraps. Constructed only by `validate`.
pub struct ValidatedBlock {
    hash: BlockHash,
    block: shekyl_wire::Block,          // kept whole: what the store persists is what the rules saw
    miner_tx_hash: TxHash,
    transactions: Vec<(TxHash, shekyl_wire::Transaction)>,   // ruling Q4/L4: one value per identity
}
impl ValidatedBlock {
    pub fn hash(&self) -> BlockHash;
    pub fn block(&self) -> &shekyl_wire::Block;
    pub fn header(&self) -> &shekyl_wire::BlockHeader;
    pub fn miner_tx(&self) -> (TxHash, &shekyl_wire::Transaction);
    pub fn transactions(&self) -> &[(TxHash, shekyl_wire::Transaction)];
}
```

In increment 1, `validate` derives `hash` and every `TxHash` (`Block::hash`,
`Transaction::hash`) and pairs them. It does **not** check the supplied bodies
against `block.transaction_hashes` — that is a 4.G rule and lands with slice 7.
CEN-B6 is the block-identity **definition**: `ValidatedBlock::derive` obtains
the hash from `B6::identity`, which records the row in coverage there — not a
`BlockRule` with a check that always passes (B7 is the no-op *policy* that
still runs through `rules::run`).

**The "check that always passes" test is run over the adversarial input
space, not the conforming one** (rule 47, "Run the cannot-fail test against
the adversarial input space"; slice 2, 2026-09-19). A refusal unreachable on
every valid chain is not dead if a corrupt store or a non-conforming peer can
reach it. Fold into a type only what cannot fail over the inputs the rule
exists to refuse; B6 qualifies (no input makes the identity function fail), a
refusal reachable from bad data does not.

**The worked example this paragraph first used was itself wrong, and the
correction is the sharper lesson (DRS-E2 RD-F17, 2026-09-20).** It said
CEN-D6's zero-target arm "never fires on a conforming chain" and fires only
on a corrupt view. LWMA-1 has **no output floor**: with every solvetime at
the `+6T` clamp the formula is zero for `avg_D ≤ 6`, so a **conforming**
slow chain derives a zero next target. The arm was therefore reachable from
valid data — which makes it a *rule's refusal* (the census: "a zero
next-block difficulty rejects the block"; the C++ refuses), not a
store-invariant fault. `Corrupt::ZeroTarget` is deleted; `D6::mint` returns
the CEN-D6 verdict. So the test has a third outcome beside "fold into a type"
and "keep the refusal": **re-classify** — a refusal reachable from valid
inputs belongs to the rules, not to the store's belts, and mis-filing it as
corruption would have halted the writer on a chain the C++ merely refuses a
block on.

The `Block` is kept **whole** rather than decomposed into header + miner tx
(the round-2 sketch): the header's `transaction_hashes` are part of what
`Block::hash` commits to and part of what S-CHAIN-W persists, and until the
4.G body rule lands nothing has established that they equal the supplied
bodies' hashes — so a store reconstructing the block from `(header, miner_tx,
transactions)` could write a blob that differs from the candidate the rules
judged. Keeping the block as received removes the reconstruction; the miner
tx is then reached through it (`miner_tx()` returns `(TxIdentity, &Transaction)`)
rather than duplicated.

**UPDATE 2026-09-15 (S-CHAIN-W commit 4, SCW-10 — owed to this consumer, landed by it):** the per-tx identity is
`TxIdentity { hash: TxHash, prunable_hash: PrunableHash }`, both derived once in
`validate` (`Transaction::hash`, `Transaction::prunable_hash`). The prunable digest is
the fourth component of a spend's txid and the value the store records as
`txs_prunable_hash`; for a coinbase it is `keccak256("")` — what the C++ store
writes — not the txid's null-hash substitute. Q4 holds: the store records it and
never derives it.
**UPDATE 2026-09-17 (slice 1 / `PDM-Q-F26` items 1–2):** the identity is
`TxIdentity { hash, pqc_auth_hash: Option<PqcAuthHash>, prunable_hash }`,
populated from `Transaction::txid_parts()` — one construction, each
discardable region hashed once. The `txs_pqc_auth_hash` store row (item 3)
landed as S-CHAIN-R amendment A3 (PR #772).

### 4.5 `Coverage<R>` (`coverage.rs`); `ChainValid<'id, V>`, `InvalidBlock`, `Locus` (`verdict.rs`)

```rust
/// The set of rows of one flag a verdict actually evaluated. A bitset over
/// `R::index()`: four words cover the whole `u8` index space, so `insert` has
/// no out-of-range case.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Coverage<R: Row> { words: [u64; 4], _rows: PhantomData<R> }
pub type RuleCoverage   = Coverage<CenRow>;
pub type PolicyCoverage = Coverage<PolicyRow>;   // E5's; one alias, staged with AdmissionPolicy
impl<R: Row> Coverage<R> {
    pub const EMPTY: Self;
    pub fn contains(&self, row: R) -> bool;
    pub fn len(&self) -> usize; pub fn is_empty(&self) -> bool;
    /// Rows in census order — persist `as_str()`, never `index()` (the bitset
    /// slot shifts when the census inserts a row).
    pub fn iter(&self) -> impl Iterator<Item = R> + '_;
    pub(crate) fn insert(&mut self, row: R); pub(crate) fn union(&mut self, other: &Self);
}
impl Coverage<CenRow> {
    /// `true` iff every row `rule_set.enforced()` yields is contained.
    /// Empty coverage is never complete. Only complete coverage is parity evidence.
    pub fn is_complete_for(&self, rule_set: &RuleSet) -> bool;
}
// Debug: the row list, not the words.

type Brand<'id> = core::marker::PhantomData<fn(&'id ()) -> &'id ()>;   // private

/// A block judged valid under `rule_set` against one view of one transaction.
pub struct ChainValid<'id, V> {
    block: ValidatedBlock,
    rule_set: RuleSetId,
    coverage: RuleCoverage,
    _brand: Brand<'id>,
    _view: PhantomData<fn(V) -> V>,   // invariant in the view type — G4
}
impl<'id, V: ChainView<'id>> ChainValid<'id, V> {
    pub fn block(&self) -> &ValidatedBlock;
    pub fn rule_set_id(&self) -> RuleSetId;
    pub fn coverage(&self) -> &RuleCoverage;
}
// Debug, no Clone (a second copy of a brand-bearing token has no meaning). The
// brand is invariant: a `compile_fail` doctest pins that `ChainValid<'long>`
// does not coerce to `ChainValid<'short>` even with `'long: 'short`.

/// Where in the candidate a refusal points. One verdict type for block-, tx- and
/// input-level refusals (handoff §2: "prefer one verdict type with a locus field").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TxSlot { Miner, Listed(usize), Lone }   // Lone: judged by tx_form/tx_against outside a block (the pool)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Locus { Block, Tx { slot: TxSlot }, Input { slot: TxSlot, input: usize } }
// Positions are `usize`: a locus indexes the candidate's in-memory `Vec`s, and
// is not a wire field (the round-2 sketch's `u32` was). Both `Display`:
// `tx #2 input #0`, `miner tx`, `block`.

/// The verdict. Names the census row; carries nothing a store error could map onto.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InvalidBlock { pub rule: CenRow, pub locus: Locus }
// Display `"{rule} refused at {locus}"` and `std::error::Error` are written by
// hand (eight lines); `thiserror` is not pulled into the crate for them.

/// Judged-and-refused (`Err`) or judged-and-passed (`Ok`). Never a fault.
pub type Verdict<T> = Result<T, InvalidBlock>;
```

### 4.6 `form`, `validate`, `tx_form`, `tx_against` (`validate.rs`); `Substrate` (`substrate.rs`); `Fault` (`fault.rs`)

**Two stages since slice 2 (2026-09-19; `CHAIN_RULES_SLICE_2.md` §4.2,
Q1/Q8/Q9 as ruled).** The partition is view-dependence and nothing else.

```rust
/// The world a block is judged in, not the chain: a clock (CEN-C1) and a
/// RandomX longhash (CEN-D2). Implemented by the daemon; mocked in tests.
pub trait Substrate {
    type Fault;
    fn local_clock(&self) -> Result<Timestamp, Self::Fault>;
    fn longhash(&self, pow_blob: &[u8], seed: &BlockHash) -> Result<PowHash, Self::Fault>;
}

/// Stateless — outside the write transaction, parallel, expensive. The
/// caller CLAIMS the rule set in force and the seed at `seedheight(h)`.
pub fn form<S: Substrate>(
    candidate: Candidate, rule_set: &RuleSet, substrate: &S,
    seed: BlockHash, attempt: FormAttempt,
) -> Result<Verdict<StructurallyValid>, S::Fault>;

/// View-bound — inside the transaction C2-R8 Q3 projects the view from.
/// Verifies the claims first; a refuted claim is a `Fault::Stale`, never a
/// refusal (unproven ≠ disproven); redo `form` as the payload's `Retry` allows.
pub fn validate<'id, V: ChainView<'id>>(
    formed: StructurallyValid, view: &V, rule_set: &RuleSet, trust: &Trust,
) -> Result<Verdict<ChainValid<'id, V>>, Fault<V::Fault>>;

/// What this node takes on the release's word — orthogonal to `RuleSet`
/// (PDM-Q5 / PDM-Q-F27; slice 3 Q1). Carries the release anchors (CEN-E1
/// reads them per block); slice 6 adds the posture arm by a second
/// constructor, `Trust::below_anchor(anchors)` (PDM-Q5 :293: band 1's
/// skeleton), and no existing caller changes.
pub struct Trust { anchors: ReleaseAnchors /* , posture — slice 6 */ }
impl Trust { pub const UNANCHORED: Self; pub const fn full(anchors: ReleaseAnchors) -> Self; pub const fn anchors(&self) -> &ReleaseAnchors; }

/// The release-carried anchor table, per network — `const` data shipped with
/// the binary (PDM-Q5 "trusted with the binary"; never an operator-editable
/// carrier), strictly ascending, const-asserted well formed. Empty on every
/// network today (`no_release_has_shipped_an_anchor_yet` pins it).
pub struct Anchor { pub height: BlockHeight, pub hash: BlockHash }
pub struct ReleaseAnchors { entries: &'static [Anchor] }
impl ReleaseAnchors {
    pub const EMPTY: Self;
    pub const fn for_network(network: Network) -> Self;
    pub fn expected_at(&self, height: BlockHeight) -> Option<BlockHash>;   // CEN-E1's read
    pub const fn current(&self) -> Option<Anchor>;                           // `C`
    pub fn covers(&self, height: BlockHeight) -> bool;                       // band 1: `height ≤ C`
    /// CEN-E5, run once by the writer at open; the remedy is the writer's.
    pub fn conflict_with<'id, V: ChainView<'id>>(&self, view: &V) -> Result<Option<AnchorConflict>, V::Fault>;
}
pub struct AnchorConflict { pub height: BlockHeight, pub expected: BlockHash, pub recorded: Option<BlockHash> }
impl AnchorConflict { pub const fn remedy(&self) -> Remedy; }
pub enum Remedy { RefuseToRun /* at genesis */, PopTo(ChainCount) /* stop at max(h − 2, 1) blocks; the tip is count.tip() */ }

pub enum Fault<V> { View(V), Stale(Stale), Corrupt(Corrupt) }
pub enum Stale { Seed { claimed, expected, retry: Retry }, RuleSet { formed_under: RuleSet, in_force: RuleSet, retry } }
pub enum Retry { Again(FormAttempt), Exhausted }          // MAX_FORM_ATTEMPTS = 3
pub enum Corrupt { CumulativeDifficultyNotMonotone { at }, CumulativeDifficultyOverflow }   // ZeroTarget deleted 2026-09-20 (RD-F17): zero is CEN-D6's verdict

/// Stateless per-tx rules (4.H). Shared verbatim by connect and pool admission.
pub fn tx_form(tx: &shekyl_wire::Transaction, rule_set: &RuleSet) -> Verdict<RuleCoverage>;

/// Stateful per-tx rules (4.I). The pool passes its `PoolView` decorator here.
pub fn tx_against<'id, V: ChainView<'id>>(
    tx: &shekyl_wire::Transaction, view: &V, rule_set: &RuleSet,
) -> Result<Verdict<RuleCoverage>, V::Fault>;
```

Generic over `V: ChainView<'id>` (not `&dyn`) so E5's decorator implements the
trait without this crate naming it. Inside a rule, `?` propagates a **fault**
and only a fault; a refusal is always written out as `Ok(Err(InvalidBlock {
rule, locus }))` at the site that judged — the row is named where the decision
is made. `validate` calls `tx_form` then `tx_against` for the miner tx and each
listed tx, re-homing a `Locus::Tx { slot: Lone }` / `Locus::Input { slot: Lone,
.. }` to the real `TxSlot`, unions the coverages, and mints the `ChainValid`.
Block-level **predicates** run in census order, each through
`rules::run_form` (stateless, in `form`) or `rules::run` (view-bound, in
`validate`), inserting `R::ROW` iff `R` passed. **Definition** rows record at
their derivation site: CEN-B6 at `B6::identity` (in `form`, carried on `StructurallyValid::hash`);
CEN-D2 at `D2::longhash` (in `form`); CEN-C3 at `C3::window`, CEN-D4 at
`D4::target` (D7 consulted inside it, D6 recorded at every `Target`
production — `D6::mint` for LWMA-1, `D6::record` for genesis-block `1` and
Fakechain `Fixed`), CEN-D1b at `D1b::record` — all derived once in
`validate` before the predicate list and read through `BlockContext`
(connecting height, tip, MTP window, target; C1's genesis exemption is
`connecting.is_zero()`). CEN-D3 is a **verification
of a claim**, recorded at `D3::verify_seed`, whose failure is `Fault::Stale`.
`Stale::RuleSet` compares the `RuleSet` by value: a Fakechain `Fixed`
target reuses `RuleSetId::GENESIS`, so the id is not the set. Stage
membership: `form` runs B1, B2, B7 and derives B6 and D2;
`validate` verifies D3, derives C3/D4/D6/D7/D1b, then runs A2, B5, C1, C2,
D1. `StructurallyValid` carries the clock reading (`judged_at`) — **the
verdict is time-dependent**: anything that caches or defers one lets CEN-C1's
leg go stale silently, so the instant is carried, not forgotten. `tx_form` /
`tx_against` are still empty and return `RuleCoverage::EMPTY` until 4.H/4.I.

The conversion ban (G2) covers the crate's own fault tokens: no `From`/`Into`
between `Stale`/`Fault` and `InvalidBlock`, no arm mapping one onto the other
(`check_store_error_conversion_ban.py`, clauses 1 and 3, with the qualified
`Fault::View(_) => InvalidBlock…` arm so the view's fault cannot be laundered
through the wrapper).

---

## 5. The registry macro and how the gate reads it

### 5.1 Invocation shape (two invocations, one per flag, in `census.rs`)

```rust
census_rows! {
    /// Consensus rows — the `C`-flagged enforced denominator.
    pub enum CenRow: Consensus {
        // 4.A — Acceptance topology
        A1 pending,
        A2 pending,
        // …
        // 4.C — Timestamps (slice 2 flips these)
        C1 pending,
        // an implemented entry, once a rule lands:
        // C3 implemented(rules::timestamps::cen_c3),
        // …
    }
}

census_rows! {
    /// Policy rows — the `P`-flagged enforced denominator.
    pub enum PolicyRow: Policy {
        M1 pending, M3 pending, /* … */ M11 pending,
    }
}
```

Grammar: header `pub enum <Name>: <Consensus|Policy> { … }`; per entry
`<Var> <pending | implemented(<rust::path>) | enforced_at(<rust::path>, "<test_fn>") | held_by_cxx("<repo/file.cpp>", "<test>")> ,`
with optional `///` doc and `//` comments between entries. `enforced_at`
(slice 3, Q4 — [`CHAIN_RULES_SLICE_3.md`](CHAIN_RULES_SLICE_3.md)) marks a
row **this crate** enforces at a site other than the per-block stages (CEN-E5
at writer open); it takes the same compile pins as `implemented` plus a Rust
`#[test]` in the crate that the gate asserts is *defined* (rule 47), leaves
`RuleSet::enforced()` like a hold, and counts as implemented unlike one.
`held_by_cxx`
(slice 1, Q2 — [`CHAIN_RULES_SLICE_1.md`](../completed/CHAIN_RULES_SLICE_1.md) §4.1) marks
acceptance topology the C++ ingest driver decides until cutover; the value is
the C++ **test that proves the holder refuses**, which the gate asserts
exists, and the row leaves `RuleSet::enforced()` so per-block completeness is
`E − H − O` (`O` the at-open rows). Entries are in census §4 order restricted to the flag
(subsystem, then row order within the table) — the gate asserts this so
`index()` is census-derived, not arbitrary.

### 5.2 What the macro emits

- `#[repr(u8)] pub enum <Name> { $var, … }` with the derives in §4.1 and the
  header's doc;
- inherent `ALL`, `as_str` (`concat!("CEN-", stringify!($var))`), `flag`
  (the header flag), `status`, `index` (`self as u8`); `Display`; the `Row`
  impl delegating to them; the sealed-trait impl;
- the **two pins** per `implemented(path)` (slice 1 shape, PR #762): the
  **G9 pin** `use $path as _;` — a path that does not resolve is a compile
  error (`use` names the item without instantiating it) — and the **SCW-18
  pin** `const _: () = assert!(matches!(<$path as rules::Bound<$name>>::ROW,
  $name::$var), …)` — a type bound to another row is a compile error.
  `Bound<R>` is the registry-generic face of `rules::Rule` (every `Rule` is
  `Bound<CenRow>`; E5's policy rules will be `Bound<PolicyRow>`), so the one
  macro serves both enums. The gate reads the same braces the compiler did;
  its entry grammar is unchanged (a type path is a `rust::path`).

### 5.3 How the gate reads it

`check_chain_rules_coverage.py` reads `rust/shekyl-chain-rules/src/census.rs`,
strips comments with the shared `strip_c_comments.py` (the conversion-ban gate's
stripper), locates every `census_rows!` invocation by brace depth, reads each
header's enum name and flag, and asserts **exactly one invocation per flag**. It
parses entries with one regex. It also asserts `lib.rs` contains `mod census;`
so the file it parsed is one the crate compiles. It does **not** run `cargo`;
the compile-time half of G9 is the `use $path as _;` the macro emits (§5.2).

---

## 6. The completeness gate — `scripts/ci/check_chain_rules_coverage.py`

### 6.1 Census side — reuse, no second parser

`from _census import Refused, Row, parse_census` (via `sys.path` on
`scripts/ci/`, the same way the conversion-ban gate loads the stripper) and
call `parse_census(text)` → `list[Row(id, subsystem, flag, bucket, bound)]`.
Header-derived column indices, `_gfm_table.py` fence/pipe handling, and every
census refusal come from that one parser. The enforced set per flag is
`{r.id : r.flag == F and r.bucket != 3}`; ratified is `bucket in (1, 2)`.

**`scripts/ci/_census.py` is the parser's home** (extracted 2026-09-15, in
this PR). It carries `Row`, `Refused`, `parse_census`, the bound regex
(`BOUND_RE_TEXT`) and the GFM table-shape helpers (`row_cells`,
`require_delimiter`, `unfenced`); `check_drs_e6_partition.py` imports the
same names, so the two gates are siblings of one parser rather than of each
other. Round 1 ruled the extraction owed once PR #751 merged (a gate
importing a sibling gate is a hidden coupling — rename the sibling and the
importer breaks confusingly); #751 merged 2026-09-15 and the extraction
landed the same day. Neither gate re-tests the parser separately: both
`--selftest` runs drive their refusals through `parse_census`, so the
module's refusals are exercised red twice per CI run.

### 6.2 Subjects asserted (rule 47) and refusals

Every refusal is a non-zero exit with the derivation in the message, and every
one is exercised red by `--selftest`:

Exit codes follow the partition gate: **2** for a missing or unparseable subject
(`Refused`), **1** for a registry/census disagreement or a G1 violation (the
figures are still printed, as derived), **0** when they agree.

| Subject / property | Refusal (exit) |
| --- | --- |
| census file readable, §4 tables present, ≥ 1 `CEN-` row, ≥ 1 bound row | inherited from `parse_census` (2) |
| `rust/shekyl-chain-rules/src/census.rs`, `lib.rs`, `Cargo.toml` exist | `registry file missing` / `crate root missing` / `Cargo.toml missing` (2) |
| `lib.rs` declares `mod census;` (comments stripped first — a commented-out declaration is absent) | `registry not compiled by the crate` (2) |
| ≥ 1 `census_rows!` invocation; braces balance | `no census_rows! invocation` / `has no closing brace` (2) |
| exactly one `census_rows!` per flag; header parses; flag ∈ {`Consensus`, `Policy`} | `no registry for flag F` / `N registries for flag F` / `unparseable header at line N` / `unknown flag` (2) |
| ≥ 1 entry per registry | `registry <Name> empty` (2) |
| entry grammar — `Var pending,`, `Var implemented(rust::path),`, `Var enforced_at(rust::path, "test_fn"),` or `Var held_by_cxx("file", "test"),`; `implemented` / `enforced_at` **must** carry a non-empty path; `enforced_at` **must** carry a quoted identifier that is a `#[test] fn` defined in the crate (a mention in a comment or a call is not a definition); `held_by_cxx` **must** carry a quoted repo-relative file and a quoted identifier | `unparseable entry at line N` (2) |
| no attribute on an entry (a `#[cfg]` the gate cannot evaluate would let the compiled enum and the counted enum differ; the enum's own attributes are fine) | `attribute on entry at line N` (2) |
| nothing after the enum's closing brace inside the invocation | `text after the enum body at line N` (2) |
| no duplicate variant across both registries | `duplicate entry X` (1) |
| every entry maps to an enforced census row (`CEN-` + var) **of its registry's flag** | `entry X (line N) has no enforced census row with flag F` (1; catches bucket-3 rows, typos, and a row filed under the wrong enum) |
| every enforced census row has an entry in the enum of its flag | `census row X (flag F) missing from registry <Name>` (1) |
| entries in census order within the flag — judged on the ids both sides share, so a missing row reports once, not as an order cascade | `registry <Name> order differs from census at X` (1) |
| every `held_by_cxx` entry's census row places the rule in C++ (`site(s)` names a C++ source — `.cc .cpp .cxx .h .hpp .inl`, one shared list `CXX_SUFFIXES` — or is a bare line citation, the census's §4 default `blockchain.cpp`) | `held_by_cxx entry X (line N): the census places this row at … which cites no C++ source` (1) |
| every `held_by_cxx` entry's holder is a **repo-relative C++ file** (same suffix list; no absolute path, no `..`) — a Rust or Markdown file that contains the identifier is not a C++ holder, and the reader also refuses absolute/`..` before resolution so the registry cannot be environment-specific | `held_by_cxx entry X (line N): holder … is not a repo-relative C++ file` (1) |
| every `held_by_cxx` entry's cited file is in the repo — its absence is cutover, and the hold expires with its holder | `held_by_cxx entry X (line N): holder file … is not in the tree — the hold has expired` (1) |
| every `held_by_cxx` entry's cited test identifier is in that file (word-bounded, comments stripped), so a hold names a test that proves the holder refuses, not a token (PWD-B10) | `held_by_cxx entry X (line N): holder test … is not in …` (1) |
| a `core_tests` holder (`tests/core_tests/…`) is **registered** — `GENERATE_AND_PLAY(<test>)` in `tests/core_tests/chaingen_main.cpp`, comments stripped — because an unregistered generator compiles and is never played; gtest holders self-register through `TEST(...)` | `… is defined but not registered with GENERATE_AND_PLAY …` / `core_tests registry … is not in the tree` (1) |
| `Cargo.toml` names neither `redb` nor `shekyl-chain-store` in **any** dependency table (`[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, `[target.*.dependencies]`; a rename via `package = "redb"` reports the package) — parsed with `tomllib`, so a comment mentioning both is not a hit | `store handle in Cargo.toml: <pkg> under [table]` (1; G1, direct) / `Cargo.toml unparseable` (2) |

### 6.3 Output format (ruling §9.4, verbatim shape)

```text
consensus: implemented I / validator-enforced (E−H)   held-by-cxx H   at-open O   enforced E   ratified R / enforced E   (E = C-rows − bucket 3; validator-enforced = E − held; per-block completeness over E − held − at-open)
policy:    implemented I / validator-enforced (E−H)   held-by-cxx H   at-open O   enforced E   ratified R / enforced E   (E = P-rows − bucket 3; validator-enforced = E − held; per-block completeness over E − held − at-open)
```

`I` = entries of that registry with status `implemented` **or `enforced_at`**
(Rust enforces both); `O` = entries with status `enforced_at` — printed so the
per-block completeness denominator `E − H − O` (what `Coverage::is_complete_for`
measures against) can be read off the line; `H` = entries with
status `held_by_cxx`; `E` = enforced rows of that flag from the census; `R` =
census rows of that flag in bucket 1 or 2. **`H` is a subtraction, not a
denominator** (slice 1, Q2 condition 3): `E` is printed and never moves for a
hold, so coverage cannot improve by moving rows out of scope — the failure the
two-number format exists to prevent. *Records-was:* increment 1's line was
`implemented I / enforced E   ratified R / enforced E`; the held terms were
added by the slice-1 `held_by_cxx` PR.
At increment 1 (records-was, verified with `check_drs_e6_partition.py
--describe` against the census in that worktree): `consensus: implemented 0 /
enforced 153   ratified 126 / enforced 153` and `policy: implemented 0 /
enforced 9     ratified 5 / enforced 9`. **After slice 1's first rules (PR
#762):** `consensus: implemented 3 / enforced 153` (4.B `3/7`), policy
unchanged. **After the `held_by_cxx` PR:** `consensus: implemented 3 /
validator-enforced 151   held-by-cxx 2   enforced 153   ratified 126 /
enforced 153` (A1, A4 held). **After slice 3 (2026-09-20):** `consensus:
implemented 18 / validator-enforced 151   held-by-cxx 2   at-open 1   enforced
153   ratified 126 / enforced 153` (E5 at open; the `at-open` term added by
that slice). **After the slice-4 precursor (2026-09-21):** `consensus:
implemented 18 / validator-enforced 150   held-by-cxx 2   at-open 1   enforced
152   ratified 126 / enforced 152` — the denominator moved for the first
time: CEN-F12, the dead decomposed-denomination gate, went to bucket 3 and
was deleted with its C++ (Q2 (a)); nothing was ported. **After slice 4
(2026-09-22):** `consensus: implemented 34 / validator-enforced 150
held-by-cxx 2   at-open 1   by-construction 4   enforced 152   ratified 126 /
enforced 152` (sixteen 4.F rows; the `by-construction` term added by that
slice — F2, F8, F19, F21). The figure moves with each slice and the landing
PR quotes its own.

`--describe` additionally prints, per census subsystem, `implemented / enforced`
and the list of implemented row ids, so a slice PR can quote its own delta.

**What each figure gates (RULED 2026-09-16; authority
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §7.6, minted by PR #760 —
this paragraph is the crate-side statement, not a second recording).** The
two numbers have two lifetimes. `implemented / enforced` is the
**parity-phase** figure: with the E2 comparator green over the replayed
chain, `implemented == enforced` — every enforced row evaluated, the
`is_complete_for` half of parity evidence — gates **cutover**, then stops
moving. `ratified / enforced` is the figure that **survives cutover**: C++
gone, comparator retired, this is the one line that stays red while an
inherited-never-judged row is still enforced, and it gates **release** —
`ratified == enforced` on the consensus line, each remaining bucket-4 row
either ratified/diverged by an R-round or ruled dead (bucket 3, leaving the
denominator). *Read against the landed text:* until this ruling the second
figure was printed (this section) and gated nothing — parity evidence as
defined (§3 of the DRS: coverage gaps, stubbed applies and passed-through
facts all empty) requires `implemented == enforced` only. The printing is
the mechanism; the gate is what §7.6 adds.

### 6.4 Wiring

`.github/workflows/docs-gates.yml`: two steps (`check_chain_rules_coverage.py`,
`… --selftest`) appended **after** the `check_drs_e6_partition.py` steps
(handoff §6: shared file, resolve by appending). That job has no Rust
toolchain and needs none for this gate.

### 6.5 The belt — `scripts/ci/check_chain_rules_no_store.sh` (G1, transitive)

One step in **`rust-audit-test.yml`**, immediately after
`check_test_only_features.py`, for the reason written at that step: it reads
`cargo tree`, so it runs where `install Rust` has run, not in `docs-gates.yml`
(relying on the hosted image happening to ship cargo is the accident that
placement note already names). *Round 2 correction:* round 1 wrote
"`build.yml`"; `build.yml` has no workspace Rust job — its only Rust step is
the toolchain-free debug-macro grep — so the belt would have had no cargo to
call.

Shape, and why it is not the one-liner round 1 sketched:

- **Fail-closed verdict.** Round 1's `cargo tree -p CRATE -i redb`, reading a
  non-zero exit as "absent", is fail-open: cargo exits 101 for "not in this
  subtree", for "no such package anywhere", and for a stale lockfile under
  `--locked` alike (measured: `-i redb`, `-i shekyl-chain-store`, and
  `-i no-such-package-xyz` all exit 101 identically). A broken resolve would
  read as a clean graph. The belt instead captures the crate's closure from
  **one** `cargo tree --locked -e normal,dev --target all -p shekyl-chain-rules --prefix
  none` call — `--target all` so a `cfg(windows)` / target-table arrival is
  not invisible on Linux CI — a cargo failure fails the assignment and the
  gate — and judges the captured text here: `^redb v` / `^shekyl-chain-store v`
  present ⇒ refuse, printing the path with `-i`.
- **Subjects first (rule 47).** The crate resolves as a workspace member
  (`--depth 0`); each banned name is a package the workspace resolves at all
  (`cargo pkgid`), so a store-engine rename turns the belt red with "update
  BANNED" rather than leaving a ban that names nothing; the closure is
  non-empty and its first line is the crate.
- **Edges.** `normal,dev` — a test-only store dependency is the mock-view
  inversion R8 banned, in test clothing. `build` edges are out of scope: a
  build script's graph is not linked into the crate.
- Verified red on both faults before wiring: a temporary
  `[dev-dependencies] shekyl-chain-store` produced two refusals, `redb` (via
  the store, the transitive case) and `shekyl-chain-store` (direct), each with
  its `cargo tree -i` path printed.

Today the adoption path is clean by luck of the graph (`shekyl-difficulty` 0
deps, `shekyl-economics` 1, none of `shekyl-fcmp`/`shekyl-crypto-pq` reach
`redb`); the belt is what makes §7.5.1's "imports neither" true as the
adoption increments arrive rather than asserted. `BANNED` in the belt and
`BANNED_PACKAGES` in the coverage gate are the same two names; keep them
together.

---

## 7. Raising the conversion-ban gate (in this PR) — DONE, commit 7

`check_store_error_conversion_ban.py` (as landed: 27 selftest cases; the live
gate on this tree reports `1143 files walked, 1 verdict-type definition(s);
clauses 1-3 clean`; negative control — renaming the definition — refuses):

- `verdict_defs == 0` becomes a refusal: `subject absent: no verdict-type
  definition found — InvalidBlock was minted in
  rust/shekyl-chain-rules/src/verdict.rs; if it moved, update VERDICT_TOKEN`;
- the header's "Clause 3 is armed and has no verdict type … The PR that mints
  `InvalidBlock` MUST turn `verdict_defs == 0` into a failure" paragraph is
  rewritten as the records-was it now is (dated), and the live sentence says
  the count is asserted `>= 1`;
- `--selftest` gains a case: a tree with a store error and **no** verdict
  definition must be refused;
- `VERDICT_TOKEN` is **unchanged** — one verdict type (`InvalidBlock`), locus
  field instead of a per-tx type.

Run after every rebase (the store lane owns `store/error.rs`).

---

## 8. Test plan

Every test's doc comment says what it bites against. Layout: sibling
`*_tests.rs` declared with `#[cfg(test)] #[path = "…"] mod …;` (build.yml's
lint scans them as production — no debug macros anywhere).

### 8.1 Registry (`census_tests.rs`)

- `as_str` round-trip on both enums: every `ALL` entry's `as_str()` starts with
  `CEN-` and `Display == as_str` (bites: a variant renamed without the prefix).
- `index` equals position in `ALL`, for both enums (bites: a hand-edited
  discriminant).
- `CenRow::FLAG == Consensus`, `PolicyRow::FLAG == Policy`; the two `as_str`
  sets are disjoint (bites: a row filed in both registries).
- The census **bijection is the Python gate's**, not re-tested in Rust (no
  second parser).

### 8.2 Coverage (`coverage_tests.rs`)

- `RuleCoverage::EMPTY.is_complete_for(&GENESIS) == false` (bites: an
  `is_complete_for` that reads "no missing rows" as `true` on empty).
- inserting every `CenRow` → `is_complete_for == true`; removing one → `false`
  (boundary pair).
- `Coverage<PolicyRow>` filled with every `PolicyRow` is a different type from
  `RuleCoverage` — pinned by a `compile_fail` doctest (`coverage.insert(PolicyRow::M1)`
  on a `RuleCoverage` does not compile). This is Q4's ruling as a test.
- `iter()` yields census order and matches `contains`; `len` matches.
- `InvalidBlock` equality is by `(rule, locus)`; `Display` carries `CEN-…`.

### 8.3 Brand and constructor pins (`lib.rs` doctests)

- `compile_fail`: `use redb::Database;`
- `compile_fail`: `use shekyl_chain_store::store::ChainStore;`
- `compile_fail`: `ChainValid { … }` / `ValidatedBlock { … }` from outside.
- `compile_fail`: cross-view handoff (on `validate`) —
  ```rust
  with_view(|outer| {
      with_view(|inner| {
          let valid = validate(formed(), &inner, &RuleSet::GENESIS, &Trust::UNANCHORED).unwrap().unwrap();
          connect(&outer, valid);   // fn connect<'id>(_: &View<'id>, _: ChainValid<'id, View<'id>>)
      })
  });
  ```
  (`with_view` is `for<'id> FnOnce(View<'id>) -> R`; the two `'id`s are
  distinct and invariant, so this does not type-check.)
- Also pinned this way (commit 4): `AtHeight` → `Option` via `.into()` and
  via `?`; `RuleSetId == u8`; `AdmissionPolicyId` → `RuleSetId`.

**Q8 amended by finding (commit 6).** The round-1 ruling took the default
`#[cfg(any(test, doctest))]` on `harness` so doctests could use the mock. That
does not work: `cfg(doctest)` is set only while rustdoc *scans* the crate to
collect snippets; each snippet is then compiled as a separate crate that
links the ordinary library build, where no `cfg(doctest)` item exists to
resolve (the Rust reference says so of the cfg; verified empirically at
commit 6 — a snippet naming `shekyl_chain_rules::harness::MockChain` fails
to resolve under `cargo test --doc`). So `harness` is `#[cfg(test)]` only, and the one
doctest that needs a branded view — the cross-view pin above — declares an
inline three-method `View<'id>` with its own `with_view`/`connect`. The
alternative, a `pub` harness behind a `test-support` feature, was not taken:
it would put a mock `ChainView` on the crate's public surface for one pin.

**A `compile_fail` proves *some* compile error — and only that, on this
toolchain.** rustdoc's `compile_fail,E0277` error-code form is checked on
nightly only; on the pinned stable (`rust-toolchain.toml`) the code is
silently ignored, so writing one claims a precision the gate does not have
(verified at commit 4: `E0999` passed). None is written. Instead every pin
was compiled once outside rustdoc to read the error it actually produces, so
a snippet that fails for a typo rather than for its reason is a review item,
not a hidden state. All eleven, at commit 8:

| pin | where | error |
| --- | --- | --- |
| `use redb::Database` | `lib.rs` | `E0432` unresolved import |
| `use shekyl_chain_store::store::ChainStore` | `lib.rs` | `E0433` failed to resolve |
| `RuleCoverage::EMPTY.contains(PolicyRow::M1)` | `coverage.rs` | `E0308` mismatched types |
| `RuleSetId::GENESIS == 1u8` | `rule_set.rs` | `E0308` mismatched types |
| `RuleSetId::from(AdmissionPolicyId)` | `rule_set.rs` | `E0277` `From` not satisfied |
| `AtHeight` → `Option` via `.into()` | `view.rs` | `E0277` `From` not satisfied |
| `AtHeight` via `?` | `view.rs` | `E0277` `Try` not implemented |
| `ChainValid<'long>` → `ChainValid<'short>` | `verdict.rs` | *lifetime may not live long enough* (no code; the invariance error) |
| `ChainValid { .. }` from outside | `verdict.rs` | `E0451` field is private |
| `ValidatedBlock { .. }` from outside | `block.rs` | `E0451` field is private |
| cross-view `connect(&outer, valid)` | `validate.rs` | `E0521` borrowed data escapes the closure (the inner brand cannot become the outer) |

The G1 pair is *not* `E0432` ×2 as an earlier draft of this section said —
an unknown crate root is `E0433`, an unknown item in a known crate `E0432`.
Exact-diagnostic pinning (`trybuild`) is not adopted: the pins here are
second lines behind the belt and the type shapes, not gates.

### 8.4 Rule sets and schedule (`rule_set_tests.rs`)

- `RuleSchedule::for_network(n).rules_at(h) == GENESIS` for every `Network` and
  `h ∈ {ZERO, 1, u64::MAX}` (the identity seed, pinned).
- `well_formed` refuses a step at `BlockHeight::ZERO` (it would shadow the
  non-optional `genesis` field); `genesis` is always issued. The identity
  schedule has `steps: &[]`.
- `RuleSet::for_id(GENESIS.id()) == Some(GENESIS)`; `for_id(from_raw(0))` and
  `from_raw(2)` are `None`.
- `RuleSetId::GENESIS.to_raw() == 1` — documented as coincident with
  `major_version == 1`, not defined by it; no `PartialEq<u8>`.

### 8.5 `validate` / `tx_form` / `tx_against` (`validate_tests.rs`)

- a well-formed candidate: `Ok(Ok(v))`, `v.coverage()` is exactly the landed
  block rows (`{A2, B1, B2, B5, B6, B7}` after the `tip()` PR — `covers_landed`
  holds, `is_complete_for` does not), `v.rule_set_id() == GENESIS.id()`.
  *Records-was:* increment 1 asserted empty coverage; #762 `{B1, B2, B7}`.
- payload: `block().hash() == BlockHash::from_bytes(candidate.block.hash())`;
  `transactions()[i].0 == TxIdentity { hash, pqc_auth_hash, prunable_hash }`
  of `tx` (from `Transaction::txid_parts`); `miner_tx().0` likewise, with the
  coinbase's `prunable_hash` pinned to `keccak256("")` and `pqc_auth_hash`
  `None` (bites: a pairing that hashes the wrong body, drops the miner tx,
  conflates the two digests, or labels a 3-part txid with a third component).
- `tx_form` / `tx_against` before 4.H/4.I land: `Ok(EMPTY)` / `Ok(Ok(EMPTY))`.
- a mock whose `Fault` is a unit type and whose `block_at` faults: `validate`
  returns `Err(fault)`, not a verdict (bites: a fault swallowed into a pass or a
  refusal). Increment 1 has no rule that reads the view, so this is exercised
  by the probe (§8.7), which does.

### 8.6 `KeyImage` relocation (`shekyl-types/src/tests.rs`; workspace)

- `KeyImage` `Debug` is `KeyImage(0000..)` (the moved test, verbatim);
  `from_canonical_bytes(b) == from_bytes(b)`; `as_bytes` round-trip.
- `compile_fail` doctest: `format!("{}", key_image)` — no `Display`.
- postcard bytes of `KeyImage` equal those of the bare `[u8; 32]`.
- `cargo test -p shekyl-engine-state --lib schema_snapshot` green before and
  after; `cargo test -p shekyl-archival-retention` (the `attestation_wire` KATs
  serialise key images) green after.

### 8.7 The harness and its probe (`harness.rs`, `harness_probe_tests.rs`)

Harness surface (`#[cfg(any(test, feature = "harness"))]` since slice 2 —
`pub mod` behind the `harness` feature for exactly one consumer, §8.8; the
probe tests stay `#[cfg(test)]`. A normal dependency enabling the feature is
a review finding; nothing in it is a production API. As landed, commit 6):

```rust
/// A recorded chain: blocks dense from height 0, roots keyed as the store keys
/// them (SCW-19: roots[h] = the state AT h; roots[0] = EMPTY; the root pushed with
/// block h is roots[h + 1]) — corrected by slice 1, whose B5 fixture caught the
/// mock one height off the store — and a key-image set.
pub struct MockChain { recorded: Vec<RecordedBlock>, roots: Vec<CurveTreeRoot>, key_images: BTreeSet<KeyImage> }
impl MockChain {
    pub fn push(self, block: RecordedBlock, root_after: CurveTreeRoot) -> Self; // height = recorded.len()
    pub fn with_key_image(self, key_image: KeyImage) -> Self;
    pub fn tip(&self) -> Option<Tip>;                                          // None when empty
    /// Project a branded view. `'id` is fresh per call (HRTB) — the mock's analogue of `ChainStore::write`.
    pub fn with_view<R>(&self, f: impl for<'id> FnOnce(MockView<'_, 'id>) -> R) -> R;
}
pub struct MockView<'a, 'id> { chain: &'a MockChain, _brand: Brand<'id> }   // impl ChainView<'id>, Fault = Infallible
/// A view whose every read faults — for the fault-channel tests.
pub struct Faulted;
pub struct FaultingView<'id>(Brand<'id>);                                    // Fault = Faulted; Default
pub fn infallible<T>(r: Result<T, Infallible>) -> T;                         // exhaustive match, never unwrap

/// Assert `result` is exactly `Err(InvalidBlock { rule, locus })`.
#[track_caller] pub fn assert_refused<T: Debug>(result: Verdict<T>, rule: CenRow, locus: Locus);
/// The last accepted value passes and the first rejected value fails with `rule` at `locus`.
#[track_caller] pub fn boundary_pair<T: Debug, V>(last_ok: V, first_bad: V, rule: CenRow, locus: Locus, f: impl Fn(V) -> Verdict<T>);

/// Well-formed values to mutate one field of.
pub mod fixture {
    pub fn coinbase(unlock_time: u64) -> Transaction;
    pub fn header() -> BlockHeader;
    pub fn candidate_on(chain: &MockChain, listed: Vec<Transaction>) -> Candidate; // on the tip: previous + root set (A2, B5)
    pub fn candidate(listed: Vec<Transaction>) -> Candidate;                        // genesis-shaped
    pub fn recorded(timestamp: u64) -> RecordedBlock;
    pub const fn root(byte: u8) -> CurveTreeRoot;
}
```

`push` rather than `with_block(h, ..)`: the mock records heights densely from
zero because that is the only shape a recorded chain has, and a builder that
let a test place height 7 with no height 6 would let a fixture describe a
chain the store cannot. `validate_tests.rs` was rewritten onto this harness in
the same commit; its private `Bare` view is gone.

**Probe rule** (the store crate's `ProbeCell` pattern): a `#[cfg(test)]`
function `probe_cen_c1<'id, V: ChainView<'id>>(&Candidate, &V) ->
Result<Verdict<()>, V::Fault>` that reads `view.block_at(ZERO)?` (so the fault
channel is exercised) and returns `Ok(Err(InvalidBlock { rule: CenRow::C1,
locus: Locus::Block }))` when `header.timestamp == 0`. It is a *label*, not an
implementation of CEN-C1 (the registry entry stays `pending`; the gate does not
see test code). Tests:

- `probe_harness_fires_on_the_named_row` — `assert_refused(probe(bad), C1)`
  passes; `boundary_pair(1, 0, C1, …)` passes.
- `#[should_panic] probe_harness_bites_wrong_row` — `assert_refused(probe(bad), C2)`.
- `#[should_panic] probe_harness_bites_ok` — `assert_refused(probe(good), C1)`.
- `#[should_panic] probe_boundary_bites_inverted_pair` — `boundary_pair(0, 1, …)`.
- `probe_propagates_a_fault` — against `FaultingView`, `probe` is `Err(Faulted)`.

A harness with no subject is a vacuous pass; the `should_panic` trio is what
makes this harness's own green mean something.

---


### 8.8 The mock reconciled against `BatchView` (`shekyl-chain-store/src/store/conformance_tests.rs`)

Every rule above is tested against `MockChain`; that the mock answers as the
store's `BatchView` does was **assumed** until slice 2 (F11). The
conformance harness makes it a gated property: the same chain is built
twice — connected into a real file through `connect`, and pushed into a
`MockChain` from the same blocks, `root_after` facts and derived work — and
`form` + `validate` run over **both** views for every shape the landed rules
can judge (well-formed, A2, B5, C1, C2/C3, D1, B1) at genesis admission, one
block and a full MTP window, asserting identical verdicts **and** identical
coverage row-lists. The reads are also compared directly (`block_at`,
`root_at` across and above the tip, `tip`) so a disagreement has a named
cause. Negative control: a mock keyed one height late is refused on B5 where
the store passes. It lives on the store side because G1 forbids this crate
from naming the store, and reaches the mock through the `harness` feature
(§8.7). The store crate still never names the verdict type: the test projects
a refusal to `(rule, locus)` through `Verdict`, so the conversion-ban gate
holds for its tests too. Not covered there, named: a full LWMA-1 window past
`N` (the store fixtures' root bytes cap the chain at 63) — the E2 replay is
that instrument.
## 9. Commit plan (rule 90; ≤ 10 commits, no AI trailers)

1. `types: move KeyImage into shekyl-types; mint CurveTreeRoot (E6 inc 1 pre-flight)`
   — `hash32!` third arm `redact, no_display`; `KeyImage` with
   `from_canonical_bytes`; `CurveTreeRoot`; `shekyl-crypto-pq` re-export; tests
   moved; snapshot/KAT runs recorded in the message.
2. `chain-rules: scaffold crate + census_rows! registry (DRS §7.5.1 item 1)` —
   `Cargo.toml`, workspace member, `lib.rs` with staging note and G1 pins,
   `census.rs` fully populated (153 + 9 at landing; 152 + 9 since CEN-F12's deletion, 2026-09-21), `census_tests.rs`.
3. `chain-rules: completeness gate check_chain_rules_coverage.py (ruling §9.4)`
   — gate + `--selftest` + `--describe`, docs-gates wiring, the
   `check_chain_rules_no_store.sh` belt in `rust-audit-test.yml`.
4. `chain-rules: ChainView<'id>, RuleSet/RuleSchedule/AdmissionPolicy, Candidate/ValidatedBlock (§7.5.1 items 2–4)`.
5. `chain-rules: ChainValid<'id>, InvalidBlock, Coverage<R>, validate/tx_form/tx_against (items 5–6)`
   + brand/ctor doctests + `coverage_tests`, `validate_tests`.
6. `chain-rules: negative-fixture harness + probe (item 8)`.
7. `ci: conversion-ban gate — verdict_defs == 0 is now a refusal (ruling §3.3)`.
8. `docs: CHAIN_RULES_CRATE.md increment 1 implemented; DRS §7 E6 row + §15; index; CHANGELOG` (§10).
   *(Planned title said "round 2 → implemented"; round 2 is implemented on its
   defaults, not closed — the reviewer closes it at PR review. Banner says so.)*

Each commit builds, `fmt`/`clippy` clean, tests green (rule 26 B5).

---

## 10. Documentation task (rule 91 — last)

- This doc: banner → `OPEN — increment 1 implemented … round 2 awaits the
  reviewer's ruling at PR review` (not "rounds 1–2 closed" as first planned:
  §12's defaults are what landed, and only the reviewer closes a round); no PR
  number is written before one exists. §11/§12 stay as the record; stays in
  `docs/design/` while increments 2+ are open (it owns their template).
- `DAEMON_REDB_STORE.md`: banner (line 11: S-CHAIN-W no longer "remains gated
  on DRS-E6 increment 1"), §7 `DRS-E6` row → "increment 1: LANDED 2026-09-15"
  (no PR number — none exists at write time), §7.5.1's `ChainView` bullet
  (`output_at` gone; `Fault`/`AtHeight` named), §15 dated entry appended below
  the E1 increment 2.5 row. E1's own rows are **not** edited: its §15 row
  still ends "remaining precondition is DRS-E6 increment 1", which the next
  row discharges — a dated log entry is records-was.
- `IMPLEMENTATION_INDEX.md` §7 documents table: one row for this doc. The
  `DRS-*` registry row's status cell: **#752 MERGED 2026-09-15** (falsifier
  `gh pr view 752 --json state` → `MERGED`); this PR appends `UPDATE 2026-09-15
  (DRS-E6 increment 1 LANDED, PR #753)` and **S-CHAIN-W is unblocked**. The
  carrier named in the landing commit fired in the review-fix commit.
- `docs/CHANGELOG.md` Unreleased: one entry (new crate + its two gates;
  `KeyImage` home, encoding unchanged; `CurveTreeRoot`). `docs/README.md`
  front-door table: one row beside the `SI-` register's.
- `CLAUDE.md` key-crates list: add `shekyl-chain-rules` (it enumerates crates).
  `25-rust-architecture.mdc` does **not** enumerate crates (verified) — no edit.
  `rust/Cargo.toml`'s member comment said `build.yml`; corrected to the
  `rust-audit-test.yml` belt script (same correction as §6.5).
- Crate `//!`: staging note (STAGED; consumer S-CHAIN-W), the graded-oracle
  hook (E2's replay harness routes disagreement through
  `shekyl_chain_store::conformance::grade` keyed by `CenRow::as_str()`; this
  crate never imports it), the consumer map (connect, pool via `PoolView`), the
  fault channel.

---

## 11. Review record — round 1 (2026-09-15), each ruling line-local

| Q | Question | Ruling |
| --- | --- | --- |
| Q1 | `KeyImage` — depend on `shekyl-crypto-pq`, bare array, or move? | **RULED 2026-09-15 — override:** move to `shekyl-types` (same 32-byte shape as `BlockHash`/`TxHash`; "we need the type" must not pull 25 crypto deps into the crate whose defining property is that it has almost none; two same-named newtypes are an unchecked drift source). Move, don't duplicate; `shekyl-crypto-pq` re-exports. **Refinement on verification (round 2):** `hash32!`'s `redact` arm would add a full-hex `Display` the type deliberately omits (spend↔wallet correlation) — a third arm `redact, no_display` is added; `from_canonical_bytes` kept (§3.4). |
| Q2 | Root type on `root_at` — bare array, mint in `shekyl-types`, or here? | **RULED 2026-09-15 — override:** mint `CurveTreeRoot` in `shekyl-types` now. "Rule 18's home is the redb-bearing curve-tree crate" is the reason to reject the default — the rules crate would depend on a store-bearing crate to *name a value*, the inversion R8 banned arriving through a type. Computation stays in the tree crate. |
| Q3 | Payloads of `block_at` / `output_at` | **RULED 2026-09-15 — default, with a binding condition:** every field is justified by a named CEN row when introduced; `ChainView`'s narrowness is what keeps rules mockable and the mock smaller than the store. **Applied (round 2):** `output_at` has no justifiable field and is dropped (§3.3); `has_output_key` is the shape the output-key row will need. |
| Q4 | Policy rows — same enum + `Flag`, or sibling enum? | **RULED 2026-09-15 — override:** sibling enums. A `Flag` field is a check someone can forget; two enums make proximity promotion unrepresentable; two coverage bitsets and two denominators are exactly the two-line record. §7.5.1's gate bullet names the hazard ("a policy row counted toward consensus coverage is proximity promotion arriving through the instrument"). |
| Q5 | `RuleSetId` representation | **RULED 2026-09-15 — accept `RuleSetId(u8)`, `GENESIS = 1`, but not defined as the header major version:** its own space with an explicit `rules_at(nettype, height) -> RuleSetId` seeded as identity. The 1:1 is true only because the hardfork table has one entry — the same inertness that hid the `on_block_popped` defect; a function preserves the R4 coupling, equality erases it. (§7.5.1 already states the fork version enters through `RuleSet`.) |
| Q6 | `InvalidBlock` locus shape | **RULED 2026-09-15 — default.** No `detail` field: an unbounded string is not evidence (the `ReviewedDivergence` reason). |
| Q7 | Census-parser reuse by import | **RULED 2026-09-15 — default, follow-up named not filed:** import now; extract to `_census.py` after #751 merges (blocker #751; falsifier `gh pr view 751 --json state`). **DISCHARGED 2026-09-15:** #751 merged; `scripts/ci/_census.py` extracted in this PR, both gates import it (§6.1). |
| Q8 | Harness visibility for doctests | **RULED 2026-09-15 — default** (`cfg(any(test, doctest))`). **AMENDED BY FINDING 2026-09-15 (commit 6):** the default's premise fails — `cfg(doctest)` items are not visible to doctest snippets (§8.3); `harness` is `#[cfg(test)]`, the cross-view pin uses an inline view. Disclosed in the commit-6 message. |
| Q9 | `Candidate` struct vs two args | **RULED 2026-09-15 — default, refined at PR #753 review.** It is what `ChainValid` carries. `#[non_exhaustive]` + `Candidate::new` so a third component later is not a breaking struct literal. |
| — | G1 mechanism | **RULED 2026-09-15 — added:** a `compile_fail` doctest proves *some* compile error and sees only a direct `use`; it cannot see transitive acquisition, which is the path the adoption increments take. The `cargo tree` belt lands in increment 1 (§6.5; corrected in round 2 to a captured-closure shape in `rust-audit-test.yml` — the `-i`-exit-code sketch was fail-open and `build.yml` has no cargo). |
| — | Census figures | **Confirmed:** consensus enforced 153 (not 159) — the denominator moved when R8 ruled; the computed-denominator mechanism working on its first real test. |

---

## 12. Questions for the reviewer — round 2

**RULED 2026-09-15 at PR #753 review.** Each default kept. G4 was tightened
in the same review (`ChainValid<'id, V>`) so an unbranded `ChainView` impl
cannot satisfy `connect`.

Each arose from applying a round-1 ruling; each has a default the
implementation follows unless ruled otherwise.

**Q12-1 — the view's fault channel (`type Fault`).** The ruling gives
`ChainView` its methods but not their fallibility. The store's projection reads
a redb transaction, and reads fail. Default: `type Fault;` on the trait, every
method `Result<_, Self::Fault>`, `validate` returning
`Result<Verdict<ChainValid>, V::Fault>` (§4.3, §4.6). Alternatives: **(a)**
infallible methods, the projection panics on an engine error (the C++ posture;
an unwind through the validator, poison by accident); **(b)** infallible
methods, the projection records the error in a side cell and returns a
placeholder, `connect` checks the cell before honouring the verdict (a protocol
nothing enforces — a wrong `InvalidBlock` can be *reported* before the check).
The default puts the ruling's three error classes in one signature and enforces
the conversion ban by genericity. Cost: rules read the view with `?` and write
refusals as `refused(...)` — which also means a refusal is never `?`-propagated
anonymously. **Ruled: keep the default.**

**Q12-2 — `tip()` on `ChainView`.** CEN-A2 (`prev_id == top_hash`), CEN-B5
(header root == *tip* root) and 4.C (the height this block will have) all read
the tip. `root_at(tip_height)` returning `AtHeight` would force every such rule
to write an unreachable `AboveTip` arm — a smell. Default: **not added in
increment 1** (no ruling names it; the handoff says methods grow with the
increment that consumes them); owed to slice 1 as
`fn tip(&self) -> Result<Tip { height, hash, root }, Self::Fault>` with each
field's row named (§13). Alternative: add it now, since the shape is settled.
**Ruled: keep the default.** Slice 1 adds `tip()` before CEN-A2/B5.
**DISCHARGED by slice 1 (PR #768), in a shape that refined this sketch:**
`fn tip(&self) -> Result<Option<Tip { height, hash }>, Fault>` — `Option`
for the empty chain (slice 1 Q1), and **no `root` field**: B5 reads
`root_at(connecting_height)`, the one read path SCW-19 keyed (key `h` = the
state at `h`), and a second root on `Tip` would have been a second path to
the same cell. The "unreachable `AboveTip` arm" this question worried about
is real and is written as a refusal (G11), pinned by a fixture against a view
with no roots. §4.3 is the contract; this paragraph is the record.

**Q12-3 — `shekyl-address` for `Network`.** `rules_at(nettype, height)` needs
the nettype enum, and the workspace's one is `shekyl_address::Network`.
Default: depend on `shekyl-address` (light; no `redb`; the G1 belt confirms).
Alternative: relocate `Network` to `shekyl-types` with the same zero-breakage
re-export move as `KeyImage` — arguably its right home (a foundational
state-shaped enum), but a third relocation in a scaffold PR, not proposed here.
**Ruled: keep the default.** Relocate `Network` in its own PR.

---

## 13. Owed to later increments (named, with consumers) — none deferred from this one

- ~~`ChainView::tip()`~~ — **DISCHARGED** by slice 1 (shape ruled at
  [`CHAIN_RULES_SLICE_1.md`](../completed/CHAIN_RULES_SLICE_1.md) §2:
  `Result<Option<Tip { height, hash }>, Fault>`; §4.3 above).
- ~~`difficulty_at`~~ — **DISCHARGED by slice 2 (4.D), 2026-09-19**, in a
  shape that refined the sketch: `lwma1_next` takes cumulative values
  directly, so no per-block difference is ever computed; `D4::target`
  derives the next target from the `RecordedBlock.cumulative_difficulty`
  window and `D4::cumulative_after` folds `parent + target` for the store to
  persist (Q5) — the arithmetic stays in this crate, as S-CHAIN-R's round-1
  Q1 ruled ([`DRS_E1_SCHAIN_R.md`](../completed/DRS_E1_SCHAIN_R.md); SCR-3),
  and the store computes nothing consensus-visible on either side.
- `ChainView::has_output_key` — the output-key-uniqueness row when ruled; §3.3.
- `RecordedBlock` field growth — ~~cumulative difficulty~~ (**landed with
  4.D, slice 2**); weight arrives with 4.G, with its row.
- `RuleCoverage` persisted encoding — S-CHAIN-W, rule 42 there (ruling §9.4
  "persisted with anything it writes").
- `ChainView` store-side implementor (`Fault = StoreError`), `connect`,
  `ChainTip.connect` — S-CHAIN-W.
- `PoolView`, `AdmissionPolicy` application, `PolicyCoverage` consumer — DRS-E5.
- Replay harness feeding `grade()` — DRS-E2.
- **A below-anchor validation mode** — owed to **slice 3 (4.E) or slice 6
  (4.I), whichever opens first**; consumer the band-1 sync driver
  (`PDM-Q5`: below the release anchor `C` a fresh node holds skeleton only —
  no prunable body, no `pqc_auths` — and proof validity is asserted by the
  anchor, not checked). Shaping request from the pruning lane's review of
  `PDM-Q-F26` (PR #765), taken 2026-09-16: **DRS-D12 and PDM-Q5 band 1
  collide at `validate`** — a skeleton block cannot pass a `validate` that
  checks proofs, so under D12 it can never be connected unless `validate`
  can be told to omit the proof rows and record the omission. *Read against
  the landed types:* the omission is already expressible — `RuleSet::
  enforced` is "the rows this set holds a block to" and `RuleCoverage`
  records what ran — and the anchor rule already has a row, **CEN-E1** (the
  release-carried `assumevalid` checkpoint after `PDM-Q-F23` removed E5). What
  does **not** exist is the *mode*: a below-anchor rule set as a second
  `RuleSetId` would be refused by `connect` (`StoreCannot::RuleSetNotInForce`
  — `in_force` comes from the consensus schedule, and "this node has no
  bodies below `C`" is node state, not consensus). **Default for the ruling
  (not decided here):** a `Trust`-shaped input to `validate` orthogonal to
  `RuleSet` — `Full` | `BelowAnchor(anchor)` — under which the proof rows are
  not run, their rows are absent from coverage, `connect`'s provenance
  records them as `rule_coverage_gaps` (so a band-1 file is never parity
  evidence, which is true), and the `in_force` check is untouched.
  Alternative: a below-anchor `RuleSet` variant with its own id, requiring
  `connect` to accept a second in-force set per height. Decide **before**
  `validate` acquires callers beyond the store tests and the E2 driver —
  the signature is one parameter today and every later caller is a retrofit
  (SCW-7's standard). Falsify by: a band-1 sync test that connects a
  skeleton block under `RuleSet::GENESIS` and is refused. **Slice 3 opened
  first (2026-09-20, [`CHAIN_RULES_SLICE_3.md`](CHAIN_RULES_SLICE_3.md) §4.1,
  Q1):** Round-0 default is the `Trust` parameter in its final position,
  carrying the release anchors E1 reads today, with the posture arm (and
  this item's falsifier, which cannot run until a proof row exists to skip
  and a skeleton block has a type — slice 3 F10) arriving in slice 6 through
  a second constructor so no caller is retrofitted. `validate` has one
  production caller at the time of the decision (`shekyl-chain-ingest`
  `connector.rs:271`, PR #806). **LANDED as the parameter, slice 3 c3
  (2026-09-20):** `Trust { anchors }`, `Trust::full` / `Trust::UNANCHORED`,
  `validate(formed, view, rule_set, trust)`; CEN-E1 is its first reader.
  **Still owed to slice 6:** the posture arm (`Trust::below_anchor`, band 1
  per `PDM-Q5` `:293`), the 4.I skip it governs, and this item's falsifier —
  which needs a proof row to skip and a **skeleton candidate type** a
  band-1 block can be (slice 3 F10; `Candidate` holds full transactions).
- **`TxIdentity::pqc_auth_hash: Option<PqcAuthHash>`** — **LANDED in the
  `tip()` PR (slice 1, 2026-09-17)**, items 1 **and** 2 of
  `DAEMON_REDB_STORE.md` §7.7's plan for `PDM-Q-F26` (PR #765): the
  `shekyl-types` `hash32!` sibling `PqcAuthHash`; the field on
  `TxIdentity`, populated from `Transaction::txid_parts()` (one
  construction: each discardable region hashed once, the txid mixed from
  those values); and, in `shekyl-wire`, `Transaction::pqc_auth_hash()`
  (`None` ⇔ the txid is 3-part) plus the two-supplied form
  `hash_with_supplied_components(pqc_auth, prunable)`, of which `hash()`
  is `txid_parts().hash` as bytes and `hash_with_supplied_prunable` is the
  one-supplied mixer. The mixer's arity is the `Option` after
  `prefix_carries_pqc_component` drops a `Some` the prefix cannot carry,
  so a supplied component on a 3-part prefix is dropped, not mixed, and
  the skeleton (`PDM-Q-F28`: neither region held)
  reconstructs its 4-part txid from the two stored digests. KAT'd
  against the pinned oracle txid on the full body **and** the skeleton
  (`pruned_tx_hash_parity`), and on the 3-part forms — coinbase,
  serve-credit (`None`; the countersignature rides the vin), a coinbase
  handed components anyway — and on the bond-post (4-part like any spend:
  the identity signature is a tx-level `pqc_auths` slot, so the arity is
  the predicate's, never an input arm's). The wire surface is **typed as
  §7.7 wrote it** — `Option<PqcAuthHash>` / `PrunableHash` in and out of
  `shekyl-wire`, which takes the `shekyl-types` dependency for it — so a
  txid, a `PqcAuthHash` and a `PrunableHash` cannot be transposed into the
  supplied forms; the raw `[u8; 32]` the crate carried there was unfinished
  migration (`RAW_TYPE_NEWTYPE_MIGRATION.md` §6), not a boundary, and
  `hash()`'s own return type is that plan's remaining row. Item
  3 — the `txs_pqc_auth_hash` row — **LANDED 2026-09-17 on PR #772**
  where §7.7 put it: S-CHAIN-W amendment A3 on S-CHAIN-R's layout commit.

**Received from `PDM-Q` 2026-09-16 (`PDM-Q-F27`, `F29`,
[`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md) §6) —
two shaping constraints on types this crate is freezing, written here at
SCW-7's standard (contract before the increment that would omit it).
Neither is a rule to port; both are properties of the surface.**

- **A below-anchor `RuleSet` must be issuable** (`F27`). Under DRS-D12
  every connected block passes `validate`, and `ChainValid::mint` panics
  on coverage short of the rule set's `enforced`. `PDM-Q5` band 1 — a
  fresh node below the release anchor `C` — holds skeleton only: no
  prunable body, no `pqc_auths`, proof validity asserted by the anchor.
  A skeleton cannot pass a proof-checking set, so **band 1 has no writer
  unless a set exists whose `enforced` omits the proof rows.** The seam
  is already here (`RuleSet { id, enforced }`, `ISSUED`); what is owed
  when `ISSUED` is next touched: (a) the below-anchor set is issued, or
  its absence is a recorded decision with `PDM-Q5` named; (b) its
  selector is *not* `RuleSchedule` — the schedule is height → set per
  network, and below-anchor is position relative to this node's `C`
  (rule 71: `C`/`H` are per-network data consumed by one arm); (c) the
  anchor check itself (block `C` has hash `H`) is either a census row
  (`CenRow` ↔ census is a bijection) or a node-policy check outside
  `CenRow` — `PDM-Q5` rules which, and it lands with the set. The store
  persists `RuleSetId` + `RuleCoverage` per block, so a band-1 connect
  is legible on disk as one; that is the property. Pre-cutover replay
  over a full LMDB chain never meets a skeleton, so E2 will not surface
  this. *Falsifier:* `ISSUED` is declared complete, or the read-side
  slice that consumes `RuleSetId` from the store lands, with only
  `GENESIS` issued and no recorded below-anchor decision.
- **`ChainView` exposes no recorded transaction bytes without a row and
  an above-`W` marking** (`F29`; `PDM-Q3`'s instrument). At `645d09dc3`
  the trait's surface is `has_key_image`, `block_at` (hash + header),
  `root_at` — no body accessor — and round-1 Q3 (§3.3) already makes a
  view field conditional on a named `CenRow`. So the residual set of
  consensus reads that could reach a discarded body is **empty by
  construction in this crate**, and the instrument `PDM-Q3` owes is this
  surface held as a standing property: a recorded-body accessor, if one
  ever arrives, returns the discarded case as a variant (the `AtHeight`
  discipline — absence is matched, never `?`'d away), and every rule
  that takes the recorded arm is by construction an above-`W` rule and
  says so in its row. *Falsifier:* a `ChainView` method returning
  recorded tx bytes with no `CenRow` justifying it, or a rule matching
  its recorded arm without an above-`W` marking. This is compile-shaped,
  not a grep; it does not discharge `PDM-Q-F8` (the C++ path still reads
  leaves at `blockchain.cpp:5327`), it says where the instrument lives
  once the validator is this crate.

Nothing scoped to increment 1 by §7.5.1 is deferred out of it. The one
increment-1 deferral this section carried — the `_census.py` extraction,
blocked on #751 — was discharged in this PR when #751 merged (§6.1, Q7).
Slice 1's own deferrals (CEN-B4 to the increment landing the bond-pubkey
read; CEN-A3 subsumed into it; CEN-A5 subsumed into 4.G; CEN-A6/A7 to the
wire-side invariant register) are recorded at
[`CHAIN_RULES_SLICE_1.md`](../completed/CHAIN_RULES_SLICE_1.md) §3–§4 and §8 Q2/Q3.
