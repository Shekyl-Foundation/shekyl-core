# `shekyl-chain-rules` slice 2 — census 4.C + 4.D (DRS-E6 increment 3)

**Status:** CLOSED-as-record — **implementation LANDED 2026-09-19** (all
commits, 1–10, including the store side 9 / 9b after #783 / #784 merged;
Rounds 1 and 2 RULED 2026-09-19, Q1–Q10, §8/§8.1; pre-flight written
2026-09-18 against `dev` @ `5adfc5423`, post-#782). Record: `implemented
16 / validator-enforced 151`, `ratified 126 / 153`; `SCHEMA_VERSION` 6 → 7;
`passed_through().count()` 7 → 6. **Open residue lives in FOLLOWUPS, not
here:** Q10's owed consumers (§4.5), F12's register, and the `Fault::Corrupt`
writer-halt whose first caller is the E2 driver (§4.3). Do not implement
from this file; the living contract is
[`CHAIN_RULES_CRATE.md`](../design/CHAIN_RULES_CRATE.md). Template:
[`CHAIN_RULES_CRATE.md`](../design/CHAIN_RULES_CRATE.md) §7.5.1; predecessor
[`CHAIN_RULES_SLICE_1.md`](CHAIN_RULES_SLICE_1.md). Parent
plan: [`DAEMON_REDB_STORE.md`](../design/DAEMON_REDB_STORE.md) §7.5 table 3 (*"slice 2 —
MTP / FTL; body in `shekyl-difficulty` (adopt)"* / *"LWMA-1 body in
`shekyl-difficulty`, PoW in `shekyl-pow-randomx` (adopt)"*). Cites
`26-sub-pr-design-discipline.mdc`. The living contract is
[`CHAIN_RULES_CRATE.md`](../design/CHAIN_RULES_CRATE.md); do not implement from this
file. Owner: the DRS-E6 lane.

**Scope (table 3).** The eleven surface-free rows of 4.C (CEN-C1, C2, C3)
and 4.D (CEN-D1, D1b, D2, D3, D4, D5, D6, D7), all `pending` in
`rust/shekyl-chain-rules/src/census.rs:270`–`:281`. Plus the one `ChainView`
growth `CHAIN_RULES_CRATE.md` §13 owes this slice — `difficulty_at` / the
`RecordedBlock.cumulative_difficulty` field ("fields grow with rows —
cumulative difficulty and weight arrive with 4.D / 4.G"). Plus the first
**store-derived** `ConnectFacts` field: `connect.rs:203`–`:207` already
names `cumulative_difficulty` as deleted-by `CEN-D4`/`CEN-D5`.

**What this pre-flight found, in one paragraph.** Every 4.C/4.D body is
already Rust and already the daemon's one implementation
(`shekyl-difficulty`: `check_timestamp_rule`, `lwma1_next`, `check_hash`;
`shekyl-pow-randomx`: `seedheight`, `compute_hash`) — this slice **adopts**
them behind `Rule`, it writes no consensus arithmetic. What it does have to
decide is the **substrate the rules read that is not chain state**: C1 needs
a wall clock, D1/D2 need a RandomX longhash (a 256 MB cache and a VM), D7
needs a daemon flag. `validate(candidate, view, rule_set)` has no channel
for any of the three today. §4 proposes one shape for all three
(`Substrate`, a second narrow trait beside `ChainView`, mocked in tests) so
the crate stays light and G1-shaped, and so a verifier failure stays a
**fault**, not a verdict — which is what the C++ does at
`blockchain.cpp:5520`–`:5531` ("rejected unverified, not disproven").
Of the eleven rows, **nine** are predicates or definitions this slice can
land (C1, C2, C3, D1, D1b, D2, D3, D4, D6); **D5** (alt-chain window) is the
same LWMA-1 over a different view and is proposed **subsumed-by-D4** with its
row closing when the alt `ChainView` exists (slice 9); **D7**
(`--fixed-difficulty`) is a bucket-4 test lever whose disposition is a
question (§8 Q6), not a default. One store-side consequence is named and
sequenced (§5): once D4 derives the target, `connect` derives
`cumulative_difficulty` and the passed-through count drops from seven to six
— a `connect.rs` edit that must land **after** PR #783 (S-OUT-KI) and be
disclosed on the S-CHAIN-W row (rule 94 §6).

---

## 1. Parents — landed? (§7.5.1 (a))

| Parent | Needed for | State at `5adfc5423` |
| --- | --- | --- |
| Slice 1 (`Rule`/`BlockRule`, `BlockContext`, `ChainView::tip()`, `Tip::connecting_height`, `held_by_cxx`) | every row here reads the connecting height; the trait shapes are frozen | **Landed** (#762, #767, #768). `rules/mod.rs:82`–`:97` (`BlockContext { candidate, rule_set }`, "the set can grow without moving any rule's signature"); `view.rs:109`–`:118` (`connecting_height`, crate-private). |
| S-CHAIN-R (#772): `BlockInfo.cumulative_difficulty`, `BlockInfo.timestamp` | the LWMA-1 window and the MTP window are reads of recorded blocks | **Landed.** `codec/chain.rs:90`–`:97`. The store's `BatchView::block_at` (`store/view.rs:173`) already projects `BlockInfo` into `RecordedBlock`; growing `RecordedBlock` by one field is a projection edit, no schema change. |
| `shekyl-difficulty` (C2-R3 timestamps ratified 2026-09-01; LWMA-1 ratified 2026-05-18; `check_hash` KAT-port) | the bodies | **Landed**, one dependency (`shekyl-types`), no `redb`, no store — G1-clean by inspection (`Cargo.toml:20`–`:21`). |
| `shekyl-pow-randomx` (RandomX v2 Rust verifier, `seedheight`) | D2, D3 | **Landed.** Depends on `aes`, `blake2`, `argon2`… (`Cargo.toml:64`–) — heavy, and a per-seed cache. §4.2 keeps it **out** of this crate's dependency closure. |
| C2-R1b (D5/D6 ratified 2026-09-03; `alt_window_plan` crossed) | D5, D6 | **Landed** in `shekyl-difficulty::alt_window`. D5's consumer (an alt `ChainView`) is slice 9's. |
| S-OUT-KI (PR #783, in flight) | nothing this slice reads — but it rewrites `store/{view,read,chain_reads,connect}.rs` | **In flight.** The store-side commit (§5 C9) is sequenced behind it. |

No parent blocks the rules-crate commits. One parent (#783) sequences the
store-side commit.

---

## 2. Row-body audit (§7.5.1 (b)) — 11 rows at `5adfc5423`

Column *body* is the Rust function that already decides the row; *site*
is where the C++ consumes it today (the marshaling this slice retires from
the validator's perspective — the C++ keeps calling it until cutover).

| Row | b | Statement (census `CONSENSUS_RULE_CENSUS.md:347`–`:362`) | Body (Rust, landed) | C++ site | Proposed disposition |
| --- | --- | --- | --- | --- | --- |
| CEN-C1 | 1 | `ts ≤ local_clock + FTL(540)`; at main and alt admission | `is_timestamp_below_ftl` (`timestamp.rs:67`), the FTL arm of `check_timestamp_rule` (`:146`) | `blockchain.cpp:5167`–`:5240` (shim + window build) | **Land** — predicate; needs the clock (§4.1) |
| CEN-C2 | 2 | `ts > median(newest 11 preceding)`, strict; alt = newest 11 of suffix+prefix | `is_above_mtp` (`:104`), `mtp_median` (`:114`) | same | **Land** — predicate over `block_at` reads; strictness pinned by `docs/test_vectors/MTP_BOUNDARY_V1.json` |
| CEN-C3 | 2 | below 11 blocks the window is right-padded with the genesis timestamp; no bootstrap carve-out | padding arm of `check_timestamp_rule` (`:155`) | `:5224`–`:5238` | **Land** — the padding value is `block_at(0).header.timestamp`, read from the view, never a constant |
| CEN-D1 | 1 | `check_hash(pow, target)` must pass; FFI failure rejects | `check_hash` (`check_hash.rs:74`) | `:5535` | **Land** — predicate; the longhash arrives through the substrate (§4.2) |
| CEN-D1b | 4 | the comparison is `hash · diff < 2^256`, hash LE-256 | `check_hash` body; vectors `shekyl-difficulty/tests/check_hash_vectors.rs` | `difficulty.cpp:52`–`:86` | **Land as adopted** — `implemented(rules::pow::D1b)` names the comparison function D1 calls; ports **as-is with the existing vectors** (bucket 4: parity first, ratification converts the class later — §7.6) |
| CEN-D2 | 1 | longhash is RandomX v2 unconditionally; verifier failure is the fail-closed gate at every difficulty | `shekyl-pow-randomx::compute_hash` (`vm.rs:2287`) | `cryptonote_tx_utils.cpp:770`–`:780`; `blockchain.cpp:5520`–`:5531` | **Land** — the *rule* is "the longhash the substrate returns is the one compared"; a substrate `Err` is a **fault** (`V::Fault`-shaped), never `InvalidBlock` (§4.2) |
| CEN-D3 | 1 | `seedheight(h) = 0 for h ≤ 2112, else (h−65) & ~2047`; seed = block id at that height | `seedheight` (`shekyl-difficulty/src/seed_epoch.rs:49`, moved from `shekyl-pow-randomx` in commit 6a so the validator adopts it without the engine — F10); constants `:37`/`:40` | `cryptonote_tx_utils.cpp:777` | **Land** — the rule derives the seed height from the connecting height and reads `block_at(seedheight).hash`; the env override (`clamp_lag`/`clamp_blocks`, `:55`/`:72`) is **not** read here — the validator has no environment (rule 71) |
| CEN-D4 | 1 | next difficulty = LWMA-1 over the last N+1 = 91; genesis constant (100) below N; T = 120 | `lwma1_next` (`lwma1.rs:64`) | `blockchain.cpp:971`–`:1010` (cached window) | **Land** — the target is a **definition row** (like B6): derived once per validation, recorded at derivation, carried in the verdict (§4.3); D1 compares against it |
| CEN-D5 | 2 | alt-chain difficulty: same LWMA-1 over prefix+suffix window ending at `bei.height − 1`; height-0 alt sentinels 0 | `alt_window_plan` (`alt_window.rs:52`) | `:1544`–`:1638` | **Subsumed-by-D4 over an alt view** — D4 reads its window through `ChainView::block_at`; the *stitching* is what an alt view's `block_at` does. Stays `pending` with a `subsumed-by` registry comment (the A5 shape); closes when slice 9 lands the alt view and a fixture drives D4 over it |
| CEN-D6 | 2 | a zero next-block difficulty rejects the block | `Difficulty::is_zero` (`types.rs:41`); `lwma1_next` cannot return 0 on main (`GENESIS_DIFFICULTY = 100`; LWMA-1 min-L clamp) | `:5494`, `:2324` | **Land as a definition belt** — §8 Q4: type (`NonZero`) vs predicate |
| CEN-D7 | 4 | `--fixed-difficulty` overrides the DAA; height 0 forced to 1 | none in Rust — `m_fixed_difficulty` at `blockchain.cpp:294`, `:973`–`:975`; parsed `cryptonote_core.cpp:95`, `:636` | same | **Question** (§8 Q6): port as-is via the substrate with a fixture (parity), or R9's test-seam ruling first |

Row-count check: 3 + 8 = 11 = the `pending` entries at `census.rs:270`–`:281`
(D1 and D1b are separate variants, `:275`–`:276`).

---

## 3. Two readings the rules need that the view already gives

- **The MTP window** (C2/C3): the timestamps of the up-to-11 blocks below
  the connecting height — `block_at(h)` for `h ∈ [max(0, c−11), c)`,
  `RecordedBlock.header.timestamp`. Genesis admission (`c = 0`) has no
  window and no genesis timestamp to pad with; the C++ passes `h == 0` with
  `median = 0` and the comment *"not a carve-out: there is no window to
  check"* (`:5224`–`:5228`). §8 Q3 decides how the row records at `c = 0`.
- **The LWMA-1 window** (D4): `(timestamp, cumulative_difficulty)` of the
  N+1 = 91 blocks below `c` when `c ≥ N` (`lwma1_next`'s length contract,
  `lwma1.rs:47`–`:55`); nothing when `c < N` (genesis constant). This is the
  read that grows `RecordedBlock` by `cumulative_difficulty` (§4.3). The
  C++ caches this window on the `Blockchain` object (`:1000`–`:1010`,
  "ND: Speedup"); this slice does **not** — 91 point reads per block is the
  baseline E2's replay will measure, and a windowed `ChainView` method is a
  reopening with a number attached, not a pre-provision (rule 21).

---

## 4. Substrate this slice adds

### 4.1 The wall clock (C1)

Not chain state, not a rule-set parameter, not the view's. Today the C++
reads `time(NULL)` inside the shim (`:5184`). The validator must receive it:
a rule that reads the system clock itself is untestable and nettype-blind
in the wrong way. **Default:** `Substrate::local_clock() -> Timestamp` on
the trait in §4.2; the store/daemon implementor reads the clock once per
`validate`, the mock returns a fixture value. `BlockContext` is **not** the
home — it is "what a block-level rule may read besides the view" from the
*candidate's* side; the clock is the environment's, and putting it beside
the PoW oracle keeps "things that are not the chain" in one place.

### 4.2 The PoW oracle (D1, D2, D3) — a second narrow trait, not a dependency

`shekyl-pow-randomx` brings `aes`, `blake2`, `argon2`, a 256 MB cache per
seed epoch, and a VM. Taking it as a dependency of the validation crate
would (i) put a cache lifecycle inside a crate whose whole design is
"unit-testable against a mock with no database", (ii) grow the closure the
G1 belt records, and (iii) make every rule test pay for a cache
derivation. The C++ already separates the two: a precompute worker fills
`m_blocks_longhash_table` and the validator looks the hash up (`:5514`–`:5519`).

**Default shape:**

```rust
/// What a rule may ask of the environment that is not the recorded chain.
/// Faults are the implementor's, opaque to every rule, and are NOT verdicts
/// (CEN-D2: a longhash the verifier could not compute leaves the block
/// unproven, not disproven — `blockchain.cpp:5520`–`:5531`).
pub trait Substrate {
    type Fault;
    /// Wall clock, Unix seconds (CEN-C1).
    fn local_clock(&self) -> Result<Timestamp, Self::Fault>;
    /// RandomX v2 longhash of `hashing_blob` under `seed` (CEN-D2). The
    /// rule chooses `seed` (CEN-D3); the implementor may cache by it.
    fn longhash(&self, hashing_blob: &[u8], seed: &BlockHash) -> Result<PowHash, Self::Fault>;
}
```

~~`validate` grows one parameter (`substrate: &S`) and one fault channel.~~
**RULED 2026-09-19 (Q1): the trait is approved, but it binds to a
stateless stage, not to `validate(candidate, view, rule_set)`.** C2-R8 Q3
ruled that the `ChainView` is projected from the write transaction that
applies the block, so `ChainValid` is minted *inside* the exclusive write
batch. Handing `Substrate` to the same entry point would run RandomX — the
most expensive call in the validator — inside that transaction and
serialize IBD behind the write lock, undoing the split by a parameter. So:

```text
form(candidate, rule_set, substrate, seed)  →  Verdict<StructurallyValid>   stateless · expensive · parallel · outside the txn
validate(structurally_valid, view, rule_set) →  Verdict<ChainValid<'id, V>>   inside the batch, view-bound
```

`StructurallyValid` is a new type; `validate` takes it **instead of** a
`Candidate`, so the second stage cannot be reached without the first
(type-enforced ordering, the same move as `ChainValid` being unmintable
outside `connect`). It carries the candidate, the stage's coverage, the
`PowHash` it computed, the `seed` it computed it under, and the clock
reading it judged FTL against. `tx_form` / `tx_against` are already this
partition for transactions (`validate.rs:12`, `:208`); this is the block
analogue.

**The wrinkle the ruling did not see, stated so it is ruled rather than
discovered in commit 6 (§8.1 Q8):** the ruling sorted "D1/D2/D3 need the
candidate and a longhash, no view". Two of the three *do* read the chain —
**D3's seed is `block_at(seedheight(c)).hash`** and **D1's target is D4's
derivation over the LWMA window**. Neither can be evaluated statelessly.
The C++ resolves the same tension by having the precompute worker fetch the
seed id itself (`cryptonote_tx_utils.cpp:777`, `get_pending_block_id_by_height`)
and comparing against the target inside the connect path (`blockchain.cpp:5535`).
The split that preserves the ruling's intent — **the expensive call outside
the txn, every chain-dependent judgement inside it**:

| Row | Stage | What it does there |
| --- | --- | --- |
| D2 | `form` | `pow = substrate.longhash(hashing_blob, seed)`; `Err` is a fault, never a verdict |
| D3 | **`validate`** | `seed == block_at(seedheight(c)).hash` — verifies the **claimed** seed `form` was given against the committing view; the seed height is always ≥ 64 blocks below `c`, so a mismatch means a ≥ 64-block reorg between the two stages, and the result is a crate-defined **fault** (`Stale::Seed`, "redo `form`"), not `InvalidBlock` — the block is unproven, not disproven |
| D4 | `validate` | target over the recorded window (definition row) |
| D1 | `validate` | `check_hash(pow, target)` — one comparison, cheap; the refusal is here |
| C1 (FTL) | `form` | `is_timestamp_below_ftl(header.timestamp, substrate.local_clock())` |
| C2, C3 | `validate` | the MTP window is recorded chain |
| B1, B2, B7 | `form` | view-free already (§8.1 Q9) |
| A2, B5 | `validate` | read the tip / the root |

`Substrate`'s fault and the view's stay **distinct and both opaque** (ruled
with Q1): `form` returns `Result<Verdict<StructurallyValid>, S::Fault>`,
`validate` returns `Result<Verdict<ChainValid<'id, V>>, Fault<V::Fault>>`
where `Fault` is the view's fault **or** the crate's own `Stale` — the store's
`connect` already handles one opaque fault and gains an arm. `PowHash` is a
new `hash32!` member in `shekyl-types` — a longhash is not a `BlockHash` and
the type refuses the transposition (RTN pattern; `RAW_TYPE_NEWTYPE_MIGRATION.md`
row, disclosed to that lane).

**Recorded with the ruling — the verdict is now time-dependent.**
`local_clock` makes `StructurallyValid`, and therefore `ChainValid`, no
longer a pure function of `(candidate, view, rule_set)`. The window is
small because the brand ties a `ChainValid` to a live batch, but anything
that caches or defers one lets the FTL leg go stale silently. The sentence
goes on both types' docs in commit 2, and `StructurallyValid` carries the
clock reading it was judged at so a consumer *can* re-check rather than
trust.

Consequences the shape buys: the crate's dependency closure is unchanged
(`shekyl-difficulty` only — §8 Q2); D2's fail-closed behaviour is the fault
channel by construction, not a belt on a sentinel (the `0xff…` hazard the
census's D2 note records cannot be written — there is no hash to return on
failure); the daemon's implementor is where the precompute table and the
seed cache live, exactly where they are now.

### 4.3 The target is a definition row, and the verdict carries it (D4 → store)

D4 is not a predicate on the candidate — nothing about a candidate fails
"what is the next difficulty". It is B6's shape: a **definition** derived
once, recorded in coverage at derivation, consumed by D1. `ValidatedBlock`
gains `target: Difficulty` (and the derived `cumulative_difficulty`, §8 Q5),
so the store's `connect` reads the value the validator computed.
**As landed (commit 9, `0aba3b815`): the field is deleted, not flipped.**
The pre-flight wrote "flips to `Fact::derived`"; a derived value the caller
still had to construct would be a second source with one right answer, and
`DELETED_BY`'s own contract is that the deriving row *deletes* the field. So
`ConnectFacts` is six fields, `connect` writes
`block_info.cumulative_difficulty` from `ValidatedBlock::cumulative_difficulty`
and nothing else, `passed_through().count()` goes **7 → 6** — the direction
the SCR-10 note says it moves when E6 lands a deriving row — and `FACT_FIELDS`
loses the name, which shrinks the `passed_through_facts` cell's accepted
vocabulary: a layout change, **`SCHEMA_VERSION` 6 → 7** (rule 42; rebuild,
never migrate). This is the first such deletion; it is the pattern 4.G's
weight rows will repeat.

**`Fault::Corrupt` at connect — deferred with its blocker named (rule 22).**
The plan had commit 9 treat `Fault::Corrupt` as an `InvariantViolated` the
store did not see itself. `connect` takes a `ChainValid`; a `Corrupt` is
returned by `validate` to the **driver**, which does not exist yet — the E2
replay is its first instance — and a store API for "the validator found the
file corrupt" has no caller until then (rule 21: not minted before a reader).
Blocker: no driver. Falsify by `rg 'Fault::Corrupt' rust/` returning a match
site outside `shekyl-chain-rules` — that site must arm the writer halt at the
noted height, exactly as a belt does, and the store API it needs is minted
with it. FOLLOWUPS row.

`RecordedBlock` grows `cumulative_difficulty: CumulativeDifficulty`
(`view.rs:129`–`:134`; the doc comment already reserves the field for 4.D).
`difficulty_at(h)` as §13 phrased it — `cum(h) − cum(h−1)` with the `h = 0`
and missing-row handling written once — is a **private helper of D4** if the
LWMA-1 window needs per-block differences; `lwma1_next` takes cumulative
values directly (`lwma1.rs:66`), so at this pin it may need no caller. Not
minted until a rule reads it (rule 21).

### 4.4 The MTP verdict's second output

`check_timestamp_rule` returns `(verdict, median)`; the median is the
miner-template floor's read, not the validator's. The rule discards it; the
template's consumer is the daemon's (unchanged, C++ until cutover).

### 4.5 CEN-D7 as Fakechain rule-set data (Q10, arm (d) as RULED)

`RuleSet` gains a difficulty parameter, `DifficultyRule::{Lwma1,
Fixed(Target)}`; D4 reads it — `Lwma1` derives over the window, `Fixed(d)`
returns `d` (connecting height 0 → 1, as `blockchain.cpp:975` has it). The
only constructor of a `Fixed` rule set is `RuleSet::fakechain(fixed)`;
`RuleSchedule::for_network(Network)` → `rules_at` → `RuleSet::for_id` can
yield only `ISSUED` sets, all `Lwma1`. D7 flips `implemented` on the type
that owns the `Fixed` arm; the census row's *"test-only carve-out live in
the production binary"* is deleted as a description, not ported as a
mechanism.

**The claim, stated as correctly as (d) delivers it (ruled 2026-09-19).**
Not "no override path in the production binary by type" — `main.cpp:374`
selects `FAKECHAIN` at runtime from `--regtest`, so a shipped binary can
reach the constructor when the operator asks for fakechain. The honest and
still-strong form: **no override path on any nettype other than Fakechain,
enforced by the type system rather than by a runtime check** — the API the
public nettypes select cannot express `Fixed`. The same guarantee shape
SCW-2 accepted for the settlement-epoch pin. A reviewer who runs
`--regtest` and constructs one has not found the guarantee failing.

**F10 — what the type system can and cannot anchor here.** The workspace's
nettype enum, `shekyl_address::Network`, has **no `Fakechain` variant**
(`network.rs:14`–`:18`; the daemon-facing `DaemonNetwork` in
`shekyl-rpc-types` does, but that is a serde DTO crate the validator does
not take). So the witness Q10 sketched — "constructible only from
`Network::Fakechain`" — has no structural source in this crate today; the
binding between the operator's `--regtest` and the `fakechain` constructor is
the daemon's. What **is** enforced by type is the half above: `for_network`
over the three public nets cannot yield `Fixed`. Adding `Network::Fakechain`
ripples through ~12 files in 9 crates (address prefixes, wallet lifecycle,
genesis tool) and is not this slice's; recorded here with the falsifier
`rg 'Fakechain' rust/shekyl-address/src/network.rs` returning a variant —
when it does, `RuleSet::fakechain` takes it as its argument and the
constructor becomes unreachable without one.

**Owed, so Q10 does not read as finished while its motivating case is open
(ruled 2026-09-19).** The two consumers whose needs refused arm (c) —
`scripts/bench/drs_bench.py` (real RandomX cost at a lowered target) and
`tests/unit_tests/curve_tree_header_root_check.cpp` (difficulty 1 as a
locus) — still have **no lever in the Rust validator**: nothing in
production calls `RuleSet::fakechain`, and the witness has no source. Q10 is
RULED, not finished, until both have a Rust-validated path; the FOLLOWUPS
row names both consumers, both halves (witness, wiring) and a falsifier for
each. Owner: this lane with the daemon-integration (E2) lane, which is
where the daemon's `--fixed-difficulty` meets a Rust rule set.

**The caveat, recorded beside the variant.** Once `RuleSet` carries
`Fixed(n)`, **`RuleSetId` no longer uniquely determines the rule set**: two
Fakechain nodes at `RuleSetId::GENESIS` may hold different rule sets.
Tolerable because Fakechain is single-operator and cross-node identity does
not matter there — but `RuleSetId` equality is no longer a valid proxy for
rule-set equality, and someone will eventually use it as one. The sentence
sits on `DifficultyRule::Fixed`'s doc, where that someone will read it.

**The consumers are Fakechain tests, and belong in a register (ruled
2026-09-19, §6 F12).** F9's consumers keep the target low for different
reasons and establish different things: `scripts/bench/drs_bench.py`
measures **real RandomX cost — the production machinery — at a target that
is not the production target**; a genuine partial, and writing down which
half is real is worth more than arguing whether it counts.
`tests/unit_tests/curve_tree_header_root_check.cpp` uses difficulty 1 as a
locus for a check that is not about difficulty at all. Each is a row in the
test-deviation register F12 proposes, with what it does and does not
establish; arm (d) is the *better* answer under that principle than (c) or
the C++ flag, because the lever is impossible on mainnet and testnet by
type rather than by a check.

---

## 5. Fixtures per row (§7.5.1 (c)) and commit plan

Negative fixture per row, over `harness::MockChain` extended with a
per-block `cumulative_difficulty` and a `MockSubstrate { clock, longhash: fn }`.

| Row | Negative fixture (red before the rule, green after) |
| --- | --- |
| C1 | `ts = clock + 541` refused on C1; `clock + 540` passes (the boundary is `≤`, `timestamp.rs:68`) |
| C2 | `ts == median` refused (strict); the `MTP_BOUNDARY_V1.json` rows re-driven through the rule, not only through `shekyl-difficulty` |
| C3 | a 5-block chain whose candidate `ts` is below the genesis-padded median refused; the same `ts` against an unpadded 5-window would pass — the fixture proves the padding is what bit |
| D1 | mock `longhash` returns a hash with the top byte set at target 100 → refused on D1; a hash of zeros passes |
| D1b | one `check_hash_vectors` row driven through D1 (the comparison form is the one the vectors seal) |
| D2 | mock `longhash` returns `Err` → `validate` returns `Err(fault)`, **not** `Ok(Err(InvalidBlock))`; asserts no row of coverage was recorded past D2 |
| D3 | at connecting heights `2112`, `2113`, `4160`, `4161` the mock records the `seed` it was asked for; asserts it equals `block_at(seedheight(h)).hash` for each — the epoch/lag boundary is the fixture |
| D4 | a 92-block mock chain with a non-trivial `(ts, cum)` series; the derived target equals `lwma1_next` over the recorded window; at 90 blocks it equals `GENESIS_DIFFICULTY` |
| D6 | per Q4: `compile_fail` that a zero `Difficulty` cannot reach `check_hash`'s target position, or a predicate fixture |
| D7 | per Q6 |
| store | `connect` with a `ChainValid` carrying `cumulative_difficulty` writes that value and records `Origin::Derived`; `passed_through().count() == 6` |

Commit plan (rule 90, ≤ 10; each names its rows):

1. `types: PowHash` — the longhash newtype; RTN row disclosed.
2. `chain-rules: the stateless stage — Substrate, form() → StructurallyValid; validate takes it` (Q1 as ruled, §4.2) — B1/B2/B7 move to `form` (Q9); `harness::MockSubstrate`; every existing test passes with a mock whose `longhash` is never called yet; the time-dependence sentence on both verdict types.
3. `chain-rules: RecordedBlock.cumulative_difficulty; MockChain carries it` — the view growth; store projection **not** in this commit (C9).
4. `chain-rules: CEN-C1 (FTL in form, MTP leg with C2) / C2 / C3` + three fixtures.
5. `chain-rules: CEN-D4 as a definition row; NonZero target (Q4, CEN-D6 recorded at the mint); ValidatedBlock.target + cumulative_difficulty (Q5)` + fixtures.
6a. `difficulty, pow-randomx, ffi: the seed-epoch schedule moves to the consensus-arithmetic crate` (F10) — `seedheight` + constants to `shekyl-difficulty::seed_epoch`, env clamps to `shekyl-ffi`, the engine crate's copy deleted; live doc anchors swept; RandomX/FFI lane disclosure.
6. `chain-rules: CEN-D2 in form; CEN-D3 seed verification and CEN-D1/D1b comparison in validate; Stale::Seed fault` (Q8) + fixtures incl. the ≥ 64-block-reorg stale-seed fixture.
7. `chain-rules: CEN-D5 subsumed-by-D4` registry comment; `CEN-D7` per Q10.
8. `chain-rules: coverage — registry flips; expected record` (§7); `DELETED_BY` narrowed to D4 (Q5, F6) — **note:** that constant lives in `chain-store/connect.rs`, so it rides C9, not this commit.
9. `chain-store: cumulative_difficulty leaves ConnectFacts — connect reads the verdict` — **LANDED `0aba3b815`** after #783/#784 merged (`3b49001fd`), on layout v6 → `SCHEMA_VERSION` 7; the field deleted rather than flipped (§4.3); `Fault::Corrupt` at connect deferred with its blocker (§4.3); S-CHAIN-W row disclosure. (The projection half of the old commit 9 landed in commit 3: the grown `RecordedBlock` would not compile without it.)
9b. `chain-store: the mock is reconciled against BatchView — conformance harness` (F11) — **LANDED `dfea31dc9`**: every landed rule, both stages, over `BatchView` on a real store and over `MockChain` built from the same inputs; identical verdicts and coverage row-lists at genesis, one block, and a full MTP window; the reads compared directly; a **negative control** (a mock keyed one height late is refused on B5 where the store passes). The mock travels to the store through a `harness` feature on the rules crate (G1 picked the side). The store crate still never names the verdict type — the test projects a refusal to `(rule, locus)` through `Verdict`, so the conversion-ban gate holds for tests too.
10. `docs` — **LANDED**: §7's record, index rows, CHANGELOG, FOLLOWUPS sweep, this file to `completed/`. Preceded by the review pass (`15563dcd5` the genesis-target correction; `a8a349253` F4/F13/F10/F12 records).

Commits 1–8 can start when Round 2 is ruled (or on its defaults if so
instructed); C9 waits for #783 regardless.

---

## 6. Substrate findings (pre-flight, rule 26 B6/A2)

- **F1 — `validate` has no environment channel.** Three rows need one
  (clock, longhash, D7's flag). `BlockContext` was designed as the growth
  point for *candidate-side* inputs; §4.2's trait is proposed rather than
  widening it, so a rule cannot mistake environment for chain and the mock
  boundary stays one trait per kind of substrate.
- **F2 — the C++ is already the shape the validator wants for D2.** The
  precompute table + lookup (`:5514`–`:5519`) is an oracle with a cache; the
  Rust `Substrate` implementor in the daemon is that table with a type.
  Nothing new is asked of the C++ before cutover.
- **F3 — genesis is exempt from C1 as well as C2/C3 in the C++** (`h == 0`
  returns before the FTL arm, `:5224`–`:5228`). The census states C1 without
  the exemption. **RULED 2026-09-19: a census amendment, not a conformance
  exception** — the row's *text* is incomplete relative to what C2-R3
  ratified and the C++ implements; filing it DIVERGENT-shaped would misstate
  which artifact is wrong. The CEN-C1 row in `CONSENSUS_RULE_CENSUS.md`
  carries the dated bracket (landed with this round's docs commit).
- **F4 — `Difficulty` can be zero by construction.** `Difficulty::ZERO`
  exists (`types.rs:25`) and `from_raw(0)` is `const fn`; the only producer
  that would return it is D5's height-0 alt sentinel, which has no Rust
  caller. D6 as a *predicate* would be a check with no reachable refusal on
  main — the "gate that cannot fail" slice 1 Q5 declined for B6. Q4.
  **Refined by the implementation (2026-09-19; rule 47 amended):** "no
  reachable refusal on main" was true and was the wrong test. Commit 6's
  fixtures met a view recording **no work across a full LWMA window**;
  LWMA-1 derived zero and the mint refused it (`Corrupt::ZeroTarget`,
  `cen_d6_a_window_with_no_work_derives_zero_and_the_mint_refuses_it`). A
  refusal unreachable on every *valid* chain is not dead — the input space
  it exists for is the non-conforming one, and slice 1's B6 reasoning,
  applied here as first written, would have deleted the arm. The
  gate-that-cannot-fail test is run over the adversarial input space;
  what cannot fail *there* folds into a type (B6), what cannot fail only on
  the happy path is a refusal and stays (D6's arm). Written where the test
  lives: rule 47, `CHAIN_RULES_CRATE.md` §4.4.
- **F5 — the seed-epoch env override is a validator-side read today.**
  `clamp_lag`/`clamp_blocks` read `SEEDHASH_EPOCH_*`; the C++ refuses them on
  public networks at init. The validator must not read the environment
  (rule 71: nettype selects data, never control flow on the consensus
  surface). §4.2's D3 uses the two constants. **RULED 2026-09-19: promoted
  from a finding to a graded register entry** — "the Rust validator reads no
  environment" is a design ruling that *creates* a behavioural difference
  between the two implementations (the CEN-I12-corrected-read class), and
  under CSR-3a it needs a register row with a pass condition, or the first E2
  comparison over a regtest chain with the override set produces a divergence
  nobody predicted. Landed on the CEN-D3 row of
  `CONSENSUS_STORE_RECONCILIATION.md` §5.4.1 (state unchanged; pass condition
  added, the I12 shape). *Checked while there:* no harness sets
  `SEEDHASH_EPOCH_*` (`rg` over `tests/ scripts/ rust/` finds only the clamp
  unit test and the FFI), so the lever has **no consumer** today; under the
  staging in §4.2 it also has **no effect** on a Rust-validated chain — D3
  derives the seed from the two constants and D2 computes under that seed,
  so a block mined under an overridden schedule fails D1. If a regtest need
  for a short epoch appears, it enters as **data** the way §8.1 Q10 proposes
  for the difficulty lever, never as an environment read.
- **F6 — `DELETED_BY` names D5 beside D4 for `cumulative_difficulty`**
  (`connect.rs:204`–`:206`). The Rust store has no alt-admission path, so D4
  alone lets `connect` derive the field for every block it will connect
  before slice 9. Q5 asks whether the entry's `rows` narrows to D4 or stays
  as written with the reason recorded.
- **F7 — `RecordedBlock`'s comment already promised this field**
  (`view.rs:126`: "cumulative difficulty and weight arrive with 4.D / 4.G").
  A promise kept on schedule; noted so nobody reads it as drift.
- **F8 — `blockchain.cpp:330` and `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` (checked
  2026-09-19 at the reviewer's request).** The site is `Blockchain::init`
  (`:300`–`:336`), reached only when the variable is *present*; it refuses
  to start on any nettype but FAKECHAIN (`:313`–`:317`) and on FAKECHAIN
  arms the override once through `shekyl_archival_settlement_epoch_arm_regtest()`.
  The `getenv` at `:330` is **diagnostic text** for the refusal message, not a
  second read of the value. On the Rust side the read is once per process
  behind a `OnceLock` (`shekyl-archival-retention/src/constants.rs:275`–`:284`),
  and consensus code consumes `effective_settlement_epoch_blocks()` — one
  latched value, never the raw env (`:290`–`:305`). So there is **one source**,
  read at init; SCW-2's `EngineLocal` reasoning holds against this site as it
  did against the arming path. **What it does expose — a forward pin for
  slice 8 (4.J):** the latched value is a process global inside a library
  crate. When the archival rows enter this validator, the epoch length must
  arrive as **data** (a `RuleSet` parameter or a `Substrate` read), not as a
  call into that global — the F5 ruling ("the validator reads no
  environment") extends to "the validator reads no process global whose value
  the environment set". Written here so slice 8's pre-flight inherits it.
- **F9 — Q6's falsifier ran and (c) fails it.** Consumers that depend on the
  difficulty **value**, not merely on PoW passing: `scripts/bench/drs_bench.py:449`–`:451`
  records `verify_exercised: {pow: True}` with the note *"PoW longhash is
  computed and checked for every block with no nettype bypass;
  `--fixed-difficulty` lowers the TARGET only"* — the store benchmark
  deliberately measures **real RandomX at a low target**, which a substrate
  that fakes the longhash removes; `tests/unit_tests/curve_tree_header_root_check.cpp:45`–`:48`
  argues difficulty 1 is *"the locus where…"* a specific check bites, and the
  P0f CEN-D2 correction was found *because* difficulty 1 was reachable.
  Every other consumer (`regtest_e2e.rs:243`, `dual_stack.rs:70`,
  `gen_ct2_fixture.py:93`, `capture_coinbase.py:80`, `node_server.cpp:920`,
  `chaingen.h:800`) uses `--fixed-difficulty=1` to make `generateblocks`
  cheap, which (c) would also serve. So the lever must **fix the target**,
  and the question is how it enters without an override path in the
  production binary — §8.1 Q10.
- **F10 — the seed-epoch schedule had the wrong home for the validator to
  adopt it.** `seedheight` and the 2048/64 constants lived in
  `shekyl-pow-randomx`, the RandomX **engine** crate — which never called
  them (it hosted them for the FFI). Adopting D3 from there would have put
  the VM and its `aes`/`blake2`/`argon2` closure into the validation crate
  (the thing Q1/Q2 keep out); re-deriving a 3-line formula would have been
  the second implementation every ruling this month refuses. The schedule
  is **consensus arithmetic the validator evaluates**, so it moved to
  `shekyl-difficulty` beside LWMA-1, the timestamp rule and `check_hash`
  (commit 6a; that crate's zero-dependency posture holds), and the env
  clamps moved to the FFI boundary that reads the environment, which their
  own doc already said owned "the ambient half". A sibling-lane write into
  the RandomX and FFI crates (rule 94 §6), disclosed in the commit and on
  the RandomX rows it touches. Also see §4.5's F10 on `Network::Fakechain`.
- **F11 (LANDED 9b, `dfea31dc9`) — the harness mock is never reconciled against the real view
  (ruled a gap 2026-09-19).** `BatchView` appears nowhere in
  `shekyl-chain-rules`; every rule landing in slices 1–9 is tested against
  a `MockChain` whose fidelity to the store's projection is **assumed**. The
  same shape as W12 (`BaseTestDB` overriding 0 of 15 archival hooks with
  green tests), CEN-I12 and SOK-10 (the e2e's `[0]` on a coinbase-only mine,
  where tree position and output index coincide and the conflation is
  unrepresentable), and the `curve_tree_roots` zero-root gap (permanent
  below ~160 blocks on FAKECHAIN, self-healing on a real chain — a regime
  production leaves and never returns to): *the condition that would expose
  the defect cannot occur in the test.* The distinction that makes the
  principle operational: the problem is not substitution but **unvalidated**
  substitution — a double's behaviour is the author's belief about the real
  thing, and a wrong belief passes the test and fails production, whether
  the double is a subsystem or a three-method trait. G1 forbids the rules
  crate from depending on the store, so the conformance test's home is the
  **store side**: each landed rule run against `BatchView` over a real store
  and against the mock, asserting identical verdicts and coverage. The
  dependency direction picks the location. Scoped into this slice as
  **commit 9b** (store side, after #783, with 9); if #783 has not landed
  when 1–8 are done, the deferral takes rule-22 shape with the falsifier
  `rg 'BatchView' rust/shekyl-chain-store/src/store/*conformance*` returning
  the harness.
- **F12 — every deviation from production configuration is a named row
  with a reason and a reopening criterion, and the set is gated (program
  principle, ruled 2026-09-19; not this slice's to mint).** The honest cost
  the principle must not pretend away: some deviations are unavoidable — a
  settlement epoch is 10 000 blocks and a segment freeze 25 992 leaves, so a
  corpus crossing either at production parameters is out of reach for a
  test, and the regtest epoch override exists because of that arithmetic.
  So the operational form is not "never deviate"; it is the shape already
  working four times over in this tree (`RUST_ONLY_TABLES`, `DEFERRED_DOCS`,
  the bijection map, `held_by_cxx`): a **test-deviation register** whose
  rows say what a test does and does not establish, with a gate that goes
  red when a deviation is acquired rather than declared. Then "what did this
  test prove" has an answer someone can read. Without the gate the principle
  erodes the way every ungated property here has — one convenient fixture at
  a time, with nothing going red. Proposed home
  `docs/design/TEST_DEVIATION_REGISTER.md` + `scripts/ci/check_test_deviations.py`;
  first rows: the two Fakechain consumers of §4.5, `SEEDHASH_EPOCH_*`
  (no consumer, no effect — F5), `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` (F8), the
  `curve_tree_roots` regime, `--fixed-difficulty=1` at every harness F9
  lists. Owner: the DRS program (E2's comparator is where "what did this
  test prove" is judged); FOLLOWUPS row carries the falsifier.
- **F13 — the census D4 row says the genesis constant is 100; the config
  says 400** (`config/consensus_constants.json:13` `daa_genesis_difficulty:
  400`, the 2026-09-11 testnet calibration per its own comment; 100 is the
  zawy12 historical pin). F3's class — row text stale against what shipped
  — **amended on the CEN-D4 row 2026-09-19** (the row now points at the JSON
  key and repeats no number). **Re-pointed on review before it reached a
  lane:** this pre-flight first filed it as a three-way discrepancy with the
  genesis tool's *"genesis difficulty is 1"*. That was two subjects read as
  one. `shekyl-difficulty/src/consts.rs:55` has `GENESIS_DIFFICULTY =
  DAA_GENESIS_DIFFICULTY` from the JSON, and `:94`–`:102` already
  distinguishes it from **the genesis block's own PoW difficulty of 1**,
  with a const assertion `GENESIS_DIFFICULTY > 1` keeping them apart —
  documented and gated. The "1" was never in question; the census's "100"
  was the only live figure. **And the re-pointing found a defect in this
  slice:** commit 5's `D4::target` returned the DAA constant at connecting
  height 0, reading `lwma1_next`'s `chain_height = 0` arm as genesis
  admission — it is the target for block **1** given a tip at 0; block 0
  has no tip and the DAA is not consulted. Judging genesis at 400 would have
  refused the shipped genesis block. Corrected in `15563dcd5`:
  `Target::GENESIS_BLOCK` (1) at connecting height 0 under every rule set,
  the same value the C++ forces there under `--fixed-difficulty`; fixtures
  pin block 0 at 1 and block 1 as the first judged at the constant. The
  FOLLOWUPS row filed for the three-way reading is withdrawn — resolved
  items are removed (rule 95).
---

## 7. Record at close of the rules-crate commits (1–8, 2026-09-19)

**Measured** (`check_chain_rules_coverage.py --describe` at the branch tip):
`consensus: implemented 16 / validator-enforced 151   held-by-cxx 2
enforced 153   ratified 126 / enforced 153`; `4.C 3/3`, `4.D 7/8`. C1, C2,
C3, D1, D1b, D2, D3, D4, D6, D7 flipped `pending → implemented`; D5
`pending` with its `subsumed-by-D4` registry comment (Q7). `ratified` did
not move: porting does not ratify (slice 1 §9). D1b and D7 are bucket-4
rows carried into the validator as-is with fixtures; the repair backlog's
denominator is unchanged by this slice. The pre-flight predicted
`15–16 / 151`; D7 landed under arm (d), so 16.

Rules crate: 102 unit tests + 14 doctests; the G1 belt at 184 packages with
neither forbidden one; `check_store_error_conversion_ban.py` green over the
new fault tokens; workspace `clippy -D warnings` clean.

**Commits 9 / 9b LANDED 2026-09-19** (`0aba3b815`, `dfea31dc9`): `connect`
writes `block_info.cumulative_difficulty` from the verdict and the field is
gone from `ConnectFacts` (`passed_through().count()` 7 → 6; `DELETED_BY` six
entries; `SCHEMA_VERSION` 7); the conformance harness runs green with its
negative control. The one piece the plan had in 9 that did not land —
`Fault::Corrupt` as a writer halt — is deferred with its blocker in §4.3 and
a FOLLOWUPS row.

---

## 8. Questions for the reviewer — round 1 (RULED 2026-09-19)

| # | Question | Default | Falsifier / what changes downstream | Ruling (2026-09-19) |
| --- | --- | --- | --- | --- |
| **Q1** | `Substrate` as a second trait beside `ChainView` (§4.2) — and do its faults unify with the view's? | **Second trait; one `Fault` type via `validate<V, S>` where `S::Fault: Into<V::Fault>`?** No — **distinct and both opaque**: `validate` returns `Result<Verdict<..>, Fault<V::Fault, S::Fault>>` (a two-arm enum the caller matches; the store's `connect` already handles one opaque fault and gains an arm). Unifying would let the store implement both with `StoreError` and lose the distinction between "the chain could not answer" and "the verifier could not compute". | If the caller never distinguishes them, the enum is ceremony — reopen when `connect`'s handling of the two arms is identical after E2. | **APPROVED, refined:** the trait binds to a **stateless stage** (`form` → `StructurallyValid`), not to `validate` — C2-R8's two-stage split keeps RandomX out of the write txn; faults distinct, as defaulted. Time-dependence sentence owed on the type. §4.2 as amended; consequences → §8.1 Q8, Q9. |
| **Q2** | Dependency: adopt `shekyl-difficulty` directly (one `shekyl-types` dep, no store); keep `shekyl-pow-randomx` **out** (behind `Substrate`). | **Yes to both.** G1's belt output before/after is the evidence (`check_chain_rules_no_store.sh`; closure grows by exactly `shekyl-difficulty`). | A rule that needs `compute_hash` in-crate — none named. | **APPROVED.** `shekyl-difficulty` depends on `shekyl-types` alone; G1-clean, verified. |
| **Q3** | Genesis admission (`connecting_height == 0`): C1/C2/C3 pass with no window (the C++'s `h == 0` arm, F3) — do the rows **record** as applied, or is coverage for them absent at height 0 (and therefore incomplete)? | **Record as applied.** The rule ran; its premise (a predecessor exists) was checked and found false; that is a decision, not a fall-through (G11). Complete coverage at genesis is what `connect` demands. | If the maintainer prefers "not applicable" to be visible in coverage, `RuleCoverage` needs an `n/a` state — a type change with 153 consumers; name it now or never. | **APPROVED as defaulted.** |
| **Q4** | CEN-D6 — a `NonZeroDifficulty` (or `Target`) type that D1 compares against, minted by D4's derivation and unconstructible from zero (**definition belt**, D6 recorded at the mint), or a predicate `target.is_zero() → refused(D6)`? | **Type.** F4: the predicate has no reachable refusal on main and would be a gate that cannot fail. The ratified statement ("a zero next-block difficulty rejects the block") is held **by construction** — the derivation site refuses to mint, and that refusal is the fault channel, not a verdict, exactly as the census's "marshaling belt on the FFI result" reads once the FFI is gone. | Slice 9's alt view: if D5's height-0 sentinel must become a *verdict* rather than a fault, the type stays and D6 gains a predicate arm there. | **APPROVED as defaulted** — a predicate with no reachable refusal is the gate that cannot fail; the `NonZero` mint is B6's move. |
| **Q5** | The verdict carries `target` only (store folds `parent.cum + target` under SI-8) or `cumulative_difficulty` too (validator computes, store persists)? And does `DELETED_BY`'s entry narrow to `["CEN-D4"]`? | **Carries both.** C2-R8 Q4: the store computes nothing consensus-visible; the fold is one `checked_add` but it is the definition of the stored quantity, and the Q1 ruling on `tip()` put per-block difficulty *and* the arithmetic on it in this crate. `DELETED_BY` narrows to D4 with the F6 reason in the comment. | If S-CHAIN-W's owner rules the fold store-side (as `cumulative_tx_count` is), the verdict carries `target` only and the store's SI-8 arm grows one line. | **APPROVED as defaulted.** |
| **Q6** | CEN-D7 `--fixed-difficulty`: (a) port as-is — `Substrate::difficulty_override() -> Option<Difficulty>`, height 0 forced to 1, fixture; (b) leave `pending` until R9's test-seam ruling; (c) rule now that the lever is the **substrate's**: a regtest `Substrate` implementor returns a constant `longhash` that always satisfies the target, and the DAA is never bypassed. | **(c)**, if the maintainer will rule it here; else (a). Under (c) the validator has no override path at all, `regtest_e2e.rs:243`'s flag is reinterpreted by the daemon's implementor, D7 becomes **REJECTED** in the registry (the lever moved to where a test seam belongs), and the "test-only carve-out live in the production binary" is deleted rather than ported. | (a) if regtest needs the difficulty *value* fixed (fee/emission tests that read it), not merely PoW to pass — check `tests/functional_tests` and the GUI regtest harness before ruling; that is the sweep this row owes and it is not done here. | **APPROVED (c) conditionally — run the falsifier before commit, not after.** Run 2026-09-19: **(c) fails it** (F9: `drs_bench.py` measures real RandomX at a lowered target; difficulty 1 is a deliberate test locus). Fourth arm → §8.1 Q10. |
| **Q7** | D5 `subsumed-by-D4` (stays `pending`, closes with slice 9's alt view) — or `implemented` now, on the grounds that D4 over any `ChainView` *is* D5? | **Subsumed, pending.** No alt view exists to drive a fixture; `implemented` without a fixture is the PWD-B10 shape. | Slice 9 lands the alt view: D5's fixture is D4 over it, row closes. | **APPROVED as defaulted** — subsumed, not deferred: the A3/B4 distinction; closes when D4 gets an alt view. |

### 8.1 Round 2 — consequences of the Q1 ruling, and Q6's fourth arm (RULED 2026-09-19)

**Q8 — RULED: take the split** ("my staging was wrong on the facts"). `Stale::Seed`
is a **fourth kind** — unproven is not disproven, not a validator hole, not a
store capability limit — with two attachments: **(i) the conversion ban
extends to it** — no `From`/`Into` between `Stale` and `InvalidBlock`, a
separate arm at every consumer, and `check_store_error_conversion_ban.py`
covers both (a retry arm is *more* tempting to collapse, because "couldn't
prove it" reads like "rejected it"); **(ii) the retry is bounded with a named
terminal outcome** — an unbounded redo on an attacker-influenced trigger
(sustained reorg pressure) is a DoS primitive; the bound is specified now,
before anyone writes the loop. The falsifier (does a second fault kind at
`connect` change the store lane's signature) **runs before commit 1** — §8.2.
**Q9 — RULED: yes.** Stage membership is a property (view-dependence), not a
record of which slice added what; B1 reads `RuleSet` and the candidate, so it
is view-free by that test. **Q10 — RULED: arm (d)**, with one correction and
one caveat, both recorded in §4.5.

| # | Question | Default | Falsifier / what changes downstream |
| --- | --- | --- | --- |
| **Q8** | The Q1 staging put D1/D2/D3 in the stateless stage, but D3's seed is a chain read and D1's target is D4's derivation (§4.2). Split as: **D2** (`longhash`) in `form` under a **caller-supplied seed**; **D3** verifies that seed against the committing view in `validate`, a mismatch being a crate-defined **fault** (`Stale::Seed`, "redo `form`") rather than `InvalidBlock`; **D1/D1b** compare in `validate`. Or: forbid the split and accept RandomX inside the txn for D1–D3 only? | **The split.** The expensive call stays outside the txn, which was the ruling's point; every chain-dependent judgement stays inside it, which was C2-R8 Q3's. The seed height is ≥ 64 blocks below `c` by construction (`seedheight`, 2048/64), so `Stale::Seed` fires only on a ≥ 64-block reorg between the stages — the block is unproven, not disproven, hence a fault. The caller (the daemon's ingest driver; E2's replay) reads the seed id from any snapshot. | If the store lane rules that `connect` must never see a crate-defined fault beside the view's (one opaque type only), `Stale::Seed` becomes a `Verdict` arm that is *not* `InvalidBlock` — a third verdict kind — and that is a bigger change than the enum arm; say so now. |
| **Q9** | Do B1, B2, B7 (view-free, landed in slice 1 on `validate`) move to `form`? | **Yes.** The partition is "reads the view or not", and a stage whose membership is "what slice 2 happened to add" is the accretion pattern. Their tests move unchanged; coverage unions. | If moving landed rules in a slice that is not theirs is ruled out of scope, they stay and the partition is documented as "view-free rules added from slice 2 onward" — worse, but honest. |
| **Q10** *(RULED (d), with an owed item — §4.5: the motivating consumers are unserved until the witness and the daemon wiring land)* | CEN-D7, fourth arm **(d): the fixed target enters as `RuleSet` data on FAKECHAIN only.** `rules_at(Network::Fakechain, …)` may issue a rule set whose difficulty parameter is `DifficultyRule::Fixed(NonZeroDifficulty)`; D4 reads `rule_set.difficulty()` — `Lwma1` derives, `Fixed(d)` returns `d` (height 0 → 1, as today). The constructor takes a `Fakechain` **witness type** obtainable only from `Network::Fakechain`, so no public-network code path can build one — the production binary has no override path *by type*, which was (c)'s virtue, and the target is really fixed, which is what F9's consumers need. `--fixed-difficulty` becomes the daemon's argument to that constructor. D7 then flips `implemented(rules::difficulty::D4)` (the `Fixed` arm is D4's), and the census row's "test-only carve-out live in the production binary" is deleted as a description, not ported as a mechanism. | **(d).** Rule 71 is satisfied literally: nettype selects **data**; the control flow is one `match` on a rule-set field that every nettype has. | (i) `RuleSet` is `Copy` and issued from a `const` list; a runtime `Fixed(d)` needs a constructor beside `for_id` and a `RuleSetId` for the persisted coverage — proposal: id `GENESIS` with the parameter carried on the value (fakechain chains are not comparable across processes anyway). If the store lane objects to a non-`ISSUED` rule set reaching `connect`, arm (a) (`Substrate::difficulty_override`) is the fallback, with the production implementor returning `None` as a **discipline**, not a structure — recorded as such. (ii) If any consumer needs *real* PoW at a fixed target **and** a fake longhash elsewhere, neither (c) nor (d) alone serves; none found. |

The seed-epoch lever (F5) has no consumer and no effect under the staging;
it is **not** given an arm here. If one is ever needed it takes Q10's shape
(`SeedSchedule` data on a fakechain rule set), and the register row's pass
condition (CEN-D3, §5.4.1) already says so.

---

### 8.2 Q8's falsifier — run before commit 1 (2026-09-19)

*Does a second fault kind at `connect` change the signature the store lane
consumes?* **No.** `ChainStore::connect` takes a `ChainValid<'id,
BatchView<'_, 'id>>` (`store/connect.rs:307`–`:312`), never `validate`'s
`Result`; and `validate` has **no production caller** outside the rules
crate (`rg` over `rust/` excluding the crate: doc mentions only — E2's
replay driver, the caller-to-be, is unlanded). The second fault kind
changes the **driver's** signature, not the store lane's. The store's own
test fixtures do call `validate` (`connect_fixtures.rs`, `view_tests.rs`)
and were adapted in commit 2 — test-only edits in #783's files, disclosed
there.

---

## 9. What this round did not examine (denominator)

4.E onward; the alt path (`handle_alternative_block`, `:2201`–`:2381`) beyond
what D5/D6 required to classify; the miner template's use of the MTP median
(daemon-side, unchanged); the RandomX cache lifecycle in the daemon
implementor (E2's / the daemon rewrite's); whether `lwma1_next`'s
`Error::Overflow` (non-monotone cumulative difficulty) is a fault or a
verdict — it cannot occur over a store that holds SI-8, so it is a fault at
this pin, recorded here so slice 9 re-asks it for alt windows; `--fixed-difficulty`'s
consumers outside the daemon (Q6's owed sweep).

---

## 10. Round log

| Date | Event |
| --- | --- |
| 2026-09-18 | Pre-flight written against `dev` @ `5adfc5423`. Q1–Q7 proposed with defaults. **HALT** for rulings (rule 26). |
| 2026-09-19 | **Round 1 RULED** (Q1–Q7). Q1 approved with the staging refinement (`Substrate` → the stateless stage `form` / `StructurallyValid`); Q2–Q5, Q7 as defaulted; Q6 approved conditionally on its falsifier, which then **failed (c)** (F9). F3 reclassified as a census amendment (CEN-C1 row bracketed); F5 promoted to a CSR-3a register entry (CEN-D3 row, pass condition added); F8 the `blockchain.cpp:330` check (SCW-2 holds; slice-8 forward pin). **Round 2 proposed:** Q8 (seed as caller-supplied claim, verified in `validate`; D1 compares there), Q9 (B1/B2/B7 move to `form`), Q10 (D7 arm (d): fixed target as fakechain `RuleSet` data behind a witness type). **HALT** for Q8–Q10, or proceed on defaults if instructed. |
| 2026-09-19 | **Round 2 RULED** (Q8 the split, with the conversion-ban extension and the bounded retry; Q9 yes; Q10 arm (d) with the corrected claim and the `RuleSetId` caveat — §4.5). **Commits 1–8 on the rulings.** Q8's falsifier ran first (§8.2: `connect` unaffected). Commits 1–5 landed on the branch; F10 forced commit 6a (the seed-epoch schedule's home). **Program findings taken from the reviewer's four instances:** F11 (the mock is never reconciled against `BatchView` — commit 9b), F12 (the test-deviation register — program-level, FOLLOWUPS), F13 (census D4 constant 100 vs config 400; genesis-tool "difficulty 1" — routed). |
| 2026-09-19 | **Review of commits 1–8.** F4 refined into a rule-47 amendment (the cannot-fail test runs over the adversarial input space; D6's arm is reachable from a no-work view). F13 re-pointed: the "1" is the genesis *block's* own difficulty, already gated (`consts.rs:94`); only the census's 100 was live — amended on CEN-D4 — **and the re-pointing exposed a slice defect: D4 judged block 0 at the DAA constant; corrected to `Target::GENESIS_BLOCK` (1) in `15563dcd5`.** F10 → an owed item on Q10 naming both unserved consumers (FOLLOWUPS). F12's falsifier made one that fires (the first E2 pre-flight). Next: sweep #783/#784 (merged), then commits 9 / 9b. |
| 2026-09-19 | **Commits 9 / 9b / 10 LANDED; file CLOSED-as-record → `completed/`.** Swept #783 (layout v6, `connect.rs` restructured; the `cumulative_difficulty` fact intact) and #784 (SOK-10 deletions; nothing this slice touches), merged (`3b49001fd`). Commit 9 deleted the fact rather than flipping it (§4.3) — `SCHEMA_VERSION` 7. Commit 9b's harness agrees on 7 shapes × 3 chain lengths and goes red on a drifted mock. `Fault::Corrupt` at connect deferred with its blocker (no driver; §4.3). Residue: FOLLOWUPS (Q10 owed consumers, F12 register, Corrupt writer-halt). |
