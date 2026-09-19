# `shekyl-chain-rules` slice 2 — census 4.C + 4.D (DRS-E6 increment 3)

**Status:** OPEN — **Round 1 proposed** (pre-flight written 2026-09-18
against `dev` @ `5adfc5423`, post-#782). No production code until the §8
questions are ruled (rule 26 halt). Template:
[`CHAIN_RULES_CRATE.md`](CHAIN_RULES_CRATE.md) §7.5.1; predecessor
[`CHAIN_RULES_SLICE_1.md`](../completed/CHAIN_RULES_SLICE_1.md). Parent
plan: [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §7.5 table 3 (*"slice 2 —
MTP / FTL; body in `shekyl-difficulty` (adopt)"* / *"LWMA-1 body in
`shekyl-difficulty`, PoW in `shekyl-pow-randomx` (adopt)"*). Cites
`26-sub-pr-design-discipline.mdc`. The living contract is
[`CHAIN_RULES_CRATE.md`](CHAIN_RULES_CRATE.md); do not implement from this
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
| CEN-D3 | 1 | `seedheight(h) = 0 for h ≤ 2112, else (h−65) & ~2047`; seed = block id at that height | `seedheight` (`seed_epoch.rs:109`); constants `:46`/`:48` | `cryptonote_tx_utils.cpp:777` | **Land** — the rule derives the seed height from the connecting height and reads `block_at(seedheight).hash`; the env override (`clamp_lag`/`clamp_blocks`, `:55`/`:72`) is **not** read here — the validator has no environment (rule 71) |
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

`validate` grows one parameter (`substrate: &S`) and one fault channel.
§8 Q1 asks whether the two faults unify (`S::Fault = V::Fault`, one
`Result`) or stay distinct (a `Fault<V, S>` enum). `PowHash` is a new
`hash32!` member in `shekyl-types` — a longhash is not a `BlockHash` and
the type refuses the transposition (RTN pattern; `RAW_TYPE_NEWTYPE_MIGRATION.md`
row, disclosed to that lane).

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
so the store's `connect` reads the value the validator computed:
`ConnectFacts.cumulative_difficulty` flips from `Fact::passed_through` to
`Fact::derived` (`connect.rs:123`/`:131`), and `passed_through()`'s count
goes **7 → 6** — the direction the SCR-10 note says it moves when E6 lands
a deriving row (`connect.rs:246`–`:251`). This is the first such flip; it is
the pattern 4.G's weight rows will repeat.

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
2. `chain-rules: Substrate trait; validate takes it; harness MockSubstrate` — no rule yet; every existing test passes with a mock that is never called.
3. `chain-rules: RecordedBlock.cumulative_difficulty; MockChain carries it` — the view growth; store projection **not** in this commit (C9).
4. `chain-rules: CEN-C1/C2/C3 — timestamps over the view` + three fixtures.
5. `chain-rules: CEN-D4 as a definition row; ValidatedBlock.target` + fixture.
6. `chain-rules: CEN-D3, D2, D1, D1b — seed, longhash via Substrate, target comparison` + fixtures.
7. `chain-rules: CEN-D6` per Q4; `CEN-D5 subsumed-by-D4` registry comment; `CEN-D7` per Q6.
8. `chain-rules: coverage — registry flips; expected record` (§7).
9. `chain-store: BatchView projects cumulative_difficulty; connect derives it from the verdict` — **after #783 merges**, rebased on layout v6; S-CHAIN-W row disclosure.
10. `docs` — §7's record, index rows, CHANGELOG (security-relevant: the validator now decides PoW and timestamps), FOLLOWUPS sweep, this file to `completed/`.

Commits 1–8 can start when the round is ruled; C9 waits for #783 regardless.

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
  the exemption. Not a divergence to repair now (parity first, §7.6); it is
  recorded so Q3's default is checked against what the C++ does, not what the
  row says.
- **F4 — `Difficulty` can be zero by construction.** `Difficulty::ZERO`
  exists (`types.rs:25`) and `from_raw(0)` is `const fn`; the only producer
  that would return it is D5's height-0 alt sentinel, which has no Rust
  caller. D6 as a *predicate* would be a check with no reachable refusal on
  main — the "gate that cannot fail" slice 1 Q5 declined for B6. Q4.
- **F5 — the seed-epoch env override is a validator-side read today.**
  `clamp_lag`/`clamp_blocks` read `SEEDHASH_EPOCH_*`; the C++ refuses them on
  public networks at init. The validator must not read the environment
  (rule 71: nettype selects data, never control flow on the consensus
  surface). §4.2's D3 uses the two constants; the fakechain lever, if kept,
  is the daemon implementor's and is out of this crate.
- **F6 — `DELETED_BY` names D5 beside D4 for `cumulative_difficulty`**
  (`connect.rs:204`–`:206`). The Rust store has no alt-admission path, so D4
  alone lets `connect` derive the field for every block it will connect
  before slice 9. Q5 asks whether the entry's `rows` narrows to D4 or stays
  as written with the reason recorded.
- **F7 — `RecordedBlock`'s comment already promised this field**
  (`view.rs:126`: "cumulative difficulty and weight arrive with 4.D / 4.G").
  A promise kept on schedule; noted so nobody reads it as drift.

---

## 7. Expected record at close

`consensus: implemented 15 / validator-enforced 151   held-by-cxx 2
enforced 153   ratified 126 / enforced 153` (C1, C2, C3, D1, D1b, D2, D3,
D4, D6 flip `pending → implemented`; D5 `pending` with a `subsumed-by-D4`
comment; D7 per Q6 — **16** if it lands). `ratified` does not move:
porting does not ratify (slice 1 §9). D1b and D7 are bucket-4 rows carried
into the validator as-is with fixtures; the repair backlog's denominator is
unchanged by this slice.

Store: `passed_through().count()` 7 → 6.

---

## 8. Questions for the reviewer — round 1

| # | Question | Default | Falsifier / what changes downstream |
| --- | --- | --- | --- |
| **Q1** | `Substrate` as a second trait beside `ChainView` (§4.2) — and do its faults unify with the view's? | **Second trait; one `Fault` type via `validate<V, S>` where `S::Fault: Into<V::Fault>`?** No — **distinct and both opaque**: `validate` returns `Result<Verdict<..>, Fault<V::Fault, S::Fault>>` (a two-arm enum the caller matches; the store's `connect` already handles one opaque fault and gains an arm). Unifying would let the store implement both with `StoreError` and lose the distinction between "the chain could not answer" and "the verifier could not compute". | If the caller never distinguishes them, the enum is ceremony — reopen when `connect`'s handling of the two arms is identical after E2. |
| **Q2** | Dependency: adopt `shekyl-difficulty` directly (one `shekyl-types` dep, no store); keep `shekyl-pow-randomx` **out** (behind `Substrate`). | **Yes to both.** G1's belt output before/after is the evidence (`check_chain_rules_no_store.sh`; closure grows by exactly `shekyl-difficulty`). | A rule that needs `compute_hash` in-crate — none named. |
| **Q3** | Genesis admission (`connecting_height == 0`): C1/C2/C3 pass with no window (the C++'s `h == 0` arm, F3) — do the rows **record** as applied, or is coverage for them absent at height 0 (and therefore incomplete)? | **Record as applied.** The rule ran; its premise (a predecessor exists) was checked and found false; that is a decision, not a fall-through (G11). Complete coverage at genesis is what `connect` demands. | If the maintainer prefers "not applicable" to be visible in coverage, `RuleCoverage` needs an `n/a` state — a type change with 153 consumers; name it now or never. |
| **Q4** | CEN-D6 — a `NonZeroDifficulty` (or `Target`) type that D1 compares against, minted by D4's derivation and unconstructible from zero (**definition belt**, D6 recorded at the mint), or a predicate `target.is_zero() → refused(D6)`? | **Type.** F4: the predicate has no reachable refusal on main and would be a gate that cannot fail. The ratified statement ("a zero next-block difficulty rejects the block") is held **by construction** — the derivation site refuses to mint, and that refusal is the fault channel, not a verdict, exactly as the census's "marshaling belt on the FFI result" reads once the FFI is gone. | Slice 9's alt view: if D5's height-0 sentinel must become a *verdict* rather than a fault, the type stays and D6 gains a predicate arm there. |
| **Q5** | The verdict carries `target` only (store folds `parent.cum + target` under SI-8) or `cumulative_difficulty` too (validator computes, store persists)? And does `DELETED_BY`'s entry narrow to `["CEN-D4"]`? | **Carries both.** C2-R8 Q4: the store computes nothing consensus-visible; the fold is one `checked_add` but it is the definition of the stored quantity, and the Q1 ruling on `tip()` put per-block difficulty *and* the arithmetic on it in this crate. `DELETED_BY` narrows to D4 with the F6 reason in the comment. | If S-CHAIN-W's owner rules the fold store-side (as `cumulative_tx_count` is), the verdict carries `target` only and the store's SI-8 arm grows one line. |
| **Q6** | CEN-D7 `--fixed-difficulty`: (a) port as-is — `Substrate::difficulty_override() -> Option<Difficulty>`, height 0 forced to 1, fixture; (b) leave `pending` until R9's test-seam ruling; (c) rule now that the lever is the **substrate's**: a regtest `Substrate` implementor returns a constant `longhash` that always satisfies the target, and the DAA is never bypassed. | **(c)**, if the maintainer will rule it here; else (a). Under (c) the validator has no override path at all, `regtest_e2e.rs:243`'s flag is reinterpreted by the daemon's implementor, D7 becomes **REJECTED** in the registry (the lever moved to where a test seam belongs), and the "test-only carve-out live in the production binary" is deleted rather than ported. | (a) if regtest needs the difficulty *value* fixed (fee/emission tests that read it), not merely PoW to pass — check `tests/functional_tests` and the GUI regtest harness before ruling; that is the sweep this row owes and it is not done here. |
| **Q7** | D5 `subsumed-by-D4` (stays `pending`, closes with slice 9's alt view) — or `implemented` now, on the grounds that D4 over any `ChainView` *is* D5? | **Subsumed, pending.** No alt view exists to drive a fixture; `implemented` without a fixture is the PWD-B10 shape. | Slice 9 lands the alt view: D5's fixture is D4 over it, row closes. |

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
