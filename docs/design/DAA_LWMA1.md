# LWMA-1 — Difficulty adjustment, Rust, from genesis

**Status.** **DRAFT — Round 0 (initial draft, 2026-05-17).** Phase 0
deliverable for the Shekyl difficulty-adjustment algorithm (DAA)
migration. Companion: [`DAA_LWMA1_PLAN.md`](./DAA_LWMA1_PLAN.md). Both
documents must pass the Phase 0 review cycle before any code lands.

**Scope.** Shekyl's target difficulty adjustment is **LWMA-1** (Linear
Weighted Moving Average, variant 1) from zawy12's canonical reference
([`zawy12/difficulty-algorithms#3`](https://github.com/zawy12/difficulty-algorithms/issues/3)).
The inherited CryptoNote cut-windowed-average algorithm in
[`src/cryptonote_basic/difficulty.cpp`](../../src/cryptonote_basic/difficulty.cpp)
is **deleted** at genesis, not gated behind a hard-fork version. No
backward compatibility: no `DIFFICULTY_LAG`, no `DIFFICULTY_CUT`, no
720-block window.

**Sibling track.** LWMA-1 ships **independently of and in parallel
with** the RandomX v2 PoW migration documented in
[`RANDOMX_V2_RUST.md`](./RANDOMX_V2_RUST.md). The two are
math-orthogonal — RandomX v2 changes the hash function; LWMA-1 changes
the difficulty adjustment that operates on `(timestamps,
cumulative_difficulties)`. Each is a separable Phase 0 → cutover
sequence. LWMA-1 lands first because it has zero external-audit
dependency, substantially smaller scope, and exercises the C++→Rust
consensus-replacement pattern before the larger RandomX v2 cutover
stresses it.

---

## 1. Why LWMA-1

### 1.1 The inherited algorithm and why it isn't right for Shekyl

Shekyl inherits CryptoNote's cut-windowed-average DAA at
[`src/cryptonote_basic/difficulty.cpp:122-163, 203-240`](../../src/cryptonote_basic/difficulty.cpp).
The inherited shape is:

1. Sort the last `DIFFICULTY_WINDOW` (720) timestamps.
2. Cut `DIFFICULTY_CUT` (60) outliers from each end after sorting.
3. Compute `time_span = timestamps[cut_end - 1] - timestamps[cut_begin]`.
4. Compute `total_work = cumulative_difficulties[cut_end - 1] -
   cumulative_difficulties[cut_begin]`.
5. Return `next_difficulty = (total_work * target_seconds +
   time_span - 1) / time_span`.

Plus a `DIFFICULTY_LAG = 15` (declared in
[`src/cryptonote_config.h:85`](../../src/cryptonote_config.h) with a
literal `// !!!` warning comment) that delays the response by 15
blocks.

**Three Shekyl-specific reasons this is the wrong inheritance** (per
`16-architectural-inheritance.mdc`, "inheriting code is not inheriting
architecture"):

1. **Window size is calibrated for a mature large-hashrate chain, not
   a bootstrapping CPU-mineable one.** 720 blocks at 120 s/block is a
   24-hour averaging window. For Shekyl's V3.0 launch — a CPU-only
   RandomX v2 chain at small initial hashrate, where adopters and
   miners will join and leave on the timescale of hours — a 24-hour
   window produces multi-hour lag in difficulty response. The miner
   experience during the bootstrap regime is "fast blocks for hours,
   then stuck blocks for hours" rather than the steady ~120 s cadence
   the algorithm targets.

2. **The `DIFFICULTY_LAG = 15` carries its own `// !!!` warning in the
   inherited code.** A constant whose canonical definition includes a
   triple-exclamation-mark warning that survived ~12 years of
   CryptoNote development is structural debt, not stable design. Per
   `15-deletion-and-debt.mdc` "default: delete," this is exactly the
   shape that gets removed at genesis pre-V3-launch.

3. **The cut-windowed average is timestamp-attack-naive by modern
   standards.** Cut-of-60 from each end handles only modest outliers;
   sustained timestamp manipulation against a small-hashrate chain
   bypasses it. LWMA-1's solvetime clamp + bias factor + minimum-L
   floor are the post-2017 community consensus on what timestamp
   attacks actually require defending against.

The disposition is to delete the inherited DAA — not to gate it
behind a hard-fork version, not to keep it as a fallback. Per
`60-no-monero-legacy.mdc`, Shekyl begins at genesis with
`RCTTypeFcmpPlusPlusPqc` as the minimum transaction type and
`HF_VERSION_LWMA1` (= 1) as the minimum DAA hard fork. Code that
handles pre-genesis CryptoNote difficulty is dead-code-on-day-one.

### 1.2 Why LWMA-1 specifically, against the priority hierarchy

Per `00-mission.mdc`:

**Commitment 1 (security and quantum resilience).** LWMA-1 is
PoW-input-independent — it operates on `(timestamp,
cumulative_difficulty)` tuples, not on the PoW hash itself, so it
doesn't intersect Shekyl's PQC posture at all. The algorithm's
security against timestamp-manipulation attacks is well-characterized
through ~8 years of real-world deployment (early Masari, multiple
Monero forks, smaller CPU-mineable projects per zawy12 Issue #3) and
through the simulation tooling in the canonical zawy12 repository
(hundreds of thousands of historical-data blocks). No PoW-side
weakening; no PQC-side weakening; structurally orthogonal to both.

**Commitment 2 (privacy is the product).** LWMA-1's linear weighting
introduces natural jitter in block intervals compared to smoother
algorithms (ASERT, EMA variants). For a privacy-focused chain where
transactions are broadcast over anonymity networks (Tor, I2P), more
variable block production adds natural obfuscation against the
statistical timing attacks that try to correlate broadcast-time with
block-find-time. This is a recognized DAA-design *side-effect*
rather than a primary LWMA goal (zawy12 doesn't advertise it; it
appears in scattered community discussions for anonymity-focused
chains) — but it aligns with mission commitment 2's "privacy is the
product" framing precisely because the inherent noise is privacy
surface that costs nothing else.

The benefit is most material during the **small-chain bootstrap
regime** when broadcast traffic is sparse and individual broadcasts
are easier to time-correlate. Once the network reaches a stable
mature hashrate with continuous transaction flow, the per-broadcast
correlation surface shrinks and the LWMA jitter benefit becomes
marginal. The disposition is to accept the side-benefit now without
treating it as load-bearing — if a future audit identifies that
ASERT's smoother behavior would deliver materially better
long-term-stability properties at the cost of negligible
privacy-jitter loss, the reversion clause in §10 covers that.

**Commitment 3 (the system must outlast the team).** LWMA-1 is a
2017-vintage algorithm with extensive post-2017 community testing.
LWMA-2/3/4 were evaluated against LWMA-1 by zawy12 and the broader
DAA community; they were not consistently better and sometimes
introduced oscillation artifacts in specific hashrate regimes — so
LWMA-1 remains the recommended baseline as of 2025–26 (the canonical
zawy12 repository is still actively referenced in 2026 papers and
projects, including post-quantum experiments). The algorithm is
simpler to reason about, debug, and audit than exponential
algorithms (ASERT, EMA), which matters disproportionately for an
unknown future maintainer who inherits the Shekyl codebase. The
canonical reference at zawy12 is a maintained dependency-of-
knowledge, not a frozen one.

### 1.3 Alternatives considered, with reversion clauses

Per `21-reversion-clause-discipline.mdc`, every rejected alternative
must record the conditions that would reopen the decision. The
alternatives below are rejected for Shekyl V3.0; each can be
revisited under named conditions.

**LWMA-2 / LWMA-3 / LWMA-4.** Iterative refinements of LWMA-1 (2018,
zawy12 Issue #3). LWMA-2 adds an 8 % jump rule when the last three
solvetimes fall below 0.8×T; LWMA-3 and LWMA-4 extend the jump rule
with multi-window logic. Community testing across multiple coins did
not establish consistent superiority over LWMA-1; later variants
introduced complexity (additional weighting schemes, more aggressive
adjustments) that produced oscillation artifacts in specific
hashrate regimes. zawy12 himself documents LWMA-4 as inappropriate
for CryptoNote-lineage coins unless pool software adjusts timestamps
during hashing — a constraint Shekyl pools cannot be relied upon to
satisfy. *Reversion criterion:* a Shekyl-specific simulation against
the canonical zawy12 tooling demonstrates that LWMA-2+ has materially
better behavior under Shekyl's specific hashrate profile (CPU-only
RandomX v2; small-chain bootstrap regime) — reopen the disposition
in a new design doc.

**ASERT (Absolutely Scheduled Exponentially Rising Targets).**
Theoretically smoother long-term stability; strong deployment record
on Bitcoin Cash; respected in DAA literature. Rejected for
Shekyl-specific reasons: (a) ASERT's smoothness reduces the
privacy-jitter side-benefit material to commitment 2 above; (b)
LWMA-1's faster response to hashrate changes is better-shaped for
the small-chain bootstrap regime where CPU miners join and leave on
short timescales; (c) ASERT's exponential math raises the
reasoning-load floor for future maintainers more than LWMA-1's
linear-weighted average does. *Reversion criterion:* Shekyl's
hashrate volatility damps to long-term equilibrium
(post-bootstrap stable regime; e.g., several years post-genesis with
consistent CPU miner participation) AND the privacy-jitter benefit
is no longer load-bearing (audit confirms the small-chain
broadcast-time-correlation surface has closed). Both conditions must
hold; reopen with a new design doc that quantifies the
load-bearing-ness change.

**Keep inherited CryptoNote cut-windowed average, retuned.** Reduce
`DIFFICULTY_WINDOW` from 720 to ~90, drop `DIFFICULTY_LAG`, keep the
cut-of-60 outlier excision. Rejected: it preserves architectural
inheritance for no Shekyl-specific gain, leaves the `// !!!` debt in
the codebase, and trades community-vetted LWMA-1 for an in-house
variant with no test corpus or simulation backing. The
cut-windowed-average's structural posture against timestamp
manipulation is weaker than LWMA-1's solvetime-clamp posture by the
zawy12 community's consensus. *Reversion criterion:* none plausible;
this is the inheritance disposition the rule
`16-architectural-inheritance.mdc` explicitly directs to migrate.

**Simple Moving Average (SMA) with a small window.** Trivial to
reason about and audit; trades response speed for stability. Rejected
because LWMA-1's solvetime-clamp + weight-shape captures the same
simplicity advantage while adding the timestamp-manipulation
defenses that an unweighted SMA lacks. SMA is the pre-2017 baseline;
LWMA-1 is the 2017+ refinement that delivered the same response
characteristics with better attack resistance. *Reversion criterion:*
none plausible; SMA's properties are a strict subset of LWMA-1's.

### 1.4 Why now (pre-genesis), not V3.x

Per `15-deletion-and-debt.mdc`, the pre-V3-launch migration path is
`rm -rf ~/.shekyl` and re-sync. Pre-genesis, schema migrations and
data-model restructurings are bounded work. Post-genesis, a DAA
change requires a hard fork, an activation window, and a coordinated
parameter change against live mining infrastructure. The asymmetry
strongly favors landing LWMA-1 at genesis.

Per `16-architectural-inheritance.mdc`, the cost-benefit-defer-to-
later anti-pattern systematically underweights the deferred cost of
structural inheritance. The CryptoNote DAA is structural inheritance
that contradicts Shekyl's threat model (timestamp-manipulation
defense calibrated for a small-hashrate bootstrap regime). The
architectural-integrity-now answer is the default unless cost is
genuinely prohibitive — and the cost here is bounded by Phase 0 design
plus one Rust crate plus one C++ deletion-and-rewire PR. Not
prohibitive.

## 2. Permanent architectural decisions

These decisions are made now and locked. Any future proposal to
reverse them must start with a new design doc that addresses the
rationale below.

### 1. Rust implementation, from genesis

Per `20-rust-vs-cpp-policy.mdc` rule 2 (Rust if any of: defines a
cryptographic contract that other code consumes), the DAA is a
cryptographic-contract surface — the verifier, the validator, and the
wallet all consume the same `next_difficulty(timestamps[],
cumulative_difficulties[], target_seconds) -> next_difficulty`
contract. Rust enforces the contract at the type system; C++
enforces it in documentation. The type-system enforcement is the
correct disposition.

The Rust crate is **`shekyl-difficulty`**, a new workspace member
under `rust/`. It is a sibling of `shekyl-pow-randomx` (the eventual
RandomX v2 verifier crate per `RANDOMX_V2_RUST.md`), not a child;
DAA and PoW are math-orthogonal surfaces and the crate-level
separation reflects that.

### 2. Single algorithm path, no version dispatch

Genesis ships with LWMA-1 and nothing else. There is no
`HF_VERSION_LWMA1` gate, no fallback to inherited Monero DAA, no
"v1 difficulty" path. Per `60-no-monero-legacy.mdc`, code that
checks `if (hf_version < HF_VERSION_LWMA1)` is dead code at genesis
and gets deleted, not gated.

This is the same disposition as the RandomX v2 plan's "no
`RX_BLOCK_VERSION` gate, no version-dispatch switch" framing
(`RANDOMX_V2_RUST.md` §13).

### 3. Spec is the source of truth, the reference implementation is the cross-check

The Rust implementation is written from zawy12's canonical
LWMA-1 specification in
[`zawy12/difficulty-algorithms#3`](https://github.com/zawy12/difficulty-algorithms/issues/3)
at the issue's HEAD as of the design-doc pin date (recorded in §3
below). The reference C++ implementation in the same issue is the
cross-check, not the source of truth: if the Rust implementation and
the C++ reference disagree, the spec (the text of the issue plus the
zawy12 simulator behavior) wins and a bug is filed against the C++
reference.

This is the same doctrine as the RandomX v2 plan's "Spec Is the
Source of Truth" framing (`RANDOMX_V2_RUST.md` §3).

### 4. The pre-design sketch is not the canonical implementation

A pre-design Rust sketch existed at
`rust/shekyl-difficulty/src/lwma1.rs` during early Phase 0
reconnaissance. It was deleted (Phase 0, 2026-05-17) before any
implementation work began so that Phase 1 starts from an empty crate
directory and is written fresh against this design doc's §5.3
algorithm specification. The divergences below are recorded as the
design rationale for why the sketch did not become the
implementation — they are an explicit anti-pattern catalogue, not a
description of any committed code. Concrete divergences from zawy12
canonical LWMA-1:

- Sketch uses a `clamp_factor` max-change-per-block parameter (3× by
  default). Canonical LWMA-1 has no per-block output clamp — output
  variance is controlled by the solvetime clamp (`6*T` on individual
  solvetime contributions to the weighted sum) and the
  minimum-L floor (`L = max(L, N*N*T/20)`). Per the canonical
  reference and zawy12 community discussion, a per-block output clamp
  was an LWMA-2-era addition that produced positive-feedback loops
  on small chains and was removed from the canonical line.
- Sketch's weighted sum operates on caller-supplied solvetimes
  (deltas). Canonical LWMA-1 operates on raw timestamps and computes
  solvetimes internally, applying the out-of-sequence safety
  conversion (`if timestamps[i] <= previous_timestamp: solvetime = 1`,
  else clamp to `6*T`).
- Sketch lacks the `N*N*T/20` minimum-L floor.
- Sketch lacks the canonical `99/200` bias factor in the
  `next_D = (avg_D * N*(N+1)*T*99) / (200*L)` formula.
- Sketch's test vectors are author-authored, not derived from the
  zawy12 simulator output on historical data.

**Disposition.** The sketch was **deleted** during Phase 0 so that
no on-disk pre-design code can accidentally become the starting
point for the implementation crate (PR B in
[`DAA_LWMA1_PLAN.md`](./DAA_LWMA1_PLAN.md)). PR B writes the
implementation fresh against this design doc's §5.3 algorithm
specification and §8 test-vector strategy. The divergence catalogue
above is preserved here as the design record of why each non-canonical
shape is rejected; it is not a description of any committed source.

### 5. FTL and MTP are co-tuned with N

The canonical LWMA-1 specification explicitly couples the DAA window
size N to two related consensus constants:

- **`BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW`** (a.k.a. Median Time Past,
  MTP). Cryptonote default: 11 (i.e., the new block's timestamp must
  be greater than the median of the previous 11). zawy12 LWMA-1
  required: **11**. Shekyl: keep at 11.
- **`BLOCK_FUTURE_TIME_LIMIT`** (FTL). Cryptonote default: 7200 s
  (= 2 hours). zawy12 LWMA-1 required: **`N * T / 20`**. For N = 90,
  T = 120: **540 s = 9 minutes**. The CryptoNote default (2 hours)
  is too high for small chains and enables sustained timestamp
  manipulation against LWMA's `6*T` clamp; the canonical reference
  documents this explicitly and the recommended FTL is a hard
  requirement, not a tunable.

This means the deletion surface includes more than `difficulty.cpp`:
the FTL constant and the MTP constant are part of the LWMA-1
landing. The version-1 inherited values are wrong-by-construction
once LWMA-1 is in place.

Phase 4 of [`DAA_LWMA1_PLAN.md`](./DAA_LWMA1_PLAN.md) covers all
three together.

### 6. No genesis difficulty "guess" — start at a single ratified constant

The canonical LWMA-1 reference includes a `difficulty_guess`
parameter that hard-codes difficulty for the first `N+1` blocks
after fork or genesis (line 107 of the canonical implementation:
`if (height >= FORK_HEIGHT && height < FORK_HEIGHT + N) { return
difficulty_guess; }`). Shekyl adopts this pattern verbatim with one
constraint: **a single ratified constant**, not a runtime parameter.

The constant is named `GENESIS_DIFFICULTY` and is typed as a `u64`
const in `shekyl-difficulty/src/lib.rs`. Its candidate value is
**100** (one hundred) — the canonical zawy12 example value — with
the rationale that:

- Genesis difficulty must be low enough that a single CPU on the
  network can produce blocks at roughly the target rate.
- It must be high enough that the first non-genesis block's hash
  meets a non-trivial difficulty target (preventing block-zero
  exploitation).
- Per the canonical zawy12 example for new chains, 100 is the
  appropriate order of magnitude for a CPU-mineable launch.

The value is **proposed**, not final — Phase 0 review ratifies
either 100 or a Shekyl-specific value derived from RandomX v2 single-
CPU hashrate measurements at the v2 fork pin.

## 3. Spec source pin and reference clone

- **Spec source:** [`zawy12/difficulty-algorithms#3`](https://github.com/zawy12/difficulty-algorithms/issues/3)
  ("LWMA difficulty algorithm").
- **Pinned issue revision:** the issue's body HEAD as of Phase 0
  close. Because GitHub issues do not carry SHA addressing, the
  pinned content is captured by hash of the rendered Markdown saved
  at `docs/design/refs/zawy12_issue_3_lwma1.md` at PR-A merge time.
  This anchors the audit trail against future edits to the issue.
- **Reference implementation:** the `LWMA1_()` C++ function defined
  inside zawy12 Issue #3 (lines 76–136 of the issue body at the
  pinned revision). Used as a cross-check only; the Rust
  implementation is written from the textual spec.
- **Simulation tooling:** zawy12's `difficulty-algorithms` repository
  contains historical-data simulators used to derive test-vector
  corpora. Specific corpus selection is described in §8.

## 4. The LWMA-1 algorithm — Shekyl parameter selection

| Parameter | Symbol | Shekyl V3.0 value | Source / rationale |
| --- | --- | --- | --- |
| Window size | `N` | **90** | zawy12 canonical recommendation for `T = 120 s` chains (Issue #3, line 84) |
| Target block time | `T` | **120 s** | Inherited from CryptoNote `DIFFICULTY_TARGET_V2`; unchanged. Orthogonal to DAA choice. |
| Solvetime clamp factor | k_st | **6** (i.e., individual solvetimes capped at `6*T`) | zawy12 canonical |
| Minimum-L floor coefficient | k_L | **1/20** (i.e., `L_min = N*N*T/20`) | zawy12 canonical |
| Bias factor numerator | b_num | **99** | zawy12 canonical (fixes 2026-era LWMA-1 alignment bug per the bams-repo/go-chain audit) |
| Bias factor denominator | b_den | **200** | zawy12 canonical |
| Genesis difficulty | `D₀` | **100** (proposed) | §2.6 — Phase 0 ratifies |
| Block future time limit | FTL | **`N * T / 20` = 540 s** | zawy12 canonical hard requirement (Issue #3 lines 85, 91) |
| Median time past window | MTP | **11** | zawy12 canonical; Cryptonote default unchanged |

All values become typed `const` in `shekyl-difficulty/src/consts.rs`
per `RANDOMX_V2_RUST.md` §9's "typed const, not env var" disposition.
No env-var overrides; consensus constants are not runtime-tunable.

Per `75-system-autonomy.mdc`, every tunable has a documented rationale
for its default and bounds for safe adjustment. The "safe adjustment
bounds" for these values are: **none post-genesis without a hard
fork.** Any value change is a consensus rule change requiring the
full hard-fork process per `00-mission.mdc`'s system-outlast-the-team
commitment. The values above are the values Shekyl ships at genesis
and the values that anchor reproducible-build verification.

## 5. The LWMA-1 algorithm — formal specification

### 5.1 Inputs

The DAA's input domain is two parallel vectors of length `N + 1`:

- `timestamps: [u64; N+1]` — raw block timestamps (seconds since
  Unix epoch), in chain order, with `timestamps[N]` being the most
  recent block.
- `cumulative_difficulties: [u128; N+1]` — cumulative difficulty up
  to and including each timestamp's block.

Plus three protocol constants: `T = 120`, `N = 90`,
`GENESIS_DIFFICULTY = 100`.

### 5.2 Output

`next_difficulty: u128` — the difficulty that the next block must
satisfy.

### 5.3 Algorithm (textual specification)

The algorithm is the canonical zawy12 LWMA-1, expressed in plain
language for spec-first review (per `05-system-thinking.mdc`'s
specification-first rule). Step-by-step:

**Step 1 — Genesis-window short-circuit.** If `chain_height < N`,
return `GENESIS_DIFFICULTY` directly. The chain has not yet
accumulated `N + 1` blocks to weight against.

**Step 2 — Out-of-sequence timestamp normalization.** Compute
solvetimes from raw timestamps via a forward pass that converts any
out-of-sequence (decreasing or equal) timestamp pair into a positive
solvetime of 1 second. Sustained adversarial out-of-sequence
timestamps are bounded by the MTP check (§5.5), which rejects new
blocks whose timestamp is below the median of the previous 11. The
forward pass is:

```text
prev = timestamps[0] - T
for i in 1..=N:
    if timestamps[i] > prev:
        solvetime[i] = timestamps[i] - prev
    else:
        solvetime[i] = 1
        timestamps[i] = prev + 1   // implicit: prev gets bumped
    prev = max(timestamps[i], prev + 1)
```

**Step 3 — Solvetime clamp.** Each solvetime is clamped to
`min(6*T, solvetime)`. Solvetimes above `6*T = 720 s` are treated as
if they were exactly `6*T`. This is the canonical defense against
timestamp manipulation that tries to drive difficulty down via one
large lying timestamp.

**Step 4 — Linear-weighted sum.** Compute the weighted-sum L as
`L = sum over i in 1..=N of (i * clamped_solvetime[i])`. The weight
`i` grows linearly with recency. The block at position `i = N`
(most recent) contributes weight `N`; the block at `i = 1` (oldest
in the window) contributes weight 1.

**Step 5 — Minimum-L floor.** If `L < N*N*T/20`, set
`L = N*N*T/20`. This prevents extreme upward difficulty swings on a
run of unusually fast blocks.

**Step 6 — Average difficulty over the window.** Compute
`avg_D = (cumulative_difficulties[N] - cumulative_difficulties[0]) / N`.

**Step 7 — Apply formula with bias factor.** Compute
`next_D = (avg_D * N * (N+1) * T * 99) / (200 * L)`. The `99/200`
factor is a bias correction (effective `0.495`) that compensates
for the asymmetric weighting of recent versus old blocks in the L
sum. The 2026 bams-repo/go-chain audit corrected this from a
`200/99` direction error in older LWMA implementations.

**Step 8 — Overflow guard.** If `avg_D > 2_000_000 * N * N * T`,
re-associate the multiplication to avoid `u128` overflow:
`next_D = (avg_D / (200 * L)) * (N * (N+1) * T * 99)`. The
re-association rounds slightly differently but stays within one
unit of the unguarded computation.

### 5.4 Properties

- **Determinism.** Given identical inputs, the algorithm returns
  identical outputs. No floating point. No clock reads. No system
  state. The Rust implementation is `#![deny(unsafe_code)]` and
  contains no `unsafe` blocks.
- **Constant-time-on-secrets posture.** The algorithm operates
  exclusively on public consensus inputs. No constant-time
  requirement applies — the inputs are not secret material. This
  satisfies `30-cryptography.mdc`'s constant-time-or-explicit-
  rejection rule by being a non-secret-handling surface where the
  rule does not engage.
- **Overflow safety.** All intermediate arithmetic uses `u128`. The
  overflow guard in §5.3 step 8 covers the only computation that
  can plausibly overflow `u128` under canonical parameter values;
  every other intermediate is bounded by `N * (N+1) * T * 6` (the
  maximum possible weighted-sum given the clamp) times the maximum
  `u64` difficulty, which fits in `u128` by construction.

### 5.5 Coupled timestamp validation

LWMA-1's properties depend on incoming-timestamp validation that is
*not* part of the DAA itself but lives in the block-header validator:

- **MTP rejection.** A new block's timestamp must be strictly
  greater than the median of the previous `MTP = 11` timestamps.
  Already implemented in the inherited block-header validator;
  preserved unchanged.
- **FTL rejection.** A new block's timestamp must be at most
  `FTL = N * T / 20 = 540 s` ahead of the validator's local clock.
  The inherited FTL of 7200 s is replaced with this value at
  genesis (Phase 4 of [`DAA_LWMA1_PLAN.md`](./DAA_LWMA1_PLAN.md)).

If either check is bypassed (consensus bug, validator
mis-implementation), LWMA-1's solvetime-clamp defense is materially
weakened. The two checks plus the `6*T` solvetime clamp together
constitute the timestamp-attack defense surface; none of the three
is replaceable.

## 6. FFI surface

Per `40-ffi-discipline.mdc`, all exports return `i32` error codes;
output values reach the caller through out-parameters.

### 6.1 The one committed export

```c
// Compute next difficulty per LWMA-1.
//
// Inputs:
//   timestamps          - pointer to N+1 u64 timestamps in chain order,
//                         oldest first
//   cum_difficulties    - pointer to N+1 u128 cumulative-difficulty
//                         values matching timestamps in order
//   count               - number of entries in each array; must equal
//                         N+1 == 91 once chain has matured
//   chain_height        - current chain height (used for genesis
//                         short-circuit per §5.3 step 1)
//   out_next_difficulty - pointer to u128 receiving the next-difficulty
//                         output on success
//
// Returns:
//   0  - OK; out_next_difficulty written
//  -1  - ERR_NULL_PTR
//  -2  - ERR_INVALID_COUNT (count != N+1 once chain_height >= N)
//  -3  - ERR_OVERFLOW (consensus invariant violation; out_next_difficulty
//                      not written; caller must treat as protocol error)
//  -4  - ERR_INTERNAL (caught panic at FFI boundary; out_next_difficulty
//                      not written)
int32_t shekyl_difficulty_lwma1_next(
    const uint64_t *timestamps,
    const __uint128_t *cum_difficulties,
    size_t count,
    uint64_t chain_height,
    __uint128_t *out_next_difficulty);
```

### 6.2 Discretionary additions (deferred to V3.x unless Phase 4 finds need)

None at Phase 0. The DAA surface is structurally a single function;
exposing the `GENESIS_DIFFICULTY` constant, the parameter values, or
intermediate computation steps as separate exports adds attack
surface without delivering caller value. The C++ side imports the
single function above and consumes the canonical constants via
header re-declarations from `shekyl-difficulty/src/consts.rs`
(generated via `cbindgen` per `25-rust-architecture.mdc`).

### 6.3 Explicitly NOT exported

- `LWMA1_()` reference C++ function. The canonical reference lives
  in the spec issue, not in the codebase. Including it would
  duplicate audit surface and create a second-source-of-truth
  problem (which one wins on disagreement?).
- Per-step pseudocode helpers. The algorithm is one function at the
  spec level; the FFI mirrors that.
- Difficulty conversion / packing helpers. Difficulty is already
  `u128` end-to-end at the FFI boundary; the inherited
  `boost::multiprecision::uint128_t` C++ type is a `__uint128_t`-
  compatible at the FFI ABI per the existing `crypto::hash` packing
  precedent.

## 7. Isolation invariants

Mirroring `RANDOMX_V2_RUST.md` §7's two-invariant pattern:

### 7.1 No legacy-DAA symbols in the daemon

CI runs `nm shekyld | rg -q '^.* (T|U) (next_difficulty_64|next_difficulty|check_difficulty_checkpoints)\b'`
and **fails on match**. These are the symbols defined in inherited
`difficulty.cpp` / declared in `difficulty.h`. Phase 4 deletes those
files; this invariant is the structural backstop against accidental
restoration via inherited-code search-and-paste.

### 7.2 `shekyl-difficulty` has no C ABI

All C-ABI exports live in `shekyl-ffi` with the
`shekyl_difficulty_*` prefix. The verifier crate itself contains no
`#[no_mangle]`, no `extern "C" fn`, and no `#[export_name = "..."]`
/ `#[unsafe(export_name = "...")]` — exactly the same three-pattern
CI grep as `RANDOMX_V2_RUST.md` §7.2:

- `#\[(?:unsafe\(\s*)?no_mangle(?:\s*\))?\]`
- `\bextern\s+"C"\s+fn\b`
- `#\[(?:unsafe\(\s*)?export_name\b`

Any hit fails CI. Foreign imports (`extern "C" { ... }` blocks) are
not forbidden but the pure-Rust `shekyl-difficulty` crate has no
need for them.

The two invariants land in the same `.github/workflows/` file as
the RandomX v2 invariants (Phase 2f of `RANDOMX_V2_PLAN.md`),
sharing the grep-scaffolding and failure-mode plumbing.

## 8. Test-vector strategy

Three test-vector tiers, each gating a specific PR:

### 8.1 Unit tests (PR B gate)

Author-derived synthetic vectors covering the algorithm's structural
properties:

- Genesis short-circuit (chain_height < N returns
  `GENESIS_DIFFICULTY` verbatim).
- Perfectly stable hashrate (`solvetime[i] = T` for all i)
  produces `next_D == avg_D` (within rounding).
- Sudden 2× hashrate increase (`solvetime[i] = T/2` for all i)
  produces `next_D ≈ 2 * avg_D`.
- Sudden 2× hashrate decrease (`solvetime[i] = 2*T`) produces
  `next_D ≈ avg_D / 2`.
- Solvetime clamp engagement (single `solvetime[N] = 100*T`)
  produces output bounded by the `6*T`-clamped contribution.
- Minimum-L floor engagement (all very fast solvetimes) produces
  output bounded by the floor.
- Out-of-sequence timestamp normalization (`timestamps[i+1] <
  timestamps[i]`) produces a valid `next_D` rather than panicking
  or returning zero.
- Bias factor direction (the `99/200` correction biases output
  toward stability, not toward variance).
- Per-canonical-reference 2026 bug avoidance: no per-block output
  clamp engaged anywhere; the bams-repo/go-chain audit findings
  cited at §2.4 do not regress.

All vectors derived analytically against the §5.3 specification.

### 8.2 Canonical-reference cross-check (PR B gate)

Generated by running the zawy12 reference `LWMA1_()` C++ function
on each of the §8.1 input cases and asserting byte-identical
output. The C++ reference is built from the issue-body source
saved at `docs/design/refs/zawy12_issue_3_lwma1.md` (per §3); a
small `tests/lwma1_cross_check.cpp` harness lives in
`tests/difficulty/` and CI runs it as part of the workspace's C++
test build.

The cross-check is **gating for PR B** (the crate scaffold + tests
PR). If the Rust output diverges from the C++ reference on any
§8.1 vector, the Rust implementation is wrong; the spec wins by
construction, but the cross-check catches the case where the
Rust implementation reads the spec differently from the C++
reference.

### 8.3 Simulated-history corpus (release-gate test, not per-PR)

Sourced from zawy12's simulator output on a representative
historical-hashrate trace. The exact trace is selected during PR B
review from the simulator's bundled inputs (Masari historical data,
Bittube historical data, and the synthetic
hashrate-attack-scenario inputs the canonical repository ships).
A 50,000-block-or-larger corpus.

Per-PR CI runs a fast subset (~1,000 blocks); release-gate suite
runs the full corpus. Same per-PR / release-gate split as the
RandomX v2 plan's "synthetic benchmark in CI, full sync test at
release time" split (`RANDOMX_V2_PLAN.md` Phase 2e).

## 9. C++ deletion surface

Concrete files and constants to remove at Phase 4 of
[`DAA_LWMA1_PLAN.md`](./DAA_LWMA1_PLAN.md):

### 9.1 Files deleted in full

- [`src/cryptonote_basic/difficulty.cpp`](../../src/cryptonote_basic/difficulty.cpp)
  (the inherited DAA implementation, including the `next_difficulty`,
  `next_difficulty_64`, `check_hash`, `check_hash_64`, `check_hash_128`,
  and `hex(difficulty_type)` functions).
- [`src/cryptonote_basic/difficulty.h`](../../src/cryptonote_basic/difficulty.h)
  (the public header for the above).
- [`tests/difficulty/difficulty.cpp`](../../tests/difficulty/difficulty.cpp)
  and [`tests/difficulty/`](../../tests/difficulty/) test harness
  data files — replaced by `shekyl-difficulty/tests/` and the
  cross-check harness in §8.2.
- [`tests/difficulty/gen_wide_data.py`](../../tests/difficulty/gen_wide_data.py)
  and `tests/difficulty/generate-data` (test-vector generation for
  the inherited algorithm).

### 9.2 Constants deleted from `src/cryptonote_config.h`

- `DIFFICULTY_TARGET_V1` (line 83) — pre-genesis variant, dead under
  `60-no-monero-legacy.mdc`.
- `DIFFICULTY_WINDOW` (line 84) — replaced by `N` const in
  `shekyl-difficulty`.
- `DIFFICULTY_LAG` (line 85, the `// !!!` constant) — not used by
  LWMA-1; deleted.
- `DIFFICULTY_CUT` (line 86) — not used by LWMA-1; deleted.
- `DIFFICULTY_BLOCKS_COUNT` (line 87) — `N+1` known from `N`;
  deleted.
- `DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN` (line 95) — test-alias for
  the inherited algorithm; deleted.

`DIFFICULTY_TARGET_V2` (line 82, value 120) is retained but renamed
to `BLOCK_TARGET_SECONDS` and moved to the typed-const home in
`shekyl-difficulty` per `RANDOMX_V2_RUST.md` §9 framing.

### 9.3 FTL and MTP constants

- `BLOCK_FUTURE_TIME_LIMIT` and `BLOCK_FUTURE_TIME_LIMIT_V2` (in
  `cryptonote_config.h`): replaced with `N * T / 20 = 540 s` and
  moved to the typed-const home.
- `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW` (MTP): kept at 11; moved to
  the typed-const home alongside the other consensus constants.

### 9.4 Call-site rewiring in `src/cryptonote_core/blockchain.cpp`

Three call sites currently consume the inherited `next_difficulty`:

- Line ~965: `Blockchain::get_difficulty_for_next_block()` —
  rewires to `shekyl_difficulty_lwma1_next`.
- Line ~1021: `Blockchain::check_difficulty_checkpoints()` —
  rewires to the same; the recalculation loop's "use historical
  difficulty target" framing collapses because LWMA-1 has only one
  parameter set, not a v1/v2 split.
- Line ~1325: `Blockchain::get_next_difficulty_for_alternative_chain()`
  — rewires to the same.

The four other `next_difficulty` consumers per the §1.1 reconnaissance
grep are:

- `src/cryptonote_basic/miner.cpp` (mining-side; consumes via the
  same blockchain interface).
- `src/cryptonote_basic/difficulty.{h,cpp}` (the implementation
  itself; deleted).
- `src/wallet/wallet_rpc_payments.cpp` (deleted in full per
  `RANDOMX_V2_RUST.md` §15).
- `src/rpc/core_rpc_server.cpp` (consumes via blockchain interface).

Net: three blockchain call sites + the miner indirect + the
core_rpc_server indirect, all rewired via a single FFI export.

## 10. Reversion clause

Per `21-reversion-clause-discipline.mdc`, this disposition's
reversion criteria are recorded explicitly. Two conditions, either
sufficient to reopen:

1. **A Shekyl-specific simulation against the zawy12 canonical
   tooling demonstrates LWMA-2 or LWMA-4 has materially better
   behavior** under Shekyl's specific hashrate profile (CPU-only
   RandomX v2; small-chain bootstrap regime). "Materially better"
   means: variance reduction ≥ 20 % on the §8.3 corpus, or
   timestamp-attack resistance against a specific named attack
   model that LWMA-1 fails. Pre-genesis: re-evaluate in a new
   design doc. Post-genesis: V3.x hard-fork-gated.
2. **ASERT's smoother behavior delivers materially better long-
   term-stability properties** AND the privacy-jitter side-benefit
   from LWMA-1 is no longer load-bearing (audit confirms the
   small-chain broadcast-time-correlation surface has closed,
   typically after several years of stable mature-hashrate
   operation). Post-genesis V3.x or later disposition.

The reversion criteria are named at write time per
`21-reversion-clause-discipline.mdc`; future re-evaluation requires
no re-derivation of the rationale.

## 11. Wallet, RPC, and node touchpoints

LWMA-1 is consumed by the daemon's block validator and miner. It is
**not** consumed by the wallet — wallets do not compute or check
difficulty (validators do). The wallet-V3.2 cutover gate that
applies to RandomX v2 (`RANDOMX_V2_RUST.md` §14) does **not** apply
to LWMA-1. LWMA-1 can land before, during, or after the wallet V3.2
migration without coupling.

The `core_rpc_server` exposes difficulty values via JSON-RPC
(`get_info`, `get_block_header_by_*`); those are read-only
consumers of the value `Blockchain::get_difficulty_for_next_block()`
returns. No RPC interface change is needed — the value's type
(`difficulty_type`, a 128-bit unsigned integer) is unchanged across
the migration.

## 12. Reviewer discipline

Per the pattern established in `RANDOMX_V2_RUST.md` §23, the
"reviewer discipline" framing applies asymmetrically here:

- **Phase 0 (this PR).** Design doc + plan. Solo-architect review
  under the aspirational `24-reviewer-discipline.mdc` rule (which
  this PR's FOLLOWUPS entry still tracks as planned). The DAA is a
  consensus-critical surface but operates on public consensus
  inputs only; reviewer attention concentrates on §4 parameter
  selection, §5 algorithm correctness against canonical reference,
  and §10 reversion criteria.
- **PR B (implementation).** External reviewer not required; the
  zawy12 canonical reference is the audit-of-record. Self-review
  is the rule, with `24-reviewer-discipline.mdc` as the
  aspirational target.
- **PR C / D (FFI + C++ cutover).** Self-review; the changes are
  mechanical against the design doc and the FFI signature in §6.
- **Release-time gate.** No external algorithm-review gate analogous
  to RandomX v2's release-time Monero-audit dependency. LWMA-1 is
  community-vetted at zawy12's repository; Shekyl's pinned spec
  revision (§3) is the audit-of-record.

## 13. Explicit non-goals

Per `60-no-monero-legacy.mdc`:

- No CryptoNote DAA compatibility, no version-dispatch in the DAA
  surface, no `HF_VERSION_LWMA1` gate, no fallback to inherited
  algorithm.
- No env-var overrides of `N`, `T`, `GENESIS_DIFFICULTY`, FTL, or
  MTP. Consensus constants are typed `const`.
- No multi-window or jump-rule logic from LWMA-2/3/4.
- No per-block output clamp ("max 3× change per block"). The
  canonical solvetime-clamp + minimum-L floor are the variance
  controls.

## 14. License and attribution

- The Rust implementation in `rust/shekyl-difficulty/` is Shekyl
  Foundation copyright per `92-copyright-header.mdc`, licensed
  BSD-3-Clause.
- The zawy12 canonical reference is MIT-licensed per the
  `// Copyright (c) 2017-2018 Zawy, MIT License` header in
  Issue #3's `LWMA1_()` C++ reference. The Shekyl Rust port is
  written from the spec, not derived from the C++ source; MIT
  attribution is not required for the Rust file, but the design
  doc cites the spec source explicitly.

## 15. MSRV

`shekyl-difficulty` inherits the workspace MSRV from
`rust/Cargo.toml` (currently the same as `shekyl-crypto-pq` per
the cross-crate consistency rule in `25-rust-architecture.mdc`).
The crate uses no nightly features, no `unsafe`, and no
crate-level `#![allow(...)]`.

## 16. Guix reproducible-build impact

`shekyl-difficulty` is a pure-Rust crate with no FFI down into
C/C++ libraries and no platform-specific code. It builds reproducibly
under the existing Guix manifest with no additional dependencies.
No `manifests/manifest.scm` changes required.

The C++ deletion surface (§9) removes ~250 lines of
`boost::multiprecision`-coupled code from the daemon build path.
Boost remains in the build via other consumers; no Boost
disposition follows from this PR.

## Cross-references

- [`DAA_LWMA1_PLAN.md`](./DAA_LWMA1_PLAN.md) — phased plan.
- [`RANDOMX_V2_RUST.md`](./RANDOMX_V2_RUST.md) — sibling PoW
  migration; orthogonal at the math level, similar architectural
  shape. §3 spec-as-source-of-truth, §7 isolation invariants, §9
  consensus-constant typing, §13 explicit non-goals, §23 reviewer
  discipline are the patterns this doc mirrors.
- [`zawy12/difficulty-algorithms#3`](https://github.com/zawy12/difficulty-algorithms/issues/3)
  — canonical LWMA-1 specification and reference.
- `.cursor/rules/00-mission.mdc`, `16-architectural-inheritance.mdc`,
  `20-rust-vs-cpp-policy.mdc`, `21-reversion-clause-discipline.mdc`,
  `40-ffi-discipline.mdc`, `60-no-monero-legacy.mdc`,
  `75-system-autonomy.mdc`.
