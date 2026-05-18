# LWMA-1 — Difficulty adjustment, Rust, from genesis

**Status.** **DRAFT — Round 8 (2026-05-17 initial draft; review
passes 1–8 have all landed against PR #49; this doc carries
the Round 4 test-vector concrete-tuple correction, the Round 5
`ShekylU128` FFI pivot, the Round 7 cleanup of the
consensus-atomic-cutover invocation against the now-ratified
`07-consensus-atomic-cutovers.mdc`, and the Round 8 bias-factor
stochastic-vs-deterministic clarification and §11 wallet-T
touchpoint correction).** Phase 0 deliverable for the Shekyl
difficulty-adjustment algorithm (DAA) migration. Companion:
[`DAA_LWMA1_PLAN.md`](./DAA_LWMA1_PLAN.md). Both documents must
pass the Phase 0 review cycle before any code lands.

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

### 2.1 Rust implementation, from genesis; leaf crate

Per `20-rust-vs-cpp-policy.mdc` rule 2 (Rust if any of: defines a
cryptographic contract that other code consumes), the DAA is a
cryptographic-contract surface — the validator and the miner all
consume the same `next_difficulty(timestamps[],
cumulative_difficulties[], chain_height) -> next_difficulty`
contract. Rust enforces the contract at the type system; C++
enforces it in documentation. The type-system enforcement is the
correct disposition.

The Rust crate is **`shekyl-difficulty`**, a new workspace member
under `rust/`. It is a **leaf crate**: it has zero internal
workspace dependencies; only `shekyl-ffi` depends on it (to export
the C ABI per §6). It is a sibling, at the leaf level, of the
existing computation-primitive crates `shekyl-consensus` (where
RandomX-related Rust code lives today) and `shekyl-fcmp` (FCMP++
proofs). It is **not** a child of either — DAA, PoW, and proof
verification are math-orthogonal surfaces, and the crate-level
separation reflects that. The planned `shekyl-pow-randomx`
verifier crate (per `RANDOMX_V2_RUST.md`) will also be a leaf
crate; the two will be siblings at the workspace level when both
land.

The dependency direction is unidirectional and worth stating
explicitly because it matters for `25-rust-architecture.mdc`'s
layering discipline:

```text
C++ Blockchain  ──(FFI)──>  shekyl-ffi  ──(rust dep)──>  shekyl-difficulty
                                                              │
                                                              └─> (no internal deps)
```

`shekyl-difficulty` does not depend on `shekyl-ffi`,
`shekyl-engine-state`, `shekyl-consensus`, or any other workspace
crate. It uses only `core`/`std` and (optionally) workspace-shared
utility crates like `thiserror` (see
[`DAA_LWMA1_PLAN.md`](./DAA_LWMA1_PLAN.md) "Phase 1 — `shekyl-difficulty`
crate scaffold").

### 2.2 Single algorithm path, no version dispatch

Genesis ships with LWMA-1 and nothing else. There is no
`HF_VERSION_LWMA1` gate, no fallback to inherited Monero DAA, no
"v1 difficulty" path. Per `60-no-monero-legacy.mdc`, code that
checks `if (hf_version < HF_VERSION_LWMA1)` is dead code at genesis
and gets deleted, not gated.

This is the same disposition as the RandomX v2 plan's "no
`RX_BLOCK_VERSION` gate, no version-dispatch switch" framing
(`RANDOMX_V2_RUST.md` §13).

### 2.3 Spec is the source of truth, the reference implementation is the cross-check

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

### 2.4 The pre-design sketch is not the canonical implementation

A pre-design Rust sketch existed at
`rust/shekyl-difficulty/src/lwma1.rs` during early Phase 0
reconnaissance. Per `15-deletion-and-debt.mdc`'s default-delete rule
(code with no live caller is audit surface, attack surface, and
review fatigue) the sketch was deleted in this PR's commit
`91c6dc44c` before any implementation work began, so that Phase 1
starts from an empty crate directory and is written fresh against
this design doc's §5.3 algorithm specification. The deletion
commit's authoritative record is in `git log`; the design doc cites
the commit hash and the binding rule, not a literal calendar date.

The divergences below are recorded as the design rationale for why
the sketch did not become the implementation — they are an explicit
anti-pattern catalogue, not a description of any committed code.
Concrete divergences from zawy12 canonical LWMA-1:

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

**Disposition.** Per `15-deletion-and-debt.mdc` (default-delete),
the sketch was **deleted** during Phase 0 (this PR, commit
`91c6dc44c`) so that no on-disk pre-design code can accidentally
become the starting point for the implementation crate (Phase 1 in
[`DAA_LWMA1_PLAN.md`](./DAA_LWMA1_PLAN.md)). Phase 1 writes the
implementation fresh against this design doc's §5.3 algorithm
specification and §8 test-vector strategy. The divergence catalogue
above is preserved here as the design record of why each non-canonical
shape is rejected; it is not a description of any committed source.

### 2.5 FTL and MTP are co-tuned with N

The canonical LWMA-1 specification explicitly couples the DAA window
size N to two related consensus constants:

- **`BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW`** (a.k.a. Median Time Past,
  MTP). **Current Shekyl-inherited value: 60** (per
  `src/cryptonote_config.h:56`, a Monero-era widening from the
  CryptoNote-original 11). zawy12 LWMA-1 required: **11**. Shekyl:
  **tighten to 11**. The Monero-era 60-block widening was a
  response to long-tail timestamp-attack scenarios that don't apply
  to LWMA-1's own timestamp discipline (`6*T` solvetime clamp +
  9-minute FTL together close the attack surface that motivated
  Monero's MTP widening), and zawy12 explicitly recommends 11 for
  LWMA-1 chains.
- **`CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT`** (FTL). Current
  Shekyl-inherited value: **7200 s = 2 hours** (per
  `src/cryptonote_config.h:51`). zawy12 LWMA-1 required:
  **`N * T / 20`**. For N = 90, T = 120: **540 s = 9 minutes**. The
  CryptoNote default (2 hours) is too high for small chains and
  enables sustained timestamp manipulation against LWMA's `6*T`
  clamp; the canonical reference documents this explicitly and the
  recommended FTL is a hard requirement, not a tunable.

This means the deletion surface includes more than `difficulty.cpp`:
the FTL constant and the MTP constant are part of the LWMA-1
landing, and both are **value changes**, not preservation. The
version-1 inherited values are wrong-by-construction once LWMA-1
is in place.

**Both predicates and both constants live in `shekyl-difficulty`.**
The crate exports, in addition to `lwma1_next`:

- `pub fn is_timestamp_below_ftl(incoming: u64, local_clock: u64)
   -> bool` — returns true when `incoming - local_clock <=
   FTL_SECONDS`, with saturating subtraction; consensus-rejection
   logic is the consumer's job, this predicate just answers the
   question.
- `pub fn is_above_mtp(incoming: u64, previous_11: &[u64; 11])
   -> bool` — returns true when `incoming` is strictly greater than
   the median of `previous_11`.

These are predicates rather than value-producing transforms, but
per `18-type-placement.mdc` predicates are just transforms whose
codomain is `bool` — same shape, same crate.

**Phase 1 implementation choice (not a Phase 0 blocker).** The
const-sized array reference `&[u64; 11]` is consensus-correct
(the MTP window size is fixed at 11 per §4) but ergonomically
costly: every C++ caller assembles a `std::vector<uint64_t>` and
needs an explicit conversion at the call site. Two equivalent
alternatives are available to Phase 1 review:

- `pub fn is_above_mtp(incoming: u64, previous: &[u64]) -> bool`
  with a runtime `debug_assert!(previous.len() == MTP_WINDOW as
  usize);` — slice ergonomics, lossless on debug, no protection
  in release.
- `pub fn is_above_mtp(incoming: u64, window: MtpWindow) -> bool`
  with a `pub struct MtpWindow([u64; 11])` newtype carrying the
  invariant — strongest type guarantee, requires a constructor.

The `&[u64; 11]` shape in this design doc is the
consensus-property-preserving baseline; Phase 1 may adopt either
alternative provided the consensus property (exactly 11 timestamps
or refuse the predicate) is preserved at the public boundary.

The disposition to co-locate FTL/MTP with the DAA (rather than
pre-extracting them into a separate `shekyl-timestamp-validation`
crate) follows `70-modular-consensus.mdc`'s rule against
speculative scaffolding: there is no second consumer of these
predicates today, and extracting before a second consumer exists
produces an empty abstraction that future maintainers cannot
attribute to a concrete need. If a non-DAA consumer of FTL/MTP
later emerges, the predicates extract then — the cost of moving
two functions is much smaller than the cost of carrying a
speculative crate.

Phase 4 of [`DAA_LWMA1_PLAN.md`](./DAA_LWMA1_PLAN.md) covers all
three together (DAA function, FTL predicate, MTP predicate).

### 2.6 No genesis difficulty "guess" — start at a single ratified constant

The canonical LWMA-1 reference includes a `difficulty_guess`
parameter that hard-codes difficulty for the first `N` blocks
after fork or genesis (line 107 of the canonical implementation:
`if (height >= FORK_HEIGHT && height < FORK_HEIGHT + N) { return
difficulty_guess; }` — canonical's `height` is the block being
validated, so `height < N` means blocks at heights `0..N-1`).
Shekyl adopts this pattern verbatim with one constraint:
**a single ratified constant**, not a runtime parameter. The
consumer-side mapping from canonical's framing
(`height < N` → `difficulty_guess`) to Shekyl's FFI framing
(`chain_height < N` → `GENESIS_DIFFICULTY`) is spelled out
explicitly in §5.6.

The constant is named `GENESIS_DIFFICULTY` and is typed as a `u128`
const in `shekyl-difficulty/src/consts.rs` (matching the difficulty-
type discipline in §11; the value is small but the type lines up
with `next_difficulty`'s codomain so no widening conversion appears
at the consumer call site). Its value is **100** (one hundred) —
the canonical zawy12 example value, ratified in Round 4 — with the
rationale that:

- Genesis difficulty must be low enough that a single CPU on the
  network can produce blocks at roughly the target rate.
- It must be high enough that the first non-genesis block's hash
  meets a non-trivial difficulty target (preventing block-zero
  exploitation).
- Per the canonical zawy12 example for new chains, 100 is the
  appropriate order of magnitude for a CPU-mineable launch.

The value is **ratified** per `DAA_LWMA1_PLAN.md` "Phase 0
dispositions." The alternative considered in Round 3 — a
Shekyl-specific value derived from RandomX v2 single-CPU hashrate
measurements at the v2 fork pin — referenced a measurement that
does not exist and cannot exist until RandomX v2 is implemented
and a CPU-only hashrate sample is collected. Ratifying-pending-
measurement is functionally identical to "100 with a documented
reversion trigger," which §10's reversion clause already provides.
First-week-of-testnet recalibration, if observed hashrate
differs materially from canonical assumptions, lands as a sibling
PR with its own design-doc justification, not as a Phase 0
unknown.

### 2.7 The DAA is a primitive, not an actor

Per `18-type-placement.mdc`'s transform-vs-state dichotomy, the
LWMA-1 DAA is **transform-shaped**: the value `next_difficulty` is
defined by the function `lwma1_next(timestamps,
cumulative_difficulties, chain_height) -> u128`, not by any
actor's allocation policy or progression record. Anyone with the
function's inputs can recompute the value; the inputs are public,
consensus-deterministic, and on-chain.

The lens applied to the question "where does this live?" returns:

> Transform-shaped types live in the crate of their defining
> function. (`18-type-placement.mdc` §"Where each shape lives".)

— so `lwma1_next` lives in `shekyl-difficulty`, and `Difficulty`
itself is just `u128` (no newtype required; the inherited
`difficulty_type` is already a 128-bit unsigned integer per the
existing C++ codebase per §11).

**No `DifficultyEngine` actor wrapper.** Wrapping `lwma1_next` in a
`DifficultyEngine` actor would be the architectural-inheritance
anti-pattern flagged by `16-architectural-inheritance.mdc`:
Monero's `cryptonote::Blockchain` is stateful (owns the chain DB,
the difficulty cache, the difficulty lock) and the DAA is a method
on it; carrying that C++ ergonomic shape into Rust would invert
the transform-vs-state dichotomy without delivering any property
the threat model needs. `shekyl-difficulty` exports a **free
function** plus the typed consensus constants (§4) and the FTL/MTP
predicates (§2.5 and §5.5) — nothing more.

The shape the actor paradigm calls for at the next level up — a
stateless block-validator actor that assembles inputs from a
chain-state owner and calls `lwma1_next` — is the **consumer**'s
responsibility, not the DAA crate's. The consumer disposition is
recorded in §17 (chain-state ownership).

This is the same shape the planned `shekyl-pow-randomx` crate is
specified to have per `RANDOMX_V2_RUST.md` §6: pure-derivation
verifier primitive, no module-level mutable state, no actor
wrapper inside the verifier crate.

## 3. Spec source pin and reference clone

- **Spec source:** [`zawy12/difficulty-algorithms#3`](https://github.com/zawy12/difficulty-algorithms/issues/3)
  ("LWMA difficulty algorithm").
- **Pinned issue revision:** captured by fetching the **raw issue
  body** via the GitHub REST API at Phase 2 PR time:

  ```text
  curl -sH "Accept: application/vnd.github.v3+json" \
    https://api.github.com/repos/zawy12/difficulty-algorithms/issues/3 \
    | jq -r .body > docs/design/refs/zawy12_issue_3_lwma1.md
  ```

  The `.body` field is the issue's canonical Markdown source as
  authored — not GitHub's rendered HTML. The rendered form changes
  over time (emoji rendering, link-formatting tweaks, table-styling
  updates from GitHub's frontend) without the underlying source
  changing; pinning the raw `.body` immunizes the audit trail
  against those rendering shifts.

  The captured file is committed to the repository and content-
  hashed at commit time. Subsequent edits by the issue author are
  detected by comparing the committed file against a fresh fetch;
  the pin is then re-ratified or the design doc updates explicitly
  per `21-reversion-clause-discipline.mdc`.

  Phase 2 of [`DAA_LWMA1_PLAN.md`](./DAA_LWMA1_PLAN.md) lands the
  pin file.
- **Reference implementation:** the `LWMA1_()` C++ function defined
  inside zawy12 Issue #3. The issue contains **four** reference
  functions (`LWMA1_()`, `LWMA2_()`, `LWMA3_()`, `LWMA4_()`);
  cross-references to "Issue #3, lines N–M" are otherwise
  ambiguous between them.
  Phase 2 of [`DAA_LWMA1_PLAN.md`](./DAA_LWMA1_PLAN.md) records
  three disambiguation anchors in `docs/design/refs/zawy12_issue_3_lwma1.md`
  alongside the raw `.body`:

  1. **Byte-offset range** `[offset_start, offset_end)` within the
     pinned raw `.body` that contains the entire `LWMA1_()`
     function definition (signature, body, closing brace). Computed
     at Phase 2 PR time via the raw `.body` SHA-256-anchored pin.
     All later citations in this design doc that read "Issue #3,
     LWMA-1 reference, lines N–M" are interpreted as lines N–M
     *within this byte-offset range*, not within the full `.body`.
  2. **First-line anchor**: the literal first line of `LWMA1_()`
     (currently
     `LWMA1_(timestamps, cumulative_difficulties, T, N, height,...) {`
     at the design-doc pin date; recorded verbatim at Phase 2 PR
     time so a future maintainer can grep it).
  3. **Last-line anchor**: the literal last line (the function's
     closing `}` plus any trailing comment), recorded verbatim.

  These anchors together pin `LWMA1_()` against future
  upstream-author edits that add or reorder content in the
  issue. Used as a cross-check only; the Rust implementation is
  written from the textual spec per §2.3.

  All §5.3 "lines N–M" citations in this design doc resolve
  against the LWMA1_() byte-offset range above, not against the
  full pinned `.body`.

- **Simulation tooling:** zawy12's `difficulty-algorithms` repository
  contains historical-data simulators used to derive test-vector
  corpora. Specific corpus selection is described in §8.

## 4. The LWMA-1 algorithm — Shekyl parameter selection

| Parameter | Symbol | Shekyl V3.0 value | Source / rationale |
| --- | --- | --- | --- |
| Window size | `N` | **90** | zawy12 canonical recommendation for `T = 120 s` chains (Issue #3, line 84) |
| Target block time | `T` | **120 s** | Shekyl's chosen target block time per zawy12 LWMA-1's recommended range (60–120 s for CPU-mineable chains). The numerical value happens to match the inherited C++ `DIFFICULTY_TARGET_V2 = 120`, but Shekyl's source-of-truth is the JSON authority `daa_target_seconds` per §4, not the inherited `#define`. The inherited define is deleted at Phase 4 per §9.2. |
| Solvetime clamp factor | k_st | **6** (i.e., individual solvetimes capped at `6*T`) | zawy12 canonical |
| Minimum-L floor coefficient | k_L | **1/20** (i.e., `L_min = N*N*T/20`) | zawy12 canonical |
| Bias factor numerator | b_num | **99** | zawy12 canonical (Issue #3, LWMA-1 reference line 127, unchanged since 2017–2018; derivation in §5.3 step 7) |
| Bias factor denominator | b_den | **200** | zawy12 canonical (same line; `200 = 2 * 100` per the derivation in §5.3 step 7, not a separate tunable) |
| Genesis difficulty | `D₀` | **100** | zawy12 canonical example for new CPU-mineable chains. Ratified in Round 4 per `DAA_LWMA1_PLAN.md` "Phase 0 dispositions"; first-week-of-testnet recalibration, if observed CPU hashrate differs materially from canonical assumptions, lands as a sibling PR with its own design-doc justification, not as a Phase 0 unknown. |
| Block future time limit | FTL | **`N * T / 20` = 540 s** | zawy12 canonical hard requirement (Issue #3 lines 85, 91); tightens inherited `CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT = 7200 s` |
| Median time past window | MTP | **11** | zawy12 LWMA-1 canonical; tightens inherited `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW = 60` back to the CryptoNote-original 11 (Monero widened to 60; LWMA-1 doesn't need the widening per §2.5) |

All values become typed `pub const` in
`shekyl-difficulty/src/consts.rs` per `RANDOMX_V2_RUST.md` §9's
"typed const, not env var" disposition. No env-var overrides;
consensus constants are not runtime-tunable.

**Source-of-truth pattern: `config/consensus_constants.json`.**
The five numeric constants — `N`, `T_SECONDS`, `FTL_SECONDS`,
`MTP_WINDOW`, `GENESIS_DIFFICULTY` — are added to the existing
JSON authority at `config/consensus_constants.json`, alongside the
`fcmp_reference_block_*_age` and `rct_type_fcmp_plus_plus_pqc`
keys already there. This matches the project's preferred
constant-drift-prevention pattern documented in
[`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) (the "Full migration of
remaining `SHEKYL_*` FFI constants to the JSON-authority pattern"
entry) and the audit trail at
[`docs/audit_trail/2026-05-ffi-constant-drift-audit.md`](../audit_trail/2026-05-ffi-constant-drift-audit.md).

**Algorithm-version-free naming.** The JSON keys and the generated
C++ symbols are `daa_*` and `SHEKYL_DAA_*`, **not**
`daa_lwma1_*` / `SHEKYL_DAA_LWMA1_*`. Rationale: if §10's reversion
clause ever fires (LWMA-2/3/4 or ASERT replaces LWMA-1), the JSON
keys and C++ symbol names should not have to change across every
consumer site at the same time as the algorithm body. The
algorithm-version flavor lives in the algorithm body
(`shekyl-difficulty/src/lwma1.rs` for LWMA-1, hypothetically
`asert.rs` for ASERT); the consensus constants are named for the
role they play (DAA window, DAA target, DAA FTL, DAA MTP, DAA
genesis difficulty), not for the algorithm that consumes them
today. This matches the existing JSON's `fcmp_reference_block_*`
pattern (FCMP is the subsystem, not a specific FCMP version) and
matches the reasoning that motivated deleting `DIFFICULTY_TARGET_V2`
instead of preserving it as a v1-specific constant.

```json
{
  "daa_window_n": 90,
  "daa_target_seconds": 120,
  "daa_ftl_seconds": 540,
  "daa_mtp_window": 11,
  "daa_genesis_difficulty": 100
}
```

The two derived/canonical constants — `b_num = 99`, `b_den = 200`,
`k_st = 6`, `k_L_num = 1`, `k_L_den = 20` — are **not** JSON-keyed
**and not named `pub const` in `consts.rs`**. They are
zawy12-canonical fixed values (per §5.3 step 7's derivation), not
Shekyl tunables, and they appear as **bare integer literals** in
the algorithm body in `shekyl-difficulty/src/lwma1.rs` so that the
formula reads against the canonical reference verbatim (e.g., the
line that applies the bias factor is literally
`next_D = avg_D * N * (N+1) * T * 99 / (200 * L)` with `99` and
`200` as literals, matching canonical Issue #3 line 127). A
brief comment at each literal cites the canonical line. Naming
these as `BIAS_NUMERATOR` / `BIAS_DENOMINATOR` consts would invite
future "tunable" misreadings; bare literals foreclose that
misreading by construction.

The cross-language generation pipeline is the existing one:

- **Rust side.** A new `rust/shekyl-difficulty/build.rs` reads the
  JSON and emits `consensus_constants_generated.rs` into `OUT_DIR`.
  `shekyl-difficulty/src/consts.rs` `include!`s the generated file
  and re-exports the constants under the canonical zawy12 names
  (`N`, `T_SECONDS`, etc.). This preserves the leaf-crate property
  per §2.1 (zero internal workspace deps; `serde_json` is a
  build-time dep only, not a runtime dep). Extending
  `rust/shekyl-engine-core/build.rs` to emit the LWMA-1 keys was
  considered and rejected: it would introduce a workspace-internal
  dep from `shekyl-difficulty` to `shekyl-engine-core` purely to
  consume generated constants, breaking the leaf-crate property
  for negligible code reduction.
- **C++ side.** `cmake/generate_consensus_constants.py` is
  extended with the five new keys, emitting them as `constexpr`
  symbols `SHEKYL_DAA_WINDOW_N`, `SHEKYL_DAA_TARGET_SECONDS`,
  `SHEKYL_DAA_FTL_SECONDS`, `SHEKYL_DAA_MTP_WINDOW`,
  `SHEKYL_DAA_GENESIS_DIFFICULTY` into the generated
  `shekyl/consensus_constants_generated.h`. The C++ side consumes
  the generated header; no hand-maintained `#define` for any DAA
  numeric constant.
- **`shekyl_ffi.h`.** Hand-maintained per
  `25-rust-architecture.mdc` (the rule permits "cbindgen or
  hand-maintained"; the project's current pattern is
  hand-maintained); numeric constants are sourced from the
  generated header, not duplicated. No `cbindgen.toml` is added
  by this PR.

Per `75-system-autonomy.mdc`, every tunable has a documented rationale
for its default and bounds for safe adjustment. The "safe adjustment
bounds" for these values are: **none post-genesis without a hard
fork.** Any value change is a consensus rule change requiring the
full hard-fork process per `00-mission.mdc`'s system-outlast-the-team
commitment. The values above are the values Shekyl ships at genesis
and the values that anchor reproducible-build verification.

## 5. The LWMA-1 algorithm — formal specification

### 5.1 Inputs

The DAA is invoked when about to validate (or compute the target
for) a new block. Let:

- `chain_height` — the height of the **chain tip** (the most recent
  block already on chain). Genesis is height 0. After N+1 blocks
  have been accepted, `chain_height == N`.
- `timestamps[0..=N]` — `u64` raw block timestamps (seconds since
  Unix epoch), in chain order, with `timestamps[0]` the oldest block
  in the window and `timestamps[N]` the chain tip. The window holds
  the most recent `N+1` accepted blocks.
- `cumulative_difficulties[0..=N]` — `u128` cumulative difficulty up
  to and including each block in the window.

Plus three protocol constants: `T = 120`, `N = 90`,
`GENESIS_DIFFICULTY = 100`.

The input-vector length is fixed at `N+1` once the chain has matured
(`chain_height >= N`). During the genesis window (`chain_height < N`,
i.e., chain holds fewer than `N+1` blocks) the algorithm returns
`GENESIS_DIFFICULTY` per §5.3 step 1 without inspecting the input
vectors at all, and the FFI shim accepts a shorter `count` per §6.1.

### 5.2 Output

`next_difficulty: u128` — the difficulty that the next block must
satisfy.

### 5.3 Algorithm (textual specification)

The algorithm is the canonical zawy12 LWMA-1, expressed in plain
language for spec-first review (per `05-system-thinking.mdc`'s
specification-first rule). Step-by-step:

**Step 1 — Genesis-window short-circuit.** If `chain_height < N`,
return `GENESIS_DIFFICULTY` directly. The chain has not yet
accumulated `N + 1` blocks to weight against. This matches the
canonical guard at zawy12 Issue #3, LWMA-1 reference, line 107:
`if (height >= FORK_HEIGHT && height < FORK_HEIGHT + N) { return
difficulty_guess; }`. Shekyl's `FORK_HEIGHT` is `0` (LWMA-1 lands at
genesis with no prior algorithm to fork away from), so the
condition collapses to `chain_height < N`.

Boundary cases, anchored to the canonical:

- `chain_height == 0` (only genesis block on chain): short-circuit
  fires; return `GENESIS_DIFFICULTY`.
- `chain_height == N - 1` (block at height `N-1` is the tip, chain
  has `N` blocks): short-circuit fires; return `GENESIS_DIFFICULTY`.
- `chain_height == N` (block at height `N` is the tip, chain has
  `N+1` blocks): **first non-short-circuit invocation**. The window
  is exactly `timestamps[0..=N]` and `cumulative_difficulties[0..=N]`,
  matching the canonical's `assert(timestamps.size() == N+1)` at
  line 108. The algorithm computes the difficulty target for the
  next block (at height `N + 1`).

The FFI surface's `count` parameter (§6.1) is bound to this
boundary: when `chain_height < N`, any `count` is acceptable (the
short-circuit ignores the vectors); when `chain_height >= N`,
`count` must equal `N + 1` exactly, and `ERR_INVALID_COUNT` fires
otherwise. This is the consensus invariant; an off-by-one here is a
hard fork.

**Step 2 — Out-of-sequence timestamp normalization.** Compute
solvetimes from raw timestamps via a forward pass that converts any
out-of-sequence (decreasing or equal) timestamp pair into a positive
solvetime of 1 second. Sustained adversarial out-of-sequence
timestamps are bounded by the MTP check (§5.5), which rejects new
blocks whose timestamp is below the median of the previous 11. The
forward pass tracks a local `prev` (the normalized previous
timestamp) and never mutates the input array:

```text
prev = timestamps[0] - T            // synthetic anchor, matches canonical line 112
for i in 1..=N:
    this_ts = max(timestamps[i], prev + 1)   // out-of-sequence safety
    solvetime[i] = this_ts - prev            // always positive, >= 1
    prev = this_ts
```

Per-iteration equivalence to canonical zawy12 Issue #3, LWMA-1
reference, lines 113–118:

- `if timestamps[i] > prev`: `this_ts == timestamps[i]`,
  `solvetime[i] == timestamps[i] - prev` (canonical lines 115, 117).
- `if timestamps[i] <= prev`: `this_ts == prev + 1`,
  `solvetime[i] == 1` (canonical lines 116, 117).

The `-T` offset on the initial `prev` is the canonical choice (line
112: `previous_timestamp = timestamps[0] - T`) and is load-bearing:
removing it would change every solvetime[1] by +T, shifting `L`'s
expected stable-state value and biasing `next_D` by a constant
factor. The offset is preserved here exactly.

The Rust implementation takes `timestamps: &[u64]` and never writes
into the caller's storage; `solvetime[i]` is local to the
computation and `prev` is a stack-local `u64`.

**Step 3 — Solvetime clamp.** Each solvetime is clamped to
`min(6*T, solvetime)`. Solvetimes above `6*T = 720 s` are treated as
if they were exactly `6*T`. This is the canonical defense against
timestamp manipulation that tries to drive difficulty down via one
large lying timestamp.

**Step 4 — Linear-weighted sum.** Compute the weighted-sum L as
`L = sum over i in 1..=N of (i * clamped_solvetime[i])`. Indexing
convention, locked:

- `solvetime[i]` is the normalized interval between the previous
  iteration's `prev` and `timestamps[i]` (steps 2–3), for `i` in
  `1..=N`.
- `solvetime[1]` is the **oldest** interval in the window —
  specifically, the gap between the synthetic anchor
  (`timestamps[0] - T`) and the normalized `timestamps[1]`. Weight
  `1`.
- `solvetime[N]` is the **most recent** interval — the gap between
  the normalized `timestamps[N-1]` and the normalized `timestamps[N]`
  (the chain tip). Weight `N`.
- There is no `solvetime[0]`. The window holds `N + 1` timestamps
  and produces `N` solvetimes.

This matches canonical zawy12 Issue #3, LWMA-1 reference, line 117:
`L += i*std::min(6*T, this_timestamp - previous_timestamp);` where
`i` is the loop iteration in `1..=N`. The Phase 1 implementer must
use this exact indexing — a 0-indexed weighting variant (weights
`0..N-1`) would change `L` by a factor of `(N-1)/N` relative to
canonical and break the bias correction in step 7.

**Step 5 — Minimum-L floor.** If `L < N*N*T/20`, set
`L = N*N*T/20`. This prevents extreme upward difficulty swings on a
run of unusually fast blocks.

**Step 6 — Average difficulty over the window.** Compute
`avg_D = (cumulative_difficulties[N] - cumulative_difficulties[0]) / N`.

**Step 7 — Apply formula with bias factor.** Compute

```text
next_D = (avg_D * N * (N+1) * T * 99) / (200 * L)
```

**Derivation** (from canonical zawy12 Issue #3, LWMA-2 reference's
commented derivation, lines 313–318 *at the Phase 2 pinned-spec
revision* per §3; the GitHub issue body's rendered Markdown can
re-flow when the upstream author edits unrelated sections, so the
line numbers above are stable only against the revision captured
in `docs/design/refs/zawy12_issue_3_lwma1.md`). Applies to the
LWMA-1 formula above with the LWMA-1 constant of `99` rather than
LWMA-2's `97`:

- `L / (N*(N+1)/2)` is the linear-weighted-moving-average of the
  clamped solvetimes (the denominator `N*(N+1)/2` is the sum of
  weights `1 + 2 + ... + N`). Call this `LWMA(STs)`.
- Therefore `(N*(N+1)) / (2*L) == 1 / LWMA(STs)`.
- `avg_D / LWMA(STs) ≈ HR` (the estimated hashrate over the window),
  and `T / LWMA(STs)` is the ratio that adjusts `avg_D` so that the
  target solvetime becomes `T` on average.
- The unadjusted target is `avg_D * T / LWMA(STs) =
  avg_D * T * N * (N+1) / (2 * L)`.
- The multiplicative correction `99 / 100` compensates for a ~1 %
  upward bias in `next_D` that arises **under stochastic operating
  conditions** from three sources documented in canonical: (a) the
  `6*T` solvetime clamp truncates the upper tail of the solvetime
  distribution, (b) low-`N` Poisson skew approximates a gamma
  distribution that pulls the empirical mean above `T`, and (c)
  downstream LWMA-2+ variants' jump rules add further upward bias
  which the canonical author chose to keep the correction
  conservative against. LWMA-1 has neither (b)-amplifiers nor jump
  rules, so the `99/100` correction is a slight over-correction for
  LWMA-1 in isolation; canonical's recommendation is to keep `99`
  regardless, on the grounds that variance reduction is cheaper
  than perfect mean centering.
- Combining: `next_D = avg_D * T * N * (N+1) / (2 * L) * 99 / 100
  = (avg_D * N * (N+1) * T * 99) / (200 * L)`. The denominator
  `200` is `2 * 100`, not a separate constant — `2` from the
  weighted-sum denominator and `100` from the bias correction.

**Stochastic-vs-deterministic clarification (load-bearing for §8.1
test interpretation).** All three bias sources above are
*stochastic*: they apply when solvetimes are Poisson-distributed
around mean `T`, with occasional outliers triggering the `6*T`
clamp. Under those conditions — the realistic chain-operating
conditions LWMA-1 is designed for — the `99/100` factor cancels
the ~1 % upward drift, leaving the long-run average difficulty
centered on `avg_D`.

Under **deterministic operating conditions** — specifically, the
synthetic unit-test inputs of §8.1 where all solvetimes are
exactly `T` and no clamp fires — none of the three stochastic
sources are present. The same `99/100` factor then produces a
deterministic 1 % downward residual: `next_D = avg_D * 99/100`
on stable-hashrate input. This is **not** a bug and **not** a
test-expectation error; it is the same algorithm operating on a
different input shape, with the bias-correction surfacing as a
visible numerical residual because the stochastic drift it was
designed to cancel isn't there.

The §8.1 unit-test corpus is deliberately deterministic (no PRNG,
no Poisson sampling) so the test vectors are reproducible
byte-for-byte across hosts. The 1 % residual is therefore the
*expected* output of a correct implementation on §8.1's stable
vector. A Phase 1 implementer who hits the §8.1 stable vector and
sees `next_D == avg_D * 99/100` is observing a correct
implementation; a Phase 1 implementer who "fixes" the algorithm
to produce `next_D == avg_D` on the deterministic vector has
**broken the stochastic centering** that the factor exists to
provide. Phase 2's canonical-reference cross-check (§8.2) is the
backstop: the canonical zawy12 `LWMA1_()` C++ function applied to
the §8.1 stable input produces `990_000` for `avg_D = 1_000_000`,
not `1_000_000`. The Phase 1 implementer transcribes the formula
verbatim and reaches the same number by construction.

**Phase 1 pre-flight verification.** Before Phase 1 implementation
begins, the canonical reference C++ implementation (extracted in
Phase 2 to `tests/difficulty/zawy12_lwma1_reference.h`) is run
once against the §8.1 stable-hashrate vector with
`avg_D = 1_000_000` and the result recorded. If the result is
`990_000`, the §8.1 expectation and this section's stochastic-vs-
deterministic framing are both correct. If the result is
`1_000_000`, the §8.1 vector is wrong (and this clarification
section needs revision in the opposite direction). The Phase 1
pre-flight task in
[`DAA_LWMA1_PLAN.md`](./DAA_LWMA1_PLAN.md) Phase 1 records this
verification step explicitly so it cannot be skipped.

The direction matters: a `200/99` formula (denominator and
numerator swapped) would invert the bias correction and produce
`~1%` *higher* difficulty than the correct value, compounding to a
chronic block-overshoot in real chains. The downstream
[bams-repo/go-chain v0.10.3 audit](https://github.com/bams-repo/go-chain/commit/ae0eeede48f2602297f75df833689549df405ef7)
documents one consumer that had the direction inverted and fixed
it; canonical zawy12 has had the correct `99/200` direction since
2017–2018. Cite preserved here as an example of how easy this
inversion is to introduce — the Phase 1 implementer must transcribe
the formula from canonical line 127 verbatim, not from secondary
sources.

**Step 8 — Overflow guard.** If `avg_D > 2_000_000 * N * N * T`,
re-associate the multiplication to avoid `u128` overflow:

```text
next_D = (avg_D / (200 * L)) * (N * (N+1) * T * 99)
```

Matches canonical zawy12 Issue #3, LWMA-1 reference, lines 124–127
*at the Phase 2 pinned-spec revision* per §3; same line-stability
caveat as step 7.

**Determinism of the branch trigger.** The condition `avg_D >
2_000_000 * N * N * T` is pure integer comparison against
deterministic inputs: `avg_D` is computed from on-chain
cumulative-difficulty values (consensus-deterministic by
construction), `N` and `T` are compile-time `u128` constants, and
the right-hand side `2_000_000 * N * N * T` is a single `u128`
multiplication chain (`2_000_000 * 90 * 90 * 120 = 1_944_000_000`,
well below `u128::MAX`). Every node evaluating the condition with
identical inputs produces an identical boolean. The branch is
consensus-safe.

**Rounding difference at the boundary.** The two formulas produce
**different** integer results when the branch trigger fires,
because integer division is not associative:
`(avg_D / (200 * L)) * K != (avg_D * K) / (200 * L)` in general,
where `K = N * (N+1) * T * 99`. The maximum divergence is bounded
by `K - 1` units in the `next_D` output (one full divide-rounding
step). For Shekyl parameters this is at most `90 * 91 * 120 * 99 =
97_297_200` units, which is small relative to any `avg_D` that
triggers the branch (`avg_D > 1.944e9`), but **not** within "one
unit" as the original draft claimed.

The consensus property is not that the two formulas produce
identical outputs — they don't — but that **every node takes the
same branch on the same inputs and produces the same output within
that branch**. The branch trigger and both formulas are
bit-deterministic per the determinism argument above.

**§8.1 test vector requirement.** The §8.1 unit-test corpus must
include at least one vector with `avg_D` straddling the boundary —
specifically: one input set with `avg_D` just below the trigger
(unguarded branch) and one input set with `avg_D` just above the
trigger (guarded branch), both cross-checked against the canonical
reference C++ output via §8.2. This proves both branches' rounding
behavior matches canonical and that the branch trigger fires at the
correct threshold. Phase 1 cannot merge if this boundary test is
absent or fails.

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

### 5.6 Validator consumer contract: `chain_height → header.difficulty`

The DAA function returns `next_difficulty` given
`(chain_height, timestamps, cumulative_difficulties)`. The
block-header validator's contract — what value of
`header.difficulty` is *accepted* for the block at a given height —
is **defined by the DAA function applied at the predecessor's
chain_height**. Spelling this out explicitly because §2.6 ratifies
the constant but the consumer mapping is the surface a Phase 4
reviewer audits, and leaving it implicit invites off-by-one bugs.

The block being validated sits at height `h`. The validator
computes its expected difficulty as
`lwma1_next(chain_height = h-1, count, timestamps, cum_difficulties)`
and asserts `header.difficulty == expected`. The three regimes:

| Block height `h` | `chain_height = h-1` | Path inside `lwma1_next` | Expected `header.difficulty` |
| --- | --- | --- | --- |
| `0` (genesis) | n/a | not invoked | hard-coded in genesis-block construction; **not** subject to DAA verification |
| `1..=N` (blocks 1 through 90) | `0..=N-1` (0 through 89) | §5.3 step 1 short-circuit | `GENESIS_DIFFICULTY` (== 100 per §4) |
| `>= N+1` (blocks 91 onwards) | `>= N` (90 onwards) | §5.3 steps 2–8 | `lwma1_next(h-1, N+1, ts[h-N-1..=h-1], cd[h-N-1..=h-1])` |

Three consequences worth surfacing:

- **First algorithm-computed block is block N+1 (== 91 for Shekyl
  V3.0).** Block N (== 90) still inherits `GENESIS_DIFFICULTY`
  because its predecessor's `chain_height = N-1` is still in the
  short-circuit range. The "the first N+1 blocks share genesis
  difficulty" framing is the consumer-contract restatement of
  §5.3 step 1's `chain_height < N` boundary.
- **Genesis block (height 0) is exempt.** Its `difficulty` field
  is part of the genesis-block hash and is written by the
  genesis-block construction code, not by the DAA. The validator
  may additionally assert `genesis.difficulty == GENESIS_DIFFICULTY`
  for symmetry with the rest of the chain, but this is a
  defense-in-depth check, not a consensus rule — the consensus
  rule is the genesis-block hash itself, which is already fixed
  at genesis-block-construction time.
- **The FFI `chain_height` parameter is the predecessor's height,
  not the block-being-validated's height.** The off-by-one between
  "height of the block whose difficulty I am about to validate"
  (== `h`) and "chain_height at the moment I am computing that
  difficulty" (== `h-1`) is the most common consumer-side error
  class and must be reviewed at every Phase 4 call site. The
  `Blockchain::get_difficulty_for_next_block()` consumer
  (§9.4) already operates on the "next block" framing, so the
  off-by-one is absorbed naturally; the
  `get_next_difficulty_for_alternative_chain()` consumer requires
  explicit attention because the alternate-chain branch may
  compute `chain_height` from the alt-chain's tip rather than the
  main chain's.

## 6. FFI surface

Per `40-ffi-discipline.mdc`, all exports return `i32` error codes;
output values reach the caller through out-parameters.

### 6.1 The one committed export

**Difficulty type at the ABI boundary: `struct ShekylU128 { lo, hi }`
little-endian by field semantics.** The FFI exchanges 128-bit
difficulty values as a `#[repr(C)]` two-`u64` struct, **not** as
Rust `u128` / C `__uint128_t`. Rationale per
`17-dependency-discipline.mdc`'s property-existence discipline and
Round 5 review:

- The Rust `u128` C ABI was **unsound on several targets** until
  rustc 1.77 (released March 2024); the `improper_ctypes` lint
  flagged it as undefined behavior up to that point, and the
  underlying ABI mismatch survives on uncommon targets even on
  current Rust. See
  [rust-lang/rust#54341](https://github.com/rust-lang/rust/issues/54341)
  and [RFC 3535](https://github.com/rust-lang/rfcs/pull/3535).
  For a **consensus-critical** FFI surface, a target-dependent
  soundness footgun is unacceptable.
- `u64` is `unsigned long long` everywhere Shekyl supports;
  its ABI is universally stable across every Rust toolchain
  Shekyl targets. Decomposing the 128-bit value into two `u64`
  fields eliminates the `improper_ctypes` exposure, removes any
  MSRV-pin-to-1.78 constraint, and skips the per-target ABI
  verification matrix entirely.
- The struct-with-named-fields shape preserves explicit
  semantics: `lo` is the low 64 bits, `hi` is the high 64 bits.
  Debugger-friendly, survives any future endianness disposition
  because the field meaning is carried by the field name, and
  unambiguous at every consumer call site. `[u64; 2]` works
  equivalently at the ABI level but loses the field naming and
  invites lo/hi confusion.
- This matches the FCMP++ and KEM-derivation FFI surfaces
  already in the workspace, which exchange field elements and
  scalars as field-named `#[repr(C)]` structs rather than
  opaque byte arrays for the same field-semantic-clarity
  reason.
- Endianness convention: **little-endian by field semantics.**
  `ShekylU128` is little-endian by field semantics — `lo` is
  the low 64 bits, `hi` is the high 64 bits. Reconstruction:
  `value = (hi as u128) << 64 | (lo as u128)`. Each `u64` field
  is itself stored in target-native byte order at memory, but
  the *semantic* meaning of `lo` vs. `hi` is consensus-locked
  by the field names; consumers reconstruct the 128-bit value
  using arithmetic, not byte-order reinterpretation.

```c
// The 128-bit difficulty representation at the FFI boundary.
// Little-endian by field semantics: lo is the low 64 bits,
// hi is the high 64 bits. To reconstruct the 128-bit value:
//   value = ((__uint128_t)hi << 64) | (__uint128_t)lo;
struct shekyl_u128 {
    uint64_t lo;
    uint64_t hi;
};

// Compute next difficulty per LWMA-1.
//
// Inputs:
//   timestamps          - pointer to count u64 timestamps in chain order,
//                         oldest first; index 0 is the oldest, index
//                         count-1 is the chain tip
//   cum_difficulties    - pointer to count shekyl_u128 cumulative-
//                         difficulty values matching timestamps in
//                         order. Each entry's (lo, hi) fields decompose
//                         the corresponding u128 cumulative difficulty.
//                         C callers with a native uint128_t-typed
//                         buffer must construct shekyl_u128 instances
//                         explicitly (`{ .lo = v, .hi = v >> 64 }`)
//                         rather than reinterpret-casting, so the
//                         field-meaning is a checkpoint at the call
//                         site.
//   count               - number of entries in each array.
//                         - If chain_height >= N: count MUST equal N+1
//                           (== 91 for Shekyl V3.0); ERR_INVALID_COUNT
//                           otherwise. This is the consensus contract
//                           per §5.3 step 1's boundary.
//                         - If chain_height <  N: count is ignored
//                           (the genesis short-circuit returns
//                           GENESIS_DIFFICULTY without inspecting the
//                           vectors). Caller may pass any value
//                           including 0.
//   chain_height        - height of the chain tip (the most recent
//                         block already on chain). Used for the
//                         genesis short-circuit per §5.3 step 1; the
//                         transition from short-circuit to algorithm
//                         fires at chain_height == N.
//   out_next_difficulty - pointer to a shekyl_u128 receiving the
//                         next-difficulty output on success; its
//                         (lo, hi) fields decompose the u128 result
//                         per the same field semantics.
//
// Returns:
//   0  - OK; out_next_difficulty written
//  -1  - ERR_NULL_PTR (any required pointer is null, including
//                      out_next_difficulty; timestamps and cum_difficulties
//                      may be null only when chain_height < N)
//  -2  - ERR_INVALID_COUNT (chain_height >= N AND count != N+1)
//  -3  - ERR_OVERFLOW (consensus invariant violation; out_next_difficulty
//                      not written; caller must treat as protocol error)
//  -4  - ERR_INTERNAL (caught panic at FFI boundary; out_next_difficulty
//                      not written)
int32_t shekyl_difficulty_lwma1_next(
    const uint64_t *timestamps,
    const struct shekyl_u128 *cum_difficulties,
    size_t count,
    uint64_t chain_height,
    struct shekyl_u128 *out_next_difficulty);
```

The Rust-side mirror lives in `rust/shekyl-ffi/src/lib.rs`:

```rust
#[repr(C)]
pub struct ShekylU128 {
    pub lo: u64,
    pub hi: u64,
}

impl From<u128> for ShekylU128 {
    fn from(v: u128) -> Self {
        Self { lo: v as u64, hi: (v >> 64) as u64 }
    }
}

impl From<ShekylU128> for u128 {
    fn from(v: ShekylU128) -> u128 {
        ((v.hi as u128) << 64) | (v.lo as u128)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn shekyl_difficulty_lwma1_next(
    timestamps: *const u64,
    cum_difficulties: *const ShekylU128,
    count: usize,
    chain_height: u64,
    out_next_difficulty: *mut ShekylU128,
) -> i32 {
    // Reads cum_difficulties[i] via core::ptr::read followed by
    // ShekylU128::into() to recover u128; writes out_next_difficulty
    // via core::ptr::write of ShekylU128::from(u128).
    // ... per the algorithm and error taxonomy above.
}
```

The conversions are infallible and lossless: the `u64`-to-`u128`
widening is loss-free in both directions, and the bit-shift
arithmetic is consensus-locked by §6.1's field-semantics
contract. The cost is one extra type definition and four lines
of `From` impls per direction — cheaper than auditing `u128`
ABI behavior on every Shekyl-supported target on every Rust
toolchain bump.

### 6.2 Discretionary additions (deferred to V3.x unless Phase 4 finds need)

None at Phase 0. The DAA surface is structurally a single function;
exposing the `GENESIS_DIFFICULTY` constant, the parameter values, or
intermediate computation steps as separate exports adds attack
surface without delivering caller value. The C++ side consumes the
numeric consensus constants (N, T, FTL, MTP, GENESIS_DIFFICULTY) via
the **generated header** `shekyl/consensus_constants_generated.h`,
which is emitted from `config/consensus_constants.json` by
`cmake/generate_consensus_constants.py` (per §4's source-of-truth
pattern). The C++ side does **not** call into Rust to read these
values at runtime; the consensus constants live at compile time on
both sides, generated from the single JSON authority.

### 6.3 Explicitly NOT exported

- `LWMA1_()` reference C++ function. The canonical reference lives
  in the spec issue, not in the codebase. Including it would
  duplicate audit surface and create a second-source-of-truth
  problem (which one wins on disagreement?).
- Per-step pseudocode helpers. The algorithm is one function at the
  spec level; the FFI mirrors that.
- Difficulty conversion / packing helpers. Difficulty is `u128`
  end-to-end at the consensus level on both sides; only the ABI
  representation differs (`struct ShekylU128 { lo, hi }` per §6.1's
  discipline). The C++ side decomposes/composes its native
  `uint128_t` against the `(lo, hi)` field semantics at every call
  site; the Rust side uses the `From<u128> ↔ From<ShekylU128>`
  conversions defined in §6.1. No general-purpose packing helper
  is exposed across the FFI.
- **The `is_above_mtp` and `is_timestamp_below_ftl` predicates
  committed in §2.5.** These live in `shekyl-difficulty` and are
  consumed by the future Rust validator actor (§17), not by C++.
  C++ performs the corresponding FTL and MTP checks directly
  against the generated header constants `SHEKYL_DAA_FTL_SECONDS`
  and `SHEKYL_DAA_MTP_WINDOW` (per §6.2's source-of-truth
  pattern) — `c.timestamp > time(NULL) + SHEKYL_DAA_FTL_SECONDS`
  is the FTL site (§9.5); the median-of-11 MTP check inlines the
  generated `SHEKYL_DAA_MTP_WINDOW` constant in the existing
  `complete_timestamps_vector` + median computation (§9.6). The
  predicate functions are Rust-internal helpers for the §17
  consumer-side actor and remain unexposed across the FFI to
  avoid duplicating logic that the C++ side already has and to
  keep the FFI surface minimal per §6.1's "one committed export"
  discipline.

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

### 8.1 Unit tests (Phase 1 gate)

Author-derived synthetic vectors covering the algorithm's structural
properties. All expected values below are stated as **concrete
numerical tuples**, not as `≈` shapes — the bias factor `99/200`
introduces a deliberate `99/100` downward correction (per §5.3
step 7 derivation), and `≈`-shaped expectations invite three failure
paths at implementation time: (a) "fix" the test by relaxing the
tolerance to absorb the 1 % shift (wrong); (b) "fix" the algorithm
by removing the bias to make the test pass (wrong); or (c) declare
"within rounding" covers a 1 % shift when it actually covers a
±1-unit shift (wrong). Concrete tuples force the implementer to
confront the bias at design time, not at debug time.

The vectors below use Shekyl V3.0 parameters (`N = 90`, `T = 120`,
`GENESIS_DIFFICULTY = 100`).

- **Genesis short-circuit.** `chain_height < N` returns
  `GENESIS_DIFFICULTY` verbatim. Specifically: for any
  `chain_height ∈ {0, 1, ..., 89}` and any `(timestamps,
  cum_difficulties)` input (including null), the output is
  exactly `100`.
- **Perfectly stable hashrate.** `solvetime[i] == T == 120` for
  all `i in 1..=N`, `cum_difficulties` arithmetic-progressing by
  a constant `d_step` such that `avg_D == d_step` over the
  window. Expected output: **`next_D == avg_D * 99 / 100`**
  (the deterministic-input residual of the `99/100` factor per
  §5.3 step 7's stochastic-vs-deterministic clarification, **not**
  `next_D == avg_D`). For `avg_D == 1_000_000` this is exactly
  `990_000`. The 1 % residual is the design intent of the `99/200`
  factor surfacing on deterministic input — under realistic
  stochastic operation, the same factor cancels the ~1 % upward
  Poisson/clamp drift and leaves long-run average difficulty
  centered on `avg_D`; on this deterministic test vector, the
  drift isn't there, so the correction surfaces as a visible
  residual. A test asserting `next_D == avg_D` on this
  deterministic vector would falsely fail on a correct
  implementation and falsely pass on an implementation that
  silently removed the bias factor — destroying its stochastic
  centering property in the process.
- **Sudden 2× hashrate increase.** `solvetime[i] == T/2 == 60`
  for all `i`. With `L = 60 * N * (N+1) / 2`, the formula yields
  **`next_D == avg_D * 99 / 50 == avg_D * 198 / 100`** (a `1.98×`
  rise, not `2×`; the bias factor pulls the response slightly
  below the naive proportional response). For `avg_D == 1_000_000`
  this is exactly `1_980_000`.
- **Sudden 2× hashrate decrease.** `solvetime[i] == 2*T == 240`
  for all `i`. With `L = 240 * N * (N+1) / 2`, the formula yields
  **`next_D == avg_D * 99 / 200`** (a `0.495×` drop, not `0.5×`).
  For `avg_D == 1_000_000` this is exactly `495_000`.
- **Solvetime clamp engagement.** Single
  `solvetime[N] = 100 * T = 12_000` with all other solvetimes at
  `T`. The clamp truncates the outlier at `6*T = 720`; the
  expected output is computed against a clamped-solvetime vector,
  not against the raw vector. Test vector includes both the
  pre-clamp expected (had the clamp not fired — should fail) and
  the post-clamp expected (correct).
- **Minimum-L floor engagement.** All `solvetime[i] = 1` (the
  out-of-sequence-normalization floor). `L_raw = N*(N+1)/2 = 4_095`
  is far below `N*N*T/20 = 48_600`; the floor fires, `L` becomes
  `48_600`. Expected
  `next_D == avg_D * N * (N+1) * T * 99 / (200 * N*N*T/20)
          == avg_D * (N+1) * 99 * 20 / (200 * N)
          == avg_D * (N+1) * 99 / (10 * N)`. For `N = 90`,
  `avg_D = 1_000_000`, this is exactly `1_000_000 * 91 * 99 / 900
  == 1_000_000 * 9009 / 900 == 10_010_000`. The ~10× rise reflects
  the floor's job: extremely fast solvetimes signal a dramatic
  hashrate increase, and the algorithm responds proportionally
  (bounded by the floor, not unbounded).
- **Out-of-sequence timestamp normalization.** `timestamps[i+1] <
  timestamps[i]` for one or more `i`. Test vector asserts (a) no
  panic, (b) no zero output, (c) the output matches the
  algorithm run with the corresponding `solvetime[i] = 1`
  substitution per §5.3 step 2.
- **Bias factor direction sanity.** Stable-hashrate input with
  `solvetime[i] == T` produces output **below** `avg_D` (per the
  stable-hashrate vector above). A `200/99` direction inversion
  per §5.3 step 7 would produce `avg_D * 100 / 99 ≈ 1.0101 * avg_D`
  — output *above* `avg_D`. A test vector that asserts the
  output's relationship to `avg_D` is `<`, not `==` or `>`,
  catches the inversion bug class.
- **Overflow-guard boundary** (per §5.3 step 8). Two paired vectors:
  one with `avg_D` immediately below `2_000_000 * N * N * T =
  1_944_000_000` (unguarded branch); one with `avg_D` immediately
  above the threshold (guarded branch). Both cross-checked against
  the canonical reference output via §8.2. **Required**: Phase 1
  cannot merge without this pair.
- Anti-pattern regression: no per-block output clamp engaged
  anywhere; the divergence catalogue in §2.4 names the four
  anti-patterns (per-block clamp, caller-supplied solvetimes,
  missing minimum-L floor, missing bias factor) and the §8.1
  vectors must not exhibit any of them under any input.
- **`solvetime[1]` `-T` offset regression vector** (per §5.3
  step 2's "the `-T` offset is load-bearing" note). A vector
  where the algorithm without the offset would shift `L`'s
  expected stable-state value by a constant factor, producing a
  different `next_D` than the canonical reference. A future
  contributor who "simplifies" the offset away on the assumption
  that it cancels in the sum gets caught by this unit test,
  not by post-genesis drift. **Required**: Phase 1 cannot merge
  without this vector.

All vectors derived analytically against the §5.3 specification.

### 8.2 Canonical-reference cross-check (Phase 2 gate)

Generated by running the zawy12 reference `LWMA1_()` C++ function
on each of the §8.1 input cases and asserting byte-identical
output. The C++ reference is built from the issue-body source
saved at `docs/design/refs/zawy12_issue_3_lwma1.md` (per §3); a
small `tests/lwma1_cross_check.cpp` harness lives in
`tests/difficulty/` and CI runs it as part of the workspace's C++
test build.

The cross-check is **gating for Phase 2** (the cross-check harness
PR; the implementation crate lands in Phase 1). If the Rust output
diverges from the C++ reference on any §8.1 vector, the Rust
implementation is wrong (the spec wins by construction per §2.3,
but the cross-check catches the case where the Rust implementation
reads the spec differently from the C++ reference). Remediation is
to fix the Phase 1 crate, not the Phase 2 harness.

### 8.3 Simulated-history corpus (release-gate test, not per-PR)

Sourced from zawy12's simulator output on a representative
historical-hashrate trace. The exact trace is selected during Phase 1
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

All five inherited `DIFFICULTY_*` `#define`s and the two
timestamp-validation `#define`s are **deleted**, not renamed. Each
is replaced by a consumer rewire to the corresponding
`SHEKYL_DAA_*` symbol in the generated header
`shekyl/consensus_constants_generated.h` (per §4's source-of-truth
pattern). Renaming any of them would preserve the
hand-maintained-`#define` drift class that the JSON authority
exists to close.

- `DIFFICULTY_TARGET_V1` (line 83) — pre-genesis variant, dead under
  `60-no-monero-legacy.mdc`; **deleted**, no replacement.
- `DIFFICULTY_TARGET_V2` (line 82, value 120) — **deleted**;
  consumers rewired to `SHEKYL_DAA_TARGET_SECONDS` from the
  generated header. (The value is unchanged; the source-of-truth
  moves from the hand-maintained `#define` to the JSON authority.
  Round 3 disposition: delete-not-rename, against the prior draft's
  rename-to-`BLOCK_TARGET_SECONDS` framing, because a rename
  preserves exactly the drift class §4 exists to close.)
- `DIFFICULTY_WINDOW` (line 84) — **deleted**; the DAA crate's `N`
  const (sourced from `SHEKYL_DAA_WINDOW_N`) replaces it. No C++
  consumer outside `difficulty.cpp` reads this directly per the
  consumer audit; verify at Phase 4 PR time.
- `DIFFICULTY_LAG` (line 85, the `// !!!` constant) — the `// !!!`
  warning marks this as a known-buggy lag setting that Monero
  preserved for compatibility; LWMA-1 has no equivalent and the
  bug class doesn't apply. **Deleted**.
- `DIFFICULTY_CUT` (line 86) — not used by LWMA-1; **deleted**.
- `DIFFICULTY_BLOCKS_COUNT` (line 87) — was `N+1`; LWMA-1's
  consumers compute `N+1` from `SHEKYL_DAA_WINDOW_N` directly.
  **Deleted**.
- `DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN` (line 95) — test-alias for
  the inherited algorithm; **deleted**.
- `CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT` (line 51, value `60*60*2 =
  7200`) — **deleted**; consumers rewired to
  `SHEKYL_DAA_FTL_SECONDS` (value 540). The value change is the
  consensus-rule change; see §9.5 for the consumer list.
- `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW` (line 56, value 60) —
  **deleted**; consumers rewired to `SHEKYL_DAA_MTP_WINDOW` (value
  11). The value change is the consensus-rule change; see §9.6 for
  the consumer list.

There is **no** `BLOCK_FUTURE_TIME_LIMIT_V2` in this codebase
(prior drafts named one — phantom).

### 9.3 FTL and MTP — deletion locations and consumer-enumeration cross-references

FTL (`CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT`) and MTP
(`BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW`) are deleted from
`src/cryptonote_config.h` per §9.2's enumeration of nine
`#define` removals (the seven `DIFFICULTY_*` defines plus FTL
plus MTP). They do not have a separate "relocation" step
because the JSON authority `config/consensus_constants.json` is
the typed-const home from genesis — there is nothing to relocate
*from* a Monero-era #define *to* a Shekyl-era constant; the
Shekyl-era constant is the canonical source and the
Monero-inherited `#define` is the deletion target.

The operational consumer enumerations for FTL and MTP are:

- **FTL consumers** — §9.5 below (one daemon site at
  `blockchain.cpp:4276`, one test-suite site at
  `block_validation.cpp:137`).
- **MTP consumers** — §9.6 below (seven daemon sites and four
  test-suite sites).

The two value-change consensus-rule effects (FTL: 7200 → 540,
MTP: 60 → 11) take effect at the daemon consumer sites
enumerated in §9.5 and §9.6 respectively, simultaneously with
the §9.4 algorithm rewire, per Phase 4's atomic-cutover
discipline (see `DAA_LWMA1_PLAN.md` Phase 4 invocation of
`07-consensus-atomic-cutovers.mdc`). The Round 2 draft's §9.3
separately enumerated FTL/MTP under "value change with
relocation to typed-const home"; Round 3 collapsed those
enumerations into §9.2 and §9.5/§9.6 because there is no
separate relocation step — the section is preserved as a
header-anchor for downstream cross-references and to make the
"why isn't this here" question self-answering.

### 9.4 Call-site rewiring of `next_difficulty` in `src/cryptonote_core/blockchain.cpp`

Three call sites consume the inherited `next_difficulty` /
`next_difficulty_64`:

- `Blockchain::get_difficulty_for_next_block()` (~line 965) —
  rewires to `shekyl_difficulty_lwma1_next`.
- `Blockchain::check_difficulty_checkpoints()` (~line 1021) —
  rewires to the same; the recalculation loop's "use historical
  difficulty target" framing collapses because LWMA-1 has only one
  parameter set, not a v1/v2 split.
- `Blockchain::get_next_difficulty_for_alternative_chain()`
  (~line 1325) — rewires to the same.

Four other inherited consumers (per the §1.1 reconnaissance grep)
are out of scope or already absorbed:

- `src/cryptonote_basic/miner.cpp` — consumes via the blockchain
  interface, not directly; rewired by the three blockchain
  changes above.
- `src/cryptonote_basic/difficulty.{h,cpp}` — the implementation
  itself; deleted per §9.1.
- `src/wallet/wallet_rpc_payments.cpp` — deleted in full per
  `RANDOMX_V2_RUST.md` §15.
- `src/rpc/core_rpc_server.cpp` — consumes `next_difficulty` via
  the blockchain interface; rewired by the three changes above.

### 9.5 `CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT` consumer enumeration

The FTL constant has **one** direct consumer in the daemon source
tree per the Round 3 reconnaissance grep, plus one test-suite
consumer:

- `src/cryptonote_core/blockchain.cpp:4276`:
  `if(b.timestamp > (uint64_t)time(NULL) +
   CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT)` — the FTL check inside
  `Blockchain::check_block_timestamp_main`. Rewires to consume
  `SHEKYL_DAA_FTL_SECONDS` from the generated header. **This is
  the consensus-rule-change site**; the value-change from 7200 to
  540 takes effect here.
- `tests/core_tests/block_validation.cpp:137`:
  `time(NULL) + 60*60 + CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT` —
  test fixture constructing a block with timestamp deliberately
  past FTL. Rewires to `SHEKYL_DAA_FTL_SECONDS`; the test's
  semantics ("timestamp is past FTL") are preserved, but the
  numerical margin shrinks from 7200 + 3600 to 540 + 3600 — i.e.,
  from "7.2 hours past FTL" to "1 hour past FTL." 1 hour is still
  comfortably past `SHEKYL_DAA_FTL_SECONDS == 540`, so the test
  block remains over the FTL threshold; the smaller margin doesn't
  change the semantic outcome on any plausible test host.

  **Phase 4 reviewer note for this test.** With the shrunken margin,
  Phase 4 confirms the fixture asserts rejection *specifically
  because of the FTL check* — i.e., that the assertion is keyed to
  the FTL-violation error code (e.g., `MERROR_VER` /
  `kFutureTimestampViolatesFutureTimeLimit`), not to a generic
  "block rejected" outcome. The latter would let the test pass
  for the wrong reason if a future refactor moved the rejection
  to some other validation path (e.g., proof-of-work check, MTP
  check) before the FTL site fires. A test that passes for the
  wrong reason loses its evidence value about FTL behavior. The
  fixture's assertion-message inspection or error-enum equality
  check (whichever the test harness uses) is the operational
  enforcement of this property.

No other consumers in the C++ tree. The Phase 4 rewire surface
for FTL is **two sites**.

### 9.6 `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW` consumer enumeration

The MTP constant has **seven** direct consumers per the Round 3
reconnaissance grep, all in the daemon source tree, plus two
test-suite consumers:

- `src/cryptonote_core/blockchain.cpp:1981, 1985` —
  `complete_timestamps_vector`: assembles a timestamps vector of
  size `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW` for the MTP check.
- `src/cryptonote_core/blockchain.cpp:4223, 4230, 4240, 4259,
  4285, 4293` — six sites inside `check_block_timestamp` and
  `get_long_term_block_weight_median`: the MTP median computation,
  bounds checks, and the diagnostic `MERROR_VER` message.
- `tests/core_tests/block_validation.h:92, 97`:
  `gen_block_ts_not_checked` and `gen_block_ts_in_past` test
  fixtures parametrized by the constant.
- `tests/core_tests/block_validation.cpp:106, 120, 122` — fixture
  body sites using the constant.

All consumers rewire to `SHEKYL_DAA_MTP_WINDOW` from the generated
header. **The value change (60 → 11) takes effect across all of
these sites simultaneously.** Phase 4 reviewers should confirm
that none of the call sites embed implicit assumptions about the
window size (e.g., off-by-one arithmetic against the literal 60).
The `complete_timestamps_vector` shape is window-size-agnostic;
the `check_block_timestamp` median-computation is
window-size-agnostic; the test fixtures are template-parameterized
on the constant, so the rewire is purely textual.

### 9.7 `DIFFICULTY_TARGET_V2` consumer enumeration

The target-block-time constant has **~14 direct consumers across 9
files** per the Round 3 reconnaissance grep. This is meaningfully
larger than the §9.4 `next_difficulty` rewire surface and deserves
its own audit. All consumers rewire to `SHEKYL_DAA_TARGET_SECONDS`
from the generated header. The value is unchanged (still 120), so
the rewire is mechanical at every site, but the **surface is
larger than the §9.4 enumeration**, and one of the sites is
RPC-contract-load-bearing:

- `src/cryptonote_basic/cryptonote_basic_impl.cpp:78, 79` —
  `static_assert(DIFFICULTY_TARGET_V2%60==0, ...)` plus a `target`
  variable. The `static_assert` becomes a `const _: () =
  assert!(SHEKYL_DAA_TARGET_SECONDS % 60 == 0);` on the Rust side
  (or its C++ `constexpr` equivalent on the C++ side).
- `src/cryptonote_core/blockchain.cpp:1020, 1322, 5894` — three
  sites; the first two are inside the `next_difficulty` call-site
  rewires from §9.4 and absorb naturally; `5894` is a getter
  returning the block target seconds.
- `src/cryptonote_core/cryptonote_core.cpp:1817, 1829, 1838` —
  three sites inside the Poisson-probability blockchain-stall
  detection threshold. The math is `T`-dependent; consumers
  rewire textually. **Phase 4 reviewer note for stall detection.**
  The rewire is value-preserving (`T` is unchanged at 120s), so
  the stall-detection threshold's numerical behavior is
  byte-identical pre- and post-rewire. *However*, the math is
  not exercised by any test in the current `tests/` tree per the
  Round 3 reconnaissance grep — the three sites compute the
  expected-blocks-per-hour from `DIFFICULTY_TARGET_V2` and feed
  it into a Poisson-probability comparison, but no unit test or
  core test invokes that path. Phase 4 either (a) confirms via
  grep that test coverage exists in the harness or (b) adds a
  minimal regression test that exercises the stall-detection
  path with a deterministic timestamp series, so the post-rewire
  daemon's stall behavior is asserted rather than asserted-by-
  textual-equivalence. The Phase 4 PR includes the (a)-or-(b)
  disposition explicitly; "rewire textually, value unchanged" is
  not by itself a sufficient verification claim for a path with
  no test coverage.
- **`src/rpc/core_rpc_server.cpp:1452`** —
  `res.block_target = DIFFICULTY_TARGET_V2;` — **this is a daemon
  RPC field consumed by wallet callers**. The value is unchanged
  (still 120), so the RPC contract is preserved; the rewire is
  source-only. The §11 wallet-touchpoints section is updated to
  acknowledge this.
- `src/daemon/rpc_command_executor.cpp:1319, 2039` — daemon CLI
  display strings ("estimated backlog", "approximated hash rate").
- `src/cryptonote_protocol/cryptonote_protocol_handler.inl:524` —
  sync-progress display.
- `src/wallet/wallet2.cpp:181, 182, 5975, 11548` — wallet defaults
  for `DEFAULT_UNLOCK_TIME`, `RECENT_SPEND_WINDOW`, and two
  `seconds_per_block` consumers. These rewire to the generated
  header; the wallet's own unlock-time and recent-spend windows
  are unaffected because the value is unchanged.
- `src/wallet/wallet_rpc_server.cpp:163` — wallet RPC
  `suggested_confirmations_threshold` math.

Phase 4 reviewer responsibility: confirm by post-rewire grep that
`git grep -nE 'DIFFICULTY_TARGET_V[12]' src/ tests/` returns zero
hits (modulo the deletion-commit's own diff).

### 9.8 RPC-contract preservation

The §9.7 enumeration surfaces one consumer that is part of the
public daemon RPC contract:
`core_rpc_server.cpp:1452 res.block_target = DIFFICULTY_TARGET_V2`.
Wallet callers read the `block_target` field from the daemon's
`get_info` response. **The numeric value of the field is
unchanged** (120 seconds before, 120 seconds after); only the
source of the value moves from a hand-maintained `#define` to the
generated header. No RPC client breakage results from this PR.
This contrasts with the FTL/MTP changes (§9.5 / §9.6), which **do**
change consensus-rule values — but FTL and MTP are not exposed via
RPC, so the daemon's RPC surface is unchanged across the entire
LWMA-1 migration.

**Phase 4 regression test.** A regression test asserts the wire-
contract preservation operationally, not just the value: a wallet
issuing `get_info` against the post-Phase-4 daemon receives a
response whose `block_target` field is **byte-identical** to the
same wallet's response against the pre-Phase-4 daemon
(captured once at PR-open as a fixture, asserted at every CI
run). The byte-identity assertion catches refactors that
preserve the numeric value (`120`) but break the wire encoding
(e.g., a future "change varint encoding to little-endian byte
array" refactor that leaves callers parsing a different number
of bytes). The value-only assertion catches the value drift; the
byte-identity assertion catches the encoding drift. Both are
required to make the RPC-contract-preservation claim auditable.

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

**The LWMA-1 algorithm** is consumed by the daemon's block
validator and miner. It is **not** consumed by the wallet —
wallets do not compute or check difficulty (validators do). The
wallet-V3.2 cutover gate that applies to RandomX v2
(`RANDOMX_V2_RUST.md` §14) does **not** apply to LWMA-1's
algorithm. LWMA-1's algorithm can land before, during, or after
the wallet V3.2 migration without coupling.

**The DAA's target-block-time constant `T`** is, however,
consumed by the wallet for unlock-time and recent-spend-window
arithmetic. Per §9.7's enumeration, `src/wallet/wallet2.cpp:181,
182, 5975, 11548` and `src/wallet/wallet_rpc_server.cpp:163` all
read the inherited `DIFFICULTY_TARGET_V2` symbol. Phase 4 rewires
these five wallet-side sites to consume `SHEKYL_DAA_TARGET_SECONDS`
from the generated header `shekyl/consensus_constants_generated.h`.
The value is unchanged (120 before and after); the rewire is
purely source-textual, the wallet's unlock-time defaults and
recent-spend-window math are byte-identical pre- and
post-rewire, and no wallet-state migration is needed. This means
LWMA-1's *constants* land on the wallet alongside the daemon —
not just the daemon — but the wallet's *observable behavior* is
unchanged.

The `core_rpc_server` exposes difficulty values via JSON-RPC
(`get_info`, `get_block_header_by_*`); those are read-only
consumers of the value `Blockchain::get_difficulty_for_next_block()`
returns. No RPC interface change is needed — the value's type
(`difficulty_type`, a 128-bit unsigned integer) is unchanged across
the migration. The `get_info` `block_target` field exposes
`SHEKYL_DAA_TARGET_SECONDS` (== 120) per §9.7's RPC consumer
enumeration; the §9.8 RPC-contract regression test asserts wire
byte-identity for this field across the cutover.

## 12. Reviewer discipline

Per the pattern established in `RANDOMX_V2_RUST.md` §23, the
"reviewer discipline" framing applies asymmetrically here.

**Status of `24-reviewer-discipline.mdc`.** The rule **does not yet
exist** at `.cursor/rules/`. Its promotion is a V3.1 follow-up
tracked by PR #45's design docs (`RANDOMX_V2_RUST.md` §17). This
PR is **not** the one that lands that rule; it follows the shape
the rule will land with. When the rule does land, no edit to this
section is required — the discipline this section describes is
already aligned with the eventual rule text.

The per-phase discipline:

- **Phase 0 (this PR).** Design doc + plan. Solo-architect review
  in the shape `24-reviewer-discipline.mdc` will land with. The DAA
  is a consensus-critical surface but operates on public consensus
  inputs only; reviewer attention concentrates on §4 parameter
  selection, §5 algorithm correctness against canonical reference,
  and §10 reversion criteria.
- **Phase 1 (implementation).** External reviewer not required;
  the zawy12 canonical reference is the audit-of-record. Self-
  review against the spec is the rule.
- **Phases 3–4 (FFI + C++ cutover).** Self-review; the changes are
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

**This PR does not set or change the workspace MSRV.** The
`shekyl-difficulty` crate inherits whatever workspace MSRV is in
effect at Phase 1 PR time, per the cross-crate consistency rule in
`25-rust-architecture.mdc`. The crate uses no nightly features, no
`unsafe`, and no crate-level `#![allow(...)]`, so any workspace MSRV
that supports the `edition = "2024"` feature set is acceptable.

**If a workspace MSRV is not pinned at Phase 1 time** (e.g., it is
still under discussion in a sibling track), the pin is a
**separate workspace-level PR** per `06-branching.mdc` rule 1 (PR
scope is bounded), not part of the `shekyl-difficulty` scaffold.
Phase 1 of `DAA_LWMA1_PLAN.md` does not block on MSRV pinning;
the crate adopts whatever pin is in effect at merge time and Phase
1's review explicitly verifies the inherited MSRV is compatible
with the crate's feature usage.

This boundary is the same one applied by the RandomX v2 plan
(`RANDOMX_V2_RUST.md` §21): MSRV decisions are workspace-level
and land in their own dedicated PR, not folded into a per-crate
landing.

## 16. Guix reproducible-build impact

`shekyl-difficulty` is a pure-Rust crate with no FFI down into
C/C++ libraries and no platform-specific code. It builds reproducibly
under the existing Guix manifest with no additional dependencies.
No `manifests/manifest.scm` changes required.

The C++ deletion surface (§9) removes ~250 lines of
`boost::multiprecision`-coupled code from the daemon build path.
Boost remains in the build via other consumers; no Boost
disposition follows from this PR.

## 17. Chain-state ownership and the consumer-side actor

The DAA crate exports `lwma1_next` and the FTL/MTP predicates per
§2.7. **It does not own the chain-state read** that produces the
`timestamps[0..=N]` and `cumulative_difficulties[0..=N]` inputs.
That read is the consumer's responsibility. The disposition for
"who is the consumer?" depends on where daemon-side chain state
lives:

**Today and through Phase 4 (this DAA migration's scope).** The
chain-state owner is C++ `cryptonote::Blockchain` (in
`src/cryptonote_core/blockchain.{h,cpp}`), backed by the
`BlockchainDB` LMDB store. `Blockchain` assembles the `N+1`
timestamps and cumulative-difficulty values from its own DB and
calls `shekyl_difficulty_lwma1_next` over FFI per §6. No Rust
state-read crate is involved; the DAA crate is a primitive at the
end of an FFI call, not part of an actor topology on the Rust
side.

**Post-V3.0 (out of this PR's scope).** When daemon-side chain
state migrates to Rust — a workspace-level concern that does not
yet have a design doc — the consumer becomes a stateless Rust
**block-validator actor**. The validator's shape, following the
pattern established by the wallet-side `STAGE_1_*` engine
extractions (DaemonEngine, LedgerEngine, RefreshEngine in
[`docs/design/STAGE_1_PR_*`](./STAGE_1_PR_1_DAEMON_ENGINE.md)),
is:

1. Receives `(block_header, parent_chain_handle)` from its caller.
2. Asks the chain-state-owning crate (let's call it
   `shekyl-chain-state` for the purposes of this paragraph; the
   actual name and shape are out of scope) for the last `N+1`
   timestamps and cumulative-difficulty values.
3. Calls `shekyl_difficulty::lwma1_next` on the assembled inputs.
4. Calls `shekyl_difficulty::is_timestamp_below_ftl` and
   `is_above_mtp` on the incoming timestamp.
5. Returns a validation verdict.

The validator holds no state; the chain-state crate holds the
state; the DAA crate holds the transform. This is the three-way
separation `18-type-placement.mdc` and the actor paradigm exist
to enforce.

**Today's `shekyl-engine-state` is wallet-side, not daemon-side.**
The existing `shekyl-engine-state` crate (per
`docs/design/STAGE_1_PR_2_LEDGER_ENGINE.md` and similar) owns
wallet `TransferDetails`, `RuntimeWalletState`, `StakerPoolState`,
and the persisted wallet-ledger blocks — not daemon-side chain
data. The future daemon-side chain-state crate is a separate
workspace member, not an extension of `shekyl-engine-state`.

**No speculation in this PR.** Per
`70-modular-consensus.mdc`'s rule against speculative
scaffolding, this design doc does not propose a name, shape, or
API for the future daemon-side chain-state crate. The disposition
is: `shekyl-difficulty` exports a transform; when the chain-state
crate exists, it consumes the transform; the transform's signature
(§6.1) is stable across that transition. No changes to
`shekyl-difficulty` are anticipated when the Rust validator lands.

## Cross-references

- [`DAA_LWMA1_PLAN.md`](./DAA_LWMA1_PLAN.md) — phased plan.
- [`RANDOMX_V2_RUST.md`](./RANDOMX_V2_RUST.md) — sibling PoW
  migration; orthogonal at the math level, similar architectural
  shape. §3 spec-as-source-of-truth, §7 isolation invariants, §9
  consensus-constant typing, §13 explicit non-goals, §23 reviewer
  discipline are the patterns this doc mirrors.
- [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md), entry "Full migration of
  remaining `SHEKYL_*` FFI constants to the JSON-authority
  pattern" — the consensus_constants.json pattern this doc adopts
  for the LWMA-1 numeric constants (§4).
- [`docs/audit_trail/2026-05-ffi-constant-drift-audit.md`](../audit_trail/2026-05-ffi-constant-drift-audit.md)
  — audit that motivated the JSON-authority pattern.
- [`STAGE_1_PR_1_DAEMON_ENGINE.md`](./STAGE_1_PR_1_DAEMON_ENGINE.md)
  and sibling `STAGE_1_PR_*` docs — wallet-side engine-extraction
  pattern referenced by §17.
- [`zawy12/difficulty-algorithms#3`](https://github.com/zawy12/difficulty-algorithms/issues/3)
  — canonical LWMA-1 specification and reference.
- `.cursor/rules/00-mission.mdc`, `15-deletion-and-debt.mdc`,
  `16-architectural-inheritance.mdc`, `17-dependency-discipline.mdc`,
  `18-type-placement.mdc`, `19-validation-surface-discipline.mdc`,
  `20-rust-vs-cpp-policy.mdc`, `25-rust-architecture.mdc`,
  `40-ffi-discipline.mdc`, `60-no-monero-legacy.mdc`,
  `70-modular-consensus.mdc`, `75-system-autonomy.mdc`.
