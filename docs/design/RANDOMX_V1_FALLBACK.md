# RandomX v1 fallback — contingency design

**Status.** **DRAFT — Round 0 (initial draft, 2026-05-16; status block
revised 2026-05-16 to match §1's late-binding framing).** Companion to
[`RANDOMX_V2_RUST.md`](./RANDOMX_V2_RUST.md). This document is
insurance, not the preferred path. Invocation is **late-binding** per
§1: it may be invoked any time between Phase 0 and the genesis release
in response to a specific finding that makes RandomX v2 the wrong
genesis primitive under `00-mission.mdc` commitment #1. The release-
time algorithm-review gate per
[`RANDOMX_V2_RUST.md`](./RANDOMX_V2_RUST.md) §1.4 is the most common
trigger, but not the only one — Monero's parallel production
deployment or audit may surface a blocker at any earlier point.

**Preferred path.** RandomX v2, Rust verifier, C miner.

**Fallback path.** RandomX v1 from genesis, still with a Rust verifier
and C miner split, still no CryptoNight and no version dispatch.

---

## 1. Trigger Criteria

This fallback is **late-binding**: it may be invoked at any point
between Phase 0 and the genesis release in response to a specific
finding that makes RandomX v2 the wrong genesis primitive under
`00-mission.mdc` commitment #1 (security and quantum resilience are
preconditions). Because Shekyl is non-divergent from upstream
tevador/RandomX (`RANDOMX_V2_RUST.md` §1.1) and Monero is the
parallel production deployer and audit funder (§1.4), the fallback
is an **unpin-and-revert** operation rather than a "stop and restart"
project — switch the submodule SHA to a pre-PR-#317 commit (default
`102f8acf`, already in the existing `external/randomx` submodule) and
toggle the verifier to its v1 spec branch.

Trigger classes:

- **Algorithm-review failure.** The Monero-funded v1→v2 delta audit
  finds a material weakness in CFROUND throttling, the F/E AES mix,
  the program-size change, the prefetch-lookahead change, or any
  resulting ASIC-resistance or randomness-uniformity argument.
- **Production-deployment failure.** Monero's parallel production
  deployment of v2 surfaces an issue — unexpected ASIC viability,
  hashrate-vs-difficulty pathology, regional centralization,
  consensus-affecting bug, or any other production-only finding —
  before Shekyl's release date.
- **Specification failure.** The v2 spec at the pinned commit is
  incomplete enough that a Rust verifier cannot be implemented from
  it without treating the C reference as source of truth.
- **Reference-implementation failure.** The upstream v2 C reference
  has unresolved consensus-affecting ambiguity, lacks enough stable
  test vectors to support independent implementation, or carries a
  bug that the Rust port would otherwise inherit.
- **Performance failure.** Phase 2 interpreter benchmarking
  indicates that the performance target in `RANDOMX_V2_RUST.md` §8
  cannot be met without reintroducing verifier-side JIT or hidden
  state.
- **Inheritance failure.** Monero diverges from `tevador/RandomX`
  (or `tevador/RandomX` itself diverges in a way Monero does not
  follow) such that Shekyl's non-divergent posture no longer maps to
  either a deployed network or a current audit scope, and Shekyl
  cannot bridge that gap before release.

The fallback is **not** triggered by inconvenience, review cost, or
the mere existence of open questions. It is triggered by a specific
finding that meets one of the classes above.

## 2. What Shipping v1 Means

The fallback does **not** restore Monero-era compatibility. It is v1
from Shekyl genesis, not v1 plus historical algorithm dispatch.

Kept from the v2 plan:

- Rust pure-software verifier.
- C/JIT miner-only library.
- No CryptoNight.
- No `RX_BLOCK_VERSION`.
- No PoW `major_version` / `hf_version` dispatch.
- No env-var overrides of consensus constants.
- Derived-first verifier design per `18-type-placement.mdc`.
- `shekyl-pow-randomx` has no C ABI and no module-level runtime-mutable
  state.
- C ABI lives in `shekyl-ffi`.
- Phase 3b deleted-call audit doc.
- Phase 4 deletion of `IPowSchema`, `pow_registry`, and the
  speculative `shekyl-consensus` crate.
- Phase 4 deletion of the RPC-payments feature in full per
  `RANDOMX_V2_RUST.md` §15. The decision is algorithm-independent —
  Shekyl deletes RPC payments whether the genesis algorithm is v2 or
  v1 — so the same deletion checklist applies under fallback.

Changed from the v2 plan:

- Phase 1 pins a RandomX v1 source. Because the
  `Shekyl-Foundation/RandomX` fork tracks upstream `tevador/RandomX`
  and the v2 algorithm landed at upstream PR #317 (commit `bb6ed2c`,
  per `RANDOMX_V2_RUST.md` §1.2), v1 lives at any pre-PR-#317 commit
  on the same fork. The fallback default is **pin
  `Shekyl-Foundation/RandomX` at `102f8acf`** (`bump benchmark
  version to 1.2.1`), which is what the existing
  `shekyl-core/external/randomx` submodule already points at, and is
  reachable from the fork without a separate upstream remote. Picking
  the fork-with-Shekyl-control pin over a direct upstream pin gives
  Shekyl patch authority for backported security fixes without giving
  up upstream compatibility.
  An alternative — pinning `tevador/RandomX` directly at the same
  commit hash — is equivalent in code content and rejected only
  because it gives up Shekyl's pin-and-audit-trail control point.
- `external/randomx-v2` disposition depends on **when** the fallback
  fires:
  - **Pre-Phase-1 trigger.** If fallback is invoked before Phase 1
    lands (e.g., the v1→v2 delta spec ships malformed and Phase 0
    rejects v2 outright), `external/randomx-v2` is never added; the
    existing `external/randomx` submodule stays at its v1-era pin
    (`102f8acf`) and Phase 1 is reduced to "confirm the existing pin
    is the right commit and document it in the design doc."
  - **Post-Phase-1 / late-binding trigger.** If fallback is invoked
    after Phase 1 has already added `external/randomx-v2` (the
    common case per §1's late-binding framing — e.g., Monero's
    audit surfaces a delta-specific blocker while Phase 2 is in
    flight), the v2 submodule is **kept in place** as the pin-and-
    audit-trail control point and a separate fallback commit toggles
    the verifier to its v1 spec branch. The v2 submodule may stay
    on the tree as inert artifact until release-prep deletes it, or
    may be removed in a follow-up cleanup commit if the team
    decides v2 is not coming back; the trigger PR does not couple
    the v2-submodule removal decision to the algorithm switch.
    The build itself reaches v1 through `external/randomx` (already
    at `102f8acf`), so no submodule-add work is required at fallback
    time.
- `BUILD_RANDOMX_V2_MINER_LIB` is renamed to a v1-neutral flag during
  fallback review (proposed: `BUILD_RANDOMX_MINER_LIB`) so the build
  flag does not encode an algorithm version that does not exist in the
  fallback.
- Phase 2 implements the v1 opcode set and v1 cache/dataset derivation.
- Differential harness compares Rust v1 against the v1 C reference at
  the pinned commit.
- `RANDOMX_FLAG_V2` is irrelevant and omitted.
- Any v2-specific security or ASIC-resistance claim is removed from the
  release narrative.

## 3. Why v1 Is a Safe Fallback

RandomX v1 has the longest production track record in this design
space. Four independent 2019 audits cover v1 and ship in the fork's
own `audits/` directory at the pinned v1 commit
(`Shekyl-Foundation/RandomX/audits/`):

- Report-TrailOfBits.pdf
- Report-X41.pdf
- Report-Kudelski.pdf
- Report-Quarkslab.pdf

Additional v1 properties:

- Monero mainnet exposure since 2019-11-30 activation.
- Broad miner and pool ecosystem support.
- Known CPU-friendly design goals and operational behavior.

For Shekyl, v1 fallback is still a genesis-only decision. It does not
require compatibility with historical CryptoNight, old Monero hard fork
versions, or RandomX transition windows. The implementation can still be
cleaner than inherited Monero code because it is v1 **without** Monero's
legacy dispatch scaffolding.

The fallback's review burden is concentrated on the Rust v1 verifier
port and its differential harness against the v1 C reference at the
pinned commit; the algorithm itself does not require a new audit.

## 4. What Shekyl Gives Up by Falling Back

`RANDOMX_V2_RUST.md` §1.3 distills the v1→v2 delta from
`doc/design_v2.md` in the pinned fork. Each of those changes is
something Shekyl forfeits by shipping v1 at genesis. The list is:

1. **CFROUND throttling.** v1 changes the FP rounding mode every
   main-loop iteration; this costs up to ~10% of hashrate on Ryzen
   CPUs because x86 was not designed for that frequency of rounding-
   mode flips. v2 throttles CFROUND to roughly every 16th execution.
   By shipping v1 Shekyl keeps the per-iteration rounding-mode cost
   and the corresponding Ryzen-class hashrate penalty.
2. **AES tweak (F/E mix with AES instead of XOR; `doc/specs.md`
   §4.6.2 step 10).** v2 roughly doubles AES per hash (using a
   previously-idle gap in the dispatch), pulls AES inside the main
   loop so a specialized scratchpad-only AES circuit no longer
   suffices for an ASIC, and improves scratchpad entropy. Shekyl
   gives up the ASIC-resistance refinement and the entropy
   improvement on the v1 fallback path.
3. **Program size 256 → 384 instructions.** Since v1 shipped in
   2019, CPU clocks and IPC have improved much faster than DRAM
   latency. v2's larger programs give the CPU more useful work to
   do while waiting on memory. Falling back to v1 leaves the
   2019-era 256-instruction program size in place and forfeits the
   "more compute per memory stall" property v2 was designed for.
4. **Two-iteration dataset prefetch lookahead (`mp` register,
   defined alongside `ma` in `doc/specs.md`).** Complements the
   program-size increase by hiding more DRAM latency. Shekyl gives
   up the additional latency-hiding on the v1 path.
5. **The ~130–165% "VM+AES work per Joule" efficiency gain on
   Zen 3/4/5** that the v2 design rationale documents (net hashrate
   stays in the 98%–110% band of v1; the gain is in *useful
   computation per watt*, not in raw hashrate). On v1 fallback,
   network-wide computational efficiency-per-watt is the v1-era
   number, not the v2-era one.

What Shekyl does **not** give up by falling back:

- **Cryptographic primitives.** v2 does not change Argon2d (cache
  derivation), Blake2b (finalization), or AES-NI (round
  primitives); the v1 path uses the same primitives at the same
  parameters. There is no audit-surface difference at the primitive
  level.
- **Audit posture for v1.** Four 2019 audits (Trail of Bits, X41,
  Kudelski, Quarkslab) cover v1; Shekyl inherits those byte-for-byte
  via the fork's `audits/` directory at the pinned v1 commit.
- **Mining-ecosystem compatibility.** xmrig, SRBMiner, and the
  pool-software stack all support v1 directly; the ecosystem
  doesn't need to learn a new algorithm.

The fallback narrative therefore concentrates on the four design-v2
changes listed above (and the efficiency-per-watt aggregate they
produce) rather than on imagined cryptographic weaknesses in v1.
If the fallback fires because Monero's delta audit finds a specific
weakness in one of these four changes, this section is updated to
record which v2 improvement turned out to be the wrong trade.

## 5. Re-evaluation Trigger

If Shekyl ships v1 at genesis, v2 (or a later RandomX successor) is not
reconsidered by default. Re-evaluation requires a new design doc and one
of:

- Independent production deployment of the successor algorithm.
- A completed external audit of the algorithm and reference
  implementation.
- A demonstrated weakness in v1 that materially affects Shekyl's
  security or decentralization posture.
- A miner-ecosystem shift that makes v1 harmful to hobbyist mining
  accessibility.

Any post-genesis PoW algorithm change is a hard-fork-level consensus
change and follows the release discipline in `06-branching.mdc`. It is
not a routine dependency update.

## 6. Review Depth Calibration

This fallback doc has two possible review depths:

- **Placeholder depth.** Used only if RandomX v2 review confidence is
  high: named external reviewers, stable v2 spec, known deployers or
  equivalent confidence, and no material unresolved findings. Placeholder
  depth records triggers and recovery outline but does not fully design
  a v1 port before v2 work begins.
- **Full depth.** Required if Shekyl is the sole deployer of v2, if v2
  review has material unresolved questions, or if the v2 spec is still
  moving. Full depth receives the same 4-6 review rounds as
  `RANDOMX_V2_RUST.md` before Phase 1 proceeds.

The review team chooses the depth in Phase 0 after answering
`RANDOMX_V2_RUST.md` §1's deployer and reviewer questions. The middle
position — a shallow fallback document despite low v2 confidence — is
explicitly rejected because it would not help if invoked.

## 7. Reviewer Discipline Under Solo-Architect Reality

Mirrors `RANDOMX_V2_RUST.md` §23. The fallback inherits the same
reviewer-discipline constraints:

- Self-review rounds are permitted on routine sections with the
  written-note + 24-hour sleep-on-it discipline.
- The decision to invoke this fallback (rather than delay genesis to
  pursue v2 further) is **not** waivable to self-review. It requires
  an external reviewer because shipping v1 instead of v2 is a
  genesis-locked consensus decision.
- A v1 algorithm-review gate is not required because v1 already has
  Trail of Bits coverage and mainnet exposure (§3). Reviewer attention
  in fallback mode concentrates on the Rust v1 verifier port itself
  and on the differential harness against the pinned v1 C reference.

The same `docs/design/RANDOMX_V2_REVIEW_LOG.md` records fallback
review activity; entries are tagged `[v1-fallback]` so the audit trail
distinguishes v2 review work from fallback-mode review work.
