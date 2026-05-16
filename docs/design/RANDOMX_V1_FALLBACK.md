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
- `external/randomx-v2` is **not** added in fallback mode; the
  existing `external/randomx` submodule stays at its v1-era pin and
  Phase 1 is reduced to "confirm the existing pin is the right
  commit and document it in the design doc."
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

This section is filled after `RANDOMX_V2_RUST.md` §1 ("Why RandomX v2")
is filled — specifically the three Phase 0 review items there: the
pinned fork commit, the spec section citations, and the list of v2
deployers besides Shekyl. It must name the exact v2 improvements Shekyl
would defer by shipping v1.

Expected categories:

- ASIC-resistance refinements claimed by the v2 opcode mix.
- Cache/dataset construction changes.
- Any JIT or interpreter hardening introduced only in the v2 fork.
- Any ecosystem or mining-performance implication of remaining on v1.

If v2's claimed improvements are vague or not review-supported, this
section records that too. The fallback should not describe an imaginary
loss; it should describe the actual delta established by review.

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
