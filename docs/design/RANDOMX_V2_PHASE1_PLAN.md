# RandomX v2 — Track A Phase 1 plan

**Status.** Pre-implementation. This plan lands on `dev` ahead of the
Phase 1 implementation branch and is the binding scope statement for
the implementation PR.

**Parent plan.** [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) §"Track A
— Phase 1" (lines 263–269) is the binding two-bullet scope; this doc
expands it into a reviewable change list, a target-collision
disposition, and a test plan.

**Base commit.** `dev` at the SHA where the Phase 1 branch is cut.
This plan does not anchor a specific SHA because Phase 1 has zero file
overlap with the in-flight Phase 4 DAA PR (#53) — Phase 1 is gated on
Phase 4 landing only for branch-hygiene reasons, not technical reasons.

**Branch (forthcoming).** `feat/randomx-v2-phase1`, to be cut off
`dev` once implementation begins. The soft sequencing precondition
(PR #53 landed before this branch is cut) has been satisfied: PR #53
merged into `dev` at commit `ef6f6bb66` on 2026-05-18. Per
`06-branching.mdc` rule 2 the branch is short-lived (target ≤5
working days, ≤10 commits); per rule 3 dev is not merged into it
mid-flight.

**Scope envelope.** Single PR. Target ≤250 lines of diff, ≤5 commits.
No Shekyl-side consumer changes: this PR adds the v2 build
infrastructure (`ExternalProject_Add` wiring per §2.3) but no Shekyl
C++ component yet links against the produced library. Phase 2's
cross-check tests are the first consumer, in a later PR.

**Cross-references.**

- **Parent plan.** [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) §"Track
  A — Phase 1" is the two-bullet scope; §"Track A — Phase 3" is where
  the v1→v2 cutover happens and where the deferred wiring decisions
  from this PR are resolved.
- **Architecture rationale.**
  [`RANDOMX_V2_RUST.md`](./RANDOMX_V2_RUST.md) §1.1 ("fork
  non-divergence") and §1.4 ("release-time algorithm-review gate") are
  the rationale for the pinned-fork approach and the deferred
  algorithm-review gate.
- **Fallback path.**
  [`RANDOMX_V1_FALLBACK.md`](./RANDOMX_V1_FALLBACK.md) §1 documents
  why this PR's submodule infrastructure stays in place even if the
  release-time algorithm-review gate fails.
- **Branch rules.**
  [`.cursor/rules/06-branching.mdc`](../../.cursor/rules/06-branching.mdc)
  rules 1–6.
- **Dependency discipline.**
  [`.cursor/rules/17-dependency-discipline.mdc`](../../.cursor/rules/17-dependency-discipline.mdc)
  — the protocol applied during the pre-flight verification in §1
  below.
- **Documentation discipline.**
  [`.cursor/rules/91-documentation-after-plans.mdc`](../../.cursor/rules/91-documentation-after-plans.mdc)
  — §7 enumerates the doc-update tasks that close this Plan.

---

## §1 Pre-flight verification (completed)

Per `17-dependency-discipline.mdc`, four claims this plan relies on
were verified at source before drafting. The verification record below
is the artifact the implementation PR cites verbatim in its
description.

### §1.1 Fork existence and lineage

`Shekyl-Foundation/RandomX` is a fork of `tevador/RandomX`, default
branch `master`. Source: GitHub REST API
`GET /repos/Shekyl-Foundation/RandomX`. The `fork: true`,
`parent: tevador/RandomX`, and `source: tevador/RandomX` fields are
the lineage anchor.

### §1.2 Pin SHA existence and identity

Pin `aaafe71` resolves to full SHA
`aaafe71322df6602c21a5c72937ac284724ae561`, dated 2026-05-10, commit
message "Prepare v2.0.1 release (#329)". Source: GitHub REST API
`GET /repos/Shekyl-Foundation/RandomX/commits/aaafe71`. This is the
v2.0.1 release commit and matches the pin recorded in
`RANDOMX_V2_PLAN.md` §"Track A — Phase 1".

### §1.3 Non-divergence from upstream

`Shekyl-Foundation/RandomX:master` is **identical** to
`tevador/RandomX:master` at the time of verification: `status:
identical`, `ahead_by: 0`, `behind_by: 0`. Source: GitHub REST API
`GET /repos/Shekyl-Foundation/RandomX/compare/tevador:master...master`.
This satisfies the `RANDOMX_V2_RUST.md` §1.1 invariant ("the
Shekyl-Foundation fork carries no consensus-affecting deviation from
upstream"), which is the load-bearing claim for the release-time
algorithm-review gate's "Shekyl inherits the audit via fork
non-divergence" disposition.

### §1.4 V1 fallback pin already reachable

`external/randomx` is on the submodule SHA `102f8acf` (v1.2.1 tag),
which is **identical** to the pre-PR-#317 fallback pin documented in
`RANDOMX_V2_PLAN.md` line 269 and `RANDOMX_V1_FALLBACK.md` §1. No
submodule SHA change is required to maintain the v1 fallback path
during or after this PR.

---

## §2 Engineering decision — CMake target-name collision

### §2.1 The collision

Both `external/randomx/CMakeLists.txt` and the v2 fork's
`external/randomx-v2/CMakeLists.txt` declare:

- `project(RandomX)`
- `set(RANDOMX_INCLUDE ... CACHE STRING "RandomX Include path")`
- `add_library(randomx ${randomx_sources})`

CMake target names and cache variables are **global within a single
configure run**. A naive `add_subdirectory(external/randomx-v2)` after
the existing `add_subdirectory(external/randomx)` produces:

1. A duplicate-target error on `randomx`.
2. A no-op on `RANDOMX_INCLUDE` (the `CACHE STRING` line is a no-op
   on re-set; the first definition wins) — leaving `${RANDOMX_INCLUDE}`
   pointing at the v1 source tree even when v2 is "selected."

### §2.2 Three options surveyed

1. **`ExternalProject_Add` for v2.** Builds v2 out-of-tree, producing
   an `IMPORTED` library target with a Shekyl-specific name
   (`shekyl_randomx_v2`). Avoids the collision entirely. Configure-time
   cost is moderate; full v2 sources do not enter the main CMake parse
   pass.
2. **Conditional `add_subdirectory`.** When `BUILD_RANDOMX_V2_MINER_LIB
   =OFF` (the default), do not enter the v2 subdirectory. When `ON`,
   `add_subdirectory(external/randomx-v2)` — but this still collides
   with v1's `randomx` target because CMake target names are global.
   Not viable while v1 remains.
3. **Patch v2's `CMakeLists.txt`** (rename target). **Prohibited** by
   `10-shekyl-first.mdc` — never contort upstream.

### §2.3 Disposition

**Option 1 (`ExternalProject_Add`).** The
`BUILD_RANDOMX_V2_MINER_LIB` option is declared with default `OFF`;
when `ON`, an `ExternalProject_Add(randomx_v2 …)` block in
`external/CMakeLists.txt` builds the submodule out-of-tree under
`${CMAKE_BINARY_DIR}/external/randomx-v2-build/` and a Shekyl-side
`IMPORTED` target `shekyl_randomx_v2` exposes the resulting static
library and its include directories. No Shekyl C++ consumer links
against `shekyl_randomx_v2` in this PR; Phase 2's cross-check tests
are the first consumer.

**Why this over deferred wiring.** Three reasons make wiring now the
better disposition than reserving the option name as a no-op:

1. **Real artifact for Phase 2.** Phase 2's cross-check tests
   (`rust/shekyl-pow-randomx/` against the canonical v2 implementation)
   benefit from having the v2 C library prebuilt and importable. A
   Phase 1 that delivers only a no-op option forces Phase 2 to either
   rebuild v2 itself or skip the cross-check — both are worse than
   Phase 1 carrying the build-system weight once.
2. **CI catches v2 regressions before they block consensus work.** A
   `BUILD_RANDOMX_V2_MINER_LIB=ON` CI matrix entry exercises the v2
   build on tier-1 platforms (Linux, macOS, MSVC) starting with Phase
   1. Without it, the first v2 build attempt on Shekyl's toolchain
   matrix is Phase 3 — and any platform-specific build issue would
   surface inside a consensus-affecting cutover, which is exactly the
   wrong time.
3. **Phase 3 keeps `ExternalProject_Add` rather than rewriting it.**
   Compile-flag scope isolation, separate target-name pool, and easier
   fork-URL changes make `ExternalProject_Add` the right shape for
   v2's CMake integration regardless of v1's presence. The "churn at
   Phase 3" argument I drafted before walking through the trade-off
   was wrong: Phase 3 likely keeps the Phase 1 wiring and only adds
   `target_link_libraries(... shekyl_randomx_v2)` at the miner
   consumer.

**Forward consistency check.** The parent plan's "default `OFF` for
daemon, `ON` for miner" language is fulfilled by Option 1 (the option
produces a real library when `ON`). Option 2's no-op-when-`ON` would
have been a documentation mismatch.

---

## §3 File-by-file change list

The PR diff is bounded by the following enumeration. Files outside
this list do not change.

### §3.1 `.gitmodules`

Add one block:

```ini
[submodule "external/randomx-v2"]
    path = external/randomx-v2
    url = https://github.com/Shekyl-Foundation/RandomX
```

No `branch =` line. The pin is at SHA `aaafe71`, captured by the
submodule's gitlink, not a branch.

### §3.2 `external/randomx-v2/` (submodule gitlink)

New submodule at SHA `aaafe71322df6602c21a5c72937ac284724ae561`. The
implementation PR adds this via `git submodule add` followed by
`git -C external/randomx-v2 checkout aaafe71`. No files are committed
into the submodule from this PR.

### §3.3 `CMakeLists.txt` (top-level)

Add the option declaration in the option-declaration block, alongside
the existing build-mode toggles. Exact placement is determined in
implementation; the canonical shape is:

```cmake
option(BUILD_RANDOMX_V2_MINER_LIB
    "Build RandomX v2 (Shekyl-Foundation fork) miner library; \
default OFF in Phase 1, wired into miner consumers in Phase 3. \
See docs/design/RANDOMX_V2_PHASE1_PLAN.md." OFF)
```

The option has no `if(BUILD_RANDOMX_V2_MINER_LIB)` consumer in this
PR. The option is declared, defaulted, and documented; that is the
exit state for Phase 1.

### §3.4 `external/CMakeLists.txt`

After the existing `add_subdirectory(randomx EXCLUDE_FROM_ALL)` on
line 80, add an `ExternalProject_Add` block guarded by the option.
Canonical shape (final block determined in implementation; this is the
intent, not a copy-paste):

```cmake
if(BUILD_RANDOMX_V2_MINER_LIB)
    include(ExternalProject)

    set(RANDOMX_V2_SRC "${CMAKE_CURRENT_SOURCE_DIR}/randomx-v2")
    set(RANDOMX_V2_INSTALL "${CMAKE_CURRENT_BINARY_DIR}/randomx-v2-install")

    ExternalProject_Add(randomx_v2_external
        SOURCE_DIR "${RANDOMX_V2_SRC}"
        PREFIX "${CMAKE_CURRENT_BINARY_DIR}/randomx-v2-build"
        INSTALL_DIR "${RANDOMX_V2_INSTALL}"
        CMAKE_ARGS
            -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            -DCMAKE_POSITION_INDEPENDENT_CODE=ON
            -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
            -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
        BUILD_BYPRODUCTS
            "${RANDOMX_V2_INSTALL}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}randomx${CMAKE_STATIC_LIBRARY_SUFFIX}"
        UPDATE_DISCONNECTED TRUE
    )

    add_library(shekyl_randomx_v2 STATIC IMPORTED GLOBAL)
    set_target_properties(shekyl_randomx_v2 PROPERTIES
        IMPORTED_LOCATION
            "${RANDOMX_V2_INSTALL}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}randomx${CMAKE_STATIC_LIBRARY_SUFFIX}"
        INTERFACE_INCLUDE_DIRECTORIES
            "${RANDOMX_V2_INSTALL}/include"
    )
    add_dependencies(shekyl_randomx_v2 randomx_v2_external)

    message(STATUS
        "RandomX v2: building Shekyl-Foundation fork (pin aaafe71, \
v2.0.1) out-of-tree; target shekyl_randomx_v2 is available. No \
Shekyl C++ consumer links it in Phase 1; first consumer is Phase 2 \
cross-check tests.")
endif()
```

**Why these specific knobs.**

- `SOURCE_DIR` pointed at the submodule path (not URL/git fetch);
  this keeps the pin in `.gitmodules`/the gitlink, not in CMake.
- `UPDATE_DISCONNECTED TRUE` prevents `ExternalProject_Add` from
  trying to fetch updates at build time — the pin is whatever the
  submodule's gitlink says.
- `BUILD_BYPRODUCTS` declares the artifact path so Ninja and other
  generators that need-to-know dependencies can plan correctly.
- `CMAKE_POSITION_INDEPENDENT_CODE=ON` matches the existing v1 build
  property (`external/randomx/CMakeLists.txt` line 220).
- Passing the parent's `CMAKE_C_COMPILER` and `CMAKE_CXX_COMPILER`
  through `CMAKE_ARGS` ensures cross-compilation toolchains
  propagate correctly.
- `IMPORTED GLOBAL` lets Phase 2/3 consumers reference
  `shekyl_randomx_v2` from any subdirectory without re-exporting.

**Lines added to `external/CMakeLists.txt`:** ~30–40.

### §3.5 `docs/design/RANDOMX_V2_PLAN.md`

Update the §"Track A — Phase 1" status block (top of doc, around lines
20–60 — verify in implementation) from "not started" to "in progress"
during the implementation PR, and to "complete" in the PR's final
commit. Cross-reference to this plan doc and to the implementation PR
number.

### §3.6 `docs/CHANGELOG.md`

Add an entry under the unreleased section:

> **RandomX v2 — Phase 1: pinned submodule + out-of-tree build
> wiring.** Adds `external/randomx-v2` submodule pinned to
> Shekyl-Foundation RandomX `aaafe71` (v2.0.1 release; identical to
> `tevador:master` per §1.3 of the Phase 1 plan). Adds
> `BUILD_RANDOMX_V2_MINER_LIB` CMake option (default OFF). When ON,
> `ExternalProject_Add` builds the v2 fork out-of-tree and exposes
> the `shekyl_randomx_v2` `IMPORTED` static-library target plus its
> include directories. No Shekyl C++ consumer links the new target
> in this PR; first consumers are Phase 2 cross-check tests against
> the canonical v2 implementation and Phase 3's miner cutover. See
> `docs/design/RANDOMX_V2_PHASE1_PLAN.md` for the full scope, the
> `ExternalProject_Add` configuration rationale, and the
> reversibility plan.

### §3.7 `docs/FOLLOWUPS.md`

No follow-up items open. Phase 1 has no in-PR deferred work; all
follow-up surfaces (Phase 2 crate, Phase 3 cutover, Phase 4 hash-pool,
Phase 5 retirement) are already tracked in `RANDOMX_V2_PLAN.md` as
phases. Adding parallel `FOLLOWUPS.md` entries would duplicate the
plan and is therefore declined.

---

## §4 Test plan

### §4.1 Default-OFF byte-equivalence

`cmake -B build-default && cmake --build build-default --target
daemon` with no flags is **byte-identical** to a build of the same
SHA with the Phase 1 commits reverted (apart from the parent `.git`
metadata for the new submodule, which is not in the artifact tree).
Verification:

```bash
# Off the Phase 1 branch, baseline:
git stash; cmake -B build-baseline; cmake --build build-baseline --target shekyld
sha256sum build-baseline/bin/shekyld

# Re-apply Phase 1:
git stash pop; cmake -B build-phase1; cmake --build build-phase1 --target shekyld
sha256sum build-phase1/bin/shekyld
```

The two SHAs should match. (If the reproducible-build pipeline already
guarantees this, recording the procedure in the PR description is
sufficient; rerunning is optional.)

### §4.2 Option-ON build smoke

`cmake -B build-on -DBUILD_RANDOMX_V2_MINER_LIB=ON` configures
cleanly and emits the `message(STATUS …)` documented in §3.4.
`cmake --build build-on --target randomx_v2_external` builds the v2
submodule out-of-tree successfully and produces
`${CMAKE_BINARY_DIR}/external/randomx-v2-install/lib/librandomx.{a,lib}`
(extension per platform).

`cmake --build build-on --target shekyld` builds the daemon
successfully (the daemon does not consume `shekyl_randomx_v2` in
Phase 1; this verifies the option does not accidentally regress the
daemon build).

The submodule directory exists on disk and contains the v2 source
tree at SHA `aaafe71`.

**Platform coverage in the implementation PR.** At minimum the
build smoke runs on Linux x86_64 with the project's default
toolchain. MSVC and macOS coverage land via the existing CI matrix
once the implementation PR opens. If a platform-specific v2 build
issue surfaces, it is fixed in this PR (not deferred) — that is
exactly the "catch v2 build issues outside a consensus cutover"
benefit §2.3 cited.

### §4.3 Submodule init smoke

A fresh clone of the branch followed by `git submodule update --init
--recursive` populates `external/randomx-v2/` at SHA `aaafe71`. This
verifies the `.gitmodules` URL is reachable and the gitlink resolves.

### §4.4 No new CI workflow

Phase 1 introduces no new invariants beyond what `06-branching.mdc`
and pre-existing CI checks cover. No `consensus-invariants.yml`
equivalent is required for this phase — the structural-isolation CI
patterns described in `RANDOMX_V2_RUST.md` §7.1–§7.2 are introduced
in Phase 2f alongside the Rust verifier crate.

---

## §5 Reversibility

Phase 1 is mechanically reversible. The three commits below (or their
equivalents) fully undo the PR:

```bash
git -C external/randomx-v2 status   # confirm clean
git rm -r --cached external/randomx-v2
rm -rf external/randomx-v2
# Hand-edit .gitmodules to remove the [submodule "external/randomx-v2"] block.
# Hand-edit CMakeLists.txt to remove the BUILD_RANDOMX_V2_MINER_LIB option block.
# Hand-edit external/CMakeLists.txt to remove the if(BUILD_RANDOMX_V2_MINER_LIB) block.
git add -A && git commit -m "Revert: RandomX v2 Phase 1 (submodule + CMake option)"
```

**When reversal is appropriate.** Only if Phase 1 itself is rejected
on grounds unrelated to the v2-vs-v1 algorithm-review gate (e.g., the
fork URL changes, the pin SHA is force-pushed away, or the
Shekyl-Foundation fork is unavailable). Reversal is **not** the
disposition for the algorithm-review gate failing — that path goes
through `RANDOMX_V1_FALLBACK.md` §1, which keeps the submodule
infrastructure and re-pins to `102f8acf`. The infrastructure this PR
adds is fallback-compatible by construction.

---

## §6 Sequencing and dependencies

### §6.1 Hard sequencing constraints

None at the technical level. Phase 1 had zero file overlap with the
DAA Phase 4 PR (#53; consensus subsystem; no shared files). PR #53
has since merged into `dev` at `ef6f6bb66` (2026-05-18), so this
section is now historical.

### §6.2 Soft sequencing recommendation (satisfied)

The soft-wait recommendation was: cut the Phase 1 branch after the
DAA Phase 4 PR (#53) merges, for branch-hygiene reasons:

- Avoids the temptation to merge dev into a long-running Phase 1
  branch (prohibited by `06-branching.mdc` rule 3).
- Keeps the per-branch attention budget on one PR at a time.
- The Phase 1 scope is small enough (≤250 lines, ≤5 commits) that
  a ~1–2 day delay was negligible.

PR #53 merged 2026-05-18; the precondition is satisfied. The
`feat/randomx-v2-phase1` branch can be cut from `dev` whenever
implementation begins.

### §6.3 Phase 2 unblocking

Phase 1's exit state unblocks Phase 2 (`rust/shekyl-pow-randomx/` new
crate). Phase 2 sub-PRs (2a–2f) consume:

- The spec text in `external/randomx-v2/doc/` (delivered by §3.2
  submodule add).
- The v2 canonical C library `shekyl_randomx_v2` as a cross-check
  reference (delivered by §3.4 `ExternalProject_Add` wiring). Phase
  2's spec-vector parity tests link against `shekyl_randomx_v2` to
  compare the Rust verifier's per-hash output against the canonical
  C output byte-for-byte.

Phase 1 → Phase 2 is a hard sequencing constraint on both counts:
Phase 2 cannot reference v2 spec docs or canonical-implementation
output that don't yet exist on disk.

### §6.4 Phase 3 unblocking

Phase 1's `ExternalProject_Add` wiring is consumed by Phase 3. Phase
3 removes v1 (`external/randomx` submodule, `external/CMakeLists.txt`
line 80's `add_subdirectory(randomx ...)`, and `src/crypto/pow_randomx.cpp`'s
v1 link), then wires the miner consumer to link
`shekyl_randomx_v2`. The `ExternalProject_Add` block introduced by
this PR is expected to **stay** through Phase 3 (and likely
permanently) per §2.3's "Phase 3 keeps it" rationale. If Phase 3's
design review surfaces a reason to migrate to `add_subdirectory(randomx-v2)`
after v1 is gone, that migration is a Phase 3 disposition, not a
Phase 1 disposition.

---

## §7 Documentation tasks (closes the Plan per `91-documentation-after-plans.mdc`)

The implementation PR's final commit performs these updates:

1. **`docs/design/RANDOMX_V2_PLAN.md`** — flip the §"Track A — Phase
   1" status from `[ ]` (not started) to `[x]` (complete) and add a
   cross-reference to this plan doc and to the PR number.
2. **`docs/CHANGELOG.md`** — entry per §3.6 above.
3. **`docs/FOLLOWUPS.md`** — no entry (per §3.7 above; phases are
   already tracked in `RANDOMX_V2_PLAN.md`).
4. **This document (`RANDOMX_V2_PHASE1_PLAN.md`)** — no in-PR
   amendment unless drift is found during implementation, in which
   case an "Implementation amendments" block is appended (mirroring
   the convention in `DAA_LWMA1.md` and `DAA_LWMA1_PHASE4_PREFLIGHT.md`
   §20).

No README updates are required; the Shekyl-core README does not
enumerate per-phase status.

---

## §8 Reviewer-map

| Concern | Reviewer focus | Section to inspect |
| --- | --- | --- |
| Pin SHA matches the parent plan | `aaafe71`'s commit message and date confirm it is v2.0.1 | §1.2, §3.1, §3.2 |
| Fork non-divergence claim | `compare/tevador:master...master` is `identical` at pin time | §1.3 |
| V1 fallback still reachable | `external/randomx` SHA `102f8acf` unchanged by this PR | §1.4, §3 (no v1 edits) |
| Target-name collision disposition | `ExternalProject_Add` out-of-tree pattern; no `add_subdirectory(randomx-v2)` lands | §2.1, §2.2, §2.3, §3.4 |
| `ExternalProject_Add` knobs | `UPDATE_DISCONNECTED`, `BUILD_BYPRODUCTS`, PIC, compiler propagation | §3.4 ("Why these specific knobs") |
| Default-OFF byte-equivalence | Option block fully `if(BUILD_RANDOMX_V2_MINER_LIB)`-guarded; no daemon-side reference | §3.3, §3.4, §4.1 |
| Option-ON build actually works | `librandomx.{a,lib}` produced at the documented install path | §4.2 |
| Scope envelope | ≤250 lines, ≤5 commits, single PR | §3 (whole), top-of-doc |
| Reversibility | The three-step undo sequence is mechanical | §5 |
| Documentation discipline | §7 enumerates the closing edits | §7 |
| Sequencing vs PR #53 | Soft constraint; no shared files | §6.1, §6.2 |
| Phase 2 unblocked correctly | `shekyl_randomx_v2` available for Phase 2 cross-check tests | §6.3 |

---

## §9 Out of scope (explicitly)

The following items belong to later phases and **must not** be added
to the Phase 1 PR:

1. Any Rust crate addition (Phase 2). `rust/shekyl-pow-randomx/` is
   a Phase 2 deliverable.
2. Any Shekyl C++ consumer of `shekyl_randomx_v2` (Phase 2 cross-check
   tests are the first consumer; Phase 3 wires the miner).
3. Any `add_subdirectory(external/randomx-v2)` block. This PR uses
   `ExternalProject_Add` exclusively per §2.3.
4. Any change to `external/randomx` submodule SHA (orthogonal; the
   v1 pin stays at `102f8acf`).
5. Any change to `src/crypto/pow_randomx.cpp` or `src/crypto/CMakeLists.txt`
   (Phase 3 — v1→v2 cutover).
6. Any hash-pool scaffolding (Phase 4).
7. Any v1 retirement / submodule removal (Phase 5).
8. Any release-checklist edits beyond the parent plan's existing
   entries (the release-time algorithm-review gate lives in the
   release checklist already, per parent plan §"Release-time
   algorithm-review gate").

"While we're here" sweeps are explicitly disallowed per
`15-deletion-and-debt.mdc`. Items spotted outside §3's file list go
in `docs/FOLLOWUPS.md` and stay out of the PR.
