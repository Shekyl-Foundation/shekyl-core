#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Per `docs/design/RANDOMX_V2_PHASE2H_PLAN.md` §3 Round 2 R2-D4 close
# (lines 2538-2633): **M5 — Mechanical citation validation.** A
# script (lands at `scripts/ci/check_phase2h_citations.sh` per the
# pre-implementation round Pass 2 disposition: "shell script in
# `scripts/ci/` per Phase 2f precedent
# (`scripts/ci/check_randomx_crate_invariants.sh`); `grep -E` plus
# `awk` is sufficient for cite-format parsing, so no `regex`
# workspace dep is needed. The Choice A (Rust binary plus `regex`
# dep) alternative was rejected pre-implementation as over-engineered
# for the single-consumer script surface; reopens if cite-validation
# needs grow beyond shell-tractable parsing").
#
# # What this script catches
#
# Per R2-D4 close + R2-D3 T-A15 mitigation chain, M5 catches
# *substrate-reference fraud* — claims about the project's substrate
# that don't match the substrate. Specifically:
#
#   - Recipe `rationale` field citations that reference non-existent
#     plan-doc files (`docs/design/<file>.md`).
#   - Recipe `rationale` field citations that reference non-existent
#     `external/randomx-v2/src/` source files
#     (`<file>.{c,cpp,h,hpp}:<line>`).
#   - Recipe `rationale` field citations that reference non-existent
#     `rust/shekyl-pow-randomx/src/` source files
#     (`<file>.rs:<line>`).
#   - Recipe `rationale` field citations whose cited line numbers
#     exceed the cited file's actual line count.
#   - Per-category prefix mismatch: a recipe in
#     `spec_silence_anchors.rs` must begin its rationale with
#     `Category 1:`; recipes in `boundary_values.rs` or
#     `dataset_item_extrema.rs` must begin with `Category 3:`;
#     recipes in `coverage_targets.rs` must begin with `Category 2:`
#     (R1-D8 close taxonomy invariant).
#
# # What this script does NOT catch (semantic verification)
#
# Per R2-D3 close: M5 is the *mechanical floor* of the T-A15
# mitigation chain. M5 plus M3 (PR-template reviewer verification of
# cited substrate; the *procedural ceiling*) compose to handle
# typo-level fraud (M5) plus semantic fraud (M3, where a citation
# resolves syntactically but the cited content doesn't say what the
# cite claims).
#
# M5 does NOT verify that:
#
#   - The cited `<file>:<line>` actually contains the symbol /
#     content the citation claims (semantic fraud — M3 covers this).
#   - The cited plan-doc section number (`§3.4`, etc.) exists within
#     the cited plan-doc file (the line-existence check is at the
#     `<file>:<line>` granularity, not the `§<section>` granularity;
#     reopen criterion (i) per R2-D3 close — Mitigation B content-
#     hash anchoring reopens for adoption if semantic fraud surfaces
#     post-genesis).
#   - The cited symbol's *value* (e.g.,
#     `RANDOMX_ARGON_MEMORY = 262144`) matches the actual
#     substrate's symbol value (this is the Phase 2g R5-D2 / Phase
#     2h Pass 3 "substrate-derived constant validation" surface,
#     orthogonal to citation-fraud).
#
# # When this script runs
#
# Per Pass 2 close: shell script in `scripts/ci/` per Phase 2f
# precedent. The CI invocation cadence is **per-PR** (same cadence
# as `check_randomx_crate_invariants.sh`) — runs in the
# `randomx-v2-differential.yml` workflow's `structural-validate`
# job (mechanical extension to that job's `extended crate-invariant
# script` step, landed at C8). Runtime is sub-second on the C4
# starter corpus (8 recipes); scales linearly with corpus size and
# remains sub-second through R1-D1's 50-200-recipe target.
#
# # Per-pattern false-positive surface (anchored at landing)
#
# Each pattern below is anchored to minimize false-positive
# surface. Where a pattern carries a known false-positive class,
# the class is named explicitly with a substrate-anchored
# justification for why the false positive is bounded.
#
# # M3 PR-template discipline (R1-D7 Sub-B at script altitude)
#
# Per the same R1-D7 Sub-B discipline that governs workflow-file
# modifications: modifications to this script are gate-determining
# substrate. The M3 PR-template review pass treats
# `scripts/ci/check_phase2h_citations.sh` changes the same as
# canonical-output changes — every modification cites the change
# class (new pattern class, new false-positive carve-out, new
# substrate scan path) and the substrate evidence justifying it.

set -euo pipefail

# Scan-scope: the four recipe modules. Each scan-target file is a
# Rust source under `rust/shekyl-randomx-differential/src/adversarial/recipes/`
# whose `rationale: "..."` strings carry the citations M5 validates.
RECIPES_DIR="rust/shekyl-randomx-differential/src/adversarial/recipes"

if [[ ! -d "${RECIPES_DIR}" ]]; then
  echo "FATAL: ${RECIPES_DIR} not found" >&2
  exit 1
fi

# Per-category file-to-prefix mapping. The taxonomy invariant from
# R1-D8 close: each recipe's `rationale` opens with `Category N: `
# where N matches the file's category subdivision per the
# `adversarial/recipes/mod.rs` aggregation. Encoded as parallel
# arrays to avoid bash 4 `declare -A` portability concerns (the CI
# runner pin is `ubuntu-latest` per the Phase 2g R1-D12 close which
# carries bash 5+, but the script also runs locally on developer
# machines where bash 3.x is common — parallel arrays work on both).
CATEGORY_FILES=(
  "spec_silence_anchors.rs"
  "coverage_targets.rs"
  "boundary_values.rs"
  "dataset_item_extrema.rs"
)
CATEGORY_PREFIXES=(
  "Category 1:"
  "Category 2:"
  "Category 3:"
  "Category 3:"
)

# Per-extension workspace root for source-file citation resolution.
# Parallel arrays for the same bash 3.x portability reason.
EXT_NAMES=(
  "rs"
  "cpp"
  "c"
  "h"
  "hpp"
)
EXT_ROOTS=(
  "rust/shekyl-pow-randomx/src"
  "external/randomx-v2/src"
  "external/randomx-v2/src"
  "external/randomx-v2/src"
  "external/randomx-v2/src"
)

failures=0

# ----------------------------------------------------------------
# Check 1: per-category prefix discipline (R1-D8 taxonomy).
# ----------------------------------------------------------------
#
# For each recipe-file with a known category prefix, every
# `rationale:` line that opens a string literal must begin with the
# category-correct prefix. Pattern: `rationale:` followed by
# whitespace and a `"` opening; the prefix immediately follows.
#
# The pattern uses `[[:space:]]*` to tolerate the rustfmt-default
# 4-space indent under the `CacheRecipe { ... }` struct-literal
# block. The opening `"` is required to disambiguate from comment
# lines that mention `rationale:` (e.g., the per-recipe `//
# rationale: ...` comments common in the recipe files do not have
# the structural `"` opening, so they don't match).
#
# False-positive surface: a recipe whose `rationale` field is a
# multi-line raw string opened on a line without the prefix would
# bypass this check. The recipe files use the line-continuation
# style (`"foo \"\n bar"` where the `"` opens the first line)
# rather than raw strings, so this bypass is empirically unused
# today; reopens if a future recipe adopts a raw-string rationale.
for i in "${!CATEGORY_FILES[@]}"; do
  file_basename="${CATEGORY_FILES[${i}]}"
  expected_prefix="${CATEGORY_PREFIXES[${i}]}"
  file_path="${RECIPES_DIR}/${file_basename}"
  if [[ ! -f "${file_path}" ]]; then
    echo "FATAL: recipe file ${file_path} not found" >&2
    failures=$((failures + 1))
    continue
  fi
  while IFS= read -r line; do
    # printf '%s\n' (not echo) handles backslashes and leading
    # dashes deterministically across shells. The matched
    # `rationale: "..."` lines may contain backslash-escaped
    # quotes or backslash-continuations; `echo`'s behavior on
    # backslashes varies by shell (bash with/without
    # `posix-defaults`, dash, ksh), where `printf '%s\n'` is
    # POSIX-mandated literal output. PR #78 Round-3 Copilot
    # finding F9 (comment 3307323153).
    content=$(printf '%s\n' "${line}" | sed -E 's/^[[:space:]]*rationale:[[:space:]]*"//')
    case "${content}" in
      "${expected_prefix}"*)
        ;;
      *)
        echo "FATAL: ${file_path}: rationale string does not open with '${expected_prefix}':" >&2
        echo "  ${line}" >&2
        failures=$((failures + 1))
        ;;
    esac
  done < <(grep -E '^[[:space:]]*rationale:[[:space:]]*"' "${file_path}" || true)
done

# ----------------------------------------------------------------
# Check 2: plan-doc citation existence.
# ----------------------------------------------------------------
#
# Plan-doc cite pattern: `<NAME>_PLAN.md` (case-sensitive). The
# uppercase-with-underscores prefix on `_PLAN.md` is the project's
# plan-doc naming convention; matching the literal suffix avoids
# matching arbitrary `.md` references (which would expand the false-
# positive surface to include narrative `.md` references that aren't
# substrate-anchored plan-docs).
#
# Resolution: each match is `<NAME>_PLAN.md` → look up
# `docs/design/<NAME>_PLAN.md`. Missing files fail the gate.
#
# False-positive surface: a plan-doc whose path doesn't follow the
# `docs/design/` convention (e.g., a future `docs/architecture/`
# subfolder) would surface as a false positive. The R2-D4 close's
# reopen criterion (ii) — "If future plan-docs surface a
# structurally distinct cite-validation requirement" — covers the
# carve-out shape if the convention extends.
PLAN_DOC_PATTERN='[A-Z][A-Z0-9_]*_PLAN\.md'
while IFS= read -r line; do
  # Format: <file>:<lineno>:<match content>
  file_path=$(echo "${line}" | cut -d: -f1)
  line_number=$(echo "${line}" | cut -d: -f2)
  match=$(echo "${line}" | cut -d: -f3-)
  # Extract every plan-doc cite from the matched line.
  for plan_doc in $(echo "${match}" | grep -oE "${PLAN_DOC_PATTERN}" | sort -u); do
    resolved="docs/design/${plan_doc}"
    if [[ ! -f "${resolved}" ]]; then
      echo "FATAL: ${file_path}:${line_number}: cited plan-doc not found at ${resolved}:" >&2
      echo "  ${match}" >&2
      failures=$((failures + 1))
    fi
  done
done < <(grep -nE "${PLAN_DOC_PATTERN}" "${RECIPES_DIR}"/*.rs || true)

# ----------------------------------------------------------------
# Check 3: `<file>:<line>` and `<file>:<start>-<end>` source-file
# citation existence + line-number validity.
# ----------------------------------------------------------------
#
# Source-file cite pattern: `<basename>.<ext>:<line>` or
# `<basename>.<ext>:<start>-<end>` where:
#
#   - `<basename>` is alphanumeric-plus-underscore.
#   - `<ext>` is one of `rs`, `c`, `cpp`, `h`, `hpp` (mapped to
#     workspace roots via `EXT_NAMES` / `EXT_ROOTS`).
#   - `<line>` / `<start>` / `<end>` are positive integers.
#
# Resolution: each match is looked up under the extension-specific
# workspace root. Three failure surfaces fail the gate:
#
#   - missing file under the extension's workspace root;
#   - cited line numbers exceeding the file's line count
#     (`end_line > wc -l`);
#   - malformed line numbers: `start < 1` (source files are
#     1-indexed) or `end < start` (reversed range like
#     `foo.rs:10-1`). These would otherwise pass the `end_line
#     > file_lines` check but are author-side typos.
#
# False-positive surface (named carve-outs):
#
#   1. Citations of crate-relative paths (e.g.,
#      `argon2-0.5.3/src/block.rs:51` — a vendored-crate cite) are
#      not resolvable against the workspace's source roots and would
#      false-positive against the basic pattern. To bound this, the
#      pattern's pre-anchor `[^/A-Za-z0-9_.]` carve-out rejects
#      cites whose preceding character is a path component or
#      identifier character — citations carrying a `/` directory
#      prefix or appended to a longer identifier are presumed to be
#      vendored-crate or out-of-tree cites and are skipped (semantic
#      verification covers them via M3).
#
#   2. The `compute_hash` divergence FOLLOWUP's eventual closure may
#      introduce a `rust/shekyl-pow-randomx/src/<file>.rs:<line>`
#      cite whose line shifted between cite-time and substrate
#      edit-time. The cite-stability sub-question (R2-D2 reopen
#      criterion (iii)) reopens M5's parser to rustdoc production-
#      reachability cites if drift surfaces.
#
# The anchor handling uses a leading sentinel character: grep's `-o`
# emits the match including the pre-anchor char (or none if the
# match is at line start), and the parser strips a leading non-
# alphanumeric byte to land at the bare cite.
SOURCE_CITE_PATTERN='(^|[^/A-Za-z0-9_.])([A-Za-z0-9_]+)\.(rs|c|cpp|h|hpp):([0-9]+)(-([0-9]+))?'
while IFS= read -r line; do
  file_path=$(echo "${line}" | cut -d: -f1)
  line_number=$(echo "${line}" | cut -d: -f2)
  content=$(echo "${line}" | cut -d: -f3-)
  # Iterate over every cite on the line.
  while IFS= read -r raw_match; do
    [[ -z "${raw_match}" ]] && continue
    # Strip the leading pre-anchor character (the carve-out
    # sentinel that ensures the cite is not glued to a path or
    # identifier). The pattern's `(^|[^/A-Za-z0-9_.])` group
    # captures either line-start (no character) or one carve-out
    # byte.
    bare="${raw_match}"
    case "${bare}" in
      [A-Za-z0-9_]*)
        ;;
      ?*)
        bare="${bare#?}"
        ;;
    esac
    basename=$(echo "${bare}" | sed -E 's/^([A-Za-z0-9_]+)\..*$/\1/')
    ext=$(echo "${bare}" | sed -E 's/^[A-Za-z0-9_]+\.([a-z]+):.*$/\1/')
    start_line=$(echo "${bare}" | sed -E 's/^[A-Za-z0-9_]+\.[a-z]+:([0-9]+).*$/\1/')
    end_line=$(echo "${bare}" | sed -E 's/^[A-Za-z0-9_]+\.[a-z]+:[0-9]+(-([0-9]+))?.*$/\2/')
    if [[ -z "${end_line}" ]]; then
      end_line="${start_line}"
    fi
    # Reject malformed line-number cites before the file-resolution
    # step. Source-file line numbers are 1-indexed and any single
    # cite or range must satisfy `1 <= start <= end`. A `:0` cite
    # or a reversed range (e.g. `foo.rs:10-1`) would pass the
    # existing `end_line > file_lines` check but is clearly an
    # author-side typo; surfacing it here keeps the M5 gate honest
    # under the reviewer-trust assumption that cites that *resolve*
    # were *intended*.
    if (( start_line < 1 )); then
      echo "FATAL: ${file_path}:${line_number}: cite uses zero/negative start line (1-indexed required):" >&2
      echo "  ${bare}" >&2
      failures=$((failures + 1))
      continue
    fi
    if (( end_line < start_line )); then
      echo "FATAL: ${file_path}:${line_number}: cite range ${start_line}-${end_line} is reversed (end < start):" >&2
      echo "  ${bare}" >&2
      failures=$((failures + 1))
      continue
    fi
    # Resolve the extension to a workspace root via parallel-array
    # lookup. Unknown extensions are skipped (the FILE_ROOT_BY_EXT
    # surface is intentionally narrow; new extensions surface as
    # explicit additions per R1-D7 Sub-B substrate-change discipline).
    root=""
    for j in "${!EXT_NAMES[@]}"; do
      if [[ "${EXT_NAMES[${j}]}" == "${ext}" ]]; then
        root="${EXT_ROOTS[${j}]}"
        break
      fi
    done
    if [[ -z "${root}" ]]; then
      continue
    fi
    resolved="${root}/${basename}.${ext}"
    if [[ ! -f "${resolved}" ]]; then
      echo "FATAL: ${file_path}:${line_number}: cited source not found at ${resolved}:" >&2
      echo "  ${bare}" >&2
      failures=$((failures + 1))
      continue
    fi
    file_lines=$(wc -l < "${resolved}")
    if (( end_line > file_lines )); then
      echo "FATAL: ${file_path}:${line_number}: cited line ${start_line}-${end_line} exceeds ${resolved} line count (${file_lines}):" >&2
      echo "  ${bare}" >&2
      failures=$((failures + 1))
    fi
  done < <(echo "${content}" | grep -oE "${SOURCE_CITE_PATTERN}" || true)
done < <(grep -nE "${SOURCE_CITE_PATTERN}" "${RECIPES_DIR}"/*.rs || true)

if [[ ${failures} -ne 0 ]]; then
  echo "M5 citation-validation: ${failures} failure(s)." >&2
  exit 1
fi

echo "M5 citation-validation clean."
