#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# check_oxide_divergence.sh — verify rust/shekyl-oxide/{crypto,shekyl-oxide}
# is byte-equal to Shekyl-Foundation/monero-oxide at the commit pinned in
# rust/shekyl-oxide/UPSTREAM_MONERO_OXIDE_COMMIT.
#
# Layered defense. This script is invoked from:
#   - .githooks/pre-commit (Layer 1, local opt-in)
#   - .github/workflows/oxide-divergence.yml on every PR (Layer 2, observe-only)
#   - the same workflow on push to dev/main (Layer 3)
#   - the same workflow's daily cron (Layer 4 tripwire)
#
# Exit codes are part of the contract. Do not collapse them.
#   0 — vendored tree is byte-equal to the pinned fork commit (OK)
#   1 — divergence detected (file lists/contents differ)
#   2 — infrastructure error (could not fetch fork, malformed metadata,
#       missing tools, or any condition where we cannot perform the check)
#
# CALLERS MUST treat exit 2 differently from exit 1. Exit 2 is "could not
# check"; flagging exit-2 as a divergence (which would block merges on flaky
# clones) defeats the purpose of the layering and trains people to ignore the
# guard. The CI workflow annotates exit 2 as a workflow-level infra failure
# rather than a status-check failure.
#
# COMPARISON SCOPE.  We compare two subtrees and only those subtrees:
#   crypto/         — fork's crypto crates (bulletproofs, fcmps, helioselene, …)
#   shekyl-oxide/   — fork's shekyl-oxide umbrella + wallet/rpc/io/etc.
# Anything outside those two roots in the fork (top-level Cargo.toml, README,
# Code of Conduct, governance docs, tests/verify-chain) is intentionally
# out of scope; it is not vendored. Per the divergence remediation plan, we
# do NOT use a global '*.md' exclusion — that was too broad and would mask
# legitimate divergence on per-crate READMEs (e.g. crypto/fcmps/ec-gadgets/
# documents what that crate does and would be silently unwatched). Two scoped
# diffs preserve the README coverage invariant by construction.
#
# CACHING.  When OXIDE_FORK_CACHE_DIR is set, this script caches the cloned
# fork tree at $OXIDE_FORK_CACHE_DIR/<commit>. The cache contains *only*
# raw `git checkout` output for that commit — never derived computation
# (no pre-computed file manifests, no diff results, no hash sums). Future
# contributors will be tempted to "optimize" by caching the diff result;
# resist. A stale derived cache is far harder to debug than a slow rebuild,
# and the cache hit on raw checkout is already fast.
#
# SELF-TEST.  This script can be invoked under the workflow's self-test job
# in synthetic mode:
#     check_oxide_divergence.sh --self-test-vendored=DIR --self-test-fork=DIR
# Both directories must already contain a `crypto/` and `shekyl-oxide/`.
# Self-test mode skips the metadata read, network fetch, and cache, and
# diffs the two supplied trees directly. The workflow asserts the script
# correctly reports divergence under controlled mutations (deep + shallow
# paths) — that is what breaks the circular trust where a silently-broken
# script would cause Layer 4 to pass forever.

set -uo pipefail

# Defaults; --self-test mode overrides VENDORED_DIR/FORK_REF.
VENDORED_DIR=""
SELF_TEST_FORK=""
ON_SELF_TEST=0

usage() {
  cat <<EOF
Usage:
  $(basename "$0") [--vendored=DIR]
  $(basename "$0") --self-test-vendored=DIR --self-test-fork=DIR

Modes:
  default     resolve UPSTREAM_MONERO_OXIDE_COMMIT, fetch fork, compare to
              \$VENDORED_DIR (or rust/shekyl-oxide of repo root).
  self-test   compare two trees that already exist on disk; skip fetch and
              metadata read. Both directories must contain crypto/ and
              shekyl-oxide/. Used by CI to verify the script itself works.

Environment:
  OXIDE_FORK_CACHE_DIR  cache root for cloned fork trees (no derived data).
  OXIDE_FORK_REPO       override fork URL (default: from metadata file).

Exit codes:
  0  byte-equal              1  divergence              2  infrastructure error
EOF
}

for arg in "$@"; do
  case "$arg" in
    --vendored=*) VENDORED_DIR="${arg#*=}" ;;
    --self-test-vendored=*) VENDORED_DIR="${arg#*=}"; ON_SELF_TEST=1 ;;
    --self-test-fork=*) SELF_TEST_FORK="${arg#*=}"; ON_SELF_TEST=1 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "[oxide-divergence] unknown argument: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

# ---- Helper: bounded retry for transient network failures.

retry_clone() {
  # $1 = repo url, $2 = commit, $3 = dest dir
  local url="$1" commit="$2" dest="$3"
  local attempt
  for attempt in 1 2 3; do
    rm -rf "$dest"
    if git -c advice.detachedHead=false clone --filter=blob:none --no-tags \
         --quiet "$url" "$dest" >/dev/null 2>&1; then
      if git -C "$dest" -c advice.detachedHead=false checkout --quiet "$commit" >/dev/null 2>&1; then
        return 0
      fi
    fi
    if [ "$attempt" -lt 3 ]; then
      sleep $((attempt * 5))
    fi
  done
  return 1
}

# ---- Helper: assert population threshold to catch silently-empty clones.

assert_population() {
  # $1 = directory expected to contain crypto/ and shekyl-oxide/
  local dir="$1"
  if [ ! -d "$dir/crypto" ] || [ ! -d "$dir/shekyl-oxide" ]; then
    echo "[oxide-divergence] [INFRA] $dir is missing crypto/ or shekyl-oxide/" >&2
    return 1
  fi
  local count
  count=$(find "$dir/crypto" "$dir/shekyl-oxide" -type f | wc -l)
  # The fork has well over 100 files in these two roots; below 50 means
  # something stripped the clone (LFS, sparse checkout misconfig, etc.).
  if [ "$count" -lt 50 ]; then
    echo "[oxide-divergence] [INFRA] $dir contains only $count files (expected >= 50)" >&2
    return 1
  fi
  return 0
}

# ---- Helper: do the actual comparison and emit a report.

compare_trees() {
  # $1 = vendored dir, $2 = fork dir
  # Two scoped invocations preserve README coverage and avoid global excludes.
  local v="$1" f="$2"
  local diffs
  diffs=$( {
    diff -rq "$v/crypto" "$f/crypto" 2>&1 || true
    diff -rq "$v/shekyl-oxide" "$f/shekyl-oxide" 2>&1 || true
  } )
  if [ -z "$diffs" ]; then
    return 0
  fi
  printf '%s\n' "$diffs"
  return 1
}

# ============================================================================
# SELF-TEST MODE
# ============================================================================

if [ "$ON_SELF_TEST" = 1 ]; then
  if [ -z "$VENDORED_DIR" ] || [ -z "$SELF_TEST_FORK" ]; then
    echo "[oxide-divergence] [INFRA] self-test requires both --self-test-vendored and --self-test-fork" >&2
    exit 2
  fi
  if ! assert_population "$VENDORED_DIR"; then exit 2; fi
  if ! assert_population "$SELF_TEST_FORK"; then exit 2; fi

  if compare_trees "$VENDORED_DIR" "$SELF_TEST_FORK" >/tmp/oxide-divergence-selftest.diff; then
    echo "[oxide-divergence] [OK] self-test trees byte-equal"
    exit 0
  fi
  cat /tmp/oxide-divergence-selftest.diff
  exit 1
fi

# ============================================================================
# NORMAL MODE
# ============================================================================

if ! command -v git >/dev/null 2>&1; then
  echo "[oxide-divergence] [INFRA] git not on PATH" >&2
  exit 2
fi
if ! command -v diff >/dev/null 2>&1; then
  echo "[oxide-divergence] [INFRA] diff not on PATH" >&2
  exit 2
fi

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ -z "$REPO_ROOT" ] || [ ! -d "$REPO_ROOT" ]; then
  echo "[oxide-divergence] [INFRA] not inside a git repository" >&2
  exit 2
fi
if [ -z "$VENDORED_DIR" ]; then
  VENDORED_DIR="$REPO_ROOT/rust/shekyl-oxide"
fi

META="$VENDORED_DIR/UPSTREAM_MONERO_OXIDE_COMMIT"
if [ ! -f "$META" ]; then
  echo "[oxide-divergence] [INFRA] missing $META" >&2
  exit 2
fi

REPO=$(awk -F= '$1=="upstream_repo"{print $2}' "$META")
BRANCH=$(awk -F= '$1=="upstream_branch"{print $2}' "$META")
COMMIT=$(awk -F= '$1=="upstream_commit"{print $2}' "$META")
if [ -z "$REPO" ] || [ -z "$BRANCH" ] || [ -z "$COMMIT" ]; then
  echo "[oxide-divergence] [INFRA] malformed metadata in $META" >&2
  exit 2
fi
if [ -n "${OXIDE_FORK_REPO:-}" ]; then
  REPO="$OXIDE_FORK_REPO"
fi

# Validate commit is a 40-char hex SHA — guards against typos in the metadata
# masquerading as branch names or arbitrary refs.
if ! printf '%s' "$COMMIT" | grep -Eq '^[0-9a-f]{40}$'; then
  echo "[oxide-divergence] [INFRA] commit '$COMMIT' is not a 40-char hex SHA" >&2
  exit 2
fi

# Resolve cache.
if [ -n "${OXIDE_FORK_CACHE_DIR:-}" ]; then
  FORK_DIR="$OXIDE_FORK_CACHE_DIR/$COMMIT"
  mkdir -p "$OXIDE_FORK_CACHE_DIR"
else
  TMPDIR_CLEANUP=$(mktemp -d -t oxide-fork-XXXXXX)
  FORK_DIR="$TMPDIR_CLEANUP"
  trap 'rm -rf "$TMPDIR_CLEANUP"' EXIT
fi

# Cache hit? Validate it is at the expected commit; otherwise re-clone.
NEEDS_CLONE=1
if [ -d "$FORK_DIR/.git" ]; then
  CACHED_HEAD=$(git -C "$FORK_DIR" rev-parse HEAD 2>/dev/null || echo "")
  if [ "$CACHED_HEAD" = "$COMMIT" ]; then
    NEEDS_CLONE=0
  fi
fi

if [ "$NEEDS_CLONE" = 1 ]; then
  if ! retry_clone "${REPO}.git" "$COMMIT" "$FORK_DIR"; then
    echo "[oxide-divergence] [INFRA] failed to clone $REPO@$COMMIT after 3 attempts" >&2
    exit 2
  fi
fi

if ! assert_population "$VENDORED_DIR"; then exit 2; fi
if ! assert_population "$FORK_DIR"; then exit 2; fi

# ---- The actual comparison.

if compare_trees "$VENDORED_DIR" "$FORK_DIR"; then
  echo "[oxide-divergence] [OK] rust/shekyl-oxide/{crypto,shekyl-oxide} is byte-equal to $REPO@$COMMIT"
  exit 0
fi

cat <<EOF >&2

[oxide-divergence] [DIVERGENCE] vendored tree differs from $REPO@$COMMIT.
Resolve by either re-syncing rust/shekyl-oxide/ (Step 2 of the vendored-oxide
remediation plan) or by promoting the local change upstream and bumping
UPSTREAM_MONERO_OXIDE_COMMIT. See docs/SHEKYL_OXIDE_VENDORING.md.
EOF
exit 1
