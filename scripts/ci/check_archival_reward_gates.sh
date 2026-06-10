#!/usr/bin/env bash
#
# Archival reward gates — mint + integer arithmetic discipline.
# Invoked from check_consensus_invariants.sh and CI.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

FAIL=0

# No f64 in canonical integer crate (structural; clippy also denies in-crate).
if rg 'f64' rust/shekyl-archival-retention/src/reward_arithmetic.rs >/dev/null 2>&1; then
  echo "FAIL: f64 found in reward_arithmetic.rs" >&2
  FAIL=1
fi

# Mint gate: no live emission vin crediting outputs (provisional bands).
if rg -n 'reward_P|archival.*emission.*mint|mint.*archival.*reward' src/fcmp src/cryptonote_core \
  --glob '*.cpp' --glob '*.h' 2>/dev/null | rg -v 'TODO|FOLLOWUP|comment' >/dev/null; then
  echo "FAIL: possible live archival reward mint path in C++ (grep hit)" >&2
  rg -n 'reward_P|archival.*emission' src/fcmp src/cryptonote_core --glob '*.cpp' --glob '*.h' 2>/dev/null || true
  FAIL=1
fi

exit "$FAIL"
