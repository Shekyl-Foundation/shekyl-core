#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# G1, the transitive half: `shekyl-chain-rules` reaches neither `redb` nor
# `shekyl-chain-store` anywhere in its resolved dependency graph, over normal
# AND dev edges (CHAIN_RULES_CRATE.md §6.5; DAEMON_REDB_STORE.md §7.5.1
# "imports neither"; CONSENSUS_C2_R8_STORE_PLACEMENT.md §9.1 — every rule
# stays unit-testable against a mock view with no database).
#
# The crate's two `compile_fail` doctests see a direct `use`; the coverage gate
# sees the crate's own Cargo.toml. Neither sees a banned package arriving
# through a dependency's dependency — which is the path the adoption
# increments take as they pull in shekyl-difficulty, shekyl-economics,
# shekyl-fcmp — and that path is the only reason this script exists. Today the
# closure is clean by the luck of the graph; the belt is what makes "imports
# neither" a property rather than an observation.
#
# Shape (46-shell-gate-exits.mdc, 47-gate-subject-assertion.mdc):
#
#   - ONE `cargo tree` call captures the closure; the verdict is computed
#     here. The obvious alternative — `cargo tree -p CRATE -i redb` and read a
#     non-zero exit as "absent" — is fail-open: cargo exits 101 for "not in
#     this subtree", for "no such package anywhere", and for a stale lockfile
#     under --locked alike, so a broken resolve would read as a clean graph.
#     Here a cargo failure is a failure.
#   - Subjects first: the crate resolves as a workspace member, and each
#     banned name is a package the workspace actually resolves (`cargo
#     pkgid`). A store-engine rename therefore turns this red with "update
#     BANNED" instead of leaving a ban that names nothing.
#   - `-e normal,dev`: a test-only store dependency is the mock-view inversion
#     R8 banned, in test clothing. Build-dependencies are out of scope: a
#     build script's graph is not linked into the crate.
#
# Runs where cargo is installed (rust-audit-test.yml, after `install Rust`),
# not in docs-gates.yml — that job's own header says it needs no toolchain,
# and relying on the hosted image happening to ship one is the class of
# accident check_test_only_features.py's placement note already names.

#
# Two subjects, one belt. `shekyl-block-template` (TXE-F8, CHAIN_RULES_SLICE_6.md
# §5.3) is the producer's half of the contract the rules crate judges, and it
# is held to the same absence: it computes nothing it could read from a
# store, so every operand arrives in its context (C2-R8 principle 3). A store
# edge there would be the same inversion arriving from the other side.

set -euo pipefail

CRATES=(shekyl-chain-rules shekyl-block-template)
# The same two names check_chain_rules_coverage.py refuses in Cargo.toml.
BANNED=(redb shekyl-chain-store)

cd "$(dirname "$0")/../../rust"

fail() {
  echo "FATAL: check_chain_rules_no_store: $*" >&2
  exit 1
}

# Subject 1: each crate is a resolvable workspace member.
for crate in "${CRATES[@]}"; do
  cargo tree --locked -p "$crate" --depth 0 >/dev/null \
    || fail "$crate does not resolve as a workspace member — the gate has no subject"
done

# Subject 2: every banned name is a package the workspace resolves at all.
for pkg in "${BANNED[@]}"; do
  cargo pkgid --locked "$pkg" >/dev/null 2>&1 \
    || fail "banned package '$pkg' is not in the workspace graph — the ban names nothing; update BANNED"
done

status=0
for crate in "${CRATES[@]}"; do
  # The closure: every package reachable from the crate over normal+dev
  # edges, one `name vX.Y.Z …` per line, **every target**. Host-only would
  # miss a `cfg(windows)` / `target.'cfg(…)'.dependencies` arrival of a
  # banned package while G1 claims the crate never reaches either
  # (Copilot #753).
  TREE=(cargo tree --locked -e normal,dev --target all -p "$crate")
  closure="$("${TREE[@]}" --prefix none)" \
    || fail "cargo tree failed for $crate; a failed resolve is not a clean graph"
  first_line="${closure%%$'\n'*}"
  case "$first_line" in
    "$crate v"*) ;;
    *) fail "closure does not start at $crate (got: '$first_line')" ;;
  esac

  clean=1
  for pkg in "${BANNED[@]}"; do
    if grep -qE "^${pkg} v[0-9]" <<<"$closure"; then
      echo "FATAL: check_chain_rules_no_store: '$pkg' is reachable from $crate (G1). Path(s):" >&2
      "${TREE[@]}" -i "$pkg" >&2 || true
      status=1
      clean=0
    fi
  done

  if [ "$clean" -eq 1 ]; then
    count="$(grep -c . <<<"$closure")"
    echo "check_chain_rules_no_store: $crate reaches none of {${BANNED[*]}} across $count packages (normal+dev)"
  fi
done
exit "$status"
