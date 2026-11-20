#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The dialer knows no connector (Rick, 2026-11-15; DIALER_OUTAGE_EVIDENCE.md
# §3.3): `shekyl-dialer` reaches no Tor crate anywhere in the graph it ships,
# normal and build edges, every target. Whether a connector's path works is
# that connector's own reading, supplied through
# `shekyl_transport_layer::PathSource`; the judge names no connector and holds
# no Tor or clearnet logic. A Tor crate on the dialer's graph is the first
# step back to a judge that reads Tor's own state.
#
# The edit that makes this fail: adding
#   shekyl-tor = { path = "../shekyl-tor" }
# (or any `shekyl-tor*` crate) under `[dependencies]` in
# rust/shekyl-dialer/Cargo.toml, directly or through a crate it adopts.
#
# Dev edges are out of scope: the dialer's tests drive a fake dial with the
# connectors' own reply tables (`shekyl-tor`, `shekyl-clearnet`), so a test
# stamps a failure as the connector does. A test build is not a shipped
# graph.
#
# Shape (46-shell-gate-exits.mdc, 47-gate-subject-assertion.mdc):
#
#   - ONE `cargo tree` call captures the closure, and the verdict is computed
#     here; a cargo failure is a failure, not an empty graph (the reasoning in
#     check_chain_rules_no_store.sh).
#   - Subjects first: the dialer resolves as a workspace member, and the
#     banned set, every workspace package named `shekyl-tor*`, is read from
#     the workspace and must not be empty, so a rename cannot leave a ban
#     that names nothing.
#
# Runs where cargo is installed (rust-audit-test.yml, after `install Rust`).

set -euo pipefail

CRATE=shekyl-dialer

cd "$(dirname "$0")/../../rust"

fail() {
  echo "FATAL: check_dialer_no_tor: $*" >&2
  exit 1
}

# Subject 1: the dialer is a resolvable workspace member.
cargo tree --locked -p "$CRATE" --depth 0 >/dev/null \
  || fail "$CRATE does not resolve as a workspace member — the gate has no subject"

# Subject 2: the banned set, read from the workspace, is not empty.
members="$(cargo metadata --locked --no-deps --format-version 1)" \
  || fail "cargo metadata failed; a failed read is not an empty workspace"
banned="$(python3 -c '
import json, sys
names = sorted(p["name"] for p in json.load(sys.stdin)["packages"])
print("\n".join(n for n in names if n.startswith("shekyl-tor")))
' <<<"$members")"
[ -n "$banned" ] || fail "no workspace package is named shekyl-tor*; the ban names nothing"

closure="$(cargo tree --locked -e normal,build --target all -p "$CRATE" --prefix none)" \
  || fail "cargo tree failed for $CRATE; a failed resolve is not a clean graph"
first_line="${closure%%$'\n'*}"
case "$first_line" in
  "$CRATE v"*) ;;
  *) fail "closure does not start at $CRATE (got: '$first_line')" ;;
esac

status=0
while IFS= read -r pkg; do
  if grep -qE "^${pkg} v[0-9]" <<<"$closure"; then
    echo "FATAL: check_dialer_no_tor: '$pkg' is reachable from $CRATE. Path(s):" >&2
    cargo tree --locked -e normal,build --target all -p "$CRATE" -i "$pkg" >&2 || true
    status=1
  fi
done <<<"$banned"

if [ "$status" -eq 0 ]; then
  count="$(grep -c . <<<"$closure")"
  n="$(grep -c . <<<"$banned")"
  echo "check_dialer_no_tor: $CRATE reaches none of the $n shekyl-tor* crates across $count packages (normal+build)"
fi
exit "$status"
