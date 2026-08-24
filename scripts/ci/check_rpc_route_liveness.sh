#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# RK — RPC route liveness gate.
#
# `docs/DAEMON_RPC_RUST.md` states the predicate: a method is live iff it has
# a route **and a live consumer**. That rule was written down, was correct,
# and was enforced by nothing — so `/get_blocks.bin` and `/get_hashes.bin`
# survived a Phase-1 audit and two design rounds with no caller at all, and
# were nearly migrated byte-exactly in RK-4 before a census caught them
# (RK-4x). A predicate stated in prose decays against the code; a predicate
# in a script decays with it.
#
# For every path in the Axum registration table, require at least one
# reference somewhere that is not route registration, not the FFI dispatch
# table, not documentation, and not this gate. A route with no such
# reference is served-but-uncalled: either it has a consumer that this
# search cannot see — in which case say so in the allowlist, with the reason
# — or it is dead surface and the tree should stop serving it.
#
# The failing edit is exact: register a route, add no consumer.
#
# Deliberately grep-cheap — no toolchain, no build, so it runs in seconds on
# every PR and cannot be starved out of CI for being slow.

set -euo pipefail

cd "$(dirname "$0")/../.."

SERVER_RS="rust/shekyl-daemon-rpc/src/server.rs"
[[ -f $SERVER_RS ]] || { echo "FAIL: $SERVER_RS not found — has the route table moved?"; exit 1; }

# Paths that are served without an in-tree caller, each with its reason.
# An entry here is a claim someone has to defend in review, which is the
# point: the cost of keeping dead surface should be visible.
declare -A ALLOW=(
  ["/json_rpc"]="the JSON-RPC envelope itself; its methods are the surface, not this path"
  # Found by this gate on its first run, and outside RK-4x's ruling. It is
  # the .bin sibling of /get_transaction_pool_hashes, which IS called; this
  # spelling is not, by anything. Retiring a served route is a surface
  # decision, so it is recorded here rather than taken inside a slice.
  # Remove this entry when it is disposed of either way.
  ["/get_transaction_pool_hashes.bin"]="UNDISPOSED: no caller; awaiting a retire-or-keep ruling (found by this gate, RK-4x)"
)

# One entry per `paths:` line, so a route's aliases are checked as a unit: a
# route is live if ANY of its names has a consumer. Checking each spelling
# separately would report every alias of a live route as dead.
mapfile -t ROUTE_PATHS < <(
  sed -n '/^pub(crate) const ROUTES/,/^];/p' "$SERVER_RS" \
    | grep -oE 'paths: &\[[^]]*\]' \
    | sed -E 's/paths: &\[//; s/\]//; s/"//g; s/, */ /g'
)

if [[ ${#ROUTE_PATHS[@]} -eq 0 ]]; then
  echo "FAIL: extracted no routes from $SERVER_RS."
  echo "      An extraction that comes back empty is a failure, not a skip:"
  echo "      a gate that silently matches nothing is worse than no gate."
  exit 1
fi

echo "rpc route liveness: ${#ROUTE_PATHS[@]} routes from the Axum table"

dead=0
for names in "${ROUTE_PATHS[@]}"; do
  read -ra paths <<<"$names"
  primary=${paths[0]}
  if [[ -n ${ALLOW[$primary]:-} ]]; then
    printf '  allow  %-34s %s\n' "$primary" "${ALLOW[$primary]}"
    continue
  fi
  live=0
  for path in "${paths[@]}"; do
      # Callers name a route with or without its leading slash — the wallet
    # client passes "get_o_indexes.bin" to `bin_call`, which adds it.
    #
    # Comment lines do not count. A doc comment naming a path as an example
    # ("e.g. /get_blocks.bin") would otherwise satisfy this check, which is
    # how the first version of this gate passed its own bite test: the route
    # was re-registered and the gate stayed green because a comment
    # elsewhere mentioned it.
    bare=${path#/}
    hits=$(grep -rE --binary-files=without-match "/?${bare//./\\.}" \
              --include='*.rs' --include='*.cpp' --include='*.h' --include='*.inl' \
              --include='*.py' --include='*.sh' --include='*.json' \
              rust src tests utils scripts 2>/dev/null \
            | grep -v "^rust/shekyl-daemon-rpc/src/server.rs:" \
            | grep -v "^rust/shekyl-daemon-rpc/src/handlers/" \
            | grep -v "^src/rpc/core_rpc_ffi.cpp:" \
            | grep -v "^scripts/ci/check_rpc_route_liveness.sh:" \
            | grep -vE '^[^:]+:[0-9]*:?\s*(//|#|\*|/\*)' \
            | grep -cv '^\s*$' || true)
    if [[ $hits -gt 0 ]]; then live=1; break; fi
  done
  if [[ $live -eq 0 ]]; then
    printf '  DEAD   %-34s no consumer outside route registration\n' "$names"
    dead=$((dead + 1))
  fi
done

if [[ $dead -gt 0 ]]; then
  cat <<EOF

FAIL: $dead route(s) are served with no in-tree consumer.

A method is live iff it has a route AND a live consumer
(docs/DAEMON_RPC_RUST.md). Serving one nobody calls is surface we are
committed to keeping correct, migrating slice by slice, and defending in
the threat model, for nothing.

Either wire the consumer, retire the route, or add it to ALLOW in this
script with the reason it is served without one.
EOF
  exit 1
fi

echo "rpc route liveness: every served route has a consumer"
