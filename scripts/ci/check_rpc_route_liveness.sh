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
)

# `assemble` registers every path the listener serves, one `.route` per
# path. The argument is a string literal or a `&str` constant the tree
# defines once. An empty extraction, or a constant that does not resolve
# to one value, fails closed (rule 47): a gate that matches nothing is
# worse than no gate.
mapfile -t ROUTE_EXPRS < <(
  sed -n '/^fn assemble/,/^}/p' "$SERVER_RS" \
    | grep -oE '\.route\([^,]+' \
    | sed -E 's/^\.route\(//'
)

resolve_route() {
  local expr="$1"
  if [[ $expr == \"*\" ]]; then
    local literal="${expr#\"}"
    literal="${literal%\"}"
    printf '%s\n' "$literal"
    return 0
  fi
  local ident="${expr##*::}"
  if [[ ! $ident =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    echo "FAIL: route expression '$expr' is not a string and not a path constant" >&2
    return 1
  fi
  local matches
  matches=$(grep -R --include='*.rs' -h -E \
    "const[[:space:]]+${ident}:[[:space:]]*&str[[:space:]]*=[[:space:]]*\"[^\"]+\"" \
    rust || true)
  local values
  values=$(printf '%s\n' "$matches" | sed -nE 's/.*"([^"]+)".*/\1/p' | sort -u)
  local count
  count=$(printf '%s\n' "$values" | grep -c . || true)
  if [[ $count -ne 1 ]]; then
    echo "FAIL: route constant ${ident} from '$expr' resolved to ${count} values" >&2
    printf '%s\n' "$matches" >&2
    return 1
  fi
  printf '%s\n' "$values"
}

if [[ ${#ROUTE_EXPRS[@]} -eq 0 ]]; then
  echo "FAIL: extracted no routes from $SERVER_RS."
  echo "      An extraction that comes back empty is a failure, not a skip:"
  echo "      a gate that silently matches nothing is worse than no gate."
  exit 1
fi

ROUTE_PATHS=()
for expr in "${ROUTE_EXPRS[@]}"; do
  path=$(resolve_route "$expr") || exit 1
  ROUTE_PATHS+=("$path")
done

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
