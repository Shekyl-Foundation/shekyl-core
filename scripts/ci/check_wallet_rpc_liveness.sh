#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Wallet RPC liveness gate — sibling of check_rpc_route_liveness.sh.
#
# `docs/api/wallet_rpc.yaml`'s `x-shekyl-method-registry` is the status of
# record for the wallet RPC namespace (rule 23: contract entries are
# structured data a checker can read). This gate holds the code to it, in
# both directions:
#
#   SPECIFIED  ⇒ a dispatch arm exists in handlers.rs AND a production
#                consumer names the method outside the server crate.
#   REJECTED / RESERVED ⇒ NO dispatch arm exists. This is the direction
#                that turns "claim stays REJECTED in the YAML" from a note
#                into an invariant: a future PR that adds the handler while
#                the registry still says refused fails here, which is
#                exactly how `--do-not-relay` should have died — it shipped
#                a string about a gate that would never open because
#                nothing checked the prose against the code.
#
# The consumer leg exists because routes-without-callers is the failure
# class the daemon gate (RK) was built for: /get_blocks.bin and
# /get_hashes.bin survived a Phase-1 audit with no caller at all. The
# wallet surface had no equivalent gate until this one.
#
# Consumer search excludes the server crate entirely (its handlers, its
# own tests, its bench helpers): a server test calling its own method is
# self-attestation, not a consumer — including those paths would pass on
# exactly the methods this gate exists to flag (rule 47). The exclusion
# is asserted below: if the excluded surface stops matching anything, the
# exclusion is dead weight and the gate says so rather than silently
# narrowing.
#
# Deliberately grep-cheap — no toolchain, no build — so it runs in seconds
# on every touch of the surface it guards.

set -euo pipefail

cd "$(dirname "$0")/../.."

YAML="docs/api/wallet_rpc.yaml"
HANDLERS="rust/shekyl-wallet-rpc/src/handlers.rs"
[[ -f $YAML ]] || { echo "FAIL: $YAML not found — has the contract moved?"; exit 1; }
[[ -f $HANDLERS ]] || { echo "FAIL: $HANDLERS not found — has the dispatch table moved?"; exit 1; }

# SPECIFIED methods served without an in-tree caller, each with its reason.
# An entry here is a claim someone has to defend in review, which is the
# point: the cost of serving a method no in-tree code calls should be
# visible. (The GUI and mobile wallets are separate repositories; a method
# they alone consume belongs here, named.)
declare -A ALLOW=()

# ── Extract the registry (status of record) ────────────────────────────────
declare -A STATUS=()
while IFS= read -r line; do
  if [[ $line =~ ^[[:space:]]{2}([a-z0-9_]+):[[:space:]]*\{[[:space:]]*status:[[:space:]]*([A-Z]+) ]]; then
    STATUS["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
  fi
done < <(sed -n '/^x-shekyl-method-registry:/,/^[^ ]/p' "$YAML")

if [[ ${#STATUS[@]} -eq 0 ]]; then
  echo "FAIL: extracted no methods from $YAML's x-shekyl-method-registry."
  echo "      An extraction that comes back empty is a failure, not a skip:"
  echo "      a gate that silently matches nothing is worse than no gate."
  exit 1
fi

# ── Extract the dispatch arms ──────────────────────────────────────────────
# The dispatcher is the single `match method {` in handlers.rs, terminated
# by a catch-all arm (`other =>` or `_ =>`). The extraction is bounded and
# fail-closed on both anchors: a missing/duplicated open anchor or a missing
# catch-all fails the gate rather than silently scanning the rest of the
# file, where an unrelated `"..." =>` would be read as a dispatch arm.
open_count=$(grep -c 'match method {' "$HANDLERS" || true)
if [[ $open_count -ne 1 ]]; then
  echo "FAIL: expected exactly one 'match method {' in $HANDLERS, found $open_count."
  echo "      The dispatcher shape moved; fix this extraction to follow it."
  exit 1
fi

if ! DISPATCH=$(awk '
  /match method \{/ { inm = 1 }
  inm {
    print
    if ($0 ~ /^[[:space:]]*(other|_)[[:space:]]*=>/) { seen_end = 1; exit }
  }
  END { if (!seen_end) exit 3 }
' "$HANDLERS"); then
  echo "FAIL: dispatcher in $HANDLERS has no catch-all arm ('other =>' / '_ =>')."
  echo "      The extraction cannot bound the match — failing closed rather"
  echo "      than scanning past the dispatcher."
  exit 1
fi

mapfile -t ARMS < <(
  printf '%s\n' "$DISPATCH" \
    | grep -oE '^\s*"[a-z0-9_]+" =>' \
    | grep -oE '[a-z0-9_]+'
)

if [[ ${#ARMS[@]} -eq 0 ]]; then
  echo "FAIL: extracted no dispatch arms from $HANDLERS."
  echo "      Either the match-shape moved (fix the extraction) or the"
  echo "      dispatcher is empty (fix the server). Empty is a failure."
  exit 1
fi

declare -A HAS_ARM=()
for arm in "${ARMS[@]}"; do HAS_ARM[$arm]=1; done

echo "wallet rpc liveness: ${#STATUS[@]} registry methods, ${#ARMS[@]} dispatch arms"

# ── Rule-47 assertion: the consumer-search exclusion is load-bearing ───────
# The server crate is excluded from the consumer search. If nothing under it
# names a method, the exclusion excludes nothing and this gate's consumer
# leg has silently stopped meaning what it says.
if ! grep -rqE '"(get_balance|get_version)"' rust/shekyl-wallet-rpc/ --include='*.rs' 2>/dev/null; then
  echo "FAIL: the excluded surface (rust/shekyl-wallet-rpc/) no longer names"
  echo "      any method — the consumer-search exclusion is dead. Re-derive"
  echo "      the exclusion list against the current tree."
  exit 1
fi

fail=0

# ── Direction 1: SPECIFIED ⇒ dispatch arm + production consumer ────────────
for method in "${!STATUS[@]}"; do
  [[ ${STATUS[$method]} == SPECIFIED ]] || continue

  if [[ -z ${HAS_ARM[$method]:-} ]]; then
    printf '  DEAD   %-28s SPECIFIED but no dispatch arm in handlers.rs\n' "$method"
    fail=$((fail + 1))
    continue
  fi

  if [[ -n ${ALLOW[$method]:-} ]]; then
    printf '  allow  %-28s %s\n' "$method" "${ALLOW[$method]}"
    continue
  fi

  # A production consumer names the method as a string somewhere that is
  # not the server crate, not a test/bench path, not docs, not a comment,
  # and not this gate.
  hits=$(grep -rE --binary-files=without-match "\"${method}\"" \
            --include='*.rs' --include='*.py' --include='*.sh' \
            rust src utils scripts 2>/dev/null \
          | grep -v "^rust/shekyl-wallet-rpc/" \
          | grep -v "^rust/target/" \
          | grep -vE '(/tests?/|/benches/|bench_support)' \
          | grep -v "^scripts/ci/check_wallet_rpc_liveness.sh:" \
          | grep -vE '^[^:]+:\s*(//|#|\*|/\*)' \
          | grep -cv '^\s*$' || true)
  if [[ $hits -eq 0 ]]; then
    printf '  DEAD   %-28s SPECIFIED, arm present, but no consumer outside the server crate\n' "$method"
    fail=$((fail + 1))
  fi
done

# ── Direction 2: REJECTED / RESERVED ⇒ no dispatch arm ─────────────────────
for method in "${!STATUS[@]}"; do
  case ${STATUS[$method]} in REJECTED | RESERVED) ;; *) continue ;; esac
  if [[ -n ${HAS_ARM[$method]:-} ]]; then
    printf '  LIVE   %-28s %s in the registry but a dispatch arm exists\n' \
      "$method" "${STATUS[$method]}"
    fail=$((fail + 1))
  fi
done

# ── Direction 3: no arm outside the registry ───────────────────────────────
# A dispatch arm whose method has no registry row is a method minted outside
# the contract — the exact silent re-minting rule 23 exists to prevent.
for arm in "${ARMS[@]}"; do
  if [[ -z ${STATUS[$arm]:-} ]]; then
    printf '  UNREG  %-28s dispatch arm with no x-shekyl-method-registry row\n' "$arm"
    fail=$((fail + 1))
  fi
done

if [[ $fail -gt 0 ]]; then
  cat <<EOF

FAIL: $fail wallet RPC method(s) violate the registry.

The x-shekyl-method-registry in docs/api/wallet_rpc.yaml is the status of
record (rule 23). SPECIFIED means an arm and a production consumer exist;
REJECTED/RESERVED means no arm exists, ever, until the registry row itself
changes in a reviewed contract edit.

Either wire the consumer, remove the arm, update the registry row (a
contract change, reviewed as one), or add a SPECIFIED method to ALLOW in
this script with the reason it has no in-tree caller.
EOF
  exit 1
fi

echo "wallet rpc liveness: registry and dispatch agree in both directions"
