#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# The run's readout. For every node in the inventory, ask its loopback RPC for
# `get_connections` and report the OUTBOUND ANONYMITY peer count — the quantity
# Q12-D6a exists to measure — plus the distribution over nodes.
#
# No new instrument is needed for this: `connection_info` already carries
# `incoming` and `address_type`, and `address_type` distinguishes i2p (3) from
# tor (4) (contrib/epee/include/net/enums.h:39-46).
#
# ---------------------------------------------------------------------------
# One reading is not a measurement (Q12-R8, Q12-R13)
#
# The density test read 29 outbound at t+0 and 62 at t+240 — a single reading
# would have reported less than half the converged count. Worse, a node that
# failed a dial has that address suppressed for 3600 s
# (P2P_FAILED_ADDR_FORGET_SECONDS), so a reading taken inside that window
# measures the start procedure rather than peer discovery, and a reading taken
# exactly at expiry catches the node mid-recovery.
#
# So: THREE readings, the last two far enough apart to agree. This script takes
# ONE. The caller schedules them, and an arm whose last two readings disagree is
# not reported as a measurement.
# ---------------------------------------------------------------------------
#
# Inventory format, one node per line, '#' comments and blanks ignored:
#
#   <ssh-host> <rpc-port> <label>
#
# Usage: read_anon_histogram.sh <inventory-file>
#
# Exit:  0  every node answered
#        1  at least one node did not answer — the reading is INCOMPLETE and
#           must not be treated as a converged distribution
#        2  bad invocation

set -uo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <inventory-file>" >&2
  exit 2
fi

INVENTORY="$1"
[ -r "$INVENTORY" ] || { echo "REFUSE: cannot read $INVENTORY" >&2; exit 2; }

SSH_TIMEOUT="${SSH_TIMEOUT:-30}"
counts=()
failed=0

echo "reading at $(date -u +%Y-%m-%dT%H:%M:%SZ)"

while read -r host port label; do
  case "${host:-}" in ''|'#'*) continue ;; esac

  out=$(timeout "$SSH_TIMEOUT" ssh -n -o BatchMode=yes -o ConnectTimeout=10 "$host" \
    "curl -s -m 10 http://127.0.0.1:$port/json_rpc -H 'Content-Type: application/json' \
     -d '{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_connections\"}'" 2>/dev/null)

  # An RPC ERROR MUST NOT READ AS ZERO CONNECTIONS. `get_connections` is
  # unavailable in restricted mode (-32601), and a `.get("result", {})` turns
  # that refusal into an empty list — reporting a healthy, well-connected node
  # as isolated. Zero is the most dangerous false value this script can produce,
  # because an isolated node IS the run's headline claim: the instrument would
  # manufacture the result it exists to test. Caught on the production testnet
  # estate, where every node read 0/0/0 and every node was fine.
  parsed=$(printf '%s' "$out" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    print("ERR unparseable-response"); raise SystemExit
if not isinstance(d, dict):
    print("ERR non-object-response"); raise SystemExit
if "error" in d and d["error"]:
    e = d["error"]
    code = e.get("code")
    msg = e.get("message")
    print("ERR rpc-error:%s:%s" % (code, msg)); raise SystemExit
if "result" not in d:
    print("ERR no-result-field"); raise SystemExit
c = d["result"].get("connections")
if c is None:
    # Absent is not empty: an empty pool of connections is reported as [].
    print("ERR no-connections-field"); raise SystemExit
tor_out = sum(1 for x in c if x.get("address_type") == 4 and not x.get("incoming"))
tor_in  = sum(1 for x in c if x.get("address_type") == 4 and x.get("incoming"))
pub     = sum(1 for x in c if x.get("address_type") != 4)
print(f"OK {tor_out} {tor_in} {pub}")' 2>/dev/null)

  case "${parsed:-}" in
    'OK '*) parsed="${parsed#OK }" ;;
    ERR*)
      printf '  %-24s %-14s %s\n' "$label" "$host" "$parsed"
      failed=$((failed + 1))
      continue
      ;;
    *)
      printf '  %-24s %-14s NO ANSWER\n' "$label" "$host"
      failed=$((failed + 1))
      continue
      ;;
  esac

  set -- $parsed
  printf '  %-24s anon_out=%-3s anon_in=%-3s public=%-3s\n' "$label" "$1" "$2" "$3"
  counts+=("$1")
done < "$INVENTORY"

echo
if [ "${#counts[@]}" -gt 0 ]; then
  printf '%s\n' "${counts[@]}" | sort -n | uniq -c | \
    awk '{printf "  anon_out=%-3s %s node(s)\n", $2, $1}'
  printf '%s\n' "${counts[@]}" | awk '{s+=$1} END {printf "\n  total outbound anonymity links: %d across %d nodes\n", s, NR}'
fi

if [ "$failed" -gt 0 ]; then
  echo >&2
  echo "INCOMPLETE: $failed node(s) did not answer. This is not a converged" >&2
  echo "distribution — a silent node is indistinguishable from an isolated one," >&2
  echo "and reporting it as zero would bias the histogram toward the run's own" >&2
  echo "headline claim." >&2
  exit 1
fi
