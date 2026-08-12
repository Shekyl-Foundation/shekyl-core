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

# This script's contract is that it never reports a wrong number, so a missing
# dependency must announce itself rather than turn every node into NO ANSWER --
# which would read as a fleet-wide outage instead of a missing interpreter.
command -v python3 >/dev/null || { echo "REFUSE: python3 not found; every node would read as NO ANSWER" >&2; exit 2; }
command -v ssh     >/dev/null || { echo "REFUSE: ssh not found" >&2; exit 2; }

SSH_TIMEOUT="${SSH_TIMEOUT:-30}"
counts=()
failed=0

echo "reading at $(date -u +%Y-%m-%dT%H:%M:%SZ)"

while read -r host port label; do
  case "${host:-}" in ''|'#'*) continue ;; esac

  # An inventory is a file, and a file is input. A host beginning with `-` is
  # read by ssh as an OPTION, and a non-numeric port is interpolated into a
  # remote shell command. Neither is a plausible typo that fails loudly, so both
  # are refused here rather than producing a confusing reading later.
  case "$host" in -*) echo "REFUSE: host '$host' starts with '-' and would be read as an ssh option" >&2; exit 2 ;; esac
  case "${port:-}" in ''|*[!0-9]*) echo "REFUSE: port '${port:-}' for '$label' is not numeric" >&2; exit 2 ;; esac
  [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || { echo "REFUSE: port $port for '$label' is out of range" >&2; exit 2; }

  # TWO instruments, one round trip. `get_connections` omits the `connections`
  # field entirely when a node has no peers — verified against a node built to
  # be genuinely isolated, which returns `{"status":"OK","untrusted":false}`.
  # So absence is ambiguous between "truly zero" and "a response shape we do
  # not understand", and the ambiguity is NOT resolved by guessing: `get_info`
  # is fetched alongside and its independent connection counts must corroborate
  # a zero before one is reported. That also survives a change to the
  # serializer's treatment of empty containers, which is an epee detail this
  # script should not depend on.
  out=$(timeout "$SSH_TIMEOUT" ssh -n -o BatchMode=yes -o ConnectTimeout=10 "$host" \
    "curl -s -m 10 http://127.0.0.1:$port/json_rpc -H 'Content-Type: application/json' \
     -d '{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_connections\"}'
     echo '@@SPLIT@@'
     curl -s -m 10 http://127.0.0.1:$port/json_rpc -H 'Content-Type: application/json' \
     -d '{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_info\"}'" 2>/dev/null)

  # An RPC ERROR MUST NOT READ AS ZERO CONNECTIONS. `get_connections` is
  # unavailable in restricted mode (-32601), and a `.get("result", {})` turns
  # that refusal into an empty list — reporting a healthy, well-connected node
  # as isolated. Zero is the most dangerous false value this script can produce,
  # because an isolated node IS the run's headline claim: the instrument would
  # manufacture the result it exists to test. Caught on the production testnet
  # estate, where every node read 0/0/0 and every node was fine.
  parsed=$(printf '%s' "$out" | python3 -c '
import sys, json

# A COUNT IS EMITTED ONLY FROM A PATH THAT AFFIRMATIVELY PARSED A LIST OF
# CONNECTION OBJECTS. Every other shape — an error, a missing field, a field of
# the wrong type, an element that is not an object, an exception nobody
# predicted — produces ERR. The class being closed is not "restricted mode": it
# is ANY unrecognized response collapsing to zero, because zero is this run its
# headline claim and the instrument must not be able to manufacture it.
def corroborated_zero(info_raw):
    """A missing `connections` field is only a zero if a SECOND instrument says so."""
    try:
        i = json.loads(info_raw)
    except Exception:
        return "ERR no-connections-field:get_info-unparseable"
    if not isinstance(i, dict) or not isinstance(i.get("result"), dict):
        return "ERR no-connections-field:get_info-unusable"
    r = i["result"]
    inc, outg = r.get("incoming_connections_count"), r.get("outgoing_connections_count")
    if not isinstance(inc, int) or not isinstance(outg, int):
        return "ERR no-connections-field:get_info-counts-missing"
    if inc == 0 and outg == 0:
        return "OK 0 0 0"
    # The node HAS peers and still omitted the list: an unknown shape, and
    # exactly the case that must never be reported as an isolated node.
    return "ERR no-connections-field:but-get_info-says-in=%d-out=%d" % (inc, outg)

def verdict():
    raw = sys.stdin.read()
    conn_raw, _, info_raw = raw.partition("@@SPLIT@@")
    try:
        d = json.loads(conn_raw)
    except Exception as e:
        return "ERR unparseable:%s" % type(e).__name__
    if not isinstance(d, dict):
        return "ERR non-object-response:%s" % type(d).__name__
    if d.get("error"):
        e = d["error"]
        if isinstance(e, dict):
            return "ERR rpc-error:%s:%s" % (e.get("code"), e.get("message"))
        return "ERR rpc-error:%s" % (e,)
    if "result" not in d:
        return "ERR no-result-field"
    r = d["result"]
    if not isinstance(r, dict):
        return "ERR result-not-an-object:%s" % type(r).__name__
    if "connections" not in r:
        return corroborated_zero(info_raw)
    c = r["connections"]
    if c is None:
        return "ERR connections-null"
    if not isinstance(c, list):
        return "ERR connections-not-a-list:%s" % type(c).__name__
    for x in c:
        if not isinstance(x, dict):
            return "ERR connection-entry-not-an-object:%s" % type(x).__name__
        if "address_type" not in x:
            return "ERR connection-entry-missing-address_type"
    tor_out = sum(1 for x in c if x.get("address_type") == 4 and not x.get("incoming"))
    tor_in  = sum(1 for x in c if x.get("address_type") == 4 and x.get("incoming"))
    pub     = sum(1 for x in c if x.get("address_type") != 4)
    return "OK %d %d %d" % (tor_out, tor_in, pub)

try:
    print(verdict())
except Exception as e:
    # Even an unforeseen failure names itself rather than vanishing into the
    # NO ANSWER bucket, which is what hid the escaped-quote defect in the
    # previous version of this parser.
    print("ERR unexpected:%s:%s" % (type(e).__name__, e))' 2>/dev/null)

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
