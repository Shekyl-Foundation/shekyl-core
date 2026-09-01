#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# The run's readout. For every node in the inventory, report two DIFFERENT
# quantities: ACHIEVED outbound anonymity links, and STORED anonymity
# candidates. Neither substitutes for the other.
#
# `connection_info` already carries `incoming` and `address_type`, and
# `address_type` distinguishes i2p (3) from tor (4)
# (contrib/epee/include/net/enums.h:39-46).
#
# ---------------------------------------------------------------------------
# Why two series (Q12, §11.9)
#
# The outbound TARGET is `P2P_DEFAULT_OUT_PEERS` = 12 and the F-8b floor is
# also 12, so at small `A` a healthy node sits at exactly 12 and the link count
# SATURATES at the value under test: a flat line is consistent both with
# "nothing ever failed" and with "everything failed and recovered between
# samples". Links alone therefore cannot separate healthy churn from the
# suppression failure this run is about.
#
#   links  = is the node above the floor D9's live check will gate on
#   stored = does it have anywhere to RECOVER to
#
# A node at 11 links with a full candidate list is churn. The same node with
# every candidate burned is the failure. Only the pair distinguishes them.
#
# Note what the floor is NOT, today: `set_max_out_peers` refuses a CONFIGURED
# cap below the floor at startup, and nothing checks the ACHIEVED count at
# runtime. That live check is owed (Q12-U2), so this script measures a quantity
# nothing currently gates on.
# ---------------------------------------------------------------------------
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
# Usage: read_anon_histogram.sh [--tsv] <inventory-file>
#
# `--tsv` emits a parsing CONTRACT instead of prose, because a consumer that
# regexes the human format is a defect waiting to happen — one such extractor
# matched the histogram summary rows as well as the per-node rows and reported
# nine values for six nodes. Rows:
#
#   READ <iso8601>
#   NODE <label> <anon_out> <anon_in> <public> <white> <gray>
#   FAIL <label> <reason>
#   END  <nodes-read> <nodes-failed>
#
# `END` is what lets a consumer tell a short reading from a complete one
# without inferring it from the row count it happened to get.
#
# Exit:  0  every node answered
#        1  at least one node did not answer — the reading is INCOMPLETE and
#           must not be treated as a converged distribution
#        2  bad invocation

set -uo pipefail

TSV=0
if [ "${1:-}" = "--tsv" ]; then TSV=1; shift; fi

if [ "$#" -ne 1 ]; then
  echo "usage: $0 [--tsv] <inventory-file>" >&2
  exit 2
fi

INVENTORY="$1"
[ -r "$INVENTORY" ] || { echo "REFUSE: cannot read $INVENTORY" >&2; exit 2; }

# This script's contract is that it never reports a wrong number, so a missing
# dependency must announce itself rather than turn every node into NO ANSWER --
# which would read as a fleet-wide outage instead of a missing interpreter.
command -v python3 >/dev/null || { echo "REFUSE: python3 not found; every node would read as NO ANSWER" >&2; exit 2; }
command -v ssh     >/dev/null || { echo "REFUSE: ssh not found" >&2; exit 2; }
# `timeout` wraps every ssh call below with exactly the same load-bearing
# role as ssh itself, and was the one dependency not preflighted.
command -v timeout >/dev/null || { echo "REFUSE: timeout not found; every node would read as NO ANSWER" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
[ -r "$SCRIPT_DIR/anon_readout_parse.py" ] || {
  echo "REFUSE: anon_readout_parse.py not found next to this script;" >&2
  echo "        every node would read as NO ANSWER" >&2; exit 2; }

SSH_TIMEOUT="${SSH_TIMEOUT:-30}"
counts=()
failed=0

if [ "$TSV" = 1 ]; then
  printf 'READ\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
else
  echo "reading at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
fi

while read -r host port label; do
  case "${host:-}" in ''|'#'*) continue ;; esac

  # An inventory is a file, and a file is input. A host beginning with `-` is
  # read by ssh as an OPTION, and a non-numeric port is interpolated into a
  # remote shell command. Neither is a plausible typo that fails loudly, so both
  # are refused here rather than producing a confusing reading later.
  case "$host" in -*) echo "REFUSE: host '$host' starts with '-' and would be read as an ssh option" >&2; exit 2 ;; esac
  case "${port:-}" in ''|*[!0-9]*) echo "REFUSE: port '${port:-}' for '$label' is not numeric" >&2; exit 2 ;; esac
  [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || { echo "REFUSE: port $port for '$label' is out of range" >&2; exit 2; }

  # TWO readings, one round trip, measuring DIFFERENT quantities — not one
  # quantity twice.
  #
  #   get_connections   ACHIEVED outbound anonymity links. This is what the
  #                     F-8b floor is about: fluff first passage depends on how
  #                     many peers you actually send to.
  #   /get_peer_list    STORED anonymity candidates. This is what RECOVERY is
  #                     about: a node at 11 links with known-good candidates
  #                     recovers; the same node with every candidate burned
  #                     cannot, and the link count alone cannot tell them apart.
  #
  # `/get_peer_list` is a PATH endpoint, not a json_rpc method — asking for it
  # over json_rpc returns -32601. Onion entries carry the address in `host`
  # with `ip`/`port` both 0, so `host` is the only usable key.
  #
  # `public_only: false` is sent EXPLICITLY, and it is load-bearing for what
  # this script measures. It used to be implicit: the C++ bridge skipped
  # deserialization entirely for an empty body, so a bare `curl` left the flag
  # value-initialized to false and got the whole stored peerlist — while the
  # same endpoint given `{}` ran the KV map, applied `OPT(public_only, true)`
  # and answered the PUBLIC subset. One route, two questions, decided by
  # whether the body was empty or `{}`. RK-5a removed that split (an absent
  # body and an absent field now mean the same thing, the declared default),
  # which would have silently narrowed this reading from stored candidates to
  # the publicly shareable ones — the instrument changing what it counts
  # without changing what it says. Asked for outright instead.
  out=$(timeout "$SSH_TIMEOUT" ssh -n -o BatchMode=yes -o ConnectTimeout=10 "$host" \
    "curl -s -m 10 http://127.0.0.1:$port/json_rpc -H 'Content-Type: application/json' \
     -d '{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_connections\"}'
     echo '@@SPLIT@@'
     curl -s -m 10 http://127.0.0.1:$port/get_peer_list \
       -H 'Content-Type: application/json' -d '{\"public_only\":false}'" 2>/dev/null)

  # An RPC ERROR MUST NOT READ AS ZERO CONNECTIONS. `get_connections` is
  # unavailable in restricted mode (-32601), and a `.get("result", {})` turns
  # that refusal into an empty list — reporting a healthy, well-connected node
  # as isolated. Zero is the most dangerous false value this script can produce,
  # because an isolated node IS the run's headline claim: the instrument would
  # manufacture the result it exists to test. Caught on the production testnet
  # estate, where every node read 0/0/0 and every node was fine.
  # The parser is a FILE next to this script, not an inline `python3 -c`.
  # See the header of anon_readout_parse.py for why.
  parsed=$(printf '%s' "$out" | python3 "$SCRIPT_DIR/anon_readout_parse.py" 2>/dev/null)

  case "${parsed:-}" in
    'OK '*) parsed="${parsed#OK }" ;;
    ERR*)
      if [ "$TSV" = 1 ]; then printf 'FAIL\t%s\t%s\n' "$label" "$parsed"
      else printf '  %-24s %-14s %s\n' "$label" "$host" "$parsed"; fi
      failed=$((failed + 1))
      continue
      ;;
    *)
      if [ "$TSV" = 1 ]; then printf 'FAIL\t%s\tNO-ANSWER\n' "$label"
      else printf '  %-24s %-14s NO ANSWER\n' "$label" "$host"; fi
      failed=$((failed + 1))
      continue
      ;;
  esac

  set -- $parsed
  if [ "$TSV" = 1 ]; then
    printf 'NODE\t%s\t%s\t%s\t%s\t%s\t%s\n' "$label" "$1" "$2" "$3" "$4" "$5"
  else
    printf '  %-24s anon_out=%-3s anon_in=%-3s public=%-3s white=%-3s gray=%-3s\n' \
      "$label" "$1" "$2" "$3" "$4" "$5"
  fi
  counts+=("$1")
done < "$INVENTORY"

if [ "$TSV" = 1 ]; then
  # A consumer must be able to tell a short reading from a complete one without
  # inferring it from the row count it happened to receive.
  printf 'END\t%s\t%s\n' "${#counts[@]}" "$failed"
elif [ "${#counts[@]}" -gt 0 ]; then
  echo
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
