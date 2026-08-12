#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# Answer one question: CAN EVERY FLEET ONION BE REACHED FROM ANOTHER NODE'S TOR?
#
# Q12-R13. A node that fails to dial a peer once does not dial it again for
# P2P_FAILED_ADDR_FORGET_SECONDS = 3600 (cryptonote_config.h:201). The address
# goes into `m_conn_fails_cache` keyed on `host_str()` — the full onion — and
# `is_addr_recently_failed` then filters it out of white-list selection
# (net_node.inl:1439), the maintainer's candidate loop (:1698) and peerlist
# appending (:2135). Nothing clears it short of a restart.
#
# So one early dial suppresses that edge for an hour, on the exact quantity the
# run measures. Q12-R8's "tor and hidden services up before daemons" is NOT
# enough: the smoke test followed it exactly — three tor processes at
# `Bootstrapped 100%` before any daemon started — and the first dial still timed
# out, because a hidden service being PUBLISHED is not the same as its
# descriptor being FETCHABLE by another client.
#
# ---------------------------------------------------------------------------
# Why this must run with the daemons ALREADY UP, and peerless
#
# A SOCKS client cannot distinguish "no descriptor yet" from "descriptor fine,
# target port closed". Measured against this fleet's own tor, with curl:
#
#   exit 52  onion reachable — TCP established through the circuit, and the
#            p2p listener closed on non-p2p bytes. THE ONLY SUCCESS.
#   exit 97  SOCKS refusal — descriptor missing OR port closed, indistinguishable
#   exit 28  the lookup hung until our own timeout
#
# Only 52 is treated as reachable, and every other code — including ones not
# listed here — is treated as not. The failure modes are not separable from
# outside, so the gate does not pretend to separate them.
#
# A gate run before the daemons exist would therefore read every node as
# unreachable and never pass. The fleet start is consequently four phases:
#
#   1. `skl-tor@*` only.
#   2. daemons started with NO peers configured — their anonymity-zone
#      listeners come up, which is what makes the onions answer.
#   3. THIS GATE, until every onion answers.
#   4. peers written into the configs, `skl-node@*` RESTARTED. The failure
#      cache is in-memory, so the restart starts every node with a clean one
#      and every onion already fetchable.
#
# The restart in (4) is the design, not recovery from a mistake.
# ---------------------------------------------------------------------------
#
# Usage: wait_onions_reachable.sh <socks-host:port> <onion:port> [<onion:port>...]
#
# Exit:  0  every onion answered
#        1  timed out with at least one unreachable — names them; the caller
#           must NOT start the run
#        2  bad invocation

set -uo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <socks-host:port> <onion:port> [<onion:port>...]" >&2
  exit 2
fi

SOCKS="$1"; shift
DEADLINE_SECONDS="${DEADLINE_SECONDS:-1800}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-45}"

command -v curl >/dev/null || { echo "REFUSE: curl not found" >&2; exit 2; }

# 52 = "Empty reply from server": the TCP connection through the onion was
# established and the p2p listener closed on non-p2p bytes. That IS the signal.
reachable() {
  curl -s -m "$PROBE_TIMEOUT" -o /dev/null --socks5-hostname "$SOCKS" "http://$1/"
  [ "$?" -eq 52 ]
}

start="$(date +%s)"
remaining=("$@")

while [ "${#remaining[@]}" -gt 0 ]; do
  still=()
  for target in "${remaining[@]}"; do
    if reachable "$target"; then
      echo "  reachable: $target"
    else
      still+=("$target")
    fi
  done
  remaining=("${still[@]+"${still[@]}"}")
  [ "${#remaining[@]}" -eq 0 ] && break

  elapsed=$(( $(date +%s) - start ))
  if [ "$elapsed" -ge "$DEADLINE_SECONDS" ]; then
    echo "UNREACHABLE after ${elapsed}s — do NOT start the run:" >&2
    printf '  %s\n' "${remaining[@]}" >&2
    echo >&2
    echo "Each of these would cost an hour of connection suppression on first dial." >&2
    echo "Waiting longer does not fix it. A hidden service can fail to publish its" >&2
    echo "descriptor entirely while its own tor reports Bootstrapped 100% — observed," >&2
    echo "and invisible from the node itself. RESTART that instance's tor: a healthy" >&2
    echo "one uploads to every HSDir within seconds (grep 'hsdesc' at Log info), and" >&2
    echo "the onion answers on the next probe. If a restart does not fix it, drop the" >&2
    echo "node from the arm and report the drop — it would otherwise enter the" >&2
    echo "histogram as an isolated node and bias the result toward the run's own" >&2
    echo "headline claim." >&2
    exit 1
  fi
  echo "  ${#remaining[@]} still unreachable at ${elapsed}s; retrying"
  sleep 30
done

echo "OK: all $# onions reachable through $SOCKS"
