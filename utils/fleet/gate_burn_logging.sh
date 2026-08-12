#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# Arm precondition: prove every instance is RECORDING DIAL FAILURES before the
# arm is allowed to conclude anything from their absence.
#
# ---------------------------------------------------------------------------
# Why this gate exists
#
# At the arm's `A` the outbound target and the F-8b floor are the same number
# (12), so the link count saturates and the retry LADDER -- the behaviour the
# 240 s window changed -- exists only in the dial log. "No burns observed" is
# therefore the arm reading "the fix worked". A dead log produces exactly that
# reading, so an instance that is not recording must refuse the arm rather than
# contribute a silent success. This is the same class as an RPC error reading
# as zero connections: the instrument must not be able to manufacture the
# result it exists to test.
#
# What is asserted, and why it is sufficient WITHOUT provoking a failure:
# `Connect failed to` and `Failed to HANDSHAKE with peer` are LOG_INFO_CC ->
# MINFO in src/p2p/net_node.inl, whose translation unit sets
# SHEKYL_DEFAULT_LOG_CATEGORY to "net.p2p" (line 70). The idle path in the same
# file logs MINFO "No available peer in ... list" (line 1650) continuously on a
# healthy node. Same file, same category, same level -- so ANY net.p2p INFO
# line proves the channel a burn would travel is live. A synthetic dead-onion
# canary would prove the same thing while spending a candidate slot and
# perturbing the measurement, so it is not used.
#
# NOTE the log is the launcher's captured STDOUT, not the `log-file=` path in
# the generated config: `--log-file` is inert on this daemon. `tools::on_startup`
# (src/common/util.cpp:793) installs the stderr sink before
# src/daemon/main.cpp:333 can install the file sink, the install-once Rust
# subscriber returns ALREADY_INIT, and mlog.cpp classifies that as expected and
# discards it without printing. Fix pending; until it lands, stdout IS the log.
# ---------------------------------------------------------------------------
#
# Usage: gate_burn_logging.sh <inventory-file> <instances-per-host>
#
#   LOG_GLOB   per-host shell glob for instance logs
#              (default /home/shekyl/fleet/log/node-*.stdout)
#   STALE_S    a log whose mtime is older than this is not recording (default 180)
#
# Exit:  0  every instance on every host is recording
#        1  at least one instance is not -- DO NOT RUN THE ARM
#        2  bad invocation

set -uo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <inventory-file> <instances-per-host>" >&2
  exit 2
fi

INVENTORY="$1"; PER_HOST="$2"
[ -r "$INVENTORY" ] || { echo "REFUSE: cannot read $INVENTORY" >&2; exit 2; }
case "$PER_HOST" in ''|*[!0-9]*) echo "REFUSE: instances-per-host '$PER_HOST' is not a number" >&2; exit 2 ;; esac
[ "$PER_HOST" -ge 1 ] || { echo "REFUSE: instances-per-host must be at least 1" >&2; exit 2; }

LOG_GLOB="${LOG_GLOB:-/home/shekyl/fleet/log/node-*.stdout}"
STALE_S="${STALE_S:-180}"
bad=0
hosts=0

echo "burn-logging gate at $(date -u +%Y-%m-%dT%H:%M:%SZ)  (expect $PER_HOST instance(s)/host)"

while read -r host port label; do
  case "${host:-}" in ''|'#'*) continue ;; esac
  case "$host" in -*) echo "REFUSE: host '$host' would be read as an ssh option" >&2; exit 2 ;; esac
  hosts=$((hosts + 1))

  # One round trip per host. Emits one line per instance:
  #   <path> <age-seconds> <net.p2p-INFO-line-count>
  # and a trailing COUNT line, so a host that matched no logs at all is
  # distinguishable from one that was never asked.
  report=$(timeout 60 ssh -n -o BatchMode=yes -o ConnectTimeout=10 "$host" "
    now=\$(date +%s); n=0
    for f in $LOG_GLOB; do
      [ -e \"\$f\" ] || continue
      n=\$((n+1))
      m=\$(stat -c %Y \"\$f\" 2>/dev/null); [ -n \"\$m\" ] || m=0
      # \`grep -c\` PRINTS 0 and EXITS 1 when nothing matches, so \`|| echo 0\`
      # emits a SECOND 0 and splits this record across two lines -- and it does
      # so only when the count is zero, which is the one case this gate exists
      # to catch. It read as a phantom extra instance with a blank age.
      c=\$(grep -c 'net::p2p' \"\$f\" 2>/dev/null); [ -n \"\$c\" ] || c=0
      echo \"\$f \$((now-m)) \$c\"
    done
    echo \"COUNT \$n\"" 2>/dev/null)

  if [ -z "$report" ]; then
    printf '  %-10s REFUSE: no report (host unreachable or shell failed)\n' "$label"
    bad=$((bad + 1)); continue
  fi

  n=$(printf '%s\n' "$report" | awk '$1=="COUNT"{print $2}')
  if [ "${n:-}" != "$PER_HOST" ]; then
    printf '  %-10s REFUSE: %s instance log(s), expected %s\n' "$label" "${n:-none}" "$PER_HOST"
    bad=$((bad + 1)); continue
  fi

  hostbad=0
  while read -r path age lines; do
    [ "$path" = "COUNT" ] && continue
    inst="${path##*/}"
    # A row this loop cannot read is a REFUSAL, not a default. Treating a
    # malformed record as "stale" or "silent" would give the right verdict for
    # the wrong reason and hide whatever produced it.
    case "${age:-}" in ''|*[!0-9]*)
      printf '  %-10s %-18s REFUSE: unreadable gate record (age=%q lines=%q)\n' \
        "$label" "$inst" "${age:-}" "${lines:-}"
      hostbad=$((hostbad + 1)); continue ;;
    esac
    case "${lines:-}" in ''|*[!0-9]*)
      printf '  %-10s %-18s REFUSE: unreadable net.p2p count (%q)\n' "$label" "$inst" "${lines:-}"
      hostbad=$((hostbad + 1)); continue ;;
    esac
    if [ "$age" -gt "$STALE_S" ]; then
      printf '  %-10s %-18s REFUSE: last write %ss ago -- not recording\n' "$label" "$inst" "$age"
      hostbad=$((hostbad + 1)); continue
    fi
    if [ "$lines" -lt 1 ]; then
      printf '  %-10s %-18s REFUSE: no net.p2p INFO lines -- a burn would not be logged\n' "$label" "$inst"
      hostbad=$((hostbad + 1)); continue
    fi
  done <<EOF
$report
EOF

  if [ "$hostbad" -eq 0 ]; then
    printf '  %-10s ok  %s/%s instance(s) recording\n' "$label" "$PER_HOST" "$PER_HOST"
  else
    bad=$((bad + hostbad))
  fi
done < "$INVENTORY"

echo
if [ "$hosts" -eq 0 ]; then
  echo "REFUSE: inventory contained no hosts; an empty gate passes vacuously" >&2
  exit 1
fi
if [ "$bad" -gt 0 ]; then
  echo "REFUSE: $bad instance(s) are not recording dial failures." >&2
  echo "An arm run now would read their silence as 'no burns occurred', which is" >&2
  echo "the result the run exists to test. Fix the logging, then re-gate." >&2
  exit 1
fi
echo "gate passed: every instance on $hosts host(s) is recording"
