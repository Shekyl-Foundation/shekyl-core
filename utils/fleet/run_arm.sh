#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# Stand up one Q12-D6a arm across a fleet, in the order Q12-R8 and
# `wait_onions_reachable.sh` require, and refuse to proceed past a phase that
# did not actually complete.
#
# This exists because the A = 60 arm was first stood up by hand, and three of
# the findings below were discovered by walking into them. A hand-run arm whose
# steps live only in a terminal is the same defect as a constant whose
# measurement nobody can re-run.
#
# ---------------------------------------------------------------------------
# The phase order is load-bearing, not stylistic
#
#   1. tor ONLY, every instance, and collect the onions.
#   2. daemons with NO peers. Their anonymity listeners are what make the
#      onions ANSWER — a SOCKS probe cannot tell "no descriptor yet" from
#      "descriptor fine, port closed", so a gate run before this never passes.
#   3. the reachability gate, until every onion answers.
#   4. peers written in, daemons RESTARTED. The failure cache is in-memory, so
#      the restart begins with a clean one and every onion already fetchable.
#
# Starting daemons before their dial targets exist suppresses the achieved
# peer count for an hour (Q12-R13) — which presents as "the graph did not
# form", the run's headline finding, from a harness artifact.
#
# ---------------------------------------------------------------------------
# Three findings this script encodes, all measured on the 2026-08-14 A = 60 run
#
# STARTUP PEAK IS ~2x STEADY STATE. A fleet instance settles at ~274 MB
# `RssAnon`, but the kernel killed one at **520 MB** during genesis
# processing. Sizing a host on steady state and starting every instance at
# once OOMs it: exactly one daemon died on each 8 GB host at 15 simultaneous
# starts, and none died at 11. Instances are therefore started with
# `START_STAGGER` seconds between them, so the peaks do not coincide. A host
# that loses an instance silently reduces `A`, which is the independent
# variable.
#
# THE TOR EXPERT BUNDLE SHIPS ITS OWN LIBRARIES. `tor` sits beside
# `libevent-2.1.so.7`, `libssl.so.3` and `libcrypto.so.3` in the bundle, and
# will not start without `LD_LIBRARY_PATH` pointing at its own directory. The
# bundle also lives at two different paths across this estate.
#
# `install -d -o user -g user a/b/c` OWNS ONLY `c`. The parent directories are
# created as root, so a later unprivileged `rm -rf` on the tree fails partway.
# Directories are created here as the running user instead.
# ---------------------------------------------------------------------------
#
# Usage: run_arm.sh <spec-file> <phase>
#
#   <spec-file>  one line per host:  <ssh-host> <anon-count> <anon-start> \
#                                    <clearnet-count> <clearnet-start>
#   <phase>      configs | tor | onions | daemons | gate | peers | status
#
# Exit:  0  phase completed and was verified
#        1  phase ran but verification failed — the caller must NOT continue
#        2  bad invocation

set -uo pipefail

FLEET_ROOT="${FLEET_ROOT:-/home/shekyl/fleet}"
BIN="${BIN:-/home/shekyl/shekyld-fleet}"
PORT_BASE="${PORT_BASE:-21000}"
VPORT="${VPORT:-13021}"
START_STAGGER="${START_STAGGER:-6}"

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <spec-file> <phase>" >&2
  exit 2
fi
SPEC="$1"; PHASE="$2"
[ -r "$SPEC" ] || { echo "REFUSE: cannot read $SPEC" >&2; exit 2; }

case "$PHASE" in
  configs|tor|onions|daemons|gate|peers|status) ;;
  *) echo "REFUSE: unknown phase '$PHASE'" >&2; exit 2 ;;
esac

# A spec line that does not parse would silently contribute zero instances and
# shrink `A` without saying so.
while read -r host an as cn cs; do
  case "${host:-}" in ''|'#'*) continue ;; esac
  for v in "$an" "$as" "$cn" "$cs"; do
    case "$v" in ''|*[!0-9]*)
      echo "REFUSE: '$host' has a non-numeric field ('$v')" >&2; exit 2 ;;
    esac
  done
done < "$SPEC"

remote() { timeout 300 ssh -n -o BatchMode=yes "$1" "$2"; }

# Resolved on the host, not assumed: the bundle is under /home/shekyl on some
# hosts and /opt/shekyl on others.
TOR_LOOKUP='TOR=$(ls -d /home/shekyl/tor-expert-bundle-*/tor/tor /opt/shekyl/tor-expert-bundle-*/tor/tor 2>/dev/null | head -1); LIBD=$(dirname "$TOR")'

fail=0

while read -r host an as cn cs; do
  case "${host:-}" in ''|'#'*) continue ;; esac
  printf '%-26s ' "$host"

  case "$PHASE" in

  configs)
    out=$(remote "$host" "
      mkdir -p $FLEET_ROOT/etc $FLEET_ROOT/log $FLEET_ROOT/data $FLEET_ROOT/tor
      export DATA_ROOT=$FLEET_ROOT/data TOR_ROOT=$FLEET_ROOT/tor LOG_ROOT=$FLEET_ROOT/log PORT_BASE=$PORT_BASE
      $FLEET_ROOT/gen_host_configs.sh $FLEET_ROOT/etc anon $an $as >/dev/null 2>&1 || exit 1
      if [ $cn -gt 0 ]; then
        $FLEET_ROOT/gen_host_configs.sh $FLEET_ROOT/etc clearnet $cn $cs >/dev/null 2>&1 || exit 1
      fi
      printf 'confs=%s torrcs=%s' \"\$(ls $FLEET_ROOT/etc/node-*.conf 2>/dev/null | wc -l)\" \\
                                  \"\$(ls $FLEET_ROOT/etc/tor-*.torrc 2>/dev/null | wc -l)\"")
    want=$((an + cn))
    echo "$out"
    case "$out" in *"confs=$want "*"torrcs=$an"*) ;; *) echo "  ^ expected confs=$want torrcs=$an" >&2; fail=1 ;; esac
    ;;

  tor)
    out=$(remote "$host" "
      $TOR_LOOKUP
      [ -x \"\$TOR\" ] || { echo 'NO-TOR-BINARY'; exit 1; }
      n=0
      for rc in $FLEET_ROOT/etc/tor-*.torrc; do
        [ -e \"\$rc\" ] || continue
        i=\$(basename \"\$rc\" .torrc); i=\${i#tor-}
        mkdir -p $FLEET_ROOT/tor/\$i && chmod 700 $FLEET_ROOT/tor/\$i
        LD_LIBRARY_PATH=\"\$LIBD\" nohup setsid \"\$TOR\" -f \"\$rc\" \\
          >$FLEET_ROOT/log/tor-\$i.out 2>&1 </dev/null &
        n=\$((n+1))
      done
      sleep 5
      printf 'launched=%s' \"\$n\"")
    echo "$out"
    case "$out" in *"launched=$an"*) ;; *) fail=1 ;; esac
    ;;

  onions)
    # Emitted as <ssh-host>\t<index>\t<onion> into $ONION_OUT for the caller.
    out=$(remote "$host" "
      for w in \$(seq 1 20); do
        c=\$(ls $FLEET_ROOT/tor/*/hs/hostname 2>/dev/null | wc -l)
        [ \"\$c\" -ge $an ] && break
        sleep 3
      done
      for f in $FLEET_ROOT/tor/*/hs/hostname; do
        [ -e \"\$f\" ] || continue
        i=\$(basename \$(dirname \$(dirname \"\$f\")))
        echo \"\$i \$(cat \"\$f\")\"
      done")
    n=$(printf '%s\n' "$out" | grep -c . || true)
    echo "onions=$n"
    printf '%s\n' "$out" | while read -r i onion; do
      [ -n "${onion:-}" ] && echo "$host	$i	$onion" >> "${ONION_OUT:-/dev/null}"
    done
    [ "$n" -eq "$an" ] || fail=1
    ;;

  daemons)
    # Phase 2: NO add-peer lines. `anonymous-inbound` is appended here because
    # it needs the onion, which did not exist when the config was generated.
    out=$(remote "$host" "
      for rc in $FLEET_ROOT/etc/tor-*.torrc; do
        [ -e \"\$rc\" ] || continue
        i=\$(basename \"\$rc\" .torrc); i=\${i#tor-}
        hn=$FLEET_ROOT/tor/\$i/hs/hostname
        [ -e \"\$hn\" ] || continue
        anonin=\$(( $PORT_BASE + i*10 + 2 ))
        grep -q '^anonymous-inbound=' $FLEET_ROOT/etc/node-\$i.conf || \\
          echo \"anonymous-inbound=\$(cat \$hn):$VPORT,127.0.0.1:\$anonin\" >> $FLEET_ROOT/etc/node-\$i.conf
      done
      d=0
      for cf in $FLEET_ROOT/etc/node-*.conf; do
        [ -e \"\$cf\" ] || continue
        i=\$(basename \"\$cf\" .conf); i=\${i#node-}
        nohup setsid $BIN --config-file \"\$cf\" --non-interactive \\
          >$FLEET_ROOT/log/node-\$i.out 2>&1 </dev/null &
        d=\$((d+1))
        sleep $START_STAGGER
      done
      sleep 15
      printf 'launched=%s alive=%s' \"\$d\" \"\$(pgrep -c -x \$(basename $BIN) 2>/dev/null || echo 0)\"")
    want=$((an + cn))
    echo "$out"
    case "$out" in *"alive=$want"*) ;; *) echo "  ^ expected alive=$want — a lost instance shrinks A" >&2; fail=1 ;; esac
    ;;

  peers|status)
    out=$(remote "$host" "
      want=\$(ls $FLEET_ROOT/etc/node-*.conf 2>/dev/null | wc -l)
      dead=''
      for cf in $FLEET_ROOT/etc/node-*.conf; do
        i=\$(basename \"\$cf\" .conf); i=\${i#node-}
        pgrep -f -x \"$BIN --config-file \$cf --non-interactive\" >/dev/null 2>&1 || dead=\"\$dead \$i\"
      done
      printf 'want=%s alive=%s dead:%s' \"\$want\" \"\$(pgrep -c -x \$(basename $BIN))\" \"\${dead:- none}\"")
    echo "$out"
    case "$out" in *"dead: none"*) ;; *) fail=1 ;; esac
    ;;

  gate)
    echo "(gate runs once, fleet-wide — see wait_onions_reachable.sh)"
    ;;
  esac
done < "$SPEC"

if [ "$fail" -ne 0 ]; then
  echo >&2
  echo "REFUSE: phase '$PHASE' did not verify on every host. Do NOT continue —" >&2
  echo "        a partially-started arm reports a low peer count as a result." >&2
  exit 1
fi
echo
echo "phase '$PHASE' verified on every host."
