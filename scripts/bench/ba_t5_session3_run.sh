#!/bin/bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# BA-T5 session 3, on the floor device: the SH-3 confirming block.
# Registered in the shekyl-core record
# docs/benchmarks/ba_t5_serve_floor_device_<date>.md before it ran.
#
#   ba_t5_session3_run.sh <work_dir> <probe_binary> <shekyld> <lan_peer:port> <topology> <passes>
#
# <topology> is `t1` or `t2p`. In both, a second testnet daemon under this
# user resyncs the whole chain from <lan_peer> while the probe serves
# beside it; the difference is where the scheduler finds the two:
#
#   t1   the daemon is a child of this script, in the probe's own session
#        scope: the GUI wallet supervising shekyld as a sidecar.
#   t2p  the daemon runs in a transient scope of this user's own systemd
#        instance (`systemd-run --user --scope`), in its own session
#        (`setsid`), while the probe runs in the login session: an
#        approximation of a Pi staker's resident system service beside a
#        wallet in a user session (T2), which needs root to start and is
#        not run here. The record says T2' is an approximation.
#
# One sync per topology; the passes sit inside it. Each pass is one
# no-serve window, then three serving cells in the pass's registered
# order, each followed by a no-serve window:
#
#   mech8   the shipped mechanism: the probe's serving runtime built through
#           the single constructor with the thread-start hook that lowers
#           each thread (BAT5_PRIORITY=thread), 8 in flight, 512 fetches
#   mech64  the same at 64 in flight
#   ctrl8   the control: the same runtime and budget, every thread at the
#           priority it inherits (BAT5_PRIORITY=budget), 8 in flight,
#           4096 fetches — long enough to hold three of the daemon's log
#           points under a serve that cuts the daemon's rate by two thirds
#
# The scheduling context is captured before the first block and after the
# last of each topology (CTX rows), and every probe's thread nice values
# are read from /proc while it serves, so the capture shows the mechanism
# took. Needs no root. The resident daemon is never touched.
set -uo pipefail
# Every path is made absolute before the chdir below (see session 2).
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(cd "$1" && pwd) || exit 3
PROBE=$(realpath "$2") || exit 3
SHEKYLD=$(realpath "$3") || exit 3
PEER=$4; TOPO=$5; PASSES=$6
case $TOPO in t1|t2p) ;; *) echo "topology must be t1 or t2p" >&2; exit 3 ;; esac
cd "$WORK" || exit 3
STAMP=$(date -u +%Y%m%dT%H%MZ)
OBS=obs-$STAMP-$TOPO.tsv; ENVF=env-$STAMP-$TOPO.tsv; SYNCF=sync-$STAMP-$TOPO.tsv; CTXF=ctx-$STAMP-$TOPO.tsv; ERR=err-$STAMP-$TOPO.log
export PATH=$HOME/.cargo/bin:$PATH
unset RUSTFLAGS

SYS_PID=$(pgrep -x shekyld | head -1)
SYNC_RPC=13030; SYNC_P2P=13021; SYNC_RPC_R=13029
SYNC_PID=""
SCOPE_UNIT="ba-t5-s3-$STAMP"
QUIET_S=45
FETCHES_MECH=512
FETCHES_CTRL=4096
# The daemon must still be syncing through the last window: stop a pass
# before it starts if fewer than this many blocks remain.
MIN_BLOCKS_LEFT=600

envrow() {  # tag
  local sh="na" ss="na" sj="na" sr="na"
  if [ -n "$SYNC_PID" ] && kill -0 "$SYNC_PID" 2>/dev/null; then
    sh=$(grep -oE 'Synced [0-9]+' "$WORK/syncdata/stdout.log" 2>/dev/null | tail -1 | grep -oE '[0-9]+$'); [ -z "$sh" ] && sh=na
    ss=$(grep -c "SYNCHRONIZED OK" "$WORK/syncdata/stdout.log" 2>/dev/null)
    sj=$(awk '{print $14+$15}' /proc/$SYNC_PID/stat 2>/dev/null || echo na)
    sr=$(awk '/VmRSS/{print $2}' /proc/$SYNC_PID/status 2>/dev/null || echo na)
  fi
  printf 'ENV\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(date -u +%FT%TZ)" "$1" \
    "$(cat /sys/class/thermal/thermal_zone0/temp)" \
    "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)" \
    "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq)" \
    "$(cut -d' ' -f1 /proc/loadavg)" \
    "$(awk '/^cpu /{print $2+$3+$4+$7+$8}' /proc/stat)" \
    "$sj" "$sr" "$sh" "$ss" \
    "$(awk '/MemAvailable/{print $2}' /proc/meminfo)" \
    "${SYNC_PID:-na}" \
    "$(awk '/VmRSS/{print $2}' /proc/$SYS_PID/status 2>/dev/null || echo na)" \
    "$(awk '/SwapTotal/{print $2}' /proc/meminfo)" \
    "$(awk '/SwapFree/{print $2}' /proc/meminfo)" >> "$ENVF"
}

ctx() {  # tag key value
  printf 'CTX\t%s\t%s\t%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$TOPO" "$1" "$2" "$3" >> "$CTXF"
}
cgroup_of() { sed 's/^0:://' /proc/$1/cgroup 2>/dev/null; }
cgroup_facts() {  # tag role pid — the process's cgroup, its parent's controllers, its own weight
  local tag=$1 role=$2 pid=$3 cg parent
  cg=$(cgroup_of "$pid"); [ -z "$cg" ] && { ctx "$tag" "$role.cgroup" "na"; return; }
  ctx "$tag" "$role.cgroup" "$cg"
  ctx "$tag" "$role.autogroup" "$(cat /proc/$pid/autogroup 2>/dev/null | tr '\t' ' ')"
  parent=$(dirname "$cg")
  ctx "$tag" "$role.parent" "$parent"
  ctx "$tag" "$role.parent.controllers" "$(cat /sys/fs/cgroup$parent/cgroup.controllers 2>/dev/null)"
  ctx "$tag" "$role.parent.subtree_control" "$(cat /sys/fs/cgroup$parent/cgroup.subtree_control 2>/dev/null)"
  ctx "$tag" "$role.cpu.weight" "$(cat /sys/fs/cgroup$cg/cpu.weight 2>/dev/null || echo na)"
}
ctx_capture() {  # tag — the scheduling context of the daemon and of this script (the probe's parent)
  ctx "$1" "sched_autogroup_enabled" "$(cat /proc/sys/kernel/sched_autogroup_enabled)"
  ctx "$1" "cgroup.root.subtree_control" "$(cat /sys/fs/cgroup/cgroup.subtree_control)"
  cgroup_facts "$1" "daemon" "${SYNC_PID:-0}"
  cgroup_facts "$1" "serving" "$$"
  ctx "$1" "resident.cgroup" "$(cgroup_of "$SYS_PID")"
}
probe_threads() {  # tag pid — every thread of the running probe: comm and nice, as a histogram
  local t c n
  cgroup_facts "$1" "probe" "$2"
  for t in /proc/$2/task/*; do
    [ -r "$t/stat" ] || continue
    c=$(cat "$t/comm" 2>/dev/null); n=$(sed 's/.*) //' "$t/stat" 2>/dev/null | awk '{print $17}')
    echo "$c:$n"
  done | sort | uniq -c | awk '{printf "%s=%s ", $2, $1}' | sed 's/ $//' | { read -r hist; ctx "$1" "probe.threads" "${hist:-na}"; }
}

poll_start() {  # label — reads the syncing daemon's own stdout log
  rm -f "$WORK/stop-poll"
  "$HERE/ba_t5_sync_poll.sh" "$WORK/syncdata/stdout.log" "$1" "$TOPO" "$WORK/stop-poll" "$SYNCF" &
  POLL_PID=$!
}
poll_stop() { touch "$WORK/stop-poll"; wait $POLL_PID 2>/dev/null; rm -f "$WORK/stop-poll"; }

probe() {  # label mode [VAR=value ...] — runs the probe, reading its threads 8 s in
  local label=$1 mode=$2; shift 2
  envrow "start.$label"
  # The probe's output goes to a file and is filtered into the capture
  # after it exits: a backgrounded pipeline would hand `wait` the grep's
  # status, not the probe's, and the probe's own pid is wanted for the
  # thread read (rule 46: the exit status does not travel through a pipe).
  local out="$WORK/probe-$label.out"
  env BAT5_STORE="$WORK/store" BAT5_MODE="$mode" BAT5_LABEL="$label" "$@" \
    "$PROBE" --ignored --nocapture > "$out" 2>>"$ERR" &
  local pid=$!
  sleep 8
  kill -0 "$pid" 2>/dev/null && probe_threads "$label" "$pid"
  wait "$pid"; local rc=$?
  grep -E '^(OBS|PHASE|LATE|BLOCK|ABANDON|TTFB)	' "$out" >> "$OBS"
  rm -f "$out"
  printf 'EXIT\t%s\t%s\t%s\n' "$label" "$mode" "$rc" >> "$OBS"
  envrow "end.$label"
}

sync_height() { grep -oE 'Synced [0-9]+/[0-9]+' "$WORK/syncdata/stdout.log" 2>/dev/null | tail -1 | grep -oE '[0-9]+/[0-9]+'; }

sync_start() {  # a fresh data directory, then the daemon, then wait until it is syncing
  rm -rf "$WORK/syncdata"; mkdir -p "$WORK/syncdata"
  local cmd=("$SHEKYLD" --testnet --data-dir "$WORK/syncdata"
    --p2p-bind-ip 0.0.0.0 --p2p-bind-port $SYNC_P2P --in-peers 0 --no-igd
    --rpc-bind-ip 127.0.0.1 --rpc-bind-port $SYNC_RPC --rpc-restricted-bind-port $SYNC_RPC_R
    --add-exclusive-node "$PEER" --clearnet-transport-encrypt
    --log-file "$WORK/syncdata/sync.log" --log-level 0 --non-interactive)
  case $TOPO in
    t1)
      "${cmd[@]}" > "$WORK/syncdata/stdout.log" 2>&1 &
      SYNC_PID=$!
      ;;
    t2p)
      # Its own session (setsid) in its own transient scope under this
      # user's systemd instance; this script does not own the process, so
      # the pid is looked up by its own command line (the executable first,
      # so setsid's argument list is not it).
      systemd-run --user --scope --quiet --unit="$SCOPE_UNIT" -- \
        setsid --fork --wait "${cmd[@]}" > "$WORK/syncdata/stdout.log" 2>&1 &
      sleep 3
      SYNC_PID=$(pgrep -f "^$SHEKYLD --testnet --data-dir $WORK/syncdata" | head -1)
      ;;
  esac
  echo "${SYNC_PID:-na}" > "$WORK/syncdata/pid"
  local h=0 waited=0
  while [ "$h" -lt 50 ]; do
    sleep 2; waited=$((waited + 2))
    h=$(sync_height | cut -d/ -f1); [ -z "$h" ] && h=0
    if [ $waited -gt 150 ]; then printf 'NOTE\tsync daemon did not reach height 50 in 150 s\n' >> "$OBS"; return 1; fi
  done
  printf 'NOTE\tsync daemon pid %s syncing from height %s at %s (%s)\n' "$SYNC_PID" "$h" "$(date -u +%FT%TZ)" "$TOPO" >> "$OBS"
}
sync_stop() {
  if [ -n "$SYNC_PID" ]; then
    kill "$SYNC_PID" 2>/dev/null
    local waited=0
    while kill -0 "$SYNC_PID" 2>/dev/null && [ $waited -lt 60 ]; do sleep 1; waited=$((waited + 1)); done
    kill -0 "$SYNC_PID" 2>/dev/null && kill -9 "$SYNC_PID" 2>/dev/null
    wait "$SYNC_PID" 2>/dev/null
  fi
  [ "$TOPO" = t2p ] && systemctl --user stop "$SCOPE_UNIT.scope" 2>/dev/null
  SYNC_PID=""
}

order_for_pass() {  # the three cells in the order registered for the pass
  case $1 in
    1) echo "mech8 mech64 ctrl8" ;;
    2) echo "ctrl8 mech8 mech64" ;;
    3) echo "mech64 ctrl8 mech8" ;;
    *) echo "mech8 mech64 ctrl8" ;;
  esac
}

{
  echo "# BA-T5 session 3 $STAMP topology $TOPO"
  echo "# tree $(git -C "$(dirname "$PROBE")/../../../.." rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "# probe sha256 $(sha256sum "$PROBE" | cut -c1-64)"
  echo "# rustc $(rustc --version); RUSTFLAGS unset; release profile"
  echo "# resident daemon: the floor device's resident testnet daemon, pid $SYS_PID"
  echo "# syncing daemon: a second testnet daemon, own data dir, exclusive peer: a testnet staker on the LAN, port ${PEER##*:} (its address is in the estate ledger, not here), in-peers 0"
  echo "# resident daemon mining_status: $(curl -s -m 5 http://127.0.0.1:12030/mining_status | python3 -c 'import sys,json;d=json.load(sys.stdin);print({k:d.get(k) for k in ("active","threads_count")})' 2>/dev/null)"
  echo "# cells mech8 (BAT5_PRIORITY=thread, 8 in flight, $FETCHES_MECH fetches), mech64 (thread, 64 in flight, $FETCHES_MECH), ctrl8 (BAT5_PRIORITY=budget, 8 in flight, $FETCHES_CTRL); no-serve windows $QUIET_S s; $PASSES passes inside one sync"
  echo "# sync rate from the syncing daemon's own stdout log (Synced H/T lines); the poll seeds its seen line at start"
  echo "# signature scheme: Ed25519 + ML-DSA-65 hybrid (shekyl/archival-attestation-scheme-v3)"
} > "$OBS"
echo "# ENV utc tag temp_mC governor cur_freq_kHz load1 busy_jiffies sync_daemon_jiffies sync_daemon_rss_kB sync_height sync_synced mem_available_kB sync_daemon_pid system_daemon_rss_kB swap_total_kB swap_free_kB" > "$ENVF"
: > "$SYNCF"
echo "# CTX utc topology tag key value" > "$CTXF"

# The store once, outside every window.
rm -rf "$WORK/store"
probe prep.store load BAT5_N=8

sync_start || { sync_stop; echo "RUN ABORTED: the sync daemon did not start"; exit 4; }
ctx_capture "before"
for pass in $(seq 1 "$PASSES"); do
  ht=$(sync_height); h=${ht%/*}; t=${ht#*/}
  if [ -n "$h" ] && [ -n "$t" ] && [ $((t - h)) -lt $MIN_BLOCKS_LEFT ]; then
    printf 'NOTE\tpass %s not started: %s blocks left in the sync, under %s\n' "$pass" "$((t - h))" "$MIN_BLOCKS_LEFT" >> "$OBS"
    break
  fi
  order=$(order_for_pass "$pass")
  printf 'NOTE\tpass %s order %s\n' "$pass" "$order" >> "$OBS"
  envrow "pass.$TOPO.$pass.start"
  poll_start "$TOPO.$pass.quiet"; sleep $QUIET_S; poll_stop
  for cell in $order; do
    label="$TOPO.$pass.$cell"
    case $cell in
      mech8)  prio=thread; n=8;  fetches=$FETCHES_MECH ;;
      mech64) prio=thread; n=64; fetches=$FETCHES_MECH ;;
      ctrl8)  prio=budget; n=8;  fetches=$FETCHES_CTRL ;;
    esac
    poll_start "$label"
    probe "$label" load BAT5_N=$fetches BAT5_IN_FLIGHT=$n BAT5_REUSE=1 BAT5_PRIORITY=$prio
    poll_stop
    poll_start "$TOPO.$pass.quiet$cell"; sleep $QUIET_S; poll_stop
  done
  envrow "pass.$TOPO.$pass.end"
done
ctx_capture "after"
sync_stop
rm -rf "$WORK/syncdata"
echo "# done $(date -u +%FT%TZ)" >> "$OBS"
echo "RUN COMPLETE $OBS $ENVF $SYNCF $CTXF"
