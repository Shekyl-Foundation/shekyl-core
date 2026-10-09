#!/bin/bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# BA-T5 session 2, on the floor device. Registered in the shekyl-core record
# docs/benchmarks/ba_t5_serve_floor_device_20261009.md before it ran.
#
#   ba_t5_session2_run.sh <work_dir> <probe_binary> <shekyld> <lan_peer:port> <passes>
#
# Three daemon states, interleaved pass by pass. In `idle` only the device's
# resident testnet daemon runs, synced and following the tip. In `sync` a
# second testnet daemon under this user, with its own data directory under
# <work_dir>, resyncs the whole chain from <lan_peer>; it is wiped and
# started again for every pass. `nice` is `sync` with the serving process
# started under `nice -n 19`. Within a pass the four in-flight counts run
# in the order registered for the pass, each serving block between two
# no-serve windows of the sync poll, so the no-serve rate is read beside the
# serving rate under the same drift.
#
# Needs no root. The resident daemon is never touched.
set -uo pipefail
WORK=$1; PROBE=$2; SHEKYLD=$3; PEER=$4; PASSES=$5
cd "$WORK" || exit 3
HERE=$(cd "$(dirname "$0")" && pwd)
STAMP=$(date -u +%Y%m%dT%H%MZ)
OBS=obs-$STAMP.tsv; ENVF=env-$STAMP.tsv; SYNCF=sync-$STAMP.tsv; ERR=err-$STAMP.log
export PATH=$HOME/.cargo/bin:$PATH
unset RUSTFLAGS

SYS_PID=$(pgrep -x shekyld | head -1)
SYNC_RPC=13030; SYNC_P2P=13021; SYNC_RPC_R=13029
SYNC_PID=""
IN_FLIGHT="8 16 32 64"
QUIET_S=30
FETCHES=256

info() { curl -s -m 3 "http://127.0.0.1:$1/get_info"; }
field() { python3 -c 'import sys,json
try:
    d=json.load(sys.stdin); print(d.get(sys.argv[1],"na"))
except Exception:
    print("na")' "$1"; }

envrow() {  # tag
  local sh="na" ss="na" sj="na" sr="na"
  if [ -n "$SYNC_PID" ] && kill -0 "$SYNC_PID" 2>/dev/null; then
    local i; i=$(info $SYNC_RPC)
    sh=$(echo "$i" | field height); ss=$(echo "$i" | field synchronized)
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

poll_start() {  # label state
  rm -f "$WORK/stop-poll"
  "$HERE/ba_t5_sync_poll.sh" $SYNC_RPC "$1" "$2" "$WORK/stop-poll" "$SYNCF" &
  POLL_PID=$!
}
poll_stop() { touch "$WORK/stop-poll"; wait $POLL_PID 2>/dev/null; rm -f "$WORK/stop-poll"; }

NICE=""  # "nice -n 19" for the nice arm
probe() {  # label mode [VAR=value ...]
  local label=$1 mode=$2; shift 2
  envrow "start.$label"
  env BAT5_STORE="$WORK/store" BAT5_MODE="$mode" BAT5_LABEL="$label" "$@" \
    $NICE "$PROBE" --ignored --nocapture 2>>"$ERR" | grep -E '^(OBS|PHASE|LATE|BLOCK|ABANDON|TTFB)	' >> "$OBS"
  printf 'EXIT\t%s\t%s\t%s\n' "$label" "$mode" "${PIPESTATUS[0]}" >> "$OBS"
  envrow "end.$label"
}

sync_start() {  # a fresh data directory, then the daemon, then wait until it is syncing
  rm -rf "$WORK/syncdata"; mkdir -p "$WORK/syncdata"
  "$SHEKYLD" --testnet --data-dir "$WORK/syncdata" \
    --p2p-bind-ip 0.0.0.0 --p2p-bind-port $SYNC_P2P --in-peers 0 --no-igd \
    --rpc-bind-ip 127.0.0.1 --rpc-bind-port $SYNC_RPC --rpc-restricted-bind-port $SYNC_RPC_R \
    --add-exclusive-node "$PEER" --clearnet-transport-encrypt \
    --log-file "$WORK/syncdata/sync.log" --log-level 0 --non-interactive >> "$WORK/syncdaemon.out" 2>&1 &
  SYNC_PID=$!
  local h=0 waited=0
  while [ "$h" = "na" ] || [ "$h" -lt 50 ]; do
    sleep 2; waited=$((waited + 2))
    h=$(info $SYNC_RPC | field height); [ "$h" = "na" ] && h=0
    if [ $waited -gt 120 ]; then printf 'NOTE\tsync daemon did not reach height 50 in 120 s\n' >> "$OBS"; return 1; fi
  done
  printf 'NOTE\tsync daemon pid %s syncing from height %s at %s\n' "$SYNC_PID" "$h" "$(date -u +%FT%TZ)" >> "$OBS"
}
sync_stop() {
  if [ -n "$SYNC_PID" ]; then kill "$SYNC_PID" 2>/dev/null; wait "$SYNC_PID" 2>/dev/null; fi
  SYNC_PID=""
}

order_for_pass() {  # the four counts in the order registered for the pass
  case $1 in
    1) echo "32 64 8 16" ;;
    2) echo "16 8 64 32" ;;
    3) echo "64 16 32 8" ;;
    *) echo "8 16 32 64" ;;
  esac
}

{
  echo "# BA-T5 session 2 $STAMP"
  echo "# tree $(git -C "$(dirname "$PROBE")/../../../.." rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "# probe sha256 $(sha256sum "$PROBE" | cut -c1-64)"
  echo "# rustc $(rustc --version); RUSTFLAGS unset; release profile"
  echo "# resident daemon: $(tr '\0' ' ' < /proc/$SYS_PID/cmdline) pid $SYS_PID"
  echo "# syncing daemon: $SHEKYLD, own data dir, exclusive peer $PEER (a LAN testnet staker), in-peers 0"
  echo "# resident daemon mining_status: $(curl -s -m 5 http://127.0.0.1:12030/mining_status | python3 -c 'import sys,json;d=json.load(sys.stdin);print({k:d.get(k) for k in ("active","threads_count")})' 2>/dev/null)"
  echo "# states idle, sync, nice (sync with the probe under nice -n 19); in-flight counts $IN_FLIGHT; $FETCHES fetches per serving block; no-serve windows $QUIET_S s; $PASSES passes per state"
  echo "# signature scheme: Ed25519 + ML-DSA-65 hybrid (shekyl/archival-attestation-scheme-v3)"
} > "$OBS"
echo "# ENV utc tag temp_mC governor cur_freq_kHz load1 busy_jiffies sync_daemon_jiffies sync_daemon_rss_kB sync_height sync_synced mem_available_kB sync_daemon_pid system_daemon_rss_kB swap_total_kB swap_free_kB" > "$ENVF"
: > "$SYNCF"

# The store once, outside every window: the probe writes it on the first
# use and every later block opens it (BAT5_REUSE).
rm -rf "$WORK/store"
probe prep.store load BAT5_N=8

for pass in $(seq 1 "$PASSES"); do
  order=$(order_for_pass "$pass")
  printf 'NOTE\tpass %s order %s\n' "$pass" "$order" >> "$OBS"
  for state in idle sync nice; do
    syncing=0; [ "$state" != idle ] && syncing=1
    NICE=""; [ "$state" = nice ] && NICE="nice -n 19"
    if [ $syncing = 1 ]; then sync_start || continue; fi
    envrow "pass.$state.$pass.start"
    if [ $syncing = 1 ]; then poll_start "$state.$pass.quiet" "$state"; sleep $QUIET_S; poll_stop; fi
    for n in $order; do
      label="$state.$pass.N$n"
      [ $syncing = 1 ] && poll_start "$label" "$state"
      probe "$label" load BAT5_N=$FETCHES BAT5_IN_FLIGHT=$n BAT5_REUSE=1
      if [ $syncing = 1 ]; then poll_stop; poll_start "$state.$pass.quiet$n" "$state"; sleep $QUIET_S; poll_stop; fi
    done
    if [ "$pass" = 1 ] && [ "$state" != nice ]; then
      [ $syncing = 1 ] && poll_start "$state.$pass.ttfb" "$state"
      probe "$state.$pass.ttfb" ttfb BAT5_N=300 BAT5_REUSE=1
      [ $syncing = 1 ] && poll_stop
    fi
    envrow "pass.$state.$pass.end"
    [ $syncing = 1 ] && sync_stop
  done
done
rm -rf "$WORK/syncdata"
echo "# done $(date -u +%FT%TZ)" >> "$OBS"
echo "RUN COMPLETE $OBS $ENVF $SYNCF"
