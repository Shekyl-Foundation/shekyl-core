#!/bin/bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# BA-T5 session 2: the daemon's sync rate across one block, from its own
# height over time.
#
#   ba_t5_sync_poll.sh <rpc_port> <label> <state> <stop_file> <out_file>
#
# Polls GET /get_info on 127.0.0.1:<rpc_port> once a second until <stop_file>
# exists, appending one row per poll to <out_file>:
#
#   SYNCH  utc label state height target_height synchronized
#
# and, when stopped, one summary row:
#
#   SYNC   label state block_start_height block_end_height seconds polls stalls
#
# `stalls` is the number of polls at which the height did not advance from
# the previous poll. The record's rule is that a syncing block counts only if
# the height advanced throughout its window; that is read from `stalls` and
# from the SYNCH rows, not asserted here.
#
# `pipefail` (rule 46): a curl that fails fails the pipe, and the `|| echo`
# after it is what then supplies the `na` row. python3 reads all of its stdin,
# so there is no early-exit consumer to trip the SIGPIPE trap.
#
# Cost: one curl and one python3 start per second, about 60 ms of CPU each on
# the floor device, so about 6 % of one core while it polls. That is charged
# to the environment's "remainder", not to the probe, and the record says so.
set -uo pipefail
port=$1; label=$2; state=$3; stop=$4; out=$5
start_height=""; prev=""; end_height=""; polls=0; stalls=0
t0=$(date -u +%s)
while [ ! -e "$stop" ]; do
  now=$(date -u +%FT%TZ)
  read -r height target synced < <(curl -s -m 2 "http://127.0.0.1:${port}/get_info" \
    | python3 -c 'import sys,json
try:
    d=json.load(sys.stdin); print(d.get("height","na"), d.get("target_height","na"), d.get("synchronized","na"))
except Exception:
    print("na na na")' 2>/dev/null || echo "na na na")
  printf 'SYNCH\t%s\t%s\t%s\t%s\t%s\t%s\n' "$now" "$label" "$state" "$height" "$target" "$synced" >> "$out"
  if [ "$height" != "na" ]; then
    [ -z "$start_height" ] && start_height=$height
    [ -n "$prev" ] && [ "$height" = "$prev" ] && stalls=$((stalls + 1))
    prev=$height; end_height=$height
  fi
  polls=$((polls + 1))
  sleep 1
done
printf 'SYNC\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$label" "$state" "${start_height:-na}" "${end_height:-na}" \
  "$(( $(date -u +%s) - t0 ))" "$polls" "$stalls" >> "$out"
