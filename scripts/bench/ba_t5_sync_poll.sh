#!/bin/bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# BA-T5 session 2: the daemon's sync rate across one window, from the
# heights its own log reports.
#
#   ba_t5_sync_poll.sh <daemon_stdout_log> <label> <state> <stop_file> <out_file>
#
# Every second until <stop_file> exists, reads the newest "Synced H/T" line
# the daemon has written to <daemon_stdout_log> (it writes one about every
# eight seconds while syncing) and appends it, if new, to <out_file>:
#
#   SYNCH  utc label state height target
#
# and, when stopped, one summary row over the points seen in the window:
#
#   SYNC   label state first_height last_height seconds points stalls last_target
#
# `seconds` is the time between the first and the last point's own log
# timestamps, so the rate (last − first) / seconds is the daemon's, not the
# window's. `stalls` is the number of points at which the height did not
# advance from the previous point. The record's rule for a valid window
# (height advancing throughout, target not reached) is read from these
# rows by the reading script, not asserted here.
#
# Why the log and not the RPC: under a sync that takes three of the four
# cores, a `get_height` call on the daemon's RPC took 6 to 9 seconds in the
# first start of this session, and the poll's 2-second timeout saw nothing.
# The log line costs the daemon nothing extra and is written whatever the
# load. The poll's own cost is one `tail` and one `grep` per second.
#
# `pipefail` (rule 46): a tail that fails fails the pipe, and the `|| true`
# supplies the empty line the loop then skips. grep -o reads all of its
# stdin, so there is no early-exit consumer to trip the SIGPIPE trap.
set -uo pipefail
log=$1; label=$2; state=$3; stop=$4; out=$5
first_h=""; first_t=""; last_h=""; last_t=""; last_target=""; prev=""; points=0; stalls=0; seen=""
to_epoch() { date -u -d "$1" +%s.%N 2>/dev/null || echo ""; }
while [ ! -e "$stop" ]; do
  line=$(tail -n 40 "$log" 2>/dev/null | grep -oE '^\S*[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z\S*.*Synced [0-9]+/[0-9]+' | tail -1 || true)
  if [ -n "$line" ] && [ "$line" != "$seen" ]; then
    seen=$line
    ts=$(echo "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z' | head -1)
    h=$(echo "$line" | grep -oE 'Synced [0-9]+' | grep -oE '[0-9]+$')
    t=$(echo "$line" | grep -oE 'Synced [0-9]+/[0-9]+' | grep -oE '[0-9]+$')
    printf 'SYNCH\t%s\t%s\t%s\t%s\t%s\n' "$ts" "$label" "$state" "$h" "$t" >> "$out"
    [ -z "$first_h" ] && { first_h=$h; first_t=$ts; }
    [ -n "$prev" ] && [ "$h" = "$prev" ] && stalls=$((stalls + 1))
    prev=$h; last_h=$h; last_t=$ts; last_target=$t; points=$((points + 1))
  fi
  sleep 1
done
seconds=0
if [ -n "$first_t" ] && [ -n "$last_t" ]; then
  a=$(to_epoch "$first_t"); b=$(to_epoch "$last_t")
  [ -n "$a" ] && [ -n "$b" ] && seconds=$(python3 -c "print(round($b - $a, 1))")
fi
printf 'SYNC\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$label" "$state" "${first_h:-na}" "${last_h:-na}" "$seconds" "$points" "$stalls" "${last_target:-na}" >> "$out"
