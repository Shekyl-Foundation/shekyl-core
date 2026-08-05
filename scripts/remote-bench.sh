#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Run a cargo bench on a remote host and capture its output WITHOUT truncation.
#
# WHY THIS EXISTS
#
# A remote sweep was launched with `cargo bench ... | tail -200`, which silently
# discarded the early cells. Criterion's `estimates.json` happened to survive
# and the run was recoverable -- but a pipeline that DISCARDS rather than FAILS
# is the same class as chaining a gate and a push with `;`, and a sweep that
# lost both would have cost a full re-run on a machine that takes ~14 minutes
# just to build.
#
# The fix is the same shape: capture to a file, and tail the FILE for display,
# so the artifact is never the thing being truncated.
#
# USAGE
#   scripts/remote-bench.sh <host> <bench-name> [remote-workspace]
set -euo pipefail
HOST="${1:?usage: $0 <host> <bench> [workspace]}"
BENCH="${2:?usage: $0 <host> <bench> [workspace]}"
WS="${3:-~/shekyl-bench/rust}"
LOG="/tmp/${BENCH}.full.log"

ssh "$HOST" "source ~/.cargo/env; cd $WS && setsid nohup sh -c '
  grep -h . /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor | sort | uniq -c
  cargo +1.94.0 bench -p shekyl-ffi --bench $BENCH -- --test
  echo verify_exit=\$?
  cargo +1.94.0 bench -p shekyl-ffi --bench $BENCH
  echo BENCH_COMPLETE
' > $LOG 2>&1 < /dev/null & disown; echo launched"

echo "capturing to $HOST:$LOG -- full output, no pipe"
echo "poll:  ssh $HOST 'tail -20 $LOG'"
