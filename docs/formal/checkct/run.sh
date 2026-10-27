#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Run cargo-checkct on one workspace made by setup.sh and keep the log.
#
# Usage:  ./run.sh <workspace> [cargo-checkct run options]
#   ./run.sh ctlpre                       # calibration: must report leaks
#   ./run.sh subject --timeout 900
#   CHECKCT_LABEL=division ./run.sh subject-noslp --checks control-flow,memory-access,dividend,divisor
#   ./run.sh helio --timeout 3600
#
# The log goes to results/<UTC date>/<workspace>.log. The exit status is
# cargo-checkct's own: 0 secure, non-zero for any insecure or unknown
# entrypoint (rule 46: the verdict never travels through a pipe).
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
IMAGE=shekyl-checkct:85271e5
ws=${1:?workspace name}; shift

DOCKER_ENV=(-e HOME=/tmp/h -e CARGO_HOME=/repo/docs/formal/checkct/.build/cargo-home)
if [ -d "$HERE/.build/rustup-home" ]; then
    DOCKER_ENV+=(-e RUSTUP_HOME=/repo/docs/formal/checkct/.build/rustup-home)
fi

day=$(date -u +%Y-%m-%d)
mkdir -p "$HERE/results/$day"
# The record is per toolchain: the workspace's pinned channel is part of the
# file name, so runs on two nightlies never overwrite each other.
channel=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$HERE/.build/$ws/checkct/rust-toolchain.toml")
# CHECKCT_LABEL distinguishes two runs of one workspace on one toolchain
# (e.g. the pass with the division checks added) so neither overwrites the other.
label=${CHECKCT_LABEL:+.$CHECKCT_LABEL}
log=$HERE/results/$day/$ws.$channel$label.log

date -u >"$log"
set +e
docker run --rm -u "$(id -u):$(id -g)" "${DOCKER_ENV[@]}" \
    -v "$REPO:/repo" -w /repo/docs/formal/checkct/.build "$IMAGE" \
    cargo checkct run -d "/repo/docs/formal/checkct/.build/$ws" --jobs "$(nproc)" "$@" >>"$log" 2>&1
status=$?
set -e
date -u >>"$log"

# Keep the compact record beside the raw log: run window, tool pins, the
# verdict table, and every leak or gap line. The raw .log is not committed
# (see .gitignore); the .txt is the dated run data.
txt=${log%.log}.txt
{
    echo "workspace: $ws"
    echo "cargo-checkct: $IMAGE   options: $*"
    echo "toolchain: $channel"
    echo "profile.release: $(grep -E '^(opt-level|panic|overflow-checks|lto|codegen-units)' "$HERE/.build/$ws/checkct/Cargo.toml" | tr '\n' ' ')"
    echo "targets + rustflags: $(grep -E '^(target|rustflags)' "$HERE/.build/$ws/checkct/.cargo/config.toml" | tr '\n' ' ')"
    echo "run window (UTC): $(head -1 "$log") -> $(tail -1 "$log")"
    echo
    awk '/^Summary:/{p=1} p' "$log"
    grep -E 'has (control flow|memory access) leak|uninterpreted|Program status is : unknown' "$log" || true
} >"$txt"

# Show the verdict table; the status printed is the run's own exit code.
awk '/^Summary:/{p=1} p' "$log"
echo "cargo-checkct exit=$status (log: $log; record: $txt)"
exit "$status"
