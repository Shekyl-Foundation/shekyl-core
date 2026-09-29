#!/bin/bash
# Every harness seed against the epee host and the seam host.
# `shekyl-p2p-harness`'s `the_runner_lists_every_seed` parses SEEDS.
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: run_seeds.sh EPEE PEER SEAM COMPARE" >&2
  exit 2
fi

EH=$1
PEER=$2
SEAM=$3
CMP=$4

for bin in "$EH" "$PEER" "$SEAM" "$CMP"; do
  if [[ ! -x "$bin" ]]; then
    echo "missing harness binary: $bin" >&2
    exit 2
  fi
done

SEEDS="1 2 3 10 11 20 30 31 32 40 100 101 102 103 104 105 106 107 108 109 110 111 112 113 114 115"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for seed in $SEEDS; do
  : >"$tmp/epee-addr"
  "$EH" "$seed" "$tmp/epee-host.txt" >"$tmp/epee-addr" 2>"$tmp/epee-err" &
  epid=$!
  for _ in $(seq 1 100); do
    if [[ -s "$tmp/epee-addr" ]]; then
      break
    fi
    sleep 0.05
  done
  if [[ ! -s "$tmp/epee-addr" ]]; then
    echo "seed $seed: epee host did not bind" >&2
    cat "$tmp/epee-err" >&2
    wait "$epid" || true
    exit 1
  fi
  if ! "$PEER" "$(head -n1 "$tmp/epee-addr")" "$seed" "$tmp/epee-peer.txt" >"$tmp/peer-err" 2>&1; then
    echo "seed $seed: epee peer failed" >&2
    cat "$tmp/peer-err" >&2
    wait "$epid" || true
    exit 1
  fi
  if ! wait "$epid"; then
    echo "seed $seed: epee host failed" >&2
    cat "$tmp/epee-err" >&2
    exit 1
  fi

  : >"$tmp/seam-addr"
  "$SEAM" "$seed" "$tmp/seam-host.txt" >"$tmp/seam-addr" 2>"$tmp/seam-err" &
  spid=$!
  for _ in $(seq 1 100); do
    if [[ -s "$tmp/seam-addr" ]]; then
      break
    fi
    sleep 0.05
  done
  if [[ ! -s "$tmp/seam-addr" ]]; then
    echo "seed $seed: seam host did not bind" >&2
    cat "$tmp/seam-err" >&2
    wait "$spid" || true
    exit 1
  fi
  if ! "$PEER" "$(head -n1 "$tmp/seam-addr")" "$seed" "$tmp/seam-peer.txt" >"$tmp/speer-err" 2>&1; then
    echo "seed $seed: seam peer failed" >&2
    cat "$tmp/speer-err" >&2
    wait "$spid" || true
    exit 1
  fi
  if ! wait "$spid"; then
    echo "seed $seed: seam host failed" >&2
    cat "$tmp/seam-err" >&2
    exit 1
  fi
  if ! "$CMP" "$tmp/seam-peer.txt" "$tmp/seam-host.txt" "$tmp/epee-peer.txt" "$tmp/epee-host.txt"; then
    echo "seed $seed: hosts differ" >&2
    exit 1
  fi
done
