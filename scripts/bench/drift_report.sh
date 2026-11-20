#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# One drift comparison: a later capture against an earlier one, through
# compare.py. The log, including every row that makes the run red, is
# compare.py's. The nightly full-weight capture (nightly_drift.sh) and
# the push to dev's baseline update (benchmarks.yml, update-baseline)
# both run it, so the two alarms share one comparator. They do not share
# a row set: each caller passes the capture it just made.
#
#   drift_report.sh <label> <earlier shekyl_rust_v0.json> <later one> <what the earlier one is>
#
# Exit: compare.py's. 0 clean (a warn is clean), 1 a row past its fail
# threshold or a row gone, 2 an input error. Rule 46: the comparison
# runs unpiped and its exit is this script's exit.
#
# Needs python3.
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <label> <earlier.json> <later.json> <what the earlier capture is>" >&2
  exit 2
fi
label="$1"
earlier="$2"
later="$3"
against="$4"
for envelope in "${earlier}" "${later}"; do
  if [ ! -s "${envelope}" ]; then
    echo "::error::${label}: ${envelope} is missing or empty"
    exit 2
  fi
done

report=$(mktemp)
trap 'rm -f "${report}"' EXIT
python3 "$(dirname "$0")/compare.py" \
  --baseline "${earlier}" --pr "${later}" --out "${report}" \
  --alarm-label "${label}" --alarm-against "${against}"
