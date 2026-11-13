#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# One drift comparison: a capture against the capture before it, through
# compare.py and its thresholds, with the per-row table printed (the
# report's delta is a fraction; the table shows it as a percentage). The
# nightly full-weight capture (nightly_drift.sh) and the push to dev's
# baseline update (benchmarks.yml, update-baseline) both run it, so the
# two alarms are one comparison.
#
#   drift_report.sh <label> <earlier shekyl_rust_v0.json> <later one> <what the earlier one is>
#
# Exit: compare.py's. 0 clean, 1 a row past its fail threshold or a row
# gone, 2 an input error. Rule 46: the comparison's exit is kept and
# returned; nothing here pipes a verdict.
#
# Needs jq and python3.
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
status=0
python3 "$(dirname "$0")/compare.py" \
  --baseline "${earlier}" --pr "${later}" --out "${report}" || status=$?
if [ -s "${report}" ]; then
  jq -r '
    "earlier " + .baseline_git_rev[0:10] + " -> later " + .pr_git_rev[0:10],
    (.entries[]
      | "\(.verdict)\t"
        + (if .delta_pct == null then "-" else (.delta_pct * 100 | tostring | .[0:8]) + "%" end)
        + "\t\(.full_id)")' \
    "${report}"
fi
if [ "${status}" -eq 1 ]; then
  echo "::error::${label}: a row moved past its fail threshold, or a row is gone, against ${against}"
fi
exit "${status}"
