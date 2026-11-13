#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The nightly capture's drift comparison: tonight's envelope against the
# newest earlier capture of the same artifact name, through compare.py and
# its thresholds. nightly.yml's bench-full-drift job runs it.
#
#   nightly_drift.sh <artifact-name> <tonight's shekyl_rust_v0.json>
#
# The earlier capture is whichever run uploaded the artifact last, green
# or not: the comparison is with the night before, so a count that moved
# on purpose is red for one night and is then the figure the next night
# is held to. The issue the red opens is the record of the move.
#
# No earlier capture (the first night, or every earlier artifact expired)
# is not a failure: there is nothing to drift from, and the run says so.
#
# Exit: compare.py's, through drift_report.sh, which the push to dev's
# baseline update uses on the pull-request set. 0 clean (a warn is
# clean), 1 a row past its fail threshold or a row gone, 2 an input
# error. Rule 46: the comparison runs unpiped and its exit is this
# script's exit.
#
# Needs GH_TOKEN (actions: read), GITHUB_REPOSITORY and GITHUB_RUN_ID, as
# a workflow step has them, and gh, jq, unzip and python3.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <artifact-name> <shekyl_rust_v0.json>" >&2
  exit 2
fi
name="$1"
current="$2"
: "${GH_TOKEN:?GH_TOKEN is not set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is not set}"
if [ ! -s "${current}" ]; then
  echo "::error::${current} is missing or empty: tonight's capture did not produce an envelope"
  exit 2
fi

listing=$(gh api "repos/${GITHUB_REPOSITORY}/actions/artifacts?name=${name}&per_page=100")
previous=$(jq -r --arg run "${GITHUB_RUN_ID}" '
  [ .artifacts[]
    | select(.expired | not)
    | select((.workflow_run.id | tostring) != $run) ]
  | sort_by(.created_at) | last | .id // empty' <<<"${listing}")
if [ -z "${previous}" ]; then
  echo "::notice::no earlier ${name} capture to compare with: tonight's is the first"
  exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT
gh api "repos/${GITHUB_REPOSITORY}/actions/artifacts/${previous}/zip" > "${work}/previous.zip"
unzip -q "${work}/previous.zip" -d "${work}/previous"
baseline="${work}/previous/shekyl_rust_v0.json"
if [ ! -s "${baseline}" ]; then
  echo "::error::artifact ${previous} (${name}) holds no shekyl_rust_v0.json"
  exit 2
fi

"$(dirname "$0")/drift_report.sh" "${name}" "${baseline}" "${current}" "the capture before tonight's (artifact ${previous})"
