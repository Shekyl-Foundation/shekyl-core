#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Say whether origin has a branch, without treating a failed lookup
# as an absent one.
#
#   origin_branch.sh <work-tree> <branch>
#
# Stdout is `present` or `absent`, and the exit is 0, only when the
# lookup itself succeeded. git ls-remote --exit-code uses status 2
# for "no matching ref"; that is the absent case. Any other status
# is a failed lookup: this script exits with that status, writes an
# ::error:: line to stderr, and does not print `absent`.
#
# A caller that collapses every nonzero status into "absent" will
# skip a drift alarm, or seed a fresh baseline, on an auth or
# transport error.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <work-tree> <branch>" >&2
  exit 2
fi
work_tree="$1"
branch="$2"

# git-ls-remote(1): --exit-code exits 2 when no matching refs are found.
LS_REMOTE_NO_MATCHING_REF=2

status=0
git -C "${work_tree}" ls-remote --exit-code --heads origin "${branch}" >/dev/null || status=$?
if [ "${status}" -eq 0 ]; then
  printf 'present\n'
elif [ "${status}" -eq "${LS_REMOTE_NO_MATCHING_REF}" ]; then
  printf 'absent\n'
else
  echo "::error::could not read origin/${branch} (ls-remote exit ${status})" >&2
  exit "${status}"
fi
