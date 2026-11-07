#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# push_scope_base.sh — the commit a push run's change scope starts from.
#
# Usage: push_scope_base.sh <workflow-file> <branch> <head-sha>
#
# Prints the head commit of the newest push run of <workflow-file> on
# <branch> that concluded success, when that commit is an ancestor of
# <head-sha>. Prints nothing otherwise; change_scope.py, handed no base,
# answers docs_only=false and everything runs.
#
# Why not the push's own `before`: the workflows' concurrency group is the
# branch, so a push to `dev` cancels the run of the push before it. Measured
# from `before`, a docs-only merge landing while a code merge's run is in
# progress would cancel that run and then skip the suite itself, and the
# code merge would never be tested on `dev`. Measured from the last green
# run, the diff holds every commit no run of this workflow has passed.
#
# That is also why a docs-only run may conclude success with the suite
# skipped: its own diff started at the last green run, so its verdict
# covers every commit since. Measuring from `before` again breaks this.
#
# Needs GH_TOKEN with `actions: read` and the history back to the base
# (`fetch-depth: 0`). Every failure prints nothing and its reason on
# stderr: a missing base costs runner minutes, a wrong one skips tests.

set -u

if [ $# -ne 3 ]; then
  echo "usage: push_scope_base.sh <workflow-file> <branch> <head-sha>" >&2
  exit 2
fi
workflow=$1
branch=$2
head=$3

runs="repos/${GITHUB_REPOSITORY}/actions/workflows/${workflow}/runs"
if ! base=$(gh api "${runs}?branch=${branch}&event=push&status=success&per_page=1" \
    --jq '.workflow_runs[0].head_sha // empty'); then
  echo "push_scope_base: could not list ${workflow} runs on ${branch}; no base" >&2
  exit 0
fi
if [ -z "$base" ]; then
  echo "push_scope_base: no green push run of ${workflow} on ${branch}; no base" >&2
  exit 0
fi
if ! git merge-base --is-ancestor "$base" "$head"; then
  echo "push_scope_base: last green ${base} is not an ancestor of ${head}; no base" >&2
  exit 0
fi
echo "push_scope_base: ${workflow} last passed on ${branch} at ${base}" >&2
echo "$base"
