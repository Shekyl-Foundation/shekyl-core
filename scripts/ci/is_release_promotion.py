#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Is this pull request a release promotion: `main` receiving commits that
are already in `dev`?

The dial-path freeze (`check_dial_path_freeze.py`, Ruling A) judges a change
against the tree it enters, which is `dev`. On a pull request into `main` its
base is the last release, so it reads a whole epoch as one change and fails
on lines that were each admitted, or predate the freeze, when they entered
`dev`. A promotion has nothing left to judge, and the workflow skips the
freeze for it.

What makes a pull request a promotion is a fact about its commits, not about
what its branch is called. The first version of this rule matched the head
branch's name (`dev`, `release-v*`). A fork's branch can carry either name,
and so can a branch here holding commits `dev` has never seen; both would
have skipped the freeze. So the rule is:

  * the event is a pull request,
  * its base is `main`, and
  * its head commit is already in `dev`'s history: `dev...head` is ahead by
    zero commits.

A release branch cut at the frozen commit passes, as `dev` itself does. A
branch with one commit `dev` lacks does not, whatever it is named, and is
judged like any other change.

The caller asks GitHub for `ahead_by` and passes what it got. Anything that
is not the integer 0 — a failed request, an empty string, a commit the
repository does not have — is "not a promotion": the exemption fails
closed, and the freeze runs.

Exit status: 0 = a promotion (skip the freeze); 1 = not one (run it).
`--selftest` runs the cases below.
"""

import argparse
import sys


def is_promotion(event, base_ref, ahead_by):
    if event != "pull_request" or base_ref != "main":
        return False
    return isinstance(ahead_by, str) and ahead_by.strip() == "0"


CASES = [
    ("dev promoted to main, head in dev", "pull_request", "main", "0", True),
    ("a release branch cut at the freeze", "pull_request", "main", "0\n", True),
    ("a branch with two commits dev lacks", "pull_request", "main", "2", False),
    ("the compare request failed", "pull_request", "main", "", False),
    ("the reply was not a number", "pull_request", "main", "null", False),
    ("an error body in place of a number", "pull_request", "main", '{"message":"Not Found"}', False),
    ("a negative count is not zero", "pull_request", "main", "-0", False),
    ("a pull request into dev", "pull_request", "dev", "0", False),
    ("a push to main", "push", "main", "0", False),
    ("the merge queue", "merge_group", "main", "0", False),
    ("no base at all", "pull_request", "", "0", False),
]


def selftest():
    failures = 0
    for label, event, base, ahead, want in CASES:
        got = is_promotion(event, base, ahead)
        if got != want:
            failures += 1
            print(f"FAIL {label}: got {got}, wanted {want}")
    if failures:
        print(f"release-promotion self-test: {failures} of {len(CASES)} cases FAILED")
        return 1
    print(f"release-promotion self-test: all {len(CASES)} cases pass")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--event", default="")
    parser.add_argument("--base-ref", default="")
    parser.add_argument("--ahead-by", default="", help="`ahead_by` of dev...head, as GitHub gave it")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    if is_promotion(args.event, args.base_ref, args.ahead_by):
        print("release promotion: base main, and the head commit is already in dev")
        return 0
    print(
        f"not a release promotion (event {args.event or 'none'}, base {args.base_ref or 'none'}, "
        f"ahead of dev by {args.ahead_by.strip() or 'unknown'})"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
