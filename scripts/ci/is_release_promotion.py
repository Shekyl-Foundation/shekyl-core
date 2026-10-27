#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Is this a release promotion: `main` receiving commits that are already in
`dev`, either as the pull request or as the push its merge makes?

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

Merging that pull request pushes to `main`, and the push runs the freeze
again with the previous `main` tip as its base: the same whole epoch, and
the same failure (the v3.1.0-alpha.10 and alpha.11 merges both went red on
`main`). The push is a promotion when:

  * the event is a push to `main`,
  * the pushed commit is a merge whose second parent, the pull request's
    head, is already in `dev`'s history: `dev...parent` is ahead by zero
    commits, and
  * the pushed commit's tree is that parent's tree, so the merge adds
    nothing `dev` did not already hold.

A pull request into `main` that was not a promotion still leaves a push
the freeze judges, and so does a promotion whose merge brought in content
of `main`'s own: its tree is not the parent's.

The caller asks GitHub for `ahead_by`, and on a push for the two trees,
and passes what it got. Anything that is not the integer 0 — a failed
request, an empty string, a commit the repository does not have — is "not
a promotion", and so is a push without `--tree-matches`: the exemption
fails closed, and the freeze runs.

Exit status: 0 = a promotion (skip the freeze); 1 = not one (run it).
`--selftest` runs the cases below.
"""

import argparse
import sys


def is_promotion(event, base_ref, ahead_by, tree_matches=False):
    """`base_ref` is the pull request's base, or the branch a push moved.

    On a push, `ahead_by` is the merged parent's distance from `dev`, and
    `tree_matches` says the pushed tree is that parent's.
    """
    in_dev = isinstance(ahead_by, str) and ahead_by.strip() == "0"
    if base_ref != "main":
        return False
    if event == "pull_request":
        return in_dev
    if event == "push":
        return in_dev and tree_matches is True
    return False


# (label, event, base or pushed branch, ahead_by, tree matches, promotion?)
CASES = [
    ("dev promoted to main, head in dev", "pull_request", "main", "0", False, True),
    ("a release branch cut at the freeze", "pull_request", "main", "0\n", False, True),
    ("a branch with two commits dev lacks", "pull_request", "main", "2", False, False),
    ("the compare request failed", "pull_request", "main", "", False, False),
    ("the reply was not a number", "pull_request", "main", "null", False, False),
    ("an error body in place of a number", "pull_request", "main", '{"message":"Not Found"}', False, False),
    ("a negative count is not zero", "pull_request", "main", "-0", False, False),
    ("a pull request into dev", "pull_request", "dev", "0", False, False),
    ("the merge queue", "merge_group", "main", "0", True, False),
    ("no base at all", "pull_request", "", "0", False, False),
    ("a promotion's merge pushed to main", "push", "main", "0", True, True),
    ("a merge whose tree differs, or was not compared", "push", "main", "0", False, False),
    ("a merged head with a commit dev lacks", "push", "main", "1", True, False),
    ("a push whose compare request failed", "push", "main", "", True, False),
    ("a push to dev", "push", "dev", "0", True, False),
    ("a push to no branch", "push", "", "0", True, False),
]


def selftest():
    failures = 0
    for label, event, base, ahead, trees, want in CASES:
        got = is_promotion(event, base, ahead, trees)
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
    parser.add_argument(
        "--base-ref", default="", help="the pull request's base, or the branch a push moved"
    )
    parser.add_argument(
        "--ahead-by",
        default="",
        help="`ahead_by` of dev...head (a pull request) or dev...merged parent (a push), as GitHub gave it",
    )
    parser.add_argument(
        "--tree-matches",
        action="store_true",
        help="a push: the pushed commit's tree is its merged parent's",
    )
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    if is_promotion(args.event, args.base_ref, args.ahead_by, args.tree_matches):
        if args.event == "push":
            print("release promotion: a push to main merging a dev commit, with that commit's tree")
        else:
            print("release promotion: base main, and the head commit is already in dev")
        return 0
    print(
        f"not a release promotion (event {args.event or 'none'}, base {args.base_ref or 'none'}, "
        f"ahead of dev by {args.ahead_by.strip() or 'unknown'}"
        + (f", tree matches: {'yes' if args.tree_matches else 'no'}" if args.event == "push" else "")
        + ")"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
