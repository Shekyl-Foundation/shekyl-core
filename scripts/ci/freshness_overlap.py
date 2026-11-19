#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Which open pull requests a merge to `dev` can break (Brief C, option (a)).

# The question

A pull request is tested on its head merged onto the `dev` of its last
push. When another pull request merges first, the one still open was never
tested against it. Each is green alone; together they can be red (#1404 and
#1409, #1425 and #1426, #1440 and #1447). After every merge to `dev`, the
freshness workflow asks this script which open pull requests overlap the
merge, and re-tests exactly those against the new `dev`.

# Overlap

Both sides are scoped by `change_scope.py`'s own `rust_scope`, the decision
the Rust job's scope makes, so the two never disagree about what a file
belongs to:

  - the merge's **changed** packages: the members its files are in, and the
    members that read a changed non-Rust file (a fixture, a packaged config,
    a workflow a test parses);
  - an open pull request's **closure**: its changed packages, every member
    that depends on one of them (the packages its CI tests, nextest's
    `rdeps()`), and everything those depend on (the code its tests compile).

They overlap when the merge changed a package in the pull request's
closure. `all` on either side (the workspace manifest, the lock, the
toolchain, a path nothing claims) overlaps every pull request that tests
anything. A documentation-only side overlaps nothing.

FAILS CLOSED: any error answers "overlaps", naming the reason, so a pull
request is re-tested rather than skipped.

# Use

    freshness_overlap.py --merge SHA [--before SHA] --pr N:BASE:HEAD [--pr ...]
        the push to `dev` (`--before` is the `dev` it replaced, by default
        the merge's first parent) against each open pull request, given as
        its number, a `dev` commit to measure it from and its head; prints
        one JSON object per pull request: its overlap, the shared crates,
        and the scope its re-test runs (`rust_tests`, `rust_doc_pkgs`)

# The re-test's scope

As ruled, the pull request's own: what its own Rust job would run on its
head merged with the new `dev` (`change_scope.py`'s `rust_tests` and
`rust_doc_pkgs` for the same files), so the re-test is the run it would
have had, had it been pushed after the merge.
    freshness_overlap.py --plan --merge SHA [--before SHA] --base REF
        the freshness workflow's step: lists the open pull requests on REF,
        leaves out drafts (their own run tests them when marked ready) and
        forks (their code would run in a push run on `dev`), fetches the
        heads, judges each, and writes `retests` (a JSON list) and `merged`
        (the merged pull requests, `#N` each) to $GITHUB_OUTPUT. Needs
        GITHUB_REPOSITORY and GH_TOKEN.
    freshness_overlap.py --replay FIRST SECOND
        two merge commits on `dev`: was the second's pull request overlapping
        when the first merged?
    freshness_overlap.py --selftest
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import change_scope as cs  # noqa: E402

ALL = "all"


class Context:
    """The tree-wide inputs `rust_scope` needs, read once."""

    def __init__(self, workspace=None):
        self.trees = cs.docs_consumer_trees(cs.consuming_workflow_text())
        self.inputs = cs.Inputs(cs.consumer_files())
        self.workspace = workspace or cs.Workspace.read()
        self.owners = cs.read_owners()
        self.workflows = sorted(
            w for w in cs.git("ls-files", cs.WORKFLOW_DIR).splitlines() if w.endswith((".yml", ".yaml"))
        )


def changed_packages(files, ctx):
    """The packages `files` change, by the Rust job's own scope: a set, ALL,
    or the empty set for a change that tests nothing."""
    docs_only, _ = cs.classify(files, ctx.inputs, ctx.trees)
    if docs_only:
        return set()
    _, tests, _ = cs.rust_scope(files, ctx.inputs, ctx.trees, ctx.workspace, ctx.owners, ctx.workflows)
    if tests == "all":
        return ALL
    if tests == "none":
        return set()
    return set(tests)


def closure(changed, deps, rdeps):
    """What a pull request's tests reach: its changed packages, their
    dependents (what its CI tests) and everything those depend on."""
    if changed == ALL:
        return ALL
    tested = rdeps(changed)
    out, stack = set(tested), list(tested)
    while stack:
        for dep in deps.get(stack.pop(), ()):
            if dep not in out:
                out.add(dep)
                stack.append(dep)
    return out


def overlap(merged, reach):
    """The packages the merge changed inside the pull request's reach; a
    non-empty answer means re-test."""
    if not merged or not reach:
        return set()
    if merged == ALL:
        return {ALL}
    if reach == ALL:
        return set(merged)
    return merged & reach


def diff_files(base, head):
    out = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...{head}"], check=True, capture_output=True, text=True
    ).stdout
    return [f for f in out.splitlines() if f]


def judge(merged_files, pr_files, ctx):
    ws = ctx.workspace
    merged = changed_packages(merged_files, ctx)
    reach = closure(changed_packages(pr_files, ctx), ws.deps, ws.rdeps)
    return sorted(overlap(merged, reach))


def retest_scope(pr_files, ctx):
    """The re-test's `rust_tests` and `rust_doc_pkgs`: the pull request's
    own scope, as its Rust job computes it."""
    docs_only, _ = cs.classify(pr_files, ctx.inputs, ctx.trees)
    if docs_only:
        return "none", ""
    _, tests, _ = cs.rust_scope(pr_files, ctx.inputs, ctx.trees, ctx.workspace, ctx.owners, ctx.workflows)
    return cs.rust_tests_value(tests), cs.doc_pkgs(ctx.workspace, tests)


# The widest re-test, for a pull request this script could not judge.
FAIL_CLOSED_SCOPE = {"rust_tests": "all", "rust_doc_pkgs": ""}


def run_merge(merge, prs, before=None):
    out = []
    try:
        ctx = Context()
        merged_files = diff_files(before or f"{merge}^1", merge)
    except Exception as e:  # fail closed: every pull request is re-tested
        for number, _, head in prs:
            out.append({"pr": number, "head": head, "overlap": True, "crates": [], "why": f"cannot decide ({e})",
                        **FAIL_CLOSED_SCOPE})
        return out
    for number, base, head in prs:
        try:
            pr_files = diff_files(base, head)
            crates = judge(merged_files, pr_files, ctx)
            tests, docs = retest_scope(pr_files, ctx)
            out.append({"pr": number, "head": head, "overlap": bool(crates), "crates": crates,
                        "why": "the merge changed a crate this pull request's tests reach" if crates else "no shared crate",
                        "rust_tests": tests, "rust_doc_pkgs": docs})
        except Exception as e:
            out.append({"pr": number, "head": head, "overlap": True, "crates": [], "why": f"cannot decide ({e})",
                        **FAIL_CLOSED_SCOPE})
    return out


def merged_prs(before, merge):
    """The pull requests the push merged, `#N` each, from the merge commits'
    subjects; a push with none is named by its commit."""
    subjects = subprocess.run(
        ["git", "log", "--format=%s", f"{before}..{merge}"], check=True, capture_output=True, text=True
    ).stdout.splitlines()
    numbers = [m.group(1) for m in (MERGE_SUBJECT.match(x) for x in subjects) if m]
    return " ".join(f"#{n}" for n in reversed(numbers)) or f"dev {merge[:10]}"


MERGE_SUBJECT = re.compile(r"^Merge pull request #(\d+) from ")


def gh_lines(path):
    out = subprocess.run(["gh", "api", "--paginate", path, "--jq", ".[]"], check=True, capture_output=True, text=True)
    return [json.loads(line) for line in out.stdout.splitlines() if line]


def plan(merge, before, base_ref):
    repo = os.environ["GITHUB_REPOSITORY"]
    # A push that created the branch has no `before` (all zeros).
    if not before or set(before) == {"0"}:
        before = f"{merge}^1"
    prs, skipped = [], []
    for p in gh_lines(f"repos/{repo}/pulls?state=open&base={base_ref}&per_page=100"):
        number = p["number"]
        if p.get("draft"):
            skipped.append((number, "a draft: its own run tests it against `dev` when it is marked ready"))
        elif (p["head"].get("repo") or {}).get("full_name") != repo:
            skipped.append((number, "a fork: its code would run in a push run on `dev`"))
        else:
            prs.append((number, merge, p["head"]["sha"]))
    if prs:
        # By SHA: the head the listing saw, even if the branch moved since.
        subprocess.run(["git", "fetch", "--no-tags", "--quiet", "origin", *[h for _, _, h in prs]], check=True)
    rows = run_merge(merge, prs, before) if prs else []
    merged = merged_prs(before, merge)
    retests = [{k: r[k] for k in ("pr", "head", "crates", "rust_tests", "rust_doc_pkgs")} for r in rows if r["overlap"]]
    lines = [f"Freshness after {merged} ({merge[:10]}), {len(retests)} re-test(s):", ""]
    lines += [f"- #{r['pr']} {r['head'][:10]}: {'re-test' if r['overlap'] else 'no re-test'}: {r['why']}"
              + (f" ({', '.join(r['crates'])})" if r["crates"] else "") for r in rows]
    lines += [f"- #{n}: not re-tested: {why}" for n, why in skipped]
    print("\n".join(lines))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
        f.write(f"retests={json.dumps(retests)}\n")
        f.write(f"merged={merged}\n")
    return 0


def replay(first, second):
    """Two merge commits on `dev`, in merge order: the second's pull request
    was open when the first merged. Its own files are its merge's diff."""
    ctx = Context()
    crates = judge(diff_files(f"{first}^1", first), diff_files(f"{second}^1", second), ctx)
    return crates


def selftest():
    """The closure and overlap rules on a small graph: core <- mid <- leaf,
    and an unrelated island."""
    deps = {"core": set(), "mid": {"core"}, "leaf": {"mid"}, "island": set()}

    def rdeps(names):
        out, grew = set(names), True
        while grew:
            grew = False
            for name, ds in deps.items():
                if name not in out and ds & out:
                    out.add(name)
                    grew = True
        return out

    cases = [
        # (merged, pr changed, expected overlap)
        ("a merge to a dependency of the PR's crate", {"core"}, {"leaf"}, {"core"}),
        ("a merge to a dependent of the PR's crate", {"leaf"}, {"core"}, {"leaf"}),
        ("a merge to the PR's own crate", {"mid"}, {"mid"}, {"mid"}),
        ("a merge to an unrelated crate", {"island"}, {"leaf"}, set()),
        ("a docs-only merge", set(), {"leaf"}, set()),
        ("a docs-only pull request", {"core"}, set(), set()),
        ("a merge that changes everything", ALL, {"island"}, {ALL}),
        ("a pull request that changes everything", {"island"}, ALL, {"island"}),
    ]
    failed = 0
    for label, merged, pr, want in cases:
        got = overlap(merged, closure(pr, deps, rdeps))
        if got != want:
            print(f"selftest FAIL: {label}: {sorted(got)} != {sorted(want)}")
            failed = 1
    # Fail closed: a context that cannot be read re-tests every pull request.
    broken = run_merge("not-a-commit", [(7, "x", "y")])
    if not (broken and broken[0]["overlap"] and "cannot decide" in broken[0]["why"]):
        print(f"selftest FAIL: an unreadable merge did not fail closed: {broken}")
        failed = 1
    if not failed:
        print(f"selftest: {len(cases)} overlap cases, and an unreadable merge fails closed")
    return failed


def main(argv):
    if "--selftest" in argv:
        return selftest()
    if "--replay" in argv:
        i = argv.index("--replay")
        first, second = argv[i + 1], argv[i + 2]
        crates = replay(first, second)
        print(json.dumps({"first": first, "second": second, "overlap": bool(crates), "crates": crates}))
        return 0
    if "--merge" in argv:
        merge = argv[argv.index("--merge") + 1]
        before = argv[argv.index("--before") + 1] if "--before" in argv else None
        if "--plan" in argv:
            return plan(merge, before, argv[argv.index("--base") + 1])
        prs = []
        for i, a in enumerate(argv):
            if a == "--pr":
                number, base, head = argv[i + 1].split(":")
                prs.append((int(number), base, head))
        for row in run_merge(merge, prs, before):
            print(json.dumps(row))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
