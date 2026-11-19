#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Which open pull requests a merge to `dev` makes stale, and what their
re-test runs (Brief C, ruled 2026-11-19).

# The question

A pull request is tested on its head merged onto the `dev` of its last
push. When another pull request merges first, the one still open was never
tested against it. Each is green alone; together they can be red (#1404 and
#1409, #1425 and #1426, #1440 and #1447).

# The shared tests

Both sides are scoped by `change_scope.py`'s own `rust_scope`, the decision
the Rust job's scope makes, so the two never disagree about what a file
belongs to. A side's **tests** are its changed packages and every member
that depends on one of them (nextest's `rdeps()`, what its CI runs). The
**shared tests** of a merge and a pull request are the tests in both: the
only tests whose result the two changes together can move. A test of a
member neither change reaches cannot change; a test only one reaches was
run by that one's own CI.

A merge **overlaps** a pull request when the shared tests are not empty
(`shared_tests`, the one definition). `all` on a side (the workspace
manifest, the lock, the toolchain, a path nothing claims) makes its tests
every member. A documentation-only side has none.

The shared tests are closed under `rdeps()` (an intersection of two closed
sets), so the re-test passes a few members whose `rdeps()` is the set as `rust_tests`
(`generators`), and nextest selects exactly the shared set.

# On demand (ruled 2026-11-19)

After a merge, an overlapping pull request is marked **stale**
(freshness_status.py) and no re-test runs. The re-test runs when the pull
request carries the `merge-next` label: when the label is added to a head
that is not fresh, and when a merge overlaps a head that carries it.

A re-test covers every merge since the head was last fresh (`since`), not
only the latest: its shared tests are the pull request's against the whole
`since..dev` diff. `since` is the `dev` of the head's last green, else the
merge base of the head with `dev` (the `dev` its own push was tested on;
`shekyl-push` merges `dev` before every push), and is carried in each status
until a green resets it.

FAILS CLOSED: an error answers "overlaps" with the pull request's whole own
scope, naming the reason, so a pull request is re-tested rather than
skipped.

# Use

    freshness_overlap.py --plan --base REF [--before SHA] [--pr N]
        freshness.yml's step, on a checkout of REF's `dev`. Without --pr, a
        push: `--before` is the `dev` it replaced; every open pull request
        on REF is judged. With --pr, the label: that one pull request.
        Drafts (their own run tests them when marked ready) and forks
        (their code would run with `dev`'s tokens) are left out. Writes
        `dev`, `marks` (each head to mark: stale, re-testing, or green with
        nothing shared) and `retests` (the re-test matrix) to
        $GITHUB_OUTPUT. Needs GITHUB_REPOSITORY and GH_TOKEN.
    freshness_overlap.py --merge SHA [--before SHA] --pr N:BASE:HEAD [--pr ...]
        the push to `dev` against each pull request (its number, a `dev`
        commit to measure it from, its head); one JSON object each
    freshness_overlap.py --replay FIRST SECOND
        two merge commits on `dev`: did the first overlap the second's pull
        request, and on which tests?
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
import freshness_status as fs  # noqa: E402

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


def tests_of(changed, rdeps):
    """A side's tests: its changed packages and their dependents."""
    return ALL if changed == ALL else rdeps(changed)


def shared_tests(merged, pr, rdeps):
    """The tests both changes reach. Not empty is what "overlaps" means."""
    if not merged or not pr:
        return set()
    a, b = tests_of(merged, rdeps), tests_of(pr, rdeps)
    if a == ALL:
        return b
    if b == ALL:
        return a
    return a & b


def generators(tests, rdeps):
    """Few members of a closed set `tests` whose `rdeps()` is the set again:
    the member reaching most first, then whatever it left. A
    dev-dependency may close a cycle, where no member is minimal, so this
    covers rather than looks for the bottom."""
    reach = {t: rdeps({t}) for t in tests}
    out, covered = set(), set()
    for t in sorted(tests, key=lambda t: (-len(reach[t]), t)):
        if t not in covered:
            out.add(t)
            covered |= reach[t]
    return out


def scope_values(tests, ws):
    """The re-test's `rust_tests` and `rust_doc_pkgs` for a shared set."""
    if tests == ALL:
        return "all", ""
    if not tests:
        return "none", ""
    mins = generators(tests, ws.rdeps)
    return cs.rust_tests_value(mins), cs.doc_pkgs(ws, mins)


def crates_named(merged, pr, ws):
    """The merge's changed packages the pull request's tests compile (its
    tests and everything they depend on): the crates a person reads in the
    status. Not the decision; `shared_tests` is."""
    if not merged or not pr:
        return []
    if merged == ALL:
        return [ALL]
    if pr == ALL:
        return sorted(merged)
    reach, stack = set(), list(ws.rdeps(pr))
    while stack:
        n = stack.pop()
        if n not in reach:
            reach.add(n)
            stack.extend(ws.deps.get(n, ()))
    return sorted(merged & reach)


def diff_files(base, head):
    out = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...{head}"], check=True, capture_output=True, text=True
    ).stdout
    return [f for f in out.splitlines() if f]


def merge_base(a, b):
    return subprocess.run(["git", "merge-base", a, b], check=True, capture_output=True, text=True).stdout.strip()


def merged_prs(before, merge):
    """The pull requests merged in `before..merge`, `#N` each, from the merge
    commits' subjects; a range with none is named by its commits."""
    if before == fs.UNKNOWN:
        return f"dev up to {merge[:10]}"
    subjects = subprocess.run(
        ["git", "log", "--format=%s", f"{before}..{merge}"], check=True, capture_output=True, text=True
    ).stdout.splitlines()
    numbers = [m.group(1) for m in (MERGE_SUBJECT.match(x) for x in subjects) if m]
    return " ".join(f"#{n}" for n in reversed(numbers)) or f"dev {before[:10]}..{merge[:10]}"


MERGE_SUBJECT = re.compile(r"^Merge pull request #(\d+) from ")


def since_for(current, head, dev):
    """The `dev` the head was last fresh against: carried by a status that
    is not green, the green's own `dev`, else the merge base of the head
    with `dev`. A status outside the grammar gives UNKNOWN."""
    if current is None:
        return merge_base(head, dev)
    if current["kind"] == "green":
        return resolve(current["dev"])
    if current["since"] == fs.UNKNOWN:
        return fs.UNKNOWN
    return resolve(current["since"])


def resolve(short_sha):
    return subprocess.run(["git", "rev-parse", "--verify", f"{short_sha}^{{commit}}"],
                          check=True, capture_output=True, text=True).stdout.strip()


def decide(event, labelled, kind, this_merge, cumulative):
    """The action for one pull request: 'stale', 'retest', 'fresh' (green
    without a run: nothing shared) or None.

    `kind` is the head's status (None, or freshness_status's kinds, '?'
    for one outside the grammar); `this_merge` the shared tests with the
    push alone, `cumulative` those with everything since the head was last
    fresh."""
    if event == "push":
        if not this_merge:
            return None
        if not labelled:
            return "stale"
        return "retest" if cumulative else "fresh"
    if event == "label":
        if kind in (None, "green"):
            return None
        return "retest" if cumulative else "fresh"
    raise ValueError(event)


def judge_pr(event, number, head, labelled, current, dev, before, ctx, merged_push):
    """One plan row, or None. Raises on anything it cannot read; the caller
    fails closed."""
    ws = ctx.workspace
    pr = changed_packages(diff_files(dev, head), ctx)
    this_merge = shared_tests(merged_push, pr, ws.rdeps) if event == "push" else set()
    if event == "push" and not this_merge:
        return None
    if event == "label" and (current is None or current["kind"] == "green"):
        return None
    since = since_for(current, head, dev)
    if event == "push" and not labelled:
        cumulative = this_merge
    elif since == fs.UNKNOWN:
        cumulative = tests_of(pr, ws.rdeps) if pr else set()
    else:
        cumulative = shared_tests(changed_packages(diff_files(since, dev), ctx), pr, ws.rdeps)
    action = decide(event, labelled, current and current["kind"], this_merge, cumulative)
    if action is None:
        return None
    if action == "stale":
        merged, named = merged_prs(before, dev), crates_named(merged_push, pr, ws)
        tests, docs = "none", ""
    else:
        merged_side = ALL if since == fs.UNKNOWN else changed_packages(diff_files(since, dev), ctx)
        merged, named = merged_prs(since, dev), crates_named(merged_side, pr, ws)
        tests, docs = scope_values(cumulative, ws)
    return {"pr": number, "head": head, "action": action, "since": since, "merged": merged, "crates": named,
            "rust_tests": tests, "rust_doc_pkgs": docs,
            "why": f"{action}: shares {tests if action != 'stale' else scope_values(this_merge, ws)[0]}"}


def fail_closed(number, head, labelled, why, since):
    """A pull request this script could not judge: stale, or re-tested on
    the widest scope when it carries the label."""
    return {"pr": number, "head": head, "action": "retest" if labelled else "stale", "since": since,
            "merged": "dev", "crates": [], "rust_tests": "all", "rust_doc_pkgs": "",
            "why": f"cannot decide ({why})"}


def gh_json(path):
    return json.loads(subprocess.run(["gh", "api", path], check=True, capture_output=True, text=True).stdout)


def gh_lines(path):
    out = subprocess.run(["gh", "api", "--paginate", path, "--jq", ".[]"], check=True, capture_output=True, text=True)
    return [json.loads(line) for line in out.stdout.splitlines() if line]


def plan(base_ref, before, only_pr):
    repo = os.environ["GITHUB_REPOSITORY"]
    dev = subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    event = "label" if only_pr else "push"
    # A push that created the branch has no `before` (all zeros).
    if not before or set(before) == {"0"}:
        before = f"{dev}^1"
    before = resolve(before) if event == "push" else before
    listed = [gh_json(f"repos/{repo}/pulls/{only_pr}")] if only_pr else \
        gh_lines(f"repos/{repo}/pulls?state=open&base={base_ref}&per_page=100")
    prs, skipped = [], []
    for p in listed:
        number = p["number"]
        if p["state"] != "open" or p["base"]["ref"] != base_ref:
            skipped.append((number, f"not open on {base_ref}"))
        elif p.get("draft"):
            skipped.append((number, "a draft: its own run tests it against `dev` when it is marked ready"))
        elif (p["head"].get("repo") or {}).get("full_name") != repo:
            skipped.append((number, "a fork: its code would run with `dev`'s tokens"))
        else:
            labelled = any(lb["name"] == fs.LABEL for lb in p.get("labels", []))
            prs.append((number, p["head"]["sha"], labelled))
    if prs:
        # By SHA: the head the listing saw, even if the branch moved since.
        subprocess.run(["git", "fetch", "--no-tags", "--quiet", "origin", *[h for _, h, _ in prs]], check=True)
    rows = []
    try:
        ctx = Context()
        merged_push = changed_packages(diff_files(before, dev), ctx) if event == "push" else set()
    except Exception as e:  # fail closed: every pull request is judged stale
        ctx, merged_push = None, ALL
        context_error = str(e)
    for number, head, labelled in prs:
        current = None
        try:
            current = fs.parse(fs.newest(fs.statuses(head)))
            if ctx is None:
                raise RuntimeError(context_error)
            row = judge_pr(event, number, head, labelled, current, dev, before, ctx, merged_push)
        except Exception as e:
            if event == "label" and current is not None and current["kind"] == "green":
                row = None
            else:
                since = current["since"] if current and current["kind"] not in ("green", "?") else fs.UNKNOWN
                row = fail_closed(number, head, labelled or event == "label", e, since)
        if row:
            rows.append(row)
        else:
            skipped.append((number, "fresh: nothing it tests changed" if event == "push" else "fresh: nothing to re-test"))
    retests = [{k: r[k] for k in ("pr", "head", "since", "merged", "crates", "rust_tests", "rust_doc_pkgs")}
               for r in rows if r["action"] == "retest"]
    title = f"Freshness after {merged_prs(before, dev)}" if event == "push" else f"Freshness on the {fs.LABEL} label"
    lines = [f"{title} (dev {dev[:10]}): {len(rows)} to mark, {len(retests)} re-test(s)", ""]
    lines += [f"- #{r['pr']} {r['head'][:10]}: {r['why']}" + (f" ({', '.join(r['crates'])})" if r["crates"] else "")
              for r in rows]
    lines += [f"- #{n}: {why}" for n, why in skipped]
    print("\n".join(lines))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    marks = [{k: r[k] for k in ("pr", "head", "action", "since", "merged", "crates")} for r in rows]
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
        f.write(f"dev={dev}\n")
        f.write(f"marks={json.dumps(marks)}\n")
        f.write(f"retests={json.dumps(retests)}\n")
    return 0


def run_merge(merge, prs, before=None):
    """The push against each (number, base, head): its shared tests."""
    out = []
    try:
        ctx = Context()
        merged = changed_packages(diff_files(before or f"{merge}^1", merge), ctx)
    except Exception as e:  # fail closed: every pull request overlaps
        return [{"pr": n, "head": h, "overlap": True, "crates": [], "rust_tests": "all", "rust_doc_pkgs": "",
                 "why": f"cannot decide ({e})"} for n, _, h in prs]
    for number, base, head in prs:
        try:
            pr = changed_packages(diff_files(base, head), ctx)
            shared = shared_tests(merged, pr, ctx.workspace.rdeps)
            tests, docs = scope_values(shared, ctx.workspace)
            out.append({"pr": number, "head": head, "overlap": bool(shared),
                        "crates": crates_named(merged, pr, ctx.workspace), "rust_tests": tests,
                        "rust_doc_pkgs": docs, "why": "shared tests" if shared else "no shared test"})
        except Exception as e:
            out.append({"pr": number, "head": head, "overlap": True, "crates": [], "rust_tests": "all",
                        "rust_doc_pkgs": "", "why": f"cannot decide ({e})"})
    return out


def replay(first, second):
    """Two merge commits on `dev`, in merge order: the second's pull request
    was open when the first merged. Its own files are its merge's diff."""
    return run_merge(first, [(0, f"{second}^1", second)], f"{first}^1")[0]


def selftest():
    """The shared-test rules on a small graph: core <- mid <- leaf, and an
    unrelated island; and the action for each state and event."""
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

    class Ws:
        pass

    ws = Ws()
    ws.deps, ws.rdeps = deps, rdeps
    failed = []
    for label, merged, pr, want in [
        # (merged, pr changed, expected shared tests)
        ("a merge to a dependency of the PR's crate", {"core"}, {"leaf"}, {"leaf"}),
        ("a merge to a dependent of the PR's crate", {"leaf"}, {"core"}, {"leaf"}),
        ("a merge to the PR's own crate", {"mid"}, {"mid"}, {"mid", "leaf"}),
        ("a merge to an unrelated crate", {"island"}, {"leaf"}, set()),
        ("a docs-only merge", set(), {"leaf"}, set()),
        ("a docs-only pull request", {"core"}, set(), set()),
        ("a merge that changes everything", ALL, {"island"}, {"island"}),
        ("a pull request that changes everything", {"mid"}, ALL, {"mid", "leaf"}),
        ("both change everything", ALL, ALL, ALL),
    ]:
        got = shared_tests(merged, pr, rdeps)
        if got != want:
            failed.append(f"shared_tests, {label}: {got} != {want}")
        # Overlap by the crates a person reads agrees with the decision.
        if bool(crates_named(merged, pr, ws)) != bool(got):
            failed.append(f"crates_named disagrees with shared_tests: {label}")
        # The generators select the shared set again.
        if got and got != ALL and rdeps(generators(got, rdeps)) != got:
            failed.append(f"generators, {label}: rdeps({generators(got, rdeps)}) != {got}")
    # A dev-dependency cycle (mid and leaf each need the other): the shared
    # set still has generators that select it.
    deps["mid"] = {"core", "leaf"}
    cyc = shared_tests({"mid"}, {"leaf"}, rdeps)
    if not cyc or rdeps(generators(cyc, rdeps)) != cyc:
        failed.append(f"generators, a dev-dependency cycle: {cyc} from {generators(cyc, rdeps)}")
    deps["mid"] = {"core"}
    # Cumulative: a merge to core, then one to the island, then the label.
    # The last merge alone shares nothing with a pull request on leaf; the
    # range since the head was fresh does.
    pr = {"leaf"}
    if shared_tests({"island"}, pr, rdeps) or shared_tests({"core", "island"}, pr, rdeps) != {"leaf"}:
        failed.append("cumulative: the range since the head was fresh is not what the re-test runs")
    # The state table.
    S = {"leaf"}
    for event, labelled, kind, this_merge, cumulative, want in [
        ("push", False, None, S, S, "stale"),
        ("push", False, "stale", S, S, "stale"),
        ("push", False, "green", S, S, "stale"),
        ("push", False, "red", S, S, "stale"),
        ("push", False, None, set(), set(), None),
        ("push", True, None, S, S, "retest"),
        ("push", True, "stale", S, S, "retest"),
        ("push", True, "re-testing", S, S, "retest"),
        ("push", True, "red", S, S, "retest"),
        ("push", True, "green", set(), set(), None),
        ("label", True, None, set(), S, None),
        ("label", True, "green", set(), S, None),
        ("label", True, "stale", set(), S, "retest"),
        ("label", True, "red", set(), S, "retest"),
        ("label", True, "re-testing", set(), S, "retest"),
        ("label", True, "?", set(), S, "retest"),
        ("label", True, "stale", set(), set(), "fresh"),
    ]:
        got = decide(event, labelled, kind, this_merge, cumulative)
        if got != want:
            failed.append(f"decide({event}, labelled={labelled}, {kind}): {got} != {want}")
    # Fail closed: a merge that cannot be read overlaps every pull request.
    broken = run_merge("not-a-commit", [(7, "x", "y")])
    if not (broken and broken[0]["overlap"] and broken[0]["rust_tests"] == "all"):
        failed.append(f"an unreadable merge did not fail closed: {broken}")
    row = fail_closed(7, "y", True, "boom", fs.UNKNOWN)
    if (row["action"], row["rust_tests"]) != ("retest", "all"):
        failed.append(f"a labelled pull request that cannot be judged: {row}")
    for f in failed:
        print(f"selftest FAIL: {f}")
    if not failed:
        print("selftest: shared tests, their generators, the cumulative range, the state table, "
              "and failing closed")
    return 1 if failed else 0


def main(argv):
    if "--selftest" in argv:
        return selftest()
    if "--replay" in argv:
        i = argv.index("--replay")
        first, second = argv[i + 1], argv[i + 2]
        print(json.dumps({"first": first, "second": second, **replay(first, second)}))
        return 0
    if "--plan" in argv:
        before = argv[argv.index("--before") + 1] if "--before" in argv else None
        pr = int(argv[argv.index("--pr") + 1]) if "--pr" in argv else None
        return plan(argv[argv.index("--base") + 1], before, pr)
    if "--merge" in argv:
        merge = argv[argv.index("--merge") + 1]
        before = argv[argv.index("--before") + 1] if "--before" in argv else None
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
