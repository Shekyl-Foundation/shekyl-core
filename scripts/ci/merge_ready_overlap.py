#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Which labelled pull requests a merge to `dev` reaches, and the tests their
`merge-ready` re-test runs (ruled 2026-11-19; merge_ready.py has the status).

# The question

A pull request is tested on its head merged onto the `dev` of its last
push. When another pull request merges first, the one still open was never
tested against it. Each is green alone; together they can be red (#1404 and
#1409, #1425 and #1426, #1440 and #1447). Two pull requests each re-tested
against the same `dev` at their labels and merged back to back are that
case too, so the label's re-test is not the end of it: each later merge
re-tests the labelled pull requests it reaches.

# The shared tests

Both sides are scoped by `change_scope.py`'s own `rust_scope`, the decision
the Rust job's scope makes, so the two never disagree about what a file
belongs to. A side's **tests** are its changed packages and every member
that depends on one of them (nextest's `rdeps()`, what its CI runs). The
**shared tests** of a merge and a pull request are the tests in both: the
only tests whose result the two changes together can move. A test of a
member neither change reaches cannot change; a test only one reaches was
run by that one's own CI.

A merge **reaches** a pull request when the shared tests are not empty
(`shared_tests`, the one definition). `all` on a side (the workspace
manifest, the lock, the toolchain, a path nothing claims) makes its tests
every member. A documentation-only side has none.

The shared tests are closed under `rdeps()` (an intersection of two closed
sets), so the re-test passes a few members whose `rdeps()` is the set as
`rust_tests` (`generators`), and nextest selects exactly the shared set.

# Since the last ready

A re-test runs the tests the pull request shares with everything merged
since its head was last ready (`since`), not only the merge that started
it: one re-test per pull request runs at a time, the newest, so a merge
whose own re-test a newer one cancelled is covered by the newer. `since` is
the `dev` of the head's last `ready`, else the merge base of the head with
`dev` (the `dev` its own push was tested on; `shekyl-push` merges `dev`
before every push), and is carried in each `re-testing` until a `ready`
resets it. The re-test computes its scope itself (`--scope`), against the
`dev` it merges, fetched when it starts: a re-test that starts later never
tests an older `dev`.

FAILS CLOSED: an error answers "reaches" with the pull request's whole own
scope, naming the reason, so a labelled pull request is re-tested rather
than skipped.

# Use

    merge_ready_overlap.py --plan --base REF --before SHA
        merge-ready-dev.yml's step, on a checkout of the pushed `dev`:
        every open pull request on REF that carries the `merge-ready` label
        and whose head passed its label check (merge_ready.PUSH_ACTS) is
        judged against the push; each one it reaches is set `re-testing`
        naming the merge, and its re-test is written to $GITHUB_OUTPUT as
        `legs`. Drafts and forks are left out. Needs GITHUB_REPOSITORY,
        GH_TOKEN and RUN_URL.
    merge_ready_overlap.py --scope --head SHA --dev SHA --since SHA
        the re-test's step, on the head merged with `dev`: writes
        `rust_tests`, `rust_doc_pkgs`, `merged` and `crates` to
        $GITHUB_OUTPUT.
    merge_ready_overlap.py --replay FIRST SECOND
        two merge commits on `dev`: did the first reach the second's pull
        request, and on which tests?
    merge_ready_overlap.py --selftest
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import change_scope as cs  # noqa: E402
import merge_ready as mr  # noqa: E402

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
    """The tests both changes reach. Not empty is what "reaches" means."""
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


MERGE_SUBJECT = re.compile(r"^Merge pull request #(\d+) from ")


def merged_prs(before, merge):
    """The pull requests merged in `before..merge`, `#N` each, from the merge
    commits' subjects; a range with none is named by its commits."""
    if before == mr.UNKNOWN:
        return f"dev up to {merge[:10]}"
    subjects = subprocess.run(
        ["git", "log", "--format=%s", f"{before}..{merge}"], check=True, capture_output=True, text=True
    ).stdout.splitlines()
    numbers = [m.group(1) for m in (MERGE_SUBJECT.match(x) for x in subjects) if m]
    return " ".join(f"#{n}" for n in reversed(numbers)) or f"dev {before[:10]}..{merge[:10]}"


def is_ancestor(a, b):
    return subprocess.run(["git", "merge-base", "--is-ancestor", a, b], capture_output=True).returncode == 0


def later(a, b, ancestor=is_ancestor):
    """The later of two `dev` commits: `b` when `a` is its ancestor."""
    return b if ancestor(a, b) else a


def resolve(short_sha):
    return subprocess.run(["git", "rev-parse", "--verify", f"{short_sha}^{{commit}}"],
                          check=True, capture_output=True, text=True).stdout.strip()


def since_for(current, head, dev, base=None, res=resolve, lat=later):
    """The `dev` the head was last ready against: a `ready`'s own `dev`, a
    `re-testing` or `red`'s carried `since`, else the merge base of the
    head with `dev`; never earlier than that merge base, which the head's
    own run tested. A status outside the grammar gives UNKNOWN."""
    base = base or merge_base(head, dev)
    kind = current and current["kind"]
    if kind in (None, "waiting", "checking", "refused"):
        return base
    if kind == "?":
        return mr.UNKNOWN
    if kind == "ready":
        return lat(res(current["dev"]), base)
    if current["since"] == mr.UNKNOWN:
        return mr.UNKNOWN
    return lat(res(current["since"]), base)


def label_row(number, head, dev, ctx):
    """The label's plan for one pull request whose label passed: 'ready'
    when it shares no test with the merges since its merge base, else
    'retest'. Raises on anything it cannot read; the caller fails closed."""
    since = merge_base(head, dev)
    shared = shared_tests(changed_packages(diff_files(since, dev), ctx),
                          changed_packages(diff_files(dev, head), ctx), ctx.workspace.rdeps)
    return {"pr": number, "head": head, "action": "retest" if shared else "ready", "since": since,
            "merged": merged_prs(since, dev), "why": f"shares {scope_values(shared, ctx.workspace)[0]}"}


def push_row(number, head, current, dev, before, ctx, merged_push):
    """A push's plan for one labelled pull request: a re-test row when the
    push reaches it, else None. Raises on anything it cannot read; the
    caller fails closed."""
    ws = ctx.workspace
    pr = changed_packages(diff_files(dev, head), ctx)
    # The push reaches the head only past what the head already holds: a
    # head that merged this `dev`, or part of the push, was tested on it by
    # its own run.
    start = later(before, merge_base(head, dev))
    if start != before:
        merged_push = changed_packages(diff_files(start, dev), ctx) if start != dev else set()
    this_merge = shared_tests(merged_push, pr, ws.rdeps)
    if not this_merge:
        return None
    return {"pr": number, "head": head, "since": since_for(current, head, dev), "merged": merged_prs(before, dev),
            "crates": crates_named(merged_push, pr, ws), "why": f"shares {scope_values(this_merge, ws)[0]}"}


def fail_closed(number, head, why, since):
    """A labelled pull request this script could not judge: re-tested on its
    whole scope."""
    return {"pr": number, "head": head, "action": "retest", "since": since, "merged": "dev", "crates": [],
            "why": f"cannot decide ({why})"}


def gh_lines(path):
    out = subprocess.run(["gh", "api", "--paginate", path, "--jq", ".[]"], check=True, capture_output=True, text=True)
    return [json.loads(line) for line in out.stdout.splitlines() if line]


def plan(base_ref, before):
    """A push to `dev`: re-test the labelled pull requests it reaches."""
    repo = os.environ["GITHUB_REPOSITORY"]
    run_url = os.environ["RUN_URL"]
    dev = subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    # A push that created the branch has no `before` (all zeros).
    if not before or set(before) == {"0"}:
        before = f"{dev}^1"
    before = resolve(before)
    prs, skipped = [], []
    for p in gh_lines(f"repos/{repo}/pulls?state=open&base={base_ref}&per_page=100"):
        number = p["number"]
        if not any(lb["name"] == mr.LABEL for lb in p.get("labels", [])):
            continue  # untouched: no label, no re-test (ruled 2026-11-19)
        if p.get("draft"):
            skipped.append((number, "a draft: the label is refused on a draft"))
        elif (p["head"].get("repo") or {}).get("full_name") != repo:
            skipped.append((number, "a fork: its code would run with `dev`'s tokens"))
        else:
            prs.append((number, p["head"]["sha"]))
    if prs:
        # By SHA: the head the listing saw, even if the branch moved since.
        subprocess.run(["git", "fetch", "--no-tags", "--quiet", "origin", *[h for _, h in prs]], check=True)
    try:
        ctx = Context()
        merged_push = changed_packages(diff_files(before, dev), ctx)
        context_error = None
    except Exception as e:  # fail closed: every labelled pull request is re-tested on its whole scope
        ctx, merged_push, context_error = None, ALL, str(e)
    legs = []
    for number, head in prs:
        sts = mr.statuses(head)
        current = mr.parse(mr.newest(sts))
        kind = current and current["kind"]
        if kind not in mr.PUSH_ACTS:
            skipped.append((number, f"{mr.CONTEXT} is {kind}: its label run decides"))
            continue
        try:
            if ctx is None:
                raise RuntimeError(context_error)
            row = push_row(number, head, current, dev, before, ctx, merged_push)
        except Exception as e:
            row = fail_closed(number, head, e, current["since"] if kind == "re-testing" else mr.UNKNOWN)
        if row is None:
            skipped.append((number, "shares no test with the push: untouched"))
            continue
        if not mr.may_post(current, run_url, dev, "mark", lambda t: mr.dev_is_newer_than(t, dev)):
            skipped.append((number, f"{mr.CONTEXT} is held by a newer dev's run"))
            continue
        mr.post_kind(head, "re-testing", f"after {row['merged']}: {', '.join(row['crates']) or 'see the run'}",
                     dev, row["since"])
        legs.append({k: row[k] for k in ("pr", "head", "since", "merged")})
        print(f"- #{number} {head[:10]}: re-test ({row['why']})")
    lines = [f"merge-ready after {merged_prs(before, dev)} (dev {dev[:10]}): {len(legs)} re-test(s)", ""]
    lines += [f"- #{r['pr']} {r['head'][:10]}: re-test since {r['since'][:10]}" for r in legs]
    lines += [f"- #{n}: {why}" for n, why in skipped]
    print("\n".join(lines))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    mr.output("legs", json.dumps(legs))
    return 0


def scope(head, dev, since):
    """The re-test's own scope, against the `dev` it merged: the tests the
    pull request shares with everything merged since `since`."""
    try:
        ctx = Context()
        ws = ctx.workspace
        pr = changed_packages(diff_files(dev, head), ctx)
        merged_side = ALL if since == mr.UNKNOWN else changed_packages(diff_files(since, dev), ctx)
        shared = tests_of(pr, ws.rdeps) if since == mr.UNKNOWN and pr else shared_tests(merged_side, pr, ws.rdeps)
        tests, docs = scope_values(shared, ws)
        merged, crates = merged_prs(since, dev), ", ".join(crates_named(merged_side, pr, ws))
    except Exception as e:  # fail closed: every test
        tests, docs, merged, crates = "all", "", f"dev up to {dev[:10]}", f"(scope unread: {e})"
    print(f"scope: {tests} (docs: {docs or 'none'}); merged {merged}; crates {crates or 'none'}")
    for key, value in (("rust_tests", tests), ("rust_doc_pkgs", docs), ("merged", merged), ("crates", crates)):
        mr.output(key, value)
    return 0


def run_merge(merge, prs, before=None):
    """The push against each (number, base, head): its shared tests."""
    out = []
    try:
        ctx = Context()
        merged = changed_packages(diff_files(before or f"{merge}^1", merge), ctx)
    except Exception as e:  # fail closed: every pull request is reached
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
    unrelated island; `since` for each status; failing closed."""
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
        if bool(crates_named(merged, pr, ws)) != bool(got):
            failed.append(f"crates_named disagrees with shared_tests: {label}")
        if got and got != ALL and rdeps(generators(got, rdeps)) != got:
            failed.append(f"generators, {label}: rdeps({generators(got, rdeps)}) != {got}")
    deps["mid"] = {"core", "leaf"}
    cyc = shared_tests({"mid"}, {"leaf"}, rdeps)
    if not cyc or rdeps(generators(cyc, rdeps)) != cyc:
        failed.append(f"generators, a dev-dependency cycle: {cyc} from {generators(cyc, rdeps)}")
    deps["mid"] = {"core"}
    # Since the last ready: a merge to core whose re-test a merge to the
    # island cancelled. The island alone shares nothing with a pull request
    # on leaf; the range since the last ready does, so the newer re-test
    # runs what the cancelled one would have.
    pr = {"leaf"}
    if shared_tests({"island"}, pr, rdeps) or shared_tests({"core", "island"}, pr, rdeps) != {"leaf"}:
        failed.append("since the last ready: the range is not what the re-test runs")
    # `since` for each status. First-parent order on dev: a, b, c.
    chain = ["a", "b", "c"]

    def anc(x, y):
        return chain.index(x) <= chain.index(y)

    def st(kind, dev=None, since=None):
        return {"kind": kind, "dev": dev, "since": since, "url": ""}

    for label, cur, base, want in [
        ("no status: the merge base", None, "a", "a"),
        ("checking: the merge base", st("checking"), "a", "a"),
        ("ready: its own dev", st("ready", "b", "a"), "a", "b"),
        ("ready before the head merged a newer dev: the merge base", st("ready", "a", "a"), "b", "b"),
        ("re-testing: the carried since", st("re-testing", "c", "b"), "a", "b"),
        ("red: the carried since", st("red", "c", "a"), "a", "a"),
        ("re-testing with an unknown since", st("re-testing", "c", mr.UNKNOWN), "a", mr.UNKNOWN),
        ("outside the grammar: unknown", st("?"), "a", mr.UNKNOWN),
    ]:
        got = since_for(cur, "h", "c", base, res=lambda x: x, lat=lambda x, y: later(x, y, anc))
        if got != want:
            failed.append(f"since_for, {label}: {got} != {want}")
    # The push's range starts at the later of `before` and what the head
    # already holds: a head that merged the pushed `dev` gets nothing.
    for label, before, base, want in [
        ("a head behind the push", "b", "a", "b"),
        ("a head that merged the pushed dev", "b", "c", "c"),
        ("a head that merged part of the push", "a", "b", "b"),
    ]:
        if later(before, base, anc) != want:
            failed.append(f"later, {label}: {later(before, base, anc)} != {want}")
    # The kinds a push re-tests: only a head whose label passed its check.
    if set(mr.PUSH_ACTS) != {"checking", "re-testing", "ready"}:
        failed.append(f"PUSH_ACTS: {mr.PUSH_ACTS}")
    # Fail closed.
    broken = run_merge("not-a-commit", [(7, "x", "y")])
    if not (broken and broken[0]["overlap"] and broken[0]["rust_tests"] == "all"):
        failed.append(f"an unreadable merge did not fail closed: {broken}")
    row = fail_closed(7, "y", "boom", mr.UNKNOWN)
    if (row["action"], row["since"]) != ("retest", mr.UNKNOWN):
        failed.append(f"a labelled pull request that cannot be judged: {row}")
    for f in failed:
        print(f"selftest FAIL: {f}")
    if not failed:
        print("selftest: shared tests, their generators, the range since the last ready, `since` for each status, "
              "the kinds a push re-tests, and failing closed")
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
        return plan(argv[argv.index("--base") + 1], before)
    if "--scope" in argv:
        def arg(name):
            return argv[argv.index(name) + 1]
        return scope(arg("--head"), arg("--dev"), arg("--since"))
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
