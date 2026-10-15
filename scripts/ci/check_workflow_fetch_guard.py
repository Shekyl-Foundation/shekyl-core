# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# A workflow step that changes the repository's depth runs only under
# GitHub Actions.
#
# `git fetch --depth=1 origin <base>` is a setup step in CI: the runner's
# checkout is a disposable shallow clone, and the step fetches the one base
# commit a ratchet compares against. Run on a developer's clone, the same
# command writes `.git/shallow` and cuts the history of the shared object
# store. Every worktree reads that store, so one local gate run truncates
# `git log` and `merge-base` for every lane on the machine. On 2026-10-15 a
# local run of `doc-claims.yml`'s steps did exactly that for thirty minutes,
# and only the measurement-ledger gate's "shares no history" noticed.
#
# The guard goes on the setup step, never on the check, so the check runs
# the same everywhere:
#
#     if [ "${GITHUB_ACTIONS:-}" != "true" ]; then
#       echo "...: not under GitHub Actions; ..."
#       exit 0
#     fi
#
# This gate parses every workflow, joins each `run:` body's continuation
# lines, and refuses a step whose body runs a depth-changing git command
# (`fetch` with `--depth`, `--deepen`, `--unshallow` or `--shallow-*`, and
# `git pull` with the same) unless the guard opens the body before it. A
# rule with no check is a convention.
#
# Instance of 47-gate-subject-assertion.mdc: an empty workflows directory,
# or an unimportable parser, fails rather than passing quietly.

from __future__ import annotations

import os
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - exercised by the CI image
    print(
        "workflow fetch guard: PyYAML is not importable, so no workflow was "
        "checked. Install python3-yaml rather than letting an absent parser "
        "read as a pass.",
        file=sys.stderr,
    )
    raise SystemExit(2)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")

DEPTH_COMMAND = re.compile(
    r"\bgit\s+(?:fetch|pull)\b[^\n]*?"
    r"--(?:depth|deepen|unshallow|shallow-since|shallow-exclude)\b"
)
GUARD = re.compile(r'^\s*if \[ "\$\{GITHUB_ACTIONS:-\}" != "true" \]; then\s*$', re.M)
GUARD_EXIT = re.compile(r"^\s*exit 0\s*$", re.M)
GUARD_END = re.compile(r"^\s*fi\s*$", re.M)


def joined(body: str) -> str:
    """The body with shell line continuations folded onto one line."""
    return re.sub(r"\\\n\s*", " ", body)


def guarded_before(body: str, at: int) -> bool:
    """Whether the guard opens, exits 0 and closes before offset `at`."""
    opener = GUARD.search(body)
    if opener is None or opener.start() > at:
        return False
    end = GUARD_END.search(body, opener.end())
    if end is None or end.start() > at:
        return False
    return GUARD_EXIT.search(body, opener.end(), end.start()) is not None


def findings(workflows: dict[str, object]) -> tuple[list[str], int]:
    """(problems, depth-changing steps seen) over `{path: parsed workflow}`."""
    problems: list[str] = []
    seen = 0
    for path, doc in sorted(workflows.items()):
        jobs = doc.get("jobs") if isinstance(doc, dict) else None
        for job_name, job in (jobs or {}).items():
            for index, step in enumerate((job or {}).get("steps") or []):
                run = step.get("run") if isinstance(step, dict) else None
                if not isinstance(run, str):
                    continue
                body = joined(run)
                command = DEPTH_COMMAND.search(body)
                if command is None:
                    continue
                seen += 1
                if not guarded_before(body, command.start()):
                    label = step.get("name") or f"step {index}"
                    problems.append(
                        f"{path}: job `{job_name}`, step `{label}` runs "
                        f"`{command.group(0).strip()}` without the "
                        "GITHUB_ACTIONS guard before it"
                    )
    return problems, seen


def load_tree() -> dict[str, object]:
    if not os.path.isdir(WORKFLOWS):
        print(f"workflow fetch guard: no {WORKFLOWS}: no subject", file=sys.stderr)
        raise SystemExit(2)
    docs: dict[str, object] = {}
    for name in sorted(os.listdir(WORKFLOWS)):
        if name.endswith((".yml", ".yaml")):
            with open(os.path.join(WORKFLOWS, name), encoding="utf-8") as f:
                docs[f".github/workflows/{name}"] = yaml.safe_load(f)
    if not docs:
        print("workflow fetch guard: no workflow files: no subject", file=sys.stderr)
        raise SystemExit(2)
    return docs


GUARD_TEXT = (
    'if [ "${GITHUB_ACTIONS:-}" != "true" ]; then\n'
    '  echo "not under GitHub Actions; skipped"\n'
    "  exit 0\n"
    "fi\n"
)


def selftest() -> int:
    def wf(run: str) -> dict[str, object]:
        return {"w.yml": {"jobs": {"j": {"steps": [{"name": "s", "run": run}]}}}}

    cases = [
        ("guarded fetch passes", wf(GUARD_TEXT + "git fetch --depth=1 origin x\n"), 0, 1),
        ("unguarded fetch refused", wf("git fetch --no-tags --depth=1 origin x\n"), 1, 1),
        (
            "continued fetch line refused",
            wf("git fetch --no-tags \\\n  --depth=1 origin x\n"),
            1,
            1,
        ),
        ("unshallow refused", wf("git fetch --unshallow origin\n"), 1, 1),
        ("pull --depth refused", wf("git pull --depth 5\n"), 1, 1),
        (
            "guard after the fetch refused",
            wf("git fetch --depth=1 origin x\n" + GUARD_TEXT),
            1,
            1,
        ),
        (
            "guard without exit 0 refused",
            wf('if [ "${GITHUB_ACTIONS:-}" != "true" ]; then\n  echo hi\nfi\n'
               "git fetch --depth=1 origin x\n"),
            1,
            1,
        ),
        ("plain fetch is not this gate's", wf("git fetch origin dev\n"), 0, 0),
        ("uses-only step ignored", {"w.yml": {"jobs": {"j": {"steps": [{"uses": "x"}]}}}}, 0, 0),
    ]
    failed = 0
    for label, docs, want_problems, want_seen in cases:
        problems, seen = findings(docs)
        if len(problems) != want_problems or seen != want_seen:
            failed += 1
            print(f"selftest FAIL: {label}: {len(problems)} problem(s), {seen} seen")
    print(f"workflow fetch guard self-test: {len(cases) - failed} / {len(cases)} cases pass")
    return 1 if failed else 0


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    problems, seen = findings(load_tree())
    for problem in problems:
        print(f"FAIL: {problem}")
    if problems:
        print(
            "A depth-changing fetch makes a developer's shared clone shallow when "
            "the step is run locally. Open its run body with the GITHUB_ACTIONS "
            "guard (this script's header)."
        )
        return 1
    print(f"workflow fetch guard: {seen} depth-changing step(s), every one guarded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
