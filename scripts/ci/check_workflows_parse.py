# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Workflow-file validity gate.
#
# Every file under .github/workflows/ must parse as YAML and be shaped like
# a workflow (name / on / jobs, each job with steps or a reusable `uses`).
#
# Why this is a gate and not a lint nicety: a workflow file GitHub cannot
# parse does not produce a failing job. It produces a run with **zero jobs**
# and the opaque banner "This run likely failed because of a workflow file
# issue" — attributed to the push, whatever the file's own `on:` says,
# because the triggers are unreadable too. Every gate that file carried is
# disarmed, and no named check goes red to say so. That is how an unquoted
# step name (`- name: Run FOLLOWUPS Target: check` — the colon-space opens
# a nested mapping) took the documentation-lifecycle gate set offline; the
# point fix was 97efe832d, this is the class.
#
# Scope, stated honestly: on a `pull_request` the checkout is the merge
# result, so this sees the tree that would land — which is the tree that
# matters, since that is what can carry a broken workflow into dev. A
# branch merely *behind* a fix inherits the fixed file in that merge and
# is not this gate's subject; its cure is merging base, not a check.
#
# `.disabled` files are checked too: a disabled workflow is a workflow
# waiting to be renamed back, and re-enabling one is exactly when nobody
# re-reads it.
#
# Instance of 47-gate-subject-assertion.mdc twice over: an empty or missing
# workflows directory is a missing subject, and an unimportable YAML parser
# is a missing instrument — both fail, neither passes quietly.

from __future__ import annotations

import os
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - exercised by the CI image, not tests
    print(
        "workflow parse: PyYAML is not importable, so no workflow was "
        "checked. Install python3-yaml (the grep-gates job does) rather "
        "than letting an absent parser read as a pass.",
        file=sys.stderr,
    )
    raise SystemExit(2)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")


class StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate mapping keys.

    PyYAML keeps the last value and says nothing; GitHub rejects the file.
    Validating only the surviving value would let this gate PASS a workflow
    Actions will not run — the precise false negative it exists to prevent,
    and the more dangerous direction of error for a gate.
    """


def _construct_mapping_no_duplicates(loader: StrictLoader, node, deep: bool = False):
    mapping: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping_no_duplicates,
)


# Exactly what GitHub executes (`.yml`/`.yaml` directly under
# .github/workflows/) plus the parked forms of the same. Suffixes, not a
# substring: a committed editor artifact (`doc-links.yml.bak`, `...yml~`) is
# a hygiene problem, not a workflow, and failing it here would report
# "not a valid workflow" about a file nobody meant to be one.
WORKFLOW_SUFFIXES = (".yml", ".yaml", ".yml.disabled", ".yaml.disabled")


def is_workflow_file(name: str) -> bool:
    """Live `.yml`/`.yaml` plus the `.disabled` variants parked beside them."""
    return name.endswith(WORKFLOW_SUFFIXES)


def check_one(path: str, doc: object) -> list[str]:
    """Structural checks for a parsed document. Returns problem strings."""
    problems: list[str] = []
    if not isinstance(doc, dict):
        return [f"{path}: top level is {type(doc).__name__}, expected a mapping"]

    if not doc.get("name"):
        problems.append(f"{path}: no top-level `name:`")

    # YAML 1.1 resolves an unquoted `on:` key to the boolean True, so a
    # workflow's trigger block arrives under either key depending on quoting.
    # Both forms at once are two spellings of one key: distinct to PyYAML, so
    # the duplicate-key loader cannot see it, and a single redefined trigger
    # to GitHub, which rejects it.
    if True in doc and "on" in doc:
        problems.append(f"{path}: `on:` given twice (bare and quoted)")
    elif True not in doc and "on" not in doc:
        problems.append(f"{path}: no `on:` trigger block")

    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        problems.append(f"{path}: no non-empty `jobs:` mapping")
        return problems

    for job_id, job in jobs.items():
        where = f"{path}: job `{job_id}`"
        if not isinstance(job, dict):
            problems.append(f"{where}: not a mapping")
            continue
        # A reusable-workflow call has `uses:` and no steps of its own; the
        # two are mutually exclusive to GitHub, not merely unusual together.
        if "uses" in job:
            if "steps" in job:
                problems.append(f"{where}: both `uses:` and `steps:`")
            continue
        steps = job.get("steps")
        if not isinstance(steps, list) or not steps:
            problems.append(f"{where}: no non-empty `steps:` list")
            continue
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                problems.append(f"{where} step {i}: not a mapping")
                continue
            # Exactly one of the two: GitHub rejects a step carrying both
            # just as it rejects one carrying neither.
            has_uses, has_run = "uses" in step, "run" in step
            if has_uses and has_run:
                problems.append(f"{where} step {i}: both `uses:` and `run:`")
            elif not has_uses and not has_run:
                problems.append(f"{where} step {i}: neither `uses:` nor `run:`")
    return problems


def main() -> int:
    if not os.path.isdir(WORKFLOWS):
        print(
            f"workflow parse: {WORKFLOWS} does not exist — the gate's "
            "subject is missing",
            file=sys.stderr,
        )
        return 2

    names = sorted(
        n
        for n in os.listdir(WORKFLOWS)
        if is_workflow_file(n) and os.path.isfile(os.path.join(WORKFLOWS, n))
    )
    if not names:
        print(
            "workflow parse: no workflow files found — the gate's subject "
            "is missing",
            file=sys.stderr,
        )
        return 2

    problems: list[str] = []
    for name in names:
        path = os.path.join(WORKFLOWS, name)
        rel = os.path.relpath(path, ROOT)
        try:
            # Binary, so PyYAML applies YAML's own encoding rules (BOM, then
            # UTF-8) instead of a hard-coded decode in this file. A file that
            # is not decodable then arrives as a ReaderError — a YAMLError,
            # caught below — rather than a UnicodeDecodeError escaping as a
            # traceback that aborts the sweep before the later files.
            with open(path, "rb") as fh:
                doc = yaml.load(fh, Loader=StrictLoader)
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            where = f" (line {mark.line + 1}, column {mark.column + 1})" if mark else ""
            problem = " ".join(str(getattr(exc, "problem", None) or exc).split())
            problems.append(f"{rel}: does not parse{where}: {problem}")
            continue
        except OSError as exc:
            problems.append(f"{rel}: unreadable: {exc}")
            continue
        problems.extend(check_one(rel, doc))

    if problems:
        print("workflow parse: invalid workflow file(s)", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nA workflow GitHub rejects runs zero jobs and fails no named "
            "check, so every gate it carries goes quiet. Common causes: an "
            "unquoted value containing a colon-space, a key defined twice, "
            "or a job/step carrying two mutually exclusive fields.",
            file=sys.stderr,
        )
        return 1

    print(f"workflow parse: {len(names)} workflow files parse and are well-formed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
