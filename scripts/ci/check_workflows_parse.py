# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Workflow-file validity gate.
#
# Every file under .github/workflows/ must parse as YAML and be shaped like
# a workflow: a trigger, jobs, and each job either a reusable `uses` or a
# runner plus steps. `name` is deliberately not among them — Actions treats
# it as optional, so requiring it would fail a workflow Actions runs.
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
import re
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
_BOOL_TAG = "tag:yaml.org,2002:bool"


class StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate keys and resolves scalars as Actions does.

    Two departures from the base, and both exist because PyYAML implements
    YAML 1.1 while the Actions runner reads the 1.2 core schema:

    * Duplicate keys are refused. PyYAML keeps the last value and says
      nothing; Actions rejects the file. Validating only the surviving value
      would let this gate PASS a workflow Actions will not run.
    * `yes`, `no`, `on` and `off` stay strings. Under 1.1 they are booleans,
      which turns a valid step (`run: no`) into `False` and makes this gate
      block a workflow Actions accepts. Keys already bypass construction
      entirely; this is the same correction applied to values.
    """


# The YAML 1.2 core schema, replacing PyYAML's 1.1 set outright rather than
# amending it. Amending only the booleans left 1.1's timestamp and
# sexagesimal resolvers live, so `run: 2026-01-01` became a date and
# `run: 12:34` became 754 — both then refused as "not text" by a required
# check, for workflows Actions runs happily. Everything not matched here is
# a string, which is what a workflow field almost always is.
#
# This fixes which TYPE a scalar resolves to, not what a number parses to:
# PyYAML's int constructor still reads a leading-zero form as 1.1 octal, so
# `012` arrives as 10 rather than 12. Nothing here reads a numeric value —
# every field this gate inspects is text, and a number in one is a defect
# whatever it equals — so that residue is deliberately left alone.
_CORE_SCHEMA = (
    ("tag:yaml.org,2002:null", r"^(?:~|null|Null|NULL|)$", list("~nN") + [""]),
    (_BOOL_TAG, r"^(?:true|True|TRUE|false|False|FALSE)$", list("tTfF")),
    (
        "tag:yaml.org,2002:int",
        r"^[-+]?(?:[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+)$",
        list("-+0123456789"),
    ),
    (
        "tag:yaml.org,2002:float",
        r"^(?:[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?"
        r"|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$",
        list("-+.0123456789"),
    ),
    # Not part of the core schema, and kept only so `<<` still arrives tagged
    # as a merge for the loader to refuse by name. Dropping it with the rest
    # of the 1.1 set silently turned that refusal into dead code and made a
    # merge-key file fail as "missing runs-on" instead — the fields the merge
    # would have supplied are simply absent under a literal `<<` key.
    ("tag:yaml.org,2002:merge", r"^(?:<<)$", ["<"]),
)

StrictLoader.yaml_implicit_resolvers = {}
for _tag, _pattern, _firsts in _CORE_SCHEMA:
    StrictLoader.add_implicit_resolver(_tag, re.compile(_pattern), _firsts)


def _construct_mapping_no_duplicates(loader: StrictLoader, node, deep: bool = False):
    mapping: dict = {}
    for key_node, value_node in node.value:
        # `<<` is refused rather than modelled. Two review rounds asserted
        # opposite things about whether Actions honours merge keys, nothing
        # in this repository uses one, and guessing wrong is a silent miss
        # in one direction or a rejected valid workflow in the other. Plain
        # anchors and aliases are untouched by this — they are resolved
        # before construction, and workflows here do use them.
        if key_node.tag == "tag:yaml.org,2002:merge":
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found a `<<` merge key, which this gate does not model; "
                "write the keys out, or settle Actions' behaviour and "
                "update this loader",
                key_node.start_mark,
            )
        if not isinstance(key_node, yaml.ScalarNode):
            # YAML permits a sequence or mapping as a key; Python cannot hash
            # one. Reported as a YAML error rather than left to escape as a
            # TypeError, which would abort the sweep over the later files.
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found a non-scalar key",
                key_node.start_mark,
            )
        # Keys are kept as WRITTEN rather than as PyYAML constructs them.
        # Actions reads a mapping key as text; YAML 1.1 does not, and
        # collapses `on`, `yes` and `true` onto one boolean while making
        # `1` equal to it. Constructing keys therefore both rejects valid
        # documents (`{on: a, yes: b}` is two names to Actions, one to
        # PyYAML) and loses whole entries silently (`on: push` followed by
        # `1: schedule` leaves only the latter, so the trigger this gate
        # validates is not the trigger that was written). Using the
        # spelling removes that entire class rather than patching its
        # instances, and makes bare `on:` and quoted `"on":` collide here
        # as the one redefined key Actions sees.
        key = key_node.value
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


def _nonempty_str(value: object) -> bool:
    """A field GitHub needs to read as text, actually carrying text."""
    return isinstance(value, str) and value.strip() != ""


def _all_nonempty_str(values: list) -> bool:
    """A non-empty list whose every entry is text — event names, labels."""
    return bool(values) and all(_nonempty_str(v) for v in values)



def check_one(path: str, doc: object) -> list[str]:
    """Structural checks for a parsed document. Returns problem strings.

    Scope, so the next reader knows where the line is: this is not a
    GitHub-schema validator and must not grow into one — that is
    `actionlint`'s job, and every rule added here is a chance to fail a
    workflow Actions would have run. The test for admitting a check is
    whether the malformation makes GitHub produce **no check at all**: no
    triggers, no jobs, no runner, a step that cannot execute. Those are the
    silent disarms this gate exists for. Cosmetic schema wrongness that
    still yields a red job reports itself and is deliberately not checked.
    """
    problems: list[str] = []
    if not isinstance(doc, dict):
        return [f"{path}: top level is {type(doc).__name__}, expected a mapping"]

    # No `name:` check. Actions treats it as optional and falls back to a
    # display name, so the workflow still runs and still reports its checks —
    # rejecting its absence would fail a workflow Actions accepts, which the
    # rule above forbids.

    # Keys arrive as written, so the trigger is `on` whether it was quoted or
    # not, and a second spelling of it is a duplicate the loader has already
    # refused.
    if "on" not in doc:
        problems.append(f"{path}: no `on:` trigger block")
    else:
        # An empty trigger is this gate's own subject, not schema pedantry:
        # a workflow with nothing to start it never runs and never reports a
        # check, which is the silent disarm the gate exists to catch.
        trigger = doc["on"]
        if isinstance(trigger, list):
            # A list of event names, so entries have to BE names: `on: [null]`
            # leaves the workflow with no event it can start on.
            usable = _all_nonempty_str(trigger)
        else:
            usable = _nonempty_str(trigger) or (isinstance(trigger, dict) and trigger)
        if not usable:
            problems.append(f"{path}: `on:` has no triggers")

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
            # The called workflow picks its own runner, so a runner here is
            # the same mutually-exclusive error as steps.
            if "runs-on" in job:
                problems.append(f"{where}: both `uses:` and `runs-on:`")
            if not _nonempty_str(job.get("uses")):
                problems.append(f"{where}: `uses:` has no workflow reference")
            continue
        # Without a usable runner GitHub creates no job, so the check this
        # workflow would have reported never appears — the same silent disarm
        # again. Actions accepts a label, a list of labels, or a runner
        # mapping (and an expression, which arrives as a string); a boolean
        # or a number is refused before the job exists, so presence alone is
        # not enough to ask.
        runs_on = job.get("runs-on")
        if isinstance(runs_on, list):
            usable = _all_nonempty_str(runs_on)
        elif isinstance(runs_on, dict):
            # Required-key, not allowlist: a runner mapping selects by group
            # and/or labels, so demanding one of those catches `{foo: bar}`
            # while staying correct if Actions adds a third key later.
            usable = "group" in runs_on or "labels" in runs_on
        else:
            usable = _nonempty_str(runs_on)
        if not usable:
            problems.append(f"{where}: `runs-on:` is missing or not a runner")
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
            else:
                # Present but empty is the same outcome as absent: the
                # workflow is refused before any job exists.
                field = "uses" if has_uses else "run"
                if not _nonempty_str(step.get(field)):
                    problems.append(
                        f"{where} step {i}: `{field}:` is empty or not text"
                    )
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
