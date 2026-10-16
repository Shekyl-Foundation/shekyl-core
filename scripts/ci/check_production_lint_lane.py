#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The production-shape clippy lane names exactly the TEST_ONLY owners.

`rust-audit-test.yml` lints each TEST_ONLY crate as production builds it:
`--lib`, no dev target, so the dev-edge feature stays off. The workspace
clippy step cannot see that shape — features unify across the targets it
builds — which is how an import used only by the gated item ships unused
and unlinted.

This is a workflow check, so it parses the step with `StrictLoader` (the
same loader `check_workflows_parse.py` uses) and grades the mapping. It
does not live inside `check_test_only_features.py`: that gate reads
`cargo metadata` and runs in the rust-audit container, which does not
install PyYAML. The owner set is still that file's `TEST_ONLY`. There is
no second list. Duplicate keys are the parse gate's job; this one refuses
a step it cannot grade as the one production-shape line.

What a passing step is:

* one step, found by `PRODUCTION_LINT_STEP`, under any job that has `steps`
* keys drawn only from `name`, `working-directory`, `run` (`working-directory`
  may be absent; a key outside the set may not)
* `run` one line, whether or not it was written as a block scalar
* cargo's side of ` -- ` a closed set: `cargo clippy`, then only `--locked`,
  `--lib`, and `-p <pkg>`
* clippy's side exactly `-D warnings`
* the `-p` set equal to the TEST_ONLY owners

A renamed step, a second step with the same name, a flag nobody has listed,
an `-A`, or a `|| true` are red. So is a workflow that does not parse: that
is a missing instrument, not a missing step.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - the grep-gates image installs it
    print(
        "production-lint lane: PyYAML is not importable, so the workflow "
        "step was not read. Install python3-yaml (the grep-gates job does) "
        "rather than letting an absent parser read as a pass.",
        file=sys.stderr,
    )
    raise SystemExit(2)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_workflows_parse import StrictLoader  # noqa: E402

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "rust-audit-test.yml"
# The step this gate holds equal to the TEST_ONLY owners. Renaming the step
# without renaming this constant is a missing subject, and the failure says so.
PRODUCTION_LINT_STEP = "cargo clippy: test-only features off, as production builds them (lib only)"
# Closed. `if:` skips the step, `continue-on-error:` lets it fail without
# failing the job, `shell:` or `env:` changes what the line means.
PRODUCTION_LINT_STEP_KEYS = frozenset({"name", "working-directory", "run"})
# Everything after ` -- `, exactly. A tuple so the allow-list cannot be
# appended to; the failure renders it as a list, which is what `.split()`
# produces and what the selftest matches.
PRODUCTION_LINT_CLIPPY_ARGS = ("-D", "warnings")
_PACKAGE_FLAG_RE = re.compile(r"(?:^|\s)-p\s+(?P<pkg>\S+)")
_WHERE = f"{WORKFLOW.name} step {PRODUCTION_LINT_STEP!r}"
# Cargo's own flags, not `-p`. A dev target unifies the test feature onto
# the lib; a feature flag selects it; `--no-default-features` builds a
# shape production never does. Anything not listed is red, including the
# flag nobody has thought of yet.
_CARGO_FLAGS = frozenset({"--locked", "--lib"})


def _show(value: object) -> str:
    """A value rendered so a boolean reads `true`/`false`, as the workflow does."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, dict):
        return ", ".join(f"{key}: {_show(item)}" for key, item in value.items())
    if isinstance(value, list):
        return ", ".join(_show(item) for item in value)
    return str(value)


def load_workflow(workflow_text: str) -> tuple[object, list[str]]:
    """The workflow mapping, or a parse failure.

    A `YAMLError` is its own failure. Collapsing it into "step not found"
    would tell an editor to restore a step the loader never got to read.
    """
    try:
        return yaml.load(workflow_text, Loader=StrictLoader), []
    except yaml.YAMLError as err:
        return None, [f"{WORKFLOW.name}: does not parse as workflow YAML ({err.__class__.__name__}: {err})"]


def production_lint_steps(doc: object) -> tuple[list[dict], list[str]]:
    """Every step named `PRODUCTION_LINT_STEP`.

    Jobs without a `steps` list (a reusable `uses:` job) are not this step
    and are skipped. A document that parsed but is not a workflow mapping
    fails here, rather than as an absent step: the subject is the mapping.
    """
    if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
        return [], [
            f"{WORKFLOW.name}: parsed, but `jobs` is not a mapping — "
            f"the production-lint step cannot be read"
        ]
    found: list[dict] = []
    for job in doc["jobs"].values():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if isinstance(step, dict) and step.get("name") == PRODUCTION_LINT_STEP:
                found.append(step)
    return found, []


def check_production_lint_lane(workflow_text: str, owners: frozenset[str]) -> list[str]:
    """The production-shape step exists once and lints exactly `owners`."""
    doc, failures = load_workflow(workflow_text)
    if failures:
        return failures
    found, failures = production_lint_steps(doc)
    if failures:
        return failures
    if not found:
        return [
            f"{_WHERE}: not found — the TEST_ONLY owners' production shape is "
            f"linted by that step alone; restore it (renamed? update PRODUCTION_LINT_STEP too)"
        ]
    if len(found) != 1:
        return [
            f"{_WHERE}: named more than once ({len(found)} steps) — the lane is one "
            f"step, and a second one with this name would let CI run a command this "
            f"gate did not grade"
        ]
    return _grade_step(found[0], owners)


def _grade_step(step: dict, owners: frozenset[str]) -> list[str]:
    failures: list[str] = []
    extra = [key for key in step if key not in PRODUCTION_LINT_STEP_KEYS]
    if extra:
        shown = "; ".join(f"{key}: {_show(step[key])}" for key in sorted(extra, key=str))
        failures.append(
            f"{_WHERE}: key(s) outside the step's closed key set "
            f"{sorted(PRODUCTION_LINT_STEP_KEYS)}: {shown} — an `if:` skips "
            f"the lint, `continue-on-error:` lets it fail quietly, a block-scalar `run:` "
            f"hides what the one line says"
        )
    run = step.get("run")
    if isinstance(run, str):
        run = run.strip()
    if not isinstance(run, str) or not run or "\n" in run:
        failures.append(f"{_WHERE}: no one-line `run:` — nothing lints the production shape")
        return failures
    failures.extend(_grade_run(run, owners))
    return failures


def _grade_run(run: str, owners: frozenset[str]) -> list[str]:
    """Cargo's side is a closed allow-list; clippy's side is exactly `-D warnings`."""
    failures: list[str] = []
    cargo_side, sep, clippy_side = run.partition(" -- ")
    tokens = cargo_side.split()
    if tokens[:2] != ["cargo", "clippy"] or not sep:
        failures.append(f"{_WHERE}: `run:` is not a `cargo clippy <cargo flags> -- -D warnings` line: {run!r}")
    if clippy_side.split() != list(PRODUCTION_LINT_CLIPPY_ARGS):
        failures.append(
            f"{_WHERE}: clippy is passed {clippy_side.split()!r}, not exactly "
            f"{list(PRODUCTION_LINT_CLIPPY_ARGS)!r} — an `-A` re-allows a lint and a shell "
            f"operator after the command (`|| true`) masks the exit"
        )
    stray: list[str] = []
    index = 2
    while index < len(tokens):
        tok = tokens[index]
        if tok == "-p" and index + 1 < len(tokens):
            index += 2
            continue
        if tok not in _CARGO_FLAGS:
            stray.append(tok)
        index += 1
    if "--lib" not in tokens[2:]:
        failures.append(f"{_WHERE}: no `--lib` — without it cargo picks the package's default targets")
    if stray:
        failures.append(
            f"{_WHERE}: flag(s) outside the lane's closed set "
            f"{sorted(_CARGO_FLAGS | {'-p <crate>'})}: "
            f"{', '.join(stray)} — a dev target unifies the test feature onto the lib, a "
            f"feature flag selects it directly, and either lints the test shape under a "
            f"step named for the production one"
        )
    linted = frozenset(match.group("pkg") for match in _PACKAGE_FLAG_RE.finditer(cargo_side))
    missing = sorted(owners - linted)
    extra = sorted(linted - owners)
    if missing:
        failures.append(
            f"{_WHERE}: TEST_ONLY owner(s) not linted feature-off: {', '.join(missing)} — "
            f"add `-p <crate>` to the lane in the commit that adds the row"
        )
    if extra:
        failures.append(
            f"{_WHERE}: lints crate(s) with no TEST_ONLY row: {', '.join(extra)} — "
            f"the lane is the table's mirror, not a second list; drop them or add the row"
        )
    return failures


def test_only_owners() -> frozenset[str]:
    """The one registry. Imported here, not at module load, so this file's
    selftest does not depend on the metadata gate and neither file imports
    the other at import time."""
    from check_test_only_features import TEST_ONLY  # noqa: E402

    return frozenset(owner for owner, _feature in TEST_ONLY)


def _workflow(body: str, *, name: str = PRODUCTION_LINT_STEP) -> str:
    """A one-job workflow whose middle step is the lane, plus a neighbour on each side."""
    return (
        "jobs:\n"
        "  rust:\n"
        "    steps:\n"
        "      - name: other step\n"
        "        run: echo before\n"
        f'      - name: "{name}"\n'
        f"{body}"
        "      - name: after\n"
        "        run: echo after\n"
    )


def _step(run: str | None, *, extra: str = "", working_directory: bool = True) -> str:
    lines: list[str] = []
    if working_directory:
        lines.append("        working-directory: rust")
    if extra:
        lines.append(extra.rstrip("\n"))
    if run is not None:
        lines.append(f"        run: {run}")
    return "\n".join(lines) + "\n"


def selftest() -> int:
    good = "cargo clippy --locked -p a -p b --lib -- -D warnings"
    owners = frozenset({"a", "b"})
    cases: list[tuple[str, str, list[str]]] = [
        ("lane names exactly the owners: green", _workflow(_step(good)), []),
        (
            "working-directory omitted is still the lane",
            _workflow(_step(good, working_directory=False)),
            [],
        ),
        (
            "a comment is not a key",
            _workflow(_step(good, extra="        # an editor's note")),
            [],
        ),
        (
            "a one-line block scalar is the line inside it",
            _workflow("        run: |\n          " + good + "\n"),
            [],
        ),
        (
            "a reusable job with no steps is not this step",
            (
                "jobs:\n"
                "  called:\n"
                "    uses: Shekyl-Foundation/shekyl-core/.github/workflows/other.yml@dev\n"
                "  rust:\n"
                "    steps:\n"
                f'      - name: "{PRODUCTION_LINT_STEP}"\n'
                f"        run: {good}\n"
            ),
            [],
        ),
        (
            "row added, lane not touched — the hole one level up",
            _workflow(_step("cargo clippy --locked -p a --lib -- -D warnings")),
            ["not linted feature-off: b"],
        ),
        (
            "lane lints a crate with no row",
            _workflow(_step("cargo clippy --locked -p a -p b -p c --lib -- -D warnings")),
            ["no TEST_ONLY row: c"],
        ),
        (
            "lane builds a dev target — the indirect way onto the lib",
            _workflow(_step("cargo clippy --locked -p a -p b --lib --all-targets -- -D warnings")),
            ["outside the lane's closed set", "--all-targets"],
        ),
        (
            "lane turns every feature on — the direct way, no dev target",
            _workflow(_step("cargo clippy --locked -p a -p b --lib --all-features -- -D warnings")),
            ["outside the lane's closed set", "--all-features"],
        ),
        (
            "lane names the test feature itself",
            _workflow(_step("cargo clippy --locked -p a -p b --lib --features a/test-signer -- -D warnings")),
            ["outside the lane's closed set", "--features", "a/test-signer"],
        ),
        (
            "lane drops default features — a shape production never builds",
            _workflow(_step("cargo clippy --locked --no-default-features -p a -p b --lib -- -D warnings")),
            ["outside the lane's closed set", "--no-default-features"],
        ),
        (
            "lane without --lib",
            _workflow(_step("cargo clippy --locked -p a -p b -- -D warnings")),
            ["no `--lib`"],
        ),
        (
            "clippy side without -D warnings",
            _workflow(_step("cargo clippy --locked -p a -p b --lib")),
            ["not a `cargo clippy"],
        ),
        (
            "step renamed away",
            _workflow(_step("cargo clippy -p a -p b --lib -- -D warnings"), name="something else"),
            ["not found"],
        ),
        (
            "step present, run missing",
            _workflow(_step(None)),
            ["no one-line `run:`"],
        ),
        (
            "exit masked after the command",
            _workflow(_step(good + " || true")),
            ["masks the exit", "'||', 'true'"],
        ),
        (
            "a lint re-allowed on the clippy side",
            _workflow(_step(good + " -A clippy::unused_imports")),
            ["not exactly ['-D', 'warnings']"],
        ),
        (
            "step skipped by a condition",
            _workflow(_step(good, extra="        if: false")),
            ["outside the step's closed key set", "if: false"],
        ),
        (
            "step allowed to fail quietly",
            _workflow(_step(good, extra="        continue-on-error: true")),
            ["outside the step's closed key set", "continue-on-error: true"],
        ),
        (
            "environment injected into the step",
            _workflow(_step(good, extra="        env:\n          RUSTFLAGS: --cap-lints allow")),
            ["outside the step's closed key set", "env:", "RUSTFLAGS"],
        ),
        (
            "a shell key changes what the line means",
            _workflow(_step(good, extra="        shell: bash")),
            ["outside the step's closed key set", "shell: bash"],
        ),
        (
            "a multi-line run is not the one line",
            _workflow("        run: |\n          " + good + "\n          echo leftover\n"),
            ["no one-line `run:`"],
        ),
        (
            "a one-line block scalar is read, so a masked exit inside it is red",
            _workflow("        run: |\n          " + good + " || true\n"),
            ["masks the exit", "'||', 'true'"],
        ),
        (
            "the step named twice",
            (
                "jobs:\n"
                "  rust:\n"
                "    steps:\n"
                f'      - name: "{PRODUCTION_LINT_STEP}"\n'
                f"        run: {good}\n"
                f'      - name: "{PRODUCTION_LINT_STEP}"\n'
                f"        run: {good}\n"
            ),
            ["named more than once"],
        ),
        (
            "workflow does not parse",
            "jobs: [\n  - :\n",
            ["does not parse"],
        ),
    ]
    bad: list[str] = []
    for label, text, want in cases:
        got = check_production_lint_lane(text, owners)
        if not want and got:
            bad.append(f"{label}: expected green, got {got!r}")
        for needle in want:
            if not any(needle in failure for failure in got):
                bad.append(f"{label}: expected a failure containing {needle!r}, got {got!r}")
        if label == "workflow does not parse" and any("not found" in failure for failure in got):
            bad.append(f"{label}: a parse error collapsed into 'not found': {got!r}")
    if bad:
        print("production-lint lane selftest FAILED:\n", file=sys.stderr)
        for item in bad:
            print(f"  - {item}", file=sys.stderr)
        return 1
    print(f"production-lint lane selftest: {len(cases)} cases held")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    if not WORKFLOW.is_file():
        print(
            f"{WORKFLOW}: not found — the production-lint lane has no workflow to read",
            file=sys.stderr,
        )
        return 1
    failures = check_production_lint_lane(WORKFLOW.read_text(encoding="utf-8"), test_only_owners())
    if failures:
        print("Production-lint lane FAILED:\n", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(
        f"Production-lint lane OK: {WORKFLOW.name} step {PRODUCTION_LINT_STEP!r} "
        f"lints exactly the TEST_ONLY owners, feature-off"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
