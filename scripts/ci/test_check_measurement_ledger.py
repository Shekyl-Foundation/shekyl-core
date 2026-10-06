#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Self-test for the measurement-ledger gate. Each scenario builds its own
# repository, so a case does not depend on commits an earlier case happened
# to leave behind. A control constant stays green beside every red one.

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import check_measurement_ledger as gate

LEDGER = gate.LEDGER
HEADER = gate.REV_SOURCE_HEADER
TRACKED = "| Id | Benchmark |\n| --- | --- |\n| **BA-T1** | a |\n| **BA-T2** | b |\n"
CARRIER = 'carrier = "BA-T1 floor re-run, owed"\n'
SENTENCE = "selftest: cost effect noted"


class Results:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.passed = 0

    def expect(
        self, root: Path, text: str, want: int, why: str, says: str = ""
    ) -> None:
        code, out = verdict(root, text)
        if code != want or (says and says not in out):
            wanted = f"exit {want}" + (f" naming {says!r}" if says else "")
            self.failures.append(f"{why}: wanted {wanted}, got {code}\n{out}")
        else:
            self.passed += 1

    def expect_code(self, root: Path, want: int, why: str) -> None:
        code = quiet(root)
        if code != want:
            self.failures.append(f"{why}: wanted exit {want}, got {code}")
        else:
            self.passed += 1


def sh(root: Path, *args: str, check: bool = True) -> str:
    # A fixture that borrows the developer's identity passes locally and
    # fails on a runner that has none.
    env = dict(
        os.environ,
        GIT_AUTHOR_NAME="t",
        GIT_AUTHOR_EMAIL="t@example.invalid",
        GIT_COMMITTER_NAME="t",
        GIT_COMMITTER_EMAIL="t@example.invalid",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_SYSTEM=os.devnull,
    )
    completed = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, env=env
    )
    if check and completed.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {completed.stderr}")
    return completed.stdout.strip()


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def commit(root: Path, message: str, ledger: bool = False) -> str:
    # The ledger a case writes is worktree state. It is committed only when
    # the case asks, so HEAD^1 holds the ledger the retirement check reads.
    if ledger:
        sh(root, "add", "-A")
    else:
        sh(root, "add", "-A", "--", ".", f":(exclude){LEDGER}")
    sh(root, "commit", "-q", "-m", message, "--allow-empty")
    return sh(root, "rev-parse", "HEAD")


def path_set(set_id: str = "hot", spec: str = '["src/hot"]', body: str = "") -> str:
    return f'[[path_set]]\nid = "{set_id}"\nspec = {spec}\n{body}\n'


def heard(*oids: str) -> str:
    entries = ", ".join(
        f'{{ through = "{oid}", note = "{SENTENCE}" }}' for oid in oids
    )
    return f"stale_through = [{entries}]\n"


def cleared(oid: str, reason: str = "comment only; no code path changed") -> str:
    return f'cleared = [{{ through = "{oid}", reason = "{reason}" }}]\n'


def constant(
    name: str,
    status: str,
    rev: str = "",
    *,
    set_id: str = "hot",
    body: str = "",
    needle: str = "LIMIT = 4",
    defined: str = "src/consts.txt",
    measured: str = '["BA-T1"]',
) -> str:
    text = (
        f'[[constant]]\nname = "{name}"\ndefined_in = "{defined}"\n'
        f'needle = "{needle}"\nmeasured_by = {measured}\nstatus = "{status}"\n'
        f'path_set = "{set_id}"\n'
    )
    if status != "unmeasured":
        text += (
            f'capture = "docs/benchmarks/cap.txt"\ncapture_rev = "{rev}"\n'
            f'rev_source = "{HEADER}"\n'
        )
    return text + body + "\n"


def estimated(
    name: str,
    *,
    set_id: str = "hot",
    body: str = "",
    captures: str = '["docs/benchmarks/cap.txt"]',
    estimate: str = '{ low = 40, high = 60, unit = "ms" }',
    basis: str = "24.8 ms before plus one 23.9 ms digest pass",
) -> str:
    return (
        f'[[constant]]\nname = "{name}"\ndefined_in = "src/consts.txt"\n'
        f'needle = "LIMIT = 4"\nmeasured_by = ["BA-T1"]\nstatus = "estimated"\n'
        f'path_set = "{set_id}"\nestimate = {estimate}\nbasis = "{basis}"\n'
        f"basis_captures = {captures}\n{CARRIER}" + body + "\n"
    )


def retired(
    name: str,
    rev: str,
    *,
    measured: str = "67.2",
    verdict: str = "falsified",
    capture: str = "docs/benchmarks/cap.txt",
    estimate: str = '{ low = 40, high = 60, unit = "ms" }',
) -> str:
    return (
        f'[[retired_estimate]]\nname = "{name}"\nestimate = {estimate}\n'
        f'measured = {measured}\ncapture = "{capture}"\ncapture_rev = "{rev}"\n'
        f'verdict = "{verdict}"\n'
        'note = "The digest costs more inside the stream than alone."\n\n'
    )


def document(
    sets: str, rows: str, toolchain: str = "", toolchain_file: str = "toolchain.toml"
) -> str:
    return (
        f'tracked_set = "docs/design/TRACKED.md"\n'
        f'toolchain_file = "{toolchain_file}"\n\n' + toolchain + sets + rows
    )


def verdict(root: Path, text: str) -> tuple[int, str]:
    write(root, LEDGER, text)
    return _run(root)


def _run(root: Path) -> tuple[int, str]:
    held = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        code = gate.run(root)
    finally:
        sys.stdout = held
    return code, buf.getvalue()


def quiet(root: Path) -> int:
    code, _ = _run(root)
    return code


def init_tree(root: Path) -> dict[str, str]:
    """A capture at c1, then one commit on a path nobody budgets."""
    sh(root, "init", "-q", "-b", "main")
    write(root, "src/consts.txt", "LIMIT = 4\n")
    write(root, "src/hot/a.rs", "fn a() {}\n")
    write(root, "src/cold/b.rs", "fn b() {}\n")
    write(root, "toolchain.toml", 'channel = "1.0"\n')
    write(root, "docs/design/TRACKED.md", TRACKED)
    c1 = commit(root, "c1: the measured tree")
    write(root, "docs/benchmarks/cap.txt", f"# git_rev={c1}\nvalue=1\n")
    c1b = commit(root, "capture lands")
    write(root, "src/cold/b.rs", "fn b() { /* cold */ }\n")
    c2 = commit(root, "c2: touches a path nobody budgets")
    return {"c1": c1, "c1b": c1b, "c2": c2}


def stale_body(since: str) -> str:
    return f'stale_since = "{since}"\n{CARRIER}'


def scenario_current(results: Results) -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        rev = init_tree(root)
        c1 = rev["c1"]
        control = constant("control", "current", c1)
        results.expect(
            root, document(path_set(), control), 0,
            "control: an untouched hot path is current",
        )
        write(root, "src/hot/a.rs", "fn a() { /* slower */ }\n")
        c3 = commit(root, "c3: changes the hot path")
        results.expect(
            root, document(path_set(), control), 1,
            "a newer commit on a budgeted path fails a current constant",
            "c3: changes the hot path",
        )
        both = control + constant("cold", "current", c1, set_id="cold")
        sets = path_set() + path_set("cold", '["src/cold"]')
        results.expect(
            root, document(sets, both), 1,
            "the question is asked per path set", "c2: touches a path",
        )
        scoped = constant("scoped", "current", c1, set_id="docs")
        results.expect(
            root, document(path_set("docs", '["docs/design"]'), scoped), 0,
            "a path set that did not move after its capture is current",
        )
        results.expect(
            root, document(path_set(body=cleared(c3)), control), 0,
            "a cleared note through the newer commit is the review point",
        )
        results.expect(
            root, document(path_set(body=cleared(c3, "ok")), control), 1,
            "a cleared note without a sentence is refused", "says nothing",
        )
        both_notes = (
            f'cleared = [{{ through = "{c3}", reason = "comment only; no code path changed" }}, '
            f'{{ through = "{rev["c2"]}", reason = "moves the review point backwards" }}]\n'
        )
        results.expect(
            root, document(path_set(body=both_notes), control), 0,
            "cleared notes are a set: order does not matter",
        )
        results.expect(
            root, document(path_set(), constant("control", "current", "0" * 40)), 1,
            "an unknown revision is refused", "not a commit",
        )
        results.expect(
            root, document(path_set(spec='["src/gone"]'), constant("control", "current", c3)), 1,
            "a pathspec that matches no tracked file is refused",
            "matches no tracked file",
        )
        results.expect(
            root,
            document(path_set(), constant("control", "current", c3, needle="LIMIT = 5")),
            1, "a constant whose value changed is refused", "needle",
        )
        fresh = constant("control", "current", c3)
        results.expect(
            root, document(path_set(), fresh.replace('["BA-T1"]', '["BA-T9"]')), 1,
            "a measured_by id the tracked set does not define is refused", "BA-T9",
        )
        results.expect(
            root, document(path_set(), fresh + 'typo_key = "x"\n'), 1,
            "an unknown key is refused", "typo_key",
        )
        results.expect(
            root, document(path_set(), fresh + 'paths = ["src/hot"]\n'), 1,
            "pathspecs belong on the path set, not the constant", "paths",
        )
        results.expect(
            root, document(path_set(), fresh + fresh), 1,
            "a duplicate constant name is refused", "duplicate",
        )
        results.expect(
            root, document(path_set(body='cleared = "nope"\n'), fresh), 1,
            "a cleared value that is not a list of tables is a finding",
            "must be a list of tables",
        )
        write(root, "docs/benchmarks/cap.txt", f"# git_rev={c3}\nvalue=2\n")
        results.expect(
            root, document(path_set(spec='["src/hot", ":(exclude,glob)src/hot/*"]'), fresh), 0,
            "an exclude pathspec is not required to match a file on its own",
        )


def scenario_stale_and_comments(results: Results) -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        rev = init_tree(root)
        c1, c3 = rev["c1"], ""
        write(root, "src/hot/a.rs", "fn a() { /* slower */ }\n")
        c3 = commit(root, "c3: changes the hot path")
        stale = constant("control", "stale", c1, body=stale_body(c3))
        results.expect(
            root, document(path_set(body=heard(c3)), stale), 0,
            "a stale constant that has heard every commit passes", "stale: control",
        )
        results.expect(
            root, document(path_set(), stale), 1,
            "a stale path set with no stale_through is refused", "stale_through",
        )
        wrong = constant("control", "stale", c1, body=stale_body(rev["c2"]))
        results.expect(
            root, document(path_set(body=heard(rev["c2"])), wrong), 1,
            "stale_since must be a commit that touched the paths", "is not among",
        )
        no_carrier = constant("control", "stale", c1, body=f'stale_since = "{c3}"\ncarrier = ""\n')
        results.expect(
            root, document(path_set(body=heard(c3)), no_carrier), 1,
            "a stale constant without a carrier is refused", "carrier",
        )
        # Inverse: the capture moves forward to c3, and the constant still says stale.
        write(root, "docs/benchmarks/cap.txt", f"# git_rev={c3}\nvalue=2\n")
        commit(root, "a newer capture lands")
        cries = constant("control", "stale", c3, body=stale_body(c3))
        results.expect(
            root, document(path_set(body=heard(c3)), cries), 1,
            "stale with nothing newer is refused", "mark it current",
        )
        fresh = constant("control", "current", c3)
        results.expect(
            root, document(path_set(), fresh), 0,
            "a newer capture makes the constant current",
        )
        results.expect(
            root, document(path_set(), constant("control", "current", c1)), 1,
            "a ledger revision that disagrees with the capture header is refused",
            "disagrees with the revision",
        )
        unmeasured = constant(
            "placeholder", "unmeasured", body='carrier = "BA-T2 derives it on the floor"\n'
        )
        results.expect(
            root, document(path_set() + path_set("other", '["src/cold"]'), fresh + unmeasured.replace(
                'path_set = "hot"', 'path_set = "other"'
            )), 0, "an unmeasured constant with a carrier passes",
        )
        bare = constant("placeholder", "unmeasured", body='carrier = ""\n')
        results.expect(
            root, document(path_set() + path_set("other", '["src/cold"]'), fresh + bare.replace(
                'path_set = "hot"', 'path_set = "other"'
            )), 1, "an unmeasured constant without a carrier is refused", "carrier",
        )
        claimed = constant(
            "placeholder", "unmeasured",
            body='carrier = "BA-T2 derives it"\ncapture = "x"\n',
        )
        results.expect(
            root, document(path_set() + path_set("other", '["src/cold"]'), fresh + claimed.replace(
                'path_set = "hot"', 'path_set = "other"'
            )), 1, "an unmeasured constant may not claim a capture", "capture",
        )
        # Cleared is not a way to retire staleness, and a stale constant does not read it.
        absorbed = path_set(body=heard(c3) + cleared(c3))
        results.expect(
            root, document(absorbed, cries), 1,
            "cleared on a path set with no current constant is refused",
            "read only by a current constant",
        )

        # The cries-wolf case rewrote the capture header to c3. These rows
        # quote c1, so the header has to agree with them again.
        write(root, "docs/benchmarks/cap.txt", f"# git_rev={c1}\nvalue=1\n")
        write(root, "src/k.rs", "// pub const K: u8 = 4;\npub const K: u8 = 5;\n")
        write(root, "src/k.h", "#define K_MAX  8   // bounds the thing\n")
        write(root, "src/mid.h", "int x; /* #define K_MAX  8 */\n#define OTHER 1\n")
        write(root, "src/k.py", "# IBD = 1.25\nIBD = 9\n")
        commit(root, "constants in source files")
        held = heard(c3)
        results.expect(
            root, document(path_set(body=held), constant(
                "control", "stale", c1, body=stale_body(c3),
                needle="pub const K: u8 = 4;", defined="src/k.rs",
            )), 1, "an old value that survives only in a line comment is refused",
            "only inside a comment",
        )
        results.expect(
            root, document(path_set(body=held), constant(
                "control", "stale", c1, body=stale_body(c3),
                needle="pub const K: u8 = 5;", defined="src/k.rs",
            )), 0, "the live definition is found beside its trailing comment",
        )
        results.expect(
            root, document(path_set(body=held), constant(
                "control", "stale", c1, body=stale_body(c3),
                needle="#define K_MAX  8", defined="src/k.h",
            )), 0, "a C #define is code",
        )
        results.expect(
            root, document(path_set(body=held), constant(
                "control", "stale", c1, body=stale_body(c3),
                needle="#define K_MAX  8", defined="src/mid.h",
            )), 1, "a needle that survives only in a mid-line block comment is refused",
            "only inside a comment",
        )
        results.expect(
            root, document(path_set(body=held), constant(
                "control", "stale", c1, body=stale_body(c3),
                needle="IBD = 1.25", defined="src/k.py",
            )), 1, "a hash-comment quotation is not the definition",
            "only inside a comment",
        )


def scenario_listening(results: Results) -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        sh(root, "init", "-q", "-b", "main")
        write(root, "src/consts.txt", "LIMIT = 4\n")
        write(root, "src/hot/a.rs", "fn a() {}\n")
        write(root, "src/hot/a_tests.rs", "fn t() {}\n")
        write(root, "toolchain.toml", 'channel = "1.0"\n')
        write(root, "docs/design/TRACKED.md", TRACKED)
        c1 = commit(root, "c1: the measured tree")
        write(root, "docs/benchmarks/cap.txt", f"# git_rev={c1}\nvalue=1\n")
        commit(root, "capture lands")
        write(root, "src/hot/a.rs", "fn a() { /* twice the work */ }\n")
        cause = commit(root, "cause: doubles the cost")
        body = stale_body(cause)
        stale = constant("control", "stale", c1, body=body)
        results.expect(
            root, document(path_set(body=heard(cause)), stale), 0,
            "control: a stale path set that has heard its cause passes",
        )
        for label, token in (
            ("HEAD", "HEAD"), ("a branch", "main"),
        ):
            results.expect(
                root, document(path_set(body=heard(token)), stale), 1,
                f"an entry naming {label} is not a commit id", "not a commit",
            )
        results.expect(
            root, document(
                path_set(body='stale_through = [{ note = "no commit named at all" }]\n'),
                stale,
            ), 1, "an entry with no commit is not a commit id", "not a commit",
        )
        results.expect(
            root, document(path_set(body=cleared("HEAD")), constant("control", "current", c1)), 1,
            "a cleared note naming HEAD cannot clear a current constant", "not a commit",
        )
        results.expect(
            root, document(path_set(body=heard(cause)), constant(
                "control", "stale", c1, body='stale_since = "HEAD"\n' + CARRIER
            )), 1, "stale_since naming HEAD is refused", "not a commit",
        )
        results.expect(
            root, document(path_set(body=heard(c1)), stale), 1,
            "a stale_through entry that does not cover the cause leaves it unheard",
            "cause: doubles the cost",
        )
        write(root, "src/hot/a.rs", "fn a() { /* four times the work */ }\n")
        again = commit(root, "again: doubles it once more")
        results.expect(
            root, document(path_set(body=heard(cause)), stale), 1,
            "a stale path set keeps listening for a later commit",
            "again: doubles it once more",
        )
        results.expect(
            root, document(path_set(body=heard(cause, again)), stale), 0,
            "advancing stale_through with a note clears the later commit",
        )
        results.expect(
            root, document(path_set(body=heard(again, cause)), stale), 0,
            "stale_through entries are a set: their order does not matter",
        )
        # Two constants, one path set, one acknowledgment.
        pair = stale + constant("sibling", "stale", c1, body=body)
        results.expect(
            root, document(path_set(body=heard(cause, again)), pair), 0,
            "two constants on one path set share one acknowledgment",
        )
        write(root, "src/hot/a.rs", "fn a() { /* shared */ }\n")
        commit(root, "shared: both constants hear this once")
        code, out = verdict(root, document(path_set(body=heard(cause, again)), pair))
        if code != 1 or "control:" not in out or "sibling:" not in out:
            results.failures.append(
                f"a shared path set names every constant that has not heard the commit, got {code}\n{out}"
            )
        else:
            results.passed += 1

        # A test file matched by an exclude does not move the path set.
        spec = '["src/hot", ":(exclude,glob)src/hot/*_tests.rs"]'
        write(root, "src/hot/a_tests.rs", "fn t() { /* not the cost */ }\n")
        commit(root, "tests: not budgeted")
        covered = heard(cause, again)
        # The "shared" commit is still unheard. Hear it, then the test commit must not matter.
        tip = sh(root, "rev-parse", "HEAD")
        # `shared` is HEAD~1 after the test commit. Hear every non-test commit explicitly.
        shared = sh(root, "rev-parse", "HEAD~1")
        results.expect(
            root, document(path_set(spec=spec, body=heard(cause, again, shared)), stale), 0,
            "a change matched only by an exclude pathspec is not a new cost",
        )
        write(root, "src/hot/a.rs", "fn a() { /* included */ }\n")
        commit(root, "included: the budgeted file moves")
        results.expect(
            root, document(path_set(spec=spec, body=heard(cause, again, shared)), stale), 1,
            "the same path set still hears a change to an included file",
            "included: the budgeted file moves",
        )
        del tip

        # Parallel tips. Neither is an ancestor of the other.
        results.expect(
            root, document(path_set(body=heard(cause, again, shared)), constant(
                "control", "stale", c1, body=stale_body(sh(root, "rev-parse", "HEAD"))
            )), 1, "the included commit is the new cause once it is named",
            "have not been heard",
        )


def scenario_parallel_and_merge(results: Results) -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        sh(root, "init", "-q", "-b", "main")
        write(root, "src/consts.txt", "LIMIT = 4\n")
        write(root, "src/hot/a.rs", "fn a() {}\n")
        write(root, "toolchain.toml", 'channel = "1.0"\n')
        write(root, "docs/design/TRACKED.md", TRACKED)
        c1 = commit(root, "c1: the measured tree")
        write(root, "docs/benchmarks/cap.txt", f"# git_rev={c1}\nvalue=1\n")
        commit(root, "capture lands")
        write(root, "src/hot/a.rs", "fn a() { /* twice */ }\n")
        cause = commit(root, "cause: doubles the cost")
        body = stale_body(cause)
        sh(root, "checkout", "-q", "-b", "left")
        write(root, "src/hot/left.rs", "fn left() {}\n")
        left = commit(root, "left: one pull request")
        sh(root, "checkout", "-q", "-b", "right", cause)
        write(root, "src/hot/right.rs", "fn right() {}\n")
        right = commit(root, "right: another pull request")
        sh(root, "checkout", "-q", "main")
        sh(root, "merge", "-q", "--no-ff", "-m", "Merge pull request #1", "left")
        sh(root, "merge", "-q", "--no-ff", "-m", "Merge pull request #2", "right")
        stale = constant("control", "stale", c1, body=body)
        results.expect(
            root, document(path_set(body=heard(cause, left)), stale), 1,
            "acknowledging one of two parallel tips leaves the other unheard",
            "right: another pull request",
        )
        results.expect(
            root, document(path_set(body=heard(cause, left, right)), stale), 0,
            "both tips acknowledged, the merge is covered",
        )
        results.expect(
            root, document(path_set(body=heard(right, left)), stale), 0,
            "the two tips alone cover everything behind them",
        )
        # Mixed status on one path set: cleared advances only the current constant.
        tip = sh(root, "rev-parse", "HEAD")
        mixed_set = path_set(body=heard(cause, left, right) + cleared(tip))
        mixed = (
            constant("live", "current", c1)
            + constant("owed", "stale", c1, body=body)
        )
        results.expect(
            root, document(mixed_set, mixed), 0,
            "cleared does not retire the stale constant that shares the path set",
            "stale: owed",
        )

        write(root, "src/hot/a.rs", "fn a() { /* third */ }\n")
        third = commit(root, "third: the hot path moves under the new capture")
        owed3 = stale_body(third)
        sh(root, "checkout", "-q", "-b", "x")
        write(root, "src/hot/a.rs", "fn a() { /* x */ }\n")
        x = commit(root, "x: one side")
        sh(root, "checkout", "-q", "-b", "y", third)
        write(root, "src/hot/a.rs", "fn a() { /* y */ }\n")
        y = commit(root, "y: the other side")
        sh(root, "checkout", "-q", "main")
        sh(root, "merge", "-q", "--no-ff", "-m", "Merge pull request #3", "x")
        sh(root, "merge", "-q", "--no-ff", "--no-commit", "y", check=False)
        write(root, "src/hot/a.rs", "fn a() { /* neither: written in the merge */ }\n")
        resolved = commit(root, "Merge pull request #4, resolved by hand")
        cap = sh(root, "rev-parse", "HEAD")
        # The capture header must name `third` only if we use it. Use c1 and stay stale.
        results.expect(
            root, document(path_set(body=heard(third, x, y)), constant(
                "control", "stale", c1, body=owed3
            )), 1, "a merge that resolves a conflict on the path is its own change",
            "resolved by hand",
        )
        results.expect(
            root, document(path_set(body=heard(resolved)), constant(
                "control", "stale", c1, body=owed3
            )), 0, "acknowledging the hand-resolved merge clears it",
        )
        del cap


def scenario_retirement(results: Results) -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        sh(root, "init", "-q", "-b", "main")
        write(root, "src/consts.txt", "LIMIT = 4\n")
        write(root, "src/hot/a.rs", "fn a() {}\n")
        write(root, "toolchain.toml", 'channel = "1.0"\n')
        write(root, "docs/design/TRACKED.md", TRACKED)
        c1 = commit(root, "c1: the measured tree")
        write(root, "docs/benchmarks/cap.txt", f"# git_rev={c1}\nvalue=1\n")
        commit(root, "capture lands")
        write(root, "src/hot/a.rs", "fn a() { /* cause */ }\n")
        cause = commit(root, "cause: doubles the cost")
        stale = document(
            path_set(body=heard(cause)),
            constant("control", "stale", c1, body=stale_body(cause)),
        )
        write(root, LEDGER, stale)
        commit(root, "the ledger as the base branch holds it", ledger=True)
        commit(root, "the pull request's commit")
        tip = sh(root, "rev-parse", "HEAD")
        absorbed = document(
            path_set(body=cleared(tip)),
            constant("control", "current", c1),
        )
        results.expect(
            root, absorbed, 1,
            "stale to current without a capture is refused against the first parent",
            "does not include",
        )
        write(root, "docs/benchmarks/cap.txt", f"# git_rev={tip}\nvalue=4\n")
        fresh = document(path_set(), constant("control", "current", tip))
        results.expect(
            root, fresh, 0,
            "a capture that includes the cause retires the stale constant",
        )
        # Deleting the name retires nothing, even when the replacement capture is new.
        renamed = document(path_set(), constant("renamed", "current", tip))
        results.expect(
            root, renamed, 1,
            "a stale constant that disappears under a new name is refused",
            "is gone",
        )
        # Parent ledger that does not parse: the question cannot be asked.
        write(root, LEDGER, "[[constant]\n")
        commit(root, "a parent ledger that does not parse", ledger=True)
        commit(root, "the next commit")
        results.expect(
            root, fresh, 2,
            "a parent ledger that does not parse is exit 2", "does not parse",
        )
        # Parent stale_since that is not a commit. The child looks current.
        dead = "0" * 40
        parent = document(
            path_set(body=heard(cause)),
            constant("control", "stale", c1, body=stale_body(dead)),
        )
        write(root, LEDGER, parent)
        commit(root, "parent names a commit that is not in the repository", ledger=True)
        commit(root, "child drops the id")
        results.expect(
            root, fresh, 1,
            "an unresolvable parent stale_since does not pass in silence",
            "not a commit",
        )
        write(root, LEDGER, 'tracked_set = "docs/design/TRACKED.md"\nconstant = "nope"\n')
        commit(root, "parent ledger has no constant list", ledger=True)
        commit(root, "the commit after a shapeless parent")
        results.expect(
            root, fresh, 2,
            "a parent ledger whose constants are not a list is exit 2",
            "no constant list",
        )


def scenario_no_parent(results: Results) -> None:
    """The first commit has no HEAD^1. That is no stale constant, not a missing subject."""
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        sh(root, "init", "-q", "-b", "main")
        write(root, "src/consts.txt", "LIMIT = 4\n")
        write(root, "src/hot/a.rs", "fn a() {}\n")
        write(root, "toolchain.toml", 'channel = "1.0"\n')
        write(root, "docs/design/TRACKED.md", TRACKED)
        born = commit(root, "the first commit")
        write(root, "docs/benchmarks/cap.txt", f"# git_rev={born}\nvalue=1\n")
        results.expect(
            root, document(path_set(), constant("control", "current", born)), 0,
            "a repository with no parent has no stale constant to retire",
        )


def scenario_subject_and_shallow(results: Results) -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        rev = init_tree(root)
        fresh = constant("control", "current", rev["c1"])
        # After init_tree the hot path has not moved (c2 touched cold). c1 is current.
        results.expect(root, document("", ""), 2, "an empty ledger is a missing subject")
        only = constant(
            "placeholder", "unmeasured", body='carrier = "BA-T2 derives it on the floor"\n'
        )
        results.expect(
            root, document(path_set(), only), 2,
            "a ledger with no measured constant never asks the question",
        )
        write(root, LEDGER, 'tracked_set = "docs/design/NOPE.md"\n\n' + path_set() + fresh)
        results.expect_code(root, 2, "a missing tracked-set document did not refuse")
        (root / LEDGER).unlink()
        results.expect_code(root, 2, "a missing ledger did not refuse")

        sh(root, "checkout", "-q", "-b", "side", rev["c1"])
        write(root, "src/side.txt", "x\n")
        side = commit(root, "a side branch that never merges")
        sh(root, "checkout", "-q", "main")
        write(root, "docs/benchmarks/cap.txt", "value=3\n")
        commit(root, "a capture with no header revision")
        # The hot path changed at... init_tree's c2 is cold. Hot is untouched on main
        # since c1, and side did not touch hot. A stale claim on hot is a cry of wolf
        # unless something touched hot. Touch it.
        write(root, "src/hot/a.rs", "fn a() { /* after */ }\n")
        moved = commit(root, "hot moves on main")
        off = constant(
            "control", "stale", side, body=stale_body(moved)
        ).replace(f'rev_source = "{HEADER}"', 'rev_source = "the run record names it"')
        results.expect(
            root, document(path_set(body=heard(moved)), off), 0,
            "a non-ancestor revision is compared from the merge-base",
            "not an ancestor of HEAD",
        )
        results.expect(
            root, document(path_set(body=heard(moved)), constant(
                "control", "stale", side, body=stale_body(moved)
            )), 1, "rev_source 'capture header' with no header revision is refused",
            "records no revision",
        )
        ledger = document(
            path_set(body=heard(moved)), off
        )
        write(root, LEDGER, ledger)
        commit(root, "ledger", ledger=True)
        recent = sh(root, "rev-parse", "HEAD~1")
        inside = constant("control", "current", recent).replace(
            f'rev_source = "{HEADER}"', 'rev_source = "the run record names it"'
        )
        with tempfile.TemporaryDirectory() as shallow:
            subprocess.run(
                ["git", "clone", "-q", "--depth", "1", "file://" + str(root), shallow],
                check=True, capture_output=True,
            )
            results.expect_code(Path(shallow), 2, "a shallow clone cut inside the range did not refuse")
        with tempfile.TemporaryDirectory() as shallow:
            subprocess.run(
                ["git", "clone", "-q", "--depth", "3", "file://" + str(root), shallow],
                check=True, capture_output=True,
            )
            write(Path(shallow), LEDGER, document(path_set(), inside))
            results.expect_code(
                Path(shallow), 0,
                "a shallow clone cut older than the review point was refused",
            )


def scenario_toolchain(results: Results) -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        sh(root, "init", "-q", "-b", "main")
        write(root, "src/consts.txt", "LIMIT = 4\n")
        write(root, "src/hot/a.rs", "fn a() {}\n")
        write(root, "toolchain.toml", 'channel = "1.0"\n')
        write(root, "docs/design/TRACKED.md", TRACKED)
        c1 = commit(root, "c1: the measured tree")
        write(root, "docs/benchmarks/cap.txt", f"# git_rev={c1}\nvalue=1\n")
        commit(root, "capture lands")
        fresh = constant("control", "current", c1)
        write(root, "toolchain.toml", 'channel = "2.0"\n')
        bump = commit(root, "bump: the pinned toolchain moves")
        results.expect(
            root, document(path_set(), fresh), 1,
            "a toolchain change after a current capture fails",
            "bump: the pinned toolchain moves",
        )
        ack = (
            f'[[toolchain]]\ncommit = "{bump}"\n'
            'note = "codegen may differ; allocation path re-read"\n\n'
        )
        results.expect(
            root, document(path_set(), fresh, toolchain=ack), 0,
            "one ledger-level acknowledgment clears a toolchain change",
        )
        write(root, "src/unrelated.txt", "not the toolchain\n")
        unrelated = commit(root, "unrelated: does not touch the pin")
        wrong = (
            f'[[toolchain]]\ncommit = "{unrelated}"\n'
            'note = "acknowledges the wrong commit"\n\n'
        )
        results.expect(
            root, document(path_set(), fresh, toolchain=wrong), 1,
            "an acknowledgment naming a commit that did not change the pin is refused",
            "does not change",
        )
        results.expect(
            root, document(path_set(), fresh, toolchain=ack, toolchain_file="nope.toml"), 1,
            "a toolchain_file that matches no tracked file is refused",
            "matches no tracked file",
        )
        write(root, "src/hot/a.rs", "fn a() { /* and again */ }\n")
        third = commit(root, "third: the hot path moves")
        results.expect(
            root, document(path_set(body=heard(third)), constant(
                "control", "stale", c1, body=stale_body(third)
            )), 0, "a ledger with no current constant owes no toolchain acknowledgment",
        )
        results.expect(
            root, document(path_set(spec='[":(exclude)src/hot"]'), fresh), 1,
            "a spec with no included pathspec is refused", "included pathspec",
        )


def scenario_estimated(results: Results) -> None:
    """A prediction with its arithmetic, and the one way it becomes a measurement."""
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        rev = init_tree(root)
        c1 = rev["c1"]
        control = constant("control", "current", c1)
        guess = estimated("guess")
        results.expect(
            root, document(path_set(), control + guess), 0,
            "control: an estimate beside a current constant passes",
            "estimate: guess",
        )
        results.expect(
            root, document(path_set(), control + estimated("guess", captures='["docs/benchmarks/nope.txt"]')), 1,
            "an estimate whose basis capture is not in the tree is refused",
            "not a tracked file",
        )
        results.expect(
            root, document(path_set(), control + estimated("guess", captures='["docs/benchmarks"]')), 1,
            "a basis capture that is a directory, not a file, is refused",
            "not a tracked file",
        )
        results.expect(
            root, document(path_set(), control + estimated("guess", captures='["docs/benchmarks/*.txt"]')), 1,
            "a basis capture that is a glob is refused", "not a tracked file",
        )
        results.expect(
            root, document(path_set(), control + estimated("guess", estimate='"about 50 ms"')), 1,
            "an estimate that is a sentence, not a band, is refused",
            "table of low, high and unit",
        )
        results.expect(
            root, document(path_set(), control + estimated(
                "guess", estimate='{ low = 60, high = 40, unit = "ms" }'
            )), 1,
            "a band whose low is above its high is refused", "is above high",
        )
        results.expect(
            root, document(path_set(), control + estimated(
                "guess", estimate='{ low = 40, high = 60 }'
            )), 1,
            "a band with no unit is refused", "names its unit",
        )
        results.expect(
            root, document(path_set(), control + estimated(
                "guess", estimate='{ low = "40", high = 60, unit = "ms" }'
            )), 1,
            "a band whose bound is a string is refused", "low and high are numbers",
        )
        results.expect(
            root, document(path_set(), control + estimated("guess", basis="x")), 1,
            "an estimate without its arithmetic is refused", "arithmetic",
        )
        results.expect(
            root, document(path_set(), control + estimated("guess", captures="[]")), 1,
            "an estimate that names no basis capture is refused", "captures its basis",
        )
        results.expect(
            root, document(path_set(), control + estimated(
                "guess", body='capture = "docs/benchmarks/cap.txt"\n'
            )), 1,
            "an estimate may not claim a capture", "not valid for an estimated constant",
        )
        # The transition. The parent holds the estimate; the child calls it
        # current on a capture the parent tree already had.
        write(root, LEDGER, document(path_set(), control + guess))
        commit(root, "the ledger as the base branch holds it", ledger=True)
        commit(root, "the pull request's commit")
        hardened = document(path_set(), control + constant("guess", "current", c1))
        results.expect(
            root, hardened, 1,
            "AN ESTIMATE MAY NOT HARDEN: current on a capture the parent already held",
            "parent tree already held",
        )
        results.expect(
            root, document(path_set(), control), 1,
            "an estimate that vanishes is refused", "is gone",
        )
        results.expect(
            root, document(path_set(), control + retired("guess", c1)), 1,
            "AN ESTIMATE MAY NOT BE RETIRED on a capture the parent already held",
            "parent tree already held",
        )
        withdrawn = document(path_set(), control + constant(
            "guess", "unmeasured", body=CARRIER
        ))
        results.expect(
            root, withdrawn, 0, "an estimate withdrawn to unmeasured passes",
        )
        write(root, "docs/benchmarks/new_cap.txt", f"# git_rev={c1}\nvalue=51\n")
        commit(root, "the measurement lands")
        measured = document(path_set(), control + constant("guess", "current", c1).replace(
            'capture = "docs/benchmarks/cap.txt"', 'capture = "docs/benchmarks/new_cap.txt"'
        ))
        # The capture file is new to the parent tree, which is the shape a PR
        # that lands a measurement and updates the ledger has.
        results.expect(
            root, measured, 0,
            "a capture file the parent tree did not hold makes the estimate current",
        )
        results.expect(
            root, document(path_set(), control + retired(
                "guess", c1, capture="docs/benchmarks/new_cap.txt"
            )), 0,
            "a capture the parent tree did not hold retires the estimate beside its number",
            "retired estimate: guess — predicted 40 to 60 ms, measured 67.2 ms: falsified",
        )


def scenario_retired(results: Results) -> None:
    """A prediction beside its measurement, with a verdict the gate computes."""
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        rev = init_tree(root)
        c1 = rev["c1"]
        control = constant("control", "current", c1)
        results.expect(
            root, document(path_set(), control + retired("old", c1)), 0,
            "control: a falsified estimate recorded beside its measurement passes",
            "measured 67.2 ms: falsified",
        )
        results.expect(
            root, document(path_set(), control + retired(
                "old", c1, measured="55", verdict="held"
            )), 0,
            "a measurement inside the band is recorded as held", "measured 55 ms: held",
        )
        results.expect(
            root, document(path_set(), control + retired("old", c1, verdict="held")), 1,
            "A VERDICT IS COMPUTED: 67.2 against 40 to 60 may not be called held",
            "is falsified",
        )
        results.expect(
            root, document(path_set(), control + retired(
                "old", c1, measured="55", verdict="falsified"
            )), 1,
            "and 55 against 40 to 60 may not be called falsified", "is held",
        )
        results.expect(
            root, document(path_set(), control + retired("old", c1, measured="60", verdict="held")), 0,
            "the band's edge is inside it",
        )
        results.expect(
            root, document(path_set(), control + retired(
                "old", c1, capture="docs/benchmarks"
            )), 1,
            "a retired estimate's capture is one tracked file", "not a tracked file",
        )
        results.expect(
            root, document(path_set(), control + retired("old", "0" * 40)), 1,
            "a retired estimate's capture_rev is a commit here", "not a commit",
        )
        results.expect(
            root, document(path_set(), control + retired("old", c1, measured='"67.2"')), 1,
            "a measured value that is a string is refused", "measured is a number",
        )
        results.expect(
            root, document(path_set(), control + retired("old", c1) + retired("old", c1)), 1,
            "two retired estimates may not share a name", "duplicate name",
        )
        results.expect(
            root, document(path_set(), control + retired("", c1)), 1,
            "a retired estimate with an empty name is refused", "non-empty string",
        )
        results.expect(
            root, document(path_set(), control + retired("old", c1).replace(
                'name = "old"', "name = 7"
            )), 1,
            "a retired estimate whose name is not a string is refused", "non-empty string",
        )
        results.expect(
            root, document(path_set(), control + estimated("guess") + retired("guess", c1)), 1,
            "OPEN OR SETTLED, NOT BOTH: one name as an estimate and as a retired estimate",
            "open or settled, not both",
        )
        results.expect(
            root, document(path_set(), control + retired("control", c1)), 1,
            "a retired estimate may not take a measured constant's name either",
            "open or settled, not both",
        )


def selftest() -> int:
    results = Results()
    scenario_estimated(results)
    scenario_retired(results)
    scenario_current(results)
    scenario_stale_and_comments(results)
    scenario_listening(results)
    scenario_parallel_and_merge(results)
    scenario_retirement(results)
    scenario_no_parent(results)
    scenario_subject_and_shallow(results)
    scenario_toolchain(results)
    if results.failures:
        print("SELFTEST FAIL:")
        for failure in results.failures:
            print("  " + failure)
        return 1
    print(f"selftest: {results.passed} cases pass")
    return 0


if __name__ == "__main__":
    sys.exit(selftest())
