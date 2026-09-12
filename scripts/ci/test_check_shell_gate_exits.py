# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Self-test for check_shell_gate_exits.py. Each of the four checks is bitten
# red independently, and the ANCHOR EXEMPTION is pinned in both directions —
# an anchored `pgrep -f` must pass and an unanchored one must fail. That pair
# is the important one: the naive version of this gate flagged four correct,
# deliberately-anchored sites in tor-pin-verify.yml, and a gate that fails
# careful code teaches the author to make it less careful.

import subprocess
import sys
import tempfile
from pathlib import Path

GATE = Path(__file__).resolve().parent / "check_shell_gate_exits.py"

CLEAN_SH = """#!/usr/bin/env bash
set -euo pipefail
cargo clippy --workspace > clippy.log 2>&1
rc=$?
grep -c warning clippy.log || true
exit "$rc"
"""

CLEAN_WF = """name: gates
jobs:
  g:
    steps:
      - run: |
          set -o pipefail
          orphan="^$GITHUB_WORKSPACE/tor/tor "
          for _ in 1 2 3; do pgrep -f "$orphan" >/dev/null || break; sleep 1; done
          ! pgrep -af "$orphan"
"""


def run(tmp, sh=CLEAN_SH, wf=CLEAN_WF, extra_sh=None):
    root = Path(tmp)
    (root / "scripts" / "ci").mkdir(parents=True, exist_ok=True)
    (root / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (root / "scripts" / "ci" / "a.sh").write_text(sh, encoding="utf-8")
    if extra_sh:
        (root / "scripts" / "ci" / "b.sh").write_text(extra_sh, encoding="utf-8")
    (root / ".github" / "workflows" / "w.yml").write_text(wf, encoding="utf-8")
    gate = root / "scripts" / "ci" / GATE.name
    gate.write_text(GATE.read_text(encoding="utf-8"), encoding="utf-8")
    return subprocess.run([sys.executable, str(gate)], capture_output=True, text=True)


CASES = []


def case(name):
    def deco(fn):
        CASES.append((name, fn))
        return fn
    return deco


@case("the clean fixture is GREEN — every red below rests on this")
def _(tmp):
    r = run(tmp)
    assert r.returncode == 0, r.stderr
    return "unpiped verdict + anchored pgrep pass"


@case("ANCHOR EXEMPTION, positive: an anchored `pgrep -f` must NOT be flagged")
def _(tmp):
    r = run(tmp)
    assert r.returncode == 0 and "pgrep" not in r.stderr, r.stderr
    return "`^$GITHUB_WORKSPACE/tor/tor ` is correct and stays unflagged"


@case("ANCHOR EXEMPTION, negative: an UNanchored `pgrep -f` FATALs")
def _(tmp):
    wf = CLEAN_WF.replace('orphan="^$GITHUB_WORKSPACE/tor/tor "', 'orphan="cargo-mutants"')
    r = run(tmp, wf=wf)
    assert r.returncode == 1, "an unanchored -f pattern can match the caller"
    assert "matches the full" in r.stderr, r.stderr
    return "the hazard fires when the anchor is removed"


@case("`pgrep -x` is accepted — it matches the binary, not the cmdline")
def _(tmp):
    wf = CLEAN_WF.replace('pgrep -f "$orphan"', 'pgrep -x tor').replace(
        'pgrep -af "$orphan"', 'pgrep -x tor')
    r = run(tmp, wf=wf)
    assert r.returncode == 0, r.stderr
    return "-x is the rule's preferred narrow form"


@case("`$?` on the line after a pipe FATALs")
def _(tmp):
    sh = """#!/usr/bin/env bash
set -eu
cargo clippy --workspace | tail -5
rc=$?
exit "$rc"
"""
    r = run(tmp, sh=sh)
    assert r.returncode == 1, "the filter's status must not read as the verdict"
    assert "filter's status" in r.stderr, r.stderr
    return "names the line and prescribes PIPESTATUS"


@case("${PIPESTATUS[0]} after a pipe is accepted")
def _(tmp):
    sh = """#!/usr/bin/env bash
set -eu
cargo clippy --workspace | tail -5
rc=${PIPESTATUS[0]}
exit "$rc"
"""
    r = run(tmp, sh=sh)
    assert r.returncode == 0, r.stderr
    return "the documented escape hatch passes"


@case("a publish chained to a piped verdict FATALs")
def _(tmp):
    sh = """#!/usr/bin/env bash
set -euo pipefail
cargo test | tail -1 && git push origin main
"""
    r = run(tmp, sh=sh)
    assert r.returncode == 1, "a swallowed verdict must not make a push unconditional"
    assert "unconditional" in r.stderr, r.stderr
    return "publishing never shares a chain with a pipe"


@case("a piped .sh with NO pipefail and NO PIPESTATUS FATALs")
def _(tmp):
    sh = """#!/usr/bin/env bash
set -eu
cargo test | tail -1
"""
    r = run(tmp, sh=sh)
    assert r.returncode == 1
    assert "neither" in r.stderr, r.stderr
    return "a script with no propagation mechanism at all is named"


@case("RULE 47: a missing subject FATALs instead of reporting no violations")
def _(tmp):
    root = Path(tmp)
    (root / "scripts" / "ci").mkdir(parents=True, exist_ok=True)
    gate = root / "scripts" / "ci" / GATE.name
    gate.write_text(GATE.read_text(encoding="utf-8"), encoding="utf-8")
    # No workflows at all, and the only .sh is the gate's own copy.
    r = subprocess.run([sys.executable, str(gate)], capture_output=True, text=True)
    assert r.returncode == 1, "an empty subject must not read as clean"
    assert "subject is missing" in r.stderr, r.stderr
    return "zero workflows is a missing subject, not a pass"


def main():
    failed = 0
    for name, fn in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                print(f"  ok   {name}\n         -> {fn(tmp)}")
            except AssertionError as e:
                failed += 1
                print(f"  FAIL {name}\n         {e}", file=sys.stderr)
    print(f"\n{len(CASES) - failed}/{len(CASES)} self-test cases passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
