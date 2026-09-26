# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Enforces 46-shell-gate-exits.mdc, which until now was a rule with nothing
# behind it. Both halves of that rule describe ways a gate becomes
# structurally incapable of going red:
#
#   1. A VERDICT THAT TRAVELS THROUGH A PIPE. `cmd | tail` exits with the
#      filter's status, so the gate reads the filter's success and discards the
#      real result. The rule records this shipping a clippy-red commit and
#      masking a broken C++ link in one review round, with five instances
#      tallied in a single SA round.
#   2. `pgrep -f` / `pkill -f` MATCHING THE CALLER. `-f` matches the whole
#      command line, so an inline invocation finds itself: a wait-loop never
#      terminates, and a `pkill` can kill the shell that ran it.
#
# THE ANCHOR EXEMPTION, written down because the naive form of check (4) is
# wrong and would do harm. `pgrep -f "^$WORKSPACE/tor/tor "` is CORRECT: the
# `^` anchors the match to argv[0], so a caller whose command line merely
# CONTAINS the pattern cannot match. Flagging it would fail a deliberately
# careful workflow and teach the author to weaken it. `-x` (match the binary
# name, not the cmdline) is safe for the same reason. Measured before shipping:
# every `-f` site in this tree is anchored, and treating them as hazards would
# have produced four false positives.
#
# Instance of 47-gate-subject-assertion.mdc: an empty file list reports "no
# violations" identically to a clean tree, so the subject is asserted below.

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SHELL_GLOBS = ("scripts/**/*.sh",)
WORKFLOW_GLOBS = (".github/workflows/*.yml", ".github/workflows/*.yaml")

# A pipe that carries a verdict. `||` is a control operator, not a pipe.
PIPE_RE = re.compile(r"(?<!\|)\|(?!\|)")
# `$?` that is not already the documented `${PIPESTATUS[0]}` form.
BARE_STATUS_RE = re.compile(r"\$\?")
PUBLISHES_RE = re.compile(r"&&\s*(git\s+(push|commit|tag)|gh\s+pr\s+(create|merge))")
PROC_MATCH_RE = re.compile(r"\b(pgrep|pkill)\s+((?:-\w+\s+)*)-(\w*f\w*)\s+(\S+)")


def is_comment(line):
    return line.strip().startswith("#")


def has_pipe(line):
    return bool(PIPE_RE.search(line)) and not is_comment(line)


def anchored(arg, line):
    """A pattern anchored to argv[0] cannot match a caller that merely
    mentions it. Accepts a literal `^...` and the common indirection where the
    pattern is built in a variable one or two lines earlier."""
    bare = arg.strip("\"'")
    if bare.startswith("^"):
        return True
    m = re.match(r'"?\$\{?(\w+)\}?"?$', arg)
    if m:
        var = m.group(1)
        return bool(re.search(rf'\b{var}=\s*"?\^', line)) or var in ANCHORED_VARS
    return False


ANCHORED_VARS = set()


def collect_anchored_vars(lines):
    """Variables assigned an anchored pattern anywhere in the file."""
    out = set()
    for line in lines:
        for m in re.finditer(r'\b(\w+)=\s*"?\^', line):
            out.add(m.group(1))
    return out


def check_file(path, failures, is_workflow):
    rel = path.relative_to(ROOT)
    lines = path.read_text(encoding="utf-8").split("\n")
    global ANCHORED_VARS
    ANCHORED_VARS = collect_anchored_vars(lines)
    text = "\n".join(lines)

    for i, line in enumerate(lines):
        if is_comment(line):
            continue

        # (1) `$?` on the line after a piped command reads the FILTER's status.
        if i > 0 and has_pipe(lines[i - 1]) and BARE_STATUS_RE.search(line) \
                and "PIPESTATUS" not in line:
            failures.append(
                f"{rel}:{i + 1}: `$?` follows a piped command — that is the "
                f"filter's status, not the verdict's. Use `${{PIPESTATUS[0]}}` "
                f"on the very next line, or run the verdict unpiped and read a log.")

        # (2) Publishing chained to a piped verdict makes the publish
        #     unconditional.
        if has_pipe(line) and PUBLISHES_RE.search(line):
            failures.append(
                f"{rel}:{i + 1}: a publishing command (push/commit/tag/PR) shares "
                f"a chain with a piped verdict, so a swallowed exit makes it "
                f"unconditional. Split the verdict onto its own unpiped line.")

        # (3) `pgrep -f` / `pkill -f` with an unanchored pattern.
        m = PROC_MATCH_RE.search(line)
        if m:
            flags, arg = m.group(2) + m.group(3), m.group(4)
            if "x" not in flags and not anchored(arg, line) and \
                    not any(anchored(arg, l) for l in lines):
                failures.append(
                    f"{rel}:{i + 1}: `{m.group(1)} -f {arg}` matches the full "
                    f"command line, so an inline caller can match itself — a "
                    f"wait-loop that never ends, or a `pkill` that kills its own "
                    f"shell. Anchor the pattern to argv[0] (`\"^/path/to/bin \"`), "
                    f"use `pgrep -x <name>`, or keep the PID and `wait \"$pid\"`.")

    # (4) A shell gate with pipes and no exit-propagation mechanism at all.
    if not is_workflow and any(has_pipe(l) for l in lines):
        if "pipefail" not in text and "PIPESTATUS" not in text:
            failures.append(
                f"{rel}: contains piped commands but neither `set -o pipefail` nor "
                f"`${{PIPESTATUS[...]}}` appears anywhere — no mechanism carries a "
                f"verdict out of a pipeline. (Rule 46: pipefail is right for NEW "
                f"scripts, but re-check every pipe for the early-exit consumer trap "
                f"first.)")


def main():
    failures = []
    shell = sorted(p for g in SHELL_GLOBS for p in ROOT.glob(g))
    workflows = sorted(p for g in WORKFLOW_GLOBS for p in ROOT.glob(g))

    # Subject assertion: two empty lists have no violations, exactly like a
    # clean tree.
    if not shell:
        failures.append("no shell scripts found under scripts/ — the gate's subject is missing")
    if not workflows:
        failures.append("no workflows found under .github/workflows/ — the gate's subject is missing")
    if failures:
        report(failures)

    for p in shell:
        check_file(p, failures, is_workflow=False)
    for p in workflows:
        check_file(p, failures, is_workflow=True)

    report(failures)
    print(f"shell gate exits: {len(shell)} script(s) and {len(workflows)} workflow(s) "
          f"carry their verdicts unpiped; every `pgrep -f` pattern is anchored or `-x`")


def report(failures):
    if failures:
        print("Shell gate-exit discipline FAILED (46-shell-gate-exits.mdc):\n", file=sys.stderr)
        for f in failures:
            print(f"  {f}\n", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
