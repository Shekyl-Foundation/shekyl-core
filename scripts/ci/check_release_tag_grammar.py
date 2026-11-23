#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""One release-tag grammar.

A tag decides whether a build is a release, whether a staging or binding gate
applies, whether the genesis gate refuses it, and whether GitHub marks it a
pre-release. Each of those once read the tag with its own expression, and they
disagreed on an optional `v`, on case and on leading zeros.

`RELEASE_TAG_GRAMMAR` in rust/xtask/src/version.rs is canonical. This gate
holds every other reader to it:

- docs/RELEASE_PROMOTION.md states it verbatim;
- scripts/release/check_staging_deadlines.py compiles it verbatim;
- the pre-release expression is the same grammar with its suffix restricted
  to `alpha`, `beta` or `rc` (and `RC`, the exact spelling 17 existing tags
  carry), in scripts/ci/check_fn_dsa_genesis_gate.py and in both of
  .github/workflows/gitian.yml's tests, matched with case;
- rust/xtask/release_tags.tsv's cases, which include every `v*` tag cut so
  far, are decided the same way here as by the xtask's std-only matcher,
  whose unit test reads the same file.

Usage: check_release_tag_grammar.py [--selftest]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FILES = {
    "version": "rust/xtask/src/version.rs",
    "promotion": "docs/RELEASE_PROMOTION.md",
    "staging": "scripts/release/check_staging_deadlines.py",
    "genesis": "scripts/ci/check_fn_dsa_genesis_gate.py",
    "workflow": ".github/workflows/gitian.yml",
    "cases": "rust/xtask/release_tags.tsv",
}
SUFFIX = r"(-[0-9A-Za-z.]+)?$"
PRERELEASE_SUFFIX = r"-(alpha|beta|rc|RC)(\.?[0-9]+)?$"
WORKFLOW_TESTS = 2
# The tags the ruling names: no `v`, a capital `V`, a leading zero.
MUST_REFUSE = ("3.1.0-alpha.1", "V3.1.0-alpha.1", "v03.1.0")


def one(pattern: str, text: str) -> str | None:
    found = re.findall(pattern, text)
    return found[0] if len(found) == 1 else None


def read_cases(text: str) -> tuple[list[tuple[str, bool, bool]], list[str]]:
    rows, problems = [], []
    for n, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        cells = line.split("\t")
        if len(cells) != 3 or cells[1] not in ("release", "not") or cells[2] not in ("pre", "final"):
            problems.append(f"{FILES['cases']}:{n}: expected tag, release|not, pre|final")
            continue
        rows.append((cells[0], cells[1] == "release", cells[2] == "pre"))
    return rows, problems


def problems(src: dict[str, str]) -> list[str]:
    grammar = one(r'RELEASE_TAG_GRAMMAR: &str =\s*r"([^"]+)";', src["version"])
    if grammar is None:
        return [f"{FILES['version']}: no single RELEASE_TAG_GRAMMAR constant"]
    if not grammar.endswith(SUFFIX):
        return [f"{FILES['version']}: the grammar does not end in the suffix {SUFFIX}"]
    pre = grammar[: -len(SUFFIX)] + PRERELEASE_SUFFIX
    out = []

    if grammar not in src["promotion"]:
        out.append(f"{FILES['promotion']} does not state the grammar {grammar}")
    if pre not in src["promotion"]:
        out.append(f"{FILES['promotion']} does not state the pre-release grammar {pre}")

    if one(r'^RELEASE_TAG_GRAMMAR = r"([^"]+)"$', _lines(src["staging"])) != grammar:
        out.append(f"{FILES['staging']}: RELEASE_TAG_GRAMMAR is not the grammar verbatim")
    if "_TAG = re.compile(RELEASE_TAG_GRAMMAR)\n" not in src["staging"]:
        out.append(f"{FILES['staging']}: _TAG does not compile RELEASE_TAG_GRAMMAR")
    if "_TAG.fullmatch(tag)" not in src["staging"]:
        out.append(f"{FILES['staging']}: the tag is not matched in full")

    if one(r'^PRERELEASE_ERE = r"([^"]+)"$', _lines(src["genesis"])) != pre:
        out.append(f"{FILES['genesis']}: PRERELEASE_ERE is not the restricted grammar")
    if "PRERELEASE_TAG = re.compile(PRERELEASE_ERE)\n" not in src["genesis"]:
        out.append(f"{FILES['genesis']}: PRERELEASE_TAG is not the expression, with case")
    if "PRERELEASE_TAG.fullmatch(tag)" not in src["genesis"]:
        out.append(f"{FILES['genesis']}: the tag is not matched in full")

    held = src["workflow"].count(f"grep -Eq '{pre}'")
    if held != WORKFLOW_TESTS:
        out.append(f"{FILES['workflow']}: {held} tests carry the pre-release grammar, not {WORKFLOW_TESTS}")
    if "contains(github.ref_name" in src["workflow"]:
        out.append(f"{FILES['workflow']}: a tag is classified by a substring")
    if re.search(r"grep -E?iE?q? .*(alpha|beta)", src["workflow"]):
        out.append(f"{FILES['workflow']}: a tag is matched without regard to case")

    rows, bad = read_cases(src["cases"])
    out += bad
    if not rows:
        out.append(f"{FILES['cases']} has no cases")
    full, restricted = re.compile(grammar), re.compile(pre)
    for tag, release, prerelease in rows:
        if bool(full.fullmatch(tag)) != release:
            out.append(f"{FILES['cases']}: the grammar disagrees on {tag!r}")
        if bool(restricted.fullmatch(tag)) != prerelease:
            out.append(f"{FILES['cases']}: the pre-release grammar disagrees on {tag!r}")
    decided = {tag: release for tag, release, _ in rows}
    for tag in MUST_REFUSE:
        if decided.get(tag) is not False:
            out.append(f"{FILES['cases']}: {tag!r} must be a case the grammar refuses")
    return out


def _lines(text: str) -> str:
    """The file with `^`/`$` usable per line by `one`, in re.M's place."""
    return "\n".join(
        line for line in text.splitlines()
        if line.startswith(("RELEASE_TAG_GRAMMAR = ", "PRERELEASE_ERE = "))
    )


def load() -> dict[str, str]:
    return {key: (ROOT / path).read_text(encoding="utf-8") for key, path in FILES.items()}


def selftest() -> int:
    src = load()
    failures = 0

    def expect(label: str, ok: bool) -> None:
        nonlocal failures
        print(f"{'ok  ' if ok else 'FAIL'} {label}")
        failures += 0 if ok else 1

    expect("the committed tree passes", problems(src) == [])

    def planted(label: str, key: str, old: str, new: str) -> None:
        if old not in src[key]:
            expect(f"{label}: the planted text is present", False)
            return
        expect(f"refuses {label}", bool(problems({**src, key: src[key].replace(old, new, 1)})))

    grammar = one(r'RELEASE_TAG_GRAMMAR: &str =\s*r"([^"]+)";', src["version"])
    pre = grammar[: -len(SUFFIX)] + PRERELEASE_SUFFIX
    optional_v = grammar.replace("^v", "^v?", 1)
    planted("a promotion doc with another grammar", "promotion", grammar, optional_v)
    planted("a staging gate with an optional v", "staging", grammar, optional_v)
    planted("a staging gate matching a prefix", "staging", "_TAG.fullmatch(tag)", "_TAG.match(tag)")
    planted("a genesis gate with an optional v", "genesis", pre, pre.replace("^v", "^v?", 1))
    planted(
        "a genesis gate ignoring case", "genesis",
        "PRERELEASE_TAG = re.compile(PRERELEASE_ERE)",
        "PRERELEASE_TAG = re.compile(PRERELEASE_ERE, re.IGNORECASE)",
    )
    planted("a workflow test ignoring case", "workflow", f"grep -Eq '{pre}'", f"grep -Eiq '{pre}'")
    planted(
        "a workflow flag read from a substring", "workflow",
        "steps.release_kind.outputs.prerelease == 'true'", "contains(github.ref_name, 'rc')",
    )
    planted("a case the grammar decides otherwise", "cases", "v03.1.0\tnot", "v03.1.0\trelease")
    planted("a required refusal removed", "cases", "V3.1.0-alpha.1\tnot\tfinal\n", "")
    planted("a malformed case row", "cases", "v3.1.0\trelease\tfinal", "v3.1.0\tyes\tfinal")
    expect("refuses a tree with no constant", bool(problems({**src, "version": ""})))

    full, restricted = re.compile(grammar), re.compile(pre)
    for tag in MUST_REFUSE:
        expect(f"the grammar refuses {tag}", not full.fullmatch(tag))
        expect(f"the pre-release grammar refuses {tag}", not restricted.fullmatch(tag))
    print("selftest: " + ("passed" if failures == 0 else f"{failures} failure(s)"))
    return 1 if failures else 0


def main() -> int:
    if sys.argv[1:] == ["--selftest"]:
        return selftest()
    if sys.argv[1:]:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        found = problems(load())
    except OSError as why:
        print(f"release-tag grammar: cannot read its inputs: {why}", file=sys.stderr)
        return 1
    for problem in found:
        print(f"FAIL: {problem}", file=sys.stderr)
    if found:
        return 1
    print("release-tag grammar: every reader carries the one grammar; PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
