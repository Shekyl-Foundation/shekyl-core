#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The daemon's option documentation is the table's (IG-9).

`docs/generated/shekyld_options.md` and `docs/generated/shekyld.example.toml`
are rendered from the daemon's table by `shekyl-daemon-config` (`docs.rs`),
whose test holds the committed text equal to the rendering. This gate holds
the guides equal to the fragments:

1. each fragment is non-empty and the table names more than a handful of
   rows (rule 47: the gate asserts its own subject);
2. every guide that embeds a fragment carries it verbatim between its
   markers, `<!-- shekyld-options: begin -->` … `<!-- shekyld-options: end -->`
   and `<!-- shekyld-example: begin -->` … `<!-- shekyld-example: end -->`;
3. in the guides listed below, every `--name` that is given to `shekyld` is a
   row of the table: a flag inside a `shekyld …` code span, or inside a
   fenced block whose command is `shekyld`. Other binaries' flags, and a
   bare flag span in prose, are not this gate's.

Exit 0 when every check holds; 1 naming each failure; 2 on a subject that
could not be read.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

TABLE_FRAGMENT = "docs/generated/shekyld_options.md"
EXAMPLE_FRAGMENT = "docs/generated/shekyld.example.toml"

# guide -> the fragments it must embed
EMBEDS = {
    "docs/EXECUTABLES.md": ["options"],
    "docs/USER_GUIDE.md": ["options", "example"],
}

# The guides whose `shekyld` flags must be rows.
FLAG_GUIDES = [
    "README.md",
    "docs/EXECUTABLES.md",
    "docs/USER_GUIDE.md",
    "docs/proxies.md",
    "docs/SHEKYLD_PREREQUISITES.md",
    "docs/COMPILING_DEBUGGING_TESTING.md",
]

MARKERS = {
    "options": ("<!-- shekyld-options: begin -->", "<!-- shekyld-options: end -->"),
    "example": ("<!-- shekyld-example: begin -->", "<!-- shekyld-example: end -->"),
}

MIN_ROWS = 10


def row_names(table_text: str) -> list[str]:
    return re.findall(r"^\| `([a-z][a-z0-9-]*)` \|", table_text, flags=re.M)


def dev_row_names(table_text: str) -> list[str]:
    """The development rows the renderer lists in its HTML comment: live on
    their networks, so a guide of a test network may name them."""
    m = re.search(r"<!-- development rows[^:]*: (.*?) -->", table_text)
    if not m:
        return []
    return re.findall(r"(?:^|; )([a-z][a-z0-9-]*) \(", m.group(1))


def embedded(guide_text: str, kind: str) -> str | None:
    begin, end = MARKERS[kind]
    if begin not in guide_text or end not in guide_text:
        return None
    inner = guide_text.split(begin, 1)[1].split(end, 1)[0]
    # A fenced example sits inside ```toml … ``` within the markers.
    inner = re.sub(r"^\s*```[a-z]*\n", "", inner)
    inner = re.sub(r"\n```\s*$", "\n", inner)
    return inner.strip("\n") + "\n"


def shekyld_flags(guide_text: str) -> list[tuple[int, str]]:
    """(line number, flag) for every --flag given to shekyld in the guide."""
    found: list[tuple[int, str]] = []
    in_fence = False
    fence_is_shekyld = False
    for number, line in enumerate(guide_text.splitlines(), start=1):
        if line.startswith("```"):
            in_fence = not in_fence
            fence_is_shekyld = False
            continue
        if in_fence:
            stripped = line.strip()
            if re.match(r"^(\./|sudo )?shekyld(\.exe)?\b", stripped):
                fence_is_shekyld = True
            elif not stripped.endswith("\\") and not stripped.startswith("--") and not stripped.startswith("-"):
                # A continuation line keeps the command; any other line ends it.
                if not fence_is_shekyld or not re.match(r"^\s+", line):
                    fence_is_shekyld = False
            if fence_is_shekyld or re.match(r"^(\./|sudo )?shekyld(\.exe)?\b", stripped):
                for flag in re.findall(r"(?<![\w-])--([a-z][a-z0-9-]*)", line):
                    found.append((number, flag))
            continue
        if re.search(r"\bshekyld\b", line) and "shekyl-cli" not in line and "wallet" not in line.lower():
            # Flags in code spans: a span that is a flag, or a `shekyld …`
            # command carrying flags.
            for span in re.findall(r"`([^`]+)`", line):
                if re.match(r"^(\./|sudo )?shekyld(\.exe)?\b", span):
                    for flag in re.findall(r"(?<![\w-])--([a-z][a-z0-9-]*)", span):
                        found.append((number, flag))
    return found


def check(repo: Path) -> list[str]:
    errors: list[str] = []
    try:
        table_text = (repo / TABLE_FRAGMENT).read_text(encoding="utf-8")
        example_text = (repo / EXAMPLE_FRAGMENT).read_text(encoding="utf-8")
    except OSError as e:
        return [f"cannot read a fragment: {e}"]
    names = row_names(table_text)
    if len(names) < MIN_ROWS:
        errors.append(f"{TABLE_FRAGMENT} names {len(names)} rows; the table is not that small — the fragment or the pattern is wrong")
    if not example_text.strip() or "# " not in example_text:
        errors.append(f"{EXAMPLE_FRAGMENT} is empty")
    if errors:
        return errors
    fragments = {"options": table_text, "example": example_text}
    for guide, kinds in EMBEDS.items():
        try:
            text = (repo / guide).read_text(encoding="utf-8")
        except OSError as e:
            errors.append(f"cannot read {guide}: {e}")
            continue
        for kind in kinds:
            got = embedded(text, kind)
            if got is None:
                errors.append(f"{guide} has no {MARKERS[kind][0]} … {MARKERS[kind][1]} markers")
            elif got != fragments[kind]:
                errors.append(f"{guide}: the text between the {kind} markers is not {TABLE_FRAGMENT if kind == 'options' else EXAMPLE_FRAGMENT}; paste the fragment")
    live = set(names) | set(dev_row_names(table_text))
    for guide in FLAG_GUIDES:
        try:
            text = (repo / guide).read_text(encoding="utf-8")
        except OSError as e:
            errors.append(f"cannot read {guide}: {e}")
            continue
        for number, flag in shekyld_flags(text):
            if flag not in live:
                errors.append(f"{guide}:{number}: `--{flag}` is not a row of the daemon's table")
    return errors


def selftest() -> int:
    table = (
        "| Option | Kind |\n|---|---|\n"
        + "".join(f"| `row-{i}` | switch |\n" for i in range(12))
        + "<!-- development rows, live on the named networks only and not in --help: dev-lever (regtest) -->\n"
    )
    example = "# shekyld configuration file\n# row-1 = true\n"
    guide_ok = (
        "# Guide\n\n<!-- shekyld-options: begin -->\n" + table + "<!-- shekyld-options: end -->\n\n"
        "<!-- shekyld-example: begin -->\n```toml\n" + example + "```\n<!-- shekyld-example: end -->\n\n"
        "Run `shekyld --row-1`.\n\n```bash\nshekyld --row-2 \\\n    --row-3\nshekyl-cli --proxy x\n```\n"
        "The wallet takes `--proxy` (shekyl-cli).\n"
    )
    cases = [
        ("an embedding guide passes", guide_ok, []),
        ("a stale embedding is named", guide_ok.replace("| `row-11` | switch |\n", ""), ["is not docs/generated/shekyld_options.md"]),
        ("a missing marker is named", guide_ok.replace("<!-- shekyld-example: end -->", ""), ["has no <!-- shekyld-example: begin -->"]),
        ("a dead flag given to shekyld is named", guide_ok.replace("`shekyld --row-1`", "`shekyld --row-x`"), ["`--row-x` is not a row"]),
        ("a dead flag in a shekyld fence is named", guide_ok.replace("    --row-3", "    --no-igd"), ["`--no-igd` is not a row"]),
        ("a development row is live", guide_ok.replace("    --row-3", "    --dev-lever"), []),
    ]
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / "docs" / "generated").mkdir(parents=True)
        (repo / TABLE_FRAGMENT).write_text(table)
        (repo / EXAMPLE_FRAGMENT).write_text(example)
        for guide in EMBEDS:
            (repo / guide).parent.mkdir(parents=True, exist_ok=True)
        for guide in FLAG_GUIDES:
            (repo / guide).parent.mkdir(parents=True, exist_ok=True)
            (repo / guide).write_text("# other\n")
        for title, guide_text, expect in cases:
            for guide in EMBEDS:
                (repo / guide).write_text(guide_text)
            errors = check(repo)
            ok = (not errors) if not expect else (len(errors) == len(expect) * len(EMBEDS) or len(errors) == len(expect)) and all(any(e in err for err in errors) for e in expect)
            print(f"{'ok' if ok else 'FAIL'}: {title}" + ("" if ok else f" — got {errors}"))
            failures += 0 if ok else 1
        (repo / TABLE_FRAGMENT).write_text("| Option |\n|---|\n")
        errors = check(repo)
        ok = any("not that small" in e for e in errors)
        print(f"{'ok' if ok else 'FAIL'}: an empty table fragment is refused")
        failures += 0 if ok else 1
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    repo = Path(__file__).resolve().parents[2]
    errors = check(repo)
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 2 if any("cannot read" in e or "pattern is wrong" in e for e in errors) else 1
    names = row_names((repo / TABLE_FRAGMENT).read_text(encoding="utf-8"))
    print(f"daemon option docs: {len(EMBEDS)} guide(s) embed the generated fragments; every shekyld flag in {len(FLAG_GUIDES)} guide(s) is one of {len(names)} rows")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
