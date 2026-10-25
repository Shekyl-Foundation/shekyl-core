#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Render the verdict records of one results/<date>/ directory as a Markdown
# table, so the README's numbers come from the files and never from hand.
#
#   python3 docs/formal/checkct/summarize.py docs/formal/checkct/results/2026-10-24
#
# One row per (record, target): counts of secure / insecure / unknown and
# the entrypoints that were not secure. A record is a run.sh .txt file; the
# dynamic rows are plain text and are listed by name only.
import re
import sys
from pathlib import Path

ROW = re.compile(r"^\s+(\S+)\s+(\S+)\s+(\S+)\s+(secure|insecure|unknown|error)\s*$")


def summarize(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    header = dict(
        line.split(": ", 1) for line in text.splitlines() if ": " in line and not line.startswith(" ")
    )
    workspace = header.get("workspace", path.stem)
    toolchain = header.get("toolchain", "?")
    options = header.get("cargo-checkct", "").split("options:")[-1].strip() or "defaults"
    by_target: dict[str, dict[str, list[str]]] = {}
    for line in text.splitlines():
        m = ROW.match(line)
        if not m:
            continue
        _driver, target, entry, status = m.groups()
        by_target.setdefault(target, {}).setdefault(status, []).append(entry.split("::")[-1])
    rows = []
    for target, statuses in sorted(by_target.items()):
        n = {s: len(statuses.get(s, [])) for s in ("secure", "insecure", "unknown", "error")}
        notes = "; ".join(
            f"{s}: {', '.join(sorted(statuses[s]))}" for s in ("insecure", "unknown", "error") if statuses.get(s)
        )
        rows.append(
            f"| `{path.name}` | {workspace} | {toolchain} | `{options}` | {target} | "
            f"{n['secure']} / {n['insecure']} / {n['unknown'] + n['error']} | {notes or '—'} |"
        )
    return rows


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: summarize.py results/<date>")
    day = Path(sys.argv[1])
    if not day.is_dir():
        raise SystemExit(f"no such results directory: {day}")
    records = sorted(day.glob("*.txt"))
    if not records:
        raise SystemExit(f"no .txt records in {day}")
    print("| record | workspace | toolchain | options | target | secure / insecure / unknown | not secure |")
    print("| --- | --- | --- | --- | --- | --- | --- |")
    dynamic = []
    for rec in records:
        rows = summarize(rec)
        if rows:
            print("\n".join(rows))
        else:
            dynamic.append(rec.name)
    for name in dynamic:
        print(f"| `{name}` | dynamic | see file | — | — | — | not a checkct record |")


if __name__ == "__main__":
    main()
