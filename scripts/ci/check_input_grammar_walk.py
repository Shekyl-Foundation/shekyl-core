# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# IG-3's walk over the RPC wire's names (docs/design/INPUT_GRAMMAR.md Part C).
#
# The glossary is the tree of terms in §3, §11, §14.2 and §19; every RPC
# method, parameter and reply-field name in §17 and §18 is a path through it
# (RPC_WIRE.md RW-Q1, RW-Q10; INPUT_GRAMMAR.md IG-Q42). This gate refuses:
#   - an undefined term: a segment no glossary table defines;
#   - a non-edge: an adjacent pair that is not a parent -> child edge;
#   - a misplaced qualifier: `max` or `min` anywhere but last;
#   - a duplicate definition: a term with two defining rows, counting every
#     `| Term | Parents |` table in the document, as the daemon's own grammar
#     test does, so a staging table left beside §19 is caught here too;
#   - a cycle: a term that is its own ancestor (IG-2);
#   - a method that does not end in a command: its last term must be a view
#     or a verb under the parent its walk used, read from the Kind column
#     (`parent:view` / `parent:verb`, `—` for a bare subject; IG-3);
#   - a kind written only in prose: a row whose meaning carries the italic
#     *view* / *verb* marker must carry the same kinds in its Kind cell, and
#     each Kind pair must name one of the row's own parents;
#   - drift: a name §17 or §18 gives that the walk table (§18.1) omits,
#     or a method the walk table lists that §17 does not.
#
# How a name walks (IG-Q42). A method starts at a subject and each pair is an
# edge; after `dev`, the rest is a reference (IG-Q49). A parameter or field
# walks its holder's path followed by its own terms; failing that, it may be a
# reference: it starts at a subject and each of its own pairs is an edge. A
# name valid neither way is refused. Glossary edges express refinement only.
#
# THIS GATE IS INTERIM. Its input is §18.1, a table kept in the document,
# because the method table RW-Q7 rules does not exist yet. The rename PR
# (RPC_WIRE.md RW-Q8) builds that table in shekyl-rpc-types; its schema gate
# reads every name and its holder from the request and reply types and
# replaces this one, with §18.1. FOLLOWUPS tracks the replacement ("The input
# grammar's walk gate reads a hand table until RW-Q7's schema gate").
#
# Instance of 47-gate-subject-assertion.mdc: an empty glossary or walk table
# is a missing subject and fails rather than passing vacuously.
#
# Usage: check_input_grammar_walk.py [--selftest] [path-to-INPUT_GRAMMAR.md]

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOC = os.path.join(ROOT, "docs", "design", "INPUT_GRAMMAR.md")

QUALIFIERS = {"max", "min"}
# Value keywords a parameters cell names that are values, not names.
VALUE_KEYWORDS = {"tip", "auto"}
GLOSSARY = [
    ("§3", "## 3. Glossary", "\n## 4."),
    ("§11", "## 11. Glossary", "\n## 12."),
    ("§14.2", "### 14.2", "\n## 15."),
    ("§19", "## 19. Glossary", "\n## 20."),
]
ROW = re.compile(r"^\| ([a-z0-9]+) \|[^\n]*$", re.M)
KINDS = {"view", "verb"}
TICK = re.compile(r"`([^`]+)`")
IDENT = re.compile(r"[a-z][a-z0-9_]*")


def section(doc: str, start: str, end: str) -> str:
    i = doc.index(start)
    return doc[i:doc.index(end, i)]


def cells(line: str) -> list[str]:
    return [c.strip() for c in re.split(r"(?<!\\)\|", line.strip())[1:-1]]


def glossary(doc: str, errors: list[str]):
    """Edges, subjects, defined terms and kinds; duplicate and stray rows are errors."""
    kinds: dict[tuple[str, str], str] = {}
    defined: dict[str, list[str]] = {}
    gains: list[tuple[str, str]] = []
    edges: set[tuple[str, str]] = set()
    subjects: set[str] = set()
    for name, start, end in GLOSSARY:
        sec = section(doc, start, end)
        parts = [(name, sec, True)]
        if name == "§19":
            i, j = sec.index("**New terms:**"), sec.index("**Terms of §3")
            parts = [("§19 new", sec[i:j], True), ("§19 gains", sec[j:], False)]
        for where, text, defining in parts:
            for m in ROW.finditer(text):
                row = cells(m.group(0))
                term, parents = row[0], [x.strip() for x in row[1].split(",")]
                meaning = row[2] if len(row) > 2 else ""
                kind_cell = row[3] if len(row) > 3 else ""
                if defining:
                    defined.setdefault(term, []).append(where)
                else:
                    gains.append((term, where))
                for p in parents:
                    if p in ("—", "any"):
                        subjects.add(term)
                    elif re.fullmatch(r"[a-z0-9]+", p):
                        edges.add((p, term))
                    else:
                        errors.append(f"{where}: `{term}` has a parent that is no term: {p!r}")
                written = set()
                for pair in (x.strip() for x in kind_cell.split(",") if x.strip()):
                    pm = re.fullmatch(r"(—|[a-z0-9]+):(\w+)", pair)
                    if not pm or pm.group(2) not in KINDS:
                        errors.append(f"{where}: `{term}`'s Kind cell has {pair!r}: a pair is `parent:view` or `parent:verb`")
                        continue
                    if pm.group(1) not in parents:
                        errors.append(f"{where}: `{term}`'s Kind pair {pair!r} names a parent the row does not list")
                    kinds[(term, pm.group(1))] = pm.group(2)
                    written.add(pm.group(2))
                prose = set(re.findall(r"\*(view|verb)\*", meaning))
                if prose and not written:
                    errors.append(f"kind drift: {where}: `{term}` is marked *{'*/*'.join(sorted(prose))}* in its meaning and has no Kind cell")
                elif prose != written and (prose or written):
                    errors.append(f"kind drift: {where}: `{term}`'s meaning marks {sorted(prose)} and its Kind cell says {sorted(written)}")
    # Any other `| Term | Parents |` table defines terms too: the daemon's
    # grammar test (shekyl-daemon-config/tests/grammar_names.rs) reads every
    # one, so a staging table outside the sections above is a second home.
    spans = [(doc.index(start), doc.index(end, doc.index(start))) for _, start, end in GLOSSARY]
    lines = doc.split("\n")
    offset, table_line = 0, None
    for n, line in enumerate(lines, 1):
        inside = any(a <= offset < b for a, b in spans)
        if line.startswith("| Term | Parents |") and not inside:
            table_line = n
        elif table_line and not line.startswith("|"):
            table_line = None
        elif table_line and not inside:
            m = ROW.match(line)
            if m:
                defined.setdefault(m.group(1), []).append(f"the table at line {table_line}")
        offset += len(line) + 1
    for term, wheres in sorted(defined.items()):
        if len(wheres) > 1:
            errors.append(f"duplicate definition: `{term}` is defined in {', '.join(wheres)}")
    for term, where in gains:
        if term not in defined:
            errors.append(f"{where}: `{term}` gains a parent but no table defines it")
    for p, c in sorted(edges):
        for t in (p, c):
            if t not in defined and t not in QUALIFIERS:
                errors.append(f"undefined term: `{t}` is a parent in the glossary but no table defines it")
    return edges, subjects, set(defined), kinds


def cycles(edges: set[tuple[str, str]]) -> list[list[str]]:
    children: dict[str, list[str]] = {}
    for p, c in edges:
        children.setdefault(p, []).append(c)
    found, state, stack = [], {}, []

    def visit(t: str) -> None:
        state[t] = 1
        stack.append(t)
        for c in sorted(children.get(t, [])):
            if state.get(c) == 1:
                found.append(stack[stack.index(c):] + [c])
            elif c not in state:
                visit(c)
        stack.pop()
        state[t] = 2

    for t in sorted(children):
        if t not in state:
            visit(t)
    return found


def walk_table(doc: str, errors: list[str]):
    """§18.1's rows: (label, holder path or None for methods, names)."""
    sec = section(doc, "### 18.1", "\n## 19.")
    rows = []
    for line in sec.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 3 or cells[0] in ("Names", "") or set(cells[0]) <= {"-"}:
            continue
        label, holder, names = cells
        obj = None if holder == "method" else TICK.fullmatch(holder).group(1).split()
        rows.append((label, obj, TICK.findall(names)))
    return rows


def drift(doc: str, rows, errors: list[str]) -> None:
    walked = {n for _, _, ns in rows for n in ns}
    methods = {n for _, obj, ns in rows if obj is None for n in ns}
    s17 = section(doc, "## 17.", "\n## 18.")
    seen17 = set()
    for line in s17.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 5 or cells[0] in ("Served today",) or set(cells[0]) <= {"-"}:
            continue
        for m in TICK.findall(cells[1]):
            seen17.add(m)
            if m not in methods:
                errors.append(f"drift: §17 names the method `{m}`, which §18.1 does not walk")
        for t in TICK.findall(cells[2]):
            keys = re.findall(r'"([a-z][a-z0-9_]*)"\s*:', t) or ([t] if IDENT.fullmatch(t) else [])
            for k in keys:
                if k not in walked and k not in methods and k not in VALUE_KEYWORDS:
                    errors.append(f"drift: §17 names the parameter `{k}`, which §18.1 does not walk")
    for m in sorted(methods - seen17):
        errors.append(f"drift: §18.1 walks the method `{m}`, which §17 does not list")
    s18 = section(doc, "## 18.", "### 18.1")
    news = set(re.findall(r"→ `([a-z][a-z0-9_]*)`", s18))
    part_c_cols: list[int] = []
    for line in s18.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not line.startswith("|"):
            part_c_cols = []
            continue
        if "Part C" in cells:
            part_c_cols = [i for i, c in enumerate(cells) if c == "Part C"]
            continue
        for i in part_c_cols:
            if i < len(cells):
                news.update(t for t in TICK.findall(cells[i]) if IDENT.fullmatch(t))
    for n in sorted(news - walked):
        errors.append(f"drift: §18 gives the name `{n}`, which §18.1 does not walk")


def check(doc: str) -> list[str]:
    errors: list[str] = []
    edges, subjects, defined, kinds = glossary(doc, errors)
    if not edges or not defined:
        return errors + ["the glossary is empty: no subject to check (rule 47)"]
    for cyc in cycles(edges):
        errors.append("cycle: " + " -> ".join(cyc))
    rows = walk_table(doc, errors)
    if not rows or not any(obj is None for _, obj, _ in rows):
        return errors + ["§18.1 has no names, or no methods: no subject to check (rule 47)"]

    def pairs_bad(path: list[str]) -> list[tuple[str, str]]:
        return [(a, b) for a, b in zip(path, path[1:]) if b not in QUALIFIERS and (a, b) not in edges]

    for label, obj, names in rows:
        for name in names:
            segs = name.split("_")
            where = f"{label}: `{name}`"
            undefined = [s for s in segs if s not in defined and s not in QUALIFIERS]
            if undefined:
                errors.append(f"undefined term: {where} uses {', '.join('`' + s + '`' for s in undefined)}")
                continue
            if any(s in QUALIFIERS for s in segs[:-1]):
                errors.append(f"misplaced qualifier: {where}: `max` and `min` may only end a path")
                continue
            if obj is None:
                if segs[0] not in subjects:
                    errors.append(f"non-edge: {where} starts at `{segs[0]}`, which is not a subject")
                    continue
                path = segs[1:] if segs[0] == "dev" and len(segs) > 1 and segs[1] in subjects else segs
                bad = pairs_bad(path)
                parent = path[-2] if len(path) > 1 else "—"
                if not bad and kinds.get((path[-1], parent)) not in KINDS:
                    under = f"under `{parent}`" if parent != "—" else "bare"
                    errors.append(f"not a command: {where} ends in `{path[-1]}`, which is neither a view nor a verb {under}")
                    continue
            else:
                bad = pairs_bad(obj + segs)
                if bad and segs[0] in subjects and not pairs_bad(segs):
                    bad = []  # a reference
            if bad:
                errors.append(f"non-edge: {where}: " + ", ".join(f"`{a}` -> `{b}`" for a, b in bad)
                              + " (and not a reference)")
    drift(doc, rows, errors)
    return errors


def selftest(doc: str) -> int:
    def add_name(holder_cell: str, name: str) -> str:
        i = doc.index("### 18.1")
        j = doc.index("\n| ", doc.index("|---", i))
        return doc[:j] + f"\n| selftest | {holder_cell} | `{name}` |" + doc[j:]

    def add_row(table_marker: str, row: str) -> str:
        i = doc.index(table_marker)
        j = doc.index("\n| ", doc.index("|---", i))
        return doc[:j] + "\n" + row + doc[j:]

    def add_method(name: str) -> str:
        out = add_name("method", name)
        i = out.index("## 17.")
        j = out.index("\n| ", out.index("|---", i))
        return out[:j] + f"\n| selftest | `{name}` | — | chain | selftest |" + out[j:]

    cases = [
        ("add chain_coinbase as a method in §17 and §18.1", add_method("chain_coinbase"),
         "ends in `coinbase`, which is neither a view nor a verb under `chain`"),
        ("a meaning marked *view* with no Kind cell",
         add_row("**New terms:**", "| selftestview | chain | *view* — a selftest | |"), "kind drift"),
        ("a Kind cell that disagrees with its meaning's marker",
         add_row("**New terms:**", "| selftestview | chain | *view* — a selftest | chain:verb |"), "kind drift"),
        ("a Kind pair naming a parent the row does not list",
         add_row("**New terms:**", "| selftestview | chain | *view* — a selftest | block:view |"), "does not list"),
        ("add socks-tor: `socks_tor` under `daemon` walks socks -> tor", add_name("`daemon`", "socks_tor"), "non-edge"),
        ("a method that starts below a subject: `socks_tor`", add_name("method", "socks_tor"), "non-edge"),
        ("an undefined term: `bogus`", add_name("`daemon`", "bogus"), "undefined term"),
        ("a misplaced qualifier: `weight_max_total`", add_name("`txpool`", "weight_max_total"), "misplaced qualifier"),
        ("a duplicate definition: `height` again in §19",
         add_row("**New terms:**", "| height | block | a duplicate |"), "duplicate definition"),
        ("a staging table outside §19 that defines `hiding` again",
         doc.replace("## 23. Part E", "| Term | Parents | Meaning |\n|---|---|---|\n| hiding | daemon | a duplicate |\n\n## 23. Part E", 1),
         "duplicate definition"),
        ("add a cycle: `block` under `header`",
         add_row("**Terms of §3", "| block | header | a cycle |"), "cycle"),
        ("drift: §18 gives `pace`, the walk table drops it",
         doc.replace("`connection`, `download_speed`, `pace`,", "`connection`, `download_speed`,", 1), "drift"),
        ("rule 47: an empty walk table",
         re.sub(r"(### 18\.1[^\n]*\n)(?:.*\n)*?(?=\n## 19\.)", r"\1", doc, count=1), "no subject"),
    ]
    base = check(doc)
    failed = 0
    if base:
        print("FAIL  the document as it stands must pass:\n  " + "\n  ".join(base))
        failed += 1
    else:
        print("ok    the document as it stands passes")
    for title, mutated, expect in cases:
        if mutated == doc:
            print(f"FAIL  {title}: the edit did not apply")
            failed += 1
            continue
        errs = check(mutated)
        if any(expect in e for e in errs):
            print(f"ok    {title}: refused ({next(e for e in errs if expect in e)})")
        else:
            print(f"FAIL  {title}: expected a `{expect}` refusal, got {errs or 'none'}")
            failed += 1
    print(f"{failed} failing case(s)")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    path = args[0] if args else DOC
    if not os.path.exists(path):
        print(f"input grammar walk: {path} is missing: no subject to check (rule 47)")
        return 1
    with open(path, encoding="utf-8") as source:
        doc = source.read()
    if "--selftest" in argv:
        return selftest(doc)
    errors = check(doc)
    for e in errors:
        print(e)
    if errors:
        print(f"\ninput grammar walk: {len(errors)} refusal(s)")
        return 1
    rows = walk_table(doc, [])
    n = sum(len(ns) for _, _, ns in rows)
    print(f"input grammar walk: {n} names walked over the glossary, acyclic")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
