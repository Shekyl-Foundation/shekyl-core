# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Documentation claim audit — a document declares the invariants it means to
# hold, and this gate holds it to them.
#
# WHY THIS EXISTS, and what the evidence was. PR #633 (DRS-P0b) took thirteen
# review rounds. The first nine were reactive: a reviewer found an instance,
# the instance was fixed, and the next round found another instance of the
# same class. From round ten the author ran a mechanical claim check before
# every push, and the character of the rounds changed — that pass caught three
# defects no reviewer had filed (a matrix row routed to a section that did not
# exist, a register that jumped W-3 to W-6, a stated writer count gone stale)
# and the later rounds found only things it could not see. A measured
# before-and-after on one PR is this gate's whole warrant.
#
# WHY DECLARED RATHER THAN UNIVERSAL. The first cut of this script inferred
# the same invariants corpus-wide and reported 991 findings against a clean
# tree. Almost all were false: `§17` usually cites *another* document's
# section, registers legitimately skip a retired number, and the CHANGELOG
# cites files that existed when it was written. A gate that fires 991 times
# on a clean tree is not a strict gate, it is an unusable one — convention
# theatre pointing the other way. So the unit is a DECLARATION: a document
# states, in its own text, which invariants it intends to satisfy, and the
# gate checks exactly those. False positives become impossible by
# construction, and each declaration is a promise a reviewer can read.
#
#     <!-- claim-audit: series DRS-W -->        register rows contiguous, no dupes
#     <!-- claim-audit: range DRS-W -->         "DRS-W1…DRS-Wn" restatements match it
#     <!-- claim-audit: sections -->            every §N names a section this doc has
#     <!-- claim-audit: numbered -->            numbered lists number themselves 1,2,3…
#     <!-- claim-audit: citations -->           every path:line cite resolves in the tree
#     <!-- claim-audit: counts -->              "**N rows**" matches the table beneath it
#
# WHAT IT CANNOT CHECK, stated in the pass line rather than left to inference:
# it audits VALUES AGAINST SOURCE, never RATIONALES AGAINST THE WORLD. Four
# premises were refuted by review in the two days before this was written — a
# doubling time, a parked-baseline frequency, an anonymity premise, and a
# "never live on the reachable grid" claim — and every one would have passed
# this gate green, because each was internally consistent and wrong about
# reality. Green here means "the numbers match their own tables and the tree",
# never "this document is right".
#
# WHAT IT DOES CATCH, as the worked example opposite those four: within an hour
# of the first declaration it found that V4_DESIGN_NOTES.md still restated the
# DRS-W finding range at its old upper bound — a fifth surface, updated in
# review round 7 and missed by the round-13 sweep of four. The rule generated
# the gate and the gate immediately caught the rule's own class in its own
# parent work.
#
# UNUSABLE AND ABSENT ARE THE SAME STATE. This is why the model is declaration
# rather than inference, and it is a rule rather than a preference: a 1.5x
# threshold that fires on thermal variation gets ignored, a flaky required
# check gets bypassed, a gate nobody can read gets disabled, and a claim audit
# with 991 findings on a clean tree gets scrolled past. A check that cannot be
# acted on has the same effect as no check, while costing the trust of the ones
# that can.
#
# SUBJECT ASSERTION (rule 47), per declaration rather than once. A document
# that declares an invariant whose subject this gate cannot find FAILS: the
# distinction that must never blur is CHECKED-AND-PASSED versus
# FOUND-NOTHING-TO-CHECK. This program has been bitten twice by an extraction
# that matched nothing and reported success (a whitespace-rigid regex that
# returned 45 names instead of 46; a macro grep that returned zero against an
# older tree) and twice by a documentation edit whose anchor silently matched
# nothing. A claim auditor that cannot find the table it was told to check and
# prints "no discrepancies" is that same defect wearing this script's name.

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"

DECL = re.compile(r"<!--\s*claim-audit:\s*([a-z]+)(?:\s+([A-Za-z][\w-]*))?\s*-->")
KINDS = {"series", "range", "sections", "numbered", "citations", "counts"}

# Floor on the corpus itself: this gate audits docs/, and a run that cannot
# find the corpus has lost its subject rather than found a tidy tree.
MIN_DOCS = 50
# Floor on adoption: the gate is pointless if nothing declares anything, and a
# run finding zero declarations means the marker syntax broke, not that every
# document opted out.
MIN_DECLARATIONS = 1


def rel(p: pathlib.Path) -> str:
    return str(p.relative_to(ROOT))


def strip_code(text: str) -> str:
    """Blank out fenced and inline code, preserving line numbers.

    Documenting the marker syntax must not opt a document in. This gate's own
    README section and CHANGELOG entry show the markers as examples, and the
    first version read them as declarations — so the documentation of a check
    became a subject of it. Newlines are preserved so every reported line
    number still points where a reader would look.
    """
    out, fenced = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            out.append("")
            continue
        out.append("" if fenced else re.sub(r"`[^`]*`", "", line))
    return "\n".join(out)


def _series_rows(text: str, prefix: str) -> list[int]:
    return [int(m.group(1)) for m in
            re.finditer(rf"^\| {re.escape(prefix)}-?(\d+) \|", text, re.MULTILINE)]


def check_series(p, text, arg, errs):
    if not arg:
        errs.append(f"{rel(p)}: `claim-audit: series` needs a prefix, e.g. "
                    "`series DRS-W`")
        return 0
    nums = _series_rows(text, arg)
    if len(nums) < 2:
        errs.append(f"{rel(p)}: declares `series {arg}` but only {len(nums)} "
                    f"`| {arg}-N |` row(s) were found — the subject this "
                    "declaration names is missing, which is a broken check, "
                    "not a clean one")
        return 0
    dupes = sorted({n for n in nums if nums.count(n) > 1})
    if dupes:
        errs.append(f"{rel(p)}: series {arg} has duplicate rows {dupes}")
    span = range(min(nums), max(nums) + 1)
    missing = [n for n in span if n not in set(nums)]
    if missing:
        errs.append(f"{rel(p)}: series {arg} runs {min(nums)}..{max(nums)} but is "
                    f"missing {missing} — a declared-contiguous register with a "
                    "gap is either incomplete or renumbered")
    return len(nums)


def check_range(p, text, arg, errs, corpus):
    """The declaring doc owns the register; every live restatement must match."""
    if not arg:
        errs.append(f"{rel(p)}: `claim-audit: range` needs a prefix")
        return 0
    nums = _series_rows(text, arg)
    if not nums:
        errs.append(f"{rel(p)}: declares `range {arg}` but owns no "
                    f"`| {arg}-N |` rows — nothing to be the range of")
        return 0
    high = max(nums)
    pat = re.compile(rf"{re.escape(arg)}-?\d+…(?:{re.escape(arg)}-?)?(\d+)")
    seen = 0
    for q, qtext in corpus:
        for m in pat.finditer(qtext):
            seen += 1
            if int(m.group(1)) != high:
                line = qtext[: m.start()].count("\n") + 1
                errs.append(f"{rel(q)}:{line}: restates the {arg} range ending at "
                            f"{m.group(1)}, but {rel(p)} holds {arg}-{high}")
    if seen == 0:
        errs.append(f"{rel(p)}: declares `range {arg}` but no document restates "
                    f"that range — the check has no subject")
    return seen


def check_sections(p, text, _arg, errs):
    have = {m.group(1) for m in re.finditer(r"^#{2,4} (\d+[a-z]?)\.", text, re.M)}
    if not have:
        errs.append(f"{rel(p)}: declares `sections` but has no numbered headings")
        return 0
    seen = 0
    for m in re.finditer(r"§(\d+[a-z]?)(?![\d.])", text):
        seen += 1
        if m.group(1) not in have:
            line = text[: m.start()].count("\n") + 1
            errs.append(f"{rel(p)}:{line}: refers to §{m.group(1)}, which this "
                        f"document does not have")
    if seen == 0:
        errs.append(f"{rel(p)}: declares `sections` but makes no §N reference")
    return seen


def check_numbered(p, text, _arg, errs):
    lines, runs, cur = text.splitlines(), [], []
    for i, line in enumerate(lines, 1):
        m = re.match(r"^(\d+)\. ", line)
        if m:
            cur.append((i, int(m.group(1))))
        elif cur and (line.strip() == "" or not line.startswith((" ", "\t"))):
            if len(cur) >= 3:
                runs.append(cur)
            cur = []
    if len(cur) >= 3:
        runs.append(cur)
    if not runs:
        errs.append(f"{rel(p)}: declares `numbered` but has no numbered list of "
                    "three or more items")
        return 0
    for run in runs:
        nums = [n for _, n in run]
        if nums != list(range(nums[0], nums[0] + len(nums))):
            errs.append(f"{rel(p)}:{run[0][0]}: numbered list runs {nums} — a gap "
                        "or repeat means a step was inserted or removed without "
                        "renumbering")
    return sum(len(r) for r in runs)


def check_citations(p, text, _arg, errs):
    # Anchored at a path boundary: without the leading (?<![\w/-]) a token like
    # `shekyl-economics-sim/src/record.rs:143` matches from its inner "src/" and
    # the gate then reports a file that was never cited. Crate-relative paths are
    # resolved under rust/ before being called missing, and a token under no
    # known root is not this gate's subject rather than a failure.
    cite = re.compile(r"(?<![\w/-])((?:src|rust|scripts|tests|external|shekyl-[\w-]+)"
                      r"/[\w./-]+\.(?:cpp|h|rs|py|sh|inl)):(\d+)")
    seen, lengths = 0, {}
    for m in cite.finditer(text):
        seen += 1
        path, want = m.group(1), int(m.group(2))
        if path not in lengths:
            f = ROOT / path
            if not f.is_file() and not path.startswith(("src/", "rust/", "scripts/",
                                                        "tests/", "external/")):
                f = ROOT / "rust" / path        # crate-relative citation
            lengths[path] = (len(f.read_text(encoding="utf-8", errors="replace")
                                 .splitlines()) if f.is_file() else -1)
        n, line = lengths[path], text[: m.start()].count("\n") + 1
        if n < 0:
            errs.append(f"{rel(p)}:{line}: cites {path}:{want}, which does not exist")
        elif want > n:
            errs.append(f"{rel(p)}:{line}: cites {path}:{want}, but that file has "
                        f"{n} lines")
    if seen == 0:
        errs.append(f"{rel(p)}: declares `citations` but makes none")
    return seen


def check_counts(p, text, _arg, errs):
    seen = 0
    for m in re.finditer(r"\*\*(\d+) (rows|sub-databases)\*\*", text):
        rows, started = [], False
        for line in text[m.end():].splitlines():
            if line.startswith("|"):
                started = True
                if not re.match(r"^\|[\s:|-]+\|?\s*$", line):
                    rows.append(line)
            elif started:
                break
        if len(rows) < 2:
            continue
        seen += 1
        claimed, actual = int(m.group(1)), len(rows) - 1  # minus the header
        if claimed != actual:
            line = text[: m.start()].count("\n") + 1
            errs.append(f"{rel(p)}:{line}: states **{claimed} {m.group(2)}** over a "
                        f"table of {actual} rows")
    if seen == 0:
        errs.append(f"{rel(p)}: declares `counts` but states no **N rows** figure "
                    "above a table")
    return seen


CHECKS = {"series": check_series, "range": check_range, "sections": check_sections,
          "numbered": check_numbered, "citations": check_citations,
          "counts": check_counts}


# Records-was surfaces: a round record or an archived plan states what was true
# when written, so a citation into a since-deleted file is history, not rot —
# its repair is to pin the sha, not to re-anchor. The ratchet counts live
# documents only.
RECORDS_WAS = ("completed/", "audit_trail/", "benchmarks/", "CHANGELOG.md",
               "V3_WALLET_DECISION_LOG.md")
BASELINE = DOCS / "ci" / "doc-claims-baseline.txt"


def is_records_was(p: pathlib.Path) -> bool:
    r = rel(p)
    return any(seg in r for seg in RECORDS_WAS)


def dead_citations(corpus) -> list[str]:
    """Every unresolvable `path:line` in a LIVE document."""
    cite = re.compile(r"(?<![\w/-])((?:src|rust|scripts|tests|external|shekyl-[\w-]+)"
                      r"/[\w./-]+\.(?:cpp|h|rs|py|sh|inl)):(\d+)")
    out, lengths = [], {}
    for p, text in corpus:
        if is_records_was(p):
            continue
        # Raw text, deliberately: citations are written INSIDE backticks by
        # convention (`src/foo.cpp:123`), so stripping inline code here hides
        # the very thing being counted — the first wiring of this ratchet
        # reported 1 dead citation against a measured 56 for exactly that
        # reason. strip_code() belongs on the DECLARATION scan, where a fenced
        # example must not opt a document in, and nowhere else.
        for m in cite.finditer(text):
            path, want = m.group(1), int(m.group(2))
            if path not in lengths:
                f = ROOT / path
                if not f.is_file() and not path.startswith(
                        ("src/", "rust/", "scripts/", "tests/", "external/")):
                    f = ROOT / "rust" / path
                lengths[path] = (len(f.read_text(encoding="utf-8", errors="replace")
                                     .splitlines()) if f.is_file() else -1)
            n = lengths[path]
            if n < 0 or want > n:
                out.append(f"{rel(p)}: {path}:{want}")
    return out


def read_baseline() -> tuple[int, dict[str, set[str]]]:
    if not BASELINE.is_file():
        sys.exit(f"FAIL: {rel(BASELINE)} is missing — the ratchet this gate "
                 "enforces has no baseline, so nothing holds the count down. "
                 "That is a broken run, not a clean one.")
    count, declares = None, {}
    for line in BASELINE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("dead-citations:"):
            count = int(line.split(":", 1)[1])
        elif line.startswith("declares:"):
            _, doc, legs = line.split(None, 2)
            declares[doc] = set(legs.split(","))
    if count is None:
        sys.exit(f"FAIL: {rel(BASELINE)} states no `dead-citations:` figure — "
                 "the ratchet cannot assert against a number that is not there")
    return count, declares


def main() -> None:
    files = sorted(p for p in DOCS.rglob("*.md") if p.is_file())
    if len(files) < MIN_DOCS:
        sys.exit(f"FAIL: found only {len(files)} markdown files under docs/ "
                 f"(floor {MIN_DOCS}) — the corpus this gate audits is missing or "
                 "mis-rooted. That is a broken run, not a clean tree.")
    corpus = [(p, p.read_text(encoding="utf-8")) for p in files]

    errors: list[str] = []
    tally: dict[str, int] = {}
    declarations = 0
    for p, text in corpus:
        for m in DECL.finditer(strip_code(text)):
            kind, arg = m.group(1), m.group(2)
            if kind not in KINDS:
                errors.append(f"{rel(p)}: unknown claim-audit kind '{kind}' "
                              f"(known: {', '.join(sorted(KINDS))})")
                continue
            declarations += 1
            fn = CHECKS[kind]
            n = (fn(p, text, arg, errors, corpus) if kind == "range"
                 else fn(p, text, arg, errors))
            tally[kind] = tally.get(kind, 0) + n

    if declarations < MIN_DECLARATIONS:
        sys.exit(f"FAIL: {declarations} claim-audit declarations found in "
                 f"{len(files)} documents (floor {MIN_DECLARATIONS}) — either the "
                 "marker syntax has changed or the declarations were removed. An "
                 "audit with nothing to audit passes vacuously, so it fails here.")
    # ── ratchet ───────────────────────────────────────────────────────────
    baseline, must_declare = read_baseline()
    dead = dead_citations(corpus)
    if len(dead) > baseline:
        errors.append(
            f"dead citations in live documents rose to {len(dead)} against a "
            f"baseline of {baseline} — new rot:\n    "
            + "\n    ".join(dead[:12])
            + (f"\n    …and {len(dead) - 12} more" if len(dead) > 12 else ""))
    elif len(dead) < baseline:
        errors.append(
            f"dead citations in live documents fell to {len(dead)} from a "
            f"baseline of {baseline} — lower the `dead-citations:` figure in "
            f"{rel(BASELINE)} to {len(dead)} in this change. The ratchet "
            "tightens deliberately; a baseline left above the truth is slack "
            "the next regression hides in.")
    present = {rel(p): {m.group(1) for m in DECL.finditer(strip_code(t))}
               for p, t in corpus}
    for doc, legs in must_declare.items():
        if doc not in present:
            continue  # deleting the document is allowed; un-declaring is not
        dropped = sorted(legs - present[doc])
        if dropped:
            errors.append(
                f"{doc} has dropped the claim-audit declaration(s) {dropped}, "
                f"which {rel(BASELINE)} records it as holding. A document may "
                "add legs freely; removing one is an opt-out that has to be "
                "argued, not a silent edit.")

    if errors:
        sys.exit(f"FAIL: {len(errors)} declared documentation claim(s) disagree "
                 "with what they describe:\n" + "\n".join("  " + e for e in errors))

    body = ", ".join(f"{tally[k]} {k}" for k in sorted(tally))
    print(f"OK: {declarations} declaration(s) across {len(files)} documents — "
          f"{body} — all consistent; dead citations in live documents at the "
          f"baseline of {baseline} (records-was surfaces excluded: a historical "
          f"citation is repaired by pinning its sha, not by re-anchoring).")
    print("     Scope: checks numeric and structural claims against source; "
          "does not check rationales.")


if __name__ == "__main__":
    main()
