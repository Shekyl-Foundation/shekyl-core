#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Hold the set of block rules that can halt the writer to the one that does.
#
# `BlockRule::check` returns `Result<Verdict<()>, ViewRead<V::Fault>>`
# (CHAIN_RULES_CRATE.md §4.6, 2026-10-07). The widening was forced: a block
# rule reads the view directly and `validate` is its only aggregator, so a
# parent-side hole or a stored bond key the grammar rejects — bytes a
# conforming writer cannot produce, which halt the writer rather than refuse
# the block — had nowhere else to lift. The cost is that every block rule's
# type now says it can produce `ViewRead::Corrupt` while exactly one can
# (CEN-B4). A type claiming more than is true is this codebase's discipline
# running backwards, and a comment does not hold it; this gate does.
#
# What is checked, over `rust/shekyl-chain-rules/src` (tests and the harness
# excluded — those construct `Corrupt` on purpose):
#
#   1. the set of functions whose error position is `ViewRead<…>` (the
#      "lifting" functions: `recorded`, `anchor_window`, `committed_hybrid_key`,
#      the drain and archival helpers, …), read off their signatures;
#   2. every `impl BlockRule for X { … }` body, for the ways `Corrupt` can
#      enter that rule's error:
#        - the path `ViewRead::Corrupt`, in either form the crate writes it:
#          the constructor call `ViewRead::Corrupt(…)` and the constructor
#          passed as a function (`map_err(ViewRead::Corrupt)`, the conversion
#          the archival folds use). A match-arm pattern
#          (`ViewRead::Corrupt(c) =>`) observes an error and is not a site;
#        - a use of a converter: a function whose return type is `ViewRead`
#          itself rather than `Result<_, ViewRead>` (`parent_read`,
#          `record_invariant`). `map_err(parent_read)` carries `Corrupt` and
#          names neither the path nor a lifting function;
#        - a `?` whose operand is a call to a lifting function (a free or
#          path-qualified call, or a method on a receiver other than `view` —
#          `view.method()?` lifts only `V::Fault`). A `?` whose operand is not
#          a call at all is a site too: it is opaque to this walk;
#        - a bare `Err(` that is neither the inner half of `Ok(Err(` nor
#          wrapping an `InvalidBlock` (a refusal, at any nesting) nor a
#          match-arm pattern (`Err(_) =>`);
#   3. the rules with a site are exactly CORRUPT_CAPABLE. A second rule gaining
#      one is a refusal naming the rule and the site, so the day it happens
#      is a reviewed day: the reviewer adds the name here, on purpose. A
#      listed rule with no site is a stale entry and refuses too.
#
# What is not checked: that a lifting function or a converter *does* construct
# `Corrupt` on some path. Both types can carry it, and that is the bar — a
# `-> ViewRead` function is how `parent_read` turns a `Fault::Corrupt` into
# the rule's error. `?` on a view method lifts only `V::Fault` (the `From<VF>
# for ViewRead<VF>` impl), so a rule whose every `?` is on a view method, and
# which never names `ViewRead::Corrupt` or a converter, cannot produce
# `Corrupt`. That is what the absence of a site establishes.
#
# Rule 47: the gate asserts its own subject. No rule files, no `impl
# BlockRule` at all, fewer than MIN_BLOCK_RULES of them, no lifting function,
# or `recorded` not among them — each exits 2, never a vacuous pass.
# `--selftest` bites every refusal red on synthetic sources and reports how
# many fired.
#
# Rule 46: the verdict is the process exit code; nothing here pipes it.

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEFAULT_SRC = REPO / "rust" / "shekyl-chain-rules" / "src"

# The block rules whose error position may carry `ViewRead::Corrupt`.
# CEN-B4 (`rules/attestation.rs`): `anchor_window` lifts a hole in the
# predecessor's anchor window to `Corrupt::HoleBelowTip`; `committed_hybrid_key`
# lifts a stored bond key the grammar rejects to `Corrupt::BondHybridKeyMalformed`.
CORRUPT_CAPABLE: frozenset[str] = frozenset({"B4"})

# Fewer `impl BlockRule` than this and the walk did not find the crate.
MIN_BLOCK_RULES = 10

# The lifting function every parent-side read goes through (`rules/mod.rs`);
# its absence from the set means the signature walk is not reading signatures.
SENTINEL_LIFTER = "recorded"

IMPL_RE = re.compile(r"impl\s+BlockRule\s+for\s+(\w+)\s*\{")
# `fn name<…>(…) -> Result<…, ViewRead<…>>`: from `fn name` to the body's `{`
# without crossing a `;` or another `{`, with `ViewRead<` in the return type.
LIFTER_RE = re.compile(
    r"\bfn\s+(\w+)\s*(?:<[^{;]*?>)?\s*\([^{;]*?\)\s*->\s*Result<[^{;]*?\bViewRead<",
    re.DOTALL,
)
# The path, not the call. `ViewRead::Corrupt(` builds one; `ViewRead::Corrupt`
# passed to `map_err` is the same constructor as a function value.
CORRUPT_PATH_RE = re.compile(r"\bViewRead::Corrupt\b")
# A function returning `ViewRead` directly (not `Result<_, ViewRead>`, which
# is a lifter). The two in the crate both build `Corrupt`.
CONVERTER_RE = re.compile(
    r"\bfn\s+(\w+)\s*(?:<[^{;]*?>)?\s*\([^{;]*?\)\s*->\s*ViewRead<",
    re.DOTALL,
)
IDENT_TAIL_RE = re.compile(r"([A-Za-z_]\w*)\s*$")
# `Err(` that is not the inner half of `Ok(Err(` and does not wrap a refusal
# (`InvalidBlock`, whatever the nesting: `Ok(match … { … => Err(InvalidBlock…) })`).
OUTER_ERR_RE = re.compile(r"(?<!Ok\()\bErr\s*\(\s*(?!InvalidBlock\b)")
VIEW_RECEIVER = "view"
EXCLUDED_SUFFIXES = ("_tests.rs",)
EXCLUDED_PARTS = ("harness",)


class Refused(Exception):
    """A subject-assertion failure (exit 2)."""


@dataclass
class Site:
    rule: str
    path: str
    line: int
    what: str


@dataclass
class Report:
    lifters: set[str] = field(default_factory=set)
    converters: set[str] = field(default_factory=set)
    rules: dict[str, list[Site]] = field(default_factory=dict)


def _strip_comments(text: str) -> str:
    """Blank `//` comments so a mention in prose is not a site, keeping line
    numbers (newlines are preserved)."""
    out: list[str] = []
    for line in text.split("\n"):
        idx = line.find("//")
        out.append(line if idx < 0 else line[:idx])
    return "\n".join(out)


def _call_before(body: str, q: int) -> tuple[str, str | None] | None:
    """The call whose value `?` at `q` propagates: `(name, receiver)`, with
    `receiver` the identifier before a `.` (a method call) or `None` (a free
    or path-qualified call). `None` when the operand is not a call."""
    i = q - 1
    while i >= 0 and body[i].isspace():
        i -= 1
    if i < 0 or body[i] != ")":
        return None
    depth = 0
    while i >= 0:
        if body[i] == ")":
            depth += 1
        elif body[i] == "(":
            depth -= 1
            if depth == 0:
                break
        i -= 1
    head = body[:i]
    m = IDENT_TAIL_RE.search(head)
    if not m:
        return None
    name = m.group(1)
    before = head[: m.start()].rstrip()
    if before.endswith("."):
        recv = IDENT_TAIL_RE.search(before[:-1].rstrip())
        return name, (recv.group(1) if recv else "")
    return name, None


def _is_corrupt_pattern(body: str, path_end: int) -> bool:
    """True when `ViewRead::Corrupt` ending at `path_end` is a match arm.

    The constructor call is `ViewRead::Corrupt(…)`. An arm is that call,
    wrapped in any number of pattern parens (`Err(ViewRead::Corrupt(c))`),
    followed by `=>`. The function form (`map_err(ViewRead::Corrupt)`) has
    no `(`, so it is a value; a call whose `)` closes an argument list is
    followed by `?` or `.`, not `=>`.
    """
    i = path_end
    while i < len(body) and body[i].isspace():
        i += 1
    if i >= len(body) or body[i] != "(":
        return False
    depth = 0
    while i < len(body):
        if body[i] == "(":
            depth += 1
        elif body[i] == ")":
            depth -= 1
            if depth == 0:
                i += 1
                break
        i += 1
    else:
        return False
    while True:
        while i < len(body) and body[i].isspace():
            i += 1
        if i < len(body) and body[i] == ")":
            i += 1
            continue
        break
    return body[i:].startswith("=>")


def _name_uses(body: str, name: str) -> list[int]:
    """Offsets where `name` is used, skipping its own `fn` definition."""
    hits: list[int] = []
    for m in re.finditer(rf"\b{re.escape(name)}\b", body):
        if body[: m.start()].rstrip().endswith("fn"):
            continue
        hits.append(m.start())
    return hits


def _is_match_pattern(body: str, open_idx: int) -> bool:
    """True when the parenthesised group opening at `open_idx` is followed by
    `=>`: a match-arm pattern, not a value."""
    depth = 0
    for i in range(open_idx, len(body)):
        c = body[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return body[i + 1 :].lstrip().startswith("=>")
    return False


def _balanced_body(text: str, open_idx: int) -> int:
    """Index one past the `}` matching the `{` at `open_idx`."""
    depth = 0
    for i in range(open_idx, len(text)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    raise Refused(f"unbalanced braces after offset {open_idx}")


def crate_sources(src: Path) -> dict[str, str]:
    if not src.is_dir():
        raise Refused(f"no source tree at {src}")
    files: dict[str, str] = {}
    for p in sorted(src.rglob("*.rs")):
        rel = p.relative_to(src).as_posix()
        if rel.endswith(EXCLUDED_SUFFIXES) or any(part in EXCLUDED_PARTS for part in p.parts):
            continue
        files[rel] = p.read_text(encoding="utf-8")
    if not files:
        raise Refused(f"no Rust sources under {src}")
    return files


def analyze(files: dict[str, str]) -> Report:
    report = Report()
    stripped = {path: _strip_comments(text) for path, text in files.items()}
    for text in stripped.values():
        for m in LIFTER_RE.finditer(text):
            report.lifters.add(m.group(1))
        for m in CONVERTER_RE.finditer(text):
            report.converters.add(m.group(1))
    if not report.lifters:
        raise Refused("no function returns Result<_, ViewRead<_>>: the signature walk found nothing")
    if SENTINEL_LIFTER not in report.lifters:
        raise Refused(
            f"`{SENTINEL_LIFTER}` is not among the lifting functions "
            f"({sorted(report.lifters)}): the signature walk is not reading signatures"
        )
    for path, text in stripped.items():
        for m in IMPL_RE.finditer(text):
            rule = m.group(1)
            if rule in report.rules:
                raise Refused(f"two `impl BlockRule for {rule}` blocks")
            open_idx = m.end() - 1
            end = _balanced_body(text, open_idx)
            body = text[open_idx:end]
            base_line = text.count("\n", 0, open_idx) + 1
            sites: list[Site] = []
            for lit in CORRUPT_PATH_RE.finditer(body):
                if _is_corrupt_pattern(body, lit.end()):
                    continue  # `ViewRead::Corrupt(c) =>` matches one, it does not build one
                line = base_line + body.count("\n", 0, lit.start())
                nxt = body[lit.end() :].lstrip()[:1]
                form = "ViewRead::Corrupt(…)" if nxt == "(" else "ViewRead::Corrupt"
                sites.append(Site(rule, path, line, form))
            for name in sorted(report.converters):
                for at in _name_uses(body, name):
                    line = base_line + body.count("\n", 0, at)
                    sites.append(Site(rule, path, line, f"{name} → ViewRead"))
            for q in (i for i, c in enumerate(body) if c == "?"):
                line = base_line + body.count("\n", 0, q)
                call = _call_before(body, q)
                if call is None:
                    sites.append(Site(rule, path, line, "? on a non-call operand"))
                    continue
                name, receiver = call
                if receiver == VIEW_RECEIVER:
                    continue  # a view method's error is V::Fault, lifted to View
                if name in report.lifters:
                    sites.append(Site(rule, path, line, f"{name}(…)?"))
            for err in OUTER_ERR_RE.finditer(body):
                if _is_match_pattern(body, err.end() - 1):
                    continue  # `Err(e) => …` matches an error, it does not build one
                line = base_line + body.count("\n", 0, err.start())
                sites.append(Site(rule, path, line, "Err( in the outer position"))
            report.rules[rule] = sites
    if not report.rules:
        raise Refused("no `impl BlockRule for …` found")
    if len(report.rules) < MIN_BLOCK_RULES:
        raise Refused(
            f"only {len(report.rules)} block rules found ({sorted(report.rules)}); "
            f"the crate has at least {MIN_BLOCK_RULES}"
        )
    return report


def judge(report: Report, capable: frozenset[str] = CORRUPT_CAPABLE) -> list[str]:
    """Findings (exit 1), empty when the capable set is exactly `capable`."""
    errs: list[str] = []
    for rule, sites in sorted(report.rules.items()):
        if sites and rule not in capable:
            where = "; ".join(f"{s.path}:{s.line} {s.what}" for s in sites)
            errs.append(
                f"block rule {rule} can produce ViewRead::Corrupt ({where}) and is not in "
                f"CORRUPT_CAPABLE. If the halt is intended, add it there with the reason; "
                f"if not, the read belongs in validate or behind a V::Fault-only path."
            )
    for rule in sorted(capable):
        if rule not in report.rules:
            errs.append(f"CORRUPT_CAPABLE names {rule}, which has no `impl BlockRule`: stale")
        elif not report.rules[rule]:
            errs.append(
                f"CORRUPT_CAPABLE names {rule}, whose body has no Corrupt site: stale entry"
            )
    return errs


def describe(report: Report) -> str:
    capable = sorted(r for r, s in report.rules.items() if s)
    return (
        f"block rules: {len(report.rules)}; lifting functions: {len(report.lifters)}; "
        f"converters: {len(report.converters)}; "
        f"Corrupt-capable: {capable or 'none'}"
    )


# --- selftest ---------------------------------------------------------------

_MOD = """
pub fn recorded<'id, V: ChainView<'id>>(view: &V, height: BlockHeight)
    -> Result<RecordedBlock, ViewRead<V::Fault>> {
    match view.block_at(height).map_err(ViewRead::View)? {
        AtHeight::Recorded(block) => Ok(block),
        AtHeight::AboveTip => Err(ViewRead::Corrupt(Corrupt::HoleBelowTip { at: height })),
    }
}
pub(crate) fn refused<T, F>(rule: CenRow, locus: Locus) -> Result<Verdict<T>, F> { todo!() }
"""

_RULE_T = """
impl BlockRule for {name} {{
    fn check<'id, V: ChainView<'id>>(cx: &BlockContext<'_>, view: &V)
        -> Result<Verdict<()>, {err}> {{
        {body}
    }}
}}
"""


def _rule(name: str, body: str, err: str = "ViewRead<V::Fault>") -> str:
    return _RULE_T.format(name=name, body=body, err=err)



_PLAIN = "if view.has_transaction(h)? { return refused(Self::ROW, Locus::Block); } Ok(Ok(()))"
_B4 = "let w = anchor_window(view, cx.connecting)?; Ok(Ok(()))"
_LIFTS = "let b = recorded(view, cx.connecting)?; Ok(Ok(()))"
_LITERAL = "if bad { return Err(ViewRead::Corrupt(Corrupt::HoleBelowTip { at })); } Ok(Ok(()))"
_MAP_ERR = "let t = accrue(x).map_err(ViewRead::Corrupt)?; Ok(Ok(()))"
_MAP_VIEW = "let t = view.tip().map_err(ViewRead::View)?; Ok(Ok(()))"
_PATTERN = (
    "match read { Ok(()) => Ok(Ok(())), Err(ViewRead::Corrupt(c)) => "
    "refused(Self::ROW, Locus::Block), Err(ViewRead::View(_)) => Ok(Ok(())) }"
)
_OUTER_ERR = "if bad { return Err(fault); } Ok(Ok(()))"
_OPAQUE = "let x = pending?; Ok(Ok(()))"
_METHOD = "let b = BurnOperands::read(view, cx.connecting)?; pairs.extend(b); Ok(Ok(()))"
_READ = """
impl BurnOperands {
    fn read<'id, V: ChainView<'id>>(view: &V, c: BlockHeight) -> Result<Self, ViewRead<V::Fault>> { todo!() }
}
"""
_ANCHOR = """
pub(crate) fn anchor_window<'id, V: ChainView<'id>>(view: &V, c: BlockHeight)
    -> Result<Option<PassAnchorWindow>, ViewRead<V::Fault>> { todo!() }
"""
_CONVERTER = """
fn parent_read<VF>(fault: Fault<VF>) -> ViewRead<VF> { ViewRead::View(fault) }
"""
_MAP_PARENT = "let e = derive(view).map_err(parent_read)?; Ok(Ok(()))"


def _synthetic(*, b4_body: str = _B4, extra: dict[str, str] | None = None, n_plain: int = 12,
               mod: str = _MOD, err: str = "ViewRead<V::Fault>", anchor: str = _ANCHOR) -> dict[str, str]:
    files = {"rules/mod.rs": mod, "rules/attestation.rs": anchor + _rule("B4", b4_body, err)}
    plain = "\n".join(_rule(f"R{i}", _PLAIN, err) for i in range(n_plain))
    # A comment that mentions the literal must not be a site, and neither is
    # a method on `view` nor a `Vec::extend` sharing a lifting method's name.
    files["rules/body.rs"] = (
        "// a comment naming ViewRead::Corrupt( and recorded(view, h)? is prose\n" + plain
    )
    for name, body in (extra or {}).items():
        files[f"rules/{name.lower()}.rs"] = _rule(name, body, err)
    return files


class _Probe:
    def __init__(self) -> None:
        self.refusals = 0

    def clean(self, name: str, files: dict[str, str]) -> None:
        errs = judge(analyze(files))
        if errs:
            raise SystemExit(f"selftest {name}: expected clean, got:\n  " + "\n  ".join(errs))

    def red(self, name: str, files: dict[str, str], needle: str, *, subject: bool = False) -> None:
        try:
            errs = judge(analyze(files))
        except Refused as e:
            if not subject:
                raise SystemExit(f"selftest {name}: expected a finding, got a subject refusal: {e}")
            if needle not in str(e):
                raise SystemExit(f"selftest {name}: refusal lacks {needle!r}: {e}")
            self.refusals += 1
            return
        if subject:
            raise SystemExit(f"selftest {name}: expected a subject refusal, got findings {errs}")
        if not any(needle in e for e in errs):
            raise SystemExit(
                f"selftest {name}: expected a finding mentioning {needle!r}, got:\n  "
                + "\n  ".join(errs)
            )
        self.refusals += 1


def selftest() -> None:
    p = _Probe()
    p.clean("consistent", _synthetic())
    p.red("second rule lifts", _synthetic(extra={"G1": _LIFTS}), "block rule G1 can produce")
    p.red("second rule literal", _synthetic(extra={"C9": _LITERAL}), "block rule C9 can produce")
    p.red("map_err constructor", _synthetic(extra={"C6": _MAP_ERR}), "block rule C6 can produce")
    p.red(
        "map_err converter",
        _synthetic(extra={"F7": _MAP_PARENT}, mod=_MOD + _CONVERTER),
        "block rule F7 can produce",
    )
    p.red("outer Err", _synthetic(extra={"C8": _OUTER_ERR}), "block rule C8 can produce")
    p.red("opaque ?", _synthetic(extra={"C7": _OPAQUE}), "block rule C7 can produce")
    p.red("path-qualified lifting method", _synthetic(extra={"F9": _METHOD}, mod=_MOD + _READ),
          "block rule F9 can produce")
    p.clean("a refusal built inside a match",
            _synthetic(extra={"G7": "Ok(match x { None => Ok(()), Some(l) => Err(InvalidBlock::new(Self::ROW, l)) })"}))
    p.clean("Err as a match pattern",
            _synthetic(extra={"B9": "match verify(x) { Ok(()) => Ok(Ok(())), Err(_) => refused(Self::ROW, Locus::Block) }"}))
    p.clean("ViewRead::Corrupt as a match pattern", _synthetic(extra={"B8": _PATTERN}))
    p.clean(
        "bare ViewRead::Corrupt pattern",
        _synthetic(extra={"B7": "match read { ViewRead::Corrupt(c) => refused(Self::ROW, Locus::Block), ViewRead::View(_) => Ok(Ok(())) }"}),
    )
    p.clean("map_err lifts only View", _synthetic(extra={"C5": _MAP_VIEW}))
    p.clean("Vec::extend shares a lifter's name",
            _synthetic(extra={"F8": "pairs.extend(xs); Ok(Ok(()))"},
                       mod=_MOD + "impl Acc { fn extend(&mut self) -> Result<(), ViewRead<F>> { todo!() } }"))
    p.red("B4 lost its sites", _synthetic(b4_body=_PLAIN), "no Corrupt site: stale entry")
    p.red("B4 impl gone", {"rules/mod.rs": _MOD, "rules/body.rs": _synthetic()["rules/body.rs"]},
          "has no `impl BlockRule`: stale")
    p.red("no impls", {"rules/mod.rs": _MOD}, "no `impl BlockRule", subject=True)
    p.red("too few impls", _synthetic(n_plain=2), "block rules found", subject=True)
    p.red("no lifters", _synthetic(mod="pub fn x() -> u8 { 0 }", err="V::Fault", anchor="",
                                   b4_body=_PLAIN), "no function returns", subject=True)
    p.red("sentinel missing", _synthetic(mod=_MOD.replace("fn recorded", "fn recorded_block")),
          "is not among the lifting functions", subject=True)
    try:
        analyze({})
    except Refused as e:
        if "no source" not in str(e) and "no Rust" not in str(e) and "no function" not in str(e):
            raise SystemExit(f"selftest empty: unexpected refusal {e}")
        p.refusals += 1
    else:
        raise SystemExit("selftest empty: expected a refusal")
    print(f"check_block_rule_corrupt_sites selftest: {p.refusals} refusals fire, consistent set passes")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Hold the Corrupt-capable block rules to CORRUPT_CAPABLE (CEN-B4)."
    )
    ap.add_argument("--src", type=Path, default=DEFAULT_SRC, help="shekyl-chain-rules/src")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--describe", action="store_true", help="print the sets and exit 0")
    args = ap.parse_args(argv)
    if args.selftest:
        selftest()
        return 0
    try:
        report = analyze(crate_sources(args.src))
    except Refused as e:
        print(f"check_block_rule_corrupt_sites: subject missing: {e}", file=sys.stderr)
        return 2
    if args.describe:
        print(describe(report))
        print("lifting functions:", ", ".join(sorted(report.lifters)))
        for rule, sites in sorted(report.rules.items()):
            print(f"  {rule}: " + ("; ".join(f"{s.path}:{s.line} {s.what}" for s in sites) or "—"))
        return 0
    errs = judge(report)
    if errs:
        for e in errs:
            print(f"check_block_rule_corrupt_sites: {e}", file=sys.stderr)
        return 1
    print(f"check_block_rule_corrupt_sites: {describe(report)}; exactly CORRUPT_CAPABLE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
