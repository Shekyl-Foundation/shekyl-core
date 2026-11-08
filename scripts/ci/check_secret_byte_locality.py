# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Rule 36 (secret-material locality): secret key bytes, and material derived
# from them, are clamped, reduced and combined only in the crates that own
# the cryptography. Every other crate passes typed values it does not open.
#
# This gate scans the production Rust sources for the two operations that
# open a secret's bytes:
#
#   clamp   the RFC 8032 / X25519 bit-twiddles on byte 0 or byte 31
#           (`&= 0xF8`, `&= 0x7F`, `|= 0x40`, decimal 248 / 127 / 64 too);
#   reduce  `from_bytes_mod_order`, `from_bytes_mod_order_wide`,
#           `from_uniform_bytes` or `from_hash` whose argument names a
#           secret (`secret`, `sk`, `seed`, `mask`, `private`, `shared`).
#
# A hit inside a crypto-owning crate (CRYPTO_CRATES) is the rule working. A
# hit anywhere else must be a row in `docs/ci/secret-byte-locality.tsv`,
# keyed by path, kind and the call's normalized text (never a line number),
# with the reason it is there. The inventory is held in both directions: a
# new site fails, and a row whose site is gone fails, so the file cannot
# grow quietly or rot.
#
# Test code is out of scope: `tests/`, `benches/`, `fuzz/`, `examples/`,
# the `shekyl-harness-*` crates, a file a test-only module declares, an
# inline test-only module, and a statement under a cfg that is false unless
# the crate is built as a test. A cfg is test-only only when `test` is
# required. `not(test)` and `any(test, feature = …)` stay in scope: both
# can compile in a non-test build, and the scan is of source, not of one
# feature set. A cfg on a field or a parameter covers that field only.
# Comments are not attributes, and a brace inside a string is not a brace.
#
# Instance of 47-gate-subject-assertion.mdc: it refuses a population under
# MIN_FILES, a crypto crate that is not in the tree, and an inventory that
# does not parse. Exit status is the verdict (46-shell-gate-exits.mdc).

from __future__ import annotations

import os
import re
import sys
import tempfile
from dataclasses import dataclass

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
INVENTORY = os.path.join("docs", "ci", "secret-byte-locality.tsv")

# The crates that own secret-bearing primitives. Adding one is a reviewed
# change to this list, not a row in the inventory.
CRYPTO_CRATES = (
    "shekyl-crypto-pq",  # keys, KEM, derivation, signatures
    "shekyl-fcmp",  # spend proofs over secret openings
    "shekyl-fcmp-proofs",
    "shekyl-proofs",  # DLEQ / Schnorr
    "shekyl-bulletproofs",  # range proofs over commitment masks
    "shekyl-ct-balance",  # commitment-mask balancing
    "shekyl-curve-primitives",
)
# Vendored downstream (rule 10); not ours to police.
EXCLUDED_CRATES = ("shekyl-oxide",)
TEST_DIRS = {"tests", "benches", "fuzz", "examples"}
SKIP_DIRS = {"target", ".git", "node_modules"}
MIN_FILES = 300

CLAMP = re.compile(
    r"\[\s*(?:0|31)\s*\]\s*(?:&=|\|=)\s*(?:0[xX][fF]8|248|0[xX]7[fF]|127|0[xX]40|64)\b"
)
REDUCE = re.compile(
    r"\b(?:from_bytes_mod_order(?:_wide)?|from_uniform_bytes|from_hash)\s*\("
)
SECRET = re.compile(
    r"(?i)(?:secret|(?<![a-z0-9])sk(?![a-z0-9])|seed|mask|private|shared)"
)
MOD_DECL = re.compile(
    r"(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*([;{])"
)
ITEM_START = re.compile(
    r"^(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:async\s+)?"
    r"(?:fn|mod|struct|enum|union|trait|impl|type|const|static|use|extern|macro)\b"
)
PATH_ATTR = re.compile(r'#\[\s*path\s*=\s*"([^"]+)"\s*\]')
# off: false in every non-test build. on: true in every non-test build.
# maybe: a feature or a target decides, so the source stays in scope.
_OFF, _ON, _MAYBE = "off", "on", "maybe"


class GateError(Exception):
    pass


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    kind: str
    text: str


@dataclass(frozen=True)
class Span:
    """A half-open-on-the-right column range, inclusive of both ends.

    A cfg on a field covers that field. The production sibling on the same
    line, past the field's comma, stays visible.
    """

    start_line: int
    start_col: int
    end_line: int
    end_col: int

    def covers(self, line: int, col: int) -> bool:
        if line < self.start_line or line > self.end_line:
            return False
        if self.start_line == self.end_line:
            return self.start_col <= col <= self.end_col
        if line == self.start_line:
            return col >= self.start_col
        if line == self.end_line:
            return col <= self.end_col
        return True


def normalize(text: str) -> str:
    """Whitespace-insensitive text, so rustfmt reflowing a call keeps its row."""
    text = " ".join(text.split())
    text = re.sub(r"\s*([(),])\s*", r"\1", text)
    return text.replace(",", ", ").replace(",  ", ", ").replace(", )", ",)")


def mask_non_code(text: str) -> str:
    """Comments and string or char contents become spaces. Newlines stay.

    A `#{` inside a string is not a brace, and `#[cfg(test)]` inside a doc
    comment is not an attribute. Columns stay put, so a match on the masked
    line is the same match on the source line.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        raw = _raw_string_at(text, i)
        if raw is not None:
            content, hashes = raw
            end = _raw_string_end(text, content, hashes)
            _blank_range(out, text, i, end)
            i = end
            continue
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if c == "/" and nxt == "*":
            i = _blank_block_comment(out, text, i)
            continue
        if c == '"' or (c in "bc" and nxt == '"' and not _ident(text[i - 1] if i else "")):
            if c != '"':
                out.append(c)
                i += 1
            i = _blank_string(out, text, i)
            continue
        if c == "'":
            end = _char_literal_end(text, i)
            if end is not None:
                _blank_range(out, text, i, end)
                i = end
                continue
        out.append(c)
        i += 1
    return "".join(out)


def _ident(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _blank_range(out: list[str], text: str, start: int, end: int) -> None:
    for ch in text[start:end]:
        out.append("\n" if ch == "\n" else " ")


def _blank_block_comment(out: list[str], text: str, i: int) -> int:
    n = len(text)
    depth = 1
    out.append(" ")
    out.append(" ")
    i += 2
    while i < n and depth:
        if text.startswith("/*", i):
            depth += 1
            out.append(" ")
            out.append(" ")
            i += 2
            continue
        if text.startswith("*/", i):
            depth -= 1
            out.append(" ")
            out.append(" ")
            i += 2
            continue
        out.append("\n" if text[i] == "\n" else " ")
        i += 1
    return i


def _blank_string(out: list[str], text: str, i: int) -> int:
    """`i` points at the opening quote. Returns the index after the closer."""
    n = len(text)
    out.append(" ")
    i += 1
    while i < n:
        ch = text[i]
        if ch == "\\":
            out.append(" ")
            i += 1
            if i < n:
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            continue
        if ch == '"':
            out.append(" ")
            return i + 1
        out.append("\n" if ch == "\n" else " ")
        i += 1
    return i


def _raw_string_at(text: str, i: int) -> tuple[int, int] | None:
    if i > 0 and _ident(text[i - 1]):
        return None
    j = i
    n = len(text)
    if text[j] in "bc" and j + 1 < n and text[j + 1] == "r":
        j += 1
    if j >= n or text[j] != "r":
        return None
    j += 1
    hashes = 0
    while j < n and text[j] == "#":
        hashes += 1
        j += 1
    if j < n and text[j] == '"':
        return j + 1, hashes
    return None


def _raw_string_end(text: str, content: int, hashes: int) -> int:
    closer = '"' + ("#" * hashes)
    found = text.find(closer, content)
    if found < 0:
        return len(text)
    return found + len(closer)


def _char_literal_end(text: str, i: int) -> int | None:
    n = len(text)
    if i + 2 >= n:
        return None
    j = i + 1
    if text[j] == "\\":
        j += 1
        if j >= n:
            return None
        if text[j] == "u" and j + 1 < n and text[j + 1] == "{":
            end = text.find("}", j)
            if end < 0:
                return None
            j = end + 1
        elif text[j] == "x":
            j += 3
        else:
            j += 1
        if j < n and text[j] == "'":
            return j + 1
        return None
    if text[j] not in "'\n" and text[j + 1] == "'":
        return j + 2
    return None


def masked_lines(lines: list[str]) -> list[str]:
    """One masked line per source line. A string or comment may span lines."""
    masked = mask_non_code("\n".join(lines)).splitlines()
    if len(masked) < len(lines):
        masked.extend("" for _ in range(len(lines) - len(masked)))
    return masked[: len(lines)]


def _skip_ws(text: str, i: int) -> int:
    while i < len(text) and text[i] in " \t\n":
        i += 1
    return i


def _parse_cfg(text: str, i: int) -> tuple[tuple, int]:
    """A cfg expression. A form this does not know is `maybe` (stays in scope)."""
    i = _skip_ws(text, i)
    for name in ("all", "any", "not"):
        if text.startswith(name, i) and (i + len(name) >= len(text) or not _ident(text[i + len(name)])):
            j = _skip_ws(text, i + len(name))
            if j >= len(text) or text[j] != "(":
                break
            args = []
            j += 1
            while True:
                j = _skip_ws(text, j)
                if j >= len(text):
                    return (name, args), j
                if text[j] == ")":
                    return (name, args), j + 1
                arg, j = _parse_cfg(text, j)
                args.append(arg)
                j = _skip_ws(text, j)
                if j < len(text) and text[j] == ",":
                    j += 1
                    continue
                if j < len(text) and text[j] == ")":
                    return (name, args), j + 1
                return ("atom", text[i:]), len(text)
    end = i
    depth = 0
    while end < len(text):
        ch = text[end]
        if ch == "(":
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
        elif ch in ",)" and depth == 0:
            break
        end += 1
    return ("atom", text[i:end].strip()), end


def _eval_cfg(node: tuple) -> str:
    kind, val = node
    if kind == "atom":
        return _OFF if val == "test" else _MAYBE
    kids = [_eval_cfg(child) for child in val]
    if kind == "all":
        if any(k == _OFF for k in kids):
            return _OFF
        if any(k == _MAYBE for k in kids):
            return _MAYBE
        return _ON
    if kind == "any":
        if not kids or any(k == _ON for k in kids):
            # `any()` is false in Rust. An empty list here is a parse of
            # `any()`; a child that is `on` makes the whole predicate on.
            return _OFF if not kids else _ON
        if all(k == _OFF for k in kids):
            return _OFF
        return _MAYBE
    if kind == "not" and len(kids) == 1:
        return {_ON: _OFF, _OFF: _ON, _MAYBE: _MAYBE}[kids[0]]
    return _MAYBE


def cfg_attribute_spans(line: str) -> list[tuple[int, int, bool]]:
    """`(start, end, test_only)` for every `#[cfg(...)]` on one masked line.

    `cfg_attr` is not a span: it changes an attribute, it does not delete
    the item. An unparsed cfg stays in scope.
    """
    found = []
    i = 0
    while True:
        start = line.find("#[", i)
        if start < 0:
            break
        end = _matching_bracket(line, start)
        if end is None:
            break
        body = line[start + 2 : end].strip()
        test_only = False
        if body.startswith("cfg") and not body.startswith("cfg_attr") and not _ident(body[3:4] or ""):
            rest = body[3:].lstrip()
            if rest.startswith("(") and rest.endswith(")"):
                node, consumed = _parse_cfg(rest, 1)
                if _skip_ws(rest, consumed) == len(rest) - 1 and rest[-1] == ")":
                    test_only = _eval_cfg(node) == _OFF
        found.append((start, end + 1, test_only))
        i = end + 1
    return found


def _matching_bracket(line: str, start: int) -> int | None:
    depth = 0
    for i in range(start, len(line)):
        if line[i] == "[":
            depth += 1
        elif line[i] == "]":
            depth -= 1
            if depth == 0:
                return i
    return None


def _next_code(lines: list[str], row: int, col: int) -> tuple[int, int] | None:
    r, c = row, col
    while r < len(lines):
        line = lines[r]
        while c < len(line) and line[c] in " \t":
            c += 1
        if c >= len(line):
            r += 1
            c = 0
            continue
        if line.startswith("#[", c):
            end = _matching_bracket(line, c)
            if end is None:
                return None
            c = end + 1
            continue
        return r, c
    return None


def _item_end(lines: list[str], row: int, col: int) -> tuple[int, int]:
    depth = 0
    opened = False
    r, c = row, col
    while r < len(lines):
        line = lines[r]
        while c < len(line):
            ch = line[c]
            if ch == "{":
                depth += 1
                opened = True
            elif ch == "}":
                depth -= 1
                if opened and depth <= 0:
                    return r, c
            elif ch == ";" and not opened:
                return r, c
            c += 1
        r += 1
        c = 0
    return _eof(lines)


def _delim_end(lines: list[str], row: int, col: int) -> tuple[int, int]:
    """End of one field, parameter or statement: comma or semicolon at depth 0,
    or a closer that belongs to the surrounding item."""
    angle = paren = brace = bracket = 0
    r, c = row, col
    while r < len(lines):
        line = lines[r]
        while c < len(line):
            ch = line[c]
            prev = line[c - 1] if c else ""
            if ch == "<":
                angle += 1
            elif ch == ">" and prev != "-" and angle:
                angle -= 1
            elif ch == "(":
                paren += 1
            elif ch == ")":
                if paren:
                    paren -= 1
                elif angle == brace == bracket == 0:
                    return r, c - 1 if c else (r, 0)
            elif ch == "{":
                brace += 1
            elif ch == "}":
                if brace:
                    brace -= 1
                elif angle == paren == bracket == 0:
                    return r, c - 1 if c else (r, 0)
            elif ch == "[":
                bracket += 1
            elif ch == "]" and bracket:
                bracket -= 1
            elif ch in ",;" and angle == paren == brace == bracket == 0:
                return r, c
            c += 1
        r += 1
        c = 0
    return _eof(lines)


def _eof(lines: list[str]) -> tuple[int, int]:
    if not lines:
        return 0, 0
    last = len(lines) - 1
    return last, max(0, len(lines[last]) - 1)


def test_spans(lines: list[str]) -> list[Span]:
    """Regions a cfg removes from every non-test build."""
    spans = []
    # Walk by attribute. An item's span jumps forward; a second cfg inside
    # it is already covered, and the search resumes after the attribute so
    # a cfg later on the same line is still seen.
    row = 0
    col = 0
    while row < len(lines):
        line = lines[row]
        attrs = [a for a in cfg_attribute_spans(line) if a[0] >= col]
        if not attrs:
            row += 1
            col = 0
            continue
        start, end, test_only = attrs[0]
        if not test_only:
            col = end
            continue
        governed = _next_code(lines, row, end)
        if governed is None:
            break
        gr, gc = governed
        if ITEM_START.match(lines[gr][gc:]):
            er, ec = _item_end(lines, gr, gc)
        else:
            er, ec = _delim_end(lines, gr, gc)
        if er < gr or (er == gr and ec < gc):
            er, ec = gr, gc
        spans.append(Span(gr, gc, er, ec))
        if (er, ec) <= (row, end):
            col = end
        else:
            row, col = er, ec + 1
    return spans


def in_spans(row: int, col: int, spans: list[Span]) -> bool:
    return any(span.covers(row, col) for span in spans)


def attributes_above(lines: list[str], row: int) -> list[str]:
    attrs = []
    r = row - 1
    while r >= 0:
        s = lines[r].strip()
        if s.startswith("#["):
            attrs.append(s)
        elif not s:
            pass
        else:
            break
        r -= 1
    return attrs


def _attr_test_only(attr: str) -> bool:
    return any(test_only for _, _, test_only in cfg_attribute_spans(attr))


def _module_child_dir(path: str, prefix: tuple[str, ...]) -> str:
    base = os.path.dirname(path)
    stem = os.path.splitext(os.path.basename(path))[0]
    child = base if stem in ("lib", "main", "mod") else os.path.join(base, stem)
    for name in prefix:
        child = os.path.join(child, name)
    return child


def declared_children(path: str, original: list[str], masked: list[str], test_only: bool) -> set[str]:
    """Files this file declares with `mod x;`.

    With `test_only`, a declaration whose own cfg requires a test build,
    and a declaration nested in an inline module that does. The child of
    `mod checks { mod helper; }` is `checks/helper.rs`, not `helper.rs`.

    Structure is read from the masked lines, so a brace in a string does
    not open a module. `#[path = "..."]` is read from the original line:
    masking a string would erase the path.
    """
    children = set()
    base = os.path.dirname(path)
    # Stack entries are (brace depth after the `{`, test-only, name).
    stack: list[tuple[int, bool, str]] = []
    depth = 0
    for row, line in enumerate(masked):
        pos = 0
        while True:
            found = MOD_DECL.search(line, pos)
            brace = _next_brace(line, pos, found.start() if found else len(line))
            if found and (brace is None or found.start() < brace):
                name, kind = found.group(1), found.group(2)
                prefix = tuple(frame[2] for frame in stack)
                inherited = any(frame[1] for frame in stack)
                at_item_start = found.start() == len(line) - len(line.lstrip())
                if at_item_start:
                    own = any(_attr_test_only(a) for a in attributes_above(masked, row))
                else:
                    own = _same_line_cfg(line, found.start())
                this_test = inherited or own
                if kind == ";":
                    if not test_only or this_test:
                        explicit = _path_attr(original, row, found.start())
                        if explicit:
                            children.add(os.path.normpath(os.path.join(base, explicit)))
                        else:
                            child_dir = _module_child_dir(path, prefix)
                            children.add(os.path.join(child_dir, name + ".rs"))
                            children.add(os.path.join(child_dir, name, "mod.rs"))
                else:
                    depth += line[pos:found.end()].count("{") - line[pos:found.end()].count("}")
                    # The `{` of this mod is inside the match. Count it once.
                    if "{" not in line[found.start():found.end()]:
                        depth += 1
                    stack.append((depth, this_test, name))
                pos = found.end()
                continue
            if brace is None:
                depth += line[pos:].count("{") - line[pos:].count("}")
                break
            ch = line[brace]
            depth += 1 if ch == "{" else -1
            if ch == "}":
                stack[:] = [frame for frame in stack if frame[0] <= depth]
            pos = brace + 1
    return children


def _next_brace(line: str, start: int, limit: int) -> int | None:
    for i in range(start, limit):
        if line[i] in "{}":
            return i
    return None


def _same_line_cfg(line: str, col: int) -> bool:
    return any(test_only for _start, end, test_only in cfg_attribute_spans(line) if end <= col)


def _path_attr(lines: list[str], row: int, col: int) -> str | None:
    """`#[path]` on the original source. The string is the path."""
    for attr in attributes_above(lines, row):
        found = PATH_ATTR.search(attr)
        if found:
            return found.group(1)
    if row < len(lines):
        found = PATH_ATTR.search(lines[row][:col])
        if found:
            return found.group(1)
    return None


def crate_of(rel: str) -> str:
    parts = rel.split(os.sep)
    return parts[1] if len(parts) > 1 and parts[0] == "rust" else ""


def rust_files(root: str) -> list[str]:
    found = []
    base = os.path.join(root, "rust")
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        rel_dir = os.path.relpath(dirpath, root)
        if crate_of(rel_dir + os.sep + "x") in EXCLUDED_CRATES:
            dirnames[:] = []
            continue
        for name in sorted(filenames):
            if name.endswith(".rs"):
                found.append(os.path.join(dirpath, name))
    return found


def scan(root: str) -> tuple[list[Hit], int]:
    files = rust_files(root)
    texts = {}
    masked = {}
    for f in files:
        with open(f, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
        texts[f] = lines
        masked[f] = masked_lines(lines)
    test_files: set[str] = set()
    for f, lines in masked.items():
        test_files |= declared_children(f, texts[f], lines, test_only=True)
    # Everything a test-only file declares is test-only too.
    frontier = set(test_files)
    while frontier:
        nxt = set()
        for f in frontier:
            if f in masked:
                nxt |= declared_children(f, texts[f], masked[f], test_only=False) - test_files
        test_files |= nxt
        frontier = nxt

    population = 0
    hits: list[Hit] = []
    for f, lines in masked.items():
        rel = os.path.relpath(f, root)
        parts = rel.split(os.sep)
        crate = crate_of(rel)
        if crate.startswith("shekyl-harness-"):
            continue
        if any(p in TEST_DIRS for p in parts[2:-1]):
            continue
        if f in test_files:
            continue
        population += 1
        if crate in CRYPTO_CRATES:
            continue
        spans = test_spans(lines)
        for row, code in enumerate(lines):
            if not code.strip():
                continue
            _scan_line(hits, rel, lines, spans, row, code)
    return hits, population


def _scan_line(hits: list[Hit], rel: str, lines: list[str], spans: list[Span], row: int, code: str) -> None:
    for found in CLAMP.finditer(code):
        if not in_spans(row, found.start(), spans):
            hits.append(Hit(rel, row + 1, "clamp", normalize(code)))
            break
    if row > 0 and not CLAMP.search(code) and not CLAMP.search(lines[row - 1]):
        joined = lines[row - 1] + " " + code
        found = CLAMP.search(joined)
        # The index is on the previous line and the operator on this one.
        # One line already matched above; this is only the split form.
        if found and found.start() < len(lines[row - 1]) and not in_spans(row, 0, spans):
            if not in_spans(row - 1, found.start(), spans):
                hits.append(Hit(rel, row + 1, "clamp", normalize(joined)))
    for found in REDUCE.finditer(code):
        if in_spans(row, found.start(), spans):
            continue
        paren = code.index("(", found.start())
        arg = call_argument(lines, row, paren)
        if SECRET.search(arg):
            name = code[found.start() : paren].strip()
            hits.append(Hit(rel, row + 1, "reduce", normalize(f"{name}({arg})")))


def call_argument(lines: list[str], row: int, col: int) -> str:
    """The text from `(` at (row, col) to its matching `)`, across lines."""
    depth = 0
    out: list[str] = []
    r, c = row, col
    while r < len(lines):
        line = lines[r]
        while c < len(line):
            ch = line[c]
            if ch == "(":
                depth += 1
                if depth == 1:
                    c += 1
                    continue
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return normalize("".join(out))
            out.append(ch)
            c += 1
        out.append(" ")
        r += 1
        c = 0
    return normalize("".join(out))


def read_inventory(root: str) -> list[tuple[str, str, str, str]]:
    path = os.path.join(root, INVENTORY)
    if not os.path.isfile(path):
        raise GateError(f"{INVENTORY} is missing — missing subject (rule 47)")
    rows = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip() or line.startswith("#"):
                continue
            cols = line.rstrip("\n").split("\t")
            if len(cols) != 4 or not all(c.strip() for c in cols):
                raise GateError(f"{INVENTORY}:{n}: want path, kind, text, reason (tab-separated)")
            path_, kind, text, reason = (c.strip() for c in cols)
            if kind not in ("clamp", "reduce"):
                raise GateError(f"{INVENTORY}:{n}: kind is clamp or reduce, not {kind!r}")
            if crate_of(path_) in CRYPTO_CRATES:
                raise GateError(f"{INVENTORY}:{n}: {path_} is in a crypto crate and needs no row")
            rows.append((path_, kind, normalize(text), reason))
    return rows


def check(root: str) -> list[str]:
    for crate in CRYPTO_CRATES:
        if not os.path.isdir(os.path.join(root, "rust", crate)):
            raise GateError(f"crypto crate rust/{crate} is not in the tree — the allowlist names a ghost")
    hits, population = scan(root)
    if population < MIN_FILES:
        raise GateError(f"scanned {population} production .rs files (< {MIN_FILES}) — missing subject (rule 47)")
    inventory = read_inventory(root)
    want: dict[tuple[str, str, str], int] = {}
    for path_, kind, text, _ in inventory:
        want[(path_, kind, text)] = want.get((path_, kind, text), 0) + 1
    have: dict[tuple[str, str, str], list[Hit]] = {}
    for h in hits:
        have.setdefault((h.path, h.kind, h.text), []).append(h)
    errors = []
    for key, found in sorted(have.items()):
        extra = len(found) - want.get(key, 0)
        for h in found[len(found) - extra :] if extra > 0 else []:
            errors.append(
                f"{h.path}:{h.line}: {h.kind} of secret bytes outside the crypto crates: {h.text}"
            )
    for key, count in sorted(want.items()):
        missing = count - len(have.get(key, []))
        if missing > 0:
            errors.append(f"{INVENTORY}: no site matches the row {key[0]} {key[1]} {key[2]!r} — delete the row")
    print(
        f"secret-byte locality: {population} production .rs files scanned, "
        f"{len(hits)} site(s) outside the crypto crates, {len(inventory)} inventory row(s)"
    )
    return errors


def selftest() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        def write(rel: str, body: str) -> None:
            p = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(body)

        for crate in CRYPTO_CRATES:
            write(f"rust/{crate}/src/lib.rs", "fn k(s: &mut [u8; 32]) { s[0] &= 248; }\n")
        for i in range(MIN_FILES):
            write(f"rust/shekyl-pad/src/f{i}.rs", "fn f() {}\n")
        write(
            "rust/shekyl-app/src/lib.rs",
            "fn a(seed: [u8; 32]) -> Scalar { Scalar::from_bytes_mod_order(\n    seed,\n) }\n"
            "fn b(x: [u8; 32]) -> Scalar { Scalar::from_bytes_mod_order(x) }\n"
            "fn c(o: &mut [u8; 64]) { o[31] |= 0x40; }\n"
            "// Scalar::from_bytes_mod_order(secret) in a comment\n"
            "#[cfg(test)]\nlet t = Scalar::from_bytes_mod_order(tx_secret);\n"
            "#[cfg(all(test, feature = \"x\"))]\nmod tests;\n"
            "#[cfg(test)]\nmod inline {\n    fn z(sk: [u8; 32]) { Scalar::from_bytes_mod_order(sk); }\n}\n"
            "#[cfg(not(test))]\nfn neg(seed: [u8; 32]) { Scalar::from_bytes_mod_order(seed); }\n"
            "/// see #[cfg(test)]\nfn documented(seed: [u8; 32]) { Scalar::from_bytes_mod_order(seed); }\n"
            "struct Fields {\n"
            "    #[cfg(test)]\n"
            "    fixture: Scalar::from_bytes_mod_order(seed),\n"
            "    scalar: Scalar::from_bytes_mod_order(seed),\n"
            "}\n"
            "#[cfg(test)]\nfn hidden() { let s = \"{\"; }\n"
            "fn after_string(seed: [u8; 32]) { Scalar::from_bytes_mod_order(seed); }\n"
            "fn split(secret: &mut [u8; 32]) {\n    secret[0]\n        &= 248;\n}\n"
            "#[cfg(any(test, feature = \"x\"))]\n"
            "fn feature_or_test(seed: [u8; 32]) { Scalar::from_bytes_mod_order(seed); }\n"
            "fn params(#[cfg(test)] fixture: u8, seed: [u8; 32]) {\n"
            "    Scalar::from_bytes_mod_order(seed);\n"
            "}\n"
            "#[cfg(test)]\nmod checks {\n    mod helper;\n}\n"
            "#[cfg(not(test))]\nmod production_child;\n"
            "// #[cfg(test)]\nmod commented;\n"
            "#[cfg(test)]\n#[path = \"renamed.rs\"]\nmod renamed_tests;\n",
        )
        write("rust/shekyl-app/src/tests.rs", "mod deeper;\nfn y(sk: [u8; 32]) { Scalar::from_bytes_mod_order(sk); }\n")
        write("rust/shekyl-app/src/tests/deeper.rs", "fn y(sk: [u8; 32]) { Scalar::from_bytes_mod_order(sk); }\n")
        write("rust/shekyl-app/tests/it.rs", "fn y(sk: [u8; 32]) { Scalar::from_bytes_mod_order(sk); }\n")
        write("rust/shekyl-oxide/src/lib.rs", "fn y(sk: [u8; 32]) { Scalar::from_bytes_mod_order(sk); }\n")
        write("rust/shekyl-app/src/checks/helper.rs", "fn y(seed: [u8; 32]) { Scalar::from_bytes_mod_order(seed); }\n")
        write("rust/shekyl-app/src/production_child.rs", "fn y(seed: [u8; 32]) { Scalar::from_bytes_mod_order(seed); }\n")
        write("rust/shekyl-app/src/commented.rs", "fn y(seed: [u8; 32]) { Scalar::from_bytes_mod_order(seed); }\n")
        write("rust/shekyl-app/src/renamed.rs", "fn y(seed: [u8; 32]) { Scalar::from_bytes_mod_order(seed); }\n")
        write("rust/shekyl-app/src/renamed_tests.rs", "fn y(seed: [u8; 32]) { Scalar::from_bytes_mod_order(seed); }\n")
        hits, _ = scan(tmp)
        got = sorted((h.path, h.kind, h.text) for h in hits)
        reduce = "from_bytes_mod_order(seed)"
        app = "rust/shekyl-app/src/lib.rs"
        expect = sorted(
            [
                (app, "reduce", "from_bytes_mod_order(seed,)"),
                (app, "clamp", normalize("fn c(o: &mut [u8; 64]) { o[31] |= 0x40; }")),
                (app, "reduce", reduce),  # #[cfg(not(test))]
                (app, "reduce", reduce),  # doc comment citing cfg(test)
                (app, "reduce", reduce),  # sibling of a cfg(test) field
                (app, "reduce", reduce),  # after a test fn whose string holds '{'
                (app, "clamp", normalize("secret[0] &= 248;")),
                (app, "reduce", reduce),  # any(test, feature)
                (app, "reduce", reduce),  # body after a cfg(test) parameter
                ("rust/shekyl-app/src/production_child.rs", "reduce", reduce),
                ("rust/shekyl-app/src/commented.rs", "reduce", reduce),
                # #[path] names renamed.rs. The default renamed_tests.rs is
                # not that module, so its reduction stays in scope.
                ("rust/shekyl-app/src/renamed_tests.rs", "reduce", reduce),
            ]
        )
        if got != expect:
            print(f"selftest: scan found {got}, expected {expect}", file=sys.stderr)
            return 1

        inv = os.path.join(tmp, INVENTORY)
        os.makedirs(os.path.dirname(inv), exist_ok=True)
        # Red: every site unlisted.
        with open(inv, "w", encoding="utf-8") as fh:
            fh.write("# empty\n")
        if len(check(tmp)) != len(expect):
            print("selftest: unlisted sites did not fail", file=sys.stderr)
            return 1
        # Green: every site listed.
        rows = [(h.path, h.kind, h.text) for h in hits]
        with open(inv, "w", encoding="utf-8") as fh:
            for p, k, t in rows:
                fh.write(f"{p}\t{k}\t{t}\tselftest\n")
        if check(tmp):
            print("selftest: a fully listed tree failed", file=sys.stderr)
            return 1
        # Red: a row whose site is gone.
        with open(inv, "a", encoding="utf-8") as fh:
            fh.write("rust/shekyl-app/src/lib.rs\treduce\tfrom_bytes_mod_order(gone_secret)\tstale\n")
        if len(check(tmp)) != 1:
            print("selftest: a stale row did not fail", file=sys.stderr)
            return 1
        # Red: a row inside a crypto crate is refused.
        with open(inv, "w", encoding="utf-8") as fh:
            fh.write("rust/shekyl-crypto-pq/src/lib.rs\tclamp\tx\tno\n")
        try:
            check(tmp)
        except GateError:
            pass
        else:
            print("selftest: a crypto-crate row was accepted", file=sys.stderr)
            return 1
    # Red: an empty population is refused.
    with tempfile.TemporaryDirectory() as empty:
        for crate in CRYPTO_CRATES:
            os.makedirs(os.path.join(empty, "rust", crate))
        try:
            check(empty)
        except GateError:
            pass
        else:
            print("selftest: an empty tree passed", file=sys.stderr)
            return 1
    print("selftest: ok")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    try:
        errors = check(ROOT)
    except GateError as e:
        print(f"secret-byte locality: {e}", file=sys.stderr)
        return 1
    for e in errors:
        print(e, file=sys.stderr)
    if errors:
        print(
            "Move the operation into a crypto crate (rule 36), or add a row with its reason "
            f"to {INVENTORY}.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
