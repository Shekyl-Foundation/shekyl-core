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
# the `shekyl-harness-*` crates, a file whose `mod` declaration carries a
# cfg naming `test`, an inline `#[cfg(...test...)] mod` block, and a
# statement under a `#[cfg(test)]` attribute.
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
TEST_CFG = re.compile(r"#\[\s*cfg\s*\((?=[^\]]*\btest\b)[^\]]*\)\s*\]")
MOD_DECL = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*(;|\{)")
PATH_ATTR = re.compile(r'#\[\s*path\s*=\s*"([^"]+)"\s*\]')


class GateError(Exception):
    pass


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    kind: str
    text: str


def normalize(text: str) -> str:
    """Whitespace-insensitive text, so rustfmt reflowing a call keeps its row."""
    text = " ".join(text.split())
    text = re.sub(r"\s*([(),])\s*", r"\1", text)
    return text.replace(",", ", ").replace(",  ", ", ").replace(", )", ",)")


def strip_line_comment(line: str) -> str:
    # Good enough for source we write: `//` inside a string literal is rare
    # in the lines these patterns can match, and a miss errs to a hit.
    idx = line.find("//")
    return line if idx < 0 else line[:idx]


def call_argument(lines: list[str], row: int, col: int) -> str:
    """The text from `(` at (row, col) to its matching `)`, across lines."""
    depth = 0
    out: list[str] = []
    r, c = row, col
    while r < len(lines):
        line = strip_line_comment(lines[r])
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


def attributes_above(lines: list[str], row: int) -> list[str]:
    attrs = []
    r = row - 1
    while r >= 0:
        s = lines[r].strip()
        if s.startswith("#["):
            attrs.append(s)
        elif s.startswith("//") or not s:
            pass
        else:
            break
        r -= 1
    return attrs


def test_spans(lines: list[str]) -> list[tuple[int, int]]:
    """Line spans (inclusive) of inline test-only blocks and statements."""
    spans = []
    i = 0
    while i < len(lines):
        if TEST_CFG.search(lines[i]):
            # The item the attribute governs starts at the next line that is
            # not an attribute or a comment.
            j = i + 1
            while j < len(lines) and (
                lines[j].strip().startswith("#[")
                or lines[j].strip().startswith("//")
                or not lines[j].strip()
            ):
                j += 1
            if j >= len(lines):
                break
            depth = 0
            opened = False
            k = j
            while k < len(lines):
                code = strip_line_comment(lines[k])
                depth += code.count("{") - code.count("}")
                if "{" in code:
                    opened = True
                if opened and depth <= 0:
                    break
                if not opened and code.rstrip().endswith(";"):
                    break
                k += 1
            spans.append((j, k))
            i = k + 1
            continue
        i += 1
    return spans


def in_spans(row: int, spans: list[tuple[int, int]]) -> bool:
    return any(a <= row <= b for a, b in spans)


def declared_children(path: str, lines: list[str], test_only: bool) -> set[str]:
    """Files this file declares with `mod x;`; with `test_only`, only those
    under a cfg that names `test`."""
    children = set()
    base = os.path.dirname(path)
    stem = os.path.splitext(os.path.basename(path))[0]
    child_dir = base if stem in ("lib", "main", "mod") else os.path.join(base, stem)
    for row, line in enumerate(lines):
        m = MOD_DECL.match(line)
        if not m or m.group(2) != ";":
            continue
        attrs = attributes_above(lines, row)
        if test_only and not any(TEST_CFG.search(a) for a in attrs):
            continue
        explicit = next((PATH_ATTR.search(a) for a in attrs if PATH_ATTR.search(a)), None)
        if explicit:
            children.add(os.path.normpath(os.path.join(base, explicit.group(1))))
        else:
            children.add(os.path.join(child_dir, m.group(1) + ".rs"))
            children.add(os.path.join(child_dir, m.group(1), "mod.rs"))
    return children


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
    for f in files:
        with open(f, encoding="utf-8", errors="replace") as fh:
            texts[f] = fh.read().splitlines()
    test_files: set[str] = set()
    for f, lines in texts.items():
        test_files |= declared_children(f, lines, test_only=True)
    # Everything a test-only file declares is test-only too.
    frontier = set(test_files)
    while frontier:
        nxt = set()
        for f in frontier:
            if f in texts:
                nxt |= declared_children(f, texts[f], test_only=False) - test_files
        test_files |= nxt
        frontier = nxt

    population = 0
    hits: list[Hit] = []
    for f, lines in texts.items():
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
        for row, raw in enumerate(lines):
            code = strip_line_comment(raw)
            if not code.strip() or in_spans(row, spans):
                continue
            if CLAMP.search(code):
                hits.append(Hit(rel, row + 1, "clamp", normalize(code)))
            for m in REDUCE.finditer(code):
                paren = code.index("(", m.start())
                arg = call_argument(lines, row, paren)
                if SECRET.search(arg):
                    name = code[m.start() : paren].strip()
                    hits.append(Hit(rel, row + 1, "reduce", normalize(f"{name}({arg})")))
    return hits, population


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
            "#[cfg(test)]\nmod inline {\n    fn z(sk: [u8; 32]) { Scalar::from_bytes_mod_order(sk); }\n}\n",
        )
        write("rust/shekyl-app/src/tests.rs", "mod deeper;\nfn y(sk: [u8; 32]) { Scalar::from_bytes_mod_order(sk); }\n")
        write("rust/shekyl-app/src/tests/deeper.rs", "fn y(sk: [u8; 32]) { Scalar::from_bytes_mod_order(sk); }\n")
        write("rust/shekyl-app/tests/it.rs", "fn y(sk: [u8; 32]) { Scalar::from_bytes_mod_order(sk); }\n")
        write("rust/shekyl-oxide/src/lib.rs", "fn y(sk: [u8; 32]) { Scalar::from_bytes_mod_order(sk); }\n")
        hits, _ = scan(tmp)
        got = sorted((h.path, h.kind, h.text) for h in hits)
        expect = sorted(
            [
                ("rust/shekyl-app/src/lib.rs", "reduce", "from_bytes_mod_order(seed,)"),
                ("rust/shekyl-app/src/lib.rs", "clamp", normalize("fn c(o: &mut [u8; 64]) { o[31] |= 0x40; }")),
            ]
        )
        if got != expect:
            print(f"selftest: scan found {got}, expected {expect}", file=sys.stderr)
            return 1

        inv = os.path.join(tmp, INVENTORY)
        os.makedirs(os.path.dirname(inv), exist_ok=True)
        # Red: both sites unlisted.
        with open(inv, "w", encoding="utf-8") as fh:
            fh.write("# empty\n")
        if len(check(tmp)) != 2:
            print("selftest: two unlisted sites did not fail", file=sys.stderr)
            return 1
        # Green: both listed.
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
