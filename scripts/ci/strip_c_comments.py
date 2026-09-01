#!/usr/bin/env python3
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
"""Print a C/C++/Rust source file with its comments removed.

Used by the grep gates that must tell a LIVE call from a mention in prose or
a call somebody disabled. Getting this wrong is a silent green: the gate
certifies a call site that no longer calls anything.

Two language differences are modelled, because both produced real bypasses of
`check_debit_auth_single_source.sh`:

* **Nested block comments.** Rust nests them (`/* /* */ */` is one comment);
  C and C++ end at the FIRST `*/`. Stripping Rust with C semantics left
  `/* outer /* inner */ live_call() */` half-stripped, so a call rustc ignores
  stayed visible to the gate. Stripping C with Rust semantics would be the
  mirror error, swallowing live code after a first terminator.

* **`'` is not always a quote.** In Rust it opens a lifetime far more often
  than a char literal, and a lifetime has no closing `'`. Treating it as a
  delimiter wedged the scanner into "inside a string" from the first lifetime
  to the next apostrophe, preserving every comment in between — `verifier.rs`
  carries ~73 of them. In C++ the same trap is the digit separator
  (`1'000'000`); none exist in this tree today, and it is handled anyway
  because the failure is silent.

UNMODELLED, and therefore the honest limit: Rust raw strings (`r"..."`,
`r#"..."#`) are scanned as ordinary strings, so a `"` inside one ends the
literal early. No raw string on the gated paths contains a comment opener.
The reopening criterion (rule 21) is the same as the gate's: if a real
misclassification lands, this needs a clang/syn-based check over the AST
rather than a scanner.

Line structure is preserved so line-oriented tools keep reporting usable
positions.

`--self-test` runs the regression cases below and is invoked by the gates
that depend on this file, so a stripper regression fails CI on its own rather
than silently widening every gate built on it (rule 47).
"""
import sys

RUST_SUFFIXES = (".rs",)


def _scan_char_or_lifetime(src: str, i: int) -> int:
    """At a `'` in Rust: return the index just past a char literal, or -1 if
    this apostrophe opens a LIFETIME (and so is not a delimiter at all)."""
    n = len(src)
    if i + 1 >= n:
        return -1
    if src[i + 1] == "\\":
        # Escape: '\n', '\'', '\\', '\u{1F600}' — scan to the closing quote.
        j = i + 2
        while j < n and src[j] != "'":
            j += 1
        return j + 1 if j < n else -1
    # A single character followed by a closing quote is a char literal;
    # anything else beginning with an identifier char is a lifetime.
    if i + 2 < n and src[i + 2] == "'":
        return i + 3
    return -1


def strip(src: str, rust: bool = False) -> str:
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]

        # ── string literal ──────────────────────────────────────────────
        if c == '"':
            out.append(c)
            i += 1
            while i < n:
                out.append(src[i])
                if src[i] == "\\" and i + 1 < n:
                    out.append(src[i + 1])
                    i += 2
                    continue
                if src[i] == '"':
                    i += 1
                    break
                i += 1
            continue

        # ── char literal (or, in Rust, a lifetime that is not a quote) ──
        if c == "'":
            if rust:
                end = _scan_char_or_lifetime(src, i)
                if end < 0:
                    # A lifetime. Emit the apostrophe and keep scanning as
                    # ordinary code; do NOT enter quote mode.
                    out.append(c)
                    i += 1
                    continue
            else:
                # C/C++: a `'` flanked by alphanumerics is a digit separator
                # (1'000'000), not a delimiter.
                if i > 0 and src[i - 1].isalnum() and i + 1 < n and src[i + 1].isalnum():
                    out.append(c)
                    i += 1
                    continue
                end = -1
                j = i + 1
                while j < n:
                    if src[j] == "\\":
                        j += 2
                        continue
                    if src[j] == "'":
                        end = j + 1
                        break
                    if src[j] == "\n":
                        break
                    j += 1
            if end < 0:
                out.append(c)
                i += 1
                continue
            out.append(src[i:end])
            i = end
            continue

        # ── comments ────────────────────────────────────────────────────
        if c == "/" and i + 1 < n:
            if src[i + 1] == "/":
                while i < n and src[i] != "\n":
                    # C and C++ splice `\<newline>` in translation phase 2,
                    # BEFORE comments are recognised in phase 3, so a line
                    # comment ending in a backslash swallows the next line
                    # too. `// disabled \` above a call means the compiler
                    # never sees that call — but this scanner used to end at
                    # the physical newline and hand it back to the gate,
                    # which would then certify a disabled authorization site.
                    # Rust has no line splicing, so it keeps ending at the
                    # newline; that difference is asserted in --self-test.
                    if rust or src[i] != "\\":
                        i += 1
                        continue
                    j = i + 1
                    if j < n and src[j] == "\r":
                        j += 1
                    if j < n and src[j] == "\n":
                        # Consume the splice, but EMIT the newline: every
                        # consumer of this output is line-oriented, and
                        # swallowing it would shift every line below.
                        out.append("\n")
                        i = j + 1
                        continue
                    i += 1
                continue
            if src[i + 1] == "*":
                depth = 1
                i += 2
                while i < n and depth > 0:
                    if src[i] == "\n":
                        # Keep newlines so line numbers and statement joins survive.
                        out.append("\n")
                        i += 1
                        continue
                    if rust and src[i] == "/" and i + 1 < n and src[i + 1] == "*":
                        depth += 1
                        i += 2
                        continue
                    if src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                        depth -= 1
                        i += 2
                        continue
                    i += 1
                continue

        out.append(c)
        i += 1
    return "".join(out)


CASES = [
    # (label, source, rust?, must_not_appear)
    ("rust nested block comment hides the call",
     "fn a() { /* outer /* inner */ live_call() */ }", True, "live_call"),
    ("rust lifetime does not wedge the scanner",
     "fn g<'a>() {}\n// live_call()\nfn h() {}", True, "live_call"),
    ("rust single lifetime then block comment",
     "struct S<'a>(&'a u8);\nfn q<'b>() {}\n/* live_call() */", True, "live_call"),
    ("rust char literal still delimits",
     "let c = '/'; // live_call()", True, "live_call"),
    ("c++ digit separator does not wedge",
     "int x = 1'000'000; // live_call()", False, "live_call"),
    ("c++ block comment ends at first terminator",
     "/* a */ int y; /* b */", False, "/*"),
    ("c++ line comment splices over a backslash-newline",
     "// disabled \\\n  live_call();\n", False, "live_call"),
    ("c++ splice handles CRLF",
     "// disabled \\\r\n  live_call();\n", False, "live_call"),
]


def self_test() -> int:
    failures = 0
    for label, src, rust, banned in CASES:
        got = strip(src, rust=rust)
        if banned in got:
            print(f"SELF-TEST FAIL: {label}\n  in : {src!r}\n  out: {got!r}", file=sys.stderr)
            failures += 1
    # Live code must SURVIVE stripping, or the gate fails closed for the wrong
    # reason and every "required call present" check reads as absent.
    survive = [
        ("rust code after a nested comment", "/* /* */ */ live_call()", True),
        ("c++ code after a comment", "/* x */ live_call();", False),
        ("rust code after a lifetime", "fn f<'a>() {} live_call()", True),
        # Rust does not splice: the line after a backslash-ended `//` is CODE,
        # and eating it would make the gate fail closed for the wrong reason.
        ("rust does not splice a backslash-newline", "// disabled \\\nlive_call()", True),
    ]
    for label, src, rust in survive:
        got = strip(src, rust=rust)
        if "live_call" not in got:
            print(f"SELF-TEST FAIL: {label} (live code was eaten)\n  out: {got!r}", file=sys.stderr)
            failures += 1
    if failures:
        print(f"strip_c_comments self-test: {failures} FAILED", file=sys.stderr)
        return 1
    print(f"strip_c_comments self-test: {len(CASES) + len(survive)} cases OK")
    return 0


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        return self_test()
    paths = sys.argv[1:]
    if not paths:
        print("usage: strip_c_comments.py <file>... | --self-test", file=sys.stderr)
        return 2
    # Several files per invocation: the domain-registry gate strips ~759
    # production files per pattern, and one interpreter start per file made
    # the honest version of that gate too slow to run. Output is concatenated;
    # every caller consumes it as a stream, not per-file.
    out = sys.stdout
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                out.write(strip(fh.read(), rust=path.endswith(RUST_SUFFIXES)))
        except OSError as exc:
            print(f"strip_c_comments: cannot read {path}: {exc}", file=sys.stderr)
            return 1
        # Keep a boundary so a match cannot be forged across two files.
        out.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
