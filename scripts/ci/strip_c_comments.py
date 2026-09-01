#!/usr/bin/env python3
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
"""Print a C/C++/Rust source file with its comments removed.

Used by the grep gates that must distinguish a LIVE call from a mention in
prose or a call someone disabled. Stripping only `//` was not enough: a
`/* ... */` around a chunk of code is the ordinary way a C++ maintainer
disables it, and the disabled text stayed visible to `rg`, so a gate could
certify a call site that no longer called anything.

This is a stripper, not a lexer. String literals are honoured (so a `//`
inside one is not mistaken for a comment opener), but escapes are handled
only well enough for that; raw strings and character-literal corner cases
are not modelled. Line structure is preserved so line-oriented tools keep
reporting usable positions.
"""
import sys


def strip(src: str) -> str:
    out = []
    i, n = 0, len(src)
    quote = None  # the delimiter of the string literal we are inside, if any
    while i < n:
        c = src[i]
        if quote is not None:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(src[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ('"', "'"):
            quote = c
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n:
            if src[i + 1] == "/":
                while i < n and src[i] != "\n":
                    i += 1
                continue
            if src[i + 1] == "*":
                i += 2
                # Keep newlines so line numbers and statement joins survive.
                while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                    if src[i] == "\n":
                        out.append("\n")
                    i += 1
                i += 2
                continue
        out.append(c)
        i += 1
    return "".join(out)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: strip_c_comments.py <file>", file=sys.stderr)
        return 2
    with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as fh:
        sys.stdout.write(strip(fh.read()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
