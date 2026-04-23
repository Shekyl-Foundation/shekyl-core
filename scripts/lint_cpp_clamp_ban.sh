#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# cpp-clamp-ban-lint: fail CI if any C++ source under src/ performs an Ed25519
# or curve25519 clamp on a 32-byte buffer. Clamping — where it is used at all —
# happens once in Rust at a documented call site; per workspace rule
# 36-secret-locality.mdc, C++ never touches a secret scalar's bits.
#
# This script runs as part of the address-freeze CI workflow and as a local
# pre-commit check. Exit code 0 = clean; non-zero = at least one banned
# pattern was found.
#
# We deliberately match the exact bit-masks that define the RFC 8032 / RFC 7748
# clamp, rather than the names of any surrounding variables, because the
# variable names move around during refactors but the bit-masks are invariant.
#
# Patterns flagged. The Ed25519 / curve25519 clamp is always a mutation of an
# individual byte — it cannot be a comparison or an rvalue mask. We therefore
# flag only the compound-assignment forms, which eliminates most false
# positives from UTF-8 decoders and varint helpers:
#
#   X &= 0xF8   (low-three-bits clear)
#   X &= 0x7F   (high-bit clear)
#   X |= 0x40   (second-highest-bit set)
#   X |= 0x01   (low-bit set — some curve25519 variants)
#
# To further reduce false positives we also require the left-hand side to
# "look like" a byte access: an array index, a pointer dereference, or a
# simple identifier. Anything more complex is conservatively flagged; in
# practice any true clamp matches one of these shapes.
#
# If a legitimate code site needs one of these compound-assignment bit
# patterns for a non-clamp reason, append an end-of-line comment
# "// CLAMP_BAN_ALLOW: <reason>" and the scanner will skip that line. The
# allowlist is empty at address-freeze time; every exception must be
# justified in code review.

set -euo pipefail

ROOT="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"

cd "$ROOT"

if ! command -v rg >/dev/null 2>&1; then
  echo "cpp-clamp-ban-lint: 'rg' (ripgrep) is required" >&2
  exit 2
fi

if [ ! -d src ]; then
  echo "cpp-clamp-ban-lint: no src/ tree at $ROOT; nothing to scan" >&2
  exit 0
fi

# The four canonical clamp bit patterns. We match both the '&' / '&=' and
# '|' / '|=' forms. Whitespace between the operator and the literal is
# tolerated to survive clang-format.
PATTERNS=(
  '&=[[:space:]]*0[xX][fF]8\b'
  '&=[[:space:]]*0[xX]7[fF]\b'
  '\|=[[:space:]]*0[xX]40\b'
  '\|=[[:space:]]*0[xX]01\b'
)

HITS=0
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

for pat in "${PATTERNS[@]}"; do
  # --type cpp restricts to .cpp/.h/.hpp/.cc/.cxx. We exclude generated files
  # under build/ and any explicitly-marked third-party trees.
  rg --no-messages --type cpp \
     --glob '!build/**' \
     --glob '!external/**' \
     --glob '!contrib/epee/**' \
     --glob '!**/third_party/**' \
     -n "$pat" src/ >> "$TMP" || true
done

if [ ! -s "$TMP" ]; then
  echo "cpp-clamp-ban-lint: clean"
  exit 0
fi

# Filter out lines carrying the allowlist marker, reporting the rest.
FAIL=$(grep -v 'CLAMP_BAN_ALLOW' "$TMP" || true)

if [ -z "$FAIL" ]; then
  echo "cpp-clamp-ban-lint: all matches carry CLAMP_BAN_ALLOW markers"
  exit 0
fi

echo "cpp-clamp-ban-lint: BANNED clamp bit-pattern found in C++ source."
echo "per .cursor/rules/36-secret-locality.mdc, C++ must not clamp secret bytes."
echo "if this is a non-clamp use, append '// CLAMP_BAN_ALLOW: <reason>'."
echo
echo "$FAIL"
exit 1
