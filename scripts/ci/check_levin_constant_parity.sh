#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# LV-1 — Levin wire-constant parity gate.
#
# Every wire constant in `rust/shekyl-levin` is a hand-copy of a C++
# definition, and the crate asserts byte-identity with that C++ in four
# places. Nothing else in CI compiles the two together: CMake builds only
# `-p shekyl-ffi` and `-p shekyl-daemon-image`, so `shekyl-levin` is never
# seen by the C++ build at all. Without this gate, raising
# LEVIN_DEFAULT_MAX_PACKET_SIZE or adding a sixth flag bit on the C++ side
# leaves a fully green tree while the Rust port silently diverges — and the
# divergence is discovered at the LV-3 cutover, on the wire, against live
# peers.
#
# The gate compares each constant's *value* (arithmetic, so `256*1024` and
# `256 * 1024` agree, as do `0x0101010101012101LL` and
# `0x0101_0101_0101_2101`). Any extraction that comes back empty is a
# failure, not a skip: a gate that silently matches nothing is worse than no
# gate.
#
# `HEADER_SIZE` has no C++ literal — it is `sizeof(bucket_head2)` — so
# `levin_base.h` carries a `static_assert(sizeof(bucket_head2) == 33)` for
# this script to read. That assert is load-bearing; see the comment on it.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

levin_base="contrib/epee/include/net/levin_base.h"
levin_compression="contrib/epee/include/net/levin_compression.h"
rust_header="rust/shekyl-levin/src/header.rs"
rust_compress="rust/shekyl-levin/src/compress.rs"

for f in "$levin_base" "$levin_compression" "$rust_header" "$rust_compress"; do
  if [[ ! -f "$f" ]]; then
    echo "FAIL: expected file is missing: $f" >&2
    echo "      (a move or rename must update this gate, not bypass it)" >&2
    exit 1
  fi
done

failures=0

# Strip comments, trailing separators, integer-literal suffixes and Rust
# digit separators, then evaluate as arithmetic.
normalize() {
  local raw="$1"
  raw="${raw%%//*}"
  raw="$(printf '%s' "$raw" | sed -E 's:/\*.*\*/::g; s:[;,].*$::' | tr -d '_ \t')"
  raw="$(printf '%s' "$raw" | sed -E 's/([0-9a-fA-FxX])(ULL|LL|UL|L|u64|u32|i32|usize|u8)$/\1/')"
  printf '%s' "$raw"
}

# Compare one C++ expression against one Rust expression by value.
compare() {
  local label="$1" cpp_raw="$2" rust_raw="$3"

  if [[ -z "$cpp_raw" ]]; then
    echo "FAIL: $label — could not extract the C++ value" >&2
    failures=$((failures + 1))
    return
  fi
  if [[ -z "$rust_raw" ]]; then
    echo "FAIL: $label — could not extract the Rust value" >&2
    failures=$((failures + 1))
    return
  fi

  local cpp rust cpp_val rust_val
  cpp="$(normalize "$cpp_raw")"
  rust="$(normalize "$rust_raw")"

  if ! cpp_val=$((cpp)) 2>/dev/null; then
    echo "FAIL: $label — C++ value '$cpp_raw' is not an integer expression" >&2
    failures=$((failures + 1))
    return
  fi
  if ! rust_val=$((rust)) 2>/dev/null; then
    echo "FAIL: $label — Rust value '$rust_raw' is not an integer expression" >&2
    failures=$((failures + 1))
    return
  fi

  if [[ "$cpp_val" != "$rust_val" ]]; then
    echo "FAIL: $label — C++ $cpp_raw ($cpp_val) != Rust $rust_raw ($rust_val)" >&2
    failures=$((failures + 1))
    return
  fi
  printf 'ok   %-28s %s\n' "$label" "$cpp_val"
}

# Every extractor ends in `|| true`. Without it, `set -e` plus `pipefail`
# aborts the whole script the moment a `grep` matches nothing — the gate
# would still fail closed, but with no diagnostic and with the "could not
# extract" branches below unreachable. A missing definition must be reported
# as the specific thing that is missing.
cpp_define() { # name file
  { grep -E "^[[:space:]]*#define[[:space:]]+$1[[:space:]]" "$2" | head -1 |
    sed -E "s/^[[:space:]]*#define[[:space:]]+$1[[:space:]]+//"; } || true
}

cpp_constexpr() { # name file
  { grep -E "^[[:space:]]*constexpr[^=]*[[:space:]*]$1[[:space:]]*=" "$2" | head -1 |
    sed -E "s/^.*[[:space:]*]$1[[:space:]]*=[[:space:]]*//"; } || true
}

rust_const() { # name file
  { grep -E "^pub const $1[[:space:]]*:" "$2" | head -1 |
    sed -E "s/^pub const $1[[:space:]]*:[^=]*=[[:space:]]*//"; } || true
}

rust_flag() { # name
  { grep -E "^[[:space:]]*pub const $1[[:space:]]*: Flags = Flags\(" "$rust_header" | head -1 |
    sed -E 's/.*Flags\(([^)]*)\).*/\1/'; } || true
}

echo "Levin wire-constant parity: $levin_base + $levin_compression vs rust/shekyl-levin"
echo

compare "LEVIN_SIGNATURE" \
  "$(cpp_define LEVIN_SIGNATURE "$levin_base")" \
  "$(rust_const LEVIN_SIGNATURE "$rust_header")"

compare "INITIAL_MAX_PACKET_SIZE" \
  "$(cpp_define LEVIN_INITIAL_MAX_PACKET_SIZE "$levin_base")" \
  "$(rust_const INITIAL_MAX_PACKET_SIZE "$rust_header")"

compare "DEFAULT_MAX_PACKET_SIZE" \
  "$(cpp_define LEVIN_DEFAULT_MAX_PACKET_SIZE "$levin_base")" \
  "$(rust_const DEFAULT_MAX_PACKET_SIZE "$rust_header")"

compare "PROTOCOL_VERSION_1" \
  "$(cpp_define LEVIN_PROTOCOL_VER_1 "$levin_base")" \
  "$(rust_const PROTOCOL_VERSION_1 "$rust_header")"

compare "Flags::REQUEST" \
  "$(cpp_define LEVIN_PACKET_REQUEST "$levin_base")" "$(rust_flag REQUEST)"
compare "Flags::RESPONSE" \
  "$(cpp_define LEVIN_PACKET_RESPONSE "$levin_base")" "$(rust_flag RESPONSE)"
compare "Flags::BEGIN" \
  "$(cpp_define LEVIN_PACKET_BEGIN "$levin_base")" "$(rust_flag BEGIN)"
compare "Flags::END" \
  "$(cpp_define LEVIN_PACKET_END "$levin_base")" "$(rust_flag END)"
compare "Flags::COMPRESSED" \
  "$(cpp_define LEVIN_PACKET_COMPRESSED "$levin_base")" "$(rust_flag COMPRESSED)"

compare "COMPRESSION_MIN_PAYLOAD" \
  "$(cpp_constexpr COMPRESSION_MIN_PAYLOAD "$levin_compression")" \
  "$(rust_const COMPRESSION_MIN_PAYLOAD "$rust_compress")"

compare "DECOMPRESSED_MAX_SIZE" \
  "$(cpp_constexpr DECOMPRESSED_MAX_SIZE "$levin_compression")" \
  "$(rust_const DECOMPRESSED_MAX_SIZE "$rust_compress")"

compare "ZSTD_COMPRESSION_LEVEL" \
  "$(cpp_constexpr ZSTD_COMPRESSION_LEVEL "$levin_compression")" \
  "$(rust_const ZSTD_COMPRESSION_LEVEL "$rust_compress")"

# HEADER_SIZE: read the C++ side out of the static_assert, since
# `sizeof(bucket_head2)` leaves no literal of its own.
header_size_cpp="$(
  { grep -E "static_assert\([[:space:]]*sizeof\(bucket_head2\)[[:space:]]*==" "$levin_base" |
    head -1 | sed -E 's/.*==[[:space:]]*([0-9]+).*/\1/'; } || true
)"
if [[ -z "$header_size_cpp" ]]; then
  echo "FAIL: HEADER_SIZE — the static_assert(sizeof(bucket_head2) == N) in" >&2
  echo "      $levin_base is gone. Restore it: it is the only literal that" >&2
  echo "      anchors the Rust HEADER_SIZE to the C++ struct." >&2
  failures=$((failures + 1))
else
  compare "HEADER_SIZE" "$header_size_cpp" "$(rust_const HEADER_SIZE "$rust_header")"
fi

echo
if [[ "$failures" -ne 0 ]]; then
  echo "Levin constant parity: $failures mismatch(es)." >&2
  echo "The C++ is the oracle. Update rust/shekyl-levin to match it, and" >&2
  echo "re-check the byte-identity claims in the crate README, the crate" >&2
  echo "docs, docs/CHANGELOG.md and the IMPLEMENTATION_INDEX LV row." >&2
  exit 1
fi
echo "Levin constant parity: all constants match."
