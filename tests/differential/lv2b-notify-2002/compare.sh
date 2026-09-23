#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# LV-2b 2002 differential: epee's encoder vs the Rust codec, byte for byte.
# Verdicts never travel through a pipe (rule 46).
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(git -C "$HERE" rev-parse --show-toplevel)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; rm -f "$ROOT/rust/shekyl-levin/tests/lv2b_differential.rs"' EXIT

# The protocol header pulls in a generated economics header. It is a build
# artifact, so point at one rather than requiring a full configure here.
GEN="${SHEKYL_GENERATED_INCLUDE:-$ROOT/build/generated_include}"
if [[ ! -f "$GEN/shekyl/economics_params_generated.h" ]]; then
  echo "FAIL: no generated headers at $GEN" >&2
  echo "      configure once (cmake -B build) or set SHEKYL_GENERATED_INCLUDE" >&2
  exit 2
fi

echo "== building the epee harness =="
g++ -std=c++17 -O0 -w \
  -I "$ROOT/src" -I "$ROOT/contrib/epee/include" -I "$ROOT/external/easylogging++" \
  -I "$ROOT/external/supercop/include" -I "$GEN" \
  "$HERE/epee_emit.cpp" "$HERE/stubs.cpp" \
  "$ROOT"/contrib/epee/src/{portable_storage,byte_slice,byte_stream,hex,string_tools,mlocker,wipeable_string,parserse_base_utils}.cpp \
  "$ROOT/contrib/epee/src/memwipe.c" \
  -lboost_filesystem -lboost_system -o "$WORK/epee_emit"

mkdir -p "$WORK/epee" "$WORK/rust"
echo "== epee =="
"$WORK/epee_emit" "$WORK/epee"

echo "== rust =="
cp "$HERE/rust_emit.rs" "$ROOT/rust/shekyl-levin/tests/lv2b_differential.rs"
LV2B_OUT="$WORK/rust" cargo test --manifest-path "$ROOT/rust/Cargo.toml" \
  -p shekyl-levin --test lv2b_differential -- --nocapture

status=0
echo
echo "== comparison =="
shopt -s nullglob
committed=("$HERE"/fixtures/*.bin)
if (( ${#committed[@]} == 0 )); then
  echo "FAIL: no committed fixtures to compare against" >&2   # rule 47
  exit 2
fi
for f in "${committed[@]}"; do
  n="$(basename "$f")"
  for side in epee rust; do
    if [[ ! -f "$WORK/$side/$n" ]]; then
      printf '  MISSING  %-24s (%s produced nothing)\n' "$n" "$side"; status=1; continue
    fi
    if cmp -s "$f" "$WORK/$side/$n"; then
      printf '  match    %-24s %s\n' "$n" "$side"
    else
      printf '  DIFFER   %-24s %s\n' "$n" "$side"; status=1
    fi
  done
done

echo
if (( status == 0 )); then
  echo "OK: both encoders reproduce all ${#committed[@]} committed fixtures"
else
  echo "DIVERGENCE: see DIFFER/MISSING above"
fi
exit "$status"
