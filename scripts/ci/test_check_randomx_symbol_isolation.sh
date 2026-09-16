#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Negative controls for check_randomx_symbol_isolation.sh (rule 50).
# Feeds synthetic `nm` dumps through a PATH shim so the six checks can
# go red without a shekyld. Name the edit that fails: each case below
# is that edit.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATE="$ROOT/scripts/ci/check_randomx_symbol_isolation.sh"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# Minimal plain/`--demangle` tables that satisfy checks 1–5 and check 6's
# presence anchors. Cases below add the one symbol that should turn red.
PLAIN_OK='0000000000695950 T shekyl_pow_randomx_v2_hash
0000000000aaaaaa t _ZN3aes4some'
DEMANGLED_OK='0000000000610d0e T cryptonote::hash_pow_randomx(void const*, unsigned long, crypto::hash const&, crypto::hash&)
0000000002e5bbb0 b cryptonote::(anonymous namespace)::s_pow_hash_override_for_tests'

install_nm() {
  local plain="$1"
  local demangled="$2"
  printf '%s\n' "$plain" >"$WORKDIR/plain"
  printf '%s\n' "$demangled" >"$WORKDIR/demangled"
  cat >"$WORKDIR/nm" <<'EOF'
#!/bin/sh
demangle=0
for a in "$@"; do
  [ "$a" = "--demangle" ] && demangle=1
done
if [ "$demangle" = 1 ]; then
  cat "$FAKE_NM_DEMANGLED"
else
  cat "$FAKE_NM_PLAIN"
fi
exit 0
EOF
  chmod +x "$WORKDIR/nm"
}

run_gate() {
  FAKE_NM_PLAIN="$WORKDIR/plain" \
  FAKE_NM_DEMANGLED="$WORKDIR/demangled" \
  PATH="$WORKDIR:$PATH" \
    "$GATE" "$WORKDIR/fake_shekyld"
}

touch "$WORKDIR/fake_shekyld"

failed=0
expect() {
  local label="$1"
  local want="$2"
  local rc=0
  local out
  out="$(run_gate 2>&1)" || rc=$?
  if [ "$rc" -eq "$want" ]; then
    echo "PASS: $label (rc=$rc)"
  else
    echo "FAIL: $label (want rc=$want, got $rc)" >&2
    printf '%s\n' "$out" >&2
    failed=1
  fi
}

install_nm "$PLAIN_OK" "$DEMANGLED_OK"
expect "happy path (setter gc'd, schema names absent)" 0

install_nm "$PLAIN_OK" "$DEMANGLED_OK
0000000000610e00 T cryptonote::set_pow_hash_override_for_tests(bool (*)(void const*, unsigned long, crypto::hash const&, crypto::hash&))"
expect "setter present" 1

# Tab-separated nm (the dialect check 1 documents). The setter absence
# must not go green because the pattern used a literal space.
install_nm "$PLAIN_OK" "$(printf '0000000000610d0e\tT\tcryptonote::hash_pow_randomx(void const*)\n0000000002e5bbb0\tb\tcryptonote::(anonymous namespace)::s_pow_hash_override_for_tests\n0000000000610e00\tT\tcryptonote::set_pow_hash_override_for_tests()')"
expect "tab-separated nm still catches setter" 1

install_nm "$PLAIN_OK" "$DEMANGLED_OK
0000000000610e00 T cryptonote::set_pow_schema_override_for_tests()"
expect "schema-seam re-minted" 1

install_nm "$PLAIN_OK" '0000000000610d0e T cryptonote::hash_pow_randomx(void const*, unsigned long, crypto::hash const&, crypto::hash&)'
expect "slot absent" 1

install_nm "$PLAIN_OK" '0000000002e5bbb0 b cryptonote::(anonymous namespace)::s_pow_hash_override_for_tests'
expect "dispatch absent" 1

if [ "$failed" -ne 0 ]; then
  exit 1
fi
echo "check_randomx_symbol_isolation negatives: OK"
