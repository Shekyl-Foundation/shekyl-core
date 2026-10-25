#!/usr/bin/env bash
#
# Copyright (c) 2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
#
# The node's template draws its secrets from the OS (DRS_X_STORE_FLIP.md
# DX-Q3, Q4).
#
# The tip follower builds the node's one block template
# (rust/shekyl-chain-ingest/src/template.rs). Its coinbase transaction
# secret is OS-random per template and its draw commitment is
# `commit_and_discard`'s. The scenario driver, a test instrument, builds
# with a counter-derived secret and a commitment stamped over
# CONFORMING_DRAW_COMMITMENT, so its blocks are reproducible. Either value
# in a production block is a key anyone can guess.
#
# Contract:
#   1. the production code of the crates that build, carry and serve the
#      template names neither CONFORMING_DRAW_COMMITMENT nor the scenario's
#      builder;
#   2. the producer draws from the OS and commits through
#      commit_and_discard;
#   3. the scenario's builder still uses both test values where this gate
#      expects them (rule 47: a moved subject fails loudly, never passes
#      on zero hits);
#   4. shekyl-ffi, which builds the C++ template's coinbase extra, names
#      the conforming value only in its coinbase-extra module, and there
#      only in the module's `use` list, the test-support writer
#      `shekyl_test_coinbase_extra` (its doc and its body) and the module's
#      `#[cfg(test)]` tests through that module's closing brace. A
#      production helper after the tests is not exempt. The production
#      writer commits through commit_and_discard, and no C++ under src/
#      calls the test writer. Two fixtures prove the brace before the real
#      file is judged: a helper before the test module and one after it
#      are reported, and a use inside the module is not.
#
# The test writer is an unconditional export, so it is in the archive the
# C++ tests link, which is the archive the non-daemon binaries link too
# (`cfg(test)` never reaches a C++ test's link: cmake builds the archive
# with `cargo build -p shekyl-ffi`). Keeping it out of shipped binaries is
# FOLLOWUPS F-7's structural gate (docs/design/F7_TEST_ONLY_FFI_EXPORTS.md);
# until then this gate holds the value to the one function, and src/ to
# no caller.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

if ! command -v rg >/dev/null 2>&1; then
  echo "FAIL: ripgrep (rg) not found — the gate cannot enforce its contract" >&2
  exit 1
fi

# rg exit-code discipline: 0 = matches, 1 = no matches, >1 = scan error.
scan() {
  local rc=0
  rg "$@" || rc=$?
  if (( rc > 1 )); then
    echo "FAIL: rg exited ${rc} (scan error, not no-match) during: rg $*" >&2
    return "${rc}"
  fi
  return 0
}

PRODUCER="rust/shekyl-chain-ingest/src/template.rs"
SCENARIO="rust/shekyl-chain-ingest/src/scenario.rs"
# The production sources of the crates that build, post and serve the
# template. Test modules, test support and the test-only scenario driver
# (`cfg(any(test, feature = "harness"))`, a TEST_ONLY feature) are out.
PRODUCTION_DIRS=(
  rust/shekyl-chain-ingest/src
  rust/shekyl-node/src
  rust/shekyl-block-template/src
  rust/shekyl-miner/src
  rust/shekyl-daemon-rpc/src
  rust/shekyl-daemon/src
)
FFI_DIR="rust/shekyl-ffi/src"
FFI_EXTRA="rust/shekyl-ffi/src/tx_extra_codec_ffi.rs"
TEST_GLOBS=(
  --glob '!*_tests.rs'
  --glob '!tests.rs'
  --glob '!test_support.rs'
  --glob '!scenario*.rs'
)

FAIL=0

for f in "$PRODUCER" "$SCENARIO" "$FFI_EXTRA"; do
  if [[ ! -f "$f" ]]; then
    echo "FAIL: $f not found — a pinned file moved; update this gate" >&2
    exit 1
  fi
done
for d in "${PRODUCTION_DIRS[@]}"; do
  if [[ ! -d "$d" ]]; then
    echo "FAIL: $d not found — a pinned crate moved; update this gate" >&2
    exit 1
  fi
done

# -- 1. No test value in production code ------------------------------------
hits="$(scan -n 'CONFORMING_DRAW_COMMITMENT|scenario::build_template' "${TEST_GLOBS[@]}" "${PRODUCTION_DIRS[@]}")"
if [[ -n "$hits" ]]; then
  echo "FAIL: a test-only template value is named in production code:" >&2
  echo "$hits" >&2
  echo "  The node's template draws its coinbase secret from the OS and its" >&2
  echo "  draw commitment from commit_and_discard (template.rs)." >&2
  FAIL=1
fi

# -- 2. The producer draws from the OS --------------------------------------
for needle in 'OsRng' 'commit_and_discard\(\)'; do
  found="$(scan -c "$needle" "$PRODUCER")"
  if [[ -z "$found" ]]; then
    echo "FAIL: ${PRODUCER} no longer names ${needle} — the template's secrets must be the OS's" >&2
    FAIL=1
  fi
done

# -- 3. The subject this gate excludes is where it is expected ---------------
for needle in 'CONFORMING_DRAW_COMMITMENT' 'counter\.to_le_bytes\(\)'; do
  found="$(scan -c "$needle" "$SCENARIO")"
  if [[ -z "$found" ]]; then
    echo "FAIL: ${SCENARIO} no longer names ${needle} — the test values moved; point this gate at them" >&2
    FAIL=1
  fi
done

# -- 4. shekyl-ffi: the conforming value only in the test-support writer ----
# Lines that name the value outside the use list, the test writer and the
# test module. The module's exemption ends at its first column-0 `}`:
# rustfmt indents every brace inside the module, so that line is the
# module's close. A column-0 brace earlier fails closed (the real constant
# in the tests would be reported). `NO_TEST_WRITER`, `NO_TEST_MODULE`,
# `NO_TEST_END` and `NOT_IN_TEST_WRITER` mean the subject moved.
commitment_outside() {
  awk '
    { line[NR] = $0 }
    END {
      for (i = 1; i <= NR; i++)
        if (line[i] ~ /^pub unsafe extern "C" fn shekyl_test_coinbase_extra\(/) fs = i
      if (!fs) { print "NO_TEST_WRITER"; exit }
      ds = fs
      while (ds > 1 && (line[ds - 1] ~ /^\/\/\// || line[ds - 1] ~ /^#\[/)) ds--
      for (i = fs; i <= NR; i++) if (line[i] ~ /^}/) { fe = i; break }
      for (i = 2; i <= NR; i++)
        if (line[i] ~ /^mod tests \{/ && line[i - 1] ~ /^#\[cfg\(test\)\]/) { ts = i - 1; break }
      if (!ts) { print "NO_TEST_MODULE"; exit }
      te = 0
      for (i = ts + 1; i <= NR; i++) if (line[i] ~ /^}/) { te = i; break }
      if (!te) { print "NO_TEST_END"; exit }
      inside = 0; in_use = 0
      for (i = 1; i <= NR; i++) {
        if (line[i] ~ /^use /) in_use = 1
        u = in_use
        if (in_use && line[i] ~ /;[[:space:]]*$/) in_use = 0
        if (line[i] !~ /CONFORMING_DRAW_COMMITMENT/) continue
        if (i >= fs && i <= fe) inside++
        if (u || (i >= ds && i <= fe) || (i >= ts && i <= te)) continue
        print i ": " line[i]
      }
      if (!inside) print "NOT_IN_TEST_WRITER"
    }' "$1"
}

# The bound, proved on fixtures before the real file is judged. Each
# fixture has the test writer and a `fn uses` inside the test module; one
# names the value from a production helper before that module and one
# after it. The files are made here, not in a command substitution: a
# substitution is a subshell and would drop them from the cleanup list.
write_bound_fixture() {
  local file="$1" where="$2"
  if [[ "$where" == before ]]; then
    cat >"$file" <<'EOF'
pub unsafe extern "C" fn shekyl_test_coinbase_extra() {
    let _ = CONFORMING_DRAW_COMMITMENT;
}

fn production_helper() { let _ = CONFORMING_DRAW_COMMITMENT; }

#[cfg(test)]
mod tests {
    fn uses() { let _ = CONFORMING_DRAW_COMMITMENT; }
}
EOF
  else
    cat >"$file" <<'EOF'
pub unsafe extern "C" fn shekyl_test_coinbase_extra() {
    let _ = CONFORMING_DRAW_COMMITMENT;
}

#[cfg(test)]
mod tests {
    fn uses() { let _ = CONFORMING_DRAW_COMMITMENT; }
}

fn production_helper() { let _ = CONFORMING_DRAW_COMMITMENT; }
EOF
  fi
}

# A decoy must be reported, and nothing the bound keeps (the in-module
# use, or a missing subject) may be.
expect_decoy() {
  local label="$1" out="$2"
  if [[ "$out" != *production_helper* ]]; then
    echo "FAIL: ${label} did not report the production helper:" >&2
    echo "$out" >&2
    FAIL=1
  fi
  if [[ "$out" == *'fn uses'* || "$out" == *NO_TEST_* || "$out" == *NOT_IN_TEST_WRITER* ]]; then
    echo "FAIL: ${label} reported a line the test-module bound must keep:" >&2
    echo "$out" >&2
    FAIL=1
  fi
}

BEFORE_FIXTURE="$(mktemp)"
AFTER_FIXTURE="$(mktemp)"
cleanup_fixtures() {
  rm -f "$BEFORE_FIXTURE" "$AFTER_FIXTURE"
}
trap cleanup_fixtures EXIT
write_bound_fixture "$BEFORE_FIXTURE" before
write_bound_fixture "$AFTER_FIXTURE" after

expect_decoy "a helper before the test module" "$(commitment_outside "$BEFORE_FIXTURE")"
expect_decoy "a helper after the test module" "$(commitment_outside "$AFTER_FIXTURE")"

ffi_hits="$(scan -l 'CONFORMING_DRAW_COMMITMENT' "${TEST_GLOBS[@]}" "$FFI_DIR")"
if [[ -n "$ffi_hits" && "$ffi_hits" != "$FFI_EXTRA" ]]; then
  echo "FAIL: shekyl-ffi names CONFORMING_DRAW_COMMITMENT outside ${FFI_EXTRA}:" >&2
  echo "$ffi_hits" >&2
  FAIL=1
fi
# Within the module: the use list, the test writer, the tests through the
# module's closing brace. Anything else, the production writer included,
# is red. The function and the test module must be found (rule 47), and
# the value must still be in the function, or the subject moved.
outside="$(commitment_outside "$FFI_EXTRA")"
if [[ -n "$outside" ]]; then
  echo "FAIL: ${FFI_EXTRA} names CONFORMING_DRAW_COMMITMENT outside the test writer and its tests:" >&2
  echo "$outside" >&2
  if [[ "$outside" == *NO_TEST_* || "$outside" == *NOT_IN_TEST_WRITER* ]]; then
    echo "  The test writer or its tests moved; update this gate." >&2
  fi
  FAIL=1
fi
for needle in 'fn shekyl_test_coinbase_extra' 'commit_and_discard\(\)\.ok\(\)'; do
  found="$(scan -c "$needle" "$FFI_EXTRA")"
  if [[ -z "$found" ]]; then
    echo "FAIL: ${FFI_EXTRA} no longer names ${needle} — the coinbase writers moved; update this gate" >&2
    FAIL=1
  fi
done
cpp_callers="$(scan -n 'shekyl_test_coinbase_extra\(' src --glob '!src/shekyl/shekyl_ffi.h')"
if [[ -n "$cpp_callers" ]]; then
  echo "FAIL: production C++ calls the test coinbase writer, whose draw commitment anyone can guess:" >&2
  echo "$cpp_callers" >&2
  FAIL=1
fi

if (( FAIL )); then
  exit 1
fi
echo "OK: the node's template takes its coinbase secret and draw commitment from the OS"
