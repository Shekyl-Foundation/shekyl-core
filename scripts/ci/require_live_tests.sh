#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Assert that each named live test ran and passed, in the output of one
# `cargo test -- --test-threads=1` run. Used by tor-pin-verify after
# run_live_tor_tests.sh, which writes that output and whose exit status is
# the run's own verdict; this script says which tests the verdict covered.
#
# Usage: require_live_tests.sh <cargo-test-output> <test name>...
#
# A name passes when a line ends with ` <name> ... ok` (or is exactly
# `<name> ... ok`): libtest prints one such line per test when it runs them
# one at a time. A count of passed tests cannot stand in for this, because a
# required test that stopped compiling on a platform leaves the count
# unchanged once another test is added.
#
# Refused before anything is matched: no names at all (a list that went
# empty would otherwise pass, rule 47), and a name outside Rust's path
# alphabet (letters, digits, `_`, `::`), which is the only alphabet a test
# name has and keeps every name literal in the pattern below.
#
# Exit status: 0 = every name passed; 1 = one or more did not (each listed);
# 2 = usage error.

set -u -o pipefail

out="${1:?usage: require_live_tests.sh <cargo-test-output> <test name>...}"
shift
if [ "$#" -eq 0 ]; then
  echo "require_live_tests: no test names given; a required set cannot be empty" >&2
  exit 2
fi
if [ ! -f "$out" ]; then
  echo "require_live_tests: $out does not exist" >&2
  exit 2
fi

missing=0
for name in "$@"; do
  if [[ ! "$name" =~ ^[A-Za-z0-9_]+(::[A-Za-z0-9_]+)*$ ]]; then
    echo "require_live_tests: '$name' is not a test path" >&2
    exit 2
  fi
  if grep -qE "(^|[[:space:]])${name} \.\.\. ok\$" "$out"; then
    echo "passed: $name"
  else
    echo "NOT PASSED: $name" >&2
    missing=1
  fi
done
exit "$missing"
