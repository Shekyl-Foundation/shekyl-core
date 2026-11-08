# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Sourced by the four nightly ignored-set scripts. Each script judges its
# crate's `--list --ignored` against the set it names, then runs that set.
#
# ignored_set_mode sets two variables:
#   ignored_set_check    0, or 1 when the caller was invoked with --check.
#   ignored_set_profile  (--release) for the nightly listing, empty for --check.
#
# --check is the per-PR judgement (rust-audit-test.yml). It lists the debug
# build that job has already compiled. ignored_set_stop_after_judgement then
# exits 0, and the release run below that call stays the nightly path. A test
# attribute cfg-gated on debug_assertions can put a name in one listing and
# not the other; the nightly lane is the release judgement.

ignored_set_mode() {
  ignored_set_check=0
  ignored_set_profile=(--release)
  case "$#:${1:-}" in
    0:) ;;
    1:--check)
      ignored_set_check=1
      ignored_set_profile=()
      ;;
    *)
      echo "usage: $0 [--check]" >&2
      exit 2
      ;;
  esac
}

# Exit 0 when this invocation is --check. The cargo run below the call is
# the nightly lane and always passes --release.
ignored_set_stop_after_judgement() {
  if [ "$ignored_set_check" -eq 1 ]; then
    exit 0
  fi
}
