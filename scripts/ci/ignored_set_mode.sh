# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Sourced by the three nightly ignored-set scripts (ignored_set_chain_ingest.sh,
# ignored_set_chain_store.sh, ignored_set_economics_sim.sh). Each script judges
# its crate's `--list --ignored` against the set it names, then runs the set.
#
# With `--check`, a script judges the listing and stops: the per-PR Rust job
# (rust-audit-test.yml) runs all three that way, so a PR that adds, renames or
# un-ignores a test fails in its own CI instead of the next night's (alpha.11
# finding 12; issue #1215 was main's chain-ingest leg stopped by an unlisted
# `#[ignore]` that dev had already listed).
#
# The check lists the debug build, which the job's workspace tests have
# already compiled; the nightly run lists the release build. The two lists
# are the same only while no test attribute in the crate is gated on the
# profile, so the check refuses such an attribute by name instead of
# assuming its absence.
#
# Sets: `check` (0 or 1) and `profile` (an array: `--release`, or empty).

ignored_set_mode() {
  check=0
  profile=(--release)
  case "$#:${1:-}" in
    0:) ;;
    1:--check)
      check=1
      profile=()
      ;;
    *)
      echo "usage: $0 [--check]" >&2
      exit 2
      ;;
  esac
}

# `$1`: the crate's directory under rust/. Run from rust/.
refuse_profile_gated_tests() {
  local gated status=0
  gated=$(grep -rEn '#!?\[cfg(_attr)?\([^]]*debug_assertions' "$1/src") || status=$?
  if [ "$status" -eq 0 ]; then
    echo "::error::$1 gates an attribute on the build profile, so its debug and release ignored sets can differ and --check cannot stand in for the nightly listing:"
    printf '%s\n' "$gated"
    exit 1
  fi
  if [ "$status" -ne 1 ]; then
    echo "::error::grep over $1/src failed (exit $status)"
    exit 1
  fi
}
