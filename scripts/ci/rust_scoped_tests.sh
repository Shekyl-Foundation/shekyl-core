#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The Rust job's scoped tests, in one place: rust-audit-test.yml's
# "cargo nextest" and "doctests" steps run it, and so does the FreeBSD
# nightly (freebsd-nightly.yml), so both run the same selection.
#
#   rust_scoped_tests.sh install-nextest
#                                  the pinned cargo-nextest (idempotent on a
#                                  cache hit: the binary is already there)
#   rust_scoped_tests.sh nextest   every test of the scope's packages and of
#                                  every package that depends on them
#   rust_scoped_tests.sh doctests  the doctests of the scope's packages that
#                                  have a library target
#
# nextest is pinned: the runner decides which tests run and what counts as a
# pass, so a new version is a change to the gate and comes in its own
# commit. 0.9.138 needs Rust 1.91; the workspace pins 1.94.0.
#
# Run from `rust/` (install-nextest from anywhere). RUST_TESTS is
# change_scope.py's `rust_tests` (`all` or
# package names; `none` never reaches here: the steps are skipped).
# RUST_DOC_PKGS is its `rust_doc_pkgs`, the `-p` arguments for doctests.
#
# `shekyl-randomx-differential` is excluded: it links the C reference's
# `librandomx.a`, which the Rust job does not build (its own workflow,
# randomx-v2-differential.yml, does). A scoped expression that selects no
# test passes: the selection was the decision, and a package name that no
# longer exists fails the expression instead.
set -euo pipefail

NEXTEST_VERSION=0.9.138

if [ "${1:-}" = install-nextest ]; then
  cargo install cargo-nextest --locked --version "$NEXTEST_VERSION"
  exit 0
fi

: "${RUST_TESTS:?RUST_TESTS is the rust_tests output of change_scope.py}"

case "${1:-}" in
  nextest)
    # The forged shard-fill chain the store's prune and slash tests start
    # from (CHAIN_FORGE.md CF-4a): an OCI artifact on GHCR, public, pulled
    # by its pinned digest and checked layer by layer before any test reads
    # it. A pull needs no credential, so a fork's pull request fetches it
    # too. Fetched whatever the scope: about 13 MB and a few seconds, and a
    # failed fetch stops the step here, by name, before a test reports it
    # as a missing file.
    python3 ../scripts/ci/fetch_test_chain.py shard-fill
    if [ "$RUST_TESTS" = all ]; then
      echo "scope: every workspace test"
      cargo nextest run --locked --profile ci --workspace --exclude shekyl-randomx-differential
    else
      expr=""
      for pkg in $RUST_TESTS; do expr="${expr:+$expr + }rdeps($pkg)"; done
      echo "scope: $expr"
      cargo nextest run --locked --profile ci --workspace --exclude shekyl-randomx-differential \
        --no-tests=pass -E "$expr"
    fi
    ;;
  doctests)
    if [ "$RUST_TESTS" = all ]; then
      cargo test --locked --doc --workspace --exclude shekyl-randomx-differential
    elif [ -z "${RUST_DOC_PKGS:-}" ]; then
      echo "scope: no package in scope has a library target; no doctests"
    else
      echo "scope: cargo test --doc $RUST_DOC_PKGS"
      # shellcheck disable=SC2086 # RUST_DOC_PKGS is the `-p a -p b` list
      cargo test --locked --doc $RUST_DOC_PKGS
    fi
    ;;
  *)
    echo "usage: rust_scoped_tests.sh install-nextest|nextest|doctests" >&2
    exit 2
    ;;
esac
