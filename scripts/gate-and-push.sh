#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Run the CI-exact gates, and push ONLY if they all pass.
#
# WHY THIS EXISTS
#
# Twice in one session a push went out with `cargo clippy` red, both times from
# the same shape: the gate and the push were issued in one command list
# separated by `;` (or the gate's output was piped, swallowing its exit code),
# so the push never depended on the gate's result. The gate ran, printed, and
# decided nothing.
#
# The project's own answer to rot that regenerates is a jig, not more care --
# the same move as `f` refusing a parameter for local timing
# (DAEMON_RELAY_PRIVACY.md §77.4) and §15.6 refusing block time a term. This
# removes the ABILITY to push past a red gate rather than requiring anyone to
# remember not to: `set -e` plus `&&` means the push line is unreachable unless
# every gate above it exited 0.
#
# USAGE
#
#   scripts/gate-and-push.sh <remote> <branch> [-p CRATE]...
#
#   scripts/gate-and-push.sh origin dev
#   scripts/gate-and-push.sh origin feat/my-branch -p shekyl-relay-privacy -p shekyl-relay
#
# Crates given with -p are tested. None given means no test step -- fmt,
# clippy and the doc-link gate still run. `cargo test --workspace` is
# deliberately never used: it pulls randomx-differential, which is not part of
# the Rust gate.

set -euo pipefail

if [[ $# -lt 2 ]]; then
	echo "usage: $0 <remote> <branch> [-p CRATE]..." >&2
	exit 2
fi

REMOTE="$1"
BRANCH="$2"
shift 2

TEST_ARGS=()
while [[ $# -gt 0 ]]; do
	case "$1" in
	-p)
		[[ $# -ge 2 ]] || {
			echo "-p needs a crate name" >&2
			exit 2
		}
		TEST_ARGS+=(-p "$2")
		shift 2
		;;
	*)
		echo "unknown argument: $1" >&2
		exit 2
		;;
	esac
done

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

echo "== fmt =="
(cd rust && cargo fmt --all -- --check)

echo "== clippy (CI-exact: +1.94.0, workspace, all targets) =="
(cd rust && cargo +1.94.0 clippy --workspace --all-targets -- -D warnings)

if [[ ${#TEST_ARGS[@]} -gt 0 ]]; then
	echo "== test ${TEST_ARGS[*]} =="
	(cd rust && cargo test "${TEST_ARGS[@]}")
fi

echo "== doc links =="
# Uninitialised submodules produce dead links that are a local artifact, not a
# regression; CI initialises them. Fail only on links outside that set.
if python3 scripts/ci/check_doc_links.py 2>&1 | grep 'dead link' | grep -v 'external/randomx-v2'; then
	echo "doc-link gate FAILED (above are not submodule artifacts)" >&2
	exit 1
fi

echo "== all gates green -- pushing $BRANCH to $REMOTE =="
git push "$REMOTE" "$BRANCH"
