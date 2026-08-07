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
#
# WHAT THIS DOES NOT COVER, stated so "all gates green" is not read as more
# than it is: `cargo audit`, the persisted-schema snapshot check, and every
# C++ / depends job run in CI. It covers the three Rust gates that reject the
# most pushes, at CI's exact invocations -- `--locked` included, because a
# lockfile that does not resolve the branch's manifests is a red CI run that
# no amount of local fmt/clippy/test can see.

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

echo "== clippy (CI-exact: +1.94.0, workspace, all targets, --locked) =="
(cd rust && cargo +1.94.0 clippy --locked --workspace --all-targets -- -D warnings)

if [[ ${#TEST_ARGS[@]} -gt 0 ]]; then
	echo "== test ${TEST_ARGS[*]} (--locked) =="
	(cd rust && cargo test --locked "${TEST_ARGS[@]}")
fi

echo "== doc links =="
# The checker exits 1 for dead links, 2 for a malformed allowlist, and
# whatever python exits with if it crashes or has been moved. ALL of those
# must stop the push; exactly one class may be waived -- dead links into an
# uninitialised submodule, which are a local artifact CI does not have.
#
# So: branch on the EXIT STATUS first, filter the output second. The inverse
# (grep for a message, ignore the status) makes every failure that does not
# print that message read as green, which is this script's own failure mode
# one level in.
DOC_LINK_OUT="$(mktemp)"
trap 'rm -f "${DOC_LINK_OUT}"' EXIT
DOC_LINK_RC=0
python3 scripts/ci/check_doc_links.py >"${DOC_LINK_OUT}" 2>&1 || DOC_LINK_RC=$?
case "${DOC_LINK_RC}" in
0) ;;
1)
	if ! grep -q 'dead link' "${DOC_LINK_OUT}"; then
		echo "doc-link gate FAILED: exit 1 with no 'dead link' rows -- the checker's contract moved" >&2
		cat "${DOC_LINK_OUT}" >&2
		exit 1
	fi
	if grep 'dead link' "${DOC_LINK_OUT}" | grep -v 'external/randomx-v2'; then
		echo "doc-link gate FAILED (above are not submodule artifacts)" >&2
		exit 1
	fi
	echo "   dead links are all uninitialised-submodule artifacts -- waived"
	;;
*)
	echo "doc-link gate FAILED: the checker itself exited ${DOC_LINK_RC}" >&2
	cat "${DOC_LINK_OUT}" >&2
	exit 1
	;;
esac

echo "== all gates green -- pushing $BRANCH to $REMOTE =="
git push "$REMOTE" "$BRANCH"
