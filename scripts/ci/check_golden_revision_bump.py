#!/usr/bin/env python3
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# SPDX-License-Identifier: BSD-3-Clause
"""Golden PNGs may not change without a RENDER_REVISION bump.

The shard-visual goldens are the raster oracle: `tests/ruling_b.rs` compares
every render against them. `RENDER_REVISION` is what tells a consumer (the GUI
wallet's `cache_digest`) that a cached image derived under an older pixel
derivation must be discarded.

Why this gate exists, and what the in-test assertion does NOT do. The KAT
asserts that the artifact's recorded `render_revision` equals the crate's
exported constant. That binds ONE direction only: goldens generated under an
older revision, left behind when the constant is bumped, fail. It cannot catch
the opposite and more likely mistake -- changing the pixel derivation and
regenerating the goldens WITHOUT bumping -- because the generator writes the
same constant the test reads, so both sides move together and every check
agrees. A binding replaces a check only per direction; this gate supplies the
missing one, and it needs the diff to do it, which a unit test cannot see.

The subject is deliberately the golden PNG bytes rather than the source files
that produce them. Pixel bytes change if and only if the derivation changed, so
this fires on the thing that matters and stays quiet for comment edits and
refactors -- a gate that reddens on harmless changes is one people learn to
ignore. Newly ADDED goldens (a fixture gaining coverage) need no bump; only
MODIFIED ones do.
"""

import os
import re
import subprocess
import sys

GOLDEN_GLOB_PREFIX = "rust/shekyl-shard-visual/tests/goldens/"
LIB_RS = "rust/shekyl-shard-visual/src/lib.rs"
REVISION_RE = re.compile(r"pub const RENDER_REVISION:\s*u32\s*=\s*(\d+)\s*;")


def run(*args: str) -> str:
    return subprocess.run(
        args, capture_output=True, text=True, check=False
    ).stdout.strip()


def revision_at(ref: str) -> str | None:
    """RENDER_REVISION's value at `ref`, or None if it cannot be read."""
    blob = run("git", "show", f"{ref}:{LIB_RS}")
    if not blob:
        return None
    m = REVISION_RE.search(blob)
    return m.group(1) if m else None


def main() -> int:
    base_ref = os.environ.get("GITHUB_BASE_REF") or "dev"
    base = None
    for candidate in (f"origin/{base_ref}", base_ref):
        merge_base = run("git", "merge-base", candidate, "HEAD")
        if merge_base:
            base = merge_base
            break
    if not base:
        print(
            f"golden revision gate: cannot resolve a merge base against "
            f"{base_ref!r}; the gate cannot run and does not pass by default",
            file=sys.stderr,
        )
        return 2

    # Rule 47: assert the subject exists. If the goldens vanished or moved, a
    # diff over their old path would report nothing and this gate would go
    # green while the oracle it protects no longer exists.
    tracked = run("git", "ls-tree", "-r", "--name-only", "HEAD", GOLDEN_GLOB_PREFIX)
    if not any(line.endswith(".png") for line in tracked.splitlines()):
        print(
            f"golden revision gate: no golden PNGs under {GOLDEN_GLOB_PREFIX} at "
            f"HEAD -- the raster oracle is missing, which is a failure, not a pass",
            file=sys.stderr,
        )
        return 2

    changed = run(
        "git", "diff", "--name-status", base, "HEAD", "--", GOLDEN_GLOB_PREFIX
    )
    modified = [
        line.split("\t", 1)[1]
        for line in changed.splitlines()
        if line.startswith("M") and line.rstrip().endswith(".png")
    ]
    if not modified:
        print("golden revision gate: no modified golden PNGs in this change")
        return 0

    head_rev = revision_at("HEAD")
    base_rev = revision_at(base)
    if head_rev is None or base_rev is None:
        print(
            f"golden revision gate: could not read RENDER_REVISION from {LIB_RS} "
            f"(base={base_rev!r} head={head_rev!r}); the constant may have been "
            f"renamed or moved, and this gate must be updated with it",
            file=sys.stderr,
        )
        return 2

    if head_rev == base_rev:
        listing = "\n".join(f"  {p}" for p in modified)
        print(
            f"golden revision gate: {len(modified)} golden PNG(s) changed while "
            f"RENDER_REVISION stayed at {head_rev}:\n{listing}\n\n"
            f"Golden pixels change only when the derivation changes, and a "
            f"consumer caching by RENDER_REVISION (the GUI wallet's "
            f"cache_digest) will keep serving images from the old derivation. "
            f"Bump RENDER_REVISION in {LIB_RS} and regenerate, or restore the "
            f"goldens if the change was unintended.",
            file=sys.stderr,
        )
        return 1

    print(
        f"golden revision gate: {len(modified)} golden PNG(s) changed and "
        f"RENDER_REVISION moved {base_rev} -> {head_rev}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
