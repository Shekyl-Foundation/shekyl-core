#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Reproduce the a04c coupling halves on the five-seed pin vector.

`a04c988b1` changes `reward.rs` and the retention `r_market_count`.
Each half is that commit's parent plus one of those files. The reward
half carries the knee step. The retention half is the control: the sim
does not call `r_market_count`, and that half reproduces the parent.
The workflow and the C++ getters in the same commit are outside the
sim build.

This is the reproducer of a finished measurement. The recorded rows
live in `scripts/sim/eup3-pin-walk/distributions.jsonl`.

`write_seeds_here` restores `scenarios.rs` between seeds, so the next
seed starts from the applied half rather than a leftover seed edit.
A half that patched `scenarios.rs` would lose that patch on the second
seed, and is refused.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import eup3_pin_walk as walk

A04C = "a04c988b1cdc24bd6c4d5d2bf6a1297e0e31c155"
A04C_PARENT = "6033beea0908da3ba3624f2fd9c179653a91791d"
A04C_HALVES = (
    ("a04c-reward", "rust/shekyl-staking-sim/src/reward.rs"),
    ("a04c-retention", "rust/shekyl-archival-retention/src/consensus_state.rs"),
)

# Restored between seeds. A half path or diff that names it is refused.
SCENARIOS_RS = "rust/shekyl-staking-sim/src/scenarios.rs"


def refuse_scenarios_patch(path: str, diff: str) -> None:
    """The per-seed restore drops a patch to `scenarios.rs`."""
    if path == SCENARIOS_RS or path.endswith("/scenarios.rs"):
        raise SystemExit(
            f"{path} is restored between seeds, so the next seed would drop the patch"
        )
    for line in diff.splitlines():
        if line.startswith(("diff --git ", "--- ", "+++ ")) and SCENARIOS_RS in line:
            raise SystemExit(
                f"{path} diff touches {SCENARIOS_RS}, which is restored between seeds"
            )


def write_seeds_here(label: str, dest: Path) -> None:
    """Five seeds at the worktree as it stands, including an applied patch."""
    head = walk.rev_parse(walk.WALK, "HEAD")
    have = {(row.get("label"), row.get("seed")) for row in walk.load_jsonl(dest)}
    for seed in walk.NOISE_SEEDS:
        if (label, seed) in have:
            print(f"seeds skip {label} {seed}", flush=True)
            continue
        print(f"seeds {label} {head[:12]} {seed}", flush=True)
        if seed != walk.PIN_SEED:
            walk.set_baseline_seed(seed)
        binary = walk.build()
        row = {
            "commit": head,
            "subject": walk.subject(walk.WALK, "HEAD"),
            "channel": walk.channel_at(walk.WALK),
            "channel_override": None,
            "seed": seed,
            "label": label,
            "vector": walk.run_binary(binary),
        }
        walk.append_jsonl(dest, row)
        have.add((label, seed))
        # The next seed starts from the patched tree, not a leftover seed.
        walk.git(["checkout", "--", SCENARIOS_RS], walk.WALK)


def half_is_recorded(dest: Path, label: str) -> bool:
    have = {(row.get("label"), row.get("seed")) for row in walk.load_jsonl(dest)}
    return all((label, seed) in have for seed in walk.NOISE_SEEDS)


def cmd_halves() -> None:
    """Apply each a04c half on its parent and record the five seeds."""
    dest = walk.OUT_DIR / "distributions.jsonl"
    for label, path in A04C_HALVES:
        if half_is_recorded(dest, label):
            print(f"half skip {label}", flush=True)
            continue
        print(f"half {label} from {A04C_PARENT[:12]} + {path}", flush=True)
        walk.checkout(A04C_PARENT)
        diff = walk.git(["diff", A04C_PARENT, A04C, "--", path], walk.REPO)
        if not diff.strip():
            raise SystemExit(f"no diff for {path}")
        refuse_scenarios_patch(path, diff)
        proc = subprocess.run(
            ["git", "apply"],
            cwd=walk.WALK,
            input=diff,
            text=True,
            capture_output=True,
        )
        if proc.returncode != 0:
            raise SystemExit(f"apply failed for {path}:\n{proc.stderr}")
        write_seeds_here(label, dest)
        walk.checkout(A04C_PARENT)
