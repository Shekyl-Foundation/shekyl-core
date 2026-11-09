#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Attribute the L11/L13 pin drift from the June records to c2dcfe601.

The population sim is deterministic for a seed. This walks every commit on
the way to dev that touches rust/shekyl-staking-sim, in parent-before-child
order, and runs one fixed scenario vector at the pin seed. A numeric step
is then re-walked through the path-dependency commits in that interval
(shekyl-archival-retention, shekyl-economics, shekyl-units, shekyl-standoff),
so a jump is not blamed on a sim commit that only inherited a dependency
change.

The noise band is five seeds at the L11 record, the L13 record, and
c2dcfe601. A step inside a field's spread is not a step.

Steps compare cDeepU with cDeepU. The published L11/L13 "deep_und"
figures are that windowed mean. The final-epoch snapshot stays in the
raw row under deep_und and is not a step field.

After the sim commits, three more passes: dependency commits between
the last sim commit and c2dcfe601, if that interval moves the vector;
each first-parent merge that touches the sim, against both parents;
and, where the pinned toolchain changes, the same commit built with
both toolchains.

Paths are arguments. This file has no default checkout, worktree, or
build directory. Measurement — checkout, build, invoke, the noise band —
is `eup3_pin_walk_measure.Walk`, constructed here once the arguments
exist.

The walk checkout is a separate worktree. This script never checks out
inside the branch that holds its own output.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from eup3_pin_walk_measure import (
    END,
    NOISE_SEEDS,
    PIN_SEED,
    SCENARIOS_RS,
    START_L11,
    START_L13,
    VECTOR,
    Walk,
    append_jsonl,
    done_keys,
    load_jsonl,
    moved,
)

# The a04c coupling halves on the five-seed pin vector.
#
# `a04c988b1` changes `reward.rs` and the retention `r_market_count`.
# Each half is that commit's parent plus one of those files. The reward
# half carries the knee step. The retention half is the control: the sim
# does not call `r_market_count`, and that half reproduces the parent.
# The workflow and the C++ getters in the same commit are outside the
# sim build. The recorded rows live in `distributions.jsonl`.
#
# `write_seeds_here` restores `scenarios.rs` between seeds, so the next
# seed starts from the applied half rather than a leftover seed edit.
# A half that patched `scenarios.rs` would lose that patch on the second
# seed, and is refused.

A04C = "a04c988b1cdc24bd6c4d5d2bf6a1297e0e31c155"
A04C_PARENT = "6033beea0908da3ba3624f2fd9c179653a91791d"
A04C_HALVES = (
    ("a04c-reward", "rust/shekyl-staking-sim/src/reward.rs"),
    ("a04c-retention", "rust/shekyl-archival-retention/src/consensus_state.rs"),
)
DIST_COMMITS = (
    ("post-repair", "4071ec03260374b76c83efb32bd0fce43f0ad1ef"),
    ("post-a04c", "a04c988b1cdc24bd6c4d5d2bf6a1297e0e31c155"),
)

COMMANDS = (
    "noise",
    "walk",
    "gaps",
    "tail",
    "merges",
    "toolchains",
    "seeds",
    "halves",
    "table",
)


def cmd_noise(walk: Walk) -> None:
    out = walk.out_dir / "noise.jsonl"
    have = done_keys(out)
    points = [
        ("l11-record", START_L11),
        ("l13-record", START_L13),
        ("end", END),
    ]
    for label, commit in points:
        full = walk.rev_parse(commit, walk.repo)
        for seed in NOISE_SEEDS:
            if (full, seed) in have:
                print(f"noise skip {label} {seed}", flush=True)
                continue
            print(f"noise {label} {commit[:12]} {seed}", flush=True)
            row = walk.measure(full, seed)
            row["label"] = label
            append_jsonl(out, row)
            have.add((row["commit"], seed))


def write_seeds(walk: Walk, commit: str, label: str, dest: Path) -> None:
    """Five seeds at one committed tree.

    `measure` checks out `commit` on every seed, which drops an uncommitted
    patch. A patched tree is measured by `write_seeds_here`.
    """
    full = walk.rev_parse(commit, walk.repo)
    have = {
        (row["commit"], row.get("seed"), row.get("label"))
        for row in load_jsonl(dest)
    }
    for seed in NOISE_SEEDS:
        if (full, seed, label) in have:
            print(f"seeds skip {label} {seed}", flush=True)
            continue
        print(f"seeds {label} {full[:12]} {seed}", flush=True)
        row = walk.measure(full, seed)
        row["label"] = label
        append_jsonl(dest, row)
        have.add((row["commit"], seed, label))


def cmd_seeds(walk: Walk) -> None:
    """Five-seed distributions at the curve repair and at a04c."""
    dest = walk.out_dir / "distributions.jsonl"
    for label, commit in DIST_COMMITS:
        write_seeds(walk, commit, label, dest)


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


def write_seeds_here(walk: Walk, label: str, dest: Path) -> None:
    """Five seeds at the worktree as it stands, including an applied patch."""
    head = walk.rev_parse("HEAD", walk.walk)
    have = {(row.get("label"), row.get("seed")) for row in load_jsonl(dest)}
    for seed in NOISE_SEEDS:
        if (label, seed) in have:
            print(f"seeds skip {label} {seed}", flush=True)
            continue
        print(f"seeds {label} {head[:12]} {seed}", flush=True)
        row = walk.measure_standing(seed)
        row["label"] = label
        append_jsonl(dest, row)
        have.add((label, seed))
        # The next seed starts from the patched tree, not a leftover seed.
        walk.git(["checkout", "--", SCENARIOS_RS], walk.walk)


def half_is_recorded(dest: Path, label: str) -> bool:
    have = {(row.get("label"), row.get("seed")) for row in load_jsonl(dest)}
    return all((label, seed) in have for seed in NOISE_SEEDS)


def cmd_halves(walk: Walk) -> None:
    """Apply each a04c half on its parent and record the five seeds."""
    dest = walk.out_dir / "distributions.jsonl"
    for label, path in A04C_HALVES:
        if half_is_recorded(dest, label):
            print(f"half skip {label}", flush=True)
            continue
        print(f"half {label} from {A04C_PARENT[:12]} + {path}", flush=True)
        walk.checkout(A04C_PARENT)
        diff = walk.git(["diff", A04C_PARENT, A04C, "--", path], walk.repo)
        if not diff.strip():
            raise SystemExit(f"no diff for {path}")
        refuse_scenarios_patch(path, diff)
        proc = subprocess.run(
            ["git", "apply"],
            cwd=walk.walk,
            input=diff,
            text=True,
            capture_output=True,
        )
        if proc.returncode != 0:
            raise SystemExit(f"apply failed for {path}:\n{proc.stderr}")
        write_seeds_here(walk, label, dest)
        walk.checkout(A04C_PARENT)


def cmd_walk(walk: Walk) -> None:
    out = walk.out_dir / "sim-commits.jsonl"
    have = {row["commit"] for row in load_jsonl(out)}
    start = walk.rev_parse(START_L11, walk.repo)
    if start not in have:
        print(f"walk start {start[:12]}", flush=True)
        append_jsonl(out, walk.measure(start))
        have.add(start)
    commits = walk.sim_commits()
    print(f"sim commits {len(commits)}", flush=True)
    for index, commit in enumerate(commits, 1):
        full = walk.rev_parse(commit, walk.repo)
        if full in have:
            continue
        print(
            f"walk {index}/{len(commits)} {full[:12]} {walk.subject(full, walk.repo)}",
            flush=True,
        )
        append_jsonl(out, walk.measure(full))
        have.add(full)


def cmd_gaps(walk: Walk) -> None:
    """Re-measure path-dep commits inside intervals where the sim-commit
    vector moved. Records them in dep-commits.jsonl."""
    band = walk.spreads()
    rows = load_jsonl(walk.out_dir / "sim-commits.jsonl")
    by_commit = {row["commit"]: row for row in rows}
    out = walk.out_dir / "dep-commits.jsonl"
    have = {row["commit"] for row in load_jsonl(out)}
    ordered = [walk.rev_parse(START_L11, walk.repo)]
    ordered.extend(walk.sim_commits())
    ordered = [walk.rev_parse(rev, walk.repo) for rev in ordered]
    for prev, commit in zip(ordered, ordered[1:]):
        before = by_commit[prev]["vector"]
        after = by_commit[commit]["vector"]
        if not walk.any_moved(before, after, band):
            continue
        interior = walk.dep_commits_between(prev, commit)
        print(
            f"gap {prev[:12]}..{commit[:12]} dep commits {len(interior)}",
            flush=True,
        )
        for rev in interior:
            full = walk.rev_parse(rev, walk.repo)
            if full in have or full in by_commit:
                continue
            print(f"  dep {full[:12]} {walk.subject(full, walk.repo)}", flush=True)
            append_jsonl(out, walk.measure(full))
            have.add(full)


def cmd_tail(walk: Walk) -> None:
    """Dependency commits after the last sim commit, up to the end pin.

    The crate can stop changing while the crates it links keep changing.
    Compare the last sim commit with the end pin; walk that interval only
    when the vector moved.
    """
    commits = [walk.rev_parse(rev, walk.repo) for rev in walk.sim_commits()]
    have = {row["commit"] for row in load_jsonl(walk.out_dir / "sim-commits.jsonl")}
    if not commits or commits[-1] not in have:
        raise SystemExit("sim walk is not finished; the tail waits for it")
    last = commits[-1]
    end = walk.rev_parse(END, walk.repo)
    dest = walk.out_dir / "tail.jsonl"
    end_row = walk.ensure_pin(end, dest)
    last_row = walk.cached_pin(last)
    if last_row is None:
        raise SystemExit(f"no pin-seed row for the last sim commit {last}")
    band = walk.spreads()
    if not walk.any_moved(last_row["vector"], end_row["vector"], band):
        print(f"tail {last[:12]}..{end[:12]} did not move", flush=True)
        return
    interior = walk.dep_commits_between(last, end)
    print(f"tail {last[:12]}..{end[:12]} dep commits {len(interior)}", flush=True)
    have_dep = {row["commit"] for row in load_jsonl(dest)}
    for rev in interior:
        full = walk.rev_parse(rev, walk.repo)
        if walk.cached_pin(full) is not None or full in have_dep:
            continue
        print(f"  tail {full[:12]} {walk.subject(full, walk.repo)}", flush=True)
        append_jsonl(dest, walk.measure(full))
        have_dep.add(full)


def first_parent_merges(walk: Walk) -> list[str]:
    text = walk.git(
        [
            "log",
            "--first-parent",
            "--format=%H",
            f"{START_L11}..{END}",
            "--",
            "rust/shekyl-staking-sim",
        ],
        walk.repo,
    )
    merges = []
    for rev in text.splitlines():
        if not rev:
            continue
        parents = walk.git(["rev-parse", f"{rev}^@"], walk.repo).split()
        if len(parents) >= 2:
            merges.append(rev)
    return merges


def cmd_merges(walk: Walk) -> None:
    """Each first-parent merge that touches the sim, against both parents.

    Side-branch commits are measured alone. A step that appears only when
    two branches are combined is visible here and nowhere in that list.
    """
    dest = walk.out_dir / "merges.jsonl"
    have = {row["commit"] for row in load_jsonl(dest)}
    band = walk.spreads()
    report = []
    for rev in first_parent_merges(walk):
        parents = walk.git(["rev-parse", f"{rev}^@"], walk.repo).split()
        rows = {}
        for commit in [rev, *parents]:
            full = walk.rev_parse(commit, walk.repo)
            if full not in have and walk.cached_pin(full) is None:
                print(
                    f"merge measure {full[:12]} {walk.subject(full, walk.repo)}",
                    flush=True,
                )
                append_jsonl(dest, walk.measure(full))
                have.add(full)
            rows[full] = walk.cached_pin(full)
        merge = walk.rev_parse(rev, walk.repo)
        diffs = {}
        for parent in parents:
            full = walk.rev_parse(parent, walk.repo)
            changes = {}
            for name in VECTOR:
                change = moved(
                    rows[full]["vector"].get(name),
                    rows[merge]["vector"].get(name),
                    band.get(name, {}),
                )
                if change:
                    changes[name] = change
            if changes:
                diffs[full] = changes
        report.append(
            {
                "merge": merge,
                "subject": walk.subject(merge, walk.repo),
                "parents": [walk.rev_parse(parent, walk.repo) for parent in parents],
                "differs_from": diffs,
            }
        )
        print(
            f"merge {merge[:12]} differs from {len(diffs)} parent(s): "
            f"{walk.subject(merge, walk.repo)}",
            flush=True,
        )
    (walk.out_dir / "merges.json").write_text(json.dumps(report, indent=2) + "\n")


def channel_key(chan: str) -> str:
    """1.94 and 1.94.0 are one pin. The comparison is the minor version."""
    parts = chan.split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else chan


def measure_or_refuse(
    walk: Walk, commit: str, channel_override: str, dest: Path, have: set
) -> dict:
    key = (commit, channel_override)
    if key in have:
        return next(
            row
            for row in load_jsonl(dest)
            if row["commit"] == commit and row.get("channel_override") == channel_override
        )
    print(f"toolchain {commit[:12]} under {channel_override}", flush=True)
    try:
        row = walk.measure(commit, channel_override=channel_override)
    except SystemExit as err:
        row = {
            "commit": walk.rev_parse(commit, walk.repo),
            "subject": walk.subject(commit, walk.repo),
            "channel": channel_override,
            "channel_override": channel_override,
            "seed": PIN_SEED,
            "refused": str(err),
            "vector": {name: None for name in VECTOR},
        }
        print(f"toolchain refused {commit[:12]} under {channel_override}", flush=True)
    append_jsonl(dest, row)
    have.add(key)
    return row


def cmd_toolchains(walk: Walk) -> None:
    """Where the pinned toolchain changes, build under both compilers.

    powf, exp and ln come from the toolchain's maths library. The commit
    that raises rust-version cannot be built by the old compiler, so that
    direction is recorded as refused. The last commit that still builds
    on the old pin is built with the new compiler: that pair is the
    maths library alone.
    """
    sequence = [walk.rev_parse(START_L11, walk.repo)]
    sequence.extend(walk.rev_parse(rev, walk.repo) for rev in walk.sim_commits())
    end = walk.rev_parse(END, walk.repo)
    if sequence[-1] != end:
        sequence.append(end)
    dest = walk.out_dir / "toolchain-pairs.jsonl"
    have = {
        (row["commit"], row.get("channel_override"))
        for row in load_jsonl(dest)
        if row.get("channel_override")
    }
    band = walk.spreads()
    report = []
    prev_commit = sequence[0]
    prev_channel = walk.channel_of(prev_commit)
    for commit in sequence[1:]:
        chan = walk.channel_of(commit)
        if channel_key(chan) != channel_key(prev_channel):
            # New code on the old compiler. Often refused by rust-version.
            backward = measure_or_refuse(walk, commit, prev_channel, dest, have)
            # Old code on the new compiler. This is the one that can run.
            forward = measure_or_refuse(walk, prev_commit, chan, dest, have)
            native_old = walk.cached_pin(prev_commit)
            native_new = walk.cached_pin(commit)
            forward_changes = {}
            backward_changes = {}
            if native_old is not None and not forward.get("refused"):
                for name in VECTOR:
                    change = moved(
                        native_old["vector"].get(name),
                        forward["vector"].get(name),
                        band.get(name, {}),
                    )
                    if change:
                        forward_changes[name] = change
            if native_new is not None and not backward.get("refused"):
                for name in VECTOR:
                    change = moved(
                        backward["vector"].get(name),
                        native_new["vector"].get(name),
                        band.get(name, {}),
                    )
                    if change:
                        backward_changes[name] = change
            report.append(
                {
                    "commit": commit,
                    "previous": prev_commit,
                    "subject": walk.subject(commit, walk.repo),
                    "from_channel": prev_channel,
                    "to_channel": chan,
                    "old_code_on_new_compiler": {
                        "refused": forward.get("refused"),
                        "scenarios": forward_changes,
                    },
                    "new_code_on_old_compiler": {
                        "refused": backward.get("refused"),
                        "scenarios": backward_changes,
                    },
                }
            )
            print(
                f"toolchain {prev_channel} -> {chan} at {commit[:12]} "
                f"old-code scenarios {len(forward_changes)} "
                f"new-code refused {bool(backward.get('refused'))}",
                flush=True,
            )
        prev_commit = commit
        prev_channel = chan
    (walk.out_dir / "toolchain-steps.json").write_text(json.dumps(report, indent=2) + "\n")


def cmd_table(walk: Walk) -> None:
    band = walk.spreads()
    (walk.out_dir / "noise-spread.json").write_text(
        json.dumps(band, indent=2, sort_keys=True) + "\n"
    )
    measured: dict[str, dict] = {}
    # Merge parents stay in merges.json. Putting them in this chain
    # turns "the crate did not exist yet" into a population step.
    for name in (
        "sim-commits.jsonl",
        "dep-commits.jsonl",
        "tail.jsonl",
    ):
        for row in load_jsonl(walk.out_dir / name):
            if row.get("seed", PIN_SEED) != PIN_SEED:
                continue
            if row.get("channel_override"):
                continue
            if "vector" not in row:
                continue
            measured[row["commit"]] = row
    # One linearization: start, then every measured commit in topo order
    # restricted to measured hashes.
    wanted = set(measured)
    ordered_text = walk.git(
        ["rev-list", "--reverse", "--topo-order", f"{START_L11}..{END}"],
        walk.repo,
    )
    ordered = [walk.rev_parse(START_L11, walk.repo)]
    for rev in ordered_text.splitlines():
        if rev in wanted and rev not in ordered:
            ordered.append(rev)
    table = []
    previous = ordered[0]
    for commit in ordered[1:]:
        changes_by_scenario = {}
        for name in VECTOR:
            change = moved(
                measured[previous]["vector"].get(name),
                measured[commit]["vector"].get(name),
                band.get(name, {}),
            )
            if change:
                changes_by_scenario[name] = change
        if changes_by_scenario:
            table.append(
                {
                    "commit": commit,
                    "subject": measured[commit]["subject"],
                    "parent_measured": previous,
                    "scenarios": changes_by_scenario,
                }
            )
        previous = commit
    (walk.out_dir / "steps.json").write_text(json.dumps(table, indent=2) + "\n")
    print(f"steps {len(table)}", flush=True)
    for step in table:
        fields = set()
        for change in step["scenarios"].values():
            fields.update(change)
        print(f"{step['commit'][:12]} {sorted(fields)} {step['subject']}")


def open_walk(args: argparse.Namespace) -> Walk:
    repo = args.repo
    out_dir = repo / "scripts/sim/eup3-pin-walk"
    out_dir.mkdir(parents=True, exist_ok=True)
    if not args.walk.is_dir():
        raise SystemExit(f"walk worktree does not exist: {args.walk}")
    script = repo / "scripts/sim/eup3_pin_walk.py"
    if not (repo / ".git").exists() and not script.exists():
        raise SystemExit(f"repo does not look like the checkout: {repo}")
    return Walk(repo, args.walk, args.target_dir, out_dir)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--walk", required=True, type=Path)
    parser.add_argument("--target-dir", required=True, type=Path)
    parser.add_argument("command", choices=COMMANDS)
    args = parser.parse_args()
    walk = open_walk(args)
    {
        "noise": cmd_noise,
        "walk": cmd_walk,
        "gaps": cmd_gaps,
        "tail": cmd_tail,
        "merges": cmd_merges,
        "toolchains": cmd_toolchains,
        "seeds": cmd_seeds,
        "halves": cmd_halves,
        "table": cmd_table,
    }[args.command](walk)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as err:
        sys.stderr.write(err.stderr or "")
        sys.stderr.write(err.stdout or "")
        raise
