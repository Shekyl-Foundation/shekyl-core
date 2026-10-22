#!/usr/bin/env python3
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
build directory.

The walk checkout is a separate worktree. This script never checks out
inside the branch that holds its own output.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

START_L11 = "59f16037cedd889e97438c0809bddc915cb2cd74"
START_L13 = "6c85e8322a9150e7379efb9df5990fb8dedda7bc"
END = "c2dcfe601b56638bd3f68fa6f9c0a78435930493"
PIN_SEED = "0x5EED_1234"
NOISE_SEEDS = [
    PIN_SEED,
    "0x1111_1111",
    "0x2222_2222",
    "0xA5A5_A5A5",
    "0x00FF_00FF",
]
AXES = [
    "participation_attractor",
    "participation_reservation",
    "participation_transfer",
    "fee_decay",
    "fee_spiral",
    "fee_servo",
]
VECTOR = [
    "l11_fill",
    "l11_trim",
    "l11_rho_r000",
    "l11_rho_r01",
    "l11_rho_r02",
    "l11_rho_r03",
    "l11_rho_r05",
    "l11_rho_r10",
    "l11_rho_r20",
    "l11_bud_b50",
    "l11_bud_b100",
    "l11_bud_b200",
    "l11_hetero",
    "l13_decay_hi",
    "l13_decay_knee",
    "l13_decay_mid",
    "l13_decay_lo",
    "l13_decay_min",
    "l13_spiral",
    "l13_servo",
]
# The published coverage figure is cDeepU, the windowed mean. deep_und in
# a raw row is the final-epoch snapshot and is not compared.
COMPARE_FIELDS = ("bondA", "cDeepU", "oUmx", "purse")
PATH_DEPS = (
    "shekyl-archival-retention",
    "shekyl-economics",
    "shekyl-units",
    "shekyl-standoff",
)

REPO: Path
WALK: Path
TARGET_ROOT: Path
OUT_DIR: Path


def git(args: list[str], cwd: Path, check: bool = True) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=check,
        text=True,
        capture_output=True,
    )
    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, proc.args, proc.stdout, proc.stderr)
    return proc.stdout


def rev_parse(repo: Path, rev: str) -> str:
    return git(["rev-parse", rev], repo).strip()


def subject(repo: Path, commit: str) -> str:
    return git(["log", "-1", "--format=%s", commit], repo).strip()


def sim_commits(repo: Path) -> list[str]:
    text = git(
        [
            "rev-list",
            "--reverse",
            "--topo-order",
            f"{START_L11}..{END}",
            "--",
            "rust/shekyl-staking-sim",
        ],
        repo,
    )
    return [line for line in text.splitlines() if line]


def cargo_toml_deps(repo: Path, commit: str) -> list[str]:
    proc = subprocess.run(
        ["git", "show", f"{commit}:rust/shekyl-staking-sim/Cargo.toml"],
        cwd=repo,
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        return []
    return re.findall(r'path\s*=\s*"\.\./([^"]+)"', proc.stdout)


def channel_at(root: Path) -> str:
    toolchain = root / "rust/rust-toolchain.toml"
    if toolchain.exists():
        match = re.search(r'channel\s*=\s*"([^"]+)"', toolchain.read_text())
        if not match:
            raise SystemExit(f"no channel in {toolchain}")
        return match.group(1)
    cargo_toml = (root / "rust/Cargo.toml").read_text()
    match = re.search(r'^rust-version\s*=\s*"([^"]+)"', cargo_toml, re.M)
    if not match:
        raise SystemExit("no rust-version and no rust-toolchain.toml")
    return match.group(1)


def checkout(commit: str) -> None:
    git(["checkout", "-f", "--detach", commit], WALK)


def set_baseline_seed(seed: str) -> None:
    """Replace baseline()'s pin seed. The literal `seed: 0x5EED_1234` is that
    assignment; other copies of the number are named constants."""
    path = WALK / "rust/shekyl-staking-sim/src/scenarios.rs"
    text = path.read_text()
    needle = "seed: 0x5EED_1234,"
    found = text.count(needle)
    if found != 1:
        raise SystemExit(f"{needle!r} occurs {found} times at this commit")
    if seed == PIN_SEED:
        return
    path.write_text(text.replace(needle, f"seed: {seed},", 1))


def channel_of(commit: str) -> str:
    """The toolchain a commit pins, read from the commit, not the worktree."""
    proc = subprocess.run(
        ["git", "show", f"{commit}:rust/rust-toolchain.toml"],
        cwd=REPO,
        text=True,
        capture_output=True,
    )
    if proc.returncode == 0:
        match = re.search(r'channel\s*=\s*"([^"]+)"', proc.stdout)
        if not match:
            raise SystemExit(f"no channel in {commit}'s rust-toolchain.toml")
        return match.group(1)
    cargo = git(["show", f"{commit}:rust/Cargo.toml"], REPO)
    match = re.search(r'^rust-version\s*=\s*"([^"]+)"', cargo, re.M)
    if not match:
        raise SystemExit(f"no rust-version at {commit}")
    return match.group(1)


def build(channel_override: str | None = None) -> str:
    pinned = channel_at(WALK)
    chan = channel_override or pinned
    target = TARGET_ROOT / chan.replace(".", "_")
    target.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["CARGO_TARGET_DIR"] = str(target)
    env.pop("RUSTUP_TOOLCHAIN", None)
    toolchain = WALK / "rust/rust-toolchain.toml"
    hidden = None
    # A toolchain file outranks `cargo +<channel>`. Hide it for the
    # alternate build so the maths library is actually the other one.
    if channel_override and channel_override != pinned and toolchain.exists():
        hidden = toolchain.read_text()
        toolchain.unlink()
    try:
        cmd = ["cargo", f"+{chan}", "build", "-p", "shekyl-staking-sim", "--release"]
        proc = subprocess.run(
            cmd, cwd=WALK / "rust", text=True, capture_output=True, env=env
        )
    finally:
        if hidden is not None:
            toolchain.write_text(hidden)
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout)[-4000:]
        raise SystemExit(f"build failed on {chan}:\n{tail}")
    binary = target / "release/shekyl-staking-sim"
    if not binary.exists():
        raise SystemExit(f"no binary at {binary}")
    return str(binary)


def extract_json(stdout: str) -> list:
    start = stdout.find("[")
    if start < 0:
        raise SystemExit(f"no JSON array in stdout:\n{stdout[:500]}")
    return json.loads(stdout[start:])


def scenario_row(raw: dict) -> dict:
    metrics = raw.get("final_metrics") or {}
    deep = metrics.get("deep_frac_under_target")
    return {
        "bondA": raw.get("bonded_active"),
        "deep_und": deep,
        "oUmx": raw.get("oldest_under_max"),
        "cDeepU": raw.get("committed_deep_under"),
        "purse": raw.get("fee_budget_end"),
    }


def run_binary(binary: str) -> dict[str, dict]:
    main = (WALK / "rust/shekyl-staking-sim/src/main.rs").read_text()
    invocations = [[]]
    if "--axis=" in main:
        invocations = [["--axis=" + axis] for axis in AXES]
    found: dict[str, dict] = {}
    for args in invocations:
        proc = subprocess.run(
            [binary, *args],
            cwd=WALK / "rust",
            text=True,
            capture_output=True,
            timeout=900,
        )
        if proc.returncode != 0:
            if "no scenarios matched" in proc.stderr:
                continue
            raise SystemExit(
                f"run failed {args}:\n{(proc.stderr or '')[-2000:]}"
            )
        for raw in extract_json(proc.stdout):
            name = raw.get("name")
            if name in VECTOR:
                found[name] = scenario_row(raw)
    return {name: found.get(name) for name in VECTOR}


def measure(
    commit: str, seed: str = PIN_SEED, channel_override: str | None = None
) -> dict:
    checkout(commit)
    if not (WALK / "rust/shekyl-staking-sim/Cargo.toml").exists():
        # A merge parent can predate the crate. That is an absent vector,
        # not a build of a package the workspace does not contain.
        return {
            "commit": rev_parse(WALK, "HEAD"),
            "subject": subject(WALK, "HEAD"),
            "channel": None,
            "channel_override": channel_override,
            "seed": seed,
            "deps": [],
            "absent": "shekyl-staking-sim did not exist",
            "vector": {name: None for name in VECTOR},
        }
    if seed != PIN_SEED:
        set_baseline_seed(seed)
    binary = build(channel_override)
    vector = run_binary(binary)
    return {
        "commit": rev_parse(WALK, "HEAD"),
        "subject": subject(WALK, "HEAD"),
        "channel": channel_override or channel_at(WALK),
        "channel_override": channel_override,
        "seed": seed,
        "deps": cargo_toml_deps(WALK, "HEAD"),
        "vector": vector,
    }


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def done_keys(path: Path) -> set[tuple[str, str]]:
    return {(row["commit"], row.get("seed", PIN_SEED)) for row in load_jsonl(path)}


def cmd_noise() -> None:
    out = OUT_DIR / "noise.jsonl"
    have = done_keys(out)
    points = [
        ("l11-record", START_L11),
        ("l13-record", START_L13),
        ("end", END),
    ]
    for label, commit in points:
        full = rev_parse(REPO, commit)
        for seed in NOISE_SEEDS:
            if (full, seed) in have:
                print(f"noise skip {label} {seed}", flush=True)
                continue
            print(f"noise {label} {commit[:12]} {seed}", flush=True)
            row = measure(full, seed)
            row["label"] = label
            append_jsonl(out, row)
            have.add((row["commit"], seed))


def write_seeds(commit: str, label: str, dest: Path) -> None:
    """Five seeds at one tree. `measure` checks out `commit` each time,
    which drops any uncommitted patch, so callers that patched the tree
    use `write_seeds_here` instead."""
    full = rev_parse(REPO, commit)
    have = {
        (row["commit"], row.get("seed"), row.get("label"))
        for row in load_jsonl(dest)
    }
    for seed in NOISE_SEEDS:
        if (full, seed, label) in have:
            print(f"seeds skip {label} {seed}", flush=True)
            continue
        print(f"seeds {label} {full[:12]} {seed}", flush=True)
        row = measure(full, seed)
        row["label"] = label
        append_jsonl(dest, row)
        have.add((row["commit"], seed, label))


def write_seeds_here(label: str, dest: Path) -> None:
    """Five seeds at the worktree as it stands, including an applied patch."""
    head = rev_parse(WALK, "HEAD")
    have = {
        (row.get("label"), row.get("seed"))
        for row in load_jsonl(dest)
    }
    for seed in NOISE_SEEDS:
        if (label, seed) in have:
            print(f"seeds skip {label} {seed}", flush=True)
            continue
        print(f"seeds {label} {head[:12]} {seed}", flush=True)
        if seed != PIN_SEED:
            set_baseline_seed(seed)
        binary = build()
        row = {
            "commit": head,
            "subject": subject(WALK, "HEAD"),
            "channel": channel_at(WALK),
            "channel_override": None,
            "seed": seed,
            "label": label,
            "vector": run_binary(binary),
        }
        append_jsonl(dest, row)
        have.add((label, seed))
        # The next seed has to start from the patched tree, not a leftover seed.
        git(
            ["checkout", "--", "rust/shekyl-staking-sim/src/scenarios.rs"],
            WALK,
        )


DIST_COMMITS = (
    ("post-repair", "4071ec03260374b76c83efb32bd0fce43f0ad1ef"),
    ("post-a04c", "a04c988b1cdc24bd6c4d5d2bf6a1297e0e31c155"),
)
A04C = "a04c988b1cdc24bd6c4d5d2bf6a1297e0e31c155"
A04C_PARENT = "6033beea0908da3ba3624f2fd9c179653a91791d"
A04C_HALVES = (
    ("a04c-reward", "rust/shekyl-staking-sim/src/reward.rs"),
    ("a04c-retention", "rust/shekyl-archival-retention/src/consensus_state.rs"),
)


def cmd_seeds() -> None:
    """Five-seed distributions at the curve repair and at a04c."""
    dest = OUT_DIR / "distributions.jsonl"
    for label, commit in DIST_COMMITS:
        write_seeds(commit, label, dest)


def cmd_halves() -> None:
    """a04c's reward.rs change and its r_market_count change, separately.

    The other files in that commit (the workflow and the C++ getters) are
    not in the sim's build. Each half is the parent plus one file from a04c.
    """
    dest = OUT_DIR / "distributions.jsonl"
    for label, path in A04C_HALVES:
        if any(row.get("label") == label for row in load_jsonl(dest)):
            # A partial label is resumed seed by seed inside write_seeds_here.
            pass
        print(f"half {label} from {A04C_PARENT[:12]} + {path}", flush=True)
        checkout(A04C_PARENT)
        diff = git(["diff", A04C_PARENT, A04C, "--", path], REPO)
        if not diff.strip():
            raise SystemExit(f"no diff for {path}")
        proc = subprocess.run(
            ["git", "apply"],
            cwd=WALK,
            input=diff,
            text=True,
            capture_output=True,
        )
        if proc.returncode != 0:
            raise SystemExit(f"apply failed for {path}:\n{proc.stderr}")
        write_seeds_here(label, dest)
        checkout(A04C_PARENT)


def cmd_walk() -> None:
    out = OUT_DIR / "sim-commits.jsonl"
    have = {row["commit"] for row in load_jsonl(out)}
    start = rev_parse(REPO, START_L11)
    if start not in have:
        print(f"walk start {start[:12]}", flush=True)
        append_jsonl(out, measure(start))
        have.add(start)
    commits = sim_commits(REPO)
    print(f"sim commits {len(commits)}", flush=True)
    for index, commit in enumerate(commits, 1):
        full = rev_parse(REPO, commit)
        if full in have:
            continue
        print(f"walk {index}/{len(commits)} {full[:12]} {subject(REPO, full)}", flush=True)
        append_jsonl(out, measure(full))
        have.add(full)


def numbers(row: dict | None) -> dict[str, float] | None:
    if row is None:
        return None
    out = {}
    for field in COMPARE_FIELDS:
        value = row.get(field)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            out[field] = float(value)
    return out


def spreads() -> dict[str, dict[str, float]]:
    """Per scenario, per field: the widest within-point seed spread.

    Each noise point (the L11 record, the L13 record, the end pin) has
    its own five seeds. The band is the max of those spreads. Pooling
    the points together would put the drift into the band.
    """
    points: dict[str, dict[str, dict[str, list[float]]]] = {}
    for row in load_jsonl(OUT_DIR / "noise.jsonl"):
        point = row.get("label") or row["commit"]
        grouped = points.setdefault(point, {})
        for name, vector in row["vector"].items():
            nums = numbers(vector)
            if not nums:
                continue
            bucket = grouped.setdefault(name, {field: [] for field in COMPARE_FIELDS})
            for field, value in nums.items():
                bucket[field].append(value)
    spread: dict[str, dict[str, float]] = {}
    for grouped in points.values():
        for name, fields in grouped.items():
            dest = spread.setdefault(name, {})
            for field, values in fields.items():
                width = 0.0 if len(values) < 2 else max(values) - min(values)
                dest[field] = max(dest.get(field, 0.0), width)
    return spread


def moved(before: dict | None, after: dict | None, spread: dict[str, float]) -> dict[str, dict]:
    changes = {}
    b = numbers(before)
    a = numbers(after)
    if b is None and a is None:
        return changes
    if b is None or a is None:
        changes["presence"] = {"before": b, "after": a}
        return changes
    for field in COMPARE_FIELDS:
        if field not in b or field not in a:
            if field in b or field in a:
                changes[field] = {"before": b.get(field), "after": a.get(field)}
            continue
        delta = abs(a[field] - b[field])
        band = spread.get(field, 0.0)
        if delta > band + 1e-9:
            changes[field] = {
                "before": b[field],
                "after": a[field],
                "delta": a[field] - b[field],
                "band": band,
            }
    return changes


def dep_commits_between(prev_sim: str, commit: str) -> list[str]:
    """Path-dep commits after the previous measured sim commit and before
    this one. The interval is the whole step, not only this commit's
    first parent: a regular commit's parent can sit on top of dependency
    commits that the previous sim measurement did not include."""
    text = git(
        [
            "rev-list",
            "--reverse",
            "--topo-order",
            f"{prev_sim}..{commit}",
            "--",
            *(f"rust/{name}" for name in PATH_DEPS),
        ],
        REPO,
    )
    found = []
    for rev in text.splitlines():
        if not rev or rev == commit:
            continue
        deps = set(cargo_toml_deps(REPO, rev))
        # A commit counts only for a crate the sim already builds against.
        names = git(
            ["diff-tree", "--no-commit-id", "--name-only", "-r", rev],
            REPO,
        ).splitlines()
        touched = set()
        for name in names:
            parts = name.split("/")
            if len(parts) >= 2 and parts[0] == "rust":
                touched.add(parts[1])
        if touched & deps & set(PATH_DEPS):
            found.append(rev)
    return found


def cmd_gaps() -> None:
    """Re-measure path-dep commits inside intervals where the sim-commit
    vector moved. Records them in dep-commits.jsonl."""
    band = spreads()
    rows = load_jsonl(OUT_DIR / "sim-commits.jsonl")
    by_commit = {row["commit"]: row for row in rows}
    out = OUT_DIR / "dep-commits.jsonl"
    have = {row["commit"] for row in load_jsonl(out)}
    ordered = [rev_parse(REPO, START_L11)]
    ordered.extend(sim_commits(REPO))
    ordered = [rev_parse(REPO, rev) for rev in ordered]
    for prev, commit in zip(ordered, ordered[1:]):
        before = by_commit[prev]["vector"]
        after = by_commit[commit]["vector"]
        any_move = False
        for name in VECTOR:
            if moved(before.get(name), after.get(name), band.get(name, {})):
                any_move = True
                break
        if not any_move:
            continue
        interior = dep_commits_between(prev, commit)
        print(
            f"gap {prev[:12]}..{commit[:12]} dep commits {len(interior)}",
            flush=True,
        )
        for rev in interior:
            full = rev_parse(REPO, rev)
            if full in have or full in by_commit:
                continue
            print(f"  dep {full[:12]} {subject(REPO, full)}", flush=True)
            append_jsonl(out, measure(full))
            have.add(full)


def cached_pin(commit: str) -> dict | None:
    """A pin-seed measurement of commit already on disk, native toolchain."""
    full = rev_parse(REPO, commit)
    for name in (
        "sim-commits.jsonl",
        "dep-commits.jsonl",
        "noise.jsonl",
        "tail.jsonl",
        "merges.jsonl",
    ):
        for row in load_jsonl(OUT_DIR / name):
            if row.get("commit") != full:
                continue
            if row.get("seed", PIN_SEED) != PIN_SEED:
                continue
            if row.get("channel_override"):
                continue
            if "vector" not in row:
                continue
            return row
    return None


def ensure_pin(commit: str, dest: Path) -> dict:
    found = cached_pin(commit)
    if found is not None:
        return found
    row = measure(commit)
    append_jsonl(dest, row)
    return row


def any_moved(before: dict, after: dict, band: dict) -> bool:
    for name in VECTOR:
        if moved(before.get(name), after.get(name), band.get(name, {})):
            return True
    return False


def cmd_tail() -> None:
    """Dependency commits after the last sim commit, up to the end pin.

    The crate can stop changing while the crates it links keep changing.
    Compare the last sim commit with the end pin; walk that interval only
    when the vector moved.
    """
    commits = [rev_parse(REPO, rev) for rev in sim_commits(REPO)]
    have = {row["commit"] for row in load_jsonl(OUT_DIR / "sim-commits.jsonl")}
    if not commits or commits[-1] not in have:
        raise SystemExit("sim walk is not finished; the tail waits for it")
    last = commits[-1]
    end = rev_parse(REPO, END)
    dest = OUT_DIR / "tail.jsonl"
    end_row = ensure_pin(end, dest)
    last_row = cached_pin(last)
    if last_row is None:
        raise SystemExit(f"no pin-seed row for the last sim commit {last}")
    band = spreads()
    if not any_moved(last_row["vector"], end_row["vector"], band):
        print(f"tail {last[:12]}..{end[:12]} did not move", flush=True)
        return
    interior = dep_commits_between(last, end)
    print(f"tail {last[:12]}..{end[:12]} dep commits {len(interior)}", flush=True)
    have_dep = {row["commit"] for row in load_jsonl(dest)}
    for rev in interior:
        full = rev_parse(REPO, rev)
        if cached_pin(full) is not None or full in have_dep:
            continue
        print(f"  tail {full[:12]} {subject(REPO, full)}", flush=True)
        append_jsonl(dest, measure(full))
        have_dep.add(full)


def first_parent_merges() -> list[str]:
    text = git(
        [
            "log",
            "--first-parent",
            "--format=%H",
            f"{START_L11}..{END}",
            "--",
            "rust/shekyl-staking-sim",
        ],
        REPO,
    )
    merges = []
    for rev in text.splitlines():
        if not rev:
            continue
        parents = git(["rev-parse", f"{rev}^@"], REPO).split()
        if len(parents) >= 2:
            merges.append(rev)
    return merges


def cmd_merges() -> None:
    """Each first-parent merge that touches the sim, against both parents.

    Side-branch commits are measured alone. A step that appears only when
    two branches are combined is visible here and nowhere in that list.
    """
    dest = OUT_DIR / "merges.jsonl"
    have = {row["commit"] for row in load_jsonl(dest)}
    band = spreads()
    report = []
    for rev in first_parent_merges():
        parents = git(["rev-parse", f"{rev}^@"], REPO).split()
        rows = {}
        for commit in [rev, *parents]:
            full = rev_parse(REPO, commit)
            if full not in have and cached_pin(full) is None:
                print(f"merge measure {full[:12]} {subject(REPO, full)}", flush=True)
                append_jsonl(dest, measure(full))
                have.add(full)
            rows[full] = cached_pin(full)
        merge = rev_parse(REPO, rev)
        diffs = {}
        for parent in parents:
            full = rev_parse(REPO, parent)
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
                "subject": subject(REPO, merge),
                "parents": [rev_parse(REPO, parent) for parent in parents],
                "differs_from": diffs,
            }
        )
        print(
            f"merge {merge[:12]} differs from {len(diffs)} parent(s): {subject(REPO, merge)}",
            flush=True,
        )
    (OUT_DIR / "merges.json").write_text(json.dumps(report, indent=2) + "\n")


def channel_key(chan: str) -> str:
    """1.94 and 1.94.0 are one pin. The comparison is the minor version."""
    parts = chan.split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else chan


def measure_or_refuse(
    commit: str, channel_override: str, dest: Path, have: set
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
        row = measure(commit, channel_override=channel_override)
    except SystemExit as err:
        row = {
            "commit": rev_parse(REPO, commit),
            "subject": subject(REPO, commit),
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


def cmd_toolchains() -> None:
    """Where the pinned toolchain changes, build under both compilers.

    powf, exp and ln come from the toolchain's maths library. The commit
    that raises rust-version cannot be built by the old compiler, so that
    direction is recorded as refused. The last commit that still builds
    on the old pin is built with the new compiler: that pair is the
    maths library alone.
    """
    sequence = [rev_parse(REPO, START_L11)]
    sequence.extend(rev_parse(REPO, rev) for rev in sim_commits(REPO))
    end = rev_parse(REPO, END)
    if sequence[-1] != end:
        sequence.append(end)
    dest = OUT_DIR / "toolchain-pairs.jsonl"
    have = {
        (row["commit"], row.get("channel_override"))
        for row in load_jsonl(dest)
        if row.get("channel_override")
    }
    band = spreads()
    report = []
    prev_commit = sequence[0]
    prev_channel = channel_of(prev_commit)
    for commit in sequence[1:]:
        chan = channel_of(commit)
        if channel_key(chan) != channel_key(prev_channel):
            # New code on the old compiler. Often refused by rust-version.
            backward = measure_or_refuse(commit, prev_channel, dest, have)
            # Old code on the new compiler. This is the one that can run.
            forward = measure_or_refuse(prev_commit, chan, dest, have)
            native_old = cached_pin(prev_commit)
            native_new = cached_pin(commit)
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
                    "subject": subject(REPO, commit),
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
    (OUT_DIR / "toolchain-steps.json").write_text(json.dumps(report, indent=2) + "\n")


def fmt_num(value) -> str:
    if value is None:
        return "absent"
    if isinstance(value, float):
        return f"{value:.4g}"
    return str(value)


def cmd_table() -> None:
    band = spreads()
    (OUT_DIR / "noise-spread.json").write_text(json.dumps(band, indent=2, sort_keys=True) + "\n")
    measured: dict[str, dict] = {}
    # Merge parents stay in merges.json. Putting them in this chain
    # turns "the crate did not exist yet" into a population step.
    for name in (
        "sim-commits.jsonl",
        "dep-commits.jsonl",
        "tail.jsonl",
    ):
        for row in load_jsonl(OUT_DIR / name):
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
    ordered_text = git(
        ["rev-list", "--reverse", "--topo-order", f"{START_L11}..{END}"],
        REPO,
    )
    ordered = [rev_parse(REPO, START_L11)]
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
    (OUT_DIR / "steps.json").write_text(json.dumps(table, indent=2) + "\n")
    print(f"steps {len(table)}", flush=True)
    for step in table:
        fields = set()
        for change in step["scenarios"].values():
            fields.update(change)
        print(f"{step['commit'][:12]} {sorted(fields)} {step['subject']}")


def main() -> None:
    global REPO, WALK, TARGET_ROOT, OUT_DIR
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--walk", required=True, type=Path)
    parser.add_argument("--target-dir", required=True, type=Path)
    parser.add_argument(
        "command",
        choices=(
            "noise",
            "walk",
            "gaps",
            "tail",
            "merges",
            "toolchains",
            "seeds",
            "halves",
            "table",
        ),
    )
    args = parser.parse_args()
    REPO = args.repo
    WALK = args.walk
    TARGET_ROOT = args.target_dir
    OUT_DIR = REPO / "scripts/sim/eup3-pin-walk"
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if not WALK.is_dir():
        raise SystemExit(f"walk worktree does not exist: {WALK}")
    if not (REPO / ".git").exists() and not (REPO / "scripts/sim/eup3_pin_walk.py").exists():
        raise SystemExit(f"repo does not look like the checkout: {REPO}")
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
    }[args.command]()


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as err:
        sys.stderr.write(err.stderr or "")
        sys.stderr.write(err.stdout or "")
        raise
