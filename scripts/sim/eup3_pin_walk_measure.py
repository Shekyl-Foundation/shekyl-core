# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Checkout, build, and read one staking-sim pin vector.

`eup3_pin_walk.py` is the commands. This module is the measurement they
share. A [`Walk`] is built in `main` from the arguments. Nothing here
reads a path from a global, so a second import cannot build against an
unset worktree.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
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
# The baseline seed lives in this file. A half that patches it is refused:
# the per-seed restore would drop that patch on the second seed.
SCENARIOS_RS = "rust/shekyl-staking-sim/src/scenarios.rs"
_BASELINE_SEED_NEEDLE = "seed: 0x5EED_1234,"


@dataclass(frozen=True)
class Walk:
    """One measurement's trees.

    `repo` names commits and holds the jsonl. `walk` is the detached
    checkout those commits are built in. `target_root` is the cargo
    target parent, one directory per toolchain. `out_dir` is the jsonl
    directory, under `repo` unless a caller says otherwise.
    """

    repo: Path
    walk: Path
    target_root: Path
    out_dir: Path

    def git(self, args: list[str], cwd: Path, check: bool = True) -> str:
        proc = subprocess.run(
            ["git", *args],
            cwd=cwd,
            check=check,
            text=True,
            capture_output=True,
        )
        if check and proc.returncode != 0:
            raise subprocess.CalledProcessError(
                proc.returncode, proc.args, proc.stdout, proc.stderr
            )
        return proc.stdout

    def rev_parse(self, rev: str, cwd: Path) -> str:
        return self.git(["rev-parse", rev], cwd).strip()

    def subject(self, commit: str, cwd: Path) -> str:
        return self.git(["log", "-1", "--format=%s", commit], cwd).strip()

    def sim_commits(self) -> list[str]:
        text = self.git(
            [
                "rev-list",
                "--reverse",
                "--topo-order",
                f"{START_L11}..{END}",
                "--",
                "rust/shekyl-staking-sim",
            ],
            self.repo,
        )
        return [line for line in text.splitlines() if line]

    def cargo_toml_deps(self, commit: str, cwd: Path) -> list[str]:
        proc = subprocess.run(
            ["git", "show", f"{commit}:rust/shekyl-staking-sim/Cargo.toml"],
            cwd=cwd,
            text=True,
            capture_output=True,
        )
        if proc.returncode != 0:
            return []
        return re.findall(r'path\s*=\s*"\.\./([^"]+)"', proc.stdout)

    def channel_at(self, root: Path) -> str:
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

    def checkout(self, commit: str) -> None:
        self.git(["checkout", "-f", "--detach", commit], self.walk)

    def set_baseline_seed(self, seed: str) -> None:
        """Replace baseline()'s pin seed. The literal `seed: 0x5EED_1234` is
        that assignment; other copies of the number are named constants."""
        path = self.walk / SCENARIOS_RS
        text = path.read_text()
        found = text.count(_BASELINE_SEED_NEEDLE)
        if found != 1:
            raise SystemExit(f"{_BASELINE_SEED_NEEDLE!r} occurs {found} times at this commit")
        if seed == PIN_SEED:
            return
        path.write_text(text.replace(_BASELINE_SEED_NEEDLE, f"seed: {seed},", 1))

    def channel_of(self, commit: str) -> str:
        """The toolchain a commit pins, read from the commit, not the worktree."""
        proc = subprocess.run(
            ["git", "show", f"{commit}:rust/rust-toolchain.toml"],
            cwd=self.repo,
            text=True,
            capture_output=True,
        )
        if proc.returncode == 0:
            match = re.search(r'channel\s*=\s*"([^"]+)"', proc.stdout)
            if not match:
                raise SystemExit(f"no channel in {commit}'s rust-toolchain.toml")
            return match.group(1)
        cargo = self.git(["show", f"{commit}:rust/Cargo.toml"], self.repo)
        match = re.search(r'^rust-version\s*=\s*"([^"]+)"', cargo, re.M)
        if not match:
            raise SystemExit(f"no rust-version at {commit}")
        return match.group(1)

    def build(self, channel_override: str | None = None) -> str:
        pinned = self.channel_at(self.walk)
        chan = channel_override or pinned
        target = self.target_root / chan.replace(".", "_")
        target.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ)
        env["CARGO_TARGET_DIR"] = str(target)
        env.pop("RUSTUP_TOOLCHAIN", None)
        toolchain = self.walk / "rust/rust-toolchain.toml"
        hidden = None
        # A toolchain file outranks `cargo +<channel>`. Hide it for the
        # alternate build so the maths library is actually the other one.
        if channel_override and channel_override != pinned and toolchain.exists():
            hidden = toolchain.read_text()
            toolchain.unlink()
        try:
            cmd = ["cargo", f"+{chan}", "build", "-p", "shekyl-staking-sim", "--release"]
            proc = subprocess.run(
                cmd, cwd=self.walk / "rust", text=True, capture_output=True, env=env
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

    def invoke(self, binary: str, args: list[str]) -> tuple[list[dict], str]:
        """Rows from one invocation, and `ok` / `empty` / `unknown` / `failed`."""
        proc = subprocess.run(
            [binary, *args],
            cwd=self.walk / "rust",
            text=True,
            capture_output=True,
            timeout=900,
        )
        if proc.returncode != 0:
            kind = classify_run(proc.stderr or "")
            if kind == "failed":
                raise SystemExit(f"run failed {args}:\n{(proc.stderr or '')[-2000:]}")
            return [], kind
        return extract_json(proc.stdout), "ok"

    def run_binary(self, binary: str) -> dict[str, dict]:
        """The pin vector, from the axes when the binary honors `--axis`.

        One unscoped run is the whole population. The probe is the first
        axis. An unknown flag, or a flag the binary ignores, falls back to
        that single unscoped run. The source text is not consulted.
        """
        found: dict[str, dict] = {}
        rows, kind = self.invoke(binary, [f"--axis={AXES[0]}"])
        if kind == "unknown":
            # `invoke` already exits when the run itself failed.
            rows, _kind = self.invoke(binary, [])
            absorb(found, rows)
            return project(found)
        if kind == "ok" and not axis_was_honored(rows, AXES[0]):
            absorb(found, rows)
            return project(found)
        if kind == "ok":
            absorb(found, rows)
        for axis in AXES[1:]:
            if all(name in found for name in VECTOR):
                break
            more, axis_kind = self.invoke(binary, [f"--axis={axis}"])
            if axis_kind == "unknown":
                continue
            if axis_kind == "ok":
                absorb(found, more)
        return project(found)

    def measure(
        self, commit: str, seed: str = PIN_SEED, channel_override: str | None = None
    ) -> dict:
        self.checkout(commit)
        if not (self.walk / "rust/shekyl-staking-sim/Cargo.toml").exists():
            # A merge parent can predate the crate. That is an absent vector,
            # not a build of a package the workspace does not contain.
            return {
                "commit": self.rev_parse("HEAD", self.walk),
                "subject": self.subject("HEAD", self.walk),
                "channel": None,
                "channel_override": channel_override,
                "seed": seed,
                "deps": [],
                "absent": "shekyl-staking-sim did not exist",
                "vector": {name: None for name in VECTOR},
            }
        if seed != PIN_SEED:
            self.set_baseline_seed(seed)
        binary = self.build(channel_override)
        vector = self.run_binary(binary)
        return {
            "commit": self.rev_parse("HEAD", self.walk),
            "subject": self.subject("HEAD", self.walk),
            "channel": channel_override or self.channel_at(self.walk),
            "channel_override": channel_override,
            "seed": seed,
            "deps": self.cargo_toml_deps("HEAD", self.walk),
            "vector": vector,
        }

    def measure_standing(self, seed: str) -> dict:
        """One seed at the checkout as it stands, including an applied patch.

        Does not check out and does not restore `scenarios.rs`. The caller
        restores that file between seeds.
        """
        if seed != PIN_SEED:
            self.set_baseline_seed(seed)
        binary = self.build()
        return {
            "commit": self.rev_parse("HEAD", self.walk),
            "subject": self.subject("HEAD", self.walk),
            "channel": self.channel_at(self.walk),
            "channel_override": None,
            "seed": seed,
            "vector": self.run_binary(binary),
        }

    def spreads(self) -> dict[str, dict[str, float]]:
        """Per scenario, per field: the widest within-point seed spread.

        Each noise point (the L11 record, the L13 record, the end pin) has
        its own five seeds. The band is the max of those spreads. Pooling
        the points together would put the drift into the band.
        """
        points: dict[str, dict[str, dict[str, list[float]]]] = {}
        for row in load_jsonl(self.out_dir / "noise.jsonl"):
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

    def dep_commits_between(self, prev_sim: str, commit: str) -> list[str]:
        """Path-dep commits after the previous measured sim commit and before
        this one. The interval is the whole step, not only this commit's
        first parent: a regular commit's parent can sit on top of dependency
        commits that the previous sim measurement did not include."""
        text = self.git(
            [
                "rev-list",
                "--reverse",
                "--topo-order",
                f"{prev_sim}..{commit}",
                "--",
                *(f"rust/{name}" for name in PATH_DEPS),
            ],
            self.repo,
        )
        found = []
        for rev in text.splitlines():
            if not rev or rev == commit:
                continue
            deps = set(self.cargo_toml_deps(rev, self.repo))
            # A commit counts only for a crate the sim already builds against.
            names = self.git(
                ["diff-tree", "--no-commit-id", "--name-only", "-r", rev],
                self.repo,
            ).splitlines()
            touched = set()
            for name in names:
                parts = name.split("/")
                if len(parts) >= 2 and parts[0] == "rust":
                    touched.add(parts[1])
            if touched & deps & set(PATH_DEPS):
                found.append(rev)
        return found

    def cached_pin(self, commit: str) -> dict | None:
        """A pin-seed measurement of commit already on disk, native toolchain."""
        full = self.rev_parse(commit, self.repo)
        for name in (
            "sim-commits.jsonl",
            "dep-commits.jsonl",
            "noise.jsonl",
            "tail.jsonl",
            "merges.jsonl",
        ):
            for row in load_jsonl(self.out_dir / name):
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

    def ensure_pin(self, commit: str, dest: Path) -> dict:
        found = self.cached_pin(commit)
        if found is not None:
            return found
        row = self.measure(commit)
        append_jsonl(dest, row)
        return row

    def any_moved(self, before: dict, after: dict, band: dict) -> bool:
        for name in VECTOR:
            if moved(before.get(name), after.get(name), band.get(name, {})):
                return True
        return False


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


def classify_run(stderr: str) -> str:
    """`empty` is a filter that matched nothing. `unknown` is a flag the
    binary does not have. Anything else is a failed run."""
    text = stderr.lower()
    if "no scenarios matched" in text:
        return "empty"
    if (
        "unexpected argument" in text
        or "unrecognized" in text
        or "unknown argument" in text
    ):
        return "unknown"
    return "failed"


def absorb(found: dict[str, dict], rows: list[dict]) -> None:
    for raw in rows:
        name = raw.get("name")
        if name in VECTOR:
            found[name] = scenario_row(raw)


def axis_was_honored(rows: list[dict], axis: str) -> bool:
    """True when every returned row carries this axis prefix.

    A binary that ignores `--axis` returns the whole population. That
    output is already the vector, and running the other prefixes would
    repeat it. A row with no `axis` field is a population dump when the
    run is larger than the pin vector.
    """
    if not rows:
        return True
    names = [row.get("axis") for row in rows]
    if any(name is None for name in names):
        return len(rows) <= len(VECTOR)
    return all(str(name).startswith(axis) for name in names)


def project(found: dict[str, dict]) -> dict[str, dict]:
    return {name: found.get(name) for name in VECTOR}


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


def numbers(row: dict | None) -> dict[str, float] | None:
    if row is None:
        return None
    out = {}
    for field in COMPARE_FIELDS:
        value = row.get(field)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            out[field] = float(value)
    return out


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
