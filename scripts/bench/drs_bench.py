#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# DRS-BENCH — consensus-store benchmark harness and IBD-floor gate.
#
# Subject: `docs/design/DAEMON_REDB_STORE.md` §7.4 (what to measure) against
# §1.3 (the pre-registered floor). Stage one lands the harness and the **LMDB
# baseline**; the redb arm lands with DRS-E1, because there is no redb consensus
# store to measure yet — `rust/shekyl-chain-store/` names `redb` in four
# type-level declarations (table definitions and LMDB key ordering) and holds no
# `Database`, no transaction, no engine. That is a measured result, not an
# assumption, and `blockers` below re-checks it on every run.
#
# WHY THE RATIO AND NOT A THROUGHPUT NUMBER. §1.3 retired the throughput column
# (decision log 2026-07-27). Absolute times are not comparable across machines;
# the floor is a RATIO taken on one machine with one binary, engine being the
# only difference. So every absolute figure here exists to produce a ratio, and
# `check` refuses to produce one from two artifacts that disagree about anything
# else (see `comparability_refusals`).
#
# ── DURABILITY IS PART OF THE MEASUREMENT, NOT METADATA ──────────────────────
#
# DRS-D9 binds the consensus store to the strictest practical durability, and
# A4 (§4, line ~273) states the requirement as "explicit ... not library
# default by omission". On the LMDB path today it IS by omission, in three
# separate ways, all of which would silently corrupt a baseline:
#
#   1. `cryptonote_core.cpp` `DEFAULT_FLAGS = DBF_FAST` — an unconfigured
#      daemon opens LMDB with `MDB_NOSYNC` (`db_lmdb.cpp`, the DBF_FAST arm).
#   2. A malformed `--db-sync-mode` value falls through the mode `else` to
#      `DEFAULT_FLAGS` **with no error**. Only a bad *threshold* token is
#      diagnosed. So `--db-sync-mode=saf` measures NOSYNC and says nothing.
#   3. With the argument defaulted, `m_db_default_sync` is true and
#      `cryptonote_protocol_handler.inl` calls `safesyncmode(false)` when sync
#      starts, restoring it only once synchronized. The shipped default
#      daemon's IBD therefore runs at `MDB_NOSYNC|MDB_MAPASYNC` — its least
#      durable phase is exactly the phase this harness measures.
#
# Consequence for the reader of any number produced here: a DRS-D9 baseline is
# **not** comparable to a default daemon's IBD time, and is expected to be
# slower. Both engines pay the same fsync cost, so the RATIO is fair; the
# ABSOLUTE is not a user-facing sync-time estimate. `scenario` and
# `durability` are recorded on every measure so this cannot be misread.
#
# `DBF_SAFE` is 1 and `db_lmdb.cpp`'s open() never reads it, so
# `--db-sync-mode=safe` leaves `mdb_flags == 0`: LMDB's own default, an fsync
# per commit. That is the production-intent configuration, and it also makes
# `safesyncmode()` a no-op because the argument is no longer defaulted.
#
# ── WHAT THIS HARNESS CANNOT OBSERVE ────────────────────────────────────────
#
# Recorded once, here, at harness level rather than probed per-run: a probe for
# a gap the harness cannot close would fire while its blocker still stood.
#
#   * **The LMDB env flags actually in force.** `mdb_env_get_flags` is
#     in-process only and the daemon logs no resolved sync mode, so nothing
#     outside the process can read them back. The harness therefore VALIDATES
#     the mode against an allowed set before spawning (`ALLOWED_SYNC_MODES`)
#     and records the argv verbatim. An allowed-set check has safe polarity —
#     over-inclusion is a false red. It is not a readback, and it is not
#     claimed as one. The enabler that would make it one is a single log line
#     reporting resolved `db_flags`/`sync_mode`, which A4 already wants.
#   * **Two rejected probes, so they are not re-invented.** `SIGKILL` cannot
#     discriminate fsync from NOSYNC: `MDB_NOSYNC` data survives process death
#     in the page cache — only power loss separates them. Counting fsyncs
#     cannot either: under the default `fast:async:1` the async
#     `store_blockchain()` calls `mdb_env_sync(force)` at about the same
#     cadence, and only the blocking-ness differs.
#   * **FCMP++ verification cost.** Any coinbase-only fixture exercises none
#     of it. §1.3's primary metric says "FCMP++ + PoW verify enabled as in real
#     sync"; PoW verify IS exercised (see below), FCMP++ is not, and
#     `verify_exercised` records that per artifact rather than letting the
#     phrase stand unqualified. §1.3 pre-authorizes the shortfall — "or max
#     available fixture; the artifact records the height it reached".
#
# PoW verify cost IS real under regtest. `blockchain.cpp`'s PoW arm computes
# `get_block_longhash` for every block with no nettype bypass — its only `else`
# is a precomputed-longhash cache — and its comment records that the
# checkpoint-zone bypass was deliberately removed. `--fixed-difficulty` lowers
# the difficulty TARGET only; the RandomX hash is still computed and checked.
#
# ── LANGUAGE ────────────────────────────────────────────────────────────────
#
# Python, under `scripts/bench/`, deliberately. Rule 20 makes Rust the default
# for the DAEMON codebase and its bug fixes; this is neither — it spawns
# daemons and compares JSON, the same job and the same directory as
# `compare.py`, `post_comment.py` and `capture_rust_baseline.sh`. Putting a
# process orchestrator in Rust here would add a crate to the workspace that
# ships nothing and advances no FFI boundary.
#
# It is NOT a second copy of `scripts/bench/compare.py`. That script is
# "**iai-callgrind only**" by construction (its own words): criterion
# wall-clock rows pass through as informational with `verdict: "info"` and no
# threshold, and its ids are `<crate>/<bench_target>/<group>/<function>`, which
# cannot name a two-daemon C++ IBD run. It could not carry these rows, and
# widening it would put an instruction-count gate and a wall-time gate behind
# one schema.

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DESIGN_DOC = os.path.join(ROOT, "docs/design/DAEMON_REDB_STORE.md")
CHAIN_STORE = os.path.join(ROOT, "rust/shekyl-chain-store")

SCHEMA = "shekyl_drs_bench_v1"

# ── §1.3, PRE-REGISTERED AND FROZEN ─────────────────────────────────────────
#
# Frozen 2026-09-12 (DRS-0 slice C) BEFORE any measurement existed. Refining a
# ratio after seeing a number is a threshold CHANGE requiring reopening under
# rule 21, not a refinement — a finding for the decision authority, never an
# edit here. `test_frozen_thresholds_*` cross-checks every value below against
# the doc's own §1.3 text in BOTH directions, so editing either side alone is
# a red.
FROZEN_AT = "ba4b3c73a"
REFERENCE_HEIGHT = 100_000
IBD_FLOOR_RATIO = 1.25       # <= passes
IBD_HARD_FAIL_RATIO = 1.50   # >  hard-fails after one documented mitigation cycle
PEAK_RSS_RATIO = 2.0         # <= passes

# The only sync mode that satisfies DRS-D9 on the LMDB path. An allowed set
# rather than a spelling check: `--db-sync-mode=saf` is accepted by the daemon
# and silently means NOSYNC, so the harness must refuse the string itself
# before a daemon ever sees it.
ALLOWED_SYNC_MODES = ("safe",)

PRIMARY_MEASURE = "ibd_wall_time_s"
MEASURE_AXES = {
    "ibd_wall_time_s": ("wall_time", "s", IBD_FLOOR_RATIO, IBD_HARD_FAIL_RATIO),
    "peak_rss_bytes": ("memory", "bytes", PEAK_RSS_RATIO, PEAK_RSS_RATIO),
    # Two disk rows, because §1.3's resource bound names a "file-size / logical-size
    # ratio": `store_bytes` is what the filesystem ALLOCATED (the operator's cost)
    # and `store_bytes_apparent` is the file length. They diverge exactly when an
    # engine leaves holes, which is a property that could differ between engines,
    # so collapsing them to one number would hide the thing worth comparing.
    # Neither carries a threshold — the ceiling is set after the first multi-year
    # sim, so a verdict here would be invented.
    "store_bytes": ("disk", "bytes", None, None),
    "store_bytes_apparent": ("disk", "bytes", None, None),
}

# ── §7.4 follow-on measures, each with a NAMED blocker (rule 22) ────────────
#
# Two kinds, and the difference is whether the blocker can be MECHANICALLY
# re-checked. One that can is probed by `blockers` and fails the moment it
# stops holding, so the deferral cannot outlive its cause. One that cannot is
# recorded here and nowhere else — a probe that cannot observe its own blocker
# would fire while the blocker still stood, which is worse than a comment.
FOLLOWON_MEASURES = {
    "pop_reorg_wall_time_s": (
        "PROBED", "best-positioned follow-on: the /pop_blocks RPC already exists, "
        "so this needs a depth schedule and an artifact row, not a new capability."),
    "store_bytes_multi_year": (
        "RECORDED", "§1.3 states the file-size ceiling is 'set after first multi-year "
        "sim', so no threshold exists to gate against. A measure with no threshold "
        "emits a number with no verdict; landing it would create the appearance of "
        "coverage. Needs the ceiling first, which is a decision, not a measurement."),
    "free_page_reclaim": (
        "RECORDED", "needs a long-lived concurrent-reader workload; no such driver "
        "exists in tests/ or scripts/."),
    "peak_rss_attacker_feed": (
        "RECORDED", "§7.4 names 'attacker-shaped input' without defining it. Choosing "
        "a shape here would invent the threat model this measure is supposed to test. "
        "Needs a definition, which is a design round."),
}


def _fail(msg):
    print(f"drs_bench: {msg}", file=sys.stderr)
    sys.exit(1)


# ── artifact validation: no number without its conditions ───────────────────

def artifact_refusals(a):
    """Reasons this artifact may not be used as a measurement. Empty == usable.

    Every entry is a condition §1.3 requires be RECORDED. The harness refuses
    to emit, and `check` refuses to read, an artifact missing any of them —
    "unlabeled numbers are not genesis-load-bearing" is made unrepresentable
    rather than merely stated.
    """
    r = []
    if not isinstance(a, dict):
        return ["artifact is not a JSON object"]
    if a.get("schema_version") != SCHEMA:
        r.append(f"schema_version is {a.get('schema_version')!r}, expected {SCHEMA!r}")
    if a.get("engine") not in ("lmdb", "redb"):
        r.append(f"engine is {a.get('engine')!r}, expected 'lmdb' or 'redb'")
    if not a.get("git_rev"):
        r.append("git_rev absent — a number with no tree is not reproducible")

    d = a.get("durability")
    if not isinstance(d, dict):
        r.append("durability block absent — §1.3(3): artifacts MUST record durability "
                 "configuration, and DRS-D9 is the policy they must record")
    else:
        if d.get("sync_mode") not in ALLOWED_SYNC_MODES:
            r.append(f"durability.sync_mode is {d.get('sync_mode')!r}; only "
                     f"{list(ALLOWED_SYNC_MODES)} satisfies DRS-D9 on the LMDB path. A "
                     "value the daemon does not recognise falls through to DBF_FAST "
                     "(MDB_NOSYNC) in silence")
        argv = d.get("imposed_argv")
        if not isinstance(argv, list) or not argv:
            r.append("durability.imposed_argv absent — the harness cannot read the env "
                     "flags back, so the argv it imposed IS the record")
        elif not any(x == f"--db-sync-mode={d.get('sync_mode')}" for x in argv):
            r.append(f"durability.imposed_argv does not carry "
                     f"--db-sync-mode={d.get('sync_mode')}, so the recorded mode is not "
                     "the mode that was imposed")
        if d.get("observed") is not False:
            r.append("durability.observed must be present and false: no readback of the "
                     "LMDB env flags exists. Recording it as observed would claim an "
                     "observation the harness cannot make")

    h = a.get("hardware")
    if not isinstance(h, dict):
        r.append("hardware block absent — §1.3 requires CPU model, RAM and disk type "
                 "in the artifact")
    else:
        for k in ("cpu_model", "ram_bytes", "disk_class"):
            if not h.get(k):
                r.append(f"hardware.{k} absent or empty")

    f = a.get("fixture")
    if not isinstance(f, dict):
        r.append("fixture block absent")
    else:
        if not f.get("nettype"):
            r.append("fixture.nettype absent")
        hr = f.get("height_reached")
        if not isinstance(hr, int) or hr <= 0:
            r.append(f"fixture.height_reached is {hr!r} — a run that reached no height "
                     "produced no measurement")
        if not isinstance(f.get("height_requested"), int):
            r.append("fixture.height_requested absent — without it the artifact cannot "
                     "say whether it fell short of §1.3's reference height")
        v = f.get("verify_exercised")
        if not isinstance(v, dict) or not all(k in v for k in ("pow", "fcmp_pp")):
            r.append("fixture.verify_exercised must state pow and fcmp_pp explicitly; "
                     "§1.3's primary metric names both and a coinbase-only fixture "
                     "exercises only one")
        if "tx_per_block" not in f:
            r.append("fixture.tx_per_block absent — it is the reason fcmp_pp is not "
                     "exercised, so it belongs in the record")

    ms = a.get("measures")
    if not isinstance(ms, list) or not ms:
        r.append("measures absent or empty")
    else:
        for i, m in enumerate(ms):
            if not isinstance(m, dict):
                r.append(f"measures[{i}] is not an object")
                continue
            name = m.get("name")
            if name not in MEASURE_AXES:
                r.append(f"measures[{i}].name is {name!r}, not one of "
                         f"{sorted(MEASURE_AXES)}")
                continue
            axis, unit, _, _ = MEASURE_AXES[name]
            if not isinstance(m.get("value"), (int, float)) or m["value"] < 0:
                r.append(f"measures[{i}] ({name}) value is {m.get('value')!r}")
            if m.get("axis") != axis:
                r.append(f"measures[{i}] ({name}) axis is {m.get('axis')!r}, expected "
                         f"{axis!r} — state the axis a figure is on")
            if m.get("unit") != unit:
                r.append(f"measures[{i}] ({name}) unit is {m.get('unit')!r}, expected "
                         f"{unit!r}")
            if not m.get("scenario"):
                r.append(f"measures[{i}] ({name}) scenario absent — an IBD RSS figure "
                         "must not be readable as §7.4's attacker-feed row")
    return r


# ── comparability: the ratio's denominator must be the same experiment ──────

def _masked_argv(a):
    """Subject argv with engine- and path-specific arguments removed.

    §1.3: "same machine, same binary flags except engine". Data directory and
    ports differ between the two runs by construction and say nothing about the
    engine, so they are masked; everything else must match, because anything
    else differing means the two numbers answer different questions.
    """
    out = []
    for x in a.get("durability", {}).get("imposed_argv", []):
        if re.match(r"^--(data-dir|p2p-bind-port|rpc-bind-port|add-exclusive-node|"
                    r"log-file|db-engine)=", x):
            continue
        out.append(x)
    return out


def _durability_policy(a):
    """The durability block minus the argv, which is compared under the mask."""
    d = dict(a.get("durability", {}))
    d.pop("imposed_argv", None)
    return d


def comparability_refusals(base, cand):
    """Reasons these two artifacts cannot produce a §1.3 ratio."""
    r = []
    if base.get("engine") == cand.get("engine"):
        r.append(f"both artifacts are engine={base.get('engine')!r}; §1.3's floor is a "
                 "ratio BETWEEN engines. Two same-engine runs are a regression "
                 "comparison, which this gate does not define thresholds for")
    if base.get("hardware") != cand.get("hardware"):
        r.append("hardware blocks differ — cross-machine absolute times are not "
                 "load-bearing, so a ratio across machines is not the floor §1.3 froze")
    # `imposed_argv` lives inside the durability block but is compared SEPARATELY,
    # under the path/port mask below: the two runs differ in data directory and
    # ports by construction. Comparing the block wholesale would therefore refuse
    # every real pair — caught by `test_control_datadir_and_ports_are_masked`,
    # which is precisely the job of a control over a refusal set.
    if _durability_policy(base) != _durability_policy(cand):
        r.append("durability blocks differ — a ratio between different durability "
                 "policies measures the policy, not the engine")
    bf, cf = base.get("fixture", {}), cand.get("fixture", {})
    for k in ("nettype", "height_reached", "verify_exercised", "tx_per_block"):
        if bf.get(k) != cf.get(k):
            r.append(f"fixture.{k} differs ({bf.get(k)!r} vs {cf.get(k)!r}) — the two "
                     "runs did not do the same work")
    if _masked_argv(base) != _masked_argv(cand):
        r.append("subject argv differs beyond engine and paths: "
                 f"{_masked_argv(base)} vs {_masked_argv(cand)}")
    bn = {m["name"] for m in base.get("measures", [])}
    cn = {m["name"] for m in cand.get("measures", [])}
    if PRIMARY_MEASURE not in bn & cn:
        r.append(f"{PRIMARY_MEASURE} is not present on both artifacts; it is §1.3's "
                 "primary metric and the floor is defined on it")
    return r


def compare(base, cand):
    """The §1.3 verdict. Callers must have validated both artifacts first."""
    bm = {m["name"]: m["value"] for m in base["measures"]}
    cm = {m["name"]: m["value"] for m in cand["measures"]}
    rows, worst = [], "PASS"
    rank = {"PASS": 0, "BAND": 1, "OVER": 2, "NO_THRESHOLD": 0}
    for name in sorted(bm.keys() & cm.keys()):
        axis, unit, floor, hard = MEASURE_AXES[name]
        b, c = bm[name], cm[name]
        if b == 0:
            rows.append({"name": name, "axis": axis, "unit": unit, "baseline": b,
                         "candidate": c, "ratio": None, "verdict": "NO_THRESHOLD",
                         "note": "baseline is zero; a ratio would be undefined"})
            continue
        ratio = c / b
        if floor is None:
            v, note = "NO_THRESHOLD", FOLLOWON_MEASURES.get(name, ("", "§1.3 states no "
                                                                   "threshold"))[1]
        elif ratio <= floor:
            v, note = "PASS", f"<= {floor}x floor"
        elif ratio > hard:
            v, note = "OVER", (f"> {hard}x — hard fail under §1.3 AFTER one documented "
                               "mitigation cycle. Whether that cycle has happened is a "
                               "human record, not a field here")
        else:
            v, note = "BAND", (f"between {floor}x and {hard}x — §1.3 makes this a "
                               "decision-log call: accept or mitigate")
        rows.append({"name": name, "axis": axis, "unit": unit, "baseline": b,
                     "candidate": c, "ratio": round(ratio, 4), "verdict": v,
                     "note": note})
        if rank[v] > rank[worst]:
            worst = v
    short = []
    for a, tag in ((base, "baseline"), (cand, "candidate")):
        f = a["fixture"]
        if f["height_reached"] < REFERENCE_HEIGHT:
            short.append(f"{tag} reached height {f['height_reached']} of §1.3's "
                         f"reference {REFERENCE_HEIGHT}")
        if not f["verify_exercised"].get("fcmp_pp"):
            short.append(f"{tag} exercised NO FCMP++ verification "
                         f"(tx_per_block={f.get('tx_per_block')})")
    return {"schema_version": "shekyl_drs_bench_compare_v1",
            "thresholds_frozen_at": FROZEN_AT, "baseline_engine": base["engine"],
            "candidate_engine": cand["engine"], "rows": rows, "verdict": worst,
            "fixture_shortfalls": short}


# ── the blocker probe: a deferral that cannot outlive its cause ─────────────

def blocker_failures():
    """FATAL when a PROBED follow-on's named blocker has stopped holding.

    Scoped to `rust/shekyl-chain-store/`, which is where DRS-E1 says the redb
    consensus engine grows. A workspace-wide grep would be wrong: redb is
    already a real engine in `rust/shekyl-curve-tree/src/store/redb_backend.rs`
    — the wallet's LeafStore, the very store DRS-D9 means by "not inherited
    from LeafStore silence" — and would fire this probe every run.
    """
    out = []
    if not os.path.isdir(CHAIN_STORE):
        return [f"{CHAIN_STORE} does not exist; this probe's subject is absent, which "
                "is the first evidence the probe is no longer reading anything"]
    engine_re = re.compile(r"redb::(Database|WriteTransaction|ReadTransaction)")
    hits, scanned = [], 0
    for dirpath, _, names in os.walk(CHAIN_STORE):
        if f"{os.sep}target{os.sep}" in dirpath + os.sep:
            continue
        for n in names:
            if not n.endswith(".rs"):
                continue
            scanned += 1
            p = os.path.join(dirpath, n)
            with open(p, encoding="utf-8") as fh:
                for i, line in enumerate(fh, 1):
                    if engine_re.search(line):
                        hits.append(f"{os.path.relpath(p, ROOT)}:{i}")
    if scanned == 0:
        out.append(f"scanned ZERO .rs files under {os.path.relpath(CHAIN_STORE, ROOT)} "
                   "— the probe's corpus is empty, so its green means nothing")
    if hits:
        out.append("the redb CONSENSUS engine now exists — " + ", ".join(hits[:8]) +
                   f" ({len(hits)} sites). The stage-one deferral of the redb arm was "
                   "blocked on its absence, and that blocker is gone: wire the redb "
                   "arm and the pop/reorg row, then remove this probe.")
    return out


# ── measurement ─────────────────────────────────────────────────────────────

def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _rpc(port, method, params=None, timeout=60):
    body = json.dumps({"jsonrpc": "2.0", "id": "0", "method": method,
                       "params": params or {}}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/json_rpc", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def hardware_fingerprint(path):
    cpu = ""
    with open("/proc/cpuinfo", encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    ram = 0
    with open("/proc/meminfo", encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("MemTotal:"):
                ram = int(line.split()[1]) * 1024
                break
    disk = "unknown"
    try:
        st = os.stat(path)
        maj, mnr = os.major(st.st_dev), os.minor(st.st_dev)
        rot = f"/sys/dev/block/{maj}:{mnr}/../queue/rotational"
        if os.path.exists(rot):
            with open(rot, encoding="utf-8") as fh:
                disk = "hdd" if fh.read().strip() == "1" else "ssd_or_nvme"
    except OSError:
        pass
    return {"cpu_model": cpu, "ram_bytes": ram, "disk_class": disk,
            "cpu_count": os.cpu_count()}


def _dir_bytes(path, apparent):
    """Total size of a directory tree: apparent file length, or allocated blocks."""
    args = ["du", "-s", "-b", path] if apparent else ["du", "-s", "-B1", path]
    return int(subprocess.run(args, check=True, capture_output=True,
                              text=True).stdout.split()[0])


def _peak_rss_bytes(pid):
    """VmHWM — the kernel's own high-water mark, read while the process lives.

    Chosen over `wait4`'s `ru_maxrss` because it can be sampled before the
    subject is asked to exit, and because it is the subject's OWN peak rather
    than an aggregate over every child this harness has spawned.
    """
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) * 1024
    except OSError:
        pass
    return None


def _wait_rpc(port, timeout):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            if _rpc(port, "get_info", timeout=5).get("result", {}).get("status") == "OK":
                return time.time()
        except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError):
            time.sleep(1)
    return None


def mining_address(timeout):
    """A current-format regtest mining address, minted by the canonical emitter.

    NOT read from `rust/shekyl-wire/tests/vectors/regtest_mining_recipients.json`.
    That committed vector holds the SAME key material at the pre-`msg_sign_pk`
    encoding and no longer decodes: `ShekylAddress::decode` reports
    `BadLength { segment: "classical", expected: 129, got: 81 }`, the 48-byte
    difference being the SLH-DSA-192s message-signing public key that became the
    fourth classical field. The C++ side rejects it identically, via
    `shekyl_address_decode` returning null ("Invalid Bech32m address format"), so
    `generateblocks` answers -4 "Failed to parse wallet address" and no chain can
    be generated from the committed fixture at all.

    The emitter named by that vector's own README is the source of truth, so this
    runs it rather than pinning a second copy of the address here — a pinned
    string would go stale on the next address-format change exactly as the vector
    did, and silently, because a stale address fails at generation time with an
    error that does not mention formats.
    """
    cmd = ["cargo", "test", "-q", "-p", "shekyl-wire", "--test", "emit_regtest_addr",
           "--", "--ignored", "--nocapture"]
    proc = subprocess.run(cmd, cwd=os.path.join(ROOT, "rust"), capture_output=True,
                          text=True, timeout=timeout)
    if proc.returncode != 0:
        _fail(f"the regtest address emitter failed (rc={proc.returncode}):\n"
              f"{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")
    hits = re.findall(r"^REGTEST_MINING_ADDR=(\S+)$", proc.stdout, re.M)
    # Rule 47: the emitter's exit status says the test passed, not that it
    # printed an address. A `--nocapture` print that stops printing leaves a
    # passing test and an empty match, and an empty address would reach the
    # daemon as a -4 parse error attributed to the wrong cause.
    if len(hits) != 1:
        _fail(f"expected exactly one REGTEST_MINING_ADDR line from the emitter, found "
              f"{len(hits)}. The emitter passed but did not report an address, so there "
              f"is nothing to mine to.\n{proc.stdout[-2000:]}")
    addr = hits[0]
    if addr.count("/") != 2 or not addr.startswith("shekyl1"):
        _fail(f"emitted address is not the expected three-segment form: {addr[:60]}...")
    return addr


def measure(args):
    """Run the LMDB IBD baseline and emit an artifact, or refuse.

    THREE PHASES, and the first two exist for one reason: `generateblocks` is
    gated on `check_core_ready()`, which requires the p2p payload to be
    synchronized, and a zero-peer daemon never becomes synchronized. The
    protocol handler initialises `m_synchronized(offline)`, so an `--offline`
    daemon is synchronized from birth and will generate. `--offline` also
    disables p2p, so the seed cannot serve in that state — hence generate
    offline, stop, restart networked over the SAME datadir, and only then
    measure the subject syncing from it. `--keep-fakechain` is load-bearing on
    every phase: without it the FAKECHAIN datadir is removed at startup and the
    restart would serve an empty chain.

    The subject is what the artifact describes. The seed is fixture.
    """
    if args.sync_mode not in ALLOWED_SYNC_MODES:
        _fail(f"--sync-mode={args.sync_mode!r} refused before any daemon was started. "
              f"Only {list(ALLOWED_SYNC_MODES)} satisfies DRS-D9, and the daemon accepts "
              "an unrecognised value by silently falling back to DBF_FAST (MDB_NOSYNC), "
              "so a typo here would measure the wrong durability and say nothing.")
    if not os.path.isfile(args.daemon):
        _fail(f"{args.daemon} is not a file — build the daemon in THIS worktree; a "
              "binary from another tree measures another tree")
    addr = mining_address(args.cargo_timeout)

    work = os.path.abspath(args.work_dir)
    os.makedirs(work, exist_ok=True)
    seed_dir = os.path.abspath(args.seed_dir or os.path.join(work, "seed"))
    subj_dir = os.path.join(work, "subject")
    # The SUBJECT is always wiped: it is the thing being measured and an IBD
    # that starts from a partial chain is a different experiment. The SEED is
    # fixture and is deliberately REUSED — at the reference height generation
    # costs many hours against an IBD measured in single hours, so regenerating
    # per run would dominate the harness, and a shared seed additionally gives
    # both engine arms a byte-identical fixture, which `check` demands.
    shutil.rmtree(subj_dir, ignore_errors=True)
    os.makedirs(subj_dir)
    os.makedirs(seed_dir, exist_ok=True)
    if args.fresh_seed:
        shutil.rmtree(seed_dir, ignore_errors=True)
        os.makedirs(seed_dir)

    common = ["--regtest", "--keep-fakechain", "--fixed-difficulty=1",
              f"--db-sync-mode={args.sync_mode}", "--allow-local-ip", "--no-igd",
              "--non-interactive", f"--log-level={args.log_level}"]
    sp2p, srpc = _free_port(), _free_port()
    bp2p, brpc = _free_port(), _free_port()

    def spawn(tag, d, argv_extra):
        argv = [args.daemon] + common + [f"--data-dir={d}", f"--p2p-bind-port=" +
                str(sp2p if tag == "seed" else bp2p),
                f"--rpc-bind-port=" + str(srpc if tag == "seed" else brpc)] + argv_extra
        log = open(os.path.join(work, f"{tag}.log"), "a", encoding="utf-8")
        return subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, cwd=d), argv

    # ── phase 1: generate the chain on an offline seed
    # Genesis alone is height 1, and N generated blocks leave height N+1, so the
    # target height for `--height N` is N+1.
    target_h = args.height + 1
    proc, _ = spawn("seed", seed_dir, ["--offline"])
    try:
        if _wait_rpc(srpc, args.startup_timeout) is None:
            _fail("seed RPC never came up")
        have_h = _rpc(srpc, "get_info")["result"]["height"]
        seed_reused = have_h > 1
        if have_h < target_h:
            r = _rpc(srpc, "generateblocks",
                     {"amount_of_blocks": target_h - have_h, "wallet_address": addr,
                      "starting_nonce": 0}, timeout=args.gen_timeout)
            st = r.get("result", {}).get("status")
            if st != "OK":
                _fail(f"generateblocks refused: status={st!r} "
                      f"({json.dumps(r)[:300]})")
        elif have_h > target_h:
            _fail(f"the seed at {seed_dir} already holds height {have_h}, past the "
                  f"requested {target_h}. Blocks cannot be un-generated without "
                  f"changing what is being measured; point --seed-dir elsewhere or "
                  f"pass --fresh-seed.")
        seed_h = _rpc(srpc, "get_info")["result"]["height"]
    finally:
        proc.terminate()
        proc.wait(args.shutdown_timeout)
    if seed_h != target_h:
        _fail(f"seed is at height {seed_h}, expected {target_h} — generation did not "
              "reach the requested height, so the fixture is not the one asked for")
    if seed_h <= 1:
        _fail(f"seed holds only height {seed_h}; nothing to sync")

    # ── phase 2: same datadir, networked, so it can serve
    proc, _ = spawn("seed", seed_dir, [])
    try:
        if _wait_rpc(srpc, args.startup_timeout) is None:
            _fail("networked seed RPC never came up")

        # ── phase 3: the subject, which is what we are measuring
        subj, subj_argv = spawn("subject", subj_dir,
                                [f"--add-exclusive-node=127.0.0.1:{sp2p}"])
        try:
            ready = _wait_rpc(brpc, args.startup_timeout)
            if ready is None:
                _fail("subject RPC never came up")
            # The denominator: from the subject answering RPC (so RandomX dataset
            # init and store open are EXCLUDED) to its height reaching the seed's.
            t0, reached, peak = ready, 0, 0
            deadline = t0 + args.sync_timeout
            while time.time() < deadline:
                try:
                    reached = _rpc(brpc, "get_info")["result"]["height"]
                except (urllib.error.URLError, OSError, json.JSONDecodeError,
                        TimeoutError):
                    time.sleep(1)
                    continue
                peak = max(peak, _peak_rss_bytes(subj.pid) or 0)
                if reached >= seed_h:
                    break
                time.sleep(args.poll_interval)
            elapsed = time.time() - t0
            peak = max(peak, _peak_rss_bytes(subj.pid) or 0)
            synced = reached >= seed_h
        finally:
            subj.terminate()
            subj.wait(args.shutdown_timeout)
        # AFTER the store is closed, never while the daemon holds it. A live LMDB
        # environment reported 40.7 MB for a 200-block chain that measured 1.43 MB
        # once closed — a ~28x overstatement. Whatever the transient is
        # (in-flight batch growth during sync), a figure that changes by that much
        # at shutdown is not a store size, and taking it while running would have
        # put an irreproducible number in a threshold-bearing artifact.
        store_bytes = _dir_bytes(subj_dir, apparent=False)
        store_apparent = _dir_bytes(subj_dir, apparent=True)
    finally:
        proc.terminate()
        proc.wait(args.shutdown_timeout)

    if not synced:
        _fail(f"subject reached height {reached} of {seed_h} in {elapsed:.1f}s and did "
              "not converge. A partial sync is not a shorter measurement of the same "
              "thing — it is a different experiment, so no artifact is written.")

    git_rev = subprocess.run(["git", "-C", ROOT, "rev-parse", "HEAD"], check=True,
                             capture_output=True, text=True).stdout.strip()
    scenario = "ibd_coinbase_only"
    artifact = {
        "schema_version": SCHEMA,
        "engine": args.engine,
        "git_rev": git_rev,
        "thresholds_frozen_at": FROZEN_AT,
        "durability": {
            "policy": "DRS-D9 full-fsync-per-commit",
            "sync_mode": args.sync_mode,
            "imposed_argv": subj_argv[1:],
            # Deliberately false, and validated as false: no readback exists.
            "observed": False,
            "readback_gap": "mdb_env_get_flags is in-process only and the daemon logs "
                            "no resolved sync mode; the mode was validated against an "
                            "allowed set before spawning and the argv is recorded "
                            "verbatim, which is not the same as observing the flags",
        },
        "hardware": hardware_fingerprint(subj_dir),
        "fixture": {
            "nettype": "fakechain",
            "height_reached": int(reached),
            "height_requested": int(args.height),
            "reference_height": REFERENCE_HEIGHT,
            "tx_per_block": 0,
            "verify_exercised": {
                "pow": True,
                "fcmp_pp": False,
            },
            "verify_note": "PoW longhash is computed and checked for every block with "
                           "no nettype bypass; --fixed-difficulty lowers the TARGET "
                           "only. generateblocks produces coinbase-only blocks, so "
                           "FCMP++ verification is not exercised at all.",
            "seed_height": int(seed_h),
            "seed_reused": bool(seed_reused),
        },
        "measures": [
            {"name": "ibd_wall_time_s", "axis": "wall_time", "unit": "s",
             "value": round(elapsed, 3), "scenario": scenario,
             "denominator": "subject's first successful get_info to height == seed "
                            "height; EXCLUDES process start, RandomX dataset init and "
                            "store open"},
            {"name": "peak_rss_bytes", "axis": "memory", "unit": "bytes",
             "value": int(peak), "scenario": scenario,
             "denominator": "subject VmHWM sampled during sync. NOT §7.4's "
                            "attacker-feed row, which has no definition yet"},
            {"name": "store_bytes", "axis": "disk", "unit": "bytes",
             "value": store_bytes, "scenario": scenario,
             "denominator": "filesystem-ALLOCATED bytes of the subject data dir, "
                            "measured after the store was closed. NOT §7.4's "
                            "multi-year row"},
            {"name": "store_bytes_apparent", "axis": "disk", "unit": "bytes",
             "value": store_apparent, "scenario": scenario,
             "denominator": "apparent (file-length) bytes of the same directory, same "
                            "moment; differs from the allocated figure only if the "
                            "engine leaves holes"},
        ],
    }
    refusals = artifact_refusals(artifact)
    if refusals:
        _fail("the harness produced an artifact it will not emit:\n  " +
              "\n  ".join(refusals))
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(artifact, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"wrote {args.out}: engine={args.engine} height_reached={reached} "
          f"{PRIMARY_MEASURE}={elapsed:.3f}s peak_rss={peak} "
          f"store={store_bytes} (apparent {store_apparent})")
    if reached < REFERENCE_HEIGHT:
        print(f"NOTE: height {reached} is below §1.3's reference {REFERENCE_HEIGHT}. "
              "§1.3 permits 'max available fixture; the artifact records the height it "
              "reached' — it is recorded, and the ratio is only valid against another "
              "artifact at the same height.")


# ── CLI ─────────────────────────────────────────────────────────────────────

def _load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main():
    ap = argparse.ArgumentParser(description="DRS-BENCH harness and IBD-floor gate")
    sub = ap.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("validate", help="refuse an artifact that is missing its "
                                        "measurement conditions")
    v.add_argument("artifact")

    c = sub.add_parser("check", help="route two artifacts through §1.3's frozen floor")
    c.add_argument("baseline")
    c.add_argument("candidate")
    c.add_argument("--json", action="store_true")

    sub.add_parser("blockers", help="FATAL if a deferred follow-on's blocker is gone")

    m = sub.add_parser("measure", help="run the IBD baseline and emit an artifact")
    m.add_argument("--engine", default="lmdb", choices=("lmdb", "redb"))
    m.add_argument("--height", type=int, default=REFERENCE_HEIGHT)
    m.add_argument("--out", required=True)
    m.add_argument("--daemon", default=os.path.join(ROOT, "build/bin/shekyld"))
    m.add_argument("--work-dir", required=True)
    m.add_argument("--sync-mode", default="safe")
    m.add_argument("--log-level", type=int, default=1)
    m.add_argument("--startup-timeout", type=float, default=300.0)
    m.add_argument("--gen-timeout", type=float, default=14400.0)
    m.add_argument("--sync-timeout", type=float, default=14400.0)
    m.add_argument("--shutdown-timeout", type=float, default=300.0)
    m.add_argument("--poll-interval", type=float, default=2.0)
    m.add_argument("--cargo-timeout", type=float, default=1800.0)
    m.add_argument("--seed-dir", default=None,
                   help="reusable seed chain (default: <work-dir>/seed). "
                        "Topped up to the requested height, never wiped "
                        "unless --fresh-seed.")
    m.add_argument("--fresh-seed", action="store_true",
                   help="discard the seed chain and regenerate it")

    args = ap.parse_args()

    if args.cmd == "validate":
        r = artifact_refusals(_load(args.artifact))
        if r:
            _fail(f"{args.artifact} is not a usable measurement:\n  " + "\n  ".join(r))
        print(f"{args.artifact}: usable")
        return

    if args.cmd == "blockers":
        f = blocker_failures()
        if f:
            _fail("a deferred follow-on's blocker no longer holds:\n  " +
                  "\n  ".join(f))
        probed = [k for k, (kind, _) in FOLLOWON_MEASURES.items() if kind == "PROBED"]
        print(f"blockers hold: {len(probed)} probed follow-on(s), "
              f"{len(FOLLOWON_MEASURES) - len(probed)} recorded at harness level")
        return

    if args.cmd == "check":
        base, cand = _load(args.baseline), _load(args.candidate)
        bad = []
        for path, a in ((args.baseline, base), (args.candidate, cand)):
            bad += [f"{path}: {x}" for x in artifact_refusals(a)]
        bad += comparability_refusals(base, cand)
        if bad:
            _fail("refusing to compute a §1.3 ratio:\n  " + "\n  ".join(bad))
        rep = compare(base, cand)
        if args.json:
            print(json.dumps(rep, indent=2, sort_keys=True))
        else:
            print(f"DRS-BENCH §1.3 floor — thresholds frozen at {rep['thresholds_frozen_at']}")
            print(f"  {rep['baseline_engine']} (baseline) vs {rep['candidate_engine']} "
                  f"(candidate)")
            for row in rep["rows"]:
                ratio = "n/a" if row["ratio"] is None else f"{row['ratio']:.4f}x"
                print(f"  [{row['verdict']:<13}] {row['name']:<18} {ratio:>10}  "
                      f"({row['axis']}) — {row['note']}")
            for s in rep["fixture_shortfalls"]:
                print(f"  SHORTFALL: {s}")
            print(f"  verdict: {rep['verdict']}")
        sys.exit(1 if rep["verdict"] == "OVER" else 0)

    if args.cmd == "measure":
        measure(args)


if __name__ == "__main__":
    main()
