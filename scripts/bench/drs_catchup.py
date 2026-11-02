#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The budget's catch-up harness mode (DAEMON_REDB_STORE.md §1.3a, PB-D2 and
# PB-D3; rule 7): a subject synced to a height stops, the seed advances a
# week, the subject resumes, and the time from its first answered get_info
# to the seed's tip is the row. The fsync probe runs beside the whole run
# and its window over the timed catch-up is recorded (rule 2). The artifact
# reports the proof-of-work share of the subject's CPU over that window
# (§1.3a.6 item 8), so a miss at a release cut names its cause.
#
# The share is read, not guessed: the replay tool connects the seed's chain
# under the production substrate and writes its per-hash timings. The share
# is the advanced blocks' hashes at that mean, over the subject's CPU
# seconds. One hash per block: the validator hashes each block once
# (CEN-D1/D2), so the count is the block count.
#
# The row names its load (§1.3a rule 4): PB-D2 is 30 transactions per block,
# PB-D3 is 4× that, each for the week's 5,040 blocks (PB-D2; the interval
# is 120 s). The harness counts `num_txes` on every advanced block and
# refuses a chain that is not the load the row names. The adversarial-block
# builder is a later piece; a coinbase-only chain fails here, loudly.
#
# Commands:
#   run    --daemon D --replay-bin R --work-dir W --height H --row PB-D2|PB-D3
#          --out F [--disk-class C]
#   --selftest

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

import drs_artifact as A  # noqa: E402
import drs_bench as B  # noqa: E402
import drs_regtest as R  # noqa: E402
import fsync_probe  # noqa: E402

SCHEMA = "shekyl_drs_catchup_v1"
HERE = os.path.dirname(os.path.abspath(__file__))

# §1.3a rule 4. The stress load is 4× the design load.
DESIGN_TX_PER_BLOCK = 30
STRESS_MULTIPLE = 4
STRESS_TX_PER_BLOCK = DESIGN_TX_PER_BLOCK * STRESS_MULTIPLE
# PB-D1 and PB-R3: the block interval. PB-D2 is one week of those blocks.
BLOCK_INTERVAL_S = 120
WEEK_S = 7 * 24 * 60 * 60
WEEK_BLOCKS = WEEK_S // BLOCK_INTERVAL_S
ROW_LOAD = {"PB-D2": DESIGN_TX_PER_BLOCK, "PB-D3": STRESS_TX_PER_BLOCK}


def one_load(counts):
    """The transaction count every advanced block carries, or None.

    A chain whose blocks do not share one count is not a named row.
    """
    if not counts:
        return None
    first = counts[0]
    if any(count != first for count in counts):
        return None
    return first


def pow_share(advanced_blocks, hash_ns_mean, subject_cpu_s):
    """The proof-of-work share of the subject's CPU over the catch-up: the
    advanced blocks' hashes at the replay tool's mean, over the subject's CPU
    seconds. None when either input is missing or the CPU figure is zero."""
    if hash_ns_mean is None or not subject_cpu_s or subject_cpu_s <= 0:
        return None
    pow_cpu_s = advanced_blocks * hash_ns_mean / 1e9
    return {"pow_cpu_s": round(pow_cpu_s, 3),
            "share_of_subject_cpu": round(pow_cpu_s / subject_cpu_s, 4),
            "hash_ns_mean": hash_ns_mean,
            "hashes": advanced_blocks}


def artifact_refusals(artifact):
    """Why this catch-up artifact is not a measurement. Empty == usable."""
    reasons = []
    if not isinstance(artifact, dict):
        return ["artifact is not a JSON object"]
    if artifact.get("schema_version") != SCHEMA:
        reasons.append(
            f"schema_version is {artifact.get('schema_version')!r}, expected {SCHEMA!r}")
    reasons.extend(A.probe_refusals(artifact.get("probe")))
    catchup = artifact.get("catchup")
    if not isinstance(catchup, dict):
        return reasons + ["catchup block absent"]
    for key in ("height_stopped", "blocks_advanced", "height_reached", "wall_s",
                "subject_cpu_s", "peak_rss_bytes", "tx_per_block"):
        if not isinstance(catchup.get(key), (int, float)):
            reasons.append(f"catchup.{key} is {catchup.get(key)!r}, not a number")
    if isinstance(catchup.get("blocks_advanced"), int) and catchup["blocks_advanced"] <= 0:
        reasons.append("catchup.blocks_advanced is not positive: nothing was caught up")
    if catchup.get("height_reached") is not None and catchup.get("height_stopped") is not None \
            and catchup.get("blocks_advanced") is not None \
            and catchup["height_reached"] != catchup["height_stopped"] + catchup["blocks_advanced"]:
        reasons.append("catchup.height_reached is not height_stopped + blocks_advanced: "
                       "the subject did not reach the seed's tip")
    row = artifact.get("row")
    load = ROW_LOAD.get(row)
    if load is None:
        reasons.append(f"row is {row!r}; PB-D2 and PB-D3 are the catch-up rows")
    else:
        if catchup.get("tx_per_block") != load:
            reasons.append(
                f"catchup.tx_per_block is {catchup.get('tx_per_block')!r}, not {row}'s "
                f"{load} (§1.3a rule 4)")
        if catchup.get("blocks_advanced") != WEEK_BLOCKS:
            reasons.append(
                f"catchup.blocks_advanced is {catchup.get('blocks_advanced')!r}, not a week "
                f"of {BLOCK_INTERVAL_S}s blocks ({WEEK_BLOCKS})")
    if "pow" not in artifact or artifact.get("pow") is None:
        reasons.append("pow share absent: PB-D2 and PB-D3 report the proof-of-work share "
                       "(§1.3a.6 item 8), and a run without it cannot name a miss's cause")
    elif not isinstance(artifact["pow"].get("share_of_subject_cpu"), (int, float)):
        reasons.append("pow.share_of_subject_cpu is not a number")
    if not isinstance(artifact.get("hardware"), dict):
        reasons.append("hardware block absent")
    if not A.is_hex64(artifact.get("subject_binary_sha256")):
        reasons.append("subject_binary_sha256 is not a sha-256")
    return reasons


def _metrics_pow(replay_bin, seed_rpc_port, work, tip_count):
    """The replay tool's mean light-mode hash over the seed's chain.

    The store is a file inside a directory. Removing the directory removes
    the file; removing the file's path as a directory does not.
    """
    corpus = os.path.join(work, "seed.corpus.e2")
    store_dir = os.path.join(work, "pow")
    shutil.rmtree(store_dir, ignore_errors=True)
    os.makedirs(store_dir)
    store = os.path.join(store_dir, "chain.db")
    trace = os.path.join(work, "pow.trace.e2")
    metrics = os.path.join(work, "pow.metrics.json")
    subprocess.run([replay_bin, "fetch", "--daemon", f"http://127.0.0.1:{seed_rpc_port}",
                    *R.REPLAY_CHAIN, "--from", "0", "--to", str(tip_count),
                    "--out", corpus], check=True, capture_output=True)
    subprocess.run([replay_bin, "baseline", "--corpus", corpus, "--store", store,
                    *R.REPLAY_CHAIN, "--out", trace, "--metrics-out", metrics],
                   check=True, capture_output=True)
    shutil.rmtree(store_dir, ignore_errors=True)
    with open(metrics, encoding="utf-8") as fh:
        return json.load(fh).get("hash_ns_mean")


def run(args):
    session = R.Session(args)
    work = session.work
    seed_dir = os.path.join(work, "seed")
    subj_dir = os.path.join(work, "subject")
    for directory in (seed_dir, subj_dir):
        shutil.rmtree(directory, ignore_errors=True)
        os.makedirs(directory)
    addr = B.mining_address(args.cargo_timeout)

    def sync_subject(target, timed):
        proc = session.spawn("subject", subj_dir,
                             ["--p2p-closed-peer", f"127.0.0.1:{session.sp2p}"],
                             session.bp2p, session.brpc)
        with session.running(proc, session.brpc) as subj:
            if not subj.ready:
                B._fail(f"subject never came up; see {work}/subject.log")
            t0 = subj.ready_at
            cpu0 = B._cpu_seconds(subj.pid)
            rss = []
            reached = 0
            deadline = t0 + args.sync_timeout
            while time.time() < deadline:
                try:
                    reached = B._rpc(session.brpc, "get_info")["result"]["height"]
                except (OSError, ValueError):
                    time.sleep(1)
                    continue
                peak = B._peak_rss_bytes(subj.pid)
                if peak is not None:
                    rss.append(peak)
                if reached >= target:
                    break
                time.sleep(args.poll_interval)
            elapsed = time.time() - t0
            cpu1 = B._cpu_seconds(subj.pid)
        if reached < target:
            B._fail(f"subject reached {reached} of {target}; no artifact for a partial run")
        if not timed:
            return None
        if cpu0 is None or cpu1 is None or not rss:
            B._fail("could not sample the subject's CPU or RSS from /proc")
        return {"t0": t0, "wall_s": round(elapsed, 3), "cpu_s": round(cpu1 - cpu0, 3),
                "peak_rss_bytes": max(rss)}

    probe_out = os.path.join(work, "probe.jsonl")
    open(probe_out, "w", encoding="utf-8").close()
    probe = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "fsync_probe.py"), "run",
         "--dir", os.path.join(work, "probe"), "--out", probe_out],
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        stopped_count = session.generate(seed_dir, args.height, addr)
        seed = session.spawn("seed", seed_dir, [], session.sp2p, session.srpc)
        with session.running(seed, session.srpc) as ready:
            if not ready.ready:
                B._fail("networked seed never came up")
            sync_subject(stopped_count, timed=False)
        tip_count = session.generate(seed_dir, WEEK_BLOCKS, addr)
        seed = session.spawn("seed", seed_dir, [], session.sp2p, session.srpc)
        with session.running(seed, session.srpc) as ready:
            if not ready.ready:
                B._fail("networked seed never came up")
            timed = sync_subject(tip_count, timed=True)
            load = one_load(session.tx_counts(session.srpc, stopped_count, tip_count - 1))
            hash_ns_mean = _metrics_pow(session.replay, session.srpc, work, tip_count)
    finally:
        probe.terminate()
        try:
            probe.wait(timeout=10)
        except subprocess.TimeoutExpired:
            probe.kill()
            probe.wait()

    if load is None:
        B._fail("the advanced blocks do not share one transaction count, so they are not "
                f"{args.row}; the adversarial-block builder is what puts that load on a chain")
    if load != ROW_LOAD[args.row]:
        B._fail(f"the advanced chain carries {load} transaction(s) per block, not "
                f"{args.row}'s {ROW_LOAD[args.row]} (§1.3a rule 4). A coinbase-only chain "
                "is not this row; the adversarial-block builder has not landed")
    advanced = tip_count - stopped_count
    if advanced != WEEK_BLOCKS:
        B._fail(f"the seed advanced {advanced} block(s), not a week ({WEEK_BLOCKS})")

    window = fsync_probe.window(fsync_probe.read(probe_out), timed["t0"],
                                timed["t0"] + timed["wall_s"])
    probe_block = fsync_probe.summary(window)
    probe_block["window_s"] = timed["wall_s"]
    artifact = {
        "schema_version": SCHEMA,
        "row": args.row,
        "git_rev": subprocess.run(["git", "-C", A.ROOT, "rev-parse", "HEAD"], check=True,
                                  capture_output=True, text=True).stdout.strip(),
        "subject_binary_sha256": B.binary_sha256(session.daemon),
        "hardware": A.hardware_fingerprint(subj_dir, args.disk_class),
        "catchup": {
            "height_stopped": stopped_count,
            "blocks_advanced": advanced,
            "height_reached": tip_count,
            "wall_s": timed["wall_s"],
            "subject_cpu_s": timed["cpu_s"],
            "peak_rss_bytes": timed["peak_rss_bytes"],
            "tx_per_block": load,
            "window": "the subject's first answered get_info after the restart to "
                      "height == the seed's tip; EXCLUDES process start and store open",
        },
        "pow": pow_share(advanced, hash_ns_mean, timed["cpu_s"]),
        "probe": probe_block,
    }
    refusals = artifact_refusals(artifact)
    if refusals:
        B._fail("the harness produced an artifact it will not emit:\n  " +
                "\n  ".join(refusals))
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(artifact, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"wrote {args.out}: {args.row} caught up {advanced} block(s) at {load} tx/block "
          f"in {timed['wall_s']} s, cpu {timed['cpu_s']} s, proof-of-work share "
          f"{artifact['pow']['share_of_subject_cpu']}, probe {probe_block['samples']} sample(s), "
          "no stall")


def _good():
    return {
        "schema_version": SCHEMA,
        "row": "PB-D2",
        "subject_binary_sha256": "ab" * 32,
        "hardware": {"cpu_model": "x"},
        "catchup": {"height_stopped": 100, "blocks_advanced": WEEK_BLOCKS,
                    "height_reached": 100 + WEEK_BLOCKS,
                    "wall_s": 10.0, "subject_cpu_s": 20.0, "peak_rss_bytes": 1 << 30,
                    "tx_per_block": DESIGN_TX_PER_BLOCK},
        "pow": pow_share(WEEK_BLOCKS, 1.25e9, 100.0),
        "probe": {"window_s": 10.0, "samples": 10, "stalls": 0},
    }


def _selftest():
    fails = []

    def check(name, got, want):
        check.names.append(name)
        if got != want:
            fails.append(f"{name}: got {got!r}, want {want!r}")

    check.names = []
    good = _good()
    check("the control is accepted", artifact_refusals(good), [])
    check("the share is the hashes over the CPU",
          pow_share(50, 1.25e9, 100.0)["share_of_subject_cpu"], 0.625)
    check("a week of 120s blocks is 5040", WEEK_BLOCKS, 5040)
    check("stress is four times the design load", STRESS_TX_PER_BLOCK, 120)
    bad = json.loads(json.dumps(good))
    bad["pow"] = None
    check("a null pow share is refused",
          any("pow share absent" in reason for reason in artifact_refusals(bad)), True)
    bad = json.loads(json.dumps(good))
    bad.pop("pow")
    check("no pow block is refused",
          any("pow share absent" in reason for reason in artifact_refusals(bad)), True)
    bad = json.loads(json.dumps(good))
    bad["catchup"]["height_reached"] = bad["catchup"]["height_stopped"] + WEEK_BLOCKS - 1
    check("a short catch-up is refused",
          any("did not reach" in reason for reason in artifact_refusals(bad)), True)
    bad = json.loads(json.dumps(good))
    bad["probe"]["stalls"] = 1
    check("a probe stall is refused",
          any("does not count" in reason for reason in artifact_refusals(bad)), True)
    bad = json.loads(json.dumps(good))
    bad["catchup"]["blocks_advanced"] = 0
    bad["catchup"]["height_reached"] = 100
    check("nothing advanced is refused",
          any("not positive" in reason for reason in artifact_refusals(bad)), True)
    bad = json.loads(json.dumps(good))
    bad["catchup"]["tx_per_block"] = 0
    check("a coinbase-only chain is not the design load",
          any("tx_per_block" in reason for reason in artifact_refusals(bad)), True)
    bad = json.loads(json.dumps(good))
    bad["row"] = "PB-D3"
    check("the stress row refuses the design load",
          any("PB-D3" in reason for reason in artifact_refusals(bad)), True)
    bad = json.loads(json.dumps(good))
    bad["catchup"]["blocks_advanced"] = WEEK_BLOCKS - 1
    bad["catchup"]["height_reached"] = 100 + WEEK_BLOCKS - 1
    check("a short week is refused",
          any("not a week" in reason for reason in artifact_refusals(bad)), True)
    check("one count is that count", one_load([30, 30, 30]), 30)
    check("mixed counts are not a row", one_load([30, 0]), None)
    check("no blocks are not a row", one_load([]), None)
    if fails:
        for failure in fails:
            print("FAIL", failure, file=sys.stderr)
        sys.exit(1)
    print(f"catch-up harness selftest: {len(check.names)} cases OK")


def main(argv=None):
    ap = argparse.ArgumentParser(description="The budget's catch-up mode (PB-D2, PB-D3)")
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    run_cmd = sub.add_parser("run")
    run_cmd.add_argument("--daemon", required=True)
    run_cmd.add_argument("--replay-bin", required=True,
                         help="shekyl-chain-replay, for the proof-of-work share")
    run_cmd.add_argument("--work-dir", required=True)
    run_cmd.add_argument("--height", type=int, required=True, help="blocks before the stop")
    run_cmd.add_argument("--row", required=True, choices=sorted(ROW_LOAD),
                         help="PB-D2 is the design load; PB-D3 is the stress load")
    run_cmd.add_argument("--out", required=True)
    run_cmd.add_argument("--disk-class", choices=A.ALLOWED_DISK_CLASSES, default=None)
    run_cmd.add_argument("--cargo-timeout", type=int, default=1800)
    run_cmd.add_argument("--startup-timeout", type=int, default=600)
    run_cmd.add_argument("--shutdown-timeout", type=int, default=120)
    run_cmd.add_argument("--gen-timeout", type=int, default=86400)
    run_cmd.add_argument("--sync-timeout", type=int, default=86400)
    run_cmd.add_argument("--poll-interval", type=float, default=0.5)
    args = ap.parse_args(argv)
    if args.selftest:
        _selftest()
    elif args.cmd == "run":
        run(args)
    else:
        ap.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
