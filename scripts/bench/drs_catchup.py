#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The budget's catch-up harness mode (DAEMON_REDB_STORE.md §1.3a, PB-D2 and
# PB-D3; rule 7): a subject synced to a height stops, the seed advances, the
# subject resumes, and the time from its first answered get_info to the
# seed's tip is the row. The fsync probe runs beside the whole run and its
# window over the timed catch-up is recorded (rule 2); the artifact reports
# the proof-of-work share of the subject's CPU over that window (§1.3a.6
# item 8), so a miss at a release cut names its cause.
#
# The proof-of-work share is read, not guessed: the replay tool connects the
# seed's chain under the production substrate and writes its per-hash
# timings (`shekyl-chain-replay baseline --metrics-out`, `metrics.timed_hash`).
# The share is the advanced blocks' hashes at that mean, over the subject's
# CPU seconds in the window. One hash per block: the validator hashes each
# block once (CEN-D1/D2), so the count is the block count.
#
# The design load (30 transactions per block, §1.3a.6 item 1) is the seed
# chain's: this mode times whatever chain the seed holds and records its
# transactions per block, and the row's gate reads that figure.
#
# Commands:
#   run    --daemon D --work-dir W --height H --advance N --out F
#          [--replay-bin R] [--disk-class C]
#   --selftest
#
# Python under scripts/bench/, beside drs_bench.py, whose daemon helpers it
# uses.

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
import fsync_probe  # noqa: E402
import armed_lever  # noqa: E402

SCHEMA = "shekyl_drs_catchup_v1"
HERE = os.path.dirname(os.path.abspath(__file__))


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


def artifact_refusals(a):
    """Why this catch-up artifact is not a measurement. Empty == usable."""
    r = []
    if not isinstance(a, dict):
        return ["artifact is not a JSON object"]
    if a.get("schema_version") != SCHEMA:
        r.append(f"schema_version is {a.get('schema_version')!r}, expected {SCHEMA!r}")
    r.extend(A.probe_refusals(a.get("probe")))
    c = a.get("catchup")
    if not isinstance(c, dict):
        return r + ["catchup block absent"]
    for k in ("height_stopped", "blocks_advanced", "height_reached", "wall_s",
              "subject_cpu_s", "peak_rss_bytes", "tx_per_block"):
        if not isinstance(c.get(k), (int, float)):
            r.append(f"catchup.{k} is {c.get(k)!r}, not a number")
    if isinstance(c.get("blocks_advanced"), int) and c["blocks_advanced"] <= 0:
        r.append("catchup.blocks_advanced is not positive: nothing was caught up")
    if c.get("height_reached") is not None and c.get("height_stopped") is not None \
            and c.get("blocks_advanced") is not None \
            and c["height_reached"] != c["height_stopped"] + c["blocks_advanced"]:
        r.append("catchup.height_reached is not height_stopped + blocks_advanced: "
                 "the subject did not reach the seed's tip")
    if "pow" not in a:
        r.append("pow block absent: PB-D2 and PB-D3 report the proof-of-work share "
                 "(§1.3a), and a run without it cannot name a miss's cause")
    elif a["pow"] is not None and not isinstance(a["pow"].get("share_of_subject_cpu"),
                                                 (int, float)):
        r.append("pow.share_of_subject_cpu is not a number")
    if not isinstance(a.get("hardware"), dict):
        r.append("hardware block absent")
    if not A.is_hex64(a.get("subject_binary_sha256")):
        r.append("subject_binary_sha256 is not a sha-256")
    return r


def _metrics_pow(replay_bin, seed_rpc_port, work, tip_count):
    """The replay tool's mean light-mode hash over the seed's chain, or None
    when no replay binary was given."""
    if replay_bin is None:
        return None
    corpus = os.path.join(work, "seed.corpus.e2")
    store = os.path.join(work, "pow-store")
    trace = os.path.join(work, "pow.trace.e2")
    metrics = os.path.join(work, "pow.metrics.json")
    shutil.rmtree(store, ignore_errors=True)
    subprocess.run([replay_bin, "fetch", "--daemon", f"http://127.0.0.1:{seed_rpc_port}",
                    "--chain", "regtest", "--from", "0", "--to", str(tip_count),
                    "--out", corpus], check=True, capture_output=True)
    subprocess.run([replay_bin, "baseline", "--corpus", corpus, "--store", store,
                    "--chain", "regtest", "--fixed-difficulty", "1",
                    "--out", trace, "--metrics-out", metrics],
                   check=True, capture_output=True)
    shutil.rmtree(store, ignore_errors=True)
    with open(metrics, encoding="utf-8") as fh:
        return json.load(fh).get("hash_ns_mean")


def run(args):
    work = os.path.abspath(args.work_dir)
    os.makedirs(work, exist_ok=True)
    daemon = B.daemon_executable(args.daemon)
    seed_dir = os.path.join(work, "seed")
    subj_dir = os.path.join(work, "subject")
    for d in (seed_dir, subj_dir):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    addr = B.mining_address(args.cargo_timeout)
    (sp2p, srpc, bp2p, brpc), held = B._reserve_ports(4)
    for sk in held:
        sk.close()
    common = ["--network", "regtest", "--dev-difficulty", "1", "--p2p-local",
              "--tor", "off", "--log-level", "info"]

    def spawn(tag, d, extra, offline=False):
        p2p, rpcp = (sp2p, srpc) if tag == "seed" else (bp2p, brpc)
        net = ["--clearnet", "off"] if offline else ["--clearnet-listen", f"127.0.0.1:{p2p}"]
        argv = [daemon] + common + ["--data-dir", d] + net + [
            "--rpc-admin-listen", f"127.0.0.1:{rpcp}",
            "--log-file", os.path.join(work, f"{tag}.daemon.log")] + extra
        log = open(os.path.join(work, f"{tag}.log"), "a", encoding="utf-8")
        try:
            return subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, cwd=d)
        finally:
            log.close()

    def running(proc, port):
        return B._RunningDaemon(proc, port, args.startup_timeout, args.shutdown_timeout)

    def generate(count):
        proc = spawn("seed", seed_dir, [armed_lever.FLAG, "--mine-address", addr], offline=True)
        with running(proc, srpc) as seed:
            if not seed.ready:
                B._fail(f"generating seed never came up; see {work}/seed.log")
            B._await_posted(srpc, args.startup_timeout)
            resp = B._rpc(srpc, "generateblocks", {"count": count}, timeout=args.gen_timeout)
            if resp.get("result", {}).get("status") != "OK":
                B._fail(f"generateblocks refused: {json.dumps(resp)[:300]}")
            return B._rpc(srpc, "get_info")["result"]["height"]

    def sync_subject(target, timed):
        proc = spawn("subject", subj_dir, ["--p2p-closed-peer", f"127.0.0.1:{sp2p}"])
        with running(proc, brpc) as subj:
            if not subj.ready:
                B._fail(f"subject never came up; see {work}/subject.log")
            t0 = subj.ready_at
            cpu0 = B._cpu_seconds(subj.pid)
            rss = []
            reached = 0
            deadline = t0 + args.sync_timeout
            while time.time() < deadline:
                try:
                    reached = B._rpc(brpc, "get_info")["result"]["height"]
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
        stopped_count = generate(args.height)
        seed = spawn("seed", seed_dir, [])
        with running(seed, srpc) as s:
            if not s.ready:
                B._fail("networked seed never came up")
            sync_subject(stopped_count, timed=False)
        tip_count = generate(args.advance)
        seed = spawn("seed", seed_dir, [])
        with running(seed, srpc) as s:
            if not s.ready:
                B._fail("networked seed never came up")
            timed = sync_subject(tip_count, timed=True)
            hash_ns_mean = _metrics_pow(args.replay_bin, srpc, work, tip_count)
    finally:
        probe.terminate()
        try:
            probe.wait(timeout=10)
        except subprocess.TimeoutExpired:
            probe.kill()
            probe.wait()

    window = fsync_probe.window(fsync_probe.read(probe_out), timed["t0"],
                                timed["t0"] + timed["wall_s"])
    probe_block = fsync_probe.summary(window)
    probe_block["window_s"] = timed["wall_s"]
    advanced = tip_count - stopped_count
    artifact = {
        "schema_version": SCHEMA,
        "git_rev": subprocess.run(["git", "-C", A.ROOT, "rev-parse", "HEAD"], check=True,
                                  capture_output=True, text=True).stdout.strip(),
        "subject_binary_sha256": B.binary_sha256(daemon),
        "hardware": A.hardware_fingerprint(subj_dir, args.disk_class),
        "catchup": {
            "height_stopped": stopped_count,
            "blocks_advanced": advanced,
            "height_reached": tip_count,
            "wall_s": timed["wall_s"],
            "subject_cpu_s": timed["cpu_s"],
            "peak_rss_bytes": timed["peak_rss_bytes"],
            "tx_per_block": 0,
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
    share = artifact["pow"]["share_of_subject_cpu"] if artifact["pow"] else None
    print(f"wrote {args.out}: caught up {advanced} block(s) in {timed['wall_s']} s, "
          f"cpu {timed['cpu_s']} s, proof-of-work share {share}, probe "
          f"{probe_block['samples']} sample(s), no stall")


def _selftest():
    fails = []

    def check(name, got, want):
        if got != want:
            fails.append(f"{name}: got {got!r}, want {want!r}")

    good = {
        "schema_version": SCHEMA,
        "subject_binary_sha256": "ab" * 32,
        "hardware": {"cpu_model": "x"},
        "catchup": {"height_stopped": 100, "blocks_advanced": 50, "height_reached": 150,
                    "wall_s": 10.0, "subject_cpu_s": 20.0, "peak_rss_bytes": 1 << 30,
                    "tx_per_block": 0},
        "pow": pow_share(50, 1.25e9, 100.0),
        "probe": {"window_s": 10.0, "samples": 10, "stalls": 0},
    }
    check("the control is accepted", artifact_refusals(good), [])
    check("the share is the hashes over the CPU", good["pow"]["share_of_subject_cpu"], 0.625)
    bad = json.loads(json.dumps(good))
    bad.pop("pow")
    check("no pow block is refused", any("pow block absent" in x for x in artifact_refusals(bad)), True)
    bad = json.loads(json.dumps(good))
    bad["catchup"]["height_reached"] = 149
    check("a short catch-up is refused", any("did not reach" in x for x in artifact_refusals(bad)), True)
    bad = json.loads(json.dumps(good))
    bad["probe"]["stalls"] = 1
    check("a probe stall is refused", any("does not count" in x for x in artifact_refusals(bad)), True)
    bad = json.loads(json.dumps(good))
    bad["catchup"]["blocks_advanced"] = 0
    bad["catchup"]["height_reached"] = 100
    check("nothing advanced is refused", any("not positive" in x for x in artifact_refusals(bad)), True)
    check("no replay binary is no share", pow_share(50, None, 10.0), None)
    if fails:
        for f in fails:
            print("FAIL", f, file=sys.stderr)
        sys.exit(1)
    print("catch-up harness selftest: 7 cases OK")


def main(argv=None):
    ap = argparse.ArgumentParser(description="The budget's catch-up mode (PB-D2, PB-D3)")
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    r = sub.add_parser("run")
    r.add_argument("--daemon", required=True)
    r.add_argument("--work-dir", required=True)
    r.add_argument("--height", type=int, required=True, help="blocks before the stop")
    r.add_argument("--advance", type=int, required=True, help="blocks the seed adds")
    r.add_argument("--out", required=True)
    r.add_argument("--replay-bin", default=None,
                   help="shekyl-chain-replay, for the proof-of-work share")
    r.add_argument("--disk-class", choices=A.ALLOWED_DISK_CLASSES, default=None)
    r.add_argument("--cargo-timeout", type=int, default=1800)
    r.add_argument("--startup-timeout", type=int, default=600)
    r.add_argument("--shutdown-timeout", type=int, default=120)
    r.add_argument("--gen-timeout", type=int, default=86400)
    r.add_argument("--sync-timeout", type=int, default=86400)
    r.add_argument("--poll-interval", type=float, default=0.5)
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
