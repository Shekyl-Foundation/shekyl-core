#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The budget's process-crash harness (DAEMON_REDB_STORE.md §1.3a, PB-S1;
# rule 7): SIGKILL trials at random points, each reopened and judged.
#
# A trial passes when every operation the daemon acknowledged before the
# kill survives the reopen, and the reopened chain's logical-state digest
# equals a clean replay of the same chain to the reopened tip. The harness
# records each acknowledgement as it arrives: a tip the subject's get_info
# published (its height, polled), so the reopened tip must be at or above
# the last one seen. The clean replay is `shekyl-chain-replay baseline`
# over the seed's chain fetched to that tip, and the reopened side is
# `shekyl-chain-replay digest` over the subject's store; both read the same
# digest function, so a difference is the crash's.
#
# Scenarios, round-robin over the trials:
#   sync    a fresh subject syncs from the seed and is killed mid-sync,
#           so the kill lands in a connect's commit at some trial;
#   idle    a synced subject is killed at its tip;
#   switch  a subject on one fork meets a heavier one and is killed while
#           it pops and replays.
# PB-S1's fourth point, a pool commit, needs a submitted transaction the
# bench cannot yet build; the artifact names the scenarios it ran, and the
# row's gate reads them.
#
# Commands:
#   run    --daemon D --replay-bin R --work-dir W --height H --trials N --out F
#   --selftest

from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import time

import drs_artifact as A  # noqa: E402
import drs_bench as B  # noqa: E402
import armed_lever  # noqa: E402

SCHEMA = "shekyl_drs_crash_v1"
SCENARIOS = ("sync", "idle", "switch")
# PB-S1's floor on the trial count.
MIN_TRIALS = 200
# The regtest seed runs the production schedule pair; the replay's levers
# must name the same pair or the store refuses the first block.
LEVERS = ["--chain", "regtest", "--fixed-difficulty", "1",
          "--settlement-epoch-blocks", "10000", "--reorg-cap", "720"]


def judge(trial):
    """Why a trial failed, or None. A trial records the last acknowledged
    tip, the reopened tip, and the two digests."""
    acked, reopened = trial.get("acked_tip"), trial.get("reopened_tip")
    if reopened is None:
        return "the reopened store has no tip"
    if trial.get("chain") is None:
        return (f"the reopened tip {reopened} ({trial.get('hash')}) is on neither the main "
                "chain nor the fork: a block no serving daemon held was recorded")
    if trial.get("expected_digest") is None:
        return f"no clean replay of the {trial['chain']} chain to {reopened} was available"
    if acked is not None and reopened < acked:
        return (f"the daemon published tip {acked} before the kill and reopened at "
                f"{reopened}: an acknowledged connect was lost")
    if trial.get("digest") != trial.get("expected_digest"):
        return (f"the reopened chain's digest at {reopened} is not a clean replay's: "
                "a write survived torn or a committed one was lost")
    return None


def artifact_refusals(a):
    r = []
    if not isinstance(a, dict):
        return ["artifact is not a JSON object"]
    if a.get("schema_version") != SCHEMA:
        r.append(f"schema_version is {a.get('schema_version')!r}, expected {SCHEMA!r}")
    trials = a.get("trials")
    if not isinstance(trials, list) or not trials:
        return r + ["no trials"]
    for t in trials:
        why = judge(t)
        if why:
            r.append(f"trial {t.get('index')} ({t.get('scenario')}): {why}")
    ran = sorted({t.get("scenario") for t in trials})
    if a.get("scenarios") != ran:
        r.append(f"scenarios is {a.get('scenarios')!r} but the trials ran {ran!r}")
    if not A.is_hex64(a.get("subject_binary_sha256")):
        r.append("subject_binary_sha256 is not a sha-256")
    return r


def gate_refusals(a):
    """Why the run is not PB-S1's verdict: under the floor's trial count, or a
    scenario PB-S1 names that the run did not reach. Separate from
    `artifact_refusals`: a short run is a valid record and not a pass."""
    r = []
    trials = a.get("trials") or []
    if len(trials) < MIN_TRIALS:
        r.append(f"{len(trials)} trial(s), under PB-S1's {MIN_TRIALS}")
    missing = [s for s in SCENARIOS + ("pool",) if s not in (a.get("scenarios") or [])]
    if missing:
        r.append(f"PB-S1's points not reached: {missing}")
    return r


class Harness:
    def __init__(self, args):
        self.args = args
        self.work = os.path.abspath(args.work_dir)
        os.makedirs(self.work, exist_ok=True)
        self.daemon = B.daemon_executable(args.daemon)
        self.replay = os.path.abspath(args.replay_bin)
        self.addr = B.mining_address(args.cargo_timeout)
        (self.sp2p, self.srpc, self.fp2p, self.frpc, self.bp2p, self.brpc), held = \
            B._reserve_ports(6)
        for sk in held:
            sk.close()
        self.expected = {}
        # Each chain's block hash per height, from the fork point up: a
        # reopened tip is judged against the chain its hash is on.
        self.hashes = {"main": {}, "fork": {}}
        self.prefix = None

    def spawn(self, tag, d, extra, p2p, rpc, offline=False):
        common = ["--network", "regtest", "--dev-difficulty", "1", "--p2p-local",
                  "--tor", "off", "--log-level", "info"]
        net = ["--clearnet", "off"] if offline else ["--clearnet-listen", f"127.0.0.1:{p2p}"]
        argv = [self.daemon] + common + ["--data-dir", d] + net + [
            "--rpc-admin-listen", f"127.0.0.1:{rpc}",
            "--log-file", os.path.join(self.work, f"{tag}.daemon.log")] + extra
        log = open(os.path.join(self.work, f"{tag}.log"), "a", encoding="utf-8")
        try:
            return subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, cwd=d)
        finally:
            log.close()

    def running(self, proc, rpc):
        return B._RunningDaemon(proc, rpc, self.args.startup_timeout, self.args.shutdown_timeout)

    def generate(self, d, count, address):
        proc = self.spawn("gen", d, [armed_lever.FLAG, "--mine-address", address],
                          self.sp2p, self.srpc, offline=True)
        with self.running(proc, self.srpc) as g:
            if not g.ready:
                B._fail(f"a generating daemon never came up; see {self.work}/gen.log")
            B._await_posted(self.srpc, self.args.startup_timeout)
            resp = B._rpc(self.srpc, "generateblocks", {"count": count}, timeout=86400)
            if resp.get("result", {}).get("status") != "OK":
                B._fail(f"generateblocks refused: {json.dumps(resp)[:300]}")
            return B._rpc(self.srpc, "get_info")["result"]["height"]

    def expected_digest(self, seed_rpc, chain_key, tip):
        """A clean replay's digest of the serving seed's chain at `tip`,
        cached per chain and tip."""
        key = (chain_key, tip)
        if key not in self.expected:
            d = os.path.join(self.work, f"expected-{chain_key}-{tip}")
            shutil.rmtree(d, ignore_errors=True)
            os.makedirs(d)
            corpus = os.path.join(d, "corpus.e2")
            subprocess.run([self.replay, "fetch", "--daemon", f"http://127.0.0.1:{seed_rpc}",
                            "--chain", "regtest", "--from", "0", "--to", str(tip + 1),
                            "--out", corpus], check=True, capture_output=True)
            store = os.path.join(d, "store")
            subprocess.run([self.replay, "baseline", "--corpus", corpus, "--store", store,
                            *LEVERS, "--out", os.path.join(d, "trace.e2")],
                           check=True, capture_output=True)
            self.expected[key] = self.store_digest(store)["digest"]
            shutil.rmtree(d, ignore_errors=True)
        return self.expected[key]

    def store_digest(self, store):
        out = subprocess.run([self.replay, "digest", "--store", store, *LEVERS],
                             check=True, capture_output=True, text=True).stdout
        return json.loads(out)

    def record_hashes(self, chain_key, rpc, top):
        for h in range(self.prefix, top + 1):
            hdr = B._rpc(rpc, "get_block_header_by_height", {"height": h})
            self.hashes[chain_key][h] = hdr["result"]["block_header"]["hash"]

    def chain_of(self, tip, tip_hash):
        """Which chain a reopened tip is on: below the fork point both are
        one chain, the main chain's; above it, the one holding that hash."""
        if tip < self.prefix:
            return "main"
        for key, hashes in self.hashes.items():
            if hashes.get(tip) == tip_hash:
                return key
        return None

    def trial(self, scenario, subj_dir, seed_rpc, seed_p2p, chain_key, kill_after):
        """Start the subject toward the seed, kill it after `kill_after`
        seconds of answered RPC, reopen it offline, and judge it against the
        chain its reopened tip is on. `chain_key` names the serving chain,
        whose clean replays can still be computed; the other's come from the
        cache filled while it served."""
        proc = self.spawn("subject", subj_dir, ["--p2p-closed-peer", f"127.0.0.1:{seed_p2p}"],
                          self.bp2p, self.brpc)
        acked = None
        t0 = None
        deadline = time.time() + self.args.startup_timeout
        while time.time() < deadline:
            if proc.poll() is not None:
                B._fail(f"the subject exited before the kill; see {self.work}/subject.log")
            try:
                h = B._rpc(self.brpc, "get_info", timeout=2)["result"]["height"]
                acked = h - 1 if acked is None else max(acked, h - 1)
                t0 = t0 or time.time()
            except (OSError, ValueError, KeyError):
                pass
            if t0 is not None and time.time() - t0 >= kill_after:
                break
            time.sleep(0.02)
        proc.kill()
        proc.wait()
        reopen = self.spawn("reopen", subj_dir, [], self.bp2p, self.brpc, offline=True)
        with self.running(reopen, self.brpc) as r:
            if not r.ready:
                return {"scenario": scenario, "kill_after_s": kill_after, "acked_tip": acked,
                        "reopened_tip": None, "error": "the reopened daemon never came up"}
        got = self.store_digest(os.path.join(subj_dir, "chain.db"))
        tip = got["tip"]
        on = None if tip is None else self.chain_of(tip, got["hash"])
        if on is None:
            expected = None
        elif on == chain_key:
            expected = self.expected_digest(seed_rpc, chain_key, tip)
        else:
            expected = self.expected.get((on, tip))
        return {"scenario": scenario, "kill_after_s": round(kill_after, 3), "acked_tip": acked,
                "reopened_tip": tip, "hash": got["hash"], "chain": on, "digest": got["digest"],
                "expected_digest": expected}

    def run(self):
        a = self.args
        rng = random.Random(a.seed)
        seed_dir = os.path.join(self.work, "seed")
        fork_dir = os.path.join(self.work, "fork")
        for d in (seed_dir, fork_dir):
            shutil.rmtree(d, ignore_errors=True)
            os.makedirs(d)
        # The main chain, and a heavier fork of it from `fork_depth` below
        # its tip: the fork's daemon starts from a copy of the main chain's
        # prefix and mines past it to another address.
        prefix = a.height - a.fork_depth
        self.prefix = prefix
        self.generate(seed_dir, prefix, self.addr)
        shutil.rmtree(fork_dir)
        shutil.copytree(seed_dir, fork_dir)
        main_tip = self.generate(seed_dir, a.fork_depth, self.addr) - 1
        fork_tip = self.generate(fork_dir, a.fork_depth + 2, a.fork_address or self.addr) - 1
        synced = os.path.join(self.work, "synced-main")
        trials = []
        # Two thirds of the trials against the main chain's seed alone, the
        # rest against the fork's daemon alone: the two never serve at once,
        # so neither can reorganise the other.
        plan = [SCENARIOS[i % len(SCENARIOS)] for i in range(a.trials)]

        def record(t, i):
            t["index"] = i
            t["verdict"] = judge(t) or "pass"
            trials.append(t)
            print(f"trial {i} {t['scenario']}: acked {t['acked_tip']} reopened "
                  f"{t['reopened_tip']} -> {t['verdict']}", flush=True)

        def fresh(subj, from_dir=None):
            shutil.rmtree(subj, ignore_errors=True)
            if from_dir is None:
                os.makedirs(subj)
            else:
                shutil.copytree(from_dir, subj)

        subj = os.path.join(self.work, "subject")
        seed = self.spawn("seed", seed_dir, [], self.sp2p, self.srpc)
        with self.running(seed, self.srpc) as s:
            if not s.ready:
                B._fail("the main chain's seed never came up")
            self.record_hashes("main", self.srpc, main_tip)
            fresh(synced)
            prepared = self.trial("prepare", synced, self.srpc, self.sp2p, "main",
                                  kill_after=a.sync_estimate)
            if prepared["reopened_tip"] != main_tip:
                B._fail(f"the preparing sync reached {prepared['reopened_tip']}, not "
                        f"{main_tip}; raise --sync-estimate")
            # A crash mid-switch can reopen anywhere on the main chain from
            # the fork point up, after its seed has stopped serving: those
            # clean replays are taken now.
            for h in range(prefix - 1, main_tip + 1):
                self.expected_digest(self.srpc, "main", h)
            for i, scenario in enumerate(plan):
                if scenario == "sync":
                    fresh(subj)
                    record(self.trial("sync", subj, self.srpc, self.sp2p, "main",
                                      rng.uniform(0.0, a.sync_estimate)), i)
                elif scenario == "idle":
                    fresh(subj, synced)
                    record(self.trial("idle", subj, self.srpc, self.sp2p, "main",
                                      rng.uniform(0.0, 3.0)), i)
        fork = self.spawn("fork", fork_dir, [], self.fp2p, self.frpc)
        with self.running(fork, self.frpc) as f:
            if not f.ready:
                B._fail("the fork's daemon never came up")
            self.record_hashes("fork", self.frpc, fork_tip)
            for i, scenario in enumerate(plan):
                if scenario == "switch":
                    fresh(subj, synced)
                    record(self.trial("switch", subj, self.frpc, self.fp2p, "fork",
                                      rng.uniform(0.0, a.switch_estimate)), i)
        artifact = {
            "schema_version": SCHEMA,
            "git_rev": subprocess.run(["git", "-C", A.ROOT, "rev-parse", "HEAD"], check=True,
                                      capture_output=True, text=True).stdout.strip(),
            "subject_binary_sha256": B.binary_sha256(self.daemon),
            "hardware": A.hardware_fingerprint(self.work, a.disk_class),
            "chain": {"main_tip": main_tip, "fork_tip": fork_tip, "fork_depth": a.fork_depth},
            "seed": a.seed,
            "scenarios": sorted({t["scenario"] for t in trials}),
            "trials": trials,
        }
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(artifact, fh, indent=2, sort_keys=True)
            fh.write("\n")
        refusals = artifact_refusals(artifact)
        gate = gate_refusals(artifact)
        print(f"wrote {a.out}: {len(trials)} trial(s), "
              f"{sum(1 for t in trials if t['verdict'] == 'pass')} passed")
        for x in refusals:
            print("FAIL", x)
        for x in gate:
            print("NOT PB-S1:", x)
        sys.exit(1 if refusals else 0)


def _selftest():
    fails = []

    def check(name, got, want):
        if got != want:
            fails.append(f"{name}: got {got!r}, want {want!r}")

    ok = {"acked_tip": 10, "reopened_tip": 10, "chain": "main", "digest": "a" * 64,
          "expected_digest": "a" * 64}
    check("an intact reopen passes", judge(ok), None)
    check("a lost acknowledged connect fails",
          "lost" in (judge(dict(ok, reopened_tip=9)) or ""), True)
    check("a reopen above the acknowledged tip passes", judge(dict(ok, reopened_tip=11)), None)
    check("a digest off the clean replay fails",
          "torn" in (judge(dict(ok, digest="b" * 64)) or ""), True)
    check("no tip fails", judge(dict(ok, reopened_tip=None)) is not None, True)
    check("a tip on no known chain fails",
          "neither" in (judge(dict(ok, chain=None)) or ""), True)
    a = {"schema_version": SCHEMA, "subject_binary_sha256": "c" * 64,
         "scenarios": ["idle", "sync"],
         "trials": [dict(ok, scenario="sync"), dict(ok, scenario="idle")]}
    check("a clean record is accepted", artifact_refusals(a), [])
    check("a short run is not PB-S1's verdict", bool(gate_refusals(a)), True)
    bad = json.loads(json.dumps(a))
    bad["trials"][1]["digest"] = "d" * 64
    check("a failed trial refuses the record", len(artifact_refusals(bad)), 1)
    if fails:
        for f in fails:
            print("FAIL", f, file=sys.stderr)
        sys.exit(1)
    print("crash harness selftest: 9 cases OK")


def main(argv=None):
    ap = argparse.ArgumentParser(description="The budget's crash harness (PB-S1)")
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    r = sub.add_parser("run")
    r.add_argument("--daemon", required=True)
    r.add_argument("--replay-bin", required=True, help="shekyl-chain-replay")
    r.add_argument("--work-dir", required=True)
    r.add_argument("--height", type=int, required=True, help="the main chain's blocks")
    r.add_argument("--fork-depth", type=int, default=6,
                   help="blocks below the main tip the heavier fork starts from")
    r.add_argument("--fork-address", default=None,
                   help="the fork's payout address (a different block content)")
    r.add_argument("--trials", type=int, default=MIN_TRIALS)
    r.add_argument("--sync-estimate", type=float, default=30.0,
                   help="seconds a full sync takes; sync kills land inside it")
    r.add_argument("--switch-estimate", type=float, default=10.0)
    r.add_argument("--seed", type=int, default=1)
    r.add_argument("--out", required=True)
    r.add_argument("--disk-class", choices=A.ALLOWED_DISK_CLASSES, default=None)
    r.add_argument("--cargo-timeout", type=int, default=1800)
    r.add_argument("--startup-timeout", type=int, default=600)
    r.add_argument("--shutdown-timeout", type=int, default=120)
    args = ap.parse_args(argv)
    if args.selftest:
        _selftest()
    elif args.cmd == "run":
        Harness(args).run()
    else:
        ap.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
