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
# equals a clean replay of the same chain to the reopened tip. The
# acknowledgement is a tip the subject's get_info published. The clean
# replay is one `shekyl-chain-replay baseline --digests-out` of the seed's
# chain, and the reopened side is `shekyl-chain-replay digest` over the
# subject's store. Both read the same digest function.
#
# Scenarios, round-robin over the trials:
#   sync    a fresh subject syncs from the seed and is killed mid-sync,
#           so the kill lands in a connect's commit at some trial;
#   idle    a synced subject is killed at its tip;
#   switch  a subject on one fork meets a heavier one and is killed while
#           it pops and replays;
#   pool    a synced subject, offline, takes the transaction source's
#           spends (drs_txsource.py) and is killed while it admits them.
#           Every submit it answered ACCEPTED must be in the reopened pool.
#           The chain tip it published before the spends is the
#           acknowledgement: admitting a transaction does not move the tip.
#           Run with --tx-source-bin; without it the seed mines to the
#           emitter's address, no transaction exists, and the artifact's
#           scenarios say the pool point was not reached. That run is not
#           PB-S1's verdict.
#
# Commands:
#   run    --daemon D --replay-bin R --work-dir W --height H --trials N --out F
#          [--tx-source-bin S]   (S from `drs_txsource.py build`)
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
import urllib.request

import drs_artifact as A  # noqa: E402
import drs_bench as B  # noqa: E402
import drs_regtest as R  # noqa: E402
import drs_txsource as T  # noqa: E402

SCHEMA = "shekyl_drs_crash_v1"
SCENARIOS = ("sync", "idle", "switch")
# The pool point runs only with a transaction source.
POOL = "pool"
# PB-S1's floor on the trial count.
MIN_TRIALS = 200


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
    if "acked_txs" in trial:
        lost = T.missing_from_pool(trial["acked_txs"], trial.get("reopened_pool"))
        if lost:
            return (f"{len(lost)} submit(s) answered ACCEPTED before the kill are not in the "
                    f"reopened pool: {lost}")
    if acked is not None and reopened < acked:
        return (f"the daemon published tip {acked} before the kill and reopened at "
                f"{reopened}: an acknowledged connect was lost")
    if trial.get("digest") != trial.get("expected_digest"):
        return (f"the reopened chain's digest at {reopened} is not a clean replay's: "
                "a write survived torn or a committed one was lost")
    return None


def artifact_refusals(artifact):
    reasons = []
    if not isinstance(artifact, dict):
        return ["artifact is not a JSON object"]
    if artifact.get("schema_version") != SCHEMA:
        reasons.append(
            f"schema_version is {artifact.get('schema_version')!r}, expected {SCHEMA!r}")
    trials = artifact.get("trials")
    if not isinstance(trials, list) or not trials:
        return reasons + ["no trials"]
    for trial in trials:
        why = judge(trial)
        if why:
            reasons.append(f"trial {trial.get('index')} ({trial.get('scenario')}): {why}")
    ran = sorted({trial.get("scenario") for trial in trials})
    if artifact.get("scenarios") != ran:
        reasons.append(f"scenarios is {artifact.get('scenarios')!r} but the trials ran {ran!r}")
    if not A.is_hex64(artifact.get("subject_binary_sha256")):
        reasons.append("subject_binary_sha256 is not a sha-256")
    return reasons


def gate_refusals(artifact):
    """Why the run is not PB-S1's verdict: under the floor's trial count, or a
    scenario PB-S1 names that the run did not reach. A short run is still a
    record. It is not a pass, and the process exits with the record written.
    """
    reasons = []
    trials = artifact.get("trials") or []
    if len(trials) < MIN_TRIALS:
        reasons.append(f"{len(trials)} trial(s), under PB-S1's {MIN_TRIALS}")
    missing = [name for name in SCENARIOS + (POOL,)
               if name not in (artifact.get("scenarios") or [])]
    if missing:
        reasons.append(f"PB-S1's points not reached: {missing}")
    return reasons


def pool_hashes(port):
    """The daemon's pool, as txids (`/get_transaction_pool_hashes`)."""
    req = urllib.request.Request(f"http://127.0.0.1:{port}/get_transaction_pool_hashes",
                                 data=b"{}", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as response:
        body = json.load(response)
    if body.get("status") != "OK":
        B._fail(f"the reopened pool did not read: {json.dumps(body)[:300]}")
    return body.get("tx_hashes") or []


class Harness:
    """PB-S1's trials over one regtest session. The wallet, when a pool
    point is asked for, is this harness's; the session does not own one."""

    def __init__(self, args):
        self.args = args
        self.session = R.Session(args)
        self.tx = args.tx_source_bin and os.path.abspath(args.tx_source_bin)
        if self.tx:
            # Creating the wallet reads its daemon, and no chain exists yet:
            # an empty daemon serves the subject's port for the creation.
            empty = os.path.join(self.session.work, "wallet-init")
            shutil.rmtree(empty, ignore_errors=True)
            os.makedirs(empty)
            proc = self.session.spawn("wallet-init", empty, [], self.session.bp2p,
                                      self.session.brpc, offline=True)
            with self.session.running(proc, self.session.brpc) as ready:
                if not ready.ready:
                    B._fail(f"the wallet's creation daemon never came up; see "
                            f"{self.session.work}/wallet-init.log")
                self.addr = T.address(self.tx, self.session.brpc, args.startup_timeout)
            shutil.rmtree(empty)
        else:
            self.addr = B.mining_address(args.cargo_timeout)

    def trial(self, scenario, subj_dir, seed_p2p, kill_after):
        """Start the subject toward the seed, kill it after `kill_after`
        seconds of answered RPC, reopen it offline, and judge it against the
        chain its reopened tip is on."""
        session = self.session
        proc = session.spawn("subject", subj_dir, ["--p2p-closed-peer", f"127.0.0.1:{seed_p2p}"],
                             session.bp2p, session.brpc)
        acked = None
        started = None
        deadline = time.time() + self.args.startup_timeout
        while time.time() < deadline:
            if proc.poll() is not None:
                B._fail(f"the subject exited before the kill; see {session.work}/subject.log")
            try:
                height = B._rpc(session.brpc, "get_info", timeout=2)["result"]["height"]
                tip = R.published_tip(height)
                if tip is not None:
                    acked = tip if acked is None else max(acked, tip)
                started = started or time.time()
            except (OSError, ValueError, KeyError):
                pass
            if started is not None and time.time() - started >= kill_after:
                break
            time.sleep(0.02)
        proc.kill()
        proc.wait()
        reopen = session.spawn("reopen", subj_dir, [], session.bp2p, session.brpc, offline=True)
        with session.running(reopen, session.brpc) as ready:
            if not ready.ready:
                return {"scenario": scenario, "kill_after_s": kill_after, "acked_tip": acked,
                        "reopened_tip": None, "error": "the reopened daemon never came up"}
        return self._reopened(scenario, kill_after, acked, subj_dir)

    def pool_trial(self, subj_dir, kill_after):
        """Start the synced subject offline, feed it the source's spends
        until the first is ACCEPTED, then kill it `kill_after` seconds into
        the spends that follow. The tip get_info published before the kill
        is the acknowledgement, including when the reopen does not come up.
        Each spend run is a fresh wallet, so every trial starts from the
        same spendable outputs."""
        session = self.session
        proc = session.spawn("subject", subj_dir, [], session.bp2p, session.brpc, offline=True)
        if not B._wait_rpc(session.brpc, self.args.startup_timeout, proc):
            B._fail(f"the pool subject never came up; see {session.work}/subject.log")
        acked = session.observed_tip(session.brpc, self.args.startup_timeout)
        if acked is None:
            proc.kill()
            proc.wait()
            B._fail("the pool subject published no tip")
        src = T.Spender(self.tx, session.brpc, self.args.spend_amount,
                        os.path.join(session.work, "tx-source.log"))
        src.first.wait(self.args.startup_timeout)
        if not src.acked:
            proc.kill()
            proc.wait()
            src.finish(60)
            if src.stopped == "not_spendable":
                B._fail("the source's outputs are not yet spendable at the main tip: the "
                        "chain is too short for its coinbase to be spent; raise --height")
            B._fail(f"no spend was ACCEPTED before the kill window opened: {src.stopped}; "
                    f"see {session.work}/tx-source.log")
        time.sleep(kill_after)
        proc.kill()
        proc.wait()
        accepted = src.finish(self.args.startup_timeout)
        reopen = session.spawn("reopen", subj_dir, [], session.bp2p, session.brpc, offline=True)
        with session.running(reopen, session.brpc) as ready:
            if not ready.ready:
                return {"scenario": POOL, "kill_after_s": kill_after, "acked_tip": acked,
                        "reopened_tip": None, "acked_txs": accepted,
                        "error": "the reopened daemon never came up"}
            pool = pool_hashes(session.brpc)
        trial = self._reopened(POOL, kill_after, acked, subj_dir)
        trial.update(acked_txs=accepted, reopened_pool=pool, source_stopped_by=src.stopped)
        return trial

    def _reopened(self, scenario, kill_after, acked, subj_dir):
        session = self.session
        got = session.store_digest(os.path.join(subj_dir, "chain.db"))
        tip = got["tip"]
        on = None if tip is None else session.chain_of(tip, got["hash"])
        expected = None if on is None else session.expected_digest(on, tip)
        return {"scenario": scenario, "kill_after_s": round(kill_after, 3), "acked_tip": acked,
                "reopened_tip": tip, "hash": got["hash"], "chain": on, "digest": got["digest"],
                "expected_digest": expected}

    def run(self):
        args = self.args
        session = self.session
        rng = random.Random(args.seed)
        seed_dir = os.path.join(session.work, "seed")
        fork_dir = os.path.join(session.work, "fork")
        prefix, main_tip, fork_tip = session.lay_fork(
            seed_dir, fork_dir, args.height, args.fork_depth, self.addr,
            args.fork_address or self.addr)
        synced = os.path.join(session.work, "synced-main")
        trials = []
        # Two chains never serve at once, so neither can reorganise the other.
        kinds = SCENARIOS + ((POOL,) if self.tx else ())
        plan = [kinds[i % len(kinds)] for i in range(args.trials)]

        def record(trial, index):
            trial["index"] = index
            trial["verdict"] = judge(trial) or "pass"
            trials.append(trial)
            print(f"trial {index} {trial['scenario']}: acked {trial['acked_tip']} reopened "
                  f"{trial['reopened_tip']} -> {trial['verdict']}", flush=True)

        def fresh(subject, from_dir=None):
            shutil.rmtree(subject, ignore_errors=True)
            if from_dir is None:
                os.makedirs(subject)
            else:
                shutil.copytree(from_dir, subject)

        subject = os.path.join(session.work, "subject")
        seed = session.spawn("seed", seed_dir, [], session.sp2p, session.srpc)
        with session.running(seed, session.srpc) as ready:
            if not ready.ready:
                B._fail("the main chain's seed never came up")
            session.record_hashes("main", session.srpc, main_tip)
            session.digest_chain(session.srpc, "main", main_tip)
            fresh(synced)
            prepared = self.trial("prepare", synced, session.sp2p, kill_after=args.sync_estimate)
            if prepared["reopened_tip"] != main_tip:
                B._fail(f"the preparing sync reached {prepared['reopened_tip']}, not "
                        f"{main_tip}; raise --sync-estimate")
            for index, scenario in enumerate(plan):
                if scenario == "sync":
                    fresh(subject)
                    record(self.trial("sync", subject, session.sp2p,
                                      rng.uniform(0.0, args.sync_estimate)), index)
                elif scenario == "idle":
                    fresh(subject, synced)
                    record(self.trial("idle", subject, session.sp2p,
                                      rng.uniform(0.0, 3.0)), index)
                elif scenario == POOL:
                    fresh(subject, synced)
                    record(self.pool_trial(subject, rng.uniform(0.0, args.pool_estimate)), index)
        fork = session.spawn("fork", fork_dir, [], session.fp2p, session.frpc)
        with session.running(fork, session.frpc) as ready:
            if not ready.ready:
                B._fail("the fork's daemon never came up")
            session.record_hashes("fork", session.frpc, fork_tip)
            session.digest_chain(session.frpc, "fork", fork_tip)
            for index, scenario in enumerate(plan):
                if scenario == "switch":
                    fresh(subject, synced)
                    record(self.trial("switch", subject, session.fp2p,
                                      rng.uniform(0.0, args.switch_estimate)), index)
        artifact = {
            "schema_version": SCHEMA,
            "git_rev": subprocess.run(["git", "-C", A.ROOT, "rev-parse", "HEAD"], check=True,
                                      capture_output=True, text=True).stdout.strip(),
            "subject_binary_sha256": B.binary_sha256(session.daemon),
            "hardware": A.hardware_fingerprint(session.work, args.disk_class),
            "chain": {"main_tip": main_tip, "fork_tip": fork_tip, "fork_depth": args.fork_depth,
                      "prefix": prefix},
            "seed": args.seed,
            "transaction_source": T.TEST if self.tx else None,
            "scenarios": sorted({trial["scenario"] for trial in trials}),
            "trials": trials,
        }
        refusals = artifact_refusals(artifact)
        gate = gate_refusals(artifact)
        artifact["row_refusals"] = gate
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(artifact, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"wrote {args.out}: {len(trials)} trial(s), "
              f"{sum(1 for trial in trials if trial['verdict'] == 'pass')} passed")
        for reason in refusals:
            print("FAIL", reason)
        for reason in gate:
            print("NOT PB-S1:", reason)
        sys.exit(1 if refusals or gate else 0)


def _selftest():
    fails = []

    def check(name, got, want):
        check.names.append(name)
        if got != want:
            fails.append(f"{name}: got {got!r}, want {want!r}")

    check.names = []
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
    artifact = {"schema_version": SCHEMA, "subject_binary_sha256": "c" * 64,
                "scenarios": ["idle", "sync"],
                "trials": [dict(ok, scenario="sync"), dict(ok, scenario="idle")]}
    check("a clean record is accepted", artifact_refusals(artifact), [])
    check("a short run is not PB-S1's verdict", bool(gate_refusals(artifact)), True)
    bad = json.loads(json.dumps(artifact))
    bad["trials"][1]["digest"] = "d" * 64
    check("a failed trial refuses the record", len(artifact_refusals(bad)), 1)
    pooled = dict(ok, acked_txs=["t1", "t2"], reopened_pool=["t2", "t1", "t0"])
    check("a pool holding every acknowledged submit passes", judge(pooled), None)
    check("a lost acknowledged submit fails",
          "not in the reopened pool" in (judge(dict(pooled, reopened_pool=["t1"])) or ""), True)
    names = ("idle", "pool", "switch", "sync")
    full = dict(artifact, scenarios=list(names),
                trials=[dict(ok, scenario=names[i % len(names)]) for i in range(MIN_TRIALS)])
    check("two hundred trials over all four points is PB-S1", gate_refusals(full), [])
    if fails:
        for failure in fails:
            print("FAIL", failure, file=sys.stderr)
        sys.exit(1)
    print(f"crash harness selftest: {len(check.names)} cases OK")


def main(argv=None):
    ap = argparse.ArgumentParser(description="The budget's crash harness (PB-S1)")
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    run = sub.add_parser("run")
    run.add_argument("--daemon", required=True)
    run.add_argument("--replay-bin", required=True, help="shekyl-chain-replay")
    run.add_argument("--work-dir", required=True)
    run.add_argument("--height", type=int, required=True, help="the main chain's blocks")
    run.add_argument("--fork-depth", type=int, default=6,
                     help="blocks below the main tip the heavier fork starts from")
    run.add_argument("--fork-address", default=None,
                     help="the fork's payout address (a different block content)")
    run.add_argument("--trials", type=int, default=MIN_TRIALS)
    run.add_argument("--sync-estimate", type=float, default=30.0,
                     help="seconds a full sync takes; sync kills land inside it")
    run.add_argument("--switch-estimate", type=float, default=10.0)
    run.add_argument("--tx-source-bin", default=None,
                     help="the transaction source's test binary (drs_txsource.py build); "
                          "the pool point needs it")
    run.add_argument("--pool-estimate", type=float, default=20.0,
                     help="seconds of spends after the first acceptance that pool kills land in")
    run.add_argument("--spend-amount", type=int, default=1_000_000_000,
                     help="atomic units each pool spend pays the wallet itself")
    run.add_argument("--seed", type=int, default=1)
    run.add_argument("--out", required=True)
    run.add_argument("--disk-class", choices=A.ALLOWED_DISK_CLASSES, default=None)
    run.add_argument("--cargo-timeout", type=int, default=1800)
    run.add_argument("--startup-timeout", type=int, default=600)
    run.add_argument("--shutdown-timeout", type=int, default=120)
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
