#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The budget's power-loss harness (DAEMON_REDB_STORE.md §1.3a, PB-S2;
# rule 7). A kill cannot test power loss: the kernel still flushes a killed
# process's writes. This harness records every write the subject's
# filesystem sends to its device, then rebuilds the device as it stood at
# each flush and FUA boundary, and at points between them, and holds each
# rebuilt store to PB-S1's condition.
#
# Capture (`capture`, needs root for the device mapper): the subject's data
# directory is on ext4 over a `dm-log-writes` device, so every write and
# every flush lands in a log in order. Each time the subject publishes a new
# tip, the harness writes a mark into that log (`dmsetup message ... mark`):
# the acknowledgements known at any point of the capture are exactly the
# marks before it. The subject syncs the main chain from a seed, then meets
# a heavier fork and switches to it, and is killed. While each seed serves,
# the clean replays' digests are taken for every height a rebuilt store
# can reopen at.
#
# Replay (`replay`, needs root): the log's flush and FUA entries, and points
# between them, are replayed in order onto a zeroed device. At each point
# the device is copied, the copy mounted (ext4 replays its journal), the
# subject daemon reopens the store offline (its own recovery path, the real
# door), and the store is digested. A point passes when:
#   - before any acknowledgement, the store is absent or opens;
#   - otherwise the reopened tip is at or above the last acknowledged one,
#     on a chain a seed served, and its digest is the clean replay's at
#     that tip (drs_crash.judge).
#
# Commands (run inside a disposable machine with root; DAEMON_REDB_STORE.md
# §1.3a.6 and the tooling row: never beside a fleet daemon):
#   capture --daemon D --replay-bin R --work-dir W --mine-address A
#           --fork-address F --height H --git-rev SHA
#   replay  --daemon D --replay-bin R --work-dir W --replay-log L
#           [--between N] [--max-points N] --out F
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
import drs_crash as C  # noqa: E402

SCHEMA = "shekyl_drs_powerloss_v1"
CAPTURE = "capture.json"
DM_NAME = "drs-pbs2"
DATA_BYTES = 4 << 30
LOG_BYTES = 16 << 30
SECTOR = 512


def sh(*argv, check=True, capture=False):
    """A root command, never through a shell."""
    proc = subprocess.run(["sudo", "-n", *argv], check=False, capture_output=True, text=True)
    if check and proc.returncode != 0:
        B._fail(f"`{' '.join(argv)}` failed (rc={proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout if capture else proc.returncode


def sparse_file(path, size):
    with open(path, "wb") as fh:
        fh.truncate(size)


def loop_attach(path):
    return sh("losetup", "--find", "--show", path, capture=True).strip()


def parse_found(out):
    """replay-log's find answer, `entry@position`, as the entry index."""
    head = out.strip().split("@", 1)[0]
    return int(head) if head.isdigit() else None


def mark_name(chain, height):
    return f"ack-{chain}-{height}"


def parse_mark(name):
    """`(chain, height)` for an acknowledgement mark, else None."""
    parts = name.split("-")
    if len(parts) != 3 or parts[0] != "ack" or not parts[2].isdigit():
        return None
    return parts[1], int(parts[2])


def acked_at(marks, entry):
    """The last acknowledgement whose mark precedes `entry`: `(chain,
    height)`, or None before the first. `marks` is `[(entry, name)]`."""
    last = None
    for at, name in sorted(marks):
        if at >= entry:
            break
        parsed = parse_mark(name)
        if parsed is not None:
            last = parsed
    return last


def checkpoints(boundaries, total, between, max_points):
    """The entries to rebuild the device at: every flush and FUA boundary,
    `between` evenly spaced points inside each gap, and the log's end, in
    order. With `max_points`, an even subsample that always keeps the first
    and last; the artifact records the coverage."""
    points = set(b for b in boundaries if 0 < b <= total)
    edges = sorted(points | {0, total})
    for lo, hi in zip(edges, edges[1:]):
        for k in range(1, between + 1):
            p = lo + (hi - lo) * k // (between + 1)
            if lo < p < hi:
                points.add(p)
    points.add(total)
    ordered = sorted(p for p in points if p > 0)
    if max_points and len(ordered) > max_points:
        step = (len(ordered) - 1) / (max_points - 1)
        ordered = sorted({ordered[round(i * step)] for i in range(max_points)})
    return ordered


def judge_point(point):
    """Why a rebuilt point fails PB-S2, or None."""
    if point.get("error"):
        return point["error"]
    if point.get("acked") is None:
        if point.get("reopened_tip") is None or point.get("digest") is not None:
            return None
        return "the store opened with no digest"
    if not point.get("store"):
        return (f"no store at a point after the subject published tip "
                f"{point['acked']}: an acknowledged connect was lost")
    return C.judge(dict(point, acked_tip=point["acked"]))


class Powerloss(C.Harness):
    def __init__(self, args):  # pylint: disable=super-init-not-called
        self.args = args
        self.work = os.path.abspath(args.work_dir)
        os.makedirs(self.work, exist_ok=True)
        self.daemon = B.daemon_executable(args.daemon)
        self.replay = os.path.abspath(args.replay_bin)
        (self.sp2p, self.srpc, self.fp2p, self.frpc, self.bp2p, self.brpc), held = \
            B._reserve_ports(6)
        for sk in held:
            sk.close()
        self.tx = None
        self.addr = getattr(args, "mine_address", None)
        self.expected = {}
        self.hashes = {"main": {}, "fork": {}}
        self.prefix = None
        self.mnt = os.path.join(self.work, "mnt")

    # -- capture ---------------------------------------------------------

    def mark(self, name):
        sh("dmsetup", "message", DM_NAME, "0", "mark", name)

    def follow(self, chain, until, deadline_s):
        """Poll the subject's tip, marking each new one, until it reaches
        `until` on `chain`'s hashes."""
        seen = None
        deadline = time.time() + deadline_s
        while time.time() < deadline:
            try:
                h = B._rpc(self.brpc, "get_info", timeout=2)["result"]["height"] - 1
                hsh = B._rpc(self.brpc, "get_block_header_by_height", {"height": h},
                             timeout=2)["result"]["block_header"]["hash"]
            except (OSError, ValueError, KeyError, TypeError):
                time.sleep(0.05)
                continue
            if seen is None or h != seen:
                on = self.chain_of(h, hsh) or chain
                self.mark(mark_name(on, h))
                seen = h
                if on == chain and h >= until:
                    return h
            time.sleep(0.02)
        B._fail(f"the subject did not reach {until} on {chain} within {deadline_s}s")

    def capture(self):
        a = self.args
        seed_dir, fork_dir = (os.path.join(self.work, d) for d in ("seed", "fork"))
        for d in (seed_dir, fork_dir):
            shutil.rmtree(d, ignore_errors=True)
            os.makedirs(d)
        prefix = a.height - a.fork_depth
        self.prefix = prefix
        self.generate(seed_dir, prefix, self.addr)
        shutil.rmtree(fork_dir)
        shutil.copytree(seed_dir, fork_dir)
        main_tip = self.generate(seed_dir, a.fork_depth, self.addr) - 1
        fork_tip = self.generate(fork_dir, a.fork_depth + 2, a.fork_address) - 1

        data, log = (os.path.join(self.work, f) for f in ("data.img", "log.img"))
        sparse_file(data, DATA_BYTES)
        sparse_file(log, LOG_BYTES)
        data_dev, log_dev = loop_attach(data), loop_attach(log)
        sectors = DATA_BYTES // SECTOR
        sh("dmsetup", "create", DM_NAME, "--table",
           f"0 {sectors} log-writes {data_dev} {log_dev}")
        dm = f"/dev/mapper/{DM_NAME}"
        sh("mkfs.ext4", "-q", "-F", dm)
        self.mark("mkfs")
        os.makedirs(self.mnt, exist_ok=True)
        sh("mount", dm, self.mnt)
        sh("chown", f"{os.getuid()}:{os.getgid()}", self.mnt)
        subj = os.path.join(self.mnt, "subject")
        os.makedirs(subj)
        self.mark("start")

        # Sync the main chain, marking each tip the subject publishes.
        seed = self.spawn("seed", seed_dir, [], self.sp2p, self.srpc)
        with self.running(seed, self.srpc) as s:
            if not s.ready:
                B._fail("the main chain's seed never came up")
            self.record_hashes("main", self.srpc, main_tip)
            for h in range(0, main_tip + 1):
                self.expected_digest(self.srpc, "main", h)
            proc = self.spawn("subject", subj, ["--p2p-closed-peer", f"127.0.0.1:{self.sp2p}"],
                              self.bp2p, self.brpc)
            self.follow("main", main_tip, a.startup_timeout)
            proc.terminate()
            proc.wait(a.shutdown_timeout)
        # Meet the heavier fork and switch to it; killed at its tip.
        fork = self.spawn("fork", fork_dir, [], self.fp2p, self.frpc)
        with self.running(fork, self.frpc) as f:
            if not f.ready:
                B._fail("the fork's daemon never came up")
            self.record_hashes("fork", self.frpc, fork_tip)
            for h in range(prefix, fork_tip + 1):
                self.expected_digest(self.frpc, "fork", h)
            proc = self.spawn("subject", subj, ["--p2p-closed-peer", f"127.0.0.1:{self.fp2p}"],
                              self.bp2p, self.brpc)
            self.follow("fork", fork_tip, a.startup_timeout)
            proc.kill()
            proc.wait()
        self.mark("end")
        sh("umount", self.mnt)
        sh("dmsetup", "remove", DM_NAME)
        sh("losetup", "-d", data_dev)
        sh("losetup", "-d", log_dev)
        os.remove(data)
        record = {
            "schema_version": SCHEMA,
            "git_rev": a.git_rev,
            "subject_binary_sha256": B.binary_sha256(self.daemon),
            "chain": {"main_tip": main_tip, "fork_tip": fork_tip, "prefix": prefix},
            "hashes": self.hashes,
            "expected": {f"{k[0]}:{k[1]}": v for k, v in self.expected.items()},
            "data_bytes": DATA_BYTES,
        }
        with open(os.path.join(self.work, CAPTURE), "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2, sort_keys=True)
        print(f"captured: main tip {main_tip}, fork tip {fork_tip}; log {log}")

    # -- replay ----------------------------------------------------------

    def find(self, replay_log, log_dev, *opts):
        """The index of the first entry matching `opts` (replay-log prints
        `entry@position`), or None when there is none."""
        proc = subprocess.run(["sudo", "-n", replay_log, "--log", log_dev, "--find", *opts],
                              check=False, capture_output=True, text=True)
        return parse_found(proc.stdout) if proc.returncode == 0 else None

    def boundaries(self, replay_log, log_dev, total):
        found = set()
        for flag in ("--next-fua", "--next-flush"):
            at = 0
            while at < total:
                entry = self.find(replay_log, log_dev, flag, "--start-entry", str(at))
                if entry is None or entry < at:
                    break
                # The device as it stood once that entry was written: the
                # first `entry + 1` entries.
                found.add(entry + 1)
                at = entry + 1
        return found

    def marks(self, replay_log, log_dev, names):
        out = []
        for name in names:
            entry = self.find(replay_log, log_dev, "--end-mark", name)
            if entry is not None:
                out.append((entry, name))
        return out

    def reopen(self, copy_img, point):
        """Mount a copy of the rebuilt device, let the subject reopen its
        store offline, digest it, and unmount."""
        dev = loop_attach(copy_img)
        try:
            if sh("mount", dev, self.mnt, check=False) != 0:
                point["store"] = False
                point["mounted"] = False
                return point
            point["mounted"] = True
            sh("chown", "-R", f"{os.getuid()}:{os.getgid()}", self.mnt)
            subj = os.path.join(self.mnt, "subject")
            store = os.path.join(subj, "chain.db")
            point["store"] = os.path.exists(store)
            if not point["store"]:
                return point
            proc = self.spawn("reopen", subj, [], self.bp2p, self.brpc, offline=True)
            with self.running(proc, self.brpc) as r:
                if not r.ready:
                    point["error"] = "the subject did not reopen the rebuilt store"
                    return point
            got = self.store_digest(store)
            point.update(reopened_tip=got["tip"], hash=got["hash"], digest=got["digest"])
            return point
        finally:
            sh("umount", self.mnt, check=False)
            sh("losetup", "-d", dev, check=False)

    def run_replay(self):
        a = self.args
        with open(os.path.join(self.work, CAPTURE), encoding="utf-8") as fh:
            cap = json.load(fh)
        self.hashes = {k: {int(h): v for h, v in d.items()} for k, d in cap["hashes"].items()}
        self.prefix = cap["chain"]["prefix"]
        self.expected = {(k.split(":")[0], int(k.split(":")[1])): v
                         for k, v in cap["expected"].items()}
        log_dev = loop_attach(os.path.join(self.work, "log.img"))
        target = os.path.join(self.work, "replay.img")
        sparse_file(target, cap["data_bytes"])
        target_dev = loop_attach(target)
        os.makedirs(self.mnt, exist_ok=True)
        try:
            total = int(sh(a.replay_log, "--log", log_dev, "--num-entries",
                           capture=True).strip())
            names = ([mark_name("main", h) for h in range(cap["chain"]["main_tip"] + 1)]
                     + [mark_name("fork", h) for h in range(self.prefix,
                                                           cap["chain"]["fork_tip"] + 1)])
            marks = self.marks(a.replay_log, log_dev, names)
            mkfs = self.find(a.replay_log, log_dev, "--end-mark", "mkfs") or 0
            bounds = self.boundaries(a.replay_log, log_dev, total)
            points = [p for p in checkpoints(bounds, total, a.between, a.max_points)
                      if p > mkfs]
            replayed = 0
            results = []
            for p in points:
                sh(a.replay_log, "--log", log_dev, "--replay", target_dev,
                   "--start-entry", str(replayed), "--limit", str(p - replayed))
                replayed = p
                copy_img = os.path.join(self.work, "point.img")
                subprocess.run(["cp", "--sparse=always", target, copy_img], check=True)
                acked = acked_at(marks, p)
                point = {"entry": p, "kind": "boundary" if p in bounds else "between",
                         "acked": None if acked is None else acked[1],
                         "acked_chain": None if acked is None else acked[0]}
                self.reopen(copy_img, point)
                os.remove(copy_img)
                tip = point.get("reopened_tip")
                if tip is not None:
                    point["chain"] = self.chain_of(tip, point.get("hash"))
                    point["expected_digest"] = self.expected.get((point["chain"], tip))
                point["verdict"] = judge_point(point) or "pass"
                results.append(point)
                print(f"entry {p}/{total} ({point['kind']}): acked {point['acked']} "
                      f"reopened {tip} -> {point['verdict']}", flush=True)
        finally:
            sh("losetup", "-d", target_dev, check=False)
            sh("losetup", "-d", log_dev, check=False)
        artifact = dict(
            {k: cap[k] for k in ("schema_version", "git_rev", "subject_binary_sha256",
                                 "chain")},
            hardware=A.hardware_fingerprint(self.work, a.disk_class),
            log_entries=total,
            boundaries=len(bounds),
            marks=len(marks),
            points=results,
            sampled=bool(a.max_points) and len(points) < len(bounds),
        )
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(artifact, fh, indent=2, sort_keys=True)
            fh.write("\n")
        failed = [r for r in results if r["verdict"] != "pass"]
        print(f"wrote {a.out}: {len(results)} point(s) over {total} entries "
              f"({len(bounds)} boundaries, {len(marks)} acknowledgements), "
              f"{len(failed)} failed")
        for r in failed:
            print(f"FAIL entry {r['entry']}: {r['verdict']}")
        sys.exit(1 if failed else 0)


def _selftest():
    fails = []

    def check(name, got, want):
        if got != want:
            fails.append(f"{name}: got {got!r}, want {want!r}")

    check("a find answer is its entry", parse_found("4127@88412\n"), 4127)
    check("an empty find answer is none", parse_found(""), None)
    check("a mark parses", parse_mark("ack-main-12"), ("main", 12))
    check("a non-ack mark is not one", parse_mark("mkfs"), None)
    marks = [(10, "mkfs"), (40, "ack-main-1"), (90, "ack-main-2"), (200, "ack-fork-3")]
    check("before the first acknowledgement", acked_at(marks, 40), None)
    check("the last mark before the point", acked_at(marks, 91), ("main", 2))
    check("a fork acknowledgement", acked_at(marks, 500), ("fork", 3))
    pts = checkpoints({100, 50}, 200, 1, None)
    check("boundaries, midpoints and the end", pts, [25, 50, 75, 100, 150, 200])
    check("a subsample keeps both ends",
          checkpoints(set(range(1, 101)), 100, 0, 5)[::4], [1, 100])
    ok = {"acked": 5, "store": True, "reopened_tip": 5, "chain": "main",
          "digest": "a" * 64, "expected_digest": "a" * 64}
    check("an intact point passes", judge_point(ok), None)
    check("a lost acknowledged connect fails",
          "lost" in (judge_point(dict(ok, reopened_tip=4)) or ""), True)
    check("a missing store after an ack fails",
          "no store" in (judge_point(dict(ok, store=False)) or ""), True)
    check("no store before any ack passes", judge_point({"acked": None, "store": False}), None)
    check("a torn digest fails",
          "torn" in (judge_point(dict(ok, digest="b" * 64)) or ""), True)
    if fails:
        for f in fails:
            print("FAIL", f, file=sys.stderr)
        sys.exit(1)
    print("power-loss harness selftest: 15 cases OK")


def main(argv=None):
    ap = argparse.ArgumentParser(description="The budget's power-loss harness (PB-S2)")
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    for name in ("capture", "replay"):
        p = sub.add_parser(name)
        p.add_argument("--daemon", required=True)
        p.add_argument("--replay-bin", required=True, help="shekyl-chain-replay")
        p.add_argument("--work-dir", required=True)
        p.add_argument("--startup-timeout", type=int, default=600)
        p.add_argument("--shutdown-timeout", type=int, default=120)
    c = sub.choices["capture"]
    c.add_argument("--mine-address", required=True)
    c.add_argument("--fork-address", required=True)
    c.add_argument("--height", type=int, required=True)
    c.add_argument("--fork-depth", type=int, default=6)
    c.add_argument("--git-rev", required=True)
    r = sub.choices["replay"]
    r.add_argument("--replay-log", required=True, help="xfstests' src/log-writes/replay-log")
    r.add_argument("--between", type=int, default=1,
                   help="points replayed inside each gap between boundaries")
    r.add_argument("--max-points", type=int, default=None)
    r.add_argument("--disk-class", choices=A.ALLOWED_DISK_CLASSES, default=None)
    r.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    if args.selftest:
        _selftest()
    elif args.cmd == "capture":
        Powerloss(args).capture()
    elif args.cmd == "replay":
        Powerloss(args).run_replay()
    else:
        ap.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
