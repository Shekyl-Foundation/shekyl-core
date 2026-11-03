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
# The oracle is the daemon's promise: once get_info has reported a tip, a
# crash after that report recovers the tip or a heavier chain it had seen
# (design review, 2026-11-03). The capture writes a mark right after each
# new tip get_info reports, so the mark sits at the report. Every point
# from the mark onward must hold that tip or a known heavier chain. A point
# before it may hold the tip or the one before, since nothing about the tip
# had been reported. Every point is also held to the checks that need no
# report: its tip is on a known chain, and its digest is a clean replay's.
# Early publication still fails: a tip reported before its fsync finished
# leaves points after the mark and before the flush on the older tip.
# Where redb's own flush falls is redb's property, not the daemon's
# promise, and nothing here infers it.
#
# Capture (`capture`, needs root for the device mapper) and replay
# (`replay`, needs root) both take xfstests' `replay-log`. While each seed
# serves, one baseline walk records the digest at every height.
#
# Commands (run inside a disposable machine with root; DAEMON_REDB_STORE.md
# §1.3a.6 and the tooling row: never beside a fleet daemon):
#   capture --daemon D --replay-bin R --replay-log L --work-dir W
#           --mine-address A --fork-address F --height H --git-rev SHA
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
import drs_regtest as R  # noqa: E402

SCHEMA = "shekyl_drs_powerloss_v2"
CAPTURE = "capture.json"
DM_NAME = "drs-pbs2"
DATA_BYTES = 4 << 30
LOG_BYTES = 16 << 30
SECTOR = 512
_FLUSH_FLAGS = ("--next-flush", "--next-fua")
# The mark after mkfs. Points before it judge an empty filesystem.
MKFS_MARK = "mkfs"


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


def find_entry(replay_log, log_dev, flag, start):
    """The index of the next entry matching `flag` at or after `start`, or None."""
    proc = subprocess.run(
        ["sudo", "-n", replay_log, "--log", log_dev, "--find", flag,
         "--start-entry", str(start)],
        check=False, capture_output=True, text=True)
    return parse_found(proc.stdout) if proc.returncode == 0 else None


def mark_name(seq):
    """The mark written after the `seq`-th report."""
    return f"ack-{seq}"


def reported_new(last, chain, tip):
    """Whether `(chain, tip)` is a report the capture has not marked yet."""
    return last != (chain, tip)


def find_mark(replay_log, log_path, name):
    """The entry index of the mark `name` in a complete log, or None."""
    proc = subprocess.run(
        ["sudo", "-n", replay_log, "--log", log_path, "--find", "--end-mark", name],
        check=False, capture_output=True, text=True)
    return parse_found(proc.stdout) if proc.returncode == 0 else None


def acked_at(acks, point):
    """The last acknowledgement whose mark entry is strictly below `point`.

    A replay point is the count of entries replayed, so the point after a
    mark's entry is the first to include it. Sorting is by entry, then
    height.
    """
    last = None
    rows = acks.values() if isinstance(acks, dict) else acks
    for ack in sorted(rows, key=lambda row: (row["entry"], row["height"])):
        if ack["entry"] >= point:
            break
        last = ack
    if last is None:
        return None
    return last["chain"], last["height"]


def subsample_points(text):
    """`--max-points`: a subsample keeps the first replay point and the last."""
    try:
        count = int(text)
    except ValueError as error:
        raise argparse.ArgumentTypeError("max-points is not an integer") from error
    if count < 2:
        raise argparse.ArgumentTypeError(
            "a subsample keeps the first point and the last, so it names at least two")
    return count


def checkpoints(boundaries, total, between, max_points):
    """The entries to rebuild the device at, and whether that list is a subsample.

    Every flush and FUA boundary, `between` evenly spaced points inside each
    gap, and the log's end, in order. `max_points` is an even subsample that
    always keeps the first and the last, so it is at least two; one point
    would have to drop an end. The flag is true only when points were
    dropped. A between-point can leave a subsample longer than the boundary
    set, which a comparison against that set would call complete.
    """
    points = set(boundary for boundary in boundaries if 0 < boundary <= total)
    edges = sorted(points | {0, total})
    for lo, hi in zip(edges, edges[1:]):
        for step in range(1, between + 1):
            point = lo + (hi - lo) * step // (between + 1)
            if lo < point < hi:
                points.add(point)
    points.add(total)
    ordered = sorted(point for point in points if point > 0)
    if max_points is None:
        return ordered, False
    if max_points < 2:
        raise ValueError(
            "a subsample keeps the first point and the last, so it names at least two")
    if len(ordered) <= max_points:
        return ordered, False
    stride = (len(ordered) - 1) / (max_points - 1)
    return sorted({ordered[round(i * stride)] for i in range(max_points)}), True


def boundaries_of(replay_log, log_dev, total):
    """Replay points just past each flush and each FUA: the first entries
    through that entry."""
    found = set()
    for flag in _FLUSH_FLAGS:
        at = 0
        while at < total:
            entry = find_entry(replay_log, log_dev, flag, at)
            if entry is None or entry < at:
                break
            found.add(entry + 1)
            at = entry + 1
    return found


def judge_point(point):
    """Why a rebuilt point fails PB-S2, or None. `store` is whether the
    rebuilt device held a store before the daemon reopened it; the digest
    is of the store after the reopen, whether it opened or created it, so
    a point before the first acknowledgement is still held to the clean
    replay at the tip it reopens at."""
    if point.get("error"):
        return point["error"]
    if point.get("acked") is not None and not point.get("store"):
        return (f"no store at a point after the subject published tip "
                f"{point['acked']}: an acknowledged connect was lost")
    return C.judge(dict(point, acked_tip=point["acked"]))


class Powerloss:
    """A capture and its replay over one regtest session. No wallet: the
    two chains are mined to the addresses the capture names."""

    def __init__(self, args):
        self.args = args
        self.session = R.Session(args)
        self.acks = []
        self.last_report = None
        self.mnt = os.path.join(self.session.work, "mnt")

    def follow(self, chain, until, deadline_s):
        """Poll the subject's tip, marking the log after each new report,
        until a report on `chain` is at or above `until`."""
        session = self.session
        deadline = time.time() + deadline_s
        while time.time() < deadline:
            try:
                height = B._rpc(session.brpc, "get_info", timeout=2)["result"]["height"]
                tip = R.published_tip(height)
                if tip is None:
                    time.sleep(0.05)
                    continue
                header = B._rpc(session.brpc, "get_block_header_by_height", {"height": tip},
                                timeout=2)["result"]["block_header"]["hash"]
            except (OSError, ValueError, KeyError, TypeError):
                time.sleep(0.05)
                continue
            on = session.chain_of(tip, header)
            # An unidentified tip is not the chain this follow is waiting
            # for. Marking it would acknowledge a height no served chain
            # has published.
            if on is None:
                time.sleep(0.02)
                continue
            if reported_new(self.last_report, on, tip):
                name = mark_name(len(self.acks))
                sh("dmsetup", "message", DM_NAME, "0", "mark", name)
                self.acks.append({"mark": name, "chain": on, "height": tip})
                self.last_report = (on, tip)
            if on == chain and tip >= until:
                return tip
            time.sleep(0.02)
        B._fail(f"the subject did not reach {until} on {chain} within {deadline_s}s")

    def capture(self):
        args = self.args
        session = self.session
        seed_dir, fork_dir = (os.path.join(session.work, name) for name in ("seed", "fork"))
        prefix, main_tip, fork_tip = session.lay_fork(
            seed_dir, fork_dir, args.height, args.fork_depth, args.mine_address, args.fork_address)

        data, log = (os.path.join(session.work, name) for name in ("data.img", "log.img"))
        sparse_file(data, DATA_BYTES)
        sparse_file(log, LOG_BYTES)
        data_dev, log_dev = loop_attach(data), loop_attach(log)
        held = {"subject": None, "mounted": False, "dm": False, "loops": [data_dev, log_dev]}
        try:
            sectors = DATA_BYTES // SECTOR
            sh("dmsetup", "create", DM_NAME, "--table",
               f"0 {sectors} log-writes {data_dev} {log_dev}")
            held["dm"] = True
            dm = f"/dev/mapper/{DM_NAME}"
            sh("mkfs.ext4", "-q", "-F", dm)
            # Every entry before this mark is mkfs's.
            sh("dmsetup", "message", DM_NAME, "0", "mark", MKFS_MARK)
            os.makedirs(self.mnt, exist_ok=True)
            sh("mount", dm, self.mnt)
            held["mounted"] = True
            sh("chown", f"{os.getuid()}:{os.getgid()}", self.mnt)
            subject = os.path.join(self.mnt, "subject")
            os.makedirs(subject)

            seed = session.spawn("seed", seed_dir, [], session.sp2p, session.srpc)
            with session.running(seed, session.srpc) as ready:
                if not ready.ready:
                    B._fail("the main chain's seed never came up")
                session.record_hashes("main", session.srpc, main_tip)
                session.digest_chain(session.srpc, "main", main_tip)
                proc = held["subject"] = session.spawn(
                    "subject", subject, ["--p2p-closed-peer", f"127.0.0.1:{session.sp2p}"],
                    session.bp2p, session.brpc)
                self.follow("main", main_tip, args.startup_timeout)
                proc.terminate()
                proc.wait(args.shutdown_timeout)
            fork = session.spawn("fork", fork_dir, [], session.fp2p, session.frpc)
            with session.running(fork, session.frpc) as ready:
                if not ready.ready:
                    B._fail("the fork's daemon never came up")
                session.record_hashes("fork", session.frpc, fork_tip)
                session.digest_chain(session.frpc, "fork", fork_tip)
                proc = held["subject"] = session.spawn(
                    "subject", subject, ["--p2p-closed-peer", f"127.0.0.1:{session.fp2p}"],
                    session.bp2p, session.brpc)
                self.follow("fork", fork_tip, args.startup_timeout)
                proc.kill()
                proc.wait()
            # A complete capture is released with every step checked: the
            # target's removal writes the log's last super block.
            sh("umount", self.mnt)
            held["mounted"] = False
            sh("dmsetup", "remove", DM_NAME)
            held["dm"] = False
            while held["loops"]:
                sh("losetup", "-d", held["loops"].pop())
        finally:
            # A failed capture releases whatever it still holds, so the next
            # run does not meet a busy device name. Its own error is the one
            # reported; these steps do not replace it.
            subject_proc = held["subject"]
            if subject_proc is not None and subject_proc.poll() is None:
                subject_proc.kill()
                subject_proc.wait()
            if held["mounted"]:
                sh("umount", self.mnt, check=False)
            if held["dm"]:
                sh("dmsetup", "remove", DM_NAME, check=False)
            for dev in held["loops"]:
                sh("losetup", "-d", dev, check=False)
        os.remove(data)
        # The log is complete once the target is removed: every mark is in
        # it, and each must be found (rule 47: an acknowledgement the log
        # does not hold is not one this capture can judge).
        mkfs_mark = find_mark(args.replay_log, log, MKFS_MARK)
        if mkfs_mark is None:
            B._fail(f"the log at {log} holds no `{MKFS_MARK}` mark")
        for ack in self.acks:
            ack["entry"] = find_mark(args.replay_log, log, ack["mark"])
            if ack["entry"] is None:
                B._fail(f"the log at {log} holds no `{ack['mark']}` mark")
        mkfs_entries = mkfs_mark + 1
        record = {
            "schema_version": SCHEMA,
            "git_rev": args.git_rev,
            "subject_binary_sha256": B.binary_sha256(session.daemon),
            "chain": {"main_tip": main_tip, "fork_tip": fork_tip, "prefix": prefix},
            "hashes": session.hashes,
            "digests": {chain: {str(height): digest for height, digest in table.items()}
                        for chain, table in session.digests.items()},
            "acks": sorted(self.acks, key=lambda ack: ack["entry"]),
            "mkfs_entries": mkfs_entries,
            "data_bytes": DATA_BYTES,
        }
        with open(os.path.join(session.work, CAPTURE), "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"captured: main tip {main_tip}, fork tip {fork_tip}; "
              f"{len(self.acks)} acknowledgement(s); log {log}")

    def reopen(self, copy_img, point):
        """Mount a copy of the rebuilt device, start the subject on it
        offline, digest the store, and unmount."""
        session = self.session
        dev = loop_attach(copy_img)
        try:
            if sh("mount", dev, self.mnt, check=False) != 0:
                point["error"] = "the filesystem did not mount after mkfs had completed"
                return point
            sh("chown", "-R", f"{os.getuid()}:{os.getgid()}", self.mnt)
            subject = os.path.join(self.mnt, "subject")
            store = os.path.join(subject, "chain.db")
            point["store"] = os.path.exists(store)
            os.makedirs(subject, exist_ok=True)
            proc = session.spawn(f"reopen-{point['entry']}", subject, [], session.bp2p,
                                 session.brpc, offline=True)
            with session.running(proc, session.brpc) as ready:
                if not ready.ready:
                    point["error"] = "the subject did not reopen the rebuilt store"
                    return point
            got = session.store_digest(store)
            point.update(reopened_tip=got["tip"], hash=got["hash"], digest=got["digest"])
            return point
        finally:
            sh("umount", self.mnt, check=False)
            sh("losetup", "-d", dev, check=False)

    def run_replay(self):
        args = self.args
        session = self.session
        with open(os.path.join(session.work, CAPTURE), encoding="utf-8") as fh:
            cap = json.load(fh)
        if cap.get("schema_version") != SCHEMA:
            B._fail(f"{CAPTURE} is {cap.get('schema_version')!r}, not {SCHEMA!r}: its "
                    "acknowledgements were recorded under another oracle")
        session.hashes = {key: {int(height): value for height, value in table.items()}
                          for key, table in cap["hashes"].items()}
        session.prefix = cap["chain"]["prefix"]
        session.digests = {chain: {int(height): digest for height, digest in table.items()}
                           for chain, table in cap["digests"].items()}
        acks = cap["acks"]
        mkfs_entries = cap["mkfs_entries"]
        log_dev = loop_attach(os.path.join(session.work, "log.img"))
        target = os.path.join(session.work, "replay.img")
        sparse_file(target, cap["data_bytes"])
        target_dev = loop_attach(target)
        os.makedirs(self.mnt, exist_ok=True)
        try:
            total = int(sh(args.replay_log, "--log", log_dev, "--num-entries",
                           capture=True).strip())
            bounds = boundaries_of(args.replay_log, log_dev, total)
            ordered, subsampled = checkpoints(bounds, total, args.between, args.max_points)
            points = [point for point in ordered if point >= mkfs_entries]
            replayed = 0
            results = []
            for point_at in points:
                sh(args.replay_log, "--log", log_dev, "--replay", target_dev,
                   "--start-entry", str(replayed), "--limit", str(point_at - replayed))
                replayed = point_at
                copy_img = os.path.join(session.work, "point.img")
                subprocess.run(["cp", "--sparse=always", target, copy_img], check=True)
                acked = acked_at(acks, point_at)
                point = {"entry": point_at,
                         "kind": "boundary" if point_at in bounds else "between",
                         "acked": None if acked is None else acked[1],
                         "acked_chain": None if acked is None else acked[0]}
                self.reopen(copy_img, point)
                os.remove(copy_img)
                tip = point.get("reopened_tip")
                if tip is not None:
                    point["chain"] = session.chain_of(tip, point.get("hash"))
                    point["expected_digest"] = session.expected_digest(point["chain"], tip)
                point["verdict"] = judge_point(point) or "pass"
                results.append(point)
                print(f"entry {point_at}/{total} ({point['kind']}): acked {point['acked']} "
                      f"reopened {tip} -> {point['verdict']}", flush=True)
        finally:
            sh("losetup", "-d", target_dev, check=False)
            sh("losetup", "-d", log_dev, check=False)
        artifact = dict(
            {key: cap[key] for key in ("schema_version", "git_rev", "subject_binary_sha256",
                                       "chain")},
            hardware=A.hardware_fingerprint(session.work, args.disk_class),
            log_entries=total,
            boundaries=len(bounds),
            acknowledgements=len(acks),
            mkfs_entries=mkfs_entries,
            points=results,
            sampled=subsampled,
        )
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(artifact, fh, indent=2, sort_keys=True)
            fh.write("\n")
        failed = [row for row in results if row["verdict"] != "pass"]
        print(f"wrote {args.out}: {len(results)} point(s) over {total} entries "
              f"({len(bounds)} boundaries, {len(acks)} acknowledgements), "
              f"{len(failed)} failed")
        for row in failed:
            print(f"FAIL entry {row['entry']}: {row['verdict']}")
        sys.exit(1 if failed else 0)


def _selftest():
    fails = []

    def check(name, got, want):
        check.names.append(name)
        if got != want:
            fails.append(f"{name}: got {got!r}, want {want!r}")

    check.names = []
    check("a find answer is its entry", parse_found("4127@88412\n"), 4127)
    check("an empty find answer is none", parse_found(""), None)
    check("the first report is new", reported_new(None, "main", 0), True)
    check("the same tip again is not a new report", reported_new(("main", 3), "main", 3), False)
    check("a higher tip is a new report", reported_new(("main", 3), "main", 4), True)
    check("the same height on the fork is a new report",
          reported_new(("main", 30), "fork", 30), True)
    check("marks are numbered by report", mark_name(7), "ack-7")
    rows = [{"entry": 90, "chain": "main", "height": 2},
            {"entry": 40, "chain": "main", "height": 1},
            {"entry": 200, "chain": "fork", "height": 3}]
    check("a point before the mark judges no report", acked_at(rows, 40), None)
    check("the point after the mark's entry holds its report", acked_at(rows, 41), ("main", 1))
    check("a later entry wins numerically", acked_at(rows, 100), ("main", 2))
    check("a fork acknowledgement", acked_at(rows, 500), ("fork", 3))
    pts, sampled = checkpoints({100, 50}, 200, 1, None)
    check("boundaries, midpoints and the end", pts, [25, 50, 75, 100, 150, 200])
    check("the full list is not a subsample", sampled, False)
    kept, sampled = checkpoints(set(range(1, 101)), 100, 0, 5)
    check("a subsample keeps both ends", [kept[0], kept[-1]], [1, 100])
    check("and records that it subsampled", sampled, True)
    short, sampled = checkpoints({100, 50}, 200, 1, 4)
    check("a subsample can stay longer than the boundary set", len(short) > 2, True)
    check("and is still a subsample", sampled, True)
    try:
        checkpoints({1, 2}, 2, 0, 1)
        one_point = False
    except ValueError:
        one_point = True
    check("one point cannot keep both ends", one_point, True)
    check("the flag refuses one point before a run", subsample_points("2"), 2)
    try:
        subsample_points("1")
        refused = False
    except argparse.ArgumentTypeError:
        refused = True
    check("one point is not a max-points value", refused, True)
    ok = {"acked": 5, "store": True, "reopened_tip": 5, "chain": "main",
          "digest": "a" * 64, "expected_digest": "a" * 64}
    fresh = dict(ok, acked=None, store=False, reopened_tip=0)
    check("a store created before any ack passes at the clean digest", judge_point(fresh), None)
    check("a torn digest before any ack fails",
          "torn" in (judge_point(dict(fresh, digest="b" * 64)) or ""), True)
    check("a refused reopen fails", judge_point(dict(fresh, error="refused")), "refused")
    check("an intact point passes", judge_point(ok), None)
    check("a lost acknowledged connect fails",
          "lost" in (judge_point(dict(ok, reopened_tip=4)) or ""), True)
    check("a missing store after an ack fails",
          "no store" in (judge_point(dict(ok, store=False)) or ""), True)
    check("a torn digest fails",
          "torn" in (judge_point(dict(ok, digest="b" * 64)) or ""), True)
    if fails:
        for failure in fails:
            print("FAIL", failure, file=sys.stderr)
        sys.exit(1)
    print(f"power-loss harness selftest: {len(check.names)} cases OK")


def main(argv=None):
    ap = argparse.ArgumentParser(description="The budget's power-loss harness (PB-S2)")
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    for name in ("capture", "replay"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--daemon", required=True)
        cmd.add_argument("--replay-bin", required=True, help="shekyl-chain-replay")
        cmd.add_argument("--replay-log", required=True,
                         help="xfstests' src/log-writes/replay-log")
        cmd.add_argument("--work-dir", required=True)
        cmd.add_argument("--startup-timeout", type=int, default=600)
        cmd.add_argument("--shutdown-timeout", type=int, default=120)
    capture = sub.choices["capture"]
    capture.add_argument("--mine-address", required=True)
    capture.add_argument("--fork-address", required=True)
    capture.add_argument("--height", type=int, required=True)
    capture.add_argument("--fork-depth", type=int, default=6)
    capture.add_argument("--git-rev", required=True)
    replay = sub.choices["replay"]
    replay.add_argument("--between", type=int, default=1,
                        help="points replayed inside each gap between boundaries")
    replay.add_argument("--max-points", type=subsample_points, default=None)
    replay.add_argument("--disk-class", choices=A.ALLOWED_DISK_CLASSES, default=None)
    replay.add_argument("--out", required=True)
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
