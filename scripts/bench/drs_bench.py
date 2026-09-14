#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# DRS-BENCH runner: two-daemon regtest IBD, emits an artifact or refuses.
# The gate (schema, refusals, §1.3 compare, redb-engine probe) lives in
# `drs_artifact.py`. Design record: `docs/design/DAEMON_REDB_STORE.md` §7.4.
#
# EXIT CODES for `check`: 0 when no axis is OVER, 1 when any axis is OVER, 2 for a
# usage or input error (argparse's convention, which `_load`'s refusals follow). A
# **BAND** verdict exits 0 on purpose: §1.3 makes 1.25x-1.50x a decision-log call
# for a human to accept or mitigate, so this gate must not convert it into a
# failure -- and equally must not let it read as a clean pass, which is why the
# text report says so in as many words.
#
# Python, under `scripts/bench/`, deliberately. Rule 20 makes Rust the default
# for the daemon codebase and its bug fixes; this spawns daemons and writes
# JSON, the same job as `compare.py`. It is not a second copy of that script:
# compare.py is iai-callgrind only, and its ids cannot name a two-daemon IBD run.
#
# Vehicle: generateblocks is gated on check_core_ready(), which a zero-peer
# daemon never satisfies, and the protocol handler initialises
# m_synchronized(offline). So: generate offline, restart networked over the
# same datadir, measure the subject syncing from it.

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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drs_artifact as A  # noqa: E402

ROOT = A.ROOT


def _fail(msg):
    print(f"drs_bench: {msg}", file=sys.stderr)
    sys.exit(1)


def _reserve_ports(n):
    """Pick n distinct free ports, holding every socket until all are chosen.

    Allocating them one at a time lets the kernel hand the same ephemeral port
    back; two daemons told to use one port hang rather than error. A foreign
    process can still take one between close and spawn, which is why a failure
    to come up reports the ports it asked for.
    """
    socks = [socket.socket() for _ in range(n)]
    for sk in socks:
        sk.bind(("127.0.0.1", 0))
    ports = [sk.getsockname()[1] for sk in socks]
    assert len(set(ports)) == n, f"port reservation collided: {ports}"
    return ports, socks


def _rpc(port, method, params=None, timeout=60):
    body = json.dumps({"jsonrpc": "2.0", "id": "0", "method": method,
                       "params": params or {}}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/json_rpc", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _dir_bytes(path, apparent):
    """Total size of a directory tree: apparent file length, or allocated blocks."""
    args = ["du", "-s", "-b", path] if apparent else ["du", "-s", "-B1", path]
    return int(subprocess.run(args, check=True, capture_output=True,
                              text=True).stdout.split()[0])


def _resolved_sync_line(log_path):
    """The daemon's own report of the durability flags it resolved, or None.

    This is the readback. The daemon logs it at startup for A4, so the harness no
    longer has to settle for recording the argv it imposed: it can check what the
    node says it opened with. Read from the SUBJECT's log, the subject being the
    process whose numbers the artifact carries.
    """
    try:
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "Database sync: flags=0x" in line:
                    # The daemon colourises its log. Strip the escapes: an artifact
                    # field is a record, and terminal control bytes in one make it
                    # harder to read and to diff.
                    return re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
    except OSError:
        return None
    return None


def _loadavg():
    """(1-minute, 5-minute) load average, or None if unreadable.

    None, not a numeric sentinel. The first version of this returned (-1.0, -1.0)
    on the reasoning that a reader can see -1 is not a load — but the VALIDATOR
    only asked `isinstance(v, (int, float))`, and -1.0 is a number, so the sentinel
    validated as a real measurement. That is the third instance in this file of the
    same defect (`disk_class: "unknown"`, a failed CPU read as `0.0`), and it slipped
    through because the test for it used `None` rather than the sentinel the code
    actually emits: the test could not fail on the real path. A failed observation
    now has no numeric representation at all, and `measure` refuses.
    """
    try:
        la = os.getloadavg()
        return la[0], la[1]
    except OSError:
        return None


def _cpu_seconds(pid):
    """utime+stime of the process, all threads, in seconds. None if unreadable."""
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
            rest = fh.read().rpartition(")")[2].split()
        utime, stime = int(rest[11]), int(rest[12])
        return (utime + stime) / os.sysconf("SC_CLK_TCK")
    except (OSError, IndexError, ValueError):
        return None


def _peak_rss_bytes(pid):
    """VmHWM in bytes, or None if unreadable."""
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) * 1024
    except OSError:
        pass
    return None


def _wait_rpc(port, timeout, proc=None):
    """Wait for the daemon's RPC to answer. Returns the timestamp, or None.

    `proc` makes a dead daemon fail fast: a process that exited will never
    answer, and waiting the full window turns a crash into a slow start.
    """
    t0 = time.time()
    while time.time() - t0 < timeout:
        if proc is not None and proc.poll() is not None:
            return None
        try:
            if _rpc(port, "get_info", timeout=5).get("result", {}).get("status") == "OK":
                return time.time()
        except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError):
            time.sleep(1)
    return None


def _stop(proc, timeout):
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


class _RunningDaemon:
    """One shekyld: wait for RPC on enter, terminate (then kill) on exit."""

    def __init__(self, proc, rpc_port, startup_timeout, shutdown_timeout):
        self.proc = proc
        self.rpc_port = rpc_port
        self.startup_timeout = startup_timeout
        self.shutdown_timeout = shutdown_timeout
        self.ready_at = None

    def __enter__(self):
        self.ready_at = _wait_rpc(self.rpc_port, self.startup_timeout, self.proc)
        return self

    def __exit__(self, *exc):
        _stop(self.proc, self.shutdown_timeout)
        return False

    @property
    def ready(self):
        return self.ready_at is not None

    @property
    def pid(self):
        return self.proc.pid


def mining_address(timeout):
    """A current-format regtest mining address, minted by the canonical emitter.

    Not read from rust/shekyl-wire/tests/vectors/regtest_mining_recipients.json:
    that vector holds the same key material at the pre-msg_sign_pk encoding and
    no longer decodes. Running the emitter named by that vector's README is the
    source of truth — a pinned string would go stale on the next address-format
    change exactly as the vector did.
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
    # printed an address.
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

    The subject is what the artifact describes. The seed is fixture. The seed
    is reused across runs (generation dominates at the reference height); the
    subject is always wiped (an IBD from a partial chain is a different
    experiment).
    """
    work = os.path.abspath(args.work_dir)
    os.makedirs(work, exist_ok=True)
    seed_dir = os.path.abspath(args.seed_dir or os.path.join(work, "seed"))
    os.makedirs(seed_dir, exist_ok=True)
    pre = A.measurement_preflight(sync_mode=args.sync_mode, daemon=args.daemon,
        work_dir=work, seed_dir=seed_dir, disk_class=args.disk_class)
    if pre:
        _fail("refusing to start:\n  " + "\n  ".join(pre))
    addr = mining_address(args.cargo_timeout)

    subj_dir = os.path.join(work, "subject")
    shutil.rmtree(subj_dir, ignore_errors=True)
    os.makedirs(subj_dir)
    if args.fresh_seed:
        shutil.rmtree(seed_dir, ignore_errors=True)
        os.makedirs(seed_dir)

    common = ["--regtest", "--keep-fakechain", "--fixed-difficulty=1",
              f"--db-sync-mode={args.sync_mode}", "--allow-local-ip", "--no-igd",
              "--non-interactive", f"--log-level={args.log_level}"]
    (sp2p, srpc, bp2p, brpc), held = _reserve_ports(4)
    for sk in held:
        sk.close()

    def spawn(tag, d, argv_extra):
        p2p, rpcp = (sp2p, srpc) if tag == "seed" else (bp2p, brpc)
        argv = [args.daemon] + common + [f"--data-dir={d}",
                                         f"--p2p-bind-port={p2p}",
                                         f"--rpc-bind-port={rpcp}"] + argv_extra
        with open(os.path.join(work, f"{tag}.argv"), "a", encoding="utf-8") as fh:
            fh.write(" ".join(argv) + "\n")
        # The SUBJECT's log is truncated; the seed's is appended. That asymmetry is
        # deliberate: the seed legitimately spans two phases (generate offline, then
        # serve networked) and both belong in one log, while the subject is spawned
        # once per run and its log is now READ BACK for the resolved durability
        # flags. Appending would let a stale line from an earlier run in this work
        # directory be read as this run's readback — `work` is not wiped between
        # runs, only the subject's data directory is.
        mode = "a" if tag == "seed" else "w"
        log = open(os.path.join(work, f"{tag}.log"), mode, encoding="utf-8")
        try:
            proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, cwd=d)
        finally:
            log.close()
        return proc, argv

    def running(proc, rpc_port):
        return _RunningDaemon(proc, rpc_port, args.startup_timeout,
                              args.shutdown_timeout)

    # Genesis alone is height 1; N generated blocks leave height N+1.
    target_h = args.height + 1
    proc, _ = spawn("seed", seed_dir, ["--offline"])
    with running(proc, srpc) as seed:
        if not seed.ready:
            _fail(f"seed RPC on 127.0.0.1:{srpc} never came up "
                  f"(exited={seed.proc.poll()}); see {work}/seed.log and seed.argv")
        have_h = _rpc(srpc, "get_info")["result"]["height"]
        seed_reused = have_h > 1
        gen_blocks, gen_wall = 0, None
        if have_h < target_h:
            gen_blocks = target_h - have_h
            gt0 = time.time()
            resp = _rpc(srpc, "generateblocks",
                        {"amount_of_blocks": gen_blocks, "wallet_address": addr,
                         "starting_nonce": 0}, timeout=args.gen_timeout)
            gen_wall = time.time() - gt0
            st = resp.get("result", {}).get("status")
            if st != "OK":
                _fail(f"generateblocks refused: status={st!r} "
                      f"({json.dumps(resp)[:300]})")
        elif have_h > target_h:
            _fail(f"the seed at {seed_dir} already holds height {have_h}, past the "
                  f"requested {target_h}. Blocks cannot be un-generated without "
                  f"changing what is being measured; point --seed-dir elsewhere or "
                  f"pass --fresh-seed.")
        seed_h = _rpc(srpc, "get_info")["result"]["height"]
    if seed_h != target_h:
        _fail(f"seed is at height {seed_h}, expected {target_h} — generation did not "
              "reach the requested height, so the fixture is not the one asked for")
    if seed_h <= 1:
        _fail(f"seed holds only height {seed_h}; nothing to sync")

    proc, _ = spawn("seed", seed_dir, [])
    with running(proc, srpc) as seed:
        if not seed.ready:
            _fail(f"networked seed RPC on 127.0.0.1:{srpc} never came up "
                  f"(exited={seed.proc.poll()}); see {work}/seed.log and seed.argv")
        subj_proc, subj_argv = spawn(
            "subject", subj_dir, [f"--add-exclusive-node=127.0.0.1:{sp2p}"])
        with running(subj_proc, brpc) as subj:
            if not subj.ready:
                _fail(f"subject RPC on 127.0.0.1:{brpc} never came up "
                      f"(exited={subj.proc.poll()}); see {work}/subject.log and "
                      f"subject.argv. A non-offline daemon's startup is variable "
                      f"here (tens of seconds to minutes) and is EXCLUDED from the "
                      f"measurement, so raising --startup-timeout does not affect "
                      f"any number.")
            # The durability READBACK, taken from the subject's own startup report
            # now that it is up. Read here rather than at the end so a subject that
            # dies mid-sync still fails on the specific missing thing.
            resolved_line = _resolved_sync_line(os.path.join(work, "subject.log"))
            # Denominator: first successful get_info to height == seed height.
            # CPU is a delta over the same window. A single end-of-run read
            # would carry startup / RandomX init / store open, which the wall
            # figure excludes.
            t0, reached, peers = subj.ready_at, 0, 0
            rss_samples = []
            cpu_at_start = _cpu_seconds(subj.pid)
            load_at_start = _loadavg()
            deadline = t0 + args.sync_timeout
            while time.time() < deadline:
                try:
                    info = _rpc(brpc, "get_info")["result"]
                except (urllib.error.URLError, OSError, json.JSONDecodeError,
                        TimeoutError):
                    time.sleep(1)
                    continue
                reached = info["height"]
                peers = max(peers, info.get("outgoing_connections_count", 0))
                rss = _peak_rss_bytes(subj.pid)
                if rss is not None:
                    rss_samples.append(rss)
                if reached >= seed_h:
                    break
                time.sleep(args.poll_interval)
            elapsed = time.time() - t0
            rss = _peak_rss_bytes(subj.pid)
            if rss is not None:
                rss_samples.append(rss)
            cpu_at_end = _cpu_seconds(subj.pid)
            load_at_end = _loadavg()
            synced = reached >= seed_h
        # Store size AFTER close: a live LMDB env reported 40.7 MB for a
        # 200-block chain that measured 1.43 MB once closed.
        store_bytes = _dir_bytes(subj_dir, apparent=False)
        store_apparent = _dir_bytes(subj_dir, apparent=True)

    if resolved_line is None:
        _fail(f"the subject never reported its resolved durability flags in "
              f"{work}/subject.log. That line is the readback for DRS-D9, so no "
              f"artifact is written: recording the mode we ASKED for while unable to "
              f"see what the daemon opened with is the posture-by-omission A4 "
              f"forbids. A daemon predating the A4 report will not log it — rebuild.")
    if load_at_start is None or load_at_end is None:
        _fail("could not read the load average from os.getloadavg(). System load is a "
              "condition of a wall-time measurement, so no artifact is written rather "
              "than one carrying an unobserved figure.")
    if cpu_at_start is None or cpu_at_end is None:
        _fail("could not sample the subject's CPU time from /proc "
              f"(start={cpu_at_start}, end={cpu_at_end}). The artifact would have to "
              "record a failed observation as a number, so none is written.")
    if not rss_samples:
        _fail("could not sample the subject's peak RSS from /proc. Emitting 0 would "
              "validate as a real measurement and skip the 2× floor.")
    cpu_s = cpu_at_end - cpu_at_start
    peak = max(rss_samples)
    if not synced:
        _fail(f"subject reached height {reached} of {seed_h} in {elapsed:.1f}s and did "
              "not converge. A partial sync is not a shorter measurement of the same "
              "thing — it is a different experiment, so no artifact is written.")

    git_rev = subprocess.run(["git", "-C", ROOT, "rev-parse", "HEAD"], check=True,
                             capture_output=True, text=True).stdout.strip()
    scenario = "ibd_coinbase_only"
    artifact = {
        "schema_version": A.SCHEMA,
        # One backend per build; the daemon never compiles two store engines
        # into one binary (ruled 2026-09-14). The label derives from the
        # recorded selection mechanism, not from a flag an operator sets.
        "engine": A.ENGINE_SELECTORS[A.ENGINE_DEFAULT_LMDB],
        "engine_selected_by": A.ENGINE_DEFAULT_LMDB,
        "git_rev": git_rev,
        "thresholds_frozen_at": A.FROZEN_AT,
        "durability": {
            "policy": "DRS-D9 full-fsync-per-commit",
            "sync_mode": args.sync_mode,
            "imposed_argv": subj_argv[1:],
            # OBSERVED, from the daemon's own report of the flags it resolved.
            # Earlier revisions recorded False with an honest note that no readback
            # existed -- `mdb_env_get_flags` is in-process and nothing logged the
            # resolved mode. A4's enabler landed that log line, so the posture is
            # measured rather than imposed-and-validated.
            "observed": True,
            "resolved_log_line": resolved_line,
            "readback": "the subject daemon's own startup report of the flags it "
                        "resolved. The mode is still validated against an allowed set "
                        "BEFORE spawning, because a refusal that comes before the run "
                        "costs nothing and this line only arrives after it",
        },
        "environment": {
            "loadavg_1m_at_start": load_at_start[0],
            "loadavg_1m_at_end": load_at_end[0],
            "loadavg_5m_at_end": load_at_end[1],
            "cpu_count": os.cpu_count(),
            "note": "the subject is meant to be the machine's only significant load. "
                    "A wall-time ratio requires two runs at comparable load: on this "
                    "machine the same fixture moved 36-55% on wall and 16-24% on CPU "
                    "between an idle box and a 5-minute load average of 8.6 over 16 "
                    "cores, and a 1.25x floor sits well inside that band",
        },
        "hardware": A.hardware_fingerprint(subj_dir, args.disk_class),
        "fixture": {
            "nettype": "fakechain",
            "height_reached": int(reached),
            "height_requested": int(args.height),
            "reference_height": A.REFERENCE_HEIGHT,
            "tx_per_block": 0,
            "prunable_region": A.PRUNABLE_ABSENT,
            "verify_exercised": {"pow": True, "fcmp_pp": False},
            "verify_note": "PoW longhash is computed and checked for every block with "
                           "no nettype bypass; --fixed-difficulty lowers the TARGET "
                           "only. generateblocks produces coinbase-only blocks, so "
                           "FCMP++ verification is not exercised at all.",
            "seed_height": int(seed_h),
            "seed_reused": bool(seed_reused),
            "peers_used": int(peers),
            "blocks_generated": int(gen_blocks),
            "generation_wall_s": None if gen_wall is None else round(gen_wall, 3),
        },
        "measures": [
            A.measure_row(
                "ibd_wall_time_s", round(elapsed, 3), scenario,
                "subject's first successful get_info to height == seed height; "
                "EXCLUDES process start, RandomX dataset init and store open"),
            A.measure_row(
                "subject_cpu_s", round(cpu_s, 3), scenario,
                "utime+stime of the subject over all threads, sampled at the first "
                "successful get_info and again at the end, reported as the DELTA — "
                "so it spans exactly the same phase as ibd_wall_time_s"),
            A.measure_row(
                "peak_rss_bytes", int(peak), scenario,
                "subject VmHWM sampled during sync. NOT §7.4's attacker-feed row, "
                "which has no definition yet"),
            A.measure_row(
                "store_bytes", store_bytes, scenario,
                "filesystem-ALLOCATED bytes of the subject data dir, measured after "
                "the store was closed. NOT §7.4's multi-year row"),
            A.measure_row(
                "store_bytes_apparent", store_apparent, scenario,
                "apparent (file-length) bytes of the same directory, same moment; "
                "differs from the allocated figure only if the engine leaves holes"),
        ],
    }
    refusals = A.artifact_refusals(artifact)
    if refusals:
        _fail("the harness produced an artifact it will not emit:\n  " +
              "\n  ".join(refusals))
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(artifact, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"wrote {args.out}: engine={artifact['engine']} height_reached={reached} "
          f"{A.PRIMARY_MEASURE}={elapsed:.3f}s peak_rss={peak} "
          f"store={store_bytes} (apparent {store_apparent}) "
          f"load={load_at_start[0]:.2f}->{load_at_end[0]:.2f} on {os.cpu_count()} cores")
    for note in A.saturation_notes(artifact, "this run"):
        print(f"CONTENTION: {note}")
    if reached < A.REFERENCE_HEIGHT:
        print(f"NOTE: height {reached} is below §1.3's reference {A.REFERENCE_HEIGHT}. "
              "§1.3 permits 'max available fixture; the artifact records the height it "
              "reached' — it is recorded, and the ratio is only valid against another "
              "artifact at the same height.")


def _positive_int(v):
    """argparse type for a count that must be at least 1.

    Rejected at the boundary rather than downstream: `--height 0` previously
    reached the seed logic and reported "seed holds only height 1; nothing to
    sync", and `--height -5` reported "already holds height 1" — both true
    statements about a symptom, neither naming the cause. An error that describes
    where the program noticed is not an error that says what the operator did.
    """
    try:
        n = int(v)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{v!r} is not an integer")
    if n < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {n}")
    return n


def _load(path):
    """Read an artifact, or refuse. Never raise.

    A gate reports verdicts; a traceback is not one. An absent file, an
    unreadable one and malformed JSON are all ordinary operator errors, and each
    used to exit through a stack trace that says where this script broke rather
    than what was wrong with the input. Same defect as reaching
    `comparability_refusals` with a non-object, one layer further out.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        _fail(f"{path}: no such artifact")
    except IsADirectoryError:
        _fail(f"{path}: is a directory, not an artifact")
    except OSError as e:
        _fail(f"{path}: cannot be read ({e.strerror})")
    except json.JSONDecodeError as e:
        _fail(f"{path}: is not valid JSON (line {e.lineno}, column {e.colno}: {e.msg})")


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

    m = sub.add_parser("measure", help="run the IBD baseline and emit an artifact")
    m.add_argument("--height", type=_positive_int,
                   default=A.REFERENCE_HEIGHT)
    m.add_argument("--out", required=True)
    m.add_argument("--daemon", default=os.path.join(ROOT, "build/bin/shekyld"))
    m.add_argument("--work-dir", required=True)
    m.add_argument("--sync-mode", default="safe")
    m.add_argument("--log-level", type=int, default=1)
    m.add_argument("--startup-timeout", type=float, default=1200.0)
    m.add_argument("--gen-timeout", type=float, default=14400.0)
    m.add_argument("--sync-timeout", type=float, default=14400.0)
    m.add_argument("--shutdown-timeout", type=float, default=300.0)
    m.add_argument("--poll-interval", type=float, default=2.0)
    m.add_argument("--cargo-timeout", type=float, default=1800.0)
    m.add_argument("--seed-dir", default=None,
                   help="reusable seed chain (default: <work-dir>/seed). "
                        "Topped up to the requested height, never wiped "
                        "unless --fresh-seed.")
    m.add_argument("--disk-class", default=None, choices=A.ALLOWED_DISK_CLASSES,
                   help="declare the disk type when it cannot be probed (btrfs, zfs, "
                        "overlay); recorded as operator-declared, not probed")
    m.add_argument("--fresh-seed", action="store_true",
                   help="discard the seed chain and regenerate it")

    args = ap.parse_args()

    if args.cmd == "validate":
        r = A.artifact_refusals(_load(args.artifact))
        if r:
            _fail(f"{args.artifact} is not a usable measurement:\n  " + "\n  ".join(r))
        print(f"{args.artifact}: usable")
        return

    if args.cmd == "check":
        base, cand = _load(args.baseline), _load(args.candidate)
        bad = []
        for path, a in ((args.baseline, base), (args.candidate, cand)):
            bad += [f"{path}: {x}" for x in A.artifact_refusals(a)]
        # Stop here if either artifact is unusable. `comparability_refusals` reads
        # both with `.get`, so a syntactically valid non-object -- `null`, a list --
        # raised AttributeError instead of being refused: a malformed input crashed
        # the gate rather than being rejected by it.
        if not bad:
            bad += A.comparability_refusals(base, cand)
        if bad:
            _fail("refusing to compute a §1.3 ratio:\n  " + "\n  ".join(bad))
        rep = A.compare(base, cand)
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
            print(f"  load: {rep['load_conditions']}")
            for c in rep["contention_notes"]:
                print(f"  CONTENTION: {c}")
            for s in rep["fixture_shortfalls"]:
                print(f"  SHORTFALL: {s}")
            print(f"  verdict: {rep['verdict']}")
            if rep["verdict"] == "BAND":
                # §1.3 makes the 1.25x-1.50x band a decision-log call, so the exit
                # status is 0 -- a human has to accept or mitigate. Said out loud
                # because a silent zero is how a band becomes a de facto pass, and
                # premature clearing is the expensive direction here.
                print("  NOTE: BAND exits 0 because §1.3 makes this a decision-log "
                      "call, NOT a pass. Do not wire this verdict as CI pass/fail on "
                      "its own; record the accept-or-mitigate decision.")
        sys.exit(1 if rep["verdict"] == "OVER" else 0)

    if args.cmd == "measure":
        measure(args)


if __name__ == "__main__":
    main()
