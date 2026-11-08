#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The budget's transaction source, from the bench's side
# (DAEMON_REDB_STORE.md §1.3a; PB-S1's pool point). The source itself is
# `engine::regtest_e2e::bench_source::bench_tx_source` in shekyl-engine-core:
# real wallet spends, built and proved by the engine, submitted to a running
# regtest daemon through its RPC. Its module doc says why it is not the
# shipped wallet RPC (VC-R3: that refuses a fakechain daemon, with no flag).
#
# This file builds the engine's test binary once, runs the source in its two
# modes, and reads the lines it prints:
#   address  BENCH_TX_SOURCE_ADDR=<addr>, the seed's --mine-address;
#   spend    ACCEPTED <txid> per fresh accept, then NOT_SPENDABLE or
#            STOPPED <why>.
#
# Commands:
#   build --target-dir D   print the test binary's path
#   --selftest

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading

import drs_bench as B  # noqa: E402

TEST = "engine::regtest_e2e::bench_source::bench_tx_source"


def parse_line(line):
    """One line of the source's output as an event, or None for the test
    runner's own lines. With `--nocapture` the runner writes `test <name> ... `
    and the source's first line after it on one line."""
    line = line.strip()
    lead = f"test {TEST} ... "
    if line.startswith(lead):
        line = line[len(lead):]
    if line.startswith("BENCH_TX_SOURCE_ADDR="):
        return ("address", line.split("=", 1)[1])
    if line.startswith("ACCEPTED "):
        return ("accepted", line.split(" ", 1)[1])
    if line == "NOT_SPENDABLE":
        return ("not_spendable", None)
    if line.startswith("STOPPED "):
        return ("stopped", line.split(" ", 1)[1])
    return None


def missing_from_pool(acked, pool):
    """The acknowledged txids the reopened pool does not hold, in order."""
    held = set(pool or [])
    return [t for t in acked if t not in held]


def build(target_dir, timeout):
    """Build shekyl-engine-core's library tests in release and return the
    test binary's path, read from cargo's own report."""
    cmd = ["cargo", "test", "--release", "--no-run", "--message-format=json",
           "-p", "shekyl-engine-core", "--lib"]
    env = dict(os.environ, CARGO_TARGET_DIR=os.path.abspath(target_dir))
    proc = subprocess.run(cmd, cwd=os.path.join(B.ROOT, "rust"), env=env, capture_output=True,
                          text=True, timeout=timeout)
    if proc.returncode != 0:
        B._fail(f"building the transaction source failed (rc={proc.returncode}):\n"
                f"{proc.stderr[-2000:]}")
    found = []
    for line in proc.stdout.splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if (msg.get("reason") == "compiler-artifact" and msg.get("executable")
                and msg.get("profile", {}).get("test")
                and msg.get("target", {}).get("name") == "shekyl_engine_core"):
            found.append(msg["executable"])
    if len(found) != 1:
        B._fail(f"expected one shekyl-engine-core test binary in cargo's report, found {found}")
    return found[0]


def _argv(binary):
    return [binary, TEST, "--ignored", "--exact", "--nocapture", "--test-threads", "1"]


def _env(port, **extra):
    env = dict(os.environ, SHEKYL_BENCH_DAEMON_RPC=str(port))
    env.update({k: str(v) for k, v in extra.items()})
    return env


def address(binary, port, timeout):
    """The source's address, from a wallet created against the daemon on
    `port`."""
    proc = subprocess.run(_argv(binary), env=_env(port, SHEKYL_BENCH_TX_SOURCE="address"),
                          capture_output=True, text=True, timeout=timeout)
    hits = [e[1] for e in map(parse_line, proc.stdout.splitlines()) if e and e[0] == "address"]
    # Rule 47: the runner's exit says the test passed, not that it printed.
    if proc.returncode != 0 or len(hits) != 1:
        B._fail(f"the transaction source gave no address (rc={proc.returncode}):\n"
                f"{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")
    return hits[0]


class Spender:
    """One spend run against the daemon on `port`, read as it goes."""

    def __init__(self, binary, port, amount, log_path):
        self.acked = []
        self.stopped = None
        self.first = threading.Event()
        self.done = threading.Event()
        self._log = open(log_path, "a", encoding="utf-8")
        self.proc = subprocess.Popen(
            _argv(binary), env=_env(port, SHEKYL_BENCH_TX_SOURCE="spend",
                                    SHEKYL_BENCH_SPEND_ATOMIC=amount),
            stdout=subprocess.PIPE, stderr=self._log, text=True)
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    def _read(self):
        for line in self.proc.stdout:
            self._log.write(line)
            ev = parse_line(line)
            if ev is None:
                continue
            if ev[0] == "accepted":
                self.acked.append(ev[1])
                self.first.set()
            elif ev[0] in ("not_spendable", "stopped"):
                self.stopped = ev[0] if ev[1] is None else f"{ev[0]}: {ev[1]}"
        self.first.set()
        self.done.set()

    def finish(self, timeout):
        """Wait for the source to stop on its own (its daemon is gone), then
        make sure it has."""
        self.done.wait(timeout)
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait()
        self._reader.join(timeout)
        self._log.close()
        return list(self.acked)


def _selftest():
    fails = []

    def check(name, got, want):
        if got != want:
            fails.append(f"{name}: got {got!r}, want {want!r}")

    check("the address line", parse_line("BENCH_TX_SOURCE_ADDR=shekyl1x/y/z\n"),
          ("address", "shekyl1x/y/z"))
    check("an accept", parse_line("ACCEPTED ab12\n"), ("accepted", "ab12"))
    check("the depth gate", parse_line("NOT_SPENDABLE"), ("not_spendable", None))
    check("a stop keeps its reason", parse_line("STOPPED submit: Transport"),
          ("stopped", "submit: Transport"))
    check("the runner's lines are not events", parse_line("running 1 test"), None)
    check("a test line naming ACCEPTED mid-line is not one",
          parse_line("test x ... ACCEPTED ab"), None)
    check("the first line shares the runner's line",
          parse_line(f"test {TEST} ... BENCH_TX_SOURCE_ADDR=shekyl1a/b/c"),
          ("address", "shekyl1a/b/c"))
    check("a held pool misses nothing", missing_from_pool(["a", "b"], ["b", "a", "c"]), [])
    check("a lost submit is named", missing_from_pool(["a", "b"], ["a"]), ["b"])
    check("an empty pool misses every acked submit", missing_from_pool(["a"], None), ["a"])
    if fails:
        for f in fails:
            print("FAIL", f, file=sys.stderr)
        sys.exit(1)
    print("transaction source selftest: 10 cases OK")


def main(argv=None):
    ap = argparse.ArgumentParser(description="The budget's transaction source")
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    b = sub.add_parser("build")
    b.add_argument("--target-dir", required=True)
    b.add_argument("--cargo-timeout", type=int, default=3600)
    args = ap.parse_args(argv)
    if args.selftest:
        _selftest()
    elif args.cmd == "build":
        print(build(args.target_dir, args.cargo_timeout))
    else:
        ap.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
