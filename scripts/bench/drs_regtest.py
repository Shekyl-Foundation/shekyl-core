#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# One regtest session the durability harnesses compose: ports, a daemon
# spawn, block generation, and one digest walk per chain
# (DAEMON_REDB_STORE.md §1.3a). The crash harness owns the wallet. This
# session does not.
#
# Replay schedule flags are omitted. When both are absent,
# shekyl-chain-replay uses FakechainSchedule::PRODUCTION, the pair the
# regtest daemon mines under. Restating that pair here would be a second
# copy of it.
#
# get_info's height is the chain length. The published tip is that length
# minus one, and an empty chain has no tip.

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

import drs_bench as B  # noqa: E402
import armed_lever  # noqa: E402

# The restricted listener refuses a range longer than this
# (RESTRICTED_BLOCK_HEADER_RANGE). The admin listener does not. A chunk of
# the cap is a complete read on either door.
HEADER_RANGE = 1000
# Chain identity only. The schedule pair is the tool's production default.
REPLAY_CHAIN = ("--chain", "regtest", "--fixed-difficulty", "1")
HEIGHT_DIGESTS_SCHEMA = "shekyl_height_digests_v1"
# The crash and power-loss harnesses each run a seed, a fork and a subject.
PORTS = 6
_GEN_TIMEOUT_S = 86400


def published_tip(height):
    """The tip index `height` has published, or None for an empty chain.

    `height` is get_info's chain length. A length of one has published
    block 0.
    """
    if isinstance(height, bool) or not isinstance(height, int) or height <= 0:
        return None
    return height - 1


def header_spans(start, end, cap=HEADER_RANGE):
    """Inclusive header spans of at most `cap` blocks, in order."""
    if end < start:
        return []
    spans = []
    at = start
    while at <= end:
        stop = min(end, at + cap - 1)
        spans.append((at, stop))
        at = stop + 1
    return spans


class Session:
    """The chain a durability harness serves, and the digests of that chain."""

    def __init__(self, args):
        self.args = args
        self.work = os.path.abspath(args.work_dir)
        os.makedirs(self.work, exist_ok=True)
        self.daemon = B.daemon_executable(args.daemon)
        self.replay = os.path.abspath(args.replay_bin)
        (self.sp2p, self.srpc, self.fp2p, self.frpc, self.bp2p, self.brpc), held = \
            B._reserve_ports(PORTS)
        for sk in held:
            sk.close()
        # chain key -> {tip index: digest hex}, filled by one baseline walk.
        self.digests = {}
        self.hashes = {"main": {}, "fork": {}}
        # The first height the two chains can differ. Below it they are one chain.
        self.prefix = None

    def spawn(self, tag, data_dir, extra, p2p, rpc, offline=False):
        common = ["--network", "regtest", "--dev-difficulty", "1", "--p2p-local",
                  "--tor", "off", "--log-level", "info"]
        net = ["--clearnet", "off"] if offline else ["--clearnet-listen", f"127.0.0.1:{p2p}"]
        argv = [self.daemon] + common + ["--data-dir", data_dir] + net + [
            "--rpc-admin-listen", f"127.0.0.1:{rpc}",
            "--log-file", os.path.join(self.work, f"{tag}.daemon.log")] + extra
        log = open(os.path.join(self.work, f"{tag}.log"), "a", encoding="utf-8")
        try:
            return subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, cwd=data_dir)
        finally:
            log.close()

    def running(self, proc, rpc):
        return B._RunningDaemon(proc, rpc, self.args.startup_timeout, self.args.shutdown_timeout)

    def generate(self, data_dir, count, address):
        """Mine `count` blocks into `data_dir` and return the chain length."""
        gen_log = os.path.join(self.work, "gen.log")
        gen_from = armed_lever.log_size(gen_log)
        proc = self.spawn("gen", data_dir, [armed_lever.FLAG, "--mine-address", address],
                          self.sp2p, self.srpc, offline=True)
        with self.running(proc, self.srpc) as gen:
            if not gen.ready:
                B._fail(f"a generating daemon never came up; see {self.work}/gen.log")
            if not armed_lever.announced_since(gen_log, gen_from):
                B._fail(f"the generating daemon did not announce {armed_lever.ANNOUNCEMENT!r} "
                        f"at start; see {gen_log}")
            B._await_posted(self.srpc, self.args.startup_timeout)
            timeout = getattr(self.args, "gen_timeout", _GEN_TIMEOUT_S)
            resp = B._rpc(self.srpc, "generateblocks", {"count": count}, timeout=timeout)
            if resp.get("result", {}).get("status") != "OK":
                B._fail(f"generateblocks refused: {json.dumps(resp)[:300]}")
            return B._rpc(self.srpc, "get_info")["result"]["height"]

    def lay_fork(self, seed_dir, fork_dir, blocks, fork_depth, address, fork_address):
        """A shared prefix, then a main tip and a heavier fork of it.

        Returns `(prefix, main_tip, fork_tip)` as a block count and two tip
        indices. `blocks` is the main chain's length.
        """
        prefix = blocks - fork_depth
        if prefix < 1:
            B._fail(f"fork depth {fork_depth} leaves no shared prefix of a {blocks}-block chain")
        self.prefix = prefix
        for directory in (seed_dir, fork_dir):
            shutil.rmtree(directory, ignore_errors=True)
            os.makedirs(directory)
        self.generate(seed_dir, prefix, address)
        shutil.rmtree(fork_dir)
        shutil.copytree(seed_dir, fork_dir)
        main_tip = published_tip(self.generate(seed_dir, fork_depth, address))
        fork_tip = published_tip(self.generate(fork_dir, fork_depth + 2, fork_address))
        if main_tip is None or fork_tip is None:
            B._fail("a laid chain published no tip")
        return prefix, main_tip, fork_tip

    def observed_tip(self, rpc, timeout=60):
        """The tip index this daemon's get_info has published."""
        height = B._rpc(rpc, "get_info", timeout=timeout)["result"]["height"]
        return published_tip(height)

    def headers(self, rpc, start, end):
        """Headers from `start` through `end`, one range per call."""
        body = B._rpc(rpc, "get_block_headers_range",
                      {"start_height": start, "end_height": end})
        result = body.get("result") or {}
        if result.get("status") != "OK":
            B._fail(f"get_block_headers_range {start}..{end} refused: {json.dumps(body)[:300]}")
        return result.get("headers") or []

    def record_hashes(self, chain_key, rpc, top):
        """Block hashes from the fork point through `top`, for chain_of."""
        if self.prefix is None or top < self.prefix:
            return
        for start, end in header_spans(self.prefix, top):
            for hdr in self.headers(rpc, start, end):
                self.hashes[chain_key][int(hdr["height"])] = hdr["hash"]

    def tx_counts(self, rpc, start, end):
        """`num_txes` on every header from `start` through `end`.

        The field is the non-coinbase count (`transaction_hashes.len()`).
        """
        counts = []
        for start_at, end_at in header_spans(start, end):
            by_height = {int(hdr["height"]): int(hdr["num_txes"])
                         for hdr in self.headers(rpc, start_at, end_at)}
            for height in range(start_at, end_at + 1):
                if height not in by_height:
                    B._fail(f"header {height} was absent from {start_at}..{end_at}")
                counts.append(by_height[height])
        return counts

    def chain_of(self, tip, tip_hash):
        """Which served chain `tip` is on, or None when its hash is on neither.

        Below the fork point the two chains are one, and that one is main.
        """
        if self.prefix is not None and tip < self.prefix:
            return "main"
        for key, hashes in self.hashes.items():
            if hashes.get(tip) == tip_hash:
                return key
        return None

    def store_digest(self, store):
        """The replay tool's read of `store`: tip, hash and logical-state digest."""
        out = subprocess.run([self.replay, "digest", "--store", store, *REPLAY_CHAIN],
                             check=True, capture_output=True, text=True).stdout
        return json.loads(out)

    def digest_chain(self, seed_rpc, chain_key, tip):
        """One fetch and one baseline of `chain_key` through `tip`.

        The baseline is asked for a digest at every height, which forces a
        window of one commit. The rows are the store's own
        `logical_state_digest_v0`. The walk's directory is removed, store
        file included.
        """
        directory = os.path.join(self.work, f"digest-{chain_key}")
        shutil.rmtree(directory, ignore_errors=True)
        os.makedirs(directory)
        try:
            corpus = os.path.join(directory, "corpus.e2")
            store_dir = os.path.join(directory, "store")
            os.makedirs(store_dir)
            store = os.path.join(store_dir, "chain.db")
            table_path = os.path.join(directory, "digests.json")
            subprocess.run([self.replay, "fetch", "--daemon", f"http://127.0.0.1:{seed_rpc}",
                            *REPLAY_CHAIN, "--from", "0", "--to", str(tip + 1),
                            "--out", corpus], check=True, capture_output=True)
            subprocess.run([self.replay, "baseline", "--corpus", corpus, "--store", store,
                            *REPLAY_CHAIN, "--out", os.path.join(directory, "trace.e2"),
                            "--digests-out", table_path],
                           check=True, capture_output=True)
            with open(table_path, encoding="utf-8") as fh:
                table = json.load(fh)
            if table.get("schema") != HEIGHT_DIGESTS_SCHEMA:
                B._fail(f"digest walk of {chain_key} wrote schema {table.get('schema')!r}, "
                        f"expected {HEIGHT_DIGESTS_SCHEMA!r}")
            got = {int(row["height"]): row["digest"] for row in table.get("rows") or []}
            missing = [height for height in range(tip + 1) if height not in got]
            if missing:
                B._fail(f"digest walk of {chain_key} omitted {len(missing)} height(s) "
                        f"through {tip}, first {missing[:5]}")
            self.digests[chain_key] = got
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def expected_digest(self, chain_key, tip):
        """The digest `digest_chain` recorded at `tip`, or None."""
        return self.digests.get(chain_key, {}).get(tip)


def _selftest():
    fails = []

    def check(name, got, want):
        check.names.append(name)
        if got != want:
            fails.append(f"{name}: got {got!r}, want {want!r}")

    check.names = []
    check("an empty chain has no tip", published_tip(0), None)
    check("a chain of one block has published block 0", published_tip(1), 0)
    check("the tip index is the length minus one", published_tip(5040), 5039)
    check("a bool is not a height", published_tip(True), None)
    check("one cap is one span", header_spans(0, HEADER_RANGE - 1), [(0, HEADER_RANGE - 1)])
    check("one past the cap is a second span",
          header_spans(0, HEADER_RANGE), [(0, HEADER_RANGE - 1), (HEADER_RANGE, HEADER_RANGE)])
    check("an empty range is no span", header_spans(5, 4), [])
    if fails:
        for failure in fails:
            print("FAIL", failure, file=sys.stderr)
        sys.exit(1)
    print(f"regtest session selftest: {len(check.names)} cases OK")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if argv == ["--selftest"]:
        _selftest()
        return
    print("drs_regtest: the session the durability harnesses compose; "
          "run a harness, or --selftest", file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    main()
