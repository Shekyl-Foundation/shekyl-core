#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause

import json
import os
import pathlib
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capture_kept_chain as K  # noqa: E402
import rpc_capture as C  # noqa: E402


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(n).decode())
        params = body.get("params")
        height = params.get("height") if isinstance(params, dict) else None
        reply = {"jsonrpc": "2.0", "id": body.get("id"), "result": {
            "method": body.get("method"), "params": params, "height": height,
            "sent": body}}
        raw = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt, *args):
        return


class Capture(unittest.TestCase):
    def test_one_file_per_request_keeps_the_raw_reply(self):
        server = HTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            out = tempfile.mkdtemp(prefix="rpc-capture-")
            n = C.capture(
                f"http://127.0.0.1:{port}",
                [{"method": "block_show", "params": {"height": 0}}],
                out)
            self.assertEqual(n, 1)
            with open(os.path.join(out, "000-block_show.json"), encoding="utf-8") as fh:
                got = json.load(fh)
            self.assertEqual(got["method"], "block_show")
            self.assertEqual(got["params"], {"height": 0})
            self.assertEqual(got["response"]["result"]["height"], 0)
            with open(os.path.join(out, "omitted.json"), encoding="utf-8") as fh:
                omitted = json.load(fh)
            methods = [row["method"] for row in omitted]
            self.assertIn("dev_block_generate", methods)
            self.assertIn("peer_connections", methods)
            # No transaction id was given: both transaction reads are named.
            self.assertIn("tx_show", methods)
            self.assertIn("tx_list", methods)
        finally:
            server.shutdown()
            server.server_close()

    def test_chain_requests_cover_genesis_tip_and_past_the_tip(self):
        # The tip height is an ordinal: the tip block is at 96.
        reqs = C.chain_requests(96, "ab" * 32, "cd" * 32)
        heights = [r["params"].get("height") for r in reqs
                   if r["method"] == "block_show"]
        self.assertEqual(heights, [0, 96, 106])
        listed = [r["params"]["height"] for r in reqs if r["method"] == "block_list"]
        self.assertEqual(listed, [[0, 96, 106]])

    def test_a_genesis_only_chain_is_a_chain(self):
        reqs = C.chain_requests(0, "ab" * 32, "ab" * 32)
        ranges = [r["params"] for r in reqs if r["method"] == "block_header_list"
                  and "from" in r["params"]]
        self.assertEqual(ranges, [{"from": 0, "to": 0}])

    def test_a_height_that_is_not_an_ordinal_is_refused(self):
        for height in (-1, True, None, 1.0):
            with self.subTest(height=height):
                with self.assertRaises(ValueError):
                    C.chain_requests(height, "ab" * 32, "cd" * 32)

    def test_every_table_row_is_asked_or_named_omitted(self):
        """The daemon's method table is the schema's `method` rows. Each is
        asked by the capture or named in OMITTED with its reason, never
        both and never neither; nothing else is asked."""
        schema = pathlib.Path(__file__).resolve().parents[2] / \
            "docs" / "generated" / "rpc_wire_schema.tsv"
        table = set()
        for line in schema.read_text(encoding="utf-8").splitlines():
            cells = line.split("\t")
            if len(cells) > 1 and cells[1] == "method":
                table.add(cells[0])
        self.assertEqual(len(table), 42)
        asked = {r["method"] for r in C.chain_requests(5, "ab" * 32, "cd" * 32, "ee" * 32)}
        omitted = [m for m, _ in C.OMITTED]
        self.assertEqual(len(omitted), len(set(omitted)))
        self.assertEqual(asked & set(omitted), set())
        self.assertEqual(asked | set(omitted), table)

    def test_a_request_is_one_method_and_its_params(self):
        out = tempfile.mkdtemp(prefix="rpc-capture-")
        with self.assertRaises(ValueError):
            C.capture("http://127.0.0.1:1",
                      [{"kind": "rest", "method": "/get_info", "params": {}}],
                      out, timeout=1)
        self.assertEqual(os.listdir(out), [])

    def test_reserved_ports_are_distinct_loopback_ports(self):
        ports, held = C.reserve_loopback_ports(3)
        try:
            self.assertEqual(len(ports), 3)
            self.assertEqual(len(set(ports)), 3)
            for sk, port in zip(held, ports):
                self.assertEqual(sk.getsockname()[:2], ("127.0.0.1", port))
        finally:
            for sk in held:
                sk.close()

    def test_a_port_count_that_is_not_a_count_is_refused(self):
        for n in (0, -1, True, None):
            with self.subTest(n=n):
                with self.assertRaises(ValueError):
                    C.reserve_loopback_ports(n)

    def test_a_missing_replies_directory_is_this_runs(self):
        parent = tempfile.mkdtemp(prefix="rpc-capture-")
        missing = os.path.join(parent, "replies")
        self.assertIsNone(C.occupied_replies_refusal(missing))

    def test_a_replies_directory_that_already_holds_a_capture_is_refused(self):
        """The previous run asked for a transaction. This run does not, so
        its omitted list would say `tx_show` was not requested
        while the old reply file still sat beside it. The stale file stays,
        and nothing from this run is written."""
        out = tempfile.mkdtemp(prefix="rpc-capture-")
        stale = os.path.join(out, "000-tx_show.json")
        stale_body = '{"stale": true}\n'
        with open(stale, "w", encoding="utf-8") as fh:
            fh.write(stale_body)
        with self.assertRaises(ValueError) as caught:
            C.capture(
                "http://127.0.0.1:1",
                [{"method": "block_show", "params": {"height": 0}}],
                out,
                timeout=1)
        self.assertIn(out, str(caught.exception))
        self.assertIn("mix replies from two runs", str(caught.exception))
        with open(stale, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), stale_body)
        self.assertFalse(os.path.exists(os.path.join(out, "000-block_show.json")))
        self.assertFalse(os.path.exists(os.path.join(out, "omitted.json")))

    def test_json_rpc_sends_one_strict_envelope(self):
        """JSON-RPC 2.0 with a numeric id. A method with no parameters
        leaves `params` out; an empty object is still sent as one."""
        server = HTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}"
            bare = C.json_rpc(url, "chain_height", timeout=5)
            empty = C.json_rpc(url, "option_show", {}, timeout=5)
            self.assertEqual(bare["id"], 0)
            self.assertNotIn("params", bare["result"]["sent"])
            self.assertEqual(bare["result"]["sent"]["jsonrpc"], "2.0")
            self.assertEqual(empty["result"]["params"], {})
        finally:
            server.shutdown()
            server.server_close()


class KeptDatadir(unittest.TestCase):
    def test_a_directory_that_holds_a_fixture_is_the_subject(self):
        parent = tempfile.mkdtemp(prefix="kept-datadir-")
        data = os.path.join(parent, "data")
        os.mkdir(data)
        with open(os.path.join(data, "chain"), "w", encoding="utf-8") as fh:
            fh.write("kept\n")
        self.assertIsNone(K.kept_datadir_refusal(data))

    def test_a_missing_kept_datadir_is_refused_before_the_output_exists(self):
        """The daemon creates a missing data directory and opens genesis in
        it. The height check would then accept that chain. The refusal comes
        before the output directory, so a mistyped path leaves nothing."""
        parent = tempfile.mkdtemp(prefix="kept-datadir-")
        data = os.path.join(parent, "missing")
        out = os.path.join(parent, "out")
        argv = sys.argv
        try:
            sys.argv = ["capture_kept_chain", os.path.join(parent, "shekyld"), data, out]
            with self.assertRaises(SystemExit) as caught:
                K.main()
        finally:
            sys.argv = argv
        self.assertIn(data, str(caught.exception))
        self.assertIn("does not exist", str(caught.exception))
        self.assertIn("genesis", str(caught.exception))
        self.assertFalse(os.path.exists(out))
        self.assertFalse(os.path.exists(data))

    def test_an_empty_directory_is_not_a_kept_fixture(self):
        parent = tempfile.mkdtemp(prefix="kept-datadir-")
        data = os.path.join(parent, "empty")
        os.mkdir(data)
        reason = K.kept_datadir_refusal(data)
        self.assertIn("empty", reason)
        self.assertIn("genesis", reason)

    def test_a_file_is_not_a_kept_data_directory(self):
        parent = tempfile.mkdtemp(prefix="kept-datadir-")
        data = os.path.join(parent, "file")
        with open(data, "w", encoding="utf-8") as fh:
            fh.write("x")
        self.assertIn("not a directory", K.kept_datadir_refusal(data))


if __name__ == "__main__":
    unittest.main()
