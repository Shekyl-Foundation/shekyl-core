#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause

import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rpc_capture as C  # noqa: E402


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(n).decode())
        params = body.get("params")
        height = params.get("height") if isinstance(params, dict) else None
        reply = {"jsonrpc": "2.0", "id": body.get("id"), "result": {
            "method": body.get("method"), "params": params, "height": height}}
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
                [{"kind": "json", "method": "get_block", "params": {"height": 0}}],
                out)
            self.assertEqual(n, 1)
            with open(os.path.join(out, "000-get_block.json"), encoding="utf-8") as fh:
                got = json.load(fh)
            self.assertEqual(got["method"], "get_block")
            self.assertEqual(got["params"], {"height": 0})
            self.assertEqual(got["response"]["result"]["height"], 0)
            with open(os.path.join(out, "omitted.json"), encoding="utf-8") as fh:
                omitted = json.load(fh)
            methods = [row["method"] for row in omitted]
            self.assertIn("generateblocks", methods)
            self.assertIn("get_connections", methods)
        finally:
            server.shutdown()
            server.server_close()

    def test_chain_requests_cover_genesis_tip_and_past_the_tip(self):
        reqs = C.chain_requests(97, "ab" * 32, "cd" * 32)
        heights = [r["params"].get("height") for r in reqs
                   if r["method"] == "get_block"]
        self.assertEqual(heights, [0, 96, 107])

    def test_an_empty_chain_is_refused(self):
        with self.assertRaises(ValueError):
            C.chain_requests(0, "ab" * 32, "cd" * 32)

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

    def test_json_rpc_keeps_a_positional_params_list(self):
        """`on_get_block_hash` takes a list. An empty list is still a list:
        coercing it to an object would ask a different question."""
        server = HTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}"
            filled = C.json_rpc(url, "on_get_block_hash", [96], timeout=5)
            empty = C.json_rpc(url, "on_get_block_hash", [], timeout=5)
            self.assertEqual(filled["result"]["params"], [96])
            self.assertEqual(empty["result"]["params"], [])
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
