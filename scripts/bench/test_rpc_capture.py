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
        reply = {"jsonrpc": "2.0", "id": body.get("id"), "result": {
            "method": body.get("method"), "height": body.get("params", {}).get("height")}}
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

    def test_chain_requests_cover_genesis_tip_and_past_the_tip(self):
        reqs = C.chain_requests(97, "ab" * 32, "cd" * 32)
        heights = [r["params"].get("height") for r in reqs
                   if r["method"] == "get_block"]
        self.assertEqual(heights, [0, 96, 107])

    def test_an_empty_chain_is_refused(self):
        with self.assertRaises(ValueError):
            C.chain_requests(0, "ab" * 32, "cd" * 32)


if __name__ == "__main__":
    unittest.main()
