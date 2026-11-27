#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The wait in posted_template.py. No daemon: a stub answers `block_template`
# with the daemon's refusal until it has "posted", then with a template. The
# defect is a wait that takes a refusal, or another answer, as ready, or one
# that never ends.

import http.server
import json
import os
import subprocess
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import posted_template  # noqa: E402

NOT_SYNCED = {
    "code": -32004,
    "message": "no template: not synced (no view of the network yet)",
    "data": {"code": "mine.syncing", "parameter": {"sync": "no_view"}},
}


class Stub:
    """A `/json_rpc` that refuses `block_template` for its first `refusals`
    calls (all of them when None), then answers with a template."""

    def __init__(self, refusals):
        self.calls = 0
        stub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                assert request["method"] == "block_template", request
                stub.calls += 1
                posted = refusals is not None and stub.calls > refusals
                reply = {"jsonrpc": "2.0", "id": 0}
                if posted:
                    reply["result"] = {"height": 1}
                else:
                    reply["error"] = NOT_SYNCED
                data = json.dumps(reply).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/json_rpc"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class AwaitPosted(unittest.TestCase):
    def test_waits_through_the_refusals_for_the_first_template(self):
        stub = Stub(refusals=3)
        try:
            posted_template.await_posted(stub.url, timeout_s=10)
            self.assertEqual(stub.calls, 4, "three refusals, then the template")
        finally:
            stub.close()

    def test_a_daemon_that_never_posts_fails_with_its_refusal(self):
        stub = Stub(refusals=None)
        try:
            with self.assertRaises(RuntimeError) as raised:
                posted_template.await_posted(stub.url, timeout_s=0.5)
            self.assertIn("no_view", str(raised.exception))
        finally:
            stub.close()

    def test_no_daemon_at_all_fails_within_the_bound(self):
        stub = Stub(refusals=None)
        url = stub.url
        stub.close()
        with self.assertRaises(RuntimeError):
            posted_template.await_posted(url, timeout_s=0.5)

    def test_the_command_line_verdict_is_the_exit_status(self):
        script = os.path.join(HERE, "posted_template.py")
        stub = Stub(refusals=1)
        try:
            posted = subprocess.run([sys.executable, script, stub.url, "10"], check=False)
            self.assertEqual(posted.returncode, 0)
        finally:
            stub.close()
        stub = Stub(refusals=None)
        try:
            refused = subprocess.run(
                [sys.executable, script, stub.url, "0.5"], check=False, capture_output=True)
            self.assertEqual(refused.returncode, 1)
        finally:
            stub.close()


if __name__ == "__main__":
    unittest.main()
