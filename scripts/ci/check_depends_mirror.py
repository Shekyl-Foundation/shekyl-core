#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Depends fetches from the Foundation's sources mirror first, and keeps
only bytes that match the pinned hash.

# What is held (Rick, 2026-11-19)

A release build must not depend on an upstream host answering at the
moment it runs: download.freebsd.org timed out on two gitian runs on
2026-11-18, and the inherited fallback (Monero's mirror) answered 404.
`contrib/depends/funcs.mk`'s `fetch_file` now tries `MIRROR_DOWNLOAD_PATH`
first and the package's own download path second, and both fetches check
the package's pinned SHA-256 before the file is kept.

The selftest runs depends' own fetch (`make download-one`) in a scratch
copy of `contrib/depends` with one planted package, against two local
HTTP servers, and needs no network:

  1. Upstream blocked, the mirror holds the file: the fetch succeeds, from
     the mirror, and the kept file has the pinned hash.
  2. Upstream blocked, the mirror's file has one byte changed: the fetch
     fails and keeps nothing.
  3. The mirror lacks the file, upstream serves it: the fetch falls back
     and succeeds.
  4. Neither holds it: the fetch fails.

It also checks that no depends file names the retired Monero mirror.

# Rule 47

Each case asserts its subject: the planted package is the only one
fetched, the server logs show which host served it, and a passing case's
file is read back and hashed.
"""

from __future__ import annotations

import functools
import hashlib
import http.server
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEPENDS = REPO / "contrib" / "depends"
PAYLOAD = b"shekyl depends mirror selftest payload\n" * 64
NAME = "zzmirror-1.tar.gz"
RETIRED = "getmonero"


class Quiet(http.server.SimpleHTTPRequestHandler):
    served: list[str] = []

    def log_message(self, *args: object) -> None:  # noqa: D401 - silence
        pass

    def do_GET(self) -> None:  # noqa: N802 - stdlib name
        Quiet.served.append(f"{self.server.server_address[1]}{self.path}")
        super().do_GET()


def serve(root: Path) -> tuple[http.server.ThreadingHTTPServer, int]:
    handler = functools.partial(Quiet, directory=str(root))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def closed_port() -> int:
    """A port nothing listens on: an upstream that refuses at once."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
    port = server.server_address[1]
    server.server_close()
    return port


def fetch(tmp: Path, mirror: str, upstream: str, digest: str) -> tuple[int, str, Path]:
    """Run depends' fetch for the planted package; the kept file's path."""
    depends = tmp / "depends"
    if depends.exists():
        shutil.rmtree(depends)
    shutil.copytree(DEPENDS, depends, ignore=shutil.ignore_patterns("sources", "built", "work", "x86_64-*"))
    (depends / "packages" / "packages.mk").write_text("packages := zzmirror\n", encoding="utf-8")
    (depends / "packages" / "zzmirror.mk").write_text(
        "package=zzmirror\n"
        "$(package)_version=1\n"
        f"$(package)_download_path={upstream}\n"
        f"$(package)_file_name={NAME}\n"
        f"$(package)_sha256_hash={digest}\n",
        encoding="utf-8",
    )
    sources = tmp / "sources"
    if sources.exists():
        shutil.rmtree(sources)
    proc = subprocess.run(
        ["make", "-C", str(depends), "download-one", "HOST=x86_64-unknown-linux-gnu",
         f"SOURCES_PATH={sources}", f"MIRROR_DOWNLOAD_PATH={mirror}"],
        capture_output=True,
        text=True,
        env=dict(os.environ, MAKEFLAGS=""),
    )
    return proc.returncode, proc.stdout + proc.stderr, sources / NAME


def selftest() -> int:
    failed = 0
    digest = hashlib.sha256(PAYLOAD).hexdigest()
    with tempfile.TemporaryDirectory() as tmp_name:
        tmp = Path(tmp_name)
        mirror_root, upstream_root = tmp / "mirror", tmp / "upstream"
        mirror_root.mkdir()
        upstream_root.mkdir()
        mirror, mport = serve(mirror_root)
        upstream, uport = serve(upstream_root)
        blocked = f"http://127.0.0.1:{closed_port()}"
        mirror_url, upstream_url = f"http://127.0.0.1:{mport}", f"http://127.0.0.1:{uport}"
        try:
            cases = [
                ("upstream blocked, the mirror holds the file", PAYLOAD, None, blocked, True, mport),
                ("upstream blocked, the mirror's file has one byte changed",
                 bytes([PAYLOAD[0] ^ 1]) + PAYLOAD[1:], None, blocked, False, None),
                ("the mirror lacks the file, upstream serves it", None, PAYLOAD, upstream_url, True, uport),
                ("neither holds it", None, None, upstream_url, False, None),
            ]
            for label, on_mirror, on_upstream, up, want_ok, served_by in cases:
                for root, body in ((mirror_root, on_mirror), (upstream_root, on_upstream)):
                    path = root / NAME
                    if path.exists():
                        path.unlink()
                    if body is not None:
                        path.write_bytes(body)
                Quiet.served.clear()
                rc, out, kept = fetch(tmp, mirror_url, up, digest)
                ok = rc == 0 and kept.is_file() and hashlib.sha256(kept.read_bytes()).hexdigest() == digest
                if want_ok and served_by is not None:
                    ok = ok and any(s.startswith(f"{served_by}/") and s.endswith(NAME) for s in Quiet.served)
                if not want_ok:
                    ok = rc != 0 and not kept.exists()
                if not ok:
                    print(f"selftest FAIL: {label}: make exited {rc}, kept {kept.exists()}, "
                          f"served {Quiet.served}\n{out[-1500:]}")
                    failed = 1
        finally:
            mirror.shutdown()
            upstream.shutdown()
    # The retired fallback is named nowhere in depends.
    named = [str(p.relative_to(REPO)) for p in DEPENDS.rglob("*")
             if p.is_file() and RETIRED in p.read_text(encoding="utf-8", errors="replace")]
    if named:
        print(f"selftest FAIL: the retired Monero mirror is still named in {named}")
        failed = 1
    if not failed:
        print("selftest: 4 fetch cases, and no depends file names the retired mirror")
    return failed


if __name__ == "__main__":
    raise SystemExit(selftest())
