#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Depends falls back to a package's alternate download paths, and keeps
only bytes that match the pinned hash.

# What is held (Rick, 2026-11-19)

Two gitian runs on 2026-11-18 failed in the FreeBSD job: download.freebsd.org
timed out, and the inherited fallback (Monero's depends mirror) answered 404.
`contrib/depends/funcs.mk`'s `fetch_file` now tries the package's own
download path, then each of its `_download_path_alternates` in order, and
every fetch checks the pinned SHA-256 before the file is kept.
`freebsd_base` names FreeBSD's community mirrors as its alternates.

The selftest runs depends' own fetch (`make download-one`) in a scratch copy
of `contrib/depends` with one planted package, against local HTTP servers,
and needs no network:

  1. The primary blocked, an alternate holds the file: fetched from it, and
     the kept file has the pinned hash.
  2. The primary blocked, the alternate's file has one byte changed: the
     fetch fails and keeps nothing.
  3. The primary blocked, the first alternate lacks the file, the second
     holds it: fetched from the second.
  4. The primary serves it: fetched from the primary, no alternate asked.
  5. No host holds it: the fetch fails.

It also checks that no depends file names the retired Monero mirror, and
that `freebsd_base` declares alternates.

# Rule 47

Each case asserts its subject: the server logs show which host served the
file, and a passing case's file is read back and hashed.
"""

from __future__ import annotations

import functools
import hashlib
import http.server
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEPENDS = REPO / "contrib" / "depends"
PAYLOAD = b"shekyl depends fetch selftest payload\n" * 64
NAME = "zzfetch-1.tar.gz"
RETIRED = "getmonero"
# The hosts in the order `fetch_file` must try them.
ORDER = ("primary", "first", "second")
SERVED: list[str] = []


class Logged(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802 - stdlib name
        SERVED.append(f"{self.server.server_address[1]}{self.path}")
        super().do_GET()


def serve(root: Path) -> tuple[http.server.ThreadingHTTPServer, int]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Logged, directory=str(root)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def closed_port() -> int:
    """A port nothing listens on: a host that refuses at once."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Logged)
    port = server.server_address[1]
    server.server_close()
    return port


def fetch(tmp: Path, primary: str, alternates: list[str], digest: str) -> tuple[int, str, Path]:
    depends = tmp / "depends"
    if depends.exists():
        shutil.rmtree(depends)
    shutil.copytree(DEPENDS, depends, ignore=shutil.ignore_patterns("sources", "built", "work", "x86_64-*"))
    (depends / "packages" / "packages.mk").write_text("packages := zzfetch\n", encoding="utf-8")
    (depends / "packages" / "zzfetch.mk").write_text(
        "package=zzfetch\n"
        "$(package)_version=1\n"
        f"$(package)_download_path={primary}\n"
        f"$(package)_download_path_alternates={' '.join(alternates)}\n"
        f"$(package)_file_name={NAME}\n"
        f"$(package)_sha256_hash={digest}\n",
        encoding="utf-8",
    )
    sources = tmp / "sources"
    if sources.exists():
        shutil.rmtree(sources)
    proc = subprocess.run(
        ["make", "-C", str(depends), "download-one", "HOST=x86_64-unknown-linux-gnu", f"SOURCES_PATH={sources}"],
        capture_output=True,
        text=True,
        env=dict(os.environ, MAKEFLAGS=""),
    )
    return proc.returncode, proc.stdout + proc.stderr, sources / NAME


def selftest() -> int:
    failed = 0
    digest = hashlib.sha256(PAYLOAD).hexdigest()
    changed = bytes([PAYLOAD[0] ^ 1]) + PAYLOAD[1:]
    with tempfile.TemporaryDirectory() as tmp_name:
        tmp = Path(tmp_name)
        roots = {k: tmp / k for k in ORDER}
        servers, ports = {}, {}
        for key, root in roots.items():
            root.mkdir()
            servers[key], ports[key] = serve(root)
        url = {k: f"http://127.0.0.1:{p}" for k, p in ports.items()}
        blocked = f"http://127.0.0.1:{closed_port()}"
        try:
            cases = [
                # label, files on (primary, first, second), primary url, want ok, served by
                # Both alternates hold it, so the first served and the second
                # never asked is the order, not the only host that answered.
                ("the primary blocked, both alternates hold the file: the first serves it",
                 (None, PAYLOAD, PAYLOAD), blocked, True, "first"),
                ("the primary blocked, the alternate's file has one byte changed",
                 (None, changed, None), blocked, False, None),
                ("the primary blocked, the first alternate lacks it, the second holds it",
                 (None, None, PAYLOAD), blocked, True, "second"),
                ("the primary serves it", (PAYLOAD, PAYLOAD, PAYLOAD), url["primary"], True, "primary"),
                ("no host holds it", (None, None, None), url["primary"], False, None),
            ]
            for label, bodies, primary, want_ok, served_by in cases:
                for key, body in zip(ORDER, bodies):
                    path = roots[key] / NAME
                    if path.exists():
                        path.unlink()
                    if body is not None:
                        path.write_bytes(body)
                SERVED.clear()
                rc, out, kept = fetch(tmp, primary, [url["first"], url["second"]], digest)
                if want_ok:
                    ok = rc == 0 and kept.is_file() and hashlib.sha256(kept.read_bytes()).hexdigest() == digest
                    hit = [s for s in SERVED if s.endswith(NAME)]
                    ok = ok and bool(hit) and hit[-1].startswith(f"{ports[served_by]}/")
                    # The order: no host after the one that served was asked.
                    later = ORDER[ORDER.index(served_by) + 1:]
                    ok = ok and not any(s.startswith(f"{ports[k]}/") for k in later for s in hit)
                else:
                    ok = rc != 0 and not kept.exists()
                if not ok:
                    print(f"selftest FAIL: {label}: make exited {rc}, kept {kept.exists()}, served {SERVED}\n{out[-1500:]}")
                    failed = 1
        finally:
            for server in servers.values():
                server.shutdown()
    named = [str(p.relative_to(REPO)) for p in DEPENDS.rglob("*")
             if p.is_file() and RETIRED in p.read_text(encoding="utf-8", errors="replace")]
    if named:
        print(f"selftest FAIL: the retired Monero mirror is still named in {named}")
        failed = 1
    freebsd = (DEPENDS / "packages" / "freebsd_base.mk").read_text(encoding="utf-8")
    alternates = re.search(r"^\$\(package\)_download_path_alternates=(.+)$", freebsd, re.M)
    if not alternates or not alternates.group(1).split():
        print("selftest FAIL: freebsd_base.mk declares no alternate download paths")
        failed = 1
    if not failed:
        print(f"selftest: 5 fetch cases; no depends file names the retired mirror; "
              f"freebsd_base has {len(alternates.group(1).split())} alternate(s)")
    return failed


if __name__ == "__main__":
    raise SystemExit(selftest())
