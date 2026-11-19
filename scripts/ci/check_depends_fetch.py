#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Depends fetches a source from the Foundation's mirror, then the
package's own path, then its alternates, and keeps only bytes that match
the pinned hash.

# What is held (Rick, 2026-11-19)

A release build must not depend on one upstream host answering at the
moment it runs: download.freebsd.org timed out on two gitian runs on
2026-11-18, and the inherited fallback (Monero's mirror) answered 404.
`contrib/depends/funcs.mk`'s `fetch_file` tries `MIRROR_DOWNLOAD_PATH`
first, then the package's own download path, then each of its
`_download_path_alternates` in order. Every fetch checks the package's
pinned SHA-256 before the file is kept, so bytes that fail it fall through
to the next host. `freebsd_base` names FreeBSD's community mirrors as its
alternates.

The selftest runs depends' own fetch (`make download-one`) in a scratch
copy of `contrib/depends` with one planted package, against local HTTP
servers, and needs no network:

  1. The mirror holds the file: fetched from it, no other host asked.
  2. The mirror lacks it, the package's path holds it: fetched from there.
  3. The mirror refuses, the package's path holds it: fetched from there.
  4. The mirror's file has one byte changed, the package's path holds it:
     fetched from the package's path; the changed bytes are never kept.
  5. The mirror lacks it, the package's path refuses, both alternates hold
     it: the first serves it.
  6. As 5, but the first alternate lacks it: the second serves it.
  7. As 5, but the one alternate holding it has one byte changed: the fetch
     fails and keeps nothing.
  8. No host holds it: the fetch fails.

It also checks that no depends file names the retired Monero mirror, and
that `freebsd_base` declares alternates.

# Rule 47

Each case asserts its subject: the server logs show which host served the
file and that no later host was asked, and a passing case's file is read
back and hashed.
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
ORDER = ("mirror", "primary", "first", "second")
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


def fetch(tmp: Path, mirror: str, primary: str, alternates: list[str], digest: str) -> tuple[int, str, Path]:
    """Run depends' fetch for the planted package; the kept file's path."""
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
            all_hold = (PAYLOAD, PAYLOAD, PAYLOAD, PAYLOAD)
            cases = [
                # label, files on (mirror, primary, first, second), mirror url,
                # primary url, want ok, served by. A host after the one that
                # serves holds the file too, so "served by" is the order, not
                # the only host that answered.
                ("the mirror holds the file", all_hold, url["mirror"], url["primary"], True, "mirror"),
                ("the mirror lacks it, the package's path holds it",
                 (None, PAYLOAD, PAYLOAD, PAYLOAD), url["mirror"], url["primary"], True, "primary"),
                ("the mirror refuses, the package's path holds it",
                 (None, PAYLOAD, PAYLOAD, PAYLOAD), blocked, url["primary"], True, "primary"),
                ("the mirror's file has one byte changed, the package's path holds it",
                 (changed, PAYLOAD, PAYLOAD, PAYLOAD), url["mirror"], url["primary"], True, "primary"),
                ("the mirror lacks it, the package's path refuses, both alternates hold it",
                 (None, None, PAYLOAD, PAYLOAD), url["mirror"], blocked, True, "first"),
                ("the mirror lacks it, the package's path refuses, the first alternate lacks it",
                 (None, None, None, PAYLOAD), url["mirror"], blocked, True, "second"),
                ("the only alternate holding it has one byte changed",
                 (None, None, changed, None), url["mirror"], blocked, False, None),
                ("no host holds it", (None, None, None, None), url["mirror"], url["primary"], False, None),
            ]
            for label, bodies, mirror, primary, want_ok, served_by in cases:
                for key, body in zip(ORDER, bodies):
                    path = roots[key] / NAME
                    if path.exists():
                        path.unlink()
                    if body is not None:
                        path.write_bytes(body)
                SERVED.clear()
                rc, out, kept = fetch(tmp, mirror, primary, [url["first"], url["second"]], digest)
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
        print(f"selftest: {len(cases)} fetch cases in the order mirror, package path, alternates; no depends "
              f"file names the retired mirror; freebsd_base has {len(alternates.group(1).split())} alternate(s)")
    return failed


if __name__ == "__main__":
    raise SystemExit(selftest())
