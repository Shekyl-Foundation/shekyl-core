# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Self-test for the two Tor pin gates: scripts/release/tor_bundle.py (what the
# packaging job runs) and scripts/ci/check_tor_pin_targets.py. Each refusal is
# bitten red by the one edit that should cause it, starting from a state that
# passes, so a gate that has stopped looking is seen here and not in a release.
#
# The bundle is a fabricated tarball in the Expert Bundle's layout (`tor/`
# with the binaries and a `pluggable_transports/` directory Shekyl does not
# ship, `docs/` with the licence texts), pinned by a pin file written to match.
# No real tor is needed and nothing is fetched: `stage` finds the tarball in
# `--sources`.

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOR_BUNDLE = REPO / "scripts" / "release" / "tor_bundle.py"
TARGETS_GATE = REPO / "scripts" / "ci" / "check_tor_pin_targets.py"

HOST = "x86_64-linux-gnu"
MEMBERS = {
    "tor/tor": b"the tor executable",
    "tor/libevent-2.1.so.7": b"libevent",
    "tor/libssl.so.3": b"libssl",
    "tor/libcrypto.so.3": b"libcrypto",
    "tor/pluggable_transports/lyrebird": b"a transport Shekyl does not ship",
    "docs/tor.txt": b"tor licence",
    "docs/libevent.txt": b"libevent licence",
    "docs/openssl.txt": b"openssl licence",
    "docs/lyrebird.txt": b"a licence for something not shipped",
}
PINNED = ["tor", "libevent-2.1.so.7", "libssl.so.3", "libcrypto.so.3"]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def make_tarball(path):
    with tarfile.open(path, "w:gz") as tar:
        for name, data in MEMBERS.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o700
            tar.addfile(info, io.BytesIO(data))
    return sha(path.read_bytes())


def base_pins(tarball_digest):
    return {
        "signing_key_fingerprint": "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290",
        "bundle_url": "https://invalid.example/{bundle_version}/{bundle_target}.tar.gz",
        "source_url": "https://invalid.example/tor-{tor_version}.tar.gz",
        "source_signature_url": "https://invalid.example/tor-{tor_version}.tar.gz.asc",
        "targets": [
            {
                "os": "linux",
                "arch": "x86_64",
                "gitian_host": HOST,
                "disposition": "pinned",
                "bundle_version": "9.9.9",
                "bundle_target": "linux-x86_64",
                "tor_version": "0.0.0.1",
                "tarball_sha256": tarball_digest,
                "executable": "tor",
                "files": [
                    {"name": name, "sha256": sha(MEMBERS[f"tor/{name}"])} for name in PINNED
                ],
                "licenses": ["docs/tor.txt", "docs/libevent.txt", "docs/openssl.txt"],
            },
            {
                "os": "linux",
                "arch": "riscv64",
                "gitian_host": "riscv64-linux-gnu",
                "disposition": "unavailable",
                "reason": "no bundle is published for it",
            },
        ],
    }


class Bench:
    """A scratch directory holding a tarball, its pin file, and room to stage."""

    def __init__(self, tmp):
        self.root = Path(tmp)
        self.sources = self.root / "sources"
        self.sources.mkdir()
        self.tarball = self.sources / "tor-expert-bundle-linux-x86_64-9.9.9.tar.gz"
        self.pins = base_pins(make_tarball(self.tarball))
        self.pins_path = self.root / "tor_pins.json"
        self.dest = self.root / "out" / "tor"
        self.licenses = self.root / "out" / "tor-licenses"
        self.write()

    def write(self):
        self.pins_path.write_text(json.dumps(self.pins), encoding="utf-8")

    def run(self, *args):
        return subprocess.run(
            [sys.executable, str(TOR_BUNDLE), "--pins", str(self.pins_path), *args],
            capture_output=True,
            text=True,
        )

    def stage(self, host=HOST):
        return self.run(
            "stage", "--host", host, "--sources", str(self.sources),
            "--dest", str(self.dest), "--licenses", str(self.licenses),
        )

    def verify(self):
        return self.run("verify", "--host", HOST, "--dir", str(self.dest))


CASES = []


def case(name):
    def deco(fn):
        CASES.append((name, fn))
        return fn
    return deco


def expect(proc, code, needle=None):
    assert proc.returncode == code, (
        f"expected exit {code}, got {proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    )
    if needle is not None:
        assert needle in proc.stdout + proc.stderr, (
            f"expected {needle!r} in the output\n{proc.stdout}\n{proc.stderr}"
        )


# --- tor_bundle.py ---------------------------------------------------------


@case("stage: a pinned tarball stages exactly the pinned files, and verifies")
def _(b):
    expect(b.stage(), 0, "staged tor 0.0.0.1")
    assert sorted(os.listdir(b.dest)) == sorted(PINNED), os.listdir(b.dest)
    assert os.stat(b.dest / "tor").st_mode & 0o777 == 0o755
    assert os.stat(b.dest / "libssl.so.3").st_mode & 0o777 == 0o644
    assert sorted(os.listdir(b.licenses)) == [
        "SOURCE.txt", "libevent.txt", "openssl.txt", "tor.txt",
    ], os.listdir(b.licenses)
    note = (b.licenses / "SOURCE.txt").read_text(encoding="utf-8")
    assert "https://invalid.example/tor-0.0.0.1.tar.gz" in note, note
    assert b.pins["targets"][0]["tarball_sha256"] in note, note
    expect(b.verify(), 0, "holds exactly the pinned bundle")


@case("stage: an edited tarball digest refuses BEFORE anything is extracted")
def _(b):
    row = b.pins["targets"][0]
    row["tarball_sha256"] = "0" * 64
    b.write()
    expect(b.stage(), 1, "is not the pinned tarball")
    assert not b.dest.exists(), "nothing may be extracted from an unverified tarball"
    assert not b.licenses.exists()


@case("stage: an edited file digest refuses, and leaves nothing staged")
def _(b):
    b.pins["targets"][0]["files"][2]["sha256"] = "0" * 64
    b.write()
    expect(b.stage(), 1, "libssl.so.3 in")
    assert not b.dest.exists(), "a file that fails its pin leaves nothing to pack"


@case("stage: the licence texts cannot share tor's directory")
def _(b):
    b.licenses = b.dest
    expect(b.stage(), 1, "cannot share tor's directory")


@case("stage: an unavailable host stages nothing and is not an error")
def _(b):
    expect(b.stage(host="riscv64-linux-gnu"), 0, "nothing staged")
    assert not b.dest.exists()
    expect(b.run("disposition", "--host", "riscv64-linux-gnu"), 0, "unavailable")
    expect(b.run("install-dir", "--host", "riscv64-linux-gnu"), 1, "is unavailable")


@case("stage: a host with no row is refused")
def _(b):
    expect(b.stage(host="sparc-unknown-linux"), 1, "no row for host")


@case("install-dir: composed from the pin's own labels")
def _(b):
    expect(b.run("install-dir", "--host", HOST), 0, "/opt/shekyl/9.9.9-linux-x86_64")


@case("verify: the packaging check fails on an edited digest")
def _(b):
    expect(b.stage(), 0)
    b.pins["targets"][0]["files"][0]["sha256"] = "f" * 64
    b.write()
    expect(b.verify(), 1, "does not match its pin")


@case("verify: fails on a file changed after staging")
def _(b):
    expect(b.stage(), 0)
    (b.dest / "libcrypto.so.3").write_bytes(b"tampered")
    expect(b.verify(), 1, "does not match its pin")


@case("verify: fails on a planted top-level file")
def _(b):
    expect(b.stage(), 0)
    (b.dest / "libz.so.1").write_bytes(b"planted")
    expect(b.verify(), 1, "'libz.so.1', which is not part of the pinned bundle")


@case("verify: fails on a planted glibc-hwcaps subdirectory")
def _(b):
    expect(b.stage(), 0)
    hwcaps = b.dest / "glibc-hwcaps" / "x86-64-v2"
    hwcaps.mkdir(parents=True)
    (hwcaps / "libz.so.1").write_bytes(b"planted")
    expect(b.verify(), 1, "'glibc-hwcaps', which is not part of the pinned bundle")


@case("verify: fails on a full extracted bundle (pluggable_transports)")
def _(b):
    for name, data in MEMBERS.items():
        out = b.root / "full" / name
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
    b.dest = b.root / "full" / "tor"
    expect(b.verify(), 1, "'pluggable_transports'")


@case("verify: fails on a pinned name that is a symlink")
def _(b):
    expect(b.stage(), 0)
    outside = b.root / "libssl.so.3"
    shutil.copy(b.dest / "libssl.so.3", outside)
    (b.dest / "libssl.so.3").unlink()
    os.symlink(outside, b.dest / "libssl.so.3")
    expect(b.verify(), 1, "is not a regular file")


@case("verify: fails on a missing pinned file")
def _(b):
    expect(b.stage(), 0)
    (b.dest / "libevent-2.1.so.7").unlink()
    expect(b.verify(), 1, "lacks the pinned file libevent-2.1.so.7")


@case("pin file: a malformed row is refused whichever host is asked for")
def _(b):
    b.pins["targets"][1].pop("reason")
    b.write()
    expect(b.stage(), 1, "states its reason")


@case("pin file: a file name that is a path is refused")
def _(b):
    b.pins["targets"][0]["files"][1]["name"] = "../libevent-2.1.so.7"
    b.write()
    expect(b.stage(), 1, "is not a plain file name")


# --- check_tor_pin_targets.py ---------------------------------------------


def targets_tree(tmp, pins=None, hosts=("x86_64-linux-gnu riscv64-linux-gnu",),
                 workflow_hosts=("x86_64-linux-gnu",), workflow_extra="",
                 checklist="Expert Bundle 9.9.9 (tor 0.0.0.1)"):
    root = Path(tmp) / "tree"
    (root / "scripts" / "release").mkdir(parents=True)
    (root / "scripts" / "ci").mkdir(parents=True)
    (root / "config").mkdir()
    (root / "contrib" / "gitian").mkdir(parents=True)
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / "docs").mkdir()
    shutil.copy(TOR_BUNDLE, root / "scripts" / "release" / TOR_BUNDLE.name)
    shutil.copy(TARGETS_GATE, root / "scripts" / "ci" / TARGETS_GATE.name)
    (root / "config" / "tor_pins.json").write_text(
        json.dumps(pins if pins is not None else base_pins("0" * 64)), encoding="utf-8"
    )
    for i, line in enumerate(hosts):
        body = "script: |\n  WRAP_DIR=$HOME/wrapped\n"
        if line is not None:
            body += f'  HOSTS="{line}"\n'
        (root / "contrib" / "gitian" / f"gitian-d{i}.yml").write_text(body, encoding="utf-8")
    (root / ".github" / "workflows" / "tor-pin-verify.yml").write_text(
        "on:\n  workflow_dispatch:\njobs:\n  verify:\n    strategy:\n      matrix:\n"
        "        target:\n"
        + "".join(f"          - host: {h}\n" for h in workflow_hosts)
        + "    steps:\n      - run: python3 scripts/release/tor_bundle.py stage\n"
        + workflow_extra,
        encoding="utf-8",
    )
    (root / "docs" / "RELEASE_CHECKLIST.md").write_text(
        f"- Current pin: **{checklist}**\n", encoding="utf-8"
    )
    return subprocess.run(
        [sys.executable, str(root / "scripts" / "ci" / TARGETS_GATE.name), "--root", str(root)],
        capture_output=True,
        text=True,
    )


TARGET_CASES = []


def tcase(name):
    def deco(fn):
        TARGET_CASES.append((name, fn))
        return fn
    return deco


@tcase("targets: hosts, workflow and checklist all agree")
def _(tmp):
    expect(targets_tree(tmp), 0, "every built host has one disposition")


@tcase("targets: a host added to a descriptor with no row fails")
def _(tmp):
    proc = targets_tree(tmp, hosts=("x86_64-linux-gnu riscv64-linux-gnu", "mips-linux-gnu"))
    expect(proc, 1, "builds mips-linux-gnu, which has no row")


@tcase("targets: a row for a host nothing builds fails")
def _(tmp):
    expect(targets_tree(tmp, hosts=("x86_64-linux-gnu",)), 1, "which no gitian descriptor builds")


@tcase("targets: a descriptor whose HOSTS line cannot be found fails")
def _(tmp):
    proc = targets_tree(tmp, hosts=("x86_64-linux-gnu riscv64-linux-gnu", None))
    expect(proc, 1, "no HOSTS=")


@tcase("targets: a bundle version written back into the workflow fails")
def _(tmp):
    proc = targets_tree(tmp, workflow_extra='      - run: echo "default: 9.9.9"\n')
    expect(proc, 1, "restates the bundle version 9.9.9")


@tcase("targets: a pinned host with no verify job fails")
def _(tmp):
    expect(targets_tree(tmp, workflow_hosts=()), 1, "no job for the pinned host x86_64-linux-gnu")


@tcase("targets: a checklist that does not name the pin fails")
def _(tmp):
    proc = targets_tree(tmp, checklist="Expert Bundle 9.9.8 (tor 0.0.0.1)")
    expect(proc, 1, "does not name the linux-x86_64 pin")


@tcase("targets: a malformed pin file fails")
def _(tmp):
    pins = base_pins("0" * 64)
    pins["targets"][0]["files"][0]["sha256"] = "not-a-digest"
    expect(targets_tree(tmp, pins=pins), 1, "sha256 is 64 lowercase hex characters")


def main():
    failures = 0
    for name, fn in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                fn(Bench(tmp))
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}\n{exc}")
    for name, fn in TARGET_CASES:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                fn(tmp)
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}\n{exc}")
    total = len(CASES) + len(TARGET_CASES)
    if failures:
        print(f"tor pin gates self-test: {failures} of {total} cases FAILED")
        return 1
    print(f"tor pin gates self-test: all {total} cases pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
