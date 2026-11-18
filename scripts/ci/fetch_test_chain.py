#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Fetch a hosted test chain by its pinned digest, and check every layer.

`CHAIN_FORGE.md` §10.4 (`CF-R11`): a chain over the storage line is an OCI
artifact on GHCR, and `rust/shekyl-chain-forge/chains/hosted.toml` pins it
by digest, with each layer's size and SHA-256. That file is the only
source of truth. This script:

  1. installs the pinned `oras` release, checking its archive's SHA-256
     against the pin before anything runs (a changed checksum is red,
     never re-pinned in passing);
  2. pulls `<reference>@<digest>` into a staging directory (by digest,
     never by tag: a tag can move, a digest cannot);
  3. checks every file the pin names, at that layer's size and SHA-256,
     and refuses a file the pin does not name, before anything is moved
     into place. The pin's form (one entry per chain, the digest's shape,
     each layer's media type) is shekyl-chain-forge's `hosted::Pins`.
     This script checks bytes.

    fetch_test_chain.py <chain>          fetch into the chain's fetched
                                         directory (kept if it already
                                         matches the pin)
    fetch_test_chain.py --all --fresh    pull every pinned chain into a
                                         scratch directory and check it
                                         (nightly's pull check: the cache
                                         is still there and still matches)
    fetch_test_chain.py --install-oras   install the pinned oras and print
                                         its path (shekyl-test-chains'
                                         publish workflow, at the commit it
                                         forges)
    fetch_test_chain.py --selftest       plant each failure and prove it
                                         refused

A missing artifact is a failure that names the forge command rebuilding the
chain at its pinned commit: the hosted copy is a cache (`CF-R6`), never a
reason to skip. Rule 47: the script asserts its subject (the pin file
parses, the named chain is pinned, `oras` is the pinned build) before it
judges; rule 46: every verdict is this process's exit status.
"""

from __future__ import annotations

import hashlib
import io
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FORGE = REPO / "rust" / "shekyl-chain-forge"
PIN_FILE = FORGE / "chains" / "hosted.toml"
ORAS_URL = "https://github.com/oras-project/oras/releases/download/v{v}/oras_{v}_{p}.tar.gz"
# What a pull needs from a chain entry. The rest of the pin's form is
# `hosted::Pins` (`shekyl-chain-forge`).
CHAIN_FIELDS = ("reference", "digest", "commit", "plan", "layer")


class Refused(Exception):
    """A verdict: the fetch is refused, with the reason."""


def load_pins(path: Path = PIN_FILE) -> dict:
    if not path.is_file():
        raise Refused(f"{path} is missing: there is no pin to fetch against")
    pins = tomllib.loads(path.read_text(encoding="utf-8"))
    oras = pins.get("oras", {})
    if not isinstance(oras, dict) or not oras.get("version") or not oras.get("sha256"):
        raise Refused(f"{path} pins no oras version or checksum")
    raw = pins.get("chain", [])
    if not isinstance(raw, list):
        raise Refused(f"{path}: chain is not a list of chains")
    return pins


def pinned(pins: dict, name: str) -> dict:
    matches = [chain for chain in pins.get("chain", []) if chain.get("name") == name]
    if not matches:
        raise Refused(f"no hosted chain {name!r} is pinned in {PIN_FILE.relative_to(REPO)}")
    if len(matches) > 1:
        raise Refused(f"chain {name!r} is pinned twice in {PIN_FILE.relative_to(REPO)}")
    chain = matches[0]
    missing = [field for field in CHAIN_FIELDS if field not in chain]
    if missing:
        raise Refused(f"chain {name!r} pins no {', '.join(missing)}")
    layers = chain["layer"]
    if not isinstance(layers, list) or not layers:
        raise Refused(f"chain {name!r} pins no layers")
    files: list[str] = []
    for layer in layers:
        file = layer.get("file")
        if not file or "size" not in layer or "sha256" not in layer:
            raise Refused(f"chain {name!r}: a layer needs a file, a size and a SHA-256")
        files.append(file)
    if len(files) != len(set(files)):
        raise Refused(f"chain {name!r}: a layer file is named twice")
    return chain


def sha256_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
            size += len(block)
    return size, digest.hexdigest()


def check_layers(chain: dict, directory: Path) -> None:
    """Every file the pin names, at its size and SHA-256; nothing else."""
    named = {layer["file"] for layer in chain["layer"]}
    for layer in chain["layer"]:
        path = directory / layer["file"]
        if not path.is_file():
            raise Refused(f"{chain['name']}: {layer['file']} is not in what was pulled")
        size, sha = sha256_file(path)
        if (size, sha) != (layer["size"], layer["sha256"]):
            raise Refused(
                f"{chain['name']}: {layer['file']} is {size} bytes with SHA-256 {sha}; "
                f"the pin says {layer['size']} bytes with SHA-256 {layer['sha256']}"
            )
    extra = sorted(p.name for p in directory.iterdir() if p.name not in named)
    if extra:
        raise Refused(f"{chain['name']}: the artifact holds files the pin does not name: {extra}")


def oras_platform() -> str:
    system = {"Linux": "linux", "Darwin": "darwin"}.get(platform.system())
    machine = {"x86_64": "amd64", "AMD64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(
        platform.machine()
    )
    if not system or not machine:
        raise Refused(f"no pinned oras archive for {platform.system()} {platform.machine()}")
    return f"{system}_{machine}"


def install_oras(pins: dict) -> Path:
    """The pinned oras, installed once per version under the user cache."""
    version = pins["oras"]["version"]
    plat = oras_platform()
    want = pins["oras"]["sha256"].get(plat)
    if not want:
        raise Refused(f"the pin file has no oras {version} checksum for {plat}")
    home = Path(os.environ.get("RUNNER_TEMP") or Path.home() / ".cache") / "shekyl-oras" / version
    binary = home / "oras"
    stamp = home / "archive.sha256"
    if binary.is_file() and stamp.is_file() and stamp.read_text().strip() == want:
        return binary
    url = ORAS_URL.format(v=version, p=plat)
    with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310 (a pinned https URL)
        archive = response.read()
    got = hashlib.sha256(archive).hexdigest()
    if got != want:
        raise Refused(f"oras {version} {plat}: the archive's SHA-256 is {got}; the pin says {want}")
    home.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        member = tar.getmember("oras")
        extracted = tar.extractfile(member)
        if extracted is None:
            raise Refused("the oras archive holds no `oras` file")
        binary.write_bytes(extracted.read())
    binary.chmod(0o755)
    stamp.write_text(want + "\n")
    return binary


def forge_command(chain: dict, out: Path) -> str:
    """The rebuild, run from the repository root.

    `--plan` is the pin's path, which is relative to that root, so Cargo is
    pointed at `rust/Cargo.toml` rather than run from `rust/` (where that
    path would not resolve). The forge also writes `blocks.txt`; the pin
    check reads only the layers, so the ledger is removed.
    """
    return (
        f"git checkout {chain['commit']} && cargo run --manifest-path rust/Cargo.toml "
        f"--locked --release -p shekyl-chain-forge --example forge -- "
        f"--plan {chain['plan']} --out {out} && rm -f {out}/blocks.txt"
    )


def pull(oras: Path, chain: dict, staging: Path) -> None:
    ref = f"{chain['reference']}@{chain['digest']}"
    result = subprocess.run(
        [str(oras), "pull", ref, "--output", str(staging)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise Refused(
            f"{chain['name']}: `oras pull {ref}` failed ({result.returncode}): "
            f"{result.stderr.strip() or result.stdout.strip()}\n"
            f"The hosted copy is a cache (CHAIN_FORGE.md CF-R6): rebuild it at its pinned commit with\n"
            f"  {forge_command(chain, FORGE / 'chains' / chain['name'] / 'hosted')}"
        )


def fetch(pins: dict, name: str, destination: Path) -> str:
    chain = pinned(pins, name)
    if destination.is_dir():
        try:
            check_layers(chain, destination)
            return f"{name}: {destination} already matches {chain['digest']}"
        except Refused:
            pass
    oras = install_oras(pins)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as scratch:
        staging = Path(scratch) / "pulled"
        staging.mkdir()
        pull(oras, chain, staging)
        check_layers(chain, staging)
        if destination.exists():
            shutil.rmtree(destination)
        staging.rename(destination)
    return f"{name}: pulled {chain['digest']} into {destination}, every layer matches its pin"


def selftest() -> int:
    failures = 0

    def expect(label: str, ok: bool) -> None:
        nonlocal failures
        print(f"{'ok  ' if ok else 'FAIL'} {label}")
        failures += 0 if ok else 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        good = root / "good"
        good.mkdir()
        contents = {"corpus.e2": b"corpus bytes", "trace.e2": b"trace", "manifest.json": b"{}"}
        for file, data in contents.items():
            (good / file).write_bytes(data)
        chain = {
            "name": "c",
            "layer": [
                {
                    "file": file,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
                for file, data in contents.items()
            ],
        }

        def refused(directory: Path) -> str | None:
            try:
                check_layers(chain, directory)
            except Refused as why:
                return str(why)
            return None

        expect("a copy that matches its pin passes", refused(good) is None)

        flipped = root / "flipped"
        shutil.copytree(good, flipped)
        data = bytearray(contents["corpus.e2"])
        data[0] ^= 1
        (flipped / "corpus.e2").write_bytes(bytes(data))
        why = refused(flipped)
        expect(
            "one byte changed is refused, naming both hashes",
            why is not None
            and hashlib.sha256(bytes(data)).hexdigest() in why
            and chain["layer"][0]["sha256"] in why,
        )

        short = root / "short"
        shutil.copytree(good, short)
        (short / "trace.e2").unlink()
        expect("a missing layer is refused", refused(short) is not None)

        extra = root / "extra"
        shutil.copytree(good, extra)
        (extra / "other.bin").write_bytes(b"x")
        expect("a file the pin does not name is refused", refused(extra) is not None)

        oras = '[oras]\nversion = "1.3.6"\n[oras.sha256]\nlinux_amd64 = "00"\n'
        bare = root / "hosted.toml"
        bare.write_text(oras, encoding="utf-8")
        try:
            pinned(load_pins(bare), "absent")
            expect("an unpinned chain is refused", False)
        except Refused:
            expect("an unpinned chain is refused", True)

        # The bytes a pull needs. Media types and digest shape are the Rust
        # schema; a missing field here used to be a KeyError.
        chain_toml = (
            '[[chain]]\nname = "c"\nplan = "p"\ncommit = "aa"\n'
            'reference = "ghcr.io/example/c"\ndigest = "sha256:00"\n'
            '[[chain.layer]]\nfile = "corpus.e2"\nsize = 1\nsha256 = "00"\n'
        )
        whole = root / "whole.toml"
        whole.write_text(oras + chain_toml, encoding="utf-8")
        try:
            pinned(load_pins(whole), "c")
            expect("a chain entry with its pull fields is accepted", True)
        except Refused as why:
            expect(f"a chain entry with its pull fields is accepted ({why})", False)

        no_digest = root / "no-digest.toml"
        no_digest.write_text(oras + chain_toml.replace('digest = "sha256:00"\n', ""), encoding="utf-8")
        try:
            pinned(load_pins(no_digest), "c")
            expect("a chain that pins no digest is refused", False)
        except Refused as why:
            expect("a chain that pins no digest is refused", "digest" in str(why))

        twice = root / "twice.toml"
        twice.write_text(oras + chain_toml + chain_toml, encoding="utf-8")
        try:
            pinned(load_pins(twice), "c")
            expect("a chain pinned twice is refused", False)
        except Refused as why:
            expect("a chain pinned twice is refused", "twice" in str(why))

    command = forge_command(
        {"commit": "abc", "plan": "rust/shekyl-chain-forge/plans/shard-fill.toml"},
        Path("out"),
    )
    expect(
        "the rebuild runs from the repository root and drops blocks.txt",
        "--manifest-path rust/Cargo.toml" in command
        and "--plan rust/shekyl-chain-forge/plans/shard-fill.toml" in command
        and command.endswith("rm -f out/blocks.txt"),
    )

    real = load_pins()
    expect("the committed pin file parses and pins oras", bool(real["oras"]["sha256"]))
    print("selftest: " + ("passed" if failures == 0 else f"{failures} failure(s)"))
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    try:
        pins = load_pins()
        if argv == ["--install-oras"]:
            print(install_oras(pins))
            return 0
        if argv == ["--all", "--fresh"]:
            if not pins.get("chain"):
                raise Refused(f"{PIN_FILE.relative_to(REPO)} pins no chain: the pull check has no subject")
            with tempfile.TemporaryDirectory() as scratch:
                for chain in pins["chain"]:
                    print(fetch(pins, chain["name"], Path(scratch) / chain["name"]))
            return 0
        if len(argv) == 1 and not argv[0].startswith("-"):
            name = argv[0]
            print(fetch(pins, name, FORGE / "chains" / name / "hosted"))
            return 0
    except Refused as why:
        print(f"::error::{why}", file=sys.stderr)
        return 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
