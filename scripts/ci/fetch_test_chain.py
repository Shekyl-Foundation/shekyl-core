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
import urllib.request
import zipfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python before 3.11, e.g. macOS's system python3
    sys.exit(
        "fetch_test_chain.py needs Python 3.11 or later (tomllib); "
        f"this is Python {sys.version_info.major}.{sys.version_info.minor}"
    )

REPO = Path(__file__).resolve().parents[2]
FORGE = REPO / "rust" / "shekyl-chain-forge"
PIN_FILE = FORGE / "chains" / "hosted.toml"
# Each platform's archive: Windows ships a zip holding `oras.exe`, the rest a
# tar.gz holding `oras`.
ORAS_URL = "https://github.com/oras-project/oras/releases/download/v{v}/oras_{v}_{p}.{ext}"
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


# What `platform.machine()` reports, per host, for the two architectures oras
# ships: `x86_64` (Linux, macOS), `AMD64` (Windows), `amd64` (FreeBSD);
# `aarch64` (Linux), `arm64` (macOS, FreeBSD).
ORAS_MACHINES = {"x86_64": "amd64", "AMD64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
ORAS_SYSTEMS = {"Linux": "linux", "Darwin": "darwin", "FreeBSD": "freebsd", "Windows": "windows"}


def oras_platform(system_name: str | None = None, machine_name: str | None = None) -> str:
    """The oras archive's platform for this host, or for the pair given."""
    system_name = platform.system() if system_name is None else system_name
    machine_name = platform.machine() if machine_name is None else machine_name
    system = ORAS_SYSTEMS.get(system_name)
    machine = ORAS_MACHINES.get(machine_name)
    if not system or not machine:
        raise Refused(f"no pinned oras archive for {system_name} {machine_name}")
    return f"{system}_{machine}"


def oras_archive(plat: str) -> tuple[str, str]:
    """The archive's extension and the binary inside it, for `plat`."""
    return ("zip", "oras.exe") if plat.startswith("windows_") else ("tar.gz", "oras")


def extract_oras(archive: bytes, plat: str) -> bytes:
    """The oras binary out of the checked archive for `plat`."""
    ext, name = oras_archive(plat)
    if ext == "zip":
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            if name not in zipped.namelist():
                raise Refused(f"the oras archive holds no `{name}` file")
            return zipped.read(name)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        try:
            member = tar.getmember(name)
        except KeyError:
            raise Refused(f"the oras archive holds no `{name}` file") from None
        extracted = tar.extractfile(member)
        if extracted is None:
            raise Refused(f"the oras archive holds no `{name}` file")
        return extracted.read()


def install_oras(pins: dict) -> Path:
    """The pinned oras, installed once per version under the user cache."""
    version = pins["oras"]["version"]
    plat = oras_platform()
    want = pins["oras"]["sha256"].get(plat)
    if not want:
        raise Refused(f"the pin file has no oras {version} checksum for {plat}")
    home = Path(os.environ.get("RUNNER_TEMP") or Path.home() / ".cache") / "shekyl-oras" / version
    ext, name = oras_archive(plat)
    binary = home / name
    stamp = home / "archive.sha256"
    if binary.is_file() and stamp.is_file() and stamp.read_text().strip() == want:
        return binary
    url = ORAS_URL.format(v=version, p=plat, ext=ext)
    with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310 (a pinned https URL)
        archive = response.read()
    got = hashlib.sha256(archive).hexdigest()
    if got != want:
        raise Refused(f"oras {version} {plat}: the archive's SHA-256 is {got}; the pin says {want}")
    home.mkdir(parents=True, exist_ok=True)
    binary.write_bytes(extract_oras(archive, plat))
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

    # Each archive form gives up its binary, and one without it is refused.
    payload = b"oras binary"
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w") as archive:
        archive.writestr("oras.exe", payload)
        archive.writestr("LICENSE", b"license")
    tarred = io.BytesIO()
    with tarfile.open(fileobj=tarred, mode="w:gz") as archive:
        info = tarfile.TarInfo("oras")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    expect("a Windows zip gives up oras.exe", extract_oras(zipped.getvalue(), "windows_amd64") == payload)
    expect("a tar.gz gives up oras", extract_oras(tarred.getvalue(), "linux_amd64") == payload)
    no_exe = io.BytesIO()
    with zipfile.ZipFile(no_exe, "w") as archive:
        archive.writestr("LICENSE", b"license")
    no_oras = io.BytesIO()
    with tarfile.open(fileobj=no_oras, mode="w:gz") as archive:
        info = tarfile.TarInfo("LICENSE")
        info.size = len(b"license")
        archive.addfile(info, io.BytesIO(b"license"))
    for label, archive_bytes, plat in (
        ("a Windows zip without oras.exe is refused", no_exe.getvalue(), "windows_amd64"),
        ("a tar.gz without oras is refused", no_oras.getvalue(), "linux_amd64"),
    ):
        try:
            extract_oras(archive_bytes, plat)
            expect(label, False)
        except Refused:
            expect(label, True)

    real = load_pins()
    expect("the committed pin file parses and pins oras", bool(real["oras"]["sha256"]))
    # Each host's own report, as `platform` gives it there, reaches a pinned
    # archive; a pair oras does not ship for is refused by name.
    for host, machine, plat in (
        ("Linux", "x86_64", "linux_amd64"),
        ("Linux", "aarch64", "linux_arm64"),
        ("Darwin", "x86_64", "darwin_amd64"),
        ("Darwin", "arm64", "darwin_arm64"),
        ("FreeBSD", "amd64", "freebsd_amd64"),
        ("Windows", "AMD64", "windows_amd64"),
    ):
        try:
            got = oras_platform(host, machine)
        except Refused:
            got = None
        expect(f"{host} {machine} maps to {plat}", got == plat)
        expect(f"the pin file pins oras for {plat}", plat in real["oras"]["sha256"])
    try:
        oras_platform("Linux", "riscv64")
        expect("an unshipped architecture is refused", False)
    except Refused as why:
        expect("an unshipped architecture is refused", "riscv64" in str(why))
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
