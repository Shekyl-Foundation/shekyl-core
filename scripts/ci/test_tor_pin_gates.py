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
# `--sources`. The Windows cases build a minimal PE32+ image whose import
# tables say what each case needs, so the PE reader is bitten by a file whose
# every byte this test chose.

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


def make_tarball(path, members=MEMBERS):
    with tarfile.open(path, "w:gz") as tar:
        for name, data in members.items():
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
        "signed_url": "https://invalid.example/signed-{bundle_version}/{bundle_target}-{name}",
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


WIN_HOST = "x86_64-w64-mingw32"
WIN_IMPORTS = ["KERNEL32.dll", "WS2_32.dll", "api-ms-win-crt-runtime-l1-1-0.dll"]


def make_pe(imports, delayed=(), import_rva=None, import_size=None, delay_size=None):
    """A PE32+ image: the DOS and PE headers, one section, and in it an import
    table naming `imports` and, when `delayed` is given, a delay-load table
    naming those. `import_rva` overrides where the import directory points;
    `import_size` and `delay_size` override the sizes the directories record
    (the tables themselves are laid out as usual)."""
    section_rva, section_raw = 0x1000, 0x200
    import_table_size = 20 * (len(imports) + 1)
    delay_table_size = 32 * (len(delayed) + 1) if delayed else 0
    names = bytearray()

    def name_rva(name):
        rva = section_rva + import_table_size + delay_table_size + len(names)
        names.extend(name.encode("ascii") + b"\0")
        return rva

    body = bytearray()
    for name in imports:
        descriptor = bytearray(20)
        descriptor[12:16] = name_rva(name).to_bytes(4, "little")
        body += descriptor
    body += bytes(20)
    for name in delayed:
        descriptor = bytearray(32)
        descriptor[0:4] = (1).to_bytes(4, "little")  # attributes: RVA form
        descriptor[4:8] = name_rva(name).to_bytes(4, "little")
        body += descriptor
    if delayed:
        body += bytes(32)
    body += names

    image = bytearray(section_raw)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x40).to_bytes(4, "little")
    image[0x40:0x44] = b"PE\0\0"
    coff = 0x44
    image[coff : coff + 2] = (0x8664).to_bytes(2, "little")
    image[coff + 2 : coff + 4] = (1).to_bytes(2, "little")
    image[coff + 16 : coff + 18] = (240).to_bytes(2, "little")
    optional = coff + 20
    image[optional : optional + 2] = (0x20B).to_bytes(2, "little")
    image[optional + 24 : optional + 32] = (0x140000000).to_bytes(8, "little")
    image[optional + 108 : optional + 112] = (16).to_bytes(4, "little")
    directories = optional + 112
    rva = section_rva if import_rva is None else import_rva
    image[directories + 8 : directories + 12] = rva.to_bytes(4, "little")
    recorded = import_table_size if import_size is None else import_size
    image[directories + 12 : directories + 16] = recorded.to_bytes(4, "little")
    if delayed:
        delay = directories + 8 * 13
        recorded = delay_table_size if delay_size is None else delay_size
        image[delay : delay + 4] = (section_rva + import_table_size).to_bytes(4, "little")
        image[delay + 4 : delay + 8] = recorded.to_bytes(4, "little")
    section = optional + 240
    image[section : section + 8] = b".idata\0\0"
    image[section + 8 : section + 12] = len(body).to_bytes(4, "little")
    image[section + 12 : section + 16] = section_rva.to_bytes(4, "little")
    image[section + 16 : section + 20] = len(body).to_bytes(4, "little")
    image[section + 20 : section + 24] = section_raw.to_bytes(4, "little")
    return bytes(image + body)


MAC_HOST = "aarch64-apple-darwin11"
ARM64 = 0x0100000C
LC_SEGMENT_64, LC_CODE_SIGNATURE = 0x19, 0x1D


def segment(name, vmaddr, vmsize, fileoff, filesize):
    cmd = bytearray(72)
    cmd[0:4] = LC_SEGMENT_64.to_bytes(4, "little")
    cmd[4:8] = (72).to_bytes(4, "little")
    cmd[8:24] = name.encode().ljust(16, b"\0")
    for i, value in enumerate((vmaddr, vmsize, fileoff, filesize)):
        cmd[24 + 8 * i : 32 + 8 * i] = value.to_bytes(8, "little")
    return bytes(cmd)


def make_macho(seed, linkedit_size=0x5F3):
    """An unsigned 64-bit Mach-O as Tor ships it: a header, a `__TEXT` and a
    `__LINKEDIT` segment, zero slack after the load commands, code bytes, and
    `__LINKEDIT` ending the file. `seed` makes two files differ."""
    text_end = 0x1000
    commands = segment("__TEXT", 0, text_end, 0, text_end) + segment(
        "__LINKEDIT", text_end, 0x1000, text_end, linkedit_size
    )
    image = bytearray(text_end + linkedit_size)
    image[0:4] = (0xFEEDFACF).to_bytes(4, "little")
    image[4:8] = ARM64.to_bytes(4, "little")
    image[12:16] = (2).to_bytes(4, "little")
    image[16:20] = (2).to_bytes(4, "little")
    image[20:24] = len(commands).to_bytes(4, "little")
    image[32 : 32 + len(commands)] = commands
    for i in range(0x100, len(image)):
        image[i] = (i * 7 + seed) % 251 + 1
    return bytes(image)


def sign(upstream, blob=b"\xfa\xde\x0c\xc0" * 128, vmsize_round=0x4000):
    """What codesign does to `upstream` (measured on the macOS build host, 2026-10-22):
    one LC_CODE_SIGNATURE appended in the zero slack, the header counting it,
    the blob on the next 16-byte boundary, and `__LINKEDIT` grown to hold it,
    its vmsize rounded up to 16 KiB."""
    image = bytearray(upstream)
    ncmds = int.from_bytes(image[16:20], "little")
    sizeofcmds = int.from_bytes(image[20:24], "little")
    at = 32 + sizeofcmds
    dataoff = -(-len(image) // 16) * 16
    image += bytes(dataoff - len(image)) + blob
    image[16:20] = (ncmds + 1).to_bytes(4, "little")
    image[20:24] = (sizeofcmds + 16).to_bytes(4, "little")
    image[at : at + 4] = LC_CODE_SIGNATURE.to_bytes(4, "little")
    image[at + 4 : at + 8] = (16).to_bytes(4, "little")
    image[at + 8 : at + 12] = dataoff.to_bytes(4, "little")
    image[at + 12 : at + 16] = len(blob).to_bytes(4, "little")
    linkedit = 32 + 72
    fileoff = int.from_bytes(image[linkedit + 40 : linkedit + 48], "little")
    filesize = len(image) - fileoff
    image[linkedit + 32 : linkedit + 40] = (-(-filesize // vmsize_round) * vmsize_round).to_bytes(8, "little")
    image[linkedit + 48 : linkedit + 56] = filesize.to_bytes(8, "little")
    return bytes(image)


MAC_FILES = ["tor", "libevent-2.1.7.dylib"]


class Bench:
    """A scratch directory holding a tarball, its pin file, and room to stage."""

    def __init__(self, tmp):
        self.root = Path(tmp)
        self.host = HOST
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

    def stage(self, host=None):
        return self.run(
            "stage", "--host", host or self.host, "--sources", str(self.sources),
            "--dest", str(self.dest), "--licenses", str(self.licenses),
        )

    def verify(self, *extra):
        return self.run("verify", "--host", self.host, "--dir", str(self.dest), *extra)

    def macos(self):
        """Make the pinned row a macOS bundle: Tor's unsigned `tor` and
        `libevent` in the tarball, their signed copies in `self.signed`, and a
        row pinning the signed bytes as `files` and Tor's as `upstream`."""
        self.upstream = {name: make_macho(seed) for seed, name in enumerate(MAC_FILES)}
        self.shipped = {name: sign(data) for name, data in self.upstream.items()}
        members = {f"tor/{name}": data for name, data in self.upstream.items()}
        members["tor/pluggable_transports/lyrebird"] = b"a transport Shekyl does not ship"
        members["docs/tor.txt"] = b"tor licence"
        self.tarball = self.sources / "tor-expert-bundle-macos-aarch64-9.9.9.tar.gz"
        self.signed = self.root / "signed"
        self.signed.mkdir()
        # The cache the release build stages from: what `fetch` puts there.
        self.signed_cache = self.sources / "tor-signed-macos-aarch64-9.9.9"
        self.signed_cache.mkdir()
        for name, data in self.shipped.items():
            (self.signed / name).write_bytes(data)
            (self.signed_cache / name).write_bytes(data)
        row = self.pins["targets"][0]
        row.update(
            os="macos",
            arch="aarch64",
            gitian_host=MAC_HOST,
            bundle_target="macos-aarch64",
            tarball_sha256=make_tarball(self.tarball, members),
            files=[{"name": n, "sha256": sha(d)} for n, d in self.shipped.items()],
            upstream=[{"name": n, "sha256": sha(d)} for n, d in self.upstream.items()],
            licenses=["docs/tor.txt"],
        )
        self.host = MAC_HOST
        self.write()

    def stage_signed(self, signed=None):
        return self.run(
            "stage", "--host", self.host, "--sources", str(self.sources),
            "--dest", str(self.dest), "--licenses", str(self.licenses),
            "--signed", str(signed or self.signed),
        )

    def tie(self, shipped_tor):
        """`tie` over a signed directory whose `tor` is `shipped_tor`."""
        signed = self.root / "tie"
        shutil.rmtree(signed, ignore_errors=True)
        signed.mkdir()
        (signed / "tor").write_bytes(shipped_tor)
        return self.run("tie", "--tarball", str(self.tarball), "--signed", str(signed))

    def windows(self, pe, imports=WIN_IMPORTS):
        """Make the pinned row a Windows bundle whose tor.exe is `pe`, with
        the bundle's other executable beside it (not shipped), and an import
        list of `imports`."""
        members = {
            "tor/tor.exe": pe,
            "tor/tor-gencert.exe": b"a tool Shekyl does not ship",
            "docs/tor.txt": b"tor licence",
            "docs/zlib.txt": b"zlib licence",
        }
        self.tarball = self.sources / "tor-expert-bundle-windows-x86_64-9.9.9.tar.gz"
        row = self.pins["targets"][0]
        row.update(
            os="windows",
            gitian_host=WIN_HOST,
            bundle_target="windows-x86_64",
            tarball_sha256=make_tarball(self.tarball, members),
            executable="tor.exe",
            files=[{"name": "tor.exe", "sha256": sha(pe)}],
            imports=list(imports),
            licenses=["docs/tor.txt", "docs/zlib.txt"],
        )
        self.host = WIN_HOST
        self.write()


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


@case("stage --no-fetch: a cache miss refuses and downloads nothing")
def _(b):
    b.tarball.unlink()
    proc = b.run(
        "stage", "--host", HOST, "--sources", str(b.sources), "--no-fetch",
        "--dest", str(b.dest), "--licenses", str(b.licenses),
    )
    # The pin file's URL is https://invalid.example: had a download been
    # attempted, the message would be the fetch failure, not this one.
    expect(proc, 1, "--no-fetch forbids downloading it")
    assert "could not fetch" not in proc.stderr, proc.stderr
    assert not b.dest.exists()
    assert list(b.sources.iterdir()) == [], "nothing may be written to the cache"


@case("stage --no-fetch: a tarball in the cache stages as usual")
def _(b):
    proc = b.run(
        "stage", "--host", HOST, "--sources", str(b.sources), "--no-fetch",
        "--dest", str(b.dest), "--licenses", str(b.licenses),
    )
    expect(proc, 0, "staged tor 0.0.0.1")


@case("pin file: pending names a work item, on an unavailable row only")
def _(b):
    b.pins["targets"][1]["pending"] = "TB-11"
    b.write()
    expect(b.run("disposition", "--host", "riscv64-linux-gnu"), 0, "unavailable")
    for bad in ("soon", "tb-11", "TB-", "after the launch test", 11):
        b.pins["targets"][1]["pending"] = bad
        b.write()
        expect(b.stage(), 1, "names the")
    del b.pins["targets"][1]["pending"]
    b.pins["targets"][0]["pending"] = "TB-11"
    b.write()
    expect(b.stage(), 1, "belongs on an unavailable row")


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
    expect(b.stage(), 1, "must state its reason")


@case("pin file: a version label that could name another directory is refused")
def _(b):
    for bad in ("../9.9.9", "9.9.9:x", "9.9.9/x", "$ORIGIN"):
        b.pins["targets"][0]["bundle_version"] = bad
        b.write()
        expect(b.run("install-dir", "--host", HOST), 1, "bundle_version is letters, digits")


@case("pin file: two licence texts that would stage under one name are refused")
def _(b):
    b.pins["targets"][0]["licenses"] = ["docs/tor.txt", "other/tor.txt"]
    b.write()
    expect(b.stage(), 1, "two licence texts would be staged under one name")
    assert not b.dest.exists()


@case("pin file: a file name that is a path is refused")
def _(b):
    b.pins["targets"][0]["files"][1]["name"] = "../libevent-2.1.so.7"
    b.write()
    expect(b.stage(), 1, "is not a plain file name")


@case("pin file: linux does not fold the executable onto its file")
def _(b):
    b.pins["targets"][0]["executable"] = "TOR"
    b.write()
    expect(b.run("disposition", "--host", HOST), 1, "the executable is not among the pinned files")


@case("pin file: linux keeps two names that differ only by case")
def _(b):
    files = b.pins["targets"][0]["files"]
    files.append({"name": "TOR", "sha256": files[0]["sha256"]})
    b.write()
    expect(b.run("disposition", "--host", HOST), 0, "pinned")


@case("pin file: windows folds the executable and refuses a case-only duplicate")
def _(b):
    row = b.pins["targets"][0]
    row["os"] = "windows"
    row["gitian_host"] = "x86_64-w64-mingw32"
    row["executable"] = "TOR"
    row["imports"] = list(WIN_IMPORTS)
    b.write()
    expect(b.run("disposition", "--host", "x86_64-w64-mingw32"), 0, "pinned")
    row["files"].append({"name": "TOR", "sha256": row["files"][0]["sha256"]})
    b.write()
    expect(b.run("disposition", "--host", "x86_64-w64-mingw32"), 1, "a file is listed twice")


@case("windows: a tor.exe importing only listed DLLs stages and verifies")
def _(b):
    b.windows(make_pe(WIN_IMPORTS), imports=[name.lower() for name in WIN_IMPORTS])
    expect(b.stage(), 0, "staged tor 0.0.0.1")
    assert os.listdir(b.dest) == ["tor.exe"], os.listdir(b.dest)
    expect(b.verify(), 0, "holds exactly the pinned bundle")


@case("windows: a planted import the list does not name is refused")
def _(b):
    b.windows(make_pe(WIN_IMPORTS + ["version.dll"]))
    expect(b.stage(), 1, "imports version.dll, which the pin's import list does not name")
    assert not b.dest.exists(), "a tor.exe that fails its import list leaves nothing staged"


@case("windows: verify reads the import table of a staged tor.exe")
def _(b):
    b.windows(make_pe(WIN_IMPORTS))
    expect(b.stage(), 0)
    b.pins["targets"][0]["imports"].remove("WS2_32.dll")
    b.write()
    expect(b.verify(), 1, "imports WS2_32.dll, which the pin's import list does not name")


@case("windows: a delay-load import is refused even when the DLL is listed")
def _(b):
    b.windows(make_pe(WIN_IMPORTS, delayed=["WS2_32.dll"]))
    expect(b.stage(), 1, "delay-loads WS2_32.dll; the pin allows no delay-load import")
    assert not b.dest.exists()


@case("windows: a directory with only one of RVA and size set is refused, either table")
def _(b):
    # The loader reads an import table from its RVA whatever the size says:
    # a zero size must not hide the planted import.
    b.windows(make_pe(WIN_IMPORTS + ["version.dll"], import_size=0))
    expect(b.stage(), 1, "data directory 1 has RVA 0x1000 and size 0")
    # Nor hide a delay-load.
    b.windows(make_pe(WIN_IMPORTS, delayed=["WS2_32.dll"], delay_size=0))
    expect(b.stage(), 1, "data directory 13 has RVA")
    # A size with no table behind it is as inconsistent.
    b.windows(make_pe(WIN_IMPORTS, import_rva=0))
    expect(b.stage(), 1, "data directory 1 has RVA 0x0 and size")
    assert not b.dest.exists()


@case("windows: an import table the reader cannot follow is refused, not read as empty")
def _(b):
    b.windows(make_pe(WIN_IMPORTS, import_rva=0x9000))
    expect(b.stage(), 1, "RVA 0x9000 is not backed by any section")
    b.windows(b"MZ" + bytes(62))
    expect(b.stage(), 1, "not a PE image")
    # Cut inside the PE32+ optional header's ImageBase (offset 0x58 + 24).
    b.windows(make_pe(WIN_IMPORTS)[: 0x58 + 28])
    expect(b.stage(), 1, "truncated PE image")


@case("pin file: the import list is a Windows row's, and well formed")
def _(b):
    b.windows(make_pe(WIN_IMPORTS))
    row = b.pins["targets"][0]
    del row["imports"]
    b.write()
    expect(b.stage(), 1, '"imports" is missing; a pinned Windows target must list')
    row["imports"] = []
    b.write()
    expect(b.stage(), 1, '"imports" is not a non-empty list')
    row["imports"] = ["KERNEL32.dll", "kernel32.DLL"]
    b.write()
    expect(b.stage(), 1, "an import is listed twice")
    row["imports"] = ["..\\KERNEL32.dll"]
    b.write()
    expect(b.stage(), 1, "is not a plain file name")


@case("pin file: a non-Windows row carrying an import list is refused")
def _(b):
    b.pins["targets"][0]["imports"] = list(WIN_IMPORTS)
    b.write()
    expect(b.stage(), 1, "only a Windows row has one")


# --- macOS: signed files tied to Tor's (TB-11) -----------------------------


@case("macos: stage --signed stages the signed files, and verify --sources ties them")
def _(b):
    b.macos()
    expect(b.stage_signed(), 0, "staged tor 0.0.0.1")
    assert sorted(os.listdir(b.dest)) == sorted(MAC_FILES), os.listdir(b.dest)
    for name, data in b.shipped.items():
        assert (b.dest / name).read_bytes() == data, name
    note = (b.licenses / "SOURCE.txt").read_text(encoding="utf-8")
    assert "signed each with its Developer ID" in note and "unmodified" not in note, note
    for name, data in b.upstream.items():
        assert sha(data) in note, f"SOURCE.txt names Tor's digest of {name}"
    expect(b.verify("--sources", str(b.sources)), 0, "holds exactly the pinned bundle")


@case("macos: stage takes the signed files from the cache, never Tor's unsigned ones")
def _(b):
    b.macos()
    proc = b.run(
        "stage", "--host", b.host, "--sources", str(b.sources), "--no-fetch",
        "--dest", str(b.dest), "--licenses", str(b.licenses),
    )
    expect(proc, 0, "staged tor 0.0.0.1")
    for name, data in b.shipped.items():
        assert (b.dest / name).read_bytes() == data, name


@case("macos: stage --no-fetch with no signed file in the cache refuses and downloads nothing")
def _(b):
    b.macos()
    (b.signed_cache / "tor").unlink()
    proc = b.run(
        "stage", "--host", b.host, "--sources", str(b.sources), "--no-fetch",
        "--dest", str(b.dest), "--licenses", str(b.licenses),
    )
    expect(proc, 1, "--no-fetch forbids downloading it")
    assert "could not fetch" not in proc.stderr, proc.stderr
    assert not b.dest.exists()


@case("macos: a cached signed file that is not the pinned one refuses")
def _(b):
    b.macos()
    (b.signed_cache / "libevent-2.1.7.dylib").write_bytes(sign(b.upstream["libevent-2.1.7.dylib"], blob=b"\x02" * 512))
    proc = b.run(
        "stage", "--host", b.host, "--sources", str(b.sources), "--no-fetch",
        "--dest", str(b.dest), "--licenses", str(b.licenses),
    )
    expect(proc, 1, "is not the pinned signed libevent-2.1.7.dylib")
    assert not b.dest.exists()


@case("pin file: a pinned macOS row needs an https signed_url naming the file")
def _(b):
    b.macos()
    for bad in (None, "http://invalid.example/{bundle_target}-{name}", "https://invalid.example/x"):
        if bad is None:
            b.pins.pop("signed_url")
        else:
            b.pins["signed_url"] = bad
        b.write()
        expect(b.stage_signed(), 1, "needs \"signed_url\"")


@case("macos: a signed file that ties but is not the pinned one refuses")
def _(b):
    b.macos()
    (b.signed / "tor").write_bytes(sign(b.upstream["tor"], blob=b"\x01" * 512))
    expect(b.stage_signed(), 1, "does not match its pin")
    assert not b.dest.exists()


@case("macos: a signed directory with a file too many refuses")
def _(b):
    b.macos()
    (b.signed / "lyrebird").write_bytes(b"x")
    expect(b.stage_signed(), 1, "the signed files are exactly")


@case("macos: a pinned signed file whose code differs from Tor's refuses the tie")
def _(b):
    b.macos()
    forged = bytearray(b.shipped["tor"])
    forged[0x800] ^= 1
    (b.signed / "tor").write_bytes(bytes(forged))
    row = b.pins["targets"][0]
    row["files"][0]["sha256"] = sha(bytes(forged))
    b.write()
    expect(b.stage_signed(), 1, "differs from the upstream file signed at byte 0x800")
    assert not b.dest.exists()


@case("macos: verify needs --sources, and the tie runs there too")
def _(b):
    b.macos()
    expect(b.stage_signed(), 0)
    expect(b.verify(), 1, "verify needs --sources")
    # An upstream pin that is not Tor's file: the tie cannot vouch for it.
    b.pins["targets"][0]["upstream"][0]["sha256"] = "0" * 64
    b.write()
    expect(b.verify("--sources", str(b.sources)), 1, "does not match its upstream pin")


@case("--signed and verify --sources belong to a macOS host only")
def _(b):
    expect(b.stage_signed(signed=b.root), 1, "--signed is for a macOS host")
    expect(b.stage(), 0)
    expect(b.verify("--sources", str(b.sources)), 1, "--sources is for a macOS host")


@case("pin file: a macOS row lists upstream, under the names it ships")
def _(b):
    b.macos()
    row = b.pins["targets"][0]
    upstream = row.pop("upstream")
    b.write()
    expect(b.stage_signed(), 1, "lists Tor's own files as \"upstream\"")
    row["upstream"] = [dict(upstream[0]), dict(upstream[1], name="libevent.dylib")]
    b.write()
    expect(b.stage_signed(), 1, "name different files")


@case("pin file: only a macOS row carries upstream")
def _(b):
    row = b.pins["targets"][0]
    row["upstream"] = row["files"]
    b.write()
    expect(b.stage(), 1, "only a macOS row has it")


@case("tie: Tor's file signed as codesign signs it ties, and both digest sets print")
def _(b):
    b.macos()
    proc = b.tie(b.shipped["tor"])
    expect(proc, 0)
    report = json.loads(proc.stdout)
    assert report == {
        "files": [{"name": "tor", "sha256": sha(b.shipped["tor"])}],
        "upstream": [{"name": "tor", "sha256": sha(b.upstream["tor"])}],
    }, report


def _mutated(b, edit):
    image = bytearray(b.shipped["tor"])
    edit(image)
    return bytes(image)


TIE_BITES = [
    ("a byte of Tor's code", lambda i: i.__setitem__(0x900, i[0x900] ^ 1),
     "differs from the upstream file signed"),
    ("ncmds not counting the signature",
     lambda i: i.__setitem__(slice(16, 20), (2).to_bytes(4, "little")),
     "the load commands do not fill sizeofcmds"),
    ("sizeofcmds not counting the signature",
     lambda i: i.__setitem__(slice(20, 24), (144).to_bytes(4, "little")),
     "a load command runs past the header's sizeofcmds"),
    ("__LINKEDIT vmsize rounded to 4 KiB, not 16 KiB",
     lambda i: i.__setitem__(slice(104 + 32, 104 + 40), (0x1000).to_bytes(8, "little")),
     "differs from the upstream file signed"),
    ("__LINKEDIT filesize short of the blob",
     lambda i: i.__setitem__(slice(104 + 48, 104 + 56), (0x5F3).to_bytes(8, "little")),
     "differs from the upstream file signed"),
    ("a non-zero padding byte before the blob",
     lambda i: i.__setitem__(0x1000 + 0x5F3, 0xAA),
     "differs from the upstream file signed"),
    ("a byte after the blob",
     lambda i: i.extend(b"\0"),
     "run to the end of the file"),
    ("the signature command's type changed",
     lambda i: i.__setitem__(slice(176, 180), (0x1E).to_bytes(4, "little")),
     "is not a code signature, or is not last"),
]

for _label, _edit, _needle in TIE_BITES:
    def _bite(b, edit=_edit, needle=_needle):
        b.macos()
        expect(b.tie(_mutated(b, edit)), 1, needle)
    case(f"tie: refuses {_label}")(_bite)


@case("tie: refuses a signature written over bytes upstream uses")
def _(b):
    b.macos()
    upstream = bytearray(b.upstream["tor"])
    upstream[176] = 0x5A  # the slack the signature's command would take
    b.upstream["tor"] = bytes(upstream)
    members = {f"tor/{n}": d for n, d in b.upstream.items()}
    make_tarball(b.tarball, members)
    expect(b.tie(sign(bytes(upstream))), 1, "overwrites bytes upstream uses")


@case("tie: refuses Tor's unsigned file offered as the signed one")
def _(b):
    b.macos()
    expect(b.tie(b.upstream["tor"]), 1, "exactly one 16-byte load command")


# --- check_tor_pin_targets.py ---------------------------------------------


STAGE_STEP = "      - run: |\n          python3 scripts/release/tor_bundle.py stage --host \"$HOST\"\n"


def workflow_yaml(hosts, steps=STAGE_STEP):
    return (
        "on:\n  workflow_dispatch:\njobs:\n  verify:\n    runs-on: ubuntu-latest\n"
        "    strategy:\n      matrix:\n        target:\n"
        + ("".join(f"          - host: {h}\n" for h in hosts) or "          - host: none\n")
        + "    steps:\n"
        + steps
    )


def targets_tree(tmp, pins=None, hosts=("x86_64-linux-gnu riscv64-linux-gnu",),
                 workflow_hosts=("x86_64-linux-gnu",), workflow_extra="", workflow=None,
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
        workflow
        if workflow is not None
        else workflow_yaml(workflow_hosts) + workflow_extra,
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
    proc = targets_tree(tmp, workflow_extra="      - run: echo bundle-9.9.9\n")
    expect(proc, 1, "restates the bundle version 9.9.9")


@tcase("targets: a pinned host with no verify job fails")
def _(tmp):
    proc = targets_tree(tmp, workflow_hosts=())
    expect(proc, 1, "no job both names the pinned host x86_64-linux-gnu")


@tcase("targets: a host named only in a comment satisfies nothing")
def _(tmp):
    wf = workflow_yaml(()) + "# host: x86_64-linux-gnu\n"
    expect(targets_tree(tmp, workflow=wf), 1, "no job both names the pinned host")


@tcase("targets: a stage command only in a script comment satisfies nothing")
def _(tmp):
    steps = (
        "      - run: |\n"
        "          # python3 scripts/release/tor_bundle.py stage --host x\n"
        "          echo skipped\n"
    )
    wf = workflow_yaml(("x86_64-linux-gnu",), steps=steps)
    expect(targets_tree(tmp, workflow=wf), 1, "no job both names the pinned host")


@tcase("targets: a stage command that is only echoed satisfies nothing")
def _(tmp):
    steps = "      - run: echo python3 scripts/release/tor_bundle.py stage --host x\n"
    wf = workflow_yaml(("x86_64-linux-gnu",), steps=steps)
    expect(targets_tree(tmp, workflow=wf), 1, "no job both names the pinned host")


@tcase("targets: a host only under the matrix's exclude satisfies nothing")
def _(tmp):
    wf = (
        "on:\n  workflow_dispatch:\njobs:\n  verify:\n    runs-on: ubuntu-latest\n"
        "    strategy:\n      matrix:\n        target:\n          - host: other-host\n"
        "        exclude:\n          - target:\n              host: x86_64-linux-gnu\n"
        "    steps:\n" + STAGE_STEP
    )
    expect(targets_tree(tmp, workflow=wf), 1, "no job both names the pinned host")


@tcase("targets: a host in one job and the stage step in another satisfies nothing")
def _(tmp):
    wf = (
        workflow_yaml(("x86_64-linux-gnu",), steps="      - run: echo no staging here\n")
        + "  other:\n    runs-on: ubuntu-latest\n    steps:\n"
        + STAGE_STEP
    )
    expect(targets_tree(tmp, workflow=wf), 1, "no job both names the pinned host")


@tcase("targets: a checklist that does not name the pin fails")
def _(tmp):
    proc = targets_tree(tmp, checklist="Expert Bundle 9.9.8 (tor 0.0.0.1)")
    expect(proc, 1, "does not name the linux-x86_64 pin")


@tcase("targets: a missing workflow fails with a diagnosis, not a traceback")
def _(tmp):
    targets_tree(tmp)  # builds the tree; its own run of the gate is not this case
    root = Path(tmp) / "tree"
    (root / ".github" / "workflows" / "tor-pin-verify.yml").unlink()
    proc = subprocess.run(
        [sys.executable, str(root / "scripts" / "ci" / TARGETS_GATE.name), "--root", str(root)],
        capture_output=True, text=True,
    )
    expect(proc, 1, "tor-pin-verify.yml: cannot be read")
    assert "Traceback" not in proc.stderr, proc.stderr


def pending_pins():
    pins = base_pins("0" * 64)
    pins["targets"][1]["pending"] = "TB-11"
    return pins


@tcase("targets: a pending row is reported and passes")
def _(tmp):
    proc = targets_tree(tmp, pins=pending_pins())
    expect(proc, 0, "riscv64-linux-gnu is unavailable pending TB-11")


@tcase("targets: a malformed pin file fails")
def _(tmp):
    pins = base_pins("0" * 64)
    pins["targets"][0]["files"][0]["sha256"] = "not-a-digest"
    expect(targets_tree(tmp, pins=pins), 1, "sha256 is 64 lowercase hex characters")


@tcase("targets: swapping two hosts' triples fails")
def _(tmp):
    pins = base_pins("0" * 64)
    pins["targets"][0]["gitian_host"] = "riscv64-linux-gnu"
    pins["targets"][1]["gitian_host"] = "x86_64-linux-gnu"
    expect(
        targets_tree(tmp, pins=pins),
        1,
        "gitian_host 'riscv64-linux-gnu' is the release triple for linux/riscv64, not linux/x86_64",
    )


@tcase("targets: an os that the triple does not name fails")
def _(tmp):
    pins = base_pins("0" * 64)
    pins["targets"][0]["os"] = "windows"
    expect(
        targets_tree(tmp, pins=pins),
        1,
        "gitian_host 'x86_64-linux-gnu' is the release triple for linux/x86_64, not windows/x86_64",
    )


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
