#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Fetch, check and stage the pinned Tor Expert Bundle for packaging
(`docs/design/TOR_BUNDLE_DISTRIBUTION.md` TB-6, TB-9, TB-13).

`config/tor_pins.json` is the one record of what Shekyl ships. This script
is its packaging-side reader; `rust/shekyl-tor-control-client/build.rs` is the
other reader and compiles the same rows into the binary. Neither holds a copy
of a digest, so the bundle a package carries and the bundle the daemon will
accept cannot drift apart without one of the two refusing.

What the daemon checks at every launch is that tor's directory holds exactly
the pinned files and that each hashes to its pin. `stage` produces such a
directory and `verify` applies the same rule to one that is about to be
packed, so a package that would be refused at first launch is refused here.

Subcommands (a target is named by its gitian host triple, `--host`):

  disposition  print `pinned` or `unavailable` for the host, and nothing else.
  install-dir  print the system directory a package installs the bundle to,
               `/opt/shekyl/<bundle_version>-<bundle_target>`.
  tarball-url  print where the host's pinned tarball is published (its
               detached signature is the same URL with `.asc` appended).
  fetch        download the host's tarball into `--sources` if it is not
               there, and check its SHA-256. `--all` does every pinned host.
  stage        check the tarball's SHA-256 BEFORE opening it, extract only the
               pinned files into `--dest`, check each file's SHA-256, and
               write the licence texts and the source pointer into
               `--licenses`. Fetches the tarball first if `--sources` lacks it,
               unless `--no-fetch` is given: then a cache miss refuses. The
               release build passes `--no-fetch`.
  verify       check that `--dir` holds exactly the pinned files, each a
               regular file with the pinned SHA-256.

An `unavailable` host is not an error: `fetch` and `stage` report it and do
nothing, and the caller branches on `disposition`. `install-dir`,
`tarball-url` and `verify` refuse it, because there is nothing for them to
describe.

The tarball's OpenPGP signature is NOT checked here. That is the pin-time
step (`docs/RELEASE_CHECKLIST.md`, "Bundled Tor pin current"): a maintainer
verifies the signature once and records the digests; from then on the
digest is the gate, and a build needs no keyring.

Exit codes: 0 = done; 1 = a check refused (the message says which); 2 = usage
error.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PINS = REPO_ROOT / "config" / "tor_pins.json"
OPT_ROOT = "/opt/shekyl"
# The directory inside the Expert Bundle tarball that holds `tor` and the
# libraries it loads.
BUNDLE_TOR_DIR = "tor"


class Refused(Exception):
    """A check failed. The message is the whole diagnosis."""


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def is_digest(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def is_label(value):
    """A version or target label. These compose `/opt/shekyl/<version>-<target>`
    and the download URL, so they are a closed alphabet: nothing that could
    name another directory, split a loader path, or bend a URL."""
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    return (
        isinstance(value, str)
        and value not in ("", ".", "..")
        and all(c in allowed for c in value)
    )


def is_work_item(value):
    """An identifier from a registered family, e.g. `TB-11`: what a pending
    row waits on. A sentence here would be a second `reason`; the point of
    the field is that a gate can read it."""
    if not isinstance(value, str) or "-" not in value:
        return False
    family, _, number = value.rpartition("-")
    return family.isalpha() and family.isupper() and number.isdigit()


def is_plain_name(value):
    return (
        isinstance(value, str)
        and value not in ("", ".", "..")
        and not any(c in value for c in "/\\\0")
    )


# A gitian host triple is how the release names a target. `os`/`arch` is how
# `build.rs` names the same target, and packaging selects a row by the host
# while the binary selects one by os/arch. The suffix is the OS family and
# the stem is the Cargo arch. darwin's trailing number is a deployment
# version. android's triple says "linux" because that is the ABI; the row's
# os is android.
_HOST_TRIPLES = (
    (re.compile(r"([A-Za-z0-9_]+)-linux-android\Z"), "android"),
    (re.compile(r"([A-Za-z0-9_]+)-linux-gnu\Z"), "linux"),
    (re.compile(r"([A-Za-z0-9_]+)-unknown-freebsd\Z"), "freebsd"),
    (re.compile(r"([A-Za-z0-9_]+)-w64-mingw32\Z"), "windows"),
    (re.compile(r"([A-Za-z0-9_]+)-apple-darwin[0-9]+\Z"), "macos"),
)


def release_target(host):
    """The `(os, arch)` a gitian host triple compiles, or `None` when this
    reader cannot check the triple."""
    if not isinstance(host, str):
        return None
    for pattern, os_name in _HOST_TRIPLES:
        match = pattern.match(host)
        if match:
            return os_name, match.group(1)
    return None


def file_identity(os_name, name):
    """The name the loader treats as this file. Windows folds case, which is
    `TorPin.names_match`; every other platform keeps the bytes."""
    return name.lower() if os_name == "windows" else name


def load_pins(path):
    """Read the pin file and refuse one that is not well formed.

    The build script applies the same rules to the row it compiles; applying
    them to every row here means a malformed row for a target nobody built
    today is still caught by the gate that runs this.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        raise Refused(f"cannot read {path}: {exc}") from exc

    for key in ("signing_key_fingerprint", "bundle_url", "source_url", "source_signature_url"):
        if not isinstance(doc.get(key), str) or not doc[key]:
            raise Refused(f"{path}: missing {key!r}")
    rows = doc.get("targets")
    if not isinstance(rows, list) or not rows:
        raise Refused(f"{path}: no targets")

    seen_targets = set()
    seen_hosts = set()
    for row in rows:
        where = f"{path} [{row.get('os')}/{row.get('arch')}]"
        for key in ("os", "arch", "gitian_host", "disposition"):
            if not isinstance(row.get(key), str) or not row[key]:
                raise Refused(f"{where}: missing {key!r}")
        target = (row["os"], row["arch"])
        if target in seen_targets:
            raise Refused(f"{where}: more than one row for this target")
        seen_targets.add(target)
        if row["gitian_host"] in seen_hosts:
            raise Refused(f"{where}: host {row['gitian_host']} is listed twice")
        seen_hosts.add(row["gitian_host"])
        compiled = release_target(row["gitian_host"])
        if compiled is None:
            raise Refused(
                f"{where}: gitian_host {row['gitian_host']!r} is not a release "
                "triple this reader knows, so it cannot be checked against os/arch"
            )
        if compiled != target:
            raise Refused(
                f"{where}: gitian_host {row['gitian_host']!r} is the release triple "
                f"for {compiled[0]}/{compiled[1]}, not {target[0]}/{target[1]}"
            )

        if "pending" in row and (
            row["disposition"] != "unavailable" or not is_work_item(row["pending"])
        ):
            raise Refused(
                f"{where}: \"pending\" belongs on an unavailable row and names the "
                "work that will pin it, as an identifier such as TB-11"
            )
        if row["disposition"] == "unavailable":
            if not isinstance(row.get("reason"), str) or not row["reason"].strip():
                raise Refused(f"{where}: an unavailable target must state its reason; none is given")
            continue
        if row["disposition"] != "pinned":
            raise Refused(f"{where}: disposition is 'pinned' or 'unavailable'")

        for key in ("bundle_version", "bundle_target", "tor_version"):
            if not is_label(row.get(key)):
                raise Refused(
                    f"{where}: {key} is letters, digits, '.', '_' and '-' "
                    "(it composes an install path and a URL)"
                )
        if not is_digest(row.get("tarball_sha256")):
            raise Refused(f"{where}: tarball_sha256 is 64 lowercase hex characters")
        files = row.get("files")
        if not isinstance(files, list) or not files:
            raise Refused(f"{where}: a pinned target lists its files")
        names = []
        for entry in files:
            if not is_plain_name(entry.get("name")):
                raise Refused(f"{where}: {entry.get('name')!r} is not a plain file name")
            if not is_digest(entry.get("sha256")):
                raise Refused(f"{where}: {entry['name']}: sha256 is 64 lowercase hex characters")
            names.append(file_identity(row["os"], entry["name"]))
        if len(set(names)) != len(names):
            raise Refused(f"{where}: a file is listed twice")
        executable = row.get("executable")
        if (
            not is_plain_name(executable)
            or file_identity(row["os"], executable) not in names
        ):
            raise Refused(f"{where}: the executable is not among the pinned files")
        licenses = row.get("licenses")
        if not isinstance(licenses, list) or not licenses:
            raise Refused(f"{where}: a pinned target lists the bundle's licence texts")
        staged_names = []
        for member in licenses:
            if not isinstance(member, str) or member.startswith("/") or ".." in member.split("/"):
                raise Refused(f"{where}: {member!r} is not a path inside the tarball")
            staged_names.append(member.rsplit("/", 1)[-1].lower())
        # Licence texts are staged flat, under their base names, beside the
        # generated SOURCE.txt. Two members sharing a base name would leave
        # one text silently overwriting the other.
        if len(set(staged_names)) != len(staged_names) or "source.txt" in staged_names:
            raise Refused(
                f"{where}: two licence texts would be staged under one name "
                "(base names must be unique, and SOURCE.txt is generated)"
            )
    return doc


def row_for_host(doc, host):
    for row in doc["targets"]:
        if row["gitian_host"] == host:
            return row
    known = ", ".join(sorted(r["gitian_host"] for r in doc["targets"]))
    raise Refused(f"no row for host {host!r} in the pin file (known: {known})")


def pinned_row(doc, host):
    row = row_for_host(doc, host)
    if row["disposition"] != "pinned":
        raise Refused(f"{host} is unavailable ({row['reason']}); there is no bundle for it")
    return row


def tarball_name(row):
    return f"tor-expert-bundle-{row['bundle_target']}-{row['bundle_version']}.tar.gz"


def tarball_url(doc, row):
    return doc["bundle_url"].format(
        bundle_version=row["bundle_version"], bundle_target=row["bundle_target"]
    )


def check_tarball(path, row):
    actual = sha256_file(path)
    if actual != row["tarball_sha256"]:
        raise Refused(
            f"{path} is not the pinned tarball: expected sha256 {row['tarball_sha256']}, "
            f"found {actual}. Nothing was extracted from it."
        )


def fetch(doc, row, sources, offline=False):
    """Make the pinned tarball present in `sources`, digest-checked.

    With `offline`, a tarball that is not already there is a refusal and
    nothing is downloaded: a release build takes its inputs from the cache
    it was given, and a cache miss that quietly became a download is how a
    build stops being reproducible without anyone deciding it should."""
    dest = sources / tarball_name(row)
    if dest.exists():
        check_tarball(dest, row)
        return dest
    if offline:
        raise Refused(
            f"{dest} is not in the sources cache and --no-fetch forbids downloading it. "
            "Populate the cache first: tor_bundle.py fetch --all --sources <cache>"
        )
    sources.mkdir(parents=True, exist_ok=True)
    url = tarball_url(doc, row)
    if not url.startswith("https://"):
        raise Refused(f"refusing to fetch over anything but https: {url}")
    print(f"fetching {url}", file=sys.stderr)
    fd, tmp_name = tempfile.mkstemp(dir=sources, prefix=dest.name + ".", suffix=".part")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as out, urllib.request.urlopen(url, timeout=120) as resp:
            shutil.copyfileobj(resp, out)
        # Checked before it takes the name later runs trust.
        check_tarball(tmp, row)
        tmp.replace(dest)
    except OSError as exc:
        raise Refused(f"could not fetch {url}: {exc}") from exc
    finally:
        tmp.unlink(missing_ok=True)
    return dest


def read_member(tar, name):
    try:
        member = tar.getmember(name)
    except KeyError as exc:
        raise Refused(f"the tarball has no member {name!r}") from exc
    if not member.isreg():
        raise Refused(f"tarball member {name!r} is not a regular file")
    try:
        handle = tar.extractfile(member)
        if handle is None:
            raise Refused(f"tarball member {name!r} could not be opened")
        return handle.read()
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise Refused(f"tarball member {name!r} could not be read: {exc}") from exc


def source_note(doc, row):
    """The text that travels with the binary (TB-13)."""
    tor = row["tor_version"]
    return (
        f"Tor {tor}, from the Tor Expert Bundle {row['bundle_version']} "
        f"({row['bundle_target']}).\n"
        "\n"
        "The files in the tor directory of this package are the Tor Project's own\n"
        "build, unmodified: Shekyl extracts them from the Expert Bundle and checks\n"
        "each against a recorded SHA-256 before every launch. The licence texts the\n"
        "bundle ships for tor and the libraries beside it are in this directory.\n"
        "\n"
        "Bundle:\n"
        f"  {tarball_url(doc, row)}\n"
        f"  SHA-256 {row['tarball_sha256']}\n"
        f"  signed by the Tor Browser Developers key {doc['signing_key_fingerprint']}\n"
        "  (signature: the same URL with .asc appended)\n"
        "\n"
        f"Source for tor {tor}:\n"
        f"  {doc['source_url'].format(tor_version=tor)}\n"
        f"  signature: {doc['source_signature_url'].format(tor_version=tor)}\n"
    )


def check_directory(directory, row):
    """The daemon's rule, applied before packing: exactly the pinned files,
    each a regular file with the pinned digest."""
    if not directory.is_dir():
        raise Refused(f"{directory} is not a directory")
    pinned = {entry["name"]: entry["sha256"] for entry in row["files"]}
    for entry in sorted(os.listdir(directory)):
        if entry not in pinned:
            raise Refused(
                f"{directory} holds {entry!r}, which is not part of the pinned bundle; "
                "the daemon refuses a tor directory that holds anything else"
            )
        mode = os.lstat(directory / entry).st_mode
        if not stat.S_ISREG(mode):
            raise Refused(f"{directory / entry} is not a regular file")
    for name, expected in pinned.items():
        path = directory / name
        if not path.exists():
            raise Refused(f"{directory} lacks the pinned file {name}")
        actual = sha256_file(path)
        if actual != expected:
            raise Refused(
                f"{path} does not match its pin: expected sha256 {expected}, found {actual}"
            )
    exe_mode = os.stat(directory / row["executable"]).st_mode
    if os.name == "posix" and not exe_mode & 0o111:
        raise Refused(f"{directory / row['executable']} is not executable")


def stage(doc, row, sources, dest, licenses, offline=False):
    tarball = fetch(doc, row, sources, offline=offline)
    # `fetch` checked a tarball it found or downloaded; the digest is read
    # again from the file this function is about to open, so the check and
    # the extraction are of one file whatever `fetch` did.
    check_tarball(tarball, row)

    for directory in (dest, licenses):
        if directory.exists() and any(directory.iterdir()):
            raise Refused(f"{directory} exists and is not empty; stage into a fresh directory")
    if dest.resolve() == licenses.resolve():
        raise Refused(
            "the licence texts cannot share tor's directory: it holds the pinned files "
            "and nothing else"
        )

    # Read and check everything first, write second: a file that fails its pin
    # leaves nothing behind for a later step to pack.
    try:
        archive = tarfile.open(tarball, "r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise Refused(f"{tarball} could not be opened as a tarball: {exc}") from exc
    with archive as tar:
        staged = []
        for entry in row["files"]:
            data = read_member(tar, f"{BUNDLE_TOR_DIR}/{entry['name']}")
            actual = hashlib.sha256(data).hexdigest()
            if actual != entry["sha256"]:
                raise Refused(
                    f"{entry['name']} in {tarball.name} does not match its pin: "
                    f"expected sha256 {entry['sha256']}, found {actual}"
                )
            staged.append((entry["name"], data))
        texts = [(Path(member).name, read_member(tar, member)) for member in row["licenses"]]

    dest.mkdir(parents=True, exist_ok=True)
    licenses.mkdir(parents=True, exist_ok=True)
    for name, data in staged:
        out = dest / name
        out.write_bytes(data)
        out.chmod(0o755 if name == row["executable"] else 0o644)
    for name, data in texts:
        out = licenses / name
        out.write_bytes(data)
        out.chmod(0o644)
    note = licenses / "SOURCE.txt"
    note.write_text(source_note(doc, row), encoding="utf-8")
    note.chmod(0o644)

    check_directory(dest, row)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--pins", type=Path, default=DEFAULT_PINS, help="the pin file")
    sub = parser.add_subparsers(dest="command", required=True)

    def with_host(name, **kwargs):
        cmd = sub.add_parser(name, **kwargs)
        cmd.add_argument("--host", help="gitian host triple, e.g. x86_64-linux-gnu")
        return cmd

    with_host("disposition")
    with_host("install-dir")
    with_host("tarball-url")
    cmd = with_host("fetch")
    cmd.add_argument("--all", action="store_true", help="every pinned host")
    cmd.add_argument("--sources", type=Path, required=True)
    cmd = with_host("stage")
    cmd.add_argument("--sources", type=Path, required=True)
    cmd.add_argument("--dest", type=Path, required=True, help="tor's directory")
    cmd.add_argument("--licenses", type=Path, required=True)
    cmd.add_argument(
        "--no-fetch",
        action="store_true",
        help="refuse if --sources lacks the tarball instead of downloading it",
    )
    cmd = with_host("verify")
    cmd.add_argument("--dir", type=Path, required=True, help="tor's directory")
    args = parser.parse_args(argv)

    if args.command == "fetch":
        if bool(args.host) == bool(args.all):
            parser.error("fetch takes exactly one of --host and --all")
    elif not args.host:
        parser.error(f"{args.command} needs --host")

    try:
        doc = load_pins(args.pins)
        if args.command == "disposition":
            print(row_for_host(doc, args.host)["disposition"])
        elif args.command == "install-dir":
            row = pinned_row(doc, args.host)
            print(f"{OPT_ROOT}/{row['bundle_version']}-{row['bundle_target']}")
        elif args.command == "tarball-url":
            print(tarball_url(doc, pinned_row(doc, args.host)))
        elif args.command == "fetch":
            rows = (
                [r for r in doc["targets"] if r["disposition"] == "pinned"]
                if args.all
                else [row_for_host(doc, args.host)]
            )
            for row in rows:
                if row["disposition"] != "pinned":
                    print(f"{row['gitian_host']}: unavailable ({row['reason']}); nothing to fetch")
                    continue
                print(f"{row['gitian_host']}: {fetch(doc, row, args.sources)}")
        elif args.command == "stage":
            row = row_for_host(doc, args.host)
            if row["disposition"] != "pinned":
                print(f"{args.host}: unavailable ({row['reason']}); nothing staged")
                return 0
            stage(doc, row, args.sources, args.dest, args.licenses, offline=args.no_fetch)
            print(
                f"{args.host}: staged tor {row['tor_version']} "
                f"(bundle {row['bundle_version']}) into {args.dest}"
            )
        elif args.command == "verify":
            row = pinned_row(doc, args.host)
            check_directory(args.dir, row)
            print(f"{args.host}: {args.dir} holds exactly the pinned bundle")
    except Refused as exc:
        print(f"tor_bundle: REFUSED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
