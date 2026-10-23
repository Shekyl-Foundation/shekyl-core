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
  fetch        download every artifact the host stages from into `--sources`,
               each checked against its pin: the tarball, and, when the row
               carries `upstream`, the signed files from `signed_url`. `--all`
               does every pinned host.
  stage        check the tarball's SHA-256 BEFORE opening it, then write the
               pinned files into `--dest` and the licence texts and the source
               pointer into `--licenses`. A row that carries `upstream` packs
               the signed files from the sources cache, after the signature
               tie. Fetches first if `--sources` lacks an input, unless
               `--no-fetch`: then a cache miss refuses. The release build
               passes `--no-fetch`.
  verify       check that `--dir` holds exactly the pinned files, each a
               regular file with the pinned SHA-256. For a Windows host it also
               reads the executable's PE import table (`tor_pe`) and refuses a
               DLL the row's `imports` does not name, and any import its
               delay-load table records (`check_imports` says what that can
               and cannot see). `--sources` re-checks the cached tarball. A row
               that carries `upstream` requires it, and ties each staged file to
               Tor's bytes in that tarball.
  tie          pin time, before the signed files are a release asset: for each
               file in `--signed`, read Tor's file of the same name from
               `--tarball` and check the tie; print both digest sets as the
               row's `files` and `upstream`. The tarball's signature is
               checked first, as for every pin.

A row that carries `upstream` ships bytes that are not Tor's release (TB-11).
Today that is a macOS row: Shekyl signs Tor's binaries with its Developer ID.
`files` are the shipped bytes, which the daemon checks at every launch, and
`upstream` are Tor's, as extracted from the signed tarball. The signed files
are a release asset (`signed_url`). `fetch` puts them in the sources cache
beside the tarball and checks each against its shipped digest: the pin is the
integrity check, not the hosting. `stage` reads that cache and no other
directory. `tie --signed` is the signing host's check, run before the upload.

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
import importlib.util
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


def _load_sibling(name):
    """Load `name`.py from this file's directory.

    The pin gate loads this file by path, and a direct run puts this
    directory on `sys.path` only for that run. Loading the sibling by its
    own path works in both cases.
    """
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tor_macho = _load_sibling("tor_macho")
tor_pe = _load_sibling("tor_pe")

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
# version.
_HOST_TRIPLES = (
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
        # The DLLs a Windows executable may import (TB-11). A PE image names
        # them; no other format's row has the list, so a row elsewhere that
        # carries one is a mistake about which reader checks it.
        imports = row.get("imports")
        if row["os"] == "windows":
            if not isinstance(imports, list) or not imports:
                problem = "is missing" if imports is None else "is not a non-empty list"
                raise Refused(
                    f"{where}: \"imports\" {problem}; a pinned Windows target must list "
                    "the DLLs its executable may import"
                )
            folded = []
            for name in imports:
                if not is_plain_name(name):
                    raise Refused(f"{where}: import {name!r} is not a plain file name")
                folded.append(name.lower())
            if len(set(folded)) != len(folded):
                raise Refused(f"{where}: an import is listed twice")
        elif "imports" in row:
            raise Refused(f"{where}: \"imports\" is the PE import list; only a Windows row has one")
        # Tor's own bytes, which the shipped (signed) files are tied to (TB-11).
        # Only a macOS row ships files Shekyl has changed.
        upstream = row.get("upstream")
        if row["os"] == "macos":
            if not isinstance(upstream, list) or not upstream:
                raise Refused(
                    f"{where}: a pinned macOS target lists Tor's own files as \"upstream\", "
                    "beside the signed files it ships"
                )
            upstream_names = []
            for entry in upstream:
                if not is_plain_name(entry.get("name")):
                    raise Refused(f"{where}: upstream {entry.get('name')!r} is not a plain file name")
                if not is_digest(entry.get("sha256")):
                    raise Refused(f"{where}: upstream {entry['name']}: sha256 is 64 lowercase hex characters")
                upstream_names.append(entry["name"])
            if sorted(upstream_names) != sorted(names):
                raise Refused(f"{where}: \"upstream\" and \"files\" name different files")
        elif upstream is not None:
            raise Refused(
                f"{where}: \"upstream\" is for files Shekyl signs; only a macOS row has it"
            )
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
    _require_signed_url(path, doc, rows)
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


# The three fields `signed_url` is filled with. A release asset is
# `{bundle_target}-{name}` under `tor-macos-{bundle_version}-signed`.
SIGNED_URL_FIELDS = ("bundle_version", "bundle_target", "name")


def carries_upstream(row):
    """The row ships bytes that are not Tor's release.

    `upstream` is Tor's own files. `files` is what the daemon checks.
    `load_pins` allows that pair on a macOS row and on no other, so the
    packager follows the row instead of the operating-system name.
    """
    upstream = row.get("upstream")
    return isinstance(upstream, list) and bool(upstream)


def signed_file_url(template, row, name):
    """Fill `signed_url` for one shipped file. A template that cannot be
    filled, or that does not stay https, is a refusal."""
    try:
        url = template.format(
            bundle_version=row["bundle_version"],
            bundle_target=row["bundle_target"],
            name=name,
        )
    except (KeyError, IndexError, ValueError) as exc:
        raise Refused(
            f"{row['gitian_host']}: signed_url cannot be filled for {name} ({exc}). "
            'A pinned macOS row needs "signed_url", an https template of '
            "{bundle_version}, {bundle_target} and {name}"
        ) from exc
    if not url.startswith("https://"):
        raise Refused(f"refusing to fetch over anything but https: {url}")
    return url


def _require_signed_url(path, doc, rows):
    """A row that carries upstream names one https template, and that template
    fills for every file the row ships."""
    signed_rows = [row for row in rows if row["disposition"] == "pinned" and carries_upstream(row)]
    if not signed_rows:
        return
    template = doc.get("signed_url")
    intro = (
        f'{path}: a pinned macOS row needs "signed_url", an https template of '
        "{bundle_version}, {bundle_target} and {name}"
    )
    if not isinstance(template, str) or not template.startswith("https://"):
        raise Refused(intro)
    missing = [f"{{{field}}}" for field in SIGNED_URL_FIELDS if f"{{{field}}}" not in template]
    if missing:
        raise Refused(f"{intro}; this one does not name {', '.join(missing)}")
    for row in signed_rows:
        for entry in row["files"]:
            signed_file_url(template, row, entry["name"])


def fetch(doc, row, sources, offline=False):
    """Make every artifact `row` stages from present in `sources`.

    Returns `(tarball, signed_dir)`. `signed_dir` is the cache of signed
    files when the row carries upstream, and None otherwise. With `offline`,
    an input that is not already there is a refusal and nothing is downloaded:
    a release build takes its inputs from the cache it was given.
    """
    dest = sources / tarball_name(row)
    _cached_or_download(tarball_url(doc, row), dest, lambda path: check_tarball(path, row), offline)
    signed = fetch_signed(doc, row, sources, offline=offline) if carries_upstream(row) else None
    return dest, signed


def _cached_or_download(url, dest, check, offline):
    """Make `dest` present and passing `check`: a cached copy is checked; a
    missing one is downloaded (unless `offline`) and checked before it takes
    the name later runs trust."""
    if dest.exists():
        check(dest)
        return
    if offline:
        raise Refused(
            f"{dest} is not in the sources cache and --no-fetch forbids downloading it. "
            "Populate the cache first: tor_bundle.py fetch --all --sources <cache>"
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not url.startswith("https://"):
        raise Refused(f"refusing to fetch over anything but https: {url}")
    print(f"fetching {url}", file=sys.stderr)
    fd, tmp_name = tempfile.mkstemp(dir=dest.parent, prefix=dest.name + ".", suffix=".part")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as out, urllib.request.urlopen(url, timeout=120) as resp:
            shutil.copyfileobj(resp, out)
        check(tmp)
        tmp.replace(dest)
    except OSError as exc:
        raise Refused(f"could not fetch {url}: {exc}") from exc
    finally:
        tmp.unlink(missing_ok=True)


def signed_cache_dir(row, sources):
    """Where a row's signed files sit in the sources cache, beside the tarball
    they are tied to. This is the only directory `stage` reads them from."""
    return sources / f"tor-signed-{row['bundle_target']}-{row['bundle_version']}"


def fetch_signed(doc, row, sources, offline=False):
    """Make the signed files present in the sources cache, each checked against
    its shipped digest (TB-11). The digest in the pin file is the integrity
    check; where the files are hosted vouches for nothing."""
    directory = signed_cache_dir(row, sources)
    template = doc["signed_url"]
    for entry in row["files"]:
        name, digest = entry["name"], entry["sha256"]

        def check(path, name=name, digest=digest):
            actual = sha256_file(path)
            if actual != digest:
                raise Refused(
                    f"{path} is not the pinned signed {name}: expected sha256 {digest}, found {actual}"
                )

        _cached_or_download(signed_file_url(template, row, name), directory / name, check, offline)
    return directory


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
    if row["os"] == "macos":
        provenance = (
            "The files in the tor directory of this package are the Tor Project's own\n"
            "build with one change: Shekyl signed each with its Developer ID, because\n"
            "macOS will not run an unsigned binary. Every byte outside the code\n"
            "signature is the Tor Project's; Shekyl checked that when it packaged them,\n"
            "against the files in the bundle below:\n"
            + "".join(f"  {e['name']}  SHA-256 {e['sha256']}\n" for e in row["upstream"])
            + "The daemon checks each signed file against a recorded SHA-256 before every\n"
            "launch. The licence texts the bundle ships for tor and the libraries beside\n"
            "it are in this directory.\n"
        )
    else:
        provenance = (
            "The files in the tor directory of this package are the Tor Project's own\n"
            "build, unmodified: Shekyl extracts them from the Expert Bundle and checks\n"
            "each against a recorded SHA-256 before every launch. The licence texts the\n"
            "bundle ships for tor and the libraries beside it are in this directory.\n"
        )
    return (
        f"Tor {tor}, from the Tor Expert Bundle {row['bundle_version']} "
        f"({row['bundle_target']}).\n"
        "\n"
        + provenance
        + "\n"
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


def pe_imports(data, where):
    """The DLL names a PE image imports (`tor_pe`).

    `(imports, delay_imports)`, each in table order. A table this reader
    cannot follow is a refusal, not an empty list.
    """
    try:
        return tor_pe.pe_imports(data, where)
    except tor_pe.PeFormatError as exc:
        raise Refused(str(exc)) from exc


def check_imports(data, where, row):
    """Windows: the executable imports only the DLLs its row names, and
    delay-loads nothing (TB-11). Names compare as the Windows loader does,
    case-folded.

    The delay-load half reads the table the linker records. The delay-load
    helper finds its descriptors through the binary's own code, not through
    that directory, so a binary built to hide one would not be seen here.
    This is a tripwire on the Tor Project's signed builds, which are digest-
    pinned already: it notices a new bundle that starts loading a DLL of its
    own. It is not a proof about an arbitrary binary."""
    allowed = {name.lower() for name in row["imports"]}
    imports, delayed = pe_imports(data, where)
    if delayed:
        raise Refused(
            f"{where} delay-loads {', '.join(delayed)}; the pin allows no delay-load import"
        )
    unlisted = [name for name in imports if name.lower() not in allowed]
    if unlisted:
        raise Refused(
            f"{where} imports {', '.join(unlisted)}, which the pin's import list does not name"
        )


def check_signature_tie(upstream, shipped, where):
    """The shipped file is `upstream` plus one code signature.

    The comparison lives in `tor_macho`, which sees only the two byte strings.
    A difference there is this gate's refusal, in the same words.
    """
    try:
        tor_macho.check_signature_tie(upstream, shipped, where)
    except tor_macho.SignatureTieError as exc:
        raise Refused(str(exc)) from exc


def open_tarball(tarball):
    """The Expert Bundle as a gzip tar, or a refusal that names the file."""
    try:
        return tarfile.open(tarball, "r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise Refused(f"{tarball} could not be opened as a tarball: {exc}") from exc


def bundle_members(tar, archive_name, entries, pin_noun):
    """`entries` from `tor/` of an already-open tarball, each matching its digest.

    `pin_noun` is `pin` for the bytes that ship, and `upstream pin` for Tor's
    own bytes on a row that carries `upstream`.
    """
    out = {}
    for entry in entries:
        name = entry["name"]
        data = read_member(tar, f"{BUNDLE_TOR_DIR}/{name}")
        actual = hashlib.sha256(data).hexdigest()
        if actual != entry["sha256"]:
            raise Refused(
                f"{name} in {archive_name} does not match its {pin_noun}: "
                f"expected sha256 {entry['sha256']}, found {actual}"
            )
        out[name] = data
    return out


def upstream_files(row, sources):
    """Tor's own bytes for a row that carries `upstream`.

    Each `upstream` file is read from the digest-checked tarball and checked
    against its own pin.
    """
    tarball = sources / tarball_name(row)
    if not tarball.is_file():
        raise Refused(
            f"{tarball} is not in the sources cache; the tie reads Tor's bytes from it"
        )
    check_tarball(tarball, row)
    with open_tarball(tarball) as tar:
        return bundle_members(tar, tarball.name, row["upstream"], "upstream pin")


def read_bundle(tarball, row):
    """One open of `tarball`. Returns `(shipped, upstream, texts)`.

    `shipped` is the bytes to pack, or None when the row carries `upstream`
    (those bytes come from the signed cache). `upstream` is Tor's then, and
    None otherwise. `texts` is the licence texts, each `(file name, bytes)`.
    A Windows executable is checked against the row's import list on the bytes
    about to be packed.
    """
    with open_tarball(tarball) as tar:
        texts = [
            (Path(member).name, read_member(tar, member)) for member in row["licenses"]
        ]
        if carries_upstream(row):
            upstream = bundle_members(tar, tarball.name, row["upstream"], "upstream pin")
            return None, upstream, texts
        shipped_map = bundle_members(tar, tarball.name, row["files"], "pin")
        if row["os"] == "windows":
            executable = row["executable"]
            for name, data in shipped_map.items():
                if file_identity(row["os"], name) == file_identity(row["os"], executable):
                    check_imports(data, f"{name} in {tarball.name}", row)
        shipped = [(entry["name"], shipped_map[entry["name"]]) for entry in row["files"]]
        return shipped, None, texts


def check_tie(directory, row, upstream):
    """Each shipped file in `directory` is its upstream file signed."""
    for name, data in upstream.items():
        check_signature_tie(data, (directory / name).read_bytes(), str(directory / name))


def check_directory(directory, row):
    """The daemon's rule, applied before packing: exactly the pinned files,
    each a regular file with the pinned digest. A Windows executable also
    imports only what its row lists (`check_imports`)."""
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
    if row["os"] == "windows":
        executable = directory / row["executable"]
        check_imports(executable.read_bytes(), str(executable), row)


def signed_files(row, signed):
    """The signed files from the sources cache.

    `signed` holds exactly the pinned names, each checked against its shipped
    pin. An extra name is a refusal: `fetch` checks the names it was asked
    for, and this is the check that the directory holds nothing else.
    """
    if not signed.is_dir():
        raise Refused(f"{signed} is not a directory")
    pinned = {entry["name"]: entry["sha256"] for entry in row["files"]}
    present = sorted(os.listdir(signed))
    if present != sorted(pinned):
        raise Refused(f"{signed} holds {present}; the signed files are exactly {sorted(pinned)}")
    out = {}
    for name, expected in pinned.items():
        path = signed / name
        if not stat.S_ISREG(os.lstat(path).st_mode):
            raise Refused(f"{path} is not a regular file")
        data = path.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise Refused(f"{path} does not match its pin: expected sha256 {expected}, found {actual}")
        out[name] = data
    return out


def stage(doc, row, sources, dest, licenses, offline=False):
    """Write the pinned files and the licence texts.

    A row that carries `upstream` packs the signed files from the sources
    cache `fetch` filled, and from nowhere else. The tarball is opened once.
    """
    tarball, signed = fetch(doc, row, sources, offline=offline)
    # `fetch` checked a file it found or downloaded. The digest is read again
    # from the file this function is about to open, so the check and the
    # extraction are of one file whatever `fetch` did.
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
    shipped, upstream, texts = read_bundle(tarball, row)
    if signed is not None:
        shipped = []
        for name, data in signed_files(row, signed).items():
            check_signature_tie(upstream[name], data, f"{name} in {signed}")
            shipped.append((name, data))

    dest.mkdir(parents=True, exist_ok=True)
    licenses.mkdir(parents=True, exist_ok=True)
    for name, data in shipped:
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


def verify_bundle(row, directory, sources):
    """The daemon's directory rule, and the cached tarball when one is given.

    `--sources` re-checks that tarball on every host. A row that carries
    `upstream` requires the cache, and ties each staged file to Tor's bytes.
    """
    check_directory(directory, row)
    if sources is not None:
        tarball = sources / tarball_name(row)
        if not tarball.is_file():
            raise Refused(
                f"{tarball} is not in the sources cache; verify was given --sources"
            )
        check_tarball(tarball, row)
    if carries_upstream(row):
        if sources is None:
            raise Refused(
                f"{row['gitian_host']} ships signed files; verify needs --sources "
                "to tie them to Tor's tarball"
            )
        check_tie(directory, row, upstream_files(row, sources))


def tie_report(tarball, signed):
    """Pin time: tie each signed file to Tor's file of the same name in
    `tarball` and return the row's `files` and `upstream` lists."""
    if not signed.is_dir():
        raise Refused(f"{signed} is not a directory")
    names = sorted(os.listdir(signed))
    if not names:
        raise Refused(f"{signed} is empty")
    files, upstream = [], []
    with open_tarball(tarball) as tar:
        for name in names:
            original = read_member(tar, f"{BUNDLE_TOR_DIR}/{name}")
            data = (signed / name).read_bytes()
            check_signature_tie(original, data, f"{name} in {signed}")
            files.append({"name": name, "sha256": hashlib.sha256(data).hexdigest()})
            upstream.append({"name": name, "sha256": hashlib.sha256(original).hexdigest()})
    return {"files": files, "upstream": upstream}


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
        help="refuse if --sources lacks a pinned input instead of downloading it",
    )
    cmd = with_host("verify")
    cmd.add_argument("--dir", type=Path, required=True, help="tor's directory")
    cmd.add_argument(
        "--sources",
        type=Path,
        help="the sources cache: re-check its tarball, and tie a row that carries upstream",
    )
    cmd = sub.add_parser("tie")
    cmd.add_argument("--tarball", type=Path, required=True, help="the signature-checked Expert Bundle")
    cmd.add_argument("--signed", type=Path, required=True, help="the signed files")
    args = parser.parse_args(argv)

    if args.command == "fetch":
        if bool(args.host) == bool(args.all):
            parser.error("fetch takes exactly one of --host and --all")
    elif args.command == "tie":
        try:
            print(json.dumps(tie_report(args.tarball, args.signed), indent=2))
        except Refused as exc:
            print(f"tor_bundle: REFUSED: {exc}", file=sys.stderr)
            return 1
        return 0
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
                tarball, signed_dir = fetch(doc, row, args.sources)
                print(f"{row['gitian_host']}: {tarball}")
                if signed_dir is not None:
                    print(f"{row['gitian_host']}: {signed_dir}")
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
            verify_bundle(row, args.dir, args.sources)
            print(f"{args.host}: {args.dir} holds exactly the pinned bundle")
    except Refused as exc:
        print(f"tor_bundle: REFUSED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
