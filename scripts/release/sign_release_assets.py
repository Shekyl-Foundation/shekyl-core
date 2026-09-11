#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The release-asset signing ceremony (RELEASE_CHECKLIST "asset manifest
signing"; CBOM §6).

`docs/SIGNING.md` governs the release TAG; this script is the ASSET half —
a signed tag authenticates the commit a release was cut from, not the
binary a user downloads. The ceremony here produces a signed `SHA256SUMS`
manifest with the Foundation signing subkey: one signature, covering every
published asset, same key and same hardware-token ceremony as the tags.

The signing subkey is hardware-token-held (SIGNING.md), so this CANNOT run
in CI by design: the release owner runs it locally, with the token
inserted. The same script is the downstream verifier (`--verify-only`),
so producers and consumers exercise one process.

Ceremony (each phase fails loud; nothing is published unverified):

  1. preflight  — key hygiene per SIGNING.md: Foundation primary present
                  as an OFFLINE STUB (`sec#`, never `sec `), signing
                  subkey present and on-card (`ssb>`); the release tag
                  verifies under a pinned Foundation fingerprint.
  2. collect    — enumerate assets (a local directory, or `--download`
                  fetches the GitHub release's published assets).
  3. manifest   — write `SHA256SUMS` in coreutils format (sorted, LF),
                  so `sha256sum -c SHA256SUMS` works everywhere.
  4. sign       — `gpg --detach-sign --armor` with EXACTLY the Foundation
                  signing subkey (`<id>!`) -> `SHA256SUMS.asc`. The token
                  prompts for its Signature PIN here.
  5. verify     — round-trip before anything ships: the signature checks
                  under the pinned subkey fingerprint AND every asset
                  re-hashes against the manifest.
  6. upload     — only with `--upload`: attach both manifest files to the
                  GitHub release (refuses to overwrite without
                  `--clobber`).

Typical use:

  # Release owner, token inserted, after the gitian job published assets:
  python3 scripts/release/sign_release_assets.py v3.1.0-alpha.5 \
      --download --upload

  # Anyone, verifying a published release:
  python3 scripts/release/sign_release_assets.py v3.1.0-alpha.5 \
      --download --verify-only

Exit codes: 0 = ceremony complete/verified; 1 = a phase refused (message
says which and why); 2 = usage error. Every subprocess verdict is read
from its own exit status, never through a pipe (rule 46).
"""

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

# ── Pinned identity — docs/SIGNING.md is canonical; these are copies ──────
# (the gpg output checks below compare against these; a rotation per
# SIGNING.md's two-year subkey expiry updates this block in the same PR
# that updates the doc).
FOUNDATION_PRIMARY_FPR = "F5F75A4770C94FE1D5A5AE59844E424F98664F44"
FOUNDATION_PRIMARY_ID = "844E424F98664F44"
FOUNDATION_SIGNING_SUBKEY_FPR = "3778B4C863C61512B5FC22036914D74823DDA8DC"
FOUNDATION_SIGNING_SUBKEY_ID = "6914D74823DDA8DC"

MANIFEST = "SHA256SUMS"
SIGNATURE = "SHA256SUMS.asc"


def die(msg: str, code: int = 1) -> "sys.NoReturn":
    print(f"refused: {msg}", file=sys.stderr)
    sys.exit(code)


def run(argv: list[str], capture: bool = True) -> subprocess.CompletedProcess:
    """Run a command; the caller inspects .returncode explicitly."""
    return subprocess.run(
        argv,
        capture_output=capture,
        text=True,
        check=False,
    )


# ── Phase 1: preflight ────────────────────────────────────────────────────


def preflight_key_hygiene(subkey_fpr: str, allow_ondisk_subkey: bool) -> None:
    """The SIGNING.md invariants, checked mechanically before any signing.

    - Primary must be an offline stub: `sec#`. A bare `sec ` means the
      primary private key is on this host — SIGNING.md calls that a
      key-hygiene incident, so this script refuses outright (no override:
      the remedy is fixing the keyring, not skipping the check).
    - Signing subkey must be present, and on-card (`ssb>`). Key material
      on disk contradicts the hardware-token posture; refused unless the
      loudly-named override is given (a legitimate case exists only for
      a non-Foundation maintainer-fallback key).
    """
    is_foundation = subkey_fpr == FOUNDATION_SIGNING_SUBKEY_FPR
    if not is_foundation:
        print(f"  preflight: non-Foundation key {subkey_fpr} — hygiene checks "
              "reduced to presence (maintainer-fallback path, SIGNING.md)")
    proc = run(["gpg", "--list-secret-keys", "--with-colons", subkey_fpr])
    if proc.returncode != 0:
        die(
            f"signing key {subkey_fpr} is not in this keyring. For the "
            "Foundation key, `gpg --import` the public block in "
            "docs/SIGNING.md — and note the SECRET half lives only on the "
            "hardware token; the keyring needs the public key plus the "
            "on-card stub (insert the token and run `gpg --card-status` "
            "once to create it)."
        )
    lines = proc.stdout.splitlines()
    if is_foundation:
        # --with-colons: field 1 is the record type. `sec` records carry
        # field 15 (token S/N): `#` = offline stub (the ONLY state
        # SIGNING.md permits for the primary), `+` = private material on
        # this host, a serial = primary moved to a card — which also
        # violates the offline-primary posture. Fail closed on anything
        # that is not exactly the stub, including never having seen the
        # primary's `sec` record at all.
        primary_state = None
        for ln in lines:
            f = ln.split(":")
            if f[0] == "sec" and FOUNDATION_PRIMARY_ID in ln:
                primary_state = f[14] if len(f) > 14 else ""
        if primary_state != "#":
            if primary_state == "+":
                die(
                    "the Foundation PRIMARY private key is present on "
                    "this host (`sec` without the stub marker). "
                    "SIGNING.md: offline-primary policy violated — stop "
                    "and treat as a key-hygiene incident."
                )
            die(
                "the Foundation primary is not an offline stub (`sec#`): "
                f"observed state {primary_state!r}. SIGNING.md permits "
                "exactly the stub — a card serial means the primary was "
                "moved onto a token (still not the offline posture), and "
                "an absent/unknown record is refused rather than assumed "
                "safe."
            )
        subkey_ok = False
        for ln in lines:
            f = ln.split(":")
            if f[0] == "ssb" and len(f) > 14:
                # on-card stubs carry the token serial number in field 15
                on_card = bool(f[14]) and f[14] not in ("+", "")
                if on_card:
                    subkey_ok = True
        if not subkey_ok and not allow_ondisk_subkey:
            die(
                "the Foundation signing subkey does not show as an on-card "
                "stub (`ssb>` / token serial in the colon listing). Either "
                "the token has not been introduced to this keyring "
                "(`gpg --card-status`), or the subkey's private material is "
                "on disk — which contradicts SIGNING.md's token posture. "
                "Pass --unsafe-allow-ondisk-subkey ONLY if you know why."
            )
    print(f"  preflight: key hygiene OK ({'Foundation' if is_foundation else 'fallback'} key)")


def preflight_tag(tag: str, expected_fprs: list[str]) -> None:
    proc = run(["git", "verify-tag", "--raw", tag])
    if proc.returncode != 0:
        die(
            f"`git verify-tag {tag}` failed — the assets ceremony refuses "
            "to sign a manifest for a tag that does not itself verify "
            "(SIGNING.md governs the tag; do that ceremony first). "
            f"stderr: {proc.stderr.strip()[:300]}"
        )
    # --raw status lines carry VALIDSIG <fingerprint> ... <primary-fpr>
    m = re.search(r"VALIDSIG (\w+) .* (\w+)$", proc.stderr, re.MULTILINE)
    fprs = set(m.groups()) if m else set()
    if not fprs & set(expected_fprs):
        die(
            f"tag {tag} verifies, but not under a pinned key "
            f"(saw {sorted(fprs)}; pinned {expected_fprs}). If this is the "
            "documented maintainer-fallback, re-run with --key <that "
            "maintainer's signing fingerprint>."
        )
    print(f"  preflight: tag {tag} verifies under a pinned key")


# ── Phases 2–3: collect + manifest ────────────────────────────────────────


def collect_assets(assets_dir: Path) -> list[Path]:
    if not assets_dir.is_dir():
        die(f"assets directory {assets_dir} does not exist")
    assets = sorted(
        p for p in assets_dir.iterdir()
        if p.is_file() and p.name not in (MANIFEST, SIGNATURE)
    )
    if not assets:
        die(f"no assets found in {assets_dir} (manifest files excluded)")
    print(f"  collect: {len(assets)} asset(s) in {assets_dir}")
    return assets


def download_assets(tag: str, assets_dir: Path, verify_only: bool) -> None:
    # A download works from a CLEAN slate, refused otherwise: a reused
    # directory can hold stale versions of same-named assets or leftovers
    # from a different tag, and both would silently enter the manifest —
    # a signed manifest that does not match the release's published
    # binaries is the exact failure this ceremony exists to prevent. The
    # refusal is deliberate (this script never deletes files it did not
    # create): point --assets-dir at a fresh directory, or clear the old
    # one yourself.
    assets_dir.mkdir(parents=True, exist_ok=True)
    leftovers = sorted(p.name for p in assets_dir.iterdir())
    if leftovers:
        die(
            f"--download requires an empty assets directory, but "
            f"{assets_dir} already contains {len(leftovers)} entr(y/ies) "
            f"(e.g. {leftovers[0]}). Use a fresh directory or clear it "
            "yourself — a reused directory can put stale or foreign files "
            "into the signed manifest."
        )
    proc = run(
        ["gh", "release", "download", tag, "--dir", str(assets_dir)],
        capture=False,
    )
    if proc.returncode != 0:
        die(f"`gh release download {tag}` failed")
    if not verify_only:
        for stale in (assets_dir / MANIFEST, assets_dir / SIGNATURE):
            if stale.exists():
                stale.unlink()
                print(f"  download: removed previously-published {stale.name} "
                      "from the working set (it is being re-produced)")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(assets: list[Path], out: Path) -> None:
    # coreutils format: "<hex>  <name>\n" (two spaces, LF) so plain
    # `sha256sum -c SHA256SUMS` verifies it with no tooling of ours.
    lines = [f"{sha256_file(p)}  {p.name}\n" for p in assets]
    out.write_text("".join(lines), encoding="ascii", newline="\n")
    print(f"  manifest: wrote {out} ({len(lines)} entries)")


# ── Phase 4: sign ─────────────────────────────────────────────────────────


def sign_manifest(manifest: Path, signature: Path, subkey_id: str) -> None:
    if signature.exists():
        signature.unlink()
    # `<id>!` = exactly this subkey, never a gpg-chosen sibling. This is
    # where the hardware token prompts for its Signature PIN.
    proc = run(
        ["gpg", "--detach-sign", "--armor", "--local-user", f"{subkey_id}!",
         "--output", str(signature), str(manifest)],
        capture=False,
    )
    if proc.returncode != 0:
        die("gpg --detach-sign failed (token not inserted, wrong PIN, or "
            "the subkey is unavailable)")
    print(f"  sign: {signature} written")


# ── Phase 5: verify (round-trip; also the downstream path) ────────────────


def verify(manifest: Path, signature: Path, assets_dir: Path,
           expected_fpr: str) -> None:
    if not manifest.exists() or not signature.exists():
        die(f"{MANIFEST} / {SIGNATURE} not found in {assets_dir}")
    proc = run(["gpg", "--status-fd", "2", "--verify",
                str(signature), str(manifest)])
    if proc.returncode != 0:
        die(f"signature does NOT verify: {proc.stderr.strip()[:300]}")
    m = re.search(r"VALIDSIG (\w+)", proc.stderr)
    got = m.group(1) if m else "<none>"
    if got != expected_fpr:
        die(
            f"manifest signature verifies, but under {got}, not the pinned "
            f"signing key {expected_fpr} — wrong key signed it."
        )
    entries = {}
    for ln in manifest.read_text(encoding="ascii").splitlines():
        m2 = re.fullmatch(r"([0-9a-f]{64})  (\S.*)", ln)
        if not m2:
            die(f"malformed manifest line: {ln!r}")
        name = m2.group(2)
        if name in entries:
            # Refuse rather than let the last line win: coreutils
            # `sha256sum -c` checks EVERY line, so a duplicate-name
            # manifest that this verifier waved through could still fail
            # (or worse, pass differently) under the standard tool — the
            # two verifiers must never diverge. Our writer cannot produce
            # duplicates; one in the input is malformed or hostile.
            die(f"duplicate manifest entry for {name!r} — malformed manifest")
        entries[name] = m2.group(1)
    if not entries:
        die("manifest is empty")
    for name, want in sorted(entries.items()):
        p = assets_dir / name
        if not p.is_file():
            die(f"manifest names {name} but it is not present in {assets_dir}")
        have = sha256_file(p)
        if have != want:
            die(f"HASH MISMATCH for {name}: manifest {want}, file {have}")
    # Completeness, not just membership: an asset present in the
    # directory but absent from the manifest is UNAUTHENTICATED — on the
    # `--download --verify-only` path that is exactly a binary someone
    # attached to the release after the ceremony, and "verified." must
    # never cover it. (The sign path builds the manifest from this same
    # directory, so extras structurally cannot exist there.)
    unlisted = sorted(
        p.name for p in assets_dir.iterdir()
        if p.is_file()
        and p.name not in (MANIFEST, SIGNATURE)
        and p.name not in entries
    )
    if unlisted:
        die(
            f"{len(unlisted)} asset(s) present but NOT in the signed "
            f"manifest (e.g. {unlisted[0]!r}) — unauthenticated files; "
            "if published, someone attached them after the ceremony."
        )
    print(f"  verify: signature OK under {expected_fpr}, "
          f"{len(entries)} hash(es) match, no unlisted assets")


# ── Phase 6: upload ───────────────────────────────────────────────────────


def upload(tag: str, manifest: Path, signature: Path, clobber: bool) -> None:
    argv = ["gh", "release", "upload", tag, str(manifest), str(signature)]
    if clobber:
        argv.append("--clobber")
    proc = run(argv, capture=False)
    if proc.returncode != 0:
        die(
            f"`gh release upload {tag}` failed. If the release already "
            "carries a manifest, re-run with --clobber ONLY if replacing "
            "it is the deliberate intent."
        )
    print(f"  upload: {MANIFEST} + {SIGNATURE} attached to {tag}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Sign (or verify) a release's SHA256SUMS manifest with "
                    "the Foundation signing subkey, per docs/SIGNING.md.",
    )
    ap.add_argument("tag", help="release tag, e.g. v3.1.0-alpha.5")
    ap.add_argument("--assets-dir", type=Path, default=None,
                    help="directory holding the release assets "
                         "(default: release-assets/<tag>)")
    ap.add_argument("--download", action="store_true",
                    help="fetch the tag's published assets via `gh release "
                         "download` into --assets-dir first")
    ap.add_argument("--upload", action="store_true",
                    help="after a verified sign, attach SHA256SUMS(.asc) to "
                         "the GitHub release")
    ap.add_argument("--clobber", action="store_true",
                    help="allow --upload to replace an existing manifest")
    ap.add_argument("--verify-only", action="store_true",
                    help="verify an existing SHA256SUMS(.asc) against the "
                         "pinned key and the assets; sign nothing (the "
                         "downstream-consumer path)")
    ap.add_argument("--key", default=None, metavar="FPR",
                    help="sign/verify under this fingerprint instead of the "
                         "Foundation subkey (the SIGNING.md maintainer-"
                         "fallback; hygiene checks reduce to presence)")
    ap.add_argument("--no-tag-check", action="store_true",
                    help="skip `git verify-tag` (ONLY for exercising the "
                         "ceremony outside a release checkout)")
    ap.add_argument("--unsafe-allow-ondisk-subkey", action="store_true",
                    help="proceed although the signing subkey is not an "
                         "on-card stub (contradicts SIGNING.md; the name "
                         "says the rest)")
    args = ap.parse_args()

    subkey_fpr = (args.key or FOUNDATION_SIGNING_SUBKEY_FPR).replace(" ", "").upper()
    subkey_id = subkey_fpr[-16:]
    assets_dir = args.assets_dir or Path("release-assets") / args.tag
    manifest = assets_dir / MANIFEST
    signature = assets_dir / SIGNATURE

    print(f"release-asset ceremony: {args.tag} "
          f"({'verify-only' if args.verify_only else 'sign'})")

    if args.download:
        download_assets(args.tag, assets_dir, args.verify_only)

    if args.verify_only:
        verify(manifest, signature, assets_dir, subkey_fpr)
        print("verified.")
        return

    preflight_key_hygiene(subkey_fpr, args.unsafe_allow_ondisk_subkey)
    if not args.no_tag_check:
        preflight_tag(args.tag,
                      [FOUNDATION_PRIMARY_FPR, subkey_fpr])
    assets = collect_assets(assets_dir)
    write_manifest(assets, manifest)
    sign_manifest(manifest, signature, subkey_id)
    verify(manifest, signature, assets_dir, subkey_fpr)
    if args.upload:
        upload(args.tag, manifest, signature, args.clobber)
    else:
        print(f"done (not uploaded): {manifest} + {signature} — attach with "
              f"--upload, or manually via `gh release upload {args.tag} ...`")


if __name__ == "__main__":
    main()
