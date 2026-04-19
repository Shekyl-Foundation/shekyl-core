# Release Signing

Shekyl release tags are signed with GPG. This document lists the current
maintainer signing keys, explains how to verify a release, and records the
policy for adding, rotating, and retiring keys.

Policy for when this applies: every release tag created from
`v3.1.0-alpha.3` onward. Earlier tags (`v3.1.0-alpha.1`, `v3.1.0-alpha.2`)
predate this policy and are not signed; their authenticity is established
by the branch topology and by reproducible Guix builds, not by tag
signatures.

## Policy

- Every release tag on `main` (`vX.Y.Z`, `vX.Y.Z-alpha.N`, `vX.Y.Z-beta.N`,
  `vX.Y.Z-rc.N`) is a **signed annotated tag** created with
  `git tag -a -s`.
- The tag is signed by the maintainer who cut the release, using a key
  listed under "Maintainer keys" below.
- Commits on `dev` and `main` SHOULD also be signed by the authoring
  maintainer so the `git log` audit trail is cryptographically linked to
  tag-signing authority. This is recommended but not enforced by branch
  protection as of V3.1.
- A Shekyl Foundation institutional signing key is NOT in use as of V3.1.
  See "Future: Foundation institutional signing key" below for the
  reasoning. Tracked in `docs/FOLLOWUPS.md`.

## Maintainer keys

### Rick Dawson

- **GPG fingerprint**: `C4C5 A5BD 808D 87C0 2A65  E067 FEFE C7EF 9952 D40C`
- **Long key ID**: `FEFEC7EF9952D40C`
- **Algorithm**: ed25519 (signing / certification) + cv25519 (encryption)
- **Created**: 2026-04-19
- **UID**: `Rick Dawson (For github development) <dawsora@gmail.com>`
- **GitHub**: [@radawson](https://github.com/radawson) — key registered
  on the GitHub account so that signed commits and tags display the
  "Verified" badge.
- **Status**: Active. Signs release tags from `v3.1.0-alpha.3` onward.

Public key (ASCII-armored):

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEaeTkSRYJKwYBBAHaRw8BAQdAX6R6m9VXwx4PL2wkW1w59rr24y/oJOljD3tN
/cKlWIa0OFJpY2sgRGF3c29uIChGb3IgZ2l0aHViIGRldmVsb3BtZW50KSA8ZGF3
c29yYUBnbWFpbC5jb20+iJAEExYKADgWIQTExaW9gI2HwCpl4Gf+/sfvmVLUDAUC
aeTkSQIbAwULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRD+/sfvmVLUDHhEAQDr
crD9FdKdYaiUXz556pEVL7JXaZG0ZX8p6Q9FNAE/IgD/WpwbDHtJMfvuKMyl+fa6
378044CTyoaOGl3mRgilJwO4OARp5ORJEgorBgEEAZdVAQUBAQdAzFQ3Q7I83i65
E3T2VU/TkJbEeRIlsDC78eNOuklMnA8DAQgHiHgEGBYKACAWIQTExaW9gI2HwCpl
4Gf+/sfvmVLUDAUCaeTkSQIbDAAKCRD+/sfvmVLUDB+2AQDEd9vAWJAVcaHGX7zf
wq00cffv1yPDDb38W3FgTOKmtwD9GhQ9/a/9i1bmZaiVJITDz7zpzCa6Sgp1MDNq
JobCfwk=
=sote
-----END PGP PUBLIC KEY BLOCK-----
```

## Verifying a release

```bash
# 1. Import the maintainer key. Any of these work:
gpg --import docs/SIGNING.md                 # extracts and imports the armored block in this file
gpg --locate-keys dawsora@gmail.com          # fetches from WKD / keyserver
gpg --recv-keys C4C5A5BD808D87C02A65E067FEFEC7EF9952D40C

# 2. Verify the tag:
git verify-tag v3.1.0-alpha.3
```

A successful verification prints a line like:

```
gpg: Good signature from "Rick Dawson (For github development) <dawsora@gmail.com>" [ultimate]
Primary key fingerprint: C4C5 A5BD 808D 87C0 2A65  E067 FEFE C7EF 9952 D40C
```

The fingerprint line **must match** a fingerprint listed in this document.
If it does not, do not trust the release. `git verify-tag` also prints
"BAD signature" or "Can't check signature: No public key" on failure; in
either case, stop and report the discrepancy on the project issue tracker.

### Reproducible-build cross-check

Tag signatures assert "an authorized maintainer approved this source." For
the stronger assertion "the binary you downloaded matches the reviewed
source," rebuild from the signed tag using the Guix pipeline and compare
the resulting artifact hash to the published one. Both mechanisms are
required for full release integrity; neither subsumes the other.

## Adding a new maintainer key

1. The new maintainer generates a GPG key and registers its public half
   with their GitHub account.
2. They open a PR against `docs/SIGNING.md` adding their entry under
   "Maintainer keys" with the same fields as existing entries.
3. The PR is signed off by at least one existing maintainer. For
   fingerprint authenticity, the existing maintainer verifies the
   fingerprint out-of-band (in person, via a second channel, or via a
   pre-existing signed communication) — not from the PR itself.
4. The new key takes effect for release signing on the first tag
   following the PR merge.

## Rotating or retiring a key

When a maintainer rotates (planned renewal) or retires (departure, loss,
suspected compromise) a key, they update their entry in `docs/SIGNING.md`:

- Change the **Status** line to
  `Retired YYYY-MM-DD. Historical signatures remain verifiable; no new releases signed by this key.`
- For a rotation (same maintainer, new key), add the new key as a
  separate subsection under the same maintainer name with its own
  fingerprint block.
- In the case of suspected compromise, also publish a GPG revocation
  certificate to keyservers so automated verification tooling picks up
  the revocation. The revocation certificate should have been generated
  at key-creation time and stored offline (see "Key hygiene" below).

Historical signatures by a retired-but-not-revoked key remain valid for
verifying older releases. Verification tooling should not warn on such
keys when checking tags created before the retirement date.

## Key hygiene

Maintainers listed in this document are expected to:

- Store the private key on an encrypted volume, a hardware token
  (YubiKey, Nitrokey, etc.), or both.
- Generate a revocation certificate at key-creation time and store it
  offline, separately from the private key.
- Keep at least one offline backup of the private key material.
- Use a passphrase on the private key.
- Register the public key with GitHub so signed commits and tags show
  the "Verified" badge, providing an independent second signal to
  downloaders.

## Why GPG, not SSH signing or Sigstore

- **SSH signing** (git 2.34+, GitHub "Verified" support from 2022) is
  adequate for commit-authorship verification but has thinner ecosystem
  support for release-tag verification workflows — downstream package
  tooling, Debian signature checks, and most `git verify-tag` consumers
  still assume GPG.
- **Sigstore / cosign** (ephemeral signing via OIDC) is a strong fit for
  container images and build-pipeline attestations, but does not align
  with the `git verify-tag` workflow that cryptocurrency-release
  downloaders expect.

GPG on ed25519 keys gives downstream-tool compatibility of traditional
PGP with the performance and cryptographic properties of modern
elliptic-curve signatures. If that calculus changes (Sigstore gains
first-class `git tag` integration, or the cryptocurrency ecosystem
migrates away from PGP), this document is revised.

## Future: Foundation institutional signing key

A Shekyl Foundation signing key is deliberately not in use at V3.1.
Threat-model reasoning:

- A "Foundation key" held by one person is operationally identical to a
  personal key, with worse threat-model clarity ("who actually signed
  this?").
- An institutional key only adds value when there is ceremony around it:
  HSM or hardware-token storage, documented rotation policy, quorum
  signing for release authority. Building that before the Foundation
  has staffing and process to maintain it adds operational risk without
  corresponding security gain.
- When Shekyl Foundation transitions from project-entity to
  multi-maintainer operational entity, an institutional signing key is
  introduced **alongside** (not replacing) maintainer keys. Downloaders
  can verify against either; the transition is additive.

Tracked in `docs/FOLLOWUPS.md` with target V3.1.x+, contingent on
multi-maintainer structure.
