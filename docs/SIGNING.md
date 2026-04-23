# Release Signing

Shekyl release tags are signed with GPG. This document is the canonical,
self-contained reference for:

- which keys are authoritative,
- how a maintainer cuts and signs a release tag (the "ceremony"),
- how a downstream consumer verifies one.

If any step in this document fails mid-release, **stop and re-read from the
top**. Do not improvise. A partially-signed or mis-signed release tag is
worse than no tag, because it poisons downstream verification tooling that
caches the first signature it sees for a given tag name.

Policy scope: every release tag created from `v3.1.0-alpha.3` onward.
Earlier tags (`v3.1.0-alpha.1`, `v3.1.0-alpha.2`) predate this policy and
are not signed; their authenticity is established by branch topology and by
reproducible Guix builds, not by tag signatures.

## Policy

- Every release tag on `main` (`vX.Y.Z`, `vX.Y.Z-alpha.N`, `vX.Y.Z-beta.N`,
  `vX.Y.Z-rc.N`) is a **signed annotated tag** created with
  `git tag -u <key> -a -s`.
- Tags live **on `main`**, on the non-fast-forward merge commit produced by
  merging `dev` into `main` at release time. Tags are never created on
  `dev` and never migrated between branches after the fact. The full
  release sequence is described in `docs/RELEASING.md`.
- From `v3.1.0-alpha.5` onward, the **preferred signer** for release tags
  is the Shekyl Foundation institutional key (subkey fingerprint
  `3778 B4C8 63C6 1512 B5FC 2203 6914 D748 23DD A8DC`, long ID
  `6914D74823DDA8DC`). See "Institutional key" below.
- Maintainer keys listed under "Maintainer keys" remain valid signing
  authorities and valid for historical verification. An individual
  maintainer MAY sign a release tag with their personal key when the
  institutional key is unavailable (hardware token lost, primary holder
  incapacitated); such a release is announced out-of-band with a reason.
  This is **additive**, not "use either at whim" — the institutional key
  is the default path and the personal-key path is a documented fallback.
- Commits on `dev` and `main` SHOULD be signed by the authoring
  maintainer's personal key (not the institutional key). Commit-level
  signatures answer "who authored this," which is a different question
  from "who represented the Foundation in releasing it." Personal
  maintainer keys remain the right tool for commit signing.

## Keys

### Institutional key — Shekyl Foundation

- **Primary fingerprint**:
  `F5F7 5A47 70C9 4FE1 D5A5  AE59 844E 424F 9866 4F44`
- **Primary long ID**: `844E424F98664F44`
- **Primary role**: certification only (`[C]`). Cannot sign tags.
  Stored **offline** — no copy of the primary private key exists on any
  internet-connected host. Verify this on your own workstation with
  `gpg --list-secret-keys 844E424F98664F44`; the line should read
  `sec#  ed25519/844E424F98664F44` — the `#` marker means the secret key
  material is absent (the keyring holds only the public half and a stub
  pointer). If you see `sec ` without the `#`, the primary key is
  present on that host and the offline-primary policy has been violated
  — stop and treat as a key-hygiene incident.
- **Signing subkey fingerprint**:
  `3778 B4C8 63C6 1512 B5FC  2203 6914 D748 23DD A8DC`
- **Signing subkey long ID**: `6914D74823DDA8DC`
- **Signing subkey role**: signing only (`[S]`). Held on an OpenPGP
  hardware token (YubiKey OpenPGP applet or equivalent); the private key
  material never leaves the hardware. Requires both physical possession
  of the token and the token's Signature PIN to produce a signature.
- **Algorithm**: ed25519 for primary and subkey.
- **Created**: 2026-04-19.
- **Subkey expiration**: 2028-04-18 (enforced two-year rotation —
  forces a yearly-ish "is this process still healthy" audit and caps
  blast radius on an undetected compromise).
- **UID**:
  `Shekyl Foundation (Release Signing Key) <releases@shekyl.org>`
- **Status**: Active. Preferred signer for release tags from
  `v3.1.0-alpha.5` onward.

Public key (ASCII-armored, primary + signing subkey):

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEaeUAjRYJKwYBBAHaRw8BAQdAjWQFECbJf52K9FZUykNNxUxqsj9vjvxC8Tqb
FUBucPy0PVNoZWt5bCBGb3VuZGF0aW9uIChSZWxlYXNlIFNpZ25pbmcgS2V5KSA8
cmVsZWFzZXNAc2hla3lsLm9yZz6IkwQTFgoAOxYhBPX3WkdwyU/h1aWuWYROQk+Y
Zk9EBQJp5QCNAhsBBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEIROQk+Y
Zk9EKDEBALJwPH68PDK9srP16ZDvN1HhQvcuNcjnHpPdmVDjeG9rAP9rijvWVHnI
Muj4p+PSpGdtoLCI3Ls5HSzMASvbu7lHDoh1BBAWCgAdFiEExMWlvYCNh8AqZeBn
/v7H75lS1AwFAmnoI/8ACgkQ/v7H75lS1AxcSwD9E8jYr6IVFa7QJXjAzADwmp6K
81JhwV2Z+8EdnDo+X7UA/1UWjYX0M8fP4HrOZ4TL+RU6RXTLR+sV+7IupOHBRT0K
uDMEaeUDHRYJKwYBBAHaRw8BAQdACIekt5u7aIxXLRPzSBIg/eQ1a83An+hfXBTd
64vVp/yI9QQYFgoAJhYhBPX3WkdwyU/h1aWuWYROQk+YZk9EBQJp5QMdAhsCBQkD
wmcAAIEJEIROQk+YZk9EdiAEGRYKAB0WIQQ3eLTIY8YVErX8IgNpFNdII92o3AUC
aeUDHQAKCRBpFNdII92o3ISNAQCdit/EJGpobyunUY+aaWck3263+gxm3RetwCEO
jh98jwD/TH5fbplLAsgMe+MN4y7THxC9rT5zWrrfeylsyajKIAAvSAD/Y2dtpZRT
dvutipLAOspNyYSi4L5l8bPKawJ+0qwAXBYBAOc4+vW1x56Bx9JyDqOaHnItG+fq
PfrTJ68L/h4QVMcO
=Lvgh
-----END PGP PUBLIC KEY BLOCK-----
```

The block above certifies both the primary certification key and the
signing subkey; importing it with `gpg --import` installs both.

Hardware-token detail (device model, serial number, firmware version) is
deliberately **not published**. Operational-security posture: naming the
hardware model in SIGNING.md is a weak signal at best for downstream
verifiers (who can only verify the signature, not the device behind it)
and a non-trivial uplift for a future second institutional-key holder
who might use different hardware. If and when a Foundation transparency
report documents device inventory, it will live in its own document.

### Maintainer keys

Maintainer keys are personal keys held by individual contributors. They
are authoritative for commit signing and serve as additive fallback for
release-tag signing (see "Policy" above — institutional key is the
default path).

#### Rick Dawson

- **GPG fingerprint**: `C4C5 A5BD 808D 87C0 2A65  E067 FEFE C7EF 9952 D40C`
- **Long key ID**: `FEFEC7EF9952D40C`
- **Algorithm**: ed25519 (signing / certification) + cv25519 (encryption)
- **Created**: 2026-04-19
- **UID**: `Rick Dawson (For github development) <dawsora@gmail.com>`
- **GitHub**: [@radawson](https://github.com/radawson) — key registered
  on the GitHub account so that signed commits and tags display the
  "Verified" badge.
- **Status**: Active. Signed release tags `v3.1.0-alpha.3` and
  `v3.1.0-alpha.4`. Remains valid for commit signing and as an
  additive fallback signer for release tags if the institutional key
  is unavailable.

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

## Release-tag signing ceremony

This is the mandatory procedure for producing a signed release tag with
the institutional key. It is self-contained; do not improvise. Every
check below has caught a real failure at least once in a neighbouring
project, and the order matters.

The ceremony assumes you have already performed `docs/RELEASING.md`
steps 1 (changelog rename on `dev`) and 2 (`git merge --no-ff dev` on
`main`). You should be on `main` with the release merge commit as
`HEAD`. The tag is placed on that commit.

### 0. Pre-flight (one time, before your first release)

Confirm on your workstation:

```bash
gpg --list-secret-keys 844E424F98664F44
```

Expected output (abbreviated):

```
sec#  ed25519/844E424F98664F44 2026-04-19 [C]
      F5F75A4770C94FE1D5A5AE59844E424F98664F44
uid           [ ... ] Shekyl Foundation (Release Signing Key) <releases@shekyl.org>
ssb>  ed25519/6914D74823DDA8DC 2026-04-19 [S] [expires: 2028-04-18]
```

The two markers that matter:

- `sec#` — hash mark on the primary line. Offline-primary invariant.
  Absence of the hash means you have the primary private key on this
  host, which is a policy violation — stop and rotate.
- `ssb>` — greater-than marker on the signing subkey line. This is
  gpg's way of saying "the secret material for this subkey lives on a
  smartcard / hardware token." Absence of the arrow means the
  subkey material is in the local keyring, which defeats the
  hardware-backing invariant — stop and investigate.

If the line for `6914D74823DDA8DC` has `[expired]` in it, the subkey
has expired and a new one needs to be issued before any release can
proceed. Escalate; do not attempt to extend the expiry from the
ceremony workstation.

### 1. Insert the YubiKey and warm the GPG agent

```bash
gpg --card-status
```

Do not skip this. `gpg --card-status` is what tells gpg-agent "the
card is here, prepare to use it." Without it, the first signing
attempt will emit `gpg: signing failed: No secret key` even with the
card physically inserted — a confusing error that has been mistaken
multiple times for "my key is gone."

Expected output (abbreviated; the parts that matter are highlighted):

```
Reader ...........: <your reader string>
Application type .: OpenPGP
Signature PIN ....: not forced
PIN retry counter : 3 0 3                    <-- see note
Signature counter : N
Signature key ....: 3778 B4C8 63C6 1512 B5FC  2203 6914 D748 23DD A8DC
General key info..: sub  ed25519/6914D74823DDA8DC ... Shekyl Foundation ...
sec#  ed25519/844E424F98664F44 ...
ssb>  ed25519/6914D74823DDA8DC ...
                                card-no: <card serial>
```

Checks:

- **Signature key fingerprint** matches
  `3778 B4C8 63C6 1512 B5FC 2203 6914 D748 23DD A8DC` exactly. A
  different fingerprint means a different card is inserted.
- **PIN retry counter `3 0 3`** is the expected shape for a signing-only
  card configuration. The three counters are
  `<Signature> <Admin> <Encryption>`; the middle `0` is NOT "admin PIN
  locked" — it reflects that no encryption subkey is provisioned on
  this card (there is no encryption key on the institutional key at
  all). If the first digit (Signature PIN retry counter) is ever `0`,
  the signature PIN is locked and must be reset with the admin PIN
  before the ceremony can proceed. If the admin PIN counter shows a
  value other than `0` and you did not consciously provision an
  encryption subkey, escalate.
- **Signature counter `N`** — remember this value. After signing the
  tag it should be exactly `N + 1`. If it is not, something signed
  other than what you intended; investigate before pushing.

### 2. Create the signed annotated tag

Use `-u` explicitly. Do **not** rely on `git config user.signingkey`
for release tags — that config is pointed at your personal commit-
signing key and should stay there. `-u` overrides it for this single
invocation.

```bash
git tag -u 6914D74823DDA8DC -a -s vX.Y.Z-alpha.N \
  -m "Shekyl vX.Y.Z-alpha.N"
```

gpg will prompt for the YubiKey's Signature PIN via pinentry. The
YubiKey's amber LED will blink on the touch-confirm step (UIF may be
off for signing on this card; if you do not see a blink, the
signature was produced without a touch). Enter the PIN, touch the
card if requested, and wait for the command to return. On success
the only output is a blank line; `git` doesn't announce success.

### 3. Verify the tag before pushing anything

This is the step that catches the wrong key being used (e.g. if you
forgot `-u` and signed with your personal key by accident).

```bash
git verify-tag vX.Y.Z-alpha.N
```

Expected output (abbreviated; the line that matters is last):

```
gpg: Signature made <date>
gpg:                using EDDSA key 3778B4C863C61512B5FC22036914D74823DDA8DC
gpg: Good signature from "Shekyl Foundation (Release Signing Key) <releases@shekyl.org>"
Primary key fingerprint: F5F7 5A47 70C9 4FE1 D5A5  AE59 844E 424F 9866 4F44
```

Checks:

- `using EDDSA key` matches the signing-subkey fingerprint
  `3778B4C863C61512B5FC22036914D74823DDA8DC`.
- `Primary key fingerprint` matches the institutional primary
  `F5F7 5A47 70C9 4FE1 D5A5 AE59 844E 424F 9866 4F44`.
- The UID is `Shekyl Foundation (Release Signing Key) ...`.

If any of the three are wrong, delete the tag locally and re-run from
step 1 after diagnosing:

```bash
git tag -d vX.Y.Z-alpha.N
```

No remote cleanup is needed because we have not pushed yet. This is
why verification happens before push — push-before-verify has created
poisoned-cache incidents in other projects.

Re-run `gpg --card-status` and observe the **Signature counter**.
Confirm it incremented by exactly 1 relative to step 1's reading. A
larger jump means an extraneous signature was produced; a zero jump
means the signature came from somewhere other than the card (which is
impossible if `verify-tag` passed, but the cross-check is free).

### 4. Push

Branch first, then tag. CI fires on tag push, and the tag must point
to a commit already present on the remote `main` or CI will fail
hard:

```bash
git push origin main
git push origin vX.Y.Z-alpha.N
```

### 5. Post-ceremony

- Physically remove the YubiKey and return it to storage.
- Record the date, tag name, and post-sign Signature-counter value
  in your operator log (a local append-only file is sufficient — the
  counter series is a useful independent cross-check if a future
  compromise investigation needs to ask "did this key sign
  something we don't have a record of?").
- Open the reverse-merge PR `main` → `dev` (or fast-forward `dev` to
  match `main`, depending on the shape of the release commit).

### Failure cheat sheet

| Symptom | Meaning | Recovery |
|---------|---------|----------|
| `gpg: OpenPGP card not available` on `gpg --card-status` | Card not inserted, or a different USB device is claiming the reader. | Reseat the card; check `pcscd` isn't holding it; retry. |
| `gpg: signing failed: No secret key` from `git tag -u ...` | Agent has not seen the card yet, or the keygrip for the requested subkey isn't known to the agent. | Run `gpg --card-status` first (step 1), then retry. |
| `gpg: signing failed: Bad PIN` | Wrong Signature PIN; counter is now `2`. | Retry with correct PIN. After three wrong tries the PIN locks and requires admin-PIN reset — stop and reset deliberately, don't panic-retry. |
| `verify-tag` shows a different fingerprint than expected | Tag was signed with the wrong key (commonly: personal key because `-u` was omitted). | `git tag -d` the local tag; retry from step 2 with `-u` explicit. |
| `Signature counter` did not increment by exactly 1 | More or fewer card signatures were produced than expected. | Do not push. Investigate what else ran between step 1 and step 3. |

## Verifying a release (for downstream consumers)

This is the procedure for anyone — user, distributor, auditor — who
wants to confirm a release tag's signature. It does not require access
to any private key material.

```bash
# 1. Import the signing keys. Any of these work:
gpg --import docs/SIGNING.md                 # extracts and imports both armored blocks in this file
gpg --locate-keys releases@shekyl.org        # fetches from WKD / keyserver (institutional)
gpg --recv-keys F5F75A4770C94FE1D5A5AE59844E424F98664F44

# 2. Verify the tag:
git verify-tag v3.1.0-alpha.5
```

Successful verification prints a line like:

```
gpg: Good signature from "Shekyl Foundation (Release Signing Key) <releases@shekyl.org>" [ultimate]
Primary key fingerprint: F5F7 5A47 70C9 4FE1 D5A5  AE59 844E 424F 9866 4F44
```

The fingerprint line **must match** one of the fingerprints listed in
this document — institutional primary, or (for historical or fallback-
signed tags) a maintainer-key fingerprint. If it does not, do not
trust the release. `git verify-tag` also prints "BAD signature" or
"Can't check signature: No public key" on failure; in either case,
stop and report the discrepancy on the project issue tracker.

### Reproducible-build cross-check

Tag signatures assert "an authorized signer approved this source." For
the stronger assertion "the binary you downloaded matches the reviewed
source," rebuild from the signed tag using the Guix pipeline and
compare the resulting artifact hash to the published one. Both
mechanisms are required for full release integrity; neither subsumes
the other.

## Adding a new maintainer key

1. The new maintainer generates a GPG key and registers its public
   half with their GitHub account.
2. They open a PR against `docs/SIGNING.md` adding their entry under
   "Maintainer keys" with the same fields as existing entries.
3. The PR is signed off by at least one existing maintainer. For
   fingerprint authenticity, the existing maintainer verifies the
   fingerprint out-of-band (in person, via a second channel, or via a
   pre-existing signed communication) — not from the PR itself.
4. The new key takes effect for commit-signing recognition on the
   first tag following the PR merge. Release-tag authority continues
   to flow through the institutional key by default.

## Adding a new institutional-key holder

As the Foundation grows, additional institutional-key holders may be
added (quorum signing, regional redundancy, succession planning). The
process is not yet exercised and will be documented here when it is.
Principles in advance:

- The institutional primary stays offline. New holders receive their
  own hardware token and a new signing subkey issued from the
  offline primary; the primary private material does not move.
- Each institutional-key holder's hardware-subkey fingerprint is
  listed here so downstream verifiers can pin on the fingerprint
  set, not on a single fingerprint.
- Transition is additive — retiring a subkey is a separate,
  documented event, not a silent replacement.

## Rotating or retiring a key

When a key (institutional or maintainer) is rotated (planned renewal)
or retired (departure, loss, suspected compromise), its entry in this
document is updated:

- The **Status** line changes to
  `Retired YYYY-MM-DD. Historical signatures remain verifiable; no new releases signed by this key.`
- For a rotation (same holder, new key), the new key is added as a
  separate subsection with its own fingerprint block. The old entry
  remains for historical-signature verification.
- In the case of suspected compromise, a GPG revocation certificate
  is published to keyservers so automated verification tooling picks
  up the revocation. The revocation certificate should have been
  generated at key-creation time and stored offline (see "Key
  hygiene" below).

Historical signatures by a retired-but-not-revoked key remain valid
for verifying older releases. Verification tooling should not warn on
such keys when checking tags created before the retirement date.

## Key hygiene

Institutional-key expectations:

- Primary key material is stored offline on encrypted media. No
  network-connected host holds the primary private key.
- Signing subkey material is held exclusively on a hardware token
  (OpenPGP applet). The subkey private material never leaves the
  token.
- A revocation certificate for the primary was generated at
  key-creation time and is stored offline, separately from the
  primary private key.
- Subkey lifetime is bounded; current subkey expires 2028-04-18.
  Rotation planning begins at least six months before expiry.

Maintainer-key expectations:

- Store the private key on an encrypted volume, a hardware token
  (YubiKey, Nitrokey, etc.), or both.
- Generate a revocation certificate at key-creation time and store
  it offline, separately from the private key.
- Keep at least one offline backup of the private key material.
- Use a passphrase on the private key.
- Register the public key with GitHub so signed commits and tags
  show the "Verified" badge, providing an independent second signal
  to downloaders.

## Why GPG, not SSH signing or Sigstore

- **SSH signing** (git 2.34+, GitHub "Verified" support from 2022) is
  adequate for commit-authorship verification but has thinner
  ecosystem support for release-tag verification workflows —
  downstream package tooling, Debian signature checks, and most
  `git verify-tag` consumers still assume GPG.
- **Sigstore / cosign** (ephemeral signing via OIDC) is a strong fit
  for container images and build-pipeline attestations, but does not
  align with the `git verify-tag` workflow that cryptocurrency-
  release downloaders expect.

GPG on ed25519 keys gives downstream-tool compatibility of
traditional PGP with the performance and cryptographic properties of
modern elliptic-curve signatures. If that calculus changes (Sigstore
gains first-class `git tag` integration, or the cryptocurrency
ecosystem migrates away from PGP), this document is revised.

## History

`v3.1.0-alpha.3` and `v3.1.0-alpha.4` were signed with Rick Dawson's
maintainer key. At the time, SIGNING.md recorded that a Foundation
institutional signing key was deliberately not in use pending the
ceremony prerequisites — offline primary, hardware-backed signing
subkey, bounded expiry. Those prerequisites were satisfied for the
`v3.1.0-alpha.5` release, at which point the institutional key became
the preferred release-tag signer. Maintainer-key signing remains a
documented additive fallback (see "Policy" above); it is not deprecated
and does not invalidate the prior alpha signatures.
