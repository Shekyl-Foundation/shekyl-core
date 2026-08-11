# Shekyl Cryptographic Bill of Materials (CBOM)

**Form:** markdown design-doc (rule-91 maintained). A CycloneDX JSON view can be
emitted later if a Phase-9 auditor asks; the authoritative content is here.

**Accretive, not a final sweep** (user directive, see
[`SIGNATURE_ALIGNMENT.md`](design/SIGNATURE_ALIGNMENT.md) §4). Each SA-round PR
files the section it already enumerated, so nothing is enumerated twice and this
document lands populated rather than being "discovered" at SA-6. SA-6 *closes and
formalizes* (audit-status column, infra PQ posture); it does not discover.

## Section status

| § | Content | Owed by | State |
|---|---|---|---|
| 1 | Primitive pins + RNG-source map | SA-1 (merged #426) | **owed** — content lives in [`SIGNATURE_ALIGNMENT.md`](design/SIGNATURE_ALIGNMENT.md) §1.5 (RNG audit) and the "seed content" list in §4; not yet transcribed here |
| 2 | Six-surface signing inventory (which key signs which surface) | SA-2 (merged #428) | **owed** — content lives in [`SIGNATURE_ALIGNMENT.md`](design/SIGNATURE_ALIGNMENT.md) §2.1 |
| 3 | **Domain / DST registry (by mechanism)** | SA-3b | **FILED (below)** |
| 5 | Persona no-classical-backstop row | SA-5 | pending |
| 6 | Close + formalize (audit-status, infra posture) | SA-6 | pending |

The §1/§2 rows are recorded as **owed with a named source**, not silently dropped:
the enumerations exist and are cited; back-filling them here is bounded transcription
tracked against SA-6's close. (SA-1/SA-2 merged before this file was created; that is
the gap being flagged, not hidden.)

---

## § 3 — Domain / DST registry (by mechanism) — FILED (SA-3b)

**Single source of truth:** [`design/CRYPTO_DOMAIN_REGISTRY.tsv`](design/CRYPTO_DOMAIN_REGISTRY.tsv).
Every production domain-separation byte-string in the Rust workspace, one row per
literal, grouped by the ONE keyed/hashing mechanism that consumes it. This section
**narrates**; the TSV is authoritative and machine-checked. Do not maintain a second
copy of the strings here — that would be the exact drift the SA through-line rule
(§5) forbids.

**Why by mechanism, not a flat list.** A domain-separation collision only matters
between two contexts that feed the *same* primitive. Every domain seam feeds exactly
one mechanism, so distinctness is an intra-mechanism property; a flat all-pairs test
would be a category error (and would spuriously flag the legitimate cross-mechanism
reuse of `b"nonce"`).

**Census (verified 2026-08-10): 92 distinct production domain strings across the
five mechanisms — 93 registered, including the SHA3-256 micro-bucket.** The
`shekyl/`-prefix lens saw ~28 — a 3.3× undercount, which is the measure of the blind
spot SA-3b closes (SIGNATURE_ALIGNMENT §3.1). (The table below sums to 93: the five
mechanisms 92, plus the 1-entry micro-bucket.)

| Mechanism | Entry point | Count | Frozen-inherited |
|---|---|---|---|
| 1 — cSHAKE256 customization | `cshake256_*`, `CShake256Core::new` | 23 | 0 |
| 2 — HKDF salt + info | `Hkdf::new(Some(salt))`, `.expand(info)` | 8 salts + 33 infos | 0 |
| 3 — FROST transcript label | `RecommendedTranscript::new`, `.domain_separate`, `Curve::CONTEXT/ID` | 4 | 3 |
| 4 — Blake2b DST | first `Blake2b512::update`; `sal_dst` tags | 9 | 0 |
| 5 — keccak / schnorr challenge DST | schnorr domain; `keccak256(..)` hash-to-point/scalar prefix | 15 | 8 |
| 6 — SHA3-256 direct-prefix (micro-bucket) | prefix fed straight to `Sha3_256` | 1 | 0 |

Distinctness identity is per-mechanism; mechanism 2 is keyed by `(salt, info)`, since
three info labels (`shekyl-ed25519-spend/-view/-ml-kem-768`) are reused across two
derivations that differ only by salt — legitimately distinct, not a collision.

**Frozen vs. live.** 11 of the 92 are **frozen-inherited** (mech-3: the FROST
ciphersuite id/context and the SAL-multisig transcript root; mech-5: the FCMP++
generator and Bulletproof(+) DSTs). Frozen strings are byte-identical to the
un-vendored upstream, are pinned by derived-output KATs, and are **rule-93
carve-outs** (a rebrand sweep skips them) — enumerated with per-seam consequences in
[`FROZEN_DOMAIN_SEPARATORS.md`](FROZEN_DOMAIN_SEPARATORS.md). The remaining 81 are
Shekyl-authored **live** strings: still byte-load-bearing, but ours to version (mint
a `…-v2` alongside a migration, never edit `…-v1` in place — SIGNATURE_ALIGNMENT §5).

**Boundary (named, not silent).** The registry excludes, each with a rowed reason:
the RandomX Argon salt, Tor SAFECOOKIE HMAC keys, the `.onion` checksum prefix, and
file/wire magics (`SWSP`, `SHEKYLWT/WS`, `SSP1`, EPEE portable-storage header) —
none are cryptographic domain separation for our purposes. Transcript field
sub-labels, schnorr nonce/challenge sub-labels, and HKDF composed-salt
sub-components are out of scope (they never stand alone as a top-level context). A
silent omission is the failure mode a registry exists to kill, so both the
exclusions and the sub-label rule are stated in the TSV header.

**How it stays honest (no published constant).**

- **Distinctness test** — `rust/shekyl-crypto-pq/tests/domain_registry.rs`: reads the
  TSV, asserts intra-mechanism distinctness (the collision-catcher), rejects malformed
  mech ids / rows, and checks the mech-2 salt-separated model still matches code.
- **CI gate** — `scripts/ci/domain_registry_gate.sh`: for every *registered* row,
  row-presence (`rg -F` the literal at its file) plus, when the const column is a real
  identifier, a `const <name>` binding (blocks pure-comment false positives); entry-
  point count-pins for mechanisms whose entry point always carries a domain (cSHAKE;
  FROST free-form transcript labels; FROST ciphersuite ID/CONTEXT in
  `shekyl-fcmp-proofs`). Anchored on the mechanism call site / registered literal,
  never the `shekyl/` prefix.

**Honest scope — completeness for mech 2/4/5/6 is a review duty.** The gate catches
drift and deletion of *registered* domains, and additions on always-domain entry
points (mech 1, mech 3). It does **not** automatically detect a new HKDF / Blake2b /
keccak / SHA3-256 domain string that lands without a registry row — those entry points
are general-purpose primitives used for non-domain hashing too, so a call-site count is
noise. When a PR introduces a new domain-like string into one of those mechanisms, the
reviewer checks that a row is added (and the distinctness test still passes). Do not
paper over this with a half-broken inverse scanner; false confidence is worse than an
honest boundary (rule 15/16).

Neither artifact makes any domain constant `pub`: the census aggregates the *bytes*
at test/gate time (visibility stays a real boundary), it does not import the consts.
