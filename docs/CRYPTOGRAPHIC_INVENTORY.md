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
| 1 | Primitive pins + RNG-source map | SA-1 (merged #426) | **FILED (SA-6, below)** — transcribed from [`SIGNATURE_ALIGNMENT.md`](design/SIGNATURE_ALIGNMENT.md) §1.5/§4, every pin re-verified at source 2026-08-14 |
| 2 | Six-surface signing inventory (which key signs which surface) | SA-2 (merged #428) | **FILED (SA-6, below)** — transcribed from [`SIGNATURE_ALIGNMENT.md`](design/SIGNATURE_ALIGNMENT.md) §2.1, scheme-domain consts re-verified at source 2026-08-14 |
| 3 | **Domain / DST registry (by mechanism)** | SA-3b | **FILED (below)** |
| 4 | Known non-PQ surfaces (curve-based ZK risk register) | SA-6 | **FILED (below)** — §5 referenced this section before it existed; SA-6 wrote it |
| 5 | Persona no-classical-backstop row | SA-5 | **FILED (below)** — surveyed negative: no persona surface is ML-DSA-only |
| 6 | Close + formalize (audit-status, infra posture, release signing) | SA-6 | **CLOSED (below)** |

---

## § 1 — Primitives, pins, and the RNG-source map — FILED (SA-6, from SA-1)

Enumerated by SA-1 (PR #426, `SIGNATURE_ALIGNMENT.md` §1.5 + §4 seed list);
transcribed and **re-verified at source 2026-08-14** (crate manifests +
`shekyl-crypto-pq/src/rng.rs`). The workspace toolchain is pinned at
**Rust 1.94.0** (`rust-toolchain.toml`; version pins in the workspace
`Cargo.toml` carry their own rationale comments).

| Primitive | Crate / pin | Role | Audit status |
|---|---|---|---|
| ML-KEM-768 | `fips203 =0.4.3` (**exact**) | Output encryption / address `ek` (hybrid KEM with X25519) | No external audit. Exact-pinned: the crate's internal `DummyRng { fill_bytes = unimplemented!() }` pattern makes silent minor-version drift a panic hazard (rationale at the pin) |
| ML-DSA-65 | `fips204 =0.4.6` (**exact**) | PQ half of `HybridEd25519MlDsa` (all six §2 surfaces); per-persona archival signing key | No external audit. Same exact-pin rationale |
| SLH-DSA-192s | `fips205 =0.4.1` (**exact**) | Wallet message signing (SM round; the last Module-LWE/SIS-**uncorrelated** signature surface) and the ratified address-v2 48-byte pk field | No external audit; **ACVP cross-check KATs vendored in our own `test_vectors/`** (NIST ACVP-Server `a7f283cdc`), which forecloses the unfixable nonconforming-keygen branch |
| Ed25519 | `ed25519-dalek 2.2.0` / `curve25519-dalek` | Classical half of every hybrid signature; the **house Schnorr** (`crate::schnorr`, raw spend scalar — dalek `SigningKey` structurally cannot sign for it) for reserve proofs and the message-signing outer half | RustCrypto/dalek lineage (community-audited upstream); house Schnorr is ours, hedged-nonce |
| cSHAKE256 | `sha3 0.10` | Every domain-separated derivation/preimage (mechanism 1 of §3; 25 domains) | RustCrypto audited lineage |
| Keccak-256 | `sha3 0.10` (`shekyl_crypto_hash::keccak256`; single implementation, empty-input KAT pins byte-identity; C ABI export keeps the `shekyl_cn_fast_hash` name) | Consensus content identity (txid / block / leaf / fingerprint) — **identity, never separation** (`keccak=identity, cSHAKE=separation`) | Same |
| SHA-512, Blake2b512 | `sha2` / `blake2 0.10` | HKDF backbone (mech 2); Blake2b DSTs incl. `DOMAIN_PQC_LEAF` (mech 4) | Same |
| Bulletproof+ / FCMP++ curve stack | Vendored, manifest-gated (`check_vendored_crypto_manifest.sh`, 59 files) | Range proofs; membership + SAL | **The known non-PQ surface — see §4** |

**RNG-source map (the F-8 audit, PR-SA-1).** Verdict at audit:
**inconsistent-only** — no test-double RNG, dummy RNG, or deterministic seed
reachable from any production key/nonce/signing path; every generic
`<R: RngCore>` seam closed by an OsRng(-seeded) production wrapper. The
structural close is a deliberate **two-policy split**, owned by
`shekyl-crypto-pq::rng`:

- **Nonces / hedging — fail-safe:** `hedged_fresh32()` degrades to the
  deterministic hedge on entropy failure instead of panicking (bad RNG must
  never become nonce reuse; dead RNG must never become a crash loop). The
  DLEQ nonce (F-1, the one bare `Scalar::random` the audit found protecting a
  full spend scalar) now binds every challenge input through this seam.
- **Key material — fail-loud:** master seeds, transaction keys, and keygen
  draw `OsRng` directly at their call sites and panic/error on entropy
  failure — a key silently minted from a degraded source is the worse
  outcome, so this path deliberately does **not** route through the hedge.

F-1..F-8 dispositions all landed in PR-SA-1 (F-7's test-keygen gating rode
PR-SA-2 with the trait rewrite, as recorded); the per-finding table stays in
`SIGNATURE_ALIGNMENT.md` §1.5 — this section records the *standing policy*,
the alignment doc records how it was reached.

---

## § 2 — Six-surface signing inventory — FILED (SA-6, from SA-2)

Enumerated by SA-2 (PR #428, `SIGNATURE_ALIGNMENT.md` §2.1); scheme-domain
constants **re-verified at source 2026-08-14** (`shekyl-crypto-pq/src/signature.rs`).
Every surface signs with `HybridEd25519MlDsa` — the **nested combiner**
(`HYBRID_SIG_VERSION = 2`: ML-DSA inner over the 64-byte cSHAKE preimage,
Ed25519 outer over `inner ‖ σ_pq`; a frozen v1 parallel-combiner fixture is
pinned to **reject**), `verify → Result<()>` fail-closed (the F1
`Ok(false)`-falls-through class is unrepresentable), and a required
scheme-level domain (`preimage = cshake256_64(domain, scheme_id ‖ msg)` — the
scheme id inside the signed preimage is SA-R-5's cross-scheme-confusion
close):

| # | Surface | Signs | Verifies | Scheme domain (verified const) |
|---|---|---|---|---|
| A | Tx per-input PQC auth (whole-payload hash) | bond / emission-prefix / spend paths | submit verifier + C++ `tx_pqc_verify` | `shekyl/pqc-auth-tx-v1` (multisig participants: `shekyl/pqc-auth-tx-multisig-v1` — same surface, distinct scheme) |
| B | Archival bond-post vin | **rides surface A** (SA-2b ruling: the whole-tx hash binds the vin type tag, cross-role replay structurally foreclosed; the parked dedicated preimage S1 was **deleted**) | as A | as A |
| C | Emission auth — claim | `stake_engine/claim.rs` | `emission_verify` claim leg | `shekyl/archival-emission-claim-scheme-v1` |
| D | Emission auth — backing | `stake_engine/claim.rs` (Auth-B) | `emission_verify` backing leg (the §5 surface-2 triple) | `shekyl/archival-emission-backing-scheme-v1` |
| E | Attestation countersignature | no in-repo signer (C++ side) | `attestation_wire` | `shekyl/archival-attestation-scheme-v1` |
| F | Serve-credit response | no in-repo signer | `serve_credit` | `shekyl/archival-serve-credit-scheme-v1` |

The pinned-positive KAT battery (`PQC_HYBRID_V2_KAT.json`: one verified
vector per surface, cross-surface rejection, domain-string tripwires) is the
executable form of this table; a surface added without a row fails the KAT
writers' cross-surface sweep, and the §3 registry gate pins the domain
literals themselves.

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

**Census (dated snapshot, 2026-08-15, incl. the fork-(ii) address-layout
slice): 94 distinct production domain strings across the five mechanisms —
95 registered, including the SHA3-256 micro-bucket.** The `shekyl/`-prefix lens saw ~28 — a 3.3× undercount, which is the
measure of the blind spot SA-3b closes (SIGNATURE_ALIGNMENT §3.1). (The table below
sums to 95: the five mechanisms 94, plus the 1-entry micro-bucket.) **This table is a
snapshot, not the checked copy** — the per-mechanism counts are pinned once, against
the parsed TSV rows, in `domain_registry.rs::PRODUCTION_PINS`; when the registry
legitimately changes, that pin fails and this table is refreshed with a new as-of
date. SA-3c moved `snapshot-id` from mechanism 5 to mechanism 1 (cn_fast_hash →
cSHAKE); the total was unchanged (one domain recategorized, not added). The
2026-08-15 refresh adds one mechanism-2 info label:
`shekyl-archival-p-msg-sign-slh-dsa-192s-v1`, the persona's SLH-DSA-192s
message-signing identity — the seventh archival-P per-slot label, forced
by the fork-(ii) address layout making `msg_sign_pk` a mandatory field of
every address (persona receive addresses included, for uniformity).

| Mechanism | Entry point | Count | Frozen-inherited |
|---|---|---|---|
| 1 — cSHAKE256 customization | `cshake256_*`, `CShake256Core::new` | 25 | 0 |
| 2 — HKDF salt + info | `Hkdf::new(Some(salt))`, `.expand(info)` | 8 salts + 34 infos | 0 |
| 3 — FROST transcript label | `RecommendedTranscript::new`, `.domain_separate`, `Curve::CONTEXT/ID` | 4 | 3 |
| 4 — Blake2b DST | first `Blake2b512::update`; `sal_dst` tags | 9 | 0 |
| 5 — keccak / schnorr challenge DST | schnorr domain; `keccak256(..)` hash-to-point/scalar prefix | 14 | 8 |
| 6 — SHA3-256 direct-prefix (micro-bucket) | prefix fed straight to `Sha3_256` | 1 | 0 |

Distinctness identity is per-mechanism; mechanism 2 is keyed by `(salt, info)`, since
three info labels (`shekyl-ed25519-spend/-view/-ml-kem-768`) are reused across two
derivations that differ only by salt — legitimately distinct, not a collision.

**Frozen vs. live.** 11 of the 94 are **frozen-inherited** (mech-3: the FROST
ciphersuite id/context and the SAL-multisig transcript root; mech-5: the FCMP++
generator and Bulletproof(+) DSTs). Frozen strings are byte-identical to the
un-vendored upstream, are pinned by derived-output KATs, and are **rule-93
carve-outs** (a rebrand sweep skips them) — enumerated with per-seam consequences in
[`FROZEN_DOMAIN_SEPARATORS.md`](FROZEN_DOMAIN_SEPARATORS.md), and the CI gate
cross-checks that every frozen row still has its entry there. The remaining 83 are
Shekyl-authored **live** strings: still byte-load-bearing, but ours to version (mint
a `…-v2` alongside a migration, never edit `…-v1` in place — SIGNATURE_ALIGNMENT §5).

**Test-domain segregation.** Domains minted by test/bench code are rowed
`test-only` and machine-checked to be disjoint from the production identities of
their mechanism (`test_domains_are_segregated_from_production`) — a test-only
domain equal to a live one would let a test-minted artifact verify against the
production context. Test-vs-test collisions are not policed. Completeness of the
test census has the same review-duty scope as mech 2/4/5/6 completeness below.

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
  mech ids / statuses / rows, pins the per-mechanism census counts (so a silently
  vanished row fails loudly), enforces test-domain segregation, and checks the mech-2
  salt-separated model still matches code. Runs on TSV-only changes too — the Rust
  workflow's path filter re-includes the registry.
- **CI gate** — `scripts/ci/domain_registry_gate.sh`: for every *registered* row,
  row-presence (`rg -F` the literal at its file, over comment-stripped code — a doc
  comment quoting the bytes cannot keep a row green) plus, when the const column is a
  real identifier, an exact `const <name>:` binding; entry-point count-pins (likewise
  comment-stripped) for mechanisms whose entry point always carries a domain (cSHAKE;
  FROST free-form transcript labels; FROST ciphersuite ID/CONTEXT in
  `shekyl-fcmp-proofs`); and a frozen-doc cross-check (every frozen-inherited row has
  its entry in `FROZEN_DOMAIN_SEPARATORS.md`). Anchored on the mechanism call site /
  registered literal, never the `shekyl/` prefix.

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

---

## § 4 — Known non-PQ surfaces: the curve-based ZK risk register — FILED (SA-6)

§5 has cited this section since it was written; SA-6 makes the reference
true. This is the **recorded, accepted** quantum exposure — the one the
mission hierarchy's "hybrid PQC from genesis" deliberately does *not* cover,
because no production-ready lattice ZK stack existed to cover it with:

| Surface | Construction | What a CRQC gets | What it does NOT get |
|---|---|---|---|
| Range proofs | Bulletproof+ (Pedersen commitments, discrete log) | **Binding/soundness**: forge a proof over an unbalanced commitment — inflation risk. An *online* attack against the live chain | **Hiding**: Pedersen commitments are perfectly hiding — recorded amounts stay private *retroactively*, even against a future CRQC |
| Membership + spend-auth linkage | FCMP++ (curve trees + SAL, discrete log) | **Soundness** (online): forge membership for a leaf not in the tree. **Retroactive linkability is the harvest-now axis**: any recorded artifact whose *unlinkability* rests on computational DL hardness (the SAL linking-tag layer) is exposed to a future CRQC replaying the chain — unlike amounts, this is not information-theoretically protected | Theft on the proof alone — the per-input **hybrid PQC auth (§2 surface A) co-signs every spend**, so spend forgery additionally requires breaking ML-DSA-65. And the *view/scanning* layer does not fall with DL: per-output key derivation is hybrid-KEM (X25519 ‖ ML-KEM-768) from genesis |

Posture, stated precisely — two different "V4"s must not be conflated:

- **Signatures:** hybrid from genesis; the V4 **lattice-only** step (the
  mission's third evaluation horizon) retires the *classical halves* of the
  hybrid signatures. It is a signature-layer transition.
- **The ZK/anonymity layer:** FCMP++ is the chosen primitive **from genesis
  by decision, with no planned lattice replacement** — the V4-A..D
  "lattice-based ring signature survey" is **retired**
  (`POST_QUANTUM_CRYPTOGRAPHY.md` §V4 Roadmap). This register is therefore
  the standing record of an *accepted* exposure, not a bridge to a
  scheduled fix: proof soundness (inflation/forgery) is an online-CRQC
  risk mitigated by the hybrid co-signature on spends, and the
  retroactive-linkability axis above is the recorded residual the
  hybrid-KEM view layer and perfectly-hiding amounts deliberately narrow
  but do not close.

**Reopen (rule 21):** two triggers, either suffices — (a) a
production-credible post-quantum membership/range proof stack becomes
available (re-opens the retired survey with a concrete candidate; the
decision is the upgrade lane's, this inventory only records it); (b) a
CRQC-credibility reassessment moves the harvest-now horizon inside the
chain's expected privacy lifetime, which would make the retroactive
linkability row above the binding constraint rather than a residual.

---

## § 5 — Persona PQ posture: the no-classical-backstop survey (SA-5)

The archival staking persona `P` is the **first account-level ML-DSA** in the
system: principal account keys carry Ed25519 + ML-KEM only (per-output ML-DSA
lives on the output path), while `P` adds a stable per-persona ML-DSA-65 signing
key via deterministic seeded keygen (`ARCHIVAL_FIREWALL_GATE6.md` §9.6;
derivation in `shekyl-crypto-pq` `archival_p` = `ARCHIVAL_P_DERIVE_V1`). SA-5
owes this section an answer to one question: **is there a persona-authorized
surface that rests on ML-DSA alone?**

**Verdict: no. Every persona-authorized surface carries a classical backstop.**
The row is filed as a surveyed negative, with the per-surface evidence below.
Recording an exposure that does not exist would be the worse failure — it
mis-aims a rule-21 reopen and invites a later editor to "resolve the
inconsistency" by deleting the classical half that is actually there.

**Surface 1 — the persona's own signing keys: hybrid.** `P`'s identity key
`hybrid_sign_pk` (the on-wire `P_pubkey` / bond id) and its debit key
`bond_spend_pk` are both `HybridEd25519MlDsa` (Ed25519 + ML-DSA-65), like every
other hybrid in the tree. So the **bond-post `pqc_auths`** and the **bond-spend
authorization** carry a classical backstop: forging either still requires
breaking Ed25519 *and* ML-DSA. The V4 lattice-only transition retires the
classical half uniformly across `archival_p` and the principal account, and a
`bond_spend_pk` re-key path already exists (it is a full Unbond +
re-JoinMarket) — `ARCHIVAL_BOND_CONSTRUCTION.md` §12.

**Surface 2 — the reward-emission backing input (GF-1): hybrid, and the leaf
binds both halves.** This is the surface that *looks* single-primitive and is
not; the check is worth writing down because the membership-only framing invites
the wrong reading. Authorizing a persona's staked collateral as a backing input
takes **three** things, and consensus requires all of them (the
`emission_vin_verify` witness triple — `ClaimsVerified`, `BackingVerified`,
`AuthVerified` — is unforgeable without each minter running):

1. an **FCMP++ membership-only proof** — genuinely **no key image**; anti-replay
   on this surface is the per-epoch dedup layer, not a linking tag
   (`emission_vin_verify_backing`, `FCMP_MEMBERSHIP_ONLY.md` §7);
2. the **leaf gate** — `hash_pqc_public_key(backing_pubkey) == pqc_pk_hash`,
   binding the revealed key to the in-circuit committed leaf scalar (C-1, #277);
3. **Auth-B — a hybrid Ed25519 + ML-DSA-65 signature** under that same
   `backing_pubkey` over the role-separated Q1 binding message
   (`emission_vin_verify_auth` → `verify_hybrid_auth` →
   `HybridEd25519MlDsa.verify`, domain `SCHEME_DOMAIN_EMISSION_BACKING`; signed
   wallet-side by `stake_engine/claim.rs`, which asserts the signer key equals
   the vin's `backing_pubkey`).

Step 3 is the classical backstop, and step 2 does not weaken it:
`hash_pqc_public_key` is `Blake2b512(DOMAIN_PQC_LEAF ‖ pk_bytes)` over the
**full canonical `HybridPublicKey`** (Ed25519 ‖ ML-DSA — see
`derive_pqc_public_key`), so the committed leaf commits *both* halves. There is
no point on this path where ML-DSA is the sole authority. The module's own
docstring states the same posture: *"Both signatures are hybrid (Ed25519 **and**
ML-DSA-65) per the ratified R1.A posture — Auth-P has no membership-proof
classical fallback, so an ML-DSA-only auth would be a single point of
cryptographic failure."*

**Reopen — rule 21: none owed on the ML-DSA-alone axis.** No persona surface is
single-primitive, so there is no trigger to key to ML-DSA-65 cryptanalysis
specifically; an ML-DSA weakening degrades the persona surfaces to their
Ed25519 half exactly as it does every other hybrid in the tree, and the uniform
V4 re-key is the existing answer. The standing PQ risk on this path remains the
one already recorded in §4 — curve-based FCMP++/Bulletproof+ ZK soundness — which
is a *quantum threat to the proof system*, a different axis from signature
backstop and not re-litigated here. If a future surface authorizes a persona
action with an ML-DSA-only signature (no Ed25519 co-signature and no
hybrid-committed leaf), **that** is the reopen: it must be recorded here before
it ships.

(Note: `ARCHIVAL_FIREWALL_GATE6.md` §7.1/§9.8 carried stale "not-yet-landed"
prose for the C-1 leaf check alongside its own "discharged (#277)"
reconciliation notes; **SA-6 corrected all four sites** — the code at
`emission_verify.rs` was always the ground truth, and the doc now agrees
with it.)

---

## § 6 — Close: audit status and infrastructure PQ posture (SA-6)

**This inventory is closed as of 2026-08-14** — every section owed by the SA
round is filed, each against a dated at-source verification. The accretion
duty continues (a new primitive, surface, or domain lands with its row in the
same PR — §3's "review duty" scope applies file-wide); what ends here is the
*backlog*.

### Audit status (the honest column)

| Artifact | Status |
|---|---|
| FIPS crates (`fips203/204/205`) | Exact-pinned; **no external audit**; ACVP conformance vendored for SLH-DSA-192s (§1) |
| In-house constructions (nested combiner, house Schnorr, hedged RNG seam, domain registry) | Internally verified: pinned-positive KATs, frozen negative fixtures, CI gates (§1–§3); **no external audit** |
| External audit | **Owed at Phase 9** (`RELEASE_CHECKLIST.md`: 4-scalar leaf circuit audit + security/code audits, gated after the stressnet run). This document is the auditor's index; a CycloneDX JSON view can be emitted from it if the engagement wants one |

### Infrastructure PQ posture (surveyed 2026-08-14)

| Surface | Today | PQ posture |
|---|---|---|
| Release tags | Signed annotated tags per `docs/SIGNING.md` (canonical policy): GPG, Shekyl Foundation institutional key — certification-only primary held offline (`sec#` stub check written in as a verifiable invariant), hardware-token signing subkey (physical possession + PIN), personal-key fallback documented | Classical, and **ruled** — scheme, key, and ceremony are settled; the primary/subkey split means a lost token never compromises the identity |
| Release assets | Gitian deterministic multi-OS builds on tags (`.github/workflows/gitian.yml`); `--detach-sign` produces builder assert files, and the release job packages and publishes assets — **no per-asset signature step exists in the workflow, and tag-signing does not close this**: a signed tag authenticates the source point, not the binary a user downloads | **Wiring landed as tooling** (`scripts/release/sign_release_assets.py`, the scripted ceremony — SIGNING.md §Release assets); the checklist row closes when exercised on a real release. See below |
| Bundled Tor (expert bundle) | Upstream GPG fingerprint pin (`TOR_SIGNING_KEY_FPR`) + byte-pin re-verification chain (`tor-pin-verify` workflow, `RELEASE_CHECKLIST.md` rows) | Classical, upstream-controlled; the durable pin is the key fingerprint, and the in-tree byte pin bounds a compromised download to a loud test failure |
| Commit signing | House discipline: GPG-signed commits, verified before push | Classical; process-level, not CI-enforced — recorded as-is |

**Asset-manifest signing is owed before the first non-RC release tag —
a wiring task with a named owner, not an open decision (corrected
2026-08-15).** The SA-6 close filed this as a three-way scheme choice;
that overstated it — `docs/SIGNING.md` already rules the policy (GPG,
Foundation institutional key, offline-primary / hardware-subkey ceremony),
and the ruling extends naturally to assets with no new decision: the
release job gains a **signed `SHA256SUMS` manifest** step — the Foundation
signing subkey signs one manifest of asset hashes; users verify the
manifest signature, then check hashes. One signature covers every asset,
uses the same key and the same hardware-token ceremony as the tags, and
composes with the reproducible-build story (independent builders reproduce
the hashes; the Foundation signs the manifest of them). What tag-signing
alone cannot provide — authentication of the downloaded binary rather than
the source point — is exactly what this step adds. Trigger unchanged:
cutting the first non-RC release tag with the `RELEASE_CHECKLIST.md` row
unchecked is the failure. (The in-tree SLH-DSA-192s stack remains
*implementable* for a future PQ or hybrid manifest signature, recorded as
capability, not as an open question.)
