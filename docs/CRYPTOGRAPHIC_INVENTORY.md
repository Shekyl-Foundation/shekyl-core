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
| 5 | Persona no-classical-backstop row | SA-5 | **FILED (below)** — surveyed negative: no persona surface is ML-DSA-only |
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

**Census (dated snapshot, 2026-08-11, incl. SA-3c): 93 distinct production domain
strings across the five mechanisms — 94 registered, including the SHA3-256
micro-bucket.** The `shekyl/`-prefix lens saw ~28 — a 3.3× undercount, which is the
measure of the blind spot SA-3b closes (SIGNATURE_ALIGNMENT §3.1). (The table below
sums to 94: the five mechanisms 93, plus the 1-entry micro-bucket.) **This table is a
snapshot, not the checked copy** — the per-mechanism counts are pinned once, against
the parsed TSV rows, in `domain_registry.rs::PRODUCTION_PINS`; when the registry
legitimately changes, that pin fails and this table is refreshed with a new as-of
date. SA-3c moved `snapshot-id` from mechanism 5 to mechanism 1 (cn_fast_hash →
cSHAKE); the total is unchanged (one domain recategorized, not added).

| Mechanism | Entry point | Count | Frozen-inherited |
|---|---|---|---|
| 1 — cSHAKE256 customization | `cshake256_*`, `CShake256Core::new` | 25 | 0 |
| 2 — HKDF salt + info | `Hkdf::new(Some(salt))`, `.expand(info)` | 8 salts + 33 infos | 0 |
| 3 — FROST transcript label | `RecommendedTranscript::new`, `.domain_separate`, `Curve::CONTEXT/ID` | 4 | 3 |
| 4 — Blake2b DST | first `Blake2b512::update`; `sal_dst` tags | 9 | 0 |
| 5 — keccak / schnorr challenge DST | schnorr domain; `keccak256(..)` hash-to-point/scalar prefix | 14 | 8 |
| 6 — SHA3-256 direct-prefix (micro-bucket) | prefix fed straight to `Sha3_256` | 1 | 0 |

Distinctness identity is per-mechanism; mechanism 2 is keyed by `(salt, info)`, since
three info labels (`shekyl-ed25519-spend/-view/-ml-kem-768`) are reused across two
derivations that differ only by salt — legitimately distinct, not a collision.

**Frozen vs. live.** 11 of the 93 are **frozen-inherited** (mech-3: the FROST
ciphersuite id/context and the SAL-multisig transcript root; mech-5: the FCMP++
generator and Bulletproof(+) DSTs). Frozen strings are byte-identical to the
un-vendored upstream, are pinned by derived-output KATs, and are **rule-93
carve-outs** (a rebrand sweep skips them) — enumerated with per-seam consequences in
[`FROZEN_DOMAIN_SEPARATORS.md`](FROZEN_DOMAIN_SEPARATORS.md), and the CI gate
cross-checks that every frozen row still has its entry there. The remaining 82 are
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

(Note: `ARCHIVAL_FIREWALL_GATE6.md` §7.1/§9.8 still carries stale
"not-yet-landed" prose for the C-1 leaf check alongside its own "discharged
(#277)" reconciliation notes; the code at `emission_verify.rs` is the ground
truth — the check is landed.)
