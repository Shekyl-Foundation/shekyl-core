# Signature Alignment Round (SA)

**Status:** ROUND OPEN — rulings SA-R-1…SA-R-6 RATIFIED 2026-08-09; PR-SA-1 in
flight, PR-SA-2…6 pending.
**Family:** `SA-*` (registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) at birth, rule 94).
**Trigger:** the message-signing round (SM, [`WALLET_MESSAGE_SIGNING.md`](WALLET_MESSAGE_SIGNING.md))
established the house standard for hybrid signing — nested combiner,
structural domain separation, pinned ctx, hedged nonces — and doing it
correctly made visible that the oldest and most consensus-critical hybrid
scheme in the tree predates every part of that standard.

---

## 1. Grounded inventory (dev `95aa83061`, verified 2026-08-09)

### 1.1 The finding: `HybridEd25519MlDsa` is a parallel combiner

`shekyl-crypto-pq/src/signature.rs:299–302`: Ed25519 and ML-DSA-65 each sign
the same bare `message` independently, ML-DSA with empty ctx. This is the
weakly-separable parallel construction Bindel–Hale (2023/423) warns about and
that SM-R-3 rejected for message signing: either half is a standalone valid
signature over the message; non-separability is provided by the fixed-length
encoder (`CANONICAL_LEN = 3385`, both fields mandatory), not the cryptography;
domain separation is caller-supplied, not structural; the module docstring
states "both signatures must verify," which SM-R-3 established is insufficient
as a security property.

### 1.2 Call-site census — nine production sites, not two

| Site | Op | Signed input | Structural domain? |
|---|---|---|---|
| `shekyl-archival-bond-builder/src/lib.rs:152` | sign | `vin.signature_preimage(tx_prefix_hash)` | yes — `shekyl/archival-bond-post-v1` |
| `shekyl-archival-retention/src/attestation_wire.rs:488` | verify | `record.nonce(r, cb_out_key)` | yes — `shekyl/archival-attestation-nonce-v1` |
| `shekyl-crypto-pq/src/output.rs:991` | sign | caller's `message` (`sign_pqc_auth_for_output`) | **no** — bare |
| `shekyl-engine-core/…/stake_engine/bond.rs:343` | sign | `bond_payload_hash` | **no** — bare hash |
| `shekyl-engine-core/…/stake_engine/claim.rs:337,484` | sign | claim / emission payload hash | **no** — bare hash |
| `shekyl-ffi/src/legacy_core.rs:157` (`shekyl_pqc_sign`) | sign | raw FFI `message` | **no** — bare, arbitrary |
| `shekyl-ffi/src/legacy_fcmp.rs:734` | verify | FFI `msg` | **no** — bare |
| `shekyl-ffi/src/archival_ffi/serve_credit.rs:117` | verify | `response.signature_preimage()` | yes — `shekyl/archival-serve-credit-response-v1` |
| `shekyl-daemon-rpc/src/submit/verifier.rs:885,901` | verify | `payload_hash` (consensus) | **no** — bare hash |
| `shekyl-archival-retention/src/emission_verify.rs:764` | verify | `msg` | **no** — bare |

Scheme-2 multisig (`multisig.rs:368–382`) *composes* the combiner — M
independent parallel hybrids over the same caller-supplied message — so its
verification semantics change with zero edits to `multisig.rs`. The
`scheme_id` discriminator lives only in the container encoding: the same
message signed under scheme 1 and scheme 2 has **identical signing input**
(cross-scheme confusion, a genuine weakness — see SA-R-5).

### 1.3 FFI boundary (verified at the C++ side)

- `shekyl_pqc_sign` has **no production C++ caller** — all callers are in
  `tests/unit_tests/fcmp.cpp`. Production C++ never signs and never holds a
  hybrid secret key outside tests (rule 36 holds).
- The one production consumer is verify-only and on consensus:
  `src/cryptonote_core/tx_pqc_verify.cpp:229` passes `scheme_id` as a
  *dispatch parameter* (it never enters the signed bytes) and the message is a
  bare `get_blob_hash(payload)` 32-byte hash.
- Consequence for SA-R-2: the fix at this boundary is the rule-40 move — the
  Rust export becomes context-specific and **owns its domain constant**; C++
  never carries a domain string it could get wrong.

### 1.4 Blast-radius facts for the nested conversion

- **Nothing fails to compile; everything changes at runtime.** `CANONICAL_LEN`
  stays 3385, every parser/DoS ceiling/C++ length pin is untouched — old and
  new signatures are byte-indistinguishable on the wire except via
  `HYBRID_SIG_VERSION` (`signature.rs:19`), which is why SA-R-4 makes the
  version byte the security boundary.
- Two committed KAT fixtures pin real, cryptographically **verified** hybrid
  signature bytes with no stored secret key
  (`gate2_serve_credit_kat.rs:605`, `gate4_lifecycle_kat.rs:268`); they must
  be regenerated via their `#[ignore]`d writers. All other pinned signature
  bytes in the tree are structural anchors (parse-only, never verified).
- `transfer_e2e_iai.rs:130–142` **inlines** the two parallel sign steps by
  design; after conversion it must be reworked or it silently benchmarks the
  wrong construction.
- `shekyl-archival-retention/src/wire.rs:24` hardcodes `3385` instead of
  aliasing `CANONICAL_LEN` — the one place the single-source discipline was
  missed; fixed in PR-SA-2.
- The genesis blob must be **checked** (not assumed) to carry no hybrid
  signature bytes, so the geblock byte-compare gate is unaffected.

### 1.5 RNG audit (workspace-wide, 2026-08-09)

Verdict: **INCONSISTENT-ONLY** — no test-double RNG, dummy RNG, or
deterministic seed is reachable from any production key/nonce/signing path;
every generic `<R: RngCore>` seam is closed by an OsRng (or OsRng-seeded
ChaCha20) production wrapper. Findings:

| # | Sev | Site | Finding | Disposition |
|---|---|---|---|---|
| F-1 | **High** | `shekyl-proofs/src/dleq.rs:95` | bare `Scalar::random(OsRng)` nonce protecting the full output spend scalar (`x = ho + b`); the sibling Schnorr in the same reserve-proof flow is hedged | **PR-SA-1**: hedged nonce binding every challenge input |
| F-2 | Med | same | `fill_bytes` panic surface contradicting the schnorr.rs fail-safe stance | fixed by F-1 |
| F-3 | Med | `shekyl-fcmp/src/frost_sal.rs:116` | FROST session-nonce ChaCha seed unwiped | **PR-SA-1**: `Zeroizing` |
| F-4 | Med | `shekyl-wallet-rpc/src/lifecycle.rs:533,543` | mnemonic/seed-hex as plain `String` (genesis-tool wraps the identical values) | **PR-SA-1**: `Zeroizing` through `SeedBackup` |
| F-5 | Low | `shekyl-fcmp-proofs/…/membership_only.rs:85` | `fill_bytes` panic inside an already-hedged construction | **PR-SA-1**: `try_fill_bytes` + zero fallback (policy restated locally — the crate does not depend on shekyl-crypto-pq) |
| F-6 | Low | `shekyl-crypto-pq/Cargo.toml` | fips204 not exact-pinned despite the identical `DummyRng { fill_bytes = unimplemented!() }` hazard as fips203/205 | **PR-SA-1**: `=0.4.6` + rationale |
| F-7 | Low | `signature.rs:255`, `kem.rs:157` | test-oriented `keypair_generate` trait impls un-gated (risk: non-derived keypair wired into a wallet) | **→ PR-SA-2** — the same trait's `sign`/`verify` signatures are being rewritten there (domain parameter), so every call site is touched once, not twice. Rule-19 bundling by validation surface, recorded here so it cannot silently drop. |
| F-8 | Info | workspace | ~30 direct OS-RNG touch points, no common seam | **PR-SA-1**: `shekyl-crypto-pq::rng` owns the hedged-entropy failure policy (`hedged_fresh32`); key-material draws deliberately stay fail-loud at call sites — see the module docs for the two-policy rationale |

---

## 2. Ratified rulings (2026-08-09)

**SA-R-1 — nested combiner.** `HybridEd25519MlDsa` becomes PQ-inner /
Ed25519-outer: `σ_pq = MLDSA.Sign(H_dom(preimage), ctx="")`,
`σ_ed = Ed25519.Sign(H_dom(preimage) ‖ σ_pq)`. Fails-closed rationale carried
from SM-R-3 into the docstring (a degenerate implementation fails to verify
rather than verifying insecurely), so the nesting order cannot be flipped for
convenience later. No wire-format, size, or schema change — only the
computation and therefore the bytes' meaning.

**SA-R-2 — domain separation moves into the scheme.** `sign`/`verify` gain a
required domain parameter; a caller cannot pass a bare message. The per-site
domain assignment table (nine sites, seven gaining structural separation for
the first time) is a PR-SA-2 design artifact ratified before that PR cuts. At
the FFI boundary the export becomes context-specific with the domain constant
Rust-owned (§1.3); the test-only generic sign export either takes the
mandatory domain or moves behind the test surface.

**SA-R-3 — ctx pin.** ML-DSA ctx stays `""`, pinned by a KAT that fails if a
non-empty context is supplied (the message-signing treatment).

**SA-R-4 — `HYBRID_SIG_VERSION` 1→2, and the version check is the security
boundary.** Wire length does not move, so the version byte is the only thing
distinguishing an old parallel signature from a new nested one. The check is
structural in the verify path — rejected before the combiner runs, not
advisory. Pinned by a negative-control KAT feeding a v1-tagged parallel
signature and asserting rejection, backed by **one frozen v1 fixture that is
never regenerated** (the live fixtures regenerate with the code and can only
attest the current construction). Pre-genesis there are no persisted
signatures; after genesis this would be a hard fork on a bonded
settlement-bearing surface — zero cost now, unpayable later.

**SA-R-5 — scheme id enters the signed preimage.** `preimage =
H(domain ‖ scheme_id ‖ message)`, closing the cross-scheme confusion in §1.2.
Folded into PR-SA-2 (scheme-2 verification is already changing; a second
migration of the same consensus surface for an already-identified defect would
violate the atomic-cutover discipline).

**SA-R-6 — persona lifecycle enforcement is wallet-level.** Consensus-level
rejection would put a permanent retirement-history state obligation on every
verifier to prevent a self-inflicted harm (re-binding a retired `p_slot`
clusters the operator's own personas onto their own principal; no third party
is harmed). The wallet tracks a **monotonic high-water mark** on `p_slot` and
never offers a used or lower slot for binding — and the mark is
**scan-derivable, not merely cached**: a restored-from-seed wallet
reconstructs it by walking the chain for bond posts under its derivable
persona ids and taking the max. A stored counter alone resets to zero on
restore and re-offers slot 0 on exactly the path where the operator is
recovering rather than paying attention. Both halves are the ruling.

---

## 3. PR decomposition (genesis-freeze ranked)

| PR | Contents | State |
|---|---|---|
| **PR-SA-1** | RNG alignment: F-1…F-6 + F-8 seam; this round doc; index registration | in flight |
| **PR-SA-2** | Nested combiner (SA-R-1/2/3/4/5), F-7, per-site domain table, fixture regeneration + frozen v1 negative fixture, iai bench rework, `wire.rs:24` aliasing, FFI context-specific exports, RELEASE_CHECKLIST rows beside the PQC-freeze block, genesis-blob check | pending — solitary review round |
| **PR-SA-3** | Registries: workspace domain registry + full-set collision test + CI grep gate (ripgrep install step); test-domain segregation; error-band table (-29xxx) | pending |
| **PR-SA-4** | Dead persisted-field sweep (writer/reader existence per persisted field; tx_notes PR-SJ-2 confirmation) | pending |
| **PR-SA-5** | Persona lifecycle: SA-R-6 guard + scan reconstruction; ruling into `ARCHIVAL_P_DERIVE_V1` module doc + operator guide (no-rotation stated as a refusal, clustering rationale named) | pending |
| **PR-SA-6** | CBOM (`docs/CRYPTOGRAPHIC_INVENTORY.md`): per-primitive pins/audit status, RNG map, persona no-classical-backstop row + rule-21 reopen keyed to ML-DSA cryptanalysis; infra PQ posture (release-signing paragraph); untrusted-cast sweep + one clamp/reject/None ruling | pending |
| tail | House conventions (envelope-vs-payload version naming; panic-vs-Option rule) → `.cursor/rules/`; FOLLOWUPS rewrap as its own mechanical commit | pending |

**Out of scope:** tx_extra canonical form (padding, ordering, duplicate tags,
tag-specific READ_LEN caps) stays in the **credit-wire lane** (PR-B2) — named
here so this round does not create a duplicate tracker.

### 3.1 Note for PR-SA-3 — the domain-style blind spot

The `shekyl/`-anchored census (~28 strings) is **not** the full set. Styles
already found outside it: `shekyl-reserve-proof-dleq-v1` (dleq),
`shekyl-pqc-leaf` (derivation), `shekyl-kem-v1` (kem HKDF salt),
`Shekyl FROST SAL v1` (transcript label), `Shekyl FCMP++ MO nonce * v1`
(Blake2b DSTs). A registry and CI grep gate anchored on `shekyl/` alone would
prove less than it appears — the exact defect class this round exists to fix.
The SA-3 sweep must enumerate by *mechanism* (every cSHAKE customization,
HKDF salt/info label, transcript label, and hash DST), not by prefix.

### 3.2 Fixed in PR-SA-1 while in the files

- `dleq.rs` `eprintln!` proof-byte dumps deleted (rule 50).
- `schnorr.rs` fresh-entropy draw migrated to the `rng` seam; its module docs
  now point at the seam as the policy owner.
