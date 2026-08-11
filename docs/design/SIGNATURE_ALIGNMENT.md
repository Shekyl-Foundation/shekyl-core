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
| ~~`shekyl-archival-bond-builder` S1 on-vin sign~~ | — | — | **Deleted in SA-2b** (§2.2): bond vin rides generic surface-A `pqc_auths` (see `stake_engine/bond.rs` bond-slot row). Live census = eight sites below |
| `shekyl-archival-retention/src/attestation_wire.rs:488` | verify | `record.nonce(r, cb_out_key)` | yes — `shekyl/archival-attestation-nonce-v1` |
| `shekyl-crypto-pq/src/output.rs:991` | sign | caller's `message` (`sign_pqc_auth_for_output`) | **no** — bare |
| `shekyl-engine-core/…/stake_engine/bond.rs:313` | sign | `bond_payload_hash` | **no** — bare hash |
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

**SA-R-1 — nested combiner, and `verify` returns `Result<()>` (fail-closed by
type).** `HybridEd25519MlDsa` becomes PQ-inner / Ed25519-outer:
`σ_pq = MLDSA.Sign(H_dom(preimage), ctx="")`,
`σ_ed = Ed25519.Sign(H_dom(preimage) ‖ σ_pq)`. Fails-closed rationale carried
from SM-R-3 into the docstring (a degenerate implementation fails to verify
rather than verifying insecurely), so the nesting order cannot be flipped for
convenience later. No wire-format, size, or schema change — only the
computation and therefore the bytes' meaning.

**Preimage width (review hardening, 2026-08-10): `H_dom` is
`cSHAKE256-64` — 64 bytes, not 32.** The digest is the *signed content*, so
its collision resistance bounds the whole scheme's unforgeability against a
counterparty who influences message bytes (a multisig payload proposer,
attacker-influenced tx/challenge content): at 32 bytes a same-domain collision
costs ~2^128 classically, below ML-DSA-65's Category-3 (192-bit) target and an
external-prehash dependence the v1 construction (ML-DSA hashing the full
message internally with the key) did not have. FIPS 204's HashML-DSA pairs
ML-DSA-65 with ≥384-bit digests for exactly this reason; 64 bytes restores
2^256. Landed inside PR-SA-2 before v2 ever shipped, so **no version bump**:
the version byte discriminates *shipped* constructions, and no v2-32 signature
exists outside the PR branch's own regenerated fixtures.

**The verify return type changes from `Result<bool, _>` to `Result<(), Error>`
— this is the highest-leverage line in the round.** `Result<bool>` is what
*created* F1 (§2.1): it makes "verification failed" (`Ok(false)`) and
"verification errored" (`Err`) two different falsy-looking values, and one
call site in six read them wrong and accepted invalid signatures. `Result<()>`
makes the accepts-invalid shape **unrepresentable** — there is no `Ok(false)`
to fall through on; every call site becomes `verify(…)?` or an explicit `Err`
match. F1 is the symptom, the return type is the cause, and this rewrite makes
the class extinct. The trait docstring states the fails-closed property so no
future edit "helpfully" restores a boolean return. **Atomic with SA-R-2:** the
`Result<()>` change and the domain parameter both alter the trait signature, so
they are one trait edit and one sweep of all six verify sites plus the FFI
twins — never split.

**SA-R-2 — domain separation moves into the scheme, distinct string per
context.** `sign`/`verify` gain a required domain parameter; a caller cannot
pass a bare message. The per-surface assignment is §2.1 (ratified). At the FFI
boundary the export becomes context-specific with the domain constant
Rust-owned (§1.3); the test-only generic sign export either takes the mandatory
domain or moves behind the test surface.

**Principle (ratified, write into the house rules):** a domain string separates
one signing context from all others; two different *layers* signing related
data are two contexts and get two strings. Reusing an inner-hash customization
as the outer scheme-level domain would create a standing proof obligation (that
the inner and outer input shapes can't cross-parse) in exchange for saving one
constant — a false economy. **Mint a distinct `…-scheme-v1` string per surface,
including for any surface added later**, and skip the collision analysis
entirely.

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

## 2.1 SA-2 domain assignment — six surfaces (ratified 2026-08-09)

The pre-cut census collapsed the nine call sites to **six signing surfaces**
(one key signs several). Two findings lead, then the surface table and the
per-surface constant.

### Two findings the census produced

**F1 — accepts-invalid-signatures bug (live, consensus path).**
`serve_credit.rs` gates verification on `.is_err()`. Because `verify` returns
`Result<bool>`, a well-formed signature under the *wrong key* returns
`Ok(false)`, `.is_err()` is `false`, and the function falls through to
`VERIFY_OK`. It is the only verify site in the tree with this shape; the other
five are `Ok(true)`-gated. Reached from live C++ (`blockchain.cpp:5462`).
**Subsumed by SA-R-1's `Result<()>` rewrite** — when that site becomes
`verify(…)?` the bug is fixed by construction — carried in PR-SA-2 (the note to
land it standalone on #426 is stale; #426 merged). Regression test is a
**wrong-key** signature asserting rejection (a malformed-signature test passes
on the broken code and proves nothing).

**F2 — surface B is a *preimage* choice on an already-occupied slot, not a
missing signature. Deferred to its own reconciliation round; out of SA-2.**
The first-pass framing ("wire a signature field onto `BondPost`") was **wrong on
two counts**, both verified at source:

- **`bond_spend_pk` is already bound at consensus.** It lives in the `BondPost`
  vin (`transaction.rs:636`); the vin is in `TxPrefix`; surface A's payload hash
  is `varint(TX_VERSION) ‖ TxPrefix::write ‖ …` (`transaction.rs:1435`);
  consensus verifies that hash under P's key (`verifier.rs:885`) and ties the
  bond auth to P's declared identity (`bond_auth.hybrid_public_key !=
  bond.hybrid_public_key` → reject, `verifier.rs:316`; `p_canonical_id`
  derivation checked `verifier.rs:304`). The binding claimed "absent" is present.
- **The design forbids an on-vin signature blob.** `ARCHIVAL_BOND_GATE4.md:308`:
  bond authorization is *transaction-level `pqc_auths[]`*, "not an on-vin
  signature blob" — and a signature over `tx_prefix_hash` cannot live inside the
  prefix it signs (circular). There is no field to add.

The bond vin's `pqc_auths` slot **already exists, is occupied, and is verified**.
Today it signs the **generic** surface-A payload hash (`bond.rs:313-315`); the
design (`gate4:311-313`) specifies it sign the **domain-separated**
`signature_preimage` (`shekyl/archival-bond-post-v1`) — which the discarded S1
signature computes. So the real question is neither "wire" nor "delete" but
**which preimage the existing slot signs.** That is its own round (below); it is
a Rust + C++ verify-path change with **no wire-layout change and no `TX_VERSION`
bump**, so folding it would break SA-2's C++-byte-identical property — the very
property that makes SA-2 reviewable as one consensus change.

**In SA-2:** the bond slot rides surface A's new `shekyl/pqc-auth-tx-v1` tx-domain
like every other auth (no bond-specific behavior). S1 and `signature_preimage`
were **retained, inert, under a named rule-21 reopen** (§2.2) — S1 compiled by
passing a bond-post scheme constant to the mandatory-domain trait; its fate was
the reconciliation round's to decide. The marker was mandatory: an inert domained
signer with no consumer is the dead-field class the round deletes, and without
the reopen the next audit re-runs the Pin-1 mistake — sees a discarded domained
signature and argues to wire it.

**Resolved in SA-2b (see §2.2):** the replay analysis found the generic surface-A
slot forecloses the cross-role replay, so **generic won** and S1 +
`signature_preimage` + `SCHEME_DOMAIN_BOND_POST` were **deleted**. The rule-21
reopen is discharged.

## 2.2 Bond-preimage reconciliation — RESOLVED in SA-2b: generic wins, S1 deleted

**Ruling (PR-SA-2b).** The bond vin's `pqc_auths` slot signs the **generic
surface-A whole-tx payload hash**. S1 (`shekyl-archival-bond-builder`),
`ArchivalBondPostVin::signature_preimage` (`bond_wire.rs`, domain
`shekyl/archival-bond-post-v1`), `BOND_POST_SIG_CUSTOMIZATION`, and
`SCHEME_DOMAIN_BOND_POST` were **deleted**. The parked path signed a strict
subset of what surface A already signs and was **verified by no production
verifier** — a domain-separated preimage that no one checks is the dead-field
class the SA round exists to remove.

The reopen criterion this round discharged was:

> **Reopen:** does the bond vin's `pqc_auths` slot sign the generic surface-A
> payload hash (code) or the design-specified domain-separated `signature_preimage`
> (`gate4:311-313`)? **Delete S1 + the preimage if generic wins; activate them
> (redirect the slot + verifier special-case) if design-aligned wins.**

**The load-bearing question was a security property, answered at the call graph —
verified, not inherited** (the Pin-1 error was inheriting an
"already-bound-therefore-redundant" claim instead of checking it): **can a
bond-post auth under P's key be replayed as an emission-prefix auth under P's
key, or vice versa, given both ride the generic surface-A path under the same
key?** Both are tx-domain-separated (`shekyl/pqc-auth-tx-v1`) but distinguished
from *each other* only by prefix **content**, not by scheme domain.

**Replay analysis — cross-role replay is structurally foreclosed.** The
surface-A payload hash is `varint(TX_VERSION) ‖ TxPrefix::write ‖ …`, and
`TxPrefix::write` emits each vin's **type tag** before its body — `0x03` for a
bond post, `0x04` for an emission input. The tag is inside the signed bytes, so a
signature produced over a bond-post prefix cannot verify against an
emission-prefix payload (the tags differ ⇒ the hashes differ ⇒ the signature
fails). The whole-tx hash binds **strictly more** than the deleted bond
preimage did — but be precise about the differential: the deleted preimage's
*first input field was `tx_prefix_hash`* (plus `p_canonical_id`, `post_kind`,
`bond_spend_pk`, holdings, and the amount fields directly), so it already bound
every vin type tag *transitively* through the prefix hash. What the bond
preimage genuinely never carried is what makes surface A the strict superset:
the `ct_base` blob (fee and `reference_block`, the curve-tree anchor), the
**prunable hash** (the FCMP++ proof and pseudo-outs), and the per-auth key-hash
list. Generic wins; the domain-separated preimage adds no separation surface A
does not already provide, and activating it would have added a verifier
special-case for zero security gain. The arm was chosen by the replay analysis,
not by which was less work.

### The six surfaces

| # | Surface | Sign | Verify | Scheme-level domain (ratified) |
|---|---|---|---|---|
| A | Tx per-input PQC auth (payload hash) | bond / emission-prefix / spend (via `sign_pqc_auth_for_output`) / C++ wallet | submit verifier, scheme-2, **C++ `tx_pqc_verify`** | **`shekyl/pqc-auth-tx-v1`** — the only undomained surface today; the load-bearing add |
| B | Archival bond-post vin (rides surface A) | bond slot signs surface-A hash (`bond.rs:313`) | submit verifier / C++ `tx_pqc_verify` (as surface A) | **`shekyl/pqc-auth-tx-v1`** (same as A). Slot-preimage choice **resolved in SA-2b: generic wins**; S1 + `signature_preimage` + `SCHEME_DOMAIN_BOND_POST` deleted (§2.2) |
| C | Emission auth — claim | `claim.rs` claim | emission_verify claim leg | `shekyl/archival-emission-claim-scheme-v1` |
| D | Emission auth — backing | `claim.rs` backing (`sign_pqc_auth_for_output`) | emission_verify backing leg | `shekyl/archival-emission-backing-scheme-v1` |
| E | Attestation countersignature | none in-repo | attestation_wire ← C++ | `shekyl/archival-attestation-scheme-v1` (assignable unilaterally) |
| F | Serve-credit response | none in-repo | serve_credit (F1) | `shekyl/archival-serve-credit-scheme-v1` (assignable unilaterally) |

Distinct `…-scheme-v1` per surface (SA-R-2 principle), including the four that
already carry an *inner* cSHAKE customization — the scheme-level domain is a
separate layer and gets its own string. Surface A's domain lives **inside the
Rust scheme**, so the C++ differential pair (`get_transaction_signed_payload` /
`transaction.rs` `pqc_signing_payload_hashes`) stays byte-identical and does
not move — the wrap is Rust-only. E and F have no in-repo signer, so their
constants are assignable now with the KAT writers the only lockstep.

### Census corrections folded as facts

- `claim.rs` backing (surface D) was a missing sign site in the first pass.
- **Scheme-2 multisig has no production signer in-repo** — SA-R-5's
  scheme-id-in-preimage lands on verify + container + tests only. The preimage
  binds the *hybrid* scheme id (the `HybridEd25519MlDsa` constant, 1 for both
  single and multisig participants), so over the same raw message a single-sig
  signature and a multisig participant signature would be byte-identical
  **without a distinct domain**. Multisig participants therefore sign and verify
  under a **distinct** `SCHEME_DOMAIN_PQC_AUTH_TX_MULTISIG`
  (`shekyl/pqc-auth-tx-multisig-v1`), separating the two contexts at the scheme
  level. The consensus tx path *also* separates them structurally
  (`PqcAuth::header_write` writes the container `scheme_id` 1 vs 2 into the
  signed payload), but that is a caller-side property of the tx builder — the
  scheme owning its own separation is what closes the standalone `verify_multisig`
  path where a caller could pass a bare payload. **Process note:** this multisig
  domain was briefly reverted (mistaking the caller-side tx-path binding for
  scheme-level closure, to accommodate C++ multisig tests that produced
  participant signatures through the single-sig FFI); the revert was itself
  reverted — the correct fix is the distinct domain plus a genuine
  multisig-participant signing path for the tests
  (`shekyl_pqc_sign_multisig_participant`, test-support FFI; a cross-domain
  rejection negative control pins the separation in `multisig.rs`).
- The emission tx carries **three** hybrid signatures from the claim path
  (A prefix-auth, C claim, D backing) — distinct messages, distinct domains.
- The §1.2 census row `shekyl-ffi/src/legacy_fcmp.rs:734`
  (`shekyl_emission_hybrid_auth_verify`) is **retired in PR-SA-2**, not
  domained. It was the PR-E1 per-auth primitive; its header contract claimed
  both emission roles ("Auth-B backing, Auth-P pseudonym") but its shape was
  backing-only (mandatory leaf gate, one domain) — serving the claim role
  through it would have hardcoded the wrong domain, a latent Rust-vs-C++
  consensus divergence. It had **no production C++ caller**: C-1's only entry
  is the coarse `shekyl_emission_vin_verify`
  (`blockchain.cpp` connect arm), whose Rust body
  `emission_verify::emission_vin_verify_auth` verifies both roles under their
  ratified per-role domains (C claim / D backing) and pins the
  leaf-gate-before-signature order (`emission_verify_kat.rs`). Deleting the
  duplicate verify path, rather than domain-patching it, is the rule-15 fix:
  one verify path per surface, nothing to drift.

### F-7 disposition (Pin 5, ratified)

Drop `keypair_generate` from the trait (SA-R-1/2 rewrite the trait anyway, so
its callers migrate once). Resurface as an inherent constructor behind a
`test-utils` feature, **renamed `generate_ephemeral_keypair_for_tests`** — the
rename is load-bearing, the old name read as a production API. Keep the FFI
keypair export for the C++ test suite but **structurally gate it if the build
can express it** (`#ifdef SHEKYL_TEST_SUPPORT` around the declaration, or
test-harness-only link surface) — a header comment does not bind a C++ caller,
link-time absence does. Comment is the fallback only if the build system can't
express the gate cleanly.

---

## 3. PR decomposition (genesis-freeze ranked)

| PR | Contents | State |
|---|---|---|
| **PR-SA-1** | RNG alignment: F-1…F-6 + F-8 seam; this round doc; index registration | **MERGED #426 (merge `69857ab9f`); archived `archive/feat/sa1-rng-alignment-2026-08-09`** — carried a user review round (`d7e3bac7f`: binding tests, seed-export hygiene) |
| **PR-SA-2** | Nested combiner (SA-R-1 incl. `Result<()>` rewrite / R-2 / R-3 / R-4 / R-5); §2.1 six-surface domains (bond slot rides surface A's `shekyl/pqc-auth-tx-v1`; **surface B is §2.2, out of SA-2** — S1 + `signature_preimage` parked inert under rule-21); SA-R-4 version check placed by the **six-path parse-from-canonical enumeration** (precondition of the trait rewrite; check goes uniformly at parse or in `verify()`, never per-path); F1 (subsumed by `Result<()>`) + wrong-key regression; F-7 disposition; fixture regeneration + frozen v1 negative fixture; iai bench rework; `wire.rs` `3385` aliasing; FFI context-specific exports; RELEASE_CHECKLIST rows; genesis-blob no-hybrid-sig check. **C++-byte-identical** (no wire/`TX_VERSION` change) | pending — solitary review round |
| **PR-SA-2b** | Bond-preimage reconciliation (§2.2): resolved the P-role replay question at the call graph — the surface-A whole-tx hash (incl. the vin type tag) forecloses cross-role replay, so **generic won**. Deleted S1 + `signature_preimage` + `BOND_POST_SIG_CUSTOMIZATION` + `SCHEME_DOMAIN_BOND_POST`; KAT surfaces 7→6. No wire change; no verifier special-case needed | **DONE** |
| **PR-SA-3a** | Consensus leaf-hash SSOT: `PqcLeafScalar::from_pqc_public_key` wraps `hash_pqc_public_key`; retired dual `DOMAIN_PQC_LEAF` + dual Blake2b/wide_reduce; pinned pre-dedup KAT (empty / 1-byte / full ML-DSA-65 / all-`0xff`). No wire change. | **MERGED #436** |
| **PR-SA-3b** | Domain registry: single-source [`CRYPTO_DOMAIN_REGISTRY.tsv`](CRYPTO_DOMAIN_REGISTRY.tsv) census of every production domain string by **mechanism** (not a flat all-pairs collision test — that is a category error, §5); **per-mechanism** distinctness test (`shekyl-crypto-pq/tests/domain_registry.rs`, mech-2 keyed by `salt\|info`) with pinned per-mechanism census counts (the ONLY count copy — TSV headers and prose defer to it) and **test-domain segregation** (test-only rows machine-checked disjoint from production identities per mechanism); CI gate (`scripts/ci/domain_registry_gate.sh`) with comment-stripped row-presence + exact `const <name>:` binding + comment-stripped entry-point count-pins on always-domain mechanisms (cSHAKE / FROST) + frozen-doc cross-check, **anchored on call sites, not the `shekyl/` prefix** (§3.1) — honest scope: new unregistered domains in general-purpose mechanisms (HKDF/Blake2b/keccak/SHA3-256) are a review duty, not a false gate guarantee; frozen consequence markers (mech-3 FROST into [`FROZEN_DOMAIN_SEPARATORS.md`](../FROZEN_DOMAIN_SEPARATORS.md), naming the per-seam break); TSV-only changes run the distinctness test (Rust workflow path re-include); through-line invariant written as a rule (§5); error-band pointer (§6). Mutates **zero** domain values. **Feeds the CBOM domain section.** | **MERGED #438** (carried a review round: `PRODUCTION_PINS` single-count, comment-stripped gate, tab-safe delimiter, frozen-doc cross-check, `signable_header` deleted for zero callers with the B2 forward-guard relocated to `sender_sig`) |
| **PR-SA-3c** | `SNAPSHOT_ID_DOMAIN` (`refresh.rs`) retargeted `cn_fast_hash` → cSHAKE256 with the domain as customization (`shekyl/snapshot-id-v1`); this **does** change a domain's bytes — permitted because `SnapshotId` is a wallet-internal reservation-staleness token (no `Serialize`, absent from `shekyl-engine-file`, never wire/cross-node — verified at the call graph), so it is a fresh mint, not a re-spelling (§5). Regression test re-cast to vary the cSHAKE customization; registry row moved mech 5 → mech 1, count-pins + dated snapshots updated; `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §segment-2g marked superseded. No persisted-state change (no rule-42 bump). | **in flight** (`feat/sa3c-snapshot-id-cshake`, stacked on dev) |
| **PR-SA-3d** | `cn_fast_hash` → `keccak256` rename (Rust-internal, byte-identical; keep FFI export name); crypto-hash doc header with the Keccak/cSHAKE one-liner | pending |
| **PR-SA-4** | Dead persisted-field sweep (writer/reader existence per persisted field; tx_notes PR-SJ-2 confirmation) | pending |
| **PR-SA-5** | Persona lifecycle: SA-R-6 guard + scan reconstruction; ruling into `ARCHIVAL_P_DERIVE_V1` module doc + operator guide (no-rotation stated as a refusal, clustering rationale named). **Feeds the CBOM persona no-backstop row.** | pending |
| **PR-SA-6** | CBOM close/formalize (see §4) + infra PQ posture (release-signing paragraph); untrusted-cast sweep + one clamp/reject/None ruling | pending |
| tail | House conventions (envelope-vs-payload version naming; panic-vs-Option rule; **SA-R-2 distinct-string-per-context**) → `.cursor/rules/`; FOLLOWUPS rewrap as its own mechanical commit | pending |

**Out of scope:** tx_extra canonical form (padding, ordering, duplicate tags,
tag-specific READ_LEN caps) stays in the **credit-wire lane** (PR-B2) — named
here so this round does not create a duplicate tracker.

### 3.1 Note for PR-SA-3b — the domain-style blind spot

The `shekyl/`-anchored census (~28 strings) is **not** the full set. Styles
already found outside it: `shekyl-reserve-proof-dleq-v1` (dleq),
`shekyl-pqc-leaf` (derivation — **SSOT after SA-3a**, no longer dual-defined),
`shekyl-kem-v1` (kem HKDF salt), `Shekyl FROST SAL v1` (transcript label),
`Shekyl FCMP++ MO nonce * v1` (Blake2b DSTs). A registry and CI grep gate
anchored on `shekyl/` alone would prove less than it appears — the exact defect
class this round exists to fix. The SA-3b sweep must enumerate by *mechanism*
(every cSHAKE customization, HKDF salt/info label, transcript label, and hash
DST), not by prefix.

**Verified in SA-3b (the enumeration by mechanism; dated snapshot, 2026-08-11,
incl. SA-3c — the checked copy of these counts is
`domain_registry.rs::PRODUCTION_PINS`):** the full production census is **93
distinct domain strings across the five mechanisms** (94 registered, including the
SHA3-256 micro-bucket), not ~28 — a 3.3× undercount by the prefix lens, which is
the measure of the blind spot. Distribution: mechanism 1 cSHAKE customization (25,
incl. the challenge-assignment domain merged mid-round by PR #435 — the round's
first live catch, the pin went stale against dev and the row was added at true-up
— and the `snapshot-id` domain SA-3c moved here from mechanism 5 on its
cn_fast_hash→cSHAKE retarget), mechanism 2 HKDF salt+info (8 salts + 33 distinct
infos), mechanism 3 FROST transcript label (4), mechanism 4 Blake2b DST (9),
mechanism 5 keccak/schnorr challenge DST (14) — those five sum to 93 — plus a
1-entry SHA3-256 direct-prefix micro-bucket (`shekyl-mlkem-chacha-seed` — a real
domain that sits outside all five, given its own bucket rather than silently folded
in), for 94 registered rows. 11 of the 93 are frozen-inherited (mech-3: 3;
mech-5: 8). The registry names its own
boundary: what it excludes (RandomX Argon salt, Tor SAFECOOKIE, `.onion`
checksum, file/wire magics) is rowed with a reason, because a silent omission is
the failure mode a registry exists to kill. The gate is anchored on the mechanism
entry point, never the spelling — `Monero Generator T`, `Shekyl FROST SAL v1`, and
`shekyl-pqc-leaf` share no prefix, and all three must be caught.

### 3.2 Fixed in PR-SA-1 while in the files

- `dleq.rs` `eprintln!` proof-byte dumps deleted (rule 50).
- `schnorr.rs` fresh-entropy draw migrated to the `rng` seam; its module docs
  now point at the seam as the policy owner.

---

## 4. The CBOM is accretive, not a final sweep (user directive 2026-08-09)

`docs/CRYPTOGRAPHIC_INVENTORY.md` — a **markdown design-doc** (user-chosen
form; can emit a CycloneDX JSON view later if a Phase-9 auditor asks), rule-91
maintained. It is **not** discovered at SA-6; it *accretes* as each PR does its
enumeration, so nothing is enumerated twice and it lands populated:

- **SA-1 (landed)** → the primitive-pin rows and the RNG-source map (the F-8
  audit *is* the RNG section: every OS-entropy touch point, the `hedged_fresh32`
  seam, the fail-safe/fail-loud split, every `<R: RngCore>` seam and its
  production closure).
- **SA-2** → the six-surface signing inventory (§2.1), keyed by which key signs
  which surface.
- **SA-3** → the domain / DST registry (by mechanism, §3.1).
- **SA-5** → the persona no-classical-backstop row + rule-21 reopen keyed to
  ML-DSA cryptanalysis.
- **SA-6** → close and formalize (primitive audit-status column, infra PQ
  posture), *not* discover.

Seed content already in hand (this round): ML-KEM-768 / ML-DSA-65 (fips203
`=0.4.3`, fips204 `=0.4.6`, fips205 `=0.4.1` — all exact-pinned, `DummyRng`
rationale, no external audit), Ed25519 (ed25519-dalek / curve25519-dalek),
SLH-DSA-192s (message signing, ACVP-conformant), the hash constructions
(cSHAKE256, Keccak / `cn_fast_hash`, SHA-512, Blake2b512), and
Bulletproof+ / FCMP++ (curve-based — the known, recorded, accepted non-PQ ZK
risk).

---

## 5. The through-line invariant — a live domain string's bytes are state, not style (RULE)

**Ratified as a standing rule (2026-08-10). Destined for `.cursor/rules/` (see the
tail row in §3); recorded here first because SA-3b is where it was needed.**

A **live** domain-separation string's *bytes* are consensus (or derivation) state,
not a naming convention. The registry [`CRYPTO_DOMAIN_REGISTRY.tsv`](CRYPTO_DOMAIN_REGISTRY.tsv)
contains strings in visibly inconsistent styles — `shekyl/pqc-auth-tx-v1`,
`shekyl-kem-v1`, `Shekyl FROST SAL v1`, `shekyl-subaddr-v1\0`, `Monero Generator T`.
**That inconsistency is intended and permanent.** Each string is the exact input to
a hash or transcript whose output is verified — by a signature check, a curve-tree
membership proof, a key derivation, a FROST session. Change one byte — normalize a
`/` to a `-`, drop a version suffix, "align" the casing, trim a trailing NUL — and
the derived value moves: the signature no longer verifies, the leaf no longer matches
the tree, the restored wallet derives different keys, the multisig session cannot
complete. Nothing fails to compile; everything fails at runtime, silently, against a
counterparty or against already-persisted state.

So **"aligning" a live domain string's spelling is the KAT-remint error at consensus
stakes** — the same class as regenerating a pinned test vector to make a red test
green (the in-tree instance of this class is the frozen-points KAT,
`rust/shekyl-curve-generators/src/tests/frozen_points.rs`, which fails the moment a
generator DST byte moves). The correct response to an
inconsistent-looking live domain is to **leave it exactly as it is** and, if the
inconsistency is genuinely confusing, document *why the bytes are frozen* — never to
touch the bytes. This is the difference between a rename (an *identifier* change,
rule 93, always safe) and a domain-value change (a *state* change, never safe once
the value is live). The registry, the distinctness test, and the CI gate exist to
make an accidental "cleanup" of these bytes **fail loudly** rather than ship.

Corollary (frozen-inherited vs. Shekyl-live): a string carrying `"Monero"`
provenance is additionally a rule-93 **carve-out** — a rebrand sweep skips it (see
[`FROZEN_DOMAIN_SEPARATORS.md`](../FROZEN_DOMAIN_SEPARATORS.md)). A Shekyl-authored
live string (e.g. `Shekyl FROST SAL v1`) is *ours to version* but no freer to
*re-spell in place*: versioning means minting a new `…-v2` string alongside a
migration, never editing the `…-v1` bytes.

## 6. Error-band allocation — pointer, not a second table

The JSON-RPC error-band allocation (`-29000..-29099` lifecycle, `-29200..-29299`
refresh/rescan, `-29300..-29399` proofs *(reserved)*, `-29400..-29499` transfers,
`-29800..-29899` sign/verify message *(reserved)*) is **single-sourced** in
[`wallet_rpc.yaml`](../api/wallet_rpc.yaml) (the band map at its head, then each code
inline). **SA-3b introduces no new band and no new code**, so — by the very §5
discipline — it does **not** re-tabulate them here; a second copy would drift and
then lie. Recorded only as the crypto cross-reference the CBOM needs: the two bands
that surface *cryptographic* verify outcomes to a wallet client are `-29300` (tx /
reserve proof malformed or unprovable) and `-29800` (message signature malformed /
checksum-rejected / verify-failed). Consensus-level auth/verify failures (the six
SA-2 signing surfaces) are **not** in this band at all — they are transaction
rejections at the daemon/C++ boundary, not wallet-RPC errors, and the CBOM records
them under the signing-surface inventory, not here.
