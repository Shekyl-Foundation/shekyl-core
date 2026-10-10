# FN-DSA hybrid signatures — scheme 3, its dependency, and the lane

**Status:** OPEN — increment 1 (the scheme in `shekyl-crypto-pq`, no
consumers) recorded 2026-10-09 and merged 2026-10-10; increment 2 (the
receipt key derived per persona slot, §7) recorded 2026-10-10. Increments 3
and 4 (the bond record carrying the receipt key, receipts moving onto it)
each land as their own change and are recorded here as they do. Closes when increment 4
lands; the dependency record (§2) then moves to
[`CRYPTOGRAPHIC_INVENTORY.md`](../CRYPTOGRAPHIC_INVENTORY.md), which already
carries its summary row.
**Substrate verified at:** `origin/dev` = `6b23eab315`.
**Authority:** [`ARCHIVAL_SERVE_CREDIT_SPEC.md`](ARCHIVAL_SERVE_CREDIT_SPEC.md)
§6, §11 and §13.1 R2–R4 (ruled 2026-10-07).
**Findings:** `FND-1…FND-13` (§5), registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md).

---

## 1. What increment 1 is

A second hybrid signature scheme, Ed25519 + FN-DSA-1024, under scheme byte 3
of the canonical four-byte header. It is the same nested combiner as the
existing Ed25519 + ML-DSA-65 scheme (SA-R-1) with a different post-quantum
half. Nothing signs or verifies with it yet.

| Piece | Where |
| --- | --- |
| The combiner and the canonical header, one body for both schemes | `rust/shekyl-crypto-pq/src/hybrid_combiner.rs` |
| Scheme 3: types, key generation, sign, verify | `rust/shekyl-crypto-pq/src/fn_dsa_hybrid.rs` |
| Scheme byte and the two scheme domains | `rust/shekyl-crypto-pq/src/signature.rs` (`HYBRID_SCHEME_ID_ED25519_FN_DSA_1024`, `SCHEME_DOMAIN_RECEIPT`, `SCHEME_DOMAIN_WITNESS_CARRIER`) |
| The hedged RNG adapter and the fail-loud key-material draw | `rust/shekyl-crypto-pq/src/rng.rs` (`HedgedOsRng`, `key_material32`) |
| Vectors | `docs/test_vectors/FN_DSA_HYBRID_V1_KAT.json`, `rust/shekyl-crypto-pq/tests/kat_fn_dsa_hybrid_v1.rs` |
| Genesis gate | `scripts/ci/check_fn_dsa_genesis_gate.py` |

**Distinct types.** `FnDsaHybridPublicKey`, `FnDsaHybridSecretKey` and
`FnDsaHybridSignature` share no type with the ML-DSA scheme's `Hybrid*`.
`SignatureScheme` carries the key and signature as associated types, so an
API written against one scheme cannot be handed the other's objects. On
bytes the parsers hold the same line: each accepts its own scheme byte, its
own version and its own two lengths.

**Sizes** are derived from the crate's constants and equal the
specification's: a 1,837-byte canonical key and a 1,356-byte canonical
signature (spec §6.2). `canonical_lengths_are_the_specified_ones` holds both
as numbers, so a disagreement between the specification and the crate fails
a test instead of being absorbed.

**The scheme byte is bound twice**: in the header, where the parser reads
it, and as the first input byte of the signed preimage. A signature made
under one scheme does not verify under the other even with its header
rewritten.

**Scheme 3 does not authorize transactions.** `verify_pqc_auth` knows
schemes 1 and 2 and refuses 3 by its discriminant
(`a_receipt_key_cannot_authorize_a_transaction`).

## 2. The dependency (rule 17)

`fn-dsa` 0.4.0 by Thomas Pornin, with its four sub-crates. Read at source
(the published crates.io packages) on 2026-10-09.

| | |
| --- | --- |
| Crates | `fn-dsa`, `fn-dsa-comm`, `fn-dsa-kgen`, `fn-dsa-sign`, `fn-dsa-vrfy`, all `=0.4.0` |
| Why five pins | `fn-dsa` depends on each sub-crate as `0.4` (caret). Pinning the wrapper alone would let a sub-crate move under it; the four are named in `shekyl-crypto-pq`'s manifest only to pin them |
| Licence | `Unlicense` in every manifest; the packages ship no licence file. The workspace has **no machine licence policy** (no `deny.toml`), so this is recorded, not checked (`FND-7`) |
| MSRV | 1.82. The workspace toolchain is pinned at 1.94.0 |
| Transitive dependencies | `rand_core` 0.6 and `zeroize` 1.x (both already in the lock, same versions), and `cpufeatures` 0.2 on x86 only (already in the lock). The lock gained the five `fn-dsa*` packages and nothing else |
| Hashing | The crate carries its own SHAKE and SHA-3 (`fn-dsa-comm/src/shake.rs`), including a four-way AVX2 SHAKE. It does not use `sha3` |
| Features | `default = []` on all five. Not enabled: `no_avx2`, `small_context`, `div_emu`, `sqrt_emu` |
| `cargo audit` | No advisory names any of the five (run at this commit; the lock's standing warnings are the ones `dev` already carries) |
| `unsafe` | By file, counting occurrences of the keyword: `fn-dsa` 0; `fn-dsa-comm` 42, all in the two AVX2 files; `fn-dsa-kgen` 62, of which 58 in the four AVX2 files and 4 in `lib.rs` (the AVX2 dispatch); `fn-dsa-sign` 73, of which 25 in the three AVX2 files and 48 outside them (`poly.rs` 28, `flr_native.rs` 9, `sampler.rs` 6, `lib.rs` 3, `flr.rs` 2 — the SSE2 and NEON intrinsics the native `f64` path uses, and the AVX2 dispatch); `fn-dsa-vrfy` 5 (AVX2 dispatch). On aarch64 the AVX2 files are not compiled; the signer's NEON intrinsics are |

**Pre-standard.** FIPS 206 is not final. The crate's README says that what
it implements is a best guess at the draft, that keys and signatures made
with it may stop verifying under later versions, and that only 1.0 will be
stable, after the standard is published. Three things follow, and each
lands with this increment:

- every vector is a pin on `=0.4.0`, and the regenerator is armed with the
  decision gate the other pinned fixtures use;
- `FOLLOWUPS.md` carries the row to move the crate and regenerate the
  vectors when FIPS 206 is final and the crate reaches 1.0;
- a genesis build on a pre-1.0 lock is refused (§4).

**API used.** `KeyPairGenerator1024::keygen`, `SigningKey1024::{decode,
sign}`, `VerifyingKey1024::{decode, verify}`, the three `*_size` constant
functions, `FN_DSA_LOGN_1024`, `DOMAIN_NONE`, `HASH_ID_RAW`. The `1024`
types accept degree 1024 only, so a 512-degree key is refused by type.

**What the crate does with randomness** (the two facts the design rests on):

- *Key generation* draws exactly 32 bytes from the RNG it is given and is
  deterministic from them. A seeded ChaCha20 stream therefore gives a
  deterministic key pair, the pattern `derivation::keygen_from_seed` already
  uses for ML-DSA.
- *Signing* draws a 40-byte seed with the infallible `fill_bytes` and
  replaces it at once with `SHAKE256(H(signing key) ‖ μ ‖ seed)`. It is a
  hedged construction in `rng.rs`'s sense. Handing it the bare `OsRng` would
  panic in the signing task when the OS RNG failed; `HedgedOsRng` gives it
  fresh bytes or zeros, and a zero seed yields a deterministic signature.

**Floating point.** Key generation and verification are integer-only.
Signing uses hardware `f64` on x86_64 (SSE2, and AVX2 when the CPU has it)
and on aarch64 (NEON), both strict IEEE-754; other targets use the crate's
integer emulation. A deterministic Falcon signer is only safe if it is
bit-reproducible — two signatures over one hashed point leak the key — so
the signing vector is the one that matters across architectures (§3).

**Canonical form.** The crate accepts one encoding per key and per
signature. Two refusals are asserted rather than assumed
(`pinned_signature_refuses_every_near_miss`): a signature whose padding is
not zero, and a key with a coefficient outside `[0, q)`.

## 3. Vectors

`FN_DSA_HYBRID_V1_KAT.json` pins, for each surface under scheme 3 (receipt,
witness carrier): key generation from two seeds to the public key bytes,
signing with a seeded RNG to the signature bytes, and verification of the
pinned signature. It also carries the cross-surface negative.

| Path | Result at this commit |
| --- | --- |
| x86_64, AVX2 (the default build on the development host) | all pass |
| x86_64, the crate's AVX2 paths compiled out (`no_avx2` on the four sub-crates) | all pass, same bytes. Run on every pull request by a step of `rust-audit-test.yml` |
| aarch64 under `qemu-aarch64` (user mode) | all pass, same bytes |

The aarch64 run is wired into `depends-aarch64-kats.yml`, beside the other
cross-architecture vectors. It is an emulated CPU: qemu's floating point is
a software IEEE-754 implementation, so it shows that the crate's aarch64
code path computes the same values, and it does not show what a physical
Cortex-A72 does. That confirmation rides the floor-device benchmark session
(`FND-9`).

### 3.1 Benchmarks

`benches/fn_dsa_hybrid.rs` (criterion: sign through the production entry,
verify, seeded key generation) and `benches/fn_dsa_hybrid_iai.rs`
(instruction counts for sign and verify, registered in the gate's `BENCHES`
list; `BENCHMARK_ALIGNMENT.md` `BA-I105`, `BA-T33`). The gated sign arm
enters through `sign_with_rng_seed`, so the rejection-sampling path is the
same on every run.

| | x86_64 development host | Floor device |
| --- | --- | --- |
| Sign | 457 µs; 6,675,212 instructions | owed (`FND-9`) |
| Verify | 58 µs; 891,246 instructions | owed |
| Seeded key generation | 6.2 ms | owed |

The x86 figures are of the path the host's CPU selects. They say the gate
repeats; they do not say what a persona on the floor pays per receipt.

Moving the existing scheme onto the shared body left its gated sign count
where it was: `crypto_bench_hybrid_sign_1_input` 7,163,792 instructions at
`6b23eab315`, 7,161,994 with this change, same host.

## 4. The genesis gate

`scripts/ci/check_fn_dsa_genesis_gate.py` reads `rust/Cargo.lock` and the
`shekyl-crypto-pq` manifest. On every pull request it asserts its subject —
all five packages locked, at one version, each pinned exact in the manifest
at that version — and reports whether the lock is pre-1.0. Given a release
tag that is not a recognised pre-release it **fails** on a pre-1.0 lock.

The tag test fails closed. A pre-release is `MAJOR.MINOR.PATCH` followed by
`-alpha`, `-beta` or `-RC` with an optional number, in any case, with or
without the leading `v`; every other shape is treated as genesis and
refused, `v3.0`, `V3.0.0` and `v3.0.0+mainnet` included. An oddly named
rehearsal tag has to be re-cut with a suffix. The suffix takes one
optional number: `v3.0.0-alpha.1.2` is refused. `gitian.yml` carries the
same expression for a tree that predates the script, and the script fails
if the workflow does not hold it verbatim.

A locked `1.0.0-rc.1` is below 1.0: a SemVer pre-release of the crate is
pre-standard as far as the gate is concerned.

**What "1.0" stands for (ruled 2026-10-09).** The property wanted is that
the crate implements final FIPS 206; the gate tests the crate's major
version. The two are assumed to coincide: 1.0 is taken to be the FIPS 206
release. Which version that turns out to be is known when it ships, and the
gate's threshold is adjusted then.

The tag rule is the repository's own:
[`RELEASE_PROMOTION.md`](../RELEASE_PROMOTION.md) reserves the first
non-pre-release tag for the genesis mainnet release. The gate runs in
`grep-gates.yml` in its reporting form. It is armed in `gitian.yml`, the
workflow that builds and publishes a tag today: the build job waits on it,
and it reads the tree of the tag being built. It is also wired into
`release-tagged.yml.disabled`, so that re-enabling that workflow does not
open a second road to a release.
[`RELEASE_CHECKLIST.md`](../RELEASE_CHECKLIST.md) carries the row.

## 5. Findings

| # | Finding | Disposition |
| --- | --- | --- |
| `FND-1` | The brief placed the workspace's seed→RNG pattern in `rng.rs`. `rng.rs` is the OS-entropy failure policy and has no seeded RNG; the pattern is `derivation::keygen_from_seed` (ChaCha20 over a 32-byte seed) | Followed the code. `rng.rs` owns both failure policies. `HedgedOsRng` is the signing adapter. `key_material32` is the fail-loud key draw, crate-private, so the public surface stays `hedged_fresh32` |
| `FND-2` | The crate does not wipe the seeds it draws: `keygen_inner`'s 32-byte seed and `sign`'s 40-byte seed are stack arrays that are never zeroized. Its key and context structures are `ZeroizeOnDrop` | Recorded. Our own copies are `Zeroizing`. The ChaCha20 generator that feeds key generation also holds the seed unwiped, as it does for ML-DSA today |
| `FND-3` | `SigningKey1024::decode` returns a ~114 kB context **by value**. Any move of it is another copy on the stack, unwiped, and in an unoptimized build each move costs its size in stack. The first draft moved it once and signing needed 1.25 MiB of stack; borrowing it in place halved that | Fixed in this increment; the measurements are on `the_scheme_runs_on_a_small_stack` |
| `FND-4` | Signing needs up to 256 KiB of stack optimized and 640 KiB unoptimized; key generation 128 KiB and 512 KiB; verification 64 KiB and 128 KiB | Held by test at half a default thread stack (unoptimized) and a quarter (optimized). **Carried to increment 4:** the serve path's signing capability should hold a decoded key across signatures rather than decode per receipt — it removes the per-signature stack cost and the ~13% the crate's own figures give for decoding |
| `FND-5` | The registry gate passed with two unregistered scheme-domain constants in the tree: it pins cSHAKE call sites, and a domain constant with no call site of its own is invisible to it | Rows added by hand, census pin moved. The gate's header already says completeness for constants is a review duty; this is an instance |
| `FND-6` | The x86_64 vectors run AVX2 code the floor device never runs | Recorded at the pin; the same vectors are run with AVX2 compiled out and under aarch64, each by its own CI step |
| `FND-7` | No licence policy is enforced anywhere in the repository | Recorded. Not this lane's to add |
| `FND-8` | The lock file moved an unrelated edge (`bindgen` → `itertools`) when the dependency was added without `--locked` | Restored by hand; the lock differs from `dev` by the five packages only |
| `FND-9` | Sign and verify figures on the floor device are owed, and so is a run of the vectors on aarch64 hardware: their agreement there was shown under emulation, which computes IEEE arithmetic in software and so cannot show what the device's own floating point does | The benches exist (§3.1). Registered as `BA-T33`'s floor arm with a FOLLOWUPS row; the capture is a floor-device session |
| `FND-10` | The brief asks for a floor-device row in the measurement ledger for sign and verify. The ledger holds one row per **constant** whose value rests on a measurement (`defined_in` and `needle` are required), and scheme 3 has no such constant yet: nothing budgets against its cost until the receipt is signed with it | Not entered: a row with no constant would not parse. The measurement is registered where a ledger row would point, `BA-T33` in the tracked set. The ledger row lands with the first constant that reads the figure |
| `FND-11` | The specification gave the receipt key "its own label" and listed one HKDF row; the brief asks for two. The key is a hybrid with two independently seeded halves, as the identity key is (`ARCHIVAL_P_ACCOUNT_SIGN_INFO`, `ARCHIVAL_P_ML_DSA_INFO`), so one label cannot seed it | Two labels, one per half. The specification's §6.3 and §16 now name both |
| `FND-12` | Deriving a persona's keys now includes one FN-DSA-1024 key generation per slot: 6.2 ms on an x86_64 development host, and unmeasured on the floor device. It is paid at engine assembly, for the lookahead set (two slots, plus a first-stake intent slot), by stakers only, inside the blocking unit that already runs one ML-KEM and two ML-DSA key generations per slot. The bond watch's probe window does not pay it: it derives identity public keys alone (`derive_archival_p_identity_pk`) | Recorded. The floor figure rides `BA-T33`'s floor arm, which already times seeded key generation |
| `FND-13` | Increment 1 held the FN-DSA secret key as a 2,369-byte array inline in `FnDsaHybridSecretKey`. Key generation returned it by value and every move of the key copied it; `Zeroizing` wipes only where a value last rested, so each earlier copy stayed on a stack nobody wipes. It went unnoticed while nothing held the key. Putting it in the persona bundle made the bundle large enough to trip clippy's stack-array lint in an engine test, which is how it was found | Fixed with increment 2: the secret half is a heap buffer that key generation writes in place, so moving the key moves a pointer. `a_secret_key_is_not_its_fn_dsa_bytes_inline` holds it. The public key and the signature stay inline; neither is secret |

## 6. What the later increments inherit

- **Increment 2** derives the receipt key per persona slot from the wallet
  master seed under two new HKDF labels and calls
  `HybridEd25519FnDsa::keypair_from_seeds`. Done: §7.
- **Increment 3** puts `ArchivalPKeys::receipt_sign_pk`, as
  `FnDsaHybridPublicKey::to_canonical_bytes()`, in the JoinMarket post; admission's "parses" is
  `FnDsaHybridPublicKey::from_canonical_bytes`, which checks both halves.
- **Increment 4** signs the unchanged 112-byte transcript under
  `SCHEME_DOMAIN_RECEIPT`. The refusal trailer's `0xFF` fill is already
  shown not to parse (`an_all_ones_fill_is_not_a_signature`).
- **Slice C** uses `HybridEd25519FnDsa::generate_keypair` for the witness's
  per-block key and `SCHEME_DOMAIN_WITNESS_CARRIER` for its signature. That
  key is random, never seeded and never stored.

## 7. Increment 2 — the receipt key

The persona's receipt key is derived with the rest of its keys, from the
wallet master seed, by slot.

| Piece | Where |
| --- | --- |
| The two labels | `ARCHIVAL_P_RECEIPT_ED_INFO` = `shekyl-archival-p-receipt-ed25519-v1`, `ARCHIVAL_P_RECEIPT_FN_DSA_INFO` = `shekyl-archival-p-receipt-fn-dsa-1024-v1` (`rust/shekyl-crypto-pq/src/archival_p.rs`) |
| The seeds | `derive_p_receipt_ed_seed`, `derive_p_receipt_fn_dsa_seed`: 32 bytes each, `HKDF-SHA-512(salt_for(net, fmt), info = LABEL ‖ 0x00 ‖ p_slot_le32)`, the frozen layout every sibling label uses |
| The key | `ArchivalPKeys::receipt_sign_pk` / `receipt_sign_sk`, from `HybridEd25519FnDsa::keypair_from_seeds` over the two seeds, inside `derive_archival_p_keys` |
| Vectors | `ARCHIVAL_P_DERIVE_V1` amended in version: four Tier-1 rows (the two seeds, a label separation against the identity seed, a network separation) and the canonical public key in each of the four Tier-2 cells. No existing vector changed |

**Network scoping is inherited, not added.** The salt carries the network
and the seed format, so the same wallet's receipt key on one network is not
its key on another. The corpus pins that as an inequality on a live
computation, and the Tier-2 matrix pins the key on three networks.

**Where it is derived.** `derive_archival_p_keys` is what engine assembly
calls for each slot it will hold (`rust/shekyl-engine-core/src/engine/lifecycle/assemble.rs`).
The stake-engine actor receives the bundles and no seed, so it holds the
receipt key exactly as it holds the identity key. Nothing else changed in
the engine: there is no receipt-signing message and no serving capability
for this key yet, because nothing signs with it until the bond record
carries its public half. Both land with their caller in increment 4.

**The secret half is pinned through its seeds.** `FnDsaHybridSecretKey` has
no encoding by design, so the corpus holds the two seeds and the public key,
not secret-key bytes.

**Recovery.** `receipt_key_recovers_from_the_seed` signs a transcript with
one derivation's key and verifies it under a second derivation's public
half; `receipt_key_is_scoped_to_slot_and_network` and
`receipt_key_shares_no_seed_with_its_siblings` hold the scoping and the
isolation from the identity, bond-spend and onion keys.
