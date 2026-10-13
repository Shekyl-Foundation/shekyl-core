# FN-DSA hybrid signatures — scheme 3, its dependency, and the lane

**Status:** OPEN — increment 1 (the scheme in `shekyl-crypto-pq`, no
consumers) recorded 2026-10-09 and merged 2026-10-10; increment 2 (the
receipt key derived per persona slot, §7) recorded 2026-10-10. **Increments 3
and 4 (the bond record carrying the receipt key, receipts moving onto it)
were handed to SO-D8 Slice C on 2026-10-11**
([`ARCHIVAL_SERVE_CREDIT_SPEC.md`](ARCHIVAL_SERVE_CREDIT_SPEC.md) `SCS-P26`,
§11): the verifier of increment 4 is that slice's bundle rule, the signer
and the verifier must switch in one change, and increment 3 lands in Rust
only. `FND-4`'s carried item, one decoded key across signatures, goes with
increment 4. This lane's own work ended with increment 2. **The document
stays OPEN as the record increments 3 and 4 are written into** when the
Slice C lane lands them; it closes when increment 4's record is in, and
the dependency record (§2) then moves to
[`CRYPTOGRAPHIC_INVENTORY.md`](../CRYPTOGRAPHIC_INVENTORY.md), which already
carries its summary row. **Increment 3 is recorded here, 2026-10-12 (§8),
built by the Slice C lane:** the receipt key is mandatory, a JoinMarket has
one wire form that commits it, and the bond record keeps it, typed and
fixed-length.
**Substrate verified at:** `origin/dev` = `6b23eab315`.
**Authority:** [`ARCHIVAL_SERVE_CREDIT_SPEC.md`](ARCHIVAL_SERVE_CREDIT_SPEC.md)
§6, §11 and §13.1 R2–R4 (ruled 2026-10-07).
**Findings:** `FND-1…FND-20` (§5) and `FND-21…FND-24` (§9.2), registered in
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
| `FND-2` | The crate does not wipe the seeds it draws: `keygen_inner`'s 32-byte seed and `sign`'s 40-byte seed are stack arrays that are never zeroized. Its key and context structures are `ZeroizeOnDrop` | Recorded. Our own copies are `Zeroizing`. The ChaCha20 generator that fed key generation also held the seed unwiped, as it did for ML-DSA and ML-KEM. Callers of `SeededRng` now move a pointer; the constructor return `FND-14` names is the residue that is still not wiped |
| `FND-3` | `SigningKey1024::decode` returns a ~114 kB context **by value**. Any move of it is another copy on the stack, unwiped, and in an unoptimized build each move costs its size in stack. The first draft moved it once and signing needed 1.25 MiB of stack; borrowing it in place halved that | Fixed in this increment; the measurements are on `the_scheme_runs_on_a_small_stack` |
| `FND-4` | Signing needs up to 256 KiB of stack optimized and 640 KiB unoptimized; key generation 128 KiB and 512 KiB; verification 64 KiB and 128 KiB | Held by test at half a default thread stack (unoptimized) and a quarter (optimized). **Carried to increment 4:** the serve path's signing capability should hold a decoded key across signatures rather than decode per receipt — it removes the per-signature stack cost and the ~13% the crate's own figures give for decoding. **Built 2026-10-12, STAGED:** `FnDsaHybridSigner`, measured in §9.1 |
| `FND-5` | The registry gate passed with two unregistered scheme-domain constants in the tree: it pins cSHAKE call sites, and a domain constant with no call site of its own is invisible to it | Rows added by hand, census pin moved. The gate's header already says completeness for constants is a review duty; this is an instance |
| `FND-6` | The x86_64 vectors run AVX2 code the floor device never runs | Recorded at the pin; the same vectors are run with AVX2 compiled out and under aarch64, each by its own CI step |
| `FND-7` | No licence policy is enforced anywhere in the repository | Recorded. Not this lane's to add |
| `FND-8` | The lock file moved an unrelated edge (`bindgen` → `itertools`) when the dependency was added without `--locked` | Restored by hand; the lock differs from `dev` by the five packages only |
| `FND-9` | Sign and verify figures on the floor device are owed, and so is a run of the vectors on aarch64 hardware: their agreement there was shown under emulation, which computes IEEE arithmetic in software and so cannot show what the device's own floating point does | The benches exist (§3.1). Registered as `BA-T33`'s floor arm with a FOLLOWUPS row; the capture is a floor-device session |
| `FND-10` | The brief asks for a floor-device row in the measurement ledger for sign and verify. The ledger holds one row per **constant** whose value rests on a measurement (`defined_in` and `needle` are required), and scheme 3 has no such constant yet: nothing budgets against its cost until the receipt is signed with it | Not entered: a row with no constant would not parse. The measurement is registered where a ledger row would point, `BA-T33` in the tracked set. The ledger row lands with the first constant that reads the figure |
| `FND-11` | The specification gave the receipt key "its own label" and listed one HKDF row; the brief asks for two. The key is a hybrid with two independently seeded halves, as the identity key is (`ARCHIVAL_P_ACCOUNT_SIGN_INFO`, `ARCHIVAL_P_ML_DSA_INFO`), so one label cannot seed it | Two labels, one per half. The specification's §6.3 and §16 now name both |
| `FND-12` | Deriving a persona's keys now includes one FN-DSA-1024 key generation per slot: 6.2 ms on an x86_64 development host, and unmeasured on the floor device. It is paid at engine assembly, for the lookahead set (two slots, plus a first-stake intent slot), by stakers only, inside the blocking unit that already runs one ML-KEM and two ML-DSA key generations per slot. The bond watch's probe window does not pay it: it derives identity public keys alone (`derive_archival_p_identity_pk`) | Recorded. The floor figure rides `BA-T33`'s floor arm, which already times seeded key generation |
| `FND-13` | Increment 1 held the FN-DSA secret key as a 2,369-byte array inline in `FnDsaHybridSecretKey`. Key generation returned it by value and every move of the key copied it; `Zeroizing` wipes only where a value last rested, so each earlier copy stayed on a stack nobody wipes. It went unnoticed while nothing held the key. Putting it in the persona bundle made the bundle large enough to trip clippy's stack-array lint in an engine test, which is how it was found | Fixed with increment 2: both secret halves are `HeapSecret<N>` (`rust/shekyl-crypto-pq/src/heap_secret.rs`), a fixed-length buffer at one heap address, wiped there on drop. Key generation writes the FN-DSA half in place and the Ed25519 half is copied from the caller's borrowed seed, so neither is a by-value array on the stack and moving the key moves two pointers (`a_secret_key_holds_neither_half_inline`). It is its own type because `zeroize` implements `Zeroize` for `Box<[Z]>` and not for `Box<[Z; N]>`, so `Zeroizing<Box<[u8; N]>>` does not compile. Callers borrow a half with `as_array`, or `as_array_mut` to write it in place. There is no `Deref`: `[u8; N]` is `Copy`, so `*secret` would be the unwiped stack copy the type exists to prevent. The type is crate-private. The public key and the signature stay inline; neither is secret |
| `FND-14` | Three sites each built `rand_chacha::ChaCha20Rng::from_seed` to generate a re-derivable key: ML-DSA-65 (`derivation::keygen_from_seed`), ML-KEM-768 (`account::ml_kem_keypair_from_d_z`) and FN-DSA-1024. That generator takes the seed by value, keeps it as its key with up to 256 bytes of buffered output, and has no wipe: every seeded key generation left its seed on the stack | One owner, `seeded_rng::SeededRng`. The cipher is `Box<ChaCha20Legacy>`: `SeededRng` is pointer-sized (`it_is_a_pointer`), a move leaves the cipher at the address it was boxed into (`a_move_does_not_move_the_cipher`), and drop wipes that heap cipher (`the_stream_is_wiped_on_drop`; the cipher's `ZeroizeOnDrop`, which the `zeroize` feature of `chacha20` provides — `chacha20` was already in the lock with that feature). Same stream, held against `ChaCha20Rng` on every call shape by `matches_rand_chacha_on_every_call_shape` and against the frozen bytes by every pinned key vector; none moved. What stays open: `ChaCha20Legacy::new` returns the cipher by value and the crate has no constructor that writes into caller memory, so `from_seed` moves that one return into the box and the source slot is not wiped. Closing it needs that upstream constructor. Unsafe placement is refused (`#[deny(unsafe_code)]` on this crate). Named in FOLLOWUPS |
| `FND-15` | `FND-13` is not peculiar to scheme 3. The persona bundle held its onion seed as an inline `Zeroizing<[u8; 32]>`, and the same shape is a field of moved structs across the workspace: about thirty fields in nine crates, with the three typed secret wrappers of `keys.rs` (one of them the 2,400-byte ML-KEM decapsulation key) held inline in the same bundle. Rule 35 prefers that shape and the by-value return that feeds it | `ArchivalPKeys::hs_id_seed` is a crate-private `HeapSecret<32>`. Other crates borrow it through `hs_id_seed() -> &[u8; 32]`; they do not name the buffer type, and a crate that does not already depend on this one does not gain a dependency to hold a secret this way. The rest are named, field by field, in a FOLLOWUPS row with the rule amendment it needs. Not fixed here: the wrappers are the wallet's principal key types and each field is a per-site judgment on whether its struct is moved |
| `FND-16` | The increment-3 brief assigned the JoinMarket's key-carrying form bond-post `post_kind` `4`, on the reading that `3` (`HoldingsUpdate`, REJECTED 2026-09-20) was the only refused byte. Byte `4` is refused too: it was `EndpointUpdate`, REJECTED 2026-09-13 ([`ARCHIVAL_ENDPOINT_UPDATE.md`](ARCHIVAL_ENDPOINT_UPDATE.md); decision log, same date), and `bond_wire_tests` pins `from_u8(4)` as `InvalidPostKind` beside byte `3` | The JoinMarket is `post_kind` **`5`**, the next byte no ruling had refused (rule 23: a refused name is not a free one). **Decided 2026-10-12: `5` stands.** With `FND-17`'s ruling, byte `0` joined `3` and `4`: the table is Reinstate `1`, Release `2`, JoinMarket `5` |
| `FND-17` | **The receipt key was optional for two revisions of this increment, and that was wrong.** Revision one stored it as `u32 len ‖ bytes` after `bond_spend_pk`, empty for a keyless join. Revision two moved it to a trailing, optional field so a keyless record kept its layout-22 bytes and no captured trace or pinned hash moved. Both kept a second JoinMarket wire form, `post_kind` `0` with no key, so that everything captured from the C++ daemon stayed readable | **Ruled 2026-10-12 on the review of PR #1046, relayed by the lane's coordinator: the receipt key is mandatory.** One JoinMarket wire form; `post_kind` `0` deleted; the record's `receipt_sign_pk` non-optional, typed and fixed-length; CEN-J28 with no keyless post to pass; the fixtures the optional field protected re-pinned; the captured C++ bond-post comparisons retired (`FND-19`). The reason given: a keyless post puts a pair in the drawable set that the `h_open(E)` snapshot cannot build, which blocks every bundle for that epoch — and the optional field was a compatibility arm, of which pre-genesis has none. What the optional field had protected, and what each became: the slash-tip snapshot hash and the codec tests' offsets are re-pinned; `bond_record.snap` is regenerated in both fixtures; the captured chains are `FND-19` |
| `FND-18` | The wallet recognised its own bond by comparing the recorded `post_kind` byte to `0` in four places (`bond_watch::sightings_in`, `staking_read::live_bonded_personas`, `staking_read::staked_balance_from_records`, `PScanAccrual::confirmed_join_market_personas`). With the JoinMarket's byte at `5`, a wallet would have posted a bond it never confirmed, never counted as staked and never sighted on restore. No type caught it: they are byte compares | Fixed with the wire change: `shekyl_wire::transaction::is_join_market_post_kind` is the one predicate (it is equality with `5`), and each site has a test that a `post_kind` `5` match is a JoinMarket and a `post_kind` `0` match is not. The recorded byte is the wire's. A P-scan state written before this change holds `0` for its joins and reads them as no bond: pre-genesis, it is rebuilt |
| `FND-19` | **Nothing captured from the C++ daemon can contain a JoinMarket this validator admits, and the Rust parser refuses the one it does contain.** The C++ serializer has `post_kind` `0` and no key-carrying kind, so every C++-built JoinMarket is keyless. Three bodies of captured material hold one | Retired, each at its site with this reason, the files themselves untouched: **(a)** the captured chains `bond-post` and `emission-claim` (`rust/shekyl-chain-ingest/tests/vectors`) list their JoinMarket in block 98. That block does not parse and the corpus reader is sequential, so what is retired is not the Bond family's comparison alone but **the replay from height 98 on** — the tip digest, the `0x04` archival snapshot, and every per-height comparison from 98 upward — in the default and the production-substrate lanes (`vectors_tests::RETIRED_KEYLESS_JOINS`). Blocks 0–97 of both still connect and are compared at every height. `emission-claim`'s `PREDATES` record (refused at 98 by CEN-J15) could no longer be observed and is replaced by the retired record. The archival-inputs table over the corpus loses those chains' three entries (two joins, a credit and a claim, all at or above 98). **(b)** `pqc_signing_preimage_v1.json` and `prunable_digest_parity_v1.json` each pin two bond-post bodies; the Rust legs hold them to their refusal and derive nothing from them, and the bond-post class is no longer in the Rust leg's class list. The C++ legs still parse them. **(c)** `gate4_lifecycle_kat_v1.json`'s `join.wire_hex` is held to its refusal, and the KAT judges the join its own builder makes today. None is regenerated: each file is also read by a C++ test whose decoder knows kind `0` and cannot read kind `5`. They return when a capture can hold a key-carrying JoinMarket |
| `FND-20` | **The C FFI can no longer verify a JoinMarket or export a bond row.** `shekyl_archival_verify_join_market_bond_post` and `shekyl_e2_archival_snapshot_push_bond` take no receipt key and their signatures are frozen (the header gate). Both refuse every call — `ERR_POST_KIND` and `SHEKYL_E2_TRACE_ERR_ROW` — rather than build a JoinMarket or a record with a key nobody committed. So the C++ daemon admits no JoinMarket (`check_archival_bond_post_input` rejects on the verify's code), and three cases of `tests/unit_tests/archival_bond_post_integration.cpp` asserted the opposite while six more passed for a reason that was no longer theirs | **Decided 2026-10-12, relayed by the lane's coordinator: the C++ test cases whose subject no longer exists are deleted** (rules 15 and 20; rule 50, a check that cannot fail is not a check). In that file and no other C++ file: deleted `gate4_integration_accepts_valid_join_market` and `gf1_join_market_credit_path_pins_identity_key` (each asserted an accept that cannot happen); deleted `gate4_integration_rejects_both_bond_terms`, `_rejects_debit_without_credit`, `_rejects_existing_bond_record`, `_rejects_floor_mismatch`, `_rejects_empty_shard_set` and `_rejects_complete_tree_with_shards` (each now passed on the blanket refusal, not on the defect in its name); `ffi_maps_each_bond_post_error_code` keeps its one live row, the Release export's key coupling, and loses its JoinMarket rows; the helper `hash_from_hex` and three fixture fields only they read are gone. **One test added**, `join_market_verify_ffi_refuses_every_call`: the JoinMarket entry point answers `ERR_POST_KIND` whatever the post says. **Dead in C++ until DEL-008 removes it:** the daemon's JoinMarket branch in `check_archival_bond_post_input`, the two always-refusing exports, and `archival_substrate_lmdb.cpp`'s opt-in capture mode (`SHEKYL_E4_CAPTURE_DIR`), which throws on a store holding a bond record — a tool path, not a CI test. `shekyl_e2_trace_export` fails on such a store for the same reason. The C++ edit was made without building the C++ tree. Falsifier: `grep -c 'SHEKYL_ARCHIVAL_BOND_POST_OK' tests/unit_tests/archival_bond_post_integration.cpp` finds only the replacement test's `EXPECT_NE`, and `git diff --stat origin/dev -- src '*.h'` is empty |

## 6. What the later increments inherit

- **Increment 2** derives the receipt key per persona slot from the wallet
  master seed under two new HKDF labels and calls
  `HybridEd25519FnDsa::keypair_from_seeds`. Done: §7.
- **Increment 3** puts `ArchivalPKeys::receipt_sign_pk`, as
  `FnDsaHybridPublicKey::to_canonical_bytes()`, in the JoinMarket post; admission's "parses" is
  `FnDsaHybridPublicKey::from_canonical_bytes`, which checks both halves. Done: §8.
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
*(2026-10-12: the record carries the public half since increment 3, §8.
Still nothing signs with the key; that is increment 4.)*

**The secret half is pinned through its seeds.** `FnDsaHybridSecretKey` has
no encoding by design, so the corpus holds the two seeds and the public key,
not secret-key bytes.

**Recovery.** `receipt_key_recovers_from_the_seed` signs a transcript with
one derivation's key and verifies it under a second derivation's public
half; `receipt_key_is_scoped_to_slot_and_network` and
`receipt_key_shares_no_seed_with_its_siblings` hold the scoping and the
isolation from the identity, bond-spend and onion keys.

## 8. Increment 3 — the receipt key on the wire and in the record

A JoinMarket commits the persona's receipt key, admission checks that it is
a key, and the bond record keeps it. The key is **mandatory** (`FND-17`).
Rust only: no file under `src/` moved, and the C++ daemon does not know the
post.

| Piece | Where |
| --- | --- |
| The wire | Bond-post `post_kind` **`5`** is the JoinMarket, its one form: `varint ‖ bond_spend_pk`, `varint(1837) ‖ receipt_sign_pk`, `endpoint[32]`. `post_kind` `0`, the keyless JoinMarket, is retired and refused at parse by both decoders. Both representations hold the key as a typed, non-optional field of the JoinMarket variant (`shekyl_wire::BondPostKind`, `shekyl_archival_retention::BondKind`) |
| The type | `shekyl_types::archival::ReceiptSignPk`: exactly `RECEIPT_SIGN_PK_LEN` (1,837) bytes. It lives in `shekyl-types` because the wire, the validator and both stores carry it and that crate holds the words they share (rule 18); parsing it as a key stays in `shekyl-crypto-pq` (`FnDsaHybridPublicKey::from_receipt_sign_pk`, `to_receipt_sign_pk`), which asserts at compile time that the two lengths are one |
| "Is this a JoinMarket?" | `BondPostKind::is_join_market` (retention) and `is_join_market_post_kind` (wire), each one predicate over one byte |
| Admission | **CEN-J28**: the key parses as a canonical `FnDsaHybridPublicKey`. `rules::tx_inputs::J28`, in `tx_form` after J11 and J12. A JoinMarket with no key, or with one of another length, is unrepresentable in the type and refused at parse, so the row judges the key's content |
| The signature | Nothing new. The key rides the signed prefix, so the identity key's `pqc_auths` slot covers it: one flipped bit of it under a standing signature is CEN-I18's refusal |
| The record | `BondRecord::receipt_sign_pk: ReceiptSignPk`, copied by the fold's `join` and by nothing else. Stored fixed-width, 1,837 bytes with no length prefix, directly after `bond_spend_pk`; store layout 24 → 25 (one bump for the layout this increment ends on — `dev` took 23 for the draw-state tables and 24 for the alt record while it was open) |
| The producer | `BondPostKeys::receipt_pk`, filled by `ArchivalPKeys::bond_post_keys`; `build_join_market_vin` has one output. Its callers did not change: the key arrives inside the value they already pass |

**The bytes.** `0`, `3` and `4` are refused names; the table is Reinstate
`1`, Release `2`, JoinMarket `5` (`FND-16`).

**The length is the type's and the wire's; the content is the rule's.** Both
parsers refuse a receipt key whose prefix declares any length but 1,837,
and the in-memory type cannot hold another. What reaches CEN-J28 is 1,837
bytes, and the rule decides whether they are a key: version, scheme byte,
reserved field, both inner lengths, an Ed25519 half that is a point and an
FN-DSA half the verifier decodes.

**Immutable.** The key is written once, at JoinMarket connect. A Release
and a Reinstate update the record in place and do not name the field; no
post kind exists that could change it. A new receipt key is a new persona,
as a new endpoint is.

**What the C++ sees, and what it can no longer do** (`FND-20`). Its decoder
refuses `post_kind` `5`, and the Rust verify it calls for the kind it does
build, `0`, refuses every call: the C++ daemon admits no JoinMarket. The
snapshot export refuses a bond row. Both keep their C signatures. CEN-J28
is recorded UNREVIEWED in the conformance register for that reason.

**What was retired** (`FND-19`). Captured C++ material that contains a
JoinMarket contains a keyless one. Two captured chains are replayed only
below their join, and three fixture files' bond-post bodies are held to
their refusal on the Rust side.

**Not in this increment.** Nothing signs with the receipt key: receipts
still verify as they did, and move to this key in increment 4.

## 9. Increment 4 — the signing capability (STAGED 2026-10-12; the switch is not this change)

**Status of this section: STAGED.** The capability that signs a receipt
under the persona's receipt key is built and tested, and so are both ends
of the wire it would travel: the serving route's signer trait and the fetch
client's target are generic over the scheme, with the receipt scheme as
their second instantiation (§9.3, ruled 2026-10-12). Nothing on the live
path selects any of it: the serving task still signs with the bond identity
key under hybrid scheme 1, every fetch target is still built over the
identity key, and the live scheme's bytes are held to fixtures captured
before the change. Receipts do not move onto the receipt key here, so this
section does not close the document and §2 stays where it is. The switch is
the settlement lane's cutover, in the change that makes a verifier accept
scheme-3 receipts (the bundle verifier), and what is left for it is
selection (§9.4).

The number is 9 and the findings start at `FND-21` because another open
change (#1046, increment 3) adds §8 and `FND-16`–`FND-18`. This change
leaves alone what that one edits — the banner, the end of §5's table and
§6 — and touches §5 in one cell, `FND-4`'s disposition, which that change
does not. The banner's findings range is to be moved to cover
`FND-21`–`FND-24` by whichever of the two merges second.

| Piece | Where |
| --- | --- |
| The held key | `FnDsaHybridSigner` (`rust/shekyl-crypto-pq/src/fn_dsa_hybrid/signer.rs`): decodes an `FnDsaHybridSecretKey` once into a heap slot, then `sign(&mut self, domain, message)`. Both it and the per-call path sign that decoded key through `sign_decoded_key` and nest through `nest_fn_dsa_signature` (`fn_dsa_hybrid.rs`) |
| Byte identity | `a_held_key_signs_the_bytes_the_scheme_signs`, and `the_held_key_reproduces_the_pinned_signatures` in `tests/kat_fn_dsa_hybrid_v1.rs`, which reads `FN_DSA_HYBRID_V1_KAT.json` and so runs on the AVX2, no-AVX2 and aarch64 lanes. No vector was added or changed |
| The key in the actor | `HeldReceiptKey` (`rust/shekyl-engine-core/src/engine/stake_engine/types.rs`), a field of `BondedPersona` and `EphemeralPersona` beside the bundle: a three-state slot — `NotBuilt` until the persona's first receipt signature, then `Built` (the decoded key) or `Undecodable` for the rest of the persona's life (`HeldPersona::sign_receipt_transcript`) |
| The actor message | `SignReceiptTranscript` (`stake_engine/persona.rs`): the 112-byte transcript in, an `FnDsaHybridSignature` out. The domain is fixed by `sign_receipt_transcript` (`shekyl-p-serve`), which `HeldPersona::sign_receipt_transcript` calls. `StakeEngineHandle::sign_receipt_transcript_blocking` is its blocking sender |
| The capability | `ResidentReceiptKey` (`stake_engine/serving/receipt_key.rs`): a weak actor handle, a slot, and a sticky bit set when a signature finds the key undecodable. A `PassKey` at the receipt envelope's width, 1,356 bytes. Pre-flight is actor liveness plus that bit. It does not ask the actor, and an unheld slot is found at sign time, as the identity key finds it |
| The signer trait | `PassKey<const W>` / `PassSigner<const W>` (`rust/shekyl-p-serve/src/countersign.rs`), sealed over the two schemes by `EnvelopeWidth<W>`; the serve loop takes every width from the signer it is bound with (§9.3) |
| The fetch target | `FetchTarget<K>` / `VerifiedShard<K>` over the sealed `PassVerifyingKey` (`rust/shekyl-p-fetch/src/target.rs`); `PFetchClient::fetch::<K>` (§9.3) |
| The receipt check | `verify_receipt_transcript` (`rust/shekyl-archival-retention/src/attestation_wire.rs`), beside `verify_pass_transcript`: the same 112-byte transcript under `SCHEME_DOMAIN_RECEIPT` |
| The staging gate | `the_serving_task_is_not_started_with_the_receipt_key` reads `serving/start.rs`; `ResidentReceiptKey::new` carries `expect(dead_code)`, so a production caller fails the lint lane; a compile-time assertion holds that the capability is not a `PassKey` at the identity width, the width of the key the serving host takes |
| Benches | `crypto_bench_fn_dsa_hybrid_sign_held` (gated) and criterion `fn_dsa_hybrid_sign_held`, `fn_dsa_hybrid_hold_key`; manifest §13 |

**Where the decoded key lives.** In the stake actor and nowhere else, as a
field of the held persona, not a map beside the set: the activation wipe,
the retire wipe and `on_stop` each drop the persona, and a decoded key is
wiped with it (`a_wiped_persona_takes_its_receipt_key_with_it`). The
serving role holds a weak handle and a slot.

**It is decoded by the first receipt signature, not when the actor starts.**
A staged capability must cost the live path nothing, and until the cutover
no persona is asked for a receipt. A decode needs up to 360 KiB of stack in
an optimized build and leaves 118,640 bytes on the heap; done at start,
every staker's wallet would pay that per held slot at open for a key
nothing signs with. So the actor's start does no FN-DSA work
(`starting_the_actor_decodes_no_receipt_key`), the slot of a persona that
never signs a receipt stays `NotBuilt` for its life, the first signature
builds the key and each later one signs from that same key
(`the_first_receipt_builds_the_key_and_the_second_reuses_it`).

**What secret material the slot holds.** Before it is built, none: no key
byte and nothing derived from one. Once built it holds the receipt key a
second time, in decoded form — the FN-DSA signing key expanded to its
118,640-byte context (x86_64) and the signer's heap copy of the 32-byte
Ed25519 seed — in addition to the encoded secret, which stays in
`ArchivalPKeys::receipt_sign_sk` in the bundle beside it and is what the
slot decodes from. Both forms are wiped when the persona drops.

**A receipt key that does not decode is refused at that first signature,
and remembered.** The first request gets the scheme's typed error and the
slot becomes `Undecodable`; each later request is refused at once with the
same error, without reading the secret or attempting a decode
(`an_undecodable_key_is_not_decoded_again`, which runs the later requests
on a stack a decode attempt does not fit in). The key bytes do not change
while the persona is held, so a decode that failed once fails every time;
retrying would spend a decode's stack and time per request, on a path a
remote reader drives once the capability is live. The capability
remembers the same refusal on itself, so a later pre-flight returns it
without another question to the actor; the slot stays the authority that
refuses a second decode. The state is a unit: no
error value and nothing computed from the key is kept. It is per persona
(`an_undecodable_key_is_one_personas_state`), the identity key and the
other personas are unaffected
(`a_corrupted_receipt_key_refuses_through_the_actor`), and a persona leaves
it only by being dropped. Nothing checks the key at start. The cutover,
which makes receipt signing live, is where a start-time check belongs if
one is wanted.

### 9.1 `FND-4`'s disposition — measured

x86_64 development host, 2026-10-12. Stack: the smallest thread stack each
step ran on, by a ladder of 8 KiB steps from 16 KiB, so each figure is an
upper bound on the need; `a_held_key_signs_on_a_small_stack` holds the
bounds. Instructions: gungraun 0.19.3, the draw pinned, two runs identical.
Time: criterion, the production entry.

| | Per-call (`HybridEd25519FnDsa::sign`) | Held (`FnDsaHybridSigner::sign`) |
| --- | --- | --- |
| Stack, unoptimized | 568 KiB | 112 KiB |
| Stack, optimized | 248 KiB | 16 KiB (the ladder's first step) |
| Instructions | 6,675,435 | 6,010,472 (−9.96 %) |
| Time | 442 µs | 411 µs (−7.0 %) |

Building the held key once (`FnDsaHybridSigner::new`): 544 KiB unoptimized,
360 KiB optimized, 52 µs. Dropping it: within 16 KiB.

`FND-4`'s row gave 640 KiB and 256 KiB for per-call signing, from a ladder
that doubled; the 8 KiB ladder puts the same path at 568 KiB and 248 KiB.

Through the actor, where the first receipt pays the decode
(`the_first_receipt_pays_the_decode_and_later_ones_do_not`, same host, same
ladder; the actor's task on a current-thread runtime's one thread):

| | Unoptimized | Optimized |
| --- | --- | --- |
| Start an actor holding personas and query it, no receipt | 152 KiB | 56 KiB |
| Start, first receipt, second receipt | 608 KiB | 376 KiB |
| A held persona's first receipt, alone | 544 KiB | 360 KiB |
| A held persona's later receipt, alone | 112 KiB | 16 KiB (the ladder's first step) |

A later receipt cannot be given a stack of its own through the actor, whose
task stays on the thread it started on, so the last two rows are of the
held persona directly. The first row is below what one decode needs: the
test starts the actor on a stack a decode does not fit in.

### 9.2 Findings

| # | Finding | Disposition |
| --- | --- | --- |
| `FND-21` | The serving route could not take a scheme-3 signer as it stood. `PassKey::sign_pass` returned the scheme-1 `HybridSignature` by type, and the response envelope was that signature's canonical length, 3,385 bytes, as one global: `SIGNATURE_ENVELOPE_LEN` sized the signed trailer, the content length and the refusal trailer in `shekyl-p-serve`, and the fetch side read the same width into a fixed array and parsed it as a `HybridSignature`. A receipt is another type and 1,356 bytes | **Built here, by ruling 2026-10-12 (§9.3):** the trait is const-generic over the envelope's width, the fetch target is generic over its key's scheme, `ResidentReceiptKey` implements the trait, and the live scheme's wire bytes are pinned from before the change. **Left for the cutover (§9.4):** selecting the receipt scheme — the host's key type, the construction in `serving/start.rs`, the daemon's fetch targets — with the verifier that accepts a receipt, and the decision on decoding at serving-task start |
| `FND-22` | `zeroize` wipes an `Option<T>` by taking the value out and writing a fresh `None`: two `T`-sized values on the stack of the caller. For a 118,640-byte decoded key that made dropping a held signer need more stack than a signature (360 KiB unoptimized and 128 KiB optimized for a signature followed by the drop, against 112 KiB and 16 KiB once fixed) | Drop runs the crate's `Zeroize` on the key in place, with the crate's own `ZeroizeOnDrop` after it. Construction keeps the `Option` wipe for the stack local the key was decoded into, because there the whole slot has to go and it is paid once: that is why building a held key needs 360 KiB optimized, more than a per-call signature |
| `FND-23` | A decoded key still reaches the heap through the stack. `SigningKey1024::decode` returns the key by value, so the signer decodes into a local, exchanges it with the heap slot and wipes the local. The crate's own frame is out of reach: in a build that does not construct the return value in place, `decode` leaves the copy it built on its dead frame (`FND-3`'s residue). The decoded key itself is `Zeroize + ZeroizeOnDrop` in the crate, asserted at compile time beside the signer | Once per key, at construction, where the per-call signer leaves it on every signature. Closing it needs a decode into caller memory upstream; unsafe placement is refused, as in `FND-14` |
| `FND-24` | The crate's own figures put decoding at about 13 % of a signature (`FND-4`). On this host holding the key removes 9.96 % of the instructions and 7.0 % of the time. The Ed25519 half is still expanded from its seed on every signature, inside the shared nested body | Recorded with the measurements (§9.1). The floor figure rides `BA-T33`'s floor arm, which now has the held-key arm to run beside the per-call one |

### 9.3 The serving route and the fetch client, generic over the scheme (ruled 2026-10-12; receipt half STAGED)

Ruled on PR #1049, on `FND-21`: *"PassKey becomes const-generic over the
envelope width, instantiated at 3,385 with ResidentPassKey. Prove the wire
bytes are identical. ResidentReceiptKey implements the trait but is not
selected. Fetch side: the width comes from the target's key type. No
dual-scheme acceptance."*

**Serve side.** `PassKey<const W>` signs with the scheme whose canonical
signature is `W` bytes. `EnvelopeWidth<W>` is sealed and implemented twice,
each time with the signature type's own `CANONICAL_LEN` written as `W`, and
it fixes the type `sign_pass` returns. The width therefore decides the
type: a key at one width cannot return the other scheme's signature, and a
width that is neither has no key and no endpoint (compile-fail doctests in
`countersign.rs`, with a compiling control beside them). The trait takes
one parameter and not an associated signature type so that
`dyn PassKey<W>` is a complete type and the width alone names the scheme
everywhere a signer is held. The serve loop names no width: the envelope it
writes, the term in the content length and the refusal trailer's fill are
the `W` of the signer the endpoint was bound with. An endpoint is bound
with one signer and so at one width.

| Width | Scheme | Signers |
| --- | --- | --- |
| `IDENTITY_ENVELOPE_LEN`, 3,385 | 1, the bond identity key | **Live.** `ResidentPassKey`; the host's `HostSigner` (generic over its key's width); the test signers |
| `RECEIPT_ENVELOPE_LEN`, 1,356 | 3, the receipt key | **STAGED.** `ResidentReceiptKey`; `TestReceiptKeySigner` behind `test-signer` |

**Fetch side.** `FetchTarget<K>` is generic over the sealed
`PassVerifyingKey`, and the key's type is the exchange's scheme: the width
read, the signature parsed, the check run (`verify_pass_transcript` for an
identity key, `verify_receipt_transcript` for a receipt key). Each
implementation takes its width from its signature type's `CANONICAL_LEN`
and parses with that type's canonical decoder, which accepts that length
only.

**No dual-scheme acceptance.** `PFetchClient::fetch::<K>` is monomorphic in
`K`. There is no second attempt under the other scheme, nothing measures a
response to choose one, no enum holds a key of either, and no function
verifies under either. A response of the other scheme fails this scheme's
reading of it:

| Target's key | Response | Refusal | Held by |
| --- | --- | --- | --- |
| receipt | identity endpoint's, small shard | `Malformed::Oversize`, from the head | `tests/scheme_separation.rs` |
| identity | receipt endpoint's, small shard | `Malformed::EnvelopeShort`, from the head | same |
| identity | a valid receipt response, shard large enough to pass the head | `Malformed::FrameShort` | `client_scheme_tests.rs` |
| receipt | a valid identity response, same | `Malformed::FrameLong` | same |
| either | an envelope of the right width holding the other scheme's signature | `Malformed::Envelope` | same |

The engine's two capabilities are put through the same four combinations
behind the real endpoint (`receipt_round_trip_tests.rs`). The type-level
half is two compile-fail doctests on `FetchTarget`, with a control. This
repository's compile-fail pattern is the doctest; `trybuild` is used in
`shekyl-crypto-pq` only.

**The wire bytes of the live scheme are identical.** They were captured
from the tree before either side was generalized, in a commit of their own,
and are held since:

| Fixture (`src/wire_pin/*.hex`) | What it pins | Test |
| --- | --- | --- |
| p-serve `identity_served` | The whole response — status line, headers with the content length, body, 3,385-byte countersignature — from the endpoint and from the in-memory composition | `a_served_response_is_the_pinned_bytes` |
| p-serve `identity_unsigned` | The same with the refusal trailer | `a_refusal_trailer_response_is_the_pinned_bytes` |
| p-fetch `identity_request` | The request the client writes | `the_request_and_a_verified_response_are_the_pinned_bytes` |
| p-fetch `identity_response`, `identity_verified` | A signed response replayed to the client, and the delivery digest and view hash it returns; the signature returned is the response's last 3,385 bytes | same |
| p-fetch `identity_refusal_response` | A refusal-trailer response replayed; the verdict is `Unsigned` | `a_pinned_refusal_trailer_response_is_unsigned` |

The signatures in them are real: a key derived from a fixed seed, the
ML-DSA half signed from a fixed seed, verified under the key before
anything is compared. No fixture changed across the generalization. The
fetch side's pin test did not change at all; the serve side's changed in an
import, its signer's two `impl` headers and one cast.
Every existing test of the two crates and of their consumers passes with
its expectations as they were; what changed in them is type plumbing.

**Crates touched:** `shekyl-p-serve`, `shekyl-p-fetch`,
`shekyl-archival-retention` (the added check), `shekyl-p-host`,
`shekyl-p-loopback`, `shekyl-engine-core`, `shekyl-archival-fetch-sched`,
`shekyl-sp-t3-spike`. `shekyl-daemon-image` builds its target from the bond
record's identity key and needed no edit.

### 9.4 What the cutover does (requirements, ruled 2026-10-12)

**Selection, in the change that makes a verifier accept a receipt.** The
trait, the envelope and both ends of the wire are built. Selecting the
receipt scheme is: the serving host's key type declares the receipt width
(`shekyl_p_host::PersonaServing::key`, the one place the host's scheme is
chosen), `serving/start.rs` constructs `ResidentReceiptKey` there, and the
daemon builds its fetch targets over the receipt key the bond record
carries (`shekyl-archival-fetch-sched`'s `Holder::target` and the
`VerifiedShard` its reads return are pinned at the identity key's type
today). Each of those is a type the compiler follows; the staged-surface
test and the `expect(dead_code)` on the capability are removed by the same
change, deliberately.

**An undecodable receipt key: decode at serving-task start, or `ready()`
refuses after a failed decode.** The key is decoded by the first signature
(§9, above), so an undecodable key is found by the first reader. When the
receipt capability is selected, one of two things must hold: the key is
decoded when the serving task starts, so that it is found before any
reader; or the capability's `ready()` refuses once a decode has failed, so
that no later reader is sent a shard that will not be signed.

The three-state slot makes the second natural, and it is built:
`ResidentReceiptKey::ready` asks the actor, which answers from the slot's
remembered state without touching the secret, and after a failed decode
every request gets the bare 503 before any shard byte. Its cost is one
response: the request that triggers the first decode has its body sent and
closed with the refusal trailer
(`an_undecodable_receipt_key_costs_one_response_then_refuses_at_pre_flight`
shows both on the wire). A cutover that wants no such response decodes at
serving-task start as well; that is one receipt-key decode per serving
start, on the stack §9.1 gives, and it is the cutover's to add because it
is the cutover that makes the cost one the live path should pay.
