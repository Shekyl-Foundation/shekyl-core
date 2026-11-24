# `CA-3`: conditional branches in the post-quantum crates, swept 2026-11-23

**State of this record: complete for the pinned fips204 revision
`904f0bdfcd`.** Shekyl builds with `overflow-checks = true`. This record says
what that does to the post-quantum crates, what the fork of fips204 changes,
and why validation cannot change.

This record describes the public change as range hardening of the NTT path,
matching the reference implementation's reduction. Upstream's `main` reduces
the same input at its call sites (`492ad87`, 2026-11-20), in no release yet. The
fork reduces inside `inv_ntt`, so every caller is covered, and the two run
together. When upstream releases, the fork rebases onto that release and keeps
only the patches still needed; its README records the steps.

## What the fork changes

The fork is fips204 tag `v0.5.0` plus:

- `infinity_norm`, `make_hint` and `decompose` have no conditional branch on a
  coefficient. The reductions they use take wrapping arithmetic, with their
  debug assertions kept.
- `inv_ntt` reduces its input below `Q` first, as the reference implementation
  does, and `to_mont` reduces before it shifts. The bound for each stage is in
  the comments at the pinned revision.

`src/encodings.rs` and `src/conversion.rs`, which hold every decoder, are
byte-identical to the tag.

## Why validation cannot change

**Wherever the old code returned a value, the new code returns the same one.**
**Wherever an overflow-checked build of the old code would have panicked, if
any input reaches such a point, the new code returns a deterministic value
instead. No signature that validated before stops validating, or the reverse.**

The argument, at the pinned revision:

1. **The same bytes are accepted for decoding.** `sig_decode`
   (`src/encodings.rs:300`), `bit_unpack` with its range check
   (`src/conversion.rs:227`, `:260`), `hint_bit_unpack`
   (`src/conversion.rs:340`) and `pk_decode` (`src/encodings.rs:54`) are
   unchanged, and `verify_internal` still returns false on a decode failure
   (`src/ml_dsa.rs:400-408`).
2. **`w′` is the same polynomial.** The old and new inverse NTT compute the same
   linear map modulo `Q`, since the added reduction preserves each residue. Both
   end in `full_reduce32`, which has one result in `[0, Q)` for each residue, so
   the coefficients are equal, not merely congruent.
3. **The rest of verification reads only those values.** `use_hint`, `w1_encode`,
   the challenge hash and the norm check (`src/ml_dsa.rs:441-456`) take `w′`, the
   decoded hint and the decoded `z`. `infinity_norm` returns the same maximum,
   tested against the iterator maximum.

Whether a decoded public key and signature can reach the old panic range has not
been established. The argument above does not depend on the answer.

**Evidence** on rustc 1.94.0. The library's executable code is unchanged after
`072a7d68`: the later commits correct the `center_mod` interval comment, record
how the fork follows upstream, and make the branch checker take the caller's
pair. The suite results below are from `072a7d68`. The x86_64 branch count was
read again at this pin.

| Check | Result |
| --- | --- |
| The fork's whole test suite in release, overflow checks on and off | 70 passed, 0 failed, 5 ignored |
| The same suite in debug, overflow checks on and off | 83 passed, 0 failed, 1 ignored |
| The exhaustive tests, in release with overflow checks on (`center_mod`, `decompose`, the norm's absolute value, `to_mont_coefficient`) | 4 passed |
| Within that suite: the NIST vector tests and the Wycheproof tests | 4 and 3 passed |
| Differential against the tag: keys and signatures | 11,000 byte-identical |
| Differential against the tag: randomly changed keys and signatures | 65,999 with the same verdict, 0 different |
| The fork's source on upstream's `main` (`a465e122b2`), both reductions present, overflow checks on | release 70 passed, debug 83 passed, exhaustive 4 passed; 0 failed |

## The guards

BINSEC's `checkct` runs the helpers on unrestricted secret `i32` inputs on
x86_64: **the tag is secure on 0 of 5 entrypoints, the fork on 5 of 5**
([`docs/formal/checkct/README.md`](../formal/checkct/README.md)).

`scripts/ci/check_fips204_branch_counts.py` runs the fork's checker on the
shipped profile and passes the pair recorded for `fips204_branch_subject`.
The fork classifies each conditional branch inlined from the helpers and
carries no count of its own. Each must be a loop back-edge or the x86 test of
the public `gamma2`. The nightly `fips204-branch-count` job runs the x86_64
pair. A toolchain bump re-pins both pairs, on x86_64 and on the floor device.

| Binary | Target | Crate | Back-edges | `gamma2` tests | Other |
| --- | --- | --- | --- | --- | --- |
| `fips204_branch_subject` | x86_64 Linux | tag | 0 | 1 | **63** |
| `fips204_branch_subject` | x86_64 Linux | fork | 16 | 4 | **0** |
| `fips204_branch_subject` | aarch64 Linux | fork | 16 | 0 | **0** |
| `ca3_pq_sign_timing` | x86_64 Linux | tag | 0 | 1 | **81** |
| `ca3_pq_sign_timing` | x86_64 Linux | fork | 27 | 4 | **0** |
| `ca3_pq_sign_timing` | aarch64 Linux | tag | 0 | 0 | **88** |
| `ca3_pq_sign_timing` | aarch64 Linux | fork | 27 | 0 | **0** |
| `ca3_pq_sign_timing` | x86_64 Windows MSVC | tag | 18 | 1 | **110** |
| `ca3_pq_sign_timing` | x86_64 Windows MSVC | fork | 21 | 4 | **0** |

The count needs line tables, and line tables move code elsewhere in the binary.
So each target compares the two builds function by function. All 68 functions
holding fips204 code in `fips204_branch_subject` are instruction-identical with
and without line tables on x86_64 and on aarch64, and all 86 in the Windows
binary. Data addresses are masked in that comparison. The Windows comparison also
masks external call targets, so it does not show that a call reaches the same
callee.

## The sweep

**Branches that can go either way on a secret.** There are none in fips203
decapsulation, fips205 signing or fn-dsa-sign beyond each scheme's designed
sampling and restart. What remains in fips204 is its designed rejection, the
packing of the public hint, and length and validity checks.

**Overflow branches.** These are the panic edges `overflow-checks = true` adds,
counted in the shipped profile. Inlining makes the two architectures differ.

| Path | aarch64 | x86_64 |
| --- | --- | --- |
| fips204 key generation, decode, signing | 777 | 359 |
| fips204 verification | 330 | 132 |
| fips203 decapsulation (two more on each in `core`'s iterators) | 32 | 21 |
| fips205 signing | 12 | 19 |
| fips205 verification | 10 | 15 |
| fn-dsa-sign signing, with fn-dsa-comm | 79 | 170 |
| fn-dsa-vrfy verification | 4 | 10 |
| fn-dsa-comm, reached from verification | 28 | 5 |

**The range each group stays in.**

- **Indices, lengths, bit positions, in every crate.** These come from public
  parameters and array sizes, and do not depend on a secret.
- **fips204 forward NTT.** Every input is at most `2^19` in magnitude: decoded `z`
  and the mask are at most `2^19`, `s1`, `s2` and `c` are small, `t0` is at most
  `2^12`, and `t1` is below `2^10` (its shift by `2^13` comes after the NTT, in
  Montgomery form). Eight layers add less than `Q` each, so values stay below
  `2^19 + 8Q < 2^27`.
- **fips204 inverse NTT.** The input is below `Q`. After layer `k` values are
  below `2^k · Q`, so at most `256Q = 2,145,386,752 < 2^31`.
- **fips204 reductions and sums.** `to_mont_coefficient` is tested over all of
  `i32`. Matrix products sum to at most `7Q`, the signing path's sums and
  differences stay within a few `Q`, and the hint count is at most `256 · K`.
- **fips203 decapsulation.** Values are below `Q` after decoding and
  decompression. The Barrett reduction is checked exhaustively up to
  `2(Q − 1)²`, with no failures.
- **fips205.** FORS tree indices stay below `k · 2^a`, XMSS indices below the
  subtree's `2^h′`, and the WOTS checksum below `len · (W − 1)`.
- **FN-DSA verification.** The signed norm is at most 722,534,400 (`B_INF` = 840),
  `comp_decode` keeps its accumulator within its invariant, and `mq` values stay
  in `[1, Q]`.
- **FN-DSA signing.** The Gaussian sampler's base value is between 0 and 18.
  `hm[i] − t0[i]` at `fn-dsa-sign` `lib.rs:700` is bounded by the sampler's
  distance from the hashed message, far from the 32-bit limit. **That one bound
  is an argument from the sampler's construction through floating point, not a
  machine-checked proof.** The input there is a hash and the signer's own key.

## What this does not cover

- BINSEC runs on x86_64 with checkct's toolchain and a freestanding target, not
  on the shipped binary. The branch counts cover the shipped profile.
- The fork carries a CI job for the exhaustive tests, but Actions are not enabled
  on the fork, so that job has not run. The result above is one recorded run at
  the pinned revision.
- Only the x86_64 count runs nightly. The aarch64 and Windows counts are one
  measurement each at this revision.
- This record is about branches. Whether signing time depends on a secret is
  measured by `CA-3`'s registered timing runs.
