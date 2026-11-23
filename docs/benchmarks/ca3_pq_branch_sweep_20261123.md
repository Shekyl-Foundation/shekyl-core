# `CA-3`: conditional branches in the post-quantum crates, swept 2026-11-23

**State of this record: complete for the pinned fips204 revision
`072a7d68be`.** Shekyl builds with `overflow-checks = true`. This record says
what that does to the post-quantum crates, what the fork of fips204 changes,
and why validation cannot change.

The analysis of the previous code's range is held privately until upstream
responds to the advisory or its 90 days run out. This record describes the
public change as range hardening of the NTT path, matching the reference
implementation's reduction.

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

Whether any verifier input reaches the old panic range is not stated here. The
argument above does not depend on the answer.

**Evidence**, at the pinned revision:

| Check | Result |
| --- | --- |
| The fork's whole test suite in release, overflow checks on and off | 70 passed, 0 failed, 5 ignored |
| The same suite in debug, overflow checks on and off | 83 passed, 0 failed, 1 ignored |
| The exhaustive tests, in release with overflow checks on (`center_mod`, `decompose`, the norm's absolute value, `to_mont_coefficient`) | 4 passed; also a job in the fork's CI |
| Within that suite: the NIST vector tests and the Wycheproof tests | 4 and 3 passed |
| Differential against the tag: keys and signatures | 11,000 byte-identical |
| Differential against the tag: randomly changed keys and signatures | 65,999 with the same verdict, 0 different |

## The guards

BINSEC's `checkct` runs the helpers on unrestricted secret `i32` inputs on
x86_64: **the tag is secure on 0 of 5 entrypoints, the fork on 5 of 5**
([`docs/formal/checkct/README.md`](../formal/checkct/README.md)).

`scripts/ci/check_fips204_branch_counts.py` counts the conditional branches
inlined from the helpers in the shipped profile. Each must be a loop back-edge
or the x86 test of the public `gamma2`. The nightly `fips204-branch-count` job
runs it on x86_64. A toolchain bump re-pins it on x86_64 and on the floor device.

| Binary | Target | Crate | Back-edges | `gamma2` tests | Other |
| --- | --- | --- | --- | --- | --- |
| `fips204_branch_subject` | x86_64 Linux | tag | 0 | 1 | **63** |
| `fips204_branch_subject` | x86_64 Linux | fork | 16 | 4 | **0** |
| `fips204_branch_subject` | aarch64 Linux | fork | 16 | 0 | **0** |
| `ca3_pq_sign_timing` | x86_64 Linux | tag | 0 | 1 | **81** |
| `ca3_pq_sign_timing` | x86_64 Linux | fork | 27 | 4 | **0** |
| `ca3_pq_sign_timing` | aarch64 Linux | tag | 0 | 0 | **88** |
| `ca3_pq_sign_timing` | aarch64 Linux | fork | 27 | 0 | **0** |
| `ca3_pq_sign_timing` | x86_64 Windows MSVC | tag | 0 | 1 | **110** |
| `ca3_pq_sign_timing` | x86_64 Windows MSVC | fork | 21 | 4 | **0** |

The count needs line tables, and line tables move code elsewhere in the binary.
So each target compares the two builds function by function. All 68 functions
holding fips204 code in `fips204_branch_subject` are instruction-identical with
and without line tables on x86_64 and on aarch64, and all 86 in the Windows
binary. Data addresses are masked in that comparison.

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
- **fips204 forward NTT.** Every input is below `Q` in magnitude: decoded `z` and
  the mask are at most `2^19`, `s1`, `s2` and `c` are small, `t0` is below `2^12`,
  and `t1 · 2^13` is below `2^23`. Eight layers add less than `Q` each, so values
  stay below `9Q < 2^27`.
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
- Only the x86_64 count runs nightly. The aarch64 and Windows counts are one
  measurement each at this revision.
- This record is about branches. Whether signing time depends on a secret is
  measured by `CA-3`'s registered timing runs.
