# CA-2 desktop field and ciphertext comparisons

The i9-13900K desktop ran x86_64 Windows MSVC binaries built from
`95b7a2ea03a8295d504c6d65ac319979dd437542` with Rust 1.94.0 and static CRT.
The [desktop amendment](../2026-11-21/ca2-desktop-amendment.md)
states the input counts and quiet conditions. The ordinary-release binary
SHA-256 was `f6bc759d0121ba9d1d57c4fe5866e91b9a47fa9fc9e7294b5a6c121210c873c5`.
The fat-LTO binary SHA-256 was
`e0b29f52f7aae3725897c9d683bb6eabe9583d1856ec3a11fa1522838aad9761`.

All three runs completed on their first quiet-gated launch, with Normal
priority, affinity 0x10, a basic-user token and exit 0. The monitor recorded
94, 4 and 15 sibling samples respectively, all below 5%. The build before
the fat-LTO run hit a rustc internal compiler error. The same compiler,
profile and source built successfully in a fresh target directory after
the desktop reboot. The initial unfiltered run was interrupted after
identifying the allocation issue. PowerShell split the row filters on an
intermediate launcher attempt, which exited before taking measurements.

Each reported score is the larger absolute value of the raw and cropped
t statistics. The registered lines are below 4.5 for a flat row and above
10 for a crossing. Positive controls must cross, and all nulls must stay
below 4.5.

| Run | Start and end (UTC, Nov 25) | Batches per class | Largest null | Positive controls | Test rows |
| --- | --- | ---: | ---: | --- | --- |
| Ordinary release | 17:30:27–17:46:19 | 1,000,000 | 1.90 | 3038.83, 5370.92 | Halves and fixed-pair companions ≤2.50. Montgomery-sparse square 3.16, mul 1.18 |
| Fat LTO | 17:49:35–17:50:26 | 1,000,000 | 1.62 | 1059.30, 5419.99 | Halves and fixed-pair companions ≤1.95 |
| Isolated `ct_ne 1088` | 17:53:43–17:56:23 | 100,000 | 1.01 | 950.27, 1742.25 | Equal vs random 1.42. Equal vs one bit flipped 1.99 |

The ordinary-release halves were flat, reproducing the earlier
behind-call baseline. The fat-LTO halves and sparse Montgomery rows were
also flat on this desktop. Neither half crossed. These runs cannot
attribute the earlier inlined timing effect to the multiplier or
reduction. The earlier Linux observations and CA-2 closure criterion
stand. This measurement changes both CPU and compiler target relative to
those observations.

The isolated comparison did not show a validity effect at the smaller
input count required by desktop memory. This agrees with the flat
[desktop RT-P4 validity rows](ca2-desktop-rt-p4.md), which used the full
one million samples per comparison. The two desktop results leave the
origin of the earlier Tiger Lake observation unresolved.

The raw results are byte-preserved and match the observer hashes.

| Capture | SHA-256 |
| --- | --- |
| [Ordinary release](ca2-desktop-targeted-release.txt) | `1d50c33cde25b48aa619aeaff82f51245c143087b33d17b8110185124ad09250` |
| [Fat LTO](ca2-desktop-targeted-lto.txt) | `2e160f29382f07af7eb729844452a8861c9707ee1b8692415b64f9eba6eece15` |
| [Isolated comparison](ca2-desktop-compare-1088.txt) | `ff9fdc52dfe0e39c361e780d85016c0edf48daa92c3ee3036db274a55058a06a` |
