# `CA-2` localisation, and the ML-KEM validity gap: registered 2026-11-21

**State: registered; no registered run has been made.** Results go into
[`CRYPTO_AUDIT.md`](../../../../design/CRYPTO_AUDIT.md) §2 and as dated
record files beside this one. This section is not edited after the first
run.

## The questions

1. **Which part of the inlined `HelioseleneField` stream carries `CA-2`?**
   The halves (`U256::square_wide`, `U256::mul_wide`, `red512`) were flat
   behind a call boundary (2026-10-25). Run them inlined to see whether the
   multiplier or the reduction carries the effect.
2. **Does a sparse Montgomery residue make `Field25519` cross?**
   `Field25519`'s shape rows are flat, and it holds `x·R mod p`, so a
   sparse canonical value is not sparse inside it. If its rows cross when
   the residue itself is sparse, the multiplier path carries the effect; if
   they stay flat, `red512` does.
3. **Is ML-KEM decapsulation's validity gap the core's, and is the compare
   its carrier?** RT-P4 on the laptop reads invalid ciphertexts as slower
   (`valid-vs-invalid` 45.41, `fixed-vs-bitflip` 10.98; the maintainer's
   acceptance stands). The hypothesis is this Tiger Lake core's
   low-activity effect: a valid ciphertext's compare folds equal bytes.

## The instruments

All in `docs/formal/checkct/dynamic/` (1,000,000 samples per class, the
size of the 2026-10-25 records) unless named otherwise. Each run also
runs the suite's own controls and nulls in the same invocation.

| Row (filter) | Build | Question |
| --- | --- | --- |
| `half:` | `--profile release-lto` (fat LTO, one codegen unit) and `--release` | 1 |
| `Montgomery-sparse` | `--release` | 2 |
| `ct_ne 1088` | `--release` | 3, the compare alone |
| RT-P4's information comparisons (`rust/shekyl-rpc-channel/examples/rt_p4_decaps_timing.rs`, a seed of this registration's choosing, `20261121`) | as RT-P4's registration builds it | 3, on other silicon and under the core controls |

## The lines

A row's `|t|` (the larger of the raw and the cropped figure) is read as
follows:
- **above 10** is a crossing;
- **below 4.5** is flat;
- **between the two** is inconclusive, and that row is reported as such.

A run is void if the positive controls are not detected or a null reads
4.5 or more.

1. **The halves under `release-lto`.**
   - If `half: U256::square_wide` or `half: U256::mul_wide` crosses with
     its `[fixed-pair]` companion while `half: helio wide_reduce (red512)`
     is flat, the multiplier carries the effect.
   - If the reduction crosses and the products are flat, the reduction
     carries it.
   - If both cross, both do.
   - The `--release` run of the same rows must reproduce the 2026-10-25
     flat halves. If it does not, the comparison with LTO is void.
2. **`Field25519` Montgomery-sparse.** Square or mul crossing means the
   multiplier path; both flat means the effect needs `red512`.
3. **`ct_ne 1088`.**
   - If `equal vs random` or `equal vs one bit flipped` crosses in the
     direction RT-P4 sees (equal faster), the compare is a carrier.
   - Both flat means the gap lies elsewhere in decapsulation.
4. **RT-P4's validity comparisons.**
   - *On other silicon:* `valid-vs-invalid` and `fixed-vs-bitflip` flat
     means the gap belongs to this core; crossing means it does not.
   - *On the Tiger Lake workstation:* the same comparisons are run three
     ways, and the figures and turbostat's IPC per class are reported
     beside each other.
     - DOITM set and clear.
     - The clock pinned (`no_turbo`, the performance governor).
     - Under turbostat.
   - *On the floor device:* CA-2's rows were flat on the Pi 4, so the
     hypothesis predicts no validity gap there. The validity lines of
     RT-P4's own floor run (#1494, made by its owner) are read and recorded
     as a confirmation or a refutation. No second run is made on that
     device for this.

## Devices and order

1. **The Tiger Lake Linux workstation** (CA-2's). Questions 1 to 3 and
   the RT-P4 comparisons. It needs a quiet claim in the estate's usage
   ledger, and the DOITM and clock steps need the maintainer's root, as on
   2026-10-24 and 2026-10-25. If a run is disturbed, it moves to another
   Tiger Lake core rather than being repeated here.
2. **The fleet measurement host** (other silicon). The same rows and the
   RT-P4 comparisons, after the claim now on it ends (2026-11-25 00:00Z).
3. **The floor device.** Read from RT-P4's registered floor run.

**Attempts.** As for any `CA-2` row: a void may be made once more after
its cause is named and fixed. Every attempt's record is committed. A
finding that the carrier is in `fips203` rather than the core is new, and
goes to the maintainer with options.

**What follows.** The localisation results go into a Round 0 to the
maintainer before any change to `HelioseleneField`. The Round 0 covers:
- the candidate shapes: a `prime-field` port, a Montgomery representation
  inside the existing type, blinding;
- what each closes (`CA-1`, `CA-2` or both);
- its cost, measured on the floor device;
- its route upstream.

## Development check of the new rows (not a result)

On the workstation, under the usual shared load (load average 4.2), at
200,000 samples per class, the `ct_ne 1088` rows each read `|t|` ≤ 2.03.
The equal-against-unequal difference was under 30 ns per 32-compare batch,
where RT-P4's 36 ns per decapsulation would read about 1,150 ns. This only
shows that the rows run, and it is not a result for question 3.
