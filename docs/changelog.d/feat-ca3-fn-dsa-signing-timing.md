- **The receipt countersignature's timing run is registered (`CA-3`, FN-DSA).** `shekyl-p-serve`'s example `ca3_receipt_sign_timing` times the held receipt signer over pass transcripts. Two classes of 256 decoded keys each have the same memory footprint, so they differ only in which keys their slots hold. Each signature's restart count is recovered from its nonce. The lines read both the timing `t` and the restart-rate `z`. A planted leak and two null comparisons can void the run. The registration (`docs/benchmarks/ca3_fn_dsa_receipt_sign_timing_20261121.md`) names three runs: the laptop's AVX2 path, its SSE2 path, and the floor device. `CRYPTO_AUDIT.md` §3.1 records the threat model and the source read of `fn-dsa-sign` 0.4.0. Every signature divides by key-derived values. The `div_emu` feature does not reach the tree's divisions. Neither device promises operand-independent division. BINSEC cannot model SSE2 floating point, which a new checkct probe shows, so no static verdict on the signer is possible.
- **FN-DSA's receipt countersignature is shown independent of the key's value, on every path (`CA-3` FN-DSA closed).** All three registered runs pass:

  | Device and path | Fixed pair | Nulls | Control |
  | --- | --- | --- | --- |
  | The 4 GB Pi 4, rule 176's floor | 2.90 | 2.77, 1.77 | 200.07 |
  | The maintainer's laptop, AVX2 | 1.71 | 2.28, 2.49 | 159.34 |
  | The same laptop, SSE2 | 1.85 | 2.25, 1.99 | 162.04 |

  Each excludes a dependence of 0.5 % of a signature or more. Two things the record discloses: the harness signs every entry from one working slot, after slot placement crossed the nulls in the shake-downs; and on the SSE2 path the wallet inlines `sign_inner`, though the sampler and the LDL decomposition are instruction-identical.
