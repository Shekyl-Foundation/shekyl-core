# CA-2 follow-up: RT-P4 on the i9-13900K desktop

The native x86_64 MSVC release build from `de9de2c9b5` used rustc 1.94.0,
the static CRT, and the locked fips203 0.5.0 dependency. The executable
SHA-256 was
`d5980c88db12a9eb65e6d979007cd40ce112f0fe1c8b32b45c2b8ea929d8b211`.

One million samples per comparison with seed `20261121`, as registered
for the CA-2 follow-up. The program labels this seed outside its own RT-P4
registration. The run took 651 seconds on 2026-11-25. The observer recorded
four quiet samples before launch, affinity 0x10, Normal priority, 64
sibling samples and exit 0. All 256 reference self-check cases agreed.
The message-class checks recorded no mismatches or unexpected accepts.

| Comparison | Desktop | Tiger Lake laptop | Floor Pi |
| --- | ---: | ---: | ---: |
| Valid vs invalid | 1.53 | 45.41 | 2.26 |
| Fixed vs bit flip | 2.96 | 10.98 | 1.66 |

The desktop's message-only line was 2.18. Its nulls were 1.91 and 1.55.
The planted 220 ns control reached 409.94. Both validity comparisons
were flat under the registered threshold of 4.5. The desktop therefore
did not reproduce the laptop's validity signal. This comparison does
not establish what caused the prior result.

The [raw result](ca2-desktop-rt-p4.txt) matches the observer's SHA-256
`8fbdf640a871da5249f237b441b819873a40fa6cf75c4e1a408eb24e27b8d506`.
The [laptop and floor results](../../../../benchmarks/rt_p4_mlkem_decaps_timing_20261121_message.md)
are the earlier captures.
