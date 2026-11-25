# CA-2 and RT-P4 follow-up on a second x86 CPU

The maintainer asked to collect the measurements on a physical Core
i9-13900K desktop and record discrepancies. The Tiger Lake workstation
has a reported failing core. Its DOITM, pinned-clock and turbostat follow-up
is removed from this PR's acceptance. Hardware failure is a possible
explanation for a workstation discrepancy. The desktop run can show
whether effects recur on this CPU and build. It cannot attribute a prior
result to a particular hardware fault. The existing RT-P4 acceptance stands.

## Run conditions

Run native Windows x86_64 MSVC with Rust 1.94.0 and static CRT from
`de9de2c9b5b06b5e69b53a504f6afb2f59c49303`. The platform differs from the
earlier Linux field measurements in both CPU and OS/compiler target.
The earlier RT-P4 laptop used MSVC on Tiger Lake. Keep the existing
desktop Balanced plan and Defender configuration. Pin at Normal priority
to logical CPU 4, a performance-core thread, and monitor its sibling,
logical CPU 5, with the CA-3 desktop quiet gate. Record the executable
hashes, measured affinity, counters and the exit of each run.

1. Run `ct-dynamic` at 1,000,000 batches per class in release and fat-LTO
   profiles. Leave the row filter empty so the controls and nulls are in
   the same invocation. Read the ordinary-release and fat-LTO halves,
   Montgomery-sparse rows, and comparison rows according to the
   [original registration](ca2-localisation-registration.md).
2. Run the RT-P4 example at 1,000,000 samples per comparison with the
   CA-2 seed `20261121`. The example labels this seed outside its own
   RT-P4 registration. It is the seed specified by CA-2's registration.
   Record both validity comparisons and the accompanying control, nulls
   and functional checks. Compare the validity rows with the existing
   Tiger Lake and Pi captures.

Use the original thresholds and rules for void, inconclusive, and
completed runs. Keep each result. A build or quiet-gate stop before
measurement leaves that run unmade.
