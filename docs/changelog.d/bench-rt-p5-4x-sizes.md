- **Benchmarks: RT-P5's message sizes are registered again on the 4.x
  wire.** The RPC channel's record size classes (`RPC_CHANNEL.md` §4.4,
  RT-O6) were derived from a trace of the 3.x wire, whose REST paths and
  method names the 4.0 rename replaced. A new registration
  (`docs/benchmarks/rt_p5_rpc_message_sizes_20261115.md`) measures the same
  generated wallet's traffic, under the same instrument, derivation rule,
  gates and determinism check, with its subjects named as 4.x methods
  (`tx_submit`, `block_show`, `chain_height`, `fee`) and seeds no earlier
  run used. It reports whether the trace's three-class table rounds to
  RT-O6's 512, 16,384 and 65,535, whether every request other than a
  submission is still at most 512 bytes, and the submission body's encoding,
  and leaves any change to the classes to the maintainer. The instrument
  reads the record constants from `shekyl-noise` instead of restating them,
  and the derivation script's tests check its copies against that crate. The
  2026-10-17 record is unchanged. **Measured 2026-11-16:** both registered
  runs passed and the determinism check passes; every request other than a
  submission is at most 197 bytes; the three-class rule now rounds to 512,
  4,096 and 65,535 against the ruled 16,384 middle class, and a submission's
  body is base64 (the padded submission's size already counts base64). Both
  findings are ruled: the middle class stays 16,384 until the mainnet reopen
  (the trace's block reads come from near-empty testnet blocks), and RT-O6
  part 2 now says base64, `66 + 4 × ⌈n / 3⌉`. This is the measurement
  RT-W12's gate names.
