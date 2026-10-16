# `BA-T33` floor arm: hybrid scheme 3 on the floor device, 2026-10-15

**State of this record: RUN COMPLETE, three sessions on 2026-10-15: 13:38Z
to 15:09Z; 16:22Z to 17:17Z for the `hold_key` arm; 20:19Z to 21:03Z for
the stack.** An
observation, not a registered test: no pass lines were set before the run,
and no constant budgets against these figures yet
([`FN_DSA_HYBRID.md`](../design/FN_DSA_HYBRID.md) `FND-10`). It closes
`FND-9` and `FND-12` and is `BA-T33`'s T3 arm
([`BENCHMARK_ALIGNMENT.md`](../design/BENCHMARK_ALIGNMENT.md)).

**In one paragraph.** On the floor device, Ed25519 + FN-DSA-1024 signs in
**2.24 ms** through the per-call entry and **1.70 ms** with the key held
across signatures, verifies in **0.57 ms**, and generates a seeded key in
**45.7 ms**. A whole persona slot's key derivation takes **466 ms**, of
which the receipt key is 9.8 %. The scheme-3 vectors, signing included,
give the pinned bytes on this hardware; until now that agreement was shown
only under emulation. Every step of both sessions exited 0, and the device
held 1.8 GHz on every core through the timed benches. Each scheme-3
operation needs the same stack on the floor as on the development host
optimized, and less unoptimized; a whole persona slot needs 8 KiB more
optimized and 4 KiB more unoptimized.

## What was run

Revision `4c3eb63446`, the commit that adds the ladder and the persona
arm, copied to the device as a `git archive` of that commit and checked by
checksum on both sides. Only `shekyl-crypto-pq` was built, once optimized
and once unoptimized, on the device. In order:

1. `cargo test --release -p shekyl-crypto-pq --no-fail-fast`: the whole
   crate, optimized.
2. `cargo test -p shekyl-crypto-pq --lib -- fn_dsa_hybrid seeded_rng
   heap_secret archival_p`, unoptimized, where the pinned stack bounds are
   tightest.
3. `cargo test -p shekyl-crypto-pq --test kat_fn_dsa_hybrid_v1 --test
   kat_archival_p_derive_v1 --test kat_hybrid_v2 --test
   kat_address_derivation_v2`, unoptimized.
4. `cargo bench -p shekyl-crypto-pq --bench fn_dsa_hybrid -- --noplot`,
   criterion's defaults, with the device's temperature and clocks sampled
   every 5 s throughout (`ba_t33_fn_dsa_floor_device_20261015_env.tsv`).

The second session ran at `7ccc42a7bc`, with the `hold_key` arm dropping
each signer outside its timed region:

5. `cargo bench -p shekyl-crypto-pq --bench fn_dsa_hybrid -- --noplot
   fn_dsa_hybrid_hold_key`, sampled the same way
   (`ba_t33_fn_dsa_floor_device_20261015_s2_env.tsv`).

The third ran at `81e612327a`, with the stack ladder in its final form
(§ Stack):

6. `fn_dsa_stack_ladder`, from the optimized and the unoptimized build
   (`ba_t33_fn_dsa_floor_device_20261015_s3_env.tsv`).

The first two sessions' scripts were rehearsed on the development host from
the same archive, in a dry mode with shorter criterion samples, and that
output was discarded; the third ran a subset of the second's rehearsed
steps.

## Conditions

| | |
| --- | --- |
| Device | The floor device (rule 76): Raspberry Pi 4 Model B, 4 cores, aarch64 |
| Toolchain | rustc 1.94.0, LLVM 21.1.8, `aarch64-unknown-linux-gnu` |
| Codegen | `RUSTFLAGS` and `CARGO_BUILD_RUSTFLAGS` unset; no cargo configuration file. The shipping configuration: no `target-cpu` |
| Governor | `ondemand` on every core |
| Clocks during the benches | 1.8 GHz on every core in all 23 samples of the first session and all 3 of the second |
| Temperature | First session: 49.7 °C at the start, 66.7 °C after the builds, 56.0 to 60.4 °C during the benches. Second: 49.2 °C at the start, 67.7 °C after the builds, 56.5 to 57.5 °C during the bench. Third: 50.1 °C at the start, 65.2 °C after the builds, 53.6 °C at the end |
| Throttle flags | Not read: `vcgencmd get_throttled` needs root there, and was refused |
| Resident | The testnet daemon, running throughout and not touched; nothing else of note. Load average 0.50 at the start, 0.8 to 1.5 during the ladder and benches |

## Vectors and tests

| Step | Result |
| --- | --- |
| Whole crate, optimized | 15 test binaries, 323 passed, 0 failed, 9 ignored |
| Scheme's unit set, unoptimized | 50 passed, 0 failed |
| Four vector files, unoptimized | 8 passed, 0 failed, 4 ignored (the armed regenerators) |

`kat_fn_dsa_hybrid_v1` passed in both profiles: seeded key generation,
**seeded signing** and verification give the pinned bytes on the device's
own floating point. `kat_archival_p_derive_v1` passed with the receipt-key
rows; `matches_rand_chacha_on_every_call_shape` passed.

`the_scheme_runs_on_a_small_stack` and `a_held_key_signs_on_a_small_stack`
passed in both profiles. On this device a passing stack test shows its
bound only where the bound is at least the thread minimum: Rust raises a
requested thread stack to the C library's minimum, which on aarch64 is
about 132 KiB (§ Stack). The 256 KiB, 512 KiB and 1 MiB bounds are above it
and hold. `a_held_key_signs_on_a_small_stack`'s 64 KiB optimized bound is
below it, so that test ran on about 132 KiB and cannot fail here; the
ladder measures the held sign at 12 KiB optimized on this device, within
the bound.

## Time

Criterion's estimate, then the spread of its 100 samples. Each sample
averages many calls, so the sample spread is not the spread of single
signatures: how often FN-DSA's rejection sampling retries a signature is
inside each sample's mean and is not shown here.

| Arm | Floor | Samples p10 / p50 / p90 | Development host, recorded |
| --- | --- | --- | --- |
| `fn_dsa_hybrid_sign` (per call) | **2.243 ms** | 2.208 / 2.226 / 2.276 ms | 442 µs (§9.1) |
| `fn_dsa_hybrid_sign_held` | **1.698 ms** | 1.676 / 1.689 / 1.756 ms | 411 µs (§9.1) |
| `fn_dsa_hybrid_hold_key` (one decode into a held key; second session) | **737 µs** | 695 / 730 / 740 µs | 52 µs (§9.1, wipe inside the timed region) |
| `fn_dsa_hybrid_verify` | **568 µs** | 566 / 567 / 569 µs | 58 µs (§3.1) |
| `fn_dsa_hybrid_keygen_from_seeds` | **45.68 ms** | 45.62 / 45.64 / 45.70 ms | 6.2 ms (§3.1) |
| `fn_dsa_hybrid_persona_slot_derivation` | **466.0 ms** | 464.7 / 464.9 / 468.2 ms | not recorded on an idle host |

The development-host figures are the ones `FN_DSA_HYBRID.md` records; that
host was shared and loaded on the day of this run, so it was not re-timed.

Holding the key saves 0.55 ms of each signature on the floor, 24 %, against
7 % on the development host, and holding it costs 0.74 ms once. The second
session's arm drops each signer outside the timed region; the first
session's, which dropped it inside, read 715 µs, so the wipe and release
of the held context are not where the time goes. A held sign plus one hold
(2.44 ms) still exceeds a per-call sign (2.24 ms): the per-call path
decodes into a context on its own stack and never allocates one.

## Stack

`fn_dsa_stack_ladder`, third session. A thread cannot be made small enough
to measure these directly on this device: Rust raises a requested thread
stack to the C library's minimum, and glibc's `PTHREAD_STACK_MIN` is 131,072
bytes on aarch64 against 16,384 on x86_64, plus a page and the thread-local
storage. So every measurement runs on an 8 MiB thread, and the budget under
test is what is left after burning stack down to it: a probe finds how deep
a frame can go, and then, from 4 KiB in 4 KiB steps, a child burns stack
until only the budget is left and runs the operation there. The first
budget that completes is the figure, good to about one step either way:
the budgets come in 4 KiB steps, and the probe's last printed depth leaves
some room below it that is not counted.

The figure is the stack the call itself consumes below its caller. Each
operation's inputs are made before the measuring thread starts and owned by
the operation on the heap, as the stake actor's keys are, and each child
makes only the inputs its operation reads. The development host's columns
are the same tool at the same revision.

| Operation | Floor, optimized | Floor, unoptimized | Dev host, optimized | Dev host, unoptimized |
| --- | --- | --- | --- | --- |
| `sign` (per call) | 240 KiB | 488 KiB | 240 KiB | 552 KiB |
| `hold_key` | 352 KiB | 472 KiB | 352 KiB | 532 KiB |
| `sign_held` | 12 KiB | 72 KiB | 12 KiB | 100 KiB |
| `verify` | 16 KiB | 32 KiB | 16 KiB | 48 KiB |
| `keygen` | 60 KiB | 296 KiB | 60 KiB | 348 KiB |
| `persona` (one slot) | 296 KiB | 736 KiB | 288 KiB | 732 KiB |

Optimized, every scheme-3 operation needs the same stack on the floor as on
the development host; unoptimized, each needs less. The whole persona slot
needs more on the floor, by 8 KiB optimized and 4 KiB unoptimized. Every
figure is far inside the 2 MiB threads the production callers run on: the
actor's runtime threads for a sign, the blocking pool's for a persona
derivation at engine assembly.

## The receipt key at engine assembly (`FND-12`)

One persona slot's derivation is 466 ms on the floor; the receipt key's
seeded generation is 45.7 ms of it, **9.8 %**, about a tenth of each slot.
The rest is the ML-KEM-768 and two ML-DSA-65 key generations and the HKDF
expands, not measured separately.

Engine assembly derives one full persona key set for every slot in the
bonded set and in the three slots from the cursor, one after another. The
slot set is `StakingBlock::derive_forward_slots`
(`rust/shekyl-engine-state/src/staking_block.rs:341-349`):

```rust
let cursor = self.monotone_current_slot_from_record();
let mut slots: BTreeSet<u32> = self.bonded_slots.iter().copied().collect();
for offset in 0..=lookahead {
    if let Some(slot) = cursor.checked_add(offset) {
        slots.insert(slot);
    }
}
```

called with `ARCHIVAL_PERSONA_LOOKAHEAD`, which is 2
(`rust/shekyl-engine-core/src/engine/stake_engine/types.rs:64`), so
`0..=lookahead` is the cursor and the two slots after it. Assembly adds the
first-stake intent slot and derives every slot in turn
(`rust/shekyl-engine-core/src/engine/lifecycle/assemble.rs:443-461`):

```rust
let mut slots = staking.derive_forward_slots(ARCHIVAL_PERSONA_LOOKAHEAD);
// ...
if let Some(intent) = first_stake_intent {
    slots.insert(intent.slot().to_raw());
}

let mut bundles = std::collections::BTreeMap::new();
for &slot in &slots {
    let keys = derive_archival_p_keys(master_seed, derivation_network, seed_format, slot)
```

For a staker with `k` bonded slots that is `k + 3` derivations, the intent
slot adding nothing when it is inside the lookahead. On the floor device a
staker's wallet open spends **(k + 3) × 466 ms** deriving persona keys:
**1.40 s with none bonded**, of which the receipt key is 45.7 ms per slot.
Only stakers pay it. The bond watch's probe window derives identity public
keys alone and does not pay it.

**An observation against the wallet-open budget.** The open-edge budget
WSS Round 1 ruled is 5 s absolute, local-daemon posture
(`docs/design/WALLET_SIDE_STORE.md`, decision log, 2026-09-19;
`docs/design/WSS_Q1B_BENCH_SPEC.md` §1, the quantity there being the held
buffer's refetch at open). On the floor device the persona derivation alone
reaches 5 s at about `k = 8` bonded slots: 11 × 466 ms = 5.13 s. The floor
device is the node-and-wallet floor, not the staker floor, which is not yet
set. [`FN_DSA_HYBRID.md`](../design/FN_DSA_HYBRID.md) `FND-25` records the
linear, sequential derivation as an open design question.

## What this does not show

- The spread of single signatures (above).
- A second session, or the device under a load other than its resident
  daemon.
- Whether the device throttled: the flag needs root. Every clock sample
  read 1.8 GHz, the maximum, during the benches.
