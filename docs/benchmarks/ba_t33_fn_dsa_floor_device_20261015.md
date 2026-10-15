# `BA-T33` floor arm: hybrid scheme 3 on the floor device, 2026-10-15

**State of this record: RUN COMPLETE, 2026-10-15 13:38Z to 15:09Z.** An
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
only under emulation. Every step of the run exited 0, the device held 1.8
GHz on every core through the timed benches, and no scheme-3 operation
needs more stack on aarch64 than the x86 ladder finds; a whole persona
slot's derivation needs slightly more, 16 KiB optimized and 8 KiB
unoptimized.

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
4. `fn_dsa_stack_ladder`, from the optimized and the unoptimized build.
5. `cargo bench -p shekyl-crypto-pq --bench fn_dsa_hybrid -- --noplot`,
   criterion's defaults, with the device's temperature and clocks sampled
   every 5 s throughout (`ba_t33_fn_dsa_floor_device_20261015_env.tsv`).

A rehearsal of the same script, from the same archive, ran on the
development host first (dry mode: shorter criterion samples, the crate's
unit tests in place of step 1); its output was discarded.

## Conditions

| | |
| --- | --- |
| Device | The floor device (rule 76): Raspberry Pi 4 Model B, 4 cores, aarch64 |
| Toolchain | rustc 1.94.0, LLVM 21.1.8, `aarch64-unknown-linux-gnu` |
| Codegen | `RUSTFLAGS` and `CARGO_BUILD_RUSTFLAGS` unset; no cargo configuration file. The shipping configuration: no `target-cpu` |
| Governor | `ondemand` on every core |
| Clocks during the benches | 1.8 GHz on every core in all 23 samples |
| Temperature | 49.7 °C at the start, 66.7 °C after the builds, 56.0 to 60.4 °C during the benches |
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
rows; `the_scheme_runs_on_a_small_stack` and
`a_held_key_signs_on_a_small_stack` passed in both profiles, so the bounds
they pin hold on aarch64; `matches_rand_chacha_on_every_call_shape` passed.

## Time

Criterion's estimate, then the spread of its 100 samples. Each sample
averages many calls, so the sample spread is not the spread of single
signatures: how often FN-DSA's rejection sampling retries a signature is
inside each sample's mean and is not shown here.

| Arm | Floor | Samples p10 / p50 / p90 | Development host, recorded |
| --- | --- | --- | --- |
| `fn_dsa_hybrid_sign` (per call) | **2.243 ms** | 2.208 / 2.226 / 2.276 ms | 442 µs (§9.1) |
| `fn_dsa_hybrid_sign_held` | **1.698 ms** | 1.676 / 1.689 / 1.756 ms | 411 µs (§9.1) |
| `fn_dsa_hybrid_hold_key` (one decode) | **715 µs** | 703 / 705 / 721 µs | 52 µs (§9.1) |
| `fn_dsa_hybrid_verify` | **568 µs** | 566 / 567 / 569 µs | 58 µs (§3.1) |
| `fn_dsa_hybrid_keygen_from_seeds` | **45.68 ms** | 45.62 / 45.64 / 45.70 ms | 6.2 ms (§3.1) |
| `fn_dsa_hybrid_persona_slot_derivation` | **466.0 ms** | 464.7 / 464.9 / 468.2 ms | not recorded on an idle host |

The development-host figures are the ones `FN_DSA_HYBRID.md` records; that
host was shared and loaded on the day of this run, so it was not re-timed.

Holding the key saves 0.55 ms of each signature on the floor, 24 %, against
7 % on the development host, and the decode it moves out of the loop costs
0.72 ms once.

## Stack

`fn_dsa_stack_ladder`: the smallest thread stack, in 8 KiB steps from
16 KiB, on which the operation completes, so each figure is an upper bound
within one step. The development host's column is the same tool at the
same revision, from the rehearsal.

| Operation | Floor, optimized | Floor, unoptimized | Dev host, optimized | Dev host, unoptimized |
| --- | --- | --- | --- | --- |
| `sign` (per call) | 256 KiB | 504 KiB | 256 KiB | 568 KiB |
| `hold_key` | 368 KiB | 488 KiB | 368 KiB | 552 KiB |
| `sign_held` | 16 KiB | 16 KiB | 32 KiB | 120 KiB |
| `verify` | 16 KiB | 16 KiB | 32 KiB | 64 KiB |
| `keygen` | 16 KiB | 312 KiB | 80 KiB | 360 KiB |
| `persona` (one slot) | 320 KiB | 752 KiB | 304 KiB | 744 KiB |

16 KiB is the ladder's first rung. The floor needs no more than the
development host for any scheme-3 operation. The whole persona slot needs
more in both profiles, by 16 KiB optimized and 8 KiB unoptimized; that
derivation runs at engine assembly, inside the blocking pool's 2 MiB
threads.

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
set.

## What this does not show

- The spread of single signatures (above).
- A second session, or the device under a load other than its resident
  daemon.
- Whether the device throttled: the flag needs root. Every clock sample
  read 1.8 GHz, the maximum, during the benches.
