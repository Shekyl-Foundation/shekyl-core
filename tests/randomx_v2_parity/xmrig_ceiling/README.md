# XMRig-ceiling hash-core differential (RandomX v2, Phase 0)

Discharges the runtime task in
[`docs/design/RANDOMX_V2_MINING_ASYMMETRY.md`](../../../docs/design/RANDOMX_V2_MINING_ASYMMETRY.md)
§3.2: prove that the hash **an adversary's miner produces** is byte-identical to the
hash **Shekyl validates**, so the ceiling leg measures a real ceiling and not noise.

## What it does

Links **XMRig 6.26.0's actual RandomX sources** (the miner an attacker runs) against a
minimal honest support layer, applies XMRig's `RandomX_ConfigurationMoneroV2` (its `rx/2`
config), and compares its `randomx_calculate_hash` output to Shekyl's committed
`CANONICAL_RANDOM_HASHES` over the shared 1024-vector corpus (`parity_corpus.dat`).

`support.cpp` supplies the few XMRig base-library symbols the RandomX layer calls
(`Cpu::info`, `VirtualMemory`, `Chrono`, `uv_hrtime`, the `rx_blake2b*` dispatch pointers).
These are provided honestly and are **hash-irrelevant**: memory-allocation method, timing,
and (per RandomX's own invariant) software-vs-hardware AES do not change the hash value.
The build is proven faithful by `--rx0` reproducing the published RandomX v1 reference
vector exactly.

## Result (2026-07-06)

| Check | Result |
|-------|--------|
| `--rx0` (published rx/0 v1 vector, build-faithfulness) | `639183aa…` **exact** |
| `--kat-full` (v2 KAT, **full dataset** = mining mode) | `34f8b017…` == Shekyl canonical KAT |
| full corpus, **full dataset** | **1024 / 1024 byte-identical, 0 mismatches** |
| `--kat` (v2 KAT, **light** verification mode) | `2fe105f9…` **≠** canonical — see caveat |

**Conclusion:** stock XMRig 6.26.0 on algorithm `rx/2`, full-dataset (mining) mode,
produces byte-identical hashes to what Shekyl validates. The ceiling-artifact decision is
**stock XMRig, no patch**.

### Load-bearing caveat (why the *mode* matters)

XMRig's **light / verification** path is v2-**incomplete**: its interpreter applies only
`Tweak_V2_PREFETCH`, and the other three v2 tweaks (`AES`/`CFROUND`/`COMMITMENT`) exist
only in its JIT — so XMRig's own light result diverges from its full-dataset result
(`2fe105f9…` vs `34f8b017…`). This is harmless for the ceiling (adversaries mine with the
full dataset) but it is exactly the trap the plan's "constant identity is necessary, not
sufficient" stance warned about: the §3.1 constants all matched, yet testing XMRig's light
path would have produced a **false divergence**. Only the full-dataset (adversary) mode
proves equivalence. Always compare against XMRig's **full-dataset** hash.

## Provenance

- **XMRig**: `/home/torvaldsl/shekyl/xmrig` @ `b2ca7248` (v6.26.0).
- **Fork / canonical**: `external/randomx-v2` @ `aaafe71` (v2.0.1); pins in
  `rust/shekyl-randomx-differential/src/canonical_outputs.rs`, carried to C++ via
  `parity_corpus.dat` (SHA-256 `713d5702…03ba`, = `PARITY_CORPUS_FILE_SHA256`).
- **Build**: g++/gcc 14.2 (Debian), `-O2 -std=c++17`, `-DXMRIG_FEATURE_ASM`, x86-64 JIT,
  software AES, Argon2 generic arch.
- **Host**: dev box `i9-11950H` (hash correctness is hardware-independent, so the dev box
  is valid here — unlike the *timing* measurements of Phase 1, which are not).

## Reproduce

```bash
XMRIG_DIR=/home/torvaldsl/shekyl/xmrig ./build.sh
./xmrig_parity --rx0        # must print the v1 reference vector (build faithful)
./xmrig_parity --kat-full   # must equal 34f8b017…
./xmrig_parity /path/to/parity_corpus.dat   # 1024/1024, full-dataset (~15 min, 32× 2 GiB inits)
```

## Status & licensing

Reference harness, **not a CI gate** — it requires a local XMRig clone, so wiring it into
CI would be a gate that cannot fire without that external input. If a pinned XMRig is ever
vendored for CI, this becomes wireable; until then the committed result above plus this
reproducible build are the record.

**Licensing:** these source files are authored by The Shekyl Foundation and are
**BSD-3-Clause**, like the rest of the repo. XMRig is **not** vendored or distributed here —
`build.sh` links a local clone via `XMRIG_DIR`. The *built binary* is GPLv3 by linkage and
is dev-only; it is not distributed.
