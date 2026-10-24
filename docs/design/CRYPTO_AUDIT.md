# Crypto audit — advisories and audit findings against the cryptographic stack

**Status:** OPEN — register opened 2026-10-24 (family `CA-`, registered at
birth in [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2). `CA-1` is
ignored in `cargo audit` by ruling (Rick, 2026-10-24); its long-term fix is
not yet designed.

One row per advisory or audit finding that touches a cryptographic
dependency or primitive and cannot be closed by a routine lockfile bump. A
row records what is affected, where secrets meet it, why it is not fixed
now, and what reopens it. A finding a bump clears does not get a row; the
bump's commit is its record.

## Register

| Id | Finding | Status |
| --- | --- | --- |
| `CA-1` | `crypto-bigint` 0.5.5, RUSTSEC-2026-0387 (timing variability) | **IGNORED BY RULING 2026-10-24** — fix undesigned (§1) |

## 1. `CA-1` — crypto-bigint 0.5.5, RUSTSEC-2026-0387

**Advisory.** Published 2026-10-23, category `crypto-failure`. Operations
meant to be constant-time could execute secret-dependent branches,
depending on compiler and target: subtraction, zero counting, division,
Montgomery multiplication. Patched only in 0.7.6. The advisory lists no
affected functions, so it covers every 0.5.x release.

**Consumers in `rust/Cargo.lock`.** `dalek-ff-group` 0.4.6 and 0.5.0
(crates.io, serai), `elliptic-curve` 0.13.8 and `minimal-ed448` 0.4.2 (both
via `ciphersuite` 0.4.2), and our `helioselene`, `ec-divisors` (vendored
`shekyl-oxide`) and `shekyl-curve-generators`.

**Where secrets meet it.** `helioselene::Field25519` is
`dalek_ff_group::FieldElement`, whose arithmetic is crypto-bigint's
`Residue` (Montgomery mul/sub). `Field25519` is the Ed25519 base field (the
coordinates of the output being spent) and Selene's scalar field (that
layer's blinds), so it carries the FCMP++ prover's secret witness on the
wallet. The adversary is a co-located timing or microarchitectural observer
of the proving machine. The daemon only verifies, on public data.

**What is not known.** Whether 0.5.5 compiles to the leaking branches is
unmeasured. Upstream's fixes (crypto-bigint #1358, #1360) target 0.7's code;
#1358's leak came from a 2025 workaround that 0.5.5 predates. No
`cargo checkct` run exists against 0.5.5.

**Why it is not fixed now.** No released `dalek-ff-group` or `ciphersuite`
uses crypto-bigint 0.7 (latest 0.5.0 / 0.4.2 as of 2026-10-24; serai
`develop` is still on 0.5), and the vendored crates sit on that stack.
Clearing it means owning a fork of the serai curve stack ported to 0.7, with
every pinned FCMP++ and curve-tree vector held byte-identical.

**Disposition.** `RUSTSEC-2026-0387` is in the `ignore` list of
[`rust/.cargo/audit.toml`](../../rust/.cargo/audit.toml), whose block
repeats the consumers and the reopen criteria. The fix is one pre-genesis
row in [`FOLLOWUPS.md`](../FOLLOWUPS.md).

**Reopen when any of:**

1. serai publishes `dalek-ff-group` / `ciphersuite` on crypto-bigint
   >= 0.7.6 — bump and drop the ignore;
2. the fork-and-port is scheduled — drop the ignore in that PR;
3. a `cargo checkct` run shows 0.5.5's `Residue` mul/sub/invert branching
   on x86_64 or aarch64 — the fork becomes blocking for the next release.
