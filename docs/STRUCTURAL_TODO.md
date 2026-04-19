# Structural TODOs — shekyl-core

Open structural weaknesses in shekyl-core. Items tracked here survive
branch switches. Resolved items have been moved to
`docs/audit_trail/` (see `RESOLVED_260419.md` for the April 2026
sweep); git history is the authoritative archive of the code changes.

> **Framing note (April 2026).** Several decisions below cite "upstream
> Monero cherry-pick risk" as a constraint. The merge base with
> `monero/master` is June 2014, and upstream activity on the C/C++ files
> Shekyl inherited is effectively dormant (~3 substantive commits across
> 8 inherited files in the last 2 years; several files are 88-100%+
> diverged by line count). Shekyl is a cousin, not a downstream, of
> Monero. Decisions that weigh heavily on cherry-pick preservation
> should be re-examined on their own merits; the cost they assume is
> largely notional. See `docs/FOLLOWUPS.md` for the scheduled V3.2
> revisit of the `/FIiso646.h` workaround and the `rct::` → `ct::`
> rename, both of which rest on this premise.

---

## Language Standard Drift

### C++ alternative tokens (`not`, `and`, `or`) used extensively
Hundreds of call sites use `not` instead of `!`, `and` instead of `&&`,
etc. MSVC does not treat these as keywords by default. Current workaround:
`/FIiso646.h` in `CMAKE_CXX_FLAGS`. Long-term options:
1. Adopt `/permissive-` for full C++ conformance on MSVC.
2. Standardize on `!` / `&&` / `||` operators (large mechanical change).
3. Keep the `/FIiso646.h` workaround (simplest, but fragile).

**Decision (April 2026):** Keep option 3 (`/FIiso646.h`). The mechanical
change to replace hundreds of `not`/`and`/`or` sites is high-effort,
low-value, and historically cited upstream-cherry-pick risk as a
primary constraint. That constraint is largely notional (see framing
note above); the decision is scheduled for a V3.2 revisit on its own
merits, tracked in `docs/FOLLOWUPS.md` §"Re-examine `/FIiso646.h` and
`rct::` → `ct::` deferrals".

---

## Third-Party / Dependency Issues

### `libunbound` completely stubbed on MSVC
**Priority**: Medium — feature regression on Windows.
**Target**: V3.2 (pick one of the three options below).

`dns_utils.cpp` is wrapped in `#ifdef HAVE_DNS_UNBOUND` with no-op stubs
in the `#else` branch. This means wallet DNS resolution (OpenAlias
address lookup, DNS checkpoint fetching) silently does nothing on
MSVC/Windows builds. Options:

1. Port `libunbound` to vcpkg (it exists in some forks).
2. Implement a Windows-native DNS backend using `DnsQuery_A` /
   `DnsQueryEx`.
3. Accept the limitation — the GUI wallet may not need CLI-style DNS
   features, and Tor/I2P transports are independent of this.

Option 3 is the lowest-effort path and arguably the right call for
Shekyl's GUI-wallet-first posture, but the decision has not been
ratified. Defer to V3.2 for a design pass; whichever option wins, the
`#else` stubs should gain a comment that declares the contract
explicitly rather than silently returning empty strings.

### Replace easylogging++ with a maintained logger
**Priority**: Low — easylogging++ works, but is unmaintained upstream.
**Target**: V4 (or earlier if a concrete maintenance cost emerges).

All known MSVC issues in the vendored `external/easylogging++/` are
fixed (see `docs/audit_trail/RESOLVED_260419.md` §"easylogging++
vendored with no MSVC support"), but the library is unmaintained
upstream and any future portability issues will require local patches.
A migration to `spdlog` or another actively maintained logger is a
V4-scale project: every log call site in `src/` is touched, output
format compatibility needs to be preserved or explicitly changed, and
CI log-scraping tests (if any) need review. Track here so the cost of
not migrating stays visible.

### MSVC warnings in vendored dependencies
**Priority**: Low — external code, but worth tracking.
**Target**: V3.2 (address the dangling-pointer case; others are
cosmetic and may stay open).

MSVC CI reveals several warnings in vendored/external code:

- **`liblmdb/mdb.c:1745`** — C4172: returning address of local `buf`
  (dangling pointer — genuine bug, but in a debug-only code path).
  This one deserves an upstream bug report and a local patch if
  upstream is unresponsive.
- **`liblmdb/mdb.c:8417`** — C4333: right shift too large (data loss).
- **`liblmdb/mdb.c:939,7840`** — C4146: unsigned negation.
- **`easylogging++.cc:2576`** — C4333: right shift too large.
- **`randomx/blake2.h:82,84`** — C4804: bool used in division.

None are in hot paths for wallet-core. The `liblmdb` dangling pointer
is the only one with genuine correctness risk; the rest are warnings
MSVC raises on patterns other compilers accept silently. Patch
upstream where possible; otherwise, carry a local diff and note it in
`contrib/` or the relevant `external/` README.

### vcpkg builds take 45+ minutes — partially resolved
**Priority**: Low — CI timing is acceptable with warm caches.
**Target**: V3.3 (manifest-mode migration, if it happens).

Even with `actions/cache` for binary packages, the vcpkg install step
takes 45+ minutes on cold runs and 10-15 minutes on warm cache hits. A
root `vcpkg.json` manifest was attempted (April 2026) but broke MSVC
CI and was reverted; packages are listed explicitly in
`.github/workflows/build.yml`. A manifest-mode migration remains
possible but is low priority — CI timing is acceptable with warm
caches, and the explicit YAML list is easier to audit. No action
required unless CI times degrade or the package list grows
significantly.

---

## Test Surface

### Trezor test path still uses ring-signature test scaffolding
**Priority**: Low — test-only, but tangled with a real feature gap.
**Target**: Resolved as part of PQC Multisig V3.1 hardware wallet
integration (`docs/FOLLOWUPS.md`, currently TBD, code work deferred
to V3.2). Not independently actionable.

`tests/core_tests/wallet_tools.cpp::gen_tx_src` (lines 162-203) builds
ring-style source entries with fake decoy outputs (`bt.get_fake_outs`,
`real_output` index selection). The function itself carries a
`DEPRECATED` comment acknowledging incompatibility with FCMP++, but
it is genuinely live: `wallet_tools::fill_tx_sources`
(`wallet_tools.cpp:119`) calls it, and
`tests/trezor/trezor_tests.cpp:849` and `:1314` call
`wallet_tools::fill_tx_sources` with non-zero mixin
(`TREZOR_TEST_MIXIN`, `m_mixin`). The Trezor test suite also drives
builder-style `->mixin(num_mixin())` calls at ~13 additional sites in
the same file (lines 1664-1873).

This is not dead code. It's the seam where Shekyl's Trezor integration
continues to exercise the pre-FCMP++ transaction-construction model
because the real hardware-wallet path hasn't been ported to Shekyl's
actual model yet. Cleaning up the test scaffolding without first
landing real Trezor support against FCMP++ / V3.1 multisig produces a
test harness with no hardware target — worse than the current state.

Coupled deliberately to the hardware-wallet integration work in
`docs/FOLLOWUPS.md` §"PQC Multisig V3.1: hardware wallet integration".
When that lands, this `gen_tx_src` path and the Trezor test mixin
scaffolding go with it.

### Audit `tx_validation.cpp` non-zero-mixin tests
**Priority**: Audit — silent-pass tests are a known external-audit
finding class.
**Target**: V3.1 pre-audit (before the Phase 9 external security
audit kicks off).

Several tests in `tests/core_tests/tx_validation.cpp` pass `nmix = 1`
to `fill_tx_sources_and_destinations` — confirmed at line 546, and
lines 836/841/847 are explicitly commented as ring-signature-shaped
cases ("Tx with nmix = 1 without signatures" / "have not enough
signatures" / "have too many signatures"). Shekyl's transaction model
does not carry ring signatures, so these tests are one of three
things: (1) still exercising meaningful behavior under FCMP++
(unlikely given the comment framing), (2) silently bypassing the
mixin path and passing trivially, or (3) quietly broken since the
ring-signature purge and still green because the assertion they
claim to test is unreachable.

Needs a focused investigation:

1. Run the tests in isolation with verbose output; confirm they
   actually execute and what they assert.
2. Trace what `fill_tx_sources_and_destinations(..., nmix=1, ...)`
   produces today against Shekyl's transaction construction path —
   whether the extra source entries survive into a submittable tx,
   get rejected, or get silently dropped.
3. Classify each affected test as **delete** (tests behavior that
   doesn't exist), **rewrite** (tests a real invariant but in the
   wrong vocabulary), or **keep** (happens to exercise a real
   FCMP++-era path via the same call site).

This item is deliberately filed ahead of external audit rather than
after, because "tests that claim coverage but exercise nothing" is
exactly the finding an auditor will surface — better for it to land
as a self-identified fix in the audit-response branch than as an
audit finding.

---

## Naming / Code Clarity

### `rct_signatures` field name is a Monero-era misnomer — partially addressed
**Priority**: Low — cosmetic, but misleading.
**Target**: V4 (full namespace rename deferred; revisit for V3.2
scheduled in `docs/FOLLOWUPS.md`).

`transaction::rct_signatures` (typed `rct::rctSig`) no longer holds ring
signatures. In Shekyl v3, the only accepted types are `RCTTypeNull`
(coinbase) and `RCTTypeFcmpPlusPlusPqc`. The struct actually carries:

- **`rctSigBase`**: Pedersen commitments (`outPk`), HKDF-encrypted amounts
  (`enc_amounts`), `txnFee`, `referenceBlock` (curve tree anchor),
  `pseudoOuts`.
- **`rctSigPrunable`**: BP+ range proofs, the opaque FCMP++ membership
  proof, `curve_trees_tree_depth`.

All ring signature types (`RCTTypeFull`, `RCTTypeSimple`, `RCTTypeCLSAG`,
`RCTTypeBulletproof`, `RCTTypeBulletproofPlus`) are rejected at
deserialization. The name "rct" (Ring Confidential Transactions) is
misleading since the ring component no longer exists.

**Status (April 2026):** `using ct_signatures = rct::rctSig;` type alias
added in `cryptonote_basic.h`. New code should use `ct_signatures` for
the type. The full caller migration and `rct::` namespace rename to
`ct::` are deferred to V4. The rationale cited "end of Monero upstream
cherry-picks" as a trigger; per the framing note above that cost is
largely notional, and the decision is scheduled for a V3.2 revisit
tracked in `docs/FOLLOWUPS.md`.

The `rct::` namespace (`src/fcmp/rctTypes.h`, `rctOps.h`, `rctSigs.h`)
has the same problem — it was renamed from `ringct/` to `fcmp/` at the
directory level but retains the `rct::` namespace internally.

---

## Upstream Techniques to Track

Cross-references to Monero upstream PRs whose structural techniques are
relevant to items above. See
`shekyl-core/docs/COMPILING_DEBUGGING_TESTING.md` (upstream triage
section) for full status. See `FCMP_BUILD_PLAN.md` (formerly
`FCMP_MIGRATION_PLAN.md`) for the complete FCMP++ implementation plan.

- **Monero #10157 — Mempool input verification caching.**
  **Status: ✅ COMPLETE (Phase 4b).**
  `txpool_tx_meta_t` now stores a 32-byte `fcmp_verification_hash` and a
  1-bit `fcmp_verified` flag (carved from the 76-byte padding, now 44
  bytes). `compute_fcmp_verification_hash()` produces a deterministic
  cache key from `hash(proof || referenceBlock || key_images)`.
  `is_transaction_ready_to_go` seeds `m_input_cache` from the meta hash
  to skip `shekyl_fcmp_verify()` for previously-verified mempool txs.
  `static_assert`s at the `memcmp` site (tx_pool.cpp) enforce struct
  size and layout. Full FCMP++ verification pipeline (Phases 1-6)
  complete. See `docs/FCMP_PLUS_PLUS.md` in shekyl-core for the
  complete specification.
- **Monero #10084 — `wallet2_basic` library extraction.** Decomposes
  monolithic `wallet2` into minimal file-I/O types. Relevant to the
  MSVC ICE on `obj_blocks`/`obj_cncrypto` (smaller TUs sidestep ICEs)
  and to the wallet Rust migration (extracted types map to what needs
  Rust equivalents). Shekyl's parallel path is `wallet2_ffi.cpp`.
- **Monero #9801 — Rust in Guix reproducible builds.**
  **Status: 🔴 BLOCKING for reproducible release.**
  Three Rust crates now in the build (`shekyl-crypto-pq`, `shekyl-ffi`,
  `shekyl-fcmp`). Rust cross-arch builds are NOT bit-identical.
  x86_64-only build requirement for release artifacts. Key constraint:
  must be resolved before the Guix reproducible release pipeline can
  produce official binaries.
  See `FCMP_BUILD_PLAN.md` for the complete implementation plan.

---

*Last updated: 2026-04-19 — Swept resolved items to
`docs/audit_trail/RESOLVED_260419.md`. Closed the POSIX-header
consolidation item (migrated to `common/compat.h` + CI lint guard).
Versioned the remaining undecided structural items (libunbound
stubbing → V3.2; MSVC vendored-code warnings → V3.2; easylogging++
replacement → V4; vcpkg manifest-mode → V3.3). Kept the framing note
at the top; the "cousin, not downstream" posture underpins the V3.2
revisit of `/FIiso646.h` and the `rct::` rename tracked in
`docs/FOLLOWUPS.md`.*
