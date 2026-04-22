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
- **`randomx/blake2.h:82,84`** — C4804: bool used in division.

None are in hot paths for wallet-core. The `liblmdb` dangling pointer
is the only one with genuine correctness risk; the rest are warnings
MSVC raises on patterns other compilers accept silently. Patch
upstream where possible; otherwise, carry a local diff and note it in
`contrib/` or the relevant `external/` README.

### 32-bit targets cannot safely run Shekyl, and the wider "bit-width carve-out without coverage" pattern
**Priority**: **High** — the 32-bit branches of the PQC pair
(`ml-kem` / `ml-dsa`) and the `slow-hash.c` PoW fallback are both
security-bearing, and "it compiles" does not imply "the constant-time
proof still holds." Dormant platform-gated code with no CI coverage
is the single most-likely source of CI-green shipped regressions in
this project.
**Target**: V3.2 (Chore #3 — retire every 32-bit target in one chore).
V3.x alpha.0 (current Chore #2) covers only the awareness entry and
the one one-line CI-green repair that exposed it.

**The security argument (the real reason, April 2026).** Shekyl's
wallet and daemon link `fips203` (ML-KEM-768) and a ML-DSA-65
implementation for the V3.1 PQC-hybrid KEM and post-quantum multisig
primitives. Both crates achieve their *constant-time* guarantee — the
property their security proofs actually require — by performing
polynomial arithmetic in `Z_q` (`q = 3329`) with `u64` operands. That
is a LLVM/GCC-assumption about the target: on any 64-bit ISA `u64` is
a single register-width op; on a 32-bit ISA the compiler lowers every
`u64` operation into a pair of 32-bit ops plus a carry-propagation
branch, and the carry path is operand-dependent. That's a
**constant-time violation introduced by the code generator**, not
the source code. The `fips203` author has no obligation to make the
32-bit lowering constant-time, and from the crate's structure there
is no evidence it has been audited for that property.

This is not theoretical. The published work on Kyber / ML-KEM timing
attacks on Cortex-M4 (2022-2024) demonstrates full secret-key
recovery from the exact kind of variable-time carry propagation that
the 32-bit lowering introduces. In the concrete Shekyl deployment
story, "32-bit wallet user" equals "wallet private key is
potentially extractable by any attacker who can measure operation
timing." On a network-connected wallet that attacker set is much
larger than "physical access" — it's anyone who can observe
request/response timing against the wallet's RPC surface.

ML-DSA-65 is the same failure mode with a larger timing surface:
signing is heavier than KEM operations, and the rejection-sampling
loop adds variable iteration counts that poorly-tuned 32-bit
implementations handle inconsistently. Bare-metal Cortex-M4 signing
with hand-tuned assembly sits at 50-200 ms per signature; a Pi Zero
(ARMv6, no NEON, no hand-tuned ASM) is measured in multiple seconds
per signature — producing both a user-visible UX failure (a wallet
nobody can transact with) and a much larger measurement window for
the timing-side-channel attacker.

**The X25519 half of the hybrid does not save us.** `curve25519-dalek`
has well-audited 32-bit constant-time implementations, so the
X25519 branch of the hybrid KEM is correct on 32-bit. The canonical
"hybrid is secure if either half is secure" framing does *not*
apply to side-channel breaks: if ML-KEM leaks its secret via timing,
the attacker recovers the ML-KEM shared secret, captures ciphertext,
and then has unlimited offline time to attack X25519. Hybrid
protects against algorithmic-break compromise of one component; it
does not protect against a side-channel compromise of one component.
On a 32-bit target, the ML-KEM half is the precise side-channel
compromise the hybrid construction was not designed to absorb.

**FCMP++ and BP+ on 32-bit are almost certainly also broken.** Proof
generation involves the prover's secret blinding factors moving
through curve operations and inner-product arguments; the
constant-time requirements on that path are real. Verification
(multi-scalar multiplication on public inputs) is performance-
sensitive but not directly timing-sensitive. The Rust Bulletproofs
ecosystem targets 64-bit; 32-bit constant-time guarantees are not
in any threat model anyone has tested for. Running Shekyl's
prover on a 32-bit target combines an untested constant-time
posture with multi-second proof-generation times on the inherited
PoW fallback path.

**Even setting cryptography aside: LMDB storage on 32-bit cannot
sync the chain safely.** `MDB_VL32` exists because 32-bit address
spaces cannot memory-map a multi-GB blockchain database. The mode
pages portions of the database in and out as needed; this is a
materially different storage path with a different bug profile
than the 64-bit `mmap-everything` strategy, and no CI runner has
ever exercised it against a real chain. Paired with multi-second
PQC verification per block, a 32-bit daemon's sync time from
genesis is measured in weeks at best. That is not a supported
posture.

**The right framing is therefore not "ARM32 is a relic, we can
drop it."** The right framing is: **32-bit Shekyl wallet users
are at meaningfully elevated risk of key extraction compared to
64-bit users, and the supported-platform claim on a 32-bit Shekyl
build is a tacit lie about the security posture of the user.**
For a privacy coin, that is the precise opposite of the value
proposition. "We dropped 32-bit because it was insecure for our
use case" is the CHANGELOG line an external auditor reads and
respects; "we dropped 32-bit because no one ran it" is the line an
auditor marks as a user-harm event we shipped and later noticed.

**What happened mechanically during Chore #2 (the CI crumb that
surfaced this).** CI run
[`24720803048`](https://github.com/Shekyl-Foundation/shekyl-core/actions/runs/24720803048)
failed on MSYS2 x86_64 with `error: 'FSCTL_SET_COMPRESSION' was
not declared in this scope` in `src/blockchain_db/lmdb/db_lmdb.cpp`.
The initial diagnosis pointed at a `if(NOT BUILD_64)` guard in the
root `CMakeLists.txt` that restricted `-D_WIN32_WINNT=0x0600` to
32-bit MinGW; that diagnosis turned out to be wrong.
`FSCTL_SET_COMPRESSION` is unconditional in mingw-w64's
`<winioctl.h>` (line 1478 of upstream
`mingw-w64-headers/include/winioctl.h`), so no `_WIN32_WINNT` tier
change can affect its visibility. The actual root cause was
include-order: with `easylogging++` retired, the TU's first
transitive `<windows.h>` exposure ran through
`<boost/filesystem.hpp>`; with `WIN32_LEAN_AND_MEAN` set
project-wide (via `MINGW_FLAG`) boost opens the `_WINDOWS_` guard
without pulling `<winioctl.h>`, and our subsequent `#include
<winioctl.h>` then processes in a context where the full
`<windows.h>` vocabulary isn't staged in the expected order. Commit
`070447f5b` chased the wrong symbol; commit `9284d781d` reverts it
and moves the `#ifdef WIN32` / `<windows.h>` / `<winioctl.h>`
block to the top of `db_lmdb.cpp`'s include list, ahead of
everything that could pre-open `<windows.h>`. The include-order fix
is what actually unblocks MSYS2 CI.

**The pattern this exposes (independent of which fix is the real
one).** The 32-bit path is an explicit knob. The 64-bit path runs
on luck, and nobody notices for years because CI only builds
64-bit. Same disease as the `ringct` naming deception a few
sections up: dormant branches of conditional code that look benign
until the invariants they silently assumed change underneath them.

This same "carve-out without coverage" antipattern shows up in at
least eight places in the tree, none of which have CI coverage on
the narrow side:

| Site | Gated branch | Severity under PQC argument |
| --- | --- | --- |
| `external/db_drivers/liblmdb/CMakeLists.txt:49` | `MDB_VL32` when `ARCH_WIDTH == 32` | **Consensus-adjacent storage.** Materially different blockchain-storage path, never exercised by any CI runner. Sync against live block data on any 32-bit target hits this code first. Delete with Chore #3. |
| `src/crypto/slow-hash.c:374, 421` | CryptonightR AES-NI gated on `__x86_64__ \|\| (_MSC_VER && _WIN64)`; 32-bit software fallback active otherwise | **Consensus-adjacent PoW.** The 32-bit software fallback is PoW verification code. Any 32-bit miner hashing against the network runs an untested consensus-adjacent path against live block hashes. Delete with Chore #3. |
| `src/blockchain_utilities/blockchain_import.cpp:64` | `#if ARCH_WIDTH != 32` branches default `db_batch_size` | Recoverability UX. 32-bit users bootstrapping hit an untested batch-size path; failure mode is silent (slow import, no crash). Delete with Chore #3. |
| `CMakeLists.txt:1352` | `libatomic` link pulled on `Clang AND ARCH_WIDTH==32 AND !IOS AND !FREEBSD` | Build-only, untested. Delete with Chore #3 as dead scaffolding. |
| `tests/hash/main.cpp:192, 206` | `sqrt_result` inline-asm under the same 64-bit guard | Test-only. Hazard is inverted: the test is width-gated away from exercising the production path it should be covering. Delete with Chore #3 (the 32-bit branch) or with `slow-hash.c` retirement. |
| `contrib/depends/packages/unbound.mk:18` | `cflags_mingw32+="-D_WIN32_WINNT=0x600"` | Inconsistency + uncovered. Note: `0x600` and `0x0600` evaluate to the same integer in preprocessor arithmetic, so it is not a numerical bug — but it is an asymmetry the `mingw64` depends path doesn't mirror, the exact same carve-out-without-coverage shape as the root-CMake bug, mirrored into the depends layer. Delete entire `_cflags_mingw32` line under Chore #3 since the `mingw32` host is going away. |
| `contrib/depends/packages/{boost,openssl}.mk` | Separate `i686_mingw32` / `x86_64_mingw32` config variants | Build-only; parallel config paths, one CI runner. Delete the `i686_mingw32` variants under Chore #3. |
| `contrib/gitian/gitian-win.yml:26-30`, `Makefile:{84,159}` (`release-static-win32`, `debug-static-win32`), `cmake/32-bit-toolchain.cmake`, `contrib/depends/README.md:31`, **plus the ARM32 siblings** `release-static-armv7`, `release-static-armv6`, `release-static-android-armv7` | Entire `i686-w64-mingw32` + ARM32 target set | Advertised build targets with no CI runners and no release workflow shipping binaries. Delete with Chore #3. |

Note the pattern within the pattern: the `unbound.mk` line and the
root-CMake `FSCTL_SET_COMPRESSION` misdirect are the *same* disease
mirrored into two different build layers — an architecture-
specific directive defined for one width and silently absent for
the other, with the "working" side running on whatever transitive
includes and toolchain defaults happen to hold that week. Both are
invisible precisely because the gated side has no CI. A workaround
whose only purpose is to execute on an untested path is, by
construction, invisible when it breaks.

**Market-reality context (researched April 2026, supporting
evidence).** Windows 11 is 64-bit only; no 32-bit Windows 11 was
ever shipped. Windows 10 entered end-of-life October 14, 2025. Per
Statcounter (March 2026), Windows 11 holds 67.1% of desktop
Windows share and Windows 10 31.3%. Within the Win10 slice the
32-bit subvariant is 0.01% of Steam Hardware Survey respondents
(August 2025). Valve drops Steam 32-bit Windows January 1, 2026;
Mozilla drops Firefox 32-bit Windows in 2026. The combined
`i686-w64-mingw32` + ARM32 user base in 2026 is not the driver of
this decision, but it closes the "who does this harm by removing"
question.

**Chore sequencing (explicit, to keep blast radii bounded).**

- **Chore #2 (V3.x alpha.0 / current branch)** — `easylogging++`
  retirement + Rust FFI bridge. Includes the include-order fix in
  `db_lmdb.cpp` (commit `9284d781d`) and the revert of the
  misdiagnosed CMake change (same commit). *No other platform
  cleanup is in Chore #2.* Keeping Chore #2 scoped matters: it is
  already a large diff (FFI, vendor deletion, env-var sweep,
  format break, daemon default sink), and bolting platform-
  retirement work onto it makes the diff harder to review and the
  revert harder if either piece breaks. The discovery happens in
  Chore #2; the cleanup is Chore #3.

- **Chore #3 (V3.2) — retire every 32-bit target.** One combined
  chore. The PQC security argument makes the Windows and ARM32
  retirements symmetric and concurrent; there is no principled
  reason to split them. Concretely:
  - Delete `cmake/32-bit-toolchain.cmake`.
  - Delete `Makefile` targets `release-static-win32`,
    `debug-static-win32`, `release-static-armv7`,
    `release-static-armv6`, `release-static-android-armv7` (and any
    `-v4` variants).
  - Delete the `i686-w64-mingw32-*` alternatives block in
    `contrib/gitian/gitian-win.yml`.
  - Delete `_config_opts_i686_mingw32`, `_config_opts_mingw32`
    (where purely 32-bit), the `_cflags_mingw32` line in
    `contrib/depends/packages/unbound.mk`, and the `i686_mingw32`
    variants in the other `contrib/depends/packages/*.mk`.
  - Delete `MDB_VL32` from `external/db_drivers/liblmdb/CMakeLists.txt`.
  - Delete the CryptonightR 32-bit software fallback in
    `src/crypto/slow-hash.c:374, 421` and the paired inline-asm
    guard in `tests/hash/main.cpp:192, 206`.
  - Delete the `#if ARCH_WIDTH != 32` default-`db_batch_size`
    branch in `src/blockchain_utilities/blockchain_import.cpp:64`
    (collapse to the 64-bit default).
  - Delete the Clang + `ARCH_WIDTH==32` `libatomic` pull at
    `CMakeLists.txt:1352`.
  - Collapse `BUILD_64` / `ARCH_WIDTH` / `BUILD_WIDTH` to
    unconditionally-true and *remove the conditionals entirely*.
    This is ~few-hundred lines of mechanical `#if` removal, and
    doing it in the same chore is essential: leaving dead
    `#if ARCH_WIDTH == 64` around is itself the same inherited-
    correctness disease this entry diagnoses — the next person to
    touch the tree will assume the gated alternative is meaningful
    and start reasoning about it.
  - Strip the Win32 and ARM32 paragraphs from `README.md`,
    `docs/INSTALLATION_GUIDE.md:154`, `contrib/depends/README.md`.
  - **CHANGELOG lead.** The `docs/CHANGELOG.md` V3.2 entry must
    lead with the security argument, not the maintenance
    argument. Suggested first paragraph: *"Shekyl no longer
    supports 32-bit targets. ML-KEM-768 and ML-DSA-65
    implementations rely on 64-bit arithmetic for their
    constant-time guarantees; on 32-bit targets, the compiler
    decomposes 64-bit operations into variable-time 32-bit
    sequences, opening a timing-attack surface that can lead to
    wallet key recovery. This affects all 32-bit ARM, x86, and
    embedded targets. Users on 32-bit hardware should not run
    Shekyl wallets. The `i686-w64-mingw32`, `release-static-armv6`,
    `release-static-armv7`, and `release-static-android-armv7`
    build targets have been removed. ARM64, x86-64, and Apple
    Silicon are the supported architectures."*
  - Precedent: V3.0's `i686-linux-gnu` retirement, see
    `docs/audit_trail/RESOLVED_260419.md` §"Dead `i686_linux_*`
    target in `contrib/depends/hosts/linux.mk`".

- **Chore #4 (V4 pre-audit) — platform-gate audit sweep.** Now
  smaller in scope because Chore #3 eliminates the worst offenders.
  A systematic pass over every `#if`, `#ifdef`, CMake `if()`, and
  Makefile conditional that gates on a platform predicate that
  *still exists* after Chore #3 — principally `__APPLE__`,
  `__ANDROID__`, `_MSC_VER`, `__FreeBSD__`, `BSD`, `__linux__`,
  plus any residual host-triple patterns in `contrib/depends/`.
  Produces a coverage report with three columns — site, claimed
  platform, CI-covered y/n — and classifies each row as **delete**
  (platform not actually claimed), **CI add** (claimed and about
  to be tested), or **document-as-unverified** (claimed but
  deliberately unverified, with explicit severity and target
  version here). Highest-value audit-defensibility deliverable
  before the V4 external audit; worth doing once, well. Target:
  V4 pre-audit.

**Migration-on-touch rubric (active immediately, for reviewers
encountering similar guards):** any of the following sites in a
PR outside Chore #3's scope is a review-time red flag equivalent
to a `ringct` sighting:

- `if(NOT BUILD_64)` / `if(BUILD_64)` in CMake.
- `#if ARCH_WIDTH != 32` / `#if ARCH_WIDTH == 32` / `#if
  ARCH_WIDTH == 64` in C/C++.
- `#if !defined(__x86_64__) && !defined(_WIN64)` guarding hot /
  PoW / consensus-adjacent / cryptographic paths.
- Any `contrib/depends/packages/*.mk` line containing `_i686_` /
  `_mingw32` / `_armv7` config variants.
- Any new `#ifdef` / CMake conditional gating a workaround on a
  platform that isn't in `.github/workflows/build.yml` or
  `depends.yml`'s active matrix.

Reviewer default: reject or require the author to either prove
CI coverage for the gated branch, add coverage, or route the
change through Chore #3 / #4 with an explicit entry here.

Cross-refs:

- Chore scheduling in `docs/FOLLOWUPS.md`.
- Precedent: `i686-linux-gnu` retirement in V3.0,
  `docs/audit_trail/RESOLVED_260419.md` §"Dead `i686_linux_*`
  target in `contrib/depends/hosts/linux.mk`".
- User-facing safety callouts pointing here:
  `README.md` §"Building on Windows", `docs/INSTALLATION_GUIDE.md`,
  `docs/USER_GUIDE.md` §"System requirements".
- Commits: `070447f5b` (misdiagnosis, reverted), `9284d781d`
  (include-order fix + revert — the actual CI repair).

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

**Deception observed (April 2026):** during the `chore/cxx-logging-
consolidation` work we nearly shipped a `make ringct` comment in the
`utils/health/clang-*-run.sh` smoke recipes as a "quick testing: build
a single target" example. `ringct` is no longer a real target (the
directory was renamed to `fcmp/` and the CMake object library is
`obj_fcmp` / `fcmp`), but the name still reads as current Shekyl
vocabulary to anyone skimming — exactly the confusion this
structural-debt entry exists to retire. The recipes now name `common`,
which is real. Every further `ringct` / `rct::` sighting in fresh
documentation, comments, or build scaffolding should be treated the
same way: it is Monero-era deadweight masquerading as current naming
and needs renaming-on-touch under rule 93.

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
stubbing → V3.2; MSVC vendored-code warnings → V3.2; vcpkg
manifest-mode → V3.3). Kept the framing note at the top; the
"cousin, not downstream" posture underpins the V3.2 revisit of
`/FIiso646.h` and the `rct::` rename tracked in
`docs/FOLLOWUPS.md`.*

*Last updated: 2026-04-21 — Closed the easylogging++ replacement
item. Chore #2 (C++ shim + vendor retirement + `MONERO_LOGS` /
`MONERO_LOG_FORMAT` retirement) landed on
`chore/cxx-logging-consolidation`; full closure narrative
(including the known V3.x alpha.0 format-break and
`MLOG_SET_THREAD_NAME` no-op regressions) is in
`docs/audit_trail/RESOLVED_260419.md` under "Replace easylogging++
with a maintained logger (Chore #1 + Chore #2)".*
