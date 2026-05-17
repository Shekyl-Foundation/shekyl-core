# C++ inheritance inventory

Canonical per-file disposition for the inherited C++ cryptographic surface
under `src/crypto/` and `src/fcmp/`. Surfaced by Phase 0 Mission Audit Lens F
(rule [`30-cryptography.mdc`](../.cursor/rules/30-cryptography.mdc)) as the
artifact gating the post-genesis C++ deletion sweep. Read this document
when:

- Performing a C++ deletion sweep and you need to know what's left after
  each pre-genesis workstream lands.
- Auditing the inherited cryptographic surface and you need per-file
  disposition without re-deriving it from `git log`.
- Onboarding a maintainer who needs to understand why specific
  pre-CryptoNote / pre-Monero code remains in `src/crypto/` after the
  Shekyl-first migration is complete.

When the Phase 0 Mission Audit doc references this inventory, this
document is the source of truth for what's where and why. Future audits
update this inventory directly rather than re-deriving the categorization
from source inspection.

## Update protocol

This document updates when:

1. **A workstream lands that changes a file's category** (e.g., the
   A-4/A-5/A-7/A-8 PoW workstream deletes the F.C++-1 set; the B-3
   architectural workstream subsumes the F.C++-3 set). The PR that
   lands the workstream updates the relevant section here in the same
   commit boundary.
2. **A new inherited C++ file is added** (rare; Shekyl-first per
   [`10-shekyl-first.mdc`](../.cursor/rules/10-shekyl-first.mdc) directs
   new code to Rust). The PR adding the file categorizes it here.
3. **A category boundary moves** (e.g., F.C++-2 file is migrated to
   Rust, changing category from "keep-justified" to "migrated").

The inventory does **not** update for every per-line C++ edit; it tracks
file-level disposition only.

## Categorization framework

Each inherited C++ file falls into exactly one of four categories:

| Category | Disposition | Driving workstream | Status |
| --- | --- | --- | --- |
| **F.C++-1** | Pending deletion | A-4/A-5/A-7/A-8 PoW workstream (RandomX v2 + LWMA-1 difficulty + CryptoNight retirement) | Pre-genesis |
| **F.C++-2** | Keep — justified (production utility, no Rust replacement warranted at V3.0) | Optional docstring sweep folded into PoW workstream | Pre-genesis (docstrings); permanent (files) |
| **F.C++-3** | Keep — transitional (subsumed by B-3 architectural workstream when Rust holds master keys) | B-3 architectural workstream + wallet2 cluster | Post-genesis V3.1+ |
| **F.C++-4** | Keep — Rust-FFI wrapper (consumes Rust crypto via FFI; not a parallel implementation) | None — verified Rust-FFI routing | Permanent |

The category boundary is **structural** (what is the file's role in the
post-Shekyl-first architecture), not **transient** (what state the file
is in today). A file's category does not change because of a single PR's
edit; it changes only when a workstream completes the work that moves
the file across the boundary.

## F.C++-1 — Pending deletion

Files in this category are CryptoNote PoW residue scheduled for deletion
as part of the A-4/A-5/A-7/A-8 PoW workstream. Per
[`60-no-monero-legacy.mdc`](../.cursor/rules/60-no-monero-legacy.mdc),
Shekyl ships RandomX v2 from genesis; CryptoNight variants are not
supported. Per the LWMA-1 difficulty algorithm pin in
[`docs/FOLLOWUPS.md`](./FOLLOWUPS.md) V3.0 queue, the difficulty
algorithm replacement also lands with this workstream.

| File | Inherited role | Notes |
| --- | --- | --- |
| [`src/crypto/slow-hash.c`](../src/crypto/slow-hash.c) | CryptoNight slow hash core | 2 MiB scratchpad never zeroized in inherited code (Lens C C-4/C-5 stop-gap-then-deletion context); see also [`docs/STRUCTURAL_TODO.md`](./STRUCTURAL_TODO.md) 32-bit-fallback gating |
| [`src/crypto/pow_cryptonight.cpp`](../src/crypto/pow_cryptonight.cpp) | CryptoNight PoW driver | Routed via the modular PoW schema interface per [`docs/DOCUMENTATION_TODOS_AND_PQC.md`](./DOCUMENTATION_TODOS_AND_PQC.md) §1.10; delete the driver, registration falls out by reference |
| `src/crypto/CryptonightR_JIT.h`, `CryptonightR_JIT_stub.c` | CryptoNight JIT compiler | Untested 32-bit fallback per [`docs/STRUCTURAL_TODO.md`](./STRUCTURAL_TODO.md) |
| `src/crypto/variant2_int_sqrt.h` | CryptoNight variant-2 integer sqrt helper | Used only by `slow-hash.c` |
| `src/crypto/variant4_random_math.h` | CryptoNight variant-4 random-math helper | Used only by `slow-hash.c` |
| `src/crypto/blake256.h` | Blake256 (CryptoNight component hash) | Not used outside CryptoNight chain |
| `src/crypto/groestl.{c,h}`, `groestl_tables.h` | Groestl (CryptoNight component hash) | Not used outside CryptoNight chain |
| `src/crypto/jh.c` | JH (CryptoNight component hash) | Not used outside CryptoNight chain |
| `src/crypto/skein_port.h` | Skein (CryptoNight component hash) | Not used outside CryptoNight chain |
| `src/crypto/hash-extra-blake.c`, `hash-extra-groestl.c`, `hash-extra-jh.c` | CryptoNight component-hash extras | Bundled with their respective component-hash files |

**Workstream attribution.** A-4/A-5/A-7/A-8 PoW workstream (paired with
RandomX-v2-from-genesis + LWMA-1 difficulty replacement). Per
[`docs/FOLLOWUPS.md`](./FOLLOWUPS.md) V3.0 queue "Difficulty algorithm:
replace inherited CryptoNote cut-windowed average with LWMA-1," this
workstream lands on `dev` shortly.

## F.C++-2 — Keep (production, justified)

Files in this category remain in C++ at V3.0 because no Rust replacement
is warranted at this stage (load-bearing utility, widely-audited
upstream, or transitional substrate for the cutover phase). Per
[`05-system-thinking.mdc`](../.cursor/rules/05-system-thinking.mdc)
"why is this here?" rule, each file's docstring should carry an explicit
Shekyl-justification comment. The optional docstring sweep is folded
into the A-4/A-5/A-7/A-8 PoW workstream as a sub-deliverable (the
workstream is already touching `pow_randomx.cpp` / `pow_registry.cpp`;
~2 hours of additional work to add docstring justifications across the
keep-set; closes Rule 05 compliance in the same commit boundary that
handles the F.C++-1 deletion set).

| File | Inherited role | Why kept at V3.0 |
| --- | --- | --- |
| [`src/crypto/keccak.c`](../src/crypto/keccak.c) | Keccak-f[1600] permutation | `cn_fast_hash` + general Keccak hashing; load-bearing for transitional period; subsumed by Rust `shekyl-crypto-pq` long-term |
| [`src/crypto/hash.{c,h}`](../src/crypto/hash.c) | General hash API | Wallet2 + tx_extra + serialization consumers; transitional substrate |
| [`src/crypto/crypto.cpp`](../src/crypto/crypto.cpp), [`src/crypto/crypto-ops.{c,h}`](../src/crypto/crypto-ops.c), `src/crypto/crypto_ops_builder/` | Bernstein ed25519 ref10 implementation | Constant-time by design; widely-audited upstream; used by C++ crypto path; mirror of Rust `curve25519-dalek` ed25519 surface |
| `src/crypto/generators.h` | Group generators (Ed25519 G, H, T) | Shared between C++ and Rust via FFI; canonical generator constants |
| [`src/crypto/pow_randomx.cpp`](../src/crypto/pow_randomx.cpp), [`src/crypto/pow_registry.cpp`](../src/crypto/pow_registry.cpp) | RandomX PoW driver + registry | Paired with A-4/A-5/A-7/A-8 PoW workstream; load-bearing for V3.0 RandomX-v2-from-genesis ship |
| [`src/crypto/random.c`](../src/crypto/random.c) | CSPRNG source (`/dev/urandom` + `CryptGenRandom`) | Lens F F.8 verified: production randomness routes through this on the C++ side; corresponds to Rust `OsRng` discipline |

**Workstream attribution.** Optional docstring sweep folded into
A-4/A-5/A-7/A-8 PoW workstream. The files themselves stay at V3.0;
re-evaluation triggers when (a) the Rust-side equivalent is feature-
complete enough to replace the C++ call surface without functional
regression, or (b) external audit surfaces a concern at a specific
file that warrants accelerated Rust migration.

## F.C++-3 — Keep (transitional; B-3 architectural workstream subsumes)

Files in this category remain in C++ at V3.0 because they're load-bearing
for the wallet2 encrypt/decrypt + auth surfaces that the B-3
architectural workstream is migrating to Rust. Per Lens B / Lens C
dispositions, the wallet2 cluster (B-1 deletion + B-2/C-1/C-3/C-4/C-5
migration with stop-gap framing) lands first at V3.0; the B-3
architectural workstream (Rust holds master keys; C++ holds encrypted
blob; Rust handles encrypt/decrypt) lands at V3.1 and subsumes these
files when it completes.

| File | Inherited role | Subsumption path |
| --- | --- | --- |
| [`src/crypto/chacha.{h,cpp}`](../src/crypto/chacha.h) | ChaCha20 stream cipher (used by wallet2 encrypt/decrypt) | B-3 architectural workstream: Rust handles encrypt/decrypt of on-disk blob with master key Rust holds internally; the C++ `chacha::generate_chacha_key` + `chacha::chacha_encrypt` / `chacha_decrypt` surfaces cease to exist when wallet2 cluster + B-3 land |
| [`src/crypto/hmac-keccak.{h,c}`](../src/crypto/hmac-keccak.h) | HMAC-Keccak (used by ChaCha cipher integrity check) | Subsumed alongside `chacha.{h,cpp}` when B-3 lands; verify usage during the wallet2-cluster pre-flight to confirm no non-wallet2 callers |

**Workstream attribution.** B-3 architectural workstream + wallet2
cluster (Lens B + C dispositions). The C-4/C-5 stop-gap context applies:
the V3.0 wallet2 cluster PR fixes the immediate Rule violations; the
V3.1 B-3 architectural workstream collapses the file set entirely. PR
descriptions for both PRs must record this subsumption so reviewers and
future auditors don't double-count the work or get confused by the
eventual collapse.

## F.C++-4 — Keep (Rust-FFI wrapper, verified routing)

Files in this category are C++ wrappers around Rust cryptographic
implementations. They are not parallel C++ implementations; they
consume Rust crypto via FFI (`shekyl/shekyl_ffi.h`) and provide
C++-shape boundaries for the consensus-validation + transaction-
construction surfaces that remain in C++ at V3.0.

| File | Wrapped Rust surface | Verification |
| --- | --- | --- |
| [`src/fcmp/rctSigs.{cpp,h}`](../src/fcmp/rctSigs.cpp) | FCMP++ signature construction + verification (Rust `shekyl-fcmp` / `shekyl-proofs`) | Confirmed Rust-FFI wrapper: `#include "shekyl/shekyl_ffi.h"` at `rctSigs.cpp:40`; `make_dummy_bulletproof_plus` is a transaction-construction-shape stand-in pattern, not a parallel implementation |
| [`src/fcmp/rctOps.{cpp,h}`](../src/fcmp/rctOps.cpp), [`src/fcmp/rctTypes.{cpp,h}`](../src/fcmp/rctTypes.cpp), [`src/fcmp/rctCryptoOps.c`](../src/fcmp/rctCryptoOps.c) | RingCT data types + crypto-ops wrappers | Supporting layer for `rctSigs.{cpp,h}`; same Rust-FFI consumer status |
| [`src/fcmp/bulletproofs_plus.h`](../src/fcmp/bulletproofs_plus.h) | Bulletproofs+ proof shape declaration | Type declaration consumed by `rctSigs.cpp`; underlying proof generation/verification routes through Rust `shekyl-proofs` / `crypto/generalized-bulletproofs` |

**Workstream attribution.** None (no migration work scheduled). These
files stay as Rust-FFI consumers as long as the transaction-construction
plus consensus-validation surfaces remain in C++ (V3.0 + V3.1.x + V3.2
scope). If a future migration brings those surfaces into Rust as well
(V3.x or later), these C++ files become eligible for deletion as part
of that migration; until then, they're the C++-shape FFI boundary that
the rest of `src/cryptonote_basic/`, `src/cryptonote_core/`, and
`src/blockchain_db/` consume.

**Verification protocol** (for future audits or migration-planning):
each file in this category must have a verifiable Rust-FFI routing
chain. The pattern to look for is `#include "shekyl/shekyl_ffi.h"`
(or transitively included via a sibling header) and per-function
delegation to the Rust FFI entry points declared in
[`rust/shekyl-ffi/src/lib.rs`](../rust/shekyl-ffi/src/lib.rs) and
[`src/shekyl/shekyl_ffi.h`](../src/shekyl/shekyl_ffi.h). Any file in
this category that has a function body containing parallel C++
cryptographic computation (rather than FFI delegation) is a
categorization error and must move to F.C++-2 or F.C++-3.

## Cross-references

- [`docs/POST_QUANTUM_CRYPTOGRAPHY.md`](./POST_QUANTUM_CRYPTOGRAPHY.md)
  — the cryptographic surface this inventory categorizes against; PQC
  primitive + tx_extra tag specification.
- [`docs/STRUCTURAL_TODO.md`](./STRUCTURAL_TODO.md) — adjacent C++
  cleanup tracks (32-bit fallback gating, Boost migration, `slow-hash.c`
  retirement).
- [`docs/DOCUMENTATION_TODOS_AND_PQC.md`](./DOCUMENTATION_TODOS_AND_PQC.md)
  — §1.10 modular PoW schema status (RandomX from genesis; CryptoNight
  variants not supported) and Boost migration table.
- [`docs/FOLLOWUPS.md`](./FOLLOWUPS.md) V3.0 queue — "Difficulty
  algorithm: replace inherited CryptoNote cut-windowed average with
  LWMA-1" pin attributes the A-4/A-5/A-7/A-8 PoW workstream that lands
  the F.C++-1 deletion set.
- [`.cursor/rules/60-no-monero-legacy.mdc`](../.cursor/rules/60-no-monero-legacy.mdc)
  — the rule that justifies F.C++-1 deletion (pre-genesis CryptoNight
  residue is dead weight by definition).
- [`.cursor/rules/16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)
  — the rule that justifies the per-file disposition discipline (inheriting
  code is not inheriting architecture; document the disposition).
- [`.cursor/rules/05-system-thinking.mdc`](../.cursor/rules/05-system-thinking.mdc)
  — "why is this here?" rule that justifies the optional F.C++-2
  docstring sweep.
- [`.cursor/rules/30-cryptography.mdc`](../.cursor/rules/30-cryptography.mdc)
  — the cryptographic-discipline rule whose globs include `src/crypto/**`
  and `src/fcmp/**` (the file scope this inventory covers).

## Inventory lifecycle

This document survives until **all four categories are empty or
permanent**:

- F.C++-1: empties when the A-4/A-5/A-7/A-8 PoW workstream lands and
  CryptoNight residue is deleted. At that point, F.C++-1 section becomes
  a historical record in [`docs/FOLLOWUPS.md`](./FOLLOWUPS.md) "Recently
  resolved (audit trail)" and the section here is deleted.
- F.C++-2: permanent in shape, but individual files may migrate to
  Rust over time (V3.x and beyond). Per-file entries are deleted as
  migrations complete.
- F.C++-3: empties when the B-3 architectural workstream lands and
  wallet2 encrypt/decrypt + auth surfaces are subsumed into Rust. Same
  lifecycle as F.C++-1: historical record in `FOLLOWUPS.md`; section
  here is deleted.
- F.C++-4: permanent in shape as long as transaction-construction +
  consensus-validation remain in C++. If those surfaces migrate to Rust
  in a future V3.x or V4 phase, F.C++-4 becomes eligible for deletion
  as part of that migration.

When all four sections are deleted or marked "see FOLLOWUPS.md audit
trail," this inventory file itself is deleted with a `git rm` recorded
in the PR that lands the final category collapse. The
[`docs/FOLLOWUPS.md`](./FOLLOWUPS.md) "Recently resolved" section
preserves the audit-trail link.
