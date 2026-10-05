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

Each inherited C++ file has a single category at any given time; the
per-section tables below list files by their primary entry point. Files
that exist only as siblings of a listed file (paired `.c`/`.h`, paired
`.cpp`/`.h`, paired `.{c,h}` shorthand, `_stub` / template / generated
variants of a primary file, and contents of explicitly-named
directories) inherit the category of their primary file unless this
inventory states otherwise. See the "Inventory convention" subsection
below for the exhaustive rules; the four categories are:

| Category | Disposition | Driving workstream | Status |
| --- | --- | --- | --- |
| **F.C++-1** | production CryptoNight **DELETED 2026-09-15**; one residue remains (FCMP Bulletproof stub) | A-4/A-5/A-7/A-8 PoW workstream (RandomX v2 + LWMA-1 difficulty + CryptoNight retirement) | Pre-genesis (production discharged; category not empty) |
| **F.C++-2** | Keep — justified (production utility, no Rust replacement warranted at V3.0) | Optional docstring sweep folded into PoW workstream | Pre-genesis (docstrings); permanent (files) |
| **F.C++-3** | C++ ChaCha/hmac **DELETED 2026-09-16**; remaining row is the C++ BulletproofPlus prover (transitional; B-3) | B-3 architectural workstream + remaining BP+ surface | ChaCha/hmac discharged; BP+ still transitional |
| **F.C++-4** | Keep — Rust-FFI wrapper (consumes Rust crypto via FFI; not a parallel implementation) | None — verified Rust-FFI routing | Permanent |

The category boundary is **structural** (what is the file's role in the
post-Shekyl-first architecture), not **transient** (what state the file
is in today). A file's category does not change because of a single PR's
edit; it changes only when a workstream completes the work that moves
the file across the boundary.

## Inventory convention

The per-section tables list files by their **primary entry point** (the
file that carries the function definitions, the type declarations, or
the public symbols a category consumer cites). Sibling files inherit
the primary file's category unless this inventory states otherwise:

- **Header/source pairs.** A row listing `foo.c` covers `foo.h` (and
  vice versa). A row using `foo.{c,h}` or `foo.{cpp,h}` shorthand
  covers both files explicitly.
- **Generated / template / stub variants.** A row listing
  `foo.c` covers `foo_template.h`, `foo_template.S`, `foo_stub.c`,
  and any compiler-emitted variants used by the primary file.
- **Directories.** A row listing `crypto_ops_builder/` covers every
  file in the directory.
- **Component-hash extras.** For CryptoNight component hashes (Blake,
  Groestl, JH, Skein), the `hash-extra-<name>.c` wrapper inherits the
  category of the primary component-hash file.

A file that is **not** a sibling of any listed file, and which is
functionally distinct (its own algorithm, library, or interface), gets
its own row. The Phase 0 audit's PR #46 review surfaced four such
files that warranted explicit rows: `src/crypto/aesb.c` and
`src/crypto/oaes_lib.{c,h}` + `src/crypto/oaes_config.h` (CryptoNight
AES primitives + OpenSSL AES port), `src/crypto/rx-slow-hash.c`
(RandomX slow-hash), and `src/fcmp/bulletproofs_plus.cc`
(BulletproofPlus parallel C++ implementation; see F.C++-3's
"bulletproofs_plus re-verification" sub-section for the
categorization-corrective note this triggered).

**Path-notation convention.** Every filename in a table row carries
its full repo-relative path (e.g., `src/crypto/foo.c`), not a bare
basename, so `grep`/navigation against this inventory is reliable. The
shorthand `src/crypto/foo.{c,h}` covers `src/crypto/foo.c` and
`src/crypto/foo.h` together; siblings listed in the same row each
carry the full path explicitly. Markdown links are added on the
primary entry-point file in each row (for click-through to source);
sibling files in the same row may omit the link but retain the full
path.

Files in `src/crypto/` and `src/fcmp/` that are pure utility headers
shared across the kept-set (e.g., `src/crypto/c_threads.h`,
`src/crypto/duration.h`, `src/crypto/generic-ops.h`,
`src/crypto/hash-ops.h`, `src/crypto/initializer.h`) inherit F.C++-2
by default; if a workstream needs to migrate or delete any of these,
the workstream's PR adds an explicit row.

## F.C++-1 — production CryptoNight deleted 2026-09-15; one residue remains

CryptoNote PoW residue. The A-4/A-5/A-7/A-8 workstream deleted
`slow-hash.c`, `pow_cryptonight.cpp`, AES/OAES/JIT/hash-extra, the
variant-4 helper, and the test-only `variant2_int_sqrt.h`. One
non-production file remains in this category because it is not PoW and
is not this workstream's deletion surface: `src/fcmp/bulletproofs.{cc,h}`
is an empty non-plus Bulletproof stub (FCMP, not CryptoNight). Per
[`60-no-monero-legacy.mdc`](../.cursor/rules/60-no-monero-legacy.mdc),
Shekyl ships RandomX v2 from genesis. The category is **not empty**.

| File | Inherited role | Notes |
| --- | --- | --- |
| `src/crypto/slow-hash.c` | CryptoNight slow hash core | **DELETED 2026-09-15** |
| `src/crypto/pow_cryptonight.cpp` | CryptoNight PoW driver | **DELETED** (with 3b) |
| `src/crypto/aesb.c` | AES block primitives used by CryptoNight slow-hash | **DELETED 2026-09-15** |
| `src/crypto/oaes_lib.{c,h}`, `src/crypto/oaes_config.h` | OpenSSL AES library port (CryptoNight dependency) | **DELETED 2026-09-15** |
| `src/crypto/CryptonightR_JIT.{c,h}`, `src/crypto/CryptonightR_JIT_stub.c`, `src/crypto/CryptonightR_template.{h,S}` | CryptoNight JIT compiler + code-generation template | **DELETED 2026-09-15** |
| `src/crypto/variant2_int_sqrt.h` | CryptoNight variant-2 integer sqrt helper | **DELETED** (test-only residue; production `slow-hash.c` already gone) |
| `src/crypto/variant4_random_math.h` | CryptoNight variant-4 random-math helper | **DELETED 2026-09-15** |
| `src/crypto/blake256.{c,h}` | Blake256 (CryptoNight component hash) | **DELETED 2026-09-15** |
| `src/crypto/groestl.{c,h}`, `src/crypto/groestl_tables.h` | Groestl (CryptoNight component hash) | **DELETED 2026-09-15** |
| `src/crypto/jh.{c,h}` | JH (CryptoNight component hash) | **DELETED 2026-09-15** |
| `src/crypto/skein.c`, `src/crypto/skein_port.h` | Skein (CryptoNight component hash) | **DELETED 2026-09-15** |
| `src/crypto/hash-extra-blake.c`, `src/crypto/hash-extra-groestl.c`, `src/crypto/hash-extra-jh.c`, `src/crypto/hash-extra-skein.c` | CryptoNight component-hash extras | **DELETED 2026-09-15** |
| [`src/fcmp/bulletproofs.{cc,h}`](../src/fcmp/bulletproofs.cc) | Legacy (non-plus) Bulletproof — already empty stub | **RESIDUE (FCMP, not PoW).** `.cc` is `#include "bulletproofs.h"` only. `RCTTypeBulletproof` is gone at consensus; the stub is not an FFI wrapper (not F.C++-4) and is not this PoW workstream's delete. |

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
workstream is already touching `pow_randomx.cpp`;
~2 hours of additional work to add docstring justifications across the
keep-set; closes Rule 05 compliance in the same commit boundary that
handles the F.C++-1 deletion set).

| File | Inherited role | Why kept at V3.0 |
| --- | --- | --- |
| [`src/crypto/keccak.{c,h}`](../src/crypto/keccak.c) | Keccak-f[1600] permutation | `cn_fast_hash` + general Keccak hashing; load-bearing for transitional period; subsumed by Rust `shekyl-crypto-pq` long-term |
| [`src/crypto/hash.{c,h}`](../src/crypto/hash.c), `src/crypto/hash-ops.h` | General hash API | Wallet2 + tx_extra + serialization consumers; transitional substrate |
| [`src/crypto/crypto.{cpp,h}`](../src/crypto/crypto.cpp), [`src/crypto/crypto-ops.{c,h}`](../src/crypto/crypto-ops.c), `src/crypto/crypto-ops-data.c`, `src/crypto/crypto_ops_builder/` | Bernstein ed25519 ref10 implementation + precomputed tables | Constant-time by design; widely-audited upstream; used by C++ crypto path; mirror of Rust `curve25519-dalek` ed25519 surface |
| `src/crypto/generators.{cpp,h}` | Group generators (Ed25519 G, H, T) | Shared between C++ and Rust via FFI; canonical generator constants |
| [`src/crypto/pow_randomx.cpp`](../src/crypto/pow_randomx.cpp) | RandomX v2 PoW dispatch (`hash_pow_randomx`) | Load-bearing for V3.0 RandomX-v2-from-genesis; `IPowSchema` / `pow_registry` deleted 2026-09-15 |
| [`src/crypto/random.{c,h}`](../src/crypto/random.c) | CSPRNG source (`/dev/urandom` + `CryptGenRandom`) | Lens F F.8 verified: production randomness routes through this on the C++ side; corresponds to Rust `OsRng` discipline |
| `src/crypto/c_threads.h`, `src/crypto/duration.h`, `src/crypto/generic-ops.h`, `src/crypto/initializer.h` | C utility headers (threading shims, timing primitives, generic-operator macros, constructor-priority macros) | Used across the kept-set; no replacement warranted at V3.0; deletion would require auditing every cross-component consumer |

**Workstream attribution.** Optional docstring sweep folded into
A-4/A-5/A-7/A-8 PoW workstream. The files themselves stay at V3.0;
re-evaluation triggers when (a) the Rust-side equivalent is feature-
complete enough to replace the C++ call surface without functional
regression, or (b) external audit surfaces a concern at a specific
file that warrants accelerated Rust migration.

## F.C++-3 — ChaCha/hmac DELETED 2026-09-16; BulletproofPlus remains transitional

`chacha.{h,cpp}` and `hmac-keccak.{h,c}` are **DELETED** (no C++ production
caller after the CN-KDF / `account_keys` encrypt cut). The remaining row
is the C++ BulletproofPlus prover, still transitional pending the
re-verification subsection below.

| File | Inherited role | Subsumption path |
| --- | --- | --- |
| `src/crypto/chacha.{h,cpp}` | ChaCha20 stream cipher (used by wallet2 encrypt/decrypt) | **DELETED.** No C++ production caller after the CN-KDF / `account_keys` encrypt cut; wallet AEAD is Rust XChaCha20-Poly1305. |
| `src/crypto/hmac-keccak.{h,c}` | HMAC-Keccak (used by ChaCha cipher integrity check) | **DELETED.** Sole remaining callers were the unit tests; no production C++ consumer after the C++ chacha cut. |
| [`src/fcmp/bulletproofs_plus.cc`](../src/fcmp/bulletproofs_plus.cc), [`src/fcmp/multiexp.{cc,h}`](../src/fcmp/multiexp.cc) | C++ BulletproofPlus prover/verifier (parallel implementation) + multi-exponentiation support | **Tentative categorization pending re-verification** — see "bulletproofs_plus re-verification" subsection below. Live C++ callers are `ct_semantics.cpp` VERIFY (lines 135, 142) plus unit-test PROVE sites; `wallet2.cpp` is **DELETED** (Phase 5) and the Trezor caller is **Retired 2026-08-18**. The F.C++-4 entry for `bulletproofs_plus.h` framed it as Rust-FFI-routed, but the call graph shows the `.cc` is the live implementation those remaining sites call. |

**Workstream attribution.** B-3 architectural workstream. ChaCha/hmac are
**DELETED**; the remaining BP+ row is still transitional. The wallet2 cluster
that originally shared this category is gone (Phase 5). The B-3 workstream
collapses the remaining C++ prover when Rust holds the canonical path.

### `bulletproofs_plus` re-verification (inventory-triggered finding)

The F.C++-4 entry for [`src/fcmp/bulletproofs_plus.h`](../src/fcmp/bulletproofs_plus.h)
(below) describes the file as Rust-FFI-routed: "Type declaration
consumed by `ct_semantics.cpp`; underlying proof generation/verification
routes through Rust `shekyl-proofs` / `crypto/generalized-bulletproofs`."
This claim was surfaced during PR #46 Copilot review as needing
verification, because [`src/fcmp/bulletproofs_plus.cc`](../src/fcmp/bulletproofs_plus.cc)
exists as a ~1000-line C++ implementation with active callers:

- ~~`src/wallet/wallet2.cpp` `bulletproof_plus_PROVE`.~~ **DELETED with Phase 5:** `src/wallet/`
  is gone; this is not a live caller.
- ~~`src/device_trezor/trezor/protocol.cpp` `bulletproof_plus_PROVE` /
  `bulletproof_plus_VERIFY`.~~ **Retired 2026-08-18:** the Trezor
  backend is deleted (no PQC firmware support), so this caller no
  longer exists.
- [`src/fcmp/ct_semantics.cpp`](../src/fcmp/ct_semantics.cpp) `bulletproof_plus_VERIFY`
  (the `make_dummy_bulletproof_plus` helper is the
  transaction-construction-shape stand-in the F.C++-4 entry referred to,
  not the actual prove/verify path). An older census also named a bond-post
  helper; that is not a prove/verify call.

These call sites resolve to the symbols defined in
`bulletproofs_plus.cc` (line 502, etc.), not to a Rust-FFI shim. The
re-verification disposition: a follow-up per-call-site walk must
determine (a) which call sites belong to the FCMP++ transaction path
(where Rust BulletproofPlus is intended to be the canonical
implementation) versus pre-FCMP++ residue (where the C++ path is
legitimately the implementation), (b) whether a Rust-side replacement
for the C++ prover/verifier is in scope for V3.0 (alongside the
wallet2 cluster + B-3 workstream) or V3.1+, and (c) accordingly
whether `bulletproofs_plus.{cc,h}` belongs in F.C++-1 (delete
post-call-site-migration), F.C++-3 (transitional with the rest of the
wallet2-cluster surface), or remains in F.C++-4 (correct
categorization once the per-call-site walk confirms FFI routing).
Until then, the entry above lists the file tentatively in F.C++-3 as
the conservative choice, and the F.C++-4 entry for `bulletproofs_plus.h`
carries a cross-reference back to this subsection.

The re-verification was prompted by PR #46 Copilot review and is the
canonical example of how this inventory's "exhaustive per-file
disposition" claim must be defended against categorization-by-shape
errors (the `.h` looked like a forward declaration consumed by Rust
because the F.C++-4 entry was written in that frame; the call graph
reveals a parallel-C++ implementation). Future audits citing this
inventory should treat F.C++-4 entries as conditional on FFI-routing
evidence at the call sites, not on the file's structural shape.

## F.C++-4 — Keep (Rust-FFI wrapper, verified routing)

Files in this category are C++ wrappers around Rust cryptographic
implementations. They are not parallel C++ implementations; they
consume Rust crypto via FFI (`shekyl/shekyl_ffi.h`) and provide
C++-shape boundaries for the consensus-validation + transaction-
construction surfaces that remain in C++ at V3.0.

| File | Wrapped Rust surface | Verification |
| --- | --- | --- |
| [`src/fcmp/ct_semantics.{cpp,h}`](../src/fcmp/ct_semantics.cpp) | FCMP++ signature construction + verification (Rust `shekyl-fcmp` / `shekyl-proofs`) | Confirmed Rust-FFI wrapper: `#include "shekyl/shekyl_ffi.h"` at `ct_semantics.cpp:40`; `make_dummy_bulletproof_plus` is a transaction-construction-shape stand-in pattern, not a parallel implementation |
| [`src/fcmp/ct_ops.{cpp,h}`](../src/fcmp/ct_ops.cpp), [`src/fcmp/ct_types.{cpp,h}`](../src/fcmp/ct_types.cpp), [`src/fcmp/ct_crypto_ops.c`](../src/fcmp/ct_crypto_ops.c) | Confidential-transaction data types + crypto-ops wrappers | Supporting layer for `ct_semantics.{cpp,h}`; same Rust-FFI consumer status |
| [`src/fcmp/bulletproofs_plus.h`](../src/fcmp/bulletproofs_plus.h) | Bulletproofs+ proof shape declaration | **Re-verification pending** — see F.C++-3's "bulletproofs_plus re-verification" subsection above. The `make_dummy_bulletproof_plus` pattern in `ct_semantics.cpp` is the transaction-construction-shape stand-in this row originally described, but `bulletproof_plus_PROVE` / `bulletproof_plus_VERIFY` call sites resolve to the C++ implementation in `bulletproofs_plus.cc`, not a Rust-FFI shim. Categorization re-evaluated when the per-call-site walk lands |

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
  cleanup tracks (32-bit fallback gating, Boost migration; `slow-hash.c`
  retirement **CLOSED 2026-09-15**).
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

- F.C++-1: production CryptoNight **deleted 2026-09-15**. One named
  residue remains (FCMP Bulletproof stub). The category is not empty.
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
