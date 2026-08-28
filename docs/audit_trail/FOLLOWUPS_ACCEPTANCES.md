# Long-lived acceptances (not a work queue)

Moved from `docs/FOLLOWUPS.md` 2026-08-26. These are documented decisions, not open items.
## Long-lived utilities (no target version required)

These items document intentional decisions rather than pending work. They
stay here as a reference; closing them is equivalent to deleting this
reference.

- **`dalek-ff-group` version isolation enforced via CI gate.**
  The Rust workspace carries two versions: 0.5.x (used directly by
  Shekyl crates) and 0.4.x (pulled transitively by vendored
  serai/`ciphersuite` internals). A CI grep gate in
  `.github/workflows/build.yml` checks all Shekyl crates
  (`shekyl-ffi`, `shekyl-fcmp`, `shekyl-crypto-pq`, `shekyl-proofs`,
  `shekyl-tx-builder`, `shekyl-scanner`,
  `shekyl-daemon-rpc`) and asserts that none of their normal dependency
  trees pull in 0.4. Direct `dalek_ff_group` usage in source is printed
  for visibility but does not fail (legitimate 0.5 usage is expected).
  The 0.4 version must stay hidden behind `Ciphersuite` trait
  abstractions (`<Ed25519 as Ciphersuite>::G`, etc.). Never reach into
  `ciphersuite`'s internals. If upstream `ciphersuite` upgrades to
  `dalek-ff-group` 0.5, remove the gate.

- **`sha2` 0.10.x has no `zeroize` feature; HKDF-SHA256 chaining-state
  residency is documented-acceptance per the reversion-clause
  discipline.** Phase 0 Mission Audit Lens D, finding D-6 (per
  [`.cursor/rules/21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)).
  Audit-at-source verification confirmed `sha2` 0.10.x has no
  `zeroize` feature or optional dep at all — in contrast to sibling
  `sha3` 0.10.x, which carries `zeroize` as an optional dep and which
  `shekyl-crypto-pq` already enables. HKDF-SHA256 derivation of
  secret material via the workspace's `hkdf` consumers
  (`shekyl-crypto-pq`, `shekyl-engine-prefs`, `shekyl-proofs`) leaves
  a per-call residency window in the SHA-256 internal chaining state
  (~32 bytes per `Sha256` instance; SHA-256 is Merkle–Damgård, not a
  sponge — the residency is the eight 32-bit chaining words plus the
  block buffer, not Keccak-style absorb/squeeze state). The derived
  material itself is held in `Zeroizing<…>` by the caller; no
  shekyl-side wrapper.

  *Rejected alternatives.* **(a)** Upstream-contribute `zeroize`
  feature to RustCrypto `sha2` is the right long-term answer and is
  pursued as a separate non-blocking workstream; not gating Shekyl
  audit closure on upstream review timeline. **(b)** A shekyl-side
  wrapper around `Sha256` with `Drop` overwrite breaks the upstream
  abstraction boundary, introduces version-bump fragility (sha2's
  internal layout could shift across minor versions in ways the
  wrapper depends on), and delivers marginal exposure reduction
  (~32 bytes vs D-10's Argon2id 64 MiB buffer concern, which is the
  real-volume risk and is addressed separately via D-10's
  zeroize-feature enablement on `argon2`).

  *Reversion criteria* (either suffices to reopen the disposition;
  both named explicitly so future audit cannot mistake the
  disposition for a hard refusal — mirroring the `AllKeysBlob`
  Not-Clone precedent at
  [`rust/shekyl-crypto-pq/src/account.rs:480-494`](../../rust/shekyl-crypto-pq/src/account.rs)
  and the
  [`docs/completed/STAGE_1_PR_3_KEY_ENGINE.md`](../completed/STAGE_1_PR_3_KEY_ENGINE.md)
  §5.4.8 #1 reject-with-reopening precedent):

  1. **Upstream `sha2` adds a `zeroize` feature** (in any minor or
     major version). The workspace declarations in `shekyl-crypto-pq`,
     `shekyl-engine-prefs`, and `shekyl-proofs` adopt
     `features = ["zeroize"]` and this disposition closes as fixed.
  2. **A specific exposure pathway is identified that elevates the
     residency window beyond the per-call SHA-256 chaining state.**
     Examples: a fault-injection, memory-snapshot, or other attack
     model that can observe the chaining state after `finalize()`
     returns under conditions reachable by the threat model. The
     pathway must be specific (named threat vector plus
     memory-locality analysis), not speculative.

  *Cross-references.*
  [`.cursor/rules/17-dependency-discipline.mdc`](../../.cursor/rules/17-dependency-discipline.mdc)
  §3 "Property existence" — `sha2` is the canonical example of a
  security-load-bearing dep whose property is absent at source,
  surfaced by audit-at-source verification rather than training-data
  recall. Sibling reversion-clause entry: V3.0 queue `Hybrid* secret
  types: Vec<u8> for fixed-size scalars`. The dependency-discipline
  lens surfaced three concentrated instances of the reversion-clause
  pattern (D-6 sha2 acceptance criteria, D-19 directional disposition
  for `Box<fips204::ml_dsa_65::PrivateKey>`, the D-1 /
  D-fips204-discipline naming-pattern amendment to rule 17); the
  meta-pattern is hardening into project-wide substrate across
  altitudes (type-derivation, design-round closure, work-item
  placement, dependency-discipline).

- **F.8-sub: exhaustive constant-time + secret-handling spot-check
  deferred with three named triggers per reversion-clause
  discipline.** Phase 0 Mission Audit Lens F, finding F.8 categorical
  verification (per
  [`.cursor/rules/21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
  and
  [`.cursor/rules/30-cryptography.mdc`](../../.cursor/rules/30-cryptography.mdc)
  §"Constant-time and trusted randomness"). The Lens F categorical
  verification confirmed (a) zero production CSPRNG-bypass uses
  (`thread_rng` / `StdRng` / `SeedableRng::seed_from` / `rand::random`
  absent from production code; 3 bench/test uses all properly
  justified inline); (b) CSPRNG sources verified across Rust
  (`OsRng`) and C++ (`/dev/urandom` on Unix per
  [`src/crypto/random.c:70-72`](../../src/crypto/random.c) and
  `CryptGenRandom` on Windows per the same file's Win32 branch); and
  (c) `subtle::ConstantTimeEq` usage concentrated where load-bearing
  (shekyl-oxide crypto crates + `shekyl-engine-prefs/src/io.rs` for
  HMAC tag verification). The categorical verification is sufficient
  for V3.0 audit-readiness.

  *Exhaustive verification scope deferred.* A per-site walk for
  (1) any production comparison of secret/auth bytes that bypasses
  `subtle::ConstantTimeEq` in favor of bare `==` on byte arrays, and
  (2) any production `log::error!` / `format!` / `Display for
  SecretType` site that could exfiltrate secret material through
  log/error paths, is **deferred** as exhaustive-verification work
  that doesn't gate V3.0 audit closure.

  *Trigger criteria* (any one suffices to fire F.8-sub work; all
  three named explicitly so future audit cannot mistake the
  disposition for indefinite deferral — mirroring the
  acceptance-criteria precedent established by the D-6 `sha2`
  no-`zeroize` entry above ("`sha2` 0.10.x has no `zeroize`
  feature — accept-with-reversion-clause + parallel upstream
  workstream")):

  1. **External audit feedback.** If the V3.0 external audit
     surfaces a constant-time-comparison concern at any specific
     site, F.8-sub's methodology becomes the response artifact:
     walk the site's call surface, walk adjacent comparison sites
     under the same crate, document each as compliant or remediate.
  2. **New cryptographic primitive landing.** Any V3.x addition
     that introduces new secret-comparison or secret-formatting
     surfaces (new PQC primitive when V4 lattice-only NIST
     standardization closes; hardware-wallet integration per the
     V3.x C-1 disposition; FROST signing implementation per the
     B-3 Site 3 canonical-protocol-shape pin) triggers F.8-sub
     against the new surface as a per-PR pre-flight check.
  3. **Discipline-drift signal.** If a future PR review surfaces a
     single instance of `==` on secret material or `format!` on a
     secret-bearing type in production code, F.8-sub broadens to
     the surrounding crate to confirm the instance is isolated
     (not the visible tip of a larger discipline-drift pattern).

  *Why this shape vs. exhaustive-now.* Exhaustive constant-time
  walks return diminishing security per unit auditor-attention once
  the categorical disciplines are verified (CSPRNG source, type-
  enforced `subtle::ConstantTimeEq` at known load-bearing sites).
  The Lens F substrate-compounding observation applies: per-site
  walks that don't have a triggering signal produce mostly
  verification-confirmations rather than novel findings. The three
  named triggers cover the cases where per-site work is actually
  load-bearing (specific audit feedback, specific new-surface
  landing, specific drift signal) without spending pre-genesis
  audit-attention on speculative walks.

  *Cross-references.*
  [`.cursor/rules/30-cryptography.mdc`](../../.cursor/rules/30-cryptography.mdc)
  §"Constant-time and trusted randomness" (the rule being deferred
  to triggers rather than exhaustively verified now);
  [`.cursor/rules/21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
  (deferral shape: rejected-with-named-reopening-criteria);
  [`docs/CPP_INHERITANCE_INVENTORY.md`](../CPP_INHERITANCE_INVENTORY.md)
  (C++ secret-handling-adjacent files inventoried; trigger 2's
  "new cryptographic primitive" includes the F.C++-3 keep-
  transitional set when those files are migrated to Rust).

- **`shekyl-daemon-rpc/src/main.rs` uses `eprintln!` intentionally.**
  The standalone binary is a stub that exits with an error. No logging
  framework is initialized at that point. When standalone mode is
  implemented, replace with `tracing::error!` and proper logger init.
  This note is informational — there is no open action until standalone
  mode is specified.

- **`shekyl-economics-sim` uses `eprintln!` for CLI progress.**
  This is a batch CLI tool that writes JSON to stdout and progress to
  stderr. `eprintln!` is idiomatic for this pattern. No change planned;
  revisit only if the sim gains a long-running mode where structured
  logging is warranted.

---

