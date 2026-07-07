# Stage 1 PR 3 — M3b pre-flight investigation

**Status.** **EXECUTED 2026-05-09.** M3b landed on
`feat/stage-1-pr3-m3b` as 10 commits cut off `dev` at `647f82d59`.
The Phase-2 dispositions in §2 / §3 / §5 below were carried
forward to implementation; the **Landing notes (M3b closed)**
sub-section in
[`STAGE_1_PR_3_MIGRATION_PLAN.md`](./STAGE_1_PR_3_MIGRATION_PLAN.md)
§3.2 records the divergences from the pre-flight estimate and the
discipline-grounded refinements that surfaced during execution. This
document is preserved as the audit trail of the Phase-1
investigation; subsequent maintainers should read the migration
plan's M3b landing notes for the actual landed state.

---

**Original status (preserved for audit).** Read-only investigation.
No code changes proposed yet.
This document surfaces findings, disposes the open design questions
flagged for M3b, and identifies the remaining open question that
requires user disposition before Phase 2 begins.

**Branch state.** `dev` clean at `76d1d2e2c` ("Merge branch
`chore/allkeysblob-typed-wrappers-monero-sweep` into dev"); typed-
wrapper sweep landed between M3a's merge and M3b's start; the files
M3b will edit (`shekyl-scanner/src/{ledger_ext,tests}.rs`,
`shekyl-engine-state/src/transfer.rs`,
`shekyl-engine-core/src/engine/{traits/key.rs,local_keys.rs}`) are
typed-wrapper-clean.

**Cross-references.** This document operationalizes
[`STAGE_1_PR_3_MIGRATION_PLAN.md`](./STAGE_1_PR_3_MIGRATION_PLAN.md)
§3.2 against the workspace state at `76d1d2e2c`. It cites
[`STAGE_1_PR_3_KEY_ENGINE.md`](./STAGE_1_PR_3_KEY_ENGINE.md) §3.3 /
§7.11–§7.13 for the design properties, and
[`STAGE_1_PR_3_MIGRATION_AUDIT.md`](./STAGE_1_PR_3_MIGRATION_AUDIT.md)
§1–§5 for the static invariants.

The §E framing carried in the M3b execution prompt — that
`sign_transaction`'s body remains a stub after M3b, with only its
trait-surface input reshaped — is the binding reading throughout this
document.

---

## §1 Audit invariants — re-verification on `dev` tip `76d1d2e2c`

| # | Invariant | Audit citation | Verification command | Result |
|---|---|---|---|---|
| 1 | Production `SpendInput` construction outside FFI/native-sign: zero | AUDIT §1.2 | `rg 'SpendInput\s*\{' rust/` | ✅ Hits only in `shekyl-tx-builder/src/{tests.rs, types.rs}` (definition site + tests) and `shekyl-ffi/src/lib.rs` (wallet2-bridged paths excluded per plan §2). **Zero production sites outside the excluded set.** |
| 2 | Production `TransferDetails` secret-field read sites: zero | AUDIT §2.2 / §2.5 | `rg 'td\.(ho\|y\|z\|k_amount\|combined_shared_secret)\s*=' rust/` for writes; `rg '\.combined_shared_secret\b\|\.k_amount\b' rust/` for reads | ✅ All non-test reads of `TransferDetails`'s secret fields are confined to `shekyl-engine-state/src/{transfer.rs, ledger_block.rs}` test code (postcard round-trip self-test) and to `shekyl-ffi/src/lib.rs` (FFI bridges). **Zero production reads outside the excluded set.** |
| 3 | Single production write site at `ledger_ext.rs:124–133` | AUDIT §3.1 | `rg 'td\.(ho\|y\|z\|k_amount\|combined_shared_secret)\s*=' rust/` | ✅ Production writes are confined to `shekyl-scanner/src/ledger_ext.rs:125–129`; the only other matches are in test setup at `shekyl-engine-state/src/transfer.rs:327–331`. **Single production write site, line shift +1 from the audit's pinned 124–129 due to comment edits.** |
| 4 | Non-wallet2-bridged `tx_builder::sign_transaction` callers: zero | AUDIT §4.2 | `rg 'tx_builder::sign_transaction\|shekyl_tx_builder::sign_transaction' rust/` | ✅ Hits only in `shekyl-engine-rpc/src/engine.rs:455` (`transfer_native`, wallet2-bridged path explicitly excluded per plan §2.5) and `shekyl-ffi/src/lib.rs:3127, 3331` (FFI bridges, excluded). **Zero non-wallet2-bridged callers in production.** |
| 5 | v31 multisig structurally aligned (no `TransferDetails`/secret-field references in `multisig/`) | AUDIT §5 | `rg 'TransferDetails\|combined_shared_secret\|k_amount' rust/shekyl-engine-core/src/multisig/` | ✅ No matches across `multisig/{dkg,group,mod,signing,tests}.rs` and `multisig/v31/`. **No drift; M3b changes do not interact with multisig.** |

**All five invariants hold.** No re-triage required; M3b can
proceed.

---

## §2 Disposition D1–D6

### D1 — Re-decap derivation primitive placement

**Decision.** Split the derivation into two layers:

- **Layer 1 (crypto-pq, transform-shaped).** A new pure function
  `shekyl_crypto_pq::output::recover_combined_ss(view_x25519_sk,
  view_ed_sk, ml_kem_dk, source_ciphertext) -> Result<SharedSecret,
  CryptoError>` that runs the X25519-+-ML-KEM-decap-+-HKDF-combine
  chain currently embedded in
  `shekyl_crypto_pq::output::scan_output_recover` (the first ~40
  lines of that function, ending at the `combine_shared_secrets`
  call). Returns the 64-byte `SharedSecret` (already `Zeroize` in
  this crate). **Pure, sync, no Edwards-curve / amount / commitment
  / PQC-keypair work** — those are scan-time-only checks the
  re-decap path has no business re-running.

- **Layer 2 (engine-core, state-shaped).** A new method
  `LocalKeys::derive_source_secrets_bundle(&self,
  source_ciphertext, output_index, subaddress_idx) ->
  Result<SourceSecretsBundle, KeyEngineError>` that:
  1. Calls Layer 1 with the engine's view secrets.
  2. Calls existing `derive_output_secrets(&combined_ss.0,
     output_index)` (already in `shekyl-crypto-pq::derivation`).
  3. Composes `ho`, `y`, `z`, `k_amount`, `combined_ss` into a
     `SourceSecretsBundle` with `spend_key_x = ho + b` (where `b` is
     the canonical spend secret + subaddress derivation) and the
     other fields as-is.

**Rationale.**

- Per `18-type-placement.mdc`, the bare cryptographic transform
  (re-decap → 64-byte `SharedSecret`) is transform-shaped — it is
  defined by what it computes, not by who owns the result. Its home
  is `shekyl-crypto-pq` alongside `combine_shared_secrets` and
  `derive_output_secrets`. Per the rule's "transform-shaped types
  live with their function" clause, this placement is rule-forced.
- The bundle composition (`spend_key_x = ho + b`) is engine-state-
  shaped: `b` is the engine's owned spend secret, and the bundle is
  defined by what the engine produces, not by an abstract transform.
  Its home is `shekyl-engine-core::engine::local_keys`.
- The split is the same shape `scan_output_recover` already uses
  internally; M3b extracts the re-decap prefix as a callable
  primitive without changing the existing recovery pipeline.

**Rejected alternatives.**

- **(a) Single function in `shekyl-crypto-pq::derivation`.**
  Rejected: the bundle composition needs `b` (engine-owned spend
  secret) and `m_i` (subaddress derivation scalar), neither of
  which can flow into `shekyl-crypto-pq` without making the crate
  engine-aware. Splits cleanly into the two-layer shape above.
- **(b) New module `shekyl-crypto-pq::output_resolution`.**
  Rejected: a new module for one function violates the workspace's
  module-density discipline. `output.rs` already houses the related
  recovery functions (`scan_output_recover`,
  `compute_output_key_image`) and is the natural home.
- **(c) Internal-only to `LocalKeys` (no exposed primitive).**
  Rejected: the byte-identical-derivation property test (D5) needs
  to call the re-decap chain in isolation against legacy-field
  values to assert bit-equality. A `pub fn` in `shekyl-crypto-pq`
  is the cleanest test surface.

### D2 — `TxInputSigningContext` field swap shape

**Decision.** Replace `source_secrets: SourceSecretsBundle` with
`source_ciphertext: HybridCiphertext`. **No other field on the
existing surface needs to move.**

**Walk of the trait-surface message shapes:**

- `OutputDetectionInput`: already carries `ciphertext:
  HybridCiphertext`, `output_key`, `commitment`, `view_tag`,
  `enc_amount`, `amount_tag_on_chain`, `output_index`, `tx_hash`.
  All public, all needed for `try_claim_output`. **No change.**
- `OutputClaim`: carries `handle`, `key_image`,
  `amount_atomic_units`. All public, all needed by the orchestrator.
  **No change.**
- `TxInputSigningContext`: today `{handle: OutputHandle,
  source_secrets: SourceSecretsBundle}`. M3b → `{handle:
  OutputHandle, source_ciphertext: HybridCiphertext}`. **One-field
  swap.**
- `TxToSign`: carries `inputs: Vec<TxInputSigningContext>`,
  `outputs`, `fcmp_plus_plus_context`. The latter two are
  forward-declared empty stubs (PR-5-pinned). **No change.**

**Output-index handling.** The output index is currently *redundant*
on the bundle (via `SourceSecretsBundle.output_index`) and must
remain accessible to `sign_transaction`'s body in PR 5 because
`derive_output_secrets` is keyed by it. The cleanest M3b shape
carries `output_index` on `TxInputSigningContext` as a sibling
field next to `source_ciphertext` — the orchestrator already has it
from the `OutputDetectionInput` it submitted at claim time. Surfaced
as **deliberate addition, not a hidden migration**: the post-M3b
shape is `TxInputSigningContext { handle, source_ciphertext,
output_index }`.

**Subaddress index handling.** The bundle's `spend_key_x = ho + b`
composition needs the subaddress index to derive the subaddress-
specific `b + m_i`. PR 5's `sign_transaction` resolves the handle
against the engine's internal handle table to recover the
subaddress index; the orchestrator does NOT carry it on
`TxInputSigningContext`. M3b's `derive_source_secrets_bundle` reads
the subaddress index from its argument list (passed by PR 5
internals; M3b ships the function with the parameter for
forward-completeness). **No new orchestrator-side data flow.**

**Debug redaction impact.** `HybridCiphertext` has `derive(Debug)`
that prints the X25519 ciphertext and ML-KEM ciphertext bytes.
These are **public on-chain values** (not secrets), so derived
`Debug` is appropriate. After the field swap,
`TxInputSigningContext`'s manual `Debug` impl simplifies (no need
for `[REDACTED]` placeholder; `source_ciphertext`'s derived debug
is safe). Same for `TxToSign`'s manual `Debug` impl — the
defence-in-depth `[REDACTED]` for `inputs` becomes optional. M3b's
disposition: **keep the defence-in-depth redaction on `inputs` and
on `TxInputSigningContext` regardless**, because the type may
re-acquire secret-bearing fields in PR 5 (`y_blind` for output
construction, etc.) and re-establishing the redaction discipline is
brittle. Cite per `35-secure-memory.mdc`'s "redact at composition
boundaries" rule.

**Rejected alternatives.**

- **(a) Move `output_index` into a wrapping `IndexedSpendInput`
  type.** Rejected: introduces a one-use wrapper for one field; the
  surrounding type is already a struct.

### D3 — `TransferDetails` schema additions

**Decision.** Add two fields, both `Option<...>`:

```rust
// rust/shekyl-engine-state/src/transfer.rs
pub source_ciphertext: Option<HybridCiphertext>,
pub output_handle: Option<OutputHandle>,
```

**Postcard schema impact.**

- `HybridCiphertext` is currently `#[derive(Debug, Clone, Serialize,
  Deserialize)]` in `shekyl-crypto-pq::kem`. **It does not derive
  `postcard_schema::Schema`.** The `TransferDetailsSchema` mirror
  struct (the postcard-schema reference shape, around
  `transfer.rs:174–230`) needs an explicit Schema-side
  representation for the new field.
- `OutputHandle` is currently `#[derive(Clone, Copy, PartialEq, Eq,
  Hash, PartialOrd, Ord)]` (manual `Debug` for redaction; **no
  Serialize, Deserialize, or Schema**) in
  `shekyl-crypto-pq::handle`. M3b adds `#[derive(Serialize,
  Deserialize)]` and a `postcard_schema::Schema` impl (or matching
  derive if available on `OutputHandle`'s pinned postcard-schema
  version) on the `OutputHandle` newtype.

**Two acceptable shapes for the schema mirror — pick one in
Phase 2 implementation:**

- **(α)** Add `#[derive(postcard_schema::Schema)]` to both
  `HybridCiphertext` (in `shekyl-crypto-pq::kem`) and `OutputHandle`
  (in `shekyl-crypto-pq::handle`) directly. The
  `TransferDetailsSchema` mirror then references both types as
  themselves: `pub source_ciphertext: Option<HybridCiphertext>`
  and `pub output_handle: Option<OutputHandle>`. Smaller diff,
  but leaks `postcard-schema` as a `shekyl-crypto-pq` dependency.
- **(β)** Mirror only at the `TransferDetailsSchema` level: add
  Schema-only struct mirrors `HybridCiphertextSchema { x25519:
  [u8; 32], ml_kem: Vec<u8> }` and `output_handle: [u8; 16]` on
  the schema side, and wire `serde_helpers` adapters for both
  types if the wire format diverges from the natural derive.
  Heavier diff, but isolates the postcard-schema dependency at the
  schema side (consistent with the existing `serde_helpers` pattern
  for curves).

**Disposition: (α) — confirmed by user 2026-05-08 conditional on
transitive-dep verification.** `postcard-schema` is **not** a
workspace-level dependency (correction from earlier draft); it is a
direct dep of `shekyl-engine-state` only, pinned at `version =
"0.2", default-features = false, features = ["derive", "use-std"]`.
M3b adds it as a direct dep of `shekyl-crypto-pq` with the same
pin.

**Transitive-dep verification (run pre-Phase-2 per
`17-dependency-discipline.mdc`):**

```text
$ cargo tree -p shekyl-engine-state | rg -A20 'postcard-schema v'
├── postcard-schema v0.2.5
│   ├── postcard-derive v0.2.2 (proc-macro)
│   │   ├── proc-macro2 v1.0.106 (*)        # already in tree
│   │   ├── quote v1.0.45 (*)                # already in tree
│   │   └── syn v2.0.117 (*)                 # already in tree
│   └── serde v1.0.228 (*)                   # already a direct dep
```

**Zero new third-party crates** introduced into `shekyl-crypto-pq`'s
transitive tree. The proc-macro substrate (`proc-macro2` / `quote`
/ `syn`) is already pulled in via `serde_derive`, `thiserror`,
and `zeroize_derive`. `serde` itself is already a direct dep
(`Cargo.toml:10`). **α is locked in.**

**Wire-format rationale.** The wire format `HybridCiphertext`'s
derived serde produces (32 raw bytes for X25519 || varint-len +
bytes for ML-KEM) is the Schema we want, and `[u8; 32] || Vec<u8>`
is directly expressible by the Schema derive without adapter
plumbing. The existing `serde_helpers` mirror pattern in
`shekyl-engine-state::transfer.rs:179–214` exists because curve
types are external (curve25519-dalek) and we deliberately avoid the
`curve25519-dalek/serde` feature; both `HybridCiphertext` and
`OutputHandle` are workspace-owned types with no analogous
pin-our-own-encoding requirement.

**Mirror-struct interaction at M3b.** The existing
`TransferDetailsSchema` mirror in `transfer.rs:179` uses `Vec<u8>`
in place of curve types. M3b extends the mirror with two new
fields: `source_ciphertext: Option<HybridCiphertext>` (because
`HybridCiphertext: postcard_schema::Schema` after α) and
`output_handle: Option<OutputHandle>` (because `OutputHandle:
postcard_schema::Schema` after α). The mirror does **not** need its
own `HybridCiphertextSchema` sub-mirror — α puts the Schema impl on
the type itself.

**Serde helper requirements.**

- `HybridCiphertext`'s wire format under derived Serialize is
  fully determined: `[u8; 32]` X25519 component + `Vec<u8>` ML-KEM
  component. No serde adapter needed for postcard.
- `OutputHandle` is `[u8; 16]` newtype with private inner field; M3b
  adds `Serialize`/`Deserialize` derives via `serde(transparent)`
  (or by exposing a public `pub(crate)` constructor that the
  Deserialize impl uses). Wire format: 16 raw bytes.
- For json/test rendering, `OutputHandle`'s manual `Debug`
  (truncated) is correct; serialization round-trips through the raw
  16 bytes.

**Zeroize allowlist impact.** Per `35-secure-memory.mdc`:

- `HybridCiphertext` is **public on-chain data** (broadcast in the
  transaction's `tx_extra`). Not a secret. **No `Zeroizing<>`
  wrapper required.**
- `OutputHandle` is a deterministic 16-byte derivative of
  `(view_secret, tx_hash, output_index)` per `KEY_ENGINE.md` §7.12.
  Per the design doc's "non-secret derivative" framing, the
  handle's role is as an opaque reference to engine-internal state;
  **disclosure of the handle does not disclose the view secret**
  (cSHAKE256 is forward-secure; recovering `view_secret` from
  `handle` requires breaking the hash). The handle is already
  redacted from `Debug` (manual impl truncates to 2 bytes) — that's
  the single-use "redact in logs" property, not a "secret" property.
  **No `Zeroizing<>` wrapper required.**
- The new `Option<HybridCiphertext>` and `Option<OutputHandle>`
  fields on `TransferDetails` therefore add **no new wipe-on-drop
  obligation**. `TransferDetails`'s existing manual `Drop` /
  `Zeroize` impls (around `transfer.rs:236–251`) are unchanged
  beyond extending the field list (no calls).
- `TransferDetails`'s `Debug` impl: confirm the new fields don't
  surface secret material in `Debug` output. `OutputHandle` is
  redacted; `HybridCiphertext` derives `Debug` and prints byte
  arrays — but those bytes are public. **No new redaction
  required.**

**Test impact.**

- `transfer.rs:317–346` (the `transfers_roundtrip_with_secrets`
  postcard test) extends to populate the two new fields and assert
  round-trip equality, mirroring the existing pattern. ~10 lines
  added.
- `ledger_block.rs:469–515` (the analogous block-level round-trip
  test) extends similarly. ~6 lines added. **This file is in
  `shekyl-engine-state`, but the diff is mechanical; per
  `15-deletion-and-debt.mdc`'s "while we're here is the enemy"
  rule, this is the file directly under M3b's edit, so the
  extension is in scope.**

### D4 — Bridge-impl fallback semantics

**Decision.** The fallback **lives inside
`LocalKeys::sign_transaction`'s body** (which remains stubbed
post-M3b per §E framing); M3b ships the **derivation primitive**
that `sign_transaction` will call when it lands in PR 5 with the
fallback dispatch logic.

The fallback semantics are spec'd at M3b but exercised only at
PR 5, **except** for the byte-identical-derivation property test
(D5) which exercises both code paths (legacy bundle from the
`SourceSecretsBundle`-equivalent computed via the existing chain;
new bundle from `derive_source_secrets_bundle`) on the same input
and asserts bit-equality. That property test does not call
`sign_transaction`; it calls the primitives directly.

**Specification of the fallback (for PR 5):**

```rust
// In LocalKeys::sign_transaction (PR 5 implementation):
let bundle = if let Some(ref ct) = transfer_details.source_ciphertext {
    // Primary path (M3b deliverable): re-derive from engine-owned secrets.
    self.derive_source_secrets_bundle(ct, output_index, subaddress_idx)?
} else {
    // Fallback path (transitional, removed at M3d):
    // legacy fields on TransferDetails populate the bundle directly.
    legacy_bundle_from_transfer_details(transfer_details)?
};
```

The fallback is selected by `Option::is_some()` on
`source_ciphertext`, **not** by a feature flag. This satisfies the
plan §4.2 "feature-detected, not feature-flagged" requirement.

**Constant-time discipline check (per
`35-secure-memory.mdc`'s constant-time-or-explicit-rejection rule):**

- The branch `if source_ciphertext.is_some()` is selected per-
  output by **wallet-state shape** (whether the field was populated
  at scan time), not by per-output secret data. The branch decision
  is derived from a public property of the on-chain output (whether
  the wallet's scanner populated the new field). **No secret-
  dependent timing variance is introduced** by the dispatch.
- Inside each branch, the underlying computation is deterministic
  and constant-time per the underlying primitives' contracts
  (`combine_shared_secrets`, `derive_output_secrets` are curve-/
  HKDF-grade constant-time; the fallback is a memcpy-equivalent
  `SourceSecretsBundle` materialization).
- During the M3b–M3d transitional window, **every production
  `TransferDetails` carries `source_ciphertext = Some(...)` if M3b
  successfully populated it**. The fallback is exercised **only**
  by:
  - Test fixtures that deliberately leave `source_ciphertext` as
    `None` (the explicit fallback test the plan calls out).
  - Pre-M3b `TransferDetails` records persisted to disk (legacy
    wallet state). Per `00-mission.mdc`'s pre-genesis posture and
    `15-deletion-and-debt.mdc`'s ruthless-deletion rule, **there are
    no such records**: V3 has not launched; pre-V3 wallet state is
    `rm -rf ~/.shekyl` discardable.
- Therefore the production fallback exposure window is empty.
  This is recorded in
  [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) (V3.x) as "M3d removes the
  fallback once the byte-identical-derivation test in M3c has
  validated the engine path."

### D5 — Byte-identical-derivation property test scope

**Decision.** **Integration test** in
`rust/shekyl-engine-core/tests/byte_identical_derivation.rs` (~100
lines per the plan estimate). The test:

1. Constructs a `LocalKeys` instance from a known seed.
2. Constructs a single on-chain output via
   `shekyl_crypto_pq::output::construct_output` (sender side; the
   same function `local_keys.rs` tests use).
3. Computes the legacy chain output: calls `scan_output_recover`
   with the wallet's view secrets and the constructed-output's
   ciphertext; reads `recovered.{ho, y, z, k_amount, combined_ss}`.
   Composes a `SourceSecretsBundle` by hand (with `spend_key_x =
   ho + b` derivable from the test seed).
4. Computes the new chain output: calls
   `LocalKeys::derive_source_secrets_bundle(&source_ciphertext,
   output_index, subaddress_idx_zero)`.
5. Asserts each field of the two bundles is byte-identical.
6. Repeats across at least 3 (preferably 8+) distinct (output_index,
   tx_hash) triples to exercise the cSHAKE256 / HKDF context-
   binding paths.

**Rationale for integration-test placement (per the plan):**

- Calling `LocalKeys::derive_source_secrets_bundle` requires the
  full `LocalKeys` shape (the engine's view secrets, spend secret,
  subaddress derivation). A unit test in `shekyl-crypto-pq` cannot
  exercise the bundle composition because that crate has no engine
  type.
- A unit test on the Layer 1 primitive
  (`shekyl_crypto_pq::output::recover_combined_ss`) is *also*
  desirable — it asserts the re-decap chain alone produces the same
  64-byte `SharedSecret` as `scan_output_recover`'s prefix. **Add
  this as a separate test file**
  `rust/shekyl-crypto-pq/tests/recover_combined_ss.rs` (~60 lines).
- Both tests together: Layer 1 unit test asserts the cryptographic
  primitive is byte-identical; Layer 2 integration test asserts
  the engine composition is byte-identical.

**Rejected alternative.** Single integration test conflating both
layers. Rejected: a Layer 1 failure should fail at `crypto-pq` test
time, not engine-core test time. Splitting localizes failures to
the layer that's wrong.

### D6 — `KeyEngineError` extensions

**Decision.** Add **one** new variant. Existing variants are
unchanged.

```rust
// rust/shekyl-engine-core/src/engine/error.rs
/// Re-decapsulation failed during source-secrets bundle derivation.
///
/// Surfaced when `LocalKeys::derive_source_secrets_bundle` calls the
/// re-decap primitive (Layer 1) and the X25519 ECDH or ML-KEM-768
/// decap rejects the input. Distinguished from
/// `[Self::SignTransactionTraitSurfaceIncomplete]` because this one
/// is a real cryptographic failure (the source ciphertext is
/// malformed or the wallet's view-key/ml_kem-dk pair doesn't decapsulate
/// it), not a named-infrastructure-gap stub.
SourceCiphertextDecapsulationFailed,
```

**No** `LegacyFallbackEngaged`, `MissingSourceCiphertext`, or
similar variants for the fallback path. The fallback at M3b is
*not* an error condition — it's a transitional code branch the
production code path takes when the field is `None`. The `None`
case is normal until M3d.

**Rationale.**

- Per `15-deletion-and-debt.mdc`'s "named-infrastructure-gap"
  pattern, error variants name failure modes that **exist**, not
  failure modes that **might exist if some future code did
  something**. The single failure mode that is real at M3b is
  decap rejection of a stored ciphertext.
- The variant is `pub(crate)` matching the rest of the trait surface
  visibility (becomes `pub` at the V3.2 wallet-RPC cutover).
- `KeyEngineError` already derives `Debug, Clone, PartialEq, Eq,
  thiserror::Error`; the new variant inherits those derives without
  any wire-format impact (the type isn't on a wire).

**Open: associated diagnostic data on the new variant.** Should
`SourceCiphertextDecapsulationFailed` carry the underlying
`CryptoError`? Existing `KeyEngineError` variants do not (they're
unit variants per the existing pattern). **Default disposition:
unit variant.** Surface only the named failure mode; the wallet UI
maps named errors to user-facing messages. If diagnostic detail is
needed in M3b's debug logs, surface via tracing at the call site,
not by widening the error variant.

---

## §3 Scanner reroute call shape — disposition

The plan §3.2 frames the reroute as "scanner emits `OutputClaim` to
`KeyEngine::try_claim_output`." That framing is **architecturally
correct** but **structurally cannot land inside
`shekyl-scanner::process_scanned_outputs`** because:

1. `shekyl-scanner` does not depend on `shekyl-engine-core` (the
   dependency direction is engine-core → scanner via
   `LedgerIndexesExt`). A scanner-side `KeyEngine` call requires
   inverting that dependency or extracting a shared trait crate.
   Neither is in M3b's scope.
2. `KeyEngine` is `pub(crate)` to `shekyl-engine-core` per the M3a
   visibility decision. Crossing a crate boundary requires
   widening visibility — also not in M3b's scope.
3. `process_scanned_outputs` is sync and called from ~30 sites
   (5 production, 25 test). Forcing it `async` cascades into
   every test fixture and bench; the plan's ~30-line `ledger_ext.rs`
   estimate is incompatible with that cascade.

**Decision.** The reroute lives at the **orchestrator layer** in
`rust/shekyl-engine-core/src/engine/merge.rs::apply_scan_result_to_state`
(or a new sibling helper called from it). The shape:

```text
[shekyl-engine-core] Engine::apply_scan_result(scan_result) [async; existing]
  └─ apply_scan_result_to_state(ledger, indexes, scan_result) [sync; existing]
       └─ for each height h:
            indexes.process_scanned_outputs(ledger, h, hash, timelocked)
                                                               │
                                                               ▼
            populates td.{ho, y, z, k_amount, combined_shared_secret,
                          key_image, …}  ← LEGACY FIELDS (transitional)

  └─ NEW M3b POST-PASS (engine-side, async):
       for each freshly-added td in ledger.transfers (those whose
       block_height fell inside the scan_result's processed range):
         build OutputDetectionInput from td + RecoveredWalletOutput residue
         claim = self.keys.try_claim_output(&input).await
         match claim {
           Mine(c)   => { td.source_ciphertext = Some(extracted_ct);
                          td.output_handle    = Some(c.handle); }
           NotMine   => { td.source_ciphertext = None;
                          td.output_handle    = None;
                          warn!("scanner detected output the engine rejects"); }
         }
```

**Plumbing.**

- `apply_scan_result_to_state` is currently `pub(crate) fn` (sync).
  It cannot itself become async without changing the trait surface
  (`Ledger::apply_scan_result` is async). Two options:
  - **(γ) Promote `apply_scan_result_to_state` to async.** Match the
    trait method's async signature; `LocalLedger::apply_scan_result`
    and `Engine::apply_scan_result` already `await` the helper or
    wrap it in `async fn`; the helper accumulates an
    `engine_population_pass` step that uses the keys reference.
    Engine reference threads in via a new parameter.
  - **(δ) Keep `apply_scan_result_to_state` sync.** Add a sibling
    async helper `populate_engine_handle_fields(ledger, indexes,
    scan_result, &keys)` that runs *after*
    `apply_scan_result_to_state` returns. Called from
    `Engine::apply_scan_result`'s body (which becomes `async fn` for
    the await; the body is one-await-deep so no executor-level
    refactor).
- **Disposition: (δ) — confirmed by user 2026-05-08 with the
  permanent-split framing pinned below.** Smaller diff. The sync
  helper's contract stays clean (it does not need engine context);
  the engine pass is its own explicit step.

**Permanent split, not transitional.** The sync/async split is
intentional and load-bearing, not a transitional shape pending
convergence. Both halves have legitimate consumers that aren't
going away:

- `apply_scan_result_to_state` (sync) is called by:
  - `LocalLedger::apply_scan_result` (delegates synchronously
    inside an async wrapper, no engine integration needed).
  - In-crate tests in `merge.rs::tests` and `pending.rs::tests`
    that exercise the bookkeeping pipeline without engine context.
  - The free-function form is the substrate the trait method
    delegates to per the canonical `engine.rs:151` /
    `local_ledger.rs:260` pattern.
- `populate_engine_handle_fields` (async) is called by:
  - `Engine::apply_scan_result` after the sync substrate runs.
  - Future engine-mediated paths (e.g., post-V3.2 wallet RPC
    cutover, M3d's "secrets confined to engine" activation point).

The sync version does not "go away in a future cleanup"; it remains
the bookkeeping-pipeline substrate. The async version layers
engine integration on top. **M3b's commit message and the helper's
doc-comment must pin this framing explicitly** so a future
maintainer reading "why two helpers?" finds the load-bearing
answer rather than re-litigating it as transitional drift.

**`OutputDetectionInput` reconstruction.** The engine's
`try_claim_output` needs `(ciphertext, output_key, commitment,
view_tag, enc_amount, amount_tag_on_chain, output_index, tx_hash)`.
The orchestrator currently has access to all of these via the
`DetectedTransfer` carrier (which holds the original
`RecoveredWalletOutput`); the residue is preserved in the merge
flow before `process_scanned_outputs` consumes it. M3b adds: the
orchestrator collects the per-output `OutputDetectionInput`s in a
side map keyed by `(tx_hash, output_index)` *before*
`process_scanned_outputs` runs; runs the post-pass keyed by the
same map. ~30–40 lines net in `merge.rs`.

**Cost.** The post-pass runs the decap a second time (the scanner
already ran it at scan-time to populate `RecoveredWalletOutput`'s
secret fields). This is the M3b–M3d transitional cost; M3d removes
the scan-time decap (legacy fields go away) and the engine-side
decap becomes the only one. The plan §4.4 implicitly accepts this
double-decap cost; surface explicitly here.

**Idempotency.** `KeyEngine::try_claim_output` is documented as
deterministic in the deterministic-handle pathway (per the trait
docstring's "Idempotency: A `Mine` result inserts into the handle
table; a re-call on the same `OutputDetectionInput` either re-binds
the same `OutputHandle`…"). Re-running the post-pass on the same
inputs produces the same `(handle, key_image, amount)` triples;
re-inserting into the handle table is idempotent. **No new
idempotency gates are required at M3b.**

**Rejected alternatives.**

- **(ε) Sync handle derivation in `process_scanned_outputs`
  (`derive_output_handle` + ciphertext extraction, no engine
  call).** Rejected: requires plumbing `view_secret` into
  `process_scanned_outputs` (the scanner does not currently take
  a view_secret parameter at this entry point). Plumbing it
  means widening `LedgerIndexesExt::process_scanned_outputs`'s
  signature, breaking ~30 call sites. Also: it bypasses the engine
  entirely, which contradicts the audit's "engine is the sole
  authority on handles" framing for M3d's "secrets confined to
  engine" property.
- **(ζ) Post-process the ledger from outside the apply-scan-result
  flow (e.g., a separate `Engine::populate_handles()` method).**
  Rejected: introduces a non-atomic intermediate state where
  `TransferDetails` exists in storage with `source_ciphertext =
  None`/`output_handle = None`. A crash between the two passes
  leaves the wallet inconsistent. Atomicity within
  `apply_scan_result` is the discipline.

---

## §4 Test fixture rewrite scope

Three fixtures populate `RecoveredWalletOutput` directly with
zero-byte sentinels for the secret fields (line numbers shifted by
the post-M3a sweep; identifiers below give the M3a-stable anchors):

| # | Location | Anchor | Function | Current shape |
|---|---|---|---|---|
| 1 | `shekyl-scanner/src/tests.rs:68–81` | `wrap_recovered` (top of `tests` module) | `wrap_recovered(WalletOutput, amount) -> RecoveredWalletOutput` | populates `ho/y/z/k_amount = [0u8;32]`; `combined_shared_secret = [0u8;64]`; `key_image` derived from `index_on_blockchain()` low 8 bytes |
| 2 | `shekyl-scanner/src/tests.rs:846–859` | `wrap_recovered` (proptest module) | identical to #1, separate copy in proptest module | identical to #1 |
| 3 | `shekyl-scanner/src/tests.rs:1004–1041` | `mock_output(global_idx, amount)` | `mock_output` (reorg/burning-bug tests) | constructs `RecoveredWalletOutput` inline with same zero-byte secret-field pattern |

**M3b shape decision.** Test fixtures **continue to populate the
legacy fields with zero-byte sentinels**. Rationale:

- The fixtures' contract is "produce a `RecoveredWalletOutput` that
  `process_scanned_outputs` can consume and stage in
  `TransferDetails`." That contract is unchanged at M3b — legacy
  fields stay populated transitionally.
- The fixtures **do not** need to construct
  `(source_ciphertext, output_handle)` pairs themselves. Those
  fields are populated by the engine post-pass (per §3 above). The
  fixtures' tests run through `process_scanned_outputs` (which
  does not call the engine post-pass) — they exercise the
  bookkeeping pipeline, not the engine handle pipeline.
- The post-pass tests (engine-mediated population) live in the new
  integration test (§D5) and in any new tests added in M3b's
  `merge.rs` test module. They use real `LocalKeys` and real
  `construct_output` outputs, **not** the synthetic
  `wrap_recovered`/`mock_output` fixtures.

**M3b test fixture diffs to expect:**

- `tests.rs:68–81`: zero changes IF the underlying
  `RecoveredWalletOutput` struct's `Zeroize` /
  `ZeroizeOnDrop` derivation is unchanged. Verify after the
  scanner-side work lands; expect zero edits to this fixture.
- `tests.rs:846–859`: identical to above; zero edits expected.
- `tests.rs:1004–1041`: identical; zero edits expected.

**Gross test diff in `shekyl-scanner/src/tests.rs`.** Plan estimate
~150 lines; actual **expected ~10–20 lines** if the engine post-
pass is in `engine-core/src/engine/merge.rs` (per §3) rather than
in the scanner. **The plan's 150-line estimate over-counted because
it assumed scanner-side engine plumbing.** Surface as a positive
deviation from estimate; the bench/test cascade does not happen.

**Net effect on plan §3.2 line-count estimate.**

| File | Plan estimate | Pre-flight estimate | Delta | Reason |
|---|---|---|---|---|
| `rust/shekyl-scanner/src/ledger_ext.rs` | ~30 lines | ~0–10 lines | −20 to −30 | Engine-call moved to engine-core orchestrator |
| `rust/shekyl-scanner/src/tests.rs` | ~150 lines | ~10–20 lines | −130 to −140 | No fixture rewrite needed (legacy fields stay) |
| `rust/shekyl-engine-core/src/engine/local_keys.rs` | ~80 lines | ~80 lines | 0 | Layer-2 derivation method + import wiring |
| `rust/shekyl-engine-core/src/engine/traits/key.rs` | (not in plan) | ~20 lines | +20 | Field swap on `TxInputSigningContext`, error import |
| `rust/shekyl-engine-core/src/engine/error.rs` | (not in plan) | ~15 lines | +15 | New `SourceCiphertextDecapsulationFailed` variant + docstring |
| `rust/shekyl-engine-core/src/engine/merge.rs` | (not in plan) | ~50–80 lines | +50–80 | Engine-side post-pass orchestration |
| `rust/shekyl-engine-core/src/engine/local_ledger.rs` (and `engine.rs`) | (not in plan) | ~10–20 lines | +10–20 | Async wrapper around `apply_scan_result_to_state` if (δ) chosen |
| `rust/shekyl-engine-state/src/transfer.rs` | (not in plan) | ~30 lines | +30 | Schema additions: 2 fields + Schema mirror + roundtrip-test extension |
| `rust/shekyl-engine-state/src/ledger_block.rs` | (not in plan) | ~6 lines | +6 | Roundtrip-test extension to cover new fields |
| `rust/shekyl-crypto-pq/src/output.rs` | (not in plan) | ~40 lines | +40 | New `recover_combined_ss` function |
| `rust/shekyl-crypto-pq/src/handle.rs` | (not in plan) | ~5 lines | +5 | `Serialize/Deserialize` derive + Schema impl |
| `rust/shekyl-crypto-pq/src/kem.rs` | (not in plan) | ~5 lines | +5 | `postcard_schema::Schema` derive on `HybridCiphertext` |
| `rust/shekyl-crypto-pq/tests/recover_combined_ss.rs` (new) | (not in plan) | ~60 lines | +60 | Layer-1 byte-identical test |
| `rust/shekyl-engine-core/tests/byte_identical_derivation.rs` (new) | ~100 lines | ~120 lines | +20 | Layer-2 byte-identical test |
| **Total net** | **~360 lines** | **~430–490 lines** | **+70–130** | Within the +600 net-line ceiling per execution prompt. |

The pre-flight estimate is ~20–35% over the plan estimate. The
overage concentrates in (a) the engine-core orchestrator work the
plan didn't explicitly call out (because it was framed as scanner-
side) and (b) the new-function/derive plumbing in `shekyl-crypto-pq`
the plan didn't budget separately. **All overage is mechanical and
review-bounded**; no unscoped substantive logic is introduced. If
review feedback finds the engine-core orchestrator changes too
large, **(δ) → (γ)** can compress by ~20 lines but not more.

---

## §5 Estimated commit progression

The execution prompt's suggested progression adapts to the Phase 1
dispositions as follows. Each commit is scoped to one concern;
commits 1–2 are independent of the scanner reroute and can be
written without the engine post-pass plumbing in place.

| # | Commit subject (proposed) | Files | Net lines | Rationale |
|---|---|---|---|---|
| 1 | `crypto-pq: extract re-decap-to-combined-ss primitive (D1 Layer 1)` | `shekyl-crypto-pq/src/output.rs` (extract new fn from `scan_output_recover` prefix; refactor `scan_output_recover` to call the new fn for compositional clarity); `shekyl-crypto-pq/tests/recover_combined_ss.rs` (new test file) | ~100 | Lands the cryptographic primitive standalone; existing `scan_output_recover` test vectors still pass via composition. |
| 2 | `crypto-pq: derive Serialize/Deserialize/Schema on OutputHandle and HybridCiphertext (D3)` | `shekyl-crypto-pq/src/handle.rs`; `shekyl-crypto-pq/src/kem.rs` | ~10 | Enables the schema additions in commit 4. |
| 3 | `engine-core: add SourceCiphertextDecapsulationFailed error variant (D6)` | `shekyl-engine-core/src/engine/error.rs` | ~15 | Lands the named-failure-mode variant as a standalone introduction; consumers land in commit 5. |
| 4 | `engine-state: add source_ciphertext + output_handle to TransferDetails (D3 schema)` | `shekyl-engine-state/src/transfer.rs`; `shekyl-engine-state/src/ledger_block.rs` (round-trip test only) | ~36 | Schema-only commit; no consumer logic yet. Postcard round-trip extension verifies wire stability. |
| 5 | `engine-core: TxInputSigningContext field swap source_secrets → source_ciphertext (D2)` | `shekyl-engine-core/src/engine/traits/key.rs` (field swap + Debug-impl simplification + redaction tests update + `output_index` addition); `shekyl-engine-core/src/engine/local_keys.rs` (consumer-side adjustments — `try_claim_output`'s impl is unaffected; `sign_transaction` stub body unaffected) | ~40 | Trait-surface change; consumers in `engine/pending.rs` etc. are pre-impl-stub today (`#[allow(dead_code)]` on every message type; per `key.rs`'s comments, consumers land in M3c+). |
| 6 | `engine-core: derive_source_secrets_bundle on LocalKeys (D1 Layer 2)` | `shekyl-engine-core/src/engine/local_keys.rs` | ~80 | Lands the bundle-composition method behind the trait. Used by M3b's byte-identical-derivation test in commit 8. |
| 7 | `engine-core: orchestrator-side handle population post-pass (§3 reroute)` | `shekyl-engine-core/src/engine/merge.rs`; `shekyl-engine-core/src/engine/{local_ledger,engine}.rs` (async wrapping per (δ)) | ~60–100 | The actual scanner-reroute equivalent — populates `td.source_ciphertext` and `td.output_handle` via `KeyEngine::try_claim_output`. |
| 8 | `engine-core: byte-identical-derivation property test (D5)` | `shekyl-engine-core/tests/byte_identical_derivation.rs` (new) | ~120 | Asserts new chain produces same bundle as legacy chain across distinct inputs. |
| 9 | `scanner: process_scanned_outputs preserves OutputDetectionInput residue` | `shekyl-scanner/src/ledger_ext.rs` (very small adjustment if needed); `shekyl-scanner/src/scan.rs` (any minor surface adjustments) | ~0–10 | If the engine post-pass needs a residue field in the carrier, this commit threads it through. May be no-op if `RecoveredWalletOutput`/`WalletOutput` already preserve everything. |
| 10 | `docs(stage-1-pr3): M3b landing notes; CHANGELOG; FOLLOWUPS` | `docs/CHANGELOG.md`; `docs/design/STAGE_1_PR_3_MIGRATION_PLAN.md` (M3b "Landing notes" sub-section); `docs/FOLLOWUPS.md` (V3.x close-records); this pre-flight document marked "executed" | ~40 | Closes out per `91-documentation-after-plans.mdc`. |

**Total estimated net lines:** ~500–550 (10 commits, average ~50/c).
**Cumulative-diff guardrail per execution prompt:** ≤600 net lines.
**Margin:** ~50–100 lines.

**Order discipline.** Commits 1–4 are mechanical / standalone /
purely-additive and can land in any order. Commit 5 (trait field
swap) is the structural lock; commit 6 depends on commit 5; commit
7 depends on commit 6; commit 8 depends on commits 6 + 7. Commits
9 and 10 are bookkeeping. **No commit relies on a future commit
to compile.** Each commit leaves the workspace `cargo check
--workspace --all-targets --all-features`-green per
`90-commits.mdc`'s bisection-friendly discipline.

---

## §6 Open questions — surface for user disposition before Phase 2

### Q1. Postcard schema shape (D3 disposition (α) vs (β)) — RESOLVED

**Decision: (α).** Derive `Schema` directly on `HybridCiphertext`
and `OutputHandle` in `shekyl-crypto-pq`. Confirmed by user
2026-05-08 conditional on transitive-dep verification, which
passed (zero new third-party crates per §2 D3 verification block).
M3b adds `postcard-schema = { version = "0.2", default-features =
false, features = ["derive", "use-std"] }` to
`shekyl-crypto-pq/Cargo.toml`. The pin matches the existing
`shekyl-engine-state` direct-dep pin.

### Q2. Engine post-pass placement (γ vs δ) — RESOLVED

**Decision: (δ) as permanent split, not transitional.** Confirmed
by user 2026-05-08 with framing pinned in §3 above. Sync helper
remains the bookkeeping-pipeline substrate; async sibling layers
engine integration. Both have legitimate consumers; the split is
load-bearing and intentional. M3b's commit message and helper
doc-comment must pin this framing explicitly.

### Q3. `KeyEngine` trait visibility post-M3b

`KeyEngine` is currently `pub(crate)`. M3b's engine post-pass is
in-crate (`shekyl-engine-core::engine::merge`), so visibility does
not need to change for M3b. **No action required at M3b**; the
visibility widening lands at the V3.2 wallet-RPC cutover per the
existing M3a Round 4a disposition. Surfaced for awareness.

### Q4. Subaddress index source for `derive_source_secrets_bundle` — RESOLVED

**Decision: parameter at M3b.** Confirmed by user 2026-05-08 with
the rationale that establishing the parameter early avoids the
compounding-call-sites pattern when PR 5 adds the handle-table
lookup. M3b ships
`LocalKeys::derive_source_secrets_bundle(source_ciphertext,
output_index, subaddress_idx)` with `subaddress_idx` populated
explicitly by callers (test code directly, future production code
from `TransferDetails::subaddress`'s existing field). PR 5 wires
the engine-internal handle-table lookup; the parameter shape stays
stable.

### Q5. Canonicalization of M3a "Landing notes" Divergence references

The execution prompt's §E refers to "M3a's Landing notes Divergence
3"; the PLAN.md's §3.1 has a "Landing notes (M3a closed)" sub-
section but the divergences are numbered locally. **No action for
M3b**; flagged so reviewers reading the M3b PR description can
locate the cross-reference if it becomes load-bearing in commit
messages.

---

## §7 Phase 2 entry conditions — ALL MET

| # | Condition | Status |
|---|---|---|
| 1 | All five audit invariants passed (§1) | ✅ Verified on `dev` tip `76d1d2e2c` |
| 2 | Q1 disposed (Postcard schema shape) | ✅ α confirmed; transitive-dep verification passed |
| 3 | Q2 disposed (Engine post-pass placement) | ✅ δ confirmed as permanent split |
| 4 | Q4 confirmed (subaddress-index parameter shape) | ✅ Parameter at M3b; PR 5 wires lookup |
| 5 | Line-count overage acknowledged (§4) | ✅ Reconciliation amendment to PLAN.md §3.2 lands as part of Phase 2 commit 10 |

**Phase 2 entry authorized** upon explicit user instruction to cut
`feat/stage-1-pr3-m3b` off `dev` and proceed per §5's commit
progression.

---

## §8 Discipline-application notes (post-resolution observations)

Pinned per user feedback 2026-05-08; these observations document
how the pre-flight investigation interacted with the project's
discipline framework, for the V3.x post-mortem record per
`16-architectural-inheritance.mdc`'s "Continuous discipline as
inheritance prevention" framing.

**The two-layer split for D1 was a framework production, not a
plan deliverable.** The migration plan (§3.2) named what to ship
(re-decap derivation primitive); it did not specify the shape.
Applying `18-type-placement.mdc`'s "transform-shaped lives with its
function; state-shaped lives with its owner" rule to the
`(view_secret, source_ciphertext) → SourceSecretsBundle` flow
yielded the Layer 1 (transform-shaped, in `shekyl-crypto-pq`) /
Layer 2 (state-shaped, in `shekyl-engine-core`) split. **The rule
produced the shape; the plan named the deliverable.** Worth
recording: this is the discipline-application cadence
`16-architectural-inheritance.mdc`'s §"Continuous discipline as
inheritance prevention" describes — continuous rule application
during pre-flight produces correct shape without an adversarial
round to surface it.

**The scanner-reroute correction (§3) was a layering-discipline
catch.** The plan's "scanner emits to engine" framing was
operationally infeasible because of the `shekyl-scanner` →
`shekyl-engine-core` dependency direction. Surfacing this in
pre-flight prevents a mid-implementation discovery; the
orchestrator-layer post-pass disposition in `shekyl-engine-core`
is the right correction. The lesson: framing-level estimates can
miss layering constraints that become load-bearing only at
implementation time. Pre-flight investigation that walks the
dependency tree alongside the call chain catches these earlier.

**The test-fixture estimate revision (§4) was an honest
re-estimation.** The plan's ~150 lines vs the pre-flight's ~10–20
lines is a ~85–93% reduction. The reduction comes from two
recognitions: (a) legacy fields stay populated transitionally, so
existing fixtures' shape is unchanged; (b) the engine post-pass is
exercised by integration tests via real `LocalKeys` /
`construct_output`, not by the synthetic
`wrap_recovered`/`mock_output` fixtures. Worth recording: this is
the kind of estimate that improves substantially with concrete
investigation versus framing-level guessing — the plan estimated
"what a test-rewrite of these fixtures would cost"; the pre-flight
discovered "no test-rewrite is needed."

**Net pre-flight value.** Three substantive corrections / framework
productions emerged from the investigation that the migration plan
alone would not have captured: D1 two-layer split, §3 scanner
reroute correction, §4 test-fixture estimate revision. The
pre-flight discipline produced what it should — sharper estimates
and corrected framings from concrete investigation versus
framing-level estimates from design rounds. Recorded for the V3.x
"discipline application is permanent" framing per
`16-architectural-inheritance.mdc`.

---

*Generated by Phase 1 pre-flight investigation per execution prompt;
no commits or branch operations performed.*
