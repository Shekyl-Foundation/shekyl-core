# Primary claim derivation — vocabulary and API cleanup

**Status.** **Approved** (2026-06-07). **Implementation gated on FA-8
(PR #113) landing on `dev`** — execute this work immediately after; do not
start PR B while FA-8 is in flight.

**Binding decisions (do not relitigate).**

- [`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) — Subaddresses dropped
  at V3.0 (End-state 5); one primary per account; payment requests (FA-8)
  for merchant attribution.
- [`SUBADDRESS_UNDER_PQC.md`](SUBADDRESS_UNDER_PQC.md) §5.7 — closed
  R2-F2; no `create_subaddress` at V3.0.
- [`V3_WALLET_DECISION_LOG.md`](../V3_WALLET_DECISION_LOG.md) — 2026-06-07
  End-state 5 entry supersedes flat `SubaddressIndex` product surface.
- FA-2 (PR #112) deleted user-facing multi-address UX and scanner lookup
  tables; **this work finishes FA-2's residue** — inherited Monero/CryptoNote
  *names* that still imply “array of receive addresses.”

**Timeframes.**

- **Now (V3.0):** rename/narrow/delete misleading APIs; production paths
  hardcode primary-only (`idx = 0` spend offset).
- **Mining era / V4:** unchanged wire math; genesis-locked `m_0` derivation
  remains byte-identical.
- **P3 (T2):** seed-derived **multi-account** is a separate primitive —
  not a reopening of Monero subaddresses (see §Reopening).

---

## 1. What the remaining math actually is

The load-bearing primitive is **not** “derive another address to give someone.”
It is the spend-side offset when claiming an output paid to the wallet's
**primary** hybrid address:

```text
decapsulate(ciphertext) → combined_ss
derive_output_secrets(combined_ss, output_index) → ho, y, …
m₀ = H("shekyl-subaddr-v1\0" || view_scalar_le32 || 0u32_le)   // idx = 0 only in production
x  = ho + b + m₀                                                // signing / key image
```

At V3.0 **only `idx = 0`** is used on production paths. See
`rust/shekyl-engine-core/src/engine/local_keys.rs` (FA-2 comment block and
`derive_source_secrets_bundle`).

### Critical nuance (document once — do not “fix” back to Monero)

| Surface | Spend key material | Notes |
|---------|-------------------|--------|
| **Encoded primary address** (what senders pay) | Base spend key `D` | `AllKeysBlob::classical_address_bytes` / `rederive_account` |
| **Output claim / signing path** | Uses `m₀` from index `0` | `x = ho + b + m₀`; `m₀ ≠ 0` in general |
| **Hypothetical `idx ≥ 1` derivation** | `D + mᵢ·G` | **Not a V3.0 product feature** — math exists for genesis lock only |

This is CryptoNote inheritance, not multi-address. The new names and crate
docs must state this explicitly so a maintainer does not “simplify” signing
to use bare `b` (wrong) or route the displayed address through
`subaddress_keys(0)` (also wrong for display).

---

## 2. Grep enumeration (2026-06-07, `dev` tip)

### 2.1 Primary targets

```text
rg -n 'SubaddressIndex|subaddress_derivation_scalar|subaddress_keys|subaddress_idx|subaddress_registry|create_subaddress|subaddress_lookahead' rust/
→ 260 lines across 35 files
```

| Symbol / pattern | Approx. hits | Crates / locations |
|------------------|-------------|-------------------|
| `SubaddressIndex` | ~180 | `shekyl-engine-state` (type + ledger), `shekyl-engine-core`, `shekyl-scanner`, benches |
| `subaddress_derivation_scalar` | ~25 | `shekyl-crypto-pq`, `shekyl-engine-core` (local_keys tests) |
| `subaddress_keys` | ~20 | `shekyl-crypto-pq`, `shekyl-engine-core`, `shekyl-scanner/view_pair.rs` |
| `subaddress_idx` (param/comment) | ~15 | `local_keys.rs`, `traits/key.rs`, tests |
| `subaddress_registry` | ~25 | `bookkeeping_block.rs`, `local_keys.rs`, `key_actor.rs`, schemas, invariants |
| `create_subaddress` | 0 in `rust/` | Product API already absent |
| `subaddress_lookahead` | 8 | `shekyl-crypto-pq/wallet_state/settings.rs`, `shekyl-engine-prefs/schema.rs` |

### 2.2 Broad `subaddress` scan

```text
rg -n 'subaddress' rust/ → 426 lines across 48 files
```

Key vestigial modules called out in source:

| File | Role today |
|------|------------|
| `rust/shekyl-crypto-pq/src/subaddress.rs` | Genesis-locked `mᵢ` + `(spend, view)` point derivation |
| `rust/shekyl-engine-state/src/subaddress.rs` | Public `SubaddressIndex` type |
| `rust/shekyl-scanner/src/subaddress.rs` | Re-export shim (“removed in Commit 2n” — still present) |
| `rust/shekyl-engine-state/src/bookkeeping_block.rs` | `subaddress_registry`, `SubaddressLabels` (FA-2 deletion incomplete in schema) |
| `rust/shekyl-scanner/src/scan.rs` | `register_subaddress`, `HashMap<…, SubaddressIndex>` |
| `rust/shekyl-engine-core/src/engine/traits/key.rs` | `derive_subaddress`, `SubaddressPurpose`, `SubaddressFor` |
| `rust/shekyl-cli/src/commands/mod.rs` | Help text: `address new`, `--subaddr-index` (stale) |

Wallet settings / metadata:

| Location | Field |
|----------|-------|
| `shekyl-crypto-pq/.../settings.rs` | `subaddress_lookahead: SubaddressLookahead` |
| `shekyl-engine-prefs/schema.rs` | same |
| `shekyl-scanner/src/output.rs` | `Metadata.subaddress: Option<SubaddressIndex>` |
| `shekyl-engine-state/src/transfer.rs` | `TransferDetails.subaddress` |
| Postcard schemas | `subaddress_registry`, `SubaddressIndex` in three `.snap` files |

Docs (historical — keep, update cross-links):

| Doc | Role |
|-----|------|
| `docs/design/SUBADDRESS_UNDER_PQC.md` | Authoritative End-state 5 closure |
| `docs/design/WALLET_REWRITE_PLAN.md` | Phase 2c / cross-cutting |
| `docs/FOLLOWUPS.md` | Design-round history (§1111+) |
| `docs/V3_WALLET_DECISION_LOG.md` | Supersession chain |
| `docs/WALLET_PREFS.md` | Stale `subaddress_lookahead_*` table rows |

### 2.3 CryptoNight (out of scope for this PR series)

```text
rg -n 'cryptonight|CryptoNight' src/ docs/ → 59 lines
```

Per `60-no-monero-legacy.mdc`, PoW residue is tracked in
[`CPP_INHERITANCE_INVENTORY.md`](../CPP_INHERITANCE_INVENTORY.md) and
[`RANDOMX_V2_PLAN.md`](RANDOMX_V2_PLAN.md) Phase 3c — **not** mixed into
this rename unless a drive-by is &lt;10 lines (it is not: 59 hits).

**FOLLOWUPS disposition:** record “CryptoNight vocabulary purge” as existing
RandomX v2 Phase 3c work; no action in primary-claim PRs.

---

## 3. Classification (delete | rename | collapse | test-only)

### 3.1 `shekyl-crypto-pq`

| Item | Disposition |
|------|-------------|
| `pub mod subaddress` | **Rename** → `output_claim` (or `spend_scalar_offset`; see §4) |
| `subaddress_derivation_scalar` | **Rename** → `output_spend_offset_scalar` (public); keep byte layout |
| `subaddress_keys` | **Delete** from public API (no V3.0 caller for `idx ≥ 1`) |
| `ViewPair::subaddress_keys` (scanner) | **Delete** with scanner table removal |
| `wallet_state::SubaddressLookahead` | **Delete** field + type |
| Module / key docs mentioning “subaddress registry” | **Rewrite** |

### 3.2 `shekyl-engine-state`

| Item | Disposition |
|------|-------------|
| `pub mod subaddress` + `SubaddressIndex` | **Delete** from public re-exports |
| `SubaddressIndex::new(n)` for `n > 0` | **Remove** — no public constructor for non-zero |
| `PRIMARY` constant / `to_canonical_bytes()` | **Move** to `shekyl-crypto-pq::output_claim` as `PRIMARY_CLAIM_INDEX_LE` (`[0,0,0,0]`) or internal `const PRIMARY_INDEX: u32 = 0` |
| `BookkeepingBlock::subaddress_registry` | **Delete** (FA-2 residue; FA-8 `PaymentRequest` replaces) |
| `SubaddressLabels` | **Delete** |
| `TransferDetails::subaddress` | **Delete** (single coordinated schema bump in PR C — §6) |
| `invariants::check_subaddress_registry_dense` | **Delete** |
| `ledger_block::spendable_outputs(..., subaddress: Option<…>)` | **Delete** filter parameter |

### 3.3 `shekyl-engine-core`

| Item | Disposition |
|------|-------------|
| `LocalKeys::subaddress_registry` | **Collapse** — primary-only: `recovered_spend == keys.spend_pk` |
| `derive_subaddress` / `SubaddressPurpose` / `SubaddressFor` / … | **Delete** trait surface |
| `derive_source_secrets_bundle(..., subaddress_idx)` | **Collapse** — drop param; always `m₀` |
| `PendingTxRequest::from_subaddress` | **Delete** |
| `key_actor` mirror of above | **Same** as `LocalKeys` |
| Property tests using `SubaddressIndex::new(1|42)` | **Reframe** — `output_spend_offset_scalar` unit tests in `crypto-pq` only; engine tests use PRIMARY-only |

### 3.4 `shekyl-scanner`

| Item | Disposition |
|------|-------------|
| `src/subaddress.rs` shim | **Delete** |
| `register_subaddress` | **Delete** |
| `ScanState.subaddresses` map | **Collapse** — single primary spend point `D` (optional `None` sentinel for “primary” in metadata) |
| `Metadata.subaddress` | **Delete** from wire metadata (+ scanner metadata version if applicable) |
| `view_pair::subaddress_keys` | **Delete** |

### 3.5 Other

| Item | Disposition |
|------|-------------|
| `shekyl-engine-prefs::SubaddressLookahead` | **Delete** |
| `shekyl-cli` help strings | **Rewrite** (payment requests, not subaddresses) |
| `shekyl-ffi` comment | **Rewrite** one doc line |
| Benches/fixtures using random `SubaddressIndex` | **Collapse** to `None` / primary |

---

## 4. Ratified naming (2026-06-07)

Module name **`output_claim`** (not `spend_scalar_offset`): describes what the
primitive *does* when read at call sites; the function inside remains
`output_spend_offset_scalar` (what `mᵢ` *is*).

| Today | Problem | Proposed |
|-------|---------|----------|
| `shekyl_crypto_pq::subaddress` | Product vocabulary on crypto | **`output_claim`** — “claiming an output’s spend scalar,” not “another address” |
| `subaddress_derivation_scalar` | Implies subaddress product | **`output_spend_offset_scalar`** — `mᵢ` in `x = ho + b + mᵢ` |
| `subaddress_keys` | Implies payable address list | **Delete public**; if KAT needs `idx ≥ 1`, keep **`pub(crate) fn derived_spend_point_for_test`** in `output_claim` with module comment |
| `SubaddressIndex` | Implies many addresses | **Delete** public type |
| Internal index bytes | Still genesis-locked | **`PRIMARY_CLAIM_INDEX: [u8; 4] = [0,0,0,0]`** in `output_claim`; no `new(42)` |
| `derive_source_secrets_bundle(..., idx)` | Caller picks “address” | **`derive_primary_source_secrets_bundle(...)`** — no index param |
| `subaddress_registry` | Monero wallet2 | **`primary_spend_pk`** field or inline compare to `spend_pk` |
| `subaddress_lookahead` | Monero wallet2 scan window | **Delete** |
| `derive_subaddress` | Product API | **Delete** |
| `TransferDetails.subaddress` | Persisted routing | **Delete** field |
| `Metadata.subaddress` (scanner) | Scan routing | **Delete** field |

**Rejected alternate:** `primary_claim_scalar` — accurate for V3.0 but wrong
name if P3 multi-account reintroduces per-account `m₀` with the same function;
`output_spend_offset_scalar(view, idx_le)` stays index-parameterized **inside**
`output_claim` as `pub(crate)` for KATs only.

---

## 5. Target API discipline

### 5.1 Production rules

1. No public Rust API accepts `u32` / index for “which receive address.”
2. No `register_*`, `create_*`, or `list_*` for derived receive keys.
3. Crate-level `//!` in `shekyl-crypto-pq` and `shekyl-engine-state`:
   **one primary receive address per account; no subaddress namespace at V3.0.**
4. `try_claim_output` / scanner: ownership iff recovered `B' == D` (base spend
   pk), not `B' ∈ registry`.

### 5.2 Crypto module shape (`shekyl-crypto-pq::output_claim`)

```rust
//! Primary output claim — spend offset mᵢ for signing (V3.0: i = 0 only).
//!
//! Display/payment address uses base spend key D; signing uses m₀. See
//! docs/design/PRIMARY_CLAIM_DERIVATION_RENAME.md §1.

pub const PRIMARY_CLAIM_INDEX_LE: [u8; 4] = [0, 0, 0, 0];

/// mᵢ = keccak256_to_scalar("shekyl-subaddr-v1\0" || view_le32 || idx_le4)
pub fn output_spend_offset_scalar(view_scalar: &Scalar, idx_le_bytes: &[u8; 4]) -> Scalar { … }

// pub(crate) for KAT / index-sensitivity tests only — not product:
// fn derived_spend_view_points_for_test(...) -> (EdwardsPoint, EdwardsPoint)
```

Byte outputs of `output_spend_offset_scalar` with `PRIMARY_CLAIM_INDEX_LE`
**must remain identical** to today's `subaddress_derivation_scalar` KAT
(`derivation_scalar_pinned_vector`).

### 5.3 Engine (`derive_primary_source_secrets_bundle`)

```rust
pub(crate) fn derive_primary_source_secrets_bundle(
    &self,
    source_ciphertext: &HybridCiphertext,
    output_index: u64,
) -> Result<SourceSecretsBundle, KeyEngineError>
```

Hardcodes `PRIMARY_CLAIM_INDEX_LE` internally. Property tests that swept
`idx ∈ {0,1,42}` **move** to `shekyl-crypto-pq` (scalar sensitivity) and
**shrink** engine tests to primary-only end-to-end vectors.

---

## 6. PR sequence (short-lived branches off `dev`)

| PR | Scope | Gates |
|----|-------|-------|
| **A — Spec** | This doc + reviewer sign-off | — |
| **B — crypto-pq** | Module rename; KAT rename; delete `subaddress_keys` from public API; delete `SubaddressLookahead` from wallet_state settings | `cargo test -p shekyl-crypto-pq`; pinned vector unchanged |
| **C — engine-state** | Delete `SubaddressIndex`, bookkeeping subaddress fields, `TransferDetails.subaddress`; **one coordinated schema bump** (`BOOKKEEPING_BLOCK_VERSION` + `LEDGER_BLOCK_VERSION` as needed) + `UPDATE_SNAPSHOTS=1` | `schema_snapshot`; proptests |
| **D — engine-core + scanner** | Delete trait subaddress surface; collapse registries; scanner primary-only; delete shim modules | `cargo test -p shekyl-engine-core -p shekyl-scanner` |
| **E — prefs + CLI + docs** | `shekyl-engine-prefs`; CLI help; `WALLET_REWRITE_PLAN.md` inventory line; `FOLLOWUPS.md` closure note; `CHANGELOG.md` | `cargo fmt --check`; `clippy -D warnings` |

Each PR: subsystem-prefixed commits (`crypto-pq:`, `engine-state:`, …),
reference this doc section. **No push without explicit instruction.**

**Gate:** FA-8 (#113) must land on `dev` first (payment-request
`BookkeepingBlock` shape). Then branch `chore/primary-claim-rename` and run
PR B→E. FA-2 (#112) is already assumed merged. PR C performs **one** schema
bump covering all subaddress-field deletions together (pre-genesis:
`rm -rf ~/.shekyl`).

---

## 7. Test strategy

| Layer | Action |
|-------|--------|
| **KAT** | Rename test fns only; **do not change** `EXPECTED_BYTES` for idx=1 vector (proves rename didn't alter math) |
| **Index sensitivity** | Stay in `crypto-pq`; doc comment: “index sensitivity; V3.0 production uses `PRIMARY_CLAIM_INDEX_LE` only” |
| **Engine property tests** | Remove `SubaddressIndex::new(1\|42)` from product-shaped tests; keep one PRIMARY e2e claim path |
| **Scanner** | Bench fixtures: stop registering fake subaddresses; use primary `D` only |
| **Schema** | **One bump** in PR C: `BOOKKEEPING_BLOCK_VERSION` + `LEDGER_BLOCK_VERSION` (subaddress field deletions); prefs version in PR E if lookahead removed |

Success: a new contributor `rg subaddress rust/` finds **no public API**
suggesting multi-address; only `pub(crate)` test helpers and comments pointing
at this doc / `SUBADDRESS_UNDER_PQC.md`.

---

## 8. Documentation updates (PR E)

- [`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) — inventory bullet: replace
  `SubaddressIndex` with “primary claim derivation (`output_claim`)”.
- [`SUBADDRESS_UNDER_PQC.md`](SUBADDRESS_UNDER_PQC.md) — add §5.7.13 pointer
  to this doc as implementation hygiene post-R2-F2.
- [`FOLLOWUPS.md`](../FOLLOWUPS.md) — close / annotate “subaddress vocabulary
  residue” when PR E lands.
- [`WALLET_PREFS.md`](../WALLET_PREFS.md) — delete lookahead rows.
- [`CHANGELOG.md`](../CHANGELOG.md) — user-visible: “removed subaddress
  settings and APIs; signing math unchanged.”
- `local_keys.rs`, `engine/mod.rs` module docs — replace FA-2 placeholder
  text with pointer to §1 nuance table.

---

## 9. Reopening clauses (`21-reversion-clause-discipline.mdc`)

### 9.1 Monero-style subaddresses — **rejected at V3.0**

**Rejection.** Flat `SubaddressIndex`, `subaddress_registry`,
`create_subaddress`, per-index hybrid addresses, and `subaddress_lookahead`
contradict End-state 5 and the PQC scan-cost model
(`SUBADDRESS_UNDER_PQC.md` §4–5).

**Reopening criteria.** None for V3.x. This is not “defer”; it is
**rejected with no Monero-subaddress reopening path.** If a future maintainer
needs per-invoice attribution, the sanctioned mechanism is **payment requests**
(FA-8), not address indices.

**Re-evaluation shape.** N/A — product decision closed R2-F2.

### 9.2 Seed-derived multi-account (T2, P3) — **distinct primitive**

**Rejection now.** Do not implement T2 under subaddress names or
`SubaddressIndex(u32)` reuse.

**Reopening criteria.** Explicit P3 design round lands per
`SUBADDRESS_UNDER_PQC.md` §5.7.3: `HKDF(master_seed, "shekyl-account-v1", i)`
→ independent keypairs; FA-6-aware multi-decap scan; wallet UX for
account picker.

**Re-evaluation shape.** New types (`AccountIndex` or similar), new persistence
block — **not** resurrection of `subaddress_keys` / registry. May **reuse**
`output_spend_offset_scalar` **per account** with that account's view secret
(same genesis-locked formula, different inputs) — that is not “subaddresses.”

### 9.3 `output_spend_offset_scalar` with `idx ≠ 0`

**Rejection now.** No production caller; no public `subaddress_keys`.

**Reopening criteria.** A spec'd cryptographic need emerges that is **not**
Monero subaddresses and **not** T2 — e.g. a consensus-visible derivation slot
with a named domain tag bump. Unlikely; listed for completeness.

**Re-evaluation shape.** Design doc amendment + new KAT vectors + hard-fork
gate if wire-affecting.

---

## 10. Review checklist

- [x] Naming table ratified — **`output_claim`** module; `output_spend_offset_scalar` function
- [x] FA-8 gate — implement **after** PR #113 lands; no parallel work
- [x] Schema bump — **one** coordinated bump in PR C (`TransferDetails` + bookkeeping subaddress deletions)
- [x] §1 nuance table accepted (display `D` vs signing `m₀`)
- [x] §9 reopening clauses accepted (9.1 vs 9.2 distinction)
- [x] CryptoNight explicitly deferred (§2.3)

**Next step (post FA-8):** branch `chore/primary-claim-rename` off `dev`,
implement PR B→E in order.
