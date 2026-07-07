# Phase 2a — send path: pre-flight audit trail

Sibling audit trail for `docs/design/PHASE_2A_SEND_PATH.md`, per
`26-sub-pr-design-discipline.mdc` §"Pre-flight pass (Round 0 disposition
naming)". Records, per sub-PR, the **substrate re-check** and **artifact
execution** that run between design closure and the first production commit.
Findings use stable IDs (`<sub-pr> PF#`) that must not be renamed; each maps to
the rule-26 discipline it instantiates.

The pre-flight pass is **not a redesign**. It catches design-time dispositions
falsified by impl-time substrate or by running produced artifacts. A
confirmatory pass (every cited claim still holds) is the expected steady-state
outcome per `16-architectural-inheritance.mdc` §"Operational implication for
forward extractions"; the pass's value is catching the cases where the
expectation breaks.

---

## 2a-2 pre-flight (Round 0) — signing context + fee/change directive + async wiring

**Run:** on `dev` at the 2a-1 merge (`#109`, merge `d78f68baa`), branch `dev`
up to date with `origin/dev`. Scope = the §5 2a-2 row: §3.7.2 signing-context
population, §3.10 F4/F8 orchestrator side, §3.1/§3.2 async boundary +
fee-source capability.

### Substrate re-check

Re-read every source file the 2a-2 dispositions cite, at the audit pin.

| Disposition (doc §) | Claim | Substrate at pin | Verdict |
|---|---|---|---|
| §3.1 async boundary | `build`/`submit` wrap `std::future::ready(build_sync/submit_sync)` | `local_pending_tx.rs:904–915` — `build` → `std::future::ready(self.build_sync(&request))`, `submit` → `std::future::ready(self.submit_sync(id))` | **Holds.** 2a-2 replaces the build-side wrap with an `async` block. |
| §3.2 least-authority | `LocalPendingTx` holds no `Arc<D>` god-object; fee-source/submitter are narrowed handles landing with first consumer | `local_pending_tx.rs:253–296` — fields are `signer: Arc<S>`, `output_selector: O`, `fee_estimator: F`, `ledger: Arc<L>`, `sink`; no daemon handle; submit uses a Phase-1 stub (`submit_daemon_outcome` test override + "daemon always accepts" `:765`) | **Holds.** No god-object present; submitter correctly absent (re-split puts it in 2a-3). |
| §3.2 2a-1 primitives | `DaemonEngine::{get_fee_estimates, submit_transaction}` exist for 2a-2/2a-3 to consume | `traits/daemon.rs:280, 308` | **Holds** (landed in 2a-1). |
| §3.7.2 reshape-from-`{}` | `FcmpPlusPlusContext`/`TxOutputContext` still empty; `TxToSign` top shape `{inputs, outputs, fcmp_plus_plus_context}` | `traits/key.rs:579` `TxOutputContext {}`, `:585` `FcmpPlusPlusContext {}`, `:547–553` `TxToSign`; `TxInputSigningContext:399` carries `source_ciphertext`/`output_index`/`handle` (pre-reshape) | **Holds.** Substrate matches the design's documented starting shape. |
| §3.10.1 W (weight) | `Transaction::weight() = serialize().len() + calculate_clawback(true, n_out).0`; clawback deterministic in `n_out`, 0 unless `n_padded_outputs > 2` | `transaction.rs:550–556` (`blob_size + Bulletproof::calculate_clawback(true, prefix.outputs.len()).0`); `fcmp/bulletproofs/src/lib.rs:80–95` (`if n_padded_outputs > 2`) | **Holds.** 2a `n_out ∈ {1,2}` ⇒ clawback 0 ⇒ `weight == blob_size` (smooth `fee_N→fee_{N+1}`). |
| §3.10.1 constants | `MAX_INPUTS = 8`, `MAX_TREE_DEPTH = 24`; ml-dsa-65 signature length constant present (~3309 B) | `shekyl-fcmp/src/lib.rs` (`= 8`, `= 24`); `shekyl-crypto-pq/src/signature.rs` `ML_DSA_65_SIGNATURE_LENGTH` | **Holds.** Grid bounds + PQC-auth dominance premise intact. |
| §3.10.2 dust nominal | `coin_select.rs` carries a nominal `dust_threshold = 1_000_000` to migrate to `dust()` | present (migration target) | **Holds** (migration target unchanged). |
| §3.10.3 `FeeDirective` | type does not yet exist (2a-2 populates) | no `FeeDirective` / `fee_no_change` / `fee_with_change` symbols in `shekyl-engine-core/src` | **Holds** (greenfield; 2a-2 introduces it). |

**Findings.**

- **2a-2 PF1 — `FeeEstimationContext` delta under-specifies the fee snapshot
  (rule-26 B6 / under-specification; §3.10.3 vs §5 re-split note).**
  §3.10.3's enumerated `FeeEstimationContext` surface delta lists **only**
  `output_count: usize`. But the §5 re-split note (and §3.3's atomic-snapshot
  decision) require the §3.3 `FeeEstimates` snapshot to **feed**
  `FeeEstimationContext` so the **synchronous** `FeeEstimator::estimate_fee`
  (`fee_estimator.rs:199`, frozen trait surface — "the trait surface does not
  re-open") can compute a daemon-derived (non-stub) fee. The current context
  (`fee_estimator.rs:120–134`) carries only `ledger`/`recipient_count`/
  `input_count`; without the snapshot field it cannot produce a real fee or the
  `Custom` `quantization_mask` (§3.3). **Disposition:** in-scope pin, not a
  reopen — `estimate_fee`'s signature is preserved; the change is to the
  `FeeEstimationContext` **struct**, which the §5 2a-2 row already lists as
  reshaped. 2a-2 adds **both** `output_count` **and** a `fee_snapshot:
  FeeEstimates` (or `&FeeEstimates`, carrying `quantization_mask`) to the
  context. `build`'s async block fetches the snapshot once via the §3.2
  fee-source handle, populates the context, then calls the unchanged sync
  `estimate_fee`. Fold this into §3.10.3.

- **2a-2 PF2 — fee-source handle placement on `LocalPendingTx` unpinned (§3.2;
  minor).** §3.2 says the fee-source is "a capability-narrowed handle (cloned
  from the engine's daemon at `assemble`)," but does not say **where** it lives:
  a new `LocalPendingTx` field distinct from `fee_estimator: F`, vs. folding the
  handle into a now-stateful `DaemonFeeEstimator` (currently zero-sized,
  `#[derive(Copy, Default)]`, `fee_estimator.rs:225`). **Disposition:** in-scope
  pin. Preferred shape (keeps the frozen sync `FeeEstimator` strategy and the
  `Copy` zero-sized `DaemonFeeEstimator` intact): the fee-source is a **separate
  narrowed capability** held alongside `fee_estimator: F` and consumed in
  `build`'s async block — **not** by making `DaemonFeeEstimator` stateful (that
  would couple I/O into the strategy trait and break its `Copy`/zero-sized
  shape). Confirm against `Engine`'s `assemble` site when 2a-2 wires it; record
  the chosen field in the 2a-2 commit.

- **No falsified dispositions.** Every §3.1 / §3.7.2 / §3.10.1 source-verified
  claim holds at the pin. The pass is **confirmatory** for the weight model,
  signing-context starting shapes, and async boundary — the expected
  forward-extraction outcome.

### Artifact execution

The §3.10.1 `predict_weight == tx.weight()` self-consistency grid and the
`fcmp_proof_size` KAT (`[1,8]×[1,24]`) are **explicitly 2a-3-gated** (they need
the 2a-3 encoder for a serializable tx; §3.10.1 "Gated on the 2a-3 encoder
existing"). They are **not runnable at 2a-2 pre-flight** and are not a 2a-2
gate. For 2a-2 the in-scope artifact is the substrate baseline the work
extends:

| Artifact | Result |
|---|---|
| `cargo test -p shekyl-engine-core fee_estim` | 11 passed; 0 failed |
| `cargo test -p shekyl-engine-core --lib engine::local_pending_tx` | 19 passed; 0 failed |
| `cargo test -p shekyl-engine-core --lib engine::pending` | 12 passed; 0 failed |

Baseline green; no budget/threshold reconciliation applies at 2a-2 (no
plan-doc numeric **budget** is gated on 2a-2; the measured grid is 2a-3, per
rule-26 B9 the threshold gate lands with the bench that measures it).

### Verdict

**2a-2 is clear to implement.** Substrate re-check confirmatory; baseline
green. Two in-scope pins (PF1, PF2) fold into §3.10.3 / §3.2 — neither is a
frozen-signature reopen (rule-26 A1), so **no design round is required**. The
`FeeEstimator::estimate_fee` trait surface is preserved; PF1/PF2 reshape the
`FeeEstimationContext` struct and add a sibling capability, both already named
in the §5 2a-2 row.

---

## 2a-3 pre-flight (Round 0) — sign, wire encode, submit

**Run:** branch `torvaldsl/2a-3-sign-wire-submit` off `dev`, scope = §5 2a-3 row.

### Substrate re-check

| ID | Finding | Disposition pinned |
|----|---------|-------------------|
| **PF1** | `SignTransaction` empty marker; `TxToSign` not `Clone` | `SignTransaction { tx: TxToSign }`; `KeyEngine::sign_transaction(tx: TxToSign)` by value across mailbox |
| **PF2** | Handle → `output_index` co-location | `tx_hash`, `internal_output_index`, `amount` on `TxInputSigningContext`; actor asserts `handle == derive_output_handle(view_sk, tx_hash, index)` |
| **PF3** | `Change` bare variant | `Change { subaddress_index: SubaddressIndex(0) }` for 2a single-recipient sends |
| **PF4** | `sign_pqc_auths` API | Verified at workspace pin in `shekyl-tx-builder/src/sign.rs` |
| **PF5** | `shekyl-oxide` wire surface | `Transaction::V2`, `Proofs`/`PrunableProof`, `Transaction::weight()` at pin |
| **PF6** | Sync `Signer::sign_transfer` under Tokio | **Reject** `block_on`/`block_in_place`; `Signer::sign_transfer` → `async`; `build_assemble_sync` + async sign in `build` |
| **PF7** | KAT grid `[1,8]×[1,24]` | Depth-parametric `synthetic_tree` helper (placeholder siblings); full grid in Phase F |
| **PF8** | C7 key-image single-site | Canonical `KeyImage` on `TxInputSigningContext` from `TransferDetails`; bridge consumes, no `compute_output_key_image` |

### Artifact execution

Baseline commands from §5 2a-3 plan (`cd rust && …`) run before first production commit.

### Verdict

**2a-3 clear to implement.** PF6/PF7/PF8 dispositions pinned above; no design round required.

---

## 2a-3 post-implementation verdict

**Branch:** `torvaldsl/2a-3-sign-wire-submit` (land on `dev` when reviewed).

### Delivered

| Item | Status |
|------|--------|
| `wire.rs` + `shekyl-oxide` dep (wire-only import guard) | Done |
| `sign_bridge` + `KeyActor` one-round-trip sign (C3/C4/F4/F8, C7) | Done |
| `TxSignatures` reshape; `OutputInfo` `ZeroizeOnDrop` | Done |
| Async `Signer::sign_transfer`; `build_assemble_sync` split | Done |
| `TransactionSubmitter` + real `tx_bytes` submit | Done |
| Non-empty `tx_bytes` on transfer path | Done |
| `fcmp_proof_size` depth-1 KAT row (`n_in` 1..8) | Done (`kat_fcmp_proof_size_depth1_row`) |
| `predict_weight == Transaction::weight()` on build path | Done (`build_then_submit_marks_outputs_spent`) |

### PF7 partial (reopening criterion)

Full `[1,8]×[2,24]` `fcmp_proof_size` grid measurement fails above `tree_depth = 1`
(`Branches::new` on placeholder branch paths). **Disposition:** depth-1 row is
KAT-pinned in `tx_fee_model.rs`; depth > 1 uses
`FCMP_PROOF_BYTES_PER_DEPTH_LAYER` extrapolation until CT-5 curve-tree fixtures
replace the synthetic branch builder. Reopen when depth-parametric synthetic
trees prove at `tree_depth > 1` (same criterion as plan PF7).

### Artifact execution

| Layer | Result |
|-------|--------|
| `cargo test -p shekyl-tx-builder` | pass (incl. wire import guard) |
| `cargo test -p shekyl-engine-core --lib engine::local_pending_tx` | 19 pass |
| `cargo test -p shekyl-engine-core --lib kat_fcmp_proof_size_depth1_row` | pass |
| M3c `engine_derived_bundle_signs_through_tx_builder_end_to_end` | pass |

### Verdict

**2a-3 implementation complete** for the §5 row scope; 2a-4 owns TestDaemon
build→submit integration and doc closeout.

---

## 2a-4 pre-flight (Round 0) — TestDaemon integration + closeout

**Run:** branch `torvaldsl/2a-4-hybrid-send-test` off `dev`, scope = §5 2a-4 row +
[`PHASE_2A_SEND_PATH.md`](PHASE_2A_SEND_PATH.md) §8 + §10 closeout.

**Pinned `dev` HEAD:** `9494adc31` (merge PR #118, 2a-3).

### Baseline

| Command | Result |
|---------|--------|
| `cargo fmt --check` | pass |
| `cargo clippy -p shekyl-engine-core --all-targets -- -D warnings` | pass |
| `cargo test -p shekyl-engine-core --lib engine::local_pending_tx` | 19 pass |
| `cargo test -p shekyl-engine-core --lib engine::test_support` | 24 pass |

### Substrate re-check

| Claim | Source | Verdict |
|-------|--------|---------|
| Production pending uses `DaemonFeeSnapshotSource` + `DaemonTransactionSubmitter` | `lifecycle.rs:738–752` | **Holds** |
| `TestDaemon` submit hash = `cn_fast_hash`; dedup → `AlreadyKnown` | `test_support.rs` tests | **Holds** |
| `build_then_submit` uses stub fee/submit, not `TestDaemon` | `local_pending_tx.rs` tests | **Holds** — 2a-4 target |
| Custom-only sanity ceiling (`tx_fee_model.rs:114–118`) | code | **Holds** — §8.2 tests Custom; daemon-tier ceiling is §10 security residual |
| PF7 partial grid deferred | 2a-3 PF7 | **Holds** — does not block 2a-4 |
| `submit_sync` consumes reservation on first accept | `finalize_submit_accept` | **Holds** — second `pending.submit(id)` → `ReservationNotFound`; §8.3 dedup via second `DaemonTransactionSubmitter::submit(bytes)` |
| §8.4 parse-back retry test | plan disposition | **Dropped** — vacuous under reservation lifecycle; redundant with §8.3 byte dedup; dominated-negative vs encode-only wire pin |

### Verdict

**2a-4 clear to implement.**

---

## 2a-4 post-implementation verdict

**Branch:** `torvaldsl/2a-4-hybrid-send-test`.

### Delivered

| Item | Status |
|------|--------|
| §8.1 `daemon_fee_estimator_maps_test_daemon_priority_tiers` | Done |
| §8.2 `custom_fee_above_sanity_ceiling_rejected` (Custom-only; documents implemented path) | Done |
| Output reservation before `await sign_transfer` (`BuiltPendingMeta` + `release_build_reservation`) | Done |
| `reserved_outputs_blocked_from_second_build` | Done |
| §8.3 `build_then_submit_via_test_daemon_uses_daemon_fee` (daemon rate → `tx.fee`) | Done |
| §8.3 `daemon_dedupes_identical_tx_bytes` (second submitter submit, not second `pending.submit`) | Done |
| `assemble_tx_to_sign_rejects_missing_key_image` | Done |
| §8.4 parse-back retry | **Dropped** — vacuous under reservation lifecycle; redundant with §8.3 byte dedup; contradicts encode-only wire pin |

### Artifact execution

| Layer | Result |
|-------|--------|
| `cargo test -p shekyl-engine-core --lib engine::fee_estimator` | pass |
| `cargo test -p shekyl-engine-core --lib engine::tx_fee_model` | pass |
| `cargo test -p shekyl-engine-core --lib engine::local_pending_tx` | 23 pass |

### §10 reconciliation (2a-4 closeout)

| §10 item | Action |
|----------|--------|
| §1 DoD hybrid TestDaemon test | **Tick** — integration asserts daemon-derived `tx.fee` |
| Daemon-tier fee sanity ceiling (`DaemonFeeUnreasonable`) | **Defer (security residual)** — impl ceilings Custom only (`tx_fee_model.rs:114-118`); reopen before wallet build against untrusted daemon |
| Output reservation before async sign | **Tick** — locks at assembly; released on sign failure |
| §3.7.3 TxSignatures reshape / `OutputInfo` ZeroizeOnDrop | **Tick** — 2a-3 |
| §3.7.8 C5 structural test | **Defer** — Debug redaction only; reopen when SpendInput field-coverage test lands |
| §3.9 B/C/D refinements | **Tick** non-Clone / handle path; **defer** `dest` zeroize to 2c |
| §3.10.1 full KAT grid | **Defer** — depth-1 row + analytic depth slope; depth-2 cell optional follow-up |
| §3.10.2/3 dust/FeeDirective | **Tick** — build path proved |
| §3.7.4 sign-bit-canonical | **Tick** — missing-KI negative test + scan path |
| §3.3 two-pass fee loop | **Tick** — `converge_fee_is_stable_within_two_passes` |
| §3.0.3 bulk-leaf RPC + KAT | **Defer** — shekyld prereq |
| §3.0.4 curve-tree client scoped | **Tick** — `CURVE_TREE_CLIENT.md` |
| `WALLET_REWRITE_PLAN.md` cross-link | **Tick** — orchestrator todo stays `pending` |

### Verdict

**Engine substrate complete:** `LocalPendingTx` build→submit proven with production
`DaemonFeeSnapshotSource` / `DaemonTransactionSubmitter` + `TestDaemon`; daemon fee
bound in integration test; reservation before async sign.

**Not claimed:** mainnet validity (real curve-tree roots, daemon structural validation) —
CT-5 + mainnet gate.

**Orchestrator Phase 2a** (`Wallet::build_pending_tx` / refresh send surface): **pending
Phase 1** — see `WALLET_REWRITE_PLAN.md` `phase2_ops_refresh_send`.
