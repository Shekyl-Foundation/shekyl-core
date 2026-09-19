# F-7 — test-only FFI exports in the production archive: finding record

**Status:** OPEN — finding record for FOLLOWUPS **F-7**, opened 2026-09-19
(PR #786, the S-TX pre-flight, which found the class again through
`scripts/ci/check_test_only_features.py`'s governance-trigger limb). This
file carries the source audit; the FOLLOWUPS row carries one sentence and a
link (rule 95). Owner: the lane that lands F-7's structural gate — **not**
S-TX. Every `file:line` below was read at `dev` `090f2e8f2`–`6c41bf820`;
re-verify before acting on one.

## 1. The row this record serves

**F-7 structural gate for the test-only FFI exports shipped in the production archive.** The PQC test helpers (`shekyl_pqc_keypair_generate`, `shekyl_pqc_sign_multisig_participant`, added under `shekyl-crypto-pq`'s `test-utils` feature because cmake builds one `-p shekyl-ffi` archive that every binary links) ship in production through feature unification; the header and Rust docs mark them, but nothing structural keeps them out. The curve-tree replica family `shekyl_curve_tree_replica_*` (PR #623 — the core_tests generator's header-root oracle, `rust/shekyl-ffi/src/curve_tree_replica_ffi.rs`) is the same class and belongs to the same gate. Remedy: a separate test-only archive, or a cmake feature that production targets never enable, with an `nm` gate asserting the families' absence from shipped binaries. *(This line was truncated on `dev` — "(added" and nothing after — and is restored here from the Cargo.toml note that cites it.)*

## 2. Two shapes, two remedies — read at source 2026-09-19

### 2.1 Shape (a) — present in the archive via feature unification

`sign_with_ml_dsa_seed` (deterministic PQ half from a fixed seed — precisely the symbol a production daemon should not link) sits in `shekyl-crypto-pq`'s `#[cfg(any(test, feature = "test-utils"))]` block (`rust/shekyl-crypto-pq/src/signature.rs:450`); `shekyl-ffi` enables the feature on a normal edge (`rust/shekyl-ffi/Cargo.toml:32`), so unification compiles it into the shipped archive, reachable from every Rust crate in that graph, not exported over C. *The remedy as written — separate test-only archive or cmake feature — addresses exactly this.* 

### 2.2 Shape (b) — unconditional export, unconditional header

`shekyl_pqc_keypair_generate` and `shekyl_pqc_sign_multisig_participant` are `#[no_mangle] pub extern "C"` with **no `cfg` at all** (`rust/shekyl-ffi/src/legacy_core.rs:69`–`70`, `:169`–`170`), declared unconditionally in the production header (`src/shekyl/shekyl_ffi.h:170`, `:196`); the guard at all four sites is the sentence *do not call from production*. So they are **reachable from any C++ that includes the header**, and *a separate test-only archive does not remove them*: nothing about them is conditional, they compile into whichever archive the crate produces and the header still declares them. The `shekyl_curve_tree_replica_*` family this row already names is the same shape (`rust/shekyl-ffi/src/curve_tree_replica_ffi.rs:113`, `:129`, `:177`, `:264` — no `cfg`). The fix for (b) is a different one, and it is this lane's to choose: `cfg` the export **and** its header declaration together; or delete the export and give the C++ tests (`tests/unit_tests/fcmp.cpp:441`, the one caller of the keypair generator) a *derived* keypair; or move the declarations into a test-only header the production build does not ship. 

### 2.3 Common to both — the `nm` gate

the `nm` gate — a shipped binary containing `shekyl_pqc_keypair_generate`, `shekyl_pqc_sign_multisig_participant`, `sign_with_ml_dsa_seed`'s mangled symbol, or any `shekyl_curve_tree_replica_*` is red regardless of which route (a) or (b) takes.

Two remedies to choose, not one; a reader sent to F-7 by the manifest comment should not conclude that the archive split covers (b).

## 3. The `nm` gate's precondition: a derived symbol list

The six symbols above were found two at a time by two people looking at unrelated things, which is a reasonable prior that the list is not finished — and a sweep run 2026-09-19 confirmed it. Method: every `pub (unsafe) extern "C" fn` under `rust/shekyl-ffi/src` (**286**, not the ~60 a per-file count suggests), cross-referenced against (i) a `#[cfg]` on the export, (ii) a declaration in `src/shekyl/*.h`, (iii) a test-only marker in its own doc comment (*do not call from production* / *test-support* / *test-only* / *not for production use*), and (iv) a production caller — **in this repo under `src/` outside `tests/`, and in every consuming repo**, because the FFI is consumed outside this tree (SOK-Q7's enumeration checked GUI, mobile and web for exactly this reason) and an export with no caller in `shekyl-core/src` may have one a deletion would break. Enumeration for the eight, run 2026-09-19: `shekyl-gui-wallet` @`9c2a378` **0 hits**, and — checked on the **resolved graph**, not the manifest, because unification operates on the graph (`check_chain_rules_no_store.sh`'s lesson): `cargo tree --locked -e normal,build,dev --target all -i shekyl-ffi` in `src-tauri/` answers *"package ID specification `shekyl-ffi` did not match any packages"* (the negative outcome, distinguished from an error by its message), and `-i shekyl-crypto-pq -f '{p} features=[{f}]'` resolves the crate with **`features=[]`** — so `test-utils` is not unified into the GUI build and `sign_with_ml_dsa_seed` does not exist there; the direct `shekyl-crypto-pq` edge at `src-tauri/Cargo.toml:39` is why, and the tree is what shows it. `shekyl-mobile-wallet` @`2a21ed6` **0 hits** by grep, but the graph-level claim is **unverifiable at this pin**: its manifest resolves no graph — `src-tauri/Cargo.toml:51` points `shekyl-rpc` at `shekyl-core/rust/shekyl-oxide/shekyl-oxide/rpc`, a path that does not exist at current core, so `cargo tree` fails before resolving. The manifest-level facts (`:24` "No `shekyl-ffi`"; `:50` the direct `shekyl-crypto-pq` edge) stand as *intent* only. That stale path dependency is the mobile lane's finding, not F-7's; F-7 sizes shape (a) as daemon-only on the GUI's graph and mobile's intent, and re-runs the tree check for mobile once its manifest resolves; `shekyl-web` @`e31c9eb` **0 hits**, no FFI at all; `shekyl-dev` @`6262b4d` 3 hits, all plan prose. The no-header case (`shekyl_ml_kem_chacha_seed_trace`) therefore has no self-declaring caller in any consuming repo either — the absence of a header was evidence about this repo's intent, and the enumeration is what makes it evidence about callers. **Re-run the enumeration at deletion time**; a consumer added between now and then is the falsifier. Results: the doc-marker discriminator (iii) finds **four** — the PQC pair, plus two new: `shekyl_ml_kem_chacha_seed_trace` (`rust/shekyl-ffi/src/account_ffi.rs:512`; unconditional; **declared in no header** — present in the archive and callable by any extern declaration; exposes the ML-KEM SHA3→ChaCha seed intermediary for Tier-2 KATs) and `shekyl_test_conforming_pqc_leaf_entry` (`rust/shekyl-ffi/src/tx_extra_ffi.rs:216`; unconditional; `shekyl_ffi.h:1380`; called only from `tests/unit_tests/pqc_spend_fixture.h:75`). And (iii) **misses the replica family**: its test-only-ness is stated once in the module doc ("the C++ test generator (`tests/core_tests/chaingen.cpp`) drives"), not per export, and `blockchain.cpp:5576` names it only in a comment. So the doc comment is a signal, not the discriminator — a sweep by comment finds what commenters wrote. **The derived discriminator is (iv):** an unconditional export with no production caller *in this repo or any consuming repo* is remedy (b)'s subject by construction, whatever its comment says; (iii) and the module-doc marker are corroboration. Remedy (b)'s subject is therefore **at least eight** (PQC pair, replica four, seed trace, conforming leaf entry) and the `nm` gate seeds from re-running the sweep, asserts the derived list is non-empty (rule 47), and is red on any listed symbol in a shipped binary. Also observed, not classified here: 17 exports *are* `cfg`-gated (`legacy_frost.rs`' sixteen under `feature = "multisig"`, `legacy_tx.rs:372`) and declared in no header — conditional, so remedy (a)'s class if the feature is test-shaped; F-7 categorizes them with the rest.

## 4. Forwarded enablement (found 2026-09-19 on PR #786 round 4)

Shape (a) has a second path the direct-edge view did not show: `shekyl-p-serve`'s
`test-signer` feature **forwards** `shekyl-crypto-pq/test-utils`
(`rust/shekyl-p-serve/Cargo.toml`), and `shekyl-sp-t3-spike` enables
`p-serve/test-signer` on a **normal** edge, as does `shekyl-p-host` through its
own `test-signer` forward. So `test-utils` reaches the shipped graph by two
routes — `shekyl-ffi`'s direct edge and `p-serve`'s forward — and remedy (a)
must close both. `check_test_only_features.py` counts forwarded activations as
enablements since that round, which is how this was seen.

## 5. Decision log

| Date | Entry |
|---|---|
| 2026-09-19 | Record opened by PR #786 to hold the audit the FOLLOWUPS row had grown into (rule 95: a row is one sentence, a link and a target). Content moved verbatim from the row's 2026-09-19 UPDATE, restructured under headings; the forwarded path (§4) added the same day. |
