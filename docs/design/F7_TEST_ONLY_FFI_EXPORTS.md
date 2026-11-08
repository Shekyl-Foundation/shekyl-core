# F-7 — test-only FFI exports in the production archive: finding record

**Status:** OPEN — finding record for FOLLOWUPS **F-7**, opened 2026-09-19
(PR #786, the S-TX pre-flight, which found the class again through
`scripts/ci/check_test_only_features.py`'s governance-trigger limb). This
file carries the source audit; the FOLLOWUPS row carries one sentence and a
link (rule 95). Owner: the lane that lands F-7's structural gate — **not**
S-TX. The `file:line` cites in §2.1 and §5 were re-read on 2026-10-14;
the rest were read at `dev` `090f2e8f2`–`6c41bf820`. Re-verify before
acting on one.

**2026-11-07:** the PQC pair below (`shekyl_pqc_keypair_generate`,
`shekyl_pqc_sign_multisig_participant`) is deleted, with `shekyl_pqc_sign`,
`shekyl_pqc_verify`, `shekyl_pqc_canonical_lens`, their header declarations
and the C++ tests that called them. `shekyl-ffi` now enables
`shekyl-crypto-pq/test-utils` on a dev edge only, so its own archive no
longer carries shape (a); `shekyl-p-serve`'s forwarded edge (§4) still
does. The replica family, `shekyl_test_coinbase_extra` and
`shekyl_test_conforming_pqc_leaf_entry` remain this row's subject (the seed
trace went with the C++ account code).

## 1. The row this record serves

**F-7 structural gate for the test-only FFI exports shipped in the production archive.** The PQC test helpers (`shekyl_pqc_keypair_generate`, `shekyl_pqc_sign_multisig_participant`, added under `shekyl-crypto-pq`'s `test-utils` feature because cmake builds one `-p shekyl-ffi` archive that every binary links) ship in production through feature unification; the header and Rust docs mark them, but nothing structural keeps them out. The curve-tree replica family `shekyl_curve_tree_replica_*` (PR #623 — the core_tests generator's header-root oracle, `rust/shekyl-ffi/src/curve_tree_replica_ffi.rs`) is the same class and belongs to the same gate. Remedy: a separate test-only archive, or a cmake feature that production targets never enable, with an `nm` gate asserting the families' absence from shipped binaries. *(This line was truncated on `dev` — "(added" and nothing after — and is restored here from the Cargo.toml note that cites it.)*

## 2. Two shapes, two remedies — read at source 2026-09-19

### 2.1 Shape (a) — present in the archive via feature unification

`sign_with_ml_dsa_seed` (deterministic PQ half from a fixed seed — precisely the symbol a production daemon should not link) sits in `shekyl-crypto-pq`'s `#[cfg(any(test, feature = "test-utils"))]` block (`rust/shekyl-crypto-pq/src/signature.rs:417`). As of 2026-11-07 `shekyl-ffi` enables that feature only under `[dev-dependencies]` (the `shekyl-crypto-pq` line in that section of `rust/shekyl-ffi/Cargo.toml`), so the archive cmake links — `cargo build -p shekyl-ffi`, dev features off — does not compile it. A crate that still enables `test-utils` on a normal edge does: `shekyl-p-serve`'s forwarded `test-signer` (§4). The symbol is not exported over C. *The remedy as written — separate test-only archive or cmake feature — addresses the normal edge that remains.* 

### 2.2 Shape (b) — unconditional export, unconditional header

The PQC exports this section used to name (`shekyl_pqc_keypair_generate`, `shekyl_pqc_sign_multisig_participant`, and with them `shekyl_pqc_sign`, `shekyl_pqc_verify`, `shekyl_pqc_canonical_lens`, `shekyl_fcmp_pqc_key_scalar`) are deleted as of 2026-11-07, header declarations included. What remains of shape (b) is still unconditional in the production header. The `shekyl_curve_tree_replica_*` family (`rust/shekyl-ffi/src/curve_tree_replica_ffi.rs`, first export at line 113, no `cfg`) is that remainder, with `shekyl_test_coinbase_extra` and `shekyl_test_conforming_pqc_leaf_entry` below. The fix for (b) is still this lane's to choose: `cfg` the export **and** its header declaration together, or move the declarations into a test-only header the production build does not ship. 

**A ninth, after the sweep: `shekyl_test_coinbase_extra`** (`rust/shekyl-ffi/src/tx_extra_codec_ffi.rs:395`; `src/shekyl/shekyl_ffi.h:906`). Shape (b): unconditional, declared in the production header. Its callers are C++ tests (`tests/core_tests/chaingen.cpp`, `tests/unit_tests/archival_lmdb_test_helpers.h`), so `cfg(test)` cannot gate it: those tests link the archive `cargo build -p shekyl-ffi` produces, which never sets `cfg(test)`. It writes the fixture draw commitment (`CONFORMING_DRAW_COMMITMENT`), a value anyone can guess, so a production call would put a guessable commitment in a coinbase. Until this gate lands, `scripts/ci/check_template_secrets.sh` holds the value to that one function and its tests, and `src/` to no caller.

### 2.3 Common to both — the `nm` gate

the `nm` gate — a shipped binary containing any `shekyl_curve_tree_replica_*`, or `sign_with_ml_dsa_seed`'s mangled symbol, is red. The deleted PQC exports (`shekyl_pqc_keypair_generate`, `shekyl_pqc_sign_multisig_participant`, `shekyl_pqc_sign`, `shekyl_pqc_verify`, `shekyl_pqc_canonical_lens`, `shekyl_fcmp_pqc_key_scalar`) stay on that list as regression sentinels: a hit means one of them was linked again.

Two remedies to choose, not one; a reader sent to F-7 by the manifest comment should not conclude that the archive split covers (b).

## 3. The `nm` gate's precondition: a derived symbol list

The enumeration in this section is the 2026-09-19 sweep, as run. The PQC pair and the seed trace it names are since deleted; §2.2 is the live shape-(b) list.

The six symbols above were found two at a time by two people looking at unrelated things, which is a reasonable prior that the list is not finished — and a sweep run 2026-09-19 confirmed it. Method: every `pub (unsafe) extern "C" fn` under `rust/shekyl-ffi/src` (**286**, not the ~60 a per-file count suggests), cross-referenced against (i) a `#[cfg]` on the export, (ii) a declaration in `src/shekyl/*.h`, (iii) a test-only marker in its own doc comment (*do not call from production* / *test-support* / *test-only* / *not for production use*), and (iv) a production caller — **in this repo under `src/` outside `tests/`, and in every consuming repo**, because the FFI is consumed outside this tree (SOK-Q7's enumeration checked GUI, mobile and web for exactly this reason) and an export with no caller in `shekyl-core/src` may have one a deletion would break. Enumeration for the eight, run 2026-09-19: `shekyl-gui-wallet` @`9c2a378` **0 hits**, and — checked on the **resolved graph**, not the manifest, because unification operates on the graph (`check_chain_rules_no_store.sh`'s lesson): `cargo tree --locked -e normal,build,dev --target all -i shekyl-ffi` in `src-tauri/` answers *"package ID specification `shekyl-ffi` did not match any packages"* (the negative outcome, distinguished from an error by its message), and `-i shekyl-crypto-pq -f '{p} features=[{f}]'` resolves the crate with **`features=[]`** — so `test-utils` is not unified into the GUI build and `sign_with_ml_dsa_seed` does not exist there; the direct `shekyl-crypto-pq` edge at `src-tauri/Cargo.toml:39` is why, and the tree is what shows it. `shekyl-mobile-wallet` @`2a21ed6` **0 hits** by grep, but the graph-level claim is **unverifiable at this pin**: its manifest resolves no graph — `src-tauri/Cargo.toml:51` points `shekyl-rpc` at `shekyl-core/rust/shekyl-oxide/shekyl-oxide/rpc`, a path that does not exist at current core, so `cargo tree` fails before resolving. The manifest-level facts (`:24` "No `shekyl-ffi`"; `:50` the direct `shekyl-crypto-pq` edge) stand as *intent* only. That stale path dependency is the mobile lane's finding, not F-7's; F-7 sizes shape (a) as daemon-only on the GUI's graph and mobile's intent, and re-runs the tree check for mobile once its manifest resolves; `shekyl-web` @`e31c9eb` **0 hits**, no FFI at all; `shekyl-dev` @`6262b4d` 3 hits, all plan prose. The no-header case (`shekyl_ml_kem_chacha_seed_trace`) therefore has no self-declaring caller in any consuming repo either — the absence of a header was evidence about this repo's intent, and the enumeration is what makes it evidence about callers. **Re-run the enumeration at deletion time**; a consumer added between now and then is the falsifier. Results: the doc-marker discriminator (iii) finds **four** — the PQC pair, plus two new: `shekyl_ml_kem_chacha_seed_trace` (`rust/shekyl-ffi/src/account_ffi.rs`, deleted with the C++ account under `NETWORK_IDENTITY.md` NI-R7; unconditional; **declared in no header** — present in the archive and callable by any extern declaration; exposes the ML-KEM SHA3→ChaCha seed intermediary for Tier-2 KATs) and `shekyl_test_conforming_pqc_leaf_entry` (`rust/shekyl-ffi/src/tx_extra_ffi.rs:216`; unconditional; `shekyl_ffi.h:1380`; called only from `tests/unit_tests/pqc_spend_fixture.h:75`). And (iii) **misses the replica family**: its test-only-ness is stated once in the module doc ("the C++ test generator (`tests/core_tests/chaingen.cpp`) drives"), not per export, and `blockchain.cpp:5576` names it only in a comment. So the doc comment is a signal, not the discriminator — a sweep by comment finds what commenters wrote. **The derived discriminator is (iv):** an unconditional export with no production caller *in this repo or any consuming repo* is remedy (b)'s subject by construction, whatever its comment says; (iii) and the module-doc marker are corroboration. Remedy (b)'s subject is therefore **at least eight** (PQC pair, replica four, seed trace, conforming leaf entry) and the `nm` gate seeds from re-running the sweep, asserts the derived list is non-empty (rule 47), and is red on any listed symbol in a shipped binary. Also observed, not classified here: 17 exports *are* `cfg`-gated (`legacy_frost.rs`' sixteen under `feature = "multisig"`, `legacy_tx.rs:372`) and declared in no header — conditional, so remedy (a)'s class if the feature is test-shaped; F-7 categorizes them with the rest.

## 4. Forwarded enablement (found 2026-09-19 on PR #786 round 4)

Shape (a) has a second path the direct-edge view did not show: `shekyl-p-serve`'s
`test-signer` feature **forwards** `shekyl-crypto-pq/test-utils`
(`rust/shekyl-p-serve/Cargo.toml`), and `shekyl-sp-t3-spike` enables
`p-serve/test-signer` on a **normal** edge, as does `shekyl-p-host` through its
own `test-signer` forward. `test-utils` reaches a shipped graph through
that forward. `shekyl-ffi`'s direct edge was the other route until
2026-11-07, when the PQC exports that called the feature were deleted and
the edge moved to `[dev-dependencies]`. Remedy (a) still closes the
forward. `check_test_only_features.py` counts forwarded activations as
enablements since that round, which is how this was seen.

## 5. Seams that mutate key material (2026-10-12; priority raised by ruling)

Ruled 2026-10-12 on PR #1049: *"Raise FOLLOWUPS F-7's priority (the seams
that mutate key material ship with shekyl-ffi)."* The row is now
`pre-genesis, priority 1`. What the ruling rests on, with every `file:line`
re-read on 2026-10-14:

**The edge.** Until 2026-11-07 `shekyl-ffi` enabled
`shekyl-crypto-pq/test-utils` on a normal dependency edge, and
`cargo tree -p shekyl-ffi -e features,normal -i shekyl-crypto-pq` printed
the feature, so every `test-utils` item was compiled into the archive
cmake links. That edge is now dev-only. `[dependencies]` in
`rust/shekyl-ffi/Cargo.toml` opens at line 23 and does not enable the
feature; the enablement is the `shekyl-crypto-pq` line under
`[dev-dependencies]`. `cargo build -p shekyl-ffi` does not compile these
seams into `libshekyl_ffi.a`. They still compile into a crate that
enables `test-utils`, or `shekyl-p-serve`'s `test-signer`, on a normal
edge (§4). Where they do, this is still shape (a) (§2.1): present in
that crate's build, not exported over C.

**The instances.** Shape (a) was recorded for seams that *produce*
signatures or keys. It now also holds a seam that *writes into a secret
key*:

| Seam | Where | What it does |
| --- | --- | --- |
| `FnDsaHybridSecretKey::corrupt_fn_dsa_half_for_tests` | `rust/shekyl-crypto-pq/src/fn_dsa_hybrid.rs:246` (added by PR #1049) | Overwrites the header byte of a receipt secret key's FN-DSA half in place, making the key undecodable. Reads no key byte out |
| `HybridEd25519FnDsa::sign_with_rng_seed` | `rust/shekyl-crypto-pq/src/fn_dsa_hybrid.rs:387` | Sign with the FN-DSA half's draw taken from a caller-chosen seed: a deterministic Falcon signature, the thing two of which over one hashed point leak the key (`FN_DSA_HYBRID.md` §2) |
| `FnDsaHybridSigner::sign_with_rng_seed` | `rust/shekyl-crypto-pq/src/fn_dsa_hybrid/signer.rs:186` | The same deterministic sign, over the key decoded once and held |
| `HybridEd25519MlDsa::sign_with_ml_dsa_seed` | `rust/shekyl-crypto-pq/src/signature.rs:417` | Already §2.1's example |

**What "ships" means here, exactly.** With `shekyl-ffi`'s edge on
dev-dependencies, these seams are not in the archive cmake links. They
are compiled into each crate that enables `test-utils` on a normal edge,
which today is the `shekyl-p-serve` forward (§4). None is `extern "C"`
and no export names one. Whether their code survives into a final linked
binary of those crates is the linker's section-collection, which nothing
asserts — that is §2.3's `nm` gate, and these mangled symbols join its
list.

**What does not reach `shekyl-ffi`.** `shekyl-p-serve`'s `test-signer`
feature (which forwards `test-utils`, §4) is not in `shekyl-ffi`'s
dependency graph: `cargo tree -p shekyl-ffi -e normal` names neither
`shekyl-p-serve` nor `shekyl-p-host`. PR #1049's `TestReceiptKeySigner`
is behind `test-signer` and so rides §4's forwarded route into the crates
that enable it on a normal edge, not this one.

**Why the priority moved.** A deterministic-signing seam is misuse-prone.
A seam that edits a secret key in place is a different kind of thing to
have compiled beside the keys it could edit, and the only thing between it
and a production caller is its name.

## 6. Decision log

| Date | Entry |
|---|---|
| 2026-09-19 | Record opened by PR #786 to hold the audit the FOLLOWUPS row had grown into (rule 95: a row is one sentence, a link and a target). Content moved verbatim from the row's 2026-09-19 UPDATE, restructured under headings; the forwarded path (§4) added the same day. |
| 2026-10-12 | Priority raised to `pre-genesis, priority 1` by ruling on PR #1049; §5 added with the feature-edge evidence and the key-mutating instance that PR introduced (`corrupt_fn_dsa_half_for_tests`). The remedy (§2) is unchanged and is still not this PR's. |
| 2026-10-24 | `shekyl_test_coinbase_extra` added to §2.2 as a ninth shape-(b) export (DRS-X PR 3c). The template-secrets gate is narrowed to it in the meantime; the structural remedy is still this record's. |
| 2026-11-07 | The PQC FFI exports named in §2.2 are deleted, and `shekyl-ffi`'s `test-utils` edge moved from `[dependencies]` to `[dev-dependencies]`. Shape (a) for that crate's production archive is closed. The live normal edge is `shekyl-p-serve`'s forward (§4). §2.1, §2.2, §4 and §5 say so. |
