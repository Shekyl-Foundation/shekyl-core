# C++/Rust FFI constant-drift audit — 2026-05-05

## Why this document exists

Two real bugs (Bug 1 + Bug 2 below) in the C++/Rust FFI constant boundary
were discovered while triaging a single failing unit-test cluster
(`wallet_storage.{store_to_mem2file, change_password_mem2file}`). The
mechanism in both cases was the same: a hand-written `#define SHEKYL_*` in
`src/shekyl/shekyl_ffi.h` had drifted from a hand-written `pub const SHEKYL_*`
in `rust/shekyl-ffi/`, with the two sides "agreeing" only via comments.

This audit was triggered by the obvious follow-up question: *what else?*
Forty-seven cross-language constants live across the FFI boundary. This
document records the result of going through every one by hand on
2026-05-05 — three real findings (Bug 1, Bug 2, Bug 3), one
documented architectural gap against a layer being deleted by the Rust
rewrite (Bug 4 — the wallet2 BIP-39 wrapper does not exist, by design),
plus one related raw-seed footgun in the legacy `account_base::generate()`
test wrapper, with the remaining 43 constants confirmed aligned.

The audit-quality story it supports:

> "We had a real instance of C++/Rust constant drift on `dev`. We
> found it via the wallet_storage failures. We then audited all 47
> cross-language constants by hand. We found two more issues from
> the same class. We landed mechanical equality-assertion tests for
> the two consensus-adjacent constants in the immediate fix branch,
> and scheduled the cbindgen-style generated header to permanently
> close the bug class for the consensus-affecting subset before the
> external audit window."

---

## Findings

### Bug 1 — `SHEKYL_CLASSICAL_ADDRESS_BYTES` off by one

| Field | Value |
| --- | --- |
| C++ | `src/shekyl/shekyl_ffi.h` defined `SHEKYL_CLASSICAL_ADDRESS_BYTES = 64` |
| Rust | `rust/shekyl-crypto-pq/src/account.rs` defines `CLASSICAL_ADDRESS_BYTES = 1 + 32 + 32 = 65` (`version || spend_pk || view_pk`) |
| Mechanism | `ShekylAllKeysBlob` is `#[repr(C)]` with byte-aligned `[u8; N]` arrays. The 1-byte deficit shifted every later field's offset by one. C++ `populate_account_from_blob` read `spend_sk` and `view_sk` from the wrong bytes; the resulting non-canonical scalars failed `sc_check` inside `secret_key_to_public_key`. |
| Failure mode | Fail-closed at every wallet load on every network. `error::wallet_files_doesnt_correspond` from `verify_keys`. No path to silent corruption. |
| Detection | Caught by every test that touched a wallet. Specifically the `wallet_storage` round-trip surface. |
| Fix | `SHEKYL_CLASSICAL_ADDRESS_BYTES` set to `65` in the header. |
| Mechanical regression test added | `rust/shekyl-ffi/src/account_ffi.rs::tests::ffi_classical_address_bytes_matches_rust_authority` |

### Bug 2 — `SHEKYL_SEED_FORMAT_*` 0/1 vs 1/2

| Field | Value |
| --- | --- |
| C++ | `src/shekyl/shekyl_ffi.h` defined `SHEKYL_SEED_FORMAT_BIP39 = 0`, `_RAW32 = 1` |
| Rust | `rust/shekyl-crypto-pq/src/account.rs` defines `SEED_FORMAT_BIP39 = 0x01`, `SEED_FORMAT_RAW32 = 0x02` (with `0` reserved for "unset") |
| Mechanism | C++ wrote `m_seed_format = 1` to disk meaning RAW32; on `wallet2::load`, the FFI `shekyl_account_rederive` received `seed_format = 1` and decoded `1` as `Bip39`; `permitted_seed_format(Fakechain, Bip39)` returned `false`; rederive returned `false`; load failed with `"(network, seed_format) pair disallowed or derivation inconsistent"`. The BIP-39 path was broken too, but in a different way: C++ wrote `0`, and `SeedFormat::from_u8(0)` returns `None` (Rust reserves `0` for "unset"), so a BIP-39 wallet would have failed at `wallet2::load` with an FFI decode error. The reason this went undetected is *not* that BIP-39 round-tripped — it's that no C++/FFI-layer test exercised the BIP-39 path at all. |
| Failure mode | Fail-closed at every wallet load on both the RAW32 path (Testnet, Fakechain) and the BIP-39 path (any network). No path to silent corruption. |
| Detection | Caught only because Bug 1's fix exposed it. Was actively undetected in `dev` for the entire window during which Bug 1 was masking it. |
| Fix | `SHEKYL_SEED_FORMAT_BIP39 = 1`, `_RAW32 = 2` in the header. |
| Mechanical regression test added | `rust/shekyl-ffi/src/account_ffi.rs::tests::ffi_seed_format_constants_match_rust_authority` |

### Bug 3 — `FCMP_REFERENCE_BLOCK_MIN_AGE` 5 vs 10

Found during the post-Bug-2 sweep. **Not in scope of `fix/wallet-storage-test`;
fixed in sibling branch `fix/fcmp-min-age-multisig-drift`.**

| Field | Value |
| --- | --- |
| C++ (consensus) | `src/cryptonote_config.h:204` defines `FCMP_REFERENCE_BLOCK_MIN_AGE = 5` (asserted by `tests/unit_tests/fcmp.cpp:668`, documented in `docs/FCMP_PLUS_PLUS.md:432`, locked by Decision 14 per `docs/CHANGELOG.md:5788`). |
| Rust (multisig wallet) | `rust/shekyl-engine-core/src/multisig/v31/intent.rs:20` defines `FCMP_REFERENCE_BLOCK_MIN_AGE = 10` with the same comment ("Minimum reference block age in blocks behind tip"). |
| Doc (also stale) | `docs/SHEKYL_MULTISIG_WIRE_FORMAT.md:90` lists `10`. |
| Mechanism | A v31 multisig proposer generating a `SpendIntent` with `ref_height = tip - {5..9}` (valid per consensus) is rejected by every co-signer's wallet with `RefBlockTooFresh`. Wallet-side bug; not a consensus split. |
| Failure mode | Fail-closed at the multisig wallet boundary. No silent acceptance, no consensus risk. |
| Detection | Caught by hand audit. No automated detection existed. |
| Status | Fixed in sibling branch, after `git log -S "10"` confirms which value was intentional. (Per discussion, almost certainly the Rust side is the typo: the comment text matches the consensus-side comment exactly, so it is unlikely to have been a deliberate wallet-side conservativeness choice.) |

### Bug 4 — `wallet2::generate_from_bip39` does not exist

**Not a bug in the conventional sense; documented architectural gap
against a layer that is being deleted by the Rust wallet rewrite at
Phase 5.** The original Bug 4 framing on first surfacing (below the
revised section) was "the C++ wallet2 BIP-39 path is broken because the
glue is missing." That framing was correct under the assumption that
the C++ layer was load-bearing. After surfacing the gap and confirming
no production caller exists pre-mainnet, the framing was revised:

| Field | Value |
| --- | --- |
| Symptom | `wallet2` exposes no `generate_from_bip39` entry point. The Rust derivation (`shekyl-crypto-pq::generate_account_from_bip39`), the FFI (`shekyl_account_generate_from_bip39`), and the lower-level C++ glue (`account_base::generate_from_bip39`) all exist and are tested; the wallet2-level wrapper was never wired through when the original wallet2-from-Electrum-mnemonic path was retired. The user-facing `wallet2::generate(name, password, recovery_param, ...)` API only routes raw-seed derivation through `account_base::generate()`, which hardcodes `FAKECHAIN`. |
| Severity | Pre-mainnet: zero production users affected. The Rust derivation path is the actual functional guarantee and is tested end-to-end. The wallet2 layer is dead-code-walking — Phase 5 of the Rust rewrite deletes `wallet2.cpp` wholesale. |
| Decision (2026-05-05) | Do **not** add the wallet2 wrapper pre-migration. Rationale: (a) any wrapper added now is deleted by Phase 5 as a removal-as-breaking-change rather than removal-as-no-op; (b) the Rust path is the actual guarantee; (c) no mainnet exists yet, so no user is affected; (d) the next beta ships before Phase 5 lands, so any "transitional" wrapper would have a lifespan shorter than its review burden. See `docs/FOLLOWUPS.md` §"V3.1+ Legacy C++ → Rust rewrite scope". |
| CI tripwire | `tests/unit_tests/wallet_storage.cpp` carries a `static_assert` on a SFINAE detector for `wallet2::generate_from_bip39`. If a future contributor adds the wrapper, the build fails with a message pointing at the FOLLOWUPS entry. The tripwire deletes itself when `wallet2.cpp` is removed at Phase 5. |
| Coverage added in this branch | `tests/unit_tests/account.cpp::rederive_from_bip39_reproduces_account_mainnet` exercises BIP-39+MAINNET end-to-end through the FFI at the `account_base` layer (the C++ hop the wallet2 wrapper would have made internally). The Rust-side primary functional guarantee is `shekyl-crypto-pq::tests::generate_from_bip39_mainnet_roundtrips_to_rederive`, which carries a doc-comment cross-referencing the C++ tripwire. |
| Discovery pattern | Bug 4 surfaced not from runtime failure but from attempting to add C++ coverage for a path that turned out not to exist. The compiler told us `wallet2::generate_from_bip39` was undefined; we stopped, surfaced the gap, and made the absence load-bearing in the audit trail rather than papering over it. **Keep this discovery pattern: writing tests for assumed APIs is a cheap audit technique, especially for "obvious" functionality nobody has tried to use.** |

### Bug 4-adjacent — `account_base::generate()` legacy 3-arg overload hardcoded `FAKECHAIN`

A separate finding from the same audit pass, distinct from the Bug 4
absence above. **Fixed in sibling branch
`fix/legacy-account-generate-network-guard` by structural deletion of
the 3-arg overload.**

| Field | Value |
| --- | --- |
| Symptom | The legacy `account_base::generate(recovery_key = secret_key{}, recover = false, two_random = false)` 3-arg overload hardcoded `cryptonote::FAKECHAIN` for raw-seed derivation regardless of caller network. Three production callers reached it via the implicit FAKECHAIN default: `wallet2::generate(name, password, recovery, recover, ...)` (the CLI / RPC wallet-creation entry), `wallet2`'s 0-change dummy-destination address generator (`transfer_selected_rct`), and `wallet_rpc_server::on_stop_background_sync`'s seed-recovery path. |
| Failure-mode pre-fix on testnet | A `wallet2::generate(...)` instantiated on `TESTNET` derived keys under `FAKECHAIN` salt; on reload, `rederive_from_master_seed(TESTNET)` returned `false` because the master seed disagreed. Same shape on `wallet_rpc_server::stop_background_sync`: spend key recovered under `FAKECHAIN` salt couldn't match the wallet's stored `TESTNET`-salted key, so the RPC's post-recovery key check always failed. |
| Failure-mode pre-fix on mainnet / stagenet | Doubly broken: (a) `FAKECHAIN`-derived keys disagree with `MAINNET/STAGENET` rederive salt; (b) `MAINNET/STAGENET` don't permit `RAW32` at all. The reachable production paths on mainnet were `wallet_rpc_server::on_create_wallet` (fresh-wallet creation, `recover=false`) and `wallet_rpc_server::on_stop_background_sync` (Electrum-words seed recovery, `recover=true`); both silently produced FAKECHAIN-salted accounts whose `wallet2::load` rederive failed key-comparison. The wallet2-recovery flow (`recover=true`) on mainnet would route through the missing BIP-39 wrapper (Bug 4), so the `wallet2::generate` wallet-recovery slot was never reached on mainnet — but the fresh-creation slot (`recover=false`) was. |
| Form of fix (delivered) | Added `account_base::generate(recovery, recover, two_random, network_type nettype)` as the only `generate(...)` overload, then **deleted** the legacy 3-arg overload entirely. Migrated `wallet2::generate(...)` and `wallet_rpc_server::on_stop_background_sync` to pass `m_nettype` / `m_wallet->nettype()`. Migrated all 28 test callers to pass `cryptonote::FAKECHAIN` explicitly. The 0-change dummy-destination caller in `wallet2::transfer_selected_rct` was migrated to the same 4-arg form but with `cryptonote::FAKECHAIN` hardcoded — the dummy address is a transient one-shot whose secret keys are discarded; properly network-matching it would require a BIP-39 path on MAINNET / STAGENET (RAW32 isn't permitted there) and is filed under FOLLOWUPS V3.2. The structural deletion eliminates the "one omitted argument away from FAKECHAIN" footgun class entirely. |
| Failure-mode change post-fix | On MAINNET / STAGENET, the migrated callers throw cleanly via the FFI's `permitted_seed_format` check instead of silently producing FAKECHAIN-salted unspendable wallets / unmatchable spend keys. The throw scope expanded relative to the originally-anticipated "recovery only" scope: `wallet_rpc_server::on_create_wallet` (fresh-wallet creation, `recover=false`) and `wallet2_ffi::create` (FFI wallet creation, `recover=true`) also throw on MAINNET / STAGENET now. This is **a strict improvement in failure mode** — both paths were already broken pre-fix (silently producing wallets that would fail to load), and both can only be properly fixed by a BIP-39 entry point at the wallet2 layer (Bug 4, deferred per the Rust migration). On TESTNET / FAKECHAIN, every migrated caller now produces correctly-network-salted accounts that round-trip through `wallet2::load`. |
| Mainnet user-visible scope | After this fix, the only working wallet creation paths on MAINNET / STAGENET are the view-only / spend+view restore paths (`wallet2::generate(name, password, address, viewkey, ...)` and `wallet2::generate(name, password, address, spendkey, viewkey, ...)`), which bypass `account_base::generate` entirely and call `create_from_viewkey` / `create_from_keys` directly. Fresh-seed wallet creation and Electrum-style recovery on MAINNET / STAGENET fail loudly with a clear FFI error pointing at the `(network, seed_format)` rejection. The proper MAINNET fresh-creation path requires the wallet2 BIP-39 wrapper (Bug 4) which is deferred to the Rust wallet migration. Filed as FOLLOWUPS V3.0: "wallet_rpc_server `on_create_wallet` MAINNET/STAGENET regression — deferred to wallet2 BIP-39 entry point." |
| Mainnet test coverage check | `wallet_rpc_server::on_stop_background_sync` is exercised only via `tests/functional_tests/transfer.py::check_background_sync` and `check_background_sync_reorg_recovery`, which run on FAKECHAIN (`assert res.nettype == "fakechain"` per `daemon_info.py`). `on_create_wallet` is exercised by `tests/functional_tests/wallet.py`, also on FAKECHAIN. No mainnet integration test exists for either RPC. Both Electrum-words and fresh-CSPRNG seed-recovery paths are fundamentally raw-seed flows that cannot work on MAINNET / STAGENET regardless of the network-salt fix; replacement with BIP-39 entry points is filed for V3.2 alongside the `shekyl-wallet-rpc` Rust cutover. |
| Regression test added | `tests/unit_tests/account.cpp::generate_uses_explicit_nettype_argument` pins (a) `generate(..., TESTNET)` produces the same account as `generate_from_raw_seed(..., TESTNET)`, (b) `generate(..., FAKECHAIN)` produces a distinct account (different HKDF salt), and (c) `generate(..., MAINNET)` and `generate(..., STAGENET)` throw at the FFI's `permitted_seed_format` check for **both** `recover=true` (recovery) and `recover=false` (fresh CSPRNG seed). |

---

## Constants confirmed aligned (43 of 47 — no drift)

The following constants were diffed by hand across `src/shekyl/shekyl_ffi.h`,
`src/shekyl/shekyl_log.h`, `src/cryptonote_config.h`, `src/fcmp/rctTypes.h`,
and the `rust/shekyl-*` crates that expose `pub const SHEKYL_*` mirrors. Each
was confirmed name-matched and value-matched.

| Group | Constants | Drift class if it occurred |
| --- | --- | --- |
| Address & key bytes | `MASTER_SEED_BYTES`, `RAW_SEED_BYTES`, `PROVE_WITNESS_HEADER_BYTES`, `PQC_PUBLIC_KEY_BYTES`, `X25519_PK_BYTES`, `ML_KEM_768_EK_BYTES`, `ML_KEM_768_DK_BYTES`, `WALLET_KEYS_WRAP_SALT_BYTES`, `WALLET_SEED_BLOCK_TAG_BYTES`, `WALLET_EXPECTED_CLASSICAL_ADDRESS_BYTES` | Buffer overrun risk → fail-closed at FFI bounds check |
| BIP-39 sizes | `BIP39_ENTROPY_BYTES`, `BIP39_WORD_COUNT`, `BIP39_PBKDF2_OUTPUT_BYTES`, `BIP39_MNEMONIC_MAX_BYTES` (caller hint, not authoritative) | Fail-closed at FFI bounds check |
| Network discriminants | `DERIVATION_NETWORK_MAINNET/TESTNET/STAGENET/FAKECHAIN` (0/1/2/3) | Wrong-network-derived wallet would fail rederive on load (fail-closed) |
| RCT type | `RCTTypeFcmpPlusPlusPqc = 7` (C++ `src/fcmp/rctTypes.h`) and `ProofType::FcmpPlusPlusPqc => 7` (Rust `shekyl-oxide`) | Consensus split (silent wrong-output) — single-source on both sides today, listed in cbindgen scope below |
| Address version | `ADDRESS_VERSION_V1 = 0x01` (single source: `rust/shekyl-address/src/address.rs`) | Silent address mismatch — single-source today |
| FCMP reorg window | `FCMP_REFERENCE_BLOCK_MAX_AGE = 100` | Wallet rejects valid intents (fail-closed) |
| Wallet capability | `WALLET_CAPABILITY_FULL/VIEW_ONLY/HARDWARE_OFFLOAD/RESERVED_MULTISIG` (1/2/3/4) | Capability misclassification — fail-closed at decap (no key material on the wrong side) |
| Wallet KDF defaults | `WALLET_KDF_ALGO_ARGON2ID = 0x01`, `M_LOG2 = 0x10`, `T = 0x03`, `P = 0x01` | Fail-closed at decrypt (wrong KDF parameters → wrong key → AEAD tag mismatch) |
| Wallet file format | `WALLET_FILE_FORMAT_VERSION = STATE_FILE_FORMAT_VERSION = 0x01` | Fail-closed at envelope-version check |
| Wallet error codes | All 29 `SHEKYL_WALLET_ERR_*` (0..28), name-matched | Misleading triage messages, never silent corruption |
| Log levels & errors | All `SHEKYL_LOG_LEVEL_*` (0..5), all `SHEKYL_LOG_ERR_*` (0..-11) | Wrong-severity log entries; non-security |

The audit was a one-pass diff of `git grep -E '^\s*#define SHEKYL_'` on the
C++ side against `git grep -E '^pub const SHEKYL_|^pub const SEED_FORMAT_|^pub const RAW_SEED|^pub const MASTER_SEED|^pub const CLASSICAL_ADDRESS|^pub const PQC_PUBLIC_KEY|^pub const ML_KEM|^pub const BIP39_|^pub const ADDRESS_VERSION_|^pub const FCMP_|^pub const WALLET_FILE_FORMAT_|^pub const STATE_FILE_FORMAT_|^pub const KDF_|^pub const DEFAULT_KDF_|^pub const CAPABILITY_'` on the Rust side.

---

## Prevention work (`chore/cbindgen-consensus-constants`)

Per the Bug-2 post-mortem, hand-maintained constants on both sides of the
FFI are the bug class. Two things are landing to close it:

1. **Rust-internal equality-assertion tests for the two consensus-adjacent
   constants** (`SHEKYL_CLASSICAL_ADDRESS_BYTES`, `SHEKYL_SEED_FORMAT_*`)
   landed inside `fix/wallet-storage-test` itself. **Honest scope:** these
   tests compare the FFI re-export in `rust/shekyl-ffi/src/account_ffi.rs`
   to the authoritative constants in `rust/shekyl-crypto-pq/src/account.rs`.
   Both values are Rust-side. The tests *do not* read the C++ header
   `src/shekyl/shekyl_ffi.h`, so a future hand-edit to the C++ `#define`
   alone — the exact drift that produced Bugs 1 and 2 — would still leave
   them green. What they *do* catch: any divergence introduced inside the
   Rust workspace between authoritative and re-exported constants, before
   the C++ build runs.

   The cross-boundary detection (catching drift in the C++ `#define`
   itself) is the explicit job of #2 below. The post-mortem framing was
   originally that #1 alone closed the bug class; that was wrong, and is
   corrected here.

2. **A reduced-scope `build.rs`-style header generator** (`chore/cbindgen-consensus-constants`)
   covers only the constants where drift would cause silent wrong-output
   rather than fail-closed-on-load:

   - `RCTTypeFcmpPlusPlusPqc` (consensus-affecting)
   - `FCMP_REFERENCE_BLOCK_MIN_AGE`, `FCMP_REFERENCE_BLOCK_MAX_AGE` (just
     bit us in the form of Bug 3)
   - `ADDRESS_VERSION_V1` (silent address mismatch)
   - The four locked economic parameters (ESF, burn_base_rate,
     `staker_pool_share`, `staker_emission_share`) if any are duplicated
     across the FFI

   Mechanism: a `build.rs` in `shekyl-ffi` reads the authoritative Rust
   constants and emits a generated `shekyl_ffi_constants.h` with `#define`s.
   The hand-written `shekyl_ffi.h` `#include`s the generated header and
   adds `static_assert` sentinels so a future hand-edit of either side
   fails the build with an explicit message. Pattern precedent:
   `rust/shekyl-staking/build.rs` already generates Rust from
   `config/economics_params.json`; this is the inverse direction.

3. **Full migration of the remaining `SHEKYL_*` constants** to the
   generator is filed as FOLLOWUPS V3.0 (target: pre-audit-final). The
   remaining constants are all fail-closed-on-misuse, so the V3.0
   slot is justifiable; the consensus-affecting subset above is doing
   the load-bearing work pre-audit.

---

## Branches

This is the audit landing pattern across four branches:

| Branch | Findings addressed | Status |
| --- | --- | --- |
| `fix/wallet-storage-test` (this) | Bug 1 fix, Bug 2 fix, equality-assertion tests for both, BIP-39 + MAINNET account-layer round-trip test (closes the only path Bug 2 broke that wasn't already covered), Monero-era wallet fixture deletion, **Bug 4 absence + CI tripwire (commits 8–10): FOLLOWUPS architectural-decision entry, `static_assert` SFINAE detector against `wallet2::generate_from_bip39`, Rust mainnet BIP-39 test cross-reference**, this audit doc, CI_BASELINE / FOLLOWUPS / CHANGELOG updates. | This commit |
| `fix/fcmp-min-age-multisig-drift` (sibling) | Bug 3 fix in `rust/shekyl-engine-core/src/multisig/v31/intent.rs` and `docs/SHEKYL_MULTISIG_WIRE_FORMAT.md`, after `git log -S "10"` confirms the canonical value. Single-line value fix + doc. | Pending |
| `fix/legacy-account-generate-network-guard` (sibling) | Bug 4-adjacent fix: `account_base::generate(.., nettype)` 4-arg overload added; legacy 3-arg overload **deleted entirely**; production callers migrated (`wallet2::generate(...)`, `wallet_rpc_server::on_stop_background_sync`, and the `transfer_selected_rct` 0-change dummy with explicit `FAKECHAIN`); all 28 test callers migrated to pass `cryptonote::FAKECHAIN` explicitly; `tests/unit_tests/account.cpp::generate_uses_explicit_nettype_argument` regression test added covering both `recover=true` and `recover=false` paths on MAINNET / STAGENET. Note: this branch does **not** add a `wallet2::generate_from_bip39` wrapper — that absence is by design (Bug 4 above) and defended by the `static_assert` tripwire on `fix/wallet-storage-test`. The `on_create_wallet` / `wallet2_ffi::create` MAINNET/STAGENET regression (these RPCs were already broken pre-fix; now throw cleanly instead of silently miscompiling) is filed as FOLLOWUPS V3.0 deferred to the wallet2 BIP-39 entry point. | Delivered |
| `chore/cbindgen-consensus-constants` (sibling) | Reduced-scope generator. Closes the bug class for the consensus-affecting subset of constants before audit. | Pending |

The full-scope cbindgen migration of the remaining ~40 constants is
deferred to FOLLOWUPS V3.0 with target post-stressnet, pre-audit-final.
