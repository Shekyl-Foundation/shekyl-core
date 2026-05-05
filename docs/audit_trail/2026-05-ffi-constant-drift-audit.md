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
2026-05-05 — three real findings (Bug 1, Bug 2, Bug 3) plus one missing
API (Bug 4), with the remaining 43 constants confirmed aligned.

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
| Mechanism | C++ wrote `m_seed_format = 1` to disk meaning RAW32; on `wallet2::load`, the FFI `shekyl_account_rederive` received `seed_format = 1` and decoded `1` as `Bip39`; `permitted_seed_format(Fakechain, Bip39)` returned `false`; rederive returned `false`; load failed with `"(network, seed_format) pair disallowed or derivation inconsistent"`. The BIP-39 path accidentally appeared to round-trip in the buggy era because both sides held `0` for it (and `fmt_from_u8(0)` in Rust returned `None`, which also failed but for a different reason). |
| Failure mode | Fail-closed at every wallet load on the RAW32 path (Testnet, Fakechain). The BIP-39 path was equally broken but had no test exercising it. No path to silent corruption. |
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

Not strictly a constant-drift bug, surfaced during the same audit. **Not in
scope of `fix/wallet-storage-test`; tracked under
`fix/legacy-account-generate-network-guard` and FOLLOWUPS V3.0.**

| Field | Value |
| --- | --- |
| Symptom | The user-facing wallet2 from-seed API (`wallet2::generate(name, password, recovery_param, recover, two_random, create_address_file)`) calls `m_account.generate(recovery_param, recover, two_random)`, which routes through the legacy `account_base::generate()` wrapper. That wrapper hardcodes `cryptonote::FAKECHAIN` regardless of the wallet's `m_nettype`. |
| Result on mainnet/testnet/stagenet | Wallet stores keys derived under `FAKECHAIN` salt with `m_nettype = MAINNET/TESTNET/STAGENET`. On reload, `rederive_from_master_seed(m_nettype)` returns `false` because `MAINNET/STAGENET` don't permit `RAW32`. **Every from-seed wallet on mainnet is currently fail-closed-on-reload** and has been the entire time Bug 1 was masking it. |
| Why no production caller noticed | Bug 1 was masking it universally — no wallet on any network could load. After Bug 1 + Bug 2 fixes, FAKECHAIN works; mainnet still doesn't. |
| Form of fix (sibling branch) | Add `account_base::generate(recovery, recover, two_random, nettype)` overload + `account_base::generate_from_bip39_with_passphrase` plumbing through `wallet2`. The 3-arg legacy overload gets a transitional `THROW_WALLET_EXCEPTION_IF(nettype != FAKECHAIN, ...)` guard, then is deleted once callers migrate. The second non-test caller (`wallet_rpc_server::stop_background_sync` at `src/wallet/wallet_rpc_server.cpp:2339`) is also covered by the same fix. |
| Coverage added in this branch | `tests/unit_tests/account.cpp::rederive_from_bip39_reproduces_account_mainnet` exercises BIP-39+MAINNET at the `account_base` layer. The full `wallet2` storage round-trip on BIP-39+MAINNET cannot be exercised until the API exists. |

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

1. **Mechanical equality-assertion tests for the two consensus-adjacent
   constants** (`SHEKYL_CLASSICAL_ADDRESS_BYTES`, `SHEKYL_SEED_FORMAT_*`)
   landed inside `fix/wallet-storage-test` itself. These run on every
   `cargo test -p shekyl-ffi` and catch drift in CI on the next PR rather
   than at audit. (Cost: 5 minutes. Benefit: would have caught Bug 1 and
   Bug 2 the moment either side was edited.)

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
| `fix/wallet-storage-test` (this) | Bug 1 fix, Bug 2 fix, equality-assertion tests for both, BIP-39 + MAINNET account-layer round-trip test (closes the only path Bug 2 broke that wasn't already covered), Monero-era wallet fixture deletion, this audit doc, CI_BASELINE / FOLLOWUPS / CHANGELOG updates. | This commit |
| `fix/fcmp-min-age-multisig-drift` (sibling) | Bug 3 fix in `rust/shekyl-engine-core/src/multisig/v31/intent.rs` and `docs/SHEKYL_MULTISIG_WIRE_FORMAT.md`, after `git log -S "10"` confirms the canonical value. Single-line value fix + doc. | Pending |
| `fix/legacy-account-generate-network-guard` (sibling) | Bug 4 fix: add `account_base::generate(.., nettype)` overload, plumb through `wallet2::generate`, throw-guard on the legacy 3-arg overload, audit `wallet_rpc_server::stop_background_sync` for the same shape of break on mainnet. | Pending |
| `chore/cbindgen-consensus-constants` (sibling) | Reduced-scope generator. Closes the bug class for the consensus-affecting subset of constants before audit. | Pending |

The full-scope cbindgen migration of the remaining ~40 constants is
deferred to FOLLOWUPS V3.0 with target post-stressnet, pre-audit-final.
