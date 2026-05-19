# Electrum-words removal — CryptoNote 25-word mnemonic subsystem deletion from genesis

**Status.** **DRAFT — Round 1 (initial draft, 2026-05-19).** Phase 0
deliverable for the Electrum-words (CryptoNote-25-word mnemonic)
subsystem removal. Companion:
[`ELECTRUM_WORDS_REMOVAL_PLAN.md`](./ELECTRUM_WORDS_REMOVAL_PLAN.md).
Both documents must close the Phase 0 review cycle (target 4–6
rounds per `20-rust-vs-cpp-policy.mdc`) before any deletion code
lands.

**Scope.** Shekyl genesis ships BIP39-only for wallet seed
material. The inherited CryptoNote 25-word "Electrum-style"
mnemonic format and its 14-language word-list infrastructure are
deleted, not version-dispatched. The Phase 0 Mission Audit Lens B
finding B-1 designates this work as a pre-genesis deletion per
`60-no-monero-legacy.mdc` and `16-architectural-inheritance.mdc`.
The user-fiat decision (recorded in the audit substrate as
`b1_disposition_settled_delete`): shekyl-gui-wallet,
shekyl-mobile-wallet, and shekyl-web will route through the
existing Rust BIP39 FFI bridge regardless of their current state.

---

## 1. Inheritance disposition

### 1.1 Why this is Rule-60 residue

The CryptoNote 25-word mnemonic format is a CryptoNote-era seed
encoding inherited via Monero. Per
[`60-no-monero-legacy.mdc`](../../.cursor/rules/60-no-monero-legacy.mdc),
Shekyl begins at its own genesis with no pre-genesis blocks to
validate and no users with legacy wallet state. Inherited code
that exists solely to handle pre-genesis Monero/CryptoNote
behaviour is dead weight; the rule's enumeration of "removed from
construction and verification" does not list the mnemonic
subsystem only because the audit had not yet enumerated it.

The Electrum-words subsystem satisfies all three deletion
criteria from
[`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc):

1. **No Shekyl users with Electrum-words seeds exist.** Pre-genesis,
   there is no installed base. The `rm -rf ~/.shekyl` migration path
   covers any developer-side test wallets.
2. **The replacement primitive already ships.** BIP39 is already the
   canonical seed path on the Rust side, exported via the
   `shekyl_bip39_*` and `shekyl_account_generate_from_bip39` FFI
   functions (see §3.1).
3. **Carrying both paths is a permanent attack surface for a one-time
   problem.** Keeping a 25-word path "for compatibility" creates a
   second seed-derivation surface that auditors must reason about
   forever, when no consumer of Shekyl at genesis depends on it.

### 1.2 Architectural-inheritance framing

Per [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc),
the inherited Electrum-words code is *correct for Monero* (where
millions of pre-existing wallets use it) and *wrong for Shekyl*
(where zero pre-genesis wallets exist). The Monero code's
architecture — 14 language word lists, a CryptoNote checksum
scheme, a custom binary-to-words encoder — is well-tested in its
original context but contradicts Shekyl's pre-genesis posture.

This is the "inheriting code is not inheriting architecture"
finding made concrete: the audit's job is to surface that the
code's architecture (multi-language mnemonic infrastructure
serving pre-existing CryptoNote users) does not deliver against
Shekyl's threat model (one user base, one mnemonic standard,
BIP39 as universal industry default).

### 1.3 Where this sits relative to the Phase 0 Mission Audit

The Phase 0 Mission Audit (closed 2026-05-17) surfaced this work
as Lens B finding B-1: *"wallet2::is_deterministic + get_seed
chain on Monero-era 25-word mnemonic format; user-fiat: GUI/mobile
will route through BIP39"*. Per the audit's `audit_trajectory_ratio_observation`
pin, the audit's job was *finding* inherited architecture that
contradicts the threat model; *executing* the migration is the
work this PR series defines.

This PR (Phase 0) plus five-to-six implementation PRs (Phases 1–6
across five or six PRs total, depending on whether Phase 6 folds
into Phase 5's PR per plan §6.3) close out the B-1 audit finding.
No follow-up audit work is expected; the symbol-isolation CI
invariants (§7) become the structural compliance check that makes
future re-acquisition of Electrum-words surface detectable.

---

## 2. Deletion surface inventory

The total deletion surface is enumerated here so the per-phase PR
descriptions can cite this section rather than re-enumerating.
Line numbers are accurate as of `dev` tip after merges of PR #46
(audit substrate), PR #47 (Batch α PR 1 / Cargo.toml zeroize
features), PR #48 (Batch α PR 2 / ring_size cleanup), PR #53
(LWMA-1 Phase 4), and PR #54 (RandomX v2 Phase 1).

**Line-number stability discipline.** Line numbers drift as `dev`
advances. Each phase's branch-cut commit must re-verify every
deletion site against `dev` tip; the function name plus a nearby
unique token (e.g., the `crypto::ElectrumWords::words_to_bytes`
call inside `parse_wallet_create_data`, or the `"mnemonic"`
string literal inside the `query_key` switch) is the stable
anchor that survives drift. If a line-number citation in this
section cannot be located by its anchor at branch-cut time, that
is a Phase-N pre-flight finding (the symbol moved or was removed
upstream) and must be resolved before the deletion lands. The
per-phase PR description records the re-verified line numbers
relative to its branch-cut commit, citing this section for the
disposition rather than for the line numbers.

### 2.1 Mnemonics subsystem (`src/mnemonics/`)

Entire directory. 14 language word-list headers (~480 KB
combined):

```text
src/mnemonics/chinese_simplified.h    src/mnemonics/japanese.h
src/mnemonics/dutch.h                 src/mnemonics/lojban.h
src/mnemonics/english.h               src/mnemonics/portuguese.h
src/mnemonics/english_old.h           src/mnemonics/russian.h
src/mnemonics/esperanto.h             src/mnemonics/spanish.h
src/mnemonics/french.h
src/mnemonics/german.h
src/mnemonics/italian.h
```

Plus the implementation + framework files:

```text
src/mnemonics/CMakeLists.txt
src/mnemonics/electrum-words.cpp
src/mnemonics/electrum-words.h
src/mnemonics/language_base.h
src/mnemonics/singleton.h
```

Plus the test file:

```text
tests/unit_tests/mnemonics.cpp
```

Total: 21 files deleted, ~570 KB.

### 2.2 wallet2 core methods

| File | Symbol | Disposition |
| --- | --- | --- |
| `src/wallet/wallet2.h:1001` | `bool is_deterministic() const` | Delete declaration (Phase 4) per §4.10's `is_deterministic` disposition (ii) |
| `src/wallet/wallet2.h:1002` | `bool get_seed(epee::wipeable_string&, const epee::wipeable_string&)` | Delete declaration (Phase 4) — Phase 1's dispatch-branch rewire (per §4.5) breaks the dependency on this method, so Phase 4 can delete it cleanly |
| `src/wallet/wallet2.h:1007` | `const std::string &get_seed_language() const` | Delete declaration (Phase 4) |
| `src/wallet/wallet2.h:1011` | `void set_seed_language(const std::string&)` | Delete declaration (Phase 4) |
| `src/wallet/wallet2.cpp:1362` | `bool wallet2::is_deterministic() const` body | Delete definition (Phase 4) |
| `src/wallet/wallet2.cpp:1372` | `bool wallet2::get_seed(...)` body | Delete definition (Phase 4) — Phase 1 rewires the only call site (`wallet2_ffi.cpp:643` dispatch branch) to call Rust BIP39 directly, leaving this method dead-but-extant at Phase 4 entry; Phase 4 deletes the body alongside the declaration |
| `src/wallet/wallet2.cpp:1425` | `const std::string &wallet2::get_seed_language() const` body | Delete definition (Phase 4) |
| `src/wallet/wallet2.cpp:1433` | `void wallet2::set_seed_language(const std::string&)` body | Delete definition (Phase 4) |

The Electrum-words rewire scope across the codebase (`words_to_bytes`,
`bytes_to_words`, `get_is_old_style_seed`, `get_language_list`,
`old_language_name`, `is_valid_language` callers) spans three files
and is **not** localized to the `wallet2::generate()` /
`wallet2::restore()` method bodies — `wallet2::generate(...,
recovery_param: secret_key, ...)` at line 5933 takes a pre-decoded
`secret_key` (the words-to-bytes conversion happens in the caller);
`wallet2::restore` at line 6106 is hardware-wallet-only restore and
has no Electrum-words branch. The actual Phase 1 rewire targets are:

| File | Line | Surface |
| --- | --- | --- |
| `src/wallet/wallet2.cpp:600` | `parse_wallet_create_data` JSON helper | `ElectrumWords::words_to_bytes(field_seed, recovery_key, old_language)` — replaced with BIP39 path |
| `src/wallet/wallet2.cpp:606–611` | `parse_wallet_create_data` JSON helper | `seed_passphrase` JSON field handling. Today calls `cryptonote::decrypt_key(recovery_key, field_seed_passphrase)` (Monero-encrypt_key semantic). Phase 1 reuses the field name + JSON schema but threads the passphrase to `shekyl_account_generate_from_bip39`'s `passphrase` parameter (BIP39-PBKDF2-HMAC-SHA512 semantic). The semantic shift is documented in §4.5.1; field-name preservation is the lowest-friction path for existing JSON-restore consumers. |
| `src/wallet/wallet2.cpp:660–661` | `parse_wallet_create_data` JSON helper | `old_language_name` + `get_is_old_style_seed` deprecated-wallet detection — deleted |
| `src/wallet/wallet2.cpp:669` | `parse_wallet_create_data` JSON helper | `wallet->set_seed_language(old_language)` — deleted |
| `src/wallet/wallet2_ffi.cpp:643` | `query_key("mnemonic")` dispatch branch implementation | Today calls `wallet2::get_seed` → `ElectrumWords::bytes_to_words`. Rewired in Phase 1 to call `shekyl_bip39_mnemonic_from_entropy(wallet.bip39_entropy())` directly via the FFI. The dispatch case label `"mnemonic"` stays per §4.5; only the implementation body changes. Phase 4 then deletes `wallet2::get_seed` outright (no longer called). The dispatch additionally hard-errors on non-empty passphrase per §4.5.1 (passphrase has no meaning at phrase-emit time under BIP39). |
| `src/wallet/wallet2.cpp:1389` | `ElectrumWords::bytes_to_words(key, ...)` call inside `wallet2::get_seed` body | Deleted in Phase 4 alongside the method body |
| `src/wallet/wallet_rpc_server.cpp:2324` | `on_stop_background_sync` seed-recovery branch | `ElectrumWords::words_to_bytes(req.seed, recovery_key, language)` — Phase 2 deletes the entire `if (!req.seed.empty())` block at lines 2316–2366 alongside the `seed` / `seed_offset` fields on `COMMAND_RPC_STOP_BACKGROUND_SYNC::request`. The seed-based recovery path is dead-on-mainnet today (per inline comment at 2345–2362) and goes wholesale; password-only stop-background-sync survives. A BIP39 seed-recovery replacement is a separate `docs/FOLLOWUPS.md` V3.2 item (currently tracked). |
| `src/wallet/wallet_rpc_server.cpp:4162` | `on_restore_deterministic_wallet` (whole RPC handler) | `ElectrumWords::words_to_bytes(req.seed, recovery_key, old_language)` — Phase 2 deletes the whole RPC command + handler (`COMMAND_RPC_RESTORE_DETERMINISTIC_WALLET`). |
| `src/wallet/wallet_rpc_server.cpp:4257` | `on_restore_deterministic_wallet` reply | `ElectrumWords::bytes_to_words(recovery_val, electrum_words, mnemonic_language)` — Phase 2 deletion (same handler as above). |
| `src/wallet/wallet_rpc_server.cpp:3630–3631` | GET_LANGUAGES handler | `ElectrumWords::get_language_list(...)` — phase 2 deletion (whole RPC command goes) |
| `src/wallet/wallet2_ffi.cpp:416` | `wallet2_ffi_restore_deterministic_wallet` body | `ElectrumWords::words_to_bytes(seed, recovery_key, old_language)` — phase 3 FFI surface deletion (whole function goes) |
| `src/wallet/wallet2_ffi.cpp:1197–1198` | language-list export | `ElectrumWords::get_language_list(...)` — phase 3 deletion |

The `language` / `old_language` local variables in `wallet2.cpp`'s
`parse_wallet_create_data` helper become unused once
`words_to_bytes` is replaced; they are deleted in the same Phase 1
atomic commit per §4.10's expanded Phase 1 scope.

**Fresh-wallet generation flow defers to shekyl-gui-wallet.** The
`wallet2_ffi_create_wallet` and `on_create_wallet` paths route
through `wallet2::generate(..., dummy_key=null_skey, recover=false,
...)` → `account_base::generate(...)` → `shekyl_account_generate_from_raw_seed`,
which is mainnet-broken today (RAW32 is TESTNET/FAKECHAIN-only per
`src/cryptonote_basic/account.cpp:443–446`). The
"fresh entropy → BIP39 phrase → BIP39 derivation → store entropy"
flow described in §4.10 point #1 lives in **shekyl-gui-wallet's
Rust path** (calls `shekyl_account_generate_from_bip39` directly,
displays the phrase to the user once for backup, hands the
resulting account material to wallet2 via a path that does *not*
populate `m_bip39_entropy` in B-1 scope). Consequence:
post-B-1, `query_key("mnemonic")` works on restore-from-phrase
wallets and hard-errors on new-via-FFI wallets. Phrase backup at
creation time is the GUI's responsibility outside wallet2 state.
A future V3.x architectural workstream may add
`wallet2_ffi_create_wallet_from_bip39` if wallet2-side entropy
tracking on the new-wallet path becomes load-bearing; not B-1 scope.
See §4.10 point #1 for the full disposition rationale.

### 2.3 wallet2 state and JSON ser/de

| File | Line | Disposition |
| --- | --- | --- |
| `src/wallet/wallet2.h` | `std::optional<epee::mlocked<tools::scrubbed_arr<uint8_t, 32>>> m_bip39_entropy;` field | **Add** (Phase 1 — new state field per §4.10) |
| `src/wallet/wallet2.h` | `const std::optional<epee::mlocked<tools::scrubbed_arr<uint8_t, 32>>>& bip39_entropy() const` accessor | **Add** (Phase 1 — read-only public accessor used by `wallet2_ffi.cpp:643` dispatch-branch rewire per §4.5 + §4.10) |
| `src/wallet/wallet2.h:1728` | `std::string seed_language;` field | Delete field (Phase 4 Commit C) |
| `src/wallet/wallet2.cpp` JSON write path | JSON write of `bip39_entropy` | **Add** (Phase 1 — new ser/de per §4.10) |
| `src/wallet/wallet2.cpp` JSON read path | JSON read of `bip39_entropy` | **Add** (Phase 1 — new ser/de per §4.10) |
| `src/wallet/wallet2.cpp:4793–4802` | JSON write of `seed_language` | Delete (Phase 4 Commit B) |
| `src/wallet/wallet2.cpp:5344–5347` | JSON read of `seed_language` | Delete (Phase 4 Commit B) |
| `src/wallet/wallet2.cpp:6479` | Comment `"Pre-v1 wallets (legacy 25-word Electrum seed…)"` | Delete (Phase 4 Commit A, or earlier as opportunistic) |

### 2.4 RPC surface

| RPC command | File | Line | Disposition |
| --- | --- | --- | --- |
| `COMMAND_RPC_GET_LANGUAGES` | `src/wallet/wallet_rpc_server_commands_defs.h:2074` | struct + handler | Delete (Phase 2) |
| `COMMAND_RPC_RESTORE_DETERMINISTIC_WALLET` | `src/wallet/wallet_rpc_server_commands_defs.h:2223` | struct + handler | Delete (Phase 2) |
| `COMMAND_RPC_QUERY_KEY` mnemonic branch | `src/wallet/wallet_rpc_server.cpp` query_key dispatch | conditional | The RPC-level dispatch label `"mnemonic"` persists per §4.5. Today the RPC handler delegates to `wallet2::get_seed`; in Phase 1 the handler is rewired to read `wallet.bip39_entropy()` and call `shekyl_bip39_mnemonic_from_entropy` directly (same shape as the FFI-level rewire in §2.5). Post-Phase-4 the RPC handler does not call `wallet2::get_seed` (which no longer exists). |
| `get_wallet_words` handler | `src/wallet/wallet_rpc_server.cpp:2214,2220` | handler body | Delete (Phase 2) |
| Language-validation branches in surviving handlers | `src/wallet/wallet_rpc_server.cpp:3661, 4082` | `is_valid_language(req.language)` validation branches in `on_create_wallet` and `on_generate_from_keys` | Delete (Phase 2) |
| `set_seed_language` calls in surviving handlers | `src/wallet/wallet_rpc_server.cpp:3688, 4088` | `wal->set_seed_language(req.language)` calls in `on_create_wallet` and `on_generate_from_keys` | Delete the call sites (Phase 2). These are paired with the validation-branch deletions above; deleting only the validation branch would leave the `set_seed_language` call referencing the about-to-be-deleted `req.language` field. |
| `language` fields on surviving RPC request structs | `src/wallet/wallet_rpc_server_commands_defs.h` (`COMMAND_RPC_CREATE_WALLET::request`, `COMMAND_RPC_GENERATE_FROM_KEYS::request`) | request-struct field | Delete the `language` field from both structs (Phase 2). Request-schema change forces JSON-parse-error on any caller that supplies a `language` field — matches the §4.3 hard-error discipline at the FFI layer; consumers that today pass `language="English"` see immediate breakage rather than silent ignore. |
| `on_restore_deterministic_wallet` handler body | `src/wallet/wallet_rpc_server.cpp:4162–4225` | `words_to_bytes`, `get_is_old_style_seed`, `is_valid_language`, `bytes_to_words` calls | Delete (Phase 2) as part of the whole `COMMAND_RPC_RESTORE_DETERMINISTIC_WALLET` handler deletion. |
| `on_stop_background_sync` seed-based recovery branch | `src/wallet/wallet_rpc_server.cpp:2316–2366` | the entire `if (!req.seed.empty()) { … }` block + `seed` / `seed_offset` fields on `COMMAND_RPC_STOP_BACKGROUND_SYNC::request` | **Delete the whole block** (Phase 2) including the request-struct field deletions. Comment at lines 2345–2362 documents this branch as mainnet-broken-today; password-only `stop_background_sync` survives. BIP39 seed-recovery replacement is a `docs/FOLLOWUPS.md` V3.2 item (not B-1 scope). |

### 2.5 FFI surface

| FFI symbol | File | Disposition |
| --- | --- | --- |
| `wallet2_ffi_restore_deterministic_wallet` | `src/wallet/wallet2_ffi.h:98–104` + `wallet2_ffi.cpp:414–431` | Delete entire function (Phase 3) |
| `wallet2_ffi_create_wallet` `language` parameter | `src/wallet/wallet2_ffi.h:87` + `wallet2_ffi.cpp:309–319` | Drop parameter (signature change; Phase 3) |
| `wallet2_ffi_generate_from_keys` `language` parameter | `src/wallet/wallet2_ffi.h:113` + `wallet2_ffi.cpp:523–527` | Drop parameter (signature change; Phase 3) |
| `query_key("mnemonic")` dispatch branch | `src/wallet/wallet2_ffi.cpp:643,653` | **Rewire implementation to Rust BIP39 routing (Phase 1 atomic commit); dispatch label `"mnemonic"` persists per §4.5; `wallet2::get_seed` call site removed when the underlying method deletes in Phase 4 Commit A.** The branch implementation post-Phase-1 reads the entropy via `wallet.bip39_entropy()` (the new accessor per §2.3) and calls `shekyl_bip39_mnemonic_from_entropy` to produce the phrase, returning the §4.10 hard error if entropy is unset. |
| `query_key("mnemonic")` dispatch — `passphrase` parameter | `src/wallet/wallet2_ffi.cpp:643` (via the wallet2 FFI `query_key` entry's `passphrase` parameter) | **Hard-error on non-empty passphrase** (Phase 1 atomic commit) per §4.5.1. Under Electrum-words the passphrase encrypted the spend secret before encoding-to-words; under BIP39 the phrase is derived from entropy alone and the passphrase has no meaning at phrase-emit time. Silently ignoring the parameter would be the §4.3-rule production-software graceful-degradation default leaking into pre-genesis; the discipline-correct disposition is loud failure. The RPC layer does not expose the passphrase parameter, so the hard-error surface is FFI-only. |
| Language-list export | `src/wallet/wallet2_ffi.cpp:1197–1198` | Delete (Phase 3) |
| `crypto::ElectrumWords::words_to_bytes` + `is_valid_language` calls | `src/wallet/wallet2_ffi.cpp:309,416,429,523` | Delete (Phase 3) |

### 2.6 Build system

| File | Change |
| --- | --- |
| `src/CMakeLists.txt` | Remove `add_subdirectory(mnemonics)` |
| `src/mnemonics/CMakeLists.txt` | Delete entire file |
| `src/wallet/CMakeLists.txt` | Remove `mnemonics` from link dependencies (if listed) |
| `tests/unit_tests/CMakeLists.txt` | Remove `mnemonics.cpp` from test sources |

### 2.7 Tests

| File | Disposition |
| --- | --- |
| `tests/unit_tests/mnemonics.cpp` | Delete entire file (Phase 5) |

Test-migration scope spans two phases, mirroring the two consumer
surfaces (RPC at Phase 2 and FFI at Phase 3):

- **Phase 2 — RPC-consumer migrations** (per the Phase 2 work-item
  list, §2.4 G7). Twelve Python functional tests under
  `tests/functional_tests/` today call
  `restore_deterministic_wallet(seed=..., language=...)`. Each
  migrates to `generate_from_keys(spend_key=..., view_key=...,
  address=...)`, with the spend / view secret keys pre-derived
  from the test's known fixed 25-word seed and hardcoded as hex
  constants in the test source. Three sites in
  `tests/functional_tests/transfer.py` call
  `stop_background_sync(seed=...)`; each converts to
  `stop_background_sync(password=...)` per the surviving
  password-based code path. These migrations land in the same
  Phase 2 PR as the RPC-deletion changes.

- **Phase 3 — FFI-consumer language-parameter drops** (alongside
  the FFI signature change in §3.1's work items 2 and 3). Any
  C++/Rust integration test that passes
  `language="English"` (or any other language string) to
  `wallet2_ffi_create_wallet` or
  `wallet2_ffi_generate_from_keys` is updated to drop the
  `language` argument. The in-tree `rust/shekyl-engine-rpc`
  wrapper tests are covered by the same Phase 3 commit per
  substrate §3.2.0's atomic-with-C++-FFI discipline.

### 2.8 Includes audit

The `#include "mnemonics/electrum-words.h"` directive appears at:

- `src/wallet/wallet2.cpp:79`
- `src/wallet/wallet2_ffi.cpp:38`
- `src/wallet/wallet_rpc_server.cpp:64`

All three are deleted in their respective phases (Phase 1 for
wallet2.cpp internal cleanup; Phase 2 for wallet_rpc_server.cpp;
Phase 3 for wallet2_ffi.cpp).

---

## 3. BIP39 replacement path

### 3.1 Existing FFI bridge

The C++ → Rust BIP39 bridge exists for four of the five required
functions; the fifth (`shekyl_bip39_mnemonic_to_entropy`) is added
in Phase 1 per §4.10. Per `src/shekyl/shekyl_ffi.h`:

```c
// src/shekyl/shekyl_ffi.h
//
// Existing (in production, called from src/cryptonote_basic/account.cpp):
bool shekyl_bip39_validate(const uint8_t* words_ptr, size_t words_len);
bool shekyl_bip39_mnemonic_from_entropy(
    const uint8_t* entropy32_ptr,
    uint8_t* words_out, size_t words_cap, size_t* words_len_out);
bool shekyl_bip39_mnemonic_to_pbkdf2_seed(
    const uint8_t* words_ptr, size_t words_len,
    const uint8_t* passphrase_ptr, size_t passphrase_len,
    uint8_t* seed_out_64);
bool shekyl_account_generate_from_bip39(
    const uint8_t* words_ptr, size_t words_len,
    const uint8_t* passphrase_ptr, size_t passphrase_len,
    uint8_t network,
    uint8_t* master_seed_out_64,
    ShekylAllKeysBlob* blob_out);

// NEW in Phase 1 (per §4.10 BIP39 entropy persistence disposition):
bool shekyl_bip39_mnemonic_to_entropy(
    const uint8_t* words_ptr, size_t words_len,
    uint8_t* out32_ptr);
```

Rust implementations for the four existing functions live in
`rust/shekyl-ffi/src/account_ffi.rs` at lines 134, 163, 212, 584.
`src/cryptonote_basic/account.cpp` already calls them (the bridge
is in production, not test scaffolding). The Rust-side
`shekyl_bip39_mnemonic_from_entropy` mandates exactly 32 bytes of
entropy (24-word canonical per
`rust/shekyl-crypto-pq/src/bip39.rs:46`); the to-be-added
`shekyl_bip39_mnemonic_to_entropy` mirrors that constraint (returns
false for any phrase whose entropy length isn't 32 bytes).

The fifth FFI function's implementation surface:

```rust
// rust/shekyl-crypto-pq/src/bip39.rs (new public function)
pub fn entropy_from_mnemonic(
    words: &str,
) -> Result<Zeroizing<[u8; SHEKYL_BIP39_ENTROPY_BYTES]>, CryptoError>;

// rust/shekyl-ffi/src/account_ffi.rs (new extern "C" function)
#[no_mangle]
pub unsafe extern "C" fn shekyl_bip39_mnemonic_to_entropy(
    words_ptr: *const u8,
    words_len: usize,
    out32_ptr: *mut u8,
) -> bool;
```

The substitution at the Electrum-words call sites listed in §2.2
is per-site (not a "straight swap at one line range"):

- `wallet2.cpp:600` (`parse_wallet_create_data` JSON helper) routes
  the JSON-supplied seed through `shekyl_bip39_validate` and
  `shekyl_bip39_mnemonic_to_entropy` (new) to recover entropy, then
  calls `shekyl_account_generate_from_bip39` to produce the account
  and populates `m_bip39_entropy` per §4.10.
- `wallet2_ffi.cpp:643` (`query_key("mnemonic")` dispatch branch
  implementation) is rewired in Phase 1 to call
  `shekyl_bip39_mnemonic_from_entropy(wallet.bip39_entropy())`
  directly via the FFI per §4.5 + §4.10. The dispatch case label
  `"mnemonic"` persists; only the implementation body changes.
  Phase 4 deletes `wallet2::get_seed` (which is no longer called
  by the rewired dispatch).
- `wallet_rpc_server.cpp` `query_key` dispatch (RPC handler that
  exposes `query_key` to RPC callers) is rewired in Phase 1 with
  the same shape as the FFI-level dispatch — read
  `wallet.bip39_entropy()` and call the FFI directly.
- `wallet_rpc_server.cpp:2324, 4162, 4257, 3630–3631` and
  `wallet2_ffi.cpp:416, 1197–1198` are RPC and FFI surfaces that
  go away entirely in Phase 2 / Phase 3 — no rewire, just
  deletion.
- `wallet2.cpp:1389` (`ElectrumWords::bytes_to_words(key, ...)`
  call inside `wallet2::get_seed`) is **not** rewired — the
  method body is dead-but-extant after Phase 1's dispatch-branch
  rewire, and Phase 4 Commit A deletes the entire method body.

No Phase 1 prerequisite work is required to add
`shekyl_bip39_mnemonic_to_entropy` — it lands in the same Phase 1
atomic commit alongside the wallet2.cpp rewire, since the rewire
depends on it.

### 3.2 Per-consumer migration map

The cross-repo coordination matrix at audit-pre-flight (2026-05-19)
collapses from three consumers to one cross-repo consumer
(`shekyl-gui-wallet`) plus one in-tree Rust consumer
(`shekyl-engine-rpc`) that lives inside `shekyl-core`'s own
workspace. The in-tree consumer is functionally the same as a
cross-repo consumer from the FFI-deletion-blast-radius perspective
— wrapper and `extern "C"` declaration are two ends of one wire —
but it lands in the same shekyl-core PR as the C++ FFI change
rather than a sibling PR.

#### 3.2.0 shekyl-engine-rpc (IN-TREE Rust consumer; Phase 3 atomic with C++ FFI)

The Rust crate at `rust/shekyl-engine-rpc/` wraps `wallet2_ffi` for
the daemon-side wallet engine. Pre-flight inspection (2026-05-19)
confirms three consumption sites:

| File | Symbol | Phase 3 disposition |
| --- | --- | --- |
| `rust/shekyl-engine-rpc/src/ffi.rs:57` | `extern "C" fn wallet2_ffi_create_wallet(... language: *const c_char ...)` declaration | Drop the `language: *const c_char` parameter (signature change atomic with the C++ FFI deletion in §3.1's work item 2). |
| `rust/shekyl-engine-rpc/src/ffi.rs:72` | `extern "C" fn wallet2_ffi_restore_deterministic_wallet(...)` declaration | Delete the entire `extern` declaration (atomic with the C++ FFI function deletion in §3.1's work item 1). |
| `rust/shekyl-engine-rpc/src/ffi.rs:82` | `extern "C" fn wallet2_ffi_generate_from_keys(... language: *const c_char ...)` declaration | Drop the `language: *const c_char` parameter (atomic with the C++ FFI deletion in §3.1's work item 3). |
| `rust/shekyl-engine-rpc/src/engine.rs:195–280` (`create_wallet`, `restore_deterministic_wallet`, `generate_from_keys` Rust wrappers) | Rust-side wrapper functions consumed by the daemon-side wallet engine | Match the FFI signature changes: drop `language: &str` parameters from `create_wallet` and `generate_from_keys`; delete `restore_deterministic_wallet` outright. Update any in-tree callers (search via `git grep -E 'engine::(create_wallet\|restore_deterministic_wallet\|generate_from_keys)'`). |

The in-tree migration lands as part of the same shekyl-core Phase 3
PR as the C++ FFI deletion — the wrapper change and the `extern "C"`
declaration change cannot land separately without producing a
non-buildable intermediate state (extern declaration referencing a
non-existent symbol; or wrapper passing a parameter the extern no
longer accepts). This is the same atomic-commit discipline as §4.10's
"every change is the same architectural change at a different
surface" — bisecting any single piece out produces a broken
intermediate. The atomicity scope is **shekyl-core PR commit**, not
**cross-repo merge** — the wrapper change is internal to the
shekyl-core repo and merges in the same PR as the FFI deletion.

The cross-repo coordination concern (§3.2.1 `shekyl-gui-wallet`)
attaches to consumers *outside* `shekyl-core`'s workspace.
`shekyl-engine-rpc` is in-workspace, so its migration runs inside
the §3.1 work-item list rather than the §3.2 sibling-PR matrix.

#### 3.2.1 shekyl-gui-wallet (ACTIVE consumer; Phase 3 coordination party)

Substantial Electrum-words integration via `src-tauri/`:

| File | Surface |
| --- | --- |
| `src-tauri/src/wallet_bridge.rs:156–159` | `create_wallet(wallet_path, password, language)` Rust-side wrapper passes `language` to `wallet2_ffi_create_wallet` |
| `src-tauri/src/wallet_bridge.rs:366–377` | `restore_deterministic_wallet(handle, path, seed, password, language, height, seed_offset)` Rust-side wrapper |
| `src-tauri/src/wallet_bridge.rs:475–477` | `query_key(handle, key_type)` dispatcher (calls `wallet2_ffi_query_key`) |
| `src-tauri/src/commands.rs:64,72,498,519,527,613,636,652,666,703,709,714` | Tauri command surface: `language` parameters on import/create flows, `query_key("mnemonic")` for seed display, `SeedInfo { seed, seed_language }` data structure |

Migration shape (Phase 3 coordinated unit):

1. `wallet_bridge.rs::create_wallet` drops `language` parameter; signature becomes `create_wallet(wallet_path, password)`.
2. `wallet_bridge.rs::restore_deterministic_wallet` deleted in its current form; replaced by a wrapper around the new BIP39 entry (whose Rust-side caller routes through `shekyl_account_generate_from_bip39` on the shekyl-core side, since `wallet2_ffi_restore_deterministic_wallet` no longer exists).
3. `wallet_bridge.rs::query_key("mnemonic")` continues to work as the string key (§4.5), but the wallet-side dispatch returns the BIP39 phrase rather than the 25-word Electrum encoding.
4. `commands.rs` Tauri command signatures lose their `language: Option<String>` parameters; the `seed_language: String` field on `SeedInfo` is dropped.
5. UI flows that show a "select seed language" picker before wallet creation are deleted; UI flows that show a 25-word display for backup are repointed to the BIP39 24-word display.

The shekyl-gui-wallet migration PR is a sibling of the shekyl-core
Phase 3 PR; both land coordinated per §5.3.

#### 3.2.2 shekyl-mobile-wallet (FUTURE consumer; no Phase 3 migration)

Pre-flight inspection (2026-05-19) confirms: zero references to
`wallet2_ffi`, `restore_deterministic_wallet`,
`set_seed_language`, or `electrum` across the entire repo. The
repo has two commits — one Android-first wallet example, one
docs realignment. Not yet a `wallet2_ffi` consumer.

shekyl-mobile-wallet picks up the post-deletion FFI surface
whenever it begins binding to `wallet2_ffi`. No Phase 3
coordination work in this repo.

#### 3.2.3 shekyl-web (NOT a consumer; no Phase 3 migration)

Pre-flight inspection: zero references. Not a `wallet2_ffi`
consumer. Will pick up the post-deletion FFI surface if/when it
begins binding.

### 3.3 Coordination convention for non-active consumers

During B-1 Phase 0 → Phase 3 flight, shekyl-mobile-wallet and
shekyl-web **defer initiating `wallet2_ffi` consumption work**.
Both repos pick up the post-deletion FFI surface (BIP39-only, no
Electrum-words paths) whenever they begin binding. This is a
coordination convention, not a blocker — both repos remain free
to develop other functionality during the flight.

If either repo's roadmap forces a `wallet2_ffi` binding during
B-1 flight, the matrix re-expands to include that repo as a Phase
3 coordination party and the disposition is re-opened per the
reversion clauses in §6.5.

**Enforcement is honor-system; no automated gate.** This is
acknowledged-and-accepted per the small-first-party-team posture:
no CI hook polices `wallet2_ffi` introduction in
shekyl-mobile-wallet or shekyl-web during B-1 flight; no
foundation-level coordination tooling automatically flags the
matrix re-expansion. The mitigation is human-review-at-PR-time —
this design doc serves as the announce-to-Foundation discipline,
and Foundation-side review of any `wallet2_ffi`-touching PRs in
mobile/web during B-1 flight catches the re-expansion early. The
risk of an honor-system slip is bounded by:

- The team is small enough that PR-author awareness of in-flight
  workstreams is the normal case.
- Both repos' current `Cargo.toml` show no `wallet2_ffi`-related
  path dependencies (verified 2026-05-19); introduction would be
  visible at the dependency level.
- The B-1 flight is bounded (5 PRs, ~weeks of elapsed time, not
  months).

A stronger automated discipline (e.g., a `wallet2_ffi` import
detector running on shekyl-mobile-wallet / shekyl-web CI during
B-1-flight tag windows) is **not** introduced in V3.0 — the
honor-system risk-bound is acceptable for the team scale, and the
automation cost outweighs the residual risk. Post-genesis, this
discipline pattern may need automation if the team scales; the
disposition is re-opened per the reversion clauses in §6.5 if a
named third-party consumer surfaces.

---

## 4. Permanent architectural decisions

These decisions are made now and locked. Any future proposal to
reverse them must start with a new design doc that addresses the
rationale below.

### 4.1 BIP39-only from genesis, no version dispatch

Per `60-no-monero-legacy.mdc`, genesis ships with BIP39 and
nothing else. No `HF_VERSION_BIP39` gate, no fallback to
Electrum-words, no "v1 mnemonic" / "v2 mnemonic" path. Inherited
code that handles pre-genesis 25-word seed material is deleted,
not gated. This matches the LWMA-1 §1 disposition and the
RandomX-v2 §1 disposition.

### 4.2 wallet2::generate() retains orchestrator role; Rust does seed production

Disposition: **(a)** from the Round 1 critical-gap review.
`wallet2::generate()` continues to be the C++ orchestrator of
wallet-file creation (keys → encrypted file persistence; wallet
state initialization; address-book bootstrap), but offloads
seed-production to the Rust BIP39 entry via
`shekyl_account_generate_from_bip39`. Rationale:

1. **Rule 20 rule 1: "Rust if touches a secret."** The BIP39
   mnemonic is the master secret. Per
   [`20-rust-vs-cpp-policy.mdc`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc)
   rule 1, secret-generation logic belongs in Rust.
2. **Rejected: (c) wholesale wallet2::generate() deletion.** That
   shape is the B-3 architectural workstream (Rust owns the
   wallet-file orchestration). Materially larger, multi-quarter,
   not pre-genesis-bounded. B-1 is a bounded deletion, not a
   re-architecture.
3. **Rejected: (b) wallet2::generate() becomes a shim requiring
   pre-generated keys.** Splits responsibility awkwardly between
   "we have keys" and "we make the file"; produces a non-obvious
   call-site contract.
4. **Accepted: (a) wallet2::generate() calls Rust BIP39 entry.**
   Matches the wallet2 cluster (B-2/C-1/C-3/C-4/C-5) stop-gap
   pattern from the audit: wallet2 keeps orchestrating while
   secret-touching operations route to Rust. The B-3 architectural
   workstream subsumes this stop-gap when it lands; until then,
   the (a) shape is the architectural-integrity-now answer per
   `16-architectural-inheritance.mdc`'s `cost-benefit-defer-to-later`
   anti-pattern recognition.

### 4.3 Phase 1 hard-error on non-empty `language` parameter

Phase 1's wallet2 internal-only rewire is **signature-preserving,
behavior-narrowing-to-hard-error** on any non-empty `language`
parameter. Empty / `None` / `nullptr` is the only accepted value.
Non-empty values return an error code (FFI-level) or throw
`tools::error::wallet_internal_error` (RPC-level).

Rationale: the alternative — "silently accept and ignore the
parameter" — is the production-software graceful-degradation
default leaking into a pre-genesis context where the
discipline-correct posture is loud failure. Specifically:

1. Silently-ignored parameters produce a window between Phase 1
   land and Phase 3 land during which consumer code that still
   passes `language="English"` *appears to work*; the parameter
   has no effect, the wallet generates correctly, and the
   consumer ships code that breaks at Phase 3 cutover with no
   prior signal.
2. Hard-error-on-non-empty makes Phase 1 land the discovery
   point for consumer migration. Consumers see the breakage
   immediately, migrate, ship; Phase 3 cutover is a no-op for
   correctly-migrated consumers.
3. This matches the §5.2 atomic-cutover disposition: no
   callable-but-discouraged surface; no zombie code. Same
   discipline at the Phase 1 boundary as at the Phase 3 boundary.

This decision pins the inversion of a recurring discipline
anti-pattern: production-software-discipline defaults
(graceful-degradation, deprecation windows) leak into pre-genesis
contexts when not explicitly inverted. The Phase 0 Mission Audit's
`b1_disposition_settled_delete` + this Phase 1 disposition are
two instances of the same inversion.

### 4.4 `seed_language` field removed; wallet creation does not carry "seed language" concept

The `seed_language` field on `wallet2` (currently
`src/wallet/wallet2.h:1728`) is dropped in Phase 4. BIP39 is
English-wordlist-only at genesis; there is no language concept to
carry. The JSON serialization of `seed_language`
(`wallet2.cpp:4793–4802` write, `:5344–5347` read) and the field
itself are both dropped in Phase 4, but in two sequential commits
per plan §4.2: **Commit B** drops the JSON write/read sites
(making the field write-only-in-memory), and **Commit C** drops
the field declaration and any remaining in-memory writers. Commit
B precedes Commit C so that a bisect landing between them sees a
wallet that no longer persists `seed_language` to disk but still
carries an unused in-memory field — a safe intermediate state.
"Dropped alongside the field" elsewhere in this doc refers to the
Phase-4-scoped pairing, not to a single commit.

Multilingual BIP39 wordlists (Japanese, Spanish, French, etc.,
per BIP39 spec) are a future feature that, if needed, lands via
the Rust-side BIP39 implementation in `shekyl-crypto-pq::bip39`,
not via re-introducing a wallet2 `seed_language` field. The wallet
state structure does not need a multilingual concept; the
seed-presentation layer (GUI) can pick a wordlist at display
time.

### 4.5 `query_key` string-key kept as `"mnemonic"`; routing changes to Rust BIP39

Split from the Gap-1 review: this is two decisions bundled into
one.

**Routing decision (load-bearing): route `query_key("mnemonic")`
to the Rust BIP39 entry directly at the dispatch site; delete
`wallet2::get_seed`.** After Phase 1, the wallet's "mnemonic"-keyed
query returns the BIP39 phrase derived from `m_bip39_entropy` (per
§4.10) — not the 25-word Electrum-words encoding. Implementation
mechanics:

1. Phase 1 adds the public accessor
   `const std::optional<epee::mlocked<tools::scrubbed_arr<uint8_t, 32>>>& wallet2::bip39_entropy() const`
   alongside the new `m_bip39_entropy` field (per §2.3).
2. Phase 1 rewires the `query_key("mnemonic")` dispatch branch
   implementation in `wallet2_ffi.cpp:643` (and the equivalent RPC
   handler in `wallet_rpc_server.cpp`) to read
   `wallet.bip39_entropy()`, call
   `shekyl_bip39_mnemonic_from_entropy` directly via the FFI, and
   return the phrase — or return the §4.10 hard error if entropy is
   unset (e.g., for wallets created from raw keys or device).
3. The `wallet2::get_seed` method (declaration at `wallet2.h:1002`,
   body at `wallet2.cpp:1372`) is **not** re-implemented in Phase
   1. It is dead-but-extant after Phase 1's rewire (the only
   caller, the dispatch branch, no longer calls it). Phase 4
   Commit A deletes the method outright per §2.2's inventory.

**Two distinguishable surfaces at the dispatch site:**

| Surface | Phase 1 disposition | Phase 4 disposition |
| --- | --- | --- |
| Dispatch case label `"mnemonic"` (the string-key entry) | Persists | Persists |
| Dispatch case implementation body | Rewired to call FFI directly via `wallet.bip39_entropy()` accessor | Unchanged from Phase 1 — does not touch `wallet2::get_seed` because Phase 1 already broke the dependency |
| `wallet2::get_seed` method (declaration + body) | Not touched in Phase 1 (left dead-but-extant) | **Deleted** in Commit A per §2.2 |

This separation resolves the round-3 internal contradiction
between the substrate's §2.5 and §4.5 dispositions for the
dispatch site. The string-key label persists; the implementation
body rewires in Phase 1; the underlying `wallet2::get_seed`
method deletes in Phase 4 (which is safe because Phase 1's
rewire already broke the only call site's dependency on it).

**String-key decision (UX call): keep the string key as
`"mnemonic"`.** Rationale: "mnemonic" is the universal industry
term for BIP39 phrases. Renaming the key to `"bip39_phrase"`
forces every downstream integrator (shekyl-gui-wallet, future
third-party wallets, future block-explorers) to migrate string
constants without semantic benefit. The phrase *is* a mnemonic;
keeping the key as `"mnemonic"` is the lower-friction choice and
matches industry convention (BIP39 spec itself uses "mnemonic
sentence" throughout).

These two decisions sit at different altitudes — the routing
decision is architecturally load-bearing (changes which code
produces the value); the string-key decision is UX (changes
which string downstream code uses to *request* the value). They
are pinned separately so future audits can re-open one without
re-opening the other.

### 4.5.1 BIP39 passphrase semantic across two surfaces

BIP39's passphrase is structurally different from Electrum-words'
passphrase, and the difference lands at two distinct surfaces
inside Phase 1's atomic commit. This subsection pins both
dispositions so neither surface is silently ignored.

**Surface A — `parse_wallet_create_data` JSON
`seed_passphrase` field (`wallet2.cpp:606–611`).**

Today the JSON-restore path uses `seed_passphrase` to decrypt the
spend secret recovered from the 25-word phrase
(`cryptonote::decrypt_key(recovery_key, field_seed_passphrase)`).
This is the Monero "seed offset" semantic: the passphrase is a
post-hoc XOR mask on the spend secret, not part of the seed
derivation itself.

BIP39's passphrase is mixed into PBKDF2-HMAC-SHA512 *during* seed
derivation (`mnemonic + passphrase → 64-byte seed → account keys`).
Functionally: same passphrase + same phrase always recovers the
same account; passphrase changes produce a different account
deterministically; an attacker who steals only the phrase cannot
recover the account without the passphrase.

**Disposition: preserve passphrase semantics through BIP39.**
Phase 1 threads `field_seed_passphrase` (the JSON field's value)
to `shekyl_account_generate_from_bip39`'s `passphrase` parameter
(`account_ffi.rs:330`-equivalent). The JSON field name
`seed_passphrase` is unchanged — JSON-restore consumers that pass
the field today continue to work, with the semantic shifted from
Monero-encrypt_key to BIP39-PBKDF2 transparently. Consumers that
relied on the precise cryptographic mechanism (the encrypt_key
XOR-on-spend-secret) rather than the user-observable property
(same-phrase-same-passphrase-recovers-same-account) see a
silent semantic shift; this is acceptable per the pre-genesis
posture (no Shekyl consumers exist with the encrypt_key
semantic expectation).

This is the lowest-friction disposition: the FFI already accepts
the passphrase parameter; the JSON schema is unchanged; the
user-observable property is preserved; the only cost is the
in-code semantic comment migration ("encrypts the spend secret"
→ "feeds the BIP39 PBKDF2-HMAC-SHA512 input").

Rejected alternative — **rename the JSON field to
`bip39_passphrase`** — would force every JSON-restore consumer to
migrate the field name without securing or clarifying anything.
The §4.5 string-key disposition's "lower-friction industry-term
preservation" framing applies here too.

Rejected alternative — **delete the JSON field entirely; require
passphrase to be empty** — strips a load-bearing BIP39 feature
(passphrase-as-25th-word-equivalent) that the BIP39 spec
deliberately specifies; this would put Shekyl out of step with
the broader BIP39 ecosystem without justification.

**Surface B — `query_key("mnemonic")` FFI dispatch's passphrase
parameter (`wallet2_ffi.cpp:643`).**

Today the dispatch calls `wallet2::get_seed(out_phrase,
passphrase)`, which under Electrum-words uses the passphrase to
encrypt the spend secret before encoding-to-words. Under BIP39,
the phrase derives from entropy alone:
`shekyl_bip39_mnemonic_from_entropy(entropy) → phrase`. The
passphrase has no meaning at phrase-emit time — it lives in the
phrase-to-seed direction (PBKDF2-HMAC-SHA512), not the
entropy-to-phrase direction.

**Disposition: hard-error on non-empty passphrase at the FFI
dispatch.** Phase 1's rewired dispatch branch (per §4.5)
inspects the passphrase parameter; if non-empty, returns a hard
error:

```text
"the 'passphrase' parameter is not meaningful when querying the
BIP-39 mnemonic phrase. The passphrase is consumed during
phrase-to-seed derivation (see query_key passphrase semantics in
the BIP-39 spec), not during phrase emission. Pass an empty
passphrase to retrieve the phrase."
```

Empty / nullptr / zero-length is the only accepted value. This
matches the §4.3 hard-error inversion: silent-ignore is the
production-software graceful-degradation default that
pre-genesis discipline inverts to loud failure. The RPC layer
does not expose the passphrase parameter (the RPC
`query_key` request struct carries only `key_type`), so the
hard-error surface is FFI-only.

**Why the two surfaces resolve differently.** Surface A preserves
the passphrase because BIP39's seed-derivation path *uses* it
load-bearingly. Surface B hard-errors because BIP39's
phrase-emission path *does not use* it at all. The two surfaces
share a parameter name (`passphrase`) but their semantic
relationships to that parameter are structurally different
under BIP39, and the dispositions reflect that structural
difference.

**Both dispositions land in the same Phase 1 atomic commit per
§4.10's expanded scope.** The commit message references this
subsection by section number; the test plan (§7.3) includes
positive cases for Surface A (round-trip phrase + passphrase →
same account) and negative cases for Surface B (non-empty
passphrase on `query_key("mnemonic")` → hard-error).

### 4.6 CryptoNote-25-word format unsupported, period

There is no fallback path. No "if seed has 25 words, try
Electrum-words decoding" branch. The 25-word format is removed
from the codebase entirely; attempting to restore from a 25-word
phrase produces a BIP39 validation error
(`"not a valid BIP39 mnemonic"`).

This is the same discipline as `60-no-monero-legacy.mdc`'s
"deleted, not gated" principle applied to seed format.

### 4.7 Cross-boundary zeroization contract for the BIP39 phrase

The BIP39 phrase is the master secret. Crossing the FFI boundary
in either direction triggers the cross-boundary zeroization
contract:

1. **Originating-scope zeroization.** Rust side produces
   `Zeroizing<[u8; N]>` for entropy and seed bytes. This holds via
   a two-layer arrangement: the in-tree workspace module
   `rust/shekyl-crypto-pq/src/bip39.rs` wraps the upstream `bip39`
   crate from crates.io (pinned at `bip39 = "2.2.2"` with
   `default-features = false, features = ["std", "zeroize"]` in
   `rust/shekyl-crypto-pq/Cargo.toml` per Batch α PR 1). The
   upstream crate's `zeroize` feature gates the `Zeroize` /
   `ZeroizeOnDrop` impls on `bip39::Mnemonic`; the workspace
   wrapper layers Shekyl-specific constraints (24-word /
   32-byte / English-only) on top and re-exports the
   already-zeroizing primitives. C++ user-input side uses
   `epee::wipeable_string` (already the pattern for wallet2
   password / seed paths).

2. **Transit buffer discipline.** Any intermediate FFI transit
   buffer (the `const uint8_t* words_ptr` parameter on the FFI
   call; any C++-side staging buffer for return values) is
   zeroized after copy. The C++ caller wraps the FFI invocation
   in a scope that wipes its staging buffer on return.

3. **No long-lived aliasing of phrase bytes in plaintext.** The
   phrase itself never persists in long-lived C++ storage after
   the FFI call returns. The **entropy** does persist (32 bytes,
   §4.10) — but inside the keyfile's chacha20-encrypted JSON
   envelope, encrypted with the wallet password-derived key,
   alongside `spend_secret` and `view_secret`. The
   entropy-on-disk is the canonical source-of-truth; the phrase
   is regenerated on demand via `shekyl_bip39_mnemonic_from_entropy`
   inside the §4.5-routed `query_key("mnemonic")` dispatch
   branch (which reads the entropy via the new
   `wallet2::bip39_entropy()` public accessor and calls the FFI
   directly), and the regenerated phrase is wipeable per the
   wipeable-string discipline that flows from the Rust
   `Zeroizing<>` wrapper through the FFI transit buffer to the
   caller's `epee::wipeable_string`. No in-memory cache of the
   phrase persists across query_key calls.

4. **Test invariant (§7.4).** A memory-residency invariant test
   runs after wallet generation/restore and after every
   `query_key("mnemonic")` call: scan the C++ heap for known
   phrase bytes after the FFI call returns; assert zero matches.
   The concrete test pattern (heap-walk scope, false-positive
   masking, instrumentation strategy) is pinned as a Phase 1
   implementation-time design sub-deliverable rather than
   inherited from an extant pattern — `tests/unit_tests/memwipe.cpp`
   is a primitive `memwipe()` functional check (malloc → write →
   memwipe → free → malloc-same-slot → assert-wiped), not a
   process-heap scan, and no broader residency-scan pattern
   exists in the repo yet. The Phase 1 commit message and test
   file are the load-bearing implementation reference once it
   lands.

5. **Constant-time secret comparison.** All equality checks
   involving secret bytes (the 32-byte BIP-39 entropy in
   `m_bip39_entropy`, the 64-byte PBKDF2 seed, derived scalars,
   derived spend/view secrets) use constant-time primitives.
   On the Rust side: `subtle::ConstantTimeEq` (or equivalent
   ct-primitives exposed by `curve25519-dalek` /
   `dalek-cryptography`'s ecosystem). On the C++ side:
   `crypto_verify_32` (or `sodium_memcmp` / `CRYPTO_memcmp`),
   not naive `memcmp` and not `std::vector<char>::operator==`
   on secret-bearing containers. The discipline applies at
   recommendation time and is enforced by the per-Rule-30
   constant-time-or-explicit-rejection rule in
   [`30-cryptography.mdc`](../../.cursor/rules/30-cryptography.mdc).
   Note that `epee::wipeable_string::operator==` at
   [`contrib/epee/include/wipeable_string.h:74`](../../contrib/epee/include/wipeable_string.h)
   delegates to `std::vector<char>::operator==` and is **not**
   constant-time; comparisons of phrase strings via the
   `wipeable_string` equality operator are forbidden on
   secret-bearing inputs. Phrase-equality is not a discipline
   Shekyl needs (the canonical secret is the entropy bytes,
   not the phrase) so this is forbidden-by-discipline, not
   forbidden-by-implementation. Phase 1 does not introduce
   any equality check against `m_bip39_entropy` (round-trip
   tests verify the FFI's regenerated phrase against the
   expected entropy via the derivation path, not via raw
   entropy `memcmp`), so the §4.7 #5 discipline is a
   forward-looking guard, not a current-bug fix.

6. **NFKD Unicode normalization (BIP-0039 §A spec compliance).**
   Mnemonic phrase and passphrase inputs are NFKD-normalized
   before PBKDF2 / entropy derivation, per the BIP-0039
   specification. Two users with logically-equivalent but
   byte-different Unicode inputs (e.g., precomposed vs.
   decomposed characters) must produce identical wallets per
   spec; absent NFKD normalization, a phrase generated on a
   host that emits NFC and re-entered on a host that expects
   NFKD silently derives a different account, breaking
   cross-platform recovery. The upstream `bip39 = "2.2.2"`
   crate applies NFKD via `Mnemonic::normalize_utf8_cow`
   ([`bip39-2.2.2/src/lib.rs:198–203`](https://github.com/rust-bitcoin/rust-bip39/blob/v2.2.2/src/lib.rs#L198)),
   gated on the upstream `unicode-normalization` feature.
   That feature is currently pulled in transitively via the
   `std → alloc → unicode-normalization` chain in
   [`bip39-2.2.2/Cargo.toml`](https://github.com/rust-bitcoin/rust-bip39/blob/v2.2.2/Cargo.toml).
   Shekyl pins the feature **explicitly** in
   [`rust/shekyl-crypto-pq/Cargo.toml`](../../rust/shekyl-crypto-pq/Cargo.toml)'s
   `bip39` dependency line (`features = ["std", "zeroize",
   "unicode-normalization"]`) as defense-in-depth against
   transitive-feature drift: a future `cargo update` or
   feature-flag refactor that breaks the `std → alloc →
   unicode-normalization` chain would silently disable NFKD
   without the explicit pin, and the resulting failure mode
   (silently-different wallets for byte-different-but-
   logically-equivalent inputs) is invisible to all standard
   tests. The explicit pin guarantees the BIP-0039 spec
   property is delivered regardless of transitive-feature
   topology. The pin alone, however, does not catch a second
   failure mode: a future refactor that migrates the consumer
   in
   [`rust/shekyl-crypto-pq/src/bip39.rs`](../../rust/shekyl-crypto-pq/src/bip39.rs)
   from the auto-NFKD-applying entry points (`parse_in`,
   `to_seed`) to the caller-pre-normalises variants
   (`parse_in_normalized`, `to_seed_normalized`) without
   adding an NFKD pre-pass would leave the pin in place and
   the feature enabled, but silently produce non-spec-compliant
   behaviour. The load-bearing enforcement is therefore a
   regression test colocated with the dependency line, not the
   pin itself: `tests::nfkd_passphrase_normalization` in
   [`rust/shekyl-crypto-pq/src/bip39.rs`](../../rust/shekyl-crypto-pq/src/bip39.rs)
   feeds NFC (`"caf\u{00E9}"`, U+00E9 precomposed) and NFKD
   (`"cafe\u{0301}"`, U+0301 combining acute) forms of the
   same passphrase through `mnemonic_to_pbkdf2_seed` and
   asserts byte-identical seeds. The English wordlist is
   ASCII-only so NFC == NFKD trivially for the phrase itself;
   the passphrase is the load-bearing surface and is where the
   test concentrates.

This contract is documented here (not just inline in code
comments) so future audits have a single load-bearing reference
for what the boundary discipline is, and so the test invariant
in §7.4 has a clear specification to verify.

### 4.8 Documented residual: swap and hibernate exposure

The cross-boundary zeroization contract in §4.7 covers
heap-resident bytes and FFI transit buffers. It does **not**
cover two pre-Linux-3.x-era exposure paths that affect every
secret-holding process on commodity operating systems:

1. **Swap-out.** During the phrase's active scope on either
   side of the FFI boundary, memory pressure can cause the OS
   to evict the holding pages to swap. The swap file persists
   the phrase bytes to disk; subsequent reads of `/dev/sda` (or
   the swap device) by an attacker with disk access recover the
   phrase.
2. **Hibernate.** When the host machine hibernates (suspend-to-disk),
   the entire process address space — including
   active secret-bearing pages — is written to the hibernate
   image. Wake-from-hibernate restores the image, but a copy
   persists in the hibernation file.

The standard mitigation is `mlock` (or `shekyl_mlock` per
[`35-secure-memory.mdc:165`](../../.cursor/rules/35-secure-memory.mdc))
on the phrase's holding pages, plus `prctl(PR_SET_DUMPABLE, 0)`
and `madvise(MADV_DONTDUMP)` per the same rule's "OS-level
protection" section. Both mitigations are partial:

- `mlock` prevents swap-out but not hibernate (hibernate
  bypasses `mlock` on most OSes because the entire RAM is
  snapshotted).
- `PR_SET_DUMPABLE` prevents core dumps but not deliberate
  attacker reads of memory via `/proc/<pid>/mem` (root) or
  `ptrace` (CAP_SYS_PTRACE).

**Disposition for V3.0:** The 32-byte BIP-39 **entropy**
persisted at rest (`m_bip39_entropy` per §4.10) is mlock-backed
via `epee::mlocked<tools::scrubbed_arr<uint8_t, 32>>`. This is
the primary mitigation for the secret bytes that persist across
function calls and whose page residency is the highest-value
target for swap-out. The Rust side independently mlocks its
secret-bearing transit buffers via the `bip39 = { features =
["zeroize"] }` `Zeroizing<>` wrapping and the `shekyl_mlock`
discipline applied to the FFI-owned entropy/seed allocations
per [`35-secure-memory.mdc:163–172`](../../.cursor/rules/35-secure-memory.mdc).

The transit-time **phrase strings** held in
`epee::wipeable_string` are wipe-on-drop only in V3.0.
Pre-flight verification at `dev` tip `60943cb16` confirmed that
`epee::wipeable_string` is backed by `std::vector<char>`
([`contrib/epee/include/wipeable_string.h:83`](../../contrib/epee/include/wipeable_string.h))
with no `mlock` / `MADV_DONTDUMP` / `prctl(PR_SET_DUMPABLE)`
application (zero matches across
[`contrib/epee/src/wipeable_string.cpp`](../../contrib/epee/src/wipeable_string.cpp)
for any of `mlock`, `madvise`, or `MADV_DONTDUMP`). Earlier
substrate text in this section claimed `wipeable_string` was
mlock-wrapped on the C++ side; that claim was incorrect and is
corrected here. The actual V3.0 disposition is "phrase strings
are wipe-on-drop, not mlocked" — phrase-string pages are
swap-eligible during the brief window between user input and
BIP-39 normalization, and during the FFI transit window in
`query_key("mnemonic")` regeneration. The mlock-backed
allocator for `epee::wipeable_string` is tracked as a
**FOLLOWUPS V3.0 post-Electrum-words-removal cleanup-series**
work item that lands before Stage 1 PR 4 kickoff (see the
"`epee::wipeable_string` mlock-backed allocator" entry in
[`docs/FOLLOWUPS.md`](../FOLLOWUPS.md)'s V3.0 pre-genesis queue).
The cleanup is structurally an `epee::wipeable_string`-internal
change, not a BIP-39-path change, so it is out of B-1 scope
per [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)'s
B-1-is-deletion-focused discipline; it is named-and-scheduled,
not deferred-indefinitely, per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)'s
reversion-clause discipline.

Hibernate exposure is **documented as a known residual**, not
enforced in V3.0 — orthogonal to the mlock landscape because
hibernate snapshots the entire RAM regardless of `mlock` page
flags on most operating systems.

**Rationale for the entropy / phrase split.** The entropy is the
canonical long-term secret persisted in the wallet keyfile;
it has high page-residency lifetime (open-wallet to
close-wallet) and accordingly justifies the per-allocation
mlock cost. The phrase strings are transit-time only and the
attack window is bounded by the FFI call duration (a few
hundred microseconds to derive entropy → phrase in
`query_key("mnemonic")`, plus the user-input latency on
wallet-restore). Phase-1's discipline is to mitigate the
higher-residency surface first (entropy mlock-backed in V3.0),
schedule the lower-residency surface for the post-Electrum
cleanup series (wipeable_string mlock-backed before PR 4),
and document both residuals so future audits don't reach a
weaker conclusion than the implementation delivers.

**Rationale for the hibernate residual:** mitigating hibernate
exposure requires either (a) OS-level cooperation (a
"no-hibernate process" flag on Linux that does not exist in
mainline as of 2026-05-19), (b) zeroing the phrase on every
userspace context switch (prohibitively expensive), or (c)
refusing to run on hibernate-capable systems (rejects every
laptop and most desktops). All three are forward-impractical.
The disposition is to mlock the entropy against swap (the
routine exposure path) — with the wipeable_string allocator
cleanup closing the phrase-string-transit-swap residual
before PR 4 — and accept hibernate as a residual the user
takes on when they choose to hibernate a machine holding
secrets.

**Pairing with the wallet master-key residual.** The wallet's
long-term spend key / view key / PQC secret keys have the same
swap-and-hibernate residual. Pinning it for the BIP-39 phrase
and entropy specifically — rather than implicitly relying on
the master-key residual to also cover them — makes the
discipline visible: every secret-bearing surface in the wallet
inherits the same residual, and every audit-priority risks
review re-asserts the same disposition.

**Reversion criteria (per Rule 21):** This residual is
re-opened if (a) the OS landscape changes such that
mlock-against-hibernate becomes practical (a mainlined Linux
kernel facility, a macOS / Windows equivalent), or (b) Shekyl
ships in a context where hibernate is structurally impossible
(e.g., a dedicated hardware appliance running a custom OS
without suspend support) and the discipline becomes
enforceable, or (c) a user-class emerges that requires the
hibernate residual to be closed (e.g., institutional
cold-storage workflows where hibernate exposure is
unacceptable). The phrase-string-transit-swap sub-residual is
re-opened if the FOLLOWUPS-tracked wipeable_string allocator
cleanup is deferred past Stage 1 PR 4 kickoff without
explicit re-justification, per the named-criteria principle
of `21-reversion-clause-discipline.mdc`.

Documentation cross-reference:
[`35-secure-memory.mdc:163–172`](../../.cursor/rules/35-secure-memory.mdc)
("OS-level protection" section) is the canonical rule for the
mitigation discipline; this §4.8 is the audit-of-record for the
BIP39 phrase's specific application of that discipline.

### 4.9 Pinned class-level observation: user-protection defaults in user-absent contexts

The Phase 1 hard-error inversion (§4.3) and the §5.2
atomic-cutover inversion are two instances of a broader class:
defaults inherited from production-software discipline where
there are deployed users to protect. Pre-genesis, with no users,
these defaults invert. The class also includes (non-exhaustive):

- **Backward-compatibility preservation.** Production-software
  default: never break consumers. Pre-genesis inversion: there
  are no consumers; delete-not-gate per
  [`60-no-monero-legacy.mdc`](../../.cursor/rules/60-no-monero-legacy.mdc).
- **Opt-in migration paths.** Production-software default:
  give users a window to migrate. Pre-genesis inversion: no
  users to give a window to; `rm -rf ~/.shekyl` is the migration
  path per
  [`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc).
- **Soft deprecation (`[[deprecated]]` annotations without
  delete dates).** Production-software default: warn early,
  delete eventually. Pre-genesis inversion: if you can't name
  the delete version, you can't deprecate — delete now per Rule
  15.
- **Version-skew tolerance.** Production-software default:
  accept old protocol versions. Pre-genesis inversion: there is
  one version (genesis); per
  [`60-no-monero-legacy.mdc`](../../.cursor/rules/60-no-monero-legacy.mdc),
  earlier versions are dead code.
- **Graceful degradation under unknown input.** Production-software
  default: accept-and-warn. Pre-genesis inversion: §4.3
  hard-error.
- **Staged rollouts with deprecation windows.** Production-software
  default: ship to a fraction, monitor, expand. Pre-genesis
  inversion: §5.2 atomic-with-justified-exceptions.

The class-level pattern is **"user-protection defaults in
user-absent contexts."** Each instance is a default that
production-software discipline ships pre-loaded; each requires
explicit inversion when the underlying "users to protect"
assumption does not hold. The inversion is not a once-per-pattern
discipline — it is a once-per-design-decision discipline,
because the same default re-enters every design review under a
different guise.

This observation is folded into
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
as a sibling subsection to the existing "cost-benefit-defer-to-later"
anti-pattern, so future PRs have a class-level name to anchor
disciplinary correction. The two PR-4-Phase-0 instances (§4.3,
§5.2) are exemplars; future PRs will surface more, and each
should cite the rule's class-level entry.

### 4.10 BIP39 entropy persistence and keyfile schema change

**Finding from Round-3 review.** BIP39 is structurally different from
Electrum-words in one critical respect: Electrum-words is a
deterministic encoding of the spend secret (`bytes_to_words(spend_secret) →
25 words`, bijective), so `wallet2::get_seed` recovers the phrase
from the wallet's existing spend secret state. BIP39 is one-way from
phrase to seed via PBKDF2-HMAC-SHA512; the seed is what derives the
spend secret. There is **no** seed-to-phrase or
spend-secret-to-phrase entry. The phrase is recoverable only from
the entropy bytes that originally produced it.

For `query_key("mnemonic")` (§4.5) to function post-Phase-1, the
wallet keyfile MUST persist either (a) the BIP39 entropy bytes, or
(b) the BIP39 phrase itself. The substrate disposition is **(a):
persist the 32-byte BIP39 entropy**.

**Why entropy, not phrase.** Entropy is the canonical source-of-truth;
the phrase is a derived encoding (English wordlist via
`mnemonic_from_entropy`). Entropy is fixed-length (32 bytes per
`rust/shekyl-crypto-pq/src/bip39.rs:46` Shekyl-mandated 24-word
constant); the phrase is variable-length (depends on whitespace
canonicalization). Encrypting and integrity-protecting a fixed-length
secret-bearing blob is the established wallet2 keyfile pattern;
persisting a variable-length phrase introduces JSON-canonicalization
edge cases without security benefit.

**Wallet state additions.** A new optional field is added to wallet2
state:

```cpp
// src/wallet/wallet2.h, alongside other long-term-secret fields
std::optional<epee::mlocked<tools::scrubbed_arr<uint8_t, 32>>> m_bip39_entropy;
```

The field is set during:

1. **Restore-from-phrase flow via `parse_wallet_create_data` (JSON
   restore path).** User-supplied JSON contains a `seed` field with
   the 24-word phrase (and optionally a `seed_passphrase` field per
   §4.5.1); phrase validated via `shekyl_bip39_validate`; entropy
   extracted via the new FFI `shekyl_bip39_mnemonic_to_entropy(phrase)
   → entropy` (added in this disposition; see below); account
   generated via `shekyl_account_generate_from_bip39(phrase,
   passphrase)`; entropy stored in `m_bip39_entropy`. This is the
   primary path where B-1 populates `m_bip39_entropy`.

2. **New-wallet generation flow via shekyl-gui-wallet's Rust path
   (NOT via `wallet2_ffi_create_wallet`).** The fresh-entropy →
   phrase → BIP39 derivation → account-keys flow runs in
   shekyl-gui-wallet's Rust code (calls `shekyl_account_generate_from_bip39`
   directly, displays the phrase to the user once for backup,
   then constructs the wallet state). In B-1 scope this path does
   **not** populate `m_bip39_entropy` — wallet2 receives
   pre-computed account material from gui-wallet, not the BIP39
   phrase or entropy. This is the **accept-partial-coverage**
   disposition for B-1; see "Partial-coverage state" below.

The field is **not** set during:

1. **`wallet2_ffi_create_wallet` / `on_create_wallet` (the wallet2
   FFI / RPC new-wallet entry).** Today this path routes through
   `wallet2::generate(...)` → `account_base::generate(...)` →
   `shekyl_account_generate_from_raw_seed`, which is
   testnet/fakechain-only per `src/cryptonote_basic/account.cpp:443–446`
   (mainnet-broken today). It does not flow through BIP39; the
   new-wallet path in shekyl-gui-wallet bypasses this entry. B-1
   does not migrate this path to a BIP39-aware shape; that work
   lives in a future V3.x architectural workstream (provisional
   name: `wallet2_ffi_create_wallet_from_bip39`) if and when the
   wallet2-side new-wallet path needs entropy tracking. Until then
   the FFI new-wallet entry remains mainnet-broken; this is a
   pre-existing condition, not introduced by B-1.
2. **Restore-from-keys flow.** User supplies raw spend/view secret
   keys; no associated BIP39 phrase exists.
3. **Restore-from-raw-seed-bytes flow.** User supplies a 32-byte raw
   seed; no associated BIP39 phrase exists.
4. **Restore-from-device flow.** Hardware-wallet device manages the
   seed off-host; phrase is recoverable from the device, not from
   wallet2 state. Trezor/Ledger restore paths must be verified at
   Phase 1 implementation time to confirm they do not accidentally
   populate `m_bip39_entropy` (verification item V3).

**Partial-coverage state post-B-1.** `query_key("mnemonic")` works
on wallets created via the JSON-restore-from-phrase path
(`m_bip39_entropy` populated by §4.5/§4.10's Phase 1 rewire) and
hard-errors on wallets created via `wallet2_ffi_create_wallet` /
`on_create_wallet` (`m_bip39_entropy` unset because the new-wallet
path doesn't flow through BIP39). Phrase backup at wallet creation
time is **shekyl-gui-wallet's responsibility outside wallet2 state**
— the GUI displays the phrase to the user once, the user copies it
down, the GUI never persists it. For B-1, this partial coverage is
acceptable per the pre-genesis posture; the alternative (full
coverage via a `wallet2_ffi_create_wallet_from_bip39` extension)
is a separate architectural workstream with its own design rounds.

**Why `wallet2_ffi_create_wallet`'s mainnet-broken state is out
of B-1 scope.** The substrate above describes
`wallet2_ffi_create_wallet` as a callable-but-mainnet-broken
FFI entry that persists across B-1. Pre-flight review surfaced
that this disposition — strictly read — risks the
[§6.1 "Keep Electrum-words for backward compat" rejection
shape](#61-keep-electrum-words-for-backward-compat-rejected):
a callable-but-discouraged surface that creates a permanent
attack surface. The disposition is reframed here with explicit
discipline-tracking so the deferral is auditable mechanically,
not author-preference-anchored, per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)'s
named-criteria principle.

The mainnet-broken behavior derives from the raw-seed-on-mainnet
restriction in
[`src/cryptonote_basic/account.cpp:443–446`](../../src/cryptonote_basic/account.cpp),
**not from Electrum-words infrastructure**. The restriction
rejects raw-seed wallet generation on Mainnet/Stagenet
regardless of the encoding the seed bytes arrived in.
Electrum-words deletion neither introduces nor depends on this
state; B-1's deletion sweep on Electrum-words is structurally
independent of the raw-seed restriction. Phase 3's signature
edit on `wallet2_ffi_create_wallet` (dropping the `language`
parameter per §4.4) is a mechanical signature change unrelated
to the mainnet-broken behavior of the function body — Phase 3
does not introduce the brokenness and does not resolve it.

The cleanup is a **separate workstream** because it requires
designing the new wallet-creation FFI shape (a
BIP-39-aware `wallet2_ffi_create_wallet_from_bip39` or
equivalent), which doesn't exist yet — architectural design
work, distinct from B-1's deletion-and-rewire scope. Per
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc) §"The
'cost-benefit-defer-to-later' anti-pattern" — when the cleanup
surface is open and the cleanup work is bounded, the discipline
is to do the cleanup now; when the cleanup is design work that
needs its own rounds, the discipline is to land it as a separate
PR with tracked discipline. The
`wallet2_ffi_create_wallet_from_bip39` shape needs design
rounds; the language-parameter drop in Phase 3 is bounded.
Folding the design work into B-1 would expand scope past the
deletion-focused premise of the PR.

The deferral is converted from "we'll get to it" to "tracked
discipline item" via the explicit FOLLOWUPS entry
"`wallet2_ffi_create_wallet` / `on_create_wallet`
mainnet-broken FFI cleanup" in
[`docs/FOLLOWUPS.md`](../FOLLOWUPS.md)'s V3.0 pre-genesis queue,
targeted at the post-Electrum-words-removal cleanup series
that lands before Stage 1 PR 4 kickoff. The FOLLOWUPS entry's
existence — not its prose — is what satisfies §4.9's
named-criteria principle and converts the §4.10 framing from
"defensible deferral with provisional V3.x workstream"
(implicit-deferred-cleanup, susceptible to "we'll get to it"
drift) to "out-of-B-1-scope with named cleanup work item"
(structural-deferral, audit-tracked).

If the FOLLOWUPS entry slips past Stage 1 PR 4 kickoff without
explicit re-justification of the deferral, the §6.1
rejection-shape recurs and the disposition reopens per the
named-criteria principle.

**Hardware-wallet BIP-39 derivation parity** is a related but
orthogonal question. A user who creates a Shekyl wallet via
shekyl-gui-wallet's BIP-39 path, records the phrase, and later
attempts to restore on a Trezor or Ledger device must receive
the same Shekyl account. Parity requires alignment across
(i) a SLIP-0044-registered or self-claimed coin type for
Shekyl, (ii) the BIP-44 derivation path used by
`shekyl_account_generate_from_bip39`, (iii) the network
identifier's interaction with the derivation, and (iv) the
PBKDF2-HMAC-SHA512 → cSHAKE-256 pipeline match between
Shekyl-host and the eventual device firmware. None of these
alignment dimensions are Electrum-words-removal questions; they
exist regardless of which mnemonic standard Shekyl adopts, and
they belong to the hardware-wallet integration workstream
that does not yet have a substrate document. The alignment
question is tracked as a separate FOLLOWUPS V3.x entry
("Hardware-wallet BIP-39 derivation parity") that the eventual
`docs/HARDWARE_WALLETS.md` will absorb when the
hardware-wallet integration workstream opens. B-1 does not
introduce the question and does not resolve it.

When the field is unset, `query_key("mnemonic")` returns a hard
error: `"this wallet was not created from a BIP-39 mnemonic; the
mnemonic phrase is not available"`. This is the loud-failure
analogue of §4.3's hard-error discipline: the absence of an
expected secret produces an explicit error, not a silent empty
return.

**FFI surface extension.** The four FFI functions enumerated in
§3.1 expand to five. The new function:

```c
// src/shekyl/shekyl_ffi.h
//
// Extract the 32-byte BIP39 entropy from a validated 24-word
// English phrase. Returns true and writes 32 bytes to `out32_ptr`
// on success; returns false and zero-fills `out32_ptr` on
// validation failure or null pointer.
bool shekyl_bip39_mnemonic_to_entropy(
    const uint8_t* words_ptr, size_t words_len,
    uint8_t* out32_ptr);
```

Rust-side implementation requires a corresponding addition to
`rust/shekyl-crypto-pq/src/bip39.rs`:

```rust
pub fn entropy_from_mnemonic(
    words: &str,
) -> Result<Zeroizing<[u8; SHEKYL_BIP39_ENTROPY_BYTES]>, CryptoError> {
    let mnemonic = Mnemonic::parse_in(Language::English, words)
        .map_err(|e| CryptoError::InvalidInput(format!("BIP-39 parse: {e}")))?;
    if mnemonic.word_count() != SHEKYL_MNEMONIC_WORD_COUNT {
        return Err(CryptoError::InvalidInput(format!(
            "Shekyl requires 24-word mnemonics; got {}",
            mnemonic.word_count()
        )));
    }
    let entropy_vec = mnemonic.to_entropy();
    if entropy_vec.len() != SHEKYL_BIP39_ENTROPY_BYTES {
        return Err(CryptoError::InvalidInput(format!(
            "BIP-39 entropy length mismatch: expected {}, got {}",
            SHEKYL_BIP39_ENTROPY_BYTES,
            entropy_vec.len()
        )));
    }
    let mut entropy = [0u8; SHEKYL_BIP39_ENTROPY_BYTES];
    entropy.copy_from_slice(&entropy_vec);
    Ok(Zeroizing::new(entropy))
}
```

The implementation delegates to upstream `bip39`'s `Mnemonic::to_entropy()`
(verified API per `bip39 = "2.x"` workspace pin); the 32-byte length
check enforces the Shekyl 24-word canonical mandate (per `bip39.rs:46`).

**Keyfile JSON ser/de.** The new field rides in the same encrypted
keyfile JSON envelope as the other long-term-secret fields:

```cpp
// src/wallet/wallet2.cpp, Phase 1 JSON write path
if (m_bip39_entropy)
{
  rapidjson::Value entropy_value;
  const auto entropy_hex = epee::string_tools::buff_to_hex_nodelimer(
      std::string(m_bip39_entropy->data(),
                  m_bip39_entropy->data() + 32));
  entropy_value.SetString(entropy_hex.c_str(), entropy_hex.length());
  json.AddMember("bip39_entropy", entropy_value, json.GetAllocator());
}
```

Encryption discipline: the entropy lives inside the
`store_keys`-encrypted JSON blob (chacha20 with the wallet
password-derived key per the existing wallet2 keyfile pattern), so
it inherits the same protection as `spend_secret` and `view_secret`.

**The Phase 1 work scope expands.** Per the Round-3 + Round-4
dispositions, Phase 1 (atomic commit) takes on:

1. Add `m_bip39_entropy: std::optional<epee::mlocked<tools::scrubbed_arr<uint8_t, 32>>>`
   field to wallet2 state.
2. Add public accessor
   `const std::optional<epee::mlocked<tools::scrubbed_arr<uint8_t, 32>>>& wallet2::bip39_entropy() const`
   alongside other read-only accessors in `wallet2.h`. This is the
   accessor the §4.5-routed dispatch branch uses to read the
   entropy when computing the phrase on demand.
3. Add JSON write + JSON read for `bip39_entropy` in the keyfile
   ser/de path.
4. Rewire `crypto::ElectrumWords::words_to_bytes` call sites at the
   parse paths (per §2 corrected inventory) to call `shekyl_bip39_*`
   FFI functions and populate `m_bip39_entropy`.
5. **Rewire `query_key("mnemonic")` dispatch branch implementation
   at `src/wallet/wallet2_ffi.cpp:643`** (and the equivalent RPC
   handler in `wallet_rpc_server.cpp`) to read
   `wallet.bip39_entropy()` and call
   `shekyl_bip39_mnemonic_from_entropy` directly via the FFI,
   returning the phrase or returning the §4.10 hard error if the
   entropy is unset. The dispatch case label `"mnemonic"` is
   unchanged; only the implementation body changes. **The dispatch
   branch does not call `wallet2::get_seed` after this rewire** —
   that method is left dead-but-extant until Phase 4 Commit A
   deletes it.
6. Hard-error on non-empty `language` parameter on the rewired
   `wallet2::generate` callers (§4.3).
7. Tests: BIP39 round-trip + entropy-persistence-roundtrip +
   memory-residency invariant (per §7.4).

The commit is large but architecturally atomic: every change above
is the same architectural change at a different surface. Bisecting
the rewire from the field addition produces a non-buildable
intermediate state.

**Phase 4's `wallet2::get_seed` disposition is preserved as
deletion (per §2.2).** Phase 1's dispatch-branch rewire (item 5
above) breaks the only call site's dependency on
`wallet2::get_seed`, so the method is dead-but-extant at Phase 4's
entry. Phase 4 Commit A deletes the declaration at
`wallet2.h:1002` and the body at `wallet2.cpp:1372` outright,
alongside the other Electrum-words-era methods (`is_deterministic`,
`get_seed_language`, `set_seed_language`).

**`is_deterministic` disposition.** Earlier substrate drafts framed
`is_deterministic` as "returns true if `seed_language` is set." That
framing was incorrect; the actual implementation at `wallet2.cpp:1362–1370`
checks the **CryptoNote keypair-shape property**:

```cpp
bool wallet2::is_deterministic() const
{
  crypto::secret_key second;
  keccak((uint8_t *)&get_account().get_keys().m_spend_secret_key,
         sizeof(crypto::secret_key), (uint8_t *)&second, sizeof(crypto::secret_key));
  sc_reduce32((uint8_t *)&second);
  return memcmp(second.data, get_account().get_keys().m_view_secret_key.data,
                sizeof(crypto::secret_key)) == 0;
}
```

The predicate returns true if the view secret equals
`sc_reduce32(keccak(spend_secret))` — the legacy CryptoNote derivation
where the view secret is keccak-derived from the spend secret. Under
Shekyl's HKDF-from-master-seed account pipeline (per
`account_base::generate` and `account_base::rederive_from_master_seed`),
the view secret is HKDF-derived from the master seed independently of
the spend secret; the keccak-derives-view property is no longer true
for any Shekyl account.

**Consequence: `is_deterministic` returns `false` for every Shekyl
wallet today, regardless of whether the wallet was created from a
BIP39 phrase or from raw keys.** The predicate is structurally
incorrect for Shekyl accounts; its current name promises a meaningful
distinction (deterministic vs non-deterministic) that the
implementation cannot deliver under Shekyl's HKDF derivation. This is
a pre-existing condition (existed before B-1) and is independent of
the Electrum-words deletion — but the Electrum-words deletion is the
forcing function that surfaces it.

Two options for Phase 4 disposition (independent of the corrected
rationale):

- **(i)** Re-implement `is_deterministic` to return
  `m_bip39_entropy.has_value()` in Phase 1; keep it indefinitely as
  a useful "this wallet has a recoverable mnemonic" predicate.
- **(ii)** Delete `is_deterministic` entirely in Phase 4; callers
  that need the predicate call `query_key("mnemonic")` and check for
  the hard-error response, or read `bip39_entropy()` directly.

The substrate disposition is **(ii)** per `60-no-monero-legacy.mdc`
and `15-deletion-and-debt.mdc`: the structural keypair-shape predicate
is dead code under Shekyl's HKDF derivation (returns `false` for
every Shekyl wallet); reusing the name for a different semantic
("has a stored BIP39 entropy") would propagate a misleading API
name; the proper query is direct on the optional field, not a
separate boolean method. Deletion is correct under both the
current-broken state (predicate is structurally wrong) and the
post-Electrum semantic (no two-class wallet distinction at the
predicate level).

**Reversion criteria (per Rule 21).** The entropy-persistence
disposition is closed under:

1. **BIP39 deprecation by industry.** If the cryptocurrency industry
   collectively abandons BIP39 in favor of a different mnemonic
   standard (extremely unlikely; BIP39 is the dominant standard with
   $T-scale assets backing it), the disposition re-opens to pin the
   replacement standard.
2. **Quantum compromise of BIP39's checksum-via-SHA256.** BIP39's
   8-bit checksum is SHA-256-based; a structural break of SHA-256
   would invalidate the checksum's integrity guarantee. The
   disposition re-opens to either drop BIP39 entirely or replace the
   checksum mechanism.
3. **Multi-length-mnemonic user-class.** If a Shekyl-V3.x user-class
   emerges that requires 12-word or other-length BIP39 support
   (currently rejected per `bip39.rs:31-32`), the disposition
   re-opens to add length-variability — and the `m_bip39_entropy`
   field shape would need adjustment (length-prefix or variable-vec
   container) to accommodate.

None of these criteria are V3.0-likely; the disposition is
expected to hold through V3.x and into V4. V4's lattice-only
transition affects key-derivation primitives but does not directly
affect BIP39 (which is a seed-encoding standard, not a key-derivation
primitive); V4 may re-evaluate the entire wallet-seed shape from
scratch, but that is V4 design territory, not a B-1 reversion
trigger.

---

## 5. Cross-repo coordination

### 5.1 Consumer matrix (post-pre-flight)

| Repo | wallet2_ffi binding state (2026-05-19) | Phase 3 migration party? |
| --- | --- | --- |
| `shekyl-core` | Host repo + in-tree Rust consumer at `rust/shekyl-engine-rpc/` (three `extern "C"` declarations + three Rust wrappers, per §3.2.0) | Yes (publishes the FFI deletion PR; the in-tree Rust consumer migrates as work items inside the same PR per §3.2.0, atomic with the C++ FFI deletion) |
| `shekyl-gui-wallet` | Active cross-repo consumer; substantial Electrum-words integration | Yes (publishes a coordinated migration PR per §3.2.1) |
| `shekyl-mobile-wallet` | Not yet a consumer | No (picks up post-deletion FFI when it begins binding) |
| `shekyl-web` | Not a consumer | No (picks up post-deletion FFI when it begins binding) |

### 5.2 Cutover default: atomic-with-justified-exceptions

For first-party Shekyl repos at pre-genesis, the default
cross-repo cutover discipline is **atomic** — the shekyl-core
FFI deletion PR and the shekyl-gui-wallet migration PR land as a
coordinated unit. **Staged cutover (with deprecation window)
requires an explicit named third-party dependency justification.**
No such third-party dependency exists for B-1; the atomic default
applies.

Rationale for the default inversion (versus the production-software
"staged with deprecation window" inheritance): per `60-no-monero-legacy.mdc`
and the pre-genesis posture, all consumers are first-party and
under coordinated maintenance. The staged-cutover pattern exists
to protect deployed third-party users; that constraint does not
apply pre-genesis. Staged cutover introduces a callable-but-deprecated
surface that is itself the failure mode `60-no-monero-legacy.mdc`
forbids ("commenting out" / "callable-but-discouraged" code).

The atomic-with-justified-exceptions default is also the
forward-template for future cross-repo deletion work: a future
PR adding a third-party Shekyl consumer (community wallet, block
explorer, etc.) that needs Electrum-words removal could file a
staged cutover with the named third-party dependency as the
justification, and the audit-of-record would accept it. Without
such a dependency, atomic is the default.

### 5.3 Phase 3 cutover mechanism: coordinated dev-tip merge (pre-genesis)

For B-1 specifically (pre-genesis), the cutover mechanism is:

1. shekyl-core PR opens against `dev` with the FFI deletion + RPC deletion + wallet2 internal cleanup.
2. shekyl-gui-wallet migration PR opens against `dev` (in the shekyl-gui-wallet repo) with the bridge / commands / UI migration. PR body cites the shekyl-core PR by URL.
3. Both PRs run their respective CI to green.
4. Same-day merge: both PRs merge into their respective `dev` branches in coordinated sequence (shekyl-core first if shekyl-gui-wallet's CI depends on a tagged shekyl-core artifact; otherwise either order works because shekyl-gui-wallet's `Cargo.toml` pin can be updated to a post-merge `dev` SHA after the shekyl-core merge).
5. The atomic boundary is the *post-merge `dev` tip state* in both repos. There is no signed-tag boundary at this phase because pre-genesis there are no released versions yet.

This is the simpler model for pre-genesis. Post-genesis, the
paired-signed-tag mechanism (next section) is the forward
default.

### 5.4 Phase 3 reversion mechanism: commit-revert in coordinated order

Matching the cutover mechanism: revert is at the commit level on
`dev` in both repos. Ordered:

1. **shekyl-gui-wallet revert** restores the Electrum-words
   consumption pattern in `wallet_bridge.rs` / `commands.rs`.
2. **shekyl-core revert** restores the FFI surface
   (`wallet2_ffi_restore_deterministic_wallet`, `language`
   parameters, `query_key("mnemonic")` dispatch).
3. **Verification** that both repos compile and pass their full
   test suites against the post-revert `dev` tip.

If a revert is needed mid-phase (after only one repo's PR has
merged), the order is simpler: revert the merged PR and re-open
the partner PR's review.

### 5.5 Post-genesis forward template: paired signed annotated tags

This is documented for completeness so future audits don't read
the §5.3 coordinated-dev-tip mechanism as a permanent precedent.

Post-genesis (V3.0 release and beyond), cross-repo coordinated
deletions follow the paired-signed-tag pattern:

1. shekyl-core PR merges to `dev`; shekyl-core release PR merges
   `dev → main` per
   [`06-branching.mdc`](../../.cursor/rules/06-branching.mdc).
2. shekyl-core signed annotated tag `vX.Y` placed on the
   resulting merge commit (Foundation YubiKey).
3. shekyl-gui-wallet `Cargo.toml` / build pin updated to
   `refs/tags/vX.Y` of shekyl-core.
4. shekyl-gui-wallet release PR + signed tag `vX.Y` (sibling
   tag, Foundation YubiKey).
5. Both tags announced together post-CI-green-on-both.

The reversion mechanism in this post-genesis future-default is
**untag both releases and re-pin shekyl-gui-wallet to the prior
shekyl-core tag.** The merged `dev` tip is not reverted; only
the release boundary moves backward. Future audits / users
consuming `refs/tags/vX.Y` see the prior tag's tree.

B-1 Phase 3 does not use this mechanism because pre-genesis
there is no `vX.Y` baseline; the genesis tag is the first
release.

---

## 6. Alternatives considered

### 6.1 Keep Electrum-words for backward compat (REJECTED)

Rationale: per §1.1, no Shekyl-side installed base exists
pre-genesis. "Backward compat" with whom? The only consumers
that could exist are first-party Shekyl repos, which are all
under coordinated maintenance per §3.2. There is no third-party
Electrum-words-relying caller to be backward-compatible with.

The version of this argument that says "but post-genesis a user
might try to restore from a 25-word Electrum seed" is rejected
by §4.6: post-genesis, attempting to restore from a 25-word
phrase produces a BIP39 validation error. This is the intended
behaviour, not a regression.

### 6.2 Partial deletion (audit-strict three-site scope) (REJECTED)

The Phase 0 Mission Audit's initial framing of "three call
sites" — `wallet2.cpp:1374` internal, `wallet2_ffi.cpp:643`
`query_key("mnemonic")` dispatch, `wallet_rpc_server.cpp:2214`
RPC handler — was a simplification that did not survive contact
with the actual deletion surface (per §2's inventory). Deleting
only the three audit-identified sites would leave:

- `is_deterministic` / `get_seed` function bodies as
  dead-but-callable code (no in-tree callers, but binary symbols
  remain).
- `wallet2_ffi_restore_deterministic_wallet` still wired through
  to `crypto::ElectrumWords::words_to_bytes`.
- `src/mnemonics/` directory still compiled, linked, and shipped
  in the wallet libraries.
- `seed_language` field still in `wallet2` state and JSON
  ser/de.

The result is a half-deleted subsystem that is exactly the
"commented out / callable-but-discouraged" residue
`60-no-monero-legacy.mdc` forbids. The architecturally-integral
answer is full subsystem deletion per the inventory in §2.

### 6.3 Defer to V3.1+ (REJECTED)

The cost-benefit calculus for "defer the Electrum-words deletion
to a V3.1 post-launch cleanup" is dominated by the
pre-genesis-discount asymmetry (per
[`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc)):

- Pre-genesis: deletion cost ≈ 5 PRs × ~half-day each = ~3 days
  developer time. No migration tooling required. No data-format
  detection. No user-facing notice.
- Post-genesis: deletion cost includes data-migration tooling for
  any user that opened a Shekyl wallet before V3.1, plus a
  deprecation-window posture for several releases. Migration
  tooling runs forever to handle state that exists for a finite
  period (per `15-deletion-and-debt.mdc`'s "migration code is a
  permanent attack surface for a one-time problem").

This is the `cost-benefit-defer-to-later` anti-pattern named
in
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc):
the deferred-benefit calculation systematically underweights
the value of pre-genesis structural cleanup. The
architecturally-integral disposition is to land the deletion
now.

### 6.4 BIP39 ↔ Electrum-words bridge function (REJECTED)

Adding a `bip39_phrase_to_electrum_words` (or the inverse)
function to the codebase as a migration aide is rejected as
load-bearing migration code per §1.1. There is no pre-genesis
installed base to migrate. Adding the bridge function creates a
new attack surface for a non-existent problem.

The version of this argument that says "post-genesis a user
might want to display their seed in both formats for redundant
backup" is rejected by §4.6: there is one canonical seed format
post-genesis (BIP39); the redundant-backup pattern is multiple
copies of the same format, not multiple formats.

### 6.5 Reversion clauses per Rule 21

Per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc),
the rejected alternatives in §6.1–6.4 are not closed forever;
they are closed under named criteria, and a future PR can
re-open the disposition by surfacing those criteria as met.
Reversion criteria:

| Disposition | Reverts on |
| --- | --- |
| §4.1 BIP39-only from genesis | A pre-genesis discovery that BIP39 has a security-load-bearing vulnerability that no other industry mnemonic standard shares (extremely unlikely; BIP39 is the broadly-deployed standard). |
| §4.2 wallet2::generate() retains orchestrator role | The B-3 architectural workstream lands and the (a) stop-gap shape becomes the dead intermediate. Note: this is a *forward* progression, not a reversion of the §4.2 disposition. |
| §4.3 Phase 1 hard-error on non-empty `language` | Never — this disposition is the locked discipline; hardening it further (e.g., compile-time deletion of the parameter at Phase 1 rather than runtime hard-error) is a forward progression that does not violate §4.3. |
| §4.4 `seed_language` field removed | Multilingual BIP39 wordlist support becomes a roadmap item AND the implementation requires wallet2-side state. The reversion path is: re-introduce the field as `bip39_wordlist_language: String` (not `seed_language`); never as the Electrum-words-coupled field this disposition removes. |
| §4.5 `query_key` string-key kept as `"mnemonic"` | An external integrator surfaces a named conflict between `"mnemonic"` and another industry usage that produces ambiguity (extremely unlikely; "mnemonic" is the universal term). |
| §4.6 CryptoNote-25-word format unsupported | Never — see §6.1. |
| §4.7 Cross-boundary zeroization contract | The audit invariant in §7.4 surfaces a residency leak. The reversion path tightens the contract, not loosens it. |
| §4.8 Swap/hibernate residual | Per §4.8 explicit reversion criteria: (a) OS-level no-hibernate facility lands; (b) Shekyl ships in a hibernate-impossible context; (c) a user-class emerges requiring the residual to be closed. Reversion path is **closing** the residual, not loosening it. |
| §4.9 Pinned class-level observation | Never — naming the class-level pattern is itself the disposition. Refinements to the named class (additional instance categories surfaced by future PRs) extend the rule's enumeration; they do not reverse §4.9. |
| §4.10 BIP39 entropy persistence | Per §4.10 explicit reversion criteria: (1) industry BIP39 deprecation; (2) quantum compromise of SHA-256 checksum; (3) multi-length-mnemonic user-class emerges. Reversion path depends on which criterion fires; none are V3.0-likely. The `is_deterministic` disposition (ii) within §4.10 is itself per-Rule-21 — re-opens if a Shekyl-V3.x caller-class surfaces that needs the predicate as a discrete query rather than via `query_key("mnemonic")` hard-error inspection. |
| §5.2 atomic cutover default | A named third-party consumer of `wallet2_ffi` surfaces during B-1 flight. The reversion path is the staged-cutover disposition with the third-party named explicitly. |

---

## 7. Test surface and verification invariants

### 7.1 nm symbol-isolation invariants

After Phase 5 lands, the following symbols MUST NOT appear in
`nm shekyld` or `nm libwallet2_api.so` output (or equivalents):

```text
crypto::ElectrumWords::words_to_bytes
crypto::ElectrumWords::bytes_to_words
crypto::ElectrumWords::is_valid_language
crypto::ElectrumWords::get_language_list
crypto::ElectrumWords::get_is_old_style_seed
crypto::ElectrumWords::old_language_name
tools::wallet2::is_deterministic
tools::wallet2::get_seed
tools::wallet2::get_seed_language
tools::wallet2::set_seed_language
wallet2_ffi_restore_deterministic_wallet
```

A CI check (`tests/symbol_isolation/electrum_words_removed.sh`)
runs `nm -C <artifact> | grep -E '<pattern>'` against the build
artifacts and fails the build if any symbol matches. The `-C`
flag demangles C++ symbols so the patterns above (which use
demangled namespace-qualified names like
`tools::wallet2::is_deterministic`) match. Without `-C`, raw nm
output is mangled (e.g.,
`_ZN5tools7wallet215is_deterministicEv`) and the demangled
patterns would not match. The script either uses `nm -C` (the
disposition) or lists mangled-name patterns directly; the
disposition is `-C` for readability and stability across compiler
mangling-scheme variations. Pattern matches the LWMA-1 Phase 4
§7.1 precedent (which also uses `nm -C`).

### 7.2 git grep no-orphans invariants

After Phase 5 lands, the following identifiers MUST NOT appear in
the source tree (excluding `docs/CHANGELOG.md` historical entries
and `docs/design/ELECTRUM_WORDS_REMOVAL*.md` which retain
references for audit purposes):

```text
ElectrumWords
electrum-words.h
seed_language
is_deterministic
get_seed_language
set_seed_language
mnemonics/english.h
mnemonics/japanese.h
(etc., all 14 language headers)
restore_deterministic_wallet
COMMAND_RPC_GET_LANGUAGES
COMMAND_RPC_RESTORE_DETERMINISTIC_WALLET
```

A CI check (`tests/grep_invariants/electrum_words_no_orphans.sh`)
runs `git grep -E '<pattern>'` against the tree and fails the
build if any non-allowlisted match exists. Pattern matches the
LWMA-1 Phase 4 no-orphaned-magic-numbers invariant.

### 7.3 BIP39 round-trip tests

Tests added in Phase 1 (alongside the wallet2 internal rewire)
verify the BIP39 path produces correct wallets:

- Generate a wallet via the new `wallet2::generate()` path; verify
  the wallet's primary address matches the BIP39-derived address
  for the same entropy + passphrase.
- Restore a wallet from a BIP39 phrase; verify the recovered
  wallet's primary address matches.
- Round-trip: generate → query seed via `query_key("mnemonic")`
  → restore from that phrase → assert wallets are identical.

These tests live in `tests/unit_tests/wallet_bip39.cpp` (a new
test file added in Phase 1).

### 7.4 Memory-residency invariant test (per §4.7)

A test added in Phase 1 verifies the cross-boundary zeroization
contract:

1. Generate a wallet with a known BIP39 entropy.
2. After the FFI call returns, scan the C++ heap (process memory
   range, or instrumented allocator hook) for the known phrase
   bytes.
3. Assert zero matches.

This test lives in `tests/unit_tests/wallet_bip39_residency.cpp`.

**Concrete test pattern is a Phase 1 implementation-time
sub-deliverable, not inherited from extant patterns.** Earlier
substrate drafts cited "the KEY_ENGINE design doc §7.5 audit
pattern" as the test-pattern source; that citation was Round-3
fold-in-corrected to acknowledge that KEY_ENGINE §7.5 is the
`AllKeysBlob: Clone` audit task (not a heap-scan pattern), and
no extant process-heap-scan pattern exists in the repo. The
closest extant test (`tests/unit_tests/memwipe.cpp`) checks
`memwipe()`-on-a-single-allocation via malloc-free-malloc-same-slot,
which is a primitive functional test, not a process-heap-scan
pattern. The Phase 1 implementation lands the test pattern as
its own design sub-deliverable; the commit message and test file
become the load-bearing implementation reference for future
similar tests (the substrate-compounding discipline per
`16-architectural-inheritance.mdc` "Discovery cadence"). The
test design at Phase 1 implementation time selects:

- Heap-walk scope: process-wide (via `/proc/self/maps` + `/proc/self/mem`)
  vs allocator-instrumented (via `LD_PRELOAD`-wrapped `malloc/free`)
  vs gtest-friendly bounded-region (declare a known-secret buffer
  in the test, perform the operation, scan only the test's own
  arena).
- False-positive masking: known phrase bytes might appear in
  unrelated heap regions (loaded English wordlist; loaded
  fixtures); the test design specifies the masking discipline.
- Instrumentation strategy: production-build vs sanitizer-build vs
  debug-build; the test may only run in one build flavor if
  full-process-scan requires ASan / MSan / debug allocator
  hooks.

### 7.5 Test fixtures touched, zero-production-keyfile confirmation

Test fixtures that exercise Electrum-words paths today:

- `tests/unit_tests/mnemonics.cpp` — deleted entirely in Phase 5.
- `tests/unit_tests/serialization.cpp` (if it deserializes legacy
  wallet JSON with `seed_language`) — Phase 4 sweep removes the
  `seed_language` field from any test fixtures.
- `tests/functional_tests/wallet.py` (Python integration tests)
  — Phase 2 sweep removes `restore_deterministic_wallet` /
  `get_languages` RPC calls; Phase 3 sweep removes any
  `set_language` integration.

**Pre-genesis posture confirmation:** there are zero production
Shekyl wallet keyfiles in existence (the project has not yet
released V3.0). Any test fixtures are project-internal artifacts
under coordinated maintenance. Deletion of the `seed_language`
field does not require production-data migration tooling.

If a future contributor discovers a production keyfile (e.g., a
test wallet committed to a branch that gets restored later), the
keyfile is regenerated from its source BIP39 phrase per the
project's pre-genesis migration discipline (`rm -rf` and re-sync
per `15-deletion-and-debt.mdc`).

---

## 8. References

### Design-doc precedents

- [`DAA_LWMA1.md`](./DAA_LWMA1.md) — LWMA-1 difficulty
  adjustment substrate doc. Style and section-decomposition
  template.
- [`DAA_LWMA1_PLAN.md`](./DAA_LWMA1_PLAN.md) — LWMA-1 multi-phase
  plan template; companion to this doc's
  [`ELECTRUM_WORDS_REMOVAL_PLAN.md`](./ELECTRUM_WORDS_REMOVAL_PLAN.md).
- [`RANDOMX_V2_RUST.md`](./RANDOMX_V2_RUST.md) — RandomX v2
  substrate doc; "no version dispatch" disposition template.

### Phase 0 Mission Audit substrate

- `docs/FOLLOWUPS.md` — Phase 0 Mission Audit findings index;
  B-1 entry.
- Audit substrate pins (in chat transcript / audit notes):
  `b1_disposition_settled_delete`, `b1_vestigial_verification`
  (now closed by this PR), `per_surface_walk_b1_b2_c1_c3`.

### BIP39 specification

- BIP-0039 — Mnemonic code for generating deterministic keys.
  Authoritative replacement path is a two-layer arrangement:
  - **In-tree workspace module:**
    `rust/shekyl-crypto-pq/src/bip39.rs`. This is the
    Shekyl-internal API surface (`entropy_from_mnemonic`,
    `mnemonic_from_entropy`, Shekyl-specific 24-word/32-byte/
    English-only enforcement, and the FFI bridge consumed by
    `rust/shekyl-ffi/src/account_ffi.rs`). It is **not** a
    crates.io dependency; it is part of the `shekyl-crypto-pq`
    workspace crate.
  - **Upstream crate (transitive dependency):**
    `bip39 = "2.2.2"` from crates.io, declared in
    `rust/shekyl-crypto-pq/Cargo.toml` with
    `default-features = false, features = ["std", "zeroize"]`
    per Batch α PR 1. This is what provides the canonical
    2048-word English wordlist, the SHA-256 checksum logic, the
    PBKDF2-HMAC-SHA512 derivation, and the `Zeroize` /
    `ZeroizeOnDrop` impls on `bip39::Mnemonic` (gated behind
    the `zeroize` feature).
  - **Layering invariant.** Callers (C++ via FFI, Rust within
    the workspace) interact only with the in-tree module's
    surface. The upstream crate is an implementation detail
    that the in-tree module wraps and constrains. Per
    `17-dependency-discipline.mdc`, this is the verified
    workspace state — the `Zeroize` impl exists on the wrapped
    type via the upstream `zeroize` feature; the in-tree
    module's `Zeroizing<[u8; N]>` returns inherit that
    property.

### Rules

- [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc) —
  priority hierarchy. B-1 is a priority-3 commitment-3 work
  (the system must outlast the team; pre-genesis cleanup serves
  unknown future maintainers).
- [`05-system-thinking.mdc`](../../.cursor/rules/05-system-thinking.mdc) —
  spec-first, code-second. This doc is the spec.
- [`06-branching.mdc`](../../.cursor/rules/06-branching.mdc) —
  short-lived branches; the five-PR decomposition fits.
- [`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc) —
  pre-genesis-discount; migration-code anti-pattern; "while
  we're here" discipline.
- [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc) —
  inheriting code vs. inheriting architecture; the
  cost-benefit-defer-to-later anti-pattern.
- [`20-rust-vs-cpp-policy.mdc`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc) —
  Rust if touches a secret. Phase 0 design rounds discipline.
- [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc) —
  reversion criteria per disposition (§6.5).
- [`35-secure-memory.mdc`](../../.cursor/rules/35-secure-memory.mdc) —
  wipe-on-drop discipline; substrate for §4.7 zeroization
  contract.
- [`36-secret-locality.mdc`](../../.cursor/rules/36-secret-locality.mdc) —
  Rust owns secrets at the C++/Rust boundary; substrate for
  §4.2 disposition (a).
- [`60-no-monero-legacy.mdc`](../../.cursor/rules/60-no-monero-legacy.mdc) —
  "deleted, not gated" principle; substrate for §4.1 and §4.6.
- [`91-documentation-after-plans.mdc`](../../.cursor/rules/91-documentation-after-plans.mdc) —
  Phase 6 docs-update obligation; CHANGELOG entry.

### Cross-repo references

- `shekyl-gui-wallet` — `src-tauri/src/wallet_bridge.rs`,
  `src-tauri/src/commands.rs` (Phase 3 migration sites).
- `shekyl-core` — `rust/shekyl-ffi/src/account_ffi.rs`,
  `src/shekyl/shekyl_ffi.h` (BIP39 bridge; already in place).
- `rust/shekyl-crypto-pq/src/bip39.rs` — Rust BIP39
  implementation (already used in production).

---

*End of substrate doc. Implementation phasing in
[`ELECTRUM_WORDS_REMOVAL_PLAN.md`](./ELECTRUM_WORDS_REMOVAL_PLAN.md).*
