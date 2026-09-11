# Frozen domain separators — the rebrand-sweep exclusion list

Some byte-strings in the tree are **consensus-frozen domain separators (DSTs)**:
they are hashed to derive generator points (or otherwise feed a transcript) that
genesis proofs verify against. Changing a single byte moves the derived point and
silently invalidates every proof built against it — a consensus corruption that
compiles clean and passes every consistency check that doesn't pin the *derived
output* (see the `divisors`-style failure mode and the generator-KAT gap closed in
the un-vendor slice-2 work).

These literals contain the word **"Monero"** because they are inherited, byte-for-byte,
from the FCMP++ research lineage and were already frozen into Shekyl's genesis
parameters. **They are not [`93-legacy-symbol-migration`](../.cursor/rules/93-legacy-symbol-migration.mdc)
targets** — rule 93 governs `MONERO_*` *identifiers* (env vars, macros, build flags),
not hash-input byte-strings. A rebrand or a `MONERO_`→`SHEKYL_` sweep **must skip every
entry below**. New code never introduces a `"Monero …"` DST (there is none to inherit);
this list is closed except by a genesis-parameter change.

## How they are protected

1. **Inline `// FROZEN DST` markers** at every site, so a grep/sweep that lands on the
   line sees the carve-out.
2. **This list** — the committed, auditable enumeration (Phase-9 audit reads it to tell
   frozen-inherited from rebrandable).
3. **A release KAT** pinning the *derived* points by frozen hex — the only guard that
   actually fails if a byte changes:
   `rust/shekyl-curve-generators/src/tests/frozen_points.rs`.

## The list (FCMP++ generator DSTs)

All in `rust/shekyl-curve-generators/src/lib.rs`:

| DST byte-string | Derives | Pinned by |
|---|---|---|
| `b"Monero Generator T"` | `T` (key-image blinding generator) | `frozen_singletons` |
| `b"Monero FCMP++ Generator U"` | `FCMP_PLUS_PLUS_U` | `frozen_singletons` |
| `b"Monero FCMP++ Generator V"` | `FCMP_PLUS_PLUS_V` | `frozen_singletons` |
| `b"Monero Helios Hash Initializer"` | `HELIOS_HASH_INIT` | `frozen_singletons` |
| `b"Monero Selene Hash Initializer"` | `SELENE_HASH_INIT` | `frozen_singletons` |
| `"Monero {id} G"` / `"Monero {id} H"` | per-ciphersuite FCMP base generators (`id` = `Helios`/`Selene`) | `frozen_fcmp_tables` |
| `"Monero {id} G {i}"` / `"Monero {id} H {i}"` | the FCMP `g_bold`/`h_bold` generator vectors | `frozen_fcmp_tables` |

The Pedersen amount generator `H` is derived from the Ed25519 basepoint (no `"Monero"`
string) but is equally frozen — also pinned by `frozen_singletons` / `frozen_h_pow_2_head`.
The Bulletproof(+) tables (`b"bulletproof"` / `b"bulletproof_plus"` prefixes, varint-fed)
are pinned by `frozen_bulletproof_tables`, and the Bulletproof+ transcript initializer
`b"bulletproof_plus_transcript"` (`shekyl-bulletproofs/src/plus/transcript.rs`,
keccak256 → hash-to-point) is frozen with them — changing it re-seeds every BP+
transcript challenge and invalidates every existing range proof.

## The list (FROST / multisig transcript DSTs)

Three more inherited byte-strings live in `rust/shekyl-fcmp-proofs/src/sal/multisig.rs`
(the un-vendored, no-longer-tracked FCMP++ SAL fork). They are frozen for the same
reason as the generator DSTs — not because we track upstream, but because they are
baked into proofs and joint signatures that verify against genesis — and each names
a **distinct** breaking consequence, so the marker is the consequence, not just the
status:

| DST byte-string | Mechanism | Consequence of changing a single byte |
|---|---|---|
| `b"Ed25519 Monero T"` (`Ed25519T::ID`) | FROST ciphersuite id → feeds `hash_to_F` DST | re-derives every FROST nonce/challenge for multisig; participants can no longer produce a joint signature that verifies — **multisig DKG and signing break** |
| `b"FROST-ED25519-FCMP++-v1"` (`Ed25519T::CONTEXT`) | FROST protocol context | same FROST session-binding change — old and new participants compute different binding factors, so **no multisig session completes** |
| `b"SpendAuthAndLinkability Multisig"` (`transcript.domain_separate`) | SAL multisig transcript root | re-computes the multisig SAL challenge; **every multisig SAL proof fails to verify → multisig-held funds become unspendable** |

These are marked inline with `// FROZEN DST (inherited)`. They are **not** rule-93
targets and are skipped by any rebrand sweep. A `MONERO_`→`SHEKYL_` identifier sweep
does not touch them (they are hash-input bytes, not identifiers).

**Not frozen — the LIVE sibling.** `b"Shekyl FROST SAL v1"`
(`rust/shekyl-fcmp/src/frost_sal.rs`, `RecommendedTranscript::new`) is
**Shekyl-authored** (absent from upstream) and is therefore governed by the SA
through-line rule ([`SIGNATURE_ALIGNMENT.md`](design/SIGNATURE_ALIGNMENT.md) §5), not
this exclusion list: its bytes are still derivation state (they root the SAL
multisig transcript), so changing the spelling is a versioned breaking change, but it
is *ours* to version — it is not inherited and carries no `"Monero"` provenance. The
distinction this file draws is inherited-frozen vs. Shekyl-live; both are
byte-load-bearing, only the former is a rebrand-sweep carve-out.

## Related (not in this list)

- The `H as SHEKYL_H` import alias in `rust/shekyl-bulletproofs/src/batch_verifier.rs`
  was a rule-93 *identifier* target (renamed from `MONERO_H` during the relocate); the
  underlying point is frozen, the local binding name is not. This is the distinction:
  a frozen hash-input string is skipped by a rebrand sweep; a `MONERO_*` identifier
  that merely binds a frozen point is still renamed.
