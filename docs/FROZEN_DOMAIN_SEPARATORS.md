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
   `rust/shekyl-oxide/shekyl-oxide/generators/src/tests/frozen_points.rs`
   (moves with the crate to `shekyl-curve-generators`).

## The list (FCMP++ generator DSTs)

All in the generator crate (`generators/src/lib.rs`, → `shekyl-curve-generators`):

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
are pinned by `frozen_bulletproof_tables`.

## Related (not in this list)

- `MONERO_H` in `fcmp/bulletproofs` is an *identifier* alias of the frozen `H` point —
  that **is** a rule-93 target (renamed to `SHEKYL_H` on touch); the underlying point is
  frozen, the local binding name is not.
