# Rule 20, Rust vs. C++ — the retired rule

**Status:** CLOSED-as-record, retired 2026-11-08 (ruled by Rick). It chose
between Rust and C++, and the C++ is deleted: the tree holds no first-party
C or C++ (PR #1299), so one option is left. What still binds moved:
"no first-party C, no C ABI" and the gate that holds it are
[`25-rust-architecture`](../../.cursor/rules/25-rust-architecture.mdc)'s
opening; §"A new subsystem is its own change" is
[`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)'s.
Do not implement from this record; the body below is the policy as it
stood, and the design records that cite "rule 20" read against it.

The tree holds no first-party C or C++. New logic is Rust. The companion
file `25-rust-architecture.mdc` covers how a crate is added; this file
covers why the logic is Rust. The only C is vendored under `external/`
(the RandomX references), and `scripts/ci/check_no_first_party_c.py`
holds the end state. Do not extend that tree with Shekyl logic, and do
not add a C ABI to reach a Rust crate.

## Rust if any of:

1. **Touches a secret.** Wallet keys, output secrets, key images, anything
   that requires wipe-on-drop. The `ZeroizeOnDrop` discipline is free in Rust
   and manual in C++; manual equals "eventually forgotten."
2. **Defines a cryptographic contract that other code consumes.** HKDF
   derivation, proof construction, witness assembly, key image computation.
   The type system enforces contracts at every use site rather than in
   documentation.
3. **Parses untrusted input.** Block deserialization, RPC response parsing,
   transaction validation. Safe slicing and `Result` propagation eliminate
   buffer-overrun bug classes.
4. **Performs integer arithmetic on amounts.** `checked_add`/`checked_mul` is
   explicit in Rust; silent overflow in C++ is a financial bug waiting to
   happen.

## Default

When a change matches any of the four cases above, it is Rust with the type
that makes the wrong value unrepresentable. A bug fix is not an exception.
