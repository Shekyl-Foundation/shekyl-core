#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# SA-3b domain-registry gate. Keeps docs/design/CRYPTO_DOMAIN_REGISTRY.tsv in
# lockstep with the code by blunt-but-firing tripwires. It does NOT parse call
# arguments (multi-line calls defeat that) and it does NOT grep by prefix.
#
# WHY call-site-anchored, not prefix-anchored: Shekyl's domain strings share no
# common prefix — "shekyl/", "shekyl-", "Shekyl ", "Monero ", "bulletproof" all
# occur. A "shekyl/"-anchored grep would silently miss shekyl-pqc-leaf,
# Shekyl FROST SAL v1, the frozen Monero DSTs, and more. That blind spot is the
# exact SA §3.1 defect this round exists to close, so the anchor is the mechanism
# entry point / the registered literal, never the spelling.
#
# WHAT THIS GATE GUARANTEES (honest scope — do not overclaim):
#   • Every *registered* row still has its literal at its defining file (and, when
#     the const column is a real identifier, a `const <name>:` definition site).
#     Catches: value change, rename, move, deletion of a registered domain.
#     Both checks see COMMENT-STRIPPED code only — a doc comment quoting the
#     bytes (or a `const NAME:` mention in prose) cannot satisfy a row after
#     the real definition changes. Registered literals must therefore never
#     contain `//` (none do; the stripper is line-comment based).
#   • Mech-1 (cSHAKE) and mech-3 free-form transcript labels cannot grow a new
#     call site without bumping a count-pin (those entry points always carry a
#     domain). Counts are likewise comment-stripped: a doc-comment code example
#     mentioning `cshake256_32(` does not move the pin.
#   • Every `frozen-inherited` row is documented in
#     docs/FROZEN_DOMAIN_SEPARATORS.md (the consequence table cannot silently
#     drop a frozen DST — this is why that doc is in the workflow trigger).
#   • Mech IDs are well-formed (`1`..`6` or `x`).
#
# WHAT THIS GATE DOES NOT GUARANTEE:
#   • Completeness for mechanisms 2 (HKDF), 4 (Blake2b), 5 (keccak), 6 (SHA3-256
#     micro-bucket). Their entry points are general-purpose primitives used for
#     non-domain hashing too, so a call-site count is noise, not signal. A new
#     domain in those mechanisms without a registry row will NOT trip this gate.
#     Completeness there is a review duty (CBOM §3 + code review of new
#     Hkdf/Blake2b/keccak/Sha3_256 domain-like string sites) plus the
#     distinctness test once a row exists. Do not invent a half-broken inverse
#     scanner that creates false confidence (rule 15/16 pre-genesis cleanliness).
#
# TRIPWIRE 1 — row-presence + const binding (all rows, every mechanism).
# TRIPWIRE 2 — entry-point count-pins (mech 1 cSHAKE; mech 3 FROST transcript
#              free-form labels; mech 3 FROST ciphersuite ID/CONTEXT in
#              shekyl-fcmp-proofs — the four registered FROST forms are covered
#              between these pins and row-presence).
#
# Requires ripgrep (rg). CI installs it in an explicit step before this runs.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"
REGISTRY="docs/design/CRYPTO_DOMAIN_REGISTRY.tsv"
FROZEN_DOC="docs/FROZEN_DOMAIN_SEPARATORS.md"

if ! command -v rg >/dev/null 2>&1; then
  echo "FATAL: ripgrep (rg) not found — CI must install it before this gate." >&2
  exit 2
fi
if [[ ! -f "$REGISTRY" ]]; then
  echo "FATAL: registry not found at $REGISTRY" >&2
  exit 2
fi
if [[ ! -f "$FROZEN_DOC" ]]; then
  echo "FATAL: frozen-DST doc not found at $FROZEN_DOC" >&2
  exit 2
fi

fail=0

# Line-comment-stripped view of a source file: presence/const checks must see
# code, not prose — a doc comment quoting the registered bytes must NOT keep a
# row green after the real definition changed (that would break the gate's
# "catches value change" guarantee). Captured into a variable, NOT piped into
# `rg -q`: under pipefail, rg -q's early exit SIGPIPEs the stripper and turns a
# successful match into a pipeline failure (flaky by file size).
#
# BLOCK comments count as prose too. Stripping only `//` meant a definition
# disabled with `/* ... */` still satisfied the row-presence check — the same
# silent-green hole found in check_debit_auth_single_source.sh (2026-08-31),
# which is why both now share ONE stripper rather than a sed each. Verified a
# no-op against the current tree (114 literals, unchanged) before landing, so
# it re-pins nothing.
#
# `count_pattern` below uses the same stripper, for the same reason. An earlier
# revision left it on inline `//` stripping and justified that by asserting its
# failure direction was benign — see the note on `count_pattern` itself for why
# that was false, and why the conversion turned out to cost nothing.
code_only() { python3 "$REPO_ROOT/scripts/ci/strip_c_comments.py" "$1"; }

# Rule 47: the row-presence arm is only as good as the stripper, so assert the
# stripper before trusting it. A regression there would widen this gate in the
# passing direction without any row changing.
if ! python3 "$REPO_ROOT/scripts/ci/strip_c_comments.py" --self-test; then
  echo "FAIL: the comment stripper failed its own regression cases; the"
  echo "      row-presence check below reads its output."
  exit 1
fi

# ── Tripwire 1: row-presence + const binding + frozen-doc cross-check ───────
# Tab is IFS whitespace, so a plain IFS=$'\t' read COLLAPSES adjacent tabs and
# shifts empty middle columns left (diverging from the Rust test's split('\t')).
# Re-delimit with unit separator (\x1f, not IFS whitespace) to keep empty
# fields in place.
rows=0
while IFS=$'\x1f' read -r mech literal file const status _key _notes || [[ -n "${mech:-}" ]]; do
  [[ -z "${mech:-}" || "${mech:0:1}" == "#" ]] && continue
  rows=$((rows + 1))

  # Well-formed mechanism id (reject typos like "55" that would create a silent
  # collision bucket in the distinctness test).
  case "$mech" in
    1|2|3|4|5|6|x) ;;
    *)
      echo "BAD MECH ID: '$mech' (literal b\"$literal\") — expected 1..6 or x" >&2
      fail=1
      continue
      ;;
  esac

  if [[ -z "$literal" || -z "$file" ]]; then
    echo "MALFORMED ROW: mech=$mech literal='$literal' file='$file' (need both)" >&2
    fail=1
    continue
  fi

  if [[ ! -f "$file" ]]; then
    echo "MISSING FILE: [$mech] $file (for literal b\"$literal\")" >&2
    fail=1
    continue
  fi

  # rg -F: fixed-string, so backslash escapes (\0, \x03) match the source's own
  # escapes verbatim. Accept either the byte-string form b"..." or the &str form
  # "..." — some frozen DSTs (the bulletproof generator names) are passed as
  # &str and .as_bytes()'d downstream. Searched over comment-stripped code only.
  code=$(code_only "$file")
  if ! rg -F -q -- "b\"$literal\"" <<<"$code" \
    && ! rg -F -q -- "\"$literal\"" <<<"$code"; then
    echo "NOT FOUND: b\"$literal\" (nor \"$literal\") in the CODE of $file  [mech $mech]" >&2
    fail=1
  fi

  # Const binding: when the const column is a real identifier (not a parenthesized
  # site descriptor like "(SeedDerivation inline)"), require a `const <leaf>:`
  # definition site in the same file — the trailing `:` anchors the exact name,
  # so a short registry name (SALT, LABEL) cannot be satisfied by a longer
  # declaration it prefixes (const SALT_KEM_DERIVE_V1). Multi-line const
  # initializers are fine — the `const` keyword, name, and `:` sit on the
  # declaration line even when the literal is on the next line (e.g.
  # SAL_MEMBERSHIP_ONLY_DST). Searched over comment-stripped code only.
  if [[ -n "$const" && "$const" != "("* ]]; then
    leaf="${const##*::}"
    if [[ -z "$leaf" ]]; then
      echo "BAD CONST: empty leaf from '$const' for b\"$literal\" in $file" >&2
      fail=1
    elif ! rg -q -- "const ${leaf}[[:space:]]*:" <<<"$code"; then
      echo "CONST MISSING: 'const $leaf:' not found in the code of $file (row b\"$literal\" [mech $mech])" >&2
      fail=1
    else
      # The literal and the const must be the SAME declaration, not merely both
      # present in the file.
      #
      # Checked separately, the two tests above are independently satisfiable:
      # a rotated separator leaves the OLD literal in the file (as the retired
      # label a negative control needs) while the registered const now holds
      # the NEW one, and both greps pass over a row that is now false. That is
      # not hypothetical — `shekyl/archival-serve-challenge-leaf` hit it
      # exactly, and the gate stayed green on a stale row. The failure mode
      # arrives precisely when a domain separator is ROTATED, which is when
      # this registry matters most.
      # Terminate on a line whose LAST character is `;`, not on any `;`: a
      # declaration like `const X: [u8; 64] =` carries a semicolon inside its
      # array type, and stopping there would truncate the declaration one line
      # above its literal — reporting a mismatch for a row that is correct.
      decl=$(awk -v name="$leaf" '
        $0 ~ ("const[[:space:]]+" name "[[:space:]]*:") { cap = 1 }
        cap {
          buf = buf $0 "\n"
          line = $0
          sub(/[[:space:]]+$/, "", line)
          if (line ~ /;$/) { printf "%s", buf; exit }
        }
      ' <<<"$code")
      if [[ -z "$decl" ]]; then
        echo "CONST UNTERMINATED: could not read the declaration of 'const $leaf' in $file (row b\"$literal\" [mech $mech])" >&2
        fail=1
      elif ! rg -F -q -- "\"$literal\"" <<<"$decl"; then
        echo "CONST/LITERAL MISMATCH: 'const $leaf' in $file does not hold b\"$literal\" [mech $mech]" >&2
        echo "  The literal exists in the file and the const exists in the file, but they are not the same declaration —" >&2
        echo "  the registry row is stale. This is what a rotated separator looks like: update the row to the const's" >&2
        echo "  current bytes, and give the retired literal its own row." >&2
        fail=1
      fi
    fi
  fi

  # Frozen-doc cross-check: every frozen-inherited row must be documented in
  # the consequence table — a rewrite of that doc cannot silently drop a
  # frozen DST while the gate stays green.
  if [[ "$status" == "frozen-inherited" ]] && ! rg -F -q -- "$literal" "$FROZEN_DOC"; then
    echo "FROZEN DST UNDOCUMENTED: b\"$literal\" ($file) has no entry in $FROZEN_DOC" >&2
    fail=1
  fi
done < <(tr '\t' '\037' < "$REGISTRY")
echo "row-presence: checked $rows registered literals"

# ── Tripwire 2: entry-point count-pins ──────────────────────────────────────
# Production trees only (exclude tests/benches/fuzz/examples dirs). Inline
# #[cfg(test)] sites in src/ are included in the pin by design: a new test that
# calls a domain-carrying entry point should still trip a look.
PROD_GLOBS=(-g 'rust/**/*.rs' -g '!**/tests/**' -g '!**/benches/**' -g '!**/fuzz/**' -g '!**/examples/**')

count_pattern() {
  # Count total matches (not lines) of a regex across production rust code,
  # with comments stripped by the SHARED stripper — whole files, not rg output
  # lines. Optional second arg: path scope (default: rust).
  #
  # It used to strip `//` inline with sed, and this comment used to claim the
  # residual failure could only be a spurious red (a commented example
  # INFLATING a pin). That was wrong, and wrong in the dangerous direction:
  # `/* cshake256_32(...) */` still matched, so block-commenting out a LIVE
  # call left the count unchanged and the gate never noticed the site had
  # gone. A silent green on a domain-separation mechanism, documented as safe
  # because the direction was asserted rather than measured.
  #
  # Converting was also free: all three pins are byte-identical under both
  # methods on the tree where this landed (43 / 2 / 2), so nothing is re-pinned
  # here and any future delta is a real change in live call sites.
  #
  # One interpreter start per pattern, not per file: `xargs` may split the
  # list, which is fine because every consumer reads this as one stream.
  local pattern=$1
  local scope=${2:-rust}
  rg --files "${PROD_GLOBS[@]}" "$scope" 2>/dev/null \
    | xargs python3 "$REPO_ROOT/scripts/ci/strip_c_comments.py" \
    | rg -o -- "$pattern" | wc -l | tr -d ' '
}

# --- mech 1: cSHAKE256 customization call sites ---
# SA-3c: 37 -> 40. snapshot-id retargeted cn_fast_hash -> cSHAKE, adding one
# production call site plus two in its rewritten domain-separation test (inline
# #[cfg(test)] sites are counted by design; see the header).
# PC-D3: 41 -> 43. The -v2 leaf-index separator's negative control hashes ONE
# preimage under both the live and the retired label to assert they differ, so
# it adds exactly two inline #[cfg(test)] sites and no production site.
MECH1_EXPECTED=43
mech1=$(count_pattern 'cshake256_(?:32|64)\(|CShake256Core::new\(')
if [[ "$mech1" != "$MECH1_EXPECTED" ]]; then
  echo "COUNT DRIFT mech 1 (cSHAKE call sites): found $mech1, pinned $MECH1_EXPECTED." >&2
  echo "  A cSHAKE call site was added/removed. Register the new domain in $REGISTRY and update the pin." >&2
  fail=1
fi

# --- mech 3a: FROST free-form transcript labels ---
# Pins RecommendedTranscript::new and .domain_separate only — the two call sites
# that inject a free-form domain label. Does NOT cover Ed25519T::ID / ::CONTEXT
# (those are typed associated consts; covered by row-presence + const binding,
# and by the ciphersuite pin below scoped to shekyl-fcmp-proofs).
MECH3_TRANSCRIPT_EXPECTED=2
mech3_tx=$(count_pattern 'RecommendedTranscript::new\(|\.domain_separate\(')
if [[ "$mech3_tx" != "$MECH3_TRANSCRIPT_EXPECTED" ]]; then
  echo "COUNT DRIFT mech 3 (FROST transcript labels): found $mech3_tx, pinned $MECH3_TRANSCRIPT_EXPECTED." >&2
  echo "  A FROST transcript label site was added/removed. Register it in $REGISTRY and update the pin." >&2
  fail=1
fi

# --- mech 3b: FROST ciphersuite ID/CONTEXT associated consts ---
# Scoped to shekyl-fcmp-proofs (the only production FROST ciphersuite owner in
# our tree). Helios/Selene curve IDs in shekyl-oxide are unrelated and out of
# scope. Catches a new production ID/CONTEXT declaration in the SAL path.
MECH3_CIPHERSUITE_EXPECTED=2
mech3_cs=$(count_pattern 'const (?:ID|CONTEXT):\s*&'\''static \[u8\]' rust/shekyl-fcmp-proofs)
if [[ "$mech3_cs" != "$MECH3_CIPHERSUITE_EXPECTED" ]]; then
  echo "COUNT DRIFT mech 3 (FROST ciphersuite ID/CONTEXT): found $mech3_cs, pinned $MECH3_CIPHERSUITE_EXPECTED." >&2
  echo "  A Ciphersuite::ID / Curve::CONTEXT site was added/removed in shekyl-fcmp-proofs." >&2
  echo "  Register the new domain in $REGISTRY and update the pin." >&2
  fail=1
fi

echo "count-pins: mech1(cSHAKE)=$mech1 mech3(transcript)=$mech3_tx mech3(ciphersuite)=$mech3_cs"

if [[ "$fail" -ne 0 ]]; then
  echo "domain-registry gate: FAIL" >&2
  exit 1
fi
echo "domain-registry gate: PASS"
