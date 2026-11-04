#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
#
# Binary-hardening gate on the linked, staged binaries.
#
# Usage: check_binary_hardening.sh [--tool-prefix <prefix>] <binary>...
#
# `shekyld` is a Rust binary that links the C++ remnant (DAEMON_CONFIG_CUTOVER.md
# DC-Q19, DC-Q21). The C++ executables took their hardening from
# `LD_SECURITY_FLAGS` through `CMAKE_EXE_LINKER_FLAGS`; the Rust binaries get
# the same list through `corrosion_add_target_local_rustflags` (shekyld) or
# rustc's own defaults (shekyl-cli, shekyl-wallet-rpc). A flag list is a claim
# about the build; this script reads the result off the staged file, so the
# claim can fail. Every check reads the binary itself: no flag grep, no
# convention check (rule 47).
#
# The object format is read from the magic bytes, and the checks follow it:
#
#   ELF     PIE (ET_DYN), a GNU_STACK segment that is not executable, a
#           GNU_RELRO segment, BIND_NOW (full RELRO with the previous), and no
#           DT_RPATH / DT_RUNPATH.
#   PE      PE32+ (64-bit), and DllCharacteristics carrying DYNAMIC_BASE,
#           NX_COMPAT and HIGH_ENTROPY_VA.
#   Mach-O  MH_PIE set, MH_ALLOW_STACK_EXECUTION clear, no LC_RPATH.
#
# What is not read here, and why: the compile-time mitigations (stack
# protector, FORTIFY, CET, `/GS`) leave no uniform header mark. Their presence
# is the compiler flag lists in CMakeLists.txt, and a pure-Rust binary has no
# `__stack_chk_fail` to find. The single-tracing-dispatcher nm gate is
# src/daemon/CMakeLists.txt's and stays there.
#
# Tools. Cross builds produce a format the host's default tool may not parse
# (the depends Cross-Mac leg links Mach-O on Linux), so ELF and Mach-O each
# have a candidate list: the `--tool-prefix` (or `SHEKYL_TOOL_PREFIX`) tool
# first, which for depends is `contrib/depends/<host>/native/bin/<host>-`,
# then the plain and the LLVM names. The first candidate that parses the
# file is used; if none can, the gate fails rather than passes (rule 47).
# PE needs no tool: its headers are at fixed offsets and are read with `od`
# (DC-F32).
#
# Rule 46: no verdict travels through a pipe. Tool output is captured once
# into a variable and inspected with `grep` under `if`.

set -euo pipefail

usage() {
  echo "usage: $0 [--tool-prefix <prefix>] <binary>..." >&2
  exit 2
}

PREFIX="${SHEKYL_TOOL_PREFIX:-}"
BINARIES=()
while [ $# -gt 0 ]; do
  case "$1" in
    --tool-prefix)
      [ $# -ge 2 ] || usage
      PREFIX="$2"
      shift 2
      ;;
    --tool-prefix=*)
      PREFIX="${1#--tool-prefix=}"
      shift
      ;;
    -h|--help)
      usage
      ;;
    -*)
      echo "unknown option: $1" >&2
      usage
      ;;
    *)
      BINARIES+=("$1")
      shift
      ;;
  esac
done

# Subject assertion: a gate given nothing to check reports nothing wrong.
if [ "${#BINARIES[@]}" -eq 0 ]; then
  echo "binary hardening gate: no binaries named — the gate's subject is missing" >&2
  exit 2
fi

FAILED=0
fail() {
  echo "  FAIL  $1" >&2
  FAILED=1
}
ok() {
  echo "  ok    $1"
}

# resolve_tool <out-var> <candidate>...: the first candidate found on PATH
# (or as an absolute path) is stored in <out-var>, as given — the name, not
# `command -v`'s path, which on a Windows runner can carry a space; the
# function returns 1 when none exists.
resolve_tool() {
  local _rt_out="$1"
  shift
  local _rt_cand
  for _rt_cand in "$@"; do
    [ -n "$_rt_cand" ] || continue
    if command -v "$_rt_cand" >/dev/null 2>&1; then
      printf -v "$_rt_out" '%s' "$_rt_cand"
      return 0
    fi
  done
  return 1
}

# run_first <out-var> <args-string>... : tries each "<tool> <args>" string in
# order and stores the first output that is non-empty and exits 0. Tools that
# cannot parse the file exit non-zero or print nothing; both are skipped.
run_first() {
  local _rf_out="$1"
  shift
  # Locals named so they cannot shadow the caller's variable that `_rf_out`
  # names: `printf -v` writes to the innermost scope that declares it.
  local _rf_cmd _rf_text
  for _rf_cmd in "$@"; do
    # shellcheck disable=SC2086
    if _rf_text=$($_rf_cmd 2>/dev/null) && [ -n "$_rf_text" ]; then
      printf -v "$_rf_out" '%s' "$_rf_text"
      return 0
    fi
  done
  return 1
}

magic_of() {
  # The first four bytes as lowercase hex, no spaces.
  od -An -N4 -tx1 "$1" | tr -d ' \n'
}

check_elf() {
  local bin="$1" tool hdr segs dyn
  local -a cands=()
  for t in "${PREFIX}readelf" readelf llvm-readelf; do
    if resolve_tool tool "$t"; then cands+=("$tool"); fi
  done
  if [ "${#cands[@]}" -eq 0 ]; then
    fail "$bin: ELF, but no readelf found (tried ${PREFIX}readelf, readelf, llvm-readelf)"
    return
  fi
  local -a hcmds=() lcmds=() dcmds=()
  for t in "${cands[@]}"; do
    hcmds+=("$t -h $bin")
    lcmds+=("$t -lW $bin")
    dcmds+=("$t -dW $bin")
  done
  if ! run_first hdr "${hcmds[@]}"; then
    fail "$bin: no readelf candidate could parse the ELF header (${cands[*]})"
    return
  fi
  run_first segs "${lcmds[@]}" || segs=""
  run_first dyn "${dcmds[@]}" || dyn=""

  if printf '%s\n' "$hdr" | grep -Eq '^\s*Type:\s+DYN\b'; then
    ok "$bin: PIE (ET_DYN)"
  else
    fail "$bin: not PIE — $(printf '%s\n' "$hdr" | grep -E '^\s*Type:' | sed 's/^ *//')"
  fi

  local stack_line
  stack_line=$(printf '%s\n' "$segs" | grep -E '^\s*GNU_STACK\b' || true)
  if [ -z "$stack_line" ]; then
    fail "$bin: no GNU_STACK segment (the loader's default may be an executable stack)"
  elif printf '%s\n' "$stack_line" | grep -Eq '\sRWE\s|\sE\s'; then
    fail "$bin: GNU_STACK is executable — $stack_line"
  else
    ok "$bin: non-executable stack (GNU_STACK without E)"
  fi

  if printf '%s\n' "$segs" | grep -Eq '^\s*GNU_RELRO\b'; then
    ok "$bin: GNU_RELRO segment present"
  else
    fail "$bin: no GNU_RELRO segment"
  fi

  if printf '%s\n' "$dyn" | grep -Eq '\(FLAGS\)\s.*\bBIND_NOW\b|\(FLAGS_1\)\s.*\bNOW\b'; then
    ok "$bin: BIND_NOW (full RELRO)"
  else
    fail "$bin: no BIND_NOW in DT_FLAGS / DT_FLAGS_1 (partial RELRO at best)"
  fi

  if printf '%s\n' "$dyn" | grep -Eq '\((RPATH|RUNPATH)\)'; then
    fail "$bin: carries a run path — $(printf '%s\n' "$dyn" | grep -E '\((RPATH|RUNPATH)\)' | sed 's/^ *//')"
  else
    ok "$bin: no DT_RPATH / DT_RUNPATH"
  fi
}

# pe_u16 / pe_u32 <file> <offset>: a little-endian field of the PE headers as
# a decimal number, or nothing when the file ends before it. `od` exits
# non-zero when asked to skip past the end; under `set -eo pipefail` that
# would end the gate with no verdict line (rule 46), so the read is allowed
# to fail and the empty result is the caller's finding.
pe_u16() {
  { od -An -tu2 -j "$2" -N2 "$1" 2>/dev/null || true; } | tr -d ' \n'
}
pe_u32() {
  { od -An -tu4 -j "$2" -N4 "$1" 2>/dev/null || true; } | tr -d ' \n'
}

check_pe() {
  local bin="$1"
  # Read from the bytes, not from a tool's text. The first form of this
  # check asked objdump / llvm-readobj / dumpbin for the headers and matched
  # their spellings; on both Windows legs the text it read carried the
  # DllCharacteristics in a form it parsed and the magic in one it did not
  # (DAEMON_CONFIG_CUTOVER.md DC-F32). The PE/COFF layout is fixed: the
  # `e_lfanew` dword at 0x3c locates the `PE\0\0` signature; the COFF file
  # header (20 bytes) follows it, with `Machine` at +4 and
  # `SizeOfOptionalHeader` at +20; the optional header follows that, with
  # `Magic` at +0 (0x20b PE32+, 0x10b PE32) and `DllCharacteristics` at +70
  # in both forms. `od` reads them the same on every host, and the values
  # read are printed so a verdict can be checked against the file.
  local lfanew sig machine opt_size magic chars opt machine_name
  lfanew=$(pe_u32 "$bin" 60)
  if [ -z "$lfanew" ] || [ "$lfanew" -lt 64 ]; then
    fail "$bin: no e_lfanew (dword at 0x3c read as '${lfanew:-nothing}')"
    return
  fi
  sig=$(pe_u32 "$bin" "$lfanew")
  if [ "${sig:-0}" -ne 17744 ]; then # 0x00004550, "PE\0\0"
    fail "$bin: no PE signature at e_lfanew=$lfanew (read '${sig:-nothing}', want 17744)"
    return
  fi
  machine=$(pe_u16 "$bin" $((lfanew + 4)))
  opt_size=$(pe_u16 "$bin" $((lfanew + 20)))
  opt=$((lfanew + 24))
  magic=$(pe_u16 "$bin" "$opt")
  if [ -z "$machine" ] || [ -z "$opt_size" ] || [ -z "$magic" ]; then
    fail "$bin: the file ends inside its COFF header"
    return
  fi
  if [ "$opt_size" -lt 72 ]; then
    fail "$bin: SizeOfOptionalHeader $opt_size is too small to carry DllCharacteristics (+70)"
    return
  fi
  case "$machine" in
    34404) machine_name="x86-64" ;;  # 0x8664
    43620) machine_name="ARM64" ;;   # 0xaa64
    *) machine_name="" ;;
  esac
  if [ "$magic" -eq 523 ] && [ -n "$machine_name" ]; then # 0x20b
    ok "$bin: PE32+ (magic 0x20b, machine $machine_name)"
  elif [ "$magic" -eq 523 ]; then
    fail "$bin: PE32+ (magic 0x20b) on a machine this gate does not name ($(printf '0x%x' "$machine"))"
  else
    fail "$bin: not a PE32+ image (magic $(printf '0x%x' "$magic"), machine $(printf '0x%x' "$machine"))"
  fi

  # IMAGE_DLLCHARACTERISTICS_* (winnt.h).
  local HIGH_ENTROPY_VA=$((0x0020)) DYNAMIC_BASE=$((0x0040)) NX_COMPAT=$((0x0100))
  chars=$(pe_u16 "$bin" $((opt + 70)))
  if [ -z "$chars" ]; then
    fail "$bin: the file ends before DllCharacteristics"
    return
  fi
  local chars_hex
  chars_hex=$(printf '%04x' "$chars")
  if [ $((chars & DYNAMIC_BASE)) -ne 0 ]; then
    ok "$bin: DYNAMIC_BASE (ASLR); DllCharacteristics 0x$chars_hex"
  else
    fail "$bin: DllCharacteristics 0x$chars_hex lacks DYNAMIC_BASE"
  fi
  if [ $((chars & HIGH_ENTROPY_VA)) -ne 0 ]; then
    ok "$bin: HIGH_ENTROPY_VA (64-bit ASLR)"
  else
    fail "$bin: DllCharacteristics 0x$chars_hex lacks HIGH_ENTROPY_VA"
  fi
  if [ $((chars & NX_COMPAT)) -ne 0 ]; then
    ok "$bin: NX_COMPAT (DEP)"
  else
    fail "$bin: DllCharacteristics 0x$chars_hex lacks NX_COMPAT"
  fi
}

check_macho() {
  local bin="$1" tool hdr cmds
  local -a hcands=() lcands=()
  for t in "${PREFIX}otool" otool llvm-otool; do
    if resolve_tool tool "$t"; then
      hcands+=("$tool -hv $bin")
      lcands+=("$tool -l $bin")
    fi
  done
  for t in "${PREFIX}objdump" llvm-objdump; do
    if resolve_tool tool "$t"; then
      hcands+=("$tool --macho --private-header $bin")
      lcands+=("$tool --macho --private-headers $bin")
    fi
  done
  if [ "${#hcands[@]}" -eq 0 ]; then
    fail "$bin: Mach-O, but no otool / llvm-otool / llvm-objdump found"
    return
  fi
  if ! run_first hdr "${hcands[@]}"; then
    fail "$bin: no Mach-O tool could parse the header (tried: ${hcands[*]})"
    return
  fi
  run_first cmds "${lcands[@]}" || cmds=""

  # `otool -hv` and `llvm-objdump --macho --private-header` both print the
  # header flags as words (NOUNDEFS DYLDLINK TWOLEVEL PIE ...). A fat file
  # prints one header per architecture; every one must carry PIE.
  local headers n_pie n_hdr
  headers=$(printf '%s\n' "$hdr" | grep -E '^\s*MH_MAGIC' || true)
  n_hdr=$(printf '%s\n' "$headers" | grep -c . || true)
  if [ "$n_hdr" -eq 0 ]; then
    fail "$bin: no MH_MAGIC header line in the tool output"
    return
  fi
  n_pie=$(printf '%s\n' "$headers" | grep -cw PIE || true)
  if [ "$n_pie" -eq "$n_hdr" ]; then
    ok "$bin: MH_PIE on $n_hdr header(s)"
  else
    fail "$bin: MH_PIE on $n_pie of $n_hdr header(s)"
  fi
  if printf '%s\n' "$headers" | grep -qw ALLOW_STACK_EXECUTION; then
    fail "$bin: MH_ALLOW_STACK_EXECUTION is set"
  else
    ok "$bin: stack not executable (no MH_ALLOW_STACK_EXECUTION)"
  fi
  if printf '%s\n' "$cmds" | grep -Eq '\bLC_RPATH\b'; then
    fail "$bin: carries LC_RPATH"
  else
    ok "$bin: no LC_RPATH"
  fi
}

for bin in "${BINARIES[@]}"; do
  if [ ! -f "$bin" ]; then
    fail "$bin: not a file"
    continue
  fi
  if [ ! -s "$bin" ]; then
    fail "$bin: empty file"
    continue
  fi
  magic=$(magic_of "$bin")
  case "$magic" in
    7f454c46)
      echo "$bin: ELF"
      check_elf "$bin"
      ;;
    4d5a*)
      echo "$bin: PE"
      check_pe "$bin"
      ;;
    cffaedfe|feedfacf|cefaedfe|feedface|cafebabe|bebafeca)
      echo "$bin: Mach-O"
      check_macho "$bin"
      ;;
    *)
      fail "$bin: unrecognised object format (magic $magic)"
      ;;
  esac
done

if [ "$FAILED" -ne 0 ]; then
  echo "binary hardening gate FAILED" >&2
  exit 1
fi
echo "binary hardening gate: ${#BINARIES[@]} binary(ies) carry the hardening of record"
