# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""CA-3 ML-DSA, Step 2: did a layout variant change only the layout?

Compares two aarch64 binaries' `.text` by disassembly. Each function becomes
its demangled name (the symbol hash removed) and its instruction stream with
everything that only encodes an address taken out:
- the address column;
- ADRP's page operand, and the low-12 immediate of an ADD, load or store whose
  base register an ADRP set;
- a branch target's numeric address (the target's symbol and offset stay, so a
  branch to a different place still differs);
- trailing NOP, UDF and zero padding after the function's last instruction.

The binaries match when the two multisets of (name, stream) are equal. The
script also reports how many fips204 and keccak functions moved, because a
variant that moved nothing tests nothing.

Exit status: 0 when the code is identical and fips204's functions moved; 1
otherwise.
"""

import argparse
import collections
import hashlib
import re
import subprocess
import sys
import tempfile

HEADER = re.compile(r"^([0-9a-f]+) <(.+)>:$")
INSTRUCTION = re.compile(r"^\s*([0-9a-f]+):\s+(\S+)(?:\s+(.*))?$")
SYMBOL_HASH = re.compile(r"::h[0-9a-f]{16}")
TARGET = re.compile(r"\b[0-9a-f]+ <([^>]+)>")
MEMORY_BASE = re.compile(r"\[(x\d+|sp), #(-?(?:0x)?[0-9a-f]+)\]")
PADDING = {"nop", "udf", ".inst", ".word"}
LOW12_USERS = {"add", "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw", "str", "strb", "strh"}


def normalise(mnemonic, operands, page_registers):
    """One instruction without its address-only content."""
    operands = operands.split("//")[0].strip()
    first = operands.split(",")[0].strip() if operands else ""
    if mnemonic == "adrp":
        page_registers.add(first)
        return f"adrp {first}, ADDR"
    operands = TARGET.sub(lambda m: f"<{SYMBOL_HASH.sub('', m.group(1))}>", operands)
    if mnemonic in LOW12_USERS:
        if mnemonic == "add":
            parts = [part.strip() for part in operands.split(",")]
            if len(parts) == 3 and parts[1] in page_registers and parts[2].startswith("#"):
                operands = f"{parts[0]}, {parts[1]}, IMM"
        else:
            match = MEMORY_BASE.search(operands)
            if match and match.group(1) in page_registers:
                operands = operands[: match.start()] + f"[{match.group(1)}, IMM]"
    if first in page_registers and mnemonic not in {"str", "strb", "strh"}:
        if mnemonic != "add" or not operands.endswith("IMM"):
            page_registers.discard(first)
    return f"{mnemonic} {operands}".strip()


def disassemble(objdump, binary):
    """Return [(name, normalised stream, address)] for every `.text` function."""
    output = subprocess.run(
        [objdump, "-d", "-C", "--no-show-raw-insn", "-j", ".text", binary],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    functions = []
    name, address, stream, raw, pages = None, None, [], [], set()

    def finish():
        if name is None:
            return
        keep = len(stream)
        while keep and raw[keep - 1] in PADDING:
            keep -= 1
        functions.append((name, tuple(stream[:keep]), address))

    for line in output.splitlines():
        header = HEADER.match(line)
        if header:
            finish()
            address = int(header.group(1), 16)
            name = SYMBOL_HASH.sub("", header.group(2))
            stream, raw, pages = [], [], set()
            continue
        instruction = INSTRUCTION.match(line)
        if instruction and name is not None:
            mnemonic, operands = instruction.group(2), instruction.group(3) or ""
            raw.append(mnemonic)
            stream.append(normalise(mnemonic, operands, pages))
    finish()
    return functions


def section_hash(objcopy, binary, section):
    """SHA-256 of one section's bytes."""
    with tempfile.NamedTemporaryFile() as out:
        subprocess.run(
            [objcopy, "-O", "binary", "-j", section, binary, out.name],
            check=True,
            capture_output=True,
        )
        return hashlib.sha256(out.read()).hexdigest()


def moved(base, variant, marker):
    """(functions matching `marker`, how many of them changed address)."""
    def addresses(functions):
        table = collections.defaultdict(list)
        for name, stream, address in functions:
            if marker in name:
                table[(name, stream)].append(address)
        return table

    first, second = addresses(base), addresses(variant)
    total = sum(len(values) for values in first.values())
    changed = 0
    for key, values in first.items():
        others = set(second.get(key, []))
        changed += sum(1 for value in values if value not in others)
    return total, changed


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("base")
    parser.add_argument("variant")
    parser.add_argument("--objdump", default="aarch64-linux-gnu-objdump")
    parser.add_argument("--objcopy", default="aarch64-linux-gnu-objcopy")
    args = parser.parse_args()
    base = disassemble(args.objdump, args.base)
    variant = disassemble(args.objdump, args.variant)
    base_set = collections.Counter((name, stream) for name, stream, _ in base)
    variant_set = collections.Counter((name, stream) for name, stream, _ in variant)
    only_base = base_set - variant_set
    only_variant = variant_set - base_set
    identical = not only_base and not only_variant
    print(
        f"functions base={len(base)} variant={len(variant)} "
        f"instructions base={sum(len(s) for _, s, _ in base)} "
        f"variant={sum(len(s) for _, s, _ in variant)}"
    )
    print(
        f"code_identical={identical} only_in_base={sum(only_base.values())} "
        f"only_in_variant={sum(only_variant.values())}"
    )
    for (name, _), _count in list(only_base.items())[:8]:
        print(f"  differs: {name[:110]}")
    fips_total, fips_moved = moved(base, variant, "fips204")
    keccak_total, keccak_moved = moved(base, variant, "keccak")
    print(f"fips204 functions={fips_total} moved={fips_moved}")
    print(f"keccak functions={keccak_total} moved={keccak_moved}")
    same_rodata = section_hash(args.objcopy, args.base, ".rodata") == section_hash(
        args.objcopy, args.variant, ".rodata"
    )
    print(f"rodata_identical={same_rodata}")
    verdict = identical and fips_total > 0 and fips_moved > 0
    print(f"verdict={'LAYOUT-ONLY' if verdict else 'NOT-LAYOUT-ONLY'}")
    return 0 if verdict else 1


if __name__ == "__main__":
    sys.exit(main())
