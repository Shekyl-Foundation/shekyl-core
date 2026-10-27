#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The macOS code-signature tie (TB-11).

Shekyl signs Tor's macOS binaries with its Developer ID, so the bytes that
ship are not Tor's release. `codesign --remove-signature` does not give Tor's
bytes back: it leaves `__LINKEDIT`'s vmsize grown. This reader needs no
`codesign` and runs anywhere. It rebuilds the signed file from the upstream
bytes with exactly the edits signing makes, taking only the signature's own
values from the shipped file, and requires the result to equal the shipped
file byte for byte.

Inputs are two byte strings, upstream and shipped, and a location named in
any refusal. Output is nothing on success. A difference is `SignatureTieError`.
The packaging gate turns that into its own refusal; this module does not know
about the pin file.
"""


class SignatureTieError(Exception):
    """The shipped file is not the upstream file plus a code signature."""


# Mach-O, 64-bit little-endian. Apple's `mach-o/loader.h`.
_MH_MAGIC_64 = 0xFEEDFACF
_MH_HEADER_SIZE = 32
# mach_header_64: ncmds at 16, sizeofcmds at 20.
_MH_NCMDS = 16
_MH_SIZEOFCMDS = 20
_LC_SEGMENT_64 = 0x19
_LC_CODE_SIGNATURE = 0x1D
# A code-signature load command is one linkedit_data_command: 16 bytes.
_LINKEDIT_CMD_SIZE = 16
# linkedit_data_command: dataoff and datasize follow cmd and cmdsize.
_SIG_DATAOFF = 8
_SIG_DATASIZE = 12
# segment_command_64: segname occupies bytes 8..24; the file fields follow.
_SEG_VMSIZE = 32
_SEG_FILEOFF = 40
_SEG_FILESIZE = 48
# CPU_TYPE_X86_64 and CPU_TYPE_ARM64 (CPU_ARCH_ABI64 already or'd in).
_CPU_TYPE_X86_64 = 0x01000007
_CPU_TYPE_ARM64 = 0x0100000C
_MACHO_CPU_TYPES = (_CPU_TYPE_ARM64, _CPU_TYPE_X86_64)
# codesign rounds the grown __LINKEDIT vmsize up to 16 KiB on both CPU types.
# Tor's x86_64 linker had rounded to 4 KiB (measured 2026-10-22, seven signed
# files, Developer ID and ad-hoc).
_SIGNED_LINKEDIT_ROUND = 0x4000
# codesign starts the signature blob on a 16-byte boundary.
_SIGNATURE_ALIGN = 16


def _u32(data, offset, where):
    if offset < 0 or offset + 4 > len(data):
        raise SignatureTieError(f"{where}: truncated Mach-O image")
    return int.from_bytes(data[offset : offset + 4], "little")


def _macho_layout(data, where):
    """`(cputype, ncmds, sizeofcmds, linkedit_offset, commands)` of one image.

    `commands` is `[(offset, cmd, size)]`. Anything this reader cannot follow
    is a refusal.
    """
    if _u32(data, 0, where) != _MH_MAGIC_64:
        raise SignatureTieError(f"{where}: not a 64-bit little-endian Mach-O image")
    cputype = _u32(data, 4, where)
    ncmds = _u32(data, _MH_NCMDS, where)
    sizeofcmds = _u32(data, _MH_SIZEOFCMDS, where)
    commands, linkedit, offset = [], None, _MH_HEADER_SIZE
    for _ in range(ncmds):
        cmd = _u32(data, offset, where)
        size = _u32(data, offset + 4, where)
        if size < 8 or offset + size > _MH_HEADER_SIZE + sizeofcmds:
            raise SignatureTieError(f"{where}: a load command runs past the header's sizeofcmds")
        if cmd == _LC_SEGMENT_64 and data[offset + 8 : offset + 24].rstrip(b"\0") == b"__LINKEDIT":
            linkedit = offset
        commands.append((offset, cmd, size))
        offset += size
    if offset != _MH_HEADER_SIZE + sizeofcmds:
        raise SignatureTieError(f"{where}: the load commands do not fill sizeofcmds")
    if linkedit is None:
        raise SignatureTieError(f"{where}: no __LINKEDIT segment")
    return cputype, ncmds, sizeofcmds, linkedit, commands


def check_signature_tie(upstream, shipped, where):
    """The shipped file is `upstream` plus one code signature, and nothing else.

    The edits signing makes, and the only ones accepted:

    - the header's ncmds grows by one and sizeofcmds by 16;
    - one `LC_CODE_SIGNATURE`, the last load command, in space that is zero
      in upstream;
    - `__LINKEDIT`, the segment that ends the file, grown to hold the blob:
      filesize to the blob's end, vmsize rounded up to 16 KiB;
    - zero padding to the 16-byte boundary where the blob starts, and the
      blob running to the end of the file.
    """
    cputype, ncmds, sizeofcmds, linkedit, _ = _macho_layout(upstream, f"{where} (upstream)")
    if cputype not in _MACHO_CPU_TYPES:
        raise SignatureTieError(f"{where}: CPU type {cputype:#x} is not arm64 or x86_64")
    s_cputype, s_ncmds, s_sizeofcmds, s_linkedit, s_commands = _macho_layout(shipped, where)
    if s_cputype != cputype or s_linkedit != linkedit:
        raise SignatureTieError(
            f"{where}: is not the upstream image signed (CPU type or segment layout differs)"
        )
    if s_ncmds != ncmds + 1 or s_sizeofcmds != sizeofcmds + _LINKEDIT_CMD_SIZE:
        raise SignatureTieError(f"{where}: signing adds exactly one 16-byte load command")
    sig_offset, sig_cmd, sig_size = s_commands[-1]
    if sig_cmd != _LC_CODE_SIGNATURE or sig_size != _LINKEDIT_CMD_SIZE:
        raise SignatureTieError(
            f"{where}: the added load command is not a code signature, or is not last"
        )
    if any(upstream[sig_offset : sig_offset + sig_size]):
        raise SignatureTieError(
            f"{where}: the code signature's load command overwrites bytes upstream uses"
        )
    dataoff = int.from_bytes(shipped[sig_offset + _SIG_DATAOFF : sig_offset + _SIG_DATAOFF + 4], "little")
    datasize = int.from_bytes(
        shipped[sig_offset + _SIG_DATASIZE : sig_offset + _SIG_DATASIZE + 4], "little"
    )
    if (
        datasize == 0
        or dataoff % _SIGNATURE_ALIGN
        or not len(upstream) <= dataoff < len(upstream) + _SIGNATURE_ALIGN
        or dataoff + datasize != len(shipped)
    ):
        raise SignatureTieError(
            f"{where}: the signature blob does not start at the first 16-byte boundary "
            "after Tor's bytes and run to the end of the file"
        )
    fileoff = int.from_bytes(upstream[linkedit + _SEG_FILEOFF : linkedit + _SEG_FILEOFF + 8], "little")
    filesize = int.from_bytes(upstream[linkedit + _SEG_FILESIZE : linkedit + _SEG_FILESIZE + 8], "little")
    if fileoff + filesize != len(upstream):
        raise SignatureTieError(
            f"{where}: upstream's __LINKEDIT does not end the file, so it cannot hold the blob"
        )

    expected = bytearray(upstream)
    expected += bytes(dataoff - len(upstream))
    expected += shipped[dataoff:]
    expected[_MH_NCMDS : _MH_NCMDS + 4] = (ncmds + 1).to_bytes(4, "little")
    expected[_MH_SIZEOFCMDS : _MH_SIZEOFCMDS + 4] = (sizeofcmds + _LINKEDIT_CMD_SIZE).to_bytes(4, "little")
    expected[sig_offset : sig_offset + sig_size] = shipped[sig_offset : sig_offset + sig_size]
    new_filesize = len(shipped) - fileoff
    new_vmsize = -(-new_filesize // _SIGNED_LINKEDIT_ROUND) * _SIGNED_LINKEDIT_ROUND
    expected[linkedit + _SEG_VMSIZE : linkedit + _SEG_VMSIZE + 8] = new_vmsize.to_bytes(8, "little")
    expected[linkedit + _SEG_FILESIZE : linkedit + _SEG_FILESIZE + 8] = new_filesize.to_bytes(8, "little")
    if bytes(expected) != shipped:
        first = next(i for i, (left, right) in enumerate(zip(expected, shipped)) if left != right)
        raise SignatureTieError(
            f"{where}: differs from the upstream file signed at byte {first:#x}; "
            "only the code signature's own fields may differ"
        )
