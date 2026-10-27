#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The Windows import-table reader (TB-11).

Reads a PE image's import directory and its delay-load directory and returns
the DLL names each records. Anything it cannot follow is `PeFormatError`,
never an empty list: a table it could not parse is not a table that names
nothing.

Inputs are the image bytes and a location named in any refusal. This module
does not know the pin file, a URL, or which DLLs are allowed. The packaging
gate turns `PeFormatError` into its own refusal and applies the row's list.
"""


class PeFormatError(Exception):
    """The image is not a PE file this reader can follow."""


# DOS header: the e_lfanew field holds the file offset of the PE signature.
_DOS_MAGIC = b"MZ"
_DOS_E_LFANEW = 0x3C
_PE_SIGNATURE = b"PE\0\0"
# IMAGE_FILE_HEADER follows the signature. NumberOfSections and
# SizeOfOptionalHeader are the two fields this reader needs; the optional
# header begins after the 20-byte COFF header.
_COFF_HEADER_SIZE = 20
_COFF_NUMBER_OF_SECTIONS = 2
_COFF_SIZE_OF_OPTIONAL_HEADER = 16
# Optional-header magic, then the fields that differ between PE32 and PE32+.
_PE32_MAGIC = 0x10B
_PE32PLUS_MAGIC = 0x20B
_PE32_IMAGE_BASE = 28
_PE32_NUMBER_OF_RVA = 92
_PE32_DATA_DIRECTORIES = 96
_PE32PLUS_IMAGE_BASE = 24
_PE32PLUS_NUMBER_OF_RVA = 108
_PE32PLUS_DATA_DIRECTORIES = 112
# IMAGE_SECTION_HEADER is 40 bytes. The four fields used here sit at these
# offsets inside it.
_SECTION_HEADER_SIZE = 40
_SECTION_VIRTUAL_SIZE = 8
_SECTION_VIRTUAL_ADDRESS = 12
_SECTION_RAW_SIZE = 16
_SECTION_RAW_OFFSET = 20
# IMAGE_DATA_DIRECTORY is an RVA and a size, four bytes each.
_DATA_DIRECTORY_SIZE = 8
_DATA_DIRECTORY_SIZE_OFFSET = 4
# ImgDelayDescr attributes word. Zero means the pre-VC7 form.
_DELAY_ATTRIBUTES_SIZE = 4
# Optional Header Data Directories: the import table, and the delay-load
# import descriptors.
_IMPORT_DIRECTORY = 1
_DELAY_IMPORT_DIRECTORY = 13
# IMAGE_IMPORT_DESCRIPTOR is 20 bytes; the DLL name RVA is at 12.
_IMPORT_DESCRIPTOR_SIZE = 20
_IMPORT_NAME_RVA = 12
# ImgDelayDescr is 32 bytes; the DLL name RVA is at 4.
_DELAY_DESCRIPTOR_SIZE = 32
_DELAY_NAME_RVA = 4
# A bound on descriptors walked, so a malformed table cannot spin the reader.
_MAX_DESCRIPTORS = 4096
# A DLL name longer than this, with no NUL inside it, is unterminated.
_DLL_NAME_LIMIT = 256
# The name field inside either descriptor is one RVA.
_NAME_RVA_SIZE = 4


def _u16(data, offset, where):
    if offset < 0 or offset + 2 > len(data):
        raise PeFormatError(f"{where}: truncated PE image")
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data, offset, where):
    if offset < 0 or offset + 4 > len(data):
        raise PeFormatError(f"{where}: truncated PE image")
    return int.from_bytes(data[offset : offset + 4], "little")


def _u64(data, offset, where):
    if offset < 0 or offset + 8 > len(data):
        raise PeFormatError(f"{where}: truncated PE image")
    return int.from_bytes(data[offset : offset + 8], "little")


def pe_imports(data, where):
    """The DLL names a PE image imports: `(imports, delay_imports)`.

    Each list is in table order. Only the headers, the section table and the
    two import directories are read.
    """
    if data[: len(_DOS_MAGIC)] != _DOS_MAGIC:
        raise PeFormatError(f"{where}: not a PE image (no MZ header)")
    pe = _u32(data, _DOS_E_LFANEW, where)
    if data[pe : pe + len(_PE_SIGNATURE)] != _PE_SIGNATURE:
        raise PeFormatError(f"{where}: not a PE image (no PE signature)")
    coff = pe + len(_PE_SIGNATURE)
    section_count = _u16(data, coff + _COFF_NUMBER_OF_SECTIONS, where)
    optional_size = _u16(data, coff + _COFF_SIZE_OF_OPTIONAL_HEADER, where)
    optional = coff + _COFF_HEADER_SIZE
    magic = _u16(data, optional, where)
    if magic == _PE32_MAGIC:
        image_base = _u32(data, optional + _PE32_IMAGE_BASE, where)
        directory_count = _u32(data, optional + _PE32_NUMBER_OF_RVA, where)
        directories = optional + _PE32_DATA_DIRECTORIES
    elif magic == _PE32PLUS_MAGIC:
        image_base = _u64(data, optional + _PE32PLUS_IMAGE_BASE, where)
        directory_count = _u32(data, optional + _PE32PLUS_NUMBER_OF_RVA, where)
        directories = optional + _PE32PLUS_DATA_DIRECTORIES
    else:
        raise PeFormatError(f"{where}: unknown PE optional-header magic {magic:#x}")

    sections = []
    table = optional + optional_size
    for i in range(section_count):
        header = table + _SECTION_HEADER_SIZE * i
        virtual_size = _u32(data, header + _SECTION_VIRTUAL_SIZE, where)
        virtual_address = _u32(data, header + _SECTION_VIRTUAL_ADDRESS, where)
        raw_size = _u32(data, header + _SECTION_RAW_SIZE, where)
        raw_offset = _u32(data, header + _SECTION_RAW_OFFSET, where)
        sections.append((virtual_address, max(virtual_size, raw_size), raw_offset, raw_size))

    def offset_of(rva):
        for virtual_address, span, raw_offset, raw_size in sections:
            if virtual_address <= rva < virtual_address + span:
                delta = rva - virtual_address
                if delta >= raw_size:
                    break
                return raw_offset + delta
        raise PeFormatError(f"{where}: RVA {rva:#x} is not backed by any section")

    def name_at(rva):
        start = offset_of(rva)
        end = data.find(b"\0", start, start + _DLL_NAME_LIMIT)
        if end < 0:
            raise PeFormatError(f"{where}: an imported DLL name at RVA {rva:#x} is unterminated")
        return data[start:end].decode("ascii", errors="strict")

    def directory(index):
        if index >= directory_count:
            return 0, 0
        entry = directories + _DATA_DIRECTORY_SIZE * index
        return (
            _u32(data, entry, where),
            _u32(data, entry + _DATA_DIRECTORY_SIZE_OFFSET, where),
        )

    def walk(index, descriptor_size, name_field):
        rva, size = directory(index)
        # Absent means both fields zero. The loader walks import descriptors
        # from the RVA to the null terminator and does not read the size, so
        # an RVA with a zero size is still a table; a pair with one field set
        # is refused rather than guessed at either way.
        if rva == 0 and size == 0:
            return []
        if rva == 0 or size == 0:
            raise PeFormatError(
                f"{where}: data directory {index} has RVA {rva:#x} and size {size}; "
                "a table is both or neither"
            )
        names = []
        base = offset_of(rva)
        for i in range(_MAX_DESCRIPTORS):
            at = base + descriptor_size * i
            descriptor = data[at : at + descriptor_size]
            if len(descriptor) < descriptor_size:
                raise PeFormatError(f"{where}: an import table runs past the end of the image")
            if not any(descriptor):
                return names
            name_rva = int.from_bytes(
                descriptor[name_field : name_field + _NAME_RVA_SIZE], "little"
            )
            # A delay-load descriptor whose attributes word is zero is the
            # pre-VC7 form, whose name field is a virtual address.
            attributes = descriptor[:_DELAY_ATTRIBUTES_SIZE]
            if index == _DELAY_IMPORT_DIRECTORY and attributes == bytes(_DELAY_ATTRIBUTES_SIZE):
                name_rva -= image_base
            names.append(name_at(name_rva))
        raise PeFormatError(f"{where}: an import table has no terminating descriptor")

    try:
        return (
            walk(_IMPORT_DIRECTORY, _IMPORT_DESCRIPTOR_SIZE, _IMPORT_NAME_RVA),
            walk(_DELAY_IMPORT_DIRECTORY, _DELAY_DESCRIPTOR_SIZE, _DELAY_NAME_RVA),
        )
    except UnicodeDecodeError as exc:
        raise PeFormatError(f"{where}: an imported DLL name is not ASCII") from exc
