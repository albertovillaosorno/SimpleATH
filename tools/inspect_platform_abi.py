#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Read-only PCI/wireless symbol inventory; never a native ABI approval gate.

Reads a retained JSON reference, x86_64 Mach-O fileset or extracted KDK
files.
Does not invoke build tools, execute target code, mount volumes, fetch files,
read the running kernel or access PCI hardware.
Output is stdout only.
Mach-O nlist candidates do not establish KPI eligibility, C++ layout, export
trie/reexport resolution, dependency versions or OpenCore relocatability.
"""

from __future__ import annotations

import argparse
from enum import StrEnum
import hashlib
import json
import mmap
import os
from pathlib import Path
import plistlib
import stat
import struct
import sys
from typing import NamedTuple
from typing import Never
from typing import TYPE_CHECKING
from typing import TypeIs
from typing import TypedDict
from typing import cast
import uuid

if TYPE_CHECKING:
    from collections.abc import Callable


class _InspectionIssue(StrEnum):
    """Stable, explicit input rejection reasons for offline ABI evidence."""

    AMBIGUOUS_X86_64_SLICES = "Ambiguous x86_64 slices"
    COLLECTION_SOURCE_CHANGED_DURING_INSPECTION = (
        "Collection source changed during inspection"
    )
    COLLECTION_SOURCE_EXCEEDS_INSPECTION_LIMITS = (
        "Collection source exceeds inspection limits"
    )
    COLLECTION_SOURCE_MUST_BE_A_REGULAR_FILE = (
        "Collection source must be a regular file"
    )
    DEFINED_SECTION_SYMBOL_HAS_NO_SECTION = (
        "Defined section symbol has no section"
    )
    EMPTY_OR_DUPLICATE_FILESET_ENTRY_NAME = (
        "Empty or duplicate fileset entry name"
    )
    EXPECTED_A_MACH_O_FILESET_NOT_A_STANDALONE_IMAGE = (
        "Expected a Mach-O fileset, not a standalone image"
    )
    EXPECTED_THIN_LITTLE_ENDIAN_X86_64_MACH_O = (
        "Expected thin little-endian x86_64 Mach-O"
    )
    EXPECTED_THIN_MACH_O_OR_BIG_ENDIAN_FAT_MAGIC = (
        "Expected thin Mach-O or big-endian FAT_MAGIC"
    )
    INVALID_FAT_ARCHITECTURE_COUNT = "Invalid fat architecture count"
    INVALID_FAT_SLICE_OFFSET_ALIGNMENT = "Invalid fat slice offset/alignment"
    INVALID_FILESET_ENTRY_NAME_OFFSET = "Invalid fileset entry name offset"
    INVALID_LC_DYLD_EXPORTS_TRIE = "Invalid LC_DYLD_EXPORTS_TRIE"
    INVALID_LC_DYLD_INFO = "Invalid LC_DYLD_INFO"
    INVALID_MACH_O_COMMAND_COUNT = "Invalid Mach-O command count"
    INVALID_MACH_O_LOAD_COMMAND_SIZE = "Invalid Mach-O load command size"
    INVALID_OR_DUPLICATE_LC_SYMTAB = "Invalid or duplicate LC_SYMTAB"
    INVALID_OR_DUPLICATE_LC_UUID = "Invalid or duplicate LC_UUID"
    KDK_INPUT_CHANGED_DURING_INSPECTION = "KDK input changed during inspection"
    KDK_INPUT_GREW_BEYOND_INSPECTION_LIMIT = (
        "KDK input grew beyond inspection limit"
    )
    KDK_INPUT_MUST_BE_A_BOUNDED_REGULAR_FILE = (
        "KDK input must be a bounded regular file"
    )
    KDK_PATH_MUST_REMAIN_BELOW_THE_SELECTED_ROOT = (
        "KDK path must remain below the selected root"
    )
    MACH_O_COMMAND_BYTES_COUNT_DISAGREE = "Mach-O command bytes/count disagree"
    MACH_O_RANGE_EXCEEDS_SUPPLIED_FILE = "Mach-O range exceeds supplied file"
    MISSING_OFFLINE_ABI_SOURCE = "Missing offline ABI source"
    NO_X86_64_SLICE = "No x86_64 slice"
    OVERLAPPING_FAT_SLICES = "Overlapping fat slices"
    SYMBOL_NAME_EXCEEDS_MACH_O_STRING_TABLE = (
        "Symbol name exceeds Mach-O string table"
    )
    SYSTEMVERSION_PLIST_HAS_EMPTY_VERSION_BUILD_FIELDS = (
        "SystemVersion.plist has empty version/build fields"
    )
    SYSTEMVERSION_PLIST_MUST_CONTAIN_A_DICTIONARY = (
        "SystemVersion.plist must contain a dictionary"
    )
    SYSTEMVERSION_PLIST_REQUIRES_VERSION_BUILD_STRINGS = (
        "SystemVersion.plist requires version/build strings"
    )
    TRUNCATED_LC_FILESET_ENTRY = "Truncated LC_FILESET_ENTRY"
    TRUNCATED_MACH_O_LOAD_COMMAND = "Truncated Mach-O load command"
    UNEXPECTED_KDK_BUNDLE_IDENTIFIER = "Unexpected KDK bundle identifier"
    UNTERMINATED_MACH_O_STRING = "Unterminated Mach-O string"


PCI_FAMILY = "IOPCIFamily"

GROUPS = {
    "pci": ("com.apple.iokit.IOPCIFamily", ("IOPCIDevice",)),
    "dma": ("com.apple.kernel", ("IODMACommand", "IOMapper")),
    "wireless": (
        "com.apple.iokit.IO80211Family",
        ("IO80211Controller", "IO80211SkywalkInterface", "IO80211Interface"),
    ),
    "skywalk": (
        "com.apple.iokit.IOSkywalkFamily",
        ("IOSkywalkNetworkInterface", "IOSkywalkPacketBufferPool"),
    ),
}


class _ImageInventory(TypedDict):
    """Candidate-only metadata from one offline Mach-O image."""

    uuid: str | None
    symbols: dict[str, str]
    entries: dict[str, int]
    exportTriePresent: bool
    symbolEvidence: str
    filetype: int


class _KdkMetadata(TypedDict):
    """Source-reported KDK artifact evidence; never loaded OS state."""

    systemVersion: dict[str, object]
    loadedImageProvenanceVerified: bool
    files: dict[str, dict[str, int | str]]
    images: dict[str, dict[str, object]]


def checked_range(
    data: bytes | mmap.mmap, offset: int, size: int
) -> tuple[int, int]:
    """Calculate a bounded Mach-O byte interval before accessing it.

    Returns:
        The start offset and exclusive end of the validated interval.

    Raises:
        ValueError: The range falls outside its containing byte buffer.

    """
    if offset < 0 or size < 0:
        raise ValueError(
            _InspectionIssue.MACH_O_RANGE_EXCEEDS_SUPPLIED_FILE.value
        )
    if offset > len(data) or size > len(data) - offset:
        raise ValueError(
            _InspectionIssue.MACH_O_RANGE_EXCEEDS_SUPPLIED_FILE.value
        )
    return offset, offset + size


def cstring(data: bytes | mmap.mmap, offset: int, end: int) -> str:
    """Read a terminated UTF-8 string inside a bounded image span.

    Returns:
        A decoded string no larger than the supplied section interval.

    Raises:
        ValueError: The span or required terminator is absent.

    """
    _ = checked_range(data, offset, end - offset)
    terminator = data.find(b"\0", offset, end)
    if terminator < 0:
        raise ValueError(_InspectionIssue.UNTERMINATED_MACH_O_STRING.value)
    return data[offset:terminator].decode("utf-8", errors="strict")


MACHO_MAGIC = 0xFEEDFACF
MACHO_MAGIC_BYTES = b"\xcf\xfa\xed\xfe"
FAT_MAGIC_BYTES = b"\xca\xfe\xba\xbe"
X86_64_CPU_TYPE = 0x01000007
MACHO_HEADER_BYTES = 32
COMMAND_HEADER_BYTES = 8
LC_UUID = 0x1B
LC_SYMTAB = 0x2
LC_FILESET_ENTRY = 0x80000035
LC_EXPORTS_TRIE = 0x80000033
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
UUID_COMMAND_BYTES = 24
SYMTAB_COMMAND_BYTES = 24
FILESET_COMMAND_BYTES = 32
EXPORT_TRIE_COMMAND_BYTES = 16
DYLD_INFO_COMMAND_BYTES = 48
N_ABS = 2
N_SECT = 14
MH_FILESET = 0xC
FAT_MAX_ARCHES = 16
FAT_MAX_ALIGNMENT = 31
FAT_ARCH_BYTES = 20

_Symtab = tuple[int, int, int, int]


def _image_header(
    data: bytes | mmap.mmap,
    header_offset: int,
) -> tuple[int, _CommandSpan]:
    """Check a thin little-endian Mach-O header and its command span.

    Returns:
        File type, command count, start and exclusive end.

    Raises:
        ValueError: The header or command span is invalid.

    """
    _ = checked_range(data, header_offset, MACHO_HEADER_BYTES)
    magic, cpu, _, filetype, count, command_bytes, _, _ = struct.unpack_from(
        "<8I", data, header_offset
    )
    if magic != MACHO_MAGIC or cpu != X86_64_CPU_TYPE:
        raise ValueError(
            _InspectionIssue.EXPECTED_THIN_LITTLE_ENDIAN_X86_64_MACH_O.value
        )
    position = header_offset + MACHO_HEADER_BYTES
    _, commands_end = checked_range(data, position, command_bytes)
    if count > command_bytes // COMMAND_HEADER_BYTES:
        raise ValueError(_InspectionIssue.INVALID_MACH_O_COMMAND_COUNT.value)
    return filetype, _CommandSpan(count, position, commands_end)


def _record_fileset_entry(
    data: bytes | mmap.mmap,
    position: int,
    size: int,
    *,
    result: _ImageInventory,
) -> None:
    """Check and retain a fileset child name and absolute image offset.

    Raises:
        ValueError: The name, command or child image span is malformed.

    """
    if size < FILESET_COMMAND_BYTES:
        raise ValueError(_InspectionIssue.TRUNCATED_LC_FILESET_ENTRY.value)
    _, offset, string_offset, _ = struct.unpack_from(
        "<QQII", data, position + COMMAND_HEADER_BYTES
    )
    if string_offset < FILESET_COMMAND_BYTES or string_offset >= size:
        raise ValueError(
            _InspectionIssue.INVALID_FILESET_ENTRY_NAME_OFFSET.value
        )
    name = cstring(data, position + string_offset, position + size)
    if not name or name in result["entries"]:
        raise ValueError(
            _InspectionIssue.EMPTY_OR_DUPLICATE_FILESET_ENTRY_NAME.value
        )
    _ = checked_range(data, offset, MACHO_HEADER_BYTES)
    result["entries"][name] = offset


def _record_uuid(
    data: bytes | mmap.mmap,
    position: int,
    size: int,
    *,
    result: _ImageInventory,
) -> None:
    """Reject duplicate LC_UUID records and preserve their identifier.

    Raises:
        ValueError: The command length or image UUID uniqueness is invalid.

    """
    if size != UUID_COMMAND_BYTES or result["uuid"] is not None:
        raise ValueError(_InspectionIssue.INVALID_OR_DUPLICATE_LC_UUID.value)
    value = data[position + COMMAND_HEADER_BYTES : position + size]
    result["uuid"] = str(uuid.UUID(bytes=value)).upper()


def _record_metadata_command(
    data: bytes | mmap.mmap,
    position: int,
    size: int,
    *,
    result: _ImageInventory,
) -> _Symtab | None:
    """Inspect UUID, symtab and fileset-entry commands.

    Returns:
        The parsed symtab tuple if the command declares one.

    Raises:
        ValueError: A command has invalid length or duplicate image UUID.

    """
    command = struct.unpack_from("<I", data, position)[0]
    if command == LC_UUID:
        _record_uuid(data, position, size, result=result)
    elif command == LC_SYMTAB:
        if size != SYMTAB_COMMAND_BYTES:
            raise ValueError(
                _InspectionIssue.INVALID_OR_DUPLICATE_LC_SYMTAB.value
            )
        return struct.unpack_from("<4I", data, position + COMMAND_HEADER_BYTES)
    elif command == LC_FILESET_ENTRY:
        _record_fileset_entry(data, position, size, result=result)
    return None


def _record_export_command(
    data: bytes | mmap.mmap,
    position: int,
    size: int,
    *,
    result: _ImageInventory,
) -> None:
    """Check and retain only the presence of an export trie.

    Raises:
        ValueError: The encoded export-data command is malformed.

    """
    command = struct.unpack_from("<I", data, position)[0]
    if command == LC_EXPORTS_TRIE:
        if size != EXPORT_TRIE_COMMAND_BYTES:
            raise ValueError(
                _InspectionIssue.INVALID_LC_DYLD_EXPORTS_TRIE.value
            )
        offset, length = struct.unpack_from(
            "<II", data, position + COMMAND_HEADER_BYTES
        )
    elif command in {LC_DYLD_INFO, LC_DYLD_INFO_ONLY}:
        if size != DYLD_INFO_COMMAND_BYTES:
            raise ValueError(_InspectionIssue.INVALID_LC_DYLD_INFO.value)
        offset, length = struct.unpack_from("<II", data, position + 40)
    else:
        return
    _ = checked_range(data, offset, length)
    result["exportTriePresent"] |= length != 0


class _CommandSpan(NamedTuple):
    """Bounded load-command count and byte interval."""

    num_commands: int
    start: int
    end: int


def _validated_command_size(
    data: bytes | mmap.mmap,
    position: int,
    end: int,
) -> int:
    """Check a command's header, alignment and bounded body.

    Returns:
        The validated byte length of one command.

    Raises:
        ValueError: The command cannot fit in the span.

    """
    if end - position < COMMAND_HEADER_BYTES:
        raise ValueError(_InspectionIssue.TRUNCATED_MACH_O_LOAD_COMMAND.value)
    _, size = struct.unpack_from("<II", data, position)
    if size < COMMAND_HEADER_BYTES or size % COMMAND_HEADER_BYTES:
        raise ValueError(
            _InspectionIssue.INVALID_MACH_O_LOAD_COMMAND_SIZE.value
        )
    if size > end - position:
        raise ValueError(
            _InspectionIssue.INVALID_MACH_O_LOAD_COMMAND_SIZE.value
        )
    return size


def _unique_symtab(
    previous: _Symtab | None, candidate: _Symtab | None
) -> _Symtab | None:
    """Preserve at most one LC_SYMTAB while scanning image metadata.

    Returns:
        The first table, or none when neither command supplies one.

    Raises:
        ValueError: Multiple symbol tables are encountered.

    """
    if candidate is None:
        return previous
    if previous is not None:
        raise ValueError(_InspectionIssue.INVALID_OR_DUPLICATE_LC_SYMTAB.value)
    return candidate


def _scan_load_commands(
    data: bytes | mmap.mmap,
    result: _ImageInventory,
    span: _CommandSpan,
) -> _Symtab | None:
    """Validate load-command alignment and duplicate symbol tables.

    Returns:
        Optional symbol-table descriptor after validating every command.

    Raises:
        ValueError: Commands are truncated, malformed or duplicated.

    """
    position = span.start
    symtab = None
    for _ in range(span.num_commands):
        size = _validated_command_size(data, position, span.end)
        candidate = _record_metadata_command(
            data, position, size, result=result
        )
        symtab = _unique_symtab(symtab, candidate)
        _record_export_command(data, position, size, result=result)
        position += size
    if position != span.end:
        raise ValueError(
            _InspectionIssue.MACH_O_COMMAND_BYTES_COUNT_DISAGREE.value
        )
    return symtab


def _is_public_definition(kind: int) -> bool:
    """Require external non-private N_SECT or N_ABS, never STAB/indirect.

    Returns:
        True only for public defined nlist entries.

    """
    if kind & 0xE0 or kind & 0x10:
        return False
    return bool(kind & 1) and kind & 0x0E in {N_ABS, N_SECT}


def _candidate_symbol_name(
    data: bytes | mmap.mmap,
    offset: int,
    string_table: tuple[int, int, int],
) -> str | None:
    """Decode an eligible public definition without trusting indirect symbols.

    Returns:
        A candidate name, or none for a private/non-definition entry.

    Raises:
        ValueError: Defined symbols point outside the bounded string table.

    """
    name_index, kind, section, _, _ = struct.unpack_from("<IBBHQ", data, offset)
    if not _is_public_definition(kind) or name_index == 0:
        return None
    definition = kind & 0x0E
    if definition == N_SECT and section == 0:
        raise ValueError(
            _InspectionIssue.DEFINED_SECTION_SYMBOL_HAS_NO_SECTION.value
        )
    strings, strings_end, string_bytes = string_table
    if name_index >= string_bytes:
        raise ValueError(
            _InspectionIssue.SYMBOL_NAME_EXCEEDS_MACH_O_STRING_TABLE.value
        )
    return cstring(data, strings + name_index, strings_end)


def _read_symbol_table(
    data: bytes | mmap.mmap,
    symtab: _Symtab,
    result: _ImageInventory,
) -> None:
    """Retain only defined public global Mach-O nlist candidates."""
    offset, count, strings, string_bytes = symtab
    _ = checked_range(data, offset, count * EXPORT_TRIE_COMMAND_BYTES)
    _, strings_end = checked_range(data, strings, string_bytes)
    for index in range(count):
        entry = offset + index * EXPORT_TRIE_COMMAND_BYTES
        name = _candidate_symbol_name(
            data, entry, (strings, strings_end, string_bytes)
        )
        if name:
            result["symbols"][name] = "global_definition_candidate"


def image_inventory(
    data: bytes | mmap.mmap,
    header_offset: int,
) -> _ImageInventory:
    """Inventory symbols without treating an nlist as an export allowlist.

    Fileset child offsets are absolute within the supplied collection.
    No relocation, vtable, instruction or native code is processed.

    Returns:
        Candidate-only image and symbol metadata.

    """
    filetype, commands = _image_header(data, header_offset)
    result: _ImageInventory = {
        "uuid": None,
        "symbols": {},
        "entries": {},
        "exportTriePresent": False,
        "symbolEvidence": "defined_global_nlist_candidates",
        "filetype": filetype,
    }
    symtab = _scan_load_commands(data, result, commands)
    if symtab is not None:
        _read_symbol_table(data, symtab, result)
    return result


COLLECTION_FILE_LIMIT = 2 * 1024 * 1024 * 1024


def load_collection(
    path: Path,
) -> tuple[str, dict[str, object], dict[str, _ImageInventory]]:
    """Inventory one bounded regular fileset without following a leaf symlink.

    Returns:
        Its digest, candidate-only UUID metadata and child inventories.

    Raises:
        ValueError: A source is nonregular, oversized, too short or unstable.

    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(
                _InspectionIssue.COLLECTION_SOURCE_MUST_BE_A_REGULAR_FILE.value
            )
        if not MACHO_HEADER_BYTES <= before.st_size <= COLLECTION_FILE_LIMIT:
            raise ValueError(
                _InspectionIssue.COLLECTION_SOURCE_EXCEEDS_INSPECTION_LIMITS.value
            )
        with mmap.mmap(descriptor, 0, access=mmap.ACCESS_READ) as data:
            digest = hashlib.sha256(data).hexdigest()
            root = image_inventory(data, 0)
            if root["filetype"] != MH_FILESET:  # MH_FILESET
                raise ValueError(
                    _InspectionIssue.EXPECTED_A_MACH_O_FILESET_NOT_A_STANDALONE_IMAGE.value
                )
            images = {
                name: image_inventory(data, offset)
                for name, offset in root["entries"].items()
            }
            after = os.fstat(descriptor)
            initial = (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            current = (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            if initial != current:
                raise ValueError(
                    _InspectionIssue.COLLECTION_SOURCE_CHANGED_DURING_INSPECTION.value
                )
    finally:
        os.close(descriptor)
    return digest, {"collectionUUID": root["uuid"]}, images


def _decode_snapshot(data: bytes) -> object:
    return cast(
        "object",
        json.loads(
            data,
            object_pairs_hook=_unique_snapshot_pairs,
            parse_constant=_reject_snapshot,
        ),
    )


def _unique_snapshot_pairs(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _reject_snapshot(f"Duplicate reference JSON key: {key}")
        result[key] = value
    return result


def _is_object_mapping(value: object) -> TypeIs[dict[object, object]]:
    return isinstance(value, dict)


def _is_mapping(value: object) -> TypeIs[dict[str, object]]:
    return _is_object_mapping(value) and all(
        isinstance(key, str) for key in value
    )


def _is_object_list(value: object) -> TypeIs[list[object]]:
    return isinstance(value, list)


def _is_string_list(value: object) -> TypeIs[list[str]]:
    return _is_object_list(value) and all(
        isinstance(item, str) for item in value
    )


def _reject_snapshot(reason: str) -> Never:
    raise ValueError(reason)


def _snapshot_mapping(value: object, description: str) -> dict[str, object]:
    if not _is_mapping(value):
        _reject_snapshot(f"Expected dictionary with string keys: {description}")
    return value


def _snapshot_string_list(value: object, description: str) -> list[str]:
    if not _is_string_list(value):
        _reject_snapshot(f"Expected list of strings: {description}")
    return value


def _manifest_match(path: Path, digest: str) -> str | None:
    manifest_path = path.with_name("manifest.json")
    if not manifest_path.is_file():
        return None
    manifest = _snapshot_mapping(
        _decode_snapshot(read_kdk_file(path.parent, manifest_path.name)),
        "reference manifest",
    )
    records = _snapshot_mapping(
        manifest.get("files"), "reference manifest files"
    )
    expected = records.get(path.name)
    if expected is None:
        return None
    if not isinstance(expected, str) or digest != expected:
        _reject_snapshot("Retained reference does not match manifest hash")
    return expected


def _snapshot_image(value: object) -> dict[str, object]:
    image = _snapshot_mapping(value, "image record")
    symbols = _snapshot_mapping(image.get("symbols"), "image symbols")
    exports = _snapshot_string_list(image.get("exports"), "image exports")
    tables = _snapshot_mapping(image.get("tables", {}), "image tables")
    functions = _snapshot_mapping(image.get("functions", {}), "image functions")
    image_uuid = image.get("uuid")
    if image_uuid is not None and not isinstance(image_uuid, str):
        _reject_snapshot("Invalid snapshot image UUID")
    reported = set(exports)
    return {
        "uuid": image_uuid,
        "symbolEvidence": "retained_snapshot_reported_exports",
        "symbols": {
            symbol: "snapshot_reported_export"
            if symbol in reported
            else "snapshot_symbol_not_reported_export"
            for symbol in symbols.keys() | reported
        },
        "recordedTableNames": sorted(tables),
        "recordedFunctionNames": sorted(functions),
    }


def load_reference(
    path: Path,
) -> tuple[str, dict[str, object], dict[str, dict[str, object]]]:
    """Read a bounded offline snapshot without following symlinks.

    Returns:
        The content digest, contextual metadata and candidate-only inventory.

    Invalid snapshot or manifest evidence raises ValueError.

    """
    data = read_kdk_file(path.parent, path.name)
    digest = hashlib.sha256(data).hexdigest()
    reference = _snapshot_mapping(_decode_snapshot(data), "snapshot root")
    if reference.get("schemaVersion") != 1:
        _reject_snapshot("Unsupported reference schema")
    recorded_images = _snapshot_mapping(reference.get("images"), "images")
    images = {
        name: _snapshot_image(image) for name, image in recorded_images.items()
    }
    metadata: dict[str, object] = {
        "profile": reference.get("profile"),
        "kernelVersion": reference.get("kernelVersion"),
        "collectionUUID": reference.get("collectionUUID"),
        "manifestHashMatched": _manifest_match(path, digest) is not None,
    }
    return digest, metadata, images


def _fat_architectures(data: bytes) -> list[tuple[int, int, int]]:
    """Check every FAT32 slice, including non-x86 overlaps and alignment.

    Returns:
        CPU type, absolute offset and length for each bounded architecture.

    Raises:
        ValueError: The FAT header or any slice range is malformed.

    """
    _ = checked_range(data, 0, COMMAND_HEADER_BYTES)
    count = struct.unpack_from(">I", data, 4)[0]
    if not 1 <= count <= FAT_MAX_ARCHES:
        raise ValueError(_InspectionIssue.INVALID_FAT_ARCHITECTURE_COUNT.value)
    _ = checked_range(data, COMMAND_HEADER_BYTES, count * FAT_ARCH_BYTES)
    records: list[tuple[int, int, int]] = []
    for index in range(count):
        cpu, _, offset, size, align = struct.unpack_from(
            ">5I", data, COMMAND_HEADER_BYTES + index * FAT_ARCH_BYTES
        )
        _ = checked_range(data, offset, size)
        _verify_fat_slice(records, (offset, size, align), count)
        records.append((cpu, offset, size))
    return records


def _verify_fat_slice(
    records: list[tuple[int, int, int]],
    span: tuple[int, int, int],
    count: int,
) -> None:
    """Reject a FAT slice which overlaps metadata or another slice.

    Raises:
        ValueError: The slice is misaligned, malformed or overlaps metadata.

    """
    offset, size, align = span
    header_end = COMMAND_HEADER_BYTES + count * FAT_ARCH_BYTES
    if offset < header_end or align > FAT_MAX_ALIGNMENT:
        raise ValueError(
            _InspectionIssue.INVALID_FAT_SLICE_OFFSET_ALIGNMENT.value
        )
    if offset % (1 << align):
        raise ValueError(
            _InspectionIssue.INVALID_FAT_SLICE_OFFSET_ALIGNMENT.value
        )
    if any(
        offset < start + length and start < offset + size
        for _, start, length in records
    ):
        raise ValueError(_InspectionIssue.OVERLAPPING_FAT_SLICES.value)


def _select_fat_x86_64(data: bytes) -> bytes:
    """Select precisely one x86_64 candidate from validated FAT records.

    Returns:
        The exact selected x86_64 bytes.

    Raises:
        ValueError: The source contains zero or multiple matching slices.

    """
    selected = None
    for cpu, offset, size in _fat_architectures(data):
        if cpu != X86_64_CPU_TYPE:
            continue
        if selected is not None:
            raise ValueError(_InspectionIssue.AMBIGUOUS_X86_64_SLICES.value)
        selected = data[offset : offset + size]
    if selected is None:
        raise ValueError(_InspectionIssue.NO_X86_64_SLICE.value)
    return selected


def x86_slice(data: bytes) -> bytes:
    """Select a bounded x86_64 Mach-O slice without executing image code.

    Returns:
        The original thin image, or one matching FAT architecture span.

    Raises:
        ValueError: A source has an unknown image header type.

    """
    if data[:4] == MACHO_MAGIC_BYTES:
        return data
    if data[:4] != FAT_MAGIC_BYTES:
        raise ValueError(
            _InspectionIssue.EXPECTED_THIN_MACH_O_OR_BIG_ENDIAN_FAT_MAGIC.value
        )
    return _select_fat_x86_64(data)


KDK_FILE_LIMIT = 128 * 1024 * 1024
KDK_READ_CHUNK = 1024 * 1024


def _open_kdk_leaf(root: Path, parts: tuple[str, ...]) -> int:
    """Open a leaf relative to held no-follow directory descriptors.

    Returns:
        An owned descriptor; callers must close it.

    """
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    parent = os.open(root, directory_flags)
    try:
        for part in parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=parent)
            os.close(parent)
            parent = child
        return os.open(parts[-1], file_flags, dir_fd=parent)
    finally:
        os.close(parent)


def _bounded_kdk_bytes(descriptor: int) -> bytes:
    """Read and verify a held regular file before trusting its bytes.

    Returns:
        All bytes of a stable, bounded regular input.

    Raises:
        ValueError: The file is nonregular, oversized or changes on read.

    """
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_size > KDK_FILE_LIMIT:
        raise ValueError(
            _InspectionIssue.KDK_INPUT_MUST_BE_A_BOUNDED_REGULAR_FILE.value
        )
    result = _read_kdk_chunks(descriptor)
    after = os.fstat(descriptor)
    old = (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    new = (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    if old != new or len(result) != before.st_size:
        raise ValueError(
            _InspectionIssue.KDK_INPUT_CHANGED_DURING_INSPECTION.value
        )
    return result


def _read_kdk_chunks(descriptor: int) -> bytes:
    """Read up to the strict file limit without trusting the recorded size.

    Returns:
        Bounded raw bytes; caller rechecks the file identity and size.

    Raises:
        ValueError: The input grows beyond the byte limit during reading.

    """
    result = bytearray()
    while True:
        chunk = os.read(
            descriptor, min(KDK_READ_CHUNK, KDK_FILE_LIMIT + 1 - len(result))
        )
        if not chunk:
            break
        result.extend(chunk)
        if len(result) > KDK_FILE_LIMIT:
            raise ValueError(
                _InspectionIssue.KDK_INPUT_GREW_BEYOND_INSPECTION_LIMIT.value
            )
    return bytes(result)


def read_kdk_file(root: Path, relative: str) -> bytes:
    """Read a bounded regular file within root without following symlinks.

    Each path component is opened relative to a held directory descriptor.

    Returns:
        Validated bytes from an immutable-during-read snapshot.

    Raises:
        ValueError: The relative path or target file is not acceptable.

    """
    path = Path(relative)
    parts = path.parts
    if path.is_absolute() or not parts or any(p in {".", ".."} for p in parts):
        raise ValueError(
            _InspectionIssue.KDK_PATH_MUST_REMAIN_BELOW_THE_SELECTED_ROOT.value
        )
    descriptor = _open_kdk_leaf(root, parts)
    try:
        return _bounded_kdk_bytes(descriptor)
    finally:
        os.close(descriptor)


def _kdk_plist_mapping(data: bytes, label: str) -> dict[str, object]:
    """Validate arbitrary plist metadata at the decoded object boundary.

    Returns:
        A mapping with string keys and untrusted object values.

    Raises:
        ValueError: The supplied package metadata is not a dictionary.

    """
    # plistlib has an untyped return; validate its shape immediately below.
    decoded = cast("object", plistlib.loads(data))
    if not _is_mapping(decoded):
        message = f"KDK {label} is not a dictionary"
        raise ValueError(message)
    return decoded


def _kdk_pci_exports(
    read: Callable[[str], bytes],
    contents: str,
    image: _ImageInventory,
    *,
    details: dict[str, object],
) -> None:
    """Intersect packaged PCI export declarations with defined nlist symbols."""
    relative = contents + "Resources/config/IOPCIFamily.exports"
    exports = {
        line.strip()
        for line in read(relative).decode("utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    image["symbols"] = {
        name: "kdk_config_export_and_defined_global_nlist"
        if name in exports
        else "defined_global_nlist_candidate_only"
        for name in image["symbols"]
    }
    details["configExportListEntries"] = len(exports)


def _kdk_family(
    read: Callable[[str], bytes],
    family: str,
    metadata: _KdkMetadata,
    *,
    images: dict[str, _ImageInventory],
) -> None:
    """Record one family's static slice and metadata, without ABI approval.

    Raises:
        ValueError: Bundle identity or packaged image metadata is invalid.

    """
    contents = f"System/Library/Extensions/{family}.kext/Contents/"
    info = _kdk_plist_mapping(
        read(contents + "Info.plist"), "family Info.plist"
    )
    identifier = "com.apple.iokit." + family
    if info.get("CFBundleIdentifier") != identifier:
        raise ValueError(
            _InspectionIssue.UNEXPECTED_KDK_BUNDLE_IDENTIFIER.value
        )
    selected = x86_slice(read(contents + "MacOS/" + family))
    image = image_inventory(selected, 0)
    images[identifier] = image
    details: dict[str, object] = {
        "version": info.get("CFBundleVersion"),
        "compatibleVersion": info.get("OSBundleCompatibleVersion"),
        "dependencies": info.get("OSBundleLibraries"),
        "x86_64SliceSha256": hashlib.sha256(selected).hexdigest(),
        "x86_64SliceBytes": len(selected),
        "uuid": image["uuid"],
    }
    metadata["images"][identifier] = details
    if family == PCI_FAMILY:
        _kdk_pci_exports(read, contents, image, details=details)


def _kdk_kernel(
    read: Callable[[str], bytes],
    metadata: _KdkMetadata,
    images: dict[str, _ImageInventory],
) -> None:
    """Record an optional packaged kernel, rejecting other read errors."""
    try:
        kernel_data = read("System/Library/Kernels/kernel")
    except FileNotFoundError:
        # KDK packages may omit the standalone kernel. Never suppress any
        # other failure including symlink and malformed-file errors.
        return
    selected = x86_slice(kernel_data)
    image = image_inventory(selected, 0)
    images["com.apple.kernel"] = image
    metadata["images"]["com.apple.kernel"] = {
        "x86_64SliceSha256": hashlib.sha256(selected).hexdigest(),
        "x86_64SliceBytes": len(selected),
        "uuid": image["uuid"],
    }


def load_kdk(
    root: Path,
) -> tuple[None, _KdkMetadata, dict[str, _ImageInventory]]:
    """Read selected package files; never treat KDK files as loaded OS images.

    Returns:
        Package-only metadata and nlist candidates, not usable ABI proof.

    Invalid source metadata or image bounds propagate their errors.

    """
    files: dict[str, dict[str, int | str]] = {}

    def read(relative: str) -> bytes:
        data = read_kdk_file(root, relative)
        files[relative] = {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        return data

    version = _kdk_plist_mapping(
        read("System/Library/CoreServices/SystemVersion.plist"),
        "SystemVersion.plist",
    )
    metadata: _KdkMetadata = {
        "systemVersion": {
            key: version.get(key)
            for key in ("ProductName", "ProductVersion", "ProductBuildVersion")
        },
        "loadedImageProvenanceVerified": False,
        "files": files,
        "images": {},
    }
    images: dict[str, _ImageInventory] = {}
    for family in (PCI_FAMILY, "IO80211Family", "IOSkywalkFamily"):
        _kdk_family(read, family, metadata, images=images)
    _kdk_kernel(read, metadata, images)
    return None, metadata, images


def read_system_version(path: Path) -> tuple[bytes, str, str]:
    """Validate a supplied offline SystemVersion plist without following links.

    Returns:
        Original bounded bytes plus explicit OS version and build identifiers.

    Raises:
        ValueError: The plist is malformed or lacks required string metadata.

    """
    data = read_kdk_file(path.parent, path.name)
    # plistlib has an untyped return; validate its shape immediately below.
    decoded = cast("object", plistlib.loads(data))
    if not _is_mapping(decoded):
        raise ValueError(
            _InspectionIssue.SYSTEMVERSION_PLIST_MUST_CONTAIN_A_DICTIONARY.value
        )
    version = decoded
    product = version.get("ProductVersion")
    build = version.get("ProductBuildVersion")
    if not isinstance(product, str) or not isinstance(build, str):
        _reject_snapshot(
            _InspectionIssue.SYSTEMVERSION_PLIST_REQUIRES_VERSION_BUILD_STRINGS.value
        )
    if not product or not build:
        raise ValueError(
            _InspectionIssue.SYSTEMVERSION_PLIST_HAS_EMPTY_VERSION_BUILD_FIELDS.value
        )
    return data, product, build


def _inventory_groups(
    images: dict[str, _ImageInventory] | dict[str, dict[str, object]],
) -> dict[str, object]:
    """Project candidate symbols into four explicit ABI evidence families.

    Returns:
        Candidate-only group metadata, never a native interface approval.

    """
    groups: dict[str, object] = {}
    for label, (image_name, classes) in GROUPS.items():
        image = images.get(image_name)
        if image is None:
            groups[label] = {
                "image": image_name,
                "state": "image_not_in_supplied_evidence",
            }
            continue
        symbol_map = _snapshot_mapping(image["symbols"], "image symbols")
        symbols = {
            name: evidence
            for name, evidence in sorted(symbol_map.items())
            if any(class_name in name for class_name in classes)
        }
        groups[label] = {
            "image": image_name,
            "uuid": image["uuid"],
            "state": "symbol_inventory_only",
            "symbols": symbols,
            "symbolEvidence": image["symbolEvidence"],
            "exportTriePresent": image.get("exportTriePresent"),
            "recordedTableNames": image.get("recordedTableNames"),
            "recordedFunctionNames": image.get("recordedFunctionNames"),
        }
    return groups


def _supplied_version(path: Path | None) -> dict[str, object] | None:
    """Keep caller-supplied OS metadata clearly unpaired from collection.

    Returns:
        Optional static metadata with an explicit unverified pairing state.

    """
    if path is None:
        return None
    data, product, build = read_system_version(path)
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "version": product,
        "build": build,
        "pairedToCollectionVerified": False,
    }


_LIMITATION_PARTS: tuple[tuple[str, ...], ...] = (
    ("Missing images mean missing evidence, not missing OS APIs.",),
    (
        "Nlist definitions are candidates, not a verified KPI export",
        "allowlist.",
    ),
    (
        "Export tries, reexports and KPI dependency/version eligibility",
        "are not resolved.",
    ),
    (
        "No C++ class size, vtable, selector, key-path or",
        "packet-lifetime contract is proven.",
    ),
    (
        "A supplied SystemVersion plist is not proof of collection",
        "provenance or pairing.",
    ),
    (
        "KDK files/export lists are package evidence, not attested",
        "loaded production images.",
    ),
    (
        "No source compilation, Mach-O import/relocation validation,",
        "load or hardware test is performed.",
    ),
)


def inventory(
    path: Path,
    *,
    reference_mode: bool,
    system_version: Path | None = None,
    kdk_mode: bool = False,
) -> dict[str, object]:
    """Inventory only supplied offline Mach-O, KDK or retained reference.

    Returns:
        A JSON-compatible, deliberately unverified ABI candidate report.

    """
    if kdk_mode:
        digest, metadata, images = load_kdk(path)
    else:
        digest, metadata, images = (
            load_reference(path) if reference_mode else load_collection(path)
        )
    return {
        "schemaVersion": 1,
        "source": str(path),
        "sha256": digest,
        "sourceKind": "extracted_kdk_files"
        if kdk_mode
        else "retained_reference"
        if reference_mode
        else "provided_collection",
        "metadata": metadata,
        "suppliedSystemVersion": _supplied_version(system_version),
        "imageNames": sorted(images),
        "groups": _inventory_groups(images),
        "nativePciAbiVerified": False,
        "nativeWirelessAbiVerified": False,
        "limitations": [" ".join(parts) for parts in _LIMITATION_PARTS],
    }


def _parsed_path(args: argparse.Namespace, name: str) -> Path | None:
    """Validate typed pathlib values returned by argparse's dynamic namespace.

    Returns:
        One optional, already-parsed path.

    Raises:
        TypeError: An option yielded an unsupported type.

    """
    raw = cast("object", getattr(args, name))
    if raw is None or isinstance(raw, Path):
        return raw
    message = f"Unexpected CLI path value for {name}"
    raise TypeError(message)


def _cli_inventory(args: argparse.Namespace) -> dict[str, object]:
    """Validate all untyped CLI inputs before reading package evidence.

    Returns:
        An offline report for the selected bounded source.

    Raises:
        ValueError: No source option was supplied.

    """
    reference = _parsed_path(args, "reference")
    collection = _parsed_path(args, "collection")
    kdk_root = _parsed_path(args, "kdk_root")
    system_version = _parsed_path(args, "system_version")
    selected = reference or collection or kdk_root
    if selected is None:
        raise ValueError(_InspectionIssue.MISSING_OFFLINE_ABI_SOURCE.value)
    return inventory(
        selected,
        reference_mode=reference is not None,
        system_version=system_version,
        kdk_mode=kdk_root is not None,
    )


def main() -> None:
    """Print candidate-only offline ABI evidence for bounded inputs."""
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    _ = inputs.add_argument(
        "--reference", type=Path, help="retained native ABI JSON reference"
    )
    _ = inputs.add_argument(
        "--collection", type=Path, help="already acquired x86_64 kernel fileset"
    )
    _ = inputs.add_argument(
        "--kdk-root",
        type=Path,
        help=(
            "already extracted KDK root containing System/Library; "
            "no install/mount"
        ),
    )
    _ = parser.add_argument(
        "--system-version",
        type=Path,
        help="optional already acquired SystemVersion.plist",
    )
    args = parser.parse_args()
    try:
        result = _cli_inventory(args)
    except (OSError, ValueError, KeyError, TypeError, struct.error) as error:
        parser.exit(2, f"Static ABI inventory failed: {error}\n")
    _ = sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
