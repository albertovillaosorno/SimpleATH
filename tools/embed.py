#!/usr/bin/env python3
#
#  embed.py
#  SimpleATH
#
#  Created by laobamac on 2026/11/1.
#  Copyright © 2026 laobamac. All rights reserved.
#

"""Generate bounded offline legacy payload metadata for native verification."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from itertools import pairwise
import json
import plistlib
import re
import shutil
import struct
import subprocess  # ruff: ignore[suspicious-subprocess-import] - Fixed argv for pinned offline disassembly.
import sys
from typing import TYPE_CHECKING
from typing import TypeIs
from typing import TypedDict

if TYPE_CHECKING:
    from collections.abc import Callable
    from collections.abc import Iterable
    from pathlib import Path

    from embed_macho_parser import LoadCommand
    from embed_macho_parser import ParsedSymbol

from abi_types import string
from abi_types import unpack_integers
from bootstrap import ROOT
from bootstrap import validate_payloads
from embed_macho_parser import parse
from embed_payload_codec import align
from embed_payload_codec import checksum
from embed_payload_codec import payload_delta
from macho import Image
from native_payload import SkywalkPlan
from native_payload import emit_system_profiles
from native_payload import prepare_native_guards
from profiles import HARDWARE_VERSION_SYMBOL
from profiles import IMAGES
from profiles import ROUTE_SYMBOLS
from profiles import SYMBOLS
from system_profiles import SYSTEMS
from verification_runtime import require_assertions_active

OUTPUT = ROOT / "build/Embedded"
LABEL_LEGACY = "Legacy"
LABEL_AIRPORT_ORIGINAL = "AirPortOriginal"
LABEL_AIRPORT = "AirPort"
LABELS = [LABEL_LEGACY, LABEL_AIRPORT_ORIGINAL, LABEL_AIRPORT]
VERSION = "1.2.0"
ALIASES = {
    "__ZN26IOSkywalkEthernetInterface18getHardwareAddressEP12ether_addr_t": (
        "__ZN26IOSkywalkEthernetInterface18getHardwareAddressEP10ether_addr"
    ),
    "__ZN26IOSkywalkEthernetInterface19setLinkLayerAddressEP12ether_addr_t": (
        "__ZN26IOSkywalkEthernetInterface19setLinkLayerAddressEP10ether_addr"
    ),
    (
        "__ZN26IOSkywalkEthernetInterface21setMulticastAddresses"
        "EPK12ether_addr_tj"
    ): (
        "__ZN26IOSkywalkEthernetInterface21setMulticastAddresses"
        "EPK10ether_addrj"
    ),
}


MAX_EMBED_RELOCATIONS = 1_000_000
MAX_EXPANDED_PAYLOAD_BYTES = 256 * 1024 * 1024
RELOCATION_RECORD_BYTES = 8
DYSYMTAB_COMMAND = 0xB
DYSYMTAB_COMMAND_BYTES = 80
MACH_LC_SEGMENT_64 = 0x19
MACH_LC_SYMTAB = 2
SYMBOL_TYPE_MASK = 0xF
SYMBOL_DEFINED_MASK = 0xE
SYMBOL_UNDEFINED_TYPE = 1
SKYWALK_NAME_MARKER = "IOSkywalk"
ABSOLUTE_RELOCATION_KIND = 0
BRANCH_RELOCATION_KIND = 2
RELOCATION_QWORD_BYTES = 8
RELOCATION_DWORD_BYTES = 4
VALID_RELOCATION_SHAPES = {
    (ABSOLUTE_RELOCATION_KIND, RELOCATION_QWORD_BYTES, 0),
    (BRANCH_RELOCATION_KIND, RELOCATION_DWORD_BYTES, 1),
}
ROUTE_MIN_BYTES = 14
ROUTE_MAX_BYTES = 32
ROUTE_RELATIVE_ADDRESS = "%rip"
ROUTE_DISASSEMBLY_LINE = re.compile(
    r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(.*)"
)
ROUTE_CONTROL_TRANSFER = re.compile(r"(j\w*|call\w*|ret\w*|loop\w*)\b")


class _PayloadStorage(TypedDict):
    """Source-side storage evidence for an emitted payload."""

    kind: str
    base: str
    file: str
    storedSize: int
    deltaRecords: int
    storedSHA256: str
    tables: list[str]


class _PayloadRecord(TypedDict):
    """Structured source and encoding metadata for a payload."""

    label: str
    identifier: str
    sourceSHA256: str
    expandedSHA256: str
    size: int
    mappedSize: int
    relocations: int
    routes: list[tuple[int, int]]
    kmodOffset: int
    namespacedClassStrings: dict[str, list[int]]
    powerDomainPatches: list[int]
    storage: _PayloadStorage


def _object_dictionary(value: object) -> TypeIs[dict[object, object]]:
    """Narrow a plist value to a generic mapping without dropping binary data.

    Returns:
        True when the input is a dictionary.

    """
    return isinstance(value, dict)


def _string_dictionary(value: object) -> TypeIs[dict[str, object]]:
    """Check dictionary key types without discarding valid plist values.

    Returns:
        True when every key is a string.

    """
    return _object_dictionary(value) and all(
        isinstance(key, str) for key in value
    )


def _decode_plist(data: bytes, decoder: Callable[[bytes], object]) -> object:
    """Decode a plist through a typed boundary preserving binary values.

    Returns:
        The original supported plist value.

    """
    return decoder(data)


def checked_info_plist(
    data: bytes,
) -> tuple[dict[str, object], str, dict[str, str]]:
    """Read a source bundle's required identity and dependency fields.

    Returns:
        Original plist values, bundle identifier and string dependencies.

    Raises:
        ValueError: Required fields are not string-valued plist records.

    """
    document = _decode_plist(data, plistlib.loads)
    if not _string_dictionary(document):
        message = "Embedded Info.plist must be a string-keyed dictionary"
        raise ValueError(message)
    identifier = string(document["CFBundleIdentifier"])
    libraries = document["OSBundleLibraries"]
    if not _string_dictionary(libraries):
        message = "Embedded OSBundleLibraries must be a dictionary"
        raise ValueError(message)
    return (
        document,
        identifier,
        {library: string(version) for library, version in libraries.items()},
    )


def require_embed(*, condition: bool, message: str) -> None:
    """Reject a violated generation invariant independently of -O mode.

    Raises:
        ValueError: Input cannot safely produce an embedded artifact.

    """
    if not condition:
        raise ValueError(message)


def checked_relocation_entries(
    data: bytes, offset: int, count: int, *, symbol_count: int
) -> list[tuple[int, int]]:
    """Check an entire Mach-O relocation span before consuming entries.

    Returns:
        The validated signed relocation addresses and encoded bit fields.

    """
    _require_relocation_span(data, offset, count, symbol_count=symbol_count)
    return [
        _decode_relocation(
            data,
            offset + i * RELOCATION_RECORD_BYTES,
            symbol_count=symbol_count,
        )
        for i in range(count)
    ]


def _require_relocation_span(
    data: bytes, offset: int, count: int, *, symbol_count: int
) -> None:
    """Reject an invalid relocation offset, count or source span.

    Raises:
        ValueError: Checked relocation table bounds are inconsistent.

    """
    invalid_counts = min(offset, count, symbol_count) < 0
    oversized_count = count > MAX_EMBED_RELOCATIONS
    span_exceeds_data = offset > len(data)
    if not span_exceeds_data:
        span_exceeds_data = (
            count > (len(data) - offset) // RELOCATION_RECORD_BYTES
        )
    if invalid_counts or oversized_count or span_exceeds_data:
        message = "Mach-O relocation table exceeds checked source bounds"
        raise ValueError(message)


def _decode_relocation(
    data: bytes, offset: int, *, symbol_count: int
) -> tuple[int, int]:
    """Decode one bounded relocation address and external symbol index.

    Returns:
        The address and its encoded relocation bits.

    Raises:
        ValueError: The address or an external symbol index is invalid.

    """
    address, bits = struct.unpack_from("<iI", data, offset)
    if address < 0:
        message = "Negative Mach-O relocation address"
        raise ValueError(message)
    if bits & (1 << 27) and bits & 0xFFFFFF >= symbol_count:
        message = "Mach-O relocation symbol index is out of range"
        raise ValueError(message)
    return address, bits


def checked_relocation_width(bits: int, *, external: bool) -> int:
    """Decode a complete relocatable x86_64 payload record.

    Returns:
        The supported relocation width in bytes.

    Raises:
        ValueError: External-table ownership or relocation kind is unsafe.

    """
    kind = bits >> 28
    width = 1 << ((bits >> 25) & 3)
    pcrel = (bits >> 24) & 1
    stored_external = bool((bits >> 27) & 1)
    if stored_external != external or (kind, width, pcrel) not in (
        VALID_RELOCATION_SHAPES
    ):
        message = "Unsupported Mach-O relocation encoding or ownership"
        raise ValueError(message)
    if not external and kind != ABSOLUTE_RELOCATION_KIND:
        message = "Local Mach-O relocation cannot branch to an external symbol"
        raise ValueError(message)
    return width


def checked_dysymtab_fields(commands: list[LoadCommand]) -> tuple[int, ...]:
    """Require exactly one complete dynamic symbol table command.

    Returns:
        The 18 unsigned table offsets and counts for checked relocation reads.

    Raises:
        ValueError: The command is absent, duplicated or malformed.

    """
    tables = [raw for command, raw in commands if command == DYSYMTAB_COMMAND]
    if len(tables) != 1 or len(tables[0]) != DYSYMTAB_COMMAND_BYTES:
        message = "Expected exactly one complete Mach-O dynamic symbol table"
        raise ValueError(message)
    command, length = struct.unpack_from("<II", tables[0])
    if command != DYSYMTAB_COMMAND or length != DYSYMTAB_COMMAND_BYTES:
        message = "Malformed Mach-O dynamic symbol table header"
        raise ValueError(message)
    return struct.unpack_from("<18I", tables[0], 8)


def checked_segment_span(
    source_size: int, segment: tuple[str, int, int, int, int]
) -> tuple[int, int] | None:
    """Validate one source-backed Mach-O segment's file and VM extents.

    Returns:
        Nonempty virtual address range, or None for a zero-sized segment.

    Raises:
        ValueError: Segment metadata exceeds source or virtual image bounds.

    """
    _, address, virtual_size, fileoff, filesize = segment
    if min(address, virtual_size, fileoff, filesize) < 0:
        message = "Mach-O payload segment exceeds source bounds"
        raise ValueError(message)
    if filesize > virtual_size or fileoff > source_size:
        message = "Mach-O payload segment exceeds source bounds"
        raise ValueError(message)
    if filesize > source_size - fileoff:
        message = "Mach-O payload segment exceeds source bounds"
        raise ValueError(message)
    end = address + virtual_size
    if end > MAX_EXPANDED_PAYLOAD_BYTES:
        message = "Mach-O payload image exceeds checked virtual limit"
        raise ValueError(message)
    return (address, end) if virtual_size else None


def checked_payload_size(
    data: bytes, segments: list[tuple[str, int, int, int, int]]
) -> int:
    """Bound the virtual memory image and every source segment before copy.

    Returns:
        The aligned allocation size, with all source bytes accounted for.

    Raises:
        ValueError: Missing, overlapping, truncated or oversized segments.

    """
    if not segments:
        message = "Mach-O payload has no segments"
        raise ValueError(message)
    mapped = _mapped_spans(data, segments)
    if not mapped:
        message = "Mach-O payload has no mapped virtual bytes"
        raise ValueError(message)
    mapped.sort()
    for earlier, following in pairwise(mapped):
        if earlier[1] > following[0]:
            message = "Mach-O payload segments overlap in virtual memory"
            raise ValueError(message)
    return align(max(end for _, end in mapped))


def _mapped_spans(
    data: bytes, segments: list[tuple[str, int, int, int, int]]
) -> list[tuple[int, int]]:
    """Collect already-bounded, nonempty virtual spans.

    Returns:
        Address pairs for nonempty source segments.

    """
    mapped: list[tuple[int, int]] = []
    for segment in segments:
        bounds = checked_segment_span(len(data), segment)
        if bounds is not None:
            mapped.append(bounds)
    return mapped


def remap_file_offset(
    offset: int, segments: list[tuple[str, int, int, int, int]]
) -> int:
    """Map a source file offset into its already parsed segment address.

    Returns:
        The address of the source byte in a mapped segment.

    Raises:
        RuntimeError: No mapped source segment contains the file offset.

    """
    for _, address, _, start, size in segments:
        if start <= offset < start + size:
            return address + offset - start
    message = f"Unmapped file offset {offset:#x}"
    raise RuntimeError(message)


def header(name: str) -> str:
    """Return the fixed attribution header for one generated source file.

    Returns:
        Header text for an offline generated source artifact.

    """
    return (
        "//\n"
        f"//  {name}\n"
        "//  SimpleATH\n"
        "//\n"
        "//  Created by laobamac on 2026/11/1.\n"
        "//  Copyright © 2026 laobamac. All rights reserved.\n"
        "//\n"
    )


def _route_instruction_bytes(line: str, end: int, name: str) -> int | None:
    """Check one disassembler line for a relocatable contiguous instruction.

    Returns:
        Complete instruction width, or None for non-instruction lines.

    Raises:
        RuntimeError: A malformed prefix would be unsafe to relocate.

    """
    match = ROUTE_DISASSEMBLY_LINE.match(line)
    if match is None:
        return None
    address = int(match[1], 16)
    if address != end:
        message = f"Non-contiguous route prefix: {name}"
        raise RuntimeError(message)
    instruction = match[3]
    if ROUTE_RELATIVE_ADDRESS in instruction or ROUTE_CONTROL_TRANSFER.match(
        instruction
    ):
        message = f"Non-relocatable route prefix: {name}: {instruction}"
        raise RuntimeError(message)
    return len(match[2].split())


def checked_route_prefix(text: str, name: str, start: int) -> int:
    """Decode and bound a relocatable prologue from disassembler text.

    Returns:
        The exact byte count of the first relocatable instruction prefix.

    Raises:
        RuntimeError: An unsafe, missing, or non-contiguous prefix.

    """
    end = start
    for line in text.splitlines():
        width = _route_instruction_bytes(line, end, name)
        if width is not None:
            end += width
            if end - start >= ROUTE_MIN_BYTES:
                break
    if not ROUTE_MIN_BYTES <= end - start <= ROUTE_MAX_BYTES:
        message = f"Invalid route prefix: {name}"
        raise RuntimeError(message)
    return end - start


def route_prefixes(image: Image, label: str) -> list[tuple[int, int]]:
    """Inspect fixed offline image routes through the Xcode disassembler.

    Returns:
        Symbol addresses and bounded relocatable prefix byte lengths.

    Raises:
        FileNotFoundError: The Xcode command driver is unavailable.
        Called prefix validation rejects unsafe disassembly text.

    """
    executable = shutil.which("xcrun")
    if executable is None:
        message = "Required offline Xcode disassembler driver is unavailable"
        raise FileNotFoundError(message)
    result: list[tuple[int, int]] = []
    for name in ROUTE_SYMBOLS[label]:
        text = subprocess.check_output(  # ruff: ignore[subprocess-without-shell-equals-true] - Explicit executable and fixed argv.
            [
                executable,
                "llvm-objdump",
                "--arch=x86_64",
                "-d",
                "--disassemble-symbols=" + name,
                str(image.path),
            ],
            text=True,
            shell=False,
        )
        start = image.symbols[name]
        result.append((start, checked_route_prefix(text, name, start)))
    return result


def _require_shared_profiles(plans: list[SkywalkPlan]) -> None:
    """Reject cross-release profile changes requiring distinct embeddings."""
    plan = plans[-1]
    for candidate in plans:
        for field in (
            "namespace",
            "compat",
            "methods",
            "method_slots",
            "native_names",
            "client_symbols",
            "packet_calls",
            "vptr_sites",
            "pool_meta",
            "pool_type",
            "power_template",
            "power_states",
        ):
            _require_profile_field(candidate, plan, field)
        for cls in ("IOSkywalkNetworkPacket", "AirPort_Brcm43xxSkywalkPacket"):
            _require_packet_table(candidate, plan, cls)


def _require_profile_field(
    candidate: SkywalkPlan, plan: SkywalkPlan, field: str
) -> None:
    """Enforce a native metadata field shared across profiles.

    Raises:
        ValueError: A source-side profile field has changed.

    """
    if getattr(candidate, field) != getattr(plan, field):
        message = f"Profiles require distinct {field}: {candidate.system}"
        raise ValueError(message)


def _require_packet_table(
    candidate: SkywalkPlan, plan: SkywalkPlan, cls: str
) -> None:
    """Enforce a shared packet implementation across profiles.

    Raises:
        ValueError: Packet implementation differs across releases.

    """
    if candidate.model.tables[cls] != plan.model.tables[cls]:
        message = "Packet implementation differs across systems: " + cls
        raise ValueError(message)


def vtable_class_name(name: str, suffix: str) -> str | None:
    """Match an exact mangled class-name field for a vtable.

    Returns:
        Its matching vtable symbol name, or None for an invalid field.

    """
    match = re.fullmatch(r"__ZN(\d+)(.*)" + suffix, name)
    if match is None or len(match[2]) != int(match[1]):
        return None
    return "__ZTV" + match[1] + match[2]


@dataclass(slots=True)
class _VtableContext:
    """Source-backed symbol and relocation lookup for one legacy image."""

    image: Image
    references: dict[int, ParsedSymbol]
    internal: set[str]
    boundaries: list[int]


def _parent_vtable(
    context: _VtableContext, name: str, address: int
) -> tuple[str, int, int] | None:
    """Find a source-backed child vtable with a genuine external parent.

    Returns:
        The parent's vtable name and the child's bounded slot interval.

    """
    child_name = vtable_class_name(name, "10superClassE")
    if child_name is None or address not in context.references:
        return None
    parent_name = vtable_class_name(
        context.references[address][0], "10gMetaClassE"
    )
    eligible = (
        parent_name is not None
        and child_name in context.image.symbols
        and parent_name not in context.internal
    )
    if (
        eligible
        and parent_name is not None
        and SKYWALK_NAME_MARKER not in parent_name
    ):
        start = context.image.symbols[child_name]
        end = min(value for value in context.boundaries if value > start)
        return parent_name, start, end
    return None


def _embedded_vtable_guards(
    image: Image,
    symbols: list[ParsedSymbol],
    fields: tuple[int, ...],
    *,
    internal: set[str],
) -> set[tuple[str, int, str]]:
    """Extract external method prerequisites of embedded legacy vtables.

    Returns:
        Parent symbols, slot offsets and unresolved external methods.

    """
    references: dict[int, ParsedSymbol] = {}
    for offset, bits in checked_relocation_entries(
        image.data, fields[14], fields[15], symbol_count=len(symbols)
    ):
        if bits >> 28 == 0:
            references[offset] = symbols[bits & 0xFFFFFF]
    context = _VtableContext(
        image, references, internal, sorted(set(image.symbols.values()))
    )
    guards: set[tuple[str, int, str]] = set()
    for name, address in image.symbols.items():
        parent = _parent_vtable(context, name, address)
        if parent is None:
            continue
        parent_name, start, end = parent
        guards.update(
            _vtable_slot_guards(references, parent_name, start, end=end)
        )
    return guards


def _vtable_slot_guards(
    references: dict[int, ParsedSymbol],
    parent: str,
    start: int,
    *,
    end: int,
) -> set[tuple[str, int, str]]:
    """Return the external child slots that need an inherited parent guard.

    Returns:
        Exact unresolved slots for the native ABI preflight.

    """
    guards: set[tuple[str, int, str]] = set()
    for slot in range(start + 16, end, 8):
        if slot not in references:
            continue
        method, kind, _, _, _ = references[slot]
        if kind & SYMBOL_DEFINED_MASK == 0 and method.startswith((
            "__ZN",
            "__ZNK",
        )):
            guards.add((parent, slot - start, method))
    return guards


@dataclass(slots=True)
class _NativeScan:
    """Parsed source image metadata for native symbol import collection."""

    images: list[Image]
    parsed: list[tuple[list[LoadCommand], list[ParsedSymbol]]]
    fields: list[tuple[int, ...]]
    exports: list[dict[str, int]]


def _undefined_imports(plan: SkywalkPlan, scan: _NativeScan) -> set[str]:
    """Resolve undeclared native symbols needed by the input payloads.

    Returns:
        Unresolved native symbols not provided by another input image.

    """
    unresolved: set[str] = set()
    for index, (_, symbols) in enumerate(scan.parsed):
        for name, kind, _, _, _ in symbols:
            if kind & SYMBOL_TYPE_MASK != SYMBOL_UNDEFINED_TYPE:
                continue
            resolved_name = ALIASES.get(name, name)
            if plan.resolve(resolved_name) is None and not (
                index and resolved_name in scan.exports[0]
            ):
                unresolved.add(resolved_name)
    return unresolved


def _native_import_catalog(
    plans: list[SkywalkPlan], scan: _NativeScan
) -> tuple[list[str], set[tuple[str, int, str]]]:
    """Collect all external native symbols and inherited vtable guards.

    Returns:
        Ordered imports and exact native vtable guard identities.

    """
    plan = plans[-1]
    native = set(plan.native_names) | prepare_native_guards(plans)
    vtable_guards: set[tuple[str, int, str]] = set()
    for index, (image, (_, symbols)) in enumerate(
        zip(scan.images, scan.parsed, strict=True)
    ):
        internal: set[str] = set(scan.exports[index])
        if index:
            internal.update(scan.exports[0])
        guards = _embedded_vtable_guards(
            image, symbols, scan.fields[index], internal=internal
        )
        vtable_guards.update(guards)
        for parent, _, method in guards:
            native.update((parent, method))
    native.update(_undefined_imports(plan, scan))
    return sorted(native), vtable_guards


@dataclass(slots=True)
class RelocationContext:
    """Checked source context for one legacy relocation table."""

    index: int
    image: Image
    symbols: list[ParsedSymbol]
    fields: tuple[int, ...]
    exports: list[dict[str, int]]
    plan: SkywalkPlan
    native_index: dict[str, int]


def checked_alias_name(
    context: RelocationContext, name: str, record: tuple[int, int, int]
) -> str:
    """Resolve a legacy alias only when its relocation matches its slot.

    Returns:
        The original symbol or a checked alternate mangling.

    """
    if name not in ALIASES:
        return name
    address, width, addend = record
    alias_index = list(ALIASES).index(name)
    expected = (
        context.image.symbols["__ZTV34AirPort_Brcm43xxLLSkywalkInterface"]
        + 16
        + 0xA70
        + alias_index * 16
    )
    require_embed(
        condition=address == expected
        and width == RELOCATION_QWORD_BYTES
        and addend == 0,
        message="Compatibility alias relocation is inconsistent",
    )
    return ALIASES[name]


def _external_target(
    context: RelocationContext, record: tuple[int, int, int, int]
) -> tuple[int, int]:
    """Resolve only recorded source, compatibility or native symbols.

    Returns:
        The relocation provider and bounded destination offset/index.

    """
    address, bits, width, addend = record
    name, stype, _, _, value = context.symbols[bits & 0xFFFFFF]
    if stype & SYMBOL_DEFINED_MASK == SYMBOL_DEFINED_MASK:
        return int(context.index != 0), value
    require_embed(
        condition=stype & SYMBOL_DEFINED_MASK == 0 and value == 0,
        message="Undefined relocation symbol has invalid metadata",
    )
    name = checked_alias_name(context, name, (address, width, addend))
    if context.index and name in context.exports[0]:
        provider, target = 0, context.exports[0][name]
    elif (compatibility := context.plan.resolve(name)) is not None:
        provider, target = 254, compatibility
    else:
        provider, target = 255, context.native_index[name]
    return provider, target


def _checked_relocation_target(
    context: RelocationContext, provider: int, target: int
) -> None:
    """Ensure a resolved address cannot leave mapped provider bytes."""
    require_embed(
        condition=provider in {254, 255}
        or 0
        <= target
        < max(
            address + size for _, address, size, _, _ in context.image.segments
        ),
        message="Relocation target is outside mapped provider bounds",
    )


def image_relocations(
    context: RelocationContext,
) -> tuple[list[tuple[int, int, int, int, int]], int]:
    """Convert both checked Mach-O relocation tables to encoded records.

    Returns:
        Ordered encoded records and number of short branch stubs.

    """
    relocations: list[tuple[int, int, int, int, int]] = []
    branches = 0
    for external, field in ((True, 14), (False, 16)):
        for address, bits in checked_relocation_entries(
            context.image.data,
            context.fields[field],
            context.fields[field + 1],
            symbol_count=len(context.symbols),
        ):
            width = checked_relocation_width(bits, external=external)
            addend = unpack_integers(
                context.image.read(address, width),
                "<q" if width == RELOCATION_QWORD_BYTES else "<i",
            )[0]
            if external:
                provider, target = _external_target(
                    context, (address, bits, width, addend)
                )
            else:
                require_embed(
                    condition=0
                    < (bits & 0xFFFFFF)
                    <= len(context.image.sections),
                    message="Local relocation section index is invalid",
                )
                provider, target, addend = int(context.index != 0), addend, 0
            _checked_relocation_target(context, provider, target)
            relocations.append((address, target, addend, provider, width))
            branches += width == RELOCATION_DWORD_BYTES
    return relocations, branches


@dataclass(slots=True)
class CommandLayout:
    """Source and mapped image extents for the relocation-safe rewrite."""

    image: Image
    commands: list[LoadCommand]
    symbols: list[ParsedSymbol]
    size: int
    stub_size: int


def _remap_segment_sections(image: Image, data: bytearray) -> None:
    """Remap only backed Mach-O sections with no section relocations."""
    address = struct.unpack_from("<Q", data, 24)[0]
    struct.pack_into("<Q", data, 40, address)
    count = struct.unpack_from("<I", data, 64)[0]
    for index in range(count):
        position = 72 + index * 80
        offset, _, _, relocations = struct.unpack_from(
            "<4I", data, position + 48
        )
        require_embed(
            condition=relocations == 0,
            message="Unexpected section-local Mach-O relocations",
        )
        if offset:
            struct.pack_into(
                "<I",
                data,
                position + 48,
                remap_file_offset(offset, image.segments),
            )


def _remap_symbol_table(
    image: Image, data: bytearray, symbols: list[ParsedSymbol]
) -> list[int]:
    """Remap file-backed symbol and string table offsets.

    Returns:
        Virtual addresses of defined symbol value storage slots.

    """
    offset, _, strings, _ = struct.unpack_from("<4I", data, 8)
    struct.pack_into("<I", data, 8, remap_file_offset(offset, image.segments))
    struct.pack_into("<I", data, 16, remap_file_offset(strings, image.segments))
    return [
        remap_file_offset(offset + i * 16, image.segments) + 8
        for i, (_, kind, _, _, _) in enumerate(symbols)
        if not kind & 0xE0 and kind & SYMBOL_DEFINED_MASK == SYMBOL_DEFINED_MASK
    ]


def _remap_dynamic_table(image: Image, data: bytearray) -> None:
    """Remap preserved indirect metadata and clear consumed relocations."""
    fields = list(struct.unpack_from("<18I", data, 8))
    for position in (6, 8, 10, 12):
        if fields[position + 1]:
            fields[position] = remap_file_offset(
                fields[position], image.segments
            )
    fields[14:] = [0, 0, 0, 0]
    struct.pack_into("<18I", data, 8, *fields)


def _rewrite_load_command(
    layout: CommandLayout, command: int, data: bytearray
) -> list[int] | None:
    """Rebase one command, retaining updated symbol storage if present.

    Returns:
        Defined value offsets, or None for nonsymbol metadata commands.

    """
    if command == MACH_LC_SEGMENT_64:
        _remap_segment_sections(layout.image, data)
    elif command == MACH_LC_SYMTAB:
        return _remap_symbol_table(layout.image, data, layout.symbols)
    elif command == DYSYMTAB_COMMAND:
        _remap_dynamic_table(layout.image, data)
    return None


def _relocated_load_commands(
    layout: CommandLayout, expanded: bytearray
) -> list[int]:
    """Rebase selected Mach-O metadata within checked VM allocations.

    Returns:
        Virtual symbol-value storage offsets in the new mapped image.

    """
    symbol_values: list[int] = []
    new_commands: list[bytes | bytearray] = []
    for command, data in layout.commands:
        if command in {0x1D, 0x1E, 0x2B}:
            continue
        values = _rewrite_load_command(layout, command, data)
        if values is not None:
            symbol_values = values
        new_commands.append(data)
    new_commands.append(
        struct.pack(
            "<II16sQQQQiiII",
            0x19,
            72,
            b"__ATH_EXEC",
            layout.size,
            layout.stub_size,
            layout.size,
            layout.stub_size,
            7,
            5,
            0,
            0,
        )
    )
    commands = b"".join(new_commands)
    first_section = min(
        offset
        for _, _, _, count, offset in layout.image.sections
        if count and offset
    )
    require_embed(
        condition=32 + len(commands) <= first_section,
        message="Expanded load commands overlap the first section",
    )
    expanded[32:first_section] = b"\0" * (first_section - 32)
    expanded[32 : 32 + len(commands)] = commands
    struct.pack_into("<II", expanded, 16, len(new_commands), len(commands))
    struct.pack_into(
        "<I",
        expanded,
        24,
        struct.unpack_from("<I", expanded, 24)[0] & ~0x80000000,
    )
    return symbol_values


def expanded_legacy_image(
    layout: CommandLayout,
) -> tuple[bytearray, list[int]]:
    """Map validated segment bytes and rebase Mach-O command metadata.

    Returns:
        Expanded binary image and remapped defined-symbol storage slots.

    """
    expanded = bytearray(layout.size)
    for _, address, _, fileoff, length in layout.image.segments:
        expanded[address : address + length] = layout.image.data[
            fileoff : fileoff + length
        ]
    return expanded, _relocated_load_commands(layout, expanded)


@dataclass(slots=True)
class _GenerationPlan:
    """Preflighted native profiles and bounded Mach-O input metadata."""

    profiles: list[SkywalkPlan]
    images: list[Image]
    parsed: list[tuple[list[LoadCommand], list[ParsedSymbol]]]
    fields: list[tuple[int, ...]]
    sizes: list[int]
    exports: list[dict[str, int]]
    native: list[str]
    guards: set[tuple[str, int, str]]
    native_index: dict[str, int]


def _generation_plan() -> _GenerationPlan:
    """Reject all source image metadata before creating output paths.

    Returns:
        Checked source images, native symbols and compatible system profiles.

    """
    profiles = [SkywalkPlan(system) for system in SYSTEMS]
    _require_shared_profiles(profiles)
    images = [Image(IMAGES[label]) for label in LABELS]
    parsed = [parse(image) for image in images]
    fields = [checked_dysymtab_fields(commands) for commands, _ in parsed]
    sizes = [
        checked_payload_size(image.data, image.segments) for image in images
    ]
    exports = [
        {
            name: value
            for name, kind, _, _, value in symbols
            if kind & SYMBOL_TYPE_MASK == SYMBOL_TYPE_MASK
        }
        for _, symbols in parsed
    ]
    native, guards = _native_import_catalog(
        profiles, _NativeScan(images, parsed, fields, exports)
    )
    return _GenerationPlan(
        profiles,
        images,
        parsed,
        fields,
        sizes,
        exports,
        native,
        guards,
        {name: i for i, name in enumerate(native)},
    )


@dataclass(slots=True)
class _GeneratedOutput:
    """Ordered source output and deduplicated C++ tables for one generation."""

    cpp: list[str]
    assembly: list[str]
    descriptors: list[str]
    expanded_images: list[bytes]
    tables: dict[tuple[str, tuple[str, ...]], str]
    records: list[_PayloadRecord]
    manifest: dict[str, object]
    library_versions: dict[str, set[str]]
    library_ids: set[str]

    def emit_table(self, kind: str, name: str, rows: Iterable[str]) -> str:
        """Intern identical generated C++ tables without changing ordering.

        Returns:
            Existing or new table name for the same type and rows.

        """
        key = (kind, tuple(rows))
        if key not in self.tables:
            self.cpp.append(f"static const {kind} {name}[] = {{")
            self.cpp.extend(row + "," for row in key[1])
            self.cpp.append("};")
            self.tables[key] = name
        return self.tables[key]


def _generated_output(plan: _GenerationPlan) -> _GeneratedOutput:
    """Create a generation sink with the original manifest field ordering.

    Returns:
        Blank source buffers and the source-only manifest declaration.

    """
    native_adapter = plan.profiles[-1].manifest()
    manifest: dict[str, object] = {
        "version": VERSION,
        "nativeImports": plan.native,
        "payloads": [],
        "driverLoading": "embedded",
        "hardwareValidation": "not-run-by-build",
        "skywalkBackend": "native",
        "nativeAdapter": native_adapter,
        "systemProfiles": [candidate.manifest() for candidate in plan.profiles],
    }
    for field in (
        "system",
        "kernel",
        "build",
        "nativeUUID",
        "wirelessUUID",
        "ethernetSize",
        "poolSize",
        "nativeSlotCount",
        "ethernetLinkSymbol",
        "ethernetLinkSlot",
        "airPortPayloadIndex",
    ):
        del native_adapter[field]
    records: list[_PayloadRecord] = []
    manifest["payloads"] = records
    return _GeneratedOutput(
        [
            header("Payloads.cpp"),
            '#include "Payload.hpp"',
            '#include "NativeProfile.hpp"',
            "namespace ath {",
        ],
        [header("Payloads.S"), ".section __TEXT,__const", ".p2align 3"],
        [],
        [],
        {},
        records,
        manifest,
        {},
        set(),
    )


@dataclass(slots=True)
class _RelocatedPayload:
    """Preflighted relocation records and mapped legacy image bytes."""

    relocations: list[tuple[int, int, int, int, int]]
    size: int
    stub_size: int
    expanded: bytearray
    symbol_values: list[int]


def _relocated_payload(plan: _GenerationPlan, index: int) -> _RelocatedPayload:
    """Map a single validated source image with bounded relocations.

    Returns:
        Relocations, load-command symbol offsets and expanded source bytes.

    """
    commands, symbols = plan.parsed[index]
    relocations, branches = image_relocations(
        RelocationContext(
            index,
            plan.images[index],
            symbols,
            plan.fields[index],
            plan.exports,
            plan.profiles[-1],
            plan.native_index,
        )
    )
    size = plan.sizes[index]
    stub_size = align(branches * 16 + 4096)
    expanded, symbol_values = expanded_legacy_image(
        CommandLayout(plan.images[index], commands, symbols, size, stub_size)
    )
    return _RelocatedPayload(
        relocations, size, stub_size, expanded, symbol_values
    )


@dataclass(slots=True)
class _PreparedPayload:
    """One checked legacy image and its source bundle identity."""

    index: int
    label: str
    image: Image
    info: dict[str, object]
    identifier: str
    libraries: dict[str, str]
    relocated: _RelocatedPayload
    kmod: int
    renamed: dict[str, list[int]]
    routes: list[tuple[int, int]]
    source_sha: str


def _prepared_payload(plan: _GenerationPlan, index: int) -> _PreparedPayload:
    """Prepare one native-namespaced image before encoding output.

    Returns:
        Source identity, mapped bytes, routes and checked kmod offset.

    """
    image = plan.images[index]
    label = LABELS[index]
    info, identifier, libraries = checked_info_plist(
        (image.path.parent.parent / "Info.plist").read_bytes()
    )
    relocated = _relocated_payload(plan, index)
    kmod = image.symbols["_kmod_info"]
    require_embed(
        condition=kmod + 196 <= relocated.size,
        message="Embedded kmod structure exceeds mapped image size",
    )
    renamed = (
        plan.profiles[0]
        if label == LABEL_AIRPORT_ORIGINAL
        else plan.profiles[-1]
    ).namespace_payload(label, relocated.expanded)
    routes = route_prefixes(image, label)
    source_sha = hashlib.sha256(image.path.read_bytes()).hexdigest()
    return _PreparedPayload(
        index,
        label,
        image,
        info,
        identifier,
        libraries,
        relocated,
        kmod,
        renamed,
        routes,
        source_sha,
    )


@dataclass(slots=True)
class _StoredPayload:
    """Output storage metadata for a full or shared-base delta image."""

    base_index: int
    delta: bytes
    delta_count: int
    stored: bytes | bytearray
    stored_blob: Path


def _store_payload(
    output: _GeneratedOutput, payload: _PreparedPayload
) -> _StoredPayload:
    """Store a mapped image and its delta, keeping original blob ordering.

    Returns:
        Source and stored blob metadata for the emitted descriptor.

    """
    blob = OUTPUT / (payload.label + ".bin")
    _ = blob.write_bytes(payload.relocated.expanded)
    output.expanded_images.append(bytes(payload.relocated.expanded))
    base_index = 1 if payload.label == LABEL_AIRPORT else payload.index
    delta, delta_count = (
        payload_delta(
            output.expanded_images[base_index], payload.relocated.expanded
        )
        if payload.label == LABEL_AIRPORT
        else (b"", 0)
    )
    stored = (
        delta if payload.label == LABEL_AIRPORT else payload.relocated.expanded
    )
    stored_blob = (
        OUTPUT / (payload.label + ".delta")
        if payload.label == LABEL_AIRPORT
        else blob
    )
    if payload.label == LABEL_AIRPORT:
        _ = stored_blob.write_bytes(stored)
    output.assembly += [
        f".globl _athPayload{payload.index}",
        f"_athPayload{payload.index}:",
        f'.incbin "{stored_blob}"',
        ".p2align 3",
    ]
    output.cpp.append(f'extern "C" const uint8_t athPayload{payload.index}[];')
    return _StoredPayload(base_index, delta, delta_count, stored, stored_blob)


@dataclass(slots=True)
class _PayloadTables:
    """Names and recorded lengths of C++ lookup tables for a payload."""

    relocations: str
    values: str
    symbols: str
    routes: str
    symbol_count: int


def _emit_payload_tables(
    output: _GeneratedOutput, payload: _PreparedPayload
) -> _PayloadTables:
    """Intern relocations, mapped symbol slots and source route tables.

    Returns:
        Table identifiers and symbol count used by the C++ payload record.

    """
    index = payload.index
    relocated = payload.relocated
    relocation_table = output.emit_table(
        "Relocation",
        f"relocs{index}",
        (
            f"{{{a}, {t}, {v}LL, {p}, {w}, {{}}}}"
            for a, t, v, p, w in relocated.relocations
        ),
    )
    value_table = output.emit_table(
        "uint32_t", f"values{index}", map(str, relocated.symbol_values)
    )
    wanted = set(SYMBOLS[payload.label]) | {"_kmod_info"}
    if payload.label != LABEL_LEGACY:
        wanted.add(HARDWARE_VERSION_SYMBOL)
    named = sorted((n, payload.image.symbols[n]) for n in wanted)
    symbol_table = output.emit_table(
        "Symbol",
        f"symbols{index}",
        (f"{{{json.dumps(n)}, {v}}}" for n, v in named),
    )
    route_table = output.emit_table(
        "RoutePrefix",
        f"routes{index}",
        (f"{{{a}, {n}}}" for a, n in payload.routes or [(0, 0)]),
    )
    return _PayloadTables(
        relocation_table, value_table, symbol_table, route_table, len(named)
    )


def _payload_plist(output: _GeneratedOutput, payload: _PreparedPayload) -> None:
    """Embed a copied source plist with the original native bundle flags."""
    payload.libraries["dev.alberto.SimpleATH"] = VERSION
    payload.info["OSBundleLibraries"] = payload.libraries
    payload.info["OSBundleRequired"] = "Root"
    if payload.label == LABEL_LEGACY:
        payload.info["IOKitPersonalities"] = {}
    plist = plistlib.dumps(payload.info, sort_keys=False).decode()
    literal = json.dumps(plist).replace("?", "\\?")
    output.cpp.append(f"static const char plist{payload.index}[] = {literal};")


def _payload_descriptor(
    output: _GeneratedOutput,
    payload: _PreparedPayload,
    stored: _StoredPayload,
    *,
    tables: _PayloadTables,
) -> str:
    """Emit the original ordered C++ descriptor declaration.

    Returns:
        Complete descriptor text without a trailing separator.

    """
    index = payload.index
    size = payload.relocated.size
    # Match ath::Payload's deliberately pointer-first in-memory field order.
    # The manifest stays keyed and unchanged; no serialized ABI is altered.
    return "".join([
        f'{{{json.dumps(payload.identifier)}, "{payload.source_sha}", ',
        f"athPayload{stored.base_index}, ",
        f"{"athPayload" + str(index) if stored.delta else "nullptr"}, ",
        f"plist{index}, {tables.relocations}, {tables.values}, ",
        f"{tables.symbols}, {tables.routes}, ",
        f"{checksum(payload.relocated.expanded)}ULL, ",
        f"{len(output.expanded_images[stored.base_index])}, ",
        f"{len(stored.delta)}, {size}, ",
        f"{size + payload.relocated.stub_size}, {size}, ",
        f"{payload.relocated.stub_size}, {payload.kmod}, ",
        f"{len(payload.relocated.relocations)}, ",
        f"{len(payload.relocated.symbol_values)}, ",
        f"{tables.symbol_count}, {len(payload.routes)}}}",
    ])


def _payload_record(
    payload: _PreparedPayload,
    stored: _StoredPayload,
    tables: _PayloadTables,
) -> _PayloadRecord:
    """Describe expanded and delta bytes without asserting hardware readiness.

    Returns:
        Exact manifest record for this payload.

    """
    return {
        "label": payload.label,
        "identifier": payload.identifier,
        "sourceSHA256": payload.source_sha,
        "expandedSHA256": hashlib.sha256(
            payload.relocated.expanded
        ).hexdigest(),
        "size": payload.relocated.size,
        "mappedSize": payload.relocated.size + payload.relocated.stub_size,
        "relocations": len(payload.relocated.relocations),
        "routes": payload.routes,
        "kmodOffset": payload.kmod,
        "namespacedClassStrings": payload.renamed,
        "powerDomainPatches": [],
        "storage": {
            "kind": "delta" if payload.label == LABEL_AIRPORT else "full",
            "base": LABELS[stored.base_index],
            "file": stored.stored_blob.name,
            "storedSize": len(stored.stored),
            "deltaRecords": stored.delta_count,
            "storedSHA256": hashlib.sha256(stored.stored).hexdigest(),
            "tables": [
                tables.relocations,
                tables.values,
                tables.symbols,
                tables.routes,
            ],
        },
    }


def _emit_payload(
    plan: _GenerationPlan, output: _GeneratedOutput, index: int
) -> None:
    """Produce one source-checked embedded image and its metadata."""
    payload = _prepared_payload(plan, index)
    output.library_ids.add(payload.identifier)
    for library, version in payload.libraries.items():
        output.library_versions.setdefault(library, set()).add(version)
    stored = _store_payload(output, payload)
    tables = _emit_payload_tables(output, payload)
    _payload_plist(output, payload)
    output.descriptors.append(
        _payload_descriptor(output, payload, stored, tables=tables)
    )
    output.records.append(_payload_record(payload, stored, tables))


def _finalize_source(plan: _GenerationPlan, output: _GeneratedOutput) -> None:
    """Write C++ and assembly payload tables in original link order."""
    output.cpp += [
        "const Payload payloads[3] = {",
        ",\n".join(output.descriptors),
        "};",
        f"const uint32_t nativeImportCount = {len(plan.native)};",
        "const char *const nativeImportNames[] = {",
        ",\n".join(json.dumps(n) for n in plan.native),
        "};",
        "const NativeVtableGuard nativeVtableGuards[] = {",
        ",\n".join(
            f"{{{plan.native_index[p]}, {o}, {plan.native_index[m]}}}"
            for p, o, m in sorted(plan.guards)
        ),
        "};",
        f"const uint32_t nativeVtableGuardCount = {len(plan.guards)};",
    ]
    sky_cpp, sky_assembly = plan.profiles[-1].emit(plan.native_index)
    output.cpp += (
        sky_cpp + emit_system_profiles(plan.profiles, plan.native_index) + ["}"]
    )
    output.assembly += [
        ".section __DATA_CONST,__const",
        ".p2align 3",
        ".globl _athNativeImports",
        "_athNativeImports:",
    ]
    output.assembly.extend(".quad " + name for name in plan.native)
    output.assembly += sky_assembly
    _ = (OUTPUT / "Payloads.cpp").write_text("\n".join(output.cpp) + "\n")
    _ = (OUTPUT / "Payloads.S").write_text("\n".join(output.assembly) + "\n")


def _finalize_manifest(plan: _GenerationPlan, output: _GeneratedOutput) -> None:
    """Write source-only import and runtime guard evidence as JSON."""
    expanded_size = sum(len(data) for data in output.expanded_images)
    stored_size = sum(p["storage"]["storedSize"] for p in output.records)
    output.manifest["payloadStorage"] = {
        "format": "shared-base-delta-v1",
        "expandedBytes": expanded_size,
        "storedBytes": stored_size,
        "savedBytes": expanded_size - stored_size,
    }
    output.manifest["nativeLibraries"] = {
        name: sorted(versions)
        for name, versions in output.library_versions.items()
        if name not in output.library_ids
    }
    output.manifest["nativeVtableGuards"] = sorted(plan.guards)
    output.manifest["nativeRuntimeGuards"] = {
        profile.system: {
            "vtables": profile.vtable_guards,
            "classes": profile.class_guards,
            "nativeOverrides": profile.unchecked_overrides,
            "linkBytes": profile.link_bytes.hex(),
            "linkMask": profile.link_mask.hex(),
            "linkReferences": profile.link_references,
        }
        for profile in plan.profiles
    }
    _ = (OUTPUT / "manifest.json").write_text(
        json.dumps(output.manifest, indent=2) + "\n"
    )


def generate() -> None:
    """Generate checked offline source metadata for pinned legacy payloads."""
    require_assertions_active()
    validate_payloads()
    plan = _generation_plan()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    output = _generated_output(plan)
    for index in range(len(plan.images)):
        _emit_payload(plan, output, index)
    _finalize_source(plan, output)
    _finalize_manifest(plan, output)
    _ = sys.stdout.write(
        "".join((
            f"Embedded {len(plan.images)} payloads, ",
            f"{len(plan.native)} native imports; output: {OUTPUT}\n",
        ))
    )


if __name__ == "__main__":
    generate()
