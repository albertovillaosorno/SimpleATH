#!/usr/bin/env python3
#
#  profiles.py
#  SimpleATH
#
#  Created by laobamac on 2026/9/18.
#  Copyright © 2026 laobamac. All rights reserved.
#

"""Verify pinned legacy binary profiles for offline reference generation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
from typing import Never
from typing import NotRequired
from typing import TYPE_CHECKING
from typing import TypedDict

if TYPE_CHECKING:
    from collections.abc import Iterator

if __package__:
    from tools.abi_types import unpack_integers
    from tools.macho import Image
else:
    from abi_types import unpack_integers
    from macho import Image


class ScalarGetRecord(TypedDict):
    """One scalar ioctl request with a pinned ABI address."""

    request: int
    address: str
    symbol: str


class GuardRecord(TypedDict):
    """One checked source image byte guard location."""

    address: str
    symbol: str


class CopyRecord(TypedDict):
    """Direct callsite position with its input/output direction."""

    address: str
    output: bool


class ImageRecord(TypedDict):
    """Stable provenance and guarded symbol inventory for one image."""

    path: str
    uuid: str | None
    sha256: str
    guards: list[GuardRecord]
    copySites: list[CopyRecord]
    scalarGetRequests: NotRequired[list[ScalarGetRecord]]
    rejectsOtherBackendAt: NotRequired[list[str]]


class ProfileManifest(TypedDict):
    """Generated profile manifest with checked per-image records."""

    copyright: str
    supportedKernel: str
    images: dict[str, ImageRecord]


ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / ".research/binaries"
IMAGES = {
    "Legacy": BINARY
    / (
        "IO80211FamilyLegacy-v1.0.0/IO80211FamilyLegacy.kext/Contents/"
        "MacOS/IO80211FamilyLegacy"
    ),
    "Skywalk": BINARY
    / (
        "IOSkywalkFamily-v1.2.0/IOSkywalkFamily.kext/Contents/"
        "MacOS/IOSkywalkFamily"
    ),
    "AirPortOriginal": BINARY
    / (
        "IO80211FamilyLegacy-v1.0.0/IO80211FamilyLegacy.kext/Contents/"
        "PlugIns/AirPortBrcmNIC.kext/Contents/MacOS/AirPortBrcmNIC"
    ),
    "AirPort": BINARY
    / (
        "AirPortBrcmNIC-Tahoe-v1.0.0/AirPortBrcmNIC-Tahoe.kext/Contents/"
        "MacOS/AirPortBrcmNIC"
    ),
}
SYMBOLS = {
    "Legacy": [
        "__ZN16IO80211Interface13newUserClientEP4taskPvjP12OSDictionaryPP12IOUserClient",
        "__ZN23IO80211VirtualInterface13newUserClientEP4taskPvjP12OSDictionaryPP12IOUserClient",
        "__ZN16IO80211Interface27IO80211InterfacePostMessageEjPvm",
        "__ZN23IO80211VirtualInterface27IO80211InterfacePostMessageEjPvm",
        "__ZN21IO80211InfraInterface19postMessageInternalEjPvm",
        "__ZN17IO80211Controller20apple80211_ioctl_getEP16IO80211InterfaceP23IO80211VirtualInterfaceP23IO80211SkywalkInterfacePv",
        "__ZN17IO80211Controller20apple80211_ioctl_setEP16IO80211InterfaceP23IO80211VirtualInterfaceP23IO80211SkywalkInterfacePv",
        "__ZN16IO80211Interface13getControllerEv",
        "__ZN23IO80211VirtualInterface13getControllerEv",
        "__ZNK17IO80211Controller11getWorkLoopEv",
        "__ZN16IO80211Interface10getBSDNameEv",
        "__ZN23IO80211VirtualInterface10getBSDNameEv",
        "__ZN23IO80211SkywalkInterface10getBSDNameEv",
        "__ZN16IO80211Interface14performCommandEP19IONetworkControllermPvS2_",
        "__ZN17IO80211Controller22apple80211RequestIoctlEjiP16IO80211InterfacePv",
        "__ZN16IO80211Interface25updateCountryCodePropertyEb",
    ],
    "AirPort": [
        "_ath_decode_anqp_nai_realm_print",
        "__dma_detach",
        "_dma64_txfast",
        "__dma_rxfill",
        "__dma_getnextrxp",
        "__ZN15AirPort_BrcmNIC9getLOCALEEP8OSObjectP22apple80211_locale_data",
        "__ZN15AirPort_BrcmNIC15getCOUNTRY_CODEEP8OSObjectP28apple80211_country_code_data",
    ],
}
SYMBOLS["AirPortOriginal"] = SYMBOLS["AirPort"]
HARDWARE_VERSION_SYMBOL = (
    "__ZN15AirPort_BrcmNIC19getHARDWARE_VERSIONEP8OSObject"
    "P23apple80211_version_data"
)
ROUTE_SYMBOLS = {
    "Legacy": [
        *SYMBOLS["Legacy"][:5],
        "__ZN16IO80211Interface25updateCountryCodePropertyEb",
    ],
    "AirPort": [
        HARDWARE_VERSION_SYMBOL,
        "__ZN15AirPort_BrcmNIC9getLOCALEEP8OSObjectP22apple80211_locale_data",
    ],
}
ROUTE_SYMBOLS["AirPortOriginal"] = ROUTE_SYMBOLS["AirPort"]
SCALAR_GET_REQUESTS = [
    5,
    8,
    13,
    15,
    18,
    21,
    26,
    28,
    31,
    33,
    34,
    35,
    36,
    41,
    45,
    50,
    52,
    55,
    56,
    57,
    58,
    59,
    60,
    63,
    64,
    70,
    71,
    72,
    82,
    87,
    88,
    96,
    100,
    101,
    235,
    241,
    256,
    258,
    259,
    261,
    265,
    267,
    336,
    353,
    369,
]


# One Mach-O 64-bit header, command header, nlist_64 and relocation record.
MACH_HEADER_SIZE = 32
LOAD_COMMAND_SIZE = 8
SYMTAB_COMMAND = 2
DYSYMTAB_COMMAND = 0xB
SYMTAB_COMMAND_SIZE = 24
DYSYMTAB_COMMAND_SIZE = 80
SYMBOL_RECORD_SIZE = 16
RELOCATION_RECORD_SIZE = 8
STRING_OFFSET_SIZE = 0xFFFFFF
RELOCATION_WIDTH_SHIFT = 25
RELOCATION_KIND_SHIFT = 28
RELOCATION_CALL_TYPE = 2
GUARD_SIZE = 32
SCALAR_TABLE_COUNT = 417
SCALAR_TABLE_ENTRY_SIZE = 8
SCALAR_GET_OFFSET = 1
EXPECTED_COPY_LEGACY = 14
EXPECTED_COPY_AIRPORT = 2
MIN_BACKEND_MISMATCHES = 5
COPYIN_SYMBOL = "_copyin"
COPYOUT_SYMBOL = "_copyout"
LEGACY_LABEL = "Legacy"
DIRECT_RELATIVE_CALL = b"\xe8"

# Synthetic byte records and pinned-file readers share these explicit bounds.
type Relocation = tuple[int, int, str, int]
type SymbolTable = tuple[int, int, int, int]
type RelocationTables = tuple[SymbolTable, int, int]


def _invalid(message: str) -> Never:
    raise ValueError(message)


def _checked_command(data: bytes, position: int, end: int) -> tuple[int, int]:
    """Read one complete load-command header inside its declared region.

    Returns:
        Identifier and checked command byte length.

    """
    if position + LOAD_COMMAND_SIZE > end:
        _invalid("Truncated Mach-O load command")
    command, length = struct.unpack_from("<II", data, position)
    if length < LOAD_COMMAND_SIZE or length > end - position:
        _invalid("Invalid Mach-O load command size")
    return command, length


def _load_commands(data: bytes) -> Iterator[tuple[int, int, int]]:
    """Yield only load commands inside the declared Mach-O command range.

    Yields:
        The command start offset, identifier and byte length.

    """
    if len(data) < MACH_HEADER_SIZE:
        _invalid("Truncated Mach-O header")
    count, size = struct.unpack_from("<II", data, 16)
    if size > len(data) - MACH_HEADER_SIZE or count > size // LOAD_COMMAND_SIZE:
        _invalid("Mach-O load commands exceed declared file range")
    position = MACH_HEADER_SIZE
    end = position + size
    for _ in range(count):
        command, length = _checked_command(data, position, end)
        yield position, command, length
        position += length
    if position != end:
        _invalid("Mach-O load commands do not fill declared command range")


def _symtab(data: bytes, position: int, size: int) -> SymbolTable:
    """Read a complete symbol-table command.

    Returns:
        The four symbol/string index fields.

    """
    if size < SYMTAB_COMMAND_SIZE:
        _invalid("Truncated symbol table command")
    return struct.unpack_from("<IIII", data, position + LOAD_COMMAND_SIZE)


def _dysymtab(data: bytes, position: int, size: int) -> tuple[int, ...]:
    """Read a complete dynamic-symbol-table command.

    Returns:
        Its eighteen checked unsigned integer fields.

    """
    if size < DYSYMTAB_COMMAND_SIZE:
        _invalid("Truncated dynamic symbol table command")
    return struct.unpack_from("<18I", data, position + LOAD_COMMAND_SIZE)


def _span_valid(data: bytes, offset: int, count: int, *, width: int) -> bool:
    """Check a bounded file range without multiplying untrusted counts first.

    Returns:
        True only when the full declared range fits the byte owner.

    """
    return offset <= len(data) and count <= (len(data) - offset) // width


def _find_tables(data: bytes) -> tuple[SymbolTable, tuple[int, ...]]:
    """Find the required Mach-O symbol and dynamic-symbol commands.

    Returns:
        Raw symbol table and dynamic relocation command fields.

    """
    symbols: SymbolTable | None = None
    dynamic: tuple[int, ...] | None = None
    for position, command, size in _load_commands(data):
        if command == SYMTAB_COMMAND:
            symbols = _symtab(data, position, size)
        elif command == DYSYMTAB_COMMAND:
            dynamic = _dysymtab(data, position, size)
    if symbols is None or dynamic is None:
        _invalid("Missing Mach-O relocation symbol tables")
    return symbols, dynamic


def _relocation_tables(data: bytes) -> RelocationTables:
    """Find and bound both nlist and external relocation tables.

    Returns:
        Checked symbol fields, relocation byte offset, and item count.

    """
    symbols, dynamic = _find_tables(data)
    symbol_offset, symbol_count, string_offset, string_size = symbols
    relocation_offset, relocation_count = dynamic[14], dynamic[15]
    valid = (
        _span_valid(data, symbol_offset, symbol_count, width=SYMBOL_RECORD_SIZE)
        and _span_valid(data, string_offset, string_size, width=1)
        and _span_valid(
            data,
            relocation_offset,
            relocation_count,
            width=RELOCATION_RECORD_SIZE,
        )
    )
    if not valid:
        _invalid("Mach-O relocation tables exceed file bounds")
    return symbols, relocation_offset, relocation_count


def _relocation_entry(
    data: bytes, address: int, symbols: SymbolTable
) -> Relocation:
    """Decode one checked external relocation and terminated symbol name.

    Returns:
        Relocation address, byte width, symbol name, and relocation kind.

    """
    position, flags = struct.unpack_from("<II", data, address)
    symbol_offset, symbol_count, string_offset, string_size = symbols
    symbol_index = flags & STRING_OFFSET_SIZE
    if symbol_index >= symbol_count:
        _invalid("Mach-O relocation references missing symbol")
    name_offset = struct.unpack_from(
        "<I", data, symbol_offset + symbol_index * SYMBOL_RECORD_SIZE
    )[0]
    if name_offset >= string_size:
        _invalid("Mach-O relocation symbol name out of bounds")
    start = string_offset + name_offset
    end = data.find(b"\0", start, string_offset + string_size)
    if end == -1:
        _invalid("Mach-O relocation symbol name is unterminated")
    return (
        position,
        1 << ((flags >> RELOCATION_WIDTH_SHIFT) & 3),
        data[start:end].decode(),
        flags >> RELOCATION_KIND_SHIFT,
    )


def relocations(image: Image) -> list[Relocation]:
    """Return bounded external relocations from a pinned Mach-O image.

    Returns:
        Every external relocation with its resolved symbol and width.

    """
    symbols, offset, count = _relocation_tables(image.data)
    return [
        _relocation_entry(
            image.data, offset + index * RELOCATION_RECORD_SIZE, symbols
        )
        for index in range(count)
    ]


def numbers(data: bytes | bytearray) -> str:
    """Format a finite byte buffer as native C++ initializer numbers.

    Returns:
        Comma-separated uppercase hex byte literals.

    """
    return ", ".join(f"0x{x:02X}" for x in data)


def guard_mask(
    relocations: list[tuple[int, int, str, int]], address: int
) -> bytearray:
    """Mask unstable relocation slots within one bounded guard window.

    Returns:
        A per-byte guard mask with relocations zeroed.

    """
    mask = bytearray([255] * GUARD_SIZE)
    for start, size, _, _ in relocations:
        for offset in range(
            max(start, address), min(start + size, address + GUARD_SIZE)
        ):
            mask[offset - address] = 0
    return mask


@dataclass(frozen=True)
class _ProfileImage:
    """Image metadata and byte-guard decisions for one static profile."""

    label: str
    path: Path
    image: Image
    relocs: list[Relocation]
    guards: list[tuple[int, str]]
    copies: list[tuple[int, bool]]
    scalar: list[ScalarGetRecord]


def _scalar_gets(
    image: Image, guards: list[tuple[int, str]]
) -> list[ScalarGetRecord]:
    """Read and validate every pinned scalar GET handler.

    Returns:
        Symbol-address records for the scalar request table.

    Raises:
        RuntimeError: A scalar handler has an unexpected ABI name.

    """
    table = unpack_integers(
        image.read(
            image.symbols["_gGetHandlerTable"],
            SCALAR_TABLE_COUNT * SCALAR_TABLE_ENTRY_SIZE,
        ),
        f"<{SCALAR_TABLE_COUNT}Q",
    )
    scalar: list[ScalarGetRecord] = []
    for request in SCALAR_GET_REQUESTS:
        address = table[request - SCALAR_GET_OFFSET]
        name = image.name(address)
        if not name.startswith("__ZL") or not name.endswith(
            "P13apple80211reqb+0x0"
        ):
            message = "Unexpected scalar GET codec"
            raise RuntimeError(message)
        scalar.append({
            "request": request,
            "address": hex(address),
            "symbol": name,
        })
        if (address, name) not in guards:
            guards.append((address, name))
    return scalar


def _copy_sites(
    image: Image,
    relocs: list[Relocation],
    label: str,
    *,
    guards: list[tuple[int, str]],
) -> list[tuple[int, bool]]:
    """Require known direct-call byte signatures for legacy copy helpers.

    Returns:
        Checked callsite addresses and direction flags.

    Raises:
        RuntimeError: A required count or opcode differs from the pin.

    """
    copies = [
        (address - 1, name == COPYOUT_SYMBOL)
        for address, _, name, kind in relocs
        if name in {COPYIN_SYMBOL, COPYOUT_SYMBOL}
        and kind == RELOCATION_CALL_TYPE
    ]
    if label not in {LEGACY_LABEL, "AirPort", "AirPortOriginal"}:
        return copies
    expected = (
        EXPECTED_COPY_LEGACY if label == LEGACY_LABEL else EXPECTED_COPY_AIRPORT
    )
    if len(copies) != expected:
        message = "Unexpected copy callsite count"
        raise RuntimeError(message)
    for address, _ in copies:
        if image.read(address, 1) != DIRECT_RELATIVE_CALL:
            message = "Expected direct relative call"
            raise RuntimeError(message)
        guards.append((address, image.name(address)))
    return copies


def _inspect_profile(label: str, path: Path) -> _ProfileImage:
    """Apply the pinned rules for one offline image without writing outputs.

    Returns:
        Complete validated model for code generation.

    """
    image = Image(path)
    relocs = relocations(image)
    guards = [(image.symbols[name], name) for name in SYMBOLS[label]]
    scalar = _scalar_gets(image, guards) if label == LEGACY_LABEL else []
    copies = _copy_sites(image, relocs, label, guards=guards)
    if label.startswith("AirPort"):
        guards.extend([
            (0x2C2612, "TX backend identity"),
            (0x2C3D78, "RX fill backend identity"),
            (0x2C4286, "RX consume backend identity"),
        ])
    return _ProfileImage(label, path, image, relocs, guards, copies, scalar)


def _profile_lines(profile: _ProfileImage) -> list[str]:
    """Emit identical C++ initializer records from the checked byte guards.

    Returns:
        C++ lines for scalar, guard and copy-site arrays.

    """
    lines: list[str] = []
    if profile.scalar:
        requests = ", ".join(str(number) for number in SCALAR_GET_REQUESTS)
        lines.append(
            f"static const uint16_t ScalarGetRequests[] = {{{requests}}};"
        )
    lines.append(f"static const ByteGuard {profile.label}Guards[] = {{")
    for address, _ in profile.guards:
        data = numbers(profile.image.read(address, GUARD_SIZE))
        mask = numbers(guard_mask(profile.relocs, address))
        lines.append(f"    {{0x{address:X}, {{{data}}}, {{{mask}}}}},")
    lines.append("};")
    if profile.label in {LEGACY_LABEL, "AirPort", "AirPortOriginal"}:
        lines.append(f"static const CopySite {profile.label}CopySites[] = {{")
        for address, output in sorted(profile.copies):
            side = "true" if output else "false"
            lines.append(f"    {{0x{address:X}, {side}}},")
        lines.append("};")
    lines.append("")
    return lines


def _profile_record(profile: _ProfileImage) -> ImageRecord:
    """Record exact input bytes and the guards used for code generation.

    Returns:
        A serializable per-image manifest with optional scalar requests.

    """
    record: ImageRecord = {
        "path": str(profile.path.relative_to(ROOT)),
        "uuid": profile.image.uuid,
        "sha256": hashlib.sha256(profile.path.read_bytes()).hexdigest(),
        "guards": [
            {"address": hex(address), "symbol": symbol}
            for address, symbol in profile.guards
        ],
        "copySites": [
            {"address": hex(address), "output": output}
            for address, output in sorted(profile.copies)
        ],
    }
    if profile.scalar:
        record["scalarGetRequests"] = profile.scalar
    return record


def _guard_mismatch(
    image: Image,
    alternative: Image,
    relocs: list[Relocation],
    *,
    address: int,
) -> bool:
    """Detect unmasked byte differences between two offline image versions.

    Returns:
        True only for a changed byte outside either relocation set.

    """
    mask = guard_mask(relocs, address)
    first = image.read(address, GUARD_SIZE)
    second = alternative.read(address, GUARD_SIZE)
    return any(
        a != b and mask[index] != 0
        for index, (a, b) in enumerate(zip(first, second, strict=True))
    )


def _backend_differences(manifest: ProfileManifest) -> None:
    """Verify AirPort guard bytes distinguish the two pinned variants.

    Raises:
        RuntimeError: The two profiles share too many unmasked guard bytes.

    """
    for label, other in (
        ("AirPort", "AirPortOriginal"),
        ("AirPortOriginal", "AirPort"),
    ):
        image, alternative = Image(IMAGES[label]), Image(IMAGES[other])
        relocs = [*relocations(image), *relocations(alternative)]
        mismatches = [
            guard["address"]
            for guard in manifest["images"][label]["guards"]
            if _guard_mismatch(
                image,
                alternative,
                relocs,
                address=int(guard["address"], 16),
            )
        ]
        if len(mismatches) < MIN_BACKEND_MISMATCHES:
            message = (
                "AirPort backend guards do not distinguish the original "
                "and Tahoe payloads"
            )
            raise RuntimeError(message)
        manifest["images"][label]["rejectsOtherBackendAt"] = mismatches


def _profile_header() -> list[str]:
    """Return the legacy C++ header prologue without changing its spelling.

    Returns:
        Header guard, types and namespace opening.

    """
    return [
        "//",
        "//  Profiles.hpp",
        "//  SimpleATH",
        "//",
        "//  Created by laobamac on 2026/9/15.",
        "//  Copyright © 2026 laobamac. All rights reserved.",
        "//",
        "",
        "#ifndef SIMPLEATH_PROFILES_HPP",
        "#define SIMPLEATH_PROFILES_HPP",
        "",
        "#include <stdint.h>",
        "",
        "namespace ath {",
        (
            "struct ByteGuard { uint32_t offset; uint8_t bytes[32]; "
            "uint8_t mask[32]; };"
        ),
        "struct CopySite { uint32_t offset; bool output; };",
        "",
    ]


def _profile_manifest() -> ProfileManifest:
    """Return the unchanged top-level legacy profile output metadata.

    Returns:
        An initially empty typed image manifest.

    """
    return {
        "copyright": "Copyright © 2026 laobamac. All rights reserved.",
        "supportedKernel": "23.x / 24.x / 25.x",
        "images": {},
    }


def _write_outputs(lines: list[str], manifest: ProfileManifest) -> None:
    """Write only changed generated files at the historical output paths."""
    outputs = {
        ROOT / "SimpleATH/Profiles.hpp": "\n".join(lines),
        ROOT / "Docs/ABI.json": json.dumps(
            manifest, indent=2, ensure_ascii=False
        )
        + "\n",
    }
    for path, content in outputs.items():
        if not path.exists() or path.read_text() != content:
            _ = path.write_text(content)


def main() -> None:
    """Render pinned offline profile source, never build or load an image."""
    lines = _profile_header()
    manifest = _profile_manifest()
    for label, path in IMAGES.items():
        if label in SYMBOLS:
            profile = _inspect_profile(label, path)
            lines.extend(_profile_lines(profile))
            manifest["images"][label] = _profile_record(profile)
    _backend_differences(manifest)
    lines.extend(["}", "", "#endif", ""])
    _write_outputs(lines, manifest)


if __name__ == "__main__":
    main()
