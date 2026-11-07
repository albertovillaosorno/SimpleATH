#!/usr/bin/env python3
#
#  native_abi.py
#  SimpleATH
#
#  Created by laobamac on 2026/11/1.
#  Copyright © 2026 laobamac. All rights reserved.
#

from __future__ import annotations

import collections
import ctypes
import functools
import hashlib
from itertools import pairwise
import mmap
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
from typing import TYPE_CHECKING
import uuid

if TYPE_CHECKING:
    from typing import BinaryIO

if __package__:
    from tools.abi_types import unpack_integers
    from tools.native_references import ReferenceImage
    from tools.native_references import reference_paths
    from tools.profiles import IMAGES
    from tools.system_profiles import SYSTEMS
else:
    from abi_types import unpack_integers
    from native_references import ReferenceImage
    from native_references import reference_paths
    from profiles import IMAGES
    from system_profiles import SYSTEMS

EXPECTED_SOURCES = {
    "OldSky": "0484ecd97d1bdb8759aef72661c196cda4309697eea1945a4a3c4d5e6d7e5e5b",
    "Legacy": "ac2dc15b77f8eaf97b71b34c5d0e1b59f862bfeac618396449306e1837e73894",
    "BrcmTahoe": "0b6cf936e594d1372960a60c8f17b6cbf68e3535a191574bd91498da49713775",
    "BrcmOriginal": "884e90b27cff151e432bb36275936f57b43e72419e95b51b3ac067d3f2ccd331",
}
PATHS = {
    key: IMAGES[label]
    for key, label in (
        ("OldSky", "Skywalk"),
        ("Legacy", "Legacy"),
        ("BrcmTahoe", "AirPort"),
        ("BrcmOriginal", "AirPortOriginal"),
    )
}


MAX_NATIVE_MACHO_BYTES = 2 * 1024 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
FAT32_MAGIC = b"\xca\xfe\xba\xbe"
FAT64_MAGIC = b"\xca\xfe\xba\xbf"
FAT_HEADER_BYTES = 8
MAX_FAT_ARCHITECTURES = 256
MAX_FAT_ALIGNMENT = 62
CPU_X86_64 = 0x01000007
MACHO_HEADER_BYTES = 32


def _open_mach_source(path: Path) -> BinaryIO:
    """Open an immutable-path, bounded regular Mach-O image for mmap.

    Returns:
        The caller-owned binary stream, positioned at its start.

    Raises:
        ValueError: A source is empty, nonregular or exceeds the byte limit.

    System opening errors, including symlink rejection, propagate as OSError.

    """
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    stream = os.fdopen(os.open(path, flags), "rb")
    try:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not (
            0 < info.st_size <= MAX_NATIVE_MACHO_BYTES
        ):
            message = "Mach-O source must be a bounded regular file"
            raise ValueError(message)
        return stream
    except BaseException:
        stream.close()
        raise


def hash_mach_source(path: Path) -> str:
    """Hash an unchanged, bounded source without loading it into memory.

    Returns:
        SHA-256 digest of the exact regular input bytes.

    Raises:
        ValueError: The file changed, was empty, or exceeded the byte limit.

    """
    with _open_mach_source(path) as stream:
        before = os.fstat(stream.fileno())
        remaining = before.st_size
        digest = hashlib.sha256()
        while remaining:
            chunk = stream.read(min(remaining, HASH_CHUNK_BYTES))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
        excess = stream.read(1)
        after = os.fstat(stream.fileno())
    attributes = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (
        remaining
        or excess
        or any(
            getattr(before, attribute) != getattr(after, attribute)
            for attribute in attributes
        )
    ):
        message = "Native Mach-O source changed while hashing"
        raise ValueError(message)
    return digest.hexdigest()


def _require_span(start: int, size: int, limit: int) -> None:
    """Reject negative or out-of-range file/mapping spans.

    Raises:
        ValueError: The requested span escapes the containing buffer.

    """
    if start < 0 or size < 0 or start > limit or size > limit - start:
        message = "Mach-O source span escapes the mapped file"
        raise ValueError(message)


def _fat_architecture(
    data: mmap.mmap, index: int, table_end: int, *, wide: bool
) -> tuple[int, int, int]:
    """Validate one FAT entry including non-selected architecture slices.

    Returns:
        CPU type, slice offset and size, all checked against the file.

    Raises:
        ValueError: A slice overlaps the table or has invalid bounds.

    """
    entry = FAT_HEADER_BYTES + index * (32 if wide else 20)
    cpu = unpack_integers(data, ">I", entry)[0]
    offset, size = unpack_integers(data, ">QQ" if wide else ">II", entry + 8)
    alignment = unpack_integers(data, ">I", entry + (24 if wide else 16))[0]
    if (
        not size
        or offset < table_end
        or alignment > MAX_FAT_ALIGNMENT
        or offset % (1 << alignment)
    ):
        message = "Malformed FAT architecture slice alignment or bounds"
        raise ValueError(message)
    _require_span(offset, size, len(data))
    return cpu, offset, size


def _fat_table_metadata(data: mmap.mmap, *, wide: bool) -> tuple[int, int]:
    """Check the FAT table's complete bounded architecture record budget.

    Returns:
        Architecture count and table end offset.

    Raises:
        ValueError: Header or record budget is invalid or truncated.

    """
    _require_span(0, FAT_HEADER_BYTES, len(data))
    count = unpack_integers(data, ">I", 4)[0]
    row_size = 32 if wide else 20
    if (
        not 0 < count <= MAX_FAT_ARCHITECTURES
        or count > (len(data) - FAT_HEADER_BYTES) // row_size
    ):
        message = "Truncated or excessive FAT architecture table"
        raise ValueError(message)
    return count, FAT_HEADER_BYTES + count * row_size


def _require_disjoint_fat_ranges(ranges: list[tuple[int, int]]) -> None:
    """Reject any pair of intersecting FAT architecture file spans.

    Raises:
        ValueError: Overlapping FAT slices.

    """
    if any(left[1] > right[0] for left, right in pairwise(sorted(ranges))):
        message = "Overlapping FAT architecture slices"
        raise ValueError(message)


def _unique_fat_x86_64(
    data: mmap.mmap, count: int, table_end: int, *, wide: bool
) -> tuple[int, int]:
    """Check all FAT records and select only one complete x86_64 image.

    Returns:
        The unique slice offset and length in the full mapped file.

    Raises:
        ValueError: Missing, ambiguous or overlapping architectures.

    """
    ranges: list[tuple[int, int]] = []
    selected: tuple[int, int] | None = None
    for index in range(count):
        cpu, offset, size = _fat_architecture(data, index, table_end, wide=wide)
        ranges.append((offset, offset + size))
        if cpu == CPU_X86_64:
            if selected is not None or size < MACHO_HEADER_BYTES:
                message = "Ambiguous or truncated x86_64 FAT architecture"
                raise ValueError(message)
            selected = (offset, size)
    _require_disjoint_fat_ranges(ranges)
    if selected is None:
        message = "FAT Mach-O has no x86_64 image"
        raise ValueError(message)
    return selected


def _fat_x86_64_range(data: mmap.mmap) -> tuple[int, int] | None:
    """Select a unique bounded FAT32/FAT64 x86_64 slice, or keep thin.

    Returns:
        Offset and length of the selected architecture, or None for thin.

    Invalid FAT tables are rejected by the bounded catalog reader.

    """
    magic = data[:4]
    if magic not in {FAT32_MAGIC, FAT64_MAGIC}:
        return None
    wide = magic == FAT64_MAGIC
    count, table_end = _fat_table_metadata(data, wide=wide)
    return _unique_fat_x86_64(data, count, table_end, wide=wide)


class Mach:
    """Own a bounded offline Mach-O image and its typed metadata indices."""

    path: str
    f: BinaryIO
    b: mmap.mmap
    base: int
    slice_end: int
    h: int
    typ: int
    fixup_base: int
    segs: list[tuple[str, int, int, int, int]]
    sects: list[
        tuple[str, str, int, int, int, int, int, int, int, int, int, int]
    ]
    entries: dict[str, tuple[int, int]]
    syms: list[tuple[str, int, int, int, int]]
    symtab: tuple[int, int, int, int] | None
    dysym: tuple[int, ...] | None
    uuid: str | None
    names: dict[str, tuple[str, int, int, int, int]]
    byaddr: collections.defaultdict[int, list[str]]

    def __new__(cls, path, entry=None):
        if Path(path).suffix == ".json":
            return ReferenceImage(path, entry)
        return super().__new__(cls)

    def __init__(self, path: str | Path, entry: str | None = None) -> None:
        self.path = str(path)
        # Initialize the complete instance contract before the first parse;
        # a fileset subimage can subsequently replace all parsed catalogs.
        self.typ = 0
        self.segs = []
        self.sects = []
        self.entries = {}
        self.syms = []
        self.symtab = None
        self.dysym = None
        self.uuid = None
        self.names = {}
        self.byaddr = collections.defaultdict(list)
        self.f = _open_mach_source(Path(path))
        try:
            self.b = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        except BaseException:
            self.f.close()
            raise
        try:
            self.base = 0
            self.slice_end = len(self.b)
            self._select_header()
            self.h = self.base
            self.parse()
            bases = [va for _, va, size, _, _ in self.segs if va and size]
            if not bases:
                message = "Mach-O image has no mapped virtual segment"
                raise ValueError(message)
            self.fixup_base = min(bases)
            if entry is not None:
                if entry not in self.entries:
                    message = "Mach-O fileset entry does not exist"
                    raise ValueError(message)
                self.h = self.base + self.entries[entry][1]
                _require_span(self.h, 32, self.slice_end)
                self.parse()
        except BaseException:
            self.close()
            raise

    def _select_header(self) -> None:
        selected = _fat_x86_64_range(self.b)
        if selected is not None:
            offset, size = selected
            self.base = offset
            self.slice_end = offset + size

    def parse(self) -> None:
        b = self.b
        h = self.h
        _require_span(h, 32, self.slice_end)
        magic, cpu, _subtype, typ, count, command_bytes, _flags, _reserved = (
            unpack_integers(b, "<8I", h)
        )
        if magic != 4277009103 or cpu != 16777223:
            message = "Expected an x86_64 Mach-O image"
            raise ValueError(message)
        _require_span(h + 32, command_bytes, self.slice_end)
        if count > command_bytes // 8:
            message = "Mach-O command count exceeds the command byte budget"
            raise ValueError(message)
        self.typ = typ
        self.segs = []
        self.sects = []
        self.entries = {}
        self.syms = []
        self.symtab = None
        self.dysym = None
        self.uuid = None
        cursor = h + 32
        command_end = cursor + command_bytes
        for _ in range(count):
            _require_span(cursor, 8, command_end)
            command, length = unpack_integers(b, "<II", cursor)
            if length < 8:
                message = "Invalid Mach-O load command size"
                raise ValueError(message)
            _require_span(cursor, length, command_end)
            if command == 25:
                _require_span(cursor, 72, cursor + length)
                segment, va, vmsize, fileoff, filesize, _, _, sections, _ = (
                    struct.unpack_from("<16sQQQQiiII", b, cursor + 8)
                )
                if sections > (length - 72) // 80 or filesize > vmsize:
                    message = "Truncated or inconsistent Mach-O segment"
                    raise ValueError(message)
                _require_span(self.base + fileoff, filesize, self.slice_end)
                name = segment.rstrip(b"\x00").decode()
                self.segs.append((name, va, vmsize, fileoff, filesize))
                for index in range(sections):
                    fields = struct.unpack_from(
                        "<16s16sQQIIIIIIII", b, cursor + 72 + 80 * index
                    )
                    self.sects.append((
                        fields[0].rstrip(b"\x00").decode(),
                        fields[1].rstrip(b"\x00").decode(),
                        *fields[2:],
                    ))
            elif command == 2:
                if self.symtab is not None:
                    message = "Duplicate Mach-O symbol table command"
                    raise ValueError(message)
                _require_span(cursor, 24, cursor + length)
                symboloff, symbols, stringoff, strings = unpack_integers(
                    b, "<IIII", cursor + 8
                )
                _require_span(
                    self.base + symboloff, symbols * 16, self.slice_end
                )
                _require_span(self.base + stringoff, strings, self.slice_end)
                self.symtab = (symboloff, symbols, stringoff, strings)
            elif command == 11:
                if self.dysym is not None:
                    message = "Duplicate Mach-O dynamic symbol table command"
                    raise ValueError(message)
                _require_span(cursor, 80, cursor + length)
                self.dysym = unpack_integers(b, "<18I", cursor + 8)
            elif command == 27:
                if self.uuid is not None:
                    message = "Duplicate Mach-O UUID command"
                    raise ValueError(message)
                _require_span(cursor, 24, cursor + length)
                self.uuid = str(
                    uuid.UUID(bytes=b[cursor + 8 : cursor + 24])
                ).upper()
            elif command == 2147483701:
                _require_span(cursor, 32, cursor + length)
                _va, fileoff, offset, _reserved = struct.unpack_from(
                    "<QQII", b, cursor + 8
                )
                if offset < 32:
                    message = "Invalid Mach-O fileset name offset"
                    raise ValueError(message)
                _require_span(self.base + fileoff, 32, self.slice_end)
                _require_span(cursor + offset, 1, cursor + length)
                ending = b.find(b"\x00", cursor + offset, cursor + length)
                if ending < 0:
                    message = "Unterminated Mach-O fileset entry name"
                    raise ValueError(message)
                name = b[cursor + offset : ending].decode()
                if not name or name in self.entries:
                    message = "Empty or duplicate Mach-O fileset entry name"
                    raise ValueError(message)
                self.entries[name] = (_va, fileoff)
            cursor += length
        if cursor != command_end:
            message = "Mach-O command sizes do not match their byte budget"
            raise ValueError(message)
        if self.symtab is not None:
            offset, count, stringoff, stringsize = self.symtab
            for index in range(count):
                nameoff, kind, section, desc, address = struct.unpack_from(
                    "<IBBHQ", b, self.base + offset + 16 * index
                )
                name = ""
                if nameoff:
                    if nameoff >= stringsize:
                        message = "Mach-O symbol string offset is outside table"
                        raise ValueError(message)
                    begin = self.base + stringoff + nameoff
                    ending = b.find(
                        b"\x00", begin, self.base + stringoff + stringsize
                    )
                    if ending < 0:
                        message = "Unterminated Mach-O symbol name"
                        raise ValueError(message)
                    name = b[begin:ending].decode(errors="replace")
                self.syms.append((name, kind, section, desc, address))
        self.names = {
            symbol[0]: symbol for symbol in self.syms if not symbol[1] & 224
        }
        self.byaddr = collections.defaultdict(list)
        for symbol in self.syms:
            if symbol[4] and symbol[0] and (not symbol[1] & 224):
                self.byaddr[symbol[4]].append(symbol[0])

    def off(self, va: int) -> int:
        for _, v, _, o, fs in self.segs:
            if v <= va < v + fs:
                offset = self.base + o + va - v
                _require_span(offset, 1, self.slice_end)
                return offset
        raise ValueError(hex(va))

    def read(self, va: int, n: int) -> bytes:
        for _, v, _, o, fs in self.segs:
            if n >= 0 and v <= va and (va + n <= v + fs):
                offset = self.base + o + va - v
                _require_span(offset, n, self.slice_end)
                return self.b[offset : offset + n]
        raise ValueError(f"Unmapped range {va:#x}+{n:#x}")

    def close(self) -> None:
        self.b.close()
        self.f.close()

    def defined(self) -> set[str]:
        return {
            n
            for n, t, _, _, _ in self.syms
            if t & 1 and t & 14 in [2, 14] and (not t & 224)
        }

    def undef(self) -> set[str]:
        return {
            n for n, t, _, _, _ in self.syms if t & 14 == 0 and (not t & 224)
        }

    def relocs(self) -> dict[int, tuple[str, int, int, int]]:
        result: dict[int, tuple[str, int, int, int]] = {}
        relocation_tables: list[tuple[int, int, int]] = []
        if self.dysym is not None:
            offset, count = self.dysym[14:16]
            relocation_tables.append((self.base + offset, count, 0))
        for section in self.sects:
            offset, count = section[6:8]
            relocation_tables.append((self.base + offset, count, section[2]))
        for offset, count, start in relocation_tables:
            _require_span(offset, count * 8, self.slice_end)
            for index in range(count):
                relative, word = unpack_integers(
                    self.b, "<iI", offset + 8 * index
                )
                symbol_index = word & 0xFFFFFF
                external = bool(word >> 27 & 1)
                if external and symbol_index >= len(self.syms):
                    message = "Mach-O relocation refers to an absent symbol"
                    raise ValueError(message)
                if relative < 0:
                    message = "Mach-O relocation has a negative address"
                    raise ValueError(message)
                result[start + relative] = (
                    self.syms[symbol_index][0] if external else "LOCAL",
                    word >> 28,
                    word >> 24 & 1,
                    word >> 25 & 3,
                )
        return result

    def funcs(self) -> list[tuple[int, str]]:
        return sorted(
            (s[4], s[0])
            for s in self.syms
            if s[2]
            and s[2] <= len(self.sects)
            and (self.sects[s[2] - 1][0] == "__text")
            and (not s[1] & 224)
        )

    def funcbytes(self, name: str) -> tuple[int, bytes]:
        a = self.names[name][4]
        ends = [x for x, _ in self.funcs() if x > a]
        e = min(ends) if ends else a + 512
        return (a, self.read(a, e - a))


def sky(ver):
    return Mach(reference_paths()[ver], "com.apple.iokit.IOSkywalkFamily")


def dem(names):
    s = list(names)
    return subprocess.check_output(
        ["c++filt"], input="\n".join(s) + "\n", text=True
    ).splitlines()


@functools.lru_cache(maxsize=1)
def disassembler():
    toolchain = Path(
        subprocess.check_output(
            ["xcrun", "--find", "llvm-objdump"], text=True
        ).strip()
    ).parent.parent
    library = ctypes.CDLL(str(toolchain / "lib/libLTO.dylib"))
    library.LLVMCreateDisasm.argtypes = [
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    library.LLVMCreateDisasm.restype = ctypes.c_void_p
    library.LLVMDisasmInstruction.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulonglong,
        ctypes.c_ulonglong,
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
    library.LLVMDisasmInstruction.restype = ctypes.c_size_t
    library.lto_initialize_disassembler()
    context = library.LLVMCreateDisasm(
        b"x86_64-apple-darwin", None, 0, None, None
    )
    if not context:
        raise RuntimeError("Unable to initialize the x86_64 disassembler")
    return library, context


def insns(data, addr):
    library, context = disassembler()
    buf = ctypes.create_string_buffer(data)
    o = 0
    while o < len(data):
        out = ctypes.create_string_buffer(512)
        l = library.LLVMDisasmInstruction(
            context, ctypes.byref(buf, o), len(data) - o, addr + o, out, 512
        )
        if not l:
            raise ValueError(f"Undecodable instruction at {addr + o:#x}")
        yield (addr + o, l, out.value.decode().strip(), data[o : o + l])
        o += l


NATIVE_CLASSES = (
    "IOSkywalkInterface",
    "IOSkywalkNetworkInterface",
    "IOSkywalkEthernetInterface",
    "IOSkywalkPacket",
    "IOSkywalkNetworkPacket",
    "IOSkywalkPacketBufferPool",
    "IOSkywalkPacketQueue",
    "IOSkywalkTxSubmissionQueue",
    "IOSkywalkRxSubmissionQueue",
    "IOSkywalkTxCompletionQueue",
    "IOSkywalkRxCompletionQueue",
    "IOSkywalkPacketBuffer",
    "IOSkywalkMemorySegment",
)
LEGACY_CLASSES = (
    ("Legacy", "IO80211SkywalkInterface", "IOSkywalkEthernetInterface"),
    ("Legacy", "IO80211InfraInterface", "IO80211SkywalkInterface"),
    (
        "BrcmTahoe",
        "AirPort_Brcm43xxLLSkywalkInterface",
        "IO80211InfraInterface",
    ),
    ("BrcmTahoe", "AirPort_Brcm43xxSkywalkPacket", "IOSkywalkNetworkPacket"),
    (
        "BrcmTahoe",
        "AirPort_Brcm43xxSkywalkPacketBufferPool",
        "IOSkywalkPacketBufferPool",
    ),
)


def vtable_name(cls):
    return "__ZTV" + str(len(cls)) + cls


METHOD_KEYS = {}


def prime_method_keys(names):
    names = sorted(set(names) - METHOD_KEYS.keys())
    if not names:
        return
    for name, readable in zip(names, dem(names)):
        key = readable.split("::", 1)[-1].replace("ether_addr_t", "ether_addr")
        destructor = re.search(r"D([012])Ev$", name)
        METHOD_KEYS[name] = "destructor" + destructor[1] if destructor else key


def method_key(name):
    if name not in METHOD_KEYS:
        prime_method_keys([name])
    return METHOD_KEYS[name]


MAX_VTABLE_SLOTS = 4096
VTABLE_HEADER_BYTES = 16
VTABLE_SLOT_BYTES = 8


def _vtable_addresses(start: int, end: int) -> range:
    """Bound vtable slots before touching any untrusted image bytes.

    Returns:
        Validated pointer-slot addresses within the symbol span.

    Raises:
        ValueError: The vtable span is empty, unaligned or too large.

    """
    payload = end - start - VTABLE_HEADER_BYTES
    if (
        start < 0
        or payload <= 0
        or payload % VTABLE_SLOT_BYTES
        or payload // VTABLE_SLOT_BYTES > MAX_VTABLE_SLOTS
    ):
        message = "Malformed or oversized native ABI vtable span"
        raise ValueError(message)
    return range(start + VTABLE_HEADER_BYTES, end, VTABLE_SLOT_BYTES)


def table(image, cls, kernel=None):
    if isinstance(image, ReferenceImage):
        return list(image.tables[cls])
    sym = image.names[vtable_name(cls)]
    start = sym[4]
    following = [
        symbol[4]
        for symbol in image.syms
        if symbol[2] == sym[2] and symbol[4] > start
    ]
    if not following:
        message = "Native ABI vtable has no terminating symbol"
        raise ValueError(message)
    addresses = _vtable_addresses(start, min(following))
    relocs = image.relocs()
    result = []
    for address in addresses:
        raw = struct.unpack("<Q", image.read(address, 8))[0]
        if address in relocs and relocs[address][0] != "LOCAL":
            name = relocs[address][0]
        elif raw:
            if kernel and raw >> 48 != 65535:
                if raw >> 30 & 3 or raw >> 63:
                    raise ValueError("Unsupported kernel collection fixup")
                target = (raw & 1073741823) + kernel.fixup_base
            else:
                target = raw
            names = image.byaddr.get(target, []) or (
                kernel.byaddr.get(target, []) if kernel else []
            )
            if not names:
                raise ValueError(
                    f"Unnamed vtable entry {cls}: {address:#x} -> {target:#x}"
                )
            name = names[0]
        else:
            break
        result.append(name)
    if not result:
        raise ValueError(f"Empty vtable: {cls}")
    return result


class NativeModel:
    def __init__(self, system: str = "Tahoe") -> None:
        self.system: str = system
        self.profile = SYSTEMS[system]
        for key, expected in EXPECTED_SOURCES.items():
            if hash_mach_source(PATHS[key]) != expected:
                raise ValueError(f"Unsupported source payload: {key}")
        self.old: Mach | ReferenceImage = Mach(PATHS["OldSky"])
        self.native: Mach | ReferenceImage = sky(system)
        self.kernel: Mach | ReferenceImage = Mach(
            self.native.path, "com.apple.kernel"
        )
        major = self.kernel.names["_version_major"][4]
        if (
            struct.unpack("<I", self.kernel.read(major, 4))[0]
            != self.profile["kernel"]
        ):
            raise ValueError(
                "Reference system kernel does not match its profile"
            )
        if self.native.uuid != self.profile["skywalk"]:
            raise ValueError(
                "Reference Skywalk UUID does not match its profile"
            )
        self.airport_source: str = (
            "BrcmTahoe" if self.profile["kernel"] == 25 else "BrcmOriginal"
        )
        self.images: dict[str, Mach | ReferenceImage] = {
            "Legacy": Mach(PATHS["Legacy"]),
            "BrcmTahoe": Mach(PATHS[self.airport_source]),
        }
        self.old_tables: dict[str, list[str]] = {}
        self.new_tables: dict[str, list[str]] = {}
        self.old_views: dict[str, list[tuple[str, str, int]]] = {}
        self.tables: dict[str, list[tuple[str, str, int]]] = {}
        self.holes: list[tuple[str, int, str]] = []
        all_names: list[str] = []
        for cls in NATIVE_CLASSES:
            all_names.extend(table(self.old, cls))
            all_names.extend(table(self.native, cls, self.kernel))
        for label, cls, parent in LEGACY_CLASSES:
            all_names.extend(table(self.images[label], cls))
        prime_method_keys(all_names)
        for cls in NATIVE_CLASSES:
            old = table(self.old, cls)
            new = table(self.native, cls, self.kernel)
            self.old_tables[cls] = old
            self.new_tables[cls] = new
            keyed = {method_key(n): i for i, n in enumerate(new)}
            entries = []
            for offset, name in enumerate(old):
                key = method_key(name)
                if key in keyed:
                    entries.append(("native", cls, keyed[key] * 8))
                else:
                    entries.append(("absent", name, 0))
                    self.holes.append((cls, offset * 8, name))
            self.old_views[cls] = entries
            self.tables[cls] = [("native", cls, i * 8) for i in range(len(new))]
        for label, cls, parent in LEGACY_CLASSES:
            image = self.images[label]
            old = table(image, cls)
            self.old_tables[cls] = old
            parent_old = self.old_tables[parent]
            parent_new = self.new_tables[parent]
            keyed = {method_key(n): i for i, n in enumerate(parent_new)}
            new = list(parent_new)
            physical = list(self.tables[parent])
            logical = []
            for i, name in enumerate(old):
                key = method_key(name)
                if i < len(parent_old) and name == parent_old[i]:
                    logical.append(self.old_views[parent][i])
                    continue
                if name in image.defined():
                    entry = (label, name, image.names[name][4])
                elif name in self.images["Legacy"].defined():
                    entry = (
                        "Legacy",
                        name,
                        self.images["Legacy"].names[name][4],
                    )
                elif key in keyed:
                    entry = self.tables[parent][keyed[key]]
                else:
                    entry = ("absent", name, 0)
                logical.append(entry)
                if i < len(parent_old) and key in keyed:
                    slot = keyed[key]
                    new[slot] = name
                    physical[slot] = entry
                elif i >= len(parent_old):
                    new.append(name)
                    physical.append(entry)
                elif entry[0] != "absent":
                    raise ValueError(f"Unmapped override: {cls} {name}")
            self.new_tables[cls] = new
            self.old_views[cls] = logical
            self.tables[cls] = physical

    def describe(self):
        sources = {
            "OldSky": PATHS["OldSky"],
            "Legacy": PATHS["Legacy"],
            "AirPort": PATHS[self.airport_source],
        }
        classes = {
            cls: {
                "oldSlotCount": len(self.old_tables[cls]),
                "nativeSlotCount": len(self.new_tables[cls]),
                "oldMethods": self.old_tables[cls],
                "nativeMethods": self.new_tables[cls],
                "legacyView": self.old_views[cls],
                "nativeView": self.tables[cls],
            }
            for cls in self.tables
        }
        return {
            "copyright": "Copyright © 2026 laobamac. All rights reserved.",
            "purpose": "Raw ABI evidence used by native_payload.py; build.py validates the executable adapter",
            "implementationStatus": "implemented",
            "hardwareValidation": "not-run-by-build",
            "system": self.system,
            "nativeUUID": self.native.uuid,
            "airPortSource": self.airport_source,
            "sourceSHA256": {
                key: hash_mach_source(path) for key, path in sources.items()
            },
            "classes": classes,
            "removedMethods": self.holes,
            "layouts": self.layouts(),
            "imports": self.imports(),
        }

    def layouts(self):
        result = {}
        for cls in NATIVE_CLASSES:
            result[cls] = {
                "old": class_size(self.old, cls),
                "native": class_size(self.native, cls),
            }
        for label, cls, parent in LEGACY_CLASSES:
            image = self.images[label]
            ktv = "__ZL" + str(len(cls) + 4) + cls + "_ktv"
            result[cls] = {
                "old": class_size(image, cls),
                "parent": parent,
                "allocationTypeView": image.names[ktv][4],
                "allocationTypeSize": struct.unpack(
                    "<I", image.read(image.names[ktv][4] + 44, 4)
                )[0],
            }
        return result

    def imports(self):
        result = {}
        for label, image in self.images.items():
            references = image.undef() & self.old.defined()
            absent = references - self.native.defined()
            result[label] = {
                "oldSkywalkImports": len(references),
                "missingInNative": sorted(absent),
                "relocations": {
                    name: [
                        address
                        for address, entry in image.relocs().items()
                        if entry[0] == name
                    ]
                    for name in sorted(absent)
                },
            }
        return result

    def close(self):
        for image in [
            self.old,
            self.native,
            self.kernel,
            *self.images.values(),
        ]:
            image.close()


def class_size(image, cls):
    name = "__ZN" + str(len(cls)) + cls + "9MetaClassC2Ev"
    address, data = image.funcbytes(name)
    sizes = [
        int(match[1])
        for _, _, text, _ in insns(data, address)
        if (match := re.fullmatch("movl\\s+\\$(\\d+), %ecx", text))
    ]
    if len(sizes) != 1:
        raise ValueError(f"Ambiguous class-size initializer: {cls}")
    return sizes[0]


def verify_model(model):
    checks = []

    def require(condition, name):
        if not condition:
            raise ValueError("ABI verification failed: " + name)
        checks.append(name)

    require(
        model.native.uuid == model.profile["skywalk"],
        model.system + " native UUID",
    )
    require(len(model.tables) == 18, "18 class tables decoded")
    for cls, old_size, native_size in [
        ("IOSkywalkInterface", 184, 176),
        (
            "IOSkywalkNetworkInterface",
            208,
            224 if model.profile["kernel"] == 25 else 208,
        ),
        ("IOSkywalkEthernetInterface", 272, model.profile["ethernetSize"]),
        ("IOSkywalkPacketBufferPool", 184, model.profile["poolSize"]),
        ("IOSkywalkPacket", 120, 112),
        ("IOSkywalkNetworkPacket", 128, 120),
    ]:
        require(
            class_size(model.old, cls) == old_size
            and class_size(model.native, cls) == native_size,
            cls + " class sizes",
        )
    cls = "IOSkywalkEthernetInterface"
    require(
        len(model.new_tables[cls]) == model.profile["ethernetSlots"],
        "Native Ethernet vtable length",
    )
    if model.profile["kernel"] == 25:
        require(
            "initBSDInterfaceParameters" in model.old_tables[cls][2256 // 8]
            and "registerNetworkInterfaceWithLogicalLink"
            in model.new_tables[cls][2256 // 8],
            "Ethernet vtable collision at 0x8d0",
        )
        require(
            "hwConfigNicProxyData" in model.old_tables[cls][2736 // 8]
            and "_RESERVEDIOSkywalkEthernetInterface0"
            in model.new_tables[cls][2736 // 8],
            "Ethernet reserved-slot collision at 0xab0",
        )
    old = model.images["Legacy"]
    require(
        old.read(683934, 7) == bytes.fromhex("48898318010000"),
        "Legacy controller pointer store at this+0x118",
    )
    name = "__ZN26IOSkywalkEthernetInterface4initEP12OSDictionary"
    address = model.native.names[name][4]
    offset = model.profile["ethernetSize"] - 8
    require(
        model.native.read(address + 38, 7)
        == b"\x48\x89\x83" + struct.pack("<I", offset),
        f"Native expansion pointer store at this+{offset:#x}",
    )
    refs = model.imports()
    require(
        refs["Legacy"]["oldSkywalkImports"] == 113
        and refs["BrcmTahoe"]["oldSkywalkImports"] == 148,
        "Skywalk dependency counts",
    )
    counts = {23: (1, 2), 24: (2, 3), 25: (2, 4)}[model.profile["kernel"]]
    require(
        (
            len(refs["Legacy"]["missingInNative"]),
            len(refs["BrcmTahoe"]["missingInNative"]),
        )
        == counts,
        "Skywalk missing-entry counts",
    )
    layouts = model.layouts()
    for label, cls, parent in LEGACY_CLASSES:
        require(
            layouts[cls]["old"] == layouts[cls]["allocationTypeSize"],
            cls + " original allocation metadata",
        )
    return checks


def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="Read-only native ABI audit; does not produce a bootable driver"
    )
    parser.add_argument("action", choices=["audit", "verify"])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--system", choices=list(SYSTEMS), default="Tahoe")
    args = parser.parse_args()
    model = NativeModel(args.system)
    try:
        result = model.describe()
        checks = verify_model(model) if args.action == "verify" else []
        result["auditChecks"] = checks
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(
            json.dumps(
                {
                    "nativeUUID": model.native.uuid,
                    "classes": len(model.tables),
                    "removedSlots": len(model.holes),
                    "auditChecksPassed": len(checks),
                    "outputKind": "abi-audit",
                },
                indent=2,
            )
        )
    finally:
        model.close()


if __name__ == "__main__":
    main()
