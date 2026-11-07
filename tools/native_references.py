#!/usr/bin/env python3
#
#  native_references.py
#  SimpleATH
#
#  Created by laobamac on 2026/11/3.
#  Copyright © 2026 laobamac. All rights reserved.
#

"""Checksum-validated, typed offline native ABI snapshot references.

The export command uses pinned system images; ordinary reference loading does
not run a native tool or compile a kernel extension.
"""

from __future__ import annotations

import argparse
import collections
from dataclasses import dataclass
import functools
import hashlib
import importlib
import json
import os
from pathlib import Path
import stat
import subprocess  # ruff: ignore[suspicious-subprocess-import] - Export-only nm with a fixed argv and no shell.
import sys
from typing import Protocol
from typing import TypeIs
from typing import TypedDict
from typing import final
from typing import runtime_checkable

if __package__:
    from tools.abi_types import json_object
    from tools.bootstrap import ROOT
    from tools.system_profiles import SYSTEMS
    from tools.system_profiles import native_source_paths
    from tools.system_profiles import system_volumes
else:
    from abi_types import json_object
    from bootstrap import ROOT
    from system_profiles import SYSTEMS
    from system_profiles import native_source_paths
    from system_profiles import system_volumes

DIRECTORY = ROOT / "src/platform/abi"
KERNEL = "com.apple.kernel"
SKYWALK = "com.apple.iokit.IOSkywalkFamily"
WIRELESS = "com.apple.iokit.IO80211Family"


TEXT_SECTION = "__text"
MAX_REFERENCE_BYTES = 8 * 1024 * 1024
MAX_REFERENCE_MANIFEST_BYTES = 1024 * 1024
EXPORT_ACTION = "export"
VERIFY_ACTION = "verify"
NM_PROGRAM = "nm"
DEFAULT_BINARY = (
    ROOT
    / "build/DerivedData/Build/Products/Release"
    / "SimpleATH.kext/Contents/MacOS/SimpleATH"
)
PAIR_FIELDS = 2
VTABLE_FIELDS = 3


class _ImageRecord(TypedDict):
    uuid: str
    exports: list[str]
    symbols: dict[str, int]
    tables: dict[str, list[str]]
    functions: dict[str, tuple[int, str]]
    ranges: list[tuple[int, str]]


class _LibraryRecord(TypedDict):
    uuid: str
    exports: list[str]
    symbols: dict[str, int]


class _LinkSearch(TypedDict):
    textSHA256: str
    matches: list[int]


class _NativeReference(TypedDict):
    file: str
    project: str
    createdBy: str
    createdOn: str
    copyright: str
    schemaVersion: int
    system: str
    profile: object
    collectionUUID: str
    kernelVersion: str
    images: dict[str, _ImageRecord]
    libraries: dict[str, _LibraryRecord]
    pointers: dict[str, int]
    linkSearch: _LinkSearch


def _is_object_dict(value: object) -> TypeIs[dict[object, object]]:
    return isinstance(value, dict)


def _is_list(value: object) -> TypeIs[list[object]]:
    return isinstance(value, list)


def _is_mapping(value: object) -> TypeIs[dict[str, object]]:
    return _is_object_dict(value) and all(isinstance(key, str) for key in value)


def _mapping(value: object) -> dict[str, object]:
    if not _is_mapping(value):
        message = "Native ABI reference entry must be a string-keyed object"
        raise TypeError(message)
    return value


def _string(value: object) -> str:
    if not isinstance(value, str):
        message = "Native ABI reference expected a string"
        raise TypeError(message)
    return value


def _integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        message = "Native ABI reference expected an integer"
        raise TypeError(message)
    return value


def _strings(value: object) -> list[str]:
    if not _is_list(value):
        message = "Native ABI reference expected an array of strings"
        raise TypeError(message)
    return [_string(item) for item in value]


def _integers(value: object) -> list[int]:
    if not _is_list(value):
        message = "Native ABI reference expected an array of integers"
        raise TypeError(message)
    return [_integer(item) for item in value]


def _symbols(value: object) -> dict[str, int]:
    return {name: _integer(item) for name, item in _mapping(value).items()}


def _tables(value: object) -> dict[str, list[str]]:
    return {name: _strings(item) for name, item in _mapping(value).items()}


def _pairs(value: object) -> list[tuple[int, str]]:
    if not _is_list(value):
        message = "Native ABI reference expected an array of offset/data pairs"
        raise TypeError(message)
    result: list[tuple[int, str]] = []
    for item in value:
        if not _is_list(item) or len(item) != PAIR_FIELDS:
            message = "Native ABI reference expected a two-element pair"
            raise TypeError(message)
        result.append((_integer(item[0]), _string(item[1])))
    return result


def _image(value: object) -> _ImageRecord:
    data = _mapping(value)
    return {
        "uuid": _string(data.get("uuid")),
        "exports": _strings(data.get("exports")),
        "symbols": _symbols(data.get("symbols")),
        "tables": _tables(data.get("tables")),
        "functions": _function_pairs(data.get("functions")),
        "ranges": _pairs(data.get("ranges")),
    }


def _function_pairs(value: object) -> dict[str, tuple[int, str]]:
    result: dict[str, tuple[int, str]] = {}
    for name, pair in _mapping(value).items():
        if not _is_list(pair) or len(pair) != PAIR_FIELDS:
            message = (
                "Native ABI reference expected a function address/data pair"
            )
            raise TypeError(message)
        result[name] = (_integer(pair[0]), _string(pair[1]))
    return result


def _library(value: object) -> _LibraryRecord:
    data = _mapping(value)
    return {
        "uuid": _string(data.get("uuid")),
        "exports": _strings(data.get("exports")),
        "symbols": _symbols(data.get("symbols")),
    }


def _link_search(value: object) -> _LinkSearch:
    data = _mapping(value)
    return {
        "textSHA256": _string(data.get("textSHA256")),
        "matches": _integers(data.get("matches")),
    }


def _decode_reference(value: object) -> _NativeReference:
    data = _mapping(value)
    return {
        "file": _string(data.get("file")),
        "project": _string(data.get("project")),
        "createdBy": _string(data.get("createdBy")),
        "createdOn": _string(data.get("createdOn")),
        "copyright": _string(data.get("copyright")),
        "schemaVersion": _integer(data.get("schemaVersion")),
        "system": _string(data.get("system")),
        "profile": data.get("profile"),
        "collectionUUID": _string(data.get("collectionUUID")),
        "kernelVersion": _string(data.get("kernelVersion")),
        "images": {
            name: _image(image)
            for name, image in _mapping(data.get("images")).items()
        },
        "libraries": {
            name: _library(image)
            for name, image in _mapping(data.get("libraries")).items()
        },
        "pointers": _symbols(data.get("pointers")),
        "linkSearch": _link_search(data.get("linkSearch")),
    }


def _read_reference_file(path: Path, limit: int) -> bytes:
    """Read a complete regular JSON file without following its final link.

    Returns:
        Immutable bytes from an unchanged, size-bounded regular file.

    Raises:
        ValueError: The source is empty, oversized, nonregular or changed.

    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            message = "Native reference file is not a bounded regular file"
            raise ValueError(message)
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    stable_identity = (
        after.st_dev == before.st_dev
        and after.st_ino == before.st_ino
        and after.st_size == before.st_size
    )
    stable_content = (
        len(data) == before.st_size and after.st_mtime_ns == before.st_mtime_ns
    )
    if not stable_identity or not stable_content:
        message = "Native reference changed while being read"
        raise ValueError(message)
    return data


@functools.cache
def load_reference(path: str | Path) -> _NativeReference:
    """Read only type-checked, checksum-matching pinned snapshot metadata.

    Returns:
        A checked reference record containing the image and collection APIs.

    Raises:
        ValueError: The snapshot hash, OS identity or source format is invalid.

    """
    source = Path(path)
    index = json_object(
        _read_reference_file(
            DIRECTORY / "manifest.json", MAX_REFERENCE_MANIFEST_BYTES
        )
    )
    expected = _string(_mapping(_mapping(index).get("files")).get(source.name))
    data = _read_reference_file(source, MAX_REFERENCE_BYTES)
    if hashlib.sha256(data).hexdigest() != expected:
        message = "Native ABI reference checksum mismatch: " + source.name
        raise ValueError(message)
    reference = _decode_reference(json_object(data))
    system = reference["system"]
    if (
        reference["schemaVersion"] != 1
        or system not in SYSTEMS
        or reference["profile"] != SYSTEMS[system]
    ):
        message = "Native ABI reference profile mismatch: " + source.name
        raise ValueError(message)
    return reference


def reference_paths() -> dict[str, Path]:
    """Return pinned snapshot or system-volume paths in the selected mode.

    Returns:
        Paths for all pinned OS profiles, or a complete-volume error.

    """
    return native_source_paths(DIRECTORY, system_volumes)


@final
class ReferenceImage:
    """Expose a verified offline snapshot through the native Mach interface."""

    def __init__(self, path: str | Path, entry: str) -> None:
        """Load one image from a checked reference document."""
        self.path = str(path)
        self.reference = load_reference(self.path)["images"][entry]
        self.uuid = self.reference["uuid"]
        exports = set(self.reference["exports"])
        self.names: dict[str, tuple[str, int, int, int, int]] = {
            name: (name, 15 if name in exports else 14, 1, 0, address)
            for name, address in self.reference["symbols"].items()
        }
        self.byaddr: collections.defaultdict[int, list[str]] = (
            collections.defaultdict(list)
        )
        for name, symbol in self.names.items():
            self.byaddr[symbol[4]].append(name)
        self.tables = self.reference["tables"]
        self.ranges = [
            (address, bytes.fromhex(data))
            for address, data in self.reference["ranges"]
        ]

    def defined(self) -> set[str]:
        """List symbols recorded as exports.

        Returns:
            Names of exported symbols.

        """
        return set(self.reference["exports"])

    def read(self, address: int, size: int) -> bytes:
        """Read bytes only within a stored range.

        Returns:
            An immutable copy of the requested bytes.

        Raises:
            ValueError: The requested range is not present.

        """
        for start, data in self.ranges:
            if (
                size >= 0
                and start <= address
                and address + size <= start + len(data)
            ):
                return data[address - start : address - start + size]
        message = f"Native ABI reference range missing: {address:#x}+{size:#x}"
        raise ValueError(message)

    def funcbytes(self, name: str) -> tuple[int, bytes]:
        """Read a recorded function body.

        Returns:
            The pinned function address and instruction bytes.

        """
        address, data = self.reference["functions"][name]
        return address, bytes.fromhex(data)

    def close(self) -> None:
        """No-op: references use immutable in-memory JSON records."""


@dataclass(frozen=True)
class ReferenceRoot:
    """Kernel collection identity from the pinned reference."""

    uuid: str


@dataclass(frozen=True)
class ReferenceLibrary:
    """Export set and addresses from one pinned collection image."""

    uuid: str
    symbols: dict[str, int]
    exports: set[str]


@final
class ReferenceCollection:
    """Expose a checked collection snapshot through the offline read API."""

    def __init__(self, path: str | Path) -> None:
        """Bind the collection UUID and library symbol indexes."""
        self.path = Path(path)
        reference = load_reference(self.path)
        self.reference = reference
        self.root = ReferenceRoot(uuid=reference["collectionUUID"])
        self.images = {
            name: ReferenceLibrary(
                symbols=image["symbols"],
                exports=set(image["exports"]),
                uuid=image["uuid"],
            )
            for name, image in reference["libraries"].items()
        }
        self.kernel = self.images[KERNEL]

    def pointer(self, address: int) -> int:
        """Look up a pinned relocation target.

        Returns:
            The referenced virtual address.

        """
        return self.reference["pointers"][str(address)]

    def version(self) -> str:
        """Return the pinned kernel version string.

        Returns:
            Version text recorded by the reference generator.

        """
        return self.reference["kernelVersion"]

    def close(self) -> None:
        """No-op: snapshot collection uses no mapped resources."""


class _ExportImage(Protocol):
    """Native image surface consumed by the offline snapshot exporter."""

    path: str | Path
    names: dict[str, tuple[str, int, int, int, int]]
    sects: list[tuple[str, str, int, int, int]]
    uuid: str | None

    def defined(self) -> set[str]: ...

    def read(self, address: int, size: int) -> bytes: ...

    def funcbytes(self, name: str) -> tuple[int, bytes]: ...

    def close(self) -> None: ...


class _ExportModel(Protocol):
    """Kernel image and release operation for one profile."""

    kernel: _ExportImage

    def close(self) -> None: ...


@runtime_checkable
class _ExportPlan(Protocol):
    """Subset of a profile plan consumed by snapshot generation."""

    system: str
    native: _ExportImage
    wireless: _ExportImage
    model: _ExportModel
    link_symbol: str
    link_bytes: bytes
    link_mask: bytes
    vtable_guards: list[tuple[str, int, str]]


class _ExportLibrary(Protocol):
    """Kernel collection symbol index required by the generator."""

    uuid: str | None
    symbols: dict[str, int]
    exports: set[str]


class _ExportCollectionRoot(Protocol):
    """Source collection's pinned UUID."""

    uuid: str | None


@runtime_checkable
class _ExportCollection(Protocol):
    """Bounded collection access for pure record-building helpers."""

    images: dict[str, _ExportLibrary]
    root: _ExportCollectionRoot

    def pointer(self, address: int) -> int: ...

    def version(self) -> str: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class _ImageSelection:
    """One logical image to record with its ABI vtable class set."""

    identifier: str
    image: _ExportImage
    classes: tuple[str, ...]


def _export_functions(
    plan: _ExportPlan, selected: _ImageSelection
) -> dict[str, list[int | str]]:
    """Collect bounded method body bytes from the selected native image.

    Returns:
        Function-address and hex-byte pairs for the legacy JSON schema.

    """
    functions: dict[str, list[int | str]] = {}
    image = selected.image
    if selected.identifier != KERNEL:
        for cls in selected.classes:
            name = "__ZN" + str(len(cls)) + cls + "9MetaClassC2Ev"
            address, data = image.funcbytes(name)
            functions[name] = [address, data.hex()]
    if selected.identifier == SKYWALK:
        address, data = image.funcbytes(plan.link_symbol)
        functions[plan.link_symbol] = [address, data.hex()]
    if selected.identifier == WIRELESS:
        functions.update(_client_free_functions(selected))
    return functions


def _client_free_functions(
    selected: _ImageSelection,
) -> dict[str, list[int | str]]:
    """Record the selected client free() methods.

    Returns:
        Original client free() address/hex-byte pairs.

    """
    functions: dict[str, list[int | str]] = {}
    for cls in selected.classes:
        name = "__ZN" + str(len(cls)) + cls + "4freeEv"
        address, data = selected.image.funcbytes(name)
        functions[name] = [address, data.hex()]
    return functions


def _export_ranges(selected: _ImageSelection) -> list[list[int | str]]:
    """Capture the version, initializer and power-state fixed read slices.

    Returns:
        Source address and hex bytes for each required fixed-size read.

    """
    image = selected.image
    ranges: list[list[int | str]] = []
    if selected.identifier == KERNEL:
        for name in ("_version_major", "_version_minor", "_version_revision"):
            address = image.names[name][4]
            ranges.append([address, image.read(address, 4).hex()])
    if selected.identifier == SKYWALK:
        name = "__ZN26IOSkywalkEthernetInterface4initEP12OSDictionary"
        address = image.names[name][4] + 38
        ranges.append([address, image.read(address, 7).hex()])
        address = image.names["__ZL13myPowerStates"][4]
        ranges.append([address, image.read(address, 192).hex()])
    return ranges


def _native_table(
    image: _ExportImage, cls: str, kernel: _ExportImage
) -> list[str]:
    """Validate the dynamic legacy native vtable reader at its boundary.

    Returns:
        String method names from the offline source reader.

    Raises:
        TypeError: The legacy reader is missing or its result is malformed.

    """
    name = "tools.native_abi" if __package__ else "native_abi"
    module = importlib.import_module(name)
    reader: object = vars(module).get("table")
    if not callable(reader):
        message = "Native ABI vtable reader is not callable"
        raise TypeError(message)
    result: object = reader(image, cls, kernel)
    return _strings(result)


def _export_image(
    plan: _ExportPlan, selection: _ImageSelection, required: set[str]
) -> dict[str, object]:
    """Collect a snapshot image's named symbols and bounded byte slices.

    Returns:
        A JSON-serializable image record using the legacy field names.

    """
    image = selection.image
    tables = {
        cls: _native_table(image, cls, plan.model.kernel)
        for cls in selection.classes
    }
    functions = _export_functions(plan, selection)
    ranges = _export_ranges(selection)
    names = required | {name for methods in tables.values() for name in methods}
    names |= {
        name for name in image.defined() if name.endswith("10gMetaClassE")
    }
    if selection.identifier == SKYWALK:
        names |= image.defined()
    if selection.identifier == KERNEL:
        names |= {"_version_major", "_version_minor", "_version_revision"}
    if selection.identifier == SKYWALK:
        names.add("__ZL13myPowerStates")
    names |= set(functions)
    return {
        "uuid": _string(image.uuid),
        "symbols": {
            name: image.names[name][4]
            for name in sorted(names & image.names.keys())
        },
        "exports": sorted(names & image.defined()),
        "tables": tables,
        "functions": functions,
        "ranges": ranges,
    }


def _is_object_tuple(value: object) -> TypeIs[tuple[object, ...]]:
    """Narrow an imported runtime tuple before examining each member.

    Returns:
        Whether the value is a tuple of objects.

    """
    return isinstance(value, tuple)


def _class_names(module: str, attribute: str) -> tuple[str, ...]:
    """Load a checked class catalog without creating a module import cycle.

    Returns:
        Strict string class names in their canonical catalog order.

    Raises:
        TypeError: The referenced module does not contain a valid catalog.

    """
    qualified = f"tools.{module}" if __package__ else module
    member: object = vars(importlib.import_module(qualified)).get(attribute)
    if not _is_object_tuple(member):
        message = f"Native class catalog is not a tuple: {qualified}"
        raise TypeError(message)
    names: list[str] = []
    for item in member:
        if not isinstance(item, str):
            message = f"Native class catalog is not all strings: {qualified}"
            raise TypeError(message)
        names.append(item)
    return tuple(names)


def _export_images(plan: _ExportPlan, required: set[str]) -> dict[str, object]:
    """Build all three image records in their original order.

    Returns:
        Image records indexed by their collection bundle identifiers.

    """
    native_classes = _class_names("native_abi", "NATIVE_CLASSES")
    client_classes = _class_names("native_payload", "CLIENT_CLASSES")

    selected = (
        _ImageSelection(KERNEL, plan.model.kernel, ("IOService",)),
        _ImageSelection(SKYWALK, plan.native, native_classes),
        _ImageSelection(WIRELESS, plan.wireless, client_classes),
    )
    return {
        item.identifier: _export_image(plan, item, required)
        for item in selected
    }


def _export_libraries(
    collection: _ExportCollection, names: list[str], required: set[str]
) -> dict[str, object]:
    """Collect only imported or required collection symbols.

    Returns:
        Per-library export sets for the reference JSON.

    """
    records: dict[str, object] = {}
    for identifier in dict.fromkeys((KERNEL, *names, WIRELESS)):
        if identifier not in collection.images:
            continue
        image = collection.images[identifier]
        records[identifier] = {
            "uuid": _string(image.uuid),
            "symbols": {
                name: image.symbols[name]
                for name in sorted(required & image.symbols.keys())
            },
            "exports": sorted(required & image.exports),
        }
    return records


def _vtable_guards(value: object) -> list[tuple[str, int, str]]:
    """Reject malformed generated vtable guard tuples.

    Returns:
        Checked parent-name, byte offset, and method-name triples.

    Raises:
        TypeError: The vtable guard list has an invalid field or shape.

    """
    if not _is_list(value):
        message = "Native ABI vtable guards must be a list"
        raise TypeError(message)
    result: list[tuple[str, int, str]] = []
    for guard in value:
        if not _is_list(guard) or len(guard) != VTABLE_FIELDS:
            message = "Native ABI vtable guard must have three elements"
            raise TypeError(message)
        result.append((
            _string(guard[0]),
            _integer(guard[1]),
            _string(guard[2]),
        ))
    return result


def _export_pointers(
    collection: _ExportCollection, guards: list[tuple[str, int, str]]
) -> dict[str, int]:
    """Require an unambiguous collection owner for every vtable guard.

    Returns:
        Guarded virtual slot addresses and resolved pointer targets.

    Raises:
        ValueError: A guard is not uniquely attached to a library image.

    """
    pointers: dict[str, int] = {}
    for parent, offset, _ in guards:
        candidates = [
            image
            for image in collection.images.values()
            if parent in image.symbols
        ]
        if len(candidates) != 1:
            message = "Ambiguous reference vtable: " + parent
            raise ValueError(message)
        address = candidates[0].symbols[parent] + offset
        pointers[str(address)] = collection.pointer(address)
    return pointers


def _link_matches(
    source: bytes, pattern: bytes, mask: bytes, *, location: tuple[int, int]
) -> list[int]:
    """Return exact masked matches or refuse ambiguous/invalid link bytes.

    Returns:
        Absolute addresses matching the unique native logical-link pattern.

    Raises:
        ValueError: Malformed mask or nonunique/nonmatching data.

    """
    if not pattern:
        return []
    address, expected = location
    if len(pattern) != len(mask):
        message = "Native logical-link mask length does not match pattern"
        raise ValueError(message)
    matches = [
        address + offset
        for offset in range(max(0, len(source) - len(pattern) + 1))
        if all(
            (actual & bits) == (wanted & bits)
            for actual, wanted, bits in zip(
                source[offset : offset + len(pattern)],
                pattern,
                mask,
                strict=True,
            )
        )
    ]
    if matches != [expected]:
        message = "Native logical-link pattern is not unique"
        raise ValueError(message)
    return matches


def _export_link_search(plan: _ExportPlan) -> dict[str, object]:
    """Hash the chosen source text and locate its single masked link site.

    Returns:
        A text SHA-256 and source-absolute match address list.

    """
    section = next(
        section for section in plan.native.sects if section[0] == TEXT_SECTION
    )
    address, length = section[2:4]
    data = plan.native.read(address, length)
    expected = plan.native.names[plan.link_symbol][4] if plan.link_bytes else 0
    return {
        "textSHA256": hashlib.sha256(data).hexdigest(),
        "matches": _link_matches(
            data,
            plan.link_bytes,
            plan.link_mask,
            location=(address, expected),
        ),
    }


def _checked_collection(value: object) -> _ExportCollection:
    """Require the legacy collection's offline export interface.

    Returns:
        A runtime-checked collection reader.

    Raises:
        TypeError: The reader does not provide the expected operations.

    """
    if not isinstance(value, _ExportCollection):
        message = "Native ABI collection lacks required export interfaces"
        raise TypeError(message)
    return value


def open_export_collection(path: str | Path) -> _ExportCollection:
    """Load the export-only reader without an eager reference import cycle.

    Returns:
        A reader with the exact checked collection protocol.

    Raises:
        TypeError: The selected reader lacks its required export interface.

    """
    name = "tools.kernel_collection" if __package__ else "kernel_collection"
    module = importlib.import_module(name)
    factory: object = vars(module).get("KernelCollection")
    if not callable(factory):
        message = "Native kernel-collection factory is not callable"
        raise TypeError(message)
    return _checked_collection(factory(path))


def _export_one(
    plan: _ExportPlan, manifest: dict[str, object], required: set[str]
) -> bytes:
    """Materialize a single profile's reference record without writing it.

    Returns:
        Deterministic UTF-8 JSON for the selected pinned system.

    """
    collection = open_export_collection(plan.native.path)
    try:
        guards = _vtable_guards(manifest.get("nativeVtableGuards"))
        guards.extend(plan.vtable_guards)
        record: dict[str, object] = {
            "file": plan.system + ".json",
            "project": "SimpleATH",
            "createdBy": "laobamac",
            "createdOn": "2026/11/3",
            "copyright": "Copyright © 2026 laobamac. All rights reserved.",
            "schemaVersion": 1,
            "system": plan.system,
            "profile": SYSTEMS[plan.system],
            "collectionUUID": _string(collection.root.uuid),
            "kernelVersion": collection.version(),
            "images": _export_images(plan, required),
            "libraries": _export_libraries(
                collection, _strings(manifest.get("nativeLibraries")), required
            ),
            "pointers": _export_pointers(collection, guards),
            "linkSearch": _export_link_search(plan),
        }
        return (
            json.dumps(record, indent=2, ensure_ascii=False) + "\n"
        ).encode()
    finally:
        collection.close()


def _export_inputs(
    binary: Path,
) -> tuple[dict[str, object], set[str], list[object]]:
    """Load explicit export-only plans and independently validated manifest.

    Returns:
        The generator manifest, required symbol set and prepared plans.

    Raises:
        TypeError: The legacy preparation operation is unavailable.

    """
    from embed import OUTPUT  # ruff: ignore[import-outside-top-level] - Explicit export operation.
    from embed import generate  # ruff: ignore[import-outside-top-level] - Explicit export operation.
    from native_payload import SkywalkPlan  # ruff: ignore[import-outside-top-level] - Explicit export operation.

    os.environ["SIMPLEATH_NATIVE_SOURCE"] = "system"
    generate()
    manifest = _mapping(json_object((OUTPUT / "manifest.json").read_bytes()))
    required = set(_strings(manifest.get("nativeImports")))
    required.update(
        subprocess.check_output(  # ruff: ignore[subprocess-without-shell-equals-true] - Fixed argv, export-only nm.
            [NM_PROGRAM, "-u", "-j", str(binary)], text=True
        ).splitlines()
    )
    plans: list[object] = [SkywalkPlan(name) for name in SYSTEMS]
    module = importlib.import_module("native_payload")
    prepare: object = vars(module).get("prepare_native_guards")
    if not callable(prepare):
        message = "Native guard preparer is not callable"
        raise TypeError(message)
    _ = prepare(plans)
    return manifest, required, plans


def _checked_plan(value: object) -> _ExportPlan:
    """Require all fields before reading or writing one native plan.

    Returns:
        A runtime-checked plan carrying the export source interfaces.

    Raises:
        TypeError: An incomplete plan lacks required source interfaces.

    """
    if not isinstance(value, _ExportPlan):
        message = "Native plan lacks required export interfaces"
        raise TypeError(message)
    return value


def _write_snapshots(
    plans: list[object], manifest: dict[str, object], required: set[str]
) -> dict[str, str]:
    """Write all generated plan snapshots and compute their exact digests.

    Returns:
        File names mapped to the bytes written for each system.

    """
    hashes: dict[str, str] = {}
    for candidate in plans:
        plan = _checked_plan(candidate)
        try:
            data = _export_one(plan, manifest, required)
            path = DIRECTORY / (plan.system + ".json")
            _ = path.write_bytes(data)
            hashes[path.name] = hashlib.sha256(data).hexdigest()
        finally:
            plan.wireless.close()
            plan.model.close()
    return hashes


def export_references(binary: Path) -> None:
    """Export pinned native ABI snapshots from an explicitly supplied binary.

    Generated snapshots are source evidence, not proof of a native driver.
    This export-only entrypoint is never run by offline host tests.

    """
    manifest, required, plans = _export_inputs(binary)
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    hashes = _write_snapshots(plans, manifest, required)
    _write_manifest(hashes)
    load_reference.cache_clear()


def _write_manifest(hashes: dict[str, str]) -> None:
    """Record checksums only after every selected snapshot is written."""
    index = {
        "file": "manifest.json",
        "project": "SimpleATH",
        "createdBy": "laobamac",
        "createdOn": "2026/11/3",
        "copyright": "Copyright © 2026 laobamac. All rights reserved.",
        "schemaVersion": 1,
        "files": hashes,
    }
    _ = (DIRECTORY / "manifest.json").write_text(
        json.dumps(index, indent=2) + "\n"
    )


class _Arguments(argparse.Namespace):
    """Typed CLI arguments for snapshot export/verification."""

    action: str = VERIFY_ACTION
    binary: Path = DEFAULT_BINARY


def main() -> None:
    """Run an explicitly requested offline export or verify saved records."""
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("action", choices=(EXPORT_ACTION, VERIFY_ACTION))
    _ = parser.add_argument(
        "--binary",
        type=Path,
        default=DEFAULT_BINARY,
    )
    args = parser.parse_args(namespace=_Arguments())
    if args.action == EXPORT_ACTION:
        export_references(args.binary)
    for name in SYSTEMS:
        _ = load_reference(DIRECTORY / (name + ".json"))
    _ = sys.stdout.write(
        "Native ABI references verified: " + ", ".join(SYSTEMS) + "\n"
    )


if __name__ == "__main__":
    main()
