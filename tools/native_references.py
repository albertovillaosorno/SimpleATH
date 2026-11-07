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
import json
import os
from pathlib import Path
import subprocess  # ruff: ignore[suspicious-subprocess-import] - Export-only nm with a fixed argv and no shell.
from typing import TypeIs
from typing import TypedDict
from typing import final

if __package__:
    from tools.abi_types import json_object
    from tools.bootstrap import ROOT
    from tools.system_profiles import SYSTEMS
    from tools.system_profiles import system_volumes
else:
    from abi_types import json_object
    from bootstrap import ROOT
    from system_profiles import SYSTEMS
    from system_profiles import system_volumes

DIRECTORY = ROOT / "src/platform/abi"
KERNEL = "com.apple.kernel"
SKYWALK = "com.apple.iokit.IOSkywalkFamily"
WIRELESS = "com.apple.iokit.IO80211Family"


SOURCE_SNAPSHOT = "snapshot"
SOURCE_SYSTEM = "system"
TEXT_SECTION = "__text"
EXPORT_ACTION = "export"
VERIFY_ACTION = "verify"
NM_PROGRAM = "nm"
PAIR_FIELDS = 2


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


@functools.cache
def load_reference(path: str | Path) -> _NativeReference:
    """Read only type-checked, checksum-matching pinned snapshot metadata.

    Returns:
        A checked reference record containing the image and collection APIs.

    Raises:
        ValueError: The snapshot hash, OS identity or source format is invalid.

    """
    source = Path(path)
    index = json_object((DIRECTORY / "manifest.json").read_bytes())
    expected = _string(_mapping(_mapping(index).get("files")).get(source.name))
    data = source.read_bytes()
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
    """Select only snapshots or complete pinned system-mode volumes.

    Returns:
        Paths for all pinned profiles in the selected reference mode.

    Raises:
        ValueError: The mode is unsupported or system volumes are incomplete.

    """
    source = os.environ.get("SIMPLEATH_NATIVE_SOURCE", SOURCE_SNAPSHOT)
    if source == SOURCE_SNAPSHOT:
        return {name: DIRECTORY / (name + ".json") for name in SYSTEMS}
    if source != SOURCE_SYSTEM:
        message = "SIMPLEATH_NATIVE_SOURCE must be snapshot or system"
        raise ValueError(message)
    volumes = system_volumes()
    if set(volumes) != set(SYSTEMS):
        message = (
            "All three reference system volumes are required for system mode"
        )
        raise ValueError(message)
    return {
        name: volumes[name]
        / "System/Library/KernelCollections/BootKernelExtensions.kc"
        for name in SYSTEMS
    }


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


def export_references(binary):
    from embed import OUTPUT
    from embed import generate
    from kernel_collection import KernelCollection
    from native_abi import NATIVE_CLASSES
    from native_abi import table
    from native_payload import CLIENT_CLASSES
    from native_payload import SkywalkPlan
    from native_payload import prepare_native_guards

    os.environ["SIMPLEATH_NATIVE_SOURCE"] = "system"
    generate()
    manifest = json.loads((OUTPUT / "manifest.json").read_text())
    required = set(manifest["nativeImports"])
    required.update(
        subprocess.check_output(
            ["nm", "-u", "-j", str(binary)], text=True
        ).splitlines()
    )
    plans = [SkywalkPlan(name) for name in SYSTEMS]
    prepare_native_guards(plans)
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for plan in plans:
        collection = KernelCollection(plan.native.path)
        images = {}
        for identifier, image, classes in (
            (KERNEL, plan.model.kernel, ("IOService",)),
            (SKYWALK, plan.native, NATIVE_CLASSES),
            (WIRELESS, plan.wireless, CLIENT_CLASSES),
        ):
            tables = {
                cls: table(image, cls, plan.model.kernel) for cls in classes
            }
            functions = {}
            ranges = []
            names = required | {
                n for methods in tables.values() for n in methods
            }
            names |= {
                name
                for name in image.defined()
                if name.endswith("10gMetaClassE")
            }
            if identifier == SKYWALK:
                names |= image.defined()
            if identifier != KERNEL:
                for cls in classes:
                    name = "__ZN" + str(len(cls)) + cls + "9MetaClassC2Ev"
                    address, data = image.funcbytes(name)
                    functions[name] = [address, data.hex()]
                    names.add(name)
            if identifier == KERNEL:
                for name in (
                    "_version_major",
                    "_version_minor",
                    "_version_revision",
                ):
                    address = image.names[name][4]
                    ranges.append([address, image.read(address, 4).hex()])
                    names.add(name)
            if identifier == SKYWALK:
                name = "__ZN26IOSkywalkEthernetInterface4initEP12OSDictionary"
                address = image.names[name][4] + 38
                ranges.append([address, image.read(address, 7).hex()])
                name = "__ZL13myPowerStates"
                address = image.names[name][4]
                ranges.append([address, image.read(address, 192).hex()])
                names.add(name)
                address, data = image.funcbytes(plan.link_symbol)
                functions[plan.link_symbol] = [address, data.hex()]
            if identifier == WIRELESS:
                for cls in CLIENT_CLASSES:
                    name = "__ZN" + str(len(cls)) + cls + "4freeEv"
                    address, data = image.funcbytes(name)
                    functions[name] = [address, data.hex()]
                    names.add(name)
            names |= set(functions)
            images[identifier] = {
                "uuid": image.uuid,
                "symbols": {
                    n: image.names[n][4]
                    for n in sorted(names & image.names.keys())
                },
                "exports": sorted(names & image.defined()),
                "tables": tables,
                "functions": functions,
                "ranges": ranges,
            }
        libraries = {}
        for identifier in dict.fromkeys((
            KERNEL,
            *manifest["nativeLibraries"],
            WIRELESS,
        )):
            if identifier not in collection.images:
                continue
            image = collection.images[identifier]
            libraries[identifier] = {
                "uuid": image.uuid,
                "symbols": {
                    n: image.symbols[n]
                    for n in sorted(required & image.symbols.keys())
                },
                "exports": sorted(required & image.exports),
            }
        pointers = {}
        for parent, offset, method in (
            *manifest["nativeVtableGuards"],
            *plan.vtable_guards,
        ):
            candidates = [
                image
                for image in collection.images.values()
                if parent in image.symbols
            ]
            if len(candidates) != 1:
                raise ValueError("Ambiguous reference vtable: " + parent)
            address = candidates[0].symbols[parent] + offset
            pointers[str(address)] = collection.pointer(address)
        section = next(s for s in plan.native.sects if s[0] == "__text")
        address, length = section[2:4]
        text = plan.native.read(address, length)
        matches = []
        if plan.link_bytes:
            for offset in range(len(text) - len(plan.link_bytes) + 1):
                if all(
                    (a & m) == (b & m)
                    for a, b, m in zip(
                        text[offset : offset + len(plan.link_bytes)],
                        plan.link_bytes,
                        plan.link_mask,
                    )
                ):
                    matches.append(address + offset)
            if matches != [plan.native.names[plan.link_symbol][4]]:
                raise ValueError("Native logical-link pattern is not unique")
        reference = {
            "file": plan.system + ".json",
            "project": "SimpleATH",
            "createdBy": "laobamac",
            "createdOn": "2026/11/3",
            "copyright": "Copyright © 2026 laobamac. All rights reserved.",
            "schemaVersion": 1,
            "system": plan.system,
            "profile": SYSTEMS[plan.system],
            "collectionUUID": collection.root.uuid,
            "kernelVersion": collection.version(),
            "images": images,
            "libraries": libraries,
            "pointers": pointers,
            "linkSearch": {
                "textSHA256": hashlib.sha256(text).hexdigest(),
                "matches": matches,
            },
        }
        path = DIRECTORY / (plan.system + ".json")
        data = (
            json.dumps(reference, indent=2, ensure_ascii=False) + "\n"
        ).encode()
        path.write_bytes(data)
        hashes[path.name] = hashlib.sha256(data).hexdigest()
        collection.close()
        plan.wireless.close()
        plan.model.close()
    index = {
        "file": "manifest.json",
        "project": "SimpleATH",
        "createdBy": "laobamac",
        "createdOn": "2026/11/3",
        "copyright": "Copyright © 2026 laobamac. All rights reserved.",
        "schemaVersion": 1,
        "files": hashes,
    }
    (DIRECTORY / "manifest.json").write_text(json.dumps(index, indent=2) + "\n")
    load_reference.cache_clear()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("export", "verify"))
    parser.add_argument(
        "--binary",
        type=Path,
        default=ROOT
        / "build/DerivedData/Build/Products/Release/SimpleATH.kext/Contents/MacOS/SimpleATH",
    )
    args = parser.parse_args()
    if args.action == "export":
        export_references(args.binary)
    for name in SYSTEMS:
        load_reference(DIRECTORY / (name + ".json"))
    print("Native ABI references verified: " + ", ".join(SYSTEMS))


if __name__ == "__main__":
    main()
