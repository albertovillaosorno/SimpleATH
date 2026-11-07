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

import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import plistlib
import stat
import struct
import uuid
from typing import Never
from typing import cast
from typing import TypeIs

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


def checked_range(data, offset, size):
    if (
        offset < 0
        or size < 0
        or offset > len(data)
        or size > len(data) - offset
    ):
        raise ValueError("Mach-O range exceeds supplied file")
    return offset, offset + size


def cstring(data, offset, end):
    checked_range(data, offset, end - offset)
    terminator = data.find(b"\0", offset, end)
    if terminator < 0:
        raise ValueError("Unterminated Mach-O string")
    return data[offset:terminator].decode("utf-8", errors="strict")


def image_inventory(data, header_offset):
    """Inventory symbols without treating an nlist as an export allowlist.

    File offsets in a fileset child refer to the supplied collection, not to
    the child's header. Only thin little-endian x86_64 filesets are accepted.
    No relocation, fixup, pointer, vtable or instruction processing is done.
    """
    checked_range(data, header_offset, 32)
    magic, cpu, _, filetype, count, command_bytes, _, _ = struct.unpack_from(
        "<8I", data, header_offset
    )
    if magic != 0xFEEDFACF or cpu != 0x01000007:
        raise ValueError("Expected thin little-endian x86_64 Mach-O")
    position = header_offset + 32
    _, commands_end = checked_range(data, position, command_bytes)
    if count > command_bytes // 8:
        raise ValueError("Invalid Mach-O command count")
    result = {
        "uuid": None,
        "symbols": {},
        "entries": {},
        "exportTriePresent": False,
        "symbolEvidence": "defined_global_nlist_candidates",
    }
    symtab = None
    for _ in range(count):
        if commands_end - position < 8:
            raise ValueError("Truncated Mach-O load command")
        command, size = struct.unpack_from("<II", data, position)
        if size < 8 or size % 8 or size > commands_end - position:
            raise ValueError("Invalid Mach-O load command size")
        if command == 0x1B:  # LC_UUID
            if size != 24 or result["uuid"] is not None:
                raise ValueError("Invalid or duplicate LC_UUID")
            result["uuid"] = str(
                uuid.UUID(bytes=data[position + 8 : position + 24])
            ).upper()
        elif command == 0x2:  # LC_SYMTAB
            if size != 24 or symtab is not None:
                raise ValueError("Invalid or duplicate LC_SYMTAB")
            symtab = struct.unpack_from("<4I", data, position + 8)
        elif command == 0x80000035:  # LC_FILESET_ENTRY
            if size < 32:
                raise ValueError("Truncated LC_FILESET_ENTRY")
            _, offset, string_offset, _ = struct.unpack_from(
                "<QQII", data, position + 8
            )
            if string_offset < 32 or string_offset >= size:
                raise ValueError("Invalid fileset entry name offset")
            name = cstring(data, position + string_offset, position + size)
            if not name or name in result["entries"]:
                raise ValueError("Empty or duplicate fileset entry name")
            checked_range(data, offset, 32)
            result["entries"][name] = offset
        elif command == 0x80000033:  # LC_DYLD_EXPORTS_TRIE
            if size != 16:
                raise ValueError("Invalid LC_DYLD_EXPORTS_TRIE")
            offset, length = struct.unpack_from("<II", data, position + 8)
            checked_range(data, offset, length)
            result["exportTriePresent"] = length != 0
        elif command in (0x22, 0x80000022):  # LC_DYLD_INFO[_ONLY]
            if size != 48:
                raise ValueError("Invalid LC_DYLD_INFO")
            offset, length = struct.unpack_from("<II", data, position + 40)
            checked_range(data, offset, length)
            result["exportTriePresent"] |= length != 0
        position += size
    if position != commands_end:
        raise ValueError("Mach-O command bytes/count disagree")
    if symtab is not None:
        offset, count, strings, string_bytes = symtab
        checked_range(data, offset, count * 16)
        _, strings_end = checked_range(data, strings, string_bytes)
        for index in range(count):
            name_index, kind, section, _, _ = struct.unpack_from(
                "<IBBHQ", data, offset + index * 16
            )
            # Exclude STAB, private externals, undefined and indirect symbols.
            # Keep only public external N_SECT or N_ABS definitions.
            definition = kind & 0x0E
            if (
                kind & 0xE0
                or kind & 0x10
                or not kind & 1
                or definition not in (2, 14)
            ):
                continue
            if definition == 14 and section == 0:
                raise ValueError("Defined section symbol has no section")
            if name_index == 0:
                continue
            if name_index >= string_bytes:
                raise ValueError("Symbol name exceeds Mach-O string table")
            name = cstring(data, strings + name_index, strings_end)
            if name:
                result["symbols"][name] = "global_definition_candidate"
    result["filetype"] = filetype
    return result


def load_collection(path):
    with (
        path.open("rb") as stream,
        mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data,
    ):
        digest = hashlib.sha256(data).hexdigest()
        root = image_inventory(data, 0)
        if root["filetype"] != 0xC:  # MH_FILESET
            raise ValueError(
                "Expected a Mach-O fileset, not a standalone image"
            )
        images = {
            name: image_inventory(data, offset)
            for name, offset in root["entries"].items()
        }
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


def x86_slice(data):
    """Select the x86_64 slice without writing or executing a Mach-O image."""
    if data[:4] == b"\xcf\xfa\xed\xfe":
        return data
    if data[:4] != b"\xca\xfe\xba\xbe":
        raise ValueError("Expected thin Mach-O or big-endian FAT_MAGIC")
    checked_range(data, 0, 8)
    count = struct.unpack_from(">I", data, 4)[0]
    if not 1 <= count <= 16:
        raise ValueError("Invalid fat architecture count")
    checked_range(data, 8, count * 20)
    selected = None
    ranges = []
    for index in range(count):
        cpu, _, offset, size, alignment = struct.unpack_from(
            ">5I", data, 8 + index * 20
        )
        checked_range(data, offset, size)
        if (
            offset < 8 + count * 20
            or alignment > 31
            or offset % (1 << alignment)
        ):
            raise ValueError("Invalid fat slice offset/alignment")
        if any(offset < end and start < offset + size for start, end in ranges):
            raise ValueError("Overlapping fat slices")
        ranges.append((offset, offset + size))
        if cpu == 0x01000007:
            if selected is not None:
                raise ValueError("Ambiguous x86_64 slices")
            selected = data[offset : offset + size]
    if selected is None:
        raise ValueError("No x86_64 slice")
    return selected


KDK_FILE_LIMIT = 128 * 1024 * 1024
KDK_READ_CHUNK = 1024 * 1024


def read_kdk_file(root: Path, relative: str) -> bytes:
    """Read a bounded regular file within root without following symlinks.

    Each directory is opened relative to an already-open parent descriptor.
    Never trust a pre-open resolve/stat check: a hostile offline package could
    replace a symlink between validation and read. No live path is permitted
    through a symlink within the supplied KDK root.
    """
    path = Path(relative)
    parts = path.parts
    if path.is_absolute() or not parts or any(p in (".", "..") for p in parts):
        raise ValueError("KDK path must remain below the selected root")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    parent = os.open(root, directory_flags)
    try:
        for part in parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=parent)
            os.close(parent)
            parent = child
        descriptor = os.open(parts[-1], file_flags, dir_fd=parent)
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_size > KDK_FILE_LIMIT
            ):
                raise ValueError("KDK input must be a bounded regular file")
            result = bytearray()
            while True:
                chunk = os.read(
                    descriptor,
                    min(KDK_READ_CHUNK, KDK_FILE_LIMIT + 1 - len(result)),
                )
                if not chunk:
                    break
                result.extend(chunk)
                if len(result) > KDK_FILE_LIMIT:
                    raise ValueError("KDK input grew beyond inspection limit")
            after = os.fstat(descriptor)
            old = (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            new = (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            if old != new or len(result) != before.st_size:
                raise ValueError("KDK input changed during inspection")
            return bytes(result)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def load_kdk(root):
    """Read selected package files; never treat KDK files as loaded OS images."""
    files = {}

    def read(relative):
        data = read_kdk_file(root, relative)
        files[relative] = {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        return data

    version = plistlib.loads(
        read("System/Library/CoreServices/SystemVersion.plist")
    )
    if not isinstance(version, dict):
        raise ValueError("KDK SystemVersion.plist is not a dictionary")
    metadata = {
        "systemVersion": {
            key: version.get(key)
            for key in ("ProductName", "ProductVersion", "ProductBuildVersion")
        },
        "loadedImageProvenanceVerified": False,
        "files": files,
        "images": {},
    }
    images = {}
    for family in ("IOPCIFamily", "IO80211Family", "IOSkywalkFamily"):
        contents = "System/Library/Extensions/" + family + ".kext/Contents/"
        info = plistlib.loads(read(contents + "Info.plist"))
        if not isinstance(info, dict):
            raise ValueError("KDK family Info.plist is not a dictionary")
        identifier = "com.apple.iokit." + family
        if info.get("CFBundleIdentifier") != identifier:
            raise ValueError("Unexpected KDK bundle identifier")
        selected = x86_slice(read(contents + "MacOS/" + family))
        image = image_inventory(selected, 0)
        images[identifier] = image
        metadata["images"][identifier] = {
            "version": info.get("CFBundleVersion"),
            "compatibleVersion": info.get("OSBundleCompatibleVersion"),
            "dependencies": info.get("OSBundleLibraries"),
            "x86_64SliceSha256": hashlib.sha256(selected).hexdigest(),
            "x86_64SliceBytes": len(selected),
            "uuid": image["uuid"],
        }
        if family == "IOPCIFamily":
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
            metadata["images"][identifier]["configExportListEntries"] = len(
                exports
            )
    kernel_path = "System/Library/Kernels/kernel"
    try:
        kernel_data = read(kernel_path)
    except FileNotFoundError:
        # KDK packages may omit the standalone kernel. Do not follow optional
        # symlinks for the existence test or silently skip hostile paths.
        kernel_data = None
    if kernel_data is not None:
        selected = x86_slice(kernel_data)
        images["com.apple.kernel"] = image_inventory(selected, 0)
        metadata["images"]["com.apple.kernel"] = {
            "x86_64SliceSha256": hashlib.sha256(selected).hexdigest(),
            "x86_64SliceBytes": len(selected),
            "uuid": images["com.apple.kernel"]["uuid"],
        }
    # A directory has no file hash; each actual input and selected slice is hashed above.
    return None, metadata, images


def read_system_version(path: Path) -> tuple[bytes, str, str]:
    """Validate a supplied offline SystemVersion plist without following links.

    Returns:
        Original bounded bytes plus explicit OS version and build identifiers.

    Raises:
        ValueError: The plist is malformed or lacks required string metadata.

    """
    data = read_kdk_file(path.parent, path.name)
    version = plistlib.loads(data)
    if not isinstance(version, dict):
        raise ValueError("SystemVersion.plist must contain a dictionary")
    product = version.get("ProductVersion")
    build = version.get("ProductBuildVersion")
    if not isinstance(product, str) or not isinstance(build, str):
        raise ValueError("SystemVersion.plist requires version/build strings")
    if not product or not build:
        raise ValueError("SystemVersion.plist has empty version/build fields")
    return data, product, build


def inventory(
    path: Path,
    reference_mode: bool,
    system_version: Path | None = None,
    kdk_mode: bool = False,
) -> dict[str, object]:
    if kdk_mode:
        digest, metadata, images = load_kdk(path)
    else:
        digest, metadata, images = (
            load_reference(path) if reference_mode else load_collection(path)
        )
    groups = {}
    for label, (image_name, classes) in GROUPS.items():
        image = images.get(image_name)
        if image is None:
            groups[label] = {
                "image": image_name,
                "state": "image_not_in_supplied_evidence",
            }
            continue
        symbols = {
            name: evidence
            for name, evidence in sorted(image["symbols"].items())
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
    supplied_system = None
    if system_version is not None:
        data, product, build = read_system_version(system_version)
        supplied_system = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "version": product,
            "build": build,
            "pairedToCollectionVerified": False,
        }
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
        "suppliedSystemVersion": supplied_system,
        "imageNames": sorted(images),
        "groups": groups,
        "nativePciAbiVerified": False,
        "nativeWirelessAbiVerified": False,
        "limitations": [
            "Missing images mean missing evidence, not missing OS APIs.",
            "Nlist definitions are candidates, not a verified KPI export allowlist.",
            "Export tries, reexports and KPI dependency/version eligibility are not resolved.",
            "No C++ class size, vtable, selector, key-path or packet-lifetime contract is proven.",
            "A supplied SystemVersion plist is not proof of collection provenance or pairing.",
            "KDK files/export lists are package evidence, not attested loaded production images.",
            "No source compilation, Mach-O import/relocation validation, load or hardware test is performed.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument(
        "--reference", type=Path, help="retained native ABI JSON reference"
    )
    inputs.add_argument(
        "--collection", type=Path, help="already acquired x86_64 kernel fileset"
    )
    inputs.add_argument(
        "--kdk-root",
        type=Path,
        help="already extracted KDK root containing System/Library; no install/mount",
    )
    parser.add_argument(
        "--system-version",
        type=Path,
        help="optional already acquired SystemVersion.plist",
    )
    args = parser.parse_args()
    try:
        result = inventory(
            args.reference or args.collection or args.kdk_root,
            args.reference is not None,
            args.system_version,
            args.kdk_root is not None,
        )
    except (OSError, ValueError, KeyError, TypeError, struct.error) as error:
        parser.exit(2, f"Static ABI inventory failed: {error}\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
