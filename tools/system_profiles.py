#!/usr/bin/env python3
#
#  system_profiles.py
#  SimpleATH
#
#  Created by laobamac on 2026/11/2.
#  Copyright © 2026 laobamac. All rights reserved.
#
"""Pinned macOS reference builds, native UUIDs, and offline validation rules."""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import plistlib
import sys
from typing import Protocol
from typing import TYPE_CHECKING
from typing import TypeIs
from typing import TypedDict
from typing import runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Callable


class _SystemProfile(TypedDict):
    kernel: int
    version: str
    build: str
    skywalk: str
    wireless: str
    ethernetSize: int
    poolSize: int
    ethernetSlots: int


@runtime_checkable
class _ImageView(Protocol):
    uuid: str | None


@runtime_checkable
class _CollectionView(Protocol):
    images: dict[str, _ImageView]

    def version(self) -> str: ...

    def close(self) -> None: ...


SYSTEMS: dict[str, _SystemProfile] = {
    "Sonoma": {
        "kernel": 23,
        "version": "14.8.8",
        "build": "23J620",
        "skywalk": "9F5908B5-BA4B-37E3-AC31-62E1D45F1589",
        "wireless": "EC4BA672-6E08-3AD2-B882-01690A960FF4",
        "ethernetSize": 272,
        "poolSize": 184,
        "ethernetSlots": 353,
    },
    "Sequoia": {
        "kernel": 24,
        "version": "15.8",
        "build": "24H23",
        "skywalk": "70DFAA8E-E369-3417-B6FD-B19FB6D5D49B",
        "wireless": "13D3592A-A6BE-35E7-984C-0ACD90A76356",
        "ethernetSize": 272,
        "poolSize": 184,
        "ethernetSlots": 352,
    },
    "Tahoe": {
        "kernel": 25,
        "version": "26.7.2",
        "build": "25G332",
        "skywalk": "A6EDB8DB-175B-3A49-8919-5769FCDB6BED",
        "wireless": "4C2B4969-2B92-3646-9512-C1769BE0F9A4",
        "ethernetSize": 288,
        "poolSize": 192,
        "ethernetSlots": 353,
    },
}
MACOS = "Darwin"
INTEL = "x86_64"
VERSION_PLIST = Path("System/Library/CoreServices/SystemVersion.plist")


def _is_object_dict(value: object) -> TypeIs[dict[object, object]]:
    return isinstance(value, dict)


def _is_mapping(value: object) -> TypeIs[dict[str, object]]:
    return _is_object_dict(value) and all(isinstance(key, str) for key in value)


def _decode_plist(data: bytes, decoder: Callable[[bytes], object]) -> object:
    return decoder(data)


def _system_info(path: Path) -> dict[str, object]:
    raw = _decode_plist(path.read_bytes(), plistlib.loads)
    if not _is_mapping(raw):
        message = f"Expected dictionary in {path}"
        raise ValueError(message)
    return raw


def system_volumes() -> dict[str, Path]:
    """Discover mounted offline volumes matching a pinned exact OS build.

    Returns:
        Matching system names and existing volume paths.

    """
    found: dict[str, Path] = {}
    reference_root = os.environ.get("SIMPLEATH_REFERENCE_ROOT")
    candidates = (
        [Path(reference_root) / name for name in SYSTEMS]
        if reference_root
        else [
            Path("/"),
            Path("/Volumes/Macintosh HD 1"),
            Path("/Volumes/Macintosh HD 2"),
        ]
    )
    for volume in candidates:
        path = volume / VERSION_PLIST
        if not path.is_file():
            continue
        info = _system_info(path)
        for name, profile in SYSTEMS.items():
            if (
                info.get("ProductVersion"),
                info.get("ProductBuildVersion"),
            ) == (profile["version"], profile["build"]):
                _ = found.setdefault(name, volume)
    return found


def system_volume(name: str) -> Path:
    """Return an available pinned system volume or refuse the lookup.

    Returns:
        The validated existing OS volume root.

    Raises:
        ValueError: The requested OS name or reference volume is unknown.

    """
    result = system_volumes().get(name)
    if result is None:
        build = SYSTEMS[name]["build"] if name in SYSTEMS else "unknown"
        message = f"Missing reference system: {name} {build}"
        raise ValueError(message)
    return result


def _reference_paths(provider: Callable[[], object]) -> dict[str, Path]:
    value = provider()
    if not _is_mapping(value):
        message = "Reference path index must be a dictionary"
        raise TypeError(message)
    paths: dict[str, Path] = {}
    for name, path in value.items():
        if not isinstance(path, Path):
            message = f"Invalid reference path: {name}"
            raise TypeError(message)
        paths[name] = path
    return paths


def _collection(
    factory: Callable[[Path], object], path: Path
) -> _CollectionView:
    value = factory(path)
    if not isinstance(value, _CollectionView):
        message = f"Invalid kernel collection interface: {path}"
        raise TypeError(message)
    return value


def _expected_uuid(image: _ImageView | None, expected: str) -> bool:
    return image is not None and image.uuid == expected.replace("-", "").lower()


def _check_uuid(
    collection: _CollectionView, name: str, profile: _SystemProfile
) -> None:
    identifiers = (
        ("com.apple.iokit.IOSkywalkFamily", profile["skywalk"]),
        ("com.apple.iokit.IO80211Family", profile["wireless"]),
    )
    for identifier, expected in identifiers:
        if not _expected_uuid(collection.images.get(identifier), expected):
            message = (
                f"{name}: {identifier} UUID differs from the reference profile"
            )
            raise RuntimeError(message)


def _check_profile(
    name: str,
    profile: _SystemProfile,
    path: Path,
    *,
    factory: Callable[[Path], object],
) -> dict[str, str]:
    collection = _collection(factory, path)
    try:
        version = collection.version()
        if int(version.split(".")[0]) != profile["kernel"]:
            message = (
                f"{name}: kernel version differs from the reference profile"
            )
            raise RuntimeError(message)
        _check_uuid(collection, name, profile)
        return {
            "reference": str(path),
            "build": profile["build"],
            "kernel": collection.version(),
            "skywalkUUID": profile["skywalk"],
            "wirelessUUID": profile["wireless"],
        }
    finally:
        collection.close()


def validate_reference_systems() -> dict[str, dict[str, str]]:
    """Validate three pinned Intel Mac OS image profiles before build use.

    Returns:
        Reference paths and verified kernel/version/UUID identities.

    Raises:
        RuntimeError: Host or reference images do not match their pins.

    """
    # Runtime imports are essential to avoid the intentional cycle through
    # native_references -> system_profiles when using snapshot mode.
    from kernel_collection import KernelCollection  # ruff: ignore[import-outside-top-level] - Breaks native_references import cycle.
    from native_references import reference_paths  # ruff: ignore[import-outside-top-level] - Delayed to avoid import cycle.

    if platform.system() != MACOS or platform.machine() != INTEL:
        message = "Build validation requires an Intel Mac"
        raise RuntimeError(message)
    references = _reference_paths(reference_paths)
    report: dict[str, dict[str, str]] = {}
    for name, profile in SYSTEMS.items():
        report[name] = _check_profile(
            name, profile, references[name], factory=KernelCollection
        )
    return report


if __name__ == "__main__":
    _ = sys.stdout.write(
        json.dumps(validate_reference_systems(), indent=2) + "\n"
    )
