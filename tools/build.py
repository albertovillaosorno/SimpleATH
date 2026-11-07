#!/usr/bin/env python3
#
#  build.py
#  SimpleATH
#
#  Created by laobamac on 2026/11/1.
#  Copyright © 2026 laobamac. All rights reserved.
#

"""Source-only native verification, deterministic build and package helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from typing import TYPE_CHECKING
from typing import TypeIs
import zipfile

from abi_types import integer
from abi_types import json_object
from abi_types import mapping
from abi_types import plist_object
from abi_types import sequence
from abi_types import string
from bootstrap import ROOT
from bootstrap import validate_payloads
from embed import ALIASES
from embed import LABELS
from embed import OUTPUT
from embed import VERSION
from embed_macho_parser import parse
from kernel_collection import KernelCollection
from macho import Image
from native_abi import Mach
from native_references import ReferenceCollection
from native_references import ReferenceImage
from native_references import reference_paths
from profiles import IMAGES
from source_fingerprint import source_fingerprint
from system_profiles import SYSTEMS
from system_profiles import validate_reference_systems
from verification_runtime import require_assertions_active
from verify import verify_abi
from verify_native import verify_native

if TYPE_CHECKING:
    from collections.abc import Callable
    from collections.abc import Iterable
    from collections.abc import Mapping

type PackageFragment = dict[str, dict[str, list[dict[str, str | bool]]]]

RELEASE_CHANNEL = "rel"
ANALYZE_ACTION = "analyze"
PACKAGE_ACTION = "package"
KEXT_EXECUTABLE = "SimpleATH"
BUNDLE_IDENTIFIER = "dev.alberto.SimpleATH"
SKYWALK_IDENTIFIER = "com.apple.iokit.IOSkywalkFamily"
LILU_IDENTIFIER = "Lilu"
NATIVE_BACKEND = "native"
JSON_SUFFIX = ".json"
TEXT_SECTION = "__text"
TAHOE_KERNEL_MAJOR = 25
MACH_KEXT_FILE_TYPE = 11
MACH_DYSYMTAB_COMMAND = 11
MACH_ABSOLUTE_SYMBOL_MASK = 14
MACH_EXTERNAL_DEFINED_SYMBOL = 15
MACH_POINTER_SIZE = 8
MACH_BRANCH_STUB = b"\xff\x25\0\0\0\0"
BUILD_WARNING_PREFIX = "warning:"
COPY_UUID_SYMBOL = "__ZN6OSKext8copyUUIDEv"
VTABLE_GUARD_FIELDS = 3

CONFIGURATIONS = ("Debug", "Release")
PROJECT = ROOT / "src/platform/SimpleATH.xcodeproj"


def package_name(
    configuration: str, channel: str = RELEASE_CHANNEL, sha: str | None = None
) -> str:
    """Generate a release or commit-pinned package name.

    Returns:
        A stable versioned package identifier.

    Raises:
        ValueError: The variant or commit hash is invalid.

    """
    if configuration not in CONFIGURATIONS or channel not in {
        "pre",
        RELEASE_CHANNEL,
    }:
        message = "Invalid package variant"
        raise ValueError(message)
    name = f"SimpleATH-v{VERSION}-{configuration.upper()}"
    if channel == RELEASE_CHANNEL:
        return name
    sha = (
        sha
        or os.environ.get("GITHUB_SHA")
        or subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
    )
    if not re.fullmatch(r"[0-9a-fA-F]{40}", sha):
        message = "Invalid commit SHA"
        raise ValueError(message)
    return f"{name}-alpha-{sha[:7].lower()}"


HOST = r"""
//
//  RelocationValidation.cpp
//  SimpleATH
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//
#include "Payload.hpp"
#include "NativeProfile.hpp"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

static unsigned restorationBoundaries() {
    const uint8_t base[] = {0, 1, 2, 3, 4, 5, 6, 7};
    const uint8_t delta[] = {0, 0, 0, 0, 2, 0, 0, 0, 9, 8, 7, 0, 0, 0, 1, 0, 0, 0, 0xaa};
    const uint8_t expected[] = {9, 8, 2, 3, 4, 5, 6, 0xaa};
    uint8_t arena[32];
    ath::Payload payload {};
    payload.bytes = base;
    payload.bytesSize = sizeof(base);
    payload.delta = delta;
    payload.deltaSize = sizeof(delta);
    payload.size = sizeof(base);
    payload.mappedSize = 16;
    payload.stubOffset = sizeof(base);
    payload.stubSize = 8;
    payload.checksum = ath::payloadChecksum(expected, sizeof(expected));
    ath::LinkedImage image {&payload, arena + 8, 0x1000, 0, false, true};
    memset(arena, 0x5a, sizeof(arena));
    assert(ath::restorePayload(image));
    assert(!memcmp(image.memory, expected, sizeof(expected)));
    for (size_t i = 0; i < 8; ++i)
        assert(arena[i] == 0x5a && image.memory[8 + i] == 0 && arena[24 + i] == 0x5a);
    assert(ath::relocateImage(image, nullptr, 0, nullptr, 0, nullptr, 0));
    const auto original = payload;
    unsigned rejected = 0;
    auto reject = [&]() {
        memset(arena, 0x5a, sizeof(arena));
        assert(!ath::restorePayload(image));
        for (auto byte : arena)
            assert(byte == 0x5a);
        payload = original;
        image = {&payload, arena + 8, 0x1000, 0, false, true};
        ++rejected;
    };
    payload.bytes = nullptr; reject();
    payload.bytesSize = 7; reject();
    payload.size = 0; reject();
    payload.mappedSize = 7; reject();
    payload.stubOffset = 7; reject();
    payload.stubSize = 9; reject();
    payload.delta = nullptr; reject();
    payload.deltaSize = 7; reject();
    payload.deltaSize = sizeof(delta) - 1; reject();
    image.payload = nullptr; reject();
    image.memory = nullptr; reject();
    image.editable = false; reject();
    image.registered = true; reject();
    image.address = UINTPTR_MAX - 7; reject();
    uint8_t bad[sizeof(delta)];
    for (auto offset : {uint32_t(8), UINT32_MAX}) {
        memcpy(bad, delta, sizeof(bad));
        memcpy(bad, &offset, 4);
        payload.delta = bad;
        reject();
    }
    for (auto length : {uint32_t(0), UINT32_MAX}) {
        memcpy(bad, delta, sizeof(bad));
        memcpy(bad + 4, &length, 4);
        payload.delta = bad;
        reject();
    }
    memcpy(bad, delta, sizeof(bad));
    bad[10] = 1;
    payload.delta = bad;
    reject();
    memcpy(bad, delta, sizeof(bad));
    bad[8] ^= 1;
    payload.delta = bad;
    assert(ath::restorePayload(image));
    assert(!ath::relocateImage(image, nullptr, 0, nullptr, 0, nullptr, 0));
    return rejected + 2;
}

int main(int argc, char **argv) {
    assert(argc == 6);
    const auto restorationChecks = restorationBoundaries();
    auto profile = ath::nativeSystemForKernel(static_cast<uint32_t>(atoi(argv[4])));
    assert(profile && !ath::nativeSystemForKernel(22) && !ath::nativeSystemForKernel(26));
    std::vector<uintptr_t> imports(ath::nativeImportCount);
    std::vector<uintptr_t> compatibility(ath::compatibilityImportCount);
    FILE *f = fopen(argv[1], "rb");
    assert(f && fread(imports.data(), 8, imports.size(), f) == imports.size());
    assert(fread(compatibility.data(), 8, compatibility.size(), f) == compatibility.size());
    fclose(f);
    unsigned linkChecks = 0;
    if (profile->ethernetLinkPattern.size) {
        f = fopen(argv[5], "rb");
        uint64_t header[3];
        assert(f && fread(header, sizeof(header), 1, f) == 1);
        std::vector<uint8_t> text(header[2]);
        assert(fread(text.data(), 1, text.size(), f) == text.size());
        fclose(f);
        const auto &pattern = profile->ethernetLinkPattern;
        auto find = [&](const std::vector<uint8_t> &bytes, uintptr_t base) {
            return ath::findNativeLink(bytes.data(), bytes.size(), base, pattern, imports.data(), imports.size());
        };
        assert(find(text, header[0]) == header[1]);
        ++linkChecks;
        constexpr uintptr_t slide = 0x20000000;
        for (auto &value : imports)
            value += slide;
        assert(find(text, header[0] + slide) == header[1] + slide);
        for (auto &value : imports)
            value -= slide;
        ++linkChecks;
        auto truncated = text;
        truncated.resize(pattern.size - 1);
        assert(!find(truncated, header[0]));
        ++linkChecks;
        auto damaged = text;
        const auto offset = header[1] - header[0];
        damaged[offset] ^= 0xff;
        assert(!find(damaged, header[0]));
        ++linkChecks;
        damaged = text;
        damaged[offset + pattern.references[0].offset] ^= 1;
        assert(!find(damaged, header[0]));
        ++linkChecks;
        auto duplicate = text;
        duplicate.insert(duplicate.end(), text.begin(), text.end());
        for (uint32_t i = 0; i < pattern.referenceCount; ++i) {
            const auto &reference = pattern.references[i];
            const auto position = text.size() + offset + reference.offset;
            const auto delta = imports[reference.target] - (header[0] + position + 4);
            const auto displacement = static_cast<int32_t>(delta);
            memcpy(duplicate.data() + position, &displacement, sizeof(displacement));
        }
        assert(!find(duplicate, header[0]));
        ++linkChecks;
    }
    const bool far = atoi(argv[3]) != 0;
    assert(ath::payloads[1].bytes == ath::payloads[2].bytes);
    assert(ath::payloads[1].relocations == ath::payloads[2].relocations);
    assert(ath::payloads[1].symbolValues == ath::payloads[2].symbolValues);
    assert(ath::payloads[1].symbols == ath::payloads[2].symbols);
    assert(ath::payloads[1].routes == ath::payloads[2].routes);
    ath::LinkedImage images[2] {};
    for (unsigned i = 0; i < 2; ++i) {
        auto &p = ath::payloads[i ? profile->airPortPayloadIndex : 0];
        images[i] = {&p, static_cast<uint8_t *>(calloc(1, p.mappedSize)),
                     (far ? 0xffffff9000000000ULL : 0xffffff8010000000ULL) + i * 0x2000000ULL,
                     0, false, true};
        assert(images[i].memory);
        assert(ath::restorePayload(images[i]));
        assert(ath::payloadChecksum(images[i].memory, p.size) == p.checksum);
        char path[4096];
        snprintf(path, sizeof(path), "%s/%u.restored.bin", argv[2], i);
        f = fopen(path, "wb");
        assert(f && fwrite(images[i].memory, 1, p.size, f) == p.size);
        fclose(f);
    }
    unsigned long total = 0;
    for (unsigned i = 0; i < 2; ++i) {
        assert(ath::relocateImage(images[i], images, 2, imports.data(), imports.size(), compatibility.data(), compatibility.size()));
        total += images[i].payload->relocationCount;
        char path[4096];
        snprintf(path, sizeof(path), "%s/%u.bin", argv[2], i);
        f = fopen(path, "wb");
        assert(f && fwrite(images[i].memory, 1, images[i].payload->mappedSize, f) == images[i].payload->mappedSize);
        fclose(f);
    }
    auto &image = images[0];
    const auto original = *image.payload;
    ath::Payload altered = original;
    image.payload = &altered;
    auto reset = [&]() {
        altered = original;
        image.stubUsed = 0;
        assert(ath::restorePayload(image));
    };
    reset();
    image.memory[0] ^= 1;
    assert(!ath::relocateImage(image, images, 2, imports.data(), imports.size(), compatibility.data(), compatibility.size()));
    reset();
    ath::Relocation bad {original.size, 0, 0, 0, 8, {}};
    altered.relocations = &bad;
    altered.relocationCount = 1;
    assert(!ath::relocateImage(image, images, 2, imports.data(), imports.size(), compatibility.data(), compatibility.size()));
    reset();
    bad = {0, ath::nativeImportCount, 0, 255, 8, {}};
    altered.relocations = &bad;
    altered.relocationCount = 1;
    assert(!ath::relocateImage(image, images, 2, imports.data(), imports.size(), compatibility.data(), compatibility.size()));
    reset();
    bad = {0, 0, 0, 253, 8, {}};
    altered.relocations = &bad;
    altered.relocationCount = 1;
    assert(!ath::relocateImage(image, images, 2, imports.data(), imports.size(), compatibility.data(), compatibility.size()));
    reset();
    altered.stubSize = 0;
    assert(!ath::allocateStub(image, 1));
    reset();
    image.editable = false;
    assert(!ath::relocateImage(image, images, 2, imports.data(), imports.size(), compatibility.data(), compatibility.size()));
    for (auto &entry : images)
        free(entry.memory);
    printf("{\"relocations\":%lu,\"negativeCases\":6,\"restorationChecks\":%u,\"nativeLinkChecks\":%u,\"farBranches\":%s}\n", total, restorationChecks, linkChecks, far ? "true" : "false");
}
"""


def require_invariant(
    condition: object, evidence: Callable[[], object] | None = None
) -> None:
    """Enforce a verifier invariant with failure-only diagnostic evaluation.

    Raises:
        AssertionError: The offline validation invariant did not hold.

    """
    if not condition:
        if evidence is None:
            raise AssertionError
        raise AssertionError(evidence())


def digest(path: Path | str) -> str:
    """Hash the contents of one source or verified artifact path.

    Returns:
        The lowercase SHA-256 hex digest.

    """
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fingerprint() -> str:
    """Hash the actual SimpleATH source tree before building or packaging.

    Returns:
        A reproducible digest of the current source/policy snapshot.

    """
    return source_fingerprint(ROOT)


def fragment(optional: bool = False) -> PackageFragment:
    """Describe the OpenCore entries for a verified package.

    Returns:
        A fresh plist-compatible fragment without filesystem activity.

    """
    entries: list[tuple[str, str]] = [("SimpleATH.kext", "SimpleATH")]
    if optional:
        entries[:0] = [
            ("Lilu.kext", "Lilu"),
            ("AirportBrcmFixup.kext", "AirportBrcmFixup"),
        ]
        entries.append((
            "AirportBrcmFixup.kext/Contents/PlugIns/AirPortBrcmNIC_Injector.kext",
            "",
        ))
    add = [
        {
            "Arch": "x86_64",
            "BundlePath": path,
            "Comment": "SimpleATH embedded stack"
            if exe == KEXT_EXECUTABLE
            else "User-supplied optional dependency",
            "Enabled": True,
            "ExecutablePath": "Contents/MacOS/" + exe if exe else "",
            "PlistPath": "Contents/Info.plist",
            "MinKernel": "23.0.0",
            "MaxKernel": "25.99.99",
        }
        for path, exe in entries
    ]
    return {"Kernel": {"Add": add, "Block": []}}


def save_plist(path: Path, value: PackageFragment) -> None:
    """Write a plist with its original package attribution header."""
    data = plistlib.dumps(value, sort_keys=False).decode()
    header = (
        f"<!--\n  {path.name}\n  SimpleATH\n\n  Created by laobamac on 2026/11/1.\n"
        "  Copyright © 2026 laobamac. All rights reserved.\n-->\n"
    )
    _ = path.write_text(
        data.replace("<!DOCTYPE", header + "<!DOCTYPE", 1), encoding="utf-8"
    )


def native_addresses(
    collection: KernelCollection | ReferenceCollection, libraries: Iterable[str]
) -> dict[str, int]:
    """Return only exported symbols from the kernel and selected libraries.

    Returns:
        Names and addresses eligible for the initial source-only import check.

    """
    kernel = collection.kernel
    available = {name: kernel.symbols[name] for name in kernel.exports}
    for name in libraries:
        if name in collection.images:
            image = collection.images[name]
            available.update({n: image.symbols[n] for n in image.exports})
    return available


def check_reference(
    folder: Path,
    addresses: Mapping[str, int],
    compatibility: Mapping[str, int],
    far: bool,
    labels: list[str],
) -> int:
    """Check a synthetic linked image against independently decoded imports.

    Returns:
        Number of relocation values checked in the offline test fixtures.

    """
    exports: list[dict[str, int]] = []
    images = [Image(IMAGES[name]) for name in labels]
    for image in images:
        _, symbols = parse(image)
        exports.append({
            n: v
            for n, t, _, _, v in symbols
            if t & MACH_EXTERNAL_DEFINED_SYMBOL == MACH_EXTERNAL_DEFINED_SYMBOL
        })
    bases = [
        (0xFFFFFF9000000000 if far else 0xFFFFFF8010000000) + i * 0x2000000
        for i in range(len(labels))
    ]
    checked = 0
    for i, image in enumerate(images):
        require_invariant(
            (folder / f"{i}.restored.bin").read_bytes()
            == (OUTPUT / (labels[i] + ".bin")).read_bytes()
        )
        actual = (folder / f"{i}.bin").read_bytes()
        commands, symbols = parse(image)
        ds = next(
            data for cmd, data in commands if cmd == MACH_DYSYMTAB_COMMAND
        )
        fields = struct.unpack_from("<18I", ds, 8)
        for external, field in [(True, 14), (False, 16)]:
            for n in range(fields[field + 1]):
                offset, bits = struct.unpack_from(
                    "<iI", image.data, fields[field] + n * 8
                )
                width = 1 << ((bits >> 25) & 3)
                addend = int.from_bytes(
                    image.read(offset, width), "little", signed=True
                )
                if external:
                    name, kind, _, _, value = symbols[bits & 0xFFFFFF]
                    if (
                        kind & MACH_ABSOLUTE_SYMBOL_MASK
                        == MACH_ABSOLUTE_SYMBOL_MASK
                    ):
                        target = bases[i] + value
                    else:
                        name = ALIASES.get(name, name)
                        matches = [
                            (j, exports[j][name])
                            for j in range(min(i, 2))
                            if name in exports[j]
                        ]
                        target = (
                            bases[matches[0][0]] + matches[0][1]
                            if matches
                            else (
                                compatibility[name]
                                if name in compatibility
                                else addresses[name]
                            )
                        )
                    expected = (target + addend) & 0xFFFFFFFFFFFFFFFF
                else:
                    expected = (bases[i] + addend) & 0xFFFFFFFFFFFFFFFF
                if width == MACH_POINTER_SIZE:
                    observed = struct.unpack_from("<Q", actual, offset)[0]
                else:
                    displacement = struct.unpack_from("<i", actual, offset)[0]
                    observed = (
                        bases[i] + offset + 4 + displacement
                    ) & 0xFFFFFFFFFFFFFFFF
                    if observed != expected:
                        stub = observed - bases[i]
                        require_invariant(0 <= stub <= len(actual) - 14)
                        require_invariant(
                            actual[stub : stub + len(MACH_BRANCH_STUB)]
                            == MACH_BRANCH_STUB
                        )
                        observed = struct.unpack_from("<Q", actual, stub + 6)[0]
                require_invariant(
                    observed == expected,
                    lambda i=i, offset=offset, observed=observed, expected=expected: (
                        labels[i],
                        hex(offset),
                        hex(observed),
                        hex(expected),
                    ),
                )
                checked += 1
        linked = Image(folder / f"{i}.bin")
        _, linked_symbols = parse(linked)
        for n, (name, kind, _, _, value) in enumerate(symbols):
            if (
                not kind & 0xE0
                and kind & MACH_ABSOLUTE_SYMBOL_MASK
                == MACH_ABSOLUTE_SYMBOL_MASK
            ):
                require_invariant(
                    linked_symbols[n][4] == value + bases[i],
                    lambda n=n, name=name: (n, name),
                )
    return checked


def _strings(value: object) -> list[str]:
    """Return a checked array of strings from a JSON reference.

    Returns:
        String elements with malformed values rejected.

    """
    return [string(item) for item in sequence(value)]


def vtable_rows(value: object) -> list[tuple[str, int, str]]:
    """Decode checked class, slot and method references.

    Returns:
        Ordered triples of symbol names and offsets.

    Raises:
        ValueError: A row lacks the required three fields.

    """
    rows: list[tuple[str, int, str]] = []
    for raw in sequence(value):
        parts = sequence(raw)
        if len(parts) != VTABLE_GUARD_FIELDS:
            message = "Native vtable guard must have exactly three fields"
            raise ValueError(message)
        rows.append((string(parts[0]), integer(parts[1]), string(parts[2])))
    return rows


def verify(configuration: str, references: Iterable[Path]) -> dict[str, object]:
    """Validate offline artifacts against the complete pinned reference set.

    Returns:
        A report of source-only checks, not evidence of device operation.

    Raises:
        TypeError: A reference collection reader has an unsupported type.

    """
    require_assertions_active()
    validate_payloads()
    source_fingerprint = fingerprint()
    manifest = json_object((OUTPUT / "manifest.json").read_text())
    payloads = [mapping(p) for p in sequence(manifest["payloads"])]
    system_profiles = [mapping(p) for p in sequence(manifest["systemProfiles"])]
    runtime_guards = mapping(manifest["nativeRuntimeGuards"])
    native_vtables = vtable_rows(manifest["nativeVtableGuards"])
    native_imports = _strings(manifest["nativeImports"])
    product = (
        ROOT
        / f"build/DerivedData/Build/Products/{configuration}/SimpleATH.kext"
    )
    binary = product / "Contents/MacOS/SimpleATH"
    evidence = json_object(
        (ROOT / f"build/Build-{configuration}.json").read_text()
    )
    require_invariant(evidence["sourceFingerprint"] == source_fingerprint)
    require_invariant(evidence["sha256"] == digest(binary))
    require_invariant(
        evidence["payloadManifestSHA256"] == digest(OUTPUT / "manifest.json")
    )
    image = Image(binary)
    require_invariant(
        struct.unpack_from("<I", image.data, 12)[0] == MACH_KEXT_FILE_TYPE
    )
    symbols = (
        product.parent
        / "SimpleATH.kext.dSYM/Contents/Resources/DWARF/SimpleATH"
    )
    require_invariant(Image(symbols).uuid == image.uuid)
    info = plist_object((product / "Contents/Info.plist").read_bytes())
    libraries = mapping(info["OSBundleLibraries"])
    require_invariant(info["CFBundleVersion"] == VERSION)
    require_invariant(info["CFBundleIdentifier"] == BUNDLE_IDENTIFIER)
    require_invariant(not any(LILU_IDENTIFIER in n for n in libraries))
    undefined = set(
        subprocess.check_output(
            ["nm", "-u", "-j", str(binary)], text=True
        ).splitlines()
    )
    require_invariant(
        not any(
            LILU_IDENTIFIER in n or n in {"_lilu", "_lilu_os_log"}
            for n in undefined
        )
    )
    require_invariant(COPY_UUID_SYMBOL not in undefined)
    for payload in payloads:
        storage = mapping(payload["storage"])
        stored = (OUTPUT / string(storage["file"])).read_bytes()
        require_invariant(len(stored) == integer(storage["storedSize"]))
        require_invariant(
            hashlib.sha256(stored).hexdigest()
            == string(storage["storedSHA256"])
        )
        require_invariant(image.data.count(stored) == 1)
    require_invariant((OUTPUT / "AirPort.bin").read_bytes() not in image.data)
    require_invariant(
        len(image.data) < 14 * 1024 * 1024,
        lambda: "Unexpected growth in the universal kext",
    )
    targets: list[dict[str, object]] = []
    addresses: dict[str, dict[str, int]] = {}
    verified_references: dict[str, Path] = {}
    for reference in references:
        c = KernelCollection(reference)
        if not isinstance(c, (KernelCollection, ReferenceCollection)):
            message = "Unexpected kernel collection reader implementation"
            raise TypeError(message)
        kernel = int(c.version().split(".")[0])
        profiles = [
            p for p in system_profiles if integer(p["kernel"]) == kernel
        ]
        require_invariant(
            len(profiles) == 1,
            lambda c=c: ("Unsupported reference kernel", c.version()),
        )
        profile = profiles[0]
        require_invariant(
            c.images["com.apple.iokit.IOSkywalkFamily"].uuid
            == string(profile["nativeUUID"]).replace("-", "").lower()
        )
        require_invariant(
            c.images["com.apple.iokit.IO80211Family"].uuid
            == string(profile["wirelessUUID"]).replace("-", "").lower()
        )
        available = native_addresses(c, libraries)
        missing = sorted(undefined - available.keys())
        require_invariant(
            not missing,
            lambda reference=reference, missing=missing: (
                str(reference),
                missing,
            ),
        )
        profile_name = string(profile["system"])
        system_guard = mapping(runtime_guards[profile_name])
        runtime_vtables = vtable_rows(system_guard["vtables"])
        for parent, offset, method in runtime_vtables:
            require_invariant(
                c.pointer(available[parent] + offset) == available[method]
            )
        for parent, offset, method in native_vtables:
            observed = c.pointer(available[parent] + offset)
            require_invariant(
                observed == available[method],
                lambda reference=reference, parent=parent, offset=offset, method=method: (
                    str(reference),
                    parent,
                    offset,
                    method,
                ),
            )
        targets.append({
            "system": profile_name,
            "build": profile["build"],
            "reference": str(reference),
            "referenceKind": "snapshot"
            if reference.suffix == JSON_SUFFIX
            else "kernel-collection",
            "kernel": c.version(),
            "uuid": c.root.uuid,
            "imports": len(undefined),
            "unmatchedImports": [],
            "nativeVtableGuards": len(native_vtables),
            "runtimeVtableGuards": len(runtime_vtables),
            "runtimeClassGuards": len(sequence(system_guard["classes"])),
        })
        addresses[profile_name] = available
        verified_references[profile_name] = reference
        c.close()
    require_invariant(addresses)
    adapter = mapping(manifest["nativeAdapter"])
    compatibility_imports = _strings(adapter["compatibilityImports"])
    compatibility_targets = _strings(adapter["compatibilityTargets"])
    require_invariant(manifest["skywalkBackend"] == NATIVE_BACKEND)
    require_invariant(LABELS == ["Legacy", "AirPortOriginal", "AirPort"])
    require_invariant(SKYWALK_IDENTIFIER in libraries)
    require_invariant(
        not any(p["identifier"] == SKYWALK_IDENTIFIER for p in payloads)
    )
    with tempfile.TemporaryDirectory(prefix="simpleath-verify-") as temporary:
        temp = Path(temporary)
        _ = (temp / "main.cpp").write_text(HOST)
        assembly = (
            (OUTPUT / "Payloads.S")
            .read_text()
            .split(".section __DATA_CONST")[0]
        )
        _ = (temp / "Payloads.S").write_text(assembly)
        executable = temp / "verify"
        _ = subprocess.run(
            [
                "xcrun",
                "clang++",
                "-std=c++14",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                "-I",
                str(ROOT / "src"),
                str(ROOT / "src/Relocate.cpp"),
                str(OUTPUT / "Payloads.cpp"),
                str(temp / "Payloads.S"),
                str(temp / "main.cpp"),
                "-o",
                str(executable),
            ],
            check=True,
        )
        runs: list[Mapping[str, object]] = []
        native_abi: dict[str, object] = {}
        for system, current in addresses.items():
            profile = SYSTEMS[system]
            reference = Mach(
                verified_references[system], "com.apple.iokit.IOSkywalkFamily"
            )
            symbol = next(
                string(p["ethernetLinkSymbol"])
                for p in system_profiles
                if string(p["system"]) == system
            )
            if isinstance(reference, ReferenceImage):
                start, code = reference.funcbytes(symbol)
            else:
                section = next(
                    s for s in reference.sects if s[0] == TEXT_SECTION
                )
                start, length = section[2:4]
                code = reference.read(start, length)
            length = len(code)
            _ = (temp / "native-link.bin").write_bytes(
                struct.pack("<3Q", start, reference.names[symbol][4], length)
                + code
            )
            reference.close()
            compatibility = {
                name: (
                    current[target]
                    if target in current
                    else 0xFFFFFF800F000000 + image.symbols[target]
                )
                for name, target in zip(
                    compatibility_imports,
                    compatibility_targets,
                    strict=True,
                )
            }
            _ = (temp / "imports.bin").write_bytes(
                b"".join(
                    struct.pack("<Q", current[name]) for name in native_imports
                )
                + b"".join(
                    struct.pack("<Q", compatibility[name])
                    for name in compatibility_imports
                )
            )
            labels = [
                "Legacy",
                "AirPort"
                if profile["kernel"] == TAHOE_KERNEL_MAJOR
                else "AirPortOriginal",
            ]
            for far in [False, True]:
                output = subprocess.check_output(
                    [
                        str(executable),
                        str(temp / "imports.bin"),
                        str(temp),
                        str(int(far)),
                        str(profile["kernel"]),
                        str(temp / "native-link.bin"),
                    ],
                    text=True,
                )
                run = json_object(output)
                run["system"] = system
                run["independentReferenceChecks"] = check_reference(
                    temp, current, compatibility, far, labels
                )
                runs.append(run)
            native_abi[system] = verify_native(temp, binary, system)
        abi = verify_abi(temp)
    require_invariant(source_fingerprint == fingerprint())
    result: dict[str, object] = {
        "version": VERSION,
        "configuration": configuration,
        "driverLoading": "embedded",
        "sourceFingerprint": source_fingerprint,
        "sha256": digest(binary),
        "uuid": image.uuid,
        "probeSHA256": digest(product.parent / "athprobe"),
        "nativeTargets": targets,
        "relocationValidation": runs,
        "sanitizers": ["AddressSanitizer", "UndefinedBehaviorSanitizer"],
        "abiValidation": abi,
        "nativeABIValidation": native_abi,
        "baseAddEntries": len(fragment()["Kernel"]["Add"]),
        "payloads": manifest["payloads"],
        "binarySize": len(image.data),
        "payloadStorage": manifest["payloadStorage"],
        "skywalkBackend": "native",
        "nativeAdapter": adapter,
        "systemProfiles": manifest["systemProfiles"],
        "kernelRegistrationExecuted": False,
        "openCoreLinkExecuted": False,
        "hardwareValidation": "not-run-by-build",
    }
    destination = ROOT / f"build/Validation-{configuration}.json"
    _ = destination.write_text(json.dumps(result, indent=2) + "\n")
    _ = sys.stdout.write(json.dumps(result, indent=2) + "\n")
    return result


def build(configuration: str, analyze: bool = False) -> None:
    """Run the explicitly requested native build or static analyze action.

    Raises:
        RuntimeError: The native tool emitted errors or warnings.

    """
    require_assertions_active()
    source_fingerprint = fingerprint()
    action = "analyze" if analyze else "build"
    log = ROOT / f"build/{action}-{configuration}.log"
    log.parent.mkdir(exist_ok=True)
    command = [
        "xcodebuild",
        "-project",
        str(PROJECT),
        "-scheme",
        "SimpleATH",
        "-configuration",
        configuration,
        "-destination",
        "generic/platform=macOS",
        "-derivedDataPath",
        str(ROOT / "build/DerivedData"),
        action,
    ]
    with log.open("w") as output:
        result = subprocess.run(
            command, stdout=output, stderr=subprocess.STDOUT, check=False
        )
    diagnostics = [
        line
        for line in log.read_text().splitlines()
        if any(
            s in line for s in ["error:", "warning:", "** BUILD", "** ANALYZE"]
        )
    ]
    _ = sys.stdout.write("\n".join(diagnostics) + "\n")
    if result.returncode or any(
        BUILD_WARNING_PREFIX in line for line in diagnostics
    ):
        message = f"Build diagnostics require attention: {log}"
        raise RuntimeError(message)
    require_invariant(
        source_fingerprint == fingerprint(),
        lambda: "Source changed during the build",
    )
    if analyze:
        _ = (ROOT / f"build/Analysis-{configuration}.json").write_text(
            json.dumps(
                {
                    "passed": True,
                    "sourceFingerprint": source_fingerprint,
                    "logSHA256": digest(log),
                },
                indent=2,
            )
            + "\n"
        )
    else:
        binary = (
            ROOT
            / f"build/DerivedData/Build/Products/{configuration}/SimpleATH.kext/Contents/MacOS/SimpleATH"
        )
        _ = (ROOT / f"build/Build-{configuration}.json").write_text(
            json.dumps(
                {
                    "sourceFingerprint": source_fingerprint,
                    "sha256": digest(binary),
                    "logSHA256": digest(log),
                    "payloadManifestSHA256": digest(OUTPUT / "manifest.json"),
                },
                indent=2,
            )
            + "\n"
        )


def copy_package_sources(root: Path, stage: Path) -> None:
    """Copy only real current source documents into an offline package.

    The original packaging helper referenced README.en.md, NOTICE.md,
    Tools/ and Docs/, none of which exist in the migrated source tree.
    Keeping these references would prevent an otherwise authorized build
    from ever being packaged. No artifact is built by this helper.

    """
    extra = stage / "Extra"
    for filename in ("README.md", "LICENSE", "THIRD_PARTY_NOTICES.md"):
        _ = shutil.copy2(root / filename, stage / filename)
    _ = shutil.copy2(root / "tools/collect.py", extra / "collect.py")
    docs = stage / "Docs"
    docs.mkdir()
    for document in sorted((root / "docs").glob("*.md")):
        _ = shutil.copy2(document, docs / document.name)
    # A checked-out OCLP reference may carry additional licensing terms.
    # Include its notice when present, never require a downloaded reference.
    license_file = root / ".research/OpenCore-Legacy-Patcher/LICENSE.txt"
    if license_file.is_file() and not license_file.is_symlink():
        _ = shutil.copy2(license_file, extra / "OCLP-LICENSE.txt")


def package(configuration: str, channel: str = "rel") -> None:
    """Package a fully verified native artifact when explicitly authorized."""
    require_assertions_active()
    report = json_object(
        (ROOT / f"build/Validation-{configuration}.json").read_text()
    )
    native_targets = [
        mapping(target) for target in sequence(report["nativeTargets"])
    ]
    product = ROOT / f"build/DerivedData/Build/Products/{configuration}"
    require_invariant(report["sourceFingerprint"] == fingerprint())
    require_invariant(
        {string(target["system"]) for target in native_targets} == set(SYSTEMS)
    )
    require_invariant(
        report["sha256"]
        == digest(product / "SimpleATH.kext/Contents/MacOS/SimpleATH")
    )
    require_invariant(report["probeSHA256"] == digest(product / "athprobe"))
    analysis = json_object((ROOT / "build/Analysis-Release.json").read_text())
    require_invariant(analysis["passed"])
    require_invariant(analysis["sourceFingerprint"] == fingerprint())
    require_invariant(
        analysis["logSHA256"] == digest(ROOT / "build/analyze-Release.log")
    )
    name = package_name(configuration, channel)
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".package-", dir=dist) as temporary:
        stage = Path(temporary) / name
        _ = shutil.copytree(
            product / "SimpleATH.kext", stage / "EFI/OC/Kexts/SimpleATH.kext"
        )
        extra = stage / "Extra"
        extra.mkdir()
        _ = shutil.copy2(product / "athprobe", extra / "athprobe")
        _ = shutil.copytree(
            product / "SimpleATH.kext.dSYM", extra / "SimpleATH.kext.dSYM"
        )
        copy_package_sources(ROOT, stage)
        _ = (extra / "Validation.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
        save_plist(stage / "config.fragment.plist", fragment())
        save_plist(
            extra / "config.AirportBrcmFixup.fragment.plist",
            fragment(optional=True),
        )
        files = {
            str(p.relative_to(stage)): digest(p)
            for p in stage.rglob("*")
            if p.is_file()
        }
        _ = (extra / "manifest.json").write_text(
            json.dumps(
                {
                    "version": VERSION,
                    "configuration": configuration,
                    "files": files,
                    "hardwareValidation": "not-run-by-build",
                    "driverLoading": "embedded",
                    "skywalkBackend": "native",
                },
                indent=2,
            )
            + "\n"
        )
        archive = dist / (name + ".zip")
        with zipfile.ZipFile(
            archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9
        ) as output:
            for path in sorted(stage.rglob("*")):
                if path.is_file():
                    output.write(
                        path, str(Path(name) / path.relative_to(stage))
                    )
        with zipfile.ZipFile(archive) as output:
            require_invariant(output.testzip() is None)
            require_invariant(
                plist_object(output.read(name + "/config.fragment.plist"))
                == fragment()
            )
            for path, sha in files.items():
                require_invariant(
                    hashlib.sha256(output.read(name + "/" + path)).hexdigest()
                    == sha
                )
    _ = archive.with_suffix(".zip.sha256").write_text(
        f"{digest(archive)}  {archive.name}\n"
    )
    _ = sys.stdout.write(f"{archive}\n")


def _is_list(value: object) -> TypeIs[list[object]]:
    return isinstance(value, list)


def _collection_paths(volumes: object) -> list[Path]:
    """Normalize only path instances produced by the CLI volume parser.

    Returns:
        Boot kernel collection paths under explicitly selected volumes.

    Raises:
        TypeError: A non-path volume was supplied.

    """
    if not _is_list(volumes):
        message = "Expected an array of target volume paths"
        raise TypeError(message)
    result: list[Path] = []
    for volume in volumes:
        if not isinstance(volume, Path):
            message = "Expected a target volume Path"
            raise TypeError(message)
        result.append(
            volume / "System/Library/KernelCollections/BootKernelExtensions.kc"
        )
    return result


def main() -> None:
    """Dispatch an explicitly selected build, verification or package action."""
    require_assertions_active()
    parser = argparse.ArgumentParser()
    _ = parser.add_argument(
        "action", choices=["build", "verify", "analyze", "package"]
    )
    _ = parser.add_argument(
        "--configuration", choices=["Debug", "Release"], default="Debug"
    )
    _ = parser.add_argument("--channel", choices=["pre", "rel"], default="rel")
    _ = parser.add_argument("--target-volume", type=Path, action="append")
    selected = vars(parser.parse_args())
    action = string(selected.get("action"))
    configuration = string(selected.get("configuration"))
    channel = string(selected.get("channel"))
    volumes: object = selected.get("target_volume")
    if action in {"build", "verify", "analyze"}:
        _ = validate_reference_systems()
    if action in {"build", "analyze"}:
        build(configuration, analyze=action == ANALYZE_ACTION)
    if action in {"verify", "build"}:
        references = (
            _collection_paths(volumes)
            if volumes is not None
            else list(reference_paths().values())
        )
        _ = verify(configuration, references)
    if action == PACKAGE_ACTION:
        package(configuration, channel)


if __name__ == "__main__":
    main()
