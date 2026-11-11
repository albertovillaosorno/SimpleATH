#!/usr/bin/env python3
# Copyright:
#   - Copyright © 2026 laobamac. All rights reserved.
# SPDX-License-Identifier:
#   - LicenseRef-SimpleBCM-All-Rights-Reserved
# Confidential:
#   - false
# License-File:
#   - LICENSE-SIMPLEBCM
# Provenance:
#   - SimpleBCM v1.2.0, by laobamac; no public license grant identified
#   - Originally authored by laobamac on 2026/9/18.
#
# Boundary-Contract:
# - Owns:
#   - Host-side tooling for audit codecs.
# - Must-Not:
#   - Read unrelated user files, hide failures, or bypass explicit tool inputs.
# - Allows:
#   - Inputs: explicit command-line, repository, or fixture inputs.
#   - Outputs: deterministic reports, generated artifacts, or error codes.
#   - Side effects: bounded local source-analysis or developer-command activity.
# - Split-When:
#   - A separate protocol stage needs independent validation and ownership.
# - Merge-When:
#   - The caller directly owns this narrow contract without reuse.
# - Summary:
#   - Host-side tooling for audit codecs.
# - Description:
#   - Implements or verifies the audit_codecs source boundary.
# - Usage:
#   - Invoked by developers or CI with an explicit checkout context.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Host-side tooling for audit codecs.

"""Audit legacy Apple80211 codec call sites against pinned binary evidence."""

from __future__ import annotations

import json
import re
import sys
from typing import Never
from typing import TYPE_CHECKING

if __package__:
    from tools.abi_types import mapping
    from tools.abi_types import unpack_integers
    from tools.macho import Image
    from tools.profiles import IMAGES
    from tools.profiles import ROOT
    from tools.profiles import SCALAR_GET_REQUESTS
    from tools.profiles import relocations
else:
    from abi_types import mapping
    from abi_types import unpack_integers
    from macho import Image
    from profiles import IMAGES
    from profiles import ROOT
    from profiles import SCALAR_GET_REQUESTS
    from profiles import relocations

if TYPE_CHECKING:
    from collections.abc import Mapping
    from collections.abc import Sequence

    from tools.abi_types import JsonValue

COPY_OUTPUT_MARKER = "copyOut"
SCALAR_REGISTER = "r8"
SAVED_POINTER_REGISTER = "rbx"
COPY_RELOCATION_KIND = 2
EXPECTED_COPY_SITES = 18
EXPECTED_BACKEND_SITES = 16
EXPECTED_COPY_IMAGES = {"Legacy": 14, "AirPort": 2, "AirPortOriginal": 2}


def _metadata_text(*parts: str) -> str:
    """Preserve pinned report strings while keeping source lines reviewable.

    Returns:
        Exactly the supplied text fragments joined without a separator.

    """
    return "".join(parts)


def disassembly_blocks(assembly: str) -> dict[int, str]:
    """Index disassembly blocks by their exact entry-point address.

    Returns:
        Recognized symbol-code blocks keyed by canonical hexadecimal address.

    Raises:
        ValueError: A duplicate handler address appears in disassembly output.

    """
    blocks: dict[int, str] = {}
    for block in assembly.split("\n\n"):
        match = re.match(r"([0-9a-f]+) <([^>]+)>:", block)
        if match:
            address = int(match[1], 16)
            if address in blocks:
                message = "Duplicate disassembly handler address"
                raise ValueError(message)
            blocks[address] = block
    return blocks


def _reject(message: str) -> Never:
    """Abort a stale binary signature without publishing stale evidence.

    Raises:
        RuntimeError: Always, with the supplied precise audit diagnostic.

    """
    raise RuntimeError(message)


def _load_legacy_handlers() -> tuple[Image, tuple[int, ...], dict[int, str]]:
    """Validate the fixed legacy GET dispatch table against text evidence.

    Returns:
        The legacy image, address table and disassembly block index.

    """
    image = Image(IMAGES["Legacy"])
    table = unpack_integers(
        image.read(image.symbols["_gGetHandlerTable"], 417 * 8), "<417Q"
    )
    assembly = image.disassemble(r"^__ZL.*get.*P17IO80211Controller")
    blocks = disassembly_blocks(assembly)
    if not (set(table) - {0}) <= blocks.keys():
        _reject(
            "The GET handler table contains entries that were not disassembled"
        )
    return image, table, blocks


def analyze_scalar_handler(
    image: Image, request: int, address: int, *, block: str
) -> dict[str, JsonValue] | None:
    """Validate one scalar GET handler against disassembled machine code.

    Returns:
        Verified JSON evidence, or None if the handler is not a scalar GET.

    """
    lines = block.splitlines()
    stores = [
        (index, line.strip())
        for index, line in enumerate(lines)
        if re.search(r"\bmov[lqw]\s+[^\n]*, 0x14\(%r(?:bx|1[2345]|8)\)", line)
    ]
    if COPY_OUTPUT_MARKER in block or not stores:
        return None
    if re.search(r"0x20\(%r(?:bx|1[2345]|8)\)", block):
        _reject(
            "A scalar GET handler accesses a data pointer; inspect it again"
        )
    for index, store in stores:
        _verify_scalar_destination(lines[:index], store)
    return mapping({
        "request": request,
        "symbol": image.name(address),
        "address": hex(address),
        "stores": [store for _, store in stores],
    })


def _verify_scalar_destination(prior_lines: list[str], store: str) -> None:
    """Require a proven request pointer before each individual output store."""
    register_match = re.search(r"0x14\(%(r\w+)\)", store)
    if register_match is None:
        _reject("Scalar output target register not found")
    register = register_match[1]
    if not _verified_request_register(prior_lines, register):
        _reject(
            "The scalar output target was not confirmed to be apple80211req"
        )


def _verified_request_register(prior_lines: list[str], register: str) -> bool:
    """Track a request pointer through known register writes and saved copies.

    Returns:
        Whether the register still holds the original request pointer.

    """
    request_valid = True
    alias_valid = register == SCALAR_REGISTER
    for line in prior_lines:
        if _overwrites_register(line, SCALAR_REGISTER):
            request_valid = False
        if register == SCALAR_REGISTER or re.search(
            r"movq\s+%r8, %" + register + r"\b", line
        ):
            alias_valid = request_valid
        elif _overwrites_register(line, register):
            alias_valid = False
    return alias_valid


def _overwrites_register(line: str, register: str) -> bool:
    """Conservatively detect register writes after a verified request alias.

    Returns:
        True for a direct destination, unary mutation or xchg of the alias.

    """
    variants = (
        (SAVED_POINTER_REGISTER, "ebx", "bx", "bl", "bh")
        if register == SAVED_POINTER_REGISTER
        else (register, register + "d", register + "w", register + "b")
    )
    target = r"%(?:" + "|".join(variants) + r")\b"
    return bool(
        re.search(r",\s*" + target, line)
        or re.search(r"\b(?:pop|inc|dec|neg|not|bswap)\w*\s+" + target, line)
        or re.search(r"\bxchg\w*\s+.*" + target, line)
        or (register == SCALAR_REGISTER and re.search(r"\bcall\w*\b", line))
    )


def _scalar_gets(
    image: Image, table: tuple[int, ...], blocks: dict[int, str]
) -> list[dict[str, JsonValue]]:
    """Extract only proven scalar handlers from pinned disassembly.

    Returns:
        Verified scalar output request evidence in ascending request order.

    """
    scalar: list[dict[str, JsonValue]] = []
    for request, address in enumerate(table, 1):
        if not address:
            continue
        entry = analyze_scalar_handler(
            image, request, address, block=blocks[address]
        )
        if entry is not None:
            scalar.append(entry)
    if [entry["request"] for entry in scalar] != SCALAR_GET_REQUESTS:
        _reject("The scalar GET mapping does not match the actual machine code")
    return scalar


def verify_copy_counts(copies: Sequence[Mapping[str, object]]) -> None:
    """Require the fixed total and backend-specific copy-site counts."""
    if len(copies) != EXPECTED_COPY_SITES:
        _reject("Unexpected total copy callsite count")
    if any(
        sum(entry["image"] == label for entry in copies) != count
        for label, count in EXPECTED_COPY_IMAGES.items()
    ):
        _reject("Unexpected backend copy callsite count")


def _copy_sites() -> list[dict[str, JsonValue]]:
    """Validate the expected backend copy relocations for two backends.

    Returns:
        Sorted image, address and symbol evidence for copy call sites.

    """
    copies: list[dict[str, JsonValue]] = []
    for label in ["Legacy", "AirPort", "AirPortOriginal"]:
        binary = Image(IMAGES[label])
        for address, _, symbol, kind in relocations(binary):
            if (
                symbol in {"_copyin", "_copyout"}
                and kind == COPY_RELOCATION_KIND
            ):
                copies.append(
                    mapping({
                        "image": label,
                        "address": hex(address - 1),
                        "symbol": binary.name(address - 1),
                        "operation": symbol,
                    })
                )
    verify_copy_counts(copies)
    return copies


def _verify_get_layout(table: tuple[int, ...], blocks: dict[int, str]) -> None:
    """Require unchanged scan/capability response structure checks."""
    if table[10] not in blocks or table[11] not in blocks:
        _reject("Required scan and capability GET handlers absent")
    scan = blocks[table[10]]
    if not re.search(r"cmpl\s+\$0x48c, 0x18\(%rbx\)", scan):
        _reject("The legacy scan-result structure length check has changed")
    capabilities = blocks[table[11]]
    if not re.search(r"cmpl\s+\$0xc, %eax", capabilities) or not re.search(
        r"leaq\s+-0x24\(%rbp\), %rsi", capabilities
    ):
        _reject("The legacy capability bitmap structure has changed")


def _verify_set_layout(image: Image) -> None:
    """Require unchanged association and roam set-command layouts."""
    set_entries = {
        request: unpack_integers(
            image.read(
                image.symbols["_gSetHandlerTable"] + (request - 1) * 8, 8
            ),
            "<Q",
        )[0]
        for request in [20, 216]
    }
    set_assembly = image.disassemble(
        r"^__ZL19setAssociateRequest|^__ZL14setRoamProfile"
    )
    if (
        set_entries != {20: 0x84430, 216: 0x8B211}
        or not re.search(r"movl\s+\$0x224, %ecx", set_assembly)
        or not re.search(r"cmpl\s+\$0x7c, 0x18\(%r8\)", set_assembly)
    ):
        _reject(
            "The legacy association or roaming profile structure has changed"
        )


def main() -> None:
    """Check pinned offline codec evidence before updating its report."""
    image, table, blocks = _load_legacy_handlers()
    scalar = _scalar_gets(image, table, blocks)
    copies = _copy_sites()
    _verify_get_layout(table, blocks)
    _verify_set_layout(image)
    report: dict[str, JsonValue] = mapping({
        "copyright": "Copyright © 2026 laobamac. All rights reserved.",
        "legacySHA256": image.source_sha256,
        "getTableCapacity": 417,
        "populatedGetEntries": sum(bool(x) for x in table),
        "uniqueGetCodecs": len(set(table) - {0}),
        "scalarGetRequests": scalar,
        "adaptedCopySites": copies,
        "associateTransfer": {
            "request": 20,
            "legacySize": 0x224,
            "nativeSize": {"Sonoma": 0x358, "Sequoia": 0x384, "Tahoe": 0x38C},
            "legacyCodec": "0x84430",
            "nativeProducer": {"Sequoia": "0xa053", "Tahoe": "0xa094"},
            "driverConsumer": "0x42b8e",
            "extendedLayoutSystems": ["Sequoia", "Tahoe"],
            "authLower": {
                "legacyOffset": 6,
                "legacyWidth": 2,
                "nativeOffset": 8,
                "nativeWidth": 4,
            },
            "authUpper": {
                "legacyOffset": 8,
                "legacyWidth": 2,
                "nativeOffset": 12,
                "nativeWidth": 4,
            },
            "ssidLength": {"legacyOffset": 0xC, "nativeOffset": 0x10},
            "key": {"legacyOffset": 0x38, "nativeOffset": 0x3C},
            "rsnLength": {"legacyOffset": 0xCC, "nativeOffset": 0xD0},
            "pmkLength": {"legacyOffset": 0x1D4, "nativeOffset": 0x1D8},
            "bssidCount": {
                "legacyOffset": 0x202,
                "nativeOffset": 0x206,
                "legacyMaximum": 3,
                "nativeMaximum": 10,
            },
            "scopeLength": {"legacyOffset": 0x218, "nativeOffset": 0x244},
        },
        "roamProfileTransfer": {
            "request": 216,
            "legacyBandSize": 0x7C,
            "nativeBandSize": 0x80,
            "aggregateSystems": ["Sequoia", "Tahoe"],
            "sonomaTransfer": _metadata_text(
                "Single 0x7C-byte Legacy band, passed ",
                "through unchanged",
            ),
            "nativeAllBandsSize": 0x180,
            "nativeValidOffset": 12,
            "legacyRecordsOffset": 12,
            "nativeRecordsOffset": 16,
            "legacySetCodec": "0x8b211",
            "legacyGetCodec": "0x806fb",
            "nativeBandParser": {"Sequoia": "0x33d0a", "Tahoe": "0x37432"},
            "bands": [2, 4],
        },
        "capabilityTransfer": {
            "request": 12,
            "legacySize": 12,
            "nativeSize": {"Sonoma": 16, "Sequoia": 19, "Tahoe": 21},
            "legacyCodec": "0x78cb7",
            "nativeBindSizeInstruction": {
                "Sequoia": "0x2672a",
                "Tahoe": "0x26a29",
            },
            "scanCompletionCapability": 46,
            "nativeScanWaitTest": "0x4259",
            "scope": _metadata_text(
                "Native-sized output for all endpoints; ",
                "only Classic advertises ",
                "bridge scan completion events; ",
                "other hardware bits are preserved.",
            ),
        },
        "scanResultTransfer": {
            "request": 11,
            "legacySize": 0x48C,
            "nativeSize": {"Sonoma": 0x4CC, "Sequoia": 0x8D8, "Tahoe": 0x8E0},
            "commonHeaderSize": 0x8C,
            "ieLengthOffset": 0x8A,
            "legacyIECapacity": 0x400,
            "nativeIECapacity": {"Sequoia": 0x800, "Tahoe": 0x800},
            "legacyCodec": "0x78a33",
            "nativeCallerSizeInstruction": "0x4333",
            "nativeParser": "0x6d4f",
            "nativeControllerSizeInstruction": "0x7ff8007d28a9",
        },
        "nativeCaller": {
            "imageUUID": "A7A35846-4067-3182-B70E-F7477FBC32BD",
            "symbol": "Apple80211RawGet",
            "instructionOffset": "0x6984",
            "behavior": _metadata_text(
                "If req_data is NULL, the native caller supplies &req_val ",
                "and length 4 as IOUC output.",
            ),
        },
    })
    report["sonoma"] = {
        "OSBuild": "23J620",
        "kernel": "23.6.0",
        "airPortBackend": "Original",
        "nativeIO80211UUID": "0a93a0f4c12532fe918856f7c24ddc41",
        "nativeIO80211FamilyUUID": "ec4ba6726e083ad2b88201690a960ff4",
        "scanResultSizeInstruction": "0x4baa",
        "capabilitySizeInstruction": "0x20e10",
        "associateSizeInstruction": "0xa5fe",
        "associateTransfer": {
            "nativeSize": 0x358,
            "legacyPrefixSize": 0x224,
            "prefixUnchanged": True,
            "authLowerOffset": 6,
            "authUpperOffset": 8,
            "authWidth": 2,
            "ssidLengthOffset": 0xC,
            "keyOffset": 0x38,
            "rsnLengthOffset": 0xCC,
            "pmkLengthOffset": 0x1D4,
            "bssidCountOffset": 0x202,
            "bssidMaximum": 3,
            "authWriteInstructions": ["0xa99c", "0xa9be"],
        },
        "scanMultipleSize": 0x14E0,
        "roamProfileSize": 0x7C,
        "selectorCount": 7,
        "commandPacketSize": 0x3C30,
        "largeCommandPacketSize": 0x3C030,
        "eventHeaderSize": 0x30,
        "driverAvailableSize": 0xB8,
        "associationDonePolicy": _metadata_text(
            "Preserve Legacy empty event; ",
            "no synthetic JoinStatus",
        ),
        "associationDoneConsumer": {
            "symbol": "__eventRead",
            "eventDispatch": "0x22376",
            "resultRequest21": "0x224d7",
            "getterCall": "0x224e5",
            "emptyPayloadCallback": ["0x22502", "0x22517"],
        },
        "validation": "Native binary analysis and host-executed codec vectors",
        "upstreamWireless": _metadata_text(
            "https://github.com/dortania/OpenCore-Legacy-Patcher/blob/",
            "8da38565fa1551a8e5ce8613ea835d04dd97e089/",
            "opencore_legacy_patcher/efi_builder/networking/wireless.py",
        ),
    }
    destination = ROOT / "docs/Control-Codecs.json"
    content = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if (
        not destination.exists()
        or destination.read_text(encoding="utf-8") != content
    ):
        _ = destination.write_text(content, encoding="utf-8")
    _ = sys.stdout.write(
        "".join((
            "GET handler table verified: ",
            f"{report["populatedGetEntries"]} entries / ",
            f"{report["uniqueGetCodecs"]} unique codec entry points, ",
            f"{len(scalar)} scalar results, and ",
            f"{EXPECTED_BACKEND_SITES} guarded copy sites per backend.\n",
        ))
    )


if __name__ == "__main__":
    main()
